//! `.xz` 容器读写（LZMA2 过滤器）。
//!
//! 实现标准 .xz 文件格式（见 tukaani.org 的 `xz-file-format.txt`），
//! 目前支持：
//! - 单个 Stream、单个或多个 Block；
//! - LZMA2 过滤器（Filter ID `0x21`）；
//! - CRC32 / CRC64 / None 三种校验（编码时使用 CRC32）。

use crate::crc::{crc32, crc64};
use crate::lzma::lzma2::{self, Decoder as Lzma2Decoder};
use crate::lzma::{LzmaError, LzmaParams};

/// `.xz` 解析/编码错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XzError {
    /// 数据损坏（魔数、CRC、结构不合法等）。
    Corrupt,
    /// 输入被截断。
    Truncated,
    /// 不支持的校验类型。
    UnsupportedCheck(u8),
    /// 不支持的过滤器（目前仅支持 LZMA2）。
    UnsupportedFilter(u64),
    /// 字典大小不是合法的 LZMA2 值（`2^n` 或 `3 * 2^(n-1)`）。
    InvalidDictSize(u32),
    /// 内层 LZMA2 解码错误。
    Lzma(LzmaError),
}

impl std::fmt::Display for XzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Corrupt => write!(f, "corrupt .xz data"),
            Self::Truncated => write!(f, "truncated .xz stream"),
            Self::UnsupportedCheck(id) => write!(f, "unsupported check type 0x{id:02x}"),
            Self::UnsupportedFilter(id) => write!(f, "unsupported filter id {id}"),
            Self::InvalidDictSize(sz) => write!(f, "invalid LZMA2 dictionary size {sz}"),
            Self::Lzma(e) => write!(f, "LZMA2 error: {e}"),
        }
    }
}

impl std::error::Error for XzError {}

impl From<LzmaError> for XzError {
    fn from(e: LzmaError) -> Self {
        Self::Lzma(e)
    }
}

const HEADER_MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0x00];
const FOOTER_MAGIC: [u8; 2] = *b"YZ";
const LZMA2_FILTER_ID: u64 = 0x21;

const CHECK_NONE: u8 = 0x00;
const CHECK_CRC32: u8 = 0x01;
const CHECK_CRC64: u8 = 0x04;

fn check_size(id: u8) -> Option<usize> {
    match id {
        CHECK_NONE => Some(0),
        CHECK_CRC32 => Some(4),
        CHECK_CRC64 => Some(8),
        _ => None,
    }
}

/// 可变长度整数编码（`.xz` 的 VLI，最多 9 字节）。
fn vli_encode(mut n: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    loop {
        let mut byte = (n & 0x7F) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
    out
}

/// 可变长度整数解码，返回 `None` 表示越界或超过 9 字节。
fn vli_decode(input: &[u8], pos: &mut usize) -> Result<u64, XzError> {
    let mut num = 0u64;
    for i in 0..9usize {
        if *pos >= input.len() {
            return Err(XzError::Truncated);
        }
        let byte = input[*pos];
        *pos += 1;
        num |= ((byte & 0x7F) as u64) << (i * 7);
        if byte & 0x80 == 0 {
            return Ok(num);
        }
    }
    Err(XzError::Corrupt)
}

/// LZMA2 过滤器属性：把字典大小编码为一个字节。
///
/// 字典必须是 `2^n`（`n ∈ 12..=30`）或 `3 * 2^(n-1)`（`n ∈ 13..=30`）。
fn lzma2_dict_props_encode(dict_size: u32) -> Option<u8> {
    if dict_size < 4096 {
        return None;
    }
    if dict_size.is_power_of_two() {
        let n = dict_size.trailing_zeros();
        if (12..=30).contains(&n) {
            return Some(((n - 12) * 2) as u8);
        }
        return None;
    }
    if dict_size.is_multiple_of(3) && (dict_size / 3).is_power_of_two() {
        let m = (dict_size / 3).trailing_zeros() + 1;
        if (13..=30).contains(&m) {
            return Some(((m - 12) * 2 + 1) as u8);
        }
    }
    None
}

/// LZMA2 过滤器属性字节解码为字典大小。
fn lzma2_dict_props_decode(props: u8) -> Option<u32> {
    if props & 1 == 0 {
        // 2^n
        let n = (props as u32 / 2) + 12;
        if n <= 30 {
            Some(1u32 << n)
        } else {
            None
        }
    } else {
        // 3 * 2^(n-1)
        let n = (props as u32 - 1) / 2 + 12;
        if (13..=30).contains(&n) {
            Some(3u32 << (n - 1))
        } else {
            None
        }
    }
}

/// 计算一个块在 Index 中记录的 Unpadded Size（块总大小减去 Block Padding）。
fn unpadded_size(header_len: usize, compressed_len: usize, check_len: usize) -> usize {
    header_len + compressed_len + check_len
}

/// 构建 Block Header。
fn build_block_header(
    compressed_size: u64,
    uncompressed_size: u64,
    dict_size: u32,
) -> Result<Vec<u8>, XzError> {
    let mut h = Vec::new();
    h.push(0x00); // Block Header Size 占位。
    h.push(0xC0); // 压缩/未压缩大小均存在，1 个过滤器。
    h.extend_from_slice(&vli_encode(compressed_size));
    h.extend_from_slice(&vli_encode(uncompressed_size));
    h.push(LZMA2_FILTER_ID as u8);
    h.push(0x01); // 属性长度。
    h.push(lzma2_dict_props_encode(dict_size).ok_or(XzError::InvalidDictSize(dict_size))?);

    // 补齐到 4 字节对齐（含末尾 4 字节 CRC32），最小块头 8 字节。
    while (h.len() + 4) % 4 != 0 {
        h.push(0x00);
    }
    let header_size = h.len() + 4;
    h[0] = (header_size / 4 - 1) as u8;

    let c = crc32(&h);
    h.extend_from_slice(&c.to_le_bytes());
    Ok(h)
}

/// 把一段数据编码为单块、单流的 `.xz`（LZMA2 + CRC32）。
pub fn encode(input: &[u8], params: &LzmaParams) -> Result<Vec<u8>, XzError> {
    let compressed = lzma2::encode(input, params, lzma2::DEFAULT_CHUNK_SIZE);

    // Stream Header。
    let mut out = Vec::with_capacity(12 + compressed.len() + 32);
    out.extend_from_slice(&HEADER_MAGIC);
    let stream_flags = [0x00, CHECK_CRC32];
    out.extend_from_slice(&stream_flags);
    out.extend_from_slice(&crc32(&stream_flags).to_le_bytes());

    // Block Header。
    let check_len = check_size(CHECK_CRC32).unwrap();
    let header = build_block_header(
        compressed.len() as u64,
        input.len() as u64,
        params.dict_size,
    )?;
    out.extend_from_slice(&header);

    // Compressed Data + Block Padding（对齐到 4）+ Check。
    out.extend_from_slice(&compressed);
    while out.len() % 4 != 0 {
        out.push(0x00);
    }
    out.extend_from_slice(&crc32(input).to_le_bytes());

    // Index。
    let unpadded = unpadded_size(header.len(), compressed.len(), check_len) as u64;
    let mut index = Vec::new();
    index.push(0x00); // Index Indicator。
    index.extend_from_slice(&vli_encode(1)); // Number of Records = 1。
    index.extend_from_slice(&vli_encode(unpadded));
    index.extend_from_slice(&vli_encode(input.len() as u64));
    while (index.len() + 4) % 4 != 0 {
        index.push(0x00);
    }
    let index_crc = crc32(&index);
    index.extend_from_slice(&index_crc.to_le_bytes());
    out.extend_from_slice(&index);

    // Stream Footer。
    let backward_size = (index.len() / 4 - 1) as u32;
    let mut footer_crc_input = Vec::with_capacity(6);
    footer_crc_input.extend_from_slice(&backward_size.to_le_bytes());
    footer_crc_input.extend_from_slice(&stream_flags);
    out.extend_from_slice(&crc32(&footer_crc_input).to_le_bytes());
    out.extend_from_slice(&backward_size.to_le_bytes());
    out.extend_from_slice(&stream_flags);
    out.extend_from_slice(&FOOTER_MAGIC);

    Ok(out)
}

/// 把一段数据编码为多块、单流的 `.xz`（每块一个 LZMA2 流 + CRC32）。
///
/// `block_size` 为每个 Block 的未压缩数据大小，`processes` 为并行压缩的进程数。
/// 多块比单块更利于并行与随机访问，系统 xz 同样可解压。
pub fn encode_blocks(
    input: &[u8],
    params: &LzmaParams,
    block_size: usize,
    processes: usize,
) -> Result<Vec<u8>, XzError> {
    let block_size = block_size.max(1);
    // 空输入仍写一个空块，保证流内至少有一个 Block。
    let blocks: Vec<&[u8]> = if input.is_empty() {
        vec![b""]
    } else {
        input.chunks(block_size).collect()
    };
    let n = blocks.len();

    // 多进程并行：每个块独立编码为完整 LZMA2 流。
    let encoded = crate::parallel::encode_blocks_parallel(
        crate::parallel::Encoder::Lzma2Stream,
        &blocks,
        params,
        processes,
    );

    let check_len = check_size(CHECK_CRC32).unwrap();
    let mut out = Vec::with_capacity(12 + input.len() / 2 + n * 32);

    // Stream Header。
    out.extend_from_slice(&HEADER_MAGIC);
    let stream_flags = [0x00, CHECK_CRC32];
    out.extend_from_slice(&stream_flags);
    out.extend_from_slice(&crc32(&stream_flags).to_le_bytes());

    // 各块 + 记录（unpadded, uncompressed）。
    let mut records: Vec<(u64, u64)> = Vec::with_capacity(n);
    for i in 0..n {
        let compressed = &encoded[i];
        let header = build_block_header(
            compressed.len() as u64,
            blocks[i].len() as u64,
            params.dict_size,
        )?;
        records.push((
            unpadded_size(header.len(), compressed.len(), check_len) as u64,
            blocks[i].len() as u64,
        ));
        out.extend_from_slice(&header);
        out.extend_from_slice(compressed);
        while out.len() % 4 != 0 {
            out.push(0x00);
        }
        out.extend_from_slice(&crc32(blocks[i]).to_le_bytes());
    }

    // Index。
    let mut index = Vec::new();
    index.push(0x00); // Index Indicator。
    index.extend_from_slice(&vli_encode(n as u64));
    for (unpadded, uncompressed) in &records {
        index.extend_from_slice(&vli_encode(*unpadded));
        index.extend_from_slice(&vli_encode(*uncompressed));
    }
    while (index.len() + 4) % 4 != 0 {
        index.push(0x00);
    }
    let index_crc = crc32(&index);
    index.extend_from_slice(&index_crc.to_le_bytes());
    out.extend_from_slice(&index);

    // Stream Footer。
    let backward_size = (index.len() / 4 - 1) as u32;
    let mut footer_crc_input = Vec::with_capacity(6);
    footer_crc_input.extend_from_slice(&backward_size.to_le_bytes());
    footer_crc_input.extend_from_slice(&stream_flags);
    out.extend_from_slice(&crc32(&footer_crc_input).to_le_bytes());
    out.extend_from_slice(&backward_size.to_le_bytes());
    out.extend_from_slice(&stream_flags);
    out.extend_from_slice(&FOOTER_MAGIC);

    Ok(out)
}

/// 解析并解压一个 Block，返回 `(明文, unpadded_size)`。
fn decode_one_block(
    input: &[u8],
    pos: &mut usize,
    check_id: u8,
    check_len: usize,
) -> Result<(Vec<u8>, usize), XzError> {
    // Block Header。
    if *pos + 2 > input.len() {
        return Err(XzError::Truncated);
    }
    let header_size = ((input[*pos] as usize) + 1) * 4;
    let block_flags = input[*pos + 1];
    *pos += 2;
    if header_size < 8 || *pos + header_size - 2 > input.len() {
        return Err(XzError::Truncated);
    }
    let header_end = *pos - 2 + header_size;

    let compressed_size = if block_flags & 0x40 != 0 {
        vli_decode(input, pos)?
    } else {
        // 目前只支持已知压缩大小的块。
        return Err(XzError::Corrupt);
    };
    let uncompressed_size = if block_flags & 0x80 != 0 {
        vli_decode(input, pos)?
    } else {
        return Err(XzError::Corrupt);
    };

    let num_filters = (block_flags & 0x03) as usize + 1;
    let mut dict_size = 0u32;
    for _ in 0..num_filters {
        let filter_id = vli_decode(input, pos)?;
        let props_size = vli_decode(input, pos)?;
        if filter_id != LZMA2_FILTER_ID {
            return Err(XzError::UnsupportedFilter(filter_id));
        }
        if props_size != 1 {
            return Err(XzError::Corrupt);
        }
        if *pos >= input.len() {
            return Err(XzError::Truncated);
        }
        dict_size = lzma2_dict_props_decode(input[*pos]).ok_or(XzError::Corrupt)?;
        *pos += 1;
    }

    // 校验块头 CRC32（从 size 字节到 padding 结束，不含 CRC）。
    let header_crc_start = header_end - 4;
    let header_crc = u32::from_le_bytes(input[header_crc_start..header_end].try_into().unwrap());
    let header_body_start = header_end - header_size;
    if crc32(&input[header_body_start..header_crc_start]) != header_crc {
        return Err(XzError::Corrupt);
    }
    *pos = header_end;

    // Compressed Data。
    if compressed_size == 0 {
        return Err(XzError::Corrupt);
    }
    if *pos + compressed_size as usize > input.len() {
        return Err(XzError::Truncated);
    }
    let compressed = &input[*pos..*pos + compressed_size as usize];
    *pos += compressed_size as usize;

    // 跳过 Block Padding（对齐到 4）。
    while !(*pos).is_multiple_of(4) {
        if *pos >= input.len() || input[*pos] != 0x00 {
            return Err(XzError::Corrupt);
        }
        *pos += 1;
    }

    // Check + 解压。
    let out = Lzma2Decoder::new(dict_size as usize).decode(compressed)?;
    if out.len() as u64 != uncompressed_size {
        return Err(XzError::Corrupt);
    }
    match check_id {
        CHECK_NONE => {}
        CHECK_CRC32 => {
            if *pos + 4 > input.len() {
                return Err(XzError::Truncated);
            }
            let stored = u32::from_le_bytes(input[*pos..*pos + 4].try_into().unwrap());
            *pos += 4;
            if stored != crc32(&out) {
                return Err(XzError::Corrupt);
            }
        }
        CHECK_CRC64 => {
            if *pos + 8 > input.len() {
                return Err(XzError::Truncated);
            }
            let stored = u64::from_le_bytes(input[*pos..*pos + 8].try_into().unwrap());
            *pos += 8;
            if stored != crc64(&out) {
                return Err(XzError::Corrupt);
            }
        }
        _ => return Err(XzError::UnsupportedCheck(check_id)),
    }

    Ok((
        out,
        unpadded_size(header_size, compressed_size as usize, check_len),
    ))
}

/// 解压单流 `.xz`（支持单个或多个 Block），返回明文。
pub fn decode(input: &[u8]) -> Result<Vec<u8>, XzError> {
    if input.len() < 12 + 12 {
        return Err(XzError::Truncated);
    }

    // Stream Header。
    if input[0..6] != HEADER_MAGIC {
        return Err(XzError::Corrupt);
    }
    let stream_flags = [input[6], input[7]];
    let stored_crc = u32::from_le_bytes(input[8..12].try_into().unwrap());
    if stored_crc != crc32(&stream_flags) {
        return Err(XzError::Corrupt);
    }
    if stream_flags[0] != 0x00 {
        return Err(XzError::Corrupt);
    }
    let check_id = stream_flags[1];
    let check_len = check_size(check_id).ok_or(XzError::UnsupportedCheck(check_id))?;

    let mut pos = 12usize;
    let mut out = Vec::new();
    let mut records: Vec<(u64, u64)> = Vec::new();

    // 逐个 Block 解压，直到遇到 Index Indicator（0x00，块头大小字节不可能为 0）。
    loop {
        if pos >= input.len() {
            return Err(XzError::Truncated);
        }
        if input[pos] == 0x00 {
            break;
        }
        let (block, unpadded) = decode_one_block(input, &mut pos, check_id, check_len)?;
        records.push((unpadded as u64, block.len() as u64));
        out.extend_from_slice(&block);
    }

    // Index（校验其 CRC32 与每条记录）。
    if pos + 4 > input.len() {
        return Err(XzError::Truncated);
    }
    let index_start = pos;
    let index_indicator = input[pos];
    if index_indicator & 0xF0 != 0 {
        return Err(XzError::Corrupt);
    }
    pos += 1;
    let record_count = vli_decode(input, &mut pos)?;
    if record_count as usize != records.len() {
        return Err(XzError::Corrupt);
    }
    for (unpadded, uncompressed) in &records {
        let iu = vli_decode(input, &mut pos)?;
        let ic = vli_decode(input, &mut pos)?;
        if iu != *unpadded || ic != *uncompressed {
            return Err(XzError::Corrupt);
        }
    }
    // Index Padding 到 4 字节对齐，其后是 4 字节 CRC32。
    while !(pos - index_start).is_multiple_of(4) {
        pos += 1;
    }
    if pos + 4 > input.len() {
        return Err(XzError::Truncated);
    }
    let index_crc = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap());
    pos += 4;
    if crc32(&input[index_start..pos - 4]) != index_crc {
        return Err(XzError::Corrupt);
    }

    // Stream Footer。
    if pos + 12 > input.len() {
        return Err(XzError::Truncated);
    }
    let footer_crc = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap());
    let backward_size = u32::from_le_bytes(input[pos + 4..pos + 8].try_into().unwrap());
    let footer_flags = [input[pos + 8], input[pos + 9]];
    if input[pos + 10..pos + 12] != FOOTER_MAGIC {
        return Err(XzError::Corrupt);
    }
    if footer_flags != stream_flags {
        return Err(XzError::Corrupt);
    }
    let real_backward = ((backward_size as usize) + 1) * 4;
    if real_backward != pos - index_start {
        return Err(XzError::Corrupt);
    }
    let mut footer_crc_input = Vec::with_capacity(6);
    footer_crc_input.extend_from_slice(&backward_size.to_le_bytes());
    footer_crc_input.extend_from_slice(&footer_flags);
    if crc32(&footer_crc_input) != footer_crc {
        return Err(XzError::Corrupt);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> LzmaParams {
        LzmaParams::new(3, 0, 2, 1 << 20)
    }

    fn roundtrip(input: &[u8]) {
        let packed = encode(input, &params()).unwrap();
        let out = decode(&packed).unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn empty_roundtrip() {
        roundtrip(b"");
    }

    #[test]
    fn small_roundtrip() {
        roundtrip(b"hello, .xz container!");
    }

    #[test]
    fn multi_chunk_roundtrip() {
        // 远大于 LZMA2 单块（64 KiB），覆盖容器内多块拼接。
        let mut data = Vec::new();
        for i in 0..200_000usize {
            data.push((i % 251) as u8);
            data.extend_from_slice(b".xz-multi-chunk-");
        }
        roundtrip(&data);
    }

    #[test]
    fn incompressible_roundtrip() {
        // 伪随机数据，压缩率差，走 LZMA2 未压缩块路径。
        let mut state = 0x1234_5678u32;
        let mut data = Vec::with_capacity(100_000);
        for _ in 0..100_000 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            data.push((state >> 24) as u8);
        }
        roundtrip(&data);
    }

    #[test]
    fn invalid_dict_size() {
        // 100_000 既不是 2^n，也不是 3 * 2^(n-1)。
        let p = LzmaParams::new(3, 0, 2, 100_000);
        assert!(matches!(
            encode(b"data", &p),
            Err(XzError::InvalidDictSize(100_000))
        ));
    }

    #[test]
    fn truncated_input() {
        let packed = encode(b"some data for truncation", &params()).unwrap();
        assert_eq!(decode(&packed[..10]), Err(XzError::Truncated));
    }

    #[test]
    fn corrupt_magic() {
        let packed = encode(b"data", &params()).unwrap();
        let mut bad = packed.clone();
        bad[0] = 0x00;
        assert_eq!(decode(&bad), Err(XzError::Corrupt));
    }

    #[test]
    fn multi_block_roundtrip() {
        let mut data = Vec::new();
        for i in 0..300_000usize {
            data.push((i % 251) as u8);
            data.extend_from_slice(b".xz-multi-block-");
        }
        let packed = encode_blocks(&data, &params(), 64 * 1024, 4).unwrap();
        let out = decode(&packed).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn multi_block_single_and_empty() {
        let p = params();
        // 单块（block_size 超过输入）。
        let input = b"short block".repeat(20);
        let packed = encode_blocks(&input, &p, 1 << 20, 1).unwrap();
        assert_eq!(decode(&packed).unwrap(), input);

        // 空输入仍产生一个空块。
        let empty = encode_blocks(b"", &p, 1 << 20, 2).unwrap();
        assert_eq!(decode(&empty).unwrap(), b"");
    }

    fn system_xz_available() -> bool {
        std::process::Command::new("xz")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn interop_with_system_xz() {
        if !system_xz_available() {
            return;
        }
        let mut data = Vec::new();
        for i in 0..300_000u32 {
            data.push((i % 251) as u8);
            data.extend_from_slice(b"interop-with-system-xz-");
        }

        let dir = std::env::temp_dir();

        // 1) 我们写出的 .xz → 系统 xz 解压。
        let ours = dir.join("rzp2_xz_ours.xz");
        std::fs::write(&ours, encode(&data, &params()).unwrap()).unwrap();
        let out = std::process::Command::new("xz")
            .arg("-dc")
            .arg(&ours)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "xz 解压失败: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, data);

        // 2) 系统 xz 压缩 → 我们解压。
        let raw = dir.join("rzp2_xz_raw.bin");
        std::fs::write(&raw, &data).unwrap();
        let sys = dir.join("rzp2_xz_sys.xz");
        let status = std::process::Command::new("xz")
            .arg("-c")
            .arg(&raw)
            .stdout(std::fs::File::create(&sys).unwrap())
            .status()
            .unwrap();
        assert!(status.success());
        let decoded = decode(&std::fs::read(&sys).unwrap()).unwrap();
        assert_eq!(decoded, data);

        let _ = std::fs::remove_file(&ours);
        let _ = std::fs::remove_file(&raw);
        let _ = std::fs::remove_file(&sys);
    }

    #[test]
    fn multi_block_interop_with_system_xz() {
        if !system_xz_available() {
            return;
        }
        let mut data = Vec::new();
        for i in 0..300_000u32 {
            data.push((i % 251) as u8);
            data.extend_from_slice(b"multi-block-interop-");
        }
        let dir = std::env::temp_dir();

        // 我们写出的多块 .xz → 系统 xz 解压。
        let ours = dir.join("rzp2_xz_blocks_ours.xz");
        std::fs::write(
            &ours,
            encode_blocks(&data, &params(), 64 * 1024, 4).unwrap(),
        )
        .unwrap();
        let out = std::process::Command::new("xz")
            .arg("-dc")
            .arg(&ours)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "xz 解压多块失败: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, data);

        // 系统 xz 多块（--block-size）→ 我们解压。
        let raw = dir.join("rzp2_xz_blocks_raw.bin");
        std::fs::write(&raw, &data).unwrap();
        let sys = dir.join("rzp2_xz_blocks_sys.xz");
        let status = std::process::Command::new("xz")
            .args(["-c", "--block-size=65536"])
            .arg(&raw)
            .stdout(std::fs::File::create(&sys).unwrap())
            .status()
            .unwrap();
        assert!(status.success());
        let decoded = decode(&std::fs::read(&sys).unwrap()).unwrap();
        assert_eq!(decoded, data);

        let _ = std::fs::remove_file(&ours);
        let _ = std::fs::remove_file(&raw);
        let _ = std::fs::remove_file(&sys);
    }
}
