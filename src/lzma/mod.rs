//! LZMA 编解码器（从零实现，与 LZMA SDK 码流兼容）。
//!
//! 输出采用 LZMA1 的「alone」格式：`properties(1) + dict_size(4, LE) + uncompressed_size(8, LE)`，
//! 后接原始 LZMA 码流。`uncompressed_size` 为 `u64::MAX` 时表示未知（以结束标记终止）。

pub mod decoder;
pub mod encoder;
pub mod lz_encoder;
pub mod lzma2;
pub mod match_finder;
pub mod prob_model;
pub mod range_coder;

pub use decoder::{LzDecoder, LzmaError};

/// LZMA 编码参数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LzmaParams {
    /// 字面量上下文比特数（0..8）。
    pub lc: u32,
    /// 字面量位置比特数（0..4）。
    pub lp: u32,
    /// 位置比特数（0..4）。
    pub pb: u32,
    /// 字典大小。
    pub dict_size: u32,
    /// 到达即停止搜索的匹配长度（快速停断阈值）。
    pub nice_len: usize,
    /// 单个哈希链最多比较的候选数。
    pub max_chain: usize,
}

impl Default for LzmaParams {
    fn default() -> Self {
        preset(DEFAULT_LEVEL)
    }
}

/// 默认压缩级别。
pub const DEFAULT_LEVEL: u8 = 5;

/// 分块并行压缩时每个块的默认大小（4 MiB）。
pub const DEFAULT_BLOCK_SIZE: usize = 4 * 1024 * 1024;

/// 根据压缩级别（0..=9）返回匹配查找器的质量参数 `(max_chain, nice_len)`。
///
/// 级别越高哈希链越深、快速停断阈值越高，压缩率越高但速度越慢。
pub fn match_finder_quality(level: u8) -> (usize, usize) {
    match level {
        0 => (4, 16),
        1 => (8, 32),
        2 => (16, 64),
        3 => (32, 128),
        4 => (64, 128),
        5 => (128, 128),
        6 => (256, 256),
        7 => (512, 273),
        8 => (1024, 273),
        _ => (4096, 273),
    }
}

/// 根据压缩级别（0..=9）返回 LZMA 参数预设。
///
/// 所有级别使用 `lc=3, lp=0, pb=2`（与 xz 默认一致），主要差异在字典大小与
/// 匹配查找器质量。级别越高字典越大、搜索越深，压缩率越高但内存与时间开销也越大。
pub fn preset(level: u8) -> LzmaParams {
    let dict_size = match level {
        0 => 1 << 16, // 64 KiB
        1 => 1 << 18, // 256 KiB
        2 => 1 << 20, // 1 MiB
        3 => 1 << 21, // 2 MiB
        4 => 1 << 22, // 4 MiB
        5 => 1 << 23, // 8 MiB
        6 => 1 << 24, // 16 MiB
        7 => 1 << 25, // 32 MiB
        _ => 1 << 26, // 64 MiB（8/9）
    };
    let (max_chain, nice_len) = match_finder_quality(level);
    LzmaParams {
        lc: 3,
        lp: 0,
        pb: 2,
        dict_size,
        nice_len,
        max_chain,
    }
}

impl LzmaParams {
    pub fn new(lc: u32, lp: u32, pb: u32, dict_size: u32) -> Self {
        let (max_chain, nice_len) = match_finder_quality(DEFAULT_LEVEL);
        Self {
            lc,
            lp,
            pb,
            dict_size,
            nice_len,
            max_chain,
        }
    }

    fn properties(&self) -> u8 {
        ((self.pb * 5 + self.lp) * 9 + self.lc) as u8
    }
}

/// 压缩一段数据，返回完整的 LZMA alone 格式字节流。
pub fn encode(input: &[u8], params: &LzmaParams) -> Vec<u8> {
    let mut out = Vec::with_capacity(13 + input.len() / 2);
    out.push(params.properties());
    out.extend_from_slice(&params.dict_size.to_le_bytes());
    out.extend_from_slice(&(input.len() as u64).to_le_bytes());
    let raw = encoder::encode(
        input,
        params.lc,
        params.lp,
        params.pb,
        params.dict_size as usize,
        params.nice_len,
        params.max_chain,
    );
    out.extend_from_slice(&raw);
    out
}

/// 流式压缩：从 `reader` 读取输入、把完整 LZMA alone 字节流写入 `writer`，返回未压缩字节数。
///
/// `uncompressed_size` 为 `None` 时在 13 字节头中写 `u64::MAX`（以结束标记终止），
/// 否则写实际值。
pub fn encode_stream<R: std::io::Read, W: std::io::Write>(
    reader: &mut R,
    params: &LzmaParams,
    uncompressed_size: Option<u64>,
    writer: &mut W,
) -> Result<u64, LzmaError> {
    let mut header = [0u8; 13];
    header[0] = params.properties();
    header[1..5].copy_from_slice(&params.dict_size.to_le_bytes());
    header[5..13].copy_from_slice(&uncompressed_size.unwrap_or(u64::MAX).to_le_bytes());
    writer
        .write_all(&header)
        .map_err(|e| LzmaError::Io(e.kind()))?;

    let n = encoder::encode_stream(
        reader,
        params.lc,
        params.lp,
        params.pb,
        params.dict_size as usize,
        params.nice_len,
        params.max_chain,
        writer,
    )?;
    Ok(n as u64)
}

/// 分块并行压缩：把输入按 `block_size` 切成独立块，用 `processes` 个工作进程并行编码，
/// 返回 `len(4 LE) + block` 帧序列，以 `len=0` 终止（块各自为完整 alone 流）。
///
/// 与 [`encode`] 不同，输出不是单条 alone 流，需用 [`decode_blocks`] 解压。
pub fn encode_blocks(
    input: &[u8],
    params: &LzmaParams,
    block_size: usize,
    processes: usize,
) -> Vec<u8> {
    let block_size = block_size.max(1);
    let blocks: Vec<&[u8]> = input.chunks(block_size).collect();
    let n = blocks.len();

    // 多进程并行：见 `crate::parallel::encode_blocks_parallel`。
    let encoded = crate::parallel::encode_blocks_parallel(
        crate::parallel::Encoder::Lzma,
        &blocks,
        params,
        processes,
    );

    let mut out = Vec::with_capacity(input.len() / 2 + n * 4);
    for block in encoded {
        out.extend_from_slice(&(block.len() as u32).to_le_bytes());
        out.extend_from_slice(&block);
    }
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

/// 解压 [`encode_blocks`] 产生的帧序列，拼接各块明文。
pub fn decode_blocks(input: &[u8]) -> Result<Vec<u8>, LzmaError> {
    decode_blocks_with_processes(input, 1)
}

/// 用 `processes` 个工作进程并行解压 [`encode_blocks`] 产生的帧序列。
///
/// `processes == 1` 时退化为串行解压；帧先解析为独立块切片，再交给多进程并行解码。
pub fn decode_blocks_with_processes(
    input: &[u8],
    processes: usize,
) -> Result<Vec<u8>, LzmaError> {
    // 1. 解析帧序列得到各块切片（每个块为完整 alone 流）。
    let mut blocks: Vec<&[u8]> = Vec::new();
    let mut offset = 0usize;
    loop {
        if offset + 4 > input.len() {
            return Err(LzmaError::Truncated);
        }
        let len = u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if len == 0 {
            break;
        }
        if offset + len > input.len() {
            return Err(LzmaError::Truncated);
        }
        blocks.push(&input[offset..offset + len]);
        offset += len;
    }

    // 2. 并行解码并按序拼接。
    let decoded = crate::parallel::decode_blocks_parallel(&blocks, processes)?;
    let total = decoded.iter().map(|b| b.len()).sum();
    let mut out = Vec::with_capacity(total);
    for block in decoded {
        out.extend_from_slice(&block);
    }
    Ok(out)
}

/// 解压 LZMA alone 格式字节流。
pub fn decode(input: &[u8]) -> Result<Vec<u8>, LzmaError> {
    if input.len() < 13 {
        return Err(LzmaError::Truncated);
    }
    let props = input[0];
    let lc = (props % 9) as u32;
    let rem = props / 9;
    let lp = (rem % 5) as u32;
    let pb = (rem / 5) as u32;
    if lp > 4 || pb > 4 {
        return Err(LzmaError::BadProperties);
    }
    let uncompressed = u64::from_le_bytes(input[5..13].try_into().unwrap());
    let expected = if uncompressed == u64::MAX {
        None
    } else {
        Some(uncompressed as usize)
    };

    let mut dec = LzDecoder::new(lc, lp, pb);
    dec.decode(&input[13..], expected)
}

/// 流式解压 LZMA alone 格式字节流到 `writer`，返回写出的字节数。
pub fn decode_to_writer<W: std::io::Write>(
    input: &[u8],
    writer: &mut W,
) -> Result<usize, LzmaError> {
    if input.len() < 13 {
        return Err(LzmaError::Truncated);
    }
    let props = input[0];
    let lc = (props % 9) as u32;
    let rem = props / 9;
    let lp = (rem % 5) as u32;
    let pb = (rem / 5) as u32;
    if lp > 4 || pb > 4 {
        return Err(LzmaError::BadProperties);
    }
    let dict_size = u32::from_le_bytes(input[1..5].try_into().unwrap()) as usize;
    let uncompressed = u64::from_le_bytes(input[5..13].try_into().unwrap());
    let expected = if uncompressed == u64::MAX {
        None
    } else {
        Some(uncompressed as usize)
    };

    let mut dec = LzDecoder::new(lc, lp, pb);
    dec.decode_to_writer(&input[13..], expected, dict_size, writer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn properties_roundtrip() {
        for lc in 0..=8u32 {
            for lp in 0..=4u32 {
                for pb in 0..=4u32 {
                    let p = LzmaParams::new(lc, lp, pb, 1 << 16);
                    let props = p.properties();
                    assert_eq!(props % 9, lc as u8);
                    let rem = props / 9;
                    assert_eq!(rem % 5, lp as u8);
                    assert_eq!(rem / 5, pb as u8);
                }
            }
        }
    }

    #[test]
    fn decode_to_writer_roundtrip() {
        // 数据长度超过字典大小，覆盖环形字典回绕与重叠匹配。
        let mut input = Vec::new();
        for i in 0..200_000usize {
            input.push((i % 251) as u8);
            input.extend_from_slice(b"repeat-me-please-");
        }
        let params = LzmaParams::new(3, 0, 2, 1 << 16);
        let packed = encode(&input, &params);

        let mut out = Vec::new();
        let written = decode_to_writer(&packed, &mut out).unwrap();
        assert_eq!(written, input.len());
        assert_eq!(out, input);
    }

    #[test]
    fn encode_stream_matches_encode() {
        let params = LzmaParams::new(3, 0, 2, 1 << 16);
        // 含重复结构、长度超过字典大小，覆盖环形窗口回绕。
        let mut input = Vec::new();
        for i in 0..300_000usize {
            input.push((i % 251) as u8);
            input.extend_from_slice(b"stream-encode-check-");
        }
        let buffered = encode(&input, &params);

        let mut reader = std::io::Cursor::new(&input);
        let mut streamed = Vec::new();
        let n = encode_stream(
            &mut reader,
            &params,
            Some(input.len() as u64),
            &mut streamed,
        )
        .unwrap();
        assert_eq!(n as usize, input.len());
        assert_eq!(streamed, buffered);
    }

    #[test]
    fn encode_stream_unknown_size_roundtrip() {
        let params = LzmaParams::new(3, 0, 2, 1 << 18);
        let mut input = Vec::new();
        for i in 0..100_000usize {
            input.push((i % 7) as u8);
            input.extend_from_slice(b"unknown-size-");
        }

        let mut reader = std::io::Cursor::new(&input);
        let mut packed = Vec::new();
        encode_stream(&mut reader, &params, None, &mut packed).unwrap();

        let mut out = Vec::new();
        let written = decode_to_writer(&packed, &mut out).unwrap();
        assert_eq!(written, input.len());
        assert_eq!(out, input);
    }

    #[test]
    fn encode_blocks_roundtrip() {
        let params = LzmaParams::new(3, 0, 2, 1 << 16);
        let mut input = Vec::new();
        for i in 0..200_000usize {
            input.push((i % 251) as u8);
            input.extend_from_slice(b"blocked-lzma-");
        }
        // 多块 + 多进程，结果必须与单块/单进程语义一致（内容一致）。
        let packed = encode_blocks(&input, &params, 64 * 1024, 4);
        let out = decode_blocks(&packed).unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn encode_blocks_single_block_and_empty() {
        let params = LzmaParams::new(3, 0, 2, 1 << 16);
        let input = b"short block".repeat(10);

        // 单个块（块大小超过输入）。
        let packed = encode_blocks(&input, &params, 1 << 20, 1);
        assert_eq!(decode_blocks(&packed).unwrap(), input);

        // 空输入仅剩终止符。
        let empty = encode_blocks(b"", &params, 1 << 20, 2);
        assert_eq!(decode_blocks(&empty).unwrap(), b"");
    }

    #[test]
    fn decode_blocks_truncated() {
        // 只有 4 字节终止符长度域，无帧与终止符。
        assert_eq!(decode_blocks(&[0u8, 0, 0, 0]).unwrap(), b"");
        // 声明长度超出剩余字节，应报截断。
        let mut bad = vec![0u8; 2];
        bad.extend_from_slice(&16u32.to_le_bytes());
        assert!(decode_blocks(&bad).is_err());
    }
}
