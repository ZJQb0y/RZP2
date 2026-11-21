//! PNG 容器级的 DEFLATE 重压缩。
//!
//! 把 PNG 的 IDAT 图像数据（标准 zlib 流）拆成「zlib 头 + DEFLATE 流 + adler32 尾」，
//! 只对其中的 DEFLATE 流做符号层重压缩；其余 chunk（IHDR / PLTE / IEND 等）原样保留，
//! 从而逐位还原原 PNG 文件。IDAT 可能被切分成多个 chunk，重建时按原始切分还原。
//!
//! 重压缩表示以魔数 `RZPN` 开头，供解码端区分「重压缩载荷」与「未重压缩的原始输入」。

use crate::formats::deflate::DeflateError;
use super::deflate as precomp;

/// 重压缩表示的魔数。
pub const MAGIC: &[u8; 4] = b"RZPN";

/// PNG 文件签名。
const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

/// 重压缩一个 PNG 文件（含多段连续 IDAT）。
pub fn recompress(input: &[u8]) -> Result<Vec<u8>, DeflateError> {
    if !input.starts_with(PNG_SIGNATURE) {
        return Err(DeflateError::Corrupt);
    }

    let mut pos = 8usize;
    let mut pre = Vec::new(); // IDAT 之前的 chunk 原始字节
    let mut post = Vec::new(); // IDAT 之后的 chunk 原始字节
    let mut idat_sizes = Vec::new(); // 各 IDAT chunk 的 data 长度
    let mut zlib = Vec::new(); // 所有 IDAT data 拼接成的 zlib 流
    let mut seen_idat = false;
    let mut idat_done = false;

    while pos < input.len() {
        if pos + 8 > input.len() {
            return Err(DeflateError::Truncated);
        }
        let len = u32::from_be_bytes(input[pos..pos + 4].try_into().unwrap()) as usize;
        let ctype = &input[pos + 4..pos + 8];
        let data_start = pos + 8;
        let data_end = data_start
            .checked_add(len)
            .ok_or(DeflateError::Corrupt)?;
        let chunk_end = data_end
            .checked_add(4)
            .ok_or(DeflateError::Corrupt)?;
        if chunk_end > input.len() {
            return Err(DeflateError::Truncated);
        }

        if ctype == b"IDAT" {
            if idat_done {
                // IDAT 必须连续，出现第二次连续段视为不可处理。
                return Err(DeflateError::Corrupt);
            }
            seen_idat = true;
            idat_sizes.push(len);
            zlib.extend_from_slice(&input[data_start..data_end]);
        } else if seen_idat {
            idat_done = true;
            post.extend_from_slice(&input[pos..chunk_end]);
        } else {
            pre.extend_from_slice(&input[pos..chunk_end]);
        }
        pos = chunk_end;
    }

    if !seen_idat || zlib.len() < 6 {
        return Err(DeflateError::Corrupt);
    }

    // zlib 流：header(2) + deflate + adler32(4)。
    let zlib_header = &zlib[..2];
    let zlib_trailer = &zlib[zlib.len() - 4..];
    let deflate_stream = &zlib[2..zlib.len() - 4];
    let packed = precomp::recompress(deflate_stream)?;

    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(MAGIC);
    out.push(1); // 版本号
    out.extend_from_slice(&(pre.len() as u32).to_le_bytes());
    out.extend_from_slice(&pre);
    out.extend_from_slice(&(idat_sizes.len() as u32).to_le_bytes());
    for &s in &idat_sizes {
        out.extend_from_slice(&(s as u32).to_le_bytes());
    }
    out.extend_from_slice(zlib_header);
    out.extend_from_slice(&(packed.len() as u32).to_le_bytes());
    out.extend_from_slice(&packed);
    out.extend_from_slice(zlib_trailer);
    out.extend_from_slice(&post);
    Ok(out)
}

/// 由重压缩表示重建原始 PNG 文件。
pub fn reconstruct(input: &[u8]) -> Result<Vec<u8>, DeflateError> {
    if !input.starts_with(MAGIC) {
        return Err(DeflateError::Corrupt);
    }
    if input.get(4) != Some(&1u8) {
        return Err(DeflateError::Corrupt);
    }

    let mut pos = 5usize;
    let pre_len = read_u32(input, &mut pos)? as usize;
    let pre = read_bytes(input, &mut pos, pre_len)?;
    let idat_count = read_u32(input, &mut pos)? as usize;
    let mut idat_sizes = Vec::with_capacity(idat_count);
    for _ in 0..idat_count {
        idat_sizes.push(read_u32(input, &mut pos)? as usize);
    }
    let zlib_header = read_bytes(input, &mut pos, 2)?;
    let packed_len = read_u32(input, &mut pos)? as usize;
    let packed = read_bytes(input, &mut pos, packed_len)?;
    let zlib_trailer = read_bytes(input, &mut pos, 4)?;
    let post = &input[pos..];

    let deflate_stream = precomp::reconstruct(packed)?;
    let mut zlib = Vec::with_capacity(2 + deflate_stream.len() + 4);
    zlib.extend_from_slice(zlib_header);
    zlib.extend_from_slice(&deflate_stream);
    zlib.extend_from_slice(zlib_trailer);

    let mut out = Vec::with_capacity(input.len() * 2);
    out.extend_from_slice(PNG_SIGNATURE);
    out.extend_from_slice(pre);

    let mut zpos = 0usize;
    for &size in &idat_sizes {
        if zpos + size > zlib.len() {
            return Err(DeflateError::Corrupt);
        }
        let data = &zlib[zpos..zpos + size];
        out.extend_from_slice(&(size as u32).to_be_bytes());
        out.extend_from_slice(b"IDAT");
        out.extend_from_slice(data);
        // PNG chunk CRC = CRC32(type || data)，大端存储。
        let mut crc_input = Vec::with_capacity(4 + size);
        crc_input.extend_from_slice(b"IDAT");
        crc_input.extend_from_slice(data);
        out.extend_from_slice(&crate::crc::crc32(&crc_input).to_be_bytes());
        zpos += size;
    }
    if zpos != zlib.len() {
        return Err(DeflateError::Corrupt);
    }
    out.extend_from_slice(post);
    Ok(out)
}

/// 判断 `input` 是否为 PNG 重压缩表示。
pub fn is_recompressed(input: &[u8]) -> bool {
    input.starts_with(MAGIC)
}

fn read_u32(input: &[u8], pos: &mut usize) -> Result<u32, DeflateError> {
    let b = input.get(*pos..*pos + 4).ok_or(DeflateError::Truncated)?;
    *pos += 4;
    Ok(u32::from_le_bytes(b.try_into().unwrap()))
}

fn read_bytes<'a>(input: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], DeflateError> {
    let b = input.get(*pos..*pos + len).ok_or(DeflateError::Truncated)?;
    *pos += len;
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 用存储块编码一段原始数据（DEFLATE 存储块：字节对齐，最简编码）。
    fn stored_deflate(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x01u8]; // BFINAL=1, BTYPE=00（LSB-first）。
        let len = data.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(data);
        out
    }

    /// Adler-32（zlib 校验），无第三方依赖。
    fn adler32(data: &[u8]) -> u32 {
        let mut a = 1u32;
        let mut b = 0u32;
        for &byte in data {
            a = (a + byte as u32) % 65521;
            b = (b + a) % 65521;
        }
        (b << 16) | a
    }

    /// 构造一个 PNG chunk（length + type + data + crc）。
    fn chunk(ctype: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + data.len());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(ctype);
        out.extend_from_slice(data);
        let mut crc_input = Vec::with_capacity(4 + data.len());
        crc_input.extend_from_slice(ctype);
        crc_input.extend_from_slice(data);
        out.extend_from_slice(&crate::crc::crc32(&crc_input).to_be_bytes());
        out
    }

    /// 构造一个最小 1x1 灰度 PNG（像素值 `pixel`）。
    fn make_png(pixel: u8) -> Vec<u8> {
        // IHDR：width=1, height=1, bit depth=8, color type=0（灰度）。
        let ihdr = [0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0];
        // 图像数据：filter byte(0) + 1 像素。
        let raw = [0u8, pixel];
        let mut zlib = vec![0x78, 0x01]; // zlib header（无压缩级别，LSB-first）。
        zlib.extend_from_slice(&stored_deflate(&raw));
        zlib.extend_from_slice(&adler32(&raw).to_be_bytes());

        let mut out = Vec::new();
        out.extend_from_slice(PNG_SIGNATURE);
        out.extend_from_slice(&chunk(b"IHDR", &ihdr));
        out.extend_from_slice(&chunk(b"IDAT", &zlib));
        out.extend_from_slice(&chunk(b"IEND", b""));
        out
    }

    #[test]
    fn png_recompress_roundtrip() {
        let png = make_png(0x42);
        let packed = recompress(&png).unwrap();
        assert!(is_recompressed(&packed));
        assert_ne!(packed, png);
        let rebuilt = reconstruct(&packed).unwrap();
        assert_eq!(rebuilt, png);
    }

    #[test]
    fn png_recompress_rejects_non_png() {
        assert!(recompress(b"not a png").is_err());
        assert!(!is_recompressed(b"not a png"));
        assert_eq!(reconstruct(b"no magic").unwrap_err(), DeflateError::Corrupt);
    }
}
