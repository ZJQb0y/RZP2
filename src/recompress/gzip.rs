//! gzip（RFC 1952）容器级的 DEFLATE 重压缩。
//!
//! 把 gzip 文件按成员拆成「头部 + DEFLATE 流 + 8 字节尾部」，只对其中的 DEFLATE 流
//! 做符号层重压缩，头部与尾部（CRC32/ISIZE）原样保留，从而逐位还原原 gzip 文件。
//!
//! 重压缩表示以魔数 `RZGD` 开头，供解码端区分「重压缩载荷」与「未重压缩的原始输入」。

use crate::formats::deflate;
use crate::formats::gzip::GzipError;
use super::deflate as precomp;

/// 重压缩表示的魔数。
pub const MAGIC: &[u8; 4] = b"RZGD";

/// 重压缩一个 gzip 文件（可含多个成员）。
pub fn recompress(input: &[u8]) -> Result<Vec<u8>, GzipError> {
    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(MAGIC);
    out.push(1); // 版本号

    let mut pos = 0usize;
    while pos < input.len() {
        let (header_end, deflate_end, member_end) = split_member(input, pos)?;
        let header = &input[pos..header_end];
        let deflate_stream = &input[header_end..deflate_end];
        let trailer = &input[deflate_end..member_end];

        out.extend_from_slice(&(header.len() as u16).to_le_bytes());
        out.extend_from_slice(header);

        let packed = precomp::recompress(deflate_stream)?;
        out.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        out.extend_from_slice(&packed);

        out.extend_from_slice(trailer);
        pos = member_end;
    }

    Ok(out)
}

/// 由重压缩表示重建原始 gzip 文件。
pub fn reconstruct(input: &[u8]) -> Result<Vec<u8>, GzipError> {
    if !input.starts_with(MAGIC) {
        return Err(GzipError::Corrupt);
    }
    if input.get(4) != Some(&1u8) {
        return Err(GzipError::Corrupt);
    }

    let mut pos = 5usize;
    let mut out = Vec::new();
    while pos < input.len() {
        let header_len = read_u16(input, &mut pos)? as usize;
        let header = read_bytes(input, &mut pos, header_len)?;

        let deflate_len = read_u32(input, &mut pos)? as usize;
        let packed = read_bytes(input, &mut pos, deflate_len)?;

        let trailer = read_bytes(input, &mut pos, 8)?;

        let deflate_stream = precomp::reconstruct(packed)?;
        out.extend_from_slice(header);
        out.extend_from_slice(&deflate_stream);
        out.extend_from_slice(trailer);
    }

    Ok(out)
}

/// 判断 `input` 是否为 gzip 重压缩表示。
pub fn is_recompressed(input: &[u8]) -> bool {
    input.starts_with(MAGIC)
}

/// 解析从 `start` 开始的单个 gzip 成员，返回
/// `(deflate 起始偏移, deflate 结束偏移, 成员结束偏移)`。
fn split_member(
    input: &[u8],
    start: usize,
) -> Result<(usize, usize, usize), GzipError> {
    if start + 10 > input.len() {
        return Err(GzipError::Truncated);
    }
    if input[start] != 0x1F || input[start + 1] != 0x8B {
        return Err(GzipError::Corrupt);
    }
    if input[start + 2] != 0x08 {
        return Err(GzipError::UnsupportedMethod(input[start + 2]));
    }

    let flg = input[start + 3];
    let mut pos = start + 10;

    if flg & 0x04 != 0 {
        // FEXTRA
        if pos + 2 > input.len() {
            return Err(GzipError::Truncated);
        }
        let xlen = u16::from_le_bytes(input[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2 + xlen;
    }
    if flg & 0x08 != 0 {
        pos = skip_cstring(input, pos)?; // FNAME
    }
    if flg & 0x10 != 0 {
        pos = skip_cstring(input, pos)?; // FCOMMENT
    }
    if flg & 0x02 != 0 {
        if pos + 2 > input.len() {
            return Err(GzipError::Truncated);
        }
        pos += 2; // FHCRC
    }

    let header_end = pos;
    let (_, consumed) = deflate::decompress_consumed(&input[pos..])?;
    let deflate_end = pos + consumed;
    if deflate_end + 8 > input.len() {
        return Err(GzipError::Truncated);
    }
    let member_end = deflate_end + 8;

    Ok((header_end, deflate_end, member_end))
}

fn skip_cstring(input: &[u8], mut pos: usize) -> Result<usize, GzipError> {
    while pos < input.len() {
        if input[pos] == 0 {
            return Ok(pos + 1);
        }
        pos += 1;
    }
    Err(GzipError::Truncated)
}

fn read_u16(input: &[u8], pos: &mut usize) -> Result<u16, GzipError> {
    let b = input
        .get(*pos..*pos + 2)
        .ok_or(GzipError::Truncated)?;
    *pos += 2;
    Ok(u16::from_le_bytes(b.try_into().unwrap()))
}

fn read_u32(input: &[u8], pos: &mut usize) -> Result<u32, GzipError> {
    let b = input
        .get(*pos..*pos + 4)
        .ok_or(GzipError::Truncated)?;
    *pos += 4;
    Ok(u32::from_le_bytes(b.try_into().unwrap()))
}

fn read_bytes<'a>(input: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], GzipError> {
    let b = input.get(*pos..*pos + len).ok_or(GzipError::Truncated)?;
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

    /// 构造一个最小 gzip 成员（存储块 + CRC32/ISIZE 尾部）。
    fn make_gzip(uncompressed: &[u8]) -> Vec<u8> {
        let mut out = vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xFF];
        out.extend_from_slice(&stored_deflate(uncompressed));
        let crc = crate::crc::crc32(uncompressed);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(uncompressed.len() as u32).to_le_bytes());
        out
    }

    #[test]
    fn gzip_recompress_roundtrip() {
        let data = b"gzip recompress roundtrip payload";
        let gz = make_gzip(data);
        let packed = recompress(&gz).unwrap();
        assert!(is_recompressed(&packed));
        assert_ne!(packed, gz);
        let rebuilt = reconstruct(&packed).unwrap();
        assert_eq!(rebuilt, gz);
        assert_eq!(crate::formats::gzip::decode(&rebuilt).unwrap(), data);
    }

    #[test]
    fn gzip_multi_member_roundtrip() {
        let mut gz = make_gzip(b"first member ");
        gz.extend_from_slice(&make_gzip(b"second member"));
        let packed = recompress(&gz).unwrap();
        let rebuilt = reconstruct(&packed).unwrap();
        assert_eq!(rebuilt, gz);
        assert_eq!(
            crate::formats::gzip::decode(&rebuilt).unwrap(),
            b"first member second member"
        );
    }

    #[test]
    fn recompress_rejects_non_gzip() {
        assert!(recompress(b"not a gzip stream").is_err());
        assert!(!is_recompressed(b"not a gzip stream"));
        assert_eq!(reconstruct(b"no magic here").unwrap_err(), GzipError::Corrupt);
    }
}
