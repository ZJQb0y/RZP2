//! ZIP（PKWARE）容器级的 DEFLATE 重压缩。
//!
//! 把 ZIP 归档按「中央目录 + 本地文件头 + 数据」拆成若干段，只对其中的 DEFLATE
//! （压缩方法 8）条目数据做符号层重压缩，本地文件头、中央目录、数据描述符、存储
//! 条目（方法 0）与其他元数据一律原样保留，从而逐位还原原始 ZIP 文件。
//!
//! 重压缩表示以魔数 `RZZP` 开头，供解码端区分「重压缩载荷」与「未重压缩的原始输入」。
//! 表示内部由若干「原始段 / DEFLATE 段」按文件顺序组成，重建时对 DEFLATE 段反解回
//! 原始 DEFLATE 位流并拼接，实现字节级无损。

use std::fmt;

use crate::formats::deflate::DeflateError;
use super::deflate as precomp;

/// ZIP 重压缩错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZipError {
    /// 数据损坏（非法签名、重叠的数据段等）。
    Corrupt,
    /// 输入被截断。
    Truncated,
    /// 未找到中央目录结束记录。
    NoEocd,
    /// 暂不支持的 ZIP 特性（多卷 / zip64 等）。
    Unsupported(&'static str),
    /// DEFLATE 符号层重压缩错误。
    Deflate(DeflateError),
}

impl fmt::Display for ZipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corrupt => write!(f, "corrupt zip stream"),
            Self::Truncated => write!(f, "truncated zip stream"),
            Self::NoEocd => write!(f, "zip end-of-central-directory not found"),
            Self::Unsupported(feature) => write!(f, "unsupported zip feature: {feature}"),
            Self::Deflate(e) => write!(f, "deflate error: {e}"),
        }
    }
}

impl std::error::Error for ZipError {}

impl From<DeflateError> for ZipError {
    fn from(e: DeflateError) -> Self {
        Self::Deflate(e)
    }
}

/// 重压缩表示的魔数。
pub const MAGIC: &[u8; 4] = b"RZZP";

const LOCAL_SIG: u32 = 0x0403_4b50; // PK\x03\x04
const CENTRAL_SIG: u32 = 0x0201_4b50; // PK\x01\x02
const EOCD_SIG: u32 = 0x0605_4b50; // PK\x05\x06

const METHOD_DEFLATE: u16 = 8;
/// 加密位（bit 0）：加密条目的数据含加密头，不可重压缩，需原样保留。
const FLAG_ENCRYPTED: u16 = 0x0001;

// 段类型标记。
const SEG_RAW: u8 = 0x00;
const SEG_DEFLATE: u8 = 0x01;

/// 重压缩一个 ZIP 文件。
pub fn recompress(input: &[u8]) -> Result<Vec<u8>, ZipError> {
    if !is_zip(input) {
        return Err(ZipError::Corrupt);
    }

    let eocd = find_eocd(input).ok_or(ZipError::NoEocd)?;
    if le16(input, eocd + 4)? != 0 {
        return Err(ZipError::Unsupported("multi-disk"));
    }
    let total = le16(input, eocd + 10)? as usize;
    let cd_size = le32(input, eocd + 12)? as usize;
    let cd_offset = le32(input, eocd + 16)? as usize;
    if total == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_offset == 0xFFFF_FFFF {
        return Err(ZipError::Unsupported("zip64"));
    }

    // 收集需要重压缩的 DEFLATE 数据区域（起始, 结束, 重压缩后的符号层表示）。
    // 单条重压缩失败或符号层不比原始更小时按「原始段」处理，避免无损性受影响。
    let mut segments: Vec<(usize, usize, Option<Vec<u8>>)> = Vec::new();
    let cd_end = cd_offset.checked_add(cd_size).ok_or(ZipError::Corrupt)?;
    let mut pos = cd_offset;
    for _ in 0..total {
        if pos + 46 > cd_end {
            return Err(ZipError::Truncated);
        }
        if le32(input, pos)? != CENTRAL_SIG {
            return Err(ZipError::Corrupt);
        }
        let flags = le16(input, pos + 8)?;
        let method = le16(input, pos + 10)?;
        let comp_size = le32(input, pos + 20)? as usize;
        let name_len = le16(input, pos + 28)? as usize;
        let extra_len = le16(input, pos + 30)? as usize;
        let comment_len = le16(input, pos + 32)? as usize;
        let local_offset = le32(input, pos + 42)? as usize;
        pos += 46 + name_len + extra_len + comment_len;

        if method == METHOD_DEFLATE && flags & FLAG_ENCRYPTED == 0 && comp_size > 0 {
            let data_off = local_data_offset(input, local_offset)?;
            let data_end = data_off.checked_add(comp_size).ok_or(ZipError::Corrupt)?;
            if data_end > input.len() {
                return Err(ZipError::Truncated);
            }
            let raw_len = data_end - data_off;
            let packed = precomp::recompress(&input[data_off..data_end])
                .ok()
                .filter(|p| p.len() < raw_len);
            segments.push((data_off, data_end, packed));
        }
    }

    segments.sort_unstable_by_key(|s| s.0);
    for w in segments.windows(2) {
        if w[0].1 > w[1].0 {
            return Err(ZipError::Corrupt);
        }
    }

    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(MAGIC);
    out.push(1); // 版本号

    let mut cursor = 0usize;
    for (start, end, packed) in segments {
        if start > cursor {
            emit_raw(&mut out, &input[cursor..start]);
        }
        match packed {
            Some(p) => {
                out.push(SEG_DEFLATE);
                out.extend_from_slice(&(p.len() as u32).to_le_bytes());
                out.extend_from_slice(&p);
            }
            None => emit_raw(&mut out, &input[start..end]),
        }
        cursor = end;
    }
    if cursor < input.len() {
        emit_raw(&mut out, &input[cursor..]);
    }

    Ok(out)
}

/// 由重压缩表示重建原始 ZIP 文件。
pub fn reconstruct(input: &[u8]) -> Result<Vec<u8>, ZipError> {
    if !input.starts_with(MAGIC) {
        return Err(ZipError::Corrupt);
    }
    if input.get(4) != Some(&1u8) {
        return Err(ZipError::Corrupt);
    }

    let mut pos = 5usize;
    let mut out = Vec::new();
    while pos < input.len() {
        let tag = *input.get(pos).ok_or(ZipError::Truncated)?;
        pos += 1;
        match tag {
            SEG_RAW => {
                let len = read_u32(input, &mut pos)? as usize;
                out.extend_from_slice(read_bytes(input, &mut pos, len)?);
            }
            SEG_DEFLATE => {
                let len = read_u32(input, &mut pos)? as usize;
                let packed = read_bytes(input, &mut pos, len)?;
                out.extend_from_slice(&precomp::reconstruct(packed)?);
            }
            _ => return Err(ZipError::Corrupt),
        }
    }
    Ok(out)
}

/// 判断 `input` 是否为 ZIP 重压缩表示。
pub fn is_recompressed(input: &[u8]) -> bool {
    input.starts_with(MAGIC)
}

/// 判断输入是否为 ZIP 文件（`PK` 魔数）。
fn is_zip(input: &[u8]) -> bool {
    input.len() >= 4 && input[0] == 0x50 && input[1] == 0x4B
}

/// 由本地文件头定位条目数据起始偏移。
fn local_data_offset(input: &[u8], local_offset: usize) -> Result<usize, ZipError> {
    if le32(input, local_offset)? != LOCAL_SIG {
        return Err(ZipError::Corrupt);
    }
    let name_len = le16(input, local_offset + 26)? as usize;
    let extra_len = le16(input, local_offset + 28)? as usize;
    Ok(local_offset + 30 + name_len + extra_len)
}

/// 从末尾向前扫描「中央目录结束记录」签名。
fn find_eocd(buf: &[u8]) -> Option<usize> {
    if buf.len() < 22 {
        return None;
    }
    let start = buf.len().saturating_sub(22 + 65535);
    for i in (start..=buf.len() - 22).rev() {
        if le32(buf, i).ok()? == EOCD_SIG {
            return Some(i);
        }
    }
    None
}

fn emit_raw(out: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    out.push(SEG_RAW);
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn le16(b: &[u8], off: usize) -> Result<u16, ZipError> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(ZipError::Truncated)
}

fn le32(b: &[u8], off: usize) -> Result<u32, ZipError> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(ZipError::Truncated)
}

fn read_u32(input: &[u8], pos: &mut usize) -> Result<u32, ZipError> {
    let b = input.get(*pos..*pos + 4).ok_or(ZipError::Truncated)?;
    *pos += 4;
    Ok(u32::from_le_bytes(b.try_into().unwrap()))
}

fn read_bytes<'a>(input: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], ZipError> {
    let b = input.get(*pos..*pos + len).ok_or(ZipError::Truncated)?;
    *pos += len;
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 用存储块编码一段原始数据（DEFLATE 存储块，字节对齐最简编码）。
    fn stored_deflate(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x01u8]; // BFINAL=1, BTYPE=00
        let len = data.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(data);
        out
    }

    /// 构造一个最小 ZIP（单条目，方法 DEFLATE，无数据描述符）。
    fn make_zip(name: &[u8], raw_deflate: &[u8], crc: u32, uncomp_size: u32) -> Vec<u8> {
        let comp_size = raw_deflate.len() as u32;
        let name_len = name.len() as u16;

        let mut out = Vec::new();
        // 本地文件头。
        out.extend_from_slice(&LOCAL_SIG.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&METHOD_DEFLATE.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&comp_size.to_le_bytes());
        out.extend_from_slice(&uncomp_size.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name);
        out.extend_from_slice(raw_deflate);

        // 中央目录条目。
        let cd_offset = out.len() as u32;
        out.extend_from_slice(&CENTRAL_SIG.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version made by
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&METHOD_DEFLATE.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&comp_size.to_le_bytes());
        out.extend_from_slice(&uncomp_size.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(&0u16.to_le_bytes()); // comment len
        out.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        out.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        out.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        out.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        out.extend_from_slice(name);

        let cd_size = (out.len() - cd_offset as usize) as u32;

        // 中央目录结束记录。
        out.extend_from_slice(&EOCD_SIG.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // disk number
        out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
        out.extend_from_slice(&1u16.to_le_bytes()); // entries on this disk
        out.extend_from_slice(&1u16.to_le_bytes()); // total entries
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment len

        out
    }

    #[test]
    fn zip_recompress_roundtrip() {
        let data = b"zip recompress roundtrip payload";
        let crc = crate::crc::crc32(data);
        let zip = make_zip(b"hello.txt", &stored_deflate(data), crc, data.len() as u32);

        let packed = recompress(&zip).unwrap();
        assert!(is_recompressed(&packed));
        assert_ne!(packed, zip);
        let rebuilt = reconstruct(&packed).unwrap();
        assert_eq!(rebuilt, zip);
    }

    #[test]
    fn zip_recompress_rejects_non_zip() {
        assert!(recompress(b"not a zip stream").is_err());
        assert!(!is_recompressed(b"not a zip stream"));
        assert_eq!(reconstruct(b"no magic here").unwrap_err(), ZipError::Corrupt);
    }
}
