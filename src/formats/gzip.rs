//! gzip 容器（RFC 1952）解析与解压。
//!
//! 头部 + DEFLATE 载荷 + CRC32/ISIZE 尾部；支持多个 gzip 成员首尾相连的输入，
//! 与 `gzip -c` 多次输出的语义一致。仅支持 CM=8（DEFLATE）。

use std::fmt;

use crate::crc::crc32;
use crate::deflate::{self, DeflateError};

const ID1: u8 = 0x1F;
const ID2: u8 = 0x8B;
const CM_DEFLATE: u8 = 0x08;

const FLG_FHCRC: u8 = 0x02;
const FLG_FEXTRA: u8 = 0x04;
const FLG_FNAME: u8 = 0x08;
const FLG_FCOMMENT: u8 = 0x10;

/// gzip 解析/解压错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GzipError {
    Corrupt,
    Truncated,
    /// 不支持的压缩方法（非 DEFLATE）。
    UnsupportedMethod(u8),
    Deflate(DeflateError),
    CrcMismatch,
    SizeMismatch,
}

impl fmt::Display for GzipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corrupt => write!(f, "corrupt gzip stream"),
            Self::Truncated => write!(f, "truncated gzip stream"),
            Self::UnsupportedMethod(m) => write!(f, "unsupported gzip compression method {m}"),
            Self::Deflate(e) => write!(f, "deflate error: {e}"),
            Self::CrcMismatch => write!(f, "gzip CRC32 mismatch"),
            Self::SizeMismatch => write!(f, "gzip size mismatch"),
        }
    }
}

impl std::error::Error for GzipError {}

impl From<DeflateError> for GzipError {
    fn from(e: DeflateError) -> Self {
        Self::Deflate(e)
    }
}

/// 解压整个 gzip 流（可含多个成员），返回未压缩明文。
pub fn decode(input: &[u8]) -> Result<Vec<u8>, GzipError> {
    if input.len() < 2 || input[0] != ID1 || input[1] != ID2 {
        return Err(GzipError::Corrupt);
    }

    let mut out = Vec::new();
    let mut pos = 0usize;

    while pos < input.len() {
        let (data, next) = decode_member(input, pos)?;
        out.extend_from_slice(&data);
        pos = next;
    }

    Ok(out)
}

/// 解析并解压从 `start` 开始的单个 gzip 成员，返回 `(明文, 下一成员偏移)`。
fn decode_member(input: &[u8], start: usize) -> Result<(Vec<u8>, usize), GzipError> {
    if start + 10 > input.len() {
        return Err(GzipError::Truncated);
    }
    if input[start] != ID1 || input[start + 1] != ID2 {
        return Err(GzipError::Corrupt);
    }
    let cm = input[start + 2];
    if cm != CM_DEFLATE {
        return Err(GzipError::UnsupportedMethod(cm));
    }
    let flg = input[start + 3];
    let mut pos = start + 10;

    if flg & FLG_FEXTRA != 0 {
        if pos + 2 > input.len() {
            return Err(GzipError::Truncated);
        }
        let xlen = u16::from_le_bytes(input[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        if pos + xlen > input.len() {
            return Err(GzipError::Truncated);
        }
        pos += xlen;
    }
    if flg & FLG_FNAME != 0 {
        pos = skip_cstring(input, pos)?;
    }
    if flg & FLG_FCOMMENT != 0 {
        pos = skip_cstring(input, pos)?;
    }
    if flg & FLG_FHCRC != 0 {
        if pos + 2 > input.len() {
            return Err(GzipError::Truncated);
        }
        pos += 2; // 头部 CRC16，暂不校验。
    }

    // DEFLATE 载荷 + 8 字节尾部（CRC32 + ISIZE）。
    let (data, consumed) = deflate::decompress_consumed(&input[pos..])?;
    let trailer_start = pos + consumed;
    if trailer_start + 8 > input.len() {
        return Err(GzipError::Truncated);
    }
    let stored_crc =
        u32::from_le_bytes(input[trailer_start..trailer_start + 4].try_into().unwrap());
    let isize = u32::from_le_bytes(
        input[trailer_start + 4..trailer_start + 8]
            .try_into()
            .unwrap(),
    );

    if stored_crc != crc32(&data) {
        return Err(GzipError::CrcMismatch);
    }
    if (data.len() as u32).wrapping_neg() == 0 {
        // 空数据：ISIZE 恒为 0。
        if isize != 0 {
            return Err(GzipError::SizeMismatch);
        }
    } else if isize != (data.len() as u32 & 0xFFFF_FFFF) {
        return Err(GzipError::SizeMismatch);
    }

    Ok((data, trailer_start + 8))
}

/// 跳过以 NUL 结尾的字符串，返回字符串之后的位置。
fn skip_cstring(input: &[u8], mut pos: usize) -> Result<usize, GzipError> {
    while pos < input.len() {
        if input[pos] == 0 {
            return Ok(pos + 1);
        }
        pos += 1;
    }
    Err(GzipError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_magic() {
        assert_eq!(decode(b"not a gzip"), Err(GzipError::Corrupt));
    }

    #[test]
    fn truncated_header() {
        assert_eq!(decode(&[ID1, ID2]), Err(GzipError::Truncated));
    }

    #[test]
    fn unsupported_method() {
        let mut h = vec![ID1, ID2, 0x00, 0x00, 0, 0, 0, 0, 0, 0];
        h[2] = 0x07;
        assert_eq!(decode(&h), Err(GzipError::UnsupportedMethod(0x07)));
    }

    #[test]
    fn decodes_real_gzip_dynamic() {
        // `printf '...' | gzip -c` 生成（动态 Huffman 块）。
        let hex = "1f8b08000000000000030bc94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d5228014ae72456552aa4e4a7eb2918181a199b989a995b5802005b75000e37000000";
        let out = decode(&hex_bytes(hex)).unwrap();
        assert_eq!(
            out,
            b"The quick brown fox jumps over the lazy dog. 0123456789"
        );
    }

    #[test]
    fn decodes_real_gzip_small() {
        // `printf 'hello world' | gzip -c` 生成。
        let hex = "1f8b0800000000000003cb48cdc9c95728cf2fca49010085114a0d0b000000";
        let out = decode(&hex_bytes(hex)).unwrap();
        assert_eq!(out, b"hello world");
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
