//! ZIP 归档解压（PKWARE ZIP 子集）。
//!
//! 从文件末尾的「中央目录结束记录」定位中央目录，再逐条读取本地文件头并解压。
//! 支持压缩方法 0（存储）与 8（DEFLATE，复用 [`crate::deflate`]），
//! 校验每项的 CRC32 与未压缩大小；暂不支持加密、多卷与 zip64。

use std::fmt;

use crate::archive::{Entry, EntryKind};
use crate::crc::crc32;
use crate::deflate;

const EOCD_SIG: u32 = 0x0605_4b50; // PK\x05\x06
const CENTRAL_SIG: u32 = 0x0201_4b50; // PK\x01\x02
const LOCAL_SIG: u32 = 0x0403_4b50; // PK\x03\x04

const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

/// ZIP 解压错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZipError {
    Truncated,
    Corrupt,
    /// 未找到中央目录结束记录。
    NoEocd,
    UnsupportedMethod(u16),
    /// 暂不支持的 ZIP 特性（加密 / 多卷 / zip64）。
    UnsupportedFeature(&'static str),
    CrcMismatch,
    SizeMismatch,
    BadUtf8,
    Deflate(deflate::DeflateError),
}

impl fmt::Display for ZipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated zip stream"),
            Self::Corrupt => write!(f, "corrupt zip stream"),
            Self::NoEocd => write!(f, "zip end-of-central-directory not found"),
            Self::UnsupportedMethod(m) => write!(f, "unsupported zip compression method {m}"),
            Self::UnsupportedFeature(feature) => write!(f, "unsupported zip feature: {feature}"),
            Self::CrcMismatch => write!(f, "zip entry CRC32 mismatch"),
            Self::SizeMismatch => write!(f, "zip entry size mismatch"),
            Self::BadUtf8 => write!(f, "invalid UTF-8 in zip entry name"),
            Self::Deflate(e) => write!(f, "deflate error: {e}"),
        }
    }
}

impl std::error::Error for ZipError {}

impl From<deflate::DeflateError> for ZipError {
    fn from(e: deflate::DeflateError) -> Self {
        Self::Deflate(e)
    }
}

/// 中央目录里的一条条目。
struct CdEntry {
    method: u16,
    crc: u32,
    comp_size: u32,
    uncomp_size: u32,
    local_offset: u32,
    external_attr: u32,
    mtime: i64,
    mode: u32,
    name: Vec<u8>,
}

/// 解压整个 ZIP 归档，返回条目列表。
pub fn decode(input: &[u8]) -> Result<Vec<Entry>, ZipError> {
    let eocd = find_eocd(input).ok_or(ZipError::NoEocd)?;

    // 磁盘号与条目数。
    if le16(input, eocd + 4)? != 0 {
        return Err(ZipError::UnsupportedFeature("multi-disk"));
    }
    let total = le16(input, eocd + 10)? as usize;
    let cd_size = le32(input, eocd + 12)? as usize;
    let cd_offset = le32(input, eocd + 16)? as usize;

    if total == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_offset == 0xFFFF_FFFF {
        return Err(ZipError::UnsupportedFeature("zip64"));
    }

    let mut entries = Vec::with_capacity(total);
    let mut pos = cd_offset;
    for _ in 0..total {
        let cd = parse_central_entry(input, &mut pos)?;
        let data = extract_data(input, &cd)?;
        let kind = classify(&cd);
        let name = String::from_utf8(cd.name.clone()).map_err(|_| ZipError::BadUtf8)?;
        let entry = match kind {
            EntryKind::Dir => Entry::dir(trim_dir_slash(&name), cd.mode, cd.mtime),
            EntryKind::Symlink => {
                let target = String::from_utf8(data).map_err(|_| ZipError::BadUtf8)?;
                Entry::symlink(name, cd.mode, cd.mtime, target)
            }
            EntryKind::File => Entry::file(name, cd.mode, cd.mtime, data),
        };
        entries.push(entry);
    }

    Ok(entries)
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

/// 解析一条中央目录条目，并把游标推进到下一项。
fn parse_central_entry(input: &[u8], pos: &mut usize) -> Result<CdEntry, ZipError> {
    if le32(input, *pos)? != CENTRAL_SIG {
        return Err(ZipError::Corrupt);
    }
    let flags = le16(input, *pos + 8)?;
    let method = le16(input, *pos + 10)?;
    let mod_time = le16(input, *pos + 12)?;
    let mod_date = le16(input, *pos + 14)?;
    let crc = le32(input, *pos + 16)?;
    let comp_size = le32(input, *pos + 20)?;
    let uncomp_size = le32(input, *pos + 24)?;
    let name_len = le16(input, *pos + 28)? as usize;
    let extra_len = le16(input, *pos + 30)? as usize;
    let comment_len = le16(input, *pos + 32)? as usize;
    let external_attr = le32(input, *pos + 38)?;
    let local_offset = le32(input, *pos + 42)?;

    // 加密位（bit 0）。
    if flags & 0x0001 != 0 {
        return Err(ZipError::UnsupportedFeature("encryption"));
    }

    let name_start = *pos + 46;
    let name = input
        .get(name_start..name_start + name_len)
        .ok_or(ZipError::Truncated)?
        .to_vec();
    *pos = name_start + name_len + extra_len + comment_len;

    let mtime = dos_to_unix(mod_date, mod_time);
    let mode = unix_mode(external_attr, classify_from_name(&name));

    Ok(CdEntry {
        method,
        crc,
        comp_size,
        uncomp_size,
        local_offset,
        external_attr,
        mtime,
        mode,
        name,
    })
}

/// 读取本地文件头并解压条目数据。
fn extract_data(input: &[u8], cd: &CdEntry) -> Result<Vec<u8>, ZipError> {
    let off = cd.local_offset as usize;
    if le32(input, off)? != LOCAL_SIG {
        return Err(ZipError::Corrupt);
    }
    let name_len = le16(input, off + 26)? as usize;
    let extra_len = le16(input, off + 28)? as usize;
    let data_off = off + 30 + name_len + extra_len;
    let comp = cd.comp_size as usize;
    let raw = input
        .get(data_off..data_off + comp)
        .ok_or(ZipError::Truncated)?;

    let data = match cd.method {
        METHOD_STORED => raw.to_vec(),
        METHOD_DEFLATE => deflate::decompress(raw)?,
        m => return Err(ZipError::UnsupportedMethod(m)),
    };

    if data.len() != cd.uncomp_size as usize {
        return Err(ZipError::SizeMismatch);
    }
    // 空条目 CRC 恒为 0，直接通过；其余按 crc32 校验。
    if !(cd.uncomp_size == 0 && cd.crc == 0) && crc32(&data) != cd.crc {
        return Err(ZipError::CrcMismatch);
    }

    Ok(data)
}

/// 由外部属性高 16 位（Unix 文件类型）与文件名判断条目类型。
fn classify(cd: &CdEntry) -> EntryKind {
    let ft = (cd.external_attr >> 16) & 0xF000;
    if ft == 0xA000 {
        EntryKind::Symlink
    } else if ft == 0x4000 || cd.name.ends_with(b"/") {
        EntryKind::Dir
    } else {
        EntryKind::File
    }
}

/// 仅依据文件名（目录以 `/` 结尾）判断类型，用于默认权限位。
fn classify_from_name(name: &[u8]) -> EntryKind {
    if name.ends_with(b"/") {
        EntryKind::Dir
    } else {
        EntryKind::File
    }
}

/// 从外部属性提取 Unix 权限位；无则按类型给默认值。
fn unix_mode(external_attr: u32, kind: EntryKind) -> u32 {
    let m = (external_attr >> 16) & 0xFFFF;
    if m != 0 {
        m
    } else {
        match kind {
            EntryKind::Dir => 0o755,
            EntryKind::Symlink => 0o777,
            EntryKind::File => 0o644,
        }
    }
}

/// 去掉目录名末尾的 `/`。
fn trim_dir_slash(name: &str) -> String {
    name.strip_suffix('/').unwrap_or(name).to_string()
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

/// DOS 日期/时间 → Unix 时间戳（秒）。
fn dos_to_unix(date: u16, time: u16) -> i64 {
    if date == 0 && time == 0 {
        return 0;
    }
    let year = (date >> 9) as i64 + 1980;
    let month = ((date >> 5) & 0x0F) as i64;
    let day = (date & 0x1F) as i64;
    let hour = (time >> 11) as i64;
    let minute = ((time >> 5) & 0x3F) as i64;
    let second = (time & 0x1F) as i64 * 2;
    days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second
}

/// 公历日期 → 自 1970-01-01 的天数（Howard Hinnant 算法）。
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dos_time_zero() {
        assert_eq!(dos_to_unix(0, 0), 0);
    }

    #[test]
    fn dos_time_epoch_reference() {
        // 1980-01-01 00:00:00 对应 DOS date=0x0021, time=0。
        assert_eq!(dos_to_unix(0x0021, 0), 315_532_800);
    }
}
