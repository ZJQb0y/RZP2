//! tar 归档解析（POSIX ustar / GNU tar 常见子集）。
//!
//! 读取 512 字节块头，解析为 [`crate::archive::Entry`]，与现有归档解包流程打通，
//! 从而支持 `.tar`、`.tar.gz`、`.tar.xz` 等「tar + 压缩」组合。

use std::fmt;

use crate::archive::Entry;

const BLOCK_SIZE: usize = 512;

/// tar 解析错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TarError {
    Truncated,
    /// 头校验和不匹配。
    BadChecksum,
    /// 非法八进制字段。
    BadOctal,
    /// 文件名非 UTF-8。
    BadUtf8,
    /// 结束块之前过早到达流尾。
    UnexpectedEof,
    /// 不支持的条目类型。
    UnsupportedType(u8),
}

impl fmt::Display for TarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated tar stream"),
            Self::BadChecksum => write!(f, "tar header checksum mismatch"),
            Self::BadOctal => write!(f, "invalid octal field in tar header"),
            Self::BadUtf8 => write!(f, "invalid UTF-8 in tar entry name"),
            Self::UnexpectedEof => write!(f, "unexpected end of tar stream"),
            Self::UnsupportedType(t) => write!(f, "unsupported tar entry type {t:#x}"),
        }
    }
}

impl std::error::Error for TarError {}

/// 解析整个 tar 归档，返回条目列表。
pub fn decode(input: &[u8]) -> Result<Vec<Entry>, TarError> {
    let mut entries = Vec::new();
    let mut pos = 0usize;

    // GNU 长文件名 / 长链接名：读取到 'L' / 'K' 条目后暂存，用于下一个条目。
    let mut pending_name: Option<Vec<u8>> = None;
    let mut pending_link: Option<Vec<u8>> = None;

    loop {
        if pos + BLOCK_SIZE > input.len() {
            return Err(TarError::Truncated);
        }
        let block = &input[pos..pos + BLOCK_SIZE];

        // 全零块表示归档结束。
        if block.iter().all(|&b| b == 0) {
            break;
        }

        let header = parse_header(block)?;

        // 数据块大小：向上取整到 512 的倍数。
        let data_size = header.size as usize;
        let padded = data_size.div_ceil(BLOCK_SIZE) * BLOCK_SIZE;
        let data_end = pos + BLOCK_SIZE + data_size;
        if data_end > input.len() {
            return Err(TarError::Truncated);
        }
        let data = &input[pos + BLOCK_SIZE..pos + BLOCK_SIZE + data_size];

        // 消费一个条目。
        match header.typeflag {
            b'L' => {
                pending_name = Some(data.to_vec());
            }
            b'K' => {
                pending_link = Some(data.to_vec());
            }
            b'x' | b'g' => {
                // PAX / 全局扩展头：跳过，不输出条目。
            }
            _ => {
                let name = match pending_name.take() {
                    Some(n) => String::from_utf8(n).map_err(|_| TarError::BadUtf8)?,
                    None => header.name.clone(),
                };
                let link_target = match pending_link.take() {
                    Some(l) => String::from_utf8(l).map_err(|_| TarError::BadUtf8)?,
                    None => header.linkname.clone(),
                };

                let entry = match header.typeflag {
                    b'0' | b'\0' | b'7' => {
                        Entry::file(name, header.mode, header.mtime, data.to_vec())
                    }
                    b'5' => Entry::dir(name, header.mode, header.mtime),
                    b'2' => Entry::symlink(name, header.mode, header.mtime, link_target),
                    b'1' => Entry::symlink(name, header.mode, header.mtime, link_target),
                    _ => return Err(TarError::UnsupportedType(header.typeflag)),
                };
                entries.push(entry);
            }
        }

        pos += BLOCK_SIZE + padded;
    }

    Ok(entries)
}

/// 已解析的 tar 头（不含数据）。
struct RawHeader {
    name: String,
    linkname: String,
    mode: u32,
    mtime: i64,
    size: u64,
    typeflag: u8,
}

/// 解析一个 512 字节 tar 头块。
fn parse_header(block: &[u8]) -> Result<RawHeader, TarError> {
    // 校验和：chksum 字段（148..156）按 8 个空格参与求和。
    let mut sum = 0u64;
    for (i, &b) in block.iter().enumerate() {
        sum += if (148..156).contains(&i) {
            b' ' as u64
        } else {
            b as u64
        };
    }
    let stored = parse_octal(&block[148..156])?;
    if stored != sum {
        return Err(TarError::BadChecksum);
    }

    let typeflag = block[156];

    // 文件名：name(0..100) + 可选 prefix(345..500)。
    let raw_name = cstr(&block[0..100]);
    let raw_prefix = cstr(&block[345..500]);
    let name = if raw_prefix.is_empty() {
        String::from_utf8(raw_name.to_vec()).map_err(|_| TarError::BadUtf8)?
    } else {
        let p = String::from_utf8(raw_prefix.to_vec()).map_err(|_| TarError::BadUtf8)?;
        let n = String::from_utf8(raw_name.to_vec()).map_err(|_| TarError::BadUtf8)?;
        format!("{p}/{n}")
    };

    let linkname =
        String::from_utf8(cstr(&block[157..257]).to_vec()).map_err(|_| TarError::BadUtf8)?;

    let mode = parse_octal(&block[100..108])? as u32;
    let mtime = parse_octal(&block[136..148])? as i64;
    let size = parse_octal(&block[124..136])?;

    Ok(RawHeader {
        name,
        linkname,
        mode,
        mtime,
        size,
        typeflag,
    })
}

/// 解析八进制字段（NUL / 空格填充），空字段返回 0。
fn parse_octal(field: &[u8]) -> Result<u64, TarError> {
    let end = field
        .iter()
        .position(|&b| b == 0 || b == b' ')
        .unwrap_or(field.len());
    let s = &field[..end];
    if s.is_empty() {
        return Ok(0);
    }
    let mut v = 0u64;
    for &b in s {
        if !(b'0'..=b'7').contains(&b) {
            return Err(TarError::BadOctal);
        }
        v = v * 8 + (b - b'0') as u64;
    }
    Ok(v)
}

/// 截取到首个 NUL 字节（不含 NUL）。
fn cstr(field: &[u8]) -> &[u8] {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    &field[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_archive() {
        // 两个全零块。
        let data = [0u8; BLOCK_SIZE * 2];
        assert!(decode(&data).unwrap().is_empty());
    }

    #[test]
    fn rejects_bad_checksum() {
        let mut block = [0u8; BLOCK_SIZE];
        // 任意非零内容，校验和必然不匹配。
        block[0] = b'a';
        assert_eq!(decode(&block), Err(TarError::BadChecksum));
    }

    #[test]
    fn truncation_rejected() {
        let mut block = [0u8; BLOCK_SIZE];
        block[156] = b'5'; // 目录
                           // 写入合法校验和：计算时 chksum 字段按空格参与。
        let sum: u64 = block
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                if (148..156).contains(&i) {
                    b' ' as u64
                } else {
                    b as u64
                }
            })
            .sum();
        write_octal(&mut block[148..156], sum);
        // 缺少结束块：目录条目后应再有两个全零块，这里直接截断。
        assert_eq!(decode(&block), Err(TarError::Truncated));
    }

    fn write_octal(field: &mut [u8], mut v: u64) {
        // 左零填充的八进制，供 parse_octal 完整读取。
        for b in field.iter_mut() {
            *b = b'0';
        }
        let mut i = field.len();
        while i > 0 {
            i -= 1;
            field[i] = b'0' + (v % 8) as u8;
            v /= 8;
        }
    }
}
