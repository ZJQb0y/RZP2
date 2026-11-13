//! 文件分片与合并（自研，零依赖）。
//!
//! 分片时把一个文件切成若干等大小片（最后一片可为小片），并写出一个二进制清单，
//! 记录原始文件名、分片数量、每片大小与总大小。合并时按清单顺序拼接回原文件。
//!
//! 清单布局（多字节整数一律小端）：
//!
//! ```text
//! magic(8) version(1) name_len(2) name(..) chunk_count(4) chunk_size(8) total_size(8)
//! ```
//!
//! 分片文件命名为 `<prefix>.part.00001`、`<prefix>.part.00002`、……，
//! 清单文件命名为 `<prefix>.manifest`。

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

/// 分片清单魔数。
pub const SPLIT_MAGIC: &[u8] = b"RZP2SPL1";
/// 清单文件后缀。
pub const MANIFEST_SUFFIX: &str = ".manifest";
/// 分片文件后缀（后接从 1 起、零填充到 5 位的序号）。
pub const PART_SUFFIX: &str = ".part.";
/// 默认分片大小：10 MiB。
pub const DEFAULT_CHUNK_SIZE: usize = 10 * 1024 * 1024;

/// 分片清单。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// 原始文件名（不含路径）。
    pub name: String,
    /// 分片数量。
    pub chunk_count: u32,
    /// 目标分片大小（最后一片可能更小）。
    pub chunk_size: u64,
    /// 原始文件总大小。
    pub total_size: u64,
}

/// 序列化清单为二进制字节流。
pub fn encode_manifest(m: &Manifest) -> Vec<u8> {
    let name = m.name.as_bytes();
    let mut out = Vec::with_capacity(32 + name.len());
    out.extend_from_slice(SPLIT_MAGIC);
    out.push(1u8); // 版本
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&m.chunk_count.to_le_bytes());
    out.extend_from_slice(&m.chunk_size.to_le_bytes());
    out.extend_from_slice(&m.total_size.to_le_bytes());
    out
}

/// 反序列化二进制清单。
pub fn decode_manifest(data: &[u8]) -> Result<Manifest, String> {
    if data.len() < 8 || data[..8] != *SPLIT_MAGIC {
        return Err("不是有效的分片清单（magic 不匹配）".into());
    }
    let mut off = 8;
    if data.len() < off + 1 {
        return Err("分片清单被截断".into());
    }
    let version = data[off];
    off += 1;
    if version != 1 {
        return Err(format!("不支持的分片清单版本 {version}"));
    }

    if data.len() < off + 2 {
        return Err("分片清单被截断".into());
    }
    let name_len = u16::from_le_bytes([data[off], data[off + 1]]) as usize;
    off += 2;
    if data.len() < off + name_len {
        return Err("分片清单被截断".into());
    }
    let name = std::str::from_utf8(&data[off..off + name_len])
        .map_err(|_| "分片清单中的文件名不是合法 UTF-8".to_string())?
        .to_string();
    off += name_len;

    if data.len() < off + 4 + 8 + 8 {
        return Err("分片清单被截断".into());
    }
    let chunk_count = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
    off += 4;
    let chunk_size = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
    off += 8;
    let total_size = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());

    Ok(Manifest {
        name,
        chunk_count,
        chunk_size,
        total_size,
    })
}

/// 由前缀与序号（从 1 起）构造分片文件路径。
pub fn chunk_path(prefix: &str, index: u32) -> String {
    format!("{prefix}{PART_SUFFIX}{index:05}")
}

/// 由用户输入（清单路径或任意分片路径）定位 `(前缀, 清单路径)`。
pub fn locate_manifest(input: &str) -> Result<(String, String), String> {
    if let Some(prefix) = input.strip_suffix(MANIFEST_SUFFIX) {
        return Ok((prefix.to_string(), input.to_string()));
    }
    if let Some(idx) = input.rfind(PART_SUFFIX) {
        let prefix = &input[..idx];
        return Ok((prefix.to_string(), format!("{prefix}{MANIFEST_SUFFIX}")));
    }
    Err(format!(
        "无法从 `{input}` 定位分片清单（请指定 .manifest 或 .part 文件）"
    ))
}

/// 拆分文件为多个分片并写出清单。`progress` 接收累计已处理的字节数，返回分片数量。
pub fn split_file(
    input: &str,
    prefix: &str,
    chunk_size: usize,
    force: bool,
    mut progress: impl FnMut(u64),
) -> Result<u32, String> {
    if chunk_size == 0 {
        return Err("分片大小必须大于 0".into());
    }

    let mut src = File::open(input).map_err(|e| format!("打开 `{input}` 失败: {e}"))?;
    let total_size = src
        .metadata()
        .map_err(|e| format!("读取 `{input}` 元数据失败: {e}"))?
        .len();
    let name = Path::new(input)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| input.to_string());

    // 空文件也切出 1 个空分片，保证合并可完整还原。
    let chunk_count = if total_size == 0 {
        1
    } else {
        total_size.div_ceil(chunk_size as u64) as u32
    };

    // 先整体检查输出是否已存在，避免写一半才发现冲突。
    let manifest_path = format!("{prefix}{MANIFEST_SUFFIX}");
    let mut outputs = vec![manifest_path.clone()];
    for i in 1..=chunk_count {
        outputs.push(chunk_path(prefix, i));
    }
    if !force {
        for p in &outputs {
            if Path::new(p).exists() {
                return Err(format!("输出 `{p}` 已存在（用 --force 覆盖）"));
            }
        }
    }

    let mut buf = vec![0u8; chunk_size];
    let mut done = 0u64;
    for i in 1..=chunk_count {
        let n = src
            .read(&mut buf)
            .map_err(|e| format!("读取 `{input}` 失败: {e}"))?;
        let path = chunk_path(prefix, i);
        let mut dst = File::create(&path).map_err(|e| format!("创建 `{path}` 失败: {e}"))?;
        dst.write_all(&buf[..n])
            .map_err(|e| format!("写入 `{path}` 失败: {e}"))?;
        done += n as u64;
        progress(done);
    }

    let manifest = Manifest {
        name,
        chunk_count,
        chunk_size: chunk_size as u64,
        total_size,
    };
    fs::write(&manifest_path, encode_manifest(&manifest))
        .map_err(|e| format!("写入 `{manifest_path}` 失败: {e}"))?;

    Ok(chunk_count)
}

/// 合并分片为原文件。`input` 可为清单路径或任意分片路径，`progress` 接收累计已写字节数。
pub fn merge_file(
    input: &str,
    output: &str,
    force: bool,
    mut progress: impl FnMut(u64),
) -> Result<u64, String> {
    if !force && Path::new(output).exists() {
        return Err(format!("输出 `{output}` 已存在（用 --force 覆盖）"));
    }

    let (prefix, manifest_path) = locate_manifest(input)?;
    let mdata =
        fs::read(&manifest_path).map_err(|e| format!("读取清单 `{manifest_path}` 失败: {e}"))?;
    let manifest = decode_manifest(&mdata)?;

    let mut dst = File::create(output).map_err(|e| format!("创建 `{output}` 失败: {e}"))?;
    let mut done = 0u64;
    for i in 1..=manifest.chunk_count {
        let path = chunk_path(&prefix, i);
        let data = fs::read(&path).map_err(|e| format!("读取分片 `{path}` 失败: {e}"))?;
        dst.write_all(&data)
            .map_err(|e| format!("写入 `{output}` 失败: {e}"))?;
        done += data.len() as u64;
        progress(done);
    }

    if done != manifest.total_size {
        return Err(format!(
            "合并后大小 {} 与清单记录 {} 不符",
            done, manifest.total_size
        ));
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_roundtrip() {
        let m = Manifest {
            name: "照片.tar".into(),
            chunk_count: 7,
            chunk_size: 1024,
            total_size: 7000,
        };
        let enc = encode_manifest(&m);
        assert_eq!(decode_manifest(&enc).unwrap(), m);
    }

    #[test]
    fn manifest_rejects_bad_magic() {
        assert!(decode_manifest(b"notsplit").is_err());
    }

    #[test]
    fn locate_manifest_from_manifest_and_chunk() {
        let (p1, m1) = locate_manifest("dir/foo.manifest").unwrap();
        assert_eq!(p1, "dir/foo");
        assert_eq!(m1, "dir/foo.manifest");

        let (p2, m2) = locate_manifest("dir/foo.part.00003").unwrap();
        assert_eq!(p2, "dir/foo");
        assert_eq!(m2, "dir/foo.manifest");
    }

    #[test]
    fn chunk_path_format() {
        assert_eq!(chunk_path("x", 1), "x.part.00001");
        assert_eq!(chunk_path("x", 12), "x.part.00012");
    }
}
