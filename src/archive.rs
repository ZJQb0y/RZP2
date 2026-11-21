//! 归档流：把多个文件 / 目录 / 符号链接打包为单一字节流。
//!
//! 归档流本身是「未压缩明文」，随后作为载荷交给 LZMA 压缩与（可选）加密。
//! 布局（多字节整数一律小端）：
//!
//! ```text
//! 每个条目:
//!   kind(1) mode(4) mtime(8) name_len(2) name(..)
//!   [symlink: link_len(2) link(..)]
//!   size(8) data(size)
//! 结束标记:
//!   kind = 0xFF
//! ```
//!
//! `kind`：0 = 普通文件、1 = 目录、2 = 符号链接。

use std::fmt;

/// 归档条目类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
}

impl EntryKind {
    fn to_byte(self) -> u8 {
        match self {
            Self::File => 0,
            Self::Dir => 1,
            Self::Symlink => 2,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::File),
            1 => Some(Self::Dir),
            2 => Some(Self::Symlink),
            _ => None,
        }
    }
}

/// 归档中的一个条目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// 相对路径，使用 `/` 作为分隔符。
    pub path: String,
    pub kind: EntryKind,
    /// Unix 权限位。
    pub mode: u32,
    /// 修改时间（Unix 秒）。
    pub mtime: i64,
    /// 文件内容（目录 / 符号链接为空）。
    pub data: Vec<u8>,
    /// 符号链接目标（仅符号链接有意义）。
    pub link_target: String,
}

impl Entry {
    pub fn file(path: String, mode: u32, mtime: i64, data: Vec<u8>) -> Self {
        Self {
            path,
            kind: EntryKind::File,
            mode,
            mtime,
            data,
            link_target: String::new(),
        }
    }

    pub fn dir(path: String, mode: u32, mtime: i64) -> Self {
        Self {
            path,
            kind: EntryKind::Dir,
            mode,
            mtime,
            data: Vec::new(),
            link_target: String::new(),
        }
    }

    pub fn symlink(path: String, mode: u32, mtime: i64, link_target: String) -> Self {
        Self {
            path,
            kind: EntryKind::Symlink,
            mode,
            mtime,
            data: Vec::new(),
            link_target,
        }
    }
}

/// 归档流结束标记（一个 `kind` 字节）。
const END_MARKER: u8 = 0xFF;

/// 归档解析错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveError {
    Truncated,
    BadKind(u8),
    BadUtf8,
    /// 结束标记后仍有数据。
    TrailingData,
    /// 不安全的条目路径（绝对路径或包含 `..`）。
    UnsafePath(String),
    /// 底层 I/O 错误。
    Io(std::io::ErrorKind),
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated archive stream"),
            Self::BadKind(k) => write!(f, "invalid archive entry kind {k}"),
            Self::BadUtf8 => write!(f, "invalid UTF-8 in archive entry name"),
            Self::TrailingData => write!(f, "trailing data after archive end marker"),
            Self::UnsafePath(p) => write!(f, "unsafe archive entry path `{p}`"),
            Self::Io(e) => write!(f, "archive I/O error: {e:?}"),
        }
    }
}

impl std::error::Error for ArchiveError {}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_i64(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// 把条目列表编码为归档流。
pub fn encode_archive(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        out.push(e.kind.to_byte());
        put_u32(&mut out, e.mode);
        put_i64(&mut out, e.mtime);
        let name = e.path.as_bytes();
        put_u16(&mut out, name.len() as u16);
        out.extend_from_slice(name);
        if e.kind == EntryKind::Symlink {
            let link = e.link_target.as_bytes();
            put_u16(&mut out, link.len() as u16);
            out.extend_from_slice(link);
        }
        put_u64(&mut out, e.data.len() as u64);
        out.extend_from_slice(&e.data);
    }
    out.push(END_MARKER);
    out
}

/// 从归档流解析条目列表。
pub fn decode_archive(data: &[u8]) -> Result<Vec<Entry>, ArchiveError> {
    let mut out = Vec::new();
    let mut off = 0usize;

    loop {
        if off >= data.len() {
            return Err(ArchiveError::Truncated);
        }
        let kind = data[off];
        off += 1;
        if kind == END_MARKER {
            break;
        }
        let kind = EntryKind::from_byte(kind).ok_or(ArchiveError::BadKind(kind))?;

        if off + 4 + 8 + 2 > data.len() {
            return Err(ArchiveError::Truncated);
        }
        let mode = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        off += 4;
        let mtime = i64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        off += 8;
        let name_len = u16::from_le_bytes(data[off..off + 2].try_into().unwrap()) as usize;
        off += 2;
        if off + name_len > data.len() {
            return Err(ArchiveError::Truncated);
        }
        let path = std::str::from_utf8(&data[off..off + name_len])
            .map_err(|_| ArchiveError::BadUtf8)?
            .to_string();
        off += name_len;

        let mut link_target = String::new();
        if kind == EntryKind::Symlink {
            if off + 2 > data.len() {
                return Err(ArchiveError::Truncated);
            }
            let link_len = u16::from_le_bytes(data[off..off + 2].try_into().unwrap()) as usize;
            off += 2;
            if off + link_len > data.len() {
                return Err(ArchiveError::Truncated);
            }
            link_target = std::str::from_utf8(&data[off..off + link_len])
                .map_err(|_| ArchiveError::BadUtf8)?
                .to_string();
            off += link_len;
        }

        if off + 8 > data.len() {
            return Err(ArchiveError::Truncated);
        }
        let size = u64::from_le_bytes(data[off..off + 8].try_into().unwrap()) as usize;
        off += 8;
        if off + size > data.len() {
            return Err(ArchiveError::Truncated);
        }
        let content = data[off..off + size].to_vec();
        off += size;

        out.push(Entry {
            path,
            kind,
            mode,
            mtime,
            data: content,
            link_target,
        });
    }

    Ok(out)
}

/// 流式解析出的条目头（不含文件内容）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StreamEntry {
    pub path: String,
    pub kind: EntryKind,
    pub mode: u32,
    pub mtime: i64,
    pub link_target: String,
    /// 文件内容长度（目录 / 符号链接为 0）。
    pub size: u64,
}

/// 流式解包回调：由调用方实现（如把条目写到磁盘）。
///
/// 普通文件条目按 `on_file_start` → 多次 `on_file_data` → `on_file_end` 的
/// 顺序回调，内容以分块形式流入，不会整块缓存；目录与符号链接走 `on_entry`。
pub(crate) trait EntrySink {
    fn on_entry(&mut self, entry: &StreamEntry) -> Result<(), ArchiveError>;
    fn on_file_start(&mut self, entry: &StreamEntry) -> Result<(), ArchiveError>;
    fn on_file_data(&mut self, data: &[u8]) -> Result<(), ArchiveError>;
    fn on_file_end(&mut self) -> Result<(), ArchiveError>;
}

/// 归档流增量解析器：边接收解压后的归档字节，边通过 [`EntrySink`] 回调条目。
///
/// 与 [`decode_archive`] 等价，但文件内容以流式分块传递，避免整包构造成
/// `Vec<Entry>` 并复制所有文件数据。
pub(crate) struct StreamUnpacker {
    buf: Vec<u8>,
    state: State,
    count: u64,
}

#[derive(Clone, Copy)]
enum State {
    Header,
    File { remaining: u64 },
    Finished,
}

enum Parsed {
    Entry(StreamEntry, usize),
    End,
    Incomplete,
}

impl StreamUnpacker {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            state: State::Header,
            count: 0,
        }
    }

    /// 喂入一段解压后的归档字节流，并驱动 [`EntrySink`] 回调。
    pub fn feed<S: EntrySink>(&mut self, data: &[u8], sink: &mut S) -> Result<(), ArchiveError> {
        if matches!(self.state, State::Finished) {
            if !data.is_empty() {
                return Err(ArchiveError::TrailingData);
            }
            return Ok(());
        }
        self.buf.extend_from_slice(data);

        loop {
            match self.state {
                State::Header => match parse_header(&self.buf)? {
                    Parsed::End => {
                        // END_MARKER 是单个 0xFF 字节，其后不允许再有任何数据。
                        if self.buf.len() > 1 {
                            return Err(ArchiveError::TrailingData);
                        }
                        self.buf.clear();
                        self.state = State::Finished;
                        break;
                    }
                    Parsed::Entry(e, consumed) => {
                        self.buf.drain(..consumed);
                        match e.kind {
                            EntryKind::File => {
                                self.state = State::File { remaining: e.size };
                                sink.on_file_start(&e)?;
                            }
                            _ => {
                                sink.on_entry(&e)?;
                                self.count += 1;
                            }
                        }
                    }
                    Parsed::Incomplete => break,
                },
                State::File { remaining } => {
                    if self.buf.is_empty() {
                        break;
                    }
                    let mut remaining = remaining;
                    let n = (self.buf.len() as u64).min(remaining) as usize;
                    sink.on_file_data(&self.buf[..n])?;
                    self.buf.drain(..n);
                    remaining -= n as u64;
                    if remaining == 0 {
                        sink.on_file_end()?;
                        self.state = State::Header;
                        self.count += 1;
                    } else {
                        self.state = State::File { remaining };
                    }
                }
                State::Finished => break,
            }
        }
        Ok(())
    }

    /// 校验流已正常结束（见到 END_MARKER），返回已解包条目数。
    pub fn finish(&self) -> Result<u64, ArchiveError> {
        if !matches!(self.state, State::Finished) {
            return Err(ArchiveError::Truncated);
        }
        Ok(self.count)
    }
}

/// 从缓冲中尝试解析一个完整条目头；返回消费的字节数，数据不足时返回 `Incomplete`。
fn parse_header(buf: &[u8]) -> Result<Parsed, ArchiveError> {
    if buf.is_empty() {
        return Ok(Parsed::Incomplete);
    }
    let kind_byte = buf[0];
    if kind_byte == END_MARKER {
        return Ok(Parsed::End);
    }
    let kind = EntryKind::from_byte(kind_byte).ok_or(ArchiveError::BadKind(kind_byte))?;

    // kind(1) + mode(4) + mtime(8) + name_len(2)。
    if buf.len() < 15 {
        return Ok(Parsed::Incomplete);
    }
    let mode = u32::from_le_bytes(buf[1..5].try_into().unwrap());
    let mtime = i64::from_le_bytes(buf[5..13].try_into().unwrap());
    let name_len = u16::from_le_bytes(buf[13..15].try_into().unwrap()) as usize;
    let mut off = 15;
    if buf.len() < off + name_len {
        return Ok(Parsed::Incomplete);
    }
    let path = std::str::from_utf8(&buf[off..off + name_len])
        .map_err(|_| ArchiveError::BadUtf8)?
        .to_string();
    off += name_len;

    let mut link_target = String::new();
    if kind == EntryKind::Symlink {
        if buf.len() < off + 2 {
            return Ok(Parsed::Incomplete);
        }
        let link_len = u16::from_le_bytes(buf[off..off + 2].try_into().unwrap()) as usize;
        off += 2;
        if buf.len() < off + link_len {
            return Ok(Parsed::Incomplete);
        }
        link_target = std::str::from_utf8(&buf[off..off + link_len])
            .map_err(|_| ArchiveError::BadUtf8)?
            .to_string();
        off += link_len;
    }

    if buf.len() < off + 8 {
        return Ok(Parsed::Incomplete);
    }
    let size = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
    off += 8;
    Ok(Parsed::Entry(
        StreamEntry {
            path,
            kind,
            mode,
            mtime,
            link_target,
            size,
        },
        off,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let entries = vec![
            Entry::dir("dir".into(), 0o755, 1_700_000_000),
            Entry::file("dir/a.txt".into(), 0o644, 1_700_000_001, b"hello".to_vec()),
            Entry::symlink("dir/link".into(), 0o777, 1_700_000_002, "a.txt".into()),
        ];
        let enc = encode_archive(&entries);
        let dec = decode_archive(&enc).unwrap();
        assert_eq!(dec, entries);
    }

    #[test]
    fn empty_archive() {
        let enc = encode_archive(&[]);
        assert_eq!(enc, vec![END_MARKER]);
        assert!(decode_archive(&enc).unwrap().is_empty());
    }

    #[test]
    fn truncation_rejected() {
        let entries = vec![Entry::file("a".into(), 0o644, 0, vec![1, 2, 3])];
        let enc = encode_archive(&entries);
        for cut in 0..enc.len() {
            let r = decode_archive(&enc[..cut]);
            // 截断后要么报错，要么在恰好完整边界处成功。
            if r.is_ok() {
                assert_eq!(cut, enc.len());
            }
        }
    }

    /// 收集流式解包结果，用于与 [`decode_archive`] 对照。
    struct CollectSink {
        entries: Vec<Entry>,
        current: Option<(StreamEntry, Vec<u8>)>,
    }

    impl EntrySink for CollectSink {
        fn on_entry(&mut self, entry: &StreamEntry) -> Result<(), ArchiveError> {
            self.entries.push(Entry {
                path: entry.path.clone(),
                kind: entry.kind,
                mode: entry.mode,
                mtime: entry.mtime,
                data: Vec::new(),
                link_target: entry.link_target.clone(),
            });
            Ok(())
        }
        fn on_file_start(&mut self, entry: &StreamEntry) -> Result<(), ArchiveError> {
            self.current = Some((entry.clone(), Vec::new()));
            Ok(())
        }
        fn on_file_data(&mut self, data: &[u8]) -> Result<(), ArchiveError> {
            if let Some((_, buf)) = &mut self.current {
                buf.extend_from_slice(data);
            }
            Ok(())
        }
        fn on_file_end(&mut self) -> Result<(), ArchiveError> {
            if let Some((entry, data)) = self.current.take() {
                self.entries.push(Entry {
                    path: entry.path,
                    kind: entry.kind,
                    mode: entry.mode,
                    mtime: entry.mtime,
                    data,
                    link_target: entry.link_target,
                });
            }
            Ok(())
        }
    }

    #[test]
    fn stream_unpacker_matches_decode() {
        let entries = vec![
            Entry::dir("dir".into(), 0o755, 1_700_000_000),
            Entry::file(
                "dir/a.txt".into(),
                0o644,
                1_700_000_001,
                b"hello world".to_vec(),
            ),
            Entry::file("big.bin".into(), 0o600, 1_700_000_002, vec![7u8; 100_000]),
            Entry::symlink("dir/link".into(), 0o777, 1_700_000_003, "a.txt".into()),
        ];
        let enc = encode_archive(&entries);

        let mut sink = CollectSink {
            entries: Vec::new(),
            current: None,
        };
        let mut up = StreamUnpacker::new();
        // 以不规整的块大小喂入，验证增量解析与跨块内容流式。
        for chunk in enc.chunks(7) {
            up.feed(chunk, &mut sink).unwrap();
        }
        assert_eq!(up.finish().unwrap(), entries.len() as u64);
        assert_eq!(sink.entries, entries);
    }

    #[test]
    fn stream_unpacker_rejects_trailing_data() {
        let mut enc = encode_archive(&[Entry::file("a".into(), 0o644, 0, b"x".to_vec())]);
        enc.push(0x00); // 结束标记后的尾随字节。
        let mut sink = CollectSink {
            entries: Vec::new(),
            current: None,
        };
        let mut up = StreamUnpacker::new();
        assert!(up.feed(&enc, &mut sink).is_err());
    }
}
