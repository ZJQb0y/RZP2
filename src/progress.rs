//! 零依赖终端进度条。
//!
//! 渲染形如：
//!
//! ```text
//! [===>             ]  45%  压缩  123 / 456 字节
//! ```
//!
//! 仅在 stderr 为终端时启用；非终端（重定向 / 管道）时静默，不污染数据流。

use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// 进度条主体宽度（不含两侧 `[` `]`）。
const BAR_WIDTH: usize = 20;
/// 刷新间隔，避免高频写终端造成闪烁与浪费。
const REFRESH: Duration = Duration::from_millis(80);

/// 一个可更新的进度条。`label` 表示当前工作类型（如 压缩 / 解压 / 分片 / 合并）。
pub struct Progress {
    label: &'static str,
    total: u64,
    done: u64,
    enabled: bool,
    last: Instant,
}

impl Progress {
    /// 创建进度条。`total == 0` 表示总大小未知，将退化为无百分比的无头进度显示。
    pub fn new(label: &'static str, total: u64, enabled: bool) -> Self {
        Self {
            label,
            total,
            done: 0,
            enabled,
            last: Instant::now(),
        }
    }

    /// 设置当前进度（累计已处理字节数）。内部按刷新间隔节流，避免刷屏。
    pub fn update(&mut self, done: u64) {
        self.done = done;
        if self.enabled && self.last.elapsed() >= REFRESH {
            self.last = Instant::now();
            self.render();
        }
    }

    /// 在当前进度上累加字节数。
    pub fn add(&mut self, n: u64) {
        self.update(self.done + n);
    }

    /// 结束：清空当前行，避免与后续输出粘连。禁用时无副作用。
    pub fn finish(&mut self) {
        if self.enabled {
            eprint!("\r\x1b[2K");
            let _ = std::io::stderr().flush();
        }
    }

    fn render(&self) {
        if self.total > 0 {
            let done = self.done.min(self.total);
            let pct = ((done as f64 * 100.0) / self.total as f64) as u32;
            eprint!(
                "\r[{}] {:3}%  {}  {} / {} 字节",
                self.bar(pct),
                pct,
                self.label,
                self.done,
                self.total
            );
        } else {
            eprint!("\r  {}  {} 字节", self.label, self.done);
        }
        let _ = std::io::stderr().flush();
    }

    /// 根据百分比绘制 `[===>        ]` 风格的主体。
    fn bar(&self, pct: u32) -> String {
        let filled = (pct as usize * BAR_WIDTH / 100).clamp(0, BAR_WIDTH);
        let mut s = String::with_capacity(BAR_WIDTH);
        if pct == 0 {
            s.push_str(&" ".repeat(BAR_WIDTH));
        } else if pct >= 100 {
            s.push_str(&"=".repeat(BAR_WIDTH));
        } else {
            s.push_str(&"=".repeat(filled.saturating_sub(1)));
            s.push('>');
            s.push_str(&" ".repeat(BAR_WIDTH - filled));
        }
        s
    }
}

/// 包装读取器，在读入字节时推进进度条。
pub struct ProgressReader<R: Read> {
    inner: R,
    progress: Progress,
}

impl<R: Read> ProgressReader<R> {
    pub fn new(inner: R, label: &'static str, total: u64, enabled: bool) -> Self {
        Self {
            inner,
            progress: Progress::new(label, total, enabled),
        }
    }

    pub fn finish(&mut self) {
        self.progress.finish();
    }
}

impl<R: Read> Read for ProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.progress.add(n as u64);
        Ok(n)
    }
}

/// 包装写出器，在写出字节时推进进度条。
pub struct ProgressWriter<W: Write> {
    inner: W,
    progress: Progress,
}

impl<W: Write> ProgressWriter<W> {
    pub fn new(inner: W, label: &'static str, total: u64, enabled: bool) -> Self {
        Self {
            inner,
            progress: Progress::new(label, total, enabled),
        }
    }

    pub fn finish(&mut self) {
        self.progress.finish();
    }
}

impl<W: Write> Write for ProgressWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.progress.add(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bar_edges() {
        let p = Progress::new("测试", 100, false);
        assert_eq!(p.bar(0), " ".repeat(BAR_WIDTH));
        assert_eq!(p.bar(100), "=".repeat(BAR_WIDTH));
        let mid = p.bar(50);
        assert_eq!(mid.len(), BAR_WIDTH);
        assert!(mid.contains('>'));
        assert!(mid.starts_with('='));
    }

    #[test]
    fn reader_tracks_bytes() {
        let data = b"hello world";
        let mut r = ProgressReader::new(&data[..], "读取", data.len() as u64, false);
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, data);
    }
}
