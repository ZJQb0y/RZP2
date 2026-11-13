//! 多进程并行块编码。
//!
//! 输入被切成互不依赖的块，交给多个工作进程并行压缩，再按块序号回填，从而把
//! 「单进程多线程」的并行模型换成「多进程」：任一工作进程崩溃不会拖垮主进程。
//!
//! - Unix（含 macOS/Linux）：`fork` + 管道。子进程经写时复制共享只读输入，零序列化。
//! - Windows：`spawn` 复用本可执行文件（`WORKER_ARG` 子命令），经 stdin/stdout 传参。
//!
//! 保持零运行时第三方依赖：Unix 侧 `fork`/`pipe`/`poll`/`waitpid` 均以 `extern "C"`
//! 直接声明，不引入 `libc`。

use crate::lzma::{self, LzmaParams};

/// Windows 工作进程的隐藏子命令标记（仅内部使用，不出现在帮助中）。
pub const WORKER_ARG: &str = "__rzp2-worker";

/// 单块编码方式。fork 与 spawn 两条路径共用同一分发函数，保证输出逐字节一致。
#[derive(Clone, Copy)]
pub enum Encoder {
    /// 完整 LZMA1 alone 流（`lzma::encode`）。
    Lzma,
    /// LZMA2 单块（不含结束标记，`lzma2::encode_chunk`）。
    Lzma2Chunk,
    /// 完整 LZMA2 帧（`lzma2::encode`）。
    Lzma2Stream,
}

impl Encoder {
    #[cfg(windows)]
    fn kind_str(self) -> &'static str {
        match self {
            Encoder::Lzma => "lzma",
            Encoder::Lzma2Chunk => "lzma2-chunk",
            Encoder::Lzma2Stream => "lzma2-stream",
        }
    }

    #[cfg(windows)]
    fn from_kind_str(s: &str) -> Option<Self> {
        match s {
            "lzma" => Some(Encoder::Lzma),
            "lzma2-chunk" => Some(Encoder::Lzma2Chunk),
            "lzma2-stream" => Some(Encoder::Lzma2Stream),
            _ => None,
        }
    }
}

/// 用 `workers` 个工作进程并行编码 `blocks`，按块序号返回结果。
///
/// `workers` 会被钳制到 `1..=块数`；`workers == 1` 或单块时直接在当前进程串行编码。
pub fn encode_blocks_parallel(
    encoder: Encoder,
    blocks: &[&[u8]],
    params: &LzmaParams,
    workers: usize,
) -> Vec<Vec<u8>> {
    let n = blocks.len();
    if n == 0 {
        return Vec::new();
    }
    let workers = workers.clamp(1, n);
    if workers == 1 {
        return (0..n).map(|i| encode_one(encoder, blocks[i], params)).collect();
    }
    run_parallel(encoder, blocks, params, workers)
}

/// 编码单个块。所有工作进程（fork 子进程 / spawn 工作进程）都调用此函数。
fn encode_one(encoder: Encoder, block: &[u8], params: &LzmaParams) -> Vec<u8> {
    match encoder {
        Encoder::Lzma => lzma::encode(block, params),
        Encoder::Lzma2Chunk => lzma::lzma2::encode_chunk(block, params),
        Encoder::Lzma2Stream => lzma::lzma2::encode(block, params, lzma::lzma2::DEFAULT_CHUNK_SIZE),
    }
}

// ---------------------------------------------------------------------------
// Unix：fork + 管道
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn run_parallel(
    encoder: Encoder,
    blocks: &[&[u8]],
    params: &LzmaParams,
    workers: usize,
) -> Vec<Vec<u8>> {
    use unix::*;

    let n = blocks.len();

    // 1. 每个工作进程一条管道，只读端由父进程持有，只写端由对应子进程持有。
    let mut pipes: Vec<[i32; 2]> = Vec::with_capacity(workers);
    for _ in 0..workers {
        let mut fds = [0i32; 2];
        if unsafe { pipe(fds.as_mut_ptr()) } != 0 {
            // 无法创建管道：退回串行。
            return (0..n).map(|i| encode_one(encoder, blocks[i], params)).collect();
        }
        pipes.push(fds);
    }

    // 2. fork 工作进程，按轮转静态分配块序号（w, w+workers, w+2*workers, ...）。
    let mut children: Vec<i32> = Vec::with_capacity(workers);
    for w in 0..workers {
        let pid = unsafe { fork() };
        if pid < 0 {
            // fork 失败：关闭父进程持有的所有 fd，回收已派生的子进程后退回串行。
            for fds in &pipes {
                unsafe {
                    close(fds[0]);
                    close(fds[1]);
                }
            }
            for &pid in &children {
                let mut status = 0i32;
                unsafe {
                    waitpid(pid, &mut status, 0);
                }
            }
            return (0..n).map(|i| encode_one(encoder, blocks[i], params)).collect();
        }
        if pid == 0 {
            // 子进程：只保留自己的写端，其余 fd 全部关闭。
            for (i, fds) in pipes.iter().enumerate() {
                unsafe {
                    close(fds[0]);
                }
                if i != w {
                    unsafe {
                        close(fds[1]);
                    }
                }
            }
            let write_fd = pipes[w][1];
            let mut i = w;
            while i < n {
                let encoded = encode_one(encoder, blocks[i], params);
                // 帧：index(u32 LE) + len(u32 LE) + data。
                unsafe {
                    write_record(write_fd, i as u32, &encoded);
                }
                i += workers;
            }
            unsafe {
                close(write_fd);
                _exit(0);
            }
        }
        children.push(pid);
    }

    // 3. 父进程：关闭所有写端，经 poll 汇聚各子进程结果。
    for fds in &pipes {
        unsafe {
            close(fds[1]);
        }
    }

    let mut read_fds: Vec<i32> = pipes.iter().map(|f| f[0]).collect();
    let mut slots: Vec<Option<Vec<u8>>> = (0..n).map(|_| None).collect();
    let mut collected = 0usize;

    while collected < n {
        let mut pfds: Vec<PollFd> = Vec::new();
        let mut fd_to_worker: Vec<usize> = Vec::new();
        for (w, &fd) in read_fds.iter().enumerate() {
            if fd >= 0 {
                pfds.push(PollFd {
                    fd,
                    events: POLLIN,
                    revents: 0,
                });
                fd_to_worker.push(w);
            }
        }
        if pfds.is_empty() {
            break;
        }
        let rc = unsafe { poll(pfds.as_mut_ptr(), pfds.len(), -1) };
        if rc < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break; // poll 出错：退回串行补齐缺失块。
        }
        for (k, pfd) in pfds.iter().enumerate() {
            if pfd.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL) == 0 {
                continue;
            }
            let w = fd_to_worker[k];
            match unsafe { read_record(pfd.fd) } {
                Some((idx, data)) => {
                    slots[idx as usize] = Some(data);
                    collected += 1;
                }
                None => {
                    // 该子进程已关闭写端（正常结束或提前崩溃）。
                    read_fds[w] = -1;
                }
            }
        }
    }

    // 4. 回收子进程，避免僵尸进程。
    for &pid in &children {
        let mut status = 0i32;
        loop {
            let r = unsafe { waitpid(pid, &mut status, 0) };
            if r == pid {
                break;
            }
            if r < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
        }
    }
    for fds in &pipes {
        unsafe {
            close(fds[0]);
        }
    }

    // 5. 按块序号回填；个别子进程崩溃导致缺失的块在当前进程串行补齐。
    (0..n)
        .map(|i| slots[i].take().unwrap_or_else(|| encode_one(encoder, blocks[i], params)))
        .collect()
}

/// Unix 侧的最小 POSIX FFI（零依赖，不引入 libc）。
#[cfg(unix)]
mod unix {
    use std::os::raw::{c_int, c_short, c_void};

    pub const POLLIN: c_short = 0x0001;
    pub const POLLHUP: c_short = 0x0010;
    pub const POLLERR: c_short = 0x0008;
    pub const POLLNVAL: c_short = 0x0020;

    #[repr(C)]
    pub struct PollFd {
        pub fd: c_int,
        pub events: c_short,
        pub revents: c_short,
    }

    extern "C" {
        pub fn fork() -> c_int;
        pub fn pipe(fds: *mut c_int) -> c_int;
        pub fn close(fd: c_int) -> c_int;
        pub fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
        pub fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
        pub fn poll(fds: *mut PollFd, nfds: usize, timeout: c_int) -> c_int;
        pub fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
        pub fn _exit(status: c_int) -> !;
    }

    /// 写完整缓冲区，处理短写与 `EINTR`。返回是否全部写入成功。
    pub unsafe fn write_all_fd(fd: c_int, mut buf: &[u8]) -> bool {
        while !buf.is_empty() {
            let n = write(fd, buf.as_ptr() as *const c_void, buf.len());
            if n < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return false;
            }
            buf = &buf[n as usize..];
        }
        true
    }

    /// 读满缓冲区，处理短读与 `EINTR`。EOF 或出错返回 `false`。
    pub unsafe fn read_exact_fd(fd: c_int, mut buf: &mut [u8]) -> bool {
        while !buf.is_empty() {
            let n = read(fd, buf.as_mut_ptr() as *mut c_void, buf.len());
            if n < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return false;
            }
            if n == 0 {
                return false; // EOF。
            }
            let n = n as usize;
            buf = &mut buf[n..];
        }
        true
    }

    /// 写入一条结果记录 `(index, data)`。
    pub unsafe fn write_record(fd: c_int, index: u32, data: &[u8]) {
        let mut head = [0u8; 8];
        head[0..4].copy_from_slice(&index.to_le_bytes());
        head[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes());
        write_all_fd(fd, &head);
        write_all_fd(fd, data);
    }

    /// 读取一条结果记录 `(index, data)`。EOF / 出错返回 `None`。
    pub unsafe fn read_record(fd: c_int) -> Option<(u32, Vec<u8>)> {
        let mut head = [0u8; 8];
        if !read_exact_fd(fd, &mut head) {
            return None;
        }
        let index = u32::from_le_bytes(head[0..4].try_into().unwrap());
        let len = u32::from_le_bytes(head[4..8].try_into().unwrap()) as usize;
        let mut data = vec![0u8; len];
        if !read_exact_fd(fd, &mut data) {
            return None;
        }
        Some((index, data))
    }
}

// ---------------------------------------------------------------------------
// Windows：spawn 子进程 + stdin/stdout
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn run_parallel(
    encoder: Encoder,
    blocks: &[&[u8]],
    params: &LzmaParams,
    workers: usize,
) -> Vec<Vec<u8>> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    let n = blocks.len();

    // 轮转静态分配块序号。
    let mut assigned: Vec<Vec<usize>> = vec![Vec::new(); workers];
    for w in 0..workers {
        let mut i = w;
        while i < n {
            assigned[w].push(i);
            i += workers;
        }
    }

    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return (0..n).map(|i| encode_one(encoder, blocks[i], params)).collect(),
    };

    let mut children = Vec::with_capacity(workers);
    for _ in 0..workers {
        let mut cmd = Command::new(&exe);
        cmd.arg(WORKER_ARG)
            .arg(encoder.kind_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        match cmd.spawn() {
            Ok(c) => children.push(Some(c)),
            Err(_) => {
                // 任一 spawn 失败：终止已派生的子进程，整体退回串行。
                for c in children.iter_mut().flatten() {
                    let _ = c.kill();
                    let _ = c.wait();
                }
                return (0..n).map(|i| encode_one(encoder, blocks[i], params)).collect();
            }
        }
    }

    // 依次写入每个工作进程的 stdin（全部写完后统一读取，避免管道死锁）。
    for w in 0..workers {
        let mut stdin = children[w].as_mut().unwrap().stdin.take().unwrap();
        write_params(&mut stdin, params);
        let _ = write_u32(&mut stdin, assigned[w].len() as u32);
        for &i in &assigned[w] {
            let _ = write_u32(&mut stdin, i as u32);
            let _ = write_u32(&mut stdin, blocks[i].len() as u32);
            let _ = stdin.write_all(blocks[i]);
        }
        // drop stdin 关闭写端，向子进程发送 EOF。
    }

    // 依次读取每个工作进程的 stdout。
    let mut slots: Vec<Option<Vec<u8>>> = (0..n).map(|_| None).collect();
    for w in 0..workers {
        let mut stdout = children[w].as_mut().unwrap().stdout.take().unwrap();
        for _ in 0..assigned[w].len() {
            let (idx, len) = match (read_u32(&mut stdout), read_u32(&mut stdout)) {
                (Some(i), Some(l)) => (i, l as usize),
                _ => break,
            };
            let mut data = vec![0u8; len];
            if stdout.read_exact(&mut data).is_err() {
                break;
            }
            slots[idx as usize] = Some(data);
        }
    }

    for c in children.iter_mut().flatten() {
        let _ = c.wait();
    }

    (0..n)
        .map(|i| slots[i].take().unwrap_or_else(|| encode_one(encoder, blocks[i], params)))
        .collect()
}

/// Windows 工作进程入口：从 stdin 读取任务，编码后写入 stdout。由 [`run_parallel`] 派生。
#[cfg(windows)]
pub fn worker_main() -> i32 {
    use std::io::{Read, Write};

    let encoder = match std::env::args().nth(2).as_deref().and_then(Encoder::from_kind_str) {
        Some(e) => e,
        None => return 2,
    };

    let stdin = std::io::stdin();
    let mut r = stdin.lock();
    let stdout = std::io::stdout();
    let mut w = stdout.lock();

    let params = match read_params(&mut r) {
        Some(p) => p,
        None => return 0,
    };
    let count = match read_u32(&mut r) {
        Some(c) => c,
        None => return 0,
    };

    for _ in 0..count {
        let idx = match read_u32(&mut r) {
            Some(v) => v,
            None => return 0,
        };
        let len = match read_u32(&mut r) {
            Some(v) => v as usize,
            None => return 0,
        };
        let mut block = vec![0u8; len];
        if r.read_exact(&mut block).is_err() {
            return 0;
        }
        let encoded = encode_one(encoder, &block, &params);
        if write_u32(&mut w, idx).is_err()
            || write_u32(&mut w, encoded.len() as u32).is_err()
            || w.write_all(&encoded).is_err()
        {
            return 1;
        }
    }
    let _ = w.flush();
    0
}

#[cfg(windows)]
fn write_u32(w: &mut impl std::io::Write, v: u32) -> std::io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

#[cfg(windows)]
fn read_u32(r: &mut impl std::io::Read) -> Option<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b).ok()?;
    Some(u32::from_le_bytes(b))
}

#[cfg(windows)]
fn write_params(w: &mut impl std::io::Write, params: &LzmaParams) {
    let _ = write_u32(w, params.lc);
    let _ = write_u32(w, params.lp);
    let _ = write_u32(w, params.pb);
    let _ = write_u32(w, params.dict_size);
    let _ = write_u32(w, params.nice_len as u32);
    let _ = write_u32(w, params.max_chain as u32);
}

#[cfg(windows)]
fn read_params(r: &mut impl std::io::Read) -> Option<LzmaParams> {
    let lc = read_u32(r)?;
    let lp = read_u32(r)?;
    let pb = read_u32(r)?;
    let dict_size = read_u32(r)?;
    let nice_len = read_u32(r)? as usize;
    let max_chain = read_u32(r)? as usize;
    Some(LzmaParams {
        lc,
        lp,
        pb,
        dict_size,
        nice_len,
        max_chain,
    })
}

// ---------------------------------------------------------------------------
// 其他平台：退回串行（保证跨目标编译）。
// ---------------------------------------------------------------------------

#[cfg(not(any(unix, windows)))]
fn run_parallel(
    encoder: Encoder,
    blocks: &[&[u8]],
    params: &LzmaParams,
    _workers: usize,
) -> Vec<Vec<u8>> {
    (0..blocks.len())
        .map(|i| encode_one(encoder, blocks[i], params))
        .collect()
}
