//! 多进程并行块编解码。
//!
//! 输入被切成互不依赖的块，交给多个工作进程并行处理（压缩或解压），再按块序号回填，
//! 从而把「单进程多线程」的并行模型换成「多进程」：任一工作进程崩溃不会拖垮主进程。
//!
//! - Unix（含 macOS/Linux）：`fork` + 管道。子进程经写时复制共享只读输入，零序列化。
//! - Windows：`spawn` 复用本可执行文件（`WORKER_ARG` 子命令），经 stdin/stdout 传参。
//!
//! 保持零运行时第三方依赖：Unix 侧 `fork`/`pipe`/`poll`/`waitpid` 均以 `extern "C"`
//! 直接声明，不引入 `libc`。

use std::path::{Path, PathBuf};

use crate::lzma::{self, LzmaError, LzmaParams};

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

/// 工作进程执行的作业类型。
#[derive(Clone, Copy)]
enum Job {
    /// 编码一个块。
    Encode(Encoder),
    /// 解码一个完整 LZMA1 alone 流块。
    Decode,
}

impl Job {
    #[cfg(windows)]
    fn kind_str(self) -> &'static str {
        match self {
            Job::Encode(Encoder::Lzma) => "lzma",
            Job::Encode(Encoder::Lzma2Chunk) => "lzma2-chunk",
            Job::Encode(Encoder::Lzma2Stream) => "lzma2-stream",
            Job::Decode => "lzma-decode",
        }
    }

    #[cfg(windows)]
    fn from_kind_str(s: &str) -> Option<Self> {
        match s {
            "lzma" => Some(Job::Encode(Encoder::Lzma)),
            "lzma2-chunk" => Some(Job::Encode(Encoder::Lzma2Chunk)),
            "lzma2-stream" => Some(Job::Encode(Encoder::Lzma2Stream)),
            "lzma-decode" => Some(Job::Decode),
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
    encode_blocks_parallel_progress(encoder, blocks, params, workers, &mut |_| {})
}

/// 并行编码块，每完成一个块时回调 `on_progress(已完成块数)`，供进度条使用。
pub fn encode_blocks_parallel_progress(
    encoder: Encoder,
    blocks: &[&[u8]],
    params: &LzmaParams,
    workers: usize,
    on_progress: &mut dyn FnMut(usize),
) -> Vec<Vec<u8>> {
    let n = blocks.len();
    if n == 0 {
        return Vec::new();
    }
    let workers = workers.clamp(1, n);
    if workers == 1 {
        return (0..n)
            .map(|i| {
                let out = encode_one(encoder, blocks[i], params);
                on_progress(i + 1);
                out
            })
            .collect();
    }
    let slots = run_parallel(Job::Encode(encoder), blocks, params, workers, on_progress);
    slots
        .into_iter()
        .enumerate()
        .map(|(i, s)| s.unwrap_or_else(|| encode_one(encoder, blocks[i], params)))
        .collect()
}

/// 用 `workers` 个工作进程并行解码 `blocks`（每个块为完整 LZMA1 alone 流），按块序号返回结果。
///
/// 任一工作进程崩溃或解码失败时，缺失 / 失败的块会在当前进程串行补齐；若串行解码
/// 仍失败，则返回对应错误。
pub fn decode_blocks_parallel(blocks: &[&[u8]], workers: usize) -> Result<Vec<Vec<u8>>, LzmaError> {
    let n = blocks.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    let workers = workers.clamp(1, n);
    if workers == 1 {
        return blocks.iter().map(|b| lzma::decode(b)).collect();
    }
    let slots = run_parallel(Job::Decode, blocks, &LzmaParams::default(), workers, &mut |_| {});
    let mut out = Vec::with_capacity(n);
    for (i, s) in slots.into_iter().enumerate() {
        match s {
            Some(data) => out.push(data),
            None => out.push(lzma::decode(blocks[i])?),
        }
    }
    Ok(out)
}

/// 用 `workers` 个工作进程并行把文件写入磁盘（复用 fork / spawn 多进程模型）。
///
/// `files` 为 `(目标绝对路径, mode, data)`；目标路径须由调用方校验为安全路径且父目录已创建。
/// Unix 下子进程经 fork 的写时复制直接访问 `files`（零序列化）；Windows 下经 stdin
/// 序列化到工作进程。任一文件写失败或未完成时，父进程串行重写以返回具体错误。
pub fn write_files_parallel(
    files: &[(PathBuf, u32, &[u8])],
    workers: usize,
) -> Result<(), String> {
    let n = files.len();
    if n == 0 {
        return Ok(());
    }
    let workers = workers.clamp(1, n);
    if workers == 1 {
        for f in files {
            write_one(&f.0, f.1, f.2).map_err(|e| e.to_string())?;
        }
        return Ok(());
    }
    for i in run_write_parallel(files, workers) {
        write_one(&files[i].0, files[i].1, files[i].2).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// 写单个文件并（Unix 下）设置权限位。
fn write_one(dest: &Path, #[cfg_attr(not(unix), allow(unused_variables))] mode: u32, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(dest, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dest, std::fs::Permissions::from_mode(mode));
    }
    Ok(())
}

/// 编码单个块。所有工作进程（fork 子进程 / spawn 工作进程）都调用此函数。
fn encode_one(encoder: Encoder, block: &[u8], params: &LzmaParams) -> Vec<u8> {
    match encoder {
        Encoder::Lzma => lzma::encode(block, params),
        Encoder::Lzma2Chunk => lzma::lzma2::encode_chunk(block, params),
        Encoder::Lzma2Stream => lzma::lzma2::encode(block, params, lzma::lzma2::DEFAULT_CHUNK_SIZE),
    }
}

/// 执行单个作业。解码失败时返回 `Err`，由工作进程转成「失败记录」回传。
fn do_one(job: Job, block: &[u8], params: &LzmaParams) -> Result<Vec<u8>, LzmaError> {
    match job {
        Job::Encode(e) => Ok(encode_one(e, block, params)),
        Job::Decode => lzma::decode(block),
    }
}

// ---------------------------------------------------------------------------
// Unix：fork + 管道
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn run_parallel(
    job: Job,
    blocks: &[&[u8]],
    params: &LzmaParams,
    workers: usize,
    on_progress: &mut dyn FnMut(usize),
) -> Vec<Option<Vec<u8>>> {
    use unix::*;

    let n = blocks.len();

    // 1. 每个工作进程一条管道，只读端由父进程持有，只写端由对应子进程持有。
    let mut pipes: Vec<[i32; 2]> = Vec::with_capacity(workers);
    for _ in 0..workers {
        let mut fds = [0i32; 2];
        if unsafe { pipe(fds.as_mut_ptr()) } != 0 {
            // 无法创建管道：退回串行（由调用方补齐）。
            for fds in &pipes {
                unsafe {
                    close(fds[0]);
                    close(fds[1]);
                }
            }
            return vec![None; n];
        }
        pipes.push(fds);
    }

    // 2. fork 工作进程，按轮转静态分配块序号（w, w+workers, w+2*workers, ...）。
    let mut children: Vec<i32> = Vec::with_capacity(workers);
    for w in 0..workers {
        let pid = unsafe { fork() };
        if pid < 0 {
            // fork 失败：关闭父进程持有的所有 fd，回收已派生的子进程后返回，由调用方串行补齐。
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
            return vec![None; n];
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
                let (ok, data) = match do_one(job, blocks[i], params) {
                    Ok(d) => (true, d),
                    Err(_) => (false, Vec::new()),
                };
                // 帧：index(u32 LE) + ok(u8) + len(u32 LE) + data。
                unsafe {
                    write_record(write_fd, i as u32, ok, &data);
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
            break; // poll 出错：由调用方串行补齐缺失块。
        }
        for (k, pfd) in pfds.iter().enumerate() {
            if pfd.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL) == 0 {
                continue;
            }
            let w = fd_to_worker[k];
            match unsafe { read_record(pfd.fd) } {
                Some((idx, ok, data)) => {
                    if ok {
                        slots[idx as usize] = Some(data);
                    }
                    collected += 1;
                    on_progress(collected);
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

    slots
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

    /// 写入一条结果记录 `(index, ok, data)`。
    pub unsafe fn write_record(fd: c_int, index: u32, ok: bool, data: &[u8]) {
        let mut head = [0u8; 9];
        head[0..4].copy_from_slice(&index.to_le_bytes());
        head[4] = ok as u8;
        head[5..9].copy_from_slice(&(data.len() as u32).to_le_bytes());
        write_all_fd(fd, &head);
        if ok {
            write_all_fd(fd, data);
        }
    }

    /// 读取一条结果记录 `(index, ok, data)`。EOF / 出错返回 `None`。
    pub unsafe fn read_record(fd: c_int) -> Option<(u32, bool, Vec<u8>)> {
        let mut head = [0u8; 9];
        if !read_exact_fd(fd, &mut head) {
            return None;
        }
        let index = u32::from_le_bytes(head[0..4].try_into().unwrap());
        let ok = head[4] != 0;
        let len = u32::from_le_bytes(head[5..9].try_into().unwrap()) as usize;
        if !ok {
            return Some((index, false, Vec::new()));
        }
        let mut data = vec![0u8; len];
        if !read_exact_fd(fd, &mut data) {
            return None;
        }
        Some((index, true, data))
    }
}

// ---------------------------------------------------------------------------
// Windows：spawn 子进程 + stdin/stdout
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn run_parallel(
    job: Job,
    blocks: &[&[u8]],
    params: &LzmaParams,
    workers: usize,
    on_progress: &mut dyn FnMut(usize),
) -> Vec<Option<Vec<u8>>> {
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
        Err(_) => return vec![None; n],
    };

    let mut children = Vec::with_capacity(workers);
    for _ in 0..workers {
        let mut cmd = Command::new(&exe);
        cmd.arg(WORKER_ARG)
            .arg(job.kind_str())
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
                return vec![None; n];
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
    let mut collected = 0usize;
    for w in 0..workers {
        let mut stdout = children[w].as_mut().unwrap().stdout.take().unwrap();
        for _ in 0..assigned[w].len() {
            let (idx, ok, len) = match (
                read_u32(&mut stdout),
                read_u8(&mut stdout),
                read_u32(&mut stdout),
            ) {
                (Some(i), Some(o), Some(l)) => (i, o, l as usize),
                _ => break,
            };
            if ok != 0 {
                let mut data = vec![0u8; len];
                if stdout.read_exact(&mut data).is_err() {
                    break;
                }
                slots[idx as usize] = Some(data);
            }
            collected += 1;
            on_progress(collected);
        }
    }

    for c in children.iter_mut().flatten() {
        let _ = c.wait();
    }

    slots
}

/// Windows 工作进程入口：从 stdin 读取任务，处理后写入 stdout。由 [`run_parallel`] 派生。
#[cfg(windows)]
pub fn worker_main() -> i32 {
    use std::io::{Read, Write};

    // 文件写入工作进程：输入 / 输出格式与 LZMA 作业不同，单独处理。
    if std::env::args().nth(2).as_deref() == Some("write-files") {
        return write_files_worker();
    }

    let job = match std::env::args()
        .nth(2)
        .as_deref()
        .and_then(Job::from_kind_str)
    {
        Some(j) => j,
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
        let (ok, data) = match do_one(job, &block, &params) {
            Ok(d) => (1u8, d),
            Err(_) => (0u8, Vec::new()),
        };
        if write_u32(&mut w, idx).is_err()
            || write_u8(&mut w, ok).is_err()
            || write_u32(&mut w, data.len() as u32).is_err()
            || (ok != 0 && w.write_all(&data).is_err())
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
fn write_u8(w: &mut impl std::io::Write, v: u8) -> std::io::Result<()> {
    w.write_all(&[v])
}

#[cfg(windows)]
fn read_u32(r: &mut impl std::io::Read) -> Option<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b).ok()?;
    Some(u32::from_le_bytes(b))
}

#[cfg(windows)]
fn read_u8(r: &mut impl std::io::Read) -> Option<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b).ok()?;
    Some(b[0])
}

#[cfg(windows)]
fn write_params(w: &mut impl std::io::Write, params: &LzmaParams) {
    let _ = write_u32(w, params.lc);
    let _ = write_u32(w, params.lp);
    let _ = write_u32(w, params.pb);
    let _ = write_u32(w, params.dict_size);
    let _ = write_u32(w, params.nice_len as u32);
    let _ = write_u32(w, params.max_chain as u32);
    let _ = write_u8(w, params.match_finder.to_u8());
}

#[cfg(windows)]
fn read_params(r: &mut impl std::io::Read) -> Option<LzmaParams> {
    let lc = read_u32(r)?;
    let lp = read_u32(r)?;
    let pb = read_u32(r)?;
    let dict_size = read_u32(r)?;
    let nice_len = read_u32(r)? as usize;
    let max_chain = read_u32(r)? as usize;
    let match_finder = crate::lzma::MatchFinderKind::from_u8(read_u8(r)?);
    Some(LzmaParams {
        lc,
        lp,
        pb,
        dict_size,
        nice_len,
        max_chain,
        match_finder,
    })
}

// ---------------------------------------------------------------------------
// 其他平台：退回串行（保证跨目标编译）。
// ---------------------------------------------------------------------------

#[cfg(not(any(unix, windows)))]
fn run_parallel(
    job: Job,
    blocks: &[&[u8]],
    params: &LzmaParams,
    _workers: usize,
    on_progress: &mut dyn FnMut(usize),
) -> Vec<Option<Vec<u8>>> {
    (0..blocks.len())
        .map(|i| {
            let out = do_one(job, blocks[i], params).ok();
            on_progress(i + 1);
            out
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 并行写文件（fork / spawn 多进程模型）
// ---------------------------------------------------------------------------

/// Unix：fork 子进程按轮转分配文件，子进程经写时复制直接访问 `files`（零序列化），
/// 通过管道回报每个文件是否写成功；父进程汇聚后返回需串行重写的序号。
#[cfg(unix)]
fn run_write_parallel(files: &[(PathBuf, u32, &[u8])], workers: usize) -> Vec<usize> {
    use unix::*;
    let n = files.len();

    let mut pipes: Vec<[i32; 2]> = Vec::with_capacity(workers);
    for _ in 0..workers {
        let mut fds = [0i32; 2];
        if unsafe { pipe(fds.as_mut_ptr()) } != 0 {
            for fds in &pipes {
                unsafe {
                    close(fds[0]);
                    close(fds[1]);
                }
            }
            return (0..n).collect();
        }
        pipes.push(fds);
    }

    let mut children: Vec<i32> = Vec::with_capacity(workers);
    for w in 0..workers {
        let pid = unsafe { fork() };
        if pid < 0 {
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
            return (0..n).collect();
        }
        if pid == 0 {
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
                let ok = write_one(&files[i].0, files[i].1, files[i].2).is_ok();
                unsafe {
                    write_record(write_fd, i as u32, ok, &[]);
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

    for fds in &pipes {
        unsafe {
            close(fds[1]);
        }
    }

    let mut read_fds: Vec<i32> = pipes.iter().map(|f| f[0]).collect();
    let mut done = vec![false; n];
    let mut bad = vec![false; n];
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
            break;
        }
        for (k, pfd) in pfds.iter().enumerate() {
            if pfd.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL) == 0 {
                continue;
            }
            let w = fd_to_worker[k];
            match unsafe { read_record(pfd.fd) } {
                Some((idx, ok, _)) => {
                    let i = idx as usize;
                    done[i] = true;
                    bad[i] = !ok;
                    collected += 1;
                }
                None => {
                    read_fds[w] = -1;
                }
            }
        }
    }

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

    (0..n).filter(|&i| !done[i] || bad[i]).collect()
}

/// Windows：spawn 工作进程，经 stdin 序列化 `(path, mode, data)`，经 stdout 收回 `(idx, ok)`。
#[cfg(windows)]
fn run_write_parallel(files: &[(PathBuf, u32, &[u8])], workers: usize) -> Vec<usize> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let n = files.len();

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
        Err(_) => return (0..n).collect(),
    };

    let mut children = Vec::with_capacity(workers);
    for _ in 0..workers {
        let mut cmd = Command::new(&exe);
        cmd.arg(WORKER_ARG)
            .arg("write-files")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        match cmd.spawn() {
            Ok(c) => children.push(Some(c)),
            Err(_) => {
                for c in children.iter_mut().flatten() {
                    let _ = c.kill();
                    let _ = c.wait();
                }
                return (0..n).collect();
            }
        }
    }

    for w in 0..workers {
        let mut stdin = children[w].as_mut().unwrap().stdin.take().unwrap();
        let _ = write_u32(&mut stdin, assigned[w].len() as u32);
        for &i in &assigned[w] {
            let path = files[i].0.as_os_str().as_encoded_bytes();
            let _ = write_u32(&mut stdin, i as u32);
            let _ = write_u32(&mut stdin, path.len() as u32);
            let _ = stdin.write_all(path);
            let _ = write_u32(&mut stdin, files[i].1);
            let _ = write_u32(&mut stdin, files[i].2.len() as u32);
            let _ = stdin.write_all(files[i].2);
        }
    }

    let mut done = vec![false; n];
    let mut bad = vec![false; n];
    for w in 0..workers {
        let mut stdout = children[w].as_mut().unwrap().stdout.take().unwrap();
        for _ in 0..assigned[w].len() {
            match (read_u32(&mut stdout), read_u8(&mut stdout)) {
                (Some(i), Some(ok)) => {
                    let i = i as usize;
                    done[i] = true;
                    bad[i] = ok == 0;
                }
                _ => break,
            }
        }
    }

    for c in children.iter_mut().flatten() {
        let _ = c.wait();
    }

    (0..n).filter(|&i| !done[i] || bad[i]).collect()
}

/// Windows 文件写入工作进程：从 stdin 读取 `(path, mode, data)`，写盘后回报 `(idx, ok)`。
#[cfg(windows)]
fn write_files_worker() -> i32 {
    use std::io::{Read, Write};

    let stdin = std::io::stdin();
    let mut r = stdin.lock();
    let stdout = std::io::stdout();
    let mut w = stdout.lock();

    let count = match read_u32(&mut r) {
        Some(c) => c,
        None => return 0,
    };
    for _ in 0..count {
        let idx = match read_u32(&mut r) {
            Some(v) => v,
            None => return 0,
        };
        let path_len = match read_u32(&mut r) {
            Some(v) => v as usize,
            None => return 0,
        };
        let mut path = vec![0u8; path_len];
        if r.read_exact(&mut path).is_err() {
            return 0;
        }
        let mode = match read_u32(&mut r) {
            Some(v) => v,
            None => return 0,
        };
        let data_len = match read_u32(&mut r) {
            Some(v) => v as usize,
            None => return 0,
        };
        let mut data = vec![0u8; data_len];
        if r.read_exact(&mut data).is_err() {
            return 0;
        }
        let dest = PathBuf::from(unsafe { std::ffi::OsString::from_encoded_bytes_unchecked(path) });
        let ok = write_one(&dest, mode, &data).is_ok();
        if write_u32(&mut w, idx).is_err() || write_u8(&mut w, ok as u8).is_err() {
            return 1;
        }
    }
    let _ = w.flush();
    0
}

/// 其他平台：标记全部为待重写，由调用方串行写出。
#[cfg(not(any(unix, windows)))]
fn run_write_parallel(files: &[(PathBuf, u32, &[u8])], _workers: usize) -> Vec<usize> {
    (0..files.len()).collect()
}
