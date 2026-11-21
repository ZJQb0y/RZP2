fn main() {
    // 多进程并行压缩的 Windows 工作进程入口（隐藏子命令）。
    #[cfg(windows)]
    if std::env::args().nth(1).as_deref() == Some(rzp2::parallel::WORKER_ARG) {
        std::process::exit(rzp2::parallel::worker_main());
    }
    // 自解压检测：若本可执行文件尾部追加了 `.rzp2` 载荷，则就地解压并退出。
    if let Some(code) = rzp2::sfx::try_extract() {
        std::process::exit(code);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(rzp2::cli::run(&args));
}
