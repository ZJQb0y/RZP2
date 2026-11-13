fn main() {
    // 自解压检测：若本可执行文件尾部追加了 `.rzp2` 载荷，则就地解压并退出。
    if let Some(code) = rzp2::sfx::try_extract() {
        std::process::exit(code);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(rzp2::cli::run(&args));
}
