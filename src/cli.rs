//! 命令行解析与分发。
//!
//! 子命令：
//! - `compress`：压缩（可选加密）为 `.rzp2`，支持单文件与目录归档
//! - `decompress`：解压（可选解密）`.rzp2`
//! - `keygen`：生成 ML-KEM 长期公私钥对
//! - `list`：列出归档条目
//! - `test`：校验容器完整性
//! - `info`：查看容器元信息

use std::fs::File;
use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use crate::archive::{
    decode_archive, encode_archive, Entry, EntryKind, EntrySink, StreamEntry, StreamUnpacker,
};
use crate::format::{Header, KemParams, MAGIC, VERSION};
use crate::hybrid::{DEFAULT_ITERATIONS, DEFAULT_LANES, DEFAULT_MEMORY_KIB};
use crate::keys::{
    decode_key, decode_private_key, encode_encrypted_private_key, encode_key, KeyKind,
};
use crate::lzma::{self, LzmaParams};
use crate::pipeline::{
    mlkem_params, pack, pack_stream_with_size, pack_to_writer, unpack, unpack_to_writer,
    DecryptKey, Encryption, PackConfig, PipelineError,
};
use crate::progress::{Progress, ProgressReader, ProgressWriter};
use crate::split;

/// 终端 ANSI 颜色支持：零依赖，非终端（重定向/管道）自动禁用。
mod style {
    use std::io::IsTerminal;
    use std::sync::OnceLock;

    const RESET: &str = "\x1b[0m";

    #[derive(Clone, Copy)]
    pub enum Color {
        Red,
        Green,
        Cyan,
        Bold,
    }

    fn code(c: Color) -> &'static str {
        match c {
            Color::Red => "\x1b[31m",
            Color::Green => "\x1b[32m",
            Color::Cyan => "\x1b[36m",
            Color::Bold => "\x1b[1m",
        }
    }

    /// `enabled` 为真时包裹 ANSI 转义，否则原样返回。
    pub fn paint(s: &str, c: Color, enabled: bool) -> String {
        if enabled {
            format!("{}{}{}", code(c), s, RESET)
        } else {
            s.to_string()
        }
    }

    pub fn stdout_tty() -> bool {
        static TTY: OnceLock<bool> = OnceLock::new();
        *TTY.get_or_init(|| std::io::stdout().is_terminal())
    }

    pub fn stderr_tty() -> bool {
        static TTY: OnceLock<bool> = OnceLock::new();
        *TTY.get_or_init(|| std::io::stderr().is_terminal())
    }
}

/// 红色 `error` 前缀，用于统一错误输出。
fn err_prefix() -> String {
    style::paint("error", style::Color::Red, style::stderr_tty())
}

/// 命令行中可用的 ML-KEM 参数集名称（与 `--help` 文案保持一致）。
const KEM_PARAM_NAMES: &str = "mlkem512/mlkem768/mlkem1024";

/// 口令来源的环境变量名，便于脚本免交互地提供口令。
const PASSWORD_ENV: &str = "RZP2_PASSWORD";

/// 解析后的动作。
enum Action {
    Help,
    Version,
    Compress(CompressOpts),
    Decompress(DecompressOpts),
    Keygen(KeygenOpts),
    List(ListOpts),
    Test(TestOpts),
    Info(InfoOpts),
    Completion(CompletionOpts),
    Sfx(SfxOpts),
    Split(SplitOpts),
    Merge(MergeOpts),
}

struct CompressOpts {
    input: String,
    output: String,
    encrypt: bool,
    public_keys: Vec<PathBuf>,
    params: Option<KemParams>,
    checksum: bool,
    level: u8,
    dict_size: Option<u32>,
    password: Option<String>,
    ask_pass: bool,
    force: bool,
    include: Vec<String>,
    exclude: Vec<String>,
    threads: usize,
    block_size: usize,
    dry_run: bool,
}

struct DecompressOpts {
    input: String,
    output: String,
    private_key: Option<PathBuf>,
    password: Option<String>,
    key_password: Option<String>,
    ask_pass: bool,
    force: bool,
    dry_run: bool,
    entry: Option<String>,
}

struct KeygenOpts {
    params: KemParams,
    public_key: PathBuf,
    private_key: PathBuf,
    private_password: Option<String>,
}

struct ListOpts {
    input: String,
    private_key: Option<PathBuf>,
    password: Option<String>,
    key_password: Option<String>,
    ask_pass: bool,
    long: bool,
    human: bool,
}

struct TestOpts {
    input: String,
    private_key: Option<PathBuf>,
    password: Option<String>,
    key_password: Option<String>,
    ask_pass: bool,
}

struct InfoOpts {
    input: String,
}

struct CompletionOpts {
    shell: Option<String>,
}

struct SfxOpts {
    input: String,
    output: String,
    force: bool,
}

struct SplitOpts {
    input: String,
    prefix: String,
    chunk_size: usize,
    force: bool,
    dry_run: bool,
}

struct MergeOpts {
    input: String,
    output: String,
    force: bool,
    dry_run: bool,
}

/// 解密凭据（已读入内存的私钥或口令）。
enum Credential {
    None,
    PrivateKey(Vec<u8>),
    Password(Vec<u8>),
}

/// CLI 入口，返回进程退出码。
pub fn run(args: &[String]) -> i32 {
    match parse(args) {
        Ok(Action::Help) => {
            print!("{}", render_usage(style::stdout_tty()));
            0
        }
        Ok(Action::Version) => {
            println!("rzp2 {}", env!("CARGO_PKG_VERSION"));
            println!("开发者: {}", env!("CARGO_PKG_AUTHORS"));
            println!(
                "编译日期: {}",
                option_env!("RZP2_BUILD_DATE").unwrap_or("unknown")
            );
            0
        }
        Ok(Action::Compress(o)) => cmd_compress(&o),
        Ok(Action::Decompress(o)) => cmd_decompress(&o),
        Ok(Action::Keygen(o)) => cmd_keygen(&o),
        Ok(Action::List(o)) => cmd_list(&o),
        Ok(Action::Test(o)) => cmd_test(&o),
        Ok(Action::Info(o)) => cmd_info(&o),
        Ok(Action::Completion(o)) => cmd_completion(&o),
        Ok(Action::Sfx(o)) => cmd_sfx(&o),
        Ok(Action::Split(o)) => cmd_split(&o),
        Ok(Action::Merge(o)) => cmd_merge(&o),
        Err(e) => {
            eprintln!("{}: {e}", err_prefix());
            eprintln!("运行 `rzp2 --help` 查看用法。");
            2
        }
    }
}

fn parse(args: &[String]) -> Result<Action, String> {
    let Some(first) = args.first() else {
        return Ok(Action::Help);
    };
    match first.as_str() {
        "-h" | "--help" | "help" => Ok(Action::Help),
        "-V" | "--version" | "version" => Ok(Action::Version),
        "compress" | "c" => Ok(Action::Compress(parse_compress(&args[1..])?)),
        "decompress" | "d" | "x" => Ok(Action::Decompress(parse_decompress(&args[1..])?)),
        "keygen" | "k" => Ok(Action::Keygen(parse_keygen(&args[1..])?)),
        "list" | "l" => Ok(Action::List(parse_list(&args[1..])?)),
        "test" | "t" => Ok(Action::Test(parse_test(&args[1..])?)),
        "info" | "i" => Ok(Action::Info(parse_info(&args[1..])?)),
        "completion" | "complete" => Ok(Action::Completion(parse_completion(&args[1..])?)),
        "sfx" => Ok(Action::Sfx(parse_sfx(&args[1..])?)),
        "split" => Ok(Action::Split(parse_split(&args[1..])?)),
        "merge" => Ok(Action::Merge(parse_merge(&args[1..])?)),
        other => Err(format!("未知子命令 `{other}`")),
    }
}

/// 简易参数迭代器，用于手写解析。
///
/// 每个带值的选项统一支持两种写法：`--opt value` 与 `--opt=value`。
struct Args<'a> {
    tokens: &'a [String],
    pos: usize,
}

impl<'a> Args<'a> {
    fn new(tokens: &'a [String]) -> Self {
        Self { tokens, pos: 0 }
    }

    fn next(&mut self) -> Option<&'a str> {
        let token = self.tokens.get(self.pos)?;
        self.pos += 1;
        Some(token.as_str())
    }

    /// 读取一个选项的值。`flag` 为去掉 `=...` 后的选项名，`inline` 为 `--opt=value` 中的 `value`。
    fn value(&mut self, flag: &str, inline: Option<&str>) -> Result<String, String> {
        if let Some(v) = inline {
            if v.is_empty() {
                return Err(format!("参数 `{flag}` 缺少值"));
            }
            return Ok(v.to_string());
        }
        self.next()
            .map(str::to_string)
            .ok_or_else(|| format!("参数 `{flag}` 缺少值"))
    }
}

/// 将 token 拆分为 `(选项名, 内联值)`。仅长选项支持 `--opt=value`。
fn split_option(token: &str) -> (&str, Option<&str>) {
    if let Some((flag, value)) = token.split_once('=') {
        if flag.starts_with("--") {
            return (flag, Some(value));
        }
    }
    (token, None)
}

/// 布尔选项不接受 `--flag=value` 形式。
fn reject_value(flag: &str, inline: Option<&str>) -> Result<(), String> {
    if inline.is_some() {
        return Err(format!("选项 `{flag}` 不接受值"));
    }
    Ok(())
}

/// 从名称解析 ML-KEM 参数集，失败时给出统一提示。
fn parse_kem_params(v: &str) -> Result<KemParams, String> {
    KemParams::from_name(v).ok_or_else(|| format!("未知参数集 `{v}`（可选 {KEM_PARAM_NAMES}）"))
}

fn parse_level(v: &str) -> Result<u8, String> {
    let n: u8 = v.parse().map_err(|_| format!("无效压缩级别 `{v}`"))?;
    if n > 9 {
        return Err(format!("压缩级别需在 0..=9 之间，收到 {n}"));
    }
    Ok(n)
}

fn parse_dict_size(v: &str) -> Result<u32, String> {
    let n: u32 = v.parse().map_err(|_| format!("无效字典大小 `{v}`"))?;
    if n == 0 {
        return Err("字典大小必须大于 0".into());
    }
    Ok(n)
}

fn parse_usize_option(flag: &str, v: &str) -> Result<usize, String> {
    let n: usize = v
        .parse()
        .map_err(|_| format!("`{flag}` 需要非负整数，收到 `{v}`"))?;
    if n == 0 {
        return Err(format!("`{flag}` 必须大于 0"));
    }
    Ok(n)
}

/// 未指定 `-o` 时压缩的默认输出：输入名后追加 `.rzp2`（stdin 则输出到 stdout）。
fn default_compress_output(input: &str) -> String {
    if input == "-" {
        "-".to_string()
    } else {
        format!("{input}.rzp2")
    }
}

/// 未指定 `-o` 时解压的默认输出：去掉结尾的 `.rzp2` 还原原名（stdin 则输出到 stdout）。
fn default_decompress_output(input: &str) -> Result<String, String> {
    if input == "-" {
        return Ok("-".to_string());
    }
    let stripped = input
        .strip_suffix(".rzp2")
        .ok_or_else(|| format!("无法从输入 `{input}` 推导输出（请用 -o 指定）"))?;
    if stripped.is_empty() {
        return Err(format!("无法从输入 `{input}` 推导输出（请用 -o 指定）"));
    }
    Ok(stripped.to_string())
}

/// `decompress --entry <path>` 未指定 `-o` 时的默认输出：取归档内条目的文件名（末段）。
fn entry_default_output(entry: &str) -> Result<String, String> {
    let leaf = entry.rsplit('/').next().unwrap_or(entry);
    if leaf.is_empty() || leaf == "." || leaf == ".." {
        return Err(format!("无法从条目 `{entry}` 推导输出（请用 -o 指定）"));
    }
    Ok(leaf.to_string())
}

fn parse_compress(args: &[String]) -> Result<CompressOpts, String> {
    let mut it = Args::new(args);
    let mut input: Option<String> = None;
    let mut output: Option<String> = None;
    let mut encrypt = false;
    let mut public_keys: Vec<PathBuf> = Vec::new();
    let mut params: Option<KemParams> = None;
    let mut checksum = false;
    let mut level = lzma::DEFAULT_LEVEL;
    let mut dict_size: Option<u32> = None;
    let mut password: Option<String> = None;
    let mut ask_pass = false;
    let mut force = false;
    let mut include: Vec<String> = Vec::new();
    let mut exclude: Vec<String> = Vec::new();
    let mut threads: usize = 1;
    let mut block_size: usize = lzma::DEFAULT_BLOCK_SIZE;
    let mut dry_run = false;

    while let Some(token) = it.next() {
        let (flag, inline) = split_option(token);
        match flag {
            "-o" | "--output" => output = Some(it.value(flag, inline)?),
            "-e" | "--encrypt" => {
                reject_value(flag, inline)?;
                encrypt = true;
            }
            "--public-key" | "--key" => public_keys.push(PathBuf::from(it.value(flag, inline)?)),
            "--params" => params = Some(parse_kem_params(&it.value(flag, inline)?)?),
            "--checksum" => {
                reject_value(flag, inline)?;
                checksum = true;
            }
            "--level" => level = parse_level(&it.value(flag, inline)?)?,
            "--dict-size" => dict_size = Some(parse_dict_size(&it.value(flag, inline)?)?),
            "--password" => password = Some(it.value(flag, inline)?),
            "--ask-pass" => {
                reject_value(flag, inline)?;
                ask_pass = true;
            }
            "--include" => include.push(it.value(flag, inline)?),
            "--exclude" => exclude.push(it.value(flag, inline)?),
            "--threads" => threads = parse_usize_option(flag, &it.value(flag, inline)?)?,
            "--block-size" => block_size = parse_usize_option(flag, &it.value(flag, inline)?)?,
            "-f" | "--force" | "--overwrite" => {
                reject_value(flag, inline)?;
                force = true;
            }
            "--dry-run" => {
                reject_value(flag, inline)?;
                dry_run = true;
            }
            "-h" | "--help" => return Err("compress 用法见 `rzp2 --help`".into()),
            _ if flag.starts_with('-') && token != "-" => {
                return Err(format!("未知选项 `{token}`"))
            }
            _ if input.is_none() => input = Some(token.to_string()),
            _ => return Err(format!("多余的位置参数 `{token}`")),
        }
    }

    let input = input.ok_or("缺少输入文件")?;
    let output = output.unwrap_or_else(|| default_compress_output(&input));
    if encrypt && public_keys.is_empty() {
        return Err("`--encrypt` 需要同时指定 `--public-key`".into());
    }
    if encrypt && password.is_some() {
        return Err("`--encrypt` 与 `--password` 不能同时使用".into());
    }
    Ok(CompressOpts {
        input,
        output,
        encrypt,
        public_keys,
        params,
        checksum,
        level,
        dict_size,
        password,
        ask_pass,
        force,
        include,
        exclude,
        threads,
        block_size,
        dry_run,
    })
}

fn parse_decompress(args: &[String]) -> Result<DecompressOpts, String> {
    let mut it = Args::new(args);
    let mut input: Option<String> = None;
    let mut output: Option<String> = None;
    let mut private_key: Option<PathBuf> = None;
    let mut password: Option<String> = None;
    let mut key_password: Option<String> = None;
    let mut ask_pass = false;
    let mut force = false;
    let mut dry_run = false;
    let mut entry: Option<String> = None;

    while let Some(token) = it.next() {
        let (flag, inline) = split_option(token);
        match flag {
            "-o" | "--output" => output = Some(it.value(flag, inline)?),
            "--private-key" | "--key" => {
                private_key = Some(PathBuf::from(it.value(flag, inline)?));
            }
            "--password" => password = Some(it.value(flag, inline)?),
            "--key-password" => key_password = Some(it.value(flag, inline)?),
            "--ask-pass" => {
                reject_value(flag, inline)?;
                ask_pass = true;
            }
            "--entry" => entry = Some(it.value(flag, inline)?),
            "-f" | "--force" | "--overwrite" => {
                reject_value(flag, inline)?;
                force = true;
            }
            "--dry-run" => {
                reject_value(flag, inline)?;
                dry_run = true;
            }
            "-h" | "--help" => return Err("decompress 用法见 `rzp2 --help`".into()),
            _ if flag.starts_with('-') && token != "-" => {
                return Err(format!("未知选项 `{token}`"))
            }
            _ if input.is_none() => input = Some(token.to_string()),
            _ => return Err(format!("多余的位置参数 `{token}`")),
        }
    }

    let input = input.ok_or("缺少输入文件")?;
    let output = match output {
        Some(o) => o,
        None if entry.is_some() => entry_default_output(entry.as_deref().unwrap())?,
        None => default_decompress_output(&input)?,
    };
    Ok(DecompressOpts {
        input,
        output,
        private_key,
        password,
        key_password,
        ask_pass,
        force,
        dry_run,
        entry,
    })
}

fn parse_keygen(args: &[String]) -> Result<KeygenOpts, String> {
    let mut it = Args::new(args);
    let mut params = KemParams::DEFAULT;
    let mut public_key: Option<PathBuf> = None;
    let mut private_key: Option<PathBuf> = None;
    let mut private_password: Option<String> = None;

    while let Some(token) = it.next() {
        let (flag, inline) = split_option(token);
        match flag {
            "--params" => params = parse_kem_params(&it.value(flag, inline)?)?,
            "--public" | "--public-key" => {
                public_key = Some(PathBuf::from(it.value(flag, inline)?))
            }
            "--private" | "--private-key" => {
                private_key = Some(PathBuf::from(it.value(flag, inline)?));
            }
            "--private-password" => private_password = Some(it.value(flag, inline)?),
            "-h" | "--help" => return Err("keygen 用法见 `rzp2 --help`".into()),
            _ if flag.starts_with('-') => return Err(format!("未知选项 `{token}`")),
            _ => return Err(format!("多余的位置参数 `{token}`")),
        }
    }

    let base = format!("rzp2_{}.key", params.name().to_ascii_lowercase());
    let public_key = public_key.unwrap_or_else(|| PathBuf::from(format!("{base}.pub")));
    let private_key = private_key.unwrap_or_else(|| PathBuf::from(base));
    Ok(KeygenOpts {
        params,
        public_key,
        private_key,
        private_password,
    })
}

fn parse_list(args: &[String]) -> Result<ListOpts, String> {
    let mut it = Args::new(args);
    let mut input: Option<String> = None;
    let mut private_key: Option<PathBuf> = None;
    let mut password: Option<String> = None;
    let mut key_password: Option<String> = None;
    let mut ask_pass = false;
    let mut long = false;
    let mut human = false;

    while let Some(token) = it.next() {
        let (flag, inline) = split_option(token);
        match flag {
            "--private-key" | "--key" => {
                private_key = Some(PathBuf::from(it.value(flag, inline)?));
            }
            "--password" => password = Some(it.value(flag, inline)?),
            "--key-password" => key_password = Some(it.value(flag, inline)?),
            "--ask-pass" => {
                reject_value(flag, inline)?;
                ask_pass = true;
            }
            "-l" | "--long" => {
                reject_value(flag, inline)?;
                long = true;
            }
            "--human-readable" => {
                reject_value(flag, inline)?;
                human = true;
            }
            "-h" | "--help" => return Err("list 用法见 `rzp2 --help`".into()),
            _ if flag.starts_with('-') && token != "-" => {
                return Err(format!("未知选项 `{token}`"))
            }
            _ if input.is_none() => input = Some(token.to_string()),
            _ => return Err(format!("多余的位置参数 `{token}`")),
        }
    }
    Ok(ListOpts {
        input: input.ok_or("缺少输入文件")?,
        private_key,
        password,
        key_password,
        ask_pass,
        long,
        human,
    })
}

fn parse_test(args: &[String]) -> Result<TestOpts, String> {
    let mut it = Args::new(args);
    let mut input: Option<String> = None;
    let mut private_key: Option<PathBuf> = None;
    let mut password: Option<String> = None;
    let mut key_password: Option<String> = None;
    let mut ask_pass = false;

    while let Some(token) = it.next() {
        let (flag, inline) = split_option(token);
        match flag {
            "--private-key" | "--key" => {
                private_key = Some(PathBuf::from(it.value(flag, inline)?));
            }
            "--password" => password = Some(it.value(flag, inline)?),
            "--key-password" => key_password = Some(it.value(flag, inline)?),
            "--ask-pass" => {
                reject_value(flag, inline)?;
                ask_pass = true;
            }
            "-h" | "--help" => return Err("test 用法见 `rzp2 --help`".into()),
            _ if flag.starts_with('-') && token != "-" => {
                return Err(format!("未知选项 `{token}`"))
            }
            _ if input.is_none() => input = Some(token.to_string()),
            _ => return Err(format!("多余的位置参数 `{token}`")),
        }
    }
    Ok(TestOpts {
        input: input.ok_or("缺少输入文件")?,
        private_key,
        password,
        key_password,
        ask_pass,
    })
}

fn parse_info(args: &[String]) -> Result<InfoOpts, String> {
    let mut it = Args::new(args);
    let mut input: Option<String> = None;
    while let Some(token) = it.next() {
        let (flag, _inline) = split_option(token);
        match flag {
            "-h" | "--help" => return Err("info 用法见 `rzp2 --help`".into()),
            _ if flag.starts_with('-') && token != "-" => {
                return Err(format!("未知选项 `{token}`"))
            }
            _ if input.is_none() => input = Some(token.to_string()),
            _ => return Err(format!("多余的位置参数 `{token}`")),
        }
    }
    Ok(InfoOpts {
        input: input.ok_or("缺少输入文件")?,
    })
}

fn parse_completion(args: &[String]) -> Result<CompletionOpts, String> {
    let mut it = Args::new(args);
    let mut shell: Option<String> = None;
    while let Some(token) = it.next() {
        let (flag, _inline) = split_option(token);
        match flag {
            "-h" | "--help" => {
                return Err("completion 用法见 `rzp2 completion <bash|zsh|fish|powershell>`".into())
            }
            _ if flag.starts_with('-') => return Err(format!("未知选项 `{token}`")),
            _ if shell.is_none() => shell = Some(token.to_string()),
            _ => return Err(format!("多余的位置参数 `{token}`")),
        }
    }
    Ok(CompletionOpts { shell })
}

/// 未指定 `-o` 时自解压的默认输出：去掉结尾 `.rzp2`（Windows 追加 `.exe`）。
fn default_sfx_output(input: &str) -> String {
    let stripped = input.strip_suffix(".rzp2").unwrap_or(input);
    #[cfg(windows)]
    {
        if stripped.to_ascii_lowercase().ends_with(".exe") {
            stripped.to_string()
        } else {
            format!("{stripped}.exe")
        }
    }
    #[cfg(not(windows))]
    {
        stripped.to_string()
    }
}

fn parse_sfx(args: &[String]) -> Result<SfxOpts, String> {
    let mut it = Args::new(args);
    let mut input: Option<String> = None;
    let mut output: Option<String> = None;
    let mut force = false;

    while let Some(token) = it.next() {
        let (flag, inline) = split_option(token);
        match flag {
            "-o" | "--output" => output = Some(it.value(flag, inline)?),
            "-f" | "--force" | "--overwrite" => {
                reject_value(flag, inline)?;
                force = true;
            }
            "-h" | "--help" => return Err("sfx 用法见 `rzp2 --help`".into()),
            _ if flag.starts_with('-') && token != "-" => {
                return Err(format!("未知选项 `{token}`"))
            }
            _ if input.is_none() => input = Some(token.to_string()),
            _ => return Err(format!("多余的位置参数 `{token}`")),
        }
    }

    let input = input.ok_or("缺少输入文件")?;
    let output = output.unwrap_or_else(|| default_sfx_output(&input));
    Ok(SfxOpts {
        input,
        output,
        force,
    })
}

fn parse_split(args: &[String]) -> Result<SplitOpts, String> {
    let mut it = Args::new(args);
    let mut input: Option<String> = None;
    let mut prefix: Option<String> = None;
    let mut chunk_size = split::DEFAULT_CHUNK_SIZE;
    let mut force = false;
    let mut dry_run = false;

    while let Some(token) = it.next() {
        let (flag, inline) = split_option(token);
        match flag {
            "-o" | "--output" => prefix = Some(it.value(flag, inline)?),
            "--chunk-size" => chunk_size = parse_usize_option(flag, &it.value(flag, inline)?)?,
            "-f" | "--force" | "--overwrite" => {
                reject_value(flag, inline)?;
                force = true;
            }
            "--dry-run" => {
                reject_value(flag, inline)?;
                dry_run = true;
            }
            "-h" | "--help" => return Err("split 用法见 `rzp2 --help`".into()),
            _ if flag.starts_with('-') && token != "-" => {
                return Err(format!("未知选项 `{token}`"))
            }
            _ if input.is_none() => input = Some(token.to_string()),
            _ => return Err(format!("多余的位置参数 `{token}`")),
        }
    }

    let input = input.ok_or("缺少输入文件")?;
    if input == "-" {
        return Err("分片不支持从 stdin 读取，请指定文件".into());
    }
    let prefix = prefix.unwrap_or_else(|| input.clone());
    Ok(SplitOpts {
        input,
        prefix,
        chunk_size,
        force,
        dry_run,
    })
}

fn parse_merge(args: &[String]) -> Result<MergeOpts, String> {
    let mut it = Args::new(args);
    let mut input: Option<String> = None;
    let mut output: Option<String> = None;
    let mut force = false;
    let mut dry_run = false;

    while let Some(token) = it.next() {
        let (flag, inline) = split_option(token);
        match flag {
            "-o" | "--output" => output = Some(it.value(flag, inline)?),
            "-f" | "--force" | "--overwrite" => {
                reject_value(flag, inline)?;
                force = true;
            }
            "--dry-run" => {
                reject_value(flag, inline)?;
                dry_run = true;
            }
            "-h" | "--help" => return Err("merge 用法见 `rzp2 --help`".into()),
            _ if flag.starts_with('-') && token != "-" => {
                return Err(format!("未知选项 `{token}`"))
            }
            _ if input.is_none() => input = Some(token.to_string()),
            _ => return Err(format!("多余的位置参数 `{token}`")),
        }
    }

    let input = input.ok_or("缺少输入文件")?;
    let output = match output {
        Some(o) => o,
        None => derive_merge_output(&input)?,
    };
    Ok(MergeOpts {
        input,
        output,
        force,
        dry_run,
    })
}

/// merge 未指定 `-o` 时推导输出：优先取清单里记录的原始文件名，失败则去掉后缀。
fn derive_merge_output(input: &str) -> Result<String, String> {
    if let Ok((_, manifest_path)) = split::locate_manifest(input) {
        if let Ok(data) = std::fs::read(&manifest_path) {
            if let Ok(m) = split::decode_manifest(&data) {
                if !m.name.is_empty() {
                    return Ok(m.name);
                }
            }
        }
    }
    let stripped = input
        .strip_suffix(split::MANIFEST_SUFFIX)
        .or_else(|| input.rfind(split::PART_SUFFIX).map(|i| &input[..i]))
        .unwrap_or(input);
    if stripped.is_empty() {
        return Err(format!("无法从 `{input}` 推导输出（请用 -o 指定）"));
    }
    Ok(stripped.to_string())
}

// ---------------------------------------------------------------------------
// 命令实现
// ---------------------------------------------------------------------------

fn read_input(path: &str) -> Result<Vec<u8>, String> {
    if path == "-" {
        use std::io::Read;
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| format!("读取 stdin 失败: {e}"))?;
        Ok(buf)
    } else {
        std::fs::read(path).map_err(|e| format!("读取 `{path}` 失败: {e}"))
    }
}

fn write_output(path: &str, data: &[u8]) -> Result<(), String> {
    if path == "-" {
        use std::io::Write;
        std::io::stdout()
            .write_all(data)
            .map_err(|e| format!("写入 stdout 失败: {e}"))?;
        Ok(())
    } else {
        std::fs::write(path, data).map_err(|e| format!("写入 `{path}` 失败: {e}"))
    }
}

/// 打开输入流（`-` 表示 stdin）。
fn open_input_stream(path: &str) -> Result<Box<dyn Read>, String> {
    if path == "-" {
        Ok(Box::new(std::io::stdin().lock()) as Box<dyn Read>)
    } else {
        File::open(path)
            .map(|f| Box::new(f) as Box<dyn Read>)
            .map_err(|e| format!("打开 `{path}` 失败: {e}"))
    }
}

/// 打开输出流（`-` 表示 stdout）。
fn open_output_stream(path: &str) -> Result<Box<dyn Write>, String> {
    if path == "-" {
        Ok(Box::new(std::io::stdout().lock()) as Box<dyn Write>)
    } else {
        File::create(path)
            .map(|f| Box::new(f) as Box<dyn Write>)
            .map_err(|e| format!("创建 `{path}` 失败: {e}"))
    }
}

/// 计数写出：统计实际写出的字节数，用于流式压缩后回显输出大小。
struct CountingWriter<W: Write> {
    inner: W,
    count: u64,
}

impl<W: Write> CountingWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner, count: 0 }
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// 写单文件输出前检查目标是否已存在（`-` 表示 stdout，跳过检查）。
fn ensure_not_exists(path: &str, force: bool) -> Result<(), String> {
    if path != "-" && !force && std::path::Path::new(path).exists() {
        return Err(format!("输出 `{path}` 已存在（用 --force 覆盖）"));
    }
    Ok(())
}

/// 输出状态消息。当数据走 stdout（`output == "-"`）时改写到 stderr，避免污染管道数据。
fn println_status(output: &str, msg: String) {
    if output == "-" {
        eprintln!("{msg}");
    } else {
        println!("{msg}");
    }
}

/// 解包归档前检查输出路径：已存在的「文件」需 --force 才能覆盖；目录允许就地解包。
fn ensure_dir_target(path: &str, force: bool) -> Result<(), String> {
    if !force && std::path::Path::new(path).is_file() {
        return Err(format!("输出 `{path}` 已存在（用 --force 覆盖）"));
    }
    Ok(())
}

/// 流式解压单文件到目标（`-` 表示 stdout），返回写出的字节数。
///
/// 写目标为文件时，若解压中途失败会清理残留的半成品文件。
fn stream_decompress(
    output: &str,
    buf: &[u8],
    key: DecryptKey<'_>,
    total: u64,
    label: &'static str,
) -> Result<u64, String> {
    let inner: Box<dyn Write> = if output == "-" {
        Box::new(std::io::stdout().lock())
    } else {
        Box::new(File::create(output).map_err(|e| format!("创建 `{output}` 失败: {e}"))?)
    };

    let mut writer = ProgressWriter::new(inner, label, total, style::stderr_tty());
    let result = unpack_to_writer(buf, key, &mut writer);
    writer.finish();

    match result {
        Ok(written) => Ok(written),
        Err(e) => {
            if output != "-" {
                let _ = std::fs::remove_file(output);
            }
            Err(pipeline_error_message("解压失败", &e))
        }
    }
}

/// 解析口令选项。`-` 表示交互式 / 从 stdin 读取；`confirm` 为真时（设置口令的场景）
/// 在终端下二次确认，避免输入错误。
fn resolve_password(pw: &Option<String>, confirm: bool) -> Result<Option<Vec<u8>>, String> {
    match pw {
        None => Ok(None),
        Some(s) if s == "-" => {
            if std::io::stdin().is_terminal() {
                let p = read_secret_tty("输入口令: ")?;
                if confirm {
                    let again = read_secret_tty("再次输入口令: ")?;
                    if p != again {
                        return Err("两次输入的口令不一致".into());
                    }
                }
                Ok(Some(p))
            } else {
                use std::io::BufRead;
                let stdin = std::io::stdin();
                let mut line = String::new();
                stdin
                    .lock()
                    .read_line(&mut line)
                    .map_err(|e| format!("读取口令失败: {e}"))?;
                let trimmed = line.trim_end_matches(['\n', '\r']).to_string();
                Ok(Some(trimmed.into_bytes()))
            }
        }
        Some(s) => Ok(Some(s.as_bytes().to_vec())),
    }
}

/// 交互式无回显读取口令，并拒绝空口令。
fn prompt_password(prompt: &str) -> Result<Vec<u8>, String> {
    let pw = read_secret_tty(prompt)?;
    if pw.is_empty() {
        return Err("口令不能为空".into());
    }
    Ok(pw)
}

/// 解密时解析容器口令，按优先级：`--password`（含 `-` 交互式）>
/// `RZP2_PASSWORD` 环境变量 > 终端交互式提示。`ask_pass` 为真时，若无法交互则报错
/// （用户显式要求交互输入）。
fn resolve_container_password(
    password: &Option<String>,
    ask_pass: bool,
) -> Result<Option<Vec<u8>>, String> {
    if password.is_some() {
        return resolve_password(password, false);
    }
    if let Ok(env) = std::env::var(PASSWORD_ENV) {
        if !env.is_empty() {
            return Ok(Some(env.into_bytes()));
        }
    }
    if std::io::stdin().is_terminal() {
        return prompt_password("输入口令: ").map(Some);
    }
    if ask_pass {
        return Err("`--ask-pass` 需要在终端中交互输入口令".into());
    }
    Ok(None)
}

/// 交互式输入两次口令并校验一致（用于设置新口令）。
fn prompt_password_confirmed() -> Result<Vec<u8>, String> {
    let p = prompt_password("输入口令: ")?;
    let again = prompt_password("再次输入口令: ")?;
    if p != again {
        return Err("两次输入的口令不一致".into());
    }
    Ok(p)
}

/// 压缩时解析加密口令：`--password`（含 `-` 交互式）优先；`--ask-pass` 则强制在
/// 终端交互输入（二次确认）。未提供任何来源时返回 None（即不加密）。
fn resolve_encryption_password(
    password: &Option<String>,
    ask_pass: bool,
) -> Result<Option<Vec<u8>>, String> {
    if password.is_some() {
        return resolve_password(password, true);
    }
    if ask_pass {
        if !std::io::stdin().is_terminal() {
            return Err("`--ask-pass` 需要在终端中交互输入口令".into());
        }
        return prompt_password_confirmed().map(Some);
    }
    Ok(None)
}

/// 在终端上无回显读取一行口令。
fn read_secret_tty(prompt: &str) -> Result<Vec<u8>, String> {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    disable_echo()?;
    let mut line = String::new();
    let res = std::io::stdin().lock().read_line(&mut line);
    let _ = enable_echo();
    eprintln!();
    res.map_err(|e| format!("读取口令失败: {e}"))?;
    Ok(line.trim_end_matches(['\n', '\r']).as_bytes().to_vec())
}

#[cfg(unix)]
fn disable_echo() -> Result<(), String> {
    let ok = std::process::Command::new("stty")
        .arg("-echo")
        .status()
        .map_err(|e| format!("无法关闭终端回显（stty）: {e}"))?
        .success();
    if ok {
        Ok(())
    } else {
        Err("无法关闭终端回显（stty 执行失败）".into())
    }
}

#[cfg(unix)]
fn enable_echo() -> Result<(), String> {
    let _ = std::process::Command::new("stty").arg("echo").status();
    Ok(())
}

#[cfg(not(unix))]
fn disable_echo() -> Result<(), String> {
    Ok(())
}

#[cfg(not(unix))]
fn enable_echo() -> Result<(), String> {
    Ok(())
}

fn load_credential(
    header: &Header,
    private_key: &Option<PathBuf>,
    password: &Option<String>,
    key_password: &Option<String>,
    ask_pass: bool,
) -> Result<Credential, String> {
    if !header.encrypted {
        return Ok(Credential::None);
    }
    if header.password {
        let pw = resolve_container_password(password, ask_pass)?
            .ok_or("容器使用口令加密，需要 --password")?;
        return Ok(Credential::Password(pw));
    }
    let path = private_key
        .as_ref()
        .ok_or("容器使用公钥加密，需要 --private-key")?;
    let pem = std::fs::read_to_string(path)
        .map_err(|e| format!("读取私钥 `{}` 失败: {e}", path.display()))?;
    let key_pw = resolve_password(key_password, false)?;
    let (_, raw) = decode_private_key(&pem, key_pw.as_deref())
        .map_err(|e| format!("解析私钥 `{}` 失败: {e}", path.display()))?;
    Ok(Credential::PrivateKey(raw))
}

fn credential_to_key(cred: &Credential) -> DecryptKey<'_> {
    match cred {
        Credential::None => DecryptKey::None,
        Credential::PrivateKey(sk) => DecryptKey::PrivateKey(sk),
        Credential::Password(pw) => DecryptKey::Password(pw),
    }
}

/// 将解包/校验错误转成面向用户的消息；口令错误给一句带人情味的提示。
fn pipeline_error_message(verb: &str, e: &PipelineError) -> String {
    match e {
        PipelineError::BadPassword => "哦!看来你 忘记了/不知道 这个文件的密码呢:D".to_string(),
        other => format!("{verb}: {other}"),
    }
}

fn build_lzma_params(level: u8, dict_size: Option<u32>) -> LzmaParams {
    let mut p = lzma::preset(level);
    if let Some(d) = dict_size {
        p.dict_size = d;
    }
    p
}

fn cmd_compress(o: &CompressOpts) -> i32 {
    // 判断输入是目录还是文件。
    let is_dir = o.input != "-"
        && std::fs::metadata(&o.input)
            .map(|m| m.is_dir())
            .unwrap_or(false);

    let archive = is_dir;

    if o.dry_run {
        let action = if archive {
            "归档目录"
        } else {
            "压缩文件"
        };
        let enc = if o.encrypt {
            "ML-KEM 加密"
        } else if o.password.is_some() || o.ask_pass {
            "口令加密"
        } else {
            "未加密"
        };
        println!(
            "将{action} `{}` → `{}`（级别 {}，{}）",
            o.input, o.output, o.level, enc
        );
        return 0;
    }

    // 组装加密配置。
    let mut raw_pks: Vec<(KemParams, Vec<u8>)> = Vec::new();
    let mut recipients_storage = Vec::new();
    let pw: Vec<u8>;
    let encryption = if o.encrypt {
        // 读取并解析全部公钥；多把公钥走多接收者模式，一把走单接收者模式。
        for path in &o.public_keys {
            let pem = match std::fs::read_to_string(path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{}: 读取公钥 `{}` 失败: {e}", err_prefix(), path.display());
                    return 1;
                }
            };
            match decode_key(KeyKind::Public, &pem) {
                Ok((key_params, r)) => {
                    if let Some(want) = o.params {
                        if want != key_params {
                            eprintln!(
                                "{}: 公钥 `{}` 参数集为 {key_params:?}，与 --params {want:?} 不符",
                                err_prefix(),
                                path.display()
                            );
                            return 1;
                        }
                    }
                    raw_pks.push((key_params, r));
                }
                Err(e) => {
                    eprintln!("{}: 解析公钥 `{}` 失败: {e}", err_prefix(), path.display());
                    return 1;
                }
            }
        }
        if raw_pks.len() == 1 {
            let (kem, pk) = &raw_pks[0];
            Encryption::Kem {
                kem: *kem,
                recipient_pk: pk.as_slice(),
            }
        } else {
            recipients_storage.extend(raw_pks.iter().map(|(k, p)| (*k, p.as_slice())));
            Encryption::KemMulti {
                recipients: &recipients_storage,
            }
        }
    } else {
        match resolve_encryption_password(&o.password, o.ask_pass) {
            Ok(Some(p)) => {
                pw = p;
                Encryption::Password {
                    password: pw.as_slice(),
                    memory_kib: DEFAULT_MEMORY_KIB,
                    iterations: DEFAULT_ITERATIONS,
                    lanes: DEFAULT_LANES,
                }
            }
            Ok(None) => Encryption::None,
            Err(e) => {
                eprintln!("{}: {e}", err_prefix());
                return 1;
            }
        }
    };

    let config = PackConfig {
        params: build_lzma_params(o.level, o.dict_size),
        level: o.level,
        add_checksum: o.checksum,
        archive,
        encryption,
        threads: o.threads,
        block_size: o.block_size,
    };

    if let Err(e) = ensure_not_exists(&o.output, o.force) {
        eprintln!("{}: {e}", err_prefix());
        return 1;
    }

    let (original_len, output_len): (u64, u64) = if archive {
        let mut entries = Vec::new();
        let filter = if o.include.is_empty() && o.exclude.is_empty() {
            None
        } else {
            Some(ArchiveFilter::from_opts(&o.include, &o.exclude))
        };
        if let Err(e) = collect_dir(Path::new(&o.input), &mut entries, filter.as_ref()) {
            eprintln!("{}: 遍历目录 `{}` 失败: {e}", err_prefix(), o.input);
            return 1;
        }
        let payload = encode_archive(&entries);
        let len = payload.len() as u64;
        let packed = match pack(&payload, &config) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}: 压缩失败: {e}", err_prefix());
                return 1;
            }
        };
        let out_len = packed.len() as u64;
        if let Err(e) = write_output(&o.output, &packed) {
            eprintln!("{}: {e}", err_prefix());
            return 1;
        }
        (len, out_len)
    } else if o.threads > 1 {
        // 分块并行压缩：需整段载入以切块，使用缓冲式打包（同时支持校验和）。
        let mut reader = match open_input_stream(&o.input) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{}: {e}", err_prefix());
                return 1;
            }
        };
        let mut data = Vec::new();
        if let Err(e) = reader.read_to_end(&mut data) {
            eprintln!("{}: 读取 `{}` 失败: {e}", err_prefix(), o.input);
            return 1;
        }
        let len = data.len() as u64;
        let packed = match pack(&data, &config) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}: 压缩失败: {e}", err_prefix());
                return 1;
            }
        };
        let out_len = packed.len() as u64;
        if let Err(e) = write_output(&o.output, &packed) {
            eprintln!("{}: {e}", err_prefix());
            return 1;
        }
        (len, out_len)
    } else if o.checksum {
        // 需要明文校验和：缓冲式流式打包（结果仍整体返回）。
        let mut reader = match open_input_stream(&o.input) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{}: {e}", err_prefix());
                return 1;
            }
        };
        let (packed, len) = match pack_stream_with_size(&mut reader, &config) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{}: 压缩失败: {e}", err_prefix());
                return 1;
            }
        };
        let out_len = packed.len() as u64;
        if let Err(e) = write_output(&o.output, &packed) {
            eprintln!("{}: {e}", err_prefix());
            return 1;
        }
        (len, out_len)
    } else {
        // 流式压缩并直接写盘（加密走分块 AEAD，不再整体驻留压缩载荷）。
        let reader = match open_input_stream(&o.input) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{}: {e}", err_prefix());
                return 1;
            }
        };
        let original_hint = if o.input == "-" {
            None
        } else {
            std::fs::metadata(&o.input).ok().map(|m| m.len())
        };
        let writer = match open_output_stream(&o.output) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("{}: {e}", err_prefix());
                return 1;
            }
        };
        let encrypted = o.encrypt || o.password.is_some() || o.ask_pass;
        let label = if encrypted { "压缩+加密" } else { "压缩" };
        let total = original_hint.unwrap_or(0);
        let mut preader = ProgressReader::new(reader, label, total, style::stderr_tty());

        let mut cw = CountingWriter::new(writer);
        let written = match pack_to_writer(&mut preader, &config, original_hint, &mut cw) {
            Ok(n) => n,
            Err(e) => {
                preader.finish();
                eprintln!("{}: 压缩失败: {e}", err_prefix());
                if o.output != "-" {
                    let _ = std::fs::remove_file(&o.output);
                }
                return 1;
            }
        };
        preader.finish();
        let _ = cw.flush();
        (written, cw.count)
    };

    println_status(
        &o.output,
        format!(
            "{} `{}`（{} 字节 → {} 字节，{}，级别 {}）",
            style::paint("已写入", style::Color::Green, style::stdout_tty()),
            o.output,
            original_len,
            output_len,
            if o.encrypt {
                "已加密(ML-KEM)"
            } else if o.password.is_some() || o.ask_pass {
                "已加密(口令)"
            } else {
                "未加密"
            },
            o.level
        ),
    );
    0
}

fn cmd_decompress(o: &DecompressOpts) -> i32 {
    if o.dry_run {
        if let Some(entry) = &o.entry {
            println!("将从 `{}` 抽取条目 `{}` → `{}`", o.input, entry, o.output);
        } else {
            println!("将解压 `{}` → `{}`", o.input, o.output);
        }
        return 0;
    }

    let buf = match read_input(&o.input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{}: {e}", err_prefix());
            return 1;
        }
    };

    let (header, _) = match Header::decode(&buf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}: 解析 `{}` 失败: {e}", err_prefix(), o.input);
            return 1;
        }
    };

    let cred = match load_credential(&header, &o.private_key, &o.password, &o.key_password, o.ask_pass) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: {e}", err_prefix());
            return 1;
        }
    };

    if o.entry.is_some() && !header.archive {
        eprintln!("{}: 非归档容器不支持 --entry", err_prefix());
        return 1;
    }

    if header.archive {
        if let Some(entry_path) = &o.entry {
            // 单条目抽取：仍需整包解压以精确匹配路径。
            let plaintext = match unpack(&buf, credential_to_key(&cred)) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{}: {}", err_prefix(), pipeline_error_message("解压失败", &e));
                    return 1;
                }
            };
            let entries = match decode_archive(&plaintext) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("{}: 解析归档失败: {e}", err_prefix());
                    return 1;
                }
            };
            let entry = match entries.iter().find(|e| e.path == *entry_path) {
                Some(e) => e,
                None => {
                    eprintln!("{}: 归档中未找到条目 `{}`", err_prefix(), entry_path);
                    return 1;
                }
            };
            if entry.kind != EntryKind::File {
                eprintln!(
                    "{}: 条目 `{}` 不是普通文件，无法抽取",
                    err_prefix(),
                    entry_path
                );
                return 1;
            }
            if let Err(e) = ensure_not_exists(&o.output, o.force) {
                eprintln!("{}: {e}", err_prefix());
                return 1;
            }
            if let Err(e) = write_output(&o.output, &entry.data) {
                eprintln!("{}: {e}", err_prefix());
                return 1;
            }
            println_status(
                &o.output,
                format!(
                    "{} `{}` → `{}`（{} 字节）",
                    style::paint("已抽取", style::Color::Green, style::stdout_tty()),
                    entry.path,
                    o.output,
                    entry.data.len()
                ),
            );
            return 0;
        }

        // 全量解包：把解压后的归档流直接按条目写到磁盘，避免整包缓存。
        if let Err(e) = ensure_dir_target(&o.output, o.force) {
            eprintln!("{}: {e}", err_prefix());
            return 1;
        }
        let out_dir = Path::new(&o.output);
        if let Err(e) = std::fs::create_dir_all(out_dir) {
            eprintln!("{}: 创建输出目录失败: {e}", err_prefix());
            return 1;
        }
        let mut extractor = ArchiveExtractor::new(out_dir);
        if let Err(e) = unpack_to_writer(&buf, credential_to_key(&cred), &mut extractor) {
            eprintln!("{}: {}", err_prefix(), pipeline_error_message("解压失败", &e));
            return 1;
        }
        match extractor.finish() {
            Ok(count) => {
                println!(
                    "{} `{}` → `{}`（{} 个条目）",
                    style::paint("已解包", style::Color::Green, style::stdout_tty()),
                    o.input,
                    o.output,
                    count
                );
            }
            Err(e) => {
                eprintln!("{}: 解析归档失败: {e}", err_prefix());
                return 1;
            }
        }
    } else {
        if let Err(e) = ensure_not_exists(&o.output, o.force) {
            eprintln!("{}: {e}", err_prefix());
            return 1;
        }
        let total = if header.original_size == u64::MAX {
            0
        } else {
            header.original_size
        };
        let label = if header.encrypted { "解密+解压" } else { "解压" };
        match stream_decompress(&o.output, &buf, credential_to_key(&cred), total, label) {
            Ok(written) => {
                println_status(
                    &o.output,
                    format!(
                        "{} `{}` → `{}`（{} 字节）",
                        style::paint("已解包", style::Color::Green, style::stdout_tty()),
                        o.input,
                        o.output,
                        written
                    ),
                );
            }
            Err(e) => {
                eprintln!("{}: {e}", err_prefix());
                return 1;
            }
        }
    }
    0
}

fn cmd_list(o: &ListOpts) -> i32 {
    let buf = match read_input(&o.input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{}: {e}", err_prefix());
            return 1;
        }
    };
    let (header, _) = match Header::decode(&buf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}: 解析 `{}` 失败: {e}", err_prefix(), o.input);
            return 1;
        }
    };
    let cred = match load_credential(&header, &o.private_key, &o.password, &o.key_password, o.ask_pass) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: {e}", err_prefix());
            return 1;
        }
    };
    let plaintext = match unpack(&buf, credential_to_key(&cred)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}: {}", err_prefix(), pipeline_error_message("解压失败", &e));
            return 1;
        }
    };

    if header.archive {
        let entries = match decode_archive(&plaintext) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("{}: 解析归档失败: {e}", err_prefix());
                return 1;
            }
        };
        for e in &entries {
            if o.long {
                println!("{}", format_long_entry(e, o.human));
            } else {
                let size = if o.human {
                    human_size(e.data.len() as u64)
                } else {
                    e.data.len().to_string()
                };
                println!("{} {:>8}  {}", kind_marker(e.kind), size, e.path);
            }
        }
    } else {
        let size = if o.human {
            human_size(plaintext.len() as u64)
        } else {
            plaintext.len().to_string()
        };
        println!("{:>8}  (single file)", size);
    }
    0
}

fn cmd_test(o: &TestOpts) -> i32 {
    let buf = match read_input(&o.input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{}: {e}", err_prefix());
            return 1;
        }
    };
    let (header, _) = match Header::decode(&buf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}: 解析 `{}` 失败: {e}", err_prefix(), o.input);
            return 1;
        }
    };
    let cred = match load_credential(&header, &o.private_key, &o.password, &o.key_password, o.ask_pass) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: {e}", err_prefix());
            return 1;
        }
    };
    let plaintext = match unpack(&buf, credential_to_key(&cred)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}: {}", err_prefix(), pipeline_error_message("校验失败", &e));
            return 1;
        }
    };
    if header.archive {
        match decode_archive(&plaintext) {
            Ok(entries) => println!(
                "{}（{} 个条目）",
                style::paint("OK", style::Color::Green, style::stdout_tty()),
                entries.len()
            ),
            Err(e) => {
                eprintln!("{}: 解析归档失败: {e}", err_prefix());
                return 1;
            }
        }
    } else {
        println!(
            "{}（{} 字节）",
            style::paint("OK", style::Color::Green, style::stdout_tty()),
            plaintext.len()
        );
    }
    0
}

fn cmd_info(o: &InfoOpts) -> i32 {
    let buf = match read_input(&o.input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{}: {e}", err_prefix());
            return 1;
        }
    };
    let (header, _) = match Header::decode(&buf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}: 解析 `{}` 失败: {e}", err_prefix(), o.input);
            return 1;
        }
    };
    let cyan = |s: &str| style::paint(s, style::Color::Cyan, style::stdout_tty());
    println!(
        "{}: {}",
        cyan("格式版本"),
        if buf[4] == VERSION { VERSION } else { buf[4] }
    );
    println!("{}: {}", cyan("压缩级别"), header.level);
    println!(
        "{}: {}",
        cyan("归档"),
        if header.archive { "是" } else { "否" }
    );
    println!(
        "{}: {}",
        cyan("加密"),
        if !header.encrypted {
            "无"
        } else if header.password {
            "口令 (Argon2id)"
        } else {
            "ML-KEM"
        }
    );
    if header.encrypted && !header.password {
        println!("{}: {}", cyan("参数集"), header.kem);
    }
    if header.encrypted && header.password {
        println!(
            "{}: {} KiB / {} 次 / {} lanes",
            cyan("Argon2id"),
            header.memory_kib,
            header.iterations,
            header.lanes
        );
    }
    println!(
        "{}: {}",
        cyan("校验和"),
        if header.checksum { "SHAKE-256" } else { "无" }
    );
    println!(
        "{}: {}",
        cyan("原始大小"),
        if header.original_size == u64::MAX {
            "未知".to_string()
        } else {
            header.original_size.to_string()
        }
    );
    println!(
        "{}: {}",
        cyan("载荷大小"),
        if header.compressed_size == u64::MAX {
            "未知".to_string()
        } else {
            header.compressed_size.to_string()
        }
    );
    0
}

fn cmd_completion(o: &CompletionOpts) -> i32 {
    let Some(shell) = o.shell.as_deref() else {
        eprintln!(
            "{}: 缺少 shell 参数（可选 bash/zsh/fish/powershell）",
            err_prefix()
        );
        eprintln!("用法: rzp2 completion <bash|zsh|fish|powershell>");
        return 2;
    };
    match crate::completion::render(shell) {
        Ok(script) => {
            print!("{script}");
            0
        }
        Err(e) => {
            eprintln!("{}: {e}", err_prefix());
            2
        }
    }
}

fn cmd_sfx(o: &SfxOpts) -> i32 {
    let stub = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}: 无法获取当前可执行文件路径: {e}", err_prefix());
            return 1;
        }
    };
    match crate::sfx::create(&stub, Path::new(&o.input), Path::new(&o.output), o.force) {
        Ok(len) => {
            println!(
                "{} `{}`（内嵌 {} 字节，存根 `{}`）",
                style::paint("已生成", style::Color::Green, style::stdout_tty()),
                o.output,
                len,
                stub.display()
            );
            0
        }
        Err(e) => {
            eprintln!("{}: {e}", err_prefix());
            1
        }
    }
}

fn cmd_split(o: &SplitOpts) -> i32 {
    if o.dry_run {
        println!(
            "将分片 `{}` → `{}`（每片 {} 字节）",
            o.input, o.prefix, o.chunk_size
        );
        return 0;
    }

    let total = std::fs::metadata(&o.input).map(|m| m.len()).unwrap_or(0);
    let mut progress = Progress::new("分片", total, style::stderr_tty());
    match split::split_file(&o.input, &o.prefix, o.chunk_size, o.force, |done| progress.update(done))
    {
        Ok(count) => {
            progress.finish();
            println_status(
                &o.prefix,
                format!(
                    "{} `{}` → {} 个分片（每片 ≤ {} 字节）",
                    style::paint("已分片", style::Color::Green, style::stdout_tty()),
                    o.input,
                    count,
                    o.chunk_size
                ),
            );
            0
        }
        Err(e) => {
            progress.finish();
            eprintln!("{}: {e}", err_prefix());
            1
        }
    }
}

fn cmd_merge(o: &MergeOpts) -> i32 {
    if o.dry_run {
        println!("将合并 `{}` → `{}`", o.input, o.output);
        return 0;
    }

    // 读取清单以获得总大小，用于进度百分比。
    let (_, manifest_path) = match split::locate_manifest(&o.input) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}: {e}", err_prefix());
            return 1;
        }
    };
    let total = match std::fs::read(&manifest_path)
        .map_err(|e| format!("读取清单 `{}` 失败: {e}", manifest_path))
        .and_then(|d| split::decode_manifest(&d))
    {
        Ok(m) => m.total_size,
        Err(e) => {
            eprintln!("{}: {e}", err_prefix());
            return 1;
        }
    };

    let mut progress = Progress::new("合并", total, style::stderr_tty());
    match split::merge_file(&o.input, &o.output, o.force, |done| progress.update(done)) {
        Ok(written) => {
            progress.finish();
            println_status(
                &o.output,
                format!(
                    "{} `{}` → `{}`（{} 字节）",
                    style::paint("已合并", style::Color::Green, style::stdout_tty()),
                    o.input,
                    o.output,
                    written
                ),
            );
            0
        }
        Err(e) => {
            progress.finish();
            eprintln!("{}: {e}", err_prefix());
            1
        }
    }
}

fn cmd_keygen(o: &KeygenOpts) -> i32 {
    let params = mlkem_params(o.params);
    let (pk, sk) = crate::mlkem::keygen(&params);

    let pub_pem = encode_key(KeyKind::Public, o.params, &pk);

    // 指定 --private-password 时用口令加密私钥，否则输出明文 PEM。
    let priv_pem = match resolve_password(&o.private_password, true) {
        Ok(Some(pw)) => match encode_encrypted_private_key(o.params, &sk, &pw) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}: 加密私钥失败: {e}", err_prefix());
                return 1;
            }
        },
        Ok(None) => encode_key(KeyKind::Private, o.params, &sk),
        Err(e) => {
            eprintln!("{}: {e}", err_prefix());
            return 1;
        }
    };

    if let Err(e) = std::fs::write(&o.public_key, &pub_pem) {
        eprintln!(
            "{}: 写入公钥 `{}` 失败: {e}",
            err_prefix(),
            o.public_key.display()
        );
        return 1;
    }
    if let Err(e) = std::fs::write(&o.private_key, &priv_pem) {
        eprintln!(
            "{}: 写入私钥 `{}` 失败: {e}",
            err_prefix(),
            o.private_key.display()
        );
        return 1;
    }
    // 私钥文件收紧为 0600（仅所有者可读写）。
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&o.private_key, std::fs::Permissions::from_mode(0o600));
    }
    println!(
        "{} {} 密钥对：\n  公钥: {}\n  私钥: {}",
        style::paint("已生成", style::Color::Green, style::stdout_tty()),
        o.params,
        o.public_key.display(),
        o.private_key.display()
    );
    0
}

fn kind_marker(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::File => "-",
        EntryKind::Dir => "d",
        EntryKind::Symlink => "l",
    }
}

/// 以字节数生成人可读大小（B / KiB / MiB / GiB / TiB）。
fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut val = n as f64;
    let mut unit = 0;
    while val >= 1024.0 && unit < UNITS.len() - 1 {
        val /= 1024.0;
        unit += 1;
    }
    if val >= 100.0 {
        format!("{:.0} {}", val, UNITS[unit])
    } else if val >= 10.0 {
        format!("{:.1} {}", val, UNITS[unit])
    } else {
        format!("{:.2} {}", val, UNITS[unit])
    }
}

/// 由完整 `mode`（含文件类型位）与条目类型生成 `ls -l` 风格权限串。
fn mode_string(mode: u32, kind: EntryKind) -> String {
    let perm = mode & 0o7777;
    let mut s = String::with_capacity(10);
    s.push(match kind {
        EntryKind::File => '-',
        EntryKind::Dir => 'd',
        EntryKind::Symlink => 'l',
    });
    let bits = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];
    for (bit, ch) in bits {
        s.push(if perm & bit != 0 { ch } else { '-' });
    }
    s
}

/// 长格式条目行：权限、大小、mtime、路径（符号链接附目标）。
fn format_long_entry(e: &Entry, human: bool) -> String {
    let size = if human {
        human_size(e.data.len() as u64)
    } else {
        e.data.len().to_string()
    };
    let mode = mode_string(e.mode, e.kind);
    let mtime = format_mtime(e.mtime);
    match e.kind {
        EntryKind::Symlink => format!(
            "{mode} {:>9}  {mtime}  {} -> {}",
            size, e.path, e.link_target
        ),
        EntryKind::Dir => format!("{mode} {:>9}  {mtime}  {}/", size, e.path),
        EntryKind::File => format!("{mode} {:>9}  {mtime}  {}", size, e.path),
    }
}

/// 将 Unix 秒转为 `YYYY-MM-DD HH:MM:SS`（UTC）。
fn format_mtime(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02}")
}

/// Howard Hinnant 的「日序数 → 公历日期」算法（`civil_from_days`）。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(unix)]
fn entry_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}

#[cfg(not(unix))]
fn entry_mode(meta: &std::fs::Metadata) -> u32 {
    if meta.is_dir() {
        0o755
    } else {
        0o644
    }
}

fn entry_mtime(meta: &std::fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 归档条目过滤器：`include` / `exclude` glob 模式。
///
/// 语义：
/// - 未指定任何 `include` 时，默认包含全部（但仍受 `exclude` 限制）。
/// - `include` 命中即包含，`exclude` 命中即排除，`exclude` 优先。
/// - 目录路径命中 `exclude` 时整棵子树被剪枝（不再递归），这是常见的高效排除语义。
struct ArchiveFilter {
    includes: Vec<String>,
    excludes: Vec<String>,
}

impl ArchiveFilter {
    fn from_opts(include: &[String], exclude: &[String]) -> Self {
        Self {
            includes: include.to_vec(),
            excludes: exclude.to_vec(),
        }
    }

    /// 条目路径（相对归档根、`/` 分隔）是否被包含。
    fn include(&self, rel: &str) -> bool {
        let included = self.includes.is_empty() || self.includes.iter().any(|p| glob_match(p, rel));
        let excluded = self.excludes.iter().any(|p| glob_match(p, rel));
        included && !excluded
    }

    /// 目录是否应被剪枝（目录自身路径命中排除模式时返回 true）。
    fn prune_dir(&self, rel: &str) -> bool {
        self.excludes.iter().any(|p| glob_match(p, rel))
    }
}

/// 简易 glob 匹配：支持 `*`（匹配任意字符序列，含 `/` 与空）、
/// `?`（匹配单个字符）与 `[...]`（字符类，支持 `!` / `^` 取反与 `a-z` 区间）。
///
/// `**` 与 `*` 视为等价。零依赖实现，避免引入 glob crate。
pub fn glob_match(pattern: &str, path: &str) -> bool {
    glob_rec(pattern.as_bytes(), path.as_bytes())
}

fn glob_rec(p: &[u8], s: &[u8]) -> bool {
    if p.is_empty() {
        return s.is_empty();
    }
    match p[0] {
        b'*' => {
            // 合并连续的 `*`（`**` 与 `*` 等价），再尝试匹配 0..=s.len() 个字符。
            let mut i = 0;
            while i < p.len() && p[i] == b'*' {
                i += 1;
            }
            let rest = &p[i..];
            for k in 0..=s.len() {
                if glob_rec(rest, &s[k..]) {
                    return true;
                }
            }
            false
        }
        b'?' => {
            if s.is_empty() {
                false
            } else {
                glob_rec(&p[1..], &s[1..])
            }
        }
        b'[' => {
            if s.is_empty() {
                return false;
            }
            match match_class(p, s[0]) {
                Some((matched, rest)) => matched && glob_rec(rest, &s[1..]),
                None => false,
            }
        }
        c => !s.is_empty() && s[0] == c && glob_rec(&p[1..], &s[1..]),
    }
}

/// 解析 `[` 开头的字符类，返回 `(是否命中, 剩余模式字节)`；`None` 表示未闭合 `]`。
fn match_class(p: &[u8], c: u8) -> Option<(bool, &[u8])> {
    debug_assert_eq!(p.first(), Some(&b'['));
    let close = p.iter().position(|&b| b == b']')?;
    let body = &p[1..close];
    let (negate, body) = match body.first() {
        Some(b'!') | Some(b'^') => (true, &body[1..]),
        _ => (false, body),
    };
    let mut i = 0;
    let mut matched = false;
    while i < body.len() {
        if i + 2 < body.len() && body[i + 1] == b'-' {
            matched |= c >= body[i] && c <= body[i + 2];
            i += 3;
        } else {
            matched |= c == body[i];
            i += 1;
        }
    }
    Some((matched ^ negate, &p[close + 1..]))
}

/// 递归收集目录条目（相对路径，`/` 分隔）。`root` 始终是顶层输入目录，
/// 以便相对路径在任意递归深度下都相对顶层计算，保留完整目录层级。
/// `filter` 为 `None` 时不作过滤。
fn collect_dir(
    root: &Path,
    entries: &mut Vec<Entry>,
    filter: Option<&ArchiveFilter>,
) -> Result<(), String> {
    collect_dir_rec(root, root, entries, filter)
}

fn collect_dir_rec(
    base: &Path,
    dir: &Path,
    entries: &mut Vec<Entry>,
    filter: Option<&ArchiveFilter>,
) -> Result<(), String> {
    for item in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
        let item = item.map_err(|e| e.to_string())?;
        let path = item.path();
        let rel = path
            .strip_prefix(base)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let meta = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        let mode = entry_mode(&meta);
        let mtime = entry_mtime(&meta);

        let ft = meta.file_type();
        if ft.is_dir() {
            // 目录自身命中排除模式时剪枝整棵子树。
            if filter.is_some_and(|f| f.prune_dir(&rel)) {
                continue;
            }
            if filter.is_none_or(|f| f.include(&rel)) {
                entries.push(Entry::dir(rel.clone(), mode, mtime));
            }
            collect_dir_rec(base, &path, entries, filter)?;
        } else if ft.is_symlink() {
            if filter.is_none_or(|f| f.include(&rel)) {
                let target = std::fs::read_link(&path)
                    .map_err(|e| e.to_string())?
                    .to_string_lossy()
                    .into_owned();
                entries.push(Entry::symlink(rel, mode, mtime, target));
            }
        } else if ft.is_file() && filter.is_none_or(|f| f.include(&rel)) {
            let data = std::fs::read(&path).map_err(|e| e.to_string())?;
            entries.push(Entry::file(rel, mode, mtime, data));
        }
        // 忽略其他类型（socket、设备等）。
    }
    Ok(())
}

/// 校验路径安全（拒绝 `..` 与绝对路径），返回拼接后的目标路径。
fn safe_join(base: &Path, rel: &str) -> Result<PathBuf, String> {
    let p = Path::new(rel);
    if p.is_absolute() {
        return Err(format!("拒绝绝对路径 `{rel}`"));
    }
    for comp in p.components() {
        if comp == std::path::Component::ParentDir {
            return Err(format!("拒绝包含 `..` 的路径 `{rel}`"));
        }
    }
    Ok(base.join(p))
}

/// 解包归档到目录。
pub(crate) fn extract_archive(entries: &[Entry], out_dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    for e in entries {
        let dest = safe_join(out_dir, &e.path)?;
        match e.kind {
            EntryKind::Dir => {
                std::fs::create_dir_all(&dest).map_err(|e| e.to_string())?;
            }
            EntryKind::File => {
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                std::fs::write(&dest, &e.data).map_err(|e| e.to_string())?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(e.mode));
                }
            }
            EntryKind::Symlink => {
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                #[cfg(unix)]
                {
                    std::os::unix::fs::symlink(&e.link_target, &dest).map_err(|e| e.to_string())?;
                }
                #[cfg(not(unix))]
                {
                    let _ = (&dest, &e.link_target);
                }
            }
        }
    }
    Ok(())
}

fn archive_path(err: String) -> crate::archive::ArchiveError {
    crate::archive::ArchiveError::UnsafePath(err)
}

fn archive_io(e: std::io::Error) -> crate::archive::ArchiveError {
    crate::archive::ArchiveError::Io(e.kind())
}

/// 流式解包的落盘回调：把解析出的条目写入 `out_dir`。
struct ArchiveSink<'a> {
    out_dir: &'a Path,
    file: Option<(File, PathBuf, u32)>,
    count: u64,
}

impl EntrySink for ArchiveSink<'_> {
    fn on_entry(&mut self, entry: &StreamEntry) -> Result<(), crate::archive::ArchiveError> {
        let dest = safe_join(self.out_dir, &entry.path).map_err(archive_path)?;
        match entry.kind {
            EntryKind::Dir => {
                std::fs::create_dir_all(&dest).map_err(archive_io)?;
            }
            EntryKind::Symlink => {
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent).map_err(archive_io)?;
                }
                #[cfg(unix)]
                std::os::unix::fs::symlink(&entry.link_target, &dest).map_err(archive_io)?;
                #[cfg(not(unix))]
                let _ = (&dest, &entry.link_target);
            }
            EntryKind::File => unreachable!("普通文件条目走 on_file_*"),
        }
        self.count += 1;
        Ok(())
    }

    fn on_file_start(&mut self, entry: &StreamEntry) -> Result<(), crate::archive::ArchiveError> {
        let dest = safe_join(self.out_dir, &entry.path).map_err(archive_path)?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(archive_io)?;
        }
        let file = File::create(&dest).map_err(archive_io)?;
        self.file = Some((file, dest, entry.mode));
        Ok(())
    }

    fn on_file_data(&mut self, data: &[u8]) -> Result<(), crate::archive::ArchiveError> {
        if let Some((file, _, _)) = &mut self.file {
            file.write_all(data).map_err(archive_io)?;
        }
        Ok(())
    }

    fn on_file_end(&mut self) -> Result<(), crate::archive::ArchiveError> {
        #[cfg(unix)]
        if let Some((file, dest, mode)) = self.file.take() {
            drop(file);
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(mode));
        }
        #[cfg(not(unix))]
        if let Some((file, _, _)) = self.file.take() {
            drop(file);
        }
        self.count += 1;
        Ok(())
    }
}

/// 把解压后的归档字节流增量喂给 [`StreamUnpacker`] 并落盘。
struct ArchiveExtractor<'a> {
    unpacker: StreamUnpacker,
    sink: ArchiveSink<'a>,
}

impl<'a> ArchiveExtractor<'a> {
    fn new(out_dir: &'a Path) -> Self {
        Self {
            unpacker: StreamUnpacker::new(),
            sink: ArchiveSink {
                out_dir,
                file: None,
                count: 0,
            },
        }
    }

    /// 校验归档流已完整结束，返回已解包条目数。
    fn finish(self) -> Result<u64, String> {
        self.unpacker.finish().map_err(|e| e.to_string())
    }
}

impl Write for ArchiveExtractor<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Err(e) = self.unpacker.feed(buf, &mut self.sink) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e.to_string(),
            ));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 计算字符串的终端显示宽度（CJK 等宽字符按 2 计）。
fn display_width(s: &str) -> usize {
    s.chars().map(|c| if is_wide_char(c) { 2 } else { 1 }).sum()
}

fn is_wide_char(c: char) -> bool {
    matches!(
        c,
        '\u{1100}'..='\u{115F}'
            | '\u{2E80}'..='\u{303E}'
            | '\u{3041}'..='\u{33FF}'
            | '\u{3400}'..='\u{4DBF}'
            | '\u{4E00}'..='\u{9FFF}'
            | '\u{A000}'..='\u{A4CF}'
            | '\u{AC00}'..='\u{D7A3}'
            | '\u{F900}'..='\u{FAFF}'
            | '\u{FE30}'..='\u{FE4F}'
            | '\u{FF00}'..='\u{FF60}'
            | '\u{FFE0}'..='\u{FFE6}'
            | '\u{20000}'..='\u{2FFFD}'
            | '\u{30000}'..='\u{3FFFD}'
    )
}

/// 把帮助文本渲染为带颜色的文本；`tty` 为真时上色，否则输出纯文本。
fn render_usage(tty: bool) -> String {
    let text = help_text();
    let lines: Vec<&str> = text.lines().collect();
    let opt_col = option_column(&lines);
    let mut out = String::new();
    for line in lines {
        out.push_str(&highlight_line(line, tty, opt_col));
        out.push('\n');
    }
    out
}

/// 计算所有选项行里最宽的“缩进 + 选项名 + 参数”显示宽度，用于对齐说明列。
fn option_column(lines: &[&str]) -> usize {
    lines
        .iter()
        .filter_map(|l| {
            let trimmed = l.trim_start();
            if !trimmed.starts_with('-') {
                return None;
            }
            let lead = l.len() - trimmed.len();
            let end = trimmed.find("  ").unwrap_or(trimmed.len());
            Some(lead + display_width(&trimmed[..end]))
        })
        .max()
        .unwrap_or(0)
}

fn highlight_line(line: &str, tty: bool, opt_col: usize) -> String {
    let trimmed = line.trim_start();
    if trimmed.starts_with("RZP2") || trimmed.starts_with("rzp2 ") || trimmed.ends_with(':') {
        style::paint(line, style::Color::Bold, tty)
    } else if is_subcommand_line(trimmed) {
        highlight_subcommand_line(line, tty)
    } else if trimmed.starts_with('-') {
        highlight_option_line(line, tty, opt_col)
    } else {
        line.to_string()
    }
}

fn is_subcommand_line(trimmed: &str) -> bool {
    const SUBS: [&str; 9] = [
        "compress",
        "decompress",
        "keygen",
        "list",
        "test",
        "info",
        "sfx",
        "split",
        "merge",
    ];
    SUBS.iter().any(|c| {
        trimmed
            .strip_prefix(c)
            .is_some_and(|rest| rest.starts_with(' '))
    })
}

/// 给 `  compress <input> ...` 行上色：命令字用青色。
fn highlight_subcommand_line(line: &str, tty: bool) -> String {
    let lead = line.len() - line.trim_start().len();
    let body = &line[lead..];
    let cmd_end = body.find(' ').unwrap_or(body.len());
    let cmd = &body[..cmd_end];
    format!(
        "{}{}{}",
        &line[..lead],
        style::paint(cmd, style::Color::Cyan, tty),
        &body[cmd_end..]
    )
}

/// 给选项行上色并对齐说明列：选项名+参数用绿色，说明文字统一对齐。
fn highlight_option_line(line: &str, tty: bool, opt_col: usize) -> String {
    let lead = line.len() - line.trim_start().len();
    let body = &line[lead..];
    let (opt, desc) = match body.find("  ") {
        Some(i) => (&body[..i], body[i..].trim_start_matches(' ')),
        None => (body, ""),
    };
    let cur = lead + display_width(opt);
    let pad = opt_col.saturating_sub(cur);
    if desc.is_empty() {
        format!(
            "{}{}",
            &line[..lead],
            style::paint(opt, style::Color::Green, tty)
        )
    } else {
        format!(
            "{}{}{}  {}",
            &line[..lead],
            style::paint(opt, style::Color::Green, tty),
            " ".repeat(pad),
            desc
        )
    }
}

fn help_text() -> String {
    format!(
        r#"RZP2-混合加密压缩工具

用法:
  rzp2 <子命令> [选项]

子命令:
  compress <input> -o <output> [选项]   压缩（可选加密）为 .rzp2 容器
  decompress <input> -o <output> [选项] 解压（可选解密） .rzp2 容器
  keygen [选项]                         生成 ML-KEM 长期公私钥对
  list <input> [选项]                   列出归档条目
  test <input> [选项]                   校验容器完整性
  info <input>                          查看容器元信息
  sfx <input> -o <output> [选项]        生成自解压可执行文件
  split <input> [选项]                  把文件切成多个分片
  merge <input> -o <output> [选项]      把分片合并回原文件

compress 选项:
  -o, --output <file>       输出文件（默认 <input>.rzp2；- 表示 stdout）
  -e, --encrypt             使用 ML-KEM 混合加密（需 --public-key）
      --public-key <file>   接收方公钥（PEM，可重复指定多个接收者）
      --params <set>        ML-KEM 参数集: {params}（默认 mlkem768）
      --password <pw>       使用口令加密（Argon2id，- 表示交互式无回显读取）
      --ask-pass            交互式输入加密口令（无回显，二次确认）
      --level <0-9>         压缩级别（默认 5）
      --dict-size <bytes>   覆盖字典大小
      --checksum            附加未压缩明文 SHAKE-256 校验和
      --include <glob>      仅打包匹配的路径（可重复，仅目录归档）
      --exclude <glob>      排除匹配的路径（可重复，仅目录归档）
      --threads <n>         并行压缩线程数（>1 启用分块压缩，默认 1）
      --block-size <bytes>  分块压缩每块大小（默认 4 MiB）
      --dry-run             只打印将执行的动作，不实际读写
  -f, --force               覆盖已存在的输出文件

decompress 选项:
  -o, --output <file>       输出文件或目录（默认去掉 .rzp2；- 表示 stdout）
      --private-key <file>  接收方私钥（PEM，ML-KEM 加密容器必需）
      --key-password <pw>   私钥文件口令（加密私钥必需，- 表示交互式无回显读取）
      --password <pw>       口令（口令加密容器必需；缺省且终端可用时自动提示）
      --ask-pass            强制交互式输入口令
      --entry <path>        仅从归档抽取单个条目（-o - 输出到 stdout）
      --dry-run             只打印将执行的动作，不实际读写
  -f, --force               覆盖已存在的输出文件

list / test 选项:
      --private-key <file>  接收方私钥（PEM）
      --key-password <pw>   私钥文件口令（加密私钥必需）
      --password <pw>       口令
      --ask-pass            强制交互式输入口令

list 选项:
  -l, --long               长格式：权限、大小、mtime、符号链接目标
      --human-readable     以 B/KiB/MiB 等可读单位显示大小

keygen 选项:
      --params <set>        ML-KEM 参数集（默认 mlkem768）
      --public <file>       公钥输出路径（默认 rzp2_<params>.key.pub）
      --private <file>      私钥输出路径（默认 rzp2_<params>.key）
      --private-password <pw> 口令加密私钥（- 表示交互式无回显读取）

sfx 选项:
  -o, --output <file>       输出自解压可执行文件（默认 <input> 去 .rzp2，Windows 加 .exe）
  -f, --force               覆盖已存在的输出文件

split 选项:
  -o, --output <prefix>     分片输出前缀（默认 <input>）
      --chunk-size <bytes>  每个分片大小（默认 10 MiB）
      --dry-run             只打印将执行的动作，不实际读写
  -f, --force               覆盖已存在的分片/清单

merge 选项:
  -o, --output <file>       输出文件（默认取清单记录的原始文件名）
      --dry-run             只打印将执行的动作，不实际读写
  -f, --force               覆盖已存在的输出文件

通用:
  -h, --help                显示帮助
  -V, --version             显示版本
  口令也可通过 RZP2_PASSWORD 环境变量提供（适合脚本免交互）。

容器格式: magic '{magic}'，版本 {ver}。输入可用 - 表示 stdin/stdout。
"#,
        params = KEM_PARAM_NAMES,
        magic = String::from_utf8_lossy(&MAGIC),
        ver = VERSION,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn compress_default_output_appends_rzp2() {
        let a = args(&["compress", "in.bin"]);
        match parse(&a).unwrap() {
            Action::Compress(o) => {
                assert_eq!(o.input, "in.bin");
                assert_eq!(o.output, "in.bin.rzp2");
            }
            _ => panic!("wrong action"),
        }
    }

    #[test]
    fn decompress_default_output_strips_rzp2() {
        let a = args(&["decompress", "in.bin.rzp2"]);
        match parse(&a).unwrap() {
            Action::Decompress(o) => {
                assert_eq!(o.input, "in.bin.rzp2");
                assert_eq!(o.output, "in.bin");
            }
            _ => panic!("wrong action"),
        }
    }

    #[test]
    fn decompress_requires_deducible_output() {
        let a = args(&["decompress", "in.bin"]);
        assert!(parse(&a).is_err());
    }

    #[test]
    fn compress_encrypt_requires_key() {
        let a = args(&["compress", "in.bin", "-o", "out.rzp2", "--encrypt"]);
        assert!(parse(&a).is_err());
    }

    #[test]
    fn compress_parse_ok() {
        let a = args(&[
            "compress",
            "in.bin",
            "-o",
            "out.rzp2",
            "--params",
            "mlkem1024",
            "--level",
            "7",
            "--checksum",
        ]);
        match parse(&a).unwrap() {
            Action::Compress(o) => {
                assert_eq!(o.params, Some(KemParams::MlKem1024));
                assert!(o.checksum);
                assert!(!o.encrypt);
                assert_eq!(o.level, 7);
            }
            _ => panic!("wrong action"),
        }
    }

    #[test]
    fn compress_parses_multiple_public_keys() {
        let a = args(&[
            "compress",
            "in.bin",
            "-o",
            "out.rzp2",
            "--encrypt",
            "--public-key",
            "a.pub",
            "--public-key",
            "b.pub",
            "--key",
            "c.pub",
        ]);
        match parse(&a).unwrap() {
            Action::Compress(o) => {
                assert_eq!(o.public_keys.len(), 3);
                assert_eq!(o.public_keys[2].to_str().unwrap(), "c.pub");
            }
            _ => panic!("wrong action"),
        }
    }

    #[test]
    fn compress_parses_threads_and_block_size() {
        let a = args(&[
            "compress",
            "in.bin",
            "-o",
            "out.rzp2",
            "--threads",
            "8",
            "--block-size",
            "1048576",
        ]);
        match parse(&a).unwrap() {
            Action::Compress(o) => {
                assert_eq!(o.threads, 8);
                assert_eq!(o.block_size, 1_048_576);
            }
            _ => panic!("wrong action"),
        }
    }

    #[test]
    fn compress_rejects_encrypt_and_password() {
        let a = args(&[
            "compress",
            "in.bin",
            "-o",
            "out.rzp2",
            "--encrypt",
            "--public-key",
            "k.pub",
            "--password",
            "x",
        ]);
        assert!(parse(&a).is_err());
    }

    #[test]
    fn compress_rejects_bad_level() {
        let a = args(&["compress", "in.bin", "-o", "o", "--level", "99"]);
        assert!(parse(&a).is_err());
    }

    #[test]
    fn force_flag_parsed() {
        let a = args(&["compress", "in.bin", "-o", "out.rzp2", "--force"]);
        match parse(&a).unwrap() {
            Action::Compress(o) => assert!(o.force),
            _ => panic!("wrong action"),
        }
        let a = args(&["decompress", "in.rzp2", "-o", "out", "--overwrite"]);
        match parse(&a).unwrap() {
            Action::Decompress(o) => assert!(o.force),
            _ => panic!("wrong action"),
        }
    }

    #[test]
    fn keygen_defaults() {
        let a = args(&["keygen"]);
        match parse(&a).unwrap() {
            Action::Keygen(o) => {
                assert_eq!(o.params, KemParams::MlKem768);
            }
            _ => panic!("wrong action"),
        }
    }

    #[test]
    fn completion_parse_ok() {
        let a = args(&["completion", "bash"]);
        match parse(&a).unwrap() {
            Action::Completion(o) => assert_eq!(o.shell.as_deref(), Some("bash")),
            _ => panic!("wrong action"),
        }
    }

    #[test]
    fn compress_parses_include_exclude() {
        let a = args(&[
            "compress",
            "dir",
            "-o",
            "out.rzp2",
            "--include",
            "*.rs",
            "--exclude",
            "target/**",
            "--exclude",
            "*.tmp",
        ]);
        match parse(&a).unwrap() {
            Action::Compress(o) => {
                assert_eq!(o.include, vec!["*.rs"]);
                assert_eq!(o.exclude, vec!["target/**", "*.tmp"]);
            }
            _ => panic!("wrong action"),
        }
    }

    #[test]
    fn glob_matches_basic() {
        assert!(glob_match("*.rs", "main.rs"));
        assert!(glob_match("*.rs", "src/main.rs"));
        assert!(!glob_match("*.rs", "main.cpp"));
        assert!(glob_match("src/*.rs", "src/main.rs"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(glob_match("**", "any/deep/path"));
        assert!(glob_match("foo", "foo"));
        assert!(!glob_match("foo", "foobar"));
    }

    #[test]
    fn glob_matches_char_class() {
        assert!(glob_match("file[0-9].txt", "file5.txt"));
        assert!(!glob_match("file[0-9].txt", "filex.txt"));
        assert!(glob_match("file[!0-9].txt", "filex.txt"));
        assert!(glob_match("file[^0-9].txt", "filex.txt"));
    }

    #[test]
    fn compress_parses_dry_run() {
        let a = args(&["compress", "in.bin", "-o", "out.rzp2", "--dry-run"]);
        match parse(&a).unwrap() {
            Action::Compress(o) => assert!(o.dry_run),
            _ => panic!("wrong action"),
        }
    }

    #[test]
    fn decompress_parses_entry_and_dry_run() {
        let a = args(&["decompress", "in.rzp2", "--entry", "dir/a.txt", "--dry-run"]);
        match parse(&a).unwrap() {
            Action::Decompress(o) => {
                assert_eq!(o.entry.as_deref(), Some("dir/a.txt"));
                assert!(o.dry_run);
                assert_eq!(o.output, "a.txt");
            }
            _ => panic!("wrong action"),
        }
    }

    #[test]
    fn decompress_entry_with_explicit_output() {
        let a = args(&["decompress", "in.rzp2", "--entry", "dir/a.txt", "-o", "x"]);
        match parse(&a).unwrap() {
            Action::Decompress(o) => assert_eq!(o.output, "x"),
            _ => panic!("wrong action"),
        }
    }

    #[test]
    fn list_parses_long_and_human() {
        let a = args(&["list", "in.rzp2", "-l", "--human-readable"]);
        match parse(&a).unwrap() {
            Action::List(o) => {
                assert!(o.long);
                assert!(o.human);
            }
            _ => panic!("wrong action"),
        }
    }

    #[test]
    fn entry_default_output_uses_leaf() {
        assert_eq!(entry_default_output("dir/a.txt").unwrap(), "a.txt");
        assert!(entry_default_output("/").is_err());
    }

    #[test]
    fn human_size_formats_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1.00 KiB");
        assert_eq!(human_size(10 * 1024), "10.0 KiB");
        assert_eq!(human_size(1500), "1.46 KiB");
        assert_eq!(human_size(2 * 1024 * 1024), "2.00 MiB");
    }

    #[test]
    fn format_mtime_known_timestamp() {
        assert_eq!(format_mtime(0), "1970-01-01 00:00:00");
        assert_eq!(format_mtime(1_700_000_000), "2023-11-14 22:13:20");
    }

    #[test]
    fn mode_string_permissions() {
        assert_eq!(mode_string(0o100755, EntryKind::File), "-rwxr-xr-x");
        assert_eq!(mode_string(0o40755, EntryKind::Dir), "drwxr-xr-x");
        assert_eq!(mode_string(0o120777, EntryKind::Symlink), "lrwxrwxrwx");
    }
}
