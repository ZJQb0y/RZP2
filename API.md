# RZP2 库 API

RZP2 0.19.1 是一个从零自研的混合加密压缩库，库名 `rzp2`。核心算法全部手写实现，
零运行时第三方依赖（OS 随机源与密钥清零均从零实现）。

## 模块概览

- `format`：容器格式定义与头部序列化 / 反序列化
- `lzma`：LZMA / LZMA2 编解码器
- `filters`：可逆预过滤链（BCJ x86/ARM/ARM64/RISC-V + Delta + Deflate / JPEG / PNG / GIF 重压缩）
- `recompress`：格式感知重压缩（DEFLATE 符号级 / gzip 容器级 / ZIP 容器级 / JPEG 熵层 /
  PNG IDAT / GIF LZW），供 `Filter::Deflate` / `Filter::Jpeg` / `Filter::Png` / `Filter::Gif` 使用
- `parallel`：多进程并行块编码（Unix fork / Windows spawn，崩溃隔离）
- `formats`：外部压缩 / 归档格式解码（`crc` / `deflate` / `gzip` / `xz` / `tar` /
  `zip` / `bzip2` / `sevenz`），供 `decompress` 按魔数探测后调用
- `mlkem`：ML-KEM（FIPS 203）密钥封装
- `aead`：ChaCha20-Poly1305 AEAD
- `crypto`：BLAKE2b、Argon2、X25519、OS 随机源（`rand`）与密钥清零（`zeroize`）原语
- `hybrid`：混合加密（ML-KEM / ML-KEM+X25519 + KDF + AEAD）与口令派生
- `archive`：目录归档流编解码
- `pipeline`：压缩 →（可选）加密 → 封包 的高层读写管线
- `progress`：零依赖终端进度条（`Progress` / `ProgressReader` / `ProgressWriter`）
- `split`：文件分片 / 合并与分片清单编解码
- `keys`：PEM 风格密钥文件序列化
- `cli`：命令行入口

## 动态库（C ABI FFI）

除 Rust 库外，工作区还包含两个按功能拆分的 `cdylib` crate，导出 C ABI 供 C/C++ 等
语言调用（各功能独立，需要哪种就用哪种）：

- `rzp2-compress`（库名 `rzp2_compress`）：LZMA1 alone 压缩 / 解压。
  - `rzp2_compress` / `rzp2_decompress` / `rzp2_decompressed_size` / `rzp2_compress_version`
- `rzp2-crypto`（库名 `rzp2_crypto`）：ML-KEM(+X25519) 密钥生成与混合加解密、AEAD、口令派生。
  - `rzp2_kem_keygen` / `rzp2_kem_public_key_size` / `rzp2_kem_secret_key_size`
  - `rzp2_crypto_encrypt` / `rzp2_crypto_decrypt`
  - `rzp2_aead_encrypt` / `rzp2_aead_decrypt` / `rzp2_derive_key`

函数签名与二进制布局见头文件 `crates/rzp2-compress/include/rzp2_compress.h` 与
`crates/rzp2-crypto/include/rzp2_crypto.h`，使用示例见 `examples/ffi/`。

## `format`

```rust
pub const MAGIC: [u8; 4];
pub const VERSION: u8;          // 4
pub const VERSION_MIN: u8;      // 1（读取兼容）
pub const HEADER_PREFIX_SIZE: usize; // 24
pub const NONCE_SIZE: usize;    // 12
pub const TAG_SIZE: usize;      // 16
pub const CHECKSUM_SIZE: usize; // 32
pub const SALT_SIZE: usize;     // 16

pub mod flag {
    pub const ENCRYPTED: u8; // 0b0000_0001
    pub const KEM_MASK: u8;  // 0b0000_0110
    pub const KEM_SHIFT: u8; // 1
    pub const CHECKSUM: u8;  // 0b0000_1000
    pub const PASSWORD: u8;  // 0b0001_0000
    pub const ARCHIVE: u8;   // 0b0010_0000
    pub const CHUNKED: u8;   // 0b0100_0000

    pub mod ext {
        pub const MULTI: u8;       // 0b0000_0001
        pub const BLOCKED: u8;     // 0b0000_0010
        pub const FINGERPRINT: u8; // 0b0000_0100
        pub const HYBRID: u8;      // 0b0000_1000（ML-KEM + X25519 混合封装）
        pub const STORED: u8;      // 0b0001_0000（直存原始明文）
        pub const FILTERS: u8;     // 0b0010_0000（可逆预过滤链）
    }
}

pub enum KemParams {
    MlKem512, MlKem768, MlKem1024,
    MlKem512X25519, MlKem768X25519, MlKem1024X25519,
}
impl KemParams {
    pub const DEFAULT: Self;
    pub fn is_hybrid(self) -> bool;         // 是否为 X25519 混合变体
    pub fn base(self) -> Self;              // 对应的纯 ML-KEM 参数集
    pub fn into_hybrid(self) -> Self;       // 转成对应混合变体
    pub fn to_bits(self) -> u8;             // flags 中的 2 位编码（不含混合标志）
    pub fn from_bits(bits: u8) -> Option<Self>;
    pub fn to_key_byte(self) -> u8;         // 密钥文件 params_byte（bit7 为混合标志）
    pub fn from_key_byte(b: u8) -> Option<Self>;
    pub fn name(self) -> &'static str;
    pub fn from_name(s: &str) -> Option<Self>;
    pub fn all() -> [Self; 6];
}

pub struct Header {
    pub original_size: u64,
    pub compressed_size: u64,
    pub encrypted: bool,
    pub password: bool,
    pub archive: bool,
    pub checksum: bool,
    pub chunked: bool,
    pub multi: bool,
    pub blocked: bool,
    pub stored: bool,
    pub filters: FilterChain,
    pub level: u8,
    pub kem: KemParams,
    pub hybrid: bool,               // 单接收者时是否使用 ML-KEM + X25519 混合封装
    pub ek: Vec<u8>,
    pub recipients: Vec<Recipient>,
    pub salt: [u8; SALT_SIZE],
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
    pub nonce: [u8; NONCE_SIZE],
    pub checksum_digest: [u8; CHECKSUM_SIZE],
}
impl Header {
    pub fn plain(original_size: u64, compressed_size: u64) -> Self;
    pub fn flags(&self) -> u8;
    pub fn encode(&self) -> Vec<u8>;
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), FormatError>;
}

pub enum FormatError {
    Truncated,
    BadMagic,
    UnsupportedVersion(u8),
    BadKemParams,
    BadFlags,
}
```

## `lzma`

```rust
pub mod decoder;
pub mod encoder;
pub mod lz_encoder;
pub mod lzma2;
pub mod match_finder;
pub mod prob_model;
pub mod range_coder;

pub use decoder::{LzDecoder, LzmaError};
pub use match_finder::MatchFinderKind;

pub const DEFAULT_LEVEL: u8; // 5

pub enum MatchFinderKind { HashChain, Bt4 }

pub struct LzmaParams {
    pub lc: u32,
    pub lp: u32,
    pub pb: u32,
    pub dict_size: u32,
    pub nice_len: usize,
    pub max_chain: usize,
    pub match_finder: MatchFinderKind,
}
impl LzmaParams {
    pub fn new(lc: u32, lp: u32, pb: u32, dict_size: u32) -> Self;
}
impl Default for LzmaParams;

pub fn preset(level: u8) -> LzmaParams;
pub fn encode(input: &[u8], params: &LzmaParams) -> Vec<u8>;
pub fn decode(input: &[u8]) -> Result<Vec<u8>, LzmaError>;
```

输出采用 LZMA1「alone」格式：`properties(1) + dict_size(4, LE) + uncompressed_size(8, LE)`
后接原始 LZMA 码流，与 LZMA SDK / xz 兼容。`preset(level)` 返回 `lc=3, lp=0, pb=2`
的预设，字典大小随级别变化；`match_finder` 在 `level >= 8` 时为 `Bt4`（二叉树匹配
查找器，压缩率更高但更慢），否则为 `HashChain`（哈希链）。`nice_len` / `max_chain`
随级别提升而增大，用于调优搜索深度与快速停断。`lzma::lzma2` 提供标准 LZMA2 分块
编解码器，供 `xz` 容器使用。

`lzma::lzma2`：

```rust
pub const DEFAULT_CHUNK_SIZE: usize; // 64 KiB

pub fn encode(input: &[u8], params: &LzmaParams, chunk_size: usize) -> Vec<u8>;
pub fn encode_parallel(input: &[u8], params: &LzmaParams, chunk_size: usize, processes: usize) -> Vec<u8>;
pub struct Decoder;
impl Decoder {
    pub fn new(dict_size: usize) -> Self;
    pub fn decode(self, input: &[u8]) -> Result<Vec<u8>, LzmaError>;
}
```

`encode_parallel` 与 `encode` 输出逐字节一致，仅并行编码各块。

## `filters`

可逆预过滤链（BCJ / Delta / DEFLATE / JPEG / PNG / GIF 重压缩），在压缩前对明文做可逆
变换、解压后逆序还原。BCJ / Delta 保长；`Deflate` 把 gzip 或 ZIP 内的 DEFLATE 流、
`Jpeg` 把 baseline JPEG 的熵段、`Png` 把 PNG IDAT 内的 zlib/DEFLATE 流、`Gif` 把 GIF
图像数据的 LZW 码流重写为符号层表示（非保长），供外层 LZMA 进一步压缩。

```rust
pub const DELTA_DISTANCE_MAX: usize; // 256

pub enum Filter {
    Delta { distance: usize }, // 差分，distance 1..=256
    X86,
    Arm,
    Arm64,
    Riscv,
    Deflate, // gzip / ZIP DEFLATE 重压缩（非保长）
    Jpeg,    // baseline JPEG 熵层重压缩（非保长）
    Png,     // PNG IDAT 重压缩（非保长）
    Gif,     // GIF LZW 重压缩（非保长）
}
impl Filter {
    pub fn delta(distance: usize) -> Option<Self>;
    pub fn encode(self, data: &[u8]) -> Vec<u8>; // 正变换
    pub fn decode(self, data: &[u8]) -> Vec<u8>; // 逆变换
}

pub struct FilterChain(Vec<Filter>);
impl FilterChain {
    pub fn new() -> Self;
    pub fn from_filters(filters: Vec<Filter>) -> Self;
    pub fn is_empty(&self) -> bool;
    pub fn len(&self) -> usize;
    pub fn iter(&self) -> impl Iterator<Item = &Filter>;
    pub fn apply_forward(&self, data: &[u8]) -> Vec<u8>; // 按声明顺序正变换
    pub fn apply_inverse(&self, data: &[u8]) -> Vec<u8>; // 按声明逆序逆变换
    pub fn encode(&self) -> Vec<u8>;   // count(1) (id(1) param(1))*
    pub fn decode(buf: &[u8]) -> Option<(Self, usize)>;
    pub fn describe(&self) -> String;
}

pub fn filter_from_name(name: &str) -> Option<Filter>;   // x86/arm/arm64/riscv/deflate/gzip/zip/jpeg/png/gif
pub fn delta_from_name(name: &str) -> Option<Filter>;    // delta / delta=N
```

BCJ / Delta 过滤器保长，`Deflate` / `Jpeg` / `Png` / `Gif` 非保长；
`FilterChain::apply_forward` 与 `apply_inverse` 互为严格逆，链式时正变换按声明顺序、
逆变换按声明逆序。过滤链经 `format::flag::ext::FILTERS` 标志序列化进容器头部（v4+），
解码端据此还原。非保长过滤器在重压缩表示不比原始输入更小时会回退到原始字节（解码端
凭魔数区分），以避免对已良好压缩的媒体文件造成容器膨胀。

## `parallel`

```rust
pub const WORKER_ARG: &str; // "__rzp2-worker"（Windows 内部隐藏子命令）

pub enum Encoder { Lzma, Lzma2Chunk, Lzma2Stream }

pub fn encode_blocks_parallel(
    encoder: Encoder,
    blocks: &[&[u8]],
    params: &LzmaParams,
    workers: usize,
) -> Vec<Vec<u8>>;
```

多进程并行块编码：把互不依赖的块交给多个工作进程并行压缩，再按块序号回填。
Unix（macOS / Linux）用 `fork` + 管道（子进程经写时复制共享只读输入，零序列化），
Windows 用 `spawn` 复用本可执行文件的隐藏子命令经 stdin/stdout 传参；任一工作进程
崩溃不会拖垮主进程，缺失块在当前进程串行补齐。`workers` 被钳制到 `1..=块数`。

## `formats`

外部压缩 / 归档格式的解码器，物理上位于 `src/formats/`，根模块以扁平路径重新导出，
因此以下类型也可通过 `rzp2::gzip` / `rzp2::zip` 等既有路径访问。

```rust
pub mod bzip2;   // pub fn decode(&[u8]) -> Result<Vec<u8>, Bzip2Error>
pub mod deflate; // pub fn decompress(&[u8]) -> Result<Vec<u8>, DeflateError>
pub mod gzip;    // pub fn decode(&[u8]) -> Result<Vec<u8>, GzipError>
pub mod tar;     // pub fn decode(&[u8]) -> Result<Vec<Entry>, TarError>
pub mod zip;     // pub fn decode(&[u8]) -> Result<Vec<Entry>, ZipError>
pub mod sevenz;  // pub fn decode(&[u8]) -> Result<Vec<Entry>, SevenZError>
pub mod xz;      // .xz 容器（见下文）
pub mod crc;     // CRC32 / CRC64（见下文）
```

- `deflate`：DEFLATE（RFC 1951）inflate；`decompress` 解出全部输出，
  `decompress_consumed` 额外返回消费的输入字节数。
- `gzip`：gzip（RFC 1952）容器，校验 CRC32 + ISIZE。
- `tar`：tar 归档拆包，返回 `Vec<Entry>`。
- `zip`：zip 容器（方法 0 存储 / 8 Deflate），返回 `Vec<Entry>`。
- `bzip2`：bzip2 解码（BWT + MTF + RLE + Huffman），校验块 CRC 与合并 CRC。
- `sevenz`：7z 容器（LZMA2 / LZMA1 / Copy），返回 `Vec<Entry>`。

## `crc`

```rust
pub fn crc32(data: &[u8]) -> u32;
pub fn crc64(data: &[u8]) -> u64;
```

CRC32（IEEE 802.3）与 CRC64（ECMA-182），查找表以 `OnceLock` 缓存。

## `xz`

```rust
pub enum XzError {
    Corrupt, Truncated, UnsupportedCheck(u8), UnsupportedFilter(u64), InvalidDictSize(u32), Lzma(LzmaError)
}

pub fn encode(input: &[u8], params: &LzmaParams) -> Result<Vec<u8>, XzError>;
pub fn encode_blocks(input: &[u8], params: &LzmaParams, block_size: usize, processes: usize) -> Result<Vec<u8>, XzError>;
pub fn decode(input: &[u8]) -> Result<Vec<u8>, XzError>;
```

读写标准 `.xz` 容器：单流、单个或多个 Block、LZMA2 过滤器、CRC32 / CRC64 / None 校验
（编码使用 CRC32）。`encode` 写单块，`encode_blocks` 按 `block_size` 写多块并并行压缩；
`decode` 统一解压单块 / 多块。`dict_size` 必须是合法的 LZMA2 值（`2^n` 或 `3 * 2^(n-1)`），
否则返回 `XzError::InvalidDictSize`。

## `mlkem`

```rust
pub mod fips202;
pub mod kem;
pub mod ntt;
pub mod params;
pub mod poly;
pub mod sampling;

pub use kem::{decaps, encaps, encaps_derand, keygen, keygen_derand};
pub use params::{params_from_name, Params, MLKEM1024, MLKEM512, MLKEM768};
```

- `keygen(&params) -> (pk, sk)`：生成长期公私钥对
- `encaps(&params, pk) -> (ct, ss)`：封装得到密文与共享密钥
- `decaps(&params, sk, ct) -> ss`：解封装恢复共享密钥

## `aead`

```rust
pub mod chacha20;
pub mod poly1305;

pub const KEY_SIZE: usize;   // 32
pub const NONCE_SIZE: usize; // 12
pub const TAG_SIZE: usize;   // 16
pub const CHUNK_SIZE: usize; // 65536（64 KiB）

pub fn aead_encrypt(key, nonce, plaintext, aad) -> (Vec<u8>, [u8; TAG_SIZE]);
pub fn aead_decrypt(key, nonce, ciphertext, aad, tag) -> Result<Vec<u8>, ()>;

pub fn chunk_nonce(base: &[u8; NONCE_SIZE], index: u64) -> [u8; NONCE_SIZE];

pub struct ChunkedWriter<W: Write> { /* ... */ }
impl<W: Write> ChunkedWriter<W> {
    pub fn new(inner: W, key: [u8; KEY_SIZE], base_nonce: [u8; NONCE_SIZE], aad_prefix: &[u8]) -> Self;
    pub fn finish(&mut self) -> std::io::Result<()>;
}
impl<W: Write> Write for ChunkedWriter<W>;

pub fn chunked_decrypt(
    key: &[u8; KEY_SIZE],
    base_nonce: &[u8; NONCE_SIZE],
    payload: &[u8],
    aad_prefix: &[u8],
) -> Result<Vec<u8>, ()>;
```

## `crypto`

```rust
pub mod argon2;
pub mod blake2b;
pub mod rand;
pub mod x25519;
pub mod zeroize;
```

- `blake2b::blake2b(data: &[u8], out_len: usize) -> Vec<u8>`：可变长度 BLAKE2b（RFC 7693）。
- `argon2::argon2(pwd, salt, lanes, out_len, memory_kib, passes, typ, secret, ad) -> Vec<u8>`：
  Argon2（d / i / id，RFC 9106）。
- `x25519`：Curve25519 / X25519（RFC 7748）。`keygen() -> ([u8; 32], [u8; 32])` 生成
  临时公/私钥对，`derive_public(sk) -> [u8; 32]` 从私钥计算公钥，`x25519(sk, pk) -> [u8; 32]`
  计算共享密钥；`BASE_POINT` 为 X25519 基点，`X25519_BYTES = 32`。
- `rand::fill_bytes(buf: &mut [u8]) -> io::Result<()>`：用系统加密随机源填充缓冲区。
- `zeroize::Zeroize`：敏感数据清零 trait，对字节数组 / 切片提供 `zeroize()`（`write_volatile`）。

## `hybrid`

```rust
pub const DEFAULT_MEMORY_KIB: u32; // 65536
pub const DEFAULT_ITERATIONS: u32; // 3
pub const DEFAULT_LANES: u32;      // 4

pub enum HybridError { AuthenticationFailed, NonceMismatch }

pub struct HybridCiphertext {
    pub kem_ct: Vec<u8>,
    pub nonce: [u8; NONCE_SIZE],
    pub ct: Vec<u8>,
    pub tag: [u8; TAG_SIZE],
}

pub fn kdf(params: &Params, ss: &[u8; 32], label: &[u8]) -> ([u8; KEY_SIZE], [u8; NONCE_SIZE]);
pub fn derive_password_key(password: &[u8], salt: &[u8], memory_kib: u32, iterations: u32, lanes: u32) -> [u8; KEY_SIZE];
pub fn encrypt(params: &Params, recipient_pk: &[u8], plaintext: &[u8]) -> HybridCiphertext;
pub fn decrypt(params: &Params, recipient_sk: &[u8], hc: &HybridCiphertext) -> Result<Vec<u8>, HybridError>;
pub fn encapsulate(params: &Params, recipient_pk: &[u8]) -> (Vec<u8>, [u8; KEY_SIZE], [u8; NONCE_SIZE]);
pub fn decapsulate(params: &Params, recipient_sk: &[u8], kem_ct: &[u8]) -> Result<([u8; KEY_SIZE], [u8; NONCE_SIZE]), HybridError>;

// ML-KEM + X25519 混合封装（密钥为 mlkem_key || x25519_key，密文为 mlkem_ct || x25519_epk）
pub const X25519_BYTES: usize; // 32
pub fn split_hybrid_pk(params: &Params, pk: &[u8]) -> Option<(&[u8], &[u8])>;
pub fn split_hybrid_sk(params: &Params, sk: &[u8]) -> Option<(&[u8], &[u8])>;
pub fn encapsulate_hybrid(params: &Params, recipient_pk: &[u8]) -> (Vec<u8>, [u8; 32]);
pub fn decapsulate_hybrid(params: &Params, recipient_sk: &[u8], ek: &[u8]) -> [u8; 32];
pub fn encapsulate_hybrid_kdf(params: &Params, recipient_pk: &[u8]) -> (Vec<u8>, [u8; KEY_SIZE], [u8; NONCE_SIZE]);
pub fn decapsulate_hybrid_kdf(params: &Params, recipient_sk: &[u8], ek: &[u8]) -> Result<([u8; KEY_SIZE], [u8; NONCE_SIZE]), HybridError>;
pub fn encrypt_hybrid(params: &Params, recipient_pk: &[u8], plaintext: &[u8]) -> HybridCiphertext;
pub fn decrypt_hybrid(params: &Params, recipient_sk: &[u8], hc: &HybridCiphertext) -> Result<Vec<u8>, HybridError>;
```

## `archive`

```rust
pub enum EntryKind { File, Dir, Symlink }

pub struct Entry {
    pub path: String,
    pub kind: EntryKind,
    pub mode: u32,
    pub mtime: i64,
    pub data: Vec<u8>,
    pub link_target: String,
}
impl Entry {
    pub fn file(path, mode, mtime, data) -> Self;
    pub fn dir(path, mode, mtime) -> Self;
    pub fn symlink(path, mode, mtime, link_target) -> Self;
}

pub enum ArchiveError { Truncated, BadKind(u8), BadUtf8 }

pub fn encode_archive(entries: &[Entry]) -> Vec<u8>;
pub fn decode_archive(data: &[u8]) -> Result<Vec<Entry>, ArchiveError>;
```

## `pipeline`

```rust
pub enum Encryption<'a> {
    None,
    Kem { kem: KemParams, recipient_pk: &'a [u8] },
    Password { password: &'a [u8], memory_kib: u32, iterations: u32, lanes: u32 },
}

pub struct PackConfig<'a> {
    pub params: LzmaParams,
    pub level: u8,
    pub add_checksum: bool,
    pub archive: bool,
    pub encryption: Encryption<'a>,
    pub processes: usize,   // >1 时使用分块 LZMA 载荷并行压缩
    pub block_size: usize,  // 分块并行压缩的每块大小
}

pub enum DecryptKey<'a> { None, PrivateKey(&'a [u8]), Password(&'a [u8]) }

pub enum PipelineError {
    Format(FormatError),
    Lzma(LzmaError),
    Hybrid(HybridError),
    Archive(ArchiveError),
    SizeMismatch { expected: u64, actual: usize },
    ChecksumMismatch,
    Truncated,
    KeyMismatch,
    StreamingChecksum,
    Io(std::io::ErrorKind),
}

pub fn mlkem_params(kem: KemParams) -> Params;
pub fn kem_params(p: &Params) -> KemParams;
pub fn checksum(data: &[u8]) -> [u8; CHECKSUM_SIZE];
pub fn pack(plaintext: &[u8], config: &PackConfig) -> Result<Vec<u8>, PipelineError>;
pub fn unpack(data: &[u8], key: DecryptKey) -> Result<Vec<u8>, PipelineError>;
pub fn pack_to_writer<R: Read, W: Write>(
    reader: &mut R,
    config: &PackConfig,
    original_size: Option<u64>,
    writer: &mut W,
) -> Result<u64, PipelineError>;
```

## `progress`

```rust
pub struct Progress { /* ... */ }
impl Progress {
    pub fn new(label: &'static str, total: u64, enabled: bool) -> Self;
    pub fn update(&mut self, done: u64);
    pub fn add(&mut self, n: u64);
    pub fn finish(&mut self);
}

pub struct ProgressReader<R: Read> { /* ... */ }
impl<R: Read> ProgressReader<R> {
    pub fn new(inner: R, label: &'static str, total: u64, enabled: bool) -> Self;
    pub fn finish(&mut self);
}
impl<R: Read> Read for ProgressReader<R>;

pub struct ProgressWriter<W: Write> { /* ... */ }
impl<W: Write> ProgressWriter<W> {
    pub fn new(inner: W, label: &'static str, total: u64, enabled: bool) -> Self;
    pub fn finish(&mut self);
}
impl<W: Write> Write for ProgressWriter<W>;
```

- 渲染形如 `[===>             ]  45%  压缩  123 / 456 字节`；`total == 0` 时退化为无百分比显示。
- 仅在 stderr 为终端时启用，非终端（重定向 / 管道）静默。

## `split`

```rust
pub const SPLIT_MAGIC: &[u8];       // b"RZP2SPL1"
pub const MANIFEST_SUFFIX: &str;     // ".manifest"
pub const PART_SUFFIX: &str;         // ".part."
pub const DEFAULT_CHUNK_SIZE: usize; // 10 MiB

pub struct Manifest {
    pub name: String,
    pub chunk_count: u32,
    pub chunk_size: u64,
    pub total_size: u64,
}

pub fn encode_manifest(m: &Manifest) -> Vec<u8>;
pub fn decode_manifest(data: &[u8]) -> Result<Manifest, String>;
pub fn chunk_path(prefix: &str, index: u32) -> String;
pub fn locate_manifest(input: &str) -> Result<(String, String), String>;
pub fn split_file(input: &str, prefix: &str, chunk_size: usize, force: bool, progress: impl FnMut(u64)) -> Result<u32, String>;
pub fn merge_file(input: &str, output: &str, force: bool, progress: impl FnMut(u64)) -> Result<u64, String>;
```

- `split_file` 把文件切成 `<prefix>.part.NNNNN` 分片并写出 `<prefix>.manifest` 清单，返回分片数。
- `merge_file` 读清单按序拼接分片到 `output`，校验总大小，返回写出字节数。

## `keys`

```rust
pub const PUBLIC_HEADER: &str;
pub const PUBLIC_FOOTER: &str;
pub const PRIVATE_HEADER: &str;
pub const PRIVATE_FOOTER: &str;

pub enum KeyKind { Public, Private }
pub enum KeyError { BadPem, BadBase64, BadParams }

pub fn encode_key(kind: KeyKind, params: KemParams, raw: &[u8]) -> String;
pub fn decode_key(kind: KeyKind, pem: &str) -> Result<(KemParams, Vec<u8>), KeyError>;
pub fn base64_encode(data: &[u8]) -> String;
pub fn base64_decode(s: &str) -> Result<Vec<u8>, ()>;
```

## `cli`

```rust
pub fn run(args: &[String]) -> i32;
```

解析命令行并执行 `compress` / `decompress` / `keygen` / `list` / `test` / `info`，
返回进程退出码。
