# RZP2 库 API

RZP2 0.8.0 是一个从零自研的混合加密压缩库，库名 `rzp2`。核心算法全部手写实现，
零运行时第三方依赖（OS 随机源与密钥清零均从零实现）。

## 模块概览

- `format`：容器格式定义与头部序列化 / 反序列化
- `lzma`：LZMA 编解码器
- `mlkem`：ML-KEM（FIPS 203）密钥封装
- `aead`：ChaCha20-Poly1305 AEAD
- `crypto`：BLAKE2b、Argon2、OS 随机源（`rand`）与密钥清零（`zeroize`）原语
- `hybrid`：混合加密（ML-KEM + KDF + AEAD）与口令派生
- `archive`：目录归档流编解码
- `pipeline`：压缩 →（可选）加密 → 封包 的高层读写管线
- `progress`：零依赖终端进度条（`Progress` / `ProgressReader` / `ProgressWriter`）
- `split`：文件分片 / 合并与分片清单编解码
- `keys`：PEM 风格密钥文件序列化
- `cli`：命令行入口

## `format`

```rust
pub const MAGIC: [u8; 4];
pub const VERSION: u8;          // 3
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
}

pub enum KemParams { MlKem512, MlKem768, MlKem1024 }
impl KemParams {
    pub const DEFAULT: Self;
    pub fn to_bits(self) -> u8;
    pub fn from_bits(bits: u8) -> Option<Self>;
    pub fn name(self) -> &'static str;
    pub fn from_name(s: &str) -> Option<Self>;
    pub fn all() -> [Self; 3];
}

pub struct Header {
    pub original_size: u64,
    pub compressed_size: u64,
    pub encrypted: bool,
    pub password: bool,
    pub archive: bool,
    pub checksum: bool,
    pub chunked: bool,
    pub level: u8,
    pub kem: KemParams,
    pub ek: Vec<u8>,
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
pub mod match_finder;
pub mod prob_model;
pub mod range_coder;

pub use decoder::{LzDecoder, LzmaError};

pub const DEFAULT_LEVEL: u8; // 5

pub struct LzmaParams { pub lc: u32, pub lp: u32, pub pb: u32, pub dict_size: u32 }
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
的预设，字典大小随级别变化。

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
pub mod zeroize;
```

- `blake2b::blake2b(data: &[u8], out_len: usize) -> Vec<u8>`：可变长度 BLAKE2b（RFC 7693）。
- `argon2::argon2(pwd, salt, lanes, out_len, memory_kib, passes, typ, secret, ad) -> Vec<u8>`：
  Argon2（d / i / id，RFC 9106）。
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
