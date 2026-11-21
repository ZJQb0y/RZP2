//! RZP2 读写管线：压缩 →（可选）加密 → 封包；解包 →（可选）解密 → 解压。

use std::io::{Read, Seek, Write};

use crate::aead;
use crate::crypto::zeroize::Zeroize;
use crate::filters::FilterChain;
use crate::format::{
    Header, KemParams, Recipient, CHECKSUM_SIZE, FINGERPRINT_SIZE, NONCE_SIZE, SALT_SIZE, TAG_SIZE,
};
use crate::hybrid::{self, HybridCiphertext};
use crate::lzma::{self, LzmaParams};
use crate::mlkem::fips202::{shake256, Keccak};
use crate::mlkem::{self, Params};

/// 可压缩性探测的采样大小（字节）：压缩前采样这么多字节判断是否值得压缩。
const STORE_SAMPLE_SIZE: usize = 64 * 1024;

/// 管线错误。
#[derive(Debug)]
pub enum PipelineError {
    Format(crate::format::FormatError),
    Lzma(lzma::LzmaError),
    Hybrid(hybrid::HybridError),
    Archive(crate::archive::ArchiveError),
    /// 解压后长度与头部记录不符。
    SizeMismatch {
        expected: u64,
        actual: usize,
    },
    /// 校验和不匹配。
    ChecksumMismatch,
    /// 输入被截断。
    Truncated,
    /// 解密所需凭据与容器加密模式不符。
    KeyMismatch,
    /// 口令解密认证失败（口令错误或数据被篡改）。
    BadPassword,
    /// 流式打包不支持附加明文校验和（需先读取全文才能写入头部）。
    StreamingChecksum,
    /// 底层 I/O 错误。
    Io(std::io::ErrorKind),
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Format(e) => write!(f, "format error: {e}"),
            Self::Lzma(e) => write!(f, "LZMA error: {e}"),
            Self::Hybrid(e) => write!(f, "hybrid error: {e}"),
            Self::Archive(e) => write!(f, "archive error: {e}"),
            Self::SizeMismatch { expected, actual } => {
                write!(f, "size mismatch: expected {expected} bytes, got {actual}")
            }
            Self::ChecksumMismatch => write!(f, "checksum mismatch"),
            Self::Truncated => write!(f, "truncated RZP2 payload"),
            Self::KeyMismatch => write!(f, "decryption key does not match container mode"),
            Self::BadPassword => write!(f, "bad password"),
            Self::StreamingChecksum => {
                write!(f, "streaming pack does not support the checksum option")
            }
            Self::Io(e) => write!(f, "I/O error: {e:?}"),
        }
    }
}

impl std::error::Error for PipelineError {}

impl From<crate::format::FormatError> for PipelineError {
    fn from(e: crate::format::FormatError) -> Self {
        Self::Format(e)
    }
}

impl From<lzma::LzmaError> for PipelineError {
    fn from(e: lzma::LzmaError) -> Self {
        Self::Lzma(e)
    }
}

impl From<hybrid::HybridError> for PipelineError {
    fn from(e: hybrid::HybridError) -> Self {
        Self::Hybrid(e)
    }
}

impl From<crate::archive::ArchiveError> for PipelineError {
    fn from(e: crate::archive::ArchiveError) -> Self {
        Self::Archive(e)
    }
}

impl From<std::io::Error> for PipelineError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind())
    }
}

/// 将 [`KemParams`] 映射为 [`mlkem::Params`]（混合变体取其纯 ML-KEM 基底）。
pub fn mlkem_params(kem: KemParams) -> Params {
    match kem.base() {
        KemParams::MlKem512 => mlkem::MLKEM512,
        KemParams::MlKem768 => mlkem::MLKEM768,
        KemParams::MlKem1024 => mlkem::MLKEM1024,
        _ => unreachable!(),
    }
}

/// 返回指定 KEM 参数集下 `ek` 字段的期望字节数（混合时含 X25519 临时公钥）。
fn ek_len(kem: KemParams, params: &Params) -> usize {
    if kem.is_hybrid() {
        params.ciphertext_bytes + hybrid::X25519_BYTES
    } else {
        params.ciphertext_bytes
    }
}

/// 从 [`mlkem::Params`] 反推 [`KemParams`]。
pub fn kem_params(p: &Params) -> KemParams {
    if p.k == 2 {
        KemParams::MlKem512
    } else if p.k == 3 {
        KemParams::MlKem768
    } else {
        KemParams::MlKem1024
    }
}

/// 计算明文校验和（SHAKE-256，32 字节）。
pub fn checksum(data: &[u8]) -> [u8; CHECKSUM_SIZE] {
    let mut out = [0u8; CHECKSUM_SIZE];
    shake256(&mut out, data);
    out
}

/// 计算接收者公钥指纹（SHAKE-256，32 字节）。
pub fn fingerprint(pk: &[u8]) -> [u8; FINGERPRINT_SIZE] {
    let mut out = [0u8; FINGERPRINT_SIZE];
    shake256(&mut out, pk);
    out
}

/// 打包时的加密配置。
#[derive(Clone, Copy)]
pub enum Encryption<'a> {
    /// 不加密。
    None,
    /// ML-KEM 公钥加密。
    Kem {
        kem: KemParams,
        recipient_pk: &'a [u8],
    },
    /// 多接收者 ML-KEM 公钥加密（每接收者独立封装随机 DEK）。
    KemMulti {
        recipients: &'a [(KemParams, &'a [u8])],
    },
    /// 口令加密（Argon2id）。
    Password {
        password: &'a [u8],
        memory_kib: u32,
        iterations: u32,
        lanes: u32,
    },
}

/// 打包配置。
pub struct PackConfig<'a> {
    /// LZMA 压缩参数。
    pub params: LzmaParams,
    /// 压缩级别预设（记录在头部，仅作元信息）。
    pub level: u8,
    /// 是否附加明文校验和。
    pub add_checksum: bool,
    /// 载荷是否为归档流。
    pub archive: bool,
    /// 加密配置。
    pub encryption: Encryption<'a>,
    /// 并行压缩进程数（>1 时使用分块 LZMA 载荷）。
    pub processes: usize,
    /// 分块并行压缩时每块的大小。
    pub block_size: usize,
    /// 可逆预过滤链（BCJ / Delta，压缩前施加、解压后逆变换）。
    pub filters: FilterChain,
}

/// 解包时的解密凭据。
pub enum DecryptKey<'a> {
    None,
    PrivateKey(&'a [u8]),
    Password(&'a [u8]),
}

/// 常量时间比较。
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// 生成随机字节（调用 OS 随机源）。
fn random_bytes(buf: &mut [u8]) -> Result<(), PipelineError> {
    crate::crypto::rand::fill_bytes(buf).map_err(|_| PipelineError::Truncated)
}

/// 为多接收者加密生成随机 DEK 与基准 nonce，封装到每个接收者并写入头部，
/// 返回 `(dek, nonce)` 供内容加密使用。
fn seal_multi_recipients(
    header: &mut Header,
    recipients: &[(KemParams, &[u8])],
) -> Result<([u8; aead::KEY_SIZE], [u8; NONCE_SIZE]), PipelineError> {
    let mut dek = [0u8; aead::KEY_SIZE];
    random_bytes(&mut dek)?;
    let mut nonce = [0u8; NONCE_SIZE];
    random_bytes(&mut nonce)?;

    header.encrypted = true;
    header.multi = true;
    header.nonce = nonce;

    let mut recs = Vec::with_capacity(recipients.len());
    for &(kem, pk) in recipients {
        let params = mlkem_params(kem);
        let (kem_ct, mut ss) = if kem.is_hybrid() {
            hybrid::encapsulate_hybrid(&params, pk)
        } else {
            hybrid::encapsulate_ss(&params, pk)
        };
        let wrapped = hybrid::wrap_dek(&params, &ss, &kem_ct, &dek);
        ss.zeroize();
        recs.push(Recipient {
            kem,
            ek: kem_ct,
            wrapped_dek: wrapped,
            fingerprint: fingerprint(pk),
        });
    }
    header.recipients = recs;
    Ok((dek, nonce))
}

/// 用接收者私钥尝试解包 DEK。多接收者场景下按公钥指纹快速定位对应接收者，
/// 指纹缺失（旧格式）或无法识别私钥参数集时回退为逐个尝试，首个认证成功即返回。
fn try_unwrap_dek(header: &Header, sk: &[u8]) -> Result<[u8; aead::KEY_SIZE], PipelineError> {
    let own_fp = public_key_fingerprint(sk);
    for r in &header.recipients {
        let params = mlkem_params(r.kem);
        if r.ek.len() != ek_len(r.kem, &params) {
            continue;
        }
        // 指纹存在且与本私钥不匹配，直接跳过；全零指纹（旧格式）仍尝试。
        if let Some(fp) = own_fp {
            if r.fingerprint != [0u8; FINGERPRINT_SIZE] && r.fingerprint != fp {
                continue;
            }
        }
        let mut ss = if r.kem.is_hybrid() {
            hybrid::decapsulate_hybrid(&params, sk, &r.ek)
        } else {
            hybrid::decapsulate_ss(&params, sk, &r.ek)
        };
        if let Ok(dek) = hybrid::unwrap_dek(&params, &ss, &r.ek, &r.wrapped_dek) {
            ss.zeroize();
            return Ok(dek);
        }
        ss.zeroize();
    }
    Err(PipelineError::Hybrid(
        hybrid::HybridError::AuthenticationFailed,
    ))
}

/// 从私钥字节中提取公钥并计算指纹；无法识别参数集时返回 `None`。
fn public_key_fingerprint(sk: &[u8]) -> Option<[u8; FINGERPRINT_SIZE]> {
    let (p, is_hybrid) = params_for_sk_len(sk.len())?;
    // sk 布局：dk_PKE || pk || H(pk) || z，其中 dk_PKE 长 `k * POLY_BYTES`。
    let indcpa_sk = p.k * crate::mlkem::params::POLY_BYTES;
    if sk.len() < indcpa_sk + p.public_key_bytes {
        return None;
    }
    let mlkem_pk = &sk[indcpa_sk..indcpa_sk + p.public_key_bytes];
    if !is_hybrid {
        return Some(fingerprint(mlkem_pk));
    }
    // 混合私钥 = mlkem_sk || x25519_sk，指纹覆盖完整公钥（mlkem_pk || x25519_pk）。
    let x25519_sk: [u8; hybrid::X25519_BYTES] = sk[p.secret_key_bytes..].try_into().ok()?;
    let x25519_pk = crate::crypto::x25519::derive_public(&x25519_sk);
    let mut full = Vec::with_capacity(p.public_key_bytes + hybrid::X25519_BYTES);
    full.extend_from_slice(mlkem_pk);
    full.extend_from_slice(&x25519_pk);
    Some(fingerprint(&full))
}

/// 根据私钥长度识别 ML-KEM 参数集与是否混合。
fn params_for_sk_len(len: usize) -> Option<(Params, bool)> {
    for p in [mlkem::MLKEM512, mlkem::MLKEM768, mlkem::MLKEM1024] {
        if len == p.secret_key_bytes {
            return Some((p, false));
        }
        if len == p.secret_key_bytes + hybrid::X25519_BYTES {
            return Some((p, true));
        }
    }
    None
}

/// 从 `reader` 读取至多 [`STORE_SAMPLE_SIZE`] 字节采样，返回采样缓冲与是否应直存。
///
/// 采样缓冲已从 `reader` 消费，调用方需将其与剩余输入拼接后再处理。
fn probe_compressibility<R: Read>(
    reader: &mut R,
    params: &LzmaParams,
) -> Result<(Vec<u8>, bool), PipelineError> {
    let mut sample = vec![0u8; STORE_SAMPLE_SIZE];
    let mut len = 0usize;
    while len < STORE_SAMPLE_SIZE {
        let n = reader.read(&mut sample[len..])?;
        if n == 0 {
            break;
        }
        len += n;
    }
    sample.truncate(len);
    let stored = !sample.is_empty() && lzma::is_incompressible(&sample, params, len);
    Ok((sample, stored))
}

/// 打包（压缩，可选加密）为完整 `.rzp2` 字节流。
pub fn pack(plaintext: &[u8], config: &PackConfig) -> Result<Vec<u8>, PipelineError> {
    pack_with_progress(plaintext, config, &mut |_, _| {})
}

/// 同 [`pack`]，并在分块并行压缩时回调 `on_progress(已完成块数, 总块数)`；
/// 串行 / 直存路径不切块，完成后回调一次 `(1, 1)`。
pub fn pack_with_progress(
    plaintext: &[u8],
    config: &PackConfig,
    on_progress: &mut dyn FnMut(usize, usize),
) -> Result<Vec<u8>, PipelineError> {
    // 1. 施加可逆预过滤链（保长），再压缩过滤后的数据（不可压缩时直存过滤数据）。
    let filtered = config.filters.apply_forward(plaintext);
    let stored = lzma::is_incompressible(&filtered, &config.params, STORE_SAMPLE_SIZE);
    let blocked = !stored && config.processes > 1;
    let compressed = if stored {
        on_progress(1, 1);
        filtered
    } else if blocked {
        lzma::encode_blocks_progress(
            &filtered,
            &config.params,
            config.block_size,
            config.processes,
            on_progress,
        )
    } else {
        on_progress(1, 1);
        lzma::encode(&filtered, &config.params)
    };

    let mut header = Header::plain(plaintext.len() as u64, compressed.len() as u64);
    header.level = config.level;
    header.archive = config.archive;
    header.blocked = blocked;
    header.stored = stored;
    header.filters = config.filters.clone();
    header.checksum = config.add_checksum;
    header.checksum_digest = if config.add_checksum {
        checksum(plaintext)
    } else {
        [0u8; CHECKSUM_SIZE]
    };

    // 2. 可选加密并序列化。
    seal(&mut header, &compressed, config)
}

/// 流式打包：从 `reader` 读取明文，压缩后返回完整 `.rzp2` 字节流。
pub fn pack_stream<R: Read>(reader: &mut R, config: &PackConfig) -> Result<Vec<u8>, PipelineError> {
    pack_stream_with_size(reader, config).map(|(packed, _)| packed)
}

/// 打包并返回打包结果与原始明文大小。
pub fn pack_stream_with_size<R: Read>(
    reader: &mut R,
    config: &PackConfig,
) -> Result<(Vec<u8>, u64), PipelineError> {
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;
    let original_size = data.len() as u64;
    let packed = pack(&data, config)?;
    Ok((packed, original_size))
}

/// 流式打包到 `writer`：明文经 LZMA 流式压缩后（若加密则套分块 AEAD）直接写出，
/// 不再在内存中构造完整压缩载荷。
///
/// `original_size` 为已知的明文大小（文件输入可由元数据得到，stdin 传 `None`）。
/// 流式模式下无法在头部记录明文校验和，`add_checksum` 必须为 `false`，否则报错。
/// 返回实际读入的明文字节数。
pub fn pack_to_writer<R: Read, W: Write>(
    reader: &mut R,
    config: &PackConfig,
    original_size: Option<u64>,
    writer: &mut W,
) -> Result<u64, PipelineError> {
    // 预过滤链需整段明文中施加，无法流式：缓冲后走缓冲式打包（支持校验和）。
    if !config.filters.is_empty() {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        let original_size = data.len() as u64;
        let packed = pack(&data, config)?;
        writer.write_all(&packed)?;
        return Ok(original_size);
    }

    if config.add_checksum {
        return Err(PipelineError::StreamingChecksum);
    }

    // 采样探测可压缩性：不可压缩时直存明文，避免无收益的压缩开销。
    let (sample, stored) = probe_compressibility(reader, &config.params)?;

    // 头部：stored 时 compressed_size 即原长；压缩时流式场景未知，置 u64::MAX。
    let compressed_size = if stored { original_size } else { None };
    let mut header = Header::plain(
        original_size.unwrap_or(u64::MAX),
        compressed_size.unwrap_or(u64::MAX),
    );
    header.level = config.level;
    header.archive = config.archive;
    header.stored = stored;

    // 加密：封装/派生密钥与基准 nonce，写入头部字段。
    let mut key: Option<[u8; aead::KEY_SIZE]> = None;
    let mut base_nonce = [0u8; aead::NONCE_SIZE];

    match &config.encryption {
        Encryption::None => {}
        Encryption::Kem { kem, recipient_pk } => {
            header.encrypted = true;
            header.chunked = true;
            header.kem = *kem;
            header.hybrid = kem.is_hybrid();
            let params = mlkem_params(*kem);
            let (kem_ct, k, nonce) = if kem.is_hybrid() {
                hybrid::encapsulate_hybrid_kdf(&params, recipient_pk)
            } else {
                hybrid::encapsulate(&params, recipient_pk)
            };
            header.ek = kem_ct;
            header.nonce = nonce;
            base_nonce = nonce;
            key = Some(k);
        }
        Encryption::KemMulti { recipients } => {
            header.chunked = true;
            let (dek, nonce) = seal_multi_recipients(&mut header, recipients)?;
            base_nonce = nonce;
            key = Some(dek);
        }
        Encryption::Password {
            password,
            memory_kib,
            iterations,
            lanes,
        } => {
            header.encrypted = true;
            header.chunked = true;
            header.password = true;
            header.memory_kib = *memory_kib;
            header.iterations = *iterations;
            header.lanes = *lanes;

            let mut salt = [0u8; SALT_SIZE];
            random_bytes(&mut salt)?;
            header.salt = salt;

            let mut nonce = [0u8; NONCE_SIZE];
            random_bytes(&mut nonce)?;
            header.nonce = nonce;
            base_nonce = nonce;

            key = Some(hybrid::derive_password_key(
                password,
                &salt,
                *memory_kib,
                *iterations,
                *lanes,
            ));
        }
    }

    let header_bytes = header.encode();
    writer.write_all(&header_bytes)?;

    // 采样数据已消费，需与剩余输入拼接后继续处理。
    let mut combined = std::io::Cursor::new(sample).chain(reader);

    match key {
        Some(k) => {
            let mut cw = aead::ChunkedWriter::new(writer, k, base_nonce, &header_bytes);
            let n = if stored {
                std::io::copy(&mut combined, &mut cw)?
            } else {
                lzma::encode_stream(&mut combined, &config.params, original_size, &mut cw)?
            };
            cw.finish()?;
            Ok(n)
        }
        None => {
            if stored {
                Ok(std::io::copy(&mut combined, writer)?)
            } else {
                Ok(lzma::encode_stream(
                    &mut combined,
                    &config.params,
                    original_size,
                    writer,
                )?)
            }
        }
    }
}

/// 流式打包到可 seek 的 writer，并支持明文校验和。
///
/// 未加密场景下，头部校验和字段位于头部末尾且不参与加密 AAD，因此可在写完载荷后
/// 回写；加密场景校验和位于头部且被 AAD 绑定，无法事后修改，返回
/// [`PipelineError::StreamingChecksum`]（调用方应回退到缓冲式打包）。
pub fn pack_to_writer_checksummed<R: Read, W: Write + Seek>(
    reader: &mut R,
    config: &PackConfig,
    original_size: Option<u64>,
    writer: &mut W,
) -> Result<u64, PipelineError> {
    if !config.add_checksum {
        return pack_to_writer(reader, config, original_size, writer);
    }
    // 预过滤链 + 校验和：缓冲后走缓冲式打包（支持校验和，且可加密）。
    if !config.filters.is_empty() {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        let original_size = data.len() as u64;
        let packed = pack(&data, config)?;
        writer.write_all(&packed)?;
        return Ok(original_size);
    }
    if !matches!(config.encryption, Encryption::None) {
        return Err(PipelineError::StreamingChecksum);
    }

    let (sample, stored) = probe_compressibility(reader, &config.params)?;

    let compressed_size = if stored { original_size } else { None };
    let mut header = Header::plain(
        original_size.unwrap_or(u64::MAX),
        compressed_size.unwrap_or(u64::MAX),
    );
    header.level = config.level;
    header.archive = config.archive;
    header.checksum = true;
    header.stored = stored;
    let header_bytes = header.encode();
    writer.write_all(&header_bytes)?;
    let checksum_offset = (header_bytes.len() - CHECKSUM_SIZE) as u64;

    let mut combined = std::io::Cursor::new(sample).chain(reader);
    let mut hashing = HashingReader::new(&mut combined, true);
    let n = if stored {
        std::io::copy(&mut hashing, writer)?
    } else {
        lzma::encode_stream(&mut hashing, &config.params, original_size, writer)?
    };
    let (_size, digest) = hashing.finish();

    // 回写头部校验和字段，然后把文件指针恢复到载荷末尾。
    let end = writer.stream_position()?;
    writer.seek(std::io::SeekFrom::Start(checksum_offset))?;
    writer.write_all(&digest)?;
    writer.seek(std::io::SeekFrom::Start(end))?;
    Ok(n)
}

/// 在读取过程中增量累计 SHAKE-256 校验和与字节数。
struct HashingReader<R: Read> {
    inner: R,
    keccak: Option<Keccak>,
    bytes: u64,
}

impl<R: Read> HashingReader<R> {
    fn new(inner: R, checksum_enabled: bool) -> Self {
        Self {
            inner,
            keccak: checksum_enabled.then(|| Keccak::new(136)),
            bytes: 0,
        }
    }

    fn finish(&mut self) -> (u64, [u8; CHECKSUM_SIZE]) {
        let mut digest = [0u8; CHECKSUM_SIZE];
        if let Some(k) = &mut self.keccak {
            k.finalize(0x1F);
            k.squeeze(&mut digest);
        }
        (self.bytes, digest)
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            if let Some(k) = &mut self.keccak {
                k.absorb(&buf[..n]);
            }
            self.bytes += n as u64;
        }
        Ok(n)
    }
}

/// 根据加密配置对压缩载荷进行加密并序列化为完整 `.rzp2` 字节流。
fn seal(
    header: &mut Header,
    compressed: &[u8],
    config: &PackConfig,
) -> Result<Vec<u8>, PipelineError> {
    match &config.encryption {
        Encryption::None => {
            let mut out = header.encode();
            out.extend_from_slice(compressed);
            Ok(out)
        }
        Encryption::Kem { kem, recipient_pk } => {
            header.encrypted = true;
            header.kem = *kem;
            header.hybrid = kem.is_hybrid();
            let params = mlkem_params(*kem);
            let hc = if kem.is_hybrid() {
                hybrid::encrypt_hybrid(&params, recipient_pk, compressed)
            } else {
                hybrid::encrypt(&params, recipient_pk, compressed)
            };
            header.ek = hc.kem_ct;
            header.nonce = hc.nonce;
            let mut out = header.encode();
            out.extend_from_slice(&hc.ct);
            out.extend_from_slice(&hc.tag);
            Ok(out)
        }
        Encryption::KemMulti { recipients } => {
            let (dek, nonce) = seal_multi_recipients(header, recipients)?;
            // AAD 绑定整个头部（含接收者列表与包裹的 DEK），防止篡改。
            let aad = header.encode();
            let (ct, tag) = aead::aead_encrypt(&dek, &nonce, compressed, &aad);
            let mut out = aad;
            out.extend_from_slice(&ct);
            out.extend_from_slice(&tag);
            Ok(out)
        }
        Encryption::Password {
            password,
            memory_kib,
            iterations,
            lanes,
        } => {
            header.encrypted = true;
            header.password = true;
            header.memory_kib = *memory_kib;
            header.iterations = *iterations;
            header.lanes = *lanes;

            let mut salt = [0u8; SALT_SIZE];
            random_bytes(&mut salt)?;
            header.salt = salt;

            let mut nonce = [0u8; NONCE_SIZE];
            random_bytes(&mut nonce)?;
            header.nonce = nonce;

            let mut key =
                hybrid::derive_password_key(password, &salt, *memory_kib, *iterations, *lanes);
            // AAD 绑定整个头部（含盐、KDF 参数、级别、大小、校验和），防止被篡改。
            let aad = header.encode();
            let (ct, t) = aead::aead_encrypt(&key, &nonce, compressed, &aad);
            key.zeroize();

            let mut out = aad;
            out.extend_from_slice(&ct);
            out.extend_from_slice(&t);
            Ok(out)
        }
    }
}

/// 从完整 `.rzp2` 字节流中定位并解密出压缩载荷（认证在解压之前完成）。
fn decrypt_payload<'a>(
    data: &[u8],
    header: &Header,
    offset: usize,
    key: DecryptKey<'a>,
) -> Result<Vec<u8>, PipelineError> {
    // 分块 AEAD：载荷为 `len + ct + tag` 帧序列，逐块认证解密，AAD 绑定头部字节与块序号。
    if header.chunked {
        let aad_prefix = &data[..offset];
        if header.multi {
            let sk = match key {
                DecryptKey::PrivateKey(sk) => sk,
                _ => return Err(PipelineError::KeyMismatch),
            };
            let dek = try_unwrap_dek(header, sk)?;
            return aead::chunked_decrypt(&dek, &header.nonce, &data[offset..], aad_prefix)
                .map_err(|_| PipelineError::Hybrid(hybrid::HybridError::AuthenticationFailed));
        }
        if header.password {
            let password = match key {
                DecryptKey::Password(p) => p,
                _ => return Err(PipelineError::KeyMismatch),
            };
            let mut derived = hybrid::derive_password_key(
                password,
                &header.salt,
                header.memory_kib,
                header.iterations,
                header.lanes,
            );
            let out = aead::chunked_decrypt(&derived, &header.nonce, &data[offset..], aad_prefix)
                .map_err(|_| PipelineError::BadPassword)?;
            derived.zeroize();
            return Ok(out);
        } else {
            let sk = match key {
                DecryptKey::PrivateKey(sk) => sk,
                _ => return Err(PipelineError::KeyMismatch),
            };
            let params = mlkem_params(header.kem);
            if header.ek.len() != ek_len(header.kem, &params) {
                return Err(PipelineError::Truncated);
            }
            let (derived_key, derived_nonce) = if header.hybrid {
                hybrid::decapsulate_hybrid_kdf(&params, sk, &header.ek)?
            } else {
                hybrid::decapsulate(&params, sk, &header.ek)?
            };
            if derived_nonce != header.nonce {
                return Err(PipelineError::Hybrid(hybrid::HybridError::NonceMismatch));
            }
            return aead::chunked_decrypt(
                &derived_key,
                &derived_nonce,
                &data[offset..],
                aad_prefix,
            )
            .map_err(|_| PipelineError::Hybrid(hybrid::HybridError::AuthenticationFailed));
        }
    }

    // 1. 定位载荷与尾部标签。
    let payload_end = if header.compressed_size == u64::MAX {
        if header.encrypted {
            data.len().saturating_sub(TAG_SIZE)
        } else {
            data.len()
        }
    } else {
        offset + header.compressed_size as usize
    };
    if data.len() < payload_end {
        return Err(PipelineError::Truncated);
    }
    let payload = &data[offset..payload_end];

    // 2. 可选解密。
    if !header.encrypted {
        return Ok(payload.to_vec());
    }

    if data.len() < payload_end + TAG_SIZE {
        return Err(PipelineError::Truncated);
    }
    let tag: [u8; TAG_SIZE] = data[payload_end..payload_end + TAG_SIZE]
        .try_into()
        .unwrap();

    if header.multi {
        let sk = match key {
            DecryptKey::PrivateKey(sk) => sk,
            _ => return Err(PipelineError::KeyMismatch),
        };
        let dek = try_unwrap_dek(header, sk)?;
        // AAD 用文件中的原始头部字节，避免序列化差异。
        return aead::aead_decrypt(&dek, &header.nonce, payload, &data[..offset], &tag)
            .map_err(|_| PipelineError::Hybrid(hybrid::HybridError::AuthenticationFailed));
    }

    if header.password {
        let password = match key {
            DecryptKey::Password(p) => p,
            _ => return Err(PipelineError::KeyMismatch),
        };
        let mut derived = hybrid::derive_password_key(
            password,
            &header.salt,
            header.memory_kib,
            header.iterations,
            header.lanes,
        );
        // AAD 用文件中的原始头部字节，避免序列化差异。
        let plain = aead::aead_decrypt(&derived, &header.nonce, payload, &data[..offset], &tag)
            .map_err(|_| PipelineError::BadPassword)?;
        derived.zeroize();
        Ok(plain)
    } else {
        let sk = match key {
            DecryptKey::PrivateKey(sk) => sk,
            _ => return Err(PipelineError::KeyMismatch),
        };
        let params = mlkem_params(header.kem);
        if header.ek.len() != ek_len(header.kem, &params) {
            return Err(PipelineError::Truncated);
        }
        let hc = HybridCiphertext {
            kem_ct: header.ek.clone(),
            nonce: header.nonce,
            ct: payload.to_vec(),
            tag,
        };
        if header.hybrid {
            Ok(hybrid::decrypt_hybrid(&params, sk, &hc)?)
        } else {
            Ok(hybrid::decrypt(&params, sk, &hc)?)
        }
    }
}

/// 解包完整 `.rzp2` 字节流（解压，可选解密）。
pub fn unpack(data: &[u8], key: DecryptKey) -> Result<Vec<u8>, PipelineError> {
    unpack_with_processes(data, key, 1)
}

/// 解包完整 `.rzp2` 字节流，分块载荷用 `processes` 个工作进程并行解压。
pub fn unpack_with_processes(
    data: &[u8],
    key: DecryptKey,
    processes: usize,
) -> Result<Vec<u8>, PipelineError> {
    let (header, offset) = Header::decode(data)?;
    let compressed = decrypt_payload(data, &header, offset, key)?;

    // 3. 解压（直存载荷直接作为过滤后数据）。
    let filtered = if header.stored {
        compressed
    } else if header.blocked {
        lzma::decode_blocks_with_processes(&compressed, processes)?
    } else {
        lzma::decode(&compressed)?
    };

    // 3.5 逆变换预过滤链，还原原始明文。
    let plaintext = header.filters.apply_inverse(&filtered);

    // 4. 校验长度（未知长度时跳过）。
    if header.original_size != u64::MAX && plaintext.len() as u64 != header.original_size {
        return Err(PipelineError::SizeMismatch {
            expected: header.original_size,
            actual: plaintext.len(),
        });
    }

    // 5. 校验校验和（常数时间比较）。
    if header.checksum && !ct_eq(&checksum(&plaintext), &header.checksum_digest) {
        return Err(PipelineError::ChecksumMismatch);
    }

    Ok(plaintext)
}

/// 流式写出时增量累计 SHAKE-256 校验和。
struct Sink<'a, W: Write> {
    inner: &'a mut W,
    keccak: Keccak,
    checksum_enabled: bool,
}

impl<W: Write> Write for Sink<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.checksum_enabled {
            self.keccak.absorb(buf);
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write> Sink<'_, W> {
    fn finish(&mut self) -> [u8; CHECKSUM_SIZE] {
        self.keccak.finalize(0x1F);
        let mut digest = [0u8; CHECKSUM_SIZE];
        self.keccak.squeeze(&mut digest);
        digest
    }
}

/// 流式解包：解压后的明文直接写入 `writer`，而非在内存中构造完整明文。
///
/// 加密/解密仍按「先认证标签、再解压」的顺序进行，不会写出未认证数据；
/// 校验和在写出过程中增量计算。返回写出的字节数。
pub fn unpack_to_writer<W: Write>(
    data: &[u8],
    key: DecryptKey,
    writer: &mut W,
) -> Result<u64, PipelineError> {
    unpack_to_writer_with_processes(data, key, writer, 1)
}

/// 流式解包：解压后的明文直接写入 `writer`，分块载荷用 `processes` 个工作进程并行解压。
pub fn unpack_to_writer_with_processes<W: Write>(
    data: &[u8],
    key: DecryptKey,
    writer: &mut W,
    processes: usize,
) -> Result<u64, PipelineError> {
    let (header, offset) = Header::decode(data)?;
    let compressed = decrypt_payload(data, &header, offset, key)?;

    let mut sink = Sink {
        inner: writer,
        keccak: Keccak::new(136),
        checksum_enabled: header.checksum,
    };
    let written = if !header.filters.is_empty() {
        // 有预过滤链：整段解压后逆变换，再写出。
        let filtered = if header.stored {
            compressed
        } else if header.blocked {
            lzma::decode_blocks_with_processes(&compressed, processes)?
        } else {
            lzma::decode(&compressed)?
        };
        let plaintext = header.filters.apply_inverse(&filtered);
        sink.write_all(&plaintext)?;
        plaintext.len()
    } else if header.stored {
        sink.write_all(&compressed)?;
        compressed.len()
    } else if header.blocked {
        let plaintext = lzma::decode_blocks_with_processes(&compressed, processes)?;
        sink.write_all(&plaintext)?;
        plaintext.len()
    } else {
        lzma::decode_to_writer(&compressed, &mut sink)?
    };

    if header.original_size != u64::MAX && written as u64 != header.original_size {
        return Err(PipelineError::SizeMismatch {
            expected: header.original_size,
            actual: written,
        });
    }
    if header.checksum && !ct_eq(&sink.finish(), &header.checksum_digest) {
        return Err(PipelineError::ChecksumMismatch);
    }

    Ok(written as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config<'a>(encryption: Encryption<'a>) -> PackConfig<'a> {
        PackConfig {
            params: LzmaParams::default(),
            level: lzma::DEFAULT_LEVEL,
            add_checksum: true,
            archive: false,
            encryption,
            processes: 1,
            block_size: lzma::DEFAULT_BLOCK_SIZE,
            filters: FilterChain::new(),
        }
    }

    /// 生成 ML-KEM + X25519 混合密钥对：公钥 `mlkem_pk || x25519_pk`，私钥 `mlkem_sk || x25519_sk`。
    fn hybrid_keypair(params: Params) -> (Vec<u8>, Vec<u8>) {
        let (mpk, msk) = mlkem::keygen(&params);
        let (xpk, xsk) = crate::crypto::x25519::keygen();
        let mut pk = Vec::new();
        pk.extend_from_slice(&mpk);
        pk.extend_from_slice(&xpk);
        let mut sk = Vec::new();
        sk.extend_from_slice(&msk);
        sk.extend_from_slice(&xsk);
        (pk, sk)
    }

    #[test]
    fn plain_roundtrip() {
        let data = b"pipeline plain roundtrip".repeat(100);
        let packed = pack(&data, &config(Encryption::None)).unwrap();
        let unpacked = unpack(&packed, DecryptKey::None).unwrap();
        assert_eq!(unpacked, data);
    }

    #[test]
    fn pack_stream_roundtrip() {
        let data = b"pack stream roundtrip".repeat(5000);

        // 明文路径。
        let mut r1 = std::io::Cursor::new(&data);
        let packed = pack_stream(&mut r1, &config(Encryption::None)).unwrap();
        let out = unpack(&packed, DecryptKey::None).unwrap();
        assert_eq!(out, data);

        // 公钥加密路径。
        let (pk, sk) = mlkem::keygen(&mlkem::MLKEM768);
        let mut r2 = std::io::Cursor::new(&data);
        let packed2 = pack_stream(
            &mut r2,
            &config(Encryption::Kem {
                kem: KemParams::MlKem768,
                recipient_pk: &pk,
            }),
        )
        .unwrap();
        let out2 = unpack(&packed2, DecryptKey::PrivateKey(&sk)).unwrap();
        assert_eq!(out2, data);
    }

    #[test]
    fn encrypted_roundtrip() {
        let (pk, sk) = mlkem::keygen(&mlkem::MLKEM768);
        let data = b"pipeline encrypted roundtrip".repeat(100);
        let packed = pack(
            &data,
            &config(Encryption::Kem {
                kem: KemParams::MlKem768,
                recipient_pk: &pk,
            }),
        )
        .unwrap();
        let unpacked = unpack(&packed, DecryptKey::PrivateKey(&sk)).unwrap();
        assert_eq!(unpacked, data);
    }

    #[test]
    fn multi_recipient_roundtrip() {
        let (pk0, sk0) = mlkem::keygen(&mlkem::MLKEM512);
        let (pk1, sk1) = mlkem::keygen(&mlkem::MLKEM768);
        let data = b"pipeline multi-recipient roundtrip".repeat(100);
        let recipients = [
            (KemParams::MlKem512, pk0.as_slice()),
            (KemParams::MlKem768, pk1.as_slice()),
        ];
        let packed = pack(
            &data,
            &config(Encryption::KemMulti {
                recipients: &recipients,
            }),
        )
        .unwrap();
        let (header, _) = Header::decode(&packed).unwrap();
        assert!(header.multi);
        assert_eq!(header.recipients.len(), 2);

        // 任一接收者私钥都可解密。
        assert_eq!(unpack(&packed, DecryptKey::PrivateKey(&sk0)).unwrap(), data);
        assert_eq!(unpack(&packed, DecryptKey::PrivateKey(&sk1)).unwrap(), data);
    }

    #[test]
    fn multi_recipient_stream_roundtrip() {
        let (pk0, sk0) = mlkem::keygen(&mlkem::MLKEM768);
        let (pk1, sk1) = mlkem::keygen(&mlkem::MLKEM1024);
        let data = b"pipeline multi-recipient stream".repeat(2000);
        let recipients = [
            (KemParams::MlKem768, pk0.as_slice()),
            (KemParams::MlKem1024, pk1.as_slice()),
        ];
        let mut r = std::io::Cursor::new(&data);
        let packed = pack_stream(
            &mut r,
            &config(Encryption::KemMulti {
                recipients: &recipients,
            }),
        )
        .unwrap();
        let (header, _) = Header::decode(&packed).unwrap();
        assert!(header.multi);
        assert_eq!(unpack(&packed, DecryptKey::PrivateKey(&sk0)).unwrap(), data);
        assert_eq!(unpack(&packed, DecryptKey::PrivateKey(&sk1)).unwrap(), data);
    }

    #[test]
    fn multi_recipient_chunked_roundtrip() {
        let (pk0, sk0) = mlkem::keygen(&mlkem::MLKEM768);
        let (pk1, sk1) = mlkem::keygen(&mlkem::MLKEM1024);
        let data = b"pipeline multi-recipient chunked".repeat(5000);
        let recipients = [
            (KemParams::MlKem768, pk0.as_slice()),
            (KemParams::MlKem1024, pk1.as_slice()),
        ];
        let mut cfg = config(Encryption::KemMulti {
            recipients: &recipients,
        });
        cfg.add_checksum = false;
        let mut r = std::io::Cursor::new(&data);
        let mut out = Vec::new();
        pack_to_writer(&mut r, &cfg, Some(data.len() as u64), &mut out).unwrap();
        let (header, _) = Header::decode(&out).unwrap();
        assert!(header.multi);
        assert!(header.chunked);
        assert_eq!(unpack(&out, DecryptKey::PrivateKey(&sk0)).unwrap(), data);
        assert_eq!(unpack(&out, DecryptKey::PrivateKey(&sk1)).unwrap(), data);
    }

    #[test]
    fn multi_recipient_wrong_key_fails() {
        let (pk0, _sk0) = mlkem::keygen(&mlkem::MLKEM768);
        let (_other_pk, other_sk) = mlkem::keygen(&mlkem::MLKEM768);
        let data = b"pipeline multi-recipient wrong key";
        let recipients = [(KemParams::MlKem768, pk0.as_slice())];
        let packed = pack(
            data,
            &config(Encryption::KemMulti {
                recipients: &recipients,
            }),
        )
        .unwrap();
        assert!(matches!(
            unpack(&packed, DecryptKey::PrivateKey(&other_sk)),
            Err(PipelineError::Hybrid(_))
        ));
    }

    #[test]
    fn hybrid_roundtrip() {
        let (pk, sk) = hybrid_keypair(mlkem::MLKEM768);
        let data = b"pipeline hybrid roundtrip".repeat(100);
        let packed = pack(
            &data,
            &config(Encryption::Kem {
                kem: KemParams::MlKem768X25519,
                recipient_pk: &pk,
            }),
        )
        .unwrap();
        let (header, _) = Header::decode(&packed).unwrap();
        assert!(header.hybrid);
        assert_eq!(unpack(&packed, DecryptKey::PrivateKey(&sk)).unwrap(), data);
    }

    #[test]
    fn hybrid_stream_roundtrip() {
        let (pk, sk) = hybrid_keypair(mlkem::MLKEM768);
        let data = b"pipeline hybrid stream".repeat(5000);
        let mut r = std::io::Cursor::new(&data);
        let packed = pack_stream(
            &mut r,
            &config(Encryption::Kem {
                kem: KemParams::MlKem768X25519,
                recipient_pk: &pk,
            }),
        )
        .unwrap();
        assert_eq!(unpack(&packed, DecryptKey::PrivateKey(&sk)).unwrap(), data);
    }

    #[test]
    fn hybrid_chunked_roundtrip() {
        let (pk, sk) = hybrid_keypair(mlkem::MLKEM768);
        let data = b"pipeline hybrid chunked".repeat(5000);
        let mut cfg = config(Encryption::Kem {
            kem: KemParams::MlKem768X25519,
            recipient_pk: &pk,
        });
        cfg.add_checksum = false;
        let mut r = std::io::Cursor::new(&data);
        let mut out = Vec::new();
        pack_to_writer(&mut r, &cfg, Some(data.len() as u64), &mut out).unwrap();
        let (header, _) = Header::decode(&out).unwrap();
        assert!(header.hybrid);
        assert!(header.chunked);
        assert_eq!(unpack(&out, DecryptKey::PrivateKey(&sk)).unwrap(), data);
    }

    #[test]
    fn hybrid_multi_recipient_roundtrip() {
        let (hpk, hsk) = hybrid_keypair(mlkem::MLKEM768);
        let (pk1, sk1) = mlkem::keygen(&mlkem::MLKEM1024);
        let data = b"pipeline hybrid multi-recipient".repeat(100);
        let recipients = [
            (KemParams::MlKem768X25519, hpk.as_slice()),
            (KemParams::MlKem1024, pk1.as_slice()),
        ];
        let packed = pack(
            &data,
            &config(Encryption::KemMulti {
                recipients: &recipients,
            }),
        )
        .unwrap();
        let (header, _) = Header::decode(&packed).unwrap();
        assert!(header.multi);
        assert!(header.recipients[0].kem.is_hybrid());
        assert_eq!(unpack(&packed, DecryptKey::PrivateKey(&hsk)).unwrap(), data);
        assert_eq!(unpack(&packed, DecryptKey::PrivateKey(&sk1)).unwrap(), data);
    }

    #[test]
    fn hybrid_wrong_key_fails() {
        let (pk, _sk) = hybrid_keypair(mlkem::MLKEM768);
        let (_other_pk, other_sk) = hybrid_keypair(mlkem::MLKEM768);
        let data = b"pipeline hybrid wrong key";
        let packed = pack(
            data,
            &config(Encryption::Kem {
                kem: KemParams::MlKem768X25519,
                recipient_pk: &pk,
            }),
        )
        .unwrap();
        assert!(matches!(
            unpack(&packed, DecryptKey::PrivateKey(&other_sk)),
            Err(PipelineError::Hybrid(_))
        ));
    }

    #[test]
    fn password_roundtrip() {
        let data = b"pipeline password roundtrip".repeat(100);
        let packed = pack(
            &data,
            &config(Encryption::Password {
                password: b"secret",
                memory_kib: 32,
                iterations: 3,
                lanes: 4,
            }),
        )
        .unwrap();
        let unpacked = unpack(&packed, DecryptKey::Password(b"secret")).unwrap();
        assert_eq!(unpacked, data);
    }

    #[test]
    fn password_wrong_password_fails() {
        let data = b"secret data";
        let packed = pack(
            data,
            &config(Encryption::Password {
                password: b"secret",
                memory_kib: 32,
                iterations: 3,
                lanes: 4,
            }),
        )
        .unwrap();
        assert!(matches!(
            unpack(&packed, DecryptKey::Password(b"wrong")),
            Err(PipelineError::BadPassword)
        ));
    }

    #[test]
    fn blocked_parallel_roundtrip() {
        let data = b"blocked parallel roundtrip".repeat(50_000);
        let mut c = config(Encryption::None);
        c.processes = 4;
        c.block_size = 256 * 1024;
        let packed = pack(&data, &c).unwrap();
        let (header, _) = Header::decode(&packed).unwrap();
        assert!(header.blocked);
        assert_eq!(unpack(&packed, DecryptKey::None).unwrap(), data);
    }

    #[test]
    fn blocked_parallel_encrypted_roundtrip() {
        let (pk, sk) = mlkem::keygen(&mlkem::MLKEM768);
        let data = b"blocked parallel encrypted".repeat(50_000);
        let mut c = config(Encryption::Kem {
            kem: KemParams::MlKem768,
            recipient_pk: &pk,
        });
        c.processes = 3;
        c.block_size = 256 * 1024;
        let packed = pack(&data, &c).unwrap();
        let (header, _) = Header::decode(&packed).unwrap();
        assert!(header.blocked);
        assert!(header.encrypted);
        assert_eq!(unpack(&packed, DecryptKey::PrivateKey(&sk)).unwrap(), data);
    }

    #[test]
    fn archive_flag_roundtrip() {
        let data = b"archive payload".repeat(10);
        let mut c = config(Encryption::None);
        c.archive = true;
        let packed = pack(&data, &c).unwrap();
        let (header, _) = Header::decode(&packed).unwrap();
        assert!(header.archive);
        assert_eq!(unpack(&packed, DecryptKey::None).unwrap(), data);
    }

    #[test]
    fn checksum_detects_corruption() {
        let data = b"checksum test data".repeat(50);
        let mut packed = pack(&data, &config(Encryption::None)).unwrap();
        let len = packed.len();
        packed[len / 2] ^= 0x01;
        let r = unpack(&packed, DecryptKey::None);
        if let Ok(unpacked) = r {
            assert_ne!(unpacked, data);
        }
    }

    #[test]
    fn truncated_payload_errors() {
        let data = b"truncate me".repeat(100);
        let mut c = config(Encryption::None);
        c.add_checksum = false;
        let packed = pack(&data, &c).unwrap();
        let r = unpack(&packed[..packed.len() / 2], DecryptKey::None);
        assert!(r.is_err());
    }

    #[test]
    fn unpack_to_writer_matches_unpack() {
        // 明文路径（校验和启用）。
        let data = b"streaming unpack plain".repeat(5000);
        let packed = pack(&data, &config(Encryption::None)).unwrap();
        let mut out = Vec::new();
        let written = unpack_to_writer(&packed, DecryptKey::None, &mut out).unwrap();
        assert_eq!(written as usize, data.len());
        assert_eq!(out, data);

        // 公钥加密路径。
        let (pk, sk) = mlkem::keygen(&mlkem::MLKEM768);
        let data2 = b"streaming unpack kem".repeat(5000);
        let packed2 = pack(
            &data2,
            &config(Encryption::Kem {
                kem: KemParams::MlKem768,
                recipient_pk: &pk,
            }),
        )
        .unwrap();
        let mut out2 = Vec::new();
        let written2 = unpack_to_writer(&packed2, DecryptKey::PrivateKey(&sk), &mut out2).unwrap();
        assert_eq!(written2 as usize, data2.len());
        assert_eq!(out2, data2);

        // 口令加密路径。
        let data3 = b"streaming unpack password".repeat(5000);
        let packed3 = pack(
            &data3,
            &config(Encryption::Password {
                password: b"pw",
                memory_kib: 32,
                iterations: 3,
                lanes: 4,
            }),
        )
        .unwrap();
        let mut out3 = Vec::new();
        let written3 = unpack_to_writer(&packed3, DecryptKey::Password(b"pw"), &mut out3).unwrap();
        assert_eq!(written3 as usize, data3.len());
        assert_eq!(out3, data3);
    }

    #[test]
    fn pack_to_writer_roundtrip() {
        let data = b"chunked streaming pack".repeat(5000);

        // 明文（无加密，直接流式）。
        let mut plain_cfg = config(Encryption::None);
        plain_cfg.add_checksum = false;
        let mut r1 = std::io::Cursor::new(&data);
        let mut out1 = Vec::new();
        let n1 = pack_to_writer(&mut r1, &plain_cfg, Some(data.len() as u64), &mut out1).unwrap();
        assert_eq!(n1 as usize, data.len());
        let mut dec1 = Vec::new();
        unpack_to_writer(&out1, DecryptKey::None, &mut dec1).unwrap();
        assert_eq!(dec1, data);

        // ML-KEM 分块 AEAD。
        let (pk, sk) = mlkem::keygen(&mlkem::MLKEM768);
        let mut kem_cfg = config(Encryption::Kem {
            kem: KemParams::MlKem768,
            recipient_pk: &pk,
        });
        kem_cfg.add_checksum = false;
        let mut r2 = std::io::Cursor::new(&data);
        let mut out2 = Vec::new();
        let n2 = pack_to_writer(&mut r2, &kem_cfg, Some(data.len() as u64), &mut out2).unwrap();
        assert_eq!(n2 as usize, data.len());
        let mut dec2 = Vec::new();
        unpack_to_writer(&out2, DecryptKey::PrivateKey(&sk), &mut dec2).unwrap();
        assert_eq!(dec2, data);

        // 口令分块 AEAD。
        let mut pw_cfg = config(Encryption::Password {
            password: b"pw",
            memory_kib: 32,
            iterations: 3,
            lanes: 4,
        });
        pw_cfg.add_checksum = false;
        let mut r3 = std::io::Cursor::new(&data);
        let mut out3 = Vec::new();
        pack_to_writer(&mut r3, &pw_cfg, Some(data.len() as u64), &mut out3).unwrap();
        let mut dec3 = Vec::new();
        unpack_to_writer(&out3, DecryptKey::Password(b"pw"), &mut dec3).unwrap();
        assert_eq!(dec3, data);
    }

    #[test]
    fn pack_to_writer_rejects_checksum() {
        let data = b"x".repeat(10);
        let mut r = std::io::Cursor::new(&data);
        let mut out = Vec::new();
        let err = pack_to_writer(
            &mut r,
            &config(Encryption::None),
            Some(data.len() as u64),
            &mut out,
        )
        .unwrap_err();
        assert!(matches!(err, PipelineError::StreamingChecksum));
    }

    #[test]
    fn pack_to_writer_checksummed_roundtrip() {
        let data = b"streaming checksummed roundtrip".repeat(5000);
        let mut cfg = config(Encryption::None);
        cfg.add_checksum = true;
        let mut r = std::io::Cursor::new(&data);
        let mut out = std::io::Cursor::new(Vec::new());
        let n =
            pack_to_writer_checksummed(&mut r, &cfg, Some(data.len() as u64), &mut out).unwrap();
        assert_eq!(n as usize, data.len());
        let packed = out.into_inner();
        let (header, _) = Header::decode(&packed).unwrap();
        assert!(header.checksum);
        assert_eq!(unpack(&packed, DecryptKey::None).unwrap(), data);
    }

    #[test]
    fn stored_incompressible_roundtrip() {
        // 高熵数据不可压缩，应触发直存（stored）。
        let mut data = vec![0u8; 256 * 1024];
        crate::crypto::rand::fill_bytes(&mut data).unwrap();
        let packed = pack(&data, &config(Encryption::None)).unwrap();
        let (header, _) = Header::decode(&packed).unwrap();
        assert!(header.stored);
        assert!(!header.blocked);
        assert_eq!(unpack(&packed, DecryptKey::None).unwrap(), data);
    }

    #[test]
    fn stored_stream_roundtrip() {
        let mut data = vec![0u8; 256 * 1024];
        crate::crypto::rand::fill_bytes(&mut data).unwrap();
        let mut cfg = config(Encryption::None);
        cfg.add_checksum = false;
        let mut r = std::io::Cursor::new(&data);
        let mut out = Vec::new();
        let n = pack_to_writer(&mut r, &cfg, Some(data.len() as u64), &mut out).unwrap();
        assert_eq!(n as usize, data.len());
        let (header, _) = Header::decode(&out).unwrap();
        assert!(header.stored);
        assert_eq!(unpack(&out, DecryptKey::None).unwrap(), data);
    }

    #[test]
    fn stored_checksummed_roundtrip() {
        let mut data = vec![0u8; 256 * 1024];
        crate::crypto::rand::fill_bytes(&mut data).unwrap();
        let mut cfg = config(Encryption::None);
        cfg.add_checksum = true;
        let mut r = std::io::Cursor::new(&data);
        let mut out = std::io::Cursor::new(Vec::new());
        let n =
            pack_to_writer_checksummed(&mut r, &cfg, Some(data.len() as u64), &mut out).unwrap();
        assert_eq!(n as usize, data.len());
        let packed = out.into_inner();
        let (header, _) = Header::decode(&packed).unwrap();
        assert!(header.stored);
        assert!(header.checksum);
        assert_eq!(unpack(&packed, DecryptKey::None).unwrap(), data);
    }

    #[test]
    fn stored_encrypted_roundtrip() {
        let (pk, sk) = mlkem::keygen(&mlkem::MLKEM768);
        let mut data = vec![0u8; 256 * 1024];
        crate::crypto::rand::fill_bytes(&mut data).unwrap();
        let packed = pack(
            &data,
            &config(Encryption::Kem {
                kem: KemParams::MlKem768,
                recipient_pk: &pk,
            }),
        )
        .unwrap();
        let (header, _) = Header::decode(&packed).unwrap();
        assert!(header.stored);
        assert!(header.encrypted);
        assert_eq!(unpack(&packed, DecryptKey::PrivateKey(&sk)).unwrap(), data);
    }

    #[test]
    fn filter_chain_roundtrip() {
        // 可压缩数据 + Delta 过滤链：应压缩且往返一致，头部记录过滤链。
        let data: Vec<u8> = (0..64 * 1024).map(|i| (i % 64) as u8).collect();
        let mut c = config(Encryption::None);
        c.filters = FilterChain::from_filters(vec![crate::filters::Filter::delta(64).unwrap()]);
        let packed = pack(&data, &c).unwrap();
        let (header, _) = Header::decode(&packed).unwrap();
        assert!(!header.filters.is_empty());
        assert_eq!(unpack(&packed, DecryptKey::None).unwrap(), data);
    }

    #[test]
    fn filter_chain_roundtrip_blocked_and_encrypted() {
        let (pk, sk) = mlkem::keygen(&mlkem::MLKEM768);
        // 混合可压缩数据 + x86 过滤，覆盖分块并行与加密路径。
        let mut data = Vec::new();
        for i in 0..(256 * 1024) {
            if i % 37 == 0 {
                data.push(0xE8);
                data.extend_from_slice(&0x1234_5678u32.to_le_bytes());
            } else {
                data.push((i % 251) as u8);
            }
        }
        let mut c = config(Encryption::Kem {
            kem: KemParams::MlKem768,
            recipient_pk: &pk,
        });
        c.processes = 3;
        c.block_size = 64 * 1024;
        c.filters = FilterChain::from_filters(vec![crate::filters::Filter::X86]);
        let packed = pack(&data, &c).unwrap();
        let (header, _) = Header::decode(&packed).unwrap();
        assert!(!header.filters.is_empty());
        assert!(header.encrypted);
        assert_eq!(unpack(&packed, DecryptKey::PrivateKey(&sk)).unwrap(), data);

        // 流式解包也应还原。
        let mut out = Vec::new();
        unpack_to_writer_with_processes(&packed, DecryptKey::PrivateKey(&sk), &mut out, 2)
            .unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn filter_chain_streaming_pack_roundtrip() {
        // 有过滤链时流式打包回退到缓冲式打包，仍需正确往返（含校验和）。
        let data: Vec<u8> = (0..128 * 1024).map(|i| (i % 32) as u8).collect();
        let mut c = config(Encryption::None);
        c.add_checksum = true;
        c.filters = FilterChain::from_filters(vec![crate::filters::Filter::delta(32).unwrap()]);
        let mut r = std::io::Cursor::new(&data);
        let mut out = std::io::Cursor::new(Vec::new());
        let n =
            pack_to_writer_checksummed(&mut r, &c, Some(data.len() as u64), &mut out).unwrap();
        assert_eq!(n as usize, data.len());
        let packed = out.into_inner();
        let (header, _) = Header::decode(&packed).unwrap();
        assert!(!header.filters.is_empty());
        assert!(header.checksum);
        assert_eq!(unpack(&packed, DecryptKey::None).unwrap(), data);
    }
}
