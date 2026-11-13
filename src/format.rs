//! RZP2 容器格式定义。
//!
//! `.rzp2` 文件布局（v2）：
//!
//! ```text
//! +-------------------+------------------------------+
//! | 固定头部前缀       | magic(4) version(1) flags(1) |
//! |                   | level(1) reserved(1)         |
//! |                   | original_size(8, LE)         |
//! |                   | compressed_size(8, LE)       |
//! +-------------------+------------------------------+
//! | 加密字段（可选）   | 见下                         |
//! +-------------------+------------------------------+
//! | 校验字段（可选）   | checksum(32)                 |
//! +-------------------+------------------------------+
//! | 载荷               | compressed payload           |
//! +-------------------+------------------------------+
//! | 尾部（可选）       | aead_tag(16)                 |
//! +-------------------+------------------------------+
//! ```
//!
//! 加密字段按加密模式区分：
//! - ML-KEM 模式：`ek_len(2, LE) ek(..) nonce(12)`
//! - 口令（Argon2id）模式：`salt(16) memory_kib(4) iterations(4) lanes(4) nonce(12)`
//!
//! 说明：
//! - `original_size` / `compressed_size` 为 `u64::MAX` 时表示未知，由 LZMA 结束标记终止
//!   （用于流式写入场景）。
//! - `level` 为压缩级别预设（0..=9），仅作记录，解码不依赖它。
//! - `ARCHIVE` 标志置位时，载荷为归档流（见 [`crate::archive`]），否则为单文件。

use std::fmt;

/// 文件魔数 `RZP2`。
pub const MAGIC: [u8; 4] = *b"RZP2";

/// 当前写入的容器格式版本号。
pub const VERSION: u8 = 3;

/// 可读取的最低容器格式版本号（保留 v1 / v2 读取兼容）。
pub const VERSION_MIN: u8 = 1;

/// 固定头部前缀字节数：
/// magic(4) + version(1) + flags(1) + level(1) + reserved(1) + original_size(8) + compressed_size(8)。
pub const HEADER_PREFIX_SIZE: usize = 24;

/// ChaCha20-Poly1305 nonce 长度（RFC 8439）。
pub const NONCE_SIZE: usize = 12;

/// AEAD 认证标签长度。
pub const TAG_SIZE: usize = 16;

/// 封装的 DEK（数据加密密钥）长度：32 字节密钥密文 + 16 字节认证标签。
pub const DEK_WRAP_SIZE: usize = 48;

/// 校验和（SHAKE-256）长度。
pub const CHECKSUM_SIZE: usize = 32;

/// 口令加密盐长度（Argon2id）。
pub const SALT_SIZE: usize = 16;

/// 头部标志位。
pub mod flag {
    /// 载荷已加密。
    pub const ENCRYPTED: u8 = 0b0000_0001;
    /// ML-KEM 参数集字段掩码（bits 1..2）。
    pub const KEM_MASK: u8 = 0b0000_0110;
    /// ML-KEM 参数集字段位移。
    pub const KEM_SHIFT: u8 = 1;
    /// 存在未压缩明文校验和。
    pub const CHECKSUM: u8 = 0b0000_1000;
    /// 口令（Argon2id）加密模式。
    pub const PASSWORD: u8 = 0b0001_0000;
    /// 载荷为归档流（多条目）。
    pub const ARCHIVE: u8 = 0b0010_0000;
    /// 载荷采用分块 AEAD 封装（仅 v3+，且仅在加密时有效）。
    pub const CHUNKED: u8 = 0b0100_0000;

    /// flags2（复用 v3+ 头部第 7 字节，原 reserved）扩展位。
    pub mod ext {
        /// 多接收者（每接收者独立封装随机 DEK）。
        pub const MULTI: u8 = 0b0000_0001;
        /// 载荷为分块 LZMA 帧序列（并行压缩，由长度前缀帧组成）。
        pub const BLOCKED: u8 = 0b0000_0010;
    }
}

/// ML-KEM 参数集。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemParams {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl KemParams {
    /// 默认参数集。
    pub const DEFAULT: Self = Self::MlKem768;

    /// 编码为 flags 位域中的 2 位。
    pub fn to_bits(self) -> u8 {
        match self {
            Self::MlKem512 => 0,
            Self::MlKem768 => 1,
            Self::MlKem1024 => 2,
        }
    }

    /// 从 flags 位域中的 2 位解码。
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0 => Some(Self::MlKem512),
            1 => Some(Self::MlKem768),
            2 => Some(Self::MlKem1024),
            _ => None,
        }
    }

    /// 参数集显示名。
    pub fn name(self) -> &'static str {
        match self {
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
        }
    }

    /// 从（忽略大小写与连字符的）名称解析参数集。
    pub fn from_name(s: &str) -> Option<Self> {
        let normalized: String = s
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_lowercase())
            .collect();
        match normalized.as_str() {
            "mlkem512" | "kem512" => Some(Self::MlKem512),
            "mlkem768" | "kem768" => Some(Self::MlKem768),
            "mlkem1024" | "kem1024" => Some(Self::MlKem1024),
            _ => None,
        }
    }

    /// 全部参数集。
    pub fn all() -> [Self; 3] {
        [Self::MlKem512, Self::MlKem768, Self::MlKem1024]
    }
}

impl fmt::Display for KemParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// 多接收者加密时，单个接收者的封装信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    /// 该接收者使用的 ML-KEM 参数集。
    pub kem: KemParams,
    /// 该接收者的 ML-KEM 封装密文。
    pub ek: Vec<u8>,
    /// 用该接收者共享密钥包裹的 DEK（32 字节密文 + 16 字节标签）。
    pub wrapped_dek: [u8; DEK_WRAP_SIZE],
}

/// RZP2 文件头部（已解析）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// 未压缩明文长度（`u64::MAX` 表示未知）。
    pub original_size: u64,
    /// 压缩后（若加密则为加密前）载荷长度（`u64::MAX` 表示未知）。
    pub compressed_size: u64,
    /// 是否加密。
    pub encrypted: bool,
    /// 是否使用口令（Argon2id）加密；仅在 `encrypted` 为真时有意义。
    pub password: bool,
    /// 载荷是否为归档流。
    pub archive: bool,
    /// 载荷是否采用分块 AEAD 封装（仅加密时有意义）。
    pub chunked: bool,
    /// 是否为多接收者加密（每接收者独立封装 DEK）。
    pub multi: bool,
    /// 载荷是否为分块 LZMA 帧序列。
    pub blocked: bool,
    /// 是否带校验和。
    pub checksum: bool,
    /// 压缩级别预设（0..=9）。
    pub level: u8,
    /// ML-KEM 参数集（仅 ML-KEM 加密模式有意义）。
    pub kem: KemParams,
    /// ML-KEM 封装密文（非 ML-KEM 模式为空；多接收者模式为空）。
    pub ek: Vec<u8>,
    /// 多接收者列表（仅 `multi` 为真时有意义）。
    pub recipients: Vec<Recipient>,
    /// 口令加密盐（仅口令模式有意义）。
    pub salt: [u8; SALT_SIZE],
    /// Argon2id 内存开销（KiB，仅口令模式有意义）。
    pub memory_kib: u32,
    /// Argon2id 迭代次数（仅口令模式有意义）。
    pub iterations: u32,
    /// Argon2id 并行度（仅口令模式有意义）。
    pub lanes: u32,
    /// AEAD nonce（未加密时全零）。
    pub nonce: [u8; NONCE_SIZE],
    /// 明文校验和（未启用时全零）。
    pub checksum_digest: [u8; CHECKSUM_SIZE],
}

impl Header {
    /// 构造一个未加密、不带校验和的头部。
    pub fn plain(original_size: u64, compressed_size: u64) -> Self {
        Self {
            original_size,
            compressed_size,
            encrypted: false,
            password: false,
            archive: false,
            chunked: false,
            multi: false,
            blocked: false,
            checksum: false,
            level: 0,
            kem: KemParams::DEFAULT,
            ek: Vec::new(),
            recipients: Vec::new(),
            salt: [0u8; SALT_SIZE],
            memory_kib: 0,
            iterations: 0,
            lanes: 0,
            nonce: [0u8; NONCE_SIZE],
            checksum_digest: [0u8; CHECKSUM_SIZE],
        }
    }

    /// 根据字段计算 flags 字节。
    pub fn flags(&self) -> u8 {
        let mut f = 0u8;
        if self.encrypted {
            f |= flag::ENCRYPTED;
        }
        if self.password {
            f |= flag::PASSWORD;
        }
        if self.archive {
            f |= flag::ARCHIVE;
        }
        if self.chunked {
            f |= flag::CHUNKED;
        }
        if self.checksum {
            f |= flag::CHECKSUM;
        }
        f |= self.kem.to_bits() << flag::KEM_SHIFT;
        f
    }

    /// 根据字段计算 flags2 字节（复用头部第 7 字节，原 reserved）。
    pub fn flags2(&self) -> u8 {
        let mut f = 0u8;
        if self.multi {
            f |= flag::ext::MULTI;
        }
        if self.blocked {
            f |= flag::ext::BLOCKED;
        }
        f
    }

    /// 序列化为字节串（不含载荷与尾部标签）。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            HEADER_PREFIX_SIZE + self.ek.len() + NONCE_SIZE + CHECKSUM_SIZE + SALT_SIZE + 12,
        );
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(self.flags());
        out.push(self.level);
        out.push(self.flags2()); // reserved 字节复用为 flags2
        out.extend_from_slice(&self.original_size.to_le_bytes());
        out.extend_from_slice(&self.compressed_size.to_le_bytes());

        if self.encrypted {
            if self.password {
                out.extend_from_slice(&self.salt);
                out.extend_from_slice(&self.memory_kib.to_le_bytes());
                out.extend_from_slice(&self.iterations.to_le_bytes());
                out.extend_from_slice(&self.lanes.to_le_bytes());
                out.extend_from_slice(&self.nonce);
            } else if self.multi {
                out.push(self.recipients.len() as u8);
                for r in &self.recipients {
                    out.push(r.kem.to_bits());
                    out.extend_from_slice(&(r.ek.len() as u16).to_le_bytes());
                    out.extend_from_slice(&r.ek);
                    out.extend_from_slice(&r.wrapped_dek);
                }
                out.extend_from_slice(&self.nonce);
            } else {
                let ek_len = self.ek.len() as u16;
                out.extend_from_slice(&ek_len.to_le_bytes());
                out.extend_from_slice(&self.ek);
                out.extend_from_slice(&self.nonce);
            }
        }
        if self.checksum {
            out.extend_from_slice(&self.checksum_digest);
        }
        out
    }

    /// 从字节串反序列化头部，返回 `(header, 消费的字节数)`。
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), FormatError> {
        if buf.len() < HEADER_PREFIX_SIZE {
            return Err(FormatError::Truncated);
        }
        if buf[0..4] != MAGIC {
            return Err(FormatError::BadMagic);
        }
        let version = buf[4];
        if !(VERSION_MIN..=VERSION).contains(&version) {
            return Err(FormatError::UnsupportedVersion(version));
        }
        let flags = buf[5];
        let level = if version >= 2 { buf[6] } else { 0 };
        // flags2 复用 v3+ 头部第 7 字节（原 reserved）；较低版本无此定义。
        let flags2 = if version >= 3 { buf[7] } else { 0 };
        let original_size = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let compressed_size = u64::from_le_bytes(buf[16..24].try_into().unwrap());

        let encrypted = flags & flag::ENCRYPTED != 0;
        let password = flags & flag::PASSWORD != 0;
        let archive = flags & flag::ARCHIVE != 0;
        let chunked = flags & flag::CHUNKED != 0;
        let checksum = flags & flag::CHECKSUM != 0;
        let multi = flags2 & flag::ext::MULTI != 0;
        let blocked = flags2 & flag::ext::BLOCKED != 0;
        let mut kem = KemParams::from_bits((flags & flag::KEM_MASK) >> flag::KEM_SHIFT)
            .ok_or(FormatError::BadKemParams)?;

        // v1 未定义这些标志位，出现即视为非法。
        if version == 1 && (password || archive || chunked) {
            return Err(FormatError::BadFlags);
        }
        // 分块 AEAD 仅在 v3+ 且加密时才有意义。
        if chunked && (!encrypted || version < 3) {
            return Err(FormatError::BadFlags);
        }
        // 多接收者仅在 v3+ 的 ML-KEM 加密模式下有意义。
        if multi && (!encrypted || password || version < 3) {
            return Err(FormatError::BadFlags);
        }
        // 分块帧载荷仅在 v3+ 有意义。
        if blocked && version < 3 {
            return Err(FormatError::BadFlags);
        }

        let mut offset = HEADER_PREFIX_SIZE;
        let mut ek = Vec::new();
        let mut recipients = Vec::new();
        let mut salt = [0u8; SALT_SIZE];
        let mut memory_kib = 0u32;
        let mut iterations = 0u32;
        let mut lanes = 0u32;
        let mut nonce = [0u8; NONCE_SIZE];

        if encrypted {
            if password {
                if buf.len() < offset + SALT_SIZE + 12 + NONCE_SIZE {
                    return Err(FormatError::Truncated);
                }
                salt.copy_from_slice(&buf[offset..offset + SALT_SIZE]);
                offset += SALT_SIZE;
                memory_kib = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
                offset += 4;
                iterations = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
                offset += 4;
                lanes = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
                offset += 4;
                nonce.copy_from_slice(&buf[offset..offset + NONCE_SIZE]);
                offset += NONCE_SIZE;
            } else if multi {
                if buf.len() < offset + 1 {
                    return Err(FormatError::Truncated);
                }
                let count = buf[offset] as usize;
                offset += 1;
                if count == 0 {
                    return Err(FormatError::BadFlags);
                }
                recipients.reserve(count);
                for _ in 0..count {
                    if buf.len() < offset + 1 + 2 {
                        return Err(FormatError::Truncated);
                    }
                    let rkem =
                        KemParams::from_bits(buf[offset]).ok_or(FormatError::BadKemParams)?;
                    offset += 1;
                    let ek_len =
                        u16::from_le_bytes(buf[offset..offset + 2].try_into().unwrap()) as usize;
                    offset += 2;
                    if buf.len() < offset + ek_len + DEK_WRAP_SIZE {
                        return Err(FormatError::Truncated);
                    }
                    let mut wrapped_dek = [0u8; DEK_WRAP_SIZE];
                    let rek = buf[offset..offset + ek_len].to_vec();
                    offset += ek_len;
                    wrapped_dek.copy_from_slice(&buf[offset..offset + DEK_WRAP_SIZE]);
                    offset += DEK_WRAP_SIZE;
                    recipients.push(Recipient {
                        kem: rkem,
                        ek: rek,
                        wrapped_dek,
                    });
                }
                if buf.len() < offset + NONCE_SIZE {
                    return Err(FormatError::Truncated);
                }
                nonce.copy_from_slice(&buf[offset..offset + NONCE_SIZE]);
                offset += NONCE_SIZE;
            } else {
                if buf.len() < offset + 2 {
                    return Err(FormatError::Truncated);
                }
                let ek_len =
                    u16::from_le_bytes(buf[offset..offset + 2].try_into().unwrap()) as usize;
                offset += 2;
                if buf.len() < offset + ek_len + NONCE_SIZE {
                    return Err(FormatError::Truncated);
                }
                ek.extend_from_slice(&buf[offset..offset + ek_len]);
                offset += ek_len;
                nonce.copy_from_slice(&buf[offset..offset + NONCE_SIZE]);
                offset += NONCE_SIZE;
            }
        }

        let mut checksum_digest = [0u8; CHECKSUM_SIZE];
        if checksum {
            if buf.len() < offset + CHECKSUM_SIZE {
                return Err(FormatError::Truncated);
            }
            checksum_digest.copy_from_slice(&buf[offset..offset + CHECKSUM_SIZE]);
            offset += CHECKSUM_SIZE;
        }

        if multi {
            // 多接收者模式下 `kem` 取首个接收者的参数集，便于统一展示。
            if let Some(first) = recipients.first() {
                kem = first.kem;
            }
        }

        Ok((
            Self {
                original_size,
                compressed_size,
                encrypted,
                password,
                archive,
                chunked,
                multi,
                blocked,
                checksum,
                level,
                kem,
                ek,
                recipients,
                salt,
                memory_kib,
                iterations,
                lanes,
                nonce,
                checksum_digest,
            },
            offset,
        ))
    }
}

/// 容器格式错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    Truncated,
    BadMagic,
    UnsupportedVersion(u8),
    BadKemParams,
    BadFlags,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated RZP2 header"),
            Self::BadMagic => write!(f, "bad RZP2 magic (not an RZP2 file?)"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported RZP2 version {v}"),
            Self::BadKemParams => write!(f, "invalid ML-KEM parameter set in header"),
            Self::BadFlags => write!(f, "invalid flag combination in header"),
        }
    }
}

impl std::error::Error for FormatError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip_plain() {
        let mut h = Header::plain(1234, 567);
        h.level = 5;
        let enc = h.encode();
        let (dec, n) = Header::decode(&enc).unwrap();
        assert_eq!(n, enc.len());
        assert_eq!(h, dec);
        assert_eq!(dec.original_size, 1234);
        assert_eq!(dec.compressed_size, 567);
        assert!(!dec.encrypted);
        assert_eq!(dec.level, 5);
    }

    #[test]
    fn header_roundtrip_mlkem() {
        let mut h = Header::plain(100, 200);
        h.encrypted = true;
        h.kem = KemParams::MlKem1024;
        h.ek = vec![1, 2, 3, 4, 5];
        h.nonce = [7u8; NONCE_SIZE];
        let enc = h.encode();
        let (dec, n) = Header::decode(&enc).unwrap();
        assert_eq!(n, enc.len());
        assert_eq!(h, dec);
        assert_eq!(dec.kem, KemParams::MlKem1024);
    }

    #[test]
    fn header_roundtrip_password() {
        let mut h = Header::plain(100, 200);
        h.encrypted = true;
        h.password = true;
        h.salt = [0xabu8; SALT_SIZE];
        h.memory_kib = 65536;
        h.iterations = 3;
        h.lanes = 4;
        h.nonce = [9u8; NONCE_SIZE];
        let enc = h.encode();
        let (dec, n) = Header::decode(&enc).unwrap();
        assert_eq!(n, enc.len());
        assert_eq!(h, dec);
    }

    #[test]
    fn header_roundtrip_archive() {
        let mut h = Header::plain(100, 200);
        h.archive = true;
        let enc = h.encode();
        let (dec, _) = Header::decode(&enc).unwrap();
        assert!(dec.archive);
    }

    #[test]
    fn header_roundtrip_chunked() {
        let mut h = Header::plain(u64::MAX, u64::MAX);
        h.encrypted = true;
        h.chunked = true;
        h.nonce = [3u8; NONCE_SIZE];
        let enc = h.encode();
        let (dec, _) = Header::decode(&enc).unwrap();
        assert!(dec.encrypted);
        assert!(dec.chunked);
        assert_eq!(dec.original_size, u64::MAX);
    }

    #[test]
    fn chunked_requires_encryption() {
        let mut h = Header::plain(100, 200);
        h.chunked = true; // 未加密却标记分块，非法。
        let enc = h.encode();
        assert_eq!(Header::decode(&enc).unwrap_err(), FormatError::BadFlags);
    }

    #[test]
    fn header_roundtrip_multi_recipient() {
        let mut h = Header::plain(100, 200);
        h.encrypted = true;
        h.multi = true;
        h.kem = KemParams::MlKem768;
        h.nonce = [5u8; NONCE_SIZE];
        h.recipients = vec![
            Recipient {
                kem: KemParams::MlKem512,
                ek: vec![1, 2, 3],
                wrapped_dek: [1u8; DEK_WRAP_SIZE],
            },
            Recipient {
                kem: KemParams::MlKem1024,
                ek: vec![4, 5, 6, 7],
                wrapped_dek: [2u8; DEK_WRAP_SIZE],
            },
        ];
        let enc = h.encode();
        let (dec, n) = Header::decode(&enc).unwrap();
        assert_eq!(n, enc.len());
        assert!(dec.multi);
        assert_eq!(dec.recipients.len(), 2);
        assert_eq!(dec.kem, KemParams::MlKem512);
        assert_eq!(dec.recipients[1].ek, vec![4, 5, 6, 7]);
        assert_eq!(dec.recipients[1].wrapped_dek, [2u8; DEK_WRAP_SIZE]);
        assert_eq!(dec.nonce, [5u8; NONCE_SIZE]);
    }

    #[test]
    fn multi_requires_mlkem() {
        let mut h = Header::plain(100, 200);
        h.multi = true; // 未加密却标记多接收者，非法。
        let enc = h.encode();
        assert_eq!(Header::decode(&enc).unwrap_err(), FormatError::BadFlags);
    }

    #[test]
    fn blocked_flag_roundtrip() {
        let mut h = Header::plain(100, 200);
        h.blocked = true;
        let enc = h.encode();
        let (dec, _) = Header::decode(&enc).unwrap();
        assert!(dec.blocked);
    }

    #[test]
    fn v1_header_still_readable() {
        // 手工构造 v1 头部（version=1，无 level 字节，reserved 两字节为 0）。
        let mut buf = vec![0u8; HEADER_PREFIX_SIZE];
        buf[0..4].copy_from_slice(&MAGIC);
        buf[4] = 1; // version
        buf[5] = 0; // flags
                    // buf[6..8] = 0（v1 的 reserved(2)）
        buf[8..16].copy_from_slice(&1234u64.to_le_bytes());
        buf[16..24].copy_from_slice(&567u64.to_le_bytes());
        let (h, n) = Header::decode(&buf).unwrap();
        assert_eq!(n, HEADER_PREFIX_SIZE);
        assert_eq!(h.original_size, 1234);
        assert_eq!(h.compressed_size, 567);
        assert_eq!(h.level, 0);
    }

    #[test]
    fn bad_magic_rejected() {
        let mut buf = vec![0u8; HEADER_PREFIX_SIZE];
        buf[0..4].copy_from_slice(b"XXXX");
        assert_eq!(Header::decode(&buf).unwrap_err(), FormatError::BadMagic);
    }

    #[test]
    fn kem_param_name_roundtrip() {
        for p in KemParams::all() {
            assert_eq!(KemParams::from_name(p.name()), Some(p));
        }
        assert_eq!(
            KemParams::from_name("ml-kem-512"),
            Some(KemParams::MlKem512)
        );
        assert_eq!(KemParams::from_name("kem1024"), Some(KemParams::MlKem1024));
        assert_eq!(KemParams::from_name("bogus"), None);
    }
}
