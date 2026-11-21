//! 密钥文件（PEM 风格）序列化约定。
//!
//! 密钥文件为文本格式：
//!
//! ```text
//! -----BEGIN RZP2 PUBLIC KEY-----
//! <base64(payload)>
//! -----END RZP2 PUBLIC KEY-----
//! ```
//!
//! `payload = params_byte(1) || raw_key_bytes`，其中 `params_byte`
//! 为 [`KemParams::to_key_byte`](crate::format::KemParams::to_key_byte) 的值，
//! `raw_key_bytes` 为 ML-KEM（混合时附 X25519）公钥/私钥的原始字节。

use crate::crypto::zeroize::Zeroize;
use crate::format::KemParams;

/// 公钥 PEM 头。
pub const PUBLIC_HEADER: &str = "-----BEGIN RZP2 PUBLIC KEY-----";
/// 公钥 PEM 尾。
pub const PUBLIC_FOOTER: &str = "-----END RZP2 PUBLIC KEY-----";
/// 私钥 PEM 头。
pub const PRIVATE_HEADER: &str = "-----BEGIN RZP2 PRIVATE KEY-----";
/// 私钥 PEM 尾。
pub const PRIVATE_FOOTER: &str = "-----END RZP2 PRIVATE KEY-----";
/// 口令加密私钥 PEM 头。
pub const ENCRYPTED_PRIVATE_HEADER: &str = "-----BEGIN RZP2 ENCRYPTED PRIVATE KEY-----";
/// 口令加密私钥 PEM 尾。
pub const ENCRYPTED_PRIVATE_FOOTER: &str = "-----END RZP2 ENCRYPTED PRIVATE KEY-----";

/// 私钥口令加密使用的 Argon2id 默认开销（与容器口令加密一致）。
pub const KEY_ENCRYPT_MEMORY_KIB: u32 = 64 * 1024;
pub const KEY_ENCRYPT_ITERATIONS: u32 = 3;
pub const KEY_ENCRYPT_LANES: u32 = 4;
/// Argon2id 类型标识（RFC 9106）。
const ARGON2ID_TYPE: u32 = 2;
/// 私钥加密 payload 的版本号。
const ENCRYPTED_KEY_VERSION: u8 = 1;

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// 密钥类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Public,
    Private,
}

impl KeyKind {
    fn header(self) -> &'static str {
        match self {
            Self::Public => PUBLIC_HEADER,
            Self::Private => PRIVATE_HEADER,
        }
    }
    fn footer(self) -> &'static str {
        match self {
            Self::Public => PUBLIC_FOOTER,
            Self::Private => PRIVATE_FOOTER,
        }
    }
}

/// 密钥序列化错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    BadPem,
    BadBase64,
    BadParams,
    /// 加密私钥 payload 格式错误。
    BadEncrypted,
    /// 加密私钥缺失口令或口令错误。
    BadPassword,
    /// 随机源失败。
    Io,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadPem => write!(f, "malformed key file (PEM framing)"),
            Self::BadBase64 => write!(f, "malformed base64 in key file"),
            Self::BadParams => write!(f, "invalid ML-KEM parameter set in key file"),
            Self::BadEncrypted => write!(f, "malformed encrypted private key"),
            Self::BadPassword => write!(f, "missing or incorrect private key password"),
            Self::Io => write!(f, "OS random source unavailable"),
        }
    }
}

impl std::error::Error for KeyError {}

/// 序列化密钥为 PEM 文本。
pub fn encode_key(kind: KeyKind, params: KemParams, raw: &[u8]) -> String {
    let mut payload = Vec::with_capacity(1 + raw.len());
    payload.push(params.to_key_byte());
    payload.extend_from_slice(raw);
    let b64 = base64_encode(&payload);
    format!("{}\n{}\n{}\n", kind.header(), wrap(&b64, 64), kind.footer())
}

/// 从 PEM 文本解析密钥，返回 `(params, raw_bytes)`。
pub fn decode_key(kind: KeyKind, pem: &str) -> Result<(KemParams, Vec<u8>), KeyError> {
    let mut lines = pem.lines().map(str::trim).filter(|l| !l.is_empty());
    let header = lines.next().ok_or(KeyError::BadPem)?;
    if header != kind.header() {
        return Err(KeyError::BadPem);
    }
    let mut b64 = String::new();
    let mut footer_found = false;
    for line in lines {
        if line == kind.footer() {
            footer_found = true;
            break;
        }
        b64.push_str(line);
    }
    if !footer_found {
        return Err(KeyError::BadPem);
    }
    let payload = base64_decode(&b64).map_err(|_| KeyError::BadBase64)?;
    if payload.is_empty() {
        return Err(KeyError::BadParams);
    }
    let params = KemParams::from_key_byte(payload[0]).ok_or(KeyError::BadParams)?;
    let raw = payload[1..].to_vec();
    Ok((params, raw))
}

/// 提取 PEM 中 base64 解码后的 payload。
fn extract_payload(pem: &str, header: &str, footer: &str) -> Result<Vec<u8>, KeyError> {
    let mut lines = pem.lines().map(str::trim).filter(|l| !l.is_empty());
    if lines.next() != Some(header) {
        return Err(KeyError::BadPem);
    }
    let mut b64 = String::new();
    let mut footer_found = false;
    for line in lines {
        if line == footer {
            footer_found = true;
            break;
        }
        b64.push_str(line);
    }
    if !footer_found {
        return Err(KeyError::BadPem);
    }
    base64_decode(&b64).map_err(|_| KeyError::BadBase64)
}

/// 用 Argon2id 从口令派生私钥加密密钥。
fn derive_key(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
) -> [u8; 32] {
    let out = crate::crypto::argon2::argon2(
        password,
        salt,
        lanes,
        32,
        memory_kib,
        iterations,
        ARGON2ID_TYPE,
        &[],
        &[],
    );
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    key
}

/// 用口令加密私钥，返回加密私钥 PEM 文本。
///
/// payload 布局（全部小端）：
///
/// ```text
/// version(1) params_byte(1) salt(16) memory_kib(4) iterations(4) lanes(4)
/// nonce(12) ciphertext(..) tag(16)
/// ```
///
/// 前 42 字节作为 AEAD 的 AAD，防止参数与密文被篡改。
pub fn encode_encrypted_private_key(
    params: KemParams,
    raw: &[u8],
    password: &[u8],
) -> Result<String, KeyError> {
    let mut salt = [0u8; 16];
    crate::crypto::rand::fill_bytes(&mut salt).map_err(|_| KeyError::Io)?;
    let mut nonce = [0u8; 12];
    crate::crypto::rand::fill_bytes(&mut nonce).map_err(|_| KeyError::Io)?;

    let mut aad = Vec::with_capacity(42);
    aad.push(ENCRYPTED_KEY_VERSION);
    aad.push(params.to_key_byte());
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&KEY_ENCRYPT_MEMORY_KIB.to_le_bytes());
    aad.extend_from_slice(&KEY_ENCRYPT_ITERATIONS.to_le_bytes());
    aad.extend_from_slice(&KEY_ENCRYPT_LANES.to_le_bytes());
    aad.extend_from_slice(&nonce);

    let mut key = derive_key(
        password,
        &salt,
        KEY_ENCRYPT_MEMORY_KIB,
        KEY_ENCRYPT_ITERATIONS,
        KEY_ENCRYPT_LANES,
    );
    let (ct, tag) = crate::aead::aead_encrypt(&key, &nonce, raw, &aad);
    key.zeroize();

    let mut payload = aad;
    payload.extend_from_slice(&ct);
    payload.extend_from_slice(&tag);

    let b64 = base64_encode(&payload);
    Ok(format!(
        "{}\n{}\n{}\n",
        ENCRYPTED_PRIVATE_HEADER,
        wrap(&b64, 64),
        ENCRYPTED_PRIVATE_FOOTER
    ))
}

/// 解析私钥 PEM（自动识别明文 / 口令加密），返回 `(params, raw_bytes)`。
///
/// 加密私钥需提供 `password`；明文私钥忽略该参数。
pub fn decode_private_key(
    pem: &str,
    password: Option<&[u8]>,
) -> Result<(KemParams, Vec<u8>), KeyError> {
    let first = pem
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .ok_or(KeyError::BadPem)?;
    if first == PRIVATE_HEADER {
        return decode_key(KeyKind::Private, pem);
    }
    if first != ENCRYPTED_PRIVATE_HEADER {
        return Err(KeyError::BadPem);
    }

    let password = password.ok_or(KeyError::BadPassword)?;
    let payload = extract_payload(pem, ENCRYPTED_PRIVATE_HEADER, ENCRYPTED_PRIVATE_FOOTER)?;

    // version(1) + params(1) + salt(16) + mem/iter/lanes(12) + nonce(12) + tag(16) = 58。
    if payload.len() < 58 || payload[0] != ENCRYPTED_KEY_VERSION {
        return Err(KeyError::BadEncrypted);
    }
    let params = KemParams::from_key_byte(payload[1]).ok_or(KeyError::BadParams)?;
    let salt: [u8; 16] = payload[2..18].try_into().unwrap();
    let memory_kib = u32::from_le_bytes(payload[18..22].try_into().unwrap());
    let iterations = u32::from_le_bytes(payload[22..26].try_into().unwrap());
    let lanes = u32::from_le_bytes(payload[26..30].try_into().unwrap());
    let nonce: [u8; 12] = payload[30..42].try_into().unwrap();
    let aad = &payload[..42];

    let ct_len = payload.len() - 42 - 16;
    let ct = &payload[42..42 + ct_len];
    let tag: [u8; 16] = payload[42 + ct_len..].try_into().unwrap();

    let mut key = derive_key(password, &salt, memory_kib, iterations, lanes);
    let raw = crate::aead::aead_decrypt(&key, &nonce, ct, aad, &tag)
        .map_err(|_| KeyError::BadPassword)?;
    key.zeroize();
    Ok((params, raw))
}

/// 标准 Base64 编码。
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// 标准 Base64 解码（容忍空白与 `=` 填充）。
#[allow(clippy::result_unit_err)]
pub fn base64_decode(s: &str) -> Result<Vec<u8>, ()> {
    let mut val = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for c in s.chars() {
        if c.is_whitespace() || c == '=' {
            continue;
        }
        let d = (B64_ALPHABET.iter().position(|&x| x == c as u8)).ok_or(())?;
        val = (val << 6) | d as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((val >> bits) & 0xff) as u8);
        }
    }
    if bits >= 6 {
        return Err(());
    }
    Ok(out)
}

fn wrap(s: &str, width: usize) -> String {
    s.as_bytes()
        .chunks(width)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        for data in [
            vec![],
            b"f".to_vec(),
            b"fo".to_vec(),
            b"foo".to_vec(),
            b"foob".to_vec(),
            b"fooba".to_vec(),
            b"foobar".to_vec(),
            (0..=255).collect::<Vec<_>>(),
        ] {
            let enc = base64_encode(&data);
            assert_eq!(base64_decode(&enc).unwrap(), data);
        }
    }

    #[test]
    fn key_pem_roundtrip() {
        let raw: Vec<u8> = (0..=255).collect();
        for kind in [KeyKind::Public, KeyKind::Private] {
            let pem = encode_key(kind, KemParams::MlKem768, &raw);
            let (params, decoded) = decode_key(kind, &pem).unwrap();
            assert_eq!(params, KemParams::MlKem768);
            assert_eq!(decoded, raw);
        }
    }

    #[test]
    fn wrong_kind_rejected() {
        let pem = encode_key(KeyKind::Public, KemParams::MlKem512, &[1, 2, 3]);
        assert_eq!(
            decode_key(KeyKind::Private, &pem).unwrap_err(),
            KeyError::BadPem
        );
    }

    #[test]
    fn encrypted_private_key_roundtrip() {
        let raw: Vec<u8> = (0..=255).collect();
        let pem = encode_encrypted_private_key(KemParams::MlKem1024, &raw, b"s3cret").unwrap();
        // 头应为加密私钥头。
        assert!(pem.starts_with(ENCRYPTED_PRIVATE_HEADER));
        let (params, decoded) = decode_private_key(&pem, Some(b"s3cret")).unwrap();
        assert_eq!(params, KemParams::MlKem1024);
        assert_eq!(decoded, raw);
    }

    #[test]
    fn encrypted_private_key_rejects_wrong_password() {
        let pem =
            encode_encrypted_private_key(KemParams::MlKem768, b"key-material", b"right").unwrap();
        assert_eq!(
            decode_private_key(&pem, Some(b"wrong")).unwrap_err(),
            KeyError::BadPassword
        );
        assert_eq!(
            decode_private_key(&pem, None).unwrap_err(),
            KeyError::BadPassword
        );
    }

    #[test]
    fn decode_private_key_plain() {
        let pem = encode_key(KeyKind::Private, KemParams::MlKem512, &[9, 8, 7]);
        let (params, raw) = decode_private_key(&pem, None).unwrap();
        assert_eq!(params, KemParams::MlKem512);
        assert_eq!(raw, vec![9, 8, 7]);
    }
}
