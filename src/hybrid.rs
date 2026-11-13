//! 混合加密：ML-KEM 密钥封装 + SHAKE-256 KDF + ChaCha20-Poly1305 AEAD。

use crate::aead::{self, KEY_SIZE, NONCE_SIZE, TAG_SIZE};
use crate::crypto::zeroize::Zeroize;
use crate::format::DEK_WRAP_SIZE;
use crate::mlkem::fips202::Keccak;
use crate::mlkem::{self, Params};

/// Argon2id 类型标识（RFC 9106）。
const ARGON2ID_TYPE: u32 = 2;

/// 默认 Argon2id 内存开销（KiB）：64 MiB。
pub const DEFAULT_MEMORY_KIB: u32 = 64 * 1024;
/// 默认 Argon2id 迭代次数。
pub const DEFAULT_ITERATIONS: u32 = 3;
/// 默认 Argon2id 并行度。
pub const DEFAULT_LANES: u32 = 4;

/// 混合加密错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HybridError {
    /// AEAD 认证失败（密钥或密文被篡改）。
    AuthenticationFailed,
    /// nonce 不一致。
    NonceMismatch,
}

impl std::fmt::Display for HybridError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthenticationFailed => write!(f, "hybrid AEAD authentication failed"),
            Self::NonceMismatch => write!(f, "hybrid nonce mismatch"),
        }
    }
}

impl std::error::Error for HybridError {}

/// 混合加密的封装结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridCiphertext {
    /// ML-KEM 封装密文（共享密钥封装）。
    pub kem_ct: Vec<u8>,
    /// AEAD nonce。
    pub nonce: [u8; NONCE_SIZE],
    /// AEAD 密文（压缩数据）。
    pub ct: Vec<u8>,
    /// AEAD 认证标签。
    pub tag: [u8; TAG_SIZE],
}

/// 从 ML-KEM 共享密钥派生 AEAD 密钥与 nonce。
///
/// 绑定上下文（label）与参数集名称，实现密钥/随机数分离派生。
pub fn kdf(params: &Params, ss: &[u8; 32], label: &[u8]) -> ([u8; KEY_SIZE], [u8; NONCE_SIZE]) {
    let mut out = [0u8; KEY_SIZE + NONCE_SIZE];
    let mut xof = Keccak::new(136);
    xof.absorb(ss);
    xof.absorb(label);
    xof.absorb(params.name().as_bytes());
    xof.finalize(0x1F);
    xof.squeeze(&mut out);
    (
        out[..KEY_SIZE].try_into().unwrap(),
        out[KEY_SIZE..].try_into().unwrap(),
    )
}

/// 从口令派生 AEAD 密钥（Argon2id，RFC 9106）。
///
/// 输出 32 字节密钥。`salt` 应为随机生成的 16 字节盐；`memory_kib` / `iterations`
/// / `lanes` 为 Argon2id 的开销参数，加密时记录在容器头部以便解密复现。
pub fn derive_password_key(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
) -> [u8; KEY_SIZE] {
    let out = crate::crypto::argon2::argon2(
        password,
        salt,
        lanes,
        KEY_SIZE as u32,
        memory_kib,
        iterations,
        ARGON2ID_TYPE,
        &[],
        &[],
    );
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&out[..KEY_SIZE]);
    key
}

/// 混合加密。
pub fn encrypt(params: &Params, recipient_pk: &[u8], plaintext: &[u8]) -> HybridCiphertext {
    let (kem_ct, key, nonce) = encapsulate(params, recipient_pk);

    // AAD 绑定 KEM 密文，防止封装密文被篡改。
    let (ct, tag) = aead::aead_encrypt(&key, &nonce, plaintext, &kem_ct);

    HybridCiphertext {
        kem_ct,
        nonce,
        ct,
        tag,
    }
}

/// 仅执行 ML-KEM 封装与 KDF，返回 `(kem_ct, key, nonce)`，供分块 AEAD 等流式路径复用。
pub fn encapsulate(
    params: &Params,
    recipient_pk: &[u8],
) -> (Vec<u8>, [u8; KEY_SIZE], [u8; NONCE_SIZE]) {
    let (kem_ct, ss) = mlkem::encaps(params, recipient_pk);
    let mut ss: [u8; 32] = ss.try_into().unwrap();
    let (key, nonce) = kdf(params, &ss, b"rzp2-hybrid-v1");
    ss.zeroize();
    (kem_ct, key, nonce)
}

/// 混合解密。
pub fn decrypt(
    params: &Params,
    recipient_sk: &[u8],
    hc: &HybridCiphertext,
) -> Result<Vec<u8>, HybridError> {
    let (key, nonce) = decapsulate(params, recipient_sk, &hc.kem_ct)?;

    if nonce != hc.nonce {
        return Err(HybridError::NonceMismatch);
    }

    aead::aead_decrypt(&key, &hc.nonce, &hc.ct, &hc.kem_ct, &hc.tag)
        .map_err(|_| HybridError::AuthenticationFailed)
}

/// 仅执行 ML-KEM 解封装与 KDF，返回 `(key, nonce)`，供分块 AEAD 等流式路径复用。
pub fn decapsulate(
    params: &Params,
    recipient_sk: &[u8],
    kem_ct: &[u8],
) -> Result<([u8; KEY_SIZE], [u8; NONCE_SIZE]), HybridError> {
    let ss = mlkem::decaps(params, recipient_sk, kem_ct);
    let mut ss: [u8; 32] = ss.try_into().unwrap();
    let (key, nonce) = kdf(params, &ss, b"rzp2-hybrid-v1");
    ss.zeroize();
    Ok((key, nonce))
}

/// 仅执行 ML-KEM 封装，返回 `(kem_ct, ss)`；`ss` 供多接收者 DEK 包裹使用。
pub fn encapsulate_ss(params: &Params, recipient_pk: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let (kem_ct, ss) = mlkem::encaps(params, recipient_pk);
    let ss: [u8; 32] = ss.try_into().unwrap();
    (kem_ct, ss)
}

/// 仅执行 ML-KEM 解封装，返回 `ss`；`ss` 供多接收者 DEK 解包使用。
pub fn decapsulate_ss(params: &Params, recipient_sk: &[u8], kem_ct: &[u8]) -> [u8; 32] {
    let ss = mlkem::decaps(params, recipient_sk, kem_ct);
    ss.try_into().unwrap()
}

/// 从共享密钥派生包裹 DEK 所用的密钥与 nonce（与内容加密 KDF 使用不同 label）。
fn derive_wrap_key(params: &Params, ss: &[u8; 32]) -> ([u8; KEY_SIZE], [u8; NONCE_SIZE]) {
    kdf(params, ss, b"rzp2-dek-wrap-v1")
}

/// 用接收者共享密钥包裹 DEK，返回 32 字节密文 + 16 字节标签。
pub fn wrap_dek(
    params: &Params,
    ss: &[u8; 32],
    kem_ct: &[u8],
    dek: &[u8; KEY_SIZE],
) -> [u8; DEK_WRAP_SIZE] {
    let (key, nonce) = derive_wrap_key(params, ss);
    let (ct, tag) = aead::aead_encrypt(&key, &nonce, dek, kem_ct);
    let mut out = [0u8; DEK_WRAP_SIZE];
    out[..KEY_SIZE].copy_from_slice(&ct);
    out[KEY_SIZE..].copy_from_slice(&tag);
    out
}

/// 解包 DEK（认证失败返回错误）。
pub fn unwrap_dek(
    params: &Params,
    ss: &[u8; 32],
    kem_ct: &[u8],
    wrapped: &[u8; DEK_WRAP_SIZE],
) -> Result<[u8; KEY_SIZE], HybridError> {
    let (key, nonce) = derive_wrap_key(params, ss);
    let ct = &wrapped[..KEY_SIZE];
    let tag: [u8; TAG_SIZE] = wrapped[KEY_SIZE..].try_into().unwrap();
    let dek = aead::aead_decrypt(&key, &nonce, ct, kem_ct, &tag)
        .map_err(|_| HybridError::AuthenticationFailed)?;
    Ok(dek.try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlkem::MLKEM768;

    #[test]
    fn roundtrip() {
        let (pk, sk) = mlkem::keygen(&MLKEM768);
        let plaintext = b"hybrid encryption roundtrip test".repeat(10);
        let hc = encrypt(&MLKEM768, &pk, &plaintext);
        let dec = decrypt(&MLKEM768, &sk, &hc).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let (pk, sk) = mlkem::keygen(&MLKEM768);
        let mut hc = encrypt(&MLKEM768, &pk, b"secret data");
        hc.ct[0] ^= 0xFF;
        assert_eq!(
            decrypt(&MLKEM768, &sk, &hc).unwrap_err(),
            HybridError::AuthenticationFailed
        );
    }

    #[test]
    fn tampered_kem_ct_rejected() {
        let (pk, sk) = mlkem::keygen(&MLKEM768);
        let mut hc = encrypt(&MLKEM768, &pk, b"secret data");
        hc.kem_ct[0] ^= 0xFF;
        assert!(decrypt(&MLKEM768, &sk, &hc).is_err());
    }

    #[test]
    fn kdf_is_deterministic() {
        let ss = [7u8; 32];
        let (k1, n1) = kdf(&MLKEM768, &ss, b"label");
        let (k2, n2) = kdf(&MLKEM768, &ss, b"label");
        assert_eq!(k1, k2);
        assert_eq!(n1, n2);
    }

    #[test]
    fn dek_wrap_roundtrip() {
        let (pk, sk) = mlkem::keygen(&MLKEM768);
        let (kem_ct, ss) = encapsulate_ss(&MLKEM768, &pk);
        let dek = [0x5au8; KEY_SIZE];
        let wrapped = wrap_dek(&MLKEM768, &ss, &kem_ct, &dek);

        let ss2 = decapsulate_ss(&MLKEM768, &sk, &kem_ct);
        assert_eq!(ss, ss2);
        let unwrapped = unwrap_dek(&MLKEM768, &ss2, &kem_ct, &wrapped).unwrap();
        assert_eq!(unwrapped, dek);
    }

    #[test]
    fn dek_wrap_tamper_rejected() {
        let (pk, sk) = mlkem::keygen(&MLKEM768);
        let (kem_ct, ss) = encapsulate_ss(&MLKEM768, &pk);
        let dek = [0x5au8; KEY_SIZE];
        let mut wrapped = wrap_dek(&MLKEM768, &ss, &kem_ct, &dek);
        wrapped[0] ^= 0xFF;
        let ss2 = decapsulate_ss(&MLKEM768, &sk, &kem_ct);
        assert_eq!(
            unwrap_dek(&MLKEM768, &ss2, &kem_ct, &wrapped).unwrap_err(),
            HybridError::AuthenticationFailed
        );
    }
}
