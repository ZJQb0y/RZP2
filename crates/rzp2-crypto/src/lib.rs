//! RZP2 加密 / 解密动态库（C ABI）。
//!
//! 暴露 ML-KEM（含 ML-KEM + X25519 混合）密钥生成与混合加解密、
//! ChaCha20-Poly1305 AEAD 以及 Argon2id 口令派生，均不含 CLI。

// FFI 导出函数的指针有效性由 C 头文件中的契约约束，调用方负责提供合法指针与长度。
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ptr;
use std::slice;

use rzp2::aead::{KEY_SIZE, NONCE_SIZE, TAG_SIZE};
use rzp2::hybrid::HybridCiphertext;
use rzp2::mlkem::Params;

/// 参数错误 / 格式错误。
const ERR_INVALID: isize = -1;
/// 输出缓冲区不足。
const ERR_TOO_SMALL: isize = -2;
/// 认证失败（密钥错误或数据被篡改）。
const ERR_AUTH: isize = -3;

/// X25519 公钥 / 私钥字节数。
const X25519_BYTES: usize = 32;

/// 由 `kem_id` 解析 `(Params, 是否混合)`。
fn kem_params(kem_id: u32) -> Option<(Params, bool)> {
    use rzp2::mlkem::{MLKEM1024, MLKEM512, MLKEM768};
    match kem_id {
        0 => Some((MLKEM512, false)),
        1 => Some((MLKEM768, false)),
        2 => Some((MLKEM1024, false)),
        3 => Some((MLKEM512, true)),
        4 => Some((MLKEM768, true)),
        5 => Some((MLKEM1024, true)),
        _ => None,
    }
}

fn pk_len(p: &Params, hybrid: bool) -> usize {
    p.public_key_bytes + if hybrid { X25519_BYTES } else { 0 }
}

fn sk_len(p: &Params, hybrid: bool) -> usize {
    p.secret_key_bytes + if hybrid { X25519_BYTES } else { 0 }
}

/// 返回指定 KEM 参数集的公钥字节数；`kem_id` 非法返回 [`ERR_INVALID`]。
#[no_mangle]
pub extern "C" fn rzp2_kem_public_key_size(kem_id: u32) -> isize {
    match kem_params(kem_id) {
        Some((p, hybrid)) => pk_len(&p, hybrid) as isize,
        None => ERR_INVALID,
    }
}

/// 返回指定 KEM 参数集的私钥字节数；`kem_id` 非法返回 [`ERR_INVALID`]。
#[no_mangle]
pub extern "C" fn rzp2_kem_secret_key_size(kem_id: u32) -> isize {
    match kem_params(kem_id) {
        Some((p, hybrid)) => sk_len(&p, hybrid) as isize,
        None => ERR_INVALID,
    }
}

/// 生成 ML-KEM（或 ML-KEM + X25519 混合）密钥对，成功返回 0。
///
/// `pk_out` / `sk_out` 需分别预分配 [`rzp2_kem_public_key_size`] /
/// [`rzp2_kem_secret_key_size`] 返回的字节数。
#[no_mangle]
pub extern "C" fn rzp2_kem_keygen(kem_id: u32, pk_out: *mut u8, sk_out: *mut u8) -> isize {
    let Some((p, hybrid)) = kem_params(kem_id) else {
        return ERR_INVALID;
    };
    if pk_out.is_null() || sk_out.is_null() {
        return ERR_INVALID;
    }

    let (mpk, msk) = rzp2::mlkem::keygen(&p);
    // SAFETY: 调用方保证 pk_out/sk_out 指向足够大的可写内存。
    unsafe {
        ptr::copy_nonoverlapping(mpk.as_ptr(), pk_out, mpk.len());
        ptr::copy_nonoverlapping(msk.as_ptr(), sk_out, msk.len());
    }

    if hybrid {
        let (xpk, xsk) = rzp2::crypto::x25519::keygen();
        // SAFETY: 偏移在调用方分配的缓冲区范围内。
        unsafe {
            ptr::copy_nonoverlapping(xpk.as_ptr(), pk_out.add(mpk.len()), X25519_BYTES);
            ptr::copy_nonoverlapping(xsk.as_ptr(), sk_out.add(msk.len()), X25519_BYTES);
        }
    }
    0
}

/// 混合加密（ML-KEM / ML-KEM+X25519 封装 + ChaCha20-Poly1305）。
///
/// 密文布局：`kem_ct_len(4, LE) | kem_ct | nonce(12) | tag(16) | ct`。
/// `out` 传空指针时返回所需缓冲区字节数（不写入）。
#[no_mangle]
pub extern "C" fn rzp2_crypto_encrypt(
    kem_id: u32,
    recipient_pk: *const u8,
    pk_bytes: usize,
    plaintext: *const u8,
    pt_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> isize {
    let Some((p, hybrid)) = kem_params(kem_id) else {
        return ERR_INVALID;
    };
    if recipient_pk.is_null() || plaintext.is_null() {
        return ERR_INVALID;
    }
    if pk_bytes != pk_len(&p, hybrid) {
        return ERR_INVALID;
    }
    // SAFETY: 调用方保证指针指向对应长度的可读内存。
    let pk = unsafe { slice::from_raw_parts(recipient_pk, pk_bytes) };
    let pt = unsafe { slice::from_raw_parts(plaintext, pt_len) };

    let hc = if hybrid {
        rzp2::hybrid::encrypt_hybrid(&p, pk, pt)
    } else {
        rzp2::hybrid::encrypt(&p, pk, pt)
    };
    write_out(&serialize_ciphertext(&hc), out, out_cap)
}

/// 混合解密，成功返回明文字节数；认证失败返回 [`ERR_AUTH`]。
#[no_mangle]
pub extern "C" fn rzp2_crypto_decrypt(
    kem_id: u32,
    recipient_sk: *const u8,
    sk_bytes: usize,
    ciphertext: *const u8,
    ct_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> isize {
    let Some((p, hybrid)) = kem_params(kem_id) else {
        return ERR_INVALID;
    };
    if recipient_sk.is_null() || ciphertext.is_null() {
        return ERR_INVALID;
    }
    if sk_bytes != sk_len(&p, hybrid) {
        return ERR_INVALID;
    }
    // SAFETY: 调用方保证指针指向对应长度的可读内存。
    let sk = unsafe { slice::from_raw_parts(recipient_sk, sk_bytes) };
    let data = unsafe { slice::from_raw_parts(ciphertext, ct_len) };

    let Some(hc) = deserialize_ciphertext(data) else {
        return ERR_INVALID;
    };
    let res = if hybrid {
        rzp2::hybrid::decrypt_hybrid(&p, sk, &hc)
    } else {
        rzp2::hybrid::decrypt(&p, sk, &hc)
    };
    match res {
        Ok(plain) => write_out(&plain, out, out_cap),
        Err(_) => ERR_AUTH,
    }
}

/// ChaCha20-Poly1305 AEAD 加密。`key` 32 字节，`nonce` 12 字节。
///
/// 密文布局：`ct | tag(16)`。`out` 传空指针时返回所需缓冲区字节数。
#[no_mangle]
pub extern "C" fn rzp2_aead_encrypt(
    key: *const u8,
    nonce: *const u8,
    plaintext: *const u8,
    pt_len: usize,
    aad: *const u8,
    aad_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> isize {
    if key.is_null() || nonce.is_null() || plaintext.is_null() {
        return ERR_INVALID;
    }
    // SAFETY: 调用方保证 key/nonce 分别为 32/12 字节。
    let key: &[u8; KEY_SIZE] = unsafe { &*(key as *const [u8; KEY_SIZE]) };
    let nonce: &[u8; NONCE_SIZE] = unsafe { &*(nonce as *const [u8; NONCE_SIZE]) };
    let pt = unsafe { slice::from_raw_parts(plaintext, pt_len) };
    let aad = if aad_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(aad, aad_len) }
    };

    let (mut ct, tag) = rzp2::aead::aead_encrypt(key, nonce, pt, aad);
    ct.extend_from_slice(&tag);
    write_out(&ct, out, out_cap)
}

/// ChaCha20-Poly1305 AEAD 解密。认证失败返回 [`ERR_AUTH`]。
#[no_mangle]
pub extern "C" fn rzp2_aead_decrypt(
    key: *const u8,
    nonce: *const u8,
    ciphertext: *const u8,
    ct_len: usize,
    aad: *const u8,
    aad_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> isize {
    if key.is_null() || nonce.is_null() || ciphertext.is_null() {
        return ERR_INVALID;
    }
    if ct_len < TAG_SIZE {
        return ERR_INVALID;
    }
    // SAFETY: 调用方保证 key/nonce 分别为 32/12 字节。
    let key: &[u8; KEY_SIZE] = unsafe { &*(key as *const [u8; KEY_SIZE]) };
    let nonce: &[u8; NONCE_SIZE] = unsafe { &*(nonce as *const [u8; NONCE_SIZE]) };
    let data = unsafe { slice::from_raw_parts(ciphertext, ct_len) };
    let aad = if aad_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(aad, aad_len) }
    };

    let tag: &[u8; TAG_SIZE] = data[data.len() - TAG_SIZE..].try_into().unwrap();
    let ct = &data[..data.len() - TAG_SIZE];
    match rzp2::aead::aead_decrypt(key, nonce, ct, aad, tag) {
        Ok(plain) => write_out(&plain, out, out_cap),
        Err(()) => ERR_AUTH,
    }
}

/// Argon2id 口令派生 32 字节密钥，成功返回 0。
#[no_mangle]
pub extern "C" fn rzp2_derive_key(
    password: *const u8,
    pw_len: usize,
    salt: *const u8,
    salt_len: usize,
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
    out: *mut u8,
) -> isize {
    if password.is_null() || salt.is_null() || out.is_null() {
        return ERR_INVALID;
    }
    // SAFETY: 调用方保证指针指向对应长度的可读内存。
    let pw = unsafe { slice::from_raw_parts(password, pw_len) };
    let salt = unsafe { slice::from_raw_parts(salt, salt_len) };
    let key = rzp2::hybrid::derive_password_key(pw, salt, memory_kib, iterations, lanes);
    // SAFETY: out 非空且指向至少 32 字节可写内存。
    unsafe {
        ptr::copy_nonoverlapping(key.as_ptr(), out, KEY_SIZE);
    }
    0
}

fn serialize_ciphertext(hc: &HybridCiphertext) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + hc.kem_ct.len() + NONCE_SIZE + TAG_SIZE + hc.ct.len());
    out.extend_from_slice(&(hc.kem_ct.len() as u32).to_le_bytes());
    out.extend_from_slice(&hc.kem_ct);
    out.extend_from_slice(&hc.nonce);
    out.extend_from_slice(&hc.tag);
    out.extend_from_slice(&hc.ct);
    out
}

fn deserialize_ciphertext(data: &[u8]) -> Option<HybridCiphertext> {
    if data.len() < 4 + NONCE_SIZE + TAG_SIZE {
        return None;
    }
    let kem_ct_len = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
    let mut off = 4;
    if data.len() < off + kem_ct_len + NONCE_SIZE + TAG_SIZE {
        return None;
    }
    let kem_ct = data[off..off + kem_ct_len].to_vec();
    off += kem_ct_len;

    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&data[off..off + NONCE_SIZE]);
    off += NONCE_SIZE;

    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&data[off..off + TAG_SIZE]);
    off += TAG_SIZE;

    let ct = data[off..].to_vec();
    Some(HybridCiphertext {
        kem_ct,
        nonce,
        ct,
        tag,
    })
}

/// 把结果写入输出缓冲区：`out` 为空时返回所需容量，缓冲区不足返回 [`ERR_TOO_SMALL`]。
fn write_out(bytes: &[u8], out: *mut u8, out_cap: usize) -> isize {
    if out.is_null() {
        return bytes.len() as isize;
    }
    if out_cap < bytes.len() {
        return ERR_TOO_SMALL;
    }
    // SAFETY: 已校验 out_cap 足够；out 非空。
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
    }
    bytes.len() as isize
}
