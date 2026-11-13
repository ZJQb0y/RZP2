//! 混合加密集成测试。

use rzp2::hybrid::{decrypt, encrypt, HybridCiphertext};
use rzp2::mlkem::{self, MLKEM1024, MLKEM512, MLKEM768};

#[test]
fn roundtrip_all_params() {
    for p in [MLKEM512, MLKEM768, MLKEM1024] {
        let (pk, sk) = mlkem::keygen(&p);
        let plaintext = b"hybrid encryption payload".repeat(50);
        let hc = encrypt(&p, &pk, &plaintext);
        let dec = decrypt(&p, &sk, &hc).unwrap();
        assert_eq!(dec, plaintext, "roundtrip failed for {}", p.name());
    }
}

#[test]
fn ciphertext_is_encrypted() {
    // 密文不应包含明文（弱检查：密文与明文不应相等）。
    let (pk, _sk) = mlkem::keygen(&MLKEM768);
    let plaintext = b"this is secret".repeat(20);
    let hc = encrypt(&MLKEM768, &pk, &plaintext);
    assert_ne!(hc.ct, plaintext);
}

#[test]
fn struct_roundtrip_via_serde_like() {
    // 验证 HybridCiphertext 各字段长度。
    let (pk, sk) = mlkem::keygen(&MLKEM768);
    let hc = encrypt(&MLKEM768, &pk, b"data");
    assert_eq!(hc.kem_ct.len(), MLKEM768.ciphertext_bytes);
    assert_eq!(hc.nonce.len(), 12);
    assert_eq!(hc.tag.len(), 16);
    let _ = decrypt(&MLKEM768, &sk, &hc).unwrap();
}

#[test]
fn tamper_detected() {
    let (pk, sk) = mlkem::keygen(&MLKEM768);
    let mut hc = encrypt(&MLKEM768, &pk, b"important secret");

    // 篡改 nonce。
    let mut hc2 = HybridCiphertext {
        kem_ct: hc.kem_ct.clone(),
        nonce: hc.nonce,
        ct: hc.ct.clone(),
        tag: hc.tag,
    };
    hc2.nonce[0] ^= 1;
    assert!(decrypt(&MLKEM768, &sk, &hc2).is_err());

    // 篡改密文。
    hc.ct[3] ^= 0x80;
    assert!(decrypt(&MLKEM768, &sk, &hc).is_err());
}
