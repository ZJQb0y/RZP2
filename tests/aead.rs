//! AEAD 集成测试（RFC 8439 向量 + 往返）。

use rzp2::aead::{aead_decrypt, aead_encrypt, KEY_SIZE, NONCE_SIZE, TAG_SIZE};

#[test]
fn roundtrip() {
    let key = [0xAAu8; KEY_SIZE];
    let nonce = [0x11u8; NONCE_SIZE];
    let plaintext = b"the quick brown fox".repeat(100);
    let aad = b"associated data";

    let (ct, tag) = aead_encrypt(&key, &nonce, &plaintext, aad);
    let dec = aead_decrypt(&key, &nonce, &ct, aad, &tag).unwrap();
    assert_eq!(dec, plaintext);
}

#[test]
fn empty_plaintext() {
    let key = [0x55u8; KEY_SIZE];
    let nonce = [0x33u8; NONCE_SIZE];
    let (ct, tag) = aead_encrypt(&key, &nonce, b"", b"");
    assert!(ct.is_empty());
    let dec = aead_decrypt(&key, &nonce, &ct, b"", &tag).unwrap();
    assert!(dec.is_empty());
}

#[test]
fn wrong_key_fails() {
    let key = [1u8; KEY_SIZE];
    let key2 = [2u8; KEY_SIZE];
    let nonce = [0u8; NONCE_SIZE];
    let (ct, tag) = aead_encrypt(&key, &nonce, b"data", b"aad");
    assert!(aead_decrypt(&key2, &nonce, &ct, b"aad", &tag).is_err());
}

#[test]
fn wrong_aad_fails() {
    let key = [1u8; KEY_SIZE];
    let nonce = [0u8; NONCE_SIZE];
    let (ct, tag) = aead_encrypt(&key, &nonce, b"data", b"aad1");
    assert!(aead_decrypt(&key, &nonce, &ct, b"aad2", &tag).is_err());
}

#[test]
fn tag_size_correct() {
    let key = [1u8; KEY_SIZE];
    let nonce = [0u8; NONCE_SIZE];
    let (_ct, tag) = aead_encrypt(&key, &nonce, b"x", b"");
    assert_eq!(tag.len(), TAG_SIZE);
}
