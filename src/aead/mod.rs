//! ChaCha20-Poly1305 AEAD（RFC 8439）。

pub mod chacha20;
pub mod poly1305;

use chacha20::{chacha20_block, chacha20_xor};
use poly1305::poly1305;

use std::io::Write;

/// 密钥长度。
pub const KEY_SIZE: usize = 32;
/// nonce 长度。
pub const NONCE_SIZE: usize = 12;
/// 认证标签长度。
pub const TAG_SIZE: usize = 16;

/// 常量时间比较，相等返回 true。
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

/// 构造 Poly1305 的输入：`aad || pad || ciphertext || pad || len(aad) || len(ct)`。
fn mac_data(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(aad.len() + ciphertext.len() + 32);
    data.extend_from_slice(aad);
    while data.len() % 16 != 0 {
        data.push(0);
    }
    data.extend_from_slice(ciphertext);
    while data.len() % 16 != 0 {
        data.push(0);
    }
    data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    data
}

/// AEAD 加密，返回 `(ciphertext, tag)`。
pub fn aead_encrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> (Vec<u8>, [u8; TAG_SIZE]) {
    let block0 = chacha20_block(key, 0, nonce);
    let poly_key: [u8; 32] = block0[..32].try_into().unwrap();

    let mut ciphertext = plaintext.to_vec();
    chacha20_xor(&mut ciphertext, key, 1, nonce);

    let tag = poly1305(&poly_key, &mac_data(aad, &ciphertext));
    (ciphertext, tag)
}

/// AEAD 解密，认证失败返回 `Err(())`。
#[allow(clippy::result_unit_err)]
pub fn aead_decrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
    tag: &[u8; TAG_SIZE],
) -> Result<Vec<u8>, ()> {
    let block0 = chacha20_block(key, 0, nonce);
    let poly_key: [u8; 32] = block0[..32].try_into().unwrap();

    let computed = poly1305(&poly_key, &mac_data(aad, ciphertext));
    if !ct_eq(&computed, tag) {
        return Err(());
    }

    let mut plaintext = ciphertext.to_vec();
    chacha20_xor(&mut plaintext, key, 1, nonce);
    Ok(plaintext)
}

/// 分块 AEAD 每块明文长度（压缩流分块）。
pub const CHUNK_SIZE: usize = 64 * 1024;

/// 由基准 nonce 与块序号派生该块的 nonce（低 8 字节与序号异或）。
pub fn chunk_nonce(base: &[u8; NONCE_SIZE], index: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = *base;
    let c = index.to_le_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= c[i];
    }
    nonce
}

/// 分块 AEAD 加密器：把明文流切成固定块，逐块加密并写出
/// `len(4, LE) + ct + tag(16)` 帧，`finish` 时写出 4 字节 0 长度终止符。
pub struct ChunkedWriter<W: Write> {
    inner: W,
    key: [u8; KEY_SIZE],
    base_nonce: [u8; NONCE_SIZE],
    aad_prefix: Vec<u8>,
    buf: Vec<u8>,
    index: u64,
    finished: bool,
}

impl<W: Write> ChunkedWriter<W> {
    pub fn new(
        inner: W,
        key: [u8; KEY_SIZE],
        base_nonce: [u8; NONCE_SIZE],
        aad_prefix: &[u8],
    ) -> Self {
        Self {
            inner,
            key,
            base_nonce,
            aad_prefix: aad_prefix.to_vec(),
            buf: Vec::with_capacity(CHUNK_SIZE),
            index: 0,
            finished: false,
        }
    }

    fn emit_chunk(&mut self, data: &[u8]) -> std::io::Result<()> {
        let nonce = chunk_nonce(&self.base_nonce, self.index);
        let mut aad = Vec::with_capacity(self.aad_prefix.len() + 8);
        aad.extend_from_slice(&self.aad_prefix);
        aad.extend_from_slice(&self.index.to_le_bytes());
        let (ct, tag) = aead_encrypt(&self.key, &nonce, data, &aad);

        self.inner.write_all(&(ct.len() as u32).to_le_bytes())?;
        self.inner.write_all(&ct)?;
        self.inner.write_all(&tag)?;
        self.index += 1;
        Ok(())
    }

    /// 冲刷剩余部分并写出终止符（幂等）。
    pub fn finish(&mut self) -> std::io::Result<()> {
        if self.finished {
            return Ok(());
        }
        if !self.buf.is_empty() {
            let buf = std::mem::take(&mut self.buf);
            self.emit_chunk(&buf)?;
        }
        self.inner.write_all(&0u32.to_le_bytes())?;
        self.finished = true;
        Ok(())
    }
}

impl<W: Write> Write for ChunkedWriter<W> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut written = 0;
        while written < data.len() {
            let space = CHUNK_SIZE - self.buf.len();
            let n = (data.len() - written).min(space);
            self.buf.extend_from_slice(&data[written..written + n]);
            written += n;
            if self.buf.len() == CHUNK_SIZE {
                let full = std::mem::take(&mut self.buf);
                self.emit_chunk(&full)?;
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// 分块 AEAD 解密：解析 `len + ct + tag` 帧直至 0 长度终止符，返回拼接后的明文。
#[allow(clippy::result_unit_err)]
pub fn chunked_decrypt(
    key: &[u8; KEY_SIZE],
    base_nonce: &[u8; NONCE_SIZE],
    payload: &[u8],
    aad_prefix: &[u8],
) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut index = 0u64;

    loop {
        if pos + 4 > payload.len() {
            return Err(());
        }
        let len = u32::from_le_bytes(payload[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if len == 0 {
            return Ok(out);
        }
        if pos + len + TAG_SIZE > payload.len() {
            return Err(());
        }
        let ct = &payload[pos..pos + len];
        pos += len;
        let tag: [u8; TAG_SIZE] = payload[pos..pos + TAG_SIZE].try_into().unwrap();
        pos += TAG_SIZE;

        let nonce = chunk_nonce(base_nonce, index);
        let mut aad = Vec::with_capacity(aad_prefix.len() + 8);
        aad.extend_from_slice(aad_prefix);
        aad.extend_from_slice(&index.to_le_bytes());
        let plain = aead_decrypt(key, &nonce, ct, &aad, &tag)?;
        out.extend_from_slice(&plain);
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8439_aead_vector() {
        // RFC 8439 §2.8.2。
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ct = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];
        let expected_tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];

        let (ct, tag) = aead_encrypt(&key, &nonce, plaintext, &aad);
        assert_eq!(ct, expected_ct);
        assert_eq!(tag, expected_tag);

        let dec = aead_decrypt(&key, &nonce, &ct, &aad, &tag).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn tampered_tag_rejected() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let (ct, mut tag) = aead_encrypt(&key, &nonce, b"hello", b"aad");
        tag[0] ^= 1;
        assert!(aead_decrypt(&key, &nonce, &ct, b"aad", &tag).is_err());
    }

    #[test]
    fn chunked_roundtrip() {
        let key = [0x33u8; KEY_SIZE];
        let nonce = [0x11u8; NONCE_SIZE];
        let aad_prefix = b"header-bytes";

        // 数据跨多个块 + 末尾非整块。
        let mut plaintext = Vec::new();
        for i in 0..(CHUNK_SIZE * 2 + 1234) {
            plaintext.push((i % 251) as u8);
        }

        let mut out = Vec::new();
        {
            let mut w = ChunkedWriter::new(&mut out, key, nonce, aad_prefix);
            for chunk in plaintext.chunks(7777) {
                w.write_all(chunk).unwrap();
            }
            w.finish().unwrap();
        }

        let dec = chunked_decrypt(&key, &nonce, &out, aad_prefix).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn chunked_tamper_rejected() {
        let key = [0x55u8; KEY_SIZE];
        let nonce = [0x22u8; NONCE_SIZE];
        let mut out = Vec::new();
        {
            let mut w = ChunkedWriter::new(&mut out, key, nonce, b"aad");
            w.write_all(b"payload that spans one chunk").unwrap();
            w.finish().unwrap();
        }
        // 翻转首块密文中的一个字节（跳过 4 字节长度前缀）。
        out[5] ^= 1;
        assert!(chunked_decrypt(&key, &nonce, &out, b"aad").is_err());
    }
}
