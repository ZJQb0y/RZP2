//! 模糊/错误注入测试：确保损坏输入不会 panic，并尽量报错。

use rzp2::format::KemParams;
use rzp2::format::{Header, HEADER_PREFIX_SIZE, MAGIC};
use rzp2::lzma;
use rzp2::mlkem;
use rzp2::pipeline::{pack, unpack, DecryptKey, Encryption, PackConfig};

fn config<'a>(encryption: Encryption<'a>, add_checksum: bool) -> PackConfig<'a> {
    PackConfig {
        params: lzma::LzmaParams::default(),
        level: lzma::DEFAULT_LEVEL,
        add_checksum,
        archive: false,
        encryption,
        processes: 1,
        block_size: lzma::DEFAULT_BLOCK_SIZE,
    }
}

#[test]
fn fuzz_lzma_decoder_never_panics() {
    // 随机字节喂给 LZMA 解码器，只要求不 panic。
    let mut seed = 0x1234_5678u32;
    for len in [0usize, 1, 4, 13, 16, 64, 256, 1024] {
        let mut buf = vec![0u8; len];
        for b in buf.iter_mut() {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            *b = (seed >> 24) as u8;
        }
        let _ = lzma::decode(&buf);
    }
}

#[test]
fn fuzz_pipeline_truncation() {
    let data = b"fuzz target data".repeat(200);
    let packed = pack(&data, &config(Encryption::None, true)).unwrap();
    // 各种截断位置。
    for cut in 0..packed.len() {
        let _ = unpack(&packed[..cut], DecryptKey::None);
    }
}

#[test]
fn fuzz_header_corruption() {
    let data = b"header corruption test".repeat(100);
    let packed = pack(&data, &config(Encryption::None, false)).unwrap();
    // 逐字节翻转头部前 24 字节。
    for i in 0..HEADER_PREFIX_SIZE.min(packed.len()) {
        let mut p = packed.clone();
        p[i] ^= 0xFF;
        let _ = unpack(&p, DecryptKey::None);
    }
}

#[test]
fn fuzz_bad_magic() {
    let mut buf = vec![0u8; 64];
    buf[0..4].copy_from_slice(b"XXXX");
    assert!(Header::decode(&buf).is_err());
    assert_eq!(buf[0..4], *b"XXXX");
    let _ = MAGIC;
}

#[test]
fn fuzz_encrypted_tampering() {
    let (pk, sk) = mlkem::keygen(&mlkem::MLKEM768);
    let data = b"encrypted fuzz".repeat(100);
    let packed = pack(
        &data,
        &config(
            Encryption::Kem {
                kem: KemParams::MlKem768,
                recipient_pk: &pk,
            },
            true,
        ),
    )
    .unwrap();
    // 翻转密文区域若干字节。
    for pos in [HEADER_PREFIX_SIZE, packed.len() / 2, packed.len() - 1] {
        if pos < packed.len() {
            let mut p = packed.clone();
            p[pos] ^= 0x5A;
            // 可能成功（碰撞概率极低）或报错，但不 panic。
            let _ = unpack(&p, DecryptKey::PrivateKey(&sk));
        }
    }
}

#[test]
fn fuzz_kem_ct_tampering() {
    let (pk, sk) = mlkem::keygen(&mlkem::MLKEM768);
    let data = b"kem ct fuzz".repeat(100);
    let packed = pack(
        &data,
        &config(
            Encryption::Kem {
                kem: KemParams::MlKem768,
                recipient_pk: &pk,
            },
            true,
        ),
    )
    .unwrap();
    // 找到 ek 区域（头部之后），翻转其内容。
    let (header, offset) = Header::decode(&packed).unwrap();
    if header.encrypted && !header.ek.is_empty() {
        let ek_start = offset - header.ek.len() - 12; // ek 位于头部加密字段
        let mut p = packed.clone();
        p[ek_start] ^= 0xAA;
        let _ = unpack(&p, DecryptKey::PrivateKey(&sk));
    }
}
