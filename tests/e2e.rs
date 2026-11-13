//! 端到端测试：完整 RZP2 读写管线（含 CLI 级别流程）。

use rzp2::format::KemParams;
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
fn e2e_plain_pipeline() {
    let data = b"end to end pipeline data".repeat(500);
    let packed = pack(&data, &config(Encryption::None, true)).unwrap();
    let unpacked = unpack(&packed, DecryptKey::None).unwrap();
    assert_eq!(unpacked, data);
}

#[test]
fn e2e_encrypted_pipeline() {
    let (pk, sk) = mlkem::keygen(&mlkem::MLKEM768);
    let data = b"end to end encrypted pipeline data".repeat(500);
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
    // 加密后不应包含明文。
    assert!(!contains_subslice(&packed, b"end to end encrypted"));
    let unpacked = unpack(&packed, DecryptKey::PrivateKey(&sk)).unwrap();
    assert_eq!(unpacked, data);
}

#[test]
fn e2e_all_kem_params() {
    let params = [
        (KemParams::MlKem512, mlkem::MLKEM512),
        (KemParams::MlKem768, mlkem::MLKEM768),
        (KemParams::MlKem1024, mlkem::MLKEM1024),
    ];
    for (kem, mp) in params {
        let (pk, sk) = mlkem::keygen(&mp);
        let data = format!("payload for {}", kem.name()).repeat(100);
        let packed = pack(
            data.as_bytes(),
            &config(
                Encryption::Kem {
                    kem,
                    recipient_pk: &pk,
                },
                false,
            ),
        )
        .unwrap();
        let unpacked = unpack(&packed, DecryptKey::PrivateKey(&sk)).unwrap();
        assert_eq!(unpacked, data.as_bytes());
    }
}

#[test]
fn e2e_large_file_streaming() {
    // 大文件（>1MB 可压缩 + 随机混合）往返。
    let mut data = Vec::with_capacity(2 << 20);
    for i in 0usize..(2 << 20) {
        // 周期性可压缩块 + 伪随机。
        let b = if i % 1024 < 800 {
            (i % 251) as u8
        } else {
            (i.wrapping_mul(2654435761) >> 13) as u8
        };
        data.push(b);
    }
    let packed = pack(&data, &config(Encryption::None, true)).unwrap();
    let unpacked = unpack(&packed, DecryptKey::None).unwrap();
    assert_eq!(unpacked, data);
}

#[test]
fn e2e_wrong_key_fails() {
    let (pk, _sk) = mlkem::keygen(&mlkem::MLKEM768);
    let (_pk2, sk2) = mlkem::keygen(&mlkem::MLKEM768);
    let data = b"sensitive data".repeat(100);
    let packed = pack(
        &data,
        &config(
            Encryption::Kem {
                kem: KemParams::MlKem768,
                recipient_pk: &pk,
            },
            false,
        ),
    )
    .unwrap();
    // 用错误私钥解封装：AEAD 认证必然失败。
    assert!(unpack(&packed, DecryptKey::PrivateKey(&sk2)).is_err());
}

/// 检查 `haystack` 是否包含 `needle`（字节级）。
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
