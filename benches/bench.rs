//! RZP2 性能基准（压缩率与吞吐）。
//!
//! 使用 nightly 的 `cargo bench` 运行：
//! ```sh
//! cargo +nightly bench
//! ```

#![feature(test)]
extern crate test;

use rzp2::format::KemParams;
use rzp2::lzma::{self, LzmaParams};
use rzp2::mlkem;
use rzp2::pipeline::{pack, unpack, DecryptKey, Encryption, PackConfig};
use test::Bencher;

fn config<'a>(encryption: Encryption<'a>, add_checksum: bool) -> PackConfig<'a> {
    PackConfig {
        params: LzmaParams::default(),
        level: lzma::DEFAULT_LEVEL,
        add_checksum,
        archive: false,
        encryption,
        processes: 1,
        block_size: lzma::DEFAULT_BLOCK_SIZE,
    }
}

/// 生成一段混合可压缩数据。
fn sample_data(n: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(n);
    for i in 0..n {
        let b = if i % 1024 < 800 {
            (i % 251) as u8
        } else {
            (i.wrapping_mul(2654435761) >> 13) as u8
        };
        data.push(b);
    }
    data
}

#[bench]
fn lzma_compress_1mb(b: &mut Bencher) {
    let data = sample_data(1 << 20);
    let params = LzmaParams::default();
    b.iter(|| lzma::encode(&data, &params));
}

#[bench]
fn lzma_decompress_1mb(b: &mut Bencher) {
    let data = sample_data(1 << 20);
    let params = LzmaParams::default();
    let compressed = lzma::encode(&data, &params);
    b.iter(|| lzma::decode(&compressed).unwrap());
}

#[bench]
fn mlkem768_keygen(b: &mut Bencher) {
    let p = mlkem::MLKEM768;
    b.iter(|| mlkem::keygen(&p));
}

#[bench]
fn mlkem768_encaps(b: &mut Bencher) {
    let p = mlkem::MLKEM768;
    let (pk, _sk) = mlkem::keygen(&p);
    b.iter(|| mlkem::encaps(&p, &pk));
}

#[bench]
fn mlkem768_decaps(b: &mut Bencher) {
    let p = mlkem::MLKEM768;
    let (pk, sk) = mlkem::keygen(&p);
    let (ct, _ss) = mlkem::encaps(&p, &pk);
    b.iter(|| mlkem::decaps(&p, &sk, &ct));
}

#[bench]
fn pipeline_pack_plain_1mb(b: &mut Bencher) {
    let data = sample_data(1 << 20);
    b.iter(|| pack(&data, &config(Encryption::None, true)).unwrap());
}

#[bench]
fn pipeline_unpack_plain_1mb(b: &mut Bencher) {
    let data = sample_data(1 << 20);
    let packed = pack(&data, &config(Encryption::None, true)).unwrap();
    b.iter(|| unpack(&packed, DecryptKey::None).unwrap());
}

#[bench]
fn pipeline_pack_encrypted_1mb(b: &mut Bencher) {
    let data = sample_data(1 << 20);
    let (pk, _sk) = mlkem::keygen(&mlkem::MLKEM768);
    b.iter(|| {
        pack(
            &data,
            &config(
                Encryption::Kem {
                    kem: KemParams::MlKem768,
                    recipient_pk: &pk,
                },
                true,
            ),
        )
        .unwrap()
    });
}

#[bench]
fn pipeline_unpack_encrypted_1mb(b: &mut Bencher) {
    let data = sample_data(1 << 20);
    let (pk, sk) = mlkem::keygen(&mlkem::MLKEM768);
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
    b.iter(|| unpack(&packed, DecryptKey::PrivateKey(&sk)).unwrap());
}
