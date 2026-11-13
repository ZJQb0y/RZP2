//! LZMA 编解码器集成测试。

use rzp2::lzma::{decode, encode, LzmaParams};

fn roundtrip(data: &[u8], params: &LzmaParams) {
    let compressed = encode(data, params);
    let decompressed = decode(&compressed).expect("decode failed");
    assert_eq!(decompressed, data, "roundtrip mismatch");
}

#[test]
fn empty_input() {
    roundtrip(b"", &LzmaParams::default());
}

#[test]
fn single_byte() {
    roundtrip(b"a", &LzmaParams::default());
}

#[test]
fn small_text() {
    roundtrip(b"hello world", &LzmaParams::default());
}

#[test]
fn repeated_data_compresses() {
    let data = vec![b'A'; 100_000];
    let params = LzmaParams::new(3, 0, 2, 1 << 16);
    let compressed = encode(&data, &params);
    assert!(
        compressed.len() < data.len() / 10,
        "repeated data should compress well: {} -> {}",
        data.len(),
        compressed.len()
    );
    let decompressed = decode(&compressed).unwrap();
    assert_eq!(decompressed, data);
}

#[test]
fn random_data_roundtrip() {
    // 伪随机数据（无重复，压缩率低但必须能往返）。
    let mut data = Vec::with_capacity(64 * 1024);
    let mut x = 0x12345678u32;
    for _ in 0..(64 * 1024) {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        data.push((x >> 24) as u8);
    }
    roundtrip(&data, &LzmaParams::new(3, 0, 2, 1 << 18));
}

#[test]
fn text_roundtrip() {
    let text = b"The quick brown fox jumps over the lazy dog. ".repeat(1000);
    roundtrip(&text, &LzmaParams::new(3, 0, 2, 1 << 16));
}

#[test]
fn various_parameters() {
    let data = b"abcabcabcabc".repeat(200);
    for lc in [0u32, 3, 4] {
        for lp in [0u32, 1, 2] {
            for pb in [0u32, 2, 4] {
                roundtrip(&data, &LzmaParams::new(lc, lp, pb, 1 << 16));
            }
        }
    }
}

#[test]
fn overlapping_matches() {
    // 制造重叠匹配（如 aaaaa... 中远距离重复）。
    let data = b"aaaaaaaaaa".repeat(5000);
    roundtrip(&data, &LzmaParams::new(3, 0, 2, 1 << 16));
}

#[test]
fn decode_truncated_errors() {
    let data = b"some data to compress".repeat(100);
    let compressed = encode(&data, &LzmaParams::default());
    // 截断后的流要么出错，要么不能静默产生错误数据；这里只验证不 panic。
    let _ = decode(&compressed[..compressed.len() / 2]);
}

#[test]
fn xz_cross_validation() {
    use std::process::Command;
    // 若 xz 不可用则跳过。
    if Command::new("xz").arg("--version").output().is_err() {
        eprintln!("skipping: xz not available");
        return;
    }
    let dir = std::env::temp_dir();
    let orig = dir.join("rzp2_lzma_xz_orig.bin");
    let ours = dir.join("rzp2_lzma_ours.lzma");

    // 生成一段可压缩 + 随机混合数据。
    let mut data = Vec::new();
    data.extend_from_slice(&b"the quick brown fox jumps over the lazy dog\n".repeat(2000));
    let mut x = 0x9E3779B9u32;
    for _ in 0..4096 {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        data.push((x >> 24) as u8);
    }
    std::fs::write(&orig, &data).unwrap();

    // 我们的编码器 -> xz 解码。
    let compressed = rzp2::lzma::encode(&data, &rzp2::lzma::LzmaParams::new(3, 0, 2, 1 << 20));
    std::fs::write(&ours, &compressed).unwrap();
    let out = Command::new("xz")
        .args(["-dc", "--format=lzma"])
        .arg(&ours)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "xz decode failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, data);

    // xz 编码 -> 我们的解码器。
    let xz_out = Command::new("xz")
        .args(["-c", "--format=lzma"])
        .arg(&orig)
        .output()
        .unwrap();
    assert!(xz_out.status.success());
    let decoded = rzp2::lzma::decode(&xz_out.stdout).expect("decode of xz stream");
    assert_eq!(decoded, data);
}
