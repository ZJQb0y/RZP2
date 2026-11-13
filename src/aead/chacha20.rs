//! ChaCha20 流密码（RFC 8439）。

const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

fn u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().unwrap())
}

/// 生成一个 ChaCha20 块（64 字节）。
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0..4].copy_from_slice(&CONSTANTS);
    for i in 0..8 {
        state[4 + i] = u32_le(&key[4 * i..4 * i + 4]);
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32_le(&nonce[4 * i..4 * i + 4]);
    }

    let mut working = state;
    for _ in 0..10 {
        // 列轮。
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        // 对角线轮。
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let v = working[i].wrapping_add(state[i]);
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

/// 用从 `counter` 开始的密钥流对 `data` 原地异或。
pub fn chacha20_xor(data: &mut [u8], key: &[u8; 32], mut counter: u32, nonce: &[u8; 12]) {
    // 有 AVX2 时走 4 路并行快路径（运行时检测，标量兜底）。
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: 已通过 `is_x86_feature_detected!` 确认 CPU 支持 AVX2。
            unsafe {
                chacha20_xor_avx2(data, key, counter, nonce);
            }
            return;
        }
    }

    // aarch64 上走 NEON 4 路并行快路径。
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            // SAFETY: NEON 是 aarch64 基线特性，且已运行时检测确认。
            unsafe {
                chacha20_xor_neon(data, key, counter, nonce);
            }
            return;
        }
    }

    let mut pos = 0usize;
    while pos < data.len() {
        let block = chacha20_block(key, counter, nonce);
        let n = (data.len() - pos).min(64);
        for i in 0..n {
            data[pos + i] ^= block[i];
        }
        pos += n;
        counter += 1;
    }
}

/// AVX2 4 路并行：一次生成 `counter..counter+3` 四个块（256 字节）的密钥流。
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn chacha20_blocks4(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 256] {
    use std::arch::x86_64::*;

    // 移位量必须是立即数，因此用宏展开为字面量。
    macro_rules! rotl {
        ($v:expr, $n:expr) => {{
            let left = _mm256_slli_epi32($v, $n);
            let right = _mm256_srli_epi32($v, 32 - $n);
            _mm256_or_si256(left, right)
        }};
    }

    #[inline]
    unsafe fn qr(x: &mut [__m256i; 16], a: usize, b: usize, c: usize, d: usize) {
        x[a] = _mm256_add_epi32(x[a], x[b]);
        x[d] = _mm256_xor_si256(x[d], x[a]);
        x[d] = rotl!(x[d], 16);
        x[c] = _mm256_add_epi32(x[c], x[d]);
        x[b] = _mm256_xor_si256(x[b], x[c]);
        x[b] = rotl!(x[b], 12);
        x[a] = _mm256_add_epi32(x[a], x[b]);
        x[d] = _mm256_xor_si256(x[d], x[a]);
        x[d] = rotl!(x[d], 8);
        x[c] = _mm256_add_epi32(x[c], x[d]);
        x[b] = _mm256_xor_si256(x[b], x[c]);
        x[b] = rotl!(x[b], 7);
    }

    // 布局：`x[i]` 的 4 个 lane 分别对应 4 个 block 的第 i 个字（转置布局）。
    let mut init = [_mm256_setzero_si256(); 16];
    for i in 0..4 {
        init[i] = _mm256_set1_epi32(CONSTANTS[i] as i32);
    }
    for i in 0..8 {
        let w = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
        init[4 + i] = _mm256_set1_epi32(w as i32);
    }
    // 4 个计数器分别放入 lane0..3：低 32 位为偶数 lane，高 32 位为奇数 lane。
    let q0 = (counter as u64) | ((counter.wrapping_add(1) as u64) << 32);
    let q1 = (counter.wrapping_add(2) as u64) | ((counter.wrapping_add(3) as u64) << 32);
    init[12] = _mm256_setr_epi64x(q0 as i64, q1 as i64, 0, 0);
    for i in 0..3 {
        let w = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
        init[13 + i] = _mm256_set1_epi32(w as i32);
    }

    let mut x = init;
    for _ in 0..10 {
        qr(&mut x, 0, 4, 8, 12);
        qr(&mut x, 1, 5, 9, 13);
        qr(&mut x, 2, 6, 10, 14);
        qr(&mut x, 3, 7, 11, 15);
        qr(&mut x, 0, 5, 10, 15);
        qr(&mut x, 1, 6, 11, 12);
        qr(&mut x, 2, 7, 8, 13);
        qr(&mut x, 3, 4, 9, 14);
    }
    for i in 0..16 {
        x[i] = _mm256_add_epi32(x[i], init[i]);
    }

    // 转置：`x[i].lane(j)` 是 block j 的第 i 个字，重组为 4 个 block 的连续 64 字节。
    // 仅低 128 位（4 个 u32 lane）承载 4 个 block，故用 128 位 store 取低半部分，
    // 避免把 256 位写满 8 lane 造成越界。
    let mut tmp = [0u32; 64];
    for i in 0..16 {
        _mm_storeu_si128(
            tmp.as_mut_ptr().add(i * 4) as *mut __m128i,
            _mm256_castsi256_si128(x[i]),
        );
    }
    let mut out = [0u8; 256];
    for j in 0..4 {
        for i in 0..16 {
            let w = tmp[i * 4 + j];
            out[j * 64 + i * 4..j * 64 + i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
    }
    out
}

/// AVX2 快路径：整块用 4 路并行，尾部用标量补齐。
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn chacha20_xor_avx2(data: &mut [u8], key: &[u8; 32], mut counter: u32, nonce: &[u8; 12]) {
    let mut pos = 0usize;
    while pos + 256 <= data.len() {
        let blocks = chacha20_blocks4(key, counter, nonce);
        for i in 0..256 {
            data[pos + i] ^= blocks[i];
        }
        pos += 256;
        counter += 4;
    }
    while pos < data.len() {
        let block = chacha20_block(key, counter, nonce);
        let n = (data.len() - pos).min(64);
        for i in 0..n {
            data[pos + i] ^= block[i];
        }
        pos += n;
        counter += 1;
    }
}

/// NEON 4 路并行：一次生成 `counter..counter+3` 四个块（256 字节）的密钥流。
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn chacha20_blocks4_neon(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 256] {
    use std::arch::aarch64::*;

    // 移位量必须是立即数，因此用宏展开为字面量。
    macro_rules! rotl {
        ($v:expr, $n:expr) => {{
            vorrq_u32(vshlq_n_u32($v, $n), vshrq_n_u32($v, 32 - $n))
        }};
    }

    #[inline]
    unsafe fn qr(x: &mut [uint32x4_t; 16], a: usize, b: usize, c: usize, d: usize) {
        x[a] = vaddq_u32(x[a], x[b]);
        x[d] = veorq_u32(x[d], x[a]);
        x[d] = rotl!(x[d], 16);
        x[c] = vaddq_u32(x[c], x[d]);
        x[b] = veorq_u32(x[b], x[c]);
        x[b] = rotl!(x[b], 12);
        x[a] = vaddq_u32(x[a], x[b]);
        x[d] = veorq_u32(x[d], x[a]);
        x[d] = rotl!(x[d], 8);
        x[c] = vaddq_u32(x[c], x[d]);
        x[b] = veorq_u32(x[b], x[c]);
        x[b] = rotl!(x[b], 7);
    }

    // 布局：`x[i]` 的 4 个 lane 分别对应 4 个 block 的第 i 个字（转置布局）。
    let mut init = [vdupq_n_u32(0); 16];
    for i in 0..4 {
        init[i] = vdupq_n_u32(CONSTANTS[i]);
    }
    for i in 0..8 {
        let w = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
        init[4 + i] = vdupq_n_u32(w);
    }
    let counters = [
        counter,
        counter.wrapping_add(1),
        counter.wrapping_add(2),
        counter.wrapping_add(3),
    ];
    init[12] = vld1q_u32(counters.as_ptr());
    for i in 0..3 {
        let w = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
        init[13 + i] = vdupq_n_u32(w);
    }

    let mut x = init;
    for _ in 0..10 {
        qr(&mut x, 0, 4, 8, 12);
        qr(&mut x, 1, 5, 9, 13);
        qr(&mut x, 2, 6, 10, 14);
        qr(&mut x, 3, 7, 11, 15);
        qr(&mut x, 0, 5, 10, 15);
        qr(&mut x, 1, 6, 11, 12);
        qr(&mut x, 2, 7, 8, 13);
        qr(&mut x, 3, 4, 9, 14);
    }
    for i in 0..16 {
        x[i] = vaddq_u32(x[i], init[i]);
    }

    // 转置：`x[i].lane(j)` 是 block j 的第 i 个字，重组为 4 个 block 的连续 64 字节。
    let mut tmp = [0u32; 64];
    for i in 0..16 {
        vst1q_u32(tmp.as_mut_ptr().add(i * 4), x[i]);
    }
    let mut out = [0u8; 256];
    for j in 0..4 {
        for i in 0..16 {
            let w = tmp[i * 4 + j];
            out[j * 64 + i * 4..j * 64 + i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
    }
    out
}

/// NEON 快路径：整块用 4 路并行，尾部用标量补齐。
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn chacha20_xor_neon(data: &mut [u8], key: &[u8; 32], mut counter: u32, nonce: &[u8; 12]) {
    let mut pos = 0usize;
    while pos + 256 <= data.len() {
        let blocks = chacha20_blocks4_neon(key, counter, nonce);
        for i in 0..256 {
            data[pos + i] ^= blocks[i];
        }
        pos += 256;
        counter += 4;
    }
    while pos < data.len() {
        let block = chacha20_block(key, counter, nonce);
        let n = (data.len() - pos).min(64);
        for i in 0..n {
            data[pos + i] ^= block[i];
        }
        pos += n;
        counter += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_known_vector() {
        // RFC 8439 §2.3.2 测试向量。
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let expected = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];
        let block = chacha20_block(&key, 1, &nonce);
        assert_eq!(&block[..], &expected[..]);
    }

    #[test]
    fn xor_matches_scalar_reference() {
        // 长度跨越多块边界（> 256 字节）以触发 SIMD 4 路快路径，并与标量参考对照。
        let key = [0x7eu8; 32];
        let nonce = [0x11u8; 12];
        let mut data: Vec<u8> = (0..1000u32).map(|i| (i % 256) as u8).collect();

        let expected = {
            let mut d = data.clone();
            let mut counter = 1u32;
            let mut pos = 0usize;
            while pos < d.len() {
                let block = chacha20_block(&key, counter, &nonce);
                let n = (d.len() - pos).min(64);
                for i in 0..n {
                    d[pos + i] ^= block[i];
                }
                pos += n;
                counter += 1;
            }
            d
        };

        chacha20_xor(&mut data, &key, 1, &nonce);
        assert_eq!(data, expected);
    }
}
