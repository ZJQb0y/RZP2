//! Poly1305 消息认证码（RFC 8439，26-bit 肢体实现）。

/// 计算 Poly1305 MAC，返回 16 字节标签。
pub fn poly1305(mac_key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    // 解析并钳制 r。
    let mut rb = [0u8; 16];
    rb.copy_from_slice(&mac_key[..16]);
    rb[3] &= 15;
    rb[7] &= 15;
    rb[11] &= 15;
    rb[15] &= 15;
    rb[4] &= 252;
    rb[8] &= 252;
    rb[12] &= 252;
    let r128 = u128::from_le_bytes(rb);
    let r0 = (r128 & 0x3ff_ffff) as u64;
    let r1 = ((r128 >> 26) & 0x3ff_ffff) as u64;
    let r2 = ((r128 >> 52) & 0x3ff_ffff) as u64;
    let r3 = ((r128 >> 78) & 0x3ff_ffff) as u64;
    let r4 = ((r128 >> 104) & 0xff_ffff) as u64;
    // s_i = r_i * 5（用于 2^130 ≡ 5 的折叠）。
    let s1 = r1.wrapping_mul(5);
    let s2 = r2.wrapping_mul(5);
    let s3 = r3.wrapping_mul(5);
    let s4 = r4.wrapping_mul(5);

    let mut h0 = 0u64;
    let mut h1 = 0u64;
    let mut h2 = 0u64;
    let mut h3 = 0u64;
    let mut h4 = 0u64;

    let mut chunks = msg.chunks_exact(16);
    for block in &mut chunks {
        let m = u128::from_le_bytes(block.try_into().unwrap());
        // h += m || 0x01（完整块追加 0x01，即 bit 128）。
        h0 = h0.wrapping_add((m & 0x3ff_ffff) as u64);
        h1 = h1.wrapping_add(((m >> 26) & 0x3ff_ffff) as u64);
        h2 = h2.wrapping_add(((m >> 52) & 0x3ff_ffff) as u64);
        h3 = h3.wrapping_add(((m >> 78) & 0x3ff_ffff) as u64);
        h4 = h4.wrapping_add((((m >> 104) | (1u128 << 24)) & 0x1ff_ffff) as u64);
        poly1305_mul(
            &mut h0, &mut h1, &mut h2, &mut h3, &mut h4, r0, r1, r2, r3, r4, s1, s2, s3, s4,
        );
    }

    let rem = chunks.remainder();
    if !rem.is_empty() {
        let len = rem.len();
        let mut m = 0u128;
        for (i, &b) in rem.iter().enumerate() {
            m |= (b as u128) << (8 * i);
        }
        m |= 1u128 << (8 * len);
        h0 = h0.wrapping_add((m & 0x3ff_ffff) as u64);
        h1 = h1.wrapping_add(((m >> 26) & 0x3ff_ffff) as u64);
        h2 = h2.wrapping_add(((m >> 52) & 0x3ff_ffff) as u64);
        h3 = h3.wrapping_add(((m >> 78) & 0x3ff_ffff) as u64);
        h4 = h4.wrapping_add(((m >> 104) & 0x1ff_ffff) as u64);
        poly1305_mul(
            &mut h0, &mut h1, &mut h2, &mut h3, &mut h4, r0, r1, r2, r3, r4, s1, s2, s3, s4,
        );
    }

    // 完全进位。
    let mut c = h1 >> 26;
    h1 &= 0x3ff_ffff;
    h2 = h2.wrapping_add(c);
    c = h2 >> 26;
    h2 &= 0x3ff_ffff;
    h3 = h3.wrapping_add(c);
    c = h3 >> 26;
    h3 &= 0x3ff_ffff;
    h4 = h4.wrapping_add(c);
    c = h4 >> 26;
    h4 &= 0x3ff_ffff;
    h0 = h0.wrapping_add(c.wrapping_mul(5));
    c = h0 >> 26;
    h0 &= 0x3ff_ffff;
    h1 = h1.wrapping_add(c);

    // 若 h >= p，则 h -= p（通过 g = h + 5 检测溢出）。
    let g0 = h0.wrapping_add(5);
    c = g0 >> 26;
    let g0 = g0 & 0x3ff_ffff;
    let g1 = h1.wrapping_add(c);
    c = g1 >> 26;
    let g1 = g1 & 0x3ff_ffff;
    let g2 = h2.wrapping_add(c);
    c = g2 >> 26;
    let g2 = g2 & 0x3ff_ffff;
    let g3 = h3.wrapping_add(c);
    c = g3 >> 26;
    let g3 = g3 & 0x3ff_ffff;
    let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);
    // g4 为负（高位为 1）表示 h < p，保留 h。
    let mask = (g4 as i64 >> 63) as u64;
    h0 = (h0 & mask) | (g0 & !mask);
    h1 = (h1 & mask) | (g1 & !mask);
    h2 = (h2 & mask) | (g2 & !mask);
    h3 = (h3 & mask) | (g3 & !mask);
    h4 = (h4 & mask) | (g4 & !mask);

    // h += s（128-bit 填充）。
    let s128 = u128::from_le_bytes(mac_key[16..].try_into().unwrap());
    h0 = h0.wrapping_add((s128 & 0x3ff_ffff) as u64);
    h1 = h1.wrapping_add(((s128 >> 26) & 0x3ff_ffff) as u64);
    h2 = h2.wrapping_add(((s128 >> 52) & 0x3ff_ffff) as u64);
    h3 = h3.wrapping_add(((s128 >> 78) & 0x3ff_ffff) as u64);
    h4 = h4.wrapping_add(((s128 >> 104) & 0xff_ffff) as u64);

    // 再次进位。
    c = h1 >> 26;
    h1 &= 0x3ff_ffff;
    h2 = h2.wrapping_add(c);
    c = h2 >> 26;
    h2 &= 0x3ff_ffff;
    h3 = h3.wrapping_add(c);
    c = h3 >> 26;
    h3 &= 0x3ff_ffff;
    h4 = h4.wrapping_add(c);
    c = h4 >> 26;
    h4 &= 0x3ff_ffff;
    h0 = h0.wrapping_add(c.wrapping_mul(5));
    c = h0 >> 26;
    h0 &= 0x3ff_ffff;
    h1 = h1.wrapping_add(c);

    // 输出 h mod 2^128。
    let result = (h0 as u128)
        | ((h1 as u128) << 26)
        | ((h2 as u128) << 52)
        | ((h3 as u128) << 78)
        | (((h4 & 0xff_ffff) as u128) << 104);
    result.to_le_bytes()
}

#[allow(clippy::too_many_arguments)]
#[inline]
fn poly1305_mul_scalar(
    h0: &mut u64,
    h1: &mut u64,
    h2: &mut u64,
    h3: &mut u64,
    h4: &mut u64,
    r0: u64,
    r1: u64,
    r2: u64,
    r3: u64,
    r4: u64,
    s1: u64,
    s2: u64,
    s3: u64,
    s4: u64,
) {
    let d0 = h0
        .wrapping_mul(r0)
        .wrapping_add(h1.wrapping_mul(s4))
        .wrapping_add(h2.wrapping_mul(s3))
        .wrapping_add(h3.wrapping_mul(s2))
        .wrapping_add(h4.wrapping_mul(s1));
    let d1 = h0
        .wrapping_mul(r1)
        .wrapping_add(h1.wrapping_mul(r0))
        .wrapping_add(h2.wrapping_mul(s4))
        .wrapping_add(h3.wrapping_mul(s3))
        .wrapping_add(h4.wrapping_mul(s2));
    let d2 = h0
        .wrapping_mul(r2)
        .wrapping_add(h1.wrapping_mul(r1))
        .wrapping_add(h2.wrapping_mul(r0))
        .wrapping_add(h3.wrapping_mul(s4))
        .wrapping_add(h4.wrapping_mul(s3));
    let d3 = h0
        .wrapping_mul(r3)
        .wrapping_add(h1.wrapping_mul(r2))
        .wrapping_add(h2.wrapping_mul(r1))
        .wrapping_add(h3.wrapping_mul(r0))
        .wrapping_add(h4.wrapping_mul(s4));
    let d4 = h0
        .wrapping_mul(r4)
        .wrapping_add(h1.wrapping_mul(r3))
        .wrapping_add(h2.wrapping_mul(r2))
        .wrapping_add(h3.wrapping_mul(r1))
        .wrapping_add(h4.wrapping_mul(r0));

    let mut c = d0 >> 26;
    *h0 = d0 & 0x3ff_ffff;
    let d1 = d1.wrapping_add(c);
    c = d1 >> 26;
    *h1 = d1 & 0x3ff_ffff;
    let d2 = d2.wrapping_add(c);
    c = d2 >> 26;
    *h2 = d2 & 0x3ff_ffff;
    let d3 = d3.wrapping_add(c);
    c = d3 >> 26;
    *h3 = d3 & 0x3ff_ffff;
    let d4 = d4.wrapping_add(c);
    c = d4 >> 26;
    *h4 = d4 & 0x3ff_ffff;
    *h0 = h0.wrapping_add(c.wrapping_mul(5));
    c = *h0 >> 26;
    *h0 &= 0x3ff_ffff;
    *h1 = h1.wrapping_add(c);
}

/// 运行时选择 Poly1305 乘法实现：aarch64 上优先走 NEON，其余回退标量。
#[allow(clippy::too_many_arguments)]
#[inline]
fn poly1305_mul(
    h0: &mut u64,
    h1: &mut u64,
    h2: &mut u64,
    h3: &mut u64,
    h4: &mut u64,
    r0: u64,
    r1: u64,
    r2: u64,
    r3: u64,
    r4: u64,
    s1: u64,
    s2: u64,
    s3: u64,
    s4: u64,
) {
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            // SAFETY: 已通过运行时检测确认 NEON 可用。
            unsafe {
                poly1305_mul_neon(h0, h1, h2, h3, h4, r0, r1, r2, r3, r4, s1, s2, s3, s4);
            }
            return;
        }
    }
    poly1305_mul_scalar(h0, h1, h2, h3, h4, r0, r1, r2, r3, r4, s1, s2, s3, s4);
}

/// NEON 快路径：把 5 个 26-bit 肢体的乘加用 `vmlal_u32`（32×32→64）并行完成。
///
/// 与标量版逐位等价：d0/d1、d2/d3 各用一对 64-bit lane 累加，d4 单肢体标量计算，
/// 进位逻辑与 [`poly1305_mul_scalar`] 完全一致。
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn poly1305_mul_neon(
    h0: &mut u64,
    h1: &mut u64,
    h2: &mut u64,
    h3: &mut u64,
    h4: &mut u64,
    r0: u64,
    r1: u64,
    r2: u64,
    r3: u64,
    r4: u64,
    s1: u64,
    s2: u64,
    s3: u64,
    s4: u64,
) {
    use std::arch::aarch64::*;

    // 肢体（≤27 位）与系数（≤29 位）均可无损放进 32 位 lane。
    let h0v = *h0 as u32;
    let h1v = *h1 as u32;
    let h2v = *h2 as u32;
    let h3v = *h3 as u32;
    let h4v = *h4 as u32;
    let r0v = r0 as u32;
    let r1v = r1 as u32;
    let r2v = r2 as u32;
    let r3v = r3 as u32;
    let s1v = s1 as u32;
    let s2v = s2 as u32;
    let s3v = s3 as u32;
    let s4v = s4 as u32;

    // d0（lane0）与 d1（lane1）并行累加。
    let mut d01 = vdupq_n_u64(0);
    d01 = vmlal_u32(
        d01,
        vdup_n_u32(h0v),
        vcreate_u32((r0v as u64) | ((r1v as u64) << 32)),
    );
    d01 = vmlal_u32(
        d01,
        vdup_n_u32(h1v),
        vcreate_u32((s4v as u64) | ((r0v as u64) << 32)),
    );
    d01 = vmlal_u32(
        d01,
        vdup_n_u32(h2v),
        vcreate_u32((s3v as u64) | ((s4v as u64) << 32)),
    );
    d01 = vmlal_u32(
        d01,
        vdup_n_u32(h3v),
        vcreate_u32((s2v as u64) | ((s3v as u64) << 32)),
    );
    d01 = vmlal_u32(
        d01,
        vdup_n_u32(h4v),
        vcreate_u32((s1v as u64) | ((s2v as u64) << 32)),
    );

    // d2（lane0）与 d3（lane1）并行累加。
    let mut d23 = vdupq_n_u64(0);
    d23 = vmlal_u32(
        d23,
        vdup_n_u32(h0v),
        vcreate_u32((r2v as u64) | ((r3v as u64) << 32)),
    );
    d23 = vmlal_u32(
        d23,
        vdup_n_u32(h1v),
        vcreate_u32((r1v as u64) | ((r2v as u64) << 32)),
    );
    d23 = vmlal_u32(
        d23,
        vdup_n_u32(h2v),
        vcreate_u32((r0v as u64) | ((r1v as u64) << 32)),
    );
    d23 = vmlal_u32(
        d23,
        vdup_n_u32(h3v),
        vcreate_u32((s4v as u64) | ((r0v as u64) << 32)),
    );
    d23 = vmlal_u32(
        d23,
        vdup_n_u32(h4v),
        vcreate_u32((s3v as u64) | ((s4v as u64) << 32)),
    );

    let d0 = vgetq_lane_u64::<0>(d01);
    let d1 = vgetq_lane_u64::<1>(d01);
    let d2 = vgetq_lane_u64::<0>(d23);
    let d3 = vgetq_lane_u64::<1>(d23);

    // d4 单肢体，无需并行。
    let d4 = (*h0 as u64)
        .wrapping_mul(r4)
        .wrapping_add((*h1 as u64).wrapping_mul(r3))
        .wrapping_add((*h2 as u64).wrapping_mul(r2))
        .wrapping_add((*h3 as u64).wrapping_mul(r1))
        .wrapping_add((*h4 as u64).wrapping_mul(r0));

    // 完全进位，与标量版一致。
    let mut c = d0 >> 26;
    *h0 = d0 & 0x3ff_ffff;
    let d1 = d1.wrapping_add(c);
    c = d1 >> 26;
    *h1 = d1 & 0x3ff_ffff;
    let d2 = d2.wrapping_add(c);
    c = d2 >> 26;
    *h2 = d2 & 0x3ff_ffff;
    let d3 = d3.wrapping_add(c);
    c = d3 >> 26;
    *h3 = d3 & 0x3ff_ffff;
    let d4 = d4.wrapping_add(c);
    c = d4 >> 26;
    *h4 = d4 & 0x3ff_ffff;
    *h0 = h0.wrapping_add(c.wrapping_mul(5));
    c = *h0 >> 26;
    *h0 &= 0x3ff_ffff;
    *h1 = h1.wrapping_add(c);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8439_poly1305_vector() {
        // RFC 8439 §2.5.2：一次性密钥。
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";
        let tag = poly1305(&key, msg);
        let expected: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];
        assert_eq!(tag, expected);
    }

    /// 在 aarch64 上直接对照 NEON 乘法与标量乘法是否逐位一致。
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn mul_neon_matches_scalar() {
        if !std::arch::is_aarch64_feature_detected!("neon") {
            return;
        }
        let mut ha = [0u64; 5];
        let mut hb = [0u64; 5];
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..1000 {
            let mut next = || {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                seed >> 32
            };
            let r0 = next() & 0x3ff_ffff;
            let r1 = next() & 0x3ff_ffff;
            let r2 = next() & 0x3ff_ffff;
            let r3 = next() & 0x3ff_ffff;
            let r4 = next() & 0x3ff_ffff;
            let s1 = r1.wrapping_mul(5);
            let s2 = r2.wrapping_mul(5);
            let s3 = r3.wrapping_mul(5);
            let s4 = r4.wrapping_mul(5);
            for i in 0..5 {
                // 肢体输入覆盖到 27 位（消息累加后的边界）。
                ha[i] = next() & 0x7ff_ffff;
                hb[i] = ha[i];
            }
            let [ha0, ha1, ha2, ha3, ha4] = &mut ha;
            let [hb0, hb1, hb2, hb3, hb4] = &mut hb;
            unsafe {
                poly1305_mul_neon(ha0, ha1, ha2, ha3, ha4, r0, r1, r2, r3, r4, s1, s2, s3, s4);
            }
            poly1305_mul_scalar(hb0, hb1, hb2, hb3, hb4, r0, r1, r2, r3, r4, s1, s2, s3, s4);
            assert_eq!(ha, hb);
        }
    }
}
