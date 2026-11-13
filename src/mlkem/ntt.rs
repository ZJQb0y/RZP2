//! 数论变换（NTT）与模运算。

use crate::mlkem::params::Q;

/// NTT 常数（与参考实现一致）。
pub const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246,
    778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
    603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
    -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

/// Montgomery 归约：返回 `a * R^{-1} mod q`（R = 2^16）。
#[inline]
pub fn montgomery_reduce(a: i32) -> i16 {
    const QINV: i32 = -3327; // q^-1 mod 2^16
    let t = ((a as i16) as i32 * QINV) as i16;
    let t = (a - t as i32 * Q) >> 16;
    t as i16
}

/// Barrett 归约：返回 a 在 `{-(q-1)/2, ..., (q-1)/2}` 中的中心代表。
#[inline]
pub fn barrett_reduce(a: i16) -> i16 {
    const V: i16 = (((1i32 << 26) + Q / 2) / Q) as i16;
    let t = ((V as i32 * a as i32 + (1i32 << 25)) >> 26) as i16;
    let t = t.wrapping_mul(Q as i16);
    a.wrapping_sub(t)
}

/// 模乘（Montgomery 域）。
#[inline]
pub fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce(a as i32 * b as i32)
}

/// 正向 NTT（输入正常序，输出位逆序）。
pub fn ntt(r: &mut [i16; 256]) {
    let mut k = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = ZETAS[k];
            k += 1;
            let end = start + len;
            for j in start..end {
                let t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;
            }
            start = end + len;
        }
        len >>= 1;
    }
}

/// 逆 NTT（输入位逆序，输出正常序，并乘以 Montgomery 因子）。
pub fn invntt(r: &mut [i16; 256]) {
    const F: i16 = 1441; // mont^2/128

    let mut k = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = ZETAS[k];
            k = k.wrapping_sub(1);
            let end = start + len;
            for j in start..end {
                let t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = r[j + len] - t;
                r[j + len] = fqmul(zeta, r[j + len]);
            }
            start = end + len;
        }
        len <<= 1;
    }

    for x in r.iter_mut() {
        *x = fqmul(*x, F);
    }
}

/// 基乘法（两个 NTT 域多项式 2×2 块相乘）。
pub fn basemul(r: &mut [i16], a: &[i16], b: &[i16], zeta: i16) {
    r[0] = fqmul(a[1], b[1]);
    r[0] = fqmul(r[0], zeta);
    r[0] += fqmul(a[0], b[0]);
    r[1] = fqmul(a[0], b[1]);
    r[1] += fqmul(a[1], b[0]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn montgomery_and_barrett() {
        // 基本往返性质。
        for &a in &[0i16, 1, 1234, 3328, -1, -1664, 1664, 999] {
            let r = barrett_reduce(a);
            assert!(r as i32 >= -(Q / 2) && r as i32 <= Q / 2);
            // r ≡ a (mod q)
            let diff = (a as i32 - r as i32).rem_euclid(Q);
            assert_eq!(diff, 0);
        }
    }

    #[test]
    fn ntt_invntt_roundtrip() {
        // invntt 内含 Montgomery 因子：invntt(ntt(a)) == tomont(a) = a * 2^16 (mod q)。
        let mut a = [0i16; 256];
        for (i, x) in a.iter_mut().enumerate() {
            *x = (((i as i32 * 7) % 3329) - 1664) as i16;
        }
        let mut b = a;
        ntt(&mut b);
        invntt(&mut b);
        const F: i32 = ((1u64 << 32) % Q as u64) as i32; // 1353 = 2^32 mod q
        for i in 0..256 {
            let expected = montgomery_reduce(a[i] as i32 * F);
            assert_eq!(barrett_reduce(b[i]), barrett_reduce(expected));
        }
    }
}
