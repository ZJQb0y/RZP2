//! X25519（RFC 7748）密钥交换，从零实现。
//!
//! 基于 Curve25519 蒙哥马利曲线 `v^2 = u^3 + 486662*u^2 + u`（模 `2^255 - 19`），
//! 实现标量乘法 [`x25519`]，用于经典 ECDH 密钥协商。本模块刻意与规范保持一致，
//! 便于逐行审计：
//! - 域运算采用 5×51 位小端 limb 表示，模数 `p = 2^255 - 19`（`2^255 ≡ 19`）。
//! - 标量乘按 RFC 7748 第 5 节的蒙哥马利梯子（`a24 = 121665`）实现。
//! - 求逆用 `a^(p-2)`（费马小定理），指数为公开常量 `2^255 - 21`。

/// 标量 / 公钥 / 共享密钥均为 32 字节（小端）。
pub const X25519_BYTES: usize = 32;

/// Curve25519 基点：`u = 9`。
pub const BASE_POINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// 单个 51 位 limb 掩码（`2^51 - 1`）。
const MASK51: u64 = 0x0007_FFFF_FFFF_FFFF;

/// 模数 `p = 2^255 - 19`，5×51 位小端 limb。
const P: [u64; 5] = [
    0x0007_FFFF_FFFF_FFED, // 2^51 - 19
    0x0007_FFFF_FFFF_FFFF, // 2^51 - 1
    0x0007_FFFF_FFFF_FFFF,
    0x0007_FFFF_FFFF_FFFF,
    0x0007_FFFF_FFFF_FFFF,
];

/// 域元素（GF(2^255 - 19)），规范表示：每个 limb `< 2^51` 且值 `< p`。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Fe([u64; 5]);

const FE_ZERO: Fe = Fe([0, 0, 0, 0, 0]);
const FE_ONE: Fe = Fe([1, 0, 0, 0, 0]);
/// `a24 = (486662 - 2) / 4 = 121665`。
const FE_A24: Fe = Fe([121665, 0, 0, 0, 0]);

/// 多 limb 减法，返回 `(差, 借位)`；借位为 1 表示 `a < b`。
fn sub_borrow(a: [u64; 5], b: [u64; 5]) -> ([u64; 5], u8) {
    let mut out = [0u64; 5];
    let mut borrow = 0u64;
    for i in 0..5 {
        let (v1, b1) = a[i].overflowing_sub(b[i]);
        let (v2, b2) = v1.overflowing_sub(borrow);
        out[i] = v2;
        borrow = u64::from(b1) | u64::from(b2);
    }
    (out, borrow as u8)
}

/// 把（松弛的）5 个 `u128` limb 规范化为域元素：前向进位 + `2^255 ≡ 19` 折叠，
/// 最后条件减 `p` 得到 `< p` 的规范值。
fn normalize(mut r: [u128; 5]) -> Fe {
    // 3 轮前向进位 + 折叠足以让所有 limb `< 2^51`（对 mul/add/sub 的输入界成立）。
    for _ in 0..3 {
        let mut carry: u128 = 0;
        for i in 0..5 {
            let v = r[i] + carry;
            r[i] = v & (MASK51 as u128);
            carry = v >> 51;
        }
        r[0] += carry * 19;
    }

    let mut limbs = [0u64; 5];
    for i in 0..5 {
        limbs[i] = r[i] as u64;
    }
    let (sub, borrow) = sub_borrow(limbs, P);
    if borrow == 0 {
        limbs = sub;
    }
    Fe(limbs)
}

/// 域乘法：5×5 schoolbook，并用 `2^255 ≡ 19` 折叠高 limb。
fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let a0 = a.0[0] as u128;
    let a1 = a.0[1] as u128;
    let a2 = a.0[2] as u128;
    let a3 = a.0[3] as u128;
    let a4 = a.0[4] as u128;
    let b0 = b.0[0] as u128;
    let b1 = b.0[1] as u128;
    let b2 = b.0[2] as u128;
    let b3 = b.0[3] as u128;
    let b4 = b.0[4] as u128;

    let s0 = a0 * b0;
    let s1 = a0 * b1 + a1 * b0;
    let s2 = a0 * b2 + a1 * b1 + a2 * b0;
    let s3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
    let s4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
    let s5 = a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1;
    let s6 = a2 * b4 + a3 * b3 + a4 * b2;
    let s7 = a3 * b4 + a4 * b3;
    let s8 = a4 * b4;

    normalize([s0 + 19 * s5, s1 + 19 * s6, s2 + 19 * s7, s3 + 19 * s8, s4])
}

/// 域平方。
fn fe_square(a: &Fe) -> Fe {
    fe_mul(a, a)
}

/// 域加法。
fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0u128; 5];
    for i in 0..5 {
        r[i] = a.0[i] as u128 + b.0[i] as u128;
    }
    normalize(r)
}

/// 域减法（结果保持非负）。
fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0u128; 5];
    for i in 0..5 {
        r[i] = a.0[i] as u128 + (2 * P[i]) as u128 - b.0[i] as u128;
    }
    normalize(r)
}

/// 域求逆：`a^(p-2)`（费马小定理），指数 `2^255 - 21` 为公开常量。
fn fe_invert(x: &Fe) -> Fe {
    // p - 2 = 2^255 - 21，小端字节。
    const EXPONENT: [u8; 32] = [
        0xEB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x7F,
    ];

    let mut result = FE_ONE;
    let mut base = *x;
    // 从低位到高位处理 255 位（第 255 位为 0）。
    for i in 0..255 {
        if (EXPONENT[i / 8] >> (i % 8)) & 1 == 1 {
            result = fe_mul(&result, &base);
        }
        base = fe_square(&base);
    }
    result
}

/// 常量时间条件交换：`swap == 1` 时交换 `a` 与 `b`。
fn fe_cswap(a: &mut Fe, b: &mut Fe, swap: u8) {
    let mask = 0u64.wrapping_sub(u64::from(swap));
    for i in 0..5 {
        let t = mask & (a.0[i] ^ b.0[i]);
        a.0[i] ^= t;
        b.0[i] ^= t;
    }
}

/// 从 32 字节小端解码 u 坐标：掩码最高位，并对非规范值做模 `p` 归约。
fn fe_from_bytes(b: &[u8; 32]) -> Fe {
    let mut b = *b;
    b[31] &= 0x7f;

    let mut limbs = [0u64; 5];
    for i in 0..5 {
        let bit0 = i * 51;
        let byte0 = bit0 / 8;
        let shift = bit0 % 8;
        let mut acc = 0u128;
        for j in 0..8 {
            let idx = byte0 + j;
            if idx < 32 {
                acc |= (b[idx] as u128) << (8 * j);
            }
        }
        limbs[i] = ((acc >> shift) as u64) & MASK51;
    }

    let (sub, borrow) = sub_borrow(limbs, P);
    if borrow == 0 {
        limbs = sub;
    }
    Fe(limbs)
}

/// 编码为 32 字节小端（最高位为 0）。
fn fe_to_bytes(x: &Fe) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..5 {
        let bit0 = i * 51;
        let byte0 = bit0 / 8;
        let shift = bit0 % 8;
        let v = (x.0[i] as u128) << shift;
        for j in 0..8 {
            let idx = byte0 + j;
            if idx < 32 {
                out[idx] |= ((v >> (8 * j)) & 0xff) as u8;
            }
        }
    }
    out[31] &= 0x7f;
    out
}

/// 蒙哥马利梯子：`x25519(k, u)`，返回标量乘结果的 u 坐标。
fn scalar_mult(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let x1 = fe_from_bytes(u);
    let mut x2 = FE_ONE;
    let mut z2 = FE_ZERO;
    let mut x3 = x1;
    let mut z3 = FE_ONE;
    let mut swap = 0u8;

    for t in (0..255).rev() {
        let k_t = (k[t / 8] >> (t % 8)) & 1;
        swap ^= k_t;
        fe_cswap(&mut x2, &mut x3, swap);
        fe_cswap(&mut z2, &mut z3, swap);
        swap = k_t;

        let a = fe_add(&x2, &z2);
        let aa = fe_square(&a);
        let b = fe_sub(&x2, &z2);
        let bb = fe_square(&b);
        let e = fe_sub(&aa, &bb);
        let c = fe_add(&x3, &z3);
        let d = fe_sub(&x3, &z3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);

        let da_plus_cb = fe_add(&da, &cb);
        let da_minus_cb = fe_sub(&da, &cb);
        x3 = fe_square(&da_plus_cb);
        z3 = fe_mul(&x1, &fe_square(&da_minus_cb));
        x2 = fe_mul(&aa, &bb);
        z2 = fe_mul(&e, &fe_add(&aa, &fe_mul(&FE_A24, &e)));
    }

    fe_cswap(&mut x2, &mut x3, swap);
    fe_cswap(&mut z2, &mut z3, swap);

    let out = fe_mul(&x2, &fe_invert(&z2));
    fe_to_bytes(&out)
}

/// X25519 标量乘法：按 RFC 7748 解码并夹紧标量 `k`，对 u 坐标 `u` 做标量乘。
pub fn x25519(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut scalar = *k;
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    scalar_mult(&scalar, u)
}

/// 由私钥（原始 32 字节随机数）推导公钥。
pub fn derive_public(sk: &[u8; 32]) -> [u8; 32] {
    x25519(sk, &BASE_POINT)
}

/// 生成随机密钥对，返回 `(公钥, 私钥)`。
pub fn keygen() -> ([u8; 32], [u8; 32]) {
    let mut sk = [0u8; 32];
    crate::crypto::rand::fill_bytes(&mut sk).expect("OS random source failed");
    let pk = derive_public(&sk);
    (pk, sk)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn from_hex(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64, "expected 32-byte hex string");
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn rfc7748_vector_1() {
        let k = from_hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = from_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let out = x25519(&k, &u);
        assert_eq!(
            hex(&out),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        );
    }

    #[test]
    fn rfc7748_vector_2() {
        let k = from_hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = from_hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let out = x25519(&k, &u);
        assert_eq!(
            hex(&out),
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
        );
    }

    #[test]
    fn rfc7748_iterated_1() {
        // 迭代测试起点：k = u = 09 00 ... 00。每轮 k = x25519(k, u)，u = 旧 k。
        let mut k = from_hex("0900000000000000000000000000000000000000000000000000000000000000");
        let mut u = from_hex("0900000000000000000000000000000000000000000000000000000000000000");
        for _ in 0..1 {
            let nk = x25519(&k, &u);
            u = k;
            k = nk;
        }
        assert_eq!(
            hex(&k),
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
        );
    }

    #[test]
    fn rfc7748_iterated_1000() {
        let mut k = from_hex("0900000000000000000000000000000000000000000000000000000000000000");
        let mut u = from_hex("0900000000000000000000000000000000000000000000000000000000000000");
        for _ in 0..1000 {
            let nk = x25519(&k, &u);
            u = k;
            k = nk;
        }
        assert_eq!(
            hex(&k),
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
        );
    }

    #[test]
    fn dh_agreement_consistency() {
        let (a_pk, a_sk) = keygen();
        let (b_pk, b_sk) = keygen();
        let ab = x25519(&a_sk, &b_pk);
        let ba = x25519(&b_sk, &a_pk);
        assert_eq!(ab, ba);
    }

    #[test]
    fn keygen_public_matches_derive() {
        let (pk, sk) = keygen();
        assert_eq!(derive_public(&sk), pk);
    }

    #[test]
    fn basepoint_roundtrip() {
        // 标量 1 与基点相乘应仍得有效输出，且 derive_public 与显式标量乘一致。
        let mut k = [0u8; 32];
        k[0] = 1;
        assert_eq!(derive_public(&k), x25519(&k, &BASE_POINT));
    }
}
