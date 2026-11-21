//! 多项式环 Z_q[X]/(X^256+1) 上的运算。

use crate::mlkem::ntt::{barrett_reduce, basemul, invntt, montgomery_reduce, ntt, ZETAS};
use crate::mlkem::params::{N, Q};

/// 多项式类型。
pub type Poly = [i16; N];

/// 压缩常数 `(round, magic, shift, mask)`。
#[inline]
pub(crate) fn compress_consts(d: u32) -> (u64, u64, u32, u64) {
    match d {
        4 => (1665, 80635, 28, 0xf),
        5 => (1664, 40318, 27, 0x1f),
        10 => (1665, 1290167, 32, 0x3ff),
        11 => (1664, 645084, 31, 0x7ff),
        _ => unreachable!("invalid compression parameter"),
    }
}

/// 压缩单个系数（输入为普通代表，先映射到 [0, q-1]）。
#[inline]
pub(crate) fn compress_coeff(x: i16, d: u32, round: u64, magic: u64, shift: u32, mask: u64) -> u64 {
    let mut u = x as i32;
    u += (u >> 15) & Q;
    let mut d0 = (u as u64) << d;
    d0 += round;
    d0 = d0.wrapping_mul(magic);
    d0 >>= shift;
    d0 & mask
}

/// 多项式加法（不归约）。
pub fn poly_add(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        r[i] = a[i] + b[i];
    }
}

/// 多项式减法（不归约）。
pub fn poly_sub(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        r[i] = a[i] - b[i];
    }
}

/// 正向 NTT 并归约。
pub fn poly_ntt(r: &mut Poly) {
    ntt(r);
    poly_reduce(r);
}

/// 逆 NTT（含 Montgomery 因子）。
pub fn poly_invntt_tomont(r: &mut Poly) {
    invntt(r);
}

/// NTT 域逐点乘法。
pub fn poly_basemul_montgomery(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..(N / 4) {
        basemul(
            &mut r[4 * i..4 * i + 2],
            &a[4 * i..4 * i + 2],
            &b[4 * i..4 * i + 2],
            ZETAS[64 + i],
        );
        basemul(
            &mut r[4 * i + 2..4 * i + 4],
            &a[4 * i + 2..4 * i + 4],
            &b[4 * i + 2..4 * i + 4],
            -ZETAS[64 + i],
        );
    }
}

/// 转换到 Montgomery 域。
pub fn poly_tomont(r: &mut Poly) {
    const F: i32 = ((1u64 << 32) % Q as u64) as i32; // 1353
    for x in r.iter_mut() {
        *x = montgomery_reduce(*x as i32 * F);
    }
}

/// Barrett 归约。
pub fn poly_reduce(r: &mut Poly) {
    for x in r.iter_mut() {
        *x = barrett_reduce(*x);
    }
}

/// 压缩并序列化多项式（dv 位）。
pub fn poly_compress(mut out: &mut [u8], a: &Poly, dv: u32) {
    let (round, magic, shift, mask) = compress_consts(dv);
    let mut t = [0u8; 8];
    for i in 0..(N / 8) {
        for j in 0..8 {
            t[j] = compress_coeff(a[8 * i + j], dv, round, magic, shift, mask) as u8;
        }
        if dv == 4 {
            out[0] = t[0] | (t[1] << 4);
            out[1] = t[2] | (t[3] << 4);
            out[2] = t[4] | (t[5] << 4);
            out[3] = t[6] | (t[7] << 4);
            out = &mut out[4..];
        } else {
            out[0] = t[0] | (t[1] << 5);
            out[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
            out[2] = (t[3] >> 1) | (t[4] << 4);
            out[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
            out[4] = (t[6] >> 2) | (t[7] << 3);
            out = &mut out[5..];
        }
    }
}

/// 反序列化并解压多项式（dv 位）。
pub fn poly_decompress(r: &mut Poly, a: &[u8], dv: u32) {
    if dv == 4 {
        let mut pos = 0usize;
        for i in 0..(N / 2) {
            r[2 * i] = (((a[pos] & 15) as u32 * Q as u32 + 8) >> 4) as i16;
            r[2 * i + 1] = (((a[pos] >> 4) as u32 * Q as u32 + 8) >> 4) as i16;
            pos += 1;
        }
    } else {
        let mut t = [0u8; 8];
        let mut pos = 0usize;
        for i in 0..(N / 8) {
            t[0] = a[pos] >> 0;
            t[1] = (a[pos] >> 5) | (a[pos + 1] << 3);
            t[2] = a[pos + 1] >> 2;
            t[3] = (a[pos + 1] >> 7) | (a[pos + 2] << 1);
            t[4] = (a[pos + 2] >> 4) | (a[pos + 3] << 4);
            t[5] = a[pos + 3] >> 1;
            t[6] = (a[pos + 3] >> 6) | (a[pos + 4] << 2);
            t[7] = a[pos + 4] >> 3;
            pos += 5;
            for j in 0..8 {
                r[8 * i + j] = (((t[j] & 31) as u32 * Q as u32 + 16) >> 5) as i16;
            }
        }
    }
}

/// 序列化多项式（12 位系数，3 字节存 2 个）。
pub fn poly_tobytes(out: &mut [u8], a: &Poly) {
    for i in 0..(N / 2) {
        let mut t0 = a[2 * i] as u16;
        t0 = t0.wrapping_add(((t0 as i16 >> 15) as u16) & (Q as u16));
        let mut t1 = a[2 * i + 1] as u16;
        t1 = t1.wrapping_add(((t1 as i16 >> 15) as u16) & (Q as u16));
        out[3 * i] = (t0 >> 0) as u8;
        out[3 * i + 1] = ((t0 >> 8) | (t1 << 4)) as u8;
        out[3 * i + 2] = (t1 >> 4) as u8;
    }
}

/// 反序列化多项式。
pub fn poly_frombytes(r: &mut Poly, a: &[u8]) {
    for i in 0..(N / 2) {
        r[2 * i] = ((a[3 * i] as u16 | (a[3 * i + 1] as u16) << 8) & 0xFFF) as i16;
        r[2 * i + 1] = (((a[3 * i + 1] >> 4) as u16 | (a[3 * i + 2] as u16) << 4) & 0xFFF) as i16;
    }
}

/// 将 32 字节消息转换为多项式（每比特映射为 0 或 (q+1)/2）。
pub fn poly_frommsg(r: &mut Poly, msg: &[u8; 32]) {
    for i in 0..(N / 8) {
        for j in 0..8 {
            let bit = (msg[i] >> j) & 1;
            // 用乘法代替分支，避免消息位（密钥相关）引入数据相关的控制流。
            r[8 * i + j] = ((Q + 1) / 2) as i16 * bit as i16;
        }
    }
}

/// 将多项式转换为 32 字节消息。
pub fn poly_tomsg(msg: &mut [u8; 32], a: &Poly) {
    for i in 0..(N / 8) {
        msg[i] = 0;
        for j in 0..8 {
            let mut t = a[8 * i + j] as u32;
            t <<= 1;
            t = t.wrapping_add(1665);
            t = t.wrapping_mul(80635);
            t >>= 28;
            t &= 1;
            msg[i] |= (t as u8) << j;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tobytes_frombytes_roundtrip() {
        let mut a = [0i16; N];
        for i in 0..N {
            a[i] = ((i as i32 * 7) % Q - Q / 2) as i16;
        }
        let mut bytes = [0u8; 384];
        poly_tobytes(&mut bytes, &a);
        let mut b = [0i16; N];
        poly_frombytes(&mut b, &bytes);
        // 序列化会丢失负号信息，但正代表应一致。
        for i in 0..N {
            let mut x = a[i];
            x += (x >> 15) & (Q as i16);
            assert_eq!(b[i] as i32, x as i32);
        }
    }

    #[test]
    fn compress_decompress_dv4() {
        let mut a = [0i16; N];
        for i in 0..N {
            a[i] = ((i as i32 * 13) % Q - Q / 2) as i16;
        }
        let mut bytes = [0u8; 128];
        poly_compress(&mut bytes, &a, 4);
        let mut b = [0i16; N];
        poly_decompress(&mut b, &bytes, 4);
        for i in 0..N {
            assert!(b[i] >= 0 && b[i] < Q as i16);
        }
    }

    #[test]
    fn compress_decompress_dv5() {
        let mut a = [0i16; N];
        for i in 0..N {
            a[i] = ((i as i32 * 13) % Q - Q / 2) as i16;
        }
        let mut bytes = [0u8; 160];
        poly_compress(&mut bytes, &a, 5);
        let mut b = [0i16; N];
        poly_decompress(&mut b, &bytes, 5);
        for i in 0..N {
            assert!(b[i] >= 0 && b[i] < Q as i16);
        }
    }

    #[test]
    fn frommsg_tomsg_roundtrip() {
        let mut msg = [0u8; 32];
        for (i, b) in msg.iter_mut().enumerate() {
            *b = (i * 37 + 1) as u8;
        }
        let mut p = [0i16; N];
        poly_frommsg(&mut p, &msg);
        // 编码结果只能是 0 或 (q+1)/2。
        for &x in p.iter() {
            assert!(x == 0 || x == ((Q + 1) / 2) as i16);
        }
        let mut out = [0u8; 32];
        poly_tomsg(&mut out, &p);
        assert_eq!(out, msg);
    }
}
