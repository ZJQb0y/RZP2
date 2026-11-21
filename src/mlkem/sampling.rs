//! CBD 采样、拒绝采样与矩阵生成。

use crate::mlkem::fips202::{shake256, Keccak};
use crate::mlkem::params::{N, Q, SYM_BYTES};
use crate::mlkem::poly::Poly;

/// SHAKE-128 速率。
const SHAKE128_RATE: usize = 168;

/// 初始矩阵生成块数（与参考实现一致）。
fn gen_matrix_nblocks() -> usize {
    ((12 * N / 8 * (1 << 12) / Q as usize + SHAKE128_RATE) / SHAKE128_RATE).max(1)
}

/// PRF：`SHAKE-256(key || nonce)`。
fn prf(out: &mut [u8], key: &[u8; SYM_BYTES], nonce: u8) {
    let mut extkey = [0u8; SYM_BYTES + 1];
    extkey[..SYM_BYTES].copy_from_slice(key);
    extkey[SYM_BYTES] = nonce;
    shake256(out, &extkey);
}

fn load32_le(buf: &[u8]) -> u32 {
    (buf[0] as u32) | ((buf[1] as u32) << 8) | ((buf[2] as u32) << 16) | ((buf[3] as u32) << 24)
}

fn load24_le(buf: &[u8]) -> u32 {
    (buf[0] as u32) | ((buf[1] as u32) << 8) | ((buf[2] as u32) << 16)
}

/// η=2 的中心二项分布采样。
fn cbd2(r: &mut Poly, buf: &[u8]) {
    for i in 0..(N / 8) {
        let t = load32_le(&buf[4 * i..]);
        let mut d = t & 0x5555_5555;
        d += (t >> 1) & 0x5555_5555;
        for j in 0..8 {
            let a = (d >> (4 * j)) & 0x3;
            let b = (d >> (4 * j + 2)) & 0x3;
            r[8 * i + j] = a as i16 - b as i16;
        }
    }
}

/// η=3 的中心二项分布采样。
fn cbd3(r: &mut Poly, buf: &[u8]) {
    for i in 0..(N / 4) {
        let t = load24_le(&buf[3 * i..]);
        let mut d = t & 0x0024_9249;
        d += (t >> 1) & 0x0024_9249;
        d += (t >> 2) & 0x0024_9249;
        for j in 0..4 {
            let a = (d >> (6 * j)) & 0x7;
            let b = (d >> (6 * j + 3)) & 0x7;
            r[4 * i + j] = a as i16 - b as i16;
        }
    }
}

/// 从种子 + nonce 采样一个 CBD 多项式（eta 为 2 或 3）。
pub fn poly_cbd(r: &mut Poly, seed: &[u8; SYM_BYTES], nonce: u8, eta: usize) {
    let buflen = eta * N / 4;
    let mut buf = vec![0u8; buflen];
    prf(&mut buf, seed, nonce);
    if eta == 3 {
        cbd3(r, &buf);
    } else {
        cbd2(r, &buf);
    }
}

/// 拒绝采样：从均匀字节中采样均匀模 q 的系数，返回已填充数量。
fn rej_uniform(r: &mut [i16], buf: &[u8]) -> usize {
    let mut ctr = 0usize;
    let mut pos = 0usize;
    while ctr < r.len() && pos + 3 <= buf.len() {
        let val0 = ((buf[pos] as u16) | ((buf[pos + 1] as u16) << 8)) & 0xFFF;
        let val1 = ((buf[pos + 1] >> 4) as u16 | ((buf[pos + 2] as u16) << 4)) & 0xFFF;
        pos += 3;

        if val0 < Q as u16 {
            r[ctr] = val0 as i16;
            ctr += 1;
        }
        if ctr < r.len() && val1 < Q as u16 {
            r[ctr] = val1 as i16;
            ctr += 1;
        }
    }
    ctr
}

/// 从种子生成 k×k 矩阵 A（`transposed` 决定 A 或 A^T）。
pub fn gen_matrix(a: &mut [Vec<Poly>], seed: &[u8; SYM_BYTES], transposed: bool) {
    let k = a.len();
    let nblocks = gen_matrix_nblocks();
    let mut buf = vec![0u8; nblocks * SHAKE128_RATE];

    for i in 0..k {
        for j in 0..k {
            let (x, y) = if transposed { (i, j) } else { (j, i) };

            let mut xof = Keccak::new(SHAKE128_RATE);
            xof.absorb(seed);
            xof.absorb(&[x as u8, y as u8]);
            xof.finalize(0x1F);

            xof.squeeze(&mut buf);
            let mut ctr = rej_uniform(&mut a[i][j], &buf);

            while ctr < N {
                let mut block = [0u8; SHAKE128_RATE];
                xof.squeeze(&mut block);
                ctr += rej_uniform(&mut a[i][j][ctr..], &block);
            }
        }
    }
}
