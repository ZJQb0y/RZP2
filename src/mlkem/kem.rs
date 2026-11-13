//! ML-KEM 密钥封装（K-PKE + KEM，含 FO 变换与隐式拒绝）。

use crate::mlkem::fips202::{sha3_256, sha3_512, Keccak};
use crate::mlkem::params::{Params, N, POLY_BYTES, SYM_BYTES};
use crate::mlkem::poly::{
    compress_coeff, compress_consts, poly_basemul_montgomery, poly_compress, poly_decompress,
    poly_frombytes, poly_frommsg, poly_invntt_tomont, poly_ntt, poly_reduce, poly_tobytes,
    poly_tomont, poly_tomsg, Poly,
};
use crate::mlkem::sampling::{gen_matrix, poly_cbd};

type PolyVec = Vec<Poly>;
type Matrix = Vec<PolyVec>;

/// 多项式向量 NTT 域累乘：`r = Σ_i a[i] ∘ b[i]`。
fn polyvec_basemul_acc(r: &mut Poly, a: &[Poly], b: &[Poly]) {
    poly_basemul_montgomery(r, &a[0], &b[0]);
    for i in 1..a.len() {
        let mut t = [0i16; N];
        poly_basemul_montgomery(&mut t, &a[i], &b[i]);
        for j in 0..N {
            r[j] += t[j];
        }
    }
    poly_reduce(r);
}

fn polyvec_ntt(v: &mut [Poly]) {
    for p in v.iter_mut() {
        poly_ntt(p);
    }
}

fn polyvec_invntt_tomont(v: &mut [Poly]) {
    for p in v.iter_mut() {
        poly_invntt_tomont(p);
    }
}

fn polyvec_reduce(v: &mut [Poly]) {
    for p in v.iter_mut() {
        poly_reduce(p);
    }
}

fn polyvec_tobytes(out: &mut [u8], v: &[Poly]) {
    for (i, p) in v.iter().enumerate() {
        poly_tobytes(&mut out[i * POLY_BYTES..(i + 1) * POLY_BYTES], p);
    }
}

fn polyvec_frombytes(v: &mut [Poly], a: &[u8]) {
    for (i, p) in v.iter_mut().enumerate() {
        poly_frombytes(p, &a[i * POLY_BYTES..(i + 1) * POLY_BYTES]);
    }
}

fn polyvec_compress(out: &mut [u8], v: &[Poly], du: u32) {
    let (round, magic, shift, mask) = compress_consts(du);
    let mut pos = 0usize;
    if du == 10 {
        for p in v {
            for j in 0..(N / 4) {
                let mut t = [0u64; 4];
                for kk in 0..4 {
                    t[kk] = compress_coeff(p[4 * j + kk], du, round, magic, shift, mask);
                }
                out[pos] = t[0] as u8;
                out[pos + 1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
                out[pos + 2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
                out[pos + 3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
                out[pos + 4] = (t[3] >> 2) as u8;
                pos += 5;
            }
        }
    } else {
        for p in v {
            for j in 0..(N / 8) {
                let mut t = [0u64; 8];
                for kk in 0..8 {
                    t[kk] = compress_coeff(p[8 * j + kk], du, round, magic, shift, mask);
                }
                out[pos] = t[0] as u8;
                out[pos + 1] = ((t[0] >> 8) | (t[1] << 3)) as u8;
                out[pos + 2] = ((t[1] >> 5) | (t[2] << 6)) as u8;
                out[pos + 3] = (t[2] >> 2) as u8;
                out[pos + 4] = ((t[2] >> 10) | (t[3] << 1)) as u8;
                out[pos + 5] = ((t[3] >> 7) | (t[4] << 4)) as u8;
                out[pos + 6] = ((t[4] >> 4) | (t[5] << 7)) as u8;
                out[pos + 7] = (t[5] >> 1) as u8;
                out[pos + 8] = ((t[5] >> 9) | (t[6] << 2)) as u8;
                out[pos + 9] = ((t[6] >> 6) | (t[7] << 5)) as u8;
                out[pos + 10] = (t[7] >> 3) as u8;
                pos += 11;
            }
        }
    }
}

fn polyvec_decompress(v: &mut [Poly], a: &[u8], du: u32) {
    let mut pos = 0usize;
    if du == 10 {
        for p in v.iter_mut() {
            for j in 0..(N / 4) {
                let t0 = (a[pos] as u16) | ((a[pos + 1] as u16) << 8);
                let t1 = ((a[pos + 1] >> 2) as u16) | ((a[pos + 2] as u16) << 6);
                let t2 = ((a[pos + 2] >> 4) as u16) | ((a[pos + 3] as u16) << 4);
                let t3 = ((a[pos + 3] >> 6) as u16) | ((a[pos + 4] as u16) << 2);
                pos += 5;
                p[4 * j] = (((t0 & 0x3FF) as u32 * 3329 + 512) >> 10) as i16;
                p[4 * j + 1] = (((t1 & 0x3FF) as u32 * 3329 + 512) >> 10) as i16;
                p[4 * j + 2] = (((t2 & 0x3FF) as u32 * 3329 + 512) >> 10) as i16;
                p[4 * j + 3] = (((t3 & 0x3FF) as u32 * 3329 + 512) >> 10) as i16;
            }
        }
    } else {
        for p in v.iter_mut() {
            for j in 0..(N / 8) {
                let t0 = (a[pos] as u16) | ((a[pos + 1] as u16) << 8);
                let t1 = ((a[pos + 1] >> 3) as u16) | ((a[pos + 2] as u16) << 5);
                let t2 = ((a[pos + 2] >> 6) as u16)
                    | ((a[pos + 3] as u16) << 2)
                    | ((a[pos + 4] as u16) << 10);
                let t3 = ((a[pos + 4] >> 1) as u16) | ((a[pos + 5] as u16) << 7);
                let t4 = ((a[pos + 5] >> 4) as u16) | ((a[pos + 6] as u16) << 4);
                let t5 = ((a[pos + 6] >> 7) as u16)
                    | ((a[pos + 7] as u16) << 1)
                    | ((a[pos + 8] as u16) << 9);
                let t6 = ((a[pos + 8] >> 2) as u16) | ((a[pos + 9] as u16) << 6);
                let t7 = ((a[pos + 9] >> 5) as u16) | ((a[pos + 10] as u16) << 3);
                pos += 11;
                let t = [t0, t1, t2, t3, t4, t5, t6, t7];
                for (kk, &tt) in t.iter().enumerate() {
                    p[8 * j + kk] = (((tt & 0x7FF) as u32 * 3329 + 1024) >> 11) as i16;
                }
            }
        }
    }
}

/// K-PKE 密钥生成（`coins` = 32 字节 d）。
fn indcpa_keypair(pk: &mut [u8], sk: &mut [u8], coins: &[u8; SYM_BYTES], p: &Params) {
    let mut buf = [0u8; SYM_BYTES + 1];
    buf[..SYM_BYTES].copy_from_slice(coins);
    buf[SYM_BYTES] = p.k as u8;
    let mut g = [0u8; 64];
    sha3_512(&mut g, &buf);
    let public_seed: [u8; SYM_BYTES] = g[..SYM_BYTES].try_into().unwrap();
    let noise_seed: [u8; SYM_BYTES] = g[SYM_BYTES..].try_into().unwrap();

    let mut a: Matrix = vec![vec![[0i16; N]; p.k]; p.k];
    gen_matrix(&mut a, &public_seed, false);

    let mut s: PolyVec = vec![[0i16; N]; p.k];
    let mut e: PolyVec = vec![[0i16; N]; p.k];
    let mut nonce = 0u8;
    for i in 0..p.k {
        poly_cbd(&mut s[i], &noise_seed, nonce, p.eta1);
        nonce += 1;
    }
    for i in 0..p.k {
        poly_cbd(&mut e[i], &noise_seed, nonce, p.eta1);
        nonce += 1;
    }

    polyvec_ntt(&mut s);
    polyvec_ntt(&mut e);

    let mut t: PolyVec = vec![[0i16; N]; p.k];
    for i in 0..p.k {
        polyvec_basemul_acc(&mut t[i], &a[i], &s);
        poly_tomont(&mut t[i]);
    }
    for i in 0..p.k {
        for j in 0..N {
            t[i][j] += e[i][j];
        }
    }
    polyvec_reduce(&mut t);

    polyvec_tobytes(sk, &s);
    polyvec_tobytes(&mut pk[..p.k * POLY_BYTES], &t);
    pk[p.k * POLY_BYTES..].copy_from_slice(&public_seed);
}

/// K-PKE 加密（`coins` = 32 字节 r）。
fn indcpa_enc(c: &mut [u8], m: &[u8; SYM_BYTES], pk: &[u8], coins: &[u8; SYM_BYTES], p: &Params) {
    let mut t: PolyVec = vec![[0i16; N]; p.k];
    let mut seed = [0u8; SYM_BYTES];
    polyvec_frombytes(&mut t, &pk[..p.k * POLY_BYTES]);
    seed.copy_from_slice(&pk[p.k * POLY_BYTES..]);

    let mut at: Matrix = vec![vec![[0i16; N]; p.k]; p.k];
    gen_matrix(&mut at, &seed, true);

    let mut sp: PolyVec = vec![[0i16; N]; p.k];
    let mut ep: PolyVec = vec![[0i16; N]; p.k];
    let mut epp = [0i16; N];
    let mut nonce = 0u8;
    for i in 0..p.k {
        poly_cbd(&mut sp[i], coins, nonce, p.eta1);
        nonce += 1;
    }
    for i in 0..p.k {
        poly_cbd(&mut ep[i], coins, nonce, p.eta2);
        nonce += 1;
    }
    poly_cbd(&mut epp, coins, nonce, p.eta2);

    let mut k = [0i16; N];
    poly_frommsg(&mut k, m);

    polyvec_ntt(&mut sp);

    let mut b: PolyVec = vec![[0i16; N]; p.k];
    for i in 0..p.k {
        polyvec_basemul_acc(&mut b[i], &at[i], &sp);
    }
    let mut v = [0i16; N];
    polyvec_basemul_acc(&mut v, &t, &sp);

    polyvec_invntt_tomont(&mut b);
    poly_invntt_tomont(&mut v);

    for i in 0..p.k {
        for j in 0..N {
            b[i][j] += ep[i][j];
        }
    }
    for j in 0..N {
        v[j] += epp[j];
    }
    for j in 0..N {
        v[j] += k[j];
    }

    polyvec_reduce(&mut b);
    poly_reduce(&mut v);

    polyvec_compress(&mut c[..p.polyvec_compressed_bytes], &b, p.du);
    poly_compress(&mut c[p.polyvec_compressed_bytes..], &v, p.dv);
}

/// K-PKE 解密。
fn indcpa_dec(m: &mut [u8; SYM_BYTES], c: &[u8], sk: &[u8], p: &Params) {
    let mut b: PolyVec = vec![[0i16; N]; p.k];
    let mut v = [0i16; N];
    polyvec_decompress(&mut b, &c[..p.polyvec_compressed_bytes], p.du);
    poly_decompress(&mut v, &c[p.polyvec_compressed_bytes..], p.dv);

    let mut s: PolyVec = vec![[0i16; N]; p.k];
    polyvec_frombytes(&mut s, sk);

    polyvec_ntt(&mut b);

    let mut mp = [0i16; N];
    polyvec_basemul_acc(&mut mp, &s, &b);
    poly_invntt_tomont(&mut mp);

    for j in 0..N {
        mp[j] = v[j] - mp[j];
    }
    poly_reduce(&mut mp);

    poly_tomsg(m, &mp);
}

/// 常量时间比较：相等返回 0，不同返回 1。
fn verify(a: &[u8], b: &[u8]) -> u8 {
    let mut r = 0u8;
    for i in 0..a.len() {
        r |= a[i] ^ b[i];
    }
    // 0 if equal, 1 if different（常量时间）。
    (r != 0) as u8
}

/// 常量时间条件拷贝：`cond` 为真时把 `src` 拷到 `out`。
fn cmov(out: &mut [u8], src: &[u8], cond: bool) {
    let mask = if cond { 0xFFu8 } else { 0x00u8 };
    for i in 0..out.len() {
        out[i] ^= mask & (out[i] ^ src[i]);
    }
}

/// 确定性密钥生成（`coins = d(32) || z(32)`）。
pub fn keygen_derand(p: &Params, coins: &[u8; 64]) -> (Vec<u8>, Vec<u8>) {
    let mut pk = vec![0u8; p.public_key_bytes];
    let mut sk = vec![0u8; p.secret_key_bytes];

    let indcpa_sk = p.k * POLY_BYTES;
    indcpa_keypair(
        &mut pk,
        &mut sk[..indcpa_sk],
        &coins[..32].try_into().unwrap(),
        p,
    );

    // sk = dk_PKE || pk || H(pk) || z
    sk[indcpa_sk..indcpa_sk + p.public_key_bytes].copy_from_slice(&pk);
    let h_offset = p.secret_key_bytes - 2 * SYM_BYTES;
    let mut h = [0u8; 32];
    sha3_256(&mut h, &pk);
    sk[h_offset..h_offset + 32].copy_from_slice(&h);
    sk[p.secret_key_bytes - 32..].copy_from_slice(&coins[32..]);

    (pk, sk)
}

/// 确定性封装（`coins = m(32)`）。
pub fn encaps_derand(p: &Params, pk: &[u8], coins: &[u8; SYM_BYTES]) -> (Vec<u8>, Vec<u8>) {
    let mut buf = [0u8; 2 * SYM_BYTES];
    buf[..SYM_BYTES].copy_from_slice(coins);
    let mut hpk = [0u8; 32];
    sha3_256(&mut hpk, pk);
    buf[SYM_BYTES..].copy_from_slice(&hpk);

    let mut kr = [0u8; 2 * SYM_BYTES];
    sha3_512(&mut kr, &buf);

    let mut ct = vec![0u8; p.ciphertext_bytes];
    indcpa_enc(&mut ct, coins, pk, &kr[SYM_BYTES..].try_into().unwrap(), p);

    let ss = kr[..SYM_BYTES].to_vec();
    (ct, ss)
}

/// 解封装。
pub fn decaps(p: &Params, sk: &[u8], ct: &[u8]) -> Vec<u8> {
    let indcpa_sk = p.k * POLY_BYTES;
    let pk = &sk[indcpa_sk..indcpa_sk + p.public_key_bytes];
    let h = &sk[p.secret_key_bytes - 2 * SYM_BYTES..p.secret_key_bytes - SYM_BYTES];
    let z = &sk[p.secret_key_bytes - SYM_BYTES..];

    let mut m = [0u8; SYM_BYTES];
    indcpa_dec(&mut m, ct, &sk[..indcpa_sk], p);

    let mut buf = [0u8; 2 * SYM_BYTES];
    buf[..SYM_BYTES].copy_from_slice(&m);
    buf[SYM_BYTES..].copy_from_slice(h);
    let mut kr = [0u8; 2 * SYM_BYTES];
    sha3_512(&mut kr, &buf);

    let mut cmp = vec![0u8; p.ciphertext_bytes];
    indcpa_enc(&mut cmp, &m, pk, &kr[SYM_BYTES..].try_into().unwrap(), p);

    let fail = verify(ct, &cmp);

    // 隐式拒绝密钥 = SHAKE-256(z || ct)。
    let mut ss = [0u8; SYM_BYTES];
    let mut xof = Keccak::new(136);
    xof.absorb(z);
    xof.absorb(ct);
    xof.finalize(0x1F);
    xof.squeeze(&mut ss);

    cmov(&mut ss, &kr[..SYM_BYTES], fail == 0);
    ss.to_vec()
}

/// 随机密钥生成（使用 OS 随机源）。
pub fn keygen(p: &Params) -> (Vec<u8>, Vec<u8>) {
    let mut coins = [0u8; 64];
    crate::crypto::rand::fill_bytes(&mut coins).expect("OS random source failed");
    keygen_derand(p, &coins)
}

/// 随机封装。
pub fn encaps(p: &Params, pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut coins = [0u8; SYM_BYTES];
    crate::crypto::rand::fill_bytes(&mut coins).expect("OS random source failed");
    encaps_derand(p, pk, &coins)
}
