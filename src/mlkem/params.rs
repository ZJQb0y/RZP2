//! ML-KEM（FIPS 203）参数集常量。

/// 环模数。
pub const Q: i32 = 3329;
/// 多项式维度（X^256 + 1）。
pub const N: usize = 256;
/// 种子/共享密钥字节数。
pub const SYM_BYTES: usize = 32;
/// 单个多项式序列化字节数。
pub const POLY_BYTES: usize = 384;

/// ML-KEM 参数集。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// 向量/矩阵维度 k。
    pub k: usize,
    /// 秘密噪声参数 η1。
    pub eta1: usize,
    /// 加密噪声参数 η2。
    pub eta2: usize,
    /// 向量 u 的压缩比特数。
    pub du: u32,
    /// 多项式 v 的压缩比特数。
    pub dv: u32,
    /// 压缩多项式字节数（dv=4 → 128，dv=5 → 160）。
    pub poly_compressed_bytes: usize,
    /// 压缩向量字节数（du=10 → k*320，du=11 → k*352）。
    pub polyvec_compressed_bytes: usize,
    /// 公钥字节数。
    pub public_key_bytes: usize,
    /// 私钥字节数。
    pub secret_key_bytes: usize,
    /// 密文字节数。
    pub ciphertext_bytes: usize,
}

impl Params {
    pub const fn new(k: usize, eta1: usize, eta2: usize, du: u32, dv: u32) -> Self {
        let poly_compressed_bytes = if dv == 4 { 128 } else { 160 };
        let polyvec_compressed_bytes = if du == 10 { k * 320 } else { k * 352 };
        let public_key_bytes = k * POLY_BYTES + SYM_BYTES;
        let secret_key_bytes = k * POLY_BYTES + public_key_bytes + 2 * SYM_BYTES;
        let ciphertext_bytes = polyvec_compressed_bytes + poly_compressed_bytes;
        Self {
            k,
            eta1,
            eta2,
            du,
            dv,
            poly_compressed_bytes,
            polyvec_compressed_bytes,
            public_key_bytes,
            secret_key_bytes,
            ciphertext_bytes,
        }
    }

    pub fn name(self) -> &'static str {
        match self.k {
            2 => "ML-KEM-512",
            3 => "ML-KEM-768",
            4 => "ML-KEM-1024",
            _ => "ML-KEM-?",
        }
    }
}

/// ML-KEM-512。
pub const MLKEM512: Params = Params::new(2, 3, 2, 10, 4);
/// ML-KEM-768。
pub const MLKEM768: Params = Params::new(3, 2, 2, 10, 4);
/// ML-KEM-1024。
pub const MLKEM1024: Params = Params::new(4, 2, 2, 11, 5);

/// 从名称解析参数集。
pub fn params_from_name(name: &str) -> Option<Params> {
    match name.to_ascii_lowercase().as_str() {
        "ml-kem-512" | "mlkem512" => Some(MLKEM512),
        "ml-kem-768" | "mlkem768" => Some(MLKEM768),
        "ml-kem-1024" | "mlkem1024" => Some(MLKEM1024),
        _ => None,
    }
}
