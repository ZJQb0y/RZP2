//! ML-KEM（FIPS 203 / Kyber）密钥封装，从零实现。

pub mod fips202;
pub mod kem;
pub mod ntt;
pub mod params;
pub mod poly;
pub mod sampling;

pub use kem::{decaps, encaps, encaps_derand, keygen, keygen_derand};
pub use params::{params_from_name, Params, MLKEM1024, MLKEM512, MLKEM768};
