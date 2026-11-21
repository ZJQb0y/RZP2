//! 从零实现的密码学原语（无第三方依赖）。
//!
//! 与 [`crate::aead`]（ChaCha20-Poly1305）配合，为 RZP2 提供：
//! - [`blake2b`]：BLAKE2b 可变长度哈希（RFC 7693），作为 Argon2id 的 H0 / H'。
//! - [`argon2`]：Argon2id 密钥派生（RFC 9106），用于口令加密。

pub mod argon2;
pub mod blake2b;
pub mod rand;
pub mod x25519;
pub mod zeroize;
