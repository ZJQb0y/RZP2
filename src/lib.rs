//! RZP2 库根模块。
//!
//! > "Talk is cheap. Show me the code." — Linus Torvalds
//!
//! 本项目从零自研 LZMA、ML-KEM 与 ChaCha20-Poly1305，
//! 以代码说话，向这位"Talk is cheap, show me the code"的践行者致敬。

pub mod aead;
pub mod archive;
pub mod cli;
pub mod crc;
pub mod crypto;
pub mod format;
pub mod hybrid;
pub mod keys;
pub mod lzma;
pub mod mlkem;
pub mod parallel;
pub mod pipeline;
pub mod progress;
pub mod split;
pub mod xz;

pub use cli::{completion, sfx};
