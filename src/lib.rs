//! RZP2 库根模块。
//!
//! > "Talk is cheap. Show me the code." — Linus Torvalds
//!
//! 本项目从零自研 LZMA、ML-KEM 与 ChaCha20-Poly1305，
//! 以代码说话，向这位"Talk is cheap, show me the code"的践行者致敬。

pub mod aead;
pub mod archive;
pub mod cli;
pub mod crypto;
pub mod filters;
pub mod format;
pub mod formats;
pub mod hybrid;
pub mod keys;
pub mod lzma;
pub mod mlkem;
pub mod parallel;
pub mod pipeline;
pub mod progress;
pub mod recompress;
pub mod split;

pub use cli::{completion, sfx};

// 外部格式解码器：物理上位于 `src/formats/`，此处以扁平路径对外暴露，
// 保持 `rzp2::gzip` / `rzp2::zip` 等既有公共 API 不变。
pub use formats::{bzip2, crc, deflate, gzip, sevenz, tar, xz, zip};
