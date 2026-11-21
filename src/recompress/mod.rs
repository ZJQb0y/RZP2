//! 格式感知重压缩（precomp 式）。
//!
//! 对已做过熵编码（DEFLATE / JPEG 等）的数据做「反熵 → 符号层 → 更强后端」的可逆
//! 再编码，使外层 LZMA 能进一步压缩这些原本几乎无法压缩的数据；反过程逐位还原原始
//! 容器，保证字节级无损。

pub mod deflate;
pub mod gif;
pub mod gzip;
pub mod jpeg;
pub mod png;
pub mod zip;
