//! 外部压缩 / 归档格式的解析与解码（零第三方依赖，手写实现）。
//!
//! 与自研 `.rzp2` 容器（见 [`crate::format`] / [`crate::pipeline`]）不同，本模块
//! 面向主流分发格式的互操作，供 `decompress` 子命令按魔数探测后调用：
//!
//! - [`deflate`]：DEFLATE（RFC 1951）inflate，gzip / zip 的压缩内核
//! - [`gzip`]：gzip（RFC 1952）容器
//! - [`xz`]：`.xz` 容器（LZMA2 过滤器）
//! - [`tar`]：tar 归档拆包
//! - [`zip`]：zip 容器（存储 / Deflate）
//! - [`bzip2`]：bzip2（BWT + MTF + RLE + Huffman）
//! - [`sevenz`]：7z 容器（复用 LZMA2 / LZMA1 内核）
//! - [`crc`]：CRC32 / CRC64 校验

pub mod bzip2;
pub mod crc;
pub mod deflate;
pub mod gzip;
pub mod sevenz;
pub mod tar;
pub mod xz;
pub mod zip;
