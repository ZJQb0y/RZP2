//! RZP2 压缩 / 解压动态库（C ABI）。
//!
//! 仅暴露 LZMA1「alone」格式的编解码，与 LZMA SDK / xz 兼容：
//! `properties(1) + dict_size(4, LE) + uncompressed_size(8, LE)` 后接原始 LZMA 码流。
//!
//! 本 crate 只依赖核心库 `rzp2` 的 `lzma` 模块，不含 CLI。

// FFI 导出函数的指针有效性由 C 头文件中的契约约束，调用方负责提供合法指针与长度。
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ptr;
use std::slice;

/// 参数错误 / 数据损坏。
const ERR_INVALID: isize = -1;
/// 输出缓冲区不足。
const ERR_TOO_SMALL: isize = -2;

/// 返回 ABI 版本号（当前为 1）。
#[no_mangle]
pub extern "C" fn rzp2_compress_version() -> u32 {
    1
}

/// LZMA1 alone 压缩。
///
/// `level` 取值 0..=9（越界按 9 处理）。`out` 传空指针时返回所需缓冲区字节数（不写入），
/// 否则写入压缩结果并返回写出字节数；`out_cap` 不足返回 [`ERR_TOO_SMALL`]。
#[no_mangle]
pub extern "C" fn rzp2_compress(
    input: *const u8,
    input_len: usize,
    level: u32,
    out: *mut u8,
    out_cap: usize,
) -> isize {
    if input.is_null() && input_len > 0 {
        return ERR_INVALID;
    }
    let data = if input_len == 0 {
        &[][..]
    } else {
        // SAFETY: 调用方保证 input 指向至少 input_len 字节的可读内存。
        unsafe { slice::from_raw_parts(input, input_len) }
    };
    let level = level.min(9) as u8;
    let encoded = rzp2::lzma::encode(data, &rzp2::lzma::preset(level));
    write_out(&encoded, out, out_cap)
}

/// 从 LZMA1 alone 头部读取未压缩长度；未知（`u64::MAX`）或非法返回 [`ERR_INVALID`]。
#[no_mangle]
pub extern "C" fn rzp2_decompressed_size(input: *const u8, input_len: usize) -> isize {
    if input.is_null() || input_len < 13 {
        return ERR_INVALID;
    }
    // SAFETY: 已校验长度至少 13。
    let header = unsafe { slice::from_raw_parts(input, 13) };
    let uncompressed = u64::from_le_bytes(header[5..13].try_into().unwrap());
    if uncompressed == u64::MAX || uncompressed > isize::MAX as u64 {
        ERR_INVALID
    } else {
        uncompressed as isize
    }
}

/// LZMA1 alone 解压。
///
/// `out` 传空指针时返回所需缓冲区字节数（不写入），否则写入明文并返回写出字节数；
/// 数据损坏返回 [`ERR_INVALID`]，`out_cap` 不足返回 [`ERR_TOO_SMALL`]。
#[no_mangle]
pub extern "C" fn rzp2_decompress(
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> isize {
    if input.is_null() {
        return ERR_INVALID;
    }
    // SAFETY: 调用方保证 input 指向至少 input_len 字节的可读内存。
    let data = unsafe { slice::from_raw_parts(input, input_len) };
    match rzp2::lzma::decode(data) {
        Ok(plain) => write_out(&plain, out, out_cap),
        Err(_) => ERR_INVALID,
    }
}

/// 把结果写入输出缓冲区：`out` 为空时返回所需容量，缓冲区不足返回 [`ERR_TOO_SMALL`]。
fn write_out(bytes: &[u8], out: *mut u8, out_cap: usize) -> isize {
    if out.is_null() {
        return bytes.len() as isize;
    }
    if out_cap < bytes.len() {
        return ERR_TOO_SMALL;
    }
    // SAFETY: 已校验 out_cap 足够；out 非空。
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
    }
    bytes.len() as isize
}
