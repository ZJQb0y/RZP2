//! CRC 校验（从零实现，供 .xz 容器与内部数据校验使用）。
//!
//! - [`crc32`]：CRC-32/IEEE 802.3（zlib / gzip / .xz 共用）。
//! - [`crc64`]：CRC-64/ECMA-182（.xz 默认的块校验之一）。

use std::sync::OnceLock;

/// CRC-32 查找表（反射多项式 0xEDB8_8320）。
fn crc32_table() -> &'static [u32; 256] {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *e = c;
        }
        t
    })
}

/// CRC-64 查找表（反射多项式 0xC96C_5795_D787_0F42）。
fn crc64_table() -> &'static [u64; 256] {
    static TABLE: OnceLock<[u64; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u64; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u64;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xC96C_5795_D787_0F42 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *e = c;
        }
        t
    })
}

/// 计算一段数据的 CRC-32 校验值（init 与 xorout 均为 0xFFFF_FFFF）。
pub fn crc32(data: &[u8]) -> u32 {
    let t = crc32_table();
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = t[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

/// 计算一段数据的 CRC-64 校验值（init 与 xorout 均为 0xFFFF_FFFF_FFFF_FFFF）。
pub fn crc64(data: &[u8]) -> u64 {
    let t = crc64_table();
    let mut c = 0xFFFF_FFFF_FFFF_FFFFu64;
    for &b in data {
        c = t[((c ^ b as u64) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF_FFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_vectors() {
        // 与标准 zlib/gzip CRC-32 对齐。
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn crc64_known_vectors() {
        // CRC-64/XZ（ECMA-182）的已知向量：空串与 "123456789"。
        assert_eq!(crc64(b""), 0x0000_0000_0000_0000);
        assert_eq!(crc64(b"123456789"), 0x995D_C9BB_DF19_39FA);
    }
}
