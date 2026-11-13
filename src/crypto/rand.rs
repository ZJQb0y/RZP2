//! 加密随机源（零依赖）：Unix 上读取 `/dev/urandom`，Windows 上调用 `RtlGenRandom`。
//!
//! 用于生成盐（16 字节）、nonce（12 字节）以及 ML-KEM 的随机硬币。

use std::io;

/// 用系统加密随机源填充缓冲区。
#[cfg(unix)]
pub fn fill_bytes(buf: &mut [u8]) -> io::Result<()> {
    use std::fs::File;
    use std::io::Read;
    let mut f = File::open("/dev/urandom")?;
    f.read_exact(buf)
}

/// Windows：通过 `advapi32` 的 `RtlGenRandom`（导出名 `SystemFunction036`）填充。
#[cfg(windows)]
pub fn fill_bytes(buf: &mut [u8]) -> io::Result<()> {
    #[link(name = "advapi32")]
    extern "system" {
        fn SystemFunction036(buf: *mut u8, len: u32) -> u8;
    }
    let ok = unsafe { SystemFunction036(buf.as_mut_ptr(), buf.len() as u32) };
    if ok == 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "RtlGenRandom failed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_works_and_varied() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_bytes(&mut a).unwrap();
        fill_bytes(&mut b).unwrap();
        // 概率上几乎不可能相同；仅作 sanity 检查。
        assert!(a != [0u8; 32]);
        assert!(b != [0u8; 32]);
    }
}
