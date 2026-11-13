//! 敏感数据清零（零依赖）：用 `write_volatile` 覆盖，防止编译器把清零优化掉。
//!
//! 与 `zeroize` crate 的 `Zeroize` trait 同名同法，仅实现本库需要的字节数组/切片。

/// 可被清零的类型。
pub trait Zeroize {
    fn zeroize(&mut self);
}

impl Zeroize for [u8] {
    fn zeroize(&mut self) {
        for b in self.iter_mut() {
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

impl<const N: usize> Zeroize for [u8; N] {
    fn zeroize(&mut self) {
        self[..].zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroizes_array_and_slice() {
        let mut arr = [0xAAu8; 16];
        arr.zeroize();
        assert_eq!(arr, [0u8; 16]);

        let mut buf = vec![0xBBu8; 32];
        buf[..].zeroize();
        assert_eq!(buf, vec![0u8; 32]);
    }
}
