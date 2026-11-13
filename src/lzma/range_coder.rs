//! LZMA 范围编码器（Range Coder）。
//!
//! 这是 LZMA 使用的二进制自适应范围编码器，概率为 11-bit 定点（`kBitModelTotal = 2048`）。
//! 归一化阈值 `TOP_VALUE = 1 << 24`，每次归一化输出/读入一个字节（带进位延迟处理）。

use std::io::Write;

/// 概率模型总比特数（11-bit 概率）。
pub const BIT_MODEL_TOTAL: u32 = 2048;
/// 概率模型移动比特数。
pub const MOVE_BITS: u32 = 5;
/// 归一化阈值：`range < TOP_VALUE` 时进行归一化。
pub const TOP_VALUE: u32 = 1 << 24;
/// 概率初始值（0.5）。
pub const PROB_INIT: u16 = (BIT_MODEL_TOTAL >> 1) as u16;

/// 范围编码器。
pub struct RangeEncoder {
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u32,
    out: Vec<u8>,
}

impl RangeEncoder {
    pub fn new() -> Self {
        Self {
            low: 0,
            range: 0xFFFF_FFFF,
            cache: 0,
            cache_size: 0,
            out: Vec::new(),
        }
    }

    /// 处理范围编码器的进位输出（与 LZMA SDK `RangeEnc_ShiftLow` 对齐）。
    fn shift_low(&mut self) {
        let low32 = self.low as u32;
        let high = (self.low >> 32) as u32;
        self.low = ((low32 as u64) << 8) & 0xFFFF_FFFF;
        if low32 < 0xFF00_0000 || high != 0 {
            let carry = high as u8;
            self.out.push(self.cache.wrapping_add(carry));
            self.cache = (low32 >> 24) as u8;
            if self.cache_size == 0 {
                return;
            }
            let high_byte = 0xFFu8.wrapping_add(carry);
            loop {
                self.out.push(high_byte);
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    return;
                }
            }
        }
        self.cache_size += 1;
    }

    fn normalize(&mut self) {
        if self.range < TOP_VALUE {
            self.range <<= 8;
            self.shift_low();
        }
    }

    /// 编码一个比特，`prob` 为对应概率（会被原地更新）。
    pub fn encode_bit(&mut self, prob: &mut u16, bit: u32) {
        let p = *prob as u32;
        let bound = (self.range >> 11) * p;
        if bit == 0 {
            self.range = bound;
            *prob = (p + ((BIT_MODEL_TOTAL - p) >> MOVE_BITS)) as u16;
        } else {
            self.low += bound as u64;
            self.range -= bound;
            *prob = (p - (p >> MOVE_BITS)) as u16;
        }
        self.normalize();
    }

    /// 编码 `num_bits` 个直接比特（无概率模型，MSB 优先）。
    pub fn encode_direct_bits(&mut self, value: u32, mut num_bits: u32) {
        while num_bits > 0 {
            self.range >>= 1;
            num_bits -= 1;
            if (value >> num_bits) & 1 == 1 {
                self.low += self.range as u64;
            }
            self.normalize();
        }
    }

    /// 结束编码并返回输出字节。
    pub fn finish(mut self) -> Vec<u8> {
        for _ in 0..5 {
            self.shift_low();
        }
        self.out
    }

    /// 当前已缓冲但尚未写出的字节数。
    pub fn out_len(&self) -> usize {
        self.out.len()
    }

    /// 将已缓冲的输出写入 `writer` 并清空缓冲（流式编码中途调用）。
    pub fn drain_to<W: Write>(&mut self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.out)?;
        self.out.clear();
        Ok(())
    }

    /// 结束编码并把最终输出写入 `writer`。
    pub fn finish_to<W: Write>(mut self, writer: &mut W) -> std::io::Result<()> {
        for _ in 0..5 {
            self.shift_low();
        }
        writer.write_all(&self.out)?;
        Ok(())
    }
}

impl Default for RangeEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// 范围解码器。
pub struct RangeDecoder<'a> {
    range: u32,
    code: u32,
    input: &'a [u8],
    pos: usize,
}

impl<'a> RangeDecoder<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        let mut d = Self {
            range: 0xFFFF_FFFF,
            code: 0,
            input,
            pos: 0,
        };
        for _ in 0..5 {
            d.code = (d.code << 8) | d.read_byte();
        }
        d
    }

    fn read_byte(&mut self) -> u32 {
        let b = if self.pos < self.input.len() {
            self.input[self.pos]
        } else {
            0
        };
        self.pos += 1;
        b as u32
    }

    fn normalize(&mut self) {
        if self.range < TOP_VALUE {
            self.code = (self.code << 8) | self.read_byte();
            self.range <<= 8;
        }
    }

    /// 解码一个比特（先归一化，再计算 bound，与 LZMA SDK 对齐）。
    pub fn decode_bit(&mut self, prob: &mut u16) -> u32 {
        self.normalize();
        let p = *prob as u32;
        let bound = (self.range >> 11) * p;
        let bit;
        if self.code < bound {
            bit = 0;
            self.range = bound;
            *prob = (p + ((BIT_MODEL_TOTAL - p) >> MOVE_BITS)) as u16;
        } else {
            bit = 1;
            self.code -= bound;
            self.range -= bound;
            *prob = (p - (p >> MOVE_BITS)) as u16;
        }
        bit
    }

    /// 解码 `num_bits` 个直接比特（MSB 优先，先归一化）。
    pub fn decode_direct_bits(&mut self, mut num_bits: u32) -> u32 {
        let mut result = 0u32;
        while num_bits > 0 {
            self.normalize();
            self.range >>= 1;
            let bit = if self.code >= self.range {
                self.code -= self.range;
                1
            } else {
                0
            };
            result = (result << 1) | bit;
            num_bits -= 1;
        }
        result
    }
}

/// 普通位树编码（MSB 优先），`probs` 以节点 1 为根，下标 0 不使用。
pub fn encode_bit_tree(rc: &mut RangeEncoder, probs: &mut [u16], num_bits: u32, symbol: u32) {
    let mut m = 1usize;
    for i in (0..num_bits).rev() {
        let bit = (symbol >> i) & 1;
        rc.encode_bit(&mut probs[m], bit);
        m = (m << 1) | bit as usize;
    }
}

/// 普通位树解码（MSB 优先）。
pub fn decode_bit_tree(rc: &mut RangeDecoder, probs: &mut [u16], num_bits: u32) -> u32 {
    let mut m = 1usize;
    for _ in 0..num_bits {
        let bit = rc.decode_bit(&mut probs[m]);
        m = (m << 1) | bit as usize;
    }
    (m - (1usize << num_bits)) as u32
}

/// 反向位树编码（LSB 优先）。
pub fn encode_reverse_bit_tree(
    rc: &mut RangeEncoder,
    probs: &mut [u16],
    num_bits: u32,
    mut symbol: u32,
) {
    let mut m = 1usize;
    for _ in 0..num_bits {
        let bit = symbol & 1;
        symbol >>= 1;
        rc.encode_bit(&mut probs[m], bit);
        m = (m << 1) | bit as usize;
    }
}

/// 反向位树解码（LSB 优先）。
pub fn decode_reverse_bit_tree(rc: &mut RangeDecoder, probs: &mut [u16], num_bits: u32) -> u32 {
    let mut m = 1usize;
    let mut symbol = 0u32;
    for i in 0..num_bits {
        let bit = rc.decode_bit(&mut probs[m]);
        m = (m << 1) | bit as usize;
        symbol |= bit << i;
    }
    symbol
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_roundtrip() {
        let mut enc = RangeEncoder::new();
        let mut prob = PROB_INIT;
        let bits = [0u32, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0];
        for &b in &bits {
            enc.encode_bit(&mut prob, b);
        }
        let data = enc.finish();

        let mut dec = RangeDecoder::new(&data);
        let mut prob2 = PROB_INIT;
        for &b in &bits {
            assert_eq!(dec.decode_bit(&mut prob2), b);
        }
    }

    #[test]
    fn direct_bits_roundtrip() {
        let mut enc = RangeEncoder::new();
        enc.encode_direct_bits(0b101101, 6);
        let data = enc.finish();

        let mut dec = RangeDecoder::new(&data);
        assert_eq!(dec.decode_direct_bits(6), 0b101101);
    }

    #[test]
    fn bit_tree_roundtrip() {
        let mut enc = RangeEncoder::new();
        let mut probs = [PROB_INIT; 64];
        encode_bit_tree(&mut enc, &mut probs, 6, 37);
        let data = enc.finish();

        let mut dec = RangeDecoder::new(&data);
        let mut probs2 = [PROB_INIT; 64];
        assert_eq!(decode_bit_tree(&mut dec, &mut probs2, 6), 37);
    }

    #[test]
    fn reverse_bit_tree_roundtrip() {
        let mut enc = RangeEncoder::new();
        let mut probs = [PROB_INIT; 32];
        encode_reverse_bit_tree(&mut enc, &mut probs, 5, 21);
        let data = enc.finish();

        let mut dec = RangeDecoder::new(&data);
        let mut probs2 = [PROB_INIT; 32];
        assert_eq!(decode_reverse_bit_tree(&mut dec, &mut probs2, 5), 21);
    }

    #[test]
    fn long_bit_sequence_roundtrip() {
        // 覆盖多次归一化与进位。
        let mut enc = RangeEncoder::new();
        let mut prob = PROB_INIT;
        let mut x = 0x1234u32;
        for _ in 0..1000 {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            let bit = (x >> 31) & 1;
            enc.encode_bit(&mut prob, bit);
        }
        let data = enc.finish();

        let mut dec = RangeDecoder::new(&data);
        let mut prob2 = PROB_INIT;
        let mut x = 0x1234u32;
        for _ in 0..1000 {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            let bit = (x >> 31) & 1;
            assert_eq!(dec.decode_bit(&mut prob2), bit);
        }
    }
}
