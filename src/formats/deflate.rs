//! DEFLATE（RFC 1951）解压内核。
//!
//! 从零实现 inflate：LSB-first 位流、固定/动态规范 Huffman 解码、LZ77 回溯窗口。
//! 供 `.gz` / `.zip`（存储/收缩方法）等容器复用，解码输出为未压缩明文。

use std::fmt;

/// DEFLATE 解码错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeflateError {
    /// 数据损坏（非法码、非法块类型、回溯越界等）。
    Corrupt,
    /// 输入被截断。
    Truncated,
}

impl fmt::Display for DeflateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corrupt => write!(f, "corrupt deflate stream"),
            Self::Truncated => write!(f, "truncated deflate stream"),
        }
    }
}

impl std::error::Error for DeflateError {}

/// Huffman 码长上限（DEFLATE 固定为 15）。
pub(crate) const MAX_BITS: usize = 15;

/// 查找表项：`(码长 << 9) | 符号`；码长 0 表示无效。符号上限 512。
const LOOKUP_SIZE: usize = 1 << MAX_BITS;

/// 规范 Huffman 解码表（LSB-first，即 DEFLATE 的「反转码」）。
pub(crate) struct HuffmanTable {
    lookup: Vec<u16>,
}

impl HuffmanTable {
    /// 由每个符号的码长构建查表（码长 0 表示该符号未出现）。
    pub(crate) fn build(lengths: &[u8]) -> Result<Self, DeflateError> {
        let mut count = [0usize; MAX_BITS + 1];
        for &l in lengths {
            if l as usize > MAX_BITS {
                return Err(DeflateError::Corrupt);
            }
            if l > 0 {
                count[l as usize] += 1;
            }
        }

        // 校验 Kraft 和 <= 1，且「单符号」表必须给予 1 位码（DEFLATE 允许）。
        let mut kraft = 0u64;
        for &l in lengths {
            if l > 0 {
                kraft += 1u64 << (MAX_BITS - l as usize);
            }
        }
        if kraft > (1u64 << MAX_BITS) {
            return Err(DeflateError::Corrupt);
        }

        // 计算 MSB-first 规范码。
        let mut next_code = [0u32; MAX_BITS + 1];
        let mut code = 0u32;
        for bits in 1..=MAX_BITS {
            code = (code + count[bits - 1] as u32) << 1;
            next_code[bits] = code;
        }

        // 反转码（流中实际以 LSB-first 出现），填充查表。
        let mut lookup = vec![0u16; LOOKUP_SIZE];
        for (sym, &l) in lengths.iter().enumerate() {
            if l == 0 {
                continue;
            }
            let len = l as usize;
            let canonical = next_code[len];
            next_code[len] += 1;
            let rev = reverse_bits(canonical, len as u8);
            let step = 1usize << len;
            let entry = ((len as u16) << 9) | sym as u16;
            let mut idx = rev as usize;
            while idx < LOOKUP_SIZE {
                lookup[idx] = entry;
                idx += step;
            }
        }

        Ok(Self { lookup })
    }

    /// 固定字面量/长度表（RFC 1951 §3.2.6）。
    pub(crate) fn fixed_litlen() -> Self {
        let mut lengths = vec![0u8; 288];
        for (i, l) in lengths.iter_mut().enumerate() {
            *l = match i {
                0..=143 => 8,
                144..=255 => 9,
                256..=279 => 7,
                _ => 8,
            };
        }
        Self::build(&lengths).expect("fixed litlen table is always valid")
    }

    /// 固定距离表（RFC 1951 §3.2.6）。
    pub(crate) fn fixed_dist() -> Self {
        Self::build(&[5u8; 30]).expect("fixed dist table is always valid")
    }
}

/// 反转 `value` 的低 `len` 位。
fn reverse_bits(mut value: u32, len: u8) -> u32 {
    let mut out = 0u32;
    for _ in 0..len {
        out = (out << 1) | (value & 1);
        value >>= 1;
    }
    out
}

/// 长度码（257..285）的基值与额外位数，索引为 `code - 257`。
pub(crate) const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
pub(crate) const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// 距离码（0..29）的基值与额外位数。
pub(crate) const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
pub(crate) const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// 码长编码符号的读取顺序（RFC 1951 §3.2.7）。
pub(crate) const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// LSB-first 位读取器，采用 `bit_buf` / `bit_cnt` 缓冲以支持快速查表。
pub(crate) struct BitReader<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) pos: usize,
    bit_buf: u64,
    bit_cnt: u32,
}

impl<'a> BitReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            bit_buf: 0,
            bit_cnt: 0,
        }
    }

    /// 填充位缓冲至至少 `n` 位（不超过 56 位，避免跨界越界）。
    fn ensure(&mut self, n: u32) -> Result<(), DeflateError> {
        while self.bit_cnt < n {
            if self.pos >= self.data.len() {
                return Err(DeflateError::Truncated);
            }
            self.bit_buf |= (self.data[self.pos] as u64) << self.bit_cnt;
            self.bit_cnt += 8;
            self.pos += 1;
        }
        Ok(())
    }

    /// 读取 `n` 位（LSB-first）。
    pub(crate) fn read_bits(&mut self, n: u32) -> Result<u32, DeflateError> {
        self.ensure(n)?;
        let mask = (1u64 << n) - 1;
        let val = (self.bit_buf & mask) as u32;
        self.bit_buf >>= n;
        self.bit_cnt -= n;
        Ok(val)
    }

    /// 解码一个 Huffman 符号。
    ///
    /// 与 [`Self::read_bits`] 不同，此处用「数据耗尽即补零」的窥视方式，因为 DEFLATE
    /// 块末尾的字节对齐填充位按 0 处理，流尾可能不足 [`MAX_BITS`] 个真实位。
    pub(crate) fn decode_symbol(&mut self, table: &HuffmanTable) -> Result<u16, DeflateError> {
        while self.bit_cnt < MAX_BITS as u32 {
            if self.pos >= self.data.len() {
                break;
            }
            self.bit_buf |= (self.data[self.pos] as u64) << self.bit_cnt;
            self.bit_cnt += 8;
            self.pos += 1;
        }
        let idx = (self.bit_buf & ((1u64 << MAX_BITS) - 1)) as usize;
        let entry = table.lookup[idx];
        let len = (entry >> 9) as u32;
        if len == 0 {
            return Err(DeflateError::Corrupt);
        }
        // 若符号所需位数超过实际剩余的位，则输入确已截断。
        if self.bit_cnt < len {
            return Err(DeflateError::Truncated);
        }
        self.bit_buf >>= len;
        self.bit_cnt -= len;
        Ok(entry & 0x1FF)
    }

    /// 丢弃到下一个字节边界（跳过不足一字节的填充位）。
    pub(crate) fn align_byte(&mut self) {
        let skip = self.bit_cnt & 7;
        self.bit_buf >>= skip;
        self.bit_cnt -= skip;
    }
}

/// 解压一段 DEFLATE 压缩数据，返回未压缩明文。
pub fn decompress(input: &[u8]) -> Result<Vec<u8>, DeflateError> {
    decompress_consumed(input).map(|(out, _)| out)
}

/// 解压 DEFLATE 数据，并返回「解压后字节对齐处的偏移」，供容器定位后续字段。
pub fn decompress_consumed(input: &[u8]) -> Result<(Vec<u8>, usize), DeflateError> {
    let mut r = BitReader::new(input);
    let mut out: Vec<u8> = Vec::with_capacity(input.len().saturating_mul(2).max(256));

    let fixed_litlen = HuffmanTable::fixed_litlen();
    let fixed_dist = HuffmanTable::fixed_dist();

    loop {
        let final_block = r.read_bits(1)? == 1;
        let btype = r.read_bits(2)?;

        match btype {
            0 => inflate_stored(&mut r, &mut out)?,
            1 => inflate_huffman(&mut r, &fixed_litlen, &fixed_dist, &mut out)?,
            2 => {
                let (litlen, dist) = read_dynamic_tables(&mut r)?;
                inflate_huffman(&mut r, &litlen, &dist, &mut out)?;
            }
            _ => return Err(DeflateError::Corrupt),
        }

        if final_block {
            break;
        }
    }

    // 对齐到字节边界后，`pos - bit_cnt/8` 即 deflate 载荷实际结束的字节偏移。
    r.align_byte();
    let consumed = r.pos - (r.bit_cnt as usize / 8);
    Ok((out, consumed))
}

/// 存储块：字节对齐后直接复制 `len` 字节（RFC 1951 §3.2.4）。
fn inflate_stored(r: &mut BitReader, out: &mut Vec<u8>) -> Result<(), DeflateError> {
    r.align_byte();
    let len = r.read_bits(16)? as usize;
    let nlen = r.read_bits(16)? as usize;
    if len != (!nlen & 0xFFFF) {
        return Err(DeflateError::Corrupt);
    }
    if r.data.len() - r.pos < len {
        return Err(DeflateError::Truncated);
    }
    out.extend_from_slice(&r.data[r.pos..r.pos + len]);
    r.pos += len;
    Ok(())
}

/// 读取动态 Huffman 块头，构建字面量/长度表与距离表（RFC 1951 §3.2.7）。
fn read_dynamic_tables(r: &mut BitReader) -> Result<(HuffmanTable, HuffmanTable), DeflateError> {
    let hlit = r.read_bits(5)? as usize + 257;
    let hdist = r.read_bits(5)? as usize + 1;
    let hclen = r.read_bits(4)? as usize + 4;

    let mut code_lengths = [0u8; 19];
    for &idx in CODE_LENGTH_ORDER.iter().take(hclen) {
        code_lengths[idx] = r.read_bits(3)? as u8;
    }
    let code_table = HuffmanTable::build(&code_lengths)?;

    let total = hlit + hdist;
    let mut lengths = Vec::with_capacity(total);
    while lengths.len() < total {
        let sym = r.decode_symbol(&code_table)?;
        match sym {
            0..=15 => lengths.push(sym as u8),
            16 => {
                if lengths.is_empty() {
                    return Err(DeflateError::Corrupt);
                }
                let prev = *lengths.last().unwrap();
                let rep = r.read_bits(2)? as usize + 3;
                for _ in 0..rep {
                    lengths.push(prev);
                }
            }
            17 => {
                let rep = r.read_bits(3)? as usize + 3;
                lengths.extend(std::iter::repeat_n(0, rep));
            }
            18 => {
                let rep = r.read_bits(7)? as usize + 11;
                lengths.extend(std::iter::repeat_n(0, rep));
            }
            _ => return Err(DeflateError::Corrupt),
        }
        if lengths.len() > total {
            return Err(DeflateError::Corrupt);
        }
    }

    let litlen = HuffmanTable::build(&lengths[..hlit])?;
    let dist = HuffmanTable::build(&lengths[hlit..])?;
    Ok((litlen, dist))
}

/// 解压一个 Huffman 编码块（固定或动态表）。
fn inflate_huffman(
    r: &mut BitReader,
    litlen: &HuffmanTable,
    dist: &HuffmanTable,
    out: &mut Vec<u8>,
) -> Result<(), DeflateError> {
    loop {
        let sym = r.decode_symbol(litlen)?;
        match sym {
            // 字面量。
            0..=255 => out.push(sym as u8),
            // 块结束。
            256 => return Ok(()),
            // 长度 + 距离匹配。
            257..=285 => {
                let li = (sym - 257) as usize;
                let length =
                    LENGTH_BASE[li] as usize + r.read_bits(LENGTH_EXTRA[li] as u32)? as usize;
                let dsym = r.decode_symbol(dist)?;
                let distance = DIST_BASE[dsym as usize] as usize
                    + r.read_bits(DIST_EXTRA[dsym as usize] as u32)? as usize;
                if distance == 0 || distance > out.len() {
                    return Err(DeflateError::Corrupt);
                }
                copy_match(out, length, distance);
            }
            _ => return Err(DeflateError::Corrupt),
        }
    }
}

/// 从输出历史中回拷 `length` 字节，回溯距离为 `distance`（可重叠，逐字节复制）。
fn copy_match(out: &mut Vec<u8>, length: usize, distance: usize) {
    let start = out.len() - distance;
    for i in 0..length {
        let b = out[start + i];
        out.push(b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 用 zlib 的固定 Huffman 表编码一段数据，返回 DEFLATE 字节流。
    fn encode_fixed(data: &[u8]) -> Vec<u8> {
        let mut bits = Vec::<bool>::new();
        // BFINAL=1, BTYPE=01（LSB-first）。
        bits.push(true);
        bits.push(true);
        bits.push(false);

        // 完整固定码长表（288 符号，RFC 1951 §3.2.6）。
        let mut lens = [0u8; 288];
        for (i, l) in lens.iter_mut().enumerate() {
            *l = match i {
                0..=143 => 8,
                144..=255 => 9,
                256..=279 => 7,
                _ => 8,
            };
        }
        let codes = canonical_codes(&lens);

        // 输出字面量（码为反转码，LSB-first 写出）。
        for &b in data {
            let sym = b as usize;
            push_code(&mut bits, codes[sym], lens[sym]);
        }
        // EOB。
        push_code(&mut bits, codes[256], lens[256]);

        bits_to_bytes(&bits)
    }

    /// 由码长计算 MSB-first 规范码。
    fn canonical_codes(lens: &[u8]) -> Vec<u32> {
        let mut count = [0u32; 16];
        for &l in lens {
            if l > 0 {
                count[l as usize] += 1;
            }
        }
        let mut next = [0u32; 16];
        let mut code = 0u32;
        for bits_len in 1..=15 {
            code = (code + count[bits_len - 1]) << 1;
            next[bits_len] = code;
        }
        let mut codes = vec![0u32; lens.len()];
        let mut assign = next;
        for (sym, &l) in lens.iter().enumerate() {
            if l > 0 {
                codes[sym] = assign[l as usize];
                assign[l as usize] += 1;
            }
        }
        codes
    }

    fn push_code(bits: &mut Vec<bool>, code: u32, len: u8) {
        // Huffman 码按 MSB-first 传输（RFC 1951 §3.1.1）。
        for i in (0..len).rev() {
            bits.push(code & (1 << i) != 0);
        }
    }

    fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bits.len().div_ceil(8));
        let mut byte = 0u8;
        let mut n = 0u8;
        for &b in bits {
            if b {
                byte |= 1 << n;
            }
            n += 1;
            if n == 8 {
                out.push(byte);
                byte = 0;
                n = 0;
            }
        }
        if n > 0 {
            out.push(byte);
        }
        out
    }

    #[test]
    fn stored_block_roundtrip() {
        // 手工构造一个存储块：BFINAL=1, BTYPE=00, 对齐, LEN/NLEN, 数据。
        let payload = b"hello stored block";
        // BFINAL=1，BTYPE=00（LSB 优先）。
        let bits = vec![true, false, false];
        let mut bytes = bits_to_bytes(&bits);

        let len = payload.len() as u16;
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&(!len).to_le_bytes());
        bytes.extend_from_slice(payload);

        assert_eq!(decompress(&bytes).unwrap(), payload);
    }

    #[test]
    fn fixed_huffman_roundtrip() {
        let data = b"The quick brown fox jumps over the lazy dog. 0123456789";
        let encoded = encode_fixed(data);
        assert_eq!(decompress(&encoded).unwrap(), data);
    }

    #[test]
    fn empty_input() {
        assert_eq!(decompress(b"").unwrap_err(), DeflateError::Truncated);
    }

    #[test]
    fn truncated_stream() {
        let data = b"some data";
        let encoded = encode_fixed(data);
        for cut in 0..encoded.len() {
            let r = decompress(&encoded[..cut]);
            if let Ok(decoded) = r {
                assert_eq!(decoded, data);
            }
        }
    }

    #[test]
    fn reserved_block_type() {
        // BFINAL=1, BTYPE=11。
        let bits = vec![true, true, true];
        assert_eq!(
            decompress(&bits_to_bytes(&bits)).unwrap_err(),
            DeflateError::Corrupt
        );
    }

    #[test]
    fn overlapping_match_copies_correctly() {
        // 直接测试 copy_match 的重叠语义（"abc" 距离 3，长度 5 → "abcabcab"）。
        let mut out = b"abc".to_vec();
        copy_match(&mut out, 5, 3);
        assert_eq!(out, b"abcabcab");
    }
}
