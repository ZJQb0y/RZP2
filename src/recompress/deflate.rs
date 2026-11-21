//! DEFLATE 流重压缩（precomp 式）。
//!
//! 把一段原始 DEFLATE 流 Huffman 解码到「符号层」（字面量 / 长度-距离匹配 / 块结构 /
//! 原始动态 Huffman 表），再序列化成对 LZMA 更友好的字节表示；反过程用保存的表
//! 重新编码出**逐位一致**的原始 DEFLATE 流，实现字节级无损还原。
//!
//! 与 [`crate::formats::deflate`] 的纯解压不同，这里保留块边界与动态 Huffman 表的
//! 原始编码（含码长 RLE 的额外位），因此重编码结果与原流 bit-for-bit 一致。

use crate::formats::deflate::{
    BitReader, DeflateError, HuffmanTable, CODE_LENGTH_ORDER, DIST_EXTRA, LENGTH_EXTRA,
};

/// 一个 DEFLATE 块。
#[derive(Debug, Clone)]
enum Block {
    /// 存储块（BTYPE=0），`data` 为原始字节。
    Stored { last: bool, data: Vec<u8> },
    /// Huffman 编码块（BTYPE=1 固定 / BTYPE=2 动态）。
    Huffman {
        last: bool,
        fixed: bool,
        /// 动态块的表定义（固定块为 `None`）。
        dyn_table: Option<DynamicTables>,
        tokens: Vec<Token>,
    },
}

/// 符号层 token。
#[derive(Debug, Clone)]
enum Token {
    /// 字面量字节。
    Literal(u8),
    /// 长度-距离匹配。保留原始符号与额外位，避免长度 258 的「双编码」歧义，
    /// 从而逐位还原原始 DEFLATE 流。
    Match {
        /// 长度符号（257..=285）。
        length_sym: u16,
        /// 长度额外位原始值。
        length_extra: u16,
        /// 距离符号（0..=29）。
        dist_sym: u16,
        /// 距离额外位原始值。
        dist_extra: u16,
    },
    /// 块结束（EOB）。
    Eob,
}

/// 动态 Huffman 块的表定义（保留原始码长 RLE 编码，保证可逐位还原）。
#[derive(Debug, Clone)]
struct DynamicTables {
    /// 字面量/长度码数量（257..=286）。
    hlit: u16,
    /// 距离码数量（1..=32）。
    hdist: u16,
    /// 码长码数量（4..=19）。
    hclen: u8,
    /// 码长码的码长（按 `CODE_LENGTH_ORDER` 顺序索引）。
    cl_lengths: [u8; 19],
    /// 码长 RLE 符号序列（含 16/17/18 的额外位）。
    cl_symbols: Vec<ClSymbol>,
}

/// 码长 RLE 序列中的一个符号。
#[derive(Debug, Clone)]
struct ClSymbol {
    /// 符号 0..=18。
    symbol: u8,
    /// 16/17/18 的额外位（其余为 0）。
    extra: u8,
}

/// 重压缩一段原始 DEFLATE 流。
pub fn recompress(input: &[u8]) -> Result<Vec<u8>, DeflateError> {
    let blocks = parse_deflate(input)?;
    Ok(serialize_blocks(&blocks))
}

/// 由重压缩表示重建原始 DEFLATE 流。
pub fn reconstruct(input: &[u8]) -> Result<Vec<u8>, DeflateError> {
    let blocks = deserialize_blocks(input)?;
    Ok(encode_blocks(&blocks))
}

// ---------------------------------------------------------------------------
// 解析（DEFLATE 位流 → 块结构）
// ---------------------------------------------------------------------------

fn parse_deflate(input: &[u8]) -> Result<Vec<Block>, DeflateError> {
    let mut r = BitReader::new(input);
    let fixed_litlen = HuffmanTable::fixed_litlen();
    let fixed_dist = HuffmanTable::fixed_dist();
    let mut blocks = Vec::new();

    loop {
        let last = r.read_bits(1)? == 1;
        let btype = r.read_bits(2)?;
        match btype {
            0 => {
                r.align_byte();
                let len = r.read_bits(16)? as usize;
                let nlen = r.read_bits(16)? as usize;
                if len != (!nlen & 0xFFFF) {
                    return Err(DeflateError::Corrupt);
                }
                if r.data.len().saturating_sub(r.pos) < len {
                    return Err(DeflateError::Truncated);
                }
                let data = r.data[r.pos..r.pos + len].to_vec();
                r.pos += len;
                blocks.push(Block::Stored { last, data });
            }
            1 => {
                let tokens = parse_huffman_tokens(&mut r, &fixed_litlen, &fixed_dist)?;
                blocks.push(Block::Huffman {
                    last,
                    fixed: true,
                    dyn_table: None,
                    tokens,
                });
            }
            2 => {
                let (dyn_table, tokens) = parse_dynamic(&mut r)?;
                blocks.push(Block::Huffman {
                    last,
                    fixed: false,
                    dyn_table: Some(dyn_table),
                    tokens,
                });
            }
            _ => return Err(DeflateError::Corrupt),
        }
        if last {
            break;
        }
    }

    Ok(blocks)
}

fn parse_huffman_tokens(
    r: &mut BitReader,
    litlen: &HuffmanTable,
    dist: &HuffmanTable,
) -> Result<Vec<Token>, DeflateError> {
    let mut tokens = Vec::new();
    loop {
        let sym = r.decode_symbol(litlen)?;
        match sym {
            0..=255 => tokens.push(Token::Literal(sym as u8)),
            256 => {
                tokens.push(Token::Eob);
                return Ok(tokens);
            }
            257..=285 => {
                let li = (sym - 257) as usize;
                let length_extra = r.read_bits(LENGTH_EXTRA[li] as u32)? as u16;
                let dist_sym = r.decode_symbol(dist)? as u16;
                let dist_extra = r.read_bits(DIST_EXTRA[dist_sym as usize] as u32)? as u16;
                tokens.push(Token::Match {
                    length_sym: sym,
                    length_extra,
                    dist_sym,
                    dist_extra,
                });
            }
            _ => return Err(DeflateError::Corrupt),
        }
    }
}

fn parse_dynamic(r: &mut BitReader) -> Result<(DynamicTables, Vec<Token>), DeflateError> {
    let hlit = r.read_bits(5)? as u16 + 257;
    let hdist = r.read_bits(5)? as u16 + 1;
    let hclen = r.read_bits(4)? as u16 + 4;

    let mut cl_lengths = [0u8; 19];
    for (i, &idx) in CODE_LENGTH_ORDER.iter().enumerate() {
        if i < hclen as usize {
            cl_lengths[idx] = r.read_bits(3)? as u8;
        }
    }
    let cl_table = HuffmanTable::build(&cl_lengths)?;

    let total = hlit as usize + hdist as usize;
    let mut cl_symbols = Vec::new();
    let mut lengths = Vec::with_capacity(total);
    while lengths.len() < total {
        let sym = r.decode_symbol(&cl_table)? as u8;
        match sym {
            0..=15 => {
                lengths.push(sym);
                cl_symbols.push(ClSymbol { symbol: sym, extra: 0 });
            }
            16 => {
                let extra = r.read_bits(2)? as u8;
                if lengths.is_empty() {
                    return Err(DeflateError::Corrupt);
                }
                let prev = *lengths.last().unwrap();
                let rep = extra as usize + 3;
                for _ in 0..rep {
                    lengths.push(prev);
                }
                cl_symbols.push(ClSymbol { symbol: 16, extra });
            }
            17 => {
                let extra = r.read_bits(3)? as u8;
                let rep = extra as usize + 3;
                for _ in 0..rep {
                    lengths.push(0);
                }
                cl_symbols.push(ClSymbol { symbol: 17, extra });
            }
            18 => {
                let extra = r.read_bits(7)? as u8;
                let rep = extra as usize + 11;
                for _ in 0..rep {
                    lengths.push(0);
                }
                cl_symbols.push(ClSymbol { symbol: 18, extra });
            }
            _ => return Err(DeflateError::Corrupt),
        }
        if lengths.len() > total {
            return Err(DeflateError::Corrupt);
        }
    }

    let litlen = HuffmanTable::build(&lengths[..hlit as usize])?;
    let dist = HuffmanTable::build(&lengths[hlit as usize..])?;
    let tokens = parse_huffman_tokens(r, &litlen, &dist)?;

    Ok((
        DynamicTables {
            hlit,
            hdist,
            hclen: hclen as u8,
            cl_lengths,
            cl_symbols,
        },
        tokens,
    ))
}

// ---------------------------------------------------------------------------
// 序列化 / 反序列化（块结构 ↔ 字节）
// ---------------------------------------------------------------------------

fn serialize_blocks(blocks: &[Block]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(1u8); // 版本号
    for block in blocks {
        match block {
            Block::Stored { last, data } => {
                out.push((*last as u8) | (0 << 1));
                out.extend_from_slice(&(data.len() as u16).to_le_bytes());
                out.extend_from_slice(data);
            }
            Block::Huffman {
                last,
                fixed,
                dyn_table,
                tokens,
            } => {
                let btype = if *fixed { 1u8 } else { 2u8 };
                out.push((*last as u8) | (btype << 1));
                if let Some(dyn_table) = dyn_table {
                    out.extend_from_slice(&dyn_table.hlit.to_le_bytes());
                    out.extend_from_slice(&dyn_table.hdist.to_le_bytes());
                    out.push(dyn_table.hclen);
                    for i in 0..dyn_table.hclen as usize {
                        out.push(dyn_table.cl_lengths[CODE_LENGTH_ORDER[i]]);
                    }
                    out.extend_from_slice(&(dyn_table.cl_symbols.len() as u16).to_le_bytes());
                    for cs in &dyn_table.cl_symbols {
                        out.push(cs.symbol);
                        match cs.symbol {
                            16 | 17 | 18 => out.push(cs.extra),
                            _ => {}
                        }
                    }
                }
                serialize_tokens(&mut out, tokens);
            }
        }
    }
    out
}

fn serialize_tokens(out: &mut Vec<u8>, tokens: &[Token]) {
    let mut i = 0usize;
    while i < tokens.len() {
        match tokens[i] {
            Token::Literal(_) => {
                let start = i;
                while i < tokens.len() && matches!(tokens[i], Token::Literal(_)) {
                    i += 1;
                }
                let run_len = (i - start) as u32;
                out.push(0); // 控制字节：字面量连续段
                out.extend_from_slice(&run_len.to_le_bytes());
                for t in &tokens[start..i] {
                    if let Token::Literal(b) = t {
                        out.push(*b);
                    }
                }
            }
            Token::Match {
                length_sym,
                length_extra,
                dist_sym,
                dist_extra,
            } => {
                out.push(1); // 控制字节：匹配
                out.extend_from_slice(&length_sym.to_le_bytes());
                out.extend_from_slice(&length_extra.to_le_bytes());
                out.extend_from_slice(&dist_sym.to_le_bytes());
                out.extend_from_slice(&dist_extra.to_le_bytes());
                i += 1;
            }
            Token::Eob => {
                out.push(2); // 控制字节：块结束
                i += 1;
            }
        }
    }
}

fn deserialize_blocks(input: &[u8]) -> Result<Vec<Block>, DeflateError> {
    if input.first() != Some(&1u8) {
        return Err(DeflateError::Corrupt);
    }
    let mut pos = 1usize;
    let mut blocks = Vec::new();

    while pos < input.len() {
        let header = *input.get(pos).ok_or(DeflateError::Truncated)?;
        pos += 1;
        let last = header & 1 != 0;
        let btype = (header >> 1) & 0x3;
        match btype {
            0 => {
                let len = read_u16(input, &mut pos)? as usize;
                if input.len().saturating_sub(pos) < len {
                    return Err(DeflateError::Truncated);
                }
                let data = input[pos..pos + len].to_vec();
                pos += len;
                blocks.push(Block::Stored { last, data });
            }
            1 => {
                let tokens = deserialize_tokens(input, &mut pos)?;
                blocks.push(Block::Huffman {
                    last,
                    fixed: true,
                    dyn_table: None,
                    tokens,
                });
            }
            2 => {
                let hlit = read_u16(input, &mut pos)?;
                let hdist = read_u16(input, &mut pos)?;
                let hclen = *input.get(pos).ok_or(DeflateError::Truncated)?;
                pos += 1;
                if !(257..=286).contains(&hlit)
                    || !(1..=32).contains(&hdist)
                    || !(4..=19).contains(&hclen)
                {
                    return Err(DeflateError::Corrupt);
                }
                let mut cl_lengths = [0u8; 19];
                for i in 0..hclen as usize {
                    cl_lengths[CODE_LENGTH_ORDER[i]] = *input.get(pos).ok_or(DeflateError::Truncated)?;
                    pos += 1;
                }
                let count = read_u16(input, &mut pos)? as usize;
                let mut cl_symbols = Vec::with_capacity(count);
                for _ in 0..count {
                    let symbol = *input.get(pos).ok_or(DeflateError::Truncated)?;
                    pos += 1;
                    let extra = match symbol {
                        16 | 17 | 18 => {
                            let e = *input.get(pos).ok_or(DeflateError::Truncated)?;
                            pos += 1;
                            e
                        }
                        0..=15 => 0,
                        _ => return Err(DeflateError::Corrupt),
                    };
                    cl_symbols.push(ClSymbol { symbol, extra });
                }
                let dyn_table = DynamicTables {
                    hlit,
                    hdist,
                    hclen,
                    cl_lengths,
                    cl_symbols,
                };
                // 展开码长以校验一致性，避免后续越界。
                let expanded = expand_cl(&dyn_table)?;
                if expanded.len() != hlit as usize + hdist as usize {
                    return Err(DeflateError::Corrupt);
                }
                let tokens = deserialize_tokens(input, &mut pos)?;
                blocks.push(Block::Huffman {
                    last,
                    fixed: false,
                    dyn_table: Some(dyn_table),
                    tokens,
                });
            }
            _ => return Err(DeflateError::Corrupt),
        }
    }

    Ok(blocks)
}

fn deserialize_tokens(input: &[u8], pos: &mut usize) -> Result<Vec<Token>, DeflateError> {
    let mut tokens = Vec::new();
    loop {
        let control = *input.get(*pos).ok_or(DeflateError::Truncated)?;
        *pos += 1;
        match control {
            0 => {
                let run_len = read_u32(input, pos)? as usize;
                if input.len().saturating_sub(*pos) < run_len {
                    return Err(DeflateError::Truncated);
                }
                for &b in &input[*pos..*pos + run_len] {
                    tokens.push(Token::Literal(b));
                }
                *pos += run_len;
            }
            1 => {
                let length_sym = read_u16(input, pos)?;
                let length_extra = read_u16(input, pos)?;
                let dist_sym = read_u16(input, pos)?;
                let dist_extra = read_u16(input, pos)?;
                if !(257..=285).contains(&length_sym) || !(0..=29).contains(&dist_sym) {
                    return Err(DeflateError::Corrupt);
                }
                let lextra_bits = LENGTH_EXTRA[(length_sym - 257) as usize] as u32;
                let dextra_bits = DIST_EXTRA[dist_sym as usize] as u32;
                if length_extra >= (1u16 << lextra_bits) || dist_extra >= (1u16 << dextra_bits) {
                    return Err(DeflateError::Corrupt);
                }
                tokens.push(Token::Match {
                    length_sym,
                    length_extra,
                    dist_sym,
                    dist_extra,
                });
            }
            2 => {
                tokens.push(Token::Eob);
                return Ok(tokens);
            }
            _ => return Err(DeflateError::Corrupt),
        }
    }
}

fn read_u16(input: &[u8], pos: &mut usize) -> Result<u16, DeflateError> {
    let b = input
        .get(*pos..*pos + 2)
        .ok_or(DeflateError::Truncated)?;
    *pos += 2;
    Ok(u16::from_le_bytes(b.try_into().unwrap()))
}

fn read_u32(input: &[u8], pos: &mut usize) -> Result<u32, DeflateError> {
    let b = input
        .get(*pos..*pos + 4)
        .ok_or(DeflateError::Truncated)?;
    *pos += 4;
    Ok(u32::from_le_bytes(b.try_into().unwrap()))
}

fn expand_cl(dyn_table: &DynamicTables) -> Result<Vec<u8>, DeflateError> {
    let mut out = Vec::new();
    for cs in &dyn_table.cl_symbols {
        match cs.symbol {
            0..=15 => out.push(cs.symbol),
            16 => {
                let prev = *out.last().ok_or(DeflateError::Corrupt)?;
                let rep = cs.extra as usize + 3;
                for _ in 0..rep {
                    out.push(prev);
                }
            }
            17 => {
                let rep = cs.extra as usize + 3;
                for _ in 0..rep {
                    out.push(0);
                }
            }
            18 => {
                let rep = cs.extra as usize + 11;
                for _ in 0..rep {
                    out.push(0);
                }
            }
            _ => return Err(DeflateError::Corrupt),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// 重编码（块结构 → 原始 DEFLATE 位流）
// ---------------------------------------------------------------------------

struct BitWriter {
    out: Vec<u8>,
    acc: u32,
    nbits: u32,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            out: Vec::new(),
            acc: 0,
            nbits: 0,
        }
    }

    fn write_bit(&mut self, bit: bool) {
        self.acc |= (bit as u32) << self.nbits;
        self.nbits += 1;
        if self.nbits == 8 {
            self.out.push(self.acc as u8);
            self.acc = 0;
            self.nbits = 0;
        }
    }

    /// LSB-first 写 `n` 位（用于头部字段 / 额外位 / 存储块字节）。
    fn write_lsb(&mut self, value: u32, n: u32) {
        for i in 0..n {
            self.write_bit((value >> i) & 1 != 0);
        }
    }

    /// MSB-first 写 `n` 位（用于 Huffman 码）。
    fn write_msb(&mut self, value: u32, n: u32) {
        for i in (0..n).rev() {
            self.write_bit((value >> i) & 1 != 0);
        }
    }

    fn align_byte(&mut self) {
        if self.nbits > 0 {
            self.out.push(self.acc as u8);
            self.acc = 0;
            self.nbits = 0;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        self.align_byte();
        self.out
    }
}

fn canonical_codes(lengths: &[u8]) -> Vec<u32> {
    let mut count = [0u32; 16];
    for &l in lengths {
        if l > 0 {
            count[l as usize] += 1;
        }
    }
    let mut next = [0u32; 16];
    let mut code = 0u32;
    for bits in 1..=15 {
        code = (code + count[bits - 1]) << 1;
        next[bits] = code;
    }
    let mut codes = vec![0u32; lengths.len()];
    for (sym, &l) in lengths.iter().enumerate() {
        if l > 0 {
            codes[sym] = next[l as usize];
            next[l as usize] += 1;
        }
    }
    codes
}

fn fixed_litlen_lengths() -> Vec<u8> {
    let mut lengths = vec![0u8; 288];
    for (i, l) in lengths.iter_mut().enumerate() {
        *l = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    lengths
}

fn fixed_dist_lengths() -> Vec<u8> {
    vec![5u8; 30]
}

fn encode_blocks(blocks: &[Block]) -> Vec<u8> {
    let mut w = BitWriter::new();
    let fixed_litlen_lens = fixed_litlen_lengths();
    let fixed_dist_lens = fixed_dist_lengths();
    let fixed_litlen_codes = canonical_codes(&fixed_litlen_lens);
    let fixed_dist_codes = canonical_codes(&fixed_dist_lens);

    for block in blocks {
        match block {
            Block::Stored { last, data } => {
                w.write_lsb(*last as u32, 1);
                w.write_lsb(0, 2);
                w.align_byte();
                let len = data.len() as u32;
                w.write_lsb(len, 16);
                w.write_lsb(!len & 0xFFFF, 16);
                for &b in data {
                    w.write_lsb(b as u32, 8);
                }
            }
            Block::Huffman {
                last,
                fixed,
                dyn_table,
                tokens,
            } => {
                w.write_lsb(*last as u32, 1);
                if *fixed {
                    w.write_lsb(1, 2);
                    encode_tokens(
                        &mut w,
                        tokens,
                        &fixed_litlen_codes,
                        &fixed_litlen_lens,
                        &fixed_dist_codes,
                        &fixed_dist_lens,
                    );
                } else {
                    let dyn_table = dyn_table.as_ref().expect("dynamic table present");
                    w.write_lsb(2, 2);
                    w.write_lsb((dyn_table.hlit - 257) as u32, 5);
                    w.write_lsb((dyn_table.hdist - 1) as u32, 5);
                    w.write_lsb((dyn_table.hclen - 4) as u32, 4);
                    for i in 0..dyn_table.hclen as usize {
                        w.write_lsb(dyn_table.cl_lengths[CODE_LENGTH_ORDER[i]] as u32, 3);
                    }
                    let cl_codes = canonical_codes(&dyn_table.cl_lengths);
                    for cs in &dyn_table.cl_symbols {
                        w.write_msb(cl_codes[cs.symbol as usize], dyn_table.cl_lengths[cs.symbol as usize] as u32);
                        match cs.symbol {
                            16 => w.write_lsb(cs.extra as u32, 2),
                            17 => w.write_lsb(cs.extra as u32, 3),
                            18 => w.write_lsb(cs.extra as u32, 7),
                            _ => {}
                        }
                    }
                    let expanded = expand_cl(dyn_table).expect("validated at parse time");
                    let litlen_lens = &expanded[..dyn_table.hlit as usize];
                    let dist_lens = &expanded[dyn_table.hlit as usize..];
                    let litlen_codes = canonical_codes(litlen_lens);
                    let dist_codes = canonical_codes(dist_lens);
                    encode_tokens(
                        &mut w,
                        tokens,
                        &litlen_codes,
                        litlen_lens,
                        &dist_codes,
                        dist_lens,
                    );
                }
            }
        }
    }

    w.finish()
}

fn encode_tokens(
    w: &mut BitWriter,
    tokens: &[Token],
    litlen_codes: &[u32],
    litlen_lens: &[u8],
    dist_codes: &[u32],
    dist_lens: &[u8],
) {
    for token in tokens {
        match token {
            Token::Literal(b) => {
                let sym = *b as usize;
                w.write_msb(litlen_codes[sym], litlen_lens[sym] as u32);
            }
            Token::Match {
                length_sym,
                length_extra,
                dist_sym,
                dist_extra,
            } => {
                let length_sym = *length_sym as usize;
                let length_extra = *length_extra as u32;
                let dist_sym = *dist_sym as usize;
                let dist_extra = *dist_extra as u32;
                let li = length_sym - 257;
                w.write_msb(litlen_codes[length_sym], litlen_lens[length_sym] as u32);
                w.write_lsb(length_extra, LENGTH_EXTRA[li] as u32);
                w.write_msb(dist_codes[dist_sym], dist_lens[dist_sym] as u32);
                w.write_lsb(dist_extra, DIST_EXTRA[dist_sym] as u32);
            }
            Token::Eob => {
                w.write_msb(litlen_codes[256], litlen_lens[256] as u32);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::deflate::{DIST_BASE, LENGTH_BASE};

    /// 由实际长度反查规范长度符号（仅测试用：测试数据不含长度 258 的双编码歧义）。
    fn length_symbol(length: u16) -> (usize, u32, u32) {
        for li in 0..LENGTH_BASE.len() {
            let base = LENGTH_BASE[li] as u32;
            let extra_bits = LENGTH_EXTRA[li] as u32;
            let max = base + ((1u32 << extra_bits) - 1);
            if length as u32 >= base && length as u32 <= max {
                return (257 + li, base, extra_bits);
            }
        }
        unreachable!("invalid length {length}")
    }

    /// 由实际距离反查规范距离符号（仅测试用）。
    fn distance_symbol(distance: u16) -> (usize, u32, u32) {
        for di in 0..DIST_BASE.len() {
            let base = DIST_BASE[di] as u32;
            let extra_bits = DIST_EXTRA[di] as u32;
            let max = base + ((1u32 << extra_bits) - 1);
            if distance as u32 >= base && distance as u32 <= max {
                return (di, base, extra_bits);
            }
        }
        unreachable!("invalid distance {distance}")
    }

    // ---------------------------------------------------------------------
    // 最小 DEFLATE 编码器（仅测试用）：存储块 / 固定 Huffman / 动态 Huffman。
    // ---------------------------------------------------------------------

    fn write_stored(w: &mut BitWriter, data: &[u8], last: bool) {
        w.write_lsb(last as u32, 1);
        w.write_lsb(0, 2);
        w.align_byte();
        let len = data.len() as u32;
        w.write_lsb(len, 16);
        w.write_lsb(!len & 0xFFFF, 16);
        for &b in data {
            w.write_lsb(b as u32, 8);
        }
    }

    fn write_fixed_literals(w: &mut BitWriter, data: &[u8], last: bool) {
        let lens = fixed_litlen_lengths();
        let codes = canonical_codes(&lens);
        w.write_lsb(last as u32, 1);
        w.write_lsb(1, 2);
        for &b in data {
            w.write_msb(codes[b as usize], lens[b as usize] as u32);
        }
        w.write_msb(codes[256], lens[256] as u32);
    }

    fn write_fixed_match(w: &mut BitWriter, length: u16, distance: u16, last: bool) {
        let ll = fixed_litlen_lengths();
        let dl = fixed_dist_lengths();
        let lc = canonical_codes(&ll);
        let dc = canonical_codes(&dl);
        let (lsym, lbase, lbits) = length_symbol(length);
        let (dsym, dbase, dbits) = distance_symbol(distance);
        w.write_lsb(last as u32, 1);
        w.write_lsb(1, 2);
        w.write_msb(lc[b'a' as usize], ll[b'a' as usize] as u32);
        w.write_msb(lc[lsym], ll[lsym] as u32);
        w.write_lsb(length as u32 - lbase, lbits);
        w.write_msb(dc[dsym], dl[dsym] as u32);
        w.write_lsb(distance as u32 - dbase, dbits);
        w.write_msb(lc[256], ll[256] as u32);
    }

    fn encode_stored(data: &[u8], last: bool) -> Vec<u8> {
        let mut w = BitWriter::new();
        write_stored(&mut w, data, last);
        w.finish()
    }

    fn encode_fixed_literals(data: &[u8], last: bool) -> Vec<u8> {
        let mut w = BitWriter::new();
        write_fixed_literals(&mut w, data, last);
        w.finish()
    }

    fn encode_fixed_match(length: u16, distance: u16, last: bool) -> Vec<u8> {
        let mut w = BitWriter::new();
        write_fixed_match(&mut w, length, distance, last);
        w.finish()
    }

    fn rle_code_lengths(lengths: &[u8]) -> Vec<ClSymbol> {
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < lengths.len() {
            let cur = lengths[i];
            let mut j = i + 1;
            while j < lengths.len() && lengths[j] == cur {
                j += 1;
            }
            let run = j - i;
            if cur == 0 {
                let mut remaining = run;
                while remaining >= 11 {
                    let take = remaining.min(138);
                    out.push(ClSymbol { symbol: 18, extra: (take - 11) as u8 });
                    remaining -= take;
                }
                while remaining >= 3 {
                    let take = remaining.min(10);
                    out.push(ClSymbol { symbol: 17, extra: (take - 3) as u8 });
                    remaining -= take;
                }
                for _ in 0..remaining {
                    out.push(ClSymbol { symbol: 0, extra: 0 });
                }
            } else {
                out.push(ClSymbol { symbol: cur, extra: 0 });
                let mut remaining = run - 1;
                while remaining >= 3 {
                    let take = remaining.min(6);
                    out.push(ClSymbol { symbol: 16, extra: (take - 3) as u8 });
                    remaining -= take;
                }
                for _ in 0..remaining {
                    out.push(ClSymbol { symbol: cur, extra: 0 });
                }
            }
            i = j;
        }
        out
    }

    fn huffman_lengths(freqs: &[u32]) -> Vec<u8> {
        use std::cmp::Reverse;
        use std::collections::BinaryHeap;

        let n = freqs.len();
        let mut parent = vec![0usize; 2 * n];
        let mut heap: BinaryHeap<Reverse<(u32, usize)>> = BinaryHeap::new();
        for (i, &f) in freqs.iter().enumerate() {
            if f > 0 {
                heap.push(Reverse((f, i)));
            }
        }
        let mut lens = vec![0u8; n];
        if heap.is_empty() {
            return lens;
        }
        if heap.len() == 1 {
            let (_, sym) = heap.pop().unwrap().0;
            lens[sym] = 1;
            return lens;
        }
        let mut next_id = n;
        while heap.len() > 1 {
            let (w1, a) = heap.pop().unwrap().0;
            let (w2, b) = heap.pop().unwrap().0;
            parent[a] = next_id;
            parent[b] = next_id;
            heap.push(Reverse((w1 + w2, next_id)));
            next_id += 1;
        }
        for i in 0..n {
            if freqs[i] > 0 {
                let mut depth = 0u8;
                let mut cur = i;
                while parent[cur] != 0 {
                    depth += 1;
                    cur = parent[cur];
                }
                lens[i] = depth;
            }
        }
        lens
    }

    fn write_dynamic(w: &mut BitWriter, litlen: &[u8], dist: &[u8], data: &[u8], last: bool) {
        let hlit = litlen.len() as u16;
        let hdist = dist.len() as u16;
        let mut all = Vec::with_capacity(litlen.len() + dist.len());
        all.extend_from_slice(litlen);
        all.extend_from_slice(dist);

        let cl_symbols = rle_code_lengths(&all);

        let mut freqs = [0u32; 19];
        for cs in &cl_symbols {
            freqs[cs.symbol as usize] += 1;
        }
        let cl_lengths = huffman_lengths(&freqs);
        let mut hclen = 19usize;
        while hclen > 4 && cl_lengths[CODE_LENGTH_ORDER[hclen - 1]] == 0 {
            hclen -= 1;
        }
        let cl_codes = canonical_codes(&cl_lengths);
        let lc = canonical_codes(litlen);

        w.write_lsb(last as u32, 1);
        w.write_lsb(2, 2);
        w.write_lsb((hlit - 257) as u32, 5);
        w.write_lsb((hdist - 1) as u32, 5);
        w.write_lsb((hclen - 4) as u32, 4);
        for i in 0..hclen {
            w.write_lsb(cl_lengths[CODE_LENGTH_ORDER[i]] as u32, 3);
        }
        for cs in &cl_symbols {
            w.write_msb(cl_codes[cs.symbol as usize], cl_lengths[cs.symbol as usize] as u32);
            match cs.symbol {
                16 => w.write_lsb(cs.extra as u32, 2),
                17 => w.write_lsb(cs.extra as u32, 3),
                18 => w.write_lsb(cs.extra as u32, 7),
                _ => {}
            }
        }
        for &b in data {
            w.write_msb(lc[b as usize], litlen[b as usize] as u32);
        }
        w.write_msb(lc[256], litlen[256] as u32);
    }

    fn encode_dynamic(litlen: &[u8], dist: &[u8], data: &[u8], last: bool) -> Vec<u8> {
        let mut w = BitWriter::new();
        write_dynamic(&mut w, litlen, dist, data, last);
        w.finish()
    }

    fn roundtrip(stream: &[u8]) {
        let packed = recompress(stream).unwrap();
        let rebuilt = reconstruct(&packed).unwrap();
        assert_eq!(rebuilt, stream, "重压缩往返未逐位还原");
    }

    #[test]
    fn stored_block_roundtrip() {
        roundtrip(&encode_stored(b"stored block payload", true));
    }

    #[test]
    fn fixed_literals_roundtrip() {
        roundtrip(&encode_fixed_literals(b"The quick brown fox jumps over the lazy dog", true));
    }

    #[test]
    fn fixed_match_roundtrip() {
        let stream = encode_fixed_match(4, 1, true);
        roundtrip(&stream);
        // 语义校验：'a' + 长度 4 距离 1 的回溯 → "aaaaa"。
        assert_eq!(crate::formats::deflate::decompress(&stream).unwrap(), b"aaaaa");
    }

    #[test]
    fn dynamic_block_roundtrip() {
        let mut litlen = vec![0u8; 257];
        for i in 0..=143 {
            litlen[i] = 8;
        }
        for i in 144..=255 {
            litlen[i] = 9;
        }
        litlen[256] = 7;
        let dist = vec![1u8];
        let stream = encode_dynamic(&litlen, &dist, b"hello dynamic deflate block", true);
        roundtrip(&stream);
        assert_eq!(
            crate::formats::deflate::decompress(&stream).unwrap(),
            b"hello dynamic deflate block"
        );
    }

    #[test]
    fn multi_block_roundtrip() {
        let mut litlen = vec![0u8; 257];
        for i in 0..=143 {
            litlen[i] = 8;
        }
        for i in 144..=255 {
            litlen[i] = 9;
        }
        litlen[256] = 7;

        let mut w = BitWriter::new();
        write_stored(&mut w, b"part one, ", false);
        write_fixed_literals(&mut w, b"part two, ", false);
        write_dynamic(&mut w, &litlen, &[1u8], b"part three", true);
        let stream = w.finish();

        roundtrip(&stream);
        assert_eq!(
            crate::formats::deflate::decompress(&stream).unwrap(),
            b"part one, part two, part three"
        );
    }
}
