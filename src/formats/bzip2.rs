//! bzip2 解压（.bz2，BWT + MTF + RLE + Huffman）。
//!
//! 从零实现 bzip2 1.0 解码器，覆盖：
//! - 流头 `BZh` + 块大小级别；
//! - 块头魔数、块 CRC、randomised 位、origPtr、符号映射表；
//! - selector 的 MTF 编码与多张规范 Huffman 表；
//! - MTF + RUNA/RUNB 零游程解码；
//! - BWT 逆变换 + 前置 RLE 展开 + 随机化掩码；
//! - 块 CRC 与流尾 combined CRC 校验。

use std::fmt;
use std::sync::OnceLock;

const RUNA: i32 = 0;
const RUNB: i32 = 1;

const MAX_CODE_LEN: usize = 23; // 码长最多 20，数组留余量。
const N_GROUPS: usize = 6;
const G_SIZE: usize = 50;
const MAX_SELECTORS: usize = 2 + 900_000 / G_SIZE; // 18002

/// bzip2 解压错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bzip2Error {
    Truncated,
    Corrupt,
    BadMagic,
    CrcMismatch,
    CombinedCrcMismatch,
}

impl fmt::Display for Bzip2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated bzip2 stream"),
            Self::Corrupt => write!(f, "corrupt bzip2 stream"),
            Self::BadMagic => write!(f, "invalid bzip2 magic"),
            Self::CrcMismatch => write!(f, "bzip2 block CRC mismatch"),
            Self::CombinedCrcMismatch => write!(f, "bzip2 combined CRC mismatch"),
        }
    }
}

impl std::error::Error for Bzip2Error {}

/// 伪随机掩码表（用于 randomised 块，见 bzip2 `randtable.c`）。
const R_NUMS: [u32; 512] = [
    619, 720, 127, 481, 931, 816, 813, 233, 566, 247, 985, 724, 205, 454, 863, 491, 741, 242, 949,
    214, 733, 859, 335, 708, 621, 574, 73, 654, 730, 472, 419, 436, 278, 496, 867, 210, 399, 680,
    480, 51, 878, 465, 811, 169, 869, 675, 611, 697, 867, 561, 862, 687, 507, 283, 482, 129, 807,
    591, 733, 623, 150, 238, 59, 379, 684, 877, 625, 169, 643, 105, 170, 607, 520, 932, 727, 476,
    693, 425, 174, 647, 73, 122, 335, 530, 442, 853, 695, 249, 445, 515, 909, 545, 703, 919, 874,
    474, 882, 500, 594, 612, 641, 801, 220, 162, 819, 984, 589, 513, 495, 799, 161, 604, 958, 533,
    221, 400, 386, 867, 600, 782, 382, 596, 414, 171, 516, 375, 682, 485, 911, 276, 98, 553, 163,
    354, 666, 933, 424, 341, 533, 870, 227, 730, 475, 186, 263, 647, 537, 686, 600, 224, 469, 68,
    770, 919, 190, 373, 294, 822, 808, 206, 184, 943, 795, 384, 383, 461, 404, 758, 839, 887, 715,
    67, 618, 276, 204, 918, 873, 777, 604, 560, 951, 160, 578, 722, 79, 804, 96, 409, 713, 940,
    652, 934, 970, 447, 318, 353, 859, 672, 112, 785, 645, 863, 803, 350, 139, 93, 354, 99, 820,
    908, 609, 772, 154, 274, 580, 184, 79, 626, 630, 742, 653, 282, 762, 623, 680, 81, 927, 626,
    789, 125, 411, 521, 938, 300, 821, 78, 343, 175, 128, 250, 170, 774, 972, 275, 999, 639, 495,
    78, 352, 126, 857, 956, 358, 619, 580, 124, 737, 594, 701, 612, 669, 112, 134, 694, 363, 992,
    809, 743, 168, 974, 944, 375, 748, 52, 600, 747, 642, 182, 862, 81, 344, 805, 988, 739, 511,
    655, 814, 334, 249, 515, 897, 955, 664, 981, 649, 113, 974, 459, 893, 228, 433, 837, 553, 268,
    926, 240, 102, 654, 459, 51, 686, 754, 806, 760, 493, 403, 415, 394, 687, 700, 946, 670, 656,
    610, 738, 392, 760, 799, 887, 653, 978, 321, 576, 617, 626, 502, 894, 679, 243, 440, 680, 879,
    194, 572, 640, 724, 926, 56, 204, 700, 707, 151, 457, 449, 797, 195, 791, 558, 945, 679, 297,
    59, 87, 824, 713, 663, 412, 693, 342, 606, 134, 108, 571, 364, 631, 212, 174, 643, 304, 329,
    343, 97, 430, 751, 497, 314, 983, 374, 822, 928, 140, 206, 73, 263, 980, 736, 876, 478, 430,
    305, 170, 514, 364, 692, 829, 82, 855, 953, 676, 246, 369, 970, 294, 750, 807, 827, 150, 790,
    288, 923, 804, 378, 215, 828, 592, 281, 565, 555, 710, 82, 896, 831, 547, 261, 524, 462, 293,
    465, 502, 56, 661, 821, 976, 991, 658, 869, 905, 758, 745, 193, 768, 550, 608, 933, 378, 286,
    215, 979, 792, 961, 61, 688, 793, 644, 986, 403, 106, 366, 905, 644, 372, 567, 466, 434, 645,
    210, 389, 550, 919, 135, 780, 773, 635, 389, 707, 100, 626, 958, 165, 504, 920, 176, 193, 713,
    857, 265, 203, 50, 668, 108, 645, 990, 626, 197, 510, 357, 358, 850, 858, 364, 936, 638,
];

/// bzip2 的 CRC-32（非反射、MSB-first，多项式 0x04C1_1DB7）。
///
/// 注意：这与 gzip/zip/xz 用的反射式 CRC-32（多项式 0xEDB8_8320）不同，
/// bzip2 采用非反射实现，因此需要独立的查表。
fn bzip2_crc(data: &[u8]) -> u32 {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    let t = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = (i as u32) << 24;
            for _ in 0..8 {
                c = if c & 0x8000_0000 != 0 {
                    (c << 1) ^ 0x04C1_1DB7
                } else {
                    c << 1
                };
            }
            *e = c;
        }
        t
    });
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = (crc << 8) ^ t[((crc >> 24) ^ b as u32) as usize];
    }
    !crc
}

/// MSB-first 位读取器（bzip2 码字与字段均按 MSB-first 传输）。
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u64,
    cnt: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            buf: 0,
            cnt: 0,
        }
    }

    fn read_bits(&mut self, n: u32) -> Result<u32, Bzip2Error> {
        while self.cnt < n {
            let b = *self.data.get(self.pos).ok_or(Bzip2Error::Truncated)?;
            self.pos += 1;
            self.buf = (self.buf << 8) | b as u64;
            self.cnt += 8;
        }
        let shift = self.cnt - n;
        let v = ((self.buf >> shift) & ((1u64 << n) - 1)) as u32;
        self.cnt = shift;
        Ok(v)
    }

    fn read_bit(&mut self) -> Result<u32, Bzip2Error> {
        self.read_bits(1)
    }
}

/// 单个 Huffman 组的解码表（limit/base/perm，算法与 bzip2 `BZ2_hbCreateDecodeTables` 一致）。
struct DecodeTables {
    limit: [i32; MAX_CODE_LEN],
    base: [i32; MAX_CODE_LEN],
    perm: Vec<i32>,
    min_len: i32,
}

fn create_decode_tables(len: &[u8], min_len: i32, max_len: i32, alpha_size: usize) -> DecodeTables {
    let mut limit = [0i32; MAX_CODE_LEN];
    let mut base = [0i32; MAX_CODE_LEN];
    let mut perm = vec![0i32; alpha_size];

    // 按码长分组填充 perm（码长相同的符号聚在一起）。
    let mut pp = 0usize;
    for i in min_len..=max_len {
        for (j, &l) in len.iter().enumerate() {
            if l as i32 == i {
                perm[pp] = j as i32;
                pp += 1;
            }
        }
    }

    for i in 0..alpha_size {
        base[len[i] as usize + 1] += 1;
    }
    for i in 1..MAX_CODE_LEN {
        base[i] += base[i - 1];
    }

    let mut vec = 0i32;
    for i in min_len..=max_len {
        vec += base[i as usize + 1] - base[i as usize];
        limit[i as usize] = vec - 1;
        vec <<= 1;
    }
    for i in (min_len + 1)..=max_len {
        base[i as usize] = ((limit[i as usize - 1] + 1) << 1) - base[i as usize];
    }

    DecodeTables {
        limit,
        base,
        perm,
        min_len,
    }
}

fn decode_symbol(br: &mut BitReader, t: &DecodeTables) -> Result<i32, Bzip2Error> {
    let mut zn = t.min_len as u32;
    let mut zvec = br.read_bits(zn)?;
    loop {
        if zn > 20 {
            return Err(Bzip2Error::Corrupt);
        }
        if zvec as i32 <= t.limit[zn as usize] {
            break;
        }
        zn += 1;
        let zj = br.read_bits(1)?;
        zvec = (zvec << 1) | zj;
    }
    let idx = zvec as i32 - t.base[zn as usize];
    if idx < 0 || (idx as usize) >= t.perm.len() {
        return Err(Bzip2Error::Corrupt);
    }
    Ok(t.perm[idx as usize])
}

/// 按 selector 组切换 Huffman 表解码符号。
struct SymbolDecoder<'a> {
    tables: &'a [DecodeTables],
    selector: &'a [u8],
    group_no: i32,
    group_pos: usize,
}

impl<'a> SymbolDecoder<'a> {
    fn next(&mut self, br: &mut BitReader) -> Result<i32, Bzip2Error> {
        if self.group_pos == 0 {
            self.group_no += 1;
            if self.group_no as usize >= self.selector.len() {
                return Err(Bzip2Error::Corrupt);
            }
            self.group_pos = G_SIZE;
        }
        self.group_pos -= 1;
        decode_symbol(
            br,
            &self.tables[self.selector[self.group_no as usize] as usize],
        )
    }
}

/// 解压整个 bzip2 流，返回原始字节。
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Bzip2Error> {
    if input.len() < 4 {
        return Err(Bzip2Error::Truncated);
    }
    if &input[0..3] != b"BZh" {
        return Err(Bzip2Error::BadMagic);
    }
    let level = input[3];
    if !(b'1'..=b'9').contains(&level) {
        return Err(Bzip2Error::BadMagic);
    }
    let block_size_100k = (level - b'0') as usize;
    let nblock_max = block_size_100k * 100_000;

    let mut br = BitReader::new(&input[4..]);
    let mut out = Vec::new();
    let mut combined_crc: u32 = 0;

    loop {
        // 下一个块魔数首字节，或流尾 0x17。
        let first = br.read_bits(8)? as u8;
        if first == 0x17 {
            let mut magic = [0u8; 5];
            for b in magic.iter_mut() {
                *b = br.read_bits(8)? as u8;
            }
            if magic != [0x72, 0x45, 0x38, 0x50, 0x90] {
                return Err(Bzip2Error::Corrupt);
            }
            let stored_combined = read_u32(&mut br)?;
            if stored_combined != combined_crc {
                return Err(Bzip2Error::CombinedCrcMismatch);
            }
            break;
        }
        if first != 0x31 {
            return Err(Bzip2Error::Corrupt);
        }
        let mut block_magic = [0u8; 5];
        for b in block_magic.iter_mut() {
            *b = br.read_bits(8)? as u8;
        }
        if block_magic != [0x41, 0x59, 0x26, 0x53, 0x59] {
            return Err(Bzip2Error::Corrupt);
        }

        let stored_block_crc = read_u32(&mut br)?;
        let randomized = br.read_bit()? != 0;
        let orig_ptr = ((br.read_bits(8)? as usize) << 16)
            | ((br.read_bits(8)? as usize) << 8)
            | (br.read_bits(8)? as usize);

        // 符号使用映射（256 个字节分为 16 组，稀疏存储）。
        let mut in_use16 = [false; 16];
        for v in in_use16.iter_mut() {
            *v = br.read_bit()? != 0;
        }
        let mut in_use = [false; 256];
        for (i, &present) in in_use16.iter().enumerate() {
            if present {
                for j in 0..16 {
                    in_use[i * 16 + j] = br.read_bit()? != 0;
                }
            }
        }
        let mut seq_to_unseq = [0u8; 256];
        let mut n_in_use = 0usize;
        for (b, &used) in in_use.iter().enumerate() {
            if used {
                seq_to_unseq[n_in_use] = b as u8;
                n_in_use += 1;
            }
        }
        if n_in_use == 0 {
            return Err(Bzip2Error::Corrupt);
        }
        let alpha_size = n_in_use + 2;

        // selector：unary 编码的 MTF 索引。
        let n_groups = br.read_bits(3)? as usize;
        if !(2..=N_GROUPS).contains(&n_groups) {
            return Err(Bzip2Error::Corrupt);
        }
        let n_selectors_raw = br.read_bits(15)? as usize;
        if n_selectors_raw < 1 {
            return Err(Bzip2Error::Corrupt);
        }
        let n_selectors = n_selectors_raw.min(MAX_SELECTORS);
        let mut selector_mtf = vec![0u8; n_selectors];
        for i in 0..n_selectors_raw {
            let mut j = 0u8;
            loop {
                let bit = br.read_bit()?;
                if bit == 0 {
                    break;
                }
                j += 1;
                if j as usize >= n_groups {
                    return Err(Bzip2Error::Corrupt);
                }
            }
            if i < n_selectors {
                selector_mtf[i] = j;
            }
        }

        // 撤销 selector 的 MTF。
        let mut selector = vec![0u8; n_selectors];
        {
            let mut pos: Vec<u8> = (0..n_groups as u8).collect();
            for i in 0..n_selectors {
                let v = selector_mtf[i] as usize;
                let tmp = pos[v];
                let mut vv = v;
                while vv > 0 {
                    pos[vv] = pos[vv - 1];
                    vv -= 1;
                }
                pos[0] = tmp;
                selector[i] = tmp;
            }
        }

        // 每组的码长（delta 编码）与解码表。
        let mut tables = Vec::with_capacity(n_groups);
        for _ in 0..n_groups {
            let mut len = vec![0u8; alpha_size];
            let mut curr = br.read_bits(5)? as i32;
            let mut min_len = i32::MAX;
            let mut max_len = 0i32;
            for i in 0..alpha_size {
                loop {
                    if !(1..=20).contains(&curr) {
                        return Err(Bzip2Error::Corrupt);
                    }
                    let bit = br.read_bit()?;
                    if bit == 0 {
                        break;
                    }
                    let bit2 = br.read_bit()?;
                    if bit2 == 0 {
                        curr += 1;
                    } else {
                        curr -= 1;
                    }
                }
                len[i] = curr as u8;
                min_len = min_len.min(curr);
                max_len = max_len.max(curr);
            }
            tables.push(create_decode_tables(&len, min_len, max_len, alpha_size));
        }

        // MTF + RUNA/RUNB 解码，产出 BWT 末列。
        let (tt, unzftab, nblock) = decode_mtf(
            &mut br,
            &tables,
            &selector,
            &seq_to_unseq,
            n_in_use,
            nblock_max,
        )?;

        if orig_ptr >= nblock {
            return Err(Bzip2Error::Corrupt);
        }

        // BWT 逆变换 + 前置 RLE 展开 + 随机化掩码。
        let block_out = inverse_bwt(&tt, &unzftab, orig_ptr, nblock, randomized)?;

        let block_crc = bzip2_crc(&block_out);
        if block_crc != stored_block_crc {
            return Err(Bzip2Error::CrcMismatch);
        }
        combined_crc = combined_crc.rotate_left(1) ^ block_crc;
        out.extend_from_slice(&block_out);
    }

    Ok(out)
}

fn read_u32(br: &mut BitReader) -> Result<u32, Bzip2Error> {
    Ok((br.read_bits(8)? << 24)
        | (br.read_bits(8)? << 16)
        | (br.read_bits(8)? << 8)
        | br.read_bits(8)?)
}

/// MTF + RUNA/RUNB 解码，返回 `(tt, unzftab, nblock)`。
///
/// `tt[i]` 存实际字节（0..255），是 BWT 末列；`unzftab` 记录每个字节的出现次数。
#[allow(clippy::too_many_arguments)]
fn decode_mtf(
    br: &mut BitReader,
    tables: &[DecodeTables],
    selector: &[u8],
    seq_to_unseq: &[u8; 256],
    n_in_use: usize,
    nblock_max: usize,
) -> Result<(Vec<u32>, [i32; 256], usize), Bzip2Error> {
    let eob = (n_in_use + 1) as i32;
    let mut mtf: Vec<u8> = (0u8..=255).collect();
    let mut tt: Vec<u32> = Vec::with_capacity(nblock_max);
    let mut unzftab = [0i32; 256];

    let mut dec = SymbolDecoder {
        tables,
        selector,
        group_no: -1,
        group_pos: 0,
    };

    let mut next_sym = dec.next(br)?;
    loop {
        if next_sym == eob {
            break;
        }

        if next_sym == RUNA || next_sym == RUNB {
            // 二进制编码的零游程长度。
            let mut es: i32 = -1;
            let mut n: i32 = 1;
            loop {
                if n >= 2 * 1024 * 1024 {
                    return Err(Bzip2Error::Corrupt);
                }
                if next_sym == RUNA {
                    es += n;
                } else {
                    es += 2 * n;
                }
                n *= 2;
                next_sym = dec.next(br)?;
                if next_sym != RUNA && next_sym != RUNB {
                    break;
                }
            }
            es += 1;

            let actual = seq_to_unseq[mtf[0] as usize];
            unzftab[actual as usize] += es;
            for _ in 0..es {
                if tt.len() >= nblock_max {
                    return Err(Bzip2Error::Corrupt);
                }
                tt.push(actual as u32);
            }
        } else {
            if tt.len() >= nblock_max {
                return Err(Bzip2Error::Corrupt);
            }
            let nn = (next_sym - 1) as usize;
            let uc = mtf[nn];
            let actual = seq_to_unseq[uc as usize];
            unzftab[actual as usize] += 1;
            tt.push(actual as u32);

            // 移到队首。
            mtf.copy_within(0..nn, 1);
            mtf[0] = uc;

            next_sym = dec.next(br)?;
        }
    }

    let nblock = tt.len();
    Ok((tt, unzftab, nblock))
}

/// BWT 逆变换，随后做前置 RLE 展开与随机化掩码，产出块内原始字节。
fn inverse_bwt(
    tt: &[u32],
    unzftab: &[i32; 256],
    orig_ptr: usize,
    nblock: usize,
    randomized: bool,
) -> Result<Vec<u8>, Bzip2Error> {
    // 前缀和：cftab[c] = 小于 c 的字节个数。
    let mut cftab = [0usize; 257];
    for i in 1..=256 {
        cftab[i] = unzftab[i - 1] as usize;
    }
    for i in 1..=256 {
        cftab[i] += cftab[i - 1];
    }

    // 就地构造 next 指针：tt[p] = 符号 | (next << 8)。
    let mut tt = tt.to_vec();
    let mut cftab_copy = cftab;
    for i in 0..nblock {
        let uc = (tt[i] & 0xff) as usize;
        tt[cftab_copy[uc]] |= (i as u32) << 8;
        cftab_copy[uc] += 1;
    }

    // 按逆 BWT 顺序取出 nblock 个符号（附随机化掩码）。
    let mut seq = Vec::with_capacity(nblock);
    let mut t_pos = (tt[orig_ptr] >> 8) as usize;
    let mut rn_to_go = 0u32;
    let mut r_t_pos = 0usize;
    for _ in 0..nblock {
        if t_pos >= nblock {
            return Err(Bzip2Error::Corrupt);
        }
        let packed = tt[t_pos];
        let mut sym = (packed & 0xff) as u8;
        t_pos = (packed >> 8) as usize;
        if randomized {
            if rn_to_go == 0 {
                rn_to_go = R_NUMS[r_t_pos];
                r_t_pos += 1;
                if r_t_pos == 512 {
                    r_t_pos = 0;
                }
            }
            rn_to_go -= 1;
            if rn_to_go == 1 {
                sym ^= 1;
            }
        }
        seq.push(sym);
    }

    // 前置 RLE 展开：4 个连续相同字节后跟一个计数（总长 = 计数 + 4）。
    let mut out = Vec::with_capacity(nblock);
    let mut i = 0usize;
    while i < nblock {
        let b = seq[i];
        i += 1;
        let mut run = 1usize;
        while run < 4 && i < nblock && seq[i] == b {
            run += 1;
            i += 1;
        }
        if run == 4 {
            if i >= nblock {
                return Err(Bzip2Error::Corrupt);
            }
            let cnt = seq[i] as usize;
            i += 1;
            out.extend(std::iter::repeat_n(b, cnt + 4));
        } else {
            out.extend(std::iter::repeat_n(b, run));
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_bytes(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rejects_bad_magic() {
        assert_eq!(
            decode(b"not a bzip2 stream").unwrap_err(),
            Bzip2Error::BadMagic
        );
    }

    #[test]
    fn bzip2_crc_known_vectors() {
        // 与 bzip2 的非反射 CRC-32 对齐（区别于反射式 CRC-32）。
        assert_eq!(bzip2_crc(b"hello world"), 0x44f7_1378);
        assert_eq!(bzip2_crc(b"123456789"), 0xfc89_1918);
    }

    #[test]
    fn rejects_truncated() {
        assert_eq!(decode(b"BZh9").unwrap_err(), Bzip2Error::Truncated);
    }

    #[test]
    fn decodes_real_small() {
        // `printf 'hello world' | bzip2 -c`
        let hex = "425a683931415926535944f7137800000191804000064490802000220334843021b68154278bb9229c2848227b89bc00";
        assert_eq!(decode(&hex_bytes(hex)).unwrap(), b"hello world");
    }

    #[test]
    fn decodes_real_rle() {
        // `printf 'aaaa' | bzip2 -c`（触发前置 RLE 展开）。
        let hex = "425a6839314159265359881233a600000241004000200020002100820b177245385090881233a6";
        assert_eq!(decode(&hex_bytes(hex)).unwrap(), b"aaaa");
    }

    #[test]
    fn decodes_real_dynamic() {
        // `printf 'The quick brown fox jumps over the lazy dog. 0123456789' | bzip2 -c`
        let hex = "425a68393141592653593be73c9d00000a1b8040017fe004003ffffff020005452341a698984c8c040618f4d4034d003469a1b536500d4e535202e2bb176b2ebf0c72cfa5bc1f21aa1171cdd829202d288bbd3144d835ad85dc914e14240ef9cf274";
        assert_eq!(
            decode(&hex_bytes(hex)).unwrap(),
            b"The quick brown fox jumps over the lazy dog. 0123456789"
        );
    }
}
