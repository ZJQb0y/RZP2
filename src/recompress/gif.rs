//! GIF（GIF87a / GIF89a）容器级的 LZW 重压缩。
//!
//! 把 GIF 按结构拆成「非图像数据」与「每帧的 LZW 图像数据」，只对图像数据里的 LZW
//! 码流做符号层重压缩：把变长、LSB-first 的 LZW 码从位流中反解成显式的码序列
//! （含 clear / end-of-information 码），再序列化成对 LZMA 更友好的定长字节表示；
//! 反过程按保存的码序列重新编码出**逐位一致**的原始 LZW 位流，实现 GIF 文件的字节级
//! 无损还原。
//!
//! GIF 的 LZW 采用与 giflib 一致的标准码长递增规则：字典表项数达到 `2^code_size`
//! 时码长加 1（上限 12 位）；clear 码复位码表与码长。因此码长序列可由码序列本身唯一
//! 确定，无需额外保存。
//!
//! 重压缩表示以魔数 `RZGI` 开头，供解码端区分「重压缩载荷」与「未重压缩的原始输入」。

use std::fmt;

/// GIF 重压缩错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GifError {
    /// 数据损坏（非法块、非法引入符、码长非法等）。
    Corrupt,
    /// 输入被截断。
    Truncated,
}

impl fmt::Display for GifError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corrupt => write!(f, "corrupt gif stream"),
            Self::Truncated => write!(f, "truncated gif stream"),
        }
    }
}

impl std::error::Error for GifError {}

/// 重压缩表示的魔数。
pub const MAGIC: &[u8; 4] = b"RZGI";

const GIF87A: &[u8; 6] = b"GIF87a";
const GIF89A: &[u8; 6] = b"GIF89a";

// 段类型标记（序列化时区分「原始字节」与「重压缩图像数据」）。
const SEG_RAW: u8 = 0x00;
const SEG_IMAGE: u8 = 0x01;

/// 重压缩一个 GIF 文件（可含多帧 / 动画）。
pub fn recompress(input: &[u8]) -> Result<Vec<u8>, GifError> {
    if !is_gif(input) {
        return Err(GifError::Corrupt);
    }

    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(MAGIC);
    out.push(1); // 版本号

    let mut pos = 6usize;
    let mut raw = Vec::new();

    // 文件头（6 字节）。
    raw.extend_from_slice(&input[..6]);

    // 逻辑屏幕描述（7 字节）。
    if pos + 7 > input.len() {
        return Err(GifError::Truncated);
    }
    raw.extend_from_slice(&input[pos..pos + 7]);
    let lsd_packed = input[pos + 4];
    pos += 7;

    // 全局颜色表（若存在）。
    if lsd_packed & 0x80 != 0 {
        let n = color_table_len(lsd_packed);
        if pos + n > input.len() {
            return Err(GifError::Truncated);
        }
        raw.extend_from_slice(&input[pos..pos + n]);
        pos += n;
    }

    // 依次处理块：扩展 / 图像描述符 / 结尾。
    loop {
        let introducer = *input.get(pos).ok_or(GifError::Truncated)?;
        match introducer {
            0x3B => {
                // 结尾标记，归入原始字节后结束。
                raw.push(0x3B);
                break;
            }
            0x21 => {
                // 扩展块：0x21 + label + 子块（整体原样保留）。
                let start = pos;
                pos += 2; // 跳过 0x21 与 label
                let (_, _, end) = read_sub_blocks(input, pos)?;
                pos = end;
                raw.extend_from_slice(&input[start..pos]);
            }
            0x2C => {
                // 图像描述符：描述符 + 局部颜色表归入原始字节，LZW 数据单独重压缩。
                let img_start = pos;
                if pos + 10 > input.len() {
                    return Err(GifError::Truncated);
                }
                pos += 1; // 跳过 0x2C
                let img_packed = input[pos + 8];
                pos += 9; // 跳过 9 字节描述符
                if img_packed & 0x80 != 0 {
                    let n = color_table_len(img_packed);
                    if pos + n > input.len() {
                        return Err(GifError::Truncated);
                    }
                    pos += n;
                }

                let min_code_size = *input.get(pos).ok_or(GifError::Truncated)?;
                // 描述符 + 局部颜色表归入原始字节（不含 min_code_size）。
                raw.extend_from_slice(&input[img_start..pos]);
                pos += 1;

                let (data, sizes, end) = read_sub_blocks(input, pos)?;
                pos = end;
                let codes = lzw_decode_codes(&data, min_code_size)?;

                push_raw(&mut out, &raw);
                raw.clear();
                push_image(&mut out, min_code_size, &sizes, &codes);
            }
            _ => return Err(GifError::Corrupt),
        }
    }

    // 冲刷剩余原始字节（结尾标记等）。
    push_raw(&mut out, &raw);

    Ok(out)
}

/// 由重压缩表示重建原始 GIF 文件。
pub fn reconstruct(input: &[u8]) -> Result<Vec<u8>, GifError> {
    if !input.starts_with(MAGIC) {
        return Err(GifError::Corrupt);
    }
    if input.get(4) != Some(&1u8) {
        return Err(GifError::Corrupt);
    }

    let mut pos = 5usize;
    let mut out = Vec::new();
    while pos < input.len() {
        let marker = *input.get(pos).ok_or(GifError::Truncated)?;
        pos += 1;
        match marker {
            SEG_RAW => {
                let len = read_u32(input, &mut pos)? as usize;
                let bytes = read_bytes(input, &mut pos, len)?;
                out.extend_from_slice(bytes);
            }
            SEG_IMAGE => {
                let min_code_size = *input.get(pos).ok_or(GifError::Truncated)?;
                pos += 1;

                let sub_count = read_u32(input, &mut pos)? as usize;
                let mut sub_sizes = Vec::with_capacity(sub_count);
                for _ in 0..sub_count {
                    sub_sizes.push(read_u32(input, &mut pos)? as usize);
                }

                let code_count = read_u32(input, &mut pos)? as usize;
                let mut codes = Vec::with_capacity(code_count);
                for _ in 0..code_count {
                    codes.push(read_u16(input, &mut pos)?);
                }

                let lzw = lzw_encode_codes(&codes, min_code_size);
                let total: usize = sub_sizes.iter().sum();
                // 原始编码器在码流恰好字节对齐时可能额外补一个全零字节；重编码结果
                // 比原始子块总长更短时，用零补齐到原长，保证逐字节还原。
                let mut lzw = lzw;
                if lzw.len() < total {
                    lzw.resize(total, 0);
                }
                if lzw.len() != total {
                    return Err(GifError::Corrupt);
                }

                out.push(min_code_size);
                let mut off = 0usize;
                for &s in &sub_sizes {
                    out.push(s as u8);
                    out.extend_from_slice(&lzw[off..off + s]);
                    off += s;
                }
                out.push(0x00); // 子块结束标记
            }
            _ => return Err(GifError::Corrupt),
        }
    }

    Ok(out)
}

/// 判断 `input` 是否为 GIF 重压缩表示。
pub fn is_recompressed(input: &[u8]) -> bool {
    input.starts_with(MAGIC)
}

/// 是否为 GIF 文件头。
fn is_gif(input: &[u8]) -> bool {
    input.len() >= 6 && (&input[..6] == GIF87A || &input[..6] == GIF89A)
}

/// 由「packed」字段计算颜色表字节数（2^(n+1) * 3，n 为低 3 位）。
fn color_table_len(packed: u8) -> usize {
    (1usize << ((packed & 0x07) + 1)) * 3
}

/// 读取子块序列，返回 `(拼接数据, 各子块长度, 结束位置)`。结束位置停在 0x00 之后。
fn read_sub_blocks(
    input: &[u8],
    mut pos: usize,
) -> Result<(Vec<u8>, Vec<u32>, usize), GifError> {
    let mut data = Vec::new();
    let mut sizes = Vec::new();
    loop {
        let size = *input.get(pos).ok_or(GifError::Truncated)? as usize;
        pos += 1;
        if size == 0 {
            break;
        }
        if pos + size > input.len() {
            return Err(GifError::Truncated);
        }
        data.extend_from_slice(&input[pos..pos + size]);
        sizes.push(size as u32);
        pos += size;
    }
    Ok((data, sizes, pos))
}

// ---------------------------------------------------------------------------
// LZW 码流：LSB-first 变长码解码 / 编码
// ---------------------------------------------------------------------------

/// 从 LZW 位流（LSB-first，连续跨子块）中解码出码序列（含 clear / eoi 码）。
fn lzw_decode_codes(bits: &[u8], min_code_size: u8) -> Result<Vec<u16>, GifError> {
    let clear = 1u32 << min_code_size;
    let eoi = clear + 1;
    let mut code_size = min_code_size as u32 + 1;
    let mut next_code = eoi + 1;
    // 紧随 clear 之后的第一个码只输出字面量、不新增字典项，故不推进 next_code。
    let mut first_after_clear = true;

    let mut reader = LsbReader::new(bits);
    let mut codes = Vec::new();

    loop {
        let code = reader.read(code_size)?;
        codes.push(code as u16);
        if code == eoi {
            break;
        }
        if code == clear {
            next_code = eoi + 1;
            code_size = min_code_size as u32 + 1;
            first_after_clear = true;
            continue;
        }
        if first_after_clear {
            first_after_clear = false;
        } else {
            next_code += 1;
            if next_code == (1u32 << code_size) && code_size < 12 {
                code_size += 1;
            }
        }
    }

    Ok(codes)
}

/// 把码序列重新编码为 LZW 位流（LSB-first，字节对齐处补零）。
fn lzw_encode_codes(codes: &[u16], min_code_size: u8) -> Vec<u8> {
    let clear = 1u32 << min_code_size;
    let eoi = clear + 1;
    let mut code_size = min_code_size as u32 + 1;
    let mut next_code = eoi + 1;
    let mut first_after_clear = true;

    let mut writer = LsbWriter::new();
    for &code in codes {
        let c = code as u32;
        writer.write(c, code_size);
        if c == eoi {
            break;
        }
        if c == clear {
            next_code = eoi + 1;
            code_size = min_code_size as u32 + 1;
            first_after_clear = true;
            continue;
        }
        if first_after_clear {
            first_after_clear = false;
        } else {
            next_code += 1;
            if next_code == (1u32 << code_size) && code_size < 12 {
                code_size += 1;
            }
        }
    }
    writer.finish()
}

/// LSB-first 位读取器。
struct LsbReader<'a> {
    data: &'a [u8],
    pos: usize,
    bit_buf: u64,
    bit_cnt: u32,
}

impl<'a> LsbReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            bit_buf: 0,
            bit_cnt: 0,
        }
    }

    fn read(&mut self, n: u32) -> Result<u32, GifError> {
        while self.bit_cnt < n {
            let byte = *self.data.get(self.pos).ok_or(GifError::Truncated)?;
            self.bit_buf |= (byte as u64) << self.bit_cnt;
            self.bit_cnt += 8;
            self.pos += 1;
        }
        let mask = (1u64 << n) - 1;
        let v = (self.bit_buf & mask) as u32;
        self.bit_buf >>= n;
        self.bit_cnt -= n;
        Ok(v)
    }
}

/// LSB-first 位写入器。
struct LsbWriter {
    bytes: Vec<u8>,
    bit_buf: u64,
    bit_cnt: u32,
}

impl LsbWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            bit_buf: 0,
            bit_cnt: 0,
        }
    }

    fn write(&mut self, value: u32, n: u32) {
        self.bit_buf |= (value as u64) << self.bit_cnt;
        self.bit_cnt += n;
        while self.bit_cnt >= 8 {
            self.bytes.push((self.bit_buf & 0xff) as u8);
            self.bit_buf >>= 8;
            self.bit_cnt -= 8;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bit_cnt > 0 {
            self.bytes.push((self.bit_buf & 0xff) as u8);
        }
        self.bytes
    }
}

// ---------------------------------------------------------------------------
// 序列化辅助
// ---------------------------------------------------------------------------

fn push_raw(out: &mut Vec<u8>, data: &[u8]) {
    out.push(SEG_RAW);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
}

fn push_image(out: &mut Vec<u8>, min_code_size: u8, sub_sizes: &[u32], codes: &[u16]) {
    out.push(SEG_IMAGE);
    out.push(min_code_size);
    out.extend_from_slice(&(sub_sizes.len() as u32).to_le_bytes());
    for &s in sub_sizes {
        out.extend_from_slice(&s.to_le_bytes());
    }
    out.extend_from_slice(&(codes.len() as u32).to_le_bytes());
    for &c in codes {
        out.extend_from_slice(&c.to_le_bytes());
    }
}

fn read_u16(input: &[u8], pos: &mut usize) -> Result<u16, GifError> {
    let b = input.get(*pos..*pos + 2).ok_or(GifError::Truncated)?;
    *pos += 2;
    Ok(u16::from_le_bytes(b.try_into().unwrap()))
}

fn read_u32(input: &[u8], pos: &mut usize) -> Result<u32, GifError> {
    let b = input.get(*pos..*pos + 4).ok_or(GifError::Truncated)?;
    *pos += 4;
    Ok(u32::from_le_bytes(b.try_into().unwrap()))
}

fn read_bytes<'a>(input: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], GifError> {
    let b = input.get(*pos..*pos + len).ok_or(GifError::Truncated)?;
    *pos += len;
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小 1x1 的 4 色 GIF，LZW 位流由调用方给出。
    fn make_gif(lzw_data: &[u8], min_code_size: u8) -> Vec<u8> {
        let mut gif = b"GIF89a".to_vec();
        // 逻辑屏幕描述：宽 1、高 1、全局颜色表（2 位 / 4 色）、背景 0、宽高比 0。
        gif.extend_from_slice(&[0x01, 0x00, 0x01, 0x00, 0x81, 0x00, 0x00]);
        // 全局颜色表：4 项，每项 3 字节。
        gif.extend_from_slice(&[0u8; 4 * 3]);
        // 图像描述符：0x2C + 左 0 + 上 0 + 宽 1 + 高 1 + packed 0（无局部颜色表）。
        gif.extend_from_slice(&[0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00]);
        // LZW 最小码长 + 单子块 + 结束标记。
        gif.push(min_code_size);
        gif.push(lzw_data.len() as u8);
        gif.extend_from_slice(lzw_data);
        gif.push(0x00);
        // 结尾标记。
        gif.push(0x3B);
        gif
    }

    #[test]
    fn lzw_codec_reference_bitstream() {
        // min_code_size = 2：clear=4, eoi=5。码序列 [clear,1,6,6,2,eoi] 的码长依次为
        // 3,3,3,3,4,4 位（紧随 clear 的第一个码不新增字典项、不推进码长），
        // LSB-first 打包后应为 0x8C 0x2D 0x05。
        let codes = vec![4u16, 1, 6, 6, 2, 5];
        assert_eq!(lzw_encode_codes(&codes, 2), vec![0x8C, 0x2D, 0x05]);
        assert_eq!(lzw_decode_codes(&[0x8C, 0x2D, 0x05], 2).unwrap(), codes);
    }

    #[test]
    fn lzw_codec_roundtrip() {
        // 含一次 clear 复位的较长序列，往返应逐位一致。
        let codes = vec![4u16, 0, 1, 0, 1, 2, 6, 7, 8, 4, 3, 2, 1, 5];
        let bits = lzw_encode_codes(&codes, 2);
        let decoded = lzw_decode_codes(&bits, 2).unwrap();
        assert_eq!(decoded, codes);
    }

    #[test]
    fn gif_recompress_roundtrip() {
        // 构造一个 LZW 位流（min_code_size=2）并验证容器往返。
        let codes = vec![4u16, 1, 6, 6, 2, 5];
        let lzw = lzw_encode_codes(&codes, 2);
        let gif = make_gif(&lzw, 2);

        let packed = recompress(&gif).unwrap();
        assert!(is_recompressed(&packed));
        assert_ne!(packed, gif);

        let rebuilt = reconstruct(&packed).unwrap();
        assert_eq!(rebuilt, gif);
    }

    #[test]
    fn gif_recompress_rejects_non_gif() {
        assert!(recompress(b"not a gif").is_err());
        assert!(!is_recompressed(b"not a gif"));
        assert_eq!(reconstruct(b"no magic").unwrap_err(), GifError::Corrupt);
    }
}
