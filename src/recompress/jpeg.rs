//! JPEG 基线顺序（baseline sequential）熵层重压缩（Lepton 式）。
//!
//! 把 JPEG 里 Huffman 熵编码的 DCT 系数反解到「符号层」（DC 系数值 / AC 游程-幅值），
//! 去掉 Huffman 熵编码后序列化成对 LZMA 更友好的结构化表示；反过程用保存的 Huffman
//! 表把系数重新编码成**逐位一致**的原始熵段，实现 JPEG 文件的字节级无损还原。
//!
//! 与纯解码不同，这里不经过反量化 / 反 DCT，而是保留量化后的 DCT 系数本身，因此
//! 重编码结果与原 JPEG 的熵编码段 bit-for-bit 一致。
//!
//! 当前支持范围：**基线顺序**（SOF0）、8 位精度、Huffman 熵编码、单扫描、无重启动
//! 间隔（DRI = 0 或缺失）。progressive / 算术编码 / 多扫描 / 重启动间隔返回
//! [`JpegError::Unsupported`]，由上层回退为原字节。

use std::fmt;

/// JPEG 重压缩错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JpegError {
    /// 数据损坏（非法标记、非法码表、非法熵码等）。
    Corrupt,
    /// 输入被截断。
    Truncated,
    /// 不支持的 JPEG 变体（progressive / 算术编码 / 多扫描 / 重启动间隔等）。
    Unsupported,
}

impl fmt::Display for JpegError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corrupt => write!(f, "corrupt jpeg stream"),
            Self::Truncated => write!(f, "truncated jpeg stream"),
            Self::Unsupported => write!(f, "unsupported jpeg variant"),
        }
    }
}

impl std::error::Error for JpegError {}

/// 重压缩表示的魔数。
pub const MAGIC: &[u8; 4] = b"RZGJ";

// ---------------------------------------------------------------------------
// 结构与状态
// ---------------------------------------------------------------------------

/// JPEG Huffman 表（规范码，MSB-first）。
#[derive(Debug, Clone)]
struct JpegHuff {
    /// 符号 -> (码, 码长)；码长 0 表示该符号不存在。
    codes: [(u16, u8); 256],
    /// 各码长的最小码（`min_code[len]`，`len` 1..=16）。
    min_code: [u16; 17],
    /// 各码长的最大码（`max_code[len]`，`len` 1..=16）。
    max_code: [u16; 17],
    /// 各码长首个符号在 `vals` 中的下标。
    valptr: [u16; 17],
    /// 按码长递增排序的符号值（HUFFVAL）。
    vals: Vec<u8>,
}

impl JpegHuff {
    /// 由码长计数（`counts[len-1]` = 码长 `len` 的码数）与符号序列构建。
    fn build(counts: &[u8; 16], vals: &[u8]) -> Result<Self, JpegError> {
        let mut codes = [(0u16, 0u8); 256];
        let mut min_code = [0u16; 17];
        let mut max_code = [0u16; 17];
        let mut valptr = [0u16; 17];

        let mut code: u32 = 0;
        let mut k = 0usize;
        for len in 1..=16u8 {
            let cnt = counts[(len - 1) as usize] as usize;
            if cnt == 0 {
                // 空长度：置为永不匹配的区间。
                min_code[len as usize] = u16::MAX;
                max_code[len as usize] = 0;
            } else {
                if code >= (1u32 << len) {
                    return Err(JpegError::Corrupt);
                }
                min_code[len as usize] = code as u16;
                valptr[len as usize] = k as u16;
                for _ in 0..cnt {
                    let sym = *vals.get(k).ok_or(JpegError::Corrupt)?;
                    k += 1;
                    if code >= (1u32 << len) {
                        return Err(JpegError::Corrupt);
                    }
                    codes[sym as usize] = (code as u16, len);
                    code += 1;
                }
                max_code[len as usize] = (code - 1) as u16;
            }
            code <<= 1;
        }
        if k != vals.len() {
            return Err(JpegError::Corrupt);
        }
        Ok(Self {
            codes,
            min_code,
            max_code,
            valptr,
            vals: vals.to_vec(),
        })
    }

    /// 解码一个符号（逐位窥视，MSB-first）。
    fn decode_symbol(&self, br: &mut JpegBits) -> Result<u8, JpegError> {
        let mut code: u32 = 0;
        for len in 1..=16u8 {
            code = (code << 1) | (br.read_bit()? as u32);
            if code >= self.min_code[len as usize] as u32
                && code <= self.max_code[len as usize] as u32
            {
                let idx =
                    self.valptr[len as usize] as usize + (code - self.min_code[len as usize] as u32) as usize;
                return self.vals.get(idx).copied().ok_or(JpegError::Corrupt);
            }
        }
        Err(JpegError::Corrupt)
    }

    /// 编码一个符号：返回 `(码, 码长)`。
    fn encode_symbol(&self, sym: u8) -> Result<(u16, u8), JpegError> {
        let (code, len) = self.codes[sym as usize];
        if len == 0 {
            return Err(JpegError::Corrupt);
        }
        Ok((code, len))
    }
}

/// 帧头（SOF0）组件描述。
#[derive(Debug, Clone)]
struct ComponentSpec {
    id: u8,
    h: u8,
    v: u8,
    _tq: u8,
}

/// 帧信息。
#[derive(Debug, Clone)]
struct FrameInfo {
    _precision: u8,
    height: u16,
    width: u16,
    components: Vec<ComponentSpec>,
}

/// 扫描（SOS）组件描述。
#[derive(Debug, Clone)]
struct ScanComponent {
    id: u8,
    dc_table: u8,
    ac_table: u8,
}

/// 扫描信息。
#[derive(Debug, Clone)]
struct ScanInfo {
    components: Vec<ScanComponent>,
}

/// 解析结果：`header` 为「SOI + 各段 + SOS 头」的原字节，熵数据从 `entropy_start` 开始。
struct ParsedJpeg {
    header_len: usize,
    frame: FrameInfo,
    scan: ScanInfo,
    huff_dc: [Option<JpegHuff>; 4],
    huff_ac: [Option<JpegHuff>; 4],
    restart_interval: u16,
}

/// 一个 8x8 块的量化 DCT 系数（熵层符号）。
#[derive(Debug, Clone)]
struct BlockCoeffs {
    dc: i16,
    /// `(前置零个数 run, 非零幅值 level)`。
    ac: Vec<(u8, i16)>,
    /// `true` 表示块以 EOB 结束（后续系数全零）；`false` 表示块填满 64 系数。
    eob: bool,
}

// ---------------------------------------------------------------------------
// 公开接口
// ---------------------------------------------------------------------------

/// 重压缩一个基线顺序 JPEG 文件。
pub fn recompress(input: &[u8]) -> Result<Vec<u8>, JpegError> {
    let parsed = parse_jpeg(input)?;
    if parsed.restart_interval > 0 {
        return Err(JpegError::Unsupported);
    }

    let (blocks, consumed) = decode_entropy(
        &input[parsed.header_len..],
        &parsed.frame,
        &parsed.scan,
        &parsed.huff_dc,
        &parsed.huff_ac,
    )?;

    let coeffs = serialize_coeffs(&blocks);
    let tail = &input[parsed.header_len + consumed..];

    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(MAGIC);
    out.push(1); // 版本号
    out.extend_from_slice(&(parsed.header_len as u32).to_le_bytes());
    out.extend_from_slice(&input[..parsed.header_len]);
    out.extend_from_slice(&coeffs);
    out.extend_from_slice(&(tail.len() as u32).to_le_bytes());
    out.extend_from_slice(tail);
    Ok(out)
}

/// 由重压缩表示重建原始 JPEG 文件。
pub fn reconstruct(input: &[u8]) -> Result<Vec<u8>, JpegError> {
    if !input.starts_with(MAGIC) {
        return Err(JpegError::Corrupt);
    }
    if input.get(4) != Some(&1u8) {
        return Err(JpegError::Corrupt);
    }

    let mut pos = 5usize;
    let header_len = read_u32(input, &mut pos)? as usize;
    let header = read_bytes(input, &mut pos, header_len)?;

    let parsed = parse_header(header)?;
    if parsed.restart_interval > 0 {
        return Err(JpegError::Unsupported);
    }

    let nblocks = block_count(&parsed.frame, &parsed.scan)?;
    let (blocks, consumed) = deserialize_blocks(&input[pos..], nblocks)?;
    pos += consumed;

    let tail_len = read_u32(input, &mut pos)? as usize;
    let tail = read_bytes(input, &mut pos, tail_len)?;

    let entropy = encode_entropy(&blocks, &parsed.frame, &parsed.scan, &parsed.huff_dc, &parsed.huff_ac)?;

    let mut out = Vec::with_capacity(header.len() + entropy.len() + tail.len());
    out.extend_from_slice(header);
    out.extend_from_slice(&entropy);
    out.extend_from_slice(tail);
    Ok(out)
}

/// 判断 `input` 是否为 JPEG 重压缩表示。
pub fn is_recompressed(input: &[u8]) -> bool {
    input.starts_with(MAGIC)
}

// ---------------------------------------------------------------------------
// JPEG 结构解析
// ---------------------------------------------------------------------------

fn parse_jpeg(input: &[u8]) -> Result<ParsedJpeg, JpegError> {
    if input.len() < 4 || input[0] != 0xFF || input[1] != 0xD8 {
        return Err(JpegError::Corrupt);
    }
    let mut pos = 2usize;
    let mut frame: Option<FrameInfo> = None;
    let mut huff_dc: [Option<JpegHuff>; 4] = [None, None, None, None];
    let mut huff_ac: [Option<JpegHuff>; 4] = [None, None, None, None];
    let mut restart_interval = 0u16;

    loop {
        if pos + 1 >= input.len() || input[pos] != 0xFF {
            return Err(JpegError::Corrupt);
        }
        let marker = input[pos + 1];
        match marker {
            0xD8 => return Err(JpegError::Corrupt),
            0xD9 => return Err(JpegError::Corrupt), // EOI 前无 SOS
            0x01 | 0xD0..=0xD7 => {
                // 独立标记（无长度字段）。
                pos += 2;
            }
            _ => {
                if pos + 4 > input.len() {
                    return Err(JpegError::Truncated);
                }
                let len = u16::from_be_bytes([input[pos + 2], input[pos + 3]]) as usize;
                if len < 2 {
                    return Err(JpegError::Corrupt);
                }
                let seg_end = pos + 2 + len;
                if seg_end > input.len() {
                    return Err(JpegError::Truncated);
                }
                let payload = &input[pos + 4..seg_end];

                match marker {
                    0xC0 => frame = Some(parse_sof(payload)?),
                    // 其它 SOF（扩展 / 渐进 / 差分）暂不支持。
                    0xC1..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF => {
                        return Err(JpegError::Unsupported);
                    }
                    0xC4 => parse_dht(payload, &mut huff_dc, &mut huff_ac)?,
                    0xDD => restart_interval = parse_dri(payload)?,
                    0xDA => {
                        let scan = parse_sos(payload)?;
                        // SOS 头（含标记与长度）结束处即熵数据起点。
                        return Ok(ParsedJpeg {
                            header_len: seg_end,
                            frame: frame.ok_or(JpegError::Corrupt)?,
                            scan,
                            huff_dc,
                            huff_ac,
                            restart_interval,
                        });
                    }
                    _ => {}
                }
                pos = seg_end;
            }
        }
    }
}

/// 仅解析已存储的 `header`（SOI + 段 + SOS 头），返回重建所需的帧/扫描/码表信息。
fn parse_header(header: &[u8]) -> Result<ParsedJpeg, JpegError> {
    parse_jpeg(header).map_err(|e| match e {
        // header 末尾不含熵数据，正常应走到 SOS 分支返回；这里不依赖该分支返回，
        // 因此直接调用完整解析即可。
        JpegError::Truncated => JpegError::Corrupt,
        other => other,
    })
}

fn parse_sof(payload: &[u8]) -> Result<FrameInfo, JpegError> {
    if payload.len() < 6 {
        return Err(JpegError::Corrupt);
    }
    let precision = payload[0];
    if precision != 8 {
        return Err(JpegError::Unsupported);
    }
    let height = u16::from_be_bytes([payload[1], payload[2]]);
    let width = u16::from_be_bytes([payload[3], payload[4]]);
    let ncomp = payload[5] as usize;
    if payload.len() < 6 + ncomp * 3 {
        return Err(JpegError::Corrupt);
    }
    let mut components = Vec::with_capacity(ncomp);
    for i in 0..ncomp {
        let b = &payload[6 + i * 3..9 + i * 3];
        components.push(ComponentSpec {
            id: b[0],
            h: b[1] >> 4,
            v: b[1] & 0x0F,
            _tq: b[2],
        });
    }
    Ok(FrameInfo {
        _precision: precision,
        height,
        width,
        components,
    })
}

fn parse_dht(
    payload: &[u8],
    huff_dc: &mut [Option<JpegHuff>; 4],
    huff_ac: &mut [Option<JpegHuff>; 4],
) -> Result<(), JpegError> {
    let mut pos = 0usize;
    while pos < payload.len() {
        if pos + 17 > payload.len() {
            return Err(JpegError::Corrupt);
        }
        let class = payload[pos] >> 4; // 0 = DC, 1 = AC
        let id = (payload[pos] & 0x0F) as usize;
        if id > 3 {
            return Err(JpegError::Corrupt);
        }
        pos += 1;
        let mut counts = [0u8; 16];
        for c in counts.iter_mut() {
            *c = payload[pos];
            pos += 1;
        }
        let total: usize = counts.iter().map(|&c| c as usize).sum();
        if pos + total > payload.len() {
            return Err(JpegError::Corrupt);
        }
        let vals = &payload[pos..pos + total];
        pos += total;

        let table = JpegHuff::build(&counts, vals)?;
        match class {
            0 => huff_dc[id] = Some(table),
            1 => huff_ac[id] = Some(table),
            _ => return Err(JpegError::Corrupt),
        }
    }
    Ok(())
}

fn parse_dri(payload: &[u8]) -> Result<u16, JpegError> {
    if payload.len() < 2 {
        return Err(JpegError::Corrupt);
    }
    Ok(u16::from_be_bytes([payload[0], payload[1]]))
}

fn parse_sos(payload: &[u8]) -> Result<ScanInfo, JpegError> {
    if payload.len() < 1 {
        return Err(JpegError::Corrupt);
    }
    let ncomp = payload[0] as usize;
    if payload.len() < 1 + ncomp * 2 {
        return Err(JpegError::Corrupt);
    }
    let mut components = Vec::with_capacity(ncomp);
    for i in 0..ncomp {
        let b = &payload[1 + i * 2..3 + i * 2];
        components.push(ScanComponent {
            id: b[0],
            dc_table: b[1] >> 4,
            ac_table: b[1] & 0x0F,
        });
    }
    Ok(ScanInfo { components })
}

/// 每个组件在一帧内包含的 8x8 块数量（扫描顺序下的 `h * v`）。
fn blocks_per_component(scan: &ScanInfo, frame: &FrameInfo) -> Result<Vec<(u8, u8, u8, u8)>, JpegError> {
    let mut out = Vec::with_capacity(scan.components.len());
    for sc in &scan.components {
        let comp = frame
            .components
            .iter()
            .find(|c| c.id == sc.id)
            .ok_or(JpegError::Corrupt)?;
        out.push((sc.dc_table, sc.ac_table, comp.h, comp.v));
    }
    Ok(out)
}

/// 总块数（供系数序列化 / 反序列化按固定条数读取）。
fn block_count(frame: &FrameInfo, scan: &ScanInfo) -> Result<usize, JpegError> {
    let plan = blocks_per_component(scan, frame)?;
    let hmax = plan.iter().map(|&(_, _, h, _)| h).max().unwrap_or(1) as usize;
    let vmax = plan.iter().map(|&(_, _, _, v)| v).max().unwrap_or(1) as usize;
    let mcu_cols = (frame.width as usize).div_ceil(8 * hmax);
    let mcu_rows = (frame.height as usize).div_ceil(8 * vmax);
    let blocks_per_mcu: usize = plan.iter().map(|&(_, _, h, v)| (h as usize) * (v as usize)).sum();
    Ok(mcu_cols * mcu_rows * blocks_per_mcu)
}

// ---------------------------------------------------------------------------
// 容器小端读取辅助
// ---------------------------------------------------------------------------

fn read_u8(input: &[u8], pos: &mut usize) -> Result<u8, JpegError> {
    let b = input.get(*pos).copied().ok_or(JpegError::Truncated)?;
    *pos += 1;
    Ok(b)
}

fn read_i16(input: &[u8], pos: &mut usize) -> Result<i16, JpegError> {
    let b = input.get(*pos..*pos + 2).ok_or(JpegError::Truncated)?;
    *pos += 2;
    Ok(i16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(input: &[u8], pos: &mut usize) -> Result<u32, JpegError> {
    let b = input.get(*pos..*pos + 4).ok_or(JpegError::Truncated)?;
    *pos += 4;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_bytes<'a>(input: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], JpegError> {
    let b = input.get(*pos..*pos + len).ok_or(JpegError::Truncated)?;
    *pos += len;
    Ok(b)
}

// ---------------------------------------------------------------------------
// 熵段位流（MSB-first + 字节填充）
// ---------------------------------------------------------------------------

/// JPEG 熵编码位读取器：MSB-first，且按 RFC 1951 的字节填充规则把数据中的
/// `0xFF` 后跟的 `0x00` 视为一个 `0xFF` 数据字节。
struct JpegBits<'a> {
    data: &'a [u8],
    pos: usize,
    cur: u8,
    valid_bits: u8,
}

impl<'a> JpegBits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0, cur: 0, valid_bits: 0 }
    }

    fn next_byte(&mut self) -> Result<u8, JpegError> {
        if self.pos >= self.data.len() {
            return Err(JpegError::Truncated);
        }
        let b = self.data[self.pos];
        self.pos += 1;
        if b == 0xFF {
            if self.pos >= self.data.len() {
                return Err(JpegError::Truncated);
            }
            if self.data[self.pos] == 0x00 {
                self.pos += 1;
                return Ok(0xFF);
            }
            // 读到了标记（不应在熵段内部出现）。
            return Err(JpegError::Corrupt);
        }
        Ok(b)
    }

    fn read_bit(&mut self) -> Result<u8, JpegError> {
        if self.valid_bits == 0 {
            self.cur = self.next_byte()?;
            self.valid_bits = 8;
        }
        self.valid_bits -= 1;
        Ok((self.cur >> self.valid_bits) & 1)
    }

    fn read_bits(&mut self, n: u8) -> Result<u16, JpegError> {
        let mut v = 0u16;
        for _ in 0..n {
            v = (v << 1) | self.read_bit()? as u16;
        }
        Ok(v)
    }
}

/// JPEG 熵编码位写入器：MSB-first，`0xFF` 数据字节后自动填充 `0x00`。
struct JpegBitsOut {
    out: Vec<u8>,
    cur: u8,
    nbits: u8,
}

impl JpegBitsOut {
    fn new() -> Self {
        Self { out: Vec::new(), cur: 0, nbits: 0 }
    }

    fn emit_byte(&mut self, b: u8) {
        self.out.push(b);
        if b == 0xFF {
            self.out.push(0x00);
        }
    }

    fn write_bit(&mut self, bit: u8) {
        self.cur = (self.cur << 1) | (bit & 1);
        self.nbits += 1;
        if self.nbits == 8 {
            let b = self.cur;
            self.cur = 0;
            self.nbits = 0;
            self.emit_byte(b);
        }
    }

    fn write_bits(&mut self, value: u16, n: u8) {
        for i in (0..n).rev() {
            self.write_bit(((value >> i) & 1) as u8);
        }
    }

    fn write_symbol(&mut self, huff: &JpegHuff, sym: u8) -> Result<(), JpegError> {
        let (code, len) = huff.encode_symbol(sym)?;
        self.write_bits(code, len);
        Ok(())
    }

    fn finish(mut self) -> Vec<u8> {
        while self.nbits != 0 {
            self.write_bit(1); // 用 1 填充到字节边界
        }
        self.out
    }
}

// ---------------------------------------------------------------------------
// 系数幅值编码
// ---------------------------------------------------------------------------

/// `|value|` 的二进制位数（`value == 0` 时为 0）。
fn magnitude_bits(value: i32) -> u8 {
    if value == 0 {
        0
    } else {
        (32 - value.unsigned_abs().leading_zeros()) as u8
    }
}

/// 解码 `size` 位的「符号幅值」编码为有符号值。
fn read_amplitude(br: &mut JpegBits, size: u8) -> Result<i32, JpegError> {
    if size == 0 {
        return Ok(0);
    }
    let v = br.read_bits(size)? as i32;
    let half = 1i32 << (size - 1);
    Ok(if v < half { v - (1i32 << size) + 1 } else { v })
}

/// 把有符号值写成 `size` 位的「符号幅值」编码。
fn write_amplitude(w: &mut JpegBitsOut, value: i32, size: u8) {
    let amplitude = if value > 0 {
        value as u16
    } else {
        (value + (1i32 << size) - 1) as u16
    };
    w.write_bits(amplitude, size);
}

// ---------------------------------------------------------------------------
// 熵段解码 / 编码
// ---------------------------------------------------------------------------

fn decode_entropy(
    data: &[u8],
    frame: &FrameInfo,
    scan: &ScanInfo,
    huff_dc: &[Option<JpegHuff>; 4],
    huff_ac: &[Option<JpegHuff>; 4],
) -> Result<(Vec<BlockCoeffs>, usize), JpegError> {
    let plan = blocks_per_component(scan, frame)?;
    let (mcu_cols, mcu_rows) = mcu_grid(frame, &plan)?;

    let mut br = JpegBits::new(data);
    let mut predictors = vec![0i32; plan.len()];
    let mut blocks = Vec::new();

    for _ in 0..(mcu_cols * mcu_rows) {
        for (ci, &(dc_t, ac_t, h, v)) in plan.iter().enumerate() {
            let dc_table = huff_dc[dc_t as usize].as_ref().ok_or(JpegError::Corrupt)?;
            let ac_table = huff_ac[ac_t as usize].as_ref().ok_or(JpegError::Corrupt)?;
            for _ in 0..((h as usize) * (v as usize)) {
                let block = decode_block(&mut br, dc_table, ac_table, &mut predictors[ci])?;
                blocks.push(block);
            }
        }
    }

    Ok((blocks, br.pos))
}

fn decode_block(
    br: &mut JpegBits,
    dc_table: &JpegHuff,
    ac_table: &JpegHuff,
    predictor: &mut i32,
) -> Result<BlockCoeffs, JpegError> {
    // DC：差分编码。
    let size = dc_table.decode_symbol(br)?;
    let diff = read_amplitude(br, size)?;
    *predictor += diff;
    let dc = *predictor as i16;

    // AC：游程-幅值。
    let mut ac = Vec::new();
    let mut count = 1usize; // DC 占 1 个系数
    let mut run_accum = 0u16;
    let mut eob = false;

    while count < 64 {
        let sym = ac_table.decode_symbol(br)?;
        if sym == 0x00 {
            eob = true;
            break;
        }
        if sym == 0xF0 {
            run_accum += 16;
            continue;
        }
        let run = run_accum + (sym >> 4) as u16;
        let size = sym & 0x0F;
        if size == 0 {
            return Err(JpegError::Corrupt);
        }
        let level = read_amplitude(br, size)?;
        run_accum = 0;
        count += run as usize + 1;
        if count > 64 {
            return Err(JpegError::Corrupt);
        }
        ac.push((run as u8, level as i16));
    }

    Ok(BlockCoeffs { dc, ac, eob })
}

fn encode_entropy(
    blocks: &[BlockCoeffs],
    frame: &FrameInfo,
    scan: &ScanInfo,
    huff_dc: &[Option<JpegHuff>; 4],
    huff_ac: &[Option<JpegHuff>; 4],
) -> Result<Vec<u8>, JpegError> {
    let plan = blocks_per_component(scan, frame)?;
    let (mcu_cols, mcu_rows) = mcu_grid(frame, &plan)?;

    let mut w = JpegBitsOut::new();
    let mut predictors = vec![0i32; plan.len()];
    let mut bi = 0usize;

    for _ in 0..(mcu_cols * mcu_rows) {
        for (ci, &(dc_t, ac_t, h, v)) in plan.iter().enumerate() {
            let dc_table = huff_dc[dc_t as usize].as_ref().ok_or(JpegError::Corrupt)?;
            let ac_table = huff_ac[ac_t as usize].as_ref().ok_or(JpegError::Corrupt)?;
            for _ in 0..((h as usize) * (v as usize)) {
                let block = blocks.get(bi).ok_or(JpegError::Corrupt)?;
                bi += 1;
                encode_block(&mut w, block, dc_table, ac_table, &mut predictors[ci])?;
            }
        }
    }
    if bi != blocks.len() {
        return Err(JpegError::Corrupt);
    }
    Ok(w.finish())
}

fn encode_block(
    w: &mut JpegBitsOut,
    block: &BlockCoeffs,
    dc_table: &JpegHuff,
    ac_table: &JpegHuff,
    predictor: &mut i32,
) -> Result<(), JpegError> {
    // DC。
    let diff = block.dc as i32 - *predictor;
    *predictor = block.dc as i32;
    let size = magnitude_bits(diff);
    w.write_symbol(dc_table, size)?;
    write_amplitude(w, diff, size);

    // AC。
    let mut count = 1usize;
    for &(run, level) in &block.ac {
        let run_total = run as usize;
        let mut r = run_total;
        while r >= 16 {
            w.write_symbol(ac_table, 0xF0)?; // ZRL
            r -= 16;
        }
        let size = magnitude_bits(level as i32);
        w.write_symbol(ac_table, ((r << 4) | size as usize) as u8)?;
        write_amplitude(w, level as i32, size);
        count += run_total + 1;
        if count > 64 {
            return Err(JpegError::Corrupt);
        }
    }
    if block.eob {
        w.write_symbol(ac_table, 0x00)?; // EOB
    } else if count != 64 {
        return Err(JpegError::Corrupt);
    }
    Ok(())
}

/// 计算 `(mcu_cols, mcu_rows)`。
fn mcu_grid(frame: &FrameInfo, plan: &[(u8, u8, u8, u8)]) -> Result<(usize, usize), JpegError> {
    let hmax = plan.iter().map(|&(_, _, h, _)| h).max().unwrap_or(1) as usize;
    let vmax = plan.iter().map(|&(_, _, _, v)| v).max().unwrap_or(1) as usize;
    let mcu_cols = (frame.width as usize).div_ceil(8 * hmax);
    let mcu_rows = (frame.height as usize).div_ceil(8 * vmax);
    Ok((mcu_cols, mcu_rows))
}

// ---------------------------------------------------------------------------
// 系数序列化 / 反序列化
// ---------------------------------------------------------------------------

fn serialize_coeffs(blocks: &[BlockCoeffs]) -> Vec<u8> {
    let mut out = Vec::with_capacity(blocks.len().saturating_mul(4));
    for b in blocks {
        out.extend_from_slice(&b.dc.to_le_bytes());
        out.push(b.ac.len() as u8);
        for &(run, level) in &b.ac {
            out.push(run);
            out.extend_from_slice(&level.to_le_bytes());
        }
        out.push(b.eob as u8);
    }
    out
}

fn deserialize_blocks(data: &[u8], nblocks: usize) -> Result<(Vec<BlockCoeffs>, usize), JpegError> {
    let mut pos = 0usize;
    let mut blocks = Vec::with_capacity(nblocks);
    for _ in 0..nblocks {
        let dc = read_i16(data, &mut pos)?;
        let ac_count = read_u8(data, &mut pos)? as usize;
        let mut ac = Vec::with_capacity(ac_count);
        for _ in 0..ac_count {
            let run = read_u8(data, &mut pos)?;
            let level = read_i16(data, &mut pos)?;
            ac.push((run, level));
        }
        let eob = read_u8(data, &mut pos)? != 0;
        blocks.push(BlockCoeffs { dc, ac, eob });
    }
    Ok((blocks, pos))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// 测试用规范 Huffman 编码器（MSB-first，与 `JpegHuff::build` 同一套规范码算法）。
    struct TestHuff {
        map: HashMap<u8, (u16, u8)>,
    }

    impl TestHuff {
        fn new(syms: &[(u8, u8)]) -> Self {
            let mut sorted: Vec<(u8, u8)> = syms.to_vec();
            sorted.sort_by_key(|&(s, l)| (l, s));
            let mut map = HashMap::new();
            let mut code: u32 = 0;
            let mut cur_len = 0u8;
            for (s, l) in sorted {
                while cur_len < l {
                    code <<= 1;
                    cur_len += 1;
                }
                map.insert(s, (code as u16, l));
                code += 1;
            }
            Self { map }
        }

        fn encode(&self, sym: u8) -> (u16, u8) {
            self.map[&sym]
        }
    }

    /// 测试用独立位写入器（避免与模块内 `JpegBitsOut` 共因导致循环验证）。
    struct TestBitsOut {
        out: Vec<u8>,
        cur: u8,
        nbits: u8,
    }

    impl TestBitsOut {
        fn new() -> Self {
            Self { out: Vec::new(), cur: 0, nbits: 0 }
        }

        fn write_bit(&mut self, b: u8) {
            self.cur = (self.cur << 1) | (b & 1);
            self.nbits += 1;
            if self.nbits == 8 {
                let byte = self.cur;
                self.cur = 0;
                self.nbits = 0;
                self.out.push(byte);
                if byte == 0xFF {
                    self.out.push(0x00);
                }
            }
        }

        fn write_bits(&mut self, v: u16, n: u8) {
            for i in (0..n).rev() {
                self.write_bit(((v >> i) & 1) as u8);
            }
        }

        fn write_amp(&mut self, value: i32, size: u8) {
            let amp = if value > 0 {
                value as u16
            } else {
                (value + (1i32 << size) - 1) as u16
            };
            self.write_bits(amp, size);
        }

        fn finish(mut self) -> Vec<u8> {
            while self.nbits != 0 {
                self.write_bit(1);
            }
            self.out
        }
    }

    /// 一个测试块。
    struct TestBlock {
        dc: i16,
        ac: Vec<(u8, i16)>,
        eob: bool,
    }

    /// 构造单个 DHT 段（含标记与长度）。
    fn build_dht_segment(class: u8, id: u8, syms: &[(u8, u8)]) -> Vec<u8> {
        let mut sorted: Vec<(u8, u8)> = syms.to_vec();
        sorted.sort_by_key(|&(s, l)| (l, s));
        let mut counts = [0u8; 16];
        for &(_, l) in &sorted {
            counts[(l - 1) as usize] += 1;
        }
        let mut payload = Vec::new();
        payload.push((class << 4) | id);
        payload.extend_from_slice(&counts);
        payload.extend(sorted.iter().map(|&(s, _)| s));
        let mut out = vec![0xFF, 0xC4];
        out.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    /// 构造一个灰度基线顺序 JPEG（无重启动间隔）。
    fn build_gray_jpeg(
        width: u16,
        height: u16,
        blocks: &[TestBlock],
        dc_syms: &[(u8, u8)],
        ac_syms: &[(u8, u8)],
    ) -> Vec<u8> {
        let dc_huff = TestHuff::new(dc_syms);
        let ac_huff = TestHuff::new(ac_syms);

        let mut out = Vec::new();
        out.extend_from_slice(&[0xFF, 0xD8]); // SOI

        // DQT（表 0，64 个非零量化值，仅占位）。
        let mut dqt = vec![0x00u8];
        dqt.extend_from_slice(&[16u8; 64]);
        out.extend_from_slice(&[0xFF, 0xDB]);
        out.extend_from_slice(&((dqt.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(&dqt);

        // SOF0（8 位，单分量 1x1）。
        let sof = [
            8u8,
            (height >> 8) as u8,
            (height & 0xFF) as u8,
            (width >> 8) as u8,
            (width & 0xFF) as u8,
            1u8,  // 分量数
            1u8,  // 分量 ID
            0x11, // H=1 V=1
            0x00, // 量化表 0
        ];
        out.extend_from_slice(&[0xFF, 0xC0]);
        out.extend_from_slice(&((sof.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(&sof);

        // DHT（DC + AC）。
        out.extend_from_slice(&build_dht_segment(0, 0, dc_syms));
        out.extend_from_slice(&build_dht_segment(1, 0, ac_syms));

        // SOS（单分量，DC/AC 表 0）。
        let sos = [1u8, 1u8, 0x00, 0u8, 63u8, 0u8];
        out.extend_from_slice(&[0xFF, 0xDA]);
        out.extend_from_slice(&((sos.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(&sos);

        // 熵数据。
        let mut w = TestBitsOut::new();
        let mut pred = 0i32;
        for b in blocks {
            let diff = b.dc as i32 - pred;
            pred = b.dc as i32;
            let size = magnitude_bits(diff);
            let (code, len) = dc_huff.encode(size);
            w.write_bits(code, len);
            w.write_amp(diff, size);

            let mut count = 1usize;
            for &(run, level) in &b.ac {
                let run_total = run as usize;
                let mut r = run_total;
                while r >= 16 {
                    let (code, len) = ac_huff.encode(0xF0);
                    w.write_bits(code, len);
                    r -= 16;
                }
                let size = magnitude_bits(level as i32);
                let (code, len) = ac_huff.encode(((r << 4) | size as usize) as u8);
                w.write_bits(code, len);
                w.write_amp(level as i32, size);
                count += run_total + 1;
            }
            if b.eob {
                let (code, len) = ac_huff.encode(0x00);
                w.write_bits(code, len);
            } else {
                assert_eq!(count, 64);
            }
        }
        out.extend_from_slice(&w.finish());

        out.extend_from_slice(&[0xFF, 0xD9]); // EOI
        out
    }

    #[test]
    fn minimal_roundtrip() {
        // 8x8 单块：DC diff +1（size 1），一个 AC 系数 (run 0, level 2)，EOB。
        let dc_syms = [(0u8, 2u8), (1, 2), (2, 2), (3, 2)];
        let ac_syms = [(0x00u8, 2u8), (0x01, 2), (0x02, 2), (0x03, 2)];
        let jpeg = build_gray_jpeg(
            8,
            8,
            &[TestBlock { dc: 1, ac: vec![(0, 2)], eob: true }],
            &dc_syms,
            &ac_syms,
        );

        let packed = recompress(&jpeg).unwrap();
        assert!(is_recompressed(&packed));
        assert_ne!(packed, jpeg);
        let rebuilt = reconstruct(&packed).unwrap();
        assert_eq!(rebuilt, jpeg, "重压缩往返应逐位还原原始 JPEG");
    }

    #[test]
    fn multiblock_roundtrip() {
        // 24x8 三块，覆盖 EOB、ZRL 与满块（无 EOB）。
        let dc_syms = [(0u8, 2u8), (1, 3), (2, 3), (3, 3), (4, 3)];
        let ac_syms = [
            (0x00u8, 2u8), // EOB
            (0x01, 4),
            (0x02, 4),
            (0x03, 4),
            (0x04, 4),
            (0x05, 4),
            (0x06, 4),
            (0x21, 5), // run 2, size 1
            (0xF0, 5), // ZRL
        ];
        let full_ac: Vec<(u8, i16)> = (0..63).map(|i| (0u8, (i + 1) as i16)).collect();
        let blocks = [
            TestBlock { dc: 5, ac: vec![(0, 3), (2, -1)], eob: true },
            TestBlock { dc: -3, ac: vec![(16, 5)], eob: true },
            TestBlock { dc: 0, ac: full_ac, eob: false },
        ];
        let jpeg = build_gray_jpeg(24, 8, &blocks, &dc_syms, &ac_syms);

        let packed = recompress(&jpeg).unwrap();
        let rebuilt = reconstruct(&packed).unwrap();
        assert_eq!(rebuilt, jpeg);
    }

    #[test]
    fn rejects_non_jpeg() {
        assert!(recompress(b"not a jpeg").is_err());
        assert!(!is_recompressed(b"not a jpeg"));
        assert_eq!(reconstruct(b"no magic").unwrap_err(), JpegError::Corrupt);
    }

    #[test]
    fn rejects_restart_interval() {
        let dc_syms = [(0u8, 2u8), (1, 2)];
        let ac_syms = [(0x00u8, 2u8), (0x01, 2)];
        let mut jpeg = build_gray_jpeg(
            8,
            8,
            &[TestBlock { dc: 0, ac: vec![(0, 1)], eob: true }],
            &dc_syms,
            &ac_syms,
        );
        // 在 SOS 前插入 DRI（重启动间隔 = 1）。
        let dri = [0xFF, 0xDD, 0x00, 0x04, 0x00, 0x01];
        // 定位 SOS（0xFF 0xDA）并插入。
        let sos_idx = jpeg.windows(2).position(|w| w == [0xFF, 0xDA]).unwrap();
        jpeg.splice(sos_idx..sos_idx, dri.iter().copied());
        assert_eq!(recompress(&jpeg).unwrap_err(), JpegError::Unsupported);
    }
}