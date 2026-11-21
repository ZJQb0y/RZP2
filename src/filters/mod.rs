//! 可逆预过滤链（BCJ / Delta / DEFLATE 重压缩）。
//!
//! 在 LZMA 压缩前对明文施加可逆变换，使机器码等结构化数据更易被 LZ77 压缩；
//! 解压后按相反顺序施加逆变换还原明文。BCJ / Delta 过滤器**保长**（输入输出等长）；
//! [`Filter::Deflate`] 例外：它把 gzip 内的 DEFLATE 流重写为符号层表示（**非保长**），
//! 供外层 LZMA 进一步压缩。正变换与逆变换互为严格逆，链式时逆序应用即可还原。
//!
//! 过滤链序列化进容器头部（`format::flag::ext::FILTERS`），解码端据此还原。

/// Delta 过滤允许的最大距离（1..=256）。
pub const DELTA_DISTANCE_MAX: usize = 256;

/// 过滤器种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    /// 差分过滤：`out[i] = in[i] - in[i - distance]`（`distance` 1..=256）。
    Delta {
        /// 实际距离（1..=256）。
        distance: usize,
    },
    /// x86 / x86-64：相对 `call/jmp/jcc` 位移转绝对地址。
    X86,
    /// 32 位 ARM（小端）：相对分支（`B` / `BL`）偏移转绝对地址。
    Arm,
    /// AArch64（小端）：相对分支（`B` / `BL`）偏移转绝对地址。
    Arm64,
    /// RISC-V（小端）：`JAL` / `AUIPC` / 条件分支偏移转绝对地址。
    Riscv,
    /// DEFLATE 流重压缩（precomp 式）：把 gzip / ZIP 内的 deflate 流反解到符号层再
    /// 序列化，供外层 LZMA 进一步压缩；**非保长**，仅对 gzip / ZIP 输入生效。
    Deflate,
    /// JPEG 熵层重压缩（Lepton 式）：把 baseline 顺序 JPEG 的 DCT 系数反解到
    /// 符号层再序列化；**非保长**，仅对基线顺序 JPEG 生效。
    Jpeg,
    /// PNG 重压缩：把 IDAT 内的 zlib/DEFLATE 流反解到符号层再序列化；**非保长**，
    /// 仅对 PNG 生效。
    Png,
    /// GIF 重压缩：把图像数据里的 LZW 码流反解到符号层再序列化；**非保长**，
    /// 仅对 GIF（GIF87a / GIF89a）生效。
    Gif,
}

impl Filter {
    /// 构造 Delta 过滤器，距离须在 1..=256 内。
    pub fn delta(distance: usize) -> Option<Self> {
        if (1..=DELTA_DISTANCE_MAX).contains(&distance) {
            Some(Self::Delta { distance })
        } else {
            None
        }
    }

    /// 过滤器种类 ID（用于头部序列化）。
    fn id(self) -> u8 {
        match self {
            Self::Delta { .. } => 1,
            Self::X86 => 2,
            Self::Arm => 3,
            Self::Arm64 => 4,
            Self::Riscv => 5,
            Self::Deflate => 6,
            Self::Jpeg => 7,
            Self::Png => 8,
            Self::Gif => 9,
        }
    }

    /// 从 `(id, param)` 解析过滤器。
    fn from_id(id: u8, param: u8) -> Option<Self> {
        match id {
            1 => Self::delta(param as usize + 1),
            2 => Some(Self::X86),
            3 => Some(Self::Arm),
            4 => Some(Self::Arm64),
            5 => Some(Self::Riscv),
            6 => Some(Self::Deflate),
            7 => Some(Self::Jpeg),
            8 => Some(Self::Png),
            9 => Some(Self::Gif),
            _ => None,
        }
    }

    /// 参数字节（Delta 为距离减 1，其余为 0）。
    fn param(self) -> u8 {
        match self {
            Self::Delta { distance } => (distance - 1) as u8,
            _ => 0,
        }
    }

    /// 正变换。对保长过滤器返回等长结果；对 [`Self::Deflate`] 返回重压缩表示。
    pub fn encode(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Delta { distance } => {
                let mut out = data.to_vec();
                delta_forward(&mut out, distance);
                out
            }
            Self::X86 => {
                let mut out = data.to_vec();
                x86_convert(&mut out, true);
                out
            }
            Self::Arm => {
                let mut out = data.to_vec();
                arm_convert(&mut out, true);
                out
            }
            Self::Arm64 => {
                let mut out = data.to_vec();
                arm64_convert(&mut out, true);
                out
            }
            Self::Riscv => {
                let mut out = data.to_vec();
                riscv_convert(&mut out, true);
                out
            }
            Self::Deflate => recompress_or_original(deflate_recompress(data), data),
            Self::Jpeg => recompress_or_original(
                crate::recompress::jpeg::recompress(data).unwrap_or_else(|_| data.to_vec()),
                data,
            ),
            Self::Png => recompress_or_original(
                crate::recompress::png::recompress(data).unwrap_or_else(|_| data.to_vec()),
                data,
            ),
            Self::Gif => recompress_or_original(
                crate::recompress::gif::recompress(data).unwrap_or_else(|_| data.to_vec()),
                data,
            ),
        }
    }

    /// 逆变换。对 [`Self::Deflate`] 还原原始 gzip。
    pub fn decode(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Delta { distance } => {
                let mut out = data.to_vec();
                delta_inverse(&mut out, distance);
                out
            }
            Self::X86 => {
                let mut out = data.to_vec();
                x86_convert(&mut out, false);
                out
            }
            Self::Arm => {
                let mut out = data.to_vec();
                arm_convert(&mut out, false);
                out
            }
            Self::Arm64 => {
                let mut out = data.to_vec();
                arm64_convert(&mut out, false);
                out
            }
            Self::Riscv => {
                let mut out = data.to_vec();
                riscv_convert(&mut out, false);
                out
            }
            Self::Deflate => {
                if crate::recompress::gzip::is_recompressed(data) {
                    crate::recompress::gzip::reconstruct(data).unwrap_or_else(|_| data.to_vec())
                } else if crate::recompress::zip::is_recompressed(data) {
                    crate::recompress::zip::reconstruct(data).unwrap_or_else(|_| data.to_vec())
                } else {
                    data.to_vec()
                }
            }
            Self::Jpeg => {
                if crate::recompress::jpeg::is_recompressed(data) {
                    crate::recompress::jpeg::reconstruct(data).unwrap_or_else(|_| data.to_vec())
                } else {
                    data.to_vec()
                }
            }
            Self::Png => {
                if crate::recompress::png::is_recompressed(data) {
                    crate::recompress::png::reconstruct(data).unwrap_or_else(|_| data.to_vec())
                } else {
                    data.to_vec()
                }
            }
            Self::Gif => {
                if crate::recompress::gif::is_recompressed(data) {
                    crate::recompress::gif::reconstruct(data).unwrap_or_else(|_| data.to_vec())
                } else {
                    data.to_vec()
                }
            }
        }
    }
}

/// 非保长重压缩的回退判定：若重压缩表示不比原始输入更小，则回退到原始字节。
///
/// 这些格式感知过滤器（Deflate/Jpeg/Png/Gif）的目标是让外层 LZMA 更易压缩；
/// 当重压缩表示本身已不小于输入时，对 LZMA 通常无益，反而会因非保长开销导致
/// 容器膨胀。解码端通过魔数判断是否重压缩，因此正变换回退原始字节后仍可正确还原。
fn recompress_or_original(out: Vec<u8>, original: &[u8]) -> Vec<u8> {
    if out.len() < original.len() {
        out
    } else {
        original.to_vec()
    }
}

/// `Filter::Deflate` 的正变换：按容器魔数尝试 gzip / ZIP 重压缩，其余原样返回。
fn deflate_recompress(data: &[u8]) -> Vec<u8> {
    if let Ok(packed) = crate::recompress::gzip::recompress(data) {
        return packed;
    }
    if let Ok(packed) = crate::recompress::zip::recompress(data) {
        return packed;
    }
    data.to_vec()
}

/// 可逆过滤链（按声明顺序施加正变换，逆序施加逆变换）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilterChain(Vec<Filter>);

impl FilterChain {
    /// 空链（无过滤）。
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// 从过滤器列表构造。
    pub fn from_filters(filters: Vec<Filter>) -> Self {
        Self(filters)
    }

    /// 链是否为空。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 过滤器数量。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 迭代过滤器。
    pub fn iter(&self) -> impl Iterator<Item = &Filter> {
        self.0.iter()
    }

    /// 正变换：按声明顺序依次过滤，返回过滤后的数据（BCJ/Delta 保长，Deflate 非保长）。
    pub fn apply_forward(&self, data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        for f in &self.0 {
            out = f.encode(&out);
        }
        out
    }

    /// 逆变换：按声明逆序依次还原，返回原始明文（BCJ/Delta 保长，Deflate 非保长）。
    pub fn apply_inverse(&self, data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        for f in self.0.iter().rev() {
            out = f.decode(&out);
        }
        out
    }

    /// 序列化：`count(1) (id(1) param(1))*`。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.0.len() * 2);
        out.push(self.0.len() as u8);
        for f in &self.0 {
            out.push(f.id());
            out.push(f.param());
        }
        out
    }

    /// 反序列化：返回 `(链, 消费字节数)`；未知 ID / 距离非法返回 `None`。
    pub fn decode(buf: &[u8]) -> Option<(Self, usize)> {
        let count = *buf.first()? as usize;
        let mut filters = Vec::with_capacity(count);
        let mut off = 1usize;
        for _ in 0..count {
            let id = *buf.get(off)?;
            let param = *buf.get(off + 1)?;
            off += 2;
            filters.push(Filter::from_id(id, param)?);
        }
        Some((Self(filters), off))
    }

    /// 展示名（用于 `info` / 日志）。
    pub fn describe(&self) -> String {
        if self.0.is_empty() {
            "none".to_string()
        } else {
            self.0
                .iter()
                .map(|f| match f {
                    Filter::Delta { distance } => format!("delta={distance}"),
                    Filter::X86 => "x86".to_string(),
                    Filter::Arm => "arm".to_string(),
                    Filter::Arm64 => "arm64".to_string(),
                    Filter::Riscv => "riscv".to_string(),
                    Filter::Deflate => "deflate".to_string(),
                    Filter::Jpeg => "jpeg".to_string(),
                    Filter::Png => "png".to_string(),
                    Filter::Gif => "gif".to_string(),
                })
                .collect::<Vec<_>>()
                .join("+")
        }
    }
}

/// 从名称解析单个过滤器（CLI 用）。返回 `None` 表示无法识别。
pub fn filter_from_name(name: &str) -> Option<Filter> {
    let normalized: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    match normalized.as_str() {
        "x86" | "x8664" | "amd64" | "bcjx86" => Some(Filter::X86),
        "arm" | "arm32" | "bcjarm" => Some(Filter::Arm),
        "arm64" | "aarch64" | "bcjarm64" => Some(Filter::Arm64),
        "riscv" | "risc64" | "bcjriscv" => Some(Filter::Riscv),
        "deflate" | "gzip" | "zip" | "precomp" => Some(Filter::Deflate),
        "jpeg" | "jpg" | "lepton" => Some(Filter::Jpeg),
        "png" => Some(Filter::Png),
        "gif" | "gif87a" | "gif89a" => Some(Filter::Gif),
        _ => None,
    }
}

/// 从 `delta` / `delta=N` 解析 Delta 过滤器。
pub fn delta_from_name(name: &str) -> Option<Filter> {
    let lower = name.to_ascii_lowercase();
    let rest = lower.strip_prefix("delta")?;
    let distance = if rest.is_empty() {
        1
    } else {
        let d = rest.strip_prefix('=')?;
        d.parse::<usize>().ok()?
    };
    Filter::delta(distance)
}

// ---------------------------------------------------------------------------
// Delta
// ---------------------------------------------------------------------------

fn delta_forward(data: &mut [u8], distance: usize) {
    for i in (0..data.len()).rev() {
        let prev = if i >= distance { data[i - distance] } else { 0 };
        data[i] = data[i].wrapping_sub(prev);
    }
}

fn delta_inverse(data: &mut [u8], distance: usize) {
    for i in 0..data.len() {
        let prev = if i >= distance { data[i - distance] } else { 0 };
        data[i] = data[i].wrapping_add(prev);
    }
}

// ---------------------------------------------------------------------------
// BCJ：通用位置跟踪
// ---------------------------------------------------------------------------

/// x86 / x86-64 相对位移转绝对地址（`encode = true` 为正向）。
///
/// 处理 `E8`（call rel32）、`E9`（jmp rel32）与 `0F 80..8F`（jcc rel32），
/// 位移值 ± 当前指令位置（与 LZMA SDK `BranchX86` 一致）。
fn x86_convert(data: &mut [u8], encode: bool) {
    let mut i = 0usize;
    while i < data.len() {
        let b = data[i];
        if b == 0xE8 || b == 0xE9 {
            if i + 4 < data.len() {
                let mut v = u32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
                v = if encode {
                    v.wrapping_add(i as u32)
                } else {
                    v.wrapping_sub(i as u32)
                };
                data[i + 1..i + 5].copy_from_slice(&v.to_le_bytes());
                i += 5;
                continue;
            }
        } else if b == 0x0F && i + 1 < data.len() {
            let b2 = data[i + 1];
            if (0x80..=0x8F).contains(&b2) {
                if i + 5 < data.len() {
                    let mut v =
                        u32::from_le_bytes([data[i + 2], data[i + 3], data[i + 4], data[i + 5]]);
                    v = if encode {
                        v.wrapping_add(i as u32)
                    } else {
                        v.wrapping_sub(i as u32)
                    };
                    data[i + 2..i + 6].copy_from_slice(&v.to_le_bytes());
                    i += 6;
                    continue;
                }
            }
        }
        i += 1;
    }
}

/// 32 位 ARM（小端）相对分支转绝对地址（与 LZMA SDK `BranchARM` 一致）。
///
/// 仅处理 4 字节对齐、高字节为 `0xEA`（`B`）/ `0xEB`（`BL`）的分支指令，
/// 24 位有符号偏移按「左移 2 → ± 位置 → 右移 2」转换。
fn arm_convert(data: &mut [u8], encode: bool) {
    let mut i = 0usize;
    while i + 4 <= data.len() {
        let op = data[i + 3];
        if op == 0xEA || op == 0xEB {
            let mut addr = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            addr <<= 2;
            addr = if encode {
                addr.wrapping_add(i as u32)
            } else {
                addr.wrapping_sub(i as u32)
            };
            addr >>= 2;
            let b = addr.to_le_bytes();
            data[i] = b[0];
            data[i + 1] = b[1];
            data[i + 2] = b[2];
        }
        i += 4;
    }
}

/// AArch64（小端）相对分支转绝对地址。
///
/// 仅处理 4 字节对齐的 `B`（opcode `0x14`）与 `BL`（opcode `0x94`）指令，
/// 26 位有符号偏移（以字为单位）± `位置 >> 2` 后回写。
fn arm64_convert(data: &mut [u8], encode: bool) {
    let mut i = 0usize;
    while i + 4 <= data.len() {
        let instr = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let opcode = instr >> 26;
        if opcode == 0x05 || opcode == 0x25 {
            // 26 位有符号立即数（以 4 字节为单位）。
            let mut imm = instr & 0x03FF_FFFF;
            // 符号扩展到 32 位再参与加减，保证 wrap 语义正确。
            if imm & 0x0200_0000 != 0 {
                imm |= 0xFC00_0000;
            }
            let delta = (i >> 2) as u32;
            let new_imm = if encode {
                imm.wrapping_add(delta)
            } else {
                imm.wrapping_sub(delta)
            } & 0x03FF_FFFF;
            let out = (instr & 0xFC00_0000) | new_imm;
            data[i..i + 4].copy_from_slice(&out.to_le_bytes());
        }
        i += 4;
    }
}

/// RISC-V（小端）相对分支转绝对地址。
///
/// 处理 4 字节对齐的 `JAL`（`0x6F`）、`AUIPC`（`0x17`）与条件分支（`0x63`），
/// 立即数拆包 ± 位置后重新打包。
fn riscv_convert(data: &mut [u8], encode: bool) {
    let mut i = 0usize;
    while i + 4 <= data.len() {
        let instr = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let opcode = instr & 0x7F;
        let out = match opcode {
            0x6F => riscv_convert_jal(instr, i, encode),
            0x17 => riscv_convert_auipc(instr, i, encode),
            0x63 => riscv_convert_branch(instr, i, encode),
            _ => instr,
        };
        data[i..i + 4].copy_from_slice(&out.to_le_bytes());
        i += 4;
    }
}

fn sign_extend(v: u32, bits: u32) -> u32 {
    let shift = 32 - bits;
    ((v << shift) as i32 >> shift) as u32
}

/// JAL（UJ 型）：21 位有符号立即数（最低位为 0）。
fn riscv_convert_jal(instr: u32, pos: usize, encode: bool) -> u32 {
    let imm = ((instr >> 31) & 1) << 20
        | ((instr >> 21) & 0x3FF) << 1
        | ((instr >> 20) & 1) << 11
        | ((instr >> 12) & 0xFF) << 12;
    let imm = sign_extend(imm, 21);
    let new_imm = if encode {
        imm.wrapping_add(pos as u32)
    } else {
        imm.wrapping_sub(pos as u32)
    } & 0x1F_FFFF;
    // 回写（保留 rd[11:7] 与 opcode[6:0]）。
    (instr & 0x0000_0FFF)
        | ((new_imm & 0x10_0000) << 11) // imm[20] -> bit 31
        | ((new_imm & 0x7FE) << 20) // imm[10:1] -> bits 21..30
        | ((new_imm & 0x800) << 9) // imm[11] -> bit 20
        | (new_imm & 0xFF_000) // imm[19:12] -> bits 12..19
}

/// AUIPC（U 型）：20 位立即数（页地址高位）。
fn riscv_convert_auipc(instr: u32, pos: usize, encode: bool) -> u32 {
    let imm = (instr >> 12) & 0xF_FFFF;
    let new_imm = if encode {
        imm.wrapping_add(pos as u32)
    } else {
        imm.wrapping_sub(pos as u32)
    } & 0xF_FFFF;
    (instr & 0x0000_0FFF) | (new_imm << 12)
}

/// 条件分支（SB 型）：13 位有符号立即数（最低位为 0）。
fn riscv_convert_branch(instr: u32, pos: usize, encode: bool) -> u32 {
    let imm = ((instr >> 31) & 1) << 12
        | ((instr >> 25) & 0x3F) << 5
        | ((instr >> 8) & 0xF) << 1
        | ((instr >> 7) & 1) << 11;
    let imm = sign_extend(imm, 13);
    let new_imm = if encode {
        imm.wrapping_add(pos as u32)
    } else {
        imm.wrapping_sub(pos as u32)
    } & 0x1FFF;
    // 保留 opcode[6:0]、funct3[14:12]、rs1[19:15]、rs2[24:20]。
    (instr & 0x01FF_F07F)
        | ((new_imm & 0x1000) << 19) // imm[12] -> bit 31
        | ((new_imm & 0x7E0) << 20) // imm[10:5] -> bits 25..30
        | ((new_imm & 0x1E) << 7) // imm[4:1] -> bits 8..11
        | ((new_imm & 0x800) >> 4) // imm[11] -> bit 7
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(f: Filter, data: &[u8]) {
        let enc = f.encode(data);
        let dec = f.decode(&enc);
        assert_eq!(dec, data, "过滤器 {} 往返失败", f_id(f));
    }

    fn f_id(f: Filter) -> u8 {
        f.id()
    }

    #[test]
    fn delta_roundtrip() {
        for &dist in &[1usize, 2, 3, 4, 8, 16, 255, 256] {
            let f = Filter::delta(dist).unwrap();
            for len in 0..=64usize {
                let mut data = Vec::with_capacity(len);
                for i in 0..len {
                    data.push((i * 31 + 7) as u8);
                }
                roundtrip(f, &data);
            }
        }
    }

    #[test]
    fn x86_roundtrip_random() {
        let mut data = vec![0u8; 4096];
        crate::crypto::rand::fill_bytes(&mut data).unwrap();
        // 注入 E8/E9/0F 80..8F 指令模式，确保命中分支路径。
        for i in 0..256 {
            data[i * 8] = 0xE8;
            data[i * 8 + 1] = 0x11;
        }
        roundtrip(Filter::X86, &data);
    }

    #[test]
    fn arm_roundtrip_random() {
        let mut data = vec![0u8; 4096];
        crate::crypto::rand::fill_bytes(&mut data).unwrap();
        for i in 0..256 {
            data[i * 8 + 3] = 0xEB;
        }
        roundtrip(Filter::Arm, &data);
    }

    #[test]
    fn arm64_roundtrip_random() {
        let mut data = vec![0u8; 4096];
        crate::crypto::rand::fill_bytes(&mut data).unwrap();
        for i in 0..128 {
            let off = i * 16;
            data[off..off + 4].copy_from_slice(&(0x9400_0000u32 | (i as u32)).to_le_bytes());
        }
        roundtrip(Filter::Arm64, &data);
    }

    #[test]
    fn riscv_roundtrip_random() {
        let mut data = vec![0u8; 4096];
        crate::crypto::rand::fill_bytes(&mut data).unwrap();
        // 注入 JAL / AUIPC / 分支。
        for i in 0..128 {
            let off = i * 16;
            let instrs = [0x0000_006Fu32, 0x0000_0017, 0x0000_0063];
            let instr = instrs[i % 3];
            data[off..off + 4].copy_from_slice(&instr.to_le_bytes());
        }
        roundtrip(Filter::Riscv, &data);
    }

    #[test]
    fn chain_roundtrip_and_serialization() {
        let chain = FilterChain::from_filters(vec![
            Filter::delta(4).unwrap(),
            Filter::X86,
            Filter::Arm64,
        ]);
        let data = b"chain roundtrip test data".repeat(100);
        let filtered = chain.apply_forward(&data);
        let restored = chain.apply_inverse(&filtered);
        assert_eq!(restored, data);

        let bytes = chain.encode();
        let (dec, n) = FilterChain::decode(&bytes).unwrap();
        assert_eq!(n, bytes.len());
        assert_eq!(dec, chain);
    }

    #[test]
    fn empty_chain_identity() {
        let chain = FilterChain::new();
        assert!(chain.is_empty());
        let data = b"no filters here".to_vec();
        assert_eq!(chain.apply_forward(&data), data);
        assert_eq!(chain.apply_inverse(&data), data);
        let bytes = chain.encode();
        assert_eq!(bytes, vec![0]);
        assert_eq!(FilterChain::decode(&bytes).unwrap().0, chain);
    }

    #[test]
    fn delta_filter_helps_on_periodic_data() {
        // 周期数据差分后应显著更可压缩（熵更低）。
        let mut data = Vec::new();
        for i in 0..4096usize {
            data.push((i % 16) as u8);
        }
        let f = Filter::delta(16).unwrap();
        let filtered = f.encode(&data);
        // 差分后大部分字节为 0 或 0xF0 的循环，应含大量重复字节。
        let zeros = filtered.iter().filter(|&&b| b == 0).count();
        assert!(zeros > filtered.len() / 2);
    }

    #[test]
    fn deflate_filter_roundtrip() {
        // 构造一个 gzip 成员（存储块），验证 Filter::Deflate 正/逆变换往返。
        let data = b"deflate filter payload";
        let mut gz = vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xFF];
        gz.push(0x01); // BFINAL=1, BTYPE=00
        let len = data.len() as u16;
        gz.extend_from_slice(&len.to_le_bytes());
        gz.extend_from_slice(&(!len).to_le_bytes());
        gz.extend_from_slice(data);
        let crc = crate::crc::crc32(data);
        gz.extend_from_slice(&crc.to_le_bytes());
        gz.extend_from_slice(&(data.len() as u32).to_le_bytes());

        let f = Filter::Deflate;
        let enc = f.encode(&gz);
        // 极小输入可能因回退判定而保持原样，往返必须无损。
        let dec = f.decode(&enc);
        assert_eq!(dec, gz);
        assert_eq!(crate::formats::gzip::decode(&dec).unwrap(), data);
    }

    #[test]
    fn deflate_filter_identity_on_non_gzip() {
        let data = b"not gzip, just plain bytes".to_vec();
        let f = Filter::Deflate;
        assert_eq!(f.encode(&data), data);
        assert_eq!(f.decode(&data), data);
    }

    /// 构造一个最小单条目 ZIP（方法 8，存储块 DEFLATE，无数据描述符）。
    fn minimal_zip() -> Vec<u8> {
        let name = b"a.txt";
        let raw = b"zip payload for filter";
        let mut comp = vec![0x01u8]; // BFINAL=1, BTYPE=00
        let len = raw.len() as u16;
        comp.extend_from_slice(&len.to_le_bytes());
        comp.extend_from_slice(&(!len).to_le_bytes());
        comp.extend_from_slice(raw);
        let crc = crate::crc::crc32(raw);
        let nlen = name.len() as u16;

        let mut z = Vec::new();
        // 本地文件头。
        z.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        z.extend_from_slice(&20u16.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes());
        z.extend_from_slice(&8u16.to_le_bytes());
        z.extend_from_slice(&[0u8; 4]); // mod time / date
        z.extend_from_slice(&crc.to_le_bytes());
        z.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        z.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        z.extend_from_slice(&nlen.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes()); // extra
        z.extend_from_slice(name);
        z.extend_from_slice(&comp);

        let cd_off = z.len() as u32;
        // 中央目录条目。
        z.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        z.extend_from_slice(&20u16.to_le_bytes()); // version made by
        z.extend_from_slice(&20u16.to_le_bytes()); // version needed
        z.extend_from_slice(&0u16.to_le_bytes()); // flags
        z.extend_from_slice(&8u16.to_le_bytes()); // method
        z.extend_from_slice(&[0u8; 4]); // mod time / date
        z.extend_from_slice(&crc.to_le_bytes());
        z.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        z.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        z.extend_from_slice(&nlen.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes()); // extra
        z.extend_from_slice(&0u16.to_le_bytes()); // comment
        z.extend_from_slice(&0u16.to_le_bytes()); // disk number
        z.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        z.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        z.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        z.extend_from_slice(name);

        let cd_size = (z.len() - cd_off as usize) as u32;
        // 中央目录结束记录。
        z.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes()); // disk number
        z.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
        z.extend_from_slice(&1u16.to_le_bytes()); // entries on disk
        z.extend_from_slice(&1u16.to_le_bytes()); // total entries
        z.extend_from_slice(&cd_size.to_le_bytes());
        z.extend_from_slice(&cd_off.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes()); // comment
        z
    }

    #[test]
    fn deflate_filter_zip_roundtrip() {
        let zip = minimal_zip();
        // 直接构造 ZIP 重压缩表示，验证 Filter::Deflate 解码分派到 ZIP 分支。
        let packed = crate::recompress::zip::recompress(&zip).unwrap();
        assert!(crate::recompress::zip::is_recompressed(&packed));
        let f = Filter::Deflate;
        assert_eq!(f.decode(&packed), zip);
        // 编码分派同样需能无损还原（极小输入可能回退原样）。
        assert_eq!(f.decode(&f.encode(&zip)), zip);
    }

    /// 构造一个最小 8x8 灰度基线顺序 JPEG（DC/AC 各 4 个 2 位码）。
    fn minimal_jpeg() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0xFF, 0xD8]); // SOI
        let mut dqt = vec![0x00u8];
        dqt.extend_from_slice(&[16u8; 64]);
        out.extend_from_slice(&[0xFF, 0xDB]);
        out.extend_from_slice(&((dqt.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(&dqt);
        let sof = [8u8, 0x00, 0x08, 0x00, 0x08, 1, 1, 0x11, 0x00];
        out.extend_from_slice(&[0xFF, 0xC0]);
        out.extend_from_slice(&((sof.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(&sof);
        out.extend_from_slice(&minimal_dht(0, [0, 1, 2, 3]));
        out.extend_from_slice(&minimal_dht(1, [0x00, 0x01, 0x02, 0x03]));
        let sos = [1u8, 1, 0x00, 0, 63, 0];
        out.extend_from_slice(&[0xFF, 0xDA]);
        out.extend_from_slice(&((sos.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(&sos);
        // 熵数据：DC diff +1，AC (run 0, level 2)，EOB。
        out.extend_from_slice(&[0x74, 0x7F]);
        out.extend_from_slice(&[0xFF, 0xD9]); // EOI
        out
    }

    fn minimal_dht(class: u8, vals: [u8; 4]) -> Vec<u8> {
        let mut counts = [0u8; 16];
        counts[1] = 4; // 码长 2，共 4 个码
        let mut payload = vec![class << 4];
        payload.extend_from_slice(&counts);
        payload.extend_from_slice(&vals);
        let mut out = vec![0xFF, 0xC4];
        out.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    #[test]
    fn jpeg_filter_roundtrip() {
        let jpeg = minimal_jpeg();
        let f = Filter::Jpeg;
        let enc = f.encode(&jpeg);
        // 极小输入可能因回退判定而保持原样，往返必须无损。
        let dec = f.decode(&enc);
        assert_eq!(dec, jpeg);
    }

    #[test]
    fn jpeg_filter_identity_on_non_jpeg() {
        let data = b"not a jpeg, just plain bytes".to_vec();
        let f = Filter::Jpeg;
        assert_eq!(f.encode(&data), data);
        assert_eq!(f.decode(&data), data);
    }

    /// 构造一个最小 1x1 灰度 PNG（IDAT 使用存储块 DEFLATE）。
    fn minimal_png() -> Vec<u8> {
        let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        // IHDR：宽 1、高 1、位深 8、颜色类型 0（灰度）。
        let ihdr = [0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0];
        png.extend_from_slice(&(ihdr.len() as u32).to_be_bytes());
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&ihdr);
        let mut crc = b"IHDR".to_vec();
        crc.extend_from_slice(&ihdr);
        png.extend_from_slice(&crate::crc::crc32(&crc).to_be_bytes());

        // IDAT：zlib = 头 + 存储块 DEFLATE + adler32。
        let raw = [0u8, 0x42];
        let mut zlib = vec![0x78, 0x01];
        zlib.push(0x01); // BFINAL=1, BTYPE=00
        zlib.extend_from_slice(&(raw.len() as u16).to_le_bytes());
        zlib.extend_from_slice(&(!(raw.len() as u16)).to_le_bytes());
        zlib.extend_from_slice(&raw);
        let (mut a, mut b) = (1u32, 0u32);
        for &byte in &raw {
            a = (a + byte as u32) % 65521;
            b = (b + a) % 65521;
        }
        zlib.extend_from_slice(&((b << 16) | a).to_be_bytes());
        png.extend_from_slice(&(zlib.len() as u32).to_be_bytes());
        png.extend_from_slice(b"IDAT");
        png.extend_from_slice(&zlib);
        let mut crc = b"IDAT".to_vec();
        crc.extend_from_slice(&zlib);
        png.extend_from_slice(&crate::crc::crc32(&crc).to_be_bytes());

        // IEND。
        png.extend_from_slice(&0u32.to_be_bytes());
        png.extend_from_slice(b"IEND");
        png.extend_from_slice(&crate::crc::crc32(b"IEND").to_be_bytes());
        png
    }

    /// 构造一个最小 1x1 的 4 色 GIF（LZW 码流硬编码）。
    fn minimal_gif() -> Vec<u8> {
        let mut gif = b"GIF89a".to_vec();
        // 逻辑屏幕描述：宽 1、高 1、全局颜色表（2 位 / 4 色）。
        gif.extend_from_slice(&[0x01, 0x00, 0x01, 0x00, 0x81, 0x00, 0x00]);
        gif.extend_from_slice(&[0u8; 4 * 3]); // 全局颜色表
        // 图像描述符（无局部颜色表）。
        gif.extend_from_slice(&[0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00]);
        gif.push(2); // LZW 最小码长
        gif.push(3); // 子块长度
        gif.extend_from_slice(&[0x8C, 0x2D, 0x05]); // 码序列 [clear,1,6,6,2,eoi]
        gif.push(0x00); // 子块结束
        gif.push(0x3B); // 文件结束
        gif
    }

    #[test]
    fn png_filter_roundtrip() {
        let png = minimal_png();
        let f = Filter::Png;
        let enc = f.encode(&png);
        // 极小输入可能因回退判定而保持原样，往返必须无损。
        let dec = f.decode(&enc);
        assert_eq!(dec, png);
    }

    #[test]
    fn gif_filter_roundtrip() {
        let gif = minimal_gif();
        let f = Filter::Gif;
        let enc = f.encode(&gif);
        // 极小输入可能因回退判定而保持原样，往返必须无损。
        let dec = f.decode(&enc);
        assert_eq!(dec, gif);
    }

    #[test]
    fn png_filter_identity_on_non_png() {
        let data = b"not a png, just plain bytes".to_vec();
        let f = Filter::Png;
        assert_eq!(f.encode(&data), data);
        assert_eq!(f.decode(&data), data);
    }

    #[test]
    fn gif_filter_identity_on_non_gif() {
        let data = b"not a gif, just plain bytes".to_vec();
        let f = Filter::Gif;
        assert_eq!(f.encode(&data), data);
        assert_eq!(f.decode(&data), data);
    }

    #[test]
    fn recompress_modules_produce_magic() {
        // 保证格式重压缩模块本身仍产出带魔数的重压缩载荷；极小输入在
        // `Filter::encode` 中因「结果不比原始更小」而回退，是预期行为，
        // 而非重压缩失效。
        let gif = minimal_gif();
        assert!(crate::recompress::gif::is_recompressed(
            &crate::recompress::gif::recompress(&gif).unwrap()
        ));
        let png = minimal_png();
        assert!(crate::recompress::png::is_recompressed(
            &crate::recompress::png::recompress(&png).unwrap()
        ));
        let jpeg = minimal_jpeg();
        assert!(crate::recompress::jpeg::is_recompressed(
            &crate::recompress::jpeg::recompress(&jpeg).unwrap()
        ));
    }
}
