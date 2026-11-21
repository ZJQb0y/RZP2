//! LZMA 解码器。

use std::io::Write;

use crate::lzma::prob_model::*;
use crate::lzma::range_coder::{decode_bit_tree, decode_reverse_bit_tree, RangeDecoder};

/// LZMA 解码错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LzmaError {
    /// 数据损坏（距离越界等）。
    CorruptData,
    /// 输入流被截断。
    Truncated,
    /// 非法属性（lc/lp/pb）。
    BadProperties,
    /// 写出失败（流式解码）。
    Io(std::io::ErrorKind),
}

impl std::fmt::Display for LzmaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CorruptData => write!(f, "corrupt LZMA data"),
            Self::Truncated => write!(f, "truncated LZMA stream"),
            Self::BadProperties => write!(f, "invalid LZMA properties (lc/lp/pb)"),
            Self::Io(e) => write!(f, "I/O error: {e:?}"),
        }
    }
}

impl std::error::Error for LzmaError {}

/// LZMA 解码器（持有概率模型）。
pub struct LzDecoder {
    pub lc: u32,
    pub lp: u32,
    pub pb: u32,
    pub probs: Vec<u16>,
    pub layout: Layout,
}

impl LzDecoder {
    pub fn new(lc: u32, lp: u32, pb: u32) -> Self {
        let layout = Layout::new(lc, lp, pb);
        Self {
            lc,
            lp,
            pb,
            probs: layout.alloc(),
            layout,
        }
    }

    /// 解码原始 LZMA 码流（不含 13 字节头）。
    ///
    /// - `expected_size = Some(n)`：解码恰好 `n` 字节后停止。
    /// - `expected_size = None`：解码到结束标记（end marker）为止。
    pub fn decode(
        &mut self,
        input: &[u8],
        expected_size: Option<usize>,
    ) -> Result<Vec<u8>, LzmaError> {
        let mut rc = RangeDecoder::new(input);
        // 初始容量取较小值，避免恶意/损坏头部导致的巨大分配。
        let initial_cap = expected_size.unwrap_or(0).min(1 << 16);
        let mut out: Vec<u8> = Vec::with_capacity(initial_cap);
        let mut state = 0usize;
        let mut reps = [1u32, 1, 1, 1];

        let num_pos_states = self.layout.num_pos_states;
        let pb_mask = num_pos_states - 1;
        let lc = self.lc;
        let lp = self.lp;

        loop {
            if let Some(expected) = expected_size {
                if out.len() >= expected {
                    break;
                }
            }

            let pos = out.len();
            let ps = pos & pb_mask;
            let layout = &self.layout;

            // isMatch。
            let is_match = layout.is_match_idx(state, ps);
            if rc.decode_bit(&mut self.probs[is_match]) == 0 {
                // 字面量。
                let prev_byte = if pos > 0 { out[pos - 1] } else { 0 };
                let ctx = layout.literal_context(pos, prev_byte, lc, lp);
                let lit_base = layout.literal + ctx * LITERAL_SIZE;
                let old_state = state;
                state = literal_next_state(state);
                let byte = if old_state < NUM_LIT_STATES {
                    decode_bit_tree(&mut rc, &mut self.probs[lit_base..], 8) as u8
                } else {
                    let rep0 = reps[0] as usize;
                    let match_byte = if pos >= rep0 && rep0 > 0 {
                        out[pos - rep0]
                    } else {
                        0
                    };
                    decode_literal_matched(&mut rc, &mut self.probs[lit_base..], match_byte as u32)
                        as u8
                };
                out.push(byte);
            } else if rc.decode_bit(&mut self.probs[layout.is_rep + state]) == 0 {
                // 普通匹配。
                state = match_next_state(state);
                let len_encoded =
                    decode_length(&mut rc, &mut self.probs, layout.len_coder, ps) as usize;
                let len = len_encoded + MATCH_MIN_LEN;
                let d = decode_distance(&mut rc, &mut self.probs, layout, len_encoded);
                if d == 0xFFFF_FFFF {
                    // 结束标记。
                    break;
                }
                let dist = (d + 1) as usize;
                if dist > pos {
                    return Err(LzmaError::CorruptData);
                }
                reps[3] = reps[2];
                reps[2] = reps[1];
                reps[1] = reps[0];
                reps[0] = dist as u32;
                copy_match(&mut out, dist, len);
            } else {
                // rep 匹配。
                if rc.decode_bit(&mut self.probs[layout.is_rep_g0 + state]) == 0 {
                    // rep0。
                    if rc.decode_bit(&mut self.probs[layout.is_rep0_long_idx(state, ps)]) == 0 {
                        // 短 rep（长度 1）。
                        state = short_rep_next_state(state);
                        let dist = reps[0] as usize;
                        if dist > pos {
                            return Err(LzmaError::CorruptData);
                        }
                        copy_match(&mut out, dist, 1);
                        continue;
                    }
                    // rep0 长匹配：reps 不变。
                } else {
                    // 旋转 rep 距离。
                    let rep_idx = if rc.decode_bit(&mut self.probs[layout.is_rep_g1 + state]) == 0 {
                        1
                    } else if rc.decode_bit(&mut self.probs[layout.is_rep_g2 + state]) == 0 {
                        2
                    } else {
                        3
                    };
                    let old = reps;
                    let dist = old[rep_idx];
                    match rep_idx {
                        1 => {
                            reps[1] = old[0];
                            reps[0] = dist;
                        }
                        2 => {
                            reps[2] = old[1];
                            reps[1] = old[0];
                            reps[0] = dist;
                        }
                        _ => {
                            reps[3] = old[2];
                            reps[2] = old[1];
                            reps[1] = old[0];
                            reps[0] = dist;
                        }
                    }
                }
                state = rep_next_state(state);
                let len_encoded =
                    decode_length(&mut rc, &mut self.probs, layout.rep_len_coder, ps) as usize;
                let len = len_encoded + MATCH_MIN_LEN;
                let dist = reps[0] as usize;
                if dist > pos {
                    return Err(LzmaError::CorruptData);
                }
                copy_match(&mut out, dist, len);
            }
        }

        Ok(out)
    }

    /// 续解码：在已有输出 `out`（须含完整历史字典）之上再解出 `expected_new` 字节，
    /// 供 LZMA2 跨块续接使用。`state` 与 `reps` 为调用方持有的持久化 LZMA 状态，
    /// 概率模型使用 `self.probs`（同样持久化）。
    ///
    /// `dict_size` 为字典大小上限，`dict_base` 为当前字典窗口在 `out` 中的起始下标
    /// （用于拒绝越过字典重置边界的越界距离）。解码到 `expected_new` 字节或遇到
    /// 结束标记为止。
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn decode_continue(
        &mut self,
        input: &[u8],
        expected_new: usize,
        dict_size: usize,
        dict_base: usize,
        out: &mut Vec<u8>,
        state: &mut usize,
        reps: &mut [u32; 4],
    ) -> Result<(), LzmaError> {
        let mut rc = RangeDecoder::new(input);
        let target = out.len().saturating_add(expected_new);

        let num_pos_states = self.layout.num_pos_states;
        let pb_mask = num_pos_states - 1;
        let lc = self.lc;
        let lp = self.lp;

        // 当前 LZMA 流内的相对位置。位置状态与字面量上下文都必须相对当前流（块）计算，
        // 而不能使用输出缓冲区的绝对下标，否则跨块续解码时会与编码器产生偏移。
        let mut local_pos = 0usize;

        loop {
            if out.len() >= target {
                break;
            }

            let pos = out.len();
            let ps = local_pos & pb_mask;
            let layout = &self.layout;

            // isMatch。
            let is_match = layout.is_match_idx(*state, ps);
            if rc.decode_bit(&mut self.probs[is_match]) == 0 {
                // 字面量。
                // 前一个字节必须相对当前流（块）判断：块首没有前一个字节，应视为 0，
                // 而不能误取上一块末尾的字节。
                let prev_byte = if local_pos > 0 { out[pos - 1] } else { 0 };
                let ctx = layout.literal_context(local_pos, prev_byte, lc, lp);
                let lit_base = layout.literal + ctx * LITERAL_SIZE;
                let old_state = *state;
                *state = literal_next_state(old_state);
                let byte = if old_state < NUM_LIT_STATES {
                    decode_bit_tree(&mut rc, &mut self.probs[lit_base..], 8) as u8
                } else {
                    let rep0 = reps[0] as usize;
                    let match_byte = if pos >= rep0 && rep0 > 0 {
                        out[pos - rep0]
                    } else {
                        0
                    };
                    decode_literal_matched(&mut rc, &mut self.probs[lit_base..], match_byte as u32)
                        as u8
                };
                out.push(byte);
                local_pos += 1;
            } else if rc.decode_bit(&mut self.probs[layout.is_rep + *state]) == 0 {
                // 普通匹配。
                *state = match_next_state(*state);
                let len_encoded =
                    decode_length(&mut rc, &mut self.probs, layout.len_coder, ps) as usize;
                let len = len_encoded + MATCH_MIN_LEN;
                let d = decode_distance(&mut rc, &mut self.probs, layout, len_encoded);
                if d == 0xFFFF_FFFF {
                    // 结束标记。
                    break;
                }
                let dist = (d + 1) as usize;
                if dist > pos || dist > dict_size {
                    return Err(LzmaError::CorruptData);
                }
                if pos - dist < dict_base {
                    return Err(LzmaError::CorruptData);
                }
                reps[3] = reps[2];
                reps[2] = reps[1];
                reps[1] = reps[0];
                reps[0] = dist as u32;
                copy_match(out, dist, len);
                local_pos += len;
            } else {
                // rep 匹配。
                if rc.decode_bit(&mut self.probs[layout.is_rep_g0 + *state]) == 0 {
                    // rep0。
                    if rc.decode_bit(&mut self.probs[layout.is_rep0_long_idx(*state, ps)]) == 0 {
                        // 短 rep（长度 1）。
                        *state = short_rep_next_state(*state);
                        let dist = reps[0] as usize;
                        if dist > pos || dist > dict_size {
                            return Err(LzmaError::CorruptData);
                        }
                        if pos - dist < dict_base {
                            return Err(LzmaError::CorruptData);
                        }
                        copy_match(out, dist, 1);
                        local_pos += 1;
                        continue;
                    }
                    // rep0 长匹配：reps 不变。
                } else {
                    // 旋转 rep 距离。
                    let rep_idx = if rc.decode_bit(&mut self.probs[layout.is_rep_g1 + *state]) == 0
                    {
                        1
                    } else if rc.decode_bit(&mut self.probs[layout.is_rep_g2 + *state]) == 0 {
                        2
                    } else {
                        3
                    };
                    let old = *reps;
                    let dist = old[rep_idx];
                    match rep_idx {
                        1 => {
                            reps[1] = old[0];
                            reps[0] = dist;
                        }
                        2 => {
                            reps[2] = old[1];
                            reps[1] = old[0];
                            reps[0] = dist;
                        }
                        _ => {
                            reps[3] = old[2];
                            reps[2] = old[1];
                            reps[1] = old[0];
                            reps[0] = dist;
                        }
                    }
                }
                *state = rep_next_state(*state);
                let len_encoded =
                    decode_length(&mut rc, &mut self.probs, layout.rep_len_coder, ps) as usize;
                let len = len_encoded + MATCH_MIN_LEN;
                let dist = reps[0] as usize;
                if dist > pos || dist > dict_size {
                    return Err(LzmaError::CorruptData);
                }
                if pos - dist < dict_base {
                    return Err(LzmaError::CorruptData);
                }
                copy_match(out, dist, len);
                local_pos += len;
            }
        }

        Ok(())
    }

    /// 流式解码：把解出的字节写入 `writer`，仅保留最近 `dict_size` 字节用于匹配回溯。
    ///
    /// 语义与 [`Self::decode`] 一致（`expected_size` 为已知长度时解到该长度即止，
    /// 为 `None` 时解码到结束标记），但输出直接落盘，避免一次性在内存中构造完整明文。
    /// 返回实际写出的字节数。
    pub fn decode_to_writer<W: Write>(
        &mut self,
        input: &[u8],
        expected_size: Option<usize>,
        dict_size: usize,
        writer: &mut W,
    ) -> Result<usize, LzmaError> {
        let mut rc = RangeDecoder::new(input);
        let mut state = 0usize;
        let mut reps = [1u32, 1, 1, 1];

        let num_pos_states = self.layout.num_pos_states;
        let pb_mask = num_pos_states - 1;
        let lc = self.lc;
        let lp = self.lp;

        // 环形字典：仅保留最近 dict_size 字节用于匹配回溯，避免整段明文驻留内存。
        let dict_len = dict_size.max(1);
        let mut dict = vec![0u8; dict_len];
        let mut total = 0usize;
        // 输出缓冲：攒到 64 KiB 再一次写出，降低系统调用次数。
        let mut out: Vec<u8> = Vec::with_capacity(64 * 1024);

        macro_rules! emit {
            ($b:expr) => {{
                let b = $b;
                dict[total % dict_len] = b;
                total += 1;
                out.push(b);
                if out.len() >= 64 * 1024 {
                    if writer.write_all(&out).is_err() {
                        return Err(LzmaError::Io(std::io::ErrorKind::Other));
                    }
                    out.clear();
                }
            }};
        }

        loop {
            if let Some(expected) = expected_size {
                if total >= expected {
                    break;
                }
            }

            let pos = total;
            let ps = pos & pb_mask;
            let layout = &self.layout;

            // isMatch。
            let is_match = layout.is_match_idx(state, ps);
            if rc.decode_bit(&mut self.probs[is_match]) == 0 {
                // 字面量。
                let prev_byte = if pos > 0 {
                    dict[(pos - 1) % dict_len]
                } else {
                    0
                };
                let ctx = layout.literal_context(pos, prev_byte, lc, lp);
                let lit_base = layout.literal + ctx * LITERAL_SIZE;
                let old_state = state;
                state = literal_next_state(state);
                let byte = if old_state < NUM_LIT_STATES {
                    decode_bit_tree(&mut rc, &mut self.probs[lit_base..], 8) as u8
                } else {
                    let rep0 = reps[0] as usize;
                    let match_byte = if pos >= rep0 && rep0 > 0 {
                        dict[(pos - rep0) % dict_len]
                    } else {
                        0
                    };
                    decode_literal_matched(&mut rc, &mut self.probs[lit_base..], match_byte as u32)
                        as u8
                };
                emit!(byte);
            } else if rc.decode_bit(&mut self.probs[layout.is_rep + state]) == 0 {
                // 普通匹配。
                state = match_next_state(state);
                let len_encoded =
                    decode_length(&mut rc, &mut self.probs, layout.len_coder, ps) as usize;
                let len = len_encoded + MATCH_MIN_LEN;
                let d = decode_distance(&mut rc, &mut self.probs, layout, len_encoded);
                if d == 0xFFFF_FFFF {
                    // 结束标记。
                    break;
                }
                let dist = (d + 1) as usize;
                if dist > pos || dist > dict_len {
                    return Err(LzmaError::CorruptData);
                }
                reps[3] = reps[2];
                reps[2] = reps[1];
                reps[1] = reps[0];
                reps[0] = dist as u32;
                for _ in 0..len {
                    let src = total - dist;
                    emit!(dict[src % dict_len]);
                }
            } else {
                // rep 匹配。
                if rc.decode_bit(&mut self.probs[layout.is_rep_g0 + state]) == 0 {
                    // rep0。
                    if rc.decode_bit(&mut self.probs[layout.is_rep0_long_idx(state, ps)]) == 0 {
                        // 短 rep（长度 1）。
                        state = short_rep_next_state(state);
                        let dist = reps[0] as usize;
                        if dist > pos || dist > dict_len {
                            return Err(LzmaError::CorruptData);
                        }
                        emit!(dict[(total - dist) % dict_len]);
                        continue;
                    }
                    // rep0 长匹配：reps 不变。
                } else {
                    // 旋转 rep 距离。
                    let rep_idx = if rc.decode_bit(&mut self.probs[layout.is_rep_g1 + state]) == 0 {
                        1
                    } else if rc.decode_bit(&mut self.probs[layout.is_rep_g2 + state]) == 0 {
                        2
                    } else {
                        3
                    };
                    let old = reps;
                    let dist = old[rep_idx];
                    match rep_idx {
                        1 => {
                            reps[1] = old[0];
                            reps[0] = dist;
                        }
                        2 => {
                            reps[2] = old[1];
                            reps[1] = old[0];
                            reps[0] = dist;
                        }
                        _ => {
                            reps[3] = old[2];
                            reps[2] = old[1];
                            reps[1] = old[0];
                            reps[0] = dist;
                        }
                    }
                }
                state = rep_next_state(state);
                let len_encoded =
                    decode_length(&mut rc, &mut self.probs, layout.rep_len_coder, ps) as usize;
                let len = len_encoded + MATCH_MIN_LEN;
                let dist = reps[0] as usize;
                if dist > pos || dist > dict_len {
                    return Err(LzmaError::CorruptData);
                }
                for _ in 0..len {
                    let src = total - dist;
                    emit!(dict[src % dict_len]);
                }
            }
        }

        if !out.is_empty() && writer.write_all(&out).is_err() {
            return Err(LzmaError::Io(std::io::ErrorKind::Other));
        }
        Ok(total)
    }
}

/// 从已解码输出中复制一段匹配（支持重叠）。
fn copy_match(out: &mut Vec<u8>, dist: usize, len: usize) {
    let start = out.len() - dist;
    for i in 0..len {
        let b = out[start + i];
        out.push(b);
    }
}

/// 解码匹配长度（返回 `len - 2`）。
fn decode_length(rc: &mut RangeDecoder, probs: &mut [u16], base: usize, ps: usize) -> u32 {
    if rc.decode_bit(&mut probs[base]) == 0 {
        decode_bit_tree(rc, &mut probs[base + (ps << 4)..], LEN_NUM_LOW_BITS as u32)
    } else if rc.decode_bit(&mut probs[base + 8]) == 0 {
        LEN_NUM_LOW_SYMBOLS as u32
            + decode_bit_tree(
                rc,
                &mut probs[base + 8 + (ps << 4)..],
                LEN_NUM_LOW_BITS as u32,
            )
    } else {
        (LEN_NUM_LOW_SYMBOLS * 2) as u32
            + decode_bit_tree(rc, &mut probs[base + 256..], LEN_NUM_HIGH_BITS as u32)
    }
}

/// 解码距离，返回 `d = distance - 1`（`0xFFFFFFFF` 表示结束标记）。
fn decode_distance(
    rc: &mut RangeDecoder,
    probs: &mut [u16],
    layout: &Layout,
    len_encoded: usize,
) -> u32 {
    let ltp = if len_encoded < 4 { len_encoded } else { 3 };
    let slot_base = layout.pos_slot_base(ltp);
    let pos_slot = decode_bit_tree(rc, &mut probs[slot_base..], NUM_POS_SLOT_BITS as u32);

    if pos_slot < START_POS_MODEL_INDEX {
        return pos_slot;
    }

    let footer_bits = (pos_slot >> 1) - 1;
    if pos_slot < END_POS_MODEL_INDEX {
        let b = ((2 | (pos_slot & 1)) << footer_bits) as usize;
        let sp = layout.spec_pos + b;
        let r = decode_reverse_bit_tree(rc, &mut probs[sp..], footer_bits);
        b as u32 + r
    } else {
        let top = rc.decode_direct_bits(footer_bits - NUM_ALIGN_BITS as u32);
        let al = layout.align;
        let align = decode_reverse_bit_tree(rc, &mut probs[al..], NUM_ALIGN_BITS as u32);
        let base = (2 | (pos_slot & 1)) << (footer_bits - NUM_ALIGN_BITS as u32);
        ((base | top) << NUM_ALIGN_BITS) | align
    }
}

/// 匹配字面量解码。
pub fn decode_literal_matched(rc: &mut RangeDecoder, probs: &mut [u16], match_byte: u32) -> u32 {
    crate::lzma::lz_encoder::decode_literal_matched(rc, probs, match_byte)
}
