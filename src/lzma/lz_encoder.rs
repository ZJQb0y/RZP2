//! LZMA 低层符号编码器：字面量 / 匹配 / rep / 结束标记。
//!
//! 维护概率模型数组、状态机与 rep 距离，向范围编码器输出比特。

use crate::lzma::prob_model::*;
use crate::lzma::range_coder::{encode_bit_tree, encode_reverse_bit_tree, RangeEncoder};

pub struct LzEncoder {
    pub lc: u32,
    pub lp: u32,
    pub pb: u32,
    pub state: u32,
    pub reps: [u32; 4],
    pub probs: Vec<u16>,
    pub layout: Layout,
}

impl LzEncoder {
    pub fn new(lc: u32, lp: u32, pb: u32) -> Self {
        let layout = Layout::new(lc, lp, pb);
        Self {
            lc,
            lp,
            pb,
            state: 0,
            reps: [1, 1, 1, 1],
            probs: layout.alloc(),
            layout,
        }
    }

    #[inline]
    fn pos_state(&self, pos: usize) -> usize {
        pos & (self.layout.num_pos_states - 1)
    }

    /// 编码一个普通字面量或匹配字面量。
    pub fn encode_literal(&mut self, rc: &mut RangeEncoder, data: &[u8], pos: usize) {
        let byte = data[pos];
        let prev_byte = if pos > 0 { data[pos - 1] } else { 0 };

        let ps = self.pos_state(pos);
        let idx = self.layout.is_match_idx(self.state as usize, ps);
        rc.encode_bit(&mut self.probs[idx], 0); // isMatch = 0

        let ctx = self
            .layout
            .literal_context(pos, prev_byte, self.lc, self.lp);
        let lit_base = self.layout.literal + ctx * LITERAL_SIZE;

        let old_state = self.state;
        self.state = literal_next_state(old_state as usize) as u32;

        if (old_state as usize) < NUM_LIT_STATES {
            encode_bit_tree(rc, &mut self.probs[lit_base..], 8, byte as u32);
        } else {
            let rep0 = self.reps[0] as usize;
            let match_byte = if pos >= rep0 && rep0 > 0 {
                data[pos - rep0]
            } else {
                0
            };
            encode_literal_matched(
                rc,
                &mut self.probs[lit_base..],
                byte as u32,
                match_byte as u32,
            );
        }
    }

    /// 环形窗口版本的字面量编码（供流式编码器使用）。
    pub fn encode_literal_window(
        &mut self,
        rc: &mut RangeEncoder,
        buf: &[u8],
        window_mask: usize,
        pos: usize,
    ) {
        let byte = buf[pos & window_mask];
        let prev_byte = if pos > 0 {
            buf[(pos - 1) & window_mask]
        } else {
            0
        };

        let ps = self.pos_state(pos);
        let idx = self.layout.is_match_idx(self.state as usize, ps);
        rc.encode_bit(&mut self.probs[idx], 0); // isMatch = 0

        let ctx = self
            .layout
            .literal_context(pos, prev_byte, self.lc, self.lp);
        let lit_base = self.layout.literal + ctx * LITERAL_SIZE;

        let old_state = self.state;
        self.state = literal_next_state(old_state as usize) as u32;

        if (old_state as usize) < NUM_LIT_STATES {
            encode_bit_tree(rc, &mut self.probs[lit_base..], 8, byte as u32);
        } else {
            let rep0 = self.reps[0] as usize;
            let match_byte = if pos >= rep0 && rep0 > 0 {
                buf[(pos - rep0) & window_mask]
            } else {
                0
            };
            encode_literal_matched(
                rc,
                &mut self.probs[lit_base..],
                byte as u32,
                match_byte as u32,
            );
        }
    }

    /// 编码一个普通匹配（长度 `len >= 2`，实际距离 `dist >= 1`）。
    pub fn encode_match(&mut self, rc: &mut RangeEncoder, len: usize, dist: u32, pos: usize) {
        let ps = self.pos_state(pos);
        let state = self.state as usize;
        rc.encode_bit(&mut self.probs[self.layout.is_match_idx(state, ps)], 1); // isMatch = 1
        rc.encode_bit(&mut self.probs[self.layout.is_rep + state], 0); // isRep = 0
        self.state = match_next_state(state) as u32;

        // 长度。
        self.encode_length(rc, self.layout.len_coder, (len - MATCH_MIN_LEN) as u32, ps);

        // 更新 rep 距离。
        self.reps[3] = self.reps[2];
        self.reps[2] = self.reps[1];
        self.reps[1] = self.reps[0];
        self.reps[0] = dist;

        // 距离。
        let d = dist - 1;
        self.encode_distance(rc, d, len_to_pos_state(len));
    }

    /// 编码 rep 匹配（`rep_idx` 0..3，长度 `len >= 2`）。
    pub fn encode_rep(&mut self, rc: &mut RangeEncoder, rep_idx: usize, len: usize, pos: usize) {
        let ps = self.pos_state(pos);
        let state = self.state as usize;

        rc.encode_bit(&mut self.probs[self.layout.is_match_idx(state, ps)], 1); // isMatch = 1
        rc.encode_bit(&mut self.probs[self.layout.is_rep + state], 1); // isRep = 1

        let old_reps = self.reps;
        if rep_idx == 0 {
            rc.encode_bit(&mut self.probs[self.layout.is_rep_g0 + state], 0); // isRepG0 = 0
            rc.encode_bit(&mut self.probs[self.layout.is_rep0_long_idx(state, ps)], 1);
        // isRep0Long = 1
        } else {
            rc.encode_bit(&mut self.probs[self.layout.is_rep_g0 + state], 1); // isRepG0 = 1
            let dist = old_reps[rep_idx];
            match rep_idx {
                1 => {
                    rc.encode_bit(&mut self.probs[self.layout.is_rep_g1 + state], 0);
                    self.reps[1] = old_reps[0];
                    self.reps[0] = dist;
                }
                2 => {
                    rc.encode_bit(&mut self.probs[self.layout.is_rep_g1 + state], 1);
                    rc.encode_bit(&mut self.probs[self.layout.is_rep_g2 + state], 0);
                    self.reps[2] = old_reps[1];
                    self.reps[1] = old_reps[0];
                    self.reps[0] = dist;
                }
                _ => {
                    rc.encode_bit(&mut self.probs[self.layout.is_rep_g1 + state], 1);
                    rc.encode_bit(&mut self.probs[self.layout.is_rep_g2 + state], 1);
                    self.reps[3] = old_reps[2];
                    self.reps[2] = old_reps[1];
                    self.reps[1] = old_reps[0];
                    self.reps[0] = dist;
                }
            }
        }

        self.state = rep_next_state(state) as u32;
        self.encode_length(
            rc,
            self.layout.rep_len_coder,
            (len - MATCH_MIN_LEN) as u32,
            ps,
        );
    }

    /// 编码短 rep（rep0 长度 1）。
    pub fn encode_short_rep(&mut self, rc: &mut RangeEncoder, pos: usize) {
        let ps = self.pos_state(pos);
        let state = self.state as usize;
        rc.encode_bit(&mut self.probs[self.layout.is_match_idx(state, ps)], 1); // isMatch = 1
        rc.encode_bit(&mut self.probs[self.layout.is_rep + state], 1); // isRep = 1
        rc.encode_bit(&mut self.probs[self.layout.is_rep_g0 + state], 0); // isRepG0 = 0
        rc.encode_bit(&mut self.probs[self.layout.is_rep0_long_idx(state, ps)], 0); // isRep0Long = 0
        self.state = short_rep_next_state(state) as u32;
    }

    /// 编码流结束标记。
    pub fn encode_end_marker(&mut self, rc: &mut RangeEncoder, pos: usize) {
        let ps = self.pos_state(pos);
        let state = self.state as usize;
        rc.encode_bit(&mut self.probs[self.layout.is_match_idx(state, ps)], 1); // isMatch = 1
        rc.encode_bit(&mut self.probs[self.layout.is_rep + state], 0); // isRep = 0
        self.state = match_next_state(state) as u32;

        self.encode_length(rc, self.layout.len_coder, 0, ps);
        self.encode_distance(rc, 0xFFFF_FFFF, 0);
    }

    fn encode_length(&mut self, rc: &mut RangeEncoder, base: usize, sym: u32, ps: usize) {
        if sym >= LEN_NUM_LOW_SYMBOLS as u32 {
            rc.encode_bit(&mut self.probs[base], 1);
            if sym >= (LEN_NUM_LOW_SYMBOLS * 2) as u32 {
                rc.encode_bit(&mut self.probs[base + 8], 1);
                encode_bit_tree(
                    rc,
                    &mut self.probs[base + 256..],
                    LEN_NUM_HIGH_BITS as u32,
                    sym - (LEN_NUM_LOW_SYMBOLS * 2) as u32,
                );
            } else {
                rc.encode_bit(&mut self.probs[base + 8], 0);
                let low = base + 8 + (ps << 4);
                encode_bit_tree(
                    rc,
                    &mut self.probs[low..],
                    LEN_NUM_LOW_BITS as u32,
                    sym - LEN_NUM_LOW_SYMBOLS as u32,
                );
            }
        } else {
            rc.encode_bit(&mut self.probs[base], 0);
            let low = base + (ps << 4);
            encode_bit_tree(rc, &mut self.probs[low..], LEN_NUM_LOW_BITS as u32, sym);
        }
    }

    /// 编码距离（`d = distance - 1` 或 `0xFFFFFFFF` 表示结束标记）。
    fn encode_distance(&mut self, rc: &mut RangeEncoder, d: u32, ltp: usize) {
        let pos_slot = get_pos_slot(d);
        let slot_base = self.layout.pos_slot_base(ltp);
        encode_bit_tree(
            rc,
            &mut self.probs[slot_base..],
            NUM_POS_SLOT_BITS as u32,
            pos_slot,
        );

        if pos_slot >= START_POS_MODEL_INDEX {
            let footer_bits = (pos_slot >> 1) - 1;
            if pos_slot < END_POS_MODEL_INDEX {
                let b = ((2 | (pos_slot & 1)) << footer_bits) as usize;
                let r = d - b as u32;
                let sp = self.layout.spec_pos + b;
                encode_reverse_bit_tree(rc, &mut self.probs[sp..], footer_bits, r);
            } else {
                let b = ((2 | (pos_slot & 1)) << footer_bits) as usize;
                let r = d - b as u32;
                rc.encode_direct_bits(r >> 4, footer_bits - NUM_ALIGN_BITS as u32);
                let al = self.layout.align;
                encode_reverse_bit_tree(rc, &mut self.probs[al..], NUM_ALIGN_BITS as u32, d & 0xF);
            }
        }
    }
}

/// 匹配字面量编码（state >= 7 时，用 match_byte 预测字面量）。
pub fn encode_literal_matched(
    rc: &mut RangeEncoder,
    probs: &mut [u16],
    byte: u32,
    match_byte: u32,
) {
    let mut sym = byte | 0x100;
    let mut mb = match_byte;
    let mut offs = 0x100u32;
    loop {
        mb <<= 1;
        let idx = (offs + (mb & offs) + (sym >> 8)) as usize;
        let bit = (sym >> 7) & 1;
        sym <<= 1;
        offs &= !(mb ^ sym);
        rc.encode_bit(&mut probs[idx], bit);
        if sym >= 0x10000 {
            break;
        }
    }
}

/// 匹配字面量解码（与 [`encode_literal_matched`] 对称）。
pub fn decode_literal_matched(
    rc: &mut crate::lzma::range_coder::RangeDecoder,
    probs: &mut [u16],
    match_byte: u32,
) -> u32 {
    let mut mb = match_byte;
    let mut offs = 0x100u32;
    let mut symbol = 1u32;
    loop {
        mb <<= 1;
        let bit = offs;
        offs &= mb;
        let idx = (offs + bit + symbol) as usize;
        let b = rc.decode_bit(&mut probs[idx]);
        symbol = (symbol << 1) | b;
        if b == 0 {
            offs ^= bit;
        }
        if symbol >= 0x100 {
            break;
        }
    }
    symbol - 0x100
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lzma::range_coder::{RangeDecoder, PROB_INIT};

    #[test]
    fn literal_matched_roundtrip() {
        for &b in &[0u32, 1, 0x55, 0xAA, 0xFF, 0x80, 0x7F, 123] {
            for &m in &[0u32, 0xAA, 0x55, 0xFF, 0x12] {
                let mut enc = RangeEncoder::new();
                let mut ep = vec![PROB_INIT; LITERAL_SIZE];
                encode_literal_matched(&mut enc, &mut ep, b, m);
                let data = enc.finish();

                let mut dec = RangeDecoder::new(&data);
                let mut dp = vec![PROB_INIT; LITERAL_SIZE];
                assert_eq!(decode_literal_matched(&mut dec, &mut dp, m), b);
            }
        }
    }
}
