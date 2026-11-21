//! LZMA 自适应概率模型常量与概率数组布局。
//!
//! 概率为 11-bit（`BIT_MODEL_TOTAL = 2048`），初始值 `PROB_INIT = 1024`。
//! 编码器与解码器各自维护一份概率数组，数组布局只需在各自内部保持一致，
//! 关键是与 LZMA SDK 保持相同的「比特编码顺序」与「上下文映射」。

use crate::lzma::range_coder::PROB_INIT;

/// 状态数量。
pub const NUM_STATES: usize = 12;
/// 字面量状态阈值（`state < 7` 使用普通字面量，否则使用匹配字面量）。
pub const NUM_LIT_STATES: usize = 7;

/// 匹配最小长度。
pub const MATCH_MIN_LEN: usize = 2;
/// 匹配最大长度。
pub const MATCH_MAX_LEN: usize = 273;

/// 位置槽比特数。
pub const NUM_POS_SLOT_BITS: usize = 6;
/// 距离编码直接比特对齐比特数。
pub const NUM_ALIGN_BITS: usize = 4;
/// 对齐表大小。
pub const ALIGN_TABLE_SIZE: usize = 1 << NUM_ALIGN_BITS;
/// 距离编码中需要额外比特的起始 pos_slot。
pub const START_POS_MODEL_INDEX: u32 = 4;
/// 距离编码中走「直接比特 + 对齐」分支的 pos_slot 阈值。
pub const END_POS_MODEL_INDEX: u32 = 14;
/// 使用 pos 编码器的完整距离数量。
pub const NUM_FULL_DISTANCES: usize = 1 << (END_POS_MODEL_INDEX >> 1);

/// 长度编码器布局常量。
pub const LEN_NUM_LOW_BITS: usize = 3;
pub const LEN_NUM_LOW_SYMBOLS: usize = 1 << LEN_NUM_LOW_BITS;
pub const LEN_NUM_HIGH_BITS: usize = 8;
pub const LEN_NUM_HIGH_SYMBOLS: usize = 1 << LEN_NUM_HIGH_BITS;

/// 字面量每个上下文使用的概率数量（`0x300 = 768`）。
pub const LITERAL_SIZE: usize = 0x300;

/// 计算距离 `pos`（`pos >= 0`）对应的 pos_slot。
///
/// 等价于 LZMA SDK 的 `GetPosSlot`：`pos=0 → 0`、`pos=1 → 1`，
/// 其余为 `2 * (floor(log2(pos)) - 1) + (pos >> (floor(log2(pos)) - 1))`。
pub fn get_pos_slot(pos: u32) -> u32 {
    if pos < 2 {
        return pos;
    }
    let log = 31 - pos.leading_zeros(); // floor(log2(pos))
    let zz = log - 1;
    (zz + zz) + (pos >> zz)
}

/// 概率数组布局（编码器与解码器共用此布局）。
#[derive(Debug, Clone)]
pub struct Layout {
    /// `1 << pb`。
    pub num_pos_states: usize,
    /// 字面量上下文数量：`1 << (lc + lp)`。
    pub literal_contexts: usize,

    pub is_match: usize,
    pub is_rep: usize,
    pub is_rep_g0: usize,
    pub is_rep_g1: usize,
    pub is_rep_g2: usize,
    pub is_rep0_long: usize,
    pub pos_slot: usize,
    pub spec_pos: usize,
    pub align: usize,
    pub len_coder: usize,
    pub rep_len_coder: usize,
    pub literal: usize,
    /// 概率数组总长度。
    pub total: usize,
}

impl Layout {
    pub fn new(lc: u32, lp: u32, pb: u32) -> Self {
        let num_pos_states = 1usize << pb;
        let literal_contexts = 1usize << (lc + lp);

        let is_match = 0;
        let is_rep = is_match + NUM_STATES * num_pos_states;
        let is_rep_g0 = is_rep + NUM_STATES;
        let is_rep_g1 = is_rep_g0 + NUM_STATES;
        let is_rep_g2 = is_rep_g1 + NUM_STATES;
        let is_rep0_long = is_rep_g2 + NUM_STATES;
        let pos_slot = is_rep0_long + NUM_STATES * num_pos_states;
        let spec_pos = pos_slot + 4 * 64;
        let align = spec_pos + NUM_FULL_DISTANCES;
        let len_coder = align + ALIGN_TABLE_SIZE;
        let rep_len_coder = len_coder + 512;
        let literal = rep_len_coder + 512;
        let total = literal + literal_contexts * LITERAL_SIZE;

        Self {
            num_pos_states,
            literal_contexts,
            is_match,
            is_rep,
            is_rep_g0,
            is_rep_g1,
            is_rep_g2,
            is_rep0_long,
            pos_slot,
            spec_pos,
            align,
            len_coder,
            rep_len_coder,
            literal,
            total,
        }
    }

    /// 分配并初始化概率数组。
    pub fn alloc(&self) -> Vec<u16> {
        vec![PROB_INIT; self.total]
    }

    /// `is_match[state][pos_state]`。
    #[inline]
    pub fn is_match_idx(&self, state: usize, pos_state: usize) -> usize {
        self.is_match + pos_state * NUM_STATES + state
    }

    /// `is_rep0_long[state][pos_state]`。
    #[inline]
    pub fn is_rep0_long_idx(&self, state: usize, pos_state: usize) -> usize {
        self.is_rep0_long + pos_state * NUM_STATES + state
    }

    /// 字面量上下文（由位置与前一字节决定）。
    #[inline]
    pub fn literal_context(&self, pos: usize, prev_byte: u8, lc: u32, lp: u32) -> usize {
        let pos_part = (pos & ((1usize << lp) - 1)) << lc;
        let byte_part = if lc == 0 {
            0
        } else {
            (prev_byte >> (8 - lc)) as usize
        };
        pos_part | byte_part
    }

    /// `pos_slot[len_to_pos_state]` 的基址。
    #[inline]
    pub fn pos_slot_base(&self, len_to_pos_state: usize) -> usize {
        self.pos_slot + len_to_pos_state * 64
    }
}

/// 长度编码器的 `len_to_pos_state`：`min(len - 2, 3)`。
#[inline]
pub fn len_to_pos_state(len: usize) -> usize {
    let l = len.saturating_sub(MATCH_MIN_LEN);
    if l > 3 {
        3
    } else {
        l
    }
}

/// 字面量后的状态转移。
#[inline]
pub fn literal_next_state(state: usize) -> usize {
    if state < 4 {
        0
    } else if state < 10 {
        state - 3
    } else {
        state - 6
    }
}

/// 普通匹配后的状态转移。
#[inline]
pub fn match_next_state(state: usize) -> usize {
    if state < NUM_LIT_STATES {
        NUM_LIT_STATES
    } else {
        10
    }
}

/// rep 匹配后的状态转移。
#[inline]
pub fn rep_next_state(state: usize) -> usize {
    if state < NUM_LIT_STATES {
        8
    } else {
        11
    }
}

/// 短 rep（rep0 长度 1）后的状态转移。
#[inline]
pub fn short_rep_next_state(state: usize) -> usize {
    if state < NUM_LIT_STATES {
        9
    } else {
        11
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pos_slot_values() {
        // 与 LZMA SDK GetPosSlot 对齐。
        assert_eq!(get_pos_slot(0), 0);
        assert_eq!(get_pos_slot(1), 1);
        assert_eq!(get_pos_slot(2), 2);
        assert_eq!(get_pos_slot(3), 3);
        assert_eq!(get_pos_slot(4), 4);
        assert_eq!(get_pos_slot(5), 4);
        assert_eq!(get_pos_slot(6), 5);
        assert_eq!(get_pos_slot(7), 5);
        assert_eq!(get_pos_slot(8), 6);
        assert_eq!(get_pos_slot(11), 6);
        assert_eq!(get_pos_slot(12), 7);
        assert_eq!(get_pos_slot(15), 7);
        assert_eq!(get_pos_slot(16), 8);
        assert_eq!(get_pos_slot(23), 8);
        assert_eq!(get_pos_slot(24), 9);
    }

    #[test]
    fn state_transitions() {
        // kLiteralNextStates = {0,0,0,0,1,2,3,4,5,6,4,5}
        assert_eq!(literal_next_state(0), 0);
        assert_eq!(literal_next_state(3), 0);
        assert_eq!(literal_next_state(4), 1);
        assert_eq!(literal_next_state(6), 3);
        assert_eq!(literal_next_state(7), 4);
        assert_eq!(literal_next_state(9), 6);
        assert_eq!(literal_next_state(10), 4);
        assert_eq!(literal_next_state(11), 5);

        assert_eq!(match_next_state(0), 7);
        assert_eq!(match_next_state(6), 7);
        assert_eq!(match_next_state(7), 10);
        assert_eq!(match_next_state(11), 10);

        assert_eq!(rep_next_state(6), 8);
        assert_eq!(rep_next_state(7), 11);
        assert_eq!(short_rep_next_state(6), 9);
        assert_eq!(short_rep_next_state(7), 11);
    }
}
