//! LZMA 编码器：匹配查找 + 贪心决策，驱动低层符号编码器。

use std::io::{Read, Write};

use crate::lzma::lz_encoder::LzEncoder;
use crate::lzma::match_finder::{
    match_len_at_distance, match_len_at_distance_ring, HashChainMatchFinder, StreamingMatchFinder,
};
use crate::lzma::prob_model::{MATCH_MAX_LEN, MATCH_MIN_LEN};
use crate::lzma::range_coder::RangeEncoder;
use crate::lzma::LzmaError;

/// 计算 `pos` 处最优 rep 匹配，返回 `(长度, rep 索引)`。
fn best_rep(data: &[u8], reps: &[u32; 4], pos: usize) -> (usize, usize) {
    let mut best_len = 0usize;
    let mut best_idx = 0usize;
    for (i, &dist) in reps.iter().enumerate() {
        let d = dist as usize;
        if d > 0 && d <= pos {
            let l = match_len_at_distance(data, pos, d, MATCH_MAX_LEN);
            if l > best_len {
                best_len = l;
                best_idx = i;
            }
        }
    }
    (best_len, best_idx)
}

/// 环形窗口版本的 [`best_rep`]。
fn best_rep_ring(
    buf: &[u8],
    window_mask: usize,
    reps: &[u32; 4],
    pos: usize,
    total: usize,
) -> (usize, usize) {
    let mut best_len = 0usize;
    let mut best_idx = 0usize;
    for (i, &dist) in reps.iter().enumerate() {
        let d = dist as usize;
        if d > 0 && d <= pos {
            let l = match_len_at_distance_ring(buf, window_mask, pos, d, total);
            if l > best_len {
                best_len = l;
                best_idx = i;
            }
        }
    }
    (best_len, best_idx)
}

/// 使用惰性匹配策略编码一段数据，返回原始 LZMA 码流（含结束标记，不含 13 字节头）。
pub fn encode(
    input: &[u8],
    lc: u32,
    lp: u32,
    pb: u32,
    dict_size: usize,
    nice_len: usize,
    max_chain: usize,
) -> Vec<u8> {
    encode_inner(input, lc, lp, pb, dict_size, nice_len, max_chain, true)
}

/// 编码已知长度的数据，返回原始 LZMA 码流（不含结束标记，供 LZMA2 分块使用）。
pub fn encode_known_size(
    input: &[u8],
    lc: u32,
    lp: u32,
    pb: u32,
    dict_size: usize,
    nice_len: usize,
    max_chain: usize,
) -> Vec<u8> {
    encode_inner(input, lc, lp, pb, dict_size, nice_len, max_chain, false)
}

#[allow(clippy::too_many_arguments)]
fn encode_inner(
    input: &[u8],
    lc: u32,
    lp: u32,
    pb: u32,
    dict_size: usize,
    nice_len: usize,
    max_chain: usize,
    write_eos: bool,
) -> Vec<u8> {
    let mut enc = LzEncoder::new(lc, lp, pb);
    let mut rc = RangeEncoder::new();
    let mut mf = HashChainMatchFinder::new(input.len(), dict_size, max_chain, nice_len);

    let mut pos = 0usize;
    while pos < input.len() {
        mf.insert(input, pos);

        // 普通匹配。
        let max_dist = dict_size.min(pos);
        let (match_len, match_dist) = mf.find_longest_match(input, pos, max_dist);
        let (best_rep_len, best_rep_idx) = best_rep(input, &enc.reps, pos);

        // 决策。
        let advance;
        if best_rep_len >= MATCH_MIN_LEN && best_rep_len >= match_len {
            enc.encode_rep(&mut rc, best_rep_idx, best_rep_len, pos);
            advance = best_rep_len;
        } else if match_len >= 3 {
            // 惰性匹配：窥视 `pos + 1` 处的普通匹配，若更长则先输出字面量，
            // 把更长的匹配留给下一轮，通常能减少总符号数。
            let peek_dist = dict_size.min(pos + 1);
            let (peek_len, _) = mf.find_longest_match(input, pos + 1, peek_dist);
            if peek_len > match_len {
                enc.encode_literal(&mut rc, input, pos);
                advance = 1;
            } else {
                enc.encode_match(&mut rc, match_len, match_dist as u32, pos);
                advance = match_len;
            }
        } else if best_rep_idx == 0 && best_rep_len >= 1 {
            enc.encode_short_rep(&mut rc, pos);
            advance = 1;
        } else {
            enc.encode_literal(&mut rc, input, pos);
            advance = 1;
        }

        let new_pos = pos + advance;
        for i in (pos + 1)..new_pos {
            mf.insert(input, i);
        }
        pos = new_pos;
    }

    if write_eos {
        enc.encode_end_marker(&mut rc, pos);
    }
    rc.finish()
}

/// 流式编码：从 `reader` 读取输入、把原始 LZMA 码流（含结束标记，不含 13 字节头）写入 `writer`。
///
/// 返回读入的未压缩字节数。内存占用与 `dict_size` 成正比（而非输入长度）。
#[allow(clippy::too_many_arguments)]
pub fn encode_stream<R: Read, W: Write>(
    reader: &mut R,
    lc: u32,
    lp: u32,
    pb: u32,
    dict_size: usize,
    nice_len: usize,
    max_chain: usize,
    writer: &mut W,
) -> Result<usize, LzmaError> {
    let mut enc = LzEncoder::new(lc, lp, pb);
    let mut rc = RangeEncoder::new();

    // 环形窗口大小取 2 的幂，需容纳 dict_size 历史 + 前瞻（含惰性匹配窥视 pos+1 的额外 1 字节）。
    let window_size = (dict_size + MATCH_MAX_LEN + 1).next_power_of_two();
    let window_bits = window_size.trailing_zeros() as usize;
    let window_mask = window_size - 1;
    let mut buf = vec![0u8; window_size];
    let mut mf = StreamingMatchFinder::new(dict_size, window_bits, max_chain, nice_len);

    let mut read_pos = 0usize; // 已读入 buf 的字节数（绝对位置）。
    let mut eof = false;
    let mut pos = 0usize; // 当前编码位置（绝对位置）。

    // 多预读 1 字节，保证惰性匹配窥视 `pos + 1` 时也有完整 MATCH_MAX_LEN 前瞻，
    // 使流式与缓冲版产生一致的匹配决策。
    const LOOKAHEAD: usize = MATCH_MAX_LEN + 1;

    loop {
        // 预读，保证足够前瞻（或读到 EOF）。
        while !eof && read_pos < pos + LOOKAHEAD {
            let mut tmp = [0u8; 8192];
            let want = (pos + LOOKAHEAD - read_pos).min(tmp.len());
            let n = reader
                .read(&mut tmp[..want])
                .map_err(|e| LzmaError::Io(e.kind()))?;
            if n == 0 {
                eof = true;
                break;
            }
            for &b in &tmp[..n] {
                buf[read_pos & window_mask] = b;
                read_pos += 1;
            }
        }

        if pos >= read_pos {
            break;
        }

        mf.insert(&buf, window_mask, pos, read_pos);

        // 普通匹配。
        let max_dist = dict_size.min(pos);
        let (match_len, match_dist) =
            mf.find_longest_match(&buf, window_mask, pos, max_dist, read_pos);
        let (best_rep_len, best_rep_idx) =
            best_rep_ring(&buf, window_mask, &enc.reps, pos, read_pos);

        // 决策（与缓冲版 `encode` 保持一致）。
        let advance;
        if best_rep_len >= MATCH_MIN_LEN && best_rep_len >= match_len {
            enc.encode_rep(&mut rc, best_rep_idx, best_rep_len, pos);
            advance = best_rep_len;
        } else if match_len >= 3 {
            // 惰性匹配：窥视 `pos + 1` 处的普通匹配。
            let peek_dist = dict_size.min(pos + 1);
            let (peek_len, _) =
                mf.find_longest_match(&buf, window_mask, pos + 1, peek_dist, read_pos);
            if peek_len > match_len {
                enc.encode_literal_window(&mut rc, &buf, window_mask, pos);
                advance = 1;
            } else {
                enc.encode_match(&mut rc, match_len, match_dist as u32, pos);
                advance = match_len;
            }
        } else if best_rep_idx == 0 && best_rep_len >= 1 {
            enc.encode_short_rep(&mut rc, pos);
            advance = 1;
        } else {
            enc.encode_literal_window(&mut rc, &buf, window_mask, pos);
            advance = 1;
        }

        let new_pos = pos + advance;
        for i in (pos + 1)..new_pos {
            mf.insert(&buf, window_mask, i, read_pos);
        }
        pos = new_pos;

        // 定期把范围编码器输出写到 writer，避免压缩码流常驻内存。
        if rc.out_len() >= 64 * 1024 {
            rc.drain_to(writer).map_err(|e| LzmaError::Io(e.kind()))?;
        }
    }

    enc.encode_end_marker(&mut rc, pos);
    rc.finish_to(writer).map_err(|e| LzmaError::Io(e.kind()))?;
    Ok(pos)
}
