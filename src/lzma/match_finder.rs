//! LZ77 匹配查找器（哈希链）。
//!
//! 使用 4 字节哈希 + 哈希链查找最长匹配。这里返回的是**实际距离**（1-based），
//! 与编码器/解码器约定一致（编码距离时使用 `distance - 1` 计算 pos_slot）。

/// 哈希链匹配查找器。
pub struct HashChainMatchFinder {
    head: Vec<i32>,
    prev: Vec<i32>,
    table_bits: usize,
    table_mask: usize,
    max_chain: usize,
    nice_len: usize,
}

impl HashChainMatchFinder {
    /// 根据数据长度与字典大小构造。
    ///
    /// `max_chain` 为单个哈希链最多比较的候选数，`nice_len` 为达到即停止搜索的
    /// 匹配长度（快速停断阈值）。二者越大压缩率越高、速度越慢，用于按压缩级别调优。
    pub fn new(data_len: usize, dict_size: usize, max_chain: usize, nice_len: usize) -> Self {
        // 哈希表大小取 2 的幂，约 1/4 的字典大小（下限 1<<10，上限 1<<20）。
        let table_bits = (dict_size.checked_next_power_of_two().unwrap_or(1 << 20) as f64)
            .log2()
            .floor() as usize
            - 2;
        let table_bits = table_bits.clamp(10, 20);
        let table_size = 1usize << table_bits;

        Self {
            head: vec![-1; table_size],
            prev: vec![-1; data_len],
            table_bits,
            table_mask: table_size - 1,
            max_chain,
            nice_len,
        }
    }

    /// 计算 4 字节哈希。
    #[inline]
    fn hash(&self, b0: u8, b1: u8, b2: u8, b3: u8) -> usize {
        let v = (b0 as u32) | ((b1 as u32) << 8) | ((b2 as u32) << 16) | ((b3 as u32) << 24);
        let h = v.wrapping_mul(0x9E37_79B1);
        ((h >> (32 - self.table_bits)) as usize) & self.table_mask
    }

    #[inline]
    fn hash_at(&self, data: &[u8], pos: usize) -> usize {
        self.hash(data[pos], data[pos + 1], data[pos + 2], data[pos + 3])
    }

    /// 查找 `pos` 处的最长匹配，返回 `(length, distance)`；无匹配返回 `(0, 0)`。
    pub fn find_longest_match(&self, data: &[u8], pos: usize, max_dist: usize) -> (usize, usize) {
        if pos + 4 > data.len() {
            return (0, 0);
        }
        let max_len = (data.len() - pos).min(crate::lzma::prob_model::MATCH_MAX_LEN);
        if max_len < crate::lzma::prob_model::MATCH_MIN_LEN {
            return (0, 0);
        }

        let h = self.hash_at(data, pos);
        let mut cur = self.head[h];
        let mut best_len = 0usize;
        let mut best_dist = 0usize;
        let mut chain = 0usize;

        while cur >= 0 && chain < self.max_chain {
            let cur_pos = cur as usize;
            let dist = pos - cur_pos;
            if dist == 0 {
                // 自身（或重复插入的位置），跳过。
                cur = self.prev[cur_pos];
                chain += 1;
                continue;
            }
            if dist > max_dist {
                break;
            }
            // 哈希链中越靠前越近（head 指向最近插入）。
            if data[cur_pos + best_len] == data[pos + best_len] {
                let len = common_prefix_len(&data[cur_pos..], &data[pos..], max_len);
                if len > best_len {
                    best_len = len;
                    best_dist = dist;
                    if len >= max_len {
                        break;
                    }
                    if best_len >= self.nice_len {
                        break;
                    }
                }
            }
            cur = self.prev[cur_pos];
            chain += 1;
        }

        if best_len >= crate::lzma::prob_model::MATCH_MIN_LEN {
            (best_len, best_dist)
        } else {
            (0, 0)
        }
    }

    /// 将 `pos` 插入哈希表。
    pub fn insert(&mut self, data: &[u8], pos: usize) {
        if pos + 4 > data.len() {
            return;
        }
        let h = self.hash_at(data, pos);
        self.prev[pos] = self.head[h];
        self.head[h] = pos as i32;
    }
}

/// 计算两段数据的公共前缀长度（上限 `max`）。
pub fn common_prefix_len(a: &[u8], b: &[u8], max: usize) -> usize {
    let n = a.len().min(b.len()).min(max);
    let mut i = 0;
    while i < n && a[i] == b[i] {
        i += 1;
    }
    i
}

/// 检查 `pos` 处与 `pos - dist` 处的最长匹配长度（用于 rep 匹配）。
pub fn match_len_at_distance(data: &[u8], pos: usize, dist: usize, max_len: usize) -> usize {
    if dist == 0 || pos < dist {
        return 0;
    }
    let n = (data.len() - pos).min(max_len);
    let mut i = 0;
    while i < n && data[pos - dist + i] == data[pos + i] {
        i += 1;
    }
    i
}

/// 环形窗口匹配查找器：`prev` 只占用窗口大小而非整个数据长度，
/// 供流式编码器使用（内存与字典大小成正比，而非输入长度）。
pub struct StreamingMatchFinder {
    head: Vec<i32>,
    prev: Vec<i32>,
    table_bits: usize,
    table_mask: usize,
    max_chain: usize,
    nice_len: usize,
}

impl StreamingMatchFinder {
    /// `window_bits` 为环形窗口大小（2 的幂）的位数；`max_chain`、`nice_len` 含义同
    /// [`HashChainMatchFinder::new`]。
    pub fn new(dict_size: usize, window_bits: usize, max_chain: usize, nice_len: usize) -> Self {
        let table_bits = (dict_size.checked_next_power_of_two().unwrap_or(1 << 20) as f64)
            .log2()
            .floor() as usize
            - 2;
        let table_bits = table_bits.clamp(10, 20);
        let table_size = 1usize << table_bits;
        Self {
            head: vec![-1; table_size],
            prev: vec![-1; 1usize << window_bits],
            table_bits,
            table_mask: table_size - 1,
            max_chain,
            nice_len,
        }
    }

    #[inline]
    fn hash(&self, b0: u8, b1: u8, b2: u8, b3: u8) -> usize {
        let v = (b0 as u32) | ((b1 as u32) << 8) | ((b2 as u32) << 16) | ((b3 as u32) << 24);
        let h = v.wrapping_mul(0x9E37_79B1);
        ((h >> (32 - self.table_bits)) as usize) & self.table_mask
    }

    #[inline]
    fn hash_at(&self, buf: &[u8], window_mask: usize, pos: usize) -> usize {
        self.hash(
            buf[pos & window_mask],
            buf[(pos + 1) & window_mask],
            buf[(pos + 2) & window_mask],
            buf[(pos + 3) & window_mask],
        )
    }

    /// 插入位置 `pos`（要求 `pos + 4 <= total`）。
    #[inline]
    pub fn insert(&mut self, buf: &[u8], window_mask: usize, pos: usize, total: usize) {
        if pos + 4 > total {
            return;
        }
        let h = self.hash_at(buf, window_mask, pos);
        let slot = pos & window_mask;
        self.prev[slot] = self.head[h];
        self.head[h] = pos as i32;
    }

    /// 查找 `pos` 处的最长匹配，返回 `(length, distance)`；`total` 为当前已读入的字节数。
    pub fn find_longest_match(
        &self,
        buf: &[u8],
        window_mask: usize,
        pos: usize,
        max_dist: usize,
        total: usize,
    ) -> (usize, usize) {
        if pos + 4 > total {
            return (0, 0);
        }
        let max_len = (total - pos).min(crate::lzma::prob_model::MATCH_MAX_LEN);
        if max_len < crate::lzma::prob_model::MATCH_MIN_LEN {
            return (0, 0);
        }

        let h = self.hash_at(buf, window_mask, pos);
        let mut cur = self.head[h];
        let mut best_len = 0usize;
        let mut best_dist = 0usize;
        let mut chain = 0usize;

        while cur >= 0 && chain < self.max_chain {
            let cur_pos = cur as usize;
            let dist = pos - cur_pos;
            if dist == 0 {
                cur = self.prev[cur_pos & window_mask];
                chain += 1;
                continue;
            }
            if dist > max_dist {
                break;
            }
            if buf[(cur_pos + best_len) & window_mask] == buf[(pos + best_len) & window_mask] {
                let len = common_prefix_len_ring(buf, window_mask, cur_pos, pos, max_len);
                if len > best_len {
                    best_len = len;
                    best_dist = dist;
                    if len >= max_len {
                        break;
                    }
                    if best_len >= self.nice_len {
                        break;
                    }
                }
            }
            cur = self.prev[cur_pos & window_mask];
            chain += 1;
        }

        if best_len >= crate::lzma::prob_model::MATCH_MIN_LEN {
            (best_len, best_dist)
        } else {
            (0, 0)
        }
    }
}

/// 环形窗口上的公共前缀长度比较（`max` 为上限）。
pub fn common_prefix_len_ring(
    buf: &[u8],
    window_mask: usize,
    a: usize,
    b: usize,
    max: usize,
) -> usize {
    let mut i = 0;
    while i < max && buf[(a + i) & window_mask] == buf[(b + i) & window_mask] {
        i += 1;
    }
    i
}

/// 环形窗口上的 rep 匹配长度（`total` 为当前已读入的字节数）。
pub fn match_len_at_distance_ring(
    buf: &[u8],
    window_mask: usize,
    pos: usize,
    dist: usize,
    total: usize,
) -> usize {
    if dist == 0 || pos < dist {
        return 0;
    }
    let max_len = (total - pos).min(crate::lzma::prob_model::MATCH_MAX_LEN);
    let mut i = 0;
    while i < max_len && buf[(pos - dist + i) & window_mask] == buf[(pos + i) & window_mask] {
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_repeated_match() {
        let data = b"hello hello hello world";
        let mut mf = HashChainMatchFinder::new(data.len(), 1 << 16, 1 << 8, 273);
        // 先插入前 11 个位置（覆盖第一个 "hello "）。
        for i in 0..11 {
            if i + 4 <= data.len() {
                mf.insert(data, i);
            }
        }
        // 位置 6 是第二个 "hello" 的 'h'，应匹配距离 6、长度 12。
        let (len, dist) = mf.find_longest_match(data, 6, 1 << 16);
        assert_eq!(len, 12);
        assert_eq!(dist, 6);
    }

    #[test]
    fn skips_self() {
        let data = b"hello hello hello world";
        let mut mf = HashChainMatchFinder::new(data.len(), 1 << 16, 1 << 8, 273);
        // 把位置 6 也插入后，查找 6 应跳过自身、仍找到位置 0。
        for i in 0..=6 {
            if i + 4 <= data.len() {
                mf.insert(data, i);
            }
        }
        let (len, dist) = mf.find_longest_match(data, 6, 1 << 16);
        assert_eq!(len, 12);
        assert_eq!(dist, 6);
    }

    #[test]
    fn no_match_at_start() {
        let data = b"abcdefghij";
        let mf = HashChainMatchFinder::new(data.len(), 1 << 16, 1 << 8, 273);
        let (len, dist) = mf.find_longest_match(data, 0, 1 << 16);
        assert_eq!((len, dist), (0, 0));
    }

    #[test]
    fn common_prefix() {
        assert_eq!(common_prefix_len(b"abcd", b"abce", 100), 3);
        assert_eq!(common_prefix_len(b"abcd", b"abcd", 100), 4);
        assert_eq!(common_prefix_len(b"a", b"a", 100), 1);
    }
}
