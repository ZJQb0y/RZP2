//! 标准 LZMA2 分块编解码器（复用 LZMA1 内核）。
//!
//! LZMA2 在 LZMA1 之上增加分块帧：每块可独立重置状态与字典，从而支持并行压缩与
//! 随机访问。字典大小由外层过滤器属性给定，不在块头中携带。
//!
//! 块控制字节（见 xz 规范 5.3.2）：
//! - `0x00`：结束标记。
//! - `0x01`：未压缩块，字典重置。
//! - `0x02`：未压缩块，字典不重置。
//! - `0x80..=0xFF`：LZMA 块，未压缩/压缩大小均显式存储；高两位区分重置语义。

use super::decoder::LzDecoder;
use super::encoder;
use super::{LzmaError, LzmaParams};

/// LZMA2 单块字节数上限。未压缩块与压缩块的大小字段均为 16 位（存 `size-1`），
/// 因此单块最多 64 KiB。
const MAX_CHUNK_SIZE: usize = 64 * 1024;

/// 默认分块大小（64 KiB，保证未压缩块与压缩块的大小字段都放得下）。
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// 把一段数据编码为 LZMA2 帧。
///
/// 每块独立压缩（状态与字典各自重置），不可压缩的块用未压缩块（`0x01`）直存。
/// `chunk_size` 会被钳制到 `1..=MAX_CHUNK_SIZE`。
pub fn encode(input: &[u8], params: &LzmaParams, chunk_size: usize) -> Vec<u8> {
    let chunk_size = chunk_size.clamp(1, MAX_CHUNK_SIZE);
    let mut out = Vec::with_capacity(input.len() / 2 + 16);
    for chunk in input.chunks(chunk_size) {
        out.extend_from_slice(&encode_chunk(chunk, params));
    }
    out.push(0x00); // 结束标记。
    out
}

/// 多进程分块并行压缩 LZMA2 帧，输出与 [`encode`] 逐字节一致。
///
/// 每个块独立编码（互不依赖），因此可以安全地并行；`processes` 会被钳制到
/// `1..=块数`。适合对块数较多的大输入加速。
pub fn encode_parallel(
    input: &[u8],
    params: &LzmaParams,
    chunk_size: usize,
    processes: usize,
) -> Vec<u8> {
    let chunk_size = chunk_size.clamp(1, MAX_CHUNK_SIZE);
    let chunks: Vec<&[u8]> = input.chunks(chunk_size).collect();

    // 多进程并行：见 `crate::parallel::encode_blocks_parallel`。
    let encoded = crate::parallel::encode_blocks_parallel(
        crate::parallel::Encoder::Lzma2Chunk,
        &chunks,
        params,
        processes,
    );

    let mut out = Vec::with_capacity(input.len() / 2 + 16);
    for block in encoded {
        out.extend_from_slice(&block);
    }
    out.push(0x00); // 结束标记。
    out
}

/// 编码单个 LZMA2 块（不含结束标记）。
pub(crate) fn encode_chunk(chunk: &[u8], params: &LzmaParams) -> Vec<u8> {
    let raw = encoder::encode_known_size(
        chunk,
        params.lc,
        params.lp,
        params.pb,
        params.dict_size as usize,
        params.nice_len,
        params.max_chain,
    );
    let mut block = Vec::with_capacity(chunk.len() / 2 + 6);
    if raw.is_empty() || raw.len() >= chunk.len() {
        // 未压缩块：0x01 + 2 字节大端 (size-1) + 原始数据。
        let n = chunk.len();
        block.push(0x01);
        block.push(((n - 1) >> 8) as u8);
        block.push(((n - 1) & 0xFF) as u8);
        block.extend_from_slice(chunk);
    } else {
        // LZMA 块：0xE0 | k（新属性 + 状态与字典重置），
        // 后接未压缩大小(2)、压缩大小(2)、属性(1)、LZMA 数据。
        let usize = chunk.len() - 1;
        let psize = raw.len() - 1;
        block.push(0xE0 | (usize >> 16) as u8);
        block.push((usize >> 8) as u8);
        block.push(usize as u8);
        block.push((psize >> 8) as u8);
        block.push(psize as u8);
        block.push(params.properties());
        block.extend_from_slice(&raw);
    }
    block
}

/// 解析 LZMA 属性字节为 `(lc, lp, pb)`。
fn decode_properties(props: u8) -> Result<(u32, u32, u32), LzmaError> {
    // props = (pb * 5 + lp) * 9 + lc，合法范围为 0..225。
    if props >= 9 * 5 * 5 {
        return Err(LzmaError::BadProperties);
    }
    let lc = (props % 9) as u32;
    let lp = ((props / 9) % 5) as u32;
    let pb = (props / 45) as u32;
    Ok((lc, lp, pb))
}

/// 有状态的 LZMA2 解码器：跨块保持概率模型、LZMA 状态与字典窗口。
pub struct Decoder {
    lz: LzDecoder,
    state: usize,
    reps: [u32; 4],
    /// 当前字典窗口在 `out` 中的起始下标（字典重置时更新）。
    dict_base: usize,
    dict_size: usize,
    out: Vec<u8>,
    /// 是否已读到 LZMA 属性（首个 LZMA 块之前必须读到）。
    has_props: bool,
}

impl Decoder {
    pub fn new(dict_size: usize) -> Self {
        Self {
            lz: LzDecoder::new(3, 0, 2), // 占位，读到属性后重建。
            state: 0,
            reps: [1, 1, 1, 1],
            dict_base: 0,
            dict_size: dict_size.max(1),
            out: Vec::new(),
            has_props: false,
        }
    }

    /// 解码整个 LZMA2 帧，返回全部解压后的字节。
    pub fn decode(mut self, input: &[u8]) -> Result<Vec<u8>, LzmaError> {
        let mut pos = 0usize;
        loop {
            if pos >= input.len() {
                return Err(LzmaError::Truncated);
            }
            let control = input[pos];
            pos += 1;

            if control == 0x00 {
                break; // 结束标记。
            }

            if control < 0x80 {
                // 未压缩块：0x01（字典重置）或 0x02（不重置）。
                if control > 0x02 {
                    return Err(LzmaError::CorruptData);
                }
                if control == 0x01 {
                    // 字典重置：后续 LZMA 块必须带新属性，LZMA 状态也一并复位。
                    self.dict_base = self.out.len();
                    self.state = 0;
                    self.reps = [1, 1, 1, 1];
                    self.has_props = false;
                }
                if pos + 2 > input.len() {
                    return Err(LzmaError::Truncated);
                }
                let n = ((input[pos] as usize) << 8 | (input[pos + 1] as usize)) + 1;
                pos += 2;
                if pos + n > input.len() {
                    return Err(LzmaError::Truncated);
                }
                self.out.extend_from_slice(&input[pos..pos + n]);
                pos += n;
                continue;
            }

            // LZMA 块：control >= 0x80。先读未压缩大小与压缩大小。
            if pos + 4 > input.len() {
                return Err(LzmaError::Truncated);
            }
            let mut usize = ((control & 0x1F) as usize) << 16;
            usize |= (input[pos] as usize) << 8;
            usize |= input[pos + 1] as usize;
            usize += 1;
            let psize = ((input[pos + 2] as usize) << 8 | (input[pos + 3] as usize)) + 1;
            pos += 4;

            // 重置语义由控制字节的 bit6（新属性）与 bit5（字典重置）决定。
            let need_properties = (control & 0x40) != 0;
            let need_dict_reset = (control & 0x20) != 0;

            if need_properties {
                // 新属性：概率模型、状态、字典全部重置。
                if pos >= input.len() {
                    return Err(LzmaError::Truncated);
                }
                let (lc, lp, pb) = decode_properties(input[pos])?;
                pos += 1;
                self.lz = LzDecoder::new(lc, lp, pb);
                self.state = 0;
                self.reps = [1, 1, 1, 1];
                self.dict_base = self.out.len();
                self.has_props = true;
            } else if need_dict_reset {
                // 仅字典重置：状态与 rep 复位，但保留概率模型。
                if !self.has_props {
                    return Err(LzmaError::CorruptData);
                }
                self.state = 0;
                self.reps = [1, 1, 1, 1];
                self.dict_base = self.out.len();
            } else if !self.has_props {
                // 0x80..=0x9F：无任何重置，但必须已有属性。
                return Err(LzmaError::CorruptData);
            }

            if psize > MAX_CHUNK_SIZE {
                return Err(LzmaError::CorruptData);
            }
            if pos + psize > input.len() {
                return Err(LzmaError::Truncated);
            }
            let start_len = self.out.len();
            self.lz.decode_continue(
                &input[pos..pos + psize],
                usize,
                self.dict_size,
                self.dict_base,
                &mut self.out,
                &mut self.state,
                &mut self.reps,
            )?;
            pos += psize;
            if self.out.len() != start_len + usize {
                return Err(LzmaError::CorruptData);
            }
        }
        Ok(self.out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(input: &[u8], chunk_size: usize) {
        let params = LzmaParams::new(3, 0, 2, 1 << 16);
        let packed = encode(input, &params, chunk_size);
        let out = Decoder::new(params.dict_size as usize)
            .decode(&packed)
            .unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn empty_roundtrip() {
        roundtrip(b"", DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn small_roundtrip() {
        roundtrip(b"hello, LZMA2!", DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn incompressible_roundtrip() {
        // 伪随机数据，压缩率差，应走未压缩块路径。
        let mut state = 0x1234_5678u32;
        let mut data = Vec::with_capacity(100_000);
        for _ in 0..100_000 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            data.push((state >> 24) as u8);
        }
        roundtrip(&data, DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn multi_chunk_roundtrip() {
        // 数据长度远大于单个块，覆盖多块拼接与跨块边界。
        let mut data = Vec::new();
        for i in 0..200_000usize {
            data.push((i % 251) as u8);
            data.extend_from_slice(b"lzma2-chunk-boundary-");
        }
        roundtrip(&data, DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn exact_chunk_boundary() {
        // 恰好一个块大小 + 尾部余量。
        let mut data = vec![b'A'; DEFAULT_CHUNK_SIZE];
        data.extend_from_slice(b"tail");
        roundtrip(&data, DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn chunk_size_clamped() {
        // 请求超大块会被钳制到 64 KiB，仍能正确解码。
        let mut data = vec![b'B'; 200_000];
        data.extend_from_slice(b"request-2-mib");
        roundtrip(&data, 1 << 21);
    }

    #[test]
    fn parallel_matches_sequential() {
        let params = LzmaParams::new(3, 0, 2, 1 << 16);
        let mut data = Vec::new();
        for i in 0..300_000usize {
            data.push((i % 251) as u8);
            data.extend_from_slice(b"parallel-lzma2-");
        }
        let seq = encode(&data, &params, DEFAULT_CHUNK_SIZE);
        let par = encode_parallel(&data, &params, DEFAULT_CHUNK_SIZE, 4);
        assert_eq!(par, seq);
        // 并行输出同样可正确解码。
        let out = Decoder::new(1 << 16).decode(&par).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn truncated_without_end_marker() {
        let params = LzmaParams::new(3, 0, 2, 1 << 16);
        let packed = encode(b"data", &params, DEFAULT_CHUNK_SIZE);
        // 去掉结尾的 0x00 结束标记。
        assert_eq!(
            Decoder::new(1 << 16).decode(&packed[..packed.len() - 1]),
            Err(LzmaError::Truncated)
        );
    }

    #[test]
    fn bad_control_byte() {
        // 0x03 既不是结束标记，也不是合法的未压缩块控制字节。
        assert_eq!(
            Decoder::new(1 << 16).decode(&[0x03]),
            Err(LzmaError::CorruptData)
        );
    }

    #[test]
    fn bad_properties() {
        // 属性字节 0xFF 超出合法范围（应 <= 224）。
        assert_eq!(
            Decoder::new(1 << 16).decode(&[0xE0, 0x00, 0x00, 0x00, 0x00, 0xFF]),
            Err(LzmaError::BadProperties)
        );
    }
}
