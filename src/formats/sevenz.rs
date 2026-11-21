//! 7z 归档解压（7-Zip 格式子集）。
//!
//! 支持 7z 格式的签名头、明文或编码（压缩）头、PackInfo / UnPackInfo /
//! SubStreamsInfo / FilesInfo 解析，并以 LZMA2、LZMA1 或 Copy 作为文件夹解码内核。
//! 目前暂不支持多 coder 文件夹（如 BCJ + LZMA2 链）与加密头。

use std::fmt;

use crate::archive::Entry;
use crate::crc::crc32;
use crate::lzma::lzma2;
use crate::lzma::{LzDecoder, LzmaError};

const SIGNATURE: [u8; 6] = *b"7z\xBC\xAF\x27\x1C";
const HEADER_SIZE: usize = 32;

// Property IDs。
const NID_END: u64 = 0x00;
const NID_HEADER: u64 = 0x01;
const NID_ARCHIVE_PROPERTIES: u64 = 0x02;
const NID_ADDITIONAL_STREAMS_INFO: u64 = 0x03;
const NID_MAIN_STREAMS_INFO: u64 = 0x04;
const NID_FILES_INFO: u64 = 0x05;
const NID_PACK_INFO: u64 = 0x06;
const NID_UNPACK_INFO: u64 = 0x07;
const NID_SUBSTREAMS_INFO: u64 = 0x08;
const NID_SIZE: u64 = 0x09;
const NID_CRC: u64 = 0x0A;
const NID_FOLDER: u64 = 0x0B;
const NID_CODERS_UNPACK_SIZE: u64 = 0x0C;
const NID_NUM_UNPACK_STREAM: u64 = 0x0D;
const NID_EMPTY_STREAM: u64 = 0x0E;
const NID_EMPTY_FILE: u64 = 0x0F;
const NID_ANTI: u64 = 0x10;
const NID_NAME: u64 = 0x11;
const NID_CTIME: u64 = 0x12;
const NID_ATIME: u64 = 0x13;
const NID_MTIME: u64 = 0x14;
const NID_WIN_ATTRIBUTES: u64 = 0x15;
const NID_ENCODED_HEADER: u64 = 0x17;
const NID_START_POS: u64 = 0x18;

/// 7z 解压错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SevenZError {
    Truncated,
    Corrupt,
    BadMagic,
    UnsupportedVersion,
    CrcMismatch,
    UnsupportedCodec(String),
    UnsupportedFeature(&'static str),
    BadUtf8,
    Lzma(LzmaError),
}

impl fmt::Display for SevenZError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated 7z stream"),
            Self::Corrupt => write!(f, "corrupt 7z stream"),
            Self::BadMagic => write!(f, "not a 7z archive"),
            Self::UnsupportedVersion => write!(f, "unsupported 7z archive version"),
            Self::CrcMismatch => write!(f, "7z header/data CRC mismatch"),
            Self::UnsupportedCodec(id) => write!(f, "unsupported 7z codec {id}"),
            Self::UnsupportedFeature(feature) => write!(f, "unsupported 7z feature: {feature}"),
            Self::BadUtf8 => write!(f, "invalid UTF-8 in 7z entry name"),
            Self::Lzma(e) => write!(f, "LZMA error: {e}"),
        }
    }
}

impl std::error::Error for SevenZError {}

impl From<LzmaError> for SevenZError {
    fn from(e: LzmaError) -> Self {
        Self::Lzma(e)
    }
}

/// 带游标的字节读取器。
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn remaining_slice(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    fn read_byte(&mut self) -> Result<u8, SevenZError> {
        let b = *self.buf.get(self.pos).ok_or(SevenZError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], SevenZError> {
        if self.pos + n > self.buf.len() {
            return Err(SevenZError::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn skip(&mut self, n: usize) -> Result<(), SevenZError> {
        self.read_bytes(n).map(|_| ())
    }

    fn read_u32(&mut self) -> Result<u32, SevenZError> {
        Ok(u32::from_le_bytes(self.read_bytes(4)?.try_into().unwrap()))
    }

    fn read_u64(&mut self) -> Result<u64, SevenZError> {
        Ok(u64::from_le_bytes(self.read_bytes(8)?.try_into().unwrap()))
    }

    /// 7z 可变长度整数（最多 9 字节）。
    fn read_number(&mut self) -> Result<u64, SevenZError> {
        let b = self.read_byte()?;
        if b & 0x80 == 0 {
            return Ok(b as u64);
        }
        if self.remaining() == 0 {
            return Err(SevenZError::Truncated);
        }
        let mut value = self.read_byte()? as u64;
        for i in 1..8 {
            let mask = 0x80u8 >> i;
            if b & mask == 0 {
                let high = (b & (mask - 1)) as u64;
                value |= high << (i * 8);
                return Ok(value);
            }
            if self.remaining() == 0 {
                return Err(SevenZError::Truncated);
            }
            value |= (self.read_byte()? as u64) << (i * 8);
        }
        Ok(value)
    }

    /// 逐 bit 读取一个布尔向量（MSB-first）。
    fn read_bool_vector(&mut self, n: usize) -> Result<Vec<bool>, SevenZError> {
        let mut v = Vec::with_capacity(n);
        let mut b = 0u8;
        let mut mask = 0u8;
        for _ in 0..n {
            if mask == 0 {
                b = self.read_byte()?;
                mask = 0x80;
            }
            v.push((b & mask) != 0);
            mask >>= 1;
        }
        Ok(v)
    }

    /// `ReadBoolVector2`：一个字节标记是否全部定义。
    fn read_bool_vector2(&mut self, n: usize) -> Result<Vec<bool>, SevenZError> {
        let all = self.read_byte()?;
        if all != 0 {
            return Ok(vec![true; n]);
        }
        self.read_bool_vector(n)
    }
}

/// 一个文件夹（单个 coder 的压缩单元）。
struct Folder {
    codec_id: Vec<u8>,
    props: Vec<u8>,
    /// 该文件夹对应的 packed stream 下标（相对当前 StreamsInfo）。
    pack_index: usize,
    /// 文件夹解压后的总大小（coder 主输出流大小）。
    unpack_size: u64,
}

/// 一段 StreamsInfo（主数据流或编码头数据流）。
struct StreamsInfo {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
    folders: Vec<Folder>,
    folder_crcs: Vec<Option<u32>>,
    num_unpack_streams: Vec<u64>,
    unpack_sizes: Vec<u64>,
    digests: Vec<Option<u32>>,
}

/// 解压整个 7z 归档，返回条目列表。
pub fn decode(input: &[u8]) -> Result<Vec<Entry>, SevenZError> {
    if input.len() < HEADER_SIZE {
        return Err(SevenZError::Truncated);
    }
    if input[0..6] != SIGNATURE {
        return Err(SevenZError::BadMagic);
    }
    let major = input[6];
    let minor = input[7];
    if major != 0 {
        return Err(SevenZError::UnsupportedVersion);
    }
    let _ = minor;

    // 校验签名头的 StartHeaderCRC（覆盖 NextHeaderOffset/Size/CRC 共 20 字节）。
    let start_crc = u32::from_le_bytes(input[8..12].try_into().unwrap());
    if crc32(&input[12..32]) != start_crc {
        return Err(SevenZError::CrcMismatch);
    }

    let next_header_offset = u64::from_le_bytes(input[12..20].try_into().unwrap());
    let next_header_size = u64::from_le_bytes(input[20..28].try_into().unwrap());
    let next_header_crc = u32::from_le_bytes(input[28..32].try_into().unwrap());

    if next_header_size == 0 {
        if next_header_offset != 0 || next_header_crc != 0 {
            return Err(SevenZError::Corrupt);
        }
        return Ok(Vec::new());
    }

    let hdr_start = HEADER_SIZE + next_header_offset as usize;
    let hdr_end = hdr_start + next_header_size as usize;
    let header_bytes = input
        .get(hdr_start..hdr_end)
        .ok_or(SevenZError::Truncated)?;
    if crc32(header_bytes) != next_header_crc {
        return Err(SevenZError::CrcMismatch);
    }

    // 头部可能是明文 kHeader，也可能先是一个编码头（kEncodedHeader）。
    let header_buf = open_header(header_bytes, input)?;

    let mut r = Reader::new(&header_buf);
    if r.read_number()? != NID_HEADER {
        return Err(SevenZError::Corrupt);
    }

    let mut data_vector: Vec<Vec<u8>> = Vec::new();
    let mut main_streams: Option<StreamsInfo> = None;
    let mut files: Option<FilesInfo> = None;

    let mut t = r.read_number()?;
    if t == NID_ARCHIVE_PROPERTIES {
        skip_archive_properties(&mut r)?;
        t = r.read_number()?;
    }
    if t == NID_ADDITIONAL_STREAMS_INFO {
        let si = parse_streams_info(&mut r)?;
        data_vector = decode_folders(&si, input)?;
        t = r.read_number()?;
    }
    if t == NID_MAIN_STREAMS_INFO {
        main_streams = Some(parse_streams_info(&mut r)?);
        t = r.read_number()?;
    }
    if t == NID_FILES_INFO {
        let num_files = r.read_number()? as usize;
        files = Some(parse_files_info(&mut r, &data_vector, num_files)?);
        t = r.read_number()?;
    }
    if t != NID_END {
        return Err(SevenZError::Corrupt);
    }

    // 主数据流文件夹解码并拆分为子流。
    let substreams = match main_streams {
        Some(si) => decode_substreams(&si, input)?,
        None => Vec::new(),
    };

    build_entries(files, &substreams)
}

/// 打开头部：返回应当以 `kHeader` 开头的明文头字节。
fn open_header(header_bytes: &[u8], input: &[u8]) -> Result<Vec<u8>, SevenZError> {
    let mut r = Reader::new(header_bytes);
    let t = r.read_number()?;
    if t == NID_HEADER {
        return Ok(header_bytes.to_vec());
    }
    if t != NID_ENCODED_HEADER {
        return Err(SevenZError::Corrupt);
    }
    // 编码头：其 StreamsInfo 描述压缩后的头数据。
    let si = parse_streams_info(&mut r)?;
    let mut data = decode_folders(&si, input)?;
    if data.len() != 1 {
        return Err(SevenZError::UnsupportedFeature(
            "multi-stream encoded header",
        ));
    }
    let decoded = data.pop().unwrap();
    let mut dr = Reader::new(&decoded);
    if dr.read_number()? != NID_HEADER {
        return Err(SevenZError::Corrupt);
    }
    Ok(decoded)
}

fn skip_archive_properties(r: &mut Reader) -> Result<(), SevenZError> {
    loop {
        let t = r.read_number()?;
        if t == NID_END {
            return Ok(());
        }
        let size = r.read_number()? as usize;
        r.skip(size)?;
    }
}

fn skip_data(r: &mut Reader) -> Result<(), SevenZError> {
    let size = r.read_number()? as usize;
    r.skip(size)
}

fn parse_streams_info(r: &mut Reader) -> Result<StreamsInfo, SevenZError> {
    let mut pack_pos = 0u64;
    let mut pack_sizes = Vec::new();
    let mut folders = Vec::new();
    let mut folder_crcs = Vec::new();
    let mut num_unpack_streams = Vec::new();
    let mut unpack_sizes = Vec::new();
    let mut digests = Vec::new();

    let mut t = r.read_number()?;
    if t == NID_PACK_INFO {
        pack_pos = r.read_number()?;
        parse_pack_info(r, &mut pack_sizes)?;
        t = r.read_number()?;
    }
    if t == NID_UNPACK_INFO {
        parse_unpack_info(r, &mut folders, &mut folder_crcs)?;
        t = r.read_number()?;
    }
    if t == NID_SUBSTREAMS_INFO {
        parse_substreams_info(
            r,
            &folders,
            &folder_crcs,
            &mut num_unpack_streams,
            &mut unpack_sizes,
            &mut digests,
        )?;
        t = r.read_number()?;
    } else {
        // 没有 SubStreamsInfo：每个文件夹恰好一个子流。
        num_unpack_streams.clear();
        unpack_sizes.clear();
        digests.clear();
        for (i, f) in folders.iter().enumerate() {
            num_unpack_streams.push(1);
            unpack_sizes.push(f.unpack_size);
            digests.push(folder_crcs.get(i).copied().flatten());
        }
    }

    if t != NID_END {
        return Err(SevenZError::Corrupt);
    }

    Ok(StreamsInfo {
        pack_pos,
        pack_sizes,
        folders,
        folder_crcs,
        num_unpack_streams,
        unpack_sizes,
        digests,
    })
}

fn parse_pack_info(r: &mut Reader, pack_sizes: &mut Vec<u64>) -> Result<(), SevenZError> {
    let n = r.read_number()? as usize;
    // kSize（0x09）之后是各 packed stream 的大小。
    if r.read_number()? != NID_SIZE {
        return Err(SevenZError::Corrupt);
    }
    pack_sizes.clear();
    for _ in 0..n {
        pack_sizes.push(r.read_number()?);
    }
    loop {
        let t = r.read_number()?;
        if t == NID_END {
            return Ok(());
        }
        if t == NID_CRC {
            let _ = read_hash_digests(r, n)?;
        } else {
            skip_data(r)?;
        }
    }
}

fn parse_unpack_info(
    r: &mut Reader,
    folders: &mut Vec<Folder>,
    folder_crcs: &mut Vec<Option<u32>>,
) -> Result<(), SevenZError> {
    if r.read_number()? != NID_FOLDER {
        return Err(SevenZError::Corrupt);
    }
    let num_folders = r.read_number()? as usize;

    // kFolder 的 External 标记：0 表示文件夹信息内联，否则在附加流中。
    let external = r.read_byte()?;
    if external != 0 {
        let _data_index = r.read_number()?;
        return Err(SevenZError::UnsupportedFeature("external folder info"));
    }

    folders.clear();
    let mut pack_stream_index = 0usize;
    for _ in 0..num_folders {
        folders.push(parse_folder(r, &mut pack_stream_index)?);
    }

    if r.read_number()? != NID_CODERS_UNPACK_SIZE {
        return Err(SevenZError::Corrupt);
    }
    let mut coder_unpack_sizes = Vec::with_capacity(num_folders);
    for _ in 0..num_folders {
        coder_unpack_sizes.push(r.read_number()?);
    }
    for (folder, size) in folders.iter_mut().zip(coder_unpack_sizes) {
        folder.unpack_size = size;
    }

    loop {
        let t = r.read_number()?;
        if t == NID_END {
            return Ok(());
        }
        if t == NID_CRC {
            *folder_crcs = read_hash_digests(r, num_folders)?;
        } else {
            skip_data(r)?;
        }
    }
}

fn parse_folder(r: &mut Reader, pack_stream_index: &mut usize) -> Result<Folder, SevenZError> {
    let num_coders = r.read_number()? as usize;
    if num_coders != 1 {
        return Err(SevenZError::UnsupportedFeature("multi-coder folder"));
    }

    let main_byte = r.read_byte()?;
    if main_byte & 0xC0 != 0 {
        return Err(SevenZError::UnsupportedFeature("coder flags"));
    }
    let id_size = (main_byte & 0x0F) as usize;
    if id_size > 8 {
        return Err(SevenZError::Corrupt);
    }
    let codec_id = r.read_bytes(id_size)?.to_vec();

    let mut num_in = 1u64;
    let mut num_out = 1u64;
    if main_byte & 0x10 != 0 {
        num_in = r.read_number()?;
        num_out = r.read_number()?;
    }
    let mut props = Vec::new();
    if main_byte & 0x20 != 0 {
        let props_size = r.read_number()? as usize;
        props = r.read_bytes(props_size)?.to_vec();
    }

    if num_in != 1 || num_out != 1 {
        return Err(SevenZError::UnsupportedFeature("complex coder streams"));
    }

    let pack_index = *pack_stream_index;
    *pack_stream_index += 1;
    Ok(Folder {
        codec_id,
        props,
        pack_index,
        unpack_size: 0,
    })
}

#[allow(clippy::too_many_arguments)]
fn parse_substreams_info(
    r: &mut Reader,
    folders: &[Folder],
    folder_crcs: &[Option<u32>],
    num_unpack_streams: &mut Vec<u64>,
    unpack_sizes: &mut Vec<u64>,
    digests: &mut Vec<Option<u32>>,
) -> Result<(), SevenZError> {
    let num_folders = folders.len();
    num_unpack_streams.clear();
    unpack_sizes.clear();
    digests.clear();

    let mut t = r.read_number()?;
    if t == NID_NUM_UNPACK_STREAM {
        for _ in 0..num_folders {
            num_unpack_streams.push(r.read_number()?);
        }
        t = r.read_number()?;
    } else {
        num_unpack_streams.resize(num_folders, 1);
    }

    if t == NID_SIZE {
        for (fi, folder) in folders.iter().enumerate() {
            let nsub = num_unpack_streams[fi] as usize;
            if nsub == 0 {
                continue;
            }
            let mut sum = 0u64;
            for _ in 1..nsub {
                let s = r.read_number()?;
                unpack_sizes.push(s);
                sum += s;
            }
            if folder.unpack_size < sum {
                return Err(SevenZError::Corrupt);
            }
            unpack_sizes.push(folder.unpack_size - sum);
        }
        t = r.read_number()?;
    } else {
        for (fi, folder) in folders.iter().enumerate() {
            if num_unpack_streams[fi] > 1 {
                return Err(SevenZError::Corrupt);
            }
            if num_unpack_streams[fi] == 1 {
                unpack_sizes.push(folder.unpack_size);
            }
        }
    }

    let num_digests: usize = folders
        .iter()
        .enumerate()
        .map(|(fi, _)| {
            let nsub = num_unpack_streams[fi] as usize;
            if nsub == 1 && folder_crcs.get(fi).copied().flatten().is_some() {
                0
            } else {
                nsub
            }
        })
        .sum();

    loop {
        if t == NID_END {
            break;
        }
        if t == NID_CRC {
            let defs = r.read_bool_vector2(num_digests)?;
            let mut k2 = 0usize;
            for (fi, _) in folders.iter().enumerate() {
                let nsub = num_unpack_streams[fi] as usize;
                if nsub == 1 {
                    if let Some(crc) = folder_crcs.get(fi).copied().flatten() {
                        digests.push(Some(crc));
                        continue;
                    }
                }
                for _ in 0..nsub {
                    let defined = defs[k2];
                    k2 += 1;
                    digests.push(if defined { Some(r.read_u32()?) } else { None });
                }
            }
        } else {
            skip_data(r)?;
        }
        t = r.read_number()?;
    }

    if digests.len() != unpack_sizes.len() {
        digests.clear();
        for (fi, _) in folders.iter().enumerate() {
            let nsub = num_unpack_streams[fi] as usize;
            if nsub == 1 {
                if let Some(crc) = folder_crcs.get(fi).copied().flatten() {
                    digests.push(Some(crc));
                    continue;
                }
            }
            for _ in 0..nsub {
                digests.push(None);
            }
        }
    }

    Ok(())
}

fn read_hash_digests(r: &mut Reader, n: usize) -> Result<Vec<Option<u32>>, SevenZError> {
    let defs = r.read_bool_vector2(n)?;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        out.push(if defs[i] { Some(r.read_u32()?) } else { None });
    }
    Ok(out)
}

/// 一个文件在 FilesInfo 中的元数据。
struct FilesInfo {
    names: Vec<String>,
    empty_stream: Vec<bool>,
    empty_file: Vec<bool>,
    mtimes: Vec<Option<u64>>,
}

fn parse_files_info(
    r: &mut Reader,
    data_vector: &[Vec<u8>],
    num_files: usize,
) -> Result<FilesInfo, SevenZError> {
    let mut names: Option<Vec<String>> = None;
    let mut empty_stream: Option<Vec<bool>> = None;
    let mut empty_file: Option<Vec<bool>> = None;
    let mut mtimes: Option<Vec<Option<u64>>> = None;

    loop {
        let t = r.read_number()?;
        if t == NID_END {
            break;
        }
        let size = r.read_number()? as usize;
        let prop = r.read_bytes(size)?;
        let mut pr = Reader::new(prop);

        match t {
            NID_EMPTY_STREAM => empty_stream = Some(pr.read_bool_vector(num_files)?),
            NID_EMPTY_FILE => {
                let n = empty_stream
                    .as_ref()
                    .map(|v| v.iter().filter(|b| **b).count())
                    .unwrap_or(0);
                empty_file = Some(pr.read_bool_vector(n)?);
            }
            NID_ANTI => {
                // 反文件（删除标记）不参与解包，仅按长度消费。
                let n = empty_stream
                    .as_ref()
                    .map(|v| v.iter().filter(|b| **b).count())
                    .unwrap_or(0);
                let _ = pr.read_bool_vector(n)?;
            }
            NID_NAME => names = Some(parse_names(&mut pr, data_vector, num_files)?),
            NID_MTIME => mtimes = Some(parse_u64_def_vector(&mut pr, data_vector, num_files)?),
            NID_CTIME | NID_ATIME | NID_START_POS => {
                let _ = parse_u64_def_vector(&mut pr, data_vector, num_files)?;
            }
            NID_WIN_ATTRIBUTES => {
                let _ = parse_u32_def_vector(&mut pr, data_vector, num_files)?;
            }
            _ => {}
        }
    }

    Ok(FilesInfo {
        names: names.unwrap_or_else(|| vec![String::new(); num_files]),
        empty_stream: empty_stream.unwrap_or_else(|| vec![false; num_files]),
        empty_file: empty_file.unwrap_or_default(),
        mtimes: mtimes.unwrap_or_else(|| vec![None; num_files]),
    })
}

fn parse_names(
    pr: &mut Reader,
    data_vector: &[Vec<u8>],
    num_files: usize,
) -> Result<Vec<String>, SevenZError> {
    let external = pr.read_byte()?;
    if external != 0 {
        let idx = pr.read_number()? as usize;
        let buf = data_vector.get(idx).ok_or(SevenZError::Corrupt)?;
        return parse_utf16_names(buf, num_files);
    }
    parse_utf16_names(pr.remaining_slice(), num_files)
}

fn parse_utf16_names(slice: &[u8], num: usize) -> Result<Vec<String>, SevenZError> {
    let mut names = Vec::with_capacity(num);
    let mut pos = 0usize;
    for _ in 0..num {
        let mut j = pos;
        while j + 1 < slice.len() && !(slice[j] == 0 && slice[j + 1] == 0) {
            j += 2;
        }
        if j + 1 >= slice.len() {
            return Err(SevenZError::Truncated);
        }
        let mut units = Vec::with_capacity((j - pos) / 2);
        let mut k = pos;
        while k < j {
            units.push(u16::from_le_bytes([slice[k], slice[k + 1]]));
            k += 2;
        }
        names.push(String::from_utf16(&units).map_err(|_| SevenZError::BadUtf8)?);
        pos = j + 2;
    }
    Ok(names)
}

fn parse_u64_def_vector(
    pr: &mut Reader,
    data_vector: &[Vec<u8>],
    num_files: usize,
) -> Result<Vec<Option<u64>>, SevenZError> {
    let defs = pr.read_bool_vector2(num_files)?;
    let external = pr.read_byte()?;
    let mut out = vec![None; num_files];
    if external != 0 {
        let idx = pr.read_number()? as usize;
        let buf = data_vector.get(idx).ok_or(SevenZError::Corrupt)?;
        let mut r = Reader::new(buf);
        for i in 0..num_files {
            if defs[i] {
                out[i] = Some(r.read_u64()?);
            }
        }
    } else {
        for i in 0..num_files {
            if defs[i] {
                out[i] = Some(pr.read_u64()?);
            }
        }
    }
    Ok(out)
}

fn parse_u32_def_vector(
    pr: &mut Reader,
    data_vector: &[Vec<u8>],
    num_files: usize,
) -> Result<Vec<Option<u32>>, SevenZError> {
    let defs = pr.read_bool_vector2(num_files)?;
    let external = pr.read_byte()?;
    let mut out = vec![None; num_files];
    if external != 0 {
        let idx = pr.read_number()? as usize;
        let buf = data_vector.get(idx).ok_or(SevenZError::Corrupt)?;
        let mut r = Reader::new(buf);
        for i in 0..num_files {
            if defs[i] {
                out[i] = Some(r.read_u32()?);
            }
        }
    } else {
        for i in 0..num_files {
            if defs[i] {
                out[i] = Some(pr.read_u32()?);
            }
        }
    }
    Ok(out)
}

/// 解压一个 StreamsInfo 的所有文件夹，返回每个文件夹的解压缓冲。
fn decode_folders(si: &StreamsInfo, input: &[u8]) -> Result<Vec<Vec<u8>>, SevenZError> {
    // packed stream 的累计偏移（相对 pack_pos）。
    let mut offsets = Vec::with_capacity(si.pack_sizes.len() + 1);
    let mut sum = 0u64;
    offsets.push(0);
    for s in &si.pack_sizes {
        sum += s;
        offsets.push(sum);
    }

    let mut out = Vec::with_capacity(si.folders.len());
    for (fi, folder) in si.folders.iter().enumerate() {
        let start = offsets
            .get(folder.pack_index)
            .copied()
            .ok_or(SevenZError::Corrupt)?;
        let end = offsets
            .get(folder.pack_index + 1)
            .copied()
            .ok_or(SevenZError::Corrupt)?;
        let len = end - start;
        let abs = HEADER_SIZE as u64 + si.pack_pos + start;
        let packed = input
            .get(abs as usize..(abs + len) as usize)
            .ok_or(SevenZError::Truncated)?;

        let data = decode_folder(folder, packed)?;
        if data.len() as u64 != folder.unpack_size {
            return Err(SevenZError::CrcMismatch);
        }
        if let Some(crc) = si.folder_crcs.get(fi).copied().flatten() {
            if crc32(&data) != crc {
                return Err(SevenZError::CrcMismatch);
            }
        }
        out.push(data);
    }
    Ok(out)
}

/// 把文件夹解码结果按子流拆分，返回顺序排列的子流字节。
fn decode_substreams(si: &StreamsInfo, input: &[u8]) -> Result<Vec<Vec<u8>>, SevenZError> {
    let folders = decode_folders(si, input)?;
    let mut substreams = Vec::with_capacity(si.unpack_sizes.len());
    let mut size_index = 0usize;
    for (fi, folder) in folders.iter().enumerate() {
        let nsub = si.num_unpack_streams[fi] as usize;
        let mut off = 0usize;
        for _ in 0..nsub {
            let sz = si.unpack_sizes[size_index] as usize;
            let chunk = folder.get(off..off + sz).ok_or(SevenZError::Corrupt)?;
            if let Some(crc) = si.digests.get(size_index).copied().flatten() {
                if crc32(chunk) != crc {
                    return Err(SevenZError::CrcMismatch);
                }
            }
            size_index += 1;
            substreams.push(chunk.to_vec());
            off += sz;
        }
        if off != folder.len() {
            return Err(SevenZError::Corrupt);
        }
    }
    Ok(substreams)
}

fn decode_folder(folder: &Folder, packed: &[u8]) -> Result<Vec<u8>, SevenZError> {
    match folder.codec_id.as_slice() {
        [0x21] => {
            // LZMA2：1 字节字典属性。
            if folder.props.len() != 1 {
                return Err(SevenZError::Corrupt);
            }
            let dict_size = lzma2_dict_size(folder.props[0])?;
            Ok(lzma2::Decoder::new(dict_size).decode(packed)?)
        }
        [0x03, 0x01, 0x01] => {
            // LZMA1：5 字节属性（lc/lp/pb + 字典大小）。
            if folder.props.len() != 5 {
                return Err(SevenZError::Corrupt);
            }
            let props = folder.props[0];
            let lc = (props % 9) as u32;
            let lp = ((props / 9) % 5) as u32;
            let pb = (props / 45) as u32;
            let mut dec = LzDecoder::new(lc, lp, pb);
            Ok(dec.decode(packed, Some(folder.unpack_size as usize))?)
        }
        [0x00] => Ok(packed.to_vec()),
        id => Err(SevenZError::UnsupportedCodec(format_codec_id(id))),
    }
}

fn format_codec_id(id: &[u8]) -> String {
    id.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// 解码 LZMA2 单字节字典属性为字典字节数。
fn lzma2_dict_size(props: u8) -> Result<usize, SevenZError> {
    let size = if props & 1 == 0 {
        let n = (props as u32 / 2) + 12;
        if n <= 30 {
            1u32 << n
        } else {
            return Err(SevenZError::Corrupt);
        }
    } else {
        let n = (props as u32 - 1) / 2 + 12;
        if (13..=30).contains(&n) {
            3u32 << (n - 1)
        } else {
            return Err(SevenZError::Corrupt);
        }
    };
    Ok(size as usize)
}

/// 7z 的 `kMTime` 值为 64 位时间戳：Unix 秒（较小值）或 Windows FILETIME
/// （100ns 自 1601-01-01）。转换为 Unix 秒。
fn time_to_unix(t: u64) -> i64 {
    // FILETIME 纪元到 Unix 纪元的秒差。
    const EPOCH_DIFF_SECS: u64 = 11_644_473_600;
    if t > 0x1_0000_0000 {
        (t / 10_000_000).saturating_sub(EPOCH_DIFF_SECS) as i64
    } else {
        t as i64
    }
}

fn build_entries(
    files: Option<FilesInfo>,
    substreams: &[Vec<u8>],
) -> Result<Vec<Entry>, SevenZError> {
    let Some(files) = files else {
        return Ok(Vec::new());
    };

    let num_files = files.names.len();
    let num_empty = files.empty_stream.iter().filter(|b| **b).count();
    if num_files - num_empty != substreams.len() {
        return Err(SevenZError::Corrupt);
    }

    let mut entries = Vec::with_capacity(num_files);
    let mut size_index = 0usize;
    let mut empty_index = 0usize;
    for i in 0..num_files {
        let name = files.names[i].clone();
        let mtime = files.mtimes[i].map(time_to_unix).unwrap_or(0);
        let has_stream = !files.empty_stream[i];

        if has_stream {
            let data = substreams[size_index].clone();
            size_index += 1;
            entries.push(Entry::file(name, 0o644, mtime, data));
        } else {
            let is_empty_file = files.empty_file.get(empty_index).copied().unwrap_or(false);
            empty_index += 1;
            if is_empty_file {
                entries.push(Entry::file(name, 0o644, mtime, Vec::new()));
            } else {
                entries.push(Entry::dir(name, 0o755, mtime));
            }
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_number_known_vectors() {
        let mut r = Reader::new(&[0x7f]);
        assert_eq!(r.read_number().unwrap(), 0x7f);

        // 10xxxxxx + 1 字节。
        let mut r = Reader::new(&[0x80, 0x01]);
        assert_eq!(r.read_number().unwrap(), 0x01);

        let mut r = Reader::new(&[0xBF, 0xFF]);
        assert_eq!(r.read_number().unwrap(), (0x3F << 8) | 0xFF);

        // 110xxxxx + 2 字节。
        let mut r = Reader::new(&[0xC0, 0x34, 0x12]);
        assert_eq!(r.read_number().unwrap(), 0x1234);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[0..6].copy_from_slice(b"not7z!");
        assert_eq!(decode(&buf), Err(SevenZError::BadMagic));
    }

    #[test]
    fn rejects_truncated() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&SIGNATURE);
        buf.extend_from_slice(&[0, 4]);
        buf.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(decode(&buf), Err(SevenZError::Truncated));
    }

    #[test]
    fn lzma2_dict_size_known() {
        // props = 0 → 2^12 = 4096。
        assert_eq!(lzma2_dict_size(0).unwrap(), 4096);
        // props = 0x24（36）→ 2^(18+... 实际 n=(36/2)+12=30) → 1 GiB。
        assert_eq!(lzma2_dict_size(0x24).unwrap(), 1 << 30);
    }
}
