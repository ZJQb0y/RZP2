# RZP2 容器格式规范

`.rzp2` 是 RZP2 的容器格式，承载「LZMA 压缩数据 +（可选）ML-KEM 或口令加密的
ChaCha20-Poly1305 密文 + 明文校验和」，并可选承载目录归档流。

当前版本为 v3；读取端保留对 v1 / v2 的兼容（见「版本兼容」）。

## 常量

| 名称 | 值 | 说明 |
| --- | --- | --- |
| `MAGIC` | `52 5A 50 32`（`"RZP2"`） | 文件魔数 |
| `VERSION` | `3` | 当前写入的容器格式版本 |
| `VERSION_MIN` | `1` | 可读取的最低容器格式版本 |
| `HEADER_PREFIX_SIZE` | `24` | 固定头部前缀字节数 |
| `NONCE_SIZE` | `12` | ChaCha20-Poly1305 nonce 长度 |
| `TAG_SIZE` | `16` | AEAD 认证标签长度 |
| `CHECKSUM_SIZE` | `32` | 明文 SHAKE-256 校验和长度 |
| `SALT_SIZE` | `16` | 口令加密盐长度（Argon2id） |
| `DEK_WRAP_SIZE` | `48` | 封装的 DEK 长度（32 字节密文 + 16 字节标签） |

## 布局

```text
+-------------------+--------------------------------+
| 固定头部前缀       | magic(4) version(1) flags(1)   |
|                   | level(1) flags2(1)             |
|                   | original_size(8, LE)           |
|                   | compressed_size(8, LE)         |
+-------------------+--------------------------------+
| 加密字段（可选）   | 见下                           |
+-------------------+--------------------------------+
| 校验字段（可选）   | checksum(32)                   |
+-------------------+--------------------------------+
| 载荷               | compressed payload             |
+-------------------+--------------------------------+
| 尾部（可选）       | aead_tag(16)                   |
+-------------------+--------------------------------+
```

- 多字节整数字段一律为小端（little-endian）。
- `original_size` 为未压缩明文长度；`compressed_size` 为载荷长度（加密时为加密前、
  即 AEAD 密文的长度）。二者为 `u64::MAX`（`FF FF FF FF FF FF FF FF`）时表示未知，
  由 LZMA 结束标记终止。
- `level` 为压缩级别预设（0..=9），仅作记录，解码不依赖它。
- `flags2` 复用 v1/v2 头部的 `reserved` 字节，承载 v3 新增的扩展标志（见「头部标志位
  `flags2`」）；v1/v2 读取端将其视为 `reserved` 忽略。
- 未加密时不写入加密字段与 `aead_tag`。
- `checksum` 为未压缩明文的 SHAKE-256 摘要（可选，32 字节）。
- 加密时 `flags.CHUNKED` 置位表示载荷为分块 AEAD 帧序列（见「分块 AEAD 载荷」），
  否则为整块 AEAD：载荷后跟单个 `aead_tag(16)`。

### 加密字段

按加密模式区分：

- **ML-KEM 模式**（`flags.PASSWORD` 未置位）：

  ```text
  ek_len(2, LE) ek(..) nonce(12)
  ```

  `ek` 为 ML-KEM 封装密文，`nonce` 为 AEAD 随机数。

- **多接收者 ML-KEM 模式**（`flags2.MULTI` 置位，仅 v3 且加密时合法）：

  ```text
  count(1)
  对每个接收者:
    kem(1) ek_len(2, LE) ek(..) wrapped_dek(48)
  nonce(12)
  ```

  加密时生成随机 DEK 与基准 nonce，对每个接收者用其公钥封装得到共享密钥，
  再用派生密钥 AEAD 包裹 DEK（`wrapped_dek = 密文(32) + tag(16)`，AAD 绑定该接收者
  的 `ek`）。载荷用 DEK + 基准 nonce 加密，AAD 绑定完整头部字节。任一接收者私钥
  解包 DEK 成功即可解密。`kem` 为该接收者参数集，`Header::kem` 取首个接收者参数集。

- **口令模式**（`flags.PASSWORD` 置位）：

  ```text
  salt(16) memory_kib(4, LE) iterations(4, LE) lanes(4, LE) nonce(12)
  ```

  `salt` 为 Argon2id 盐，`memory_kib` / `iterations` / `lanes` 为 KDF 参数，
  `nonce` 为 AEAD 随机数。

## 分块 AEAD 载荷（v3）

`flags.CHUNKED` 置位时，压缩流被切成固定大小的明文块，逐块加密为 AEAD 帧，帧序列即
载荷；块大小 `CHUNK_SIZE = 64 * 1024` 字节（最后一块可不足）。帧格式（多字节整数
小端）：

```text
每帧:
  len(4, LE)              // 本帧密文长度（> 0）
  ciphertext[len]
  tag(16)                 // 本帧 ChaCha20-Poly1305 认证标签
终止帧:
  len = 0x00000000
```

- 每帧 nonce 由基准 nonce（头部记录的 `nonce`）派生：`nonce = base ^ (index 写入
  低 8 字节)`，`index` 为该帧序号（从 0 递增）。
- 每帧 AAD 绑定「完整头部字节 + 帧序号（8 字节 LE）」，防止帧重排、截断与头部篡改。
- 终止帧（`len = 0`）本身不加密，用于标识帧序列结束；缺少终止帧视为载荷截断。
- 解压时不校验 `compressed_size` 与帧字节数的严格一致，而是以终止帧与 LZMA 结束标记
  判定完整性。

## 分块 LZMA 载荷（v3，`flags2.BLOCKED`）

`flags2.BLOCKED` 置位时，压缩载荷为多个独立 LZMA alone 流的帧序列（并行压缩产物），
而非单个 alone 流。帧格式（多字节整数小端）：

```text
每帧:
  len(4, LE)              // 本帧字节数（> 0）
  block[len]              // 一个完整 LZMA alone 流（13 字节头 + 码流 + 结束标记）
终止帧:
  len = 0x00000000
```

- 每个 `block` 是自包含的 LZMA alone 流，解压时逐帧解压后按序拼接明文。
- 分块大小由 CLI `--block-size` 控制（默认 4 MiB），线程数由 `--threads` 控制。
- `BLOCKED` 与 `CHUNKED` 正交：前者描述压缩层布局，后者描述加密层 AEAD 帧封装。

## 头部标志位 `flags`

| 位 | 掩码 | 说明 |
| --- | --- | --- |
| 0 | `0b0000_0001` | 载荷已加密 |
| 1..2 | `0b0000_0110` | ML-KEM 参数集（`KEM_SHIFT = 1`） |
| 3 | `0b0000_1000` | 存在未压缩明文校验和 |
| 4 | `0b0001_0000` | 口令（Argon2id）加密模式 |
| 5 | `0b0010_0000` | 载荷为归档流 |
| 6 | `0b0100_0000` | 分块 AEAD 载荷（仅 v3 且加密时合法） |

ML-KEM 参数集编码：

| 值 | 参数集 |
| --- | --- |
| `0` | ML-KEM-512 |
| `1` | ML-KEM-768 |
| `2` | ML-KEM-1024 |

## 头部标志位 `flags2`

`flags2` 复用头部第 7 字节（v1/v2 的 `reserved`），仅在 v3 有意义：

| 位 | 掩码 | 说明 |
| --- | --- | --- |
| 0 | `0b0000_0001` | 多接收者加密（`MULTI`，仅加密且非口令模式时合法） |
| 1 | `0b0000_0010` | 载荷为分块 LZMA 帧序列（`BLOCKED`） |

## 头部序列化

`Header::encode` 依次写入：

1. `MAGIC`（4 字节）
2. `VERSION`（1 字节，恒为 `3`）
3. `flags`（1 字节，由 `encrypted` / `password` / `archive` / `checksum` / `kem` / `chunked` 计算）
4. `level`（1 字节）
5. `flags2`（1 字节，由 `multi` / `blocked` 计算）
6. `original_size`（8 字节，LE）
7. `compressed_size`（8 字节，LE）
8. 若加密且为口令模式：`salt`（16）→ `memory_kib`（4）→ `iterations`（4）→ `lanes`（4）→ `nonce`（12）
9. 若加密且为多接收者模式：`count`（1）→ 逐接收者 `kem`（1）`ek_len`（2，LE）`ek` `wrapped_dek`（48）→ `nonce`（12）
10. 若加密且为单接收者 ML-KEM 模式：`ek_len`（2，LE）→ `ek` → `nonce`（12）
11. 若带校验和：`checksum_digest`（32 字节）

载荷与（加密时的）AEAD 标签不包含在头部序列化结果中，由管线（`pack` / `unpack`）负责拼接。

## 归档流

`flags.ARCHIVE` 置位时，载荷在压缩前为归档流。归档流本身为未压缩明文，布局如下
（多字节整数一律小端）：

```text
每个条目:
  kind(1) mode(4) mtime(8) name_len(2) name(..)
  [symlink: link_len(2) link(..)]
  size(8) data(size)
结束标记:
  kind = 0xFF
```

- `kind`：`0` = 普通文件、`1` = 目录、`2` = 符号链接。
- `mode` 为 Unix 权限位；`mtime` 为 Unix 秒（有符号 64 位）。
- `name` 为相对路径，使用 `/` 作为分隔符。
- 符号链接条目在 `name` 之后、`size` 之前额外写入 `link_len(2) link(..)`。
- 目录 / 符号链接条目的 `size` 恒为 `0`。

解包归档时必须校验路径安全：拒绝绝对路径与包含 `..` 的路径。

## 密钥文件（PEM 风格）

密钥文件为文本格式：

```text
-----BEGIN RZP2 PUBLIC KEY-----
<base64(payload)>
-----END RZP2 PUBLIC KEY-----
```

其中 `payload = params_byte(1) || raw_key_bytes`：

- `params_byte` 为 `KemParams::to_bits` 的值（见上表）。
- `raw_key_bytes` 为 ML-KEM 公钥 / 私钥的原始字节。
- 私钥头尾为 `-----BEGIN RZP2 PRIVATE KEY-----` / `-----END RZP2 PRIVATE KEY-----`。

## 自解压（SFX）

`rzp2 sfx` 生成的自解压可执行文件布局（多字节整数小端）：

```text
[rzp2 存根字节][.rzp2 载荷][RZP2SFX][payload_len(8, LE)]
```

- 存根为 `rzp2` 自身，运行时读取自身文件末尾的 footer 定位载荷并解压到当前目录。
- footer 由 `RZP2SFX`（7 字节）与内嵌载荷长度（8 字节小端）组成，据此计算载荷起始偏移，避免在二进制里扫描 `RZP2` 魔数造成误命中。
- 自解压不改变容器格式本身，载荷仍为标准的 `.rzp2`（v3）；ML-KEM 加密容器不通过 SFX 携带私钥。

## 分片清单（split）

`rzp2 split` / `rzp2 merge` 使用独立于 `.rzp2` 容器的分片清单，用于记录分片元数据。
清单为二进制，多字节整数一律小端：

```text
magic(8) version(1) name_len(2, LE) name(..) chunk_count(4, LE) chunk_size(8, LE) total_size(8, LE)
```

- `magic` 为 `52 5A 50 32 53 50 4C 31`（`"RZP2SPL1"`），`version` 为 `1`。
- `name` 为原始文件名（UTF-8，不含路径）；`chunk_count` 为分片数；`chunk_size` 为目标
  分片大小（最后一片可不足）；`total_size` 为原始文件总大小。
- 分片文件命名为 `<prefix>.part.00001`、`<prefix>.part.00002`、……（序号从 1 起零填充
  到 5 位），清单命名为 `<prefix>.manifest`。
- 合并时按清单序号顺序拼接分片，并校验合并后总大小与 `total_size` 一致。

## 版本兼容

- v1 头部为 `magic(4) version(1) flags(1) reserved(2) original_size(8) compressed_size(8)`，
  共 24 字节，无 `level` / `archive` / 口令加密。
- v2 头部在 v1 基础上新增 `level` 字节与 `PASSWORD` / `ARCHIVE` 标志位，支持未知长度。
- v3 头部在 v2 基础上新增 `CHUNKED` 标志位与 `flags2`（复用 `reserved` 字节），
  支持分块 AEAD 载荷、多接收者加密与分块 LZMA 载荷；读取端对 v1 / v2 保持兼容。
- 读取 v1 时：`level` 视为 `0`；若 v1 头部出现 `PASSWORD` / `ARCHIVE` / `CHUNKED`
  标志位，视为非法（`BadFlags`）。
- `CHUNKED` 仅在 `encrypted` 且 `version >= 3` 时合法；否则视为 `BadFlags`。
- `MULTI`（`flags2`）仅在 `encrypted`、非口令模式且 `version >= 3` 时合法；否则视为
  `BadFlags`。
- `BLOCKED`（`flags2`）仅在 `version >= 3` 时合法；否则视为 `BadFlags`。

## 安全说明

- ML-KEM 混合加密采用「临时 ML-KEM 密钥封装 → SHAKE-256 KDF 派生 AEAD 密钥与 nonce →
  ChaCha20-Poly1305 加密压缩数据」；AAD 绑定 `ek`，防止封装密文被篡改。
- 口令加密采用 Argon2id（RFC 9106）派生对称密钥，AAD 绑定完整头部字节（盐、KDF 参数、
  级别、大小、校验和），防止头部被篡改。
- 分块 AEAD（v3）下每帧使用独立的 nonce（基准 nonce 与帧序号异或派生）与独立的 tag，
  AAD 绑定完整头部字节 + 帧序号，防止帧重排、截断与重放。
- 本格式为教学 / 研究用途，未经第三方安全审计，请勿用于生产环境的关键数据保护。
