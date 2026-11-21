# RZP2 路线图

本文记录 RZP2 的演进方向与计划。目标始终是：**保持零运行时第三方依赖、核心算法
手写且逐行可审计**，在此基础上补齐能力与性能短板。

优先级标记：

- **P0**：近期（下一个/下两个小版本）优先落地，收益直接、改动可控。
- **P1**：中期，方向明确，需要较大改动或格式扩展。
- **P2**：长期/探索，涉及格式升级或较重的工程投入。

## 已完成

### ≤ 0.16

- LZMA / LZMA2 编解码，`.rzp2`（v3，兼容读 v1/v2）与 `.xz`（LZMA2 + CRC32）容器。
- ML-KEM 512/768/1024、ChaCha20-Poly1305、Argon2id、SHAKE-256、BLAKE2b。
- X25519（RFC 7748）与 ML-KEM + X25519 混合封装（`hybrid` 双算法共享密钥合并，v3 `flags2.HYBRID`）。
- 多接收者加密（随机 DEK + 逐接收者封装）、分块 AEAD（v3 `CHUNKED`）、分块 LZMA（`BLOCKED`）。
- 目录归档、自解压（SFX）、文件分片/合并、shell 补全、性能基准（`bench`）。
- 多进程并行块编码（Unix `fork` / Windows `spawn`，崩溃隔离，缺失块串行补齐）。
- 并行解压（`decode_blocks_parallel`，复用多进程模型，崩溃/失败回退串行补齐）。
- 流式压缩 + 明文校验和（未加密文件输出经 seek 回写头部，stdin/加密回退缓冲式打包）。
- `--processes` 默认按可用 CPU 核数自动检测（`compress` / `decompress` / `xz`）。
- 多接收者公钥指纹（`Recipient.fingerprint`，v3 `flags2` 扩展标志，解密按指纹快速定位，`info` 展示）。
- 主流压缩格式解压：`decompress` 按魔数探测 `.zip` / `.gz` / `.7z` / `.bz2` / `.tar.gz` /
  `.tar.xz`，手写 `deflate` / `gzip` / `tar` / `zip` / `bzip2` / `sevenz` 内核（复用 LZMA2 /
  LZMA1），统一归入 `src/formats/` 目录。
- 主流压缩格式解压打磨：`decompress --format <fmt>` 显式覆盖魔数探测
  （`gzip/xz/bzip2/tar/zip/7z`）；`list` / `info` 扩展到外部归档与单文件，展示条目清单
  与格式元信息；外部归档解包复用 `--processes` 并行写文件条目。

### 0.17

- 按功能拆分的 C ABI 动态库，无需 CLI 即可供 C/C++ 等语言按需链接：
  `rzp2-compress`（LZMA1 alone 压缩/解压）与 `rzp2-crypto`（ML-KEM(+X25519) 密钥生成与
  混合加解密、ChaCha20-Poly1305 AEAD、Argon2id 口令派生）。
- 两个动态库均附带 C 头文件与可编译示例；`package.sh` / `package.ps1` 打包时收集
  `.so` / `.dll` 与头文件到 `dist` 的 `lib/`、`include/` 子目录。

### 0.18

- 更强匹配查找：BT4 二叉树匹配查找器（`lzma::match_finder`），高压缩级别（`level >= 8`）
  自动启用。
- 可逆预过滤链：新增 `filters` 模块（Delta + BCJ x86 / ARM / ARM64 / RISC-V），容器升级
  到 v4 并新增 `flags2.FILTERS` 标志与过滤链头部，CLI 新增 `--filter`。
- 格式感知重压缩（DEFLATE）：把 gzip 内 DEFLATE 流反解到符号层后序列化，重建时逐位还原；
  作为 `Filter::Deflate` 接入过滤链，`--filter deflate` 可用。
- 格式感知重压缩（JPEG，Lepton 式）：把 baseline 顺序 JPEG 的 Huffman 熵编码 DCT 系数反解
  到符号层，重建时逐位还原；作为 `Filter::Jpeg` 接入过滤链，`--filter jpeg` 可用。

### 0.19

- 格式感知重压缩（PNG）：把 IDAT 内 zlib/DEFLATE 流反解到符号层，重建时按原始 IDAT 切分
  并重算 CRC32；作为 `Filter::Png` 接入过滤链，`--filter png` 可用。
- 格式感知重压缩（GIF）：把 GIF87a / GIF89a 图像数据的 LZW 码流反解到符号层，重建时按
  原始子块切分；作为 `Filter::Gif` 接入过滤链，`--filter gif` 可用。
- 格式感知重压缩（ZIP）：把归档内方法 8（DEFLATE）条目的原始 DEFLATE 流反解到符号层，
  其余元数据原样保留；`Filter::Deflate` 新增 ZIP 分支，`--filter deflate`（别名 `zip`）
  可同时识别 gzip 与 ZIP 容器。
- 重压缩回退保护：`deflate` / `jpeg` / `png` / `gif` 在重压缩表示不比原始输入更小时回退
  原字节，避免容器膨胀。
- `bench` 增强：每项报告 min/max 范围与变异系数、峰值常驻内存（RSS）增量，新增
  `--sweep` 一次性扫描 LZMA 级别 0~9。
- 视频 / 音频熵层重编码收益极低，暂不投入，改由下方 P1 的 CDC 去重覆盖。

## 规划中

### P1 — 中期

#### 1. 内容定义分块去重（CDC dedup）

- **现状**：重复字节只能靠 LZMA 局部匹配，受字典大小限制，无法跨文件/跨目录利用
  重复内容；归档内大量重复或相似文件（备份、镜像、构建产物）无法去重。
- **方案**：
  - 滚动哈希（Buzhash / Gear / FastCDC）做内容定义分块，平均块约 64 KiB，块边界
    随内容稳定（局部修改不影响其余块）。
  - 块用已有 SHAKE-256 作指纹建索引，重复块只存一次、其余位置引用指纹；块字典
    随归档/容器保存。
  - 作为 `archive` 模式的去重层，支持跨文件去重与增量备份（追加式日志）；后续可
    扩展跨文件 delta 差分（bsdiff 式）进一步压缩相似块。
- **影响**：新增 `src/dedup/`（分块器 / 指纹索引 / 字典编解码）、`archive`、
  `format`（版本策略）。
- **收益**：备份/重复文件场景显著省空间（典型可 50%~80%+ 去重），对已压缩与不可
  压缩文件同样有效，与已完成的格式感知重压缩互补。

#### 2. 自解压（SFX）能力增强

- **现状**：ML-KEM 公钥加密容器无法通过 SFX 解压（存根内不能安全携带私钥），
  需改走 `decompress --private-key`。
- **方案**：支持 SFX 运行时指定私钥文件路径（`--private-key`）或环境变量；口令加密
  容器支持从环境变量非交互读口令。
- **影响**：`cli::sfx`、运行时自检测逻辑。
- **收益**：加密 SFX 分发场景可用性提升。

#### 3. Argon2id 参数自适应与私钥口令封装规范化

- **现状**：口令加密默认 `64 MiB / 3 次 / 4 lanes`，参数固定；私钥口令加密为自有
  PEM + 口令形式。
- **方案**：
  - 提供 `--password-memory/--password-iters` 或「auto」档位，按机器性能自适应调参。
  - 评估 PKCS#8 兼容的私钥封装（EncryptedPrivateKeyInfo），提升跨工具互操作。
- **影响**：`hybrid`、`crypto::argon2`、`keys`。
- **收益**：口令加密强度可调、密钥文件更标准。

#### 4. 容器统一到 LZMA2（可选）

- **现状**：`.rzp2` 主容器载荷用 LZMA1 alone 流（分块时多 alone 流），`.xz` 才用
  LZMA2。两套并存。
- **方案**：评估让 `.rzp2` 载荷也采用 LZMA2 分块，获得更好的分块/流式/随机访问；
  需要新增格式版本或扩展标志，保持旧版本读取兼容。
- **影响**：`format`（版本策略）、`lzma::lzma2`、`pipeline`。
- **收益**：简化内核、统一编解码路径；属较大的格式变更，需谨慎排期。

#### 5. 后量子数字签名：ML-DSA / SLH-DSA / FN-DSA

- **现状**：已实现 ML-KEM 公钥加密与 X25519 混合封装，但尚无签名能力；容器与接收者
  身份仅靠加密保证机密性，无法做来源认证 / 完整性签名。
- **方案**：
  - 实现 FIPS 204 ML-DSA 512/768/1024（Dilithium），复用 `mlkem` 的 NTT / SHAKE-256 /
    采样等基础设施。
  - 实现 FIPS 205 SLH-DSA（SPHINCS+，无状态哈希签名），复用 SHAKE/SHA-2 内核。
  - 实现 FIPS 206 FN-DSA（Falcon，FFT 格签名），新增整数 FFT 模块。
  - 增加 `sign` / `verify` 子命令与签名文件格式，支持对 `.rzp2` 归档做签名认证。
- **影响**：新增 `mldsa` / `slhdsa` / `fndsa` 模块，`crypto`（SHA-256）、`keys`、
  `format`、`cli`（`sign` / `verify`）。
- **收益**：补齐后量子签名能力，实现归档来源认证与不可否认性；与 ML-KEM 共同构成
  完整后量子密钥体系，且复用既有手写内核。

#### 6. 国密算法：SM2 / SM3 / SM4

- **现状**：已有国际标准算法（SHAKE-256、BLAKE2b、ChaCha20-Poly1305、X25519），
  但无国密算法支持，无法满足国密合规 / 等保场景。
- **方案**：
  - 实现 SM3 密码杂凑算法（GB/T 32905，256 位），用于摘要、签名与密钥派生。
  - 实现 SM4 分组密码（GB/T 32907，128 位块 / 密钥），支持 CTR / CBC 及 GM/T 认证
    加密模式（如 SM4-GCM 或 SM4-CTR + SM3 MAC）。
  - 实现 SM2 椭圆曲线公钥密码（GB/T 32918，256 位素数域），覆盖签名（配合 SM3）、
    密钥交换与公钥加密。
  - 评估 SM2 作为归档签名 / 加密的国密可选算法，扩展 `sign` / `verify` / `hybrid`。
- **影响**：新增 `sm2` / `sm3` / `sm4` 模块，`aead`、`keys`、`format`（版本策略）、
  `cli`（算法开关 / 子命令）。
- **收益**：补齐国密算法能力，满足国内合规与等保要求；扩展算法覆盖面，服务国内
  场景，且延续手写可审计内核。

### P2 — 长期 / 探索

#### 1. SIMD 扩展到压缩内核

- **现状**：SIMD 仅用于 ChaCha20（AVX2/NEON）与 Poly1305（NEON）。
- **方向**：范围编码器 / 匹配查找 / CRC 的 SIMD 加速，按运行时特性检测 + 标量兜底。
- **影响**：`lzma::range_coder`、`lzma::match_finder`、`crc`。
- **收益**：进一步压缩/解压吞吐提升。

#### 2. 内存保护与密钥管理增强

- **方向**：关键密钥内存 `mlock`（防换出）、更严格的 `Zeroize` 覆盖、`#[zeroize_on_drop]`
  语义核对；评估恒定时间 AES 之外的旁路缓解。
- **影响**：`crypto::zeroize`、`aead`、`hybrid`、`pipeline`。
- **收益**：提升密钥在内存中的安全性。

#### 3. 测试与质量持续投入

- 引入 `cargo-fuzz` / proptest / 差分 fuzz（与系统 `xz`、Python `lzma` 交叉验证）。
- CI 增加 fuzz 冒烟与 `bench` 回归门禁。
- 补充更多跨实现测试向量与损坏/截断/恶意输入用例。

#### 4. 打包与发布自动化

- CI 自动构建三平台 release 产物并签名、上传 GitHub Release。
- 增加 SBOM 生成、musl 静态构建、Homebrew/scoop 自动更新管线。
- 发布前跑 `cargo deny`、`cargo audit`、`cargo fmt --check` 与 `clippy -D warnings`。

#### 5. 核心算法内核 `no_std` 化

- **现状**：库与 CLI 紧密耦合，`lib.rs` 直接暴露 `cli`；核心算法模块普遍依赖
  `std`（`Vec` / `String` / `fmt::Display` / `std::error::Error`），仅测试期引入
  serde_json。
- **方案**：
  - 将纯算法内核（`crypto` / `aead` / `lzma` / `mlkem`）改为 `#![no_std]` + `alloc`。
  - 抽出可移植的分配、错误与随机源抽象；CLI 侧继续使用 `std`。
  - 评估 `core::error::Error`（Rust 1.81+）替代 `std::error::Error`，以
    `alloc::string::String` / `alloc::vec::Vec` 替换字符串/向量依赖。
- **影响**：`lib.rs` 模块边界、各算法模块、错误类型，`keys` / `format`
  （base64 与字符串依赖）。
- **收益**：内核可移植到嵌入式 / 受限环境，扩大库适用场景，并进一步强化
  「零依赖」定位。

#### 6. HQC 码基 KEM（备用 / 探索）

- **现状**：仅 ML-KEM 一个后量子 KEM 与 X25519 混合封装；单一格假设存在集中风险。
- **方向**：实现 HQC（Hamming Quasi-Cyclic）基于纠错码的 KEM，作为格之外的备用密钥
  封装算法；评估其与 ML-KEM 的双算法封装（多假设混合）。
- **影响**：新增 `hqc` 模块（编码 / 译码 / 采样）、`hybrid`、`format` 版本策略。
- **收益**：引入基于码的密码学假设，降低单一格假设风险；提供算法多样性备份。

#### 7. 更强熵编码后端：PPMd / 上下文混合（CM）

- **现状**：熵编码仅 LZMA 的二进制自适应范围编码；对「无 LZ 重复但存在统计冗余」
  的半不可压缩数据（结构化二进制、日志、部分文本、残余字节）建模能力有限。
- **方向**：
  - 实现 PPMd（预测部分匹配，PPMII 变长上下文），作为中等开销的更强统计压缩器。
  - 实现上下文混合（CM，PAQ 系）对高熵残余做多模型混合，压缩率最强但速度极慢，
    仅作 `--level` 最高档或 `--ultra` 实验档。
  - 评估与 LZMA 后端的选择/混合，解码端按头部记录自动选择。
- **影响**：新增 `src/ppm/` / `src/cm/` 模块、`lzma`（后端选择）、`format`。
- **收益**：压榨 LZMA 无法建模的残余冗余，接近 PAQ 级压缩率，以速度换大小；
  仅面向极端压缩率场景。

## 持续原则

- 任何新能力不得破坏「零运行时第三方依赖」与「核心算法手写可审计」定位。
- 格式变更必须考虑向后兼容（读取端保留旧版本），并在 `FORMAT.md` / `CHANGELOG.md`
  同步更新。
- 性能优化以可复现的 `bench` 数据为准，跨机器对齐单线程/固定进程基线。
