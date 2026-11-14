# RZP2 路线图

本文记录 RZP2 的演进方向与计划。目标始终是：**保持零运行时第三方依赖、核心算法
手写且逐行可审计**，在此基础上补齐能力与性能短板。

优先级标记：

- **P0**：近期（下一个/下两个小版本）优先落地，收益直接、改动可控。
- **P1**：中期，方向明确，需要较大改动或格式扩展。
- **P2**：长期/探索，涉及格式升级或较重的工程投入。

## 已完成（≤ 0.13）

- LZMA / LZMA2 编解码，`.rzp2`（v3，兼容读 v1/v2）与 `.xz`（LZMA2 + CRC32）容器。
- ML-KEM 512/768/1024、ChaCha20-Poly1305、Argon2id、SHAKE-256、BLAKE2b。
- 多接收者加密（随机 DEK + 逐接收者封装）、分块 AEAD（v3 `CHUNKED`）、分块 LZMA（`BLOCKED`）。
- 目录归档、自解压（SFX）、文件分片/合并、shell 补全、性能基准（`bench`）。
- 多进程并行块编码（Unix `fork` / Windows `spawn`，崩溃隔离，缺失块串行补齐）。
- 并行解压（`decode_blocks_parallel`，复用多进程模型，崩溃/失败回退串行补齐）。
- 流式压缩 + 明文校验和（未加密文件输出经 seek 回写头部，stdin/加密回退缓冲式打包）。
- `--processes` 默认按可用 CPU 核数自动检测（`compress` / `decompress` / `xz`）。
- 多接收者公钥指纹（`Recipient.fingerprint`，v3 `flags2` 扩展标志，解密按指纹快速定位，`info` 展示）。

## P0 — 近期（0.13 / 0.14）

> 本批次 P0 已完成，见上方「已完成」。保留本节标题以维持 P1/P2 编号稳定。

## P1 — 中期（0.15+）

### 5. 压缩率提升：更强匹配查找 / 二进制过滤器

- **现状**：LZMA 匹配器为哈希链 + 延迟匹配，级别自适应深度/停断（见
  [src/lzma/lz_encoder.rs](src/lzma/lz_encoder.rs)）。
- **方案**：
  - 增加 BT4/二叉树匹配查找或更优解析，提升高压缩级别压缩率。
  - 增加 BCJ/Delta 过滤器（x86/ARM/通用二进制数据），在压缩前做可逆变换。
- **影响**：`lzma`（`match_finder` / `lz_encoder`）、新增过滤器模块。
- **收益**：接近 xz 高等级压缩率，缩小与系统 xz 的差距。

### 6. 自解压（SFX）能力增强

- **现状**：ML-KEM 公钥加密容器无法通过 SFX 解压（存根内不能安全携带私钥），
  需改走 `decompress --private-key`。
- **方案**：支持 SFX 运行时指定私钥文件路径（`--private-key`）或环境变量；口令加密
  容器支持从环境变量非交互读口令。
- **影响**：`cli::sfx`、运行时自检测逻辑。
- **收益**：加密 SFX 分发场景可用性提升。

### 7. Argon2id 参数自适应与私钥口令封装规范化

- **现状**：口令加密默认 `64 MiB / 3 次 / 4 lanes`，参数固定；私钥口令加密为自有
  PEM + 口令形式。
- **方案**：
  - 提供 `--password-memory/--password-iters` 或「auto」档位，按机器性能自适应调参。
  - 评估 PKCS#8 兼容的私钥封装（EncryptedPrivateKeyInfo），提升跨工具互操作。
- **影响**：`hybrid`、`crypto::argon2`、`keys`。
- **收益**：口令加密强度可调、密钥文件更标准。

### 8. 容器统一到 LZMA2（可选）

- **现状**：`.rzp2` 主容器载荷用 LZMA1 alone 流（分块时多 alone 流），`.xz` 才用
  LZMA2。两套并存。
- **方案**：评估让 `.rzp2` 载荷也采用 LZMA2 分块，获得更好的分块/流式/随机访问；
  需要新增格式版本或扩展标志，保持旧版本读取兼容。
- **影响**：`format`（版本策略）、`lzma::lzma2`、`pipeline`。
- **收益**：简化内核、统一编解码路径；属较大的格式变更，需谨慎排期。

## P2 — 长期 / 探索

### 9. SIMD 扩展到压缩内核

- **现状**：SIMD 仅用于 ChaCha20（AVX2/NEON）与 Poly1305（NEON）。
- **方向**：范围编码器 / 匹配查找 / CRC 的 SIMD 加速，按运行时特性检测 + 标量兜底。
- **影响**：`lzma::range_coder`、`lzma::match_finder`、`crc`。
- **收益**：进一步压缩/解压吞吐提升。

### 10. 内存保护与密钥管理增强

- **方向**：关键密钥内存 `mlock`（防换出）、更严格的 `Zeroize` 覆盖、`#[zeroize_on_drop]`
  语义核对；评估恒定时间 AES 之外的旁路缓解。
- **影响**：`crypto::zeroize`、`aead`、`hybrid`、`pipeline`。
- **收益**：提升密钥在内存中的安全性。

### 11. 测试与质量持续投入

- 引入 `cargo-fuzz` / proptest / 差分 fuzz（与系统 `xz`、Python `lzma` 交叉验证）。
- CI 增加 fuzz 冒烟与 `bench` 回归门禁。
- 补充更多跨实现测试向量与损坏/截断/恶意输入用例。

### 12. 打包与发布自动化

- CI 自动构建三平台 release 产物并签名、上传 GitHub Release。
- 增加 SBOM 生成、musl 静态构建、Homebrew/scoop 自动更新管线。
- 发布前跑 `cargo deny`、`cargo audit`、`cargo fmt --check` 与 `clippy -D warnings`。

## 持续原则

- 任何新能力不得破坏「零运行时第三方依赖」与「核心算法手写可审计」定位。
- 格式变更必须考虑向后兼容（读取端保留旧版本），并在 `FORMAT.md` / `CHANGELOG.md`
  同步更新。
- 性能优化以可复现的 `bench` 数据为准，跨机器对齐单线程/固定进程基线。
