# RZP2 路线图

> 本文档记录 RZP2 后续可升级方向。每一项都标注了「现状」与「目标」，供按优先级排期。
> 当前版本：0.8.0（见 [CHANGELOG.md](CHANGELOG.md)）。

优先级约定：

- **P0**：近期、高价值、影响核心使用
- **P1**：中期、显著提升
- **P2**：长期 / 探索性

---

## 1. 流式与内存占用（P0）

**现状**：压缩侧已打通流式管线。[pipeline.rs](src/pipeline.rs) 的 `pack_to_writer` 与
[lzma](src/lzma/mod.rs) 的 `encode_stream` 支持 `Read` / `Write` 边读边处理，加密时经
`ChunkedWriter` 分块落盘；解压侧 `unpack_to_writer` 已知 `original_size` 时流式写出。
剩余缺口：归档解包仍整包 `decode_archive` 到内存；校验和路径因头部需先写明文摘要仍走缓冲。

**方向**：

- [x] 引入 `Read` / `Write` 流式接口，`compress` / `decompress` 边读边处理，而非整体载入内存。
- [x] 解压时已知 `original_size` 走流式写出，避免一次性构造明文。
- [x] 归档解包按条目流式落盘，避免整包 `decode_archive` 到内存。
- [ ] 为流式路径设置内存上限（尤其是 Argon2id 的 `memory_kib` 显式可控）。

---

## 2. 性能（P0 / P1）

### 2.1 SIMD 加速加密原语（P0）

**现状**：ChaCha20 已有 AVX2 快路径；Poly1305、BLAKE2b、Argon2 仍为标量实现。

- [x] ChaCha20 加 AVX2 快路径（运行时检测 + 纯标量兜底）。
- [x] ChaCha20 补 NEON 快路径（保持零依赖，用 `core::arch` 内在函数）。
- [x] Poly1305 补 NEON 快路径（保持零依赖，用 `core::arch` 内在函数）。
- [ ] BLAKE2b 的压缩轮与 Argon2 的 BLAKE2b 轮做向量化。
- [x] 用 `#[cfg(target_feature)]` + 运行时/编译期选择，保留纯标量兜底。

### 2.2 LZMA 编码器（P1）

**现状**：`match_finder` 为哈希链匹配，单线程；`encoder` 无最优解析。

- [ ] 匹配查找器升级（BT4 或更高质量），提升高压缩级别压缩率。
- [x] 增加最优解析 / 延迟匹配选项，改善 `--level 7..=9` 的压缩率。
- [x] 分块并行压缩：大输入切块多线程压缩后拼接（需配套容器格式改动，见 §4）。
- [x] 暴露 `--threads` 控制并行度。

### 2.3 基准与回归（P1）

- [ ] 建立可复现的性能基准集（文本 / 二进制 / 已压缩 / 高度重复）。
- [ ] CI 加入 `cargo bench`（nightly）或独立 benchmark 工作流，跟踪性能回退。

---

## 3. 安全与密码学（P0 / P1）

### 3.1 私钥保护（P0）

**现状**：私钥默认以明文 PEM 存储（[keys.rs](src/keys.rs)），现支持口令加密私钥。

- [x] 支持口令加密私钥（Argon2id 派生密钥加密私钥 payload，PEM 风格 + 加密标记）。
- [x] `keygen` 提供 `--private-password` 选项；解密时从 stdin / `--key-password` 读取口令。
- [x] 校验并加固私钥文件写入权限（Unix 下默认 `0600`）。

### 3.2 侧信道与常量时间（P1）

- [x] 审查并补全所有密钥相关路径的常量时间实现（Poly1305 比较、ML-KEM 采样与 decaps 分支）。
- [ ] ML-KEM 侧信道防护（掩码 / 打乱），降低旁路攻击面。
- [ ] 引入 dudect / ctgrind 类工具做常量时间回归测试。

### 3.3 密码学可配置性（P2）

- [ ] 可选 AEAD 算法（如 XChaCha20-Poly1305、AES-GCM），通过 feature flag 或容器字段选择。
- [ ] 口令模式支持 Argon2id 参数上限校验，防止恶意容器用超大 `memory_kib` 造成 DoS。
- [ ] 引入算法敏捷性字段，为未来密码学升级留出升级路径（不破坏兼容）。

### 3.4 审计（P1）

- [ ] 寻求第三方安全审计（格式、原语、KEM 组合、解析器健壮性）。
- [ ] 发布安全策略（SECURITY.md）与负责任披露流程。

---

## 4. 容器格式演进（P1 / P2）

**现状**：v3 已支持分块 AEAD（`CHUNKED` 标志 + `ChunkedWriter`），加密载荷逐块认证；
仍未支持多线程并行压缩与可追加条目。

- [x] v3：分块 / 分帧布局（已支持逐块 AEAD 认证）。
  - [x] 逐块校验（单块损坏导致所在帧认证失败，可定位到帧）。
  - [ ] 多线程并行压缩 / 解压（与 §2.2 呼应）。
  - [ ] 可追加条目（增量归档）。
- [x] 每块独立 AEAD tag 与 nonce 派生，避免整包单一 nonce。
- [x] 保留 v1 / v2 读取兼容，v3 通过版本号渐进升级。
- [ ] 扩展头部字段为 TLV，便于未来扩展而不破坏解析。

---

## 5. CLI 与功能（P0 / P1）

**现状**：子命令 `compress` / `decompress` / `keygen` / `list` / `test` / `info` / `completion` 已就绪，
但缺少大量实用选项（[cli.rs](src/cli.rs) 手写解析）。

- [x] `--force` / `--overwrite`：覆盖已存在输出文件。
- [x] 自解压（SFX）：`rzp2 sfx` 生成自解压可执行文件（把 `rzp2` 自身作为存根追加 `.rzp2` 载荷，可选）。
- [ ] `--keep`：保留源文件。
- [x] `--dry-run`：只打印将执行的动作。
- [x] 详细进度条：压缩 / 解压 / 分片 / 合并显示 `[===>]` 风格进度条（百分比 + 工作类型）。
- [x] 多接收者加密：`--public-key` 支持重复指定多个公钥（多接收者 KEM）。
- [x] 口令交互式输入（无回显）与二次确认，替代明文 `--password` 的易泄露场景。
- [x] `list` 增强：显示 `-lh` 式人可读大小、mtime、权限、符号链接目标。
- [x] 归档过滤器：`--include` / `--exclude`（glob），选择性打包。
- [x] `decompress` 支持从归档中抽取单个条目到 stdout（`-o -` 单文件抽取）。
- [x] 文件分片 / 合并：`split` / `merge` 子命令（自研分片清单）。

---

## 6. 测试与工程化（P1）

**现状**：单元测试覆盖原语与管线，含模糊测试与 xz 交叉验证；CI 仅做三平台 build/test/clippy/fmt
（[ci.yml](.github/workflows/ci.yml)）。`deny.toml` 已配置但未接入 CI。

- [ ] CI 接入 `cargo deny check`（advisories / licenses / bans）。
- [ ] CI 增加持续模糊测试（`cargo fuzz` 短跑）与 `cargo-careful` / Miri 检查。
- [ ] CI 增加 sanitizer（ASan / MSan）构建与常量时间回归。
- [ ] 建立最低支持 Rust 版本（MSRV）并在 CI 校验。
- [ ] 代码覆盖率（cargo-llvm-cov）并设定最低门槛。
- [ ] 属性测试（proptest）补充 LZMA / 归档 / 头部编解码的边界。

---

## 7. 打包与分发（P1 / P2）

**现状**：deb / rpm / Arch / AUR / Homebrew / Scoop / NSIS / 可移植 zip 已覆盖（[Cargo.toml](Cargo.toml)、
[package.sh](package.sh)、[package.ps1](package.ps1)）。

- [ ] 发布到 crates.io，支持 `cargo install rzp2`。
- [ ] Flatpak / winget / Chocolatey 分发。
- [ ] 交叉编译产物加入 musl 静态链接（Linux 免 glibc 版本差异）。
- [ ] 为发布产物附 SHA-256 校验和与签名（minisign / Sigstore）。
- [ ] CI 自动化发布（tag 触发，上传多平台产物与校验和）。

---

## 8. 图形界面与生态集成（P2）

- [ ] 可选 TUI（如终端进度 + 交互式选择）与 GUI 前端（桌面端可视化压缩 / 解压 / 密钥管理）。
- [ ] 扩展文件管理器集成（除 Nautilus 外，补充 KDE Dolphin、Windows 资源管理器右键菜单）。
- [ ] 与 `tar` / `xz` 生态更深入互操作（如直接读写 xz 流、支持 `.tar.rzp2`）。

---

## 9. 文档与社区（P2）

- [ ] 多语言文档（英文版 README / FORMAT / API）。
- [ ] 安全性与性能基准报告，随版本发布。
- [ ] 贡献指南（CONTRIBUTING.md）与 issue 模板。

---

## 里程碑建议（非时间承诺）

- **0.4**（已发布）：流式接口 + SIMD 加密原语（ChaCha20 AVX2）+ `--force` / 进度条 +
  私钥口令加密 + 分块 AEAD（v3 容器）。
- **0.5**：LZMA 匹配器升级 + 分块并行 + 多接收者 + 归档过滤（P1 主体）。（已完成）
- **0.6 / 1.0**：容器 v3 完整分块（TLV 头部 / 随机访问 / 可追加）+ 安全审计 + 常量时间
  加固 + crates.io / 签名分发。
