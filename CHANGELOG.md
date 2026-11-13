# 变更日志

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

## [0.8.0] - 2026-11-13

### 新增

- 详细进度条：压缩 / 解压 / 分片 / 合并均显示 `[===>   ]` 风格进度条，包含百分比、
  工作类型（压缩 / 压缩+加密 / 解压 / 解密+解压 / 分片 / 合并）与已处理字节数；仅在
  stderr 为终端时启用
- 文件分片与合并：新增 `split` / `merge` 子命令，自研二进制清单（`RZP2SPL1`）记录
  原始文件名、分片数、每片大小与总大小；把文件切成 `<prefix>.part.NNNNN` 等大小分片，
  再按清单顺序合并还原并校验总大小
- 库模块：新增 `progress`（零依赖进度条 + `ProgressReader` / `ProgressWriter`）与
  `split`（分片 / 合并 + 清单编解码）

## [0.7.0] - 2026-11-07

### 新增

- CLI：`compress` / `decompress` 支持 `--dry-run`，只打印将执行的动作而不实际读写
- CLI：`decompress --entry <path>` 从归档中抽取单个条目（配合 `-o -` 输出到 stdout）
- CLI：`list -l/--long` 长格式（权限、大小、mtime、符号链接目标），`--human-readable` 以
  B / KiB / MiB 等可读单位显示大小
- CLI：`--password -` / `--key-password -` / `--private-password -` 在终端下无回显读取，
  设置口令（压缩 / keygen）时二次确认
- 归档流式解包：`decompress` 对归档按条目增量落盘，文件内容以分块形式写出，避免整包
  `decode_archive` 到内存（`StreamUnpacker` + `EntrySink`）
- SIMD：ChaCha20 在 aarch64 上补 NEON 4 路并行快路径（运行时检测 + 标量兜底）
- SIMD：Poly1305 在 aarch64 上补 NEON 2 路并行乘加快路径（运行时检测 + 标量兜底）

### 修复

- ChaCha20 AVX2 快路径转置阶段以 256 位 store 写入 64 字缓冲区，存在越界写；改为 128 位
  store 仅写低 4 lane
- 归档流式解包对「结束标记与尾随字节同批喂入」未报错，现统一拒绝尾随数据
- ML-KEM `poly_frommsg` 用乘法替代消息位相关分支，消除密钥相关数据依赖控制流

## [0.6.0] - 2026-11-06

### 新增

- 自解压（SFX）：新增 `sfx` 子命令，把 `rzp2` 自身作为存根追加 `.rzp2` 载荷生成自解压可执行文件
- 运行时自检测：启动时识别内嵌载荷（尾部 footer `RZP2SFX` + 8 字节小端载荷长度）并解压到当前目录
- SFX 支持未加密 / 口令加密容器（口令加密运行时提示输入口令）；ML-KEM 加密容器提示改用
  `decompress --private-key`
- 文档与补全：README / FORMAT / ROADMAP / man 及四种 shell 补全同步新增 `sfx`

## [0.5.0] - 2026-11-06

### 新增

- LZMA 匹配器升级：延迟匹配（lazy matching）与级别自适应的哈希链深度 / 快速停断阈值，
  提升高压缩级别压缩率
- 分块并行压缩：`--threads <n>`（>1 启用分块 LZMA 载荷，v3 `BLOCKED` 标志）+ `--block-size <bytes>`
- 多接收者加密：`--public-key` 可重复指定多把公钥，采用随机 DEK + 每接收者独立封装
  （v3 `MULTI` 标志，复用头部第 7 字节作为 flags2 扩展）
- 归档过滤器：`--include` / `--exclude`（零依赖 glob 匹配），选择性打包目录条目

### 变更

- 容器 v3 头部第 7 字节（原 reserved）复用为 flags2，承载 `MULTI` 与 `BLOCKED` 两个扩展标志
- `PackConfig` 新增 `threads` 与 `block_size` 字段
- 压缩 / 补全帮助文本新增 `--include` / `--exclude` / `--threads` / `--block-size` 选项

## [0.4.1] - 2026-11-06

### 新增

- `-o` / `--output` 改为可选：压缩默认输出 `<input>.rzp2`，解压默认去掉 `.rzp2` 还原原名

### 修复

- 目录归档相对路径改为始终相对顶层目录计算，修复嵌套文件 / 目录解压后层级被平铺到同一目录的问题

## [0.4.0] - 2026-11-06

### 新增

- 分块 AEAD（v3 容器）：压缩流切成 64 KiB 块逐块加密为 `len + ct + tag` 帧，每帧独立
  nonce 派生（基准 nonce 与帧序号异或），AAD 绑定头部字节 + 帧序号，防止重排 / 截断 / 重放
- 流式压缩：单文件（无校验和）边读边压缩边加密直接落盘，不再整包驻留内存
- SIMD 加速 ChaCha20（AVX2 快路径，运行时检测 + 纯标量兜底）
- 私钥口令加密：`keygen --private-password` 输出加密私钥；解压 / 列表 / 校验支持 `--key-password`
- `--force` / `--overwrite`：覆盖已存在输出文件
- 流式解压进度条（仅终端启用）

### 变更

- 容器格式升级到 v3：新增 `CHUNKED` 标志位，加密载荷默认采用分块 AEAD；读取端保留 v1 / v2 兼容
- `hybrid` 拆出 `encapsulate` / `decapsulate` 供流式分块路径复用
- `pipeline` 新增 `pack_to_writer` 流式打包接口

## [0.3.0] - 2026-11-05

### 新增

- 跨 shell Tab 补全：新增 `completion` 子命令，支持 bash / zsh / fish / PowerShell；可补全子命令（含短别名前缀）、各选项、`--params` / `--level` 取值与文件路径
- 打包接入：deb / rpm / Arch / Homebrew 安装时自动写入对应 shell 的补全目录；Windows 安装包在安装向导中提供「注册 PowerShell Tab 补全」选项，可移植 zip 附带 `rzp2-completion.ps1`

## [0.2.1] - 2026-11-05

### 新增

- CLI 彩色化：帮助文本、错误、成功状态与 `info` 标签带 ANSI 颜色，非终端（重定向 / 管道）自动禁用；帮助选项说明统一对齐

### 变更

- 移除运行时依赖 `getrandom` 与 `zeroize`：OS 随机源（`crypto::rand`）与密钥清零（`crypto::zeroize`）改为从零实现，达成零运行时第三方依赖

## [0.2.0] - 2026-11-04

### 新增

- 压缩级别与字典大小预设：`--level 0..=9`、`--dict-size`，写入容器头部 `level` 字段
- 口令加密：Argon2id（RFC 9106）派生对称密钥 + ChaCha20-Poly1305 AEAD，CLI 新增 `--password`（`-` 从 stdin 读取）
- BLAKE2b（RFC 7693）与 Argon2 原语模块，通过 RFC 官方测试向量
- 目录归档：递归打包 / 解包，保留相对路径、Unix 权限、mtime 与符号链接
- 归档流编解码模块（`archive`），路径安全检查（拒绝绝对路径与 `..`）
- CLI 新增 `list` / `test` / `info` 子命令，查看条目、校验完整性、查看元信息
- CLI 输入 / 输出支持 `-`（stdin / stdout），便于管道组合

### 变更

- 容器格式升级到 v2：头部新增 `level` 字节，新增 `PASSWORD` / `ARCHIVE` 标志位，
  支持未知长度（`u64::MAX`）；读取端保留 v1 兼容
- `pipeline` 接口重构为 `PackConfig` / `Encryption` / `DecryptKey`，统一三种加密模式
  （无 / ML-KEM / 口令）

### 修复

- `list` 输出条目类型标记的格式（`-` / `d` / `l`）

## [0.1.0] - 2026-11-04

### 新增

- 从零实现 LZMA 编解码器（LZ77 + 范围编码 + 自适应概率模型），码流与 LZMA SDK / xz 兼容
- ML-KEM（FIPS 203 / Kyber）512 / 768 / 1024 密钥封装，通过 NIST ACVP 官方测试向量
- ChaCha20-Poly1305 AEAD（RFC 8439）
- SHAKE-256 KDF 混合加密管线
- `.rzp2` 容器格式与 PEM 风格密钥文件
- 命令行子命令 `compress` / `decompress` / `keygen`
- 跨平台构建与打包脚本、CI、图标与文档
