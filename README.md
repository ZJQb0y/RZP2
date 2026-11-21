# RZP2

RZP2 是一个从零自研的混合加密压缩工具（第二代，与一代 RZP 不兼容）。
当前版本：RZP2 0.19.1。

- **压缩**：LZMA（LZ77 + 范围编码 + 自适应概率模型），码流与 LZMA SDK / xz 兼容
- **LZMA2 + .xz**：`rzp2 xz` / `rzp2 unxz` 读写标准 `.xz`（LZMA2）容器，与系统 xz 互操作
- **主流格式解压**：`rzp2 decompress` 按魔数探测 `.zip` / `.gz` / `.7z` / `.bz2` /
  `.tar.gz` / `.tar.xz` 等，零依赖手写各格式解析与解码内核；可用 `--format` 显式覆盖，
  `list` / `info` 同样支持外部归档，解包复用 `--processes` 并行写条目
- **压缩级别**：`--level 0..=9`（`lc=3 lp=0 pb=2`，字典大小 64 KiB ～ 64 MiB）
- **密钥封装**：ML-KEM（FIPS 203，即 Kyber）512/768/1024，及 ML-KEM + X25519 混合封装
- **口令加密**：Argon2id（RFC 9106）派生对称密钥 + ChaCha20-Poly1305 AEAD
- **对称加密**：ChaCha20-Poly1305 AEAD（RFC 8439）
- **密钥派生**：SHAKE-256 KDF（ML-KEM / ML-KEM+X25519 混合加密）；BLAKE2b 作为 Argon2 的 H0 / H'
- **归档**：目录递归打包，保留相对路径 / 权限 / mtime / 符号链接
- **容器格式**：`.rzp2`（v3，读取兼容 v1/v2）
- **自解压（SFX）**：`rzp2 sfx` 生成自解压可执行文件（可选）
- **进度条**：压缩 / 解压 / 分片 / 合并显示 `[===>   ]` 风格进度条（百分比 + 工作类型）
- **分片 / 合并**：`rzp2 split` / `rzp2 merge` 把文件切成多片再按清单合并还原
- **性能基准**：`rzp2 bench` 内置 LZMA / ML-KEM / 管线吞吐与每秒操作数基准，并对比 xz / zstd / 7z 压缩吞吐；除中位数外额外报告 min/max 范围、变异系数与峰值内存（RSS），并可用 `--sweep` 一次性扫描 LZMA 级别 0~9

核心算法全部手写实现，零运行时第三方依赖（OS 随机源与密钥清零均从零实现），并通过官方测试向量验证。

## 构建

```sh
cargo build --release
```

## 动态库（C ABI）

除命令行工具外，`cargo build --release` 还会按功能产出两个独立的 C ABI 动态库，
供 C/C++ 等语言在无需 CLI 的情况下按需链接：

| 库 | 头文件 | 产物（Linux / macOS / Windows） | 功能 |
| --- | --- | --- | --- |
| 压缩 / 解压 | `crates/rzp2-compress/include/rzp2_compress.h` | `librzp2_compress.so` / `.dylib` / `rzp2_compress.dll` | LZMA1 alone 编解码 |
| 加密 / 解密 | `crates/rzp2-crypto/include/rzp2_crypto.h` | `librzp2_crypto.so` / `.dylib` / `rzp2_crypto.dll` | ML-KEM(+X25519) 密钥生成与混合加解密、ChaCha20-Poly1305 AEAD、Argon2id 口令派生 |

完整 C 示例见：

- `examples/ffi/rzp2_compress_demo.c`
- `examples/ffi/rzp2_crypto_demo.c`

打包脚本会把 `.so` / `.dll` 与头文件一并收集到 `dist` 的 `lib/`、`include/` 子目录。

## 命令行

```sh
# 生成 ML-KEM 长期密钥对
rzp2 keygen --params mlkem768 --public pub.key --private priv.key

# 压缩（未加密）
rzp2 compress input.txt -o output.rzp2 --checksum

# 压缩 + 混合加密
rzp2 compress input.txt -o output.rzp2 --encrypt --public-key pub.key --checksum

# 口令加密（- 表示口令从 stdin 读取）
rzp2 compress input.txt -o output.rzp2 --password -

# 压缩目录（递归归档）
rzp2 compress ./docs -o docs.rzp2

# 解压（未加密）
rzp2 decompress output.rzp2 -o restored.txt

# 解压 + 解密
rzp2 decompress output.rzp2 -o restored.txt --private-key priv.key

# 列出归档条目 / 校验完整性 / 查看元信息
rzp2 list docs.rzp2
rzp2 test docs.rzp2
rzp2 info docs.rzp2

# 生成自解压可执行文件（把 rzp2 自身作为存根追加 .rzp2 载荷）
rzp2 sfx docs.rzp2 -o docs.exe

# 分片（默认每片 10 MiB，可用 --chunk-size 指定）与合并
rzp2 split big.bin -o parts --chunk-size 1048576
rzp2 merge parts.manifest -o big.bin

# 性能基准（吞吐 / 每秒操作数 / 峰值内存；可用 --size 调整数据大小、--processes 固定进程数）
rzp2 bench
rzp2 bench --size 4194304 --processes 4 --level 6 --budget 200
rzp2 bench --json --size 1048576 --level 9
rzp2 bench --sweep   # 扫描 LZMA 级别 0~9 的吞吐与压缩率

# 压缩为标准 .xz（LZMA2）容器 / 解压 .xz（与系统 xz 互操作）
rzp2 xz input.txt -o output.xz --level 6
rzp2 unxz output.xz -o restored.txt

# 产出多块 .xz 并并行压缩（--block-size 指定每块未压缩大小，--processes 指定进程数）
rzp2 xz big.bin -o big.xz --block-size 65536 --processes 4

# 解压主流格式（按魔数自动探测，无需指定 --format）
rzp2 decompress archive.zip -o dir
rzp2 decompress data.tar.gz -o dir
rzp2 decompress data.tar.xz -o dir
rzp2 decompress file.gz -o file
rzp2 decompress file.bz2 -o file
rzp2 decompress archive.7z -o dir
```

参数集 `<set>`：`mlkem512` / `mlkem768` / `mlkem1024`（默认 `mlkem768`）；
加 `-x25519` 后缀（如 `mlkem768-x25519`）启用 ML-KEM + X25519 混合封装。
输入 / 输出可用 `-` 表示 stdin / stdout，例如 `tar -c ... | rzp2 compress - -o out.rzp2`。

自解压可执行文件把 `rzp2` 自身作为存根，尾部追加 `.rzp2` 载荷；运行时检测到内嵌载荷即解压到当前目录（归档按条目还原，单文件则以可执行文件去扩展名的基名输出）。未加密与口令加密容器可直接自解压（口令加密运行时提示输入口令）；ML-KEM 公钥加密容器因无法在存根内安全携带私钥，请改用 `rzp2 decompress --private-key` 解压。

跨平台分发时，可用 `--stub` 指定目标平台的 `rzp2` 存根，从而在本机生成其他系统的自解压文件。例如在 Linux 上生成 Windows 自解压文件：

```sh
# 1. 交叉编译 Windows 存根（需 rustup target + mingw-w64）
cargo build --release --target x86_64-pc-windows-gnu

# 2. 用该存根生成 Windows 自解压文件
rzp2 sfx docs.rzp2 --stub target/x86_64-pc-windows-gnu/release/rzp2.exe -o docs.exe
```

也可直接使用 `./package.sh` 打包产出的 `dist/rzp2-<版本>-x86_64-windows-sfx-stub.exe` 作为存根。

## Shell 补全

`rzp2` 内置 bash / zsh / fish / PowerShell 的 Tab 补全，可通过 `rzp completion <shell>` 生成：

```sh
# 临时启用（当前会话）
source <(rzp completion bash)     # bash / zsh
rzp completion fish | source      # fish
```

```powershell
# PowerShell 临时启用（当前会话）
rzp completion powershell | Out-String | Invoke-Expression
```

永久启用可将补全脚本写入 shell 配置（如 PowerShell 的 `$PROFILE`）：

```powershell
rzp completion powershell | Out-File -Encoding utf8 "$PROFILE" -Append
```

例如输入 `rzp c` 后按 Tab 会自动补全为 `compress`；各子命令的选项（`--params` 的取值、`-o` 的文件路径等）同样支持补全。deb / rpm / Arch / Homebrew 安装时会自动写入对应 shell 的补全目录；Windows 安装包（NSIS）会在安装向导中询问是否自动把补全写入 PowerShell 的 `$PROFILE`，可移植 zip 则附带 `rzp2-completion.ps1` 供手动引用。

## 文档

- [FORMAT.md](FORMAT.md)：`.rzp2` 容器格式与密钥文件规范
- [API.md](API.md)：库 API 说明
- [man/rzp2.1](man/rzp2.1)：命令行手册页
- [CHANGELOG.md](CHANGELOG.md)：变更日志
- [ROADMAP.md](ROADMAP.md)：路线图

## 测试

```sh
cargo test
```

测试覆盖：

- **LZMA**：范围编码器、位树、随机/重复/文本数据往返、压缩率基准，以及与 `xz` 的双向码流交叉验证
- **ML-KEM**：NIST ACVP（FIPS 203）官方 KAT 字节级校验（keygen 75 组 + encap/decap 75 组）、往返与 FO 隐式拒绝测试
- **AEAD**：RFC 8439 官方测试向量、篡改检测
- **Argon2id**：RFC 9106 Argon2d / Argon2i / Argon2id / p=4 官方测试向量
- **BLAKE2b**：RFC 7693 官方测试向量
- **归档**：条目编解码往返、空归档、截断拒绝
- **分片 / 合并**：清单编解码往返、从清单 / 分片路径定位分片
- **端到端**：完整管线往返、口令 / 公钥加密、错误密钥拒绝、大文件
- **模糊测试**：随机输入 / 截断 / 头部损坏 / 密文篡改均不 panic

基准测试需要 nightly：

```sh
cargo +nightly bench
```

也可直接运行内置性能基准（无需 nightly）：

```sh
rzp2 bench
```

## 算法与安全说明

### 压缩

LZMA 编码器采用 LZ77 匹配（哈希链）+ 自适应二进制范围编码。输出为标准 LZMA1「alone」格式码流（`properties + dict_size + uncompressed_size + raw stream`），可由标准 `xz --format=lzma` 解压，反之亦可。

`--level 0..=9` 映射到 `lc=3, lp=0, pb=2` 与字典大小预设：

| level | 字典大小 |
| --- | --- |
| 0 | 64 KiB |
| 1 | 256 KiB |
| 2 | 1 MiB |
| 3 | 2 MiB |
| 4 | 4 MiB |
| 5 | 8 MiB（默认） |
| 6 | 16 MiB |
| 7 | 32 MiB |
| 8 | 64 MiB |
| 9 | 64 MiB |

### 密钥封装

ML-KEM 实现严格遵循 FIPS 203：

- 多项式环 `Z_q[X]/(X^256 + 1)`，`q = 3329`
- NTT / 逆 NTT、CBD 采样、拒绝采样
- K-PKE（IND-CPA）与 KEM（FO 变换，解封装失败返回隐式拒绝值）

三档参数集均通过 NIST ACVP 官方测试向量的字节级校验。

### 混合加密（ML-KEM / ML-KEM + X25519）

1. 加密方生成临时 ML-KEM 密钥对，`encaps` 得到密文 `ek` 与共享密钥 `ss`；混合模式下
   同时生成临时 X25519 密钥对做一次 ECDH，把 ML-KEM 与 X25519 两个共享密钥经
   SHAKE-256 合并为单一 `ss`
2. `ss` 经 SHAKE-256 KDF 派生 AEAD 密钥与 nonce（绑定 label 与参数集名称）
3. ChaCha20-Poly1305 加密压缩数据，AAD 绑定 `ek` 防止封装密文被篡改
4. 解密方 `decaps`（混合时加 X25519 ECDH）→ KDF → AEAD 解密校验

### 口令加密（Argon2id）

1. 生成随机 16 字节盐与 12 字节 AEAD nonce
2. Argon2id（RFC 9106）从口令派生 32 字节对称密钥；默认 `64 MiB / 3 次 / 4 lanes`
3. ChaCha20-Poly1305 加密压缩数据，AAD 绑定完整头部（盐、KDF 参数、级别、大小、校验和），防止头部被篡改
4. 头部记录 `salt / memory_kib / iterations / lanes`，解密时按记录参数重新派生

### 容器格式

```text
+-------------------+--------------------------------+
| 固定头部前缀       | magic(4) version(1) flags(1)   |
|                   | level(1) reserved(1)           |
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

- 魔数 `RZP2`，版本 `3`（读取兼容 v1/v2）
- 加密字段按模式区分：ML-KEM 为 `ek_len(2, LE) ek(..) nonce(12)`（混合封装时 `ek` 为 `mlkem_ct || x25519_epk`）；口令模式为 `salt(16) memory_kib(4) iterations(4) lanes(4) nonce(12)`
- 加密时载荷默认采用分块 AEAD（v3）：压缩流切成 64 KiB 块逐块加密为 `len(4) + ct + tag(16)` 帧，
  每帧独立 nonce，AAD 绑定头部字节 + 帧序号；末尾以 `len=0` 终止帧结束
- `level` 为压缩级别预设（0..=9），仅作记录
- `ARCHIVE` 标志置位时，载荷为归档流（见 [FORMAT.md](FORMAT.md)）
- `checksum` 为未压缩明文的 SHAKE-256 摘要（可选）

### 安全声明

- 本实现为教学 / 研究用途，从零自研以学习算法原理，未经过第三方安全审计，请勿用于生产环境的关键数据保护。
- 密钥材料在使用后通过自实现的 `Zeroize` 清零（共享密钥、派生密钥、口令派生密钥）。
- 口令不会出现在进程参数中（可用 `--password -` 从 stdin 读取）。
- 私钥文件以 PEM 风格文本保存，请妥善保管并设置合适的文件权限。

## 打包与跨平台

- [package.sh](package.sh)：Linux 打包脚本（可移植 tar.gz、deb、rpm，及 Windows 交叉编译 zip）
- [package.ps1](package.ps1)：Windows 打包脚本（可移植 zip、rpm）
- [.github/workflows/ci.yml](.github/workflows/ci.yml)：Linux / macOS / Windows 三平台 CI

Windows 版本图标与版本信息由 [build.rs](build.rs) 在编译时嵌入 `rzp2.exe`。

## 许可

MIT OR Apache-2.0
