#!/usr/bin/env bash
#
# RZP2 一键发版脚本：校验 → 测试 → 同步版本号 → 生成 SBOM → 提交打 tag。
#
# 用法:
#   scripts/release.sh <新版本号> [--push]
#
# 步骤:
#   1. 校验工作区干净、版本号格式、当前分支为 main
#   2. cargo test / clippy / fmt 全绿
#   3. 更新 Cargo.toml 与 Cargo.lock 中的版本号
#   4. 校验并（尽力）同步 README / API / man 中的版本号
#   5. 生成 SBOM（若已安装 cargo-cyclonedx）
#   6. 提交变更并打 tag v<版本号>（加 --push 时同时推送）
#
# 版本号以 Cargo.toml 为唯一权威来源；CHANGELOG.md 请手工在发布前补齐 [Unreleased]。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

NEW_VERSION="${1:-}"
PUSH=0
for arg in "$@"; do
    [ "$arg" = "--push" ] && PUSH=1
done

if [ -z "$NEW_VERSION" ]; then
    echo "用法: $0 <新版本号> [--push]" >&2
    exit 1
fi

# 版本号必须是 x.y.z（可带预发布/构建后缀），拒绝空串或含空白。
if ! printf '%s' "$NEW_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$'; then
    echo "错误: 版本号 \"$NEW_VERSION\" 不符合 semver 风格（示例: 2.2.0）。" >&2
    exit 1
fi

CUR_VERSION="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' Cargo.toml | head -n1)"
: "${CUR_VERSION:?无法从 Cargo.toml 解析当前版本号}"

if [ "$NEW_VERSION" = "$CUR_VERSION" ]; then
    echo "错误: 新版本号与当前版本号相同（$CUR_VERSION）。" >&2
    exit 1
fi

echo "==> 校验工作区状态"
if ! git diff --quiet --exit-code; then
    echo "错误: 工作区有未提交改动，请先提交或暂存。" >&2
    exit 1
fi
if [ -n "$(git status --porcelain)" ]; then
    echo "错误: 工作区有未跟踪文件，请先处理。" >&2
    exit 1
fi

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ "$BRANCH" != "main" ]; then
    echo "错误: 当前分支为 \"$BRANCH\"，发版请在 main 分支进行。" >&2
    exit 1
fi

echo "==> 运行测试与静态检查"
cargo test --release
# 基准测试（benches/bench.rs）依赖 nightly 的 `test` crate，故静态检查不包含 benches。
cargo clippy --lib --bins --tests --examples -- -D warnings
cargo fmt --all -- --check

echo "==> 更新版本号 $CUR_VERSION -> $NEW_VERSION"
# Cargo.toml 的 version 行。
sed -i "s/^version[[:space:]]*=[[:space:]]*\"$CUR_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml
# Cargo.lock 顶部 package 块中的 version。
sed -i "0,/^version[[:space:]]*=[[:space:]]*\"$CUR_VERSION\"/s//version = \"$NEW_VERSION\"/" Cargo.lock

# 文档版本同步：能自动替换的做替换，其余交给 check-version.sh 校验。
sed -i "s/RZP2 ${CUR_VERSION}/RZP2 ${NEW_VERSION}/g" README.md API.md
sed -i "s/rzp2 ${CUR_VERSION}/rzp2 ${NEW_VERSION}/g" man/rzp2.1

echo "==> 校验文档版本号一致"
scripts/check-version.sh

echo "==> 生成 SBOM（可选）"
if command -v cargo-cyclonedx >/dev/null 2>&1; then
    cargo cyclonedx --all --format json --output-format json 2>/dev/null || true
    echo "    -> bom.json"
else
    echo "    未检测到 cargo-cyclonedx，跳过 SBOM（可执行: cargo install cargo-cyclonedx）"
fi

echo "==> 提交并打 tag"
git add Cargo.toml Cargo.lock README.md API.md man/rzp2.1
# CHANGELOG 若存在且被改动则一并纳入。
if [ -n "$(git status --porcelain CHANGELOG.md)" ]; then
    git add CHANGELOG.md
fi
git commit -m "chore: 发布 v$NEW_VERSION"

TAG="v$NEW_VERSION"
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null 2>&1; then
    echo "警告: tag $TAG 已存在，跳过打 tag。"
else
    git tag -a "$TAG" -m "RZP2 $NEW_VERSION"
fi

if [ "$PUSH" -eq 1 ]; then
    echo "==> 推送到远端"
    git push origin main
    git push origin "$TAG"
else
    echo "提示: 未推送。确认无误后执行: git push origin main && git push origin $TAG"
fi

echo "完成: 已准备 v$NEW_VERSION 发版。请确认 CHANGELOG.md 已更新 [Unreleased] -> [$NEW_VERSION]。"
