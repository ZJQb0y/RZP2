#!/usr/bin/env bash
#
# 校验各文件中的版本号与 Cargo.toml 保持一致。
#
# 用法:
#   scripts/check-version.sh
#
# 以 Cargo.toml 的 `version` 为唯一权威来源，逐一比对以下位置：
#   README.md、API.md、man/rzp2.1

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' Cargo.toml | head -n1)"
: "${VERSION:?无法从 Cargo.toml 解析版本号}"

fail=0

check() {
    local file="$1" pattern="$2"
    if [ -f "$file" ] && grep -qF "$pattern" "$file"; then
        echo "OK   $file"
    else
        echo "FAIL $file（未找到 \"$pattern\"）" >&2
        fail=1
    fi
}

check "README.md"  "RZP2 ${VERSION}"
check "API.md"     "RZP2 ${VERSION}"
check "man/rzp2.1" "rzp2 ${VERSION}"

if [ "$fail" -ne 0 ]; then
    echo "版本号不一致，请统一为 ${VERSION}。" >&2
    exit 1
fi

echo "版本号一致：${VERSION}"
