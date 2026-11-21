<#
.SYNOPSIS
  RZP2 Windows 一键打包脚本

.DESCRIPTION
  在 Windows 上编译 release 并生成：
    dist\rzp2-<版本>-<架构>-windows.zip          可移植二进制 + 文档 + 图标
    dist\rzp2-<版本>-<架构>-windows-setup.exe     NSIS 安装包（需已安装 NSIS）
    dist\rzp2-<版本>-1.<架构>.rpm                 RPM 安装包（跨平台，需已安装 cargo-generate-rpm 且存在 Linux 二进制）
    dist\rzp2-<版本>-1-<架构>.pkg.tar.zst         Arch Linux 安装包（需已安装 makepkg，Windows 下跳过）

  图标与版本信息由 build.rs 在编译时嵌入 rzp2.exe。

.PARAMETER SkipInstaller
  跳过 NSIS 安装包生成，只产出可移植 zip。

.EXAMPLE
  .\package.ps1

.EXAMPLE
  .\package.ps1 -SkipInstaller
#>
[CmdletBinding()]
param(
    [switch]$SkipInstaller
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = $PSScriptRoot
Set-Location $Root

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

function Get-CargoVersion {
    $cargo = Get-Content -Raw (Join-Path $Root 'Cargo.toml')
    if ($cargo -notmatch '(?m)^version\s*=\s*"([^"]+)"') {
        throw '无法从 Cargo.toml 解析版本号'
    }
    $Matches[1]
}

function Find-MakeNsis {
    $cmd = Get-Command makensis -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $candidates = @(
        "$env:ProgramFiles\NSIS\makensis.exe",
        "${env:ProgramFiles(x86)}\NSIS\makensis.exe",
        "$env:ProgramData\chocolatey\bin\makensis.exe",
        "$env:USERPROFILE\scoop\shims\makensis.exe"
    )

    foreach ($key in @('HKLM:\SOFTWARE\NSIS', 'HKLM:\SOFTWARE\WOW6432Node\NSIS')) {
        $dir = Get-ItemPropertyValue -Path $key -Name '(default)' -ErrorAction SilentlyContinue
        if ($dir) {
            $candidates += (Join-Path $dir 'makensis.exe')
            $candidates += (Join-Path $dir 'Bin\makensis.exe')
        }
    }

    foreach ($p in $candidates) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

# ---------------------------------------------------------------------------
# 1. 版本号
# ---------------------------------------------------------------------------
$Version = Get-CargoVersion
$parts = ($Version -split '\.')
while ($parts.Count -lt 4) { $parts += '0' }
$ViVersion = ($parts[0..3] -join '.')

# ---------------------------------------------------------------------------
# 2. 目标架构
# ---------------------------------------------------------------------------
$hostLine = (rustc -vV | Select-String '^host:').Line
$hostTriple = $hostLine.Substring($hostLine.IndexOf(':') + 1).Trim()
switch -Regex ($hostTriple) {
    '^x86_64'   { $Arch = 'x86_64' }
    '^aarch64'  { $Arch = 'aarch64' }
    '^i[3-6]86' { $Arch = 'i686' }
    default     { $Arch = $hostTriple }
}
$WinPlatform = "$Arch-windows"

# ---------------------------------------------------------------------------
# 3. 编译 release
# ---------------------------------------------------------------------------
Write-Host '==> 编译 release 版本' -ForegroundColor Cyan
cargo build --release
if ($LASTEXITCODE -ne 0) { throw 'cargo build --release 失败' }

# ---------------------------------------------------------------------------
# 4. 收集产物
# ---------------------------------------------------------------------------
$Dist  = Join-Path $Root 'dist'
$Stage = Join-Path $Dist "rzp2-$Version-$WinPlatform"
if (Test-Path $Stage) { Remove-Item -Recurse -Force $Stage }
New-Item -ItemType Directory -Force -Path $Stage | Out-Null

Write-Host "==> 收集产物到 $Stage" -ForegroundColor Cyan
Copy-Item (Join-Path $Root 'target\release\rzp2.exe') (Join-Path $Stage 'rzp2.exe') -Force
foreach ($doc in @('README.md', 'FORMAT.md', 'API.md', 'LICENSE', 'LICENSE-MIT', 'LICENSE-APACHE')) {
    $src = Join-Path $Root $doc
    if (Test-Path $src) { Copy-Item $src $Stage -Force }
}
$icon = Join-Path $Root 'assets\rzp2.ico'
if (Test-Path $icon) { Copy-Item $icon (Join-Path $Stage 'rzp2.ico') -Force }

# 收集动态库（.dll）与 C 头文件。
Write-Host '==> 收集动态库（.dll）与 C 头文件' -ForegroundColor Cyan
$libDir = Join-Path $Stage 'lib'
$incDir = Join-Path $Stage 'include'
New-Item -ItemType Directory -Force -Path $libDir | Out-Null
New-Item -ItemType Directory -Force -Path $incDir | Out-Null
Copy-Item (Join-Path $Root 'target\release\rzp2_compress.dll') (Join-Path $libDir 'rzp2_compress.dll') -Force
Copy-Item (Join-Path $Root 'target\release\rzp2_crypto.dll') (Join-Path $libDir 'rzp2_crypto.dll') -Force
Copy-Item (Join-Path $Root 'crates\rzp2-compress\include\rzp2_compress.h') (Join-Path $incDir 'rzp2_compress.h') -Force
Copy-Item (Join-Path $Root 'crates\rzp2-crypto\include\rzp2_crypto.h') (Join-Path $incDir 'rzp2_crypto.h') -Force

# 生成 PowerShell Tab 补全脚本（供用户 dot-source 或写入 $PROFILE）。
Write-Host '==> 生成 PowerShell Tab 补全脚本' -ForegroundColor Cyan
$completionPs1 = Join-Path $Stage 'rzp2-completion.ps1'
& (Join-Path $Root 'target\release\rzp2.exe') completion powershell |
    Set-Content -Path $completionPs1 -Encoding UTF8

# ---------------------------------------------------------------------------
# 5. 可移植 zip
# ---------------------------------------------------------------------------
$Zip = Join-Path $Dist "rzp2-$Version-$WinPlatform.zip"
if (Test-Path $Zip) { Remove-Item $Zip }
Write-Host '==> 生成可移植 zip' -ForegroundColor Cyan
Compress-Archive -Path $Stage -DestinationPath $Zip

# ---------------------------------------------------------------------------
# 6. NSIS 安装包
# ---------------------------------------------------------------------------
if ($SkipInstaller) {
    Write-Host '已跳过 NSIS 安装包生成（-SkipInstaller）' -ForegroundColor Yellow
}
else {
    $MakeNsis = Find-MakeNsis
    if (-not $MakeNsis) {
        Write-Host '未检测到 NSIS（makensis.exe），跳过安装包生成。' -ForegroundColor Yellow
        Write-Host '请安装 NSIS 或将其加入 PATH。' -ForegroundColor Yellow
    }
    else {
        Write-Host "==> 使用 NSIS 生成安装包（$MakeNsis）" -ForegroundColor Cyan
        $NsiPath = Join-Path $Root 'packaging\windows\rzp2.nsi'
        $InstallerOut = Join-Path $Dist "rzp2-$Version-$WinPlatform-setup.exe"

        # NSIS 的 !cd / OutFile 接受正斜杠，避免反斜杠在命令行参数中被解释。
        $OutFileForNsis  = $InstallerOut.Replace('\', '/')
        $StageDirForNsis = $Stage.Replace('\', '/')

        & $MakeNsis `
            "-DVERSION=$Version" `
            "-DVIVERSION=$ViVersion" `
            "-DARCH=$Arch" `
            "-DOUTFILE=$OutFileForNsis" `
            "-DSTAGEDIR=$StageDirForNsis" `
            $NsiPath
        if ($LASTEXITCODE -ne 0) {
            throw "makensis 失败（退出码 $LASTEXITCODE）"
        }
    }
}

# ---------------------------------------------------------------------------
# 7. RPM 安装包（跨平台，cargo-generate-rpm 生成，无需 rpmbuild；需要 Linux 二进制）
# ---------------------------------------------------------------------------
$CargoGenerateRpm = Get-Command cargo-generate-rpm -ErrorAction SilentlyContinue
$RpmLinuxBin = Join-Path $Root 'target\release\rzp2'
if (-not $CargoGenerateRpm) {
    Write-Host '未检测到 cargo-generate-rpm，跳过 .rpm 生成。' -ForegroundColor Yellow
    Write-Host '可执行: cargo install cargo-generate-rpm' -ForegroundColor Yellow
}
elseif (-not (Test-Path $RpmLinuxBin)) {
    Write-Host '.rpm 为 Linux 安装包，未找到 Linux 二进制 target\release\rzp2，跳过。' -ForegroundColor Yellow
}
else {
    Write-Host '==> 生成 RPM 安装包' -ForegroundColor Cyan
    $RpmOut = Join-Path $Dist "rzp2-$Version-1.$Arch.rpm"
    $RpmOutForCargo = $RpmOut.Replace('\', '/')
    cargo generate-rpm -o $RpmOutForCargo
    if ($LASTEXITCODE -ne 0) {
        throw "cargo generate-rpm 失败（退出码 $LASTEXITCODE）"
    }
}

# ---------------------------------------------------------------------------
# 8. Arch Linux 安装包（.pkg.tar.zst 仅适用于 Linux/Arch，Windows 下跳过）
# ---------------------------------------------------------------------------
if (-not (Get-Command makepkg -ErrorAction SilentlyContinue)) {
    Write-Host '未检测到 makepkg，跳过 .pkg.tar.zst 生成（使用 Linux 上的 package.sh 生成）。' -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 9. 汇总
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '打包完成：' -ForegroundColor Green
Get-ChildItem $Dist -File | Where-Object {
    $_.Name -like "rzp2-$Version-$WinPlatform*"
} | ForEach-Object {
    '{0,8:N1} KB  {1}' -f ($_.Length / 1KB), $_.FullName
}
Get-ChildItem $Dist -File | Where-Object {
    $_.Name -eq "rzp2-$Version-1.$Arch.rpm"
} | ForEach-Object {
    '{0,8:N1} KB  {1}' -f ($_.Length / 1KB), $_.FullName
}
