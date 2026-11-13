//! 命令行 Tab 补全脚本。
//!
//! 通过隐藏子命令 `rzp completion <shell>` 输出对应 shell 的补全脚本，
//! 保持「零运行时第三方依赖」的定位不变。支持 bash / zsh / fish / powershell。用户可直接：
//!
//! ```sh
//! source <(rzp completion bash)   # bash / zsh 临时启用
//! rzp completion fish | source     # fish 临时启用
//! rzp completion powershell | Out-String | Invoke-Expression  # PowerShell 临时启用
//! ```

/// 输出指定 shell 的补全脚本；不认识的 shell 返回错误。
pub fn render(shell: &str) -> Result<String, String> {
    match shell {
        "bash" => Ok(BASH.to_string()),
        "zsh" => Ok(ZSH.to_string()),
        "fish" => Ok(FISH.to_string()),
        "powershell" | "pwsh" => Ok(POWERSHELL.to_string()),
        other => Err(format!(
            "未知 shell `{other}`（可选 bash/zsh/fish/powershell）"
        )),
    }
}

/// bash 补全脚本。可补全子命令（支持短别名前缀匹配）、各子命令选项，
/// 以及 `--params` / `--level` 的取值和文件型选项的路径。
const BASH: &str = r#"# bash completion for rzp2

_rzp2_subcommands="compress decompress keygen list test info sfx split merge help version"
_rzp2_global_opts="-h --help -V --version"

_rzp2_compress_opts="-o --output -e --encrypt --public-key --key --params --password --level --dict-size --checksum --include --exclude --threads --block-size --dry-run -h --help"
_rzp2_decompress_opts="-o --output --private-key --key --password --key-password --entry --dry-run -h --help"
_rzp2_keygen_opts="--params --public --public-key --private --private-key --private-password -h --help"
_rzp2_list_opts="--private-key --key --password --key-password -l --long --human-readable -h --help"
_rzp2_test_opts="--private-key --key --password --key-password -h --help"
_rzp2_info_opts="-h --help"
_rzp2_sfx_opts="-o --output -f --force -h --help"
_rzp2_split_opts="-o --output --chunk-size --dry-run -f --force -h --help"
_rzp2_merge_opts="-o --output --dry-run -f --force -h --help"

_rzp2_is_file_opt() {
    case "$1" in
        -o|--output|--public-key|--key|--private-key|--public|--private) return 0 ;;
        *) return 1 ;;
    esac
}

_rzp2_complete_opts() {
    local opts="$1" files
    case "$prev" in
        --params) COMPREPLY=( $(compgen -W "mlkem512 mlkem768 mlkem1024" -- "$cur") ); return ;;
        --level)  COMPREPLY=( $(compgen -W "0 1 2 3 4 5 6 7 8 9" -- "$cur") ); return ;;
        --password|--key-password|--dict-size|--include|--exclude|--threads|--block-size|--entry|--chunk-size) COMPREPLY=(); return ;;
    esac
    if _rzp2_is_file_opt "$prev"; then
        COMPREPLY=( $(compgen -f -- "$cur") )
        return
    fi
    COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
    # 未输入 `-` 时，同时提供文件补全，便于补全位置参数（输入/输出路径）。
    if [[ "$cur" != -* ]]; then
        files=( $(compgen -f -- "$cur") )
        COMPREPLY+=( "${files[@]}" )
    fi
}

_rzp2() {
    local cur prev sub i
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    sub=""

    for ((i=1; i < COMP_CWORD; i++)); do
        case "${COMP_WORDS[i]}" in
            -*) continue ;;
            *) sub="${COMP_WORDS[i]}"; break ;;
        esac
    done

    case "$sub" in
        compress|c)         _rzp2_complete_opts "$_rzp2_compress_opts" ;;
        decompress|d|x)     _rzp2_complete_opts "$_rzp2_decompress_opts" ;;
        keygen|k)           _rzp2_complete_opts "$_rzp2_keygen_opts" ;;
        list|l)             _rzp2_complete_opts "$_rzp2_list_opts" ;;
        test|t)             _rzp2_complete_opts "$_rzp2_test_opts" ;;
        info|i)             _rzp2_complete_opts "$_rzp2_info_opts" ;;
        sfx)                _rzp2_complete_opts "$_rzp2_sfx_opts" ;;
        split)              _rzp2_complete_opts "$_rzp2_split_opts" ;;
        merge)              _rzp2_complete_opts "$_rzp2_merge_opts" ;;
        help|version)       COMPREPLY=() ;;
        "")
            COMPREPLY=( $(compgen -W "$_rzp2_subcommands $_rzp2_global_opts" -- "$cur") )
            ;;
        *) COMPREPLY=() ;;
    esac
}

complete -o default -F _rzp2 rzp2
"#;

/// zsh 补全脚本（`#compdef rzp2` 约定，供 `compinit` 自动加载）。
const ZSH: &str = r#"#compdef rzp2

_rzp2() {
  local -a commands
  commands=(
    'compress:压缩（可选加密）为 .rzp2 容器'
    'decompress:解压（可选解密）.rzp2 容器'
    'keygen:生成 ML-KEM 长期公私钥对'
    'list:列出归档条目'
    'test:校验容器完整性'
    'info:查看容器元信息'
    'sfx:生成自解压可执行文件'
    'split:把文件切成多个分片'
    'merge:把分片合并回原文件'
    'help:显示帮助'
    'version:显示版本'
  )

  local context state line
  typeset -A opt_args

  _arguments -C \
    '(-h --help)'{-h,--help}'[显示帮助]' \
    '(-V --version)'{-V,--version}'[显示版本]' \
    '1:子命令:->subcmd' \
    '*::参数:->args'

  case "$state" in
    subcmd)
      _describe -t commands '子命令' commands
      ;;
    args)
      case "${words[2]}" in
        compress|c)
          _arguments \
            '(-o --output)'{-o,--output}'[输出文件]:文件:_files' \
            '(-e --encrypt)'{-e,--encrypt}'[使用 ML-KEM 混合加密]' \
            '--public-key[接收方公钥（可重复）]:文件:_files' \
            '--key[接收方公钥（可重复）]:文件:_files' \
            '--params[ML-KEM 参数集]:(mlkem512 mlkem768 mlkem1024)' \
            '--password[口令]' \
            '--level[压缩级别]:(0 1 2 3 4 5 6 7 8 9)' \
            '--dict-size[字典大小]' \
            '--checksum[附加校验和]' \
            '--include[仅打包匹配路径]' \
            '--exclude[排除匹配路径]' \
            '--threads[并行线程数]' \
            '--block-size[分块大小]' \
            '--dry-run[只打印将执行的动作]' \
            '(-h --help)'{-h,--help}'[显示帮助]'
          ;;
        decompress|d|x)
          _arguments \
            '(-o --output)'{-o,--output}'[输出文件或目录]:文件:_files' \
            '--private-key[接收方私钥]:文件:_files' \
            '--key[接收方私钥]:文件:_files' \
            '--password[口令]' \
            '--key-password[私钥文件口令]' \
            '--entry[仅从归档抽取单个条目]' \
            '--dry-run[只打印将执行的动作]' \
            '(-h --help)'{-h,--help}'[显示帮助]'
          ;;
        keygen|k)
          _arguments \
            '--params[ML-KEM 参数集]:(mlkem512 mlkem768 mlkem1024)' \
            '--public[公钥输出路径]:文件:_files' \
            '--public-key[公钥输出路径]:文件:_files' \
            '--private[私钥输出路径]:文件:_files' \
            '--private-key[私钥输出路径]:文件:_files' \
            '--private-password[口令加密私钥]' \
            '(-h --help)'{-h,--help}'[显示帮助]'
          ;;
        list|l)
          _arguments \
            '--private-key[接收方私钥]:文件:_files' \
            '--key[接收方私钥]:文件:_files' \
            '--password[口令]' \
            '--key-password[私钥文件口令]' \
            '(-l --long)'{-l,--long}'[长格式]' \
            '--human-readable[以可读单位显示大小]' \
            '(-h --help)'{-h,--help}'[显示帮助]'
          ;;
        test|t)
          _arguments \
            '--private-key[接收方私钥]:文件:_files' \
            '--key[接收方私钥]:文件:_files' \
            '--password[口令]' \
            '--key-password[私钥文件口令]' \
            '(-h --help)'{-h,--help}'[显示帮助]'
          ;;
        info|i)
          _arguments \
            '(-h --help)'{-h,--help}'[显示帮助]'
          ;;
        sfx)
          _arguments \
            '(-o --output)'{-o,--output}'[输出自解压可执行文件]:文件:_files' \
            '(-f --force --overwrite)'{-f,--force,--overwrite}'[覆盖已存在的输出]' \
            '(-h --help)'{-h,--help}'[显示帮助]'
          ;;
        split)
          _arguments \
            '(-o --output)'{-o,--output}'[分片输出前缀]:文件:_files' \
            '--chunk-size[每个分片大小]' \
            '--dry-run[只打印将执行的动作]' \
            '(-f --force --overwrite)'{-f,--force,--overwrite}'[覆盖已存在的分片/清单]' \
            '(-h --help)'{-h,--help}'[显示帮助]'
          ;;
        merge)
          _arguments \
            '(-o --output)'{-o,--output}'[输出文件]:文件:_files' \
            '--dry-run[只打印将执行的动作]' \
            '(-f --force --overwrite)'{-f,--force,--overwrite}'[覆盖已存在的输出]' \
            '(-h --help)'{-h,--help}'[显示帮助]'
          ;;
      esac
      ;;
  esac
}

_rzp2 "$@"
"#;

/// fish 补全脚本。
const FISH: &str = r#"# fish completion for rzp2

complete -c rzp2 -f
complete -c rzp2 -s h -l help -d '显示帮助'
complete -c rzp2 -s V -l version -d '显示版本'

complete -c rzp2 -n '__fish_use_subcommand' -a compress -d '压缩（可选加密）为 .rzp2 容器'
complete -c rzp2 -n '__fish_use_subcommand' -a decompress -d '解压（可选解密）.rzp2 容器'
complete -c rzp2 -n '__fish_use_subcommand' -a keygen -d '生成 ML-KEM 长期公私钥对'
complete -c rzp2 -n '__fish_use_subcommand' -a list -d '列出归档条目'
complete -c rzp2 -n '__fish_use_subcommand' -a test -d '校验容器完整性'
complete -c rzp2 -n '__fish_use_subcommand' -a info -d '查看容器元信息'
complete -c rzp2 -n '__fish_use_subcommand' -a sfx -d '生成自解压可执行文件'
complete -c rzp2 -n '__fish_use_subcommand' -a split -d '把文件切成多个分片'
complete -c rzp2 -n '__fish_use_subcommand' -a merge -d '把分片合并回原文件'
complete -c rzp2 -n '__fish_use_subcommand' -a help -d '显示帮助'
complete -c rzp2 -n '__fish_use_subcommand' -a version -d '显示版本'

# compress
complete -c rzp2 -n '__fish_seen_subcommand_from compress c' -s o -l output -r -d '输出文件'
complete -c rzp2 -n '__fish_seen_subcommand_from compress c' -s e -l encrypt -d '使用 ML-KEM 混合加密'
complete -c rzp2 -n '__fish_seen_subcommand_from compress c' -l public-key -r -d '接收方公钥'
complete -c rzp2 -n '__fish_seen_subcommand_from compress c' -l key -r -d '接收方公钥'
complete -c rzp2 -n '__fish_seen_subcommand_from compress c' -l params -x -a 'mlkem512 mlkem768 mlkem1024' -d 'ML-KEM 参数集'
complete -c rzp2 -n '__fish_seen_subcommand_from compress c' -l password -x -d '口令'
complete -c rzp2 -n '__fish_seen_subcommand_from compress c' -l level -x -a '0 1 2 3 4 5 6 7 8 9' -d '压缩级别'
complete -c rzp2 -n '__fish_seen_subcommand_from compress c' -l dict-size -x -d '字典大小'
complete -c rzp2 -n '__fish_seen_subcommand_from compress c' -l checksum -d '附加校验和'
complete -c rzp2 -n '__fish_seen_subcommand_from compress c' -l include -x -d '仅打包匹配路径'
complete -c rzp2 -n '__fish_seen_subcommand_from compress c' -l exclude -x -d '排除匹配路径'
complete -c rzp2 -n '__fish_seen_subcommand_from compress c' -l threads -x -d '并行线程数'
complete -c rzp2 -n '__fish_seen_subcommand_from compress c' -l block-size -x -d '分块大小'
complete -c rzp2 -n '__fish_seen_subcommand_from compress c' -l dry-run -d '只打印将执行的动作'
complete -c rzp2 -n '__fish_seen_subcommand_from compress c' -s h -l help -d '显示帮助'

# decompress
complete -c rzp2 -n '__fish_seen_subcommand_from decompress d x' -s o -l output -r -d '输出文件或目录'
complete -c rzp2 -n '__fish_seen_subcommand_from decompress d x' -l private-key -r -d '接收方私钥'
complete -c rzp2 -n '__fish_seen_subcommand_from decompress d x' -l key -r -d '接收方私钥'
complete -c rzp2 -n '__fish_seen_subcommand_from decompress d x' -l password -x -d '口令'
complete -c rzp2 -n '__fish_seen_subcommand_from decompress d x' -l key-password -x -d '私钥文件口令'
complete -c rzp2 -n '__fish_seen_subcommand_from decompress d x' -l entry -x -d '仅从归档抽取单个条目'
complete -c rzp2 -n '__fish_seen_subcommand_from decompress d x' -l dry-run -d '只打印将执行的动作'
complete -c rzp2 -n '__fish_seen_subcommand_from decompress d x' -s h -l help -d '显示帮助'

# keygen
complete -c rzp2 -n '__fish_seen_subcommand_from keygen k' -l params -x -a 'mlkem512 mlkem768 mlkem1024' -d 'ML-KEM 参数集'
complete -c rzp2 -n '__fish_seen_subcommand_from keygen k' -l public -r -d '公钥输出路径'
complete -c rzp2 -n '__fish_seen_subcommand_from keygen k' -l public-key -r -d '公钥输出路径'
complete -c rzp2 -n '__fish_seen_subcommand_from keygen k' -l private -r -d '私钥输出路径'
complete -c rzp2 -n '__fish_seen_subcommand_from keygen k' -l private-key -r -d '私钥输出路径'
complete -c rzp2 -n '__fish_seen_subcommand_from keygen k' -l private-password -x -d '口令加密私钥'
complete -c rzp2 -n '__fish_seen_subcommand_from keygen k' -s h -l help -d '显示帮助'

# list
complete -c rzp2 -n '__fish_seen_subcommand_from list l' -l private-key -r -d '接收方私钥'
complete -c rzp2 -n '__fish_seen_subcommand_from list l' -l key -r -d '接收方私钥'
complete -c rzp2 -n '__fish_seen_subcommand_from list l' -l password -x -d '口令'
complete -c rzp2 -n '__fish_seen_subcommand_from list l' -l key-password -x -d '私钥文件口令'
complete -c rzp2 -n '__fish_seen_subcommand_from list l' -s l -l long -d '长格式'
complete -c rzp2 -n '__fish_seen_subcommand_from list l' -l human-readable -d '以可读单位显示大小'
complete -c rzp2 -n '__fish_seen_subcommand_from list l' -s h -l help -d '显示帮助'

# test
complete -c rzp2 -n '__fish_seen_subcommand_from test t' -l private-key -r -d '接收方私钥'
complete -c rzp2 -n '__fish_seen_subcommand_from test t' -l key -r -d '接收方私钥'
complete -c rzp2 -n '__fish_seen_subcommand_from test t' -l password -x -d '口令'
complete -c rzp2 -n '__fish_seen_subcommand_from test t' -l key-password -x -d '私钥文件口令'
complete -c rzp2 -n '__fish_seen_subcommand_from test t' -s h -l help -d '显示帮助'

# info
complete -c rzp2 -n '__fish_seen_subcommand_from info i' -s h -l help -d '显示帮助'

# sfx
complete -c rzp2 -n '__fish_seen_subcommand_from sfx' -s o -l output -r -d '输出自解压可执行文件'
complete -c rzp2 -n '__fish_seen_subcommand_from sfx' -s f -l force -d '覆盖已存在的输出'
complete -c rzp2 -n '__fish_seen_subcommand_from sfx' -s h -l help -d '显示帮助'

# split
complete -c rzp2 -n '__fish_seen_subcommand_from split' -s o -l output -r -d '分片输出前缀'
complete -c rzp2 -n '__fish_seen_subcommand_from split' -l chunk-size -x -d '每个分片大小'
complete -c rzp2 -n '__fish_seen_subcommand_from split' -l dry-run -d '只打印将执行的动作'
complete -c rzp2 -n '__fish_seen_subcommand_from split' -s f -l force -d '覆盖已存在的分片/清单'
complete -c rzp2 -n '__fish_seen_subcommand_from split' -s h -l help -d '显示帮助'

# merge
complete -c rzp2 -n '__fish_seen_subcommand_from merge' -s o -l output -r -d '输出文件'
complete -c rzp2 -n '__fish_seen_subcommand_from merge' -l dry-run -d '只打印将执行的动作'
complete -c rzp2 -n '__fish_seen_subcommand_from merge' -s f -l force -d '覆盖已存在的输出'
complete -c rzp2 -n '__fish_seen_subcommand_from merge' -s h -l help -d '显示帮助'
"#;

/// PowerShell 补全脚本（`Register-ArgumentCompleter`，兼容 Windows PowerShell 与 pwsh）。
/// 补全子命令（含短别名前缀）、各子命令选项，以及 `--params` / `--level` 取值和文件路径。
const POWERSHELL: &str = r#"# PowerShell tab completion for rzp2

function _rzp2_Files($prefix) {
    $dir = Split-Path -Parent $prefix
    $leaf = Split-Path -Leaf $prefix
    if (-not $dir) { $dir = '.' }
    if (-not $leaf) { $leaf = '' }
    Get-ChildItem -LiteralPath $dir -ErrorAction SilentlyContinue |
        Where-Object { $_.Name.StartsWith($leaf, [System.StringComparison]::OrdinalIgnoreCase) } |
        ForEach-Object {
            $name = $_.Name
            if ($_.PSIsContainer) { $name += '\' }
            if ($dir -eq '.') { $name } else { Join-Path $dir $name }
        }
}

Register-ArgumentCompleter -Native -CommandName rzp2 -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $subcommands = 'compress decompress keygen list test info sfx split merge help version'.Split(' ')
    $globalOpts = @('-h', '--help', '-V', '--version')
    $fileOpts = @('-o', '--output', '--public-key', '--key', '--private-key', '--public', '--private')

    $optionSpecs = @{
        'compress'   = '-o --output -e --encrypt --public-key --key --params --password --level --dict-size --checksum --include --exclude --threads --block-size --dry-run -h --help'
        'c'          = '-o --output -e --encrypt --public-key --key --params --password --level --dict-size --checksum --include --exclude --threads --block-size --dry-run -h --help'
        'decompress' = '-o --output --private-key --key --password --key-password --entry --dry-run -h --help'
        'd'          = '-o --output --private-key --key --password --key-password --entry --dry-run -h --help'
        'x'          = '-o --output --private-key --key --password --key-password --entry --dry-run -h --help'
        'keygen'     = '--params --public --public-key --private --private-key --private-password -h --help'
        'k'          = '--params --public --public-key --private --private-key --private-password -h --help'
        'list'       = '--private-key --key --password --key-password -l --long --human-readable -h --help'
        'l'          = '--private-key --key --password --key-password -l --long --human-readable -h --help'
        'test'       = '--private-key --key --password --key-password -h --help'
        't'          = '--private-key --key --password --key-password -h --help'
        'info'       = '-h --help'
        'i'          = '-h --help'
        'sfx'        = '-o --output -f --force -h --help'
        'split'      = '-o --output --chunk-size --dry-run -f --force -h --help'
        'merge'      = '-o --output --dry-run -f --force -h --help'
    }

    # 光标前已输入的 token；[0] 为命令名 rzp2，其余为参数。
    $text = $commandAst.Extent.Text
    $before = $text.Substring(0, [Math]::Min($cursorPosition, $text.Length))
    $words = @($before.TrimStart() -split '\s+' | Where-Object { $_ -ne '' })
    $rest = @()
    if ($words.Count -gt 1) { $rest = @($words[1..($words.Count - 1)]) }

    # 正在输入的部分单词不算“已选定”，据此区分补全子命令还是子命令选项。
    $completeArgs = @()
    if ($before.EndsWith(' ')) { $completeArgs = $rest }
    elseif ($rest.Count -gt 1) { $completeArgs = @($rest[0..($rest.Count - 2)]) }

    $sub = $null
    foreach ($a in $completeArgs) {
        if ($a -notmatch '^-') { $sub = $a; break }
    }

    if ($null -eq $sub) {
        return @($subcommands + $globalOpts) |
            Where-Object { $_.ToString().StartsWith($wordToComplete, [System.StringComparison]::OrdinalIgnoreCase) }
    }

    $opts = $optionSpecs[$sub]
    if ($null -eq $opts) { return }

    $prev = if ($completeArgs.Count -ge 1) { $completeArgs[-1] } else { '' }
    switch ($prev) {
        '--params' {
            return 'mlkem512', 'mlkem768', 'mlkem1024' |
                Where-Object { $_.ToString().StartsWith($wordToComplete, [System.StringComparison]::OrdinalIgnoreCase) }
        }
        '--level' {
            return '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' |
                Where-Object { $_.ToString().StartsWith($wordToComplete, [System.StringComparison]::OrdinalIgnoreCase) }
        }
        { $fileOpts -contains $_ } {
            return _rzp2_Files $wordToComplete
        }
    }

    $result = @($opts.Split(' ') |
        Where-Object { $_.ToString().StartsWith($wordToComplete, [System.StringComparison]::OrdinalIgnoreCase) })
    if ($wordToComplete -notmatch '^-') {
        $result += _rzp2_Files $wordToComplete
    }
    return $result
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_known_shells() {
        for shell in ["bash", "zsh", "fish", "powershell", "pwsh"] {
            assert!(!render(shell).unwrap().is_empty());
        }
    }

    #[test]
    fn render_unknown_shell() {
        assert!(render("cmd").is_err());
    }

    #[test]
    fn bash_script_registers_function() {
        let s = render("bash").unwrap();
        assert!(s.contains("complete -o default -F _rzp2 rzp2"));
    }

    #[test]
    fn powershell_script_registers_completer() {
        let s = render("powershell").unwrap();
        assert!(s.contains("Register-ArgumentCompleter -Native -CommandName rzp2"));
    }
}
