//! 自解压（SFX）支持。
//!
//! SFX 可执行文件 = 存根（`rzp2` 自身）+ 追加的 `.rzp2` 载荷 + 尾部 footer。
//! footer 记录载荷长度，避免在全文件里扫描 `RZP2` 魔数造成误命中。
//!
//! 布局（多字节整数小端）：
//!
//! ```text
//! [rzp2 存根字节][.rzp2 载荷][RZP2SFX][payload_len(8, LE)]
//! ```

use std::path::Path;

use crate::archive::decode_archive;
use crate::format::Header;
use crate::pipeline::{unpack, DecryptKey};

/// SFX 尾部标记（与容器魔数 `RZP2` 区分开）。
pub const SFX_MAGIC: [u8; 7] = *b"RZP2SFX";

/// footer 大小：`SFX_MAGIC`(7) + 载荷长度(8, LE)。
const FOOTER_SIZE: usize = SFX_MAGIC.len() + 8;

/// 拼接自解压可执行文件：`存根 + 载荷 + footer`。
pub fn append(stub: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(stub.len() + payload.len() + FOOTER_SIZE);
    out.extend_from_slice(stub);
    out.extend_from_slice(payload);
    out.extend_from_slice(&SFX_MAGIC);
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out
}

/// 在自解压二进制末尾定位追加的载荷，返回 `(偏移, 长度)`；非 SFX 返回 `None`。
pub fn locate(data: &[u8]) -> Option<(usize, usize)> {
    if data.len() < FOOTER_SIZE {
        return None;
    }
    let footer = &data[data.len() - FOOTER_SIZE..];
    if !footer.starts_with(&SFX_MAGIC) {
        return None;
    }
    let len = u64::from_le_bytes(footer[SFX_MAGIC.len()..].try_into().ok()?) as usize;
    let start = data.len().checked_sub(FOOTER_SIZE + len)?;
    Some((start, len))
}

/// 创建自解压可执行文件：把 `payload_path`（`.rzp2`）追加到 `stub_path`（当前 rzp2），
/// 写入 `output`。返回内嵌的载荷字节数。
pub fn create(
    stub_path: &Path,
    payload_path: &Path,
    output: &Path,
    force: bool,
) -> Result<u64, String> {
    if !force && output.exists() {
        return Err(format!(
            "输出 `{}` 已存在（用 --force 覆盖）",
            output.display()
        ));
    }
    let stub = std::fs::read(stub_path)
        .map_err(|e| format!("读取存根 `{}` 失败: {e}", stub_path.display()))?;
    let payload = std::fs::read(payload_path)
        .map_err(|e| format!("读取 `{}` 失败: {e}", payload_path.display()))?;
    Header::decode(&payload)
        .map_err(|e| format!("`{}` 不是有效的 .rzp2 容器: {e}", payload_path.display()))?;

    let len = payload.len() as u64;
    let sfx = append(&stub, &payload);
    std::fs::write(output, &sfx).map_err(|e| format!("写入 `{}` 失败: {e}", output.display()))?;

    // 让生成的自解压文件可直接执行。
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(output, std::fs::Permissions::from_mode(0o755));
    }
    Ok(len)
}

/// 若当前进程的可执行文件内嵌了自解压载荷，则解压到当前目录并返回退出码；
/// 否则返回 `None`（按普通 CLI 继续分发）。
pub fn try_extract() -> Option<i32> {
    let exe = std::env::current_exe().ok()?;
    let data = std::fs::read(&exe).ok()?;
    let (start, len) = locate(&data)?;
    let payload = data[start..start + len].to_vec();

    let exe_name = exe.file_name()?.to_string_lossy().into_owned();
    // 单文件 SFX 的解出文件名：取可执行文件去扩展名的基名；与自身同名时追加 `.out`。
    let single_name = exe
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| *s != exe_name)
        .unwrap_or_else(|| format!("{exe_name}.out"));

    Some(extract(&payload, &single_name))
}

/// 解压内嵌载荷到当前目录，返回退出码。
fn extract(payload: &[u8], single_name: &str) -> i32 {
    let (header, _) = match Header::decode(payload) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: 解析内嵌容器失败: {e}");
            return 1;
        }
    };

    // 凭据：未加密直接解；口令加密提示输入口令；ML-KEM 加密无法在 SFX 内安全携带私钥。
    let password: Option<String> = if header.password {
        eprint!("口令: ");
        use std::io::Write;
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if let Err(e) = std::io::stdin().read_line(&mut line) {
            eprintln!("error: 读取口令失败: {e}");
            return 1;
        }
        Some(line.trim_end_matches(['\n', '\r']).to_string())
    } else {
        None
    };

    let key: DecryptKey<'_> = if !header.encrypted {
        DecryptKey::None
    } else if header.password {
        DecryptKey::Password(password.as_deref().unwrap().as_bytes())
    } else {
        eprintln!(
            "error: 该自解压容器使用 ML-KEM 公钥加密，请改用 `rzp2 decompress --private-key <file>` 解压"
        );
        return 1;
    };

    let plaintext = match unpack(payload, key) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: 解压失败: {e}");
            return 1;
        }
    };

    if header.archive {
        let entries = match decode_archive(&plaintext) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("error: 解析归档失败: {e}");
                return 1;
            }
        };
        if let Err(e) = crate::cli::extract_archive(&entries, Path::new(".")) {
            eprintln!("error: 解包归档失败: {e}");
            return 1;
        }
        println!("已解包 {} 个条目到当前目录", entries.len());
    } else {
        if let Err(e) = std::fs::write(single_name, &plaintext) {
            eprintln!("error: 写入 `{}` 失败: {e}", single_name);
            return 1;
        }
        println!("已解包到 `{}`（{} 字节）", single_name, plaintext.len());
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_locate_roundtrip() {
        let stub = b"fake executable stub".to_vec();
        let payload = b"fake .rzp2 payload".to_vec();
        let sfx = append(&stub, &payload);
        assert_eq!(&sfx[..stub.len()], stub.as_slice());
        assert_eq!(
            &sfx[stub.len()..stub.len() + payload.len()],
            payload.as_slice()
        );

        let (start, len) = locate(&sfx).unwrap();
        assert_eq!(start, stub.len());
        assert_eq!(len, payload.len());
        assert_eq!(&sfx[start..start + len], payload.as_slice());
    }

    #[test]
    fn locate_rejects_plain_binary() {
        assert!(locate(b"just a normal executable").is_none());
        assert!(locate(b"").is_none());
    }

    #[test]
    fn locate_rejects_truncated_footer() {
        let stub = b"stub";
        let payload = b"payload";
        let mut sfx = append(stub, payload);
        sfx.pop(); // 去掉 footer 最后一个字节
        assert!(locate(&sfx).is_none());
    }
}
