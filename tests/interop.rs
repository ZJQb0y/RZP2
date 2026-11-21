//! 与系统 `gzip` / `tar` 工具的交叉互操作测试。
//!
//! 这些测试仅在相应系统工具存在时运行，用于验证自研内核与标准实现的一致性。

use std::io::Write;
use std::process::{Command, Stdio};

use rzp2::bzip2;
use rzp2::filters::Filter;
use rzp2::gzip;
use rzp2::sevenz;
use rzp2::tar;
use rzp2::zip;

/// 检查命令是否可用。
fn have_tool(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// 用系统 `gzip -c` 压缩一段数据。
fn gzip_compress(data: &[u8]) -> Option<Vec<u8>> {
    let mut child = Command::new("gzip")
        .arg("-c")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(data).ok()?;
    let out = child.wait_with_output().ok()?;
    out.status.success().then_some(out.stdout)
}

/// 用系统 `tar` 打包一组相对路径，返回 tar 字节流。
fn tar_create(files: &[(&str, &[u8])]) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join(format!("rzp2_interop_{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    for (path, content) in files {
        let p = dir.join(path);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).ok()?;
        }
        std::fs::write(&p, content).ok()?;
    }
    let child = Command::new("tar")
        .arg("-cf")
        .arg("-")
        .arg("-C")
        .arg(&dir)
        .args(files.iter().map(|(p, _)| *p))
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    let out = child.wait_with_output().ok()?;
    std::fs::remove_dir_all(&dir).ok()?;
    out.status.success().then_some(out.stdout)
}

/// 用系统 `bzip2 -c` 压缩一段数据。
fn bzip2_compress(data: &[u8]) -> Option<Vec<u8>> {
    let mut child = Command::new("bzip2")
        .arg("-c")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(data).ok()?;
    let out = child.wait_with_output().ok()?;
    out.status.success().then_some(out.stdout)
}

#[test]
fn gzip_roundtrip_system() {
    if !have_tool("gzip") {
        eprintln!("skipping: gzip not available");
        return;
    }
    let data = b"The quick brown fox jumps over the lazy dog. 0123456789\n".repeat(100);
    let compressed = gzip_compress(&data).expect("gzip -c failed");
    assert_eq!(gzip::decode(&compressed).unwrap(), data);
}

#[test]
fn deflate_recompress_roundtrip_system() {
    if !have_tool("gzip") {
        eprintln!("skipping: gzip not available");
        return;
    }
    // 重复数据使 gzip 产生长度-距离匹配与动态 Huffman 表，覆盖重压缩的各路径。
    let data = b"The quick brown fox jumps over the lazy dog. 0123456789\n".repeat(500);
    let gz = gzip_compress(&data).expect("gzip -c failed");

    let f = Filter::Deflate;
    let packed = f.encode(&gz);
    assert_ne!(packed, gz, "重压缩应产生不同表示");
    let rebuilt = f.decode(&packed);
    assert_eq!(rebuilt, gz, "重压缩往返应逐位还原原始 gzip");
    assert_eq!(gzip::decode(&rebuilt).unwrap(), data);
}

#[test]
fn tar_roundtrip_system() {
    if !have_tool("tar") {
        eprintln!("skipping: tar not available");
        return;
    }
    let files: Vec<(&str, &[u8])> = vec![
        ("hello.txt", b"hello tar"),
        ("sub/nested.txt", b"nested content"),
        ("empty.txt", b""),
    ];
    let bytes = tar_create(&files).expect("tar -cf failed");
    let entries = tar::decode(&bytes).unwrap();

    let mut got: Vec<(String, Vec<u8>)> = entries
        .iter()
        .filter(|e| e.kind == rzp2::archive::EntryKind::File)
        .map(|e| (e.path.clone(), e.data.clone()))
        .collect();
    got.sort();

    let mut want: Vec<(String, Vec<u8>)> = files
        .iter()
        .map(|(p, c)| (p.to_string(), c.to_vec()))
        .collect();
    want.sort();

    assert_eq!(got, want);
}

#[test]
fn bzip2_roundtrip_system() {
    if !have_tool("bzip2") {
        eprintln!("skipping: bzip2 not available");
        return;
    }
    // 覆盖多字节与长游程，验证 MTF / RLE / BWT / Huffman 各阶段。
    let data = b"The quick brown fox jumps over the lazy dog. 0123456789\n".repeat(500);
    let compressed = bzip2_compress(&data).expect("bzip2 -c failed");
    assert_eq!(bzip2::decode(&compressed).unwrap(), data);
}

#[test]
fn zip_roundtrip_system() {
    if !have_tool("zip") {
        eprintln!("skipping: zip not available");
        return;
    }
    let dir = std::env::temp_dir().join(format!("rzp2_zip_{}", std::process::id()));
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("a.txt"), b"zip alpha").unwrap();
    std::fs::write(dir.join("sub/b.txt"), b"zip beta").unwrap();

    let out = Command::new("zip")
        .arg("-q")
        .arg("-r")
        .arg("-")
        .arg(".")
        .current_dir(&dir)
        .output()
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(out.status.success());

    let entries = zip::decode(&out.stdout).unwrap();
    let mut got: Vec<(String, Vec<u8>)> = entries
        .iter()
        .filter(|e| e.kind == rzp2::archive::EntryKind::File)
        .map(|e| (e.path.clone(), e.data.clone()))
        .collect();
    got.sort();
    assert_eq!(
        got,
        vec![
            ("a.txt".to_string(), b"zip alpha".to_vec()),
            ("sub/b.txt".to_string(), b"zip beta".to_vec()),
        ]
    );
}

#[test]
fn sevenz_roundtrip_system() {
    if !have_tool("7z") {
        eprintln!("skipping: 7z not available");
        return;
    }
    let dir = std::env::temp_dir().join(format!("rzp2_7z_{}", std::process::id()));
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::create_dir_all(dir.join("empty_dir")).unwrap();
    std::fs::write(dir.join("a.txt"), b"7z alpha").unwrap();
    std::fs::write(dir.join("sub/b.txt"), b"7z beta").unwrap();
    std::fs::write(dir.join("sub/empty.txt"), b"").unwrap();

    let archive = dir.with_extension("7z");
    let out = Command::new("7z")
        .arg("a")
        .arg("-t7z")
        .arg("-bso0")
        .arg("-bsp0")
        .arg(&archive)
        .arg("a.txt")
        .arg("sub")
        .arg("empty_dir")
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "7z a failed: {:?}", out);

    let entries = sevenz::decode(&std::fs::read(&archive).unwrap()).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_file(&archive).unwrap();

    let mut got: Vec<(String, Vec<u8>)> = entries
        .iter()
        .filter(|e| e.kind == rzp2::archive::EntryKind::File)
        .map(|e| (e.path.clone(), e.data.clone()))
        .collect();
    got.sort();
    assert_eq!(
        got,
        vec![
            ("a.txt".to_string(), b"7z alpha".to_vec()),
            ("sub/b.txt".to_string(), b"7z beta".to_vec()),
            ("sub/empty.txt".to_string(), b"".to_vec()),
        ]
    );
}

#[test]
fn jpeg_recompress_roundtrip_system() {
    let cmd = if have_tool("convert") {
        "convert"
    } else if have_tool("magick") {
        "magick"
    } else {
        eprintln!("skipping: imagemagick not available");
        return;
    };

    // 构造小型灰度 PGM（P5），再经 ImageMagick 转成 baseline JPEG。
    let (w, h) = (32usize, 32usize);
    let mut pgm = Vec::new();
    write!(&mut pgm, "P5\n{} {}\n255\n", w, h).unwrap();
    for y in 0..h {
        for x in 0..w {
            pgm.push(((x * 7 + y * 13) % 256) as u8);
        }
    }

    let mut child = Command::new(cmd)
        .arg("pgm:-")
        .arg("-interlace")
        .arg("none")
        .arg("-quality")
        .arg("90")
        .arg("jpg:-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn imagemagick failed");
    child.stdin.take().unwrap().write_all(&pgm).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "imagemagick 转 JPEG 失败: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let jpg = out.stdout;
    assert!(jpg.starts_with(&[0xFF, 0xD8]), "应生成 JPEG 字节流");

    let f = Filter::Jpeg;
    let packed = f.encode(&jpg);
    assert_ne!(packed, jpg, "JPEG 重压缩应生效而非回退原字节");
    let rebuilt = f.decode(&packed);
    assert_eq!(rebuilt, jpg, "JPEG 重压缩往返应逐位还原原始 JPEG");
}
