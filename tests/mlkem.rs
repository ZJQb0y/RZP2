//! ML-KEM 测试：往返、FO 隐式拒绝与 NIST 官方 ACVP KAT 字节级校验。

use rzp2::mlkem::{
    decaps, encaps, encaps_derand, keygen, keygen_derand, params_from_name, Params, MLKEM1024,
    MLKEM512, MLKEM768,
};

fn hex_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn roundtrip_all_params() {
    for p in [MLKEM512, MLKEM768, MLKEM1024] {
        let (pk, sk) = keygen(&p);
        let (ct, ss1) = encaps(&p, &pk);
        let ss2 = decaps(&p, &sk, &ct);
        assert_eq!(ss1, ss2, "roundtrip failed for {}", p.name());
    }
}

#[test]
fn implicit_rejection() {
    for p in [MLKEM512, MLKEM768, MLKEM1024] {
        let (pk, sk) = keygen(&p);
        let (mut ct, ss1) = encaps(&p, &pk);
        // 篡改密文：解封装应返回隐式拒绝密钥（不等于 ss1），且不 panic。
        ct[0] ^= 0x5A;
        let ss2 = decaps(&p, &sk, &ct);
        assert_ne!(ss1, ss2, "implicit rejection failed for {}", p.name());
    }
}

#[test]
fn sizes_are_correct() {
    assert_eq!(MLKEM512.public_key_bytes, 800);
    assert_eq!(MLKEM512.secret_key_bytes, 1632);
    assert_eq!(MLKEM512.ciphertext_bytes, 768);
    assert_eq!(MLKEM768.public_key_bytes, 1184);
    assert_eq!(MLKEM768.secret_key_bytes, 2400);
    assert_eq!(MLKEM768.ciphertext_bytes, 1088);
    assert_eq!(MLKEM1024.public_key_bytes, 1568);
    assert_eq!(MLKEM1024.secret_key_bytes, 3168);
    assert_eq!(MLKEM1024.ciphertext_bytes, 1568);
}

// ---------------------------------------------------------------------------
// NIST ACVP KAT（FIPS 203 官方测试向量）
// ---------------------------------------------------------------------------

fn load_json(name: &str) -> serde_json::Value {
    let path = format!("{}/tests/kat/{}", env!("CARGO_MANIFEST_DIR"), name);
    let data = std::fs::read_to_string(path).unwrap();
    serde_json::from_str(&data).unwrap()
}

fn param_from_set_name(s: &str) -> Params {
    params_from_name(s).unwrap_or_else(|| panic!("unknown parameter set {s}"))
}

#[test]
fn kat_keygen() {
    let v = load_json("key-gen.json");
    let mut checked = 0usize;
    for group in v["testGroups"].as_array().unwrap() {
        let p = param_from_set_name(group["parameterSet"].as_str().unwrap());
        for test in group["tests"].as_array().unwrap() {
            let d = hex_decode(test["d"].as_str().unwrap());
            let z = hex_decode(test["z"].as_str().unwrap());
            let ek = hex_decode(test["ek"].as_str().unwrap());
            let dk = hex_decode(test["dk"].as_str().unwrap());

            assert_eq!(d.len(), 32);
            assert_eq!(z.len(), 32);
            let mut coins = [0u8; 64];
            coins[..32].copy_from_slice(&d);
            coins[32..].copy_from_slice(&z);

            let (pk, sk) = keygen_derand(&p, &coins);
            assert_eq!(pk, ek, "pk mismatch for {} tc {}", p.name(), test["tcId"]);
            assert_eq!(sk, dk, "sk mismatch for {} tc {}", p.name(), test["tcId"]);
            checked += 1;
        }
    }
    assert_eq!(checked, 75, "expected 75 keygen KAT cases");
}

#[test]
fn kat_encap_decap() {
    let v = load_json("encap-decap.json");
    let mut checked = 0usize;
    for group in v["testGroups"].as_array().unwrap() {
        let p = param_from_set_name(group["parameterSet"].as_str().unwrap());
        for test in group["tests"].as_array().unwrap() {
            // 只校验 AFT 正向量（含 ek/dk/m）；VAL 组（modify ciphertext）缺少 ek/dk 无法独立复现。
            if test.get("m").is_none() {
                continue;
            }
            let ek = hex_decode(test["ek"].as_str().unwrap());
            let dk = hex_decode(test["dk"].as_str().unwrap());
            let m = hex_decode(test["m"].as_str().unwrap());
            let c = hex_decode(test["c"].as_str().unwrap());
            let k = hex_decode(test["k"].as_str().unwrap());

            assert_eq!(m.len(), 32);
            let mut coins = [0u8; 32];
            coins.copy_from_slice(&m);

            let (ct, ss) = encaps_derand(&p, &ek, &coins);
            assert_eq!(ct, c, "ct mismatch for {} tc {}", p.name(), test["tcId"]);
            assert_eq!(ss, k, "ss mismatch for {} tc {}", p.name(), test["tcId"]);

            let ss2 = decaps(&p, &dk, &c);
            assert_eq!(
                ss2,
                k,
                "decaps mismatch for {} tc {}",
                p.name(),
                test["tcId"]
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 75, "expected 75 encap/decap KAT cases");
}
