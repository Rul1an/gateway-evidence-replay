use std::fs;
use std::path::Path;

use gateway_evidence_replay::pack::replay_pack_dir;
use serde_json::Value;
use sha2::{Digest, Sha256};

const DEMO_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/gateway-path-v0/demo");
const DEMO_FILES: &[&str] = &[
    "README.md",
    "clean-route.json",
    "partial-route-substitution.json",
    "stale-attestation.json",
    "unknown-source.json",
    "expected.json",
    "manifest.json",
    "manifest-sha256.txt",
];

#[test]
fn demo_manifest_pins_fixture_and_expected_bytes() {
    replay_pack_dir(Path::new(DEMO_DIR)).expect("demo manifest verifies");
}

#[test]
fn fixture_tamper_fails_manifest_check() {
    let temp = copy_demo_dir();
    fs::write(temp.path().join("clean-route.json"), "{}\n").expect("tamper fixture");

    let err = replay_pack_dir(temp.path()).expect_err("fixture tamper must fail");
    assert!(err.to_string().contains("clean-route.json"), "{err}");
}

#[test]
fn expected_tamper_fails_manifest_check() {
    let temp = copy_demo_dir();
    fs::write(temp.path().join("expected.json"), "{}\n").expect("tamper expected");

    let err = replay_pack_dir(temp.path()).expect_err("expected tamper must fail");
    assert!(err.to_string().contains("expected.json"), "{err}");
}

#[test]
fn manifest_tamper_fails_manifest_sha_check() {
    let temp = copy_demo_dir();
    let manifest_path = temp.path().join("manifest.json");
    let mut manifest: Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["claims"] = Value::String("externally_reproduced".to_string());
    write_json(&manifest_path, &manifest);

    let err = replay_pack_dir(temp.path()).expect_err("manifest tamper must fail");
    assert!(err.to_string().contains("manifest.json"), "{err}");
}

#[test]
fn replay_mismatch_fails_after_digest_gate_passes() {
    let temp = copy_demo_dir();
    let expected_path = temp.path().join("expected.json");
    let manifest_path = temp.path().join("manifest.json");
    let manifest_sha_path = temp.path().join("manifest-sha256.txt");

    let mut expected: Value =
        serde_json::from_str(&fs::read_to_string(&expected_path).unwrap()).unwrap();
    expected["cases"][0]["status"] = Value::String("invalid".to_string());
    write_json(&expected_path, &expected);

    let mut manifest: Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["expected_sha256"] = Value::String(sha256_file(&expected_path));
    write_json(&manifest_path, &manifest);
    fs::write(
        &manifest_sha_path,
        format!("{}\n", sha256_file(&manifest_path)),
    )
    .unwrap();

    let err = replay_pack_dir(temp.path()).expect_err("replay mismatch must fail");
    assert!(err.to_string().contains("clean-route.json"), "{err}");
}

fn copy_demo_dir() -> tempfile::TempDir {
    let temp = tempfile::tempdir().expect("tempdir");
    for name in DEMO_FILES {
        fs::copy(Path::new(DEMO_DIR).join(name), temp.path().join(name)).expect("copy demo file");
    }
    temp
}

fn write_json(path: &Path, value: &Value) {
    fs::write(
        path,
        format!("{}\n", serde_json::to_string_pretty(value).unwrap()),
    )
    .unwrap();
}

fn sha256_file(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
