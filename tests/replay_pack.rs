use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gateway_evidence_replay::pack::replay_pack_dir;
use serde_json::Value;
use sha2::Digest;

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
fn cli_replays_digest_pinned_demo_pack_as_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_gateway-evidence-replay"))
        .args(["replay-pack", DEMO_DIR, "--json"])
        .output()
        .expect("run replay-pack");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json report");
    assert_eq!(report["profile"], "gateway-path.v0.replay-pack");
    assert_eq!(report["status"], "passed");
    assert_eq!(report["cases_total"], 4);
    assert_eq!(report["cases_passed"], 4);
    assert_eq!(report["manifest_sha256"], pinned_manifest_sha());
    assert_eq!(report["cases"][0]["file"], "clean-route.json");
    assert_eq!(report["cases"][0]["status"], "path_verified");
}

#[test]
fn replay_pack_rejects_fixture_tamper_before_trusting_replay() {
    let temp = copy_demo_dir();
    fs::write(temp.path().join("clean-route.json"), "{}\n").expect("tamper fixture");

    let err = replay_pack_dir(temp.path()).expect_err("fixture tamper must fail");
    assert!(err.to_string().contains("clean-route.json"), "{err}");
    assert!(err.to_string().contains("digest mismatch"), "{err}");
}

#[test]
fn replay_pack_rejects_manifest_path_traversal() {
    let temp = copy_demo_dir();
    let manifest_path = temp.path().join("manifest.json");
    let manifest_sha_path = temp.path().join("manifest-sha256.txt");

    let mut manifest: Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["fixtures"][0]["file"] = Value::String("../clean-route.json".to_string());
    write_json(&manifest_path, &manifest);
    fs::write(
        &manifest_sha_path,
        format!("{}\n", sha256_file(&manifest_path)),
    )
    .unwrap();

    let err = replay_pack_dir(temp.path()).expect_err("path traversal must fail");
    assert!(err.to_string().contains("unsafe path"), "{err}");
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

fn pinned_manifest_sha() -> String {
    fs::read_to_string(Path::new(DEMO_DIR).join("manifest-sha256.txt"))
        .expect("manifest sha")
        .trim()
        .to_string()
}

fn sha256_file(path: &PathBuf) -> String {
    let bytes = fs::read(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}
