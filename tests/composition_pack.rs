use std::fs;
use std::path::Path;
use std::process::Command;

use gateway_evidence_replay::composition::replay_composition_pack_dir;
use serde_json::Value;
use sha2::Digest;

const CASE_A: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/composition-v0/path-verified-tool-not-verifiable"
);
const CASE_B: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/composition-v0/tool-unchanged-path-mismatch"
);
const CASE_FILES: &[&str] = &[
    "gateway-path.json",
    "tool-surface.json",
    "expected.json",
    "manifest.json",
    "manifest-sha256.txt",
];

#[test]
fn cli_replays_path_verified_tool_not_verifiable_without_whole_action_verdict() {
    let output = Command::new(env!("CARGO_BIN_EXE_gateway-evidence-replay"))
        .args(["replay-composition-pack", CASE_A, "--json"])
        .output()
        .expect("run replay-composition-pack");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json report");
    assert_eq!(report["profile"], "gateway-composition.v0.replay-pack");
    assert_eq!(report["status"], "passed");
    assert_eq!(report["gateway_path"]["status"], "path_verified");
    assert_eq!(report["tool_surface"]["status"], "not_verifiable");
    assert_eq!(report["non_claims"][0], "not_whole_action_trust_score");
    assert!(report.get("whole_action_trusted").is_none());
}

#[test]
fn cli_replays_tool_unchanged_path_mismatch_as_separate_verdicts() {
    let output = Command::new(env!("CARGO_BIN_EXE_gateway-evidence-replay"))
        .args(["replay-composition-pack", CASE_B, "--json"])
        .output()
        .expect("run replay-composition-pack");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("json report");
    assert_eq!(report["gateway_path"]["status"], "path_mismatch");
    assert_eq!(report["gateway_path"]["reasons"][0], "route_substitution");
    assert_eq!(report["tool_surface"]["status"], "unchanged");
}

#[test]
fn composition_pack_rejects_fixture_tamper_before_replay() {
    let temp = copy_case_dir(CASE_A);
    fs::write(temp.path().join("tool-surface.json"), "{}\n").expect("tamper tool record");

    let err = replay_composition_pack_dir(temp.path()).expect_err("fixture tamper must fail");
    assert!(err.to_string().contains("tool-surface.json"), "{err}");
    assert!(err.to_string().contains("digest mismatch"), "{err}");
}

#[test]
fn composition_pack_rejects_context_mismatch() {
    let temp = copy_case_dir(CASE_A);
    let tool_path = temp.path().join("tool-surface.json");
    let manifest_path = temp.path().join("manifest.json");
    let manifest_sha_path = temp.path().join("manifest-sha256.txt");

    let mut tool: Value = serde_json::from_str(&fs::read_to_string(&tool_path).unwrap()).unwrap();
    tool["run_id"] = Value::String("other-run".to_string());
    write_json(&tool_path, &tool);

    let mut manifest: Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["tool_surface_record"]["sha256"] = Value::String(sha256_file(&tool_path));
    write_json(&manifest_path, &manifest);
    fs::write(
        &manifest_sha_path,
        format!("{}\n", sha256_file(&manifest_path)),
    )
    .unwrap();

    let err = replay_composition_pack_dir(temp.path()).expect_err("context mismatch must fail");
    assert!(err.to_string().contains("action_id/run_id"), "{err}");
}

#[test]
fn composition_pack_rejects_manifest_path_traversal() {
    let temp = copy_case_dir(CASE_A);
    let manifest_path = temp.path().join("manifest.json");
    let manifest_sha_path = temp.path().join("manifest-sha256.txt");

    let mut manifest: Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["gateway_record"]["file"] = Value::String("../gateway-path.json".to_string());
    write_json(&manifest_path, &manifest);
    fs::write(
        &manifest_sha_path,
        format!("{}\n", sha256_file(&manifest_path)),
    )
    .unwrap();

    let err = replay_composition_pack_dir(temp.path()).expect_err("path traversal must fail");
    assert!(err.to_string().contains("unsafe path"), "{err}");
}

#[test]
fn composition_pack_error_messages_escape_control_characters() {
    let temp = copy_case_dir(CASE_A);
    let manifest_path = temp.path().join("manifest.json");
    let manifest_sha_path = temp.path().join("manifest-sha256.txt");

    let mut manifest: Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["tool_surface_record"]["file"] = Value::String("\u{1b}]0;owned\u{7}.json".to_string());
    write_json(&manifest_path, &manifest);
    fs::write(
        &manifest_sha_path,
        format!("{}\n", sha256_file(&manifest_path)),
    )
    .unwrap();

    let message = replay_composition_pack_dir(temp.path())
        .expect_err("hostile manifest path must fail")
        .to_string();
    assert!(
        !message.chars().any(char::is_control),
        "raw control character leaked in {message:?}"
    );
    assert!(message.contains("\\u{1b}"), "{message}");
    assert!(message.contains("\\u{7}"), "{message}");
}

#[test]
fn composition_pack_parse_errors_escape_control_characters() {
    let temp = copy_case_dir(CASE_A);
    let manifest_path = temp.path().join("manifest.json");
    let manifest_sha_path = temp.path().join("manifest-sha256.txt");

    let mut manifest: Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["\u{1b}]0;owned\u{7}evil"] = Value::String("hostile".to_string());
    write_json(&manifest_path, &manifest);
    fs::write(
        &manifest_sha_path,
        format!("{}\n", sha256_file(&manifest_path)),
    )
    .unwrap();

    let message = replay_composition_pack_dir(temp.path())
        .expect_err("hostile unknown field must fail")
        .to_string();
    assert!(
        !message.chars().any(char::is_control),
        "raw control character leaked in {message:?}"
    );
    assert!(message.contains("\\u{1b}"), "{message}");
    assert!(message.contains("\\u{7}"), "{message}");
}

fn copy_case_dir(src: &str) -> tempfile::TempDir {
    let temp = tempfile::tempdir().expect("tempdir");
    for name in CASE_FILES {
        fs::copy(Path::new(src).join(name), temp.path().join(name)).expect("copy case file");
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
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}
