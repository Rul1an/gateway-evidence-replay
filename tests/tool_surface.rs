use gateway_evidence_replay::{verify_tool_surface_json_str, ToolSurfaceReason, ToolSurfaceStatus};

fn record(
    coverage: &str,
    verified: bool,
    approved_hash: &str,
    observed_hash: Option<&str>,
) -> String {
    format!(
        r#"{{
  "profile": "tool-surface.v0",
  "action_id": "action-test",
  "run_id": "run-test",
  "coverage": "{coverage}",
  "approved_tool_surface_hash": "{approved_hash}",
  "observed_tool_surface_hash": {observed_hash},
  "evidence": {{
    "evidence_verified": {verified}
  }},
  "finding": null
}}"#,
        observed_hash = observed_hash
            .map(|value| format!(r#""{value}""#))
            .unwrap_or_else(|| "null".to_string())
    )
}

#[test]
fn unchanged_requires_verified_complete_matching_hashes() {
    let result = verify_tool_surface_json_str(&record(
        "complete",
        true,
        "sha256:approved",
        Some("sha256:approved"),
    ));

    assert_eq!(result.status, ToolSurfaceStatus::Unchanged);
    assert!(result.reasons.is_empty());
}

#[test]
fn hash_mismatch_refutes_even_before_coverage_can_confirm() {
    let result = verify_tool_surface_json_str(&record(
        "partial",
        true,
        "sha256:approved",
        Some("sha256:observed"),
    ));

    assert_eq!(result.status, ToolSurfaceStatus::Drifted);
    assert_eq!(result.reasons, vec![ToolSurfaceReason::SurfaceHashMismatch]);
}

#[test]
fn unverified_hash_mismatch_is_not_verifiable_not_drifted() {
    let result = verify_tool_surface_json_str(&record(
        "partial",
        false,
        "sha256:approved",
        Some("sha256:observed"),
    ));

    assert_eq!(result.status, ToolSurfaceStatus::NotVerifiable);
    assert_eq!(result.reasons, vec![ToolSurfaceReason::EvidenceNotVerified]);
}

#[test]
fn matching_but_unverified_is_not_verifiable() {
    let result = verify_tool_surface_json_str(&record(
        "complete",
        false,
        "sha256:approved",
        Some("sha256:approved"),
    ));

    assert_eq!(result.status, ToolSurfaceStatus::NotVerifiable);
    assert_eq!(result.reasons, vec![ToolSurfaceReason::EvidenceNotVerified]);
}

#[test]
fn matching_but_partial_coverage_is_not_verifiable() {
    let result = verify_tool_surface_json_str(&record(
        "partial",
        true,
        "sha256:approved",
        Some("sha256:approved"),
    ));

    assert_eq!(result.status, ToolSurfaceStatus::NotVerifiable);
    assert_eq!(result.reasons, vec![ToolSurfaceReason::CoverageNotComplete]);
}

#[test]
fn missing_observed_hash_is_not_verifiable() {
    let result = verify_tool_surface_json_str(&record("complete", true, "sha256:approved", None));

    assert_eq!(result.status, ToolSurfaceStatus::NotVerifiable);
    assert_eq!(
        result.reasons,
        vec![ToolSurfaceReason::ObservedSurfaceMissing]
    );
}

#[test]
fn malformed_json_is_invalid() {
    let result = verify_tool_surface_json_str("{}");

    assert_eq!(result.status, ToolSurfaceStatus::Invalid);
    assert_eq!(result.reasons, vec![ToolSurfaceReason::MalformedInput]);
}
