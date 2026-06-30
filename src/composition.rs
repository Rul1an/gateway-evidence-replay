use std::fs;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::schema::{Ceiling, EvidenceBundle, Reason, Status};
use crate::tool_surface::{verify_tool_surface_json_str, ToolSurfaceReason, ToolSurfaceStatus};
use crate::verify_json_str;

pub const COMPOSITION_PACK_PROFILE: &str = "gateway-composition.v0.replay-pack";
const COMPOSITION_DEMO_PROFILE: &str = "gateway-composition.v0.demo";
const COMPOSITION_EXPECTED_PROFILE: &str = "gateway-composition.v0.demo.expected";
const COMPOSITION_NON_CLAIMS: &[&str] = &[
    "not_whole_action_trust_score",
    "not_action_safety",
    "not_provider_honesty",
    "not_model_output_truth",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionReport {
    pub profile: &'static str,
    pub status: CompositionStatus,
    pub action_id: String,
    pub run_id: String,
    pub manifest_sha256: String,
    pub expected_sha256: String,
    pub gateway_path: GatewayPathReport,
    pub tool_surface: ToolSurfaceReport,
    pub non_claims: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositionStatus {
    Passed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayPathReport {
    pub file: String,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ceiling: Option<Ceiling>,
    pub reasons: Vec<Reason>,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSurfaceReport {
    pub file: String,
    pub status: ToolSurfaceStatus,
    pub reasons: Vec<ToolSurfaceReason>,
    pub passed: bool,
}

#[derive(Debug, Error)]
pub enum CompositionError {
    #[error("read {path}: {detail}")]
    Read { path: String, detail: String },
    #[error("parse {path}: {detail}")]
    Parse { path: String, detail: String },
    #[error("{path} digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("unsafe path in manifest: {path}")]
    UnsafePath { path: String },
    #[error("invalid {path}: {message}")]
    InvalidMetadata { path: String, message: String },
    #[error("{path} replay mismatch")]
    ReplayMismatch { path: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompositionManifest {
    profile: String,
    gateway_evidence_replay_version: String,
    claims: String,
    action_id: String,
    run_id: String,
    gateway_record: ManifestFile,
    tool_surface_record: ManifestFile,
    expected_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    file: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompositionExpected {
    profile: String,
    gateway_path: ExpectedGatewayPath,
    tool_surface: ExpectedToolSurface,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedGatewayPath {
    file: String,
    status: Status,
    ceiling: Option<Ceiling>,
    reasons: Vec<Reason>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedToolSurface {
    file: String,
    status: ToolSurfaceStatus,
    reasons: Vec<ToolSurfaceReason>,
}

pub fn replay_composition_pack_dir(dir: &Path) -> Result<CompositionReport, CompositionError> {
    let manifest_path = dir.join("manifest.json");
    let manifest_sha_path = dir.join("manifest-sha256.txt");
    let expected_path = dir.join("expected.json");

    let pinned_manifest_sha = read_to_string(&manifest_sha_path)?;
    let actual_manifest_sha = sha256_file(&manifest_path)?;
    let pinned_manifest_sha = pinned_manifest_sha.trim();
    if pinned_manifest_sha != actual_manifest_sha {
        return Err(CompositionError::DigestMismatch {
            path: "manifest.json".to_string(),
            expected: terminal_safe(pinned_manifest_sha),
            actual: actual_manifest_sha,
        });
    }

    let manifest: CompositionManifest = parse_json(&manifest_path)?;
    validate_manifest_metadata(&manifest)?;

    let actual_expected_sha = sha256_file(&expected_path)?;
    if manifest.expected_sha256 != actual_expected_sha {
        return Err(CompositionError::DigestMismatch {
            path: "expected.json".to_string(),
            expected: terminal_safe(&manifest.expected_sha256),
            actual: actual_expected_sha,
        });
    }

    verify_pinned_file(dir, &manifest.gateway_record)?;
    verify_pinned_file(dir, &manifest.tool_surface_record)?;

    let expected: CompositionExpected = parse_json(&expected_path)?;
    validate_expected_metadata(&expected)?;

    if expected.gateway_path.file != manifest.gateway_record.file {
        return Err(CompositionError::InvalidMetadata {
            path: "expected.json".to_string(),
            message: "gateway_path file must match manifest".to_string(),
        });
    }
    if expected.tool_surface.file != manifest.tool_surface_record.file {
        return Err(CompositionError::InvalidMetadata {
            path: "expected.json".to_string(),
            message: "tool_surface file must match manifest".to_string(),
        });
    }

    let gateway_path = replay_gateway_path(dir, &manifest, &expected.gateway_path)?;
    let tool_surface = replay_tool_surface(dir, &manifest, &expected.tool_surface)?;

    Ok(CompositionReport {
        profile: COMPOSITION_PACK_PROFILE,
        status: CompositionStatus::Passed,
        action_id: manifest.action_id,
        run_id: manifest.run_id,
        manifest_sha256: actual_manifest_sha,
        expected_sha256: actual_expected_sha,
        gateway_path,
        tool_surface,
        non_claims: COMPOSITION_NON_CLAIMS,
    })
}

fn replay_gateway_path(
    dir: &Path,
    manifest: &CompositionManifest,
    expected: &ExpectedGatewayPath,
) -> Result<GatewayPathReport, CompositionError> {
    let path = safe_relative_path(&expected.file)?;
    let body = read_to_string(&dir.join(path))?;
    let bundle = serde_json::from_str::<EvidenceBundle>(&body).map_err(|source| {
        CompositionError::Parse {
            path: terminal_safe(&expected.file),
            detail: terminal_safe(&source.to_string()),
        }
    })?;
    if bundle.request_id != manifest.run_id {
        return Err(CompositionError::InvalidMetadata {
            path: terminal_safe(&expected.file),
            message: "gateway request_id must match manifest run_id".to_string(),
        });
    }

    let got = verify_json_str(&body);
    let passed = got.status == expected.status
        && got.ceiling == expected.ceiling
        && got.reasons == expected.reasons;
    if !passed {
        return Err(CompositionError::ReplayMismatch {
            path: terminal_safe(&expected.file),
        });
    }

    Ok(GatewayPathReport {
        file: expected.file.clone(),
        status: got.status,
        ceiling: got.ceiling,
        reasons: got.reasons,
        passed,
    })
}

fn replay_tool_surface(
    dir: &Path,
    manifest: &CompositionManifest,
    expected: &ExpectedToolSurface,
) -> Result<ToolSurfaceReport, CompositionError> {
    let path = safe_relative_path(&expected.file)?;
    let body = read_to_string(&dir.join(path))?;
    let record = serde_json::from_str::<serde_json::Value>(&body).map_err(|source| {
        CompositionError::Parse {
            path: terminal_safe(&expected.file),
            detail: terminal_safe(&source.to_string()),
        }
    })?;
    if record
        .get("action_id")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value == manifest.action_id)
        && record
            .get("run_id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value == manifest.run_id)
    {
        let got = verify_tool_surface_json_str(&body);
        let passed = got.status == expected.status && got.reasons == expected.reasons;
        if !passed {
            return Err(CompositionError::ReplayMismatch {
                path: terminal_safe(&expected.file),
            });
        }
        return Ok(ToolSurfaceReport {
            file: expected.file.clone(),
            status: got.status,
            reasons: got.reasons,
            passed,
        });
    }

    Err(CompositionError::InvalidMetadata {
        path: terminal_safe(&expected.file),
        message: "tool surface action_id/run_id must match manifest".to_string(),
    })
}

fn validate_manifest_metadata(manifest: &CompositionManifest) -> Result<(), CompositionError> {
    if manifest.profile != COMPOSITION_DEMO_PROFILE {
        return Err(CompositionError::InvalidMetadata {
            path: "manifest.json".to_string(),
            message: format!("profile must be {COMPOSITION_DEMO_PROFILE}"),
        });
    }
    if manifest.gateway_evidence_replay_version.trim().is_empty()
        || manifest.claims.trim().is_empty()
        || manifest.action_id.trim().is_empty()
        || manifest.run_id.trim().is_empty()
    {
        return Err(CompositionError::InvalidMetadata {
            path: "manifest.json".to_string(),
            message: "version, claims, action_id, and run_id must be non-empty".to_string(),
        });
    }
    Ok(())
}

fn validate_expected_metadata(expected: &CompositionExpected) -> Result<(), CompositionError> {
    if expected.profile != COMPOSITION_EXPECTED_PROFILE {
        return Err(CompositionError::InvalidMetadata {
            path: "expected.json".to_string(),
            message: format!("profile must be {COMPOSITION_EXPECTED_PROFILE}"),
        });
    }
    Ok(())
}

fn verify_pinned_file(dir: &Path, fixture: &ManifestFile) -> Result<(), CompositionError> {
    let safe_path = safe_relative_path(&fixture.file)?;
    let actual = sha256_file(&dir.join(safe_path))?;
    if actual != fixture.sha256 {
        return Err(CompositionError::DigestMismatch {
            path: terminal_safe(&fixture.file),
            expected: terminal_safe(&fixture.sha256),
            actual,
        });
    }
    Ok(())
}

fn safe_relative_path(path: &str) -> Result<&Path, CompositionError> {
    let path_obj = Path::new(path);
    let safe = !path_obj.as_os_str().is_empty()
        && !path_obj.is_absolute()
        && path_obj
            .components()
            .all(|part| matches!(part, Component::Normal(_)));
    if safe {
        Ok(path_obj)
    } else {
        Err(CompositionError::UnsafePath {
            path: terminal_safe(path),
        })
    }
}

fn parse_json<T>(path: &Path) -> Result<T, CompositionError>
where
    T: for<'de> Deserialize<'de>,
{
    let body = read_to_string(path)?;
    serde_json::from_str(&body).map_err(|source| CompositionError::Parse {
        path: display_path(path),
        detail: terminal_safe(&source.to_string()),
    })
}

fn read_to_string(path: &Path) -> Result<String, CompositionError> {
    fs::read_to_string(path).map_err(|source| CompositionError::Read {
        path: display_path(path),
        detail: terminal_safe(&source.to_string()),
    })
}

fn sha256_file(path: &Path) -> Result<String, CompositionError> {
    let bytes = fs::read(path).map_err(|source| CompositionError::Read {
        path: display_path(path),
        detail: terminal_safe(&source.to_string()),
    })?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn display_path(path: &Path) -> String {
    let value = path
        .file_name()
        .and_then(|name| name.to_str())
        .map_or_else(|| path.display().to_string(), ToString::to_string);
    terminal_safe(&value)
}

fn terminal_safe(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_control() {
            out.push_str(&format!("\\u{{{:x}}}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
}
