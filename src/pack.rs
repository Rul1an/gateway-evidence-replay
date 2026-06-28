use std::fs;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::schema::{Ceiling, Reason, Status};
use crate::verify_json_str;

pub const PACK_PROFILE: &str = "gateway-path.v0.replay-pack";
const DEMO_PROFILE: &str = "gateway-path.v0.demo";
const EXPECTED_PROFILE: &str = "gateway-path.v0.demo.expected";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackReport {
    pub profile: &'static str,
    pub status: PackStatus,
    pub cases_total: usize,
    pub cases_passed: usize,
    pub manifest_sha256: String,
    pub expected_sha256: String,
    pub cases: Vec<PackCaseReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackStatus {
    Passed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackCaseReport {
    pub file: String,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ceiling: Option<Ceiling>,
    pub reasons: Vec<Reason>,
    pub passed: bool,
}

#[derive(Debug, Error)]
pub enum PackError {
    #[error("read {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("parse {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
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
struct Manifest {
    profile: String,
    gateway_evidence_replay_version: String,
    claims: String,
    fixtures: Vec<ManifestFile>,
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
struct ExpectedFile {
    profile: String,
    cases: Vec<ExpectedCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedCase {
    file: String,
    status: Status,
    ceiling: Option<Ceiling>,
    reasons: Vec<Reason>,
}

pub fn replay_pack_dir(dir: &Path) -> Result<PackReport, PackError> {
    let manifest_path = dir.join("manifest.json");
    let manifest_sha_path = dir.join("manifest-sha256.txt");
    let expected_path = dir.join("expected.json");

    let pinned_manifest_sha = read_to_string(&manifest_sha_path)?;
    let actual_manifest_sha = sha256_file(&manifest_path)?;
    let pinned_manifest_sha = pinned_manifest_sha.trim();
    if pinned_manifest_sha != actual_manifest_sha {
        return Err(PackError::DigestMismatch {
            path: "manifest.json".to_string(),
            expected: pinned_manifest_sha.to_string(),
            actual: actual_manifest_sha,
        });
    }

    let manifest: Manifest = parse_json(&manifest_path)?;
    validate_manifest_metadata(&manifest)?;

    let actual_expected_sha = sha256_file(&expected_path)?;
    if manifest.expected_sha256 != actual_expected_sha {
        return Err(PackError::DigestMismatch {
            path: "expected.json".to_string(),
            expected: manifest.expected_sha256,
            actual: actual_expected_sha,
        });
    }

    for fixture in &manifest.fixtures {
        let safe_path = safe_relative_path(&fixture.file)?;
        let actual = sha256_file(&dir.join(safe_path))?;
        if actual != fixture.sha256 {
            return Err(PackError::DigestMismatch {
                path: fixture.file.clone(),
                expected: fixture.sha256.clone(),
                actual,
            });
        }
    }

    let expected: ExpectedFile = parse_json(&expected_path)?;
    validate_expected_metadata(&expected)?;
    let mut cases = Vec::with_capacity(expected.cases.len());
    for case in expected.cases {
        let safe_path = safe_relative_path(&case.file)?;
        let body = read_to_string(&dir.join(safe_path))?;
        let got = verify_json_str(&body);
        let passed =
            got.status == case.status && got.ceiling == case.ceiling && got.reasons == case.reasons;
        if !passed {
            return Err(PackError::ReplayMismatch { path: case.file });
        }
        cases.push(PackCaseReport {
            file: case.file,
            status: got.status,
            ceiling: got.ceiling,
            reasons: got.reasons,
            passed,
        });
    }

    Ok(PackReport {
        profile: PACK_PROFILE,
        status: PackStatus::Passed,
        cases_total: cases.len(),
        cases_passed: cases.len(),
        manifest_sha256: actual_manifest_sha,
        expected_sha256: actual_expected_sha,
        cases,
    })
}

fn validate_manifest_metadata(manifest: &Manifest) -> Result<(), PackError> {
    if manifest.profile != DEMO_PROFILE {
        return Err(PackError::InvalidMetadata {
            path: "manifest.json".to_string(),
            message: format!("profile must be {DEMO_PROFILE}"),
        });
    }
    if manifest.gateway_evidence_replay_version.trim().is_empty() {
        return Err(PackError::InvalidMetadata {
            path: "manifest.json".to_string(),
            message: "gateway_evidence_replay_version must be non-empty".to_string(),
        });
    }
    if manifest.claims.trim().is_empty() {
        return Err(PackError::InvalidMetadata {
            path: "manifest.json".to_string(),
            message: "claims must be non-empty".to_string(),
        });
    }
    if manifest.fixtures.is_empty() {
        return Err(PackError::InvalidMetadata {
            path: "manifest.json".to_string(),
            message: "fixtures must be non-empty".to_string(),
        });
    }
    Ok(())
}

fn validate_expected_metadata(expected: &ExpectedFile) -> Result<(), PackError> {
    if expected.profile != EXPECTED_PROFILE {
        return Err(PackError::InvalidMetadata {
            path: "expected.json".to_string(),
            message: format!("profile must be {EXPECTED_PROFILE}"),
        });
    }
    if expected.cases.is_empty() {
        return Err(PackError::InvalidMetadata {
            path: "expected.json".to_string(),
            message: "cases must be non-empty".to_string(),
        });
    }
    Ok(())
}

fn safe_relative_path(path: &str) -> Result<&Path, PackError> {
    let path_obj = Path::new(path);
    let safe = !path_obj.as_os_str().is_empty()
        && !path_obj.is_absolute()
        && path_obj
            .components()
            .all(|part| matches!(part, Component::Normal(_)));
    if safe {
        Ok(path_obj)
    } else {
        Err(PackError::UnsafePath {
            path: path.to_string(),
        })
    }
}

fn parse_json<T>(path: &Path) -> Result<T, PackError>
where
    T: for<'de> Deserialize<'de>,
{
    let body = read_to_string(path)?;
    serde_json::from_str(&body).map_err(|source| PackError::Parse {
        path: display_path(path),
        source,
    })
}

fn read_to_string(path: &Path) -> Result<String, PackError> {
    fs::read_to_string(path).map_err(|source| PackError::Read {
        path: display_path(path),
        source,
    })
}

fn sha256_file(path: &Path) -> Result<String, PackError> {
    let bytes = fs::read(path).map_err(|source| PackError::Read {
        path: display_path(path),
        source,
    })?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn display_path(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .map_or_else(|| path.display().to_string(), ToString::to_string)
}
