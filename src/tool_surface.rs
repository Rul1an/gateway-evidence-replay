use serde::{Deserialize, Serialize};

use crate::schema::Coverage;

pub const TOOL_SURFACE_PROFILE: &str = "tool-surface.v0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolSurfaceStatus {
    Unchanged,
    Drifted,
    NotVerifiable,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum ToolSurfaceReason {
    SurfaceHashMismatch,
    EvidenceNotVerified,
    CoverageNotComplete,
    ObservedSurfaceMissing,
    MalformedInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum ToolSurfaceNonClaim {
    NotActionSafety,
    NotGatewayPathTruth,
    NotProviderHonesty,
    NotPolicyApproval,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSurfaceResult {
    pub profile: &'static str,
    pub status: ToolSurfaceStatus,
    pub reasons: Vec<ToolSurfaceReason>,
    pub non_claims: Vec<ToolSurfaceNonClaim>,
}

impl ToolSurfaceResult {
    fn new(status: ToolSurfaceStatus, mut reasons: Vec<ToolSurfaceReason>) -> Self {
        reasons.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));
        reasons.dedup();
        Self {
            profile: TOOL_SURFACE_PROFILE,
            status,
            reasons,
            non_claims: ToolSurfaceNonClaim::all().to_vec(),
        }
    }

    fn invalid() -> Self {
        Self::new(
            ToolSurfaceStatus::Invalid,
            vec![ToolSurfaceReason::MalformedInput],
        )
    }
}

impl ToolSurfaceReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SurfaceHashMismatch => "surface_hash_mismatch",
            Self::EvidenceNotVerified => "evidence_not_verified",
            Self::CoverageNotComplete => "coverage_not_complete",
            Self::ObservedSurfaceMissing => "observed_surface_missing",
            Self::MalformedInput => "malformed_input",
        }
    }
}

impl ToolSurfaceNonClaim {
    const fn all() -> &'static [Self] {
        &[
            Self::NotActionSafety,
            Self::NotGatewayPathTruth,
            Self::NotProviderHonesty,
            Self::NotPolicyApproval,
        ]
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSurfaceRecord {
    pub profile: String,
    pub action_id: String,
    pub run_id: String,
    pub coverage: Coverage,
    pub approved_tool_surface_hash: String,
    pub observed_tool_surface_hash: Option<String>,
    pub evidence: ToolSurfaceEvidence,
    pub finding: Option<String>,
}

impl ToolSurfaceRecord {
    fn validate_shape(&self) -> bool {
        self.profile == TOOL_SURFACE_PROFILE
            && non_empty(&self.action_id)
            && non_empty(&self.run_id)
            && non_empty(&self.approved_tool_surface_hash)
            && self
                .observed_tool_surface_hash
                .as_deref()
                .is_none_or(non_empty)
            && self.finding.as_deref().is_none_or(non_empty)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSurfaceEvidence {
    pub evidence_verified: bool,
}

pub fn verify_tool_surface_json_str(value: &str) -> ToolSurfaceResult {
    match serde_json::from_str::<ToolSurfaceRecord>(value) {
        Ok(record) => verify_tool_surface_record(&record),
        Err(_) => ToolSurfaceResult::invalid(),
    }
}

pub fn verify_tool_surface_record(record: &ToolSurfaceRecord) -> ToolSurfaceResult {
    if !record.validate_shape() {
        return ToolSurfaceResult::invalid();
    }

    if !record.evidence.evidence_verified {
        return ToolSurfaceResult::new(
            ToolSurfaceStatus::NotVerifiable,
            vec![ToolSurfaceReason::EvidenceNotVerified],
        );
    }

    let Some(observed_hash) = record.observed_tool_surface_hash.as_deref() else {
        return ToolSurfaceResult::new(
            ToolSurfaceStatus::NotVerifiable,
            vec![ToolSurfaceReason::ObservedSurfaceMissing],
        );
    };

    if observed_hash != record.approved_tool_surface_hash {
        return ToolSurfaceResult::new(
            ToolSurfaceStatus::Drifted,
            vec![ToolSurfaceReason::SurfaceHashMismatch],
        );
    }

    if record.coverage != Coverage::Complete {
        return ToolSurfaceResult::new(
            ToolSurfaceStatus::NotVerifiable,
            vec![ToolSurfaceReason::CoverageNotComplete],
        );
    }

    ToolSurfaceResult::new(ToolSurfaceStatus::Unchanged, Vec::new())
}

fn non_empty(value: &str) -> bool {
    !value.trim().is_empty()
}
