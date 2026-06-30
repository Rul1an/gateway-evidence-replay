//! Deterministic replay verifier for `gateway-path.v0` evidence bundles.

pub mod composition;
pub mod pack;
pub mod replay;
pub mod schema;
pub mod tool_surface;

pub use composition::{replay_composition_pack_dir, CompositionError, CompositionReport};
pub use replay::{verify_bundle, verify_json_str, verify_json_value, VerifyError};
pub use schema::{
    Ceiling, EvidenceBundle, NonClaim, Reason, ReplayResult, SourceClass, Status, PROFILE,
};
pub use tool_surface::{
    verify_tool_surface_json_str, ToolSurfaceReason, ToolSurfaceResult, ToolSurfaceStatus,
    TOOL_SURFACE_PROFILE,
};
