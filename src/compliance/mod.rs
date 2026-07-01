//! Enterprise compliance posture tooling (PR-F).
//!
//! Source of truth for the `zeroclaw compliance { report, audit-trail,
//! ai-bom }` subcommand family. Each submodule is a narrowly-scoped
//! surface with its own argument parsing and emission; this module
//! is just the host that re-exports and stamps the clap wiring.
//!
//! Per AGENTS.md §"Single Source of Truth": every typed primitive
//! declared here (ComplianceError, ComplianceReport, ControlMatrix,
//! etc.) lives in exactly one submodule and is referenced through this
//! module's re-exports. The `scripts/ssot-verify.sh` script fails the
//! build if any of these types sprout a duplicate definition in another
//! crate.

pub mod ai_bom;
pub mod audit_export;
pub mod audit_verify;
pub mod control_matrix;
pub mod error;
pub mod report;
