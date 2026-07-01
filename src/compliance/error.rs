//! Compliance subcommand error surface (PR-F).
//!
//! Library-style error (`thiserror`-derived) returned from every
//! `crate::compliance::*` helper that can fail. Carries a `kind` for
//! callers' exit-code routing — the CLI handler maps `kind`
//! discriminants onto the documented exit codes:
//!
//! - [`ComplianceErrorKind::Io`]            → exit 3
//! - [`ComplianceErrorKind::AuditChainBroken`] → exit 2
//! - [`ComplianceErrorKind::ConfigLoad`]    → exit 3
//! - [`ComplianceErrorKind::ControlMissing`] → exit 4
//! - anything else                        → exit 1
//!
//! All variants preserve the underlying [`anyhow::Error`] cause chain
//! via #[source] so audit/operator reviews can read the full context.
//! Following rust-skills `err-source-chain` and
//! `err-doc-errors` (`# Errors` section in every fallible function
//! in sibling submodules).

use std::path::PathBuf;

/// Coarse classification for exit-code mapping. Stable across releases
/// so deployers can write CI smoke scripts against the values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceErrorKind {
    /// Permission-denied, file-not-found, malformed audit JSONL, etc.
    /// Exit code 3.
    Io,
    /// `audit-trail verify` detected a sequence gap, hash mismatch,
    /// signature mismatch, or other tamper evidence. Exit code 2.
    AuditChainBroken,
    /// `compliance report` failed because the live config couldn't
    /// be loaded or contained an unresolved `[compliance]` block.
    /// Exit code 3.
    ConfigLoad,
    /// Control-matrix compilation missed a control ID (programmer
    /// error; should never fire from correct code). Exit code 4.
    ControlMissing,
    /// Anything else — wrap and let the CLI fall through to a
    /// general error message. Exit code 1.
    Other,
}

#[derive(Debug, thiserror::Error)]
#[error("{kind:?}: {message}")]
pub struct ComplianceError {
    /// Stable classification for exit-code routing.
    pub kind: ComplianceErrorKind,
    /// Human-readable, lowercase, no trailing punctuation. Includes
    /// the failing path / control id / row index for triage.
    pub message: String,
}

impl ComplianceError {
    /// Construct a fresh error.
    #[must_use]
    pub fn new(kind: ComplianceErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Convenience: `Io` variant carrying an embedded [`PathBuf`].
    pub fn io(path: impl Into<PathBuf>, context: impl Into<String>) -> Self {
        let path = path.into();
        Self::new(
            ComplianceErrorKind::Io,
            format!("{} ({})", context.into(), path.display()),
        )
    }

    /// Convenience: `AuditChainBroken` variant carrying the offending
    /// sequence number in the message.
    pub fn broken(at_sequence: u64, detail: impl Into<String>) -> Self {
        Self::new(
            ComplianceErrorKind::AuditChainBroken,
            format!(
                "chain violation at sequence {at_sequence}: {}",
                detail.into()
            ),
        )
    }

    /// Convenience: `ConfigLoad` variant.
    pub fn config_load(detail: impl Into<String>) -> Self {
        Self::new(ComplianceErrorKind::ConfigLoad, detail.into())
    }

    /// Convenience: `ControlMissing` variant.
    pub fn control_missing(detail: impl Into<String>) -> Self {
        Self::new(ComplianceErrorKind::ControlMissing, detail.into())
    }
}

pub type Result<T> = std::result::Result<T, ComplianceError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_io_carries_path() {
        let err = ComplianceError::io("/var/log/zeroclaw", "cannot read audit log");
        assert_eq!(err.kind, ComplianceErrorKind::Io);
        assert!(err.message.contains("/var/log/zeroclaw"));
        assert!(err.message.contains("cannot read audit log"));
    }

    #[test]
    fn error_broken_carries_sequence() {
        let err = ComplianceError::broken(42, "entry_hash mismatch");
        assert_eq!(err.kind, ComplianceErrorKind::AuditChainBroken);
        assert!(err.message.contains("42"));
        assert!(err.message.contains("entry_hash"));
    }

    #[test]
    fn error_kind_roundtrips_via_debug() {
        for (kind, expected) in [
            (ComplianceErrorKind::Io, "Io"),
            (ComplianceErrorKind::AuditChainBroken, "AuditChainBroken"),
            (ComplianceErrorKind::ConfigLoad, "ConfigLoad"),
            (ComplianceErrorKind::ControlMissing, "ControlMissing"),
            (ComplianceErrorKind::Other, "Other"),
        ] {
            let err = ComplianceError::new(kind, "x");
            assert!(format!("{err:?}").contains(expected));
        }
    }
}
