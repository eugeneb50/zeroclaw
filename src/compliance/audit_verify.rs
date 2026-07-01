//! Audit-trail chain verification (PR-F).
//!
//! Thin wrapper over `zeroclaw_runtime::security::audit::verify_chain`
//! that maps the runtime `Result<u64, anyhow::Error>` onto
//! [`crate::compliance::error::ComplianceError`] so the CLI can use
//! stable exit codes:
//!
//! - exit 2 — chain broken (sequence gap, prev-hash mismatch,
//!   entry-hash mismatch, signature mismatch).
//! - exit 3 — I/O failure (file not found, permission denied, malformed
//!   JSONL).
//! - exit 1 — anything else (preserved via
//!   [`ComplianceError::new`] with `ComplianceErrorKind::Other`).

use std::path::Path;

use super::error::{ComplianceError, ComplianceErrorKind, Result};

/// Verify the audit-log chain. Returns the count of audit entries
/// on success.
///
/// # Errors
///
/// - `AuditChainBroken` — the chain failed an integrity check.
///   The embedded sequence number tells auditors which entry to look at.
/// - `Io` — the log file is missing, unreadable, or contains
///   malformed JSON.
/// - `Other` — any other runtime failure (preserves the source cause).
pub fn verify_chain(log_path: &Path) -> Result<u64> {
    match zeroclaw_runtime::security::audit::verify_chain(log_path) {
        Ok(count) => Ok(count),
        Err(err) => {
            // Cheap regex-free token scan: split, find the first
            // token composed of ASCII digits, parse to u64.
            let rendered = format!("{err}");
            let sequence = rendered
                .split_whitespace()
                .find_map(|token| {
                    if token.chars().all(|c| c.is_ascii_digit()) {
                        token.parse::<u64>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            // Distinguish "chain broken" (sequence gap / hash / signature)
            // from generic I/O or parse errors. The runtime emits the chain
            // messages with the words "sequence", "entry_hash",
            // "signature", or "prev_hash" — we *could* type on those, but
            // `verify_chain` does not surface typed variants yet, so we
            // translate on the message keywords:
            let kind = if rendered.contains("sequence")
                || rendered.contains("entry_hash")
                || rendered.contains("prev_hash")
                || rendered.contains("signature")
            {
                ComplianceErrorKind::AuditChainBroken
            } else if rendered.contains("os error")
                || rendered.contains("No such file")
                || rendered.contains("Permission denied")
                || rendered.contains("is not a file")
                || rendered.contains("malformed")
            {
                ComplianceErrorKind::Io
            } else {
                ComplianceErrorKind::Other
            };
            // Route into the most specific constructor when possible.
            Err(match kind {
                ComplianceErrorKind::AuditChainBroken => {
                    ComplianceError::broken(sequence, rendered)
                }
                ComplianceErrorKind::Io => ComplianceError::io(log_path, "verify_chain failed"),
                _ => ComplianceError::new(kind, rendered),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::AuditLogger; // re-export from zeroclaw_runtime
    use std::io::Write as _;
    use tempfile::TempDir;

    fn write_n_events(dir: &TempDir, n: usize) -> std::path::PathBuf {
        // Build a fresh AuditLogger bound to a tempdir config.toml.
        let zeroclaw_dir = dir.path().join("zeroclaw");
        std::fs::create_dir_all(&zeroclaw_dir).expect("make dir");
        let audit_cfg = zeroclaw_config::schema::AuditConfig {
            enabled: true,
            log_path: "audit.log".into(),
            max_size_mb: 100,
            sign_events: false,
        };
        let logger = AuditLogger::new(audit_cfg, zeroclaw_dir.clone()).expect("logger");
        for i in 0..n {
            let event = zeroclaw_runtime::security::audit::AuditEvent::new(
                zeroclaw_runtime::security::audit::AuditEventType::CommandExecution,
            )
            .with_actor("telegram".into(), Some(format!("user-{i}")), None)
            .with_action(format!("echo {i}"), "low".into(), false, true);
            logger.log(&event).expect("log");
        }
        zeroclaw_dir.join("audit.log")
    }

    #[test]
    fn verify_chain_returns_count_on_clean_log() {
        let tmp = TempDir::new().expect("tempdir");
        let log = write_n_events(&tmp, 3);
        let count = verify_chain(&log).expect("verify_chain ok");
        assert_eq!(count, 3);
    }

    #[test]
    fn verify_chain_detects_missing_file_as_io_error() {
        let tmp = TempDir::new().expect("tempdir");
        let bogus = tmp.path().join("does-not-exist.log");
        let err = verify_chain(&bogus).expect_err("must fail");
        assert_eq!(err.kind, ComplianceErrorKind::Io);
    }

    #[test]
    fn verify_chain_detects_tampered_entry_as_chain_broken() {
        let tmp = TempDir::new().expect("tempdir");
        let log = write_n_events(&tmp, 4);
        // Mutate one entry's actor payload to invalidate the chain.
        let raw = std::fs::read_to_string(&log).expect("read");
        let mut poisoned = raw.clone();
        // Replace a stable string in the second major block (line ~3).
        if let Some(idx) = poisoned.find("echo 2\n") {
            // Find the same line and rewrite payload so the entry_hash changes.
            // Simplest: replace the second actor.user_id with `"mallory"`.
            // We avoid line-based editing and instead swap the JSONL string rep:
            // use a distinguishable substring inside one of the JSON objects.
            if let Some(user_pos) = poisoned[idx..].find("\"user-2\"") {
                let abs = idx + user_pos;
                poisoned.replace_range(abs..abs + "\"user-2\"".len(), "\"mallory\"");
                let _ = idx;
            }
        }
        std::fs::write(&log, poisoned).expect("rewrite");
        let err = verify_chain(&log).expect_err("must detect tamper");
        assert_eq!(err.kind, ComplianceErrorKind::AuditChainBroken);
    }

    #[test]
    fn verify_chain_detects_sequence_gap() {
        let tmp = TempDir::new().expect("tempdir");
        let log = write_n_events(&tmp, 3);
        // Truncate one line to simulate a gap.
        let raw = std::fs::read_to_string(&log).expect("read");
        let mut lines: Vec<&str> = raw.lines().collect();
        if lines.len() >= 2 {
            lines.remove(1);
        }
        let truncated: String = lines.join("\n");
        std::fs::write(&log, truncated).expect("truncated write");
        let err = verify_chain(&log).expect_err("must fail");
        assert!(matches!(
            err.kind,
            ComplianceErrorKind::AuditChainBroken | ComplianceErrorKind::Other
        ));
    }
}
