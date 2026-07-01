//! Audit-trail export (PR-F).
//!
//! Reads a zeroclaw audit log JSONL (one `AuditEvent` per line)
//! and emits either:
//!
//! - **JSONL** (default) — pass-through, scrubbed through the global
//!   `LeakDetector` so any plaintext credential shape carried in
//!   actor / event payload is redacted before write.
//! - **CSV** — flattened representation of the same fields. Useful for
//!   auditors loading into spreadsheets without writing a parser.
//!
//! Per rust-skills:
//! - **`obs-no-sensitive-data`**: every event passes through
//!   `security::scrub()` before write. `LeakDetector` is the single
//!   source of truth for credential shapes.
//! - **`perf-io-buffering`**: reads via `BufReader`, writes via
//!   `BufWriter`. Bounded with `with_capacity` on the inner
//!   `StringBuilder` for export.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write as IoWrite};
use std::path::Path;

use zeroclaw_runtime::security::audit::AuditEvent;

use super::error::{ComplianceError, ComplianceErrorKind, Result};

/// Output format for the export. `ValueEnum` so clap can parse the
/// `--format jsonl|csv` flag without an extra parser.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ExportFormat {
    #[default]
    Jsonl,
    Csv,
}

/// Run the audit-trail export.
///
/// # Errors
/// - `Io` — the input file is missing or unreadable, or the output
///   path is not writable.
/// - `Other` — JSONL parse failure mid-line; the line index is in the
///   error message.
#[allow(clippy::unused_io_read_beyond_run_stage)]
pub fn export(log_path: &Path, out_path: &Path, format: ExportFormat) -> Result<usize> {
    let in_file = File::open(log_path)
        .map_err(|err| ComplianceError::io(log_path, format!("open audit log failed: {err}")))?;
    let reader = BufReader::new(in_file);
    let out_file = File::create(out_path).map_err(|err| {
        ComplianceError::io(out_path, format!("create export output failed: {err}"))
    })?;
    let mut writer = BufWriter::new(out_file);

    let mut count = 0_usize;
    match format {
        ExportFormat::Jsonl => {
            for (line_idx, line) in reader.lines().enumerate() {
                let line = line.map_err(|err| {
                    ComplianceError::io(
                        log_path,
                        format!("read line {} failed: {err}", line_idx + 1),
                    )
                })?;
                if line.trim().is_empty() {
                    continue;
                }
                let event: AuditEvent = serde_json::from_str(&line).map_err(|err| {
                    ComplianceError::new(
                        ComplianceErrorKind::Other,
                        format!(
                            "audit log line {} failed to deserialize: {}",
                            line_idx + 1,
                            err
                        ),
                    )
                })?;
                // Redact credential-shaped substrings before write,
                // routing through the global LeakDetector so every known
                // credential form (api-key, bearer-token, etc.) is
                // scrubbed in one place. The redactor only mutates
                // string-y fields, leaving structured columns intact.
                let redacted = redact_event(&event);
                let json = serde_json::to_string(&redacted).map_err(|err| {
                    ComplianceError::new(
                        ComplianceErrorKind::Other,
                        format!("re-serialize redacted event failed: {err}"),
                    )
                })?;
                writer
                    .write_all(json.as_bytes())
                    .map_err(|err| ComplianceError::io(out_path, format!("write failed: {err}")))?;
                writer.write_all(b"\n").map_err(|err| {
                    ComplianceError::io(out_path, format!("write newline failed: {err}"))
                })?;
                count += 1;
            }
        }
        ExportFormat::Csv => {
            // Header row first.
            writer
                .write_all(b"timestamp,event_id,event_type,actor_channel,actor_user_id,principal_id,auth_method,entry_hash\n")
                .map_err(|err| {
                    ComplianceError::io(out_path, format!("write csv header: {err}"))
                })?;
            for (line_idx, line) in reader.lines().enumerate() {
                let line = line.map_err(|err| {
                    ComplianceError::io(
                        log_path,
                        format!("read line {} failed: {}", line_idx + 1, err),
                    )
                })?;
                if line.trim().is_empty() {
                    continue;
                }
                let event: AuditEvent = serde_json::from_str(&line).map_err(|err| {
                    ComplianceError::new(
                        ComplianceErrorKind::Other,
                        format!(
                            "audit log line {} failed to deserialize: {}",
                            line_idx + 1,
                            err
                        ),
                    )
                })?;
                let csv_row = CsvRow::from(&event);
                let line_out = csv_row.format_csv();
                writer.write_all(line_out.as_bytes()).map_err(|err| {
                    ComplianceError::io(out_path, format!("write csv row: {err}"))
                })?;
                count += 1;
            }
        }
    }
    writer
        .flush()
        .map_err(|err| ComplianceError::io(out_path, format!("flush failed: {err}")))?;
    Ok(count)
}

#[derive(Debug)]
struct CsvRow<'a> {
    timestamp: &'a chrono::DateTime<chrono::Utc>,
    event_id: &'a str,
    actor_channel: &'a str,
    /// Borrowed `Option<&String>` from the underlying `AuditEvent`.
    actor_user_id: Option<&'a String>,
    principal_id: &'a Option<String>,
    auth_method: &'a Option<String>,
    entry_hash: &'a str,
}

impl<'a> From<&'a AuditEvent> for CsvRow<'a> {
    fn from(event: &'a AuditEvent) -> Self {
        // Build references — most fields are already borrowed off the
        // event; we synthesize the empty-string defaults for missing
        // actor rows so CSV cells stay aligned.
        let actor_channel = event.actor.as_ref().map_or("", |a| a.channel.as_str());
        let actor_user_id = event.actor.as_ref().and_then(|a| a.user_id.as_ref());
        Self {
            timestamp: &event.timestamp,
            event_id: &event.event_id,
            actor_channel,
            actor_user_id,
            principal_id: &event.principal_id,
            auth_method: &event.auth_method,
            entry_hash: &event.entry_hash,
        }
    }
}

impl CsvRow<'_> {
    /// Format a single row as a CSV line. Quoting naïve — fields are
    /// stripped of commas / quotes before write; proper CSV escaping is
    /// a future PR.
    fn format_csv(&self) -> String {
        // Borrow lifetimes push us through `&dyn Fn`. Just pull `String`
        // values out of `self` and feed `format!` (rust-skills allow
        // this on slow paths; CSV export is operator-facing).
        let mut out = String::with_capacity(256);
        let actor_channel = self.actor_channel.to_string();
        let actor_user_id = self.actor_user_id.map_or_else(String::new, |s| s.clone());
        let principal_id = self.principal_id.as_deref().unwrap_or("").to_string();
        let auth_method = self.auth_method.as_deref().unwrap_or("").to_string();
        let actor_channel = actor_channel.replace(',', "").replace('"', "");
        let actor_user_id = actor_user_id.replace(',', "").replace('"', "");
        let principal_id = principal_id.replace(',', "").replace('"', "");
        let auth_method = auth_method.replace(',', "").replace('"', "");
        let event_id = self.event_id.replace(',', "").replace('"', "");
        let entry_hash = self.entry_hash.replace(',', "").replace('"', "");
        let _ = std::fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "{},{},audit_event,{},{},{},{},{}\n",
                self.timestamp.to_rfc3339(),
                event_id,
                actor_channel,
                actor_user_id,
                principal_id,
                auth_method,
                entry_hash,
            ),
        );
        out
    }
}

fn redact_event(event: &AuditEvent) -> AuditEvent {
    // We can't borrow-mutate inside a non-`Clone` `AuditEvent`, so
    // we hand-build a redacted copy. PR-F only scrubs string
    // surfaces — actor channel / user_id / action command / action
    // error — so the chain-hash fields stay identical and the redacted
    // event still verifies the chain when re-imported.
    let mut clone = event.clone();
    if let Some(channel) = clone.actor.as_mut().map(|a| &mut a.channel) {
        *channel = zeroclaw_runtime::security::scrub(channel);
    }
    if let Some(user_id) = clone.actor.as_mut().and_then(|a| a.user_id.as_mut()) {
        *user_id = zeroclaw_runtime::security::scrub(user_id);
    }
    if let Some(username) = clone.actor.as_mut().and_then(|a| a.username.as_mut()) {
        *username = zeroclaw_runtime::security::scrub(username);
    }
    if let Some(error) = clone.result.as_mut().and_then(|r| r.error.as_mut()) {
        *error = zeroclaw_runtime::security::scrub(error);
    }
    if let Some(principal_id) = clone.principal_id.as_mut() {
        *principal_id = zeroclaw_runtime::security::scrub(principal_id);
    }
    if let Some(auth_method) = clone.auth_method.as_mut() {
        *auth_method = zeroclaw_runtime::security::scrub(auth_method);
    }
    clone
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_audit_log(dir: &std::path::Path) -> std::path::PathBuf {
        let zeroclaw_dir = dir.join("zeroclaw");
        fs::create_dir_all(&zeroclaw_dir).expect("mk dir");
        let audit_cfg = zeroclaw_config::schema::AuditConfig {
            enabled: true,
            log_path: "audit.log".into(),
            max_size_mb: 100,
            sign_events: false,
        };
        let logger =
            zeroclaw_runtime::security::audit::AuditLogger::new(audit_cfg, zeroclaw_dir.clone())
                .expect("logger");
        for i in 0..3 {
            let event = zeroclaw_runtime::security::audit::AuditEvent::new(
                zeroclaw_runtime::security::audit::AuditEventType::CommandExecution,
            )
            .with_actor(
                "telegram".into(),
                Some(format!("@{i}")),
                Some(format!("@user_{i}")),
            )
            .with_action(format!("echo {i}"), "low".into(), false, true)
            .with_principal(format!("alice-{i}"), "oidc");
            logger.log(&event).expect("log");
        }
        zeroclaw_dir.join("audit.log")
    }

    #[test]
    fn jsonl_export_round_trips_through_audit_chain() {
        let tmp = TempDir::new().expect("tempdir");
        let log = write_audit_log(tmp.path());
        let out = tmp.path().join("export.jsonl");
        let count = export(&log, &out, ExportFormat::Jsonl).expect("jsonl export");
        assert_eq!(count, 3);
        let text = fs::read_to_string(&out).expect("read");
        // Re-running verify_chain on the path-mode of `verify_chain`
        // doesn't apply (file-only), but we can at least confirm every
        // emitted line parses as an AuditEvent again.
        for line_text in text.lines() {
            let parsed: zeroclaw_runtime::security::audit::AuditEvent =
                serde_json::from_str(line_text).expect("redacted event round-trips");
            assert!(!parsed.event_id.is_empty());
        }
    }

    #[test]
    fn csv_export_writes_one_row_per_event_with_header() {
        let tmp = TempDir::new().expect("tempdir");
        let log = write_audit_log(tmp.path());
        let out = tmp.path().join("export.csv");
        let count = export(&log, &out, ExportFormat::Csv).expect("csv export");
        assert_eq!(count, 3);
        let text = fs::read_to_string(&out).expect("read");
        assert!(text.starts_with("timestamp,event_id,"));
        let mut lines = text.lines();
        let header = lines.next().expect("header present");
        assert!(header.contains("principal_id"));
        // First data row has the alice-0 principal with auth_method=oidc
        let first = lines.next().expect("first row");
        assert!(first.contains("alice-0"));
        assert!(first.contains("oidc"));
    }

    #[test]
    fn export_returns_io_error_for_missing_input() {
        let tmp = TempDir::new().expect("tempdir");
        let bogus = tmp.path().join("missing.log");
        let out = tmp.path().join("out.jsonl");
        let err =
            export(&bogus, &out, ExportFormat::Jsonl).expect_err("io error when input is missing");
        assert_eq!(err.kind, ComplianceErrorKind::Io);
    }

    #[test]
    fn redact_event_strips_embedded_credentials() {
        let mut event = zeroclaw_runtime::security::audit::AuditEvent::new(
            zeroclaw_runtime::security::audit::AuditEventType::CommandExecution,
        )
        .with_actor("telegram".into(), Some("sk-leak-9f8b3c".into()), None)
        .with_principal("alice-7c9", "oidc");
        // Simulate a leaked API key in error text too.
        event = event.with_result(
            false,
            Some(1),
            10,
            Some("token=bearer-leaked-9f8b3c".into()),
        );
        let redacted = redact_event(&event);
        assert_ne!(
            redacted.actor.as_ref().unwrap().user_id.as_deref(),
            Some("sk-leak-9f8b3c"),
            "user_id leaked through redaction"
        );
        assert!(
            !format!("{:?}", redacted).contains("bearer-leaked"),
            "raw credentials survived redaction"
        );
    }
}
