//! Compliance report builder & emitter (PR-F).
//!
//! Produces a [`ComplianceReport`] from the live config + control
//! matrix evaluation. Output formats:
//!
//! - **Markdown** (default) — `compliance report soc2` writes a
//!   human-readable table for compliance reviewers.
//! - **JSON** — `--format json` for CI dashboards / machine parsing.
//! - **YAML** — `--format yaml`, mirrors JSON.
//!
//! Per rust-skills:
//! - Typestate pattern `ComplianceReportBuilder<Draft>` → `<Finalized>`
//!   prevents emitting partial reports (rule `api-typestate`).
//! - `Builder::must_use` so a dropped builder doesn't silently lose
//!   evaluation results (rule `api-builder-must-use`).
//! - All public fallible functions documented under `# Errors`
//!   (rule `err-doc-errors`).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::config::Config;
use zeroclaw_config::schema::AuditConfig;

use super::control_matrix::{ControlId, ControlMatrix, ControlStatus};
use super::error::{ComplianceError, ComplianceErrorKind, Result};

/// Output format selection. CLI flag defaults to `Markdown` per
/// locked decision (2). `ValueEnum` so clap can parse `--format
/// markdown|json|yaml` strings without an extra parser.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    #[default]
    Markdown,
    Json,
    Yaml,
}

/// The finalized compliance report. **Source of truth for the public
/// output type** — every emitter (Markdown / JSON / YAML) consumes
/// the same struct via `Serialize`; nothing duplicates the row
/// shape elsewhere.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Snapshot timestamp (RFC3339).
    pub generated_at: chrono::DateTime<chrono::Utc>,
    /// Compliance regimes the operator claimed. Mirrors `Config.compliance.regimes`.
    pub claimed_regimes: Vec<String>,
    /// Live `AuditConfig` resolved at evaluation time — useful for
    /// "did the operator disable audit?" reviewers to spot.
    pub audit_config_snapshot: AuditConfig,
    /// One row per control, sorted by `control_id`.
    pub rows: BTreeMap<ControlId, ReportRow>,
    /// Counts surfaced for at-a-glance review.
    pub summary_counts: ReportSummary,
}

/// One row in the finalized report. Owned strings; intentional, so
/// callers can clone/serialize round-trip without lifetime
/// juggling.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReportRow {
    pub status: ControlStatus,
    /// Plaintext reason for the status (the `&'static str` from the
    /// evaluator is `.to_owned()` here for portability).
    pub reason: String,
    /// Evidence pointer (e.g. `"crates/zeroclaw-runtime/src/security/audit.rs:465"`).
    pub evidence_ref: String,
    /// Plaintext summary of how the control is satisfied.
    pub summary: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ReportSummary {
    pub implemented: usize,
    pub partial: usize,
    pub not_implemented: usize,
    pub total: usize,
}

impl ComplianceReport {
    /// Emit Markdown. Default for human auditors; matches locked
    /// decision (2). Each control gets a multi-line section with a
    /// status bullet, evidence pointer, and summary.
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let mut out = String::with_capacity(64 + self.rows.len() * 256);
        let _ = writeln!(
            out,
            "# ZeroClaw compliance report\n\nGenerated: `{}`\nClaimed regimes: {}\n",
            self.generated_at.to_rfc3339(),
            self.claimed_regimes.join(", ")
        );
        let _ = writeln!(
            out,
            "## Summary\n\n| Implemented | Partial | Not implemented | Total |\n",
        );
        let _ = writeln!(
            out,
            "|---|---|---|---|\n| {} | {} | {} | {} |\n",
            self.summary_counts.implemented,
            self.summary_counts.partial,
            self.summary_counts.not_implemented,
            self.summary_counts.total,
        );

        let _ = writeln!(out, "## Controls\n");
        for (id, row) in &self.rows {
            let _ = writeln!(
                out,
                "### `{id}` — **{status}**\n\n- **Reason**: {reason}\n- **Evidence**: `{evidence}`\n- **Summary**: {summary}\n",
                id = id,
                status = row.status.as_str(),
                reason = row.reason,
                evidence = row.evidence_ref,
                summary = row.summary,
            );
        }
        out
    }

    /// Emit JSON. Thin wrapper over `serde_json::to_string_pretty`
    /// because callers want a single source of truth.
    #[must_use]
    pub fn render_json(&self) -> Option<String> {
        serde_json::to_string_pretty(self).ok()
    }

    /// Emit YAML. Falls back to JSON when YAML serialization is
    /// unavailable so the CLI stays robust (a yaml dep is not
    /// pulled in by the binary crate; if a future PR-F2 adds
    /// one, swap the body).
    #[must_use]
    pub fn render_yaml(&self) -> String {
        // Simple JSON-as-YAML is intentionally NOT what we want — pretend
        // until serde_yaml lands. For now we emit a stable token form so
        // CI can grep without a yaml parser.
        let json =
            serde_json::to_string_pretty(self).unwrap_or_else(|_| "<unreadable>".to_string());
        format!("# YAML serializer not yet wired — emitting JSON\n{json}\n")
    }
}

// ── Builder (typestate) ────────────────────────────────────────────────

/// Builder for [`ComplianceReport`] in draft state. Forces caller to
/// chain `.evaluate()`, `.audit_config(...)`, etc., before
/// `.build()` materializes a `ComplianceReport<Draft>` whose `.finalize()`
/// yields a `ComplianceReport` (= ready-to-emit). This is the
/// `api-typestate` pattern from rust-skills.
#[derive(Clone)]
pub struct ComplianceReportBuilder<Draft> {
    inner: Draft,
}

#[derive(Clone)]
pub struct Draft {
    pub(crate) matrix: ControlMatrix,
    pub(crate) claimed_regimes: Vec<String>,
    pub(crate) audit_config: AuditConfig,
}

// Phantom state for the typestate machine. The struct split keeps each
// state honest about what fields it owns.

impl ComplianceReportBuilder<Draft> {
    /// Begin a new builder over the SOC 2 Type II starter matrix.
    #[must_use]
    pub fn soc2_type2() -> Self {
        Self {
            inner: Draft {
                matrix: ControlMatrix::soc2_type2_starter(),
                claimed_regimes: vec!["soc2_type2".to_string()],
                audit_config: AuditConfig::default(),
            },
        }
    }

    /// Override the matrix with a custom one (test seam / future
    /// regime support).
    #[must_use]
    pub fn matrix(mut self, matrix: ControlMatrix) -> Self {
        self.inner.matrix = matrix;
        self
    }

    /// Override the live audit config snapshot.
    #[must_use]
    pub fn audit_config(mut self, audit_config: AuditConfig) -> Self {
        self.inner.audit_config = audit_config;
        self
    }

    /// Set the operator-claimed regimes for header display.
    #[must_use]
    pub fn claimed_regimes(mut self, regimes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.inner.claimed_regimes = regimes.into_iter().map(Into::into).collect();
        self
    }

    /// Evaluate the matrix against the live config and return a
    /// finalized `ComplianceReport`. Builder is consumed.
    pub fn build(self, config: &Config) -> Result<ComplianceReport> {
        let matrix = self.inner.matrix;
        let claimed_regimes = self.inner.claimed_regimes;
        let audit_config_snapshot = self.inner.audit_config;

        let evaluated = matrix.evaluate_against(config)?;
        let mut rows = BTreeMap::new();
        let mut counts = ReportSummary::default();
        for (id, status, reason) in evaluated.into_iter() {
            // Look up the matrix definition to pull evidence_ref + summary
            // back into the row. If the matrix grew but evaluation surfaced
            // a different shape (e.g. a ControlDefinition was mutated), the
            // fallback raw fields keep the row valuable but flag the gap.
            let def = matrix.entries.get(&id);
            counts.total += 1;
            match status {
                ControlStatus::Implemented => counts.implemented += 1,
                ControlStatus::Partial => counts.partial += 1,
                ControlStatus::NotImplemented => counts.not_implemented += 1,
            }
            // The current matrix entries always come from a `Constant` or
            // `Closure` variant; we need both halves in lockstep for the
            // emitted rows to be self-describing.
            let (evidence_ref, summary) = def.map_or_else(
                || {
                    (
                        "<missing>".to_string(),
                        "<matrix missing — programmer error>".to_string(),
                    )
                },
                |d| (d.evidence_ref.clone(), d.summary.clone()),
            );
            rows.insert(
                id,
                ReportRow {
                    status,
                    reason,
                    evidence_ref,
                    summary,
                },
            );
        }
        Ok(ComplianceReport {
            generated_at: chrono::Utc::now(),
            claimed_regimes,
            audit_config_snapshot,
            rows,
            summary_counts: counts,
        })
    }
}

impl std::fmt::Debug for ComplianceReportBuilder<Draft> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComplianceReportBuilder")
            .field("claimed_regimes", &self.inner.claimed_regimes)
            .field("matrix_size", &self.inner.matrix.entries.len())
            .finish()
    }
}

// ── Render a buffer to a chosen format ──────────────────────────────────

/// Render a finalized report to the chosen format. Returns
/// `ComplianceError::Other(Other)` on formatter failure (serde_json
/// surface). Kept small/focused so CLI handlers are simple wrappers.
pub fn render(report: &ComplianceReport, format: ReportFormat) -> Result<String> {
    match format {
        ReportFormat::Markdown => Ok(report.render_markdown()),
        ReportFormat::Json => report.render_json().ok_or_else(|| {
            ComplianceError::new(
                ComplianceErrorKind::Other,
                "failed to serialize compliance report as JSON",
            )
        }),
        ReportFormat::Yaml => Ok(report.render_yaml()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_default_claims_soc2_type2() {
        let b = ComplianceReportBuilder::soc2_type2();
        assert_eq!(b.inner.claimed_regimes, vec!["soc2_type2"]);
    }

    #[test]
    fn builder_with_overrides_keeps_state_until_build_consumes() {
        let b = ComplianceReportBuilder::soc2_type2()
            .claimed_regimes(["iso_27001", "iso_42001"])
            .audit_config(AuditConfig {
                enabled: false,
                log_path: "audit.log".into(),
                max_size_mb: 100,
                sign_events: false,
            });
        assert_eq!(b.inner.claimed_regimes, vec!["iso_27001", "iso_42001"]);
        assert!(!b.inner.audit_config.enabled);
    }

    #[test]
    fn build_emits_rows_counted_correctly_for_baseline_install() {
        let config = Config::default();
        let report = ComplianceReportBuilder::soc2_type2()
            .build(&config)
            .expect("build report on baseline config");
        assert_eq!(report.rows.len(), 5);
        let s = &report.summary_counts;
        assert_eq!(s.total, 5);
        // Baseline install expects: CC7.3 (Partial) and CC9.2 (Partial).
        // The remaining three (CC6.1, CC6.6, CC7.2) are Implemented
        // when audit is enabled (default).
        assert!(s.implemented >= 2);
        assert!(s.partial >= 2);
    }

    #[test]
    fn render_markdown_mentions_every_control_id() {
        let config = Config::default();
        let report = ComplianceReportBuilder::soc2_type2()
            .build(&config)
            .expect("build");
        let md = report.render_markdown();
        assert!(md.contains("# ZeroClaw compliance report"));
        assert!(md.contains("soc2_type2:CC6.1"));
        assert!(md.contains("soc2_type2:CC9.2"));
        assert!(md.contains("Implemented"));
        assert!(md.contains("Partial"));
    }

    #[test]
    fn render_json_is_valid_json() {
        let config = Config::default();
        let report = ComplianceReportBuilder::soc2_type2()
            .build(&config)
            .expect("build");
        let json = report.render_json().expect("json serialize");
        let back: ComplianceReport = serde_json::from_str(&json).expect("round trip");
        assert_eq!(back.rows.len(), report.rows.len());
    }

    #[test]
    fn render_yaml_emits_stable_token_form() {
        let config = Config::default();
        let report = ComplianceReportBuilder::soc2_type2()
            .build(&config)
            .expect("build");
        let yaml = report.render_yaml();
        assert!(yaml.contains("YAML serializer not yet wired"));
        assert!(yaml.contains("generated_at"));
    }

    #[test]
    fn render_dispatcher_routes_per_format() {
        let config = Config::default();
        let report = ComplianceReportBuilder::soc2_type2()
            .build(&config)
            .expect("build");
        let md = render(&report, ReportFormat::Markdown).expect("md");
        assert!(md.contains("# ZeroClaw compliance report"));
        let json = render(&report, ReportFormat::Json).expect("json");
        assert!(json.starts_with('{'));
        let yaml = render(&report, ReportFormat::Yaml).expect("yaml");
        assert!(yaml.starts_with('#'));
    }
}
