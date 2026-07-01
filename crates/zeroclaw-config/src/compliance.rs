//! Enterprise compliance posture configuration (PR-F).
//!
//! Source of truth for operator-declared compliance regimes, audit retention
//! floors, kill-switch signer credential classification, and AI-BOM refresh
//! cadence. Consumed live by `zeroclaw compliance report` and the
//! `compliance audit-trail`/`compliance ai-bom` subcommands.
//!
//! Per PR-E and AGENTS.md §"Single Source of Truth": every credential-shaped
//! field carries `#[secret]` + `#[credential_class = "encrypted_secret"]` +
//! manual `Debug` redaction. The existing
//! `credential_shaped_prop_fields_have_explicit_classification` test in
//! `schema.rs` enforces this for any new field at compile time.
//!
//! This module is `pub(crate)` so the secret-bearing structs can't leak
//! outside the config crate's surface (operator-facing tooling in `src/`
//! reaches them via the typed API on `Config`).

use serde::{Deserialize, Serialize};

/// Compliance regimes an operator may declare a deployment implements.
///
/// `Soc2Type2` lands in PR-F; the additional variants stay
/// `#[non_exhaustive]` so future epics (`PR-F2`+) extend the enum without
/// breaking external call sites.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    zeroclaw_macros::ConfigEnum,
)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ComplianceRegime {
    /// AICPA Trust Services Criteria — SOC 2 Type II (security, availability,
    /// processing integrity, confidentiality, privacy). PR-F initial scope.
    #[default]
    Soc2Type2,
    /// ISO/IEC 27001:2022 — Information Security Management System.
    /// Roadmap (PR-F2).
    Iso27001,
    /// ISO/IEC 42001:2023 — AI Management System. Roadmap (PR-F2).
    Iso42001,
    /// OWASP Top 10 for Agentic Applications. Roadmap (PR-F2).
    OwaspAgenticAi,
}

/// Operator-signed credential accepted by the kill-switch resume flow.
///
/// Carries an HMAC-over-key or SSH-key reference and an opaque signer
/// identifier. The credential itself is never serialized as plaintext to
/// disk; `SecretStore::encrypt` produces the on-disk form (`enc2:`-prefixed
/// hex ciphertext).
///
/// **This is the single source of truth for a kill-switch signer credential.**
/// Do not duplicate this shape elsewhere.
#[derive(Clone, Serialize, Deserialize, zeroclaw_macros::Configurable)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[natural_key = "signer_id"]
pub struct KillSwitchSigner {
    /// Opaque operator identifier (e.g. `"ops-primary"`).
    pub signer_id: String,
    /// Encrypted credential reference (HMAC-SHA256 key, SHA-256 of an SSH pubkey,
    /// or external reference such as `op://` / `vault://`). The plaintext form
    /// lives only in memory after `SecretStore::decrypt`.
    #[secret]
    #[credential_class = "encrypted_secret"]
    pub credential_ref: String,
}

impl std::fmt::Debug for KillSwitchSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KillSwitchSigner")
            .field("signer_id", &self.signer_id)
            .field("credential_ref", &"[REDACTED]")
            .finish()
    }
}

/// Top-level compliance posture configuration (`[compliance]`).
///
/// Loaded by `Configurable` derive at config-load time. Whether or not this
/// block exists, `compliance report` always answers (the report's
/// `regime_coverage` field exposes which regimes the operator has declared).
#[derive(Debug, Clone, Default, Serialize, Deserialize, zeroclaw_macros::Configurable)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[prefix = "compliance"]
pub struct ComplianceConfig {
    /// Regimes the operator's deployment claims to satisfy. Empty =
    /// `"baseline"` (no formal claim); non-empty triggers the matching
    /// control-matrix evaluation in `compliance report`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regimes: Vec<ComplianceRegime>,

    /// Audit-log retention floor (days). Drives the audit-log rotation
    /// policy: rotated files older than this are eligible for compaction.
    /// `0` disables explicit retention (rotated logs grow unbounded).
    #[serde(default = "default_audit_retention_days")]
    pub audit_retention_days: u32,

    /// Kill-switch signer credentials accepted by `estop resume`. Empty
    /// means the kill-switch can be engaged with the local API but only
    /// the operator on-host shell can resume without an external signer
    /// (intentionally restrictive default).
    ///
    /// `#[nested]` is required so the `Configurable` derive's
    /// `encrypt_secrets` / `decrypt_secrets` recursion reaches each
    /// `KillSwitchSigner.credential_ref`. Without `#[nested]` the macro
    /// treats the field as opaque and the plaintext value would survive
    /// `Config::save()`. The save/readback regression test
    /// `compliance_kill_switch_signer_round_trips_encrypted` pins this.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[nested]
    #[natural_key = "signer_id"]
    pub kill_switch_signers: Vec<KillSwitchSigner>,

    /// AI-BOM refresh cadence (cron-style 5-field expression). `null` =
    /// manual refresh only. Consumed by `compliance ai-bom` and any future
    /// scheduled blow-up. PR-F informational; PR-F2 wires the scheduler.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_bom_refresh: Option<String>,
}

fn default_audit_retention_days() -> u32 {
    365
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_compliance_config_is_baseline() {
        let cfg = ComplianceConfig::default();
        assert!(cfg.regimes.is_empty(), "no regimes by default");
        assert_eq!(cfg.audit_retention_days, 365);
        assert!(cfg.kill_switch_signers.is_empty());
        assert!(cfg.ai_bom_refresh.is_none());
    }

    #[test]
    fn kill_switch_signer_debug_redacts_credential() {
        let s = KillSwitchSigner {
            signer_id: "ops-primary".into(),
            credential_ref: "sk-very-secret-do-not-leak".into(),
        };
        let rendered = format!("{s:?}");
        assert!(rendered.contains("ops-primary"));
        assert!(!rendered.contains("sk-very-secret-do-not-leak"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn compliance_regime_serializes_snake_case() {
        let j = serde_json::to_string(&ComplianceRegime::Soc2Type2).expect("serialize");
        assert_eq!(j, "\"soc2_type2\"");
        let j = serde_json::to_string(&ComplianceRegime::OwaspAgenticAi).expect("serialize");
        assert_eq!(j, "\"owasp_agentic_ai\"");
    }

    #[test]
    fn compliance_regime_roundtrips_through_json() {
        for r in [
            ComplianceRegime::Soc2Type2,
            ComplianceRegime::Iso27001,
            ComplianceRegime::Iso42001,
            ComplianceRegime::OwaspAgenticAi,
        ] {
            let s = serde_json::to_string(&r).expect("serialize");
            let back: ComplianceRegime = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(r, back);
        }
    }

    #[test]
    fn compliance_config_skip_serializing_if_empty_fixtures_hold() {
        let mut cfg = ComplianceConfig::default();
        assert!(cfg.kill_switch_signers.is_empty());
        // Add a signer and confirm the round-trip preserves it.
        cfg.kill_switch_signers.push(KillSwitchSigner {
            signer_id: "ops-1".into(),
            credential_ref: "enc2:deadbeef".into(),
        });
        let j = serde_json::to_string(&cfg).expect("serialize");
        assert!(j.contains("ops-1"));
        let back: ComplianceConfig = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(back.kill_switch_signers.len(), 1);
        assert_eq!(back.kill_switch_signers[0].signer_id, "ops-1");
    }
}
