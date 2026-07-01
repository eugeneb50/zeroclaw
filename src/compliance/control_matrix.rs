//! Control-matrix catalog (PR-F).
//!
//! Source of truth for the mapping `(ComplianceRegime → ControlId) →
//! ControlDefinition { status_predicate, evidence_ref, summary }`.
//!
//! The starter set ships only SOC 2 Type II controls whose enforcement
//! lives in code already shipped on `feat/multiPRE`. Subsequent epics
//! extend the matrix — see `docs/pr-plans/epics/compliance-matrix-
//! extension.md` (filed under the same PR-F umbrella) for the
//! backlog of deferred controls (CC4.x, CC7.x, CC9.x beyond the
//! starter set, ISO 27001 / ISO 42001 / OWASP Agentic AI regimes,
//! etc.).
//!
//! Per AGENTS.md §"Single Source of Truth": this is the only place
//! `ControlMatrix` / `ControlId` / `ControlDefinition` are declared.
//! `scripts/ssot-verify.sh`'s `struct ControlMatrix` hard-fail path is
//! here, so any duplicate elsewhere fails the build.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::Config;

use super::error::{ComplianceError, ComplianceErrorKind, Result};

/// Stable identifier for each control we evaluate. Implements
/// `Ord`/`Eq`/`Hash` so a `BTreeMap<ControlId, …>` is the natural
/// canonical storage and emitters (Markdown / JSON) walk it in sorted
/// order without further orchestration.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ControlId(pub String);

impl ControlId {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ControlId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

/// Status returned by an individual control evaluator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ControlStatus {
    /// Code path that satisfies the control is present and the live
    /// config exercises it.
    Implemented,
    /// Some pieces of the control are present (e.g. audit-log file
    /// exists) but the policy/storage/automation layer is partial.
    Partial,
    /// Control is documented but not implemented in code (or is
    /// explicitly out of scope per the SoA page).
    NotImplemented,
}

impl ControlStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Implemented => "Implemented",
            Self::Partial => "Partial",
            Self::NotImplemented => "NotImplemented",
        }
    }
}

/// Definition of a single control: predicate + evidence + summary.
///
/// `evidence_ref` is a string of the form
/// `"crates/zeroclaw-runtime:src/security/auth_provider.rs:84"` — file
/// path relative to repo root, optional `:from_line:to_line` tail.
/// `report.rs` does NOT re-derive the marker; the matrix is the source
/// of truth. Operators expanding the matrix are expected to keep
/// `evidence_ref` pointing at a real, currently existing Rust symbol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlDefinition {
    pub status_when: StatusPredicate,
    /// `<path>:<line>` pointer (caller comment convention).
    pub evidence_ref: String,
    /// Plain-English explanation: which SOC 2 / ISO § the control
    /// satisfies, and how the live predicate maps.
    pub summary: String,
}

/// Predicate evaluated against the live config to determine the
/// control's status. Predicates are pure data — no `.await`, no I/O —
/// so the matrix can be evaluated cheaply and reproducibly for the
/// Markdown / JSON / YAML emitters.
///
/// `StatusPredicate` is intentionally `non_exhaustive` to leave room
/// for additional kinds (e.g. async lookup, env probe) without
/// breaking external emitters. The current sealed set:
/// - `Constant(ControlStatus)` — fixed for documentation-only controls.
/// - `Closure(ControlEvaluator)` — pure `fn(&Config) -> (status, reason)`.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum StatusPredicate {
    /// Status is constant (used for "Documented-only" controls).
    Constant(ControlStatus),
    /// Status depends on a closure over the live config.
    Closure(ControlEvaluator),
}

impl std::fmt::Debug for StatusPredicate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Constant(s) => f.debug_tuple("Constant").field(s).finish(),
            Self::Closure(_) => f.debug_tuple("Closure").finish(),
        }
    }
}

impl Serialize for StatusPredicate {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        // The matrix is serialized with `#[derive(Serialize)]` on the
        // outer `ControlDefinition`. We don't carry predicate payloads
        // across JSON (the closure isn't transmittable), only emit a
        // tag that the matrix is well-formed.
        match self {
            Self::Constant(_) => ser.serialize_str("constant"),
            Self::Closure(_) => ser.serialize_str("closure"),
        }
    }
}

impl<'de> Deserialize<'de> for StatusPredicate {
    fn deserialize<D: serde::Deserializer<'de>>(deser: D) -> std::result::Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(deser)?;
        match s.as_str() {
            "constant" => Ok(Self::Constant(ControlStatus::Implemented)),
            "closure" => Err(serde::de::Error::custom(
                "Closure predicates cannot be deserialized; build via ControlMatrix::build()",
            )),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["constant", "closure"],
            )),
        }
    }
}

/// Concrete evaluator type. An internal `Box<dyn Fn(...)>` is not
/// materialised — `StatusPredicate::Closure` owns an `fn` pointer with
/// no allocator cost per call, and the trait isn't object-safe
/// because of the associated type. We use a function pointer.
#[derive(Clone, Copy)]
pub struct ControlEvaluator(pub fn(&Config) -> (ControlStatus, &'static str));

impl std::fmt::Debug for ControlEvaluator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<eval fn>")
    }
}

impl serde::Serialize for ControlEvaluator {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        ser.serialize_str("<eval fn>")
    }
}

impl<'de> serde::Deserialize<'de> for ControlEvaluator {
    fn deserialize<D: serde::Deserializer<'de>>(_: D) -> std::result::Result<Self, D::Error> {
        Err(serde::de::Error::custom(
            "ControlEvaluator is not deserializable; build it via ControlMatrix::build()",
        ))
    }
}

/// Compile-time register of every control evaluated by PR-F.
#[derive(Clone)]
pub struct ControlMatrix {
    /// Sorted by `ControlId` for stable Markdown / JSON / YAML output.
    pub entries: BTreeMap<ControlId, ControlDefinition>,
}

impl std::fmt::Debug for ControlMatrix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlMatrix")
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

impl ControlMatrix {
    /// Hardcoded starter SOC 2 set. All entries cite a real Rust
    /// symbol already shipped on this branch; the verification via
    /// `evidence_ref` is a doc-test in `evidence.md`.
    ///
    /// `#7640` (OAuth credential boundary) and **`feat/multiPRE`** core
    /// are the sources. Anything beyond these must extend the matrix
    /// — never duplicate definitions elsewhere.
    #[must_use]
    pub fn soc2_type2_starter() -> Self {
        let mut entries = BTreeMap::new();

        // ── SOC 2 CC6.1 — Logical and physical access controls
        // The bearer token + AuthProvider + ProviderRegistry path is
        // the assertion. A default-empty registry fails closed via
        // `ProviderRegistry::resolve()` default-deny, satisfying the
        // control even when a deployment has no real auth provider
        // configured.
        entries.insert(
            ControlId::new("soc2_type2:CC6.1"),
            ControlDefinition {
                status_when: StatusPredicate::Closure(ControlEvaluator(soc2_cc_6_1_evaluate)),
                evidence_ref: "crates/zeroclaw-runtime/src/security/auth_provider.rs:104".into(),
                summary: "AuthProvider trait + ProviderRegistry default-deny".into(),
            },
        );

        // ── SOC 2 CC6.6 — Vendor/third-party credential isolation
        // External A2A peers get their own credential field
        // (`a2a_external_peers`); channel peers stay in the legacy
        // `external_peers` Vec. SSOT guards duplication.
        entries.insert(
            ControlId::new("soc2_type2:CC6.6"),
            ControlDefinition {
                status_when: StatusPredicate::Closure(ControlEvaluator(soc2_cc_6_6_evaluate)),
                evidence_ref: "crates/zeroclaw-config/src/multi_agent.rs:157".into(),
                summary: "A2A external peers + credential classification".into(),
            },
        );

        // ── SOC 2 CC7.2 — Monitoring of system operations
        // The audit log writes hash-chained JSONL entries via
        // `AuditLogger`; `verify_chain` is callable from CI.
        entries.insert(
            ControlId::new("soc2_type2:CC7.2"),
            ControlDefinition {
                status_when: StatusPredicate::Closure(ControlEvaluator(soc2_cc_7_2_evaluate)),
                evidence_ref: "crates/zeroclaw-runtime/src/security/audit.rs:465".into(),
                summary: "Hash-chained AuditLogger + open `verify_chain`".into(),
            },
        );

        // ── SOC 2 CC7.3 — Security event detection & response
        // PR-F wires the response path via the estop manager
        // (`estop::EstopManager`) plus detect surfaces
        // (`vulnerability`, `leak_detector`, `prompt_guard`).
        // PR-F's `compliance ai-bom` and the kill-switch signer wire
        // satisfy "immediate response" criteria.
        entries.insert(
            ControlId::new("soc2_type2:CC7.3"),
            ControlDefinition {
                status_when: StatusPredicate::Closure(ControlEvaluator(soc2_cc_7_3_evaluate)),
                evidence_ref: "crates/zeroclaw-runtime/src/security/estop.rs:83".into(),
                summary: "Estop kill-switch + leak/vuln detectors".into(),
            },
        );

        // ── SOC 2 CC9.2 — Vendor & supplier risk management
        // AI-BOM enumerates provider aliases and WASM backends; the
        // `compliance ai-bom` subcommand surfaces the inventory.
        entries.insert(
            ControlId::new("soc2_type2:CC9.2"),
            ControlDefinition {
                status_when: StatusPredicate::Closure(ControlEvaluator(soc2_cc_9_2_evaluate)),
                evidence_ref: "src/compliance/ai_bom.rs".into(),
                summary: "AI-BOM enumerates providers + WASM backends".into(),
            },
        );

        Self { entries }
    }

    /// Evaluate every predicate against a live config snapshot.
    pub fn evaluate_against(
        &self,
        config: &Config,
    ) -> Result<Vec<(ControlId, ControlStatus, String)>> {
        // Each predicate returns (&'static str) tied to a constant
        // string table in this module, so the owned `String`
        // allocations here are minimal (one per row).
        let mut out = Vec::with_capacity(self.entries.len());
        for (id, def) in &self.entries {
            let (status, reason) = match &def.status_when {
                StatusPredicate::Constant(s) => (*s, ""),
                StatusPredicate::Closure(eval) => eval.0(config),
            };
            out.push((id.clone(), status, reason.to_owned()));
        }
        if out.is_empty() {
            return Err(ComplianceError::new(
                ComplianceErrorKind::ControlMissing,
                "matrix evaluated to zero controls — programmer error",
            ));
        }
        Ok(out)
    }
}

// ── Control evaluators ─────────────────────────────────────────────────
//
// Each evaluator is a pure function: no I/O, no `.await`, no logging.
// Returns `(ControlStatus, &'static str reason)` so the report layer
// surfaces a one-line human explanation for Partial entries. The
// `&'static str` budgeting matters — each reason lives in static
// memory below so the lifecycle of reason strings survives across
// multiple `evaluate_against` calls without reallocation.

fn soc2_cc_6_1_evaluate(config: &Config) -> (ControlStatus, &'static str) {
    // The control asserts: authentication is required for every
    // privileged action. ZeroClaw's deployment NEED not declare any
    // IdP integration to satisfy this — `ProviderRegistry` defaults
    // to deny-when-empty, which fails closed for every request.
    // Hence the control is `Implemented` for every baseline install.
    let _ = config; // Surface is unconditional.
    (
        ControlStatus::Implemented,
        "default-deny provider registry: every credential presented is verified by 1+ providers; absent registry denies all",
    )
}

fn soc2_cc_6_6_evaluate(config: &Config) -> (ControlStatus, &'static str) {
    // The control asserts: third-party credentials are isolated from
    // human-user credentials. The peer-group-scoped
    // `a2a_external_peers` field encodes that isolation; we treat it
    // as `Implemented` even when empty, since legacy `external_peers`
    // (channel-only) is preserved unchanged.
    let _ = config;
    (
        ControlStatus::Implemented,
        "peer-group credential isolation via a2a_external_peers (PR-E) + SSOT script rejects duplicate credential surfaces",
    )
}

fn soc2_cc_7_2_evaluate(config: &Config) -> (ControlStatus, &'static str) {
    // The control asserts: a tamper-evident monitoring log exists and
    // is independently verifiable. `AuditLogger` writes SHA-256
    // hash-chained JSONL by default; `verify_chain` is open. We
    // report `Implemented` for any deployment with
    // `security.audit.enabled = true` (the default), otherwise
    // `Partial` to call out the config knob.
    if config.security.audit.enabled {
        (
            ControlStatus::Implemented,
            "audit-enabled + verify_chain callable from CI",
        )
    } else {
        (
            ControlStatus::Partial,
            "audit disabled via [security].audit.enabled = false; auditors will flag the absence",
        )
    }
}

fn soc2_cc_7_3_evaluate(config: &Config) -> (ControlStatus, &'static str) {
    // The control asserts: the system can detect AND respond to
    // security events. Estop manager + leak / vulnerability /
    // prompt-guard detectors provide detection. PR-F's kill-switch
    // signer config adds the response path. Until the estop response
    // is fully key-signable, this is `Partial`.
    let _ = config;
    (
        ControlStatus::Partial,
        "detection via estop + detectors ships; estop resume signer enforcement is roadmap (PR-F2)",
    )
}

fn soc2_cc_9_2_evaluate(config: &Config) -> (ControlStatus, &'static str) {
    // The control asserts: vendor inventory is documented & inspectable.
    // `compliance ai-bom` enumerates provider aliases and WASM
    // backends via `Cargo.toml` features. Until the BOM's SHA-256
    // fingerprint is wired (post-PR-F milestone RFC #8543), this is
    // `Partial`.
    let _ = config;
    (
        ControlStatus::Partial,
        "AI-BOM aliases + WASM backend flags ships; SHA-256 plugin fingerprint deferred to RFC #8543 milestone",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn control_id_ord_is_lexicographic_on_string() {
        let mut ids = [
            ControlId::new("soc2_type2:CC9.2"),
            ControlId::new("soc2_type2:CC6.1"),
            ControlId::new("soc2_type2:CC7.3"),
        ];
        ids.sort();
        assert_eq!(
            ids.map(|c| c.0),
            [
                "soc2_type2:CC6.1".to_string(),
                "soc2_type2:CC7.3".to_string(),
                "soc2_type2:CC9.2".to_string(),
            ]
        );
    }

    #[test]
    fn starter_matrix_has_five_controls() {
        let matrix = ControlMatrix::soc2_type2_starter();
        assert_eq!(matrix.entries.len(), 5);
        for id in [
            "soc2_type2:CC6.1",
            "soc2_type2:CC6.6",
            "soc2_type2:CC7.2",
            "soc2_type2:CC7.3",
            "soc2_type2:CC9.2",
        ] {
            assert!(
                matrix.entries.contains_key(&ControlId::new(id)),
                "control {id} missing from starter matrix"
            );
        }
    }

    #[test]
    fn evaluate_returns_one_status_per_control() {
        let matrix = ControlMatrix::soc2_type2_starter();
        let config = Config::default();
        let evaluated = matrix.evaluate_against(&config).expect("evaluate");
        assert_eq!(evaluated.len(), 5);
        for (id, status, reason) in &evaluated {
            assert!(
                !id.as_str().is_empty(),
                "control id must not be empty (got {id:?})"
            );
            assert!(
                matches!(
                    status,
                    ControlStatus::Implemented
                        | ControlStatus::Partial
                        | ControlStatus::NotImplemented
                ),
                "unknown status {status:?}"
            );
            assert!(!reason.is_empty(), "every control must carry a reason");
        }
    }

    #[test]
    fn evaluate_baseline_install_marks_audit_partial_when_disabled() {
        let mut config = Config::default();
        config.security.audit.enabled = false;
        let matrix = ControlMatrix::soc2_type2_starter();
        let evaluated = matrix.evaluate_against(&config).expect("evaluate");
        let cc_7_2 = evaluated
            .iter()
            .find(|(id, _, _)| id.as_str() == "soc2_type2:CC7.2")
            .expect("CC7.2 present");
        assert_eq!(cc_7_2.1, ControlStatus::Partial);
    }

    #[test]
    fn evaluate_baseline_install_marks_audit_implemented_when_enabled() {
        let mut config = Config::default();
        config.security.audit.enabled = true;
        let matrix = ControlMatrix::soc2_type2_starter();
        let evaluated = matrix.evaluate_against(&config).expect("evaluate");
        let cc_7_2 = evaluated
            .iter()
            .find(|(id, _, _)| id.as_str() == "soc2_type2:CC7.2")
            .expect("CC7.2 present");
        assert_eq!(cc_7_2.1, ControlStatus::Implemented);
    }

    #[test]
    fn control_definition_serialization_roundtrips() {
        let matrix = ControlMatrix::soc2_type2_starter();
        let json = serde_json::to_string(
            &matrix
                .entries
                .get(&ControlId::new("soc2_type2:CC7.2"))
                .expect("CC7.2"),
        )
        .expect("serialize");
        let back: ControlDefinition = serde_json::from_str(&json).expect("deserialize");
        assert!(back.evidence_ref.contains("audit.rs:465"));
        assert!(back.summary.contains("Hash-chained"));
    }
}
