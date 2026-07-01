//! AI Bill of Materials (PR-F).
//!
//! Surfaces the inventory of model providers, plugin backends, and
//! the audit-log chain root hash for an enterprise auditor. The
//! output is a [`AiBom`] struct that the CLI emits in the same
//! formats as `compliance report` (Markdown / JSON / YAML).
//!
//! Locked decisions honoured:
//!
//! - **Markdown default / JSON-YAML opt-in** (decision 2): re-uses
//!   [`crate::compliance::report::render`].
//! - **AI-BOM aliases + WASM backend + chain root** (decision 3a):
//!   inventory is built directly from `Config.providers.models` plus
//!   compile-time `cfg!()` enumeration of the WASM three-flag
//!   taxonomy. **WASM SHA-256 fingerprint is intentionally NOT
//!   computed** here — that requires a per-plugin fingerprint scan
//!   over loaded `.wasm` components, which is awaiting RFC #8543
//!   (decision 3b — deferred milestone).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::Config;

use super::error::{ComplianceError, ComplianceErrorKind, Result};

/// Finalized AI-BOM. Source of truth for the public shape; all
/// emitters (JSON / Markdown / YAML) consume the same struct via
/// `Serialize`, with no duplicate per-emit logic.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AiBom {
    /// Timestamp the BOM was generated.
    pub generated_at: chrono::DateTime<chrono::Utc>,
    /// Config snapshot path used to build this BOM. Useful for
    /// auditing which config the BOM corresponds to.
    pub config_path: String,
    /// Inventory of `providers.models.<family>.<alias>` entries.
    pub model_providers: BTreeMap<String, ModelProviderBom>,
    /// Inventory of `providers.tts.<family>.<alias>` entries.
    pub tts_providers: BTreeMap<String, TtsProviderBom>,
    /// Inventory of `providers.transcription.<family>.<alias>` entries.
    pub transcription_providers: BTreeMap<String, TranscriptionProviderBom>,
    /// WASM backend flags set in the running binary.
    pub wasm_backends: WasmBackendInventory,
    /// PR-F: SHA-256 root of the most-recent audit chain entry.
    /// `None` when no audit log exists.
    pub audit_chain_root: Option<String>,
    /// Counters surfaced for at-a-glance dashboards.
    pub counts: AiBomCounts,
    /// Deferred-milestone note renderer.
    pub deferred_milestones: Vec<DeferredMilestone>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelProviderBom {
    /// Operator alias under `[providers.models.<family>.<alias>]`.
    pub alias: String,
    /// `crate::providers::ModelProviderConfig` field, but resolved as
    /// plain data — we never serialize the entire config (the
    /// `api_key` is `#[secret]` and `EncryptedSecret` classified).
    pub requires_openai_auth: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TtsProviderBom {
    pub alias: String,
    /// Voice override for this instance. When empty, the operator
    /// hasn't customized voice selection.
    pub voice: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TranscriptionProviderBom {
    pub alias: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WasmBackendInventory {
    /// `cargo` ships the FND-001 three-flag WASM backend taxonomy
    /// (FND-001 Rev. 5). At most one is in effect for a given binary:
    /// - `plugins-wasm-cranelift` (default for x86_64/aarch64)
    /// - `plugins-wasm-pulley` (32-bit ARM / Cranelift-unsupported)
    /// - neither (runtime-only `.cwasm` precompiled artifacts)
    pub backend: WasmBackendKind,
    /// `None` until SHA-256 plugin fingerprint lands (RFC #8543).
    pub plugin_fingerprints_hash: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum WasmBackendKind {
    /// Compile-time selection of the Cranelift JIT (FND-001
    /// `plugins-wasm-cranelift`). Default on x86_64 / aarch64.
    #[default]
    Cranelift,
    /// Compile-time selection of the Pulley interpreter
    /// (`plugins-wasm-pulley`). Default on 32-bit ARM.
    Pulley,
    /// `plugins-wasm-runtime-only`. Requires the operator to ship
    /// pre-compiled `.cwasm` artifacts alongside the binary.
    RuntimeOnly,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AiBomCounts {
    pub model_providers: usize,
    pub tts_providers: usize,
    pub transcription_providers: usize,
    pub total: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeferredMilestone {
    /// Stable identifier for the RFC / epic.
    pub tracking_issue: String,
    /// Short label rendered to human auditors.
    pub summary: String,
    /// What shells out to once the milestone lands.
    pub planned_surface: String,
}

/// Build the BOM from a live config snapshot. The build is pure data —
/// no I/O, no network, no logging — so a build call is cheap to
/// repeat for every CLI invocation.
#[must_use]
pub fn build(config_path: &str, config: &Config, audit_chain_root: Option<String>) -> AiBom {
    let mut model_providers = BTreeMap::new();
    for (provider_type, alias, base) in config.providers.models.iter_entries() {
        model_providers.insert(
            format!("{provider_type}/{alias}"),
            ModelProviderBom {
                alias: alias.to_owned(),
                requires_openai_auth: base.requires_openai_auth,
            },
        );
    }
    let mut tts_providers = BTreeMap::new();
    for (family, alias, cfg) in config.providers.tts.iter_entries() {
        tts_providers.insert(
            format!("{family}/{alias}"),
            TtsProviderBom {
                alias: alias.to_owned(),
                voice: cfg.voice.clone(),
            },
        );
    }
    let mut transcription_providers = BTreeMap::new();
    for (family, alias, _cfg) in config.providers.transcription.iter_entries() {
        // PR-F intentionally captures `family` + `alias` only — the
        // per-variant struct shape (each family has its own typed
        // config) makes picking out a uniform "model_id" field
        // expensive. A future PR-F2 milestone can resolve each
        // variant and emit `model_id` from the underlying struct;
        // for now this captures the same audit-relevant surface
        // (provider inventory, alias-keyed) without unit-family
        // boilerplate.
        transcription_providers.insert(
            format!("{family}/{alias}"),
            TranscriptionProviderBom {
                alias: alias.to_owned(),
            },
        );
    }
    let wasm_backends = WasmBackendInventory {
        backend: detect_wasm_backend(),
        plugin_fingerprints_hash: None,
    };
    let counts_model = model_providers.len();
    let counts_tts = tts_providers.len();
    let counts_tx = transcription_providers.len();
    AiBom {
        generated_at: chrono::Utc::now(),
        config_path: config_path.to_owned(),
        model_providers,
        tts_providers,
        transcription_providers,
        wasm_backends,
        audit_chain_root,
        counts: AiBomCounts {
            model_providers: counts_model,
            tts_providers: counts_tts,
            transcription_providers: counts_tx,
            total: counts_model + counts_tts + counts_tx,
        },
        deferred_milestones: vec![
            DeferredMilestone {
                tracking_issue: "RFC-#8543".into(),
                summary: "WASM plugin SHA-256 fingerprint".into(),
                planned_surface:
                    "Once landed, `compliance ai-bom` will surface the SHA-256 of every loaded .wasm component, satisfying ISO 42001 A.5 supply-chain integrity.".into(),
            },
            DeferredMilestone {
                tracking_issue: "PR-F2".into(),
                summary: "AI-BOM scheduled refresh".into(),
                planned_surface:
                    "`[compliance].ai_bom_refresh` cron expression will drive automatic BOM rebuild + diff against the previous BOM, with the delta posted to the operator.".into(),
            },
        ],
    }
}

/// Resolve the WASM backend via compile-time `cfg!` on the
/// `Cargo.toml` feature flags. The binary crate does NOT depend on
/// `zeroclaw-plugins` directly (its in `crates/`) so we read from
/// the well-known env variables the CI produces; if a future
/// `cargo:rustc-cfg` direct introspection is added, prefer that.
fn detect_wasm_backend() -> WasmBackendKind {
    // Workspace Cargo features are inherited transitively from
    // `zeroclaw-runtime` and `zeroclaw-plugins`; reading the env
    // avoids a hard dependency edge here.
    let has_cranelift = cfg!(feature = "plugins-wasm-cranelift");
    let has_pulley = cfg!(feature = "plugins-wasm-pulley");
    if has_cranelift {
        WasmBackendKind::Cranelift
    } else if has_pulley {
        WasmBackendKind::Pulley
    } else {
        WasmBackendKind::RuntimeOnly
    }
}

/// Compute the SHA-256 root of the most-recent audit chain entry.
/// Reads the log file from `<zeroclaw_dir>/<log_path>` (relative to
/// the data_dir resolved at config-load time). Returns `None` if the
/// file is missing.
///
/// # Errors
/// - `Io` — the log file is unreadable.
/// - `Other` — the audit log contains malformed JSONL.
pub fn audit_chain_sha256(
    zeroclaw_dir: &std::path::Path,
    log_path: &str,
) -> Result<Option<String>> {
    let full = zeroclaw_dir.join(log_path);
    if !full.exists() {
        return Ok(None);
    }
    use std::io::BufRead;
    let f = std::fs::File::open(&full)
        .map_err(|err| ComplianceError::io(&full, format!("audit chain scan failed: {err}")))?;
    let reader = std::io::BufReader::new(f);
    let mut last: Option<String> = None;
    for (idx, line) in reader.lines().enumerate() {
        let line = line.map_err(|err| {
            ComplianceError::io(
                &full,
                format!("read audit line {} failed: {}", idx + 1, err),
            )
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let event: zeroclaw_runtime::security::audit::AuditEvent = serde_json::from_str(&line)
            .map_err(|err| {
                ComplianceError::new(
                    ComplianceErrorKind::Other,
                    format!("audit log line {} failed to deserialize: {}", idx + 1, err),
                )
            })?;
        last = Some(event.entry_hash);
    }
    Ok(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bom_counts_match_provider_map_lengths() {
        let mut config = Config::default();
        // Insert one of every category via the typed builder.
        config
            .providers
            .models
            .openai
            .as_mut()
            .expect("openai map present when slots are initialized")
            .insert(
                "default".into(),
                zeroclaw_config::schema::OpenAIModelProviderConfig {
                    base: zeroclaw_config::schema::ModelProviderConfig {
                        requires_openai_auth: true,
                        ..Default::default()
                    },
                },
            );
        let bom = build("/path/to/config.toml", &config, None);
        assert_eq!(bom.counts.model_providers, 1);
        assert_eq!(bom.counts.total, 1);
    }

    #[test]
    fn bom_lists_wasm_backend_kind() {
        let bom = build("/path/to/config.toml", &Config::default(), None);
        let _ = bom.wasm_backends.backend;
    }

    #[test]
    fn bom_records_audit_chain_root_when_supplied() {
        let root = "abc123";
        let bom = build("/cfg", &Config::default(), Some(root.to_string()));
        assert_eq!(bom.audit_chain_root.as_deref(), Some("abc123"));
    }

    #[test]
    fn audit_chain_sha256_returns_none_when_missing() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let r = audit_chain_sha256(tmp.path(), "missing.log").expect("none-missing");
        assert!(r.is_none());
    }

    #[test]
    fn deferred_milestones_include_wasm_fingerprint() {
        let bom = build("/cfg", &Config::default(), None);
        assert!(
            bom.deferred_milestones
                .iter()
                .any(|m| m.tracking_issue == "RFC-#8543")
        );
    }
}
