# Compliance Evidence — How to Invoke the PR-F Tooling

PR-F ships a CLI surface for emitting auditable evidence to enterprise reviewers. Every subcommand has a documented exit-code contract so CI scripts can rely on the result.

## Subcommands

| Subcommand | Markdown default | JSON / YAML | CSV / JSONL | Exit 0 | Exit 1 | Exit 2 | Exit 3 | Exit 4 |
|---|---|---|---|---|---|---|---|---|
| `compliance report`           | yes | opt-in `--format` | — | rendered | (validation) | n/a | (config-load fail) | (matrix mismatch) |
| `compliance audit-trail verify` | — | — | — | chain clean | (other) | chain broken | IO error | n/a |
| `compliance audit-trail export` | — | — | yes (default JSONL) | written | n/a | n/a | write fail | n/a |
| `compliance ai-bom`           | yes | opt-in `--format` | — | rendered | n/a | n/a | n/a | n/a |

> **Markdown is the default** for `report` and `ai-bom` because human auditors are the primary consumer; CI/dashboards should pass `--format json`.

## Control Set Today

PR-F ships a **starter SOC 2 Type II control set** that anchors on code already shipped on `feat/multiPRE`:

| ID | Status | Evidence |
|---|---|---|
| `soc2_type2:CC6.1` | Implemented (default-deny) | `crates/zeroclaw-runtime/src/security/auth_provider.rs:104` |
| `soc2_type2:CC6.6` | Implemented (peer-group isolation) | `crates/zeroclaw-config/src/multi_agent.rs:157` |
| `soc2_type2:CC7.2` | Implemented (audit-log hash chain) — `Partial` when `[security].audit.enabled = false` | `crates/zeroclaw-runtime/src/security/audit.rs:465` |
| `soc2_type2:CC7.3` | Partial (estop leak/vuln detectors; signer enforcement is PR-F2) | `crates/zeroclaw-runtime/src/security/estop.rs:83` |
| `soc2_type2:CC9.2` | Partial (provider aliases + WASM backends; SHA-256 fingerprint deferred to RFC #8543) | `crates/zeroclaw-config/src/compliance.rs` |

The control matrix is declared in `src/compliance/control_matrix.rs` as the **single source of truth** for both the evaluators and the JSON-SSOT guard. Subsequent epics extend it via `docs/pr-plans/epics/compliance-matrix-extension.md` — never duplicate a definition elsewhere.

## Audit-Trail Hash Chain

The audit log (`<install>/audit/audit-YYYY-MM-DD.jsonl` or `audit.log`) is hash-chained via SHA-256: each entry's `entry_hash = H(prev_hash || canonical_json)`. Modifying any entry invalidates the chain; `compliance audit-trail verify` detects tamper evidence with exit code 2 and reports the offending sequence number.

PR-F extended the chain's canonical JSON to cover `principal_id` and `auth_method` (the audit-stamp helper at `crates/zeroclaw-gateway/src/auth_middleware.rs::principal_to_audit_actor`), so IdP attestation is part of the integrity assertion from day one.

## Exit Code Contract

CI smoke scripts can rely on these exit codes without parsing output:

```bash
# CI smoke: clean chain → continue; broken chain → fail the build.
zeroclaw compliance audit-trail verify --log-path "$AUDIT_LOG" \
    || { echo "audit chain check failed"; exit 1; }
```

| Exit | Subcommand | Meaning | CI Reaction |
|---|---|---|---|
| 0 | any | success | green |
| 1 | any | unclassified failure | re-run + check stderr |
| 2 | audit-trail verify | chain broken | block merge |
| 3 | any | I/O / config / parse failure | rebuild + retry |
| 4 | report | matrix missing controls (programmer error) | file follow-up issue |

## What You're Shipping

| Surface | Path | Purpose |
|---|---|---|
| Command handlers | `src/main.rs::handle_compliance_command` (+ `compliance::ComplianceCommands`) | entry points |
| Error mapping | `src/compliance/error.rs` | stable error → exit-code mapping |
| Control evaluators | `src/compliance/control_matrix.rs` | STABLE MATRIX; extend via epic |
| Renderers | `src/compliance/{report,ai_bom}.rs` | Markdown / JSON / YAML |
| Hash-chain wrapper | `src/compliance/audit_verify.rs` | wraps `zeroclaw_runtime::security::audit::verify_chain` |
| Export redaction | `src/compliance/audit_export.rs` | scrub via `LeakDetector` before write |
| Schema | `crates/zeroclaw-config/src/compliance.rs` | `ComplianceConfig`, `KillSwitchSigner` |
| Audit integration | `crates/zeroclaw-runtime/src/security/audit.rs` | `principal_id`, `auth_method`, `with_principal()` |
| SSOT script | `scripts/ssot-verify.sh` | hard-fail on duplicate type mirrors |
| CI smoke | `scripts/compliance-smoke.sh` | generates fresh chain + verifies it |
| Plan + epic + ADR | `docs/pr-plans/PR-F.md`, `epics/compliance-matrix-extension.md`, `adr-compliance-foundation.md` | roadmap |
