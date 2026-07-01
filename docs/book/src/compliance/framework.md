# Compliance Framework

This page is the agent-runtime's view of the SOC 2 / ISO 27001 / ISO 42001 / OWASP Agentic AI control catalogs that an enterprise deployment is likely to be evaluated against. It is the canonical adaptation of the internal compliance matrix (`obsidian/zeroclaw/soc.md`) into the repo, alongside the [`Statement of Applicability`](./soa.md) which enumerates ZeroClaw's actual coverage.

> See also: [`evidence.md`](./evidence.md) for the CLI surface and exit-code contract.

## Where the framework lives in code

The **control matrix** is the single source of truth — both for evaluation and for the SSOT guard:

```
src/compliance/control_matrix.rs     # evaluators + ids + evidence_refs + summaries
src/compliance/report.rs             # ComplianceReport builder + Markdown/JSON/YAML emitters
src/compliance/audit_verify.rs       # wrapper around AuditLogger::verify_chain
src/compliance/audit_export.rs       # jsonl/csv with LeakDetector::scrub redaction
src/compliance/ai_bom.rs             # provider/WASM-backend/audit-chain-root inventory
crates/zeroclaw-config/src/compliance.rs   # ComplianceConfig / KillSwitchSigner schema
```

`scripts/ssot-verify.sh` hard-fails on duplicate declarations of these types (mirrors the same discipline PR-E introduced for `Principal` / `AuthMethod` / `A2aExternalPeerEntry`).

## Domains Adapted From `obsidian/zeroclaw/soc.md`

The source document covers 11 domains:

| # | Domain | ZeroClaw Surface |
|---|---|---|
| 1 | Identity, Access & Authentication | `AuthProvider` / `ProviderRegistry` (CC6.1) |
| 2 | Agent Isolation, Sandboxing & Multi-Tenancy | `Sandbox` trait (Docker / Firejail / Bubblewrap / Landlock) (CC6.6) |
| 3 | Audit Trails, Logging & Observability | `AuditLogger` hash chain (CC7.2) |
| 4 | Human Oversight & Governed Autonomy | `AutonomyLevel` + `EstopManager` (CC7.3) |
| 5 | Prompt Injection & I/O Security | `PromptGuard` + `LeakDetector` (OWASP AA-01, AA-03) |
| 6 | Data Governance & Training-Data Integrity | `SecretStore` encryption + ACL on credentials |
| 7 | Third-Party & Supply Chain Security | `compliance ai-bom` (CC9.2) |
| 8 | AI Governance, Policy & Ethics | Out of code (operator-driven AIMS) |
| 9 | Change Management & Model Versioning | FND-001 §4.4.2 release artifacts |
| 10 | Incident Response & Resilience | `EstopManager` + `Playbook` (CC7.3) |
| 11 | Transparency, Documentation & Evidence | This book + `compliance report` (CC9.2) |

The exact subset that lands as evidence in `compliance report` today is enumerated in the [`Statement of Applicability`](./soa.md).

## Subcommands

```text
$ zeroclaw compliance report --help
$ zeroclaw compliance audit-trail verify --help
$ zeroclaw compliance audit-trail export --help
$ zeroclaw compliance ai-bom --help
```

Run `compliance report soc2-type2` against a baseline install and the Markdown default emits the table auditors read first.

## Migration Plan From the SOC Framework Document

`obsidian/zeroclaw/soc.md` is the upstream source. The repo-level copy is regenerated from the source on a best-effort basis; the substantive content lives in `control_matrix.rs`'s evaluators. **When extending the matrix, update the source document, the matrix, and the SoA page in lock-step** so an audit reading any one of the three finds consistent information.
