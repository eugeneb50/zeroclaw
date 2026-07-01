# Statement of Applicability

The `Statement of Applicability` (SoA) is a single page that maps each control in the SOC 2 / ISO 27001 / ISO 42001 / OWASP Agentic AI frameworks against ZeroClaw's current implementation state. It is regenerated whenever the matrix in `src/compliance/control_matrix.rs` changes — the same source that powers `compliance report`.

## SOC 2 Type II (PR-F starter set)

| Control | Title | Implementation | Status | Rationale |
|---|---|---|---|---|
| CC6.1 | Logical and physical access controls | `AuthProvider` trait + `ProviderRegistry::default-deny` | **Implemented** | Every inbound Credential is verified by 1+ registered providers. An empty registry denies all (fail-closed). No silent allow paths exist. |
| CC6.6 | Vendor / third-party credential isolation | `a2a_external_peers` HashMap on `PeerGroupConfig` + SSOT guard | **Implemented** | Peer-group-scoped A2A credentials live in a typed struct with `#[secret] + #[credential_class = "encrypted_secret"]`. The legacy `external_peers: Vec<PeerUsername>` (channel-only) is preserved untouched. |
| CC7.2 | Monitoring of system operations | `AuditLogger` writes hash-chained JSONL; `verify_chain` is open | **Implemented** (Partial when audit is disabled) | Hash chain covers `timestamp / event_id / event_type / actor / action / result / security / principal_id / auth_method / sequence`. Tamper evidence is reported with offending sequence number. |
| CC7.3 | Detection & response to security events | `EstopManager` + `LeakDetector` + `Vulnerability` + `PromptGuard` | **Partial** | Detectors ship on `zeroclaw-runtime`. Kill-switch signer enforcement (`compliance.config.kill_switch_signers` → crypto-resume) is roadmap (PR-F2). |
| CC9.2 | Vendor / supplier risk management | `compliance ai-bom` enumerates providers + WASM backends | **Partial** | Aliases land in PR-F. WASM plugin SHA-256 fingerprinting is RFC #8543 (separate milestone). |

## ISO 27001 (Roadmap — PR-F2)

Status: **Organizational scope, not implemented in code**. ZeroClaw's auth surface (RBAC, least-privilege, MFA via IdP) covers the technical ISO 27001 controls via SOC 2 CC6.1 / CC6.6; the rest is operator-driven.

| Control | Mapping | Status |
|---|---|---|
| A.5.1 (policies) | Operator must publish | n/a |
| A.8.15 (logging) | `AuditLogger` (SOC 2 CC7.2) | **Implemented** |
| A.8.16 (monitoring) | `Compliance` subcommands + `LeakDetector` | **Implemented** |
| A.5.19 (supplier) | `compliance ai-bom` | **Partial — see SoA §SOC 2 CC9.2** |

## ISO 42001 (Roadmap — PR-F2)

Status: **Roadmap**, mirroring the SOC 2 set. The AI-BOM surface is the bridge: it provides AI Management System observability via tooling.

| Control | Mapping |
|---|---|
| 6.1.2 AI risk assessment | Operator-driven; matrix enumerated |
| 6.1.4 AI System Impact Assessment | Operator-driven |
| 8.4 Lifecycle management | Versioned release per FND-001 §4.4.2 |

## OWASP Top 10 for Agentic Applications (Roadmap — PR-F2)

Status: **Roadmap**, mirrored against built-in defenses:

| Risk | Mapping |
|---|---|
| AA-01 Prompt injection | `PromptGuard` + `LeakDetector` |
| AA-02 Sandboxing | `Sandbox` trait + Docker/Firejail/Bubblewrap/Landlock |
| AA-04 Multi-tenant isolation | `PeerGroupConfig` + `AuthProvider` registry |
| AA-05 Human oversight | `AutonomyLevel::Supervised` default; medium-risk requires approval |

## Out of Scope

- Cardinal control 4.7 (Appoint AI Security Officer) — organizational; not code.
- Cardinal control 6.x (training-data integrity) — inference-only runtime; not applicable.
- Cardinal control 8.x (AIMS documentation) — outside the codebase; this page is the codebase's invoice of what's covered, not the org-level AIMS narrative.

## Maintenance

When extending the matrix (per `docs/pr-plans/epics/compliance-matrix-extension.md`), update this page in lock-step. Operators and auditors both read it; a divergence against the actual `compliance report` output would be a documentation defect and a `Partial` regression.
