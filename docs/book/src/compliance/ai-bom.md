# AI Bill of Materials (BOM)

The AI-BOM is the inventory ZeroClaw emits for enterprise supply-chain reviewers. It satisfies SOC 2 Type II CC9.2 (vendor / supplier risk management) and ISO 27001 A.5.19 (supplier relationships) by enumerating:

- **Provider aliases** — every `[providers.models.*.<alias>]`, `[providers.tts.*.<alias>]`, `[providers.transcription.*.<alias>]` configured for the running binary.
- **WASM backend flags** — at-rest inventory of which `Cargo.toml` feature is compiled into the running binary (per FND-001 Rev. 5; one of `plugins-wasm-cranelift`, `plugins-wasm-pulley`, or neither → `runtime-only`).
- **Audit-log chain root** — SHA-256 of the most-recent entry in `<zeroclaw_dir>/<config.security.audit.log_path>`.
- **Deferred milestones** — explicit notes on what is intentionally NOT yet emitted (RFC #8543 fingerprint, scheduled refresh).

## CLI

```text
$ zeroclaw compliance ai-bom --format markdown
$ zeroclaw compliance ai-bom --format json --out bom.json
$ zeroclaw compliance ai-bom --format yaml
```

Default is Markdown (locked decision 2); `--format json|yaml` opts in for machine readers.

## Schema

`| Helidon` (representative row):

```json
{
  "config_path": "/home/operator/.zeroclaw/config.toml",
  "model_providers": {
    "anthropic/default": { "alias": "default", "requires_openai_auth": false },
    "openai/default":    { "alias": "default", "requires_openai_auth": true  }
  },
  "tts_providers": {},
  "transcription_providers": { "groq/fast": { "alias": "fast" } },
  "wasm_backends": {
    "backend": "Cranelift",
    "plugin_fingerprints_hash": null
  },
  "audit_chain_root": "abc…",
  "deferred_milestones": [
    { "tracking_issue": "RFC-#8543", "summary": "WASM plugin SHA-256 fingerprint",
      "planned_surface": "Once landed, BOM surfaces SHA-256 of every loaded .wasm component" }
  ]
}
```

PR-F intentionally does NOT include:
- provider API keys / OIDC client secrets — these are `EncryptedSecret`-classified in the schema and routed through `SecretStore`; the BOM does not reach into them.
- per-channel transport credentials — out of scope for CC9.2; deferred to PR-F2 per `obsidian/zeroclaw/soc.md` §7.

## Configuration

`[compliance].ai_bom_refresh` (optional cron-style 5-field expression) is informational in PR-F; the cron surface drives the scheduled refresh in a follow-up epic. In the meantime, run the subcommand on demand whenever an enterprise auditor asks.

## Evidence Pointers

- `feature/workspace:src/compliance/ai_bom.rs` — BOM construction (single source of truth for the public type).
- `feature/workspace:crates/zeroclaw-config/src/compliance.rs` — `ComplianceConfig` schema.

## Open Landmark: WASM SHA-256 Fingerprint (RFC #8543)

Today's `compliance ai-bom` reports the **WASM backend flag** but not the SHA-256 of loaded `.wasm` components. The fingerprint collector is tracked as RFC #8543; PR-F will **not** punt on the milestone, but it reserves the `plugin_fingerprints_hash` field in the `AiBom` schema so the future epic lands as a non-breaking addition.

## Audit Trail Anchor

The `audit_chain_root` field ties the BOM directly to the hash-chained audit log. An auditor who pulls a BOM at one moment and then runs `compliance audit-trail verify` a week later can confirm both that the body hasn't changed and that the BOM was sourced from a chain root that still verifies.
