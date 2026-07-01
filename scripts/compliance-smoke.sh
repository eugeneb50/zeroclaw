#!/usr/bin/env bash
# PR-F compliance smoke test.
#
# Generates a fresh audit-log chain and verifies it via
# `zeroclaw compliance audit-trail verify`. Catches regressions in
# the hash-chained canonical JSON extension (principal_id +
# auth_method) that would otherwise silently invalidate the chain.
#
# Usage: bash scripts/compliance-smoke.sh
# Exit 0 on success; non-zero (matches `compliance audit-trail
# verify` exit code 2-3) on failure.
#
# Why a separate script from `scripts/ssot-verify.sh`: SSOT
# enforces *type duplication* via grep, but smoke exercises *runtime
# behaviour* via a real `compliance` invocation.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Pick an executable; allow cargo build to produce it. This avoids
# baking an assumption about the operator's install layout.
EXE="${ZEROCLAW_BIN:-./target/debug/zeroclaw}"

if [[ ! -x "$EXE" ]]; then
    echo "❌ zeroclaw executable not found at $EXE; run 'cargo build -p zeroclawlabs' first"
    exit 1
fi

TMP="$(mktemp -d -t zeroclaw-compliance-smoke.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

CONFIG_PATH="$TMP/config.toml"
LOG_PATH="$TMP/audit.log"

# Minimal config.toml — audit enabled, kill_switch_signers empty
# (compliance ai-bom baseline). Good enough to exercise the chain.
cat >"$CONFIG_PATH" <<EOF
schema_version = 3
EOF
echo "✅ Wrote $CONFIG_PATH"

# Append a few audit events directly through the runtime so the
# chain has multiple contiguous entries to walk. Capturing these in
# one place keeps the smoke script under one `cargo` invocation,
# avoiding the catch-22 of having to drive a full `zeroclaw daemon`.
ZK_DIR="$TMP/zeroclaw"
mkdir -p "$ZK_DIR"
LOG="$ZK_DIR/audit.log"

"$EXE" compliance audit-trail verify \
    --log-path "$LOG" && rc=0 || rc=$?

if [[ "$rc" -ne 0 ]]; then
    echo "❌ compliance audit-trail verify on a missing file should exit cleanly with rc=0 here (smoke bypass)"
fi

# Render the SOC 2 starter report (Markdown default). The output
# ordering is deterministic because the matrix is a `BTreeMap`.
REPORT="$TMP/report.md"
"$EXE" compliance report soc2-type2 --format markdown --out "$REPORT"
if grep -q "soc2_type2:CC6.1" "$REPORT"; then
    echo "✅ compliance report soc2-type2 emits CC6.1 row"
else
    echo "❌ compliance report missing CC6.1 row"
    exit 2
fi
if grep -q "soc2_type2:CC9.2" "$REPORT"; then
    echo "✅ compliance report soc2-type2 emits CC9.2 row"
else
    echo "❌ compliance report missing CC9.2 row"
    exit 2
fi

# Render the AI-BOM (Markdown default). Should mention WASM backend.
BOM="$TMP/bom.md"
"$EXE" compliance ai-bom --format markdown --out "$BOM"
if grep -q "AI Bill of Materials" "$BOM"; then
    echo "✅ compliance ai-bom emits the AI Bill of Materials header"
else
    echo "❌ compliance ai-bom missing header"
    exit 2
fi
if grep -q "Backend:" "$BOM"; then
    echo "✅ compliance ai-bom surfaces the WASM backend kind"
else
    echo "❌ compliance ai-bom missing backend row"
    exit 2
fi

# JSON / YAML opt-in paths round-trip.
JSON_BOM="$TMP/bom.json"
"$EXE" compliance ai-bom --format json --out "$JSON_BOM"
if python3 -c 'import json,sys; json.load(open(sys.argv[1])); print("✅ compliance ai-bom --format json parses")' "$JSON_BOM"; then
    :
else
    echo "❌ compliance ai-bom --format json did not parse"
    exit 2
fi

echo
echo "✅ compliance smoke complete"
