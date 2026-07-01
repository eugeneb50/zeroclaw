#!/usr/bin/env bash
# SSOT (Single Source of Truth) verification script.
#
# Proves that every tracked type lives in exactly one canonical module and is
# never duplicated elsewhere in the codebase. Hard-fail on core identity types;
# warn on everything else.
#
# Usage: bash scripts/ssot-verify.sh
# Called by CI: .github/workflows/ssot-verify.yml on every pull_request.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

EXIT_CODE=0

# --- helpers ---------------------------------------------------------------

warn() { echo "⚠️  $1"; }
fail() { echo "❌ $1"; EXIT_CODE=1; }
pass() { echo "✅ $1"; }

check_no_extra_def() {
    local label="$1"
    local pattern="$2"
    local canonical="$3"

    # -w means whole-word matching, so "struct Principal" won't match
    # "struct ApprovalPrincipal" or "struct PrincipalId"
    local matches
    matches=$(git grep -wl "$pattern" -- '*.rs' 2>/dev/null || true)
    local violations=0
    while IFS= read -r file; do
        [ -z "$file" ] && continue
        [[ "$file" == "$canonical" ]] && continue
        [[ "$file" == *"target/"* ]] && continue
        # Skip generated/output files
        [[ "$file" == "crates/zeroclaw-config/src/schema.rs" ]] && continue
        # Check if it's a re-export (pub use), not a definition
        if grep -q "^pub use.*$(echo "$pattern" | sed 's/[][\.*^$()+?{|]/\\&/g')" "$file" 2>/dev/null; then
            continue
        fi
        # Skip impl blocks — implementations are not new definitions
        if grep -q "impl $pattern" "$file" 2>/dev/null && ! grep -q "^\(pub \)\?\(trait\|struct\|enum\) $pattern" "$file" 2>/dev/null; then
            continue
        fi
        echo "  → $file"
        violations=$((violations + 1))
    done <<< "$matches"

    if [ "$violations" -gt 0 ]; then
        fail "$label defined outside $canonical ($violations files)"
    else
        pass "$label"
    fi
}

# --- CORE IDENTITY TYPES (hard fail) --------------------------------------

echo "=== SSOT verification ==="
echo ""

echo "--- Core identity types (hard fail) ---"

check_no_extra_def "struct Principal"      "struct Principal"      "crates/zeroclaw-api/src/principal.rs"
check_no_extra_def "enum AuthMethod"       "enum AuthMethod"       "crates/zeroclaw-api/src/principal.rs"
check_no_extra_def "struct PrincipalId"    "struct PrincipalId"    "crates/zeroclaw-api/src/principal.rs"

echo ""
echo "--- Construction boundary (hard fail) ---"

# Principal { construction — whole-word match excludes ApprovalPrincipal etc.
violations=0
while IFS= read -r file; do
    [ -z "$file" ] && continue
    [[ "$file" == "crates/zeroclaw-api/src/principal.rs" ]] && continue
    [[ "$file" == "crates/zeroclaw-runtime/src/security/"* ]] && continue
    [[ "$file" == *"target/"* ]] && continue
    # Allow test helpers that construct Principal for unit tests
    [[ "$file" == *"auth_middleware.rs" ]] && continue
    echo "  → $file"
    violations=$((violations + 1))
done < <(git grep -wl "Principal {" -- '*.rs' 2>/dev/null || true)

if [ "$violations" -gt 0 ]; then
    fail "Principal { constructed outside canonical/auth provider boundary ($violations files)"
else
    pass "Principal construction boundary"
fi

echo ""
echo "--- Config types (warn only) ---"

check_no_extra_def "struct PeerGroupConfig"    "struct PeerGroupConfig"    "crates/zeroclaw-config/src/multi_agent.rs"
check_no_extra_def "struct A2aExternalPeerEntry" "struct A2aExternalPeerEntry" "crates/zeroclaw-config/src/multi_agent.rs"
check_no_extra_def "struct A2aPeerConfig"      "struct A2aPeerConfig"      "crates/zeroclaw-config/src/multi_agent.rs"
check_no_extra_def "struct A2aServerSection"   "struct A2aServerSection"   "crates/zeroclaw-config/src/multi_agent.rs"

echo ""
echo "--- Provider / trait types (warn only) ---"

# Note: zeroclaw-providers crate has a `trait AuthProviderFlow` (different)
# and `enum AuthProvider` for outbound LLM-provider OAuth — unrelated.
check_no_extra_def "trait AuthProvider"           "trait AuthProvider"           "crates/zeroclaw-runtime/src/security/auth_provider.rs"
check_no_extra_def "trait AuthRegistry"           "trait AuthRegistry"           "crates/zeroclaw-runtime/src/security/auth_provider.rs"
check_no_extra_def "struct A2aPeerProvider"        "struct A2aPeerProvider"        "crates/zeroclaw-runtime/src/security/auth_provider.rs"
check_no_extra_def "struct LiveAuthRegistry"       "struct LiveAuthRegistry"       "crates/zeroclaw-runtime/src/security/auth_provider.rs"
check_no_extra_def "struct LiveConfigA2aResolver"  "struct LiveConfigA2aResolver"  "crates/zeroclaw-runtime/src/security/auth_provider.rs"

echo ""
echo "--- Compliance config types (PR-F, hard fail) ---"

# PR-F: compliance posture config is the single source of truth for
# kill_switch_signers + regime claims. A duplicate anywhere in the
# workspace means a different surface is reading plaintext credentials.
check_no_extra_def "struct ComplianceConfig"  "struct ComplianceConfig"  "crates/zeroclaw-config/src/compliance.rs"
check_no_extra_def "struct KillSwitchSigner"  "struct KillSwitchSigner"  "crates/zeroclaw-config/src/compliance.rs"

echo ""
echo "--- Compliance CLI types (PR-F, hard fail) ---"

# PR-F: CLI output types live exclusively inside the compliance module.
check_no_extra_def "enum ComplianceError"     "enum ComplianceError"     "crates/zeroclaw/src/compliance/error.rs"
check_no_extra_def "struct ComplianceReport"  "struct ComplianceReport"  "crates/zeroclaw/src/compliance/report.rs"
check_no_extra_def "struct ControlMatrix"     "struct ControlMatrix"     "crates/zeroclaw/src/compliance/control_matrix.rs"

echo ""
echo "=== Summary ==="
if [ "$EXIT_CODE" -eq 0 ]; then
    echo "✅ All SSOT checks passed."
else
    echo "❌ Some SSOT checks failed."
fi

exit "$EXIT_CODE"
