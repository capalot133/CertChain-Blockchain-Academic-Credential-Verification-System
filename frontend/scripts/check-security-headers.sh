#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# check-security-headers.sh
# ──────────────────────────────────────────────────────────────────────────────
# Usage:
#   ./scripts/check-security-headers.sh <base-url> [api-path]
#
# Example:
#   ./scripts/check-security-headers.sh https://acredia-stellar-tau.vercel.app /api/health
#
# This script checks that the expected security headers are present in the
# response from a production (or preview) deployment, and verifies that CSP
# nonces rotate across requests for both an HTML page and an API route.
# It exits with code 0 if all checks pass, or 1 with details about failures.
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <base-url> [api-path]"
    echo "Example: $0 https://acredia-stellar-tau.vercel.app /api/health"
    exit 1
fi

BASE_URL="${1%/}"
API_PATH="${2:-/api/health}"
FAILED=0

check_header() {
    local header_name="$1"
    local expected_pattern="$2"
    local location="$3"

    local value
    value=$(curl -sI "$location" | grep -i "^${header_name}:" | sed 's/^[^:]*:\s*//i' | tr -d '\r')

    if [ -z "$value" ]; then
        echo "  MISSING: $header_name"
        FAILED=1
        return
    fi

    if echo "$value" | grep -qE "$expected_pattern"; then
        echo "  OK: $header_name"
    else
        echo "⚠  $header_name present but pattern mismatch"
        echo "   Expected pattern: $expected_pattern"
        echo "   Got: $value"
        FAILED=1
    fi
}

extract_nonce() {
    local location="$1"
    curl -sI "$location" | grep -i "^content-security-policy:" \
        | grep -oE "'nonce-[A-Za-z0-9+/=_-]+'" | head -n1 | tr -d "'"
}

check_nonce_rotation() {
    local label="$1"
    local location="$2"

    local first second
    first=$(extract_nonce "$location")
    second=$(extract_nonce "$location")

    if [ -z "$first" ] || [ -z "$second" ]; then
        echo "  MISSING: nonce in CSP for $label"
        FAILED=1
        return
    fi

    if [ "$first" = "$second" ]; then
        echo "  FAIL: CSP nonce not rotating for $label"
        FAILED=1
    else
        echo "  OK: CSP nonce rotates for $label"
    fi
}

echo "── Checking security headers at ${BASE_URL} ──"
echo ""

check_header "Content-Security-Policy" "default-src" "$BASE_URL"
check_header "X-Frame-Options" "DENY" "$BASE_URL"
check_header "X-Content-Type-Options" "nosniff" "$BASE_URL"
check_header "Referrer-Policy" "strict-origin-when-cross-origin" "$BASE_URL"
check_header "Permissions-Policy" "camera=\(self\)" "$BASE_URL"
check_header "Strict-Transport-Security" "max-age=" "$BASE_URL"

echo ""
echo "── Checking CSP nonce rotation ──"
check_nonce_rotation "HTML page" "$BASE_URL/"
check_nonce_rotation "API route" "${BASE_URL}${API_PATH}"

echo ""
if [ $FAILED -eq 0 ]; then
    echo "✓ All security headers are present and nonces rotate."
else
    echo "✗ Some security checks failed (headers or nonce rotation)."
    echo "  Update the CSP in src/lib/securityHeaders.ts if a new integration"
    echo "  intentionally requires additional domains."
fi
exit $FAILED
