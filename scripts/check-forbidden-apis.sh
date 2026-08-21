#!/usr/bin/env bash
# Reject browser APIs the project has ruled out (ADR-0048).
#
# alert(), confirm() and prompt() block the main thread, cannot be styled, and
# sit outside the translation layer. Every dialog uses SweetAlert2 instead.
# localStorage and sessionStorage are never used; browser state goes in cookies.
#
# The embedded SweetAlert2 distribution file legitimately contains these names,
# so the vendor directory is excluded. Widening that exclusion requires an ADR.
set -euo pipefail

cd "$(dirname "$0")/.."

# Dialog calls are only meaningful where the UI lives.
readonly UI_SCOPE='crates/ek-ek-api'
# Browser storage must not appear anywhere, because any crate could emit markup.
readonly ALL_SCOPE='crates'
readonly VENDOR_DIR='vendor'

found=0

# A comment line naming a forbidden call is documentation, not a call. The rule
# itself is written in module docs, so matching those would make the check
# unusable. Comment text cannot execute, so skipping it loses no coverage.
readonly COMMENT_LINE='^[^:]+:[0-9]+:[[:space:]]*(//|<!--)'

report() {
    local pattern="$1" scope="$2" label="$3"

    local hits
    hits="$(grep -rnE "$pattern" "$scope" \
        --include='*.rs' --include='*.html' --include='*.js' \
        --exclude-dir="$VENDOR_DIR" \
        | grep -vE "$COMMENT_LINE" || true)"

    if [ -n "$hits" ]; then
        echo "forbidden: $label"
        echo "$hits" | sed 's/^/  /'
        found=$((found + 1))
    fi
}

if [ -d "$UI_SCOPE" ]; then
    report '\balert[[:space:]]*\(' "$UI_SCOPE" 'alert() - use the SweetAlert2 wrapper'
    report '\bconfirm[[:space:]]*\(' "$UI_SCOPE" 'confirm() - use the SweetAlert2 wrapper'
    report '\bprompt[[:space:]]*\(' "$UI_SCOPE" 'prompt() - use SweetAlert2 with an input'
fi

report '\blocalStorage\b' "$ALL_SCOPE" 'localStorage - store browser state in a cookie'
report '\bsessionStorage\b' "$ALL_SCOPE" 'sessionStorage - store browser state in a cookie'

if [ "$found" -ne 0 ]; then
    echo "forbidden API check failed: $found pattern(s) matched"
    exit 1
fi

echo "forbidden API check passed"
