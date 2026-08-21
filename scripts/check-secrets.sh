#!/usr/bin/env bash
# Refuse to let a credential reach a tracked file.
#
# The repository is public from the first commit. A leaked secret cannot be
# taken back: deleting the commit does not un-publish it, and the credential
# must be treated as compromised from the moment it is pushed.
#
# Only tracked files are scanned. plan/, design/ and .env are gitignored and
# never reach the remote, so scanning them would only produce noise.
set -uo pipefail

cd "$(dirname "$0")/.."

found=0

report() {
    local label="$1" pattern="$2"

    local hits
    # -e is required: several patterns start with a dash, and without it grep
    # reads the pattern as an option and silently matches nothing.
    hits="$(git ls-files -z \
        | xargs -0 grep -nIE -e "$pattern" 2>/dev/null \
        | grep -vE '^scripts/check-secrets\.sh:' || true)"

    if [ -n "$hits" ]; then
        echo "possible secret: $label"
        echo "$hits" | sed 's/^/  /'
        found=$((found + 1))
    fi
}

# Private key material of any kind.
report 'private key block' '-----BEGIN [A-Z ]*PRIVATE KEY-----'

# Provider tokens with a fixed, recognisable shape. These have no false
# positives worth worrying about.
report 'AWS access key id' 'AKIA[0-9A-Z]{16}'
report 'GitHub token' 'gh[pousr]_[A-Za-z0-9]{36}'
report 'Slack token' 'xox[baprs]-[0-9A-Za-z-]{10,}'
report 'Google API key' 'AIza[0-9A-Za-z_-]{35}'
report 'private key in a JSON service account' '"private_key"[[:space:]]*:[[:space:]]*"-----BEGIN'

# Assignments that carry an actual value. An empty assignment is a template
# placeholder, which is exactly what .env.example is allowed to contain.
report 'password with a value' '(password|passwd|pwd)[[:space:]]*[:=][[:space:]]*["'"'"']?[^"'"'"'[:space:]]{8,}'
report 'api key with a value' 'api[_-]?key[[:space:]]*[:=][[:space:]]*["'"'"']?[^"'"'"'[:space:]]{16,}'
report 'secret with a value' 'secret[_-]?(key|token)?[[:space:]]*[:=][[:space:]]*["'"'"']?[^"'"'"'[:space:]]{16,}'

# The environment file itself must never be tracked.
if git ls-files --error-unmatch .env >/dev/null 2>&1; then
    echo "possible secret: .env is tracked; it must stay gitignored"
    found=$((found + 1))
fi

if [ "$found" -ne 0 ]; then
    echo "secret scan failed: $found pattern(s) matched"
    echo "treat any real credential found here as compromised and rotate it"
    exit 1
fi

echo "secret scan passed"
