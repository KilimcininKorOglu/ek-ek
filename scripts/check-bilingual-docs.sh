#!/usr/bin/env bash
# Warn when one half of a bilingual document pair changed without the other.
#
# Every document the project writes ships in two languages (ADR-0049).
# Updating one and leaving the other publishes two different documents. This
# check cannot verify that the contents match, only that both files moved
# together.
#
# It warns and exits 0 on purpose: splitting a translation into a follow-up
# commit is a legitimate workflow, and failing the build would block it.
set -euo pipefail

cd "$(dirname "$0")/.."

# Compare against the previous commit by default, or against a ref passed in.
readonly BASE="${1:-HEAD~1}"

readonly PAIRS=(
    "README.md:README.tr.md"
    "CONTRIBUTING.md:CONTRIBUTING.tr.md"
)

if ! git rev-parse --verify --quiet "$BASE" >/dev/null; then
    echo "bilingual check skipped: $BASE does not exist"
    exit 0
fi

changed="$(git diff --name-only "$BASE" HEAD)"
warnings=0

for pair in "${PAIRS[@]}"; do
    en="${pair%%:*}"
    tr="${pair##*:}"

    en_changed=0
    tr_changed=0
    grep -qxF "$en" <<<"$changed" && en_changed=1
    grep -qxF "$tr" <<<"$changed" && tr_changed=1

    if [ "$en_changed" -ne "$tr_changed" ]; then
        if [ "$en_changed" -eq 1 ]; then
            echo "warning: $en changed but $tr did not"
        else
            echo "warning: $tr changed but $en did not"
        fi
        warnings=$((warnings + 1))
    fi
done

if [ "$warnings" -ne 0 ]; then
    echo "bilingual check: $warnings pair(s) out of sync since $BASE"
    exit 0
fi

echo "bilingual check passed"
