#!/usr/bin/env bash
# Verify that every Rust source file starts with the header in LICENSE-HEADER.txt.
#
# The project is dual licensed (ADR-0011). Adding headers later rewrites the
# whole history, so they go in from the first commit.
set -euo pipefail

cd "$(dirname "$0")/.."

readonly SPDX_LINE='// SPDX-License-Identifier: AGPL-3.0-or-later'
readonly COPYRIGHT_PATTERN='^// Copyright \(C\) [0-9]{4} '

missing=0

while IFS= read -r file; do
    header="$(head -2 "$file")"

    if ! grep -qE "$COPYRIGHT_PATTERN" <<<"$header"; then
        echo "missing copyright line: $file"
        missing=$((missing + 1))
        continue
    fi

    if ! grep -qxF "$SPDX_LINE" <<<"$header"; then
        echo "missing or wrong SPDX line: $file"
        missing=$((missing + 1))
    fi
done < <(find crates -name '*.rs' -type f | sort)

if [ "$missing" -ne 0 ]; then
    echo "license header check failed: $missing file(s)"
    exit 1
fi

echo "license header check passed"
