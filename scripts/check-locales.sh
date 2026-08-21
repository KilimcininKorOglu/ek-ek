#!/usr/bin/env bash
# Enforce that every language file says the same set of things (ADR-0015).
#
# A translation is added by adding a key to one file and forgetting the other.
# Nothing else catches that: the missing key renders as the key itself, which
# looks like a deliberate identifier until a user reports it. This script is
# what turns the omission into a failed build.
#
# It takes the locales directory as an optional argument, so a test can point
# it at a catalogue it built on purpose to be wrong. A checker nobody can aim
# at a known fault is a checker nobody has measured.
set -uo pipefail

LOCALES="${1:-$(cd "$(dirname "$0")/.." && pwd)/locales}"

python3 - "$LOCALES" <<'PY'
import json
import re
import sys
from pathlib import Path

locales = Path(sys.argv[1])

# A key is an identifier, never an English sentence. A sentence used as a key
# breaks every translation the moment the sentence is edited.
KEY_SHAPE = re.compile(r"^[a-z0-9]+(\.[a-z0-9_]+)+$")

# A dialog needs all four, because a destructive confirmation without a title,
# a named effect and two named buttons is not acceptable (ADR-0048).
DIALOG_PARTS = ("title", "body", "confirm", "cancel")

problems: list[str] = []

documents: dict[str, dict[str, str]] = {}
for path in sorted(locales.glob("*.json")):
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        problems.append(f"{path.name}: not readable as JSON: {error}")
        continue
    if not isinstance(loaded, dict):
        problems.append(f"{path.name}: the document is not an object of keys")
        continue
    for key, value in loaded.items():
        if not isinstance(value, str):
            problems.append(f"{path.name}: '{key}' is not a string")
    documents[path.stem] = loaded

if len(documents) < 2:
    # With one file there is nothing to compare, so the check would pass while
    # measuring nothing at all.
    problems.append(
        f"{locales}: {len(documents)} language file(s) found, at least 2 are needed"
    )

if documents:
    every_key: set[str] = set()
    for keys in documents.values():
        every_key |= set(keys)

    for language in sorted(documents):
        keys = set(documents[language])
        for key in sorted(every_key - keys):
            problems.append(f"{language}: '{key}' is missing")
        # Reported from the other side too: a key only one language has is
        # just as wrong, and only one of the two directions is caught by
        # comparing against the union.
        for other in sorted(documents):
            if other == language:
                continue
            for key in sorted(keys - set(documents[other])):
                problems.append(f"{language}: '{key}' is not in {other}")

    for key in sorted(every_key):
        if not KEY_SHAPE.match(key):
            problems.append(f"'{key}' is not an identifier shaped key")
        if key.startswith("log."):
            problems.append(f"'{key}': log messages are not translated")

    dialogs = {key.split(".")[1] for key in every_key if key.startswith("dialog.")}
    for dialog in sorted(dialogs):
        for part in DIALOG_PARTS:
            key = f"dialog.{dialog}.{part}"
            if key not in every_key:
                problems.append(f"dialog '{dialog}': '{part}' is missing")

if problems:
    for problem in problems:
        print(f"locales: {problem}")
    print(f"locales check failed: {len(problems)} problem(s)")
    sys.exit(1)

languages = ", ".join(sorted(documents))
count = len(next(iter(documents.values())))
print(f"locales check passed: {count} key(s) in each of {languages}")
PY
