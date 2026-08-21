#!/usr/bin/env bash
# Enforce the crate dependency direction from ADR-0014.
#
# The layering only means something if the build rejects a violation. A comment
# in a Cargo.toml is a note; this script is the rule.
#
# It reads cargo metadata rather than grepping manifests, so an indirect
# dependency introduced through a third crate is caught as well.
set -uo pipefail

cd "$(dirname "$0")/.."

python3 - <<'PY'
import json
import subprocess
import sys

# (crate, forbidden dependency, why)
RULES = [
    ("ek-ek-config", "ek-ek-agent", "the config model is the base layer"),
    ("ek-ek-config", "ek-ek-api", "the config model is the base layer"),
    ("ek-ek-config", "ek-ek-dataplane", "the config model is the base layer"),
    ("ek-ek-config", "ek-ek-ipc", "the config model is the base layer"),
    ("ek-ek-config", "ek-ek-store", "the config model is the base layer"),
    ("ek-ek-config", "ek-ek-vrrp", "the config model is the base layer"),
    ("ek-ek-config", "ek-ek", "the config model is the base layer"),
    ("ek-ek-dataplane", "ek-ek-vrrp", "the traffic path must not know about VRRP"),
    ("ek-ek-vrrp", "ek-ek-dataplane", "VRRP must not know about the traffic path"),
]

raw = subprocess.run(
    ["cargo", "metadata", "--no-deps", "--format-version", "1"],
    capture_output=True, text=True, check=True,
).stdout
meta = json.loads(raw)

workspace = {p["name"] for p in meta["packages"]}
direct = {
    p["name"]: {d["name"] for d in p["dependencies"] if d["name"] in workspace}
    for p in meta["packages"]
}


def reaches(start, target, seen=None):
    """Follow the dependency graph, so an indirect path is caught too."""
    seen = seen or set()
    for dep in direct.get(start, ()):
        if dep == target:
            return True
        if dep not in seen:
            seen.add(dep)
            if reaches(dep, target, seen):
                return True
    return False


violations = 0
for crate, forbidden, why in RULES:
    if crate not in workspace or forbidden not in workspace:
        continue
    if reaches(crate, forbidden):
        print(f"layering violation: {crate} depends on {forbidden} ({why})")
        violations += 1

if violations:
    print(f"layering check failed: {violations} violation(s)")
    sys.exit(1)

print(f"layering check passed: {len(RULES)} rule(s) hold")
PY
