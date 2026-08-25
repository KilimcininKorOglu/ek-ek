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
    ("ek-ek-config", "ek-ek-tls", "the config model is the base layer"),
    ("ek-ek-dataplane", "ek-ek-vrrp", "the traffic path must not know about VRRP"),
    ("ek-ek-vrrp", "ek-ek-dataplane", "VRRP must not know about the traffic path"),
    # Certificate upload is a control plane job. It reads what an operator
    # sends and writes a store state; nothing it does happens while a request
    # does (ADR-0002).
    ("ek-ek-tls", "ek-ek-dataplane", "the upload path must not pull in the traffic path"),
    ("ek-ek-tls", "ek-ek-vrrp", "certificates have nothing to do with VRRP"),
    # Peer trust and the certificates an operator uploads are separate trust
    # domains (ADR-0008). The separation is only real if the build refuses to
    # let one reach the other, so it is a rule in both directions (ADR-0082).
    ("ek-ek-peer", "ek-ek-tls", "the cluster CA is not the certificate an operator uploads"),
    ("ek-ek-tls", "ek-ek-peer", "an uploaded certificate has nothing to do with peer trust"),
    ("ek-ek-peer", "ek-ek-dataplane", "peer trust must not reach the traffic path"),
    ("ek-ek-peer", "ek-ek-vrrp", "peer trust has nothing to do with VRRP"),
    ("ek-ek-config", "ek-ek-peer", "the config model is the base layer"),
    # ADR-0004's invariant: losing quorum must never affect the traffic path.
    # A sentence in a document is not a boundary unless the build refuses to
    # cross it, so it is a rule in both directions (ADR-0083).
    ("ek-ek-raft", "ek-ek-dataplane", "quorum loss must not reach the traffic path"),
    ("ek-ek-raft", "ek-ek-vrrp", "consensus has nothing to do with VRRP"),
    ("ek-ek-dataplane", "ek-ek-raft", "the traffic path must not wait on a quorum"),
    ("ek-ek-vrrp", "ek-ek-raft", "VRRP decides who holds an address without a quorum"),
    ("ek-ek-raft", "ek-ek-tls", "consensus is not the certificate an operator uploads"),
    ("ek-ek-config", "ek-ek-raft", "the config model is the base layer"),
    # The channel carries a service name and an opaque body. Teaching it what
    # a Raft message is would put the state machine below the transport.
    ("ek-ek-peer", "ek-ek-raft", "the channel must not know what it carries"),
    ("ek-ek-store", "ek-ek-raft", "the store is measured without consensus anywhere near it"),
    # The agent starts the traffic path as a process and speaks to it over a
    # socket (ADR-0002). Linking it would put the proxy inside the process that
    # is supposed to survive the proxy crashing, which is the whole point of
    # there being two of them (ADR-0087).
    ("ek-ek-agent", "ek-ek-dataplane", "the supervisor must not link what it supervises"),
    # Supervision and consensus are separate jobs on separate schedules. An
    # agent that waited on a quorum to notice a dead traffic path would hold
    # this node's address through a quorum loss (ADR-0004).
    ("ek-ek-agent", "ek-ek-raft", "supervising a process must not wait on a quorum"),
]

# Crates that must depend on no workspace crate at all.
#
# The integration harness drives the cluster from outside and observes it
# the way an operator would. Linking a product crate into it would let a
# change in the product quietly change what the tests measure (ADR-0055).
ISOLATED = [
    ("ek-ek-itest", "the integration harness observes the product from outside"),
    # Both node-agent and data-plane log, so the logging layer sits below both.
    # Depending on the config model would drag the whole model into a crate
    # that only has to write lines (ADR-0037).
    ("ek-ek-log", "the logging layer sits below every crate that logs"),
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

for crate, why in ISOLATED:
    if crate not in workspace:
        continue
    for other in sorted(workspace - {crate}):
        if reaches(crate, other):
            print(f"layering violation: {crate} depends on {other} ({why})")
            violations += 1

if violations:
    print(f"layering check failed: {violations} violation(s)")
    sys.exit(1)

print(f"layering check passed: {len(RULES) + len(ISOLATED)} rule(s) hold")
PY
