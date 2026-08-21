#!/usr/bin/env bash
# Run the T-009 choreography and report what it measured.
#
# The question: can a supervising process replace a pingora process on a
# listener change without dropping a request and without interrupting work that
# must never stop? ADR-0002 stands or falls on the answer.
#
# pingora's own documentation gives two different orderings for the upgrade, so
# both are measured and the report says which one held.
set -uo pipefail

cd "$(dirname "$0")/.."

readonly COMPOSE=(docker compose --env-file .env -f docker/compose.yml)
readonly IN_SPIKE=("${COMPOSE[@]}" exec -T spike)
readonly PROXY_ADDR=172.28.0.31:6180
readonly NEW_ADDR=172.28.0.31:6181
readonly RESULTS=docker-data/spike-results

if [ ! -f .env ]; then
    echo "missing .env; run 'make dev-env' first"
    exit 1
fi

mkdir -p "$RESULTS"

echo "== building the spike inside the container =="
"${IN_SPIKE[@]}" bash -c '
    set -e
    cp -r /spike/src-tree/upgrade/. /spike/build 2>/dev/null || {
        mkdir -p /spike/build && cp -r /spike/src-tree/upgrade/. /spike/build
    }
    cd /spike/build
    cargo build --release --quiet
    cp target/release/proxy target/release/agent target/release/load target/release/long /spike/
    # grace_period_seconds is set low on purpose. Its default is long enough
    # that the old process outlives a short measurement, which reads as a
    # failure to exit when it is really a wait that was never observed.
    printf "version: 1\nthreads: 2\npid_file: /tmp/spike.pid\nupgrade_sock: /tmp/spike-upgrade.sock\ngrace_period_seconds: 2\ngraceful_shutdown_timeout_seconds: 2\n" > /spike/pingora.yaml
' || { echo "build failed"; exit 1; }

run_order() {
    local order="$1"
    echo
    echo "== measuring order: $order =="

    "${IN_SPIKE[@]}" bash -c 'pkill -9 -f /spike/proxy || true; rm -f /tmp/spike-upgrade.sock /tmp/spike.pid' >/dev/null 2>&1

    "${IN_SPIKE[@]}" env \
        SPIKE_ORDER="$order" \
        SPIKE_UPGRADE_AFTER_MS=8000 SPIKE_RUN_MS=18000 \
        SPIKE_LISTENERS_GEN1="0.0.0.0:6180" \
        SPIKE_LISTENERS_GEN2="0.0.0.0:6180,0.0.0.0:6181" \
        /spike/agent > "$RESULTS/agent-$order.json" 2>"$RESULTS/agent-$order.err" &
    local agent_pid=$!

    # Wait until the proxy actually accepts a connection before generating load.
    # Starting earlier counts the startup window as dropped requests, which says
    # nothing about the upgrade and hides whether the upgrade itself dropped any.
    local ready=false
    for _ in $(seq 1 40); do
        if "${IN_SPIKE[@]}" curl -fsS --max-time 1 "http://$PROXY_ADDR/" >/dev/null 2>&1; then
            ready=true
            break
        fi
        sleep 0.25
    done
    if [ "$ready" != true ]; then
        echo "  proxy never came up for order $order"
        printf '{"sent":0,"failed":-1,"first_error":"proxy never came up"}\n' \
            > "$RESULTS/load-$order.json"
        wait "$agent_pid" 2>/dev/null
        echo "false" > "$RESULTS/newlistener-$order.txt"
        echo "0" > "$RESULTS/zombies-$order.txt"
        return
    fi

    # One keep-alive connection is opened before the upgrade and kept in use
    # across it, which is what ADR-0009 promises will not be cut.
    "${IN_SPIKE[@]}" env \
        SPIKE_TARGET="$PROXY_ADDR" SPIKE_LONG_MS=15000 SPIKE_LONG_EVERY_MS=500 \
        /spike/long > "$RESULTS/long-$order.json" 2>"$RESULTS/long-$order.err" &
    local long_pid=$!

    # The load window straddles the upgrade, so a dropped request can only come
    # from the handover itself.
    "${IN_SPIKE[@]}" env \
        SPIKE_TARGET="$PROXY_ADDR" SPIKE_RATE=100 SPIKE_LOAD_MS=12000 \
        /spike/load > "$RESULTS/load-$order.json" 2>"$RESULTS/load-$order.err"

    wait "$long_pid" 2>/dev/null

    wait "$agent_pid" 2>/dev/null

    # Does the listener that only the second generation declares actually serve?
    if "${IN_SPIKE[@]}" curl -fsS --max-time 3 "http://$NEW_ADDR/" >/dev/null 2>&1; then
        echo "true" > "$RESULTS/newlistener-$order.txt"
    else
        echo "false" > "$RESULTS/newlistener-$order.txt"
    fi

    # Count only zombies left by the spike's own processes. A bare zombie count
    # also picks up short-lived helpers from docker exec, which is noise.
    "${IN_SPIKE[@]}" bash -c \
        'ps -eo stat,comm | awk "/^Z/ && (/proxy/ || /agent/)" | wc -l' \
        > "$RESULTS/zombies-$order.txt" 2>/dev/null

    "${IN_SPIKE[@]}" bash -c 'pkill -9 -f /spike/proxy || true' >/dev/null 2>&1
}

report() {
    local order="$1"
    python3 - "$order" "$RESULTS" <<'PY'
import json, sys, pathlib
order, results = sys.argv[1], pathlib.Path(sys.argv[2])

def load(name, default=None):
    p = results / name
    if not p.exists() or not p.read_text().strip():
        return default
    text = p.read_text().strip()
    try:
        return json.loads(text.splitlines()[-1])
    except json.JSONDecodeError:
        return default

agent = load(f"agent-{order}.json", {})
loadgen = load(f"load-{order}.json", {})
keepalive = load(f"long-{order}.json", {})
new_listener = (results / f"newlistener-{order}.txt").read_text().strip() == "true"
zombies = int((results / f"zombies-{order}.txt").read_text().strip() or 0)

sent = loadgen.get("sent", 0)
failed = loadgen.get("failed", -1)
missed = agent.get("heartbeat_missed", -1)
gap = agent.get("heartbeat_longest_gap_ms", -1)
pid_stable = agent.get("agent_pid_start") == agent.get("agent_pid_end")
gen1_gone = not agent.get("gen1_still_alive", True)
exit_ms = agent.get("gen1_exit_ms")

rows = [
    ("requests sent", sent, sent >= 1000),
    ("requests failed", failed, failed == 0),
    ("first error", loadgen.get("first_error", "") or "-", failed == 0),
    ("agent pid stable", pid_stable, pid_stable),
    ("heartbeat ticks", agent.get("heartbeat_ticks", 0), True),
    ("heartbeat missed", missed, missed == 0),
    ("longest heartbeat gap ms", gap, 0 <= gap <= 450),
    ("old process exited", gen1_gone, gen1_gone),
    ("old process exit ms", exit_ms if exit_ms is not None else "never", gen1_gone),
    ("new listener serves", new_listener, new_listener),
    ("zombies", zombies, zombies == 0),
    ("keepalive survived upgrade", keepalive.get("ok", 0), keepalive.get("ok", 0) >= 20),
    ("keepalive failures", keepalive.get("failed", -1), keepalive.get("failed", -1) == 0),
    (
        "keepalive broke after ms",
        keepalive.get("broke_after_ms") if keepalive.get("broke_after_ms") is not None else "never",
        True,
    ),
]

print(f"  order: {order}")
ok = True
for label, value, good in rows:
    mark = "ok    " if good else "FAILED"
    print(f"  {mark} {label}: {value}")
    ok = ok and good
print(f"  verdict: {'PASS' if ok else 'FAIL'}")
sys.exit(0 if ok else 1)
PY
}

run_order "signal-first"
run_order "new-first"

echo
echo "== results =="
signal_ok=0
new_ok=0
report "signal-first" || signal_ok=1
echo
report "new-first" || new_ok=1

echo
if [ "$signal_ok" -eq 0 ] || [ "$new_ok" -eq 0 ]; then
    echo "at least one ordering holds; see plan/notes/spike-upgrade-koreografisi.md"
    exit 0
fi
echo "neither ordering held; ADR-0002 needs revisiting"
exit 1
