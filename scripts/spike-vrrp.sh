#!/usr/bin/env bash
# Run the T-010 measurement and report what it found.
#
# The question: do VRRP advertisements, rtnetlink address moves and gratuitous
# ARP work together well enough for failover, and how long does a takeover
# actually take? ADR-0006 and ADR-0007 depend on the answer.
#
# The gratuitous ARP is measured on its own. Without it the VIP still appears
# in `ip addr` on the new master, so any check that only looks at the address
# reports success while frames keep arriving at the old node.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

COMPOSE=(docker compose --env-file .env -f docker/compose.yml)
# The default the product intends to ship (ADR-0029). Every scenario that is
# not sweeping the interval runs at this value, so what is measured is the
# behaviour users will get rather than a number picked for the test.
ADVER_MS=300
VIP=172.28.0.100
PREFIX=24
RESULTS=docker-data/spike-vrrp-results

if [ ! -f .env ]; then
    echo "missing .env; run 'make dev-env' first"
    exit 1
fi

rm -rf "$RESULTS"
mkdir -p "$RESULTS"

node_ip() {
    case "$1" in
        node1) echo 172.28.0.11 ;;
        node2) echo 172.28.0.12 ;;
        node3) echo 172.28.0.13 ;;
        *) echo "unknown node $1" >&2; return 1 ;;
    esac
}

peers_for() {
    local self="$1" out=""
    for n in node1 node2 node3; do
        [ "$n" = "$self" ] && continue
        out="$out,$(node_ip "$n")"
    done
    echo "${out#,}"
}

in_node() {
    local node="$1"
    shift
    "${COMPOSE[@]}" exec -T "$node" "$@" 2>/dev/null | tr -d '\r'
}

mac_of() {
    in_node "$1" cat /sys/class/net/eth0/address | tr -d '\n'
}

# --------------------------------------------------------------------------
# Building and distributing the binary
# --------------------------------------------------------------------------
# The nodes carry the capabilities but no Rust toolchain, and the spike
# container has the toolchain but no capabilities. Both images are bookworm, so
# the binary built in one runs in the other. The bind mounts are the transport.

echo "== building the spike =="
"${COMPOSE[@]}" exec -T spike bash -c '
    set -e
    rm -rf /spike/vrrp-build
    mkdir -p /spike/vrrp-build
    cp -r /spike/src-tree/vrrp/. /spike/vrrp-build
    cd /spike/vrrp-build
    CARGO_TARGET_DIR=/spike/target/vrrp cargo build --release --quiet
' || { echo "build failed"; exit 1; }

for n in node1 node2 node3; do
    cp docker-data/spike-target/vrrp/release/vrrp "docker-data/$n/vrrp" || exit 1
    chmod +x "docker-data/$n/vrrp"
done

NODE1_MAC="$(mac_of node1)"
NODE2_MAC="$(mac_of node2)"
echo "  node1 mac $NODE1_MAC"
echo "  node2 mac $NODE2_MAC"

# --------------------------------------------------------------------------
# Process and state helpers
# --------------------------------------------------------------------------

start_vrrp() {
    # node priority adver_ms preempt multicast run_ms tag [skip_garp]
    local node="$1" prio="$2" adver="$3" preempt="$4" multicast="$5" run_ms="$6" tag="$7"
    local skip_garp="${8:-0}"
    "${COMPOSE[@]}" exec -T "$node" env \
        VRRP_NODE="$node" \
        VRRP_SELF="$(node_ip "$node")" \
        VRRP_VIP="$VIP" \
        VRRP_PREFIX_LEN="$PREFIX" \
        VRRP_PEERS="$(peers_for "$node")" \
        VRRP_PRIORITY="$prio" \
        VRRP_ADVER_MS="$adver" \
        VRRP_PREEMPT="$preempt" \
        VRRP_MULTICAST="$multicast" \
        VRRP_RUN_MS="$run_ms" \
        VRRP_SKIP_GARP="$skip_garp" \
        /var/lib/ek-ek/vrrp \
        >"$RESULTS/$tag-$node.jsonl" 2>"$RESULTS/$tag-$node.err" &
}

kill_vrrp() {
    # An unplanned loss. No priority zero advertisement, so the peers have to
    # notice by timeout, which is the case failover has to survive.
    in_node "$1" pkill -9 -f /var/lib/ek-ek/vrrp >/dev/null 2>&1
}

stop_vrrp() {
    # A planned stop. The process removes the VIP and says goodbye.
    in_node "$1" pkill -TERM -f /var/lib/ek-ek/vrrp >/dev/null 2>&1
}

reset_all() {
    for n in node1 node2 node3; do
        in_node "$n" pkill -9 -f /var/lib/ek-ek/vrrp >/dev/null 2>&1
        in_node "$n" ip addr del "$VIP/$PREFIX" dev eth0 >/dev/null 2>&1
        in_node "$n" ip neigh flush dev eth0 >/dev/null 2>&1
    done
    wait 2>/dev/null
    sleep 0.3
}

has_vip() {
    in_node "$1" ip -4 addr show dev eth0 | grep -q "$VIP" && echo yes || echo no
}

neigh_mac() {
    in_node "$1" ip neigh show "$VIP" dev eth0 \
        | awk '/lladdr/ { for (i = 1; i < NF; i++) if ($i == "lladdr") print $(i + 1) }' \
        | head -1
}

wait_for_event() {
    # file event timeout_seconds
    local file="$1" event="$2" limit="${3:-15}" i=0
    while [ "$i" -lt $((limit * 10)) ]; do
        if grep -q "\"event\":\"$event\"" "$file" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

field() {
    # file event key -> value of the LAST matching event, empty when absent.
    #
    # The last one, not the first. A cold start can produce a short lived
    # master before the first advertisement arrives, and reading the first
    # event would report that transition instead of the takeover under test.
    python3 - "$1" "$2" "$3" <<'PY'
import json, sys
path, event, key = sys.argv[1:4]
try:
    lines = open(path).read().splitlines()
except OSError:
    sys.exit(0)
found = None
for line in lines:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        continue
    if obj.get("event") == event and obj.get(key) is not None:
        found = obj.get(key)
print("" if found is None else found)
PY
}

CHECK_FILE="$RESULTS/checks.txt"
: >"$CHECK_FILE"

check() {
    # label ok detail
    printf '%s|%s|%s\n' "$1" "$2" "${3:-}" >>"$CHECK_FILE"
}

# --------------------------------------------------------------------------
# S1: advertisements flow, the higher priority node takes the VIP
# --------------------------------------------------------------------------

scenario_election() {
    echo
    echo "== S1: election and advertisement flow =="
    reset_all

    in_node node3 bash -c \
        'timeout 12 tcpdump -i eth0 -n -c 20 -v "proto 112 or arp"' \
        >"$RESULTS/s1-tcpdump.txt" 2>&1 &
    local capture=$!
    sleep 1.5

    start_vrrp node1 200 "$ADVER_MS" 1 0 11000 s1
    start_vrrp node2 150 "$ADVER_MS" 1 0 11000 s1

    if ! wait_for_event "$RESULTS/s1-node1.jsonl" became_master 10; then
        check "S1 node1 becomes master" no "no became_master event"
        reset_all
        return
    fi
    sleep 1

    check "S1 node1 becomes master" yes "priority 200"
    check "S1 VIP on node1" "$(has_vip node1)" ""
    check "S1 VIP absent on node2" "$([ "$(has_vip node2)" = no ] && echo yes || echo no)" ""

    wait "$capture" 2>/dev/null
    if grep -q "VRRPv3, Advertisement, vrid 51, prio 200" "$RESULTS/s1-tcpdump.txt"; then
        check "S1 tcpdump parses the advertisement as VRRPv3" yes \
            "$(grep -m1 -o 'VRRPv3, Advertisement.*' "$RESULTS/s1-tcpdump.txt")"
    else
        check "S1 tcpdump parses the advertisement as VRRPv3" no "see s1-tcpdump.txt"
    fi

    # A wrong checksum is invisible to our own decoder because it never verifies
    # one. tcpdump does, and says so.
    if grep -qi "bad vrrp cksum" "$RESULTS/s1-tcpdump.txt"; then
        check "S1 checksum accepted by an independent parser" no "tcpdump reports a bad checksum"
    else
        check "S1 checksum accepted by an independent parser" yes ""
    fi

    if grep -q "224.0.0.18" "$RESULTS/s1-tcpdump.txt"; then
        check "S1 unicast run sends nothing to the VRRP group" no "224.0.0.18 seen on the wire"
    else
        check "S1 unicast run sends nothing to the VRRP group" yes ""
    fi

    reset_all
}

# --------------------------------------------------------------------------
# S2: failover time, gratuitous ARP, and reachability of the new master
# --------------------------------------------------------------------------

scenario_failover() {
    # adver_ms skip_garp tag
    #
    # With skip_garp the expectations invert. That run is the negative control:
    # if the ARP checks still pass without an ARP being sent, they are not
    # measuring anything and the rest of the scenario proves nothing.
    #
    # assert_deadline is only set for the interval the product intends to make
    # its default. The other intervals are a sweep: their numbers go into the
    # table so the default can be chosen from measurements instead of taste.
    local adver="$1" skip_garp="$2" tag="$3" assert_deadline="${4:-no}"
    echo
    echo "== S2: failover, adver_ms=$adver skip_garp=$skip_garp =="
    reset_all

    start_vrrp node1 200 "$adver" 1 0 25000 "$tag"
    start_vrrp node2 150 "$adver" 1 0 25000 "$tag" "$skip_garp"

    if ! wait_for_event "$RESULTS/$tag-node1.jsonl" became_master 10; then
        check "S2/$tag node1 becomes master" no "no became_master event"
        reset_all
        return
    fi
    sleep 0.5

    # Teach node3 the old mapping first. Without this the cache is empty after
    # failover and an empty cache would look the same as a refreshed one.
    in_node node3 ping -c 2 -W 1 "$VIP" >/dev/null 2>&1
    local before
    before="$(neigh_mac node3)"
    check "S2/$tag node3 learns node1 as the VIP owner" \
        "$([ "$before" = "$NODE1_MAC" ] && echo yes || echo no)" "$before"

    in_node node3 bash -c 'timeout 12 tcpdump -i eth0 -n -c 30 arp' \
        >"$RESULTS/$tag-arp.txt" 2>&1 &
    local capture=$!
    sleep 1

    kill_vrrp node1

    if ! wait_for_event "$RESULTS/$tag-node2.jsonl" became_master 12; then
        check "S2/$tag node2 takes over" no "no became_master event"
        wait "$capture" 2>/dev/null
        reset_all
        return
    fi

    # The cache is read before any traffic is sent, so only an unsolicited ARP
    # could have changed it.
    local after
    after="$(neigh_mac node3)"

    local detect
    detect="$(field "$RESULTS/$tag-node2.jsonl" became_master detect_ms)"
    check "S2/$tag node2 takes over" yes "detect_ms=$detect"
    printf '%s\t%s\t%s\n' "$adver" "$skip_garp" "${detect:-unknown}" >>"$RESULTS/sweep.tsv"
    if [ "$assert_deadline" = yes ]; then
        check "S2/$tag takeover under 3000 ms" \
            "$([ -n "$detect" ] && [ "$detect" -lt 3000 ] && echo yes || echo no)" \
            "${detect:-unknown} ms"
    else
        echo "  sweep: adver_ms=$adver detect_ms=${detect:-unknown}"
    fi
    check "S2/$tag VIP on node2" "$(has_vip node2)" ""

    wait "$capture" 2>/dev/null
    local garp_seen=no
    grep -q "Reply $VIP is-at $NODE2_MAC" "$RESULTS/$tag-arp.txt" && garp_seen=yes
    local cache_moved=no
    [ "$after" = "$NODE2_MAC" ] && cache_moved=yes

    local reachable=no
    in_node node3 ping -c 2 -W 1 "$VIP" >/dev/null 2>&1 && reachable=yes

    if [ "$skip_garp" = 1 ]; then
        check "S2/$tag control: no gratuitous ARP is sent" \
            "$([ "$garp_seen" = no ] && echo yes || echo no)" "garp_seen=$garp_seen"
        check "S2/$tag control: node3 cache still points at the dead node" \
            "$([ "$cache_moved" = no ] && echo yes || echo no)" "$after"

        # A killed master never removed its own VIP, so the address exists on
        # both nodes and the ping still succeeds.
        check "S2/$tag control: the dead node still holds the VIP" "$(has_vip node1)" ""
        echo "  control: VIP reachable with the stale cache: $reachable"

        # What this environment can prove is where the frames are addressed.
        # Where they arrive is a property of the switch: the Docker bridge
        # floods a frame whose destination MAC it cannot place, so the new
        # master answers even though the frame was not meant for it. On a
        # physical switch it would not. That half belongs to T-069 (R-25).
        in_node node1 ip addr del "$VIP/$PREFIX" dev eth0 >/dev/null 2>&1
        in_node node3 bash -c 'timeout 8 tcpdump -i eth0 -n -e icmp' \
            >"$RESULTS/$tag-stale.txt" 2>&1 &
        local stale_capture=$!
        sleep 1
        in_node node3 ping -c 2 -W 1 "$VIP" >/dev/null 2>&1
        wait "$stale_capture" 2>/dev/null

        if grep -q "> $NODE1_MAC.*ICMP echo request" "$RESULTS/$tag-stale.txt"; then
            check "S2/$tag control: traffic is still addressed to the dead node" yes \
                "destination mac $NODE1_MAC"
        else
            check "S2/$tag control: traffic is still addressed to the dead node" no \
                "no request to $NODE1_MAC captured"
        fi
        local replier
        replier="$(grep -m1 'ICMP echo reply' "$RESULTS/$tag-stale.txt" | awk '{print $2}')"
        echo "  control: the reply came from ${replier:-nobody}; the bridge floods,"
        echo "           so who receives the frame is not measurable here (R-25, T-069)"
    else
        check "S2/$tag gratuitous ARP seen on the wire" "$garp_seen" \
            "Reply $VIP is-at $NODE2_MAC"
        check "S2/$tag node3 cache points at node2 without new traffic" \
            "$cache_moved" "$after"
        check "S2/$tag new master answers the VIP" "$reachable" ""
        # Recorded because it decides what failover actually depends on: after
        # an unclean loss the address exists on both nodes, so the gratuitous
        # ARP is the only thing steering traffic to the new one.
        check "S2/$tag killed node still holds the VIP" "$(has_vip node1)" ""
    fi

    reset_all
}

# --------------------------------------------------------------------------
# S3: preempt on and off
# --------------------------------------------------------------------------

scenario_preempt() {
    # preempt tag
    local preempt="$1" tag="$2"
    echo
    echo "== S3: preempt=$preempt =="
    reset_all

    start_vrrp node1 200 "$ADVER_MS" 1 0 8000 "$tag-first"
    start_vrrp node2 150 "$ADVER_MS" 1 0 30000 "$tag"

    if ! wait_for_event "$RESULTS/$tag-first-node1.jsonl" became_master 10; then
        check "S3/$tag node1 starts as master" no ""
        reset_all
        return
    fi

    kill_vrrp node1
    if ! wait_for_event "$RESULTS/$tag-node2.jsonl" became_master 12; then
        check "S3/$tag node2 takes over" no ""
        reset_all
        return
    fi
    check "S3/$tag node2 takes over" yes ""

    # node1 comes back with the higher priority. Whether it should reclaim the
    # VIP is exactly what preempt decides.
    start_vrrp node1 200 "$ADVER_MS" "$preempt" 0 12000 "$tag-return"
    sleep 6

    local on_node1 on_node2
    on_node1="$(has_vip node1)"
    on_node2="$(has_vip node2)"

    if [ "$preempt" = 1 ]; then
        check "S3 preempt on: node1 reclaims the VIP" "$on_node1" ""
        check "S3 preempt on: node2 gives it up" \
            "$([ "$on_node2" = no ] && echo yes || echo no)" ""
    else
        check "S3 preempt off: node1 stays backup" \
            "$([ "$on_node1" = no ] && echo yes || echo no)" ""
        check "S3 preempt off: node2 keeps the VIP" "$on_node2" ""
    fi

    reset_all
}

# --------------------------------------------------------------------------
# S4: three nodes, the second in line takes over, not the third
# --------------------------------------------------------------------------

scenario_three_nodes() {
    local adver="$1" rounds="$2"
    echo
    echo "== S4: three nodes, adver_ms=$adver, $rounds rounds =="
    local correct=0 round=1

    while [ "$round" -le "$rounds" ]; do
        reset_all
        local tag="s4-$adver-$round"
        start_vrrp node1 200 "$adver" 1 0 20000 "$tag"
        start_vrrp node2 150 "$adver" 1 0 20000 "$tag"
        start_vrrp node3 100 "$adver" 1 0 20000 "$tag"

        if ! wait_for_event "$RESULTS/$tag-node1.jsonl" became_master 10; then
            echo "  round $round: node1 never became master"
            round=$((round + 1))
            continue
        fi
        sleep 1
        kill_vrrp node1

        if ! wait_for_event "$RESULTS/$tag-node2.jsonl" became_master 12; then
            echo "  round $round: node2 did not take over"
            round=$((round + 1))
            continue
        fi
        # Give node3 more than its own master down interval to get it wrong.
        sleep 2

        local n2 n3 detect
        n2="$(has_vip node2)"
        n3="$(has_vip node3)"
        detect="$(field "$RESULTS/$tag-node2.jsonl" became_master detect_ms)"
        if [ "$n2" = yes ] && [ "$n3" = no ]; then
            correct=$((correct + 1))
            echo "  round $round: node2 took over in ${detect:-?} ms, node3 stayed backup"
        else
            echo "  round $round: WRONG node2=$n2 node3=$n3"
        fi
        round=$((round + 1))
    done

    reset_all
    check "S4 second in line takes over every round" \
        "$([ "$correct" -eq "$rounds" ] && echo yes || echo no)" \
        "$correct/$rounds"
}

# --------------------------------------------------------------------------
# S7: repeated cold starts
# --------------------------------------------------------------------------
# At a cold start nobody advertises until somebody is master, so each node arms
# its timer from its own process start rather than from a shared packet. What
# separates two nodes is then the difference in skew time alone, which is close
# to the jitter of starting three processes. Once is not a sample, so the start
# is repeated and the log analysis at the end counts what happened.

scenario_cold_start() {
    local rounds="$1" settled=0 round=1
    echo
    echo "== S7: $rounds cold starts =="

    while [ "$round" -le "$rounds" ]; do
        reset_all
        local tag="s7-$round"
        start_vrrp node1 200 "$ADVER_MS" 1 0 6000 "$tag"
        start_vrrp node2 150 "$ADVER_MS" 1 0 6000 "$tag"
        start_vrrp node3 100 "$ADVER_MS" 1 0 6000 "$tag"

        if wait_for_event "$RESULTS/$tag-node1.jsonl" became_master 8; then
            sleep 1.5
            local holders=0
            for n in node1 node2 node3; do
                [ "$(has_vip "$n")" = yes ] && holders=$((holders + 1))
            done
            if [ "$holders" -eq 1 ] && [ "$(has_vip node1)" = yes ]; then
                settled=$((settled + 1))
            else
                echo "  round $round: $holders holder(s) after settling"
            fi
        else
            echo "  round $round: node1 never became master"
        fi
        round=$((round + 1))
    done

    reset_all
    check "S7 a cold start settles on the highest priority node" \
        "$([ "$settled" -eq "$rounds" ] && echo yes || echo no)" "$settled/$rounds"
}

# --------------------------------------------------------------------------
# S5: a planned stop removes the VIP
# --------------------------------------------------------------------------

scenario_vip_removal() {
    echo
    echo "== S5: planned stop removes the VIP =="
    reset_all

    start_vrrp node1 200 "$ADVER_MS" 1 0 30000 s5
    if ! wait_for_event "$RESULTS/s5-node1.jsonl" became_master 10; then
        check "S5 node1 becomes master" no ""
        reset_all
        return
    fi
    check "S5 VIP present before the stop" "$(has_vip node1)" ""

    stop_vrrp node1
    sleep 2
    check "S5 VIP gone after the stop" \
        "$([ "$(has_vip node1)" = no ] && echo yes || echo no)" ""

    if grep -q '"event":"vip_removed"' "$RESULTS/s5-node1.jsonl"; then
        check "S5 removal reported by the process" yes ""
    else
        check "S5 removal reported by the process" no ""
    fi

    reset_all
}

# --------------------------------------------------------------------------
# S6: the same thing over multicast
# --------------------------------------------------------------------------

scenario_multicast() {
    echo
    echo "== S6: multicast mode =="
    reset_all

    in_node node3 bash -c 'timeout 20 tcpdump -i eth0 -n -c 20 -v proto 112' \
        >"$RESULTS/s6-tcpdump.txt" 2>&1 &
    local capture=$!
    sleep 1.5

    start_vrrp node1 200 "$ADVER_MS" 1 1 18000 s6
    start_vrrp node2 150 "$ADVER_MS" 1 1 18000 s6

    if ! wait_for_event "$RESULTS/s6-node1.jsonl" became_master 10; then
        check "S6 multicast election works" no ""
        wait "$capture" 2>/dev/null
        reset_all
        return
    fi
    sleep 1
    check "S6 multicast election works" "$(has_vip node1)" ""

    kill_vrrp node1
    if wait_for_event "$RESULTS/s6-node2.jsonl" became_master 12; then
        check "S6 multicast failover works" "$(has_vip node2)" \
            "detect_ms=$(field "$RESULTS/s6-node2.jsonl" became_master detect_ms)"
    else
        check "S6 multicast failover works" no ""
    fi

    wait "$capture" 2>/dev/null
    if grep -q "224.0.0.18" "$RESULTS/s6-tcpdump.txt"; then
        check "S6 advertisements reach the VRRP group address" yes ""
    else
        check "S6 advertisements reach the VRRP group address" no ""
    fi

    reset_all
}

# --------------------------------------------------------------------------

trap 'reset_all' EXIT

printf 'adver_ms\tskip_garp\tdetect_ms\n' >"$RESULTS/sweep.tsv"

scenario_election
scenario_failover 1000 0 s2-1000 no
scenario_failover 500 0 s2-500 no
scenario_failover "$ADVER_MS" 0 "s2-$ADVER_MS" yes
scenario_failover 250 0 s2-250 no
scenario_failover "$ADVER_MS" 1 s2-nogarp no
scenario_preempt 1 s3-on
scenario_preempt 0 s3-off
scenario_three_nodes "$ADVER_MS" 5
scenario_cold_start 15
scenario_vip_removal
scenario_multicast

# --------------------------------------------------------------------------
# Cold start: how long can two nodes hold the VIP at once
# --------------------------------------------------------------------------
# Until somebody is master nobody advertises, so at a cold start each node arms
# its timer from its own process start instead of from a shared packet. What
# separates two nodes is then only the difference in skew time, around 100 ms
# at a 500 ms interval, which is the same order as process start jitter. So two
# nodes can briefly claim the VIP. The window is measured rather than assumed
# to be absent, and the check is that the first advertisement closes it.

echo
echo "== cold start analysis =="
python3 - "$RESULTS" >"$RESULTS/double-master.txt" <<'PY'
import json, pathlib, sys

results = pathlib.Path(sys.argv[1])
cold, preempted = [], []

for path in sorted(results.glob("*.jsonl")):
    claim = None
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = event.get("event")
        if name == "became_master":
            claim = event
        elif name == "vip_removed" and event.get("reason") == "preempted" and claim:
            span = event["ts"] - claim["ts"]
            # A claim made without ever having heard a peer is the cold start
            # race. A claim made after a real detection is the intended
            # handover back to a stronger node, which is a different number.
            bucket = cold if claim.get("last_peer_adv_ts") is None else preempted
            bucket.append((path.name, span))
            claim = None

for name, span in cold:
    print(f"cold-window {name} {span}")
for name, span in preempted:
    print(f"preempt-window {name} {span}")
print(f"cold-count {len(cold)}")
print(f"cold-max {max((s for _, s in cold), default=0)}")
print(f"preempt-count {len(preempted)}")
print(f"preempt-max {max((s for _, s in preempted), default=0)}")
PY
cat "$RESULTS/double-master.txt"

cold_count="$(awk '/^cold-count /{print $2}' "$RESULTS/double-master.txt")"
cold_max="$(awk '/^cold-max /{print $2}' "$RESULTS/double-master.txt")"
# The window has to close on the first advertisement, so it must be shorter
# than one advertisement interval. Anything longer means the yield path did not
# run and two nodes really do keep the address.
check "cold start: the first advertisement closes the double master window" \
    "$([ "${cold_max:-0}" -lt "$ADVER_MS" ] && echo yes || echo no)" \
    "${cold_count:-0} occurrence(s), longest ${cold_max:-0} ms"

echo
echo "== results =="
failed=0
while IFS='|' read -r label ok detail; do
    if [ "$ok" = yes ]; then
        printf '  ok     %s%s\n' "$label" "${detail:+  ($detail)}"
    else
        printf '  FAILED %s%s\n' "$label" "${detail:+  ($detail)}"
        failed=$((failed + 1))
    fi
done <"$CHECK_FILE"

echo
if [ "$failed" -eq 0 ]; then
    echo "all checks passed; write the numbers into plan/notes/spike-vrrp.md"
    exit 0
fi
echo "$failed check(s) failed; raw output is under $RESULTS"
exit 1
