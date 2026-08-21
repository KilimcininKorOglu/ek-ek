#!/usr/bin/env bash
# Prove the preconditions the product depends on, one at a time.
#
# Every check reports on its own line and the script never stops at the first
# failure, because a single run must show which precondition is missing rather
# than the first one encountered.
#
# The multicast check is the important one. If it fails, VRRP cannot work in
# this environment and ADR-0012 has to be revisited.
set -uo pipefail

cd "$(dirname "$0")/.."

# --env-file is explicit: compose looks for .env next to the compose file, not
# in the project root, and a missing HOST_UID makes the persistence check write
# as the wrong user.
readonly COMPOSE=(docker compose --env-file .env -f docker/compose.yml)

if [ ! -f .env ]; then
    echo "missing .env; run 'make dev-env' first"
    exit 1
fi
readonly NODE1=node1
readonly NODE2=node2
# Not assigned to any container; reserved for VIP tests.
readonly TEST_VIP=172.28.0.100
readonly VRRP_GROUP=224.0.0.18
# VRRP rides directly on IP, protocol number 112. Testing with UDP would prove
# less, because UDP multicast can pass where a raw protocol does not.
readonly VRRP_PROTO=112

passed=0
failed=0

ok() {
    echo "  ok      $1"
    passed=$((passed + 1))
}

fail() {
    echo "  FAILED  $1"
    failed=$((failed + 1))
}

check() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        ok "$label"
    else
        fail "$label"
    fi
}

echo "development environment checks"

# --- Containers -------------------------------------------------------------

for name in node1 node2 node3 backend1 backend2; do
    check "container ek-ek-$name is running" \
        bash -c "[ \"\$(docker inspect -f '{{.State.Running}}' ek-ek-$name 2>/dev/null)\" = true ]"
done

# --- Fixed addressing -------------------------------------------------------

for pair in "node1:172.28.0.11" "node2:172.28.0.12" "node3:172.28.0.13"; do
    svc="${pair%%:*}"
    want="${pair##*:}"
    check "$svc holds its fixed address $want" \
        bash -c "\"\${@}\" exec -T $svc ip -4 -o addr show eth0 | grep -q '$want'" _ "${COMPOSE[@]}"
done

# --- Reachability -----------------------------------------------------------

check "node1 reaches node2" \
    "${COMPOSE[@]}" exec -T "$NODE1" ping -c1 -W2 172.28.0.12

check "node1 reaches the gateway" \
    "${COMPOSE[@]}" exec -T "$NODE1" ping -c1 -W2 172.28.0.1

# --- Capabilities -----------------------------------------------------------

# Adding and removing an address is exactly what VIP management does.
if "${COMPOSE[@]}" exec -T "$NODE1" ip addr add "$TEST_VIP/24" dev eth0 >/dev/null 2>&1; then
    ok "CAP_NET_ADMIN: node1 can add $TEST_VIP"

    # The VIP must stay inside the container network namespace. If it shows up
    # on the host, a test could hijack an address the host actually uses.
    if ifconfig 2>/dev/null | grep -q "inet $TEST_VIP" \
        || ip -4 -o addr show 2>/dev/null | grep -q "$TEST_VIP"; then
        fail "the VIP leaked onto the host"
    else
        ok "the VIP stayed inside the container namespace"
    fi

    check "node1 can remove $TEST_VIP again" \
        "${COMPOSE[@]}" exec -T "$NODE1" ip addr del "$TEST_VIP/24" dev eth0
else
    fail "CAP_NET_ADMIN: node1 cannot add $TEST_VIP"
    fail "the VIP stayed inside the container namespace (skipped, add failed)"
    fail "node1 can remove $TEST_VIP again (skipped, add failed)"
fi

check "CAP_NET_RAW: node1 can open a raw socket on protocol $VRRP_PROTO" \
    "${COMPOSE[@]}" exec -T "$NODE1" python3 -c \
    "import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, $VRRP_PROTO).close()"

# --- Multicast, the VRRP precondition ---------------------------------------

echo "  ...     capturing protocol $VRRP_PROTO on node2"
capture="$(mktemp)"
"${COMPOSE[@]}" exec -T "$NODE2" \
    timeout 12 tcpdump -i eth0 -c 1 -n "proto $VRRP_PROTO" >"$capture" 2>&1 &
capture_pid=$!

sleep 3
for _ in 1 2 3 4 5; do
    "${COMPOSE[@]}" exec -T "$NODE1" python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, $VRRP_PROTO)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
s.sendto(b'ek-ek multicast probe', ('$VRRP_GROUP', 0))
s.close()
" >/dev/null 2>&1
    sleep 1
done

wait "$capture_pid" 2>/dev/null
if grep -q "$VRRP_GROUP" "$capture"; then
    ok "multicast: node2 saw a protocol $VRRP_PROTO packet sent to $VRRP_GROUP"
else
    fail "multicast: node2 saw nothing on $VRRP_GROUP (VRRP cannot work here)"
    sed 's/^/          /' "$capture"
fi
rm -f "$capture"

# --- Backends ---------------------------------------------------------------

check "node1 reaches backend1 over HTTP" \
    "${COMPOSE[@]}" exec -T "$NODE1" curl -fsS --max-time 5 http://172.28.0.21/

check "node1 reaches backend2 over HTTP" \
    "${COMPOSE[@]}" exec -T "$NODE1" curl -fsS --max-time 5 http://172.28.0.22/

# --- Persistence ------------------------------------------------------------

stamp="probe-$$"
if "${COMPOSE[@]}" exec -T "$NODE1" bash -c \
    "setpriv --reuid=\${HOST_UID} --regid=\${HOST_GID} --clear-groups \
     tee /var/lib/ek-ek/$stamp <<<'$stamp'" >/dev/null 2>&1; then
    ok "node1 can write into /var/lib/ek-ek as the host user"

    check "the file appears on the host under docker-data/node1" \
        test -f "docker-data/node1/$stamp"

    owner="$(stat -f '%u' "docker-data/node1/$stamp" 2>/dev/null \
        || stat -c '%u' "docker-data/node1/$stamp" 2>/dev/null)"
    if [ "$owner" = "$(id -u)" ]; then
        ok "the file belongs to the host user, not root"
    else
        fail "the file belongs to uid $owner, expected $(id -u)"
    fi

    rm -f "docker-data/node1/$stamp"
else
    fail "node1 can write into /var/lib/ek-ek as the host user"
    fail "the file appears on the host under docker-data/node1 (skipped)"
    fail "the file belongs to the host user, not root (skipped)"
fi

# --- No named volumes -------------------------------------------------------

if [ -z "$(docker volume ls --filter 'name=ek-ek' --format '{{.Name}}')" ]; then
    ok "no docker named volume was created"
else
    fail "a docker named volume exists; data must live in docker-data"
fi

echo
echo "passed: $passed, failed: $failed"
[ "$failed" -eq 0 ]
