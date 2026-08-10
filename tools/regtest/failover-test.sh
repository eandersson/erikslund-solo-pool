#!/usr/bin/env bash
# Verify that the pool fails over to a peered backup Bitcoin Core node and keeps mining.
set -uo pipefail

export MSYS_NO_PATHCONV=1

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && { pwd -W 2>/dev/null || pwd; })}"
NETWORK=erikslund-failover
BITCOIND_IMAGE=erikslund-bitcoind:regtest
TOOLCHAIN_IMAGE=erikslund-pool-build
MINER_IMAGE=erikslund-miner:latest
CONFIG="$REPO_ROOT/tools/regtest/failover-pool.yml"
PRIMARY=ep-fo-a
BACKUP=ep-fo-b
POOL_CONTAINER=ep-fo-pool
MINER_CONTAINER=ep-fo-miner
MINER_ADDRESS=bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf
BITCOIN_CLI="bitcoin-cli -regtest -rpcuser=erikslund -rpcpassword=erikslundpass -rpcport=18443"
FAILOVER_BUDGET_SECONDS="${FAILOVER_BUDGET_SECONDS:-20}"
REGTEST_COMPOSE="docker compose -f $REPO_ROOT/tools/regtest/docker-compose.yml"

PASS_COUNT=0
FAIL_COUNT=0

pass() {
    echo "  [PASS] $*"
    PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
    echo "  [FAIL] $*"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

height() {
    docker exec "$1" $BITCOIN_CLI getblockcount 2>/dev/null || echo "-1"
}

pool_logs() {
    docker logs "$POOL_CONTAINER" 2>&1
}

cleanup() {
    docker rm -f "$POOL_CONTAINER" "$MINER_CONTAINER" "$PRIMARY" "$BACKUP" >/dev/null 2>&1
    docker network rm "$NETWORK" >/dev/null 2>&1
}
trap cleanup EXIT
cleanup

run_bitcoind() {
    docker run -d --name "$1" --network "$NETWORK" \
        -v "$REPO_ROOT/tools/regtest/bitcoin.conf:/etc/bitcoin/bitcoin.conf:ro" \
        "$BITCOIND_IMAGE" >/dev/null
}

run_miner() {
    docker rm -f "$MINER_CONTAINER" >/dev/null 2>&1
    docker run -d --name "$MINER_CONTAINER" --network "$NETWORK" \
        "$MINER_IMAGE" --algo sha256d \
        --url "stratum+tcp://$POOL_CONTAINER:3333" \
        --user "$MINER_ADDRESS" --pass x --threads 2 --retry-pause 1 >/dev/null
}

failover_epoch() {
    local timestamp
    timestamp=$(docker logs --timestamps "$POOL_CONTAINER" 2>&1 | grep -m1 "failed over to" \
        | awk '{print $1}' | sed -E 's/\.[0-9]+Z$/Z/')
    [ -n "$timestamp" ] && date -u -d "$timestamp" +%s 2>/dev/null
}

echo "==> 1/6 build pool, bitcoind, and miner images"
docker build -q -t "$BITCOIND_IMAGE" -f "$REPO_ROOT/tools/regtest/Dockerfile.bitcoind" \
    "$REPO_ROOT/tools/regtest" >/dev/null
$REGTEST_COMPOSE build miner >/dev/null 2>&1
POOL_READY=0
if [ "${POOL_PREBUILT:-0}" = "1" ]; then
    POOL_READY=1
elif docker build -q -t "$TOOLCHAIN_IMAGE" "$REPO_ROOT/docker" >/dev/null && \
        docker run --rm -v "$REPO_ROOT:/src:ro" -v erikslund-build:/build \
            "$TOOLCHAIN_IMAGE" >/tmp/failover-build.log 2>&1; then
    POOL_READY=1
fi
if [ "$POOL_READY" -eq 1 ]; then
    pass "pool ready"
else
    fail "pool build"
    tail -30 /tmp/failover-build.log 2>/dev/null
    exit 1
fi

echo "==> 2/6 start two peered regtest nodes"
docker network create "$NETWORK" >/dev/null 2>&1
run_bitcoind "$PRIMARY"
run_bitcoind "$BACKUP"
for node in "$PRIMARY" "$BACKUP"; do
    for _ in $(seq 1 30); do
        [ "$(height "$node")" != "-1" ] && break
        sleep 1
    done
done
docker exec "$PRIMARY" $BITCOIN_CLI addnode "$BACKUP:18444" add >/dev/null 2>&1
docker exec "$BACKUP" $BITCOIN_CLI addnode "$PRIMARY:18444" add >/dev/null 2>&1
for _ in $(seq 1 15); do
    PEER_COUNT=$(docker exec "$PRIMARY" $BITCOIN_CLI getconnectioncount 2>/dev/null || echo 0)
    [ "$PEER_COUNT" -gt 0 ] 2>/dev/null && break
    sleep 1
done
if [ "$(height "$PRIMARY")" -ge 0 ] && [ "$(height "$BACKUP")" -ge 0 ] && \
        [ "$PEER_COUNT" -gt 0 ]; then
    pass "both nodes ready and peered"
else
    fail "nodes not ready or peered"
    exit 1
fi

echo "==> 3/6 start the pool with both nodes"
docker run -d --name "$POOL_CONTAINER" --network "$NETWORK" \
    -v erikslund-build:/build:ro -v "$CONFIG:/cfg/pool.yml:ro" \
    --entrypoint /build/cmake/erikslund-pool "$TOOLCHAIN_IMAGE" \
    --config /cfg/pool.yml >/dev/null
for _ in $(seq 1 30); do
    POOL_LOGS="$(pool_logs || true)"
    [[ "$POOL_LOGS" == *"Stratum listening"* ]] && break
    sleep 1
done
if [[ "$POOL_LOGS" == *"Stratum listening"* ]]; then
    pass "pool listening on the primary"
else
    fail "pool did not start"
    pool_logs | tail -25
    exit 1
fi

echo "==> 4/6 mine through the primary and synchronize the backup"
run_miner
for _ in $(seq 1 25); do
    [ "$(height "$PRIMARY")" -gt 2 ] 2>/dev/null && break
    sleep 1
done
docker rm -f "$MINER_CONTAINER" >/dev/null 2>&1
for _ in $(seq 1 20); do
    [ "$(height "$PRIMARY")" -gt 0 ] && \
        [ "$(height "$BACKUP")" = "$(height "$PRIMARY")" ] 2>/dev/null && break
    sleep 1
done
PRIMARY_HEIGHT=$(height "$PRIMARY")
BACKUP_HEIGHT=$(height "$BACKUP")
if [ "$PRIMARY_HEIGHT" -gt 0 ]; then
    pass "primary produced blocks"
else
    fail "primary produced no blocks"
fi
if [ "$BACKUP_HEIGHT" = "$PRIMARY_HEIGHT" ]; then
    pass "backup synchronized the primary chain"
else
    fail "backup did not synchronize"
fi

echo "==> 5/6 stop the primary and wait for the backup to advance"
HEIGHT_AT_FAILURE=$(height "$BACKUP")
FAILURE_EPOCH=$(date +%s)
docker kill "$PRIMARY" >/dev/null
run_miner
for _ in $(seq 1 45); do
    sleep 1
    [ "$(height "$BACKUP")" -gt "$HEIGHT_AT_FAILURE" ] 2>/dev/null && break
done
FINAL_HEIGHT=$(height "$BACKUP")
FAILOVER_SECONDS=""
FAILOVER_EPOCH=$(failover_epoch)
[ -n "$FAILOVER_EPOCH" ] && FAILOVER_SECONDS=$((FAILOVER_EPOCH - FAILURE_EPOCH))

echo "==> 6/6 verify continued mining and bounded failover"
if [ "$FINAL_HEIGHT" -gt "$HEIGHT_AT_FAILURE" ]; then
    pass "backup advanced the chain ($HEIGHT_AT_FAILURE -> $FINAL_HEIGHT)"
else
    fail "backup did not advance after failover"
fi
if [ -z "$FAILOVER_SECONDS" ]; then
    if pool_logs | grep -q "failed over to"; then
        pass "pool logged the failover"
    else
        fail "pool did not log a failover"
    fi
elif [ "$FAILOVER_SECONDS" -le "$FAILOVER_BUDGET_SECONDS" ]; then
    pass "failover completed in ${FAILOVER_SECONDS}s"
else
    fail "failover took ${FAILOVER_SECONDS}s (budget ${FAILOVER_BUDGET_SECONDS}s)"
fi

if [ "$FAIL_COUNT" -gt 0 ]; then
    pool_logs | grep -iE "fail|resolve|transport|unreachable|ignoring|waiting" | tail -20
fi

echo
if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "ALL CHECKS PASSED ($PASS_COUNT passed)."
else
    echo "$FAIL_COUNT CHECK(S) FAILED."
fi
exit "$FAIL_COUNT"
