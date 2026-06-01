#!/usr/bin/env bash
#
# Multi-bitcoind failover e2e for the C++ pool. Proves the pool survives losing
# its primary bitcoind: configured with two backends, we mine via the primary,
# kill it mid-run, and assert the pool fails over to the backup and keeps
# producing accepted blocks -- the backup's height climbs ONLY after failover.
#
# Run from the repo root:  bash cpp/docker/failover-test.sh
# (On Windows/git-bash:    MSYS_NO_PATHCONV=1 bash cpp/docker/failover-test.sh)
#
set -uo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && { pwd -W 2>/dev/null || pwd; })}"
NET=erikslund-failover
BTC_IMG=erikslund-bitcoind:regtest
POOL_IMG=erikslund-pool-cpp
MINER_IMG=erikslund-miner:latest
A=ep-fo-a            # primary bitcoind
B=ep-fo-b            # backup bitcoind
POOL=ep-fo-pool
MINER_ADDR=bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf
CLI="bitcoin-cli -regtest -rpcuser=erikslund -rpcpassword=erikslundpass -rpcport=18443"
REGTEST_COMPOSE="docker compose -f $REPO_ROOT/tools/regtest/docker-compose.yml"

PASS=0
FAIL=0
pass() { echo "  [PASS] $*"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }
height() { docker exec "$1" $CLI getblockcount 2>/dev/null || echo "-1"; }
cleanup() {
    docker rm -f "$POOL" "$A" "$B" >/dev/null 2>&1
    docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT
cleanup # clear any leftovers from a prior run

echo "==> 1/6 build pool + bitcoind + miner images"
docker build -q -t "$POOL_IMG" "$REPO_ROOT/cpp/docker" >/dev/null
docker build -q -t "$BTC_IMG" -f "$REPO_ROOT/tools/regtest/Dockerfile.bitcoind" \
    "$REPO_ROOT/tools/regtest" >/dev/null
$REGTEST_COMPOSE build miner >/dev/null 2>&1
if docker run --rm -v "$REPO_ROOT/cpp:/src:ro" -v erikslund-cpp-build:/build \
        "$POOL_IMG" >/tmp/fo-build.log 2>&1; then
    pass "build + unit tests"
else
    fail "build / unit tests"; tail -30 /tmp/fo-build.log; exit 1
fi

echo "==> 2/6 start two regtest bitcoinds (primary + backup)"
docker network create "$NET" >/dev/null 2>&1
for name in "$A" "$B"; do
    docker run -d --name "$name" --network "$NET" \
        -v "$REPO_ROOT/tools/regtest/bitcoin.conf:/etc/bitcoin/bitcoin.conf:ro" \
        "$BTC_IMG" >/dev/null
done
for node in "$A" "$B"; do
    for _ in $(seq 1 30); do [ "$(height "$node")" != "-1" ] && break; sleep 1; done
done
if [ "$(height "$A")" -ge 0 ] && [ "$(height "$B")" -ge 0 ]; then
    pass "both bitcoinds ready (a=$(height "$A") b=$(height "$B"))"
else
    fail "bitcoinds not ready"; exit 1
fi

echo "==> 3/6 start the pool with both backends (primary first)"
docker run -d --name "$POOL" --network "$NET" \
    -v erikslund-cpp-build:/build:ro \
    -v "$REPO_ROOT/cpp/docker/failover-pool.yml:/cfg/pool.yml:ro" \
    --entrypoint /build/cmake/erikslund-pool "$POOL_IMG" --config /cfg/pool.yml >/dev/null
for _ in $(seq 1 15); do
    POOL_LOGS="$(docker logs "$POOL" 2>&1 || true)"
    [[ "$POOL_LOGS" == *"Stratum listening"* ]] && break
    sleep 1
done
if [[ "$POOL_LOGS" == *"Stratum listening"* ]]; then
    pass "pool listening on :3333 (primary=$A)"
else
    fail "pool did not start"; docker logs "$POOL"; exit 1
fi

echo "==> 4/6 mine ~15s via the primary"
timeout 18 docker run --rm --network "$NET" "$MINER_IMG" \
    --algo sha256d --url "stratum+tcp://$POOL:3333" \
    --user "$MINER_ADDR" --pass x --threads 2 --retry-pause 1 >/dev/null 2>&1
A1=$(height "$A")
B1=$(height "$B")
echo "  heights after primary mining: a=$A1 b=$B1"
if [ "$A1" -gt 0 ]; then pass "primary produced blocks (a=$A1)"; else fail "primary produced no blocks"; fi
if [ "$B1" -eq 0 ]; then pass "backup untouched while primary healthy (b=0)"; else fail "backup used before failover (b=$B1)"; fi

echo "==> 5/6 KILL the primary, then keep mining ~30s"
docker kill "$A" >/dev/null
timeout 33 docker run --rm --network "$NET" "$MINER_IMG" \
    --algo sha256d --url "stratum+tcp://$POOL:3333" \
    --user "$MINER_ADDR" --pass x --threads 2 --retry-pause 1 >/dev/null 2>&1
B2=$(height "$B")

echo "==> 6/6 verify failover kept the pool mining"
echo "  backup height after killing primary: b=$B2 (was $B1)"
if [ "$B2" -gt 0 ]; then
    pass "pool failed over to the backup and produced blocks there (b=$B2)"
else
    fail "no blocks on the backup after failover"
fi
POOL_LOGS="$(docker logs "$POOL" 2>&1 || true)"
if [[ "$POOL_LOGS" == *"failed over to"* ]]; then
    pass "pool logged the RPC failover"
else
    fail "pool did not log a failover"
fi

echo
if [ "$FAIL" -eq 0 ]; then
    echo "ALL CHECKS PASSED ($PASS passed)."
else
    echo "$FAIL CHECK(S) FAILED."
fi
exit "$FAIL"
