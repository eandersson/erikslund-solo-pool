#!/usr/bin/env bash
# End-to-end verification of the Python solo pool against regtest bitcoind.
#
# Proves: bitcoind(regtest) -> erikslund_pool serves work + HTTP API -> pooler/cpuminer
# submits shares -> erikslund_pool assembles a segwit block -> bitcoind ACCEPTS it ->
# the HTTP API reflects the found block. Reuses the shared bitcoind + miner harness (docker/).
#
# Usage:  ./python/e2e_regtest.sh         # run and tear down
#         KEEP=1 ./python/e2e_regtest.sh  # leave everything running
set -euo pipefail
cd "$(dirname "$0")/.."                                   # repo root

DC="docker compose -f tools/regtest/docker-compose.yml"
CLI="$DC exec -T bitcoind bitcoin-cli -regtest -rpcuser=erikslund -rpcpassword=erikslundpass -rpcport=18443"
NET=erikslund-regtest_default
KEEP="${KEEP:-0}"
POOL_ON_HOST="${POOL_ON_HOST:-0}"
POOL_LOG=/tmp/eppy-pool.log
POOL_PID=""

if [ "$POOL_ON_HOST" = "1" ]; then
    api() { python -c "import sys,urllib.request as u; sys.stdout.write(u.urlopen('http://127.0.0.1:7777$1',timeout=4).read().decode())"; }
    MINER_URL="stratum+tcp://host.docker.internal:3333"
else
    # Hit the pool's HTTP API from inside its own container (has Python, no curl needed).
    api() { docker exec erikslund_pool-py python -c "import sys,urllib.request as u; sys.stdout.write(u.urlopen('http://127.0.0.1:7777$1',timeout=4).read().decode())"; }
    MINER_URL="stratum+tcp://erikslund_pool-py:3333"
fi

pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; exit 1; }
pool_logs() { if [ "$POOL_ON_HOST" = "1" ]; then cat "$POOL_LOG" 2>/dev/null; else docker logs erikslund_pool-py 2>&1; fi; }
cleanup() {
    [ "$KEEP" = "1" ] && return 0   # KEEP=1 leaves everything running (incl. on failure)
    docker rm -f miner-py >/dev/null 2>&1 || true
    [ -n "$POOL_PID" ] && kill "$POOL_PID" >/dev/null 2>&1 || true
    docker rm -f erikslund_pool-py >/dev/null 2>&1 || true
    $DC down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> 1/6 start bitcoind (regtest)"
$DC up -d bitcoind >/dev/null
for i in $(seq 1 40); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
$CLI getblockchaininfo >/dev/null 2>&1 && pass "bitcoind RPC up" || fail "bitcoind never came up"

echo "==> 2/6 wallet + advance chain past the BIP34 height-16 edge"
$CLI loadwallet test >/dev/null 2>&1 || $CLI -named createwallet wallet_name=test >/dev/null 2>&1 || true
ADDR="$($CLI getnewaddress)"
$CLI generatetoaddress 20 "$ADDR" >/dev/null
[ "$($CLI getblockcount)" -ge 20 ] && pass "chain ready (payout addr=$ADDR)" || fail "chain did not advance"

echo "==> 3/6 start erikslund_pool"
if [ "$POOL_ON_HOST" = "1" ]; then
    # Host process on the runner's prebuilt 3.14t (deps pip-installed by the workflow). Reaches
    # bitcoind via the published 127.0.0.1:18443; binds 0.0.0.0 so the miner container can connect.
    : > "$POOL_LOG"
    python -m erikslund_pool \
      --rpc-url http://127.0.0.1:18443 --rpc-user erikslund --rpc-password erikslundpass \
      --bind-host 0.0.0.0 --bind-port 3333 --api-host 127.0.0.1 --api-port 7777 \
      --difficulty 0.001 --no-vardiff >"$POOL_LOG" 2>&1 &
    POOL_PID=$!
    for i in $(seq 1 30); do
        POOL_LOGS="$(cat "$POOL_LOG" 2>/dev/null || true)"
        [[ "$POOL_LOGS" == *"Stratum listening"* ]] && break
        kill -0 "$POOL_PID" 2>/dev/null || break   # exited early -> stop waiting
        sleep 1
    done
else
    docker build -q -t erikslund_pool-py python >/dev/null
    docker rm -f erikslund_pool-py >/dev/null 2>&1 || true
    docker run -d --name erikslund_pool-py --network "$NET" -p 3333:3333 -p 7777:7777 erikslund_pool-py \
      --rpc-url http://bitcoind:18443 --rpc-user erikslund --rpc-password erikslundpass \
      --bind-host 0.0.0.0 --bind-port 3333 --api-host 0.0.0.0 --api-port 7777 \
      --difficulty 0.001 --no-vardiff >/dev/null
    for i in $(seq 1 30); do
        POOL_LOGS="$(docker logs erikslund_pool-py 2>&1 || true)"
        [[ "$POOL_LOGS" == *"Stratum listening"* ]] && break
        sleep 1
    done
fi
# Capture-then-match, never `docker logs | grep -q` (the pipe races on Docker Desktop).
[[ "$POOL_LOGS" == *"Stratum listening"* ]] && pass "pool listening (stratum 3333, API 7777)" \
  || { pool_logs; fail "pool did not start"; }

echo "==> 4/6 HTTP API responds"
HEALTHY=""
for i in $(seq 1 15); do
    [ "$(api /health 2>/dev/null || true)" = "ok" ] && { HEALTHY=1; break; }
    sleep 1
done
[ -n "$HEALTHY" ] && pass "GET /health -> ok" || fail "/health never ok"
echo "$(api /status)" | grep -Eq '"name": *"erikslund-solo-pool"' && pass "GET /status JSON" || fail "/status bad"

echo "==> 5/6 mine with pooler/cpuminer (up to ~45s, stops as soon as a block lands)"
$DC build miner >/dev/null 2>&1 || true
START="$($CLI getblockcount)"
docker rm -f miner-py >/dev/null 2>&1 || true
# Run the miner DETACHED and stop it with `docker rm -f` (SIGKILL). Never
# `timeout docker run --rm`: the attached CLI forwards SIGTERM to cpuminer, which
# as PID 1 ignores it, so the container never stops. Poll so we exit on first block.
# --add-host host.docker.internal:host-gateway lets the miner reach the host pool in POOL_ON_HOST
# mode; it's an unused extra entry in Docker-pool mode (which uses the container DNS name).
docker run -d --name miner-py --network "$NET" --add-host host.docker.internal:host-gateway \
  erikslund-miner:latest \
  --algo sha256d --url "$MINER_URL" --user "$ADDR" --pass x --threads 2 >/dev/null
for i in $(seq 1 45); do
    [ "$($CLI getblockcount 2>/dev/null || echo "$START")" -gt "$START" ] && break
    sleep 1
done
NOW="$($CLI getblockcount)"
docker rm -f miner-py >/dev/null 2>&1 || true
[ "$NOW" -gt "$START" ] && pass "bitcoind accepted erikslund_pool blocks ($START -> $NOW)" \
  || { pool_logs | tail -20; fail "no block accepted"; }

echo "==> 6/6 API reflects the found block(s)"
echo "$(api /stats/pool)" | grep -Eq '"blocks_found": *[1-9]' && pass "/stats/pool blocks_found > 0" \
  || { api /stats/pool; fail "blocks_found not updated"; }

echo ""
echo "ALL CHECKS PASSED (height $START -> $NOW)."
# Teardown is handled by the `trap cleanup EXIT` above (honors KEEP).
if [ "$KEEP" = "1" ]; then
  echo "(left running: dashboard http://localhost:7777/ , stratum localhost:3333)"
else
  echo "(torn down; set KEEP=1 to leave running - dashboard at http://localhost:7777/)"
fi
