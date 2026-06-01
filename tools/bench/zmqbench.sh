#!/usr/bin/env bash
# Benchmark the ZMQ fastblock critical path per implementation: from a new block
# at bitcoind to a connected miner receiving fresh work (mining.notify). Each pool
# runs with tools/bench/zmq-bench.yml, whose blockpoll is 10 min so the ONLY way new
# work can reach miners is the ZMQ hashblock -> fastblock path. tools/bench/zmqlatency.py
# (a Stratum client) generates blocks and times the notify. Latency benchmark.
#
#   bash tools/bench/zmqbench.sh
# Linux/CI; on Windows/git-bash run with BENCH_ROOT=C:/... MSYS_NO_PATHCONV=1.
set -uo pipefail
cd "$(dirname "$0")/../.."
ROOT="${BENCH_ROOT:-$(pwd)}"
NET=erikslund-regtest_default
REG="docker compose -f tools/regtest/docker-compose.yml"
CLI="$REG exec -T bitcoind bitcoin-cli -regtest -rpcuser=erikslund -rpcpassword=erikslundpass -rpcport=18443"
IMPLS=${IMPLS:-"cpp python"}
CFG="$ROOT/tools/bench/zmq-bench.yml"
ADDR=bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf
ROUNDS=${ROUNDS:-20}
POOL=zmq-pool

cleanup() { docker rm -f "$POOL" >/dev/null 2>&1; }
trap 'cleanup; $REG --profile mine down -v --remove-orphans >/dev/null 2>&1' EXIT

echo "==> Building images" >&2
docker build -q -t erikslund-pool-cpp cpp/docker >/dev/null
docker run --rm -v "$ROOT/cpp:/src:ro" -v erikslund-cpp-build:/build erikslund-pool-cpp >/dev/null 2>&1
docker build -q -t erikslund-pool-py-ft python >/dev/null 2>&1

echo "==> Starting bitcoind and mining past BIP34 height" >&2
$REG up -d bitcoind >/dev/null 2>&1
for _ in $(seq 1 30); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
$CLI loadwallet test >/dev/null 2>&1 || $CLI -named createwallet wallet_name=test >/dev/null 2>&1 || true
WADDR=$($CLI getnewaddress); $CLI generatetoaddress 20 "$WADDR" >/dev/null

start_pool() {
    cleanup
    case "$1" in
    cpp) docker run -d --name "$POOL" --network "$NET" -v erikslund-cpp-build:/build:ro \
            -v "$CFG:/cfg/pool.yml:ro" --entrypoint /build/cmake/erikslund-pool erikslund-pool-cpp \
            --config /cfg/pool.yml >/dev/null ;;
    python) docker run -d --name "$POOL" --network "$NET" -v "$CFG:/cfg/pool.yml:ro" \
            erikslund-pool-py-ft --config /cfg/pool.yml --log-level WARNING >/dev/null ;;
    esac
}

echo "impl  | new block -> miner gets new work (ZMQ fastblock critical path)"
echo "------+------------------------------------------------------------------"
for impl in $IMPLS; do
    start_pool "$impl"
    for _ in $(seq 1 40); do docker logs "$POOL" 2>&1 | grep -qiE "listening|stratum" && break; sleep 1; done
    sleep 3   # let the ZMQ subscriber connect
    result=$(docker run --rm --network "$NET" -v "$ROOT/tools/bench:/bench:ro" python:3.14-slim \
        python /bench/zmqlatency.py --host "$POOL" --port 3333 --address "$ADDR" \
        --rpc http://bitcoind:18443 --rounds "$ROUNDS" 2>&1 | tail -1)
    printf '%-9s | %s\n' "$impl" "$result"
    cleanup
done
echo "==> Done" >&2
