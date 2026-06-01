#!/usr/bin/env bash
# Benchmark the block-submission CRITICAL PATH per implementation: the latency
# from "winning share found" to "bitcoind accepted the block", read from each
# pool's own log timestamps (candidate -> accepted). A real cpuminer mines
# low-difficulty regtest blocks; empty blocks (no mempool) isolate the
# assemble + spool + submitblock-RPC + bitcoind-validate path that every solved
# block pays. This is a LATENCY benchmark (one block per ~10 min in reality), not
# throughput.
#
#   bash tools/bench/blocksubmit.sh
# Linux/CI; on Windows/git-bash run with BENCH_ROOT=C:/... MSYS_NO_PATHCONV=1.
set -uo pipefail
cd "$(dirname "$0")/../.."
ROOT="${BENCH_ROOT:-$(pwd)}"
NET=erikslund-regtest_default
REG="docker compose -f tools/regtest/docker-compose.yml"
CLI="$REG exec -T bitcoind bitcoin-cli -regtest -rpcuser=erikslund -rpcpassword=erikslundpass -rpcport=18443"
IMPLS=${IMPLS:-"cpp python"}
CFG="${CFG:-$ROOT/tools/bench/mine.yml}"   # low diff, plain C-schema (no impl-specific keys)
POOL=blk-pool
MINE_SEC=${MINE_SEC:-25}
THREADS=${THREADS:-2}

cleanup() { docker rm -f "$POOL" blk-miner >/dev/null 2>&1; }
trap 'cleanup; $REG --profile mine down -v --remove-orphans >/dev/null 2>&1' EXIT

PARSE='
import sys, re, datetime
ts = re.compile(r"\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3})\]")
def ms(s):
    return datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f").timestamp() * 1000.0
pending, d, nc, na = None, [], 0, 0
for line in sys.stdin:
    low = line.lower()
    cand = ("block candidate" in low) or ("candidate block found" in low)
    acc = ("block accepted" in low) or ("solved and confirmed accepted" in low)
    nc += cand; na += acc
    m = ts.search(line)
    if not m: continue
    t = ms(m.group(1))
    if cand: pending = t
    elif acc and pending is not None: d.append(t - pending); pending = None
if d:
    d.sort()
    print("n=%-3d  median=%.2f ms  avg=%.2f ms  min=%.2f  max=%.2f"
          % (len(d), d[len(d)//2], sum(d)/len(d), d[0], d[-1]))
else:
    print("no pairs (candidate_lines=%d accepted_lines=%d)" % (nc, na))
'

echo "==> Building images" >&2
docker build -q -t erikslund-pool-cpp cpp/docker >/dev/null
docker run --rm -v "$ROOT/cpp:/src:ro" -v erikslund-cpp-build:/build erikslund-pool-cpp >/dev/null 2>&1
docker build -q -t erikslund-pool-py-ft python >/dev/null 2>&1

echo "==> Starting bitcoind and mining past BIP34 height for spendable coins" >&2
$REG up -d bitcoind >/dev/null 2>&1
for _ in $(seq 1 30); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
$CLI loadwallet test >/dev/null 2>&1 || $CLI -named createwallet wallet_name=test >/dev/null 2>&1 || true
ADDR=$($CLI getnewaddress)
$CLI generatetoaddress 110 "$ADDR" >/dev/null   # past height 16 + coinbase maturity

start_pool() {
    cleanup
    case "$1" in
    cpp) docker run -d --name "$POOL" --network "$NET" -v erikslund-cpp-build:/build:ro \
            -v "$CFG:/cfg/pool.yml:ro" --entrypoint /build/cmake/erikslund-pool erikslund-pool-cpp \
            --config /cfg/pool.yml >/dev/null ;;
    python) docker run -d --name "$POOL" --network "$NET" -v "$CFG:/cfg/pool.yml:ro" \
            erikslund-pool-py-ft --config /cfg/pool.yml --log-level INFO >/dev/null ;;
    esac
}

echo "impl  | candidate -> accepted (block-submission critical path, empty regtest blocks)"
echo "------+--------------------------------------------------------------------------"
for impl in $IMPLS; do
    start_pool "$impl"
    for _ in $(seq 1 40); do docker logs "$POOL" 2>&1 | grep -qiE "listening|stratum" && break; sleep 1; done
    sleep 2
    docker rm -f blk-miner >/dev/null 2>&1
    docker run -d --name blk-miner --network "$NET" erikslund-miner:latest \
        --algo sha256d --url "stratum+tcp://$POOL:3333" --user "$ADDR" --pass x \
        --threads "$THREADS" --retry-pause 2 >/dev/null
    sleep "$MINE_SEC"
    docker rm -f blk-miner >/dev/null 2>&1
    result=$(docker logs "$POOL" 2>&1 | docker run --rm -i python:3.14-slim python3 -c "$PARSE")
    printf '%-9s | %s\n' "$impl" "$result"
    cleanup
done
echo "==> Done" >&2
