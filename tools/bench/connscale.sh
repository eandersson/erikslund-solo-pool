#!/usr/bin/env bash
# Connection-scaling memory test: open N idle Stratum connections to each pool and
# measure the pool container's RSS, to see the per-connection memory cost at
# scale (e.g. 10k connections). Reveals how each connection model (thread-per-conn
# vs epoll/event-loop) holds up under many connections.
#
#   bash tools/bench/connscale.sh
#   CONNS="1000 10000" IMPLS="cpp" bash tools/bench/connscale.sh
# Linux/CI; on Windows/git-bash run with BENCH_ROOT=C:/... MSYS_NO_PATHCONV=1.
set -uo pipefail
cd "$(dirname "$0")/../.."
ROOT="${BENCH_ROOT:-$(pwd)}"
NET=erikslund-regtest_default
REG="docker compose -f tools/regtest/docker-compose.yml"
CLI="$REG exec -T bitcoind bitcoin-cli -regtest -rpcuser=erikslund -rpcpassword=erikslundpass -rpcport=18443"
ADDR=bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf
CFG="$ROOT/tools/bench/conn-bench.yml"
IMPLS=${IMPLS:-"cpp python"}
CONNS=${CONNS:-"1000 10000"}
NOFILE=${NOFILE:-65535}
POOL=conn-pool

cleanup() { docker rm -f "$POOL" conn-client >/dev/null 2>&1; }
trap 'cleanup; $REG --profile mine down -v --remove-orphans >/dev/null 2>&1' EXIT

mem_parse() { docker run --rm -i python:3.14-slim python3 -c '
import sys
peak = 0.0
for line in sys.stdin:
    used = line.split("/")[0].strip()
    num = "".join(c for c in used if c.isdigit() or c == ".")
    try: v = float(num)
    except ValueError: continue
    if "GiB" in used: v *= 1024
    elif "kiB" in used: v /= 1024
    peak = max(peak, v)
print("%.0f" % peak)'; }

echo "==> Building images" >&2
docker build -q -t erikslund-pool-cpp cpp/docker >/dev/null
docker run --rm -v "$ROOT/cpp:/src:ro" -v erikslund-cpp-build:/build erikslund-pool-cpp >/dev/null 2>&1
docker build -q -t erikslund-pool-py-ft python >/dev/null 2>&1

echo "==> Starting bitcoind" >&2
$REG up -d bitcoind >/dev/null 2>&1
for _ in $(seq 1 30); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done

start_pool() {
    cleanup
    case "$1" in
    cpp) docker run -d --name "$POOL" --network "$NET" --ulimit nofile=$NOFILE -v erikslund-cpp-build:/build:ro \
            -v "$CFG:/cfg/pool.yml:ro" -p 127.0.0.1:7777:7777 \
            --entrypoint /build/cmake/erikslund-pool erikslund-pool-cpp --config /cfg/pool.yml >/dev/null ;;
    python) docker run -d --name "$POOL" --network "$NET" --ulimit nofile=$NOFILE -v "$CFG:/cfg/pool.yml:ro" \
            -p 127.0.0.1:7777:7777 erikslund-pool-py-ft --config /cfg/pool.yml --log-level WARNING >/dev/null ;;
    esac
}

printf '%-10s %8s %16s %10s %10s\n' impl conns established idle_MiB peak_MiB
for impl in $IMPLS; do
    for n in $CONNS; do
        start_pool "$impl"
        ok=
        for _ in $(seq 1 40); do
            [ "$(curl -s --max-time 2 http://localhost:7777/health 2>/dev/null)" = "ok" ] && { ok=1; break; }
            sleep 1
        done
        [ -n "$ok" ] || { echo "  [$impl] not ready; skipping" >&2; cleanup; continue; }
        sleep 2
        idle=$(docker stats --no-stream --format '{{.MemUsage}}' "$POOL" 2>/dev/null | mem_parse)
        stats=$(mktemp)
        ( for _ in $(seq 1 16); do docker stats --no-stream --format '{{.MemUsage}}' "$POOL" 2>/dev/null; done ) >"$stats" &
        sp=$!
        est=$(docker run --rm --name conn-client --network "$NET" --ulimit nofile=$NOFILE \
                -v "$ROOT/tools/bench:/bench:ro" python:3.14-slim \
                python /bench/connscale.py --host "$POOL" --port 3333 --address "$ADDR" \
                --connections "$n" --hold 16 2>&1 | grep -o 'ESTABLISHED [0-9]*/[0-9]*' | tail -1)
        kill "$sp" >/dev/null 2>&1; wait "$sp" 2>/dev/null
        peak=$(mem_parse <"$stats"); rm -f "$stats"
        alive=$(docker ps --format '{{.Names}}' | grep -qx "$POOL" && echo yes || echo CRASHED)
        printf '%-10s %8s %16s %10s %10s  %s\n' "$impl" "$n" "${est#ESTABLISHED }" "$idle" "$peak" "$alive"
        cleanup
    done
done
echo "==> Done" >&2
