#!/usr/bin/env bash
# Benchmark the C++ and Python pools' share-validation hot path on regtest.
# For each implementation: start it on the shared regtest bitcoind with the same
# bench.yml (vardiff off, fixed high difficulty -> shares never meet target, so
# no accepts/blocks and a stable job), drive it with the synthetic Stratum load
# generator (tools/bench/stratum_bench.py), and sample the pool container's CPU/RSS.
# Reports shares-validated/sec, submit->ack latency, CPU% and peak RSS per pool.
#
#   bash tools/bench/run_bench.sh
#   CONNECTIONS=100 PIPELINE=32 DURATION=30 IMPLS="cpp" bash tools/bench/run_bench.sh
#
# Linux/CI script. On Windows/git-bash, run it under WSL (bind mounts + the
# volume:/path arg quoting don't survive MSYS path conversion otherwise).
set -uo pipefail
cd "$(dirname "$0")/../.."
ROOT="${BENCH_ROOT:-$(pwd)}"   # override on Windows/git-bash with the C:/... path
NET=erikslund-regtest_default
REG="docker compose -f tools/regtest/docker-compose.yml"
CLI="$REG exec -T bitcoind bitcoin-cli -regtest -rpcuser=erikslund -rpcpassword=erikslundpass -rpcport=18443"
ADDR=bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf
CONNECTIONS=${CONNECTIONS:-50}
PIPELINE=${PIPELINE:-16}
WORKERS=${WORKERS:-1}
WARMUP=${WARMUP:-3}
DURATION=${DURATION:-20}
IMPLS=${IMPLS:-"cpp python"}
CORES=${CORES:-0}    # >0 pins each pool to N cores: --cpus=N + worker_threads=N (core-matched run)
POOL=bench-pool

# With CORES set, cap compute (--cpus) AND pin the pool's reactor/worker-thread count so it
# fills exactly N cores instead of auto-threading to the host's core count (worker_threads:0
# is auto and NOT cgroup-aware, so it would over-thread a --cpus-limited container).
CFG="$ROOT/tools/bench/bench.yml"
CPUS_ARG=""
if [ "$CORES" -gt 0 ]; then
    CPUS_ARG="--cpus=$CORES"
    CFG="$ROOT/tools/bench/.bench-cores.yml"
    { cat "$ROOT/tools/bench/bench.yml"; echo "worker_threads: $CORES"; } > "$CFG"
    echo "==> Core-matched run: each pool pinned to $CORES cores (--cpus + worker_threads)"
fi

cleanup_pool() { docker rm -f "$POOL" >/dev/null 2>&1; }
trap 'cleanup_pool; rm -f "$ROOT/tools/bench/.bench-cores.yml"; $REG --profile mine down -v --remove-orphans >/dev/null 2>&1' EXIT

echo "==> Building images"
docker build -q -t erikslund-pool-cpp cpp/docker >/dev/null
docker run --rm -e BUILD_TYPE=Release -e RUN_TESTS=0 \
    -v "$ROOT/cpp:/src:ro" -v erikslund-cpp-build:/build erikslund-pool-cpp >/dev/null 2>&1
docker build -q -t erikslund-pool-py-ft python >/dev/null

echo "==> Starting regtest bitcoind"
$REG up -d bitcoind >/dev/null 2>&1
for _ in $(seq 1 30); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
$CLI getblockchaininfo >/dev/null 2>&1 || { echo "bitcoind never came up"; exit 1; }

start_pool() {
    cleanup_pool
    case "$1" in
    cpp) docker run -d --name "$POOL" --network "$NET" $CPUS_ARG \
            -v erikslund-cpp-build:/build:ro \
            -v "$CFG:/cfg/pool.yml:ro" -p 127.0.0.1:7777:7777 \
            --entrypoint /build/cmake/erikslund-pool erikslund-pool-cpp \
            --config /cfg/pool.yml --quiet >/dev/null ;;
    python) docker run -d --name "$POOL" --network "$NET" $CPUS_ARG \
            -v "$CFG:/cfg/pool.yml:ro" -p 127.0.0.1:7777:7777 \
            erikslund-pool-py-ft --config /cfg/pool.yml --log-level WARNING >/dev/null ;;
    esac
}

declare -A RESULT
for impl in $IMPLS; do
    echo "==> [$impl] Starting pool"
    start_pool "$impl"
    ready=
    for _ in $(seq 1 40); do
        [ "$(curl -s --max-time 2 http://localhost:7777/health 2>/dev/null)" = "ok" ] && { ready=1; break; }
        sleep 1
    done
    [ -n "$ready" ] || { echo "  [$impl] Pool not ready; skipping"; docker logs "$POOL" 2>&1 | tail -12; continue; }

    echo "==> [$impl] Load: ${CONNECTIONS} conns x pipeline ${PIPELINE} x ${WORKERS} workers, ${DURATION}s (+${WARMUP}s warmup)"
    stats=$(mktemp)
    ( while docker ps --format '{{.Names}}' | grep -qx "$POOL"; do
        docker stats --no-stream --format '{{.CPUPerc}}|{{.MemUsage}}' "$POOL" 2>/dev/null
        sleep 1
      done ) >"$stats" &
    spid=$!
    json=$(docker run --rm --network "$NET" -v "$ROOT/tools/bench:/bench:ro" python:3.14-slim \
        python /bench/stratum_bench.py --host "$POOL" --port 3333 --address "$ADDR" \
        --connections "$CONNECTIONS" --pipeline "$PIPELINE" --workers "$WORKERS" \
        --warmup "$WARMUP" --duration "$DURATION")
    kill "$spid" >/dev/null 2>&1
    read -r cpu mem < <(docker run --rm -i python:3.14-slim python3 -c '
import sys
cpus, mems = [], []
for line in sys.stdin:
    if "|" not in line: continue
    c, m = line.strip().split("|", 1)
    try: cpus.append(float(c.rstrip("%")))
    except ValueError: pass
    used = m.split("/")[0].strip()
    num = "".join(ch for ch in used if ch.isdigit() or ch == ".")
    try: v = float(num)
    except ValueError: continue
    if "GiB" in used: v *= 1024
    elif "kiB" in used: v /= 1024
    mems.append(v)
print("%.0f %.0f" % (sum(cpus)/len(cpus) if cpus else 0, max(mems) if mems else 0))
' < "$stats")
    rm -f "$stats"
    RESULT[$impl]="$json|$cpu|$mem"
    echo "  $json  (cpu=${cpu}% peak_rss=${mem}MiB)"
    cleanup_pool
done

echo
printf '%-8s %12s %8s %8s %8s %6s %8s\n' impl val/s p50ms p95ms p99ms cpu% rssMiB
for impl in $IMPLS; do
    r="${RESULT[$impl]:-}"
    [ -z "$r" ] && { printf '%-8s %12s\n' "$impl" FAILED; continue; }
    echo "$impl|$r" | docker run --rm -i python:3.14-slim python3 -c '
import sys, json
impl, rest = sys.stdin.read().strip().split("|", 1)
j, cpu, mem = rest.rsplit("|", 2)
d = json.loads(j); lat = d["latency_ms"]
print("%-8s %12.0f %8.3f %8.3f %8.3f %6s %8s" % (
    impl, d["validated_per_sec"], lat["p50"], lat["p95"], lat["p99"], cpu, mem))
'
done
