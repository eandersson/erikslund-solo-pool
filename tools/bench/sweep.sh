#!/usr/bin/env bash
# Sweep the share-validation benchmark over connection counts for each pool and
# write a CSV of performance numbers to tools/bench/results.csv (also printed).
# Each pool is started once on the shared regtest bitcoind, then driven by
# tools/bench/stratum_bench.py: first a pure-latency point (1 connection, 1 in-flight),
# then a throughput sweep using WORKERS load-gen processes so the single-process
# client stops being the bottleneck.
#
#   bash tools/bench/sweep.sh
#   CONNS="1 8 32 96" WORKERS=6 PIPELINE=16 DURATION=10 bash tools/bench/sweep.sh
#
# Linux/CI; on Windows/git-bash run with BENCH_ROOT=C:/... MSYS_NO_PATHCONV=1.
# Note: the load-gen workers and the pool share the host's cores, so if a pool's
# own core use is high a many-worker run can contend.
set -uo pipefail
cd "$(dirname "$0")/../.."
ROOT="${BENCH_ROOT:-$(pwd)}"
NET=erikslund-regtest_default
REG="docker compose -f tools/regtest/docker-compose.yml"
CLI="$REG exec -T bitcoind bitcoin-cli -regtest -rpcuser=erikslund -rpcpassword=erikslundpass -rpcport=18443"
ADDR=bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf
PIPELINE=${PIPELINE:-16}
WORKERS=${WORKERS:-4}
WARMUP=${WARMUP:-2}
DURATION=${DURATION:-8}
CONNS=${CONNS:-"1 4 16 64"}
IMPLS=${IMPLS:-"cpp python"}
POOL=bench-pool
OUT="${OUT:-tools/bench/results.csv}"

cleanup_pool() { docker rm -f "$POOL" >/dev/null 2>&1; }
trap 'cleanup_pool; $REG --profile mine down -v --remove-orphans >/dev/null 2>&1' EXIT

echo "==> Building images" >&2
docker build -q -t erikslund-pool-cpp cpp/docker >/dev/null
docker run --rm -v "$ROOT/cpp:/src:ro" -v erikslund-cpp-build:/build erikslund-pool-cpp >/dev/null 2>&1
docker build -q -t erikslund-pool-py-ft python >/dev/null 2>&1   # free-threaded (3.14t); cached if prebuilt

echo "==> Starting regtest bitcoind" >&2
$REG up -d bitcoind >/dev/null 2>&1
for _ in $(seq 1 30); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
$CLI getblockchaininfo >/dev/null 2>&1 || { echo "bitcoind never came up" >&2; exit 1; }

start_pool() {
    cleanup_pool
    case "$1" in
    cpp) docker run -d --name "$POOL" --network "$NET" \
            -v erikslund-cpp-build:/build:ro \
            -v "$ROOT/tools/bench/bench.yml:/cfg/pool.yml:ro" -p 127.0.0.1:7777:7777 \
            --entrypoint /build/cmake/erikslund-pool erikslund-pool-cpp \
            --config /cfg/pool.yml --quiet >/dev/null ;;
    python) docker run -d --name "$POOL" --network "$NET" \
            -v "$ROOT/tools/bench/ft-bench.yml:/cfg/pool.yml:ro" -p 127.0.0.1:7777:7777 \
            erikslund-pool-py-ft --config /cfg/pool.yml --log-level WARNING >/dev/null ;;
    esac
}

stats_parse() {  # $1 = stats file -> "avg_cpu% peak_rss_mib"
    docker run --rm -i python:3.14-slim python3 -c '
import sys
cpus, mems = [], []
for line in sys.stdin:
    if "|" not in line: continue
    cc, m = line.strip().split("|", 1)
    try: cpus.append(float(cc.rstrip("%")))
    except ValueError: pass
    used = m.split("/")[0].strip()
    num = "".join(ch for ch in used if ch.isdigit() or ch == ".")
    try: v = float(num)
    except ValueError: continue
    if "GiB" in used: v *= 1024
    elif "kiB" in used: v /= 1024
    mems.append(v)
print("%.0f %.0f" % (sum(cpus)/len(cpus) if cpus else 0, max(mems) if mems else 0))
' < "$1"
}

run_one() {  # $1=connections $2=pipeline $3=workers  (appends a CSV row for $impl)
    echo "==> [$impl] Running connections=$1 pipeline=$2 workers=$3" >&2
    local stats; stats=$(mktemp)
    ( while docker ps --format '{{.Names}}' | grep -qx "$POOL"; do
        docker stats --no-stream --format '{{.CPUPerc}}|{{.MemUsage}}' "$POOL" 2>/dev/null
      done ) >"$stats" &
    local spid=$!
    local json; json=$(docker run --rm --network "$NET" -v "$ROOT/tools/bench:/bench:ro" python:3.14-slim \
        python /bench/stratum_bench.py --host "$POOL" --port 3333 --address "$ADDR" \
        --connections "$1" --pipeline "$2" --workers "$3" --warmup "$WARMUP" --duration "$DURATION")
    kill "$spid" >/dev/null 2>&1
    local cpu mem; read -r cpu mem < <(stats_parse "$stats")
    rm -f "$stats"
    echo "$impl|$json|$cpu|$mem" | docker run --rm -i python:3.14-slim python3 -c '
import sys, json
impl, rest = sys.stdin.read().strip().split("|", 1)
j, cpu, mem = rest.rsplit("|", 2)
d = json.loads(j); l = d["latency_ms"]
print("%s,%s,%s,%s,%.0f,%.3f,%.3f,%.3f,%s,%s" % (
    impl, d["connections"], d.get("workers", 1), d["pipeline"],
    d["validated_per_sec"], l["p50"], l["p95"], l["p99"], cpu, mem))
' >> "$OUT"
}

echo "impl,connections,workers,pipeline,validated_per_sec,p50_ms,p95_ms,p99_ms,cpu_pct,rss_mib" > "$OUT"
for impl in $IMPLS; do
    echo "==> [$impl] Starting pool" >&2
    start_pool "$impl"
    ready=
    for _ in $(seq 1 40); do
        [ "$(curl -s --max-time 2 http://localhost:7777/health 2>/dev/null)" = "ok" ] && { ready=1; break; }
        sleep 1
    done
    [ -n "$ready" ] || { echo "  [$impl] Pool not ready; skipping" >&2; continue; }
    run_one 1 1 1                                  # pure per-share latency (no concurrency)
    for c in $CONNS; do run_one "$c" "$PIPELINE" "$WORKERS"; done
    cleanup_pool
done

echo "==> Wrote $OUT" >&2
cat "$OUT"
