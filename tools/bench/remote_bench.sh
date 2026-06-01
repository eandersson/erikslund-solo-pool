#!/usr/bin/env bash
# Benchmark a pool running on a REMOTE host (e.g. a Linux VM) from THIS machine
# (e.g. a Windows PC under git-bash). The load generator runs here in Docker and
# drives the remote pool's stratum port. Running the generator off the pool's host
# avoids the CPU contention that skews a co-located benchmark, so the numbers
# reflect the pool, not a fight over cores.
#
#   POOL_HOST=192.168.64.10 bash tools/bench/remote_bench.sh
#   POOL_HOST=vm WORKERS=16 CONNECTIONS=160 PIPELINE=32 DURATION=30 bash tools/bench/remote_bench.sh
#   POOL_HOST=vm POOL_SSH=me@vm bash tools/bench/remote_bench.sh        # + sample remote CPU/RSS
#
# Requires Docker here. POOL_HOST must be reachable from this machine (use the
# VM's LAN IP, not "localhost"). ADDRESS defaults to the regtest address that
# tools/bench/bench_server.sh uses; override it if your pool runs on another network.
#
# Point this ONLY at a dedicated benchmark instance; it floods shares as fast as
# it can. Never aim it at a production pool.
#
# Knobs (env): POOL_HOST POOL_PORT ADDRESS CONNECTIONS PIPELINE WORKERS WARMUP
#              DURATION  POOL_SSH POOL_CONTAINER
set -uo pipefail
cd "$(dirname "$0")/../.."
ROOT="${BENCH_ROOT:-$(pwd)}"   # on Windows/git-bash: export BENCH_ROOT=C:/path/to/repo

: "${POOL_HOST:?set POOL_HOST to the VM IP or hostname}"
POOL_PORT=${POOL_PORT:-3333}
ADDRESS=${ADDRESS:-bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf}
CONNECTIONS=${CONNECTIONS:-50}
PIPELINE=${PIPELINE:-16}
WORKERS=${WORKERS:-1}
WARMUP=${WARMUP:-5}
DURATION=${DURATION:-30}

echo "==> ${CONNECTIONS} conns x pipeline ${PIPELINE} x ${WORKERS} workers, ${DURATION}s -> ${POOL_HOST}:${POOL_PORT}"

# Optional: sample the remote pool container's CPU/RSS over SSH while load runs.
stats=; spid=
if [ -n "${POOL_SSH:-}" ]; then
    container="${POOL_CONTAINER:-bench-pool}"
    stats=$(mktemp)
    ( ssh -o BatchMode=yes "$POOL_SSH" \
        "while docker ps --format '{{.Names}}' | grep -qx '$container'; do docker stats --no-stream --format '{{.CPUPerc}}|{{.MemUsage}}' '$container' 2>/dev/null; sleep 1; done" \
      ) >"$stats" 2>/dev/null &
    spid=$!
fi

json=$(MSYS_NO_PATHCONV=1 docker run --rm -v "$ROOT/tools/bench:/bench:ro" python:3.14-slim \
    python /bench/stratum_bench.py --host "$POOL_HOST" --port "$POOL_PORT" --address "$ADDRESS" \
    --connections "$CONNECTIONS" --pipeline "$PIPELINE" --workers "$WORKERS" \
    --warmup "$WARMUP" --duration "$DURATION")

cpu=-; mem=-
if [ -n "$stats" ]; then
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
fi

echo
printf '%12s %8s %8s %8s %8s %8s\n' val/s p50ms p95ms p99ms cpu% rssMiB
echo "$json|$cpu|$mem" | docker run --rm -i python:3.14-slim python3 -c '
import sys, json
j, cpu, mem = sys.stdin.read().strip().rsplit("|", 2)
d = json.loads(j); lat = d["latency_ms"]
print("%12.0f %8.3f %8.3f %8.3f %8s %8s" % (
    d["validated_per_sec"], lat["p50"], lat["p95"], lat["p99"], cpu, mem))
'
