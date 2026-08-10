#!/usr/bin/env bash
#
# Reproduce the mainnet OOM on regtest by driving mainnet-like GBT/Job churn at a LOW miner count.
#
# The mainnet OOM happens at ~14 miners / 2 addresses, so it is NOT data-structure scale (registry,
# seen_shares, per-connection state are all tiny there). The only thing that scales with that workload
# is the TIME-driven GBT -> BlockTemplate -> Job -> broadcast -> share cycle, fed by ~2MB templates.
# Regtest templates are normally empty, so we manufacture the condition: keep a sizable, CONTINUOUSLY
# MUTATING mempool (every refresh => a DISTINCT, non-trivial job, defeating work-dedup suppression),
# connect only a few miners, and sample RSS against the pool's own jobs_created counter.
#
#   RSS climbs steadily here  => time-driven leak/fragmentation in the GBT/Job/share cycle (CONFIRMED).
#   RSS flat                  => leak is elsewhere / needs a trigger regtest still can't produce.
#
# bytes-leaked-per-job = d(RSS) / d(jobs_created). Run from repo root: bash docker/oom_repro.sh
set -uo pipefail
export MSYS_NO_PATHCONV=1

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/.." && { pwd -W 2>/dev/null || pwd; })}"
COMPOSE="docker compose -f $REPO_ROOT/tools/regtest/docker-compose.yml"
CLI="$COMPOSE exec -T bitcoind bitcoin-cli -regtest -rpcuser=erikslund -rpcpassword=erikslundpass -rpcport=18443"
NET=erikslund-regtest_default
POOL=ep-oomrepro
APIPORT=17777
MINER_ADDR=bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf
DURATION="${DURATION:-1200}"          # seconds of churn (default 20 min)
NMINERS="${NMINERS:-4}"               # low, like production (a few rigs)
# Generated config lives under REPO_ROOT (a Windows-visible path); a mktemp /tmp dir is NOT
# bind-mountable on Docker Desktop for Windows, which silently mounts it empty.
GENCFG="$REPO_ROOT/docker/.oom_repro_pool.gen.yml"

cleanup() {
    for i in $(seq 1 "$NMINERS"); do docker rm -f "$POOL-m$i" >/dev/null 2>&1; done
    docker rm -f "$POOL" >/dev/null 2>&1
    $COMPOSE down -v --remove-orphans >/dev/null 2>&1
    rm -f "$GENCFG"
}
trap cleanup EXIT

rss()  { docker stats --no-stream --format '{{.MemUsage}}' "$POOL" 2>/dev/null | awk '{print $1}'; }
jobs() { curl -s "http://localhost:$APIPORT/metrics.json" 2>/dev/null \
           | grep -o '"jobs_created"[: ]*[0-9]*' | grep -o '[0-9]*$'; }
mp()   { $CLI getmempoolinfo 2>/dev/null | grep -o '"bytes"[: ]*[0-9]*' | grep -o '[0-9]*$'; }

echo "==> build pool"
docker build -q -t erikslund-pool-build "$REPO_ROOT/docker" >/dev/null
docker run --rm -v "$REPO_ROOT:/src:ro" \
    -v erikslund-build:/build erikslund-pool-build \
    >/tmp/oomrepro-build.log 2>&1 || { echo "BUILD FAILED"; tail -30 /tmp/oomrepro-build.log; exit 1; }

echo "==> bitcoind + wallet + funds (150 blocks)"
$COMPOSE up -d bitcoind >/dev/null 2>&1
for _ in $(seq 1 40); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
$CLI createwallet w >/dev/null 2>&1 || $CLI loadwallet w >/dev/null 2>&1 || true
ADDR=$($CLI getnewaddress)
$CLI generatetoaddress 150 "$ADDR" >/dev/null 2>&1

echo "==> build a reusable 120-output payout set + JSON (one-time)"
OUTS=""
for _ in $(seq 1 120); do
    a=$($CLI getnewaddress 2>/dev/null) || continue
    OUTS+="\"$a\":0.0002,"
done
JSON="{${OUTS%,}}"

fill() {  # push large multi-output txns into the mempool (each ~5KB, distinct) up to $1 calls
    for _ in $(seq 1 "$1"); do $CLI sendmany "" "$JSON" >/dev/null 2>&1 || break; done
}

echo "==> pre-fill mempool (~hundreds of KB of distinct txns => non-trivial templates)"
fill 40
echo "    mempool bytes after prefill: $(mp)"

echo "==> accelerated-churn config (work_rebroadcast 2s, status 3s)"
sed -e 's/work_rebroadcast_seconds: 30/work_rebroadcast_seconds: 2/' \
    -e 's/status_interval_seconds: 5/status_interval_seconds: 3/' \
    "$REPO_ROOT/docker/regtest.yml" > "$GENCFG"
# Optional thread-count override (default: pool auto = min(host cores, 16)). Lets us A/B the
# per-thread mimalloc-heap cost: WORKER_THREADS=16 vs WORKER_THREADS=2 under identical churn.
[ -n "${WORKER_THREADS:-}" ] && echo "worker_threads: $WORKER_THREADS" >> "$GENCFG"
echo "    worker_threads = ${WORKER_THREADS:-auto(min host-cores,16)}"

echo "==> start pool (API published on :$APIPORT; NO mem cap, so we observe the trend not a kill)"
docker rm -f "$POOL" >/dev/null 2>&1
docker run -d --name "$POOL" --network "$NET" -p "$APIPORT:7777" \
    -v erikslund-build:/build:ro -v "$GENCFG:/cfg/pool.yml:ro" \
    --entrypoint /build/cmake/erikslund-pool erikslund-pool-build --config /cfg/pool.yml >/dev/null
for _ in $(seq 1 30); do [[ "$(docker logs "$POOL" 2>&1)" == *"Stratum listening"* ]] && break; sleep 1; done
if [[ "$(docker logs "$POOL" 2>&1)" != *"Stratum listening"* ]]; then
    echo "POOL FAILED TO START -- aborting:"; docker logs "$POOL" 2>&1 | tail -20; exit 1
fi
echo "    reactor: $(docker logs "$POOL" 2>&1 | grep -o 'reactor: [0-9]* threads')  |  startup RSS (pre-churn): $(rss)"

echo "==> connect $NMINERS miners across 2 addresses (like production)"
$COMPOSE build miner >/dev/null 2>&1
for i in $(seq 1 "$NMINERS"); do
    docker run -d --name "$POOL-m$i" --network "$NET" erikslund-miner:latest \
        --algo sha256d --url "stratum+tcp://$POOL:3333" \
        --user "$MINER_ADDR.rig$i" --pass x --threads 1 --retry-pause 2 >/dev/null
done

echo "==> drive churn ${DURATION}s: mutate mempool every loop (distinct jobs) + block every ~25s"
echo "    t(s)   RSS        jobs_created   mempool_bytes"
start=$(date +%s); END=$(( start + DURATION )); last_block=0
while [ "$(date +%s)" -lt "$END" ]; do
    now=$(date +%s); t=$(( now - start ))
    fill 4                                   # mutate + grow the template => a distinct job each refresh
    if [ $(( now - last_block )) -ge 25 ]; then
        $CLI generatetoaddress 1 "$ADDR" >/dev/null 2>&1   # ZMQ new-block -> fastblock + GBT refresh
        fill 30                                            # refill so the post-block template stays large
        last_block=$now
    fi
    printf "    %4d   %-9s  %-12s   %s\n" "$t" "$(rss)" "$(jobs)" "$(mp)"
    sleep 6
done

echo "==> final state"
docker inspect -f 'running={{.State.Running}} restarts={{.RestartCount}} oomkilled={{.State.OOMKilled}}' "$POOL"
echo "==> (read the RSS vs jobs_created columns: monotonic RSS climb at flat miner count = confirmed leak/frag)"
