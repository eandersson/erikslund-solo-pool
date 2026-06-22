#!/usr/bin/env bash
#
# Shared multi-bitcoind FAILOVER e2e -- the IDENTICAL scenario against either pool.
# POOL=cpp|python selects the implementation. By default the pool runs in a CONTAINER; for the
# Python pool, POOL_ON_HOST=1 instead runs it as a host process (matching python/e2e_regtest.sh and
# the CI python jobs, which use actions/setup-python rather than the slow source-CPython image).
# Only HOW the pool is built/started/reached differs; the bitcoind/peering/mine/kill/assert logic
# below is shared, so both pools are tested the same way. Both read tools/regtest/failover-pool.yml.
#
#   POOL=cpp                   bash tools/regtest/failover-test.sh   (= bash cpp/docker/failover-test.sh)
#   POOL=python                bash tools/regtest/failover-test.sh   (containerized Python pool)
#   POOL=python POOL_ON_HOST=1 bash tools/regtest/failover-test.sh   (host Python process; the CI path)
# On Windows/git-bash, prefix MSYS_NO_PATHCONV=1 (host mode is Linux-only).
#
# Shares container/network names, so don't run two at once on one host (CI runs them as separate
# jobs). Set FO_POOL_PREBUILT=1 to skip building the pool image (CI may prebuild + cache it).
set -uo pipefail

POOL="${POOL:-cpp}"
case "$POOL" in cpp | python) ;; *) echo "POOL must be 'cpp' or 'python' (got '$POOL')" >&2; exit 2 ;; esac
MODE=container
if [ "${POOL_ON_HOST:-0}" = "1" ]; then
    [ "$POOL" = python ] || { echo "POOL_ON_HOST=1 is only supported for POOL=python" >&2; exit 2; }
    MODE=host
fi

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && { pwd -W 2>/dev/null || pwd; })}"
NET=erikslund-failover
BTC_IMG=erikslund-bitcoind:regtest
MINER_IMG=erikslund-miner:latest
CONFIG="$REPO_ROOT/tools/regtest/failover-pool.yml"
A=ep-fo-a # primary bitcoind
B=ep-fo-b # backup bitcoind
POOL_CT=ep-fo-pool
MINER=ep-fo-miner
MINER_ADDR=bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf
CLI="bitcoin-cli -regtest -rpcuser=erikslund -rpcpassword=erikslundpass -rpcport=18443"
FAILOVER_BUDGET="${FAILOVER_BUDGET:-20}"
REGTEST_COMPOSE="docker compose -f $REPO_ROOT/tools/regtest/docker-compose.yml"
# host-mode scratch (unused in container mode)
POOL_LOG=/tmp/eppy-fo-pool.log
POOL_PID=""
HOST_CONFIG=/tmp/eppy-fo-config.yml
HOST_STATS=/tmp/eppy-fo-stats

PASS=0
FAIL=0
pass() { echo "  [PASS] $*"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }
height() { docker exec "$1" $CLI getblockcount 2>/dev/null || echo "-1"; }
pool_logs() { if [ "$MODE" = host ]; then cat "$POOL_LOG" 2>/dev/null; else docker logs "$POOL_CT" 2>&1; fi; }
cleanup() {
    [ -n "$POOL_PID" ] && kill "$POOL_PID" >/dev/null 2>&1
    docker rm -f "$POOL_CT" "$MINER" "$A" "$B" >/dev/null 2>&1
    docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT
cleanup # clear any leftovers from a prior run

# --- per-pool / per-mode seams --------------------------------------------------------------------
build_pool() {
    [ "${FO_POOL_PREBUILT:-0}" = "1" ] && return 0
    if [ "$POOL" = cpp ]; then
        # toolchain image -> compile + ctest into the cpp-build volume (start_pool mounts it).
        docker build -q -t erikslund-pool-cpp "$REPO_ROOT/cpp/docker" >/dev/null \
            && docker run --rm -v "$REPO_ROOT/cpp:/src:ro" -v erikslund-cpp-build:/build \
                erikslund-pool-cpp >/tmp/fo-build.log 2>&1
    elif [ "$MODE" = host ]; then
        python -c "import erikslund_pool" >/tmp/fo-build.log 2>&1 # CI pip-installs the pool
    else
        docker build -q -t erikslund_pool-py "$REPO_ROOT/python" >/tmp/fo-build.log 2>&1
    fi
}
start_pool() {
    if [ "$POOL" = cpp ]; then
        docker run -d --name "$POOL_CT" --network "$NET" \
            -v erikslund-cpp-build:/build:ro -v "$CONFIG:/cfg/pool.yml:ro" \
            --entrypoint /build/cmake/erikslund-pool erikslund-pool-cpp --config /cfg/pool.yml >/dev/null
    elif [ "$MODE" = host ]; then
        # Same shared config, with the bitcoind addresses rewritten to the host-published ports and
        # stats_directory pointed at a writable temp (the config's /stats needs root on a CI runner).
        sed -e 's#ep-fo-a:18443#127.0.0.1:18443#' -e 's#ep-fo-b:18443#127.0.0.1:18445#' \
            -e 's#tcp://ep-fo-a:28332#tcp://127.0.0.1:28332#' \
            -e "s#stats_directory: /stats#stats_directory: $HOST_STATS#" "$CONFIG" >"$HOST_CONFIG"
        rm -rf "$HOST_STATS"; mkdir -p "$HOST_STATS"
        : >"$POOL_LOG"
        python -m erikslund_pool --config "$HOST_CONFIG" --stats-dir "$HOST_STATS" >"$POOL_LOG" 2>&1 &
        POOL_PID=$!
    else
        docker run -d --name "$POOL_CT" --network "$NET" \
            -v "$CONFIG:/cfg/pool.yml:ro" erikslund_pool-py --config /cfg/pool.yml >/dev/null
    fi
}
run_bitcoind() { # $1=name  $2=extra docker args (host-mode port publishing)
    # shellcheck disable=SC2086
    docker run -d --name "$1" --network "$NET" $2 \
        -v "$REPO_ROOT/tools/regtest/bitcoin.conf:/etc/bitcoin/bitcoin.conf:ro" "$BTC_IMG" >/dev/null
}
run_miner() {
    if [ "$MODE" = host ]; then # reach the host pool's 0.0.0.0:3333 from the miner container
        docker run -d --name "$MINER" --network "$NET" --add-host host.docker.internal:host-gateway \
            "$MINER_IMG" --algo sha256d --url "stratum+tcp://host.docker.internal:3333" \
            --user "$MINER_ADDR" --pass x --threads 2 --retry-pause 1 >/dev/null
    else
        docker run -d --name "$MINER" --network "$NET" \
            "$MINER_IMG" --algo sha256d --url "stratum+tcp://$POOL_CT:3333" \
            --user "$MINER_ADDR" --pass x --threads 2 --retry-pause 1 >/dev/null
    fi
}
failover_epoch() { # echo the epoch seconds of the first "failed over to" log line (or nothing)
    local ts
    if [ "$MODE" = host ]; then # the pool's own "[YYYY-MM-DD HH:MM:SS.mmm]" stamp (host wall clock)
        ts=$(grep -m1 "failed over to" "$POOL_LOG" 2>/dev/null \
            | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}')
        [ -n "$ts" ] && date -d "$ts" +%s 2>/dev/null
    else # docker's RFC3339 --timestamps prefix (UTC)
        ts=$(docker logs --timestamps "$POOL_CT" 2>&1 | grep -m1 "failed over to" \
            | awk '{print $1}' | sed -E 's/\.[0-9]+Z$/Z/')
        [ -n "$ts" ] && date -u -d "$ts" +%s 2>/dev/null
    fi
}

echo "==> 1/6 build the $POOL pool ($MODE) + bitcoind + miner images"
docker build -q -t "$BTC_IMG" -f "$REPO_ROOT/tools/regtest/Dockerfile.bitcoind" \
    "$REPO_ROOT/tools/regtest" >/dev/null
$REGTEST_COMPOSE build miner >/dev/null 2>&1
if build_pool; then
    pass "$POOL pool ready ($MODE)"
else
    fail "$POOL pool build"; tail -30 /tmp/fo-build.log 2>/dev/null; exit 1
fi

echo "==> 2/6 start two PEERED regtest bitcoinds (shared chain, like a real HA pair)"
docker network create "$NET" >/dev/null 2>&1
if [ "$MODE" = host ]; then
    run_bitcoind "$A" "-p 18443:18443 -p 28332:28332" # publish RPC + zmq for the host pool
    run_bitcoind "$B" "-p 18445:18443"                # backup RPC on a distinct host port
else
    run_bitcoind "$A" ""
    run_bitcoind "$B" ""
fi
for node in "$A" "$B"; do
    for _ in $(seq 1 30); do [ "$(height "$node")" != "-1" ] && break; sleep 1; done
done
# Peer them (regtest P2P port 18444) so the backup follows the primary's chain. Without this the two
# nodes are INDEPENDENT chains, and after failover the pool's height-monotonicity guard correctly
# refuses the backup's lower-height work ("Ignoring a GBT below the current job's height") -- a test
# artifact, not a real HA scenario where both nodes track the same chain.
docker exec "$A" $CLI addnode "$B:18444" add >/dev/null 2>&1
docker exec "$B" $CLI addnode "$A:18444" add >/dev/null 2>&1
peers() { docker exec "$A" $CLI getconnectioncount 2>/dev/null || echo 0; }
for _ in $(seq 1 15); do [ "$(peers)" -gt 0 ] 2>/dev/null && break; sleep 1; done
if [ "$(height "$A")" -ge 0 ] && [ "$(height "$B")" -ge 0 ] && [ "$(peers)" -gt 0 ]; then
    pass "both bitcoinds ready + peered (a=$(height "$A") b=$(height "$B"), peers=$(peers))"
else
    fail "bitcoinds not ready/peered (peers=$(peers))"; exit 1
fi

echo "==> 3/6 start the $POOL pool ($MODE) with both backends (primary first)"
start_pool
for _ in $(seq 1 30); do
    POOL_LOGS="$(pool_logs || true)"
    [[ "$POOL_LOGS" == *"Stratum listening"* ]] && break
    [ "$MODE" = host ] && { kill -0 "$POOL_PID" 2>/dev/null || break; } # exited early -> stop waiting
    sleep 1
done
if [[ "$POOL_LOGS" == *"Stratum listening"* ]]; then
    pass "pool listening on :3333 (primary=$A)"
else
    fail "pool did not start"; pool_logs | tail -25; exit 1
fi

echo "==> 4/6 mine ~15s via the primary; let the backup sync the chain over P2P"
run_miner
for _ in $(seq 1 25); do [ "$(height "$A")" -gt 2 ] 2>/dev/null && break; sleep 1; done
# Stop mining and let the backup FULLY catch up, so both tips match at kill time. A backup even one
# block behind would re-trip the height guard, since the primary -- now dead -- can't supply it.
docker rm -f "$MINER" >/dev/null 2>&1
for _ in $(seq 1 20); do
    [ "$(height "$A")" -gt 0 ] && [ "$(height "$B")" = "$(height "$A")" ] 2>/dev/null && break
    sleep 1
done
A1=$(height "$A")
B1=$(height "$B")
echo "  after mining + sync: a=$A1 b=$B1"
if [ "$A1" -gt 0 ]; then pass "primary produced blocks (a=$A1)"; else fail "primary produced no blocks"; fi
if [ "$B1" = "$A1" ]; then pass "backup fully synced the primary's chain (b=$B1)"; else fail "backup did not sync (a=$A1 b=$B1)"; fi

echo "==> 5/6 KILL the primary; verify the backup takes over and time the failover"
B_KILL=$(height "$B")
KILL_EPOCH=$(date +%s)
docker kill "$A" >/dev/null
echo "  killed primary at backup height $B_KILL (epoch $KILL_EPOCH)"
# Fresh miner for the post-kill phase (the prior one was stopped to let the chains sync).
run_miner
# Wait (up to 45s) for the backup chain to advance past the kill height -- proof the pool mined via
# the backup (which it can only do after failing over).
for _ in $(seq 1 45); do
    sleep 1
    [ "$(height "$B")" -gt "$B_KILL" ] 2>/dev/null && break
done
B2=$(height "$B")
# Failover latency from the LOG (settled now), not the poll loop: the "backup advanced" break can
# win the race against the failover line reaching the log.
FAILOVER_SECS=""
FO_EPOCH=$(failover_epoch)
[ -n "$FO_EPOCH" ] && FAILOVER_SECS=$((FO_EPOCH - KILL_EPOCH))
echo "  backup advanced $B_KILL -> $B2; failover logged at +${FAILOVER_SECS:-"?"}s after the kill"

echo "==> 6/6 verify the backup kept the pool mining, and the failover was prompt"
# Functional gate (hard): the backup chain advanced => the pool failed over and mined via it.
if [ "$B2" -gt "$B_KILL" ]; then
    pass "pool failed over and the backup advanced the chain ($B_KILL -> $B2)"
else
    fail "backup chain did not advance after failover (stuck at $B_KILL)"
fi
# Latency gate: prompt failover (bounded by the poll-path RPC + connect timeouts).
if [ -z "$FAILOVER_SECS" ]; then
    if pool_logs | grep -q "failed over to"; then
        pass "pool logged the RPC failover (latency unmeasured)"
    else
        fail "pool did not log a failover"
    fi
elif [ "$FAILOVER_SECS" -le "$FAILOVER_BUDGET" ]; then
    pass "failover within budget (${FAILOVER_SECS}s <= ${FAILOVER_BUDGET}s)"
else
    fail "failover too slow (${FAILOVER_SECS}s > ${FAILOVER_BUDGET}s budget)"
fi

if [ "$FAIL" -gt 0 ]; then
    echo "  --- pool log (failover-relevant lines, shown because a check failed) ---"
    pool_logs | grep -iE "fail|resolve|transport|unreachable|ignoring|waiting" | tail -20
fi

echo
if [ "$FAIL" -eq 0 ]; then
    echo "ALL CHECKS PASSED ($PASS passed, POOL=$POOL, $MODE)."
else
    echo "$FAIL CHECK(S) FAILED (POOL=$POOL, $MODE)."
fi
exit "$FAIL"
