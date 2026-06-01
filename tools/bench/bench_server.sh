#!/usr/bin/env bash
# Stand up a benchmark pool instance ON THIS HOST (e.g. a Linux VM) and expose it
# on the network, so a remote machine (e.g. a Windows PC) can drive load at it
# with tools/bench/remote_bench.sh. Keeping the load generator off the pool's host is
# the clean way to benchmark: there is no CPU contention between the two.
#
# Brings up the shared regtest bitcoind plus the chosen pool with bench.yml
# (vardiff off, high fixed difficulty, so every share is fully validated then
# rejected: pure validation throughput, no blocks), publishing the stratum port
# :3333 and API :7777 on all interfaces.
#
#   bash tools/bench/bench_server.sh              # C++ pool (default)
#   IMPL=python bash tools/bench/bench_server.sh  # Python pool
#   bash tools/bench/bench_server.sh stop         # tear it all down
#
# Run this ON THE VM (Linux + Docker). It prints the exact command to run on your
# PC afterwards.
set -uo pipefail
cd "$(dirname "$0")/../.."
NET=erikslund-regtest_default
REG="docker compose -f tools/regtest/docker-compose.yml"
POOL=bench-pool
IMPL=${IMPL:-cpp}

if [ "${1:-}" = "stop" ]; then
    docker rm -f "$POOL" >/dev/null 2>&1
    $REG --profile mine down -v --remove-orphans >/dev/null 2>&1
    echo "Stopped and cleaned up."
    exit 0
fi

echo "==> Building '$IMPL' image"
case "$IMPL" in
cpp)
    docker build -q -t erikslund-pool-cpp cpp/docker >/dev/null
    docker run --rm -e BUILD_TYPE=Release -e RUN_TESTS=0 \
        -v "$(pwd)/cpp:/src:ro" -v erikslund-cpp-build:/build erikslund-pool-cpp >/dev/null 2>&1 ;;
python)
    docker build -q -t erikslund-pool-py-ft python >/dev/null ;;
*)
    echo "IMPL must be 'cpp' or 'python' (got '$IMPL')"; exit 1 ;;
esac

echo "==> Starting regtest bitcoind"
$REG up -d bitcoind >/dev/null 2>&1
CLI="$REG exec -T bitcoind bitcoin-cli -regtest -rpcuser=erikslund -rpcpassword=erikslundpass -rpcport=18443"
for _ in $(seq 1 30); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
$CLI getblockchaininfo >/dev/null 2>&1 || { echo "bitcoind never came up"; exit 1; }

docker rm -f "$POOL" >/dev/null 2>&1
echo "==> Starting '$IMPL' pool (stratum :3333 + API :7777 on all interfaces)"
case "$IMPL" in
cpp) docker run -d --name "$POOL" --network "$NET" \
        -v erikslund-cpp-build:/build:ro \
        -v "$(pwd)/tools/bench/bench.yml:/cfg/pool.yml:ro" \
        -p 0.0.0.0:3333:3333 -p 0.0.0.0:7777:7777 \
        --entrypoint /build/cmake/erikslund-pool erikslund-pool-cpp \
        --config /cfg/pool.yml --quiet >/dev/null ;;
python) docker run -d --name "$POOL" --network "$NET" \
        -v "$(pwd)/tools/bench/bench.yml:/cfg/pool.yml:ro" \
        -p 0.0.0.0:3333:3333 -p 0.0.0.0:7777:7777 \
        erikslund-pool-py-ft --config /cfg/pool.yml --log-level WARNING >/dev/null ;;
esac

ready=
for _ in $(seq 1 40); do
    [ "$(curl -s --max-time 2 http://localhost:7777/health 2>/dev/null)" = "ok" ] && { ready=1; break; }
    sleep 1
done
[ -n "$ready" ] || { echo "Pool not healthy; recent logs:"; docker logs "$POOL" 2>&1 | tail -15; exit 1; }

ip=$(hostname -I 2>/dev/null | awk '{print $1}')
ip=${ip:-<this-vm-ip>}
echo
echo "==> Ready: '$POOL' ($IMPL) is serving stratum on :3333 (API on :7777)."
echo
echo "   From your PC (in this repo), point the load generator at this host:"
echo "     POOL_HOST=$ip bash tools/bench/remote_bench.sh"
echo "   Saturating run:"
echo "     POOL_HOST=$ip WORKERS=16 CONNECTIONS=160 PIPELINE=32 bash tools/bench/remote_bench.sh"
echo "   With CPU/RSS sampling (needs SSH from the PC to this VM):"
echo "     POOL_HOST=$ip POOL_SSH=$(whoami)@$ip bash tools/bench/remote_bench.sh"
echo
echo "   Stop when done:  bash tools/bench/bench_server.sh stop"
