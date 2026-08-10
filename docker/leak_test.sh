#!/usr/bin/env bash
# Does hammering the HTTP API grow the pool's memory? Regtest templates are tiny,
# so GBT-churn can't fire here -- any RSS growth under load is the API path itself.
set -uo pipefail
export MSYS_NO_PATHCONV=1

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/.." && { pwd -W 2>/dev/null || pwd; })}"
COMPOSE="docker compose -f $REPO_ROOT/tools/regtest/docker-compose.yml"
CLI="$COMPOSE exec -T bitcoind bitcoin-cli -regtest -rpcuser=erikslund -rpcpassword=erikslundpass -rpcport=18443"
NET=erikslund-regtest_default
POOL=ep-leak
MINER=ep-leak-miner
MINER_ADDR=bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf

cleanup() {
    docker rm -f "$MINER" "$POOL" >/dev/null 2>&1
    $COMPOSE down -v --remove-orphans >/dev/null 2>&1
}
trap cleanup EXIT

mem() { docker stats --no-stream --format '{{.MemUsage}}' "$POOL"; }

echo "==> build"
docker build -q -t erikslund-pool-build "$REPO_ROOT/docker" >/dev/null
docker run --rm -v "$REPO_ROOT:/src:ro" \
    -v erikslund-build:/build \
    erikslund-pool-build >/tmp/pool-leak-build.log 2>&1 || { tail -30 /tmp/pool-leak-build.log; exit 1; }

echo "==> bitcoind"
$COMPOSE up -d bitcoind >/dev/null 2>&1
for _ in $(seq 1 40); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
$CLI createwallet w >/dev/null 2>&1 || true
ADDR=$($CLI getnewaddress 2>/dev/null) && $CLI generatetoaddress 120 "$ADDR" >/dev/null 2>&1

echo "==> pool"
docker rm -f "$POOL" >/dev/null 2>&1
docker run -d --name "$POOL" --network "$NET" \
    -v erikslund-build:/build:ro \
    -v "$REPO_ROOT/docker/regtest.yml:/cfg/pool.yml:ro" \
    --entrypoint /build/cmake/erikslund-pool erikslund-pool-build --config /cfg/pool.yml >/dev/null
for _ in $(seq 1 30); do
    [[ "$(docker logs "$POOL" 2>&1)" == *"Stratum listening"* ]] && break
    sleep 1
done

echo "==> miner (keep one client connected)"
$COMPOSE build miner >/dev/null 2>&1
docker rm -f "$MINER" >/dev/null 2>&1
docker run -d --name "$MINER" --network "$NET" erikslund-miner:latest \
    --algo sha256d --url "stratum+tcp://$POOL:3333" \
    --user "$MINER_ADDR" --pass x --threads 1 --retry-pause 2 >/dev/null
sleep 8

echo "==> baseline memory"
BEFORE=$(mem); echo "  before: $BEFORE"

echo "==> hammer /metrics.json + /stats/client (200k requests each, keep-alive)"
docker run --rm --network "$NET" curlimages/curl:latest -s -o /dev/null \
    "http://$POOL:7777/metrics.json?[1-200000]"
docker run --rm --network "$NET" curlimages/curl:latest -s -o /dev/null \
    "http://$POOL:7777/stats/client/$MINER_ADDR?[1-200000]"

echo "==> memory after load"
AFTER=$(mem); echo "  after:  $AFTER"
echo "RESULT before=$BEFORE after=$AFTER"
