# Benchmark harness

Compares the **share-validation hot path** of the C++ and Python pools on a
private regtest chain -- the part that actually costs CPU under load: parse
`mining.submit` -> rebuild coinbase/merkle/header -> double-SHA256 -> target check.

## How it works

`stratum_bench.py` is a synthetic Stratum v1 client: it opens N connections,
subscribes + authorizes, then floods well-formed shares with a rolling nonce
(**no proof-of-work**). Every share is structurally valid and unique, so the
pool runs the *full* validation path on each one. Both run the same
[`bench.yml`](bench.yml): vardiff off at a high fixed difficulty, so shares
never meet target -- no accepts, no blocks, a stable job -- and what's measured is
pure validation throughput, not luck.

`run_bench.sh` builds each pool, starts it on the shared regtest bitcoind
([`../docker`](../docker)) with that config, runs the load generator, samples the
pool container's CPU/RSS via `docker stats`, and prints a comparison.

## Run

```sh
bash tools/bench/run_bench.sh
# knobs (env): CONNECTIONS PIPELINE WORKERS DURATION WARMUP IMPLS
#
# A single generator worker caps at ~60k shares/s (it hashes each share, so it's
# CPU-bound too) -- at that rate both pools coast and look tied. To actually
# saturate a fast pool, add load-generator worker processes:
WORKERS=16 CONNECTIONS=160 PIPELINE=32 bash tools/bench/run_bench.sh
```

Example output (16 workers on a 32-core host -- generator-bound, so per-core/RSS are the signal):

```
impl            val/s    p50ms    p95ms    p99ms   cpu%   rssMiB
cpp            391349   10.309   14.481   16.112    602      326
python         275692   15.307   33.146   36.273   1480      939
```

> At 16 workers the generator and the pool share the host's cores, so these are
> throughput-under-load, not isolated maxima. See the root
> [README](../README.md#benchmarks) for the full two-point comparison + caveats.

Just the load generator, against any running pool:

```sh
docker run --rm --network erikslund-regtest_default -v "$PWD/bench:/bench:ro" python:3.14-slim \
  python /bench/stratum_bench.py --host bench-pool --port 3333 \
  --address bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf --connections 50 --duration 20
```

## Remote benchmarking (pool on a Linux VM)

To benchmark a pool running on a separate Linux box -- and dodge the
generator-vs-pool CPU contention that caps a co-located run -- split it: host the
pool on the VM, drive load from your PC.

**On the VM** (Linux + Docker, in this repo) bring up a port-exposed benchmark
instance (regtest bitcoind + the pool on `bench.yml`):

```sh
bash tools/bench/bench_server.sh              # C++ pool (IMPL=python for the Python one)
# prints the exact PC command to run next; when finished:
bash tools/bench/bench_server.sh stop
```

**On your PC** (in this repo; git-bash is fine) drive the load at the VM's stratum
port -- the generator runs locally in Docker, only `POOL_HOST` is required:

```sh
POOL_HOST=<vm-ip> bash tools/bench/remote_bench.sh
POOL_HOST=<vm-ip> WORKERS=16 CONNECTIONS=160 PIPELINE=32 bash tools/bench/remote_bench.sh
```

It reports val/s + submit->ack latency from the PC side. To also capture the
pool's CPU/RSS, give it SSH to the VM:

```sh
POOL_HOST=<vm-ip> POOL_SSH=user@<vm-ip> bash tools/bench/remote_bench.sh
```

Notes: use the VM's **LAN IP**, not `localhost`; on **Windows** export
`BENCH_ROOT=C:/path/to/repo` first (so the Docker bind-mount resolves); `ADDRESS`
defaults to the regtest address `bench_server.sh` uses (override for another
network); and only ever point `remote_bench.sh` at a **dedicated benchmark
instance** -- it floods shares. Knobs mirror `run_bench.sh` plus `POOL_PORT
ADDRESS POOL_SSH POOL_CONTAINER`.

## Reading the numbers

- **val/s** -- shares fully validated per second (all rejected above-target; the
  reject is the same hash work as an accept, which is the point).
- **latency** -- submit->ack, sampled over the measurement window after warmup.
- **cpu% / rssMiB** -- the pool container's mean CPU and peak RSS during the run.
- **Bottleneck check:** if a pool's `cpu%` is well under `100 x cores` while
  `val/s` plateaus, the *load generator* is the limit, not the pool -- raise
  `CONNECTIONS`/`PIPELINE`, or run several load-gen containers, until the pool's
  CPU saturates. The Python generator can itself cap throughput against the fast
  C++ pool; CPU% disambiguates.

Linux/CI script. On Windows, run under WSL -- MSYS path conversion mangles the
bind-mount and `volume:/path` arguments otherwise.
