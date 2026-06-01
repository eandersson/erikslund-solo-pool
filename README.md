# erikslund-solo-pool

Two independent implementations of a **Bitcoin solo mining pool** -- one in modern
**C++**, one in **free-threaded Python** -- sharing a config format, an
HTTP/Prometheus API, and a Docker regtest harness. Both speak Stratum v1, build
block templates from `bitcoind`, validate miner shares, and submit solved blocks.

*Solo* means every block a miner finds pays **that miner's address in full**
(minus an optional donation); the pool coordinates and distributes work, it does
not split rewards across participants.

> WARNING: **This builds and submits real Bitcoin blocks.** Run it on regtest/signet/testnet with your actual hardware first.

## Two implementations, one behavior

| | [`cpp/`](cpp/) | [`python/`](python/) |
| --- | --- | --- |
| Language / runtime | C++26 (GCC 16.1) | Free-threaded CPython 3.14t (no-GIL) |
| Concurrency | epoll reactor, one thread per core | N asyncio event loops (`SO_REUSEPORT`), one per core |
| Share hashing | Vendored Bitcoin Core SHA-256 -- SSE4 / AVX2 / SHA-NI runtime dispatch | `hashlib` (OpenSSL) |
| JSON | simdjson (parse) | msgspec |
| Allocator | mimalloc | CPython default |
| Leans toward | Throughput, memory, latency | Readability, hackability |

## Quick start

**Real network** -- Docker Compose stacks in [`deploy/`](deploy/), with or without
an embedded Bitcoin Core.

**Bring your own Bitcoin node** -- these stacks run the pool only and bind-mount
its config + data from the host. The pool runs as **UID/GID 1000**, so create the
host dirs owned by `1000:1000` (Docker does not chown bind-mounts) or it can't
persist stats or spool found blocks:

```sh
sudo mkdir -p /opt/erikslund-pool/etc /opt/erikslund-pool/data /opt/erikslund-pool/logs
sudo cp conf/pool.yml /opt/erikslund-pool/etc/pool.yml
sudo chown -R 1000:1000 /opt/erikslund-pool

docker compose -f deploy/docker-compose.cpp.yml    up -d --build   # C++ pool
docker compose -f deploy/docker-compose.python.yml up -d --build   # Python pool
```

## Configuration

One YAML file, [`conf/pool.yml`](conf/pool.yml), validated by
[`conf/pool.schema.json`](conf/pool.schema.json) and read by **both** pools:

```yaml
bitcoin_nodes:
  - address: bitcoind:8332      # extra entries are failover nodes
    username: erikslund
    password: CHANGE_ME_before_deploying
stratum_listen:  [0.0.0.0:3333] # multiple entries bind multiple ports
api_listen:      [127.0.0.1:7777] # status + /metrics -- loopback default; override to expose
initial_difficulty: 10000       # vardiff adjusts from here
minimum_difficulty: 1
zmq_block_endpoint: tcp://bitcoind:28332   # instant new-block work
```

| Port | Purpose                                                                       |
| --- |--------------------------------------------------------------------------------|
| `3333` | Stratum V1 -- miners connect here                                            |
| `7777` | HTTP status JSON + Prometheus `/metrics` (`/health`, `/status`, `/stats/*`) |

## Benchmarks

[`tools/bench/`](tools/bench/) measures the **share-validation hot path** -- parse
`mining.submit` -> rebuild coinbase/merkle/header -> double-SHA256 -> target
compare -- on a private regtest chain. A synthetic Stratum client
([`stratum_bench.py`](tools/bench/stratum_bench.py)) floods structurally-valid,
always-above-target shares (no proof-of-work, so no blocks), exercising the
pool's *full* validation path. Both pools run the identical
[`tools/bench/bench.yml`](tools/bench/bench.yml) and the same generator.

Measured on a **32-core x86-64** host, Docker, 30 s window after a 5 s warmup
(`WORKERS=16 CONNECTIONS=160 PIPELINE=32 bash tools/bench/run_bench.sh`, Release build).
The generator hashes each share too, so it's CPU-bound: even at 16 workers the C++ pool
runs well under saturation (~6 of 32 cores), so throughput here is *generator-bound*,
making the **per-core** and **memory** columns -- not raw shares/s -- the efficiency signal.

| impl | shares/s | per core | p50 ms | p95 ms | p99 ms | CPU % | peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **C++** | 391,349 | **~65,000** | 10.3 | 14.5 | 16.1 | 602 | **326 MiB** |
| **Python** | 275,692 | ~18,600 | 15.3 | 33.1 | 36.3 | 1480 | 939 MiB |

C++ sustains **391k shares/s on ~6.0 cores**; Python **276k on ~14.8** -- about
**3.5x the throughput per core**, with **~2.9x less memory** and a far tighter
tail (**p99 16 ms vs 36 ms**).

**Memory at connection scale** -- idle connections (each does a real
`mining.subscribe` + `mining.authorize`, then holds), pool RSS via `docker stats`
(`CONNS="50 20000" bash tools/bench/connscale.sh`, Debug build, 32-core host):

| idle connections | C++ RSS | Python RSS |
| --- | ---: | ---: |
| 50 | 7 MiB | 75 MiB |
| 20,000 | **109 MiB** (~5 KiB/conn) | **443 MiB** (~19 KiB/conn) |

Both hold 20,000 idle connections without dropping any. The ceiling here is the
benchmark, not the pool: a single load-generator container caps near ~28k
connections (ephemeral source ports, 60999-32768), and `conn-bench.yml` caps
`max_clients` at 20,000. To push higher, raise `max_clients`, the deploy's
`nofile`, and drive load from multiple client IPs / listen ports.

## Layout

| Path | What |
| --- | --- |
| [`cpp/`](cpp/) | C++26 pool -- sources, tests (doctest), Docker build + smoke test |
| [`python/`](python/) | Free-threaded Python pool -- package `erikslund_pool`, tests, Docker image |
| [`conf/`](conf/) | Shared `pool.yml` + JSON-Schema |
| [`tools/`](tools/) | Dev & test tooling -- `regtest/` harness (bitcoind + miner), `bench/` (share-validation benchmark), CPU miner, fake bitcoind, status page |
| [`deploy/`](deploy/) | Production Compose stacks (embedded / external bitcoind) |

## License

Licensed under the **[GNU General Public License v3.0 or later](LICENSE)**. The
vendored Bitcoin Core SHA-256 in [`cpp/third_party/bitcoin/`](cpp/third_party/bitcoin/)
is **MIT** (Bitcoin Core developers, GPL-compatible), used unmodified with its
license/attribution preserved there.

## Credits

- Stratum V1; design lineage from [ckpool](https://bitbucket.org/ckolivas/ckpool).
