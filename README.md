# erikslund-solo-pool

A modern C++ Bitcoin solo mining pool. It builds work from Bitcoin Core, validates
shares, and submits solved blocks. Stratum V1 is the default miner protocol;
authenticated Stratum V2 Standard and Extended Channels are optional.

Solo mining means every block pays the miner's address in full, minus an optional
donation. The pool coordinates work but never divides rewards between miners.

> **Warning:** This software builds and submits real Bitcoin blocks. Test with your
> hardware on regtest, signet, or testnet before using mainnet.

## Quick start

Run against an existing node:

```sh
sudo sh deploy/setup.sh --create-directories
sudo cp conf/pool.yml /opt/erikslund-pool/etc/pool.yml

# Set the node address, RPC credentials, and ZMQ endpoint before starting.
# Use 127.0.0.1 when Bitcoin Core runs on this host.
sudoedit /opt/erikslund-pool/etc/pool.yml

docker compose -f deploy/docker-compose.yml up -d --build
```

The container runs as UID/GID 1000. Host directories must be writable by that user
so the pool can persist statistics and spool found blocks.

## Configuration

[`conf/pool.yml`](conf/pool.yml) is the documented default configuration and
[`conf/pool.schema.json`](conf/pool.schema.json) defines every accepted field.

```yaml
bitcoin_nodes:
  - address: bitcoind:8332
    username: erikslund
    password: CHANGE_ME_before_deploying
stratum_listen: [0.0.0.0:3333]
api_listen: [127.0.0.1:7777]
initial_difficulty: 10000
minimum_difficulty: 1
zmq_block_endpoint: tcp://bitcoind:28332
```

| Port | Purpose |
| --- | --- |
| `3333` | Stratum V1 |
| `3334` | Optional authenticated Stratum V2 |
| `7777` | Status API, health checks, and Prometheus metrics |

## Development

The toolchain image provides GCC, CMake, the dependencies, static analysis, and
sanitizers. No host compiler is required.

```sh
docker build -t erikslund-pool-build docker
docker run --rm -v "$PWD:/src:ro" -v erikslund-build:/build erikslund-pool-build
```

End-to-end tests exercise a real regtest node and native CPU miner:

```sh
bash docker/smoketest.sh
bash tools/regtest/failover-test.sh
```

The in-process submit benchmark in `tools/bench/` is built as `erikslund-bench`.

## Layout

| Path | Purpose |
| --- | --- |
| [`src/`](src/) | Pool sources, grouped by subsystem |
| [`tests/`](tests/) | Unit, adversarial, and concurrency tests |
| [`third_party/`](third_party/) | Unmodified vendored Bitcoin Core SHA-256 code |
| [`conf/`](conf/) | Pool configuration and schema |
| [`docker/`](docker/) | Reproducible build, analysis, and test tooling |
| [`deploy/`](deploy/) | Compose deployments |
| [`tools/regtest/`](tools/regtest/) | Bitcoin Core and CPU-miner regtest harness |

## License

Licensed under the [GNU General Public License v3.0 or later](LICENSE). The
vendored Bitcoin Core SHA-256 code is MIT-licensed and retains its attribution.

## Credits

- Stratum V1 design lineage from [ckpool](https://bitbucket.org/ckolivas/ckpool).
