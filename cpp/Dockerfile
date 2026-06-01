# Production image for erikslund pool (C++26). Multi-stage: GCC 16.1 on Debian
# trixie compiles the binary (libstdc++/libgcc statically linked), then a slim
# Debian runtime carries only the shared libs it needs (libcurl, libzmq).
#
# Build (from the repo root):
#   docker build -t erikslund-pool-cpp-rt cpp
#
# Run with your own config (must point at a real bitcoind):
#   docker run -d --name pool -p 3333:3333 \
#     -v $PWD/my.yml:/etc/erikslund-pool/pool.yml erikslund-pool-cpp-rt
#
# The bundled default binds the HTTP API/metrics to 127.0.0.1 (loopback only).
# To scrape /metrics from outside, set "api_listen":["0.0.0.0:7777"] in your mounted
# config and publish -p 7777:7777. The config file uses the same schema as the
# Python pool -- one config works on both.

# ---- builder ---------------------------------------------------------------
FROM gcc:16.1.0-trixie AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        make \
        libcurl4-openssl-dev \
        libzmq3-dev \
        libmimalloc-dev \
        nlohmann-json3-dev \
        libyaml-cpp-dev \
        libsimdjson-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

ARG NATIVE_ARCH=ON
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DNATIVE_ARCH=${NATIVE_ARCH} \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc" \
    && cmake --build build --target erikslund-pool -j"$(nproc)" \
    && test -x build/erikslund-pool

RUN set -eux; \
    triplet="$(dpkg-architecture -qDEB_HOST_MULTIARCH)"; \
    mkdir -p /staging/lib; \
    cp -a "/usr/lib/${triplet}"/libmimalloc.so* /staging/lib/

# ---- runtime ---------------------------------------------------------------
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libcurl4 libzmq5 libyaml-cpp0.8 libsimdjson* curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 pool \
    && useradd --uid 1000 --gid 1000 --create-home --home-dir /var/lib/erikslund-pool \
        --shell /usr/sbin/nologin pool

COPY --from=builder /src/build/erikslund-pool /usr/local/bin/erikslund-pool
COPY --from=builder /staging/lib/ /usr/local/lib/
RUN ldconfig
COPY --from=builder /src/conf/pool.yml /etc/erikslund-pool/pool.yml

# Default log dir for a standalone `docker run` with --log-file /var/log/erikslund-pool/...
# Created as root *before* dropping privileges. (The compose deploy bind-mounts a
# host dir over this path -- chown that host dir to uid 1000 so the pool can write.)
RUN mkdir -p /var/log/erikslund-pool && chown pool:pool /var/log/erikslund-pool

WORKDIR /var/lib/erikslund-pool
USER pool

EXPOSE 3333 4001 7777

HEALTHCHECK --interval=30s --timeout=4s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:7777/health || exit 1

ENTRYPOINT ["erikslund-pool"]
CMD ["--config", "/etc/erikslund-pool/pool.yml"]
