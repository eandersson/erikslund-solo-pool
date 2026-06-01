# Toolchain image for building + testing the C++26 port (erikslund-pool-cpp).
#
# Mirrors the philosophy of c/docker: the source tree is mounted read-only at
# /src at run time and the out-of-source CMake build lives in a /build volume,
# so the host tree stays pristine and rebuilds are incremental across runs.
#
# Usage (from repo root):
#   docker build -t erikslund-pool-cpp cpp/docker
#   docker run --rm -v "$PWD/cpp:/src:ro" -v erikslund-cpp-build:/build erikslund-pool-cpp
#
FROM gcc:16.1.0-trixie

ENV DEBIAN_FRONTEND=noninteractive
# The gcc image already ships g++ 16 (C++26) + make; add CMake, clang-tidy (the
# lint gate; see clang-tidy.sh), and the libraries.
RUN apt-get update && apt-get dist-upgrade -y && apt-get install -y --no-install-recommends \
        cmake \
        make \
        clang-tidy \
        cppcheck \
        libcurl4-openssl-dev \
        libzmq3-dev \
        libmimalloc-dev \
        nlohmann-json3-dev \
        libsimdjson-dev \
        libyaml-cpp-dev \
        doctest-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY build-entrypoint.sh /usr/local/bin/build-entrypoint.sh
COPY clang-tidy.sh /usr/local/bin/clang-tidy.sh
COPY cppcheck.sh /usr/local/bin/cppcheck.sh
RUN chmod +x /usr/local/bin/build-entrypoint.sh /usr/local/bin/clang-tidy.sh \
        /usr/local/bin/cppcheck.sh

WORKDIR /build
ENTRYPOINT ["/usr/local/bin/build-entrypoint.sh"]
