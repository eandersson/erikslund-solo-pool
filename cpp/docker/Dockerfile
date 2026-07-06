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
        git \
        clang-tidy \
        cppcheck \
        libcurl4-openssl-dev \
        libzmq3-dev \
        libyaml-cpp-dev \
        doctest-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Glaze (header-only: JSON/YAML/CBOR/... serialization + compile-time reflection): the JSON
# parser/serializer the pool builds against. Header-only -> drop the include tree onto the
# default search path (/usr/local/include); no link step.
ARG GLAZE_VERSION=v7.8.4
RUN git clone --depth 1 --branch "${GLAZE_VERSION}" https://github.com/stephenberry/glaze.git /tmp/glaze \
    && cp -r /tmp/glaze/include/glaze /usr/local/include/glaze \
    && rm -rf /tmp/glaze

# mimalloc (Microsoft): the interposed allocator. Built from a pinned release (like Glaze) instead
# of the distro package -- installs libmimalloc.so + mimalloc.h to /usr/local (MI_INSTALL_TOPLEVEL).
ARG MIMALLOC_VERSION=v3.3.2
RUN git clone --depth 1 --branch "${MIMALLOC_VERSION}" https://github.com/microsoft/mimalloc.git /tmp/mimalloc \
    && cmake -S /tmp/mimalloc -B /tmp/mimalloc/build -DCMAKE_BUILD_TYPE=Release \
        -DMI_INSTALL_TOPLEVEL=ON -DMI_BUILD_TESTS=OFF \
    && cmake --build /tmp/mimalloc/build -j"$(nproc)" \
    && cmake --install /tmp/mimalloc/build \
    && rm -rf /tmp/mimalloc \
    && ldconfig

COPY build-entrypoint.sh /usr/local/bin/build-entrypoint.sh
COPY clang-tidy.sh /usr/local/bin/clang-tidy.sh
COPY cppcheck.sh /usr/local/bin/cppcheck.sh
COPY sanitize.sh /usr/local/bin/sanitize.sh
COPY tsan.sh /usr/local/bin/tsan.sh
RUN chmod +x /usr/local/bin/build-entrypoint.sh /usr/local/bin/clang-tidy.sh \
        /usr/local/bin/cppcheck.sh /usr/local/bin/sanitize.sh /usr/local/bin/tsan.sh

WORKDIR /build
ENTRYPOINT ["/usr/local/bin/build-entrypoint.sh"]
