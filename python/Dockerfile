# syntax=docker/dockerfile:1
# Free-threaded (no-GIL) base image for erikslund_pool, built from CPython source.
#
# Based on the official docker-library/python 3.14/slim-trixie Dockerfile
#   https://github.com/docker-library/python/blob/master/3.14/slim-trixie/Dockerfile
# adapted in two ways:
#   1. `./configure --disable-gil` -> a free-threaded interpreter (python3.14t).
#      No official free-threaded image exists yet, hence the source build.
#   2. Built with all the general optimizations the official image uses:
#      PGO (--enable-optimizations) + link-time optimization (--with-lto) +
#      release CFLAGS. (We omit the official's --enable-shared/rpath dance: that
#      lets a *base* image share libpython with downstream images; this is a leaf
#      app image, so a self-contained static libpython is simpler and the
#      optimizations are independent of it.)
#
# Build from the repository root -- the native Noise core is shared with C++:
#   docker build -f python/Dockerfile -t erikslund-pool-python .

FROM gcc:16.1.0-trixie AS noise-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
		cmake \
		git \
		libssl-dev \
	&& rm -rf /var/lib/apt/lists/*

ARG SECP256K1_COMMIT=1a53f4961f337b4d166c25fce72ef0dc88806618
RUN git init -q /tmp/secp256k1 \
	&& git -C /tmp/secp256k1 fetch -q --depth 1 \
		https://github.com/bitcoin-core/secp256k1.git "${SECP256K1_COMMIT}" \
	&& git -C /tmp/secp256k1 checkout -q --detach FETCH_HEAD \
	&& test "$(git -C /tmp/secp256k1 rev-parse HEAD)" = "${SECP256K1_COMMIT}" \
	&& cmake -S /tmp/secp256k1 -B /tmp/secp256k1/build \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_INSTALL_PREFIX=/usr/local \
		-DBUILD_SHARED_LIBS=OFF \
		-DCMAKE_POSITION_INDEPENDENT_CODE=ON \
		-DCMAKE_C_VISIBILITY_PRESET=hidden \
		-DSECP256K1_INSTALL=ON \
		-DSECP256K1_ENABLE_API_VISIBILITY_ATTRIBUTES=OFF \
		-DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON \
		-DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON \
		-DSECP256K1_ENABLE_MODULE_ELLSWIFT=ON \
		-DSECP256K1_ENABLE_MODULE_ECDH=OFF \
		-DSECP256K1_ENABLE_MODULE_RECOVERY=OFF \
		-DSECP256K1_ENABLE_MODULE_MUSIG=OFF \
		-DSECP256K1_BUILD_TESTS=OFF \
		-DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF \
		-DSECP256K1_BUILD_CTIME_TESTS=OFF \
		-DSECP256K1_BUILD_BENCHMARK=OFF \
		-DSECP256K1_BUILD_EXAMPLES=OFF \
		-DSECP256K1_VALGRIND=OFF \
	&& cmake --build /tmp/secp256k1/build -j"$(nproc)" \
	&& cmake --install /tmp/secp256k1/build \
	&& install -D /tmp/secp256k1/COPYING /usr/share/doc/libsecp256k1/COPYING \
	&& rm -rf /tmp/secp256k1

COPY cpp/src/sv2_noise /src/sv2-noise
RUN cmake -S /src/sv2-noise -B /build \
		-DCMAKE_BUILD_TYPE=Release \
		-DSV2_NOISE_BUILD_STATIC=OFF \
		-DSV2_NOISE_BUILD_SHARED=ON \
		-DSV2_NOISE_BUILD_CREDENTIAL_TOOL=OFF \
		-DSV2_NOISE_BUILD_TESTS=OFF \
	&& cmake --build /build --target sv2_noise_shared -j"$(nproc)" \
	&& test -f /build/libsv2_noise.so

FROM debian:trixie-slim AS runtime

ENV PATH=/usr/local/bin:$PATH

RUN set -eux; \
	apt-get update; \
	apt-get dist-upgrade -y; \
	apt-get install -y --no-install-recommends \
		ca-certificates \
		libmimalloc3 \
		libssl3t64 \
		netbase \
		tzdata \
	; \
	apt-get dist-clean

ENV PYTHON_VERSION=3.14.5
ENV PYTHON_SHA256=7e32597b99e5d9a39abed35de4693fa169df3e5850d4c334337ffd6a19a36db6

ARG CPU_ARCH=native

RUN set -eux; \
	\
	savedAptMark="$(apt-mark showmanual)"; \
	apt-get update; \
	apt-get dist-upgrade -y; \
	apt-get install -y --no-install-recommends \
		dpkg-dev \
		gcc \
		gnupg \
		libbluetooth-dev \
		libbz2-dev \
		libc6-dev \
		libdb-dev \
		libffi-dev \
		libgdbm-dev \
		liblzma-dev \
		libncursesw5-dev \
		libreadline-dev \
		libsqlite3-dev \
		libssl-dev \
		libzstd-dev \
		make \
		tk-dev \
		uuid-dev \
		wget \
		xz-utils \
		zlib1g-dev \
	; \
	\
	wget -O python.tar.xz "https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz"; \
	echo "$PYTHON_SHA256 *python.tar.xz" | sha256sum -c -; \
	mkdir -p /usr/src/python; \
	tar --extract --directory /usr/src/python --strip-components=1 --file python.tar.xz; \
	rm python.tar.xz; \
	\
	cd /usr/src/python; \
	gnuArch="$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)"; \
	./configure \
		--build="$gnuArch" \
		--disable-gil \
		--enable-loadable-sqlite-extensions \
		--enable-optimizations \
		--enable-option-checking=fatal \
		$(test "${gnuArch%%-*}" != 'riscv64' && echo '--with-lto') \
		--with-ensurepip \
	; \
	nproc="$(nproc)"; \
	EXTRA_CFLAGS="$(dpkg-buildflags --get CFLAGS)"; \
	LDFLAGS="$(dpkg-buildflags --get LDFLAGS)"; \
	EXTRA_CFLAGS="${EXTRA_CFLAGS:-} -O3 -march=${CPU_ARCH} -mtune=${CPU_ARCH} -fno-plt -fno-semantic-interposition -funroll-loops -fomit-frame-pointer -falign-functions=32 -falign-loops=32 -pipe"; \
	LDFLAGS="${LDFLAGS:-} -Wl,--strip-all -Wl,-O3 -Wl,--as-needed -Wl,-z,relro -Wl,-z,now"; \
	make -j "$nproc" \
		"EXTRA_CFLAGS=${EXTRA_CFLAGS:-}" \
		"LDFLAGS=${LDFLAGS:-}" \
	; \
	make install; \
	\
	cd /; \
	rm -rf /usr/src/python; \
	\
	find /usr/local -depth \
		\( \
			\( -type d -a \( -name test -o -name tests -o -name idle_test \) \) \
			-o \( -type f -a \( -name '*.pyc' -o -name '*.pyo' -o -name 'libpython*.a' \) \) \
		\) -exec rm -rf '{}' + \
	; \
	\
	ldconfig; \
	\
# keep only the shared libraries the interpreter actually links at runtime,
# then purge the -dev build dependencies
	apt-mark auto '.*' > /dev/null; \
	apt-mark manual $savedAptMark; \
	find /usr/local -type f -executable -not \( -name '*tkinter*' \) -exec ldd '{}' ';' \
		| awk '/=>/ { so = $(NF-1); if (index(so, "/usr/local/") == 1) { next }; gsub("^/(usr/)?", "", so); printf "*%s\n", so }' \
		| sort -u \
		| xargs -rt dpkg-query --search \
		| awk 'sub(":$", "", $1) { print $1 }' \
		| sort -u \
		| xargs -r apt-mark manual \
	; \
	apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \
	apt-get dist-clean; \
	\
	export PYTHONDONTWRITEBYTECODE=1; \
	python3.14t --version; \
	python3.14t -m pip --version

RUN set -eux; \
	ln -sfvT python3.14t /usr/local/bin/python3; \
	ln -sfvT python3.14t /usr/local/bin/python; \
	python --version; \
	python -c "import sys; print('GIL default:', sys._is_gil_enabled())"

RUN python -m pip install --no-cache-dir --only-binary=:all: \
		"fastapi>=0.136" uvicorn uvloop httptools msgspec pyzmq

RUN python -m pip install --no-cache-dir pyyaml
RUN python -c "import sys, fastapi, uvicorn, uvloop, httptools, msgspec, zmq, pydantic_core, yaml; \
print('stack imported; fastapi', fastapi.__version__); \
assert not sys._is_gil_enabled(), 'FAIL: an import re-enabled the GIL'; \
print('PASS: GIL stays OFF on 3.14t with the full stack (orjson excluded)')"

RUN set -eux; \
	mimallocPath="$(ldconfig -p | awk '/libmimalloc\.so\.3 / { print $NF; exit }')"; \
	test -n "$mimallocPath"; \
	test -e "$mimallocPath"; \
	mkdir -p /usr/local/lib; \
	ln -sfvT "$mimallocPath" /usr/local/lib/libmimalloc.so.3; \
	test -e /usr/local/lib/libmimalloc.so.3
ENV LD_PRELOAD=/usr/local/lib/libmimalloc.so.3

RUN set -eux; \
	test "$(python -c 'print(open("/proc/self/maps").read().count("mimalloc"))')" -gt 0; \
	python -c "import sys; assert not sys._is_gil_enabled(), 'FAIL: GIL re-enabled'; \
print('PASS: mimalloc preloaded and GIL OFF')"

COPY --from=noise-builder /build/libsv2_noise.so /usr/local/lib/libsv2_noise.so
COPY cpp/src/sv2_noise/LICENSE-secp256k1 /usr/share/doc/erikslund-pool/LICENSE-secp256k1
RUN ldconfig
COPY python/pyproject.toml /app/pyproject.toml
COPY python/erikslund_pool /app/erikslund_pool
RUN chmod -R a+rX /app
ENV PYTHONPATH=/app
RUN mkdir -p /var/lib/erikslund-pool && chown 1000:1000 /var/lib/erikslund-pool
RUN mkdir -p /var/log/erikslund-pool && chown 1000:1000 /var/log/erikslund-pool
WORKDIR /var/lib/erikslund-pool
ENTRYPOINT ["python", "-m", "erikslund_pool"]
