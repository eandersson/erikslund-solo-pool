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

FROM debian:trixie-slim

ENV PATH=/usr/local/bin:$PATH

RUN set -eux; \
	apt-get update; \
	apt-get dist-upgrade -y; \
	apt-get install -y --no-install-recommends \
		ca-certificates \
		libmimalloc3 \
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

COPY pyproject.toml /app/pyproject.toml
COPY erikslund_pool /app/erikslund_pool
RUN chmod -R a+rX /app
ENV PYTHONPATH=/app
RUN mkdir -p /var/lib/erikslund-pool && chown 1000:1000 /var/lib/erikslund-pool
RUN mkdir -p /var/log/erikslund-pool && chown 1000:1000 /var/log/erikslund-pool
WORKDIR /var/lib/erikslund-pool
ENTRYPOINT ["python", "-m", "erikslund_pool"]
