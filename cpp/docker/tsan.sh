#!/usr/bin/env bash
#
# ThreadSanitizer runtime gate for the C++ pool. Builds the test suite with
# -DSANITIZE_THREAD=ON and runs the doctest corpus -- most importantly the
# cross-thread stress tests (reactor read loop vs. work-thread notify vs.
# EPOLLOUT flush on one SocketConnection) -- under TSan, so a data race or
# lock-order inversion fails the gate. Complements sanitize.sh (ASan+UBSan):
# TSan cannot combine with ASan, so it gets its own build tree and pass.
#
# Source is mounted read-only at /src; the instrumented build lives in /build.
# Invoke via the toolchain image:
#   docker run --rm -v "$PWD/cpp:/src:ro" -v erikslund-cpp-tsan-build:/build \
#       --entrypoint /usr/local/bin/tsan.sh erikslund-pool-cpp
#
set -euo pipefail

BUILD_DIR=/build/cmake
echo "==> configure (Debug + TSan)"
cmake -S /src -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug -DSANITIZE_THREAD=ON >/dev/null

echo "==> build erikslund_tests (instrumented)"
cmake --build "$BUILD_DIR" --target erikslund_tests -j"$(nproc)"

echo "==> test (TSan halt-on-error)"
export TSAN_OPTIONS=halt_on_error=1:abort_on_error=1:second_deadlock_stack=1
ctest --test-dir "$BUILD_DIR" --output-on-failure

echo "==> OK: TSan clean"
