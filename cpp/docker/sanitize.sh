#!/usr/bin/env bash
#
# ASan + UBSan runtime gate for the C++ pool. Builds the test suite with
# AddressSanitizer + UndefinedBehaviorSanitizer (-DSANITIZE=ON) and runs the
# doctest corpus -- including the *_adversarial.cpp untrusted-input tests -- under
# them, so a memory error or UB violation fails the gate. Complements the GCC
# build + ctest (build-entrypoint.sh) and the clang-tidy/cppcheck static gates
# with a dynamic, runtime check. Builds only erikslund_tests: the main executable
# links mimalloc, which would fight ASan's malloc interception at run time.
#
# Source is mounted read-only at /src; the instrumented build lives in /build.
# Invoke via the toolchain image:
#   docker run --rm -v "$PWD/cpp:/src:ro" -v erikslund-cpp-asan-build:/build \
#       --entrypoint /usr/local/bin/sanitize.sh erikslund-pool-cpp
#
set -euo pipefail

BUILD_DIR=/build/cmake
echo "==> configure (Debug + ASan/UBSan)"
cmake -S /src -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug -DSANITIZE=ON >/dev/null

echo "==> build erikslund_tests (instrumented)"
cmake --build "$BUILD_DIR" --target erikslund_tests -j"$(nproc)"

echo "==> test (UBSan fatal, ASan halt-on-error)"
export ASAN_OPTIONS=halt_on_error=1:abort_on_error=1:detect_leaks=1
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
ctest --test-dir "$BUILD_DIR" --output-on-failure

echo "==> OK: ASan + UBSan clean"
