#!/usr/bin/env bash
#
# Configure + compile + test the C++ port. Source is mounted read-only at /src;
# everything written goes to the /build volume (true out-of-source build).
#
# Env knobs:
#   BUILD_TYPE   CMake build type            (default: Debug)
#   RUN_TESTS    run ctest after building    (default: 1)
#   CLEAN        wipe the CMake cache first   (default: 0)
#
set -euo pipefail

: "${BUILD_TYPE:=Debug}"
: "${RUN_TESTS:=1}"
: "${CLEAN:=0}"

if [ "$CLEAN" = "1" ]; then
    echo "==> CLEAN: removing /build/cmake"
    rm -rf /build/cmake
fi

echo "==> configure (BUILD_TYPE=$BUILD_TYPE)"
cmake -S /src -B /build/cmake -DCMAKE_BUILD_TYPE="$BUILD_TYPE"

echo "==> build"
cmake --build /build/cmake -j"$(nproc)"

if [ "$RUN_TESTS" = "1" ]; then
    echo "==> test"
    ctest --test-dir /build/cmake --output-on-failure
fi

echo "==> CPP BUILD OK"
