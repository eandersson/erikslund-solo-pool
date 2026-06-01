#!/usr/bin/env bash
#
# clang-tidy lint gate for the C++ pool. Static-analysis pass over the curated
# checks in cpp/.clang-tidy. GCC (build-entrypoint.sh) is the authoritative
# compiler; clang front-end diagnostics (e.g. a libstdc++ consteval std::format,
# which GCC compiles fine) are surfaced as NOTES but do not gate -- only findings
# from our enabled checks fail the build.
#
# Source is mounted read-only at /src; compile_commands.json comes from a CMake
# configure into the /build volume. Invoke via the toolchain image:
#   docker run --rm -v "$PWD/cpp:/src:ro" -v erikslund-cpp-build:/build \
#       --entrypoint /usr/local/bin/clang-tidy.sh erikslund-pool-cpp
#
set -uo pipefail

BUILD_DIR=/build/cmake
echo "==> configure (for compile_commands.json)"
cmake -S /src -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug >/dev/null

mapfile -t files < <(find /src/src -name '*.cpp' | sort)
echo "==> clang-tidy on ${#files[@]} translation units"

OUT=/tmp/tidy.d
rm -rf "$OUT"; mkdir -p "$OUT"
export BUILD_DIR OUT
# One clang-tidy per TU, in parallel; per-file logs avoid interleaving. A TU that
# clang cannot constant-evaluate exits nonzero -- tolerated here (|| true); the
# gate below reads the diagnostics, not the exit code.
printf '%s\0' "${files[@]}" | xargs -0 -P "$(nproc)" -I{} sh -c '
    clang-tidy -p "$BUILD_DIR" --quiet "$1" > "$OUT/$(echo "$1" | tr / _).log" 2>&1 || true
' _ {}
cat "$OUT"/*.log > /tmp/clang-tidy.log

# GCC is the compile authority: clang's own front-end diagnostics are notes only.
notes=$(grep -hE ': (warning|error): .*\[clang-diagnostic-' /tmp/clang-tidy.log | sed 's#^/src/##' | sort -u)
if [ -n "$notes" ]; then
    echo "==> note: clang front-end diagnostics (NOT gated -- GCC is the compiler):"
    echo "$notes" | sed 's/^/      /'
fi

# Gate: any finding from our enabled checks fails the build.
findings=$(grep -hE ': warning: ' /tmp/clang-tidy.log | grep -vE '\[clang-diagnostic-' | sed 's#^/src/##' | sort -u)
if [ -n "$findings" ]; then
    echo "==> FAIL: clang-tidy reported $(printf '%s\n' "$findings" | wc -l) finding(s):"
    printf '%s\n' "$findings" | sed 's/^/      /'
    exit 1
fi
echo "==> OK: clang-tidy clean"
