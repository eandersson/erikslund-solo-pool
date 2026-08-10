#!/usr/bin/env bash
#
# clang-tidy lint gate for the C++ pool. Static-analysis pass over the curated
# checks in .clang-tidy. GCC (build-entrypoint.sh) is the authoritative
# compiler; clang front-end diagnostics are surfaced as NOTES but do not gate --
# only findings from our enabled checks fail the build.
#
# Source is mounted read-only at /src; compile_commands.json and the generated IPC
# headers come from a CMake build tree in the /build volume. Invoke via the toolchain image:
#   docker run --rm -v "$PWD:/src:ro" \
#       -v erikslund-build:/build \
#       --entrypoint /usr/local/bin/clang-tidy.sh erikslund-pool-build
#
set -euo pipefail

BUILD_DIR=/build/cmake
echo "==> configure (for compile_commands.json)"
cmake -S /src -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug >/dev/null

echo "==> generate IPC bindings"
cmake --build "$BUILD_DIR" --target generate_ipc_bindings --parallel "$(nproc)" >/dev/null

mapfile -t files < <(find /src/src -name '*.cpp' | sort)
echo "==> clang-tidy on ${#files[@]} translation units"

OUT=/tmp/tidy.d
rm -rf "$OUT"
mkdir -p "$OUT"
export BUILD_DIR OUT
# One clang-tidy per TU, in parallel; per-file logs avoid interleaving. Preserve every exit status
# so compiler-only diagnostics can remain notes without hiding a missing command, crash, or other
# analyzer failure.
printf '%s\0' "${files[@]}" | xargs -0 -P "$(nproc)" -I{} sh -c '
    prefix="$OUT/$(echo "$1" | tr / _)"
    status=0
    clang-tidy -p "$BUILD_DIR" --quiet --export-fixes="$prefix.yaml" "$1" \
        >"$prefix.log" 2>&1 || status=$?
    printf "%s\t%s\n" "$status" "$1" >"$prefix.status"
' _ {}
cat "$OUT"/*.log > /tmp/clang-tidy.log

status_count=$(find "$OUT" -maxdepth 1 -type f -name '*.status' | wc -l)
if [ "$status_count" -ne "${#files[@]}" ]; then
    echo "==> FAIL: clang-tidy completed $status_count of ${#files[@]} translation units"
    exit 1
fi

# GCC is the compile authority: clang's own front-end diagnostics are notes only.
notes=$(
    grep -hE ': (warning|error): .*\[clang-diagnostic-' /tmp/clang-tidy.log |
        sed 's#^/src/##' | sort -u || true
)
if [ -n "$notes" ]; then
    echo "==> note: clang front-end diagnostics (NOT gated -- GCC is the compiler):"
    echo "$notes" | sed 's/^/      /'
fi

unexpected_statuses=()
for status_file in "$OUT"/*.status; do
    IFS=$'\t' read -r status source < "$status_file"
    if [ "$status" -eq 0 ]; then
        continue
    fi

    fixes_file="${status_file%.status}.yaml"
    if [ "$status" -eq 1 ] && [ -f "$fixes_file" ] &&
            grep -qE '^  - DiagnosticName:[[:space:]]+clang-diagnostic-error' "$fixes_file" &&
            ! grep -E '^  - DiagnosticName:' "$fixes_file" |
                grep -qvE 'DiagnosticName:[[:space:]]+clang-diagnostic-'; then
        continue
    fi
    unexpected_statuses+=("$status_file")
done

if [ "${#unexpected_statuses[@]}" -ne 0 ]; then
    echo "==> FAIL: clang-tidy did not complete normally:"
    for status_file in "${unexpected_statuses[@]}"; do
        IFS=$'\t' read -r status source < "$status_file"
        echo "      $source (exit $status)"
        tail -40 "${status_file%.status}.log" | sed 's/^/        /'
    done
    exit 1
fi

# Gate: any finding from our enabled checks fails the build.
findings=$(
    grep -hE ': (warning|error): ' /tmp/clang-tidy.log |
        grep -vE '\[clang-diagnostic-' | sed 's#^/src/##' | sort -u || true
)
if [ -n "$findings" ]; then
    echo "==> FAIL: clang-tidy reported $(printf '%s\n' "$findings" | wc -l) finding(s):"
    printf '%s\n' "$findings" | sed 's/^/      /'
    exit 1
fi
echo "==> OK: clang-tidy clean"
