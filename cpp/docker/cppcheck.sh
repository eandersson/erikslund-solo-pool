#!/usr/bin/env bash
#
# cppcheck static-analysis gate for the C++ pool -- a second, independent analyzer
# alongside clang-tidy (build-entrypoint.sh runs GCC + ctest; clang-tidy.sh is the
# other lint gate). Runs the higher-signal checks (warning + performance +
# portability) at the exhaustive analysis level over the pool source (src/), skipping
# the vendored Bitcoin Core crypto under third_party.
#
# The opinionated `style` checks are intentionally NOT enabled: on this codebase they
# only emit refactor suggestions (e.g. useStlAlgorithm), not bugs -- noise for a gate.
#
# Source is mounted read-only at /src. Invoke via the toolchain image:
#   docker run --rm -v "$PWD/cpp:/src:ro" \
#       --entrypoint /usr/local/bin/cppcheck.sh erikslund-pool-cpp
#
set -uo pipefail

cd /src
echo "==> $(cppcheck --version) on src/ (warning,performance,portability; exhaustive)"

# --error-exitcode=1 makes any finding fail the gate. missingInclude(System) is noise
# without the full toolchain include graph; normalCheckLevelMaxBranches is an
# informational note, not a finding.
cppcheck \
    --enable=warning,performance,portability \
    --check-level=exhaustive \
    --std=c++20 \
    --language=c++ \
    --inline-suppr \
    --suppress=missingInclude \
    --suppress=missingIncludeSystem \
    --suppress=normalCheckLevelMaxBranches \
    --error-exitcode=1 \
    --quiet \
    -i third_party \
    src/
status=$?

if [ "$status" -eq 0 ]; then
    echo "==> OK: cppcheck clean"
else
    echo "==> FAIL: cppcheck reported findings (exit $status)"
fi
exit "$status"
