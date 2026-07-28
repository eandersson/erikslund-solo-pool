#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
    echo "usage: $0 CREDENTIAL_TOOL" >&2
    exit 2
fi

tool="$1"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/sv2-noise-credentials-cli.XXXXXX")"
cleanup() {
    rm -rf -- "$work_dir"
}
trap cleanup EXIT

public_key="$work_dir/authority.public"
printf '%b' \
    '\166\143\160\000\227\234\034\021' \
    '\257\014\060\013\315\214\177\344' \
    '\206\020\374\351\271\301\036\075' \
    '\256\343\132\340\260\212\164\125' \
    > "$public_key"

expected="$work_dir/expected"
printf '%s\n' \
    '9bXiEd8boQVhq7WddEcERUL5tyyJVFYdU8th3HfbNXK3Yw6GRXh' \
    > "$expected"
actual="$work_dir/actual"
"$tool" print-authority-key "$public_key" > "$actual"
cmp "$expected" "$actual"

short_key="$work_dir/short.public"
printf '\000' > "$short_key"
if "$tool" print-authority-key "$short_key" \
    > "$work_dir/invalid-output" \
    2> "$work_dir/invalid-error"; then
    echo "short authority key was accepted" >&2
    exit 1
fi
test ! -s "$work_dir/invalid-output"
