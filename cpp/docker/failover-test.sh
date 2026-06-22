#!/usr/bin/env bash
exec env POOL=cpp bash "$(dirname "$0")/../../tools/regtest/failover-test.sh" "$@"
