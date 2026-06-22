#!/usr/bin/env bash
exec env POOL=python bash "$(dirname "$0")/../tools/regtest/failover-test.sh" "$@"
