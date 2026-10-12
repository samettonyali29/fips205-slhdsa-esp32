#!/usr/bin/env bash
# Copyright (c) 2026 The fips205-slhdsa-esp32 authors
# SPDX-License-Identifier: Apache-2.0
#
# Re-vendor the slhdsa-c sources into src/.
#
# usage: bash scripts/update_slhdsa_c.sh /path/to/slhdsa-c
#
# Copies the slhdsa-c implementation (top-level *.c / *.h, without test/).
# The ESP32 port's own files are NOT touched:
#   src/slhdsa_esp32.c, src/slhdsa_esp32.h, src/SLHDSA.h, src/SLHDSA_NVS.h
#
# Afterwards re-run the conformance tests (examples/slhdsa_test_vectors and
# the full ACVP set on the host, see README).

set -euo pipefail

UP=${1:?usage: $0 /path/to/slhdsa-c}
DST=$(cd "$(dirname "$0")/.." && pwd)/src
[ -f "$UP/slh_dsa.h" ] || { echo "not an slhdsa-c checkout: $UP" >&2; exit 1; }

cp "$UP"/*.c "$UP"/*.h "$DST"/
cp "$UP"/LICENSE "$DST"/LICENSE.slhdsa-c
echo "Updated $DST from $UP"
