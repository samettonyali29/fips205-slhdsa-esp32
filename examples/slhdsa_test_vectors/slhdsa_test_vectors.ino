/*
 * SLH-DSA FIPS 205 Test Vector Verification (NIST ACVP)
 *
 * Verifies this implementation against official NIST ACVP test vectors for
 * all 12 parameter sets, to ensure conformance with FIPS 205.
 *
 * Test vector source:
 *   https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/
 *   SLH-DSA-keyGen-FIPS205, SLH-DSA-sigGen-FIPS205, SLH-DSA-sigVer-FIPS205
 * converted into acvp_vectors.h by scripts/gen_acvp_vectors.py.
 *
 * The default subset (about 10 minutes on an ESP32 @ 240 MHz):
 *   - keyGen:  1 case per parameter set (all 12)
 *   - sigGen:  2 cases per fast ("f") set, 1 for SLH-DSA-SHA2-128s; the
 *              cases cover pure SLH-DSA with context, HashSLH-DSA (pre-hash)
 *              and the internal interface, deterministic and hedged
 *   - sigVer:  1 valid + 1 invalid signature per parameter set (all 12)
 *   - randomized round trips with negative tests for the "f" sets
 * Regenerate the header with other options (see the script) for more
 * cases; signing with the larger "s" sets takes minutes per case.
 *
 * The test logic is in acvp_runner.h; the same file is used by host tests,
 * which run every one of the 1248 ACVP cases.
 *
 * Copyright (c) 2026 The fips205-slhdsa-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <mbedtls/sha256.h>

static unsigned long caseStart;

static void acvp_sha256(const uint8_t *in, size_t len, uint8_t out[32]) {
  mbedtls_sha256(in, len, out, 0);
}
static void acvp_fail(const char *what, unsigned tcId) {
  Serial.printf("  [FAIL] %s tcId=%u\n", what, tcId);
}
static void acvp_progress(const char *what, unsigned tcId) {
  Serial.printf("  %-10s %4u  (+%lu s)\n", what, tcId, (millis() - caseStart) / 1000);
}

#include "acvp_runner.h"

// Round trips for the six "f" sets (bits 2, 3, 6, 7, 10, 11)
static const unsigned ROUND_TRIP_SETS = 0x0CCC;

static void testTask(void *) {
  Serial.println();
  Serial.println("================================================");
  Serial.println("  SLH-DSA FIPS 205 Test Vector Verification");
  Serial.println("  (NIST ACVP SLH-DSA keyGen / sigGen / sigVer)");
  Serial.println("================================================");
  Serial.printf("%u keyGen, %u sigGen, %u sigVer cases; elapsed time in ( )\n\n",
                (unsigned)acvp_keygen_count, (unsigned)acvp_siggen_count,
                (unsigned)acvp_sigver_count);

  acvp::Result r;
  caseStart = millis();
  acvp::runAll(r, ROUND_TRIP_SETS);

  Serial.println();
  Serial.println("================================================");
  Serial.printf("  Results: %d passed, %d failed (%lu s)\n", r.pass, r.fail,
                (millis() - caseStart) / 1000);
  Serial.println(r.fail == 0 ? "  ALL TESTS PASSED -- FIPS 205 conformant"
                             : "  SOME TESTS FAILED");
  Serial.println("================================================");
  vTaskDelete(NULL);
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  // SLH-DSA needs < 5 KB of stack; the runner adds a few hundred bytes.
  xTaskCreatePinnedToCore(testTask, "acvp", 12 * 1024, NULL, 1, NULL, 1);
}

void loop() {
  delay(1000);
}
