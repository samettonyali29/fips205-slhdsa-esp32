/*
 * SLH-DSA: SHA hardware accelerator vs. software
 *
 * Compares the software SHA-2 parameter sets (slh_dsa_sha2_*) with the
 * hardware-backed ones (slh_dsa_sha2_*_hw), using the C API so both can be
 * used in one sketch:
 *
 *   1. runs the hardware self-test (slhdsa_esp32_hw_sha_active)
 *   2. for each selected SHA2 parameter set, with random seeds and messages:
 *      - KeyGen from the same seed must give identical keys
 *      - deterministic and hedged signing (same randomness) must give
 *        byte-identical signatures
 *      - each signature must verify with the other implementation, and a
 *        tampered signature must be rejected by both
 *      and reports the timings and the speed-up.
 *
 * To use the hardware in your own sketches through the C++ wrapper
 * (SLHDSA_SHA2_128f etc.), enable SLHDSA_ESP32_HW_SHA, see
 * src/slhdsa_esp32_config.h. This example does not need it.
 *
 * Build flags: -DHW_SETS=mask (bit 0..5 = SHA2-128f, 192f, 256f, 128s, 192s,
 * 256s; default 0x0F: the three "f" sets and SHA2-128s), -DHW_ROUNDS=n
 * (random rounds per "f" set, default 3).
 *
 * Copyright (c) 2026 The fips205-slhdsa-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <SLHDSA.h>
#include <esp_timer.h>

#ifndef HW_SETS
#define HW_SETS 0x0F
#endif
#ifndef HW_ROUNDS
#define HW_ROUNDS 3
#endif

struct Pair {
  const char *name;
  const slh_param_t *sw, *hw;  // sw: slhdsa-c set (made cooperative below)
};
static const Pair PAIRS[6] = {
    {"SLH-DSA-SHA2-128f", &slh_dsa_sha2_128f, &slh_dsa_sha2_128f_hw},
    {"SLH-DSA-SHA2-192f", &slh_dsa_sha2_192f, &slh_dsa_sha2_192f_hw},
    {"SLH-DSA-SHA2-256f", &slh_dsa_sha2_256f, &slh_dsa_sha2_256f_hw},
    {"SLH-DSA-SHA2-128s", &slh_dsa_sha2_128s, &slh_dsa_sha2_128s_hw},
    {"SLH-DSA-SHA2-192s", &slh_dsa_sha2_192s, &slh_dsa_sha2_192s_hw},
    {"SLH-DSA-SHA2-256s", &slh_dsa_sha2_256s, &slh_dsa_sha2_256s_hw}};

static uint8_t pkS[64], skS[128], pkH[64], skH[128];
static uint8_t sigS[slhdsa_esp32::MAX_SIGNATURE_SIZE];
static uint8_t sigH[slhdsa_esp32::MAX_SIGNATURE_SIZE];
static int errors = 0;

static void check(bool ok, const char *what) {
  if (!ok) {
    errors++;
    Serial.printf("    [FAIL] %s\n", what);
  }
}

/* Runs fn (in a hardware session if hw), returns ms. */
template <class F>
double timed(bool hw, F fn) {
  slhdsa_esp32::HwSession hws(hw);
  int64_t t0 = esp_timer_get_time();
  fn();
  return (esp_timer_get_time() - t0) / 1000.0;
}

static void comparePair(const Pair &pr, int rounds) {
  /* cooperative copy of the software set: same results, but it lets the
   * idle task run during long operations (task watchdog) */
  const Pair p = {pr.name, slhdsa_esp32_coop(pr.sw), pr.hw};
  const size_t n = slh_pk_sz(p.sw) / 2, siglen = slh_sig_sz(p.sw);
  double kg[2] = {0, 0}, sg[2] = {0, 0}, vf[2] = {0, 0};
  Serial.printf("\n--- %s (%d round%s) ---\n", p.name, rounds, rounds > 1 ? "s" : "");
  for (int r = 0; r < rounds; r++) {
    uint8_t seed[96], addrnd[32], msg[100], ctx[20];
    esp_fill_random(seed, sizeof seed);
    esp_fill_random(addrnd, sizeof addrnd);
    esp_fill_random(msg, sizeof msg);
    esp_fill_random(ctx, sizeof ctx);
    const size_t mlen = 1 + esp_random() % sizeof msg, clen = esp_random() % sizeof ctx;

    // KeyGen from the same seed
    kg[0] += timed(false, [&] { slh_keygen_internal(skS, pkS, seed, seed + n, seed + 2 * n, p.sw); });
    kg[1] += timed(true, [&] { slh_keygen_internal(skH, pkH, seed, seed + n, seed + 2 * n, p.hw); });
    check(memcmp(skS, skH, 4 * n) == 0 && memcmp(pkS, pkH, 2 * n) == 0, "keys differ");

    // Signing: deterministic in the first round, hedged (same addrnd) after
    const uint8_t *rnd = r == 0 ? NULL : addrnd;
    size_t lS = 0, lH = 0;
    sg[0] += timed(false, [&] { lS = slh_sign(sigS, msg, mlen, ctx, clen, skS, rnd, p.sw); });
    sg[1] += timed(true, [&] { lH = slh_sign(sigH, msg, mlen, ctx, clen, skH, rnd, p.hw); });
    check(lS == siglen && lH == siglen && memcmp(sigS, sigH, siglen) == 0,
          "signatures differ");

    // Cross verification + tamper test
    int vS = 0, vH = 0;
    vf[0] += timed(false, [&] { vS = slh_verify(msg, mlen, sigH, siglen, ctx, clen, pkS, p.sw); });
    vf[1] += timed(true, [&] { vH = slh_verify(msg, mlen, sigS, siglen, ctx, clen, pkH, p.hw); });
    check(vS == 1 && vH == 1, "cross verification failed");
    sigH[siglen / 3] ^= 0x04;
    int tS = slh_verify(msg, mlen, sigH, siglen, ctx, clen, pkS, p.sw), tH = 1;
    timed(true, [&] { tH = slh_verify(msg, mlen, sigH, siglen, ctx, clen, pkH, p.hw); });
    check(tS == 0 && tH == 0, "tampered signature accepted");
  }
  memset(skS, 0, sizeof skS);
  memset(skH, 0, sizeof skH);
  Serial.println("               software     hardware   speed-up");
  const char *ops[3] = {"KeyGen", "Sign", "Verify"};
  double *t[3] = {kg, sg, vf};
  for (int i = 0; i < 3; i++) {
    Serial.printf("  %-8s %10.1f ms %10.1f ms     %4.2fx\n", ops[i], t[i][0] / rounds,
                  t[i][1] / rounds, t[i][0] / t[i][1]);
    Serial.printf("CSV,%s,%s,%.1f,%.1f\n", p.name, ops[i], t[i][0] / rounds, t[i][1] / rounds);
  }
}

static void testTask(void *) {
  Serial.println();
  Serial.println("================================================");
  Serial.println("  SLH-DSA: SHA hardware accelerator vs software");
  Serial.println("================================================");
  int64_t t0 = esp_timer_get_time();
  int active = slhdsa_esp32_hw_sha_active();
  Serial.printf("Hardware self-test: %s (%.1f ms)\n",
                active ? "PASSED, hardware SHA in use" : "FAILED / not supported, software fallback",
                (esp_timer_get_time() - t0) / 1000.0);
  Serial.printf("SLHDSA_ESP32_HW_SHA (wrapper classes use hardware): %s\n",
#if defined(SLHDSA_ESP32_HW_SHA)
                "enabled"
#else
                "disabled"
#endif
  );

  for (int i = 0; i < 6; i++) {
    if (HW_SETS & (1 << i)) comparePair(PAIRS[i], i < 3 ? HW_ROUNDS : 1);
  }

  Serial.println();
  Serial.printf("Result: %s (%d errors)\n", errors ? "MISMATCH" : "hardware == software", errors);
  Serial.println("HW comparison complete.");
  vTaskDelete(NULL);
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  xTaskCreatePinnedToCore(testTask, "hwsha", 12 * 1024, NULL, 1, NULL, 1);
}

void loop() {
  delay(1000);
}
