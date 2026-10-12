/*
 * SLH-DSA Demo for ESP32
 *
 * Demonstrates stateless hash-based post-quantum signatures with SLH-DSA
 * (FIPS 205), using the plain slhdsa-c C API for the core steps and the C++
 * wrapper for the rest, and shows the properties of the scheme:
 *
 *   1. Sizes of all 12 parameter sets ("s" = small signature, "f" = fast)
 *   2. Key generation, signing (hedged), verification with timing
 *   3. Tampered signature / modified message / other context -> rejected
 *   4. Hedged vs deterministic signing
 *   5. HashSLH-DSA: signing a SHA2-256 pre-hash of the message
 *   6. Secret key validation (recomputing the public key)
 *
 * Copyright (c) 2026 The fips205-slhdsa-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <SLHDSA.h>

typedef SLHDSA_SHA2_128f DSA;

static uint8_t pk[DSA::PUBLIC_KEY_SIZE];
static uint8_t sk[DSA::SECRET_KEY_SIZE];
static uint8_t sig[DSA::SIGNATURE_SIZE];
static uint8_t sig2[DSA::SIGNATURE_SIZE];

static void printHex(const char *label, const uint8_t *data, size_t len) {
  Serial.printf("%s (%u bytes): ", label, (unsigned)len);
  for (size_t i = 0; i < len && i < 32; i++) {
    Serial.printf("%02X", data[i]);
  }
  if (len > 32) {
    Serial.print("... [truncated]");
  }
  Serial.println();
}

static void printMemInfo(const char *phase) {
  Serial.printf("[%s] Free heap: %u bytes, free stack: %u bytes\n", phase,
                (unsigned)ESP.getFreeHeap(),
                (unsigned)uxTaskGetStackHighWaterMark(NULL));
}

static const char *verdict(int ret) {
  return ret != 0 ? "correctly REJECTED" : "WARNING: accepted!";
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println();
  Serial.println("========================================");
  Serial.println("  SLH-DSA (FIPS 205) Demo for ESP32");
  Serial.println("========================================");

  // --- 1. Parameter sets ---
  Serial.println("\n--- The 12 SLH-DSA parameter sets ---");
  static const slh_param_t *const SETS[12] = {
      &slh_dsa_sha2_128s, &slh_dsa_shake_128s, &slh_dsa_sha2_128f, &slh_dsa_shake_128f,
      &slh_dsa_sha2_192s, &slh_dsa_shake_192s, &slh_dsa_sha2_192f, &slh_dsa_shake_192f,
      &slh_dsa_sha2_256s, &slh_dsa_shake_256s, &slh_dsa_sha2_256f, &slh_dsa_shake_256f};
  Serial.println("  Parameter set          PK    SK    Signature");
  for (const slh_param_t *p : SETS) {
    Serial.printf("  %-20s %4u  %4u  %6u bytes\n", slh_alg_id(p),
                  (unsigned)slh_pk_sz(p), (unsigned)slh_sk_sz(p),
                  (unsigned)slh_sig_sz(p));
  }
  Serial.printf("\nThis demo uses %s.\n", DSA::name());
  printMemInfo("Start");

  const char *message = "Hello, post-quantum world!";
  const uint8_t *m = (const uint8_t *)message;
  const size_t mlen = strlen(message);
  const uint8_t ctx[] = "firmware-v1";  // optional FIPS 205 context string
  const size_t ctxlen = sizeof(ctx) - 1;
  int ret;
  unsigned long start;
  size_t siglen;

  // --- 2. Key generation, signing, verification (C API) ---
  Serial.println("\n--- Key Generation ---");
  uint8_t seed[3 * 16];  // SK.seed || SK.prf || PK.seed
  slhdsa_esp32_randombytes(seed, sizeof(seed));
  start = millis();
  ret = slh_keygen_internal(sk, pk, seed, seed + 16, seed + 32, DSA::params());
  Serial.printf("Keypair generated in %lu ms (ret=%d)\n", millis() - start, ret);
  memset(seed, 0, sizeof(seed));
  printHex("Public Key", pk, sizeof(pk));

  Serial.println("\n--- Signing ---");
  Serial.printf("Message: \"%s\" (%u bytes), context: \"%s\"\n", message,
                (unsigned)mlen, (const char *)ctx);
  uint8_t addrnd[16];  // hedged signing: fresh randomness
  slhdsa_esp32_randombytes(addrnd, sizeof(addrnd));
  start = millis();
  siglen = slh_sign(sig, m, mlen, ctx, ctxlen, sk, addrnd, DSA::params());
  Serial.printf("Signed in %lu ms (signature: %u bytes)\n", millis() - start,
                (unsigned)siglen);
  printHex("Signature", sig, siglen);

  Serial.println("\n--- Verification ---");
  start = millis();
  ret = slh_verify(m, mlen, sig, siglen, ctx, ctxlen, pk, DSA::params());
  Serial.printf("Verification %s (%lu ms)\n", ret == 1 ? "SUCCESS" : "FAILED",
                millis() - start);
  printMemInfo("After sign/verify");

  // --- 3. Tamper tests (C++ wrapper: 0 = valid) ---
  Serial.println("\n--- Tamper Tests ---");
  sig[1000] ^= 0x01;
  Serial.printf("Tampered signature: %s\n",
                verdict(DSA::verify(sig, siglen, m, mlen, pk, ctx, ctxlen)));
  sig[1000] ^= 0x01;
  Serial.printf("Modified message:   %s\n",
                verdict(DSA::verify(sig, siglen, m, mlen - 1, pk, ctx, ctxlen)));
  Serial.printf("Other context:      %s\n",
                verdict(DSA::verify(sig, siglen, m, mlen, pk)));

  // --- 4. Hedged vs deterministic ---
  Serial.println("\n--- Hedged vs Deterministic Signing ---");
  ret = DSA::sign(sig2, &siglen, m, mlen, sk, ctx, ctxlen);
  Serial.printf("Hedged (default): two signatures of the same message %s\n",
                ret == 0 && memcmp(sig, sig2, siglen) != 0 ? "DIFFER (randomized)" : "match?!");
  ret = DSA::signDeterministic(sig, &siglen, m, mlen, sk, ctx, ctxlen) |
        DSA::signDeterministic(sig2, &siglen, m, mlen, sk, ctx, ctxlen);
  Serial.printf("Deterministic:      two signatures of the same message %s\n",
                ret == 0 && memcmp(sig, sig2, siglen) == 0 ? "MATCH" : "differ?!");

  // --- 5. HashSLH-DSA ---
  Serial.println("\n--- HashSLH-DSA (pre-hash SHA2-256) ---");
  start = millis();
  ret = DSA::signPreHash(sig, &siglen, m, mlen, sk, "SHA2-256", ctx, ctxlen);
  Serial.printf("Pre-hash signature: %s (%lu ms)\n", ret == 0 ? "OK" : "FAILED",
                millis() - start);
  ret = DSA::verifyPreHash(sig, siglen, m, mlen, pk, "SHA2-256", ctx, ctxlen);
  Serial.printf("Pre-hash verification: %s\n", ret == 0 ? "SUCCESS" : "FAILED");
  Serial.printf("Same signature as pure SLH-DSA: %s\n",
                verdict(DSA::verify(sig, siglen, m, mlen, pk, ctx, ctxlen)));

  // --- 6. Secret key validation ---
  Serial.println("\n--- Secret Key Validation ---");
  uint8_t pk2[DSA::PUBLIC_KEY_SIZE];
  ret = DSA::publicKeyFromSecretKey(pk2, sk);
  Serial.printf("Valid secret key: %s, public key %s\n", ret == 0 ? "OK" : "REJECTED",
                memcmp(pk, pk2, sizeof(pk)) == 0 ? "matches" : "DIFFERS");
  sk[5] ^= 0x01;  // corrupt SK.seed
  ret = DSA::publicKeyFromSecretKey(pk2, sk);
  Serial.printf("Corrupted secret key: %s\n",
                ret == SLHDSA_ERR_INVALID_KEY ? "correctly REJECTED" : "WARNING");

  // Zeroize sensitive material
  memset(sk, 0, sizeof(sk));

  Serial.println("\n========================================");
  printMemInfo("End");
  Serial.println("Demo complete.");
  Serial.println("========================================");
}

void loop() {
  delay(1000);
}
