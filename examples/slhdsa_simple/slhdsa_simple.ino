/*
 * Simple SLH-DSA example using the SLHDSA_SHA2_128f C++ wrapper.
 *
 * Generates a keypair, signs a message and verifies the signature.
 *
 * SLH-DSA-SHA2-128f is the fastest parameter set on the ESP32 (about 0.1 s
 * key generation, 2.6 s signing, 0.15 s verification). Its signature is
 * 17 KB, so the buffers are static, not on the 8 KB loop() stack. The
 * library itself needs less than 5 KB of stack, so no dedicated FreeRTOS task
 * is required.
 *
 * Copyright (c) 2026 The fips205-slhdsa-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <SLHDSA.h>

typedef SLHDSA_SHA2_128f DSA;  // try any of the 12 parameter sets

static uint8_t pk[DSA::PUBLIC_KEY_SIZE];
static uint8_t sk[DSA::SECRET_KEY_SIZE];
static uint8_t sig[DSA::SIGNATURE_SIZE];

void setup() {
  Serial.begin(115200);
  delay(1000);

  // Generate keypair
  if (DSA::generateKeypair(pk, sk) != 0) {
    Serial.println("Keygen failed!");
    return;
  }
  Serial.printf("%s keypair generated.\n", DSA::name());

  // Sign a message
  const char *msg = "Hello, post-quantum world!";
  size_t siglen;
  unsigned long start = millis();
  if (DSA::sign(sig, &siglen, (const uint8_t *)msg, strlen(msg), sk) != 0) {
    Serial.println("Signing failed!");
    return;
  }
  Serial.printf("Signed (%u bytes) in %lu ms\n", (unsigned)siglen, millis() - start);

  // Verify
  if (DSA::verify(sig, siglen, (const uint8_t *)msg, strlen(msg), pk) == 0) {
    Serial.println("Verification OK!");
  } else {
    Serial.println("Verification FAILED!");
  }

  // Clean up secret key
  memset(sk, 0, sizeof(sk));
}

void loop() {
  delay(1000);
}
