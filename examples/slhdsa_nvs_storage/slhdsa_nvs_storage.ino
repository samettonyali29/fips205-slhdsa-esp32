/*
 * SLH-DSA NVS Persistent Key Storage Example
 *
 * Demonstrates storing an SLH-DSA-SHA2-128f keypair in the ESP32's
 * Non-Volatile Storage (NVS) so the device keeps a stable signing identity
 * across reboots.
 *
 * First boot:  Generates a new keypair and stores it in NVS flash.
 * Next boots:  Loads the existing keypair from NVS and validates it.
 *
 * Only the 64-byte secret key is stored (it contains the public key).
 * The example then signs and verifies a message to prove the loaded keys
 * work. Send 'e' over the serial monitor to erase the key and reboot.
 *
 * Copyright (c) 2026 The fips205-slhdsa-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <SLHDSA.h>
#include <SLHDSA_NVS.h>

typedef SLHDSA_SHA2_128f DSA;
typedef SLHDSA_NVS<DSA> Store;

static const char *NVS_NAMESPACE = "slhdsa";

static uint8_t pk[DSA::PUBLIC_KEY_SIZE];
static uint8_t sk[DSA::SECRET_KEY_SIZE];
static uint8_t sig[DSA::SIGNATURE_SIZE];

static void printHex(const char *label, const uint8_t *data, size_t len) {
  Serial.printf("%s (%u bytes): ", label, (unsigned)len);
  for (size_t i = 0; i < len && i < 16; i++) Serial.printf("%02X", data[i]);
  if (len > 16) Serial.print("...");
  Serial.println();
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println();
  Serial.printf("=== %s NVS Key Storage Demo ===\n\n", DSA::name());

  if (Store::hasKeypair(NVS_NAMESPACE)) {
    Serial.println("Found existing keypair in NVS, loading and validating...");
    unsigned long start = millis();
    if (!Store::loadKeypair(NVS_NAMESPACE, pk, sk, /*validate=*/true)) {
      Serial.println("ERROR: Failed to load keypair (missing or corrupted)!");
      return;
    }
    Serial.printf("Keypair loaded and validated in %lu ms\n", millis() - start);
  } else {
    Serial.println("No keypair in NVS. Generating a new one...");
    unsigned long start = millis();
    int ret = Store::generateAndSave(NVS_NAMESPACE, pk, sk);
    if (ret != 0) {
      Serial.printf("ERROR: generateAndSave failed (code %d)\n", ret);
      return;
    }
    Serial.printf("Keypair generated and saved to NVS in %lu ms\n", millis() - start);
  }

  // The public key is the device's stable identity; it survives reboots.
  printHex("Public Key", pk, sizeof(pk));

  // Sign a test message to verify the keys work
  const char *msg = "NVS stored key test";
  size_t siglen;
  Serial.printf("\nSigning: \"%s\"\n", msg);
  if (DSA::sign(sig, &siglen, (const uint8_t *)msg, strlen(msg), sk) != 0) {
    Serial.println("ERROR: Signing failed!");
  } else if (DSA::verify(sig, siglen, (const uint8_t *)msg, strlen(msg), pk) == 0) {
    Serial.println("Verification OK -- stored keys work correctly!");
  } else {
    Serial.println("ERROR: Verification failed!");
  }

  memset(sk, 0, sizeof(sk));

  Serial.println("\nReboot the board: the same public key will be loaded.");
  Serial.println("Send 'e' to erase the stored keypair and reboot.");
}

void loop() {
  if (Serial.available() && Serial.read() == 'e') {
    Store::eraseKeypair(NVS_NAMESPACE);
    Serial.println("Keypair erased. Rebooting...");
    delay(100);
    ESP.restart();
  }
  delay(50);
}
