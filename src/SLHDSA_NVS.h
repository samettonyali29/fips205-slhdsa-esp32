/*
 * SLHDSA_NVS.h - NVS (Non-Volatile Storage) helper for SLH-DSA keypairs
 *
 * Persists SLH-DSA keypairs in the ESP32 NVS flash partition so they
 * survive reboots and power cycles:
 *
 *   SLHDSA_NVS<SLHDSA_SHA2_128f>::generateAndSave("slhdsa", pk, sk);
 *   SLHDSA_NVS<SLHDSA_SHA2_128f>::loadKeypair("slhdsa", pk, sk);
 *
 * An SLH-DSA secret key is small (64/96/128 bytes) and already contains the
 * public key (SK = SK.seed || SK.prf || PK.seed || PK.root), so only the
 * secret key is stored, together with the parameter set name: a key saved
 * for one parameter set is never loaded for another.
 *
 * NVS checksums every entry (CRC32), so accidental flash corruption is
 * detected on read. loadKeypair(..., validate = true) additionally
 * recomputes PK.root from the seeds (one key generation: 0.1-2 s for the
 * "f" sets, 7-49 s for the "s" sets on an ESP32 @ 240 MHz).
 *
 * NVS stores data unencrypted unless flash/NVS encryption is enabled on
 * the chip. Treat NVS contents as readable by anyone with physical access.
 *
 * Requires: ESP32 Arduino core (Preferences library, included by default).
 *
 * Copyright (c) 2026 The fips205-slhdsa-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SLHDSA_NVS_H
#define SLHDSA_NVS_H

#include <Preferences.h>
#include <stdint.h>
#include <string.h>
#include "SLHDSA.h"

template <class D>
class SLHDSA_NVS {
public:
  /*
   * Save a keypair. ns: NVS namespace (max 15 chars).
   * pk must belong to sk (it is part of sk). Returns true on success.
   */
  static bool saveKeypair(const char *ns, const uint8_t *pk, const uint8_t *sk) {
    if (memcmp(pk, sk + 2 * D::N, D::PUBLIC_KEY_SIZE) != 0) {
      return false;
    }
    Preferences prefs;
    if (!prefs.begin(ns, false)) {
      return false;
    }
    prefs.remove("sk");
    bool ok = prefs.putString("set", D::name()) > 0 &&
              prefs.putBytes("sk", sk, D::SECRET_KEY_SIZE) == D::SECRET_KEY_SIZE;
    prefs.end();
    return ok;
  }

  /*
   * Load a keypair of this parameter set. With validate = true the secret
   * key is also checked by recomputing the public key (see above).
   * On failure, sk is zeroized and false is returned.
   */
  static bool loadKeypair(const char *ns, uint8_t *pk, uint8_t *sk,
                          bool validate = false) {
    Preferences prefs;
    if (!prefs.begin(ns, true)) {
      return false;
    }
    bool ok = prefs.getString("set", "") == D::name() &&
              prefs.getBytes("sk", sk, D::SECRET_KEY_SIZE) == D::SECRET_KEY_SIZE;
    prefs.end();
    if (ok) {
      memcpy(pk, sk + 2 * D::N, D::PUBLIC_KEY_SIZE);
      if (validate) {
        ok = D::publicKeyFromSecretKey(pk, sk) == 0;
      }
    }
    if (!ok) {
      slhdsa_esp32::wipe(sk, D::SECRET_KEY_SIZE);
    }
    return ok;
  }

  /* Load only the public key (taken from the stored secret key). */
  static bool loadPublicKey(const char *ns, uint8_t *pk) {
    uint8_t sk[D::SECRET_KEY_SIZE];
    bool ok = loadKeypair(ns, pk, sk, false);
    slhdsa_esp32::wipe(sk, sizeof(sk));
    return ok;
  }

  /* True if a keypair of this parameter set is stored. */
  static bool hasKeypair(const char *ns) {
    Preferences prefs;
    if (!prefs.begin(ns, true)) {
      return false;
    }
    bool has = prefs.getString("set", "") == D::name() &&
               prefs.getBytesLength("sk") == D::SECRET_KEY_SIZE;
    prefs.end();
    return has;
  }

  /* Remove the key material from the namespace. */
  static bool eraseKeypair(const char *ns) {
    Preferences prefs;
    if (!prefs.begin(ns, false)) {
      return false;
    }
    prefs.remove("sk");
    prefs.remove("set");
    prefs.end();
    return true;
  }

  /*
   * Generate a new keypair and save it.
   * Returns 0 on success, negative on keygen error, 1 on NVS save error.
   */
  static int generateAndSave(const char *ns, uint8_t *pk, uint8_t *sk) {
    int ret = D::generateKeypair(pk, sk);
    if (ret != 0) {
      return ret;
    }
    return saveKeypair(ns, pk, sk) ? 0 : 1;
  }
};

#endif /* SLHDSA_NVS_H */
