/*
 * acvp_runner.h - runs the NIST ACVP SLH-DSA vectors of acvp_vectors.h
 *
 * Platform independent (used by the Arduino sketch and by host tests). The
 * includer must define, before including this file:
 *
 *   void acvp_sha256(const uint8_t *in, size_t len, uint8_t out[32]);
 *   void acvp_fail(const char *what, unsigned tcId);   // report a failure
 *   void acvp_progress(const char *what, unsigned tcId); // before each case
 *
 * Copyright (c) 2026 The fips205-slhdsa-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ACVP_RUNNER_H
#define ACVP_RUNNER_H

#include <string.h>
#include <SLHDSA.h>
#include "acvp_vectors.h"

namespace acvp {

/* Scratch buffers, sized for the largest parameter set. */
static uint8_t pk[slhdsa_esp32::MAX_PUBLIC_KEY_SIZE];
static uint8_t sk[slhdsa_esp32::MAX_SECRET_KEY_SIZE];
static uint8_t sig[slhdsa_esp32::MAX_SIGNATURE_SIZE];

struct Result {
  int pass = 0, fail = 0;
  void check(bool ok, const char *what, unsigned tcId) {
    if (ok) {
      pass++;
    } else {
      fail++;
      acvp_fail(what, tcId);
    }
  }
};

static bool sha256Matches(const uint8_t *data, size_t len,
                          const uint8_t *expect) {
  uint8_t digest[32];
  acvp_sha256(data, len, digest);
  return memcmp(digest, expect, 32) == 0;
}

/* keyGen: (SK.seed, SK.prf, PK.seed) -> (sk, pk) */
template <class D>
void keyGen(Result &r, const acvp_keygen_t &t) {
  int ret = D::generateKeypairFromSeed(pk, sk, t.seed);
  r.check(ret == 0 && t.sk_len == D::SECRET_KEY_SIZE &&
              memcmp(sk, t.sk, D::SECRET_KEY_SIZE) == 0 &&
              memcmp(pk, t.sk + 2 * D::N, D::PUBLIC_KEY_SIZE) == 0,
          "keyGen", t.tcId);
}

/* sigGen: (sk, message, ctx, addrnd) -> signature */
template <class D>
void sigGen(Result &r, const acvp_siggen_t &t) {
  slhdsa_esp32::HwSession hws(D::hardwareSha());
  int ret = -1;
  size_t len = 0;
  switch (t.mode) {
    case MODE_PURE:
      if (t.rnd == NULL) {  // deterministic variant: through the wrapper
        ret = D::signDeterministic(sig, &len, t.msg, t.msg_len, t.sk, t.ctx,
                                   t.ctx_len);
      } else {
        len = slh_sign(sig, t.msg, t.msg_len, t.ctx, t.ctx_len, t.sk, t.rnd,
                       D::params());
        ret = len == D::SIGNATURE_SIZE ? 0 : -1;
      }
      break;
    case MODE_PREHASH:
      if (t.rnd == NULL) {
        ret = D::signPreHash(sig, &len, t.msg, t.msg_len, t.sk, t.hashAlg,
                             t.ctx, t.ctx_len, true);
      } else {
        len = hash_slh_sign(sig, t.msg, t.msg_len, t.ctx, t.ctx_len, t.hashAlg,
                            t.sk, t.rnd, D::params());
        ret = len == D::SIGNATURE_SIZE ? 0 : -1;
      }
      break;
    case MODE_INTERNAL:
      len = slh_sign_internal(sig, t.msg, t.msg_len, t.sk, t.rnd, D::params());
      ret = len == D::SIGNATURE_SIZE ? 0 : -1;
      break;
  }
  r.check(ret == 0 && sha256Matches(sig, D::SIGNATURE_SIZE, t.sig_sha256),
          "sigGen", t.tcId);
}

/* sigVer: (pk, message, ctx, signature) -> valid / invalid */
template <class D>
void sigVer(Result &r, const acvp_sigver_t &t) {
  slhdsa_esp32::HwSession hws(D::hardwareSha());
  int ret = -1;
  switch (t.mode) {
    case MODE_PURE:
      ret = D::verify(t.sig, t.sig_len, t.msg, t.msg_len, t.pk, t.ctx, t.ctx_len);
      break;
    case MODE_PREHASH:
      ret = D::verifyPreHash(t.sig, t.sig_len, t.msg, t.msg_len, t.pk, t.hashAlg,
                             t.ctx, t.ctx_len);
      break;
    case MODE_INTERNAL:
      ret = slh_verify_internal(t.msg, t.msg_len, t.sig, t.sig_len, t.pk,
                                D::params()) == 1
                ? 0
                : -1;
      break;
  }
  r.check((ret == 0) == t.valid, "sigVer", t.tcId);
}

/* Randomized round trip with the hardware RNG, plus negative tests. */
template <class D>
void roundTrip(Result &r, unsigned id) {
  static const uint8_t text[] = "FIPS 205 round trip";
  static const uint8_t c1[] = "context-1";
  size_t len = 0;
  bool ok = D::generateKeypair(pk, sk) == 0 &&
            D::sign(sig, &len, text, sizeof text, sk, c1, sizeof c1) == 0 &&
            len == D::SIGNATURE_SIZE &&
            D::verify(sig, len, text, sizeof text, pk, c1, sizeof c1) == 0;
  r.check(ok, "round trip", id);
  r.check(D::verify(sig, len, text, sizeof text, pk) != 0, "ctx mismatch", id);
  r.check(D::verify(sig, len, text, sizeof text - 1, pk, c1, sizeof c1) != 0,
          "modified message", id);
  sig[len / 2] ^= 0x10;
  r.check(D::verify(sig, len, text, sizeof text, pk, c1, sizeof c1) != 0,
          "tampered signature", id);
  sig[len / 2] ^= 0x10;
  r.check(D::verify(sig, len - 1, text, sizeof text, pk, c1, sizeof c1) != 0,
          "short signature", id);
  /* validation of a correct and of a corrupted secret key */
  uint8_t pk2[slhdsa_esp32::MAX_PUBLIC_KEY_SIZE];
  r.check(D::publicKeyFromSecretKey(pk2, sk) == 0 &&
              memcmp(pk, pk2, D::PUBLIC_KEY_SIZE) == 0,
          "pk_from_sk", id);
  sk[0] ^= 1;  // SK.seed
  r.check(D::publicKeyFromSecretKey(pk2, sk) == SLHDSA_ERR_INVALID_KEY,
          "corrupted sk", id);
  sk[0] ^= 1;
  /* long contexts are rejected */
  static uint8_t longctx[256];
  r.check(D::sign(sig, &len, text, sizeof text, sk, longctx, 256) ==
                  SLHDSA_ERR_INVALID_ARG && len == 0,
          "long context", id);
  memset(sk, 0, sizeof sk);
}

/* Dispatch a parameter set index (see acvp_vectors.h) to its class. */
#define ACVP_DISPATCH(set, FN, ...)                                \
  switch (set) {                                                   \
    case 0:  FN<SLHDSA_SHA2_128s>(__VA_ARGS__); break;             \
    case 1:  FN<SLHDSA_SHAKE_128s>(__VA_ARGS__); break;            \
    case 2:  FN<SLHDSA_SHA2_128f>(__VA_ARGS__); break;             \
    case 3:  FN<SLHDSA_SHAKE_128f>(__VA_ARGS__); break;            \
    case 4:  FN<SLHDSA_SHA2_192s>(__VA_ARGS__); break;             \
    case 5:  FN<SLHDSA_SHAKE_192s>(__VA_ARGS__); break;            \
    case 6:  FN<SLHDSA_SHA2_192f>(__VA_ARGS__); break;             \
    case 7:  FN<SLHDSA_SHAKE_192f>(__VA_ARGS__); break;            \
    case 8:  FN<SLHDSA_SHA2_256s>(__VA_ARGS__); break;             \
    case 9:  FN<SLHDSA_SHAKE_256s>(__VA_ARGS__); break;            \
    case 10: FN<SLHDSA_SHA2_256f>(__VA_ARGS__); break;             \
    case 11: FN<SLHDSA_SHAKE_256f>(__VA_ARGS__); break;            \
  }

static const char *const SET_NAME[12] = {
    "SHA2-128s", "SHAKE-128s", "SHA2-128f", "SHAKE-128f",
    "SHA2-192s", "SHAKE-192s", "SHA2-192f", "SHAKE-192f",
    "SHA2-256s", "SHAKE-256s", "SHA2-256f", "SHAKE-256f"};

/* roundTripMask: bit i = run the randomized round trip for set i */
static void runAll(Result &r, unsigned roundTripMask) {
  for (size_t i = 0; i < acvp_keygen_count; i++) {
    acvp_progress("keyGen", acvp_keygen[i].tcId);
    ACVP_DISPATCH(acvp_keygen[i].set, keyGen, r, acvp_keygen[i])
  }
  for (size_t i = 0; i < acvp_siggen_count; i++) {
    acvp_progress("sigGen", acvp_siggen[i].tcId);
    ACVP_DISPATCH(acvp_siggen[i].set, sigGen, r, acvp_siggen[i])
  }
  for (size_t i = 0; i < acvp_sigver_count; i++) {
    acvp_progress("sigVer", acvp_sigver[i].tcId);
    ACVP_DISPATCH(acvp_sigver[i].set, sigVer, r, acvp_sigver[i])
  }
  for (unsigned s = 0; s < 12; s++) {
    if (roundTripMask & (1u << s)) {
      acvp_progress(SET_NAME[s], s);
      ACVP_DISPATCH(s, roundTrip, r, s)
    }
  }
}

} /* namespace acvp */

#endif /* ACVP_RUNNER_H */
