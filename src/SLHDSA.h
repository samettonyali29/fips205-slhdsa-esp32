/*
 * SLHDSA.h - Arduino-friendly C++ wrapper for SLH-DSA (FIPS 205)
 *
 * Usage:
 *   #include <SLHDSA.h>
 *
 *   static uint8_t pk[SLHDSA_SHA2_128f::PUBLIC_KEY_SIZE];
 *   static uint8_t sk[SLHDSA_SHA2_128f::SECRET_KEY_SIZE];
 *   static uint8_t sig[SLHDSA_SHA2_128f::SIGNATURE_SIZE];   // 17 KB!
 *   size_t siglen;
 *
 *   SLHDSA_SHA2_128f::generateKeypair(pk, sk);
 *   SLHDSA_SHA2_128f::sign(sig, &siglen, msg, msglen, sk);
 *   SLHDSA_SHA2_128f::verify(sig, siglen, msg, msglen, pk);   // 0 == valid
 *
 * All 12 FIPS 205 parameter sets are available and share the same API:
 *
 *   SLHDSA_SHA2_128s  SLHDSA_SHAKE_128s  SLHDSA_SHA2_128f  SLHDSA_SHAKE_128f
 *   SLHDSA_SHA2_192s  SLHDSA_SHAKE_192s  SLHDSA_SHA2_192f  SLHDSA_SHAKE_192f
 *   SLHDSA_SHA2_256s  SLHDSA_SHAKE_256s  SLHDSA_SHA2_256f  SLHDSA_SHAKE_256f
 *
 * "s" sets have small signatures but slow signing, "f" sets sign fast but
 * produce larger signatures. All functions return 0 on success and a
 * negative SLHDSA_ERR_* code on failure.
 *
 * Copyright (c) 2026 The fips205-slhdsa-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SLHDSA_WRAPPER_H
#define SLHDSA_WRAPPER_H

#include <stddef.h>
#include <stdint.h>
#include <stdint.h>
#include <string.h>
#include "slhdsa_esp32.h"

/* Stack bytes overwritten after each secret-key operation (see
 * slhdsa_esp32_stack_wipe): the measured peak stack use of slhdsa-c on the
 * ESP32 (5024 bytes, SLH-DSA-SHA2-256f verify) plus a margin. Never exceeds
 * the free stack of the task. Note that the wipe itself shows up in
 * uxTaskGetStackHighWaterMark(). */
#ifndef SLHDSA_ESP32_WIPE_BYTES
#define SLHDSA_ESP32_WIPE_BYTES 5376
#endif

namespace slhdsa_esp32 {

/* The hardware-backed variant of a SHA2 parameter set, if the SHA hardware
 * backend is enabled (SLHDSA_ESP32_HW_SHA); otherwise the software set, so
 * that the hardware code is not linked in at all. */
#if defined(SLHDSA_ESP32_HW_SHA)
#define SLHDSA_ESP32_HW(sym) &sym##_hw
#else
#define SLHDSA_ESP32_HW(sym) &sym
#endif

/* Parameter set descriptions (FIPS 205, Table 2). Not meant to be used
 * directly; use the SLHDSA_* typedefs below. */
#define SLHDSA_ESP32_PARAMS(NAME, SW, HW, N, SIG, CAT, FAST, SHAKE, ID)       \
  struct NAME {                                                               \
    static constexpr size_t n = N;                                            \
    static constexpr size_t sig = SIG;                                        \
    static constexpr unsigned category = CAT;                                 \
    static constexpr bool fast = FAST;                                        \
    static constexpr bool shake = SHAKE;                                      \
    static const slh_param_t *sw() { return &SW; }                            \
    static const slh_param_t *hw() { return HW; }                             \
    static const char *name() { return ID; }                                  \
  };

SLHDSA_ESP32_PARAMS(SHA2_128s,  slh_dsa_sha2_128s,  SLHDSA_ESP32_HW(slh_dsa_sha2_128s), 16,  7856, 1, false, false, "SLH-DSA-SHA2-128s")
SLHDSA_ESP32_PARAMS(SHAKE_128s, slh_dsa_shake_128s, &slh_dsa_shake_128s,                16,  7856, 1, false, true,  "SLH-DSA-SHAKE-128s")
SLHDSA_ESP32_PARAMS(SHA2_128f,  slh_dsa_sha2_128f,  SLHDSA_ESP32_HW(slh_dsa_sha2_128f), 16, 17088, 1, true,  false, "SLH-DSA-SHA2-128f")
SLHDSA_ESP32_PARAMS(SHAKE_128f, slh_dsa_shake_128f, &slh_dsa_shake_128f,                16, 17088, 1, true,  true,  "SLH-DSA-SHAKE-128f")
SLHDSA_ESP32_PARAMS(SHA2_192s,  slh_dsa_sha2_192s,  SLHDSA_ESP32_HW(slh_dsa_sha2_192s), 24, 16224, 3, false, false, "SLH-DSA-SHA2-192s")
SLHDSA_ESP32_PARAMS(SHAKE_192s, slh_dsa_shake_192s, &slh_dsa_shake_192s,                24, 16224, 3, false, true,  "SLH-DSA-SHAKE-192s")
SLHDSA_ESP32_PARAMS(SHA2_192f,  slh_dsa_sha2_192f,  SLHDSA_ESP32_HW(slh_dsa_sha2_192f), 24, 35664, 3, true,  false, "SLH-DSA-SHA2-192f")
SLHDSA_ESP32_PARAMS(SHAKE_192f, slh_dsa_shake_192f, &slh_dsa_shake_192f,                24, 35664, 3, true,  true,  "SLH-DSA-SHAKE-192f")
SLHDSA_ESP32_PARAMS(SHA2_256s,  slh_dsa_sha2_256s,  SLHDSA_ESP32_HW(slh_dsa_sha2_256s), 32, 29792, 5, false, false, "SLH-DSA-SHA2-256s")
SLHDSA_ESP32_PARAMS(SHAKE_256s, slh_dsa_shake_256s, &slh_dsa_shake_256s,                32, 29792, 5, false, true,  "SLH-DSA-SHAKE-256s")
SLHDSA_ESP32_PARAMS(SHA2_256f,  slh_dsa_sha2_256f,  SLHDSA_ESP32_HW(slh_dsa_sha2_256f), 32, 49856, 5, true,  false, "SLH-DSA-SHA2-256f")
SLHDSA_ESP32_PARAMS(SHAKE_256f, slh_dsa_shake_256f, &slh_dsa_shake_256f,                32, 49856, 5, true,  true,  "SLH-DSA-SHAKE-256f")
#undef SLHDSA_ESP32_PARAMS

/* Parameter set actually used: the hardware-backed one if it exists (SHA2
 * set, backend enabled) and passed its self-test, otherwise the cooperative
 * copy of the software set (see slhdsa_esp32_coop: keeps the task watchdog
 * happy during long operations). */
static inline bool useHw(const slh_param_t *sw, const slh_param_t *hw) {
#if defined(SLHDSA_ESP32_HW_SHA)
  return hw != sw && slhdsa_esp32_hw_sha_active();
#else
  (void)sw;
  (void)hw;
  return false;
#endif
}

static inline const slh_param_t *pick(const slh_param_t *sw,
                                      const slh_param_t *hw) {
  return useHw(sw, hw) ? hw : slhdsa_esp32_coop(sw);
}

/* Holds the SHA hardware for the lifetime of the object (if in use). */
struct HwSession {
  bool on;
  explicit HwSession(bool use) : on(use) {
    if (on) slhdsa_esp32_hw_begin();
  }
  ~HwSession() {
    if (on) slhdsa_esp32_hw_end();
  }
};

/* Largest sizes over all parameter sets, e.g. for shared buffers. */
static constexpr size_t MAX_PUBLIC_KEY_SIZE = 64;
static constexpr size_t MAX_SECRET_KEY_SIZE = 128;
static constexpr size_t MAX_SIGNATURE_SIZE = 49856;

/* slhdsa-c passes (pointer, length) pairs to memcpy; memcpy(dst, NULL, 0)
 * is undefined behaviour in C. Empty inputs are therefore always passed as
 * a valid pointer. Returns false for (NULL, len > 0). */
static inline bool nonNull(const uint8_t *&p, size_t len) {
  static const uint8_t empty[1] = {0};
  if (p == nullptr) {
    if (len != 0) {
      return false;
    }
    p = empty;
  }
  return true;
}


static inline void wipe(void *p, size_t len) {
  volatile uint8_t *v = (volatile uint8_t *)p;
  while (len--) {
    *v++ = 0;
  }
}

} /* namespace slhdsa_esp32 */

template <class P>
class SLHDSA {
public:
  /* Parameter set name, e.g. "SLH-DSA-SHA2-128f" */
  static const char *name() { return P::name(); }
  /* Underlying slhdsa-c parameter set (for the C API): the hardware-backed
   * variant if the SHA hardware backend is enabled and active. */
  static const slh_param_t *params() { return slhdsa_esp32::pick(P::sw(), P::hw()); }

  /* true if this parameter set computes its hashes on the SHA hardware */
  static bool hardwareSha() { return slhdsa_esp32::useHw(P::sw(), P::hw()); }

  /* NIST security category: 1 (~AES-128), 3 (~AES-192) or 5 (~AES-256) */
  static constexpr unsigned SECURITY_CATEGORY = P::category;
  /* true for the "f" (fast signing) sets, false for "s" (small signature) */
  static constexpr bool FAST = P::fast;
  /* true for SHAKE-based sets, false for SHA2-based sets */
  static constexpr bool SHAKE = P::shake;

  static constexpr size_t N               = P::n;      /* 16, 24 or 32 */
  static constexpr size_t PUBLIC_KEY_SIZE = 2 * P::n;  /* PK.seed || PK.root */
  static constexpr size_t SECRET_KEY_SIZE = 4 * P::n;  /* SK.seed || SK.prf || PK */
  static constexpr size_t SIGNATURE_SIZE  = P::sig;
  static constexpr size_t SEED_SIZE       = 3 * P::n;  /* SK.seed || SK.prf || PK.seed */
  static constexpr size_t MAX_CONTEXT_SIZE = 255;

  /*
   * Generate a new keypair using the ESP32 hardware RNG.
   * Note: this computes the top Merkle tree; it takes seconds for the "s"
   * parameter sets.
   *
   * Returns 0 on success, negative on error.
   */
  static int generateKeypair(uint8_t *pk, uint8_t *sk) {
    uint8_t seed[SEED_SIZE];
    int ret = SLHDSA_ERR_RNG_FAIL;
    if (slhdsa_esp32_randombytes(seed, sizeof(seed)) == 0) {
      ret = generateKeypairFromSeed(pk, sk, seed);
    }
    slhdsa_esp32::wipe(seed, sizeof(seed));
    return ret;
  }

  /*
   * Deterministically derive a keypair from a 3n-byte seed
   * SK.seed || SK.prf || PK.seed (FIPS 205, slh_keygen_internal).
   *
   * Returns 0 on success, negative on error.
   */
  static int generateKeypairFromSeed(uint8_t *pk, uint8_t *sk,
                                     const uint8_t *seed) {
    int ret;
    {
      slhdsa_esp32::HwSession hws(hardwareSha());
      ret = slh_keygen_internal(sk, pk, seed, seed + N, seed + 2 * N,
                                params()) == 0
                ? 0
                : SLHDSA_ERR_FAIL;
    }
    slhdsa_esp32_stack_wipe(SLHDSA_ESP32_WIPE_BYTES);
    return ret;
  }

  /*
   * Sign a message (FIPS 205 slh_sign, hedged: n fresh random bytes from
   * the hardware RNG are mixed in).
   *
   * sig:    output buffer of SIGNATURE_SIZE bytes (7.8-49.9 KB: use a static
   *         or heap buffer, not the stack)
   * siglen: output, set to SIGNATURE_SIZE on success (may be nullptr)
   * ctx:    optional context string (nullptr if ctxlen == 0), max 255 bytes
   *
   * Returns 0 on success, negative on error.
   */
  static int sign(uint8_t *sig, size_t *siglen, const uint8_t *msg,
                  size_t msglen, const uint8_t *sk,
                  const uint8_t *ctx = nullptr, size_t ctxlen = 0) {
    uint8_t addrnd[N];
    int ret = SLHDSA_ERR_RNG_FAIL;
    if (slhdsa_esp32_randombytes(addrnd, sizeof(addrnd)) == 0) {
      ret = signWith(sig, siglen, msg, msglen, sk, ctx, ctxlen, addrnd);
    } else if (siglen != nullptr) {
      *siglen = 0;
    }
    slhdsa_esp32::wipe(addrnd, sizeof(addrnd));
    return ret;
  }

  /*
   * Deterministic signing (FIPS 205 "deterministic variant": the randomizer
   * is derived from the key only). The same (sk, message, context) always
   * gives the same signature.
   */
  static int signDeterministic(uint8_t *sig, size_t *siglen,
                               const uint8_t *msg, size_t msglen,
                               const uint8_t *sk, const uint8_t *ctx = nullptr,
                               size_t ctxlen = 0) {
    return signWith(sig, siglen, msg, msglen, sk, ctx, ctxlen, nullptr);
  }

  /*
   * Verify a signature (FIPS 205 slh_verify).
   *
   * Returns 0 if the signature is valid, SLHDSA_ERR_INVALID_SIGNATURE
   * otherwise (also if siglen != SIGNATURE_SIZE), SLHDSA_ERR_INVALID_ARG if
   * the context is longer than 255 bytes.
   */
  static int verify(const uint8_t *sig, size_t siglen, const uint8_t *msg,
                    size_t msglen, const uint8_t *pk,
                    const uint8_t *ctx = nullptr, size_t ctxlen = 0) {
    if (ctxlen > MAX_CONTEXT_SIZE || !slhdsa_esp32::nonNull(ctx, ctxlen) ||
        !slhdsa_esp32::nonNull(msg, msglen)) {
      return SLHDSA_ERR_INVALID_ARG;
    }
    if (siglen != SIGNATURE_SIZE) {
      return SLHDSA_ERR_INVALID_SIGNATURE;
    }
    slhdsa_esp32::HwSession hws(hardwareSha());
    return slh_verify(msg, msglen, sig, siglen, ctx, ctxlen, pk, params()) == 1
               ? 0
               : SLHDSA_ERR_INVALID_SIGNATURE;
  }

  /*
   * HashSLH-DSA (FIPS 205 Section 10.2): sign / verify a pre-hashed message.
   * The message is hashed inside with the named hash function: "SHA2-224",
   * "SHA2-256", "SHA2-384", "SHA2-512", "SHA2-512/224", "SHA2-512/256",
   * "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE-128", "SHAKE-256".
   * Signing is hedged; pass deterministic = true for the deterministic
   * variant. An unknown hash name makes signing fail (SLHDSA_ERR_FAIL) and
   * verification return SLHDSA_ERR_INVALID_SIGNATURE.
   */
  static int signPreHash(uint8_t *sig, size_t *siglen, const uint8_t *msg,
                         size_t msglen, const uint8_t *sk, const char *hashAlg,
                         const uint8_t *ctx = nullptr, size_t ctxlen = 0,
                         bool deterministic = false) {
    uint8_t addrnd[N];
    int ret = SLHDSA_ERR_RNG_FAIL;
    if (ctxlen > MAX_CONTEXT_SIZE || !slhdsa_esp32::nonNull(ctx, ctxlen) ||
        !slhdsa_esp32::nonNull(msg, msglen)) {
      ret = finishSign(sig, 0, siglen, SIZE_MAX);
    } else if (deterministic ||
               slhdsa_esp32_randombytes(addrnd, sizeof(addrnd)) == 0) {
      size_t len;
      {
        slhdsa_esp32::HwSession hws(hardwareSha());
        len = hash_slh_sign(sig, msg, msglen, ctx, ctxlen, hashAlg, sk,
                            deterministic ? nullptr : addrnd, params());
      }
      slhdsa_esp32_stack_wipe(SLHDSA_ESP32_WIPE_BYTES);
      ret = finishSign(sig, len, siglen, ctxlen);
    } else if (siglen != nullptr) {
      *siglen = 0;
    }
    slhdsa_esp32::wipe(addrnd, sizeof(addrnd));
    return ret;
  }

  static int verifyPreHash(const uint8_t *sig, size_t siglen,
                           const uint8_t *msg, size_t msglen, const uint8_t *pk,
                           const char *hashAlg, const uint8_t *ctx = nullptr,
                           size_t ctxlen = 0) {
    if (ctxlen > MAX_CONTEXT_SIZE || !slhdsa_esp32::nonNull(ctx, ctxlen) ||
        !slhdsa_esp32::nonNull(msg, msglen)) {
      return SLHDSA_ERR_INVALID_ARG;
    }
    if (siglen != SIGNATURE_SIZE) {
      return SLHDSA_ERR_INVALID_SIGNATURE;
    }
    slhdsa_esp32::HwSession hws(hardwareSha());
    return hash_slh_verify(msg, msglen, sig, siglen, ctx, ctxlen, hashAlg, pk,
                           params()) == 1
               ? 0
               : SLHDSA_ERR_INVALID_SIGNATURE;
  }

  /*
   * Extract the public key from a secret key and validate the secret key by
   * recomputing PK.root from SK.seed (one key generation: seconds for the
   * "s" sets). Returns 0 if valid, SLHDSA_ERR_INVALID_KEY otherwise.
   */
  static int publicKeyFromSecretKey(uint8_t *pk, const uint8_t *sk) {
    uint8_t sk2[SECRET_KEY_SIZE];
    uint8_t pk2[PUBLIC_KEY_SIZE];
    int ret = generateKeypairFromSeed(pk2, sk2, sk);  // sk starts with the seed
    bool ok = ret == 0 && memcmp(sk2, sk, SECRET_KEY_SIZE) == 0;
    slhdsa_esp32::wipe(sk2, sizeof(sk2));
    if (!ok) {
      return SLHDSA_ERR_INVALID_KEY;
    }
    memcpy(pk, pk2, PUBLIC_KEY_SIZE);
    return 0;
  }

private:
  static int signWith(uint8_t *sig, size_t *siglen, const uint8_t *msg,
                      size_t msglen, const uint8_t *sk, const uint8_t *ctx,
                      size_t ctxlen, const uint8_t *addrnd) {
    size_t len = 0;
    if (!slhdsa_esp32::nonNull(ctx, ctxlen) || !slhdsa_esp32::nonNull(msg, msglen)) {
      ctxlen = SIZE_MAX;  // reported as SLHDSA_ERR_INVALID_ARG
    } else if (ctxlen <= MAX_CONTEXT_SIZE) {
      slhdsa_esp32::HwSession hws(hardwareSha());
      len = slh_sign(sig, msg, msglen, ctx, ctxlen, sk, addrnd, params());
      slhdsa_esp32_stack_wipe(SLHDSA_ESP32_WIPE_BYTES);
    }
    return finishSign(sig, len, siglen, ctxlen);
  }

  static int finishSign(uint8_t *sig, size_t len, size_t *siglen,
                        size_t ctxlen) {
    int ret = 0;
    if (ctxlen > MAX_CONTEXT_SIZE) {
      ret = SLHDSA_ERR_INVALID_ARG;
    } else if (len != SIGNATURE_SIZE) {
      ret = SLHDSA_ERR_FAIL;
    }
    if (ret != 0) {
      memset(sig, 0, SIGNATURE_SIZE);
    }
    if (siglen != nullptr) {
      *siglen = ret == 0 ? SIGNATURE_SIZE : 0;
    }
    return ret;
  }
};

/* Pre-C++17 out-of-class definitions of the static constexpr members, so
 * that they may be ODR-used (e.g. bound to a const reference). */
#if __cplusplus < 201703L
template <class P> constexpr unsigned SLHDSA<P>::SECURITY_CATEGORY;
template <class P> constexpr bool SLHDSA<P>::FAST;
template <class P> constexpr bool SLHDSA<P>::SHAKE;
template <class P> constexpr size_t SLHDSA<P>::N;
template <class P> constexpr size_t SLHDSA<P>::PUBLIC_KEY_SIZE;
template <class P> constexpr size_t SLHDSA<P>::SECRET_KEY_SIZE;
template <class P> constexpr size_t SLHDSA<P>::SIGNATURE_SIZE;
template <class P> constexpr size_t SLHDSA<P>::SEED_SIZE;
template <class P> constexpr size_t SLHDSA<P>::MAX_CONTEXT_SIZE;
#endif

typedef SLHDSA<slhdsa_esp32::SHA2_128s>  SLHDSA_SHA2_128s;
typedef SLHDSA<slhdsa_esp32::SHAKE_128s> SLHDSA_SHAKE_128s;
typedef SLHDSA<slhdsa_esp32::SHA2_128f>  SLHDSA_SHA2_128f;
typedef SLHDSA<slhdsa_esp32::SHAKE_128f> SLHDSA_SHAKE_128f;
typedef SLHDSA<slhdsa_esp32::SHA2_192s>  SLHDSA_SHA2_192s;
typedef SLHDSA<slhdsa_esp32::SHAKE_192s> SLHDSA_SHAKE_192s;
typedef SLHDSA<slhdsa_esp32::SHA2_192f>  SLHDSA_SHA2_192f;
typedef SLHDSA<slhdsa_esp32::SHAKE_192f> SLHDSA_SHAKE_192f;
typedef SLHDSA<slhdsa_esp32::SHA2_256s>  SLHDSA_SHA2_256s;
typedef SLHDSA<slhdsa_esp32::SHAKE_256s> SLHDSA_SHAKE_256s;
typedef SLHDSA<slhdsa_esp32::SHA2_256f>  SLHDSA_SHA2_256f;
typedef SLHDSA<slhdsa_esp32::SHAKE_256f> SLHDSA_SHAKE_256f;

#endif /* SLHDSA_WRAPPER_H */
