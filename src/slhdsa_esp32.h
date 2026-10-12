/*
 * slhdsa_esp32.h - C API of SLH-DSA (FIPS 205) for ESP32
 *
 * Declares the slhdsa-c API (all 12 parameter sets, selected at run time
 * by a parameter-set pointer such as &slh_dsa_sha2_128f) and the ESP32 glue
 * functions. The C++ wrapper SLHDSA.h is the recommended interface.
 *
 * Use slhdsa_esp32_coop(&slh_dsa_...) as prm for long operations (see below).
 *
 *   slh_keygen_internal(sk, pk, sk_seed, sk_prf, pk_seed, prm)
 *   slh_sign(sig, m, m_sz, ctx, ctx_sz, sk, addrnd, prm)  -> sig size or 0
 *   slh_verify(m, m_sz, sig, sig_sz, ctx, ctx_sz, pk, prm) -> 1 if valid
 *   hash_slh_sign / hash_slh_verify                       (HashSLH-DSA)
 *   slh_pk_sz / slh_sk_sz / slh_sig_sz / slh_alg_id
 *
 * Copyright (c) 2026 The fips205-slhdsa-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SLHDSA_ESP32_H
#define SLHDSA_ESP32_H

#include <stddef.h>
#include <stdint.h>
#include "slh_dsa.h"
#include "slh_prehash.h"
#include "slhdsa_esp32_config.h"

/* Error codes of the C++ wrapper (same values as fips204-mldsa-esp32's MLD_ERR_*) */
#define SLHDSA_ERR_FAIL (-1)
#define SLHDSA_ERR_RNG_FAIL (-3)
#define SLHDSA_ERR_INVALID_SIGNATURE (-6)
#define SLHDSA_ERR_INVALID_KEY (-7)
#define SLHDSA_ERR_INVALID_ARG (-9)

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The random source used for key generation and hedged signing: the ESP32
 * hardware RNG (esp_fill_random). Returns 0 on success. Output is true
 * random only while Wi-Fi/BT (or bootloader_random_enable()) is active.
 */
int slhdsa_esp32_randombytes(uint8_t *out, size_t outlen);

/*
 * Overwrite up to len bytes of the stack area below the caller's stack
 * pointer (bounded by the free stack of the current task). Used by the
 * C++ wrapper to remove secret key material left on the stack by slhdsa-c.
 */
void slhdsa_esp32_stack_wipe(size_t len);

/*
 * Cooperative copy of one of the 12 slhdsa-c parameter sets (e.g.
 * slhdsa_esp32_coop(&slh_dsa_sha2_128s)): same results, but long
 * computations sleep for one tick every 500 ms, so the idle task can run
 * and the ESP32 task watchdog does not reset the chip during key generation
 * or signing (which takes up to minutes for the "s" sets). The C++ wrapper
 * uses these copies; use them with the C API as well. Returns prm itself
 * for other parameter sets (the *_hw sets below yield by themselves).
 */
const slh_param_t *slhdsa_esp32_coop(const slh_param_t *prm);

/* The yield check used by the cooperative and *_hw parameter sets. */
void slhdsa_esp32_yield_point(void);

/*
 * SHA-2 hardware backend (see slhdsa_esp32_hwsha.c and SLHDSA_ESP32_HW_SHA in
 * slhdsa_esp32_config.h). The *_hw parameter sets are the SLH-DSA-SHA2-*
 * sets with F, H, T_l, PRF computed on the SHA accelerator; they always give
 * the same results as the software sets (they fall back to software if the
 * hardware self-test fails or the target has no supported accelerator).
 */
extern const slh_param_t slh_dsa_sha2_128s_hw;
extern const slh_param_t slh_dsa_sha2_128f_hw;
extern const slh_param_t slh_dsa_sha2_192s_hw;
extern const slh_param_t slh_dsa_sha2_192f_hw;
extern const slh_param_t slh_dsa_sha2_256s_hw;
extern const slh_param_t slh_dsa_sha2_256f_hw;

/* 1 if the SHA hardware passed its self-test and is used by the *_hw sets
 * (runs the self-test on first call, ~1 ms), 0 otherwise. */
int slhdsa_esp32_hw_sha_active(void);

/* Hold the SHA engine(s) for a sequence of *_hw operations in the calling
 * task (optional, the C++ wrapper does it for you; without a session each
 * hash acquires the engine itself, which is correct but slower). The engine
 * is still released briefly every few hundred hashes for other users.
 * Calls nest. */
void slhdsa_esp32_hw_begin(void);
void slhdsa_esp32_hw_end(void);

#ifdef __cplusplus
}
#endif

#endif /* !SLHDSA_ESP32_H */
