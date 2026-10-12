/*
 * slhdsa_esp32_hwsha.c - SHA-2 hardware backend for SLH-DSA-SHA2-*
 *
 * Provides the parameter sets slh_dsa_sha2_{128,192,256}{s,f}_hw: the same
 * FIPS 205 parameter sets as slh_dsa_sha2_*, but with the hash functions
 * F, H, T_l, PRF and the WOTS+ chain computed on the ESP32 SHA accelerator.
 * The once-per-signature functions H_msg and PRF_msg stay in software; they
 * are verbatim copies of the slhdsa-c implementation (slh_sha2.c).
 *
 * slhdsa-c computes F etc. as one SHA-256 compression starting from a
 * precomputed "PK.seed || 0..." midstate. The original ESP32 cannot load a
 * hash state into the accelerator, so here every call hashes the full
 * message (PK.seed block + data block) from the initial state: 2 hardware
 * blocks instead of 1 software compression, still ~2.4x faster on the
 * original ESP32 (2245 vs 5458 CPU cycles per F).
 *
 * Hardware access
 *   - Original ESP32 ("parallel engine": SHA-1, SHA-256 and SHA-384/512 are
 *     separate engines sharing one register block): all engines are locked for
 *     a whole SLH-DSA operation (slhdsa_esp32_hw_begin/end, called by the
 *     C++ wrapper), so the shared registers are exclusively ours and no
 *     critical section is needed. They are briefly released every
 *     SESSION_CALLS hashes so that blocking users (esp_sha) get a turn;
 *     mbedTLS try-locks the engines and falls back to software meanwhile.
 *   - ESP32-S2/S3/C3/C6... (single engine, ESP-IDF >= 5): the engine is
 *     acquired for batches of SESSION_CALLS hashes only, because mbedTLS
 *     waits for it. (These chips could resume from a midstate; that
 *     optimisation is not implemented yet.) The C3/C6 have no SHA-512
 *     engine; SHA-512 hashes are computed in software there.
 *   - Other targets / ESP-IDF 4.x on non-ESP32 chips: no hardware backend;
 *     the *_hw parameter sets then compute in software.
 *
 * Safety: before the hardware is used for the first time, a self-test
 * compares hardware and software SHA-256/SHA-512 on several message lengths
 * (and determines the byte order of the digest registers). If it fails,
 * everything is computed in software, so the *_hw parameter sets always
 * produce correct results.
 *
 * Copyright (c) The slhdsa-c project authors (H_msg, PRF_msg, structure)
 * Copyright (c) 2026 The fips205-slhdsa-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sdkconfig.h>
#include <esp_idf_version.h>
#include <soc/soc_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include "plat_local.h"
#include "sha2_api.h"
#include "slh_adrs.h"
#include "slh_var.h"
#include "slhdsa_esp32.h"

#if defined(CONFIG_IDF_TARGET_ESP32)
#define HW_CLASSIC 1
#include <sha/sha_parallel_engine.h>
#include <hal/sha_ll.h>
#include <soc/dport_access.h>
#include <soc/hwcrypto_reg.h>
#define SESSION_CALLS 256
#elif ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0) && defined(SOC_SHA_SUPPORTED)
#define HW_CORE 1
#include <sha/sha_core.h>
#define SESSION_CALLS 64
#endif

#if defined(HW_CLASSIC) || defined(HW_CORE)
#define HW_AVAILABLE 1
/* ESP32-C3/C6 have no SHA-512 engine: SHA-512 (H, T_l of the 192/256 sets)
 * then stays in software; F, PRF and the chains are SHA-256 anyway. */
#if defined(SOC_SHA_SUPPORT_SHA512)
#define HW_HAS_512 1
#endif
#endif

/* ---- hardware state --------------------------------------------------- */

enum { HW_UNTESTED = 0, HW_OK = 1, HW_FAILED = 2 };
static volatile int s_hw_state = HW_UNTESTED;
static bool s_force_hw;      /* self-test in progress */
static uint8_t s_mode256;    /* digest byte order, see convert() */
static uint8_t s_mode512;

#if defined(HW_AVAILABLE)
static TaskHandle_t s_owner; /* task holding a session */
static unsigned s_depth;     /* nesting depth of the session */
static unsigned s_calls;     /* hashes since the engine was (re)acquired */

static void hw_acquire(void)
{
#if defined(HW_CLASSIC)
  /* All engines -- SHA-1, SHA-256 and SHA-384/512 (SHA-384 and SHA-512
   * share one engine and one lock; locking both would deadlock): then no
   * other user can be using the shared text registers, so no critical
   * section is needed around them (mbedTLS try-locks the engines and falls
   * back to software meanwhile). Fixed order. */
  esp_sha_lock_engine(SHA1);
  esp_sha_lock_engine(SHA2_256);
  esp_sha_lock_engine(SHA2_512);
#else
  esp_sha_acquire_hardware();
#endif
}

static void hw_release(void)
{
#if defined(HW_CLASSIC)
  esp_sha_unlock_engine(SHA2_512);
  esp_sha_unlock_engine(SHA2_256);
  esp_sha_unlock_engine(SHA1);
#else
  esp_sha_release_hardware();
#endif
}

/* Called at the start of every hardware hash. Returns true if the engine
 * was acquired for this hash only (no session in the current task). */
static bool hw_enter(void)
{
  if (s_owner != NULL && s_owner == xTaskGetCurrentTaskHandle())
  {
    if (++s_calls >= SESSION_CALLS)
    {
      s_calls = 0;
      hw_release(); /* let other users of the SHA engine in */
      taskYIELD();
      hw_acquire();
    }
    return false;
  }
  hw_acquire();
  return true;
}

static void hw_leave(bool per_call)
{
  if (per_call)
  {
    hw_release();
  }
}
#endif /* HW_AVAILABLE */

/* ---- streaming SHA-256 / SHA-512, hardware or software ---------------- */

typedef struct
{
  bool hw;
  bool per_call;
  bool first;
  uint16_t bs; /* block size: 64 or 128 */
  size_t fill;
  uint64_t total;
  union
  {
    sha2_256_t s256;
    sha2_512_t s512;
  } sw;
  uint32_t buf[32]; /* one block, word aligned */
} hs_t;

static bool use_hw(void)
{
  return s_force_hw || s_hw_state == HW_OK;
}

#if defined(HW_AVAILABLE)
static esp_sha_type hs_type(const hs_t *c)
{
#if defined(HW_HAS_512)
  return c->bs == 64 ? SHA2_256 : SHA2_512;
#else
  (void)c;
  return SHA2_256; /* SHA-512 never runs on the hardware here */
#endif
}

#if defined(HW_CLASSIC)
/* Original ESP32, register level (as ESP-IDF's sha_hal/sha_ll, but with
 * inline byte swapping and busy-polling of the own engine only). All four
 * engines are held (hw_acquire), so the shared text registers are ours. */
static void cl_wait_own(const hs_t *c)
{
  const uint32_t reg = c->bs == 64 ? SHA_256_BUSY_REG : SHA_512_BUSY_REG;
  while (DPORT_REG_READ(reg) != 0)
  {
  }
}
#endif

static void hw_block(hs_t *c)
{
#if defined(HW_CLASSIC)
  volatile uint32_t *text = (volatile uint32_t *)SHA_TEXT_BASE;
  unsigned i;
  if (!c->first)
  {
    cl_wait_own(c); /* previous block still being processed? */
  }
  for (i = 0; i < c->bs / 4u; i++)
  {
    text[i] = __builtin_bswap32(c->buf[i]);
  }
  if (c->first)
  {
    sha_ll_start_block(hs_type(c));
  }
  else
  {
    sha_ll_continue_block(hs_type(c));
  }
#else
  esp_sha_block(hs_type(c), c->buf, c->first);
#endif
  c->first = false;
}
#endif

static void hs_init(hs_t *c, unsigned alg)
{
  c->bs = alg == 256 ? 64 : 128;
  c->fill = 0;
  c->total = 0;
  c->first = true;
#if defined(HW_AVAILABLE)
#if defined(HW_HAS_512)
  c->hw = use_hw();
#else
  c->hw = alg == 256 && use_hw();
#endif
  if (c->hw)
  {
    c->per_call = hw_enter();
#if defined(HW_CORE)
    esp_sha_set_mode(hs_type(c));
#endif
    return;
  }
#endif
  c->hw = false;
  if (alg == 256)
  {
    sha2_256_init(&c->sw.s256);
  }
  else
  {
    sha2_512_init(&c->sw.s512);
  }
}

static void hs_update(hs_t *c, const uint8_t *m, size_t len)
{
  if (!c->hw)
  {
    if (c->bs == 64)
    {
      sha2_256_update(&c->sw.s256, m, len);
    }
    else
    {
      sha2_512_update(&c->sw.s512, m, len);
    }
    return;
  }
#if defined(HW_AVAILABLE)
  c->total += len;
  while (len > 0)
  {
    size_t t = c->bs - c->fill;
    if (t > len)
    {
      t = len;
    }
    memcpy((uint8_t *)c->buf + c->fill, m, t);
    c->fill += t;
    m += t;
    len -= t;
    if (c->fill == c->bs)
    {
      hw_block(c);
      c->fill = 0;
    }
  }
#endif
}

/* Hash starting with the block PK.seed || 0^(bs-n), as F, H, T_l and PRF
 * of the SHA2 parameter sets do. */
static void hs_init_prefixed(hs_t *c, unsigned alg, const slh_var_t *var)
{
  static const uint8_t zero[128] = {0};
  size_t n = var->prm->n;
  hs_init(c, alg);
#if defined(HW_AVAILABLE)
  if (c->hw)
  { /* the prefix is exactly one block */
    memcpy(c->buf, var->pk_seed, n);
    memset((uint8_t *)c->buf + n, 0, c->bs - n);
    c->total = c->bs;
    hw_block(c);
    return;
  }
#endif
  hs_update(c, var->pk_seed, n);
  hs_update(c, zero, c->bs - n);
}

/* Digest register byte order: 0 = as read, 1 = byte-swapped 32-bit words,
 * 2 = byte-swapped 64-bit words. */
static void convert(uint8_t *d, size_t len, uint8_t mode)
{
  size_t i, w = mode == 1 ? 4 : 8;
  if (mode == 0)
  {
    return;
  }
  for (i = 0; i < len; i += w)
  {
    size_t a = i, b = i + w - 1;
    while (a < b)
    {
      uint8_t t = d[a];
      d[a++] = d[b];
      d[b--] = t;
    }
  }
}

static void hs_final_raw(hs_t *c, uint8_t *digest, size_t need)
{
  /* digest: at least the first `need` bytes (rounded up to whole 64-bit
   * words), in the hardware byte order */
#if defined(HW_AVAILABLE)
  uint8_t *b = (uint8_t *)c->buf;
  size_t lenpos = c->bs - (c->bs == 64 ? 8 : 16);
  uint64_t bits = c->total * 8;
  int i;
  b[c->fill++] = 0x80;
  if (c->fill > lenpos)
  {
    memset(b + c->fill, 0, c->bs - c->fill);
    hw_block(c);
    c->fill = 0;
  }
  memset(b + c->fill, 0, c->bs - c->fill);
  for (i = 0; i < 8; i++)
  {
    b[c->bs - 1 - i] = (uint8_t)(bits >> (8 * i));
  }
  hw_block(c);
#if defined(HW_CLASSIC)
  {
    const uint32_t *text = (const uint32_t *)SHA_TEXT_BASE;
    uint32_t *w = (uint32_t *)digest; /* digest is word aligned */
    size_t words = ((need + 7) / 8) * 2;
    size_t j;
    cl_wait_own(c);
    sha_ll_load(hs_type(c)); /* digest -> text registers */
    cl_wait_own(c);
    {
      DPORT_INTERRUPT_DISABLE();
      for (j = 0; j < words; j++)
      {
        w[j] = DPORT_SEQUENCE_REG_READ((uint32_t)&text[j]);
      }
      DPORT_INTERRUPT_RESTORE();
    }
  }
#else
  (void)need;
  esp_sha_read_digest_state(hs_type(c), digest);
#endif
  hw_leave(c->per_call);
#else
  (void)c;
  (void)digest;
  (void)need;
#endif
}

static void hs_final(hs_t *c, uint8_t *out, size_t outlen)
{
  uint32_t d32[16];
  uint8_t *d = (uint8_t *)d32;
  if (!c->hw)
  {
    if (c->bs == 64)
    {
      sha2_256_final_len(&c->sw.s256, out, outlen);
    }
    else
    {
      sha2_512_final_len(&c->sw.s512, out, outlen);
    }
    return;
  }
  hs_final_raw(c, d, outlen);
  convert(d, ((outlen + 7) / 8) * 8, c->bs == 64 ? s_mode256 : s_mode512);
  memcpy(out, d, outlen);
}

/* ---- self-test -------------------------------------------------------- */

#if defined(HW_AVAILABLE)
/* Hardware digest of m (raw register order) */
static void hw_digest_raw(unsigned alg, const uint8_t *m, size_t len,
                          uint8_t *raw)
{
  hs_t c;
  hs_init(&c, alg);
  hs_update(&c, m, len);
  hs_final_raw(&c, raw, alg == 256 ? 32 : 64);
}

static bool selftest_alg(unsigned alg, uint8_t *mode_out)
{
  static const size_t lens[] = {0, 3, 55, 56, 63, 64, 111, 112, 127, 128, 200};
  uint8_t m[200], ref[64];
  uint32_t raw32[16];
  uint8_t *raw = (uint8_t *)raw32;
  size_t i, dlen = alg == 256 ? 32 : 64;
  int mode = -1, md;
  for (i = 0; i < sizeof(m); i++)
  {
    m[i] = (uint8_t)(i * 131 + 7);
  }
  for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++)
  {
    if (alg == 256)
    {
      sha2_256(ref, m, lens[i]);
    }
    else
    {
      sha2_512(ref, m, lens[i]);
    }
    hw_digest_raw(alg, m, lens[i], raw);
    if (mode < 0)
    { /* determine the byte order from the first case */
      for (md = 0; md <= 2 && mode < 0; md++)
      {
        uint8_t t[64];
        memcpy(t, raw, dlen);
        convert(t, dlen, (uint8_t)md);
        if (memcmp(t, ref, dlen) == 0)
        {
          mode = md;
        }
      }
      if (mode < 0)
      {
        return false;
      }
    }
    convert(raw, dlen, (uint8_t)mode);
    if (memcmp(raw, ref, dlen) != 0)
    {
      return false;
    }
  }
  *mode_out = (uint8_t)mode;
  return true;
}
#endif /* HW_AVAILABLE */

int slhdsa_esp32_hw_sha_active(void)
{
  if (s_hw_state == HW_UNTESTED)
  {
#if defined(HW_AVAILABLE)
    static portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
    static bool running = false;
    bool mine = false;
    taskENTER_CRITICAL(&mux);
    if (!running)
    {
      running = mine = true;
    }
    taskEXIT_CRITICAL(&mux);
    if (mine)
    {
      uint8_t m256 = 0, m512 = 0;
      bool ok;
      s_force_hw = true;
      ok = selftest_alg(256, &m256);
#if defined(HW_HAS_512)
      ok = ok && selftest_alg(512, &m512);
#endif
      s_force_hw = false;
      s_mode256 = m256;
      s_mode512 = m512;
      s_hw_state = ok ? HW_OK : HW_FAILED;
    }
    else
    {
      while (s_hw_state == HW_UNTESTED)
      {
        vTaskDelay(1); /* another task is running the self-test */
      }
    }
#else
    s_hw_state = HW_FAILED; /* no hardware backend on this target */
#endif
  }
  return s_hw_state == HW_OK;
}

void slhdsa_esp32_hw_begin(void)
{
#if defined(HW_AVAILABLE)
  TaskHandle_t me = xTaskGetCurrentTaskHandle();
  if (!slhdsa_esp32_hw_sha_active())
  {
    return;
  }
  if (s_owner == me)
  {
    s_depth++;
    return;
  }
  hw_acquire();
  s_calls = 0;
  s_depth = 1;
  s_owner = me;
#endif
}

void slhdsa_esp32_hw_end(void)
{
#if defined(HW_AVAILABLE)
  if (s_owner == NULL || s_owner != xTaskGetCurrentTaskHandle())
  {
    return;
  }
  if (--s_depth == 0)
  {
    s_owner = NULL;
    hw_release();
  }
#endif
}

/* ---- SLH-DSA hash functions (FIPS 205, Section 11.2) ------------------ */

static unsigned alg_hh(const slh_var_t *var)
{
  /* H and T_l use SHA-256 for category 1, SHA-512 for categories 3 and 5 */
  return var->prm->n == 16 ? 256 : 512;
}

#if defined(HW_CLASSIC)
/* Fast path for the dominant hash shape (F, PRF, and H of category 1):
 *   Trunc_n(SHA-256(PK.seed || 0^(64-n) || ADRSc || d1 || d2))
 * with 22 + |d1| + |d2| <= 55, i.e. exactly two blocks. The blocks are
 * written straight into the text registers. Returns false if the hardware
 * is not in use (the caller then takes the generic path). */
static bool cl_fast256(slh_var_t *var, uint8_t *h, const uint8_t *d1,
                       size_t l1, const uint8_t *d2, size_t l2)
{
  volatile uint32_t *text = (volatile uint32_t *)SHA_TEXT_BASE;
  uint32_t blk[16], dig[8];
  uint8_t *b = (uint8_t *)blk;
  const size_t n = var->prm->n, len = 22 + l1 + l2;
  const uint32_t bits = (uint32_t)(64 + len) * 8;
  bool per_call;
  unsigned i;
  if (s_hw_state != HW_OK || s_mode256 != 1)
  {
    return false;
  }
  /* second block, prepared before touching the hardware */
  adrsc_22(var, b);
  memcpy(b + 22, d1, l1);
  if (l2 != 0)
  {
    memcpy(b + 22 + l1, d2, l2);
  }
  b[len] = 0x80;
  memset(b + len + 1, 0, 64 - 4 - (len + 1));
  b[60] = (uint8_t)(bits >> 24);
  b[61] = (uint8_t)(bits >> 16);
  b[62] = (uint8_t)(bits >> 8);
  b[63] = (uint8_t)bits;
  memcpy(dig, var->pk_seed, n); /* first block: PK.seed || 0 */

  per_call = hw_enter();
  for (i = 0; i < n / 4; i++)
  {
    text[i] = __builtin_bswap32(dig[i]);
  }
  for (; i < 16; i++)
  {
    text[i] = 0;
  }
  sha_ll_start_block(SHA2_256);
  for (i = 0; i < 16; i++)
  {
    blk[i] = __builtin_bswap32(blk[i]);
  }
  while (DPORT_REG_READ(SHA_256_BUSY_REG) != 0)
  {
  }
  for (i = 0; i < 16; i++)
  {
    text[i] = blk[i];
  }
  sha_ll_continue_block(SHA2_256);
  while (DPORT_REG_READ(SHA_256_BUSY_REG) != 0)
  {
  }
  sha_ll_load(SHA2_256);
  while (DPORT_REG_READ(SHA_256_BUSY_REG) != 0)
  {
  }
  {
    DPORT_INTERRUPT_DISABLE();
    for (i = 0; i < n / 4; i++)
    {
      dig[i] = DPORT_SEQUENCE_REG_READ((uint32_t)&text[i]);
    }
    DPORT_INTERRUPT_RESTORE();
  }
  hw_leave(per_call);
  for (i = 0; i < n / 4; i++)
  {
    dig[i] = __builtin_bswap32(dig[i]);
  }
  memcpy(h, dig, n);
  return true;
}
#endif

/* F(PK.seed, ADRS, M1) = Trunc_n(SHA-256(PK.seed || 0 || ADRSc || M1)) */
static void hw_f(slh_var_t *var, uint8_t *h, const uint8_t *m1)
{
  hs_t c;
  uint8_t ac[22];
  size_t n = var->prm->n;
#if defined(HW_CLASSIC)
  if (cl_fast256(var, h, m1, n, NULL, 0))
  {
    return;
  }
#endif
  adrsc_22(var, ac);
  hs_init_prefixed(&c, 256, var);
  hs_update(&c, ac, 22);
  hs_update(&c, m1, n);
  hs_final(&c, h, n);
}

/* H(PK.seed, ADRS, M2) = Trunc_n(SHA-x(PK.seed || 0 || ADRSc || M2)) */
static void hw_h(slh_var_t *var, uint8_t *h, const uint8_t *m1,
                 const uint8_t *m2)
{
  slhdsa_esp32_yield_point(); /* task watchdog, see slhdsa_esp32.c */
  hs_t c;
  uint8_t ac[22];
  size_t n = var->prm->n;
#if defined(HW_CLASSIC)
  if (n == 16 && cl_fast256(var, h, m1, n, m2, n))
  {
    return;
  }
#endif
  adrsc_22(var, ac);
  hs_init_prefixed(&c, alg_hh(var), var);
  hs_update(&c, ac, 22);
  hs_update(&c, m1, n);
  hs_update(&c, m2, n);
  hs_final(&c, h, n);
}

/* T_l(PK.seed, ADRS, Ml) = Trunc_n(SHA-x(PK.seed || 0 || ADRSc || Ml)) */
static void hw_tl(slh_var_t *var, uint8_t *h, const uint8_t *m, size_t m_sz)
{
  slhdsa_esp32_yield_point(); /* task watchdog, see slhdsa_esp32.c */
  hs_t c;
  uint8_t ac[22];
  adrsc_22(var, ac);
  hs_init_prefixed(&c, alg_hh(var), var);
  hs_update(&c, ac, 22);
  hs_update(&c, m, m_sz);
  hs_final(&c, h, var->prm->n);
}

/* PRF(PK.seed, SK.seed, ADRS) = Trunc_n(SHA-256(PK.seed || 0 || ADRSc ||
 * SK.seed)) */
static void hw_prf(slh_var_t *var, uint8_t *h)
{
  hs_t c;
  uint8_t ac[22];
  size_t n = var->prm->n;
#if defined(HW_CLASSIC)
  if (cl_fast256(var, h, var->sk_seed, n, NULL, 0))
  {
    return;
  }
#endif
  adrsc_22(var, ac);
  hs_init_prefixed(&c, 256, var);
  hs_update(&c, ac, 22);
  hs_update(&c, var->sk_seed, n);
  hs_final(&c, h, n);
}

/* Algorithm 5: chain(X, i, s, PK.seed, ADRS) */
static void hw_chain(slh_var_t *var, uint8_t *tmp, const uint8_t *x,
                     uint32_t i, uint32_t s)
{
  slhdsa_esp32_yield_point(); /* task watchdog, see slhdsa_esp32.c */
  uint32_t j;
  if (s == 0)
  {
    memcpy(tmp, x, var->prm->n);
    return;
  }
  for (j = 0; j < s; j++)
  {
    adrs_set_hash_address(var, i + j);
    hw_f(var, tmp, j == 0 ? x : tmp);
  }
}

/* Combination WOTS PRF + chain (as in slhdsa-c) */
static void hw_wots_chain(slh_var_t *var, uint8_t *tmp, uint32_t s)
{
  slhdsa_esp32_yield_point(); /* task watchdog, see slhdsa_esp32.c */
  adrs_set_type(var, ADRS_WOTS_PRF);
  adrs_set_tree_index(var, 0);
  hw_prf(var, tmp);

  adrs_set_type(var, ADRS_WOTS_HASH);
  adrs_set_tree_index(var, 0);
  hw_chain(var, tmp, tmp, 0, s);
}

/* Combination FORS PRF + F if s == 1 (as in slhdsa-c) */
static void hw_fors_hash(slh_var_t *var, uint8_t *tmp, uint32_t s)
{
  slhdsa_esp32_yield_point(); /* task watchdog, see slhdsa_esp32.c */
  adrs_set_type(var, ADRS_FORS_PRF);
  adrs_set_tree_height(var, 0);
  hw_prf(var, tmp);

  if (s == 1)
  {
    adrs_set_type(var, ADRS_FORS_TREE);
    hw_f(var, tmp, tmp);
  }
}

/* Context set-up (as sha2_mk_var in slhdsa-c, without the software
 * midstates, which the functions above do not use). */
static void hw_mk_var(slh_var_t *var, const uint8_t *pk, const uint8_t *sk,
                      const slh_param_t *prm)
{
  size_t n = prm->n;
  var->prm = prm;
  if (sk != NULL)
  {
    memcpy(var->sk_seed, sk, n);
    memcpy(var->sk_prf, sk + n, n);
    memcpy(var->pk_seed, sk + 2 * n, n);
    memcpy(var->pk_root, sk + 3 * n, n);
  }
  else if (pk != NULL)
  {
    memcpy(var->pk_seed, pk, n);
    memcpy(var->pk_root, pk + n, n);
  }
  var->adrs = &var->t_adrs;
}

/* ---- H_msg and PRF_msg: software, verbatim from slhdsa-c slh_sha2.c ---- */

static void sha2_256_h_msg(slh_var_t *var, uint8_t *h, const uint8_t *r,
                           const uint8_t *m, size_t m_sz, const uint8_t *ctx,
                           size_t ctx_sz)
{
  sha2_256_t sha2;
  size_t i;
  size_t n = var->prm->n;
  uint8_t buf[16 + 16 + 32 + 4];
  size_t mgf_sz;
  uint8_t *ctr;

  sha2_256_init(&sha2);
  sha2_256_update(&sha2, r, n);
  sha2_256_update(&sha2, var->pk_seed, n);
  sha2_256_update(&sha2, var->pk_root, n);
  if (ctx_sz != SLH_CTX_SZ_NO_CONTEXT)
  {
    buf[0] = 0;
    buf[1] = ctx_sz & 0xFF;
    sha2_256_update(&sha2, buf, 2);
    sha2_256_update(&sha2, ctx, ctx_sz);
  }
  sha2_256_update(&sha2, m, m_sz);
  sha2_256_final(&sha2, buf + 2 * n);

  memcpy(buf, r, n);
  memcpy(buf + n, var->pk_seed, n);
  mgf_sz = 2 * n + 32 + 4;
  ctr = buf + mgf_sz - 4;
  for (i = 0; i < var->prm->m; i += 32)
  {
    uint32_t c = i / 32;
    ctr[0] = c >> 24;
    ctr[1] = (c >> 16) & 0xFF;
    ctr[2] = (c >> 8) & 0xFF;
    ctr[3] = c & 0xFF;
    sha2_256_init(&sha2);
    sha2_256_update(&sha2, buf, mgf_sz);
    if ((var->prm->m - i) >= 32)
    {
      sha2_256_final(&sha2, h + i);
    }
    else
    {
      sha2_256_final(&sha2, buf);
      memcpy(h + i, buf, var->prm->m - i);
    }
  }
}

static void sha2_512_h_msg(slh_var_t *var, uint8_t *h, const uint8_t *r,
                           const uint8_t *m, size_t m_sz, const uint8_t *ctx,
                           size_t ctx_sz)
{
  size_t i;
  sha2_512_t sha2;
  uint8_t buf[32 + 32 + 64 + 4];
  size_t mgf_sz;
  uint8_t *ctr;
  size_t n = var->prm->n;

  sha2_512_init(&sha2);
  sha2_512_update(&sha2, r, n);
  sha2_512_update(&sha2, var->pk_seed, n);
  sha2_512_update(&sha2, var->pk_root, n);
  if (ctx_sz != SLH_CTX_SZ_NO_CONTEXT)
  {
    buf[0] = 0;
    buf[1] = ctx_sz & 0xFF;
    sha2_512_update(&sha2, buf, 2);
    sha2_512_update(&sha2, ctx, ctx_sz);
  }
  sha2_512_update(&sha2, m, m_sz);
  sha2_512_final(&sha2, buf + 2 * n);

  memcpy(buf, r, n);
  memcpy(buf + n, var->pk_seed, n);
  mgf_sz = 2 * n + 64 + 4;
  ctr = buf + mgf_sz - 4;
  for (i = 0; i < var->prm->m; i += 64)
  {
    uint32_t c = i / 64;
    ctr[0] = c >> 24;
    ctr[1] = (c >> 16) & 0xFF;
    ctr[2] = (c >> 8) & 0xFF;
    ctr[3] = c & 0xFF;
    sha2_512_init(&sha2);
    sha2_512_update(&sha2, buf, mgf_sz);
    if ((var->prm->m - i) >= 64)
    {
      sha2_512_final(&sha2, h + i);
    }
    else
    {
      sha2_512_final(&sha2, buf);
      memcpy(h + i, buf, var->prm->m - i);
    }
  }
}

static void sha2_256_prf_msg(slh_var_t *var, uint8_t *h,
                             const uint8_t *opt_rand, const uint8_t *m,
                             size_t m_sz, const uint8_t *ctx, size_t ctx_sz)
{
  unsigned i;
  sha2_256_t sha2;
  uint8_t pad[64], buf[32];
  size_t n = var->prm->n;

  memcpy(pad, var->sk_prf, n);
  for (i = 0; i < n; i++)
  {
    pad[i] ^= 0x36;
  }
  memset(pad + n, 0x36, 64 - n);

  sha2_256_init(&sha2);
  sha2_256_update(&sha2, pad, 64);
  sha2_256_update(&sha2, opt_rand, n);
  if (ctx_sz != SLH_CTX_SZ_NO_CONTEXT)
  {
    buf[0] = 0;
    buf[1] = ctx_sz & 0xFF;
    sha2_256_update(&sha2, buf, 2);
    sha2_256_update(&sha2, ctx, ctx_sz);
  }
  sha2_256_update(&sha2, m, m_sz);
  sha2_256_final(&sha2, buf);

  for (i = 0; i < 64; i++)
  {
    pad[i] ^= 0x36 ^ 0x5C;
  }
  sha2_256_init(&sha2);
  sha2_256_update(&sha2, pad, 64);
  sha2_256_update(&sha2, buf, 32);
  sha2_256_final_len(&sha2, h, n);
}

static void sha2_512_prf_msg(slh_var_t *var, uint8_t *h,
                             const uint8_t *opt_rand, const uint8_t *m,
                             size_t m_sz, const uint8_t *ctx, size_t ctx_sz)
{
  unsigned i;
  sha2_512_t sha2;
  uint8_t pad[128], buf[64];
  size_t n = var->prm->n;

  memcpy(pad, var->sk_prf, n);
  for (i = 0; i < n; i++)
  {
    pad[i] ^= 0x36;
  }
  memset(pad + n, 0x36, 128 - n);

  sha2_512_init(&sha2);
  sha2_512_update(&sha2, pad, 128);
  sha2_512_update(&sha2, opt_rand, n);
  if (ctx_sz != SLH_CTX_SZ_NO_CONTEXT)
  {
    buf[0] = 0;
    buf[1] = ctx_sz & 0xFF;
    sha2_512_update(&sha2, buf, 2);
    sha2_512_update(&sha2, ctx, ctx_sz);
  }
  sha2_512_update(&sha2, m, m_sz);
  sha2_512_final(&sha2, buf);

  for (i = 0; i < 128; i++)
  {
    pad[i] ^= 0x36 ^ 0x5C;
  }
  sha2_512_init(&sha2);
  sha2_512_update(&sha2, pad, 128);
  sha2_512_update(&sha2, buf, 64);
  sha2_512_final_len(&sha2, h, n);
}

/* ---- parameter sets (FIPS 205, Table 2) ------------------------------- */

#define HW_SET_1(NAME, ID, N, H, D, HP, A, K, M)                              \
  const slh_param_t NAME = {ID, N, H, D, HP, A, K, 4, M,                     \
                            hw_mk_var, hw_chain, hw_wots_chain, hw_fors_hash, \
                            sha2_256_h_msg, hw_prf, sha2_256_prf_msg,         \
                            hw_f, hw_h, hw_tl};
#define HW_SET_35(NAME, ID, N, H, D, HP, A, K, M)                             \
  const slh_param_t NAME = {ID, N, H, D, HP, A, K, 4, M,                     \
                            hw_mk_var, hw_chain, hw_wots_chain, hw_fors_hash, \
                            sha2_512_h_msg, hw_prf, sha2_512_prf_msg,         \
                            hw_f, hw_h, hw_tl};

HW_SET_1(slh_dsa_sha2_128s_hw, "SLH-DSA-SHA2-128s", 16, 63, 7, 9, 12, 14, 30)
HW_SET_1(slh_dsa_sha2_128f_hw, "SLH-DSA-SHA2-128f", 16, 66, 22, 3, 6, 33, 34)
HW_SET_35(slh_dsa_sha2_192s_hw, "SLH-DSA-SHA2-192s", 24, 63, 7, 9, 14, 17, 39)
HW_SET_35(slh_dsa_sha2_192f_hw, "SLH-DSA-SHA2-192f", 24, 66, 22, 3, 8, 33, 42)
HW_SET_35(slh_dsa_sha2_256s_hw, "SLH-DSA-SHA2-256s", 32, 64, 8, 8, 14, 22, 47)
HW_SET_35(slh_dsa_sha2_256f_hw, "SLH-DSA-SHA2-256f", 32, 68, 17, 4, 9, 35, 49)
