/*
 * slhdsa_esp32.c - ESP32 platform glue for slhdsa-c
 *
 * 1. Hardware RNG: slhdsa_esp32_randombytes() reads the ESP32
 *    hardware RNG (esp_fill_random). Its output is true random whenever an
 *    entropy source is running: Wi-Fi or Bluetooth enabled, or
 *    bootloader_random_enable() active (see the "Random Number Generation"
 *    chapter of the ESP-IDF API reference). With all of them off the RNG
 *    output should be treated as pseudo-random only.
 *
 * 2. Stack wiping: slhdsa-c keeps the secret seeds (SK.seed, SK.prf) in a
 *    context structure on the stack and does not zeroize it. The C++
 *    wrapper therefore calls slhdsa_esp32_stack_wipe() after every
 *    operation that touches a secret key: it overwrites the stack area just
 *    used by the operation (the region below the caller's stack pointer).
 *
 * 3. Task watchdog: key generation and signing of the "s" parameter sets
 *    run for seconds to minutes. The Arduino-ESP32 core watches the idle
 *    task of core 0 with a 5 s panic timeout, so such an operation on
 *    core 0 (always the case on single-core chips) would reset the chip.
 *    slhdsa_esp32_coop() returns cooperative copies of the parameter sets
 *    whose hash functions call slhdsa_esp32_yield_point(): every 500 ms of
 *    computation the task sleeps for one tick, so the idle task runs and
 *    feeds the watchdog (cost: ~0.2% run time). The C++ wrapper uses them.
 *    (Earlier versions unsubscribed the idle tasks from the watchdog
 *    instead; ESP-IDF's reconfiguration has a race that occasionally logs
 *    "esp_task_wdt_reset(): task not found", so that approach was dropped.)
 *
 * Copyright (c) 2026 The fips205-slhdsa-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>
#include <stdint.h>
#include <esp_random.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include "slhdsa_esp32.h"
#include "slh_var.h"

int slhdsa_esp32_randombytes(uint8_t *out, size_t outlen)
{
  if (outlen == 0)
  {
    return 0;
  }
  if (out == NULL)
  {
    return -1;
  }
  esp_fill_random(out, outlen);
  return 0;
}

/* Free stack space below the current stack pointer, in bytes. */
static size_t free_stack_below_sp(void)
{
  uint8_t marker;
  uint8_t *start = pxTaskGetStackStart(NULL); /* lowest stack address */
  if (start == NULL || &marker <= start)
  {
    return 0;
  }
  return (size_t)(&marker - start);
}

/* The array lives in this function's own frame (allocated with the
 * windowed-ABI movsp sequence), so the zeroing loop never writes below the
 * active stack pointer and calls no other function while it runs. */
static void __attribute__((noinline)) wipe_frame(size_t len)
{
  volatile uint8_t buf[len];
  size_t i;
  for (i = 0; i < len; i++)
  {
    buf[i] = 0;
  }
  __asm__ __volatile__("" : : "r"(buf) : "memory");
}

void slhdsa_esp32_stack_wipe(size_t len)
{
  /* Never wipe more than what is free (minus a safety margin for this
   * frame, the wipe_frame frame and possible interrupt context). */
  const size_t margin = 768;
  size_t avail;
  if (len == 0)
  {
    return;
  }
  avail = free_stack_below_sp();
  if (avail <= margin)
  {
    return;
  }
  if (len > avail - margin)
  {
    len = avail - margin;
  }
  wipe_frame(len);
}

/* ---- cooperative scheduling ------------------------------------------- */

#ifndef SLHDSA_ESP32_YIELD_MS
#define SLHDSA_ESP32_YIELD_MS 500
#endif

void slhdsa_esp32_yield_point(void)
{
  static volatile TickType_t last;
  const TickType_t now = xTaskGetTickCount();
  if ((TickType_t)(now - last) >= pdMS_TO_TICKS(SLHDSA_ESP32_YIELD_MS))
  {
    last = now;
    vTaskDelay(1); /* lets the idle task run (and feed the task watchdog) */
  }
}

/* Cooperative copies of the 12 slhdsa-c parameter sets: identical
 * parameters, each function forwards to the slhdsa-c implementation; the
 * frequently called ones pass through slhdsa_esp32_yield_point() first.
 * slhdsa-c stores the parameter set it was called with in var->prm, so
 * the forwarders find the original set by its index. */
#define NSETS 12
static const slh_param_t *const s_up[NSETS] = {
    &slh_dsa_sha2_128s, &slh_dsa_shake_128s, &slh_dsa_sha2_128f,
    &slh_dsa_shake_128f, &slh_dsa_sha2_192s, &slh_dsa_shake_192s,
    &slh_dsa_sha2_192f, &slh_dsa_shake_192f, &slh_dsa_sha2_256s,
    &slh_dsa_shake_256s, &slh_dsa_sha2_256f, &slh_dsa_shake_256f};
static slh_param_t s_coop[NSETS];
static volatile bool s_coop_ready;

static const slh_param_t *up(const slh_param_t *prm)
{
  return s_up[prm - s_coop];
}

static void c_mk_var(slh_var_t *var, const uint8_t *pk, const uint8_t *sk,
                     const slh_param_t *prm)
{
  up(prm)->mk_var(var, pk, sk, prm); /* var->prm = prm (the copy) */
}
static void c_chain(slh_var_t *var, uint8_t *tmp, const uint8_t *x,
                    uint32_t i, uint32_t s)
{
  slhdsa_esp32_yield_point();
  up(var->prm)->chain(var, tmp, x, i, s);
}
static void c_wots_chain(slh_var_t *var, uint8_t *tmp, uint32_t s)
{
  slhdsa_esp32_yield_point();
  up(var->prm)->wots_chain(var, tmp, s);
}
static void c_fors_hash(slh_var_t *var, uint8_t *tmp, uint32_t s)
{
  slhdsa_esp32_yield_point();
  up(var->prm)->fors_hash(var, tmp, s);
}
static void c_h_msg(slh_var_t *var, uint8_t *h, const uint8_t *r,
                    const uint8_t *m, size_t m_sz, const uint8_t *ctx,
                    size_t ctx_sz)
{
  up(var->prm)->h_msg(var, h, r, m, m_sz, ctx, ctx_sz);
}
static void c_prf(slh_var_t *var, uint8_t *h)
{
  up(var->prm)->prf(var, h);
}
static void c_prf_msg(slh_var_t *var, uint8_t *h, const uint8_t *opt_rand,
                      const uint8_t *m, size_t m_sz, const uint8_t *ctx,
                      size_t ctx_sz)
{
  up(var->prm)->prf_msg(var, h, opt_rand, m, m_sz, ctx, ctx_sz);
}
static void c_h_f(slh_var_t *var, uint8_t *h, const uint8_t *m1)
{
  up(var->prm)->h_f(var, h, m1);
}
static void c_h_h(slh_var_t *var, uint8_t *h, const uint8_t *m1,
                  const uint8_t *m2)
{
  slhdsa_esp32_yield_point();
  up(var->prm)->h_h(var, h, m1, m2);
}
static void c_h_t(slh_var_t *var, uint8_t *h, const uint8_t *m, size_t m_sz)
{
  slhdsa_esp32_yield_point();
  up(var->prm)->h_t(var, h, m, m_sz);
}

const slh_param_t *slhdsa_esp32_coop(const slh_param_t *prm)
{
  static portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
  int i;
  if (!s_coop_ready)
  {
    taskENTER_CRITICAL(&mux);
    if (!s_coop_ready)
    {
      for (i = 0; i < NSETS; i++)
      {
        s_coop[i] = *s_up[i];
        s_coop[i].mk_var = c_mk_var;
        s_coop[i].chain = c_chain;
        s_coop[i].wots_chain = c_wots_chain;
        s_coop[i].fors_hash = c_fors_hash;
        s_coop[i].h_msg = c_h_msg;
        s_coop[i].prf = c_prf;
        s_coop[i].prf_msg = c_prf_msg;
        s_coop[i].h_f = c_h_f;
        s_coop[i].h_h = c_h_h;
        s_coop[i].h_t = c_h_t;
      }
      s_coop_ready = true;
    }
    taskEXIT_CRITICAL(&mux);
  }
  for (i = 0; i < NSETS; i++)
  {
    if (prm == s_up[i])
    {
      return &s_coop[i];
    }
  }
  return prm; /* not an slhdsa-c set (e.g. a *_hw set: yields by itself) */
}
