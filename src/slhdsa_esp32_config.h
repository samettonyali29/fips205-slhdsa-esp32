/*
 * slhdsa_esp32_config.h - build options of fips205-slhdsa-esp32
 *
 * Options can be enabled here, or as compiler flags (PlatformIO:
 * `build_flags = -DSLHDSA_ESP32_HW_SHA`; arduino-cli:
 * --build-property "compiler.c.extra_flags=-DSLHDSA_ESP32_HW_SHA"
 * --build-property "compiler.cpp.extra_flags=-DSLHDSA_ESP32_HW_SHA").
 * The Arduino IDE has no per-sketch compiler flags: uncomment the line below.
 *
 * Copyright (c) 2026 The fips205-slhdsa-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SLHDSA_ESP32_CONFIG_H
#define SLHDSA_ESP32_CONFIG_H

/*
 * SLHDSA_ESP32_HW_SHA  (default: off)
 *
 * Compute the SHA-2 hashes of the six SLH-DSA-SHA2-* parameter sets with
 * the ESP32's SHA hardware accelerator instead of in software (about 2x
 * faster on the original ESP32, see README). The SHAKE sets are not
 * affected (the ESP32 has no SHA-3 hardware).
 *
 * The C++ wrapper runs a self-test (hardware vs. software SHA-2) on first
 * use and silently falls back to the software implementation if it fails;
 * slhdsa_esp32_hw_sha_active() tells which one is in use.
 */
/* #define SLHDSA_ESP32_HW_SHA */

#endif /* SLHDSA_ESP32_CONFIG_H */
