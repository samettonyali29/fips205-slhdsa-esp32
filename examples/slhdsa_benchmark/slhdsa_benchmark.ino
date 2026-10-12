/*
 * SLH-DSA benchmark for ESP32
 *
 * Measures, for all 12 SLH-DSA parameter sets (or a selection):
 *   - execution time of KeyGen, Sign and Verify (min / median / mean / max
 *     over the iterations, in milliseconds and CPU cycles)
 *   - peak stack usage of each operation (bytes). SLH-DSA allocates no
 *     heap memory; signatures (7.8-49.9 KB) live in a static buffer here.
 *
 * Each parameter set runs KeyGen, then Sign with the generated key, then
 * Verify of the last signature (plus a negative test), each operation in a
 * fresh task whose stack high-water mark gives the peak stack depth.
 *
 * Every signature is verified, so the benchmark doubles as a stress test.
 *
 * The "s" (small signature) parameter sets sign slowly -- tens of seconds
 * per signature for SLH-DSA-*-256s -- so the full run takes a while.
 * Build flags:
 *   -DBENCH_ITERATIONS=n   runs per operation (default 3; SLH-DSA timing
 *                          hardly varies, so a few runs suffice)
 *   -DBENCH_SETS=0x0CCC    bit mask of the parameter sets to run, bit i =
 *                          set i in the order of SET_NAME below (default:
 *                          all 12; 0x0CCC = only the "f" sets)
 *
 * Results are printed as a table and as CSV lines (prefix "CSV,"):
 *   CSV,parameter_set,operation,iterations,min_us,median_us,mean_us,max_us,min_cycles,stack_bytes
 *
 * Copyright (c) 2026 The fips205-slhdsa-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
/* No stack wiping inside the benchmark, so that the stack high-water mark
 * reflects the SLH-DSA operation itself (the wipe would touch 6 KB). */
#define SLHDSA_ESP32_WIPE_BYTES 0
#include <SLHDSA.h>
#include <esp_timer.h>

#ifndef BENCH_ITERATIONS
#define BENCH_ITERATIONS 3
#endif
#ifndef BENCH_SETS
#define BENCH_SETS 0x0FFF
#endif
static const int ITERATIONS = BENCH_ITERATIONS;
static const uint32_t TASK_STACK = 24 * 1024;

enum Op { OP_KEYGEN, OP_SIGN, OP_VERIFY };
static const char *OP_NAME[] = {"KeyGen", "Sign", "Verify"};
static const char *SET_NAME[12] = {
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHA2-192s", "SLH-DSA-SHAKE-192s", "SLH-DSA-SHA2-192f", "SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHA2-256s", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-256f"};

static const uint8_t MESSAGE[32] = {  // e.g. a SHA-256 digest of a document
    0x53, 0x4c, 0x48, 0x2d, 0x44, 0x53, 0x41, 0x20, 0x6f, 0x6e, 0x20,
    0x45, 0x53, 0x50, 0x33, 0x32, 0x20, 0x62, 0x65, 0x6e, 0x63, 0x68,
    0x6d, 0x61, 0x72, 0x6b, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61};

/* Timing in microseconds with the 64-bit esp_timer: the 32-bit CPU cycle
 * counter wraps after 17.9 s at 240 MHz, shorter than an "s" signature. */
static uint64_t usBuf[BENCH_ITERATIONS];

/* Key/signature buffers, sized for the largest parameter set. */
static struct {
  uint8_t pk[slhdsa_esp32::MAX_PUBLIC_KEY_SIZE];
  uint8_t sk[slhdsa_esp32::MAX_SECRET_KEY_SIZE];
  uint8_t sig[slhdsa_esp32::MAX_SIGNATURE_SIZE];
  size_t siglen;
} b;

/* Every operation runs in a fresh worker task, started by a small controller
 * task; the worker's stack high-water mark gives the peak stack depth of the
 * operation (a constant task overhead, measured with an empty job, is
 * subtracted). */
struct Job {
  int set;  // 0..11, or -1 for the empty (overhead) job
  Op op;
  /* results, microseconds */
  uint64_t umin, umed, umax;
  double umean;
  int errors;
  uint32_t freeStack;
  TaskHandle_t notify;
};

static int cmpU64(const void *x, const void *y) {
  uint64_t p = *(const uint64_t *)x, q = *(const uint64_t *)y;
  return (p > q) - (p < q);
}

template <class D>
int runOp(Op op) {
  switch (op) {
    case OP_KEYGEN: return D::generateKeypair(b.pk, b.sk);
    case OP_SIGN:   return D::sign(b.sig, &b.siglen, MESSAGE, sizeof MESSAGE, b.sk);
    default:        return D::verify(b.sig, b.siglen, MESSAGE, sizeof MESSAGE, b.pk);
  }
}

template <class D>
void timeOp(Job *j) {
  uint64_t sum = 0;
  j->errors = 0;
  for (int i = 0; i < ITERATIONS; i++) {
    int64_t t0 = esp_timer_get_time();
    int ret = runOp<D>(j->op);
    int64_t t1 = esp_timer_get_time();
    usBuf[i] = (uint64_t)(t1 - t0);
    sum += usBuf[i];
    if (ret != 0) j->errors++;
    vTaskDelay(1);  // let other tasks run between iterations
  }
  /* The signature must not verify for a different message. */
  if (j->op == OP_VERIFY) {
    static const uint8_t other[32] = {1};
    j->errors += D::verify(b.sig, b.siglen, other, sizeof other, b.pk) == 0;
  }
  qsort(usBuf, ITERATIONS, sizeof(uint64_t), cmpU64);
  j->umin = usBuf[0];
  j->umax = usBuf[ITERATIONS - 1];
  j->umed = usBuf[ITERATIONS / 2];
  j->umean = (double)sum / ITERATIONS;
}

#define DISPATCH(set, FN, ...)                         \
  switch (set) {                                       \
    case 0:  FN<SLHDSA_SHA2_128s>(__VA_ARGS__); break; \
    case 1:  FN<SLHDSA_SHAKE_128s>(__VA_ARGS__); break; \
    case 2:  FN<SLHDSA_SHA2_128f>(__VA_ARGS__); break; \
    case 3:  FN<SLHDSA_SHAKE_128f>(__VA_ARGS__); break; \
    case 4:  FN<SLHDSA_SHA2_192s>(__VA_ARGS__); break; \
    case 5:  FN<SLHDSA_SHAKE_192s>(__VA_ARGS__); break; \
    case 6:  FN<SLHDSA_SHA2_192f>(__VA_ARGS__); break; \
    case 7:  FN<SLHDSA_SHAKE_192f>(__VA_ARGS__); break; \
    case 8:  FN<SLHDSA_SHA2_256s>(__VA_ARGS__); break; \
    case 9:  FN<SLHDSA_SHAKE_256s>(__VA_ARGS__); break; \
    case 10: FN<SLHDSA_SHA2_256f>(__VA_ARGS__); break; \
    case 11: FN<SLHDSA_SHAKE_256f>(__VA_ARGS__); break; \
    default: break;                                    \
  }

static void worker(void *arg) {
  Job *j = (Job *)arg;
  DISPATCH(j->set, timeOp, j)
  j->freeStack = uxTaskGetStackHighWaterMark(NULL);
  xTaskNotifyGive(j->notify);
  vTaskDelete(NULL);
}

static bool runJob(Job &j) {
  j.notify = xTaskGetCurrentTaskHandle();
  if (xTaskCreate(worker, "worker", TASK_STACK, &j, 1, NULL) != pdPASS) {
    Serial.printf("  cannot create a task with %u bytes of stack\n", (unsigned)TASK_STACK);
    return false;
  }
  ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
  vTaskDelay(2);  // let the idle task free the deleted task
  return true;
}

static int totalErrors = 0;

static void benchSet(int set) {
  const uint32_t mhz = getCpuFrequencyMhz();
  Job empty = {-1, OP_KEYGEN};
  runJob(empty);
  int errors = 0;

  Serial.printf("\n--- %s ---\n", SET_NAME[set]);
  Serial.println("  Operation        min ms     median ms       mean ms        max ms   min Mcycles   stack B");
  for (int o = OP_KEYGEN; o <= OP_VERIFY; o++) {
    Job t = {set, (Op)o};
    if (!runJob(t)) return;
    errors += t.errors;
    const unsigned stack = empty.freeStack - t.freeStack;
    Serial.printf("  %-8s %13.1f %13.1f %13.1f %13.1f %13.1f %9u\n", OP_NAME[o],
                  t.umin / 1000.0, t.umed / 1000.0, t.umean / 1000.0,
                  t.umax / 1000.0, (double)t.umin * mhz / 1e6, stack);
    Serial.printf("CSV,%s,%s,%d,%llu,%llu,%.0f,%llu,%llu,%u\n", SET_NAME[set],
                  OP_NAME[o], ITERATIONS, (unsigned long long)t.umin,
                  (unsigned long long)t.umed, t.umean,
                  (unsigned long long)t.umax,
                  (unsigned long long)(t.umin * mhz), stack);
  }
  Serial.printf("  Correctness: %s (%d errors)\n", errors ? "FAILED" : "OK", errors);
  totalErrors += errors;
  memset(b.sk, 0, sizeof b.sk);
}

static void benchTask(void *) {
  Serial.println();
  Serial.println("==============================================");
  Serial.println("  SLH-DSA (FIPS 205) benchmark");
  Serial.println("==============================================");
  Serial.printf("Chip: %s rev %u, %u cores @ %u MHz, flash %u MB, PSRAM %u KB\n",
                ESP.getChipModel(), ESP.getChipRevision(), ESP.getChipCores(),
                (unsigned)getCpuFrequencyMhz(), (unsigned)(ESP.getFlashChipSize() >> 20),
                (unsigned)(ESP.getPsramSize() >> 10));
  Serial.printf("ESP-IDF %s, %d iterations per operation, %u-byte message\n",
                esp_get_idf_version(), ITERATIONS, (unsigned)sizeof MESSAGE);
  const uint32_t heapBefore = ESP.getFreeHeap();
  const unsigned long t0 = millis();

  for (int set = 0; set < 12; set++) {
    if (BENCH_SETS & (1 << set)) benchSet(set);
  }

  Serial.printf("\nFree heap: before %u, after %u bytes. Total time %lu s.\n",
                (unsigned)heapBefore, (unsigned)ESP.getFreeHeap(),
                (millis() - t0) / 1000);
  Serial.printf("Correctness overall: %s\n", totalErrors ? "FAILED" : "OK");
  Serial.println("Benchmark complete.");
  vTaskDelete(NULL);
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  xTaskCreate(benchTask, "bench", 8192, NULL, 1, NULL);  // controller
}

void loop() {
  delay(1000);
}
