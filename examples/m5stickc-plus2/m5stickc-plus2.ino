/*
 * SLH-DSA (FIPS 205) live demo for the M5StickC PLUS2
 * (ESP32-PICO-V3-02, 1.14" 135x240 ST7789V2 display).
 *
 * Runs KeyGen -> Sign -> Verify rounds and shows the timing of every step,
 * the running averages and a fingerprint of the latest signature.
 *
 *   Button A (front, "M5"):  tamper test -- flips one bit of the latest
 *                            signature and shows that verification rejects it
 *   Button B (right side):   switch parameter set; the 6 fast ("f") sets
 *                            come first, then the 6 small-signature ("s") sets
 *
 * The "s" sets sign slowly (about a minute for SLH-DSA-SHA2-128s, several
 * minutes for SHAKE-256s), so the cryptography runs in its own task: the
 * display stays live and shows the elapsed time of the running step.
 * Button presses are applied when the current round has finished.
 * Every round is also logged on the serial port (115200 baud).
 *
 * With the SHA hardware backend enabled (SLHDSA_ESP32_HW_SHA, see
 * src/slhdsa_esp32_config.h) the SHA2 sets run about 2.5x faster; the
 * header then shows "HW".
 *
 * Requires the M5Unified library (Library Manager: "M5Unified"), which also
 * keeps the PLUS2 powered on battery (HOLD pin G4).
 * Board: "M5StickCPlus2" (esp32:esp32:m5stack_stickc_plus2).
 *
 * Copyright (c) 2026 The fips205-slhdsa-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <M5Unified.h>
#include <SLHDSA.h>

// Colors (RGB565)
#define COL_BG       0x0000
#define COL_HEADER   0x04B4  // teal (same in all three demos)
#define COL_CARD     0x2124
#define COL_ACTIVE   0x4A49  // card of the running step
#define COL_LABEL    0xBDF7
#define COL_OK       0x07E0
#define COL_ERR      0xF800
#define COL_WARN     0xFD20

// Buffers sized for the largest parameter set
static uint8_t pk[slhdsa_esp32::MAX_PUBLIC_KEY_SIZE];
static uint8_t sk[slhdsa_esp32::MAX_SECRET_KEY_SIZE];
static uint8_t sig[slhdsa_esp32::MAX_SIGNATURE_SIZE];
static size_t siglen;
static char msg[48];

// Display order: fast sets first
static const int ORDER[12] = {2, 3, 6, 7, 10, 11, 0, 1, 4, 5, 8, 9};
static const char *SET_NAME[12] = {
    "SHA2-128s", "SHAKE-128s", "SHA2-128f", "SHAKE-128f",
    "SHA2-192s", "SHAKE-192s", "SHA2-192f", "SHAKE-192f",
    "SHA2-256s", "SHAKE-256s", "SHA2-256f", "SHAKE-256f"};
static const char *OP_LABEL[3] = {"KeyGen", "Sign", "Verify"};

// ---- state shared between the crypto task and the UI (loop) --------------
struct Shared {
  int orderIdx;             // index into ORDER
  int phase;                // -1 idle, 0..2 running KeyGen/Sign/Verify
  uint32_t phaseStartMs;
  uint32_t runs, failures;
  uint64_t sumUs[3];
  uint32_t lastUs[3];
  uint8_t fp[4];            // signature fingerprint
  char status[32];
  uint16_t statusColor;
  bool haveSig;
};
static Shared st;
static portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
static volatile bool switchRequested = false, tamperRequested = false;

static void setStatus(const char *s, uint16_t color) {
  portENTER_CRITICAL(&mux);
  strncpy(st.status, s, sizeof(st.status) - 1);
  st.statusColor = color;
  portEXIT_CRITICAL(&mux);
}

static void setPhase(int phase) {
  portENTER_CRITICAL(&mux);
  st.phase = phase;
  st.phaseStartMs = millis();
  portEXIT_CRITICAL(&mux);
}

// ---- SLH-DSA operations for the selected parameter set ---------------------
template <class D>
int doOp(int op) {
  switch (op) {
    case 0: return D::generateKeypair(pk, sk);
    case 1: return D::sign(sig, &siglen, (const uint8_t *)msg, strlen(msg), sk);
    default: return D::verify(sig, siglen, (const uint8_t *)msg, strlen(msg), pk);
  }
}

template <class D>
bool usesHw() {
  return D::hardwareSha();
}

static bool hwFor(int set) {
  switch (set) {
    case 0:  return usesHw<SLHDSA_SHA2_128s>();
    case 2:  return usesHw<SLHDSA_SHA2_128f>();
    case 4:  return usesHw<SLHDSA_SHA2_192s>();
    case 6:  return usesHw<SLHDSA_SHA2_192f>();
    case 8:  return usesHw<SLHDSA_SHA2_256s>();
    case 10: return usesHw<SLHDSA_SHA2_256f>();
    default: return false;  // SHAKE sets: no SHA-3 hardware
  }
}

static int runOp(int set, int op) {
  switch (set) {
    case 0:  return doOp<SLHDSA_SHA2_128s>(op);
    case 1:  return doOp<SLHDSA_SHAKE_128s>(op);
    case 2:  return doOp<SLHDSA_SHA2_128f>(op);
    case 3:  return doOp<SLHDSA_SHAKE_128f>(op);
    case 4:  return doOp<SLHDSA_SHA2_192s>(op);
    case 5:  return doOp<SLHDSA_SHAKE_192s>(op);
    case 6:  return doOp<SLHDSA_SHA2_192f>(op);
    case 7:  return doOp<SLHDSA_SHAKE_192f>(op);
    case 8:  return doOp<SLHDSA_SHA2_256s>(op);
    case 9:  return doOp<SLHDSA_SHAKE_256s>(op);
    case 10: return doOp<SLHDSA_SHA2_256f>(op);
    default: return doOp<SLHDSA_SHAKE_256f>(op);
  }
}

static void cryptoTask(void *) {
  for (;;) {
    if (switchRequested) {
      switchRequested = false;
      portENTER_CRITICAL(&mux);
      int idx = (st.orderIdx + 1) % 12;
      memset(&st, 0, sizeof(st));
      st.orderIdx = idx;
      st.phase = -1;
      portEXIT_CRITICAL(&mux);
      Serial.printf("Switched to SLH-DSA-%s\n", SET_NAME[ORDER[idx]]);
      setStatus("starting...", COL_LABEL);
    }
    const int set = ORDER[st.orderIdx];

    if (tamperRequested) {
      tamperRequested = false;
      if (st.haveSig) {
        size_t pos = esp_random() % siglen;
        uint8_t bit = 1u << (esp_random() & 7);
        sig[pos] ^= bit;
        bool rejected = runOp(set, 2) != 0;
        sig[pos] ^= bit;
        Serial.printf("Tamper test (sig byte %u flipped): %s\n", (unsigned)pos,
                      rejected ? "REJECTED" : "NOT rejected!");
        setStatus(rejected ? "tamper REJECTED" : "tamper ACCEPTED!",
                  rejected ? COL_WARN : COL_ERR);
        vTaskDelay(pdMS_TO_TICKS(2500));
      }
      continue;
    }

    // One KeyGen -> Sign -> Verify round
    snprintf(msg, sizeof(msg), "M5StickC PLUS2 message #%lu",
             (unsigned long)st.runs);
    uint32_t us[3];
    int ret = 0;
    for (int op = 0; op < 3 && ret == 0; op++) {
      setPhase(op);
      uint32_t t0 = micros();
      ret = runOp(set, op);
      us[op] = micros() - t0;
      if (switchRequested && op < 2) break;  // abandon the round early
    }
    setPhase(-1);
    if (switchRequested) continue;
    memset(sk, 0, sizeof(sk));

    bool ok = ret == 0;
    portENTER_CRITICAL(&mux);
    st.runs++;
    if (!ok) st.failures++;
    for (int i = 0; i < 3; i++) {
      st.lastUs[i] = us[i];
      st.sumUs[i] += us[i];
    }
    memcpy(st.fp, sig, sizeof(st.fp));
    st.haveSig = ok;
    portEXIT_CRITICAL(&mux);
    setStatus(ok ? "signature VALID" : "FAILED", ok ? COL_OK : COL_ERR);
    Serial.printf("SLH-DSA-%s #%lu keygen=%.1fms sign=%.1fms verify=%.1fms %s\n",
                  SET_NAME[set], (unsigned long)st.runs, us[0] / 1000.0,
                  us[1] / 1000.0, us[2] / 1000.0, ok ? "VALID" : "FAILED");
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}

// ---- UI ------------------------------------------------------------------
static M5Canvas canvas(&M5.Display);  // off-screen buffer: flicker-free

// Times: "6.15 ms" below 100 ms, "123.4 ms" below 10 s, "54.27 s" above
// (same format in the ML-KEM, ML-DSA and SLH-DSA demos)
static void fmtTime(char *buf, size_t n, double ms) {
  if (ms < 100) {
    snprintf(buf, n, "%.2f ms", ms);
  } else if (ms < 10000) {
    snprintf(buf, n, "%.1f ms", ms);
  } else {
    snprintf(buf, n, "%.2f s", ms / 1000.0);
  }
}

// Header: small algorithm name + bold parameter set (same in all demos)
static void drawTitle(const char *alg, const char *variant) {
  canvas.setTextColor(TFT_WHITE, COL_HEADER);
  canvas.setTextDatum(middle_left);
  canvas.setFont(&fonts::Font2);
  canvas.drawString(alg, 6, 12);
  const int x = 6 + canvas.textWidth(alg) + 6;
  canvas.setFont(&fonts::FreeSansBold9pt7b);
  canvas.drawString(variant, x, 11);
  canvas.setFont(&fonts::Font2);
}

static void drawScreen() {
  Shared s;
  portENTER_CRITICAL(&mux);
  s = st;
  portEXIT_CRITICAL(&mux);
  const int W = canvas.width();
  const int set = ORDER[s.orderIdx];
  canvas.fillScreen(COL_BG);

  // Header
  canvas.fillRect(0, 0, W, 22, COL_HEADER);
  drawTitle("SLH-DSA", SET_NAME[set]);
  canvas.setTextDatum(middle_right);
  canvas.drawString(String(M5.Power.getBatteryLevel()) + "%", W - 5, 11);
  if (hwFor(set)) {
    canvas.drawString("HW", W - 46, 11);  // SHA hardware accelerator in use
  }

  // Timing rows: last run and average (or live elapsed time while running)
  canvas.setFont(&fonts::Font2);
  for (int i = 0; i < 3; i++) {
    int y = 26 + i * 21;
    const bool running = s.phase == i;
    const uint16_t bg = running ? COL_ACTIVE : COL_CARD;
    canvas.fillRoundRect(3, y, W - 6, 19, 4, bg);
    canvas.setTextDatum(middle_left);
    canvas.setTextColor(COL_LABEL, bg);
    canvas.drawString(OP_LABEL[i], 9, y + 10);
    char last[16], avg[16], buf[40];
    if (running) {
      fmtTime(last, sizeof(last), (double)(millis() - s.phaseStartMs));
      snprintf(buf, sizeof(buf), "running %s", last);
      canvas.setTextColor(COL_WARN, bg);
    } else if (s.runs == 0) {
      snprintf(buf, sizeof(buf), "-");
      canvas.setTextColor(TFT_WHITE, bg);
    } else {
      fmtTime(last, sizeof(last), s.lastUs[i] / 1000.0);
      fmtTime(avg, sizeof(avg), s.sumUs[i] / 1000.0 / s.runs);
      snprintf(buf, sizeof(buf), "%s  avg %s", last, avg);
      canvas.setTextColor(TFT_WHITE, bg);
    }
    canvas.setTextDatum(middle_right);
    canvas.drawString(buf, W - 9, y + 10);
  }

  // Signature fingerprint + status
  canvas.setTextDatum(middle_left);
  canvas.setTextColor(COL_LABEL, COL_BG);
  char fp[40];
  if (s.runs) {
    snprintf(fp, sizeof(fp), "sig: %02X%02X%02X%02X..", s.fp[0], s.fp[1],
             s.fp[2], s.fp[3]);
  } else {
    snprintf(fp, sizeof(fp), "sig: -");
  }
  canvas.drawString(fp, 6, 99);
  canvas.setTextColor(s.statusColor, COL_BG);
  canvas.setTextDatum(middle_right);
  canvas.drawString(s.status, W - 6, 99);

  // Footer
  canvas.setTextColor(COL_LABEL, COL_BG);
  canvas.setTextDatum(middle_left);
  char foot[48];
  snprintf(foot, sizeof(foot), "#%lu  fail %lu", (unsigned long)s.runs,
           (unsigned long)s.failures);
  canvas.drawString(foot, 6, 122);
  canvas.setTextDatum(middle_right);
  canvas.drawString(switchRequested ? "switching..." : "A:tamper B:level",
                    W - 6, 122);

  canvas.pushSprite(0, 0);
}

// ---- Arduino ---------------------------------------------------------------
void setup() {
  auto cfg = M5.config();
  M5.begin(cfg);
  Serial.begin(115200);
  M5.Display.setRotation(1);  // landscape, 240 x 135
  M5.Display.setBrightness(96);
  canvas.createSprite(M5.Display.width(), M5.Display.height());
  memset(&st, 0, sizeof(st));
  st.phase = -1;
  setStatus("ready", COL_LABEL);
  Serial.println("\nSLH-DSA live demo (M5StickC PLUS2)");
  // SLH-DSA needs < 5 KB of stack; core 0, the UI runs on core 1 (loop)
  xTaskCreatePinnedToCore(cryptoTask, "slhdsa", 12 * 1024, NULL, 1, NULL, 0);
}

void loop() {
  static uint32_t lastDraw = 0;
  M5.update();
  if (M5.BtnB.wasPressed()) switchRequested = true;
  if (M5.BtnA.wasPressed()) tamperRequested = true;
  if (millis() - lastDraw >= 200) {
    lastDraw = millis();
    drawScreen();
  }
  delay(10);
}
