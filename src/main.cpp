// ============================================================
//  Mirage — ESP32-S3 / M5Stack Cardputer
//  Dual-interface WiFi security tool (educational / lab use)
// ============================================================
//
//  LEGAL NOTICE
//  ─────────────────────────────────────────────────────────────
//  This firmware is intended strictly for:
//    • Authorised penetration testing on networks you own or
//      have explicit written permission to test.
//    • Controlled lab environments for security research.
//    • CTF competitions and educational coursework.
//
//  Using this tool against networks without authorisation is
//  illegal in most jurisdictions (e.g. CFAA, Computer Misuse
//  Act, EU Directive 2013/40/EU). The authors accept no
//  liability for misuse.
// ============================================================

#include <M5Cardputer.h>
#include <M5Unified.h>
#include <SD.h>
#include <esp_wifi.h>
#include <memory>
#include "utility/Keyboard/KeyboardReader/TCA8418.h"

#include "ui/Theme.h"
#include "ui/MenuRed.h"
#include "ui/MenuBlue.h"
#include "ui/MenuGrey.h"
#include "AppState.h"
#include "../include/config.h"

// ── Global state (also declared extern in menu/module files) ──
uint32_t g_packetCount    = 0;
uint8_t  g_currentChannel = 1;
bool     g_sdReady        = false;

// ── Mode ──────────────────────────────────────────────────────
enum class AppMode { RED, BLUE, GREY };
static AppMode  s_mode   = AppMode::RED;
static MenuRed  s_menuRed;
static MenuBlue s_menuBlue;
static MenuGrey s_menuGrey;
static bool     s_needFullRedraw = true;

// ── Splash ────────────────────────────────────────────────────
static void drawSplash() {
    auto& d = M5.Display;
    d.fillScreen(Theme::BG);

    static const char* title = "MIRAGE";
    d.setTextSize(Theme::FONT_LARGE);

    int titleW = strlen(title) * 12;
    int startX = (Theme::W - titleW) / 2;
    int titleY = Theme::H / 2 - 20;

    for (int i = 0; title[i]; i++) {
        uint16_t col = (i % 2 == 0) ? Theme::RED_ACCENT : Theme::BLUE_ACCENT;
        char ch[2] = { title[i], '\0' };
        d.setTextColor(col, Theme::BG);
        d.drawString(ch, startX + i * 12, titleY);
        delay(80);
    }

    d.setTextSize(Theme::FONT_NORMAL);
    d.setTextColor(Theme::TEXT_DIM, Theme::BG);
    d.drawCentreString("WiFi Security Lab Tool", Theme::W / 2, titleY + 26, 1);
    d.drawCentreString("v" MIRAGE_VERSION, Theme::W / 2, titleY + 38, 1);

    d.drawFastHLine(20, titleY + 50, Theme::W - 40, Theme::BORDER);

    d.setTextColor(Theme::STATUS_FAIL, Theme::BG);
    d.drawCentreString("AUTHORISED USE ONLY", Theme::W / 2, titleY + 58, 1);

    int barY = Theme::H - 20;
    int barX = 20;
    int barW = Theme::W - 40;
    d.drawRect(barX, barY, barW, 6, Theme::BORDER);

    uint32_t start = millis();
    while (millis() - start < SPLASH_DURATION_MS) {
        float prog = (float)(millis() - start) / SPLASH_DURATION_MS;
        int   fill = (int)(prog * (barW - 2));
        uint16_t barCol = (prog < 0.5f) ? Theme::RED_ACCENT : Theme::BLUE_ACCENT;
        d.fillRect(barX + 1, barY + 1, fill, 4, barCol);
        delay(20);
    }
}

// ── SD initialisation ─────────────────────────────────────────
static void initSD() {
    g_sdReady = (SD.cardType() != CARD_NONE);
    if (!g_sdReady) {
        // SPI(40 MHz, MOSI=14, MISO=39, SCK=40, CS=12) — Cardputer wiring.
        g_sdReady = SD.begin(12, SPI, 40000000);
    }
    if (g_sdReady && !SD.exists(SD_LOG_DIR)) {
        SD.mkdir(SD_LOG_DIR);
    }
}

// ── Mode-switch animation ─────────────────────────────────────
static void drawModeTransition(AppMode to) {
    auto& d = M5.Display;
    uint16_t col = (to == AppMode::RED)  ? Theme::RED_ACCENT
                 : (to == AppMode::BLUE) ? Theme::BLUE_ACCENT
                                         : Theme::GREY_ACCENT;
    for (int x = 0; x <= Theme::W; x += 8) {
        d.fillRect(x, 0, 8, Theme::H, col);
        delay(4);
    }
    delay(60);
}

// ── Full-screen redraw dispatcher ─────────────────────────────
static void fullRedraw() {
    M5.Display.fillScreen(Theme::BG);
    if      (s_mode == AppMode::RED)  s_menuRed.draw();
    else if (s_mode == AppMode::BLUE) s_menuBlue.draw();
    else                              s_menuGrey.draw();
    s_needFullRedraw = false;
}

// ── Arduino setup ─────────────────────────────────────────────
void setup() {
    Serial.begin(115200);
    delay(200);

    // Pass enableKeyboard=false so M5Cardputer.begin() does NOT call
    // Keyboard.begin() automatically.  We call it exactly once below,
    // after all other inits, to prevent SD.begin() or module inits from
    // clobbering the GPIO11 interrupt used by the TCA8418.
    M5Cardputer.begin(false);

    M5.Display.setBrightness(180);
    M5.Display.setRotation(1);
    M5.Display.setTextFont(0);
    M5.Display.setTextSize(1);

    drawSplash();

    initSD();
    s_menuRed.init();
    s_menuBlue.init();
    s_menuGrey.init();

    // ── Keyboard init AFTER all other inits ───────────────────
    // SD.begin() on ESP32-S3 may reconfigure GPIO11 (default SPI MOSI),
    // which is also the TCA8418 INT pin.  Initialising the keyboard last
    // ensures the GPIO11 interrupt is attached after everything else.
    M5Cardputer.Keyboard.begin(std::make_unique<TCA8418KeyboardReader>());

    // Drain any stale TCA8418 FIFO events before entering the main loop.
    for (uint8_t i = 0; i < 20; i++) {
        M5Cardputer.Keyboard.updateKeyList();
        M5Cardputer.Keyboard.updateKeysState();
        delay(5);
    }

    s_needFullRedraw = true;
}

// ── Arduino loop ──────────────────────────────────────────────
void loop() {
    // M5Cardputer.update() skips keyboard when _enableKeyboard=false, so we
    // call M5.update() for buttons/power and the keyboard methods directly.
    M5.update();
    M5Cardputer.Keyboard.updateKeyList();
    M5Cardputer.Keyboard.updateKeysState();

    // ── Keyboard input ───────────────────────────────────────
    char pressedKey = 0;

    if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
        // IMPORTANT: updateKeysState() routes ENTER, TAB, and BACKSPACE to
        // boolean flags — they are NEVER placed in kstate.word.
        const Keyboard_Class::KeysState& kstate = M5Cardputer.Keyboard.keysState();

        if (kstate.enter) {
            pressedKey = KEY_ENTER;
        } else if (kstate.del) {
            pressedKey = KEY_BACKSPACE;
        } else if (kstate.tab) {
            pressedKey = KEY_TAB;
        } else if (!kstate.word.empty()) {
            pressedKey = kstate.word[0];

            // FN + i/j/k/l → navigation (secondary bindings alongside `;`/`.`/`,`/`/`).
            if (kstate.fn) {
                switch (pressedKey) {
                    case 'i': pressedKey = KEY_UP;    break;
                    case 'k': pressedKey = KEY_DOWN;  break;
                    case 'j': pressedKey = KEY_LEFT;  break;
                    case 'l': pressedKey = KEY_RIGHT; break;
                    case '`': pressedKey = KEY_ESC;   break;
                    default:  pressedKey = 0;         break;
                }
            }
        }

        // TAB: cycle RED → BLUE → GREY → RED
        if (pressedKey == KEY_TAB) {
            if      (s_mode == AppMode::RED)  s_menuRed.stopCurrent();
            else if (s_mode == AppMode::BLUE) s_menuBlue.stopCurrent();
            else                              s_menuGrey.stopCurrent();

            AppMode next = (s_mode == AppMode::RED)  ? AppMode::BLUE
                         : (s_mode == AppMode::BLUE) ? AppMode::GREY
                                                     : AppMode::RED;
            drawModeTransition(next);
            s_mode = next;
            s_needFullRedraw = true;
            pressedKey = 0;  // consumed
        }
    }

    // ── Initial / post-transition full redraw ────────────────
    if (s_needFullRedraw) {
        fullRedraw();
    }

    // ── Route key to active menu ─────────────────────────────
    if (pressedKey != 0) {
        if      (s_mode == AppMode::RED)  s_menuRed.update(pressedKey);
        else if (s_mode == AppMode::BLUE) s_menuBlue.update(pressedKey);
        else                              s_menuGrey.update(pressedKey);
    }

    // ── Periodic status bar refresh (~4 Hz) ──────────────────
    static uint32_t lastStatusRefresh = millis();
    if (millis() - lastStatusRefresh > 250) {
        lastStatusRefresh = millis();
        if      (s_mode == AppMode::RED)  s_menuRed.drawStatusBar();
        else if (s_mode == AppMode::BLUE) s_menuBlue.drawStatusBar();
        else                              s_menuGrey.drawStatusBar();
    }

    delay(10);
}
