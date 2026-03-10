#include "MenuGrey.h"
#include "Theme.h"
#include "../../include/config.h"
#include <cstdio>
#include <cstring>
#include <SD.h>

// ============================================================
//  MenuGrey — implementation
// ============================================================

extern uint32_t g_packetCount;
extern uint8_t  g_currentChannel;
extern bool     g_sdReady;

// ── Constructor ───────────────────────────────────────────────

MenuGrey::MenuGrey() {
    _items[0] = { "SCAN & ANALYZE" };
    _items[1] = { "SET TARGET"     };
    _items[2] = { "SET DEFENDED"   };
    _items[3] = { "SETTINGS"       };
}

void MenuGrey::init() {
    loadConfigFromSD();
}

// ── Helpers ───────────────────────────────────────────────────

const char* MenuGrey::encTag(wifi_auth_mode_t auth) {
    switch (auth) {
        case WIFI_AUTH_OPEN:          return "OPEN";
        case WIFI_AUTH_WEP:           return "WEP ";
        case WIFI_AUTH_WPA_PSK:       return "WPA ";
        case WIFI_AUTH_WPA2_PSK:
        case WIFI_AUTH_WPA_WPA2_PSK:  return "WPA2";
        case WIFI_AUTH_WPA3_PSK:      return "WPA3";
        default:                       return "    ";
    }
}

// ── WiFi scan ─────────────────────────────────────────────────

void MenuGrey::runScan() {
    // Disable any active promiscuous capture
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    esp_wifi_stop();
    esp_wifi_deinit();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();

    wifi_scan_config_t sc{};
    sc.scan_type = WIFI_SCAN_TYPE_ACTIVE;
    _aps.clear();

    if (esp_wifi_scan_start(&sc, true) == ESP_OK) {
        uint16_t n = 0;
        esp_wifi_scan_get_ap_num(&n);
        if (n > 64) n = 64;
        _aps.resize(n);
        esp_wifi_scan_get_ap_records(&n, _aps.data());
        _aps.resize(n);
    }

    esp_wifi_stop();
}

// ── Store selection ───────────────────────────────────────────

void MenuGrey::storeSelection() {
    if (_aps.empty() || _apSel >= (uint8_t)_aps.size()) return;
    const auto& ap  = _aps[_apSel];
    SelectedAP& dst = (_scanMode == ScanMode::TARGET) ? g_targetAP : g_defendedAP;
    memcpy(dst.ssid,  ap.ssid,  sizeof(dst.ssid));
    memcpy(dst.bssid, ap.bssid, 6);
    dst.channel = ap.primary;
    dst.rssi    = ap.rssi;
    dst.valid   = true;
}

void MenuGrey::storePassword() {
    SelectedAP& dst = (_scanMode == ScanMode::TARGET) ? g_targetAP : g_defendedAP;
    memcpy(dst.password, _pwBuf, sizeof(dst.password));
    saveConfigToSD();
}

// ── SD config persistence ─────────────────────────────────────

#define CONFIG_PATH  SD_LOG_DIR "/config.ini"

static void writeBssid(char* buf, size_t len, const uint8_t* b) {
    snprintf(buf, len, "%02X:%02X:%02X:%02X:%02X:%02X",
             b[0], b[1], b[2], b[3], b[4], b[5]);
}

static bool parseBssid(const char* s, uint8_t* b) {
    unsigned v[6];
    if (sscanf(s, "%02X:%02X:%02X:%02X:%02X:%02X",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return false;
    for (int i = 0; i < 6; i++) b[i] = (uint8_t)v[i];
    return true;
}

void MenuGrey::saveConfigToSD() {
    if (!g_sdReady) return;
    if (!SD.exists(SD_LOG_DIR)) SD.mkdir(SD_LOG_DIR);

    File f = SD.open(CONFIG_PATH, FILE_WRITE);
    if (!f) return;

    char bssid[20];
    auto writeAP = [&](const char* prefix, const SelectedAP& ap) {
        char line[96];
        writeBssid(bssid, sizeof(bssid), ap.bssid);
        snprintf(line, sizeof(line), "%s_SSID=%s\n",    prefix, ap.ssid);    f.print(line);
        snprintf(line, sizeof(line), "%s_BSSID=%s\n",   prefix, bssid);      f.print(line);
        snprintf(line, sizeof(line), "%s_CH=%d\n",      prefix, ap.channel); f.print(line);
        snprintf(line, sizeof(line), "%s_RSSI=%d\n",    prefix, ap.rssi);    f.print(line);
        snprintf(line, sizeof(line), "%s_PASS=%s\n",    prefix, ap.password);f.print(line);
        snprintf(line, sizeof(line), "%s_VALID=%d\n",   prefix, ap.valid);   f.print(line);
    };

    f.println("# Mirage config — auto-generated");
    if (g_targetAP.valid)   writeAP("TGT", g_targetAP);
    if (g_defendedAP.valid) writeAP("DEF", g_defendedAP);
    f.close();
}

void MenuGrey::loadConfigFromSD() {
    if (!g_sdReady) return;
    if (!SD.exists(CONFIG_PATH)) return;

    File f = SD.open(CONFIG_PATH, FILE_READ);
    if (!f) return;

    auto stripNL = [](char* s) {
        size_t l = strlen(s);
        while (l > 0 && (s[l-1] == '\n' || s[l-1] == '\r')) s[--l] = '\0';
    };

    char line[96];
    while (f.available()) {
        size_t n = 0;
        while (f.available() && n < sizeof(line) - 1) {
            char c = f.read();
            if (c == '\n') break;
            line[n++] = c;
        }
        line[n] = '\0';
        stripNL(line);
        if (line[0] == '#' || line[0] == '\0') continue;

        // Parse KEY=VALUE
        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char* key = line;
        const char* val = eq + 1;

        auto matchAP = [&](const char* prefix, SelectedAP& ap) {
            char k[32];
            snprintf(k, sizeof(k), "%s_SSID",  prefix); if (!strcmp(key, k)) { strncpy(ap.ssid, val, 32); return; }
            snprintf(k, sizeof(k), "%s_BSSID", prefix); if (!strcmp(key, k)) { parseBssid(val, ap.bssid); return; }
            snprintf(k, sizeof(k), "%s_CH",    prefix); if (!strcmp(key, k)) { ap.channel = (uint8_t)atoi(val); return; }
            snprintf(k, sizeof(k), "%s_RSSI",  prefix); if (!strcmp(key, k)) { ap.rssi    = (int8_t)atoi(val);  return; }
            snprintf(k, sizeof(k), "%s_PASS",  prefix); if (!strcmp(key, k)) { strncpy(ap.password, val, 63); return; }
            snprintf(k, sizeof(k), "%s_VALID", prefix); if (!strcmp(key, k)) { ap.valid   = atoi(val) != 0; return; }
        };
        matchAP("TGT", g_targetAP);
        matchAP("DEF", g_defendedAP);
    }
    f.close();
}

// ── Input handler ─────────────────────────────────────────────

bool MenuGrey::update(char key) {
    switch (_view) {

    case GreyView::MENU:
        if (key == KEY_UP && _sel > 0) {
            uint8_t prev = _sel--;
            drawMenuRow(prev);
            drawMenuRow(_sel);
        } else if (key == KEY_DOWN && _sel < ITEM_COUNT - 1) {
            uint8_t prev = _sel++;
            drawMenuRow(prev);
            drawMenuRow(_sel);
        } else if (key == KEY_ENTER) {
            if (_sel == 3) {
                _view = GreyView::SETTINGS;
                _dirty = true;
            } else {
                _scanMode = (_sel == 0) ? ScanMode::ANALYZE
                          : (_sel == 1) ? ScanMode::TARGET
                                        : ScanMode::DEFENDED;
                _apSel = 0;  _apScroll = 0;
                _view = GreyView::SCANNING;
                draw();           // show "Scanning..." before blocking call
                runScan();
                _view  = GreyView::AP_LIST;
                _dirty = true;
            }
        }
        break;

    case GreyView::AP_LIST:
        if (key == KEY_ESC) {
            _view = GreyView::MENU;  _dirty = true;
        } else if (key == KEY_UP && _apSel > 0) {
            _apSel--;
            if (_apSel < _apScroll) _apScroll = _apSel;
            _dirty = true;
        } else if (key == KEY_DOWN && _apSel + 1 < (uint8_t)_aps.size()) {
            _apSel++;
            if (_apSel >= _apScroll + MAX_VISIBLE)
                _apScroll = _apSel - MAX_VISIBLE + 1;
            _dirty = true;
        } else if (key == KEY_ENTER) {
            if (_scanMode == ScanMode::ANALYZE) {
                _view = GreyView::MENU;
            } else {
                storeSelection();   // store SSID/BSSID/ch/rssi
                // Ask for password for both TARGET and DEFENDED.
                // For OPEN networks in TARGET mode we still allow skip.
                _pwLen = 0;
                memset(_pwBuf, 0, sizeof(_pwBuf));
                _view = GreyView::PASSWORD;
            }
            _dirty = true;
        }
        break;

    case GreyView::PASSWORD:
        if (key == KEY_ESC) {
            // Skip password — keep selection, clear any previous password
            SelectedAP& dst = (_scanMode == ScanMode::TARGET) ? g_targetAP : g_defendedAP;
            memset(dst.password, 0, sizeof(dst.password));
            saveConfigToSD();
            _view = GreyView::MENU;  _dirty = true;
        } else if (key == KEY_ENTER) {
            storePassword();        // validates & saves to SD
            _view = GreyView::MENU;  _dirty = true;
        } else if (key == KEY_BACKSPACE) {
            if (_pwLen > 0) { _pwBuf[--_pwLen] = '\0'; _dirty = true; }
        } else if (key >= 0x20 && key < 0x7F && _pwLen < 63) {
            _pwBuf[_pwLen++] = key;
            _pwBuf[_pwLen]   = '\0';
            _dirty = true;
        }
        break;

    case GreyView::SETTINGS:
        if (key == KEY_ESC || key == KEY_ENTER) {
            _view = GreyView::MENU;  _dirty = true;
        }
        break;

    default: break;
    }

    if (_dirty) { draw(); _dirty = false; }
    return true;
}

// ── Draw dispatcher ───────────────────────────────────────────

void MenuGrey::draw() {
    switch (_view) {
        case GreyView::MENU:     drawMenu();     break;
        case GreyView::SCANNING: drawScanning(); break;
        case GreyView::AP_LIST:  drawApList();   break;
        case GreyView::PASSWORD: drawPassword(); break;
        case GreyView::SETTINGS: drawSettings(); break;
    }
    drawStatusBar();
}

// ── Single row redraw (no-flicker navigation) ─────────────────
void MenuGrey::drawMenuRow(uint8_t i) {
    auto& d = M5.Display;
    int availH = Theme::STATUS_BAR_Y - Theme::MENU_TOP - 12;
    int stride  = availH / ITEM_COUNT;
    int rowH    = stride - 1;
    int y       = Theme::MENU_TOP + i * stride;
    bool isSel  = (i == _sel);

    uint16_t rowBg = isSel ? Theme::BG_SEL : Theme::BG_ITEM;
    d.fillRect(0, y, Theme::W, rowH, rowBg);
    if (isSel)
        d.fillRect(0, y, 3, rowH, Theme::GREY_ACCENT);

    char buf[64];
    if (i == 1 && g_targetAP.valid)
        snprintf(buf, sizeof(buf), "%d. %s  [%.14s]", i + 1, _items[i].title, g_targetAP.ssid);
    else if (i == 2 && g_defendedAP.valid)
        snprintf(buf, sizeof(buf), "%d. %s  [%.12s]", i + 1, _items[i].title, g_defendedAP.ssid);
    else
        snprintf(buf, sizeof(buf), "%d. %s", i + 1, _items[i].title);

    d.setTextColor(isSel ? Theme::GREY_BRIGHT : Theme::TEXT, rowBg);
    d.setTextSize(Theme::FONT_NORMAL);
    d.drawString(buf, 6, y + (rowH - 8) / 2);
    d.drawFastHLine(0, y + rowH, Theme::W, Theme::BORDER);
}

// ── Menu view ─────────────────────────────────────────────────

void MenuGrey::drawMenu() {
    auto& d = M5.Display;

    d.fillRect(0, 0, Theme::W, Theme::HEADER_H, Theme::GREY_GLOW);
    d.setTextColor(Theme::TEXT_BRIGHT, Theme::GREY_GLOW);
    d.setTextSize(Theme::FONT_NORMAL);
    d.drawString("[SYS]  SELECT ACTION", 4, 2);

    d.fillRect(0, Theme::MENU_TOP, Theme::W,
               Theme::CONTENT_H - Theme::HEADER_H - Theme::STATUS_BAR_H, Theme::BG);

    int availH = Theme::STATUS_BAR_Y - Theme::MENU_TOP - 12;
    int stride = availH / ITEM_COUNT;
    int rowH   = stride - 1;

    for (uint8_t i = 0; i < ITEM_COUNT; i++) {
        int y = Theme::MENU_TOP + i * stride;
        bool isSel = (i == _sel);

        uint16_t rowBg = isSel ? Theme::BG_SEL : Theme::BG_ITEM;
        d.fillRect(0, y, Theme::W, rowH, rowBg);
        if (isSel)
            d.fillRect(0, y, 3, rowH, Theme::GREY_ACCENT);

        // Show currently selected network next to SET TARGET / SET DEFENDED
        char buf[64];
        if (i == 1 && g_targetAP.valid)
            snprintf(buf, sizeof(buf), "%d. %s  [%.14s]", i + 1, _items[i].title, g_targetAP.ssid);
        else if (i == 2 && g_defendedAP.valid)
            snprintf(buf, sizeof(buf), "%d. %s  [%.12s]", i + 1, _items[i].title, g_defendedAP.ssid);
        else
            snprintf(buf, sizeof(buf), "%d. %s", i + 1, _items[i].title);

        d.setTextColor(isSel ? Theme::GREY_BRIGHT : Theme::TEXT, rowBg);
        d.setTextSize(Theme::FONT_NORMAL);
        d.drawString(buf, 6, y + (rowH - 8) / 2);

        d.drawFastHLine(0, y + rowH, Theme::W, Theme::BORDER);
    }

    int hintY = Theme::STATUS_BAR_Y - 12;
    d.fillRect(0, hintY, Theme::W, 12, Theme::BG);
    d.setTextColor(Theme::TEXT_DIM, Theme::BG);
    d.drawString(" TAB:mode  ;/.:nav  ENTER:select", 0, hintY + 1);
}

// ── Scanning view ─────────────────────────────────────────────

void MenuGrey::drawScanning() {
    auto& d = M5.Display;

    d.fillRect(0, 0, Theme::W, Theme::HEADER_H, Theme::GREY_GLOW);
    d.setTextColor(Theme::TEXT_BRIGHT, Theme::GREY_GLOW);
    d.setTextSize(Theme::FONT_NORMAL);
    d.drawString("[SYS]  SCANNING...", 4, 2);

    d.fillRect(0, Theme::MENU_TOP, Theme::W,
               Theme::CONTENT_H - Theme::HEADER_H - Theme::STATUS_BAR_H, Theme::BG);

    d.setTextColor(Theme::GREY_ACCENT, Theme::BG);
    d.drawCentreString("Scanning WiFi networks...", Theme::W / 2, Theme::H / 2 - 8, 1);
    d.setTextColor(Theme::TEXT_DIM, Theme::BG);
    d.drawCentreString("Please wait", Theme::W / 2, Theme::H / 2 + 6, 1);
}

// ── AP list view ──────────────────────────────────────────────

void MenuGrey::drawApList() {
    auto& d = M5.Display;

    const char* label = (_scanMode == ScanMode::ANALYZE) ? "SCAN & ANALYZE"
                      : (_scanMode == ScanMode::TARGET)  ? "SET TARGET"
                                                         : "SET DEFENDED";
    char hdr[48];
    snprintf(hdr, sizeof(hdr), "[SYS]  %s  (%d)", label, (int)_aps.size());
    d.fillRect(0, 0, Theme::W, Theme::HEADER_H, Theme::GREY_GLOW);
    d.setTextColor(Theme::TEXT_BRIGHT, Theme::GREY_GLOW);
    d.setTextSize(Theme::FONT_NORMAL);
    d.drawString(hdr, 4, 2);

    d.fillRect(0, Theme::MENU_TOP, Theme::W,
               Theme::CONTENT_H - Theme::HEADER_H - Theme::STATUS_BAR_H, Theme::BG);

    if (_aps.empty()) {
        d.setTextColor(Theme::TEXT_DIM, Theme::BG);
        d.drawCentreString("No networks found", Theme::W / 2, Theme::H / 2, 1);
    } else {
        int rowH = Theme::MENU_ITEM_H;
        for (uint8_t i = 0; i < MAX_VISIBLE; i++) {
            uint8_t idx = _apScroll + i;
            if (idx >= (uint8_t)_aps.size()) break;
            const auto& ap  = _aps[idx];
            int  y          = Theme::MENU_TOP + i * (rowH + 1);
            bool isSel      = (idx == _apSel);

            uint16_t rowBg = isSel ? Theme::BG_SEL : Theme::BG_ITEM;
            d.fillRect(0, y, Theme::W, rowH, rowBg);
            if (isSel)
                d.fillRect(0, y, 3, rowH, Theme::GREY_ACCENT);

            // Encryption badge
            bool isOpen = (ap.authmode == WIFI_AUTH_OPEN);
            uint16_t encCol = isOpen ? Theme::STATUS_OK : Theme::STATUS_RUN;
            d.fillRect(4, y + 3, 28, 11, encCol);
            d.setTextColor(Theme::BG, encCol);
            d.drawString(encTag(ap.authmode), 5, y + 4);

            // SSID
            char ssid[22];
            snprintf(ssid, sizeof(ssid), "%.21s", (const char*)ap.ssid);
            d.setTextColor(isSel ? Theme::GREY_BRIGHT : Theme::TEXT, rowBg);
            d.drawString(ssid, 36, y + 4);

            // RSSI + channel (right side)
            char info[14];
            snprintf(info, sizeof(info), "%d C%d", ap.rssi, ap.primary);
            d.setTextColor(Theme::TEXT_DIM, rowBg);
            d.drawRightString(info, Theme::W - 2, y + 4, 1);

            d.drawFastHLine(0, y + rowH, Theme::W, Theme::BORDER);
        }
    }

    int hintY = Theme::STATUS_BAR_Y - 12;
    d.fillRect(0, hintY, Theme::W, 12, Theme::BG);
    d.setTextColor(Theme::TEXT_DIM, Theme::BG);
    d.drawString(_scanMode == ScanMode::ANALYZE
                     ? " ;/.:scroll  ENTER/ESC:back"
                     : " ;/.:scroll  ENTER:select  ESC:back",
                 0, hintY + 1);
}

// ── Password view ─────────────────────────────────────────────

void MenuGrey::drawPassword() {
    auto& d = M5.Display;

    bool isTarget = (_scanMode == ScanMode::TARGET);
    const SelectedAP& ap = isTarget ? g_targetAP : g_defendedAP;

    // Header
    d.fillRect(0, 0, Theme::W, Theme::HEADER_H, Theme::GREY_GLOW);
    d.setTextColor(Theme::TEXT_BRIGHT, Theme::GREY_GLOW);
    d.setTextSize(Theme::FONT_NORMAL);
    d.drawString(isTarget ? "[SYS]  SET TARGET — PASSWORD"
                          : "[SYS]  SET DEFENDED — PASSWORD", 4, 2);

    d.fillRect(0, Theme::MENU_TOP, Theme::W,
               Theme::CONTENT_H - Theme::HEADER_H - Theme::STATUS_BAR_H, Theme::BG);

    // Network name
    char label[48];
    snprintf(label, sizeof(label), "Network: %.26s", ap.ssid);
    d.setTextColor(Theme::GREY_ACCENT, Theme::BG);
    d.drawString(label, 4, Theme::MENU_TOP + 8);

    // Optional hint for target mode
    if (isTarget) {
        d.setTextColor(Theme::TEXT_DIM, Theme::BG);
        d.drawString("(optional — ESC to skip)", 4, Theme::MENU_TOP + 20);
    }

    // Password field
    int fieldY = isTarget ? Theme::MENU_TOP + 36 : Theme::MENU_TOP + 30;
    d.setTextColor(Theme::TEXT_DIM, Theme::BG);
    d.drawString("Password:", 4, fieldY);

    int boxY = fieldY + 14;
    d.fillRect(4, boxY, Theme::W - 8, 15, Theme::BG_ITEM);
    d.drawRect(4, boxY, Theme::W - 8, 15, Theme::GREY_ACCENT);

    // Show password as asterisks
    char stars[65] = {};
    for (uint8_t i = 0; i < _pwLen; i++) stars[i] = '*';
    d.setTextColor(Theme::TEXT_BRIGHT, Theme::BG_ITEM);
    d.drawString(stars, 8, boxY + 3);

    // Cursor
    int curX = 8 + _pwLen * 6;
    if (_pwLen < 63 && curX < Theme::W - 14)
        d.drawString("_", curX, boxY + 3);

    // Length validation hint (WPA2 min 8 chars)
    if (_pwLen > 0 && _pwLen < 8) {
        d.setTextColor(Theme::STATUS_FAIL, Theme::BG);
        d.drawString("WPA2: min 8 chars", 4, boxY + 20);
    }

    int hintY = Theme::STATUS_BAR_Y - 12;
    d.fillRect(0, hintY, Theme::W, 12, Theme::BG);
    d.setTextColor(Theme::TEXT_DIM, Theme::BG);
    d.drawString(isTarget ? " ENTER:save  DEL:back  ESC:skip"
                          : " ENTER:save  DEL:back  ESC:skip",
                 0, hintY + 1);
}

// ── Settings view ─────────────────────────────────────────────

void MenuGrey::drawSettings() {
    auto& d = M5.Display;

    d.fillRect(0, 0, Theme::W, Theme::HEADER_H, Theme::GREY_GLOW);
    d.setTextColor(Theme::TEXT_BRIGHT, Theme::GREY_GLOW);
    d.setTextSize(Theme::FONT_NORMAL);
    d.drawString("[SYS]  SETTINGS", 4, 2);

    d.fillRect(0, Theme::MENU_TOP, Theme::W,
               Theme::CONTENT_H - Theme::HEADER_H - Theme::STATUS_BAR_H, Theme::BG);

    int y  = Theme::MENU_TOP + 4;
    int lh = 13;

    auto row = [&](const char* key, const char* val) {
        d.setTextColor(Theme::TEXT_DIM, Theme::BG);
        d.drawString(key, 4, y);
        d.setTextColor(Theme::GREY_BRIGHT, Theme::BG);
        d.drawString(val, 92, y);
        y += lh;
    };

    char buf[32];

    snprintf(buf, sizeof(buf), "v" MIRAGE_VERSION);
    row("Firmware:", buf);

    snprintf(buf, sizeof(buf), "%d-%d  dwell %dms", SCAN_CHANNEL_MIN, SCAN_CHANNEL_MAX, SCAN_DWELL_MS);
    row("Channels:", buf);

    snprintf(buf, sizeof(buf), ">%d f/s", DEAUTH_FLOOD_THRESHOLD);
    row("Deauth thr:", buf);

    if (g_targetAP.valid) {
        snprintf(buf, sizeof(buf), "%.18s%s", g_targetAP.ssid,
                 g_targetAP.password[0] ? " [pw]" : "");
        row("Target:", buf);
    } else {
        row("Target:", "[not set]");
    }
    if (g_defendedAP.valid) {
        snprintf(buf, sizeof(buf), "%.16s%s", g_defendedAP.ssid,
                 g_defendedAP.password[0] ? " [pw]" : "");
        row("Defended:", buf);
    } else {
        row("Defended:", "[not set]");
    }
    row("SD:", g_sdReady ? "mounted" : "not found");

    int hintY = Theme::STATUS_BAR_Y - 12;
    d.fillRect(0, hintY, Theme::W, 12, Theme::BG);
    d.setTextColor(Theme::TEXT_DIM, Theme::BG);
    d.drawString(" ENTER/ESC:back", 0, hintY + 1);
}

// ── Status bar ────────────────────────────────────────────────

void MenuGrey::drawStatusBar() {
    auto& d = M5.Display;
    d.fillRect(0, Theme::STATUS_BAR_Y, Theme::W, Theme::STATUS_BAR_H, Theme::BG_HEADER);
    d.drawFastHLine(0, Theme::STATUS_BAR_Y, Theme::W, Theme::GREY_ACCENT);

    char buf[64];
    snprintf(buf, sizeof(buf), " SYS | TGT:%-14s | DEF:%.10s",
             g_targetAP.valid   ? g_targetAP.ssid   : "--",
             g_defendedAP.valid ? g_defendedAP.ssid : "--");
    d.setTextColor(Theme::GREY_ACCENT, Theme::BG_HEADER);
    d.drawString(buf, 0, Theme::STATUS_BAR_Y + 2);
}

// ── Stop ──────────────────────────────────────────────────────

void MenuGrey::stopCurrent() {
    _view  = GreyView::MENU;
    _dirty = true;
}
