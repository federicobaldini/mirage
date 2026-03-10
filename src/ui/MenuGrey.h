#pragma once

#include <M5Unified.h>
#include "../IModule.h"
#include "../AppState.h"
#include <vector>
#include <esp_wifi.h>

// ============================================================
//  MenuGrey — SYSTEM menu (scan, target selection, settings)
// ============================================================

enum class GreyView { MENU, SCANNING, AP_LIST, PASSWORD, SETTINGS };
enum class ScanMode { ANALYZE, TARGET, DEFENDED };

class MenuGrey {
public:
    MenuGrey();

    void init();
    bool update(char key);
    void draw();
    void stopCurrent();

    void drawStatusBar();

private:
    static constexpr uint8_t ITEM_COUNT  = 4;
    static constexpr uint8_t MAX_VISIBLE = 5;  // AP rows visible at once

    struct MenuItem { const char* title; };

    MenuItem _items[ITEM_COUNT];
    uint8_t  _sel      = 0;
    GreyView _view     = GreyView::MENU;
    ScanMode _scanMode = ScanMode::ANALYZE;
    bool     _dirty    = true;

    // AP list state
    std::vector<wifi_ap_record_t> _aps;
    uint8_t  _apSel    = 0;
    uint8_t  _apScroll = 0;

    // Password input state
    char    _pwBuf[64] = {};
    uint8_t _pwLen     = 0;

    void drawMenu();
    void drawMenuRow(uint8_t i);
    void drawScanning();
    void drawApList();
    void drawPassword();
    void drawSettings();

    void runScan();
    void storeSelection();
    void storePassword();
    void saveConfigToSD();
    void loadConfigFromSD();

    static const char* encTag(wifi_auth_mode_t auth);
};
