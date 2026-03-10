#include "MenuBlue.h"
#include "Theme.h"
#include "../../include/config.h"
#include "../AppState.h"
#include <cstdio>

// ============================================================
//  MenuBlue — implementation
// ============================================================

MenuBlue::MenuBlue() {
    _items[0] = { "SEE EVERYTHING",
                  "Passive monitor: beacons, probes, clients, RSSI",
                  &_awareness };
    _items[1] = { "DETECT THREATS",
                  "Deauth flood, Evil Twin, rogue AP, beacon flood",
                  &_detection };
    _items[2] = { "LOCK IT DOWN",
                  "Audit APs, flag weak configs, hardening report",
                  &_hardening };
}

void MenuBlue::init() {
    _awareness.init();
    _detection.init();
    _hardening.init();
}

bool MenuBlue::update(char key) {
    if (_view == BlueView::MENU) {
        if (key == KEY_UP && _sel > 0) {
            uint8_t prev = _sel--;
            drawMenuRow(prev);
            drawMenuRow(_sel);
        } else if (key == KEY_DOWN && _sel < ITEM_COUNT - 1) {
            uint8_t prev = _sel++;
            drawMenuRow(prev);
            drawMenuRow(_sel);
        } else if (key == KEY_ENTER) {
            _view  = BlueView::PIPELINE;
            _dirty = true;
            launchSelected();
        }
    } else {
        if (key == KEY_ESC) {
            stopCurrent();
            _blocked = false;
            _view    = BlueView::MENU;
            _dirty   = true;
        }
    }

    if (_dirty) { draw(); _dirty = false; }
    return true;
}

void MenuBlue::draw() {
    if (_view == BlueView::MENU)
        drawMenu();
    else
        drawPipeline();
    drawStatusBar();
}

// ── Single row redraw (no-flicker navigation) ─────────────────
void MenuBlue::drawMenuRow(uint8_t i) {
    auto& d = M5.Display;
    int stride = Theme::MENU_ITEM_H * 2 + 2;
    int rowH   = Theme::MENU_ITEM_H * 2 + 1;
    int y      = Theme::MENU_TOP + i * stride;
    bool isSel = (i == _sel);

    uint16_t rowBg = isSel ? Theme::BG_SEL : Theme::BG_ITEM;
    d.fillRect(0, y, Theme::W, rowH, rowBg);
    if (isSel)
        d.fillRect(0, y, 3, rowH, Theme::BLUE_ACCENT);

    char buf[64];
    snprintf(buf, sizeof(buf), "%d. %s", i + 1, _items[i].title);
    d.setTextColor(isSel ? Theme::BLUE_BRIGHT : Theme::TEXT, rowBg);
    d.setTextSize(Theme::FONT_NORMAL);
    d.drawString(buf, 6, y + 2);

    d.setTextColor(Theme::TEXT_DIM, rowBg);
    d.drawString(_items[i].subtitle, 6, y + Theme::MENU_ITEM_H + 1);

    d.drawFastHLine(0, y + rowH, Theme::W, Theme::BORDER);
}

void MenuBlue::drawMenu() {
    auto& d = M5.Display;

    d.fillRect(0, 0, Theme::W, Theme::HEADER_H, Theme::BLUE_DIM);
    d.setTextColor(Theme::TEXT_BRIGHT, Theme::BLUE_DIM);
    d.setTextSize(Theme::FONT_NORMAL);
    d.drawString("[BLUE]  SELECT OBJECTIVE", 4, 2);

    d.fillRect(0, Theme::MENU_TOP, Theme::W,
               Theme::MENU_CONTENT_H - Theme::STATUS_BAR_H, Theme::BG);

    for (uint8_t i = 0; i < ITEM_COUNT; i++) {
        int y      = Theme::MENU_TOP + i * (Theme::MENU_ITEM_H * 2 + 2);
        bool isSel = (i == _sel);

        uint16_t rowBg = isSel ? Theme::BG_SEL : Theme::BG_ITEM;
        d.fillRect(0, y, Theme::W, Theme::MENU_ITEM_H * 2 + 1, rowBg);

        if (isSel)
            d.fillRect(0, y, 3, Theme::MENU_ITEM_H * 2 + 1, Theme::BLUE_ACCENT);

        char buf[64];
        snprintf(buf, sizeof(buf), "%d. %s", i + 1, _items[i].title);
        d.setTextColor(isSel ? Theme::BLUE_BRIGHT : Theme::TEXT, rowBg);
        d.setTextSize(Theme::FONT_NORMAL);
        d.drawString(buf, 6, y + 2);

        d.setTextColor(Theme::TEXT_DIM, rowBg);
        d.drawString(_items[i].subtitle, 6, y + Theme::MENU_ITEM_H + 1);

        d.drawFastHLine(0, y + Theme::MENU_ITEM_H * 2 + 1,
                        Theme::W, Theme::BORDER);
    }

    int hintY = Theme::STATUS_BAR_Y - 12;
    d.fillRect(0, hintY, Theme::W, 12, Theme::BG);
    d.setTextColor(Theme::TEXT_DIM, Theme::BG);
    d.drawString(" TAB:mode  ;/.:nav  ENTER:run  Fn+i/k", 0, hintY + 1);
}

void MenuBlue::drawPipeline() {
    auto& d = M5.Display;

    d.fillRect(0, 0, Theme::W, Theme::HEADER_H, Theme::BLUE_DIM);
    d.setTextColor(Theme::TEXT_BRIGHT, Theme::BLUE_DIM);
    d.setTextSize(Theme::FONT_NORMAL);
    char hdr[64];
    snprintf(hdr, sizeof(hdr), "[BLUE]  %s", _items[_sel].title);
    d.drawString(hdr, 4, 2);

    d.fillRect(0, Theme::MENU_TOP, Theme::W,
               Theme::CONTENT_H - Theme::HEADER_H - Theme::STATUS_BAR_H,
               Theme::BG);

    // Blocked: no defended AP selected
    if (_blocked) {
        int cy = Theme::MENU_TOP + 14;
        d.setTextColor(Theme::STATUS_FAIL, Theme::BG);
        d.drawString(" [!] NO DEFENDED AP SET", 4, cy);
        d.setTextColor(Theme::TEXT_DIM, Theme::BG);
        d.drawString(" Go to GREY > SET DEFENDED", 4, cy + 14);
        d.drawString(" then try again.", 4, cy + 26);
        d.drawString(" ESC:back", 4, Theme::STATUS_BAR_Y - 13);
        return;
    }

    IModule* mod = _items[_sel].module;
    uint8_t  stepCount = 0;
    const PipelineStep* steps = mod->getSteps(stepCount);
    int maxVisible = (Theme::CONTENT_H - Theme::HEADER_H - Theme::STATUS_BAR_H)
                     / (Theme::MENU_ITEM_H + 2);
    int scrollOffset = 0;

    for (uint8_t i = 0; i < stepCount; i++) {
        if (steps[i].status == StepStatus::RUNNING) {
            if ((int)i >= scrollOffset + maxVisible)
                scrollOffset = (int)i - maxVisible + 1;
            break;
        }
    }

    for (int i = scrollOffset;
         i < stepCount && i < scrollOffset + maxVisible; i++) {
        int y = Theme::MENU_TOP + (i - scrollOffset) * (Theme::MENU_ITEM_H + 2);
        drawStepRow(y, steps[i], steps[i].status == StepStatus::RUNNING);
    }

    extern uint32_t g_packetCount;
    extern uint8_t  g_currentChannel;

    const char* runDesc = nullptr;
    for (uint8_t i = 0; i < stepCount; i++) {
        if (steps[i].status == StepStatus::RUNNING) {
            runDesc = steps[i].description;
            break;
        }
    }

    int hintY1 = Theme::STATUS_BAR_Y - 24;
    int hintY2 = Theme::STATUS_BAR_Y - 12;
    d.fillRect(0, hintY1, Theme::W, 24, Theme::BG);
    d.setTextColor(Theme::TEXT_DIM, Theme::BG);
    if (runDesc) {
        char desc[42];
        snprintf(desc, sizeof(desc), " > %.37s", runDesc);
        d.drawString(desc, 0, hintY1 + 1);
        char stats[42];
        snprintf(stats, sizeof(stats), " CH:%02d | PKT:%-6lu | ESC:stop",
                 g_currentChannel, g_packetCount);
        d.drawString(stats, 0, hintY2 + 1);
    } else {
        d.drawString(" ESC:back", 0, hintY2 + 1);
    }
}

void MenuBlue::drawStepRow(int y, const PipelineStep& step, bool isCurrent) {
    auto& d = M5.Display;

    uint16_t bg = isCurrent ? Theme::BG_SEL : Theme::BG;
    d.fillRect(0, y, Theme::W, Theme::MENU_ITEM_H + 1, bg);

    if (isCurrent)
        d.fillRect(0, y, 3, Theme::MENU_ITEM_H + 1, Theme::BLUE_ACCENT);

    uint16_t badgeCol;
    switch (step.status) {
        case StepStatus::RUNNING: badgeCol = Theme::STATUS_RUN;  break;
        case StepStatus::OK:      badgeCol = Theme::STATUS_OK;   break;
        case StepStatus::FAIL:    badgeCol = Theme::STATUS_FAIL; break;
        case StepStatus::SKIP:    badgeCol = Theme::STATUS_SKIP; break;
        default:                  badgeCol = Theme::STATUS_IDLE; break;
    }

    char badge[5];
    if (step.status == StepStatus::RUNNING) {
        static const char spinChars[] = {'/', '-', '\\', '|'};
        snprintf(badge, sizeof(badge), "RUN%c", spinChars[(millis() / 200) & 3]);
    } else {
        strncpy(badge, stepStatusStr(step.status), sizeof(badge));
    }
    d.fillRect(2, y + 2, 32, 11, badgeCol);
    d.setTextColor(Theme::BG, badgeCol);
    d.drawString(badge, 3, y + 3);

    d.setTextColor(isCurrent ? Theme::TEXT_BRIGHT : Theme::TEXT, bg);
    d.drawString(step.name, 38, y + 3);

    d.drawFastHLine(0, y + Theme::MENU_ITEM_H + 1, Theme::W, Theme::BORDER);
}

void MenuBlue::drawStatusBar() {
    extern uint32_t g_packetCount;
    extern uint8_t  g_currentChannel;
    extern bool     g_sdReady;

    auto& d = M5.Display;
    d.fillRect(0, Theme::STATUS_BAR_Y, Theme::W, Theme::STATUS_BAR_H,
               Theme::BG_HEADER);
    d.drawFastHLine(0, Theme::STATUS_BAR_Y, Theme::W, Theme::BLUE_ACCENT);

    char buf[64];
    snprintf(buf, sizeof(buf), " BLUE| CH:%02d | PKT:%-6lu | SD:%s",
             g_currentChannel,
             g_packetCount,
             g_sdReady ? "OK" : "--");
    d.setTextColor(Theme::BLUE_ACCENT, Theme::BG_HEADER);
    d.drawString(buf, 0, Theme::STATUS_BAR_Y + 2);
}

void MenuBlue::launchSelected() {
    // Items 1-2 (threat detection / hardening) require a defended AP to be set
    if (_sel > 0 && !g_defendedAP.valid) {
        _blocked = true;
        return;
    }
    _blocked = false;
    _running = true;
    _items[_sel].module->setProgressCallback([this]() {
        drawPipeline();
        drawStatusBar();
    });
    _items[_sel].module->run();
    _items[_sel].module->setProgressCallback(nullptr);
    _running = false;
    _dirty   = true;
}

void MenuBlue::stopCurrent() {
    _items[_sel].module->stop();
    _running = false;
}
