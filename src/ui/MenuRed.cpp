#include "MenuRed.h"
#include "Theme.h"
#include "../../include/config.h"
#include <cstdio>

// ============================================================
//  MenuRed — implementation
// ============================================================

MenuRed::MenuRed() {
    _items[0] = { "KNOW THE FIELD",
                  "Passive + active recon, fingerprint all APs",
                  &_recon };
    _items[1] = { "GET INSIDE",
                  "WPS, PMKID, deauth+handshake, open-portal",
                  &_infiltration };
    _items[2] = { "CONFUSE THE FIELD",
                  "Evil Twin, deauth flood, fake probes, captive portal",
                  &_deception };
    _items[3] = { "CAUSE CHAOS",
                  "Saturate air with random SSIDs (beacon flood)",
                  &_chaos };
}

void MenuRed::init() {
    _recon.init();
    _infiltration.init();
    _deception.init();
    _chaos.init();
}

bool MenuRed::update(char key) {
    if (_view == RedView::MENU) {
        if (key == KEY_UP && _sel > 0) {
            uint8_t prev = _sel--;
            drawMenuRow(prev);
            drawMenuRow(_sel);
        } else if (key == KEY_DOWN && _sel < ITEM_COUNT - 1) {
            uint8_t prev = _sel++;
            drawMenuRow(prev);
            drawMenuRow(_sel);
        } else if (key == KEY_ENTER) {
            _view = RedView::PIPELINE;
            _dirty = true;
            launchSelected();
        }
    } else {  // PIPELINE view
        if (key == KEY_ESC) {
            stopCurrent();
            _view  = RedView::MENU;
            _dirty = true;
        }
    }

    if (_dirty) { draw(); _dirty = false; }
    return true;
}

void MenuRed::draw() {
    if (_view == RedView::MENU)
        drawMenu();
    else
        drawPipeline();
    drawStatusBar();
}

// ── Single row redraw (no-flicker navigation) ─────────────────
void MenuRed::drawMenuRow(uint8_t i) {
    auto& d = M5.Display;
    int availH = Theme::STATUS_BAR_Y - Theme::MENU_TOP - 12;
    int stride  = availH / ITEM_COUNT;
    int rowH    = stride - 1;
    int y       = Theme::MENU_TOP + i * stride;
    bool isSel  = (i == _sel);

    uint16_t rowBg = isSel ? Theme::BG_SEL : Theme::BG_ITEM;
    d.fillRect(0, y, Theme::W, rowH, rowBg);
    if (isSel)
        d.fillRect(0, y, 3, rowH, Theme::RED_ACCENT);

    char buf[64];
    snprintf(buf, sizeof(buf), "%d. %s", i + 1, _items[i].title);
    d.setTextColor(isSel ? Theme::RED_BRIGHT : Theme::TEXT, rowBg);
    d.setTextSize(Theme::FONT_NORMAL);
    d.drawString(buf, 6, y + 2);

    if (rowH >= Theme::MENU_ITEM_H + 8) {
        d.setTextColor(Theme::TEXT_DIM, rowBg);
        d.drawString(_items[i].subtitle, 6, y + Theme::MENU_ITEM_H + 1);
    }

    d.drawFastHLine(0, y + rowH, Theme::W, Theme::BORDER);
}

// ── Menu view ─────────────────────────────────────────────────
void MenuRed::drawMenu() {
    auto& d = M5.Display;

    // Header
    d.fillRect(0, 0, Theme::W, Theme::HEADER_H, Theme::RED_GLOW);
    d.setTextColor(Theme::TEXT_BRIGHT, Theme::RED_GLOW);
    d.setTextSize(Theme::FONT_NORMAL);
    d.drawString("[RED]  SELECT OBJECTIVE", 4, 2);

    // Clear content area
    d.fillRect(0, Theme::MENU_TOP, Theme::W,
               Theme::MENU_CONTENT_H - Theme::STATUS_BAR_H, Theme::BG);

    // Dynamic stride: divide available content height evenly among items
    // Available area = STATUS_BAR_Y - MENU_TOP - hint row (12px)
    int availH = Theme::STATUS_BAR_Y - Theme::MENU_TOP - 12;
    int stride  = availH / ITEM_COUNT;   // px per row including divider
    int rowH    = stride - 1;            // row fill height (leave 1px for divider)

    for (uint8_t i = 0; i < ITEM_COUNT; i++) {
        int y      = Theme::MENU_TOP + i * stride;
        bool isSel = (i == _sel);

        uint16_t rowBg = isSel ? Theme::BG_SEL : Theme::BG_ITEM;
        d.fillRect(0, y, Theme::W, rowH, rowBg);

        if (isSel) {
            d.fillRect(0, y, 3, rowH, Theme::RED_ACCENT);
        }

        // Item number + title
        char buf[64];
        snprintf(buf, sizeof(buf), "%d. %s", i + 1, _items[i].title);
        d.setTextColor(isSel ? Theme::RED_BRIGHT : Theme::TEXT, rowBg);
        d.setTextSize(Theme::FONT_NORMAL);
        d.drawString(buf, 6, y + 2);

        // Subtitle (only if row is tall enough)
        if (rowH >= Theme::MENU_ITEM_H + 8) {
            d.setTextColor(Theme::TEXT_DIM, rowBg);
            d.drawString(_items[i].subtitle, 6, y + Theme::MENU_ITEM_H + 1);
        }

        d.drawFastHLine(0, y + rowH, Theme::W, Theme::BORDER);
    }

    // Hint at bottom of menu area
    int hintY = Theme::STATUS_BAR_Y - 12;
    d.fillRect(0, hintY, Theme::W, 12, Theme::BG);
    d.setTextColor(Theme::TEXT_DIM, Theme::BG);
    d.drawString(" TAB:mode  ;/.:nav  ENTER:run  Fn+i/k", 0, hintY + 1);
}

// ── Pipeline / checklist view ─────────────────────────────────
void MenuRed::drawPipeline() {
    auto& d = M5.Display;
    IModule* mod = _items[_sel].module;

    // Header
    d.fillRect(0, 0, Theme::W, Theme::HEADER_H, Theme::RED_GLOW);
    d.setTextColor(Theme::TEXT_BRIGHT, Theme::RED_GLOW);
    d.setTextSize(Theme::FONT_NORMAL);
    char hdr[64];
    snprintf(hdr, sizeof(hdr), "[RED]  %s", _items[_sel].title);
    d.drawString(hdr, 4, 2);

    d.fillRect(0, Theme::MENU_TOP, Theme::W,
               Theme::CONTENT_H - Theme::HEADER_H - Theme::STATUS_BAR_H,
               Theme::BG);

    uint8_t  stepCount = 0;
    const PipelineStep* steps = mod->getSteps(stepCount);
    int scrollOffset = 0;
    int maxVisible   = (Theme::CONTENT_H - Theme::HEADER_H - Theme::STATUS_BAR_H)
                       / (Theme::MENU_ITEM_H + 2);

    // find current running step for scroll
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

    // ESC hint
    d.setTextColor(Theme::TEXT_DIM, Theme::BG);
    int hintY = Theme::STATUS_BAR_Y - 12;
    d.fillRect(0, hintY, Theme::W, 12, Theme::BG);
    d.drawString(" ESC:abort", 0, hintY + 1);
}

void MenuRed::drawStepRow(int y, const PipelineStep& step, bool isCurrent) {
    auto& d = M5.Display;

    uint16_t bg = isCurrent ? Theme::BG_SEL : Theme::BG;
    d.fillRect(0, y, Theme::W, Theme::MENU_ITEM_H + 1, bg);

    // Status badge colour
    uint16_t badgeCol;
    switch (step.status) {
        case StepStatus::RUNNING: badgeCol = Theme::STATUS_RUN;  break;
        case StepStatus::OK:      badgeCol = Theme::STATUS_OK;   break;
        case StepStatus::FAIL:    badgeCol = Theme::STATUS_FAIL; break;
        case StepStatus::SKIP:    badgeCol = Theme::STATUS_SKIP; break;
        default:                  badgeCol = Theme::STATUS_IDLE; break;
    }

    // Badge: [STAT]
    d.fillRect(2, y + 2, 32, 11, badgeCol);
    d.setTextColor(Theme::BG, badgeCol);
    d.drawString(stepStatusStr(step.status), 3, y + 3);

    // Step name
    d.setTextColor(isCurrent ? Theme::TEXT_BRIGHT : Theme::TEXT, bg);
    d.drawString(step.name, 38, y + 3);

    // Divider
    d.drawFastHLine(0, y + Theme::MENU_ITEM_H + 1, Theme::W, Theme::BORDER);
}

// ── Status bar ────────────────────────────────────────────────
void MenuRed::drawStatusBar() {
    extern uint32_t g_packetCount;
    extern uint8_t  g_currentChannel;
    extern bool     g_sdReady;

    auto& d = M5.Display;
    d.fillRect(0, Theme::STATUS_BAR_Y, Theme::W, Theme::STATUS_BAR_H,
               Theme::BG_HEADER);
    d.drawFastHLine(0, Theme::STATUS_BAR_Y, Theme::W, Theme::RED_ACCENT);

    char buf[64];
    snprintf(buf, sizeof(buf), " RED | CH:%02d | PKT:%-6lu | SD:%s",
             g_currentChannel,
             g_packetCount,
             g_sdReady ? "OK" : "--");
    d.setTextColor(Theme::RED_ACCENT, Theme::BG_HEADER);
    d.drawString(buf, 0, Theme::STATUS_BAR_Y + 2);
}

// ── Launch ────────────────────────────────────────────────────
void MenuRed::launchSelected() {
    _running = true;
    _items[_sel].module->run();
    _running = false;
    _dirty   = true;
}

void MenuRed::stopCurrent() {
    _items[_sel].module->stop();
    _running = false;
}
