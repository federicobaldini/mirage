#pragma once

#include <cstdint>

// ============================================================
//  Theme — colour palette and layout constants for Mirage UI
//  All colours are 16-bit RGB565 for the ST7789 display.
// ============================================================

// ── Helper: pack RGB888 → RGB565 ─────────────────────────────
static constexpr uint16_t rgb(uint8_t r, uint8_t g, uint8_t b) {
    return ((r & 0xF8u) << 8) | ((g & 0xFCu) << 3) | (b >> 3);
}

namespace Theme {

// ── Shared backgrounds & neutrals ────────────────────────────
constexpr uint16_t BG            = rgb(  8,   8,  12);   // near-black
constexpr uint16_t BG_ITEM       = rgb( 18,  18,  26);   // menu row
constexpr uint16_t BG_SEL        = rgb( 34,  34,  48);   // selected row
constexpr uint16_t BG_HEADER     = rgb( 12,  12,  18);   // section header
constexpr uint16_t TEXT          = rgb(200, 200, 210);   // primary text
constexpr uint16_t TEXT_DIM      = rgb(100, 100, 115);   // dimmed / subtitle
constexpr uint16_t TEXT_BRIGHT   = rgb(240, 240, 255);   // highlighted text
constexpr uint16_t BORDER        = rgb( 50,  50,  65);   // divider lines

// ── Red team palette ─────────────────────────────────────────
constexpr uint16_t RED_ACCENT    = rgb(220,  40,  40);   // primary red
constexpr uint16_t RED_BRIGHT    = rgb(255,  80,  80);   // bright red (selected)
constexpr uint16_t RED_DIM       = rgb(120,  20,  20);   // muted red
constexpr uint16_t RED_GLOW      = rgb(180,  30,  30);   // status bar accent

// ── Blue team palette ─────────────────────────────────────────
constexpr uint16_t BLUE_ACCENT   = rgb( 40, 120, 220);   // primary blue
constexpr uint16_t BLUE_BRIGHT   = rgb( 80, 160, 255);   // bright blue (selected)
constexpr uint16_t BLUE_DIM      = rgb( 20,  60, 120);   // muted blue
constexpr uint16_t BLUE_GLOW     = rgb( 30,  90, 180);   // status bar accent

// ── Grey / system palette ────────────────────────────────────
constexpr uint16_t GREY_ACCENT   = rgb(160, 160, 185);   // primary grey
constexpr uint16_t GREY_BRIGHT   = rgb(220, 220, 240);   // bright grey (selected)
constexpr uint16_t GREY_DIM      = rgb( 50,  50,  70);   // muted grey
constexpr uint16_t GREY_GLOW     = rgb( 65,  65,  90);   // header strip

// ── Status indicator colours ──────────────────────────────────
constexpr uint16_t STATUS_OK     = rgb( 50, 200,  80);   // green
constexpr uint16_t STATUS_RUN    = rgb(220, 180,  40);   // amber
constexpr uint16_t STATUS_FAIL   = rgb(220,  50,  50);   // red
constexpr uint16_t STATUS_SKIP   = rgb( 90,  90, 110);   // grey
constexpr uint16_t STATUS_IDLE   = rgb( 60,  60,  80);   // dark grey

// ── Severity colours (blue threat feed) ──────────────────────
constexpr uint16_t SEV_INFO      = rgb( 60, 160, 220);
constexpr uint16_t SEV_WARN      = rgb(220, 160,  40);
constexpr uint16_t SEV_CRIT      = rgb(220,  40,  40);

// ── Layout geometry (px) ─────────────────────────────────────
constexpr int W              = 240;
constexpr int H              = 135;
constexpr int STATUS_BAR_Y   = H - 14;        // top of status bar
constexpr int STATUS_BAR_H   = 14;
constexpr int CONTENT_H      = H - STATUS_BAR_H; // usable area height
constexpr int HEADER_H       = 16;            // mode header strip
constexpr int MENU_TOP       = HEADER_H;      // first menu item Y
constexpr int MENU_ITEM_H    = 18;
constexpr int MENU_CONTENT_H = CONTENT_H - HEADER_H; // menu rows area

// ── Text sizes ───────────────────────────────────────────────
// M5GFX uses integer text-size multipliers
constexpr uint8_t FONT_SMALL  = 1;
constexpr uint8_t FONT_NORMAL = 1;
constexpr uint8_t FONT_LARGE  = 2;

}  // namespace Theme
