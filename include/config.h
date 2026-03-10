#pragma once

// ============================================================
//  Mirage — Global Tunable Parameters
// ============================================================

// ── Firmware identity ────────────────────────────────────────
#define MIRAGE_VERSION       "0.1.0"
#define MIRAGE_BUILD_DATE    __DATE__

// ── Channel scanning ─────────────────────────────────────────
// Dwell time on each channel during passive scan (ms)
#define SCAN_DWELL_MS             120
// Full channel-hop cycle interval (ms) for monitor mode
#define HOP_INTERVAL_MS            80
// 2.4 GHz channels to scan (1-13; US: 1-11)
#define SCAN_CHANNEL_MIN            1
#define SCAN_CHANNEL_MAX           13

// ── Deauth / attack detection ─────────────────────────────────
// Frames/second threshold above which a deauth flood is flagged
#define DEAUTH_FLOOD_THRESHOLD     20
// Window (ms) for counting deauth frames in detection
#define DEAUTH_WINDOW_MS         1000
// Number of deauths sent per burst in infiltration
#define DEAUTH_BURST_COUNT         64
// Interval between deauth bursts (ms)
#define DEAUTH_BURST_INTERVAL_MS  200
// Min deauth burst peak to flag handshake-harvest pattern in detection
#define DEAUTH_BURST_MIN           10

// ── Handshake / PMKID capture ─────────────────────────────────
// Max time to wait for a 4-way handshake after deauth (ms)
#define HANDSHAKE_TIMEOUT_MS     30000
// Max time to wait for a PMKID frame (ms)
#define PMKID_TIMEOUT_MS         15000

// ── Evil Twin / Captive Portal ────────────────────────────────
// 0 = minimal redirect page, 1 = WiFi login clone
#define EVIL_TWIN_PORTAL_TYPE        0
// SSID to broadcast when no target is selected
#define EVIL_TWIN_DEFAULT_SSID   "Free_WiFi"
// AP channel for Evil Twin
#define EVIL_TWIN_CHANNEL            6
// Max captive-portal credential log entries kept in RAM
#define PORTAL_CRED_RING_SIZE       32

// ── Beacon flood ─────────────────────────────────────────────
// Number of fake SSIDs to broadcast in chaos mode
#define BEACON_FLOOD_COUNT         128
// Interval between beacon transmissions (ms)
#define BEACON_FLOOD_INTERVAL_MS    10

// ── WPS brute-force ──────────────────────────────────────────
// Timeout for Pixie Dust exchange (ms)
#define WPS_PIXIE_TIMEOUT_MS      8000
// Max WPS PIN attempts before giving up
#define WPS_PIN_MAX_ATTEMPTS     1000

// ── Threat detection thresholds ───────────────────────────────
// Unique SSIDs appearing within this window triggers beacon-flood alert (ms)
#define BEACON_FLOOD_WINDOW_MS    5000
// Unique SSID count within above window to flag as flood
#define BEACON_FLOOD_SSID_THRESH   30
// RSSI delta (dBm) to flag a possible Evil Twin with stronger signal
#define EVIL_TWIN_RSSI_DELTA        8

// ── SD card ──────────────────────────────────────────────────
// Root directory for all Mirage logs and captures
#define SD_LOG_DIR               "/mirage"
// Maximum PCAP file size before rotation (bytes)
#define PCAP_MAX_FILE_SIZE       (4 * 1024 * 1024)

// ── Display geometry (ST7789 240x135) ───────────────────────
// NOTE: DISPLAY_W/H, STATUS_BAR_H, MENU_ITEM_H are defined as constexpr
// in src/ui/Theme.h (inside namespace Theme) to avoid Arduino macro clashes.
#define SPLASH_DURATION_MS     2000

// ── FreeRTOS ─────────────────────────────────────────────────
#define SNIFF_TASK_STACK       8192
#define SNIFF_TASK_PRIORITY       5
#define UI_TASK_STACK          4096
#define UI_TASK_PRIORITY          3

// ── Keyboard key codes (Cardputer physical layout) ────────────
// These are character values from kstate.word[0], NOT HID scan codes.
// Undefine any conflicting Arduino/M5Cardputer macros first.
#undef KEY_UP
#undef KEY_DOWN
#undef KEY_LEFT
#undef KEY_RIGHT
#undef KEY_ENTER
#undef KEY_TAB
#undef KEY_ESC
#undef KEY_BACKSPACE
#define KEY_UP                 ';'
#define KEY_DOWN               '.'
#define KEY_LEFT               ','
#define KEY_RIGHT              '/'
#define KEY_ENTER              '\n'
#define KEY_TAB                '\t'
#define KEY_ESC                '`'
#define KEY_BACKSPACE          '\b'
