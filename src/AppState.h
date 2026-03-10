#pragma once
#include <cstdint>

// ============================================================
//  AppState — shared global target / defended AP selection
//  Defined in AppState.cpp; extern'd wherever needed.
// ============================================================

struct SelectedAP {
    char    ssid[33]     = {};
    uint8_t bssid[6]     = {};
    uint8_t channel      = 0;
    int8_t  rssi         = 0;
    char    password[64] = {};   // optional for both target and defended
    bool    valid        = false;
};

extern SelectedAP g_targetAP;    // RED team attack target
extern SelectedAP g_defendedAP;  // BLUE team defended network
