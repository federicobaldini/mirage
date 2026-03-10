#pragma once

#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <cstring>
#include <cstdint>

// ============================================================
//  WiFi raw-frame helpers shared across Red and Blue modules
// ============================================================

// ── 802.11 frame-control subtypes ────────────────────────────
constexpr uint8_t FC_SUBTYPE_ASSOC_REQ    = 0x00;
constexpr uint8_t FC_SUBTYPE_ASSOC_RESP   = 0x01;
constexpr uint8_t FC_SUBTYPE_PROBE_REQ    = 0x04;
constexpr uint8_t FC_SUBTYPE_PROBE_RESP   = 0x05;
constexpr uint8_t FC_SUBTYPE_BEACON       = 0x08;
constexpr uint8_t FC_SUBTYPE_DISASSOC     = 0x0A;
constexpr uint8_t FC_SUBTYPE_AUTH         = 0x0B;
constexpr uint8_t FC_SUBTYPE_DEAUTH       = 0x0C;
constexpr uint8_t FC_TYPE_MGMT            = 0x00;
constexpr uint8_t FC_TYPE_CTRL            = 0x01;
constexpr uint8_t FC_TYPE_DATA            = 0x02;

// Packed 802.11 MAC header (24 bytes for 3-address frames)
#pragma pack(push, 1)
struct ieee80211_mac_hdr {
    uint16_t frame_ctrl;
    uint16_t duration;
    uint8_t  addr1[6];   // DA
    uint8_t  addr2[6];   // SA
    uint8_t  addr3[6];   // BSSID
    uint16_t seq_ctrl;
};

struct ieee80211_beacon_hdr {
    ieee80211_mac_hdr mac;
    uint64_t          timestamp;
    uint16_t          beacon_interval;
    uint16_t          capability;
};
#pragma pack(pop)

// Extract frame type (bits 2-3) and subtype (bits 4-7) from frame_ctrl
inline uint8_t fc_type(uint16_t fc)    { return (fc >> 2) & 0x03; }
inline uint8_t fc_subtype(uint16_t fc) { return (fc >> 4) & 0x0F; }

// True if this is a beacon frame
inline bool is_beacon(const wifi_promiscuous_pkt_t* p) {
    uint16_t fc;
    memcpy(&fc, p->payload, 2);
    return fc_type(fc) == FC_TYPE_MGMT && fc_subtype(fc) == FC_SUBTYPE_BEACON;
}

// True if this is a deauth frame
inline bool is_deauth(const wifi_promiscuous_pkt_t* p) {
    uint16_t fc;
    memcpy(&fc, p->payload, 2);
    return fc_type(fc) == FC_TYPE_MGMT && fc_subtype(fc) == FC_SUBTYPE_DEAUTH;
}

// True if this is a probe request
inline bool is_probe_req(const wifi_promiscuous_pkt_t* p) {
    uint16_t fc;
    memcpy(&fc, p->payload, 2);
    return fc_type(fc) == FC_TYPE_MGMT && fc_subtype(fc) == FC_SUBTYPE_PROBE_REQ;
}

// Extract SSID from beacon or probe-response payload.
// Returns number of chars written, 0 on error.
inline uint8_t extract_ssid(const uint8_t* payload, uint16_t len,
                              char* out, uint8_t out_max) {
    // payload starts at MAC header; beacon body starts at offset 36
    if (len < 38) return 0;
    const uint8_t* ie = payload + 36;   // first IE after fixed fields
    const uint8_t* end = payload + len;
    while (ie + 2 <= end) {
        uint8_t id  = ie[0];
        uint8_t iel = ie[1];
        if (id == 0) {  // SSID element
            uint8_t copy = (iel < out_max - 1) ? iel : (out_max - 1);
            memcpy(out, ie + 2, copy);
            out[copy] = '\0';
            return copy;
        }
        ie += 2 + iel;
    }
    return 0;
}

// Extract DS-parameter-set channel from beacon IEs.
inline uint8_t extract_channel_ie(const uint8_t* payload, uint16_t len) {
    if (len < 38) return 0;
    const uint8_t* ie  = payload + 36;
    const uint8_t* end = payload + len;
    while (ie + 2 <= end) {
        if (ie[0] == 3 && ie[1] == 1)  // DS param set
            return ie[2];
        ie += 2 + ie[1];
    }
    return 0;
}

// Check if RSN (WPA2) IE is present in beacon.
inline bool has_rsn_ie(const uint8_t* payload, uint16_t len) {
    if (len < 38) return false;
    const uint8_t* ie  = payload + 36;
    const uint8_t* end = payload + len;
    while (ie + 2 <= end) {
        if (ie[0] == 48) return true;  // RSN element
        ie += 2 + ie[1];
    }
    return false;
}

// Check if WPS IE is present in beacon.
inline bool has_wps_ie(const uint8_t* payload, uint16_t len) {
    if (len < 38) return false;
    const uint8_t* ie  = payload + 36;
    const uint8_t* end = payload + len;
    while (ie + 2 <= end) {
        // Vendor-specific IE (0xDD) with WPS OUI: 00-50-F2-04
        if (ie[0] == 0xDD && ie[1] >= 4) {
            if (ie[2] == 0x00 && ie[3] == 0x50 &&
                ie[4] == 0xF2 && ie[5] == 0x04)
                return true;
        }
        ie += 2 + ie[1];
    }
    return false;
}

// Build a deauthentication frame into buf.
// Returns total frame length.
inline int build_deauth(uint8_t* buf, const uint8_t* client_mac,
                         const uint8_t* ap_mac, uint16_t reason) {
    uint8_t frame[26] = {};
    frame[0] = 0xC0;  frame[1] = 0x00;   // FC: Deauth
    frame[2] = 0x3A;  frame[3] = 0x01;   // Duration
    memcpy(frame + 4,  client_mac, 6);     // DA
    memcpy(frame + 10, ap_mac,     6);     // SA
    memcpy(frame + 16, ap_mac,     6);     // BSSID
    frame[22] = 0x00;  frame[23] = 0x00;  // seq ctrl
    frame[24] = reason & 0xFF;
    frame[25] = (reason >> 8) & 0xFF;
    memcpy(buf, frame, 26);
    return 26;
}

// Inject a raw 802.11 frame via esp_wifi_80211_tx.
// wifi_if: WIFI_IF_STA or WIFI_IF_AP
inline esp_err_t inject_frame(wifi_interface_t wifi_if,
                               const uint8_t* buf, int len) {
    return esp_wifi_80211_tx(wifi_if, buf, len, false);
}

// ── OUI vendor lookup (abbreviated table) ────────────────────
static const struct { uint8_t oui[3]; const char* vendor; } kOuiTable[] = {
    {{0x00, 0x17, 0xF2}, "Apple"},
    {{0xAC, 0xBC, 0x32}, "Apple"},
    {{0x00, 0x1A, 0x11}, "Google"},
    {{0xF4, 0xF5, 0xDB}, "Google"},
    {{0x00, 0x14, 0xBF}, "Linksys"},
    {{0x00, 0x18, 0xF8}, "Linksys"},
    {{0x00, 0x22, 0xB0}, "Cisco"},
    {{0x00, 0x1B, 0xD5}, "Cisco"},
    {{0xC0, 0x3F, 0x0E}, "Netgear"},
    {{0x9C, 0x3D, 0xCF}, "Netgear"},
    {{0x00, 0x90, 0x4C}, "Epson"},
    {{0xEC, 0x08, 0x6B}, "TP-Link"},
    {{0x50, 0xD4, 0xF7}, "TP-Link"},
    {{0x00, 0x0F, 0xB5}, "Netgear"},
    {{0x00, 0x26, 0xB9}, "D-Link"},
    {{0x1C, 0xBD, 0xB9}, "D-Link"},
    {{0x00, 0x23, 0x69}, "ASUS"},
    {{0x04, 0x92, 0x26}, "ASUS"},
    {{0x00, 0x15, 0x6D}, "Ubiquiti"},
    {{0x78, 0x8A, 0x20}, "Ubiquiti"},
    {{0xDC, 0x9F, 0xDB}, "Ubiquiti"},
};

inline const char* oui_vendor(const uint8_t* mac) {
    for (const auto& entry : kOuiTable) {
        if (mac[0] == entry.oui[0] &&
            mac[1] == entry.oui[1] &&
            mac[2] == entry.oui[2])
            return entry.vendor;
    }
    return "Unknown";
}
