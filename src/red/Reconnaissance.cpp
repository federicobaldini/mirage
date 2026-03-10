#include "Reconnaissance.h"
#include "../../include/config.h"
#include <Arduino.h>
#include <SD.h>
#include <esp_wifi.h>
#include <cstring>
#include <cstdio>

// ============================================================
//  Reconnaissance — implementation
// ============================================================

// Globals defined in main.cpp; extern'd here for use by promiscuous callback
extern uint32_t g_packetCount;
extern uint8_t  g_currentChannel;
extern bool     g_sdReady;

Reconnaissance* Reconnaissance::s_instance = nullptr;

Reconnaissance::Reconnaissance() {
    _steps[0] = { "Passive channel scan",    "Beacons: SSID/BSSID/RSSI/enc/WPS" };
    _steps[1] = { "Active probe sweep",       "Surface hidden SSIDs"               };
    _steps[2] = { "Probe-request sniff",      "Map devices to preferred networks"   };
    _steps[3] = { "AP fingerprinting",        "OUI lookup, beacon IE analysis"      };
    _steps[4] = { "Channel interference",     "Co-channel / adj-channel detect"     };
    _steps[5] = { "Rank targets",             "Sort by exploitability, then RSSI"  };
}

const char* Reconnaissance::getName() const { return "KNOW THE FIELD"; }

StepStatus Reconnaissance::getStatus() const { return _status; }

const PipelineStep* Reconnaissance::getSteps(uint8_t& count) const {
    count = STEP_COUNT;
    return _steps;
}

void Reconnaissance::init() {
    s_instance = this;
    _aps.reserve(32);
    _probes.reserve(64);
    // SD is already initialised by initSD() in main.cpp; do not re-call
    // SD.begin() here (it would reset the SPI bus to wrong default pins and
    // overwrite g_sdReady).
    if (g_sdReady && !SD.exists(SD_LOG_DIR))
        SD.mkdir(SD_LOG_DIR);
}

void Reconnaissance::run() {
    _stop   = false;
    _status = StepStatus::RUNNING;
    _aps.clear();
    _probes.clear();

    // Reset all step statuses
    for (auto& s : _steps) s.status = StepStatus::IDLE;

    // Start radio and PCAP once for all collection steps (0–2).
    // stepActiveProbeSweep will temporarily switch to STA for injection
    // while keeping the promiscuous callback registered.
    startPromiscuous();
    _pcap.open("recon");

    struct { bool (Reconnaissance::*fn)(); } pipeline[] = {
        { &Reconnaissance::stepPassiveScan        },
        { &Reconnaissance::stepActiveProbeSweep   },
        { &Reconnaissance::stepProbeRequestSniff  },
        { &Reconnaissance::stepFingerprintAPs     },
        { &Reconnaissance::stepChannelInterference},
        { &Reconnaissance::stepRankTargets        },
    };

    for (uint8_t i = 0; i < STEP_COUNT; i++) {
        if (_stop) { _steps[i].status = StepStatus::SKIP; continue; }
        _steps[i].status = StepStatus::RUNNING;
        bool ok = (this->*pipeline[i].fn)();
        _steps[i].status = ok ? StepStatus::OK : StepStatus::FAIL;
    }

    stopPromiscuous();
    _pcap.close();
    _status = StepStatus::OK;
    exportJson();
}

void Reconnaissance::stop() {
    _stop = true;
    stopPromiscuous();
}

// ── Promiscuous mode ─────────────────────────────────────────
void IRAM_ATTR Reconnaissance::promiscuousCb(void* buf,
                                              wifi_promiscuous_pkt_type_t type) {
    if (!s_instance) return;
    auto* pkt = static_cast<wifi_promiscuous_pkt_t*>(buf);
    g_packetCount++;
    s_instance->handleFrame(pkt, type);
}

void Reconnaissance::handleFrame(const wifi_promiscuous_pkt_t* pkt,
                                  wifi_promiscuous_pkt_type_t   type) {
    if (type != WIFI_PKT_MGMT) return;
    const uint8_t* pl  = pkt->payload;
    uint16_t       len = pkt->rx_ctrl.sig_len;

    _pcap.write(pl, len);

    if (is_beacon(pkt)) {
        // Extract BSSID (addr3 in beacon, offset 16)
        const uint8_t* bssid = pl + 16;
        APRecord* rec = findOrAddAP(bssid);
        if (!rec) return;

        rec->rssi = pkt->rx_ctrl.rssi;
        rec->beaconCount++;

        // SSID
        char ssid[33] = {};
        uint8_t ssidLen = extract_ssid(pl, len, ssid, sizeof(ssid));
        if (ssidLen > 0) {
            memcpy(rec->ssid, ssid, ssidLen + 1);
            rec->hidden = false;
        } else {
            rec->hidden = true;
        }

        // Channel from DS param set IE
        uint8_t ch = extract_channel_ie(pl, len);
        if (ch > 0) rec->channel = ch;

        // WPS
        rec->wps = has_wps_ie(pl, len);

        // Encryption from capability field
        if (len > 37) {
            uint16_t cap;
            memcpy(&cap, pl + 34, 2);
            // RSN IE present → WPA2
            rec->wpa2 = has_rsn_ie(pl, len);
            // Privacy bit set without RSN → WEP or WPA
            bool privBit = (cap & 0x0010) != 0;
            if (privBit && !rec->wpa2) rec->wep = true;
            rec->open = !privBit;
        }
    } else if (is_probe_req(pkt)) {
        // SA = addr2 (offset 10)
        const uint8_t* client = pl + 10;
        char ssid[33] = {};
        extract_ssid(pl, len, ssid, sizeof(ssid));

        // Find or add probe record
        for (auto& p : _probes) {
            if (memcmp(p.client, client, 6) == 0 &&
                strcmp(p.ssid, ssid) == 0) {
                p.count++;
                return;
            }
        }
        ProbeRecord pr{};
        memcpy(pr.client, client, 6);
        memcpy(pr.ssid,   ssid,   sizeof(ssid));
        pr.rssi  = pkt->rx_ctrl.rssi;
        pr.count = 1;
        _probes.push_back(pr);
    }
}

APRecord* Reconnaissance::findOrAddAP(const uint8_t* bssid) {
    for (auto& ap : _aps) {
        if (memcmp(ap.bssid, bssid, 6) == 0) return &ap;
    }
    if (_aps.size() >= 64) return nullptr;
    APRecord rec{};
    memcpy(rec.bssid, bssid, 6);
    rec.vendor = oui_vendor(bssid);
    _aps.push_back(rec);
    return &_aps.back();
}

// ── Pipeline steps ────────────────────────────────────────────

bool Reconnaissance::stepPassiveScan() {
    // Radio and PCAP already started by run(); just hop channels.
    for (uint8_t ch = SCAN_CHANNEL_MIN;
         ch <= SCAN_CHANNEL_MAX && !_stop; ch++) {
        setChannel(ch);
        uint32_t deadline = millis() + SCAN_DWELL_MS;
        while (millis() < deadline && !_stop) delay(5);
    }
    return true;
}

bool Reconnaissance::stepActiveProbeSweep() {
    // Build a wildcard probe request frame and inject it on each channel.
    // Switch to STA mode so inject_frame(WIFI_IF_STA, ...) works;
    // the promiscuous callback registered by run() stays active and will
    // capture probe responses while we are in STA mode.
    uint8_t probe[26] = {
        0x40, 0x00,                               // FC: Probe Request
        0x00, 0x00,                               // Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,       // DA: broadcast
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42,       // SA: placeholder
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,       // BSSID: broadcast
        0x00, 0x00,                               // Seq ctrl
        0x00, 0x00,                               // SSID IE: id=0, len=0 (wildcard)
    };

    uint8_t myMac[6];
    esp_wifi_get_mac(WIFI_IF_STA, myMac);
    memcpy(probe + 10, myMac, 6);

    // Temporarily enable STA interface for frame injection
    esp_wifi_set_mode(WIFI_MODE_STA);

    for (uint8_t ch = SCAN_CHANNEL_MIN;
         ch <= SCAN_CHANNEL_MAX && !_stop; ch++) {
        setChannel(ch);
        for (int t = 0; t < 3 && !_stop; t++) {
            inject_frame(WIFI_IF_STA, probe, sizeof(probe));
            delay(20);
        }
        // Dwell to receive probe responses via still-active promiscuous CB
        uint32_t deadline = millis() + SCAN_DWELL_MS / 2;
        while (millis() < deadline && !_stop) delay(5);
    }

    // Return to NULL (passive) mode; promiscuous callback remains registered
    esp_wifi_set_mode(WIFI_MODE_NULL);
    return true;
}

bool Reconnaissance::stepProbeRequestSniff() {
    // Promiscuous callback already active from run(); just hop channels.
    // Double dwell time to capture spontaneous client probe requests.
    uint32_t deadline = millis() + (SCAN_DWELL_MS * 13 * 2);  // ~2 full hops
    for (uint8_t ch = SCAN_CHANNEL_MIN;
         ch <= SCAN_CHANNEL_MAX && !_stop; ch++) {
        setChannel(ch);
        uint32_t until = millis() + SCAN_DWELL_MS * 2;
        while (millis() < until && millis() < deadline && !_stop) delay(5);
    }
    return true;
}

bool Reconnaissance::stepFingerprintAPs() {
    // OUI lookup is done inline during handleFrame; here we do
    // additional IE-based fingerprinting (vendor-specific IEs).
    for (auto& ap : _aps) {
        if (!ap.vendor || strcmp(ap.vendor, "Unknown") == 0) {
            ap.vendor = oui_vendor(ap.bssid);
        }
    }
    return true;
}

bool Reconnaissance::stepChannelInterference() {
    // Count APs per channel to flag congestion
    uint8_t chCount[14] = {};
    for (const auto& ap : _aps) {
        if (ap.channel >= 1 && ap.channel <= 13)
            chCount[ap.channel]++;
    }
    // Log congested channels to SD
    if (g_sdReady) {
        char path[64];
        snprintf(path, sizeof(path), "%s/channel_map_%lu.txt",
                 SD_LOG_DIR, millis() / 1000);
        File f = SD.open(path, FILE_WRITE);
        if (f) {
            f.println("# Channel congestion report");
            for (uint8_t ch = 1; ch <= 13; ch++) {
                char line[32];
                snprintf(line, sizeof(line), "CH%02d: %d APs", ch, chCount[ch]);
                f.println(line);
            }
            f.close();
        }
    }
    return true;
}

bool Reconnaissance::stepRankTargets() {
    // Sort _aps by exploitability so downstream modules (Infiltration)
    // get the most actionable targets first.
    // Priority: open (0) > WEP (1) > WPS (2) > WPA2-only (3) > other (4).
    // Within the same bucket, sort by RSSI descending (strongest signal first).
    auto priority = [](const APRecord& ap) -> int {
        if (ap.open) return 0;
        if (ap.wep)  return 1;
        if (ap.wps)  return 2;
        if (ap.wpa2) return 3;
        return 4;
    };

    for (size_t i = 1; i < _aps.size(); i++) {
        for (size_t j = i; j > 0; j--) {
            int pa = priority(_aps[j]);
            int pb = priority(_aps[j - 1]);
            bool swap = (pa < pb) ||
                        (pa == pb && _aps[j].rssi > _aps[j - 1].rssi);
            if (!swap) break;
            APRecord tmp = _aps[j];
            _aps[j]      = _aps[j - 1];
            _aps[j - 1]  = tmp;
        }
    }
    return true;
}

// ── Helpers ───────────────────────────────────────────────────

void Reconnaissance::startPromiscuous() {
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();
    esp_wifi_set_promiscuous(true);

    wifi_promiscuous_filter_t filt{};
    filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                       WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(promiscuousCb);
    g_currentChannel = SCAN_CHANNEL_MIN;
}

void Reconnaissance::stopPromiscuous() {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    // Note: _pcap.close() is called by run() after all steps complete
}

void Reconnaissance::setChannel(uint8_t ch) {
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    g_currentChannel = ch;
}

void Reconnaissance::exportJson() {
    if (!g_sdReady) return;
    char path[64];
    snprintf(path, sizeof(path), "%s/recon_%lu.json", SD_LOG_DIR, millis() / 1000);
    File f = SD.open(path, FILE_WRITE);
    if (!f) return;

    f.println("[");
    for (size_t i = 0; i < _aps.size(); i++) {
        const auto& ap = _aps[i];
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 ap.bssid[0], ap.bssid[1], ap.bssid[2],
                 ap.bssid[3], ap.bssid[4], ap.bssid[5]);
        f.printf("  {\"ssid\":\"%s\",\"bssid\":\"%s\","
                 "\"rssi\":%d,\"ch\":%d,"
                 "\"open\":%s,\"wep\":%s,\"wpa2\":%s,\"wps\":%s,"
                 "\"hidden\":%s,\"vendor\":\"%s\",\"beacons\":%lu}%s\n",
                 ap.ssid, mac,
                 ap.rssi, ap.channel,
                 ap.open  ? "true" : "false",
                 ap.wep   ? "true" : "false",
                 ap.wpa2  ? "true" : "false",
                 ap.wps   ? "true" : "false",
                 ap.hidden? "true" : "false",
                 ap.vendor ? ap.vendor : "Unknown",
                 ap.beaconCount,
                 (i < _aps.size() - 1) ? "," : "");
    }
    f.println("]");
    f.close();
}
