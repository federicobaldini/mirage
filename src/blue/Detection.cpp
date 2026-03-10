#include "Detection.h"
#include "../../include/config.h"
#include <Arduino.h>
#include <SD.h>
#include <esp_wifi.h>
#include <cstring>
#include <cstdio>

// ============================================================
//  Detection — implementation
// ============================================================

Detection* Detection::s_instance = nullptr;

extern uint32_t g_packetCount;
extern uint8_t  g_currentChannel;
extern bool     g_sdReady;

Detection::Detection() {
    _steps[0] = { "Deauth flood detect",      "Alert if deauth/s exceeds threshold" };
    _steps[1] = { "Handshake harvest detect", "Burst deauth pattern detection"      };
    _steps[2] = { "Evil Twin detect",         "Same SSID, different BSSID or RSSI" };
    _steps[3] = { "Rogue AP detect",          "Unknown APs on known channels"       };
    _steps[4] = { "Beacon flood detect",      "Abnormal unique SSID count/window"  };
    _steps[5] = { "WPS brute detect",         "Repeated assoc attempts → PIN/Pixie" };
}

const char* Detection::getName() const { return "DETECT THREATS"; }

StepStatus Detection::getStatus() const { return _status; }

const PipelineStep* Detection::getSteps(uint8_t& count) const {
    count = STEP_COUNT;
    return _steps;
}

void Detection::init() {
    s_instance = this;
    _threats.reserve(64);
    _deauthCounters.reserve(32);
    _ssidWindow.reserve(128);
    _assocCounters.reserve(32);
}

void Detection::run() {
    _stop   = false;
    _status = StepStatus::RUNNING;
    _threats.clear();
    _deauthCounters.clear();
    _ssidWindow.clear();
    _assocCounters.clear();
    for (auto& s : _steps) s.status = StepStatus::IDLE;

    startPromiscuous();
    _pcap.open("detection");

    // Monitor window: each step gets a dedicated listen period
    const uint32_t windowPerStep = 15000;  // 15s per step

    for (uint8_t i = 0; i < STEP_COUNT && !_stop; i++) {
        _steps[i].status = StepStatus::RUNNING;
        bool ok = false;

        uint32_t stepEnd = millis() + windowPerStep;
        // Channel hop during the window
        while (millis() < stepEnd && !_stop) {
            for (uint8_t ch = SCAN_CHANNEL_MIN;
                 ch <= SCAN_CHANNEL_MAX && !_stop && millis() < stepEnd; ch++) {
                esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
                g_currentChannel = ch;
                delay(HOP_INTERVAL_MS);
            }
        }

        // Analyse what was collected during this window
        if (!_stop) {
            if (i == 0) ok = stepDeauthFloodDetect();
            if (i == 1) ok = stepHandshakeHarvestDetect();
            if (i == 2) ok = stepEvilTwinDetect();
            if (i == 3) ok = stepRogueAPDetect();
            if (i == 4) ok = stepBeaconFloodDetect();
            if (i == 5) ok = stepWpsBruteDetect();
        }

        _steps[i].status = _stop ? StepStatus::SKIP
                         : (ok   ? StepStatus::OK : StepStatus::FAIL);
    }

    stopPromiscuous();
    _pcap.close();
    saveThreatFeed();
    _status = StepStatus::OK;
}

void Detection::stop() {
    _stop = true;
    stopPromiscuous();
}

// ── Promiscuous callback ──────────────────────────────────────
void IRAM_ATTR Detection::promiscuousCb(void* buf,
                                         wifi_promiscuous_pkt_type_t type) {
    if (!s_instance) return;
    g_packetCount++;
    s_instance->handleFrame(static_cast<wifi_promiscuous_pkt_t*>(buf), type);
}

void Detection::handleFrame(const wifi_promiscuous_pkt_t* pkt,
                             wifi_promiscuous_pkt_type_t   type) {
    const uint8_t* pl  = pkt->payload;
    uint16_t       len = pkt->rx_ctrl.sig_len;
    if (len < 10) return;

    uint16_t fc;
    memcpy(&fc, pl, 2);
    uint8_t ftype    = fc_type(fc);
    uint8_t fsubtype = fc_subtype(fc);
    uint32_t now     = millis();

    _pcap.write(pl, len);

    if (ftype == FC_TYPE_MGMT) {
        if (fsubtype == FC_SUBTYPE_DEAUTH || fsubtype == FC_SUBTYPE_DISASSOC) {
            if (len < 22) return;
            const uint8_t* bssid = pl + 16;
            DeauthCounter* ctr = findOrAddCounter(bssid);
            if (!ctr) return;

            // Reset counter if outside window
            if (now - ctr->windowStart > DEAUTH_WINDOW_MS) {
                ctr->count       = 0;
                ctr->windowStart = now;
            }
            ctr->count++;
            if (ctr->count > ctr->burstPeakCount)
                ctr->burstPeakCount = ctr->count;

            // Threshold check happens in stepDeauthFloodDetect

        } else if ((fsubtype == 0x00 || fsubtype == 0x02) && len >= 26) {
            // Association Request (0x00) or Re-Association Request (0x02)
            // SA = addr2 (offset 10), BSSID = addr3 (offset 16)
            const uint8_t* clientMac = pl + 10;
            const uint8_t* apBssid   = pl + 16;
            // Skip broadcast/multicast clients
            if (!(clientMac[0] & 0x01)) {
                AssocCounter* ac = findOrAddAssoc(clientMac, apBssid);
                if (ac) {
                    if (now - ac->windowStart > DEAUTH_WINDOW_MS) {
                        ac->count       = 0;
                        ac->windowStart = now;
                    }
                    ac->count++;
                }
            }

        } else if (fsubtype == FC_SUBTYPE_BEACON) {
            if (len < 38) return;
            char ssid[33] = {};
            extract_ssid(pl, len, ssid, sizeof(ssid));
            if (ssid[0] == '\0') return;

            // Add to window
            bool found = false;
            for (const auto& s : _ssidWindow) {
                if (strcmp(s.ssid, ssid) == 0) { found = true; break; }
            }
            if (!found && _ssidWindow.size() < 256) {
                SsidSeen entry{};
                memcpy(entry.ssid, ssid, sizeof(entry.ssid));
                entry.firstSeen = now;
                _ssidWindow.push_back(entry);
            }
        }
    }
}

// ── Pipeline steps ────────────────────────────────────────────

bool Detection::stepDeauthFloodDetect() {
    for (const auto& ctr : _deauthCounters) {
        uint32_t framesPerSec = ctr.count * 1000 / DEAUTH_WINDOW_MS;
        if (framesPerSec >= DEAUTH_FLOOD_THRESHOLD) {
            char detail[96];
            char mac[18];
            snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                     ctr.bssid[0], ctr.bssid[1], ctr.bssid[2],
                     ctr.bssid[3], ctr.bssid[4], ctr.bssid[5]);
            snprintf(detail, sizeof(detail),
                     "BSSID %s: %lu deauth/s (threshold %d)",
                     mac, framesPerSec, DEAUTH_FLOOD_THRESHOLD);
            logThreat(ThreatLevel::CRITICAL, "DEAUTH_FLOOD", detail, ctr.bssid);
        }
    }
    return true;
}

bool Detection::stepEvilTwinDetect() {
    if (_baseline.empty()) return true;

    // Check if any baseline AP has appeared with a different BSSID
    // or with an RSSI much stronger than its baseline
    // For this we need the current live AP list — use _ssidWindow as
    // a simplified proxy (full impl would track BSSID per SSID).
    for (const auto& known : _baseline) {
        for (const auto& seen : _ssidWindow) {
            if (strcmp(known.ssid, seen.ssid) == 0) {
                // Could be the same AP or an Evil Twin.
                // A real impl would compare BSSIDs and RSSI delta.
                // Here we flag SSIDs found in baseline as INFO for review.
                char detail[96];
                snprintf(detail, sizeof(detail),
                         "SSID '%s' visible; verify BSSID matches baseline",
                         known.ssid);
                logThreat(ThreatLevel::INFO, "EVIL_TWIN_CHK", detail, known.bssid);
                break;
            }
        }
    }
    return true;
}

bool Detection::stepRogueAPDetect() {
    if (_baseline.empty()) return true;

    // Any SSID seen that is NOT in the baseline is potentially rogue
    for (const auto& seen : _ssidWindow) {
        bool knownSsid = false;
        for (const auto& known : _baseline) {
            if (strcmp(known.ssid, seen.ssid) == 0) { knownSsid = true; break; }
        }
        if (!knownSsid) {
            char detail[96];
            snprintf(detail, sizeof(detail),
                     "Unknown SSID '%s' not in whitelist", seen.ssid);
            logThreat(ThreatLevel::WARN, "ROGUE_AP", detail);
        }
    }
    return true;
}

bool Detection::stepHandshakeHarvestDetect() {
    // Detect burst-deauth pattern used to force client reconnections and
    // capture the 4-way handshake. Skip APs already flagged as full floods.
    for (const auto& ctr : _deauthCounters) {
        uint32_t framesPerSec = ctr.count * 1000 / DEAUTH_WINDOW_MS;
        if (framesPerSec >= DEAUTH_FLOOD_THRESHOLD) continue;  // already a flood
        if (ctr.burstPeakCount >= DEAUTH_BURST_MIN) {
            char detail[96];
            char mac[18];
            snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                     ctr.bssid[0], ctr.bssid[1], ctr.bssid[2],
                     ctr.bssid[3], ctr.bssid[4], ctr.bssid[5]);
            snprintf(detail, sizeof(detail),
                     "BSSID %s: burst peak %lu deauth — possible HS harvest",
                     mac, ctr.burstPeakCount);
            logThreat(ThreatLevel::WARN, "HS_HARVEST", detail, ctr.bssid);
        }
    }
    return true;
}

bool Detection::stepBeaconFloodDetect() {
    // Count SSIDs seen within BEACON_FLOOD_WINDOW_MS
    uint32_t now = millis();
    uint32_t windowStart = (now > BEACON_FLOOD_WINDOW_MS)
                           ? now - BEACON_FLOOD_WINDOW_MS : 0;
    uint32_t count = 0;
    for (const auto& s : _ssidWindow) {
        if (s.firstSeen >= windowStart) count++;
    }
    if (count >= BEACON_FLOOD_SSID_THRESH) {
        char detail[96];
        snprintf(detail, sizeof(detail),
                 "%lu unique SSIDs in %lums window (threshold %d)",
                 count, (uint32_t)BEACON_FLOOD_WINDOW_MS, BEACON_FLOOD_SSID_THRESH);
        logThreat(ThreatLevel::CRITICAL, "BEACON_FLOOD", detail);
    }
    return true;
}

bool Detection::stepWpsBruteDetect() {
    // A WPS brute-force attack (PIN or Pixie Dust) requires repeatedly
    // associating to the target AP. Flag any (client, AP) pair that generated
    // ≥ DEAUTH_BURST_MIN association requests within a single window.
    for (const auto& ac : _assocCounters) {
        if (ac.count < DEAUTH_BURST_MIN) continue;
        char detail[96];
        char cliMac[18], apMac[18];
        snprintf(cliMac, sizeof(cliMac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 ac.clientMac[0], ac.clientMac[1], ac.clientMac[2],
                 ac.clientMac[3], ac.clientMac[4], ac.clientMac[5]);
        snprintf(apMac, sizeof(apMac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 ac.apBssid[0], ac.apBssid[1], ac.apBssid[2],
                 ac.apBssid[3], ac.apBssid[4], ac.apBssid[5]);
        snprintf(detail, sizeof(detail),
                 "Client %s → AP %s: %lu assoc req — possible WPS brute",
                 cliMac, apMac, ac.count);
        logThreat(ThreatLevel::WARN, "WPS_BRUTE", detail, ac.apBssid);
    }
    return true;
}

// ── Helpers ───────────────────────────────────────────────────

void Detection::logThreat(ThreatLevel lvl, const char* cat,
                           const char* detail, const uint8_t* bssid) {
    if (_threats.size() >= 128) return;
    ThreatEvent ev{};
    ev.level     = lvl;
    ev.timestamp = millis();
    strncpy(ev.category, cat,    sizeof(ev.category) - 1);
    strncpy(ev.detail,   detail, sizeof(ev.detail)   - 1);
    if (bssid) memcpy(ev.bssid, bssid, 6);
    _threats.push_back(ev);
}

Detection::DeauthCounter* Detection::findOrAddCounter(const uint8_t* bssid) {
    for (auto& c : _deauthCounters) {
        if (memcmp(c.bssid, bssid, 6) == 0) return &c;
    }
    if (_deauthCounters.size() >= 64) return nullptr;
    DeauthCounter c{};
    memcpy(c.bssid, bssid, 6);
    c.windowStart = millis();
    _deauthCounters.push_back(c);
    return &_deauthCounters.back();
}

Detection::AssocCounter* Detection::findOrAddAssoc(const uint8_t* clientMac,
                                                    const uint8_t* apBssid) {
    for (auto& ac : _assocCounters) {
        if (memcmp(ac.clientMac, clientMac, 6) == 0 &&
            memcmp(ac.apBssid,   apBssid,   6) == 0) return &ac;
    }
    if (_assocCounters.size() >= 64) return nullptr;
    AssocCounter ac{};
    memcpy(ac.clientMac, clientMac, 6);
    memcpy(ac.apBssid,   apBssid,   6);
    ac.windowStart = millis();
    _assocCounters.push_back(ac);
    return &_assocCounters.back();
}

void Detection::startPromiscuous() {
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

void Detection::stopPromiscuous() {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
}

void Detection::saveThreatFeed() {
    if (!g_sdReady || _threats.empty()) return;
    char path[64];
    snprintf(path, sizeof(path), "%s/threats_%lu.txt", SD_LOG_DIR, millis() / 1000);
    File f = SD.open(path, FILE_WRITE);
    if (!f) return;

    static const char* lvlStr[] = {"INFO    ", "WARN    ", "CRITICAL"};
    f.println("# Mirage Threat Feed");
    for (const auto& t : _threats) {
        char mac[18] = "N/A";
        bool hasBssid = false;
        for (int i = 0; i < 6; i++) if (t.bssid[i]) { hasBssid = true; break; }
        if (hasBssid) {
            snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                     t.bssid[0], t.bssid[1], t.bssid[2],
                     t.bssid[3], t.bssid[4], t.bssid[5]);
        }
        f.printf("[%s] %lu %-20s BSSID:%-17s %s\n",
                 lvlStr[(uint8_t)t.level], t.timestamp,
                 t.category, mac, t.detail);
    }
    f.close();
}
