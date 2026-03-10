#include "Awareness.h"
#include "../../include/config.h"
#include <Arduino.h>
#include <SD.h>
#include <esp_wifi.h>
#include <cstring>
#include <cstdio>
#include <cctype>

// ============================================================
//  Awareness — implementation
// ============================================================

Awareness* Awareness::s_instance = nullptr;

extern uint32_t g_packetCount;
extern uint8_t  g_currentChannel;
extern bool     g_sdReady;

// RSSI swing (dBm) that flags a possible Evil Twin with stronger signal
static constexpr int8_t RSSI_ANOMALY_DELTA = 15;
// Deauths/second above this rate is suspicious
static constexpr float  DEAUTH_RATE_WARN   = 0.5f;
// Minimum beacons before flagging honeypot (no data traffic)
static constexpr uint32_t HONEYPOT_MIN_BCN = 100;

Awareness::Awareness() {
    _steps[0] = { "Passive collection",     "Channel-hop, capture all frames"      };
    _steps[1] = { "Traffic rate analysis",  "Beacon/deauth rates, honeypot detect" };
    _steps[2] = { "RSSI anomaly detect",    "Flag large signal swings per AP"      };
    _steps[3] = { "MAC classification",     "OUI lookup, random-MAC ratio"         };
    _steps[4] = { "Export log",             "Write structured report to SD"        };
}

const char* Awareness::getName()  const { return "SEE EVERYTHING"; }
StepStatus  Awareness::getStatus() const { return _status; }

const PipelineStep* Awareness::getSteps(uint8_t& count) const {
    count = STEP_COUNT;
    return _steps;
}

void Awareness::init() {
    s_instance = this;
    _aps.reserve(64);
    _clients.reserve(128);
    _analysis.reserve(64);
}

void Awareness::run() {
    _stop   = false;
    _status = StepStatus::RUNNING;
    _aps.clear();
    _clients.clear();
    _analysis.clear();
    for (auto& s : _steps) s.status = StepStatus::IDLE;

    auto runStep = [&](uint8_t idx, bool (Awareness::*fn)()) {
        if (_stop) { _steps[idx].status = StepStatus::SKIP; notifyProgress(); return; }
        _steps[idx].status = StepStatus::RUNNING;
        notifyProgress();
        bool ok = (this->*fn)();
        _steps[idx].status = ok ? StepStatus::OK : StepStatus::FAIL;
        notifyProgress();
    };

    runStep(0, &Awareness::stepPassiveCollection);
    runStep(1, &Awareness::stepAnalyzeTrafficRates);
    runStep(2, &Awareness::stepDetectRssiAnomalies);
    runStep(3, &Awareness::stepClassifyMACs);
    runStep(4, &Awareness::stepExportLog);

    _status = StepStatus::OK;
}

void Awareness::stop() {
    _stop = true;
    stopPromiscuous();
}

// ── Promiscuous callback ──────────────────────────────────────
void IRAM_ATTR Awareness::promiscuousCb(void* buf,
                                         wifi_promiscuous_pkt_type_t type) {
    if (!s_instance) return;
    g_packetCount++;
    s_instance->handleFrame(static_cast<wifi_promiscuous_pkt_t*>(buf), type);
}

void Awareness::handleFrame(const wifi_promiscuous_pkt_t* pkt,
                             wifi_promiscuous_pkt_type_t   type) {
    const uint8_t* pl  = pkt->payload;
    uint16_t       len = pkt->rx_ctrl.sig_len;
    if (len < 10) return;

    uint16_t fc;
    memcpy(&fc, pl, 2);
    uint8_t ftype    = fc_type(fc);
    uint8_t fsubtype = fc_subtype(fc);
    int8_t  rssi     = pkt->rx_ctrl.rssi;
    uint32_t now     = millis();

    _pcap.write(pl, len);

    if (ftype == FC_TYPE_MGMT) {
        if (fsubtype == FC_SUBTYPE_BEACON && len > 22) {
            const uint8_t* bssid = pl + 16;
            AwarenessAP* ap = findOrAddAP(bssid);
            if (!ap) return;
            ap->beaconCount++;
            ap->rssiLast = rssi;
            if (rssi < ap->rssiMin) ap->rssiMin = rssi;
            if (rssi > ap->rssiMax) ap->rssiMax = rssi;
            ap->lastSeen = now;
            char ssid[33] = {};
            extract_ssid(pl, len, ssid, sizeof(ssid));
            if (ssid[0]) memcpy(ap->ssid, ssid, sizeof(ssid));
            uint8_t ch = extract_channel_ie(pl, len);
            if (ch) ap->channel = ch;

        } else if (fsubtype == FC_SUBTYPE_DEAUTH && len >= 10) {
            const uint8_t* bssid = pl + 16;
            AwarenessAP* ap = findOrAddAP(bssid);
            if (ap) { ap->deauthCount++; ap->lastSeen = now; }

        } else if (fsubtype == FC_SUBTYPE_PROBE_REQ && len >= 10) {
            const uint8_t* src = pl + 10;
            AwarenessClient* cli = findOrAddClient(src);
            if (cli) { cli->frameCount++; cli->rssiLast = rssi; cli->lastSeen = now; }
            // probe requests go to broadcast BSSID — don't create AP entry for FF:FF...
        }

    } else if (ftype == FC_TYPE_DATA && len >= 22) {
        const uint8_t* src   = pl + 10;
        const uint8_t* bssid = pl + 16;

        AwarenessAP* ap = findOrAddAP(bssid);
        if (ap) { ap->dataCount++; ap->lastSeen = now; }

        AwarenessClient* cli = findOrAddClient(src);
        if (cli) {
            cli->frameCount++;
            cli->rssiLast = rssi;
            cli->lastSeen = now;
            memcpy(cli->apBssid, bssid, 6);
        }
    }
}

// ── Pipeline step 0: passive collection ──────────────────────
bool Awareness::stepPassiveCollection() {
    startPromiscuous();
    _pcap.open("awareness");
    _collectionStartMs = millis();

    // Three full channel sweeps per the hop interval
    uint32_t totalWindow = (uint32_t)HOP_INTERVAL_MS
                           * (SCAN_CHANNEL_MAX - SCAN_CHANNEL_MIN + 1) * 3;
    uint32_t deadline = millis() + totalWindow;

    while (millis() < deadline && !_stop) {
        for (uint8_t ch = SCAN_CHANNEL_MIN;
             ch <= SCAN_CHANNEL_MAX && !_stop; ch++) {
            esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
            g_currentChannel = ch;
            delay(HOP_INTERVAL_MS);
        }
    }

    _collectionEndMs = millis();
    stopPromiscuous();
    _pcap.close();
    return true;
}

// ── Pipeline step 1: traffic rate analysis ───────────────────
bool Awareness::stepAnalyzeTrafficRates() {
    uint32_t durationMs = _collectionEndMs - _collectionStartMs;
    if (durationMs == 0) durationMs = 1;
    float durationS = durationMs / 1000.0f;

    _analysis.clear();
    for (const auto& ap : _aps) {
        ApAnalysis a{};
        a.ap          = &ap;
        a.beaconRate  = ap.beaconCount  / durationS;
        a.deauthRate  = ap.deauthCount  / durationS;
        a.suspiciousDeauth = (a.deauthRate > DEAUTH_RATE_WARN);
        // A high beacon count with zero data traffic suggests a fake/honeypot AP
        a.noDataTraffic = (ap.beaconCount >= HONEYPOT_MIN_BCN && ap.dataCount == 0);
        _analysis.push_back(a);
    }
    return true;
}

// ── Pipeline step 2: RSSI anomaly detection ──────────────────
bool Awareness::stepDetectRssiAnomalies() {
    for (auto& a : _analysis) {
        int8_t delta = a.ap->rssiMax - a.ap->rssiMin;
        a.rssiAnomaly = (delta > RSSI_ANOMALY_DELTA);
    }
    return true;
}

// ── Pipeline step 3: MAC classification ──────────────────────
bool Awareness::stepClassifyMACs() {
    // OUI lookup for static-MAC clients; flag random-MAC clients
    for (auto& cli : _clients) {
        cli.randomMac = (cli.mac[0] & 0x02) != 0;
        if (!cli.randomMac) {
            cli.vendor = oui_vendor(cli.mac);
        }
    }
    // Also flag APs with locally-administered BSSIDs (rare; may indicate spoofing)
    for (auto& ap : _aps) {
        ap.hasRandomMac = (ap.bssid[0] & 0x02) != 0;
    }
    return true;
}

// ── Pipeline step 4: export structured log ───────────────────
bool Awareness::stepExportLog() {
    if (!g_sdReady) return false;
    char path[64];
    snprintf(path, sizeof(path), "%s/awareness_%lu.txt",
             SD_LOG_DIR, millis() / 1000);
    File f = SD.open(path, FILE_WRITE);
    if (!f) return false;

    uint32_t durationMs = _collectionEndMs - _collectionStartMs;

    f.println("================================================");
    f.println("  MIRAGE — Awareness Report");
    f.println("================================================");
    f.printf("  Collection: %lu ms   APs: %d   Clients: %d\n\n",
             durationMs, _aps.size(), _clients.size());

    f.println("## Access Points");
    for (size_t i = 0; i < _aps.size(); i++) {
        const auto& ap = _aps[i];
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 ap.bssid[0], ap.bssid[1], ap.bssid[2],
                 ap.bssid[3], ap.bssid[4], ap.bssid[5]);

        f.printf("%s  %-32s  CH:%2d  RSSI:%4d/%4d  BCN:%5lu  DEAUTH:%4lu  DATA:%5lu",
                 mac, ap.ssid, ap.channel,
                 ap.rssiMin, ap.rssiMax,
                 ap.beaconCount, ap.deauthCount, ap.dataCount);

        // Append analysis flags
        if (i < _analysis.size()) {
            const auto& a = _analysis[i];
            if (a.rssiAnomaly)      f.print("  [RSSI-ANOMALY]");
            if (a.suspiciousDeauth) f.print("  [SUSPICIOUS-DEAUTH]");
            if (a.noDataTraffic)    f.print("  [POSSIBLE-HONEYPOT]");
            if (ap.hasRandomMac)    f.print("  [RANDOM-BSSID]");
        }
        f.println();
    }

    f.println("\n## Clients");
    uint32_t randomCount = 0;
    for (const auto& c : _clients) {
        char mac[18], apMac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 c.mac[0], c.mac[1], c.mac[2],
                 c.mac[3], c.mac[4], c.mac[5]);
        snprintf(apMac, sizeof(apMac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 c.apBssid[0], c.apBssid[1], c.apBssid[2],
                 c.apBssid[3], c.apBssid[4], c.apBssid[5]);
        f.printf("%s  AP:%s  RSSI:%4d  FRAMES:%5lu  RAND:%s  VENDOR:%s\n",
                 mac, apMac, c.rssiLast, c.frameCount,
                 c.randomMac ? "yes" : "no",
                 (c.vendor && !c.randomMac) ? c.vendor : "—");
        if (c.randomMac) randomCount++;
    }

    if (!_clients.empty()) {
        f.printf("\n  Random-MAC clients: %lu / %d (%.0f%%)\n",
                 randomCount, _clients.size(),
                 100.0f * randomCount / _clients.size());
    }

    f.println("================================================");
    f.close();
    return true;
}

// ── Helpers ───────────────────────────────────────────────────
AwarenessAP* Awareness::findOrAddAP(const uint8_t* bssid) {
    // Skip broadcast
    if (bssid[0] == 0xFF) return nullptr;
    for (auto& ap : _aps) {
        if (memcmp(ap.bssid, bssid, 6) == 0) return &ap;
    }
    if (_aps.size() >= 128) return nullptr;
    AwarenessAP rec{};
    memcpy(rec.bssid, bssid, 6);
    rec.rssiMin   = 0;
    rec.rssiMax   = -120;
    rec.firstSeen = millis();
    rec.lastSeen  = rec.firstSeen;
    _aps.push_back(rec);
    return &_aps.back();
}

AwarenessClient* Awareness::findOrAddClient(const uint8_t* mac) {
    if (mac[0] & 0x01) return nullptr;  // skip broadcast/multicast
    for (auto& c : _clients) {
        if (memcmp(c.mac, mac, 6) == 0) return &c;
    }
    if (_clients.size() >= 256) return nullptr;
    AwarenessClient rec{};
    memcpy(rec.mac, mac, 6);
    rec.randomMac = (mac[0] & 0x02) != 0;
    rec.firstSeen = millis();
    rec.lastSeen  = rec.firstSeen;
    _clients.push_back(rec);
    return &_clients.back();
}

void Awareness::startPromiscuous() {
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

void Awareness::stopPromiscuous() {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
}
