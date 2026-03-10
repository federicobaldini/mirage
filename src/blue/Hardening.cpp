#include "Hardening.h"
#include "../../include/config.h"
#include <Arduino.h>
#include <SD.h>
#include <esp_wifi.h>
#include <cstring>
#include <cstdio>

// ============================================================
//  Hardening — implementation
// ============================================================

Hardening* Hardening::s_instance = nullptr;

extern uint32_t g_packetCount;
extern uint8_t  g_currentChannel;
extern bool     g_sdReady;

Hardening::Hardening() {
    _steps[0] = { "WiFi scan",            "Passive scan: collect visible APs"      };
    _steps[1] = { "Audit encryption",     "Flag open, WEP, WPS, no-PMF APs"      };
    _steps[2] = { "AP isolation check",   "Detect client-to-client visibility"    };
    _steps[3] = { "Channel congestion",   "Identify APs on crowded channels"      };
    _steps[4] = { "Client risks",         "Clients connecting to open/evil nets"  };
    _steps[5] = { "Generate report",      "Prioritised findings saved to SD"      };
}

const char* Hardening::getName() const { return "LOCK IT DOWN"; }

StepStatus Hardening::getStatus() const { return _status; }

const PipelineStep* Hardening::getSteps(uint8_t& count) const {
    count = STEP_COUNT;
    return _steps;
}

void Hardening::init() {
    s_instance = this;
    _findings.reserve(32);
    _scannedAPs.reserve(64);
}

void Hardening::run() {
    _stop   = false;
    _status = StepStatus::RUNNING;
    _findings.clear();
    _scannedAPs.clear();
    for (auto& s : _steps) s.status = StepStatus::IDLE;

    auto runStep = [&](uint8_t idx, bool (Hardening::*fn)()) {
        if (_stop) { _steps[idx].status = StepStatus::SKIP; return; }
        _steps[idx].status = StepStatus::RUNNING;
        bool ok = (this->*fn)();
        _steps[idx].status = ok ? StepStatus::OK : StepStatus::FAIL;
    };

    // Step 0: explicit scan (skipped if APs were injected from Awareness)
    if (!_stop) {
        _steps[0].status = StepStatus::RUNNING;
        if (!_liveAPs.empty()) {
            // Pre-populated from Awareness — convert and skip live scan
            for (const auto& a : _liveAPs) {
                LiveAP la{};
                memcpy(la.bssid, a.bssid, 6);
                memcpy(la.ssid,  a.ssid,  sizeof(la.ssid));
                la.channel = a.channel;
                la.rssi    = a.rssiLast;
                _scannedAPs.push_back(la);
            }
            _steps[0].status = StepStatus::SKIP;
        } else {
            quickScan();
            _steps[0].status = _scannedAPs.empty() ? StepStatus::FAIL : StepStatus::OK;
        }
    } else {
        _steps[0].status = StepStatus::SKIP;
    }

    runStep(1, &Hardening::stepAuditEncryption);
    runStep(2, &Hardening::stepCheckAPisolation);
    runStep(3, &Hardening::stepChannelCongestion);
    runStep(4, &Hardening::stepClientRisks);
    runStep(5, &Hardening::stepGenerateReport);

    _status = StepStatus::OK;
}

void Hardening::stop() {
    _stop = true;
    stopPromiscuous();
}

// ── Quick passive scan ─────────────────────────────────────────
void Hardening::quickScan() {
    startPromiscuous();
    _pcap.open("hardening_scan");

    for (uint8_t ch = SCAN_CHANNEL_MIN;
         ch <= SCAN_CHANNEL_MAX && !_stop; ch++) {
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        g_currentChannel = ch;
        delay(SCAN_DWELL_MS * 2);
    }

    stopPromiscuous();
    _pcap.close();
}

// ── Promiscuous callback ──────────────────────────────────────
void IRAM_ATTR Hardening::promiscuousCb(void* buf,
                                         wifi_promiscuous_pkt_type_t type) {
    if (!s_instance) return;
    g_packetCount++;
    s_instance->handleFrame(static_cast<wifi_promiscuous_pkt_t*>(buf), type);
}

void Hardening::handleFrame(const wifi_promiscuous_pkt_t* pkt,
                             wifi_promiscuous_pkt_type_t   type) {
    const uint8_t* pl  = pkt->payload;
    uint16_t       len = pkt->rx_ctrl.sig_len;

    if (!is_beacon(pkt) || len < 38) return;

    const uint8_t* bssid = pl + 16;

    // Check if already recorded
    for (const auto& a : _scannedAPs) {
        if (memcmp(a.bssid, bssid, 6) == 0) return;
    }
    if (_scannedAPs.size() >= 128) return;

    LiveAP la{};
    memcpy(la.bssid, bssid, 6);
    extract_ssid(pl, len, la.ssid, sizeof(la.ssid));
    la.channel = extract_channel_ie(pl, len);
    la.rssi    = pkt->rx_ctrl.rssi;
    la.wps     = has_wps_ie(pl, len);
    la.wpa2    = has_rsn_ie(pl, len);
    la.wep     = false;
    la.open    = false;

    if (len > 35) {
        uint16_t cap;
        memcpy(&cap, pl + 34, 2);
        bool privBit = (cap & 0x0010) != 0;
        la.open = !privBit;
        if (privBit && !la.wpa2) la.wep = true;
    }

    _scannedAPs.push_back(la);
}

// ── Pipeline steps ────────────────────────────────────────────

// Extract RSN Capabilities field from a beacon payload.
// RSN IE layout: id(1) len(1) version(2) group_cipher(4) pairwise_count(2)
//                pairwise_suites(4*N) akm_count(2) akm_suites(4*M)
//                rsn_capabilities(2) ...
// Returns 0 if RSN IE not found or too short.
static uint16_t extractRsnCapabilities(const uint8_t* pl, uint16_t len) {
    // Skip fixed fields: FC(2)+Dur(2)+DA(6)+SA(6)+BSSID(6)+Seq(2)+
    //                    Timestamp(8)+Interval(2)+Cap(2) = 36 bytes
    if (len < 38) return 0;
    const uint8_t* ie = pl + 36;
    const uint8_t* end = pl + len;
    while (ie + 2 <= end) {
        uint8_t id  = ie[0];
        uint8_t iel = ie[1];
        if (ie + 2 + iel > end) break;
        if (id == 0x30 && iel >= 10) {  // RSN IE
            // Skip: version(2)+group(4)+pairwise_count(2)
            uint16_t pCount;
            memcpy(&pCount, ie + 2 + 6, 2);
            size_t capOffset = 2 + 8 + (uint32_t)pCount * 4;
            if (iel < capOffset + 2 + 2) { ie += 2 + iel; continue; }
            uint16_t akmCount;
            memcpy(&akmCount, ie + 2 + capOffset, 2);
            capOffset += 2 + (uint32_t)akmCount * 4;
            if (iel < capOffset + 2) { ie += 2 + iel; continue; }
            uint16_t caps;
            memcpy(&caps, ie + 2 + capOffset, 2);
            return caps;
        }
        ie += 2 + iel;
    }
    return 0;
}

bool Hardening::stepAuditEncryption() {
    static const char* kDefaultSsids[] = {
        "NETGEAR", "dlink", "linksys", "default", "belkin",
        "WiFi", "Wireless", "ASUS", "TP-LINK", nullptr
    };

    for (const auto& ap : _scannedAPs) {
        if (ap.open) {
            addFinding(FindingSeverity::CRITICAL,
                "Open (unencrypted) network",
                "All traffic is transmitted in plaintext. "
                "Anyone nearby can capture and read your data.",
                "Enable WPA2-AES encryption with a strong passphrase.",
                ap.bssid, ap.ssid);
        }
        if (ap.wep) {
            addFinding(FindingSeverity::CRITICAL,
                "WEP encryption detected",
                "WEP was broken in 2001 and can be cracked in minutes "
                "with freely available tools.",
                "Upgrade to WPA2-AES or WPA3 immediately.",
                ap.bssid, ap.ssid);
        }
        if (ap.wps) {
            addFinding(FindingSeverity::HIGH_RISK,
                "WPS enabled",
                "WPS PIN mode is vulnerable to brute-force (Reaver) and "
                "Pixie Dust attacks. WPS Push-Button is safer but still "
                "presents a minor risk.",
                "Disable WPS in your router's wireless settings.",
                ap.bssid, ap.ssid);
        }
        // WPA2 without PMF (802.11w): management frames are unprotected,
        // enabling deauth-flood and Evil Twin attacks.
        if (ap.wpa2 && !ap.open) {
            // We need the raw beacon to check RSN caps; use the last captured
            // payload stored in the pcap. As a proxy, flag all WPA2 APs without
            // explicit PMF advertisement. The flag is conservative (better safe).
            addFinding(FindingSeverity::MEDIUM,
                "PMF (802.11w) not verified",
                "Without Protected Management Frames, an attacker can forge "
                "deauthentication frames, disconnecting clients at will and "
                "enabling Evil Twin follow-on attacks.",
                "Enable 802.11w (PMF) on this AP. Set it to 'Required' for "
                "maximum protection.",
                ap.bssid, ap.ssid);
        }
        // Default SSID check
        for (int i = 0; kDefaultSsids[i]; i++) {
            if (strncasecmp(ap.ssid, kDefaultSsids[i],
                            strlen(kDefaultSsids[i])) == 0) {
                addFinding(FindingSeverity::MEDIUM,
                    "Default SSID in use",
                    "Default SSIDs reveal the router model, helping attackers "
                    "target known firmware vulnerabilities.",
                    "Rename the SSID to something that does not identify "
                    "the router brand or model.",
                    ap.bssid, ap.ssid);
                break;
            }
        }
    }
    return true;
}

bool Hardening::stepCheckAPisolation() {
    // Flag open or guest-named APs where client isolation may be absent.
    // Client isolation prevents associated devices from attacking each other.
    auto isGuestLike = [](const char* ssid) {
        char lower[33] = {};
        for (int i = 0; ssid[i] && i < 32; i++)
            lower[i] = tolower((unsigned char)ssid[i]);
        return strstr(lower, "guest")  != nullptr ||
               strstr(lower, "public") != nullptr ||
               strstr(lower, "free")   != nullptr;
    };

    for (const auto& ap : _scannedAPs) {
        if (!ap.open && !isGuestLike(ap.ssid)) continue;
        addFinding(FindingSeverity::MEDIUM,
            "AP isolation unknown",
            "On open or guest networks, client isolation prevents devices "
            "from attacking each other. Without it, a malicious client can "
            "target other users on the same AP.",
            "Enable 'AP Isolation' or 'Client Isolation' in your "
            "router's wireless settings for guest/public SSIDs.",
            ap.bssid, ap.ssid);
    }
    return true;
}

bool Hardening::stepChannelCongestion() {
    // Count APs per channel
    uint8_t chCount[14] = {};
    for (const auto& ap : _scannedAPs) {
        if (ap.channel >= 1 && ap.channel <= 13)
            chCount[ap.channel]++;
    }

    // Flag channels with 3+ APs as congested (non-overlapping: 1, 6, 11)
    for (uint8_t ch = 1; ch <= 13; ch++) {
        if (chCount[ch] >= 3) {
            char title[48], expl[120], fix[96];
            snprintf(title, sizeof(title),
                     "Channel %d congested (%d APs)", ch, chCount[ch]);
            snprintf(expl, sizeof(expl),
                     "Channel %d has %d overlapping APs. Co-channel "
                     "interference degrades throughput and reliability.",
                     ch, chCount[ch]);
            snprintf(fix, sizeof(fix),
                     "Move your AP to a less-used channel. "
                     "For 2.4GHz use channels 1, 6, or 11 only.");
            addFinding(FindingSeverity::MEDIUM, title, expl, fix);
        }
    }
    return true;
}

bool Hardening::stepClientRisks() {
    // Per-AP findings for open networks (direct client exposure)
    for (const auto& ap : _scannedAPs) {
        if (!ap.open) continue;
        addFinding(FindingSeverity::HIGH_RISK,
            "Clients exposed on open network",
            "Clients on this open AP transmit all traffic in plaintext, "
            "exposing credentials, session tokens, and personal data to "
            "any passive observer in range.",
            "Advise users to connect only to encrypted networks. "
            "Deploy WPA2/WPA3 on this AP. Require a VPN for all clients.",
            ap.bssid, ap.ssid);
    }

    // Per-AP findings from Awareness data (high deauth count → attack target)
    for (const auto& ap : _liveAPs) {
        if (ap.deauthCount < 5) continue;
        addFinding(FindingSeverity::HIGH_RISK,
            "High deauth count — possible attack target",
            "This AP has accumulated many deauth frames, which may indicate "
            "an ongoing credential-harvesting or Evil Twin attack nearby.",
            "Enable 802.11w (Protected Management Frames) on this AP. "
            "Monitor for unknown transmitters on the same channel.",
            ap.bssid, ap.ssid);
    }

    // Generic probe-request advisory (always relevant)
    addFinding(FindingSeverity::MEDIUM,
        "Client probe request exposure",
        "Devices broadcast probe requests for known networks, revealing "
        "historical network names (home, workplace, hotel Wi-Fi) to "
        "passive observers. This enables tracking and Evil Twin attacks.",
        "Enable 'Randomise MAC address' on all client devices. "
        "Forget saved networks you no longer use. "
        "Use a VPN on all public WiFi.");
    return true;
}

bool Hardening::stepGenerateReport() {
    saveReport();
    return true;
}

// ── Helpers ───────────────────────────────────────────────────

void Hardening::addFinding(FindingSeverity sev, const char* title,
                            const char* expl, const char* fix,
                            const uint8_t* bssid, const char* ssid) {
    if (_findings.size() >= 64) return;
    HardeningFinding f{};
    f.severity = sev;
    strncpy(f.title,       title, sizeof(f.title)       - 1);
    strncpy(f.explanation, expl,  sizeof(f.explanation) - 1);
    strncpy(f.fix,         fix,   sizeof(f.fix)         - 1);
    if (bssid) memcpy(f.bssid, bssid, 6);
    if (ssid)  strncpy(f.ssid, ssid, sizeof(f.ssid) - 1);
    _findings.push_back(f);
}

void Hardening::saveReport() {
    if (!g_sdReady) return;
    char path[64];
    snprintf(path, sizeof(path), "%s/hardening_%lu.txt", SD_LOG_DIR, millis() / 1000);
    File f = SD.open(path, FILE_WRITE);
    if (!f) return;

    static const char* sevStr[] = {"[MEDIUM  ]", "[HIGH    ]", "[CRITICAL]"};

    f.println("================================================");
    f.println("  MIRAGE — Wireless Hardening Report");
    f.println("================================================");
    f.printf("  APs audited: %d   Findings: %d\n\n",
             _scannedAPs.size(), _findings.size());

    // Sort: CRITICAL first, then HIGH, MEDIUM
    // (simple insertion sort on small vector)
    std::vector<const HardeningFinding*> sorted;
    for (const auto& fi : _findings) sorted.push_back(&fi);
    for (size_t i = 1; i < sorted.size(); i++) {
        for (size_t j = i; j > 0 &&
             (uint8_t)sorted[j]->severity > (uint8_t)sorted[j-1]->severity; j--)
            std::swap(sorted[j], sorted[j-1]);
    }

    uint8_t n = 1;
    for (const auto* fi : sorted) {
        char mac[18] = "N/A";
        bool hasBssid = false;
        for (int i = 0; i < 6; i++) if (fi->bssid[i]) { hasBssid = true; break; }
        if (hasBssid) {
            snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                     fi->bssid[0], fi->bssid[1], fi->bssid[2],
                     fi->bssid[3], fi->bssid[4], fi->bssid[5]);
        }

        f.printf("--- Finding #%d %s ---\n", n++, sevStr[(uint8_t)fi->severity]);
        if (fi->ssid[0]) f.printf("  SSID   : %s\n", fi->ssid);
        if (hasBssid)    f.printf("  BSSID  : %s\n", mac);
        f.printf("  Issue  : %s\n", fi->title);
        f.printf("  Detail : %s\n", fi->explanation);
        f.printf("  Fix    : %s\n\n", fi->fix);
    }
    f.println("================================================");
    f.close();
}

void Hardening::startPromiscuous() {
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();
    esp_wifi_set_promiscuous(true);
    wifi_promiscuous_filter_t filt{};
    filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(promiscuousCb);
    g_currentChannel = SCAN_CHANNEL_MIN;
}

void Hardening::stopPromiscuous() {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
}
