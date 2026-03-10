#pragma once

#include "../IModule.h"
#include "../WiFiUtils.h"
#include "../PcapLogger.h"
#include "../red/Reconnaissance.h"
#include <vector>
#include <cstdint>

// ============================================================
//  Infiltration — RED module 2
//  Attempt to obtain network access or captured credentials
// ============================================================

enum class InfiltrationResult : uint8_t {
    NONE,
    OPEN_CONNECTED,
    WPS_PIXIE,
    WPS_PIN,
    HANDSHAKE_CAPTURED,
    PMKID_CAPTURED,
    PORTAL_FINGERPRINTED,
};

struct TargetResult {
    APRecord          ap;
    InfiltrationResult result;
    char              detail[64];    // e.g. PIN found, PMKID hex, portal type
    uint32_t          timestamp;
};

class Infiltration : public IModule {
public:
    Infiltration();

    void init()   override;
    void run()    override;
    void stop()   override;

    StepStatus          getStatus()              const override;
    const PipelineStep* getSteps(uint8_t& count) const override;
    const char*         getName()                const override;

    // Inject target list from Reconnaissance results
    void setTargets(const std::vector<APRecord>& aps) { _targets = aps; }

    const std::vector<TargetResult>& getResults() const { return _results; }

private:
    static constexpr uint8_t STEP_COUNT = 5;
    PipelineStep _steps[STEP_COUNT];
    StepStatus   _status = StepStatus::IDLE;
    volatile bool _stop  = false;

    std::vector<APRecord>    _targets;
    std::vector<TargetResult> _results;
    PcapLogger               _pcap;

    // Sniff state for handshake capture
    static Infiltration* s_instance;
    static void IRAM_ATTR sniffCb(void* buf, wifi_promiscuous_pkt_type_t type);
    void handleFrame(const wifi_promiscuous_pkt_t* pkt,
                     wifi_promiscuous_pkt_type_t   type);

    volatile bool _handshakeCapured = false;
    volatile bool _pmkidCaptured    = false;
    uint8_t _targetBssid[6] = {};

    // Pipeline steps
    bool stepClassifyTargets();
    bool stepWpsAttack(APRecord& ap);
    bool stepDeauthHandshake();
    bool stepCaptivePortal();
    bool stepPmkidHarvest();

    // Helpers
    bool sendDeauthBurst(const uint8_t* clientMac, const uint8_t* apMac);
    bool tryPixieDust(const APRecord& ap);
    bool tryWpsPin(const APRecord& ap);
    void startPromiscuousForCapture(const uint8_t* bssid);
    void stopPromiscuous();
};
