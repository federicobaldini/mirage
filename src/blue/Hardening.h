#pragma once

#include "../IModule.h"
#include "../WiFiUtils.h"
#include "../PcapLogger.h"
#include "../blue/Awareness.h"
#include <vector>
#include <cstdint>

// ============================================================
//  Hardening — BLUE module 3
//  Audit visible APs and generate actionable recommendations
// ============================================================

enum class FindingSeverity : uint8_t { MEDIUM = 0, HIGH_RISK = 1, CRITICAL = 2 };

struct HardeningFinding {
    FindingSeverity severity;
    char            title[48];
    char            explanation[120];
    char            fix[96];
    uint8_t         bssid[6];   // related AP (may be zero for general findings)
    char            ssid[33];
};

class Hardening : public IModule {
public:
    Hardening();

    void init()   override;
    void run()    override;
    void stop()   override;

    StepStatus          getStatus()              const override;
    const PipelineStep* getSteps(uint8_t& count) const override;
    const char*         getName()                const override;

    const std::vector<HardeningFinding>& getFindings() const { return _findings; }

    // Optionally pre-populate with Awareness data to skip live scan
    void setAPs(const std::vector<AwarenessAP>& aps) { _liveAPs = aps; }

private:
    static constexpr uint8_t STEP_COUNT = 6;
    PipelineStep _steps[STEP_COUNT];
    StepStatus   _status = StepStatus::IDLE;
    volatile bool _stop  = false;

    std::vector<HardeningFinding> _findings;
    std::vector<AwarenessAP>      _liveAPs;
    PcapLogger _pcap;

    // Promiscuous sniff for a quick survey if no data injected
    static Hardening* s_instance;
    static void IRAM_ATTR promiscuousCb(void* buf,
                                         wifi_promiscuous_pkt_type_t type);
    void handleFrame(const wifi_promiscuous_pkt_t* pkt,
                     wifi_promiscuous_pkt_type_t   type);

    struct LiveAP {
        uint8_t bssid[6];
        char    ssid[33];
        uint8_t channel;
        bool    open;
        bool    wep;
        bool    wpa2;
        bool    wps;
        int8_t  rssi;
    };
    std::vector<LiveAP> _scannedAPs;

    // Pipeline steps
    bool stepAuditEncryption();
    bool stepCheckAPisolation();
    bool stepChannelCongestion();
    bool stepClientRisks();
    bool stepGenerateReport();

    // Helpers
    void addFinding(FindingSeverity sev, const char* title,
                    const char* expl, const char* fix,
                    const uint8_t* bssid = nullptr, const char* ssid = nullptr);
    void quickScan();
    void saveReport();
    void startPromiscuous();
    void stopPromiscuous();
};
