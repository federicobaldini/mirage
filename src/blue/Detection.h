#pragma once

#include "../IModule.h"
#include "../WiFiUtils.h"
#include "../PcapLogger.h"
#include "../blue/Awareness.h"
#include <vector>
#include <cstdint>

// ============================================================
//  Detection — BLUE module 2
//  Identify active attacks happening in the environment
// ============================================================

enum class ThreatLevel : uint8_t { INFO = 0, WARN = 1, CRITICAL = 2 };

struct ThreatEvent {
    ThreatLevel level;
    char        category[24];
    char        detail[96];
    uint8_t     bssid[6];     // related AP (may be zero)
    uint32_t    timestamp;
};

class Detection : public IModule {
public:
    Detection();

    void init()   override;
    void run()    override;
    void stop()   override;

    StepStatus          getStatus()              const override;
    const PipelineStep* getSteps(uint8_t& count) const override;
    const char*         getName()                const override;

    const std::vector<ThreatEvent>& getThreats() const { return _threats; }

    // Inject a known-good AP baseline before running
    // (e.g. from Awareness results or a saved whitelist)
    void setBaseline(const std::vector<AwarenessAP>& baseline) {
        _baseline = baseline;
    }

private:
    static constexpr uint8_t STEP_COUNT = 6;
    PipelineStep _steps[STEP_COUNT];
    StepStatus   _status = StepStatus::IDLE;
    volatile bool _stop  = false;

    std::vector<ThreatEvent>  _threats;
    std::vector<AwarenessAP>  _baseline;
    PcapLogger  _pcap;

    // Live counters (updated by promiscuous CB)
    static Detection* s_instance;
    static void IRAM_ATTR promiscuousCb(void* buf,
                                         wifi_promiscuous_pkt_type_t type);
    void handleFrame(const wifi_promiscuous_pkt_t* pkt,
                     wifi_promiscuous_pkt_type_t   type);

    // Per-AP deauth counters keyed by BSSID[0..5] packed as uint64
    struct DeauthCounter {
        uint8_t  bssid[6];
        uint32_t count;
        uint32_t windowStart;
        uint32_t burstPeakCount;  // peak count within any single DEAUTH_WINDOW_MS
    };
    std::vector<DeauthCounter> _deauthCounters;

    // Seen SSIDs for beacon flood detection
    struct SsidSeen {
        char     ssid[33];
        uint32_t firstSeen;
    };
    std::vector<SsidSeen> _ssidWindow;

    // Pipeline steps
    bool stepDeauthFloodDetect();
    bool stepHandshakeHarvestDetect();
    bool stepEvilTwinDetect();
    bool stepRogueAPDetect();
    bool stepBeaconFloodDetect();
    bool stepWpsBruteDetect();

    // Per (client, AP) association counter for WPS brute detection
    struct AssocCounter {
        uint8_t  clientMac[6];
        uint8_t  apBssid[6];
        uint32_t count;
        uint32_t windowStart;
    };
    std::vector<AssocCounter> _assocCounters;

    // Helpers
    void logThreat(ThreatLevel lvl, const char* cat,
                   const char* detail, const uint8_t* bssid = nullptr);
    void saveThreatFeed();
    void startPromiscuous();
    void stopPromiscuous();
    DeauthCounter*  findOrAddCounter(const uint8_t* bssid);
    AssocCounter*   findOrAddAssoc(const uint8_t* clientMac, const uint8_t* apBssid);
};
