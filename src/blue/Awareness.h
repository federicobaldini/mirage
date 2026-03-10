#pragma once

#include "../IModule.h"
#include "../WiFiUtils.h"
#include "../PcapLogger.h"
#include <vector>
#include <cstdint>

// ============================================================
//  Awareness — BLUE module 1
//  Full passive situational awareness of the environment
// ============================================================

struct AwarenessAP {
    uint8_t  bssid[6];
    char     ssid[33];
    int8_t   rssiMin;
    int8_t   rssiMax;
    int8_t   rssiLast;
    uint8_t  channel;
    uint32_t beaconCount;
    uint32_t deauthCount;
    uint32_t probeCount;
    uint32_t dataCount;
    uint32_t firstSeen;
    uint32_t lastSeen;
    bool     hasRandomMac;  // BSSID locally-administered bit set
};

struct AwarenessClient {
    uint8_t  mac[6];
    uint8_t  apBssid[6];    // associated AP (may be zero if unassociated)
    int8_t   rssiLast;
    uint32_t frameCount;
    uint32_t firstSeen;
    uint32_t lastSeen;
    bool     randomMac;     // locally-administered bit
    const char* vendor;     // OUI lookup result (may be nullptr)
};

class Awareness : public IModule {
public:
    Awareness();

    void init()   override;
    void run()    override;
    void stop()   override;

    StepStatus          getStatus()              const override;
    const PipelineStep* getSteps(uint8_t& count) const override;
    const char*         getName()                const override;

    const std::vector<AwarenessAP>&     getAPs()     const { return _aps;     }
    const std::vector<AwarenessClient>& getClients() const { return _clients; }

private:
    static constexpr uint8_t STEP_COUNT = 5;
    PipelineStep _steps[STEP_COUNT];
    StepStatus   _status = StepStatus::IDLE;
    volatile bool _stop  = false;

    std::vector<AwarenessAP>     _aps;
    std::vector<AwarenessClient> _clients;
    PcapLogger _pcap;

    uint32_t _collectionStartMs = 0;
    uint32_t _collectionEndMs   = 0;

    // Post-collection analysis flags (parallel to _aps)
    struct ApAnalysis {
        const AwarenessAP* ap;
        float    beaconRate;       // beacons / second
        float    deauthRate;       // deauths / second
        bool     rssiAnomaly;      // RSSI range > threshold
        bool     suspiciousDeauth; // deauthRate > 0.5/s
        bool     noDataTraffic;    // high beacon count but zero data (honeypot)
    };
    std::vector<ApAnalysis> _analysis;

    static Awareness* s_instance;
    static void IRAM_ATTR promiscuousCb(void* buf,
                                         wifi_promiscuous_pkt_type_t type);
    void handleFrame(const wifi_promiscuous_pkt_t* pkt,
                     wifi_promiscuous_pkt_type_t   type);

    // Pipeline steps (real implementations)
    bool stepPassiveCollection();   // channel-hop monitor + frame capture
    bool stepAnalyzeTrafficRates(); // compute beacon/deauth rates, flag anomalies
    bool stepDetectRssiAnomalies(); // flag large RSSI swings per AP
    bool stepClassifyMACs();        // OUI lookup, random-MAC ratio
    bool stepExportLog();           // write structured report to SD

    AwarenessAP*     findOrAddAP(const uint8_t* bssid);
    AwarenessClient* findOrAddClient(const uint8_t* mac);
    void startPromiscuous();
    void stopPromiscuous();
};
