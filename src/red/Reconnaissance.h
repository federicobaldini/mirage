#pragma once

#include "../IModule.h"
#include "../WiFiUtils.h"
#include "../PcapLogger.h"
#include <vector>
#include <cstdint>

// ============================================================
//  Reconnaissance — RED module 1
//  Builds a complete picture of the wireless environment
// ============================================================

struct APRecord {
    char     ssid[33];
    uint8_t  bssid[6];
    int8_t   rssi;
    uint8_t  channel;
    bool     open;
    bool     wep;
    bool     wpa;
    bool     wpa2;
    bool     wps;
    bool     hidden;
    uint32_t beaconCount;
    const char* vendor;
};

struct ProbeRecord {
    uint8_t  client[6];
    char     ssid[33];
    int8_t   rssi;
    uint32_t count;
};

class Reconnaissance : public IModule {
public:
    Reconnaissance();

    void init()   override;
    void run()    override;
    void stop()   override;

    StepStatus          getStatus()                     const override;
    const PipelineStep* getSteps(uint8_t& count)        const override;
    const char*         getName()                        const override;

    // Access results after run()
    const std::vector<APRecord>&    getAPs()    const { return _aps; }
    const std::vector<ProbeRecord>& getProbes() const { return _probes; }

private:
    static constexpr uint8_t STEP_COUNT = 6;
    PipelineStep _steps[STEP_COUNT];
    StepStatus   _status = StepStatus::IDLE;
    volatile bool _stop  = false;

    std::vector<APRecord>    _aps;
    std::vector<ProbeRecord> _probes;
    PcapLogger               _pcap;

    // Static promiscuous callback — routes to the singleton
    static Reconnaissance* s_instance;
    static void IRAM_ATTR promiscuousCb(void* buf,
                                         wifi_promiscuous_pkt_type_t type);
    void handleFrame(const wifi_promiscuous_pkt_t* pkt,
                     wifi_promiscuous_pkt_type_t   type);

    // Pipeline steps
    bool stepPassiveScan();
    bool stepActiveProbeSweep();
    bool stepProbeRequestSniff();
    bool stepFingerprintAPs();
    bool stepChannelInterference();
    bool stepRankTargets();

    // Helpers
    APRecord* findOrAddAP(const uint8_t* bssid);
    void      exportJson();
    void      startPromiscuous();
    void      stopPromiscuous();
    void      setChannel(uint8_t ch);
};
