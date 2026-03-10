#pragma once

#include "../IModule.h"
#include "../WiFiUtils.h"
#include "../PcapLogger.h"
#include "../red/Reconnaissance.h"
#include <WebServer.h>
#include <vector>
#include <cstdint>
#include <cstring>

// ============================================================
//  Deception — RED module 3
//  Manipulate the wireless environment for controlled testing
// ============================================================

struct CredentialCapture {
    char     username[64];
    char     password[64];
    char     client_ip[16];
    uint32_t timestamp;
};

class Deception : public IModule {
public:
    Deception();
    ~Deception();

    void init()   override;
    void run()    override;
    void stop()   override;

    StepStatus          getStatus()              const override;
    const PipelineStep* getSteps(uint8_t& count) const override;
    const char*         getName()                const override;

    // Set which AP to clone (from Recon results)
    void setTarget(const APRecord& ap);

    const std::vector<CredentialCapture>& getCredentials() const { return _creds; }

private:
    static constexpr uint8_t STEP_COUNT = 5;
    PipelineStep _steps[STEP_COUNT];
    StepStatus   _status = StepStatus::IDLE;
    volatile bool _stop  = false;

    APRecord  _targetAP  = {};
    bool      _hasTarget = false;

    std::vector<CredentialCapture> _creds;
    PcapLogger _pcap;

    WebServer* _httpServer = nullptr;
    TaskHandle_t _portalTask = nullptr;

    volatile uint32_t _associationCount = 0;  // clients that associated to Evil Twin

    // Pipeline steps
    bool stepEvilTwinAP();
    bool stepDeauthFlood();
    bool stepFakeProbeResponses();
    bool stepCaptivePortal();
    bool stepMonitorAssociations();

    // Helpers
    void startEvilTwinAP(const char* ssid, uint8_t channel);
    void stopEvilTwinAP();
    void setupCaptivePortal();
    void saveCreds();

    static void portalTaskFn(void* arg);

    // Promiscuous monitor for association counting
    static Deception* s_instance;
    static void IRAM_ATTR monitorCb(void* buf, wifi_promiscuous_pkt_type_t type);
    void countAssocFrame(const wifi_promiscuous_pkt_t* pkt);
};
