#pragma once

#include "../IModule.h"
#include "../WiFiUtils.h"
#include <cstdint>

// ============================================================
//  CauseChaoS — RED module 4
//  Saturate the air with random beacon SSIDs (beacon flood)
// ============================================================

class CauseChaoS : public IModule {
public:
    CauseChaoS();

    void init()   override;
    void run()    override;
    void stop()   override;

    StepStatus          getStatus()              const override;
    const PipelineStep* getSteps(uint8_t& count) const override;
    const char*         getName()                const override;

private:
    static constexpr uint8_t STEP_COUNT = 1;
    PipelineStep _steps[STEP_COUNT];
    StepStatus   _status = StepStatus::IDLE;
    volatile bool _stop  = false;

    TaskHandle_t _beaconTask = nullptr;

    bool stepSsidStorm();

    static void beaconTaskFn(void* arg);
    int buildBeaconFrame(uint8_t* buf, const char* ssid,
                         const uint8_t* bssid, uint8_t channel);
};
