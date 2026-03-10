#pragma once

#include <cstdint>

// ============================================================
//  IModule — common interface for all Red/Blue pipeline modules
// ============================================================

enum class StepStatus : uint8_t {
    IDLE    = 0,
    RUNNING = 1,
    OK      = 2,
    FAIL    = 3,
    SKIP    = 4,
};

static const char* stepStatusStr(StepStatus s) {
    switch (s) {
        case StepStatus::IDLE:    return "IDLE";
        case StepStatus::RUNNING: return "RUN ";
        case StepStatus::OK:      return " OK ";
        case StepStatus::FAIL:    return "FAIL";
        case StepStatus::SKIP:    return "SKIP";
        default:                  return "????";
    }
}

// A single auto-executed pipeline step shown in the checklist view.
struct PipelineStep {
    const char* name        = nullptr;
    const char* description = nullptr;
    StepStatus  status      = StepStatus::IDLE;

    PipelineStep() = default;
    PipelineStep(const char* n, const char* d)
        : name(n), description(d), status(StepStatus::IDLE) {}
};

// Base interface every module must implement.
class IModule {
public:
    virtual ~IModule() = default;

    // Called once at startup to allocate resources.
    virtual void init() = 0;

    // Called when the user selects this module's menu entry.
    // Runs the full pipeline synchronously (use FreeRTOS tasks internally
    // for background work, but this call blocks until complete or stop()).
    virtual void run() = 0;

    // Signals the module to abort its pipeline gracefully.
    virtual void stop() = 0;

    // Current overall status of the module.
    virtual StepStatus getStatus() const = 0;

    // Pointer to the step array + count (valid after init()).
    virtual const PipelineStep* getSteps(uint8_t& count) const = 0;

    // Human-readable module name (shown in menu header).
    virtual const char* getName() const = 0;
};
