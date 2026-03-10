#pragma once

#include <M5Unified.h>
#include "../IModule.h"
#include "../blue/Awareness.h"
#include "../blue/Detection.h"
#include "../blue/Hardening.h"

// ============================================================
//  MenuBlue — BLUE team menu screen
// ============================================================

enum class BlueView { MENU, PIPELINE };

class MenuBlue {
public:
    MenuBlue();

    void init();
    bool update(char key);
    void draw();
    void stopCurrent();

    bool isRunning() const { return _running; }

private:
    static constexpr uint8_t ITEM_COUNT = 3;

    struct MenuItem {
        const char*  title;
        const char*  subtitle;
        IModule*     module;
    };

    MenuItem   _items[ITEM_COUNT];
    uint8_t    _sel     = 0;
    BlueView   _view    = BlueView::MENU;
    bool       _dirty   = true;
    bool       _running = false;

    Awareness  _awareness;
    Detection  _detection;
    Hardening  _hardening;

    void drawMenu();
    void drawPipeline();
    void launchSelected();

public:
    void drawStatusBar();
    void drawStepRow(int y, const PipelineStep& step, bool isCurrent);
};
