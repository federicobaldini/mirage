#pragma once

#include <M5Unified.h>
#include "../IModule.h"
#include "../red/Reconnaissance.h"
#include "../red/Infiltration.h"
#include "../red/Deception.h"
#include "../red/CauseChaoS.h"

// ============================================================
//  MenuRed — RED team menu screen
// ============================================================

enum class RedView { MENU, PIPELINE };

class MenuRed {
public:
    MenuRed();

    // Call once during setup().
    void init();

    // Call every loop() iteration; handles key input and re-draws if dirty.
    // Returns true if the screen consumed the key and no parent action needed.
    bool update(char key);

    // Force a full redraw.
    void draw();

    // Request graceful stop of whatever module is running.
    void stopCurrent();

    bool isRunning() const { return _running; }

private:
    static constexpr uint8_t ITEM_COUNT = 4;

    struct MenuItem {
        const char*  title;
        const char*  subtitle;
        IModule*     module;
    };

    MenuItem   _items[ITEM_COUNT];
    uint8_t    _sel     = 0;
    RedView    _view    = RedView::MENU;
    bool       _dirty   = true;
    bool       _running = false;

    Reconnaissance _recon;
    Infiltration   _infiltration;
    Deception      _deception;
    CauseChaoS     _chaos;

    void drawMenu();
    void drawMenuRow(uint8_t i);
    void drawPipeline();
    void launchSelected();

public:
    void drawStatusBar();
    void drawStepRow(int y, const PipelineStep& step, bool isCurrent);
};
