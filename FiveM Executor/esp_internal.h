#pragma once
#include "sdk_internal.h"
#include <string>

// ESP Settings Struct
struct ESPSettings {
    bool box = false;
    bool skeleton = false;
    bool lines = false;
    bool playerid = false;
    bool heathbar = false;
    bool armorbar = false;
    bool distance = false;
    bool ignoreped = false;
    bool ignoredead = false;
    int boxtype = 0;
    int HealthBar_type = 0;
    int distanceint = 200;
    
    // Centers
    float skeletoncolor[4] = { 1.f, 1.f, 1.f, 1.f };
    float boxcolor[4] = { 1.f, 1.f, 1.f, 1.f };
    float LineColor[4] = { 1.f, 1.f, 1.f, 1.f };
};

class ESP {
public:
    static ESP& inst() {
        static ESP i;
        return i;
    }

    ESPSettings settings;
    void Draw();
    
private:
    void DrawSkeleton(uintptr_t ped_base);
};
