#include "esp_internal.h"
#include <string>

extern uintptr_t oWorld;
extern uintptr_t oReplay;
extern uintptr_t oViewport;

void ESP::DrawSkeleton(uintptr_t ped_base) {
    const int boneIds[] = { 0, 3, 4, 5, 6, 7, 8 };
    D3DXVECTOR2 screens[9];
    bool valid[9] = { false };

    for (int id : boneIds) {
        D3DXVECTOR3 pos = SDK::inst().GetBonePosition(ped_base, id);
        if (pos.x == 0.f && pos.y == 0.f && pos.z == 0.f) continue;

        D3DXVECTOR2 scr = SDK::inst().WorldToScreen(pos);
        if (scr.x != 0.f || scr.y != 0.f) {
            screens[id] = scr;
            valid[id] = true;
        }
    }

    auto draw_bone_line = [&](int id1, int id2) {
        if (valid[id1] && valid[id2]) {
            ImGui::GetForegroundDrawList()->AddLine(
                ImVec2(screens[id1].x, screens[id1].y),
                ImVec2(screens[id2].x, screens[id2].y),
                ImGui::ColorConvertFloat4ToU32(ImVec4(settings.skeletoncolor[0], settings.skeletoncolor[1], settings.skeletoncolor[2], settings.skeletoncolor[3])),
                1.8f
            );
        }
    };

    draw_bone_line(0, 7);
    draw_bone_line(7, 6);
    draw_bone_line(7, 5);
    draw_bone_line(7, 8);
    draw_bone_line(8, 3);
    draw_bone_line(8, 4);
}

void ESP::Draw() {
    if (!oWorld || !oReplay) return;

    // Use pointers directly
    uintptr_t world_ptr = Memory::Read<uintptr_t>(oWorld);
    if (!world_ptr) return;
    
    uintptr_t localplayer = Memory::Read<uintptr_t>(world_ptr + 0x8);
    if (!localplayer) return;

    uintptr_t replay_ptr = Memory::Read<uintptr_t>(oReplay);
    if (!replay_ptr) return;

    uintptr_t PedReplayInterface = Memory::Read<uintptr_t>(replay_ptr + 0x18);
    if (!PedReplayInterface) return;

    uintptr_t PedList = Memory::Read<uintptr_t>(PedReplayInterface + 0x100);
    int entitylist = Memory::Read<int>(PedReplayInterface + 0x108);

    if (!PedList) return;

    D3DXVECTOR3 GetCordLocal = Memory::Read<D3DXVECTOR3>(localplayer + 0x90);
    
    ImGuiIO& io = ImGui::GetIO();
    ImVec2 centerScreen(io.DisplaySize.x / 2.0f, io.DisplaySize.y / 2.0f);

    for (int i = 0; i < entitylist; i++) {
        uintptr_t Ped = Memory::Read<uintptr_t>(PedList + (i * 0x10));
        if (!Ped) continue;
        if (Ped == localplayer) continue;

        if (settings.ignoreped) {
             // 0x10A8 or 0x10B8 or 0x10C8 depending on build. 
             // Using a generic check or offset. 
             // External cheat used "cheat.playerinfo". It was 0x10A8 in build build 2802.
             // Let's assume 0x10A8 for now or skip if problematic.
             if (!Memory::Read<uintptr_t>(Ped + 0x10A8)) continue;
        }

        float HealthPed = Memory::Read<float>(Ped + 0x280);
        if (settings.ignoredead && HealthPed <= 0.f) continue;

        D3DXVECTOR3 GetCordPed = Memory::Read<D3DXVECTOR3>(Ped + 0x90);
        
        float dx = GetCordLocal.x - GetCordPed.x;
        float dy = GetCordLocal.y - GetCordPed.y;
        float dz = GetCordLocal.z - GetCordPed.z;
        double Distance = sqrt(dx*dx + dy*dy + dz*dz);
        
        if (Distance > settings.distanceint) continue;

        // Bone calculations
        auto bone_pos = SDK::inst().GetBonePosition(Ped, 0); // Head
        D3DXVECTOR2 screen = SDK::inst().WorldToScreen(bone_pos);
        
        // Skip offscreen
        // Basic check: 
        if (screen.x < 0 || screen.y < 0 || screen.x > io.DisplaySize.x || screen.y > io.DisplaySize.y) continue;

        // Feet for box
        auto RightFoot = SDK::inst().GetBonePosition(Ped, 4);
        auto LeftFoot = SDK::inst().GetBonePosition(Ped, 3);

        D3DXVECTOR2 screen2 = SDK::inst().WorldToScreen(RightFoot);
        D3DXVECTOR2 screen4 = SDK::inst().WorldToScreen(LeftFoot);

        float Foot_Middle = (screen4.y + screen2.y) / 2.f;
        float Height = std::abs(screen.y - Foot_Middle) * 1.35f;
        float Width = (Height / 1.75f);
        
        ImVec2 tl(screen.x - Width / 2, screen.y - Height / 10); // Head top approx
        // Adjust TL/BR logic from external cheat:
        // External: 
        // tl = Ped_Location.x - Width/2, Ped_Location.y - Height/2
        // Ped_Location was likely center of box.
        // My screen var is Head.
        
        // Let's use GetCordPed as center?
        D3DXVECTOR2 Ped_Location = SDK::inst().WorldToScreen(GetCordPed);
        
        // Using Ped_Location as center
        ImVec2 top_left(Ped_Location.x - Width / 2, Ped_Location.y - Height / 2);
        ImVec2 bottom_right(Ped_Location.x + Width / 2, Ped_Location.y + Height / 2);

        ImU32 boxCol = ImGui::ColorConvertFloat4ToU32(ImVec4(settings.boxcolor[0], settings.boxcolor[1], settings.boxcolor[2], settings.boxcolor[3]));
        
        if (settings.box) {
             ImGui::GetForegroundDrawList()->AddRect(top_left, bottom_right, boxCol, 0, 0, 1.5f);
        }
        
        if (settings.lines) {
             ImGui::GetForegroundDrawList()->AddLine(centerScreen, ImVec2(Ped_Location.x, Ped_Location.y), ImGui::ColorConvertFloat4ToU32(ImVec4(settings.LineColor[0], settings.LineColor[1], settings.LineColor[2], settings.LineColor[3])), 1.0f);
        }
        
        if (settings.skeleton) {
            DrawSkeleton(Ped);
        }
        
        if (settings.distance) {
            std::string d = std::to_string((int)Distance) + " m";
            ImGui::GetForegroundDrawList()->AddText(ImVec2(Ped_Location.x, bottom_right.y), 0xFFFFFFFF, d.c_str());
        }
    }
}
