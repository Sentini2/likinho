#include "sdk_internal.h"
#include <vector>
#include <string>

// Offsets
uintptr_t oWorld = 0;
uintptr_t oReplay = 0;
uintptr_t oViewport = 0;

void SDK::Init() {
    uintptr_t base = (uintptr_t)GetModuleHandle(NULL);
    
    char filename[MAX_PATH];
    GetModuleFileNameA(NULL, filename, MAX_PATH);
    std::string name = filename;

    // Detect Build and set offsets
    // These offsets are ported from 1/main/fivem-external.cpp
    
    if (name.find("b3323") != std::string::npos) {
        oWorld = base + 0x25C15B0;
        oReplay = base + 0x1F85458;
        oViewport = base + 0x202DC50;
    }
    else if (name.find("b3407") != std::string::npos) {
        oWorld = base + 0x25D7108;
        oReplay = base + 0x1F9A9D8;
        oViewport = base + 0x20431C0;
    }
    else if (name.find("b3570") != std::string::npos) {
        oWorld = base + 0x25EC580;
        oReplay = base + 0x1FB0418;
        oViewport = base + 0x2058BA0;
    }
    else if (name.find("b3717") != std::string::npos) {
        oWorld = base + 0x2603908;
        oReplay = base + 0x1fc38a8;
        oViewport = base + 0x206c060;
    }
    else {
        // Default: FiveM_GTAProcess.exe (sem build number) ou build desconhecida
        // Offsets do dump mais recente
        oWorld = base + 0x25B14B0;
        oReplay = base + 0x1FBD4F0;
        oViewport = base + 0x201DBA0;
    }
}

D3DXVECTOR3 SDK::GetBonePosition(uintptr_t ped_ptr, int bone_id) {
    auto matrix = Memory::Read<D3DXMATRIX>(ped_ptr + 0x60);
    auto bone = Memory::Read<D3DXVECTOR3>(ped_ptr + (0x410 + (bone_id * 0x10)));

    D3DXVECTOR4 transform;
    // Manual transform since we don't have D3DXVec3Transform
    transform.x = bone.x * matrix.m[0][0] + bone.y * matrix.m[1][0] + bone.z * matrix.m[2][0] + matrix.m[3][0];
    transform.y = bone.x * matrix.m[0][1] + bone.y * matrix.m[1][1] + bone.z * matrix.m[2][1] + matrix.m[3][1];
    transform.z = bone.x * matrix.m[0][2] + bone.y * matrix.m[1][2] + bone.z * matrix.m[2][2] + matrix.m[3][2];
    transform.w = 1.0f; // Simplified

    return D3DXVECTOR3(transform.x, transform.y, transform.z);
}

D3DXVECTOR2 SDK::WorldToScreen(D3DXVECTOR3 world_pos) {
    uintptr_t viewport_ptr = Memory::Read<uintptr_t>(oViewport);
    if (!viewport_ptr) return {0, 0};
    
    auto viewmatrix = Memory::Read<D3DXMATRIX>(viewport_ptr + 0x24C);

    // Matrix logic ported from 1/sdk/sdk.cpp
    // vec_x = row 2 (1,0 1,1 1,2 1,3) -> m[1][0]...
    // The external code accessed _12, _22, _32, _42. _12 is Row 1 Col 2.
    // D3DXMATRIX struct in SDK.h is float m[4][4].
    // m[row][col]
    
    // External:
    // vec_x = (_12, _22, _32, _42) => (m[0][1], m[1][1], m[2][1], m[3][1])
    // vec_y = (_13, _23, _33, _43) => (m[0][2], m[1][2], m[2][2], m[3][2])
    // vec_z = (_14, _24, _34, _44) => (m[0][3], m[1][3], m[2][3], m[3][3])
    
    // BUT the external code said:
    // vec_x was row 2 of transposed...
    // Let's stick to the accessors used:
    // _12 (Row 1 Col 2), _22 (Row 2 Col 2)...
    
    float _12 = viewmatrix.m[0][1]; float _22 = viewmatrix.m[1][1]; float _32 = viewmatrix.m[2][1]; float _42 = viewmatrix.m[3][1];
    float _13 = viewmatrix.m[0][2]; float _23 = viewmatrix.m[1][2]; float _33 = viewmatrix.m[2][2]; float _43 = viewmatrix.m[3][2];
    float _14 = viewmatrix.m[0][3]; float _24 = viewmatrix.m[1][3]; float _34 = viewmatrix.m[2][3]; float _44 = viewmatrix.m[3][3];

    D3DXVECTOR3 screen_pos(
        (_12 * world_pos.x) + (_22 * world_pos.y) + (_32 * world_pos.z) + _42,
        (_13 * world_pos.x) + (_23 * world_pos.y) + (_33 * world_pos.z) + _43,
        (_14 * world_pos.x) + (_24 * world_pos.y) + (_34 * world_pos.z) + _44
    );

    if (screen_pos.z <= 0.1f) return {0, 0};

    float inv_z = 1.0f / screen_pos.z;
    screen_pos.x *= inv_z;
    screen_pos.y *= inv_z;

    ImGuiIO& io = ImGui::GetIO();
    float width = io.DisplaySize.x;
    float height = io.DisplaySize.y;

    float x_temp = width / 2.0f;
    float y_temp = height / 2.0f;

    return {
        x_temp + (0.5f * screen_pos.x * width + 0.5f),
        y_temp - (0.5f * screen_pos.y * height + 0.5f)
    };
}
