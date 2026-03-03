#pragma once
#include <windows.h>
#include <cmath>
#include <d3d11.h>
#include <DirectXMath.h>
#include "../imgui/imgui.h"

// Define vectors compatible with D3DX9 usage in ported code, or map them to DirectXMath
struct D3DXVECTOR3 {
    float x, y, z;

    D3DXVECTOR3() : x(0), y(0), z(0) {}
    D3DXVECTOR3(float _x, float _y, float _z) : x(_x), y(_y), z(_z) {}

    D3DXVECTOR3 operator+(const D3DXVECTOR3& v) const { return D3DXVECTOR3(x + v.x, y + v.y, z + v.z); }
    D3DXVECTOR3 operator-(const D3DXVECTOR3& v) const { return D3DXVECTOR3(x - v.x, y - v.y, z - v.z); }
};

struct D3DXVECTOR2 {
    float x, y;
};

struct D3DXVECTOR4 {
    float x, y, z, w;
};

struct D3DXMATRIX {
    float m[4][4];
};

// Internal Memory Reader Helper
class Memory {
public:
    template<typename T>
    static T Read(uintptr_t address) {
        if (!address) return T();
        if (IsBadReadPtr((void*)address, sizeof(T))) return T();
        return *(T*)address;
    }

    // Helper for pointer reading
    static uintptr_t ReadPtr(uintptr_t address) {
        return Read<uintptr_t>(address);
    }
};

// SDK Class similar to external one but internal
class SDK {
public:
    static SDK& inst() {
        static SDK i;
        return i;
    }

    void Init(); // Added Missing Declaration
    D3DXVECTOR2 WorldToScreen(D3DXVECTOR3 world_pos);
    D3DXVECTOR3 GetBonePosition(uintptr_t ped_ptr, int bone_id);
};
