#include "Aimbot.hpp"

#ifdef USE_VMPROTECT
#include "VMProtectSDK.h"
#endif

// Función para calcular SmoothStep sin interferencia de VMProtect
__declspec(noinline) float GetSmoothStep(float SmoothFactor) {
    if (SmoothFactor > 0) {
        if (SmoothFactor >= 98 && SmoothFactor <= 100) return 0.1f / SmoothFactor;
        if (SmoothFactor >= 80 && SmoothFactor < 98) return 0.5f / SmoothFactor;
        if (SmoothFactor >= 60 && SmoothFactor < 80) return 0.8f / SmoothFactor;
        if (SmoothFactor >= 40 && SmoothFactor < 60) return 0.9f / SmoothFactor;
        if (SmoothFactor >= 20 && SmoothFactor < 40) return 1.0f / SmoothFactor;
        return 3.0f / SmoothFactor;
    }
    return 1.0f;
}

void Core::Features::cAimbot::SetViewAngles(CPed* Ped, D3DXVECTOR3 BonePos)
{
#ifdef USE_VMPROTECT
    VMProtectBeginMutation("SetViewAngles");
#endif

    uintptr_t CamFollowPedCamera = Mem.Read<uintptr_t>(Core::SDK::Pointers::pCamGamePlayDirector + 0x2C0);
    if (!CamFollowPedCamera) return;

    D3DXVECTOR3 CamPos = Mem.Read<D3DXVECTOR3>(CamFollowPedCamera + 0x60);
    D3DXVECTOR3 CurrentViewAngles = Mem.Read<D3DXVECTOR3>(CamFollowPedCamera + 0x40);
    D3DXVECTOR3 TargetViewAngles = BonePos - CamPos;

    D3DXVec3Normalize(&TargetViewAngles, &TargetViewAngles);

    D3DXVECTOR3 FinalAngles;

    // Guardamos SmoothFactor en una variable local antes de usarlo
    float SmoothFactor = std::clamp(static_cast<float>(g_Config.Aimbot->AimbotSpeed), 0.0f, 100.0f);

    // Debug: Imprimir valores para ver si VMProtect los altera
    std::cout << "SmoothFactor (from Config): " << g_Config.Aimbot->AimbotSpeed << std::endl;
    std::cout << "SmoothFactor (Local): " << SmoothFactor << std::endl;

    // Forzar lectura correcta del SmoothStep desde memoria
    volatile float LocalSmoothStep = GetSmoothStep(SmoothFactor);

    std::cout << "SmoothStep: " << LocalSmoothStep << std::endl; // Para depuración

    // Aplicar interpolación de ángulos
    FinalAngles.x = CurrentViewAngles.x + (TargetViewAngles.x - CurrentViewAngles.x) * LocalSmoothStep;
    FinalAngles.y = CurrentViewAngles.y + (TargetViewAngles.y - CurrentViewAngles.y) * LocalSmoothStep;
    FinalAngles.z = CurrentViewAngles.z + (TargetViewAngles.z - CurrentViewAngles.z) * LocalSmoothStep;

    D3DXVec3Normalize(&FinalAngles, &FinalAngles);

    // Escribimos en memoria con valores correctos
    Mem.Write<D3DXVECTOR3>(CamFollowPedCamera + 0x40, FinalAngles);
    Mem.Write<D3DXVECTOR3>(CamFollowPedCamera + 0x3D0, FinalAngles);

#ifdef USE_VMPROTECT
    VMProtectEnd();
#endif
}

void Core::Features::cAimbot::Start()
{
#ifdef USE_VMPROTECT
    VMProtectBeginMutation("AimbotLoop");
#endif

    while (true)
    {
        if (g_Config.Aimbot->Enabled && g_Config.Aimbot->KeyBind && (GetAsyncKeyState(g_Config.Aimbot->KeyBind) & 0x8000) && GetForegroundWindow() != g_Variables.g_hCheatWindow)
        {
            CPed* Ped = Core::SDK::Game::GetClosestPed(g_Config.Aimbot->MaxDistance, g_Config.Aimbot->IgnoreNPCs, g_Config.Aimbot->OnlyVisible);
            if (!Ped) {
                std::this_thread::sleep_for(std::chrono::nanoseconds(1)); // Evitar consumo innecesario
                continue;
            }

            D3DXVECTOR3 HeadPos = Ped->GetBonePosDefault(0 /*Head*/);
            D3DXVECTOR2 ScreenHeadPos = Core::SDK::Game::WorldToScreen(HeadPos);

            if (Core::SDK::Game::IsOnScreen(ScreenHeadPos))
            {
                int Fov = std::hypot(ScreenHeadPos.x - g_Variables.g_vGameWindowCenter.x, ScreenHeadPos.y - g_Variables.g_vGameWindowCenter.y);
                if (Fov < g_Config.Aimbot->FOV)
                {
                    SetViewAngles(Ped, HeadPos + D3DXVECTOR3(0, 0, 0.08));
                }
            }
        }

        std::this_thread::sleep_for(std::chrono::nanoseconds(1)); // Mejora rendimiento sin afectar la suavidad
    }

#ifdef USE_VMPROTECT
    VMProtectEnd();
#endif
}


