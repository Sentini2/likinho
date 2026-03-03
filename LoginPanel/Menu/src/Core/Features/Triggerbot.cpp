#include "Triggerbot.hpp"

void Core::Features::cTriggerbot::Shoot( int delay )
{
	std::this_thread::sleep_for( std::chrono::milliseconds( delay ) );
	mouse_event( MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0 );
	std::this_thread::sleep_for( std::chrono::nanoseconds( 500 ) );
	mouse_event( MOUSEEVENTF_LEFTUP, 0, 0, 0, 0 );
}

void Core::Features::cTriggerbot::Start( )
{
	while ( true )
	{
		
		if ( g_Config.TriggerBot->Enabled && g_Config.TriggerBot->KeyBind && GetAsyncKeyState(g_Config.TriggerBot->KeyBind) & 0x8000 && GetForegroundWindow() != g_Variables.g_hCheatWindow)
		{
			if (!g_Config.TriggerBot->SmartTrigger)
			{

				CPed* Ped = Core::SDK::Game::GetClosestPed(g_Config.TriggerBot->MaxDistance, g_Config.TriggerBot->IgnoreNPCs, g_Config.TriggerBot->OnlyVisible);
				if (!Ped) 
					continue;

				D3DXVECTOR3 HeadPos = Ped->GetBonePosDefault(0 /*Head*/);
				D3DXVECTOR2 ScreenHeadPos = Core::SDK::Game::WorldToScreen(HeadPos);

				if (Core::SDK::Game::IsOnScreen(ScreenHeadPos))
				{
					int Fov = std::hypot(ScreenHeadPos.x - g_Variables.g_vGameWindowCenter.x, ScreenHeadPos.y - g_Variables.g_vGameWindowCenter.y);
					if (Fov < g_Config.TriggerBot->FOV)
					{
						Shoot(g_Config.TriggerBot->Delay);
					}
				}
			}
			else
			{
				CPed* Ped = Mem.Read<CPed*>(g_Offsets.m_AimCPedPatternResult + Mem.Read<int>(g_Offsets.m_AimCPedPatternResult + 3) + 7);
				
				if (!Ped)
					continue;

				Shoot(g_Config.TriggerBot->Delay);
			}
			
		}
		std::this_thread::sleep_for( std::chrono::nanoseconds( 1 ) );
	}
}