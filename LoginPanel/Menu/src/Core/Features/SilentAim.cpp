#include "SilentAim.hpp"

bool Core::Features::cSilentAim::SilentAimInitialized;
std::uintptr_t Core::Features::cSilentAim::StartAddy;

void Core::Features::cSilentAim::InitializeSilentAim( )
{
	StartAddy = g_Offsets.m_SilentAim;
	SilentAimHook = Mem.CreateCodeCave( 500 );

	if ( !SilentAimHook )return;

	Mem.WriteBytes( SilentAimHook, SilentAimShell );

	OriginalFuncTable = Mem.ReadBytes( StartAddy, 38 );

	Mem.HookJMP( StartAddy, SilentAimHook );
}

void Core::Features::cSilentAim::RestoreSilent( )
{
	Mem.WriteBytes( StartAddy, OriginalFuncTable );
	Mem.FreeCave( SilentAimHook );
}

void Core::Features::cSilentAim::HookSilent( )
{
	while ( true )
	{
		if ( g_Config.SilentAim->Enabled && g_Config.SilentAim->KeyBind != 0 && GetAsyncKeyState( g_Config.SilentAim->KeyBind ) & 0x8000 && GetForegroundWindow( ) != g_Variables.g_hCheatWindow )
		{
			CPed * Ped = Core::SDK::Game::GetClosestPed( g_Config.SilentAim->MaxDistance, g_Config.SilentAim->IgnoreNPCs, g_Config.SilentAim->OnlyVisible );
			if ( !Ped ) { continue; }

			D3DXVECTOR3 HeadPos = Ped->GetBonePosDefault( 0 );
			D3DXVECTOR2 HeadToScreen = Core::SDK::Game::WorldToScreen( HeadPos );

			if ( Core::SDK::Game::IsOnScreen( HeadToScreen ) ) {
				int Fov = std::hypot( HeadToScreen.x - g_Variables.g_vGameWindowCenter.x, HeadToScreen.y - g_Variables.g_vGameWindowCenter.y );
				if ( Fov < g_Config.SilentAim->FOV ) {

					if ( !SilentAimInitialized ) {
						InitializeSilentAim( );
						SilentAimInitialized = true;
					}

					bool Miss = g_Config.SilentAim->MissChance >= Utils::GenRandomInt( 0, 100 );
					auto FinalPos = Miss ? HeadPos + D3DXVECTOR3( 0.0, 0.4, 0 ) :  HeadPos + D3DXVECTOR3( 0, 0, 0.08 );

					memcpy( SilentAimShell.data( ) + 3, &FinalPos.x, sizeof( float ) );
					memcpy( SilentAimShell.data( ) + 10, &FinalPos.y, sizeof( float ) );
					memcpy( SilentAimShell.data( ) + 17, &FinalPos.z, sizeof( float ) );

					uintptr_t BackAddress = ( uintptr_t ) ( StartAddy + 0x26 );
					memcpy( SilentAimShell.data( ) + 27, &BackAddress, sizeof( BackAddress ) );

					Mem.WriteBytes( SilentAimHook, SilentAimShell );

				}
				else {
					if ( SilentAimInitialized ) {
						RestoreSilent( );
						SilentAimInitialized = false;
					}
				}
			}
			else {
				if ( SilentAimInitialized ) {
					RestoreSilent( );
					SilentAimInitialized = false;
				}
			}

		}
		else {
			if ( SilentAimInitialized ) {
				RestoreSilent( );
				SilentAimInitialized = false;
			}
		}

		std::this_thread::sleep_for( std::chrono::nanoseconds( 10 ) );
	}
}