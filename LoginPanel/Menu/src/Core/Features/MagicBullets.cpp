#include "MagicBullets.hpp"

uintptr_t Core::Features::cMagicBullets::GetCWeaponObj( )
{
	//Atualizar Offsets
	CWeaponManager * WeaponMgr = Core::SDK::Pointers::pLocalPlayer->GetWeaponManager( );
	auto CObject = Mem.Read<uintptr_t>( ( uintptr_t ) WeaponMgr + g_Offsets.m_CObject );

	return Mem.Read<uintptr_t>( CObject + g_Offsets.m_CWeapon );
}

void Core::Features::cMagicBullets::Initialize( )
{
	CWeapon = this->GetCWeaponObj( );
	if ( !CWeapon || !g_Offsets.m_MagicBulletsPatch ) return;

	Mem.PatchFunc( g_Offsets.m_MagicBulletsPatch, 4 );
}

void Core::Features::cMagicBullets::Restore( )
{
	std::vector<uint8_t> UpdateMuzzlePosTable
	{
		0x0F, 0x29, 0x4F, 0x20 //movaps [rdi+20], xmm1
	};

	Mem.WriteBytes( g_Offsets.m_MagicBulletsPatch, UpdateMuzzlePosTable );
}

void Core::Features::cMagicBullets::Start( )
{
	while ( true )
	{
		if ( g_Config.SilentAim->MagicBullets && g_Config.SilentAim->KeyBind && GetAsyncKeyState( g_Config.SilentAim->KeyBind ) & 0x8000 && GetForegroundWindow( ) != g_Variables.g_hCheatWindow )
		{
			
			CPed * Ped = Core::SDK::Game::GetClosestPed( g_Config.SilentAim->MaxDistance, g_Config.SilentAim->IgnoreNPCs, g_Config.SilentAim->OnlyVisible );
			if ( !Ped ) { continue; }

			D3DXVECTOR3 HeadPos = Ped->GetBonePosDefault( 0 );
			D3DXVECTOR2 HeadToScreen = Core::SDK::Game::WorldToScreen( HeadPos );

			if ( Core::SDK::Game::IsOnScreen( HeadToScreen ) ) 
			{
				int Fov = std::hypot( HeadToScreen.x - g_Variables.g_vGameWindowCenter.x, HeadToScreen.y - g_Variables.g_vGameWindowCenter.y );
				if ( Fov < g_Config.SilentAim->FOV ) {

					if ( !Initialized ) {
						Initialize( );
						Initialized = true;
					}

					bool Miss = g_Config.SilentAim->MissChance >= Utils::GenRandomInt( 0, 100 );

					auto BulletStartPos = g_Config.SilentAim->Enabled ? HeadPos + D3DXVECTOR3( 0, 0, 0.3 ) : HeadPos;

					auto FinalPos = Miss ? BulletStartPos + D3DXVECTOR3( 0.0, 0.3, 0 ) : BulletStartPos;

					Mem.Write( CWeapon + 0x20, FinalPos );
				}
				else {
					if ( Initialized ) {
						Restore( );
						Initialized = false;
					}
				}
			}
			else {
				if ( Initialized ) {
					Restore( );
					Initialized = false;
				}
			}
		}
		else
		{
			if ( Initialized ) {
				Restore( );
				Initialized = false;
			}
		}

		std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
	}
}