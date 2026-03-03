#pragma once
#include <Includes/Includes.hpp>
#include <Includes/Utils.hpp>
#include <Core/Offsets.hpp>
#include <Core/Core.hpp>
#include <iostream>
#include <fstream>
#include <string>
#include <regex>

namespace Core 
{
    namespace Threads 
    {
        class cUpdatePtrs {
        public:
            void Update( )
            {
                while ( true )
                {
                    std::this_thread::sleep_for( std::chrono::seconds( 2 ) );

                    //if ( !g_MenuInfo.IsLogged && !g_Variables.g_bPassedByThisVerify )
                     //   continue;

                    Core::SDK::Pointers::pWorld = Mem.Read<CPedFactory *>( g_Offsets.m_World );
                    Core::SDK::Pointers::pLocalPlayer = Core::SDK::Pointers::pWorld->GetLocalPlayer( );
                    Core::SDK::Pointers::pReplayInterFace = Mem.Read<CReplayInterFace *>( g_Offsets.m_ReplayInterFace );
                    Core::SDK::Pointers::pViewPort = Mem.Read<uintptr_t>( g_Offsets.m_ViewPort );
                    Core::SDK::Pointers::pCamGamePlayDirector = Mem.Read<uintptr_t>( g_Offsets.m_CamGameplayDirector );
                }
            }
        };

        inline cUpdatePtrs g_UpdatePtrs;
    }
}
