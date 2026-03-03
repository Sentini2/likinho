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
        class cVehicleList {
        private:
            CVehInterFace * VehInterface = nullptr;
            CVehicleList * VehList = nullptr;
            int MaxVehicles;
        public:
            std::mutex vehicleListMutex;
        public:
            void Update( )
            {
                while ( true )
                {

                    std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );

                   // if ( !g_MenuInfo.IsLogged && !g_Variables.g_bPassedByThisVerify )
                        //continue;

                    if ( !Core::SDK::Pointers::pReplayInterFace )
                        continue;

                    if ( !VehInterface || !VehList )
                    {
                        VehInterface = Core::SDK::Pointers::pReplayInterFace->InterfaceVeh( );
                        if ( !VehInterface )
                            continue; //*

                        VehList = VehInterface->VehicleList( );
                        if ( !VehList )
                            continue; //*
                    };

                    if ( !MaxVehicles )
                        MaxVehicles = VehInterface->MaxVehicles( );

                    size_t Size = Core::SDK::Game::VehicleList.size( );
                    size_t Index = 0;

                    std::vector<Core::SDK::Game::VehicleStructure> updatedVehicleList;

                    for ( int i = 0; i < MaxVehicles; i++ )
                    {
                        CVehicle * CurrentVeh = VehList->Vehicle( i );

                        //if ( CurrentVeh == Core::SDK::Pointers::pLocalPlayer->GetLastVehicle( ) )
                        //    continue;

                        uintptr_t vehicleModelInfo = Mem.Read<uintptr_t>( ( uintptr_t ) CurrentVeh + 0x20 );
                        std::string vehicleName = Mem.ReadString( vehicleModelInfo + 0x298 );
                        D3DXVECTOR3 DistanceCalculation = CurrentVeh->GetPos( ) - Core::SDK::Pointers::pLocalPlayer->GetPos( );
                        float Distance = sqrtf( DistanceCalculation.x * DistanceCalculation.x + DistanceCalculation.y * DistanceCalculation.y + DistanceCalculation.z * DistanceCalculation.z );

                        if ( vehicleName.empty( ) )
                            continue;

                        Core::SDK::Game::VehicleStructure Vehicle;

                        Vehicle.Pointer = CurrentVeh;
                        Vehicle.Name = Utils::StringToFirstUpperCase( vehicleName );
                        Vehicle.Dist = Distance;
                        Vehicle.IsLocked = CurrentVeh->IsLocked( );
                        Vehicle.Driver = CurrentVeh->GetDriver( );
                        Vehicle.Pos = CurrentVeh->GetPos( );

                        updatedVehicleList.push_back( Vehicle );
                    }

                    std::sort( updatedVehicleList.begin( ), updatedVehicleList.end( ), [ ] ( const auto & lhs, const auto & rhs ) { return lhs.Dist < rhs.Dist; } );

                    {
                        std::lock_guard<std::mutex> lock( vehicleListMutex );
                        Core::SDK::Game::VehicleList = std::move( updatedVehicleList );
                    }

                }
            }
        };

        inline cVehicleList g_VehicleList;
    }
}