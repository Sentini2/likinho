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
        class cEntityList 
        {
        private:
            std::mutex EntityListMutex;
        private:
            CPedInterFace * CPedInterFace = nullptr;
            CPedList * CPedList = nullptr;
        public:
            std::unordered_map<CPed *, Core::SDK::Game::EntityStruct> CachedEntities;
        public:
            void Update( )
            {
                while ( true )
                {
                    std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );

                    if ( !g_MenuInfo.IsLogged && !g_Variables.g_bPassedByThisVerify )
                        continue;

                    if ( !Core::SDK::Pointers::pReplayInterFace ) 
                        continue;

                    CPedInterFace = Core::SDK::Pointers::pReplayInterFace->InterfacePed( );
                    CPedList = CPedInterFace->PedList( );

                    if ( !CPedInterFace || !CPedList )
                        continue;

                    size_t Size = Core::SDK::Game::EntityList.size( );
                    size_t Index = 0;
                    static const int PedCount = CPedInterFace->MaxPed();

                    {
                        std::lock_guard<std::mutex> Guard( EntityListMutex );

                        for ( int i = 0; i < PedCount; i++ )
                        {
                            CPed * CurrentPed = CPedList->Ped( i );

                            if ( !CurrentPed )
                                continue;

                            //if ( CurrentPed == Core::SDK::Pointers::pLocalPlayer )
                                //continue;

                            if ( CachedEntities.find( CurrentPed ) == CachedEntities.end( ) ) 
                            {
                                Core::SDK::Game::EntityStruct NewEntity;
                                NewEntity.Id = CurrentPed->GetID( );
                                NewEntity.Index = i;
                                NewEntity.Pos = CurrentPed->GetPos( );
                                NewEntity.IsFriend = Core::SDK::Game::FriendMap[ CurrentPed ];
                                NewEntity.MaxHealth = CurrentPed->GetMaxHealth( );
                                NewEntity.Health = CurrentPed->GetHealth( );
                                NewEntity.Armor = CurrentPed->GetArmor( );
                                NewEntity.PedType = CurrentPed->GetPedType( );
                                NewEntity.Distance = CurrentPed->GetDistance( Core::SDK::Pointers::pLocalPlayer->GetPos( ), NewEntity.Pos );

                                CachedEntities[ CurrentPed ] = NewEntity;
                            }

                            Core::SDK::Game::EntityStruct CachedEntity = CachedEntities[ CurrentPed ];
                            CachedEntity.Health = CurrentPed->GetHealth( );
                            CachedEntity.Armor = CurrentPed->GetArmor( );
                            CachedEntity.Pos = CurrentPed->GetPos( );
                            CachedEntity.IsFriend = Core::SDK::Game::FriendMap[ CurrentPed ];
                            CachedEntity.Distance = CurrentPed->GetDistance( Core::SDK::Pointers::pLocalPlayer->GetPos( ), CachedEntity.Pos );
                            CachedEntity.WeaponName = CurrentPed->GetWeaponManager( )->GetWeaponInfo( )->GetName( );

                            Core::SDK::Game::EntityStruct Entity;
                            Entity.Ped = CurrentPed;
                            Entity.Id = CachedEntity.Id;

                            auto& NetworkInfo = Core::Threads::g_UpdateNames.NetworkMap[ Entity.Id ];

                            Entity.Index = CachedEntity.Index;
                            Entity.Pos = CachedEntity.Pos;
                            Entity.IsFriend = CachedEntity.IsFriend;
                            Entity.MaxHealth = CachedEntity.MaxHealth;
                            Entity.Health = CachedEntity.Health;
                            Entity.Armor = CachedEntity.Armor;
                            Entity.PedType = CachedEntity.PedType;
                            Entity.Distance = CachedEntity.Distance;
                            Entity.WeaponName = CachedEntity.WeaponName;

                            Entity.NetworkInfo.UserName = Utils::StringToFirstUpperCase( NetworkInfo.UserName );

                            if ( Entity.NetworkInfo.UserName.empty( ) ) {
                                Entity.NetworkInfo.UserName = xorstr( "Unknown" );
                            }

                            Entity.NetworkInfo.SteamId = NetworkInfo.SteamId;
                            Entity.NetworkInfo.DiscordId = NetworkInfo.DiscordId;

                            if ( Index < Size )
                                Core::SDK::Game::EntityList[ Index ] = Entity;
                            else
                                Core::SDK::Game::EntityList.push_back( Entity );

                            Index++;
                        }
                    }

                    if ( Index < Size )
                        Core::SDK::Game::EntityList.resize( Index );

                }
            }
        };

        inline cEntityList g_EntityList;
    }
}