#pragma once
#include <Includes/Includes.hpp>
#include <Includes/Utils.hpp>
#include <iostream>
#include <fstream>
#include <sstream>
#include <set>
#include <string>
namespace Core {

	class Config {
	public:
		Config() {
			General = new struct General();
			Aimbot = new struct Aimbot();
			TriggerBot = new struct TriggerBot();
			SilentAim = new struct SilentAim();
			ESP = new struct ESP();
			VehicleESP = new struct VehicleESP();
			Player = new struct Player();
		}

		struct General {
		public:
			inline static bool StreamProof = false;
			inline static bool WaterMark;
			inline static bool WaterMarkCol;
			inline static bool ArrayList;
			inline static bool ArrayListCol;
			inline static bool VSync = true;
			inline static int ProcessPriority = 0;
			inline static int MenuKey = VK_INSERT;
		} *General;

		struct Aimbot {
		public:
			inline static bool Enabled;
			inline static bool ShowFov;
			inline static bool OnlyVisible;
			inline static bool IgnoreNPCs;
			inline static bool Prediction;
			inline static int FOV = 180;
			inline static int MaxDistance = 240;
			//inline static int SmoothHorizontal = 12;
			//inline static int SmoothVertical = 12;
			inline static int AimbotSpeed = 12;
			inline static int KeyBind;
			inline static ImColor FovColor { 255, 255, 255 };
			inline static std::set<std::string> FriendList;
		} *Aimbot;

		struct TriggerBot {
		public:
			inline static bool Enabled;
			inline static bool ShowFov;
			inline static bool OnlyVisible;
			inline static bool IgnoreNPCs;
			inline static bool SmartTrigger;
			inline static int FOV = 20;
			inline static int MaxDistance = 200;
			inline static int Delay = 0;
			inline static int KeyBind;
			inline static ImColor FovColor { 255, 255, 255 };
		} *TriggerBot;

		struct SilentAim {
		public:
			inline static bool Enabled;
			inline static bool ShowFov;
			inline static bool OnlyVisible;
			inline static bool MagicBullets;
			inline static bool IgnoreNPCs;
			inline static int FOV = 40;
			inline static int MissChance = 0;
			inline static int MaxDistance = 200;
			inline static int KeyBind;
			inline static ImColor FovColor { 224, 94, 103, 200 };
		} *SilentAim;

		struct ESP {
		public:
			inline static bool UpdateCfgESP;
			inline static bool Enabled;
			inline static bool Box;
			inline static bool FilledBox;
			inline static int BoxState = 0;
			inline static bool Skeleton;
			inline static bool HealthBar;
			inline static ImVec2 HealthBarPos;
			inline static int HealthBarState = 0;
			inline static bool ArmorBar;
			inline static ImVec2 ArmorBarPos;
			inline static int ArmorBarState = 0;
			inline static bool WeaponName;
			inline static ImVec2 WeaponNamePos;
			inline static int WeaponNameState = 0;
			inline static bool SnapLines;
			inline static bool UserNames;
			inline static ImVec2 UserNamesPos;
			inline static int UserNamesState = 0;
			inline static bool HeadCircle;
			inline static bool IgnoreNPCs;
			inline static bool ShowLocalPlayer;
			inline static bool HighlightVisible;
			inline static bool IgnoreDead;
			inline static bool DistanceFromMe;
			inline static bool FriendsMarker;
			inline static int FriendsMarkerBind;
			inline static ImVec2 DistanceFromMePos;
			inline static int DistanceFromMeState = 0;
			inline static int MaxDistance = 200;
			inline static ImColor DistanceCol { 230, 230, 230, 255 };
			inline static ImColor UserNamesCol { 230, 230, 230, 255 };
			inline static ImColor WeaponNameCol { 230, 230, 230, 255 };
			inline static ImColor SkeletonCol { 255, 255, 255, 200 };
			inline static ImColor BoxCol { 255, 255, 255, 200 };
			inline static ImColor FilledBoxCol { 0, 0, 0, 40 };
			inline static ImColor SnapLinesCol { 255, 255, 255, 200 };
			inline static ImColor FriendCol { 255, 204, 0, 255 };
			inline static int KeyBind;
			// Admin System
			inline static bool AdminList;
			inline static bool AdminSkeleton;
			inline static bool AdminLines;
			inline static int AdminDistance = 150;
		} *ESP;

		struct VehicleESP {
		public:
			inline static bool Enabled;
			inline static bool SnapLines;
			inline static bool ShowLockUnlock;
			inline static bool VehName;
			inline static bool DistanceFromMe;
			inline static int MaxDistance = 200;
			inline static ImColor SnapLinesCol { 255, 255, 255, 200 };
		} *VehicleESP;

		struct Player {
		public:
			inline static float CurrentHealthValue;
			inline static float CurrentArmorValue;
			inline static bool FastRun;
			inline static float RunSpeed = 1.f;
			inline static bool InfiniteStamina;
			inline static bool WeaponOptions;
			inline static bool NoRecoilEnabled;
			inline static float RecoilValue;
			inline static bool NoSpreadEnabled;
			inline static float SpreadValue;
			inline static bool InfiniteAmmoEnabled;
			inline static bool NoReloadEnabled;
			inline static bool NoClipEnabled;
			inline static bool HandlingEditor;
			inline static int NoClipKey;
			inline static float NoClipSpeed = 2.0f;
			inline static bool InfiniteCombatRoll;
			inline static bool EnableGodMode;
			inline static bool VehicleGodMode;
			inline static bool SeatBelt;
			inline static bool ForceWeaponWheel;
			inline static bool ShrinkEnabled;
			inline static bool NoRagDollEnabled;
			inline static bool AntiHSEnabled;
			inline static bool StealCarEnabled;
			inline static int GodModeKey;
		} *Player;


		nlohmann::json ImColToJson( const ImColor & Col ) {
			return nlohmann::json::array( { Col.Value.x, Col.Value.y, Col.Value.z, Col.Value.w } );
		}

		ImColor JsonToImCol( const nlohmann::json & JsonCol ) {
			if ( JsonCol.is_array( ) && JsonCol.size( ) == 4 ) {
				float r = JsonCol[ 0 ];
				float g = JsonCol[ 1 ];
				float b = JsonCol[ 2 ];
				float a = JsonCol[ 3 ];
				return ImColor( r, g, b, a );
			}
			else {
				return ImColor( 0.0f, 0.0f, 0.0f, 1.0f );
			}
		}

		std::string SaveCurrentConfig( std::string CfgName )
		{
			try {
				nlohmann::json CfgJson;
				auto& GeneralCfg = CfgJson[ xorstr( "General" ) ];
				auto& FeaturesCfg = CfgJson;

				//General
				GeneralCfg[ xorstr( "StreamProof" ) ] = General->StreamProof;
				GeneralCfg[ xorstr( "WaterMark" ) ] = General->WaterMark;
				GeneralCfg[ xorstr( "ArrayList" ) ] = General->ArrayList;
				GeneralCfg[ xorstr( "VSync" ) ] = General->VSync;
				GeneralCfg[ xorstr( "ProcessPriority" ) ] = General->ProcessPriority;
				GeneralCfg[ xorstr( "MenuKey" ) ] = General->MenuKey;

				// Features - Aimbot
				FeaturesCfg[ xorstr( "Aimbot" ) ][ xorstr( "Enabled" ) ] = Aimbot->Enabled;
				FeaturesCfg[ xorstr( "Aimbot" ) ][ xorstr( "ShowFov" ) ] = Aimbot->ShowFov;
				FeaturesCfg[ xorstr( "Aimbot" ) ][ xorstr( "OnlyVisible" ) ] = Aimbot->OnlyVisible;
				FeaturesCfg[ xorstr( "Aimbot" ) ][ xorstr( "IgnoreNPCs" ) ] = Aimbot->IgnoreNPCs;
				FeaturesCfg[ xorstr( "Aimbot" ) ][ xorstr( "Prediction" ) ] = Aimbot->Prediction;
				FeaturesCfg[ xorstr( "Aimbot" ) ][ xorstr( "FOV" ) ] = Aimbot->FOV;
				FeaturesCfg[ xorstr( "Aimbot" ) ][ xorstr( "MaxDistance" ) ] = Aimbot->MaxDistance;
				//FeaturesCfg[ xorstr( "Aimbot" ) ][ xorstr( "SmoothHorizontal" ) ] = Aimbot->SmoothHorizontal;
				//FeaturesCfg[ xorstr( "Aimbot" ) ][ xorstr( "SmoothVertical" ) ] = Aimbot->SmoothHorizontal;
				FeaturesCfg[xorstr("Aimbot")][xorstr("AimSpeed")] = Aimbot->AimbotSpeed;
				FeaturesCfg[ xorstr( "Aimbot" ) ][ xorstr( "KeyBind" ) ] = Aimbot->KeyBind;
				FeaturesCfg[ xorstr( "Aimbot" ) ][ xorstr( "FovColor" ) ] = ImColToJson( Aimbot->FovColor );

				// Features - TriggerBot
				FeaturesCfg[ xorstr( "TriggerBot" ) ][ xorstr( "Enabled" ) ] = TriggerBot->Enabled;
				FeaturesCfg[ xorstr( "TriggerBot" ) ][ xorstr( "ShowFov" ) ] = TriggerBot->ShowFov;
				FeaturesCfg[ xorstr( "TriggerBot" ) ][ xorstr( "OnlyVisible" ) ] = TriggerBot->OnlyVisible;
				FeaturesCfg[ xorstr( "TriggerBot" ) ][ xorstr( "IgnoreNPCs" ) ] = TriggerBot->IgnoreNPCs;
				FeaturesCfg[ xorstr( "TriggerBot" ) ][ xorstr( "FOV" ) ] = TriggerBot->FOV;
				FeaturesCfg[ xorstr( "TriggerBot" ) ][ xorstr( "MaxDistance" ) ] = TriggerBot->MaxDistance;
				FeaturesCfg[ xorstr( "TriggerBot" ) ][ xorstr( "Delay" ) ] = TriggerBot->Delay;
				FeaturesCfg[ xorstr( "TriggerBot" ) ][ xorstr( "KeyBind" ) ] = TriggerBot->KeyBind;
				FeaturesCfg[ xorstr( "TriggerBot" ) ][ xorstr( "FovColor" ) ] = ImColToJson( TriggerBot->FovColor );

				// Features - SilentAim
				FeaturesCfg[ xorstr( "SilentAim" ) ][ xorstr( "Enabled" ) ] = SilentAim->Enabled;
				FeaturesCfg[ xorstr( "SilentAim" ) ][ xorstr( "ShowFov" ) ] = SilentAim->ShowFov;
				FeaturesCfg[ xorstr( "SilentAim" ) ][ xorstr( "OnlyVisible" ) ] = SilentAim->OnlyVisible;
				FeaturesCfg[ xorstr( "SilentAim" ) ][ xorstr( "IgnoreNPCs" ) ] = SilentAim->IgnoreNPCs;
				FeaturesCfg[ xorstr( "SilentAim" ) ][ xorstr( "FOV" ) ] = SilentAim->FOV;
				FeaturesCfg[ xorstr( "SilentAim" ) ][ xorstr( "MaxDistance" ) ] = SilentAim->MaxDistance;
				FeaturesCfg[ xorstr( "SilentAim" ) ][ xorstr( "KeyBind" ) ] = SilentAim->KeyBind;
				FeaturesCfg[ xorstr( "SilentAim" ) ][ xorstr( "MissChance" ) ] = SilentAim->MissChance;
				FeaturesCfg[ xorstr( "SilentAim" ) ][ xorstr( "MagicBullets" ) ] = SilentAim->MagicBullets;
				FeaturesCfg[ xorstr( "SilentAim" ) ][ xorstr( "FovColor" ) ] = ImColToJson( SilentAim->FovColor );

				// Features - ESP
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "Enabled" ) ] = ESP->Enabled;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "Box" ) ] = ESP->Box;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "BoxState" ) ] = ESP->BoxState;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "Skeleton" ) ] = ESP->Skeleton;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "HealthBar" ) ] = ESP->HealthBar;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "HealthBarState" ) ] = ESP->HealthBarState;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "ArmorBar" ) ] = ESP->ArmorBar;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "ArmorBarState" ) ] = ESP->ArmorBarState;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "WeaponName" ) ] = ESP->WeaponName;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "WeaponNameState" ) ] = ESP->WeaponNameState;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "SnapLines" ) ] = ESP->SnapLines;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "UserNames" ) ] = ESP->UserNames;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "UserNamesState" ) ] = ESP->UserNamesState;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "HeadCircle" ) ] = ESP->HeadCircle;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "IgnoreNPCs" ) ] = ESP->IgnoreNPCs;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "HighlightVisible" ) ] = ESP->HighlightVisible;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "IgnoreDead" ) ] = ESP->IgnoreDead;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "DistanceFromMe" ) ] = ESP->DistanceFromMe;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "DistanceFromMeState" ) ] = ESP->DistanceFromMeState;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "MaxDistance" ) ] = ESP->MaxDistance;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "ShowLocalPlayer" ) ] = ESP->ShowLocalPlayer;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "FriendsMarker" ) ] = ESP->FriendsMarker;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "FriendsMarkerBind" ) ] = ESP->FriendsMarkerBind;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "DistanceCol" ) ] = ImColToJson( ESP->DistanceCol );
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "UserNamesCol" ) ] = ImColToJson( ESP->UserNamesCol );
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "WeaponNameCol" ) ] = ImColToJson( ESP->WeaponNameCol );
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "SkeletonCol" ) ] = ImColToJson( ESP->SkeletonCol );
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "BoxCol" ) ] = ImColToJson( ESP->BoxCol );
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "SnapLinesCol" ) ] = ImColToJson( ESP->SnapLinesCol );
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "FriendCol" ) ] = ImColToJson( ESP->FriendCol );

				// Features - VehicleESP
				FeaturesCfg[ xorstr( "VehicleESP" ) ][ xorstr( "Enabled" ) ] = VehicleESP->Enabled;
				FeaturesCfg[ xorstr( "VehicleESP" ) ][ xorstr( "SnapLines" ) ] = VehicleESP->SnapLines;
				FeaturesCfg[ xorstr( "VehicleESP" ) ][ xorstr( "ShowLockUnlock" ) ] = VehicleESP->ShowLockUnlock;
				FeaturesCfg[ xorstr( "VehicleESP" ) ][ xorstr( "VehName" ) ] = VehicleESP->VehName;
				FeaturesCfg[ xorstr( "VehicleESP" ) ][ xorstr( "DistanceFromMe" ) ] = VehicleESP->DistanceFromMe;
				FeaturesCfg[ xorstr( "VehicleESP" ) ][ xorstr( "MaxDistance" ) ] = VehicleESP->MaxDistance;
				FeaturesCfg[ xorstr( "VehicleESP" ) ][ xorstr( "SnapLinesCol" ) ] = ImColToJson( VehicleESP->SnapLinesCol );

				// Features - Player
				FeaturesCfg[ xorstr( "Player" ) ][ xorstr( "NoClipKey" ) ] = Player->NoClipKey;
				FeaturesCfg[ xorstr( "Player" ) ][ xorstr( "NoClipSpeed" ) ] = Player->NoClipSpeed;
				FeaturesCfg[ xorstr( "Player" ) ][ xorstr( "GodModeKey" ) ] = Player->GodModeKey;

				std::string CfgJsonStr = CfgJson.dump( );

				Utils::PasteClipboard( Utils::EncodeB64( Utils::Str2Hex( Utils::EncodeB64( CfgJsonStr ) ) ).c_str( ) );

				return xorstr( "Config Exported to Clipboard." );
			}
			catch ( const std::exception & e ) {
				return xorstr( "Failed to save config." );
			}
		}

		std::string SaveConfigFile( std::string filename, int language, int theme )
		{
			try {
				nlohmann::json CfgJson;
				auto& GeneralCfg = CfgJson[ xorstr( "General" ) ];
				auto& FeaturesCfg = CfgJson;

				//General
				GeneralCfg[ xorstr( "StreamProof" ) ] = General->StreamProof;
				GeneralCfg[ xorstr( "WaterMark" ) ] = General->WaterMark;
				GeneralCfg[ xorstr( "ArrayList" ) ] = General->ArrayList;
				GeneralCfg[ xorstr( "VSync" ) ] = General->VSync;
				GeneralCfg[ xorstr( "ProcessPriority" ) ] = General->ProcessPriority;
				GeneralCfg[ xorstr( "MenuKey" ) ] = General->MenuKey;

				// Features - Aimbot
				FeaturesCfg[ xorstr( "Aimbot" ) ][ xorstr( "Enabled" ) ] = Aimbot->Enabled;
				FeaturesCfg[ xorstr( "Aimbot" ) ][ xorstr( "ShowFov" ) ] = Aimbot->ShowFov;
				FeaturesCfg[ xorstr( "Aimbot" ) ][ xorstr( "OnlyVisible" ) ] = Aimbot->OnlyVisible;
				FeaturesCfg[ xorstr( "Aimbot" ) ][ xorstr( "IgnoreNPCs" ) ] = Aimbot->IgnoreNPCs;
				FeaturesCfg[ xorstr( "Aimbot" ) ][ xorstr( "Prediction" ) ] = Aimbot->Prediction;
				FeaturesCfg[ xorstr( "Aimbot" ) ][ xorstr( "FOV" ) ] = Aimbot->FOV;
				FeaturesCfg[ xorstr( "Aimbot" ) ][ xorstr( "MaxDistance" ) ] = Aimbot->MaxDistance;
				FeaturesCfg[xorstr("Aimbot")][xorstr("AimSpeed")] = Aimbot->AimbotSpeed;
				FeaturesCfg[ xorstr( "Aimbot" ) ][ xorstr( "KeyBind" ) ] = Aimbot->KeyBind;
				FeaturesCfg[ xorstr( "Aimbot" ) ][ xorstr( "FovColor" ) ] = ImColToJson( Aimbot->FovColor );

				// Features - TriggerBot
				FeaturesCfg[ xorstr( "TriggerBot" ) ][ xorstr( "Enabled" ) ] = TriggerBot->Enabled;
				FeaturesCfg[ xorstr( "TriggerBot" ) ][ xorstr( "ShowFov" ) ] = TriggerBot->ShowFov;
				FeaturesCfg[ xorstr( "TriggerBot" ) ][ xorstr( "OnlyVisible" ) ] = TriggerBot->OnlyVisible;
				FeaturesCfg[ xorstr( "TriggerBot" ) ][ xorstr( "IgnoreNPCs" ) ] = TriggerBot->IgnoreNPCs;
				FeaturesCfg[ xorstr( "TriggerBot" ) ][ xorstr( "FOV" ) ] = TriggerBot->FOV;
				FeaturesCfg[ xorstr( "TriggerBot" ) ][ xorstr( "MaxDistance" ) ] = TriggerBot->MaxDistance;
				FeaturesCfg[ xorstr( "TriggerBot" ) ][ xorstr( "Delay" ) ] = TriggerBot->Delay;
				FeaturesCfg[ xorstr( "TriggerBot" ) ][ xorstr( "KeyBind" ) ] = TriggerBot->KeyBind;
				FeaturesCfg[ xorstr( "TriggerBot" ) ][ xorstr( "FovColor" ) ] = ImColToJson( TriggerBot->FovColor );

				// Features - SilentAim
				FeaturesCfg[ xorstr( "SilentAim" ) ][ xorstr( "Enabled" ) ] = SilentAim->Enabled;
				FeaturesCfg[ xorstr( "SilentAim" ) ][ xorstr( "ShowFov" ) ] = SilentAim->ShowFov;
				FeaturesCfg[ xorstr( "SilentAim" ) ][ xorstr( "OnlyVisible" ) ] = SilentAim->OnlyVisible;
				FeaturesCfg[ xorstr( "SilentAim" ) ][ xorstr( "IgnoreNPCs" ) ] = SilentAim->IgnoreNPCs;
				FeaturesCfg[ xorstr( "SilentAim" ) ][ xorstr( "FOV" ) ] = SilentAim->FOV;
				FeaturesCfg[ xorstr( "SilentAim" ) ][ xorstr( "MaxDistance" ) ] = SilentAim->MaxDistance;
				FeaturesCfg[ xorstr( "SilentAim" ) ][ xorstr( "KeyBind" ) ] = SilentAim->KeyBind;
				FeaturesCfg[ xorstr( "SilentAim" ) ][ xorstr( "MissChance" ) ] = SilentAim->MissChance;
				FeaturesCfg[ xorstr( "SilentAim" ) ][ xorstr( "MagicBullets" ) ] = SilentAim->MagicBullets;
				FeaturesCfg[ xorstr( "SilentAim" ) ][ xorstr( "FovColor" ) ] = ImColToJson( SilentAim->FovColor );

				// Features - ESP
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "Enabled" ) ] = ESP->Enabled;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "Box" ) ] = ESP->Box;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "BoxState" ) ] = ESP->BoxState;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "Skeleton" ) ] = ESP->Skeleton;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "HealthBar" ) ] = ESP->HealthBar;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "HealthBarState" ) ] = ESP->HealthBarState;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "ArmorBar" ) ] = ESP->ArmorBar;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "ArmorBarState" ) ] = ESP->ArmorBarState;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "WeaponName" ) ] = ESP->WeaponName;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "WeaponNameState" ) ] = ESP->WeaponNameState;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "SnapLines" ) ] = ESP->SnapLines;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "UserNames" ) ] = ESP->UserNames;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "UserNamesState" ) ] = ESP->UserNamesState;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "HeadCircle" ) ] = ESP->HeadCircle;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "IgnoreNPCs" ) ] = ESP->IgnoreNPCs;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "HighlightVisible" ) ] = ESP->HighlightVisible;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "IgnoreDead" ) ] = ESP->IgnoreDead;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "DistanceFromMe" ) ] = ESP->DistanceFromMe;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "DistanceFromMeState" ) ] = ESP->DistanceFromMeState;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "MaxDistance" ) ] = ESP->MaxDistance;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "ShowLocalPlayer" ) ] = ESP->ShowLocalPlayer;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "FriendsMarker" ) ] = ESP->FriendsMarker;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "FriendsMarkerBind" ) ] = ESP->FriendsMarkerBind;
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "DistanceCol" ) ] = ImColToJson( ESP->DistanceCol );
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "UserNamesCol" ) ] = ImColToJson( ESP->UserNamesCol );
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "WeaponNameCol" ) ] = ImColToJson( ESP->WeaponNameCol );
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "SkeletonCol" ) ] = ImColToJson( ESP->SkeletonCol );
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "BoxCol" ) ] = ImColToJson( ESP->BoxCol );
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "SnapLinesCol" ) ] = ImColToJson( ESP->SnapLinesCol );
				FeaturesCfg[ xorstr( "ESP" ) ][ xorstr( "FriendCol" ) ] = ImColToJson( ESP->FriendCol );

				// Features - VehicleESP
				FeaturesCfg[ xorstr( "VehicleESP" ) ][ xorstr( "Enabled" ) ] = VehicleESP->Enabled;
				FeaturesCfg[ xorstr( "VehicleESP" ) ][ xorstr( "SnapLines" ) ] = VehicleESP->SnapLines;
				FeaturesCfg[ xorstr( "VehicleESP" ) ][ xorstr( "ShowLockUnlock" ) ] = VehicleESP->ShowLockUnlock;
				FeaturesCfg[ xorstr( "VehicleESP" ) ][ xorstr( "VehName" ) ] = VehicleESP->VehName;
				FeaturesCfg[ xorstr( "VehicleESP" ) ][ xorstr( "DistanceFromMe" ) ] = VehicleESP->DistanceFromMe;
				FeaturesCfg[ xorstr( "VehicleESP" ) ][ xorstr( "MaxDistance" ) ] = VehicleESP->MaxDistance;
				FeaturesCfg[ xorstr( "VehicleESP" ) ][ xorstr( "SnapLinesCol" ) ] = ImColToJson( VehicleESP->SnapLinesCol );

				// Features - Player
				FeaturesCfg[ xorstr( "Player" ) ][ xorstr( "NoClipKey" ) ] = Player->NoClipKey;
				FeaturesCfg[ xorstr( "Player" ) ][ xorstr( "NoClipSpeed" ) ] = Player->NoClipSpeed;
				FeaturesCfg[ xorstr( "Player" ) ][ xorstr( "GodModeKey" ) ] = Player->GodModeKey;

				// Global Settings
				FeaturesCfg[ xorstr( "Language" ) ] = language;
				FeaturesCfg[ xorstr( "Theme" ) ] = theme;

				std::string CfgJsonStr = CfgJson.dump( 4 );
				CreateDirectoryA(xorstr("cfg"), NULL); // Creates cfg dir if missing
				std::string path = std::string(xorstr("cfg\\")) + filename + xorstr(".json");
				std::ofstream file(path);
				if (file.is_open()) {
					file << CfgJsonStr;
					file.close();
				}
				
				return xorstr( "Config Saved to cfg/" ) + filename + xorstr( ".json" );
			}
			catch ( const std::exception & e ) {
				return xorstr( "Failed to save config." );
			}
		}

		std::string LoadConfigFile( std::string filename, int& outLanguage, int& outTheme )
		{
			try {
				std::string path = std::string(xorstr("cfg\\")) + filename + xorstr(".json");
				std::ifstream file(path);
				if (!file.is_open()) {
					return xorstr("No config found.");
				}

				std::stringstream buffer;
				buffer << file.rdbuf();
				std::string fileContent = buffer.str();
				nlohmann::json CfgJson = nlohmann::json( ).parse( fileContent );

				auto& GeneralCfg = CfgJson[ xorstr( "General" ) ];
				auto& FeaturesCfg = CfgJson;

				// General
				if ( GeneralCfg != NULL )
				{
					General->StreamProof = GeneralCfg[ xorstr( "StreamProof" ) ];
					General->WaterMark = GeneralCfg[ xorstr( "WaterMark" ) ];
					General->ArrayList = GeneralCfg[ xorstr( "ArrayList" ) ];
					General->VSync = GeneralCfg[ xorstr( "VSync" ) ];
					General->ProcessPriority = GeneralCfg[ xorstr( "ProcessPriority" ) ];
					General->MenuKey = GeneralCfg[ xorstr( "MenuKey" ) ];
				}

				// Global Settings
				if (FeaturesCfg.contains(xorstr("Language"))) {
					outLanguage = FeaturesCfg[xorstr("Language")];
				}
				if (FeaturesCfg.contains(xorstr("Theme"))) {
					outTheme = FeaturesCfg[xorstr("Theme")];
				}

				// Features - Aimbot
				if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("Enabled"))) Aimbot->Enabled = FeaturesCfg[xorstr("Aimbot")][xorstr("Enabled")];
				if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("ShowFov"))) Aimbot->ShowFov = FeaturesCfg[xorstr("Aimbot")][xorstr("ShowFov")];
				if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("OnlyVisible"))) Aimbot->OnlyVisible = FeaturesCfg[xorstr("Aimbot")][xorstr("OnlyVisible")];
				if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("IgnoreNPCs"))) Aimbot->IgnoreNPCs = FeaturesCfg[xorstr("Aimbot")][xorstr("IgnoreNPCs")];
				if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("Prediction"))) Aimbot->Prediction = FeaturesCfg[xorstr("Aimbot")][xorstr("Prediction")];
				if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("FOV"))) Aimbot->FOV = FeaturesCfg[xorstr("Aimbot")][xorstr("FOV")];
				if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("MaxDistance"))) Aimbot->MaxDistance = FeaturesCfg[xorstr("Aimbot")][xorstr("MaxDistance")];
				if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("AimSpeed"))) Aimbot->AimbotSpeed = FeaturesCfg[xorstr("Aimbot")][xorstr("AimSpeed")];
				if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("KeyBind"))) Aimbot->KeyBind = FeaturesCfg[xorstr("Aimbot")][xorstr("KeyBind")];
				if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("FovColor"))) Aimbot->FovColor = JsonToImCol(FeaturesCfg[xorstr("Aimbot")][xorstr("FovColor")]);

				// Features - TriggerBot
				if (FeaturesCfg[xorstr("TriggerBot")].contains(xorstr("Enabled"))) TriggerBot->Enabled = FeaturesCfg[xorstr("TriggerBot")][xorstr("Enabled")];
				if (FeaturesCfg[xorstr("TriggerBot")].contains(xorstr("ShowFov"))) TriggerBot->ShowFov = FeaturesCfg[xorstr("TriggerBot")][xorstr("ShowFov")];
				if (FeaturesCfg[xorstr("TriggerBot")].contains(xorstr("OnlyVisible"))) TriggerBot->OnlyVisible = FeaturesCfg[xorstr("TriggerBot")][xorstr("OnlyVisible")];
				if (FeaturesCfg[xorstr("TriggerBot")].contains(xorstr("IgnoreNPCs"))) TriggerBot->IgnoreNPCs = FeaturesCfg[xorstr("TriggerBot")][xorstr("IgnoreNPCs")];
				if (FeaturesCfg[xorstr("TriggerBot")].contains(xorstr("FOV"))) TriggerBot->FOV = FeaturesCfg[xorstr("TriggerBot")][xorstr("FOV")];
				if (FeaturesCfg[xorstr("TriggerBot")].contains(xorstr("MaxDistance"))) TriggerBot->MaxDistance = FeaturesCfg[xorstr("TriggerBot")][xorstr("MaxDistance")];
				if (FeaturesCfg[xorstr("TriggerBot")].contains(xorstr("Delay"))) TriggerBot->Delay = FeaturesCfg[xorstr("TriggerBot")][xorstr("Delay")];
				if (FeaturesCfg[xorstr("TriggerBot")].contains(xorstr("KeyBind"))) TriggerBot->KeyBind = FeaturesCfg[xorstr("TriggerBot")][xorstr("KeyBind")];
				if (FeaturesCfg[xorstr("TriggerBot")].contains(xorstr("FovColor"))) TriggerBot->FovColor = JsonToImCol(FeaturesCfg[xorstr("TriggerBot")][xorstr("FovColor")]);

				// Features - SilentAim
				if (FeaturesCfg[xorstr("SilentAim")].contains(xorstr("Enabled"))) SilentAim->Enabled = FeaturesCfg[xorstr("SilentAim")][xorstr("Enabled")];
				if (FeaturesCfg[xorstr("SilentAim")].contains(xorstr("ShowFov"))) SilentAim->ShowFov = FeaturesCfg[xorstr("SilentAim")][xorstr("ShowFov")];
				if (FeaturesCfg[xorstr("SilentAim")].contains(xorstr("OnlyVisible"))) SilentAim->OnlyVisible = FeaturesCfg[xorstr("SilentAim")][xorstr("OnlyVisible")];
				if (FeaturesCfg[xorstr("SilentAim")].contains(xorstr("IgnoreNPCs"))) SilentAim->IgnoreNPCs = FeaturesCfg[xorstr("SilentAim")][xorstr("IgnoreNPCs")];
				if (FeaturesCfg[xorstr("SilentAim")].contains(xorstr("FOV"))) SilentAim->FOV = FeaturesCfg[xorstr("SilentAim")][xorstr("FOV")];
				if (FeaturesCfg[xorstr("SilentAim")].contains(xorstr("MaxDistance"))) SilentAim->MaxDistance = FeaturesCfg[xorstr("SilentAim")][xorstr("MaxDistance")];
				if (FeaturesCfg[xorstr("SilentAim")].contains(xorstr("KeyBind"))) SilentAim->KeyBind = FeaturesCfg[xorstr("SilentAim")][xorstr("KeyBind")];
				if (FeaturesCfg[xorstr("SilentAim")].contains(xorstr("MagicBullets"))) SilentAim->MagicBullets = FeaturesCfg[xorstr("SilentAim")][xorstr("MagicBullets")];
				if (FeaturesCfg[xorstr("SilentAim")].contains(xorstr("FovColor"))) SilentAim->FovColor = JsonToImCol(FeaturesCfg[xorstr("SilentAim")][xorstr("FovColor")]);

				// Features - ESP
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("Enabled"))) ESP->Enabled = FeaturesCfg[xorstr("ESP")][xorstr("Enabled")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("Box"))) ESP->Box = FeaturesCfg[xorstr("ESP")][xorstr("Box")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("BoxState"))) ESP->BoxState = FeaturesCfg[xorstr("ESP")][xorstr("BoxState")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("Skeleton"))) ESP->Skeleton = FeaturesCfg[xorstr("ESP")][xorstr("Skeleton")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("HealthBar"))) ESP->HealthBar = FeaturesCfg[xorstr("ESP")][xorstr("HealthBar")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("HealthBarState"))) ESP->HealthBarState = FeaturesCfg[xorstr("ESP")][xorstr("HealthBarState")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("ArmorBar"))) ESP->ArmorBar = FeaturesCfg[xorstr("ESP")][xorstr("ArmorBar")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("ArmorBarState"))) ESP->ArmorBarState = FeaturesCfg[xorstr("ESP")][xorstr("ArmorBarState")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("WeaponName"))) ESP->WeaponName = FeaturesCfg[xorstr("ESP")][xorstr("WeaponName")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("WeaponNameState"))) ESP->WeaponNameState = FeaturesCfg[xorstr("ESP")][xorstr("WeaponNameState")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("SnapLines"))) ESP->SnapLines = FeaturesCfg[xorstr("ESP")][xorstr("SnapLines")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("UserNames"))) ESP->UserNames = FeaturesCfg[xorstr("ESP")][xorstr("UserNames")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("UserNamesState"))) ESP->UserNamesState = FeaturesCfg[xorstr("ESP")][xorstr("UserNamesState")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("HeadCircle"))) ESP->HeadCircle = FeaturesCfg[xorstr("ESP")][xorstr("HeadCircle")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("IgnoreNPCs"))) ESP->IgnoreNPCs = FeaturesCfg[xorstr("ESP")][xorstr("IgnoreNPCs")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("HighlightVisible"))) ESP->HighlightVisible = FeaturesCfg[xorstr("ESP")][xorstr("HighlightVisible")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("IgnoreDead"))) ESP->IgnoreDead = FeaturesCfg[xorstr("ESP")][xorstr("IgnoreDead")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("DistanceFromMe"))) ESP->DistanceFromMe = FeaturesCfg[xorstr("ESP")][xorstr("DistanceFromMe")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("DistanceFromMeState"))) ESP->DistanceFromMeState = FeaturesCfg[xorstr("ESP")][xorstr("DistanceFromMeState")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("ShowLocalPlayer"))) ESP->ShowLocalPlayer = FeaturesCfg[xorstr("ESP")][xorstr("ShowLocalPlayer")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("MaxDistance"))) ESP->MaxDistance = FeaturesCfg[xorstr("ESP")][xorstr("MaxDistance")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("DistanceCol"))) ESP->DistanceCol = JsonToImCol(FeaturesCfg[xorstr("ESP")][xorstr("DistanceCol")]);
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("UserNamesCol"))) ESP->UserNamesCol = JsonToImCol(FeaturesCfg[xorstr("ESP")][xorstr("UserNamesCol")]);
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("WeaponNameCol"))) ESP->WeaponNameCol = JsonToImCol(FeaturesCfg[xorstr("ESP")][xorstr("WeaponNameCol")]);
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("SkeletonCol"))) ESP->SkeletonCol = JsonToImCol(FeaturesCfg[xorstr("ESP")][xorstr("SkeletonCol")]);
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("BoxCol"))) ESP->BoxCol = JsonToImCol(FeaturesCfg[xorstr("ESP")][xorstr("BoxCol")]);
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("SnapLinesCol"))) ESP->SnapLinesCol = JsonToImCol(FeaturesCfg[xorstr("ESP")][xorstr("SnapLinesCol")]);
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("FriendCol"))) ESP->FriendCol = JsonToImCol(FeaturesCfg[xorstr("ESP")][xorstr("FriendCol")]);

				// Features - VehicleESP
				if (FeaturesCfg[xorstr("VehicleESP")].contains(xorstr("Enabled"))) VehicleESP->Enabled = FeaturesCfg[xorstr("VehicleESP")][xorstr("Enabled")];
				if (FeaturesCfg[xorstr("VehicleESP")].contains(xorstr("SnapLines"))) VehicleESP->SnapLines = FeaturesCfg[xorstr("VehicleESP")][xorstr("SnapLines")];
				if (FeaturesCfg[xorstr("VehicleESP")].contains(xorstr("ShowLockUnlock"))) VehicleESP->ShowLockUnlock = FeaturesCfg[xorstr("VehicleESP")][xorstr("ShowLockUnlock")];
				if (FeaturesCfg[xorstr("VehicleESP")].contains(xorstr("VehName"))) VehicleESP->VehName = FeaturesCfg[xorstr("VehicleESP")][xorstr("VehName")];
				if (FeaturesCfg[xorstr("VehicleESP")].contains(xorstr("DistanceFromMe"))) VehicleESP->DistanceFromMe = FeaturesCfg[xorstr("VehicleESP")][xorstr("DistanceFromMe")];
				if (FeaturesCfg[xorstr("VehicleESP")].contains(xorstr("MaxDistance"))) VehicleESP->MaxDistance = FeaturesCfg[xorstr("VehicleESP")][xorstr("MaxDistance")];
				if (FeaturesCfg[xorstr("VehicleESP")].contains(xorstr("SnapLinesCol"))) VehicleESP->SnapLinesCol = JsonToImCol(FeaturesCfg[xorstr("VehicleESP")][xorstr("SnapLinesCol")]);

				// Features - Player
				if (FeaturesCfg[xorstr("Player")].contains(xorstr("NoClipKey"))) Player->NoClipKey = FeaturesCfg[xorstr("Player")][xorstr("NoClipKey")];
				if (FeaturesCfg[xorstr("Player")].contains(xorstr("NoClipSpeed"))) Player->NoClipSpeed = FeaturesCfg[xorstr("Player")][xorstr("NoClipSpeed")];
				if (FeaturesCfg[xorstr("Player")].contains(xorstr("GodModeKey"))) Player->GodModeKey = FeaturesCfg[xorstr("Player")][xorstr("GodModeKey")];

				ESP->UpdateCfgESP = true;

				return xorstr( "Config loaded with success." );
			}
			catch ( const std::exception & e ) {
				return xorstr( "Error Loading Config!");
			}
		}

		std::string LoadCfg( std::string CfgName, std::string CfgCode )
		{
			try {
				std::string DecCfgCodeStr = Utils::DecodeB64( Utils::Hex2Str( Utils::DecodeB64( CfgCode ) ) );
				nlohmann::json CfgJson = nlohmann::json( ).parse( DecCfgCodeStr );

	
				auto& GeneralCfg = CfgJson[ xorstr( "General" ) ];
				auto& FeaturesCfg = CfgJson;

				// General
				if ( GeneralCfg != NULL )
				{
					General->StreamProof = GeneralCfg[ xorstr( "StreamProof" ) ];
					General->WaterMark = GeneralCfg[ xorstr( "WaterMark" ) ];
					General->ArrayList = GeneralCfg[ xorstr( "ArrayList" ) ];
					General->VSync = GeneralCfg[ xorstr( "VSync" ) ];
					General->ProcessPriority = GeneralCfg[ xorstr( "ProcessPriority" ) ];
					General->MenuKey = GeneralCfg[ xorstr( "MenuKey" ) ];
				}

				// Features - Aimbot
				if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("Enabled"))) Aimbot->Enabled = FeaturesCfg[xorstr("Aimbot")][xorstr("Enabled")];
				if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("ShowFov"))) Aimbot->ShowFov = FeaturesCfg[xorstr("Aimbot")][xorstr("ShowFov")];
				if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("OnlyVisible"))) Aimbot->OnlyVisible = FeaturesCfg[xorstr("Aimbot")][xorstr("OnlyVisible")];
				if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("IgnoreNPCs"))) Aimbot->IgnoreNPCs = FeaturesCfg[xorstr("Aimbot")][xorstr("IgnoreNPCs")];
				if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("Prediction"))) Aimbot->Prediction = FeaturesCfg[xorstr("Aimbot")][xorstr("Prediction")];
				if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("FOV"))) Aimbot->FOV = FeaturesCfg[xorstr("Aimbot")][xorstr("FOV")];
				if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("MaxDistance"))) Aimbot->MaxDistance = FeaturesCfg[xorstr("Aimbot")][xorstr("MaxDistance")];
				//if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("SmoothHorizontal"))) Aimbot->SmoothHorizontal = FeaturesCfg[xorstr("Aimbot")][xorstr("SmoothHorizontal")];
				//if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("SmoothVertical"))) Aimbot->SmoothVertical = FeaturesCfg[xorstr("Aimbot")][xorstr("SmoothVertical")];
				if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("AimSpeed"))) Aimbot->AimbotSpeed = FeaturesCfg[xorstr("Aimbot")][xorstr("AimSpeed")];
				if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("KeyBind"))) Aimbot->KeyBind = FeaturesCfg[xorstr("Aimbot")][xorstr("KeyBind")];
				if (FeaturesCfg[xorstr("Aimbot")].contains(xorstr("FovColor"))) Aimbot->FovColor = JsonToImCol(FeaturesCfg[xorstr("Aimbot")][xorstr("FovColor")]);

				// Features - TriggerBot
				if (FeaturesCfg[xorstr("TriggerBot")].contains(xorstr("Enabled"))) TriggerBot->Enabled = FeaturesCfg[xorstr("TriggerBot")][xorstr("Enabled")];
				if (FeaturesCfg[xorstr("TriggerBot")].contains(xorstr("ShowFov"))) TriggerBot->ShowFov = FeaturesCfg[xorstr("TriggerBot")][xorstr("ShowFov")];
				if (FeaturesCfg[xorstr("TriggerBot")].contains(xorstr("OnlyVisible"))) TriggerBot->OnlyVisible = FeaturesCfg[xorstr("TriggerBot")][xorstr("OnlyVisible")];
				if (FeaturesCfg[xorstr("TriggerBot")].contains(xorstr("IgnoreNPCs"))) TriggerBot->IgnoreNPCs = FeaturesCfg[xorstr("TriggerBot")][xorstr("IgnoreNPCs")];
				if (FeaturesCfg[xorstr("TriggerBot")].contains(xorstr("FOV"))) TriggerBot->FOV = FeaturesCfg[xorstr("TriggerBot")][xorstr("FOV")];
				if (FeaturesCfg[xorstr("TriggerBot")].contains(xorstr("MaxDistance"))) TriggerBot->MaxDistance = FeaturesCfg[xorstr("TriggerBot")][xorstr("MaxDistance")];
				if (FeaturesCfg[xorstr("TriggerBot")].contains(xorstr("Delay"))) TriggerBot->Delay = FeaturesCfg[xorstr("TriggerBot")][xorstr("Delay")];
				if (FeaturesCfg[xorstr("TriggerBot")].contains(xorstr("KeyBind"))) TriggerBot->KeyBind = FeaturesCfg[xorstr("TriggerBot")][xorstr("KeyBind")];
				if (FeaturesCfg[xorstr("TriggerBot")].contains(xorstr("FovColor"))) TriggerBot->FovColor = JsonToImCol(FeaturesCfg[xorstr("TriggerBot")][xorstr("FovColor")]);

				// Features - SilentAim
				if (FeaturesCfg[xorstr("SilentAim")].contains(xorstr("Enabled"))) SilentAim->Enabled = FeaturesCfg[xorstr("SilentAim")][xorstr("Enabled")];
				if (FeaturesCfg[xorstr("SilentAim")].contains(xorstr("ShowFov"))) SilentAim->ShowFov = FeaturesCfg[xorstr("SilentAim")][xorstr("ShowFov")];
				if (FeaturesCfg[xorstr("SilentAim")].contains(xorstr("OnlyVisible"))) SilentAim->OnlyVisible = FeaturesCfg[xorstr("SilentAim")][xorstr("OnlyVisible")];
				if (FeaturesCfg[xorstr("SilentAim")].contains(xorstr("IgnoreNPCs"))) SilentAim->IgnoreNPCs = FeaturesCfg[xorstr("SilentAim")][xorstr("IgnoreNPCs")];
				if (FeaturesCfg[xorstr("SilentAim")].contains(xorstr("FOV"))) SilentAim->FOV = FeaturesCfg[xorstr("SilentAim")][xorstr("FOV")];
				if (FeaturesCfg[xorstr("SilentAim")].contains(xorstr("MaxDistance"))) SilentAim->MaxDistance = FeaturesCfg[xorstr("SilentAim")][xorstr("MaxDistance")];
				if (FeaturesCfg[xorstr("SilentAim")].contains(xorstr("KeyBind"))) SilentAim->KeyBind = FeaturesCfg[xorstr("SilentAim")][xorstr("KeyBind")];
				if (FeaturesCfg[xorstr("SilentAim")].contains(xorstr("MagicBullets"))) SilentAim->MagicBullets = FeaturesCfg[xorstr("SilentAim")][xorstr("MagicBullets")];
				if (FeaturesCfg[xorstr("SilentAim")].contains(xorstr("FovColor"))) SilentAim->FovColor = JsonToImCol(FeaturesCfg[xorstr("SilentAim")][xorstr("FovColor")]);

				// Features - ESP
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("Enabled"))) ESP->Enabled = FeaturesCfg[xorstr("ESP")][xorstr("Enabled")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("Box"))) ESP->Box = FeaturesCfg[xorstr("ESP")][xorstr("Box")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("BoxState"))) ESP->BoxState = FeaturesCfg[xorstr("ESP")][xorstr("BoxState")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("Skeleton"))) ESP->Skeleton = FeaturesCfg[xorstr("ESP")][xorstr("Skeleton")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("HealthBar"))) ESP->HealthBar = FeaturesCfg[xorstr("ESP")][xorstr("HealthBar")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("HealthBarState"))) ESP->HealthBarState = FeaturesCfg[xorstr("ESP")][xorstr("HealthBarState")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("ArmorBar"))) ESP->ArmorBar = FeaturesCfg[xorstr("ESP")][xorstr("ArmorBar")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("ArmorBarState"))) ESP->ArmorBarState = FeaturesCfg[xorstr("ESP")][xorstr("ArmorBarState")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("WeaponName"))) ESP->WeaponName = FeaturesCfg[xorstr("ESP")][xorstr("WeaponName")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("WeaponNameState"))) ESP->WeaponNameState = FeaturesCfg[xorstr("ESP")][xorstr("WeaponNameState")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("SnapLines"))) ESP->SnapLines = FeaturesCfg[xorstr("ESP")][xorstr("SnapLines")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("UserNames"))) ESP->UserNames = FeaturesCfg[xorstr("ESP")][xorstr("UserNames")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("UserNamesState"))) ESP->UserNamesState = FeaturesCfg[xorstr("ESP")][xorstr("UserNamesState")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("HeadCircle"))) ESP->HeadCircle = FeaturesCfg[xorstr("ESP")][xorstr("HeadCircle")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("IgnoreNPCs"))) ESP->IgnoreNPCs = FeaturesCfg[xorstr("ESP")][xorstr("IgnoreNPCs")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("HighlightVisible"))) ESP->HighlightVisible = FeaturesCfg[xorstr("ESP")][xorstr("HighlightVisible")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("IgnoreDead"))) ESP->IgnoreDead = FeaturesCfg[xorstr("ESP")][xorstr("IgnoreDead")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("DistanceFromMe"))) ESP->DistanceFromMe = FeaturesCfg[xorstr("ESP")][xorstr("DistanceFromMe")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("DistanceFromMeState"))) ESP->DistanceFromMeState = FeaturesCfg[xorstr("ESP")][xorstr("DistanceFromMeState")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("ShowLocalPlayer"))) ESP->ShowLocalPlayer = FeaturesCfg[xorstr("ESP")][xorstr("ShowLocalPlayer")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("MaxDistance"))) ESP->MaxDistance = FeaturesCfg[xorstr("ESP")][xorstr("MaxDistance")];
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("DistanceCol"))) ESP->DistanceCol = JsonToImCol(FeaturesCfg[xorstr("ESP")][xorstr("DistanceCol")]);
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("UserNamesCol"))) ESP->UserNamesCol = JsonToImCol(FeaturesCfg[xorstr("ESP")][xorstr("UserNamesCol")]);
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("WeaponNameCol"))) ESP->WeaponNameCol = JsonToImCol(FeaturesCfg[xorstr("ESP")][xorstr("WeaponNameCol")]);
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("SkeletonCol"))) ESP->SkeletonCol = JsonToImCol(FeaturesCfg[xorstr("ESP")][xorstr("SkeletonCol")]);
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("BoxCol"))) ESP->BoxCol = JsonToImCol(FeaturesCfg[xorstr("ESP")][xorstr("BoxCol")]);
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("SnapLinesCol"))) ESP->SnapLinesCol = JsonToImCol(FeaturesCfg[xorstr("ESP")][xorstr("SnapLinesCol")]);
				if (FeaturesCfg[xorstr("ESP")].contains(xorstr("FriendCol"))) ESP->FriendCol = JsonToImCol(FeaturesCfg[xorstr("ESP")][xorstr("FriendCol")]);

				// Features - VehicleESP
				if (FeaturesCfg[xorstr("VehicleESP")].contains(xorstr("Enabled"))) VehicleESP->Enabled = FeaturesCfg[xorstr("VehicleESP")][xorstr("Enabled")];
				if (FeaturesCfg[xorstr("VehicleESP")].contains(xorstr("SnapLines"))) VehicleESP->SnapLines = FeaturesCfg[xorstr("VehicleESP")][xorstr("SnapLines")];
				if (FeaturesCfg[xorstr("VehicleESP")].contains(xorstr("ShowLockUnlock"))) VehicleESP->ShowLockUnlock = FeaturesCfg[xorstr("VehicleESP")][xorstr("ShowLockUnlock")];
				if (FeaturesCfg[xorstr("VehicleESP")].contains(xorstr("VehName"))) VehicleESP->VehName = FeaturesCfg[xorstr("VehicleESP")][xorstr("VehName")];
				if (FeaturesCfg[xorstr("VehicleESP")].contains(xorstr("DistanceFromMe"))) VehicleESP->DistanceFromMe = FeaturesCfg[xorstr("VehicleESP")][xorstr("DistanceFromMe")];
				if (FeaturesCfg[xorstr("VehicleESP")].contains(xorstr("MaxDistance"))) VehicleESP->MaxDistance = FeaturesCfg[xorstr("VehicleESP")][xorstr("MaxDistance")];
				if (FeaturesCfg[xorstr("VehicleESP")].contains(xorstr("SnapLinesCol"))) VehicleESP->SnapLinesCol = JsonToImCol(FeaturesCfg[xorstr("VehicleESP")][xorstr("SnapLinesCol")]);

				// Features - Player
				if (FeaturesCfg[xorstr("Player")].contains(xorstr("NoClipKey"))) Player->NoClipKey = FeaturesCfg[xorstr("Player")][xorstr("NoClipKey")];
				if (FeaturesCfg[xorstr("Player")].contains(xorstr("NoClipSpeed"))) Player->NoClipSpeed = FeaturesCfg[xorstr("Player")][xorstr("NoClipSpeed")];
				if (FeaturesCfg[xorstr("Player")].contains(xorstr("GodModeKey"))) Player->GodModeKey = FeaturesCfg[xorstr("Player")][xorstr("GodModeKey")];

				ESP->UpdateCfgESP = true;

				return xorstr( "Config loaded with success." );
			}
			catch ( const std::exception & e ) {
				//std::cout << e.what() << "\n";
				return xorstr( "Error Loading Config!");
			}
		}

	};

	inline Config g_Config;

}

