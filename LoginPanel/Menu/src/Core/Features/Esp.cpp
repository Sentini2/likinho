#include "Esp.hpp"



void Core::Features::cEsp::Draw( )
{
	auto Cfg = g_Config.ESP;



	if ( !Cfg->Enabled )
		return;

	static std::unordered_map<CPed *, Core::SDK::Game::EspAnim> vEspAnimations;
	static std::vector<std::pair<std::string, float>> AdminAlerts;
	AdminAlerts.clear();
	ImVec4 admin_rgb;
	ImGui::ColorConvertHSVtoRGB(fmodf(ImGui::GetTime() * 1.5f, 1.0f), 1.0f, 1.0f, admin_rgb.x, admin_rgb.y, admin_rgb.z);
	admin_rgb.w = 1.0f;
	ImColor currentAdminCol = ImColor(admin_rgb);

	for ( auto & Entity : Core::SDK::Game::EntityList )
	{
		CPed * Ped = Entity.Ped;
		auto DrawList = ImGui::GetBackgroundDrawList( );

		auto & CurrentESPAnim = vEspAnimations[ Ped ];
		CurrentESPAnim.CanFadeOut = false;

		float Distance = Entity.Distance;
		float Health = Entity.Health;
		int PedType = Entity.PedType;
		bool IsFriend = false;
		
		if (!Entity.NetworkInfo.UserName.empty() && Entity.NetworkInfo.UserName != "Invalid") {
			IsFriend = g_Config.Aimbot->FriendList.find(Entity.NetworkInfo.UserName) != g_Config.Aimbot->FriendList.end();
		}
		bool IsLocalPlayer = Ped == Core::SDK::Pointers::pLocalPlayer;
		
		D3DXVECTOR2 screenPos = Core::SDK::Game::WorldToScreen(Entity.Pos);
		bool IsOnScreen = (screenPos.x != 0 || screenPos.y != 0);

		bool IsInvisible = (Mem.Read<BYTE>((uintptr_t)Ped + 0x2C) & 0x01) == 0;
		bool IsAdmin = IsInvisible && IsOnScreen;
		if (IsAdmin && Distance <= Cfg->AdminDistance && Cfg->AdminList) {
			AdminAlerts.push_back({Entity.NetworkInfo.UserName, Distance});
		}

		if ( !Cfg->ShowLocalPlayer && IsLocalPlayer )
			continue;

		if ( Distance > Cfg->MaxDistance )
			continue;

		if ( Cfg->IgnoreNPCs && PedType != 2 && !IsLocalPlayer )
			continue;

		if ( Cfg->IgnoreDead && !IsLocalPlayer )
		{
			if ( PedType == 2 )
			{
				if ( Health > 400.f || Health <= 101.f )
					continue;
			}
			else
			{
				if ( Health > 200.f || Health <= 1.f )
					continue;
			}
		}

		D3DXVECTOR3 HeadPos = Ped->GetBonePosDefault( 0 );
		D3DXVECTOR2 EntityTop;
		D3DXVECTOR2 EntityBottom;
		
		if (HeadPos.x == 0.f && HeadPos.y == 0.f && HeadPos.z == 0.f)
		{
			// FragInst is null because player is invisible (bones froze), fallback to root position
			EntityTop = Core::SDK::Game::WorldToScreen( Entity.Pos + D3DXVECTOR3( 0, 0, 0.8f ) );
			EntityBottom = Core::SDK::Game::WorldToScreen( Entity.Pos - D3DXVECTOR3( 0, 0, 1.0f ) );
		}
		else
		{
			EntityTop = Core::SDK::Game::WorldToScreen( HeadPos + D3DXVECTOR3( 0, 0, 0.2 ) ); //Head
			EntityBottom = Core::SDK::Game::WorldToScreen(
				Ped->GetBonePosDefault( 8 ) - ( g_Offsets.CurrentBuild >= 2802 ? D3DXVECTOR3( 0, 0, 2 ) : D3DXVECTOR3( 0, 0, 1.2 ) ) //Abdomen
			);
		}

		if ( !Core::SDK::Game::IsOnScreen( EntityTop ) || !Core::SDK::Game::IsOnScreen( EntityBottom ) )
			continue;

		float Height = EntityBottom.y - EntityTop.y;
		float Width = Height * 0.2f;

		const float BoxLeft = EntityTop.x - Width;
		const float BoxRight = EntityBottom.x + Width;

		ImVec2 BoxMin( BoxLeft, EntityTop.y );
		ImVec2 BoxMax( BoxRight, EntityBottom.y );
		ImVec2 BoxCenter = ImVec2( ( BoxMin.x + BoxMax.x ) * 0.5f, ( BoxMin.y + BoxMax.y ) * 0.5f );


		float FirstTextBoxTop = BoxMin.y - 18;

		float FirstTextBoxBottom = BoxMax.y + 4;
		float SecondTextBoxBottom = BoxMax.y + ( 4 * 2 ) + 8; //8 is padding
		float ThirdTextBoxBottom = BoxMax.y + ( 4 * 3 ) + ( 8 * 2 );

		if ( Cfg->HealthBarState == 2 && Cfg->ArmorBarState == 2 ) {
			FirstTextBoxBottom += 16;
			SecondTextBoxBottom += 16;
			ThirdTextBoxBottom += 16;
		}
		else if ( Cfg->HealthBarState == 2 ) {
			FirstTextBoxBottom += 8;
			SecondTextBoxBottom += 8;
			ThirdTextBoxBottom += 8;
		}
		else if ( Cfg->ArmorBarState == 2 ) {
			FirstTextBoxBottom += 16;
			SecondTextBoxBottom += 16;
			ThirdTextBoxBottom += 16;
		}

		if ( Cfg->HealthBarState == 0 && Cfg->ArmorBarState == 0 ) {
			FirstTextBoxTop -= 4;
		}
		else if ( Cfg->HealthBarState == 0 ) {
			FirstTextBoxTop -= 4;
		}
		else if ( Cfg->ArmorBarState == 0 ) {
			FirstTextBoxTop -= 4;
		}

		if ( Cfg->FriendsMarker && !IsLocalPlayer )
		{
			float radius = 2 / Distance;

			const static int FovRadius = 60;
			const static int Delay = 300;
			int Key = Cfg->FriendsMarkerBind;
			//std::string PlayerSetFriend = xorstr( "Press ") + std::string(keys[ Key ]) + xorstr(" to Add Friend" );
			std::string PlayerSetFriend = xorstr("Add Friend" );
			std::string PlayerUnFriend = xorstr( "Unfriend" );


			int FovSize = std::hypot( BoxCenter.x - g_Variables.g_vGameWindowCenter.x, BoxCenter.y - g_Variables.g_vGameWindowCenter.y );

			ImGui::PushFont( g_Variables.m_FontSmaller );

			if ( IsFriend && FovSize < FovRadius )
			{
				DrawList->AddCircleFilled( ImVec2( BoxCenter.x, BoxCenter.y ), radius + Distance < 1 ? 1 : 4, ImColor( 0, 0, 0 ), 999 );
				DrawList->AddCircleFilled( ImVec2( BoxCenter.x, BoxCenter.y ), radius + Distance < 1 ? 0 : 3, ImColor( g_Col.Base ), 999 );

				//ImVec2 TextSize = g_Variables.m_FontSmaller->CalcTextSizeA( g_Variables.m_FontSmaller->FontSize, FLT_MAX, 0.0f, PlayerUnFriend.c_str( ) );
				//DrawList->AddText( ImVec2( BoxCenter.x - ( TextSize.x / 2 ), BoxCenter.y ), ImColor( 0, 0, 0 ), PlayerUnFriend.c_str( ) );
				//DrawList->AddText( ImVec2( BoxCenter.x - ( TextSize.x / 2 ), BoxCenter.y - 2 ), ImColor( 255, 255, 255 ), PlayerUnFriend.c_str( ) );

				if ( Utils::KeyPressedWithDelay( Key, Delay ) )
				{
					IsFriend = false;
					Core::SDK::Game::FriendMap[ Ped ] = IsFriend;
				}
			}
			else if( !IsFriend && FovSize < FovRadius )
			{
				DrawList->AddCircleFilled( ImVec2( BoxCenter.x, BoxCenter.y ), radius + Distance < 1 ? 1 : 4, ImColor( 0, 0, 0 ), 999 );
				DrawList->AddCircleFilled( ImVec2( BoxCenter.x, BoxCenter.y ), radius + Distance < 1 ? 0 : 3, ImColor( 255, 255, 255 ), 999 );

				//ImVec2 TextSize = g_Variables.m_FontSmaller->CalcTextSizeA( g_Variables.m_FontSmaller->FontSize, FLT_MAX, 0.0f, PlayerSetFriend.c_str( ) );
				//DrawList->AddText( ImVec2( BoxCenter.x - ( TextSize.x / 2 ), BoxCenter.y ), ImColor( 0, 0, 0 ), PlayerSetFriend.c_str( ) );
				//DrawList->AddText( ImVec2( BoxCenter.x - ( TextSize.x / 2 ), BoxCenter.y - 1 ), ImColor( 255, 255, 255 ), PlayerSetFriend.c_str( ) );

				if ( Utils::KeyPressedWithDelay( Key, Delay ) )
				{
					IsFriend = true;
					Core::SDK::Game::FriendMap[ Ped ] = IsFriend;
				}
			}
			ImGui::PopFont( );
		}

		// Removemos "if (IsFriend) continue;" para que o ESP renderize os amigos
		// Porém se o usuario não quiser o ESP no amigo, removeríamos aqui. O Usuario pediu: "o esp dele fica azul skeleton boxes"

		if ( Cfg->SnapLines )
		{
			ImColor curLineCol = IsFriend ? Cfg->FriendCol : Cfg->SnapLinesCol;
			DrawList->AddLine( ImVec2( g_Variables.g_vGameWindowCenter.x, g_Variables.g_vGameWindowPos.y + g_Variables.g_vGameWindowSize.y ), ImVec2( BoxCenter.x, BoxMax.y ), ImColor( 0, 0, 0 ), 2.5 );
			DrawList->AddLine( ImVec2( g_Variables.g_vGameWindowCenter.x, g_Variables.g_vGameWindowPos.y + g_Variables.g_vGameWindowSize.y ), ImVec2( BoxCenter.x, BoxMax.y ), curLineCol, 1.5 );
		}

		if ( Cfg->Box )
		{
			if ( Cfg->FilledBox )
				DrawList->AddRectFilled( { BoxLeft, EntityTop.y }, { BoxRight, EntityBottom.y }, Cfg->FilledBoxCol, 0, 0 );

			ImColor drawBoxCol = IsFriend ? Cfg->FriendCol : Cfg->BoxCol;
			DrawList->AddRect( { BoxLeft - 1, EntityTop.y - 1 }, { BoxRight + 1, EntityBottom.y + 1 }, ImColor( 0, 0, 0, 200 ), 0, 0, 1.5 );
			DrawList->AddRect( { BoxLeft + 1, EntityTop.y + 1 }, { BoxRight - 1, EntityBottom.y - 1 }, ImColor( 0, 0, 0, 200 ), 0, 0, 1.5 );
			DrawList->AddRect( { BoxLeft, EntityTop.y }, { BoxRight, EntityBottom.y }, drawBoxCol, 0, 0, 1.5 );
		}

		if ( Cfg->Skeleton )
		{
			//auto Skeleton = Entity.Skeleton;
			uintptr_t FragInstNMGta = Mem.Read<uintptr_t>( ( uintptr_t ) Ped + g_Offsets.m_FragInst );
			uintptr_t v9 = Mem.Read<uintptr_t>( FragInstNMGta + 0x68 );

			if ( !v9 )
				continue;

			Core::SDK::Game::cSkeleton_t Skeleton;

			Skeleton.m_pSkeleton = Mem.Read<uintptr_t>( v9 + 0x178 );

			Skeleton.crSkeletonData.Ptr = Mem.Read<uintptr_t>( Skeleton.m_pSkeleton );
			Skeleton.crSkeletonData.m_Used = Mem.Read<unsigned int>( Skeleton.crSkeletonData.Ptr + 0x1A );
			Skeleton.crSkeletonData.m_NumBones = Mem.Read<unsigned int>( Skeleton.crSkeletonData.Ptr + 0x5E );
			Skeleton.crSkeletonData.m_BoneIdTable_Slots = Mem.Read<unsigned short>( Skeleton.crSkeletonData.Ptr + 0x18 );

			if ( !Skeleton.crSkeletonData.m_BoneIdTable_Slots )
				continue;

			Skeleton.crSkeletonData.m_BoneIdTable = Mem.Read<uintptr_t>( Skeleton.crSkeletonData.Ptr + 0x10 );

			Skeleton.Arg1 = Mem.Read<D3DXMATRIX>( Mem.Read<uintptr_t>( Skeleton.m_pSkeleton + 0x8 ) );
			Skeleton.Arg2 = Mem.Read<uintptr_t>( Skeleton.m_pSkeleton + 0x18 );


			D3DXVECTOR3 PelvisPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_Pelvis, Skeleton );
			D3DXVECTOR3 NeckPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_Neck_1, Skeleton );
			D3DXVECTOR3 LeftUperarmPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_L_UpperArm, Skeleton );
			D3DXVECTOR3 RightUperarmPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_R_UpperArm, Skeleton );
			D3DXVECTOR3 RightFormArmPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_R_Forearm, Skeleton );
			D3DXVECTOR3 LeftFormArmPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_L_Forearm, Skeleton );
			D3DXVECTOR3 RightHandPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_R_Hand, Skeleton );
			D3DXVECTOR3 LeftHandPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_L_Hand, Skeleton );
			D3DXVECTOR3 LeftThighPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_L_Thigh, Skeleton );
			D3DXVECTOR3 LeftCalfPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_L_Calf, Skeleton );
			D3DXVECTOR3 RightThighPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_R_Thigh, Skeleton );
			D3DXVECTOR3 RightCalfPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_R_Calf, Skeleton );
			D3DXVECTOR3 LfootPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_L_Foot, Skeleton );
			D3DXVECTOR3 RfootPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_R_Foot, Skeleton );

			D3DXVECTOR2 Pelvis = Core::SDK::Game::WorldToScreen( PelvisPos );
			D3DXVECTOR2 Neck = Core::SDK::Game::WorldToScreen( NeckPos );
			D3DXVECTOR2 LeftUperarm = Core::SDK::Game::WorldToScreen( LeftUperarmPos );
			D3DXVECTOR2 RightUperarm = Core::SDK::Game::WorldToScreen( RightUperarmPos );
			D3DXVECTOR2 RightFormArm = Core::SDK::Game::WorldToScreen( RightFormArmPos );
			D3DXVECTOR2 LeftFormArm = Core::SDK::Game::WorldToScreen( LeftFormArmPos );
			D3DXVECTOR2 RightHand = Core::SDK::Game::WorldToScreen( RightHandPos );
			D3DXVECTOR2 LeftHand = Core::SDK::Game::WorldToScreen( LeftHandPos );
			D3DXVECTOR2 LeftThigh = Core::SDK::Game::WorldToScreen( LeftThighPos );
			D3DXVECTOR2 LeftCalf = Core::SDK::Game::WorldToScreen( LeftCalfPos );
			D3DXVECTOR2 RightThigh = Core::SDK::Game::WorldToScreen( RightThighPos );
			D3DXVECTOR2 RightCalf = Core::SDK::Game::WorldToScreen( RightCalfPos );
			D3DXVECTOR2 Lfoot = Core::SDK::Game::WorldToScreen( LfootPos );
			D3DXVECTOR2 Rfoot = Core::SDK::Game::WorldToScreen( RfootPos );


			if ( !Core::SDK::Game::IsOnScreen( Lfoot ) || !Core::SDK::Game::IsOnScreen( Rfoot ) || !Core::SDK::Game::IsOnScreen( Pelvis ) || !Core::SDK::Game::IsOnScreen( Neck ) || !Core::SDK::Game::IsOnScreen( LeftUperarm ) || !Core::SDK::Game::IsOnScreen( RightUperarm ) || !Core::SDK::Game::IsOnScreen( RightFormArm ) || !Core::SDK::Game::IsOnScreen( LeftFormArm ) || !Core::SDK::Game::IsOnScreen( RightHand ) || !Core::SDK::Game::IsOnScreen( LeftHand ) || !Core::SDK::Game::IsOnScreen( LeftThigh ) || !Core::SDK::Game::IsOnScreen( RightThigh ) || !Core::SDK::Game::IsOnScreen( RightCalf ) )
				continue;

			ImColor drawSkelCol = IsFriend ? Cfg->FriendCol : Cfg->SkeletonCol;

			auto ScreenHead = Core::SDK::Game::WorldToScreen( HeadPos );
			//DrawList->AddLine( ImVec2( ScreenHead.x, ScreenHead.y ), ImVec2( Neck.x, Neck.y ), ImColor( 0, 0, 0 ), 2.5 );
			DrawList->AddLine( ImVec2( ScreenHead.x, ScreenHead.y ), ImVec2( Neck.x, Neck.y ), drawSkelCol, 1.5 );

			//DrawList->AddLine( ImVec2( LeftUperarm.x, LeftUperarm.y ), ImVec2( RightUperarm.x, RightUperarm.y ), ImColor( 0, 0, 0 ), 2.5 );
			DrawList->AddLine( ImVec2( LeftUperarm.x, LeftUperarm.y ), ImVec2( RightUperarm.x, RightUperarm.y ), drawSkelCol, 1.5 );

			//DrawList->AddLine( ImVec2( RightUperarm.x, RightUperarm.y ), ImVec2( RightFormArm.x, RightFormArm.y ), ImColor( 0, 0, 0 ), 2.5 );
			DrawList->AddLine( ImVec2( RightUperarm.x, RightUperarm.y ), ImVec2( RightFormArm.x, RightFormArm.y ), drawSkelCol, 1.5 );

			//DrawList->AddLine( ImVec2( LeftUperarm.x, LeftUperarm.y ), ImVec2( LeftFormArm.x, LeftFormArm.y ), ImColor( 0, 0, 0 ), 2.5 );
			DrawList->AddLine( ImVec2( LeftUperarm.x, LeftUperarm.y ), ImVec2( LeftFormArm.x, LeftFormArm.y ), drawSkelCol, 1.5 );

			//DrawList->AddLine( ImVec2( RightFormArm.x, RightFormArm.y ), ImVec2( RightHand.x, RightHand.y ), ImColor( 0, 0, 0 ), 2.5 );
			DrawList->AddLine( ImVec2( RightFormArm.x, RightFormArm.y ), ImVec2( RightHand.x, RightHand.y ), drawSkelCol, 1.5 );

			//DrawList->AddLine( ImVec2( LeftFormArm.x, LeftFormArm.y ), ImVec2( LeftHand.x, LeftHand.y ), ImColor( 0, 0, 0 ), 2.5 );
			DrawList->AddLine( ImVec2( LeftFormArm.x, LeftFormArm.y ), ImVec2( LeftHand.x, LeftHand.y ), drawSkelCol, 1.5 );

			//DrawList->AddLine( ImVec2( Neck.x, Neck.y ), ImVec2( Pelvis.x, Pelvis.y ), ImColor( 0, 0, 0 ), 2.5 );
			DrawList->AddLine( ImVec2( Neck.x, Neck.y ), ImVec2( Pelvis.x, Pelvis.y ), drawSkelCol, 1.5 );

			//DrawList->AddLine( ImVec2( Pelvis.x, Pelvis.y ), ImVec2( LeftThigh.x, LeftThigh.y ), ImColor( 0, 0, 0 ), 2.5 );
			DrawList->AddLine( ImVec2( Pelvis.x, Pelvis.y ), ImVec2( LeftThigh.x, LeftThigh.y ), drawSkelCol, 1.5 );

			//DrawList->AddLine( ImVec2( Pelvis.x, Pelvis.y ), ImVec2( RightThigh.x, RightThigh.y ), ImColor( 0, 0, 0 ), 2.5 );
			DrawList->AddLine( ImVec2( Pelvis.x, Pelvis.y ), ImVec2( RightThigh.x, RightThigh.y ), drawSkelCol, 1.5 );

			//DrawList->AddLine( ImVec2( LeftThigh.x, LeftThigh.y ), ImVec2( LeftCalf.x, LeftCalf.y ), ImColor( 0, 0, 0 ), 2.5 );
			DrawList->AddLine( ImVec2( LeftThigh.x, LeftThigh.y ), ImVec2( LeftCalf.x, LeftCalf.y ), drawSkelCol, 1.5 );

			//DrawList->AddLine( ImVec2( RightThigh.x, RightThigh.y ), ImVec2( RightCalf.x, RightCalf.y ), ImColor( 0, 0, 0 ), 2.5 );
			DrawList->AddLine( ImVec2( RightThigh.x, RightThigh.y ), ImVec2( RightCalf.x, RightCalf.y ), drawSkelCol, 1.5 );

			//DrawList->AddLine( ImVec2( LeftCalf.x, LeftCalf.y ), ImVec2( Lfoot.x, Lfoot.y ), ImColor( 0, 0, 0 ), 2.5 );
			DrawList->AddLine( ImVec2( LeftCalf.x, LeftCalf.y ), ImVec2( Lfoot.x, Lfoot.y ), drawSkelCol, 1.5 );

			//DrawList->AddLine( ImVec2( RightCalf.x, RightCalf.y ), ImVec2( Rfoot.x, Rfoot.y ), ImColor( 0, 0, 0 ), 2.5 );
			DrawList->AddLine( ImVec2( RightCalf.x, RightCalf.y ), ImVec2( Rfoot.x, Rfoot.y ), drawSkelCol, 1.5 );

		}

		if ( Cfg->HeadCircle )
		{
			if ( HeadPos != D3DXVECTOR3( 0, 0, 0 ) ) {
				D3DXVECTOR2 head_screen_pos = SDK::Game::WorldToScreen( HeadPos );
				if ( head_screen_pos != D3DXVECTOR2( 0, 0 ) ) {

					int CircleValue = Height / 15;
					if ( CircleValue <= 10 ) { Height / 20; }

					ImVec2 center( head_screen_pos.x, head_screen_pos.y );
					DrawList->AddCircle( center, CircleValue, Cfg->SkeletonCol, 999, 1.5 );
				}
			}
		}

		if ( Cfg->DistanceFromMe )
		{

			std::string DistStr = std::to_string( ( int ) Distance ) + xorstr( "m" );

			ImVec2 TextSize = g_Variables.m_DrawFont->CalcTextSizeA( g_Variables.m_DrawFont->FontSize, FLT_MAX, 0.0f, DistStr.c_str( ) );
			ImVec2 TextPos = ImVec2( BoxCenter.x - ( TextSize.x / 2 ), FirstTextBoxBottom );

			switch ( Cfg->DistanceFromMeState )
			{

			case 0: //Top

				if ( Cfg->UserNames && Cfg->UserNamesState == 0 )
				{
					TextPos.y = FirstTextBoxTop - 15;
				}

				if ( Cfg->WeaponName && Cfg->WeaponNameState == 0 )
				{
					TextPos.y = FirstTextBoxTop - 15;
				}

				if ( Cfg->WeaponName && Cfg->WeaponNameState == 0 && Cfg->UserNames && Cfg->UserNamesState == 0 )
				{
					TextPos.y = FirstTextBoxTop - 30;
				}

				if ( Cfg->WeaponNameState == 2 && Cfg->UserNamesState == 2 )
				{
					TextPos.y = FirstTextBoxTop;
				}


				if ( !Cfg->UserNames && !Cfg->WeaponName )
				{
					TextPos.y = FirstTextBoxTop;
				}

				break;
			case 2: //Bottom
				if ( Cfg->UserNames && Cfg->UserNamesState == 2 )
				{
					TextPos.y = FirstTextBoxBottom + 15;
				}

				if ( Cfg->WeaponName && Cfg->WeaponNameState == 2 )
				{
					TextPos.y = FirstTextBoxBottom + 15;
				}

				if ( Cfg->WeaponName && Cfg->WeaponNameState == 2 && Cfg->UserNames && Cfg->UserNamesState == 2 )
				{
					TextPos.y = FirstTextBoxBottom + 30;
				}

				if ( !Cfg->UserNames && !Cfg->WeaponName )
				{
					TextPos.y = FirstTextBoxBottom;
				}

				break;
			default:
				TextPos.y = FirstTextBoxBottom;
				break;
			}

			/*DrawList->AddText( g_Variables.m_DrawFont, g_Variables.m_DrawFont->FontSize, ImVec2( TextPos.x + 1, TextPos.y + 1 ), ImColor( 0, 0, 0, 100 ), DistStr.c_str( ) );
			DrawList->AddText( g_Variables.m_DrawFont, g_Variables.m_DrawFont->FontSize, ImVec2( TextPos.x - 1, TextPos.y + 1 ), ImColor( 0, 0, 0, 100 ), DistStr.c_str( ) );
			DrawList->AddText( g_Variables.m_DrawFont, g_Variables.m_DrawFont->FontSize, ImVec2( TextPos.x + 1, TextPos.y - 1 ), ImColor( 0, 0, 0, 100 ), DistStr.c_str( ) );
			DrawList->AddText( g_Variables.m_DrawFont, g_Variables.m_DrawFont->FontSize, ImVec2( TextPos.x - 1, TextPos.y - 1 ), ImColor( 0, 0, 0, 100 ), DistStr.c_str( ) );*/

			DrawList->AddText( g_Variables.m_DrawFont, g_Variables.m_DrawFont->FontSize, ImVec2( TextPos.x + 1, TextPos.y + 1 ), ImColor( 0.f, 0.f, 0.f, Cfg->DistanceCol.Value.w ), DistStr.c_str( ) );
			DrawList->AddText( g_Variables.m_DrawFont, g_Variables.m_DrawFont->FontSize, TextPos, Cfg->DistanceCol, DistStr.c_str( ) );

		}

		if ( Cfg->WeaponName ) {

			std::string weaponName = Entity.WeaponName;

			auto to_lower = [ ] ( const char * str ) {
				std::string message = str;
				if ( !message.empty( ) ) {
					std::transform( message.begin( ), message.end( ), message.begin( ), ::tolower );
					message[ 0 ] = std::toupper( message[ 0 ] );
				}
				return message;
				};

			if ( weaponName.empty( ) )
				weaponName = xorstr( "Unarmed" );

			ImVec2 TextSize = g_Variables.m_DrawFont->CalcTextSizeA( g_Variables.m_DrawFont->FontSize, FLT_MAX, 0.0f, to_lower( weaponName.c_str( ) ).c_str( ) );
			ImVec2 TextPos = ImVec2( BoxCenter.x - ( TextSize.x / 2 ), FirstTextBoxBottom );

			if ( Cfg->DistanceFromMe )
				TextPos.y = FirstTextBoxBottom;

			if ( Cfg->UserNamesState == 1 )
				TextPos.y = SecondTextBoxBottom;

			switch ( Cfg->WeaponNameState )
			{

			case 0: //Top
				if ( Cfg->UserNamesState == 0 && Cfg->UserNames )
				{
					TextPos.y = FirstTextBoxTop - 15;
				}
				else
				{
					TextPos.y = FirstTextBoxTop;
				}

				break;
			case 2: //Bottom
				if ( Cfg->UserNamesState == 2 && Cfg->UserNames )
				{
					TextPos.y = FirstTextBoxBottom + 15;
				}
				else
				{
					TextPos.y = FirstTextBoxBottom;
				}
				break;
			default:
				TextPos.y = FirstTextBoxBottom;
				break;
			}

			std::string WeaponNameUnder = to_lower( weaponName.c_str( ) );

			/*DrawList->AddText( g_Variables.m_DrawFont, g_Variables.m_DrawFont->FontSize, ImVec2( TextPos.x + 1, TextPos.y + 1 ), ImColor( 0, 0, 0, 100 ), WeaponNameUnder.c_str( ) );
			DrawList->AddText( g_Variables.m_DrawFont, g_Variables.m_DrawFont->FontSize, ImVec2( TextPos.x - 1, TextPos.y + 1 ), ImColor( 0, 0, 0, 100 ), WeaponNameUnder.c_str( ) );
			DrawList->AddText( g_Variables.m_DrawFont, g_Variables.m_DrawFont->FontSize, ImVec2( TextPos.x + 1, TextPos.y - 1 ), ImColor( 0, 0, 0, 100 ), WeaponNameUnder.c_str( ) );
			DrawList->AddText( g_Variables.m_DrawFont, g_Variables.m_DrawFont->FontSize, ImVec2( TextPos.x - 1, TextPos.y - 1 ), ImColor( 0, 0, 0, 100 ), WeaponNameUnder.c_str( ) );*/

			DrawList->AddText( g_Variables.m_DrawFont, g_Variables.m_DrawFont->FontSize, ImVec2( TextPos.x + 1, TextPos.y + 1 ), ImColor( 0.f, 0.f, 0.f, Cfg->WeaponNameCol.Value.w ), to_lower( weaponName.c_str( ) ).c_str( ) );
			DrawList->AddText( g_Variables.m_DrawFont, g_Variables.m_DrawFont->FontSize, TextPos, Cfg->WeaponNameCol, WeaponNameUnder.c_str( ) );
		}

		if ( Cfg->UserNames )
		{

			std::string PlayerName = Entity.NetworkInfo.UserName;

			ImVec2 TextSize = g_Variables.m_DrawFont->CalcTextSizeA( g_Variables.m_DrawFont->FontSize, FLT_MAX, 0.0f, PlayerName.c_str( ) );
			ImVec2 TextPos = ImVec2( BoxCenter.x - ( TextSize.x / 2 ), FirstTextBoxTop );

			switch ( Cfg->UserNamesState )
			{

			case 0: //Top
				TextPos.y = FirstTextBoxTop;
				break;
			case 2: //Bottom
				TextPos.y = FirstTextBoxBottom;
				break;
			default:
				TextPos.y = FirstTextBoxTop;
				break;
			}

			/*DrawList->AddText( g_Variables.m_DrawFont, g_Variables.m_DrawFont->FontSize, ImVec2( TextPos.x + 1, TextPos.y + 1 ), ImColor( 0, 0, 0, 100 ), PlayerName.c_str( ) );
			DrawList->AddText( g_Variables.m_DrawFont, g_Variables.m_DrawFont->FontSize, ImVec2( TextPos.x - 1, TextPos.y + 1 ), ImColor( 0, 0, 0, 100 ), PlayerName.c_str( ) );
			DrawList->AddText( g_Variables.m_DrawFont, g_Variables.m_DrawFont->FontSize, ImVec2( TextPos.x + 1, TextPos.y - 1 ), ImColor( 0, 0, 0, 100 ), PlayerName.c_str( ) );
			DrawList->AddText( g_Variables.m_DrawFont, g_Variables.m_DrawFont->FontSize, ImVec2( TextPos.x - 1, TextPos.y - 1 ), ImColor( 0, 0, 0, 100 ), PlayerName.c_str( ) );*/

			DrawList->AddText( ImVec2( TextPos.x + 1, TextPos.y + 1 ), ImColor( 0.f, 0.f, 0.f, Cfg->UserNamesCol.Value.w ), PlayerName.c_str( ) );
			DrawList->AddText( TextPos, Cfg->UserNamesCol, PlayerName.c_str( ) );
		}

		const auto DrawHealthBarV = [ &DrawList ] ( ImVec2 pos, ImVec2 dim, ImColor col, int background ) {
			if ( background == 1 ) { //Bar
				DrawList->AddRectFilled( ImVec2( pos.x, pos.y ), ImVec2( pos.x + dim.x, pos.y - ( dim.y + 1 ) ), col );
			}
			else { //BackGround
				DrawList->AddRectFilled( ImVec2( pos.x - 1, pos.y + 1 ), ImVec2( pos.x + dim.x + 1, pos.y - ( dim.y + 2 ) ), ImColor( 0, 0, 0, 255 ) );
				DrawList->AddRectFilled( ImVec2( pos.x, pos.y - 1 ), ImVec2( pos.x + dim.x, pos.y - ( dim.y + 2 ) ), ImColor( 80, 80, 80, 125 ) );
			}
			};
		const auto DrawHealthBarH = [ &DrawList ] ( ImVec2 pos, ImVec2 dim, ImColor col, int background ) {
			if ( background == 1 ) { //Bar
				DrawList->AddRectFilled( ImVec2( pos.x, pos.y ), ImVec2( pos.x + dim.y, pos.y + dim.x ), col );
			}
			else { //BackGround
				DrawList->AddRectFilled( ImVec2( pos.x - 1, pos.y - 1 ), ImVec2( pos.x + dim.y + 1, pos.y + dim.x + 1 ), ImColor( 0, 0, 0, 255 ) );
				DrawList->AddRectFilled( ImVec2( pos.x, pos.y ), ImVec2( pos.x + dim.y, pos.y + dim.x ), ImColor( 80, 80, 80, 125 ) );
			}
			};

		if ( Cfg->HealthBar )
		{
			float MaxHealth = Entity.MaxHealth;

			CurrentESPAnim.Health = ImLerp( CurrentESPAnim.Health, Health, ImGui::GetIO( ).DeltaTime * 4 );
			float AnimHealth = CurrentESPAnim.Health;

			float FullHealthBar = Height / 100 * 100;
			float DecreaseHealthBar = FullHealthBar * ( AnimHealth / MaxHealth );

			float Width2 = BoxRight - BoxLeft;
			float FullHealthBarH = Width2 / 100 * 100;
			float DecreaseHealthBarH = FullHealthBarH * ( AnimHealth / MaxHealth );

			if ( DecreaseHealthBarH > FullHealthBarH )
			{
				DecreaseHealthBarH = FullHealthBarH;
			}

			if ( DecreaseHealthBar > FullHealthBar )
			{
				DecreaseHealthBar = FullHealthBar;
			}

			ImColor BarColor;
			ImColor FullHealth =( ImVec4( ImColor( 80, 80, 80, 200 ) ) );

			if ( Health > ( MaxHealth / 2 ) )
			{
				BarColor =( ImVec4( ImColor( 66, 245, 132, 255 ) ) );
			}
			else if ( Health <= ( MaxHealth / 2 ) && MaxHealth == 200 ? Health > 50 : Health > 150 )
			{
				BarColor =( ImVec4( ImColor( 245, 135, 66, 255 ) ) );
			}
			else
			{
				BarColor =( ImVec4( ImColor( 245, 66, 66, 255 ) ) );
			}

			switch ( Cfg->HealthBarState )
			{
			case 0: //Top
				DrawHealthBarH( ImVec2( BoxMin.x, BoxMin.y - 4 ), ImVec2( 2, FullHealthBarH ),( ImVec4( FullHealth ) ), 0 );
				DrawHealthBarH( ImVec2( BoxMin.x, BoxMin.y - 4 ), ImVec2( 2, DecreaseHealthBarH ),( ImVec4( BarColor ) ), 1 );
				break;
			case 1: //Right
				DrawHealthBarV( ImVec2( BoxMax.x + 6, BoxMax.y ), ImVec2( 2, FullHealthBar ),( ImVec4( FullHealth ) ), 0 );
				DrawHealthBarV( ImVec2( BoxMax.x + 6, BoxMax.y ), ImVec2( 2, DecreaseHealthBar ),( ImVec4( BarColor ) ), 1 );
				break;
			case 2: //Bottom
				DrawHealthBarH( ImVec2( BoxMin.x, BoxMax.y + 6 ), ImVec2( 2, FullHealthBarH ),( ImVec4( FullHealth ) ), 0 );
				DrawHealthBarH( ImVec2( BoxMin.x, BoxMax.y + 6 ), ImVec2( 2, DecreaseHealthBarH ),( ImVec4( BarColor ) ), 1 );
				break;
			case 3: //Left
				DrawHealthBarV( ImVec2( BoxMin.x - 6, BoxMax.y ), ImVec2( 2, FullHealthBar ),( ImVec4( FullHealth ) ), 0 );
				DrawHealthBarV( ImVec2( BoxMin.x - 6, BoxMax.y ), ImVec2( 2, DecreaseHealthBar ),( ImVec4( BarColor ) ), 1 );
				break;

			default:
				DrawHealthBarV( ImVec2( BoxMin.x - 6, BoxMax.y ), ImVec2( 2, FullHealthBar ),( ImVec4( FullHealth ) ), 0 );
				DrawHealthBarV( ImVec2( BoxMin.x - 6, BoxMax.y ), ImVec2( 2, DecreaseHealthBar ),( ImVec4( BarColor ) ), 1 );
				break;
			}
		}

		if ( Cfg->ArmorBar )
		{
			float MaxHealth = Entity.MaxHealth;
			float Armor = Entity.Armor;

			if ( Armor > 0 )
			{
				MaxHealth = MaxHealth / 2;

				CurrentESPAnim.Armor = ImLerp( CurrentESPAnim.Armor, Armor, ImGui::GetIO( ).DeltaTime * 4 );
				float AnimArmor = CurrentESPAnim.Armor;

				float FullArmorBar = Height / 100 * 100;
				float DecreaseHealthBar = FullArmorBar * ( AnimArmor / MaxHealth );

				float Width2 = BoxRight - BoxLeft;
				float FullArmorBarH = Width2 / 100 * 100;
				float DecreaseArmorBarH = FullArmorBarH * ( AnimArmor / MaxHealth );


				if ( DecreaseHealthBar > FullArmorBar )
				{
					DecreaseHealthBar = FullArmorBar;
				}

				if ( DecreaseArmorBarH > FullArmorBarH )
				{
					DecreaseArmorBarH = FullArmorBarH;
				}

				ImColor BarColor;
				ImColor FullArmor = ImVec4( ImColor( 80, 80, 80, 200 ) );

				if ( Armor > ( MaxHealth / 2 ) ) {
					BarColor = ImVec4( ImColor( 85, 128, 200, 255 ) );
				}
				else if ( Armor <= ( MaxHealth / 2 ) && MaxHealth == 200 ? Armor > 50 : Armor > 150 ) {
					BarColor = ImVec4( ImColor( 69, 102, 157, 255 ) );
				}
				else {
					BarColor = ImVec4( ImColor( 45, 62, 92, 255 ) );
				}

				switch ( Cfg->ArmorBarState )
				{

				case 0: //Top
					if ( Cfg->HealthBar && Cfg->HealthBarState == Cfg->ArmorBarState )
					{
						DrawHealthBarH( ImVec2( BoxMin.x, BoxMin.y - 8 ), ImVec2( 2, FullArmorBarH ), FullArmor, 0 );
						DrawHealthBarH( ImVec2( BoxMin.x, BoxMin.y - 8 ), ImVec2( 2, DecreaseArmorBarH ), BarColor, 1 );
					}
					else
					{
						DrawHealthBarH( ImVec2( BoxMin.x, BoxMin.y - 4 ), ImVec2( 2, FullArmorBarH ), FullArmor, 0 );
						DrawHealthBarH( ImVec2( BoxMin.x, BoxMin.y - 4 ), ImVec2( 2, DecreaseArmorBarH ), BarColor, 1 );
					}
					break;
				case 1: //Right
					if ( Cfg->HealthBar && Cfg->HealthBarState == Cfg->ArmorBarState )
					{
						DrawHealthBarV( ImVec2( BoxMax.x + 12, BoxMax.y ), ImVec2( 2, FullArmorBar ), FullArmor, 0 );
						DrawHealthBarV( ImVec2( BoxMax.x + 12, BoxMax.y ), ImVec2( 2, DecreaseHealthBar ), BarColor, 1 );
					}
					else
					{
						DrawHealthBarV( ImVec2( BoxMax.x + 6, BoxMax.y ), ImVec2( 2, FullArmorBar ), FullArmor, 0 );
						DrawHealthBarV( ImVec2( BoxMax.x + 6, BoxMax.y ), ImVec2( 2, DecreaseHealthBar ), BarColor, 1 );
					}
					break;
				case 2: //Bottom
					if ( Cfg->HealthBar && Cfg->HealthBarState == Cfg->ArmorBarState )
					{
						DrawHealthBarH( ImVec2( BoxMin.x, BoxMax.y + 12 ), ImVec2( 2, FullArmorBarH ), FullArmor, 0 );
						DrawHealthBarH( ImVec2( BoxMin.x, BoxMax.y + 12 ), ImVec2( 2, DecreaseArmorBarH ), BarColor, 1 );
					}
					else
					{
						DrawHealthBarH( ImVec2( BoxMin.x, BoxMax.y + 6 ), ImVec2( 2, FullArmorBarH ), FullArmor, 0 );
						DrawHealthBarH( ImVec2( BoxMin.x, BoxMax.y + 6 ), ImVec2( 2, DecreaseArmorBarH ), BarColor, 1 );
					}
					break;
				case 3: //Left
					if ( Cfg->HealthBar && Cfg->HealthBarState == Cfg->ArmorBarState )
					{
						DrawHealthBarV( ImVec2( BoxMin.x - 12, BoxMax.y ), ImVec2( 2, FullArmorBar ), FullArmor, 0 );
						DrawHealthBarV( ImVec2( BoxMin.x - 12, BoxMax.y ), ImVec2( 2, DecreaseHealthBar ), BarColor, 1 );
					}
					else
					{
						DrawHealthBarV( ImVec2( BoxMin.x - 6, BoxMax.y ), ImVec2( 2, FullArmorBar ), FullArmor, 0 );
						DrawHealthBarV( ImVec2( BoxMin.x - 6, BoxMax.y ), ImVec2( 2, DecreaseHealthBar ), BarColor, 1 );
					}
					break;

				default:
					DrawHealthBarV( ImVec2( BoxMin.x - 6, BoxMax.y ), ImVec2( 2, FullArmorBar ), FullArmor, 0 );
					DrawHealthBarV( ImVec2( BoxMin.x - 6, BoxMax.y ), ImVec2( 2, DecreaseHealthBar ), BarColor, 1 );
					break;
				}

			}

		}
	}
}

void Core::Features::cEsp::DrawVehicle( )
{
	auto Cfg = g_Config.VehicleESP;

	if ( !Cfg->Enabled )
		return;

	

	for ( auto Entity : Core::SDK::Game::VehicleList )
	{
		CVehicle * Vehicle = Entity.Pointer;
		auto DrawList = ImGui::GetBackgroundDrawList( );

		float Distance = Entity.Dist;

		if ( Distance > Cfg->MaxDistance )
			continue;

		D3DXVECTOR2 VehicleLocation = Core::SDK::Game::WorldToScreen(
			Vehicle->GetPos( ) //Usei aqui pra n�o ter esse delay do esp por causa da thread
		);

		if ( !VehicleLocation )
			continue;

		if ( !SDK::Game::IsOnScreen( VehicleLocation ) )
			continue;

		if ( Cfg->SnapLines )
		{
			DrawList->AddLine( ImVec2( g_Variables.g_vGameWindowCenter.x, g_Variables.g_vGameWindowPos.y + g_Variables.g_vGameWindowSize.y ), ImVec2( VehicleLocation.x, VehicleLocation.y + 30 ), ImColor( 0, 0, 0 ), 2.5 );
			DrawList->AddLine( ImVec2( g_Variables.g_vGameWindowCenter.x, g_Variables.g_vGameWindowPos.y + g_Variables.g_vGameWindowSize.y ), ImVec2( VehicleLocation.x, VehicleLocation.y + 30 ), Cfg->SnapLinesCol, 1.5 );
		}

		if ( Cfg->VehName )
		{
			ImVec2 text_size = g_Variables.m_DrawFont->CalcTextSizeA( g_Variables.m_DrawFont->FontSize, FLT_MAX, 0.0f, Entity.Name.c_str( ) );

			DrawList->AddText( ImVec2( VehicleLocation.x - ( text_size.x / 2 ), VehicleLocation.y + 2 ), ImColor( 0, 0, 0 ), Entity.Name.c_str( ) );
			DrawList->AddText( ImVec2( VehicleLocation.x - ( text_size.x / 2 ), VehicleLocation.y ), ImColor( 255, 255, 255 ), Entity.Name.c_str( ) );
		}

		if ( Cfg->ShowLockUnlock ) {
			bool IsLocked = Entity.IsLocked;
			float radius = 2 / Distance;

			const static std::string VehicleLocked = xorstr( "Press L to Unlock" );
			const static std::string VehicleUnlocked = xorstr( "Press L to Lock" );
			const static int fovRadius = 40;
			const static int L = 0x4C;
			const static int Delay = 500;


			int FovSize = std::hypot( VehicleLocation.x - g_Variables.g_vGameWindowCenter.x, VehicleLocation.y - g_Variables.g_vGameWindowCenter.y );

			if ( IsLocked )
			{
				DrawList->AddCircleFilled( ImVec2( VehicleLocation.x, VehicleLocation.y - 6 ), radius + Distance < 1 ? 1 : 4, ImColor( 0, 0, 0 ), 999 );
				DrawList->AddCircleFilled( ImVec2( VehicleLocation.x, VehicleLocation.y - 6 ), radius + Distance < 1 ? 0 : 3, ImColor( 250, 72, 62, 255 ), 999 );

				if ( FovSize < fovRadius )
				{
					ImVec2 text_size = g_Variables.m_DrawFont->CalcTextSizeA( g_Variables.m_DrawFont->FontSize, FLT_MAX, 0.0f, VehicleLocked.c_str( ) );

					DrawList->AddText( ImVec2( VehicleLocation.x - ( text_size.x / 2 ), VehicleLocation.y - 28 ), ImColor( 0, 0, 0 ), VehicleLocked.c_str( ) );
					DrawList->AddText( ImVec2( VehicleLocation.x - ( text_size.x / 2 ), VehicleLocation.y - 30 ), ImColor( 255, 255, 255 ), VehicleLocked.c_str( ) );

					if ( Utils::KeyPressedWithDelay( L, Delay ) )
						Vehicle->DoorState( true );
				}



			}
			else if ( !IsLocked )
			{
				DrawList->AddCircleFilled( ImVec2( VehicleLocation.x, VehicleLocation.y - 6 ), radius + Distance < 1 ? 1 : 4, ImColor( 0, 0, 0 ), 999 );
				DrawList->AddCircleFilled( ImVec2( VehicleLocation.x, VehicleLocation.y - 6 ), radius + Distance < 1 ? 0 : 3, ImColor( 102, 255, 133, 255 ), 999 );

				if ( FovSize < fovRadius )
				{
					ImVec2 text_size = g_Variables.m_DrawFont->CalcTextSizeA( g_Variables.m_DrawFont->FontSize, FLT_MAX, 0.0f, VehicleUnlocked.c_str( ) );

					DrawList->AddText( ImVec2( VehicleLocation.x - ( text_size.x / 2 ), VehicleLocation.y - 28 ), ImColor( 0, 0, 0 ), VehicleUnlocked.c_str( ) );
					DrawList->AddText( ImVec2( VehicleLocation.x - ( text_size.x / 2 ), VehicleLocation.y - 30 ), ImColor( 255, 255, 255 ), VehicleUnlocked.c_str( ) );

					if ( Utils::KeyPressedWithDelay( L, Delay ) )
						Vehicle->DoorState( false );
				}
			}
		}

		if ( Cfg->DistanceFromMe )
		{
			std::string vehicleDistance = std::to_string( int( Distance ) ) + xorstr( "m" );
			ImVec2 text_size = g_Variables.m_DrawFont->CalcTextSizeA( g_Variables.m_DrawFont->FontSize, FLT_MAX, 0.0f, vehicleDistance.c_str( ) );

			DrawList->AddText( ImVec2( VehicleLocation.x - ( text_size.x / 2 ), VehicleLocation.y + 16 ), ImColor( 0, 0, 0 ), vehicleDistance.c_str( ) );
			DrawList->AddText( ImVec2( VehicleLocation.x - ( text_size.x / 2 ), VehicleLocation.y + 14 ), ImColor( 255, 255, 255 ), vehicleDistance.c_str( ) );
		}

	}
}








void Core::Features::cEsp::DrawAdminWarning()
{
	auto Cfg = g_Config.ESP;
	if ( !Cfg->AdminList ) return;

	// â”€â”€ Skeleton & Lines: ALWAYS a cycling RGB (independent of theme) â”€â”€
	float hue = fmodf( ImGui::GetTime() * 0.6f, 1.0f );
	ImVec4 rgb;
	ImGui::ColorConvertHSVtoRGB( hue, 1.0f, 1.0f, rgb.x, rgb.y, rgb.z );
	rgb.w = 1.0f;
	ImColor rgbCol = ImColor( rgb );

	// â”€â”€ Panel border & dot: follow the active theme's primary color â”€â”€
	ImVec4 themeCol = activeTheme.primary;
	ImColor themeImCol = ImColor( themeCol );

	struct AdminEntry { std::string Name; float Dist; };
	std::vector<AdminEntry> admins;

	auto DrawList = ImGui::GetBackgroundDrawList();

	for ( auto& Entity : Core::SDK::Game::EntityList )
	{
		CPed* Ped = Entity.Ped;
		if ( !Ped ) continue;
		if ( Entity.PedType != 2 && Ped != Core::SDK::Pointers::pLocalPlayer ) continue;
		if ( Entity.Distance > (float)Cfg->AdminDistance ) continue;

		D3DXVECTOR2 screenPos = Core::SDK::Game::WorldToScreen(Entity.Pos);
		bool IsOnScreen = (screenPos.x != 0 || screenPos.y != 0);
		bool IsInvisible = (Mem.Read<BYTE>((uintptr_t)Ped + 0x2C) & 0x01) == 0;
		if (!IsInvisible || !IsOnScreen) continue;

		std::string name = Entity.NetworkInfo.UserName.empty() ? "?" : Entity.NetworkInfo.UserName;
		admins.push_back({ name, Entity.Distance });

		// â”€â”€ Full complex skeleton â”€ ALWAYS RGB â”€â”€
		if ( Cfg->AdminSkeleton )
		{
			uintptr_t FragInstNMGta = Mem.Read<uintptr_t>( ( uintptr_t ) Ped + g_Offsets.m_FragInst );
			uintptr_t v9 = Mem.Read<uintptr_t>( FragInstNMGta + 0x68 );
			if ( v9 )
			{
				Core::SDK::Game::cSkeleton_t Skeleton;
				Skeleton.m_pSkeleton = Mem.Read<uintptr_t>( v9 + 0x178 );
				Skeleton.crSkeletonData.Ptr = Mem.Read<uintptr_t>( Skeleton.m_pSkeleton );
				Skeleton.crSkeletonData.m_Used = Mem.Read<unsigned int>( Skeleton.crSkeletonData.Ptr + 0x1A );
				Skeleton.crSkeletonData.m_NumBones = Mem.Read<unsigned int>( Skeleton.crSkeletonData.Ptr + 0x5E );
				Skeleton.crSkeletonData.m_BoneIdTable_Slots = Mem.Read<unsigned short>( Skeleton.crSkeletonData.Ptr + 0x18 );
				if ( Skeleton.crSkeletonData.m_BoneIdTable_Slots )
				{
					Skeleton.crSkeletonData.m_BoneIdTable = Mem.Read<uintptr_t>( Skeleton.crSkeletonData.Ptr + 0x10 );
					Skeleton.Arg1 = Mem.Read<D3DXMATRIX>( Mem.Read<uintptr_t>( Skeleton.m_pSkeleton + 0x8 ) );
					Skeleton.Arg2 = Mem.Read<uintptr_t>( Skeleton.m_pSkeleton + 0x18 );

					auto B = [&]( int id ) { return Core::SDK::Game::WorldToScreen( Core::SDK::Game::GetBonePosComplex( Ped, id, Skeleton ) ); };
					auto L = [&]( D3DXVECTOR2 a, D3DXVECTOR2 b ) {
						if ( Core::SDK::Game::IsOnScreen( a ) && Core::SDK::Game::IsOnScreen( b ) )
							DrawList->AddLine( ImVec2( a.x, a.y ), ImVec2( b.x, b.y ), rgbCol, 2.0f ); // << RGB
					};

					D3DXVECTOR2 Head   = Core::SDK::Game::WorldToScreen( Ped->GetBonePosDefault( 0 ) );
					D3DXVECTOR2 Neck   = B( SKEL_Neck_1 );
					D3DXVECTOR2 Pelvis = B( SKEL_Pelvis );
					D3DXVECTOR2 LUp    = B( SKEL_L_UpperArm );
					D3DXVECTOR2 RUp    = B( SKEL_R_UpperArm );
					D3DXVECTOR2 LFore  = B( SKEL_L_Forearm );
					D3DXVECTOR2 RFore  = B( SKEL_R_Forearm );
					D3DXVECTOR2 LHand  = B( SKEL_L_Hand );
					D3DXVECTOR2 RHand  = B( SKEL_R_Hand );
					D3DXVECTOR2 LThigh = B( SKEL_L_Thigh );
					D3DXVECTOR2 RThigh = B( SKEL_R_Thigh );
					D3DXVECTOR2 LCalf  = B( SKEL_L_Calf );
					D3DXVECTOR2 RCalf  = B( SKEL_R_Calf );
					D3DXVECTOR2 LFoot  = B( SKEL_L_Foot );
					D3DXVECTOR2 RFoot  = B( SKEL_R_Foot );

					L( Head, Neck ); L( Neck, Pelvis );
					L( Neck, LUp ); L( LUp, LFore ); L( LFore, LHand );
					L( Neck, RUp ); L( RUp, RFore ); L( RFore, RHand );
					L( Pelvis, LThigh ); L( LThigh, LCalf ); L( LCalf, LFoot );
					L( Pelvis, RThigh ); L( RThigh, RCalf ); L( RCalf, RFoot );
				}
			}
		}

		// â”€â”€ Snapline â”€ ALWAYS RGB â”€â”€
		if ( Cfg->AdminLines )
		{
			D3DXVECTOR3 HeadPos = Ped->GetBonePosDefault( 0 );
			D3DXVECTOR3 TargetPos = (HeadPos.x == 0.f && HeadPos.y == 0.f && HeadPos.z == 0.f) ? (Entity.Pos + D3DXVECTOR3(0, 0, 0.8f)) : HeadPos;
			D3DXVECTOR2 PedScr = Core::SDK::Game::WorldToScreen( TargetPos );
			
			ImVec2 screenBottom = ImVec2( g_Variables.g_vGameWindowCenter.x,
			                              g_Variables.g_vGameWindowPos.y + g_Variables.g_vGameWindowSize.y );
			if ( Core::SDK::Game::IsOnScreen( PedScr ) )
				DrawList->AddLine( screenBottom, ImVec2( PedScr.x, PedScr.y ), rgbCol, 1.5f ); // << RGB
		}
	}
	// if ( admins.empty() ) return;

	// â”€â”€ Overlay panel â”€ uses THEME color â”€â”€
	ImGuiWindowFlags panelFlags =
		ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_AlwaysAutoResize |
		ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoBringToFrontOnFocus;

	ImGui::PushStyleColor( ImGuiCol_WindowBg, ImVec4( 0.05f, 0.05f, 0.07f, 0.88f ) );
	ImGui::PushStyleColor( ImGuiCol_Border,   ImVec4( themeCol.x, themeCol.y, themeCol.z, 0.75f ) );
	ImGui::PushStyleColor( ImGuiCol_ChildBg,  ImVec4( 0, 0, 0, 0 ) );
	ImGui::PushStyleVar( ImGuiStyleVar_WindowPadding,    ImVec2( 8.f, 6.f ) );
	ImGui::PushStyleVar( ImGuiStyleVar_ItemSpacing,      ImVec2( 6.f, 4.f ) );
	ImGui::PushStyleVar( ImGuiStyleVar_WindowRounding,   8.f );
	ImGui::PushStyleVar( ImGuiStyleVar_WindowBorderSize, 1.5f );

	ImGui::SetNextWindowPos( ImVec2( 10.f, 10.f ), ImGuiCond_Always );

	if ( ImGui::Begin( "##AdminWarning", nullptr, panelFlags ) )
	{
		float lineH = ImGui::GetTextLineHeight();

		// âš¡ Icon in theme color â€” push draw font which has FA glyphs
		ImGui::PushFont( g_Variables.m_DrawFont );
		ImVec2 iconPos = ImGui::GetCursorScreenPos();
		ImGui::GetWindowDrawList()->AddText( iconPos, themeImCol, ICON_FA_BOLT );
		ImVec2 iconSz = ImGui::CalcTextSize( ICON_FA_BOLT );
		ImGui::Dummy( ImVec2( iconSz.x, lineH ) );
		ImGui::PopFont();
		ImGui::SameLine( 0, 6 );

		// Title
		ImGui::TextColored( ImVec4( 0.9f, 0.9f, 0.9f, 1.0f ), "Administrators" );

		// Separator in theme color
		ImVec2 sepMin = ImGui::GetCursorScreenPos();
		ImVec2 sepMax = ImVec2( sepMin.x + ImGui::GetContentRegionAvail().x, sepMin.y + 1.0f );
		ImGui::GetWindowDrawList()->AddRectFilled( sepMin, sepMax, themeImCol );
		ImGui::Dummy( ImVec2( 0, 3.f ) );

		for ( auto& a : admins )
		{
			// Small dot in theme color
			ImVec2 dotPos = ImGui::GetCursorScreenPos();
			dotPos.x += 2.f; dotPos.y += lineH * 0.5f - 3.f;
			ImGui::GetWindowDrawList()->AddCircleFilled( dotPos, 3.5f, themeImCol );
			ImGui::SetCursorPosX( ImGui::GetCursorPosX() + 12.f );
			char buf[128];
			snprintf( buf, sizeof(buf), "%-16s  %3.0fm", a.Name.c_str(), a.Dist );
			ImGui::TextColored( ImVec4( 0.95f, 0.95f, 0.95f, 1.0f ), "%s", buf );
		}
	}
	ImGui::End();
	ImGui::PopStyleVar( 4 );
	ImGui::PopStyleColor( 3 );
}


