#pragma once
#include <Includes/Includes.hpp>

namespace Custom
{
	class EspPreview {
	public:
		void DragDropHandler( )
		{
			Position Positions[ ] =
			{
				{ImVec2( iBox_X, iBox_Y - 3.5f )}, // Top
				{ImVec2( iBox_X + iBox_Width + 3.5f, iBox_Y )}, // Right
				{ImVec2( iBox_X, iBox_Y + iBox_Height + 3.5f )}, // Bottom
				{ImVec2( iBox_X - 3.5f, iBox_Y )}, // Left
			};

			for ( size_t i = 0; i < mWidgets.size( ); i++ )
			{
				auto & Widget = mWidgets.at( i );

				if ( !Widget.Initialized )
					continue;

				if ( Widget.AlphaAnimation == 0 )
					continue;

				ImGui::PushID( i );
				{
					ImGui::SetCursorScreenPos( Widget.Position );
					ImGui::InvisibleButton( ( xorstr( "Drag&Drop##" ) + Widget.Text ).c_str( ), Widget.Size + ImVec2( 10, 10 ) );
					bool Hovered = ImGui::IsItemHovered( );
					int Pos = FindClosestPosition( ImGui::GetMousePos( ), Positions, Widget.Type );
					Widget.Helding = false;
					if ( ImGui::BeginDragDropSource( ImGuiDragDropFlags_SourceNoPreviewTooltip ) )
					{
						ImGui::SetDragDropPayload( xorstr( "Drag&Drop" ), &i, sizeof( int ), 0 );
						Widget.Pos = 4;
						Widget.PossiblePos = Pos;
						Widget.Helding = true;
						ImGui::EndDragDropSource( );
					}
					else if ( Widget.Pos == 4 )
					{
						Widget.Pos = Widget.PossiblePos;
						Widget.PossiblePos = -1;
					}

					Widget.HeldingAnimation = ImClamp( Widget.HeldingAnimation + ( 6 * ImGui::GetIO( ).DeltaTime * ( Widget.Helding ? 1.f : -1.f ) ), 0.f, 1.f );
					//ImGui::GetWindowDrawList( )->AddShadowRect( Widget.Position, Widget.Position + Widget.Size, ImColor( 1.f, 1.f, 1.f, ImGui::GetStyle( ).Alpha * Widget.HeldingAnimation ), 15, ImVec2( 0, 0 ), ImDrawFlags_ShadowCutOutShapeBackground );
				}
				ImGui::PopID( );
			}
		}

		void Draw( )
		{
			iBox_Height = 280;
			iBox_Width = iBox_Height / 2.f;

			iBox_X = ImGui::GetWindowPos( ).x + ImGui::GetWindowSize( ).x / 2 - iBox_Width / 2;
			iBox_Y = ImGui::GetWindowPos( ).y + ImGui::GetWindowSize( ).y / 2 - iBox_Height / 2;

			if (g_Variables.NpcImage) {
				ImU32 imgColor = ImGui::GetColorU32(ImVec4(1.0f, 1.0f, 1.0f, ImGui::GetStyle().Alpha));
				ImGui::GetWindowDrawList()->AddImage((void*)g_Variables.NpcImage, ImVec2(iBox_X, iBox_Y), ImVec2(iBox_X + iBox_Width, iBox_Y + iBox_Height), ImVec2(0, 0), ImVec2(1, 1), imgColor);
			}

			Position Positions[ ] =
			{
				{ImVec2( iBox_X, iBox_Y - 3.5f )}, // Top
				{ImVec2( iBox_X + iBox_Width + 3.5f, iBox_Y )}, // Right
				{ImVec2( iBox_X, iBox_Y + iBox_Height + 3.5f )}, // Bottom
				{ImVec2( iBox_X - 3.5f, iBox_Y )}, // Left
			};

			static float BoxAnimation = 0.f;
			BoxAnimation = ImClamp( BoxAnimation + ( 6 * ImGui::GetIO( ).DeltaTime * ( g_Config.ESP->Box ? 1.f : -1.f ) ), 0.f, g_Config.ESP->BoxCol.Value.w );

			static float BoxFillAnimation = 0.f;
			BoxFillAnimation = ImClamp( BoxFillAnimation + ( 6 * ImGui::GetIO( ).DeltaTime * ( g_Config.ESP->FilledBox ? 1.f : -1.f ) ), 0.f, g_Config.ESP->FilledBoxCol.Value.w );

			if ( BoxFillAnimation != 0 )
			{
				ImGui::GetWindowDrawList( )->AddRectFilled( ImVec2( iBox_X, iBox_Y ), ImVec2( iBox_X + iBox_Width, iBox_Y + iBox_Height ), ImColor( ( int ) g_Config.ESP->FilledBoxCol.Value.x * 255, ( int ) g_Config.ESP->FilledBoxCol.Value.y * 255, ( int ) g_Config.ESP->FilledBoxCol.Value.z * 255, ( int ) ( ( int ) ( ImGui::GetStyle( ).Alpha * 255 ) * BoxFillAnimation ) ), 0, ImDrawFlags_None );
			}

			if ( BoxAnimation != 0 )
			{
				ImGui::GetWindowDrawList( )->AddRect( ImVec2( iBox_X, iBox_Y ), ImVec2( iBox_X + iBox_Width, iBox_Y + iBox_Height ), ImColor( 0, 0, 0, ( int ) ( ( int ) ( ImGui::GetStyle( ).Alpha * 255 ) * BoxAnimation ) ), 0, ImDrawFlags_None, 2 );
				ImGui::GetWindowDrawList( )->AddRect( ImVec2( iBox_X, iBox_Y ), ImVec2( iBox_X + iBox_Width, iBox_Y + iBox_Height ), ImColor( ( int ) g_Config.ESP->BoxCol.Value.x * 255, ( int ) g_Config.ESP->BoxCol.Value.y * 255, ( int ) g_Config.ESP->BoxCol.Value.z * 255, ( int ) ( ( int ) ( ImGui::GetStyle( ).Alpha * 255 ) * BoxAnimation ) ), 0, ImDrawFlags_None );
			}

			static float SkeletonAnimation = 0.f;
			SkeletonAnimation = ImClamp( SkeletonAnimation + ( 6 * ImGui::GetIO( ).DeltaTime * ( g_Config.ESP->Skeleton ? 1.f : -1.f ) ), 0.f, g_Config.ESP->SkeletonCol.Value.w );

			if ( SkeletonAnimation > 0.f )
			{
				ImColor skelCol( ( int ) (g_Config.ESP->SkeletonCol.Value.x * 255), ( int ) (g_Config.ESP->SkeletonCol.Value.y * 255), ( int ) (g_Config.ESP->SkeletonCol.Value.z * 255), ( int ) ( ( int ) ( ImGui::GetStyle( ).Alpha * 255 ) * SkeletonAnimation ) );
				auto L = [&]( ImVec2 a, ImVec2 b ) { ImGui::GetWindowDrawList( )->AddLine( a, b, skelCol, 1.5f ); };

				ImVec2 Head( iBox_X + iBox_Width * 0.5f, iBox_Y + iBox_Height * 0.15f );
				ImVec2 Neck( iBox_X + iBox_Width * 0.5f, iBox_Y + iBox_Height * 0.22f );
				ImVec2 Pelvis( iBox_X + iBox_Width * 0.5f, iBox_Y + iBox_Height * 0.55f );

				ImVec2 LShoulder( iBox_X + iBox_Width * 0.35f, iBox_Y + iBox_Height * 0.25f );
				ImVec2 RShoulder( iBox_X + iBox_Width * 0.65f, iBox_Y + iBox_Height * 0.25f );
				ImVec2 LElbow( iBox_X + iBox_Width * 0.25f, iBox_Y + iBox_Height * 0.40f );
				ImVec2 RElbow( iBox_X + iBox_Width * 0.75f, iBox_Y + iBox_Height * 0.40f );
				ImVec2 LHand( iBox_X + iBox_Width * 0.2f, iBox_Y + iBox_Height * 0.55f );
				ImVec2 RHand( iBox_X + iBox_Width * 0.8f, iBox_Y + iBox_Height * 0.55f );

				ImVec2 LKnee( iBox_X + iBox_Width * 0.4f, iBox_Y + iBox_Height * 0.75f );
				ImVec2 RKnee( iBox_X + iBox_Width * 0.6f, iBox_Y + iBox_Height * 0.75f );
				ImVec2 LFoot( iBox_X + iBox_Width * 0.35f, iBox_Y + iBox_Height * 0.95f );
				ImVec2 RFoot( iBox_X + iBox_Width * 0.65f, iBox_Y + iBox_Height * 0.95f );

				L( Head, Neck ); L( Neck, Pelvis );
				L( Neck, LShoulder ); L( LShoulder, LElbow ); L( LElbow, LHand );
				L( Neck, RShoulder ); L( RShoulder, RElbow ); L( RElbow, RHand );
				L( Pelvis, LKnee ); L( LKnee, LFoot );
				L( Pelvis, RKnee ); L( RKnee, RFoot );
			}

			static float HeadCircleAnimation = 0.f;
			HeadCircleAnimation = ImClamp( HeadCircleAnimation + ( 6 * ImGui::GetIO( ).DeltaTime * ( g_Config.ESP->HeadCircle ? 1.f : -1.f ) ), 0.f, g_Config.ESP->SkeletonCol.Value.w );

			if ( HeadCircleAnimation > 0.f )
			{
				ImColor headCol( ( int ) (g_Config.ESP->SkeletonCol.Value.x * 255), ( int ) (g_Config.ESP->SkeletonCol.Value.y * 255), ( int ) (g_Config.ESP->SkeletonCol.Value.z * 255), ( int ) ( ( int ) ( ImGui::GetStyle( ).Alpha * 255 ) * HeadCircleAnimation ) );
				ImVec2 HeadPosC( iBox_X + iBox_Width * 0.5f, iBox_Y + iBox_Height * 0.12f );
				ImGui::GetWindowDrawList()->AddCircle( HeadPosC, iBox_Height / 15.f, headCol, 0, 1.5f );
			}

			for ( size_t i = 0; i < mWidgets.size( ); i++ )
			{
				auto & Widget = mWidgets.at( i );

				if ( Widget.IsIcon )
					ImGui::PushFont( g_Variables.FontAwesomeSolid );
				else
					ImGui::PushFont( Widget.SmallFont ? g_Variables.m_FontSecundary : g_Variables.m_FontSecundary );

				if ( !Widget.Initialized )
				{
					Widget.Position = Positions[ Widget.InitialPos ].Pos;
					Widget.Pos = Widget.InitialPos;

					if ( Widget.Type == 0 )
					{
						Widget.Size = ImGui::CalcTextSize( Widget.Text.c_str( ) );
					}
					else if ( Widget.Type == 1 )
					{
						if ( Widget.InitialPos == 0 || Widget.InitialPos == 2 )
						{
							Widget.Size = ImVec2( iBox_Width, 2 );
						}
						else
						{
							Widget.Size = ImVec2( 2, iBox_Height );
						}
					}

					Widget.Initialized = true;
				}

				switch ( i )
				{
				case 0:
					Widget.Enabled = g_Config.ESP->HealthBar;
					g_Config.ESP->HealthBarPos = Widget.RawPos;
					break;
				case 1:
					Widget.Enabled = g_Config.ESP->ArmorBar;
					g_Config.ESP->ArmorBarPos = Widget.RawPos;
					break;
				case 2:
					Widget.Enabled = g_Config.ESP->UserNames;
					g_Config.ESP->UserNamesPos = Widget.RawPos;
					break;
				case 3:
					Widget.Enabled = g_Config.ESP->WeaponName;
					g_Config.ESP->WeaponNamePos = Widget.RawPos;
					break;
				case 4:
					Widget.Enabled = g_Config.ESP->DistanceFromMe;
					g_Config.ESP->DistanceFromMePos = Widget.RawPos;
					break;
				}

				switch ( i )
				{
				case 0:
					if ( Widget.Pos != 4 )
					{
						if ( g_Config.ESP->UpdateCfgESP )
							Widget.Pos = g_Config.ESP->HealthBarState;
						else
							g_Config.ESP->HealthBarState = Widget.Pos;
					}
					break;
				case 1:
					if ( Widget.Pos != 4 )
					{
						if ( g_Config.ESP->UpdateCfgESP )
							Widget.Pos = g_Config.ESP->ArmorBarState;
						else
							g_Config.ESP->ArmorBarState = Widget.Pos;
					}
					break;
				case 2:
					if ( Widget.Pos != 4 )
					{
						if ( g_Config.ESP->UpdateCfgESP )
							Widget.Pos = g_Config.ESP->UserNamesState;
						else
							g_Config.ESP->UserNamesState = Widget.Pos;
					}
					break;
				case 3:
					if ( Widget.Pos != 4 )
					{
						if ( g_Config.ESP->UpdateCfgESP )
							Widget.Pos = g_Config.ESP->WeaponNameState;
						else
							g_Config.ESP->WeaponNameState = Widget.Pos;
					}
					break;
				case 4:
					if ( Widget.Pos != 4 )
					{
						if ( g_Config.ESP->UpdateCfgESP )
							Widget.Pos = g_Config.ESP->DistanceFromMeState;
						else
							g_Config.ESP->DistanceFromMeState = Widget.Pos;
					}
					break;
				}


				Widget.AlphaAnimation = ImClamp( Widget.AlphaAnimation + ( 6 * ImGui::GetIO( ).DeltaTime * ( Widget.Enabled ? 1.f : -1.f ) ), 0.f, 1.f );
				if ( Widget.AlphaAnimation == 0 )
				{
					ImGui::PopFont( );
					continue;
				}

				if ( Widget.Helding )
				{
					switch ( Widget.PossiblePos )
					{
					case 0:
						PaddingY[ 0 ] += -Widget.Size.y - 2;
						break;
					case 1:
						Widget.Type == 0 ? PaddingY[ 1 ] += Widget.Size.y + 2 : PaddingX[ 1 ] += Widget.Size.x + 2;
						break;
					case 2:
						PaddingY[ 2 ] += Widget.Size.y + 2;
						break;
					case 3:
						Widget.Type == 0 ? PaddingY[ 3 ] += Widget.Size.y + 2 : PaddingX[ 3 ] += -Widget.Size.x - 2;
						break;
					}
				}

				if ( Widget.Type == 0 ) //Text
				{
					if ( Widget.Pos == 0 ) // Top
					{
						Widget.Position = Positions[ Widget.Pos ].Pos + ImVec2( iBox_Width / 2 - Widget.Size.x / 2, -Widget.Size.y + PaddingY[ 0 ] );
						Widget.RawPos = ImVec2( 0, -Widget.Size.y + PaddingY[ 0 ] );
						PaddingY[ 0 ] += -Widget.Size.y - 1;
					}
					else if ( Widget.Pos == 1 ) // Right
					{
						Widget.Position = Positions[ Widget.Pos ].Pos + ImVec2( PaddingX[ 1 ], PaddingY[ 1 ] );
						Widget.RawPos = ImVec2( PaddingX[ 1 ], PaddingY[ 1 ] );
						PaddingY[ 1 ] += Widget.Size.y + 1;
					}
					else if ( Widget.Pos == 2 ) // Bottom
					{
						Widget.Position = Positions[ Widget.Pos ].Pos + ImVec2( iBox_Width / 2 - Widget.Size.x / 2, PaddingY[ 2 ] );
						Widget.RawPos = ImVec2( 0, PaddingY[ 2 ] );
						PaddingY[ 2 ] += Widget.Size.y + 1;
					}
					else if ( Widget.Pos == 3 ) // Left
					{
						Widget.Position = Positions[ Widget.Pos ].Pos + ImVec2( -Widget.Size.x + PaddingX[ 3 ], PaddingY[ 3 ] );
						Widget.RawPos = ImVec2( PaddingX[ 3 ], PaddingY[ 3 ] );
						PaddingY[ 3 ] += Widget.Size.y + 1;
					}
					else if ( Widget.Pos == 4 ) // Moving
					{
						Widget.Position = ImLerp( Widget.Position, ImGui::GetMousePos( ) + ImVec2( -Widget.Size.x / 2.f, 0 ), ImGui::GetIO( ).DeltaTime * 8 );
					}

					ImGui::GetWindowDrawList( )->AddText( Widget.Position, ImColor( 0.f, 0.f, 0.f, ImGui::GetStyle( ).Alpha * Widget.AlphaAnimation ), Widget.Text.c_str( ) );
					ImGui::GetWindowDrawList( )->AddText( Widget.Position + ImVec2( 1, 1 ), ImGui::GetColorU32( ImVec4( Widget.Color.Value.x, Widget.Color.Value.y, Widget.Color.Value.z, ImGui::GetStyle( ).Alpha * Widget.AlphaAnimation ) ), Widget.Text.c_str( ) );
				}
				else if ( Widget.Type == 1 ) //Bar
				{
					if ( Widget.Pos == 0 ) // Top
					{
						Widget.Size = ImVec2( iBox_Width, 3 );
						Widget.Position = Positions[ Widget.Pos ].Pos + ImVec2( 0, -Widget.Size.y + PaddingY[ 0 ] );
						Widget.RawPos = ImVec2( 0, -Widget.Size.y + PaddingY[ 0 ] );
						PaddingY[ 0 ] += -Widget.Size.y - 4;
					}
					else if ( Widget.Pos == 1 ) // Right
					{
						Widget.Size = ImVec2( 3, iBox_Height );
						Widget.Position = Positions[ Widget.Pos ].Pos + ImVec2( PaddingX[ 1 ], 0 );
						Widget.RawPos = ImVec2( PaddingX[ 1 ], 0 );
						PaddingX[ 1 ] += Widget.Size.x + 4;
					}
					else if ( Widget.Pos == 2 ) // Bottom
					{
						Widget.Size = ImVec2( iBox_Width, 3 );
						Widget.Position = Positions[ Widget.Pos ].Pos + ImVec2( 0, PaddingY[ 2 ] );
						Widget.RawPos = ImVec2( 0, PaddingY[ 2 ] );
						PaddingY[ 2 ] += Widget.Size.y + 4;
					}
					else if ( Widget.Pos == 3 ) // Left
					{
						Widget.Size = ImVec2( 3, iBox_Height );
						Widget.Position = Positions[ Widget.Pos ].Pos + ImVec2( -Widget.Size.x + PaddingX[ 3 ], 0 );
						Widget.RawPos = ImVec2( -Widget.Size.x + PaddingX[ 3 ], 0 );
						PaddingX[ 3 ] += -Widget.Size.x - 4;
					}
					else if ( Widget.Pos == 4 ) // Moving
					{
						if ( Widget.PossiblePos == 0 || Widget.PossiblePos == 2 )
							Widget.Size = ImVec2( iBox_Width, 3 );
						else if ( Widget.PossiblePos == 1 || Widget.PossiblePos == 3 )
							Widget.Size = ImVec2( 3, iBox_Height );

						Widget.Position = ImLerp( Widget.Position, ImGui::GetMousePos( ) + ImVec2( 0, 0 ), ImGui::GetIO( ).DeltaTime * 8 );
					}

					ImGui::GetWindowDrawList( )->AddRectFilled( Widget.Position - ImVec2( 1, 1 ), Widget.Position + Widget.Size + ImVec2( 1, 1 ), ImGui::GetColorU32( ImVec4( ImColor( 0, 0, 0 ) ), ImGui::GetStyle( ).Alpha * Widget.AlphaAnimation ) );
					ImGui::GetWindowDrawList( )->AddRectFilled( Widget.Position, Widget.Position + Widget.Size, ImGui::GetColorU32( ImVec4( ImColor( 80, 80, 80 ) ), ImGui::GetStyle( ).Alpha * ( 125.f / 255.f ) ) );
					ImGui::GetWindowDrawList( )->AddRectFilled( Widget.Position, Widget.Position + Widget.Size, ImGui::GetColorU32( ImVec4( Widget.Color.Value.x, Widget.Color.Value.y, Widget.Color.Value.z, ImGui::GetStyle( ).Alpha * Widget.AlphaAnimation ) ) );
				}

				ImGui::PopFont( );

				if ( i == mWidgets.size( ) - 1 )
				{
					if ( g_Config.ESP->UpdateCfgESP )
						g_Config.ESP->UpdateCfgESP = false;
				}
			}

			for ( size_t i = 0; i < 4; i++ )
			{
				PaddingY[ i ] = 0;
				PaddingX[ i ] = 0;
			}
		}

	private:
		class cDragWidget {
		public:
			int Type; // 0 = Text | 1 = Bar
			int InitialPos; // 0 = Top | 1 = Right | 2 = Bottom | 3 = Left
			std::string Text;
			ImColor Color;
			bool IsIcon;
			bool SmallFont = false;
			bool Initialized = false;
			bool Enabled;
			ImVec2 Position;
			int Pos;
			ImVec2 Size;
			int PossiblePos;
			bool Helding;
			float HeldingAnimation;
			float AlphaAnimation;
			ImVec2 RawPos;
		};

		float PaddingY[ 4 ] = { 0, 0, 0, 0 };
		float PaddingX[ 4 ] = { 0, 0, 0, 0 };

		struct Position {
			ImVec2 Pos;
		};

		std::vector<cDragWidget> mWidgets =
		{
			cDragWidget{ 1, 3, xorstr( "HealthBar" ), ImColor( 66, 245, 132 ) },
			cDragWidget{ 1, 3, xorstr( "ArmorBar" ), ImColor( 85, 128, 200 ) },
			cDragWidget{ 0, 0, xorstr( "Name" ), ImColor( g_Config.ESP->UserNamesCol ) },
			cDragWidget{ 0, 2, xorstr( "Unarmed" ), ImColor( g_Config.ESP->WeaponNameCol ), false, true },
			cDragWidget{ 0, 2, xorstr( "0m" ), ImColor( g_Config.ESP->DistanceCol ), false, true }
		};

	private:
		int FindClosestPosition( ImVec2 CurrentPos, Position Positions[ ], int WidgetType )
		{
			float Closest = FLT_MAX;
			int Best = -1;
			for ( int i = 0; i < 4; i++ )
			{
				if ( WidgetType == 0 && ( i == 1 || i == 3 ) )
					continue; // Ignore as posições 1 (Direita) e 3 (Esquerda) para widgets do tipo 0 (texto)

				ImVec2 Pos = Positions[ i ].Pos;
				float dist = std::sqrt( ( CurrentPos.x - Pos.x ) * ( CurrentPos.x - Pos.x ) + ( CurrentPos.y - Pos.y ) * ( CurrentPos.y - Pos.y ) );

				if ( Closest > dist )
				{
					Closest = dist;
					Best = i;
				}
			}

			return Best;
		}


	private:
		int iBox_X;
		int iBox_Y;
		int iBox_Width;
		int iBox_Height;

	};
	inline EspPreview g_EspPreview;

}

