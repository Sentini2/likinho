#pragma once
#include <Includes/Includes.hpp>

namespace Custom
{
	namespace WaterMark
	{
		void Render( )
		{
			ImDrawList * DrawList = ImGui::GetBackgroundDrawList( );

			ImVec2 LogoSize = ImVec2( 44, 44 );

			const float Padding = 10;

			ImVec2 Size( 200, 40 ); 
			ImVec2 Pos( g_Variables.g_vGameWindowSize.x - Size.x, 10 );

			DrawList->AddRectFilled( Pos, Pos + Size, ImColor( g_Col.ChildCol ), 6, ImDrawFlags_RoundCornersLeft );

		}
	}

	namespace ArrayList
	{
		void Render( )
		{

		}
	}

}