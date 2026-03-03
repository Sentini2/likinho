#include "imgui_tricks.hpp"
#include <Includes/menu_settings.h>
#include <globals.hpp>

namespace imtricks {

	namespace Animations {

		int FastLerpInt( const char * identifier, bool state, int min, int max, int speed ) {

			static std::map<const char *, int> valuesMapInt;
			auto value = valuesMapInt.find( identifier );

			if ( value == valuesMapInt.end( ) ) {
				valuesMapInt.insert( { identifier,  0 } );
				value = valuesMapInt.find( identifier );
			}

			const float frameRateSpeed = speed * ( 1.f - ImGui::GetIO( ).DeltaTime );

			if ( state ) {
				if ( value->second < max )
					value->second += frameRateSpeed;
			}
			else {
				if ( value->second > min )
					value->second -= frameRateSpeed;
			}

			value->second = std::clamp( value->second, min, max );

			return value->second;
		}

		float FastLerpFloat( const char * identifier, bool state, float min, float max, float speed ) {

			static std::map<const char *, float> valuesMapFloat;
			auto value = valuesMapFloat.find( identifier );

			if ( value == valuesMapFloat.end( ) ) {
				valuesMapFloat.insert( { identifier, 0.f } );
				value = valuesMapFloat.find( identifier );
			}

			const float frameRateSpeed = speed * ( 1.f - ImGui::GetIO( ).DeltaTime );

			if ( state ) {
				if ( value->second < max )
					value->second += frameRateSpeed;
			}
			else {
				if ( value->second > min )
					value->second -= frameRateSpeed;
			}

			value->second = std::clamp( value->second, min, max );

			return value->second;
		}

		ImColor FastColorLerp( ImColor start, ImColor end, float stage )
		{
			ImVec4 lerp = ImLerp(
				ImVec4( start.Value.x, start.Value.y, start.Value.z, start.Value.w ),
				ImVec4( end.Value.x, end.Value.y, end.Value.z, end.Value.w ),
				stage );

			return ImGui::ColorConvertFloat4ToU32( lerp );
		}

	}

	namespace notify {

		//Gambiarra extrema que chagpt ajudou : )

		std::vector<notify_structure> notifies;

		void send_notify( const char * title, const char * message, NotifyState state ) {
			notifies.push_back( { title, message, state, GetTickCount64( ) + 3000 } );
		}

		void render_notifies( ImDrawList * draw ) {
			if ( notifies.empty( ) )
				return;

			const auto screen_size = ImGui::GetIO( ).DisplaySize;
			float not_pos_y = 10.f;

			auto draw_notify = [ &draw, &not_pos_y, &screen_size ] ( notify_structure & notify ) {

				ImVec2 message_text_size = g_Variables.m_FontSecundary->CalcTextSizeA( 12, FLT_MAX, 0.f, notify.message );
				ImVec2 title_text_size = g_Variables.m_FontNormal->CalcTextSizeA( 13, FLT_MAX, 0.f, notify.title );

				float initial_x_pos = notify.x_pos;
				float target_x_pos = 0.f;
				float speed = 8.f;

				if ( notify.time > GetTickCount64( ) ) { // enter
					target_x_pos = initial_x_pos - ( initial_x_pos - message_text_size.x - 30.f ) + 10.f;
				}
				else { // out
					target_x_pos = -message_text_size.x - 30.f + 10.f;
					speed = 2.f;
				}

				notify.x_pos = ImLerp( notify.x_pos, target_x_pos, ImGui::GetIO( ).DeltaTime * speed );

				ImVec2 notify_pos = screen_size - ImVec2( notify.x_pos, ImGui::GetIO( ).DisplaySize.y - not_pos_y );

				const auto notify_end_pos = notify_pos + ImVec2( message_text_size.x + 20.f, message_text_size.y + 50.f );

				draw->AddRectFilled( notify_pos, notify_end_pos, ImGui::GetColorU32( ( ImVec4 ) ImColor( 18, 18, 18 ) ), 4.f );
				draw->AddRect( notify_pos, notify_end_pos, ImGui::GetColorU32( ( ImVec4 ) ImColor( 22, 22, 22 ) ), 4.f );

				draw->AddLine( { notify_pos.x, notify_pos.y + 30.f }, { notify_end_pos.x, notify_pos.y + 30.f }, ImGui::GetColorU32( ( ImVec4 ) ImColor( 22, 22, 22 ) ), 1.f );

				auto state_color = ImColor( 45, 45, 45 );

				//switch ( notify.state ) {
				//case ImTrickNotify_Success: state_color = ImColor( 0, 255, 0 ); break;
				//case ImTrickNotify_Warning: state_color = ImColor( 130, 255, 0 ); break;
				//case ImTrickNotify_Danger: state_color = ImColor( 255, 0, 0 ); break;
				//case ImTrickNotify_Default:
				//default:
				//	state_color = ImColor( 45, 45, 45 );
				//	break;
				//}

				//draw->AddRectFilled( notify_pos, ImVec2( notify_pos.x + 5.f, notify_pos.y + message_text_size.y + 20.f ), state_color, 1.f );

				const auto text_pos = notify_pos + ImVec2( 6.f, 36.f );
				const auto title_text_pos = notify_pos + ImVec2( 6.f, 8.f );

				draw->AddText( g_Variables.m_FontSecundary, 12, text_pos, ImGui::GetColorU32( ( ImVec4 ) ImColor( 140, 140, 140 ) ), notify.message );
				draw->AddText( g_Variables.m_FontNormal, 13, title_text_pos, ImGui::GetColorU32( ( ImVec4 ) ImColor( 255, 255, 255 ) ), notify.title );

				not_pos_y += message_text_size.y + 60.f;

				if ( notify.x_pos <= -message_text_size.x - 30.f ) {
					notifies.erase( std::remove_if( notifies.begin( ), notifies.end( ),
						[ &notify ] ( const notify_structure & n ) { return n.time == notify.time; } ),
						notifies.end( ) );
				}
			};

			for ( auto & notify : notifies ) {
				draw_notify( notify );
			}
		}
	}


	namespace Widgets {
		void ColorEdit3( const char * label, ImColor & color, ImGuiColorEditFlags flags ) {
			static float col[ 3 ] = { color.Value.x, color.Value.y, color.Value.z };

			if ( ImGui::ColorEdit3( label, col, flags ) )
				color = ImColor( col[ 0 ], col[ 1 ], col[ 2 ] );
		}

		void ColorEdit4( const char * label, ImColor & color, ImGuiColorEditFlags flags ) {
			static float col[ 4 ] = { color.Value.x, color.Value.y, color.Value.z , color.Value.w };

			if ( ImGui::ColorEdit4( label, col, flags ) )
				color = ImColor( col[ 0 ], col[ 1 ], col[ 2 ], col[ 3 ] );
		}
	}

}