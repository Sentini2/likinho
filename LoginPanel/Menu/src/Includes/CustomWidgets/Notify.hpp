#pragma once
#include <Includes/Includes.hpp>
#include <Includes/Utils.hpp>
#include <chrono>
#include <map>

namespace NotifyManager
{
	enum eType {
		None,
		Info,
		Warning
	};

	enum eState {
		In,
		Current,
		Out,
		Expired
	};

	class NotifyClass {
	private:
		std::string Title;
		std::string Description;
		time_t ExpireTime = 0;
		time_t CreationTime = 0;
		eType Type = eType::None;
		eState CurrentState = eState::In;
	public:
		void SetTitle( std::string NewTitle ) { this->Title = NewTitle; }
		void SetDescription( std::string NewDesc ) { this->Description = NewDesc; }
		void SetType( eType NewType ) { this->Type = NewType; }
		void SetState( eState NewState ) { this->CurrentState = NewState; }
		void SetCreationTime( time_t NewCreationTime ) { this->CreationTime = NewCreationTime; }
	public:
		std::string GetTitle( ) { return Title; }
		std::string GetDescription( ) { return Description; }
		time_t GetExpireTime( ) { return ExpireTime; }
		time_t GetCreationTime( ) { return CreationTime; }
		eType GetType( ) { return Type; }
		eState GetCurrentState( ) { return CurrentState; }
	public:
		time_t GetNowTime( ) {
			using namespace std::chrono;
			return duration_cast< milliseconds >( steady_clock::now( ).time_since_epoch( ) ).count( );
		}

		time_t GetTimeDiff( ) {
			return ( time_t ) ( GetNowTime( ) - CreationTime );
		}

		NotifyClass( eType Type, time_t ExpireTime = 4000 )
		{
			this->Type = Type;
			this->ExpireTime = ExpireTime;
			this->CreationTime = GetNowTime( );
		}
	};

	inline std::vector<NotifyClass> NotifyList;

    inline void DeleteNotify( int Index )
	{
		NotifyList.erase( NotifyList.begin( ) + Index );
	}

    inline void Render( )
	{
        const auto DrawList = ImGui::GetForegroundDrawList( );
        const auto WindowSize = g_Variables.g_vGameWindowSize;
        float NextHeight = 0.f;

        for ( auto i = 0; i < NotifyList.size( ); i++ )
        {
            auto & Notify = NotifyList.at( i );

            struct NotifyWid_t {
                float SlideX = 0.f;
                float YPos = 0.f;
                float Alpha = 0.f;
            };

            static std::map<std::string, NotifyWid_t> anim;
            const auto Id = Notify.GetDescription( ) + std::to_string( Notify.GetCreationTime( ) );
            auto NotifyAnim = anim.find( Id );
            if ( NotifyAnim == anim.end( ) )
            {
                anim.insert( { Id, NotifyWid_t( ) } );
                NotifyAnim = anim.find( Id );
            }

            if ( Notify.GetCurrentState( ) == eState::Expired )
            {
                Notify.SetState( eState::In );
                DeleteNotify( i );
                anim.erase( Id );
                i--;
                continue;
            }

            auto TitleTxtSize = Utils::CalcTextSize( g_Variables.m_FontNormal, g_Variables.m_FontNormal->FontSize, Notify.GetTitle( ).c_str( ) );
            auto DescTxtSize = Utils::CalcTextSize( g_Variables.m_FontSecundary, g_Variables.m_FontSecundary->FontSize, Notify.GetDescription( ).c_str( ) );

            const float Padding = 8;

            static ImVec2 NotifySize;

            if ( TitleTxtSize.x > DescTxtSize.x ) {
                NotifySize = ImVec2( TitleTxtSize.x + ( Padding * 2 ), DescTxtSize.y + TitleTxtSize.y + ( Padding * 2 ) + 4 );
            }
            else {
                NotifySize = ImVec2( DescTxtSize.x + ( Padding * 2 ), DescTxtSize.y + TitleTxtSize.y + ( Padding * 2 ) + 4 );
            }

            if ( Notify.GetCurrentState( ) == eState::In || Notify.GetCurrentState( ) == eState::Current )
            {
                NotifyAnim->second.SlideX = ImLerp( NotifyAnim->second.SlideX, NotifySize.x, ImGui::GetIO( ).DeltaTime * 8 );
                NotifyAnim->second.Alpha = ImLerp( NotifyAnim->second.Alpha, 1.f, ImGui::GetIO( ).DeltaTime * 8 );
            }

            if ( NotifyAnim->second.SlideX >= NotifySize.x - 1.f ) {
                Notify.SetState( eState::Current );
            }

            if ( Notify.GetCurrentState( ) == eState::Current && Notify.GetTimeDiff( ) > Notify.GetExpireTime( ) ) {
                Notify.SetState( eState::Out );
            }

            if ( Notify.GetCurrentState( ) == eState::Out )
            {
                NotifyAnim->second.SlideX = ImLerp( NotifyAnim->second.SlideX, 0.f, ImGui::GetIO( ).DeltaTime * 8 );
                NotifyAnim->second.Alpha = ImLerp( NotifyAnim->second.Alpha, 0.f, ImGui::GetIO( ).DeltaTime * 6 );
                if ( NotifyAnim->second.SlideX <= 2.f )
                {
                    Notify.SetState( eState::Expired );
                }
            }

            NotifyAnim->second.YPos = ImLerp( NotifyAnim->second.YPos, NextHeight, ImGui::GetIO( ).DeltaTime * 8 );

            float NotifyStartX = WindowSize.x - NotifySize.x;
            float NotifyStartY = WindowSize.y - NotifySize.y - Padding - NotifyAnim->second.YPos;


            if ( Notify.GetCurrentState( ) != eState::In )
            {
               // NotifyAnim->second.YPos = ImLerp( NotifyAnim->second.YPos, NotifyStartY, ImGui::GetIO( ).DeltaTime * 8 );
            }
            else {
               // NotifyAnim->second.YPos = NotifyStartY;
            }

            ImRect NotifyPos(
                ImVec2( NotifyStartX + NotifySize.x - NotifyAnim->second.SlideX, NotifyStartY ), // Min
                ImVec2( NotifyStartX + NotifySize.x - NotifyAnim->second.SlideX + NotifySize.x, NotifyStartY + NotifySize.y ) // Max
            );

            ImGui::PushStyleVar( ImGuiStyleVar_Alpha, NotifyAnim->second.Alpha );

            DrawList->AddRectFilled( NotifyPos.Min, NotifyPos.Max, ImGui::GetColorU32( ImVec4( ImColor( 14, 14, 14, 255 ) ) ), 0 );
            //DrawList->AddRect( NotifyPos.Min, NotifyPos.Max, ImGui::GetColorU32( ImVec4( ImColor( 24, 24, 24, 255 ) ) ), 0 );

            float Progress = 1.0f - ( ( float ) Notify.GetTimeDiff( ) / ( float ) Notify.GetExpireTime( ) );
            ImVec2 ProgressBarMin = ImVec2( NotifyPos.Min.x, NotifyPos.Max.y - 3 );
            ImVec2 ProgressBarMax = ImVec2( NotifyPos.Min.x + ( NotifySize.x * Progress ), NotifyPos.Max.y - 1 );
            ImVec2 ProgressBarShadowMax = ImVec2( NotifyPos.Min.x + ( NotifySize.x * (Progress * 1.1) ), NotifyPos.Max.y );
            DrawList->AddRectFilled( ProgressBarMin, ProgressBarShadowMax, ImGui::GetColorU32( ImVec4( g_Col.Base ), 0.3 ), 99 );
            DrawList->AddRectFilled( ProgressBarMin, ProgressBarMax, ImGui::GetColorU32( ImVec4( g_Col.Base ) ), 99 );

            auto TitlePos = ImVec2( NotifyPos.Min.x + Padding, NotifyPos.Min.y + Padding - 1 );
            DrawList->AddText( g_Variables.m_FontNormal, g_Variables.m_FontNormal->FontSize, TitlePos, ImGui::GetColorU32( ImVec4( ImColor( g_Col.PrimaryText ) ) ), Notify.GetTitle( ).c_str( ) );
            DrawList->AddText( g_Variables.m_FontSecundary, g_Variables.m_FontSecundary->FontSize, TitlePos + ImVec2( 0, TitleTxtSize.y + 2.f ), ImGui::GetColorU32( ImVec4( ImColor( g_Col.SecundaryText ) ) ), Notify.GetDescription( ).c_str( ) );

            ImGui::PopStyleVar( );

            NextHeight += NotifySize.y + 10.f;
        }
	}

    inline void Send( std::string Description, time_t ExpireTime )
    {
        Beep( 100, 300 );
        NotifyManager::NotifyClass Notify( NotifyManager::eType::Info, ExpireTime );
        Notify.SetTitle( xorstr( "Nome do teu cheat" ) );
        Notify.SetDescription( Description );
        NotifyList.push_back( Notify );
    }

}