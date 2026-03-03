#pragma once
#include <Includes/Includes.hpp>
#include <windows.h>
#include <iostream>
#include <thread>
#include <Core/SDK/SDK.hpp>

using namespace std;

namespace Combat {

	static int iSubTabCount = 0;
	static float SubTabAlpha = 0.f;
	static int iSubTab = 0;

	void Render( ) {

		// Sub-tabs with proper spacing
		ImGui::Spacing();
		if ( Custom::SubTab( Lang(xorstr( "Aimbot###com_aim" ), xorstr("Mira Automatica###com_aim")), 0 == iSubTabCount ) ) {
			iSubTabCount = 0;
		}
		ImGui::SameLine(0, 8);
		if ( Custom::SubTab( Lang(xorstr( "TriggerBot###com_trig" ), xorstr("Gatilho Automatico###com_trig")), 1 == iSubTabCount ) ) {
			iSubTabCount = 1;
		}
		ImGui::SameLine(0, 8);
		if ( Custom::SubTab( Lang(xorstr( "SilentAim###com_sil" ), xorstr("Mira Silenciosa###com_sil")), 2 == iSubTabCount ) ) {
			iSubTabCount = 2;
		}
		ImGui::SameLine(0, 8);
		if (Custom::SubTab(Lang(xorstr("Colors###com_col"), xorstr("Cores###com_col")), 3 == iSubTabCount)) {
			iSubTabCount = 3;
		}
		ImGui::SameLine(0, 8);
		if (Custom::SubTab(Lang(xorstr("Friends###com_friends"), xorstr("Amigos###com_friends")), 4 == iSubTabCount)) {
			iSubTabCount = 4;
		}


		SubTabAlpha = ImClamp( SubTabAlpha + ( 5.f * ImGui::GetIO( ).DeltaTime * ( iSubTabCount == iSubTab ? 1.f : -1.f ) ), 0.f, 1.f );

		if ( SubTabAlpha == 0.f )
			iSubTab = iSubTabCount;

		ImGui::PushStyleVar( ImGuiStyleVar_Alpha, SubTabAlpha * ImGui::GetStyle( ).Alpha );

		// Content area below sub-tabs
		ImGui::Spacing();
		ImGui::Spacing();
		ImGui::BeginGroup( );
		{
			float availW = ImGui::GetContentRegionAvail().x;
			float panelW = (availW - 20) * 0.5f;
			
			switch ( iSubTab )
			{
			case 0: //Aimbot
				ImGui::BeginGroup( );
				{
					ImGui::BeginChild( Lang(xorstr( "Globals" ), xorstr("Gerais")), ImVec2( panelW, 350 ), false, 0 );
					{
						Custom::CheckBox( Lang(xorstr( "Toggle" ), xorstr("Ativar")), &g_Config.Aimbot->Enabled );
						Custom::CheckBox( Lang(xorstr( "Show Fov" ), xorstr("Mostrar FOV")), &g_Config.Aimbot->ShowFov );
						ImGui::SameLine(); ImGui::TextDisabled("(?)"); if (ImGui::IsItemHovered()) ImGui::SetTooltip(Lang("Displays the aimbot field of view\ncircle on screen.", "Mostra o circulo do campo de visao\ndo aimbot na tela."));
						Custom::CheckBox( Lang(xorstr( "Ignore NPCs" ), xorstr("Ignorar NPCs")), &g_Config.Aimbot->IgnoreNPCs );
						ImGui::SameLine(); ImGui::TextDisabled("(?)"); if (ImGui::IsItemHovered()) ImGui::SetTooltip(Lang("Only targets real players,\nignores AI/NPCs.", "Mira apenas em jogadores reais,\nignora bots/NPCs."));
					}
					ImGui::EndChild( );
				}
				ImGui::EndGroup( );
				ImGui::SameLine(0, 20);
				ImGui::BeginGroup( );
				{
					ImGui::BeginChild( Lang(xorstr( "Settings" ), xorstr("Config")), ImVec2( panelW, 350 ), false, 0 );
					{
						Custom::SliderInt( Lang(xorstr( "Field of View" ), xorstr("Campo de Visao")), &g_Config.Aimbot->FOV, 0, 400, xorstr( "%d" ), 0 );
						Custom::SliderInt( Lang(xorstr( "Smooth" ), xorstr("Suavidade")), &g_Config.Aimbot->AimbotSpeed, 0, 100, xorstr( "%d" ), 0 );
						ImGui::SameLine(); ImGui::TextDisabled("(?)"); if (ImGui::IsItemHovered()) ImGui::SetTooltip(Lang("Higher = slower, more natural aim.\nLower = faster, more snappy.", "Maior = lento, mira mais natural.\nMenor = rapido, mais travado."));
						Custom::SliderInt( Lang(xorstr( "Max Distance" ), xorstr("Distancia Maxima")), &g_Config.Aimbot->MaxDistance, 0, 1000, xorstr( "%dm" ), 0 );
						static int aimKeyMode = 1;
						ImGui::Keybind( Lang(xorstr( "Bind" ), xorstr("Tecla")), &g_Config.Aimbot->KeyBind, &aimKeyMode );
					}
					ImGui::EndChild( );
				}
				ImGui::EndGroup( );

				break;
			case 1: //Trigger
				ImGui::BeginGroup( );
				{
					ImGui::BeginChild( Lang(xorstr( "Globals" ), xorstr("Gerais")), ImVec2( panelW, 350 ), false, 0 );
					{
						Custom::CheckBox( Lang(xorstr( "Toggle" ), xorstr("Ativar")), &g_Config.TriggerBot->Enabled );

						if (!g_Config.TriggerBot->SmartTrigger) {
						Custom::CheckBox( Lang(xorstr( "Show Fov" ), xorstr("Mostrar FOV")), &g_Config.TriggerBot->ShowFov );
						}
						else
						{
							g_Config.TriggerBot->ShowFov = false;
						}

						Custom::CheckBox( Lang(xorstr( "Smart Triggerbot" ), xorstr("Trigger Inteligente")), &g_Config.TriggerBot->SmartTrigger );
						ImGui::SameLine(); ImGui::TextDisabled("(?)"); if (ImGui::IsItemHovered()) ImGui::SetTooltip(Lang("Auto-fires when crosshair is on a player.\nNo FOV circle needed.", "Atira automaticamente quando a mira\nesta num jogador (sem necessidade de FOV)."));
						Custom::CheckBox( Lang(xorstr( "Ignore NPCs" ), xorstr("Ignorar NPCs")), &g_Config.TriggerBot->IgnoreNPCs );
					}
					ImGui::EndChild( );
				}
				ImGui::EndGroup( );
				ImGui::SameLine(0, 20);
				ImGui::BeginGroup( );
				{
					ImGui::BeginChild( Lang(xorstr( "Settings" ), xorstr("Config")), ImVec2( panelW, 350 ), false, 0 );
					{
						if (!g_Config.TriggerBot->SmartTrigger) {
							Custom::SliderInt(Lang(xorstr("Field of View"), xorstr("Campo de Visao")), &g_Config.TriggerBot->FOV, 0, 400, xorstr("%d"), 0);
							Custom::SliderInt(Lang(xorstr("Max Distance"), xorstr("Distancia Maxima")), &g_Config.TriggerBot->MaxDistance, 0, 1000, xorstr("%dm"), 0);
						}
						
						Custom::SliderInt( Lang(xorstr( "Delay" ), xorstr("Atraso (ms)")), &g_Config.TriggerBot->Delay, 0, 10, xorstr( "%d" ), 0 );
						static int trigKeyMode = 1;
						ImGui::Keybind( Lang(xorstr( "Bind" ), xorstr("Tecla")), &g_Config.TriggerBot->KeyBind, &trigKeyMode );
					}
					ImGui::EndChild( );
				}
				ImGui::EndGroup( );
				break;
			case 2: //Silent
				ImGui::BeginGroup( );
				{
					ImGui::BeginChild( Lang(xorstr( "Globals" ), xorstr("Gerais")), ImVec2( panelW, 350 ), false, 0 );
					{
						Custom::CheckBox( Lang(xorstr( "Toggle" ), xorstr("Ativar")), &g_Config.SilentAim->Enabled );
						Custom::CheckBox( Lang(xorstr( "Show Fov" ), xorstr("Mostrar FOV")), &g_Config.SilentAim->ShowFov );
						Custom::CheckBox( Lang(xorstr( "Magic Bullets" ), xorstr("Balas Magicas")), &g_Config.SilentAim->MagicBullets );
						ImGui::SameLine(); ImGui::TextDisabled("(?)"); if (ImGui::IsItemHovered()) ImGui::SetTooltip(Lang("Bullets hit target regardless of\nwhere you actually shoot.", "Os tiros acertam o alvo independente\nde onde voce atire."));
						Custom::CheckBox( Lang(xorstr( "Ignore NPCs" ), xorstr("Ignorar NPCs")), &g_Config.SilentAim->IgnoreNPCs );
					}
					ImGui::EndChild( );
				}
				ImGui::EndGroup( );
				ImGui::SameLine(0, 20);
				ImGui::BeginGroup( );
				{
					ImGui::BeginChild( Lang(xorstr( "Settings" ), xorstr("Config")), ImVec2( panelW, 350 ), false, 0 );
					{
						Custom::SliderInt( Lang(xorstr( "Field of View" ), xorstr("Campo de Visao")), &g_Config.SilentAim->FOV, 0, 400, xorstr( "%d" ), 0 );
						Custom::SliderInt( Lang(xorstr( "Miss Chance" ), xorstr("Chance de Erro")), &g_Config.SilentAim->MissChance, 0, 100, xorstr( "%dx" ), 0 );
						ImGui::SameLine(); ImGui::TextDisabled("(?)"); if (ImGui::IsItemHovered()) ImGui::SetTooltip(Lang("Percentage of shots that intentionally miss.\nHigher = more legit looking.", "Porcentagem de tiros que erram de proposito.\nMaior = mais legitimo."));
						Custom::SliderInt( Lang(xorstr( "Max Distance" ), xorstr("Distancia Maxima")), &g_Config.SilentAim->MaxDistance, 0, 1000, xorstr( "%dm" ), 0 );
						static int silKeyMode = 1;
						ImGui::Keybind( Lang(xorstr( "Bind" ), xorstr("Tecla")), &g_Config.SilentAim->KeyBind, &silKeyMode );
					}
					ImGui::EndChild( );
				}
				ImGui::EndGroup( );
				break;
			case 3: //Colors
				ImGui::BeginGroup();
				{
					ImGui::BeginChild(Lang(xorstr("Colors"), xorstr("Cores")), ImVec2(panelW * 2 + 20, 350), false, 0);
					{
						static float AimbotFovCol[4] = { g_Config.Aimbot->FovColor.Value.x, g_Config.Aimbot->FovColor.Value.y, g_Config.Aimbot->FovColor.Value.z,g_Config.Aimbot->FovColor.Value.w };
						if (ImGui::ColorEdit4(Lang(xorstr("Aimbot Fov"), xorstr("FOV da Mira")), AimbotFovCol, ImGuiColorEditFlags_AlphaBar))
						{
							g_Config.Aimbot->FovColor.Value.x = AimbotFovCol[0];
							g_Config.Aimbot->FovColor.Value.y = AimbotFovCol[1];
							g_Config.Aimbot->FovColor.Value.z = AimbotFovCol[2];
							g_Config.Aimbot->FovColor.Value.w = AimbotFovCol[3];
						}


						static float TriggerFovCol[4] = { g_Config.TriggerBot->FovColor.Value.x, g_Config.TriggerBot->FovColor.Value.y, g_Config.TriggerBot->FovColor.Value.z,g_Config.TriggerBot->FovColor.Value.w };
						if (ImGui::ColorEdit4(Lang(xorstr("Triggerbot Fov"), xorstr("FOV do Gatilho")), TriggerFovCol, ImGuiColorEditFlags_AlphaBar))
						{
							g_Config.TriggerBot->FovColor.Value.x = TriggerFovCol[0];
							g_Config.TriggerBot->FovColor.Value.y = TriggerFovCol[1];
							g_Config.TriggerBot->FovColor.Value.z = TriggerFovCol[2];
							g_Config.TriggerBot->FovColor.Value.w = TriggerFovCol[3];
						}

						static float SilentAimFovCol[4] = { g_Config.SilentAim->FovColor.Value.x, g_Config.SilentAim->FovColor.Value.y, g_Config.SilentAim->FovColor.Value.z,g_Config.SilentAim->FovColor.Value.w };
						if (ImGui::ColorEdit4(Lang(xorstr("SilentAim Fov"), xorstr("FOV da Mira Silenciosa")), SilentAimFovCol, ImGuiColorEditFlags_AlphaBar))
						{
							g_Config.SilentAim->FovColor.Value.x = SilentAimFovCol[0];
							g_Config.SilentAim->FovColor.Value.y = SilentAimFovCol[1];
							g_Config.SilentAim->FovColor.Value.z = SilentAimFovCol[2];
							g_Config.SilentAim->FovColor.Value.w = SilentAimFovCol[3];
						}
					}
					ImGui::EndChild();
				}
				ImGui::EndGroup();
				break;
			case 4: //Friends
				ImGui::BeginGroup();
				{
					ImGui::BeginChild(Lang(xorstr("Friend List"), xorstr("Lista de Amigos")), ImVec2(panelW * 2 + 20, 350), false, 0);
					{
						ImGui::TextColored(g_Col.PrimaryText, Lang("Players Nearby:", "Jogadores Proximos:"));
						ImGui::Spacing();

						if (ImGui::BeginChild("##friends_scroller", ImVec2(panelW - 10, 250), true))
						{
							for (auto& entity : Core::SDK::Game::EntityList) {
								std::string entityName = entity.NetworkInfo.UserName;
								if (entity.PedType == 2 && !entityName.empty() && entityName != "Invalid") { // Is Player
									bool isFriend = g_Config.Aimbot->FriendList.find(entityName) != g_Config.Aimbot->FriendList.end();
									
									ImVec4 color = isFriend ? ImVec4(0, 0.6f, 1.0f, 1) : ImVec4(0.8f, 0.8f, 0.8f, 1);
									ImGui::PushStyleColor(ImGuiCol_Text, color);
									
									if (ImGui::Selectable(entityName.c_str(), isFriend)) {
										if (isFriend)
											g_Config.Aimbot->FriendList.erase(entityName);
										else
											g_Config.Aimbot->FriendList.insert(entityName);
									}
									ImGui::PopStyleColor();
									
									if (ImGui::IsItemHovered()) {
										ImGui::SetTooltip(Lang("Click to add/remove from friends", "Clique para adicionar/remover dos amigos"));
									}
								}
							}
						}
						ImGui::EndChild();
						
						ImGui::SameLine();
						
						ImGui::BeginGroup();
						{
							ImGui::TextDisabled(Lang("Note:", "Nota:"));
							ImGui::TextWrapped(Lang("Friends selected in blue will be completely ignored by the aimbot, and their ESP will instantly turn blue.", "Amigos selecionados em azul serao completamente ignorados pela mira automatica, e o ESP deles ficara azul instantaneamente."));
							ImGui::Spacing();
							if (ImGui::Button(Lang("Clear Friends", "Limpar Amigos"), ImVec2(120, 30))) {
								g_Config.Aimbot->FriendList.clear();
							}
						}
						ImGui::EndGroup();
					}
					ImGui::EndChild();
				}
				ImGui::EndGroup();
				break;
			default:
				break;
			}

		}
		ImGui::EndGroup( );

		ImGui::PopStyleVar( );
	}
}



