#pragma once
#include <Includes/includes.hpp>
#include <windows.h>
#include <iostream>
#include <thread>
#include <Includes/CustomWidgets/Preview.hpp>

#include <Core/SDK/SDK.hpp>

using namespace std;

namespace Visuals {

	static int iSubTabCount = 0;
	static float SubTabAlpha = 0.f;
	static int iSubTab = 0;

	void Render( ) {


		//ImGui::PushStyleVar( ImGuiStyleVar_::ImGuiStyleVar_ItemSpacing, ImVec2( 6, 0 ) );

		if ( Custom::SubTab( Lang(xorstr( "Players###vis_pla" ), xorstr("Jogadores###vis_pla")), 0 == iSubTabCount ) ) {
			iSubTabCount = 0;
		}
		ImGui::SameLine( );
		if ( Custom::SubTab( Lang(xorstr( "Vehicles###vis_veh" ), xorstr("Veiculos###vis_veh")), 1 == iSubTabCount ) ) {
			iSubTabCount = 1;
		}
		ImGui::SameLine();
		if (Custom::SubTab(Lang(xorstr("Admin List###vis_adm"), xorstr("Lista Admin###vis_adm")), 2 == iSubTabCount)) {
			iSubTabCount = 2;
		}
		ImGui::SameLine();
		if (Custom::SubTab(Lang(xorstr("Colors###vis_col"), xorstr("Cores###vis_col")), 3 == iSubTabCount)) {
			iSubTabCount = 3;
		}


		SubTabAlpha = ImClamp( SubTabAlpha + ( 5.f * ImGui::GetIO( ).DeltaTime * ( iSubTabCount == iSubTab ? 1.f : -1.f ) ), 0.f, 1.f );

		if ( SubTabAlpha == 0.f )
			iSubTab = iSubTabCount;


		ImGui::PushStyleVar( ImGuiStyleVar_Alpha, SubTabAlpha * ImGui::GetStyle( ).Alpha );

		ImGui::Spacing(); ImGui::Spacing();
		ImGui::BeginGroup( );
		{
			switch ( iSubTab )
			{
		case 0: //Players
			{
				float availW = ImGui::GetContentRegionAvail().x;
				float colW = (availW - 30) / 3.0f; // 3 columns with 15px gaps

				// === LEFT COLUMN: First 8 checkboxes ===
				ImGui::BeginGroup();
				{
					ImGui::BeginChild(xorstr("col1"), ImVec2(colW, 0), false, 0);
					{
						if (Custom::CheckBox(Lang(xorstr("Toggle"), xorstr("Ativar")), &g_Config.ESP->Enabled));
						if (Custom::CheckBox(Lang(xorstr("Box"), xorstr("Caixa")), &g_Config.ESP->Box)) {
							if (!g_Config.ESP->Box) g_Config.ESP->FilledBox = false;
						}
						if (Custom::CheckBox(Lang(xorstr("Filled Box"), xorstr("Caixa Preenchida")), &g_Config.ESP->FilledBox)) {
							if (!g_Config.ESP->Box) g_Config.ESP->Box = true;
						}
						ImGui::SameLine(); ImGui::TextDisabled("(?)"); if (ImGui::IsItemHovered()) ImGui::SetTooltip(Lang("Fills the ESP box with a semi-transparent color.\nAutomatically enables Box.", "Preenche a caixa de ESP com uma cor semitransparente.\nAtiva Caixa automaticamente."));
						Custom::CheckBox(Lang(xorstr("Player Names"), xorstr("Nomes dos Jogadores")), &g_Config.ESP->UserNames);
						Custom::CheckBox(Lang(xorstr("Weapon Names"), xorstr("Nomes das Armas")), &g_Config.ESP->WeaponName);
						Custom::CheckBox(Lang(xorstr("Distance"), xorstr("Distancia")), &g_Config.ESP->DistanceFromMe);
						if (Custom::CheckBox(Lang(xorstr("Skeleton"), xorstr("Esqueleto")), &g_Config.ESP->Skeleton))
							Core::SDK::Pointers::pLocalPlayer->RemoveKinematics();
						ImGui::SameLine(); ImGui::TextDisabled("(?)"); if (ImGui::IsItemHovered()) ImGui::SetTooltip(Lang("Draws bone connections on players.\nShows their body pose through walls.", "Desenha conexoes osseas nos jogadores.\nMostra a pose do corpo deles atraves de paredes."));
						Custom::CheckBox(Lang(xorstr("Head Circle"), xorstr("Circulo na Cabeca")), &g_Config.ESP->HeadCircle);
						ImGui::SameLine(); ImGui::TextDisabled("(?)"); if (ImGui::IsItemHovered()) ImGui::SetTooltip(Lang("Draws a circle around the player's head.\nUseful for headshot targeting.", "Desenha um circulo ao redor da cabeca do jogador.\nUtil para mirar na cabeca."));
					}
					ImGui::EndChild();
				}
				ImGui::EndGroup();
				ImGui::SameLine(0, 15);

				// === MIDDLE COLUMN: Remaining checkboxes + slider ===
				ImGui::BeginGroup();
				{
					ImGui::BeginChild(xorstr("col2"), ImVec2(colW, 0), false, 0);
					{
						Custom::CheckBox(Lang(xorstr("Health Bar"), xorstr("Barra de Vida")), &g_Config.ESP->HealthBar);
						Custom::CheckBox(Lang(xorstr("Armor Bar"), xorstr("Barra de Colete")), &g_Config.ESP->ArmorBar);
						Custom::CheckBox(Lang(xorstr("SnapLines"), xorstr("Linhas")), &g_Config.ESP->SnapLines);
						Custom::CheckBox(Lang(xorstr("Show LocalPlayer"), xorstr("Mostrar Proprio Player")), &g_Config.ESP->ShowLocalPlayer);
						ImGui::SameLine(); ImGui::TextDisabled("(?)"); if (ImGui::IsItemHovered()) ImGui::SetTooltip(Lang("Shows ESP on your own character.\nUseful for testing ESP settings.", "Mostra o ESP no seu proprio personagem.\nUtil para testar configuracoes do ESP."));
						Custom::CheckBox(Lang(xorstr("Ignore Dead"), xorstr("Ignorar Mortos")), &g_Config.ESP->IgnoreDead);
						ImGui::SameLine(); ImGui::TextDisabled("(?)"); if (ImGui::IsItemHovered()) ImGui::SetTooltip(Lang("Hides dead players from ESP.\nReduces clutter on screen.", "Esconde jogadores mortos do ESP.\nReduz a poluicao na tela."));
						Custom::CheckBox(Lang(xorstr("Ignore NPCs"), xorstr("Ignorar NPCs")), &g_Config.ESP->IgnoreNPCs);
						ImGui::Spacing();
						Custom::SliderInt(Lang(xorstr("Max Distance"), xorstr("Distancia Maxima")), &g_Config.ESP->MaxDistance, 0, 1000, xorstr("%dm"), 0);
					}
					ImGui::EndChild();
				}
				ImGui::EndGroup();
				ImGui::SameLine(0, 15);

				// === RIGHT COLUMN: Preview ===
				ImGui::BeginGroup();
				{
					ImGui::BeginChild(xorstr("Preview"), ImVec2(colW, 0), false, ImGuiWindowFlags_NoScrollbar);
					{
						Custom::g_EspPreview.DragDropHandler();
						Custom::g_EspPreview.Draw();
					}
					ImGui::EndChild();
				}
				ImGui::EndGroup();
			}
			break;
			case 1: //Vehicles
				ImGui::BeginGroup( );
				{
					ImGui::BeginChild( xorstr( "Globals" ), ImVec2( 230, 400 ), false, 0 );
					{
						Custom::CheckBox( Lang(xorstr( "Toggle" ), xorstr("Ativar")), &g_Config.VehicleESP->Enabled );
						Custom::CheckBox( Lang(xorstr( "Vehicle Names" ), xorstr("Nomes dos Veiculos")), &g_Config.VehicleESP->VehName );
						Custom::CheckBox( Lang(xorstr( "Locked/Unlocked" ), xorstr("Trancado/Destrancado")), &g_Config.VehicleESP->ShowLockUnlock );
						Custom::CheckBox( Lang(xorstr( "SnapLines" ), xorstr("Linhas")), &g_Config.VehicleESP->SnapLines );
						Custom::CheckBox( Lang(xorstr( "Distance" ), xorstr("Distancia")), &g_Config.VehicleESP->DistanceFromMe );
					}
					ImGui::EndChild( );
				}
				ImGui::EndGroup( );
				ImGui::SameLine( );
				ImGui::BeginGroup( );
				{
					ImGui::BeginChild( xorstr( "Settings" ), ImVec2( 230, 400 ), false, 0 );
					{
						Custom::SliderInt( Lang(xorstr( "Max Distance" ), xorstr("Distancia Maxima")), &g_Config.VehicleESP->MaxDistance, 0, 1000, xorstr( "%dm" ), 0 );
					}
					ImGui::EndChild( );
				}
				ImGui::EndGroup( );
				break;
			case 2: // Admin
				ImGui::BeginGroup();
				{
					ImGui::BeginChild(xorstr("AdminGlobals"), ImVec2(230, 400), false, 0);
					{
						Custom::CheckBox(Lang(xorstr("Admin List"), xorstr("Lista Admin")), &g_Config.ESP->AdminList);
						ImGui::SameLine(); ImGui::TextDisabled("(?)"); if (ImGui::IsItemHovered()) ImGui::SetTooltip(Lang("Shows a list of invisible players near you.", "Mostra uma lista de jogadores invisiveis proximos a voce."));
						Custom::CheckBox(Lang(xorstr("Admin Skeleton"), xorstr("Esqueleto Admin")), &g_Config.ESP->AdminSkeleton);
						Custom::CheckBox(Lang(xorstr("Admin Lines"), xorstr("Linhas Admin")), &g_Config.ESP->AdminLines);
					}
					ImGui::EndChild();
				}
				ImGui::EndGroup();
				ImGui::SameLine();
				ImGui::BeginGroup();
				{
					ImGui::BeginChild(xorstr("AdminSettings"), ImVec2(230, 400), false, 0);
					{
						Custom::SliderInt(Lang(xorstr("Max Distance"), xorstr("Distancia Maxima")), &g_Config.ESP->AdminDistance, 0, 1000, xorstr("%dm"), 0);
					}
					ImGui::EndChild();
				}
				ImGui::EndGroup();
				break;
			case 3: //Colors
				ImGui::BeginGroup();
				{
					ImGui::BeginChild(xorstr("Colors"), ImVec2(480, 400), false, 0);
					{
						static float box_col[4] = { g_Config.ESP->BoxCol.Value.x, g_Config.ESP->BoxCol.Value.y, g_Config.ESP->BoxCol.Value.z,g_Config.ESP->BoxCol.Value.w };
						if (ImGui::ColorEdit4(Lang(xorstr("Box"), xorstr("Caixa")), box_col, ImGuiColorEditFlags_AlphaBar))
						{
							g_Config.ESP->BoxCol.Value.x = box_col[0];
							g_Config.ESP->BoxCol.Value.y = box_col[1];
							g_Config.ESP->BoxCol.Value.z = box_col[2];
							g_Config.ESP->BoxCol.Value.w = box_col[3];
						}

						static float filled_box_col[4] = { g_Config.ESP->FilledBoxCol.Value.x, g_Config.ESP->FilledBoxCol.Value.y, g_Config.ESP->FilledBoxCol.Value.z,g_Config.ESP->FilledBoxCol.Value.w };
						if (ImGui::ColorEdit4(Lang(xorstr("Filled Box"), xorstr("Caixa Preenchida")), filled_box_col, ImGuiColorEditFlags_AlphaBar))
						{
							g_Config.ESP->FilledBoxCol.Value.x = filled_box_col[0];
							g_Config.ESP->FilledBoxCol.Value.y = filled_box_col[1];
							g_Config.ESP->FilledBoxCol.Value.z = filled_box_col[2];
							g_Config.ESP->FilledBoxCol.Value.w = filled_box_col[3];
						}

						static float skeleton_col[4] = { g_Config.ESP->SkeletonCol.Value.x, g_Config.ESP->SkeletonCol.Value.y, g_Config.ESP->SkeletonCol.Value.z,g_Config.ESP->SkeletonCol.Value.w };
						if (ImGui::ColorEdit4(Lang(xorstr("Skeleton"), xorstr("Esqueleto")), skeleton_col, ImGuiColorEditFlags_AlphaBar))
						{
							g_Config.ESP->SkeletonCol.Value.x = skeleton_col[0];
							g_Config.ESP->SkeletonCol.Value.y = skeleton_col[1];
							g_Config.ESP->SkeletonCol.Value.z = skeleton_col[2];
							g_Config.ESP->SkeletonCol.Value.w = skeleton_col[3];
						}

						static float lines_col[4] = { g_Config.ESP->SnapLinesCol.Value.x, g_Config.ESP->SnapLinesCol.Value.y, g_Config.ESP->SnapLinesCol.Value.z,g_Config.ESP->SnapLinesCol.Value.w };
						if (ImGui::ColorEdit4(Lang(xorstr("SnapLines"), xorstr("Linhas")), lines_col, ImGuiColorEditFlags_AlphaBar))
						{
							g_Config.ESP->SnapLinesCol.Value.x = lines_col[0];
							g_Config.ESP->SnapLinesCol.Value.y = lines_col[1];
							g_Config.ESP->SnapLinesCol.Value.z = lines_col[2];
							g_Config.ESP->SnapLinesCol.Value.w = lines_col[3];
						}

						static float names_col[4] = { g_Config.ESP->UserNamesCol.Value.x, g_Config.ESP->UserNamesCol.Value.y, g_Config.ESP->UserNamesCol.Value.z,g_Config.ESP->UserNamesCol.Value.w };
						if (ImGui::ColorEdit4(Lang(xorstr("Names"), xorstr("Nomes")), names_col, ImGuiColorEditFlags_AlphaBar))
						{
							g_Config.ESP->UserNamesCol.Value.x = names_col[0];
							g_Config.ESP->UserNamesCol.Value.y = names_col[1];
							g_Config.ESP->UserNamesCol.Value.z = names_col[2];
							g_Config.ESP->UserNamesCol.Value.w = names_col[3];
						}

						static float weapon_names_col[4] = { g_Config.ESP->WeaponNameCol.Value.x, g_Config.ESP->WeaponNameCol.Value.y, g_Config.ESP->WeaponNameCol.Value.z,g_Config.ESP->WeaponNameCol.Value.w };
						if (ImGui::ColorEdit4(Lang(xorstr("Weapon Names"), xorstr("Nomes das Armas")), weapon_names_col, ImGuiColorEditFlags_AlphaBar))
						{
							g_Config.ESP->WeaponNameCol.Value.x = weapon_names_col[0];
							g_Config.ESP->WeaponNameCol.Value.y = weapon_names_col[1];
							g_Config.ESP->WeaponNameCol.Value.z = weapon_names_col[2];
							g_Config.ESP->WeaponNameCol.Value.w = weapon_names_col[3];
						}

						static float dist_col[4] = { g_Config.ESP->DistanceCol.Value.x, g_Config.ESP->DistanceCol.Value.y, g_Config.ESP->DistanceCol.Value.z,g_Config.ESP->DistanceCol.Value.w };
						if (ImGui::ColorEdit4(Lang(xorstr("Distance"), xorstr("Distancia")), dist_col, ImGuiColorEditFlags_AlphaBar))
						{
							g_Config.ESP->DistanceCol.Value.x = dist_col[0];
							g_Config.ESP->DistanceCol.Value.y = dist_col[1];
							g_Config.ESP->DistanceCol.Value.z = dist_col[2];
							g_Config.ESP->DistanceCol.Value.w = dist_col[3];
						}
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
