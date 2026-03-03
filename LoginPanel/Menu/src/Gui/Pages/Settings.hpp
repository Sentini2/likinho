#pragma once
#include <Includes/Includes.hpp>
#include <windows.h>
#include <iostream>
#include <thread>

using namespace std;

namespace Settings {

	static int iSubTabCount = 0;
	static float SubTabAlpha = 0.f;
	static int iSubTab = 0;


	void Render( ) {

		if ( Custom::SubTab( Lang(xorstr( "Main###sub_main" ), xorstr("Principal###sub_main")), 0 == iSubTabCount ) ) {
			iSubTabCount = 0;
		}
		ImGui::SameLine( 0, 15 );
		if ( Custom::SubTab( Lang(xorstr( "Configs###sub_cfg" ), xorstr("Configuracoes###sub_cfg")), 1 == iSubTabCount ) ) {
			iSubTabCount = 1;
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
			case 0: //Settings
				ImGui::BeginGroup( );
				{
					float availW = ImGui::GetContentRegionAvail().x;
					float colW = (availW - 20) * 0.5f;

					// --- LEFT COLUMN ---
					ImGui::BeginGroup();
					{
						ImGui::BeginChild( Lang(xorstr( "Globals" ), xorstr("Gerais")), ImVec2( colW, 0 ), false, 0 );
						{
							Custom::CheckBox( xorstr( "VSync" ), &g_Config.General->VSync );
							ImGui::SameLine(); ImGui::TextDisabled("(?)"); if (ImGui::IsItemHovered()) ImGui::SetTooltip(Lang("Limits FPS to monitor refresh rate.\nReduces tearing and GPU usage.", "Limita o FPS à taxa de atualização do monitor.\nReduz screen tearing e uso de GPU."));
							
							if ( Custom::CheckBox( xorstr( "Stream Proof" ), &g_Config.General->StreamProof ) )
							{
								if ( g_Config.General->StreamProof )
								{
									SetWindowDisplayAffinity( g_Variables.g_hCheatWindow, WDA_EXCLUDEFROMCAPTURE );
								}
								else
								{
									SetWindowDisplayAffinity( g_Variables.g_hCheatWindow, WDA_NONE );
								}
							}
							ImGui::SameLine(); ImGui::TextDisabled("(?)"); if (ImGui::IsItemHovered()) ImGui::SetTooltip(Lang("Hides the overlay from screenshots\nand screen recordings.", "Esconde o menu de capturas de tela\ne gravações."));

							static int KeyMode = 1;
							ImGui::Keybind( Lang(xorstr( "Menu Key" ), xorstr("Tecla do Menu")), &g_Config.General->MenuKey, &KeyMode );
							ImGui::SameLine(); ImGui::TextDisabled("(?)"); if (ImGui::IsItemHovered()) ImGui::SetTooltip(Lang("Key to open/close this menu.\nDefault: INSERT", "Tecla para abrir/fechar este menu.\nPadrão: INSERT"));

							ImGui::Spacing();
							ImGui::Spacing();
							ImGui::Separator();
							ImGui::Spacing();
						}
						ImGui::EndChild();
					}
					ImGui::EndGroup();
					
					ImGui::SameLine(0, 20);

					// --- RIGHT COLUMN ---
					ImGui::BeginGroup();
					{
						ImGui::BeginChild( Lang(xorstr( "Appearance" ), xorstr("Aparencia")), ImVec2( colW, 0 ), false, 0 );
						{
							// === LANGUAGE SELECTOR ===
							ImGui::Spacing();
							ImGui::TextColored(g_Col.PrimaryText, Lang("Language:", "Idioma:"));
							ImGui::SetNextItemWidth(180.f);
							const char* langItems[] = { "English", "Português" };
							ImGui::PushID("lang_combo");
							ImGui::Combo("", &g_Language, langItems, IM_ARRAYSIZE(langItems));
							ImGui::PopID();
							ImGui::SameLine(); ImGui::TextDisabled("(?)"); if (ImGui::IsItemHovered()) ImGui::SetTooltip(Lang("Changes the menu language.", "Muda o idioma do menu."));

							// === THEME SELECTOR (DROPDOWN) ===
							ImGui::Spacing();
							ImGui::TextColored(g_Col.PrimaryText, Lang("Theme:", "Tema:"));
							ImGui::SetNextItemWidth(180.f);
							int currentThemeIdx = (int)currentTheme;
							const char* themeItems[] = { "LiKinho", "Nippy", "No Animations" };


							ImGui::PushID("theme_combo");
							if (ImGui::Combo("", &currentThemeIdx, themeItems, IM_ARRAYSIZE(themeItems))) {
								Theme newThm = (Theme)currentThemeIdx;
								if (newThm != currentTheme) {
									::ApplyTheme(newThm);
								}
							}
							ImGui::PopID();
							ImGui::SameLine(); ImGui::TextDisabled("(?)"); if (ImGui::IsItemHovered()) ImGui::SetTooltip(Lang("Changes the menu accent color and effects.\nNo Animations = plain black background.", "Muda a cor de destaque e os efeitos do menu.\nSem Animações = fundo preto simples."));

							// === CUSTOM COLOR PICKER ===
							ImGui::Spacing();
							{
								if (ImGui::Button(Lang("Custom Color", "Cor Personalizada"), ImVec2(150, 24)))
									ImGui::OpenPopup("##custom_color_popup");

								// Force popup to appear ABOVE the button so it doesn't get clipped
								ImVec2 btnPos = ImGui::GetItemRectMin();
								ImGui::SetNextWindowPos(ImVec2(btnPos.x, btnPos.y - 200.f), ImGuiCond_Always);
								ImGui::SetNextWindowSize(ImVec2(200.f, 200.f), ImGuiCond_Always);
								ImGui::SetNextWindowBgAlpha(0.95f);

								if (ImGui::BeginPopup("##custom_color_popup", ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoTitleBar))
								{
									float col3[3] = { activeTheme.primary.x, activeTheme.primary.y, activeTheme.primary.z };
									ImGui::SetNextItemWidth(180.f);
									ImGui::PushID("cp");
									if (ImGui::ColorPicker3("", col3,
										ImGuiColorEditFlags_PickerHueBar |
										ImGuiColorEditFlags_NoSidePreview |
										ImGuiColorEditFlags_NoSmallPreview |
										ImGuiColorEditFlags_NoLabel))
									{
										activeTheme.primary   = ImVec4(col3[0], col3[1], col3[2], 1.0f);
										activeTheme.secondary = ImVec4(col3[0] * 0.85f, col3[1] * 0.85f, col3[2] * 0.85f, 1.0f);
										activeTheme.accent    = ImVec4(col3[0], col3[1], col3[2], 1.0f);
										g_Col.Base            = ImVec4(col3[0], col3[1], col3[2], 1.0f);
										for (auto& star : galaxyStars)
											star.color = ImVec4(col3[0], col3[1], col3[2], star.color.w);
									}
									ImGui::PopID();
									ImGui::EndPopup();
								}
							}
						}

						ImGui::EndChild( );
					}
					ImGui::EndGroup( );
				}
				ImGui::EndGroup( );
				break;
			case 1: // Configs
				ImGui::BeginGroup( );
				{
					float availW = ImGui::GetContentRegionAvail().x;
					float colW = (availW - 20) * 0.5f;

					ImGui::BeginGroup();
					{
						ImGui::BeginChild( Lang(xorstr( "Save" ), xorstr("Salvar")), ImVec2( colW, 0 ), false, 0 );
						{
							static char configName[64] = "default";
							ImGui::TextColored(g_Col.PrimaryText, Lang("Config Name:", "Nome da Config:"));
							ImGui::SetNextItemWidth(colW - 15);
							ImGui::PushID("configname");
							ImGui::InputText("", configName, IM_ARRAYSIZE(configName));
							ImGui::PopID();
							ImGui::Spacing();
							if (ImGui::Button(Lang("Save Config", "Salvar Config"), ImVec2(colW - 15, 30))) {
								Core::g_Config.SaveConfigFile(configName, g_Language, (int)currentTheme);
							}
						}
						ImGui::EndChild();
					}
					ImGui::EndGroup();

					ImGui::SameLine(0, 20);

					ImGui::BeginGroup();
					{
						ImGui::BeginChild( Lang(xorstr( "Load" ), xorstr("Carregar")), ImVec2( colW, 0 ), false, 0 );
						{
							static std::vector<std::string> configs;
							static int selectedConfig = 0;
							
							static bool initConfigs = false;
							if (!initConfigs) {
								configs.clear();
								try {
									if (std::filesystem::exists("cfg") && std::filesystem::is_directory("cfg")) {
										for (const auto& entry : std::filesystem::directory_iterator("cfg")) {
											if (entry.is_regular_file() && entry.path().extension() == ".json") {
												configs.push_back(entry.path().stem().string());
											}
										}
									}
								} catch (...) {}
								initConfigs = true;
							}

							if (ImGui::Button(Lang("Refresh Configs", "Atualizar Lista"), ImVec2(colW - 15, 30))) {
								initConfigs = false; // Trigger refresh
								selectedConfig = 0;
							}
							ImGui::Spacing();
							if (ImGui::Button(Lang("Clear All Configs", "Limpar Todas as Configs"), ImVec2(colW - 15, 30))) {
								ImGui::OpenPopup(Lang("Clear All", "Limpar Tudo"));
							}

							if (ImGui::BeginPopupModal(Lang("Clear All", "Limpar Tudo"), NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
								ImGui::Text(Lang("Are you sure you want to delete ALL configs?", "Tem certeza que deseja apagar TODAS as configuracoes?"));
								ImGui::Spacing();
								if (ImGui::Button(Lang("Yes", "Sim"), ImVec2(120, 0))) {
									try {
										if (std::filesystem::exists("cfg") && std::filesystem::is_directory("cfg")) {
											std::vector<std::filesystem::path> pathsToDelete;
											for (const auto& entry : std::filesystem::directory_iterator("cfg")) {
												if (entry.is_regular_file() && entry.path().extension() == ".json") {
													pathsToDelete.push_back(entry.path());
												}
											}
											for (const auto& p : pathsToDelete) {
												std::filesystem::remove(p);
											}
										}
									} catch (...) {}
									initConfigs = false; // Refresh
									selectedConfig = 0;
									ImGui::CloseCurrentPopup();
								}
								ImGui::SameLine();
								if (ImGui::Button(Lang("No", "Nao"), ImVec2(120, 0))) {
									ImGui::CloseCurrentPopup();
								}
								ImGui::EndPopup();
							}

							ImGui::Spacing();
							std::vector<const char*> configCstrs;
							for (const auto& str : configs) {
								configCstrs.push_back(str.c_str());
							}
							ImGui::SetNextItemWidth(colW - 40);
							ImGui::PushID("configs_combo");
							const char* empty_item = "Nenhuma/Vazio";
							if (configCstrs.empty()) {
								ImGui::Combo("", &selectedConfig, &empty_item, 1);
							} else {
								ImGui::Combo("", &selectedConfig, configCstrs.data(), (int)configCstrs.size());
							}
							ImGui::PopID();

							ImGui::SameLine(0, 5);
							if (ImGui::Button("\xEF\x80\x94", ImVec2(20, 20))) { // FA_TRASH
								if (!configs.empty() && selectedConfig >= 0 && selectedConfig < configs.size()) {
									ImGui::OpenPopup(Lang("Delete Config", "Apagar Config"));
								}
							}

							if (ImGui::BeginPopupModal(Lang("Delete Config", "Apagar Config"), NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
								ImGui::Text(Lang("Are you sure you want to delete this config?", "Tem certeza que deseja apagar essa configuracao?"));
								ImGui::Spacing();
								if (ImGui::Button(Lang("Yes", "Sim"), ImVec2(120, 0))) {
									std::string filePath = "cfg\\" + configs[selectedConfig] + ".json";
									if (std::filesystem::exists(filePath)) {
										std::filesystem::remove(filePath);
									}
									initConfigs = false; // Refresh
									ImGui::CloseCurrentPopup();
								}
								ImGui::SameLine();
								if (ImGui::Button(Lang("No", "Nao"), ImVec2(120, 0))) {
									ImGui::CloseCurrentPopup();
								}
								ImGui::EndPopup();
							}

							ImGui::Spacing();
							if (ImGui::Button(Lang("Load Config", "Carregar Config"), ImVec2(colW - 15, 30))) {
								if (selectedConfig >= 0 && selectedConfig < configs.size()) {
									int loadedLang = g_Language;
									int loadedTheme = (int)currentTheme;
									Core::g_Config.LoadConfigFile(configs[selectedConfig], loadedLang, loadedTheme);
									g_Language = loadedLang;
									Theme newThm = (Theme)loadedTheme;
									if (newThm != currentTheme) {
										::ApplyTheme(newThm);
									}
								}
							}
						}
						ImGui::EndChild();
					}
					ImGui::EndGroup();
				}
				ImGui::EndGroup( );
				break;
			default:
				break;
			}

		}
		ImGui::EndGroup( );

		ImGui::PopStyleVar( );
	}
}

