#pragma once
#include <Globals.hpp>

namespace Premium {

	inline void Render()
	{
		// Don't render if menu is not open
		if (!g_MenuInfo.IsOpen) return;

		static float pulse = 0.0f;
		pulse += ImGui::GetIO().DeltaTime * 2.0f;

		// Match Settings page layout - compact card
		ImVec2 startPos = ImGui::GetCursorScreenPos();
		startPos.x += 20;
		startPos.y += 10;

		ImDrawList* dl = ImGui::GetWindowDrawList();

		// Check if user has menu key
		if (g_MenuInfo.HasMenuKey) {
			// === COMPACT CARD - Same size as Settings options ===
			ImVec2 cardMin = startPos;
			ImVec2 cardMax = ImVec2(startPos.x + 240, startPos.y + 90);
			dl->AddRectFilled(cardMin, cardMax, IM_COL32(20, 20, 25, 240), 6.0f);
			dl->AddRect(cardMin, cardMax, ImGui::ColorConvertFloat4ToU32(ImVec4(g_Col.Base.x * 0.3f, g_Col.Base.y * 0.3f, g_Col.Base.z * 0.3f, 0.6f)), 6.0f, 0, 1.5f);

			// === STAR ICON ===
			dl->AddText(g_Variables.FontAwesomeSolid, g_Variables.FontAwesomeSolid->FontSize * 1.2f,
				ImVec2(startPos.x + 15, startPos.y + 12),
				ImGui::ColorConvertFloat4ToU32(g_Col.Base), ICON_FA_STAR);

			// === TITLE ===
			dl->AddText(g_Variables.m_FontNormal, g_Variables.m_FontNormal->FontSize,
				ImVec2(startPos.x + 45, startPos.y + 12),
				IM_COL32(240, 240, 240, 255), "LiKinho Menu");

			// === DESCRIPTION ===
			dl->AddText(g_Variables.m_FontNormal, g_Variables.m_FontNormal->FontSize * 0.85f,
				ImVec2(startPos.x + 15, startPos.y + 38),
				IM_COL32(130, 130, 130, 255), Lang("Premium Lua executor", "Executor Lua Premium"));

			// === LOAD BUTTON ===
			ImGui::SetCursorScreenPos(ImVec2(startPos.x + 15, startPos.y + 58));
			
			float btnPulse = 0.8f + sinf(pulse) * 0.1f;
			ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 5.0f);
			ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(g_Col.Base.x * btnPulse, g_Col.Base.y * btnPulse, g_Col.Base.z * btnPulse, 0.9f));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(g_Col.Base.x * 1.2f, g_Col.Base.y * 1.2f, g_Col.Base.z * 1.2f, 1.0f));
			ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(g_Col.Base.x * 0.6f, g_Col.Base.y * 0.6f, g_Col.Base.z * 0.6f, 1.0f));
			ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));

			if (ImGui::Button(Lang("LOAD", "CARREGAR"), ImVec2(80, 24)))
			{
				// TODO: Load action
			}

			ImGui::PopStyleColor(4);
			ImGui::PopStyleVar();

			dl->AddText(g_Variables.m_FontNormal, g_Variables.m_FontNormal->FontSize * 0.8f,
				ImVec2(startPos.x + 185, startPos.y + 64),
				ImGui::ColorConvertFloat4ToU32(ImVec4(g_Col.Base.x * 0.7f, g_Col.Base.y * 0.7f, g_Col.Base.z * 0.7f, 1.0f)), Lang("Never", "Nunca"));
		}
		else 
		{
			// Show "Nothing here" centered
			const char* text = Lang("Nothing here", "Nada aqui");
			ImVec2 txtSz = g_Variables.m_FontNormal->CalcTextSizeA(g_Variables.m_FontNormal->FontSize, FLT_MAX, 0, text);
			
			// Center in the available space (roughly)
			ImVec2 centerPos = ImVec2(startPos.x + 120 - txtSz.x/2, startPos.y + 45 - txtSz.y/2);
			
			dl->AddText(g_Variables.m_FontNormal, g_Variables.m_FontNormal->FontSize,
				centerPos,
				IM_COL32(150, 150, 150, 200), text);
		}
	}
}


