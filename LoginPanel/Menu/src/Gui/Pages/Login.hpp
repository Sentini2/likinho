#pragma once
#include <Includes/Includes.hpp>
#include <windows.h>
#include <iostream>
#include <thread>

using namespace std;

namespace Login {

	static int iSubTabCount = 0;
	static float SubTabAlpha = 0.f;
	static int iSubTab = 0;

	ImVec2 window_center = ImVec2(g_MenuInfo.MenuSize.x * 0.5f, g_MenuInfo.MenuSize.y * 0.5f);

	void CentralizedText(const char* text, ImVec4 color, ImVec2 adjust = { 0, 0 }) {
		ImVec2 text_size = ImGui::CalcTextSize(text);
		ImGui::SetCursorPos({ window_center.x - text_size.x / 2 + adjust.x, window_center.y - text_size.y / 2 + adjust.y });
		ImU32 col_u32 = ImGui::GetColorU32(color);
		ImGui::TextColored(color, text);
	}

	void Render() {

		CentralizedText("LOG IN", g_Col.PrimaryText, { -200,0 });

		
	}
}