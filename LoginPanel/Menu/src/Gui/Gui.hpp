#pragma once
#include <Includes/Includes.hpp>

#include <vector>
#include <string>
#include <algorithm>

namespace Gui {

	void Rendering();
	inline DWORD ImGuiWindowFlags = ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar;

}

// Galaxy functions
void DrawGalaxyBackground(ImDrawList* draw_list, ImVec2 pos, ImVec2 size, float time);
void InitializeGalaxyStars();
void ApplyTheme(Theme theme);