#pragma once
#include "imgui.h"
#include <d3d9.h>
#include <d3d11.h>

namespace menu_settings
{
	inline int tab_count = 0;
	inline float tab_alpha = 0.f;
	inline int active_tab = 0.f;
	inline float tab_add = 0.f;
	inline float line_offset = 0.f;
}

namespace colors
{
	inline ImVec4 accent = ImColor( 127, 112, 212 );

	inline ImVec4 window_background = ImColor( 12, 12, 12 );
	inline ImVec4 window_sidebar = ImColor( 15, 15, 15 );

	inline ImVec4 window_border = ImColor( 18, 18, 18 );

	inline ImVec4 child_background = ImColor( 14, 14, 14 );
	inline ImVec4 child_border = ImColor( 20, 20, 20 );
	inline ImVec4 child_label = ImColor( 180, 180, 180 );

	inline ImVec4 listbox_background = ImColor( 14, 14, 14 );
	inline ImVec4 listbox_border = ImColor( 20, 20, 20 );
	inline ImVec4 listbox_label_active = ImColor( 197, 197, 197 );
	inline ImVec4 listbox_label_inactive = ImColor( 73, 73, 73 );

	inline ImVec4 scrollbar_background = ImColor( 14, 14, 14 );
	inline ImVec4 scrollbar_background_two = ImColor( 15, 15, 15 );

	inline ImVec4 tab_icon = ImColor( 73, 73, 73 );
	inline ImVec4 subtab_col = ImColor( 20, 20, 20 );

	inline ImVec4 checkbox_label_active = ImColor( 160, 160, 160 );
	inline ImVec4 checkbox_label_inactive = ImColor( 73, 73, 73 );
	inline ImVec4 checkbox_background = ImColor( 18, 18, 18 );
	inline ImVec4 checkbox_outline = ImColor( 22, 22, 22 );

	inline ImVec4 slider_label = ImColor( 160, 160, 160 );
	inline ImVec4 slider_background = ImColor( 18, 18, 18 );
	inline ImVec4 slider_outline = ImColor( 22, 22, 22 );
	inline ImVec4 slider_circle_fadein = ImColor( 238, 238, 238 );
	inline ImVec4 slider_circle_fadeout = ImColor( 163, 163, 163 );

	inline ImVec4 combo_label = ImColor( 73, 73, 73 );
	inline ImVec4 combo_background = ImColor( 18, 18, 18 );
	inline ImVec4 combo_outline = ImColor( 22, 22, 22 );
	inline ImVec4 combo_arrow = ImColor( 73, 73, 73 );

	inline ImVec4 selectable_label_active = ImColor( 197, 197, 197 );
	inline ImVec4 selectable_label_inactive = ImColor( 73, 73, 73 );
	inline ImVec4 selectable_background = ImColor( 20, 20, 20 );
	inline ImVec4 selectable_outline = ImColor( 25, 25, 25 );

	inline ImVec4 input_label = ImColor( 73, 73, 73 );
	inline ImVec4 input_background = ImColor( 18, 18, 18 );

	inline ImVec4 button_label_active = ImColor( 197, 197, 197 );
	inline ImVec4 button_label_inactive = ImColor( 73, 73, 73 );
	inline ImVec4 button_background = ImColor( 16, 16, 16 );
	inline ImVec4 button_outline = ImColor( 21, 21, 21 );

	inline ImVec4 color_label = ImColor( 73, 73, 73 );
	inline ImVec4 color_background = ImColor( 8, 8, 8 );

	inline ImVec4 key_label = ImColor( 73, 73, 73 );
	inline ImVec4 key_background = ImColor( 20, 20, 20 );
	inline ImVec4 key_outline = ImColor( 25, 25, 25 );
}