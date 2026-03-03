#pragma once

#define IMGUI_DEFINE_MATH_OPERATORS
#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "Utils.hpp"
#include "FontAwesome.hpp"
#include "Globals.hpp"
#include <map>

namespace Custom {

    using namespace ImGui;

    // Smooth easing function for animations
    inline double EaseInOutCirc(double t) {
        if (t < 0.5)
            return (1 - std::sqrt(1 - 2 * t)) * 0.5;
        else
            return (1 + std::sqrt(2 * t - 1)) * 0.5;
    }

    // Custom Button with Wexize style
    inline bool Button(const char* label, const ImVec2& size_arg = ImVec2(0, 0)) {
        struct ButtonAnim {
            float hoverAnim = 0.f;
            float activeAnim = 0.f;
        };

        ImGuiWindow* window = GetCurrentWindow();
        if (window->SkipItems)
            return false;

        ImGuiContext& g = *GImGui;
        const ImGuiStyle& style = g.Style;
        const ImGuiID id = window->GetID(label);
        const ImVec2 label_size = CalcTextSize(label, NULL, true);

        static std::map<ImGuiID, ButtonAnim> anim;
        auto it_anim = anim.find(id);
        if (it_anim == anim.end()) {
            anim.insert({ id, ButtonAnim() });
            it_anim = anim.find(id);
        }

        ImVec2 pos = window->DC.CursorPos;
        ImVec2 size = CalcItemSize(size_arg, label_size.x + style.FramePadding.x * 2.0f, label_size.y + style.FramePadding.y * 2.0f);

        const ImRect bb(pos, ImVec2(pos.x + size.x, pos.y + size.y));
        ItemSize(size, style.FramePadding.y);
        if (!ItemAdd(bb, id))
            return false;

        bool hovered, held;
        bool pressed = ButtonBehavior(bb, id, &hovered, &held);

        // Animations
        it_anim->second.hoverAnim = ImLerp(it_anim->second.hoverAnim, hovered ? 1.f : 0.f, g.IO.DeltaTime * 8.f);
        it_anim->second.activeAnim = ImLerp(it_anim->second.activeAnim, held ? size.y : 0.f, g.IO.DeltaTime * 12.f);

        // Colors
        ImU32 bg_col = GetColorU32(ImVec4(0.07f, 0.07f, 0.08f, 1.0f));
        ImU32 border_col = GetColorU32(ImLerp(ImVec4(0.09f, 0.09f, 0.10f, 1.0f), g_Col.Base, it_anim->second.hoverAnim));

        // Render
        window->DrawList->AddRectFilled(bb.Min, bb.Max, bg_col, 12.f);
        window->DrawList->AddRect(bb.Min, bb.Max, border_col, 12.f);

        // Active bar
        if (it_anim->second.activeAnim > 0.1f) {
            window->DrawList->AddRectFilled(
                ImVec2(bb.Min.x, bb.Max.y - it_anim->second.activeAnim),
                bb.Max,
                GetColorU32(ImVec4(g_Col.Base.x, g_Col.Base.y, g_Col.Base.z, 0.3f)),
                12.f
            );
        }

        // Text
        ImVec4 text_col = ImLerp(ImVec4(0.55f, 0.55f, 0.55f, 1.0f), ImVec4(0.85f, 0.85f, 0.85f, 1.0f), it_anim->second.hoverAnim);
        PushStyleColor(ImGuiCol_Text, text_col);
        RenderTextClipped(bb.Min + style.FramePadding, bb.Max - style.FramePadding, label, NULL, &label_size, style.ButtonTextAlign, &bb);
        PopStyleColor();

        return pressed;
    }

    // Custom Checkbox with Wexize style
    inline bool CheckBox(const char* label, bool* v) {
        struct CheckBoxAnim {
            ImVec4 bgColor = ImVec4(0.07f, 0.07f, 0.08f, 1.0f);
            ImVec4 checkColor = ImVec4(0.07f, 0.07f, 0.08f, 0.0f);
            float checkScale = 0.f;
        };

        ImGuiWindow* window = GetCurrentWindow();
        if (window->SkipItems)
            return false;

        ImGuiContext& g = *GImGui;
        const ImGuiStyle& style = g.Style;
        const ImGuiID id = window->GetID(label);
        const ImVec2 label_size = CalcTextSize(label, NULL, true);

        static std::map<ImGuiID, CheckBoxAnim> anim;
        auto it_anim = anim.find(id);
        if (it_anim == anim.end()) {
            anim.insert({ id, CheckBoxAnim() });
            it_anim = anim.find(id);
        }

        const float square_sz = GetFrameHeight();
        const ImVec2 pos = window->DC.CursorPos;
        const ImRect total_bb(pos, ImVec2(pos.x + square_sz + (label_size.x > 0.0f ? style.ItemInnerSpacing.x + label_size.x : 0.0f), pos.y + label_size.y + style.FramePadding.y * 2.0f));
        ItemSize(total_bb, style.FramePadding.y);
        if (!ItemAdd(total_bb, id))
            return false;

        bool hovered, held;
        bool pressed = ButtonBehavior(total_bb, id, &hovered, &held);
        if (pressed) {
            *v = !(*v);
            MarkItemEdited(id);
        }

        // Animations
        it_anim->second.bgColor = ImLerp(it_anim->second.bgColor, *v ? g_Col.Base : (hovered ? ImVec4(0.09f, 0.09f, 0.10f, 1.0f) : ImVec4(0.07f, 0.07f, 0.08f, 1.0f)), g.IO.DeltaTime * 10.f);
        it_anim->second.checkScale = ImLerp(it_anim->second.checkScale, *v ? 1.f : 0.f, g.IO.DeltaTime * 12.f);
        it_anim->second.checkColor = ImLerp(it_anim->second.checkColor, *v ? ImVec4(0.08f, 0.08f, 0.09f, 1.0f) : ImVec4(0.08f, 0.08f, 0.09f, 0.0f), g.IO.DeltaTime * 10.f);

        const ImRect check_bb(pos, ImVec2(pos.x + square_sz, pos.y + square_sz));

        // Render checkbox
        window->DrawList->AddRectFilled(check_bb.Min, check_bb.Max, GetColorU32(ImVec4(0.07f, 0.07f, 0.08f, 1.0f)), 12.f);
        window->DrawList->AddRect(check_bb.Min, check_bb.Max, GetColorU32(ImVec4(0.10f, 0.10f, 0.11f, 1.0f)), 12.f);

        if (it_anim->second.checkScale > 0.01f) {
            const float pad = ImMax(1.0f, (float)(int)(square_sz / 6.0f));
            const float scale = it_anim->second.checkScale;
            window->DrawList->AddRectFilled(
                ImVec2(check_bb.Min.x + pad * (1.f - scale), check_bb.Min.y + pad * (1.f - scale)),
                ImVec2(check_bb.Max.x - pad * (1.f - scale), check_bb.Max.y - pad * (1.f - scale)),
                GetColorU32(it_anim->second.bgColor),
                3.f
            );

            // Check mark
            if (scale > 0.5f) {
                const float check_sz = square_sz * 0.4f;
                const float check_thick = ImMax(1.0f, square_sz / 8.0f);
                const ImVec2 center = ImVec2((check_bb.Min.x + check_bb.Max.x) * 0.5f, (check_bb.Min.y + check_bb.Max.y) * 0.5f);

                window->DrawList->PathLineTo(ImVec2(center.x - check_sz * 0.3f, center.y));
                window->DrawList->PathLineTo(ImVec2(center.x - check_sz * 0.1f, center.y + check_sz * 0.3f));
                window->DrawList->PathLineTo(ImVec2(center.x + check_sz * 0.4f, center.y - check_sz * 0.4f));
                window->DrawList->PathStroke(GetColorU32(it_anim->second.checkColor), false, check_thick);
            }
        }

        // Label
        if (label_size.x > 0.0f) {
            ImVec4 label_col = ImLerp(ImVec4(0.40f, 0.40f, 0.40f, 1.0f), ImVec4(0.55f, 0.55f, 0.55f, 1.0f), *v ? 1.f : 0.f);
            window->DrawList->AddText(ImVec2(check_bb.Max.x + style.ItemInnerSpacing.x, pos.y + style.FramePadding.y), GetColorU32(label_col), label);
        }

        return pressed;
    }

    // Text centered helper
    inline void TextCentered(const char* text) {
        ImVec2 textSize = CalcTextSize(text);
        float windowWidth = GetWindowSize().x;
        float textX = (windowWidth - textSize.x) * 0.5f;
        if (textX > 0) SetCursorPosX(textX);
        Text(text);
    }

} // namespace Custom
