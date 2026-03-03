#pragma once
#include "../imgui/imgui.h"
#include <algorithm>

namespace Utils {
    // Calculate text size with custom font
    inline ImVec2 CalcTextSize(ImFont* font, float size, const char* label) {
        if (!font) return ImGui::CalcTextSize(label);
        return font->CalcTextSizeA(size, FLT_MAX, 0, label);
    }
    
    // String to lowercase
    inline std::string StringToLowerCase(std::string Input) {
        std::transform(Input.begin(), Input.end(), Input.begin(), 
            [](unsigned char c) { return std::tolower(c); });
        return Input;
    }
    
    //  String to first uppercase
    inline std::string StringToFirstUpperCase(std::string Input) {
        if (!Input.empty()) {
            Input[0] = std::toupper(Input[0]);
            std::transform(Input.begin() + 1, Input.end(), Input.begin() + 1,
                [](unsigned char c) { return std::tolower(c); });
        }
        return Input;
    }
}
