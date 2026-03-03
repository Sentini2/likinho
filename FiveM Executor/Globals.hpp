#pragma once
#include <string>

// Forward declarations
struct ImVec4;
struct ImVec2;
struct ImFont;

// Color system - Based on Wexize color scheme
class cColors {
public:
    ImVec4 Base = ImVec4(180.0f / 255.0f, 180.0f / 255.0f, 180.0f / 255.0f, 1.0f);  
    ImVec4 PrimaryText = ImVec4(200.0f / 255.0f, 200.0f / 255.0f, 200.0f / 255.0f, 1.0f);
    ImVec4 SecundaryText = ImVec4(80.0f / 255.0f, 80.0f / 255.0f, 80.0f / 255.0f, 1.0f);
    
    ImVec4 FeaturesText = ImVec4(140.0f / 255.0f, 140.0f / 255.0f, 140.0f / 255.0f, 1.0f);
    ImVec4 SecundaryFeaturesText = ImVec4(100.0f / 255.0f, 100.0f / 255.0f, 100.0f / 255.0f, 1.0f);
    
    ImVec4 BorderCol = ImVec4(32.0f / 255.0f, 32.0f / 255.0f, 34.0f / 255.0f, 1.0f);
    ImVec4 LinesCol = ImVec4(30.0f / 255.0f, 30.0f / 255.0f, 33.0f / 255.0f, 1.0f);
    ImVec4 BackgroundCol = ImVec4(12.0f / 255.0f, 12.0f / 255.0f, 14.0f / 255.0f, 1.0f);
    
    ImVec4 ChildCol = ImVec4(16.0f / 255.0f, 16.0f / 255.0f, 18.0f / 255.0f, 1.0f);
    ImVec4 ChildBorderCol = ImVec4(18.0f / 255.0f, 18.0f / 255.0f, 20.0f / 255.0f, 1.0f);
    
    ImVec4 TitleBar = ImVec4(15.0f / 255.0f, 15.0f / 255.0f, 18.0f / 255.0f, 1.0f);
    ImVec4 TitleBarBorder = ImVec4(21.0f / 255.0f, 21.0f / 255.0f, 24.0f / 255.0f, 1.0f);
    
    ImVec4 SideBar = ImVec4(14.0f / 255.0f, 14.0f / 255.0f, 16.0f / 255.0f, 1.0f);
    ImVec4 SideBarBorder = ImVec4(21.0f / 255.0f, 21.0f / 255.0f, 23.0f / 255.0f, 1.0f);
    
    ImVec4 ButtonHovered = ImVec4(180.0f / 255.0f, 180.0f / 255.0f, 180.0f / 255.0f, 100.0f / 255.0f);
    
    ImVec4 InputBackground = ImVec4(16.0f / 255.0f, 16.0f / 255.0f, 16.0f / 255.0f, 1.0f);
    ImVec4 InputBorder = ImVec4(22.0f / 255.0f, 22.0f / 255.0f, 22.0f / 255.0f, 1.0f);
};

// Global variables structure
class c_globals {
public:
    ImFont* m_FontNormal = nullptr;
    ImFont* m_FontSecundary = nullptr;
    ImFont* m_FontSmaller = nullptr;
    ImFont* FontAwesomeSolid = nullptr;
    
    // Additional variables for Custom widgets
    std::string UserName = "User";
    std::string Role = "Premium";
    void* Logo = nullptr;
};

// Menu info structure
class cMenuInfo {
public:
    ImVec2 MenuSize = ImVec2(800, 600);
    bool IsOpen = true;
};

// Global instances
inline cColors g_Col;
inline c_globals g_Variables;
inline cMenuInfo g_MenuInfo;
