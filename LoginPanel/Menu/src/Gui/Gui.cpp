#include "Gui.hpp"

#include <Includes/CustomWidgets/Custom.hpp>
#include <Includes/CustomWidgets/WaterMarks.hpp>
#include <Includes/CustomWidgets/Notify.hpp>

#include <Gui/Pages/Combat.hpp>
#include <Gui/Pages/Visuals.hpp>
#include <Gui/Pages/Local.hpp>
#include <Gui/Pages/Exploits.hpp>
#include <Gui/Pages/Executor.hpp>
#include <Gui/Pages/World.hpp>
#include <Gui/Pages/Settings.hpp>
#include <Gui/Pages/Login.hpp>
#include <Gui/Pages/Premium.hpp>
#include <Core/Features/Exploits/Exploits.hpp>
#include <Includes/CustomWidgets/Notify.hpp>
#include <Core/Features/Esp.hpp>

int PauseLoop;
inline std::mutex DrawMtx;

float accent_color[4] = {
136 / 255.f, // r
100 / 255.f, // g
255 / 255.f, // b
1.f          // a
};

#pragma region Animation
struct Particle
{
	ImVec2 position;
	ImVec2 velocity;
	ImVec4 color;
	float radius;
};

class ParticleSystem
{
public:
	ParticleSystem(int numParticles)
	{
		setupParticles(numParticles);
	}

	void update(float deltaTime, const ImVec2& windowPos)
	{
		this->windowPos = windowPos;

		if (!g_MenuInfo.particles) return;

		for (auto& particle : particles)
		{
			particle.position.x += particle.velocity.x * deltaTime;
			particle.position.y += particle.velocity.y * deltaTime;

			// Check if the particle is out of bounds, reset its position
			if (particle.position.x < 0 || particle.position.x > ImGui::GetWindowWidth() ||
				particle.position.y < 0 || particle.position.y > ImGui::GetWindowHeight())
			{
				resetParticle(particle);
			}
		}
	}

	void draw()
	{
		ImGuiWindow* window = ImGui::GetCurrentWindow();
		ImDrawList* drawList = window->DrawList;

		if (!g_MenuInfo.particles) return;

		// Draw particles
		for (const auto& particle : particles)
		{
			ImVec4 particleColor = ImVec4(accent_color[0], accent_color[1], accent_color[2], accent_color[3]);
			drawList->AddCircleFilled(
				ImVec2(particle.position.x + windowPos.x, particle.position.y + windowPos.y),
				particle.radius,
				ImGui::GetColorU32(particleColor));
		}

		// Draw lines connecting particles within a certain distance
		float maxDistance = 150.0f; // Maximum distance to draw a line
		for (size_t i = 0; i < particles.size(); ++i)
		{
			for (size_t j = i + 1; j < particles.size(); ++j)
			{
				float distance = std::sqrt(
					std::pow(particles[i].position.x - particles[j].position.x, 2) +
					std::pow(particles[i].position.y - particles[j].position.y, 2));

				if (distance < maxDistance)
				{
					// Fade line opacity based on distance
					float alpha = 0.5f - (distance / maxDistance);
					ImU32 lineColor = ImGui::GetColorU32(ImVec4(1.0f, 1.0f, 1.0f, alpha));
					drawList->AddLine(
						ImVec2(particles[i].position.x + windowPos.x, particles[i].position.y + windowPos.y),
						ImVec2(particles[j].position.x + windowPos.x, particles[j].position.y + windowPos.y),
						lineColor, 1.0f);
				}
			}
		}
	}

private:
	ImVec2 windowPos;
	std::vector<Particle> particles;

	void setupParticles(int numParticles)
	{
		particles.clear();

		std::random_device rd;
		std::mt19937 gen(rd());
		std::uniform_real_distribution<> disPos(0, 10);
		std::uniform_real_distribution<> disVel(-50, 50);
		std::uniform_real_distribution<> disColor(0, 1);
		std::uniform_real_distribution<> disRadius(1, 3);

		for (int i = 0; i < numParticles; ++i)
		{
			Particle particle;
			particle.position = ImVec2(disPos(gen) * ImGui::GetWindowWidth(), disPos(gen) * ImGui::GetWindowHeight());
			particle.velocity = ImVec2(disVel(gen), disVel(gen));
			particle.color = ImVec4(disColor(gen), disColor(gen), disColor(gen), 0.4f);
			particle.radius = disRadius(gen);

			particles.push_back(particle);
		}
	}

	void resetParticle(Particle& particle)
	{
		std::random_device rd;
		std::mt19937 gen(rd());
		std::uniform_real_distribution<> disPos(0, 1);
		std::uniform_real_distribution<> disVel(-50, 50);

		particle.position = ImVec2(disPos(gen) * ImGui::GetWindowWidth(), disPos(gen) * ImGui::GetWindowHeight());
		particle.velocity = ImVec2(disVel(gen), disVel(gen));
	}
};


#pragma endregion 

// ============ GALAXY THEME FUNCTIONS ============

void ::DrawGalaxyBackground(ImDrawList* draw_list, ImVec2 pos, ImVec2 size, float time)
{
	// No Animations theme: plain black, skip all galaxy effects
	if (currentTheme == Theme::NoAnim) {
		draw_list->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y), IM_COL32(8, 8, 10, 255));
		return;
	}

	// Background gradient
	draw_list->AddRectFilledMultiColor(
		pos,
		ImVec2(pos.x + size.x, pos.y + size.y),
		IM_COL32(5, 5, 10, 255),
		IM_COL32(10, 8, 15, 255),
		IM_COL32(15, 10, 20, 255),
		IM_COL32(8, 5, 12, 255)
	);

	// Animated stars
	for (auto& star : galaxyStars)
	{
		star.pos.x += star.speed * cos(time * 0.5f + star.pos.y * 0.01f);
		star.pos.y += star.speed * 0.3f;

		star.brightness = 0.3f + abs(sin(time * star.speed * 2.0f + star.pos.x * 0.01f)) * 0.7f;
		star.color.w = star.brightness;

		if (star.pos.x > pos.x + size.x + 50) star.pos.x = pos.x - 50;
		if (star.pos.x < pos.x - 50) star.pos.x = pos.x + size.x + 50;
		if (star.pos.y > pos.y + size.y + 50) star.pos.y = pos.y - 50;

		ImVec2 starPos = ImVec2(
			pos.x + fmod(star.pos.x - pos.x, size.x),
			pos.y + fmod(star.pos.y - pos.y, size.y)
		);

		ImU32 color = ImGui::ColorConvertFloat4ToU32(star.color);

		draw_list->AddCircleFilled(starPos, star.size, color, 6);

		if (star.brightness > 0.6f)
		{
			ImVec4 glowColor = star.color;
			glowColor.w *= 0.3f;
			draw_list->AddCircleFilled(starPos, star.size * 2.0f,
				ImGui::ColorConvertFloat4ToU32(glowColor), 8);
		}
	}

	// Nebulas - USE THEME COLOR (not hardcoded purple!)
	ImU32 nebulaBaseColor = ImGui::ColorConvertFloat4ToU32(activeTheme.primary);
	int nebulaR = (nebulaBaseColor >> 0) & 0xFF;
	int nebulaG = (nebulaBaseColor >> 8) & 0xFF;
	int nebulaB = (nebulaBaseColor >> 16) & 0xFF;
	
	for (int i = 0; i < 3; i++)
	{
		float nebulaX = pos.x + size.x * (0.2f + i * 0.3f);
		float nebulaY = pos.y + size.y * 0.5f + sin(time * 0.3f + i) * 100;

		for (int j = 0; j < 5; j++)
		{
			float radius = 80 + j * 30;
			float alpha = (30 - j * 5) / 255.0f;

			draw_list->AddCircleFilled(
				ImVec2(nebulaX + sin(time * 0.2f + i) * 50, nebulaY),
				radius,
				IM_COL32(nebulaR, nebulaG, nebulaB, (int)(alpha * 255)),
				32
			);
		}
	}
}

// Apply theme (Orange or Purple)
void ::ApplyTheme(Theme theme) {
	currentTheme = theme;

	if (theme == Theme::LiKinho) {
		// ORANGE THEME (DEFAULT)
		executorName = "WEXIZE EXECUTOR";
		themeDisplayName = "Orange Theme";

		// PURE ORANGE - NO purple!
		activeTheme.primary = ImVec4(1.0f, 0.5f, 0.0f, 1.0f);     // Pure orange
		activeTheme.secondary = ImVec4(1.0f, 0.6f, 0.1f, 1.0f);   // Light orange
		activeTheme.accent = ImVec4(1.0f, 0.5f, 0.0f, 1.0f);      // Orange accent

		// Update custom widget accent color
		g_Col.Base = ImVec4(1.0f, 0.5f, 0.0f, 1.0f);  // Orange for all widgets

		// Reinitialize stars with orange colors
		for (auto& star : galaxyStars) {
			int colorType = rand() % 3;
			if (colorType == 0)
				star.color = ImVec4(1.0f, 0.5f, 0.0f, star.brightness);  // Orange
			else if (colorType == 1)
				star.color = ImVec4(1.0f, 0.6f, 0.1f, star.brightness);  // Light orange
			else
				star.color = ImVec4(0.9f, 0.4f, 0.0f, star.brightness);  // Dark orange
		}
	}
	else if (theme == Theme::Nippy) {
		// NIPPY - PURPLE THEME
		executorName = "LIKINHO EXECUTOR";
		themeDisplayName = "Nippy Theme";

		activeTheme.primary   = ImVec4(0.5f,  0.0f,  1.0f,  1.0f);
		activeTheme.secondary = ImVec4(0.6f,  0.2f,  1.0f,  1.0f);
		activeTheme.accent    = ImVec4(0.5f,  0.0f,  1.0f,  1.0f);
		g_Col.Base = ImVec4(0.5f, 0.0f, 1.0f, 1.0f);

		for (auto& star : galaxyStars) {
			int colorType = rand() % 3;
			if (colorType == 0)      star.color = ImVec4(0.5f, 0.0f, 1.0f, star.brightness);
			else if (colorType == 1) star.color = ImVec4(0.6f, 0.2f, 1.0f, star.brightness);
			else                     star.color = ImVec4(0.4f, 0.0f, 0.8f, star.brightness);
		}
	}
	else {

		// NO ANIMATIONS THEME
		executorName = "LIKINHO EXECUTOR";
		themeDisplayName = "No Animations";

		activeTheme.primary   = ImVec4(0.55f, 0.55f, 0.60f, 1.0f);
		activeTheme.secondary = ImVec4(0.60f, 0.60f, 0.65f, 1.0f);
		activeTheme.accent    = ImVec4(0.55f, 0.55f, 0.60f, 1.0f);

		g_Col.Base = ImVec4(0.55f, 0.55f, 0.60f, 1.0f);
	}
}



void ::InitializeGalaxyStars()
{
	if (!galaxyStars.empty()) return;

	for (int i = 0; i < 200; i++)
	{
		Star star;
		star.pos = ImVec2((float)(rand() % 2000), (float)(rand() % 2000));
		star.size = 1.0f + (rand() % 30) / 10.0f;
		star.brightness = 0.3f + (rand() % 70) / 100.0f;
		star.speed = 0.1f + (rand() % 20) / 100.0f;
		star.color = ImVec4(1.0f, 0.6f, 0.2f, star.brightness); // Orange default
		galaxyStars.push_back(star);
	}
	
	// Apply default Orange theme
	::ApplyTheme(Theme::LiKinho);
}



void Gui::Rendering()
{
	// NO MORE ParticleSystem - removed!
	
	// Initialize galaxy once
	::InitializeGalaxyStars();
	
	// Update animation time
	animTime += 0.016f;

	if (!g_MenuInfo.IsLogged)
	{
		g_MenuInfo.MenuSize = { 500, 350 };
	}
	else
	{
		// Only set default size on first open, then user can resize
		static bool sizeInitialized = false;
		if (!sizeInitialized)
		{
			g_MenuInfo.MenuSize = { 850, 550 };
			sizeInitialized = true;
		}
	}
	
	// Allow resize with constraints
	ImGui::SetNextWindowSizeConstraints(ImVec2(800, 400), ImVec2(1400, 900));
	ImGui::SetNextWindowSize(g_MenuInfo.MenuSize, ImGuiCond_Once);

	// Smooth Open/Close Animation System (Fade + Slight Scale slide)
	static float menuAnimGlobal = g_MenuInfo.IsOpen ? 1.0f : 0.0f;
	menuAnimGlobal = ImLerp(menuAnimGlobal, g_MenuInfo.IsOpen ? 1.0f : 0.0f, ImGui::GetIO().DeltaTime * 12.0f);

	if (!PauseLoop) { ImGui::SetNextWindowPos(g_Variables.g_vGameWindowSize / 2 - g_MenuInfo.MenuSize / 2); PauseLoop++; }

	// === MODERN PILL-SHAPED DESIGN ===
	ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 15.0f);
	ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 12.0f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 12.0f); // Makes sliders & inputs round like pills
	ImGui::PushStyleVar(ImGuiStyleVar_GrabRounding, 12.0f); // Round slider grabber
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
	ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 2.0f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f); // Give clear boundary to sliders
	ImGui::PushStyleVar(ImGuiStyleVar_Alpha, menuAnimGlobal); // Global Fade-In Fade-out animation
	
	// === DARK ROUNDED WINDOW BACKGROUND ===
	ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.04f, 0.04f, 0.06f, 0.92f));  // Dark semi-transparent
	ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.1f, 0.1f, 0.1f, 0.9f));         // Subtle dark border
	ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));                     // Transparent children
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.08f, 0.08f, 0.10f, 0.8f));     // Dark frame backgrounds
	ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0.12f, 0.12f, 0.14f, 0.9f));
	ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(0.15f, 0.15f, 0.17f, 1.0f));
	
	// Remove the sliding animation since it overrides saved window positions
	// Only fade-in / fade-out using menuAnimGlobal alpha
	
	ImGui::Begin(" ", nullptr, ImGuiWindowFlags);
	ImGui::PushFont(g_Variables.m_FontNormal);
	{
		// === PUSH THEME COLORS FOR ALL IMGUI ELEMENTS ===
		ImVec4 themeCol = activeTheme.primary;
		ImVec4 themeHover = ImVec4(themeCol.x * 1.2f, themeCol.y * 1.2f, themeCol.z * 1.2f, 1.0f);
		ImVec4 themeActive = ImVec4(themeCol.x * 0.8f, themeCol.y * 0.8f, themeCol.z * 0.8f, 1.0f);
		ImVec4 themeDim = ImVec4(themeCol.x * 0.4f, themeCol.y * 0.4f, themeCol.z * 0.4f, 0.6f);

		ImGui::PushStyleColor(ImGuiCol_SliderGrab, themeCol);
		ImGui::PushStyleColor(ImGuiCol_SliderGrabActive, themeHover);
		ImGui::PushStyleColor(ImGuiCol_CheckMark, themeCol);
		ImGui::PushStyleColor(ImGuiCol_Button, themeDim);
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, themeHover);
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, themeActive);
		ImGui::PushStyleColor(ImGuiCol_Header, themeDim);
		ImGui::PushStyleColor(ImGuiCol_HeaderHovered, themeCol);
		ImGui::PushStyleColor(ImGuiCol_HeaderActive, themeActive);
		ImGui::PushStyleColor(ImGuiCol_BorderShadow, ImVec4(0, 0, 0, 0));
		
		Custom::DrawBackground(g_MenuInfo.IsLogged);
		
		// === DRAW GALAXY WHEN LOGGED IN AND VISIBLE (Including during Fade Out) ===
		if (g_MenuInfo.IsLogged && menuAnimGlobal > 0.01f)
		{
			ImDrawList* draw_list = ImGui::GetWindowDrawList();
			ImVec2 winPos = ImGui::GetWindowPos();
			ImVec2 winSize = ImGui::GetWindowSize();
			
			// Draw galaxy background
			::DrawGalaxyBackground(draw_list, winPos, winSize, animTime);
			
			// Dark overlay so content is readable
			draw_list->AddRectFilled(
				winPos,
				ImVec2(winPos.x + winSize.x, winPos.y + winSize.y),
				IM_COL32(0, 0, 0, 100),
				15.0f
			);
			
			// ======= LAYER 1: TITLE BAR (Y=0 to Y=28) =======
			draw_list->AddRectFilled(
				winPos,
				ImVec2(winPos.x + winSize.x, winPos.y + 28),
				IM_COL32(15, 15, 15, 240),
				15.0f, ImDrawFlags_RoundCornersTop
			);
			
			// Title text centered vertically in title bar
			const char* titleText = "LiKinho Executor";
			ImVec2 titleSz = g_Variables.m_FontNormal->CalcTextSizeA(g_Variables.m_FontNormal->FontSize, FLT_MAX, 0, titleText);
			draw_list->AddText(
				g_Variables.m_FontNormal, g_Variables.m_FontNormal->FontSize,
				ImVec2(winPos.x + 12, winPos.y + (28 - titleSz.y) * 0.5f),
				IM_COL32(255, 255, 255, 255),
				titleText
			);
			
			// ======= LAYER 2: BLACK ROUNDED BORDER =======
			draw_list->AddRect(
				winPos,
				ImVec2(winPos.x + winSize.x, winPos.y + winSize.y),
				IM_COL32(0, 0, 0, 200),
				15.0f, 0, 2.0f
			);
			
			// ======= LAYER 3: LOGO IMAGE - RIGHT SIDE, BIGGER =======
			float logoSize = 35.0f;
			ImVec2 logoCenter(winPos.x + winSize.x - logoSize - 20, winPos.y + 50);
			float frameRadius = logoSize;
			float imgRadius = logoSize - 3.0f;

			// Draw theme-colored circle frame (border)
			draw_list->AddCircleFilled(logoCenter, frameRadius, ImGui::ColorConvertFloat4ToU32(activeTheme.accent), 32);

			// Draw logo image inside the circle frame
			if (g_Variables.Logo) {
				draw_list->AddImageRounded(
					(ImTextureID)g_Variables.Logo,
					ImVec2(logoCenter.x - imgRadius, logoCenter.y - imgRadius),
					ImVec2(logoCenter.x + imgRadius, logoCenter.y + imgRadius),
					ImVec2(0, 0), ImVec2(1, 1),
					IM_COL32(255, 255, 255, 255),
					99.0f // Full rounding = circle mask
				);
			} else {
				// Fallback: text "L" if texture not loaded
				draw_list->AddText(g_Variables.m_FontSecundary, logoSize * 0.8f, ImVec2(logoCenter.x - logoSize * 0.25f, logoCenter.y - logoSize * 0.4f), IM_COL32(255, 255, 255, 255), "L");
			}

			// ======= LAYER 4: TABS (Y=32, starting at X=55) =======
			ImGui::SetCursorPos(ImVec2(12, 32));
			ImGui::BeginGroup();
			ImGui::PushFont(g_Variables.m_FontSecundary);
			{
				// === ACTIVE TABS (order: Executor, Visuals, Combat, Premium, Settings) ===
				if (Custom::Tab(ICON_FA_CODE, Lang(xorstr("Executor"), xorstr("Executor")), g_MenuInfo.Executor == g_MenuInfo.iTabCount))
					g_MenuInfo.iTabCount = g_MenuInfo.Executor;
				ImGui::SameLine(0, 24);
				if (Custom::Tab(ICON_FA_EYE, Lang(xorstr("Visuals"), xorstr("Visuais")), g_MenuInfo.Visuals == g_MenuInfo.iTabCount))
					g_MenuInfo.iTabCount = g_MenuInfo.Visuals;
				ImGui::SameLine(0, 24);
				if (Custom::Tab(ICON_FA_CROSSHAIRS, Lang(xorstr("Combat"), xorstr("Combate")), g_MenuInfo.Combat == g_MenuInfo.iTabCount))
					g_MenuInfo.iTabCount = g_MenuInfo.Combat;
				ImGui::SameLine(0, 24);
				if (Custom::Tab(ICON_FA_CROWN, Lang(xorstr("Premium"), xorstr("Premium")), g_MenuInfo.Premium == g_MenuInfo.iTabCount))
					g_MenuInfo.iTabCount = g_MenuInfo.Premium;
				ImGui::SameLine(0, 24);
				if (Custom::Tab(ICON_FA_WRENCH, Lang(xorstr("Settings"), xorstr("Configuracoes")), g_MenuInfo.Settings == g_MenuInfo.iTabCount))
					g_MenuInfo.iTabCount = g_MenuInfo.Settings;

				// === COMMENTED OUT TABS (preserved for future use) ===
				//ImGui::SameLine(0, 12);
				//if (Custom::Tab(ICON_FA_USER, xorstr("Player"), g_MenuInfo.Local == g_MenuInfo.iTabCount))
				//	g_MenuInfo.iTabCount = g_MenuInfo.Local;
				//ImGui::SameLine(0, 12);
				//if (Custom::Tab(ICON_FA_GLOBE, xorstr("World"), g_MenuInfo.World == g_MenuInfo.iTabCount))
				//	g_MenuInfo.iTabCount = g_MenuInfo.World;
				//ImGui::SameLine(0, 12);
				//if (Custom::Tab(ICON_FA_BARS, xorstr("Exploits"), g_MenuInfo.Exploits == g_MenuInfo.iTabCount))
				//	g_MenuInfo.iTabCount = g_MenuInfo.Exploits;
			}
			ImGui::PopFont();
			ImGui::EndGroup();
		}
		
			if (g_MenuInfo.IsLogged)
		{
		g_MenuInfo.TabAlpha = ImClamp(g_MenuInfo.TabAlpha + (5.f * ImGui::GetIO().DeltaTime * (g_MenuInfo.iTabCount == g_MenuInfo.iCurrentPage ? 1.f : -1.f)), 0.f, 1.f);

		if (g_MenuInfo.TabAlpha == 0.f)
			g_MenuInfo.iCurrentPage = g_MenuInfo.iTabCount;

		ImGuiStyle* style = &ImGui::GetStyle();
		ImGui::PushStyleVar(ImGuiStyleVar_Alpha, g_MenuInfo.TabAlpha * style->Alpha);

		if (g_MenuInfo.IsLogged)
		{
			// ======= CONTENT AREA (Y=68 - more space below tabs) =======
			ImGui::SetCursorPos(ImVec2(10, 68));
			ImGui::BeginGroup();



			switch (g_MenuInfo.iCurrentPage)
			{

			case g_MenuInfo.Combat:
				Combat::Render();
				break;
			case g_MenuInfo.Visuals:
				Visuals::Render();
				break;
			case g_MenuInfo.Local:
				Local::Render();
				break;
			case g_MenuInfo.World:
				World::Render();
				break;
			case g_MenuInfo.Exploits:
				Exploits::Render();
				break;
			case g_MenuInfo.Settings:
				Settings::Render();
				break;
			case g_MenuInfo.Executor:
				Executor::Render();
				break;
			case g_MenuInfo.Premium:
				Premium::Render();
				break;

			}

			ImGui::EndGroup();


			HWND ActiveWindow = GetForegroundWindow();

			{
				std::lock_guard<std::mutex> Lock(DrawMtx);

				NotifyManager::Render();

				if (ActiveWindow == g_Variables.g_hGameWindow)
				{
					if (GetAsyncKeyState(g_Config.Player->GodModeKey) & 1)
					{
						g_Config.Player->EnableGodMode = !g_Config.Player->EnableGodMode;

						Core::SDK::Pointers::pLocalPlayer->SetGodMode(g_Config.Player->EnableGodMode);

						std::thread([&]()
							{
								NotifyManager::Send(xorstr("GodMode has been ") + (std::string)(g_Config.Player->EnableGodMode ? xorstr("enabled!") : xorstr("disabled!")), 2000);
							}
						).detach();

					}

					if (GetAsyncKeyState(g_Config.ESP->KeyBind) & 1)
					{
						g_Config.ESP->Enabled = !g_Config.ESP->Enabled;

						std::thread([&]()
							{
								NotifyManager::Send(xorstr("ESP has been ") + (std::string)(g_Config.ESP->Enabled ? xorstr("enabled!") : xorstr("disabled!")), 2000);
							}
						).detach();

					}

					if (GetAsyncKeyState(g_Config.Player->NoClipKey) & 1)
					{
						g_Config.Player->NoClipEnabled = !g_Config.Player->NoClipEnabled;

						Core::SDK::Pointers::pLocalPlayer->FreezePed(g_Config.Player->NoClipEnabled);

						std::thread([&]()
							{
								NotifyManager::Send(xorstr("NoClip has been ") + (std::string)(g_Config.Player->NoClipEnabled ? xorstr("enabled!") : xorstr("disabled!")), 2000);
							}
						).detach();
					}

					if (g_Config.Player->NoClipEnabled)
						Features::Exploits::NoClip();

				}

				if (ActiveWindow == g_Variables.g_hGameWindow || ActiveWindow == g_Variables.g_hCheatWindow)
				{
					struct FovFuncs_t {
						bool* Enabled;
						int* FovSize;
						ImVec4 FovColor;
					};

					std::vector<FovFuncs_t> FovDrawList = {
						FovFuncs_t(&g_Config.Aimbot->ShowFov, &g_Config.Aimbot->FOV, g_Config.Aimbot->FovColor),
						FovFuncs_t(&g_Config.SilentAim->ShowFov, &g_Config.SilentAim->FOV, g_Config.SilentAim->FovColor),
						FovFuncs_t(&g_Config.TriggerBot->ShowFov, &g_Config.TriggerBot->FOV, g_Config.TriggerBot->FovColor),
					};

					static std::vector<float> Alphas(FovDrawList.size(), 0.0f);
					static std::vector<float> Sizes(FovDrawList.size(), 0.0f);

					for (int i = 0; i < FovDrawList.size(); ++i)
					{
						auto& Fov = FovDrawList[i];

						Alphas[i] = ImClamp(ImLerp(Alphas[i], *Fov.Enabled ? 1.f : 0.f, ImGui::GetIO().DeltaTime * 10.f), 0.f, 1.f);
						Sizes[i] = ImLerp(Sizes[i], (float)*Fov.FovSize, ImGui::GetIO().DeltaTime * 12.f);

						ImGui::PushStyleVar(ImGuiStyleVar_Alpha, Alphas[i]);

						ImGui::GetBackgroundDrawList()->AddCircle(ImVec2(g_Variables.g_vGameWindowCenter.x, g_Variables.g_vGameWindowCenter.y), Sizes[i], ImGui::GetColorU32(Fov.FovColor), 999);

						ImGui::PopStyleVar();
					}

					if (g_Config.General->WaterMark)
						Custom::WaterMark::Render();

					ImGui::PushFont(g_Variables.m_DrawFont);

					Features::g_Esp.Draw();
					Features::g_Esp.DrawVehicle();

					// Admin Warning: renders only when game is active
					Core::Features::g_Esp.DrawAdminWarning();

					ImGui::PopFont();
				}
				else {

					if (ImGui::GetStyle().Alpha >= 0.9f)
					{
						g_MenuInfo.IsOpen = false;
						SetWindowLong(g_Variables.g_hCheatWindow, GWL_EXSTYLE, WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_TRANSPARENT);
					}

				}

			}
		}
		ImGui::PopStyleColor(10); // Theme: SliderGrab, SliderGrabActive, CheckMark, Button, ButtonHover, ButtonActive, Header, HeaderHover, HeaderActive, BorderShadow
		ImGui::PopStyleColor(6); // WindowBg, Border, ChildBg, FrameBg, FrameBgHovered, FrameBgActive
		ImGui::PopStyleVar(7); // WindowRounding, ChildRounding, FrameRounding, GrabRounding, WindowPadding, WindowBorderSize, FrameBorderSize
		ImGui::PopFont();
	}

	}
	ImGui::End();
}




