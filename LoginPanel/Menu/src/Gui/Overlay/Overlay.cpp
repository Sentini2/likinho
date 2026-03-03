#include "Overlay.hpp"
#include <Gui/Pages/Executor.hpp> // Access Executor shared memory
#include <Includes/ImGui/Files/imgui_freetype.h>
#include <Includes/CustomWidgets/Notify.hpp>
#include <Includes/ImGui/Images.hpp>
#include <Includes/ImGui/Fonts.hpp>
#include <Core/Core.hpp>
#include <Gui/Gui.hpp>

#include <dwmapi.h>
#include <tchar.h>
#include <thread>

//#define FULLSCREEN_EX

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace Gui
{
	typedef HWND(WINAPI* CreateWindowInBand)(_In_ DWORD dwExStyle, _In_opt_ ATOM atom, _In_opt_ LPCWSTR lpWindowName, _In_ DWORD dwStyle, _In_ int X, _In_ int Y, _In_ int nWidth, _In_ int nHeight, _In_opt_ HWND hWndParent, _In_opt_ HMENU hMenu, _In_opt_ HINSTANCE hInstance, _In_opt_ LPVOID lpParam, DWORD band);

	inline HHOOK hKeyboardHook;

	inline LRESULT CALLBACK KeyboardCallBack(int nCode, WPARAM wParam, LPARAM lParam)
	{
		if (nCode >= 0)
		{
			//	if ( GetForegroundWindow( ) == g_Variables.g_hCheatWindow )
				//{
			KBDLLHOOKSTRUCT* pKeyboard = (KBDLLHOOKSTRUCT*)lParam;
			PostMessage(g_Variables.g_hCheatWindow, wParam, pKeyboard->vkCode, 0);
			//}
		}
		return CallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
	}

	void Overlay::Render()
	{

#ifdef FULLSCREEN_EX
		CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
		CreateWindowInBand pCreateWindowInBand = reinterpret_cast<CreateWindowInBand>(GetProcAddress(LoadLibraryA(xorstr("user32.dll")), xorstr("CreateWindowInBand")));
		PrepareForUIAccess();
#endif // FULLSCREEN_EX

		WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, Overlay::WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, L" ", NULL };
		ATOM RegClass = RegisterClassExW(&wc);

#ifdef FULLSCREEN_EX
		g_Variables.g_hCheatWindow = pCreateWindowInBand(WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE, RegClass, L" ", WS_POPUP, static_cast<int>(g_Variables.g_vGameWindowPos.x), static_cast<int>(g_Variables.g_vGameWindowPos.y), static_cast<int>(g_Variables.g_vGameWindowSize.x), static_cast<int>(g_Variables.g_vGameWindowSize.y), NULL, NULL, wc.hInstance, NULL, 2/*ZBID_UIACCESS*/);
#else
		g_Variables.g_hCheatWindow = CreateWindowExW(WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_TRANSPARENT, wc.lpszClassName, L" ", WS_POPUP, g_Variables.g_vGameWindowPos.x, g_Variables.g_vGameWindowPos.y, g_Variables.g_vGameWindowSize.x, g_Variables.g_vGameWindowSize.y, NULL, NULL, wc.hInstance, NULL);
#endif // FULLSCREEN_EX		

		SetLayeredWindowAttributes(g_Variables.g_hCheatWindow, RGB(0, 0, 0), 255, LWA_ALPHA);
		MARGINS Margin = { g_Variables.g_vGameWindowPos.x, g_Variables.g_vGameWindowPos.y, g_Variables.g_vGameWindowSize.x,g_Variables.g_vGameWindowSize.y };
		DwmExtendFrameIntoClientArea(g_Variables.g_hCheatWindow, &Margin);

		if (!CreateDeviceD3D(g_Variables.g_hCheatWindow))
		{
			CleanupDeviceD3D();
			UnregisterClassW(wc.lpszClassName, wc.hInstance);
			return;
		}


		SetWindowDisplayAffinity(g_Variables.g_hCheatWindow, g_Config.General->StreamProof ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE);

		ShowWindow(g_Variables.g_hCheatWindow, SW_SHOWDEFAULT);
		UpdateWindow(g_Variables.g_hCheatWindow);


		ImGui::CreateContext();

		Style();
		Fonts();

		ImGui_ImplWin32_Init(g_Variables.g_hCheatWindow);
		ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

#ifdef FULLSCREEN_EX
		hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardCallBack, NULL, 0);
#endif // FULLSCREEN_EX

		Core::StartThreads();
		if (!Core::ThreadsStarted) return;

		// Loading screen state
		static bool loadingDone = false;
		static float loadProgress = 0.0f;
		static float loadStartTime = -1.0f;
		static const float LOAD_DURATION = 3.0f; // 3.0 seconds for smooth animation

		static RECT old_rc;
		ZeroMemory(&Message, sizeof(MSG));

		while (Message.message != WM_QUIT)
		{
			// During loading, keep overlay visible over game window
			if (!loadingDone) {
				SetWindowLong(g_Variables.g_hCheatWindow, GWL_EXSTYLE, WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TOOLWINDOW);
			}
			while (PeekMessage(&Message, g_Variables.g_hCheatWindow, 0, 0, PM_REMOVE)) {
				TranslateMessage(&Message);
				DispatchMessage(&Message);
			}

			HWND ActiveWindow = GetForegroundWindow();

			// Only allow menu toggle after loading is done
			if (loadingDone) {
				if (GetAsyncKeyState(g_Config.General->MenuKey) & 1) {

					if (g_MenuInfo.IsOpen == false) {
						if (ActiveWindow == g_Variables.g_hGameWindow) {
							g_MenuInfo.IsOpen = true;

#ifdef FULLSCREEN_EX
							SetWindowLong(g_Variables.g_hCheatWindow, GWL_EXSTYLE, WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE);
#else
							SetWindowLong(g_Variables.g_hCheatWindow, GWL_EXSTYLE, WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TOOLWINDOW);
#endif // FULLSCREEN_EX		
						}
						else {
							SetWindowLong(g_Variables.g_hCheatWindow, GWL_EXSTYLE, WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_TRANSPARENT);
						}
					}
					else {
						g_MenuInfo.IsOpen = false;
						SetWindowLong(g_Variables.g_hCheatWindow, GWL_EXSTYLE, WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_TRANSPARENT);
					}

					// Auto-click to transfer focus (External menu requirement)
					mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
					mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
				}
			}



			static float BgAlpha = 0.f;
			BgAlpha = ImLerp(BgAlpha, g_MenuInfo.IsOpen ? 1.f : 0.f, ImGui::GetIO().DeltaTime * 8);

			ImGui_ImplDX11_NewFrame();
			ImGui_ImplWin32_NewFrame();

			ImGui::NewFrame();
			{
			// === LOADING SCREEN ===
				if (!loadingDone)
				{
					static bool connectionFailed = false;
					static float failTime = 0.0f;
					static float connectionAttemptStart = -1.0f;

					if (loadStartTime < 0.0f) loadStartTime = ImGui::GetTime();
					float elapsed = (float)(ImGui::GetTime() - loadStartTime);

					if (!connectionFailed) {
						loadProgress = (elapsed / LOAD_DURATION);

						// Pause at 70% to check connection
						if (loadProgress >= 0.70f) {
							Executor::InitSharedMemory();
							bool connected = Executor::pShared && Executor::pShared->dllReady;

							if (!connected) {
								if (connectionAttemptStart < 0) connectionAttemptStart = ImGui::GetTime();
								
								// Hold progress visual at 70%
								loadProgress = 0.70f;
								// Adjust start time to keep it stuck here until success/fail
								loadStartTime = ImGui::GetTime() - (0.70f * LOAD_DURATION);

								if (ImGui::GetTime() - connectionAttemptStart > 20.0f) {
									connectionFailed = true;
									failTime = ImGui::GetTime();
								}
							}
						}
						
						if (loadProgress > 1.0f) loadProgress = 1.0f;
					}

					ImVec2 screenSz(g_Variables.g_vGameWindowSize.x, g_Variables.g_vGameWindowSize.y);
					ImDrawList* dl = ImGui::GetBackgroundDrawList();
					float cx = screenSz.x * 0.5f;
					float cy = screenSz.y * 0.5f;

					if (connectionFailed)
					{
						// === FAILURE ANIMATION (Red X at spinner position) ===
						
						// Keep normal background
						ImVec2 vignetteGrad[4] = {
							ImVec2(0, 0),
							ImVec2(screenSz.x, 0),
							ImVec2(screenSz.x, screenSz.y),
							ImVec2(0, screenSz.y)
						};
						float vignetteRad = sqrtf(screenSz.x * screenSz.x + screenSz.y * screenSz.y) * 0.5f;
						for (int i = 0; i < 4; i++) {
							float dist = sqrtf(powf(vignetteGrad[i].x - cx, 2) + powf(vignetteGrad[i].y - cy, 2));
							float alpha = (dist / vignetteRad) * 180.0f;
							if (alpha > 180) alpha = 180;
							dl->AddRectFilled(ImVec2(0, i * screenSz.y / 4), ImVec2(screenSz.x, (i + 1) * screenSz.y / 4), IM_COL32(5, 5, 10, (int)alpha));
						}

						// Animated Red X (fades in, then fades out)
						float animTime = (float)(ImGui::GetTime() - failTime);
						float xAlpha = 255.0f;
						
						// Fade in (0-0.5s)
						if (animTime < 0.5f) {
							xAlpha = (animTime / 0.5f) * 255.0f;
						}
						// Stay visible (0.5-2.5s)
						else if (animTime < 2.5f) {
							xAlpha = 255.0f;
						}
						// Fade out (2.5-3.5s)
						else if (animTime < 3.5f) {
							xAlpha = (1.0f - ((animTime - 2.5f) / 1.0f)) * 255.0f;
						}
						// Close overlay after animation completes
						else {
							xAlpha = 0.0f;
							// DO NOT ExitProcess(0) as it will kill explorer.exe
							// Instead, break the loop to terminate only the overlay thread
							break;
						}

						float xSize = 50.0f;
						float xThick = 6.0f;
						ImU32 xColor = IM_COL32(255, 50, 50, (int)xAlpha);

						// Red X at spinner position (cy - 80)
						dl->AddLine(ImVec2(cx - xSize, cy - 80 - xSize), ImVec2(cx + xSize, cy - 80 + xSize), xColor, xThick);
						dl->AddLine(ImVec2(cx + xSize, cy - 80 - xSize), ImVec2(cx - xSize, cy - 80 + xSize), xColor, xThick);

						// Title still shows (fades with X)
						const char* title = "LiKinho Executor";
						ImVec2 titleSz(0, 0);
						if (g_Variables.m_FontBig) titleSz = g_Variables.m_FontBig->CalcTextSizeA(28.0f, FLT_MAX, 0, title);

						for (int i = 0; i < 3; i++) {
							float glowAlpha = (30.0f - (i * 10.0f)) * (xAlpha / 255.0f);
							float glowOffset = (float)(i + 1);
							if (g_Variables.m_FontBig)
								dl->AddText(g_Variables.m_FontBig, 28.0f, ImVec2(cx - titleSz.x * 0.5f, cy + 10 + glowOffset), IM_COL32(255, 140, 0, (int)glowAlpha), title);
						}
						if (g_Variables.m_FontBig)
							dl->AddText(g_Variables.m_FontBig, 28.0f, ImVec2(cx - titleSz.x * 0.5f, cy + 10), IM_COL32(255, 255, 255, (int)xAlpha), title);

						// Error message (fades with X)
						const char* errorMsg = "Error modules not found";
						ImVec2 errSz(0, 0);
						if (g_Variables.m_FontSmaller) errSz = g_Variables.m_FontSmaller->CalcTextSizeA(14.0f, FLT_MAX, 0, errorMsg);
						if (g_Variables.m_FontSmaller)
							dl->AddText(g_Variables.m_FontSmaller, 14.0f, ImVec2(cx - errSz.x * 0.5f, cy + 52), IM_COL32(255, 50, 50, (int)xAlpha), errorMsg);


					}
					else
					{
						// Status messages based on progress
						const char* statusMsg = "Initializing...";
						if (loadProgress > 0.10f) statusMsg = "Loading fonts...";
						if (loadProgress > 0.25f) statusMsg = "Loading images...";
						if (loadProgress > 0.40f) statusMsg = "Loading resources...";
						if (loadProgress > 0.55f) statusMsg = "Preparing overlay...";
						if (loadProgress > 0.70f) statusMsg = "Connecting modules...";
						if (loadProgress > 0.85f) statusMsg = "Almost ready...";
						if (loadProgress >= 1.0f) statusMsg = "Done!";

						// === Ultra-Modern Minimalist Loading Screen ===
						// Background deep gradient
						ImVec2 gradientPoints[4] = {
							ImVec2(0, 0), ImVec2(screenSz.x, 0),
							ImVec2(screenSz.x, screenSz.y), ImVec2(0, screenSz.y)
						};
						
						dl->AddRectFilledMultiColor(ImVec2(0,0), screenSz, 
							IM_COL32(10, 5, 15, 240), IM_COL32(5, 5, 8, 240), 
							IM_COL32(15, 10, 25, 250), IM_COL32(5, 5, 15, 250));

						float time = (float)ImGui::GetTime();
						
						// Floating ambient neon particles
						for (int i = 0; i < 30; i++) {
							float pX = cx + sinf(time * 0.2f + i * 2.1f) * (screenSz.x * 0.4f);
							float pY = cy + cosf(time * 0.3f + i * 3.5f) * (screenSz.y * 0.4f);
							float pAlpha = (sinf(time * 1.5f + i) * 60.0f) + 80.0f;
							float pSize = 1.0f + sinf(time + i) * 1.5f;
							// Mix of purple and orange particles
							ImU32 pCol = (i % 2 == 0) ? IM_COL32(160, 50, 255, (int)pAlpha) : IM_COL32(255, 100, 0, (int)pAlpha);
							dl->AddCircleFilled(ImVec2(pX, pY), pSize, pCol, 6);
							// particle glow
							dl->AddCircleFilled(ImVec2(pX, pY), pSize * 3.5f, pCol & 0xAAFFFFFF, 6); 
						}

						// Main Centerpiece: Dual Rotating Neon Arcs
						float baseRadius = 65.0f;
						float spin1 = time * -4.5f;
						float spin2 = time * 3.0f;
						
						// Inner Purple Arc
						dl->PathArcTo(ImVec2(cx, cy - 60), baseRadius, spin1, spin1 + IM_PI * 1.3f, 40);
						dl->PathStroke(IM_COL32(160, 50, 255, 255), 0, 4.0f);
						// Inner Purple Glow
						dl->PathArcTo(ImVec2(cx, cy - 60), baseRadius, spin1, spin1 + IM_PI * 1.3f, 40);
						dl->PathStroke(IM_COL32(160, 50, 255, 50), 0, 12.0f);
						
						// Outer Orange Arc
						dl->PathArcTo(ImVec2(cx, cy - 60), baseRadius + 15.0f, spin2, spin2 + IM_PI * 0.8f, 40);
						dl->PathStroke(IM_COL32(255, 120, 0, 255), 0, 3.0f);
						// Outer Orange Glow
						dl->PathArcTo(ImVec2(cx, cy - 60), baseRadius + 15.0f, spin2, spin2 + IM_PI * 0.8f, 40);
						dl->PathStroke(IM_COL32(255, 120, 0, 60), 0, 10.0f);

						// Center Pulsing Core
						float corePulse = 1.0f + sinf(time * 6.0f) * 0.15f;
						dl->AddCircleFilled(ImVec2(cx, cy - 60), 20.0f * corePulse, IM_COL32(160, 50, 255, 140), 32);
						dl->AddCircleFilled(ImVec2(cx, cy - 60), 10.0f, IM_COL32(255, 255, 255, 200), 32);

						// Title Text
						const char* title = "L i K i n h o   E x e c u t o r";
						ImVec2 titleSz(0, 0);
						if (g_Variables.m_FontBig) titleSz = g_Variables.m_FontBig->CalcTextSizeA(26.0f, FLT_MAX, 0, title);
						if (g_Variables.m_FontBig) {
							// Text Glow
							dl->AddText(g_Variables.m_FontBig, 26.0f, ImVec2(cx - titleSz.x * 0.5f, cy + 50), IM_COL32(160, 50, 255, 80), title);
							dl->AddText(g_Variables.m_FontBig, 26.0f, ImVec2(cx - titleSz.x * 0.5f, cy + 50), IM_COL32(240, 240, 250, 255), title);
						}

						// Sleek Progress Line
						float barW = 300.0f;
						float barY = cy + 100.0f;
						float fillW = barW * loadProgress;
						
						// Background track
						dl->AddLine(ImVec2(cx - barW*0.5f, barY), ImVec2(cx + barW*0.5f, barY), IM_COL32(30, 30, 45, 255), 2.0f);
						
						if (fillW > 0) {
							// Neon line Fill
							dl->AddLine(ImVec2(cx - barW*0.5f, barY), ImVec2((cx - barW*0.5f) + fillW, barY), IM_COL32(255, 120, 0, 255), 3.0f);
							// Glowing flare at the head
							dl->AddCircleFilled(ImVec2((cx - barW*0.5f) + fillW, barY), 4.0f, IM_COL32(255, 200, 100, 255), 12);
							dl->AddCircleFilled(ImVec2((cx - barW*0.5f) + fillW, barY), 12.0f, IM_COL32(255, 120, 0, 60), 12);
						}

						// Dynamic Status Text
						ImVec2 statusSz(0, 0);
						char statusBuf[128];
						sprintf_s(statusBuf, "%s  [%d%%]", statusMsg, (int)(loadProgress * 100));
						if (g_Variables.m_FontSmaller) statusSz = g_Variables.m_FontSmaller->CalcTextSizeA(14.0f, FLT_MAX, 0, statusBuf);
						
						if (g_Variables.m_FontSmaller) {
							dl->AddText(g_Variables.m_FontSmaller, 14.0f, ImVec2(cx - statusSz.x * 0.5f, barY + 15), IM_COL32(140, 140, 160, 255), statusBuf);
						}

						// === Done? Open menu ===
						if (loadProgress >= 1.0f && elapsed > LOAD_DURATION + 0.5f) {
							loadingDone = true;
							g_MenuInfo.IsOpen = true;
	#ifdef FULLSCREEN_EX
							SetWindowLong(g_Variables.g_hCheatWindow, GWL_EXSTYLE, WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE);
	#else
							SetWindowLong(g_Variables.g_hCheatWindow, GWL_EXSTYLE, WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TOOLWINDOW);
	#endif
						}
					}
				}
				else
				{
					// Normal menu rendering
					ImGui::PushStyleVar(ImGuiStyleVar_Alpha, BgAlpha);

					ImGui::GetBackgroundDrawList()->AddRectFilled(ImVec2(0, 0), ImVec2(g_Variables.g_vGameWindowSize.x, g_Variables.g_vGameWindowSize.y), ImColor(0.f, 0.f, 0.f, BgAlpha >= 0.4f ? 0.4f : BgAlpha));
					Gui::Rendering();

					ImGui::PopStyleVar();
				}


			}
			ImGui::EndFrame();

			const float ClearColor[4] = { 0 };
			g_pd3dDeviceContext->OMSetRenderTargets(1U, &g_mainRenderTargetView, NULL);
			g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, ClearColor);

			ImGui::Render();
			ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

			g_pSwapChain->Present(g_Config.General->VSync, 0U); //VSync
		}

		ImGui_ImplDX11_Shutdown();
		ImGui_ImplWin32_Shutdown();
		ImGui::DestroyContext();

		CleanupDeviceD3D();
		DestroyWindow(g_Variables.g_hCheatWindow);
		UnregisterClassW(wc.lpszClassName, wc.hInstance);

#ifdef FULLSCREEN_EX
		UnhookWindowsHookEx(hKeyboardHook);
#endif // FULLSCREEN_EX
		return;
	}

	void Overlay::Fonts()
	{
		ImGuiIO& io = ImGui::GetIO(); (void)io;
		io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
		io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;
		io.IniFilename = nullptr;

		ImFontConfig Cfg;
		Cfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_ForceAutoHint | ImGuiFreeTypeBuilderFlags_LightHinting | ImGuiFreeTypeBuilderFlags_LoadColor;
		Cfg.FontDataOwnedByAtlas = false;

		ImFontConfig DrawCfg;
		DrawCfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_ForceAutoHint | ImGuiFreeTypeBuilderFlags_Bitmap;
		DrawCfg.FontDataOwnedByAtlas = false;

		// Setup FontAwesome Config
		static const ImWchar FontAwesomeRanges[] = { ICON_MIN_FA, ICON_MAX_FA, 0 };
		static const ImWchar FontAwesomeRangesBrands[] = { ICON_MIN_FAB, ICON_MAX_FAB, 0 };

		ImFontConfig FontAwesomeConfig;
		FontAwesomeConfig.PixelSnapH = true;
		FontAwesomeConfig.GlyphMinAdvanceX = 19;
		FontAwesomeConfig.FontDataOwnedByAtlas = false;

		// 1. Load Big (Default) + Merge FA
		g_Variables.m_FontBig = io.Fonts->AddFontFromMemoryTTF(InterSemiBold, sizeof(InterSemiBold), 20.f, &Cfg, io.Fonts->GetGlyphRangesCyrillic());
		
		FontAwesomeConfig.MergeMode = true;
		io.Fonts->AddFontFromMemoryCompressedTTF(FontAwesome6Solid_compressed_data, sizeof(FontAwesome6Solid_compressed_size), 19, &FontAwesomeConfig, FontAwesomeRanges);
		FontAwesomeConfig.MergeMode = false;

		// 2. Load BigSmall
		g_Variables.m_FontBigSmall = io.Fonts->AddFontFromMemoryTTF(InterSemiBold, sizeof(InterSemiBold), 18.f, &Cfg, io.Fonts->GetGlyphRangesCyrillic());

		// 3. Load Normal + Merge FA
		g_Variables.m_FontNormal = io.Fonts->AddFontFromMemoryTTF(InterSemiBold, sizeof(InterSemiBold), 18.f, &Cfg, io.Fonts->GetGlyphRangesCyrillic());
		
		FontAwesomeConfig.MergeMode = true;
		io.Fonts->AddFontFromMemoryCompressedTTF(FontAwesome6Solid_compressed_data, sizeof(FontAwesome6Solid_compressed_size), 18, &FontAwesomeConfig, FontAwesomeRanges);
		FontAwesomeConfig.MergeMode = false;

		// 4. Load Secundary + Merge FA
		g_Variables.m_FontSecundary = io.Fonts->AddFontFromMemoryTTF(InterSemiBold, sizeof(InterSemiBold), 16.f, &Cfg, io.Fonts->GetGlyphRangesCyrillic());
		
		FontAwesomeConfig.MergeMode = true;
		io.Fonts->AddFontFromMemoryCompressedTTF(FontAwesome6Solid_compressed_data, sizeof(FontAwesome6Solid_compressed_size), 16, &FontAwesomeConfig, FontAwesomeRanges);
		FontAwesomeConfig.MergeMode = false;

		// 5. Smaller
		g_Variables.m_FontSmaller = io.Fonts->AddFontFromMemoryTTF(InterSemiBold, sizeof(InterSemiBold), 14.f, &Cfg, io.Fonts->GetGlyphRangesCyrillic());

		// 6. DrawFont
		g_Variables.m_DrawFont = io.Fonts->AddFontFromMemoryTTF(InterSemiBold, sizeof(InterSemiBold), 12.f, &DrawCfg, io.Fonts->GetGlyphRangesCyrillic());

		// 7. Load Standalone FA (for direct usage)
		g_Variables.FontAwesomeSolid = io.Fonts->AddFontFromMemoryCompressedTTF(FontAwesome6Solid_compressed_data, sizeof(FontAwesome6Solid_compressed_size), 19, &FontAwesomeConfig, FontAwesomeRanges);
		g_Variables.FontAwesomeSolidSmall = io.Fonts->AddFontFromMemoryCompressedTTF(FontAwesome6Solid_compressed_data, sizeof(FontAwesome6Solid_compressed_size), 16, &FontAwesomeConfig, FontAwesomeRanges);
		g_Variables.FontAwesomeRegular = io.Fonts->AddFontFromMemoryCompressedTTF(FontAwesome6Regular_compressed_data, sizeof(FontAwesome6Regular_compressed_size), 19, &FontAwesomeConfig, FontAwesomeRanges);

		g_Variables.m_Expand = io.Fonts->AddFontFromMemoryTTF(expand_binary, sizeof(expand_binary), 11.f, &Cfg, io.Fonts->GetGlyphRangesCyrillic());
	}

	void Overlay::Style()
	{
		ImGui::StyleColorsDark();

		ImGuiStyle* style = &ImGui::GetStyle();
		{
			style->WindowPadding = ImVec2(0, 0);
			style->WindowBorderSize = 0.f;
			style->ItemSpacing = ImVec2(12, 12);
			style->ScrollbarSize = 4.f;
		}

		if (g_Variables.Logo == nullptr)
		{
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, logo_binary, sizeof(logo_binary), &Info, Pump, &g_Variables.Logo, 0);
			#include <Includes/npc_image.h>
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, npc_image_data, npc_image_size, &Info, Pump, &g_Variables.NpcImage, 0);
			//WeaponsIcons (disabled - weapon tabs not active)
			//Overlay::LoadWeaponIcons();
		}
	}

	bool Overlay::CreateDeviceD3D(HWND hWnd)
	{
		DXGI_SWAP_CHAIN_DESC sd;
		ZeroMemory(&sd, sizeof(sd));
		sd.BufferCount = 2;
		sd.BufferDesc.Width = 0;
		sd.BufferDesc.Height = 0;
		sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
		sd.BufferDesc.RefreshRate.Numerator = 60;
		sd.BufferDesc.RefreshRate.Denominator = 1;
		sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
		sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
		sd.OutputWindow = hWnd;
		sd.SampleDesc.Count = 1;
		sd.SampleDesc.Quality = 0;
		sd.Windowed = TRUE;
		sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

		UINT createDeviceFlags = 0;
		//createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
		D3D_FEATURE_LEVEL featureLevel;
		const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
		if (D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext) != S_OK)
			return false;

		CreateRenderTarget();
		return true;
	}

	void Overlay::CleanupDeviceD3D()
	{
		CleanupRenderTarget();

		if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = NULL; }
		if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = NULL; }
		if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = NULL; }
	}

	void Overlay::CreateRenderTarget()
	{
		ID3D11Texture2D* pBackBuffer;
		g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
		g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
		pBackBuffer->Release();
	}

	void Overlay::CleanupRenderTarget()
	{
		if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = NULL; }
	}

	LRESULT CALLBACK Overlay::WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
		if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
			return true;

		switch (msg) {
		case WM_SIZE:
			if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED) {
				Overlay::CleanupRenderTarget();
				g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
				Overlay::CreateRenderTarget();
			}
			return 0;
		case WM_DESTROY:
			::PostQuitMessage(0);
			return 0;
			break;
		}

		return DefWindowProc(hWnd, msg, wParam, lParam);
	}

	DWORD Overlay::GetWinLogonToken(DWORD dwSessionId, DWORD dwDesiredAccess, PHANDLE phToken)
	{
		DWORD dwErr;
		PRIVILEGE_SET ps;

		ps.PrivilegeCount = 1;
		ps.Control = PRIVILEGE_SET_ALL_NECESSARY;

		if (LookupPrivilegeValue(NULL, SE_TCB_NAME, &ps.Privilege[0].Luid)) {
			HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (INVALID_HANDLE_VALUE != hSnapshot) {
				BOOL bCont, bFound = FALSE;
				PROCESSENTRY32 pe;

				pe.dwSize = sizeof(pe);
				dwErr = ERROR_NOT_FOUND;

				for (bCont = Process32First(hSnapshot, &pe); bCont; bCont = Process32Next(hSnapshot, &pe)) {
					HANDLE hProcess;

					if (0 != _tcsicmp(pe.szExeFile, xorstr("winlogon.exe"))) {
						continue;
					}

					hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
					if (hProcess) {
						HANDLE hToken;
						DWORD dwRetLen, sid;

						if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) {
							BOOL fTcb;

							if (PrivilegeCheck(hToken, &ps, &fTcb) && fTcb) {
								if (GetTokenInformation(hToken, TokenSessionId, &sid, sizeof(sid), &dwRetLen) && sid == dwSessionId) {
									bFound = TRUE;
									if (DuplicateTokenEx(hToken, dwDesiredAccess, NULL, SecurityImpersonation, TokenImpersonation, phToken)) {
										dwErr = ERROR_SUCCESS;
									}
									else {
										dwErr = GetLastError();
									}
								}
							}
							CloseHandle(hToken);
						}
						CloseHandle(hProcess);
					}

					if (bFound) break;
				}

				CloseHandle(hSnapshot);
			}
			else {
				dwErr = GetLastError();
			}
		}
		else {
			dwErr = GetLastError();
		}


		return dwErr;
	}

	DWORD Overlay::CreateUIAccessToken(PHANDLE phToken)
	{
		DWORD dwErr;
		HANDLE hTokenSelf;

		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &hTokenSelf)) {
			DWORD dwSessionId, dwRetLen;

			if (GetTokenInformation(hTokenSelf, TokenSessionId, &dwSessionId, sizeof(dwSessionId), &dwRetLen)) {
				HANDLE hTokenSystem;

				dwErr = GetWinLogonToken(dwSessionId, TOKEN_IMPERSONATE, &hTokenSystem);
				if (ERROR_SUCCESS == dwErr) {
					if (SetThreadToken(NULL, hTokenSystem)) {
						if (DuplicateTokenEx(hTokenSelf, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, NULL, SecurityAnonymous, TokenPrimary, phToken)) {
							BOOL bUIAccess = TRUE;

							if (!SetTokenInformation(*phToken, TokenUIAccess, &bUIAccess, sizeof(bUIAccess))) {
								dwErr = GetLastError();
								CloseHandle(*phToken);
							}
						}
						else {
							dwErr = GetLastError();
						}
						RevertToSelf();
					}
					else {
						dwErr = GetLastError();
					}
					CloseHandle(hTokenSystem);
				}
			}
			else {
				dwErr = GetLastError();
			}

			CloseHandle(hTokenSelf);
		}
		else {
			dwErr = GetLastError();
		}

		return dwErr;
	}

	BOOL Overlay::CheckForUIAccess(DWORD* pdwErr, DWORD* pfUIAccess)
	{
		BOOL result = FALSE;
		HANDLE hToken;

		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
			DWORD dwRetLen;

			if (GetTokenInformation(hToken, TokenUIAccess, pfUIAccess, sizeof(*pfUIAccess), &dwRetLen)) {
				result = TRUE;
			}
			else {
				*pdwErr = GetLastError();
			}
			CloseHandle(hToken);
		}
		else {
			*pdwErr = GetLastError();
		}

		return result;
	}

	DWORD Overlay::PrepareForUIAccess()
	{
		DWORD dwErr;
		HANDLE hTokenUIAccess;
		DWORD fUIAccess;

		if (CheckForUIAccess(&dwErr, &fUIAccess)) {
			if (fUIAccess) {
				dwErr = ERROR_SUCCESS;
			}
			else {
				dwErr = CreateUIAccessToken(&hTokenUIAccess);
				if (ERROR_SUCCESS == dwErr) {
					STARTUPINFO si;
					PROCESS_INFORMATION pi;

					GetStartupInfo(&si);
					if (CreateProcessAsUser(hTokenUIAccess, NULL, GetCommandLine(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
						CloseHandle(pi.hProcess), CloseHandle(pi.hThread);
						ExitProcess(0);
					}
					else {
						dwErr = GetLastError();
					}

					CloseHandle(hTokenUIAccess);
				}
			}
		}

		return dwErr;
	}

	void Overlay::LoadWeaponIcons() {
		// Weapon icons disabled - tabs not active
		/*
		{
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::gadget_parachute, sizeof(FiveM_Weapons::gadget_parachute), &Info, Pump, &g_Variables.FiveM_WeaponsPic.gadget_parachute, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_advancedrifle, sizeof(FiveM_Weapons::weapon_advancedrifle), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_advancedrifle, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_appistol, sizeof(FiveM_Weapons::weapon_appistol), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_appistol, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_assaultrifle, sizeof(FiveM_Weapons::weapon_assaultrifle), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_assaultrifle, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_assaultrifle_mk2, sizeof(FiveM_Weapons::weapon_assaultrifle_mk2), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_assaultrifle_mk2, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_assaultshotgun, sizeof(FiveM_Weapons::weapon_assaultshotgun), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_assaultshotgun, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_assaultsmg, sizeof(FiveM_Weapons::weapon_assaultsmg), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_assaultsmg, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_autoshotgun, sizeof(FiveM_Weapons::weapon_autoshotgun), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_autoshotgun, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_ball, sizeof(FiveM_Weapons::weapon_ball), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_ball, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_bat, sizeof(FiveM_Weapons::weapon_bat), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_bat, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_battleaxe, sizeof(FiveM_Weapons::weapon_battleaxe), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_battleaxe, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_bottle, sizeof(FiveM_Weapons::weapon_bottle), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_bottle, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_bullpuprifle, sizeof(FiveM_Weapons::weapon_bullpuprifle), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_bullpuprifle, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_bullpuprifle_mk2, sizeof(FiveM_Weapons::weapon_bullpuprifle_mk2), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_bullpuprifle_mk2, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_bullpupshotgun, sizeof(FiveM_Weapons::weapon_bullpupshotgun), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_bullpupshotgun, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_bzgas, sizeof(FiveM_Weapons::weapon_bzgas), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_bzgas, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_carbinerifle, sizeof(FiveM_Weapons::weapon_carbinerifle), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_carbinerifle, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_carbinerifle_mk2, sizeof(FiveM_Weapons::weapon_carbinerifle_mk2), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_carbinerifle_mk2, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_ceramicpistol, sizeof(FiveM_Weapons::weapon_ceramicpistol), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_ceramicpistol, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_combatmg, sizeof(FiveM_Weapons::weapon_combatmg), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_combatmg, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_combatmg_mk2, sizeof(FiveM_Weapons::weapon_combatmg_mk2), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_combatmg_mk2, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_combatpdw, sizeof(FiveM_Weapons::weapon_combatpdw), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_combatpdw, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_combatpistol, sizeof(FiveM_Weapons::weapon_combatpistol), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_combatpistol, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_combatshotgun, sizeof(FiveM_Weapons::weapon_combatshotgun), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_combatshotgun, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_compactlauncher, sizeof(FiveM_Weapons::weapon_compactlauncher), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_compactlauncher, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_compactrifle, sizeof(FiveM_Weapons::weapon_compactrifle), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_compactrifle, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_crowbar, sizeof(FiveM_Weapons::weapon_crowbar), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_crowbar, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_dagger, sizeof(FiveM_Weapons::weapon_dagger), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_dagger, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_dbshotgun, sizeof(FiveM_Weapons::weapon_dbshotgun), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_dbshotgun, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_doubleaction, sizeof(FiveM_Weapons::weapon_doubleaction), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_doubleaction, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_fireextinguisher, sizeof(FiveM_Weapons::weapon_fireextinguisher), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_fireextinguisher, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_firework, sizeof(FiveM_Weapons::weapon_firework), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_firework, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_flare, sizeof(FiveM_Weapons::weapon_flare), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_flare, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_flaregun, sizeof(FiveM_Weapons::weapon_flaregun), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_flaregun, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_flashlight, sizeof(FiveM_Weapons::weapon_flashlight), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_flashlight, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_gadgetpistol, sizeof(FiveM_Weapons::weapon_gadgetpistol), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_gadgetpistol, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_golfclub, sizeof(FiveM_Weapons::weapon_golfclub), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_golfclub, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_grenade, sizeof(FiveM_Weapons::weapon_grenade), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_grenade, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_grenadelauncher, sizeof(FiveM_Weapons::weapon_grenadelauncher), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_grenadelauncher, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_grenadelauncher_smoke, sizeof(FiveM_Weapons::weapon_grenadelauncher_smoke), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_grenadelauncher_smoke, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_gusenberg, sizeof(FiveM_Weapons::weapon_gusenberg), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_gusenberg, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_hammer, sizeof(FiveM_Weapons::weapon_hammer), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_hammer, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_hatchet, sizeof(FiveM_Weapons::weapon_hatchet), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_hatchet, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_hazardcan, sizeof(FiveM_Weapons::weapon_hazardcan), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_hazardcan, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_heavypistol, sizeof(FiveM_Weapons::weapon_heavypistol), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_heavypistol, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_heavyshotgun, sizeof(FiveM_Weapons::weapon_heavyshotgun), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_heavyshotgun, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_heavysniper, sizeof(FiveM_Weapons::weapon_heavysniper), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_heavysniper, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_hominglauncher, sizeof(FiveM_Weapons::weapon_hominglauncher), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_hominglauncher, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_knife, sizeof(FiveM_Weapons::weapon_knife), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_knife, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_knuckle, sizeof(FiveM_Weapons::weapon_knuckle), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_knuckle, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_machete, sizeof(FiveM_Weapons::weapon_machete), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_machete, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_machinepistol, sizeof(FiveM_Weapons::weapon_machinepistol), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_machinepistol, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_marksmanpistol, sizeof(FiveM_Weapons::weapon_marksmanpistol), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_marksmanpistol, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_marksmanrifle, sizeof(FiveM_Weapons::weapon_marksmanrifle), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_marksmanrifle, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_marksmanrifle_mk2, sizeof(FiveM_Weapons::weapon_marksmanrifle_mk2), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_marksmanrifle_mk2, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_mg, sizeof(FiveM_Weapons::weapon_mg), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_mg, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_microsmg, sizeof(FiveM_Weapons::weapon_microsmg), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_microsmg, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_militaryrifle, sizeof(FiveM_Weapons::weapon_militaryrifle), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_militaryrifle, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_minigun, sizeof(FiveM_Weapons::weapon_minigun), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_minigun, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_minismg, sizeof(FiveM_Weapons::weapon_minismg), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_minismg, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_molotov, sizeof(FiveM_Weapons::weapon_molotov), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_molotov, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_musket, sizeof(FiveM_Weapons::weapon_musket), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_musket, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_navyrevolver, sizeof(FiveM_Weapons::weapon_navyrevolver), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_navyrevolver, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_nightstick, sizeof(FiveM_Weapons::weapon_nightstick), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_nightstick, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_petrolcan, sizeof(FiveM_Weapons::weapon_petrolcan), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_petrolcan, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_pipebomb, sizeof(FiveM_Weapons::weapon_pipebomb), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_pipebomb, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_pistol, sizeof(FiveM_Weapons::weapon_pistol), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_pistol, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_pistol50, sizeof(FiveM_Weapons::weapon_pistol50), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_pistol50, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_pistol_mk2, sizeof(FiveM_Weapons::weapon_pistol_mk2), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_pistol_mk2, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_poolcue, sizeof(FiveM_Weapons::weapon_poolcue), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_poolcue, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_proxmine, sizeof(FiveM_Weapons::weapon_proxmine), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_proxmine, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_pumpshotgun, sizeof(FiveM_Weapons::weapon_pumpshotgun), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_pumpshotgun, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_pumpshotgun_mk2, sizeof(FiveM_Weapons::weapon_pumpshotgun_mk2), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_pumpshotgun_mk2, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_railgun, sizeof(FiveM_Weapons::weapon_railgun), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_railgun, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_raycarbine, sizeof(FiveM_Weapons::weapon_raycarbine), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_raycarbine, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_rayminigun, sizeof(FiveM_Weapons::weapon_rayminigun), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_rayminigun, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_raypistol, sizeof(FiveM_Weapons::weapon_raypistol), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_raypistol, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_revolver, sizeof(FiveM_Weapons::weapon_revolver), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_revolver, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_revolver_mk2, sizeof(FiveM_Weapons::weapon_revolver_mk2), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_revolver_mk2, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_rpg, sizeof(FiveM_Weapons::weapon_rpg), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_rpg, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_sawnoffshotgun, sizeof(FiveM_Weapons::weapon_sawnoffshotgun), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_sawnoffshotgun, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_smg, sizeof(FiveM_Weapons::weapon_smg), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_smg, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_smg_mk2, sizeof(FiveM_Weapons::weapon_smg_mk2), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_smg_mk2, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_smokegrenade, sizeof(FiveM_Weapons::weapon_smokegrenade), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_smokegrenade, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_sniperrifle, sizeof(FiveM_Weapons::weapon_sniperrifle), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_sniperrifle, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_snowball, sizeof(FiveM_Weapons::weapon_snowball), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_snowball, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_snspistol, sizeof(FiveM_Weapons::weapon_snspistol), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_snspistol, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_snspistol_mk2, sizeof(FiveM_Weapons::weapon_snspistol_mk2), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_snspistol_mk2, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_specialcarbine, sizeof(FiveM_Weapons::weapon_specialcarbine), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_specialcarbine, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_specialcarbine_mk2, sizeof(FiveM_Weapons::weapon_specialcarbine_mk2), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_specialcarbine_mk2, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_stickybomb, sizeof(FiveM_Weapons::weapon_stickybomb), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_stickybomb, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_stone_hatchet, sizeof(FiveM_Weapons::weapon_stone_hatchet), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_stone_hatchet, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_stungun, sizeof(FiveM_Weapons::weapon_stungun), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_stungun, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_switchblade, sizeof(FiveM_Weapons::weapon_switchblade), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_switchblade, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_unarmed, sizeof(FiveM_Weapons::weapon_unarmed), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_unarmed, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_vintagepistol, sizeof(FiveM_Weapons::weapon_vintagepistol), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_vintagepistol, 0);
			D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, FiveM_Weapons::weapon_wrench, sizeof(FiveM_Weapons::weapon_wrench), &Info, Pump, &g_Variables.FiveM_WeaponsPic.weapon_wrench, 0);
		}
		*/
	}
}

