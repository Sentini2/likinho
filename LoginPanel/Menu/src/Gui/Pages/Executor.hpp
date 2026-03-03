#pragma once
#include "../../../../SharedExecutor.hpp"
#include <Includes/TextEditor.h>
#include <Utils/LuaObfuscator.hpp>
#include <fstream>

namespace Executor {

	inline HANDLE hSharedMem = NULL;
	inline SharedExecutorData* pShared = nullptr;
	inline bool sharedInitialized = false;
	inline bool isObfuscating = false;
	inline std::string obfuscationStatus = "";

	// TextEditor
	inline TextEditor editor;
	inline bool editorInitialized = false;

	inline void InitSharedMemory()
	{
		// Retry every time if not yet connected (DLL may not be injected yet)
		if (sharedInitialized && pShared && pShared->dllReady) return;

		if (hSharedMem == NULL || hSharedMem == INVALID_HANDLE_VALUE)
		{
			hSharedMem = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, SHARED_MEM_NAME);
		}

		if (hSharedMem && !pShared)
		{
			pShared = (SharedExecutorData*)MapViewOfFile(hSharedMem, FILE_MAP_ALL_ACCESS, 0, 0, SHARED_MEM_SIZE);
		}

		if (hSharedMem && pShared)
		{
			sharedInitialized = true;
		}
	}

	inline void InitializeEditor()
	{
		if (editorInitialized) return;

		// Set Lua language with galaxy theme
		TextEditor::LanguageDefinition lang = TextEditor::LanguageDefinition::Lua();
		editor.SetLanguageDefinition(lang);
		
		// Apply themed palette
		TextEditor::Palette themePalette = TextEditor::GetDarkPalette();
		themePalette[(int)TextEditor::PaletteIndex::Default] = 0xFFE5E5E5;
		themePalette[(int)TextEditor::PaletteIndex::Background] = 0xFF0F0F12;
		themePalette[(int)TextEditor::PaletteIndex::Cursor] = ImGui::ColorConvertFloat4ToU32(activeTheme.accent);
		themePalette[(int)TextEditor::PaletteIndex::Selection] = 0xFF804020;

		if (currentTheme == Theme::LiKinho) {
			themePalette[(int)TextEditor::PaletteIndex::Keyword] = 0xFFFF8833;
			themePalette[(int)TextEditor::PaletteIndex::Number] = 0xFFFFAA55;
		}
		else {
			themePalette[(int)TextEditor::PaletteIndex::Keyword] = 0xFFBB66FF;
			themePalette[(int)TextEditor::PaletteIndex::Number] = 0xFFDD99FF;
		}

		themePalette[(int)TextEditor::PaletteIndex::String] = 0xFF88DD66;
		themePalette[(int)TextEditor::PaletteIndex::CharLiteral] = 0xFF99EE77;
		themePalette[(int)TextEditor::PaletteIndex::Identifier] = 0xFFE5E5E5;
		themePalette[(int)TextEditor::PaletteIndex::Comment] = 0xFF888888;
		themePalette[(int)TextEditor::PaletteIndex::MultiLineComment] = 0xFF888888;
		themePalette[(int)TextEditor::PaletteIndex::Preprocessor] = ImGui::ColorConvertFloat4ToU32(activeTheme.primary);
		themePalette[(int)TextEditor::PaletteIndex::ErrorMarker] = 0xFFFF3333;
		themePalette[(int)TextEditor::PaletteIndex::Breakpoint] = 0xFFDD3333;
		themePalette[(int)TextEditor::PaletteIndex::LineNumber] = 0xFF606060;
		themePalette[(int)TextEditor::PaletteIndex::CurrentLineFill] = 0x33FFFFFF;
		themePalette[(int)TextEditor::PaletteIndex::CurrentLineFillInactive] = 0x11FFFFFF;

		editor.SetPalette(themePalette);
		editor.SetShowWhitespaces(false);

		std::string defaultScript =
			"-- LiKinho On Top\n"
			"print(\"Dev by Nippy!\")\n";
		editor.SetText(defaultScript);

		editorInitialized = true;
	}

	inline void Render()
	{
		InitSharedMemory();
		InitializeEditor();

		bool dllConnected = (pShared && pShared->dllReady);

		// === FULL SCREEN EDITOR - Fills entire menu! ===
		editor.Render("##LuaEditor", ImVec2(-1, -60));

		// === BOTTOM BAR ===
		ImGui::Spacing();
		
		// Execute button (theme colored)
		ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(activeTheme.primary.x, activeTheme.primary.y, activeTheme.primary.z, 0.9f));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, activeTheme.secondary);
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, activeTheme.accent);
		
		if (ImGui::Button(Lang("Execute", "Executar"), ImVec2(120, 28)))
		{
			if (dllConnected)
			{
				std::string script = editor.GetText();
				if (!script.empty())
				{
					// Send script to DLL via shared memory
					strncpy_s(pShared->scriptBuffer, sizeof(pShared->scriptBuffer), script.c_str(), _TRUNCATE);
					strncpy_s(pShared->customPrefix, sizeof(pShared->customPrefix), "likinho", _TRUNCATE);
					pShared->selectedResource = 0;
					pShared->executeFlag = true;
				}
			}
		}
		ImGui::PopStyleColor(3);

		ImGui::SameLine();

		// Clear button
		if (ImGui::Button(Lang("Clear", "Limpar"), ImVec2(70, 28)))
		{
			editor.SetText("");
		}

		ImGui::SameLine();

		// Reset button (uninject)
		if (ImGui::Button(Lang("\xEF\x87\xB8 Reset", "\xEF\x87\xB8 Resetar"), ImVec2(85, 28)))
		{
			if (dllConnected)
			{
				pShared->resetFlag = true;
			}
		}

		ImGui::SameLine();

		// Import Lua button
		if (ImGui::Button(Lang("Import", "Importar"), ImVec2(80, 28)))
		{
			// Close menu and minimize FiveM so dialog appears outside game
			g_MenuInfo.IsOpen = false;
			ShowWindow(g_Variables.g_hGameWindow, SW_MINIMIZE);
			Sleep(100);
			
			OPENFILENAMEA ofn;
			char szFile[260] = { 0 };
			ZeroMemory(&ofn, sizeof(ofn));
			ofn.lStructSize = sizeof(ofn);
			ofn.hwndOwner = NULL;
			ofn.lpstrFile = szFile;
			ofn.nMaxFile = sizeof(szFile);
			ofn.lpstrFilter = "Lua Files\0*.lua\0All Files\0*.*\0";
			ofn.nFilterIndex = 1;
			ofn.lpstrFileTitle = NULL;
			ofn.nMaxFileTitle = 0;
			ofn.lpstrInitialDir = NULL;
			ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_ENABLESIZING;

			if (GetOpenFileNameA(&ofn))
			{
				std::ifstream file(ofn.lpstrFile, std::ios::binary | std::ios::ate);
				if (file.is_open())
				{
					std::streamsize size = file.tellg();
					file.seekg(0, std::ios::beg);
					std::string content;
					content.resize(size);
					if (file.read(&content[0], size))
					{
						editor.SetText(content);
					}
					file.close();
				}
			}
			
			ShowWindow(g_Variables.g_hGameWindow, SW_RESTORE);
			SetForegroundWindow(g_Variables.g_hGameWindow);
			Sleep(100);
			g_MenuInfo.IsOpen = true;
		}

		// Space at the bottom
		ImGui::Spacing();
	}
}


