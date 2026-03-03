@echo off
setlocal enabledelayedexpansion

echo ============================================
echo   LiKinho Executor - Master Build
echo ============================================
echo.

set "VCVARS="

where cl >nul 2>&1
if %ERRORLEVEL% EQU 0 goto :setup_env_done

echo [*] Searching for Visual Studio...
if exist "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat"
)

if not defined VCVARS (
    echo [ERROR] Visual Studio not found.
    :: pause
    exit /b 1
)

echo [*] Initializing VS Environment...
call "%VCVARS%" x64

:setup_env_done

echo.
echo [1/4] Building FiveM Executor (DLL)...
cd Executor
msbuild "ImGui DirectX 11 Kiero Hook.vcxproj" /p:Configuration=Release /p:Platform=x64 /t:Rebuild
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Executor build failed.
    :: pause
    exit /b 1
)
cd ..
copy /y "Executor\x64\Release\d3d10.dll" "LK_Executor_embed.dll"

echo.
echo [2/4] Building Fivem Menu (DLL)...
cd Menu
msbuild "src\src.vcxproj" /p:Configuration=Release /p:Platform=x64 /t:Rebuild
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Menu build failed.
    :: pause
    exit /b 1
)
cd ..
copy /y "Menu\src\x64\Release\Loader.dll" "MenuLoader.dll"
copy /y "Menu\src\x64\Release\D3DCompiler_43.dll" "D3DCompiler_43.dll"
copy /y "Menu\src\x64\Release\d3dx9_43.dll" "d3dx9_43.dll"
copy /y "Menu\src\x64\Release\d3dx10_43.dll" "d3dx10_43.dll"
copy /y "Menu\src\x64\Release\d3dx11_43.dll" "d3dx11_43.dll"

:: DLLs de dependencia ficam embutidas no recurso do LoaderLK.exe
:: Sao injetadas 100% da memoria â€” sem extrair arquivos para o disco

echo.
echo [3/4] Generating Version and Compiling Resources...

:: Generate Random Build Code (1000-9999)
set /a BUILD_CODE=%RANDOM% * (9999 - 1000 + 1) / 32768 + 1000
echo #pragma once > Version.h
echo #define LOADER_VERSION "%BUILD_CODE%" >> Version.h
echo.
echo [INFO] Generated Version Code: %BUILD_CODE%
echo.

rc /nologo resource.rc

echo.
echo [4/4] Compiling LoaderLK...
set IMGUI_DIR=Executor\imgui

cl /nologo /MT /EHsc /std:c++20 /O2 /utf-8 /I"%IMGUI_DIR%" /D "WIN32" /D "_WINDOWS" /D "NDEBUG" /c main.cpp
if %errorlevel% neq 0 exit /b %errorlevel%

echo Compiling ImGui...
cl /nologo /MT /EHsc /std:c++20 /O2 /I"%IMGUI_DIR%" /D "WIN32" /D "_WINDOWS" /D "NDEBUG" /FI"algorithm" /c "%IMGUI_DIR%\imgui.cpp"
if %errorlevel% neq 0 exit /b %errorlevel%

cl /nologo /MT /EHsc /std:c++20 /O2 /I"%IMGUI_DIR%" /D "WIN32" /D "_WINDOWS" /D "NDEBUG" /FI"algorithm" /c "%IMGUI_DIR%\imgui_draw.cpp"
if %errorlevel% neq 0 exit /b %errorlevel%

cl /nologo /MT /EHsc /std:c++20 /O2 /I"%IMGUI_DIR%" /D "WIN32" /D "_WINDOWS" /D "NDEBUG" /FI"algorithm" /c "%IMGUI_DIR%\imgui_widgets.cpp"
if %errorlevel% neq 0 exit /b %errorlevel%

cl /nologo /MT /EHsc /std:c++20 /O2 /I"%IMGUI_DIR%" /D "WIN32" /D "_WINDOWS" /D "NDEBUG" /FI"algorithm" /c "%IMGUI_DIR%\imgui_impl_dx11.cpp"
if %errorlevel% neq 0 exit /b %errorlevel%

cl /nologo /MT /EHsc /std:c++20 /O2 /I"%IMGUI_DIR%" /D "WIN32" /D "_WINDOWS" /D "NDEBUG" /FI"algorithm" /c "%IMGUI_DIR%\imgui_impl_win32.cpp"
if %errorlevel% neq 0 exit /b %errorlevel%

echo Linking...
link /nologo /SUBSYSTEM:WINDOWS /MACHINE:X64 /OUT:LoaderLK.exe /MANIFESTUAC:"level='requireAdministrator' uiAccess='false'" ^
    main.obj imgui.obj imgui_draw.obj imgui_widgets.obj imgui_impl_dx11.obj imgui_impl_win32.obj resource.res ^
    d3d11.lib dxgi.lib winhttp.lib ole32.lib windowscodecs.lib user32.lib gdi32.lib dwmapi.lib winmm.lib advapi32.lib shell32.lib gdiplus.lib urlmon.lib

echo.
echo [DONE] build_lite.bat removed - all features consolidated in LoaderLK.

:: LKstarter removido â€” LoaderLK.exe agora e standalone (nao precisa de bootstrap)
:: O inject funciona 100% da memoria do LoaderLK.exe
echo.
echo [OK] Build concluido. Apenas LoaderLK.exe e necessario para distribuicao.

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ============================================
    echo [SUCCESS] Master build complete!
    echo LoaderLK.exe built successfully.
    echo Inject 100%% in-memory â€” sem arquivos em disco
    echo ============================================
    del /q *.obj >nul 2>&1
    del /q resource.res >nul 2>&1
    del /q Version.h >nul 2>&1
) else (
    echo.
    echo [ERROR] Loader compilation failed.
)

:: pause

