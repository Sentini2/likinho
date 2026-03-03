@echo off
echo Building FiveM Executor DLL...
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
msbuild "ImGui DirectX 11 Kiero Hook.vcxproj" /p:Configuration=Release /p:Platform=x64
