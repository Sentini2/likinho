$path = 'd:\Projetos 2\LiKinho Exec\LoginPanel\Menu\src\Includes\CustomWidgets\Preview.hpp'
$content = Get-Content -Path $path -Raw
$find = 'iBox_Y = ImGui::GetWindowPos( ).y + ImGui::GetWindowSize( ).y / 2 - iBox_Height / 2;'
$replace = 'iBox_Y = ImGui::GetWindowPos( ).y + ImGui::GetWindowSize( ).y / 2 - iBox_Height / 2;' + "`r`n`r`n`t`t`tif (g_Variables.NpcImage) {`r`n`t`t`t`tImGui::GetWindowDrawList()->AddImage((void*)g_Variables.NpcImage, ImVec2(iBox_X, iBox_Y), ImVec2(iBox_X + iBox_Width, iBox_Y + iBox_Height));`r`n`t`t`t}"
$content = $content.Replace($find, $replace)
Set-Content -Path $path -Value $content -Encoding UTF8
