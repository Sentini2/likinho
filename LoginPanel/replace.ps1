$files = Get-ChildItem -Path "d:\Projetos 2\LiKinho Exec\LoginPanel" -Include *.cpp,*.hpp,*.h -Recurse
foreach ($f in $files) {
    if ($f.FullName -match "vendor|libs|imgui") { continue }
    $content = Get-Content -Raw $f.FullName
    $newContent = $content -creplace 'LiKinho', 'Sentini' `
                           -creplace 'Likinho', 'Sentini' `
                           -creplace 'likinho', 'sentini' `
                           -creplace 'LIKINHO', 'SENTINI'
    if ($content -ne $newContent) {
        Write-Host "Modified: $($f.FullName)"
        Set-Content -Path $f.FullName -Value $newContent
    }
}
Write-Host "Done"
