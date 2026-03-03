$files = Get-ChildItem -Path "d:\Projetos 2\LiKinho Exec\LoginPanel" -Include *.cpp,*.hpp,*.h -Recurse
foreach ($f in $files) {
    if ($f.FullName -match "vendor|libs|imgui") { continue }
    $content = Get-Content -Raw $f.FullName
    
    # Proteger a URL
    $content = $content -creplace 'sentini555', '@@@URL@@@'
    
    $newContent = $content -creplace 'Sentini', 'LiKinho' `
                           -creplace 'sentini', 'likinho' `
                           -creplace 'SENTINI', 'LIKINHO'
                           
    # Restaurar a URL
    $newContent = $newContent -creplace '@@@URL@@@', 'sentini555'
    
    if ($content -ne $newContent) {
        Write-Host "Modified: $($f.FullName)"
        Set-Content -Path $f.FullName -Value $newContent
    }
}
Write-Host "Done"
