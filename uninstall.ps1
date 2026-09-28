# uninstall.ps1 | Author: klahack | MIT License
$ErrorActionPreference = 'Stop'

$Tool = 'klahack-portscope'
$InstallDir = Join-Path $env:LOCALAPPDATA $Tool
$NormalizedInstall = $InstallDir.TrimEnd('\')

if (Test-Path -LiteralPath $InstallDir) {
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
    Write-Host "[$Tool] Removed $InstallDir."
}
else {
    Write-Host "[$Tool] Installation folder is already absent."
}

$UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($UserPath) {
    $KeptEntries = @($UserPath -split ';' | Where-Object {
        $_ -and $_.Trim().TrimEnd('\') -ine $NormalizedInstall
    })
    [Environment]::SetEnvironmentVariable('Path', ($KeptEntries -join ';'), 'User')
}
$CurrentEntries = @($env:Path -split ';' | Where-Object {
    $_ -and $_.Trim().TrimEnd('\') -ine $NormalizedInstall
})
$env:Path = $CurrentEntries -join ';'

Write-Host "[$Tool] Uninstall complete. Open a new terminal to use the updated PATH."
return
