# install.ps1 | Author: klahack | MIT License
$REPO_RAW = if ($env:KLAHACK_PORTSCOPE_REPO_RAW) { $env:KLAHACK_PORTSCOPE_REPO_RAW } else { 'https://raw.githubusercontent.com/klahack/klahack-portscope/main' }
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$Tool = 'klahack-portscope'
$InstallDir = Join-Path $env:LOCALAPPDATA $Tool
$SourceName = 'klahack_portscope.py'
$ChecksumName = 'SHA256SUMS'

function Find-CompatiblePython {
    $Candidates = @(
        [PSCustomObject]@{ Name = 'py'; Prefix = @('-3') },
        [PSCustomObject]@{ Name = 'python'; Prefix = @() }
    )
    foreach ($Candidate in $Candidates) {
        $Command = Get-Command $Candidate.Name -ErrorAction SilentlyContinue
        if ($null -eq $Command) {
            continue
        }
        try {
            $Arguments = @($Candidate.Prefix) + @(
                '-c',
                'import sys; print("%d.%d" % sys.version_info[:2]); raise SystemExit(0 if sys.version_info >= (3, 8) else 1)'
            )
            $Version = & $Command.Source @Arguments 2>$null
            if ($LASTEXITCODE -eq 0 -and $Version -match '^\d+\.\d+$') {
                return [PSCustomObject]@{
                    Command = $Command.Source
                    Prefix = $Candidate.Prefix
                    Version = $Version
                }
            }
        }
        catch {
            continue
        }
    }
    return $null
}

$Python = Find-CompatiblePython
if ($null -eq $Python) {
    Write-Host "[$Tool] Python 3.8+ was not found; installing Python 3.12 with winget."
    $Winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($null -eq $Winget) {
        throw 'Python 3.8+ is required and winget is unavailable. Install Python, disable the Microsoft Store alias if necessary, and retry.'
    }
    & $Winget.Source install --id Python.Python.3.12 --exact --source winget --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) {
        throw 'winget could not install Python 3.12.'
    }
    $MachinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $RefreshedUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$MachinePath;$RefreshedUserPath"
    $Python = Find-CompatiblePython
    if ($null -eq $Python) {
        throw 'Python was installed but is not visible yet. Open a new terminal and rerun this installer.'
    }
}
Write-Host "[$Tool] Using Python $($Python.Version)."

$TempDir = Join-Path ([IO.Path]::GetTempPath()) ("klahack-portscope-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
try {
    $SourcePath = Join-Path $TempDir $SourceName
    $ChecksumPath = Join-Path $TempDir $ChecksumName
    $Base = $REPO_RAW.TrimEnd('/')
    Write-Host "[$Tool] Downloading scanner and checksum list."
    Invoke-WebRequest -UseBasicParsing -Uri "$Base/$SourceName" -OutFile $SourcePath
    Invoke-WebRequest -UseBasicParsing -Uri "$Base/$ChecksumName" -OutFile $ChecksumPath

    $ChecksumLine = Get-Content -LiteralPath $ChecksumPath | Where-Object {
        $_ -match '\s\*?klahack_portscope\.py$'
    } | Select-Object -First 1
    if (-not $ChecksumLine) {
        throw "$ChecksumName does not contain a checksum for $SourceName."
    }
    $Expected = ($ChecksumLine.Trim() -split '\s+')[0].ToLowerInvariant()
    $Actual = (Get-FileHash -LiteralPath $SourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Expected -ne $Actual) {
        throw 'SHA256 verification failed; refusing to install.'
    }
    Write-Host "[$Tool] SHA256 verification passed."

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item -LiteralPath $SourcePath -Destination (Join-Path $InstallDir $SourceName) -Force

    $PrefixText = if ($Python.Prefix.Count -gt 0) { ($Python.Prefix -join ' ') + ' ' } else { '' }
    $EscapedPython = $Python.Command.Replace('"', '""')
    $Wrapper = @"
@echo off
"$EscapedPython" $PrefixText"%~dp0$SourceName" %*
"@
    $WrapperPath = Join-Path $InstallDir "$Tool.cmd"
    Set-Content -LiteralPath $WrapperPath -Value $Wrapper -Encoding ASCII

    $UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $Entries = @()
    if ($UserPath) {
        $Entries = @($UserPath -split ';' | Where-Object { $_ })
    }
    $NormalizedInstall = $InstallDir.TrimEnd('\')
    $AlreadyPresent = $false
    foreach ($Entry in $Entries) {
        if ($Entry.Trim().TrimEnd('\') -ieq $NormalizedInstall) {
            $AlreadyPresent = $true
            break
        }
    }
    if (-not $AlreadyPresent) {
        $NewPath = (@($Entries) + @($InstallDir)) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $NewPath, 'User')
    }
    if (($env:Path -split ';') -notcontains $InstallDir) {
        $env:Path = "$InstallDir;$env:Path"
    }

    Write-Host "[$Tool] Installed idempotently at $InstallDir."
    & $WrapperPath --version
    if ($LASTEXITCODE -ne 0) {
        throw 'Installation verification failed.'
    }
    Write-Host "[$Tool] Installation verified. Open a new terminal before using $Tool."
}
finally {
    Remove-Item -LiteralPath $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
return
