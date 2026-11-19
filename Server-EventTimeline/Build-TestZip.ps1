#Requires -Version 5.1
<#
.SYNOPSIS
    Builds Server-EventTimeline.zip: the tool's files, ready to copy to a test server.

.DESCRIPTION
    Puts the scripts the tool needs and its README in a Server-EventTimeline folder inside
    the zip, with BUILD.txt saying which commit it came from and when, so you can tell which
    version is on a test server. Extract the zip on the server and run
    Start-ServerEventTimeline.ps1 from the extracted folder.

    The files come from a fixed list, never "everything in the folder": the Reports folder
    beside the script holds client data and must not travel. The tests check that the list
    covers every .ps1 in the folder, so a new script can't be left out.

    The zip is replaced on each build. *.zip and dist\ are in .gitignore.

.PARAMETER OutputPath
    Where to write Server-EventTimeline.zip. Default: dist\ at the repository root.

.EXAMPLE
    .\Build-TestZip.ps1
    Writes dist\Server-EventTimeline.zip at the repository root and prints its path.

.EXAMPLE
    .\Build-TestZip.ps1 -OutputPath C:\Temp
    Writes C:\Temp\Server-EventTimeline.zip.

.NOTES
    Read-only on the tool folder. Uses System.IO.Compression.ZipFile (.NET Framework 4.5+),
    which ships with Windows PowerShell 5.1.

    REFERENCES
    - ZipFile.CreateFromDirectory:
      https://learn.microsoft.com/dotnet/api/system.io.compression.zipfile.createfromdirectory
#>
[CmdletBinding()]
param(
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
# Worked out here, not as the parameter's default: Windows PowerShell 5.1 leaves $PSScriptRoot
# empty while parameter defaults are evaluated.
if (-not $OutputPath) { $OutputPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'dist' }

# Everything the tool needs on a server. Add a new script here (the tests will remind you).
$files = @(
    'Start-ServerEventTimeline.ps1'
    'ServerEventTimeline.Core.ps1'
    'ServerEventTimeline.Engine.ps1'
    'ServerEventTimeline.ServerList.ps1'
    'ServerEventTimeline.AddServersDialog.ps1'
    'ServerEventTimeline.Story.ps1'
    'CaseKit.ps1'
    'README.md'
)

$commit = 'unknown'
$note = ''
try {
    $c = & git -C $PSScriptRoot rev-parse --short HEAD 2>$null
    if ($LASTEXITCODE -eq 0 -and $c) { $commit = [string]$c }
    $dirty = & git -C $PSScriptRoot status --porcelain -- . 2>$null
    if ($LASTEXITCODE -eq 0 -and $dirty) { $note = ' (plus uncommitted changes)' }
}
catch { }

$stage = Join-Path ([System.IO.Path]::GetTempPath()) ('SETZip_' + [guid]::NewGuid().ToString('N'))
$folder = Join-Path $stage 'Server-EventTimeline'
try {
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    foreach ($f in $files) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $f) -Destination $folder }
    $built = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $info = @(
        'Server Event Timeline - test build'
        "Commit: $commit$note"
        "Built: $built"
        ''
        'Run Start-ServerEventTimeline.ps1 from this folder. Keep the files together.'
    )
    Set-Content -LiteralPath (Join-Path $folder 'BUILD.txt') -Value $info -Encoding UTF8

    if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
    $zip = Join-Path (Resolve-Path -LiteralPath $OutputPath).ProviderPath 'Server-EventTimeline.zip'
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($folder, $zip, [System.IO.Compression.CompressionLevel]::Optimal, $true)
    Write-Host "[PASS] Built $zip (commit $commit$note)" -ForegroundColor Green
    $zip
}
finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
