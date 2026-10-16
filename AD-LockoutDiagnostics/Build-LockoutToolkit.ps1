# Compress-Archive is a 5.0 cmdlet; this runs on the admin's workstation, not on servers.
#Requires -Version 5.1

<#
.SYNOPSIS
    Builds AD-Lockout-Diagnostics.zip, the single-folder copy of the lockout toolkit that is
    handed to technicians.

.DESCRIPTION
    The toolkit spans two folders in this repository: this one, and three scripts from
    AD-AuthSourceEvidence that the investigation runs as steps 6-7 (and the live watcher).
    The zip puts them all in ONE flat folder - Invoke-ADLockoutInvestigation.ps1 looks for
    its companions beside itself first (Resolve-CompanionScript), so the flat copy works
    with no path setup.

    The zip used to be assembled by hand and drifted badly: the copy replaced by this
    script dated from 2026-08-27 and was missing the device timeline step entirely.
    Building it from the manifest below means a rebuild is one command and always matches
    the repository.

    Only files tracked by git are copied. The tools write case folders (Case_*), CSVs and
    HTML reports beside themselves, and those contain client AD data - they must never end
    up in a zip that gets passed around. Tests, zips and this script are left out.

    Copies come from the working tree, so uncommitted edits to tracked files are included.
    Commit first if the zip must match a pushed version.

.PARAMETER OutputPath
    Folder to write AD-Lockout-Diagnostics.zip into. Defaults to this script's folder, where
    the zip has always lived.

.PARAMETER Force
    Replace an existing zip without prompting.

.EXAMPLE
    .\AD-LockoutDiagnostics\Build-LockoutToolkit.ps1 -Force

    Rebuilds AD-LockoutDiagnostics\AD-Lockout-Diagnostics.zip in place.

.EXAMPLE
    .\AD-LockoutDiagnostics\Build-LockoutToolkit.ps1 -OutputPath C:\Temp

    Writes C:\Temp\AD-Lockout-Diagnostics.zip, asking first if one is already there.

.NOTES
    Requires git on PATH and must be run from a clone of this repository.
    To add a file from another folder, add it to $companions below. Files added to this
    folder are picked up automatically once they are tracked by git.
    Tests\Build-LockoutToolkit.Tests.ps1 checks that every companion script the
    investigation resolves is in $companions.

    REFERENCES
      Compress-Archive: https://learn.microsoft.com/powershell/module/microsoft.powershell.archive/compress-archive
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Write-Status {
    param([ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Level, [string]$Message)
    $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$Level]
    Write-Host "[$Level] $Message" -ForegroundColor $color
}

# Files from other folders, relative to the repository root. Everything git tracks at the
# top level of this folder is included as well (see $excludePatterns).
$companions = @(
    'AD-AuthSourceEvidence/Export-ADAuthSourceEvidence.ps1'   # step 6 - which machine
    'AD-AuthSourceEvidence/Get-LockoutCause.ps1'              # step 7 - what to fix
    'AD-AuthSourceEvidence/Watch-ADLockoutActivity.ps1'       # live watcher
)

# Matched against the file name of each top-level file in this folder.
$excludePatterns = @(
    '\.zip$'
    '^Build-LockoutToolkit\.ps1$'
)

$zipName  = 'AD-Lockout-Diagnostics.zip'
$repoRoot = Split-Path -Parent $PSScriptRoot
$folder   = Split-Path -Leaf $PSScriptRoot

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Status FAIL 'git was not found on PATH. The build copies only git-tracked files, so it needs git.'
    exit 1
}

if (-not $OutputPath) { $OutputPath = $PSScriptRoot }
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$zipPath = Join-Path $OutputPath $zipName

if (Test-Path -LiteralPath $zipPath) {
    if (-not $Force) {
        $answer = Read-Host "$zipPath already exists. Replace it? (y/N)"
        if ($answer -notmatch '^[Yy]') { Write-Status WARN 'Nothing was changed.'; exit 1 }
    }
}

# git writes paths as UTF-8; PowerShell decodes native output with the OEM code page unless
# told otherwise, which mangles non-ASCII names. -z keeps names with spaces intact.
$previousEncoding = [Console]::OutputEncoding
try {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
    $tracked = @((& git -C $repoRoot ls-files -z -- $folder @companions) -split "`0" | Where-Object { $_ })
} finally {
    [Console]::OutputEncoding = $previousEncoding
}
if ($LASTEXITCODE -ne 0) { Write-Status FAIL 'git ls-files failed.'; exit 1 }

$files = @($tracked | Where-Object {
    $rel = $_
    if ($companions -contains $rel) { return $true }
    # Top level of this folder only: subfolders are Tests and local run output.
    $name = $rel.Substring($folder.Length + 1)
    if ($name -match '/') { return $false }
    -not ($excludePatterns | Where-Object { $name -match $_ })
})

foreach ($c in $companions) {
    if ($tracked -notcontains $c) { Write-Status FAIL "Companion not tracked by git: $c"; exit 1 }
}

$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("LockoutToolkit_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage -Force | Out-Null
try {
    $names = @{}
    foreach ($rel in $files) {
        $source = Join-Path $repoRoot $rel
        if (-not (Test-Path -LiteralPath $source)) { Write-Status WARN "Tracked but missing from the working tree, skipped: $rel"; continue }
        $leaf = Split-Path -Leaf $rel
        # A flat folder cannot hold two files with one name; stop rather than overwrite.
        if ($names.ContainsKey($leaf)) { Write-Status FAIL "Two files would both be '$leaf' in the flat zip: $($names[$leaf]) and $rel"; exit 1 }
        $names[$leaf] = $rel
        Copy-Item -LiteralPath $source -Destination (Join-Path $stage $leaf) -Force
    }

    if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zipPath -CompressionLevel Optimal -Force
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}

foreach ($leaf in ($names.Keys | Sort-Object)) { Write-Status INFO ("  {0,-48} <- {1}" -f $leaf, $names[$leaf]) }
$hash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Status PASS "$($names.Count) file(s) in $zipPath"
Write-Status PASS "SHA-256: $hash"
