#Requires -Version 5.1

<#
.SYNOPSIS
    Builds the Service Desk Escalation Toolkit bundle from the tool folders in this repository.

.DESCRIPTION
    The ServiceDesk-Toolkit bundle is a curated copy of about ten tools from this repository,
    laid out for service desk staff with a single START HERE page (README.md next to this
    script). Keeping hand-made copies in git meant they drifted from the real tools, so the
    bundle is generated instead and never committed.

    Only files tracked by git are copied. That keeps local run output (case folders,
    exports, logs that can contain client AD/tenant data) out of the bundle even when it
    is sitting in the tool folders. Pester tests, the workbench launcher source, .gitkeep
    placeholders and zips are left out; technicians don't need them.

    Copies are taken from the working tree, so uncommitted edits to tracked files are
    included. Commit first if the bundle must match a pushed version.

.PARAMETER OutputPath
    Folder the bundle is written into, as <OutputPath>\ServiceDesk-Toolkit. Defaults to
    the repository's dist folder (ignored by git). The usual current-directory default is
    not used because running from the repository root would collide with this folder.

.PARAMETER Zip
    Also create <OutputPath>\ServiceDesk-Toolkit.zip, ready to upload to SharePoint.

.PARAMETER Force
    Replace an existing bundle folder and zip at the output location without prompting.

.EXAMPLE
    .\ServiceDesk-Toolkit\Build-ServiceDeskToolkit.ps1

    Builds dist\ServiceDesk-Toolkit in the repository.

.EXAMPLE
    .\ServiceDesk-Toolkit\Build-ServiceDeskToolkit.ps1 -OutputPath C:\Temp -Zip -Force

    Rebuilds C:\Temp\ServiceDesk-Toolkit and C:\Temp\ServiceDesk-Toolkit.zip, replacing
    any previous build.

.NOTES
    Requires git on PATH and must be run from a clone of this repository.
    To add a tool to the bundle, add an entry to $manifest below and a row to the
    "Which tool do I run?" table in README.md.
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$Zip,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Write-Status {
    param([ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Level, [string]$Message)
    $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$Level]
    Write-Host "[$Level] $Message" -ForegroundColor $color
}

# Source is a folder or file relative to the repository root; Destination is relative to
# the bundle root. Folder entries copy every tracked file below them (minus $excludePatterns).
# The AD lockout and drive-map tools find their companions beside themselves (see
# Resolve-CompanionScript in Invoke-ADLockoutInvestigation.ps1). Those companions live in
# the same folder in the repo, so each toolkit ships as one folder entry.
$manifest = @(
    @{ Source = 'AD-LockoutDiagnostics';                                 Destination = 'AD-LockoutDiagnostics' }
    @{ Source = 'AD-GroupMembership-Export';                             Destination = 'AD-GroupMembership-Export' }
    @{ Source = 'Block 365 Sign-in';                                     Destination = 'Block 365 Sign-in' }
    @{ Source = 'Citrix-FSLogix-HealthCollector';                        Destination = 'Citrix-FSLogix-HealthCollector' }
    @{ Source = 'DriveMap-Diagnostics';                                  Destination = 'DriveMap-Diagnostics' }
    @{ Source = 'Get-AzureFilesFSLogixProfiles';                         Destination = 'Get-AzureFilesFSLogixProfiles' }
    @{ Source = 'Get-CitrixVDAResources';                                Destination = 'Get-CitrixVDAResources' }
    @{ Source = 'Get-RAM-Usage';                                         Destination = 'Get-RAM-Usage' }
    @{ Source = 'HideFromGal';                                           Destination = 'HideFromGal' }
    @{ Source = 'MSP-TroubleshootingWorkbench';                          Destination = 'MSP-TroubleshootingWorkbench' }
    @{ Source = 'RDS-FSLogix-EventExport';                               Destination = 'RDS-FSLogix-EventExport' }
    @{ Source = 'ServiceDesk-Toolkit/README.md';                         Destination = 'README.md' }
)

# Matched against the path relative to a folder entry, with forward slashes.
$excludePatterns = @(
    '(^|/)[Tt]ests/'    # Pester suites
    '^Build-[^/]+\.ps1$' # Repo build scripts (e.g. Build-LockoutToolkit.ps1); they need git
    '^launcher/'        # MSPWorkbench.exe source; the built exe is shipped
    '(^|/)\.gitkeep$'
    '\.zip$'
    '^Nerdio\d*\.ps1$'  # Scratch scripts in RDS-FSLogix-EventExport, not part of the tool
)

$repoRoot = Split-Path -Parent $PSScriptRoot

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Status FAIL 'git was not found on PATH. The build copies only git-tracked files, so it needs git.'
    exit 1
}

if (-not $OutputPath) { $OutputPath = Join-Path $repoRoot 'dist' }
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$bundleRoot = Join-Path $OutputPath 'ServiceDesk-Toolkit'
$zipPath = Join-Path $OutputPath 'ServiceDesk-Toolkit.zip'

if ($bundleRoot.TrimEnd('\') -ieq $PSScriptRoot.TrimEnd('\')) {
    Write-Status FAIL "The output would overwrite this script's own folder ($PSScriptRoot). Choose another -OutputPath."
    exit 1
}

foreach ($existing in @($bundleRoot, $zipPath)) {
    if (-not (Test-Path -LiteralPath $existing)) { continue }
    if ($existing -eq $zipPath -and -not $Zip) { continue }
    if (-not $Force) {
        $answer = Read-Host "$existing already exists. Replace it? (y/N)"
        if ($answer -notmatch '^[Yy]') {
            Write-Status WARN 'Nothing was changed.'
            exit 1
        }
    }
    Remove-Item -LiteralPath $existing -Recurse -Force
}

Write-Status INFO "Building $bundleRoot"
$copied = 0

foreach ($entry in $manifest) {
    $sourceFull = Join-Path $repoRoot $entry.Source
    if (-not (Test-Path -LiteralPath $sourceFull)) {
        Write-Status FAIL "Missing source: $($entry.Source)"
        exit 1
    }

    # -z keeps paths with spaces intact, and git writes paths as UTF-8. PowerShell decodes
    # native output with [Console]::OutputEncoding (the OEM code page by default), which
    # mangles names like "FSLogix Profile Report — Quick Guide.docx", so switch it briefly.
    $previousEncoding = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
        $tracked = @((& git -C $repoRoot ls-files -z -- $entry.Source) -split "`0" | Where-Object { $_ })
    }
    finally {
        [Console]::OutputEncoding = $previousEncoding
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Status FAIL "git ls-files failed for $($entry.Source)"
        exit 1
    }
    if ($tracked.Count -eq 0) {
        Write-Status FAIL "$($entry.Source) has no files tracked by git. Commit it before building."
        exit 1
    }

    $isFolder = Test-Path -LiteralPath $sourceFull -PathType Container
    $entryCount = 0
    foreach ($file in $tracked) {
        if ($isFolder) {
            $relative = $file.Substring($entry.Source.TrimEnd('/').Length + 1)
            if ($excludePatterns | Where-Object { $relative -match $_ }) { continue }
            $target = Join-Path $bundleRoot (Join-Path $entry.Destination $relative)
        }
        else {
            $target = Join-Path $bundleRoot $entry.Destination
        }

        $source = Join-Path $repoRoot $file
        if (-not (Test-Path -LiteralPath $source)) {
            Write-Status WARN "Tracked but missing from the working tree, skipped: $file"
            continue
        }
        $targetDir = Split-Path -Parent $target
        if (-not (Test-Path -LiteralPath $targetDir)) {
            New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
        }
        Copy-Item -LiteralPath $source -Destination $target -Force
        $entryCount++
    }
    $copied += $entryCount
    Write-Status PASS ("{0,-55} -> {1} ({2} file(s))" -f $entry.Source, $entry.Destination, $entryCount)
}

Write-Status PASS "$copied file(s) copied to $bundleRoot"

if ($Zip) {
    Compress-Archive -Path $bundleRoot -DestinationPath $zipPath -CompressionLevel Optimal
    Write-Status PASS "Zip created: $zipPath"
}
