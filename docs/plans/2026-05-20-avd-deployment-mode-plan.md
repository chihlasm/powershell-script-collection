# AVD Deployment Mode Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a first-class `AVD` value to `-DeploymentType` in the Teams VDI install script — using Microsoft's recommended `teamsbootstrapper.exe` deployment on modern Windows, setting the `IsWVDEnvironment` registry key, and renaming the folder/script to reflect broader scope.

**Architecture:** Reuse the existing `RDS` provisioning skeleton (all-users cleanup, install-mode toggle for WebView2) for `AVD` mode, with three additions: (a) a 5-second live-host warning before any work, (b) a new `Install-TeamsAVD` function that calls `teamsbootstrapper.exe -p -o <msix>` on build ≥ 19041 and falls back to `Add-AppxProvisionedPackage` on Server 2019, (c) setting `HKLM\SOFTWARE\Microsoft\Teams\IsWVDEnvironment=1` after a successful install. Zero behavior change for existing `CitrixVDA` / `RDS` callers.

**Tech Stack:** PowerShell 5.1+, Add-AppxProvisionedPackage / DISM, teamsbootstrapper.exe, registry via `New-ItemProperty`.

**Design doc:** `docs/plans/2026-05-20-avd-deployment-mode-design.md`

**Branch:** `feat/avd-deployment-mode` (already created, design doc committed)

**Repo conventions reminder (from CLAUDE.md):**
- No test framework. "Testing" = manual verification with explicit Run/Expected commands.
- Dual-output logging: color-coded `Write-Host` + accumulated log lines.
- Status prefixes `[PASS]` `[WARN]` `[FAIL]` `[INFO]`.
- Conventional commits, `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>` footer.
- Per-script `README.md`.

---

## Task 1: Rename folder and script via git mv

**Files:**
- Move: `Install-TeamsOnCitrixVDA/` → `Install-TeamsOnVirtualDesktop/`
- Move: `Install-TeamsOnVirtualDesktop/Install-TeamsOnCitrixVDA.ps1` → `Install-TeamsOnVirtualDesktop/Install-TeamsOnVirtualDesktop.ps1`

This must be the first commit so git tracks the renames cleanly. All subsequent file paths in this plan refer to the new names.

**Step 1: Rename the folder**

Run:
```powershell
git mv "Install-TeamsOnCitrixVDA" "Install-TeamsOnVirtualDesktop"
```

Expected: no output, exit 0.

**Step 2: Rename the script inside the folder**

Run:
```powershell
git mv "Install-TeamsOnVirtualDesktop/Install-TeamsOnCitrixVDA.ps1" "Install-TeamsOnVirtualDesktop/Install-TeamsOnVirtualDesktop.ps1"
```

Expected: no output, exit 0.

**Step 3: Verify git sees renames not delete/add**

Run:
```powershell
git status
```

Expected: two `renamed:` lines showing the folder and the script. If you see `deleted:` + `new file:` instead, git lost the rename — `git reset` and re-run with `-k` or use `-f` after staging.

**Step 4: Commit**

```powershell
git commit -m "refactor: rename Install-TeamsOnCitrixVDA to Install-TeamsOnVirtualDesktop

Script now covers Citrix VDA, RDS, and AVD deployments. Folder and
filename renamed to match the broader scope. No code changes yet.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Add `AVD` to ValidateSet and new bootstrapper URL parameter

**Files:**
- Modify: `Install-TeamsOnVirtualDesktop/Install-TeamsOnVirtualDesktop.ps1` (param block, was lines 65–75)

**Step 1: Update the ValidateSet**

In the `param()` block, change:
```powershell
[ValidateSet('CitrixVDA', 'RDS')]
[string]$DeploymentType,
```
to:
```powershell
[ValidateSet('CitrixVDA', 'RDS', 'AVD')]
[string]$DeploymentType,
```

**Step 2: Add the `$TeamsBootstrapperUrl` parameter**

Insert this line after the existing `$TeamsDownloadUrl` line and before `$TeamsMsixPath`:
```powershell
    [string]$TeamsBootstrapperUrl = "https://go.microsoft.com/fwlink/?linkid=2243204",
```

The full param block after edits should look like:
```powershell
[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [ValidateSet('CitrixVDA', 'RDS', 'AVD')]
    [string]$DeploymentType,

    [string]$TeamsDownloadUrl = "https://go.microsoft.com/fwlink/?linkid=2196106",
    [string]$TeamsBootstrapperUrl = "https://go.microsoft.com/fwlink/?linkid=2243204",
    [string]$TeamsMsixPath,
    [string]$WebView2Url = "https://go.microsoft.com/fwlink/p/?LinkId=2124703",
    [switch]$Force
)
```

**Step 3: Verify the script still parses**

Run:
```powershell
pwsh -NoProfile -Command "Get-Command -Syntax .\Install-TeamsOnVirtualDesktop\Install-TeamsOnVirtualDesktop.ps1"
```

Expected: outputs the syntax line including `[-DeploymentType] <string>` and `[-TeamsBootstrapperUrl <string>]`. No parse errors.

**Step 4: Verify ValidateSet rejects unknown values**

Run:
```powershell
pwsh -NoProfile -Command ".\Install-TeamsOnVirtualDesktop\Install-TeamsOnVirtualDesktop.ps1 -DeploymentType FOO -WhatIf"
```

Expected: error containing "Cannot validate argument on parameter 'DeploymentType'" and listing `CitrixVDA, RDS, AVD`.

**Step 5: Commit**

```powershell
git add Install-TeamsOnVirtualDesktop/Install-TeamsOnVirtualDesktop.ps1
git commit -m "feat: add AVD value to -DeploymentType ValidateSet

- Adds 'AVD' alongside existing 'CitrixVDA' and 'RDS' (additive, no
  breaking change to existing callers)
- Adds -TeamsBootstrapperUrl parameter for teamsbootstrapper.exe
  download, mirroring the existing -TeamsDownloadUrl pattern

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Make `Test-NewTeamsInstalled` and `Remove-NewTeams` AVD-aware

**Files:**
- Modify: `Install-TeamsOnVirtualDesktop/Install-TeamsOnVirtualDesktop.ps1` (functions around lines 178–236)

Both functions currently branch on `if ($DeploymentType -eq 'RDS')`. AVD must take the same `-AllUsers` path because AVD multi-session, like RDS, has many user profiles.

**Step 1: Update `Test-NewTeamsInstalled`**

Change line 179 from:
```powershell
    if ($DeploymentType -eq 'RDS') {
```
to:
```powershell
    if ($DeploymentType -in @('RDS', 'AVD')) {
```

**Step 2: Update `Remove-NewTeams`**

Change line 200 from:
```powershell
        if ($DeploymentType -eq 'RDS') {
```
to:
```powershell
        if ($DeploymentType -in @('RDS', 'AVD')) {
```

**Step 3: Manual sanity check**

Run:
```powershell
pwsh -NoProfile -Command "Get-Command -Syntax .\Install-TeamsOnVirtualDesktop\Install-TeamsOnVirtualDesktop.ps1"
```

Expected: parses cleanly, no syntax errors.

**Step 4: Commit**

```powershell
git add Install-TeamsOnVirtualDesktop/Install-TeamsOnVirtualDesktop.ps1
git commit -m "feat: route AVD mode through all-users Teams detection/removal

AVD multi-session has the same profile model as RDS, so both
Test-NewTeamsInstalled and Remove-NewTeams take the -AllUsers branch
when mode is AVD.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Make `Install-WebView2` install-mode toggle AVD-aware

**Files:**
- Modify: `Install-TeamsOnVirtualDesktop/Install-TeamsOnVirtualDesktop.ps1` (function around lines 259–296)

**Step 1: Update the install-mode entry toggle (around line 265)**

Change:
```powershell
        if ($DeploymentType -eq 'RDS') {
            Write-Log "Switching to install mode for RDS..."
            & change user /install 2>$null
        }
```
to:
```powershell
        if ($DeploymentType -in @('RDS', 'AVD')) {
            Write-Log "Switching to install mode for multi-session ($DeploymentType)..."
            & change user /install 2>$null
        }
```

**Step 2: Update the install-mode exit toggle (around line 288)**

Change:
```powershell
        if ($DeploymentType -eq 'RDS') {
            & change user /execute 2>$null
            Write-Log "Switched back to execute mode"
        }
```
to:
```powershell
        if ($DeploymentType -in @('RDS', 'AVD')) {
            & change user /execute 2>$null
            Write-Log "Switched back to execute mode"
        }
```

**Step 3: Commit**

```powershell
git add Install-TeamsOnVirtualDesktop/Install-TeamsOnVirtualDesktop.ps1
git commit -m "feat: toggle install mode for WebView2 in AVD mode

AVD multi-session honors 'change user /install' / '/execute' the same
as RDS, so the toggle now fires for both modes.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Add `Install-TeamsAVD` function

**Files:**
- Modify: `Install-TeamsOnVirtualDesktop/Install-TeamsOnVirtualDesktop.ps1` (insert after `Install-TeamsRDS`, around line 355)

**Step 1: Insert the new function**

Add this function immediately after the `Install-TeamsRDS` function (after line 355, before the `# Main script execution` comment):

```powershell
# Function to install Teams on AVD (Azure Virtual Desktop)
function Install-TeamsAVD {
    param ([string]$MsixPath)

    $osBuild = [System.Environment]::OSVersion.Version.Build

    if ($osBuild -ge 19041) {
        # Win10 20H1+, Win11, Server 2022+ — Microsoft-recommended path
        Write-Log "Installing Microsoft Teams for AVD via teamsbootstrapper.exe (build $osBuild)..."
        $bootstrapperPath = "$env:TEMP\teamsbootstrapper.exe"
        try {
            Invoke-WebRequest -Uri $TeamsBootstrapperUrl -OutFile $bootstrapperPath
            Write-Log "teamsbootstrapper.exe downloaded to $bootstrapperPath"

            $proc = Start-Process -FilePath $bootstrapperPath `
                                  -ArgumentList "-p", "-o", $MsixPath `
                                  -Wait -PassThru -NoNewWindow
            if ($proc.ExitCode -ne 0) {
                throw "teamsbootstrapper.exe failed with exit code $($proc.ExitCode). See C:\WINDOWS\Temp\teamsprovision.log.* for details."
            }
            Write-Log "Teams provisioned successfully via teamsbootstrapper.exe (AVD)"
        }
        catch {
            $errMsg = $_.Exception.Message
            Write-Log "Error provisioning Teams via bootstrapper: $errMsg"
            throw
        }
        finally {
            if (Test-Path $bootstrapperPath) {
                Remove-Item -Path $bootstrapperPath -Force
            }
        }
    }
    else {
        # Server 2019 (build 17763) — DISM-equivalent is the only supported method
        Write-Log "Installing Microsoft Teams for AVD via Add-AppxProvisionedPackage (build $osBuild — Server 2019 fallback)..."
        try {
            Add-AppxProvisionedPackage -Online -PackagePath $MsixPath -SkipLicense
            Write-Log "Teams provisioned successfully for all users (AVD on Server 2019)"
        }
        catch {
            $errMsg = $_.Exception.Message
            Write-Log "Error provisioning Teams: $errMsg"
            throw
        }
    }
}
```

**Step 2: Verify syntax**

Run:
```powershell
pwsh -NoProfile -Command "Get-Command -Syntax .\Install-TeamsOnVirtualDesktop\Install-TeamsOnVirtualDesktop.ps1"
```

Expected: parses cleanly.

**Step 3: Commit**

```powershell
git add Install-TeamsOnVirtualDesktop/Install-TeamsOnVirtualDesktop.ps1
git commit -m "feat: add Install-TeamsAVD function

Uses teamsbootstrapper.exe -p -o <msix> on build 19041+ (Win10 20H1,
Win11, Server 2022+) per Microsoft's current VDI deployment guidance.
Falls back to Add-AppxProvisionedPackage on Server 2019 (build 17763),
which Microsoft Learn lists as the only supported method on that OS.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Replace OS gate with mode-aware version

**Files:**
- Modify: `Install-TeamsOnVirtualDesktop/Install-TeamsOnVirtualDesktop.ps1` (around lines 364–368, inside the main `try` block)

**Step 1: Replace the OS gate**

Find this block (was lines 364–368):
```powershell
    # New Teams (MSIX) requires Server 2019+ / Windows 10 1809+
    $osBuild = [System.Environment]::OSVersion.Version.Build
    if ($osBuild -lt 17763) {
        throw "New Teams requires Windows Server 2019 or later (build 17763+). This system is build $osBuild. Install Teams Classic (MSI) instead."
    }
```

Replace with:
```powershell
    # OS gate is mode-aware:
    #  - CitrixVDA / RDS: build 17763+ (Server 2019)
    #  - AVD: build 19041+ (Win10 20H1, Win11, Server 2022+) per Microsoft Learn
    #    https://learn.microsoft.com/en-us/microsoftteams/new-teams-vdi-requirements-deploy
    $osBuild = [System.Environment]::OSVersion.Version.Build
    if ($DeploymentType -eq 'AVD') {
        if ($osBuild -lt 19041) {
            throw "AVD deployment requires Windows 10 build 19041 (20H1) or later, Windows 11, or Server 2022+. This system is build $osBuild."
        }
    }
    else {
        if ($osBuild -lt 17763) {
            throw "New Teams requires Windows Server 2019 or later (build 17763+). This system is build $osBuild. Install Teams Classic (MSI) instead."
        }
    }
```

**Step 2: Commit**

```powershell
git add Install-TeamsOnVirtualDesktop/Install-TeamsOnVirtualDesktop.ps1
git commit -m "feat: mode-aware OS gate (AVD requires build 19041+)

Per Microsoft Learn, new Teams VDI deployments require Windows 10
20H1 (19041) or higher. CitrixVDA and RDS keep the original
build 17763+ floor.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Add live-host warning, route old-Teams cleanup through all-users branch for AVD, dispatch to Install-TeamsAVD, set IsWVDEnvironment

This task makes four edits inside the main `try` block. They're grouped because they all touch the orchestration flow and a single commit is cleaner than four against intertwined lines.

**Files:**
- Modify: `Install-TeamsOnVirtualDesktop/Install-TeamsOnVirtualDesktop.ps1` (main `try` block, formerly lines 358–448)

**Step 1: Add the live-host warning (AVD only, near top of `try`)**

Find this line (was line 362):
```powershell
    Write-Log "Starting Teams installation script - Deployment Type: $DeploymentType"
```

Insert this block **immediately after** it:
```powershell

    # AVD mode is intended for image-build VMs. Warn loudly if it's being
    # run anywhere else so a live-host operator has a chance to abort.
    if ($DeploymentType -eq 'AVD') {
        Write-Log "[WARN] AVD mode provisions Teams machine-wide. This is intended for use inside a"
        Write-Log "[WARN] golden-image VM before sysprep/sealing. Running on a live AVD session host"
        Write-Log "[WARN] will affect all users on this host. Continuing in 5 seconds — Ctrl+C to abort."
        Start-Sleep -Seconds 5
    }
```

**Step 2: Add AVD to the old-Teams cleanup branch (was lines 383–392)**

Find this block:
```powershell
    # Check and remove old Teams
    if ($DeploymentType -eq 'RDS') {
        if (Test-OldTeamsInstalledAllUsers) {
            Remove-OldTeamsAllUsers
        }
    }
    else {
        if (Test-OldTeamsInstalled) {
            Remove-OldTeams
        }
    }
```

Replace with:
```powershell
    # Check and remove old Teams
    if ($DeploymentType -in @('RDS', 'AVD')) {
        if (Test-OldTeamsInstalledAllUsers) {
            Remove-OldTeamsAllUsers
        }
    }
    else {
        if (Test-OldTeamsInstalled) {
            Remove-OldTeams
        }
    }
```

**Step 3: Dispatch to `Install-TeamsAVD` in both MSIX-source branches**

Find the local-MSIX branch (was around lines 424–429):
```powershell
        if ($DeploymentType -eq 'CitrixVDA') {
            Install-TeamsCitrixVDA -MsixPath $TeamsMsixPath
        }
        else {
            Install-TeamsRDS -MsixPath $TeamsMsixPath
        }
```

Replace with:
```powershell
        switch ($DeploymentType) {
            'CitrixVDA' { Install-TeamsCitrixVDA -MsixPath $TeamsMsixPath }
            'RDS'       { Install-TeamsRDS -MsixPath $TeamsMsixPath }
            'AVD'       { Install-TeamsAVD -MsixPath $TeamsMsixPath }
        }
```

Find the downloaded-MSIX branch (was around lines 435–440):
```powershell
        if ($DeploymentType -eq 'CitrixVDA') {
            Install-TeamsCitrixVDA -MsixPath $downloadedMsixPath
        }
        else {
            Install-TeamsRDS -MsixPath $downloadedMsixPath
        }
```

Replace with:
```powershell
        switch ($DeploymentType) {
            'CitrixVDA' { Install-TeamsCitrixVDA -MsixPath $downloadedMsixPath }
            'RDS'       { Install-TeamsRDS -MsixPath $downloadedMsixPath }
            'AVD'       { Install-TeamsAVD -MsixPath $downloadedMsixPath }
        }
```

**Step 4: Set `IsWVDEnvironment` after a successful AVD install**

Find this line (the success log, was line 448):
```powershell
    Write-Log "Teams installation script completed successfully for $DeploymentType"
```

Insert this block **immediately before** it:
```powershell
    # AVD media optimization requires this registry key. Per Microsoft Learn,
    # without it Teams installs but won't enable AV redirection on AVD.
    # NOTE: WebRTC-based optimization is deprecated — End of Support 2026-10-01,
    # End of Availability 2027-04-01 — but the key remains required until then.
    if ($DeploymentType -eq 'AVD') {
        $teamsRegPath = "HKLM:\SOFTWARE\Microsoft\Teams"
        if (-not (Test-Path $teamsRegPath)) {
            New-Item -Path $teamsRegPath -Force | Out-Null
        }
        New-ItemProperty -Path $teamsRegPath -Name "IsWVDEnvironment" `
                         -Value 1 -PropertyType DWORD -Force | Out-Null
        Write-Log "Set HKLM\SOFTWARE\Microsoft\Teams\IsWVDEnvironment = 1 (enables AVD media optimization)"
    }

```

**Step 5: Verify syntax**

Run:
```powershell
pwsh -NoProfile -Command "Get-Command -Syntax .\Install-TeamsOnVirtualDesktop\Install-TeamsOnVirtualDesktop.ps1"
```

Expected: parses cleanly.

**Step 6: Smoke test — verify ValidateSet error short-circuits before any side effects**

Run:
```powershell
pwsh -NoProfile -Command ".\Install-TeamsOnVirtualDesktop\Install-TeamsOnVirtualDesktop.ps1 -DeploymentType BadValue"
```

Expected: ValidateSet error, no log output, no side effects.

**Step 7: Commit**

```powershell
git add Install-TeamsOnVirtualDesktop/Install-TeamsOnVirtualDesktop.ps1
git commit -m "feat: wire AVD mode into main orchestration

- 5-second [WARN] before any work in AVD mode (live-host safety)
- AVD takes the all-users old-Teams cleanup branch
- Install dispatch switches to a 3-arm switch covering all modes
- After install, AVD mode sets HKLM\SOFTWARE\Microsoft\Teams\IsWVDEnvironment=1
  for AVD media optimization (per Microsoft Learn)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Update inline help (.SYNOPSIS, .DESCRIPTION, .PARAMETER, .EXAMPLE, .NOTES)

**Files:**
- Modify: `Install-TeamsOnVirtualDesktop/Install-TeamsOnVirtualDesktop.ps1` (comment-based help block at the top, was lines 4–63)

**Step 1: Update `.SYNOPSIS` and `.DESCRIPTION`**

Replace the existing `.SYNOPSIS` and `.DESCRIPTION` (was lines 5–21) with:

```
.SYNOPSIS
    Downloads and installs Microsoft Teams on a Citrix VDA, RDS Terminal Server,
    or Azure Virtual Desktop session host. Removes old Teams and new Teams if
    present, ensures prerequisites are met, and performs a clean installation.

.DESCRIPTION
    This script performs the following actions:
    1. Checks for and removes old Microsoft Teams (classic) if installed
    2. Checks for and removes new Microsoft Teams (MSIX) if installed
    3. Verifies and installs prerequisites (WebView2, .NET Framework)
    4. Downloads the latest Microsoft Teams MSIX package (and on AVD, the
       teamsbootstrapper.exe)
    5. Installs Microsoft Teams for the target environment

    Three deployment modes are supported:
    - CitrixVDA: Uses Add-AppxPackage; Teams auto-detects the VDA and provisions
      machine-wide via Citrix registry keys.
    - RDS: Uses Add-AppxProvisionedPackage for machine-wide provisioning on
      standard Remote Desktop Services terminal servers without Citrix.
    - AVD: Uses Microsoft's recommended teamsbootstrapper.exe -p -o <msix>
      command on Windows 10 build 19041+ (20H1, Win11, Server 2022+), or falls
      back to Add-AppxProvisionedPackage on Server 2019 (the only supported
      method on that OS). After install, sets HKLM\SOFTWARE\Microsoft\Teams\
      IsWVDEnvironment = 1 so Teams enables AVD media optimization.
```

**Step 2: Update `.PARAMETER DeploymentType`**

Replace the existing block (was lines 22–25) with:

```
.PARAMETER DeploymentType
    Target environment for the installation. Must be 'CitrixVDA', 'RDS', or 'AVD'.
    - CitrixVDA: Standard Citrix Virtual Delivery Agent servers
    - RDS: Windows Remote Desktop Services terminal servers (no Citrix)
    - AVD: Azure Virtual Desktop session hosts. Intended for use in a
      golden-image VM before sysprep/sealing; the script will warn for
      5 seconds before proceeding to give an operator a chance to abort
      on a live host.
```

**Step 3: Add `.PARAMETER TeamsBootstrapperUrl`**

Insert this block immediately after the existing `.PARAMETER TeamsDownloadUrl` block (was around line 30):

```
.PARAMETER TeamsBootstrapperUrl
    URL to download teamsbootstrapper.exe. Used only in AVD mode on build 19041+.
    If not specified, uses the official Microsoft URL.
```

**Step 4: Add AVD `.EXAMPLE` blocks**

Insert these two examples after the existing CitrixVDA / RDS `.EXAMPLE` blocks (around line 58, before `.NOTES`):

```
.EXAMPLE
    .\Install-TeamsOnVirtualDesktop.ps1 -DeploymentType AVD
    Installs Teams on an AVD image-build VM using the Microsoft-recommended
    teamsbootstrapper.exe path. Sets IsWVDEnvironment=1 for media optimization.

.EXAMPLE
    .\Install-TeamsOnVirtualDesktop.ps1 -DeploymentType AVD -TeamsMsixPath "\\fileserver\software\Teams_x64.msix"
    Same as above but uses a local/UNC MSIX path instead of downloading.
```

**Step 5: Update `.NOTES`**

Replace the existing `.NOTES` block (was lines 60–63) with:

```
.NOTES
    On Citrix VDA, Teams detects the VDA environment via registry keys and
    auto-provisions machine-wide. On RDS and AVD, the script ensures
    machine-wide provisioning explicitly.

    AVD image-build workflow:
        1. Spin up the AVD image-build VM
        2. Run this script with -DeploymentType AVD
        3. Verify Get-AppxProvisionedPackage -Online shows Teams and
           Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Teams IsWVDEnvironment
           returns 1
        4. Sysprep and capture the image

    AVD WebRTC redirector: not installed by this script. Image-build
    pipelines should install MsRdcWebRTCSvc separately.

    Deprecation timeline (per Microsoft Learn 2026-05-15):
        WebRTC-based optimization End of Support 2026-10-01,
        End of Availability 2027-04-01. The IsWVDEnvironment key remains
        required until that date. A new SlimCore-based VDI 2.0 stack
        replaces it.

    Reference: https://learn.microsoft.com/en-us/microsoftteams/new-teams-vdi-requirements-deploy
```

**Step 6: Verify help renders correctly**

Run:
```powershell
pwsh -NoProfile -Command "Get-Help .\Install-TeamsOnVirtualDesktop\Install-TeamsOnVirtualDesktop.ps1 -Full"
```

Expected: full help block with all three modes documented, two new AVD examples, `TeamsBootstrapperUrl` parameter described, deprecation notes in `.NOTES`.

**Step 7: Commit**

```powershell
git add Install-TeamsOnVirtualDesktop/Install-TeamsOnVirtualDesktop.ps1
git commit -m "docs: update inline help for AVD mode

- .SYNOPSIS / .DESCRIPTION mention all three modes
- New .PARAMETER block for -TeamsBootstrapperUrl
- Two new .EXAMPLE blocks for AVD (with and without local MSIX)
- .NOTES documents the image-build workflow, the WebRTC deprecation
  timeline, and that the WebRTC redirector is out of scope

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Rewrite folder README

**Files:**
- Replace: `Install-TeamsOnVirtualDesktop/README.md`

**Step 1: Replace the entire README**

Replace the file contents with:

````markdown
# Install-TeamsOnVirtualDesktop

**Description**: PowerShell script that downloads and installs Microsoft Teams on a Citrix VDA, RDS Terminal Server, or Azure Virtual Desktop (AVD) session host. Performs a clean installation by removing existing Teams versions, ensuring prerequisites are met, and provisioning Teams using the correct mechanism for each environment.

## Features

- **Three deployment modes**: Citrix VDA, RDS Terminal Server, and Azure Virtual Desktop via the `-DeploymentType` parameter.
- **AVD uses Microsoft's recommended path**: `teamsbootstrapper.exe -p -o <msix>` on Windows 10 build 19041+, Windows 11, and Server 2022+. Falls back to `Add-AppxProvisionedPackage` on Server 2019, which Microsoft Learn lists as the only supported method on that OS.
- **AVD media optimization**: sets `HKLM\SOFTWARE\Microsoft\Teams\IsWVDEnvironment = 1` after a successful AVD install so Teams enables AV redirection.
- **Clean installation**: detects and removes old Microsoft Teams (classic) and new Microsoft Teams (MSIX) before proceeding.
- **Machine-wide provisioning (RDS / AVD)**: ensures all current and future users receive Teams.
- **All-user cleanup (RDS / AVD)**: scans every user profile under `C:\Users` for stale Teams installations.
- **Prerequisite verification**: checks WebView2, installs if missing; verifies .NET Framework version.
- **Live-host safety on AVD**: prints a 5-second `[WARN]` before any work, giving an operator a chance to abort on a session host that shouldn't be touched.
- **Comprehensive logging**: timestamped console output throughout.

## Prerequisites

- PowerShell 5.1 or later
- Administrator privileges (script requires `-RunAsAdministrator`)
- Internet access for downloading Teams, WebView2, and (on AVD) `teamsbootstrapper.exe` — unless using `-TeamsMsixPath`
- **CitrixVDA mode**: Windows Server 2019+ with the Citrix Virtual Delivery Agent installed
- **RDS mode**: Windows Server 2019+ with the Remote Desktop Services role
- **AVD mode**: Windows 10 build 19041 (20H1) or higher, Windows 11, or Server 2022+

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-DeploymentType` | Yes | Target environment: `CitrixVDA`, `RDS`, or `AVD` |
| `-TeamsDownloadUrl` | No | Custom URL for the Teams MSIX. Ignored if `-TeamsMsixPath` is specified. Default: official Microsoft URL |
| `-TeamsBootstrapperUrl` | No | Custom URL for `teamsbootstrapper.exe`. Used only in AVD mode on build 19041+. Default: official Microsoft URL |
| `-TeamsMsixPath` | No | Local or UNC path to a Teams MSIX. Skips download when provided |
| `-WebView2Url` | No | Custom URL for the WebView2 runtime. Default: official Microsoft URL |
| `-Force` | No | Reinstall Teams even if already installed. Without this, the script exits early if Teams is detected |

## Usage Examples

### Citrix VDA
```powershell
.\Install-TeamsOnVirtualDesktop.ps1 -DeploymentType CitrixVDA
```

### RDS Terminal Server
```powershell
.\Install-TeamsOnVirtualDesktop.ps1 -DeploymentType RDS
```

### Azure Virtual Desktop (image build)
```powershell
.\Install-TeamsOnVirtualDesktop.ps1 -DeploymentType AVD
```

### AVD with a local/UNC MSIX
```powershell
.\Install-TeamsOnVirtualDesktop.ps1 -DeploymentType AVD -TeamsMsixPath "\\fileserver\software\Teams_x64.msix"
```

### Force reinstall
```powershell
.\Install-TeamsOnVirtualDesktop.ps1 -DeploymentType AVD -Force
```

## Why AVD mode exists

Non-persistent AVD pools reimage their session hosts nightly. Any per-session install evaporates at the next reboot, which means Teams must be baked into the golden image. AVD mode is intended to be run **once, inside the image-build VM, before sysprep/sealing**. The 5-second `[WARN]` exists because running it on a live session host affects all users on that host — the warning gives an operator a chance to abort.

## How It Works

### CitrixVDA mode
1. Checks and removes old Teams for the current user
2. Checks and removes new Teams (MSIX) for the current user
3. Verifies prerequisites (WebView2, .NET Framework)
4. Installs Teams via `Add-AppxPackage` — Teams auto-detects the Citrix VDA via `HKLM:\SOFTWARE\Citrix\PortICA` and provisions machine-wide

### RDS mode
1. Scans all user profiles under `C:\Users` and removes old Teams from each
2. Checks and removes new Teams for all users (`-AllUsers`), including the provisioned package
3. Verifies prerequisites; installs WebView2 in RDS install mode (`change user /install`)
4. Installs Teams via `Add-AppxProvisionedPackage -Online -SkipLicense`

### AVD mode
1. Prints a 5-second `[WARN]` (live-host safety)
2. Scans all user profiles and removes old Teams
3. Checks and removes new Teams for all users, including the provisioned package
4. Verifies prerequisites; installs WebView2 in install mode
5. **On build 19041+ (Win10 20H1, Win11, Server 2022+)**: downloads `teamsbootstrapper.exe` and runs `teamsbootstrapper.exe -p -o <msix>` (Microsoft's recommended VDI deployment path)
6. **On Server 2019 (build 17763)**: falls back to `Add-AppxProvisionedPackage` (the only supported method on that OS)
7. Sets `HKLM\SOFTWARE\Microsoft\Teams\IsWVDEnvironment = 1` to enable AVD media optimization

## Requirements Verification

### .NET Framework
- Minimum version: 4.6.2 (Release 394802+)
- Script checks the registry for the installed version
- Warns if version is insufficient (modern AVD/RDS base images clear this easily)

### WebView2
- Automatically downloaded and installed if not detected
- Registry check: `HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`
- On RDS and AVD, installed in install mode so registry mappings apply to all users

## Out of scope

This script does not install the **AVD WebRTC Redirector** (`MsRdcWebRTCSvc.exe`). Image-build pipelines typically install it separately. The WebRTC Redirector is required for AVD media optimization to work in conjunction with the `IsWVDEnvironment` key this script sets.

## Deprecation timeline

Per [Microsoft Learn](https://learn.microsoft.com/en-us/microsoftteams/new-teams-vdi-requirements-deploy) (updated 2026-05-15), WebRTC-based optimization for Teams on AVD has the following timeline:

- **End of Support**: 2026-10-01
- **End of Availability**: 2027-04-01

The `IsWVDEnvironment` registry key this script sets remains required until then. A new "SlimCore-based" VDI 2.0 optimization stack replaces it after.

## Troubleshooting

### `teamsbootstrapper.exe` failed with exit code
Logs are in `C:\WINDOWS\Temp\teamsprovision.log.*`. Common codes:
- `0x80070057` — use full path to MSIX, not relative
- `0x80070032` — UNC path issue; try copying MSIX to a local folder first
- `0x80004004` — stale `maglevInstallationSource` regkey at `HKLM\Software\WoW6432Node\Microsoft\Office\Teams`; delete and retry

### Teams installs but doesn't optimize on AVD
Verify both:
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Teams" -Name IsWVDEnvironment
Get-Service MsRdcWebRTCSvc  # WebRTC Redirector — installed separately
```

### Provisioned package removal fails (RDS / AVD)
Ensure no users are actively running Teams, then:
```powershell
Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*Teams*" }
```

## Compatibility

- **CitrixVDA / RDS**: Windows Server 2019+
- **AVD**: Windows 10 build 19041+ (20H1), Windows 11 (all releases), Windows Server 2022+. Server 2019 supported via DISM fallback path.
- **PowerShell**: 5.1+
- **Teams**: latest MSIX

## Notes

- `-DeploymentType` is mandatory
- Safe to re-run (idempotent — checks before removing or installing)
- AVD mode is designed for image-build workflows; the live-host warning gives 5 seconds to abort
- Test in a non-production image-build VM first
- Temp files stored in `%TEMP%` and cleaned up

## Reference

- Microsoft Learn — *Microsoft Teams for Virtualized Desktop Infrastructure (VDI)*: <https://learn.microsoft.com/en-us/microsoftteams/new-teams-vdi-requirements-deploy>
````

**Step 2: Commit**

```powershell
git add Install-TeamsOnVirtualDesktop/README.md
git commit -m "docs: rewrite folder README for three deployment modes

Adds AVD mode documentation: the image-build workflow, the
bootstrapper-vs-DISM split by OS build, the IsWVDEnvironment registry
key, the WebRTC deprecation timeline, and a troubleshooting block
for teamsbootstrapper.exe error codes.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Update root README

**Files:**
- Modify: `README.md` (lines 16, 220, 222, 229–230)

**Step 1: Update the TOC anchor (line 16)**

Change:
```markdown
- [Install-TeamsOnCitrixVDA](#install-teamsoncitrixvda)
```
to:
```markdown
- [Install-TeamsOnVirtualDesktop](#install-teamsonvirtualdesktop)
```

**Step 2: Update the section heading (line 220)**

Change:
```markdown
## Install-TeamsOnCitrixVDA
```
to:
```markdown
## Install-TeamsOnVirtualDesktop
```

**Step 3: Update the description (line 222)**

Change:
```markdown
**Description**: Downloads and installs Microsoft Teams on a Citrix VDA running Windows Server 2019. Removes old Teams and new Teams if present, ensures prerequisites are met, and performs clean installation.
```
to:
```markdown
**Description**: Downloads and installs Microsoft Teams on a Citrix VDA, RDS Terminal Server, or Azure Virtual Desktop (AVD) session host. Removes old Teams and new Teams if present, ensures prerequisites are met, and performs a clean installation. Sets `IsWVDEnvironment=1` for AVD media optimization on AVD deployments.
```

**Step 4: Update the usage example paths (lines 229–230)**

Change:
```markdown
- Basic installation: `.\Install-TeamsOnCitrixVDA\Install-TeamsOnCitrixVDA.ps1`
- Custom URLs: `.\Install-TeamsOnCitrixVDA\Install-TeamsOnCitrixVDA.ps1 -TeamsDownloadUrl "https://custom.url/teams.msix"`
```
to:
```markdown
- Basic installation: `.\Install-TeamsOnVirtualDesktop\Install-TeamsOnVirtualDesktop.ps1 -DeploymentType AVD`
- Custom URLs: `.\Install-TeamsOnVirtualDesktop\Install-TeamsOnVirtualDesktop.ps1 -DeploymentType RDS -TeamsDownloadUrl "https://custom.url/teams.msix"`
```

**Step 5: Verify no other references to the old name in the root README**

Run:
```powershell
Select-String -Path README.md -Pattern "Install-TeamsOnCitrixVDA"
```

Expected: no matches.

**Step 6: Commit**

```powershell
git add README.md
git commit -m "docs: update root README for Install-TeamsOnVirtualDesktop rename

- TOC anchor, section heading, description, and usage examples updated
- Description now mentions all three deployment modes
- Examples show -DeploymentType in the command

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: End-to-end manual verification

**Files:**
- Read-only: `Install-TeamsOnVirtualDesktop/Install-TeamsOnVirtualDesktop.ps1`

This task is verification only — no code changes, no commit.

**Step 1: Syntax check**

Run:
```powershell
pwsh -NoProfile -Command "Get-Command -Syntax .\Install-TeamsOnVirtualDesktop\Install-TeamsOnVirtualDesktop.ps1"
```

Expected: outputs the syntax line including all three parameter values and `-TeamsBootstrapperUrl`. No errors.

**Step 2: Help renders**

Run:
```powershell
pwsh -NoProfile -Command "Get-Help .\Install-TeamsOnVirtualDesktop\Install-TeamsOnVirtualDesktop.ps1 -Full" | more
```

Expected:
- `SYNOPSIS` mentions all three modes
- `DESCRIPTION` lists CitrixVDA, RDS, AVD with what each uses
- `PARAMETER DeploymentType` lists `CitrixVDA`, `RDS`, `AVD`
- `PARAMETER TeamsBootstrapperUrl` block present
- At least 5 `EXAMPLE` blocks (including 2 new AVD ones)
- `NOTES` includes the image-build workflow and deprecation timeline
- Reference URL to Microsoft Learn

**Step 3: ValidateSet rejects bad values**

Run:
```powershell
pwsh -NoProfile -Command ".\Install-TeamsOnVirtualDesktop\Install-TeamsOnVirtualDesktop.ps1 -DeploymentType Garbage"
```

Expected: "Cannot validate argument on parameter 'DeploymentType'" listing `CitrixVDA, RDS, AVD`.

**Step 4: Verify all functions are defined**

Run:
```powershell
Select-String -Path "Install-TeamsOnVirtualDesktop\Install-TeamsOnVirtualDesktop.ps1" -Pattern "^function "
```

Expected (order may vary): `Write-Log`, `Test-OldTeamsInstalled`, `Test-OldTeamsInstalledAllUsers`, `Remove-OldTeams`, `Remove-OldTeamsAllUsers`, `Test-NewTeamsInstalled`, `Remove-NewTeams`, `Test-DotNetVersion`, `Install-WebView2`, `Test-WebView2Installed`, `Get-TeamsInstaller`, `Install-TeamsCitrixVDA`, `Install-TeamsRDS`, `Install-TeamsAVD`.

**Step 5: Confirm no stragglers reference the old path**

Run:
```powershell
Select-String -Path *.md,**/*.md,**/*.ps1 -Pattern "Install-TeamsOnCitrixVDA" -SimpleMatch | Where-Object { $_.Path -notmatch "graphify-out|docs.plans" }
```

Expected: no matches outside `graphify-out/` (generated) and `docs/plans/` (historical design doc, fine to reference the old name).

**Step 6: If running in an AVD image-build VM, full end-to-end test**

Manual verification with side effects — only run inside a disposable AVD image-build VM (Win11 multi-session):

```powershell
.\Install-TeamsOnVirtualDesktop\Install-TeamsOnVirtualDesktop.ps1 -DeploymentType AVD
```

Expected:
- 5-second `[WARN]` block prints, then proceeds
- WebView2 check (likely already installed on Win11)
- `teamsbootstrapper.exe` downloads to `%TEMP%`
- Install completes with exit code 0
- `%TEMP%\teamsbootstrapper.exe` removed
- Final log: `Set HKLM\SOFTWARE\Microsoft\Teams\IsWVDEnvironment = 1 (enables AVD media optimization)`
- Final log: `Teams installation script completed successfully for AVD`

Post-install checks:
```powershell
Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like '*Teams*'
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Teams' IsWVDEnvironment
```
Expected: provisioned package present; `IsWVDEnvironment` returns `1`.

**Step 7: Open PR**

Run:
```powershell
gh pr create --base main --head feat/avd-deployment-mode --title "feat: add AVD deployment mode to Teams VDI install script" --body @'
Adds a first-class `AVD` value to `-DeploymentType` alongside the
existing `CitrixVDA` and `RDS` values. Uses Microsoft's currently
recommended `teamsbootstrapper.exe -p -o <msix>` path on Windows 10
build 19041+, Windows 11, and Server 2022+; falls back to
`Add-AppxProvisionedPackage` on Server 2019 (the only supported
method on that OS). Sets `HKLM\SOFTWARE\Microsoft\Teams\IsWVDEnvironment=1`
after install so Teams enables AVD media optimization.

Renames the folder and script to `Install-TeamsOnVirtualDesktop` to
reflect the broader scope. Zero behavior change for existing
`CitrixVDA` / `RDS` callers.

Design: `docs/plans/2026-05-20-avd-deployment-mode-design.md`
Plan: `docs/plans/2026-05-20-avd-deployment-mode-plan.md`
Reference: https://learn.microsoft.com/en-us/microsoftteams/new-teams-vdi-requirements-deploy

🤖 Generated with [Claude Code](https://claude.com/claude-code)
'@
```

---

## Acceptance criteria

- [ ] Folder renamed to `Install-TeamsOnVirtualDesktop/` and script renamed to match
- [ ] `-DeploymentType` accepts `CitrixVDA`, `RDS`, `AVD` (and rejects others)
- [ ] New `-TeamsBootstrapperUrl` parameter exists with the correct default
- [ ] AVD mode prints a 5-second `[WARN]` before any work
- [ ] AVD mode on build 19041+ calls `teamsbootstrapper.exe -p -o <msix>` and cleans up the exe in `finally`
- [ ] AVD mode on build 17763 falls back to `Add-AppxProvisionedPackage`
- [ ] AVD mode rejects builds < 19041 with a clear error (when not on Server 2019 path)
- [ ] After successful AVD install, `HKLM\SOFTWARE\Microsoft\Teams\IsWVDEnvironment = 1` (DWORD)
- [ ] `CitrixVDA` and `RDS` modes produce identical behavior to before this change
- [ ] `Get-Help -Full` shows all three modes, the new parameter, the two new examples, and the deprecation timeline
- [ ] Folder `README.md` and root `README.md` reflect the new name and AVD mode
- [ ] No references to `Install-TeamsOnCitrixVDA` outside `graphify-out/` and the design/plan documents
- [ ] PR opened against `main` from `feat/avd-deployment-mode`
