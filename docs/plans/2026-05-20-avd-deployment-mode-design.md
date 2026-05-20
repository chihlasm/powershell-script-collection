# Add AVD deployment mode to Install-TeamsOnCitrixVDA

**Date**: 2026-05-20
**Status**: Approved — ready for implementation plan
**Source script**: `Install-TeamsOnCitrixVDA/Install-TeamsOnCitrixVDA.ps1`
**Target script**: `Install-TeamsOnVirtualDesktop/Install-TeamsOnVirtualDesktop.ps1` (renamed)

## Problem

The current script supports two deployment modes — `CitrixVDA` and `RDS` — but Azure Virtual Desktop (AVD) is increasingly common, particularly Windows 11 Enterprise multi-session pools that get reimaged nightly. Today the workable path on AVD is "use `-DeploymentType RDS` and hope for the best." That works for provisioning but misses one critical piece (the `IsWVDEnvironment` registry key) and uses a deployment command Microsoft no longer recommends for modern Windows.

## Goals

- First-class `AVD` deployment mode that produces a Teams install ready to bake into a golden image for a reimaged-nightly AVD multi-session pool.
- Use Microsoft's currently recommended deployment method (`teamsbootstrapper.exe`) on supported OS versions, falling back to `Add-AppxProvisionedPackage` only on Server 2019 where it's the only supported method.
- Set `HKLM\SOFTWARE\Microsoft\Teams\IsWVDEnvironment = 1` so Teams enables AVD media optimization. Without this, Teams installs but runs unoptimized.
- Generalize the script's name to reflect its broader scope (Citrix VDA, RDS, AVD), without breaking existing automation that calls the script by parameter values.
- Zero behavior change for existing `CitrixVDA` and `RDS` callers.

## Non-goals

- Supporting the new "SlimCore-based" VDI 2.0 optimization stack — `IsWVDEnvironment` remains required through April 2027 per Microsoft Learn, and this script targets today's deployments.
- Adding `-WhatIf` / `-Confirm` plumbing (out of scope; flag for future).
- Renaming the `-DeploymentType` enum values (`RDS` → `MultiSession`) — breaking change rejected during brainstorm.
- Any unit test framework — repo doesn't have one; manual testing only.

## Revision history

- **2026-05-20 (initial)** — design as captured below.
- **2026-05-20 (amendment 1)** — added WebRTC Redirector install and per-machine classic Teams MSI cleanup after comparing against a working Nerdio scripted-action (`RDS-FSLogix-EventExport/Nerdio.ps1`). Without the WebRTC Redirector, `IsWVDEnvironment=1` flags Teams as VDI-aware but no codec partner exists for AV redirection, so calls fall back to server-side rendering. Without per-machine MSI cleanup, image-build VMs that previously had classic Teams Machine-Wide Installer leave the MSI registered after our run.

## Authoritative source

Microsoft Learn, *Microsoft Teams for Virtualized Desktop Infrastructure (VDI)*, updated 2026-05-15:
<https://learn.microsoft.com/en-us/microsoftteams/new-teams-vdi-requirements-deploy>

Key facts confirmed against that page:

- **Supported Windows**: "Windows 10.0.19041 or higher (excluding Windows LTSC)" — covers Win11 22H2/23H2/24H2/25H2 single-session and multi-session.
- **Recommended deploy method**: `teamsbootstrapper.exe -p -o "<path to MSIX>"`. Quote: "**Recommended way to deploy Teams in VDI.**"
- **Server 2019 exception**: "the only supported installation method is `Dism /Online /Add-ProvisionedAppxPackage /PackagePath:<MSIX> /SkipLicense`."
- **`IsWVDEnvironment` registry key**: still mandatory for AVD media optimization. Path `HKLM\SOFTWARE\Microsoft\Teams`, name `IsWVDEnvironment`, type `DWORD`, value `1`.
- **Deprecation timeline (flag in script .NOTES)**: WebRTC-based optimization End of Support 2026-10-01, End of Availability 2027-04-01.

## Design

### 1. Rename

Folder and script rename via `git mv` to preserve history:

- `Install-TeamsOnCitrixVDA/` → `Install-TeamsOnVirtualDesktop/`
- `Install-TeamsOnCitrixVDA.ps1` → `Install-TeamsOnVirtualDesktop.ps1`

Root `README.md` references (TOC anchor, section heading, two example paths at lines 16, 220, 229–230) updated to the new path and section title.

### 2. Parameter changes

`ValidateSet` gains `'AVD'` (additive; existing values unchanged):

```powershell
[ValidateSet('CitrixVDA', 'RDS', 'AVD')]
[string]$DeploymentType,
```

New parameters mirroring the existing `$TeamsDownloadUrl` / `$WebView2Url` pattern:

```powershell
[string]$TeamsBootstrapperUrl = "https://go.microsoft.com/fwlink/?linkid=2243204",
[string]$WebRTCRedirectorUrl  = "https://aka.ms/msrdcwebrtcsvc/msi",
[switch]$SkipWebRTCRedirector
```

`-WebRTCRedirectorUrl` and `-SkipWebRTCRedirector` are AVD-only and quietly ignored in `CitrixVDA` / `RDS` modes (Citrix has its own HDX optimization stack; RDS without AVD doesn't use the MS WebRTC redirector).

`.SYNOPSIS`, `.DESCRIPTION`, `.NOTES`, and `.EXAMPLE` blocks updated. New `.EXAMPLE` blocks demonstrate AVD mode with download, with a local MSIX, and with `-SkipWebRTCRedirector`. `.NOTES` gains a paragraph on the image-build workflow (run once in the build VM before sealing) and a paragraph citing the WebRTC deprecation timeline.

### 3. AVD branch behavior

The `AVD` branch is mostly the existing `RDS` provisioning flow with five additions:

**a. Live-host warning** (before any removal/install work, only in AVD mode):

```
[WARN] AVD mode provisions Teams machine-wide. This is intended for use inside
       a golden-image VM before sysprep/sealing. Running on a live session host
       affects all users on this host. Continuing in 5 seconds — Ctrl+C to abort.
```

5-second `Start-Sleep`. No `quser` check — `quser` is unreliable on AVD multi-session and the warning is sufficient.

**b. Bootstrapper-based install on modern Windows**

Pseudocode for the new dispatch:

```powershell
function Install-TeamsAVD {
    param ([string]$MsixPath)
    if ($osBuild -ge 19041) {
        # Win10 20H1+, Win11, Server 2022+ — Microsoft-recommended path
        $bootstrapperPath = "$env:TEMP\teamsbootstrapper.exe"
        Invoke-WebRequest -Uri $TeamsBootstrapperUrl -OutFile $bootstrapperPath
        & change user /install 2>$null
        try {
            $proc = Start-Process -FilePath $bootstrapperPath `
                                  -ArgumentList "-p","-o",$MsixPath `
                                  -Wait -PassThru -NoNewWindow
            if ($proc.ExitCode -ne 0) {
                throw "teamsbootstrapper.exe failed with exit code $($proc.ExitCode). See C:\WINDOWS\Temp\teamsprovision.log.*"
            }
        } finally {
            & change user /execute 2>$null
            if (Test-Path $bootstrapperPath) { Remove-Item $bootstrapperPath -Force }
        }
    } else {
        # Server 2019 (build 17763) — DISM-equivalent is the only supported method
        Add-AppxProvisionedPackage -Online -PackagePath $MsixPath -SkipLicense
    }
}
```

**c. `IsWVDEnvironment` registry key** (set after successful provisioning):

```powershell
$teamsRegPath = "HKLM:\SOFTWARE\Microsoft\Teams"
if (-not (Test-Path $teamsRegPath)) {
    New-Item -Path $teamsRegPath -Force | Out-Null
}
New-ItemProperty -Path $teamsRegPath -Name "IsWVDEnvironment" `
                 -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Log "Set HKLM\SOFTWARE\Microsoft\Teams\IsWVDEnvironment = 1 (enables AVD media optimization)"
```

**d. Per-machine classic Teams MSI cleanup** (added to existing all-users cleanup phase):

The existing `Remove-OldTeamsAllUsers` handles per-user classic Teams installs under `%LOCALAPPDATA%\Microsoft\Teams`. It does **not** remove the Teams Machine-Wide Installer MSI (product code `{731F6BAA-A986-45A4-8936-7C3AAAAA760B}`) — a separate per-machine install that's common on older image-build VMs.

New helper `Remove-OldTeamsPerMachine`:

```powershell
function Remove-OldTeamsPerMachine {
    # Detect via uninstall registry hive (NOT Win32_Product — that triggers
    # MSI self-repair on every product and is dog-slow).
    $teamsMsiCode = '{731F6BAA-A986-45A4-8936-7C3AAAAA760B}'
    $uninstallKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$teamsMsiCode",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$teamsMsiCode"
    )
    $found = $uninstallKeys | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $found) {
        Write-Log "Per-machine classic Teams MSI not detected"
        return
    }
    Write-Log "Per-machine classic Teams MSI detected, uninstalling..."
    $proc = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" `
                          -ArgumentList "/x", $teamsMsiCode, "/qn", "/norestart" `
                          -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -in @(0, 1605, 3010)) {
        # 0 = success, 1605 = product not installed (race), 3010 = success but reboot required
        Write-Log "Per-machine classic Teams MSI uninstall completed (exit $($proc.ExitCode))"
    }
    else {
        Write-Log "[WARN] msiexec /x for classic Teams MSI returned $($proc.ExitCode); continuing"
    }
}
```

Called from both `RDS` and `AVD` cleanup phases — it's safe to run when not installed (early return on registry miss).

**e. WebRTC Redirector install** (AVD only, after `IsWVDEnvironment` set, unless `-SkipWebRTCRedirector`):

Without the WebRTC Redirector service installed, `IsWVDEnvironment=1` flags Teams as VDI-aware but no codec partner exists. Calls work but AV is server-rendered on the VM — exactly the load AVD is supposed to offload to the client.

New helper `Install-WebRTCRedirector`:

```powershell
function Install-WebRTCRedirector {
    # Check existing version via uninstall registry first (idempotent re-runs)
    $rtcMsiCode = '{FB41EDB3-4138-4240-AC09-B5A184E8F8E4}'
    $existingPath = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$rtcMsiCode",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$rtcMsiCode"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($existingPath) {
        $existingVersion = (Get-ItemProperty $existingPath).DisplayVersion
        Write-Log "WebRTC Redirector $existingVersion already installed; uninstalling before upgrade..."
        Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" `
                      -ArgumentList "/x", $rtcMsiCode, "/qn", "/norestart" `
                      -Wait -NoNewWindow | Out-Null
    }

    $installerPath = "$env:TEMP\MsRdcWebRTCSvc_x64.msi"
    try {
        Invoke-WebRequest -Uri $WebRTCRedirectorUrl -OutFile $installerPath
        Write-Log "WebRTC Redirector MSI downloaded to $installerPath"

        $proc = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" `
                              -ArgumentList "/i", $installerPath, "/qn", "/norestart" `
                              -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -in @(0, 3010)) {
            Write-Log "WebRTC Redirector installed (exit $($proc.ExitCode))"
        }
        else {
            throw "WebRTC Redirector install failed with exit code $($proc.ExitCode)"
        }
    }
    finally {
        if (Test-Path $installerPath) { Remove-Item $installerPath -Force }
    }
}
```

Failure to install the WebRTC Redirector is **not fatal** — script logs `[WARN]` and continues. Teams itself is installed and `IsWVDEnvironment` is set; an operator can rerun or install manually. This keeps a transient network failure from forcing a full image-build retry.

### 4. OS gate becomes mode-aware

Today: throws at `$osBuild -lt 17763` regardless of mode.

New:

```powershell
$osBuild = [System.Environment]::OSVersion.Version.Build
switch ($DeploymentType) {
    'AVD' {
        # Per Microsoft Learn: Windows 10.0.19041+ for AVD/Win365 VDI scenarios
        if ($osBuild -lt 19041) {
            throw "AVD deployment requires Windows 10 build 19041 (20H1) or later, Win11, or Server 2022+. This system is build $osBuild."
        }
    }
    default {
        # CitrixVDA and RDS keep the original gate
        if ($osBuild -lt 17763) {
            throw "New Teams requires Windows Server 2019 or later (build 17763+). This system is build $osBuild. Install Teams Classic (MSI) instead."
        }
    }
}
```

### 5. Existing function reuse

`AVD` mode reuses these existing functions unchanged:

- `Test-NewTeamsInstalled` — takes the `-AllUsers` branch (already mode-aware on line 179, just add `'AVD'` to the condition)
- `Remove-NewTeams` — takes the `-AllUsers` branch (same)
- `Test-OldTeamsInstalledAllUsers` + `Remove-OldTeamsAllUsers` — AVD takes this branch (lines 383–392)
- `Install-WebView2` — `change user /install`/`/execute` toggle fires for `RDS` *or* `AVD` (lines 265, 288)

The condition pattern across these functions becomes `if ($DeploymentType -in @('RDS','AVD'))` rather than `if ($DeploymentType -eq 'RDS')`.

### 6. Code layout summary

| Location | Today (line) | Change |
|---|---|---|
| `param()` ValidateSet | 68 | Add `'AVD'` |
| `param()` new params | after 73 | Add `$TeamsBootstrapperUrl`, `$WebRTCRedirectorUrl`, `$SkipWebRTCRedirector` |
| `Test-NewTeamsInstalled` | 179 | Mode check includes AVD |
| `Remove-NewTeams` | 200 | Mode check includes AVD |
| `Install-WebView2` toggles | 265, 288 | Mode check includes AVD |
| Main: OS gate | 365–368 | Mode-aware (19041 for AVD, 17763 otherwise) |
| Main: post-install AVD warning | top of `try` block | New, AVD-only, 5-sec sleep |
| Main: old Teams cleanup branch | 383–392 | AVD/RDS take AllUsers branch + call `Remove-OldTeamsPerMachine` |
| Main: install dispatch | 424–429, 435–440 | AVD calls new `Install-TeamsAVD` |
| New function | end of function block | `Install-TeamsAVD` |
| New function | end of function block | `Remove-OldTeamsPerMachine` |
| New function | end of function block | `Install-WebRTCRedirector` |
| Main: after install | after dispatch | Set `IsWVDEnvironment=1` + call `Install-WebRTCRedirector` (AVD only, unless `-SkipWebRTCRedirector`) |

### 7. README updates

**Folder `README.md`** (now `Install-TeamsOnVirtualDesktop/README.md`):

- Title and description updated to "Citrix VDA, RDS Terminal Server, or Azure Virtual Desktop"
- Parameters table: `-DeploymentType` row updated to `CitrixVDA`, `RDS`, or `AVD`; new rows for `-TeamsBootstrapperUrl`, `-WebRTCRedirectorUrl`, `-SkipWebRTCRedirector`
- New "How It Works" subsection for AVD mode explaining the image-build workflow, bootstrapper path, Server 2019 fallback, `IsWVDEnvironment` registry key, and WebRTC Redirector install
- New "Why AVD mode exists" callout: non-persistent AVD reimages nightly, so Teams must be in the golden image; the live-host warning exists because running on a session host affects all users
- New AVD usage examples (with download, with local MSIX, with `-SkipWebRTCRedirector`)
- Compatibility section: add Win11 22H2+ and AVD multi-session
- Note that the WebRTC Redirector is now installed by AVD mode (previously listed as out-of-scope)

**Root `README.md`**:

- TOC line 16: anchor updated to `install-teamsonvirtualdesktop`
- Section heading line 220: `## Install-TeamsOnVirtualDesktop`
- Description line 222: updated to mention all three platforms
- Usage examples lines 229–230: paths updated to new folder/script names

## Testing

Manual only; matches repo convention.

1. **Syntax**: `pwsh -NoProfile -Command "Get-Command -Syntax .\Install-TeamsOnVirtualDesktop.ps1"` parses cleanly.
2. **Help**: `Get-Help .\Install-TeamsOnVirtualDesktop.ps1 -Full` shows all three modes documented with examples.
3. **No-mode failure**: running without `-DeploymentType` errors as before.
4. **CitrixVDA mode regression**: existing behavior unchanged — same `Add-AppxPackage` call, no new registry writes, no bootstrapper download.
5. **RDS mode regression**: existing behavior unchanged — same `Add-AppxProvisionedPackage` call.
6. **AVD mode dry-run on Win11**: run in an AVD image-build VM. Verify:
   - 5-second warning fires
   - `Remove-OldTeamsPerMachine` runs (logs "not detected" on a clean image, completes if present)
   - `teamsbootstrapper.exe` downloads and runs to exit code 0
   - `Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like '*Teams*'` returns the package
   - `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Teams' IsWVDEnvironment` returns `1`
   - WebRTC Redirector MSI downloads and installs (or is skipped if `-SkipWebRTCRedirector`)
   - `Get-Service MsRdcWebRTCSvc` returns Running after install
   - Temp files cleaned up
7. **AVD mode with `-SkipWebRTCRedirector`**: verify WebRTC step is skipped and logged as such.
8. **AVD mode WebRTC failure tolerance**: temporarily set `-WebRTCRedirectorUrl` to a bad URL; verify `[WARN]` is logged and the script still exits 0 (Teams + reg key already set successfully).
9. **AVD mode on Server 2019**: verify falls back to `Add-AppxProvisionedPackage` path (build 17763 < 19041 gate, but mode-specific path picks DISM equivalent on the fallback).

## Risks and mitigations

- **Bootstrapper URL stability**: Microsoft's fwlink for `teamsbootstrapper.exe` (`linkid=2243204`) could change. Mitigation: it's a parameter; operators can override.
- **Bootstrapper requires elevated install mode on multi-session**: handled by reusing the existing `change user /install`/`/execute` toggle.
- **`IsWVDEnvironment` deprecation**: WebRTC-based optimization End of Support 2026-10-01. Mitigation: `.NOTES` documents the timeline; the key remains correct and required until then.
- **WebRTC Redirector version drift**: Microsoft ships new redirector versions periodically. The script always uninstalls any existing version before installing the latest from `aka.ms/msrdcwebrtcsvc/msi`, so reruns stay current. Operators can pin a version by passing `-WebRTCRedirectorUrl <pinned-msi-url>`.
- **WebRTC Redirector install fails**: non-fatal `[WARN]`; Teams + `IsWVDEnvironment` succeed independently. Mitigation: `-SkipWebRTCRedirector` lets pipelines opt out entirely if they manage the redirector separately.
- **`msiexec /x` on classic Teams MSI**: rare exit codes (e.g. 1603) are logged as `[WARN]` and the script continues; we don't want a stale classic install to block a new Teams provisioning.
- **Running on live AVD session host**: 5-second warning + log message. Operators have time to abort.

## Open questions

None remaining after brainstorm and Nerdio script comparison. All scope decisions confirmed:

- AVD as third ValidateSet value (additive)
- `IsWVDEnvironment` registry key set after Teams install
- WebRTC Redirector installed by default in AVD mode, `-SkipWebRTCRedirector` to opt out
- Per-machine classic Teams MSI cleanup for AVD/RDS via uninstall-registry detection (not `Win32_Product`)
- Warn + proceed on live hosts, no `quser` gating
- Update both folder README and root README
- Rename folder + script
- Use bootstrapper on modern Windows, DISM fallback on Server 2019
