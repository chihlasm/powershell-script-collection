# Install-TeamsOnVirtualDesktop

**Description**: PowerShell script that downloads and installs Microsoft Teams on a Citrix VDA, RDS Terminal Server, or Azure Virtual Desktop (AVD) session host. Performs a clean installation by removing existing Teams versions, ensuring prerequisites are met, and provisioning Teams using the correct mechanism for each environment.

## Features

- **Three deployment modes**: Citrix VDA, RDS Terminal Server, and Azure Virtual Desktop via the `-DeploymentType` parameter.
- **AVD uses Microsoft's recommended path**: `teamsbootstrapper.exe -p -o <msix>` on Windows 10 build 19041+, Windows 11, and Server 2022+. Server 2019 is not supported in AVD mode — use RDS mode on Server 2019.
- **AVD media optimization**: sets `HKLM\SOFTWARE\Microsoft\Teams\IsWVDEnvironment = 1` and installs the AVD WebRTC Redirector after a successful AVD install so Teams enables AV redirection. Skip the redirector with `-SkipWebRTCRedirector` if a pipeline manages it separately.
- **Clean installation**: detects and removes old Microsoft Teams (classic, per-user and per-machine MSI) and new Microsoft Teams (MSIX) before proceeding. Per-machine MSI detection uses the uninstall registry hive — not `Win32_Product`, which triggers MSI self-repair across every installed product.
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
| `-WebRTCRedirectorUrl` | No | Custom URL for `MsRdcWebRTCSvc_x64.msi`. AVD mode only. Default: `aka.ms/msrdcwebrtcsvc/msi` |
| `-SkipWebRTCRedirector` | No | Skip the WebRTC Redirector install (AVD mode only). Use when a pipeline manages the redirector separately |
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

### AVD without the WebRTC Redirector (pipeline manages it separately)

```powershell
.\Install-TeamsOnVirtualDesktop.ps1 -DeploymentType AVD -SkipWebRTCRedirector
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
2. Removes the per-machine classic Teams Machine-Wide Installer MSI if present
3. Checks and removes new Teams for all users (`-AllUsers`), including the provisioned package
4. Verifies prerequisites; installs WebView2 in RDS install mode (`change user /install`)
5. Installs Teams via `Add-AppxProvisionedPackage -Online -SkipLicense`

### AVD mode

1. Prints a 5-second `[WARN]` (live-host safety)
2. Scans all user profiles and removes old Teams
3. Removes the per-machine classic Teams Machine-Wide Installer MSI if present
4. Checks and removes new Teams for all users, including the provisioned package
5. Verifies prerequisites; installs WebView2 in install mode
6. Downloads `teamsbootstrapper.exe` and runs `teamsbootstrapper.exe -p -o <msix>` (Microsoft's recommended VDI deployment path)
7. Sets `HKLM\SOFTWARE\Microsoft\Teams\IsWVDEnvironment = 1` to enable AVD media optimization
8. Installs the AVD WebRTC Redirector (`MsRdcWebRTCSvc_x64.msi`) unless `-SkipWebRTCRedirector` is set. Detects + uninstalls any existing redirector version first, then installs the latest. Failure to install the redirector is logged as `[WARN]` but is not fatal.

## Requirements Verification

### .NET Framework

- Minimum version: 4.6.2 (Release 394802+)
- Script checks the registry for the installed version
- Warns if version is insufficient (modern AVD/RDS base images clear this easily)

### WebView2

- Automatically downloaded and installed if not detected
- Registry check: `HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`
- On RDS and AVD, installed in install mode so registry mappings apply to all users

## WebRTC Redirector behavior

In AVD mode the script installs `MsRdcWebRTCSvc_x64.msi` automatically. The redirector is the codec partner for `IsWVDEnvironment=1` — without it, Teams flags itself as VDI-aware but AV is server-rendered on the VM (defeats the purpose of AVD optimization). To opt out, pass `-SkipWebRTCRedirector`. To pin a specific version, pass `-WebRTCRedirectorUrl` pointing at a known MSI.

Re-runs are idempotent: the script detects any existing redirector via uninstall registry, uninstalls it, and reinstalls the version from the URL. A failed redirector install is logged as `[WARN]` and does not fail the script — Teams + `IsWVDEnvironment` are already configured at that point.

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
- **AVD**: Windows 10 build 19041+ (20H1), Windows 11 (all releases), Windows Server 2022+. Server 2019 is not supported in AVD mode — use RDS mode instead.
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
