# Install-MSI

Discovers and installs MSI packages from a network share. Copies the MSI locally before installing for reliability. Supports transform files (`.mst`), custom MSI properties, and additional `msiexec` arguments. Works both interactively and silently for RMM deployment.

## Usage

```powershell
# Interactive — discovers and installs from a share
.\Install-MSI.ps1 -SharePath "\\fileserver\software\7zip"

# Silent with wildcard filter (for RMM)
.\Install-MSI.ps1 -SharePath "\\fileserver\software" -MsiName "Agent*.msi" -Silent

# With transform file and custom install directory
.\Install-MSI.ps1 -SharePath "\\fileserver\software" -TransformPath "\\fileserver\software\custom.mst" -MsiProperties "INSTALLDIR=D:\Apps"

# Preview mode
.\Install-MSI.ps1 -SharePath "\\fileserver\software\app" -WhatIf
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `SharePath` | Yes | UNC path to the folder containing MSI file(s) |
| `MsiName` | No | Filter or wildcard to select a specific MSI (e.g. `Agent*.msi`) |
| `TransformPath` | No | Path to an MST transform file |
| `MsiProperties` | No | Array of `KEY=VALUE` MSI property strings |
| `AdditionalArguments` | No | Raw additional `msiexec` arguments |
| `Silent` | No | Suppress interactive prompts (required for RMM/unattended use) |
| `WhatIf` | No | Preview mode — shows what would happen without making changes |
| `LogFile` | No | Override log path. Default: `C:\Temp\Logs\Install-MSI.log` |

## Requirements

- PowerShell 5.1+
- Run as Administrator
- Network access to the share path
