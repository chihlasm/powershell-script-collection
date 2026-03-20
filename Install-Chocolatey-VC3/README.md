# Install-Chocolatey-VC3

Installs Chocolatey CLI and configures the VC3 private MyGet repository source.

## What It Does

1. Installs Chocolatey (or upgrades if already installed)
2. Adds the `vc3protected` MyGet source with priority 20
3. Removes the legacy `streamedapps` source if present
4. Validates connectivity to the VC3 feed

## Usage

Run as Administrator:

```powershell
.\Install-Chocolatey-VC3.ps1
```

## Requirements

- PowerShell 5.1+
- Run as Administrator
- Internet access to `community.chocolatey.org` and `www.myget.org`
