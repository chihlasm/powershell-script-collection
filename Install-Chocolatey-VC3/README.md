# Install-Chocolatey-VC3

Installs Chocolatey CLI and configures the VC3 private MyGet repository source.

## What It Does

1. Installs Chocolatey (or upgrades if already installed)
2. Adds the `vc3protected` MyGet source with priority 20
3. Removes the legacy `streamedapps` source if present
4. Validates connectivity to the VC3 feed

## Usage

Run as Administrator, supplying the authenticated feed URL at runtime:

```powershell
.\Install-Chocolatey-VC3.ps1 -FeedUrl '<authenticated feed URL>'
```

Or set it once in the session (or as an RMM secure variable) and run without parameters:

```powershell
$env:CHOCO_PRIVATE_FEED_URL = '<authenticated feed URL>'
.\Install-Chocolatey-VC3.ps1
```

The feed URL contains an access token, so treat it as a password: keep it in a password manager or your RMM's secure variables, and never commit it to this repository.

## Requirements

- PowerShell 5.1+
- Run as Administrator
- Internet access to `community.chocolatey.org` and `www.myget.org`
