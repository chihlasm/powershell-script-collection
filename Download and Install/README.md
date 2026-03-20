# Download and Install

Downloads an MSI installer from a URL and installs it silently using `msiexec`.

## Usage

1. Edit the script to set `$DownloadUrl` and `$InstallerName` for your target MSI.
2. Run as Administrator:

```powershell
.\download-install.ps1
```

## How It Works

1. Downloads the MSI to `%TEMP%` via `Invoke-WebRequest` (TLS 1.2)
2. Runs `msiexec /i` with quiet mode (`/qn`), no-restart, and verbose logging
3. Reports success, reboot-required (exit 3010), or failure with log path
4. Cleans up the downloaded file automatically

## Configuration

Edit these variables at the top of the script:

| Variable | Description |
|----------|-------------|
| `$DownloadUrl` | Full URL to the MSI file |
| `$InstallerName` | Local filename for the download |

## Requirements

- PowerShell 5.1+
- Run as Administrator
