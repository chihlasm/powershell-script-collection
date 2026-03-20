# Network-Troubleshooting-Palette

A menu-driven PowerShell console tool for common network troubleshooting tasks.

## Usage

```powershell
.\NetworkTroubleshootingPalette.ps1
```

## Available Tools

| Option | Description |
|--------|-------------|
| 1 | Test Connectivity (Ping) |
| 2 | Trace Route (Tracert) |
| 3 | DNS Lookup (Resolve-DnsName) |
| 4 | Test Port (Test-NetConnection) |
| 5 | Show Application Connections (Get-NetTCPConnection) |
| 6 | Show Local Adapter Info |
| 7 | Show Routing Table |
| 8 | Check Public IP |
| 9 | Check Wi-Fi Signal |
| 10 | Check SSL Certificate |
| 11 | Check Interface MTU |
| 12 | Port Scanner (Common Ports) |
| L | Toggle session logging (transcript) |
| Q | Quit |

## Features

- Interactive menu loop — pick a tool, run it, return to menu
- Optional transcript logging to file
- No external dependencies — uses built-in Windows/PowerShell cmdlets
