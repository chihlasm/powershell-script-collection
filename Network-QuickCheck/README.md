# Network-QuickCheck

**"I can't reach the server" / "the app won't connect" / "my mapped drive won't connect."**

Run it **on the computer that has the problem** and name the server and port it can't reach.
The first line answers the question:

```
Can PC-0423 reach FILESRV01 on port 445?  YES, WITH WARNINGS
======================================================================
Warnings:
  [WARN] Ping: FILESRV01 did not answer a ping.
         What to do: Many servers block ping on purpose. If the port test passes, ignore this.
Looks fine:
  [PASS] Name lookup (DNS): FILESRV01 resolves to 10.0.0.5.
  [PASS] Port 445 (file shares (SMB)): Connected to 10.0.0.5:445 from 10.0.0.20:51234.
  [PASS] Default gateway: Gateway 10.0.0.1 on Ethernet.
```

It is **read-only**.

## Quick start

```powershell
# Mapped drive won't connect
.\Invoke-NetworkQuickCheck.ps1 -TargetAddress FILESRV01 -Port 445

# Remote Desktop gateway: two ports at once, with a report for the ticket
.\Invoke-NetworkQuickCheck.ps1 -TargetAddress rds.contoso.com -Port 443,3389 -OutputPath C:\Temp

# An IP address works too (the DNS step is skipped)
.\Invoke-NetworkQuickCheck.ps1 -TargetAddress 10.0.0.5 -Port 3389
```

## What it checks

1. **Name lookup (DNS).** Does the name turn into an address? Skipped for an IP address.
2. **Ping.** A missed ping is only a warning; many servers block it.
3. **Each TCP port.** Does the port accept a connection within 3 seconds? This is the result
   that matters.
4. **Default gateway.** Does this computer have a way off its own subnet?

The answer is **YES** when every port connects, **PARTLY** when some do, and **NO** when none do.

### Common ports

| Port | Used by |
|---|---|
| 445 | File shares / mapped drives (SMB) |
| 3389 | Remote Desktop |
| 443 / 80 | Websites, most cloud apps, RD Gateway |
| 1494 / 2598 | Citrix ICA / session reliability |
| 389 / 636 / 3268 | LDAP / LDAPS / Global Catalog |
| 88 | Kerberos |
| 53 | DNS |
| 1433 | SQL Server |
| 5985 / 5986 | WinRM |

## Parameters

| Parameter | Meaning |
|---|---|
| `-TargetAddress` | Host name, FQDN or IP address. Required. Aliases `-ComputerName`, `-Target`. |
| `-Port` | One or more TCP ports. Default 443. |
| `-TimeoutMilliseconds` | Wait per port before calling it closed. Default 3000. |
| `-OutputPath` | Folder for `NetworkQuickCheck_<target>_<timestamp>.txt` and `.csv`. Omit for console only. |
| `-PassThru` | Return the result object instead of setting an exit code (for other scripts). |
| `-Quiet` | No console output. Use with `-PassThru` or `-OutputPath`. |

**Exit codes** (without `-PassThru`): 0 = reachable, 1 = reachable with warnings, 2 = cannot reach
(or no target given).

## Requirements

PowerShell 3.0 or later. Nothing to install. On Windows 8 / Server 2012 and later it uses
`Resolve-DnsName` and `Get-NetRoute`; on older systems it falls back to the .NET resolver and
skips the gateway check.

## What it does not check

UDP ports, the firewall on the far end, share or NTFS permissions, or whether the service
behind the port is healthy. A port that connects only tells you something is listening.

For an interactive menu of more network tools (traceroute, Wi-Fi details, certificate check),
see `Network-Troubleshooting-Palette`.

## For other tools

`-PassThru -Quiet` returns an object with `CheckId` (`network.quick`), `Status`, `Answer`
(`YES` / `YES, WITH WARNINGS` / `PARTLY` / `NO`), `Summary`, `Evidence` (Name, Status,
Detail, Action), `RecommendedNextSteps`, `RawOutput`, `StartedAt`, `FinishedAt` and `Error`.
Apart from the new `Answer` field, this is the same shape the old `MSP-TroubleshootingWorkbench`
check returned.

## Tests

```powershell
Invoke-Pester .\Network-QuickCheck\Tests
```

## History

This was the `network.quick` check of `MSP-TroubleshootingWorkbench`, which now lives in its own
repository. Changes made when it became a standalone tool:

- Added plain-English console output, `-OutputPath`, exit codes, and several ports per run.
- `-TargetAddress` is required. The old check quietly tested `localhost` when none was given.
- An IP address no longer gives a misleading DNS warning.
- Ports are tested with a 3-second TCP connect instead of `Test-NetConnection`, which waits
  about 20 seconds on a closed port and does not exist on Server 2012.
- Requires only PowerShell 3.0.
