# powershell-script-collection

PowerShell tools for Windows Server, Active Directory, Citrix/RDS and Microsoft 365
administration in MSP environments. Each folder is one self-contained tool with its own
`README.md`. Copy the folder to the machine you run it from; there are no shared modules.

**Service desk staff: start with [ServiceDesk-Toolkit/README.md](ServiceDesk-Toolkit/README.md)**,
which says which tool to run for each kind of ticket. The bundle it builds is what gets
handed out, so it always matches this repository.

## Tool index

### Start here

| Folder | What it does |
|---|---|
| [ServiceDesk-Toolkit](ServiceDesk-Toolkit/) | Builds the service desk bundle and its START HERE page |

### Active Directory and Group Policy

| Folder | What it does |
|---|---|
| [AD-UserQuickCheck](AD-UserQuickCheck/) | Can this user sign in right now? Plain-English yes/no with reasons and next steps |
| [AD-LockoutDiagnostics](AD-LockoutDiagnostics/) | Why does this account keep locking out, and from which device? Includes source-device evidence, cause ranking and a live watcher |
| [AD-GroupMembership-Export](AD-GroupMembership-Export/) | Who has access to what: every group and member, with nesting and overlap |
| [Find-PrivilegedAccessPaths](Find-PrivilegedAccessPaths/) | Why is this user an admin? Plus a domain-wide privileged access report |
| [AD-Audit](AD-Audit/) | Whole-domain posture audit: accounts, password policy, DCs, trusts, infrastructure |
| [AD-GroupPolicy-Audit](AD-GroupPolicy-Audit/) | Audits every GPO for duplicates, conflicts, security issues and FSLogix settings |
| [DriveMap-Diagnostics](DriveMap-Diagnostics/) | Why is a mapped drive missing? Also audits every GPO drive map and searches SYSVOL logon scripts |
| [ADReplicationDiagnostics](ADReplicationDiagnostics/) | AD replication and DFSR/DFS Namespace health |
| [DC-Diagnostics](DC-Diagnostics/) | Run on a DC: health and events lined up against an outage window |
| [DHCP-Audit](DHCP-Audit/) | DHCP failover health across every authorized DHCP server |
| [Search-DNSRecords](Search-DNSRecords/) | Browser GUI to search and audit DNS records |
| [LocalAdminManager](LocalAdminManager/) | Add or remove domain users/groups in local Administrators |
| [HideFromGal](HideFromGal/) | **Changes AD.** Hide or unhide users in the Exchange Online address book |
| [Block 365 Sign-in](Block%20365%20Sign-in/) | **Changes AD.** Block Microsoft 365 sign-in while keeping on-prem login |

### Microsoft Entra ID and Microsoft 365

| Folder | What it does |
|---|---|
| [Get-EntraPasswordPolicy](Get-EntraPasswordPolicy/) | Tenant password policy, smart lockout and per-user expiry |
| [Get-M365SecurityEvidence](Get-M365SecurityEvidence/) | MFA, password policy and privileged-account evidence for audits |
| [Entra-DeviceActivityTimeline](Entra-DeviceActivityTimeline/) | When was this Entra-joined device on, asleep, locked and signed in to? |

### Citrix, RDS and FSLogix

| Folder | What it does |
|---|---|
| [Citrix-FSLogix-Triage](Citrix-FSLogix-Triage/) | Profile won't load? Plain-English FSLogix check of one session host, with next steps |
| [Citrix-FSLogix-HealthCollector](Citrix-FSLogix-HealthCollector/) | Health verdict per session host: performance plus event logs |
| [Citrix-PerfTriage](Citrix-PerfTriage/) | One-command performance triage on a session host |
| [CitrixVDADiagnostics](CitrixVDADiagnostics/) | Deeper VDA and FSLogix performance diagnostics |
| [Get-CitrixVDAResources](Get-CitrixVDAResources/) | Which VDAs are short on CPU, memory or disk, farm-wide |
| [Get-CitrixSessions](Get-CitrixSessions/) / [CitrixUserSessions](CitrixUserSessions/) | Who is logged on to which VDA |
| [Get-RAM-Usage](Get-RAM-Usage/) | RAM by user and process on a multi-session server |
| [RDS-FSLogix-EventExport](RDS-FSLogix-EventExport/) | RDS and FSLogix event-log errors for a time window |
| [Get-FSLogixStorageEvents](Get-FSLogixStorageEvents/) / [Parse-FSLogixLogs](Parse-FSLogixLogs/) | FSLogix storage events and log parsing |
| [Get-AzureFilesFSLogixProfiles](Get-AzureFilesFSLogixProfiles/) | FSLogix containers on Azure Files, with sizes |
| [FSLogix-ProfileDiskRepair](FSLogix-ProfileDiskRepair/) | Scan and repair FSLogix VHDX filesystem errors |
| [FSLogix-Profile-Backup](FSLogix-Profile-Backup/) | Back up browser saved passwords from profiles |
| [FSLogix-miExcel-Cleanup](FSLogix-miExcel-Cleanup/) | Remove the miExcel add-in from FSLogix profiles |
| [Storage Space Clean-up](Storage%20Space%20Clean-up/) | Disk cleanup for VDAs with FSLogix |
| [Install-TeamsOnVirtualDesktop](Install-TeamsOnVirtualDesktop/) | Clean Teams install on Citrix / RDS / AVD |
| [Migrate-AdobeProducts](Migrate-AdobeProducts/) | Replace Adobe Acrobat on Citrix VDAs |
| [CitrixWorkspaceApp_Remediation](CitrixWorkspaceApp_Remediation/) | Clean up and reinstall Citrix Workspace app |

### Files, storage and permissions

| Folder | What it does |
|---|---|
| [FolderPermissionManager](FolderPermissionManager/) | Browser GUI for NTFS permissions |
| [RobocopyMigration](RobocopyMigration/) | GUI for server-to-server file migrations |
| [CopyFileToServer](CopyFileToServer/) | GUI to copy files to many servers |
| [FileCopyMoveGUI](FileCopyMoveGUI/) | GUI copy/move with Robocopy-style options |
| [DeleteOldFolders](DeleteOldFolders/) | Delete `.old` folders past an age |
| [Drive-Storage-Report](Drive-Storage-Report/) | HTML report of drive and folder usage |
| [DiskSpdDiagnostic](DiskSpdDiagnostic/) | Storage performance triage with diskspd |
| [Storage-Corruption-Diagnostic](Storage-Corruption-Diagnostic/) | Read-only checks for suspected filesystem corruption |
| [SMBTest](SMBTest/) | Step-by-step SMB connectivity diagnostics |

### Servers and virtualization

| Folder | What it does |
|---|---|
| [Hyper-V-Inventory](Hyper-V-Inventory/) / [VMware-Inventory](VMware-Inventory/) | Host and VM inventory with capacity rollups |
| [HyperV-Host-Diagnostics](HyperV-Host-Diagnostics/) | Hyper-V host evidence for guest data loss or reboots |
| [Sql-Corruption-Diagnostic](Sql-Corruption-Diagnostic/) | Read-only SQL Server corruption diagnostics |
| [Schedule-Reboot](Schedule-Reboot/) | Schedule a one-time server reboot |

### Software, printers and desktop fixes

| Folder | What it does |
|---|---|
| [Install-MSI](Install-MSI/) / [Download and Install](Download%20and%20Install/) | Install an MSI from a share or URL |
| [Install-Chocolatey-VC3](Install-Chocolatey-VC3/) | Install Chocolatey with the private repository source |
| [Set-PrinterDefaults](Set-PrinterDefaults/) | Set black-and-white, two-sided defaults on printers |
| [CursorFix](CursorFix/) | Fix invisible cursor issues |

### Network

| Folder | What it does |
|---|---|
| [Network-QuickCheck](Network-QuickCheck/) | Can this computer reach that server on that port? Plain-English YES / PARTLY / NO |
| [Network-Troubleshooting-Palette](Network-Troubleshooting-Palette/) | Network troubleshooting command palette |
| [Juniper-ConsoleSetup](Juniper-ConsoleSetup/) | Browser GUI for Juniper console-cable provisioning |
| [Juniper-DeviceManager](Juniper-DeviceManager/) | Work in progress: Juniper fleet management over NETCONF |
| [JunOS - Info](JunOS%20-%20Info/) | Python: Juniper firmware and config audit |

### Retired tools

| Was | Use instead |
|---|---|
| `AD Export` | [AD-GroupMembership-Export](AD-GroupMembership-Export/) (see its "Migrating from AD Export" section) |
| `PasswordPolicyAuditor` | [AD-Audit](AD-Audit/) for the domain policy and fine-grained policies, [Get-EntraPasswordPolicy](Get-EntraPasswordPolicy/) for the cloud |
| `AD-AuthSourceEvidence` | Merged into [AD-LockoutDiagnostics](AD-LockoutDiagnostics/) |
| `AD-GroupPolicy-DriveMaps`, `Search-SYSVOLScripts` | Merged into [DriveMap-Diagnostics](DriveMap-Diagnostics/) |
| `MSP-TroubleshootingWorkbench` | The workbench now lives in its own repository. Its checks are standalone tools here: [Citrix-FSLogix-Triage](Citrix-FSLogix-Triage/), [Network-QuickCheck](Network-QuickCheck/), [AD-LockoutDiagnostics](AD-LockoutDiagnostics/) and [Citrix-FSLogix-HealthCollector](Citrix-FSLogix-HealthCollector/) |

## Tool details

The sections below are older summaries for some of the tools. Each folder's own README is
the authoritative, current documentation.

### DeleteOldFolders.ps1

**Description**: This PowerShell script recursively searches for and deletes folders ending with '.old' that are older than a specified number of days. It's designed for automated cleanup of temporary, backup, or obsolete folders to free up disk space.

**Parameters**:
- `-DrivePath <string>` (Required): The root directory path to scan for old folders (e.g., "C:\Temp").
- `-DaysOld <int>` (Optional, default: 14): The age threshold in days for folders to be considered for deletion.
- `-WhatIf` (Optional): Switch to simulate the deletion process without actually deleting folders.
- `-SkipConfirmation` (Optional): Switch to skip the confirmation prompt before deletion.
- `-LogFile <string>` (Optional): Path to a log file where all actions and results are recorded.

**Usage Examples**:
- Basic one-time cleanup: `.\DeleteOldFolders.ps1 -DrivePath "C:\Temp" -DaysOld 30`
- Simulation mode (safe to test): `.\DeleteOldFolders.ps1 -DrivePath "C:\Temp" -DaysOld 30 -WhatIf`
- Automated with logging: `.\DeleteOldFolders.ps1 -DrivePath "C:\Backups" -DaysOld 90 -LogFile "C:\Logs\cleanup.log" -SkipConfirmation`
- Scheduled task setup: Use Windows Task Scheduler to run the script daily with parameters like `-DrivePath "C:\Temp" -DaysOld 7 -LogFile "C:\Logs\cleanup.log" -SkipConfirmation`

**Notes**:
- The script determines folder age using the older of LastWriteTime or CreationTime.
- Supports long file paths and handles access-denied directories gracefully.
- Always use `-WhatIf` first to preview what would be deleted.
- Requires appropriate permissions to delete folders in the specified path.

### FileCopyMoveGUI.ps1

**Description**: This PowerShell script provides a graphical user interface (GUI) for performing file and folder copy or move operations with Robocopy-like features. It allows users to select source and destination directories, choose between copy and move operations, and configure options such as recursive copying, mirroring, and file exclusions.

**Parameters**:
- None (interactive GUI application)

**Usage Examples**:
- Run the script: `.\FileCopyMoveGUI.ps1`
- Select source folder using the Browse button
- Select destination folder using the Browse button
- Choose operation type (Copy or Move)
- Configure options as needed (Recursive, Mirror, Exclusions)
- Click Start to begin the operation
- Monitor progress and view logs in the interface

**Notes**:
- Requires Windows Forms assemblies (included in the script)
- Uses robocopy.exe for the actual file operations
- Supports recursive copying, mirroring, and file exclusions
- Provides real-time progress tracking and error logging
- Cancel button allows stopping the operation mid-process
- Requires appropriate permissions for source and destination paths

### CopyFileToServer.ps1

**GUI**: `CopyFileToServer-GUI.ps1` opens a desktop window for the same job. You can paste or import a server list, edit or untick individual servers, check connections, copy several servers at once with a live status for each, and retry the ones that failed. See [CopyFileToServer/README.md](CopyFileToServer/README.md).

**Description**: A PowerShell script that copies a single file to multiple destination servers. It creates the destination directory if it doesn't exist and handles errors gracefully for each server.

**Parameters**:
- `-SourceFile <string>` (Required): Path to the source file to copy (e.g., "C:\Scripts\script.ps1").
- `-DestServers <string[]>` (Required): Array of destination server names (e.g., @("Server01", "Server02")).
- `-DestPath <string>` (Required): Destination path on each server (e.g., "share\folder" or "C$\Scripts").

**Usage Examples**:
- Copy to multiple servers: `.\CopyFileToServer.ps1 -SourceFile "C:\Temp\file.txt" -DestServers @("Server01", "Server02") -DestPath "Shared\Files"`

**Notes**:
- Creates destination folders automatically if they don't exist
- Handles UNC paths for remote server destinations
- Continues to next server if one fails

### CursorFix.ps1

**Description**: A PowerShell script that fixes cursor visibility issues in Windows applications by enabling Overlay Test Mode for the Desktop Window Manager (DWM).

**Parameters**:
- None (no parameters required)

**Usage Examples**:
- Run as administrator: `.\CursorFix.ps1`

**Notes**:
- Requires administrator privileges to modify HKLM registry
- Changes take effect after logging off/on (or restarting the system)
- This is a common fix for cursor issues in Citrix, RDS, or other virtualized environments

## Citrix-FSLogix-HealthCollector

**Description**: Fleet health collector for Citrix, RDS, and FSLogix servers. Gathers **sampled performance metrics** and **critical / error / warning events** in a single pass, then rolls each machine up to one verdict with plain-English reasons. Built to produce a client-ready deliverable from one command.

**Files Included**:
- `Get-CitrixFSLogixHealth.ps1` - Main collector
- `Tests/Get-CitrixFSLogixHealth.Tests.ps1` - Pester suite (93 tests)
- `README.md` - Full documentation

**Two ways to choose targets**:
- **Broker discovery** (default) - asks a Delivery Controller for every VDA; `-AdditionalComputerName` appends non-VDA servers such as the FSLogix file servers.
- **Explicit list** - `-ComputerName` takes any set of Windows servers, with no Citrix SDK or Delivery Controller involved.

**Key behaviours**:
- Performance is **sampled** across a window (`-SampleSeconds`, default 30) and reported as average *and* peak, because a single counter read on a session host says almost nothing. `-SampleSeconds 0` gives a fast instantaneous reading, and the report says so.
- Processor queue length is **normalized per logical processor** - Microsoft's own published thresholds disagree, and all of them describe a single system-wide queue, so a raw threshold would flag every healthy multi-vCPU host.
- Citrix event channels are **discovered at runtime**, not hardcoded. Citrix does not publish the literal channel names, and a wrong guess would return zero rows while looking successful.
- Performance (CIM over WinRM, falling back to DCOM) and events (`Get-WinEvent` over RPC) are **tracked separately**. A machine is only called Unreachable when both fail, so a WinRM-blocked server still yields its event history.

**Usage**:
```powershell
# Every VDA in the site
.\Get-CitrixFSLogixHealth.ps1 -DeliveryController DDC01

# VDA fleet plus the FSLogix file servers, three days of event history
.\Get-CitrixFSLogixHealth.ps1 -DeliveryController DDC01 `
    -AdditionalComputerName FS01, FS02 -LastDays 3 -OutputPath C:\Reports\Contoso

# No Citrix - just name the servers
.\Get-CitrixFSLogixHealth.ps1 -ComputerName RDS01, RDS02, FS01 -SampleSeconds 120
```

**Output**: per-machine CSV, event CSV, **raw per-sample CSV** (so a performance claim stays auditable), and a self-contained dark HTML report with fleet tiles, a per-machine table, and the fleet-wide most common problems.

## Citrix-PerfTriage

**Description**: One-command performance triage for Citrix / RDS session hosts with FSLogix, including the Hyper-V hosts underneath. Runs the health collector, FSLogix log parser, storage event collector, RDS event export, DiskSpd profile share benchmark and the Hyper-V host scripts against the same servers and time window, then writes one summary report that says what to look at first.

**Files Included**:
- `Invoke-CitrixPerfTriage.ps1` - Orchestrator
- `Tests/Invoke-CitrixPerfTriage.Tests.ps1` - Pester suite (65 tests)
- `README.md` - Full documentation

**Key behaviours**:
- Each tool runs in its own Windows PowerShell 5.1 process with a time limit, so one failure never stops the rest.
- FSLogix profile re-attach times from the logs are fed into the storage event collector, so SMB or disk events that triggered them are flagged.
- The profile share is found from `VHDLocations` / `CCDLocations` and benchmarked by default (`-SkipStorageBenchmark` to leave it out - it writes a 1 GB test file and loads the share for ~30 s).
- When a Hyper-V host refuses access, it builds a **hand-off package** (read-only scripts, a one-command collector and plain-English instructions) for the Hyper-V administrators instead of failing.

**Usage**:
```powershell
.\Invoke-CitrixPerfTriage.ps1 -ComputerName CTXVDA01, CTXVDA02 -HyperVCluster HVCLUSTER01
.\Invoke-CitrixPerfTriage.ps1 -DeliveryController DDC01 -LookbackHours 72
```

To run it on a client server, build a portable kit first: `.\Citrix-PerfTriage\Invoke-CitrixPerfTriage.ps1 -CreateKit C:\Temp\CitrixPerfTriageKit.zip`, then copy, extract and run it there. On a Delivery Controller it finds the session hosts by itself.

## Get-AzureFilesFSLogixProfiles

**Description**: Lists every FSLogix profile/ODFC container (`.vhd`/`.vhdx`) on Azure Files shares with user name, SID, size and last-modified date, all through the Azure APIs. You don't need to map the share or connect to a file server. Given only a tenant, it finds the subscriptions, storage accounts and shares itself.

**Files**:
- `Get-AzureFilesFSLogixProfiles.ps1` - Main script
- `README.md` - Step-by-step guide for ASTs, including the permissions required

**Usage**:
```powershell
# Discover everything in the client tenant
.\Get-AzureFilesFSLogixProfiles.ps1 -TenantId contoso.onmicrosoft.com

# One known share
.\Get-AzureFilesFSLogixProfiles.ps1 -TenantId contoso.com -StorageAccountName stavdprofiles01 -ShareName fslogix
```
## RDS-FSLogix-EventExport

**Description**: Exports RDS- and FSLogix-related Windows event log entries for a time window to CSV plus a self-contained HTML report. Collects from **one or many** session hosts.

**Files Included**:
- `Export-RDSFSLogixEvents.ps1` - Main export script
- `Tests/Export-RDSFSLogixEvents.Tests.ps1` - Pester suite (30 tests)
- `README.md` - Full documentation

**Usage**:
```powershell
# Last 4 hours from the local host
.\Export-RDSFSLogixEvents.ps1 -LastHours 4

# Sweep a pool of session hosts into one combined report
.\Export-RDSFSLogixEvents.ps1 -ComputerName CTXVDA01, CTXVDA02, CTXVDA03 -LastHours 8
```

For a combined performance *and* event view across a fleet, use [Citrix-FSLogix-HealthCollector](#citrix-fslogix-healthcollector) instead.

## ServiceDesk-Toolkit

**Description**: Builds the Service Desk Escalation Toolkit, a bundle of about ten tools from this repository (sign-in checks, lockouts, drive maps, network reachability, Citrix/RDS/FSLogix, GAL hiding, M365 sign-in blocking) with one START HERE page for service desk staff. The bundle is generated from the tool folders, not kept in git, so it always matches the current tools.

**Files**:
- `Build-ServiceDeskToolkit.ps1` - Copies the git-tracked tool files into the bundle (no tests, no local run output)
- `README.md` - The START HERE page shipped as the bundle's README

**Usage**:
```powershell
# Build dist\ServiceDesk-Toolkit plus a zip for SharePoint
.\ServiceDesk-Toolkit\Build-ServiceDeskToolkit.ps1 -Zip -Force
```

## CitrixVDADiagnostics

**Description**: A comprehensive diagnostic tool for Citrix Virtual Desktop Agent (VDA) servers, specifically designed to monitor performance issues related to FSlogix user profiles. The tool analyzes disk queue length, storage space utilization, CPU and RAM usage per user, Windows update status, FSlogix version, and I/O performance, providing actionable recommendations for optimizing Citrix environments.

**Parameters**:
- `-ServerName <string>` (Optional, default: local computer): Target server for diagnostics.
- `-Verbose` (Optional): Switch to show detailed session information and critical update counts.

**Usage Examples**:
- Basic local diagnostics: `.\CitrixVDADiagnostics\CitrixVDADiagnostics.ps1`
- Remote server analysis: `.\CitrixVDADiagnostics\CitrixVDADiagnostics.ps1 -ServerName "CitrixServer01"`
- Verbose output: `.\CitrixVDADiagnostics\CitrixVDADiagnostics.ps1 -Verbose`
- Scheduled monitoring: Use Windows Task Scheduler to run daily with logging redirection

**Features**:
- **Citrix Session Monitoring**: Detects active user sessions using Citrix cmdlets or fallback methods
- **FSlogix Integration**: Automatically detects FSlogix version and analyzes profile VHD storage locations
- **Windows Update Monitoring**: Checks for pending Windows updates and critical security patches
- **Disk Performance Analysis**: Measures disk queue length for storage drives hosting user profiles
- **Storage Capacity Monitoring**: Tracks disk space usage with configurable thresholds
- **I/O Performance Diagnostics**: Measures read/write performance and latency for both local and network storage
- **Resource Usage Tracking**: Monitors CPU and RAM usage with per-user calculations
- **Automated Recommendations**: Provides actionable insights for performance optimization
- **Color-coded Alerts**: Visual indicators for OK/WARNING/CRITICAL status levels

**Thresholds**:
- Disk Queue Length: OK (< 2.0), WARNING (2.0-5.0), CRITICAL (> 5.0)
- Storage Usage: OK (< 80%), WARNING (80-90%), CRITICAL (> 90%)
- CPU per User: WARNING (> 80%), CRITICAL (> 100%)
- Memory per User: WARNING (> 1GB), CRITICAL (> 2GB)
- I/O Performance: Read/Write < 50 MB/s (Red), 50-100 MB/s (Yellow), > 100 MB/s (Green)
- I/O Latency: > 20ms (Red), 10-20ms (Yellow), < 10ms (Green)
- Windows Updates: > 10 pending (Red), 5-10 pending (Yellow), < 5 pending (Green)

**Notes**:
- Designed specifically for Citrix VDA servers with FSlogix
- Includes fallback methods for environments without Citrix PowerShell SDK
- Requires administrative privileges for performance counter access
- Compatible with Windows Server 2016+ and PowerShell 5.1+
- Can be run locally or against remote servers
- I/O testing for UNC paths creates temporary test files (1MB) that are automatically cleaned up
- Output can be redirected to log files for automated monitoring
- Windows Update checking requires Windows Update service access

### CloudSignInMgr.ps1 (Block 365 Sign-in)

**Description**: A collection of PowerShell scripts for managing Microsoft 365 cloud sign-in access for Active Directory users. Provides both one-time setup and ongoing management capabilities for blocking/unblocking cloud access.

**Scripts**:
- **CloudSignInMgr.ps1**: GUI-based tool for managing cloud sign-in blocking by setting/clearing the `msDS-cloudExtensionAttribute10` attribute on AD user accounts.
- **Block365SignIn-RuleBuilder.ps1**: Creates a custom Entra Connect synchronization rule that maps the `msDS-cloudExtensionAttribute10` AD attribute to `cloudFiltered` in Azure AD.

**Prerequisites**:
- Entra Connect server with Azure AD Connect installed and ADSync module available
- Domain-joined administrative workstation with Active Directory module
- Domain Admin or equivalent permissions for AD modifications
- Administrative access to Entra Connect server for rule creation

**Usage**:
1. **Setup (One-time)**: Run `Block365SignIn-RuleBuilder.ps1` on the Entra Connect server to create the synchronization rule.
2. **Management (Ongoing)**: Run `CloudSignInMgr.ps1` on a domain workstation to block/unblock users from cloud sign-in.

**Features**:
- Automatic domain detection and connector lookup for rule builder
- GUI with search, bulk selection, and confirmation prompts for user management
- Manual synchronization triggering
- Error handling and user-friendly messages

**Notes**:
- Run rule builder only once per Entra Connect server/domain
- GUI tool supports search, select all/deselect all, and bulk operations
- Changes take effect after Entra Connect synchronization cycle
- Uses cloud extension attribute that doesn't conflict with on-premises AD
- Test in non-production environment first

## Install-TeamsOnVirtualDesktop

**Description**: Downloads and installs Microsoft Teams on a Citrix VDA, RDS Terminal Server, or Azure Virtual Desktop (AVD) session host. Removes old Teams and new Teams if present, ensures prerequisites are met, and performs a clean installation. Sets `IsWVDEnvironment=1` for AVD media optimization on AVD deployments.

**Parameters**:
- `-TeamsDownloadUrl <string>` (Optional, default: official Microsoft URL): URL to download Teams MSIX.
- `-WebView2Url <string>` (Optional, default: official Microsoft URL): URL to download WebView2 runtime.

**Usage Examples**:
- Basic installation: `.\Install-TeamsOnVirtualDesktop\Install-TeamsOnVirtualDesktop.ps1 -DeploymentType AVD`
- Custom URLs: `.\Install-TeamsOnVirtualDesktop\Install-TeamsOnVirtualDesktop.ps1 -DeploymentType RDS -TeamsDownloadUrl "https://custom.url/teams.msix"`

**Notes**:
- Requires administrator privileges.
- Designed for Windows Server 2019 Citrix VDA environments.
- Automatically removes existing Teams installations before installing the new version.
- Ensures WebView2 and .NET Framework prerequisites are met.

## LocalAdminManager

**Description**: A PowerShell script for managing the local Administrators group on Windows computers by adding or removing domain users and groups.

**Parameters**:
- `-Action <string>` (Required): Action to perform ('Add' or 'Remove').
- `-Member <string>` (Required): Domain user or group in 'DOMAIN\Username' format.
- `-ComputerName <string>` (Optional): Target computer name (defaults to localhost).

**Usage Examples**:
- Add user locally: `.\LocalAdminManager\LocalAdminManager.ps1 -Action Add -Member "CONTOSO\JohnDoe"`
- Remove group remotely: `.\LocalAdminManager\LocalAdminManager.ps1 -Action Remove -Member "CONTOSO\DomainAdmins" -ComputerName "RemotePC01"`

**Notes**:
- Requires administrator privileges.
- Supports local and remote computer management.
- Domain users/groups must exist in Active Directory.

## DriveMap-Diagnostics

**Description**: A toolkit that diagnoses why a user's mapped network drive intermittently disappears. Gates on whether Group Policy Preferences logging is even turned on (it's off by default, so an empty report and a healthy machine otherwise look identical), collects endpoint and domain-side evidence, watches a drive live to catch the actual disappearance transition, and produces a ranked, plain-English verdict plus a tabbed HTML case report.

**Files Included**:
- `Invoke-DriveMapInvestigation.ps1` - Orchestrator; runs the gate and every collector below, then writes a ranked verdict
- `Test-DriveMapLoggingReadiness.ps1` - Prerequisite gate; also flags the "every other logon" and UAC split-token risks directly
- `Export-DriveMapEvidence.ps1` - Endpoint evidence collector (live/persistent mounts, GPP events, logon scripts, scheduled tasks, startup items)
- `Watch-DriveMapActivity.ps1` - Live watcher; captures full context at the moment the drive actually disappears
- `New-DriveMapCaseReport.ps1` - Builds the self-contained, tabbed HTML case report
- `DriveMapReference.psd1` - Shared, documented event IDs and registry paths
- `README.md` - Full documentation, including a PS Remoting setup guide and known limitations

**Prerequisites**:
- PowerShell 5.1 or later
- RSAT `GroupPolicy` and `ActiveDirectory` modules (for the domain-side steps)
- Local administrator rights on the target machine for elevated-context checks
- PowerShell Remoting (WinRM) if collecting evidence remotely — optional; evidence can be collected locally and handed back instead

**Usage Examples**:
- Full investigation: `.\DriveMap-Diagnostics\Invoke-DriveMapInvestigation.ps1 -Identity jsmith -ComputerName WS01 -DriveLetter X`
- Check whether a machine's evidence can even be trusted first: `.\DriveMap-Diagnostics\Test-DriveMapLoggingReadiness.ps1 -ComputerName WS01 -DriveLetter X`
- Watch a drive live to catch the disappearance itself: `.\DriveMap-Diagnostics\Watch-DriveMapActivity.ps1 -DriveLetter X -DurationHours 8`

For full documentation, see [DriveMap-Diagnostics/README.md](DriveMap-Diagnostics/README.md)

# SMB Diagnostic & Drive Mapping Script

**Description:**  
This PowerShell script diagnoses SMB connectivity, detects protocol versions, tests access, lists files, and maps network drives between Windows clients (Windows 7–11) and Windows Servers (2008–2022).

## Features

- ✅ Test TCP connectivity to SMB port 445
- ✅ Check active SMB sessions
- ✅ Detect SMB protocol version (SMB1/2/3)
- ✅ Test folder access and permissions
- ✅ List files and folders in the target share
- ✅ Map network drives safely
- ✅ Color-coded output:
  - **Green** = Pass
  - **Yellow** = Warning
  - **Red** = Fail/Error

## Requirements

- PowerShell 3.0+
- Windows clients: Windows 7 – 11
- Windows servers: Server 2008 – 2022
- Network access to the SMB share (TCP 445)
- Permissions to access the target share

> SMB dialect detection requires Windows 8 / Server 2012+. Legacy servers fallback to `net use`.

## Installation & Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/chihlasm/powershell-script-collection.git
   cd powershell-script-collection
**Configure the script (SMB_Diagnostic.ps1) by editing the variables:**

$ServerIP   = "xxx.xxx.xxx.xxx"   # Replace with your SMB server IP
$ShareName  = "folder"            # Replace with your share name
$DriveLetter = "Z"                # Desired local drive letter


**Run the script in PowerShell:**

powershell.exe -ExecutionPolicy Bypass -File .\SMB_Diagnostic.ps1


**The script performs the following steps:**

Step 1: Test TCP connectivity to SMB port 445 
Step 2: Check existing SMB sessions on the client and server
Step 3: Detect SMB protocol version (SMB1/2/3)
Step 4: Test folder access and permissions
Step 5: List files and folders in the share
Step 6: Map network drive to the chosen letter

**Example Output**
=== Step 1: Test TCP connectivity on port 445 ===
[PASS] TCP connection to SMB port 445 successful.

=== Step 2: Check existing SMB sessions ===
[INFO] Active SMB sessions found:
ServerName    ShareName UserName  Dialect
----------    --------- --------  -------
192.168.1.10  Share1    DOMAIN\User  3.1.1

=== Step 3: Detect SMB protocol version ===
[PASS] SMB2/3 in use — modern protocol, Explorer should work.

=== Step 4: Test folder access ===
[PASS] Access to \\192.168.1.10\Share1 successful.

=== Step 5: List files/folders ===
[PASS] Files/folders in \\192.168.1.10\Share1:
Name           Length LastWriteTime
----           ------ -------------
File1.txt      1024   9/23/2025 8:45 AM
Folder1        0      9/22/2025 3:12 PM

=== Step 6: Map network drive Z: ===
[PASS] Mapped \\192.168.1.10\Share1 to drive Z:

=== Diagnostic Complete ===

Notes

SMB1 detected → Consider enabling SMB2/3 on the server to prevent Explorer hangs.

Admin rights not required for diagnostics; may be required for persistent drives.

Fully safe for internal networks; changes are limited to the mapped share.

## Get-CitrixSessions

**Description**: A PowerShell script that queries Citrix VDA sessions using the Citrix Broker Admin SDK for comprehensive session monitoring and CSV export. Displays detailed session information including user details, connection properties, idle time, and client information.

**Parameters**:
- `-VdaMachineName <string>` (Optional): Target VDA machine name (e.g., "DOMAIN\VDAServer01").
- `-OutputPath <string>` (Optional): Path for CSV export file.

**Usage Examples**:
- Query all active sessions: `.\Get-CitrixSessions\Get-CitrixSessions.ps1`
- Query specific VDA: `.\Get-CitrixSessions\Get-CitrixSessions.ps1 -VdaMachineName "DOMAIN\VDAServer01"`
- Export to CSV: `.\Get-CitrixSessions\Get-CitrixSessions.ps1 -OutputPath "C:\Reports\Sessions.csv"`

**Prerequisites**:
- Citrix Virtual Apps & Desktops PowerShell SDK (on Delivery Controller or with Studio installed)
- Administrative permissions for Citrix session management

For full documentation, see [Get-CitrixSessions/README.md](Get-CitrixSessions/README.md)

## FolderPermissionManager

**Description**: A PowerShell script for managing permissions on folders and their sub-folders. It allows taking ownership of sub-folders, reviewing current permissions, and replicating permissions from the top-level folder to all sub-folders.

**Parameters**:
- `-Path <string>` (Optional): The path to the top-level folder. If not provided, the script will prompt for it.

**Usage Examples**:
- Run with path: `.\FolderPermissionManager\FolderPermissionManager.ps1 -Path "C:\SharedFolder"`
- Run without path (prompts): `.\FolderPermissionManager\FolderPermissionManager.ps1`

**Notes**:
- Requires administrative privileges to modify ownership and permissions.
- Run the script from an elevated PowerShell session.
- Taking ownership uses `icacls` and may fail without proper permissions.
- Replicating permissions adds the top-level folder's access rules to sub-folders without removing existing permissions (ownership is taken at the beginning).
- Test on a small folder first to understand the behavior.

## FSLogix-Profile-Backup

**Description**: A comprehensive collection of PowerShell scripts for backing up and restoring FSLogix user profile settings in virtual desktop environments. When FSLogix profiles need to be rebuilt or migrated, important user customizations are often lost. This toolkit backs up and restores Windows Explorer Quick Access shortcuts, Chrome/Edge bookmarks, display and scaling settings, taskbar configurations, and browser password export instructions.

**Scripts Included**:
- `Backup-FSLogixProfile.ps1` - Main orchestration script that runs all individual backups
- `Restore-FSLogixProfile.ps1` - Main restoration script that orchestrates all restores
- Individual backup/restore scripts for each component (Quick Access shortcuts, browser bookmarks, display settings, taskbar settings, browser passwords)

**Parameters** (Backup-FSLogixProfile.ps1):
- `-BackupPath <string>` (Optional, default: ".\FSLogixBackups"): Root directory for backups
- `-CreateZip <bool>` (Optional, default: true): Create ZIP archive of backup
- `-FSLogixProfile <string>` (Optional): Path to FSLogix VHD/VHDX file for offline backup
- `-MountProfile <switch>` (Optional): Enable mounting of FSLogix profile (requires -FSLogixProfile)

**Parameters** (Restore-FSLogixProfile.ps1):
- `-BackupPath <string>` (Optional): Path to backup directory to restore from
- `-SkipRegistry <switch>` (Optional): Skip registry-based restorations
- `-SkipBrowser <switch>` (Optional): Skip browser-related restorations

**Usage Examples**:
- Full profile backup: `.\FSLogix-Profile-Backup\Backup-FSLogixProfile.ps1`
- Offline FSLogix backup: `.\FSLogix-Profile-Backup\Backup-FSLogixProfile.ps1 -MountProfile -FSLogixProfile "C:\FSLogixProfiles\User123.vhd"`
- Full profile restore: `.\FSLogix-Profile-Backup\Restore-FSLogixProfile.ps1`
- Selective restore: `.\FSLogix-Profile-Backup\Restore-FSLogixProfile.ps1 -SkipBrowser`

**Features**:
- **Multi-Profile Support**: Automatically detects and backs up all Chrome/Edge profiles (Default, Profile 1, Profile 2, etc.)
- **Offline Backup Capability**: Mount FSLogix VHD/VHDX files for offline profile backups
- **Progress Tracking**: Real-time progress indicators for long backup operations
- **Modular Design**: Individual scripts for each component (bookmarks, registry settings, etc.)
- **Error Resilience**: Continues with other backups even if one component fails
- **Backup Manifest**: Creates detailed manifest with backup contents and metadata
- **Security-Enhanced**: Modern PowerShell patterns with secure parameter handling

**Prerequisites**:
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or later
- Administrator privileges recommended
- Google Chrome and/or Microsoft Edge installed (for browser backups)
- FSLogix agent installed (for offline backup capability)

**Notes**:
- Browser passwords require manual export due to security restrictions
- Registry settings may not restore correctly across different hardware/OS versions
- Test restoration procedures on non-production systems first
- Scripts assume default browser profile locations
- Supports both online (current user) and offline (VHD/VHDX file) backup modes

For full documentation, see [FSLogix-Profile-Backup/README.md](FSLogix-Profile-Backup/README.md)

## AD-GroupPolicy-Audit

**Description**: A comprehensive Active Directory Group Policy audit tool that analyzes all GPOs in a domain for duplicates, conflicts, optimization opportunities, security issues, and FSLogix configuration problems. Generates detailed HTML and CSV reports.

**Files Included**:
- `Audit-ADGroupPolicy.ps1` - Consolidated GPO audit script

**Parameters**:
- `-OutputPath <string>` (Optional, default: script directory): Directory where reports will be saved.
- `-IncludeFSLogix <bool>` (Optional, default: $true): Include FSLogix-specific policy audit.
- `-ExportFormat <string>` (Optional, default: Both): Export format for reports (HTML, CSV, or Both).
- `-ExportXML <bool>` (Optional, default: $true): Export individual and combined GPO XML files.
- `-Domain <string>` (Optional): Specific domain to audit.
- `-Credential <PSCredential>` (Optional): Credential for connecting to domain.
- `-SkipBrowserOpen` (Optional): Do not open the HTML report in the default browser.

**Usage Examples**:
- Full audit: `.\AD-GroupPolicy-Audit\Audit-ADGroupPolicy.ps1`
- HTML only: `.\AD-GroupPolicy-Audit\Audit-ADGroupPolicy.ps1 -OutputPath "C:\Reports" -ExportFormat HTML`
- Specific domain: `.\AD-GroupPolicy-Audit\Audit-ADGroupPolicy.ps1 -Domain "contoso.com" -IncludeFSLogix $false`

**Features**:
- **GPO Report Caching**: Fetches XML reports once per GPO and reuses across all analysis passes for performance
- **Duplicate Detection**: SHA256 hash comparison for exact duplicates plus similar name detection
- **Conflict Analysis**: Identifies registry settings configured differently across multiple GPOs
- **Optimization Checks**: Finds empty, unlinked, stale, and disabled GPOs
- **Security Analysis**: Reviews GPO permissions for overly permissive access
- **Security Filtering Audit**: Detects GPOs that will not apply to anyone
- **FSLogix Audit**: Analyzes FSLogix-specific settings, conflicts, and best practices
- **HTML-Escaped Output**: All dynamic values in HTML reports are escaped to prevent markup issues
- **Progress Indicators**: Write-Progress bars for all long-running operations

**Prerequisites**:
- GroupPolicy module (via RSAT)
- ActiveDirectory module (via RSAT)
- Domain permissions to read GPO settings and permissions

## HideFromGal

**Description**: A collection of PowerShell scripts for managing user visibility in the Exchange Online Global Address List (GAL) using Entra Connect synchronization rules. Provides both one-time setup and ongoing management capabilities for hiding users from GAL.

**Scripts**:
- **HideFromGal-RuleBuilder.ps1**: Creates a custom Entra Connect synchronization rule that maps the `msDS-cloudExtensionAttribute1` AD attribute to `msExchHideFromAddressLists` in Exchange Online.
- **HideFromGAL.ps1**: GUI-based tool for managing GAL visibility by setting/clearing the `msDS-cloudExtensionAttribute1` attribute on AD user accounts.

**Prerequisites**:
- Entra Connect server with Azure AD Connect installed and ADSync module available
- Domain-joined administrative workstation with Active Directory module
- Domain Admin or equivalent permissions for AD modifications
- Administrative access to Entra Connect server for rule creation

**Usage**:
1. **Setup (One-time)**: Run `HideFromGal-RuleBuilder.ps1` on the Entra Connect server to create the synchronization rule.
2. **Management (Ongoing)**: Run `HideFromGAL.ps1` on a domain workstation to hide/unhide users from GAL.

**Features**:
- Automatic domain detection and connector lookup
- GUI with search, bulk selection, and confirmation prompts
- Manual synchronization triggering
- Comprehensive logging to `C:\Temp\`
- Error handling and user-friendly messages

**Notes**:
- Run rule builder only once per Entra Connect server/domain
- GUI tool supports search, select all/deselect all, and bulk operations
- Changes take effect after Entra Connect synchronization cycle
- Uses cloud extension attribute that doesn't conflict with on-premises AD
- Test in non-production environment first

## Entra-DeviceActivityTimeline

When was one Windows device on, asleep, locked, unlocked and signed in to? For Microsoft Entra joined / Intune managed devices, where there is no domain to query from. Runs on the device itself (RMM session, Defender Live Response, or an Intune Remediation run on demand) and writes an HTML day-by-day report plus CSVs, zipped for collection.

```powershell
.\Entra-DeviceActivityTimeline\Get-DeviceActivityTimeline.ps1 -UserName jdoe@contoso.com -DaysBack 30
```

- Says up front whether lock/unlock (4800/4801) can exist. The audit setting that writes them is off by default in Intune, so the report recovers unlocks from the sign-in record (4624 type 7) instead
- Recovers real wake times after long sleeps, which Windows logs with the frozen pre-sleep clock
- `-IntuneSummary` fits the answer into Intune's 2,048-character Remediation output; `-EnableLockAuditing` starts recording lock/unlock now

See [Entra-DeviceActivityTimeline/README.md](Entra-DeviceActivityTimeline/README.md).
