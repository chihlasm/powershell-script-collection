# Get-CitrixSessions.ps1

## Overview

Get-CitrixSessions.ps1 is a PowerShell script that retrieves and displays Citrix Virtual Desktop Infrastructure (VDI) session information using the Citrix Broker Admin SDK. The script provides comprehensive session details including user information, session state, client details, and connection metrics, with optional CSV export functionality.

## Features

- ✅ Query sessions from specific VDA or entire Citrix site
- ✅ Display comprehensive session information in tabular format
- ✅ Multiple Citrix module loading methods for compatibility
- ✅ Optional CSV export with UTF-8 encoding
- ✅ Color-coded output for better readability
- ✅ Robust error handling and informative messages
- ✅ Verbose logging for troubleshooting

## Requirements

### Prerequisites

- **PowerShell**: Version 5.1 or higher (PSCore compatible)
- **Citrix Licenses**: Valid Citrix Virtual Apps & Desktops licenses
- **Permissions**: Administrative access to Citrix Delivery Controllers or VDA servers
- **Network Access**: Connectivity to Citrix Delivery Controllers

### Module Requirements

The script requires one of the following Citrix PowerShell modules:

- **PSSnapin**: Citrix.Broker.Admin.V2 (available on Delivery Controllers)
- **Module**: Citrix.Broker.Admin.V2 (newer installations)

If not installed, you'll receive an error message with installation guidance:
```
Citrix PowerShell modules are not installed. Please install Citrix Virtual Apps & Desktops PowerShell SDK from the Citrix Delivery Controller or use a machine with Citrix VDA/Citrix Server installed.
```

## Installation

1. Download `Get-CitrixSessions.ps1` to your preferred directory
2. Ensure execution policy allows script execution:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
3. If needed, run PowerShell as Administrator

## Usage

### Syntax

```powershell
.\Get-CitrixSessions.ps1 [-VdaMachineName <string>] [-OutputPath <string>] [-Verbose]
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `VdaMachineName` | String | No | All sessions | Target VDA machine (DOMAIN\Machine) |
| `OutputPath` | String | No | No export | Full path for CSV export file |
| `Verbose` | Switch | No | Disabled | Show detailed progress messages |

### Examples

#### Basic Usage - All Sessions

```powershell
.\Get-CitrixSessions.ps1
```

Queries all active sessions across the Citrix site and displays them in the console.

#### Query Specific VDA

```powershell
.\Get-CitrixSessions.ps1 -VdaMachineName "DOMAIN\VDAServer01"
```

Retrieves only sessions running on the specified Virtual Desktop Agent.

#### Export to CSV

```powershell
.\Get-CitrixSessions.ps1 -OutputPath "C:\Reports\CitrixSessions_20251023.csv"
```

Exports session data to a CSV file in the specified location.

#### Verbose Mode

```powershell
.\Get-CitrixSessions.ps1 -VdaMachineName "DOMAIN\VDAServer01" -OutputPath "C:\Temp\Sessions.csv" -Verbose
```

Combines all options with verbose logging output.

## Output Data

The script displays and exports the following session information:

| Field | Description | Example |
|-------|-------------|---------|
| UserName | Active Directory username | DOMAIN\john.doe |
| FullName | User display name | John Doe |
| MachineName | VDA server hosting session | DOMAIN\VDAServer01 |
| SessionState | Human-readable state | Active |
| SessionStateRaw | Raw session status | Established |
| ClientName | Client device hostname | JD-Laptop |
| LogonTime | Session brokering timestamp | 10/23/2025 2:00:00 PM |
| IdleDuration | Session idle time | 00:05:30 |
| DeliveryGroup | Citrix delivery group | Production Users |
| ClientAddress | Client IP address | 192.168.1.100 |
| ClientVersion | Citrix Receiver/Workspaces version | 24.4.10.12 |
| Protocol | Connection protocol | HDX |
| EstablishmentTime | Session establishment timestamp | 10/23/2025 1:58:45 PM |

## Color Coding

The script uses console colors to indicate different states:

- **White**: Normal information
- **Yellow**: Warning messages (e.g., no sessions found)
- **Green**: Success messages (e.g., export completed)
- **Red**: Error messages

## Common Use Cases

### Citrix Administration

- **User Monitoring**: Track logged-in users and their activities
- **Load Balancing**: Monitor session distribution across VDA servers
- **Troubleshooting**: Investigate connection issues and session states
- **Capacity Planning**: Analyze session patterns and usage metrics

### Scripting and Automation

- **Scheduled Reports**: Generate daily session reports via Task Scheduler
- **Alerting**: Check for exceeded session limits or unusual activities
- **Maintenance**: Identify sessions before server shutdown
- **Auditing**: Log session information for compliance requirements

## Troubleshooting

### Common Issues

**"Citrix PowerShell modules are not installed"**
- Run the script on a Citrix Delivery Controller
- Install Citrix Studio on management workstation
- Ensure you have Citrix Virtual Apps licenses

**No Sessions Found**
- Verify permissions to query Citrix sessions
- Check if Delivery Controller is reachable
- Confirm VDA machines are registered and online

**Access Denied Errors**
- Run PowerShell as Administrator
- Ensure account has Citrix administrative permissions
- Check network connectivity to Delivery Controllers

**Module Loading Failures**
- Older Citrix versions: Use PSSnapin method
- Newer versions: Use Import-Module method
- Enterprise environments: Install Citrix SDK components

### Diagnostic Commands

Check installed Citrix modules:
```powershell
Get-PSSnapin | Where-Object {$_.Name -like "*Citrix*"}
Get-Module | Where-Object {$_.Name -like "*Citrix*"}
```

Test Connectivity to Delivery Controller:
```powershell
Test-NetConnection -ComputerName "DeliveryControllerName" -Port 80
```

Check Citrix Site:
```powershell
# From Delivery Controller
Get-BrokerController
Get-BrokerMachine
```

## Security Considerations

- **Authentication**: Run with minimal required permissions
- **Network**: Store CSV files in secure locations
- **Information Disclosure**: Session data contains user and client information
- **Auditing**: Log script execution for compliance tracking

## Performance Notes

- **Query Scope**: Limit to specific VDA when possible for faster results
- **Large Sites**: Add pagination if querying thousands of sessions
- **CSV Export**: Consider compressing large exports for transfer
- **Frequency**: Use appropriate intervals for automated monitoring

## Exit Codes

- **0**: Success (sessions found and displayed)
- **1**: Error (module loading, permissions, connectivity issues)

## Examples in Scripts

### Batch File for Scheduled Reporting

```batch
@echo off
powershell.exe -ExecutionPolicy Bypass -File "C:\Scripts\Get-CitrixSessions.ps1" -OutputPath "C:\Reports\DailySessions_%date:~-4,4%%date:~-10,2%%date:~-7,2%.csv"
```

### Integration with Monitoring Systems

```powershell
# PowerShell function for integration
function Get-CitrixSessionCount {
    $sessions = & "Get-CitrixSessions.ps1"
    return $sessions.Count
}
```

## Version History

- **v1.0** (2025-10-23): Initial release
  - Basic session querying and display
  - Multiple module loading compatibility
  - CSV export functionality
  - Comprehensive error handling

## License

This script is provided as-is for administrative and monitoring purposes. Test thoroughly in non-production environments before implementing in production scenarios.

## Support

For issues or questions:

1. Verify all prerequisites are met
2. Test with simple parameters first
3. Use `-Verbose` for detailed debugging
4. Check Citrix delivery controller logs if available
5. Consult Citrix documentation for module installation
