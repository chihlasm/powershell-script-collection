# Active Directory Group Members Export Tool

A comprehensive PowerShell script to export user members from multiple Active Directory groups with flexible output options.

## Features

- **Multiple Group Support**: Export members from multiple AD groups in a single operation
- **Flexible Output**: Choose between individual CSV files per group or combined output
- **Nested Groups**: Option to include members from nested groups (recursive membership)
- **Rich User Data**: Exports comprehensive user information including contact details, department, and account status
- **Group Information**: Optional inclusion of group metadata (description, category, scope, etc.)
- **Comprehensive Logging**: Detailed logging with timestamps and error handling
- **Progress Tracking**: Real-time progress updates during processing
- **Error Handling**: Robust error handling with graceful failure recovery

## Files Included

- `Export-MultipleADGroupMembers.ps1` - Main PowerShell script
- `Export-ADGroupMembers-Example.ps1` - Usage examples and demonstrations
- `README-AD-Group-Export.md` - This documentation file

## Prerequisites

1. **Active Directory Module**: The script requires the Active Directory PowerShell module
   - Install RSAT (Remote Server Administration Tools) if not already installed
   - Or run on a Domain Controller

2. **Permissions**: You need appropriate AD permissions to read group membership
   - Domain User account with read access to the groups
   - For best results, run as Domain Administrator or with delegated permissions

3. **PowerShell Execution Policy**: Ensure PowerShell execution policy allows script execution
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Installation

1. Download the script files to your preferred location
2. Ensure you have the required prerequisites installed
3. Run PowerShell as Administrator

## Usage

### Basic Syntax

```powershell
.\Export-MultipleADGroupMembers.ps1 -GroupNames "Group1", "Group2", "Group3" [options]
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `GroupNames` | String[] | Yes | Array of group names to export members from |
| `OutputPath` | String | No | Directory path for output files (default: current directory) |
| `CombinedOutput` | Switch | No | Create a single combined CSV file instead of individual files |
| `IncludeNestedGroups` | Switch | No | Include members of nested groups (recursive membership) |
| `IncludeGroupInfo` | Switch | No | Include group information in the output |

### Examples

#### Example 1: Basic Export
Export members from Domain Admins and Enterprise Admins to separate CSV files:
```powershell
.\Export-MultipleADGroupMembers.ps1 -GroupNames "Domain Admins", "Enterprise Admins"
```

#### Example 2: Combined Output
Export members from multiple groups to a single CSV file:
```powershell
.\Export-MultipleADGroupMembers.ps1 -GroupNames "IT Support", "Help Desk", "System Administrators" -CombinedOutput
```

#### Example 3: Include Nested Groups
Export members including those from nested groups:
```powershell
.\Export-MultipleADGroupMembers.ps1 -GroupNames "All Employees" -IncludeNestedGroups
```

#### Example 4: Custom Output Directory
Export to a specific directory with group information:
```powershell
.\Export-MultipleADGroupMembers.ps1 -GroupNames "Project Team A", "Project Team B" -OutputPath "C:\AD_Exports" -IncludeGroupInfo
```

#### Example 5: All Options Combined
Use all available options:
```powershell
.\Export-MultipleADGroupMembers.ps1 -GroupNames "Department A", "Department B" -OutputPath "C:\Reports" -CombinedOutput -IncludeNestedGroups -IncludeGroupInfo
```

#### Example 6: Dynamic Group Names
Use variables for dynamic group processing:
```powershell
$groupsToExport = @("Sales Team", "Marketing Team", "HR Department")
.\Export-MultipleADGroupMembers.ps1 -GroupNames $groupsToExport -CombinedOutput -OutputPath "C:\GroupReports"
```

## Output Files

### CSV Files
The script generates CSV files with the following naming convention:
- Individual files: `ADGroupMembers_GroupName_YYYYMMDD_HHMMSS.csv`
- Combined file: `ADGroupMembers_Combined_YYYYMMDD_HHMMSS.csv`

### CSV Columns
The exported CSV files contain the following user information:

| Column | Description |
|--------|-------------|
| GroupName | Name of the Active Directory group |
| DisplayName | User's display name |
| SamAccountName | User's login name (pre-Windows 2000) |
| UserPrincipalName | User's UPN (user@domain.com) |
| EmailAddress | User's email address |
| Department | User's department |
| Title | User's job title |
| Office | User's office location |
| Enabled | Account enabled status (True/False) |
| LastLogonDate | Date of last login |
| PasswordLastSet | Date password was last set |
| ExportDate | Date and time of export |

### Additional Columns (with -IncludeGroupInfo)
When using the `-IncludeGroupInfo` parameter, additional columns are added:

| Column | Description |
|--------|-------------|
| GroupDescription | Group description |
| GroupCategory | Security or Distribution group |
| GroupScope | Domain Local, Global, or Universal |
| GroupCreated | Group creation date |
| GroupModified | Group last modified date |

### Log File
A log file named `ADGroupExport.log` is created in the output directory containing:
- Processing start/end times
- Group processing status
- Error messages and warnings
- Export summary information

## Error Handling

The script includes comprehensive error handling:

- **Group Not Found**: Logs error and continues with next group
- **Permission Issues**: Logs error and provides helpful messages
- **Network Issues**: Retries operations and logs connectivity problems
- **Invalid Output Path**: Creates directory if it doesn't exist
- **Module Import Failures**: Provides installation guidance

## Troubleshooting

### Common Issues

1. **"Get-ADGroup : Cannot find an object with identity"**
   - Verify the group name is spelled correctly
   - Check if you have permissions to read the group
   - Try using the group's distinguished name

2. **"Import-Module : The specified module 'ActiveDirectory' was not loaded"**
   - Install RSAT (Remote Server Administration Tools)
   - Run PowerShell as Administrator
   - Check Windows features for "Active Directory module for Windows PowerShell"

3. **"Access is denied"**
   - Run PowerShell as Administrator
   - Ensure your account has read permissions on the groups
   - Check if you're in the correct domain

4. **Empty CSV files**
   - Verify groups contain user members (not just other groups)
   - Check if users are enabled accounts
   - Use `-IncludeNestedGroups` if users are in nested groups

### Getting Group Names

To find available group names in your domain:

```powershell
# List all groups
Get-ADGroup -Filter * | Select-Object Name, DistinguishedName

# Search for groups by name pattern
Get-ADGroup -Filter "Name -like '*admin*'" | Select-Object Name

# Get groups for a specific user
Get-ADUser -Identity "username" -Properties MemberOf | Select-Object -ExpandProperty MemberOf | Get-ADGroup | Select-Object Name
```

## Security Considerations

- The script only reads Active Directory data; it does not modify anything
- CSV files contain user information that should be handled according to your organization's data protection policies
- Consider encrypting sensitive exports or storing them in secure locations
- Log files may contain group names and processing details

## Performance Notes

- Processing large groups with nested membership can take time
- The script processes groups sequentially to avoid overwhelming the domain controllers
- For very large environments, consider running during off-peak hours
- The script includes progress indicators for long-running operations

## Support

If you encounter issues:

1. Check the log file (`ADGroupExport.log`) for detailed error messages
2. Verify all prerequisites are met
3. Test with a single small group first
4. Ensure you have appropriate network connectivity to domain controllers

## Version History

- **v1.0** (2025-08-29): Initial release with core functionality
  - Multiple group support
  - Flexible output options
  - Comprehensive error handling
  - Rich user data export
  - Detailed logging

## License

This script is provided as-is for educational and administrative purposes. Please test thoroughly in a non-production environment before using in production scenarios.
