# Block 365 Sign-in Manager

## Overview

The **CloudSignInMgr.ps1** script provides a graphical user interface (GUI) for managing Microsoft 365 cloud sign-in access for Active Directory users. This tool allows administrators to selectively block or allow cloud sign-in for users while maintaining their local Active Directory authentication capabilities.

## How It Works

The script leverages Azure AD Connect synchronization rules to control cloud sign-in behavior by manipulating the `msDS-cloudExtensionAttribute10` Active Directory attribute:

- **Block Cloud Sign-In**: Sets `msDS-cloudExtensionAttribute10 = "BlockCloudSignIn"`
- **Allow Cloud Sign-In**: Clears the `msDS-cloudExtensionAttribute10` attribute (sets to null/empty)

When Azure AD Connect synchronizes these changes to Azure AD, users with the "BlockCloudSignIn" value will be unable to sign into Microsoft 365 services (including Office 365, Azure AD, etc.) while retaining full access to their local Active Directory domain resources.

## Prerequisites

- **Active Directory Environment**: Domain-joined computer with Active Directory PowerShell module
- **Permissions**: Domain Administrator or equivalent permissions to modify user attributes
- **Azure AD Connect**: Installed and configured for synchronization
- **PowerShell Version**: 5.1 or higher
- **Windows Forms**: .NET Framework with Windows Forms support (included by default on Windows Server 2016+)

## Installation

1. Download the `CloudSignInMgr.ps1` script to your domain controller or management workstation
2. Ensure the Active Directory PowerShell module is available:
   ```powershell
   Import-Module ActiveDirectory
   ```
3. Configure Azure AD Connect synchronization rules (see Configuration section below)

## Usage

### Running the Script

1. Open PowerShell as Administrator
2. Navigate to the script directory:
   ```powershell
   cd "C:\Path\To\Block 365 Sign-in"
   ```
3. Execute the script:
   ```powershell
   .\CloudSignInMgr.ps1
   ```

### GUI Interface

The script opens a Windows Forms GUI with the following components:

#### User Management Grid
- **Columns**:
  - Select: Checkbox for user selection
  - Username: Active Directory SamAccountName
  - Full Name: Display name
  - Enabled: Account status
  - Cloud Sign-In Status: Current blocking status (Allowed/Blocked)

#### Search Functionality
- Real-time search by username or display name
- Filters the user list as you type

#### Action Buttons
- **Refresh List**: Reloads the user list from Active Directory
- **Select All**: Selects all visible users
- **Deselect All**: Clears all selections
- **Block Cloud Sign-In**: Applies blocking to selected users
- **Unblock Cloud Sign-In**: Removes blocking from selected users

### Workflow

1. **Search Users**: Use the search box to find specific users
2. **Select Users**: Check the boxes next to users you want to modify
3. **Choose Action**: Click "Block Cloud Sign-In" or "Unblock Cloud Sign-In"
4. **Confirm**: Review the confirmation dialog and click Yes
5. **Sync Changes**: Optionally trigger Azure AD Connect synchronization

## Azure AD Connect Configuration

To enable cloud sign-in blocking, you must configure Azure AD Connect synchronization rules to process the `msDS-cloudExtensionAttribute10` attribute.

### Method 1: Using Synchronization Rules Editor

1. Open **Azure AD Connect** on your sync server
2. Click **Synchronization Rules Editor**
3. Create a new **Inbound** synchronization rule:
   - **Name**: "In from AD - User BlockCloudSignIn"
   - **Connected System**: Your Active Directory domain
   - **Connected System Object Type**: user
   - **Metaverse Object Type**: person
   - **Link Type**: Join
   - **Precedence**: Choose an appropriate precedence (lower numbers = higher priority)

4. **Scoping Filter**:
   - Add condition: `msDS-cloudExtensionAttribute10 ISNOTNULL`

5. **Join Rules**:
   - Source Attribute: `msDS-cloudExtensionAttribute10`
   - Target Attribute: `msDS-cloudExtensionAttribute10`
   - Join type: `Expression`

6. **Transformations**:
   - Flow Type: `Expression`
   - Target Attribute: `cloudFiltered`
   - Source: `IIF(IsPresent([msDS-cloudExtensionAttribute10]) && [msDS-cloudExtensionAttribute10] = "BlockCloudSignIn", True, False)`

### Method 2: Using PowerShell

```powershell
# Import ADSync module
Import-Module ADSync

# Create the synchronization rule
New-ADSyncRule `
    -Name 'In from AD - User BlockCloudSignIn' `
    -Identifier '12345678-1234-1234-1234-123456789012' `
    -Description 'Rule to block cloud sign-in based on msDS-cloudExtensionAttribute10' `
    -Direction 'Inbound' `
    -Precedence 100 `
    -PrecedenceAfter '00000000-0000-0000-0000-000000000000' `
    -PrecedenceBefore '00000000-0000-0000-0000-000000000000' `
    -SourceObjectType 'user' `
    -TargetObjectType 'person' `
    -Connector 'your-ad-connector-guid' `
    -LinkType 'Join' `
    -SoftDeleteExpiryInterval 0 `
    -ImmutableTag '' `
    -OutVariable syncRule

# Add transformations
Add-ADSyncAttributeFlowMapping `
    -SynchronizationRule $syncRule[0] `
    -Destination 'cloudFiltered' `
    -FlowType 'Expression' `
    -ValueMergeType 'Update' `
    -Expression 'IIF(IsPresent([msDS-cloudExtensionAttribute10]) && [msDS-cloudExtensionAttribute10] = "BlockCloudSignIn", True, False)' `
    -OutVariable attributeFlowMapping
```

### Verification

After creating the rule:

1. Run a **Full Synchronization** cycle:
   ```powershell
   Start-ADSyncSyncCycle -PolicyType Initial
   ```

2. Verify the rule is working by checking Azure AD user properties in the Azure portal

## Synchronization Timing

- **Default Sync Interval**: Every 30 minutes (configurable)
- **Manual Sync**: Use the script's sync prompt or run:
  ```powershell
  Start-ADSyncSyncCycle -PolicyType Delta
  ```
- **Force Full Sync** (for testing):
  ```powershell
  Start-ADSyncSyncCycle -PolicyType Initial
  ```

## Troubleshooting

### Common Issues

#### Script Won't Load Users
- **Cause**: Insufficient AD permissions or module not loaded
- **Solution**: Run as Domain Admin, ensure ActiveDirectory module is imported

#### Changes Not Taking Effect in Cloud
- **Cause**: Synchronization hasn't run or rule not configured
- **Solution**: Check Azure AD Connect event logs, verify sync rules, run manual sync

#### Attribute Not Syncing
- **Cause**: Synchronization rule misconfiguration
- **Solution**: Verify rule precedence and transformations in Synchronization Rules Editor

#### GUI Not Displaying
- **Cause**: Windows Forms assemblies not available
- **Solution**: Ensure .NET Framework is properly installed

### Error Messages

- **"Access denied"**: Check user permissions for AD attribute modification
- **"Module not found"**: Install RSAT tools or import ActiveDirectory module
- **"Sync failed"**: Check Azure AD Connect service status and event logs

### Logs and Monitoring

- **Script Logs**: Check PowerShell console for error messages
- **AD Connect Logs**: View in Event Viewer under Applications and Services Logs > Microsoft > Azure AD Connect
- **Azure AD Audit Logs**: Check in Azure portal for synchronization events

## Security Considerations

- **Principle of Least Privilege**: Run with minimum required permissions
- **Audit Trail**: Changes are logged in Active Directory audit logs
- **Backup**: Always backup AD before bulk operations
- **Testing**: Test with a small group of users first

## Advanced Usage

### Bulk Operations via PowerShell

```powershell
# Block multiple users
$users = "user1", "user2", "user3"
foreach ($user in $users) {
    Set-ADUser -Identity $user -Add @{'msDS-cloudExtensionAttribute10'="BlockCloudSignIn"}
}

# Unblock users
foreach ($user in $users) {
    Set-ADUser -Identity $user -Clear 'msDS-cloudExtensionAttribute10'
}
```

### Custom Synchronization Rules

For complex scenarios, you can create conditional rules based on:
- Group membership
- Organizational unit
- Other AD attributes
- Time-based conditions

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Verify Azure AD Connect configuration
3. Review Active Directory permissions
4. Consult Microsoft documentation for Azure AD Connect

## Version History

- **v1.0**: Initial release with basic GUI functionality
- **v1.1**: Added search functionality and bulk operations
- **v1.2**: Integrated Azure AD Connect sync triggering
- **v1.3**: Enhanced error handling and user feedback

---

**Note**: This tool requires proper understanding of Active Directory and Azure AD Connect. Always test in a development environment before production use.
