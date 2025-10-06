# HideFromGal Scripts

This collection of PowerShell scripts provides a solution for hiding Active Directory users from the Global Address List (GAL) in Exchange Online using Entra Connect (formerly Azure AD Connect) synchronization rules.

## Scripts Overview

### HideFromGal-RuleBuilder.ps1
- **Purpose**: Creates a custom Entra Connect synchronization rule to map the `msDS-cloudExtensionAttribute1` attribute to `msExchHideFromAddressLists`.
- **When to Run**: Once per Entra Connect server/domain setup. This rule enables the hiding mechanism.
- **Execution Context**: Run on the Entra Connect server with administrative privileges.

### HideFromGAL.ps1
- **Purpose**: GUI-based tool for managing user visibility in the GAL by setting/clearing the `msDS-cloudExtensionAttribute1` attribute on AD user accounts.
- **When to Run**: Ongoing management - use this script to hide or unhide users as needed.
- **Execution Context**: Run on a domain-joined machine with Active Directory administrative access.

## Prerequisites

1. **Entra Connect Server**:
   - Azure AD Connect installed and configured
   - Administrative access to the server
   - ADSync module available

2. **Domain-Joined Machine** (for HideFromGAL.ps1):
   - Windows with PowerShell
   - Active Directory module for Windows PowerShell
   - Administrative privileges
   - Domain join status

3. **Permissions**:
   - Domain Admin or equivalent rights for AD modifications
   - Access to modify synchronization rules (Entra Connect server)

## Usage Instructions

### Step 1: Set Up the Synchronization Rule

1. Copy `HideFromGal-RuleBuilder.ps1` to your Entra Connect server.
2. Open PowerShell as Administrator on the Entra Connect server.
3. Navigate to the script location and run:
   ```powershell
   PowerShell -ExecutionPolicy Bypass -File .\HideFromGal-RuleBuilder.ps1
   ```
4. The script will:
   - Automatically detect the local AD domain
   - Find the corresponding AD connector
   - Create a new synchronization rule with a unique identifier
   - Configure attribute mapping: `msDS-cloudExtensionAttribute1` → `msExchHideFromAddressLists`
   - Enable the rule

5. Verify the rule was created successfully by checking the output.

### Step 2: Manage User GAL Visibility

1. Copy `HideFromGAL.ps1` to a domain-joined administrative workstation.
2. Open PowerShell as Administrator.
3. Navigate to the script location and run:
   ```powershell
   PowerShell -ExecutionPolicy Bypass -File .\HideFromGAL.ps1
   ```

4. The GUI will open with the following features:
   - **Search**: Filter users by name or username
   - **Select Users**: Check boxes to select users for bulk operations
   - **Hide from GAL**: Sets `msDS-cloudExtensionAttribute1 = "HideFromGAL"`
   - **Unhide from GAL**: Clears the `msDS-cloudExtensionAttribute1` attribute
   - **Sync to Entra**: Triggers a delta synchronization cycle

### Step 3: Verify Changes

After hiding/unhiding users:
- The synchronization rule will automatically apply during the next sync cycle
- Users with `msDS-cloudExtensionAttribute1 = "HideFromGAL"` will be hidden from Exchange Online GAL
- Changes typically take 15-30 minutes to propagate to Exchange Online

## How It Works

1. **Rule Creation**: The synchronization rule maps the AD attribute `msDS-cloudExtensionAttribute1` to the Exchange Online attribute `msExchHideFromAddressLists` using an expression that evaluates to `True` when the attribute equals "HideFromGAL".

2. **User Management**: The GUI script modifies the `msDS-cloudExtensionAttribute1` attribute on selected AD users.

3. **Synchronization**: Entra Connect syncs the attribute value, which controls GAL visibility in Exchange Online.

## Important Notes

- **One-Time Setup**: Run `HideFromGal-RuleBuilder.ps1` only once per Entra Connect server/domain combination.
- **Attribute Usage**: `msDS-cloudExtensionAttribute1` is a cloud extension attribute that syncs to Azure AD but doesn't conflict with on-premises usage.
- **Synchronization Timing**: Changes require a sync cycle to take effect. The script includes a manual sync trigger.
- **Logging**: `HideFromGAL.ps1` creates log files in `C:\Temp\` for auditing.
- **Error Handling**: Both scripts include error checking and user-friendly messages.
- **Testing**: Test in a non-production environment first.
- **Backup**: Ensure you have AD backups before making bulk changes.

## Troubleshooting

- **Rule Creation Fails**: Verify ADSync module is available and you have permissions to create sync rules.
- **Connector Not Found**: Ensure the Entra Connect server is domain-joined and the connector name matches the domain.
- **AD Modifications Fail**: Check domain admin rights and AD connectivity.
- **GAL Changes Not Visible**: Wait for sync cycle completion and check Azure AD/Entra admin portal.

## Security Considerations

- Run scripts with least privilege required
- Audit log files for compliance
- Use secure PowerShell execution policies
- Store scripts in secure locations

## Support

For issues or questions:
- Check PowerShell error messages
- Review log files in `C:\Temp\`
- Verify Entra Connect health
- Consult Microsoft documentation for sync rules and GAL management
