# Local Admin Manager

A PowerShell script to easily add or remove domain users and groups from the local Administrators group on Windows computers.

## Features

- Add domain users or groups to local Administrators
- Remove domain users or groups from local Administrators
- Supports local and remote computer management
- Validates administrator privileges
- Provides clear success/failure feedback

## Requirements

- Windows PowerShell 5.1 or later
- Administrator privileges on the target computer(s)
- Domain-joined computer (for domain users/groups)
- For remote management: Administrative access to remote computers

## Usage

### Basic Syntax

```powershell
.\LocalAdminManager.ps1 -Action <Add|Remove> -Member "DOMAIN\Username" [-ComputerName "ComputerName"]
```

### Parameters

- **Action**: Required. Specify "Add" to add a member or "Remove" to remove a member.
- **Member**: Required. The domain user or group in the format "DOMAIN\Username" or "DOMAIN\GroupName".
- **ComputerName**: Optional. The name of the computer to manage. Defaults to the local computer.

### Examples

#### Add a Domain User to Local Admins (Local Computer)

```powershell
.\LocalAdminManager.ps1 -Action Add -Member "CONTOSO\JohnDoe"
```

This adds the user JohnDoe from the CONTOSO domain to the local Administrators group on the current computer.

#### Remove a Domain Group from Local Admins (Remote Computer)

```powershell
.\LocalAdminManager.ps1 -Action Remove -Member "CONTOSO\DomainAdmins" -ComputerName "RemotePC01"
```

This removes the DomainAdmins group from the CONTOSO domain from the local Administrators group on the computer named RemotePC01.

#### Add a Domain Group to Local Admins

```powershell
.\LocalAdminManager.ps1 -Action Add -Member "CONTOSO\ITSupport"
```

This adds the ITSupport group from the CONTOSO domain to the local Administrators group on the current computer.

#### Batch Operations

You can use this script in batch files or other scripts for multiple operations:

```batch
REM Add multiple users
powershell.exe -ExecutionPolicy Bypass -File "LocalAdminManager.ps1" -Action Add -Member "CONTOSO\User1"
powershell.exe -ExecutionPolicy Bypass -File "LocalAdminManager.ps1" -Action Add -Member "CONTOSO\User2"

REM Remove a group
powershell.exe -ExecutionPolicy Bypass -File "LocalAdminManager.ps1" -Action Remove -Member "CONTOSO\TempAdmins"
```

## Notes

- The script must be run with administrator privileges. It will check for this and exit if not running as admin.
- For domain users/groups, ensure they exist in Active Directory. The script will attempt the operation and report any errors.
- When managing remote computers, ensure you have administrative access and that remote management is enabled.
- The script uses the built-in `Add-LocalGroupMember` and `Remove-LocalGroupMember` cmdlets, which are available in Windows 10/Windows Server 2016 and later.

## Troubleshooting

- **Access Denied**: Ensure you're running the script as an administrator.
- **Member not found**: Verify the domain user/group exists and is spelled correctly.
- **RPC Server Unavailable**: For remote computers, check network connectivity and administrative access.
- **The specified account name is not valid**: Ensure the member format is correct (DOMAIN\Username).

## Security Considerations

- Only grant local administrator access when necessary and for the minimum required time.
- Regularly review and remove unnecessary admin access.
- Consider using Group Policy or other centralized management for large-scale deployments.
