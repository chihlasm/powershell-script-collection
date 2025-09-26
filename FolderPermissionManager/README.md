# Folder Permission Manager

This PowerShell script helps manage permissions on folders and their sub-folders. It provides functionality to take ownership of sub-folders, review current permissions, and replicate permissions from the top-level folder to all sub-folders.

## Features

- **Take Ownership**: Recursively takes ownership of all sub-folders within the specified top-level folder.
- **Review Permissions**: Displays the current permissions (owner and access rules) on the top-level folder and lists the owners of sub-folders.
- **Replicate Permissions**: Optionally replicates the permissions from the top-level folder to all sub-folders.

## Requirements

- Windows PowerShell (version 5.1 or later recommended).
- Administrative privileges (run as Administrator) to modify ownership and permissions.
- The script must be run from an elevated PowerShell session.

## Usage

1. Open PowerShell as Administrator.
2. Navigate to the script directory.
3. Run the script with the path to the top-level folder:

   ```powershell
   .\FolderPermissionManager.ps1 -Path "C:\Path\To\TopLevelFolder"
   ```

   Or, if no path is provided, the script will prompt for it.

4. The script will:
   - Take ownership of sub-folders.
   - Display permissions on the top-level folder.
   - List sub-folders and their owners.
   - Ask for confirmation to replicate permissions.

5. If you confirm, it will set the top-level folder's permissions on all sub-folders.

## Notes

- Taking ownership and setting permissions may fail if you do not have sufficient privileges.
- The script uses `icacls` for taking ownership and PowerShell's `Get-Acl`/`Set-Acl` for permissions.
- Replicating permissions adds the top-level folder's access rules to sub-folders without removing existing permissions (ownership is taken at the beginning).
- Test on a small folder first to understand the behavior.

## Example

```powershell
.\FolderPermissionManager.ps1 -Path "C:\SharedFolder"
```

This will process `C:\SharedFolder` and its sub-folders.
