# CopyFileToServer.ps1

**Description**: A PowerShell script that copies a single file to multiple destination servers. It creates the destination directory if it doesn't exist and handles errors gracefully for each server.

**Parameters**:

- `-SourceFile <string>` (Required): Path to the source file to copy (e.g., "C:\Scripts\script.ps1").
- `-DestServers <string[]>` (Required): Array of destination server names (e.g., @("Server01", "Server02")).
- `-DestPath <string>` (Required): Destination path on each server (e.g., "share\folder" or "C$\Scripts").

**Usage Examples**:

- Copy to multiple servers: `.\CopyFileToServer.ps1 -SourceFile "C:\Temp\file.txt" -DestServers @("Server01", "Server02") -DestPath "Shared\Files"`
- Copy to UNC path: `.\CopyFileToServer.ps1 -SourceFile ".\script.ps1" -DestServers @("RemotePC") -DestPath "C$\Temp"`

**Requirements**:

- Network access to destination servers
- Permissions to write to destination paths on remote servers
- Source file must exist locally
- PowerShell 3.0 or higher

**Notes**:

- Creates destination folders automatically if they don't exist
- Handles UNC paths for remote server destinations
- Continues to next server if one fails
- Requires appropriate network and file system permissions
- All paths should use backslashes for UNC format
