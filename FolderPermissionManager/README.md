# Folder Permission Manager

Tools for managing NTFS folder permissions, ownership, and ACLs. Includes a command-line script and a browser-based GUI.

## Scripts

### FolderPermissionManager-GUI.ps1 (Web GUI)

A browser-based interface for managing folder permissions across local drives and network shares. Runs a local web server and opens an interactive dashboard.

**Features:**
- Browse all local drives and network shares in a folder tree
- View ownership, inheritance status, and full ACL entries for any folder
- Take ownership (single folder or recursive)
- Add and remove permission entries (identity, rights, allow/deny)
- Replicate parent permissions to selected child folders
- Export permissions report as CSV
- Dark/light theme toggle

**Usage:**

```powershell
# Launch with defaults (opens browser automatically)
.\FolderPermissionManager-GUI.ps1

# Custom port, don't auto-open browser
.\FolderPermissionManager-GUI.ps1 -Port 9090 -NoBrowserOpen
```

Press Ctrl+C in the PowerShell window to stop the server.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Port` | `8271` | TCP port for the local web server (1024-65535) |
| `-NoBrowserOpen` | — | Don't automatically open the browser on launch |

### FolderPermissionManager.ps1 (CLI)

Command-line script that takes ownership of subfolders, reviews permissions, and optionally replicates parent ACLs to all children.

```powershell
.\FolderPermissionManager.ps1 -Path "C:\SharedFolder"
```

If no path is provided, the script will prompt for it.

## Requirements

- PowerShell 5.1+
- Run as Administrator (required for ownership and permission operations)
