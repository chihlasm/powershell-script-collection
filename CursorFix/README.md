# CursorFix.ps1

**Description**: A PowerShell script that fixes cursor visibility issues in Windows applications by enabling Overlay Test Mode for the Desktop Window Manager (DWM). This addresses problems where the mouse pointer appears behind overlaid windows in certain applications or virtualized environments like Citrix or RDS.

**Parameters**:
- None (no parameters required)

**Usage Examples**:
- Run as administrator: `.\CursorFix.ps1`
- Scheduled task: Create a task with elevated permissions to run the script on login

**Requirements**:
- Windows 7 / Server 2008 R2 or higher
- Administrative privileges (required for registry modification)
- PowerShell execution policy allowing script execution

**Notes**:
- Requires administrator privileges to modify HKLM registry
- This is a common fix for cursor issues in Citrix, RDS, or other virtualized environments
- Changes take effect after logging off/on (or restarting the system)
- The script sets OverlayTestMode to 5 in HKLM:\SOFTWARE\Microsoft\Windows\Dwm
- No danger of data loss - affects only cursor rendering behavior
- Can be safely run multiple times
- Script will display success message if registry modification succeeds
- Always test in non-production environment first
