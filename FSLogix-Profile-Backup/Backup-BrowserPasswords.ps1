<#
.SYNOPSIS
    Backs up browser auto-fill passwords (Chrome and Edge)
.DESCRIPTION
    Attempts to export browser passwords for backup and restoration
    Note: Browser passwords are encrypted and may require manual export through browser interface
.PARAMETER OutputPath
    Path where to save the backup files (default: current directory)
.PARAMETER ChromePath
    Path to Chrome executable (default: auto-detected)
.PARAMETER EdgePath
    Path to Edge executable (default: auto-detected)
#>

param (
    [string]$OutputPath = ".\BrowserPasswords",
    [string]$ChromePath,
    [string]$EdgePath
)

Write-Host "Attempting to backup browser passwords..."
Write-Warning "Note: Browser password backups require manual intervention and may not work in all environments"
Write-Host "For security reasons, passwords are encrypted and cannot be automatically exported by scripts"
Write-Host "Please use these paths to locate your browsers and export passwords manually:"

# Create backup directory if it doesn't exist
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

try {
    # Auto-detect browser paths if not provided
    if (-not $ChromePath) {
        $chromeCommon = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
        $chromePf = "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
        if (Test-Path $chromeCommon) { $ChromePath = $chromeCommon }
        elseif (Test-Path $chromePf) { $ChromePath = $chromePf }
    }

    if (-not $EdgePath) {
        $edgeCommon = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
        $edgePf = "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe"
        if (Test-Path $edgeCommon) { $EdgePath = $edgeCommon }
        elseif (Test-Path $edgePf) { $EdgePath = $edgePf }
    }

    # Instructions for Chrome
    if ($ChromePath) {
        Write-Host "`nChrome found at: $ChromePath"
        Write-Host "To export Chrome passwords:"
        Write-Host "  1. Open Chrome"
        Write-Host "  2. Go to chrome://settings/passwords"
        Write-Host "  3. Click the three dots menu -> Export passwords"
        Write-Host "  4. Save the file to: $OutputPath\ChromePasswords.csv"
        Write-Host "  5. Enter your Windows credentials when prompted"

        # Try to open Chrome settings (this may not work in all environments)
        try {
            Start-Process $ChromePath "chrome://settings/passwords" -ErrorAction SilentlyContinue
        } catch {
            Write-Host "Could not automatically open Chrome settings. Please do so manually."
        }
    } else {
        Write-Warning "Chrome not found. Skipping Chrome password backup."
    }

    # Instructions for Edge
    if ($EdgePath) {
        Write-Host "`nEdge found at: $EdgePath"
        Write-Host "To export Edge passwords:"
        Write-Host "  1. Open Edge"
        Write-Host "  2. Go to edge://settings/passwords"
        Write-Host "  3. Click the three dots menu -> Export passwords"
        Write-Host "  4. Save the file to: $OutputPath\EdgePasswords.csv"
        Write-Host "  5. Enter your Windows credentials when prompted"

        # Try to open Edge settings (this may not work in all environments)
        try {
            Start-Process $EdgePath "edge://settings/passwords" -ErrorAction SilentlyContinue
        } catch {
            Write-Host "Could not automatically open Edge settings. Please do so manually."
        }
    } else {
        Write-Warning "Edge not found. Skipping Edge password backup."
    }

    # Create a placeholder file to indicate password backup path
    $instructionFile = Join-Path $OutputPath "PasswordBackupInstructions.txt"
    $instructions = @"
Browser Password Export Instructions
===================================

IMPORTANT SECURITY NOTES:
- Password exports contain sensitive information
- Store backup files securely and delete when no longer needed
- Passwords may not import correctly across different machines/environments
- Consider security implications before backing up passwords

CHROME PASSWORD EXPORT:
1. Open Chrome and navigate to chrome://settings/passwords
2. Click the three dots menu (⋮)
3. Select "Export passwords"
4. Choose a secure location and filename: ChromePasswords.csv
5. Enter your Windows credentials to confirm

MICROSOFT EDGE PASSWORD EXPORT:
1. Open Edge and navigate to edge://settings/passwords
2. Click the three dots menu (⋮)
3. Select "Export passwords"
4. Choose a secure location and filename: EdgePasswords.csv
5. Enter your Windows credentials to confirm

AFTER EXPORT:
- Move the exported CSV files to this directory: $OutputPath
- The files will be included in your profile backup
"@

    $instructions | Out-File -FilePath $instructionFile -Encoding UTF8

    Write-Host "`nInstructions saved to: $instructionFile"
    Write-Host "Please follow the manual steps above to export browser passwords."

}
catch {
    Write-Error "Error setting up browser password backup: $($_.Exception.Message)"
}
