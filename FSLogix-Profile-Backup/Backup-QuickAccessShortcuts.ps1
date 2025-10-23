<#
.SYNOPSIS
    Backs up Windows Explorer Quick Access shortcuts
.DESCRIPTION
    Exports the registry keys containing Quick Access shortcuts for backup
.PARAMETER OutputPath
    Path where to save the backup file (default: current directory\QuickAccessBackup.reg)
.PARAMETER ProfilePath
    Path to mounted profile (not applicable for registry-based backups)
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = ".\QuickAccessBackup.reg",

    [Parameter(Mandatory = $false)]
    [string]$ProfilePath
)

Write-Verbose "Starting Quick Access shortcuts backup..."

if ($ProfilePath) {
    Write-Warning "ProfilePath parameter not applicable for registry-based backups. Exporting current user's registry."
}

try {
    # Resolve output path
    $OutputPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($OutputPath)

    # Create backup directory if it doesn't exist
    $backupDir = Split-Path -Path $OutputPath -Parent
    if (-not (Test-Path $backupDir)) {
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        Write-Verbose "Created backup directory: $backupDir"
    }

    # Export Quick Access registry key using secure method
    $regPath = "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Quick Access"
    Write-Verbose "Exporting registry key: $regPath"

    # Use reg.exe directly without Invoke-Expression
    $process = Start-Process -FilePath "reg.exe" -ArgumentList "export", "`"$regPath`"", "`"$OutputPath`"", "/y" -NoNewWindow -Wait -PassThru

    if ($process.ExitCode -eq 0 -and (Test-Path $OutputPath)) {
        $fileSize = (Get-Item $OutputPath).Length
        Write-Host "Quick Access shortcuts backed up successfully to: $OutputPath"
        Write-Host "Backup size: $fileSize bytes"
        Write-Verbose "Registry export completed successfully"
    } else {
        Write-Warning "Registry export failed with exit code: $($process.ExitCode)"
        if (-not (Test-Path $OutputPath)) {
            Write-Warning "Backup file was not created"
        }
    }
}
catch {
    Write-Error "Error backing up Quick Access shortcuts: $($_.Exception.Message)"
}
