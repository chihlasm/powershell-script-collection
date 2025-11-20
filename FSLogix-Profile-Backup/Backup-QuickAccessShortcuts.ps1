<#
.SYNOPSIS
    Backs up Windows Explorer Quick Access shortcuts
.DESCRIPTION
    Exports the registry keys containing Quick Access shortcuts for backup.
    Supports both current user registry and mounted FSLogix profile NTUSER.DAT.
.PARAMETER OutputPath
    Path where to save the backup file (default: current directory\QuickAccessBackup.reg)
.PARAMETER ProfilePath
    Path to mounted profile (used for file-based lookups)
.PARAMETER NTUserPath
    Path to NTUSER.DAT file for offline registry backup from mounted FSLogix profile
.EXAMPLE
    .\Backup-QuickAccessShortcuts.ps1
    Backs up Quick Access shortcuts from current user's registry
.EXAMPLE
    .\Backup-QuickAccessShortcuts.ps1 -NTUserPath "E:\Profile\NTUSER.DAT" -OutputPath "C:\Backup\QuickAccess.reg"
    Backs up Quick Access shortcuts from a mounted FSLogix profile
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = ".\QuickAccessBackup.reg",

    [Parameter(Mandatory = $false)]
    [string]$ProfilePath,

    [Parameter(Mandatory = $false)]
    [string]$NTUserPath
)

Write-Verbose "Starting Quick Access shortcuts backup..."

# Track if we loaded a hive
$loadedHive = $false
$tempHiveName = "FSLogix_Backup_$([guid]::NewGuid().ToString('N').Substring(0,8))"

try {
    # Resolve output path
    $OutputPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($OutputPath)

    # Create backup directory if it doesn't exist
    $backupDir = Split-Path -Path $OutputPath -Parent
    if (-not (Test-Path $backupDir)) {
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        Write-Verbose "Created backup directory: $backupDir"
    }

    # Determine registry path based on whether we're using mounted profile
    if ($NTUserPath -and (Test-Path $NTUserPath)) {
        Write-Host "Loading NTUSER.DAT from mounted profile: $NTUserPath"

        # Load the NTUSER.DAT hive
        $loadResult = & reg.exe load "HKU\$tempHiveName" "$NTUserPath" 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to load registry hive: $loadResult"
        }
        $loadedHive = $true
        Write-Verbose "Registry hive loaded as HKU\$tempHiveName"

        # Export from the loaded hive
        $regPath = "HKU\$tempHiveName\Software\Microsoft\Windows\CurrentVersion\Explorer\Quick Access"
        Write-Host "Exporting Quick Access from mounted profile..."
    } else {
        if ($NTUserPath) {
            Write-Warning "NTUSER.DAT not found at: $NTUserPath"
            Write-Warning "Falling back to current user's registry"
        }

        # Export from current user
        $regPath = "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Quick Access"
        Write-Host "Exporting Quick Access from current user's registry..."
    }

    Write-Verbose "Exporting registry key: $regPath"

    # Use reg.exe directly without Invoke-Expression
    $process = Start-Process -FilePath "reg.exe" -ArgumentList "export", "`"$regPath`"", "`"$OutputPath`"", "/y" -NoNewWindow -Wait -PassThru

    if ($process.ExitCode -eq 0 -and (Test-Path $OutputPath)) {
        # If we exported from a loaded hive, we need to fix the paths in the .reg file
        if ($loadedHive) {
            Write-Verbose "Updating registry paths in export file..."
            $content = Get-Content $OutputPath -Raw
            $content = $content -replace "HKU\\$tempHiveName", "HKEY_CURRENT_USER"
            $content | Set-Content $OutputPath -Encoding Unicode
        }

        $fileSize = (Get-Item $OutputPath).Length
        Write-Host "Quick Access shortcuts backed up successfully to: $OutputPath"
        Write-Host "Backup size: $fileSize bytes"
        Write-Verbose "Registry export completed successfully"
    } else {
        # Check if the key exists
        $keyExists = & reg.exe query "$regPath" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Quick Access registry key not found or empty"
            Write-Warning "This may be normal if Quick Access has no custom shortcuts"
        } else {
            Write-Warning "Registry export failed with exit code: $($process.ExitCode)"
        }

        if (-not (Test-Path $OutputPath)) {
            Write-Warning "Backup file was not created"
        }
    }
}
catch {
    Write-Error "Error backing up Quick Access shortcuts: $($_.Exception.Message)"
}
finally {
    # Unload the registry hive if we loaded it
    if ($loadedHive) {
        Write-Verbose "Unloading registry hive..."

        # Force garbage collection to release any handles
        [gc]::Collect()
        Start-Sleep -Milliseconds 500

        $unloadResult = & reg.exe unload "HKU\$tempHiveName" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Failed to unload registry hive: $unloadResult"
            Write-Warning "You may need to manually unload HKU\$tempHiveName"
        } else {
            Write-Verbose "Registry hive unloaded successfully"
        }
    }
}
