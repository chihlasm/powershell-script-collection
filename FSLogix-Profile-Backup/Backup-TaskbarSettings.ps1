<#
.SYNOPSIS
    Backs up Windows Taskbar shortcuts and settings
.DESCRIPTION
    Exports registry keys containing taskbar settings and pinned items for backup and restoration.
    Supports both current user registry and mounted FSLogix profile NTUSER.DAT.
.PARAMETER OutputPath
    Path where to save the backup file (default: current directory\TaskbarSettingsBackup.reg)
.PARAMETER ProfilePath
    Path to mounted profile (used for file-based lookups)
.PARAMETER NTUserPath
    Path to NTUSER.DAT file for offline registry backup from mounted FSLogix profile
.EXAMPLE
    .\Backup-TaskbarSettings.ps1
    Backs up taskbar settings from current user's registry
.EXAMPLE
    .\Backup-TaskbarSettings.ps1 -NTUserPath "E:\Profile\NTUSER.DAT" -OutputPath "C:\Backup\Taskbar.reg"
    Backs up taskbar settings from a mounted FSLogix profile
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = ".\TaskbarSettingsBackup.reg",

    [Parameter(Mandatory = $false)]
    [string]$ProfilePath,

    [Parameter(Mandatory = $false)]
    [string]$NTUserPath
)

Write-Verbose "Starting taskbar settings backup..."

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

    # Determine if we're using mounted profile
    $useLoadedHive = $false
    if ($NTUserPath -and (Test-Path $NTUserPath)) {
        Write-Host "Loading NTUSER.DAT from mounted profile: $NTUserPath"

        # Load the NTUSER.DAT hive
        $loadResult = & reg.exe load "HKU\$tempHiveName" "$NTUserPath" 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to load registry hive: $loadResult"
        }
        $loadedHive = $true
        $useLoadedHive = $true
        Write-Verbose "Registry hive loaded as HKU\$tempHiveName"
        Write-Host "Exporting taskbar settings from mounted profile..."
    } else {
        if ($NTUserPath) {
            Write-Warning "NTUSER.DAT not found at: $NTUserPath"
            Write-Warning "Falling back to current user's registry"
        }
        Write-Host "Exporting taskbar settings from current user's registry..."
    }

    # Taskbar-related registry keys to export
    $regKeys = @(
        "Software\Microsoft\Windows\CurrentVersion\Explorer\TaskBand",
        "Software\Microsoft\Windows\CurrentVersion\Explorer\Taskbar",
        "Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    )

    $exportCount = 0
    Write-Verbose "Exporting $($regKeys.Count) registry keys..."

    foreach ($regKey in $regKeys) {
        # Build full registry path based on source
        if ($useLoadedHive) {
            $regPath = "HKU\$tempHiveName\$regKey"
        } else {
            $regPath = "HKCU\$regKey"
        }

        Write-Verbose "Checking registry key: $regPath"

        # Check if key exists
        $keyExists = & reg.exe query "$regPath" 2>&1
        if ($LASTEXITCODE -eq 0) {
            try {
                # Create temporary file in the same directory as output to avoid cross-volume issues
                $tempFile = Join-Path $backupDir ([System.IO.Path]::GetRandomFileName())

                # Use Start-Process instead of Invoke-Expression for security
                $process = Start-Process -FilePath "reg.exe" -ArgumentList "export", "`"$regPath`"", "`"$tempFile`"", "/y" -NoNewWindow -Wait -PassThru

                if ($process.ExitCode -eq 0 -and (Test-Path $tempFile)) {
                    # Read and process content
                    $tempContent = Get-Content $tempFile

                    # If using loaded hive, fix the paths
                    if ($useLoadedHive) {
                        $tempContent = $tempContent -replace "HKU\\$tempHiveName", "HKEY_CURRENT_USER"
                    }

                    if ($exportCount -eq 0) {
                        # First export - include version header
                        $tempContent | Out-File -FilePath $OutputPath -Encoding Unicode
                    } else {
                        # Subsequent exports - skip version header and append
                        $tempContent | Select-Object -Skip 1 | Out-File -FilePath $OutputPath -Encoding Unicode -Append
                    }

                    $exportCount++
                    Write-Verbose "Successfully exported: $regKey"
                    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                } else {
                    Write-Verbose "Failed to export registry key: $regKey (Exit code: $($process.ExitCode))"
                }
            }
            catch {
                Write-Verbose "Error exporting registry key $regKey : $($_.Exception.Message)"
            }
            finally {
                # Ensure temp file is cleaned up
                if ($tempFile -and (Test-Path $tempFile)) {
                    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                }
            }
        } else {
            Write-Verbose "Registry path not found: $regPath"
        }
    }

    if ($exportCount -gt 0 -and (Test-Path $OutputPath)) {
        $fileSize = (Get-Item $OutputPath).Length
        Write-Host "Taskbar settings backed up successfully to: $OutputPath"
        Write-Host "Registry keys exported: $exportCount"
        Write-Host "Backup size: $fileSize bytes"
        Write-Verbose "Taskbar settings backup completed successfully"
    } else {
        Write-Warning "No taskbar settings were backed up. No valid registry keys found or export failed."
        if (Test-Path $OutputPath) {
            Remove-Item $OutputPath -Force -ErrorAction SilentlyContinue
        }
    }
}
catch {
    Write-Error "Error backing up taskbar settings: $($_.Exception.Message)"
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
