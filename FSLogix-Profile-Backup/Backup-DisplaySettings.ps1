<#
.SYNOPSIS
    Backs up Windows display and scaling settings
.DESCRIPTION
    Exports registry keys containing display settings for backup and restoration
.PARAMETER OutputPath
    Path where to save the backup file (default: current directory\DisplaySettingsBackup.reg)
.PARAMETER ProfilePath
    Path to mounted profile (not applicable for registry-based backups)
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = ".\DisplaySettingsBackup.reg",

    [Parameter(Mandatory = $false)]
    [string]$ProfilePath
)

Write-Verbose "Starting display settings backup..."

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

    # Display-related registry keys to export
    $regPaths = @(
        "HKCU\Software\Microsoft\Windows\CurrentVersion\Display",
        "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Dpi",
        "HKCU\Software\Microsoft\Windows\DWM",
        "HKCU\Control Panel\Desktop",
        "HKCU\Control Panel\Desktop\WindowMetrics"
    )

    $exportCount = 0
    $totalSize = 0
    Write-Verbose "Exporting $($regPaths.Count) registry keys..."

    foreach ($regPath in $regPaths) {
        Write-Verbose "Checking registry key: $regPath"

        if (Test-Path $regPath) {
            try {
                # Create temporary file in the same directory as output to avoid cross-volume issues
                $tempFile = Join-Path $backupDir ([System.IO.Path]::GetRandomFileName())

                # Use Start-Process instead of Invoke-Expression for security
                $process = Start-Process -FilePath "reg.exe" -ArgumentList "export", "`"$regPath`"", "`"$tempFile`"", "/y" -NoNewWindow -Wait -PassThru

                if ($process.ExitCode -eq 0 -and (Test-Path $tempFile)) {
                    # Append to output file, skipping the first line (Windows Registry Editor Version) if not the first export
                    $tempContent = Get-Content $tempFile
                    if ($exportCount -eq 0) {
                        # First export - include version header
                        $tempContent | Out-File -FilePath $OutputPath -Encoding Unicode -Append
                    } else {
                        # Subsequent exports - skip version header and append
                        $tempContent | Select-Object -Skip 1 | Out-File -FilePath $OutputPath -Encoding Unicode -Append
                    }

                    $exportCount++
                    Write-Verbose "Successfully exported: $regPath"
                    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                } else {
                    Write-Verbose "Failed to export registry key: $regPath (Exit code: $($process.ExitCode))"
                }
            }
            catch {
                Write-Verbose "Error exporting registry key $regPath : $($_.Exception.Message)"
            }
            finally {
                # Ensure temp file is cleaned up
                if (Test-Path $tempFile) {
                    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                }
            }
        } else {
            Write-Verbose "Registry path not found: $regPath"
        }
    }

    if ($exportCount -gt 0 -and (Test-Path $OutputPath)) {
        $fileSize = (Get-Item $OutputPath).Length
        Write-Host "Display settings backed up successfully to: $OutputPath"
        Write-Host "Registry keys exported: $exportCount"
        Write-Host "Backup size: $fileSize bytes"
        Write-Verbose "Display settings backup completed successfully"
    } else {
        Write-Warning "No display settings were backed up. No valid registry keys found or export failed."
        if (Test-Path $OutputPath) {
            Remove-Item $OutputPath -Force -ErrorAction SilentlyContinue
        }
    }
}
catch {
    Write-Error "Error backing up display settings: $($_.Exception.Message)"
}
