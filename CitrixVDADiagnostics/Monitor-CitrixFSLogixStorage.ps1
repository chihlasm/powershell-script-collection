# Monitor-CitrixFSLogixStorage.ps1
# Monitors storage space on Citrix VDAs and FSLogix storage servers

param(
    [string[]]$TargetServers,
    [switch]$IncludeLocalVDA,
    [string]$CredentialFile,
    [switch]$ExportReport,
    [ValidateSet("HTML", "CSV", "TXT")]
    [string]$ReportFormat = "HTML",
    [string]$ReportPath = "",
    [int]$WarningThresholdPercent = 80,
    [int]$CriticalThresholdPercent = 90,
    [switch]$Verbose
)

# Function to get FSLogix profile locations from registry
function Get-FSlogixProfileLocations {
    param([string]$ComputerName = $env:COMPUTERNAME)

    try {
        $fslogixKey = "HKLM:\SOFTWARE\FSLogix\Profiles"

        if ($ComputerName -ne $env:COMPUTERNAME) {
            # Remote registry access would require additional permissions
            Write-Warning "Remote registry access not implemented. Using local FSLogix config for storage server inference."
        }

        # Local registry access
        if (Test-Path $fslogixKey) {
            $enabled = Get-ItemProperty $fslogixKey -Name "Enabled" -ErrorAction SilentlyContinue
            if ($enabled.Enabled -eq 1) {
                $vhdLocations = Get-ItemProperty $fslogixKey -Name "VHDLocations" -ErrorAction SilentlyContinue
                if ($vhdLocations.VHDLocations) {
                    $locations = ($vhdLocations.VHDLocations -split ';') | Where-Object { $_ }
                    return $locations | Where-Object { $_ -match '^\\\\' } # Only UNC paths
                }
            }
        }

        return @()
    }
    catch {
        Write-Warning "Could not retrieve FSlogix configuration: $_"
        return @()
    }
}

# Function to extract server names from UNC paths
function Get-StorageServersFromPaths {
    param([string[]]$Paths)

    $servers = @()
    foreach ($path in $Paths) {
        if ($path -match '^\\\\([^\\]+)\\') {
            $server = $matches[1]
            if ($servers -notcontains $server) {
                $servers += $server
            }
        }
    }
    return $servers
}

# Function to get storage information
function Get-StorageInfo {
    param([string]$ServerName)

    try {
        $volumes = @()

        if ($ServerName -eq $env:COMPUTERNAME) {
            # Local storage
            $localVolumes = Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -in @('Fixed', 'Network') }
            foreach ($vol in $localVolumes) {
                $driveLetter = $vol.DriveLetter
                $disk = Get-Partition -DriveLetter $driveLetter -ErrorAction SilentlyContinue

                $volumes += [PSCustomObject]@{
                    ServerName = $ServerName
                    Drive = "$driveLetter`:"
                    TotalGB = [math]::Round($vol.Size / 1GB, 2)
                    FreeGB = [math]::Round($vol.SizeRemaining / 1GB, 2)
                    UsedGB = [math]::Round($vol.Size - $vol.SizeRemaining, 2)
                    UsedPercent = [math]::Round(($vol.Size - $vol.SizeRemaining) / $vol.Size * 100, 2)
                    DriveType = $vol.DriveType
                    Label = $vol.FileSystemLabel
                }
            }
        } else {
            # Remote server storage check via Invoke-Command
            $credential = $null
            if ($CredentialFile -and (Test-Path $CredentialFile)) {
                try {
                    $credential = Import-Clixml -Path $CredentialFile
                } catch {
                    Write-Warning "Could not load credentials from $CredentialFile`: $_"
                }
            }

            $scriptBlock = {
                Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -in @('Fixed', 'Network') } | ForEach-Object {
                    $vol = $_
                    $driveLetter = $vol.DriveLetter

                    [PSCustomObject]@{
                        ServerName = $using:ServerName
                        Drive = "$driveLetter`:"
                        TotalGB = [math]::Round($vol.Size / 1GB, 2)
                        FreeGB = [math]::Round($vol.SizeRemaining / 1GB, 2)
                        UsedGB = [math]::Round($vol.Size - $vol.SizeRemaining, 2)
                        UsedPercent = [math]::Round((($vol.Size - $vol.SizeRemaining) / $vol.Size) * 100, 2)
                        DriveType = $vol.DriveType
                        Label = $vol.FileSystemLabel
                    }
                }
            }

            try {
                $volumes = Invoke-Command -ComputerName $ServerName -ScriptBlock $scriptBlock -Credential $credential
            } catch {
                Write-Warning "Could not query storage on remote server $ServerName`: $_"
                # Fallback: try to get drive info using drive letters that might be mapped
                $mappedDrives = Get-PSDrive | Where-Object { $_.Name -match '^[A-Z]$' -and $_.Provider -eq 'FileSystem' -and $_.Root -match "^\\\\$ServerName\\" }
                foreach ($drive in $mappedDrives) {
                    try {
                        $driveInfo = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$($drive.Name):'"
                        if ($driveInfo) {
                            $volumes += [PSCustomObject]@{
                                ServerName = $ServerName
                                Drive = "$($drive.Name):"
                                TotalGB = [math]::Round($driveInfo.Size / 1GB, 2)
                                FreeGB = [math]::Round($driveInfo.FreeSpace / 1GB, 2)
                                UsedGB = [math]::Round(($driveInfo.Size - $driveInfo.FreeSpace) / 1GB, 2)
                                UsedPercent = [math]::Round((($driveInfo.Size - $driveInfo.FreeSpace) / $driveInfo.Size) * 100, 2)
                                DriveType = "Mapped"
                                Label = "Mapped Drive"
                            }
                        }
                    } catch {
                        Write-Warning "Could not get info for mapped drive $($drive.Name): on $ServerName`: $_"
                    }
                }
            }
        }

        return $volumes
    }
    catch {
        Write-Warning "Could not get storage info for $ServerName`: $_"
        return @()
    }
}

# Function to analyze storage health
function Get-StorageHealth {
    param(
        [PSCustomObject]$StorageInfo,
        [int]$WarningThreshold = 80,
        [int]$CriticalThreshold = 90
    )

    $healthStatus = if ($StorageInfo.UsedPercent -ge $CriticalThreshold) {
        "CRITICAL"
    } elseif ($StorageInfo.UsedPercent -ge $WarningThreshold) {
        "WARNING"
    } else {
        "OK"
    }

    $color = switch ($healthStatus) {
        "CRITICAL" { "Red" }
        "WARNING" { "Yellow" }
        "OK" { "Green" }
        default { "White" }
    }

    return @{
        Status = $healthStatus
        Color = $color
        Issue = if ($healthStatus -ne "OK") {
            "Low disk space ($($StorageInfo.UsedPercent)%)"
        } else { $null }
    }
}

# Function to generate HTML report
function New-HTMLStorageReport {
    param(
        [array]$StorageData,
        [string]$FilePath
    )

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Citrix FSLogix Storage Monitor Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .section { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .status-ok { color: #28a745; font-weight: bold; }
        .status-warning { color: #ffc107; font-weight: bold; }
        .status-critical { color: #dc3545; font-weight: bold; }
        .storage-item { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #eee; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>💾 Citrix FSLogix Storage Monitor Report</h1>
        <p><strong>Report Generated:</strong> $(Get-Date)</p>
    </div>

    <div class="section">
        <h2>Storage Analysis Summary</h2>
        <p>Monitored Servers: $(($StorageData | Select-Object -ExpandProperty ServerName -Unique).Count)</p>
        <p>Total Drives Checked: $($StorageData.Count)</p>
        <p>Warning Threshold: ${WarningThresholdPercent}% | Critical Threshold: ${CriticalThresholdPercent}%</p>
    </div>

    <div class="section">
        <h2>📊 Storage Details</h2>
        <table>
            <tr>
                <th>Server</th>
                <th>Drive</th>
                <th>Total (GB)</th>
                <th>Used (GB)</th>
                <th>Free (GB)</th>
                <th>Usage %</th>
                <th>Status</th>
                <th>Type</th>
            </tr>
"@

    foreach ($storage in $StorageData) {
        $health = Get-StorageHealth -StorageInfo $storage -WarningThreshold $WarningThresholdPercent -CriticalThreshold $CriticalThresholdPercent
        $statusClass = "status-" + $health.Status.ToLower()

        $html += @"
            <tr>
                <td>$($storage.ServerName)</td>
                <td>$($storage.Drive)</td>
                <td>$($storage.TotalGB)</td>
                <td>$($storage.UsedGB)</td>
                <td>$($storage.FreeGB)</td>
                <td>$($storage.UsedPercent)%</td>
                <td class="$statusClass">$($health.Status)</td>
                <td>$($storage.DriveType)</td>
            </tr>
"@
    }

    $html += @"
        </table>
    </div>

    <div class="section">
        <h2>🔧 Recommendations</h2>
"@

    $criticalIssues = $StorageData | Where-Object { (Get-StorageHealth -StorageInfo $_ -WarningThreshold $WarningThresholdPercent -CriticalThreshold $CriticalThresholdPercent -ErrorAction SilentlyContinue).Status -eq "CRITICAL" }
    $warningIssues = $StorageData | Where-Object {
        $health = Get-StorageHealth -StorageInfo $_ -WarningThreshold $WarningThresholdPercent -CriticalThreshold $CriticalThresholdPercent -ErrorAction SilentlyContinue
        $health.Status -eq "WARNING"
    }

    if ($criticalIssues) {
        $html += "<h3>🚨 Critical Issues (Immediate Action Required)</h3>"
        foreach ($issue in $criticalIssues) {
            $html += "<p>• <strong>$($issue.ServerName) - $($issue.Drive)</strong>: Low disk space ($($issue.UsedPercent)%) - Free up space immediately</p>"
        }
    }

    if ($warningIssues) {
        $html += "<h3>⚠️ Warnings (Monitor Closely)</h3>"
        foreach ($issue in $warningIssues) {
            $html += "<p>• <strong>$($issue.ServerName) - $($issue.Drive)</strong>: Approaching capacity limit ($($issue.UsedPercent)%) - Plan capacity expansion</p>"
        }
    }

    if (-not $criticalIssues -and -not $warningIssues) {
        $html += "<p>✅ All monitored storage is within acceptable limits.</p>"
    }

    $html += @"
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $FilePath -Encoding UTF8
    Write-Host "HTML storage report saved to: $FilePath" -ForegroundColor Green
}

# Function to generate CSV report
function New-CSVStorageReport {
    param(
        [array]$StorageData,
        [string]$FilePath
    )

    $csvData = $StorageData | Select-Object ServerName, Drive, TotalGB, UsedGB, FreeGB, UsedPercent,
        DriveType, Label,
        @{Name="Status"; Expression={ (Get-StorageHealth -StorageInfo $_ -WarningThreshold $WarningThresholdPercent -CriticalThreshold $CriticalThresholdPercent).Status }},
        @{Name="Timestamp"; Expression={ Get-Date }}

    $csvData | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV storage report saved to: $FilePath" -ForegroundColor Green
}

# Main function
function Monitor-CitrixFSLogixStorage {
    Write-Host "=== Citrix FSLogix Storage Monitor ===" -ForegroundColor Cyan
    Write-Host "Warning Threshold: $WarningThresholdPercent%" -ForegroundColor Yellow
    Write-Host "Critical Threshold: $CriticalThresholdPercent%" -ForegroundColor Red
    Write-Host ""

    $allStorageData = @()

    # Determine servers to monitor
    $serversToMonitor = @()

    if ($IncludeLocalVDA) {
        $serversToMonitor += $env:COMPUTERNAME
    }

    if ($TargetServers) {
        $serversToMonitor += $TargetServers
    }

    # Get FSLogix configured storage servers
    $fslogixLocations = Get-FSlogixProfileLocations
    $fslogixServers = Get-StorageServersFromPaths -Paths $fslogixLocations

    Write-Host "FSLogix Profile Locations Found:" -ForegroundColor Yellow
    if ($fslogixLocations) {
        $fslogixLocations | ForEach-Object { Write-Host "  - $_" }
        $serversToMonitor += $fslogixServers
    } else {
        Write-Host "  (No FSLogix locations found)" -ForegroundColor Gray
    }

    if ($serversToMonitor.Count -eq 0) {
        Write-Host "No servers specified for monitoring. Use -IncludeLocalVDA or -TargetServers parameter." -ForegroundColor Yellow
        return
    }

    $serversToMonitor = $serversToMonitor | Select-Object -Unique

    Write-Host "`nMonitoring Storage on $(($serversToMonitor).Count) servers:" -ForegroundColor Cyan
    $serversToMonitor | ForEach-Object { Write-Host "  - $_" }
    Write-Host ""

    # Monitor each server's storage
    foreach ($server in $serversToMonitor) {
        Write-Host "Checking storage on: $server" -ForegroundColor Cyan

        $storageInfo = Get-StorageInfo -ServerName $server

        if ($storageInfo.Count -eq 0) {
            Write-Host "  No storage information retrieved for $server" -ForegroundColor Red
            continue
        }

        foreach ($drive in $storageInfo) {
            $health = Get-StorageHealth -StorageInfo $drive -WarningThreshold $WarningThresholdPercent -CriticalThreshold $CriticalThresholdPercent

            Write-Host "  Drive $($drive.Drive) ($($drive.DriveType)):" -ForegroundColor White
            Write-Host "    Total: $($drive.TotalGB) GB" -ForegroundColor Blue
            Write-Host "    Used:  $($drive.UsedGB) GB ($($drive.UsedPercent)%)" -ForegroundColor $health.Color
            Write-Host "    Free:  $($drive.FreeGB) GB" -ForegroundColor Green
            Write-Host "    Status: $($health.Status)" -ForegroundColor $health.Color

            if ($health.Issue) {
                Write-Host "    ⚠️  $($health.Issue)" -ForegroundColor $health.Color
            }
            Write-Host ""

            $allStorageData += $drive
        }
    }

    # Generate report if requested
    if ($ExportReport) {
        if (-not $ReportPath) {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $ReportPath = "CitrixFSLogixStorage_Report_${timestamp}.$($ReportFormat.ToLower())"
        }

        # Ensure the directory exists
        $directory = Split-Path -Path $ReportPath -Parent
        if ($directory -and -not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }

        switch ($ReportFormat) {
            "HTML" { New-HTMLStorageReport -StorageData $allStorageData -FilePath $ReportPath }
            "CSV" { New-CSVStorageReport -StorageData $allStorageData -FilePath $ReportPath }
            "TXT" {
                $textReport = $allStorageData | Format-Table -AutoSize | Out-String
                $textReport | Out-File -FilePath $ReportPath -Encoding UTF8
                Write-Host "Text storage report saved to: $ReportPath" -ForegroundColor Green
            }
        }
    }

    Write-Host "=== Storage Monitoring Complete ===" -ForegroundColor Cyan
    Write-Host "Summary: $($allStorageData.Count) drives checked across $($serversToMonitor.Count) servers" -ForegroundColor White
}

# Execute the storage monitoring
Monitor-CitrixFSLogixStorage
