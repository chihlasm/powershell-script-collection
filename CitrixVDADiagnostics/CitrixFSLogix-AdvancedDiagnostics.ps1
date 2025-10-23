# CitrixFSLogix-AdvancedDiagnostics.ps1
# Advanced diagnostics for Citrix FSLogix troubleshooting and health checks

param(
    [string]$ServerName = $env:COMPUTERNAME,
    [switch]$FullScan,
    [switch]$ExportReport,
    [ValidateSet("HTML", "CSV", "TXT")]
    [string]$ReportFormat = "HTML",
    [string]$ReportPath = "",
    [switch]$Verbose
)

# Function to check FSLogix service status
function Get-FSLogixServiceStatus {
    $fslogixServices = @(
        @{ Name = "frxsvc"; DisplayName = "FSLogix Virtualization Service" },
        @{ Name = "frxccds"; DisplayName = "FSLogix Cloud Caching Service" }
    )

    $results = @()
    foreach ($service in $fslogixServices) {
        try {
            $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
            if ($svc) {
                $startupType = Get-Service -Name $service.Name | Select-Object -ExpandProperty StartType -ErrorAction SilentlyContinue

                $results += [PSCustomObject]@{
                    ServiceName = $service.DisplayName
                    Status = $svc.Status
                    StartType = $startupType
                    IsRunning = ($svc.Status -eq 'Running')
                    Exists = $true
                }
            } else {
                $results += [PSCustomObject]@{
                    ServiceName = $service.DisplayName
                    Status = "Not Found"
                    StartType = "N/A"
                    IsRunning = $false
                    Exists = $false
                }
            }
        } catch {
            $results += [PSCustomObject]@{
                ServiceName = $service.DisplayName
                Status = "Error: $_"
                StartType = "N/A"
                IsRunning = $false
                Exists = $false
            }
        }
    }

    return $results
}

# Function to check FSLogix VHDX files
function Get-FSLogixProfileHealth {
    try {
        # Get FSLogix profile locations
        $fslogixKey = "HKLM:\SOFTWARE\FSLogix\Profiles"
        $profileLocations = @()

        if (Test-Path $fslogixKey) {
            $enabled = Get-ItemProperty $fslogixKey -Name "Enabled" -ErrorAction SilentlyContinue
            if ($enabled.Enabled -eq 1) {
                $vhdLocations = Get-ItemProperty $fslogixKey -Name "VHDLocations" -ErrorAction SilentlyContinue
                if ($vhdLocations.VHDLocations) {
                    $profileLocations = ($vhdLocations.VHDLocations -split ';') | Where-Object { $_ }
                }
            }
        }

        if ($profileLocations.Count -eq 0) {
            return @([PSCustomObject]@{
                Location = "N/A"
                VHDCount = 0
                TotalSizeGB = 0
                Status = "No FSLogix locations configured"
                HealthyVHDs = 0
                CorruptVHDs = 0
            })
        }

        $allResults = @()

        foreach ($location in $profileLocations) {
            try {
                $vhdxFiles = Get-ChildItem -Path $location -Filter "*.vhdx" -Recurse -ErrorAction SilentlyContinue
                $vhdFiles = Get-ChildItem -Path $location -Filter "*.vhd" -Recurse -ErrorAction SilentlyContinue
                $allVHDs = $vhdxFiles + $vhdFiles

                $totalSize = 0
                $healthyVHDs = 0
                $corruptVHDs = 0

                foreach ($vhd in $allVHDs) {
                    $totalSize += $vhd.Length

                    # Basic health check - can we read file properties and size is reasonable
                    $isHealthy = $false
                    try {
                        if ($vhd.Length -gt 0) {
                            # Try to access the file stream to ensure it's accessible
                            $stream = [System.IO.File]::Open($vhd.FullName, 'Open', 'Read', 'Read')
                            $stream.Close()
                            $isHealthy = $true
                        }
                    } catch {
                        $isHealthy = $false
                    }

                    if ($isHealthy) {
                        $healthyVHDs++
                    } else {
                        $corruptVHDs++
                    }
                }

                $totalSizeGB = [math]::Round($totalSize / 1GB, 2)

                $status = if ($corruptVHDs -gt 0) {
                    "Found $corruptVHDs potentially corrupt VHD files"
                } elseif ($allVHDs.Count -eq 0) {
                    "No VHD files found"
                } else {
                    "Healthy"
                }

                $allResults += [PSCustomObject]@{
                    Location = $location
                    VHDCount = $allVHDs.Count
                    TotalSizeGB = $totalSizeGB
                    Status = $status
                    HealthyVHDs = $healthyVHDs
                    CorruptVHDs = $corruptVHDs
                }

                if ($Verbose) {
                    Write-Host "Scanned $($allVHDs.Count) VHD files in $location" -ForegroundColor Blue
                    Write-Host "  Total size: $totalSizeGB GB" -ForegroundColor Blue
                    Write-Host "  Healthy: $healthyVHDs, Potentially corrupt: $corruptVHDs" -ForegroundColor Blue
                }
            } catch {
                $allResults += [PSCustomObject]@{
                    Location = $location
                    VHDCount = 0
                    TotalSizeGB = 0
                    Status = "Error scanning location: $_"
                    HealthyVHDs = 0
                    CorruptVHDs = 0
                }
            }
        }

        return $allResults
    } catch {
        return @([PSCustomObject]@{
            Location = "Error"
            VHDCount = 0
            TotalSizeGB = 0
            Status = "Error getting profile health: $_"
            HealthyVHDs = 0
            CorruptVHDs = 0
        })
    }
}

# Function to analyze event logs for FSLogix and Citrix issues
function Get-EventLogAnalysis {
    param([int]$LastHours = 24)

    $eventResults = @()

    try {
        # Define event log sources to check
        $logSources = @(
            @{ LogName = "Application"; Source = "FSLogix-Apps"; DisplayName = "FSLogix Apps" },
            @{ LogName = "Application"; Source = "Citrix"; DisplayName = "Citrix" },
            @{ LogName = "System"; EventId = 7036; DisplayName = "Service Events" } # Service stop/start events
        )

        $startTime = (Get-Date).AddHours(-$LastHours)

        foreach ($logSource in $logSources) {
            try {
                $events = @()

                if ($logSource.Source) {
                    # Filter by source
                    $events = Get-EventLog -LogName $logSource.LogName -Source $logSource.Source -After $startTime -ErrorAction SilentlyContinue
                } elseif ($logSource.EventId) {
                    # Filter by event ID (commonly service events)
                    $events = Get-EventLog -LogName $logSource.LogName -After $startTime -ErrorAction SilentlyContinue |
                             Where-Object { $_.EventID -eq $logSource.EventId }
                }

                # Categorize events
                $errorEvents = $events | Where-Object { $_.EntryType -eq "Error" }
                $warningEvents = $events | Where-Object { $_.EntryType -eq "Warning" }
                $infoEvents = $events | Where-Object { $_.EntryType -eq "Information" }

                $eventResults += [PSCustomObject]@{
                    Source = $logSource.DisplayName
                    TotalEvents = $events.Count
                    Errors = $errorEvents.Count
                    Warnings = $warningEvents.Count
                    Info = $infoEvents.Count
                    LastEvent = if ($events) { ($events | Sort-Object TimeGenerated -Descending | Select-Object -First 1).TimeGenerated } else { $null }
                    Status = if ($errorEvents.Count -gt 0) { "Has Errors" } elseif ($warningEvents.Count -gt 0) { "Has Warnings" } else { "OK" }
                }
            } catch {
                $eventResults += [PSCustomObject]@{
                    Source = $logSource.DisplayName
                    TotalEvents = 0
                    Errors = 0
                    Warnings = 0
                    Info = 0
                    LastEvent = $null
                    Status = "Error reading logs: $_"
                }
            }
        }

        return $eventResults
    } catch {
        return @([PSCustomObject]@{
            Source = "Error"
            TotalEvents = 0
            Errors = 0
            Warnings = 0
            Info = 0
            LastEvent = $null
            Status = "Error analyzing event logs: $_"
        })
    }
}

# Function to test network connectivity to profile shares
function Test-NetworkConnectivity {
    $connectivityResults = @()

    try {
        # Get FSLogix locations
        $fslogixKey = "HKLM:\SOFTWARE\FSLogix\Profiles"
        $profileLocations = @()

        if (Test-Path $fslogixKey) {
            $enabled = Get-ItemProperty $fslogixKey -Name "Enabled" -ErrorAction SilentlyContinue
            if ($enabled.Enabled -eq 1) {
                $vhdLocations = Get-ItemProperty $fslogixKey -Name "VHDLocations" -ErrorAction SilentlyContinue
                if ($vhdLocations.VHDLocations) {
                    $profileLocations = ($vhdLocations.VHDLocations -split ';') | Where-Object { $_ }
                }
            }
        }

        foreach ($location in $profileLocations) {
            if ($location -match '^\\\\([^\\]+)\\([^\\]+)') {
                $server = $matches[1]
                $share = $matches[2]

                # Test connectivity
                $pingResult = Test-Connection -ComputerName $server -Count 1 -Quiet

                # Test share access
                $shareAccessible = $false
                $sharePath = "\\$server\$share"

                try {
                    $testDir = Get-ChildItem -Path $sharePath -ErrorAction Stop | Select-Object -First 1
                    $shareAccessible = $true
                } catch {
                    $shareAccessible = $false
                }

                # Get network adapter info
                $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1

                $connectivityResults += [PSCustomObject]@{
                    Server = $server
                    Share = $share
                    PingSuccess = $pingResult
                    ShareAccessible = $shareAccessible
                    NetworkAdapter = if ($networkAdapters) { $networkAdapters.Name } else { "N/A" }
                    LinkSpeed = if ($networkAdapters) { $networkAdapters.LinkSpeed } else { "N/A" }
                    Status = if ($pingResult -and $shareAccessible) { "OK" } elseif ($pingResult) { "Ping OK, Share Inaccessible" } else { "Network Issue" }
                }
            }
        }

        return $connectivityResults
    } catch {
        return @([PSCustomObject]@{
            Server = "Error"
            Share = "Error"
            PingSuccess = $false
            ShareAccessible = $false
            NetworkAdapter = "N/A"
            LinkSpeed = "N/A"
            Status = "Error testing connectivity: $_"
        })
    }
}

# Function to check FSLogix performance counters
function Get-FSLogixPerformanceCounters {
    try {
        $counters = @()

        # Try to get FSLogix specific counters if installed
        $counterPaths = @(
            "\FSLogix Apps\*",
            "\FSLogix\*"
        )

        foreach ($counterPath in $counterPaths) {
            try {
                $availableCounters = Get-Counter -ListSet $counterPath -ErrorAction SilentlyContinue
                if ($availableCounters) {
                    foreach ($counterSet in $availableCounters) {
                        $counters += [PSCustomObject]@{
                            CounterSet = $counterSet.CounterSetName
                            Description = $counterSet.Description
                            Status = "Available"
                        }
                    }
                }
            } catch {
                # Continue
            }
        }

        if ($counters.Count -eq 0) {
            $counters += [PSCustomObject]@{
                CounterSet = "FSLogix Counters"
                Description = "No FSLogix performance counters found"
                Status = "Not Available"
            }
        }

        return $counters
    } catch {
        return @([PSCustomObject]@{
            CounterSet = "Error"
            Description = "Error getting performance counters: $_"
            Status = "Error"
        })
    }
}

# Function to check registry configuration
function Get-FSLogixRegistryHealth {
    try {
        $registryHealth = @()

        $fslogixKeys = @(
            "HKLM:\SOFTWARE\FSLogix\Profiles",
            "HKLM:\SOFTWARE\FSLogix\Apps",
            "HKLM:\SOFTWARE\Policies\FSLogix"
        )

        foreach ($key in $fslogixKeys) {
            $exists = Test-Path $key
            $properties = @()

            if ($exists) {
                try {
                    $keyProperties = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                    if ($keyProperties) {
                        $properties = $keyProperties.PSObject.Properties.Name | Where-Object { $_ -notlike "PS*" }
                    }
                } catch {
                    $properties = @("Error reading properties: $_")
                }
            }

            $registryHealth += [PSCustomObject]@{
                RegistryKey = $key
                Exists = $exists
                Properties = $properties -join ", "
                Status = if ($exists) { "OK" } else { "Key not found" }
            }
        }

        return $registryHealth
    } catch {
        return @([PSCustomObject]@{
            RegistryKey = "Error"
            Exists = $false
            Properties = "Error checking registry: $_"
            Status = "Error"
        })
    }
}

# Function to get top processes by CPU and RAM usage
function Get-TopProcessUsage {
    try {
        # Use performance data for accurate CPU percentage
        $procPerf = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfProc_Process | Where-Object { $_.Name -notmatch '^(_Total|Idle)$' } | Select-Object Name, PercentProcessorTime, IDProcess, @{Name="RAM_MB"; Expression={ [math]::Round($_.WorkingSetPrivate / 1MB, 0) }}

        # Get top 10 processes by CPU percentage
        $cpuTop = $procPerf | Sort-Object -Property PercentProcessorTime -Descending | Select-Object -First 10 -Property @{Name="Process Name"; Expression={ $_.Name }}, @{Name="PID"; Expression={ $_.IDProcess }}, @{Name="CPU %"; Expression={ "{0:N1}%" -f $_.PercentProcessorTime }}, @{Name="RAM (MB)"; Expression={ $_.RAM_MB }}

        # Get top 10 processes by RAM
        $ramTop = $procPerf | Sort-Object -Property RAM_MB -Descending | Select-Object -First 10 -Property @{Name="Process Name"; Expression={ $_.Name }}, @{Name="PID"; Expression={ $_.IDProcess }}, @{Name="CPU %"; Expression={ "{0:N1}%" -f $_.PercentProcessorTime }}, @{Name="RAM (MB)"; Expression={ $_.RAM_MB }}

        # Get unique processes from both lists (top 10 by RAM sorting of combined)
        $allProcesses = $cpuTop + $ramTop
        $uniqueProcesses = $allProcesses | Sort-Object -Property @{Expression={ [double]$_.{RAM (MB)} }; Descending=$true} | Select-Object -First 10 -Unique -Property "Process Name"

        return [PSCustomObject]@{
            TopCPUProcesses = $cpuTop
            TopRAMProcesses = $ramTop
            TopUniqueProcesses = $uniqueProcesses
        }
    } catch {
        return [PSCustomObject]@{
            TopCPUProcesses = @()
            TopRAMProcesses = @()
            TopUniqueProcesses = @()
            Error = "Error getting process usage: $_"
        }
    }
}

# Function to generate HTML report
function New-AdvancedDiagnosticsReport {
    param(
        [hashtable]$DiagnosticData,
        [string]$FilePath
    )

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>FSLogix Advanced Diagnostics Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .section { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .status-ok { color: #28a745; font-weight: bold; }
        .status-warning { color: #ffc107; font-weight: bold; }
        .status-error { color: #dc3545; font-weight: bold; }
        .metric { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #eee; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: bold; }
        .health-good { background-color: #d4edda; }
        .health-warning { background-color: #fff3cd; }
        .health-error { background-color: #f8d7da; }
    </style>
</head>
<body>
    <div class="header">
        <h1>FSLogix Advanced Diagnostics Report</h1>
        <p><strong>Server:</strong> $($DiagnosticData.ServerName)</p>
        <p><strong>Report Generated:</strong> $($DiagnosticData.Timestamp)</p>
    </div>

    <div class="section">
        <h2>FSLogix Services</h2>
        <table>
            <tr><th>Service</th><th>Status</th><th>Start Type</th><th>State</th></tr>
"@

    foreach ($service in $DiagnosticData.Services) {
        $statusClass = if ($service.IsRunning) { "status-ok" } elseif ($service.Exists) { "status-warning" } else { "status-error" }
        $html += "<tr><td>$($service.ServiceName)</td><td class='$statusClass'>$($service.Status)</td><td>$($service.StartType)</td><td>$($service.IsRunning)</td></tr>"
    }

    $html += @"
        </table>
    </div>

    <div class="section">
        <h2>Profile Health</h2>
        <table>
            <tr><th>Location</th><th>VHD Count</th><th>Total Size (GB)</th><th>Healthy</th><th>Corrupt</th><th>Status</th></tr>
"@

    foreach ($profile in $DiagnosticData.ProfileHealth) {
        $statusClass = if ($profile.CorruptVHDs -eq 0) { "status-ok" } else { "status-error" }
        $html += "<tr><td>$($profile.Location)</td><td>$($profile.VHDCount)</td><td>$($profile.TotalSizeGB)</td><td>$($profile.HealthyVHDs)</td><td>$($profile.CorruptVHDs)</td><td class='$statusClass'>$($profile.Status)</td></tr>"
    }

    $html += @"
        </table>
    </div>

    <div class="section">
        <h2>Event Log Analysis</h2>
        <table>
            <tr><th>Source</th><th>Total Events</th><th>Errors</th><th>Warnings</th><th>Status</th></tr>
"@

    foreach ($event in $DiagnosticData.EventLogs) {
        $statusClass = if ($event.Errors -eq 0 -and $event.Warnings -eq 0) { "status-ok" } elseif ($event.Errors -gt 0) { "status-error" } else { "status-warning" }
        $html += "<tr><td>$($event.Source)</td><td>$($event.TotalEvents)</td><td>$($event.Errors)</td><td>$($event.Warnings)</td><td class='$statusClass'>$($event.Status)</td></tr>"
    }

    $html += @"
        </table>
    </div>

    <div class="section">
        <h2>Network Connectivity</h2>
        <table>
            <tr><th>Server</th><th>Share</th><th>Ping</th><th>Share Access</th><th>Network Adapter</th><th>Status</th></tr>
"@

    foreach ($conn in $DiagnosticData.NetworkConnectivity) {
        $statusClass = if ($conn.Status -eq "OK") { "status-ok" } elseif ($conn.Status -like "*Inaccessible*") { "status-warning" } else { "status-error" }
        $html += "<tr><td>$($conn.Server)</td><td>$($conn.Share)</td><td>$($conn.PingSuccess)</td><td>$($conn.ShareAccessible)</td><td>$($conn.NetworkAdapter)</td><td class='$statusClass'>$($conn.Status)</td></tr>"
    }

    $html += @"
        </table>
    </div>

    <div class="section">
        <h2>Registry Configuration</h2>
        <table>
            <tr><th>Registry Key</th><th>Exists</th><th>Properties</th><th>Status</th></tr>
"@

    foreach ($reg in $DiagnosticData.RegistryHealth) {
        $statusClass = if ($reg.Exists) { "status-ok" } else { "status-warning" }
        $html += "<tr><td>$($reg.RegistryKey)</td><td>$($reg.Exists)</td><td>$($reg.Properties)</td><td class='$statusClass'>$($reg.Status)</td></tr>"
    }

    $html += @"
        </table>
    </div>

    <div class="section">
        <h2>Top CPU Consuming Processes</h2>
        <table>
            <tr><th>Process Name</th><th>PID</th><th>CPU %</th><th>RAM (MB)</th></tr>
"@

    if ($DiagnosticData.ProcessUsage.TopCPUProcesses) {
        foreach ($process in $DiagnosticData.ProcessUsage.TopCPUProcesses) {
            $html += "<tr><td>$($process.'Process Name')</td><td>$($process.PID)</td><td>$($process.'CPU %')</td><td>$($process.'RAM (MB)')</td></tr>"
        }
    } else {
        $html += "<tr><td colspan='4'>No CPU process data available</td></tr>"
    }

    $html += @"
        </table>
    </div>

    <div class="section">
        <h2>Top RAM Consuming Processes</h2>
        <table>
            <tr><th>Process Name</th><th>PID</th><th>CPU %</th><th>RAM (MB)</th></tr>
"@

    if ($DiagnosticData.ProcessUsage.TopRAMProcesses) {
        foreach ($process in $DiagnosticData.ProcessUsage.TopRAMProcesses) {
            $html += "<tr><td>$($process.'Process Name')</td><td>$($process.PID)</td><td>$($process.'CPU %')</td><td>$($process.'RAM (MB)')</td></tr>"
        }
    } else {
        $html += "<tr><td colspan='4'>No RAM process data available</td></tr>"
    }

    $html += @"
        </table>
    </div>

    <div class="section">
        <h2>Recommendations</h2>
        <ul>
"@

    # Generate recommendations based on diagnostic data
    $recommendations = @()

    if ($DiagnosticData.Services | Where-Object { -not $_.IsRunning -and $_.Exists }) {
        $recommendations += "Start required FSLogix services that are stopped"
    }

    if ($DiagnosticData.ProfileHealth | Where-Object { $_.CorruptVHDs -gt 0 }) {
        $recommendations += "Investigate and repair or recover corrupt VHD files"
        $recommendations += "<strong>Potential causes of VHDX corruption:</strong>"
        $recommendations += "- Network connectivity interruptions during profile operations"
        $recommendations += "- Disk space exhaustion on storage servers"
        $recommendations += "- Sudden server restarts or power losses"
        $recommendations += "- Antivirus software interfering with VHDX files"
        $recommendations += "- Hardware failures in storage controllers or disks"
        $recommendations += "- Concurrent access conflicts from multiple sessions"
        $recommendations += "<strong>Prevention tips:</strong>"
        $recommendations += "- Ensure stable network connectivity and sufficient bandwidth"
        $recommendations += "- Implement RAID storage with redundancy"
        $recommendations += "- Monitor disk space usage and implement alerts"
        $recommendations += "- Configure antivirus exclusions for VHDX files"
        $recommendations += "- Use UPS and proper shutdown procedures"
        $recommendations += "- Limit concurrent profile accesses per user"
    }

    if ($DiagnosticData.EventLogs | Where-Object { $_.Errors -gt 0 }) {
        $recommendations += "Review event logs for error details and take corrective action"
    }

    if ($DiagnosticData.NetworkConnectivity | Where-Object { -not $_.ShareAccessible }) {
        $recommendations += "Fix network connectivity issues to profile shares"
    }

    if ($recommendations.Count -eq 0) {
        $recommendations += "All systems appear healthy"
    }

    foreach ($rec in $recommendations) {
        $html += "<li>$rec</li>"
    }

    $html += @"
        </ul>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $FilePath -Encoding UTF8
    Write-Host "Advanced diagnostics HTML report saved to: $FilePath" -ForegroundColor Green
}

# Main diagnostic function
function Run-AdvancedDiagnostics {
    Write-Host "=== FSLogix Advanced Diagnostics ===" -ForegroundColor Cyan
    Write-Host "Server: $ServerName" -ForegroundColor Cyan
    Write-Host "Full Scan: $FullScan" -ForegroundColor Cyan
    Write-Host ""

    $diagnosticResults = @{
        ServerName = $ServerName
        Timestamp = Get-Date
        Services = $null
        ProfileHealth = $null
        EventLogs = $null
        NetworkConnectivity = $null
        RegistryHealth = $null
        PerformanceCounters = $null
        ProcessUsage = $null
    }

    # Check FSLogix services
    Write-Host "Checking FSLogix services..." -ForegroundColor Yellow
    $diagnosticResults.Services = Get-FSLogixServiceStatus
    foreach ($service in $diagnosticResults.Services) {
        $color = if ($service.IsRunning) { "Green" } elseif ($service.Exists) { "Yellow" } else { "Red" }
        Write-Host "  $($service.ServiceName): $($service.Status)" -ForegroundColor $color
    }

    # Check profile health
    Write-Host "`nChecking profile health..." -ForegroundColor Yellow
    $diagnosticResults.ProfileHealth = Get-FSLogixProfileHealth
    foreach ($profile in $diagnosticResults.ProfileHealth) {
        $color = if ($profile.CorruptVHDs -eq 0) { "Green" } else { "Red" }
        Write-Host "  $($profile.Location): $($profile.Status)" -ForegroundColor $color
        Write-Host "    VHDs: $(($profile.VHDCount)) Total: $($profile.TotalSizeGB)GB Healthy: $($profile.HealthyVHDs) Corrupt: $($profile.CorruptVHDs)" -ForegroundColor Blue
    }

    # Analyze event logs
    Write-Host "`nAnalyzing event logs..." -ForegroundColor Yellow
    $diagnosticResults.EventLogs = Get-EventLogAnalysis
    foreach ($event in $diagnosticResults.EventLogs) {
        $color = if ($event.Errors -eq 0 -and $event.Warnings -eq 0) { "Green" } elseif ($event.Errors -gt 0) { "Red" } else { "Yellow" }
        Write-Host "  $($event.Source): $($event.Status) ($($event.TotalEvents) events)" -ForegroundColor $color
    }

    # Test network connectivity
    Write-Host "`nTesting network connectivity..." -ForegroundColor Yellow
    $diagnosticResults.NetworkConnectivity = Test-NetworkConnectivity
    foreach ($conn in $diagnosticResults.NetworkConnectivity) {
        $color = if ($conn.Status -eq "OK") { "Green" } elseif ($conn.PingSuccess) { "Yellow" } else { "Red" }
        Write-Host "  $($conn.Server)\$($conn.Share): $($conn.Status)" -ForegroundColor $color
    }

    # Check registry configuration
    Write-Host "`nChecking registry configuration..." -ForegroundColor Yellow
    $diagnosticResults.RegistryHealth = Get-FSLogixRegistryHealth
    foreach ($reg in $diagnosticResults.RegistryHealth) {
        $color = if ($reg.Exists) { "Green" } else { "Yellow" }
        Write-Host "  $($reg.RegistryKey): $($reg.Status)" -ForegroundColor $color
    }

    # Check process usage
    Write-Host "`nChecking top process usage..." -ForegroundColor Yellow
    $diagnosticResults.ProcessUsage = Get-TopProcessUsage
    Write-Host "  Top CPU processes collected: $($diagnosticResults.ProcessUsage.TopCPUProcesses.Count)" -ForegroundColor Green
    Write-Host "  Top RAM processes collected: $($diagnosticResults.ProcessUsage.TopRAMProcesses.Count)" -ForegroundColor Green
    Write-Host "  Unique processes collected: $($diagnosticResults.ProcessUsage.TopUniqueProcesses.Count)" -ForegroundColor Green

    # Optional full scan items
    if ($FullScan) {
        Write-Host "`nFull scan - Checking performance counters..." -ForegroundColor Yellow
        $diagnosticResults.PerformanceCounters = Get-FSLogixPerformanceCounters
        foreach ($counter in $diagnosticResults.PerformanceCounters) {
            Write-Host "  $($counter.CounterSet): $($counter.Status)" -ForegroundColor Blue
        }
    }

    # Generate report if requested
    if ($ExportReport) {
        if (-not $ReportPath) {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $ReportPath = "FSLogixAdvancedDiagnostics_${ServerName}_${timestamp}.$($ReportFormat.ToLower())"
        }

        # Ensure the directory exists
        $directory = Split-Path -Path $ReportPath -Parent
        if ($directory -and -not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }

        switch ($ReportFormat) {
            "HTML" { New-AdvancedDiagnosticsReport -DiagnosticData $diagnosticResults -FilePath $ReportPath }
            default {
                # Simple text export
                $diagnosticResults | ConvertTo-Json -Depth 5 | Out-File -FilePath $ReportPath -Encoding UTF8
                Write-Host "Advanced diagnostics text report saved to: $ReportPath" -ForegroundColor Green
            }
        }
    }

    Write-Host "`n=== Advanced Diagnostics Complete ===" -ForegroundColor Cyan
    Write-Host "Use -ExportReport to save detailed results to file." -ForegroundColor White
}

# Execute the diagnostics
Run-AdvancedDiagnostics
