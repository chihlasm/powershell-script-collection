# Citrix VDA Diagnostics Tool
# Diagnoses disk queue length, storage space, CPU, and RAM usage for Citrix VDA servers with FSlogix

param(
    [string]$ServerName = $env:COMPUTERNAME,
    [switch]$Verbose,
    [switch]$ExportReport,
    [ValidateSet("HTML", "CSV", "JSON", "TXT")]
    [string]$ReportFormat = "HTML",
    [string]$ReportPath = ""
)

# Function to get Citrix sessions
function Get-CitrixSessions {
    try {
        # Try to use Citrix cmdlets if available
        if (Get-Command Get-BrokerSession -ErrorAction SilentlyContinue) {
            $sessions = Get-BrokerSession -AdminAddress $ServerName | Where-Object { $_.SessionState -eq 'Active' }
            return $sessions
        }
        # Fallback: use quser or query session
        else {
            $sessions = query session /server:$ServerName | Where-Object { $_ -match '\sActive\s' }
            return $sessions
        }
    }
    catch {
        Write-Warning "Could not retrieve Citrix sessions: $_"
        return $null
    }
}

# Function to get FSlogix profile paths
function Get-FSlogixProfilePaths {
    $profilePaths = @()
    try {
        # Check FSlogix registry for profile locations
        $fslogixKey = "HKLM:\SOFTWARE\FSLogix\Profiles"
        if (Test-Path $fslogixKey) {
            $enabled = Get-ItemProperty -Path $fslogixKey -Name "Enabled" -ErrorAction SilentlyContinue
            if ($enabled.Enabled -eq 1) {
                $vhdLocations = Get-ItemProperty -Path $fslogixKey -Name "VHDLocations" -ErrorAction SilentlyContinue
                if ($vhdLocations.VHDLocations) {
                    $profilePaths = $vhdLocations.VHDLocations -split ';'
                }
            }
        }
    }
    catch {
        Write-Warning "Could not retrieve FSlogix configuration: $_"
    }
    return $profilePaths
}

# Function to get FSlogix version
function Get-FSlogixVersion {
    try {
        # Check FSlogix Apps registry for version
        $fslogixAppsKey = "HKLM:\SOFTWARE\FSLogix\Apps"
        if (Test-Path $fslogixAppsKey) {
            $version = Get-ItemProperty -Path $fslogixAppsKey -Name "InstallVersion" -ErrorAction SilentlyContinue
            if ($version.InstallVersion) {
                return $version.InstallVersion
            }
        }

        # Fallback: Check installed programs
        $fslogixApp = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*FSLogix*" } | Select-Object -First 1
        if ($fslogixApp) {
            return $fslogixApp.Version
        }

        # Another fallback: Check file version of frx.exe
        $frxPath = "${env:ProgramFiles}\FSLogix\Apps\frx.exe"
        if (Test-Path $frxPath) {
            $fileVersion = (Get-Item $frxPath).VersionInfo.FileVersion
            return $fileVersion
        }

        return $null
    }
    catch {
        Write-Warning "Could not retrieve FSlogix version: $_"
        return $null
    }
}

# Function to check for pending Windows updates
function Get-PendingWindowsUpdates {
    try {
        # Try using Windows Update COM objects
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=0")

        $pendingUpdates = @()
        foreach ($update in $searchResult.Updates) {
            $pendingUpdates += @{
                Title = $update.Title
                KB = $update.KBArticleIDs -join ", "
                IsCritical = $update.IsCritical
            }
        }

        return @{
            Count = $pendingUpdates.Count
            Updates = $pendingUpdates
        }
    }
    catch {
        Write-Warning "Could not check for Windows updates: $_"
        return @{
            Count = -1
            Updates = @()
            Error = $_.Exception.Message
        }
    }
}

# Function to diagnose I/O operations for FSlogix shares
function Get-FSlogixIOPerformance {
    param([string]$Path)

    try {
        $ioStats = @{}

        if ($Path -match "^([A-Za-z]):") {
            # Local drive - use performance counters
            $driveLetter = $matches[1]
            $counters = @(
                "\LogicalDisk($($driveLetter):)\Disk Read Bytes/sec",
                "\LogicalDisk($($driveLetter):)\Disk Write Bytes/sec",
                "\LogicalDisk($($driveLetter):)\Avg. Disk sec/Read",
                "\LogicalDisk($($driveLetter):)\Avg. Disk sec/Write"
            )

            $counterData = Get-Counter -Counter $counters -SampleInterval 2 -MaxSamples 3 -ErrorAction SilentlyContinue

            if ($counterData) {
                $readBytes = ($counterData.CounterSamples | Where-Object { $_.Path -like "*Disk Read Bytes/sec*" } | Measure-Object CookedValue -Average).Average
                $writeBytes = ($counterData.CounterSamples | Where-Object { $_.Path -like "*Disk Write Bytes/sec*" } | Measure-Object CookedValue -Average).Average
                $readLatency = ($counterData.CounterSamples | Where-Object { $_.Path -like "*Avg. Disk sec/Read*" } | Measure-Object CookedValue -Average).Average * 1000
                $writeLatency = ($counterData.CounterSamples | Where-Object { $_.Path -like "*Avg. Disk sec/Write*" } | Measure-Object CookedValue -Average).Average * 1000

                $ioStats = @{
                    Type = "Local Drive"
                    ReadMBps = [math]::Round($readBytes / 1MB, 2)
                    WriteMBps = [math]::Round($writeBytes / 1MB, 2)
                    ReadLatencyMs = [math]::Round($readLatency, 2)
                    WriteLatencyMs = [math]::Round($writeLatency, 2)
                    TotalMBps = [math]::Round(($readBytes + $writeBytes) / 1MB, 2)
                }
            }
        }
        elseif ($Path -match "^\\\\([^\\]+)\\([^\\]+)") {
            # UNC path - test file operations
            $server = $matches[1]
            $share = $matches[2]

            # Create a test file and measure I/O
            $testFile = Join-Path $Path "fslogix_test.tmp"
            $testData = "X" * 1MB  # 1MB test data

            try {
                # Test write performance
                $writeStart = Get-Date
                [System.IO.File]::WriteAllText($testFile, $testData)
                $writeEnd = Get-Date
                $writeTime = ($writeEnd - $writeStart).TotalSeconds

                # Test read performance
                $readStart = Get-Date
                $readData = [System.IO.File]::ReadAllText($testFile)
                $readEnd = Get-Date
                $readTime = ($readEnd - $readStart).TotalSeconds

                # Clean up
                Remove-Item $testFile -Force -ErrorAction SilentlyContinue

                $writeMBps = [math]::Round(1 / $writeTime, 2)  # MB/s
                $readMBps = [math]::Round(1 / $readTime, 2)    # MB/s

                $ioStats = @{
                    Type = "UNC Path ($server\$share)"
                    ReadMBps = $readMBps
                    WriteMBps = $writeMBps
                    TotalMBps = [math]::Round($readMBps + $writeMBps, 2)
                    NetworkTest = $true
                }
            }
            catch {
                $ioStats = @{
                    Type = "UNC Path ($server\$share)"
                    Error = "Could not perform I/O test: $_"
                }
            }
        }

        return $ioStats
    }
    catch {
        Write-Warning "Could not get I/O performance for $Path`: $_"
        return @{ Error = $_.Exception.Message }
    }
}

# Function to get disk queue length
function Get-DiskQueueLength {
    param([string]$DriveLetter)
    try {
        $counter = "\LogicalDisk($($DriveLetter):)\Avg. Disk Queue Length"
        $queueLength = Get-Counter -Counter $counter -SampleInterval 1 -MaxSamples 1
        return [math]::Round($queueLength.CounterSamples.CookedValue, 2)
    }
    catch {
        Write-Warning "Could not get disk queue length for $DriveLetter`: $_"
        return $null
    }
}

# Function to get storage information
function Get-StorageInfo {
    param([string]$DriveLetter)
    try {
        $volume = Get-Volume -DriveLetter $DriveLetter
        $totalGB = [math]::Round($volume.Size / 1GB, 2)
        $freeGB = [math]::Round($volume.SizeRemaining / 1GB, 2)
        $usedGB = $totalGB - $freeGB
        $usedPercent = [math]::Round(($usedGB / $totalGB) * 100, 2)

        return @{
            TotalGB = $totalGB
            FreeGB = $freeGB
            UsedGB = $usedGB
            UsedPercent = $usedPercent
        }
    }
    catch {
        Write-Warning "Could not get storage info for ${DriveLetter}: $_"
        return $null
    }
}

# Function to get CPU and RAM usage
function Get-SystemResources {
    try {
        # CPU Usage
        $cpuCounter = Get-Counter -Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 1
        $cpuPercent = [math]::Round($cpuCounter.CounterSamples.CookedValue, 2)

        # Memory Usage
        $memoryCounters = Get-Counter -Counter @('\Memory\Available MBytes', '\Memory\Committed Bytes') -SampleInterval 1 -MaxSamples 1
        $availableMB = $memoryCounters.CounterSamples[0].CookedValue
        $committedBytes = $memoryCounters.CounterSamples[1].CookedValue

        $totalMemory = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory
        $totalMB = [math]::Round($totalMemory / 1MB, 2)
        $usedMB = [math]::Round($committedBytes / 1MB, 2)
        $usedPercent = [math]::Round(($usedMB / $totalMB) * 100, 2)

        return @{
            CPUPercent = $cpuPercent
            TotalMemoryMB = $totalMB
            UsedMemoryMB = $usedMB
            AvailableMemoryMB = [math]::Round($availableMB, 2)
            MemoryUsedPercent = $usedPercent
        }
    }
    catch {
        Write-Warning "Could not get system resource information: $_"
        return $null
    }
}

# Main diagnostic function
function Run-CitrixVDADiagnostics {
    Write-Host "=== Citrix VDA Diagnostics Tool ===" -ForegroundColor Cyan
    Write-Host "Server: $ServerName" -ForegroundColor Cyan
    Write-Host "Timestamp: $(Get-Date)" -ForegroundColor Cyan
    Write-Host ""

    # Get active sessions
    $sessions = Get-CitrixSessions
    $userCount = if ($sessions) { $sessions.Count } else { 0 }

    Write-Host "Active Sessions: $userCount" -ForegroundColor Yellow
    if ($Verbose) {
        $sessions | ForEach-Object { Write-Host "  - $($_.UserName)" }
    }
    Write-Host ""

    # Get FSlogix version
    $fslogixVersion = Get-FSlogixVersion
    Write-Host "FSlogix Version:" -ForegroundColor Yellow
    if ($fslogixVersion) {
        Write-Host "  - $fslogixVersion" -ForegroundColor Green
    } else {
        Write-Host "  - FSlogix not detected or version unknown" -ForegroundColor Red
    }
    Write-Host ""

    # Get FSlogix profile paths
    $profilePaths = Get-FSlogixProfilePaths
    Write-Host "FSlogix Profile Locations:" -ForegroundColor Yellow
    if ($profilePaths) {
        $profilePaths | ForEach-Object { Write-Host "  - $_" }
    } else {
        Write-Host "  - No FSlogix configuration found or not enabled" -ForegroundColor Red
    }
    Write-Host ""

    # Get system resources
    $resources = Get-SystemResources
    if ($resources) {
        Write-Host "System Resources:" -ForegroundColor Yellow
        Write-Host "  CPU Usage: $($resources.CPUPercent)%"
        Write-Host "  Memory: $($resources.UsedMemoryMB)MB used / $($resources.TotalMemoryMB)MB total ($($resources.MemoryUsedPercent)%)"
        Write-Host "  Available Memory: $($resources.AvailableMemoryMB)MB"

        if ($userCount -gt 0) {
            $cpuPerUser = [math]::Round($resources.CPUPercent / $userCount, 2)
            $memoryPerUserMB = [math]::Round($resources.UsedMemoryMB / $userCount, 2)
            Write-Host "  Per User (estimated): $cpuPerUser% CPU, ${memoryPerUserMB}MB RAM" -ForegroundColor Green
        }
        Write-Host ""
    }

    # Check storage for each profile path
    if ($profilePaths) {
        Write-Host "Storage Analysis:" -ForegroundColor Yellow
        foreach ($path in $profilePaths) {
            # Extract drive letter properly - handle both local drives and UNC paths
            $driveLetter = $null
            if ($path -match "^([A-Za-z]):") {
                # Local drive (e.g., "C:\path\to\profiles")
                $driveLetter = $matches[1]
            }
            elseif ($path -match "^\\\\([^\\]+)\\([^\\]+)") {
                # UNC path (e.g., "\\server\share\profiles")
                Write-Host "  UNC Path: $path" -ForegroundColor Cyan
                Write-Host "    Note: UNC paths are not analyzed for local disk metrics" -ForegroundColor Yellow
                continue
            }
            else {
                Write-Host "  Path: $path" -ForegroundColor Cyan
                Write-Host "    Warning: Could not determine drive letter from path" -ForegroundColor Red
                continue
            }

            if ($driveLetter) {
                Write-Host "  Drive $driveLetter`:" -ForegroundColor Cyan

                # Disk queue length
                $queueLength = Get-DiskQueueLength -DriveLetter $driveLetter
                if ($queueLength -ne $null) {
                    $status = if ($queueLength -gt 2) { "WARNING" } elseif ($queueLength -gt 5) { "CRITICAL" } else { "OK" }
                    Write-Host "    Disk Queue Length: $queueLength ($status)" -ForegroundColor $(if ($status -eq "OK") { "Green" } elseif ($status -eq "WARNING") { "Yellow" } else { "Red" })
                }

                # Storage info
                $storage = Get-StorageInfo -DriveLetter $driveLetter
                if ($storage) {
                    $storageStatus = if ($storage.UsedPercent -gt 90) { "CRITICAL" } elseif ($storage.UsedPercent -gt 80) { "WARNING" } else { "OK" }
                    Write-Host "    Storage: $($storage.UsedGB)GB used / $($storage.TotalGB)GB total ($($storage.UsedPercent)%) ($storageStatus)" -ForegroundColor $(if ($storageStatus -eq "OK") { "Green" } elseif ($storageStatus -eq "WARNING") { "Yellow" } else { "Red" })
                    Write-Host "    Free Space: $($storage.FreeGB)GB"
                }
                Write-Host ""
            }
        }
    }

    # Recommendations
    Write-Host "Recommendations:" -ForegroundColor Yellow
    if ($resources -and $userCount -gt 0) {
        $cpuPerUser = $resources.CPUPercent / $userCount
        if ($cpuPerUser -gt 80) {
            Write-Host "  - High CPU usage per user ($cpuPerUser%). Consider adding more CPU cores or reducing user load." -ForegroundColor Red
        }

        $memoryPerUserMB = $resources.UsedMemoryMB / $userCount
        if ($memoryPerUserMB -gt 1024) { # 1GB per user
            Write-Host "  - High memory usage per user (${memoryPerUserMB}MB). Consider adding more RAM or optimizing applications." -ForegroundColor Red
        }
    }

    if ($profilePaths) {
        foreach ($path in $profilePaths) {
            # Extract drive letter properly for recommendations
            $driveLetter = $null
            if ($path -match "^([A-Za-z]):") {
                $driveLetter = $matches[1]
            }
            elseif ($path -match "^\\\\([^\\]+)\\([^\\]+)") {
                # Skip UNC paths for recommendations
                continue
            }

            if ($driveLetter) {
                $queueLength = Get-DiskQueueLength -DriveLetter $driveLetter
                if ($queueLength -gt 2) {
                    Write-Host "  - High disk queue length on $driveLetter. Consider faster storage or distributing VHDs across multiple drives." -ForegroundColor Red
                }

                $storage = Get-StorageInfo -DriveLetter $driveLetter
                if ($storage -and $storage.UsedPercent -gt 85) {
                    Write-Host "  - Low free space on $driveLetter ($($storage.UsedPercent)% used). Clean up old profiles or add storage capacity." -ForegroundColor Red
                }
            }
        }
    }

    # Check for pending Windows updates
    Write-Host "Windows Updates:" -ForegroundColor Yellow
    $windowsUpdates = Get-PendingWindowsUpdates
    if ($windowsUpdates.Count -eq -1) {
        Write-Host "  - Could not check for updates: $($windowsUpdates.Error)" -ForegroundColor Red
    }
    elseif ($windowsUpdates.Count -eq 0) {
        Write-Host "  - All updates are current" -ForegroundColor Green
    }
    else {
        Write-Host "  - $($windowsUpdates.Count) pending updates" -ForegroundColor $(if ($windowsUpdates.Count -gt 10) { "Red" } elseif ($windowsUpdates.Count -gt 5) { "Yellow" } else { "Green" })
        if ($Verbose -and $windowsUpdates.Updates) {
            $criticalCount = ($windowsUpdates.Updates | Where-Object { $_.IsCritical }).Count
            if ($criticalCount -gt 0) {
                Write-Host "  - $criticalCount critical updates pending" -ForegroundColor Red
            }
        }
    }
    Write-Host ""

    # I/O Performance Analysis
    if ($profilePaths) {
        Write-Host "I/O Performance Analysis:" -ForegroundColor Yellow
        foreach ($path in $profilePaths) {
            Write-Host "  Path: $path" -ForegroundColor Cyan
            $ioStats = Get-FSlogixIOPerformance -Path $path

            if ($ioStats.Error) {
                Write-Host "    Error: $($ioStats.Error)" -ForegroundColor Red
            }
            elseif ($ioStats.Type) {
                Write-Host "    Type: $($ioStats.Type)" -ForegroundColor White
                if ($ioStats.ReadMBps -ne $null) {
                    Write-Host "    Read Performance: $($ioStats.ReadMBps) MB/s" -ForegroundColor $(if ($ioStats.ReadMBps -lt 50) { "Red" } elseif ($ioStats.ReadMBps -lt 100) { "Yellow" } else { "Green" })
                }
                if ($ioStats.WriteMBps -ne $null) {
                    Write-Host "    Write Performance: $($ioStats.WriteMBps) MB/s" -ForegroundColor $(if ($ioStats.WriteMBps -lt 50) { "Red" } elseif ($ioStats.WriteMBps -lt 100) { "Yellow" } else { "Green" })
                }
                if ($ioStats.TotalMBps -ne $null) {
                    Write-Host "    Total I/O: $($ioStats.TotalMBps) MB/s" -ForegroundColor $(if ($ioStats.TotalMBps -lt 100) { "Red" } elseif ($ioStats.TotalMBps -lt 200) { "Yellow" } else { "Green" })
                }
                if ($ioStats.ReadLatencyMs -ne $null) {
                    Write-Host "    Read Latency: $($ioStats.ReadLatencyMs) ms" -ForegroundColor $(if ($ioStats.ReadLatencyMs -gt 20) { "Red" } elseif ($ioStats.ReadLatencyMs -gt 10) { "Yellow" } else { "Green" })
                }
                if ($ioStats.WriteLatencyMs -ne $null) {
                    Write-Host "    Write Latency: $($ioStats.WriteLatencyMs) ms" -ForegroundColor $(if ($ioStats.WriteLatencyMs -gt 20) { "Red" } elseif ($ioStats.WriteLatencyMs -gt 10) { "Yellow" } else { "Green" })
                }
                if ($ioStats.NetworkTest) {
                    Write-Host "    Note: Network I/O test performed (may impact performance temporarily)" -ForegroundColor Yellow
                }
            }
            else {
                Write-Host "    No performance data available" -ForegroundColor Yellow
            }
            Write-Host ""
        }
    }

    # Additional recommendations based on new diagnostics
    if ($windowsUpdates.Count -gt 0) {
        Write-Host "  - $($windowsUpdates.Count) Windows updates pending. Schedule maintenance window for updates." -ForegroundColor $(if ($windowsUpdates.Count -gt 10) { "Red" } else { "Yellow" })
    }

    Write-Host ""
    Write-Host "=== Diagnostics Complete ===" -ForegroundColor Cyan
}

# Function to generate HTML report
function New-HTMLReport {
    param(
        [hashtable]$ReportData,
        [string]$FilePath
    )

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Citrix VDA Diagnostics Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .section { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .metric { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #eee; }
        .status-ok { color: #28a745; font-weight: bold; }
        .status-warning { color: #ffc107; font-weight: bold; }
        .status-critical { color: #dc3545; font-weight: bold; }
        .recommendations { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 10px 0; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: bold; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .summary-item { background: white; padding: 15px; border-radius: 6px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .summary-value { font-size: 24px; font-weight: bold; color: #333; }
        .summary-label { color: #666; font-size: 14px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🖥️ Citrix VDA Diagnostics Report</h1>
        <p><strong>Server:</strong> $($ReportData.ServerName)</p>
        <p><strong>Report Generated:</strong> $($ReportData.Timestamp)</p>
    </div>

    <div class="summary">
        <div class="summary-item">
            <div class="summary-value">$($ReportData.Sessions.Count)</div>
            <div class="summary-label">Active Sessions</div>
        </div>
        <div class="summary-item">
            <div class="summary-value">$($ReportData.SystemResources.CPUPercent)%</div>
            <div class="summary-label">CPU Usage</div>
        </div>
        <div class="summary-item">
            <div class="summary-value">$($ReportData.SystemResources.MemoryUsedPercent)%</div>
            <div class="summary-label">Memory Usage</div>
        </div>
        <div class="summary-item">
            <div class="summary-value">$($ReportData.WindowsUpdates.Count)</div>
            <div class="summary-label">Pending Updates</div>
        </div>
    </div>

    <div class="section">
        <h2>🔍 System Information</h2>
        <div class="metric">
            <span>FSlogix Version:</span>
            <span class="$(if($ReportData.FSlogixVersion){'status-ok'}else{'status-warning'})">$(if($ReportData.FSlogixVersion){$ReportData.FSlogixVersion}else{'Not Detected'})</span>
        </div>
        <div class="metric">
            <span>Profile Locations:</span>
            <span>$($ReportData.ProfilePaths.Count) configured</span>
        </div>
    </div>

    <div class="section">
        <h2>💻 System Resources</h2>
        <div class="metric">
            <span>CPU Usage:</span>
            <span class="$(if($ReportData.SystemResources.CPUPercent -lt 70){'status-ok'}elseif($ReportData.SystemResources.CPUPercent -lt 90){'status-warning'}else{'status-critical'})">$($ReportData.SystemResources.CPUPercent)%</span>
        </div>
        <div class="metric">
            <span>Memory Usage:</span>
            <span class="$(if($ReportData.SystemResources.MemoryUsedPercent -lt 80){'status-ok'}elseif($ReportData.SystemResources.MemoryUsedPercent -lt 95){'status-warning'}else{'status-critical'})">$($ReportData.SystemResources.UsedMemoryMB)MB / $($ReportData.SystemResources.TotalMemoryMB)MB ($($ReportData.SystemResources.MemoryUsedPercent)%)</span>
        </div>
        <div class="metric">
            <span>Available Memory:</span>
            <span>$($ReportData.SystemResources.AvailableMemoryMB)MB</span>
        </div>
"@

    if ($ReportData.Sessions.Count -gt 0) {
        $html += @"

        <div class="metric">
            <span>Per User CPU:</span>
            <span>$([math]::Round($ReportData.SystemResources.CPUPercent / $ReportData.Sessions.Count, 2))%</span>
        </div>
        <div class="metric">
            <span>Per User Memory:</span>
            <span>$([math]::Round($ReportData.SystemResources.UsedMemoryMB / $ReportData.Sessions.Count, 2))MB</span>
        </div>
"@
    }

    $html += @"
    </div>

    <div class="section">
        <h2>💾 Storage Analysis</h2>
"@

    foreach ($storage in $ReportData.StorageAnalysis) {
        $statusClass = if ($storage.UsedPercent -lt 80) { 'status-ok' } elseif ($storage.UsedPercent -lt 90) { 'status-warning' } else { 'status-critical' }
        $html += @"
        <div class="metric">
            <span>$($storage.Path):</span>
            <span class="$statusClass">$($storage.UsedGB)GB used / $($storage.TotalGB)GB total ($($storage.UsedPercent)%)</span>
        </div>
"@

        if ($storage.QueueLength -ne $null) {
            $queueClass = if ($storage.QueueLength -lt 2) { 'status-ok' } elseif ($storage.QueueLength -lt 5) { 'status-warning' } else { 'status-critical' }
            $html += @"
        <div class="metric">
            <span>Queue Length:</span>
            <span class="$queueClass">$($storage.QueueLength)</span>
        </div>
"@
        }
    }

    $html += @"
    </div>

    <div class="section">
        <h2>🌐 I/O Performance</h2>
"@

    foreach ($io in $ReportData.IOPerformance) {
        $html += @"
        <div class="metric">
            <span>$($io.Path):</span>
            <span>$($io.Type)</span>
        </div>
"@

        if ($io.ReadMBps -ne $null) {
            $readClass = if ($io.ReadMBps -gt 50) { 'status-ok' } elseif ($io.ReadMBps -gt 25) { 'status-warning' } else { 'status-critical' }
            $html += @"
        <div class="metric">
            <span>Read Performance:</span>
            <span class="$readClass">$($io.ReadMBps) MB/s</span>
        </div>
"@
        }

        if ($io.WriteMBps -ne $null) {
            $writeClass = if ($io.WriteMBps -gt 40) { 'status-ok' } elseif ($io.WriteMBps -gt 20) { 'status-warning' } else { 'status-critical' }
            $html += @"
        <div class="metric">
            <span>Write Performance:</span>
            <span class="$writeClass">$($io.WriteMBps) MB/s</span>
        </div>
"@
        }
    }

    $html += @"
    </div>

    <div class="section">
        <h2>🔄 Windows Updates</h2>
        <div class="metric">
            <span>Pending Updates:</span>
            <span class="$(if($ReportData.WindowsUpdates.Count -eq 0){'status-ok'}elseif($ReportData.WindowsUpdates.Count -lt 5){'status-warning'}else{'status-critical'})">$($ReportData.WindowsUpdates.Count)</span>
        </div>
    </div>

    <div class="section">
        <h2>📋 Recommendations</h2>
"@

    foreach ($rec in $ReportData.Recommendations) {
        $html += @"
        <div class="recommendations">
            <strong>$($rec.Priority.ToUpper()):</strong> $($rec.Message)
        </div>
"@
    }

    $html += @"
    </div>

    <div class="section">
        <h2>📊 Detailed Metrics</h2>
        <table>
            <tr>
                <th>Category</th>
                <th>Metric</th>
                <th>Value</th>
                <th>Status</th>
            </tr>
"@

    # Add detailed metrics rows
    $html += @"
            <tr>
                <td>System</td>
                <td>Active Sessions</td>
                <td>$($ReportData.Sessions.Count)</td>
                <td class="status-ok">Info</td>
            </tr>
            <tr>
                <td>System</td>
                <td>FSlogix Version</td>
                <td>$(if($ReportData.FSlogixVersion){$ReportData.FSlogixVersion}else{'Not Detected'})</td>
                <td class="$(if($ReportData.FSlogixVersion){'status-ok'}else{'status-warning'})">$(if($ReportData.FSlogixVersion){'OK'}else{'Warning'})</td>
            </tr>
            <tr>
                <td>Resources</td>
                <td>CPU Usage</td>
                <td>$($ReportData.SystemResources.CPUPercent)%</td>
                <td class="$(if($ReportData.SystemResources.CPUPercent -lt 70){'status-ok'}elseif($ReportData.SystemResources.CPUPercent -lt 90){'status-warning'}else{'status-critical'})">$(if($ReportData.SystemResources.CPUPercent -lt 70){'OK'}elseif($ReportData.SystemResources.CPUPercent -lt 90){'Warning'}else{'Critical'})</td>
            </tr>
            <tr>
                <td>Resources</td>
                <td>Memory Usage</td>
                <td>$($ReportData.SystemResources.MemoryUsedPercent)%</td>
                <td class="$(if($ReportData.SystemResources.MemoryUsedPercent -lt 80){'status-ok'}elseif($ReportData.SystemResources.MemoryUsedPercent -lt 95){'status-warning'}else{'status-critical'})">$(if($ReportData.SystemResources.MemoryUsedPercent -lt 80){'OK'}elseif($ReportData.SystemResources.MemoryUsedPercent -lt 95){'Warning'}else{'Critical'})</td>
            </tr>
            <tr>
                <td>Updates</td>
                <td>Pending Updates</td>
                <td>$($ReportData.WindowsUpdates.Count)</td>
                <td class="$(if($ReportData.WindowsUpdates.Count -eq 0){'status-ok'}elseif($ReportData.WindowsUpdates.Count -lt 5){'status-warning'}else{'status-critical'})">$(if($ReportData.WindowsUpdates.Count -eq 0){'OK'}elseif($ReportData.WindowsUpdates.Count -lt 5){'Warning'}else{'Critical'})</td>
            </tr>
"@

    $html += @"
        </table>
    </div>

    <div style="text-align: center; margin-top: 20px; color: #666; font-size: 12px;">
        <p>Report generated by Citrix VDA Diagnostics Tool</p>
        <p>For questions or support, refer to the documentation</p>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $FilePath -Encoding UTF8
    Write-Host "HTML report saved to: $FilePath" -ForegroundColor Green
}

# Function to generate CSV report
function New-CSVReport {
    param(
        [hashtable]$ReportData,
        [string]$FilePath
    )

    $csvData = @()

    # System Information
    $csvData += [PSCustomObject]@{
        Category = "System"
        Metric = "Server Name"
        Value = $ReportData.ServerName
        Status = "Info"
        Timestamp = $ReportData.Timestamp
    }

    $csvData += [PSCustomObject]@{
        Category = "System"
        Metric = "Active Sessions"
        Value = $ReportData.Sessions.Count
        Status = "Info"
        Timestamp = $ReportData.Timestamp
    }

    $fslogixValue = if($ReportData.FSlogixVersion){$ReportData.FSlogixVersion}else{"Not Detected"}
    $fslogixStatus = if($ReportData.FSlogixVersion){"OK"}else{"Warning"}

    $csvData += [PSCustomObject]@{
        Category = "System"
        Metric = "FSlogix Version"
        Value = $fslogixValue
        Status = $fslogixStatus
        Timestamp = $ReportData.Timestamp
    }

    # System Resources
    $csvData += [PSCustomObject]@{
        Category = "Resources"
        Metric = "CPU Usage %"
        Value = $ReportData.SystemResources.CPUPercent
        Status = if($ReportData.SystemResources.CPUPercent -lt 70){"OK"}elseif($ReportData.SystemResources.CPUPercent -lt 90){"Warning"}else{"Critical"}
        Timestamp = $ReportData.Timestamp
    }

    $csvData += [PSCustomObject]@{
        Category = "Resources"
        Metric = "Memory Usage %"
        Value = $ReportData.SystemResources.MemoryUsedPercent
        Status = if($ReportData.SystemResources.MemoryUsedPercent -lt 80){"OK"}elseif($ReportData.SystemResources.MemoryUsedPercent -lt 95){"Warning"}else{"Critical"}
        Timestamp = $ReportData.Timestamp
    }

    $csvData += [PSCustomObject]@{
        Category = "Resources"
        Metric = "Memory Used MB"
        Value = $ReportData.SystemResources.UsedMemoryMB
        Status = "Info"
        Timestamp = $ReportData.Timestamp
    }

    $csvData += [PSCustomObject]@{
        Category = "Resources"
        Metric = "Memory Total MB"
        Value = $ReportData.SystemResources.TotalMemoryMB
        Status = "Info"
        Timestamp = $ReportData.Timestamp
    }

    # Storage Analysis
    foreach ($storage in $ReportData.StorageAnalysis) {
        $csvData += [PSCustomObject]@{
            Category = "Storage"
            Metric = "Drive $($storage.Path)"
            Value = "$($storage.UsedGB)GB used of $($storage.TotalGB)GB ($($storage.UsedPercent)%)"
            Status = if($storage.UsedPercent -lt 80){"OK"}elseif($storage.UsedPercent -lt 90){"Warning"}else{"Critical"}
            Timestamp = $ReportData.Timestamp
        }

        if ($storage.QueueLength -ne $null) {
            $csvData += [PSCustomObject]@{
                Category = "Storage"
                Metric = "Queue Length $($storage.Path)"
                Value = $storage.QueueLength
                Status = if($storage.QueueLength -lt 2){"OK"}elseif($storage.QueueLength -lt 5){"Warning"}else{"Critical"}
                Timestamp = $ReportData.Timestamp
            }
        }
    }

    # I/O Performance
    foreach ($io in $ReportData.IOPerformance) {
        if ($io.ReadMBps -ne $null) {
            $csvData += [PSCustomObject]@{
                Category = "I/O"
                Metric = "Read Performance $($io.Path)"
                Value = "$($io.ReadMBps) MB/s"
                Status = if($io.ReadMBps -gt 50){"OK"}elseif($io.ReadMBps -gt 25){"Warning"}else{"Critical"}
                Timestamp = $ReportData.Timestamp
            }
        }

        if ($io.WriteMBps -ne $null) {
            $csvData += [PSCustomObject]@{
                Category = "I/O"
                Metric = "Write Performance $($io.Path)"
                Value = "$($io.WriteMBps) MB/s"
                Status = if($io.WriteMBps -gt 40){"OK"}elseif($io.WriteMBps -gt 20){"Warning"}else{"Critical"}
                Timestamp = $ReportData.Timestamp
            }
        }
    }

    # Windows Updates
    $csvData += [PSCustomObject]@{
        Category = "Updates"
        Metric = "Pending Updates"
        Value = $ReportData.WindowsUpdates.Count
        Status = if($ReportData.WindowsUpdates.Count -eq 0){"OK"}elseif($ReportData.WindowsUpdates.Count -lt 5){"Warning"}else{"Critical"}
        Timestamp = $ReportData.Timestamp
    }

    $csvData | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV report saved to: $FilePath" -ForegroundColor Green
}

# Function to generate JSON report
function New-JSONReport {
    param(
        [hashtable]$ReportData,
        [string]$FilePath
    )

    $ReportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $FilePath -Encoding UTF8
    Write-Host "JSON report saved to: $FilePath" -ForegroundColor Green
}

# Function to generate text report
function New-TXTReport {
    param(
        [hashtable]$ReportData,
        [string]$FilePath
    )

    $report = @"
Citrix VDA Diagnostics Report

Report Generated: $($ReportData.Timestamp)
Server: $($ReportData.ServerName)

SUMMARY
-------
Active Sessions: $($ReportData.Sessions.Count)
CPU Usage: $($ReportData.SystemResources.CPUPercent)%
Memory Usage: $($ReportData.SystemResources.MemoryUsedPercent)%
Pending Updates: $($ReportData.WindowsUpdates.Count)
FSlogix Version: $(if($ReportData.FSlogixVersion){$ReportData.FSlogixVersion}else{'Not Detected'})

SYSTEM INFORMATION
------------------
FSlogix Profile Locations: $($ReportData.ProfilePaths.Count)
"@

    if ($ReportData.ProfilePaths.Count -gt 0) {
        $report += "`nProfile Paths:"
        foreach ($path in $ReportData.ProfilePaths) {
            $report += "`n  - $path"
        }
    }

    $report += @"


SYSTEM RESOURCES
----------------
CPU Usage: $($ReportData.SystemResources.CPUPercent)% of total
Memory: $($ReportData.SystemResources.UsedMemoryMB)MB used / $($ReportData.SystemResources.TotalMemoryMB)MB total ($($ReportData.SystemResources.MemoryUsedPercent)%)
Available Memory: $($ReportData.SystemResources.AvailableMemoryMB)MB
"@

    if ($ReportData.Sessions.Count -gt 0) {
        $cpuPerUser = [math]::Round($ReportData.SystemResources.CPUPercent / $ReportData.Sessions.Count, 2)
        $memPerUser = [math]::Round($ReportData.SystemResources.UsedMemoryMB / $ReportData.Sessions.Count, 2)
        $report += "`nPer User (estimated): ${cpuPerUser}% CPU, ${memPerUser}MB RAM"
    }

    $report += @"


STORAGE ANALYSIS
----------------
"@

    foreach ($storage in $ReportData.StorageAnalysis) {
        $report += "Drive $($storage.Path):`n"
        $report += "  Usage: $($storage.UsedGB)GB used / $($storage.TotalGB)GB total ($($storage.UsedPercent)%)`n"
        $report += "  Free Space: $($storage.FreeGB)GB`n"
        if ($storage.QueueLength -ne $null) {
            $report += "  Queue Length: $($storage.QueueLength)`n"
        }
        $report += "`n"
    }

    $report += @"


I/O PERFORMANCE
---------------
"@

    foreach ($io in $ReportData.IOPerformance) {
        $report += "$($io.Path):`n"
        $report += "  Type: $($io.Type)`n"
        if ($io.ReadMBps -ne $null) {
            $report += "  Read Performance: $($io.ReadMBps) MB/s`n"
        }
        if ($io.WriteMBps -ne $null) {
            $report += "  Write Performance: $($io.WriteMBps) MB/s`n"
        }
        if ($io.TotalMBps -ne $null) {
            $report += "  Total I/O: $($io.TotalMBps) MB/s`n"
        }
        if ($io.ReadLatencyMs -ne $null) {
            $report += "  Read Latency: $($io.ReadLatencyMs) ms`n"
        }
        if ($io.WriteLatencyMs -ne $null) {
            $report += "  Write Latency: $($io.WriteLatencyMs) ms`n"
        }
        $report += "`n"
    }

    $report += @"


WINDOWS UPDATES
---------------
Pending Updates: $($ReportData.WindowsUpdates.Count)
"@

    if ($ReportData.WindowsUpdates.Updates -and $ReportData.WindowsUpdates.Updates.Count -gt 0) {
        $report += "`nRecent Updates:"
        foreach ($update in $ReportData.WindowsUpdates.Updates | Select-Object -First 5) {
            $report += "`n  - $($update.Title)"
        }
    }

    $report += @"


RECOMMENDATIONS
---------------
"@

    foreach ($rec in $ReportData.Recommendations) {
        $report += "- [$($rec.Priority.ToUpper())] $($rec.Message)`n"
    }

    $report | Out-File -FilePath $FilePath -Encoding UTF8
    Write-Host "Text report saved to: $FilePath" -ForegroundColor Green
}

# Function to export report
function Export-CitrixVDADiagnosticsReport {
    param(
        [hashtable]$ReportData,
        [string]$Format = "HTML",
        [string]$Path = ""
    )

    # Generate default filename if not provided
    if (-not $Path) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $serverName = $ReportData.ServerName -replace "[^a-zA-Z0-9]", "_"
        $Path = "CitrixVDA_Report_${serverName}_${timestamp}.$($Format.ToLower())"
    }

    # Ensure the directory exists
    $directory = Split-Path -Path $Path -Parent
    if ($directory -and -not (Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    switch ($Format) {
        "HTML" { New-HTMLReport -ReportData $ReportData -FilePath $Path }
        "CSV" { New-CSVReport -ReportData $ReportData -FilePath $Path }
        "JSON" { New-JSONReport -ReportData $ReportData -FilePath $Path }
        "TXT" { New-TXTReport -ReportData $ReportData -FilePath $Path }
        default {
            Write-Warning "Unsupported format: $Format. Using HTML."
            New-HTMLReport -ReportData $ReportData -FilePath ($Path -replace "\.[^.]*$", ".html")
        }
    }
}

# Main diagnostic function with report generation
function Run-CitrixVDADiagnostics {
    # ... existing code ...

    # Collect all diagnostic data
    $diagnosticData = @{
        ServerName = $ServerName
        Timestamp = Get-Date
        Sessions = $sessions
        FSlogixVersion = $fslogixVersion
        ProfilePaths = $profilePaths
        SystemResources = $resources
        StorageAnalysis = @()
        IOPerformance = @()
        WindowsUpdates = $windowsUpdates
        Recommendations = @()
    }

    # ... existing diagnostic code ...

    # Generate report if requested
    if ($ExportReport) {
        Write-Host "`nGenerating $ReportFormat report..." -ForegroundColor Cyan

        # Add storage analysis data
        if ($profilePaths) {
            foreach ($path in $profilePaths) {
                $driveLetter = $null
                if ($path -match "^([A-Za-z]):") {
                    $driveLetter = $matches[1]
                }

                if ($driveLetter) {
                    $storage = Get-StorageInfo -DriveLetter $driveLetter
                    $queueLength = Get-DiskQueueLength -DriveLetter $driveLetter

                    $diagnosticData.StorageAnalysis += @{
                        Path = "$driveLetter`:"
                        UsedGB = $storage.UsedGB
                        TotalGB = $storage.TotalGB
                        UsedPercent = $storage.UsedPercent
                        FreeGB = $storage.FreeGB
                        QueueLength = $queueLength
                    }
                }
            }
        }

        # Add I/O performance data
        if ($profilePaths) {
            foreach ($path in $profilePaths) {
                $ioStats = Get-FSlogixIOPerformance -Path $path
                if ($ioStats -and -not $ioStats.Error) {
                    $diagnosticData.IOPerformance += @{
                        Path = $path
                        Type = $ioStats.Type
                        ReadMBps = $ioStats.ReadMBps
                        WriteMBps = $ioStats.WriteMBps
                        TotalMBps = $ioStats.TotalMBps
                        ReadLatencyMs = $ioStats.ReadLatencyMs
                        WriteLatencyMs = $ioStats.WriteLatencyMs
                    }
                }
            }
        }

        # Add recommendations
        if ($resources -and $userCount -gt 0) {
            $cpuPerUser = $resources.CPUPercent / $userCount
            if ($cpuPerUser -gt 80) {
                $diagnosticData.Recommendations += @{
                    Priority = "High"
                    Message = "High CPU usage per user (${cpuPerUser}%). Consider adding more CPU cores or reducing user load."
                }
            }

            $memoryPerUserMB = $resources.UsedMemoryMB / $userCount
            if ($memoryPerUserMB -gt 1024) {
                $diagnosticData.Recommendations += @{
                    Priority = "High"
                    Message = "High memory usage per user (${memoryPerUserMB}MB). Consider adding more RAM or optimizing applications."
                }
            }
        }

        if ($windowsUpdates.Count -gt 0) {
            $diagnosticData.Recommendations += @{
                Priority = if($windowsUpdates.Count -gt 10){"High"}else{"Medium"}
                Message = "$($windowsUpdates.Count) Windows updates pending. Schedule maintenance window for updates."
            }
        }

        # Export the report
        Export-CitrixVDADiagnosticsReport -ReportData $diagnosticData -Format $ReportFormat -Path $ReportPath
    }

    Write-Host "`n=== Diagnostics Complete ===" -ForegroundColor Cyan
}

# Run the diagnostics
Run-CitrixVDADiagnostics
