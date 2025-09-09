# Citrix VDA Diagnostics Tool
# Diagnoses disk queue length, storage space, CPU, and RAM usage for Citrix VDA servers with FSlogix

param(
    [string]$ServerName = $env:COMPUTERNAME,
    [switch]$Verbose
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

# Run the diagnostics
Run-CitrixVDADiagnostics
