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
            $driveLetter = $path.Substring(0, 1)
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
            $driveLetter = $path.Substring(0, 1)
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

    Write-Host ""
    Write-Host "=== Diagnostics Complete ===" -ForegroundColor Cyan
}

# Run the diagnostics
Run-CitrixVDADiagnostics
