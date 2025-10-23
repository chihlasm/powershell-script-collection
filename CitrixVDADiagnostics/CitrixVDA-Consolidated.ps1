# Citrix VDA Consolidated Diagnostics Script
# Combination of CitrixVDADiagnostics.ps1 and CitrixFSLogix-AdvancedDiagnostics.ps1

param(
    [string]$ServerName = $env:COMPUTERNAME,
    [switch]$FullScan,
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

# Function to get FSlogix basic configuration
function Get-FSLogixProfilePaths {
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
function Get-FSLogixVersion {
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

# Function to check for Citrix Virtual Apps and Desktops installation
function Get-CitrixVADVersion {
    try {
        # Check for Citrix Virtual Apps and Desktops in registry
        $citrixDeliveryKey = "HKLM:\SOFTWARE\Citrix\DeliveryServices"
        if (Test-Path $citrixDeliveryKey) {
            $version = Get-ItemProperty -Path $citrixDeliveryKey -Name "DisplayVersion" -ErrorAction SilentlyContinue
            if ($version.DisplayVersion) {
                return @{
                    Installed = $true
                    Version = $version.DisplayVersion
                    Product = "Citrix Virtual Apps and Desktops"
                }
            }
        }

        # Check for Citrix Receiver or Workspace App (common on VDA servers)
        $citrixReceiverKey = "HKLM:\SOFTWARE\Citrix\Receiver"
        if (Test-Path $citrixReceiverKey) {
            $version = Get-ItemProperty -Path $citrixReceiverKey -Name "DisplayVersion" -ErrorAction SilentlyContinue
            if ($version.DisplayVersion) {
                return @{
                    Installed = $true
                    Version = $version.DisplayVersion
                    Product = "Citrix Receiver"
                }
            }
        }

        # Check for Citrix ICA Client
        $citrixICAKey = "HKLM:\SOFTWARE\Citrix\ICA Client"
        if (Test-Path $citrixICAKey) {
            $version = Get-ItemProperty -Path $citrixICAKey -Name "DisplayVersion" -ErrorAction SilentlyContinue
            if ($version.DisplayVersion) {
                return @{
                    Installed = $true
                    Version = $version.DisplayVersion
                    Product = "Citrix ICA Client"
                }
            }
        }

        # Check installed programs for Citrix products
        $citrixApp = Get-WmiObject -Class Win32_Product | Where-Object {
            $_.Name -like "*Citrix*" -and (
                $_.Name -match "Virtual Apps and Desktops|Virtual Delivery Agent|Receiver|Workspace|ICA"
            )
        } | Select-Object -First 1

        if ($citrixApp) {
            return @{
                Installed = $true
                Version = $citrixApp.Version
                Product = $citrixApp.Name
            }
        }

        return @{
            Installed = $false
            Version = $null
            Product = $null
        }
    }
    catch {
        Write-Warning "Could not check for Citrix VAD installation: $_"
        return @{
            Installed = $false
            Version = $null
            Product = $null
        }
    }
}

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

# Function to check FSLogix VHDX file health
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

# Function to get system resources (CPU/RAM usage)
function Get-SystemResources {
    try {
        # CPU Usage
        $cpuCounter = Get-Counter -Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 1
        $cpuPercent = [math]::Round($cpuCounter.CounterSamples.CookedValue, 2)

        # Memory Usage - Use physical memory for accurate RAM calculation
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $totalMemoryBytes = $osInfo.TotalVisibleMemorySize * 1KB  # Convert to bytes
        $freeMemoryBytes = $osInfo.FreePhysicalMemory * 1KB       # Convert to bytes
        $usedMemoryBytes = $totalMemoryBytes - $freeMemoryBytes

        $totalMB = [math]::Round($totalMemoryBytes / 1MB, 2)
        $usedMB = [math]::Round($usedMemoryBytes / 1MB, 2)
        $availableMB = [math]::Round($freeMemoryBytes / 1MB, 2)
        $usedPercent = [math]::Round(($usedMB / $totalMB) * 100, 2)

        return @{
            CPUPercent = $cpuPercent
            TotalMemoryMB = $totalMB
            UsedMemoryMB = $usedMB
            AvailableMemoryMB = $availableMB
            MemoryUsedPercent = $usedPercent
        }
    }
    catch {
        Write-Warning "Could not get system resource information: $_"
        return $null
    }
}

# Function to get top processes by CPU and RAM usage (enhanced version)
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

# Function to test network connectivity
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

# Function to get FSLogix performance counters
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

# Function to check FSLogix registry configuration
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

# Main consolidated diagnostic function
function Run-CitrixVDAConsolidatedDiagnostics {
    Write-Host "Citrix VDA Consolidated Diagnostics" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host "Server: $ServerName" -ForegroundColor Cyan
    Write-Host "Timestamp: $(Get-Date)" -ForegroundColor Cyan
    Write-Host ""

    # Initialize diagnostic data
    $diagnosticData = @{
        ServerName = $ServerName
        Timestamp = Get-Date
        Sessions = @()
        FSlogixVersion = $null
        CitrixVADInfo = $null
        ProfilePaths = @()
        Services = @()
        ProfileHealth = @()
        EventLogs = @()
        NetworkConnectivity = @()
        RegistryHealth = @()
        SystemResources = $null
        ProcessUsage = $null
        StorageAnalysis = @()
        IOPerformance = @()
        WindowsUpdates = @()
        PerformanceCounters = $null
        Recommendations = @()
    }

    # Get basic Citrix and FSlogix info
    $sessions = Get-CitrixSessions
    $diagnosticData.Sessions = $sessions
    $userCount = if ($sessions) { $sessions.Count } else { 0 }

    Write-Host "Active Sessions: $userCount" -ForegroundColor Yellow
    if ($Verbose) {
        $sessions | ForEach-Object { Write-Host "  - $($_.UserName)" }
    }
    Write-Host ""

    # Get FSlogix version and paths
    $fslogixVersion = Get-FSLogixVersion
    $diagnosticData.FSlogixVersion = $fslogixVersion
    $profilePaths = Get-FSLogixProfilePaths
    $diagnosticData.ProfilePaths = $profilePaths

    # Get Citrix VAD information
    $citrixVADInfo = Get-CitrixVADVersion
    $diagnosticData.CitrixVADInfo = $citrixVADInfo

    Write-Host "=== Software Information ===" -ForegroundColor Cyan

    Write-Host "Citrix Virtual Apps & Desktops:" -ForegroundColor Yellow
    if ($citrixVADInfo.Installed) {
        Write-Host "  - Product: $($citrixVADInfo.Product)" -ForegroundColor Green
        Write-Host "  - Version: $($citrixVADInfo.Version)" -ForegroundColor Green
    } else {
        Write-Host "  - Not detected on this system" -ForegroundColor Red
    }

    Write-Host "FSlogix Version:" -ForegroundColor Yellow
    if ($fslogixVersion) {
        Write-Host "  - $fslogixVersion" -ForegroundColor Green
    } else {
        Write-Host "  - FSlogix not detected or version unknown" -ForegroundColor Red
    }

    Write-Host "Profile Locations:" -ForegroundColor Yellow
    if ($profilePaths -and $profilePaths.Count -gt 0) {
        foreach ($path in $profilePaths) {
            Write-Host "  - $path" -ForegroundColor Green
        }
    } else {
        Write-Host "  - No profile locations configured" -ForegroundColor Red
    }
    Write-Host ""

    # FSlogix services
    Write-Host "FSlogix Services:" -ForegroundColor Yellow
    $services = Get-FSLogixServiceStatus
    $diagnosticData.Services = $services
    foreach ($service in $services) {
        $color = if ($service.IsRunning) { "Green" } elseif ($service.Exists) { "Yellow" } else { "Red" }
        Write-Host "  $($service.ServiceName): $($service.Status)" -ForegroundColor $color
    }
    Write-Host ""

    # VHD health check
    Write-Host "Profile Health:" -ForegroundColor Yellow
    $profileHealth = Get-FSLogixProfileHealth
    $diagnosticData.ProfileHealth = $profileHealth
    foreach ($profile in $profileHealth) {
        $color = if ($profile.CorruptVHDs -eq 0) { "Green" } else { "Red" }
        Write-Host "  $($profile.Location): $($profile.Status)" -ForegroundColor $color
        if ($Verbose -or $profile.VHDCount -gt 0) {
            Write-Host "    VHDs: $(($profile.VHDCount)) Total: $($profile.TotalSizeGB)GB Healthy: $($profile.HealthyVHDs) Corrupt: $($profile.CorruptVHDs)" -ForegroundColor Blue
        }
    }
    Write-Host ""

    # Event log analysis
    Write-Host "Event Log Analysis:" -ForegroundColor Yellow
    $eventLogs = Get-EventLogAnalysis
    $diagnosticData.EventLogs = $eventLogs
    foreach ($event in $eventLogs) {
        $color = if ($event.Errors -eq 0 -and $event.Warnings -eq 0) { "Green" } elseif ($event.Errors -gt 0) { "Red" } else { "Yellow" }
        Write-Host "  $($event.Source): $($event.Status) ($($event.TotalEvents) events)" -ForegroundColor $color
    }
    Write-Host ""

    # Network connectivity
    Write-Host "Network Connectivity:" -ForegroundColor Yellow
    $networkConnectivity = Test-NetworkConnectivity
    $diagnosticData.NetworkConnectivity = $networkConnectivity
    foreach ($conn in $networkConnectivity) {
        $color = if ($conn.Status -eq "OK") { "Green" } elseif ($conn.PingSuccess) { "Yellow" } else { "Red" }
        Write-Host "  $($conn.Server)\$($conn.Share): $($conn.Status)" -ForegroundColor $color
    }
    Write-Host ""

    # Registry configuration
    Write-Host "Registry Configuration:" -ForegroundColor Yellow
    $registryHealth = Get-FSLogixRegistryHealth
    $diagnosticData.RegistryHealth = $registryHealth
    foreach ($reg in $registryHealth) {
        $color = if ($reg.Exists) { "Green" } else { "Yellow" }
        Write-Host "  $($reg.RegistryKey): $($reg.Status)" -ForegroundColor $color
    }
    Write-Host ""

    # System resources
    Write-Host "System Resources:" -ForegroundColor Yellow
    $resources = Get-SystemResources
    $diagnosticData.SystemResources = $resources
    if ($resources) {
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

    # Process usage
    Write-Host "Top Process Usage:" -ForegroundColor Yellow
    $processUsage = Get-TopProcessUsage
    $diagnosticData.ProcessUsage = $processUsage
    Write-Host "  Top CPU processes collected: $($processUsage.TopCPUProcesses.Count)" -ForegroundColor Green
    Write-Host "  Top RAM processes collected: $($processUsage.TopRAMProcesses.Count)" -ForegroundColor Green
    Write-Host ""

    # Storage and I/O analysis - analyze local drives if no profile paths or all configured drives
    Write-Host "Storage and I/O Analysis:" -ForegroundColor Yellow

    # Get all local drives to analyze
    $drivesToAnalyze = @{}

    # First, add FSLogix profile drives if configured
    if ($profilePaths) {
        foreach ($path in $profilePaths) {
            # Extract drive letter properly - handle both local drives and UNC paths
            $driveLetter = $null
            if ($path -match "^([A-Za-z]):") {
                # Local drive (e.g., "C:\path\to\profiles")
                $driveLetter = $matches[1]
                $drivesToAnalyze[$driveLetter] = $true
            }
            elseif ($path -match "^\\\\([^\\]+)\\([^\\]+)") {
                # UNC path (e.g., "\\server\share\profiles")
                Write-Host "  UNC Path: $path" -ForegroundColor Cyan
                Write-Host "    Note: UNC paths are not analyzed for local disk metrics" -ForegroundColor Yellow
                continue
            }
        }
    }

    # If no profile drives or we want all drives, analyze all local volumes
    if ($drivesToAnalyze.Count -eq 0) {
        try {
            $volumes = Get-Volume | Where-Object { $_.DriveLetter -and $_.FileSystem -in @('NTFS', 'ReFS') }
            foreach ($volume in $volumes) {
                $drivesToAnalyze[$volume.DriveLetter] = $true
            }
        }
        catch {
            Write-Host "  Warning: Could not retrieve drive information: $_" -ForegroundColor Yellow
        }
    }

    # Analyze each drive
    foreach ($driveLetter in $drivesToAnalyze.Keys | Sort-Object) {
        Write-Host "  Drive ${driveLetter}:" -ForegroundColor Cyan

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

            # Add to diagnostic data for reports
            $diagnosticData.StorageAnalysis += @{
                Path = "${driveLetter}:"
                UsedGB = $storage.UsedGB
                TotalGB = $storage.TotalGB
                UsedPercent = $storage.UsedPercent
                FreeGB = $storage.FreeGB
                QueueLength = $queueLength
            }
        }
        Write-Host ""
    }

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

                # Add to diagnostic data
                if (-not $ioStats.Error) {
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
            else {
                Write-Host "    No performance data available" -ForegroundColor Yellow
            }
            Write-Host ""
        }
    }

    # Windows Updates
    Write-Host "Windows Updates:" -ForegroundColor Yellow
    $windowsUpdates = Get-PendingWindowsUpdates
    $diagnosticData.WindowsUpdates = $windowsUpdates
    if ($windowsUpdates.Count -eq -1) {
        Write-Host "  - Could not check for updates: $($windowsUpdates.Error)" -ForegroundColor Red
    }
    elseif ($windowsUpdates.Count -eq 0) {
        Write-Host "  - All updates are current" -ForegroundColor Green
    }
    else {
        Write-Host "  - $($windowsUpdates.Count) pending updates" -ForegroundColor $(if ($windowsUpdates.Count -gt 10) { "Red" } elseif ($windowsUpdates.Count -gt 5) { "Yellow" } else { "Green" })

        # Show update details
        if ($windowsUpdates.Updates -and $windowsUpdates.Updates.Count -gt 0) {
            $criticalCount = ($windowsUpdates.Updates | Where-Object { $_.IsCritical }).Count
            if ($criticalCount -gt 0) {
                Write-Host "  - $criticalCount critical security updates pending" -ForegroundColor Red
            }
            $securityCount = ($windowsUpdates.Updates | Where-Object { $_.Title -match "(Security|KB\d{7})" }).Count
            if ($securityCount -gt 0) {
                Write-Host "  - $securityCount security/hotfix updates" -ForegroundColor $(if ($securityCount -gt 5) { "Red" } else { "Yellow" })
            }

            # Show first few update titles if verbose
            if ($Verbose) {
                Write-Host "  Top pending updates:" -ForegroundColor Cyan
                $windowsUpdates.Updates | Select-Object -First 3 | ForEach-Object {
                    $updateType = if ($_.IsCritical) { "[CRITICAL]" } elseif ($_.Title -match "Security") { "[SECURITY]" } else { "[UPDATE]" }
                    $kb = if ($_.KB) { " - $($_.KB)" } else { "" }
                    Write-Host "    $updateType $($_.Title)$kb" -ForegroundColor $(if ($_.IsCritical) { "Red" } elseif ($_.Title -match "Security") { "Red" } else { "Yellow" })
                }
                if ($windowsUpdates.Count -gt 3) {
                    Write-Host "    ... and $($windowsUpdates.Count - 3) more updates" -ForegroundColor Yellow
                }
            } else {
                Write-Host "  Use -Verbose to see detailed update list" -ForegroundColor Blue
            }
        }
    }
    Write-Host ""

    # Performance counters if FullScan
    if ($FullScan) {
        Write-Host "Performance Counters (Full Scan):" -ForegroundColor Yellow
        $perfCounters = Get-FSLogixPerformanceCounters
        $diagnosticData.PerformanceCounters = $perfCounters
        foreach ($counter in $perfCounters) {
            Write-Host "  $($counter.CounterSet): $($counter.Status)" -ForegroundColor Blue
        }
        Write-Host ""
    }

    # Generate recommendations
    Write-Host "Recommendations:" -ForegroundColor Yellow
    $recommendations = @()

    # Service-related recommendations
    if ($diagnosticData.Services | Where-Object { -not $_.IsRunning -and $_.Exists }) {
        $recommendations += "Start required FSLogix services that are stopped"
    }

    # Profile health recommendations
    if ($diagnosticData.ProfileHealth | Where-Object { $_.CorruptVHDs -gt 0 }) {
        $recommendations += "Investigate and repair or recover corrupt VHD files"
        if ($Verbose) {
            $recommendations += "<strong>Potential causes of VHDX corruption:</strong>"
            $recommendations += "- Network connectivity interruptions during profile operations"
            $recommendations += "- Disk space exhaustion on storage servers"
            $recommendations += "- Sudden server restarts or power losses"
            $recommendations += "- Antivirus software interfering with VHDX files"
            $recommendations += "- Hardware failures in storage controllers or disks"
            $recommendations += "- Concurrent access conflicts from multiple sessions"
        }
    }

    # Event log recommendations
    if ($diagnosticData.EventLogs | Where-Object { $_.Errors -gt 0 }) {
        $recommendations += "Review event logs for error details and take corrective action"
    }

    # Network recommendations
    if ($diagnosticData.NetworkConnectivity | Where-Object { -not $_.ShareAccessible }) {
        $recommendations += "Fix network connectivity issues to profile shares"
    }

    # Resource recommendations
    if ($resources -and $userCount -gt 0) {
        $cpuPerUser = $resources.CPUPercent / $userCount
        if ($cpuPerUser -gt 80) {
            $recommendations += "High CPU usage per user (${cpuPerUser}%). Consider adding more CPU cores or reducing user load."
        }

        $memoryPerUserMB = $resources.UsedMemoryMB / $userCount
        if ($memoryPerUserMB -gt 1024) { # 1GB per user
            $recommendations += "High memory usage per user (${memoryPerUserMB}MB). Consider adding more RAM or optimizing applications."
        }
    }

    # Storage recommendations - check all analyzed drives
    foreach ($storageData in $diagnosticData.StorageAnalysis) {
        $driveLetter = $storageData.Path.TrimEnd(':')

        if ($storageData.QueueLength -gt 2) {
            $recommendations += "High disk queue length on $driveLetter ($($storageData.QueueLength)). Consider faster storage or distributing data across multiple drives."
        }

        if ($storageData.UsedPercent -gt 85) {
            $recommendations += "Low free space on $driveLetter ($($storageData.UsedPercent)% used, $($storageData.FreeGB)GB free). Clean up unnecessary files or add storage capacity."
        }

        if ($storageData.UsedPercent -gt 95) {
            $recommendations += "CRITICAL: Extremely low free space on $driveLetter ($($storageData.UsedPercent)% used). Immediate action required to prevent system issues."        }
    }

    # Update recommendations
    if ($windowsUpdates.Count -gt 0) {
        $recommendations += "$($windowsUpdates.Count) Windows updates pending. Schedule maintenance window for updates."
    }

    $diagnosticData.Recommendations = $recommendations

    # Display recommendations
    if ($recommendations.Count -eq 0) {
        Write-Host "  - All systems appear healthy" -ForegroundColor Green
    } else {
        foreach ($rec in $recommendations) {
            $color = if ($rec -match "(corrupt|high|low|fix|investigate)" -or $rec -match "updates pending") { "Red" } elseif ($rec -match "warning" -or $rec -match "review") { "Yellow" } else { "Magenta" }
            Write-Host "  - $rec" -ForegroundColor $color
        }
    }
    Write-Host ""

    # Generate report if requested
    if ($ExportReport) {
        Write-Host "`nGenerating $ReportFormat report..." -ForegroundColor Cyan
        Export-CitrixVDAConsolidatedReport -ReportData $diagnosticData -Format $ReportFormat -Path $ReportPath
    }

    Write-Host ""
    Write-Host "=== Consolidated Diagnostics Complete ===" -ForegroundColor Cyan
}

# Unified report generation functions

# Function to generate consolidated HTML report
function New-ConsolidatedHTMLReport {
    param(
        [hashtable]$ReportData,
        [string]$FilePath
    )

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Citrix VDA Consolidated Diagnostics Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .section { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .status-ok { color: #28a745; font-weight: bold; }
        .status-warning { color: #ffc107; font-weight: bold; }
        .status-critical { color: #dc3545; font-weight: bold; }
        .metric { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #eee; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: bold; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .summary-item { background: white; padding: 15px; border-radius: 6px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .summary-value { font-size: 24px; font-weight: bold; color: #333; }
        .summary-label { color: #666; font-size: 14px; }
        .recommendation { background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Citrix VDA Consolidated Diagnostics Report</h1>
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
        <h2>System Information</h2>
        <div class="metric">
            <span>Citrix Virtual Apps & Desktops:</span>
            <span class="$(if($ReportData.CitrixVADInfo.Installed){'status-ok'}else{'status-warning'})">
                $(if($ReportData.CitrixVADInfo.Installed){
                    "$($ReportData.CitrixVADInfo.Product) - v$($ReportData.CitrixVADInfo.Version)"
                }else{
                    'Not Detected'
                })
            </span>
        </div>
        <div class="metric">
            <span>FSlogix Version:</span>
            <span class="$(if($ReportData.FSlogixVersion){'status-ok'}else{'status-warning'})">$(if($ReportData.FSlogixVersion){$ReportData.FSlogixVersion}else{'Not Detected'})</span>
        </div>
        <div class="metric">
            <span>Profile Locations:</span>
            <span>$($ReportData.ProfilePaths.Count) configured</span>
        </div>
"@

    if ($ReportData.ProfilePaths -and $ReportData.ProfilePaths.Count -gt 0) {
        $html += @"
        <h3>Profile Paths:</h3>
        <ul>
"@

        foreach ($path in $ReportData.ProfilePaths) {
            $html += "<li>$path</li>"
        }

        $html += @"
        </ul>
"@

    }

    $html += @"
    </div>

    <div class="section">
        <h2>FSLogix Services</h2>
        <table>
            <tr><th>Service</th><th>Status</th><th>Start Type</th><th>State</th></tr>
"@

    foreach ($service in $ReportData.Services) {
        $statusClass = if ($service.IsRunning) { "status-ok" } elseif ($service.Exists) { "status-warning" } else { "status-critical" }
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

    foreach ($profile in $ReportData.ProfileHealth) {
        $statusClass = if ($profile.CorruptVHDs -eq 0) { "status-ok" } else { "status-critical" }
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

    foreach ($event in $ReportData.EventLogs) {
        $statusClass = if ($event.Errors -eq 0 -and $event.Warnings -eq 0) { "status-ok" } elseif ($event.Errors -gt 0) { "status-critical" } else { "status-warning" }
        $html += "<tr><td>$($event.Source)</td><td>$($event.TotalEvents)</td><td>$($event.Errors)</td><td>$($event.Warnings)</td><td class='$statusClass'>$($event.Status)</td></tr>"
    }

    $html += @"
        </table>
    </div>

    <div class="section">
        <h2>Network Connectivity</h2>
        <table>
            <tr><th>Server</th><th>Share</th><th>Ping</th><th>Share Access</th><th>Status</th></tr>
"@

    foreach ($conn in $ReportData.NetworkConnectivity) {
        $statusClass = if ($conn.Status -eq "OK") { "status-ok" } elseif ($conn.Status -like "*Inaccessible*") { "status-warning" } else { "status-critical" }
        $html += "<tr><td>$($conn.Server)</td><td>$($conn.Share)</td><td>$($conn.PingSuccess)</td><td>$($conn.ShareAccessible)</td><td class='$statusClass'>$($conn.Status)</td></tr>"
    }

    $html += @"
        </table>
    </div>

    <div class="section">
        <h2>System Resources</h2>
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
        <h2>Storage Analysis</h2>
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
        <h2>I/O Performance</h2>
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
        <h2>Windows Updates</h2>
        <div class="metric">
            <span>Pending Updates:</span>
            <span class="$(if($ReportData.WindowsUpdates.Count -eq 0){'status-ok'}elseif($ReportData.WindowsUpdates.Count -lt 5){'status-warning'}else{'status-critical'})">$($ReportData.WindowsUpdates.Count)</span>
        </div>
"@

    if ($ReportData.WindowsUpdates.Updates -and $ReportData.WindowsUpdates.Updates.Count -gt 0) {
        $html += @"
        <h3>Update Details</h3>
        <table>
            <tr><th>Update Type</th><th>Title</th><th>KB Number</th></tr>
"@

        foreach ($update in $ReportData.WindowsUpdates.Updates | Select-Object -First 10) {
            $updateType = if ($update.IsCritical) { "Critical" } elseif ($update.Title -match "Security") { "Security" } else { "Update" }
            $typeClass = if ($update.IsCritical) { "status-critical" } elseif ($update.Title -match "Security") { "status-critical" } else { "status-ok" }
            $html += "<tr><td class='$typeClass'>$updateType</td><td>$($update.Title)</td><td>$($update.KB)</td></tr>"
        }

        $html += @"
        </table>
"@
        if ($ReportData.WindowsUpdates.Count -gt 10) {
            $html += "<p>... and $($ReportData.WindowsUpdates.Count - 10) more updates</p>"
        }
    }

    $html += @"
    </div>

    <div class="section">
        <h2>Recommendations</h2>
"@

    foreach ($rec in $ReportData.Recommendations) {
        $html += @"
        <div class="recommendation">
            $rec
        </div>
"@

    }

    $html += @"
    </div>

    <div style="text-align: center; margin-top: 20px; color: #666; font-size: 12px;">
        <p>Report generated by Citrix VDA Consolidated Diagnostics Tool</p>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $FilePath -Encoding UTF8
    Write-Host "Consolidated HTML report saved to: $FilePath" -ForegroundColor Green
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

    # FSLogix Services
    foreach ($service in $ReportData.Services) {
        $csvData += [PSCustomObject]@{
            Category = "Services"
            Metric = $service.ServiceName
            Value = "$($service.Status) ($($service.StartType))"
            Status = if($service.IsRunning){"OK"}elseif($service.Exists){"Warning"}else{"Critical"}
            Timestamp = $ReportData.Timestamp
        }
    }

    # Profile Health
    foreach ($profile in $ReportData.ProfileHealth) {
        $csvData += [PSCustomObject]@{
            Category = "Profile Health"
            Metric = $profile.Location
            Value = "VHDs: $($profile.VHDCount), Size: $($profile.TotalSizeGB)GB, Healthy: $($profile.HealthyVHDs), Corrupt: $($profile.CorruptVHDs)"
            Status = if($profile.CorruptVHDs -eq 0){"OK"}else{"Critical"}
            Timestamp = $ReportData.Timestamp
        }
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
Citrix VDA Consolidated Diagnostics Report

Report Generated: $($ReportData.Timestamp)
Server: $($ReportData.ServerName)

SUMMARY
-------
Active Sessions: $($ReportData.Sessions.Count)
CPU Usage: $($ReportData.SystemResources.CPUPercent)%
Memory Usage: $($ReportData.SystemResources.MemoryUsedPercent)%
FSlogix Version: $(if($ReportData.FSlogixVersion){$ReportData.FSlogixVersion}else{'Not Detected'})
Pending Updates: $($ReportData.WindowsUpdates.Count)

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


FSLOGIX SERVICES
----------------
"@

    foreach ($service in $ReportData.Services) {
        $report += "$($service.ServiceName): $($service.Status) ($($service.StartType))`n"
    }

    $report += @"


PROFILE HEALTH
--------------
"@

    foreach ($profile in $ReportData.ProfileHealth) {
        $report += "$($profile.Location):`n"
        $report += "  VHDs: $($profile.VHDCount) Total: $($profile.TotalSizeGB)GB`n"
        $report += "  Healthy: $($profile.HealthyVHDs) Corrupt: $($profile.CorruptVHDs)`n"
        $report += "  Status: $($profile.Status)`n`n"
    }

    $report += @"


EVENT LOG ANALYSIS
------------------
"@

    foreach ($event in $ReportData.EventLogs) {
        $report += "$($event.Source): $($event.Status) ($($event.TotalEvents) events, $($event.Errors) errors, $($event.Warnings) warnings)`n"
    }

    $report += @"


NETWORK CONNECTIVITY
--------------------
"@

    foreach ($conn in $ReportData.NetworkConnectivity) {
        $report += "$($conn.Server)\$($conn.Share): $($conn.Status)`n"
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
        $report += "- $rec`n"
    }

    $report | Out-File -FilePath $FilePath -Encoding UTF8
    Write-Host "Text report saved to: $FilePath" -ForegroundColor Green
}

# Function to export consolidated report
function Export-CitrixVDAConsolidatedReport {
    param(
        [hashtable]$ReportData,
        [string]$Format = "HTML",
        [string]$Path = ""
    )

    # Generate default filename if not provided
    if (-not $Path) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $serverName = $ReportData.ServerName -replace "[^a-zA-Z0-9]", "_"
        $Path = "CitrixVDA_Consolidated_Report_${serverName}_${timestamp}.$($Format.ToLower())"
    }

    # Ensure the directory exists
    $directory = Split-Path -Path $Path -Parent
    if ($directory -and -not (Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    switch ($Format) {
        "HTML" { New-ConsolidatedHTMLReport -ReportData $ReportData -FilePath $Path }
        "CSV" { New-CSVReport -ReportData $ReportData -FilePath $Path }
        "JSON" { New-JSONReport -ReportData $ReportData -FilePath $Path }
        "TXT" { New-TXTReport -ReportData $ReportData -FilePath $Path }
        default {
            Write-Warning "Unsupported format: $Format. Using HTML."
            New-ConsolidatedHTMLReport -ReportData $ReportData -FilePath ($Path -replace "\.[^.]*$", ".html")
        }
    }
}

# Run the diagnostics
Run-CitrixVDAConsolidatedDiagnostics
