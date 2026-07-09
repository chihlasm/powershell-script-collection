#Requires -Version 5.1

<#
.SYNOPSIS
    Runs a read-only Citrix and FSLogix triage check.

.DESCRIPTION
    Collects target reachability, FSLogix service state, FSLogix profile
    registry configuration, recent FSLogix and Terminal Services events, local
    fixed disk free space, and configured profile path reachability evidence.
    Remote queries use the named affected device through ComputerName-aware
    cmdlets or a remote registry base key. Blocked remote access is reported as
    Warn evidence and does not stop the rest of the check.

.PARAMETER AffectedDevice
    Server or workstation to inspect. Defaults to the local computer when the
    script is run standalone.

.PARAMETER AffectedUser
    Optional user name involved in the reported profile issue. Used only for
    context and simple profile path token replacement before path reachability
    is checked from the affected device context.

.PARAMETER EventLookbackHours
    Number of hours of FSLogix and Terminal Services events to collect.
    Defaults to 24.

.EXAMPLE
    .\Invoke-CitrixFSLogixTriageCheck.ps1 -AffectedDevice RDSH01 -AffectedUser jdoe

.NOTES
    Returns the shared MSP Troubleshooting Workbench check result object. This
    check is read-only and avoids MSI inventory queries.
#>
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$AffectedDevice = $env:COMPUTERNAME,

    [string]$AffectedUser = "",

    [ValidateRange(1, 168)]
    [int]$EventLookbackHours = 24
)

function New-EvidenceItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet("Pass", "Warn", "Fail")]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Detail
    )

    [PSCustomObject]@{
        Name   = $Name
        Status = $Status
        Detail = $Detail
    }
}

function ConvertTo-StringArray {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return @()
    }

    if ($Value -is [System.Array]) {
        $items = @()
        foreach ($item in @($Value)) {
            if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace([string]$item)) {
                $items += [string]$item
            }
        }

        return @($items)
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return @()
    }

    return @($text)
}

function ConvertTo-ProfilePathForTest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [string]$UserName
    )

    $resolvedPath = $Path
    if (-not [string]::IsNullOrWhiteSpace($UserName)) {
        $resolvedPath = [regex]::Replace($resolvedPath, '(?i)%username%', { param($Match) $UserName })
        $resolvedPath = [regex]::Replace($resolvedPath, '(?i)#username#', { param($Match) $UserName })
    }

    return $resolvedPath
}

function Test-IsLocalComputerTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    $normalized = $ComputerName.Trim()
    return (
        $normalized -eq "." -or
        $normalized -eq "localhost" -or
        $normalized -eq "127.0.0.1" -or
        $normalized -eq "::1" -or
        $normalized -ieq $env:COMPUTERNAME
    )
}

function Read-FSLogixProfileRegistryKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey]$LocalMachine,

        [Parameter(Mandatory)]
        [string]$SubKeyPath,

        [Parameter(Mandatory)]
        [string]$Label
    )

    $key = $null
    try {
        $key = $LocalMachine.OpenSubKey($SubKeyPath)
        if ($null -eq $key) {
            return [PSCustomObject]@{
                Label = $Label
                Path  = ("HKLM:\{0}" -f $SubKeyPath)
                Found = $false
                Error = ""
            }
        }

        $values = [ordered]@{}
        foreach ($valueName in @($key.GetValueNames())) {
            $value = $key.GetValue($valueName)
            if ($value -is [System.Array]) {
                $values[$valueName] = ((ConvertTo-StringArray -Value $value) -join "; ")
            }
            elseif ($null -eq $value) {
                $values[$valueName] = ""
            }
            else {
                $values[$valueName] = [string]$value
            }
        }

        return [PSCustomObject]@{
            Label = $Label
            Path  = ("HKLM:\{0}" -f $SubKeyPath)
            Found = $true
            Error = ""
            Values = [PSCustomObject]$values
        }
    }
    catch {
        return [PSCustomObject]@{
            Label = $Label
            Path  = ("HKLM:\{0}" -f $SubKeyPath)
            Found = $false
            Error = $_.Exception.Message
        }
    }
    finally {
        if ($null -ne $key) {
            $key.Close()
        }
    }
}

function Get-RegistryValueText {
    [CmdletBinding()]
    param(
        [object[]]$RegistryKeys,

        [Parameter(Mandatory)]
        [string]$ValueName
    )

    foreach ($registryKey in @($RegistryKeys)) {
        if ($registryKey.Found -and $registryKey.PSObject.Properties.Name -contains "Values") {
            if ($registryKey.Values.PSObject.Properties.Name -contains $ValueName) {
                return [string]$registryKey.Values.$ValueName
            }
        }
    }

    return ""
}

function New-CitrixFSLogixResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Pass", "Warn", "Fail")]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Summary,

        [object[]]$Evidence,

        [string[]]$RecommendedNextSteps,

        [object]$RawOutput,

        [string]$StartedAt,

        [string[]]$Errors
    )

    [PSCustomObject]@{
        CheckId              = "citrix.fslogix.triage"
        Name                 = "Citrix/FSLogix Triage"
        Category             = "Citrix"
        Status               = $Status
        Summary              = $Summary
        Evidence             = @($Evidence)
        RecommendedNextSteps = @($RecommendedNextSteps)
        RawOutput            = $RawOutput
        StartedAt            = $StartedAt
        FinishedAt           = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Error                = (@($Errors) -join "; ")
    }
}

$startedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$AffectedDevice = $AffectedDevice.Trim()
$AffectedUser = $AffectedUser.Trim()
$eventStartTime = (Get-Date).AddHours(-1 * $EventLookbackHours)
$evidence = @()
$errors = @()

$rawOutput = [ordered]@{
    AffectedDevice     = $AffectedDevice
    AffectedUser       = $AffectedUser
    EventLookbackHours = $EventLookbackHours
    Reachability       = @()
    Services           = @()
    Registry           = @()
    Events             = @()
    Disks              = @()
    ProfilePaths       = @()
}

try {
    $reachable = Test-Connection -ComputerName $AffectedDevice -Count 1 -Quiet -ErrorAction Stop
    $rawOutput.Reachability += [PSCustomObject]@{
        Target    = $AffectedDevice
        Succeeded = [bool]$reachable
        Error     = ""
    }

    if ($reachable) {
        $evidence += New-EvidenceItem -Name "Server reachability" -Status "Pass" -Detail "$AffectedDevice responded to ICMP echo."
    }
    else {
        $evidence += New-EvidenceItem -Name "Server reachability" -Status "Fail" -Detail "$AffectedDevice did not respond to ICMP echo."
    }
}
catch {
    $errors += "Reachability: $($_.Exception.Message)"
    $rawOutput.Reachability += [PSCustomObject]@{
        Target    = $AffectedDevice
        Succeeded = $false
        Error     = $_.Exception.Message
    }
    $evidence += New-EvidenceItem -Name "Server reachability" -Status "Warn" -Detail "Ping could not complete: $($_.Exception.Message)"
}

try {
    $serviceErrors = @()
    $services = @(Get-Service -ComputerName $AffectedDevice -Name frxsvc, frxccds -ErrorAction SilentlyContinue -ErrorVariable serviceErrors |
        Select-Object Name, DisplayName, Status, StartType)
    $rawOutput.Services = @($services | ForEach-Object {
        [PSCustomObject]@{
            Name        = [string]$_.Name
            DisplayName = [string]$_.DisplayName
            Status      = [string]$_.Status
            StartType   = [string]$_.StartType
        }
    })

    if ($serviceErrors.Count -gt 0 -and $services.Count -eq 0) {
        $errorText = ((@($serviceErrors) | ForEach-Object { $_.Exception.Message }) -join "; ")
        $errors += "Services: $errorText"
        $rawOutput.Services += [PSCustomObject]@{
            Name        = ""
            DisplayName = ""
            Status      = ""
            StartType   = ""
            Error       = $errorText
        }
        $evidence += New-EvidenceItem -Name "FSLogix services" -Status "Warn" -Detail "FSLogix services could not be queried or were not found: $errorText"
    }
    else {
        foreach ($service in @($services)) {
            $serviceStatus = [string]$service.Status
            if ($serviceStatus -eq "Running") {
                $evidence += New-EvidenceItem -Name ("Service {0}" -f $service.Name) -Status "Pass" -Detail ("{0} is running." -f $service.DisplayName)
            }
            else {
                $evidence += New-EvidenceItem -Name ("Service {0}" -f $service.Name) -Status "Fail" -Detail ("{0} is {1}." -f $service.DisplayName, $serviceStatus)
            }
        }

        foreach ($expectedService in @("frxsvc", "frxccds")) {
            if (-not (@($services.Name) -contains $expectedService)) {
                $evidence += New-EvidenceItem -Name ("Service {0}" -f $expectedService) -Status "Warn" -Detail "$expectedService was not returned by Get-Service on $AffectedDevice."
            }
        }
    }
}
catch {
    $errors += "Services: $($_.Exception.Message)"
    $rawOutput.Services = @([PSCustomObject]@{
        Name        = ""
        DisplayName = ""
        Status      = ""
        StartType   = ""
        Error       = $_.Exception.Message
    })
    $evidence += New-EvidenceItem -Name "FSLogix services" -Status "Warn" -Detail "FSLogix services could not be queried: $($_.Exception.Message)"
}

$registryKeys = @()
$remoteRegistry = $null
try {
    $remoteRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $AffectedDevice)
    $registryKeys += Read-FSLogixProfileRegistryKey -LocalMachine $remoteRegistry -SubKeyPath "SOFTWARE\FSLogix\Profiles" -Label "Local profile configuration"
    $registryKeys += Read-FSLogixProfileRegistryKey -LocalMachine $remoteRegistry -SubKeyPath "SOFTWARE\Policies\FSLogix\Profiles" -Label "Policy profile configuration"
    $rawOutput.Registry = @($registryKeys | ForEach-Object {
        $valueSummary = ""
        if ($_.Found -and $_.PSObject.Properties.Name -contains "Values") {
            $pairs = @()
            foreach ($property in @($_.Values.PSObject.Properties)) {
                $pairs += ("{0}={1}" -f $property.Name, $property.Value)
            }
            $valueSummary = $pairs -join "; "
        }

        [PSCustomObject]@{
            Label  = [string]$_.Label
            Path   = [string]$_.Path
            Found  = [bool]$_.Found
            Values = $valueSummary
            Error  = [string]$_.Error
        }
    })

    $foundKeys = @($registryKeys | Where-Object { $_.Found })
    if ($foundKeys.Count -gt 0) {
        $enabled = Get-RegistryValueText -RegistryKeys $registryKeys -ValueName "Enabled"
        if ($enabled -eq "1") {
            $evidence += New-EvidenceItem -Name "FSLogix profile registry" -Status "Pass" -Detail "FSLogix profile containers are enabled in registry configuration."
        }
        elseif ([string]::IsNullOrWhiteSpace($enabled)) {
            $evidence += New-EvidenceItem -Name "FSLogix profile registry" -Status "Warn" -Detail "FSLogix profile registry keys exist, but Enabled was not set."
        }
        else {
            $evidence += New-EvidenceItem -Name "FSLogix profile registry" -Status "Fail" -Detail "FSLogix profile containers appear disabled. Enabled=$enabled."
        }
    }
    else {
        $evidence += New-EvidenceItem -Name "FSLogix profile registry" -Status "Warn" -Detail "FSLogix profile registry keys were not found."
    }
}
catch {
    $errors += "Registry: $($_.Exception.Message)"
    $rawOutput.Registry = @([PSCustomObject]@{
        Label  = "Remote registry"
        Path   = "HKLM:\SOFTWARE\FSLogix\Profiles"
        Found  = $false
        Values = ""
        Error  = $_.Exception.Message
    })
    $evidence += New-EvidenceItem -Name "FSLogix profile registry" -Status "Warn" -Detail "Remote registry could not be read: $($_.Exception.Message)"
}
finally {
    if ($null -ne $remoteRegistry) {
        $remoteRegistry.Close()
    }
}

$eventLogs = @(
    "Microsoft-FSLogix-Apps/Operational",
    "Microsoft-FSLogix-Apps/Admin",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
)

foreach ($logName in $eventLogs) {
    try {
        $events = @(Get-WinEvent -ComputerName $AffectedDevice -FilterHashtable @{ LogName = $logName; StartTime = $eventStartTime } -MaxEvents 25 -ErrorAction Stop)
        $errorCount = @($events | Where-Object { $_.LevelDisplayName -eq "Error" -or $_.LevelDisplayName -eq "Critical" }).Count
        $warningCount = @($events | Where-Object { $_.LevelDisplayName -eq "Warning" }).Count

        foreach ($event in @($events | Select-Object -First 10)) {
            $message = [string]$event.Message
            if ($message.Length -gt 180) {
                $message = $message.Substring(0, 180)
            }

            $rawOutput.Events += [PSCustomObject]@{
                LogName      = $logName
                TimeCreated  = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                Id           = [int]$event.Id
                Level        = [string]$event.LevelDisplayName
                ProviderName = [string]$event.ProviderName
                Message      = $message
                Error        = ""
            }
        }

        $friendlyName = $logName
        if ($logName -like "Microsoft-FSLogix-*") {
            $friendlyName = "Recent FSLogix events"
        }
        else {
            $friendlyName = "Recent Terminal Services events"
        }

        if ($errorCount -gt 0) {
            $evidence += New-EvidenceItem -Name $friendlyName -Status "Fail" -Detail ("{0} error or critical event(s) found in {1} during the last {2} hour(s)." -f $errorCount, $logName, $EventLookbackHours)
        }
        elseif ($warningCount -gt 0) {
            $evidence += New-EvidenceItem -Name $friendlyName -Status "Warn" -Detail ("{0} warning event(s) found in {1} during the last {2} hour(s)." -f $warningCount, $logName, $EventLookbackHours)
        }
        else {
            $evidence += New-EvidenceItem -Name $friendlyName -Status "Pass" -Detail ("No error or warning events found in {0} during the last {1} hour(s)." -f $logName, $EventLookbackHours)
        }
    }
    catch {
        $errors += "Events ${logName}: $($_.Exception.Message)"
        $rawOutput.Events += [PSCustomObject]@{
            LogName      = $logName
            TimeCreated  = ""
            Id           = 0
            Level        = ""
            ProviderName = ""
            Message      = ""
            Error        = $_.Exception.Message
        }
        $evidence += New-EvidenceItem -Name "Event log access" -Status "Warn" -Detail "Could not read $logName on ${AffectedDevice}: $($_.Exception.Message)"
    }
}

try {
    $disks = @(Get-CimInstance -ComputerName $AffectedDevice -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop)
    foreach ($disk in @($disks)) {
        $sizeGb = 0
        $freeGb = 0
        $freePercent = 0
        if ($disk.Size -gt 0) {
            $sizeGb = [math]::Round(([double]$disk.Size / 1GB), 2)
            $freeGb = [math]::Round(([double]$disk.FreeSpace / 1GB), 2)
            $freePercent = [math]::Round((([double]$disk.FreeSpace / [double]$disk.Size) * 100), 2)
        }

        $rawOutput.Disks += [PSCustomObject]@{
            DeviceId    = [string]$disk.DeviceID
            SizeGB      = [string]$sizeGb
            FreeGB      = [string]$freeGb
            FreePercent = [string]$freePercent
            Error       = ""
        }

        if ($freeGb -lt 5 -or $freePercent -lt 10) {
            $evidence += New-EvidenceItem -Name ("Disk {0}" -f $disk.DeviceID) -Status "Fail" -Detail ("{0} GB free ({1} percent)." -f $freeGb, $freePercent)
        }
        elseif ($freeGb -lt 10 -or $freePercent -lt 15) {
            $evidence += New-EvidenceItem -Name ("Disk {0}" -f $disk.DeviceID) -Status "Warn" -Detail ("{0} GB free ({1} percent)." -f $freeGb, $freePercent)
        }
        else {
            $evidence += New-EvidenceItem -Name ("Disk {0}" -f $disk.DeviceID) -Status "Pass" -Detail ("{0} GB free ({1} percent)." -f $freeGb, $freePercent)
        }
    }

    if ($disks.Count -eq 0) {
        $evidence += New-EvidenceItem -Name "Local disk free space" -Status "Warn" -Detail "No fixed disks were returned."
    }
}
catch {
    $errors += "Disks: $($_.Exception.Message)"
    $rawOutput.Disks += [PSCustomObject]@{
        DeviceId    = ""
        SizeGB      = ""
        FreeGB      = ""
        FreePercent = ""
        Error       = $_.Exception.Message
    }
    $evidence += New-EvidenceItem -Name "Local disk free space" -Status "Warn" -Detail "Disk free space could not be queried: $($_.Exception.Message)"
}

$configuredPaths = @()
foreach ($valueName in @("VHDLocations", "CCDLocations")) {
    $text = Get-RegistryValueText -RegistryKeys $registryKeys -ValueName $valueName
    if (-not [string]::IsNullOrWhiteSpace($text)) {
        $configuredPaths += @($text -split ";" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
}

if ($configuredPaths.Count -gt 0) {
    $isLocalTarget = Test-IsLocalComputerTarget -ComputerName $AffectedDevice
    foreach ($profilePath in @($configuredPaths | Select-Object -Unique)) {
        $pathToTest = ConvertTo-ProfilePathForTest -Path $profilePath -UserName $AffectedUser
        try {
            if ($isLocalTarget) {
                $pathReachable = Test-Path -LiteralPath $pathToTest -ErrorAction Stop
                $testContext = "Local target"
            }
            else {
                $pathReachable = Invoke-Command -ComputerName $AffectedDevice -ScriptBlock {
                    param(
                        [Parameter(Mandatory)]
                        [string]$LiteralPath
                    )

                    Test-Path -LiteralPath $LiteralPath -ErrorAction Stop
                } -ArgumentList $pathToTest -ErrorAction Stop
                $testContext = "Remote target $AffectedDevice"
            }

            $rawOutput.ProfilePaths += [PSCustomObject]@{
                ConfiguredPath = [string]$profilePath
                TestedPath     = [string]$pathToTest
                Context        = $testContext
                Reachable      = [bool]$pathReachable
                Error          = ""
            }

            if ($pathReachable) {
                $evidence += New-EvidenceItem -Name "Profile path reachability" -Status "Pass" -Detail "$testContext Test-Path reached $pathToTest."
            }
            else {
                $evidence += New-EvidenceItem -Name "Profile path reachability" -Status "Warn" -Detail "$testContext Test-Path could not reach $pathToTest."
            }
        }
        catch {
            $errors += "Profile path ${profilePath}: $($_.Exception.Message)"
            if ($isLocalTarget) {
                $testContext = "Local target"
            }
            else {
                $testContext = "Remote target $AffectedDevice"
            }

            $rawOutput.ProfilePaths += [PSCustomObject]@{
                ConfiguredPath = [string]$profilePath
                TestedPath     = [string]$pathToTest
                Context        = $testContext
                Reachable      = $false
                Error          = $_.Exception.Message
            }
            $evidence += New-EvidenceItem -Name "Profile path reachability" -Status "Warn" -Detail "$testContext Test-Path failed for ${pathToTest}: $($_.Exception.Message)"
        }
    }
}
else {
    $evidence += New-EvidenceItem -Name "Profile path reachability" -Status "Warn" -Detail "No VHDLocations or CCDLocations value was found to test."
}

$failures = @($evidence | Where-Object { $_.Status -eq "Fail" })
$warnings = @($evidence | Where-Object { $_.Status -eq "Warn" })

if ($failures.Count -gt 0) {
    $status = "Fail"
    $summary = $failures[0].Detail
}
elseif ($warnings.Count -gt 0) {
    $status = "Warn"
    $summary = $warnings[0].Detail
}
else {
    $status = "Pass"
    $summary = "Citrix/FSLogix triage did not find high-risk findings on $AffectedDevice."
}

$nextSteps = @()
if ($status -eq "Pass") {
    $nextSteps += "Review application-layer symptoms or user-specific profile data if the issue remains."
}
else {
    $nextSteps += "Start with the first Fail or Warn evidence row; it is the highest-risk finding observed by this read-only triage."
    $nextSteps += "Validate remote access, Remote Registry, Event Log, and CIM permissions before treating missing evidence as healthy."
    $nextSteps += "Run the check against a real Citrix or RDS host to validate FSLogix-specific findings."
}

New-CitrixFSLogixResult -Status $status -Summary $summary -Evidence $evidence `
    -RecommendedNextSteps $nextSteps -RawOutput ([PSCustomObject]$rawOutput) `
    -StartedAt $startedAt -Errors $errors
