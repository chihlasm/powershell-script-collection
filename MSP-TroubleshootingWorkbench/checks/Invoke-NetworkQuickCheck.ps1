#Requires -Version 5.1

<#
.SYNOPSIS
    Runs a read-only network quick check.

.DESCRIPTION
    Captures ping, DNS, TCP port, and local default route evidence for a target
    address without making changes to the local computer or remote endpoint.

.PARAMETER TargetAddress
    Hostname or IP address to test. Defaults to localhost.

.PARAMETER Port
    TCP port to test. Defaults to 443.

.EXAMPLE
    .\Invoke-NetworkQuickCheck.ps1 -TargetAddress localhost -Port 445

.NOTES
    Returns the shared MSP Troubleshooting Workbench check result object.
#>
[CmdletBinding()]
param(
    [string]$TargetAddress = "localhost",

    [ValidateRange(1, 65535)]
    [int]$Port = 443
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

$startedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$evidence = @()
$errors = @()
$rawOutput = [ordered]@{
    TargetAddress = $TargetAddress
    Port          = $Port
    Ping          = $null
    Dns           = $null
    Tcp           = $null
    Routes        = @()
}

if ([string]::IsNullOrWhiteSpace($TargetAddress)) {
    $finishedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    return [PSCustomObject]@{
        CheckId              = "network.quick"
        Name                 = "Network Quick Check"
        Category             = "Network"
        Status               = "Fail"
        Summary              = "Target address is required."
        Evidence             = @(New-EvidenceItem -Name "Input" -Status "Fail" -Detail "Target address was blank.")
        RecommendedNextSteps = @("Enter a hostname or IP address and run the check again.")
        RawOutput            = [PSCustomObject]$rawOutput
        StartedAt            = $startedAt
        FinishedAt           = $finishedAt
        Error                = "Target address is required."
    }
}

$TargetAddress = $TargetAddress.Trim()
$rawOutput.TargetAddress = $TargetAddress

try {
    $pingSucceeded = Test-Connection -ComputerName $TargetAddress -Count 2 -Quiet -ErrorAction Stop
    $rawOutput.Ping = [PSCustomObject]@{
        Succeeded = [bool]$pingSucceeded
    }

    if ($pingSucceeded) {
        $evidence += New-EvidenceItem -Name "Ping" -Status "Pass" -Detail "Target responded to ICMP echo."
    }
    else {
        $evidence += New-EvidenceItem -Name "Ping" -Status "Warn" -Detail "Target did not respond to ICMP echo."
    }
}
catch {
    $errors += "Ping: $($_.Exception.Message)"
    $rawOutput.Ping = [PSCustomObject]@{
        Succeeded = $false
        Error     = $_.Exception.Message
    }
    $evidence += New-EvidenceItem -Name "Ping" -Status "Warn" -Detail "Ping test could not complete: $($_.Exception.Message)"
}

try {
    $dnsRecords = @(Resolve-DnsName -Name $TargetAddress -ErrorAction Stop | Select-Object -First 5 Name, Type, IPAddress, NameHost)
    $rawOutput.Dns = @($dnsRecords)

    if ($dnsRecords.Count -gt 0) {
        $evidence += New-EvidenceItem -Name "DNS" -Status "Pass" -Detail ("Resolved {0} DNS record(s)." -f $dnsRecords.Count)
    }
    else {
        $evidence += New-EvidenceItem -Name "DNS" -Status "Warn" -Detail "No DNS records were returned."
    }
}
catch {
    $errors += "DNS: $($_.Exception.Message)"
    $rawOutput.Dns = [PSCustomObject]@{
        Error = $_.Exception.Message
    }
    $evidence += New-EvidenceItem -Name "DNS" -Status "Warn" -Detail "DNS lookup could not complete: $($_.Exception.Message)"
}

try {
    $tcpResult = Test-NetConnection -ComputerName $TargetAddress -Port $Port -InformationLevel Detailed -WarningAction SilentlyContinue -ErrorAction Stop
    $rawOutput.Tcp = $tcpResult | Select-Object ComputerName, RemoteAddress, RemotePort, InterfaceAlias, SourceAddress, PingSucceeded, TcpTestSucceeded

    if ($tcpResult.TcpTestSucceeded) {
        $evidence += New-EvidenceItem -Name "TCP port" -Status "Pass" -Detail ("TCP port {0} is reachable." -f $Port)
    }
    else {
        $evidence += New-EvidenceItem -Name "TCP port" -Status "Fail" -Detail ("TCP port {0} is not reachable." -f $Port)
    }
}
catch {
    $errors += "TCP: $($_.Exception.Message)"
    $rawOutput.Tcp = [PSCustomObject]@{
        Port  = $Port
        Error = $_.Exception.Message
    }
    $evidence += New-EvidenceItem -Name "TCP port" -Status "Fail" -Detail "TCP test could not complete: $($_.Exception.Message)"
}

try {
    $routes = @(Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop | Select-Object -First 5 DestinationPrefix, NextHop, InterfaceAlias, RouteMetric, ifIndex)
    $rawOutput.Routes = @($routes)

    if ($routes.Count -gt 0) {
        $evidence += New-EvidenceItem -Name "Default route" -Status "Pass" -Detail ("Found {0} IPv4 default route(s)." -f $routes.Count)
    }
    else {
        $evidence += New-EvidenceItem -Name "Default route" -Status "Warn" -Detail "No IPv4 default route was found."
    }
}
catch {
    $errors += "Route: $($_.Exception.Message)"
    $rawOutput.Routes = @([PSCustomObject]@{
        Error = $_.Exception.Message
    })
    $evidence += New-EvidenceItem -Name "Default route" -Status "Warn" -Detail "Default route snapshot could not complete: $($_.Exception.Message)"
}

$failCount = @($evidence | Where-Object { $_.Status -eq "Fail" }).Count
$warnCount = @($evidence | Where-Object { $_.Status -eq "Warn" }).Count

if ($failCount -gt 0) {
    $status = "Fail"
    $summary = "Network quick check found a blocking issue for $TargetAddress."
}
elseif ($warnCount -gt 0) {
    $status = "Warn"
    $summary = "Network quick check completed with warnings for $TargetAddress."
}
else {
    $status = "Pass"
    $summary = "Network quick check passed for $TargetAddress."
}

$nextSteps = @()
if ($status -eq "Pass") {
    $nextSteps += "Continue troubleshooting above the network layer if the user impact remains."
}
else {
    $nextSteps += "Confirm the target address and port are correct."
    $nextSteps += "Check local routing, firewall policy, and service listener state for the target."
}

$finishedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

[PSCustomObject]@{
    CheckId              = "network.quick"
    Name                 = "Network Quick Check"
    Category             = "Network"
    Status               = $status
    Summary              = $summary
    Evidence             = @($evidence)
    RecommendedNextSteps = @($nextSteps)
    RawOutput            = [PSCustomObject]$rawOutput
    StartedAt            = $startedAt
    FinishedAt           = $finishedAt
    Error                = ($errors -join "; ")
}
