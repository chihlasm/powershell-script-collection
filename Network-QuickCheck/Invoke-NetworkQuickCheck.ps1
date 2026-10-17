# 3.0 so this runs on Server 2012 (PS 3.0) / 2012 R2 (PS 4.0) as shipped; Tests\PSVersionFloor.Tests.ps1 guards it.
#Requires -Version 3.0

<#
.SYNOPSIS
    "I can't reach the server / the app won't connect" - read-only check of whether this
    computer can reach a host and port, in plain English.
.DESCRIPTION
    Built for the service desk. Run it on the computer that has the problem, name the server
    (and port) it cannot reach, and the first line of output is the answer:

        Can this computer reach FILESRV01 on port 445?  YES / PARTLY / NO

    Each finding follows with a one-line "What to do". The tool is READ-ONLY.

    WHAT IT CHECKS (from this computer)

      1. The name turns into an address (DNS). Skipped when you give an IP address.
      2. The host answers a ping. Many servers block ping, so a missed ping alone is only a
         warning.
      3. Each TCP port you name accepts a connection (3-second timeout per port).
      4. This computer has a default gateway (a default route).

    Common ports: 445 file shares (SMB), 3389 Remote Desktop, 443 HTTPS, 80 HTTP,
    1494 / 2598 Citrix ICA / session reliability, 389 / 636 LDAP / LDAPS, 53 DNS, 1433 SQL Server.

    WHAT THIS DOES NOT CHECK: UDP ports, firewall rules on the far end, share or NTFS
    permissions, or whether the service behind the port is healthy.
.PARAMETER TargetAddress
    Host name, fully qualified name or IP address to test. Aliases: ComputerName, Target.
.PARAMETER Port
    One or more TCP ports to test. Default 443.
.PARAMETER TimeoutMilliseconds
    How long to wait for each port before calling it closed. Default 3000 (3 seconds).
.PARAMETER OutputPath
    Optional folder. When given, a text report ready to paste into a ticket and a CSV of the
    findings are written there, named NetworkQuickCheck_<target>_<yyyy-MM-dd_HHmmss>. When
    omitted the tool is console-only.
.PARAMETER PassThru
    Return the result object (CheckId, Status, Summary, Evidence, RecommendedNextSteps,
    RawOutput, StartedAt, FinishedAt, Error) instead of setting an exit code.
.PARAMETER Quiet
    Do not write the console report. Combine with -PassThru or -OutputPath.
.PARAMETER LoadFunctionsOnly
    Define the functions and return without running a check (used by the tests).
.EXAMPLE
    .\Invoke-NetworkQuickCheck.ps1 -TargetAddress FILESRV01 -Port 445
    Can this PC reach the file server's shares?
.EXAMPLE
    .\Invoke-NetworkQuickCheck.ps1 -TargetAddress rds.contoso.com -Port 443,3389 -OutputPath C:\Temp
    Test two ports and save a report for the ticket.
.NOTES
    Exit codes (without -PassThru): 0 = reachable, 1 = warnings, 2 = cannot reach.

    Formerly the network.quick check of the retired MSP-TroubleshootingWorkbench folder. The
    result object keeps the same shape. Changes from that version: -TargetAddress is now
    required (it defaulted to localhost), several ports can be tested at once, an IP address no
    longer triggers a misleading DNS warning, and ports are tested with a 3-second
    TcpClient connect instead of Test-NetConnection, which waits about 20 seconds on a closed
    port and does not exist on Server 2012.

    Resolve-DnsName and Get-NetRoute (Windows 8 / Server 2012 and later) are used when
    present; otherwise the .NET resolver is used and the route check is skipped.

    REFERENCES
      Resolve-DnsName
        https://learn.microsoft.com/powershell/module/dnsclient/resolve-dnsname
      Get-NetRoute (0.0.0.0/0 is the IPv4 default route)
        https://learn.microsoft.com/powershell/module/nettcpip/get-netroute
      Test-Connection (-Quiet returns True/False; PowerShell 7 keeps -ComputerName as an alias of -TargetName)
        https://learn.microsoft.com/powershell/module/microsoft.powershell.management/test-connection
      System.Net.Sockets.TcpClient.BeginConnect
        https://learn.microsoft.com/dotnet/api/system.net.sockets.tcpclient.beginconnect
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [Alias('ComputerName', 'Target')]
    [string]$TargetAddress,

    [Parameter(Position = 1)]
    [ValidateRange(1, 65535)]
    [int[]]$Port = @(443),

    [ValidateRange(250, 60000)]
    [int]$TimeoutMilliseconds = 3000,

    [string]$OutputPath,

    [switch]$PassThru,

    [switch]$Quiet,

    [switch]$LoadFunctionsOnly
)

function New-EvidenceItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Warn', 'Fail')]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Detail,

        [string]$Action = ''
    )

    [PSCustomObject]@{
        Name   = $Name
        Status = $Status
        Detail = $Detail
        Action = $Action
    }
}

function Test-IsIpAddress {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Value)

    $parsed = $null
    return [System.Net.IPAddress]::TryParse($Value, [ref]$parsed)
}

function Get-PortLabel {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$Port)

    $known = @{
        53 = 'DNS'; 80 = 'HTTP'; 88 = 'Kerberos'; 135 = 'RPC'; 389 = 'LDAP'; 443 = 'HTTPS'
        445 = 'file shares (SMB)'; 636 = 'LDAPS'; 1433 = 'SQL Server'; 1494 = 'Citrix ICA'
        2598 = 'Citrix session reliability'; 3268 = 'Global Catalog'; 3389 = 'Remote Desktop'
        5985 = 'WinRM'; 5986 = 'WinRM over HTTPS'
    }
    if ($known.ContainsKey($Port)) { return ('{0} ({1})' -f $Port, $known[$Port]) }
    return [string]$Port
}

function Format-Endpoint {
    <#
    .SYNOPSIS
        Shows an IPv4-mapped IPv6 endpoint ([::ffff:10.0.0.5]:445) as plain IPv4 (10.0.0.5:445).
    #>
    [CmdletBinding()]
    param([AllowNull()][string]$Endpoint)

    if ([string]::IsNullOrEmpty($Endpoint)) { return '' }
    return ($Endpoint -replace '^\[::ffff:(\d{1,3}(?:\.\d{1,3}){3})\]', '$1')
}

function Test-TcpPort {
    <#
    .SYNOPSIS
        Tries a TCP connection with a timeout. Returns Succeeded, LocalAddress, RemoteAddress, Error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutMilliseconds = 3000
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)) {
            return [PSCustomObject]@{ Succeeded = $false; LocalAddress = ''; RemoteAddress = ''; Error = ('No answer within {0} ms' -f $TimeoutMilliseconds) }
        }

        $client.EndConnect($async)
        return [PSCustomObject]@{
            Succeeded     = $true
            LocalAddress  = Format-Endpoint -Endpoint ([string]$client.Client.LocalEndPoint)
            RemoteAddress = Format-Endpoint -Endpoint ([string]$client.Client.RemoteEndPoint)
            Error         = ''
        }
    }
    catch {
        $message = $_.Exception.Message
        if ($_.Exception.InnerException) { $message = $_.Exception.InnerException.Message }
        return [PSCustomObject]@{ Succeeded = $false; LocalAddress = ''; RemoteAddress = ''; Error = $message }
    }
    finally {
        $client.Close()
    }
}

function Resolve-TargetName {
    <#
    .SYNOPSIS
        Resolves a host name to addresses. Uses Resolve-DnsName when present, else System.Net.Dns.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    if (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue) {
        $records = @(Resolve-DnsName -Name $Name -ErrorAction Stop |
            Where-Object { $_.Type -eq 'A' -or $_.Type -eq 'AAAA' -or $_.Type -eq 'CNAME' } |
            Select-Object -First 5 Name, Type, IPAddress, NameHost)
        return @($records)
    }

    return @([System.Net.Dns]::GetHostAddresses($Name) | Select-Object -First 5 | ForEach-Object {
        [PSCustomObject]@{ Name = $Name; Type = [string]$_.AddressFamily; IPAddress = $_.IPAddressToString; NameHost = '' }
    })
}

function Get-NetworkVerdict {
    [CmdletBinding()]
    param([object[]]$Evidence)

    $portItems = @($Evidence | Where-Object { $_.Name -like 'Port *' })
    $openPorts = @($portItems | Where-Object { $_.Status -eq 'Pass' })
    $failures = @($Evidence | Where-Object { $_.Status -eq 'Fail' })
    $warnings = @($Evidence | Where-Object { $_.Status -eq 'Warn' })

    if ($failures.Count -gt 0) {
        $status = 'Fail'
    }
    elseif ($warnings.Count -gt 0) {
        $status = 'Warn'
    }
    else {
        $status = 'Pass'
    }

    # YES only when every port answered; PARTLY when some did, or all did with warnings.
    if ($portItems.Count -gt 0 -and $openPorts.Count -eq $portItems.Count) {
        $answer = if ($status -eq 'Pass') { 'YES' } else { 'YES, WITH WARNINGS' }
    }
    elseif ($openPorts.Count -gt 0) {
        $answer = 'PARTLY'
    }
    else {
        $answer = 'NO'
    }

    return [PSCustomObject]@{ Status = $status; Answer = $answer }
}

function Invoke-NetworkQuickCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TargetAddress,
        [int[]]$Port = @(443),
        [int]$TimeoutMilliseconds = 3000
    )

    $startedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $TargetAddress = $TargetAddress.Trim()
    $evidence = @()
    $errors = @()
    $rawOutput = [ordered]@{
        TargetAddress = $TargetAddress
        Port          = @($Port)
        Ping          = $null
        Dns           = $null
        Tcp           = @()
        Routes        = @()
    }

    # --- 1. DNS --------------------------------------------------------------------------
    if (Test-IsIpAddress -Value $TargetAddress) {
        $rawOutput.Dns = @()
        $evidence += New-EvidenceItem -Name 'Name lookup (DNS)' -Status 'Pass' -Detail 'Not needed: you gave an IP address.'
    }
    else {
        try {
            $dnsRecords = @(Resolve-TargetName -Name $TargetAddress)
            $rawOutput.Dns = @($dnsRecords)
            $addresses = @($dnsRecords | Where-Object { $_.IPAddress } | ForEach-Object { [string]$_.IPAddress })
            if ($addresses.Count -gt 0) {
                $evidence += New-EvidenceItem -Name 'Name lookup (DNS)' -Status 'Pass' -Detail ('{0} resolves to {1}.' -f $TargetAddress, ($addresses -join ', '))
            }
            else {
                $evidence += New-EvidenceItem -Name 'Name lookup (DNS)' -Status 'Warn' `
                    -Detail "DNS answered for $TargetAddress but returned no address." `
                    -Action 'Try the fully qualified name (for example server.contoso.com) or the IP address.'
            }
        }
        catch {
            $errors += "DNS: $($_.Exception.Message)"
            $rawOutput.Dns = [PSCustomObject]@{ Error = $_.Exception.Message }
            $evidence += New-EvidenceItem -Name 'Name lookup (DNS)' -Status 'Fail' `
                -Detail "$TargetAddress could not be found in DNS: $($_.Exception.Message)" `
                -Action 'Check the spelling, try the fully qualified name, and check this PC is on the network or VPN.'
        }
    }

    # --- 2. Ping -------------------------------------------------------------------------
    try {
        $pingSucceeded = Test-Connection -ComputerName $TargetAddress -Count 2 -Quiet -ErrorAction Stop
        $rawOutput.Ping = [PSCustomObject]@{ Succeeded = [bool]$pingSucceeded }
        if ($pingSucceeded) {
            $evidence += New-EvidenceItem -Name 'Ping' -Status 'Pass' -Detail "$TargetAddress answered a ping."
        }
        else {
            $evidence += New-EvidenceItem -Name 'Ping' -Status 'Warn' `
                -Detail "$TargetAddress did not answer a ping." `
                -Action 'Many servers block ping on purpose. If the port test passes, ignore this.'
        }
    }
    catch {
        $errors += "Ping: $($_.Exception.Message)"
        $rawOutput.Ping = [PSCustomObject]@{ Succeeded = $false; Error = $_.Exception.Message }
        $evidence += New-EvidenceItem -Name 'Ping' -Status 'Warn' `
            -Detail "Ping could not run: $($_.Exception.Message)" `
            -Action 'Many servers block ping on purpose. If the port test passes, ignore this.'
    }

    # --- 3. TCP ports --------------------------------------------------------------------
    foreach ($portNumber in @($Port | Select-Object -Unique)) {
        $label = Get-PortLabel -Port $portNumber
        $tcp = Test-TcpPort -ComputerName $TargetAddress -Port $portNumber -TimeoutMilliseconds $TimeoutMilliseconds
        $rawOutput.Tcp += [PSCustomObject]@{
            RemotePort       = $portNumber
            RemoteAddress    = $tcp.RemoteAddress
            SourceAddress    = $tcp.LocalAddress
            TcpTestSucceeded = [bool]$tcp.Succeeded
            Error            = $tcp.Error
        }

        if ($tcp.Succeeded) {
            $evidence += New-EvidenceItem -Name "Port $label" -Status 'Pass' -Detail ('Connected to {0} from {1}.' -f $tcp.RemoteAddress, $tcp.LocalAddress)
        }
        else {
            $errors += "TCP ${portNumber}: $($tcp.Error)"
            $evidence += New-EvidenceItem -Name "Port $label" -Status 'Fail' `
                -Detail ('Could not connect to {0} on port {1}: {2}.' -f $TargetAddress, $portNumber, $tcp.Error) `
                -Action 'The service may be stopped, or a firewall (on this PC, the network, or the server) is blocking it. Escalate with this result.'
        }
    }

    # --- 4. Default route ----------------------------------------------------------------
    if (Get-Command -Name Get-NetRoute -ErrorAction SilentlyContinue) {
        try {
            $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                Sort-Object RouteMetric | Select-Object -First 5 DestinationPrefix, NextHop, InterfaceAlias, RouteMetric, ifIndex)
            $rawOutput.Routes = @($routes)
            if ($routes.Count -gt 0) {
                $evidence += New-EvidenceItem -Name 'Default gateway' -Status 'Pass' -Detail ('Gateway {0} on {1}.' -f $routes[0].NextHop, $routes[0].InterfaceAlias)
            }
            else {
                $evidence += New-EvidenceItem -Name 'Default gateway' -Status 'Warn' `
                    -Detail 'This computer has no default gateway (IPv4).' `
                    -Action 'It can only reach its own subnet. Check the network cable, Wi-Fi, or VPN.'
            }
        }
        catch {
            $errors += "Route: $($_.Exception.Message)"
            $rawOutput.Routes = @([PSCustomObject]@{ Error = $_.Exception.Message })
            $evidence += New-EvidenceItem -Name 'Default gateway' -Status 'Warn' -Detail "Could not read the routing table: $($_.Exception.Message)"
        }
    }

    $verdict = Get-NetworkVerdict -Evidence $evidence
    $portText = (@($Port | Select-Object -Unique) -join ', ')
    $summary = switch ($verdict.Answer) {
        'NO' { "This computer cannot reach $TargetAddress on port $portText." }
        'PARTLY' { "This computer can reach $TargetAddress on some ports but not all ($portText)." }
        default { "This computer can reach $TargetAddress on port $portText." }
    }

    $nextSteps = @()
    if ($verdict.Status -eq 'Pass') {
        $nextSteps += 'The network path is fine. Look at the application, the sign-in, or permissions next.'
    }
    else {
        $nextSteps += 'Confirm the server name and port are right for the application.'
        $nextSteps += 'Run the same check from a computer that works; if it passes there, the problem is this computer or its network.'
    }

    [PSCustomObject]@{
        CheckId              = 'network.quick'
        Name                 = 'Network Quick Check'
        Category             = 'Network'
        Status               = $verdict.Status
        Answer               = $verdict.Answer
        Summary              = $summary
        Evidence             = @($evidence)
        RecommendedNextSteps = @($nextSteps)
        RawOutput            = [PSCustomObject]$rawOutput
        StartedAt            = $startedAt
        FinishedAt           = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Error                = ($errors -join '; ')
    }
}

function ConvertTo-NetworkText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Result)

    $portText = (@($Result.RawOutput.Port | Select-Object -Unique) -join ', ')
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(('Can {0} reach {1} on port {2}?  {3}' -f $env:COMPUTERNAME, $Result.RawOutput.TargetAddress, $portText, $Result.Answer))
    $lines.Add(('=' * 70))
    $lines.Add(('Checked: {0}' -f $Result.StartedAt))

    $sections = @(
        @{ Status = 'Fail'; Title = 'Problems:' },
        @{ Status = 'Warn'; Title = 'Warnings:' },
        @{ Status = 'Pass'; Title = 'Looks fine:' }
    )
    foreach ($section in $sections) {
        $items = @($Result.Evidence | Where-Object { $_.Status -eq $section.Status })
        if ($items.Count -eq 0) { continue }
        $lines.Add('')
        $lines.Add($section.Title)
        foreach ($item in $items) {
            $lines.Add(('  [{0}] {1}: {2}' -f $item.Status.ToUpperInvariant(), $item.Name, $item.Detail))
            if ($item.Action) {
                $lines.Add(('         What to do: {0}' -f $item.Action))
            }
        }
    }

    $lines.Add('')
    $lines.Add('Next steps:')
    foreach ($step in @($Result.RecommendedNextSteps)) {
        $lines.Add(('  - {0}' -f $step))
    }

    return $lines.ToArray()
}

function Write-NetworkConsole {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Result)

    $headColor = switch ($Result.Status) { 'Fail' { 'Red' } 'Warn' { 'Yellow' } default { 'Green' } }
    $first = $true
    foreach ($line in @(ConvertTo-NetworkText -Result $Result)) {
        $color = 'Gray'
        if ($first) { $color = $headColor; $first = $false }
        elseif ($line -match '^  \[FAIL\]') { $color = 'Red' }
        elseif ($line -match '^  \[WARN\]') { $color = 'Yellow' }
        elseif ($line -match '^  \[PASS\]') { $color = 'Green' }
        elseif ($line -match '^(Problems|Warnings|Looks fine|Next steps):$') { $color = 'White' }
        elseif ($line -match '^=+$') { $color = 'DarkGray' }
        Write-Host $line -ForegroundColor $color
    }
    Write-Host ''
}

function Export-NetworkReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Result,
        [Parameter(Mandatory)][string]$OutputPath
    )

    if (-not (Test-Path -LiteralPath $OutputPath)) {
        $null = New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop
    }

    $safeName = ($Result.RawOutput.TargetAddress -replace '[^A-Za-z0-9._-]', '_')
    $stem = Join-Path $OutputPath ('NetworkQuickCheck_{0}_{1}' -f $safeName, (Get-Date -Format 'yyyy-MM-dd_HHmmss'))
    ConvertTo-NetworkText -Result $Result | Set-Content -LiteralPath "$stem.txt" -Encoding UTF8
    @($Result.Evidence) | Select-Object Status, Name, Detail, Action |
        Export-Csv -LiteralPath "$stem.csv" -NoTypeInformation -Encoding UTF8
    return @("$stem.txt", "$stem.csv")
}

# STUB (SQ-010, tests first): the adapter that maps a result to a ticket note. Not implemented yet.
function ConvertTo-NetworkQuickCheckTicketNote {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Result,
        [string[]]$EvidencePaths = @()
    )
    throw 'ConvertTo-NetworkQuickCheckTicketNote is not implemented yet.'
}

if ($LoadFunctionsOnly) {
    return
}

if ([string]::IsNullOrWhiteSpace($TargetAddress)) {
    Write-Host '[FAIL] Name the server to test, for example: .\Invoke-NetworkQuickCheck.ps1 -TargetAddress FILESRV01 -Port 445' -ForegroundColor Red
    if ($PassThru) {
        return [PSCustomObject]@{
            CheckId = 'network.quick'; Name = 'Network Quick Check'; Category = 'Network'; Status = 'Fail'; Answer = 'NO'
            Summary = 'Target address is required.'
            Evidence = @(New-EvidenceItem -Name 'Input' -Status 'Fail' -Detail 'Target address was blank.')
            RecommendedNextSteps = @('Enter a hostname or IP address and run the check again.')
            RawOutput = [PSCustomObject]@{ TargetAddress = ''; Port = @($Port) }
            StartedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; FinishedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Error = 'Target address is required.'
        }
    }
    exit 2
}

$result = Invoke-NetworkQuickCheck -TargetAddress $TargetAddress -Port $Port -TimeoutMilliseconds $TimeoutMilliseconds

if (-not $Quiet) {
    Write-NetworkConsole -Result $result
}

if ($OutputPath) {
    try {
        $files = Export-NetworkReport -Result $result -OutputPath $OutputPath
        if (-not $Quiet) {
            foreach ($file in $files) { Write-Host ('[INFO] Saved {0}' -f $file) -ForegroundColor Cyan }
        }
    }
    catch {
        Write-Host ("[WARN] Could not write the report to {0}: {1}" -f $OutputPath, $_.Exception.Message) -ForegroundColor Yellow
    }
}

if ($PassThru) {
    return $result
}

exit $(switch ($result.Status) { 'Fail' { 2 } 'Warn' { 1 } default { 0 } })
