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
    omitted the tool is console-only. With -TicketNumber, this is the folder that holds
    Ticket_<number>.
.PARAMETER TicketNumber
    Optional ticket number (letters, digits, - or _, up to 32 characters). The text report, the
    CSV and the ticket note are saved in <root>\Ticket_<number>, where root is -OutputPath if
    given, else %USERPROFILE%\Documents\TicketNotes. TicketNote\Join-TicketNotes.ps1 later
    joins every tool's note in that folder into one. A number that does not fit is refused
    with a [FAIL] line and exit code 3, before anything is checked.
.PARAMETER NoClipboard
    Do not copy the ticket note to the clipboard. Without it the note goes to the clipboard,
    where it can enter clipboard history (Win+V) or the cloud clipboard on Windows PowerShell
    5.0 and later, and travels over RDP clipboard redirection.
.PARAMETER FullDetail
    Keep IP addresses and share paths in the ticket note. By default the note is paste-safe:
    they are replaced by [IP removed] / [share path removed]. The question at the top is
    never changed.
.PARAMETER PassThru
    Return the result object (CheckId, Status, Summary, Evidence, RecommendedNextSteps,
    RawOutput, StartedAt, FinishedAt, Error, TicketNote) instead of setting an exit code.
.PARAMETER Quiet
    Do not write the console report. Combine with -PassThru or -OutputPath. Also leaves the
    clipboard alone, because another script is the caller.
.PARAMETER LoadFunctionsOnly
    Define the functions and return without running a check (used by the tests).
.EXAMPLE
    .\Invoke-NetworkQuickCheck.ps1 -TargetAddress FILESRV01 -Port 445
    Can this PC reach the file server's shares?
.EXAMPLE
    .\Invoke-NetworkQuickCheck.ps1 -TargetAddress rds.contoso.com -Port 443,3389 -OutputPath C:\Temp
    Test two ports and save a report for the ticket.
.EXAMPLE
    .\Invoke-NetworkQuickCheck.ps1 -TargetAddress FILESRV01 -Port 445 -TicketNumber 482113
    Same answer; the text report, the CSV and the ticket note go into
    %USERPROFILE%\Documents\TicketNotes\Ticket_482113, and the note is copied to the clipboard.
.NOTES
    Exit codes (without -PassThru): 0 = reachable, 1 = warnings, 2 = cannot reach (or no
    target given), 3 = an unusable -TicketNumber.

    TICKET NOTE. Every run ends with a four-part note (Checked, Ruled out, Could not check,
    Next step) copied to the clipboard. It is also saved as Note_<time>_Network-QuickCheck.txt
    when -TicketNumber or -OutputPath is given. A check is only "Ruled out" when it really ran:
    a ping or routing-table read that could not run is listed under "Could not check", and so
    is the default gateway on Windows versions without Get-NetRoute. The note never changes
    the answer or the exit code. It is built by CaseKit.ps1 in this folder (a copy of
    TicketNote\CaseKit.ps1); if it is missing the check still runs, without a note.

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
      Ticket note clipboard (in CaseKit.ps1): Set-Clipboard is 5.0, so it is used behind a
      Get-Command check with a WinForms fallback; STA is the default since 3.0; never clip.exe,
      because $OutputEncoding is ASCII in 5.1 and would mangle non-ASCII names
        https://learn.microsoft.com/powershell/scripting/whats-new/what-s-new-in-windows-powershell-50
        https://learn.microsoft.com/powershell/module/microsoft.powershell.management/set-clipboard?view=powershell-5.1
        https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1
        https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-5.1
      Clipboard history / cloud clipboard opt-out formats (CanIncludeInClipboardHistory,
      CanUploadToCloudClipboard; set by the kit's WinForms path, not by Set-Clipboard)
        https://learn.microsoft.com/windows/win32/dataxchg/clipboard-formats
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

    # Checked in the script body (Test-TicketNumber in CaseKit.ps1), not with ValidatePattern,
    # so a mistyped number gets a plain-English [FAIL] line instead of a parameter-binding error.
    [string]$TicketNumber,

    [switch]$NoClipboard,

    [switch]$FullDetail,

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

        [string]$Action = '',

        # The check could not run at all (as opposed to running and finding something). The
        # Status stays as given, so the verdict is unchanged; only the ticket note moves the
        # item to "Could not check".
        [switch]$NotChecked
    )

    [PSCustomObject]@{
        Name       = $Name
        Status     = $Status
        Detail     = $Detail
        Action     = $Action
        NotChecked = [bool]$NotChecked
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
        $evidence += New-EvidenceItem -Name 'Ping' -Status 'Warn' -NotChecked `
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
            $evidence += New-EvidenceItem -Name 'Default gateway' -Status 'Warn' -NotChecked -Detail "Could not read the routing table: $($_.Exception.Message)"
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

# =============================================================================
# Ticket note (CaseKit.ps1)
# =============================================================================

function ConvertTo-NetworkQuickCheckTicketNote {
    <#
    .SYNOPSIS
        Maps a network quick-check result to a ticket note. The gate decisions for this tool live here.
    .DESCRIPTION
        Pass -> Ruled out (only when the check really ran), Fail -> PROBLEM, Warn -> WARNING.
        A Warn that is NotChecked (ping or route lookup could not run) -> Could not check.

        The "not needed" name-lookup item for an IP target is left out: nothing was looked up, so
        it is neither ruled out nor missing. The scope line says no lookup was needed instead.

        Without Get-NetRoute (before Windows 8 / Server 2012) the check adds no gateway evidence,
        so the verdict cannot change; the note alone says the gateway was not checked.

        Next steps are the result's RecommendedNextSteps. The stamp scope is this computer,
        because every check runs from here.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Result,
        [string[]]$EvidencePaths = @()
    )

    $target = [string]$Result.RawOutput.TargetAddress
    $portText = (@($Result.RawOutput.Port | Select-Object -Unique) -join ', ')
    $isIp = (-not [string]::IsNullOrEmpty($target)) -and (Test-IsIpAddress -Value $target)
    $items = New-Object System.Collections.Generic.List[object]

    foreach ($e in @($Result.Evidence)) {
        if ($isIp -and $e.Name -eq 'Name lookup (DNS)') { continue }

        # "Ping: Ping could not run: ..." reads badly; drop the name when the detail starts with it.
        $text = if (([string]$e.Detail).StartsWith([string]$e.Name, [System.StringComparison]::OrdinalIgnoreCase)) { [string]$e.Detail } else { '{0}: {1}' -f $e.Name, $e.Detail }
        $notChecked = ($e.PSObject.Properties.Name -contains 'NotChecked') -and [bool]$e.NotChecked
        switch ([string]$e.Status) {
            'Pass' { $items.Add((New-TicketNoteItem -Kind Clear -Text $text -CouldLook (-not $notChecked))) }
            'Fail' { $items.Add((New-TicketNoteItem -Kind Problem -Text $text)) }
            default {
                $kind = if ($notChecked) { 'NotChecked' } else { 'Warning' }
                $items.Add((New-TicketNoteItem -Kind $kind -Text $text))
            }
        }
    }

    # Every branch of the route check adds a 'Default gateway' item, except "no Get-NetRoute".
    if (@($Result.Evidence | Where-Object { $_.Name -eq 'Default gateway' }).Count -eq 0) {
        $items.Add((New-TicketNoteItem -Kind NotChecked -Text 'Default gateway: not checked (this Windows version has no Get-NetRoute)'))
    }

    $headline = 'Can {0} reach {1} on port {2}? {3}' -f $env:COMPUTERNAME, $target, $portText, $Result.Answer
    # The scope says where from and to; each check is its own line below.
    $scopeLine = 'Tested from {0} to {1} on TCP port {2}.' -f $env:COMPUTERNAME, $target, $portText
    if ($isIp) { $scopeLine += ' It is an IP address, so no name lookup was needed.' }

    $stampArgs = @{ ScopeLabel = 'Computer'; Scope = $env:COMPUTERNAME }
    $started = [datetime]::MinValue
    if ([datetime]::TryParseExact([string]$Result.StartedAt, 'yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$started)) {
        $stampArgs['Now'] = $started
    }
    $stamp = New-TicketNoteStamp @stampArgs

    return New-TicketNote -Tool 'Network-QuickCheck' -Headline $headline -ScopeLine $scopeLine -Items $items.ToArray() `
        -NextSteps @($Result.RecommendedNextSteps) -Stamp $stamp -EvidencePaths $EvidencePaths
}

# The ticket-note kit ships beside this script (a copy of TicketNote\CaseKit.ps1). Without it
# the check still runs; only the note is skipped.
$kit = Join-Path $PSScriptRoot 'CaseKit.ps1'
if (Test-Path -LiteralPath $kit) { . $kit } else { $script:CaseKitMissing = $true }

if ($LoadFunctionsOnly) {
    return
}

# A result for the cases where the check cannot start (-PassThru callers get it instead of an exit code).
function New-NetworkStartFailure([string]$Message, [string]$Detail, [string]$NextStep) {
    [PSCustomObject]@{
        CheckId = 'network.quick'; Name = 'Network Quick Check'; Category = 'Network'; Status = 'Fail'; Answer = 'NO'
        Summary = $Message
        Evidence = @(New-EvidenceItem -Name 'Input' -Status 'Fail' -Detail $Detail)
        RecommendedNextSteps = @($NextStep)
        RawOutput = [PSCustomObject]@{ TargetAddress = [string]$TargetAddress; Port = @($Port) }
        StartedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; FinishedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Error = $Message
        TicketNote = $null
    }
}

if ([string]::IsNullOrWhiteSpace($TargetAddress)) {
    Write-Host '[FAIL] Name the server to test, for example: .\Invoke-NetworkQuickCheck.ps1 -TargetAddress FILESRV01 -Port 445' -ForegroundColor Red
    if ($PassThru) {
        return (New-NetworkStartFailure 'Target address is required.' 'Target address was blank.' 'Enter a hostname or IP address and run the check again.')
    }
    exit 2
}

if ($TicketNumber -and $script:CaseKitMissing) {
    if (-not $Quiet) { Write-Host "[WARN] CaseKit.ps1 is missing from this folder, so -TicketNumber $TicketNumber was ignored: the reports go to -OutputPath (if given) and there is no ticket note this time." -ForegroundColor Yellow }
    $TicketNumber = ''
    $script:CaseKitWarned = $true
}
if ($TicketNumber -and -not (Test-TicketNumber -TicketNumber $TicketNumber)) {
    $msg = "'$TicketNumber' is not a usable ticket number. Use letters, digits, - or _ (up to 32 characters, starting with a letter or digit), for example 482113."
    if (-not $Quiet) { Write-Host "[FAIL] $msg" -ForegroundColor Red }
    if ($PassThru) { return (New-NetworkStartFailure $msg $msg 'Run the check again with the ticket number as it appears in the ticket.') }
    exit 3
}

$result = Invoke-NetworkQuickCheck -TargetAddress $TargetAddress -Port $Port -TimeoutMilliseconds $TimeoutMilliseconds

if (-not $Quiet) {
    Write-NetworkConsole -Result $result
}

# Where the files go: with -TicketNumber, <OutputPath or the default root>\Ticket_<n> (reports
# and note together, so the note's evidence names sit beside it); with only -OutputPath, that
# folder; with neither, no files (the note goes to the clipboard, or the console).
$folder = $OutputPath
if ($TicketNumber) {
    $root = if ($OutputPath) { $OutputPath } else { Get-TicketNoteDefaultRoot }
    try {
        $folder = Resolve-TicketFolder -TicketNumber $TicketNumber -Root $root
    }
    catch {
        if (-not $Quiet) { Write-Host ("[WARN] Could not create the ticket folder under {0}: {1}" -f $root, $_.Exception.Message) -ForegroundColor Yellow }
    }
}

$evidencePaths = @()
if ($folder) {
    try {
        $files = Export-NetworkReport -Result $result -OutputPath $folder
        $evidencePaths = @($files)
        if (-not $Quiet) {
            foreach ($file in $files) { Write-Host ('[INFO] Saved {0}' -f $file) -ForegroundColor Cyan }
        }
    }
    catch {
        Write-Host ("[WARN] Could not write the report to {0}: {1}" -f $folder, $_.Exception.Message) -ForegroundColor Yellow
    }
}

$note = $null
if ($script:CaseKitMissing) {
    if (-not $Quiet -and -not $script:CaseKitWarned) { Write-Host '[WARN] CaseKit.ps1 is missing from this folder - no ticket note this time.' -ForegroundColor Yellow }
}
else {
    # The note is extra: a failure while building or saving it never changes the answer or the
    # exit code. The check's own result above stands.
    try {
        $note = ConvertTo-NetworkQuickCheckTicketNote -Result $result -EvidencePaths $evidencePaths
        if ($Quiet) {
            # Another script is the caller: no console and no clipboard. The note is still saved
            # when a folder is in play, and it is always on the result object.
            if ($folder) { $null = Save-TicketNote -Note $note -Folder $folder -PasteSafe:(-not $FullDetail) }
        }
        else {
            $null = Publish-TicketNote -Note $note -Folder $folder -PasteSafe:(-not $FullDetail) -NoClipboard:$NoClipboard
        }
    }
    catch {
        if (-not $Quiet) { Write-Host ("[WARN] Could not make the ticket note: {0}. The check above is still valid." -f $_.Exception.Message) -ForegroundColor Yellow }
        $note = $null
    }
}
$result | Add-Member -NotePropertyName TicketNote -NotePropertyValue $note -Force

if ($PassThru) {
    return $result
}

exit $(switch ($result.Status) { 'Fail' { 2 } 'Warn' { 1 } default { 0 } })
