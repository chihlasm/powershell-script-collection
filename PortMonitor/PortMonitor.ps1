#Requires -Version 3.0

<#
.SYNOPSIS
    Keeps checking whether a list of servers answer on their TCP ports, in a window or in the
    console, and logs every time one goes up or down.

.DESCRIPTION
    Port Monitor checks each target (a host name or IP address plus a TCP port) on its own
    interval and shows the result:

      Open         the port accepted a connection (latency is shown)
      Refused      the server answered but nothing is listening on that port
      Timeout      no answer in time - a firewall dropping traffic, or the host is off
      DNS Failure  the host name could not be resolved
      Error        anything else (for example "network unreachable"); see the Details column

    The name is resolved first (System.Net.Dns), then a TCP connection is attempted
    (System.Net.Sockets.TcpClient). Test-Connection and Test-NetConnection are not used, so it
    works the same on Windows PowerShell 3.0-5.1 and PowerShell 7, needs no module, and does
    not need administrator rights.

    The window (WPF) never freezes: checks run in a background runspace pool and a timer on the
    window collects the results. Up to 16 checks run at the same time.

    Only changes are logged (for example Open -> Timeout), to one CSV file per day. The first
    result for each target after it starts is also logged (PreviousStatus "Not checked") so the
    log shows what state monitoring started in.

    One-off blips are ignored: a target that was Open is only reported down after FailAfter
    failed checks in a row (default 2), and back up after RecoverAfter good checks (default 1).
    Both are set per target (1-10). Until a change is confirmed the target keeps its status and
    the Details column says "Confirming". Fails and Uptime % still count every check.

    Packet loss ("up, but bad"): a port check cannot see lost packets, because TCP resends
    them and the port still answers. A target with MeasureLoss pings the same address after
    each port check (LossPings pings, default 10) and shows Loss % and Jitter. It warns (log,
    notification, amber tray icon) when the loss reaches LossAlertPercent (default 5) for
    FailAfter checks in a row. Zero replies while the port is open means ping is blocked, not
    100 % loss, so it is shown as "no reply" and not reported. Every target also gets a
    "Slow answer" hint in Details when a connect takes far longer than usual, which is often a
    lost packet that had to be resent. Loss changes go to their own daily CSV.

    Adding a server: the Add window has "What is it?" presets (domain controller, file server,
    Remote Desktop, SQL Server, Exchange, web server, network printer, WinRM) that add one row
    per usual port, with the ports from Microsoft's documentation; untick any you don't need.

    Report: the window's Report button (or -Report on the command line) turns the logs into an
    HTML page with each target's uptime %, every outage with start, end and duration, and a
    one-line verdict at the top.

    Keyboard: Insert = Add, Delete = Remove, Enter or F2 = Edit, F5 = Start/Stop. The look
    (dark or light), window size and position, and the grid's sort order are remembered.

    Running in the background: -Tray (or the window's Run in Background button) keeps checking
    with the window hidden. An icon in the notification area shows the overall state (green:
    all open, red: something is not answering, blue: checking, grey: stopped) and a Windows
    notification appears when a target goes down or comes back. Click the icon to open the
    window; closing the window then hides it again; Exit is on the icon's right-click menu,
    which also has "Start when I sign in". The first time it runs in the background it offers to
    add that Startup shortcut. Only one window/icon runs per user session: starting the tool
    again brings the running copy forward.

    Files (defaults; nothing is written anywhere else):
      %APPDATA%\PortMonitor\targets.json                 the target list (auto-saved by the window)
      %APPDATA%\PortMonitor\Logs\PortMonitor_yyyyMMdd.csv state changes, one file per day
      %APPDATA%\PortMonitor\Logs\PortMonitor_Loss_yyyyMMdd.csv packet-loss changes (targets that measure it)
      %APPDATA%\PortMonitor\settings.json                look, window placement, sort order, Startup offer shown
      %APPDATA%\PortMonitor\Logs\Reports\                reports made from the window's Report button
      <Startup folder>\Port Monitor.lnk                  only if the user chooses "Start when I sign in"

    The window auto-saves the target list after every Add, Edit, Remove or Enabled change. If
    the file could not be read when it was loaded (invalid JSON, or entries that had to be
    skipped), the first save keeps a copy of it next to it as targets.json.bak-yyyy-MM-dd_HHmmss
    so nothing is lost. The console mode (-NoGui) never writes the target list.

.PARAMETER ConfigPath
    The target list (JSON) to load. Default: %APPDATA%\PortMonitor\targets.json. A missing file
    means an empty list. In the window, Import switches to another file and auto-save then
    writes to that file.

.PARAMETER LogPath
    The folder for the daily state-change CSV files. Default: %APPDATA%\PortMonitor\Logs.

.PARAMETER NoGui
    Console mode, for RMM tools or a quick look on a server: runs the same checks in a loop,
    shows a coloured status table (or, when the output is redirected, one line per change), and
    logs changes the same way. Stop it with Ctrl+C.

.PARAMETER Once
    Console mode, one pass: check every enabled target once, print the table, and exit.
    Exit code 0 = every enabled target is Open, 1 = at least one is not (or is losing packets at
    or above its LossAlertPercent), 2 = nothing to check (no enabled targets). Implies -NoGui. Meant for RMM checks and scheduled tasks.

.PARAMETER Tray
    Start in the background: no window, an icon in the notification area, checking starts at
    once, and a notification appears for every change. This is what the "Start when I sign in"
    shortcut runs. Cannot be combined with -NoGui or -Once.

.PARAMETER Report
    Make the uptime and outage report from the logs in -LogPath for the last -Days days, write
    PortMonitor_Report_yyyy-MM-dd_HHmmss.html to -OutputPath, and exit. Checks nothing.

.PARAMETER Days
    How many days back the -Report covers (1-366). Default 7.

.PARAMETER OutputPath
    Where -Report writes the HTML file. Default: the current folder.

.PARAMETER SmokeTest
    Checks that this copy of the tool starts, then closes by itself: the real window is built
    and rendered off-screen (it never takes the focus), a probe runs in the background pool,
    and one [PASS] or [FAIL] line is written with exit code 0 (passed) or 1 (failed). Reads no
    target list, checks no ports and writes no file. Needs an STA host (powershell.exe -STA, or
    pwsh). In the repository, Tests\Invoke-SmokeTest.ps1 -ScriptPath PortMonitor\PortMonitor.ps1
    runs it with a time limit.

.PARAMETER LoadFunctionsOnly
    Define the script's functions and return without doing anything. Used by the Pester tests.

.EXAMPLE
    .\PortMonitor.ps1
    Opens the window with the default target list.

.EXAMPLE
    .\PortMonitor.ps1 -ConfigPath '\\fileserver\it\clients\contoso-ports.json'
    Opens the window with one client's target list. Changes are auto-saved to that file.

.EXAMPLE
    .\PortMonitor.ps1 -Report -Days 30 -OutputPath C:\Temp
    Writes a 30-day uptime and outage report from the default logs to C:\Temp.

.EXAMPLE
    .\PortMonitor.ps1 -Tray
    Starts in the background (notification area icon) and notifies on every change.

.EXAMPLE
    .\PortMonitor.ps1 -NoGui -ConfigPath C:\Temp\targets.json -LogPath C:\Temp\PortLogs
    Console mode on a server: a live table, changes logged to C:\Temp\PortLogs.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\PortMonitor.ps1 -Once -ConfigPath .\targets.json
    One pass for an RMM check: exit code 0 when everything is Open, 1 when something is not.

.NOTES
    Version : 1.2.1
    Requires: Windows PowerShell 3.0 or later, or PowerShell 7 on Windows; .NET Framework 4.5
              or later (for TcpClient.ConnectAsync and Dns.GetHostAddressesAsync). No modules,
              no administrator rights.

    Timeouts: TimeoutMs applies to the DNS lookup and, separately, to the TCP connect, so one
    check can take up to twice TimeoutMs. Latency is the TCP connect time only (DNS excluded).
    The default is 3000 ms, not 2000: Windows retries a connection that was answered with a
    reset, so a closed port takes about 2.1 seconds to report "refused" (measured on Windows 11,
    2026-11-16, both on loopback and in Windows PowerShell 5.1 and PowerShell 7). With a
    timeout under ~2200 ms a closed port shows as Timeout instead of Refused. Learn documents
    the SYN retry count ("Max SYN Retransmissions", netsh int tcp show global) but not the
    retry-after-reset timing.

    Packet loss is measured with ICMP echo (System.Net.NetworkInformation.Ping), 200 ms apart,
    each waiting up to TimeoutMs (capped at 2000 ms). Jitter is the mean absolute difference
    between consecutive round-trip times. Slow answers: at least 5 x the median of the last 20
    open connect times and at least 500 ms more. Windows' initial SYN retransmission timeout
    is documented as 3000 ms by default (netsh initialrto), so on such a machine a lost SYN
    shows as a Timeout (and the blip filter hides one) rather than as a slow answer; ping is
    the dependable measure.

    When a name resolves to several addresses, the first IPv4 address is checked (the first
    IPv6 address if there is no IPv4 one). The Details column shows which address was used.

    This file is pure ASCII on purpose: Windows PowerShell reads a BOM-less file as ANSI, so
    icons in the XAML are written as &#x....; entities.

    REFERENCES
    - TcpClient.ConnectAsync(IPAddress, Int32): available in .NET Framework 4.5+ and .NET
      Core/5+; non-usage exceptions (SocketException) are stored in the returned Task and
      thrown when it is waited on.
      https://learn.microsoft.com/dotnet/api/system.net.sockets.tcpclient.connectasync
    - Dns.GetHostAddressesAsync(String): .NET Framework 4.5+; an IP address string is returned
      without a DNS query; resolution errors are a SocketException stored in the Task.
      https://learn.microsoft.com/dotnet/api/system.net.dns.gethostaddressesasync
    - Windows Sockets error codes (WSAECONNREFUSED 10061, WSAETIMEDOUT 10060), surfaced as
      SocketException.SocketErrorCode ConnectionRefused / TimedOut.
      https://learn.microsoft.com/windows/win32/winsock/windows-sockets-error-codes-2
    - Troubleshoot TCP/IP connectivity: SYN retransmissions, Max SYN Retransmissions, ACK+RST
      for a refused SYN.
      https://learn.microsoft.com/troubleshoot/windows-client/networking/tcp-ip-connectivity-issues-troubleshooting
    - ConvertTo-Json (5.1): default -Depth is 2; no -AsArray parameter in 5.1.
      https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/convertto-json?view=powershell-5.1
    - ConvertFrom-Json (5.1): errors on JSON comments in 5.1; PowerShell 6+ accepts them.
      https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/convertfrom-json?view=powershell-5.1
    - Export-Csv: -Append was introduced in Windows PowerShell 3.0; -LiteralPath; the default
      encoding in 5.1 is ASCII, so -Encoding UTF8 is passed.
      https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/export-csv?view=powershell-5.1
    - Dispatcher: a DispatcherObject can only be accessed from the thread that created it, so
      all UI updates happen on the window's thread (the DispatcherTimer tick).
      https://learn.microsoft.com/dotnet/api/system.windows.threading.dispatcher
    - InitialSessionState.CreateDefault2 (used for the background pool, as in
      FolderPermissionManager): loads the default commands through their modules in Windows
      PowerShell and PowerShell 7 alike.
      https://learn.microsoft.com/dotnet/api/system.management.automation.runspaces.initialsessionstate.createdefault2
    - NotifyIcon.Text: maximum 63 characters on .NET Framework and .NET 5, 127 on .NET 6+.
      https://learn.microsoft.com/dotnet/api/system.windows.forms.notifyicon.text
    - NotifyIcon.ShowBalloonTip: one balloon at a time; a newer one from the same app replaces
      it; the timeout is ignored (system accessibility settings decide).
      https://learn.microsoft.com/dotnet/api/system.windows.forms.notifyicon.showballoontip
    - NOTIFYICONDATA: notification title up to 64 and text up to 256 characters including the
      terminating null.
      https://learn.microsoft.com/windows/win32/api/shellapi/ns-shellapi-notifyicondataw
    - Environment.SpecialFolder.Startup: the user's Startup program group, run at every logon.
      https://learn.microsoft.com/dotnet/api/system.environment.specialfolder
    - WshShortcut (CreateShortcut, TargetPath, Arguments, Save) and WindowStyle 7 (minimized).
      https://learn.microsoft.com/previous-versions/windows/internet-explorer/ie-developer/windows-scripting/xk6kst2k(v=vs.84)
      https://learn.microsoft.com/previous-versions/windows/internet-explorer/ie-developer/windows-scripting/w88k7fw2(v=vs.84)
    - Mutex names: "Local\" is shared only within the sign-in session.
      https://learn.microsoft.com/dotnet/api/system.threading.mutex.-ctor
    - Dispatcher.PushFrame (message loop without ShowDialog, so the window can hide and show).
      https://learn.microsoft.com/dotnet/api/system.windows.threading.dispatcher.pushframe
    - Role preset ports: Service overview and network port requirements for Windows (DNS 53,
      Kerberos 88, RPC 135, LDAP 389, SMB 445, Kerberos password 464, LDAP SSL 636, Global
      Catalog 3268/3269, RDS 3389, SQL 1433, HTTP 80, HTTPS 443, WinRM 5985/5986, LPD 515).
      https://learn.microsoft.com/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements
    - Exchange client and mail-flow ports (HTTPS 443, SMTP 25, authenticated SMTP 587).
      https://learn.microsoft.com/exchange/plan-and-deploy/deployment-ref/network-ports
    - Standard TCP/IP port monitor: RAW printing default port 9100.
      https://learn.microsoft.com/troubleshoot/windows-server/printing/standard-port-monitor-for-tcpip
      https://learn.microsoft.com/windows-server/administration/windows-commands/prnport
    - Ping.Send(IPAddress, Int32): a reply not received within the timeout has Status
      TimedOut; RoundtripTime is meaningful for Status Success.
      https://learn.microsoft.com/dotnet/api/system.net.networkinformation.ping.send
      https://learn.microsoft.com/dotnet/api/system.net.networkinformation.pingreply.roundtriptime
    - netsh interface tcp set global: initialrto (initial SYN retransmission timeout, default
      3000 ms) and maxsynretransmissions (default 2).
      https://learn.microsoft.com/windows-server/administration/windows-commands/netsh-interface
    - Troubleshoot TCP/IP connectivity: lost packets are retransmitted; diagnosing packet loss.
      https://learn.microsoft.com/troubleshoot/windows-client/networking/tcp-ip-connectivity-issues-troubleshooting
    - PowerShell support lifecycle (Server 2012 ships 3.0, 2012 R2 ships 4.0).
      https://learn.microsoft.com/powershell/scripting/install/powershell-support-lifecycle
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ConfigPath,

    [Parameter()]
    [string]$LogPath,

    [Parameter()]
    [switch]$NoGui,

    [Parameter()]
    [switch]$Once,

    [Parameter()]
    [switch]$Tray,

    [Parameter()]
    [switch]$Report,

    [Parameter()]
    [ValidateRange(1, 366)]
    [int]$Days = 7,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$SmokeTest,

    [Parameter()]
    [switch]$LoadFunctionsOnly
)

$script:PortMonitorVersion = '1.2.1'
$script:StatusNotChecked = 'Not checked'
$script:StatusDisabled = 'Disabled'
$script:FailureStatuses = @('Refused', 'Timeout', 'DNS Failure', 'Error')

#region Paths

function Get-PortMonitorDefaultRoot {
    # %APPDATA%\PortMonitor. Falls back to LOCALAPPDATA, then TEMP, for odd service contexts
    # where APPDATA is not set.
    $base = $env:APPDATA
    if (-not $base) { $base = $env:LOCALAPPDATA }
    if (-not $base) { $base = [System.IO.Path]::GetTempPath() }
    Join-Path $base 'PortMonitor'
}

function Resolve-PortMonitorPath {
    # Turns a relative path into a full one against PowerShell's current location (not the
    # process's), because the .NET file APIs used below resolve against the process directory.
    param([Parameter(Mandatory)][string]$Path)
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

#endregion

#region Connectivity check (reusable on its own; also copied into the background pool)

function Get-PortCheckFailure {
    <#
    .SYNOPSIS
        Classifies an exception from a connect attempt as Refused, Timeout or Error.
    .DESCRIPTION
        Walks the exception chain (PowerShell's MethodInvocationException -> AggregateException
        -> SocketException) and maps SocketException.SocketErrorCode:
        ConnectionRefused (WSAECONNREFUSED 10061) -> Refused, TimedOut (WSAETIMEDOUT 10060)
        -> Timeout, anything else -> Error.
        https://learn.microsoft.com/windows/win32/winsock/windows-sockets-error-codes-2
    #>
    param(
        [Parameter(Mandatory)][System.Exception]$Exception,
        [int]$Port = 0,
        [int]$TimeoutMs = 0
    )
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue($Exception)
    $innermost = $Exception
    $guard = 0
    while ($queue.Count -gt 0 -and $guard -lt 50) {
        $guard++
        $e = $queue.Dequeue()
        if ($null -eq $e) { continue }
        $innermost = $e
        if ($e -is [System.Net.Sockets.SocketException]) {
            $code = [string]$e.SocketErrorCode
            switch ($code) {
                'ConnectionRefused' {
                    return [PSCustomObject]@{ Status = 'Refused'; Detail = "The host answered, but nothing is listening on port $Port (connection refused)." }
                }
                'TimedOut' {
                    return [PSCustomObject]@{ Status = 'Timeout'; Detail = 'No answer (the connection attempt timed out). A firewall may be dropping the traffic, or the host is off.' }
                }
                default {
                    return [PSCustomObject]@{ Status = 'Error'; Detail = "$code ($($e.ErrorCode)): $($e.Message)" }
                }
            }
        }
        if ($e -is [System.AggregateException]) {
            foreach ($inner in $e.InnerExceptions) { $queue.Enqueue($inner) }
        }
        elseif ($null -ne $e.InnerException) {
            $queue.Enqueue($e.InnerException)
        }
    }
    [PSCustomObject]@{ Status = 'Error'; Detail = "$($innermost.GetType().Name): $($innermost.Message)" }
}

function Test-TcpPort {
    <#
    .SYNOPSIS
        Checks once whether a host accepts a TCP connection on a port.
    .DESCRIPTION
        Resolves the name with System.Net.Dns first, so the result can tell a DNS failure from
        a connection failure, then connects with System.Net.Sockets.TcpClient.ConnectAsync and
        waits up to TimeoutMs. Returns Status (Open, Refused, Timeout, DNS Failure, Error),
        LatencyMs (connect time, Open only), Address (the IP checked) and Detail (plain English).
        The TcpClient is always closed. Works without the rest of this script:
            . .\PortMonitor.ps1 -LoadFunctionsOnly; Test-TcpPort -HostName server01 -Port 443
    .PARAMETER HostName
        A DNS name or an IPv4/IPv6 address.
    .PARAMETER Port
        TCP port, 1-65535.
    .PARAMETER TimeoutMs
        How long to wait for DNS and, separately, for the connection (100-30000 ms). Default
        3000: Windows takes ~2.1 s to report a refused connection (see the script's .NOTES),
        so a shorter timeout reports closed ports as Timeout.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Alias('ComputerName')][string]$HostName,
        [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port,
        [ValidateRange(100, 30000)][int]$TimeoutMs = 3000
    )

    $result = [PSCustomObject]@{
        HostName  = $HostName
        Port      = $Port
        Status    = 'Error'
        LatencyMs = $null
        Address   = $null
        Detail    = ''
        Timestamp = (Get-Date)
    }
    $name = $HostName.Trim()
    if (-not $name) {
        $result.Detail = 'No host name or address was given.'
        return $result
    }

    # 1. DNS. An IP address string is returned as-is without a query (Dns.GetHostAddressesAsync
    #    docs), but parse it here anyway so a literal never waits on a resolver.
    $addresses = @()
    $literal = $null
    if ([System.Net.IPAddress]::TryParse($name, [ref]$literal)) {
        $addresses = @($literal)
    }
    else {
        try {
            $dnsTask = [System.Net.Dns]::GetHostAddressesAsync($name)
            if (-not $dnsTask.Wait($TimeoutMs)) {
                $result.Status = 'DNS Failure'
                $result.Detail = "DNS did not answer for '$name' within $TimeoutMs ms."
                return $result
            }
            $addresses = @($dnsTask.Result)
        }
        catch {
            $inner = $_.Exception
            while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
            $result.Status = 'DNS Failure'
            $result.Detail = "The name '$name' could not be resolved: $($inner.Message)"
            return $result
        }
        if ($addresses.Count -eq 0) {
            $result.Status = 'DNS Failure'
            $result.Detail = "The name '$name' resolved to no addresses."
            return $result
        }
    }

    # Prefer IPv4: the client is created for that one address family, which behaves the same
    # on .NET Framework (Windows PowerShell) and .NET (PowerShell 7).
    $target = $addresses | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -First 1
    if ($null -eq $target) { $target = $addresses[0] }
    $result.Address = $target.ToString()

    # 2. TCP connect. ConnectAsync stores a SocketException in the task; Wait() rethrows it
    #    wrapped in an AggregateException (TcpClient.ConnectAsync docs). A Wait() that returns
    #    false means no answer within the timeout; closing the client abandons the attempt.
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient -ArgumentList $target.AddressFamily
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $task = $client.ConnectAsync($target, $Port)
        $completed = $task.Wait($TimeoutMs)
        $watch.Stop()
        if ($completed -and $client.Connected) {
            $result.Status = 'Open'
            $result.LatencyMs = [math]::Round($watch.Elapsed.TotalMilliseconds, 1)
            $result.Detail = "Connected to $($result.Address) on port $Port."
        }
        elseif (-not $completed) {
            $result.Status = 'Timeout'
            $result.Detail = "No answer from $($result.Address) within $TimeoutMs ms. A firewall may be dropping the traffic, or the host is off."
        }
        else {
            $result.Status = 'Error'
            $result.Detail = "The connection to $($result.Address) did not complete."
        }
    }
    catch {
        $failure = Get-PortCheckFailure -Exception $_.Exception -Port $Port -TimeoutMs $TimeoutMs
        $result.Status = $failure.Status
        $result.Detail = "$($result.Address): $($failure.Detail)"
    }
    finally {
        # Close() disposes the TcpClient in every .NET version (Dispose() is not public on
        # .NET Framework 4.5).
        if ($null -ne $client) { try { $client.Close() } catch { } }
    }
    $result
}

function ConvertTo-PortPingSummary {
    <#
    .SYNOPSIS
        Turns one burst of ping round-trip times into Sent, Received, LossPercent, AvgMs and
        JitterMs. Pure: no network.
    .PARAMETER RoundTrips
        One entry per ping sent: the round-trip time in ms, or $null for no reply.
    .DESCRIPTION
        Jitter is the average difference between consecutive replies (the idea behind RFC 3550's
        interarrival jitter, without its smoothing), so it shows how uneven the answers are.
        It needs at least two replies; otherwise it is $null.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$RoundTrips = @())
    $all = @($RoundTrips)
    $replies = @($all | Where-Object { $null -ne $_ } | ForEach-Object { [double]$_ })
    $sent = $all.Count
    $received = $replies.Count
    $loss = $null
    if ($sent -gt 0) { $loss = [math]::Round(100.0 * ($sent - $received) / $sent, 1) }
    $avg = $null
    if ($received -gt 0) { $avg = [math]::Round((($replies | Measure-Object -Sum).Sum) / $received, 1) }
    $jitter = $null
    if ($received -ge 2) {
        $total = 0.0
        for ($i = 1; $i -lt $received; $i++) { $total += [math]::Abs($replies[$i] - $replies[$i - 1]) }
        $jitter = [math]::Round($total / ($received - 1), 1)
    }
    [PSCustomObject]@{ Sent = $sent; Received = $received; LossPercent = $loss; AvgMs = $avg; JitterMs = $jitter }
}

function Measure-PingLoss {
    <#
    .SYNOPSIS
        Sends a burst of pings (ICMP echo) to one address and reports how many were lost.
    .DESCRIPTION
        Uses System.Net.NetworkInformation.Ping.Send(IPAddress, Int32): a reply that does not
        arrive within the timeout comes back with Status TimedOut, and only Status Success
        carries a usable RoundtripTime. No administrator rights are needed on Windows.
        https://learn.microsoft.com/dotnet/api/system.net.networkinformation.ping.send
        https://learn.microsoft.com/dotnet/api/system.net.networkinformation.pingreply.roundtriptime
        Pings are spaced GapMs apart so a short burst of loss is less likely to hit every one.
        A PingException (for example no route to the address) stops the burst; it comes back as
        Error with the counts set to $null, because it says nothing about loss on the wire.
        Many firewalls drop pings: zero replies while the port is open means "ping is blocked",
        not "100 % loss" - Update-PortTargetQuality makes that call, not this function.
    .OUTPUTS
        PSCustomObject: Sent, Received, LossPercent, AvgMs, JitterMs, Error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Address,
        [ValidateRange(1, 50)][int]$Count = 10,
        [ValidateRange(100, 5000)][int]$TimeoutMs = 1000,
        [ValidateRange(0, 5000)][int]$GapMs = 200
    )
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$ip)) {
        return [PSCustomObject]@{ Sent = $null; Received = $null; LossPercent = $null; AvgMs = $null; JitterMs = $null; Error = "'$Address' is not an IP address." }
    }
    $times = New-Object System.Collections.ArrayList
    $ping = New-Object System.Net.NetworkInformation.Ping
    try {
        for ($i = 0; $i -lt $Count; $i++) {
            if ($i -gt 0 -and $GapMs -gt 0) { Start-Sleep -Milliseconds $GapMs }
            $reply = $ping.Send($ip, $TimeoutMs)
            if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) { [void]$times.Add([double]$reply.RoundtripTime) }
            else { [void]$times.Add($null) }
        }
    }
    catch {
        $inner = $_.Exception
        while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
        return [PSCustomObject]@{ Sent = $null; Received = $null; LossPercent = $null; AvgMs = $null; JitterMs = $null; Error = "Ping could not be sent to ${Address}: $($inner.Message)" }
    }
    finally {
        # Ping is a Component (IDisposable) in .NET Framework 2.0+ and .NET.
        try { $ping.Dispose() } catch { }
    }
    $summary = ConvertTo-PortPingSummary -RoundTrips @($times)
    $summary | Add-Member -NotePropertyName Error -NotePropertyValue $null
    $summary
}

function Invoke-PortTargetCheck {
    <#
    .SYNOPSIS
        What the background pool runs for one target: the port check, then (with -MeasureLoss
        and an address to ping) a burst of pings to the same address. The port result is
        returned with a Loss property ($null when loss was not measured).
    .DESCRIPTION
        The pings go to the address the port check used, so DNS is not asked twice and both
        measurements are of the same machine. Each ping waits at most TimeoutMs, capped at
        2000 ms so a burst cannot run for minutes.
    #>
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutMs = 3000,
        [switch]$MeasureLoss,
        [int]$LossPings = 10
    )
    $result = Test-TcpPort -HostName $HostName -Port $Port -TimeoutMs $TimeoutMs
    $loss = $null
    if ($MeasureLoss -and $result.Address) {
        $pingTimeout = [math]::Min([math]::Max($TimeoutMs, 100), 2000)
        $count = [math]::Min([math]::Max($LossPings, 1), 50)
        $loss = Measure-PingLoss -Address $result.Address -Count $count -TimeoutMs $pingTimeout
    }
    $result | Add-Member -NotePropertyName Loss -NotePropertyValue $loss -Force
    $result
}

#endregion

#region Targets and config file

function Get-PortTargetField {
    # Reads a field from a PSCustomObject (ConvertFrom-Json) or a hashtable, case-insensitively.
    param($InputObject, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) { if ("$key" -eq $Name) { return $InputObject[$key] } }
        return $null
    }
    $p = $InputObject.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    $null
}

function ConvertTo-PortTarget {
    <#
    .SYNOPSIS
        Normalises anything target-shaped (JSON entry, hashtable, grid row) into the saved schema:
        Label, Host, Port, IntervalSec, TimeoutMs, Enabled, FailAfter, RecoverAfter, MeasureLoss,
        LossPings, LossAlertPercent.
    .DESCRIPTION
        Blank IntervalSec / TimeoutMs / Enabled / FailAfter / RecoverAfter / MeasureLoss /
        LossPings / LossAlertPercent get defaults (30 s, 3000 ms, true, 2, 1, false, 10, 5). A
        value that is present but not a whole number becomes 0 so validation reports it instead
        of a default silently replacing it. A blank Label becomes "Host:Port". Lists saved by
        older versions (no FailAfter/RecoverAfter, no loss fields) load with the defaults.
    #>
    param([Parameter(Mandatory)][AllowNull()]$InputObject)

    $toInt = {
        param($value, [int]$default)
        if ($null -eq $value -or "$value".Trim() -eq '') { return $default }
        $n = 0
        if ([int]::TryParse("$value".Trim(), [ref]$n)) { return $n }
        0
    }
    $hostValue = "$(Get-PortTargetField $InputObject 'Host')".Trim()
    $port = & $toInt (Get-PortTargetField $InputObject 'Port') 0
    $interval = & $toInt (Get-PortTargetField $InputObject 'IntervalSec') 30
    $timeout = & $toInt (Get-PortTargetField $InputObject 'TimeoutMs') 3000
    $failAfter = & $toInt (Get-PortTargetField $InputObject 'FailAfter') 2
    $recoverAfter = & $toInt (Get-PortTargetField $InputObject 'RecoverAfter') 1
    $lossPings = & $toInt (Get-PortTargetField $InputObject 'LossPings') 10
    $lossAlert = & $toInt (Get-PortTargetField $InputObject 'LossAlertPercent') 5

    $toBool = {
        param($raw, [bool]$default)
        if ($null -eq $raw -or "$raw".Trim() -eq '') { return $default }
        if ($raw -is [bool]) { return $raw }
        @('true', '1', 'yes', 'on') -contains "$raw".Trim().ToLowerInvariant()
    }
    $enabled = & $toBool (Get-PortTargetField $InputObject 'Enabled') $true
    $measureLoss = & $toBool (Get-PortTargetField $InputObject 'MeasureLoss') $false

    $label = "$(Get-PortTargetField $InputObject 'Label')".Trim()
    if (-not $label -and $hostValue) { $label = "${hostValue}:$port" }

    [PSCustomObject]@{
        Label       = $label
        Host        = $hostValue
        Port        = $port
        IntervalSec = $interval
        TimeoutMs    = $timeout
        Enabled      = [bool]$enabled
        FailAfter    = $failAfter
        RecoverAfter = $recoverAfter
        MeasureLoss      = [bool]$measureLoss
        LossPings        = $lossPings
        LossAlertPercent = $lossAlert
    }
}

function Test-PortTargetDefinition {
    # Returns the problems with a target in plain English; an empty array means it is valid.
    param([Parameter(Mandatory)]$Target)
    $t = ConvertTo-PortTarget $Target
    $problems = New-Object System.Collections.ArrayList
    if (-not $t.Host) { [void]$problems.Add('Host is blank: enter a server name or IP address.') }
    elseif ($t.Host -match '\s') { [void]$problems.Add('Host cannot contain spaces.') }
    if ($t.Port -lt 1 -or $t.Port -gt 65535) { [void]$problems.Add('Port must be a whole number from 1 to 65535.') }
    if ($t.IntervalSec -lt 1) { [void]$problems.Add('Check every must be at least 1 second.') }
    if ($t.TimeoutMs -lt 100 -or $t.TimeoutMs -gt 30000) { [void]$problems.Add('Timeout must be from 100 to 30000 ms.') }
    if ($t.FailAfter -lt 1 -or $t.FailAfter -gt 10) { [void]$problems.Add('Down after must be from 1 to 10 failed checks.') }
    if ($t.RecoverAfter -lt 1 -or $t.RecoverAfter -gt 10) { [void]$problems.Add('Back up after must be from 1 to 10 good checks.') }
    if ($t.LossPings -lt 1 -or $t.LossPings -gt 50) { [void]$problems.Add('Pings per check must be from 1 to 50.') }
    if ($t.LossAlertPercent -lt 1 -or $t.LossAlertPercent -gt 100) { [void]$problems.Add('Alert above must be from 1 to 100 % lost.') }
    # Emitted one by one (no leading comma): callers wrap in @() and count.
    foreach ($p in $problems) { [string]$p }
}

function Get-PortMonitorPortSets {
    <#
    .SYNOPSIS
        Role presets: the TCP ports to watch for common kinds of server, so a technician picks
        "Domain controller" instead of typing seven ports.
    .DESCRIPTION
        Ports and service names are from Microsoft's documentation:
        - Domain controller, file server, SQL Server, Remote Desktop, web, WinRM, LPD:
          "Service overview and network port requirements for Windows" - DNS 53, Kerberos 88,
          RPC 135, LDAP 389, SMB 445, Kerberos Password V5 464, LDAP SSL 636, Global Catalog
          3268/3269, RDS 3389, SQL over TCP 1433, HTTP 80, HTTPS 443, WinRM 5985/5986, LPD 515.
          https://learn.microsoft.com/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements
        - Exchange: HTTPS 443 (Outlook, OWA, ActiveSync, EWS, Autodiscover), SMTP 25 (inbound
          mail), authenticated SMTP 587 (client submission).
          https://learn.microsoft.com/exchange/plan-and-deploy/deployment-ref/network-ports
        - Network printer: RAW 9100 is the Standard TCP/IP port monitor's default.
          https://learn.microsoft.com/troubleshoot/windows-server/printing/standard-port-monitor-for-tcpip
        SQL Server 1433 is the default instance; named instances use another (often dynamic)
        port, which the preset cannot know - the Port field can be changed after adding.
    #>
    $set = {
        param([string]$Name, [string]$Description, [object[]]$Ports)
        [PSCustomObject]@{
            Name        = $Name
            Description = $Description
            Ports       = @(foreach ($p in $Ports) { [PSCustomObject]@{ Port = [int]$p[0]; Service = [string]$p[1] } })
        }
    }
    @(
        & $set 'Domain controller' 'Active Directory: DNS, Kerberos, LDAP, Global Catalog, SMB (SYSVOL/logon scripts)' @(
            @(53, 'DNS'), @(88, 'Kerberos'), @(135, 'RPC'), @(389, 'LDAP'), @(445, 'SMB'),
            @(464, 'Kerberos password change'), @(636, 'LDAP SSL'), @(3268, 'Global Catalog'), @(3269, 'Global Catalog SSL'))
        & $set 'File server' 'File shares (SMB)' @(, @(445, 'SMB'))
        & $set 'Remote Desktop server' 'RDP; RD Gateway and RD Web also answer on HTTPS' @(@(3389, 'RDP'), @(443, 'HTTPS (RD Gateway / RD Web)'))
        & $set 'SQL Server' 'Default instance' @(, @(1433, 'SQL Server'))
        & $set 'Exchange server' 'Outlook/OWA/ActiveSync over HTTPS, inbound mail, client SMTP' @(@(443, 'HTTPS'), @(25, 'SMTP'), @(587, 'SMTP submission'))
        & $set 'Web server' 'HTTP and HTTPS' @(@(80, 'HTTP'), @(443, 'HTTPS'))
        & $set 'Network printer' 'RAW printing (Standard TCP/IP port) and LPD' @(@(9100, 'RAW printing'), @(515, 'LPD'))
        & $set 'Remote management (WinRM)' 'PowerShell remoting' @(@(5985, 'WinRM HTTP'), @(5986, 'WinRM HTTPS'))
    )
}

function New-PortTargetsFromSet {
    <#
    .SYNOPSIS
        One target per port of a preset, labelled "<name> - <service>". Ports already monitored
        on that host (ExistingTargets) are left out so nothing is added twice.
    .DESCRIPTION
        Packet loss belongs to the host, not the port, so with MeasureLoss only the first target
        created measures it; pinging the same host once per port would add nothing but traffic.
    #>
    param(
        [Parameter(Mandatory)]$Set,
        [Parameter(Mandatory)][string]$HostName,
        [string]$Name,
        [int[]]$Ports,
        [int]$IntervalSec = 30,
        [int]$TimeoutMs = 3000,
        [int]$FailAfter = 2,
        [int]$RecoverAfter = 1,
        [bool]$Enabled = $true,
        [bool]$MeasureLoss = $false,
        [int]$LossPings = 10,
        [int]$LossAlertPercent = 5,
        [AllowNull()][AllowEmptyCollection()][object[]]$ExistingTargets = @()
    )
    $hostValue = $HostName.Trim()
    if (-not $Name) { $Name = $hostValue }
    $taken = @{}
    foreach ($e in @($ExistingTargets)) { if ($e) { $taken["$($e.Host)".ToLowerInvariant() + ':' + [int]$e.Port] = $true } }
    $lossLeft = $MeasureLoss
    foreach ($p in $Set.Ports) {
        if ($PSBoundParameters.ContainsKey('Ports') -and $Ports -notcontains $p.Port) { continue }
        if ($taken.ContainsKey($hostValue.ToLowerInvariant() + ':' + $p.Port)) { continue }
        ConvertTo-PortTarget ([PSCustomObject]@{
                Label = "$Name - $($p.Service)"; Host = $hostValue; Port = $p.Port; IntervalSec = $IntervalSec
                TimeoutMs = $TimeoutMs; Enabled = $Enabled; FailAfter = $FailAfter; RecoverAfter = $RecoverAfter
                MeasureLoss = $lossLeft; LossPings = $LossPings; LossAlertPercent = $LossAlertPercent
            })
        $lossLeft = $false
    }
}

function Read-PortMonitorConfig {
    <#
    .SYNOPSIS
        Loads a target list. Never throws: a missing file is an empty list; invalid JSON or
        invalid entries come back as Warnings with NeedsBackup set.
    .OUTPUTS
        PSCustomObject: Path, Targets (array), Warnings (string[]), NeedsBackup (bool).
    #>
    param([Parameter(Mandatory)][string]$Path)

    $targets = New-Object System.Collections.ArrayList
    $warnings = New-Object System.Collections.ArrayList
    $needsBackup = $false
    $make = {
        [PSCustomObject]@{
            Path        = $Path
            Targets     = @($targets)
            Warnings    = [string[]]@($warnings)
            NeedsBackup = $needsBackup
        }
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return (& $make) }

    try { $raw = [System.IO.File]::ReadAllText($Path) }
    catch {
        [void]$warnings.Add("Could not read '$Path': $($_.Exception.Message)")
        $needsBackup = $true
        return (& $make)
    }
    if ([string]::IsNullOrWhiteSpace($raw)) { return (& $make) }

    try { $parsed = ConvertFrom-Json -InputObject $raw -ErrorAction Stop }
    catch {
        [void]$warnings.Add("'$Path' is not valid JSON, so the target list starts empty. The file has not been changed. ($($_.Exception.Message))")
        $needsBackup = $true
        return (& $make)
    }

    # Windows PowerShell 5.1 outputs a JSON array as ONE array object; PowerShell 7 enumerates
    # it, so a one-element array arrives as a single object. Normalise both, and also accept
    # an object with a Targets array.
    $items = @()
    if ($null -ne $parsed) {
        if ($parsed -is [System.Array]) { $items = @($parsed) }
        elseif ($parsed.PSObject.Properties['Targets']) { $items = @($parsed.Targets) }
        else { $items = @($parsed) }
    }

    $index = 0
    foreach ($item in $items) {
        $index++
        if ($null -eq $item) { continue }
        $t = ConvertTo-PortTarget $item
        $problems = @(Test-PortTargetDefinition $t)
        if ($problems.Count -gt 0) {
            $name = $t.Label
            if (-not $name) { $name = '(no label)' }
            [void]$warnings.Add("Entry $index ($name) was skipped: $($problems -join ' ')")
            $needsBackup = $true
            continue
        }
        [void]$targets.Add($t)
    }
    & $make
}

function Save-PortMonitorConfig {
    <#
    .SYNOPSIS
        Writes the target list as a JSON array (UTF-8, no BOM). Creates the folder if missing.
    .PARAMETER BackupExisting
        Copy the current file to <file>.bak-yyyy-MM-dd_HHmmss first (used for the first save
        after a file could not be fully read, so nothing in it is lost).
    .OUTPUTS
        PSCustomObject: Path, Count, BackupPath ($null when no backup was made).
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [AllowNull()][AllowEmptyCollection()][object[]]$Targets = @(),
        [switch]$BackupExisting
    )
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
    }

    $backup = $null
    if ($BackupExisting -and (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $backup = '{0}.bak-{1}' -f $Path, (Get-Date -Format 'yyyy-MM-dd_HHmmss')
        Copy-Item -LiteralPath $Path -Destination $backup -Force -ErrorAction Stop
    }

    $clean = @(foreach ($t in @($Targets)) { if ($null -ne $t) { ConvertTo-PortTarget $t } })
    if ($clean.Count -eq 0) { $json = '[]' }
    else {
        # -InputObject (not the pipeline) keeps a one-element list as a JSON array on 5.1.
        $json = ConvertTo-Json -InputObject $clean -Depth 3
    }

    # Write to a temp file and swap it in, so a crash mid-write cannot leave a half file.
    $utf8NoBom = New-Object System.Text.UTF8Encoding -ArgumentList $false
    $temp = "$Path.tmp"
    [System.IO.File]::WriteAllText($temp, $json, $utf8NoBom)
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        try { [System.IO.File]::Replace($temp, $Path, $null) }
        catch {
            [System.IO.File]::Copy($temp, $Path, $true)
            Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        [System.IO.File]::Move($temp, $Path)
    }
    [PSCustomObject]@{ Path = $Path; Count = $clean.Count; BackupPath = $backup }
}

#endregion

#region Monitoring state (pure: no network, no UI)

function New-PortTargetState {
    # A live row for one target: the saved fields plus what monitoring has seen so far.
    param([Parameter(Mandatory)]$Target)
    $t = ConvertTo-PortTarget $Target
    $status = $script:StatusNotChecked
    if (-not $t.Enabled) { $status = $script:StatusDisabled }
    [PSCustomObject]@{
        Id              = [guid]::NewGuid().ToString()
        Enabled         = $t.Enabled
        Label           = $t.Label
        Host            = $t.Host
        Port            = $t.Port
        IntervalSec     = $t.IntervalSec
        TimeoutMs       = $t.TimeoutMs
        FailAfter       = $t.FailAfter
        RecoverAfter    = $t.RecoverAfter
        MeasureLoss     = $t.MeasureLoss
        LossPings       = $t.LossPings
        LossAlertPercent = $t.LossAlertPercent
        LossPercent     = $null
        JitterMs        = $null
        LossStatus      = $null
        LastKnownLossStatus = $null
        LossHighStreak  = 0
        LossOkStreak    = 0
        PingsSent       = 0
        PingsReceived   = 0
        LossText        = ''
        LatencyHistory  = New-Object System.Collections.ArrayList
        SlowCount       = 0
        FailStreak      = 0
        OkStreak        = 0
        Status          = $status
        LatencyMs       = $null
        LastChecked     = $null
        LastStateChange = $null
        FailCount       = 0
        UptimePercent   = $null
        Checks          = 0
        OpenCount       = 0
        LastKnownStatus = $null
        Detail          = ''
        NextDue         = [datetime]::MinValue
        InFlight        = $false
    }
}

function Update-PortTargetState {
    <#
    .SYNOPSIS
        Applies one check result to a target's state. Returns a change record when the
        confirmed status changes (including the first result), otherwise nothing.
    .DESCRIPTION
        Blip suppression: going from Open to not-open is only reported after FailAfter failed
        checks in a row, and back to Open after RecoverAfter good checks in a row. Until then
        Status keeps the confirmed value and Detail says the change is being confirmed. The
        first result after monitoring starts is accepted at once (there is no known-good state
        to protect), and a change between two failure kinds (Timeout -> Refused) is reported at
        once because the target is down either way.
        FailCount and UptimePercent count every check, confirmed or not (Uptime % = Open checks
        / all checks).
    #>
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)]$Result,
        [datetime]$Now = (Get-Date)
    )
    $raw = [string]$Result.Status
    $isOpen = $raw -eq 'Open'
    $State.Checks = [int]$State.Checks + 1
    if ($isOpen) {
        $State.OpenCount = [int]$State.OpenCount + 1
        $State.LatencyMs = $Result.LatencyMs
        $State.OkStreak = [int]$State.OkStreak + 1
        $State.FailStreak = 0
    }
    else {
        $State.FailCount = [int]$State.FailCount + 1
        $State.LatencyMs = $null
        $State.FailStreak = [int]$State.FailStreak + 1
        $State.OkStreak = 0
    }
    $State.UptimePercent = [math]::Round(100.0 * $State.OpenCount / $State.Checks, 1)
    $State.LastChecked = $Now
    $State.Detail = [string]$Result.Detail

    $previous = $State.LastKnownStatus
    if ($previous -and (($previous -eq 'Open') -ne $isOpen)) {
        # Crossing between up and down: wait for the streak.
        $needed = [int]$State.FailAfter
        $streak = [int]$State.FailStreak
        if ($isOpen) { $needed = [int]$State.RecoverAfter; $streak = [int]$State.OkStreak }
        if ($needed -lt 1) { $needed = 1 }
        if ($streak -lt $needed) {
            $State.Status = $previous
            $State.Detail = "Confirming: $raw ($streak of $needed in a row). $($Result.Detail)"
            return
        }
    }
    $newStatus = $raw
    $State.Status = $newStatus
    if ($previous -eq $newStatus) { return }
    $State.LastKnownStatus = $newStatus
    $State.LastStateChange = $Now
    if (-not $previous) { $previous = $script:StatusNotChecked }
    [PSCustomObject]@{
        Kind           = 'State'
        Timestamp      = $Now
        Label          = $State.Label
        Host           = $State.Host
        Port           = $State.Port
        PreviousStatus = $previous
        NewStatus      = $newStatus
        LatencyMs      = $State.LatencyMs
    }
}

function Get-PortLatencySpike {
    <#
    .SYNOPSIS
        Says whether a connect time is far above the target's usual one. Pure.
    .DESCRIPTION
        A TCP connection whose first packet is lost still succeeds once Windows resends it, but
        the connect time jumps by the resend wait (initial retransmission timeout; netsh
        documents a default of 3000 ms, configurable as initialrto, so a resend can also take
        longer than TimeoutMs and show as Timeout instead).
        https://learn.microsoft.com/windows-server/administration/windows-commands/netsh-interface
        "Usual" is the median of the recent open connect times (at least 5 needed). A spike is
        at least 5 times the usual AND at least 500 ms more, so a fast LAN target at 1 ms is
        not flagged for 6 ms, and a WAN target at 120 ms is not flagged for 300 ms.
    .OUTPUTS
        PSCustomObject (IsSpike, UsualMs), or $null when there is not enough history yet.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$History = @(), [Parameter(Mandatory)][double]$LatencyMs)
    $samples = @($History | Where-Object { $null -ne $_ } | ForEach-Object { [double]$_ } | Sort-Object)
    if ($samples.Count -lt 5) { return $null }
    $mid = [int][math]::Floor($samples.Count / 2)
    if ($samples.Count % 2 -eq 1) { $usual = $samples[$mid] }
    else { $usual = ($samples[$mid - 1] + $samples[$mid]) / 2 }
    $isSpike = ($LatencyMs -ge 5 * $usual) -and ($LatencyMs -ge $usual + 500)
    [PSCustomObject]@{ IsSpike = [bool]$isSpike; UsualMs = [math]::Round($usual, 1) }
}

function Update-PortTargetQuality {
    <#
    .SYNOPSIS
        Applies the "is the connection good, not just up" part of a check result: slow-answer
        hints from the connect time and, when the target measures it, packet loss from pings.
        Returns a loss change record (Kind 'Loss') when the confirmed loss state changes.
    .DESCRIPTION
        Call after Update-PortTargetState with the same result.
        Slow answers: an Open result far above the usual connect time (Get-PortLatencySpike)
        adds to SlowCount and says in Detail that a packet was probably lost and resent. Not
        logged or notified on its own: one resend is normal on any network.
        Packet loss, per burst of pings (Result.Loss):
          OK          loss below LossAlertPercent
          High loss   loss at or above LossAlertPercent
          No replies  no ping answered while the port is open: a firewall drops pings, so loss
                      cannot be measured here (not reported as loss, and not notified)
        Going from OK to High loss needs FailAfter bursts in a row and back needs RecoverAfter,
        like the port status. The first state is accepted at once. While the port is not Open
        the loss state is left alone: the outage is already reported, and every ping failing
        then says nothing new.
    #>
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)]$Result,
        [datetime]$Now = (Get-Date)
    )
    $isOpen = [string]$Result.Status -eq 'Open'

    # --- Slow answers (every target) ---
    if ($isOpen -and $null -ne $Result.LatencyMs) {
        $spike = Get-PortLatencySpike -History @($State.LatencyHistory) -LatencyMs ([double]$Result.LatencyMs)
        if ($spike -and $spike.IsSpike) {
            $State.SlowCount = [int]$State.SlowCount + 1
            $State.Detail = "Slow answer: $($Result.LatencyMs) ms (usually $($spike.UsualMs) ms), often a lost packet that had to be resent. $($State.Detail)"
        }
        [void]$State.LatencyHistory.Add([double]$Result.LatencyMs)
        while ($State.LatencyHistory.Count -gt 20) { $State.LatencyHistory.RemoveAt(0) }
    }

    # --- Packet loss (targets that measure it) ---
    if (-not $State.MeasureLoss) { return }
    $loss = $Result.PSObject.Properties['Loss']
    if ($null -eq $loss -or $null -eq $loss.Value) {
        if (-not $isOpen) { $State.LossPercent = $null; $State.JitterMs = $null; $State.LossText = '' }
        return
    }
    $loss = $loss.Value
    if ($loss.Error -or $null -eq $loss.Sent) {
        $State.LossPercent = $null; $State.JitterMs = $null; $State.LossText = 'error'
        $State.Detail = "$($State.Detail) Packet loss not measured: $($loss.Error)".Trim()
        return
    }
    $State.PingsSent = [int]$State.PingsSent + [int]$loss.Sent
    $State.PingsReceived = [int]$State.PingsReceived + [int]$loss.Received
    $State.LossPercent = $loss.LossPercent
    $State.JitterMs = $loss.JitterMs
    if ([int]$loss.Received -eq 0) { $State.LossText = 'no reply' }
    else { $State.LossText = ('{0:0.0}' -f [double]$loss.LossPercent) }
    if (-not $isOpen) { return }

    if ([int]$loss.Received -eq 0) { $raw = 'No replies' }
    elseif ([double]$loss.LossPercent -ge [double]$State.LossAlertPercent) { $raw = 'High loss' }
    else { $raw = 'OK' }
    if ($raw -eq 'High loss') { $State.LossHighStreak = [int]$State.LossHighStreak + 1; $State.LossOkStreak = 0 }
    elseif ($raw -eq 'OK') { $State.LossOkStreak = [int]$State.LossOkStreak + 1; $State.LossHighStreak = 0 }
    else { $State.LossHighStreak = 0; $State.LossOkStreak = 0 }

    $summary = "$($loss.Received) of $($loss.Sent) pings answered ($($State.LossText) % lost"
    if ($raw -eq 'No replies') { $summary = "No ping answered ($($loss.Sent) sent) although the port is open: a firewall probably blocks ping, so packet loss cannot be measured for this host" }
    else {
        if ($null -ne $loss.JitterMs) { $summary += ", jitter $($loss.JitterMs) ms" }
        $summary += ')'
    }

    $previous = $State.LastKnownLossStatus
    if (($previous -eq 'OK' -and $raw -eq 'High loss') -or ($previous -eq 'High loss' -and $raw -eq 'OK')) {
        $needed = [int]$State.FailAfter; $streak = [int]$State.LossHighStreak
        if ($raw -eq 'OK') { $needed = [int]$State.RecoverAfter; $streak = [int]$State.LossOkStreak }
        if ($needed -lt 1) { $needed = 1 }
        if ($streak -lt $needed) {
            $State.LossStatus = $previous
            $State.Detail = "$($State.Detail) Packet loss: $summary. Confirming $raw ($streak of $needed in a row).".Trim()
            return
        }
    }
    $State.LossStatus = $raw
    $State.Detail = "$($State.Detail) Packet loss: $summary.".Trim()
    if ($previous -eq $raw) { return }
    $State.LastKnownLossStatus = $raw
    if (-not $previous) { $previous = $script:StatusNotChecked }
    [PSCustomObject]@{
        Kind           = 'Loss'
        Timestamp      = $Now
        Label          = $State.Label
        Host           = $State.Host
        Port           = $State.Port
        PreviousStatus = $previous
        NewStatus      = $raw
        LossPercent    = $loss.LossPercent
        JitterMs       = $loss.JitterMs
        AvgMs          = $loss.AvgMs
        Sent           = $loss.Sent
        Received       = $loss.Received
    }
}

function Reset-PortTargetLoss {
    # Clears what loss measuring has seen (used when it is turned on or off in Edit).
    param([Parameter(Mandatory)]$State)
    $State.LossPercent = $null; $State.JitterMs = $null; $State.LossText = ''
    $State.LossStatus = $null; $State.LastKnownLossStatus = $null
    $State.LossHighStreak = 0; $State.LossOkStreak = 0
    $State.PingsSent = 0; $State.PingsReceived = 0
}

function Set-PortTargetEnabled {
    # Turns a target on or off. Off shows "Disabled"; on shows "Not checked" and checks it on
    # the next tick. The last known status is kept so a change while it was off is still logged.
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][bool]$Enabled)
    $State.Enabled = $Enabled
    $State.FailStreak = 0
    $State.OkStreak = 0
    if ($Enabled) {
        $State.Status = $script:StatusNotChecked
        $State.NextDue = [datetime]::MinValue
    }
    else {
        $State.Status = $script:StatusDisabled
        $State.LatencyMs = $null
        $State.LossPercent = $null
        $State.JitterMs = $null
        $State.LossText = ''
        $State.LossStatus = $null
    }
}

function Get-DuePortTargets {
    # The enabled targets whose interval has elapsed and that have no check running, oldest first.
    param([AllowNull()][AllowEmptyCollection()][object[]]$States = @(), [datetime]$Now = (Get-Date))
    @($States | Where-Object { $_ -and $_.Enabled -and -not $_.InFlight -and $_.NextDue -le $Now } | Sort-Object NextDue)
}

function Write-PortStateChangeLog {
    <#
    .SYNOPSIS
        Appends one state change to <LogDirectory>\PortMonitor_yyyyMMdd.csv (date of the change).
        Never throws: a locked file (open in Excel) comes back as Ok = $false with the reason.
    #>
    param(
        [Parameter(Mandatory)][string]$LogDirectory,
        [Parameter(Mandatory)]$Change
    )
    $file = Join-Path $LogDirectory ('PortMonitor_{0}.csv' -f $Change.Timestamp.ToString('yyyyMMdd'))
    try {
        if (-not (Test-Path -LiteralPath $LogDirectory)) {
            New-Item -ItemType Directory -Path $LogDirectory -Force -ErrorAction Stop | Out-Null
        }
        $latency = ''
        if ($null -ne $Change.LatencyMs) { $latency = ([double]$Change.LatencyMs).ToString([System.Globalization.CultureInfo]::InvariantCulture) }
        $row = [PSCustomObject]@{
            Timestamp      = $Change.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')
            Label          = $Change.Label
            Host           = $Change.Host
            Port           = $Change.Port
            PreviousStatus = $Change.PreviousStatus
            NewStatus      = $Change.NewStatus
            LatencyMs      = $latency
        }
        $row | Export-Csv -LiteralPath $file -Append -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        [PSCustomObject]@{ Ok = $true; Path = $file; Error = $null }
    }
    catch {
        [PSCustomObject]@{ Ok = $false; Path = $file; Error = $_.Exception.Message }
    }
}

function Write-PortLossChangeLog {
    <#
    .SYNOPSIS
        Appends one packet-loss change to <LogDirectory>\PortMonitor_Loss_yyyyMMdd.csv. A file of
        its own, so the port-status log keeps its columns and older tools still read it.
        Never throws, like Write-PortStateChangeLog.
    #>
    param(
        [Parameter(Mandatory)][string]$LogDirectory,
        [Parameter(Mandatory)]$Change
    )
    $file = Join-Path $LogDirectory ('PortMonitor_Loss_{0}.csv' -f $Change.Timestamp.ToString('yyyyMMdd'))
    $num = { param($v) if ($null -eq $v) { '' } else { ([double]$v).ToString([System.Globalization.CultureInfo]::InvariantCulture) } }
    try {
        if (-not (Test-Path -LiteralPath $LogDirectory)) {
            New-Item -ItemType Directory -Path $LogDirectory -Force -ErrorAction Stop | Out-Null
        }
        $row = [PSCustomObject]@{
            Timestamp      = $Change.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')
            Label          = $Change.Label
            Host           = $Change.Host
            Port           = $Change.Port
            PreviousStatus = $Change.PreviousStatus
            NewStatus      = $Change.NewStatus
            LossPercent    = & $num $Change.LossPercent
            JitterMs       = & $num $Change.JitterMs
            AvgMs          = & $num $Change.AvgMs
            Sent           = $Change.Sent
            Received       = $Change.Received
        }
        $row | Export-Csv -LiteralPath $file -Append -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        [PSCustomObject]@{ Ok = $true; Path = $file; Error = $null }
    }
    catch {
        [PSCustomObject]@{ Ok = $false; Path = $file; Error = $_.Exception.Message }
    }
}

function Format-PortStateChangeLine {
    # One plain-English line for a change, used by the console and the window's status bar.
    param([Parameter(Mandatory)]$Change)
    if ($Change.PSObject.Properties['Kind'] -and $Change.Kind -eq 'Loss') {
        $detail = ''
        if ($null -ne $Change.LossPercent -and $Change.NewStatus -ne 'No replies') {
            $detail = " ($($Change.LossPercent) % lost"
            if ($null -ne $Change.JitterMs) { $detail += ", jitter $($Change.JitterMs) ms" }
            $detail += ')'
        }
        return ('{0}  {1} ({2})  Packet loss: {3} -> {4}{5}' -f $Change.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'),
            $Change.Label, $Change.Host, $Change.PreviousStatus, $Change.NewStatus, $detail)
    }
    $latency = ''
    if ($null -ne $Change.LatencyMs) { $latency = " ($($Change.LatencyMs) ms)" }
    '{0}  {1} ({2}:{3})  {4} -> {5}{6}' -f $Change.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'),
    $Change.Label, $Change.Host, $Change.Port, $Change.PreviousStatus, $Change.NewStatus, $latency
}

#endregion

#region Background engine (runspace pool)

function New-PortMonitorEngine {
    # A runspace pool that has Invoke-PortTargetCheck (and its helpers) defined, plus the list of running
    # checks. Results are collected by Receive-PortCheckResult on the caller's thread.
    param([ValidateRange(1, 64)][int]$MaxConcurrency = 16)
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
    foreach ($name in @('Get-PortCheckFailure', 'Test-TcpPort', 'ConvertTo-PortPingSummary', 'Measure-PingLoss', 'Invoke-PortTargetCheck')) {
        $definition = (Get-Command -Name $name -CommandType Function).Definition
        $entry = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $name, $definition
        $iss.Commands.Add($entry)
    }
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $MaxConcurrency, $iss, $Host)
    $pool.Open()
    [PSCustomObject]@{
        Pool           = $pool
        InFlight       = New-Object System.Collections.ArrayList
        Draining       = New-Object System.Collections.ArrayList
        MaxConcurrency = $MaxConcurrency
    }
}

function Start-PortCheck {
    # Starts one check in the pool and schedules the target's next one (interval from start).
    param([Parameter(Mandatory)]$Engine, [Parameter(Mandatory)]$State, [datetime]$Now = (Get-Date))
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.RunspacePool = $Engine.Pool
    [void]$ps.AddCommand('Invoke-PortTargetCheck').AddParameter('HostName', [string]$State.Host).AddParameter('Port', [int]$State.Port).AddParameter('TimeoutMs', [int]$State.TimeoutMs)
    if ($State.MeasureLoss) { [void]$ps.AddParameter('MeasureLoss', $true).AddParameter('LossPings', [int]$State.LossPings) }
    $handle = $ps.BeginInvoke()
    [void]$Engine.InFlight.Add([PSCustomObject]@{
            Id         = $State.Id
            Host       = $State.Host
            Port       = $State.Port
            PowerShell = $ps
            Handle     = $handle
            Started    = $Now
        })
    $State.InFlight = $true
    $State.NextDue = $Now.AddSeconds([int]$State.IntervalSec)
}

function Receive-PortCheckResult {
    <#
    .SYNOPSIS
        Collects finished checks, disposes them, and applies each result to its target.
    .DESCRIPTION
        A result is ignored when its target was removed, disabled, or its host/port edited while
        the check ran. Checks moved to Draining (after Stop) are disposed and their results
        dropped. Returns Processed (results applied) and Changes (port-status records, Kind
        'State', and packet-loss records, Kind 'Loss').
    #>
    param(
        [Parameter(Mandatory)]$Engine,
        [AllowNull()][AllowEmptyCollection()][object[]]$States = @(),
        [datetime]$Now = (Get-Date)
    )
    foreach ($job in @($Engine.Draining)) {
        if (-not $job.Handle.IsCompleted) { continue }
        try { [void]$job.PowerShell.EndInvoke($job.Handle) } catch { }
        try { $job.PowerShell.Dispose() } catch { }
        $Engine.Draining.Remove($job)
    }

    $changes = New-Object System.Collections.ArrayList
    $processed = 0
    foreach ($job in @($Engine.InFlight)) {
        if (-not $job.Handle.IsCompleted) { continue }
        $result = $null
        try {
            $output = $job.PowerShell.EndInvoke($job.Handle)
            $result = @($output) | Where-Object { $null -ne $_ } | Select-Object -Last 1
            if ($null -eq $result -and $job.PowerShell.Streams.Error.Count -gt 0) {
                $result = [PSCustomObject]@{ Status = 'Error'; LatencyMs = $null; Detail = "$($job.PowerShell.Streams.Error[0])" }
            }
        }
        catch {
            $result = [PSCustomObject]@{ Status = 'Error'; LatencyMs = $null; Detail = $_.Exception.Message }
        }
        finally {
            try { $job.PowerShell.Dispose() } catch { }
            $Engine.InFlight.Remove($job)
        }
        if ($null -eq $result) { $result = [PSCustomObject]@{ Status = 'Error'; LatencyMs = $null; Detail = 'The check returned nothing.' } }

        $state = $null
        foreach ($s in @($States)) { if ($s -and $s.Id -eq $job.Id) { $state = $s; break } }
        if ($null -eq $state) { continue }
        $state.InFlight = $false
        if (-not $state.Enabled -or $state.Host -ne $job.Host -or [int]$state.Port -ne [int]$job.Port) { continue }

        $processed++
        $change = Update-PortTargetState -State $state -Result $result -Now $Now
        if ($change) { [void]$changes.Add($change) }
        $lossChange = Update-PortTargetQuality -State $state -Result $result -Now $Now
        if ($lossChange) { [void]$changes.Add($lossChange) }
    }
    [PSCustomObject]@{ Processed = $processed; Changes = @($changes) }
}

function Invoke-PortMonitorCycle {
    # One scheduler tick: collect finished checks, log changes, start the checks that are due
    # (up to the pool size). Returns Processed, Started, Changes and LogErrors.
    param(
        [Parameter(Mandatory)]$Engine,
        [AllowNull()][AllowEmptyCollection()][object[]]$States = @(),
        [Parameter(Mandatory)][string]$LogDirectory,
        [datetime]$Now = (Get-Date),
        [switch]$NoLog
    )
    $received = Receive-PortCheckResult -Engine $Engine -States $States -Now $Now
    $logErrors = New-Object System.Collections.ArrayList
    if (-not $NoLog) {
        foreach ($change in @($received.Changes)) {
            if ($change.Kind -eq 'Loss') { $write = Write-PortLossChangeLog -LogDirectory $LogDirectory -Change $change }
            else { $write = Write-PortStateChangeLog -LogDirectory $LogDirectory -Change $change }
            if (-not $write.Ok) { [void]$logErrors.Add("Could not write the log file $($write.Path): $($write.Error)") }
        }
    }
    $started = 0
    foreach ($state in @(Get-DuePortTargets -States $States -Now $Now)) {
        if ($Engine.InFlight.Count -ge $Engine.MaxConcurrency) { break }
        Start-PortCheck -Engine $Engine -State $state -Now $Now
        $started++
    }
    [PSCustomObject]@{
        Processed = $received.Processed
        Started   = $started
        Changes   = @($received.Changes)
        LogErrors = [string[]]@($logErrors)
    }
}

function Suspend-PortMonitorChecks {
    # Stop button: running checks are left to finish (at most TimeoutMs x 2) and are then
    # disposed without applying their results; no new checks start.
    param([Parameter(Mandatory)]$Engine, [AllowNull()][AllowEmptyCollection()][object[]]$States = @())
    foreach ($job in @($Engine.InFlight)) { [void]$Engine.Draining.Add($job) }
    $Engine.InFlight.Clear()
    foreach ($s in @($States)) { if ($s) { $s.InFlight = $false } }
}

function Stop-PortMonitorEngine {
    # Shutdown: asks every running check to stop and closes the pool without blocking the
    # caller (a check blocked inside a .NET Wait() ends within its timeout).
    param([AllowNull()]$Engine)
    if ($null -eq $Engine) { return }
    foreach ($job in @($Engine.InFlight) + @($Engine.Draining)) {
        if ($null -eq $job) { continue }
        try {
            if ($job.Handle.IsCompleted) { $job.PowerShell.Dispose() }
            else { [void]$job.PowerShell.BeginStop($null, $null) }
        }
        catch { }
    }
    $Engine.InFlight.Clear()
    $Engine.Draining.Clear()
    try { [void]$Engine.Pool.BeginClose($null, $null) } catch { }
}

#endregion

#region Console mode (-NoGui / -Once)

function Get-PortStatusConsoleColor {
    param([string]$Status)
    switch ($Status) {
        'Open' { 'Green' }
        'Error' { 'Yellow' }
        { $script:FailureStatuses -contains $_ } { 'Red' }
        default { 'DarkGray' }
    }
}

function Format-PortMonitorTableRow {
    # Fixed-width columns for the console table. Returns the cells so the caller can colour
    # the Status cell only.
    param([Parameter(Mandatory)]$State)
    $fit = { param([string]$text, [int]$width) if ($text.Length -gt $width) { $text.Substring(0, $width - 1) + '~' } else { $text.PadRight($width) } }
    $latency = ''
    if ($null -ne $State.LatencyMs) { $latency = '{0:0.0}' -f $State.LatencyMs }
    $checked = ''
    if ($State.LastChecked) { $checked = $State.LastChecked.ToString('yyyy-MM-dd HH:mm:ss') }
    $changed = ''
    if ($State.LastStateChange) { $changed = $State.LastStateChange.ToString('yyyy-MM-dd HH:mm:ss') }
    $uptime = ''
    if ($null -ne $State.UptimePercent) { $uptime = '{0:0.0}' -f $State.UptimePercent }
    $loss = ''
    if ($State.MeasureLoss) { $loss = [string]$State.LossText }
    if ($State.LossStatus -eq 'High loss') { $loss = "!$loss" }
    [PSCustomObject]@{
        Status = & $fit ([string]$State.Status) 12
        Rest   = '{0} {1} {2} {3} {4} {5} {6} {7} {8}' -f (& $fit ([string]$State.Label) 22), (& $fit ([string]$State.Host) 26),
        ([string]$State.Port).PadLeft(5), $latency.PadLeft(8), (& $fit $loss 8).TrimEnd().PadLeft(8), $checked.PadRight(19), $changed.PadRight(19),
        ([string]$State.FailCount).PadLeft(5), $uptime.PadLeft(7)
    }
}

function Write-PortMonitorTable {
    param([AllowNull()][AllowEmptyCollection()][object[]]$States = @(), [string[]]$RecentChanges = @(), [string]$Footer = '')
    $header = '{0} {1} {2} {3} {4} {5} {6} {7} {8} {9}' -f 'Status'.PadRight(12), 'Label'.PadRight(22), 'Host'.PadRight(26), 'Port'.PadLeft(5),
    'Lat ms'.PadLeft(8), 'Loss %'.PadLeft(8), 'Last checked'.PadRight(19), 'Last change'.PadRight(19), 'Fails'.PadLeft(5), 'Up %'.PadLeft(7)
    Write-Host $header -ForegroundColor Cyan
    Write-Host ('-' * $header.Length) -ForegroundColor DarkGray
    foreach ($s in @($States)) {
        if ($null -eq $s) { continue }
        $row = Format-PortMonitorTableRow -State $s
        Write-Host $row.Status -ForegroundColor (Get-PortStatusConsoleColor $s.Status) -NoNewline
        Write-Host (' ' + $row.Rest)
    }
    if (@($RecentChanges).Count -gt 0) {
        Write-Host ''
        Write-Host 'Recent changes (also in the log):' -ForegroundColor Cyan
        foreach ($line in $RecentChanges) { Write-Host "  $line" }
    }
    if ($Footer) { Write-Host ''; Write-Host $Footer -ForegroundColor DarkGray }
}

function Invoke-PortMonitorHeadless {
    <#
    .SYNOPSIS
        Console mode. Returns the exit code (only meaningful with -Once): 0 all Open (and no
        target that measures packet loss is losing packets), 1 at least one not Open or losing
        packets at or above its alert level, 2 nothing to check.
    #>
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][string]$LogDirectory,
        [switch]$Once
    )
    $config = Read-PortMonitorConfig -Path $ConfigPath
    foreach ($w in $config.Warnings) { Write-Host "[WARN] $w" -ForegroundColor Yellow }
    $states = @(foreach ($t in $config.Targets) { New-PortTargetState $t })
    $enabled = @($states | Where-Object { $_.Enabled })
    if ($enabled.Count -eq 0) {
        Write-Host "[FAIL] No enabled targets in $ConfigPath. Add targets in the window (run without -NoGui) or edit the JSON file." -ForegroundColor Red
        return 2
    }

    $interactive = $true
    try { if ([Console]::IsOutputRedirected) { $interactive = $false } } catch { $interactive = $false }
    if ($Once) { $interactive = $false }

    Write-Host "[INFO] Port Monitor $script:PortMonitorVersion - $($enabled.Count) target(s) from $ConfigPath" -ForegroundColor Cyan
    Write-Host "[INFO] State changes are logged to $LogDirectory" -ForegroundColor Cyan
    if (-not $Once) { Write-Host '[INFO] Press Ctrl+C to stop.' -ForegroundColor Cyan }

    $engine = New-PortMonitorEngine
    $recent = New-Object System.Collections.ArrayList
    $lastDraw = [datetime]::MinValue
    $firstDraw = $true
    try {
        while ($true) {
            $now = Get-Date
            $cycle = Invoke-PortMonitorCycle -Engine $engine -States $states -LogDirectory $LogDirectory -Now $now
            foreach ($e in $cycle.LogErrors) { Write-Host "[WARN] $e" -ForegroundColor Yellow }
            foreach ($change in $cycle.Changes) {
                $line = Format-PortStateChangeLine -Change $change
                [void]$recent.Insert(0, $line)
                while ($recent.Count -gt 10) { $recent.RemoveAt($recent.Count - 1) }
                if (-not $interactive -and -not $Once) {
                    $prefix = '[FAIL]'; $color = 'Red'
                    if ($change.NewStatus -eq 'Open' -or $change.NewStatus -eq 'OK') { $prefix = '[PASS]'; $color = 'Green' }
                    elseif ($change.NewStatus -eq 'High loss') { $prefix = '[WARN]'; $color = 'Yellow' }
                    elseif ($change.NewStatus -eq 'No replies') { $prefix = '[INFO]'; $color = 'Cyan' }
                    Write-Host "$prefix $line" -ForegroundColor $color
                }
            }

            if ($Once) {
                $pending = @($enabled | Where-Object { $_.Checks -lt 1 })
                if ($pending.Count -eq 0) { break }
            }
            elseif ($interactive -and (($cycle.Processed -gt 0) -or (($now - $lastDraw).TotalSeconds -ge 1))) {
                $lastDraw = $now
                $drawn = $false
                try {
                    if ($firstDraw) { Clear-Host; $firstDraw = $false }
                    [Console]::SetCursorPosition(0, 0)
                    $drawn = $true
                }
                catch { Clear-Host }
                $running = @($states | Where-Object { $_.InFlight }).Count
                Write-PortMonitorTable -States $states -RecentChanges @($recent) -Footer ("{0}  Monitoring {1} target(s), {2} check(s) running. Log: {3}  Ctrl+C to stop." -f $now.ToString('yyyy-MM-dd HH:mm:ss'), $enabled.Count, $running, $LogDirectory)
                if ($drawn) {
                    # Blank out anything left over from a longer previous frame.
                    try {
                        $width = [Math]::Max(1, [Console]::WindowWidth - 1)
                        $top = [Console]::CursorTop
                        for ($i = 0; $i -lt 3; $i++) { Write-Host (' ' * $width) }
                        [Console]::SetCursorPosition(0, $top)
                    }
                    catch { }
                }
            }
            Start-Sleep -Milliseconds 200
        }
    }
    finally {
        # Also runs on Ctrl+C: PowerShell runs finally blocks when the pipeline is stopped.
        Stop-PortMonitorEngine -Engine $engine
    }

    Write-PortMonitorTable -States $states
    $notOpen = @($enabled | Where-Object { $_.Status -ne 'Open' })
    $lossy = @($enabled | Where-Object { $_.Status -eq 'Open' -and $_.LossStatus -eq 'High loss' })
    foreach ($s in @($enabled | Where-Object { $_.LossStatus -eq 'No replies' })) {
        Write-Host "[INFO] $($s.Label): no ping answered although the port is open; ping is probably blocked, so packet loss could not be measured." -ForegroundColor Cyan
    }
    if ($notOpen.Count -eq 0 -and $lossy.Count -eq 0) {
        Write-Host "[PASS] All $($enabled.Count) target(s) are open." -ForegroundColor Green
        return 0
    }
    if ($notOpen.Count -gt 0) {
        Write-Host "[FAIL] $($notOpen.Count) of $($enabled.Count) target(s) are not open: $((@($notOpen | ForEach-Object { "$($_.Label) ($($_.Status))" })) -join ', ')" -ForegroundColor Red
    }
    if ($lossy.Count -gt 0) {
        Write-Host "[FAIL] $($lossy.Count) target(s) are open but losing packets: $((@($lossy | ForEach-Object { "$($_.Label) ($($_.LossText) % lost)" })) -join ', ')" -ForegroundColor Red
    }
    1
}

#endregion

#region Uptime and outage report (from the state-change logs)

function Read-PortStateLog {
    <#
    .SYNOPSIS
        Reads every PortMonitor_yyyyMMdd.csv in a folder up to a date, oldest first. Rows with an
        unreadable timestamp are skipped. Returns Rows and the Files read.
    #>
    param([Parameter(Mandatory)][string]$LogDirectory, [datetime]$To = (Get-Date))
    $rows = New-Object System.Collections.ArrayList
    $files = @()
    if (Test-Path -LiteralPath $LogDirectory) {
        $files = @(Get-ChildItem -LiteralPath $LogDirectory -Filter 'PortMonitor_*.csv' -File | Where-Object {
                $day = [datetime]::MinValue
                $_.BaseName -match '^PortMonitor_(\d{8})$' -and
                [datetime]::TryParseExact($Matches[1], 'yyyyMMdd', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$day) -and
                $day -le $To.Date
            } | Sort-Object Name)
    }
    foreach ($f in $files) {
        foreach ($r in @(Import-Csv -LiteralPath $f.FullName)) {
            $t = [datetime]::MinValue
            if (-not [datetime]::TryParseExact([string]$r.Timestamp, 'yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$t)) { continue }
            [void]$rows.Add([PSCustomObject]@{
                    Timestamp = $t; Label = [string]$r.Label; Host = [string]$r.Host; Port = [string]$r.Port
                    PreviousStatus = [string]$r.PreviousStatus; NewStatus = [string]$r.NewStatus
                })
        }
    }
    [PSCustomObject]@{ Rows = @($rows | Sort-Object Timestamp); Files = @($files | ForEach-Object { $_.FullName }) }
}

function Read-PortLossLog {
    <#
    .SYNOPSIS
        Reads every PortMonitor_Loss_yyyyMMdd.csv in a folder up to a date, oldest first.
        Returns Rows (Timestamp, Label, Host, Port, PreviousStatus, NewStatus, LossPercent).
    #>
    param([Parameter(Mandatory)][string]$LogDirectory, [datetime]$To = (Get-Date))
    $rows = New-Object System.Collections.ArrayList
    $files = @()
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    if (Test-Path -LiteralPath $LogDirectory) {
        $files = @(Get-ChildItem -LiteralPath $LogDirectory -Filter 'PortMonitor_Loss_*.csv' -File | Where-Object {
                $day = [datetime]::MinValue
                $_.BaseName -match '^PortMonitor_Loss_(\d{8})$' -and
                [datetime]::TryParseExact($Matches[1], 'yyyyMMdd', $inv, [System.Globalization.DateTimeStyles]::None, [ref]$day) -and
                $day -le $To.Date
            } | Sort-Object Name)
    }
    foreach ($f in $files) {
        foreach ($r in @(Import-Csv -LiteralPath $f.FullName)) {
            $t = [datetime]::MinValue
            if (-not [datetime]::TryParseExact([string]$r.Timestamp, 'yyyy-MM-dd HH:mm:ss', $inv, [System.Globalization.DateTimeStyles]::None, [ref]$t)) { continue }
            $lossValue = $null; $parsed = 0.0
            if ([double]::TryParse([string]$r.LossPercent, [System.Globalization.NumberStyles]::Float, $inv, [ref]$parsed)) { $lossValue = $parsed }
            [void]$rows.Add([PSCustomObject]@{
                    Timestamp = $t; Label = [string]$r.Label; Host = [string]$r.Host; Port = [string]$r.Port
                    PreviousStatus = [string]$r.PreviousStatus; NewStatus = [string]$r.NewStatus; LossPercent = $lossValue
                })
        }
    }
    [PSCustomObject]@{ Rows = @($rows | Sort-Object Timestamp); Files = @($files | ForEach-Object { $_.FullName }) }
}

function Get-PortLossReport {
    <#
    .SYNOPSIS
        Periods of high packet loss in [From, To] from packet-loss change rows. Pure.
    .DESCRIPTION
        Same rules as Get-PortOutageReport: a period starts at a change to "High loss" and ends
        at the next change away from it; a "Not checked" row (Port Monitor restarted) closes a
        period with EndUncertain; one still open at To is Ongoing. Grouped by host (loss is a
        property of the host, whichever port measured it).
    #>
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Rows = @(),
        [Parameter(Mandatory)][datetime]$From,
        [Parameter(Mandatory)][datetime]$To
    )
    $byHost = [ordered]@{}
    foreach ($r in @($Rows | Where-Object { $_ -and $_.Timestamp -le $To } | Sort-Object Timestamp)) {
        $key = ([string]$r.Host).ToLowerInvariant()
        if (-not $byHost.Contains($key)) { $byHost[$key] = New-Object System.Collections.ArrayList }
        [void]$byHost[$key].Add($r)
    }
    $periods = New-Object System.Collections.ArrayList
    foreach ($key in $byHost.Keys) {
        $open = $null
        foreach ($r in $byHost[$key]) {
            $isRestart = $r.PreviousStatus -eq $script:StatusNotChecked
            $isHigh = $r.NewStatus -eq 'High loss'
            if ($open -and ($isRestart -or -not $isHigh)) {
                $open.End = $r.Timestamp; $open.EndUncertain = $isRestart
                [void]$periods.Add($open); $open = $null
            }
            if ($isHigh -and -not $open) {
                $open = [PSCustomObject]@{ Label = $r.Label; Host = $r.Host; Start = $r.Timestamp; End = $null; LossAtStart = $r.LossPercent; EndUncertain = $false; Ongoing = $false }
            }
        }
        if ($open) { $open.End = $To; $open.Ongoing = $true; [void]$periods.Add($open) }
    }
    $inRange = @($periods | Where-Object { $_.End -gt $From -and $_.Start -lt $To } | ForEach-Object {
            $_ | Add-Member -NotePropertyName Duration -NotePropertyValue ($_.End - $_.Start) -Force -PassThru
        } | Sort-Object Start)
    [PSCustomObject]@{ From = $From; To = $To; Periods = $inRange }
}

function Format-PortDuration {
    # "45 s", "12 min", "2 h 5 min", "3 d 4 h".
    param([TimeSpan]$Span)
    if ($Span.TotalSeconds -lt 60) { return '{0} s' -f [int][math]::Round($Span.TotalSeconds) }
    if ($Span.TotalMinutes -lt 60) { return '{0} min' -f [int][math]::Floor($Span.TotalMinutes) }
    if ($Span.TotalHours -lt 24) { return '{0} h {1} min' -f [int][math]::Floor($Span.TotalHours), $Span.Minutes }
    '{0} d {1} h' -f [int][math]::Floor($Span.TotalDays), $Span.Hours
}

function Get-PortOutageReport {
    <#
    .SYNOPSIS
        Works out outages and uptime per target for [From, To] from state-change rows.
    .DESCRIPTION
        The log holds changes only, so a target's state between two rows is the state of the
        earlier row. An outage starts when a target becomes not-Open and ends at the next Open
        row. A "Not checked" row means Port Monitor was (re)started: an outage still open at that
        point is closed there and marked EndUncertain, because nothing was checked while Port
        Monitor was not running. Time before a target's first row is not counted. Outages that
        overlap the range are listed in full; only the part inside the range counts as downtime.
    #>
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Rows = @(),
        [Parameter(Mandatory)][datetime]$From,
        [Parameter(Mandatory)][datetime]$To
    )
    $byTarget = [ordered]@{}
    foreach ($r in @($Rows | Where-Object { $_ -and $_.Timestamp -le $To } | Sort-Object Timestamp)) {
        $key = ("{0}:{1}" -f $r.Host, $r.Port).ToLowerInvariant()
        if (-not $byTarget.Contains($key)) { $byTarget[$key] = New-Object System.Collections.ArrayList }
        [void]$byTarget[$key].Add($r)
    }

    $targets = New-Object System.Collections.ArrayList
    $outages = New-Object System.Collections.ArrayList
    foreach ($key in $byTarget.Keys) {
        $list = $byTarget[$key]
        $label = $list[$list.Count - 1].Label
        $hostName = $list[0].Host; $port = $list[0].Port
        $mine = New-Object System.Collections.ArrayList
        $open = $null      # the outage in progress
        foreach ($r in $list) {
            $isRestart = $r.PreviousStatus -eq $script:StatusNotChecked
            $isDown = $r.NewStatus -ne 'Open'
            if ($open -and ($isRestart -or -not $isDown)) {
                $open.End = $r.Timestamp
                $open.EndUncertain = $isRestart
                [void]$mine.Add($open); $open = $null
            }
            if ($isDown -and -not $open) {
                $open = [PSCustomObject]@{ Label = $label; Host = $hostName; Port = $port; Start = $r.Timestamp; End = $null; Status = $r.NewStatus; EndUncertain = $false; Ongoing = $false }
            }
            elseif ($isDown -and $open) { $open.Status = $r.NewStatus }
        }
        if ($open) { $open.End = $To; $open.Ongoing = $true; [void]$mine.Add($open) }

        $monitoredFrom = $list[0].Timestamp
        if ($monitoredFrom -lt $From) { $monitoredFrom = $From }
        $monitored = $To - $monitoredFrom
        $down = [TimeSpan]::Zero
        $inRange = New-Object System.Collections.ArrayList
        foreach ($o in $mine) {
            if ($o.End -le $From -or $o.Start -ge $To) { continue }
            $s = $o.Start; if ($s -lt $From) { $s = $From }
            $e = $o.End; if ($e -gt $To) { $e = $To }
            $o | Add-Member -NotePropertyName DownInRange -NotePropertyValue ($e - $s) -Force
            $o | Add-Member -NotePropertyName Duration -NotePropertyValue ($o.End - $o.Start) -Force
            $down += ($e - $s)
            [void]$inRange.Add($o); [void]$outages.Add($o)
        }
        $uptime = $null
        if ($monitored.TotalSeconds -gt 0) { $uptime = [math]::Round(100.0 * (1 - $down.TotalSeconds / $monitored.TotalSeconds), 2) }
        $longest = $null
        if ($inRange.Count -gt 0) { $longest = ($inRange | Sort-Object { $_.DownInRange } -Descending | Select-Object -First 1).DownInRange }
        [void]$targets.Add([PSCustomObject]@{
                Label = $label; Host = $hostName; Port = $port
                UptimePercent = $uptime; Outages = $inRange.Count; Downtime = $down; Longest = $longest
                Ongoing = [bool](@($inRange | Where-Object { $_.Ongoing }).Count)
                MonitoredFrom = $monitoredFrom
            })
    }
    [PSCustomObject]@{
        From    = $From
        To      = $To
        Targets = @($targets | Where-Object { $_.MonitoredFrom -lt $To } | Sort-Object @{ Expression = { $_.Downtime }; Descending = $true }, Label)
        Outages = @($outages | Sort-Object Start)
    }
}

function ConvertTo-PortOutageReportHtml {
    # A self-contained HTML page: verdict first, then a table per target, then every outage.
    param([Parameter(Mandatory)]$Report, [string]$Title = 'Port Monitor - uptime and outages', $LossReport)
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $fmt = 'yyyy-MM-dd HH:mm'
    $targets = @($Report.Targets)
    $hit = @($targets | Where-Object { $_.Outages -gt 0 })
    $ongoing = @($targets | Where-Object { $_.Ongoing })
    if ($targets.Count -eq 0) {
        $verdict = 'No state changes were logged for this period, so there is nothing to report. Was Port Monitor running?'
        $verdictClass = 'none'
    }
    elseif ($hit.Count -eq 0) {
        $verdict = "All $($targets.Count) target(s) were up for the whole period."
        $verdictClass = 'ok'
    }
    else {
        $worst = $hit | Sort-Object @{ Expression = { $_.Longest }; Descending = $true } | Select-Object -First 1
        $total = [TimeSpan]::Zero; foreach ($t in $hit) { $total += $t.Downtime }
        $verdict = "$($hit.Count) of $($targets.Count) target(s) had outages: $(@($Report.Outages).Count) in total, $(Format-PortDuration $total) of downtime. Longest: $(Format-PortDuration $worst.Longest) ($($worst.Label))."
        if ($ongoing.Count -gt 0) { $verdict += " Still down at the end of the period: $((@($ongoing | ForEach-Object { $_.Label })) -join ', ')." }
        $verdictClass = 'bad'
    }
    $lossPeriods = @()
    if ($LossReport) { $lossPeriods = @($LossReport.Periods) }
    if ($lossPeriods.Count -gt 0) {
        $lossHosts = @($lossPeriods | ForEach-Object { $_.Host } | Sort-Object -Unique)
        $lossText = "$($lossHosts.Count) host(s) had periods of high packet loss ($($lossPeriods.Count) in total): $($lossHosts -join ', ')."
        if ($verdictClass -eq 'ok') { $verdict = "All $($targets.Count) target(s) stayed up, but $lossText"; $verdictClass = 'warn' }
        elseif ($verdictClass -eq 'none') { $verdict = $lossText; $verdictClass = 'warn' }
        else { $verdict += " $lossText" }
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(& $enc $Title)</title>
<style>
body{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:24px;color:#1b1e22;background:#fff}
h1{font-size:22px;margin:0 0 4px} h2{font-size:16px;margin:28px 0 8px}
.meta{color:#5b636e;font-size:13px}
.verdict{margin:16px 0;padding:12px 16px;border-left:4px solid;font-size:15px;font-weight:600}
.verdict.ok{border-color:#1d7a45;background:#eaf6ee}.verdict.warn{border-color:#9a6700;background:#fff8e5}.verdict.bad{border-color:#a8322a;background:#fbecea}.verdict.none{border-color:#8a939e;background:#f1f3f5}
table{border-collapse:collapse;width:100%;font-size:13px} th,td{text-align:left;padding:6px 10px;border-bottom:1px solid #e3e6ea}
th{background:#f4f6f8;color:#3c434c;font-weight:600} td.num{text-align:right;font-variant-numeric:tabular-nums}
.mono{font-family:Consolas,'Cascadia Mono',monospace} .down{color:#a8322a;font-weight:600} .up{color:#1d7a45;font-weight:600}
.note{color:#5b636e;font-size:12px;margin-top:20px;max-width:900px}
</style></head><body>
<h1>$(& $enc $Title)</h1>
<div class="meta">Period: $($Report.From.ToString($fmt)) to $($Report.To.ToString($fmt)) &middot; Created $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') on $(& $enc $env:COMPUTERNAME)</div>
<div class="verdict $verdictClass">$(& $enc $verdict)</div>
"@)
    if ($targets.Count -gt 0) {
        [void]$sb.Append('<h2>Targets</h2><table><tr><th>Target</th><th>Host</th><th>Port</th><th>Uptime</th><th>Outages</th><th>Downtime</th><th>Longest</th></tr>')
        foreach ($t in $targets) {
            $up = 'n/a'; if ($null -ne $t.UptimePercent) { $up = '{0:0.00} %' -f $t.UptimePercent }
            $cls = 'up'; if ($t.Outages -gt 0) { $cls = 'down' }
            $longest = ''; if ($t.Longest) { $longest = Format-PortDuration $t.Longest }
            $downtime = ''; if ($t.Outages -gt 0) { $downtime = Format-PortDuration $t.Downtime }
            [void]$sb.Append(("<tr><td>{0}</td><td class=""mono"">{1}</td><td class=""num mono"">{2}</td><td class=""num {3}"">{4}</td><td class=""num"">{5}</td><td class=""num"">{6}</td><td class=""num"">{7}</td></tr>" -f
                    (& $enc $t.Label), (& $enc $t.Host), (& $enc $t.Port), $cls, $up, $t.Outages, $downtime, $longest))
        }
        [void]$sb.Append('</table>')
    }
    if (@($Report.Outages).Count -gt 0) {
        [void]$sb.Append('<h2>Outages</h2><table><tr><th>Target</th><th>Went down</th><th>Came back</th><th>Duration</th><th>Last status</th></tr>')
        foreach ($o in $Report.Outages) {
            $start = $o.Start.ToString('yyyy-MM-dd HH:mm:ss')
            if ($o.Start -lt $Report.From) { $start += ' (before this period)' }
            if ($o.Ongoing) { $end = 'still down' }
            elseif ($o.EndUncertain) { $end = $o.End.ToString('yyyy-MM-dd HH:mm:ss') + ' or earlier (Port Monitor was restarted)' }
            else { $end = $o.End.ToString('yyyy-MM-dd HH:mm:ss') }
            $duration = Format-PortDuration $o.Duration
            if ($o.Ongoing) { $duration = 'at least ' + $duration }
            [void]$sb.Append(("<tr><td>{0} <span class=""mono"">({1}:{2})</span></td><td class=""mono"">{3}</td><td class=""mono"">{4}</td><td class=""num"">{5}</td><td class=""down"">{6}</td></tr>" -f
                    (& $enc $o.Label), (& $enc $o.Host), (& $enc $o.Port), (& $enc $start), (& $enc $end), (& $enc $duration), (& $enc $o.Status)))
        }
        [void]$sb.Append('</table>')
    }
    if ($lossPeriods.Count -gt 0) {
        [void]$sb.Append('<h2>Packet loss</h2><table><tr><th>Host</th><th>Started</th><th>Ended</th><th>Duration</th><th>Lost when it started</th></tr>')
        foreach ($l in $lossPeriods) {
            $start = $l.Start.ToString('yyyy-MM-dd HH:mm:ss')
            if ($l.Start -lt $LossReport.From) { $start += ' (before this period)' }
            if ($l.Ongoing) { $end = 'still losing packets' }
            elseif ($l.EndUncertain) { $end = $l.End.ToString('yyyy-MM-dd HH:mm:ss') + ' or earlier (Port Monitor was restarted)' }
            else { $end = $l.End.ToString('yyyy-MM-dd HH:mm:ss') }
            $duration = Format-PortDuration $l.Duration
            if ($l.Ongoing) { $duration = 'at least ' + $duration }
            $lost = ''; if ($null -ne $l.LossAtStart) { $lost = ('{0:0.0} %' -f $l.LossAtStart) }
            [void]$sb.Append(("<tr><td>{0} <span class=""mono"">({1})</span></td><td class=""mono"">{2}</td><td class=""mono"">{3}</td><td class=""num"">{4}</td><td class=""num down"">{5}</td></tr>" -f
                    (& $enc $l.Label), (& $enc $l.Host), (& $enc $start), (& $enc $end), (& $enc $duration), (& $enc $lost)))
        }
        [void]$sb.Append('</table>')
    }
    [void]$sb.Append(@'
<p class="note">How to read this: Port Monitor logs only changes. Uptime counts from the first time a target appears in the log
(or the start of the period). Time when Port Monitor was not running counts as the last state it saw, so a gap in monitoring can hide
or lengthen an outage; outages cut short by a restart are marked. Short blips are already filtered by each target's "Down after" setting.
Packet loss is only measured for targets with "Measure packet loss" turned on, by pinging the host after each port check; a period of
high loss starts when the loss reaches the target's alert level for "Down after" checks in a row.</p>
</body></html>
'@)
    $sb.ToString()
}

function Export-PortOutageReport {
    <#
    .SYNOPSIS
        Builds the report for the last N days from a log folder and writes
        PortMonitor_Report_yyyy-MM-dd_HHmmss.html to OutputPath. Returns the file path and the
        report data.
    #>
    param(
        [Parameter(Mandatory)][string]$LogDirectory,
        [Parameter(Mandatory)][string]$OutputPath,
        [ValidateRange(1, 366)][int]$Days = 7,
        [datetime]$Now = (Get-Date)
    )
    $from = $Now.AddDays(-$Days)
    $log = Read-PortStateLog -LogDirectory $LogDirectory -To $Now
    $report = Get-PortOutageReport -Rows $log.Rows -From $from -To $Now
    $lossLog = Read-PortLossLog -LogDirectory $LogDirectory -To $Now
    $lossReport = Get-PortLossReport -Rows $lossLog.Rows -From $from -To $Now
    $period = "last $Days day(s)"; if ($Days -eq 1) { $period = 'last 24 hours' }
    $html = ConvertTo-PortOutageReportHtml -Report $report -Title "Port Monitor - uptime and outages, $period" -LossReport $lossReport
    if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null }
    $file = Join-Path $OutputPath ('PortMonitor_Report_{0}.html' -f $Now.ToString('yyyy-MM-dd_HHmmss'))
    [System.IO.File]::WriteAllText($file, $html, (New-Object System.Text.UTF8Encoding -ArgumentList $true))
    [PSCustomObject]@{ Path = $file; Report = $report; LossReport = $lossReport; LogFiles = @($log.Files) + @($lossLog.Files) }
}

#endregion

#region Tray, notifications, startup shortcut, single instance

function Limit-PortMonitorText {
    # Cuts text to a Windows limit, ending with '...' when cut.
    param([AllowNull()][string]$Text, [Parameter(Mandatory)][int]$Max)
    if ($null -eq $Text) { return '' }
    if ($Text.Length -le $Max) { return $Text }
    $Text.Substring(0, $Max - 3) + '...'
}

function Get-PortChangeNotification {
    <#
    .SYNOPSIS
        Turns one tick's state changes into one notification (title, text, Down/Up), or nothing.
    .DESCRIPTION
        A first result that is Open ("Not checked -> Open") is not news and is left out; a first
        result that is a failure is reported. Several changes in the same tick become one
        notification, because Windows shows one balloon at a time and a newer one from the same
        app replaces the older one (NotifyIcon.ShowBalloonTip docs).
        Title is cut to 63 characters and text to 255 (NOTIFYICONDATA szInfoTitle[64] /
        szInfo[256], including the terminating null).
        https://learn.microsoft.com/windows/win32/api/shellapi/ns-shellapi-notifyicondataw
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Changes = @())
    $isLoss = { param($c) $c.PSObject.Properties['Kind'] -and $c.Kind -eq 'Loss' }
    # Packet loss: only "started losing packets" and "back to normal after losing packets" are
    # news. A first OK, and "No replies" (ping blocked: a setup matter, shown in the window),
    # are not.
    $news = @($Changes | Where-Object {
            $_ -and $(if (& $isLoss $_) { $_.NewStatus -eq 'High loss' -or ($_.NewStatus -eq 'OK' -and $_.PreviousStatus -eq 'High loss') }
                else { -not ($_.PreviousStatus -eq $script:StatusNotChecked -and $_.NewStatus -eq 'Open') })
        })
    if ($news.Count -eq 0) { return }
    $down = @($news | Where-Object { $_.NewStatus -ne 'Open' -and $_.NewStatus -ne 'OK' })
    $kind = 'Up'
    if ($down.Count -gt 0) { $kind = 'Down' }

    if ($news.Count -eq 1) {
        $c = $news[0]
        $when = $c.Timestamp.ToString('HH:mm:ss')
        if (& $isLoss $c) {
            $jitter = ''
            if ($null -ne $c.JitterMs) { $jitter = ", jitter $($c.JitterMs) ms" }
            if ($c.NewStatus -eq 'High loss') {
                $title = "$($c.Label) is losing packets"
                $text = "$($c.Host): $($c.LossPercent) % of pings lost$jitter at $when. The port still answers, but calls, RDP and file copies may be slow or choppy."
            }
            else {
                $title = "$($c.Label): packet loss back to normal"
                $text = "$($c.Host): $($c.LossPercent) % of pings lost$jitter at $when."
            }
        }
        elseif ($c.NewStatus -eq 'Open') {
            $title = "$($c.Label) is back up"
            $latency = ''
            if ($null -ne $c.LatencyMs) { $latency = " in $($c.LatencyMs) ms" }
            $text = "$($c.Host):$($c.Port) answered$latency at $when (was $($c.PreviousStatus))."
        }
        else {
            $title = "$($c.Label) is not answering"
            if ($c.PreviousStatus -eq $script:StatusNotChecked) { $text = "$($c.Host):$($c.Port): $($c.NewStatus) on the first check at $when." }
            else { $text = "$($c.Host):$($c.Port): $($c.PreviousStatus) -> $($c.NewStatus) at $when." }
        }
    }
    else {
        if ($down.Count -eq $news.Count) { $title = "$($news.Count) targets are not answering" }
        elseif ($down.Count -eq 0) { $title = "$($news.Count) targets are back up" }
        else { $title = "$($news.Count) targets changed ($($down.Count) down)" }
        $lines = @($news | Select-Object -First 4 | ForEach-Object {
                if (& $isLoss $_) { "$($_.Label): packet loss $($_.PreviousStatus) -> $($_.NewStatus) ($($_.LossPercent) %)" }
                else { "$($_.Label): $($_.PreviousStatus) -> $($_.NewStatus)" }
            })
        if ($news.Count -gt 4) { $lines += "and $($news.Count - 4) more" }
        $text = $lines -join "`n"
    }
    [PSCustomObject]@{
        Title = Limit-PortMonitorText -Text $title -Max 63
        Text  = Limit-PortMonitorText -Text $text -Max 255
        Kind  = $kind
    }
}

function Get-PortMonitorTraySummary {
    <#
    .SYNOPSIS
        What the tray icon shows: State (Stopped, Checking, Ok, Degraded, Problem) and its
        tooltip. Degraded: every port answers but at least one host is losing packets.
    .DESCRIPTION
        The tooltip is cut to 63 characters: NotifyIcon.Text throws above 63 on .NET Framework
        (Windows PowerShell) and .NET 5; .NET 6+ allows 127.
        https://learn.microsoft.com/dotnet/api/system.windows.forms.notifyicon.text
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$States = @(), [bool]$Running)
    $enabled = @($States | Where-Object { $_ -and $_.Enabled })
    if (-not $Running) {
        $state = 'Stopped'; $text = 'Port Monitor - stopped'
    }
    elseif ($enabled.Count -eq 0) {
        $state = 'Stopped'; $text = 'Port Monitor - nothing to check'
    }
    else {
        $failing = @($enabled | Where-Object { $script:FailureStatuses -contains $_.Status })
        $open = @($enabled | Where-Object { $_.Status -eq 'Open' })
        if ($failing.Count -gt 0) {
            $state = 'Problem'
            $text = "Port Monitor - $($failing.Count) of $($enabled.Count) not answering"
            if ($failing.Count -eq 1) { $text = "Port Monitor - $($failing[0].Label) not answering" }
        }
        elseif ($open.Count -eq $enabled.Count) {
            $lossy = @($enabled | Where-Object { $_.LossStatus -eq 'High loss' })
            if ($lossy.Count -eq 1) { $state = 'Degraded'; $text = "Port Monitor - $($lossy[0].Label) losing packets" }
            elseif ($lossy.Count -gt 1) { $state = 'Degraded'; $text = "Port Monitor - $($lossy.Count) losing packets" }
            else { $state = 'Ok'; $text = "Port Monitor - all $($enabled.Count) open" }
        }
        else {
            $state = 'Checking'; $text = "Port Monitor - checking $($enabled.Count) target(s)"
        }
    }
    [PSCustomObject]@{ State = $state; Text = (Limit-PortMonitorText -Text $text -Max 63) }
}

function New-PortMonitorTrayIcon {
    # A 16x16 round icon in one colour, drawn at run time so the tool stays one file.
    param([Parameter(Mandatory)][string]$Color)
    Add-Type -AssemblyName System.Drawing
    $bmp = New-Object System.Drawing.Bitmap -ArgumentList 16, 16
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    try {
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.Clear([System.Drawing.Color]::Transparent)
        $fill = New-Object System.Drawing.SolidBrush -ArgumentList ([System.Drawing.ColorTranslator]::FromHtml($Color))
        $edge = New-Object System.Drawing.Pen -ArgumentList ([System.Drawing.ColorTranslator]::FromHtml('#101214')), 1.5
        $g.FillEllipse($fill, 1.5, 1.5, 12.5, 12.5)
        $g.DrawEllipse($edge, 1.5, 1.5, 12.5, 12.5)
        $fill.Dispose(); $edge.Dispose()
    }
    finally { $g.Dispose() }
    [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
}

function Get-PortMonitorStartupShortcutPath {
    # The per-user Startup folder (SpecialFolder.Startup: "The system starts these programs
    # whenever a user logs on"). No admin rights needed.
    # https://learn.microsoft.com/dotnet/api/system.environment.specialfolder
    param([string]$StartupFolder)
    if (-not $StartupFolder) { $StartupFolder = [Environment]::GetFolderPath([Environment+SpecialFolder]::Startup) }
    Join-Path $StartupFolder 'Port Monitor.lnk'
}

function Get-PortMonitorStartupCommand {
    <#
    .SYNOPSIS
        The program and arguments the Startup shortcut runs: Windows PowerShell (always present,
        unlike pwsh) starting this script hidden in the tray. -ConfigPath / -LogPath are added
        only when they differ from the defaults.
    #>
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][string]$LogPath,
        [Parameter(Mandatory)][string]$DefaultConfigPath,
        [Parameter(Mandatory)][string]$DefaultLogPath
    )
    $windowsDir = $env:SystemRoot
    if (-not $windowsDir) { $windowsDir = 'C:\Windows' }
    $arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -STA -File "{0}" -Tray' -f $ScriptPath
    if ($ConfigPath -ne $DefaultConfigPath) { $arguments += ' -ConfigPath "{0}"' -f $ConfigPath }
    if ($LogPath -ne $DefaultLogPath) { $arguments += ' -LogPath "{0}"' -f $LogPath }
    [PSCustomObject]@{
        TargetPath = Join-Path $windowsDir 'System32\WindowsPowerShell\v1.0\powershell.exe'
        Arguments  = $arguments
        ScriptPath = $ScriptPath
    }
}

function Set-PortMonitorStartup {
    <#
    .SYNOPSIS
        Creates or removes the Startup shortcut. Only the file named 'Port Monitor.lnk' is ever
        removed.
    .DESCRIPTION
        The shortcut is made with WScript.Shell CreateShortcut / WshShortcut.Save. WindowStyle 7
        ("Minimizes the window and activates the next top-level window") plus -WindowStyle Hidden
        keeps the console from showing in front at sign-in.
        https://learn.microsoft.com/previous-versions/windows/internet-explorer/ie-developer/windows-scripting/xk6kst2k(v=vs.84)
        https://learn.microsoft.com/previous-versions/windows/internet-explorer/ie-developer/windows-scripting/w88k7fw2(v=vs.84)
    #>
    param(
        [Parameter(Mandatory)][bool]$Enabled,
        [Parameter(Mandatory)][string]$ShortcutPath,
        $Command
    )
    if (-not $Enabled) {
        if (Test-Path -LiteralPath $ShortcutPath -PathType Leaf) { Remove-Item -LiteralPath $ShortcutPath -Force -ErrorAction Stop }
        return
    }
    if ($null -eq $Command) { throw 'A command is needed to create the Startup shortcut.' }
    $folder = Split-Path -Parent $ShortcutPath
    if ($folder -and -not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop | Out-Null }
    $shell = New-Object -ComObject WScript.Shell
    try {
        $link = $shell.CreateShortcut($ShortcutPath)
        $link.TargetPath = $Command.TargetPath
        $link.Arguments = $Command.Arguments
        $link.WindowStyle = 7
        $link.Description = 'Port Monitor: checks server ports in the background and notifies on changes'
        $link.WorkingDirectory = Split-Path -Parent $Command.TargetPath
        $link.Save()
    }
    finally { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }
}

function Read-PortMonitorSettings {
    <#
    .SYNOPSIS
        Per-user settings in settings.json. Never throws: a missing or broken file gives the
        defaults. Keys: StartupOffered (bool), Theme ('Dark'/'Light'), Window (Left, Top, Width,
        Height, Maximized - or $null), SortColumn (column header or ''), SortDirection
        ('Ascending'/'Descending').
    #>
    param([Parameter(Mandatory)][string]$Path)
    $settings = @{ StartupOffered = $false; Theme = 'Dark'; Window = $null; SortColumn = ''; SortDirection = 'Ascending' }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $settings }
    try {
        $parsed = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($Path)) -ErrorAction Stop
        if ($null -eq $parsed) { return $settings }
        $p = $parsed.PSObject.Properties
        if ($p['StartupOffered']) { $settings.StartupOffered = [bool]$parsed.StartupOffered }
        if ($p['Theme'] -and @('Dark', 'Light') -contains [string]$parsed.Theme) { $settings.Theme = [string]$parsed.Theme }
        if ($p['SortColumn']) { $settings.SortColumn = [string]$parsed.SortColumn }
        if ($p['SortDirection'] -and @('Ascending', 'Descending') -contains [string]$parsed.SortDirection) { $settings.SortDirection = [string]$parsed.SortDirection }
        if ($p['Window'] -and $parsed.Window) {
            $w = $parsed.Window
            $settings.Window = @{
                Left = [double]$w.Left; Top = [double]$w.Top; Width = [double]$w.Width; Height = [double]$w.Height
                Maximized = [bool]$w.Maximized
            }
        }
    }
    catch { }
    $settings
}

function Save-PortMonitorSettings {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][hashtable]$Settings)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null }
    $theme = 'Dark'; if ($Settings.Theme -eq 'Light') { $theme = 'Light' }
    $direction = 'Ascending'; if ($Settings.SortDirection -eq 'Descending') { $direction = 'Descending' }
    $window = $null
    if ($Settings.Window) {
        $w = $Settings.Window
        $window = [PSCustomObject]@{ Left = [double]$w.Left; Top = [double]$w.Top; Width = [double]$w.Width; Height = [double]$w.Height; Maximized = [bool]$w.Maximized }
    }
    $json = ConvertTo-Json -Depth 3 -InputObject ([PSCustomObject]@{
            StartupOffered = [bool]$Settings.StartupOffered
            Theme          = $theme
            Window         = $window
            SortColumn     = [string]$Settings.SortColumn
            SortDirection  = $direction
        })
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding -ArgumentList $false))
}

function Test-PortMonitorWindowBounds {
    <#
    .SYNOPSIS
        True when a remembered window position is still usable: at least 120 x 24 px of its top
        edge (where the title bar is) lies on one of the given screens. A window remembered on
        a monitor that has since been unplugged would otherwise open out of reach.
    .PARAMETER Screens
        Working areas of the connected monitors: objects with Left, Top, Width, Height.
    #>
    param([Parameter(Mandatory)]$Bounds, [AllowEmptyCollection()][object[]]$Screens = @())
    if ($null -eq $Bounds -or [double]$Bounds.Width -lt 200 -or [double]$Bounds.Height -lt 150) { return $false }
    $l = [double]$Bounds.Left; $t = [double]$Bounds.Top; $r = $l + [double]$Bounds.Width; $b = $t + 24
    foreach ($s in @($Screens)) {
        $sl = [double]$s.Left; $st = [double]$s.Top; $sr = $sl + [double]$s.Width; $sb = $st + [double]$s.Height
        $w = [math]::Min($r, $sr) - [math]::Max($l, $sl)
        $h = [math]::Min($b, $sb) - [math]::Max($t, $st)
        if ($w -ge 120 -and $h -ge 24) { return $true }
    }
    $false
}

function Get-PortMonitorPalette {
    <#
    .SYNOPSIS
        The colours for the dark (default) or light look, by resource key. The status colours
        (green Open, red down, amber Error) are the same in both and live in the XAML.
    #>
    param([ValidateSet('Dark', 'Light')][string]$Theme = 'Dark')
    if ($Theme -eq 'Light') {
        return @{
            Bg = '#F3F5F7'; Panel = '#FFFFFF'; Surface = '#FFFFFF'; SurfaceAlt = '#F7F9FB'; ColHeader = '#EEF1F4'
            Btn = '#FFFFFF'; BtnBorder = '#C3CAD2'; Line = '#DCE1E6'; GridLine = '#E8ECF0'; RowHover = '#EAF2FA'
            Text = '#1B1E22'; TextMuted = '#5B636E'; TextSoft = '#3C434C'; Hint = '#6B737D'
            Accent = '#1D6FB0'; Pressed = '#D3E5F5'; Selection = '#CFE3F5'; SelectionText = '#0F2A40'
            PrimaryBg = '#1D6FB0'; PrimaryBorder = '#165A91'; DangerBg = '#FBECEA'; DangerBorder = '#E0A39D'; DangerText = '#8A2A23'
            InputBg = '#FFFFFF'; Badge = '#E6EAEE'; BadgeRunning = '#DDF3E4'; PillNeutral = '#E1E5EA'; PillNeutralText = '#3C434C'
        }
    }
    @{
        Bg = '#17191C'; Panel = '#1D2024'; Surface = '#1B1E22'; SurfaceAlt = '#1F2226'; ColHeader = '#202328'
        Btn = '#262A30'; BtnBorder = '#3A4048'; Line = '#2C3036'; GridLine = '#262A30'; RowHover = '#262A30'
        Text = '#E6E8EB'; TextMuted = '#9AA3AE'; TextSoft = '#C5CBD3'; Hint = '#8A939E'
        Accent = '#4FA3E0'; Pressed = '#16405F'; Selection = '#1C3F5E'; SelectionText = '#FFFFFF'
        PrimaryBg = '#1D6FB0'; PrimaryBorder = '#2B86D1'; DangerBg = '#3A2224'; DangerBorder = '#6E3236'; DangerText = '#F2B8B5'
        InputBg = '#15171A'; Badge = '#2A2E34'; BadgeRunning = '#163A24'; PillNeutral = '#30353C'; PillNeutralText = '#C5CBD3'
    }
}

function Set-PortMonitorTheme {
    # Puts the palette's brushes into an element's resources; every {DynamicResource Key} in the
    # window or dialog then picks up the new colour at once.
    param([Parameter(Mandatory)]$Element, [Parameter(Mandatory)][hashtable]$Palette)
    $converter = New-Object System.Windows.Media.BrushConverter
    foreach ($key in $Palette.Keys) {
        $brush = $converter.ConvertFromString($Palette[$key])
        $brush.Freeze()
        $Element.Resources[$key] = $brush
    }
}

function Enter-PortMonitorInstance {
    <#
    .SYNOPSIS
        Takes the one-window-per-user lock. Owned = $false means another Port Monitor window
        (or tray icon) is already running in this sign-in session; signal its ShowEvent to bring
        it forward instead of starting a second copy that would log every change twice.
    .DESCRIPTION
        "Local\" names are shared only by processes in the same session, so other users on an
        RDS host get their own copy. An abandoned mutex (the previous copy was killed) counts
        as acquired; PowerShell wraps the AbandonedMutexException, so the inner exception is
        checked.
        https://learn.microsoft.com/dotnet/api/system.threading.mutex.-ctor
    #>
    param([string]$Name = 'PortMonitor.Gui')
    $mutex = New-Object System.Threading.Mutex -ArgumentList $false, "Local\$Name"
    $owned = $false
    try { $owned = $mutex.WaitOne(0) }
    catch {
        $inner = $_.Exception
        while ($inner -and -not ($inner -is [System.Threading.AbandonedMutexException])) { $inner = $inner.InnerException }
        if ($inner) { $owned = $true } else { throw }
    }
    $showEvent = New-Object System.Threading.EventWaitHandle -ArgumentList $false, ([System.Threading.EventResetMode]::AutoReset), "Local\$Name.Show"
    [PSCustomObject]@{ Mutex = $mutex; Owned = $owned; ShowEvent = $showEvent }
}

function Exit-PortMonitorInstance {
    param([AllowNull()]$Instance)
    if ($null -eq $Instance) { return }
    if ($Instance.Owned) { try { $Instance.Mutex.ReleaseMutex() } catch { } }
    try { $Instance.Mutex.Dispose() } catch { }
    try { $Instance.ShowEvent.Dispose() } catch { }
}

#endregion

#region Window (WPF)

function Get-PortMonitorMainXaml {
    @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Port Monitor" Width="1360" Height="660" MinWidth="1120" MinHeight="420"
        Background="{DynamicResource Bg}" Foreground="{DynamicResource Text}" FontFamily="Segoe UI" FontSize="13"
        WindowStartupLocation="CenterScreen" UseLayoutRounding="True" SnapsToDevicePixels="True">
  <Window.Resources>
    <FontFamily x:Key="Sym">Segoe UI Symbol</FontFamily>
    <Style x:Key="Btn" TargetType="Button">
      <Setter Property="Foreground" Value="{DynamicResource Text}"/>
      <Setter Property="Background" Value="{DynamicResource Btn}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource BtnBorder}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="12,6"/>
      <Setter Property="Margin" Value="0,0,6,0"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="2" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource Accent}"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="{DynamicResource Pressed}"/>
              </Trigger>
              <Trigger Property="IsKeyboardFocused" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource Accent}"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Opacity" Value="0.4"/>
                <Setter Property="Cursor" Value="Arrow"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="PrimaryBtn" TargetType="Button" BasedOn="{StaticResource Btn}">
      <Setter Property="Background" Value="{DynamicResource PrimaryBg}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource PrimaryBorder}"/>
      <Setter Property="Foreground" Value="#FFFFFF"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style x:Key="DangerBtn" TargetType="Button" BasedOn="{StaticResource Btn}">
      <Setter Property="Background" Value="{DynamicResource DangerBg}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource DangerBorder}"/>
    </Style>
    <Style x:Key="Icon" TargetType="TextBlock">
      <Setter Property="FontFamily" Value="{StaticResource Sym}"/>
      <Setter Property="Margin" Value="0,0,7,0"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="{DynamicResource ColHeader}"/>
      <Setter Property="Foreground" Value="{DynamicResource TextMuted}"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Padding" Value="8,7"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Line}"/>
      <Setter Property="BorderThickness" Value="0,0,1,1"/>
    </Style>
    <Style TargetType="DataGridCell">
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="8,0"/>
      <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="DataGridCell">
            <Border Background="{TemplateBinding Background}" Padding="{TemplateBinding Padding}">
              <ContentPresenter VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Background" Value="{DynamicResource Selection}"/>
          <Setter Property="Foreground" Value="{DynamicResource SelectionText}"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="CellText" TargetType="TextBlock">
      <Setter Property="TextTrimming" Value="CharacterEllipsis"/>
    </Style>
    <Style TargetType="DataGridRow">
      <Setter Property="ToolTip" Value="{Binding Detail}"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="{DynamicResource RowHover}"/>
        </Trigger>
      </Style.Triggers>
    </Style>
  </Window.Resources>

  <Grid Background="{DynamicResource Bg}">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Header -->
    <Border Grid.Row="0" Background="{DynamicResource Panel}" BorderBrush="{DynamicResource Line}" BorderThickness="0,0,0,1" Padding="18,14,18,12">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <Border Width="4" Background="{DynamicResource Accent}" Margin="0,2,12,2"/>
        <StackPanel Grid.Column="1">
          <TextBlock Text="Port Monitor" FontSize="20" FontWeight="Bold"/>
          <TextBlock Text="Is each server answering on its port? Checked continuously; every up/down change is logged."
                     Foreground="{DynamicResource TextMuted}" Margin="0,2,0,0"/>
        </StackPanel>
        <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
          <Button x:Name="BtnTheme" Style="{StaticResource Btn}" Margin="0,0,10,0" ToolTip="Switch between the dark and light look">
            <StackPanel Orientation="Horizontal"><TextBlock x:Name="ThemeIcon" Style="{StaticResource Icon}" Text="&#x263C;"/><TextBlock x:Name="ThemeText" Text="Light mode"/></StackPanel>
          </Button>
          <Border x:Name="RunBadge" Background="{DynamicResource Badge}" CornerRadius="2" Padding="12,6" VerticalAlignment="Center">
            <StackPanel Orientation="Horizontal">
              <TextBlock x:Name="RunDot" Text="&#x25CF;" Foreground="#6B737D" Margin="0,0,7,0" VerticalAlignment="Center"/>
              <TextBlock x:Name="RunText" Text="Stopped" FontWeight="SemiBold" VerticalAlignment="Center"/>
            </StackPanel>
          </Border>
        </StackPanel>
      </Grid>
    </Border>

    <!-- Toolbar -->
    <Border Grid.Row="1" Padding="18,12,18,10">
      <DockPanel LastChildFill="False">
        <StackPanel Orientation="Horizontal" DockPanel.Dock="Left">
          <Button x:Name="BtnStart" Style="{StaticResource PrimaryBtn}" ToolTip="Start checking every enabled target">
            <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#x25B6;"/><TextBlock Text="Start"/></StackPanel>
          </Button>
          <Button x:Name="BtnStop" Style="{StaticResource Btn}" ToolTip="Stop checking (the list and log are kept)">
            <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#x25A0;"/><TextBlock Text="Stop"/></StackPanel>
          </Button>
          <Border Width="1" Background="{DynamicResource Line}" Margin="6,2,12,2"/>
          <Button x:Name="BtnAdd" Style="{StaticResource Btn}" ToolTip="Add a server and port to monitor">
            <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="+" FontWeight="Bold"/><TextBlock Text="Add"/></StackPanel>
          </Button>
          <Button x:Name="BtnEdit" Style="{StaticResource Btn}" ToolTip="Change the selected target (or double-click a row)">
            <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#x270E;"/><TextBlock Text="Edit"/></StackPanel>
          </Button>
          <Button x:Name="BtnRemove" Style="{StaticResource DangerBtn}" ToolTip="Stop monitoring the selected target">
            <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#x2715;"/><TextBlock Text="Remove"/></StackPanel>
          </Button>
        </StackPanel>
        <StackPanel Orientation="Horizontal" DockPanel.Dock="Right">
          <Button x:Name="BtnBackground" Style="{StaticResource Btn}" ToolTip="Hide this window and keep checking in the notification area (near the clock). You get a notification when a server goes down or comes back.">
            <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#x2198;"/><TextBlock Text="Run in Background"/></StackPanel>
          </Button>
          <Border Width="1" Background="{DynamicResource Line}" Margin="0,2,12,2"/>
          <Button x:Name="BtnImport" Style="{StaticResource Btn}" ToolTip="Open another target list (for example one client's list); changes are saved to that file">
            <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#x21E9;"/><TextBlock Text="Import"/></StackPanel>
          </Button>
          <Button x:Name="BtnExport" Style="{StaticResource Btn}" ToolTip="Save a copy of this target list to a file">
            <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#x21E7;"/><TextBlock Text="Export"/></StackPanel>
          </Button>
          <Button x:Name="BtnReport" Style="{StaticResource Btn}" ToolTip="Make an uptime and outage report from the logs (last 24 hours, 7 days or 30 days) and open it">
            <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#x2261;"/><TextBlock Text="Report"/><TextBlock Style="{StaticResource Icon}" Text="&#x25BE;" Margin="6,0,0,0"/></StackPanel>
          </Button>
          <Button x:Name="BtnLogs" Style="{StaticResource Btn}" Margin="0" ToolTip="Open the folder with the daily state-change CSV files">
            <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#x2630;"/><TextBlock Text="Open Log Folder"/></StackPanel>
          </Button>
        </StackPanel>
      </DockPanel>
    </Border>

    <!-- Grid -->
    <Grid Grid.Row="2" Margin="18,0,18,12">
      <!-- Fixed columns are kept narrow (units in the cells, dates without the year) so everything
           fits at the default size. Label, Host and Details share the rest but never shrink below
           their MinWidth: in a narrower window the grid scrolls sideways instead of squashing them. -->
      <DataGrid x:Name="Grid" AutoGenerateColumns="False" IsReadOnly="True" CanUserAddRows="False" CanUserDeleteRows="False"
                HorizontalScrollBarVisibility="Auto"
                SelectionMode="Single" SelectionUnit="FullRow" HeadersVisibility="Column" GridLinesVisibility="Horizontal"
                HorizontalGridLinesBrush="{DynamicResource GridLine}" Background="{DynamicResource Surface}" RowBackground="{DynamicResource Surface}" AlternatingRowBackground="{DynamicResource SurfaceAlt}"
                Foreground="{DynamicResource Text}" BorderBrush="{DynamicResource Line}" BorderThickness="1" RowHeight="30" CanUserResizeRows="False">
        <DataGrid.Columns>
          <DataGridTemplateColumn Header="Enabled" Width="66" SortMemberPath="Enabled">
            <DataGridTemplateColumn.CellTemplate>
              <DataTemplate>
                <CheckBox IsChecked="{Binding Enabled, Mode=OneWay}" HorizontalAlignment="Center" VerticalAlignment="Center"
                          Cursor="Hand" ToolTip="Turn checking of this target on or off"/>
              </DataTemplate>
            </DataGridTemplateColumn.CellTemplate>
          </DataGridTemplateColumn>
          <DataGridTextColumn Header="Label" Binding="{Binding Label}" Width="1.4*" MinWidth="120" FontWeight="SemiBold" ElementStyle="{StaticResource CellText}"/>
          <DataGridTextColumn Header="Host" Binding="{Binding Host}" Width="1.3*" MinWidth="120" FontFamily="Cascadia Mono, Consolas" ElementStyle="{StaticResource CellText}"/>
          <DataGridTextColumn Header="Port" Binding="{Binding Port}" Width="58" FontFamily="Cascadia Mono, Consolas"/>
          <DataGridTemplateColumn Header="Status" Width="108" SortMemberPath="Status">
            <DataGridTemplateColumn.CellTemplate>
              <DataTemplate>
                <Border x:Name="Pill" Background="{DynamicResource PillNeutral}" CornerRadius="2" Padding="8,2" HorizontalAlignment="Left" VerticalAlignment="Center">
                  <TextBlock x:Name="PillText" Text="{Binding Status}" Foreground="{DynamicResource PillNeutralText}" FontWeight="SemiBold" FontSize="12"/>
                </Border>
                <DataTemplate.Triggers>
                  <DataTrigger Binding="{Binding Status}" Value="Open">
                    <Setter TargetName="Pill" Property="Background" Value="#1D7A45"/>
                    <Setter TargetName="PillText" Property="Foreground" Value="#FFFFFF"/>
                  </DataTrigger>
                  <DataTrigger Binding="{Binding Status}" Value="Refused">
                    <Setter TargetName="Pill" Property="Background" Value="#A8322A"/>
                    <Setter TargetName="PillText" Property="Foreground" Value="#FFFFFF"/>
                  </DataTrigger>
                  <DataTrigger Binding="{Binding Status}" Value="Timeout">
                    <Setter TargetName="Pill" Property="Background" Value="#A8322A"/>
                    <Setter TargetName="PillText" Property="Foreground" Value="#FFFFFF"/>
                  </DataTrigger>
                  <DataTrigger Binding="{Binding Status}" Value="DNS Failure">
                    <Setter TargetName="Pill" Property="Background" Value="#A8322A"/>
                    <Setter TargetName="PillText" Property="Foreground" Value="#FFFFFF"/>
                  </DataTrigger>
                  <DataTrigger Binding="{Binding Status}" Value="Error">
                    <Setter TargetName="Pill" Property="Background" Value="#9A6510"/>
                    <Setter TargetName="PillText" Property="Foreground" Value="#FFFFFF"/>
                  </DataTrigger>
                </DataTemplate.Triggers>
              </DataTemplate>
            </DataGridTemplateColumn.CellTemplate>
          </DataGridTemplateColumn>
          <DataGridTextColumn Header="Latency" Binding="{Binding LatencyMs, StringFormat='{}{0:0.0} ms', TargetNullValue=''}" Width="80"/>
          <DataGridTemplateColumn Header="Loss %" Width="68" SortMemberPath="LossPercent">
            <DataGridTemplateColumn.CellTemplate>
              <DataTemplate>
                <Border x:Name="LossPill" Background="Transparent" CornerRadius="2" Padding="6,1" HorizontalAlignment="Left" VerticalAlignment="Center">
                  <TextBlock x:Name="LossTxt" Text="{Binding LossText}" Foreground="{DynamicResource Text}"/>
                </Border>
                <DataTemplate.Triggers>
                  <DataTrigger Binding="{Binding LossStatus}" Value="High loss">
                    <Setter TargetName="LossPill" Property="Background" Value="#9A6510"/>
                    <Setter TargetName="LossTxt" Property="Foreground" Value="#FFFFFF"/>
                    <Setter TargetName="LossTxt" Property="FontWeight" Value="SemiBold"/>
                  </DataTrigger>
                  <DataTrigger Binding="{Binding LossStatus}" Value="No replies">
                    <Setter TargetName="LossTxt" Property="Foreground" Value="{DynamicResource TextMuted}"/>
                    <Setter TargetName="LossTxt" Property="FontStyle" Value="Italic"/>
                  </DataTrigger>
                </DataTemplate.Triggers>
              </DataTemplate>
            </DataGridTemplateColumn.CellTemplate>
          </DataGridTemplateColumn>
          <DataGridTextColumn Header="Jitter" Binding="{Binding JitterMs, StringFormat='{}{0:0.0} ms', TargetNullValue=''}" Width="72"/>
          <DataGridTextColumn Header="Last Checked" Binding="{Binding LastChecked, StringFormat={}{0:MM-dd HH:mm:ss}}" Width="110"/>
          <DataGridTextColumn Header="Last Change" Binding="{Binding LastStateChange, StringFormat={}{0:MM-dd HH:mm:ss}}" Width="110"/>
          <DataGridTextColumn Header="Fails" Binding="{Binding FailCount}" Width="56"/>
          <DataGridTextColumn Header="Uptime %" Binding="{Binding UptimePercent, StringFormat={}{0:0.0}}" Width="76"/>
          <!-- The colour is set on the cell's TextBlock, not on the column: a column is not in the
               visual tree, so a theme colour set on it never resolves (the text came out black). -->
          <DataGridTextColumn Header="Details" Binding="{Binding Detail}" Width="2*" MinWidth="200">
            <DataGridTextColumn.ElementStyle>
              <Style TargetType="TextBlock" BasedOn="{StaticResource CellText}">
                <Setter Property="Foreground" Value="{DynamicResource TextMuted}"/>
              </Style>
            </DataGridTextColumn.ElementStyle>
          </DataGridTextColumn>
        </DataGrid.Columns>
      </DataGrid>
      <StackPanel x:Name="EmptyState" HorizontalAlignment="Center" VerticalAlignment="Center" IsHitTestVisible="False">
        <TextBlock Text="No targets yet" FontSize="16" FontWeight="SemiBold" HorizontalAlignment="Center"/>
        <TextBlock Text="Click Add to monitor a server and port, or Import a client's target list." Foreground="{DynamicResource TextMuted}" Margin="0,6,0,0"/>
      </StackPanel>
    </Grid>

    <!-- Status bar -->
    <Border Grid.Row="3" Background="{DynamicResource Panel}" BorderBrush="{DynamicResource Line}" BorderThickness="0,1,0,0" Padding="18,7">
      <Grid>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <TextBlock Text="Targets file:" Foreground="{DynamicResource TextMuted}" Margin="0,0,6,0"/>
        <TextBlock x:Name="ConfigText" Grid.Column="1" FontFamily="Cascadia Mono, Consolas" FontSize="12" VerticalAlignment="Center"
                   TextTrimming="CharacterEllipsis" ToolTip="{Binding Text, RelativeSource={RelativeSource Self}}"/>
        <TextBlock Text="Log folder:" Grid.Column="2" Foreground="{DynamicResource TextMuted}" Margin="16,0,6,0"/>
        <TextBlock x:Name="LogText" Grid.Column="3" FontFamily="Cascadia Mono, Consolas" FontSize="12" VerticalAlignment="Center"
                   TextTrimming="CharacterEllipsis" ToolTip="{Binding Text, RelativeSource={RelativeSource Self}}"/>
        <TextBlock x:Name="MessageText" Grid.Row="1" Grid.ColumnSpan="4" Foreground="{DynamicResource TextSoft}" TextTrimming="CharacterEllipsis" Margin="0,4,0,0"
                   ToolTip="{Binding Text, RelativeSource={RelativeSource Self}}"/>
      </Grid>
    </Border>
  </Grid>
</Window>
'@
}

function Get-PortTargetDialogXaml {
    @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Target" Width="520" SizeToContent="Height" ResizeMode="NoResize"
        Background="{DynamicResource Panel}" Foreground="{DynamicResource Text}" FontFamily="Segoe UI" FontSize="13"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False">
  <Window.Resources>
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="{DynamicResource InputBg}"/>
      <Setter Property="Foreground" Value="{DynamicResource Text}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource BtnBorder}"/>
      <Setter Property="CaretBrush" Value="{DynamicResource Text}"/>
      <Setter Property="Padding" Value="6,5"/>
      <Setter Property="Margin" Value="0,4,0,0"/>
      <Style.Triggers>
        <Trigger Property="IsKeyboardFocused" Value="True"><Setter Property="BorderBrush" Value="{DynamicResource Accent}"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="Lbl" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{DynamicResource TextSoft}"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Margin" Value="0,12,0,0"/>
    </Style>
    <Style x:Key="Hint" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{DynamicResource Hint}"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Margin" Value="0,3,0,0"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
    </Style>
    <Style x:Key="Btn" TargetType="Button">
      <Setter Property="Foreground" Value="{DynamicResource Text}"/>
      <Setter Property="Background" Value="{DynamicResource Btn}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource BtnBorder}"/>
      <Setter Property="Padding" Value="16,6"/>
      <Setter Property="Margin" Value="8,0,0,0"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="2" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource Accent}"/></Trigger>
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="Bd" Property="Background" Value="{DynamicResource Pressed}"/></Trigger>
              <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource Accent}"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>
  <StackPanel Margin="20,14,20,18">
    <TextBlock x:Name="Heading" Text="Add a target" FontSize="17" FontWeight="Bold"/>
    <TextBlock Text="Label" Style="{StaticResource Lbl}"/>
    <TextBox x:Name="TxtLabel"/>
    <TextBlock Text="A name you will recognise, for example &quot;Contoso DC01 - LDAP&quot;. Optional." Style="{StaticResource Hint}"/>
    <TextBlock Text="Host" Style="{StaticResource Lbl}"/>
    <TextBox x:Name="TxtHost" FontFamily="Cascadia Mono, Consolas"/>
    <TextBlock Text="Server name or IP address." Style="{StaticResource Hint}"/>
    <StackPanel x:Name="RolePanel">
      <TextBlock Text="What is it?" Style="{StaticResource Lbl}"/>
      <ComboBox x:Name="CmbRole" Margin="0,4,0,0" Padding="6,4" Foreground="#1B1E22"/>
      <TextBlock x:Name="RoleHint" Text="Pick a kind of server to add all its usual ports at once, or keep &quot;One port&quot;." Style="{StaticResource Hint}"/>
      <WrapPanel x:Name="PortChecks" Margin="0,6,0,0" Visibility="Collapsed"/>
    </StackPanel>
    <Grid>
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="12"/>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="12"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <StackPanel x:Name="PortBox" Grid.Column="0">
        <TextBlock Text="Port" Style="{StaticResource Lbl}"/>
        <TextBox x:Name="TxtPort" FontFamily="Cascadia Mono, Consolas"/>
        <TextBlock Text="1 - 65535" Style="{StaticResource Hint}"/>
      </StackPanel>
      <StackPanel Grid.Column="2">
        <TextBlock Text="Check every (sec)" Style="{StaticResource Lbl}"/>
        <TextBox x:Name="TxtInterval" FontFamily="Cascadia Mono, Consolas"/>
        <TextBlock Text="1 or more" Style="{StaticResource Hint}"/>
      </StackPanel>
      <StackPanel Grid.Column="4">
        <TextBlock Text="Timeout (ms)" Style="{StaticResource Lbl}"/>
        <TextBox x:Name="TxtTimeout" FontFamily="Cascadia Mono, Consolas"/>
        <TextBlock Text="100 - 30000. Under 2500 a closed port shows as Timeout." Style="{StaticResource Hint}"/>
      </StackPanel>
    </Grid>
    <Grid>
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="12"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <StackPanel Grid.Column="0">
        <TextBlock Text="Report down after" Style="{StaticResource Lbl}"/>
        <TextBox x:Name="TxtFailAfter" FontFamily="Cascadia Mono, Consolas"/>
        <TextBlock Text="failed checks in a row (1 - 10). 2 ignores one-off blips." Style="{StaticResource Hint}"/>
      </StackPanel>
      <StackPanel Grid.Column="2">
        <TextBlock Text="Report back up after" Style="{StaticResource Lbl}"/>
        <TextBox x:Name="TxtRecoverAfter" FontFamily="Cascadia Mono, Consolas"/>
        <TextBlock Text="good checks in a row (1 - 10)." Style="{StaticResource Hint}"/>
      </StackPanel>
    </Grid>
    <Border BorderBrush="{DynamicResource Line}" BorderThickness="0,1,0,0" Margin="0,16,0,0" Padding="0,12,0,0">
      <StackPanel>
        <CheckBox x:Name="ChkLoss" Content="Measure packet loss (ping the host after each check)" Foreground="{DynamicResource Text}"/>
        <Grid x:Name="LossBox" IsEnabled="{Binding IsChecked, ElementName=ChkLoss}">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="12"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <StackPanel Grid.Column="0">
            <TextBlock Text="Pings per check" Style="{StaticResource Lbl}"/>
            <TextBox x:Name="TxtLossPings" FontFamily="Cascadia Mono, Consolas"/>
            <TextBlock Text="1 - 50. More pings give a steadier figure." Style="{StaticResource Hint}"/>
          </StackPanel>
          <StackPanel Grid.Column="2">
            <TextBlock Text="Warn when this % is lost" Style="{StaticResource Lbl}"/>
            <TextBox x:Name="TxtLossAlert" FontFamily="Cascadia Mono, Consolas"/>
            <TextBlock Text="1 - 100. Uses the Report down / back up counts above." Style="{StaticResource Hint}"/>
          </StackPanel>
        </Grid>
        <TextBlock x:Name="LossHint" Style="{StaticResource Hint}" Margin="0,8,0,0"
                   Text="Shows lost packets that the port check cannot see. Some firewalls block ping: then Loss % says &quot;no reply&quot; and nothing is reported."/>
      </StackPanel>
    </Border>
    <CheckBox x:Name="ChkEnabled" Content="Check this target" Foreground="{DynamicResource Text}" Margin="0,14,0,0" IsChecked="True"/>
    <Border x:Name="ErrorBox" Background="{DynamicResource DangerBg}" BorderBrush="{DynamicResource DangerBorder}" BorderThickness="1" CornerRadius="2" Padding="10,7" Margin="0,14,0,0" Visibility="Collapsed">
      <TextBlock x:Name="ErrorText" Foreground="{DynamicResource DangerText}" TextWrapping="Wrap"/>
    </Border>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,18,0,0">
      <Button x:Name="BtnCancel" Content="Cancel" Style="{StaticResource Btn}" IsCancel="True"/>
      <Button x:Name="BtnSave" Content="Save" Style="{StaticResource Btn}" Background="{DynamicResource PrimaryBg}" BorderBrush="{DynamicResource PrimaryBorder}" Foreground="#FFFFFF" FontWeight="SemiBold" IsDefault="True"/>
    </StackPanel>
  </StackPanel>
</Window>
'@
}

function Show-PortTargetDialog {
    <#
    .SYNOPSIS
        Add/Edit dialog. Returns the validated targets as an array (empty when cancelled):
        one target, or one per ticked port when a role preset is chosen in Add mode.
    .PARAMETER ExistingTargets
        Targets already in the list: preset ports already monitored on the same host are left
        out (and the dialog says how many).
    #>
    param($Owner, $Target, [hashtable]$Palette, [AllowNull()][AllowEmptyCollection()][object[]]$ExistingTargets = @())
    $dialog = [System.Windows.Markup.XamlReader]::Parse((Get-PortTargetDialogXaml))
    if ($Palette) { Set-PortMonitorTheme -Element $dialog -Palette $Palette }
    $f = @{}
    foreach ($n in 'Heading', 'TxtLabel', 'TxtHost', 'TxtPort', 'TxtInterval', 'TxtTimeout', 'TxtFailAfter', 'TxtRecoverAfter', 'ChkEnabled',
        'ErrorBox', 'ErrorText', 'BtnSave', 'RolePanel', 'CmbRole', 'RoleHint', 'PortChecks', 'PortBox', 'ChkLoss', 'TxtLossPings', 'TxtLossAlert', 'LossHint') {
        $f[$n] = $dialog.FindName($n)
    }
    $sets = @(Get-PortMonitorPortSets)
    $f.Sets = $sets
    if ($null -ne $Target) {
        $dialog.Title = 'Edit target'
        $f.Heading.Text = 'Edit target'
        $f.RolePanel.Visibility = 'Collapsed'
        $f.TxtLabel.Text = [string]$Target.Label
        $f.TxtHost.Text = [string]$Target.Host
        $f.TxtPort.Text = [string]$Target.Port
        $f.TxtInterval.Text = [string]$Target.IntervalSec
        $f.TxtTimeout.Text = [string]$Target.TimeoutMs
        $f.TxtFailAfter.Text = [string]$Target.FailAfter
        $f.TxtRecoverAfter.Text = [string]$Target.RecoverAfter
        $f.ChkEnabled.IsChecked = [bool]$Target.Enabled
        $f.ChkLoss.IsChecked = [bool]$Target.MeasureLoss
        $f.TxtLossPings.Text = [string]$Target.LossPings
        $f.TxtLossAlert.Text = [string]$Target.LossAlertPercent
    }
    else {
        $dialog.Title = 'Add target'
        $f.TxtInterval.Text = '30'
        $f.TxtTimeout.Text = '3000'
        $f.TxtFailAfter.Text = '2'
        $f.TxtRecoverAfter.Text = '1'
        $f.TxtLossPings.Text = '10'
        $f.TxtLossAlert.Text = '5'
        [void]$f.CmbRole.Items.Add('One port (type it below)')
        foreach ($s in $sets) { [void]$f.CmbRole.Items.Add("$($s.Name) - $(@($s.Ports | ForEach-Object { $_.Port }) -join ', ')") }
        $f.CmbRole.SelectedIndex = 0
    }
    if ($null -ne $Owner) { $dialog.Owner = $Owner }

    $f.CmbRole.add_SelectionChanged({
            $f.PortChecks.Children.Clear()
            $i = $f.CmbRole.SelectedIndex
            if ($i -le 0) {
                $f.PortChecks.Visibility = 'Collapsed'
                $f.PortBox.Visibility = 'Visible'
                $f.RoleHint.Text = 'Pick a kind of server to add all its usual ports at once, or keep "One port".'
                return
            }
            $set = $f.Sets[$i - 1]
            $f.RoleHint.Text = "$($set.Description). Untick any port you don't want; each ticked port becomes its own row."
            foreach ($p in $set.Ports) {
                $box = New-Object System.Windows.Controls.CheckBox
                $box.Content = "$($p.Port) $($p.Service)"
                $box.Tag = $p.Port
                $box.IsChecked = $true
                $box.Margin = '0,2,14,2'
                $box.SetResourceReference([System.Windows.Controls.Control]::ForegroundProperty, 'Text')
                [void]$f.PortChecks.Children.Add($box)
            }
            $f.PortChecks.Visibility = 'Visible'
            $f.PortBox.Visibility = 'Collapsed'
            $f.LossHint.Text = 'Shows lost packets that the port check cannot see. With a preset only the first port pings the host: loss is the same for every port. Some firewalls block ping: then Loss % says "no reply".'
        })

    $outcome = @{ Value = @() }
    $f.BtnSave.add_Click({
            $role = $f.CmbRole.SelectedIndex
            $candidate = [PSCustomObject]@{
                Label        = $f.TxtLabel.Text
                Host         = $f.TxtHost.Text
                Port         = $f.TxtPort.Text
                IntervalSec  = $f.TxtInterval.Text
                TimeoutMs    = $f.TxtTimeout.Text
                FailAfter    = $f.TxtFailAfter.Text
                RecoverAfter = $f.TxtRecoverAfter.Text
                Enabled      = [bool]$f.ChkEnabled.IsChecked
                MeasureLoss  = [bool]$f.ChkLoss.IsChecked
                LossPings    = $f.TxtLossPings.Text
                LossAlertPercent = $f.TxtLossAlert.Text
            }
            if ($null -eq $Target -and $role -gt 0) { $candidate.Port = 1 }   # ports come from the preset
            $normalised = ConvertTo-PortTarget $candidate
            $problems = @(Test-PortTargetDefinition $normalised)
            # A blank port must not pass as the default: say so explicitly.
            if (($null -ne $Target -or $role -le 0) -and "$($candidate.Port)".Trim() -eq '') {
                $problems = @('Port is blank: enter a number from 1 to 65535.') + @($problems | Where-Object { $_ -notlike 'Port *' })
            }
            $result = @($normalised)
            if ($null -eq $Target -and $role -gt 0 -and $problems.Count -eq 0) {
                $ticked = @($f.PortChecks.Children | Where-Object { $_.IsChecked } | ForEach-Object { [int]$_.Tag })
                if ($ticked.Count -eq 0) { $problems += 'Tick at least one port.' }
                else {
                    $name = "$($candidate.Label)".Trim()
                    $result = @(New-PortTargetsFromSet -Set $f.Sets[$role - 1] -HostName $normalised.Host -Name $name -Ports $ticked `
                            -IntervalSec $normalised.IntervalSec -TimeoutMs $normalised.TimeoutMs -FailAfter $normalised.FailAfter `
                            -RecoverAfter $normalised.RecoverAfter -Enabled $normalised.Enabled -MeasureLoss $normalised.MeasureLoss `
                            -LossPings $normalised.LossPings -LossAlertPercent $normalised.LossAlertPercent -ExistingTargets $ExistingTargets)
                    if ($result.Count -eq 0) { $problems += "Every ticked port on $($normalised.Host) is already in the list." }
                }
            }
            if (@($problems).Count -gt 0) {
                $f.ErrorText.Text = ($problems -join [Environment]::NewLine)
                $f.ErrorBox.Visibility = 'Visible'
                return
            }
            $outcome.Value = $result
            $dialog.DialogResult = $true
        })
    $dialog.add_ContentRendered({
            # Can arrive after the dialog already closed (then $f is out of scope): guard it.
            if (-not $f -or -not $f.TxtHost -or -not $dialog.IsVisible) { return }
            $f.TxtHost.Focus() | Out-Null
            if ($f.TxtHost.Text) { $f.TxtLabel.Focus() | Out-Null }
        })
    [void]$dialog.ShowDialog()
    # Emitted one by one (no leading comma): callers collect with @(). A wrapped array would
    # reach the caller as ONE item and every preset target would collapse into a single row.
    foreach ($t in @($outcome.Value)) { $t }
}

function Set-SmokeWindowPosition {
    # Puts the window beyond the top-left of the virtual screen (all monitors) so it renders
    # without being seen and without taking the focus. A hidden window would never render.
    # https://learn.microsoft.com/dotnet/api/system.windows.systemparameters.virtualscreenleft
    param([Parameter(Mandatory)]$Window)
    $Window.WindowStartupLocation = 'Manual'
    $Window.ShowInTaskbar = $false
    $Window.ShowActivated = $false
    $Window.Left = [System.Windows.SystemParameters]::VirtualScreenLeft - $Window.Width - 200
    $Window.Top = [System.Windows.SystemParameters]::VirtualScreenTop - $Window.Height - 200
}

function Show-PortMonitorWindow {
    <#
    .SYNOPSIS
        Builds the window and the tray icon and runs until the user exits. Returns the
        smoke-test exit code with -SmokeTest, else 0.
    .DESCRIPTION
        Window mode: the window opens; closing it exits.
        Tray mode (-Tray, or "Run in Background"): monitoring runs with the window hidden;
        closing the window hides it again; only Exit on the tray menu quits.
        The window is shown with Show() and the thread runs a DispatcherFrame, not ShowDialog(),
        so the window can be hidden and shown again while the app keeps running.
        https://learn.microsoft.com/dotnet/api/system.windows.threading.dispatcher.pushframe
    #>
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][string]$LogDirectory,
        [switch]$Tray,
        [switch]$SmokeTest,
        [string]$SettingsPath,
        [string]$StartupShortcutPath,
        $StartupCommand,
        $Instance
    )
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms, System.Drawing

    $window = [System.Windows.Markup.XamlReader]::Parse((Get-PortMonitorMainXaml))
    $c = @{}
    foreach ($n in 'Grid', 'EmptyState', 'BtnStart', 'BtnStop', 'BtnAdd', 'BtnEdit', 'BtnRemove', 'BtnImport', 'BtnExport', 'BtnLogs', 'BtnBackground',
        'BtnReport', 'BtnTheme', 'ThemeIcon', 'ThemeText', 'RunBadge', 'RunDot', 'RunText', 'ConfigText', 'LogText', 'MessageText') {
        $c[$n] = $window.FindName($n)
        if ($null -eq $c[$n]) { throw "The window layout is missing the element '$n'." }
    }

    # A DataGrid short of space squeezes fixed-width columns down to their MinWidth (20 by
    # default) before it scrolls, which cut the Enabled and Port columns in half. Pinning
    # MinWidth to each fixed width makes it scroll sideways instead.
    foreach ($col in $c.Grid.Columns) {
        if (-not $col.Width.IsStar -and $col.Width.Value -gt 0) { $col.MinWidth = $col.Width.Value }
    }

    # Everything the handlers change lives in this hashtable: handler scriptblocks run in a
    # child scope, so assigning a plain variable there would not change it here.
    $c.MessageText.Text = 'Click Start to begin checking. Double-click a row to change it.'
    $ui = @{
        States              = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
        Engine              = $null
        Running             = $false
        ConfigPath          = $ConfigPath
        LogDirectory        = $LogDirectory
        BackupPending       = $false
        StartupNotes        = @()
        TrayMode            = [bool]$Tray
        Exiting             = $false
        Frame               = $null
        Notify              = $null
        Icons               = @{}
        TrayState           = ''
        HideTipShown        = $false
        SettingsPath        = $SettingsPath
        StartupShortcutPath = $StartupShortcutPath
        StartupCommand      = $StartupCommand
        ShowEvent           = $null
        Smoke               = [bool]$SmokeTest
        SmokeRendered       = $false
        SmokeProbe          = $null
        SmokeProbeOk        = $false
        SmokeProbeDone      = $false
        SmokeFailures       = New-Object System.Collections.ArrayList
        SmokeStarted        = Get-Date
        ConsoleKeys         = $false
        CtrlC               = $false
    }
    if ($null -ne $Instance) { $ui.ShowEvent = $Instance.ShowEvent }
    $ui.Window = $window
    $ui.Balloons = New-Object System.Collections.ArrayList
    $ui.WasShown = $false
    # Per-user look and window placement (not read or written in a smoke run).
    $ui.Settings = @{ StartupOffered = $false; Theme = 'Dark'; Window = $null; SortColumn = ''; SortDirection = 'Ascending' }
    if (-not $ui.Smoke -and $ui.SettingsPath) { $ui.Settings = Read-PortMonitorSettings -Path $ui.SettingsPath }
    $ui.Palette = Get-PortMonitorPalette -Theme $ui.Settings.Theme
    Set-PortMonitorTheme -Element $window -Palette $ui.Palette
    # For tests that dot-source the script: lets them see the live state while the app runs.
    $script:PortMonitorUi = $ui

    function Show-Message {
        param([string]$Text, [string]$Title = 'Port Monitor', [string]$Buttons = 'OK', [string]$Icon = 'Information')
        if ($ui.Smoke) { [void]$ui.SmokeFailures.Add("a message box would have been shown: $Text"); return 'OK' }
        # A hidden owner would hide the message too: own it only while the window is on screen.
        if ($window.IsVisible) { return [string][System.Windows.MessageBox]::Show($window, $Text, $Title, $Buttons, $Icon) }
        [string][System.Windows.MessageBox]::Show($Text, $Title, $Buttons, $Icon)
    }
    function Set-StatusMessage { param([string]$Text) $c.MessageText.Text = $Text }
    function Update-Tray {
        if ($null -eq $ui.Notify) { return }
        $summary = Get-PortMonitorTraySummary -States @($ui.States) -Running $ui.Running
        if ($summary.State -ne $ui.TrayState) {
            $ui.Notify.Icon = $ui.Icons[$summary.State]
            $ui.TrayState = $summary.State
        }
        if ($ui.Notify.Text -ne $summary.Text) { $ui.Notify.Text = $summary.Text }
    }
    function Update-View {
        $c.Grid.Items.Refresh()
        $hasRows = $ui.States.Count -gt 0
        if ($hasRows) { $c.EmptyState.Visibility = 'Collapsed' } else { $c.EmptyState.Visibility = 'Visible' }
        $selected = $null -ne $c.Grid.SelectedItem
        $c.BtnEdit.IsEnabled = $selected
        $c.BtnRemove.IsEnabled = $selected
        $c.BtnStart.IsEnabled = -not $ui.Running
        $c.BtnStop.IsEnabled = $ui.Running
        $c.ConfigText.Text = $ui.ConfigPath
        $c.LogText.Text = $ui.LogDirectory
        $converter = New-Object System.Windows.Media.BrushConverter
        if ($ui.Running) {
            $enabledCount = @($ui.States | Where-Object { $_.Enabled }).Count
            $c.RunText.Text = "Running - $enabledCount target(s)"
            $c.RunDot.Foreground = $converter.ConvertFromString('#3FB950')
            $c.RunBadge.Background = $converter.ConvertFromString($ui.Palette.BadgeRunning)
        }
        else {
            $c.RunText.Text = 'Stopped'
            $c.RunDot.Foreground = $converter.ConvertFromString('#6B737D')
            $c.RunBadge.Background = $converter.ConvertFromString($ui.Palette.Badge)
        }
        Update-Tray
    }
    function Save-UiTargets {
        if ($ui.Smoke) { [void]$ui.SmokeFailures.Add('the target list would have been saved'); return }
        try {
            $saved = Save-PortMonitorConfig -Path $ui.ConfigPath -Targets @($ui.States) -BackupExisting:$ui.BackupPending
            $ui.BackupPending = $false
            if ($saved.BackupPath) { Set-StatusMessage "Saved. The previous file was kept as $($saved.BackupPath)" }
            else { Set-StatusMessage ("Saved {0} target(s) at {1}" -f $saved.Count, (Get-Date -Format 'HH:mm:ss')) }
        }
        catch {
            Show-Message -Text "Could not save the target list to $($ui.ConfigPath):`n`n$($_.Exception.Message)" -Icon 'Warning' | Out-Null
        }
    }
    function Get-EngineReady {
        if ($null -eq $ui.Engine) { $ui.Engine = New-PortMonitorEngine }
        $ui.Engine
    }
    function Start-Monitoring {
        param([switch]$Quiet)
        $enabled = @($ui.States | Where-Object { $_.Enabled })
        if ($enabled.Count -eq 0) {
            if (-not $Quiet) { Show-Message -Text 'There is nothing to check yet. Add a target, or turn one on with its Enabled box.' | Out-Null }
            return
        }
        [void](Get-EngineReady)
        foreach ($s in $enabled) { $s.NextDue = [datetime]::MinValue }
        $ui.Running = $true
        Set-StatusMessage 'Monitoring started.'
        Update-View
    }
    function Stop-Monitoring {
        if ($ui.Engine) { Suspend-PortMonitorChecks -Engine $ui.Engine -States @($ui.States) }
        $ui.Running = $false
        Set-StatusMessage 'Monitoring stopped. The list and the log are kept.'
        Update-View
    }
    function Show-Balloon {
        param([string]$Title, [string]$Text, [string]$Icon = 'Info')
        if ($null -eq $ui.Notify -or -not $ui.Notify.Visible -or -not $Text) { return }
        [void]$ui.Balloons.Add([PSCustomObject]@{ Time = (Get-Date); Title = $Title; Text = $Text; Icon = $Icon })
        while ($ui.Balloons.Count -gt 20) { $ui.Balloons.RemoveAt(0) }
        # The timeout argument is ignored on Vista and later (system accessibility settings).
        $ui.Notify.ShowBalloonTip(10000, $Title, $Text, [System.Windows.Forms.ToolTipIcon]$Icon)
    }
    function Show-MainWindow {
        if ($ui.Smoke) { return }
        $window.Show()
        if ($window.WindowState -eq [System.Windows.WindowState]::Minimized) { $window.WindowState = [System.Windows.WindowState]::Normal }
        [void]$window.Activate()
        Update-View
    }
    function Test-StartupEnabled {
        if (-not $ui.StartupShortcutPath) { return $false }
        Test-Path -LiteralPath $ui.StartupShortcutPath -PathType Leaf
    }
    function Set-StartupEnabled {
        param([bool]$Enabled)
        if ($ui.Smoke) { [void]$ui.SmokeFailures.Add('the Startup shortcut would have been changed'); return }
        try {
            Set-PortMonitorStartup -Enabled $Enabled -ShortcutPath $ui.StartupShortcutPath -Command $ui.StartupCommand
            if ($Enabled) { Show-Balloon -Title 'Port Monitor will start when you sign in' -Text 'It runs here in the notification area. Right-click the icon to change this.' }
            else { Set-StatusMessage 'Port Monitor will no longer start when you sign in.' }
        }
        catch {
            Show-Message -Text "Could not change the Startup shortcut $($ui.StartupShortcutPath):`n`n$($_.Exception.Message)" -Icon 'Warning' | Out-Null
        }
    }
    function Request-StartupOffer {
        # Asked once per user (remembered in settings.json), and only while it is not set up.
        if ($ui.Smoke -or -not $ui.SettingsPath -or -not $ui.StartupShortcutPath) { return }
        if (Test-StartupEnabled) { return }
        if ($ui.Settings.StartupOffered) { return }
        $ui.Settings.StartupOffered = $true
        Save-UiSettings
        $answer = Show-Message -Title 'Port Monitor' -Buttons 'YesNo' -Icon 'Question' -Text ("Start Port Monitor in the background every time you sign in?`n`n" +
            "It sits in the notification area (near the clock), keeps checking your list, and shows a notification when a server goes down or comes back.`n`n" +
            "This adds a shortcut to your Startup folder (no admin rights needed). It runs the script from where it is now:`n$($ui.StartupCommand.ScriptPath)`n`n" +
            "You can change this any time: right-click the Port Monitor icon and choose 'Start when I sign in'.")
        if ($answer -eq 'Yes') { Set-StartupEnabled -Enabled $true }
    }
    function Enter-TrayMode {
        $ui.TrayMode = $true
        if (-not $ui.Running) { Start-Monitoring -Quiet }
        Update-WindowPlacement
        Save-UiSettings
        $window.Hide()
        if (-not $ui.HideTipShown) {
            $ui.HideTipShown = $true
            $what = 'Checking continues here.'
            if (-not $ui.Running) { $what = 'Nothing is being checked yet: open it to add targets.' }
            Show-Balloon -Title 'Port Monitor is still running' -Text "$what Click the icon to open it; right-click for more."
        }
        Request-StartupOffer
    }
    function Save-UiSettings {
        if ($ui.Smoke -or -not $ui.SettingsPath) { return }
        try { Save-PortMonitorSettings -Path $ui.SettingsPath -Settings $ui.Settings } catch { }
    }
    function Update-WindowPlacement {
        # Size and position (the normal size even when maximized), and the grid's sort order.
        if (-not $ui.WasShown) { return }
        $b = $window.RestoreBounds
        if (-not $b.IsEmpty -and $b.Width -gt 0) {
            $ui.Settings.Window = @{ Left = $b.Left; Top = $b.Top; Width = $b.Width; Height = $b.Height
                Maximized = ($window.WindowState -eq [System.Windows.WindowState]::Maximized) }
        }
        $sorted = @($c.Grid.Columns | Where-Object { $null -ne $_.SortDirection }) | Select-Object -First 1
        if ($sorted) { $ui.Settings.SortColumn = [string]$sorted.Header; $ui.Settings.SortDirection = [string]$sorted.SortDirection }
        else { $ui.Settings.SortColumn = '' }
    }
    function Set-UiTheme {
        param([string]$Theme)
        $ui.Settings.Theme = $Theme
        $ui.Palette = Get-PortMonitorPalette -Theme $Theme
        Set-PortMonitorTheme -Element $window -Palette $ui.Palette
        if ($Theme -eq 'Light') { $c.ThemeText.Text = 'Dark mode'; $c.ThemeIcon.Text = [string][char]0x263E }
        else { $c.ThemeText.Text = 'Light mode'; $c.ThemeIcon.Text = [string][char]0x263C }
        Update-View
    }
    function Invoke-Report {
        param([int]$Days)
        if ($ui.Smoke) { [void]$ui.SmokeFailures.Add('a report would have been written'); return }
        try {
            $out = Export-PortOutageReport -LogDirectory $ui.LogDirectory -OutputPath (Join-Path $ui.LogDirectory 'Reports') -Days $Days
            Set-StatusMessage "Report saved: $($out.Path)"
            Start-Process -FilePath $out.Path
        }
        catch {
            Show-Message -Text "Could not make the report:`n`n$($_.Exception.Message)" -Icon 'Warning' | Out-Null
        }
    }
    function Exit-App {
        $ui.Exiting = $true
        $window.Close()
        # A window that was never shown (started in the tray) may not raise Closed: end the
        # message loop here too. Clean-up runs in the finally block below.
        if ($ui.Frame) { $ui.Frame.Continue = $false }
    }

    # Load the target list (not in a smoke run: it reads nothing).
    if (-not $ui.Smoke) {
        $root = Split-Path -Parent $ConfigPath
        if ($root -and -not (Test-Path -LiteralPath $root)) {
            try { New-Item -ItemType Directory -Path $root -Force -ErrorAction Stop | Out-Null } catch { }
        }
        $config = Read-PortMonitorConfig -Path $ConfigPath
        foreach ($t in $config.Targets) { $ui.States.Add((New-PortTargetState $t)) }
        $ui.BackupPending = $config.NeedsBackup
        $ui.StartupNotes = @($config.Warnings)
    }
    $c.Grid.ItemsSource = $ui.States

    # --- Tray icon and its menu ---------------------------------------------------------------
    $ui.Icons = @{
        Stopped  = New-PortMonitorTrayIcon -Color '#6B737D'
        Checking = New-PortMonitorTrayIcon -Color '#4FA3E0'
        Ok       = New-PortMonitorTrayIcon -Color '#3FB950'
        Degraded = New-PortMonitorTrayIcon -Color '#D29922'
        Problem  = New-PortMonitorTrayIcon -Color '#E5534B'
    }
    $notify = New-Object System.Windows.Forms.NotifyIcon
    $ui.Notify = $notify
    $menu = New-Object System.Windows.Forms.ContextMenuStrip
    $miOpen = $menu.Items.Add('Open Port Monitor')
    $miOpen.Font = New-Object System.Drawing.Font -ArgumentList $miOpen.Font, ([System.Drawing.FontStyle]::Bold)
    $miToggle = $menu.Items.Add('Stop monitoring')
    [void]$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
    $miLogs = $menu.Items.Add('Open log folder')
    $miStartup = $menu.Items.Add('Start when I sign in')
    [void]$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
    $miExit = $menu.Items.Add('Exit Port Monitor')
    $notify.ContextMenuStrip = $menu
    Update-Tray
    # Smoke runs build the icon but never show it: they must not appear on the user's screen.
    $notify.Visible = -not $ui.Smoke

    $menu.add_Opening({
            if ($ui.Running) { $miToggle.Text = 'Stop monitoring' } else { $miToggle.Text = 'Start monitoring' }
            $miStartup.Checked = Test-StartupEnabled
        })
    $miOpen.add_Click({ Show-MainWindow })
    $miToggle.add_Click({ if ($ui.Running) { Stop-Monitoring } else { Start-Monitoring } })
    $miLogs.add_Click({ $c.BtnLogs.RaiseEvent((New-Object System.Windows.RoutedEventArgs -ArgumentList ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))) })
    $miStartup.add_Click({ Set-StartupEnabled -Enabled (-not (Test-StartupEnabled)) })
    $miExit.add_Click({ Exit-App })
    $notify.add_MouseClick({
            param($src, $e)
            if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Left) { Show-MainWindow }
        })
    $notify.add_BalloonTipClicked({ Show-MainWindow })

    # --- Buttons ---------------------------------------------------------------------------
    $c.BtnStart.add_Click({ Start-Monitoring })
    $c.BtnStop.add_Click({ Stop-Monitoring })
    $c.BtnBackground.add_Click({ Enter-TrayMode })

    $addTargets = {
        $added = @(Show-PortTargetDialog -Owner $window -Target $null -Palette $ui.Palette -ExistingTargets @($ui.States))
        if ($added.Count -eq 0) { return }
        $state = $null
        foreach ($t in $added) {
            $state = New-PortTargetState $t
            if ($ui.Running) { $state.NextDue = [datetime]::MinValue }
            $ui.States.Add($state)
        }
        $c.Grid.SelectedItem = $state
        Save-UiTargets
        if ($added.Count -gt 1) { Set-StatusMessage "Added $($added.Count) targets for $($added[0].Host)." }
        Update-View
    }
    $c.BtnAdd.add_Click($addTargets)

    $editSelected = {
        $state = $c.Grid.SelectedItem
        if ($null -eq $state) { return }
        $t = @(Show-PortTargetDialog -Owner $window -Target $state -Palette $ui.Palette) | Select-Object -First 1
        if ($null -eq $t) { return }
        if ($t.Host -ne $state.Host -or [int]$t.Port -ne [int]$state.Port) {
            # A different endpoint is a different target: start its history again.
            $fresh = New-PortTargetState $t
            $index = $ui.States.IndexOf($state)
            $ui.States[$index] = $fresh
            $c.Grid.SelectedItem = $fresh
        }
        else {
            $state.Label = $t.Label
            $state.TimeoutMs = $t.TimeoutMs
            $state.FailAfter = $t.FailAfter
            $state.RecoverAfter = $t.RecoverAfter
            if ([bool]$t.MeasureLoss -ne [bool]$state.MeasureLoss) { Reset-PortTargetLoss -State $state }
            $state.MeasureLoss = [bool]$t.MeasureLoss
            $state.LossPings = $t.LossPings
            $state.LossAlertPercent = $t.LossAlertPercent
            if ([int]$t.IntervalSec -ne [int]$state.IntervalSec) {
                $state.IntervalSec = $t.IntervalSec
                $sooner = (Get-Date).AddSeconds($t.IntervalSec)
                if ($state.NextDue -gt $sooner) { $state.NextDue = $sooner }
            }
            if ([bool]$t.Enabled -ne [bool]$state.Enabled) { Set-PortTargetEnabled -State $state -Enabled ([bool]$t.Enabled) }
        }
        Save-UiTargets
        Update-View
    }
    $c.BtnEdit.add_Click($editSelected)
    $c.Grid.add_MouseDoubleClick({
            param($src, $e)
            # Only rows: not the header or empty space.
            $dep = $e.OriginalSource
            while ($null -ne $dep -and -not ($dep -is [System.Windows.Controls.DataGridRow])) {
                if ($dep -is [System.Windows.Controls.Primitives.DataGridColumnHeader]) { return }
                $dep = [System.Windows.Media.VisualTreeHelper]::GetParent($dep)
            }
            if ($null -ne $dep) { & $editSelected }
        })

    $c.BtnRemove.add_Click({
            $state = $c.Grid.SelectedItem
            if ($null -eq $state) { return }
            $answer = Show-Message -Text ("Stop monitoring {0} ({1}:{2}) and remove it from the list?`n`nIts past changes stay in the log." -f $state.Label, $state.Host, $state.Port) -Buttons 'YesNo' -Icon 'Question'
            if ($answer -ne 'Yes') { return }
            [void]$ui.States.Remove($state)
            Save-UiTargets
            Update-View
        })

    $c.BtnImport.add_Click({
            $dlg = New-Object Microsoft.Win32.OpenFileDialog
            $dlg.Title = 'Import a target list'
            $dlg.Filter = 'Target lists (*.json)|*.json|All files (*.*)|*.*'
            $folder = Split-Path -Parent $ui.ConfigPath
            if ($folder -and (Test-Path -LiteralPath $folder)) { $dlg.InitialDirectory = $folder }
            if (-not $dlg.ShowDialog($window)) { return }
            $loaded = Read-PortMonitorConfig -Path $dlg.FileName
            if (@($loaded.Targets).Count -eq 0 -and @($loaded.Warnings).Count -gt 0) {
                Show-Message -Text ("Could not import {0}:`n`n{1}`n`nThe current list was not changed." -f $dlg.FileName, ($loaded.Warnings -join "`n")) -Icon 'Warning' | Out-Null
                return
            }
            $wasRunning = $ui.Running
            if ($wasRunning) { Stop-Monitoring }
            $ui.States.Clear()
            foreach ($t in $loaded.Targets) { $ui.States.Add((New-PortTargetState $t)) }
            $ui.ConfigPath = $dlg.FileName
            $ui.BackupPending = $loaded.NeedsBackup
            $note = "Imported $(@($loaded.Targets).Count) target(s). Changes are now saved to this file."
            if ($wasRunning) { $note += ' Monitoring was stopped: click Start to check the new list.' }
            Set-StatusMessage $note
            if (@($loaded.Warnings).Count -gt 0) {
                Show-Message -Text ("Imported with problems:`n`n{0}" -f ($loaded.Warnings -join "`n")) -Icon 'Warning' | Out-Null
            }
            Update-View
        })

    $c.BtnExport.add_Click({
            $dlg = New-Object Microsoft.Win32.SaveFileDialog
            $dlg.Title = 'Export the target list'
            $dlg.Filter = 'Target lists (*.json)|*.json'
            $dlg.FileName = 'targets.json'
            if (-not $dlg.ShowDialog($window)) { return }
            try {
                $saved = Save-PortMonitorConfig -Path $dlg.FileName -Targets @($ui.States)
                Set-StatusMessage ("Exported {0} target(s) to {1}" -f $saved.Count, $saved.Path)
            }
            catch {
                Show-Message -Text "Could not export to $($dlg.FileName):`n`n$($_.Exception.Message)" -Icon 'Warning' | Out-Null
            }
        })

    $c.BtnLogs.add_Click({
            try {
                if (-not (Test-Path -LiteralPath $ui.LogDirectory)) { New-Item -ItemType Directory -Path $ui.LogDirectory -Force -ErrorAction Stop | Out-Null }
                Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$($ui.LogDirectory)`""
            }
            catch {
                Show-Message -Text "Could not open $($ui.LogDirectory):`n`n$($_.Exception.Message)" -Icon 'Warning' | Out-Null
            }
        })

    # The Enabled checkbox in each row (the grid itself is read-only).
    $c.Grid.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler] {
            param($src, $e)
            $box = $e.OriginalSource
            if (-not ($box -is [System.Windows.Controls.CheckBox])) { return }
            $state = $box.DataContext
            if ($null -eq $state -or $null -eq $state.PSObject.Properties['Enabled']) { return }
            Set-PortTargetEnabled -State $state -Enabled ([bool]$box.IsChecked)
            Save-UiTargets
            Update-View
        })
    $c.Grid.add_SelectionChanged({ Update-View })

    # Theme toggle.
    $c.BtnTheme.add_Click({
            $next = 'Light'; if ($ui.Settings.Theme -eq 'Light') { $next = 'Dark' }
            Set-UiTheme -Theme $next
            Save-UiSettings
        })

    # Report: a drop-down of periods under the button.
    $reportMenu = New-Object System.Windows.Controls.ContextMenu
    foreach ($choice in @(@(1, 'Last 24 hours'), @(7, 'Last 7 days'), @(30, 'Last 30 days'))) {
        $item = New-Object System.Windows.Controls.MenuItem
        $item.Header = $choice[1]
        $item.Tag = $choice[0]
        $item.add_Click({ param($src, $e) Invoke-Report -Days ([int]$src.Tag) })
        [void]$reportMenu.Items.Add($item)
    }
    $c.BtnReport.ContextMenu = $reportMenu
    $c.BtnReport.add_Click({
            $reportMenu.PlacementTarget = $c.BtnReport
            $reportMenu.Placement = [System.Windows.Controls.Primitives.PlacementMode]::Bottom
            $reportMenu.IsOpen = $true
        })

    # Keyboard: Insert = Add, Delete = Remove, Enter/F2 = Edit, F5 = Start/Stop.
    $window.add_PreviewKeyDown({
            param($src, $e)
            if ($e.OriginalSource -is [System.Windows.Controls.TextBox]) { return }
            $click = { param($b) $b.RaiseEvent((New-Object System.Windows.RoutedEventArgs -ArgumentList ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))) }
            switch ($e.Key) {
                'Insert' { & $click $c.BtnAdd; $e.Handled = $true }
                'Delete' { if ($c.Grid.SelectedItem) { & $click $c.BtnRemove; $e.Handled = $true } }
                'F2' { if ($c.Grid.SelectedItem) { & $editSelected; $e.Handled = $true } }
                'Return' { if ($c.Grid.SelectedItem -and $c.Grid.IsKeyboardFocusWithin) { & $editSelected; $e.Handled = $true } }
                'F5' { if ($ui.Running) { Stop-Monitoring } else { Start-Monitoring }; $e.Handled = $true }
            }
        })

    # Restore the remembered look, size, position and sort order.
    Set-UiTheme -Theme $ui.Settings.Theme
    if ($ui.Settings.Window -and -not $ui.Smoke) {
        # Screen working areas are in pixels; WPF positions are in 1/96-inch units.
        $scale = 1.0
        try { $scale = [System.Windows.SystemParameters]::PrimaryScreenWidth / [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width } catch { }
        $screens = @([System.Windows.Forms.Screen]::AllScreens | ForEach-Object {
                [PSCustomObject]@{ Left = $_.WorkingArea.Left * $scale; Top = $_.WorkingArea.Top * $scale; Width = $_.WorkingArea.Width * $scale; Height = $_.WorkingArea.Height * $scale }
            })
        $w = $ui.Settings.Window
        if (Test-PortMonitorWindowBounds -Bounds $w -Screens $screens) {
            $window.WindowStartupLocation = 'Manual'
            $window.Left = $w.Left; $window.Top = $w.Top; $window.Width = $w.Width; $window.Height = $w.Height
            if ($w.Maximized) { $window.WindowState = [System.Windows.WindowState]::Maximized }
        }
    }
    if ($ui.Settings.SortColumn) {
        # Headers renamed in 1.2.1; a sort saved under the old name is still applied.
        $renamed = @{ 'Latency (ms)' = 'Latency'; 'Jitter (ms)' = 'Jitter'; 'Last State Change' = 'Last Change'; 'Fail Count' = 'Fails' }
        if ($renamed.ContainsKey($ui.Settings.SortColumn)) { $ui.Settings.SortColumn = $renamed[$ui.Settings.SortColumn] }
        $col = @($c.Grid.Columns | Where-Object { [string]$_.Header -eq $ui.Settings.SortColumn }) | Select-Object -First 1
        if ($col -and $col.SortMemberPath) {
            $dir = [System.ComponentModel.ListSortDirection]$ui.Settings.SortDirection
            $col.SortDirection = $dir
            $c.Grid.Items.SortDescriptions.Add((New-Object System.ComponentModel.SortDescription -ArgumentList $col.SortMemberPath, $dir))
        }
    }
    $window.add_ContentRendered({ $ui.WasShown = $true })

    # --- Timer: the only place results reach the UI -----------------------------------------
    $consoleKeys = $false
    if (-not $ui.Smoke) {
        try {
            if (-not [Console]::IsInputRedirected) { [Console]::TreatControlCAsInput = $true; $consoleKeys = $true }
        }
        catch { $consoleKeys = $false }
    }
    $ui.ConsoleKeys = $consoleKeys

    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(250)
    $timer.add_Tick({
            try {
                # Ctrl+C in the console that started the app exits it cleanly.
                if ($ui.ConsoleKeys) {
                    try {
                        while ([Console]::KeyAvailable) {
                            $key = [Console]::ReadKey($true)
                            if ($key.Key -eq 'C' -and ($key.Modifiers -band [ConsoleModifiers]::Control)) { $ui.CtrlC = $true }
                        }
                    }
                    catch { $ui.ConsoleKeys = $false }
                    if ($ui.CtrlC) { Exit-App; return }
                }
                # A second launch asked this copy to show itself.
                if ($null -ne $ui.ShowEvent -and $ui.ShowEvent.WaitOne(0)) { Show-MainWindow }

                $now = Get-Date
                if ($ui.Running) {
                    $cycle = Invoke-PortMonitorCycle -Engine $ui.Engine -States @($ui.States) -LogDirectory $ui.LogDirectory -Now $now -NoLog:$ui.Smoke
                    if ($cycle.Processed -gt 0 -or $cycle.Started -gt 0) { Update-View }
                    $last = @($cycle.Changes) | Select-Object -Last 1
                    if ($last) { Set-StatusMessage ('Last change: ' + (Format-PortStateChangeLine -Change $last)) }
                    if (@($cycle.LogErrors).Count -gt 0) { Set-StatusMessage ('[WARN] ' + $cycle.LogErrors[0]) }
                    # Notify unless the user is looking at the window already.
                    if (-not $window.IsActive) {
                        $note = Get-PortChangeNotification -Changes @($cycle.Changes)
                        if ($note) {
                            $icon = 'Info'
                            if ($note.Kind -eq 'Down') { $icon = 'Warning' }
                            Show-Balloon -Title $note.Title -Text $note.Text -Icon $icon
                        }
                    }
                }
                elseif ($ui.Engine) {
                    [void](Receive-PortCheckResult -Engine $ui.Engine -States @() -Now $now)
                }

                if ($ui.Smoke) {
                    if ($null -ne $ui.SmokeProbe -and $ui.SmokeProbe.Handle.IsCompleted) {
                        try {
                            $out = @($ui.SmokeProbe.PowerShell.EndInvoke($ui.SmokeProbe.Handle))
                            $ui.SmokeProbeOk = ($out.Count -gt 0 -and [int]$out[-1] -eq 5)
                            if (-not $ui.SmokeProbeOk) { [void]$ui.SmokeFailures.Add('the check functions are missing in the background pool') }
                        }
                        catch { [void]$ui.SmokeFailures.Add("the background probe failed: $($_.Exception.Message)") }
                        finally { $ui.SmokeProbe.PowerShell.Dispose(); $ui.SmokeProbe = $null; $ui.SmokeProbeDone = $true }
                    }
                    if ($ui.SmokeRendered -and $ui.SmokeProbeDone) { Exit-App; return }
                    if (((Get-Date) - $ui.SmokeStarted).TotalSeconds -ge 30) {
                        [void]$ui.SmokeFailures.Add('the window did not render and finish its background probe within 30 seconds')
                        Exit-App
                    }
                }
            }
            catch {
                if ($ui.Smoke) { [void]$ui.SmokeFailures.Add("timer error: $($_.Exception.Message)") }
                else { Set-StatusMessage "[WARN] $($_.Exception.Message)" }
            }
        })

    $window.add_ContentRendered({
            $ui.SmokeRendered = $true
            if ($ui.Smoke) {
                # Probe: the pool must have the check function. Reads nothing, connects nowhere.
                $engine = Get-EngineReady
                $ps = [System.Management.Automation.PowerShell]::Create()
                $ps.RunspacePool = $engine.Pool
                [void]$ps.AddScript('@(Get-Command -Name Invoke-PortTargetCheck, Test-TcpPort, Get-PortCheckFailure, Measure-PingLoss, ConvertTo-PortPingSummary -CommandType Function -ErrorAction SilentlyContinue).Count')
                $ui.SmokeProbe = [PSCustomObject]@{ PowerShell = $ps; Handle = $ps.BeginInvoke() }
            }
            elseif (@($ui.StartupNotes).Count -gt 0) {
                $notes = $ui.StartupNotes
                $ui.StartupNotes = @()
                Set-StatusMessage '[WARN] The target list had problems; see the message.'
                Show-Message -Text ("The target list {0} had problems:`n`n{1}`n`nIf you save changes, the original file is kept as a .bak copy first." -f $ui.ConfigPath, ($notes -join "`n")) -Icon 'Warning' | Out-Null
            }
        })

    $window.add_Closing({
            param($src, $e)
            # In tray mode the close button hides the window; only Exit on the tray menu quits.
            if ($ui.TrayMode -and -not $ui.Exiting -and -not $ui.Smoke) {
                $e.Cancel = $true
                Enter-TrayMode
                return
            }
            if ($window.IsVisible) { Update-WindowPlacement }
            Save-UiSettings
            $timer.Stop()
            Stop-PortMonitorEngine -Engine $ui.Engine
            $ui.Engine = $null
            if ($ui.Notify) { $ui.Notify.Visible = $false; $ui.Notify.Dispose(); $ui.Notify = $null }
            if ($ui.ConsoleKeys) { try { [Console]::TreatControlCAsInput = $false } catch { } }
        })
    $window.add_Closed({ if ($ui.Frame) { $ui.Frame.Continue = $false } })

    if ($ui.Smoke) { Set-SmokeWindowPosition -Window $window }
    Update-View
    $timer.Start()
    try {
        if ($ui.TrayMode -and -not $ui.Smoke) {
            # Started for the tray (for example at sign-in): check at once, show no window.
            Start-Monitoring -Quiet
            if (-not $ui.Running) {
                Show-Balloon -Title 'Port Monitor has nothing to check' -Text 'Click here to open it and add the servers and ports to watch.'
            }
            elseif (@($ui.StartupNotes).Count -gt 0) {
                Show-Balloon -Title 'Port Monitor: target list problems' -Text 'Some targets could not be read. Click here to see which.' -Icon 'Warning'
            }
            Request-StartupOffer
        }
        else {
            $window.Show()
        }
        $ui.Frame = New-Object System.Windows.Threading.DispatcherFrame
        [System.Windows.Threading.Dispatcher]::PushFrame($ui.Frame)
    }
    finally {
        $timer.Stop()
        Stop-PortMonitorEngine -Engine $ui.Engine
        if ($ui.Notify) { try { $ui.Notify.Visible = $false; $ui.Notify.Dispose() } catch { } }
        foreach ($i in @($ui.Icons.Values)) { try { $i.Dispose() } catch { } }
        if ($ui.ConsoleKeys) { try { [Console]::TreatControlCAsInput = $false } catch { } }
    }

    if (-not $ui.Smoke) { return 0 }
    $failures = @($ui.SmokeFailures)
    if (-not $ui.SmokeRendered) { $failures = @('the window was not rendered') + $failures }
    elseif (-not $ui.SmokeProbeOk -and $failures.Count -eq 0) { $failures = @('the background probe did not report back') }
    if ($failures.Count -eq 0) {
        $ms = [int]((Get-Date) - $ui.SmokeStarted).TotalMilliseconds
        Write-Host "[PASS] PortMonitor.ps1: the window opened and closed by itself ($ms ms, PowerShell $($PSVersionTable.PSVersion))" -ForegroundColor Green
        return 0
    }
    foreach ($f in $failures) { Write-Host "[FAIL] PortMonitor.ps1: $f" -ForegroundColor Red }
    1
}

#endregion

if ($LoadFunctionsOnly) { return }

#region Main

if ($Once) { $NoGui = [switch]$true }
if ($SmokeTest -and $NoGui) {
    Write-Host '[FAIL] -SmokeTest checks the window; it cannot be combined with -NoGui or -Once.' -ForegroundColor Red
    exit 1
}
if ($Tray -and $NoGui) {
    Write-Host '[FAIL] -Tray runs the window in the notification area; it cannot be combined with -NoGui or -Once.' -ForegroundColor Red
    exit 1
}

$defaultRoot = Get-PortMonitorDefaultRoot
$defaultConfigPath = Join-Path $defaultRoot 'targets.json'
$defaultLogPath = Join-Path $defaultRoot 'Logs'
if (-not $ConfigPath) { $ConfigPath = $defaultConfigPath }
if (-not $LogPath) { $LogPath = $defaultLogPath }
$ConfigPath = Resolve-PortMonitorPath $ConfigPath
$LogPath = Resolve-PortMonitorPath $LogPath

if ($Report) {
    # Uptime and outage report from the logs; no window, no checks.
    if (-not $OutputPath) { $OutputPath = (Get-Location).ProviderPath }
    $OutputPath = Resolve-PortMonitorPath $OutputPath
    try {
        $made = Export-PortOutageReport -LogDirectory $LogPath -OutputPath $OutputPath -Days $Days
        $count = @($made.Report.Outages).Count
        Write-Host "[INFO] Read $(@($made.LogFiles).Count) log file(s) from $LogPath" -ForegroundColor Cyan
        if ($count -eq 0) { Write-Host "[PASS] No outages in the last $Days day(s)." -ForegroundColor Green }
        else { Write-Host "[WARN] $count outage(s) in the last $Days day(s)." -ForegroundColor Yellow }
        $lossCount = @($made.LossReport.Periods).Count
        if ($lossCount -gt 0) { Write-Host "[WARN] $lossCount period(s) of high packet loss in the last $Days day(s)." -ForegroundColor Yellow }
        Write-Host "[INFO] Report: $($made.Path)" -ForegroundColor Cyan
        exit 0
    }
    catch {
        Write-Host "[FAIL] Could not make the report: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

if ($NoGui) {
    $code = Invoke-PortMonitorHeadless -ConfigPath $ConfigPath -LogDirectory $LogPath -Once:$Once
    if ($Once) { exit ([int](@($code)[-1])) }
    return
}

# WPF needs a single-threaded apartment (STA). Windows PowerShell and pwsh both start STA by
# default, but a host can be MTA (for example powershell.exe -MTA, or some RMM agents): relaunch
# this script in an STA process with the same parameters. GetApartmentState() is the
# non-obsolete form of Thread.ApartmentState.
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
    $exe = (Get-Process -Id $PID).Path
    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$PSCommandPath`"",
        '-ConfigPath', "`"$ConfigPath`"", '-LogPath', "`"$LogPath`"")
    if ($SmokeTest) {
        # The smoke runner reads this process's output, so run the child in this console and wait.
        $relaunch += '-SmokeTest'
        $child = Start-Process -FilePath $exe -ArgumentList $relaunch -NoNewWindow -Wait -PassThru
        exit $child.ExitCode
    }
    if ($Tray) { $relaunch += '-Tray' }
    Start-Process -FilePath $exe -ArgumentList $relaunch -WindowStyle Hidden
    return
}

# One window (or tray icon) per user session: a second launch brings the running one forward
# instead of starting a copy that would check and log everything twice. Smoke runs skip this
# so they never disturb a copy the user has open.
$instance = $null
if (-not $SmokeTest) {
    $instance = Enter-PortMonitorInstance
    if (-not $instance.Owned) {
        [void]$instance.ShowEvent.Set()
        Write-Host '[INFO] Port Monitor is already running for this user (window or notification area icon); it has been brought forward.' -ForegroundColor Cyan
        Exit-PortMonitorInstance -Instance $instance
        return
    }
}

try {
    $startupCommand = Get-PortMonitorStartupCommand -ScriptPath $PSCommandPath -ConfigPath $ConfigPath -LogPath $LogPath `
        -DefaultConfigPath $defaultConfigPath -DefaultLogPath $defaultLogPath
    $exitCode = Show-PortMonitorWindow -ConfigPath $ConfigPath -LogDirectory $LogPath -Tray:$Tray -SmokeTest:$SmokeTest `
        -SettingsPath (Join-Path $defaultRoot 'settings.json') -StartupShortcutPath (Get-PortMonitorStartupShortcutPath) `
        -StartupCommand $startupCommand -Instance $instance
}
catch {
    Write-Host "[FAIL] Port Monitor could not start its window: $($_.Exception.Message)" -ForegroundColor Red
    if (-not $SmokeTest) {
        try {
            Add-Type -AssemblyName PresentationFramework
            [void][System.Windows.MessageBox]::Show("Port Monitor could not start its window:`n`n$($_.Exception.Message)", 'Port Monitor', 'OK', 'Error')
        }
        catch { }
    }
    Exit-PortMonitorInstance -Instance $instance
    exit 1
}
Exit-PortMonitorInstance -Instance $instance
if ($SmokeTest) { exit ([int](@($exitCode)[-1])) }

#endregion
