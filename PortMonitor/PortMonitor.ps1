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
      %APPDATA%\PortMonitor\settings.json                remembers that the Startup offer was shown
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
    Exit code 0 = every enabled target is Open, 1 = at least one is not, 2 = nothing to check
    (no enabled targets). Implies -NoGui. Meant for RMM checks and scheduled tasks.

.PARAMETER Tray
    Start in the background: no window, an icon in the notification area, checking starts at
    once, and a notification appears for every change. This is what the "Start when I sign in"
    shortcut runs. Cannot be combined with -NoGui or -Once.

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
    .\PortMonitor.ps1 -Tray
    Starts in the background (notification area icon) and notifies on every change.

.EXAMPLE
    .\PortMonitor.ps1 -NoGui -ConfigPath C:\Temp\targets.json -LogPath C:\Temp\PortLogs
    Console mode on a server: a live table, changes logged to C:\Temp\PortLogs.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\PortMonitor.ps1 -Once -ConfigPath .\targets.json
    One pass for an RMM check: exit code 0 when everything is Open, 1 when something is not.

.NOTES
    Version : 1.0.0
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
    [switch]$SmokeTest,

    [Parameter()]
    [switch]$LoadFunctionsOnly
)

$script:PortMonitorVersion = '1.0.0'
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
        Label, Host, Port, IntervalSec, TimeoutMs, Enabled.
    .DESCRIPTION
        Blank IntervalSec / TimeoutMs / Enabled get defaults (30 s, 3000 ms, true). A value that
        is present but not a whole number becomes 0 so validation reports it instead of a
        default silently replacing it. A blank Label becomes "Host:Port".
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

    $enabledRaw = Get-PortTargetField $InputObject 'Enabled'
    $enabled = $true
    if ($null -ne $enabledRaw -and "$enabledRaw".Trim() -ne '') {
        if ($enabledRaw -is [bool]) { $enabled = $enabledRaw }
        else { $enabled = @('true', '1', 'yes', 'on') -contains "$enabledRaw".Trim().ToLowerInvariant() }
    }

    $label = "$(Get-PortTargetField $InputObject 'Label')".Trim()
    if (-not $label -and $hostValue) { $label = "${hostValue}:$port" }

    [PSCustomObject]@{
        Label       = $label
        Host        = $hostValue
        Port        = $port
        IntervalSec = $interval
        TimeoutMs   = $timeout
        Enabled     = [bool]$enabled
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
    # Emitted one by one (no leading comma): callers wrap in @() and count.
    foreach ($p in $problems) { [string]$p }
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
        Applies one check result to a target's state. Returns a change record when the status
        differs from the last known one (including the first result), otherwise nothing.
    .DESCRIPTION
        FailCount and UptimePercent count every check since monitoring of this target started
        (Uptime % = Open checks / all checks).
    #>
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)]$Result,
        [datetime]$Now = (Get-Date)
    )
    $newStatus = [string]$Result.Status
    $State.Checks = [int]$State.Checks + 1
    if ($newStatus -eq 'Open') {
        $State.OpenCount = [int]$State.OpenCount + 1
        $State.LatencyMs = $Result.LatencyMs
    }
    else {
        $State.FailCount = [int]$State.FailCount + 1
        $State.LatencyMs = $null
    }
    $State.UptimePercent = [math]::Round(100.0 * $State.OpenCount / $State.Checks, 1)
    $State.LastChecked = $Now
    $State.Detail = [string]$Result.Detail
    $State.Status = $newStatus

    $previous = $State.LastKnownStatus
    if ($previous -eq $newStatus) { return }
    $State.LastKnownStatus = $newStatus
    $State.LastStateChange = $Now
    if (-not $previous) { $previous = $script:StatusNotChecked }
    [PSCustomObject]@{
        Timestamp      = $Now
        Label          = $State.Label
        Host           = $State.Host
        Port           = $State.Port
        PreviousStatus = $previous
        NewStatus      = $newStatus
        LatencyMs      = $State.LatencyMs
    }
}

function Set-PortTargetEnabled {
    # Turns a target on or off. Off shows "Disabled"; on shows "Not checked" and checks it on
    # the next tick. The last known status is kept so a change while it was off is still logged.
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][bool]$Enabled)
    $State.Enabled = $Enabled
    if ($Enabled) {
        $State.Status = $script:StatusNotChecked
        $State.NextDue = [datetime]::MinValue
    }
    else {
        $State.Status = $script:StatusDisabled
        $State.LatencyMs = $null
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

function Format-PortStateChangeLine {
    # One plain-English line for a change, used by the console and the window's status bar.
    param([Parameter(Mandatory)]$Change)
    $latency = ''
    if ($null -ne $Change.LatencyMs) { $latency = " ($($Change.LatencyMs) ms)" }
    '{0}  {1} ({2}:{3})  {4} -> {5}{6}' -f $Change.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'),
    $Change.Label, $Change.Host, $Change.Port, $Change.PreviousStatus, $Change.NewStatus, $latency
}

#endregion

#region Background engine (runspace pool)

function New-PortMonitorEngine {
    # A runspace pool that has Test-TcpPort (and its helper) defined, plus the list of running
    # checks. Results are collected by Receive-PortCheckResult on the caller's thread.
    param([ValidateRange(1, 64)][int]$MaxConcurrency = 16)
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
    foreach ($name in @('Get-PortCheckFailure', 'Test-TcpPort')) {
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
    [void]$ps.AddCommand('Test-TcpPort').AddParameter('HostName', [string]$State.Host).AddParameter('Port', [int]$State.Port).AddParameter('TimeoutMs', [int]$State.TimeoutMs)
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
        dropped. Returns Processed (results applied) and Changes (state-change records).
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
            $write = Write-PortStateChangeLog -LogDirectory $LogDirectory -Change $change
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
    [PSCustomObject]@{
        Status = & $fit ([string]$State.Status) 12
        Rest   = '{0} {1} {2} {3} {4} {5} {6} {7}' -f (& $fit ([string]$State.Label) 22), (& $fit ([string]$State.Host) 26),
        ([string]$State.Port).PadLeft(5), $latency.PadLeft(8), $checked.PadRight(19), $changed.PadRight(19),
        ([string]$State.FailCount).PadLeft(5), $uptime.PadLeft(7)
    }
}

function Write-PortMonitorTable {
    param([AllowNull()][AllowEmptyCollection()][object[]]$States = @(), [string[]]$RecentChanges = @(), [string]$Footer = '')
    $header = '{0} {1} {2} {3} {4} {5} {6} {7} {8}' -f 'Status'.PadRight(12), 'Label'.PadRight(22), 'Host'.PadRight(26), 'Port'.PadLeft(5),
    'Lat ms'.PadLeft(8), 'Last checked'.PadRight(19), 'Last change'.PadRight(19), 'Fails'.PadLeft(5), 'Up %'.PadLeft(7)
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
        Console mode. Returns the exit code (only meaningful with -Once): 0 all Open,
        1 at least one not Open, 2 nothing to check.
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
                    if ($change.NewStatus -eq 'Open') { $prefix = '[PASS]'; $color = 'Green' }
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
    if ($notOpen.Count -eq 0) {
        Write-Host "[PASS] All $($enabled.Count) target(s) are open." -ForegroundColor Green
        return 0
    }
    Write-Host "[FAIL] $($notOpen.Count) of $($enabled.Count) target(s) are not open: $((@($notOpen | ForEach-Object { "$($_.Label) ($($_.Status))" })) -join ', ')" -ForegroundColor Red
    1
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
    $news = @($Changes | Where-Object { $_ -and -not ($_.PreviousStatus -eq $script:StatusNotChecked -and $_.NewStatus -eq 'Open') })
    if ($news.Count -eq 0) { return }
    $down = @($news | Where-Object { $_.NewStatus -ne 'Open' })
    $kind = 'Up'
    if ($down.Count -gt 0) { $kind = 'Down' }

    if ($news.Count -eq 1) {
        $c = $news[0]
        $when = $c.Timestamp.ToString('HH:mm:ss')
        if ($c.NewStatus -eq 'Open') {
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
        $lines = @($news | Select-Object -First 4 | ForEach-Object { "$($_.Label): $($_.PreviousStatus) -> $($_.NewStatus)" })
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
        What the tray icon shows: State (Stopped, Checking, Ok, Problem) and its tooltip.
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
            $state = 'Ok'; $text = "Port Monitor - all $($enabled.Count) open"
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
    # Small per-user settings (for now only whether the Startup offer was shown). Never throws.
    param([Parameter(Mandatory)][string]$Path)
    $settings = @{ StartupOffered = $false }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $settings }
    try {
        $parsed = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($Path)) -ErrorAction Stop
        if ($parsed -and $parsed.PSObject.Properties['StartupOffered']) { $settings.StartupOffered = [bool]$parsed.StartupOffered }
    }
    catch { }
    $settings
}

function Save-PortMonitorSettings {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][hashtable]$Settings)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null }
    $json = ConvertTo-Json -InputObject ([PSCustomObject]@{ StartupOffered = [bool]$Settings.StartupOffered })
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding -ArgumentList $false))
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
        Title="Port Monitor" Width="1240" Height="660" MinWidth="940" MinHeight="420"
        Background="#17191C" Foreground="#E6E8EB" FontFamily="Segoe UI" FontSize="13"
        WindowStartupLocation="CenterScreen" UseLayoutRounding="True" SnapsToDevicePixels="True">
  <Window.Resources>
    <FontFamily x:Key="Sym">Segoe UI Symbol</FontFamily>
    <Style x:Key="Btn" TargetType="Button">
      <Setter Property="Foreground" Value="#E6E8EB"/>
      <Setter Property="Background" Value="#262A30"/>
      <Setter Property="BorderBrush" Value="#3A4048"/>
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
                <Setter TargetName="Bd" Property="BorderBrush" Value="#4FA3E0"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#16405F"/>
              </Trigger>
              <Trigger Property="IsKeyboardFocused" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="#4FA3E0"/>
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
      <Setter Property="Background" Value="#1D6FB0"/>
      <Setter Property="BorderBrush" Value="#2B86D1"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style x:Key="DangerBtn" TargetType="Button" BasedOn="{StaticResource Btn}">
      <Setter Property="Background" Value="#3A2224"/>
      <Setter Property="BorderBrush" Value="#6E3236"/>
    </Style>
    <Style x:Key="Icon" TargetType="TextBlock">
      <Setter Property="FontFamily" Value="{StaticResource Sym}"/>
      <Setter Property="Margin" Value="0,0,7,0"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="#202328"/>
      <Setter Property="Foreground" Value="#9AA3AE"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Padding" Value="8,7"/>
      <Setter Property="BorderBrush" Value="#30353C"/>
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
          <Setter Property="Background" Value="#1C3F5E"/>
          <Setter Property="Foreground" Value="#FFFFFF"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="DataGridRow">
      <Setter Property="ToolTip" Value="{Binding Detail}"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="#262A30"/>
        </Trigger>
      </Style.Triggers>
    </Style>
  </Window.Resources>

  <Grid Background="#17191C">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Header -->
    <Border Grid.Row="0" Background="#1D2024" BorderBrush="#2C3036" BorderThickness="0,0,0,1" Padding="18,14,18,12">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <Border Width="4" Background="#4FA3E0" Margin="0,2,12,2"/>
        <StackPanel Grid.Column="1">
          <TextBlock Text="Port Monitor" FontSize="20" FontWeight="Bold"/>
          <TextBlock Text="Is each server answering on its port? Checked continuously; every up/down change is logged."
                     Foreground="#9AA3AE" Margin="0,2,0,0"/>
        </StackPanel>
        <Border Grid.Column="2" x:Name="RunBadge" Background="#2A2E34" CornerRadius="2" Padding="12,6" VerticalAlignment="Center">
          <StackPanel Orientation="Horizontal">
            <TextBlock x:Name="RunDot" Text="&#x25CF;" Foreground="#6B737D" Margin="0,0,7,0" VerticalAlignment="Center"/>
            <TextBlock x:Name="RunText" Text="Stopped" FontWeight="SemiBold" VerticalAlignment="Center"/>
          </StackPanel>
        </Border>
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
          <Border Width="1" Background="#30353C" Margin="6,2,12,2"/>
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
          <Border Width="1" Background="#30353C" Margin="0,2,12,2"/>
          <Button x:Name="BtnImport" Style="{StaticResource Btn}" ToolTip="Open another target list (for example one client's list); changes are saved to that file">
            <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#x21E9;"/><TextBlock Text="Import"/></StackPanel>
          </Button>
          <Button x:Name="BtnExport" Style="{StaticResource Btn}" ToolTip="Save a copy of this target list to a file">
            <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#x21E7;"/><TextBlock Text="Export"/></StackPanel>
          </Button>
          <Button x:Name="BtnLogs" Style="{StaticResource Btn}" Margin="0" ToolTip="Open the folder with the daily state-change CSV files">
            <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#x2630;"/><TextBlock Text="Open Log Folder"/></StackPanel>
          </Button>
        </StackPanel>
      </DockPanel>
    </Border>

    <!-- Grid -->
    <Grid Grid.Row="2" Margin="18,0,18,12">
      <DataGrid x:Name="Grid" AutoGenerateColumns="False" IsReadOnly="True" CanUserAddRows="False" CanUserDeleteRows="False"
                SelectionMode="Single" SelectionUnit="FullRow" HeadersVisibility="Column" GridLinesVisibility="Horizontal"
                HorizontalGridLinesBrush="#262A30" Background="#1B1E22" RowBackground="#1B1E22" AlternatingRowBackground="#1F2226"
                Foreground="#E6E8EB" BorderBrush="#2C3036" BorderThickness="1" RowHeight="30" CanUserResizeRows="False">
        <DataGrid.Columns>
          <DataGridTemplateColumn Header="Enabled" Width="68" SortMemberPath="Enabled">
            <DataGridTemplateColumn.CellTemplate>
              <DataTemplate>
                <CheckBox IsChecked="{Binding Enabled, Mode=OneWay}" HorizontalAlignment="Center" VerticalAlignment="Center"
                          Cursor="Hand" ToolTip="Turn checking of this target on or off"/>
              </DataTemplate>
            </DataGridTemplateColumn.CellTemplate>
          </DataGridTemplateColumn>
          <DataGridTextColumn Header="Label" Binding="{Binding Label}" Width="1.2*" FontWeight="SemiBold"/>
          <DataGridTextColumn Header="Host" Binding="{Binding Host}" Width="1.3*" FontFamily="Cascadia Mono, Consolas"/>
          <DataGridTextColumn Header="Port" Binding="{Binding Port}" Width="60" FontFamily="Cascadia Mono, Consolas"/>
          <DataGridTemplateColumn Header="Status" Width="112" SortMemberPath="Status">
            <DataGridTemplateColumn.CellTemplate>
              <DataTemplate>
                <Border x:Name="Pill" Background="#30353C" CornerRadius="2" Padding="8,2" HorizontalAlignment="Left" VerticalAlignment="Center">
                  <TextBlock x:Name="PillText" Text="{Binding Status}" Foreground="#C5CBD3" FontWeight="SemiBold" FontSize="12"/>
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
          <DataGridTextColumn Header="Latency (ms)" Binding="{Binding LatencyMs, StringFormat={}{0:0.0}}" Width="96"/>
          <DataGridTextColumn Header="Last Checked" Binding="{Binding LastChecked, StringFormat={}{0:yyyy-MM-dd HH:mm:ss}}" Width="142"/>
          <DataGridTextColumn Header="Last State Change" Binding="{Binding LastStateChange, StringFormat={}{0:yyyy-MM-dd HH:mm:ss}}" Width="142"/>
          <DataGridTextColumn Header="Fail Count" Binding="{Binding FailCount}" Width="78"/>
          <DataGridTextColumn Header="Uptime %" Binding="{Binding UptimePercent, StringFormat={}{0:0.0}}" Width="78"/>
          <DataGridTextColumn Header="Details" Binding="{Binding Detail}" Width="2*" Foreground="#9AA3AE"/>
        </DataGrid.Columns>
      </DataGrid>
      <StackPanel x:Name="EmptyState" HorizontalAlignment="Center" VerticalAlignment="Center" IsHitTestVisible="False">
        <TextBlock Text="No targets yet" FontSize="16" FontWeight="SemiBold" HorizontalAlignment="Center"/>
        <TextBlock Text="Click Add to monitor a server and port, or Import a client's target list." Foreground="#9AA3AE" Margin="0,6,0,0"/>
      </StackPanel>
    </Grid>

    <!-- Status bar -->
    <Border Grid.Row="3" Background="#1D2024" BorderBrush="#2C3036" BorderThickness="0,1,0,0" Padding="18,7">
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
        <TextBlock Text="Targets file:" Foreground="#9AA3AE" Margin="0,0,6,0"/>
        <TextBlock x:Name="ConfigText" Grid.Column="1" FontFamily="Cascadia Mono, Consolas" FontSize="12" VerticalAlignment="Center"
                   TextTrimming="CharacterEllipsis" ToolTip="{Binding Text, RelativeSource={RelativeSource Self}}"/>
        <TextBlock Text="Log folder:" Grid.Column="2" Foreground="#9AA3AE" Margin="16,0,6,0"/>
        <TextBlock x:Name="LogText" Grid.Column="3" FontFamily="Cascadia Mono, Consolas" FontSize="12" VerticalAlignment="Center"
                   TextTrimming="CharacterEllipsis" ToolTip="{Binding Text, RelativeSource={RelativeSource Self}}"/>
        <TextBlock x:Name="MessageText" Grid.Row="1" Grid.ColumnSpan="4" Foreground="#C5CBD3" TextTrimming="CharacterEllipsis" Margin="0,4,0,0"
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
        Title="Target" Width="460" SizeToContent="Height" ResizeMode="NoResize"
        Background="#1D2024" Foreground="#E6E8EB" FontFamily="Segoe UI" FontSize="13"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False">
  <Window.Resources>
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="#15171A"/>
      <Setter Property="Foreground" Value="#E6E8EB"/>
      <Setter Property="BorderBrush" Value="#3A4048"/>
      <Setter Property="CaretBrush" Value="#E6E8EB"/>
      <Setter Property="Padding" Value="6,5"/>
      <Setter Property="Margin" Value="0,4,0,0"/>
      <Style.Triggers>
        <Trigger Property="IsKeyboardFocused" Value="True"><Setter Property="BorderBrush" Value="#4FA3E0"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="Lbl" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#C5CBD3"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Margin" Value="0,12,0,0"/>
    </Style>
    <Style x:Key="Hint" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#8A939E"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Margin" Value="0,3,0,0"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
    </Style>
    <Style x:Key="Btn" TargetType="Button">
      <Setter Property="Foreground" Value="#E6E8EB"/>
      <Setter Property="Background" Value="#262A30"/>
      <Setter Property="BorderBrush" Value="#3A4048"/>
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
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="#4FA3E0"/></Trigger>
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="Bd" Property="Background" Value="#16405F"/></Trigger>
              <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="#4FA3E0"/></Trigger>
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
    <Grid>
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="12"/>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="12"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <StackPanel Grid.Column="0">
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
    <CheckBox x:Name="ChkEnabled" Content="Check this target" Foreground="#E6E8EB" Margin="0,14,0,0" IsChecked="True"/>
    <Border x:Name="ErrorBox" Background="#3A2224" BorderBrush="#6E3236" BorderThickness="1" CornerRadius="2" Padding="10,7" Margin="0,14,0,0" Visibility="Collapsed">
      <TextBlock x:Name="ErrorText" Foreground="#F2B8B5" TextWrapping="Wrap"/>
    </Border>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,18,0,0">
      <Button x:Name="BtnCancel" Content="Cancel" Style="{StaticResource Btn}" IsCancel="True"/>
      <Button x:Name="BtnSave" Content="Save" Style="{StaticResource Btn}" Background="#1D6FB0" BorderBrush="#2B86D1" FontWeight="SemiBold" IsDefault="True"/>
    </StackPanel>
  </StackPanel>
</Window>
'@
}

function Show-PortTargetDialog {
    # Add/Edit dialog. Returns the validated target, or $null when cancelled.
    param($Owner, $Target)
    $dialog = [System.Windows.Markup.XamlReader]::Parse((Get-PortTargetDialogXaml))
    $f = @{}
    foreach ($n in 'Heading', 'TxtLabel', 'TxtHost', 'TxtPort', 'TxtInterval', 'TxtTimeout', 'ChkEnabled', 'ErrorBox', 'ErrorText', 'BtnSave') {
        $f[$n] = $dialog.FindName($n)
    }
    if ($null -ne $Target) {
        $dialog.Title = 'Edit target'
        $f.Heading.Text = 'Edit target'
        $f.TxtLabel.Text = [string]$Target.Label
        $f.TxtHost.Text = [string]$Target.Host
        $f.TxtPort.Text = [string]$Target.Port
        $f.TxtInterval.Text = [string]$Target.IntervalSec
        $f.TxtTimeout.Text = [string]$Target.TimeoutMs
        $f.ChkEnabled.IsChecked = [bool]$Target.Enabled
    }
    else {
        $dialog.Title = 'Add target'
        $f.TxtInterval.Text = '30'
        $f.TxtTimeout.Text = '3000'
    }
    if ($null -ne $Owner) { $dialog.Owner = $Owner }

    $outcome = @{ Value = $null }
    $f.BtnSave.add_Click({
            $candidate = [PSCustomObject]@{
                Label       = $f.TxtLabel.Text
                Host        = $f.TxtHost.Text
                Port        = $f.TxtPort.Text
                IntervalSec = $f.TxtInterval.Text
                TimeoutMs   = $f.TxtTimeout.Text
                Enabled     = [bool]$f.ChkEnabled.IsChecked
            }
            # A blank port must not pass as the default: say so explicitly.
            $normalised = ConvertTo-PortTarget $candidate
            $problems = @(Test-PortTargetDefinition $normalised)
            if ("$($candidate.Port)".Trim() -eq '') {
                $problems = @('Port is blank: enter a number from 1 to 65535.') + @($problems | Where-Object { $_ -notlike 'Port *' })
            }
            if (@($problems).Count -gt 0) {
                $f.ErrorText.Text = ($problems -join [Environment]::NewLine)
                $f.ErrorBox.Visibility = 'Visible'
                return
            }
            $outcome.Value = $normalised
            $dialog.DialogResult = $true
        })
    $dialog.add_ContentRendered({ $f.TxtHost.Focus() | Out-Null; if ($f.TxtHost.Text) { $f.TxtLabel.Focus() | Out-Null } })
    [void]$dialog.ShowDialog()
    $outcome.Value
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
        'RunBadge', 'RunDot', 'RunText', 'ConfigText', 'LogText', 'MessageText') {
        $c[$n] = $window.FindName($n)
        if ($null -eq $c[$n]) { throw "The window layout is missing the element '$n'." }
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
            $c.RunBadge.Background = $converter.ConvertFromString('#163A24')
        }
        else {
            $c.RunText.Text = 'Stopped'
            $c.RunDot.Foreground = $converter.ConvertFromString('#6B737D')
            $c.RunBadge.Background = $converter.ConvertFromString('#2A2E34')
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
        $settings = Read-PortMonitorSettings -Path $ui.SettingsPath
        if ($settings.StartupOffered) { return }
        $settings.StartupOffered = $true
        try { Save-PortMonitorSettings -Path $ui.SettingsPath -Settings $settings } catch { }
        $answer = Show-Message -Title 'Port Monitor' -Buttons 'YesNo' -Icon 'Question' -Text ("Start Port Monitor in the background every time you sign in?`n`n" +
            "It sits in the notification area (near the clock), keeps checking your list, and shows a notification when a server goes down or comes back.`n`n" +
            "This adds a shortcut to your Startup folder (no admin rights needed). It runs the script from where it is now:`n$($ui.StartupCommand.ScriptPath)`n`n" +
            "You can change this any time: right-click the Port Monitor icon and choose 'Start when I sign in'.")
        if ($answer -eq 'Yes') { Set-StartupEnabled -Enabled $true }
    }
    function Enter-TrayMode {
        $ui.TrayMode = $true
        if (-not $ui.Running) { Start-Monitoring -Quiet }
        $window.Hide()
        if (-not $ui.HideTipShown) {
            $ui.HideTipShown = $true
            $what = 'Checking continues here.'
            if (-not $ui.Running) { $what = 'Nothing is being checked yet: open it to add targets.' }
            Show-Balloon -Title 'Port Monitor is still running' -Text "$what Click the icon to open it; right-click for more."
        }
        Request-StartupOffer
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

    $c.BtnAdd.add_Click({
            $t = Show-PortTargetDialog -Owner $window -Target $null
            if ($null -eq $t) { return }
            $state = New-PortTargetState $t
            $ui.States.Add($state)
            $c.Grid.SelectedItem = $state
            Save-UiTargets
            Update-View
        })

    $editSelected = {
        $state = $c.Grid.SelectedItem
        if ($null -eq $state) { return }
        $t = Show-PortTargetDialog -Owner $window -Target $state
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
                            $ui.SmokeProbeOk = ($out.Count -gt 0 -and [int]$out[-1] -eq 2)
                            if (-not $ui.SmokeProbeOk) { [void]$ui.SmokeFailures.Add('Test-TcpPort is missing in the background pool') }
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
                [void]$ps.AddScript('@(Get-Command -Name Test-TcpPort, Get-PortCheckFailure -CommandType Function -ErrorAction SilentlyContinue).Count')
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
