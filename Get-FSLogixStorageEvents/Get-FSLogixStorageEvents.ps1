#Requires -Version 5.1
<#
.SYNOPSIS
    Collects the Windows event logs that matter when troubleshooting FSLogix container
    attach failures, SMB session loss, and profile load problems on AVD / RDS hosts.

.DESCRIPTION
    FSLogix's own logs tell you a container was lost and re-attached. They do not tell you
    WHY. The answer usually lives in the SMB client, storage, and session logs, spread
    across nine different event channels that are tedious to query one at a time.

    This script pulls a curated set of those channels for a time window, from one or many
    hosts, and returns flat objects you can sort, filter, and export.

    Channels collected by default:
      Microsoft-Windows-SMBClient/Connectivity   - session and connection loss (the big one)
      Microsoft-Windows-SMBClient/Operational    - share mount / dialect / redirector detail
      Microsoft-Windows-SMBClient/Security       - SMB auth and signing failures
      Microsoft-FSLogix-Apps/Operational         - FSLogix's own event channel
      Microsoft-FSLogix-Apps/Admin               - FSLogix admin-level events
      TerminalServices-LocalSessionManager/Op.   - session connect/disconnect/reconnect
      User Profile Service/Operational           - temp profile and hive load failures
      System        (storage providers only)     - disk resets, IO retries, NTFS corruption
      Application   (Winlogon only)              - slow logon / shell notification warnings

    Low-volume diagnostic channels are collected in full rather than filtered by event ID,
    because guessing at IDs risks silently dropping the event that explains the outage.
    The noisy channels (System, Application) are narrowed by provider instead.

    CORRELATION
    Pass the timestamps of your FSLogix re-attach events via -CorrelateWith and the script
    flags every event that lands within -CorrelationWindowSeconds of one. That collapses
    thousands of events down to the handful that share a moment with the failure.

.PARAMETER ComputerName
    One or more hosts to query. Defaults to the local machine. Remote queries need RPC
    (TCP 135 + dynamic range) or WinRM reachable, and admin rights on the target.

.PARAMETER StartTime
    Beginning of the window. Defaults to 24 hours ago. Interpreted in the TARGET host's
    local time, which is how Get-WinEvent filters.

.PARAMETER EndTime
    End of the window. Defaults to now.

.PARAMETER LogName
    Replace the curated channel list with your own. All events in the window are returned
    for each channel given.

.PARAMETER ExcludeLog
    Drop channels from the curated list. Accepts wildcards, e.g. '*RdpCore*', 'Application'.

.PARAMETER EventId
    Restrict every queried channel to these event IDs.

.PARAMETER Level
    Restrict to these severity levels.

.PARAMETER CorrelateWith
    One or more reference timestamps, typically FSLogix re-attach times. Events within
    -CorrelationWindowSeconds of any reference get NearReference = $true, along with the
    signed offset in SecondsFromReference.

.PARAMETER CorrelationWindowSeconds
    Half-width of the correlation window. Default 60.

.PARAMETER MaxEventsPerLog
    Safety cap per channel per host. Default 5000.

.PARAMETER MessageMaxLength
    Truncate the Message field to keep CSVs readable. 0 means no truncation. Default 600.

.PARAMETER ExportPath
    Write Events.csv and Summary.csv into this directory. Created if absent.

.PARAMETER Report
    Print a console summary grouped by channel and event ID.

.PARAMETER Credential
    Credential for remote queries.

.EXAMPLE
    .\Get-FSLogixStorageEvents.ps1 -Report

    Last 24 hours from the local host, with a summary.

.EXAMPLE
    .\Get-FSLogixStorageEvents.ps1 -ComputerName KBH-AVD-c547 `
        -StartTime '2026-08-06 09:00' -EndTime '2026-08-06 11:00' `
        -Report -ExportPath C:\Temp\Triage

    Target the window around a known incident on one host.

.EXAMPLE
    # Chain both scripts: let the FSLogix parser find the loop, then explain it.
    $p = .\Parse-FSLogixLogs.ps1 -Path 'C:\ProgramData\FSLogix\Logs\Profile'
    $loop = $p.ReattachLoops | Where-Object RegularCadence | Select-Object -First 1
    $times = ($p.Reattaches | Where-Object User -eq $loop.User).Timestamp

    .\Get-FSLogixStorageEvents.ps1 `
        -StartTime $loop.FirstSeen.AddMinutes(-10) `
        -EndTime   $loop.LastSeen.AddMinutes(10) `
        -CorrelateWith $times -CorrelationWindowSeconds 30 -Report |
        Where-Object NearReference | Format-Table TimeCreated, Id, Category, Note

.EXAMPLE
    .\Get-FSLogixStorageEvents.ps1 -ComputerName (Get-Content .\pool-hosts.txt) `
        -StartTime (Get-Date).AddDays(-2) -ExportPath \\fileserver\Triage\KBH

    Sweep an entire host pool and drop CSVs somewhere a ticket can reference.

.NOTES
    Read-only. Queries event logs; never clears or writes them.
    Targets Windows PowerShell 5.1 so it runs on session hosts as-is.

    The Note field on each event is a triage HINT, not authoritative. The event's own
    Message text is the source of truth - always read it before drawing a conclusion.

    References:
      https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/smb-known-issues
      https://learn.microsoft.com/en-us/fslogix/concepts-fslogix-logging
      https://learn.microsoft.com/en-us/azure/storage/files/files-troubleshoot-smb-connectivity
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline = $true)]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [datetime]$StartTime = (Get-Date).AddHours(-24),

    [datetime]$EndTime = (Get-Date),

    [string[]]$LogName,

    [string[]]$ExcludeLog,

    [int[]]$EventId,

    [ValidateSet('Critical', 'Error', 'Warning', 'Information', 'Verbose')]
    [string[]]$Level,

    [datetime[]]$CorrelateWith,

    [ValidateRange(1, 3600)]
    [int]$CorrelationWindowSeconds = 60,

    [ValidateRange(1, 100000)]
    [int]$MaxEventsPerLog = 5000,

    [ValidateRange(0, 32767)]
    [int]$MessageMaxLength = 600,

    [string]$ExportPath,

    [switch]$Report,

    [System.Management.Automation.PSCredential]$Credential
)

begin {
    Set-StrictMode -Version 1.0

    if ($EndTime -le $StartTime) {
        throw "EndTime ($EndTime) must be later than StartTime ($StartTime)."
    }

    # $env:COMPUTERNAME is always set on Windows, but fall back rather than silently
    # iterating zero hosts if it is ever missing.
    $ComputerName = @($ComputerName | Where-Object { $_ })
    if ($ComputerName.Count -eq 0) {
        $ComputerName = @([System.Net.Dns]::GetHostName())
        Write-Verbose "ComputerName was empty; defaulting to $($ComputerName[0])"
    }
    $localNames = @($env:COMPUTERNAME, [System.Net.Dns]::GetHostName(), '.', 'localhost', '127.0.0.1') |
        Where-Object { $_ }

    #region Curated channels
    # Ids     = @()  -> take every event in the window (low-volume diagnostic channels)
    # Provider= @(..) -> narrow a noisy shared channel to relevant providers only
    $channels = @(
        [PSCustomObject]@{
            Log = 'Microsoft-Windows-SMBClient/Connectivity'
            Category = 'SMB Connectivity'; Ids = @(); Provider = @()
            Why = 'Session and connection loss to the file share - the primary suspect for container detach'
        }
        [PSCustomObject]@{
            Log = 'Microsoft-Windows-SMBClient/Operational'
            Category = 'SMB Operational'; Ids = @(); Provider = @()
            Why = 'Share mount, dialect negotiation, and redirector behaviour'
        }
        [PSCustomObject]@{
            Log = 'Microsoft-Windows-SMBClient/Security'
            Category = 'SMB Security'; Ids = @(); Provider = @()
            Why = 'SMB authentication, signing, and encryption failures'
        }
        [PSCustomObject]@{
            Log = 'Microsoft-FSLogix-Apps/Operational'
            Category = 'FSLogix'; Ids = @(); Provider = @()
            Why = 'FSLogix service events, complements the text logs'
        }
        [PSCustomObject]@{
            Log = 'Microsoft-FSLogix-Apps/Admin'
            Category = 'FSLogix'; Ids = @(); Provider = @()
            Why = 'FSLogix admin-level failures'
        }
        [PSCustomObject]@{
            Log = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
            Category = 'RDS Session'; Ids = @(); Provider = @()
            Why = 'Session connect/disconnect/reconnect - rules user activity in or out as the trigger'
        }
        [PSCustomObject]@{
            Log = 'Microsoft-Windows-User Profile Service/Operational'
            Category = 'User Profile'; Ids = @(); Provider = @()
            Why = 'Temporary profile fallback and registry hive load failures'
        }
        [PSCustomObject]@{
            Log = 'System'
            Category = 'Storage / OS'; Ids = @()
            # Deliberately broad: which of these exist varies by VM generation and build,
            # and absent ones are filtered out per host rather than failing the query.
            Provider = @('disk', 'storahci', 'storvsc', 'vhdmp', 'volmgr', 'partmgr',
                         'Ntfs', 'Microsoft-Windows-Ntfs', 'volsnap', 'srv2', 'LanmanWorkstation',
                         'Microsoft-Windows-StorageSpaces-Driver')
            Why = 'Disk resets, IO retries, and NTFS structure errors on the mounted VHDX'
        }
        [PSCustomObject]@{
            Log = 'Application'
            Category = 'Winlogon'; Ids = @()
            Provider = @('Microsoft-Windows-Winlogon', 'Microsoft-Windows-User Profiles Service')
            Why = 'Slow logon / shell notification warnings, often the user-visible symptom'
        }
    )

    if ($PSBoundParameters.ContainsKey('LogName')) {
        $channels = foreach ($l in $LogName) {
            [PSCustomObject]@{ Log = $l; Category = 'Custom'; Ids = @(); Provider = @(); Why = 'User specified' }
        }
    }
    if ($PSBoundParameters.ContainsKey('ExcludeLog')) {
        $channels = @($channels | Where-Object {
            $keep = $true
            foreach ($pat in $ExcludeLog) { if ($_.Log -like $pat) { $keep = $false } }
            $keep
        })
    }
    #endregion

    #region Event ID triage hints
    # Keyed by "<lowercase logname>|<id>". Event IDs are only unique WITHIN a provider,
    # so keying on the ID alone mislabels events - FSLogix event 57 is not NTFS event 57.
    # Anything not listed here is returned with a blank Note on purpose: a wrong label is
    # worse than no label. Read the Message field.
    $notes = @{
        # --- SMB client: connectivity ---
        'microsoft-windows-smbclient/connectivity|30800' = 'SMB: server name could not be resolved (DNS/WINS) - target name is in the Message'
        'microsoft-windows-smbclient/connectivity|30803' = 'SMB: failed to establish a network connection - transport level (TCP/QUIC), not SMB itself'
        'microsoft-windows-smbclient/connectivity|30804' = 'SMB: a network connection was disconnected'
        'microsoft-windows-smbclient/connectivity|30805' = 'SMB: client lost its session to the server (expect a matching 30806 anti-event)'
        'microsoft-windows-smbclient/connectivity|30806' = 'SMB: session to the server was re-established (anti-event of 30805)'
        'microsoft-windows-smbclient/connectivity|30807' = 'SMB: connection to the share was lost (expect a matching 30808 anti-event)'
        'microsoft-windows-smbclient/connectivity|30808' = 'SMB: connection to the share was re-established (anti-event of 30807)'
        # --- SMB client: operational ---
        'microsoft-windows-smbclient/operational|30952'  = 'SMB: redirector rejected a connection attempted over a given transport - see the failure status in the Message'
        # --- SMB client: security ---
        # This one matters: the error is carried in the Message, and the distinction is
        # diagnostic. "Access Denied" is a credential / Kerberos / share-permission
        # problem. A timeout would be a network problem. They lead opposite directions.
        'microsoft-windows-smbclient/security|31010'     = 'SMB: client FAILED TO CONNECT to the share - read the error in the Message. {Access Denied} means credentials/Kerberos/share ACL, NOT network'
        # --- FSLogix ---
        'microsoft-fslogix-apps/admin|35'                = 'FSLogix: installed agent version'
        'microsoft-fslogix-apps/admin|46'                = 'FSLogix: VHD(X) was RE-ATTACHED - note the detach may have invalidated open file handles in the live session'
        'microsoft-fslogix-apps/admin|48'                = 'FSLogix: a user VHD(X) was DETACHED, attempting to reattach - this is the container actually dropping, not a health check'
        'microsoft-fslogix-apps/operational|8'           = 'FSLogix: frxdrv driver loaded'
        'microsoft-fslogix-apps/operational|9'           = 'FSLogix: frxsvc service unloaded'
        'microsoft-fslogix-apps/operational|25'          = 'FSLogix: profile load result (Status/Reason/Error in the Message; 0/0/0 is success)'
        'microsoft-fslogix-apps/operational|31'          = 'FSLogix: profile unload'
        'microsoft-fslogix-apps/operational|57'          = 'FSLogix: disk compaction outcome and its effect on logoff time'
        # --- RDS session lifecycle ---
        'microsoft-windows-terminalservices-localsessionmanager/operational|21' = 'RDS: session logon succeeded'
        'microsoft-windows-terminalservices-localsessionmanager/operational|22' = 'RDS: shell start notification received'
        'microsoft-windows-terminalservices-localsessionmanager/operational|23' = 'RDS: session logoff succeeded'
        'microsoft-windows-terminalservices-localsessionmanager/operational|24' = 'RDS: session disconnected'
        'microsoft-windows-terminalservices-localsessionmanager/operational|25' = 'RDS: session reconnection succeeded'
        'microsoft-windows-terminalservices-localsessionmanager/operational|39' = 'RDS: session disconnected by another session or an administrator'
        'microsoft-windows-terminalservices-localsessionmanager/operational|40' = 'RDS: session disconnected - reason code in the Message'
        # --- User Profile Service ---
        'microsoft-windows-user profile service/operational|1511' = 'UPS: profile not found, signed in with a TEMPORARY profile'
        'microsoft-windows-user profile service/operational|1515' = 'UPS: temporary profile saved, will be deleted on next sign-in'
        'microsoft-windows-user profile service/operational|1530' = 'UPS: registry in use by another process (handle leak on unload)'
        'microsoft-windows-user profile service/operational|1533' = 'UPS: failed to delete profile directory'
        'microsoft-windows-user profile service/operational|1542' = 'UPS: failed to load a user registry hive'
        # --- Storage stack (System log) ---
        'system|129' = 'Storage: adapter reset issued - IO stalled long enough to force a bus reset'
        'system|153' = 'Storage: IO operation retried'
        'system|157' = 'Disk was surprise-removed (expected at container detach, suspicious otherwise)'
        'system|55'  = 'NTFS: file system structure corruption detected - run chkdsk on the volume'
        'system|57'  = 'NTFS: failed to flush data to the transaction log (write failure)'
        'system|137' = 'NTFS: default transaction resource manager encountered an error'
        'system|140' = 'NTFS: failed to flush data - data loss possible'
    }
    #endregion

    $levelMap = @{ Critical = 1; Error = 2; Warning = 3; Information = 4; Verbose = 5 }

    $refTimes = @()
    if ($PSBoundParameters.ContainsKey('CorrelateWith')) {
        $refTimes = @($CorrelateWith | Sort-Object)
    }

    $collected = New-Object System.Collections.Generic.List[object]
    $issues    = New-Object System.Collections.Generic.List[object]

    Write-Verbose ("Window: {0:yyyy-MM-dd HH:mm:ss} .. {1:yyyy-MM-dd HH:mm:ss}" -f $StartTime, $EndTime)
    Write-Verbose ("Channels: {0}" -f $channels.Count)
}

process {
    foreach ($computer in $ComputerName) {

        $isLocal = ($computer -in $localNames)
        Write-Verbose "Querying $computer"

        # Enumerate registered providers once per host so provider filters can be
        # narrowed to what exists rather than failing the whole query.
        $validProviders = New-Object 'System.Collections.Generic.HashSet[string]'
        try {
            $lpParams = @{ ListProvider = '*'; ErrorAction = 'Stop' }
            if (-not $isLocal) { $lpParams['ComputerName'] = $computer }
            foreach ($lp in (Get-WinEvent @lpParams)) { $null = $validProviders.Add($lp.Name.ToLower()) }
            Write-Verbose "  $($validProviders.Count) provider(s) registered"
        }
        catch {
            Write-Verbose "  Could not enumerate providers; provider filters will be passed through unchecked"
        }

        foreach ($ch in $channels) {

            $filter = @{
                LogName   = $ch.Log
                StartTime = $StartTime
                EndTime   = $EndTime
            }
            if ($ch.Ids.Count -gt 0)   { $filter['ID'] = $ch.Ids }
            # Get-WinEvent throws the ENTIRE query if any single name in ProviderName is
            # not registered on the target. Gen2 Azure VMs have no 'storvsc', and
            # 'Winlogon' is registered as 'Microsoft-Windows-Winlogon' - either one
            # silently cost us the whole System or Application channel. Intersect the
            # wanted list against what the host actually has, first.
            if ($ch.Provider.Count -gt 0) {
                $present = if ($validProviders.Count -eq 0) { $ch.Provider }
                           else { @($ch.Provider | Where-Object { $validProviders.Contains($_.ToLower()) } |
                                        Sort-Object -Unique) }
                if ($present.Count -gt 0) {
                    $filter['ProviderName'] = $present
                    $absent = @($ch.Provider | Where-Object { -not $validProviders.Contains($_.ToLower()) })
                    if ($absent.Count -gt 0) {
                        Write-Verbose "  $($ch.Log): skipping absent provider(s): $($absent -join ', ')"
                    }
                }
                else {
                    $issues.Add([PSCustomObject]@{
                        Computer = $computer; LogName = $ch.Log
                        Problem  = "None of the wanted providers are registered on this host ($($ch.Provider -join ', ')) - channel skipped"
                    })
                    continue
                }
            }
            if ($PSBoundParameters.ContainsKey('EventId')) { $filter['ID'] = $EventId }
            if ($PSBoundParameters.ContainsKey('Level'))   { $filter['Level'] = @($Level | ForEach-Object { $levelMap[$_] }) }

            $params = @{
                FilterHashtable = $filter
                MaxEvents       = $MaxEventsPerLog
                ErrorAction     = 'Stop'
            }
            if (-not $isLocal) { $params['ComputerName'] = $computer }
            if ($PSBoundParameters.ContainsKey('Credential') -and -not $isLocal) {
                $params['Credential'] = $Credential
            }

            $events = $null
            try {
                $events = @(Get-WinEvent @params)
            }
            catch {
                $m = $_.Exception.Message
                # "No events were found" is the normal, healthy outcome - not a problem.
                if ($m -match 'No events were found') {
                    Write-Verbose "  $($ch.Log): no events in window"
                    continue
                }
                $reason = if ($m -match 'There is not an event log|could not be found|does not exist') {
                    'Channel not present on this host (feature not installed, or log disabled)'
                }
                elseif ($m -match 'Access is denied') { 'Access denied - need local admin on the target' }
                elseif ($m -match 'RPC server is unavailable') { 'RPC unreachable - check firewall / host is up' }
                else { $m }

                $issues.Add([PSCustomObject]@{
                    Computer = $computer; LogName = $ch.Log; Problem = $reason
                })
                Write-Verbose "  $($ch.Log): $reason"
                continue
            }

            if ($events.Count -eq $MaxEventsPerLog) {
                $issues.Add([PSCustomObject]@{
                    Computer = $computer; LogName = $ch.Log
                    Problem  = ("Hit the MaxEventsPerLog cap of {0}. Get-WinEvent returns NEWEST events first, so the OLDEST were dropped - the earliest timestamp reported for this channel is a floor, not the true start of the condition. Re-run against a narrower/earlier window, or raise -MaxEventsPerLog, to find when it actually began." -f $MaxEventsPerLog)
                })
            }

            foreach ($e in $events) {

                $msg = if ($e.Message) { ($e.Message -replace '\s+', ' ').Trim() } else { '' }
                if ($MessageMaxLength -gt 0 -and $msg.Length -gt $MessageMaxLength) {
                    $msg = $msg.Substring(0, $MessageMaxLength) + '...[truncated]'
                }

                # Nearest reference timestamp
                $near = $false; $offset = $null; $refHit = $null
                if ($refTimes.Count -gt 0) {
                    $best = $null
                    foreach ($rt in $refTimes) {
                        $d = ($e.TimeCreated - $rt).TotalSeconds
                        if ($null -eq $best -or [math]::Abs($d) -lt [math]::Abs($best)) {
                            $best = $d; $refHit = $rt
                        }
                    }
                    $offset = [math]::Round($best, 1)
                    $near   = ([math]::Abs($best) -le $CorrelationWindowSeconds)
                }

                $collected.Add([PSCustomObject]@{
                    TimeCreated          = $e.TimeCreated
                    TimeCreatedUtc       = $e.TimeCreated.ToUniversalTime()
                    Computer             = $computer
                    Category             = $ch.Category
                    LogName              = $e.LogName
                    Id                   = $e.Id
                    Level                = $e.LevelDisplayName
                    Provider             = $e.ProviderName
                    Note                 = $(
                        $nk = ('{0}|{1}' -f $e.LogName.ToLower(), $e.Id)
                        if ($notes.ContainsKey($nk)) { $notes[$nk] } else { $null })
                    NearReference        = $near
                    SecondsFromReference = $offset
                    ReferenceTime        = $refHit
                    Message              = $msg
                })
            }

            Write-Verbose "  $($ch.Log): $($events.Count) event(s)"
        }
    }
}

end {
    $all = @($collected | Sort-Object TimeCreated)

    #region Export
    if ($ExportPath) {
        if (-not (Test-Path -LiteralPath $ExportPath)) {
            New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
        }
        if ($all.Count -gt 0) {
            $all | Export-Csv -LiteralPath (Join-Path $ExportPath 'Events.csv') -NoTypeInformation -Encoding UTF8
            $all | Group-Object Computer, LogName, Id |
                Select-Object @{n = 'Computer'; e = { $_.Group[0].Computer } },
                              @{n = 'LogName';  e = { $_.Group[0].LogName } },
                              @{n = 'Id';       e = { $_.Group[0].Id } },
                              @{n = 'Level';    e = { $_.Group[0].Level } },
                              @{n = 'Count';    e = { $_.Count } },
                              @{n = 'FirstSeen';e = { ($_.Group | Measure-Object TimeCreated -Minimum).Minimum } },
                              @{n = 'LastSeen'; e = { ($_.Group | Measure-Object TimeCreated -Maximum).Maximum } },
                              @{n = 'Note';     e = { $_.Group[0].Note } } |
                Sort-Object Count -Descending |
                Export-Csv -LiteralPath (Join-Path $ExportPath 'Summary.csv') -NoTypeInformation -Encoding UTF8
        }
        if ($issues.Count -gt 0) {
            $issues | Export-Csv -LiteralPath (Join-Path $ExportPath 'CollectionIssues.csv') -NoTypeInformation -Encoding UTF8
        }
        Write-Host "Export complete: $ExportPath" -ForegroundColor Green
    }
    #endregion

    #region Report
    if ($Report) {
        Write-Host ''
        Write-Host ('=' * 78)
        Write-Host ' FSLogix / SMB / Storage Event Collection' -ForegroundColor Cyan
        Write-Host ('=' * 78)
        Write-Host ("  Window : {0:yyyy-MM-dd HH:mm:ss} .. {1:yyyy-MM-dd HH:mm:ss} (target local time)" -f $StartTime, $EndTime)
        Write-Host ("  Hosts  : {0}" -f ($ComputerName -join ', '))
        Write-Host ("  Events : {0}" -f $all.Count)
        if ($refTimes.Count -gt 0) {
            $nearCount = @($all | Where-Object NearReference).Count
            Write-Host ("  Correlation: {0} reference time(s), +/-{1}s -> {2} event(s) inside the window" -f `
                $refTimes.Count, $CorrelationWindowSeconds, $nearCount) -ForegroundColor Yellow
        }

        if ($all.Count -eq 0) {
            Write-Host ''
            Write-Host '  No events returned. If you expected some, widen the window or check that' -ForegroundColor Yellow
            Write-Host '  the SMBClient channels are enabled (they are analytic/debug on some builds):' -ForegroundColor Yellow
            Write-Host '    wevtutil sl Microsoft-Windows-SMBClient/Connectivity /e:true' -ForegroundColor Gray
        }
        else {
            Write-Host ''
            Write-Host ' Counts by channel and event ID' -ForegroundColor Cyan
            $all | Group-Object LogName, Id |
                Select-Object @{n = 'LogName'; e = { $_.Group[0].LogName } },
                              @{n = 'Id';      e = { $_.Group[0].Id } },
                              @{n = 'Level';   e = { $_.Group[0].Level } },
                              @{n = 'Count';   e = { $_.Count } },
                              @{n = 'Note';    e = { $_.Group[0].Note } } |
                Sort-Object Count -Descending |
                Format-Table -AutoSize | Out-String -Width 220 | Write-Host

            $errs = @($all | Where-Object { $_.Level -in @('Error', 'Critical') })
            if ($errs.Count -gt 0) {
                Write-Host ' Errors and criticals' -ForegroundColor Red
                $errs | Select-Object TimeCreated, Computer, LogName, Id, Note |
                    Format-Table -AutoSize | Out-String -Width 220 | Write-Host
            }

            if ($refTimes.Count -gt 0) {
                $nr = @($all | Where-Object NearReference | Sort-Object { [math]::Abs($_.SecondsFromReference) })
                if ($nr.Count -gt 0) {
                    Write-Host ' Events correlated to reference timestamps (closest first)' -ForegroundColor Yellow
                    $nr | Select-Object -First 40 TimeCreated, SecondsFromReference, LogName, Id, Level, Note |
                        Format-Table -AutoSize | Out-String -Width 220 | Write-Host
                    Write-Host ' An event ID repeating at nearly every reference time is your trigger.' -ForegroundColor Gray
                }
                else {
                    Write-Host ' No events fell inside the correlation window.' -ForegroundColor Yellow
                    Write-Host ' That is itself informative: the cause is likely NOT logged locally.' -ForegroundColor Gray
                    Write-Host ' Next look at Azure Files metrics (Transactions by ResponseType) and AV/EDR logs.' -ForegroundColor Gray
                }
            }
        }

        if ($issues.Count -gt 0) {
            Write-Host ' Collection issues' -ForegroundColor DarkYellow
            $issues | Format-Table -AutoSize | Out-String -Width 220 | Write-Host
        }
        Write-Host ('=' * 78)
        Write-Host ''
    }
    #endregion

    $all
}
