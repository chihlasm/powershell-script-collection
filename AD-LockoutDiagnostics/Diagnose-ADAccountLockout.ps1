#Requires -Version 5.1
<#
.SYNOPSIS
    Diagnoses why an Active Directory account keeps locking out and traces the source.
.DESCRIPTION
    Investigates repeated account lockouts (often mistaken for forced password resets).
    Reads account state and effective lockout policy (including any Fine-Grained
    Password Policy) from the PDC emulator, builds a lockout timeline from event 4740,
    traces bad-password sources via 4625/4771 across all DCs, flags admin resets (4724),
    and writes a ranked-verdict HTML report.
.PARAMETER Identity
    SamAccountName, UPN, or DN of the user to investigate.
.PARAMETER OutputPath
    Folder where the HTML report is written, created if missing. Defaults to a "Reports"
    folder beside this script, so reports land in the same place as those from
    Get-ADLockoutHistory.ps1 regardless of the current working directory.
.PARAMETER DaysBack
    How many days of Security event logs to search. 1-90, default 7.
.PARAMETER DomainController
    Optional. One or more DC names to query instead of auto-discovering all DCs.
.PARAMETER EntraConnectServer
    Optional. Entra Connect / sync server to query for hybrid authentication evidence.
    When supplied, the report includes ADSync/PTA service status plus PHS/PTA event-log
    diagnostics from that server.
.PARAMETER HybridAuthMode
    Optional. Expected hybrid sign-in mode: Auto, PHS, PTA, or Unknown. Defaults to Auto.
.EXAMPLE
    .\Diagnose-ADAccountLockout.ps1 -Identity jdoe
    Report written to the Reports folder beside the script.
.EXAMPLE
    .\Diagnose-ADAccountLockout.ps1 -Identity jdoe -DaysBack 14 -OutputPath C:\Reports
    Override the default folder.
.EXAMPLE
    .\Diagnose-ADAccountLockout.ps1 -Identity jdoe -EntraConnectServer AADCONNECT01 -HybridAuthMode PTA
.NOTES
    Run on a DC or admin box with RSAT. Requires permission to read DC Security logs.
    Optional Entra Connect diagnostics require remote service/CIM and event-log access to
    the sync server.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Identity,

    # Defaults to a "Reports" folder beside this script (resolved from $PSScriptRoot, not
    # the caller's working directory) so reports stay together no matter where it's run
    # from. Falls back to the current directory when $PSScriptRoot is unavailable, e.g.
    # when the script body is pasted into a console rather than invoked as a file.
    [string]$OutputPath,

    [ValidateRange(1, 90)]
    [int]$DaysBack = 7,

    [string[]]$DomainController,

    [string]$EntraConnectServer,

    [ValidateSet('Auto','PHS','PTA','Unknown')]
    [string]$HybridAuthMode = 'Auto',

    # Internal: dot-source the functions without running the orchestration body.
    # Used by the Pester tests so they can load helpers on a box without RSAT.
    [switch]$LoadFunctionsOnly
)

function Write-Status {
    param(
        [ValidateSet('PASS','WARN','FAIL','INFO')][string]$Level,
        [string]$Message
    )
    $color = @{ PASS='Green'; WARN='Yellow'; FAIL='Red'; INFO='Cyan' }[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

function ConvertFrom-LockoutEvent {
    param([string]$EventXml, [string]$DcName)
    $x = [xml]$EventXml
    $d = @{}
    foreach ($node in $x.Event.EventData.Data) { $d[$node.Name] = $node.'#text' }
    [PSCustomObject]@{
        Time           = [datetime]$x.Event.System.TimeCreated.SystemTime
        User           = $d['TargetUserName']
        Domain         = $d['TargetDomainName']
        CallerComputer = $d['CallerComputerName']
        DC             = $DcName
    }
}

function ConvertFrom-BadLogonEvent {
    # Parses event 4625 (failed logon) OR 4771 (Kerberos pre-auth failure) into a
    # normalized row. The two event types have different field layouts, so the caller
    # passes the EventId in (both types are queried together) and we branch on it.
    param(
        [string]$EventXml,
        [int]$EventId,
        [string]$DcName
    )
    $x = [xml]$EventXml
    $d = @{}
    foreach ($node in $x.Event.EventData.Data) { $d[$node.Name] = $node.'#text' }

    if ($EventId -eq 4625) {
        $sourceHost = $d['WorkstationName']
        $sourceIp   = $d['IpAddress']
        $logonType  = $d['LogonType']
        # SubStatus usually carries the precise reason while Status is a generic
        # 0xC000006D. BUT SubStatus is frequently 0x0 (e.g. Microsoft's own sample for a
        # locked-out account has Status=0xC0000234, SubStatus=0x0), and 0x0 is "no error"
        # - reporting it would hide the real cause. So only prefer SubStatus when it is
        # actually populated with a non-zero value.
        # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625
        $sub = $d['SubStatus']
        $st  = $d['Status']
        $subIsMeaningful = $sub -and ($sub -notmatch '^0x0+$')
        if ($subIsMeaningful)  { $status = $sub }
        elseif ($st)           { $status = $st }
        else                   { $status = $null }
    }
    else {
        # 4771: no WorkstationName / LogonType; client address is in IpAddress.
        $sourceHost = $null
        $sourceIp   = $d['IpAddress']
        $logonType  = $null
        $status     = $d['Status']
    }

    # Normalize loopback / empty source IPs to a readable marker. Leave ::ffff:
    # mapped addresses untouched.
    if ([string]::IsNullOrEmpty($sourceIp) -or $sourceIp -in @('-', '::1', '127.0.0.1')) {
        $sourceIp = '(local)'
    }

    [PSCustomObject]@{
        Time       = [datetime]$x.Event.System.TimeCreated.SystemTime
        EventId    = [int]$EventId
        User       = $d['TargetUserName']
        SourceHost = $sourceHost
        SourceIp   = $sourceIp
        LogonType  = $logonType
        Status     = $status
        DC         = $DcName
    }
}

function Get-EntraConnectEventClassification {
    # Pure event classifier for Entra Connect / hybrid-auth evidence. The live collector
    # supplies the log name and event ID; this helper only labels what the row means.
    param(
        [int]$EventId,
        [string]$LogName
    )

    if ($LogName -match 'AuthenticationAgent') {
        return [PSCustomObject]@{
            AuthMode = 'PTA'
            Status   = 'Info'
            Meaning  = 'Microsoft Entra Connect Authentication Agent admin log event.'
        }
    }

    $phsEvents = @{
        601 = @{ Status = 'Info';    Meaning = 'Password hash sync manager is starting.' }
        602 = @{ Status = 'Info';    Meaning = 'Password hash sync is stopping.' }
        603 = @{ Status = 'Error';   Meaning = 'Password hash sync encountered an unexpected error.' }
        604 = @{ Status = 'Error';   Meaning = 'Password hash sync task error occurred.' }
        605 = @{ Status = 'Warn';    Meaning = 'Password hash sync items were added to the retry queue.' }
        606 = @{ Status = 'Info';    Meaning = 'Password hash sync items were removed from the retry queue.' }
        607 = @{ Status = 'Error';   Meaning = 'Password hash sync is not able to start.' }
        609 = @{ Status = 'Warn';    Meaning = 'Password hash sync has stopped.' }
        610 = @{ Status = 'Error';   Meaning = 'Password hash sync cannot stop cleanly.' }
        611 = @{ Status = 'Error';   Meaning = 'Error during password hash sync for a domain.' }
        612 = @{ Status = 'Error';   Meaning = 'Error initializing a password hash sync context.' }
        650 = @{ Status = 'Info';    Meaning = 'Password hash sync cycle started.' }
        651 = @{ Status = 'Info';    Meaning = 'Password hash sync cycle completed.' }
        652 = @{ Status = 'Error';   Meaning = 'Error during password hash sync operation.' }
        653 = @{ Status = 'Info';    Meaning = 'Password hash sync ping started.' }
        654 = @{ Status = 'Healthy'; Meaning = 'Password hash sync heartbeat was observed.' }
        655 = @{ Status = 'Error';   Meaning = 'Error during password hash sync heartbeat/ping.' }
    }

    if ($phsEvents.ContainsKey($EventId)) {
        return [PSCustomObject]@{
            AuthMode = 'PHS'
            Status   = $phsEvents[$EventId].Status
            Meaning  = $phsEvents[$EventId].Meaning
        }
    }

    [PSCustomObject]@{
        AuthMode = 'Unknown'
        Status   = 'Info'
        Meaning  = 'Unclassified Entra Connect event.'
    }
}

function ConvertFrom-EntraConnectEvent {
    param(
        [string]$EventXml,
        [int]$EventId,
        [string]$Server,
        [string]$LogName,
        [string]$Message
    )
    $x = [xml]$EventXml
    $classification = Get-EntraConnectEventClassification -EventId $EventId -LogName $LogName
    $provider = $null
    try { $provider = $x.Event.System.Provider.Name } catch { }

    [PSCustomObject]@{
        Time     = [datetime]$x.Event.System.TimeCreated.SystemTime
        Server   = $Server
        LogName  = $LogName
        EventId  = [int]$EventId
        AuthMode = $classification.AuthMode
        Status   = $classification.Status
        Meaning  = $classification.Meaning
        Provider = $provider
        Message  = $Message
    }
}

function Get-EntraConnectVerdictHints {
    # Pure summarizer for the optional Entra Connect diagnostics block. It does not
    # decide the whole lockout verdict; it appends hybrid-auth-specific next steps.
    param([object]$Diagnostics)

    $hints = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $Diagnostics) { return $hints.ToArray() }

    $server = if ([string]::IsNullOrWhiteSpace($Diagnostics.Server)) { 'the Entra Connect server' } else { $Diagnostics.Server }
    $events = @($Diagnostics.Events)
    $services = @($Diagnostics.Services)
    $notes = @($Diagnostics.Notes)
    $errors = @($Diagnostics.Errors)

    foreach ($err in $errors) {
        if (-not [string]::IsNullOrWhiteSpace($err)) {
            $hints.Add("Entra Connect diagnostics could not query ${server}: $err")
        }
    }

    $adSync = $services | Where-Object { $_.Name -eq 'ADSync' } | Select-Object -First 1
    if ($adSync -and $adSync.Status -ne 'Running') {
        $hints.Add("Entra Connect ADSync service on $server is $($adSync.Status); password sync and connector status may be stale until the sync service is healthy.")
    }

    $phsErrors = @($events | Where-Object { $_.AuthMode -eq 'PHS' -and $_.Status -eq 'Error' })
    if ($phsErrors.Count -gt 0) {
        $ids = (($phsErrors | Select-Object -ExpandProperty EventId -Unique) -join ', ')
        $hints.Add("Password Hash Sync (PHS) diagnostics on $server show error event(s) $ids; check the Entra Connect Application log and run the password sync troubleshooting task or Invoke-ADSyncDiagnostics for this synced account.")
    }

    if ($notes -match 'heartbeat') {
        $hints.Add("Password Hash Sync (PHS) diagnostics did not find a recent heartbeat event 654 on $server; verify password hash sync is enabled, the server is not in staging mode, and the connector account can read password hashes.")
    }

    $ptaService = $services | Where-Object { $_.Name -eq 'AzureADConnectAuthenticationAgent' } | Select-Object -First 1
    $ptaEvents = @($events | Where-Object { $_.AuthMode -eq 'PTA' })
    if (($Diagnostics.HybridAuthMode -eq 'PTA') -or $ptaService -or $ptaEvents.Count -gt 0) {
        if ($ptaService -and $ptaService.Status -ne 'Running') {
            $hints.Add("Pass-through Authentication (PTA) agent service on $server is $($ptaService.Status); cloud sign-ins may fail or shift to another agent.")
        }
        if ($ptaEvents.Count -gt 0 -or ($ptaService -and $ptaService.Status -eq 'Running')) {
            $hints.Add("Pass-through Authentication (PTA) evidence exists on $server; Entra cloud sign-ins can be validated against on-prem AD through this agent, so correlate Entra sign-in timestamps with 4740/4625/4771 events and PTA agent logs.")
        }
    }

    return $hints.ToArray()
}

function Get-EntraConnectDiagnostics {
    # Optional live collector. This runs only when -EntraConnectServer is supplied;
    # all remote failures are captured as diagnostic rows/notes so the AD lockout
    # investigation can continue.
    param(
        [string]$EntraConnectServer,

        [ValidateSet('Auto','PHS','PTA','Unknown')]
        [string]$HybridAuthMode = 'Auto',

        [int]$DaysBack = 7
    )

    $result = [ordered]@{
        Server         = $EntraConnectServer
        HybridAuthMode = $HybridAuthMode
        Checked        = $false
        Services       = @()
        Events         = @()
        Notes          = @()
        Errors         = @()
    }

    if ([string]::IsNullOrWhiteSpace($EntraConnectServer)) {
        $result.Notes += 'Entra Connect diagnostics not run; supply -EntraConnectServer to collect sync-server service and event-log evidence for a hybrid-synced account.'
        return [PSCustomObject]$result
    }

    $result.Checked = $true
    $startTime = (Get-Date).AddDays(-$DaysBack)

    foreach ($serviceName in @('ADSync','AzureADConnectAuthenticationAgent','AzureADConnectAgentUpdater')) {
        try {
            $svc = Get-CimInstance -ClassName Win32_Service -ComputerName $EntraConnectServer -Filter "Name='$serviceName'" -ErrorAction Stop
            if ($svc) {
                $result.Services += [PSCustomObject]@{
                    Name   = $serviceName
                    Status = $svc.State
                    Detail = "StartMode=$($svc.StartMode); Account=$($svc.StartName)"
                }
            } else {
                $result.Services += [PSCustomObject]@{
                    Name   = $serviceName
                    Status = 'NotFound'
                    Detail = 'Service was not found on this server.'
                }
            }
        } catch {
            $result.Services += [PSCustomObject]@{
                Name   = $serviceName
                Status = 'Error'
                Detail = $_.Exception.Message
            }
            $result.Errors += "Service check failed for ${serviceName}: $($_.Exception.Message)"
        }
    }

    $phsEventIds = @(601,602,603,604,605,606,607,609,610,611,612,650,651,652,653,654,655)
    try {
        $phsEvents = @(Get-WinEvent -ComputerName $EntraConnectServer -FilterHashtable @{
                LogName = 'Application'
                Id = $phsEventIds
                StartTime = $startTime
            } -ErrorAction Stop)
        foreach ($e in $phsEvents) {
            $result.Events += ConvertFrom-EntraConnectEvent -EventXml $e.ToXml() -EventId $e.Id `
                -Server $EntraConnectServer -LogName 'Application' -Message $e.Message
        }
    } catch {
        if ($_.Exception.Message -match 'No events were found') {
            $result.Notes += "No Entra Connect Password Hash Sync Application events were found on $EntraConnectServer in the last $DaysBack day(s)."
        } else {
            $result.Errors += "Could not read Entra Connect Password Hash Sync Application events from ${EntraConnectServer}: $($_.Exception.Message)"
        }
    }

    $heartbeat = @($result.Events | Where-Object { $_.AuthMode -eq 'PHS' -and $_.EventId -eq 654 })
    if (($HybridAuthMode -in @('Auto','PHS')) -and $heartbeat.Count -eq 0) {
        $result.Notes += "No PHS heartbeat event 654 found in the searched window on $EntraConnectServer."
    }

    try {
        $ptaEvents = @(Get-WinEvent -ComputerName $EntraConnectServer -FilterHashtable @{
                LogName = 'Microsoft-AzureADConnect-AuthenticationAgent/Admin'
                StartTime = $startTime
            } -ErrorAction Stop | Select-Object -First 50)
        foreach ($e in $ptaEvents) {
            $result.Events += ConvertFrom-EntraConnectEvent -EventXml $e.ToXml() -EventId $e.Id `
                -Server $EntraConnectServer -LogName 'Microsoft-AzureADConnect-AuthenticationAgent/Admin' -Message $e.Message
        }
    } catch {
        if ($_.Exception.Message -match 'No events were found') {
            if ($HybridAuthMode -in @('Auto','PTA')) {
                $result.Notes += "No PTA Authentication Agent Admin events were found on $EntraConnectServer in the last $DaysBack day(s)."
            }
        } else {
            $result.Errors += "Could not read PTA Authentication Agent Admin events from ${EntraConnectServer}: $($_.Exception.Message)"
        }
    }

    return [PSCustomObject]$result
}

function Get-LockoutVerdict {
    # Pure ranking helper. Takes parsed lockout rows, bad-logon rows, and the effective
    # policy object, and returns an ORDERED [string[]] of plain-English findings shown as
    # the "Likely cause" verdict at the top of the report. No event-log or AD calls here.
    param(
        [object[]]$Lockouts,    # rows from ConvertFrom-LockoutEvent (have .CallerComputer)
        [object[]]$BadLogons,   # rows from ConvertFrom-BadLogonEvent (.SourceHost/.SourceIp/.LogonType)
        [object]$Policy,        # has .LockoutThreshold (int)
        [object]$EntraConnectDiagnostics
    )

    # Treat null arrays as empty so callers can pass $null without guarding.
    if ($null -eq $Lockouts)  { $Lockouts  = @() }
    if ($null -eq $BadLogons) { $BadLogons = @() }

    $findings = [System.Collections.Generic.List[string]]::new()

    # 4) No evidence: nothing in either bucket -> single guidance line, return early.
    if ($Lockouts.Count -eq 0 -and $BadLogons.Count -eq 0) {
        $findings.Add("Found no on-prem lockout or bad-password events in the searched window. Consider widening -DaysBack. If the account is synced with Password Hash Sync (PHS), failed Entra sign-ins may not create matching on-prem bad-password events; investigate Entra ID sign-in logs, Smart Lockout, and SSPR activity.")
        # Still surface an aggressive-policy note if the threshold is low.
        if ($Policy -and $Policy.LockoutThreshold -gt 0 -and $Policy.LockoutThreshold -le 3) {
            $findings.Add("Lockout policy threshold is $($Policy.LockoutThreshold) — this is an aggressively low threshold; a few stray bad passwords will lock the account.")
        }
        foreach ($hint in (Get-EntraConnectVerdictHints -Diagnostics $EntraConnectDiagnostics)) {
            $findings.Add($hint)
        }
        return $findings.ToArray()
    }

    # 1) Dominant caller computer: group lockouts by caller, ignoring null/empty names.
    $callerGroups = $Lockouts |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.CallerComputer) } |
        Group-Object -Property CallerComputer |
        Sort-Object -Property Count -Descending
    if ($callerGroups) {
        $top         = $callerGroups[0]
        $totalCalled = ($callerGroups | Measure-Object -Property Count -Sum).Sum
        $findings.Add("Most lockouts ($($top.Count) of $totalCalled) originate from caller computer '$($top.Name)' — likely a stale cached credential on that machine (mapped drive, saved password, service, or mobile device).")

        # Varied sources with no clear dominant caller can indicate a credential
        # compromise (a spray/guessing attack) rather than one stale credential.
        if ($callerGroups.Count -ge 4 -and $top.Count -lt ($totalCalled / 2)) {
            $callerNames = (($callerGroups | Select-Object -First 5).Name) -join ', '
            $findings.Add("Lockouts come from $($callerGroups.Count) different caller computers with no single dominant source ($callerNames ...) — this pattern can indicate a compromised credential or password-guessing attack rather than one stale credential. Consider forcing a password change and reviewing for unexpected sign-ins.")
        }
    }

    # 2) Bad-logon source hint: summarize the top source (by host, else IP) and translate
    #    the most common LogonType for that source into plain English.
    if ($BadLogons.Count -gt 0) {
        $logonTypeText = @{
            '2'  = 'interactive logon'
            '3'  = 'network (mapped drive / share)'
            '4'  = 'batch / scheduled task'
            '5'  = 'service'
            '10' = 'RDP / Remote Desktop'
        }
        $sourceGroups = $BadLogons |
            Group-Object -Property {
                if (-not [string]::IsNullOrWhiteSpace($_.SourceHost)) { $_.SourceHost }
                else { $_.SourceIp }
            } |
            Sort-Object -Property Count -Descending
        $topSource = $sourceGroups[0]
        $sourceName = if ([string]::IsNullOrWhiteSpace($topSource.Name)) { '(unknown source)' } else { $topSource.Name }
        $entraConnectPattern = '(?i)(entra\s*-?\s*connect|azure\s*-?\s*ad\s*-?\s*connect|aad\s*-?\s*connect|ad\s*-?\s*connect|pta\s*-?\s*agent|ptaauth)'
        $sourceIsEntraConnect = $sourceName -match $entraConnectPattern

        # Pick the dominant logon type within the top source, if any is present.
        $ltGroup = $topSource.Group |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.LogonType) } |
            Group-Object -Property LogonType |
            Sort-Object -Property Count -Descending |
            Select-Object -First 1
        if ($sourceIsEntraConnect) {
            $msg = "Most bad-password attempts ($($topSource.Count) of $($BadLogons.Count)) come from Entra Connect/PTA agent source '$sourceName'"
            if ($ltGroup) {
                $lt    = $ltGroup.Name
                $plain = if ($logonTypeText.ContainsKey($lt)) { $logonTypeText[$lt] } else { "logon type $lt" }
                $msg  += " (AD event logon type $lt / $plain)"
            }
            $msg += " — if the tenant uses Pass-through Authentication (PTA), stale cloud credentials can be validated by the on-prem agent and lock the AD account. Check Entra sign-in logs, PTA agent health, and the clients submitting bad passwords."
        } else {
            $msg = "Most bad-password attempts ($($topSource.Count) of $($BadLogons.Count)) come from '$sourceName'"
            if ($ltGroup) {
                $lt    = $ltGroup.Name
                $plain = if ($logonTypeText.ContainsKey($lt)) { $logonTypeText[$lt] } else { "logon type $lt" }
                $msg  += " via $plain"
            }
            $msg += " — check that source for a saved or expired credential."
        }
        $findings.Add($msg)
    }

    # 3) Aggressive policy: low threshold means a few stray bad passwords lock the account.
    if ($Policy -and $Policy.LockoutThreshold -gt 0 -and $Policy.LockoutThreshold -le 3) {
        $findings.Add("Lockout policy threshold is $($Policy.LockoutThreshold) — this is an aggressively low threshold; a few stray bad passwords will lock the account.")
    }

    foreach ($hint in (Get-EntraConnectVerdictHints -Diagnostics $EntraConnectDiagnostics)) {
        $findings.Add($hint)
    }

    return $findings.ToArray()
}

function Get-LockoutEvents {
    # Query event 4740 (account lockout) on the PDC emulator (authoritative for 4740).
    # Returns parsed lockout rows for the target user only. "No events" is normal -> WARN, return @().
    param(
        [string]$Pdc,
        [string]$SamAccountName,
        [int]$DaysBack
    )
    $filter = @{ LogName = 'Security'; Id = 4740; StartTime = (Get-Date).AddDays(-$DaysBack) }
    try {
        $events = Get-WinEvent -ComputerName $Pdc -FilterHashtable $filter -ErrorAction Stop
    } catch {
        # Get-WinEvent throws a specific (non-fatal) error when no events match the filter.
        if ($_.Exception.Message -match 'No events were found') {
            Write-Status WARN "No 4740 lockout events found on $Pdc in the last $DaysBack day(s)."
        } else {
            Write-Status WARN "Could not read 4740 events from ${Pdc}: $($_.Exception.Message)"
        }
        return @()
    }
    $rows = foreach ($e in $events) {
        $row = ConvertFrom-LockoutEvent -EventXml $e.ToXml() -DcName $Pdc
        if ($row.User -and $row.User -ieq $SamAccountName) { $row }
    }
    $rows = @($rows)
    Write-Status PASS "Found $($rows.Count) lockout event(s) for $SamAccountName on $Pdc."
    return $rows
}

function Get-BadLogonEvents {
    # Query failed-logon (4625) and Kerberos pre-auth failure (4771) events across all
    # supplied DCs, parse them, and return rows for the target user only. Each DC is
    # queried in its own try/catch so one unreachable DC doesn't halt the run.
    param(
        [string[]]$DomainControllers,
        [string]$SamAccountName,
        [int]$DaysBack
    )
    $filter = @{ LogName = 'Security'; Id = 4625, 4771; StartTime = (Get-Date).AddDays(-$DaysBack) }
    $all = foreach ($dc in $DomainControllers) {
        try {
            $events = Get-WinEvent -ComputerName $dc -FilterHashtable $filter -ErrorAction Stop
            Write-Status PASS "${dc}: read $($events.Count) bad-logon event(s)."
        } catch {
            if ($_.Exception.Message -match 'No events were found') {
                Write-Status INFO "${dc}: no 4625/4771 events in window."
            } else {
                Write-Status WARN "${dc}: $($_.Exception.Message)"
            }
            continue
        }
        foreach ($e in $events) {
            $row = ConvertFrom-BadLogonEvent -EventXml $e.ToXml() -EventId $e.Id -DcName $dc
            if ($row.User -and $row.User -ieq $SamAccountName) { $row }
        }
    }
    return @($all)
}

function Get-AdminResetEvents {
    # Query event 4724 (an admin/helpdesk attempted to reset the account's password)
    # across all supplied DCs. Returns rows: Time, Target, By (who did it), DC.
    param(
        [string[]]$DomainControllers,
        [string]$SamAccountName,
        [int]$DaysBack
    )
    $filter = @{ LogName = 'Security'; Id = 4724; StartTime = (Get-Date).AddDays(-$DaysBack) }
    $all = foreach ($dc in $DomainControllers) {
        try {
            $events = Get-WinEvent -ComputerName $dc -FilterHashtable $filter -ErrorAction Stop
        } catch {
            if ($_.Exception.Message -notmatch 'No events were found') {
                Write-Status WARN "${dc}: $($_.Exception.Message)"
            }
            continue
        }
        foreach ($e in $events) {
            $x = [xml]$e.ToXml()
            $d = @{}
            foreach ($node in $x.Event.EventData.Data) { $d[$node.Name] = $node.'#text' }
            if ($d['TargetUserName'] -and $d['TargetUserName'] -ieq $SamAccountName) {
                [PSCustomObject]@{
                    Time   = [datetime]$x.Event.System.TimeCreated.SystemTime
                    Target = $d['TargetUserName']
                    By     = $d['SubjectUserName']
                    DC     = $dc
                }
            }
        }
    }
    return @($all)
}

function Get-EffectiveLockoutPolicy {
    # Returns the lockout policy that actually applies to the user. A Fine-Grained
    # Password Policy (FGPP) overrides the default domain policy and can itself be the
    # cause (e.g. a threshold of 3). Try resultant first; fall back to domain default.
    param($User, $Server)
    try {
        $fgpp = Get-ADUserResultantPasswordPolicy -Identity $User -Server $Server -ErrorAction Stop
        if ($fgpp) {
            return [PSCustomObject]@{
                Source                   = "Fine-Grained ($($fgpp.Name))"
                LockoutThreshold         = $fgpp.LockoutThreshold
                LockoutObservationWindow = $fgpp.LockoutObservationWindow
                LockoutDuration          = $fgpp.LockoutDuration
            }
        }
    } catch { }
    try {
        $d = Get-ADDefaultDomainPasswordPolicy -Server $Server -ErrorAction Stop
    } catch {
        Write-Status WARN "Could not read default domain password policy from ${Server}: $($_.Exception.Message)"
        return $null
    }
    [PSCustomObject]@{
        Source                   = 'Default Domain Policy'
        LockoutThreshold         = $d.LockoutThreshold
        LockoutObservationWindow = $d.LockoutObservationWindow
        LockoutDuration          = $d.LockoutDuration
    }
}

function Write-LockoutReport {
    # Builds a self-contained dark-themed HTML report and writes it to disk. Returns the
    # full path. No console logging here (the orchestration body logs the path).
    param(
        $User,
        $Policy,
        [object[]]$Lockouts,
        [object[]]$BadLogons,
        [object[]]$Resets,
        [string[]]$Verdict,
        [object]$EntraConnectDiagnostics,
        [string]$OutputPath,
        [int]$DaysBack,
        [string[]]$DcList,
        [string]$Pdc
    )

    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    }

    $stamp    = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $sam      = $User.SamAccountName
    $fileName = "ADLockout_${sam}_${stamp}.html"
    $fullPath = Join-Path -Path $OutputPath -ChildPath $fileName

    # --- HTML escaping helper (tolerant of nulls) ---
    function Convert-Esc { param($v)
        if ($null -eq $v) { return '' }
        ([string]$v).Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;')
    }

    # --- pwdLastSet: filetime Int64 or datetime ---
    $pwdLastSet = $null
    try {
        if (($User.pwdLastSet -is [int64] -or $User.pwdLastSet -is [int]) -and [int64]$User.pwdLastSet -gt 0) {
            $pwdLastSet = [datetime]::FromFileTime([int64]$User.pwdLastSet)
        } elseif (($User.pwdLastSet -is [int64] -or $User.pwdLastSet -is [int]) -and [int64]$User.pwdLastSet -eq 0) {
            # pwdLastSet of 0 means "user must change password at next logon" — directly
            # relevant to a reset/lockout investigation, so label it rather than show 1601.
            $pwdLastSet = '0 (user must change password at next logon)'
        } else {
            $pwdLastSet = $User.pwdLastSet
        }
    } catch {
        $pwdLastSet = $User.pwdLastSet
    }

    # lockoutTime alone does NOT mean the account is locked right now.
    #
    # Per [MS-ADTS], the ADS_UF_LOCKOUT bit in msDS-User-Account-Control-Computed is set
    # only when lockoutTime is non-zero AND the lockout duration has not yet elapsed. AD
    # does not clear lockoutTime when an account auto-unlocks, so a stale timestamp
    # persists on an account that is perfectly usable. Showing it unqualified reads as
    # "still locked" and sends the helpdesk to unlock an account that is already fine.
    # The LockedOut property already reflects the computed attribute, so use it to label
    # the timestamp rather than letting the raw value speak for itself.
    # https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/b80798ae-1f8c-4d30-9d80-a1f3281e96e2
    $lockoutTime = $null
    try {
        if ($User.lockoutTime -and ($User.lockoutTime -is [int64] -or $User.lockoutTime -is [int]) -and [int64]$User.lockoutTime -gt 0) {
            $stamp = [datetime]::FromFileTime([int64]$User.lockoutTime)
            $lockoutTime = if ($User.LockedOut) {
                "$($stamp.ToString('yyyy-MM-dd HH:mm:ss')) (still locked)"
            } else {
                "$($stamp.ToString('yyyy-MM-dd HH:mm:ss')) (last lockout - has since auto-unlocked)"
            }
        } elseif (-not $User.lockoutTime -or [int64]$User.lockoutTime -eq 0) {
            $lockoutTime = 'Never locked out'
        } else {
            $lockoutTime = $User.lockoutTime
        }
    } catch {
        $lockoutTime = $User.lockoutTime
    }

    # --- Builders for HTML table rows ---
    $nl = [Environment]::NewLine

    # 1) Account State
    #    (The verdict is rendered near the document body, where the first finding becomes
    #     the headline and the rest become supporting detail.)
    # NOTE: use [PSCustomObject] rows with Label/Value. A nested plain-array
    # (@( @('a','b'), ... )) would be flattened by the pipeline, leaving $_ as a
    # single string and $_[0] indexing its first CHARACTER.
    $accountRows = @(
        [PSCustomObject]@{ Label = 'Logon Name (SamAccountName)'; Value = $User.SamAccountName }
        [PSCustomObject]@{ Label = 'Full Account Path (DN)';      Value = $User.DistinguishedName }
        [PSCustomObject]@{ Label = 'Currently Locked Out';        Value = $User.LockedOut }
        [PSCustomObject]@{ Label = 'Bad Password Count';          Value = $User.badPwdCount }
        [PSCustomObject]@{ Label = 'Last Bad Password Attempt';   Value = $User.LastBadPasswordAttempt }
        [PSCustomObject]@{ Label = 'Password Last Set';           Value = $pwdLastSet }
        [PSCustomObject]@{ Label = 'Lockout Time';                Value = $lockoutTime }
    )
    $accountHtml = ($accountRows | ForEach-Object {
        "      <tr><th>$(Convert-Esc $_.Label)</th><td>$(Convert-Esc $_.Value)</td></tr>"
    }) -join $nl

    # 3) Effective Lockout Policy
    $policyRows = @(
        [PSCustomObject]@{ Label = 'Where this policy comes from';                  Value = $Policy.Source }
        [PSCustomObject]@{ Label = 'Lockout Threshold (bad tries before lockout)';  Value = $Policy.LockoutThreshold }
        [PSCustomObject]@{ Label = 'Observation Window (counter reset)';            Value = $Policy.LockoutObservationWindow }
        [PSCustomObject]@{ Label = 'Lockout Duration';                              Value = $Policy.LockoutDuration }
    )
    $policyHtml = ($policyRows | ForEach-Object {
        "      <tr><th>$(Convert-Esc $_.Label)</th><td>$(Convert-Esc $_.Value)</td></tr>"
    }) -join $nl

    # Generic data-table builder
    function New-DataTable {
        param([object[]]$Rows, [string[]]$Headers, [string[]]$Props, [string]$EmptyText)
        if (-not $Rows -or $Rows.Count -eq 0) {
            return "    <p class=`"empty`">$(Convert-Esc $EmptyText)</p>"
        }
        $thead = ($Headers | ForEach-Object { "<th>$(Convert-Esc $_)</th>" }) -join ''
        $body  = foreach ($r in $Rows) {
            $cells = ($Props | ForEach-Object { "<td>$(Convert-Esc $r.$_)</td>" }) -join ''
            "        <tr>$cells</tr>"
        }
        "    <table>$nl      <thead><tr>$thead</tr></thead>$nl      <tbody>$nl$($body -join $nl)$nl      </tbody>$nl    </table>"
    }

    # 4) Lockout Timeline (4740)
    $lockoutHtml = New-DataTable -Rows $Lockouts `
        -Headers @('Time','Caller Computer','DC') `
        -Props   @('Time','CallerComputer','DC') `
        -EmptyText "No lockout events in the last $DaysBack day(s)."

    # 5) Bad-Password Sources (4625 / 4771)
    $badHtml = New-DataTable -Rows $BadLogons `
        -Headers @('Time','Event','Source Host','Source IP','Logon Type','Status','DC') `
        -Props   @('Time','EventId','SourceHost','SourceIp','LogonType','Status','DC') `
        -EmptyText "No bad-password events (4625 / 4771) found in the last $DaysBack day(s)."

    # 6) Admin / Helpdesk Resets (4724)
    $resetHtml = New-DataTable -Rows $Resets `
        -Headers @('Time','Reset By','DC') `
        -Props   @('Time','By','DC') `
        -EmptyText "No admin password resets in window."

    # 7) Entra Connect / Hybrid Auth Diagnostics
    $entraHtml = if ($EntraConnectDiagnostics) {
        $summaryRows = @(
            [PSCustomObject]@{ Label = 'Entra Connect Server'; Value = $EntraConnectDiagnostics.Server }
            [PSCustomObject]@{ Label = 'Hybrid Auth Mode';     Value = $EntraConnectDiagnostics.HybridAuthMode }
            [PSCustomObject]@{ Label = 'Diagnostics Ran';      Value = $EntraConnectDiagnostics.Checked }
        )
        $summaryHtml = ($summaryRows | ForEach-Object {
            "      <tr><th>$(Convert-Esc $_.Label)</th><td>$(Convert-Esc $_.Value)</td></tr>"
        }) -join $nl

        $servicesHtml = New-DataTable -Rows @($EntraConnectDiagnostics.Services) `
            -Headers @('Service','Status','Detail') `
            -Props   @('Name','Status','Detail') `
            -EmptyText "No Entra Connect service checks were collected."

        $eventsHtml = New-DataTable -Rows @($EntraConnectDiagnostics.Events) `
            -Headers @('Time','Server','Log','Event','Mode','Status','Meaning','Message') `
            -Props   @('Time','Server','LogName','EventId','AuthMode','Status','Meaning','Message') `
            -EmptyText "No Entra Connect PHS/PTA events were collected."

        $noteItems = @()
        foreach ($note in @($EntraConnectDiagnostics.Notes)) {
            if (-not [string]::IsNullOrWhiteSpace($note)) { $noteItems += "      <li>$(Convert-Esc $note)</li>" }
        }
        foreach ($err in @($EntraConnectDiagnostics.Errors)) {
            if (-not [string]::IsNullOrWhiteSpace($err)) { $noteItems += "      <li>$(Convert-Esc $err)</li>" }
        }
        $notesHtml = if ($noteItems.Count -gt 0) {
            "    <ol>$nl$($noteItems -join $nl)$nl    </ol>"
        } else {
            '    <p class="empty">No Entra Connect diagnostic notes.</p>'
        }

        @"
    <table><tbody>
$summaryHtml
    </tbody></table>
    <h3>Services</h3>
$servicesHtml
    <h3>Events</h3>
$eventsHtml
    <h3>Notes</h3>
$notesHtml
"@
    } else {
        '    <p class="empty">Entra Connect diagnostics were not requested. Re-run with -EntraConnectServer to collect sync-server service and event-log evidence.</p>'
    }

    $genTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # Shared stylesheet so all reports stay consistent; minimal fallback if absent.
    $css = $null
    $refPath = Join-Path $PSScriptRoot 'LockoutReference.psd1'
    if (Test-Path -LiteralPath $refPath) {
        try { $css = (Import-PowerShellDataFile -Path $refPath -ErrorAction Stop).ReportCss } catch { $css = $null }
    }
    if (-not $css) {
        $css = @'
  body { background:#15181c; color:#e8eaed; font-family:'Segoe UI',system-ui,sans-serif;
         margin:0; padding:32px; max-width:1100px; margin-inline:auto; line-height:1.55; }
  .verdict { border-left:5px solid #e2686a; padding:4px 0 4px 20px; margin-bottom:26px; }
  .verdict .line { font-size:25px; font-weight:600; color:#fff; margin:0 0 12px; }
  .card { background:#1d2126; border:1px solid #333a44; border-radius:8px;
          padding:14px 18px; margin-bottom:10px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  td, th { padding:7px 10px; border-bottom:1px solid #242931; text-align:left; }
'@
    }

    # --- Verdict: the first finding is the headline; the rest are supporting detail. ---
    $verdictArr  = @($Verdict)
    $headline    = if ($verdictArr.Count -gt 0) { $verdictArr[0] } else { 'No clear cause identified from the on-prem evidence.' }
    $supporting  = if ($verdictArr.Count -gt 1) { $verdictArr[1..($verdictArr.Count - 1)] } else { @() }

    # Colour the verdict by what was actually found rather than by severity of wording.
    $lockCount = @($Lockouts).Count
    $badCount  = @($BadLogons).Count
    $verdictClass = if ($lockCount -gt 0 -or $badCount -gt 0) { 'bad' }
                    elseif ($verdictArr.Count -gt 0) { 'warn' } else { 'unknown' }

    $supportingHtml = if ($supporting.Count -gt 0) {
        $items = ($supporting | ForEach-Object { "      <li>$(Convert-Esc $_)</li>" }) -join $nl
        "  <ol>$nl$items$nl  </ol>"
    } else { '' }

    # Headline numbers: the three counts that frame everything below.
    $resetCount = @($Resets).Count
    $lockClass  = if ($lockCount -gt 0) { 'bad' } else { '' }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lockout Diagnostics - $(Convert-Esc $sam)</title>
<style>
$css
</style>
</head>
<body>

<div class="top">
  <h1>Lockout Diagnostics</h1>
  <div class="facts">
    <span>Account <b>$(Convert-Esc $sam)</b></span>
    <span>Last <b>$DaysBack days</b></span>
    <span><b>$genTime</b></span>
  </div>
</div>

<div class="verdict $verdictClass">
  <div class="label">Most likely cause</div>
  <p class="line">$(Convert-Esc $headline)</p>
$supportingHtml
</div>

<div class="stats">
  <div class="stat"><div class="n $lockClass">$lockCount</div><div class="k">Lockouts</div></div>
  <div class="stat"><div class="n">$badCount</div><div class="k">Bad passwords</div></div>
  <div class="stat"><div class="n">$resetCount</div><div class="k">Admin resets</div></div>
</div>

<h2>Where the bad passwords came from</h2>
<div class="tablewrap">
$badHtml
</div>

<h2>When it locked</h2>
<div class="tablewrap">
$lockoutHtml
</div>

<details>
  <summary>Account state and lockout policy</summary>
  <div class="tablewrap">
    <table><tbody>
$accountHtml
    </tbody></table>
  </div>
  <h3>Effective lockout policy</h3>
  <div class="tablewrap">
    <table><tbody>
$policyHtml
    </tbody></table>
  </div>
</details>

<details>
  <summary>Admin and helpdesk password resets ($resetCount)</summary>
  <div class="tablewrap">
$resetHtml
  </div>
</details>

<details>
  <summary>Entra Connect / hybrid authentication</summary>
$entraHtml
</details>

<footer>
  <b>To fix a stale credential</b>, go to the machine named above and check:
  <code>cmdkey /list</code>, mapped drives, scheduled tasks and services running as this
  user, the Outlook profile, and any phone with a saved password.<br><br>
  Logon type tells you which: <b>3</b> = mapped drive or share, <b>5</b> = service,
  <b>10</b> = RDP, <b>4</b> = scheduled task.<br><br>
  Lockout events (4740) come from the PDC emulator; bad-password events (4625/4771) are
  collected from every domain controller. Entra Connect diagnostics require
  <code>-EntraConnectServer</code>.
</footer>
</body>
</html>
"@

    Set-Content -Path $fullPath -Value $html -Encoding UTF8
    return $fullPath
}

if (-not $LoadFunctionsOnly) {
    # --- Resolve the output folder before any slow AD work, so a bad path fails fast ---
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $OutputPath = Join-Path $scriptRoot 'Reports'
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        Write-Status FAIL "ActiveDirectory module not found. Install RSAT and retry."
        exit 1
    }

    # --- Resolve PDC and target user (PDC is authoritative for 4740 + current counters) ---
    try {
        $pdc = (Get-ADDomain -ErrorAction Stop).PDCEmulator
        Write-Status INFO "PDC emulator: $pdc"
    } catch {
        Write-Status FAIL "Could not contact the domain. $($_.Exception.Message)"
        exit 1
    }

    $userProps = @('LockedOut','badPwdCount','lockoutTime','pwdLastSet',
                   'LastBadPasswordAttempt','whenChanged')
    try {
        $user = Get-ADUser -Identity $Identity -Server $pdc -Properties $userProps -ErrorAction Stop
        Write-Status PASS "Resolved user: $($user.SamAccountName) ($($user.DistinguishedName))"
    } catch {
        Write-Status FAIL "Could not resolve identity '$Identity'. $($_.Exception.Message)"
        exit 1
    }

    # --- Effective lockout policy (FGPP-aware) ---
    $policy = Get-EffectiveLockoutPolicy -User $user.SamAccountName -Server $pdc
    Write-Status INFO "Lockout policy ($($policy.Source)): threshold=$($policy.LockoutThreshold)"

    # --- Determine DC list (override or auto-discover) ---
    if ($DomainController) {
        $dcList = $DomainController
    } else {
        try {
            $dcList = @(Get-ADDomainController -Filter * -Server $pdc | Select-Object -ExpandProperty HostName)
        } catch {
            Write-Status WARN "DC auto-discovery failed; falling back to PDC only. $($_.Exception.Message)"
            $dcList = @($pdc)
        }
    }
    Write-Status INFO "Querying $($dcList.Count) DC(s) for the last $DaysBack day(s)."

    # --- Gather evidence ---
    $lockouts  = Get-LockoutEvents    -Pdc $pdc -SamAccountName $user.SamAccountName -DaysBack $DaysBack
    $badLogons = Get-BadLogonEvents   -DomainControllers $dcList -SamAccountName $user.SamAccountName -DaysBack $DaysBack
    $resets    = Get-AdminResetEvents -DomainControllers $dcList -SamAccountName $user.SamAccountName -DaysBack $DaysBack
    $entraConnectDiagnostics = Get-EntraConnectDiagnostics -EntraConnectServer $EntraConnectServer `
        -HybridAuthMode $HybridAuthMode -DaysBack $DaysBack
    if ($entraConnectDiagnostics.Checked) {
        Write-Status INFO "Collected Entra Connect diagnostics from $($entraConnectDiagnostics.Server): $(@($entraConnectDiagnostics.Services).Count) service check(s), $(@($entraConnectDiagnostics.Events).Count) event(s)."
    } else {
        Write-Status INFO "Entra Connect diagnostics not run. Supply -EntraConnectServer to include sync-server evidence."
    }

    # --- Verdict ---
    $verdict = Get-LockoutVerdict -Lockouts $lockouts -BadLogons $badLogons -Policy $policy `
        -EntraConnectDiagnostics $entraConnectDiagnostics
    Write-Status INFO "Verdict:"
    foreach ($line in $verdict) { Write-Host "    - $line" -ForegroundColor White }

    # --- Report ---
    $reportPath = Write-LockoutReport -User $user -Policy $policy -Lockouts $lockouts `
        -BadLogons $badLogons -Resets $resets -Verdict $verdict `
        -EntraConnectDiagnostics $entraConnectDiagnostics -OutputPath $OutputPath `
        -DaysBack $DaysBack -DcList $dcList -Pdc $pdc
    Write-Status PASS "Report written: $reportPath"
}
