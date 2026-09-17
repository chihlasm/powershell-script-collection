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

    REFERENCES
      Event 4740 (account lockout) - the caller machine is in TargetDomainName; there is
      no CallerComputerName element despite the Event Viewer label:
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740

      lockoutTime semantics - a non-zero value does not mean currently locked; AD never
      clears it on auto-unlock:
        https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/b80798ae-1f8c-4d30-9d80-a1f3281e96e2

      Password Hash Sync event table (601-668), the "Directory synchronization" source,
      connectivity events 0/611/652/655, and the three-hour heartbeat check on event 654:
        https://learn.microsoft.com/entra/identity/hybrid/connect/tshoot-connect-password-hash-synchronization

      Pass-through Authentication agent Admin log channel
      (Application and Service Logs\Microsoft\AzureAdConnect\AuthenticationAgent\Admin)
      and the PTA sign-in error codes:
        https://learn.microsoft.com/entra/identity/hybrid/connect/tshoot-connect-pass-through-authentication

      PTA agent behaviour - agents validate passwords via the Win32 LogonUser API, so
      failures surface on a DC as ordinary 4625/4771 events sourced from the agent host:
        https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-pta-quick-start
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
    # The caller machine is in TargetDomainName. There is NO CallerComputerName element in
    # the 4740 event XML, even though Event Viewer displays the value under the label
    # "Caller Computer Name" - reading that key returns null for every real event, so
    # every source rendered as "(not recorded)".
    #
    # Microsoft's own sample event shows TargetDomainName="WIN81" for an account in the
    # CONTOSO domain: the field holds the SOURCE WORKSTATION, not the account's domain.
    # Some producers also emit CallerComputerName, so that key is honored as a fallback
    # rather than assumed absent.
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740
    $caller = $d['TargetDomainName']
    if ([string]::IsNullOrWhiteSpace($caller)) { $caller = $d['CallerComputerName'] }

    [PSCustomObject]@{
        Time           = [datetime]$x.Event.System.TimeCreated.SystemTime
        User           = $d['TargetUserName']
        # The account's own domain is in SubjectDomainName; TargetDomainName is the caller.
        Domain         = $d['SubjectDomainName']
        CallerComputer = $caller
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

    # Normalize the source address for display.
    #
    # Windows renders an IPv4 client in IPv4-mapped IPv6 notation, e.g.
    # "::ffff:192.168.105.128" - Microsoft's own 4771 sample shows this form. The prefix
    # carries no diagnostic value and makes the address harder to read, copy, or resolve,
    # so strip it. ::1 and 127.0.0.1 both mean the attempt originated on the DC itself.
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4771
    if ([string]::IsNullOrEmpty($sourceIp) -or $sourceIp -in @('-', '::1', '127.0.0.1')) {
        $sourceIp = '(on the DC itself)'
    } elseif ($sourceIp -match '^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$') {
        $sourceIp = $Matches[1]
    }

    # Event 4771 has no workstation field at all - only IpAddress and IpPort. A blank
    # cell reads as "collection failed"; say plainly that the field does not exist so the
    # investigator resolves the IP instead of hunting for a missing hostname.
    if ([string]::IsNullOrWhiteSpace($sourceHost)) {
        $sourceHost = if ($EventId -eq 4771) { '(4771 records no hostname - resolve the IP)' } else { '(not recorded)' }
    }
    if ([string]::IsNullOrWhiteSpace($logonType) -and $EventId -eq 4771) {
        $logonType = '(n/a for Kerberos)'
    }

    # Translate the status code. A raw "0x18" tells the reader nothing; the meaning is
    # what distinguishes a genuine bad password from a clock-skew or policy rejection.
    # Codes transcribed from the Microsoft Learn tables for 4771 (RFC 4120 KDC errors)
    # and 4625/4776 (Winlogon errors).
    $statusText = $status
    if ($status) {
        $known = @{
            '0x0'        = 'Success'
            '0x6'        = 'Username does not exist'
            '0xC'        = 'Rejected by KDC policy (logon hours or workstation restriction)'
            '0x10'       = 'Smart-card / certificate problem'
            '0x12'       = 'Credentials revoked - disabled, expired, or locked out'
            '0x17'       = 'Password has expired'
            '0x18'       = 'Bad password'
            '0x19'       = 'Additional pre-authentication required'
            '0x25'       = 'Clock skew too great'
            '0xC000005E' = 'No logon servers available'
            '0xC0000064' = 'Username does not exist'
            '0xC000006A' = 'Bad password'
            '0xC000006D' = 'Bad username/password, or LAN Manager auth level mismatch'
            '0xC000006F' = 'Logon outside authorized hours'
            '0xC0000070' = 'Logon from unauthorized workstation'
            '0xC0000071' = 'Password expired'
            '0xC0000072' = 'Account disabled'
            '0xC000015B' = 'Logon type not granted on that machine'
            '0xC0000193' = 'Account expired'
            '0xC0000224' = 'Must change password at next logon'
            '0xC0000234' = 'Account locked out'
        }
        $key = ([string]$status).Trim()
        $meaning = $known[$key]
        if (-not $meaning) { $meaning = $known[($key.ToUpper() -replace '^0X', '0x')] }
        if ($meaning) { $statusText = "$key - $meaning" }
    }

    [PSCustomObject]@{
        Time       = [datetime]$x.Event.System.TimeCreated.SystemTime
        EventId    = [int]$EventId
        User       = $d['TargetUserName']
        SourceHost = $sourceHost
        SourceIp   = $sourceIp
        LogonType  = $logonType
        Status     = $statusText
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

    # Meanings are quoted from the documented Password Hash Sync event table rather than
    # paraphrased, so a reader can match a row in the report against the Microsoft page
    # without translating wording. Two corrections worth naming, because the earlier
    # paraphrases were confidently wrong:
    #
    #   653/654 are "Start of password hash sync ping" and "End of password hash sync
    #   ping" - NOT "heartbeat observed". 654 is the event the troubleshooting task
    #   searches for as the heartbeat (logged every 30 minutes while the channel is
    #   active and no password changes are pending), but that is its role, not its text.
    #
    #   650/651 are the start and end of a sync BATCH, not a "cycle".
    #
    # Event 0 is not in the table but is named in the manual troubleshooting steps:
    #   Source: "Directory synchronization"  ID: 0, 611, 652, 655
    #   "If you see these events, you have a connectivity problem."
    # It was missing entirely, so the most commonly cited PHS connectivity event fell
    # through to "Unclassified".
    # https://learn.microsoft.com/entra/identity/hybrid/connect/tshoot-connect-password-hash-synchronization
    $phsEvents = @{
        0   = @{ Status = 'Error';   Meaning = 'Password hash sync connectivity problem (documented with 611/652/655 as a connectivity event).' }
        601 = @{ Status = 'Info';    Meaning = 'Password hash sync manager is starting.' }
        602 = @{ Status = 'Info';    Meaning = 'Password hash sync is stopping.' }
        603 = @{ Status = 'Error';   Meaning = 'Password hash sync unexpected error occured.' }
        604 = @{ Status = 'Error';   Meaning = 'Password hash sync task error occured.' }
        605 = @{ Status = 'Warn';    Meaning = 'Password hash sync items are added to the retry queue.' }
        606 = @{ Status = 'Info';    Meaning = 'Password hash sync items are removed from the retry queue.' }
        607 = @{ Status = 'Error';   Meaning = 'Password hash sync is not able to start.' }
        609 = @{ Status = 'Warn';    Meaning = 'Password hash sync has stopped.' }
        610 = @{ Status = 'Error';   Meaning = 'Password hash sync cannot stop.' }
        611 = @{ Status = 'Error';   Meaning = 'Error during password hash sync for a domain.' }
        612 = @{ Status = 'Error';   Meaning = 'Error initializing a password hash sync context.' }
        613 = @{ Status = 'Warn';    Meaning = 'Password hash sync agent has paused because directory full sync has not yet completed.' }
        614 = @{ Status = 'Warn';    Meaning = 'Password hash sync start is called when not shutdown.' }
        615 = @{ Status = 'Error';   Meaning = 'Password hash sync worker thread exception occured.' }
        616 = @{ Status = 'Error';   Meaning = 'Password hash sync connection to preferred DC failed.' }
        617 = @{ Status = 'Info';    Meaning = 'Full password hash sync started for forest.' }
        618 = @{ Status = 'Info';    Meaning = 'Full password hash sync started for a domain.' }
        619 = @{ Status = 'Info';    Meaning = 'Shows the progress of password hash sync for a domain.' }
        620 = @{ Status = 'Warn';    Meaning = 'No-retry password hash sync objects are reported.' }
        621 = @{ Status = 'Error';   Meaning = 'Full password hash sync attempt failed.' }
        622 = @{ Status = 'Info';    Meaning = 'Full password hash sync completed for a domain.' }
        623 = @{ Status = 'Info';    Meaning = 'Full password hash sync completed for a forest.' }
        650 = @{ Status = 'Info';    Meaning = 'Start of password hash sync batch.' }
        651 = @{ Status = 'Info';    Meaning = 'End of password hash sync batch.' }
        652 = @{ Status = 'Error';   Meaning = 'Error during password hash sync operation.' }
        653 = @{ Status = 'Info';    Meaning = 'Start of password hash sync ping.' }
        654 = @{ Status = 'Healthy'; Meaning = 'End of password hash sync ping (the heartbeat event; logged every 30 minutes while the channel is active).' }
        655 = @{ Status = 'Error';   Meaning = 'Error during password hash sync ping.' }
        656 = @{ Status = 'Info';    Meaning = 'Password hash sync request message.' }
        657 = @{ Status = 'Info';    Meaning = 'Password hash sync response message.' }
        658 = @{ Status = 'Info';    Meaning = 'DCaaS sync event log message.' }
        659 = @{ Status = 'Info';    Meaning = 'Password policy sync event log message.' }
        660 = @{ Status = 'Info';    Meaning = 'Start of password hash sync company feature self-healing.' }
        661 = @{ Status = 'Info';    Meaning = 'End of password hash sync company feature self-healing.' }
        662 = @{ Status = 'Error';   Meaning = 'Password hash sync health task failed during ping operation.' }
        663 = @{ Status = 'Healthy'; Meaning = 'Password hash sync manager is alive and running.' }
        664 = @{ Status = 'Error';   Meaning = 'Single object sync task failed.' }
        665 = @{ Status = 'Error';   Meaning = 'Storing password hash sync cycle state for a domain failed.' }
        666 = @{ Status = 'Error';   Meaning = 'Password hash sync failed for a domain due to sql deadlock.' }
        667 = @{ Status = 'Error';   Meaning = 'Generating MD5 decryption key has failed.' }
        668 = @{ Status = 'Info';    Meaning = 'Number of objects in password hash sync batch that only have PwdLastSet changed.' }
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

function Get-PhsEnabledState {
    # Asks the sync server whether password hash sync is ENABLED before judging its
    # health. Without this, a PTA-only tenant - where PHS is off by design and no
    # heartbeat is correct - gets warned about a missing heartbeat, which reads as a
    # broken sync channel and sends someone to fix a healthy server.
    #
    # Get-ADSyncAADCompanyFeature exposes the tenant's PasswordHashSync flag, and
    # Get-ADSyncScheduler exposes StagingModeEnabled (staging suppresses PHS entirely
    # while everything still looks healthy). Both come from the ADSync module, which
    # exists only on the sync server, so this runs remotely and degrades to 'Unknown'
    # whenever it cannot be determined - never to a false 'enabled' or 'disabled'.
    # https://learn.microsoft.com/entra/identity/hybrid/connect/reference-connect-adsync
    # https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-feature-scheduler
    param([string]$Server)

    $state = [PSCustomObject]@{
        PhsEnabled  = $null      # $true / $false / $null when undetermined
        StagingMode = $null
        Determined  = $false
        Detail      = ''
    }

    if ([string]::IsNullOrWhiteSpace($Server)) { return $state }

    try {
        $remote = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock {
            Import-Module ADSync -ErrorAction Stop
            [PSCustomObject]@{
                Phs     = [bool](Get-ADSyncAADCompanyFeature -ErrorAction Stop).PasswordHashSync
                Staging = [bool](Get-ADSyncScheduler -ErrorAction Stop).StagingModeEnabled
            }
        }
        if ($remote) {
            $state.PhsEnabled  = $remote.Phs
            $state.StagingMode = $remote.Staging
            $state.Determined  = $true
            $state.Detail      = "PasswordHashSync=$($remote.Phs); StagingModeEnabled=$($remote.Staging)"
        }
    } catch {
        $state.Detail = "Could not determine password hash sync configuration on ${Server}: $($_.Exception.Message)"
    }

    return $state
}

function Test-PhsHeartbeatFreshness {
    # Password hash sync logs event 654 every 30 minutes while the channel is active and
    # no password changes are pending, and the built-in troubleshooting task checks for
    # one "within the past three hours".
    #
    # The original collector searched the whole -DaysBack window and only reported a
    # problem when the ENTIRE window held no 654. On the default 7-day search that means
    # PHS could have died yesterday and still be reported healthy - the exact failure the
    # check exists to catch. Freshness is judged against the documented three-hour
    # window, independent of how far back the events were gathered.
    # https://learn.microsoft.com/entra/identity/hybrid/connect/tshoot-connect-password-hash-synchronization
    param(
        [datetime[]]$HeartbeatTimes,
        [datetime]$Now = (Get-Date),
        [int]$WindowHours = 3
    )

    $times = @($HeartbeatTimes | Where-Object { $_ })
    if ($times.Count -eq 0) {
        return [PSCustomObject]@{
            Fresh    = $false
            Newest   = $null
            AgeHours = $null
            Message  = "No password hash sync heartbeat (event 654) was found. Verify password hash sync is enabled, the server is not in staging mode, and the AD DS connector account can read password hashes."
        }
    }

    # Sort rather than trust collection order: a stale entry appearing first would make a
    # healthy server look dead.
    $newest = ($times | Sort-Object -Descending)[0]
    $age = ($Now - $newest).TotalHours

    if ($age -le $WindowHours) {
        return [PSCustomObject]@{
            Fresh    = $true
            Newest   = $newest
            AgeHours = [math]::Round($age, 2)
            Message  = "Password hash sync heartbeat (event 654) is current; newest is $([math]::Round($age, 2)) hour(s) old."
        }
    }

    [PSCustomObject]@{
        Fresh    = $false
        Newest   = $newest
        AgeHours = [math]::Round($age, 2)
        Message  = "Most recent password hash sync heartbeat (event 654) is $([math]::Round($age, 2)) hour(s) old; the documented health check expects one within three hours. Verify password hash sync is enabled, the server is not in staging mode, and the AD DS connector account can read password hashes."
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

    # "Not Running" covers three states that mean completely different things, and the
    # earlier code treated them alike:
    #
    #   NotFound - the service is not installed. For the PTA agent on a PHS-only server
    #              that is the CORRECT configuration, not a fault. For ADSync it means the
    #              server named is not the sync server.
    #   Error    - the query failed. We do not know the state and must not assert one.
    #   Stopped  - queried successfully and genuinely not running. This is the finding.
    #
    # Reporting the first two as faults sends someone to fix a healthy server, which
    # during a lockout incident is worse than saying nothing.
    $adSync = $services | Where-Object { $_.Name -eq 'ADSync' } | Select-Object -First 1
    if ($adSync) {
        switch ($adSync.Status) {
            'Running'  { }
            'NotFound' {
                $hints.Add("The ADSync service is not installed on $server, so this is not an Entra Connect sync server. Re-run with -EntraConnectServer pointed at the actual sync server, or omit it if the account is not synced.")
            }
            'Error'    {
                $hints.Add("ADSync service state on $server could not be determined (the query failed), so sync health is unknown rather than known-bad. Check remote CIM/WinRM access to that server before drawing conclusions from this section.")
            }
            default    {
                $hints.Add("Entra Connect ADSync service on $server is $($adSync.Status); password sync and connector status may be stale until the sync service is healthy.")
            }
        }
    }

    $phsErrors = @($events | Where-Object { $_.AuthMode -eq 'PHS' -and $_.Status -eq 'Error' })
    if ($phsErrors.Count -gt 0) {
        $ids = @($phsErrors | Select-Object -ExpandProperty EventId -Unique)
        $idText = ($ids -join ', ')
        $hints.Add("Password Hash Sync (PHS) diagnostics on $server show error event(s) $idText; check the Entra Connect Application log and run the password sync troubleshooting task or Invoke-ADSyncDiagnostics for this synced account.")

        # Events 0, 611, 652 and 655 are documented together as indicating a connectivity
        # problem, and the event message names the affected forest. Calling that out
        # separately matters here: a sync server that cannot reach a DC is NOT the source
        # of the bad passwords, but it looks like a broken account from the cloud side.
        # https://learn.microsoft.com/entra/identity/hybrid/connect/tshoot-connect-password-hash-synchronization
        $connectivityIds = @($ids | Where-Object { $_ -in @(0, 611, 652, 655) })
        if ($connectivityIds.Count -gt 0) {
            $hints.Add("PHS event(s) $($connectivityIds -join ', ') on $server indicate a connectivity problem between Entra Connect and Active Directory; the event message names the affected forest. Confirm the AD DS connector account holds Replicate Directory Changes and Replicate Directory Changes All at the root of every domain, and that the preferred domain controllers are reachable.")
        }
    }

    # Matches both the missing-heartbeat and stale-heartbeat notes the collector writes.
    if (@($notes | Where-Object { $_ -match 'heartbeat' }).Count -gt 0) {
        $hints.Add("Password Hash Sync (PHS) heartbeat event 654 on $server is missing or stale; the documented health check expects one within three hours. Verify password hash sync is enabled, the server is not in staging mode, and the connector account can read password hashes.")
    }

    $ptaService = $services | Where-Object { $_.Name -eq 'AzureADConnectAuthenticationAgent' } | Select-Object -First 1
    $ptaEvents = @($events | Where-Object { $_.AuthMode -eq 'PTA' })
    $ptaInstalled = $ptaService -and $ptaService.Status -notin @('NotFound','Error')

    if (($Diagnostics.HybridAuthMode -eq 'PTA') -or $ptaInstalled -or $ptaEvents.Count -gt 0) {
        if ($ptaInstalled -and $ptaService.Status -ne 'Running') {
            $hints.Add("Pass-through Authentication (PTA) agent service on $server is $($ptaService.Status); cloud sign-ins may fail or shift to another agent.")
        }
        if ($ptaEvents.Count -gt 0 -or ($ptaService -and $ptaService.Status -eq 'Running')) {
            $hints.Add("Pass-through Authentication (PTA) evidence exists on $server; Entra cloud sign-ins can be validated against on-prem AD through this agent, so correlate Entra sign-in timestamps with 4740/4625/4771 events and PTA agent logs.")
        }
        # Explicitly asked for PTA but the agent is not there: the mode is wrong, or the
        # agent lives on a different server. PTA runs on standalone agent hosts as often
        # as on the sync server, and Microsoft recommends at least three of them.
        # https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-pta-quick-start
        if (($Diagnostics.HybridAuthMode -eq 'PTA') -and $ptaService -and $ptaService.Status -eq 'NotFound') {
            $hints.Add("-HybridAuthMode PTA was requested but no Pass-through Authentication agent is installed on $server. PTA agents are commonly installed on standalone servers rather than the sync server, so check the Entra admin center for the agent list and re-run against one of those hosts.")
        }
    }

    if ($ptaService -and $ptaService.Status -eq 'Error') {
        $hints.Add("Pass-through Authentication agent state on $server could not be determined (the query failed); PTA involvement is unknown rather than ruled out.")
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
        # $true / $false / $null when it could not be determined. Kept distinct from
        # $false so "PHS is off" is never confused with "we could not tell".
        PhsEnabled     = $null
        StagingMode    = $null
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

    # Filtered by PROVIDER as well as ID. Event IDs in the 600s are not unique to password
    # hash sync - they are low numbers in a shared Application log, and other publishers
    # use them freely. Without the provider filter, an unrelated application logging its
    # own event 611 would be classified as "Error during password hash sync for a domain"
    # and reported as a sync failure that never happened.
    #
    # The source is "Directory Synchronization", per the manual troubleshooting steps
    # ("Source: 'Directory synchronization' ID: 0, 611, 652, 655") and the 611 KB article,
    # which shows the event logged in the Application log under that source.
    # https://learn.microsoft.com/entra/identity/hybrid/connect/tshoot-connect-password-hash-synchronization
    # https://learn.microsoft.com/troubleshoot/entra/entra-id/user-prov-sync/pwd-hash-sync-stops-work
    $phsEventIds = @(0,601,602,603,604,605,606,607,609,610,611,612,613,614,615,616,617,
                     618,619,620,621,622,623,650,651,652,653,654,655,656,657,658,659,
                     660,661,662,663,664,665,666,667,668)
    # $phsQueryUsable tracks whether the query itself was sound. It is NOT the same as
    # "found events", and conflating the two is dangerous here: if the provider name is
    # wrong, or the publisher is not registered on this server, the query returns no rows
    # and looks exactly like a healthy-but-quiet sync channel. The heartbeat check would
    # then report a stale heartbeat on a perfectly healthy server, which is the same class
    # of confident-wrong answer this whole section exists to avoid.
    $phsQueryUsable = $true
    try {
        $phsEvents = @(Get-WinEvent -ComputerName $EntraConnectServer -FilterHashtable @{
                LogName      = 'Application'
                ProviderName = 'Directory Synchronization'
                Id           = $phsEventIds
                StartTime    = $startTime
            } -ErrorAction Stop)
        foreach ($e in $phsEvents) {
            $result.Events += ConvertFrom-EntraConnectEvent -EventXml $e.ToXml() -EventId $e.Id `
                -Server $EntraConnectServer -LogName 'Application' -Message $e.Message
        }
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match 'is not an event provider|not an event provider on') {
            # The publisher is not registered on that machine. Either the server does not
            # run password hash sync, or the documented source name does not match what
            # this build registers. Either way we cannot conclude anything about PHS
            # health from silence.
            $phsQueryUsable = $false
            $result.Errors += "The 'Directory Synchronization' event provider is not registered on $EntraConnectServer, so Password Hash Sync events could not be read. Confirm this server runs password hash sync; if it does, check the provider name with: Get-WinEvent -ComputerName $EntraConnectServer -ListProvider *Directory* | Select-Object Name"
        }
        elseif ($msg -match 'No events were found') {
            $result.Notes += "No Entra Connect Password Hash Sync Application events were found on $EntraConnectServer in the last $DaysBack day(s)."
        }
        else {
            $phsQueryUsable = $false
            $result.Errors += "Could not read Entra Connect Password Hash Sync Application events from ${EntraConnectServer}: $msg"
        }
    }

    # Ask whether PHS is even enabled before judging its health. A PTA-only tenant has no
    # heartbeat by design, and warning about it is a false alarm that points at a healthy
    # server during an incident.
    $phsState = Get-PhsEnabledState -Server $EntraConnectServer
    $result.PhsEnabled  = $phsState.PhsEnabled
    $result.StagingMode = $phsState.StagingMode

    if ($phsState.Determined -and -not $phsState.PhsEnabled) {
        $result.Notes += "Password hash sync is NOT enabled on this tenant (PasswordHashSync=False), so the absence of heartbeat event 654 is expected rather than a fault. Sign-in validation is happening elsewhere - check the Pass-through Authentication evidence below, or Entra sign-in logs if neither applies."
    }
    elseif ($phsState.Determined -and $phsState.StagingMode) {
        $result.Notes += "This Entra Connect server is in STAGING MODE, which suppresses password hash sync entirely. A missing heartbeat is expected here; the active sync server is elsewhere."
    }
    elseif (-not $phsState.Determined -and $phsState.Detail) {
        $result.Notes += $phsState.Detail
    }

    # Only judge heartbeat freshness when the query worked AND password hash sync is
    # actually in use. $null (undetermined) still runs the check - better a hedged
    # warning than silence when we genuinely do not know.
    $phsInUse = -not ($phsState.Determined -and (-not $phsState.PhsEnabled -or $phsState.StagingMode))
    if ($phsQueryUsable -and $phsInUse -and $HybridAuthMode -in @('Auto','PHS')) {
        $heartbeatTimes = @($result.Events |
            Where-Object { $_.AuthMode -eq 'PHS' -and $_.EventId -eq 654 } |
            Select-Object -ExpandProperty Time)
        $freshness = Test-PhsHeartbeatFreshness -HeartbeatTimes $heartbeatTimes
        if (-not $freshness.Fresh) {
            $result.Notes += "$($freshness.Message) (server: $EntraConnectServer)"
        }
    }

    # -MaxEvents rather than "| Select-Object -First 50": both keep 50, but -MaxEvents
    # stops the provider reading after 50 instead of pulling the whole channel across the
    # wire and discarding most of it. Get-WinEvent returns newest-first, so the cap keeps
    # the 50 most recent - the right end for an active incident.
    # The channel name is DISCOVERED rather than hardcoded. Microsoft documents the PTA
    # Admin log only as an Event Viewer tree path -
    #   Application and Service Logs\Microsoft\AzureAdConnect\AuthenticationAgent\Admin
    # - and never prints the channel string in the form Get-WinEvent -LogName expects.
    # Translating that path by hand is a guess, and a wrong guess fails as "no events",
    # which reads as "no PTA activity" - a wrong answer rather than an error.
    #
    # Asking the server which channels it actually has removes the guess. The documented
    # spelling stays as the fallback so behaviour is unchanged when enumeration is not
    # permitted (-ListLog needs remote registry/WinRM that event reads alone do not).
    # https://learn.microsoft.com/entra/identity/hybrid/connect/tshoot-connect-pass-through-authentication
    $ptaLogName = 'Microsoft-AzureADConnect-AuthenticationAgent/Admin'
    try {
        $found = @(Get-WinEvent -ComputerName $EntraConnectServer -ListLog '*AuthenticationAgent*' -ErrorAction Stop |
                   Where-Object { $_.LogName -like '*Admin*' } |
                   Select-Object -ExpandProperty LogName)
        if ($found.Count -gt 0) {
            if ($found -notcontains $ptaLogName) {
                $result.Notes += "PTA Admin log channel on $EntraConnectServer is '$($found[0])' rather than the assumed '$ptaLogName'; using the discovered name."
            }
            $ptaLogName = $found[0]
        }
    } catch {
        # Enumeration unavailable - fall through and try the documented name directly.
        Write-Verbose "Could not enumerate PTA log channels on ${EntraConnectServer}: $($_.Exception.Message)"
    }

    $ptaCap = 50
    try {
        $ptaEvents = @(Get-WinEvent -ComputerName $EntraConnectServer -FilterHashtable @{
                LogName   = $ptaLogName
                StartTime = $startTime
            } -MaxEvents $ptaCap -ErrorAction Stop)

        # Say so when the cap is hit. A silently truncated list reads as "this is all the
        # PTA activity there was", which is the wrong conclusion to hand someone during a
        # lockout investigation.
        if ($ptaEvents.Count -ge $ptaCap) {
            $result.Notes += "PTA Authentication Agent Admin log returned the $ptaCap most recent events (the cap); older events in the $DaysBack-day window were not read. Review the log directly on $EntraConnectServer for the full picture."
        }
        foreach ($e in $ptaEvents) {
            $result.Events += ConvertFrom-EntraConnectEvent -EventXml $e.ToXml() -EventId $e.Id `
                -Server $EntraConnectServer -LogName $ptaLogName -Message $e.Message
        }
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match 'There is not an event log|not find the specified log|not exist') {
            # No such channel. On a PHS-only server that is expected; the distinction that
            # matters is "the log is not there" versus "the log is there and empty", and
            # only the second supports "no PTA activity".
            $result.Notes += "No PTA Authentication Agent log channel exists on $EntraConnectServer, so no Pass-through Authentication agent is installed there. This is expected on a password-hash-sync-only server."
        }
        elseif ($msg -match 'No events were found') {
            if ($HybridAuthMode -in @('Auto','PTA')) {
                $result.Notes += "The PTA Authentication Agent Admin log exists on $EntraConnectServer but recorded no events in the last $DaysBack day(s)."
            }
        }
        else {
            $result.Errors += "Could not read PTA Authentication Agent Admin events from ${EntraConnectServer}: $msg"
        }
    }

    return [PSCustomObject]$result
}

function Get-BadPasswordSummary {
    # Collapses the raw bad-password rows into one row per (source, status, logon type).
    #
    # A real run produced 78 rows that differed only by second - same IP, same DC, same
    # status - so the table showed 78 lines of noise and made the reader reconstruct the
    # actual finding by scrolling. The finding is "one source, one status, this many
    # attempts, over this span", which is one line.
    #
    # Status is part of the key on purpose: 0x18 (bad password) and 0x12 (account already
    # locked) mean different things. The first is the cause, the second the consequence.
    # Merging them would hide which attempts actually drove the lockout.
    param([object[]]$Rows)

    $rows = @($Rows | Where-Object { $_ })
    if ($rows.Count -eq 0) { return @() }

    $groups = $rows | Group-Object {
        '{0}|{1}|{2}|{3}' -f $_.SourceHost, $_.SourceIp, $_.Status, $_.LogonType
    }

    $summary = foreach ($g in $groups) {
        # try/catch rather than [datetime]::TryParse: passing [ref] to a local declared
        # inside a ForEach-Object scriptblock fails to bind the overload under PS 5.1
        # ("Cannot find an overload for TryParse and the argument count: 2").
        $times = @($g.Group | ForEach-Object {
            try { [datetime]$_.Time } catch { }
        }) | Sort-Object

        $first = if ($times.Count) { $times[0] } else { $null }
        $last  = if ($times.Count) { $times[-1] } else { $null }

        # The span separates an automated retry loop from a person typing. 78 attempts in
        # 90 seconds and 78 over a week need completely different remediation.
        $span = if ($first -and $last) {
            $d = $last - $first
            if     ($d.TotalSeconds -lt 1)  { 'same second' }
            elseif ($d.TotalMinutes -lt 1)  { '{0} sec' -f [int]$d.TotalSeconds }
            elseif ($d.TotalHours   -lt 1)  { '{0} min' -f [int]$d.TotalMinutes }
            elseif ($d.TotalDays    -lt 1)  { '{0} hr'  -f [int]$d.TotalHours }
            else                            { '{0} days' -f [int]$d.TotalDays }
        } else { '' }

        [PSCustomObject]@{
            SourceHost = $g.Group[0].SourceHost
            SourceIp   = $g.Group[0].SourceIp
            LogonType  = $g.Group[0].LogonType
            Status     = $g.Group[0].Status
            DC         = $g.Group[0].DC
            Attempts   = $g.Count
            FirstSeen  = if ($first) { $first.ToString('yyyy-MM-dd HH:mm:ss') } else { ($g.Group[0].Time) }
            LastSeen   = if ($last)  { $last.ToString('yyyy-MM-dd HH:mm:ss') }  else { ($g.Group[0].Time) }
            Span       = $span
        }
    }

    return @($summary | Sort-Object Attempts -Descending)
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
            $findings.Add("Lockout policy threshold is $($Policy.LockoutThreshold) - this is an aggressively low threshold; a few stray bad passwords will lock the account.")
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
        $findings.Add("Most lockouts ($($top.Count) of $totalCalled) originate from caller computer '$($top.Name)' - likely a stale cached credential on that machine (mapped drive, saved password, service, or mobile device).")

        # Varied sources with no clear dominant caller can indicate a credential
        # compromise (a spray/guessing attack) rather than one stale credential.
        if ($callerGroups.Count -ge 4 -and $top.Count -lt ($totalCalled / 2)) {
            $callerNames = (($callerGroups | Select-Object -First 5).Name) -join ', '
            $findings.Add("Lockouts come from $($callerGroups.Count) different caller computers with no single dominant source ($callerNames ...) - this pattern can indicate a compromised credential or password-guessing attack rather than one stale credential. Consider forcing a password change and reviewing for unexpected sign-ins.")
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
            $msg += " - if the tenant uses Pass-through Authentication (PTA), stale cloud credentials can be validated by the on-prem agent and lock the AD account. Check Entra sign-in logs, PTA agent health, and the clients submitting bad passwords."
        } else {
            $msg = "Most bad-password attempts ($($topSource.Count) of $($BadLogons.Count)) come from '$sourceName'"
            if ($ltGroup) {
                $lt    = $ltGroup.Name
                $plain = if ($logonTypeText.ContainsKey($lt)) { $logonTypeText[$lt] } else { "logon type $lt" }
                $msg  += " via $plain"
            }
            $msg += " - check that source for a saved or expired credential."
        }
        $findings.Add($msg)
    }

    # 3) Aggressive policy: low threshold means a few stray bad passwords lock the account.
    if ($Policy -and $Policy.LockoutThreshold -gt 0 -and $Policy.LockoutThreshold -le 3) {
        $findings.Add("Lockout policy threshold is $($Policy.LockoutThreshold) - this is an aggressively low threshold; a few stray bad passwords will lock the account.")
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
            # pwdLastSet of 0 means "user must change password at next logon" - directly
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
        # -Classes tags each column so the stylesheet can size it. Without per-column
        # classes the browser sizes purely by content, which let a 14-character IP wrap
        # onto two lines while a status sentence took a third of the width. An IP address
        # is a fixed-width identifier and must never wrap - it is the thing the reader is
        # scanning for.
        param(
            [object[]]$Rows, [string[]]$Headers, [string[]]$Props, [string]$EmptyText,
            [string[]]$Classes
        )
        if (-not $Rows -or $Rows.Count -eq 0) {
            return "    <p class=`"empty`">$(Convert-Esc $EmptyText)</p>"
        }
        $cls = { param([int]$i) if ($Classes -and $i -lt $Classes.Count) { " class=`"c-$($Classes[$i])`"" } else { '' } }

        $thead = (0..($Headers.Count - 1) | ForEach-Object {
            "<th$(& $cls $_)>$(Convert-Esc $Headers[$_])</th>" }) -join ''
        $body  = foreach ($r in $Rows) {
            $cells = (0..($Props.Count - 1) | ForEach-Object {
                "<td$(& $cls $_)>$(Convert-Esc $r.($Props[$_]))</td>" }) -join ''
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
    # Grouped view first - it answers the question the table is read to answer - with the
    # raw per-event rows kept underneath in a collapsed section for anyone who needs the
    # individual timestamps.
    $badSummary = Get-BadPasswordSummary -Rows $BadLogons
    $badSummaryHtml = if (@($badSummary).Count -eq 0) {
        "    <p class=`"empty`">No bad-password events (4625 / 4771) found in the last $DaysBack day(s).</p>"
    } else {
        New-DataTable -Rows $badSummary `
            -Headers @('Attempts','Source','Source IP','Logon Type','Status','Span','Last seen','DC') `
            -Props   @('Attempts','SourceHost','SourceIp','LogonType','Status','Span','LastSeen','DC') `
            -EmptyText 'None.' `
            -Classes  @('num','host','ip','type','status','span','time','dc')
    }

    $badHtml = New-DataTable -Rows $BadLogons `
        -Headers @('Time','Event','Source Host','Source IP','Logon Type','Status','DC') `
        -Props   @('Time','EventId','SourceHost','SourceIp','LogonType','Status','DC') `
        -EmptyText "No bad-password events (4625 / 4771) found in the last $DaysBack day(s)." `
        -Classes  @('time','num','host','ip','type','status','dc')

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
<p class="meta">Grouped by source and result. Repeated attempts from the same place with the
same outcome are one row - the span tells you whether it is an automated retry loop or a
person. Individual events are below.</p>
<div class="tablewrap">
$badSummaryHtml
</div>

<details>
  <summary>Every bad-password event ($badCount)</summary>
  <div class="tablewrap">
$badHtml
  </div>
</details>

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
