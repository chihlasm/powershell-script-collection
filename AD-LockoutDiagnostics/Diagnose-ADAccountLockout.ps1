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
    Folder where the HTML report is written. Defaults to the current directory.
.PARAMETER DaysBack
    How many days of Security event logs to search. 1-90, default 7.
.PARAMETER DomainController
    Optional. One or more DC names to query instead of auto-discovering all DCs.
.EXAMPLE
    .\Diagnose-ADAccountLockout.ps1 -Identity jdoe
.EXAMPLE
    .\Diagnose-ADAccountLockout.ps1 -Identity jdoe -DaysBack 14 -OutputPath C:\Reports
.NOTES
    Run on a DC or admin box with RSAT. Requires permission to read DC Security logs.
    Hybrid/Entra lockouts are out of scope (lockouts originate on-prem).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Identity,

    [string]$OutputPath = (Get-Location).Path,

    [ValidateRange(1, 90)]
    [int]$DaysBack = 7,

    [string[]]$DomainController,

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
        # Prefer SubStatus (the precise failure reason) when present, else Status.
        if ($d.ContainsKey('SubStatus'))  { $status = $d['SubStatus'] }
        elseif ($d.ContainsKey('Status')) { $status = $d['Status'] }
        else                              { $status = $null }
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

function Get-LockoutVerdict {
    # Pure ranking helper. Takes parsed lockout rows, bad-logon rows, and the effective
    # policy object, and returns an ORDERED [string[]] of plain-English findings shown as
    # the "Likely cause" verdict at the top of the report. No event-log or AD calls here.
    param(
        [object[]]$Lockouts,    # rows from ConvertFrom-LockoutEvent (have .CallerComputer)
        [object[]]$BadLogons,   # rows from ConvertFrom-BadLogonEvent (.SourceHost/.SourceIp/.LogonType)
        [object]$Policy         # has .LockoutThreshold (int)
    )

    # Treat null arrays as empty so callers can pass $null without guarding.
    if ($null -eq $Lockouts)  { $Lockouts  = @() }
    if ($null -eq $BadLogons) { $BadLogons = @() }

    $findings = [System.Collections.Generic.List[string]]::new()

    # 4) No evidence: nothing in either bucket -> single guidance line, return early.
    if ($Lockouts.Count -eq 0 -and $BadLogons.Count -eq 0) {
        $findings.Add("Found no on-prem lockout or bad-password events in the searched window. Consider widening -DaysBack, or investigate hybrid/Entra ID sign-in logs if the account is synced.")
        # Still surface an aggressive-policy note if the threshold is low.
        if ($Policy -and $Policy.LockoutThreshold -gt 0 -and $Policy.LockoutThreshold -le 3) {
            $findings.Add("Lockout policy threshold is $($Policy.LockoutThreshold) — this is an aggressively low threshold; a few stray bad passwords will lock the account.")
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

        # Pick the dominant logon type within the top source, if any is present.
        $ltGroup = $topSource.Group |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.LogonType) } |
            Group-Object -Property LogonType |
            Sort-Object -Property Count -Descending |
            Select-Object -First 1
        $msg = "Most bad-password attempts ($($topSource.Count) of $($BadLogons.Count)) come from '$sourceName'"
        if ($ltGroup) {
            $lt    = $ltGroup.Name
            $plain = if ($logonTypeText.ContainsKey($lt)) { $logonTypeText[$lt] } else { "logon type $lt" }
            $msg  += " via $plain"
        }
        $msg += " — check that source for a saved or expired credential."
        $findings.Add($msg)
    }

    # 3) Aggressive policy: low threshold means a few stray bad passwords lock the account.
    if ($Policy -and $Policy.LockoutThreshold -gt 0 -and $Policy.LockoutThreshold -le 3) {
        $findings.Add("Lockout policy threshold is $($Policy.LockoutThreshold) — this is an aggressively low threshold; a few stray bad passwords will lock the account.")
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

if (-not $LoadFunctionsOnly) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        Write-Status FAIL "ActiveDirectory module not found. Install RSAT and retry."
        exit 1
    }
}
