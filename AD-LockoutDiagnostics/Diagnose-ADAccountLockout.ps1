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

    $lockoutTime = $null
    try {
        if ($User.lockoutTime -and ($User.lockoutTime -is [int64] -or $User.lockoutTime -is [int]) -and [int64]$User.lockoutTime -gt 0) {
            $lockoutTime = [datetime]::FromFileTime([int64]$User.lockoutTime)
        } else {
            $lockoutTime = $User.lockoutTime
        }
    } catch {
        $lockoutTime = $User.lockoutTime
    }

    # --- Builders for HTML table rows ---
    $nl = [Environment]::NewLine

    # 1) Likely Cause
    $verdictHtml = if ($Verdict -and $Verdict.Count -gt 0) {
        $items = ($Verdict | ForEach-Object { "      <li>$(Convert-Esc $_)</li>" }) -join $nl
        "    <ol>$nl$items$nl    </ol>"
    } else {
        '    <p class="empty">No findings.</p>'
    }

    # 2) Account State
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

    $genTime  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $dcJoined = if ($DcList) { ($DcList -join ', ') } else { '' }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Account Lockout Diagnostics - $(Convert-Esc $sam)</title>
<style>
  :root { --bg:#1a1d21; --panel:#23272e; --row:#1f2329; --rowalt:#262b33;
          --text:#e6e6e6; --muted:#9aa4b0; --accent:#5dade2; --border:#384150; }
  * { box-sizing:border-box; }
  body { background:var(--bg); color:var(--text); margin:0; padding:32px;
         font-family:'Segoe UI',Consolas,Menlo,monospace; line-height:1.5; }
  header { border-left:4px solid var(--accent); padding:8px 0 8px 16px; margin-bottom:28px; }
  h1 { font-size:24px; margin:0 0 12px; color:#fff; letter-spacing:.3px; }
  h2 { font-size:16px; text-transform:uppercase; letter-spacing:1px;
       color:var(--accent); border-bottom:1px solid var(--border);
       padding-bottom:6px; margin:32px 0 12px; }
  .meta { color:var(--muted); font-size:13px; }
  .meta b { color:var(--text); font-weight:600; }
  section { background:var(--panel); border:1px solid var(--border);
            border-radius:6px; padding:16px 20px; margin-bottom:20px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  thead th { background:var(--accent); color:#0b1117; text-align:left;
             padding:8px 10px; font-weight:600; }
  th { text-align:left; padding:6px 10px; color:var(--muted); font-weight:600;
       white-space:nowrap; vertical-align:top; }
  td { padding:6px 10px; border-top:1px solid var(--border); vertical-align:top;
       word-break:break-word; }
  tbody tr:nth-child(odd) { background:var(--row); }
  tbody tr:nth-child(even) { background:var(--rowalt); }
  ol { margin:4px 0; padding-left:22px; }
  li { margin:6px 0; }
  .empty { color:var(--muted); font-style:italic; margin:4px 0; }
  footer { color:var(--muted); font-size:12px; margin-top:32px;
           border-top:1px solid var(--border); padding-top:12px; }
</style>
</head>
<body>
<header>
  <h1>Account Lockout Diagnostics</h1>
  <div class="meta">
    Account: <b>$(Convert-Esc $sam)</b><br>
    Generated: <b>$genTime</b><br>
    Search window: <b>$DaysBack day(s)</b><br>
    Domain controllers queried: <b>$(Convert-Esc $dcJoined)</b>
  </div>
</header>

<section>
  <h2>Likely Cause</h2>
$verdictHtml
</section>

<section>
  <h2>Account State</h2>
  <table><tbody>
$accountHtml
  </tbody></table>
</section>

<section>
  <h2>Effective Lockout Policy</h2>
  <table><tbody>
$policyHtml
  </tbody></table>
</section>

<section>
  <h2>Lockout Timeline (Event 4740 - from PDC $(Convert-Esc $Pdc))</h2>
$lockoutHtml
</section>

<section>
  <h2>Bad-Password Sources (Events 4625 / 4771)</h2>
$badHtml
</section>

<section>
  <h2>Admin / Helpdesk Resets (Event 4724)</h2>
$resetHtml
</section>

<footer>
  Account Lockout Diagnostics - internal MSP tooling. Lockouts originate on-prem;
  hybrid/Entra sign-in failures are out of scope.
</footer>
</body>
</html>
"@

    Set-Content -Path $fullPath -Value $html -Encoding UTF8
    return $fullPath
}

if (-not $LoadFunctionsOnly) {
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

    # --- Verdict ---
    $verdict = Get-LockoutVerdict -Lockouts $lockouts -BadLogons $badLogons -Policy $policy
    Write-Status INFO "Verdict:"
    foreach ($line in $verdict) { Write-Host "    - $line" -ForegroundColor White }

    # --- Report ---
    $reportPath = Write-LockoutReport -User $user -Policy $policy -Lockouts $lockouts `
        -BadLogons $badLogons -Resets $resets -Verdict $verdict -OutputPath $OutputPath `
        -DaysBack $DaysBack -DcList $dcList -Pdc $pdc
    Write-Status PASS "Report written: $reportPath"
}
