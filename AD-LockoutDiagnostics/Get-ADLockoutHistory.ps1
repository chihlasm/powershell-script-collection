#Requires -Version 5.1

<#
.SYNOPSIS
    Reports every Active Directory account lockout across the domain over a time window.
.DESCRIPTION
    Domain-wide lockout triage. Queries event 4740 (account locked out) on the PDC
    emulator - the DC that authoritatively collects 4740 domain-wide - and ranks every
    account that locked out in the window by how often it happened, naming the caller
    computer(s) that submitted the bad password.

    This answers "is this one stale service account or a widespread problem?". For the
    deep per-account source trace (events 4625/4771 across all DCs), run
    Diagnose-ADAccountLockout.ps1 against the top offenders this report identifies.

    Because the Security event log wraps, the script checks how far back the log
    actually reaches on the queried DC and reports the real coverage. A 30-day report
    backed by 11 days of retained log says so on its face rather than looking like a
    quiet month.
.PARAMETER DaysBack
    How many days of Security event log to search. 1-90, default 30.
.PARAMETER OutputPath
    Folder where the report files are written. Defaults to a "Reports" folder beside
    this script, created if missing.
.PARAMETER DomainController
    Optional. One or more DC names to query instead of auto-discovering the PDC emulator.
    The first DC that answers is used; the rest are fallbacks.
.PARAMETER MinLockouts
    Only include accounts with at least this many lockouts in the window. Default 1
    (report everything). Raise it to filter noise on a busy domain.
.PARAMETER Format
    Which output files to write: Html, Csv, or Both. Default Both.
.EXAMPLE
    .\Get-ADLockoutHistory.ps1
    Last 30 days, HTML + CSV into .\Reports\.
.EXAMPLE
    .\Get-ADLockoutHistory.ps1 -DaysBack 60 -MinLockouts 5
    Last 60 days, only accounts that locked out 5+ times.
.EXAMPLE
    .\Get-ADLockoutHistory.ps1 -DomainController DC01 -OutputPath C:\Reports -Format Csv
.NOTES
    Run on a DC or admin box with RSAT. Requires permission to read the Security event
    log on the queried domain controller.

    Companion tool: Diagnose-ADAccountLockout.ps1 (per-account deep dive).
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 90)]
    [int]$DaysBack = 30,

    [string]$OutputPath,

    [string[]]$DomainController,

    [ValidateRange(1, [int]::MaxValue)]
    [int]$MinLockouts = 1,

    [ValidateSet('Html','Csv','Both')]
    [string]$Format = 'Both',

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
    # Parses a single event 4740 into a normalized row. Same shape as the parser in
    # Diagnose-ADAccountLockout.ps1 - carried locally because repo convention is
    # self-contained scripts with no shared modules.
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

function Get-LogCoverage {
    # Determines how far back the Security log on $DcName actually reaches, so a short
    # retention window isn't silently misread as "few lockouts". Returns a result object
    # rather than throwing: coverage reporting must never break the main run.
    param(
        [string]$DcName,
        [int]$DaysBack
    )
    $result = [PSCustomObject]@{
        DC             = $DcName
        OldestEvent    = $null
        CoverageDays   = $null
        RequestedDays  = $DaysBack
        IsComplete     = $true
        Note           = ''
    }
    try {
        # MaxEvents 1 on an oldest-first read gives the earliest retained record cheaply.
        $oldest = Get-WinEvent -ComputerName $DcName -LogName 'Security' -Oldest -MaxEvents 1 -ErrorAction Stop
        if ($oldest) {
            $result.OldestEvent  = $oldest.TimeCreated
            $span                = (Get-Date) - $oldest.TimeCreated
            $result.CoverageDays = [math]::Round($span.TotalDays, 1)
            if ($span.TotalDays -lt $DaysBack) {
                $result.IsComplete = $false
                $result.Note = ("Security log on {0} only reaches back {1} day(s); {2} day(s) were requested. Older lockouts have already been overwritten and are NOT in this report." -f $DcName, $result.CoverageDays, $DaysBack)
            }
        }
    } catch {
        $result.Note = "Could not determine Security log retention on ${DcName}: $($_.Exception.Message)"
    }
    return $result
}

function Get-DomainLockoutEvents {
    # Queries event 4740 for the whole domain (no per-user filter) on the given DC.
    # "No events" is a normal outcome -> WARN and return @().
    param(
        [string]$DcName,
        [int]$DaysBack
    )
    $filter = @{ LogName = 'Security'; Id = 4740; StartTime = (Get-Date).AddDays(-$DaysBack) }
    try {
        $events = Get-WinEvent -ComputerName $DcName -FilterHashtable $filter -ErrorAction Stop
    } catch {
        if ($_.Exception.Message -match 'No events were found') {
            Write-Status WARN "No 4740 lockout events found on $DcName in the last $DaysBack day(s)."
            return @()
        }
        throw
    }
    $rows = foreach ($e in $events) {
        # Machine accounts end in $ and lock out for different reasons (duplicate SPNs,
        # broken secure channel) than user accounts. Keep them - they're real lockouts -
        # but they're flagged downstream so they don't muddy user triage.
        ConvertFrom-LockoutEvent -EventXml $e.ToXml() -DcName $DcName
    }
    return @($rows)
}

function Group-LockoutsByAccount {
    # Pure aggregation: raw 4740 rows -> one ranked row per account. No event-log or AD
    # calls, so this is directly unit-testable.
    param(
        [object[]]$Lockouts,
        [int]$MinLockouts = 1
    )
    if ($null -eq $Lockouts) { $Lockouts = @() }
    $Lockouts = @($Lockouts)
    if ($Lockouts.Count -eq 0) { return @() }

    $grouped = $Lockouts | Group-Object -Property User | ForEach-Object {
        $times   = @($_.Group.Time | Sort-Object)
        # Blank CallerComputerName shows up when the submitting host can't be resolved;
        # surface that honestly instead of rendering an empty cell.
        $callers = @($_.Group.CallerComputer |
            ForEach-Object { if ([string]::IsNullOrWhiteSpace($_)) { '(not recorded)' } else { $_ } } |
            Sort-Object -Unique)
        $name    = $_.Name

        [PSCustomObject]@{
            User            = $name
            IsComputer      = ($name -like '*$')
            LockoutCount    = $_.Count
            DistinctSources = $callers.Count
            Sources         = ($callers -join ', ')
            FirstSeen       = $times[0]
            LastSeen        = $times[-1]
        }
    }

    $filtered = @($grouped | Where-Object { $_.LockoutCount -ge $MinLockouts })
    # Rank by frequency, then most-recent - the account locking out most is the one to
    # investigate first.
    return @($filtered | Sort-Object -Property @{Expression='LockoutCount';Descending=$true},
                                               @{Expression='LastSeen';Descending=$true})
}

function New-LockoutHistoryHtml {
    # Builds the self-contained dark-themed report. Kept free of event-log calls so it
    # can be exercised with synthetic rows.
    param(
        [object[]]$Summary,
        [object[]]$Lockouts,
        [object]$Coverage,
        [string]$DcName,
        [int]$DaysBack,
        [int]$MinLockouts
    )

    function Convert-Esc { param($v)
        if ($null -eq $v) { return '' }
        ([string]$v).Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;')
    }

    $nl = [Environment]::NewLine

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

    $Summary  = @($Summary)
    $Lockouts = @($Lockouts)

    # --- Headline numbers ---
    $totalLockouts = $Lockouts.Count
    $userAccounts  = @($Summary | Where-Object { -not $_.IsComputer }).Count
    $computerAccts = @($Summary | Where-Object { $_.IsComputer }).Count

    # --- The verdict: one plain-English sentence answering "so what?" ---
    # This is the only thing many readers will actually read, so it has to carry the
    # finding AND the next action, without jargon.
    $verdictClass = 'ok'
    $verdictLine  = ''
    $verdictNext  = ''

    if ($Summary.Count -eq 0) {
        $verdictClass = 'unknown'
        $verdictLine  = "No account locked out in the last $DaysBack days."
        $verdictNext  = 'That is either genuinely quiet or the domain controllers are not recording lockouts. Run Test-ADAuditPolicy.ps1 to tell the two apart.'
    } else {
        $top      = $Summary[0]
        $topName  = $top.User
        $topCount = $top.LockoutCount
        $times    = if ($topCount -eq 1) { 'once' } else { "$topCount times" }
        $runnerUp = if ($Summary.Count -gt 1) { $Summary[1].LockoutCount } else { 0 }

        # A single account dominating points at one stale credential. Many accounts at
        # similar counts points at something systemic instead.
        $dominates = ($Summary.Count -eq 1) -or ($topCount -ge ($runnerUp * 2))

        if ($dominates -and $top.DistinctSources -eq 1) {
            $verdictClass = 'bad'
            $verdictLine  = "$topName locked out $times, always from $($top.Sources)."
            $verdictNext  = "Go to $($top.Sources) and clear the saved password for $topName. A single repeating source is almost always one stale cached credential - a mapped drive, a scheduled task, a service, or a phone."
        } elseif ($dominates) {
            $verdictClass = 'bad'
            $verdictLine  = "$topName locked out $times from $($top.DistinctSources) different computers."
            $verdictNext  = "Check each source: $($top.Sources). Several machines locking one account usually means the password was changed and the old one is still saved in more than one place."
        } else {
            $verdictClass = 'warn'
            $verdictLine  = "$($Summary.Count) accounts locked out, with no single account standing out."
            $verdictNext  = 'Spread evenly across accounts, this points at something shared rather than one stale credential - a low lockout threshold, a service account used everywhere, or a logon script. Check the lockout threshold first.'
        }
    }

    # --- Coverage: the honest scope of the data ---
    $coverageHtml = if ($Coverage -and -not $Coverage.IsComplete) {
        @"
  <div class="alert">
    <div class="alert-title">These results are incomplete</div>
    <p>$(Convert-Esc $Coverage.Note)</p>
    <p class="alert-sub">Anything older has already been overwritten. Treat an empty result as "no data", not "no lockouts".</p>
  </div>
"@
    } elseif ($Coverage -and $Coverage.Note) {
        "  <div class=`"note`">$(Convert-Esc $Coverage.Note)</div>"
    } else {
        ''
    }

    # --- Ranked accounts, rendered as cards rather than a wide table ---
    # A six-column table forces horizontal scanning to answer "who is worst?".
    # Cards put the count and the source - the two things that matter - side by side.
    $rankHtml = if ($Summary.Count -eq 0) {
        "    <p class=`"empty`">No accounts met the minimum of $MinLockouts lockout(s) in the last $DaysBack day(s).</p>"
    } else {
        $maxCount = ($Summary | Measure-Object -Property LockoutCount -Maximum).Maximum
        $cards = foreach ($r in $Summary) {
            # Bar width is proportional to the worst offender, so relative severity is
            # readable at a glance without reading any numbers.
            $pct  = if ($maxCount -gt 0) { [math]::Max(4, [math]::Round(($r.LockoutCount / $maxCount) * 100)) } else { 4 }
            $kind = if ($r.IsComputer) { '<span class="tag">computer account</span>' } else { '' }
            $srcLabel = if ($r.DistinctSources -eq 1) { 'Source' } else { "$($r.DistinctSources) sources" }
            @"
      <article class="rank">
        <div class="rank-head">
          <span class="rank-name">$(Convert-Esc $r.User)</span>$kind
          <span class="rank-count">$($r.LockoutCount)<small>&times;</small></span>
        </div>
        <div class="bar"><span style="width:$pct%"></span></div>
        <dl class="rank-meta">
          <dt>$srcLabel</dt><dd>$(Convert-Esc $r.Sources)</dd>
          <dt>Last seen</dt><dd>$(Convert-Esc $r.LastSeen)</dd>
          <dt>First seen</dt><dd>$(Convert-Esc $r.FirstSeen)</dd>
        </dl>
      </article>
"@
        }
        $cards -join $nl
    }

    # Raw timeline, newest first - the evidence behind the ranking.
    $timelineRows = @($Lockouts | Sort-Object -Property Time -Descending)
    $timelineHtml = New-DataTable -Rows $timelineRows `
        -Headers @('Time','Account','Caller Computer','DC') `
        -Props   @('Time','User','CallerComputer','DC') `
        -EmptyText "No lockout events in the last $DaysBack day(s)."

    $genTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $nextCmd = if ($Summary.Count -gt 0) {
        ".\Diagnose-ADAccountLockout.ps1 -Identity $($Summary[0].User)"
    } else {
        '.\Test-ADAuditPolicy.ps1'
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AD Lockout History - Last $DaysBack Day(s)</title>
<style>
  /* Structure follows reading order: verdict -> what to do -> who -> raw evidence.
     Everything below the verdict is optional detail, and the raw timeline is collapsed
     by default so the page opens short. */
  :root {
    --bg:#15181c; --surface:#1d2126; --surface-2:#242931; --line:#333a44;
    --ink:#e8eaed; --ink-dim:#98a2b0; --ink-faint:#6d7885;
    --accent:#5dade2; --bad:#e2686a; --warn:#e0a458; --ok:#5fc98a;
    --space: clamp(20px, 4vw, 40px);
  }
  * { box-sizing:border-box; }
  body { background:var(--bg); color:var(--ink); margin:0; padding:var(--space);
         font-family:'Segoe UI',system-ui,sans-serif; line-height:1.55;
         max-width:1100px; margin-inline:auto; }

  /* --- Header: small, gets out of the way --- */
  .top { display:flex; flex-wrap:wrap; gap:8px 20px; align-items:baseline;
         padding-bottom:14px; border-bottom:1px solid var(--line); margin-bottom:var(--space); }
  .top h1 { font-size:15px; font-weight:700; letter-spacing:.14em; text-transform:uppercase;
            color:var(--ink-dim); margin:0; }
  .top .facts { color:var(--ink-faint); font-size:12.5px; display:flex; flex-wrap:wrap; gap:14px; }
  .top .facts b { color:var(--ink-dim); font-weight:600; }

  /* --- Verdict: the one thing to read. Sized to be unmissable. --- */
  .verdict { border-left:5px solid var(--ink-faint); padding:4px 0 4px 20px; margin-bottom:26px; }
  .verdict.bad     { border-left-color:var(--bad); }
  .verdict.warn    { border-left-color:var(--warn); }
  .verdict.ok      { border-left-color:var(--ok); }
  .verdict.unknown { border-left-color:var(--ink-faint); }
  .verdict .label { font-size:11px; letter-spacing:.16em; text-transform:uppercase;
                    color:var(--ink-faint); margin-bottom:6px; }
  .verdict .line { font-size:clamp(20px, 3.4vw, 27px); line-height:1.25; font-weight:600;
                   color:#fff; margin:0 0 12px; letter-spacing:-.01em; }
  .verdict .next { font-size:15px; color:var(--ink-dim); margin:0; max-width:68ch; }

  /* --- Alert: only appears when the data itself is untrustworthy --- */
  .alert { background:color-mix(in srgb, var(--warn) 12%, var(--surface));
           border:1px solid color-mix(in srgb, var(--warn) 45%, var(--line));
           border-radius:8px; padding:14px 18px; margin-bottom:24px; }
  .alert-title { font-weight:700; color:var(--warn); font-size:14px; margin-bottom:4px; }
  .alert p { margin:4px 0; font-size:13.5px; color:var(--ink-dim); }
  .alert-sub { color:var(--ink-faint) !important; }
  .note { color:var(--ink-faint); font-size:13px; margin-bottom:24px; }

  /* --- Stat strip: three numbers, no table --- */
  .stats { display:flex; flex-wrap:wrap; gap:10px; margin-bottom:30px; }
  .stat { background:var(--surface); border:1px solid var(--line); border-radius:8px;
          padding:12px 18px; min-width:132px; flex:1 1 132px; }
  .stat .n { font-size:26px; font-weight:700; color:#fff; line-height:1.1;
             font-variant-numeric:tabular-nums; }
  .stat .k { font-size:11.5px; color:var(--ink-faint); text-transform:uppercase;
             letter-spacing:.09em; margin-top:3px; }

  h2 { font-size:12px; letter-spacing:.15em; text-transform:uppercase; color:var(--ink-faint);
       margin:0 0 14px; font-weight:700; }

  /* --- Ranked cards: count and source together, bar for relative severity --- */
  .rank { background:var(--surface); border:1px solid var(--line); border-radius:8px;
          padding:14px 18px; margin-bottom:10px; }
  .rank:first-of-type { border-color:color-mix(in srgb, var(--bad) 40%, var(--line));
                        background:color-mix(in srgb, var(--bad) 6%, var(--surface)); }
  .rank-head { display:flex; align-items:baseline; gap:10px; flex-wrap:wrap; }
  .rank-name { font-size:17px; font-weight:650; color:#fff; word-break:break-all; }
  .rank-count { margin-left:auto; font-size:22px; font-weight:700; color:var(--ink);
                font-variant-numeric:tabular-nums; }
  .rank-count small { font-size:13px; color:var(--ink-faint); font-weight:400; }
  .tag { font-size:10.5px; text-transform:uppercase; letter-spacing:.08em;
         color:var(--ink-faint); border:1px solid var(--line); border-radius:99px;
         padding:1px 8px; }
  .bar { height:3px; background:var(--surface-2); border-radius:99px; overflow:hidden;
         margin:10px 0 12px; }
  .bar span { display:block; height:100%; background:var(--accent); border-radius:99px; }
  .rank:first-of-type .bar span { background:var(--bad); }
  .rank-meta { display:grid; grid-template-columns:auto 1fr; gap:3px 14px; margin:0;
               font-size:13px; }
  .rank-meta dt { color:var(--ink-faint); white-space:nowrap; }
  .rank-meta dd { margin:0; color:var(--ink-dim); word-break:break-word; }

  /* --- Collapsed raw evidence --- */
  details { border-top:1px solid var(--line); margin-top:26px; padding-top:16px; }
  summary { cursor:pointer; font-size:12px; letter-spacing:.15em; text-transform:uppercase;
            color:var(--ink-faint); font-weight:700; list-style:none; }
  summary::-webkit-details-marker { display:none; }
  summary::before { content:'\25B8'; display:inline-block; margin-right:8px;
                    transition:transform .15s ease-out; }
  details[open] summary::before { transform:rotate(90deg); }
  summary:hover { color:var(--ink-dim); }
  .tablewrap { overflow-x:auto; margin-top:14px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  thead th { text-align:left; padding:8px 10px; font-weight:600; color:var(--ink-faint);
             border-bottom:1px solid var(--line); white-space:nowrap;
             font-size:11px; letter-spacing:.07em; text-transform:uppercase; }
  td { padding:7px 10px; border-bottom:1px solid var(--surface-2); vertical-align:top;
       word-break:break-word; }
  tbody tr:hover { background:var(--surface); }
  .empty { color:var(--ink-faint); font-style:italic; }

  footer { color:var(--ink-faint); font-size:12.5px; margin-top:34px;
           border-top:1px solid var(--line); padding-top:16px; }
  code { background:var(--surface-2); padding:2px 7px; border-radius:4px;
         color:var(--accent); font-size:12.5px; }
  @media print {
    body { background:#fff; color:#000; max-width:none; }
    details { display:block; }
    details > summary { display:none; }
    .rank, .stat { break-inside:avoid; }
  }
</style>
</head>
<body>

<div class="top">
  <h1>Lockout History</h1>
  <div class="facts">
    <span>Last <b>$DaysBack days</b></span>
    <span>DC <b>$(Convert-Esc $DcName)</b></span>
    <span><b>$genTime</b></span>
  </div>
</div>

<div class="verdict $verdictClass">
  <div class="label">What this means</div>
  <p class="line">$(Convert-Esc $verdictLine)</p>
  <p class="next">$(Convert-Esc $verdictNext)</p>
</div>

$coverageHtml

<div class="stats">
  <div class="stat"><div class="n">$totalLockouts</div><div class="k">Lockout events</div></div>
  <div class="stat"><div class="n">$userAccounts</div><div class="k">User accounts</div></div>
  <div class="stat"><div class="n">$computerAccts</div><div class="k">Computer accounts</div></div>
</div>

<h2>Worst first</h2>
$rankHtml

<details>
  <summary>Every lockout event ($totalLockouts)</summary>
  <div class="tablewrap">
$timelineHtml
  </div>
</details>

<footer>
  Next: <code>$(Convert-Esc $nextCmd)</code><br><br>
  Event 4740 comes from the PDC emulator, which receives account lockout events
  domain-wide. &ldquo;Source&rdquo; is the computer that submitted the bad password &mdash;
  usually where a stale saved credential lives.
</footer>
</body>
</html>
"@
    return $html
}

# Tests dot-source this script to load the pure helpers without a domain.
if ($LoadFunctionsOnly) { return }

# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

Write-Status INFO "AD Lockout History - searching the last $DaysBack day(s)."

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Status FAIL "Could not load the ActiveDirectory module (RSAT). $($_.Exception.Message)"
    exit 1
}

# --- Resolve which DC(s) to try ---
$candidates = @()
if ($DomainController) {
    $candidates = @($DomainController)
    Write-Status INFO "Using supplied domain controller(s): $($candidates -join ', ')"
} else {
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $candidates = @($domain.PDCEmulator)
        Write-Status INFO "PDC emulator discovered: $($domain.PDCEmulator)"
        # Other DCs are fallbacks only. 4740 lands on the PDC reliably; a non-PDC DC may
        # hold a partial picture, which the report calls out if we end up using one.
        $others = @(Get-ADDomainController -Filter * -ErrorAction Stop |
            Where-Object { $_.HostName -ne $domain.PDCEmulator } |
            Select-Object -ExpandProperty HostName)
        $candidates += $others
    } catch {
        Write-Status FAIL "Could not contact the domain. $($_.Exception.Message)"
        exit 1
    }
}

# --- Query the first DC that answers ---
$lockouts = $null
$usedDc   = $null
foreach ($dc in $candidates) {
    try {
        Write-Status INFO "Querying event 4740 on $dc ..."
        $lockouts = Get-DomainLockoutEvents -DcName $dc -DaysBack $DaysBack
        $usedDc   = $dc
        break
    } catch {
        Write-Status WARN "Could not read the Security log on ${dc}: $($_.Exception.Message)"
        continue
    }
}

if (-not $usedDc) {
    Write-Status FAIL "No domain controller could be queried. Check connectivity and Security log read permissions."
    exit 1
}

if ($usedDc -ne $candidates[0] -and -not $DomainController) {
    Write-Status WARN "The PDC emulator was unreachable; results came from $usedDc and may be incomplete for 4740."
}

$lockouts = @($lockouts)
Write-Status PASS "Retrieved $($lockouts.Count) lockout event(s) from $usedDc."

# --- Retention / coverage check ---
$coverage = Get-LogCoverage -DcName $usedDc -DaysBack $DaysBack
if (-not $coverage.IsComplete) {
    Write-Status WARN $coverage.Note
} elseif ($coverage.Note) {
    Write-Status WARN $coverage.Note
} else {
    Write-Status PASS "Security log covers the full $DaysBack-day window."
}

# --- Aggregate ---
$summary = @(Group-LockoutsByAccount -Lockouts $lockouts -MinLockouts $MinLockouts)

if ($summary.Count -eq 0) {
    Write-Status WARN "No accounts met the minimum of $MinLockouts lockout(s) in the window."
    # An empty result has two very different causes, and they are indistinguishable here:
    # genuinely no lockouts, or the DCs never logged them. Say so rather than letting an
    # empty report read as a quiet domain.
    Write-Status INFO 'An empty result can mean no lockouts occurred, OR that the DCs are not'
    Write-Status INFO 'configured to log them. Confirm with: .\Test-ADAuditPolicy.ps1'
} else {
    Write-Status PASS "$($summary.Count) account(s) locked out in the window."
    Write-Host ''
    $summary | Select-Object -First 10 -Property User, LockoutCount, DistinctSources, LastSeen |
        Format-Table -AutoSize | Out-String | Write-Host
    if ($summary.Count -gt 10) {
        Write-Status INFO "Showing the top 10 of $($summary.Count). The full list is in the report."
    }
}

# --- Resolve output folder: default to a Reports folder beside this script ---
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $OutputPath = Join-Path $scriptRoot 'Reports'
}
if (-not (Test-Path -LiteralPath $OutputPath)) {
    try {
        New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null
        Write-Status INFO "Created output folder: $OutputPath"
    } catch {
        Write-Status FAIL "Could not create output folder ${OutputPath}: $($_.Exception.Message)"
        exit 1
    }
}

$stamp    = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$baseName = "ADLockoutHistory_$stamp"

# --- CSV: raw events, for pivoting ---
if ($Format -in @('Csv','Both')) {
    $csvPath = Join-Path $OutputPath "$baseName.csv"
    try {
        if ($lockouts.Count -gt 0) {
            $lockouts | Select-Object Time, User, Domain, CallerComputer, DC |
                Sort-Object -Property Time -Descending |
                Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        } else {
            # Still write the file so an empty result is explicit, not a missing artifact.
            [PSCustomObject]@{ Time=''; User=''; Domain=''; CallerComputer=''; DC='' } |
                Select-Object Time, User, Domain, CallerComputer, DC |
                Where-Object { $false } |
                Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        }
        Write-Status PASS "CSV written: $csvPath"
    } catch {
        Write-Status FAIL "Could not write CSV: $($_.Exception.Message)"
    }
}

# --- HTML: ranked triage report ---
if ($Format -in @('Html','Both')) {
    $htmlPath = Join-Path $OutputPath "$baseName.html"
    try {
        $html = New-LockoutHistoryHtml -Summary $summary -Lockouts $lockouts -Coverage $coverage `
            -DcName $usedDc -DaysBack $DaysBack -MinLockouts $MinLockouts
        Set-Content -Path $htmlPath -Value $html -Encoding UTF8 -ErrorAction Stop
        Write-Status PASS "HTML report written: $htmlPath"
    } catch {
        Write-Status FAIL "Could not write HTML report: $($_.Exception.Message)"
    }
}

if ($summary.Count -gt 0) {
    Write-Status INFO "Next: .\Diagnose-ADAccountLockout.ps1 -Identity $($summary[0].User) -DaysBack $DaysBack"
}
