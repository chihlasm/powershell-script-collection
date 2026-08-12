#Requires -Version 5.1
<#
.SYNOPSIS
    Verifies that domain controllers are configured to log the events lockout
    investigations depend on.
.DESCRIPTION
    A lockout report can only find what the domain controllers actually record. If
    failure auditing is disabled, every lockout investigation returns empty no matter how
    far back it searches - the events were never written.

    This is a PREREQUISITE CHECK. Run it before trusting an empty result from
    Get-ADLockoutHistory.ps1 or Diagnose-ADAccountLockout.ps1.

    For every domain controller it reports whether these subcategories log Failure events:

      User Account Management           -> event 4740 (account locked out) + 4724 (reset)
      Logon                            -> event 4625 (failed logon)
      Kerberos Authentication Service   -> event 4771 (Kerberos pre-auth failed)
      Account Lockout                  -> event 4625 against an already-locked account

    Note that event 4740 - the lockout itself - is produced by Audit User Account
    Management, NOT by the similarly-named Audit Account Lockout subcategory. That
    subcategory logs 4625 for logons attempted against an account that is already locked,
    and has no Success events at all. Getting this wrong means checking the wrong setting
    and declaring a blind DC healthy.
    https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-account-lockout

    It also checks two things that silently defeat a correct-looking configuration:

      * Legacy vs Advanced audit policy conflict. If SCENoApplyLegacyAuditPolicy is not
        enabled, legacy audit settings can override the Advanced Audit Policy, so
        auditpol may report the right values while the effective policy differs.
      * Security log retention, since correct auditing plus a log that wraps in days
        still yields an empty long-window report.

    This script REPORTS ONLY and changes nothing. Audit policy belongs in Group Policy on
    the Domain Controllers OU; a local change would be reverted at the next refresh. The
    report prints the exact GPO path and auditpol commands needed.
.PARAMETER DomainController
    Optional. One or more DC names to check instead of auto-discovering all DCs.
.PARAMETER OutputPath
    Folder for the CSV/HTML report. Defaults to a "Reports" folder beside this script.
.PARAMETER Format
    Which output files to write: Html, Csv, or Both. Default Both.
.EXAMPLE
    .\Test-ADAuditPolicy.ps1
    Checks every discovered DC and reports which lockout events are being logged.
.EXAMPLE
    .\Test-ADAuditPolicy.ps1 -DomainController DC01,DC02
.NOTES
    Requires RSAT ActiveDirectory module, PowerShell remoting (WinRM) to the DCs, and
    administrative rights on them. auditpol must be run ON each DC, which is why remoting
    is required rather than a remote registry read.

    Companion tools: Get-ADLockoutHistory.ps1, Diagnose-ADAccountLockout.ps1,
    Set-DCSecurityLogRetention.ps1
#>
[CmdletBinding()]
param(
    [string[]]$DomainController,

    [string]$OutputPath,

    [ValidateSet('Html','Csv','Both')]
    [string]$Format = 'Both',

    # Internal: dot-source the functions without running the orchestration body.
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

# The subcategories that gate lockout evidence. GUIDs are used because subcategory
# display names are localized - on a non-English DC, matching on the name alone fails.
$script:LockoutSubcategories = @(
    [PSCustomObject]@{
        # NOTE: 'Audit Account Lockout' does NOT produce event 4740. Microsoft documents
        # this subcategory as generating 4625 for logons attempted against an ALREADY
        # locked-out account, and states it "doesn't have Success events". Event 4740 is
        # produced by Audit User Account Management (below).
        # https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-account-lockout
        Name        = 'Account Lockout'
        Guid        = '{0CCE9217-69AE-11D9-BED3-505054503030}'
        EventId     = 4625
        Needs       = 'Failure'
        Explains    = 'Logon attempts against an already locked-out account (4625) - shows repeat attempts after the lock'
    }
    [PSCustomObject]@{
        Name        = 'Logon'
        Guid        = '{0CCE9215-69AE-11D9-BED3-505054503030}'
        EventId     = 4625
        Needs       = 'Failure'
        Explains    = 'Failed logons - the source host/IP and logon type of bad passwords'
    }
    [PSCustomObject]@{
        Name        = 'Kerberos Authentication Service'
        Guid        = '{0CCE9242-69AE-11D9-BED3-505054503030}'
        EventId     = 4771
        Needs       = 'Failure'
        Explains    = 'Kerberos pre-authentication failures (domain-joined bad passwords)'
    }
    [PSCustomObject]@{
        # This subcategory gates BOTH event 4740 (account locked out) and 4724 (admin
        # password reset), and both are Success events. 4740 is the single most important
        # event in a lockout investigation, so a gap here makes every lockout report
        # structurally blind - it is called out explicitly in the verdict.
        # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740
        Name        = 'User Account Management'
        Guid        = '{0CCE9235-69AE-11D9-BED3-505054503030}'
        EventId     = 4740
        Needs       = 'Success'
        Explains    = 'Account lockout events (4740) - the lockout timeline itself - and admin password resets (4724)'
    }
)

function ConvertFrom-AuditPolCsv {
    # Parses `auditpol /get /r` CSV output into subcategory -> setting rows.
    #
    # Pure text parsing, kept separate so it is testable without a domain. auditpol's CSV
    # has columns: Machine Name, Policy Target, Subcategory, Subcategory GUID,
    # Inclusion Setting, Exclusion Setting. We match on GUID because the Subcategory
    # display name is localized.
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$CsvText
    )

    $rows = @()
    if ([string]::IsNullOrWhiteSpace($CsvText)) { return $rows }

    try {
        $parsed = $CsvText | ConvertFrom-Csv
    } catch {
        return $rows
    }

    foreach ($p in $parsed) {
        # Column names vary slightly by OS language/version; find them tolerantly.
        $guidProp = $p.PSObject.Properties.Name | Where-Object { $_ -match 'GUID' } | Select-Object -First 1
        $setProp  = $p.PSObject.Properties.Name | Where-Object { $_ -match 'Inclusion' } | Select-Object -First 1
        $subProp  = $p.PSObject.Properties.Name | Where-Object { $_ -match 'Subcategory' -and $_ -notmatch 'GUID' } | Select-Object -First 1
        if (-not $guidProp -or -not $setProp) { continue }

        $rows += [PSCustomObject]@{
            Guid        = ([string]$p.$guidProp).Trim()
            Subcategory = if ($subProp) { ([string]$p.$subProp).Trim() } else { '' }
            Setting     = ([string]$p.$setProp).Trim()
        }
    }
    return $rows
}

function Test-SubcategorySetting {
    # Decides whether an auditpol "Inclusion Setting" satisfies what a subcategory needs.
    #
    # auditpol reports one of: "No Auditing", "Success", "Failure", "Success and Failure".
    # Pure logic - no remote calls - so the pass/fail rules are directly testable.
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Setting,
        [Parameter(Mandatory)][ValidateSet('Success','Failure')][string]$Needs
    )

    $result = [PSCustomObject]@{
        Setting  = $Setting
        Needs    = $Needs
        Logs     = $false
        Status   = 'Fail'
        Detail   = ''
    }

    if ([string]::IsNullOrWhiteSpace($Setting)) {
        $result.Detail = 'Subcategory not reported by auditpol; cannot confirm it is enabled.'
        $result.Status = 'Unknown'
        return $result
    }

    $s = $Setting.Trim()
    # "Success and Failure" satisfies either requirement; otherwise the setting must
    # contain the specific audit type needed.
    $hasSuccess = $s -match '(?i)success'
    $hasFailure = $s -match '(?i)failure'
    $noAuditing = $s -match '(?i)no auditing'

    if ($noAuditing) {
        $result.Detail = 'No Auditing - these events are not written at all.'
        return $result
    }

    $result.Logs = if ($Needs -eq 'Failure') { $hasFailure } else { $hasSuccess }
    if ($result.Logs) {
        $result.Status = 'Pass'
        $result.Detail = "Logging $Needs events."
    } else {
        $result.Detail = "Set to '$s' - $Needs events are NOT logged."
    }
    return $result
}

function Get-DCAuditPolicy {
    # Collects audit policy + supporting state from one DC. Every remote call is wrapped
    # so a single unreachable DC never halts the sweep.
    param(
        [Parameter(Mandatory)][string]$DcName
    )

    $result = [PSCustomObject]@{
        DC                 = $DcName
        Reachable          = $false
        Subcategories      = @()
        LegacyOverrideRisk = $null
        LogMaxMB           = $null
        RetentionDays      = $null
        Errors             = @()
    }

    try {
        # auditpol reports the EFFECTIVE local policy, so it must run on the DC itself.
        $remote = Invoke-Command -ComputerName $DcName -ErrorAction Stop -ScriptBlock {
            $csv = & auditpol.exe /get /category:* /r 2>$null | Out-String
            $key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
            $sce = $null
            try {
                $sce = (Get-ItemProperty -Path $key -Name 'SCENoApplyLegacyAuditPolicy' -ErrorAction Stop).SCENoApplyLegacyAuditPolicy
            } catch { $sce = $null }
            [PSCustomObject]@{ AuditPolCsv = $csv; SCENoApplyLegacyAuditPolicy = $sce }
        }
        $result.Reachable = $true
    } catch {
        $result.Errors += "Could not run auditpol remotely: $($_.Exception.Message)"
        return $result
    }

    $parsed = ConvertFrom-AuditPolCsv -CsvText $remote.AuditPolCsv
    if ($parsed.Count -eq 0) {
        $result.Errors += 'auditpol returned no parseable rows; verify remoting and administrative rights.'
    }

    $subRows = foreach ($sub in $script:LockoutSubcategories) {
        $match = $parsed | Where-Object { $_.Guid -eq $sub.Guid } | Select-Object -First 1
        $setting = if ($match) { $match.Setting } else { '' }
        $eval = Test-SubcategorySetting -Setting $setting -Needs $sub.Needs

        [PSCustomObject]@{
            DC          = $DcName
            Subcategory = $sub.Name
            EventId     = $sub.EventId
            Needs       = $sub.Needs
            Setting     = if ($setting) { $setting } else { '(not reported)' }
            Status      = $eval.Status
            Detail      = $eval.Detail
            Explains    = $sub.Explains
        }
    }
    $result.Subcategories = @($subRows)

    # SCENoApplyLegacyAuditPolicy = 1 means Advanced Audit Policy wins. If it is absent or
    # 0, legacy audit settings can override it, so auditpol's values may not be effective.
    $sce = $remote.SCENoApplyLegacyAuditPolicy
    $result.LegacyOverrideRisk = -not ($sce -eq 1)

    try {
        $log = Get-WinEvent -ListLog Security -ComputerName $DcName -ErrorAction Stop
        $result.LogMaxMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 0)
        $oldest = Get-WinEvent -ComputerName $DcName -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop
        if ($oldest) {
            $result.RetentionDays = [math]::Round(((Get-Date) - $oldest.TimeCreated).TotalDays, 2)
        }
    } catch {
        $result.Errors += "Could not read Security log state: $($_.Exception.Message)"
    }

    return $result
}

function Get-AuditPolicyVerdict {
    # Turns collected per-DC results into ranked plain-English findings. Pure logic.
    param([object[]]$Results)

    $findings = [System.Collections.Generic.List[string]]::new()
    $Results = @($Results)
    $reachable = @($Results | Where-Object { $_.Reachable })

    if ($reachable.Count -eq 0) {
        $findings.Add('No domain controller could be queried. Audit policy could not be verified, so an empty lockout report proves nothing.')
        return $findings.ToArray()
    }

    $allSubs = @($reachable | ForEach-Object { $_.Subcategories })

    # The headline: any failure-audit gap makes lockout reports structurally blind.
    foreach ($sub in $script:LockoutSubcategories) {
        $rows    = @($allSubs | Where-Object { $_.Subcategory -eq $sub.Name })
        $failing = @($rows | Where-Object { $_.Status -ne 'Pass' })
        if ($failing.Count -eq 0) { continue }

        if ($failing.Count -eq $rows.Count) {
            $findings.Add(("'{0}' is not logging {1} events on ANY checked DC. Event {2} is never written, so {3} cannot be found by any lockout report regardless of the search window." -f $sub.Name, $sub.Needs, $sub.EventId, $sub.Explains))
        } else {
            $dcs = ($failing | Select-Object -ExpandProperty DC) -join ', '
            $findings.Add(("'{0}' is not logging {1} events on: {2}. Event {3} is missing from those DCs, so evidence will be incomplete depending on which DC handled the authentication." -f $sub.Name, $sub.Needs, $dcs, $sub.EventId))
        }
    }

    $legacyRisk = @($reachable | Where-Object { $_.LegacyOverrideRisk -eq $true })
    if ($legacyRisk.Count -gt 0) {
        $dcs = ($legacyRisk | Select-Object -ExpandProperty DC) -join ', '
        $findings.Add(("SCENoApplyLegacyAuditPolicy is not enabled on: {0}. Legacy audit settings can override the Advanced Audit Policy, so the values above may not be what is actually in effect. Enable 'Force audit policy subcategory settings to override audit policy category settings'." -f $dcs))
    }

    # Correct auditing plus a short log still yields empty long-window reports.
    $shortLogs = @($reachable | Where-Object { $null -ne $_.RetentionDays -and $_.RetentionDays -lt 7 })
    if ($shortLogs.Count -gt 0) {
        $detail = ($shortLogs | ForEach-Object { "$($_.DC) ($($_.RetentionDays) days)" }) -join ', '
        $findings.Add(("Security log retention is under 7 days on: {0}. Even with correct auditing, older evidence is already overwritten. See Set-DCSecurityLogRetention.ps1." -f $detail))
    }

    if ($findings.Count -eq 0) {
        $findings.Add('All lockout-relevant audit subcategories are logging on every checked DC. An empty lockout report is therefore meaningful: the events genuinely did not occur on-prem, which points at a cloud-side origin (Entra sign-in logs, Smart Lockout, PTA) rather than a collection gap.')
    }

    return $findings.ToArray()
}

function New-AuditPolicyHtml {
    # Self-contained dark-themed report, matching the other tools in this folder.
    param(
        [object[]]$Results,
        [string[]]$Verdict
    )

    function Convert-Esc { param($v)
        if ($null -eq $v) { return '' }
        ([string]$v).Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;')
    }

    $nl = [Environment]::NewLine
    $Results = @($Results)

    $allSubs = @($Results | ForEach-Object { $_.Subcategories })

    # --- Verdict: can this domain produce lockout evidence at all? ---
    # The headline is binary and blunt, because everything downstream depends on it.
    $lockoutGaps = @($allSubs | Where-Object { $_.EventId -eq 4740 -and $_.Status -ne 'Pass' })
    $otherGaps   = @($allSubs | Where-Object { $_.EventId -ne 4740 -and $_.Status -ne 'Pass' })
    $reachable   = @($Results | Where-Object { $_.Reachable })

    if ($allSubs.Count -eq 0 -or $reachable.Count -eq 0) {
        $verdictClass = 'unknown'
        $verdictLine  = 'Audit policy could not be read.'
        $verdictNext  = 'Without this, an empty lockout report proves nothing - it could mean no lockouts, or no auditing. Check WinRM connectivity and administrative rights on the domain controllers, then run this again.'
    } elseif ($lockoutGaps.Count -gt 0) {
        $dcs = ($lockoutGaps | Select-Object -ExpandProperty DC -Unique) -join ', '
        $verdictClass = 'bad'
        $verdictLine  = "Account lockouts are not being recorded on $dcs."
        $verdictNext  = 'Event 4740 is the lockout itself. Until Audit User Account Management is set to Success, every lockout report on this domain will come back empty - and empty will look exactly like clean. Fix this before investigating anything else.'
    } elseif ($otherGaps.Count -gt 0) {
        $missing = ($otherGaps | Select-Object -ExpandProperty EventId -Unique | Sort-Object) -join ', '
        $verdictClass = 'warn'
        $verdictLine  = "Lockouts are recorded, but supporting evidence is missing (event $missing)."
        $verdictNext  = 'You will see that an account locked out, but not always what caused it. Reports will name the account and often the machine, while the specific bad-password attempts may be absent.'
    } else {
        $verdictClass = 'ok'
        $verdictLine  = 'Everything needed to investigate lockouts is being recorded.'
        $verdictNext  = 'An empty lockout report is therefore a real result: the events genuinely did not happen on-prem. That points at a cloud-side origin - Entra sign-in logs, Smart Lockout, or a pass-through authentication agent - rather than a gap in collection.'
    }

    # --- Per-subcategory cards, worst first ---
    $subHtml = if ($allSubs.Count -eq 0) {
        '    <p class="empty">No audit policy data was collected.</p>'
    } else {
        # Sort failures to the top: the reader needs the problems, not an alphabet.
        $ordered = @($allSubs | Sort-Object @{Expression={ if ($_.Status -eq 'Pass') { 1 } else { 0 } }},
                                            @{Expression={ if ($_.EventId -eq 4740) { 0 } else { 1 } }},
                                            DC)
        $cards = foreach ($r in $ordered) {
            $isPass = $r.Status -eq 'Pass'
            $cls    = if ($isPass) { 'ok' } elseif ($r.EventId -eq 4740) { 'bad' } else { '' }
            $tagCls = if ($isPass) { 'ok' } elseif ($r.Status -eq 'Unknown') { 'warn' } else { 'bad' }
            $label  = if ($isPass) { 'Logging' } elseif ($r.Status -eq 'Unknown') { 'Unknown' } else { 'Not logging' }
            $crit   = if (-not $isPass -and $r.EventId -eq 4740) { ' <span class="tag bad">blocks all lockout reports</span>' } else { '' }
            @"
      <article class="card $cls">
        <div class="card-head">
          <span class="card-name">$(Convert-Esc $r.Subcategory)</span>
          <span class="tag $tagCls">$label</span>$crit
          <span class="card-count">$(Convert-Esc $r.EventId)</span>
        </div>
        <dl class="kv">
          <dt>Domain controller</dt><dd>$(Convert-Esc $r.DC)</dd>
          <dt>Currently</dt><dd>$(Convert-Esc $r.Setting) &mdash; needs <b>$(Convert-Esc $r.Needs)</b></dd>
          <dt>Gives you</dt><dd>$(Convert-Esc $r.Explains)</dd>
          <dt>Detail</dt><dd>$(Convert-Esc $r.Detail)</dd>
        </dl>
      </article>
"@
        }
        $cards -join $nl
    }

    # Raw table retained behind a disclosure for anyone who wants the grid view.
    $subTableHtml = if ($allSubs.Count -eq 0) { '' } else {
        $body = foreach ($r in $allSubs) {
            $cls = switch ($r.Status) { 'Pass' { 'ok' } 'Unknown' { 'warn' } default { 'bad' } }
            "        <tr><td>$(Convert-Esc $r.DC)</td><td>$(Convert-Esc $r.Subcategory)</td><td>$(Convert-Esc $r.EventId)</td><td>$(Convert-Esc $r.Needs)</td><td>$(Convert-Esc $r.Setting)</td><td class=`"$cls`">$(Convert-Esc $r.Status)</td></tr>"
        }
        "    <table>$nl      <thead><tr><th>DC</th><th>Subcategory</th><th>Event</th><th>Needs</th><th>Current</th><th>Status</th></tr></thead>$nl      <tbody>$nl$($body -join $nl)$nl      </tbody>$nl    </table>"
    }

    $stateRows = foreach ($r in $Results) {
        $reach = if ($r.Reachable) { 'Yes' } else { 'No' }
        $legacy = if ($null -eq $r.LegacyOverrideRisk) { 'Unknown' } elseif ($r.LegacyOverrideRisk) { 'AT RISK' } else { 'Enforced' }
        "        <tr><td>$(Convert-Esc $r.DC)</td><td>$reach</td><td>$(Convert-Esc $r.LogMaxMB)</td><td>$(Convert-Esc $r.RetentionDays)</td><td>$legacy</td></tr>"
    }
    $stateHtml = "    <table>$nl      <thead><tr><th>DC</th><th>Reachable</th><th>Log Max (MB)</th><th>Retention (days)</th><th>Advanced Policy</th></tr></thead>$nl      <tbody>$nl$($stateRows -join $nl)$nl      </tbody>$nl    </table>"

    $errItems = @()
    foreach ($r in $Results) {
        foreach ($e in @($r.Errors)) {
            if (-not [string]::IsNullOrWhiteSpace($e)) { $errItems += "      <li>$(Convert-Esc "$($r.DC): $e")</li>" }
        }
    }
    $errHtml = if ($errItems.Count -gt 0) { "    <ol>$nl$($errItems -join $nl)$nl    </ol>" } else { '    <p class="empty">No collection errors.</p>' }

    $genTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # Shared stylesheet, so a design change applies to every report at once. Falls back to
    # a minimal inline set if the reference file is missing, rather than rendering unstyled.
    $css = $null
    $refPath = Join-Path $PSScriptRoot 'LockoutReference.psd1'
    if (Test-Path -LiteralPath $refPath) {
        try { $css = (Import-PowerShellDataFile -Path $refPath -ErrorAction Stop).ReportCss } catch { $css = $null }
    }
    if (-not $css) {
        $css = @'
  body { background:#15181c; color:#e8eaed; font-family:'Segoe UI',system-ui,sans-serif;
         margin:0; padding:32px; max-width:1100px; margin-inline:auto; line-height:1.55; }
  .verdict { border-left:5px solid #6d7885; padding:4px 0 4px 20px; margin-bottom:26px; }
  .verdict.bad { border-left-color:#e2686a; } .verdict.warn { border-left-color:#e0a458; }
  .verdict.ok { border-left-color:#5fc98a; }
  .verdict .line { font-size:25px; font-weight:600; color:#fff; margin:0 0 12px; }
  .verdict .next { color:#98a2b0; margin:0; max-width:68ch; }
  .card { background:#1d2126; border:1px solid #333a44; border-radius:8px;
          padding:14px 18px; margin-bottom:10px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  td, th { padding:7px 10px; border-bottom:1px solid #242931; text-align:left; }
'@
    }

    $dcCount   = @($Results).Count
    $gapCount  = @($allSubs | Where-Object { $_.Status -ne 'Pass' }).Count
    $passCount = @($allSubs | Where-Object { $_.Status -eq 'Pass' }).Count
    $gapClass  = if ($gapCount -gt 0) { 'bad' } else { 'ok' }

    # Only show the fix instructions when there is something to fix.
    $fixHtml = if ($gapCount -eq 0) { '' } else {
@"
<h2>How to fix</h2>
<p style="color:var(--ink-dim);font-size:14px;max-width:68ch;">Set these in <b>Group Policy</b> on
   the Domain Controllers OU &mdash; a local change is reverted at the next GPO refresh.<br>
   <code>Computer Configuration &rarr; Policies &rarr; Windows Settings &rarr; Security Settings &rarr; Advanced Audit Policy Configuration</code></p>
<ul class="fix">
  <li><b>Account Management &rarr; Audit User Account Management</b> &rarr; <b>Success</b><br>
      Produces event 4740, the lockout itself. Without this nothing else matters.</li>
  <li><b>Account Logon &rarr; Audit Kerberos Authentication Service</b> &rarr; Success <i>and</i> Failure (4771)</li>
  <li><b>Logon/Logoff &rarr; Audit Logon</b> &rarr; Success <i>and</i> Failure (4625)</li>
  <li><b>Logon/Logoff &rarr; Audit Account Lockout</b> &rarr; <b>Failure</b><br>
      This subcategory has no Success events, so enabling Success achieves nothing.</li>
  <li><b>Local Policies &rarr; Security Options &rarr;</b> &ldquo;Force audit policy subcategory settings
      to override audit policy category settings&rdquo; &rarr; <b>Enabled</b><br>
      Without this, legacy settings can silently override everything above.</li>
</ul>
<p style="color:var(--ink-faint);font-size:13px;">Then <code>gpupdate /force</code> on the DCs and run this check again.</p>
"@
    }

    @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Audit Policy Check</title>
<style>
$css
</style>
</head>
<body>

<div class="top">
  <h1>Audit Policy Check</h1>
  <div class="facts">
    <span><b>$dcCount</b> domain controller(s)</span>
    <span>Lockout events <b>4740 / 4625 / 4771 / 4724</b></span>
    <span><b>$genTime</b></span>
  </div>
</div>

<div class="verdict $verdictClass">
  <div class="label">What this means</div>
  <p class="line">$(Convert-Esc $verdictLine)</p>
  <p class="next">$(Convert-Esc $verdictNext)</p>
</div>

<div class="stats">
  <div class="stat"><div class="n $gapClass">$gapCount</div><div class="k">Not logging</div></div>
  <div class="stat"><div class="n">$passCount</div><div class="k">Logging</div></div>
  <div class="stat"><div class="n">$dcCount</div><div class="k">DCs checked</div></div>
</div>

<h2>Problems first</h2>
$subHtml

$fixHtml

<details>
  <summary>Domain controller state</summary>
  <div class="tablewrap">
$stateHtml
  </div>
</details>

<details>
  <summary>All subcategories as a table</summary>
  <div class="tablewrap">
$subTableHtml
  </div>
</details>

<details>
  <summary>Collection errors</summary>
$errHtml
</details>

<footer>
  Audit policy decides whether lockout evidence exists at all. If the subcategory behind
  event 4740 is not logging, no lockout report can find anything &mdash; regardless of the
  search window or how large the Security log is.<br><br>
  Verify manually on a DC with:
  <code>auditpol /get /category:"Logon/Logoff","Account Logon","Account Management"</code>
</footer>
</body>
</html>
"@
}

if ($LoadFunctionsOnly) { return }

# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

Write-Status INFO 'Checking whether domain controllers log lockout-relevant events.'

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Status FAIL "Could not load the ActiveDirectory module (RSAT). $($_.Exception.Message)"
    exit 1
}

if ($DomainController) {
    $dcs = @($DomainController)
    Write-Status INFO "Using supplied DC(s): $($dcs -join ', ')"
} else {
    try {
        $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName)
        Write-Status INFO "Discovered $($dcs.Count) DC(s): $($dcs -join ', ')"
    } catch {
        Write-Status FAIL "Could not enumerate domain controllers. $($_.Exception.Message)"
        exit 1
    }
}

$results = foreach ($dc in $dcs) {
    Write-Status INFO "Querying audit policy on $dc ..."
    $r = Get-DCAuditPolicy -DcName $dc
    if (-not $r.Reachable) {
        foreach ($e in $r.Errors) { Write-Status WARN "${dc}: $e" }
    }
    $r
}
$results = @($results)

# --- Console summary ---
Write-Host ''
$flat = @($results | ForEach-Object { $_.Subcategories })
if ($flat.Count -gt 0) {
    $flat | Format-Table -AutoSize -Property DC, Subcategory, EventId, Setting, Status |
        Out-String | Write-Host
}

foreach ($row in $flat | Where-Object { $_.Status -ne 'Pass' }) {
    Write-Status FAIL "$($row.DC) / $($row.Subcategory) (event $($row.EventId)): $($row.Detail)"
}

$verdict = Get-AuditPolicyVerdict -Results $results
Write-Host ''
Write-Status INFO 'Findings:'
foreach ($line in $verdict) { Write-Host "    - $line" -ForegroundColor White }

# --- Output ---
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $OutputPath = Join-Path $scriptRoot 'Reports'
}
if (-not (Test-Path -LiteralPath $OutputPath)) {
    try {
        New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Status FAIL "Could not create output folder ${OutputPath}: $($_.Exception.Message)"
        exit 1
    }
}

$stamp    = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$baseName = "ADAuditPolicy_$stamp"

if ($Format -in @('Csv','Both')) {
    $csvPath = Join-Path $OutputPath "$baseName.csv"
    try {
        if ($flat.Count -gt 0) {
            $flat | Select-Object DC, Subcategory, EventId, Needs, Setting, Status, Detail |
                Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-Status PASS "CSV written: $csvPath"
        } else {
            Write-Status WARN 'No audit policy rows collected; CSV not written.'
        }
    } catch {
        Write-Status FAIL "Could not write CSV: $($_.Exception.Message)"
    }
}

if ($Format -in @('Html','Both')) {
    $htmlPath = Join-Path $OutputPath "$baseName.html"
    try {
        $html = New-AuditPolicyHtml -Results $results -Verdict $verdict
        Set-Content -Path $htmlPath -Value $html -Encoding UTF8 -ErrorAction Stop
        Write-Status PASS "HTML report written: $htmlPath"
    } catch {
        Write-Status FAIL "Could not write HTML report: $($_.Exception.Message)"
    }
}
