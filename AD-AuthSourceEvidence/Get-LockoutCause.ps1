#Requires -Version 5.1

<#
.SYNOPSIS
    Turns collected lockout evidence into a ranked list of likely causes and fixes.
.DESCRIPTION
    The last step of a lockout investigation, and the one the tooling previously left to
    human judgement: given the evidence already collected - logon types, process names,
    device class, which events fired - name the LIKELY CAUSE and the SPECIFIC REMEDIATION.

    Every cause this can emit is drawn from Microsoft's documented list of account lockout
    causes. Nothing here is invented from experience:
    https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2003/cc773155(v=ws.10)

    The mapping is possible because the evidence is unusually diagnostic. LogonType in
    particular is close to a direct answer:

      5  Service          -> a Windows service whose saved password is stale
      4  Batch            -> a scheduled task with expired credentials
      3  Network          -> a mapped drive, share access, or stored credential
      10 RemoteInteractive-> a disconnected RDP/Terminal Server session still running
      2  Interactive      -> cached credentials on a console session
      7  Unlock           -> the same, surfacing at the lock screen

    PURE FUNCTION, NO COLLECTION. This script queries nothing. It reasons over data
    already gathered, so it cannot be slow, cannot hang, and is fully unit-testable. That
    is deliberate: every performance problem in this toolkit has come from collection.

    MULTI-USER LOCKOUTS. Nothing here needs a username. The classifier reasons about a
    SOURCE DEVICE and the accounts it hit, so a domain-wide run and a single-user run take
    the same path. When one source is failing against many accounts that fact is raised
    first, because it changes the fix: thirty users with thirty stale mapped drives is
    thirty tickets, whereas thirty users behind one server with a stale scheduled task is
    one.

    IT SUGGESTS, IT DOES NOT CONCLUDE. Output is a ranked list of hypotheses with the
    evidence behind each, not a verdict. A stale service password and a stale scheduled
    task look identical from the domain controller; only the technician on the box can
    tell them apart. Confidence is stated so a Low-confidence guess is not mistaken for
    an answer.
.PARAMETER LogonTypes
    Logon type values seen in the failure events for this source. The strongest signal.
.PARAMETER DeviceClass
    Device classification from Export-ADAuthSourceEvidence.ps1: DomainJoinedWorkstation,
    Server, DomainController, NetworkDevice, NonDomainDevice, LocalOrConsole, Unknown.
.PARAMETER ProcessNames
    Process names from event 4625, where present.
.PARAMETER EventIds
    Which event IDs fired for this source. A 4776-only source implies NTLM-only clients.
.PARAMETER MacVendor
    Hardware vendor from the MAC OUI, when DHCP supplied one.
.PARAMETER DistinctAccounts
    How many different accounts this one source failed against. Evaluated before every
    other signal, because it reframes them: the same evidence means "one user's stale
    mapped drive" at 1 account and "one shared misconfiguration, or a password spray" at
    30. Microsoft notes a spray "looks like an isolated failed login" from any single
    user's perspective, which is why a per-account investigation cannot see it.
.PARAMETER SourceKey
    The source's IP or hostname, used in the evidence text.
.PARAMETER LoadFunctionsOnly
    Dot-source the functions without running anything. Used by the tests.
.EXAMPLE
    Get-LockoutCause -LogonTypes @(5) -DeviceClass 'Server' -ProcessNames @() -EventIds @(4625)
    Ranks "service with a stale password" first.
.EXAMPLE
    .\Get-LockoutCause.ps1 -SourcesCsv .\Reports\AuthSources_2026-08-20_141530.csv
    Classifies every source in an existing export.
.NOTES
    Read-only, offline, no dependencies.

    REFERENCES
      Troubleshooting Account Lockout - the documented cause list this maps to
        https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2003/cc773155(v=ws.10)
      Event 4624 logon type table
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624
      Event 4625 logon type table and SubStatus codes
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625
      Account lockout threshold - Microsoft baseline is 10
        https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/account-lockout-threshold

    Verified against Microsoft Learn on 2026-08-20.
#>
[CmdletBinding()]
param(
    [string]$SourcesCsv,
    [string]$OutputPath,
    [switch]$LoadFunctionsOnly
)

$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# Process names that tell you nothing about the cause.
#
# lsass.exe is the process that PERFORMS authentication - it appears on essentially every
# failed logon and identifies the authenticating machine, not the offending application.
# Reporting it as "the culprit" sends the technician to inspect LSASS on a domain
# controller, which is never the answer.
# -----------------------------------------------------------------------------
$script:UninformativeProcesses = @('lsass.exe', 'services.exe', '-', '')

# -----------------------------------------------------------------------------
# Applications that commonly hold a stale credential of their own. Matching one does not
# prove it is the cause, but it names a specific thing to open and check, which is far
# more actionable than "some program".
# -----------------------------------------------------------------------------
$script:CredentialHoldingApps = @{
    'outlook.exe'   = 'Microsoft Outlook (cached mail profile credential)'
    'teams.exe'     = 'Microsoft Teams (cached sign-in)'
    'onedrive.exe'  = 'OneDrive (cached sign-in)'
    'chrome.exe'    = 'Google Chrome (saved intranet credential)'
    'msedge.exe'    = 'Microsoft Edge (saved intranet credential)'
    'firefox.exe'   = 'Mozilla Firefox (saved intranet credential)'
    'explorer.exe'  = 'Windows Explorer (mapped drive or shortcut to a share)'
    'mstsc.exe'     = 'Remote Desktop client (saved connection credential)'
    'sqlservr.exe'  = 'SQL Server (service or linked-server credential)'
    'w3wp.exe'      = 'IIS application pool (identity or stored connection credential)'
    'inetinfo.exe'  = 'IIS (token cache - reset the IIS token cache)'
    'taskeng.exe'   = 'Task Scheduler engine (a task is running as this account)'
    'taskhostw.exe' = 'Task Scheduler host (a task is running as this account)'
    'svchost.exe'   = 'A Windows service host (several services share this process)'
}

function New-Cause {
    # Uniform shape for every hypothesis, so callers can sort and render without
    # special-casing.
    param(
        [Parameter(Mandatory)][string]$Cause,
        [Parameter(Mandatory)][ValidateSet('High','Medium','Low')][string]$Confidence,
        [Parameter(Mandatory)][string]$Evidence,
        [Parameter(Mandatory)][string]$Remediation
    )
    [PSCustomObject]@{
        Cause       = $Cause
        Confidence  = $Confidence
        Evidence    = $Evidence
        Remediation = $Remediation
    }
}

$script:FallbackCss = @'
  :root { --bg:#15181c; --surface:#1d2126; --line:#333a44; --ink:#e8eaed;
          --ink-dim:#98a2b0; --ink-faint:#6d7885; --accent:#5dade2;
          --bad:#e2686a; --warn:#e0a458; --ok:#5fc98a; }
  * { box-sizing:border-box; }
  body { background:var(--bg); color:var(--ink); margin:0 auto; padding:32px; max-width:1100px;
         font-family:'Segoe UI',system-ui,sans-serif; line-height:1.55; }
  h1 { font-size:15px; font-weight:700; letter-spacing:.14em; text-transform:uppercase; color:var(--ink-dim); margin:0; }
  .top { padding-bottom:14px; border-bottom:1px solid var(--line); margin-bottom:28px; }
  .facts { color:var(--ink-faint); font-size:12.5px; display:flex; gap:16px; margin-top:6px; }
  .verdict { border-left:5px solid var(--bad); padding:4px 0 4px 20px; margin-bottom:26px; }
  .verdict.ok { border-left-color:var(--ok); }
  .verdict .label { font-size:11px; letter-spacing:.16em; text-transform:uppercase; color:var(--ink-faint); }
  .verdict .line { font-size:25px; line-height:1.25; font-weight:600; margin:6px 0 10px; }
  .verdict .next { font-size:15px; color:var(--ink-dim); margin:0; max-width:68ch; }
  .card { background:var(--surface); border:1px solid var(--line); border-radius:8px; padding:18px; margin-bottom:14px; }
  .card-head { display:flex; align-items:baseline; gap:10px; flex-wrap:wrap; }
  .card-name { font-size:17px; font-weight:650; color:#fff; word-break:break-all; }
  .card-meta { color:var(--ink-faint); font-size:12.5px; }
  .card-count { margin-left:auto; font-size:22px; font-weight:700; }
  .card-count small { font-size:13px; color:var(--ink-faint); font-weight:400; }
  table { width:100%; border-collapse:collapse; font-size:13px; margin-top:12px; }
  th,td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--ink-faint); text-transform:uppercase; font-size:11px; letter-spacing:.1em; }
  details { border-top:1px solid var(--line); margin-top:26px; padding-top:16px; }
  summary { cursor:pointer; font-size:12px; letter-spacing:.15em; text-transform:uppercase; color:var(--ink-faint); }
  .tablewrap { overflow-x:auto; margin-top:14px; }
  .pill { display:inline-block; padding:2px 9px; border-radius:999px; font-size:11px; font-weight:600; }
  .pill.High { background:rgba(226,104,106,.16); color:var(--bad); }
  .pill.Medium { background:rgba(224,164,88,.16); color:var(--warn); }
  .pill.Low { background:rgba(109,120,133,.16); color:var(--ink-faint); }
'@

# =============================================================================
# HTML case report
#
# One page to attach to a ticket. Follows the reading order every other report in this
# toolkit uses: verdict (what this means + what to do) -> per-source detail -> raw
# evidence collapsed behind <details>, so the page opens short rather than dumping rows.
# =============================================================================

function ConvertTo-HtmlSafe {
    # Device names, account names and inventory fields are user-supplied, and in the
    # password-spray case may be attacker-influenced - a machine named <script> must not
    # become one. Everything interpolated into the page goes through here.
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Get-ReportCss {
    # Prefer the shared stylesheet so every report in the toolkit looks like one family;
    # fall back to an inline copy so this script still renders standalone.
    $refPaths = @(
        (Join-Path $PSScriptRoot 'LockoutReference.psd1'),
        (Join-Path (Split-Path $PSScriptRoot -Parent) 'AD-LockoutDiagnostics\LockoutReference.psd1')
    )
    foreach ($p in $refPaths) {
        if (Test-Path -LiteralPath $p) {
            try {
                $ref = Import-PowerShellDataFile -LiteralPath $p -ErrorAction Stop
                if ($ref.ReportCss) { return $ref.ReportCss }
            } catch { }
        }
    }
    return $script:FallbackCss
}

function New-CaseReportHtml {
    <#
    .SYNOPSIS
        Renders the ranked causes as one self-contained HTML page.
    .DESCRIPTION
        Self-contained by design - no external stylesheet or script - because these get
        attached to tickets and opened on machines with no internet access, where a CDN
        reference would render the page unstyled.
    #>
    param(
        [object[]]$CauseRows,
        [string]$GeneratedOn,
        [int]$Window
    )

    $css = Get-ReportCss
    $sb  = New-Object System.Text.StringBuilder

    $null = $sb.AppendLine('<!DOCTYPE html>')
    $null = $sb.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    $null = $sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    $null = $sb.AppendLine('<title>Account Lockout - Likely Causes</title>')
    $null = $sb.AppendLine("<style>$css</style></head><body>")

    $windowText = if ($Window -gt 0) { "<span>Window $Window day(s)</span>" } else { '' }
    $null = $sb.AppendLine('<div class="top"><h1>Account Lockout &mdash; Likely Causes</h1>')
    $null = $sb.AppendLine(("<div class='facts'><span>Generated {0}</span>{1}</div></div>" -f (ConvertTo-HtmlSafe $GeneratedOn), $windowText))

    $rows = @($CauseRows)
    if ($rows.Count -eq 0) {
        $null = $sb.AppendLine('<div class="verdict ok"><div class="label">Result</div>')
        $null = $sb.AppendLine('<p class="line">No sources with authentication failures were found.</p>')
        $null = $sb.AppendLine('<p class="next">If that is unexpected, confirm failure auditing is enabled on the domain controllers &mdash; an empty report and a clean domain look identical. Run Test-ADAuditPolicy.ps1 before treating this as a clean result.</p></div>')
        $null = $sb.AppendLine('</body></html>')
        return $sb.ToString()
    }

    # One group per source; the first row of each is its highest-ranked cause.
    $bySource = $rows | Group-Object SourceKey | Sort-Object { [int]($_.Group[0].FailureCount) } -Descending

    # --- Verdict: the single most important finding, largest text on the page ---
    $top     = $bySource[0].Group[0]
    $topName = if ($top.ResolvedName) { $top.ResolvedName } else { $top.SourceKey }
    $null = $sb.AppendLine('<div class="verdict bad"><div class="label">Most likely cause</div>')
    $null = $sb.AppendLine(("<p class='line'>{0} &mdash; {1}</p>" -f (ConvertTo-HtmlSafe $topName), (ConvertTo-HtmlSafe $top.Cause)))
    $null = $sb.AppendLine(("<p class='next'>{0}</p>" -f (ConvertTo-HtmlSafe $top.Remediation)))
    $null = $sb.AppendLine('</div>')

    # --- One card per source, most failures first ---
    foreach ($grp in $bySource) {
        $first = $grp.Group[0]
        $name  = if ($first.ResolvedName) { $first.ResolvedName } else { '(unresolved)' }

        $null = $sb.AppendLine('<div class="card">')
        $null = $sb.AppendLine('<div class="card-head">')
        $null = $sb.AppendLine(("<span class='card-name'>{0}</span>" -f (ConvertTo-HtmlSafe $name)))
        $null = $sb.AppendLine(("<span class='card-meta'>{0}</span>" -f (ConvertTo-HtmlSafe $first.SourceKey)))
        $null = $sb.AppendLine(("<span class='card-count'>{0} <small>failures</small></span>" -f (ConvertTo-HtmlSafe $first.FailureCount)))
        $null = $sb.AppendLine('</div>')
        $null = $sb.AppendLine(("<p class='card-meta'>{0} &middot; {1} account(s): {2}</p>" -f (ConvertTo-HtmlSafe $first.DeviceClass), (ConvertTo-HtmlSafe $first.DistinctAccounts), (ConvertTo-HtmlSafe $first.Accounts)))

        $null = $sb.AppendLine('<table><tr><th>Confidence</th><th>Likely cause</th><th>What to do</th></tr>')
        foreach ($c in $grp.Group) {
            $null = $sb.AppendLine(("<tr><td><span class='pill {0}'>{0}</span></td><td>{1}<br><small class='card-meta'>{2}</small></td><td>{3}</td></tr>" -f (ConvertTo-HtmlSafe $c.Confidence), (ConvertTo-HtmlSafe $c.Cause), (ConvertTo-HtmlSafe $c.Evidence), (ConvertTo-HtmlSafe $c.Remediation)))
        }
        $null = $sb.AppendLine('</table></div>')
    }

    # --- Raw rows, collapsed so the page opens short ---
    $null = $sb.AppendLine('<details><summary>All rows</summary><div class="tablewrap"><table>')
    $null = $sb.AppendLine('<tr><th>Source</th><th>Name</th><th>Class</th><th>Failures</th><th>Accounts</th><th>Confidence</th><th>Cause</th></tr>')
    foreach ($r in $rows) {
        $null = $sb.AppendLine(("<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>" -f (ConvertTo-HtmlSafe $r.SourceKey), (ConvertTo-HtmlSafe $r.ResolvedName), (ConvertTo-HtmlSafe $r.DeviceClass), (ConvertTo-HtmlSafe $r.FailureCount), (ConvertTo-HtmlSafe $r.DistinctAccounts), (ConvertTo-HtmlSafe $r.Confidence), (ConvertTo-HtmlSafe $r.Cause)))
    }
    $null = $sb.AppendLine('</table></div></details>')

    $null = $sb.AppendLine('</body></html>')
    return $sb.ToString()
}

function Format-AccountList {
    <#
    .SYNOPSIS
        Renders an account list short enough to read in a one-line finding.
    .DESCRIPTION
        A source hitting many accounts is the most diagnostically valuable signal this
        toolkit produces - but pasting forty usernames into a sentence makes the summary
        unreadable, which is how the signal gets lost. Name the first few and count the
        rest, so the sentence stays scannable while the magnitude survives.
    #>
    param(
        [string]$Accounts,
        [int]$MaxNamed = 3
    )

    if ([string]::IsNullOrWhiteSpace($Accounts)) { return '(account unknown)' }

    $list = @($Accounts -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($list.Count -eq 0) { return '(account unknown)' }
    if ($list.Count -le $MaxNamed) { return ($list -join ', ') }

    $named = ($list | Select-Object -First $MaxNamed) -join ', '
    return "$named (+ $($list.Count - $MaxNamed) more)"
}

function Get-MultiAccountFinding {
    <#
    .SYNOPSIS
        Reports when one source is hitting enough accounts to change the diagnosis.
    .DESCRIPTION
        THE MULTI-USER CASE, and the reading most often missed.

        One device failing against many accounts is a categorically different problem from
        one device failing against one account, and Microsoft names exactly why it gets
        overlooked: in a password spray "from the vantage point of an individual user or
        company, the attack just looks like an isolated failed login."
        https://learn.microsoft.com/security/operations/incident-response-playbook-password-spray

        A per-account investigation therefore cannot see it - each user is opened as its
        own ticket and closed as its own mystery. Only a per-DEVICE view makes the pattern
        visible, which is what this export produces.

        CONTEXT DECIDES THE MEANING. A file server, terminal server or domain controller
        legitimately authenticates on behalf of many users, so the same count that is
        alarming from an unknown device is unremarkable from a known server. Calling that
        an attack sends the technician hunting an intruder inside their own file server.
    #>
    param(
        [Parameter(Mandatory)][int]$DistinctAccounts,
        [string]$DeviceClass = '',
        [string]$SourceKey = ''
    )

    # Two accounts is ordinary shared-workstation or shared-machine noise, not a pattern.
    if ($DistinctAccounts -lt 3) { return $null }

    # Infrastructure that authenticates for many users by design.
    if ($DeviceClass -in @('Server', 'DomainController')) {
        return New-Cause -Cause "Shared server or service authenticating for $DistinctAccounts accounts" `
            -Confidence 'Medium' `
            -Evidence "$SourceKey failed against $DistinctAccounts distinct accounts, but is a domain-joined server - servers authenticate for many users legitimately" `
            -Remediation "Look for one shared cause rather than $DistinctAccounts separate ones: a service or scheduled task on this server running as several accounts, a shared mapped drive in a login script, or an application pool holding stale credentials. Fixing the single stale configuration usually resolves every affected user at once."
    }

    if ($DeviceClass -eq 'NetworkDevice') {
        return New-Cause -Cause "Gateway carrying failures for $DistinctAccounts accounts" `
            -Confidence 'Medium' `
            -Evidence "$SourceKey failed against $DistinctAccounts distinct accounts and is network equipment, so it is aggregating traffic from many real devices" `
            -Remediation "The account count reflects everything behind this gateway, not one offender. Check the device's VPN/NAT session logs to attribute failures to real clients, and check any RADIUS or LDAP integration on it for a stale service credential - a single wrong password there fails for every user who authenticates through it."
    }

    # An unknown or non-domain device hitting many accounts is a security question first.
    $confidence = if ($DistinctAccounts -ge 10) { 'High' } else { 'Medium' }
    return New-Cause -Cause "One device failing against multiple accounts ($DistinctAccounts) - possible password spray" `
        -Confidence $confidence `
        -Evidence "$SourceKey failed against $DistinctAccounts distinct accounts and is not a known server" `
        -Remediation "Treat this as a security concern, not only a lockout: a single source failing against many accounts is the classic password-spray signature, and Microsoft notes it looks like an isolated failed login from any one user's perspective. Identify the device (switch MAC table, DHCP, VPN logs). If it is not a legitimate shared machine, isolate it and review it for compromise. If it IS legitimate, look for one shared stale credential rather than many separate ones."
}

function ConvertFrom-LogonTypeText {
    <#
    .SYNOPSIS
        Recovers numeric logon types from the human-readable text in an AuthSources CSV.
    .DESCRIPTION
        The CSV stores logon types as prose ("Network - mapped drive, file share, or
        service account connection"), joined with '; ' when a source produced several.

        Parsing this needs care. A naive substring search for 'Service' matches the
        phrase "service account connection" INSIDE the type 3 description, which made a
        mapped-drive source report "Windows service with a stale password" as its top
        cause with High confidence - a confidently wrong answer sending the technician to
        services.msc for a problem that lives in net use.

        Each entry is therefore split on '; ' and matched against the LEADING type name
        only - the text before the first ' - ' separator - so words appearing later in a
        description cannot be mistaken for a type.
    #>
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }

    # Leading name of each documented logon type description.
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625
    $byName = @{
        'interactive'       = 2
        'network'           = 3
        'batch'             = 4
        'service'           = 5
        'unlock'            = 7
        'networkcleartext'  = 8
        'newcredentials'    = 9
        'remoteinteractive' = 10
        'cachedinteractive' = 11
    }

    $found = @()
    foreach ($entry in ($Text -split ';')) {
        $name = (($entry -split ' - ')[0]).Trim().ToLowerInvariant()
        if ($byName.ContainsKey($name)) { $found += $byName[$name] }
    }

    return @($found | Select-Object -Unique)
}

function Get-LockoutCause {
    <#
    .SYNOPSIS
        Ranks the likely causes of the failures seen from one source.
    .DESCRIPTION
        Signals are evaluated strongest-first. LogonType outranks everything else because
        it describes the KIND of authentication the operating system performed, which
        narrows the cause list mechanically rather than by inference.
    #>
    param(
        [int[]]$LogonTypes = @(),
        [string]$DeviceClass = '',
        [string[]]$ProcessNames = @(),
        [int[]]$EventIds = @(),
        [string]$MacVendor = '',
        [int]$DistinctAccounts = 0,
        [string]$SourceKey = ''
    )

    $causes = New-Object System.Collections.Generic.List[object]
    $seen   = New-Object System.Collections.Generic.HashSet[string]

    function Add-Cause {
        param([object]$Cause)
        # Several signals routinely point at the same cause (logon type 4 and a
        # taskeng.exe process name both mean "scheduled task"). Emit it once.
        if ($seen.Add($Cause.Cause)) { $causes.Add($Cause) | Out-Null }
    }

    $types = @($LogonTypes | Where-Object { $_ } | Select-Object -Unique)

    # --- Breadth first: how many accounts is this one source hitting? ---------
    # Evaluated before logon type because it reframes everything else. "Stale mapped
    # drive" is a per-user fix; the same evidence from a device hitting thirty accounts
    # is one shared misconfiguration - or an attack - and the remediation differs.
    $multi = Get-MultiAccountFinding -DistinctAccounts $DistinctAccounts -DeviceClass $DeviceClass -SourceKey $SourceKey
    if ($multi) { Add-Cause $multi }

    # --- Logon type: the strongest signal ------------------------------------
    if ($types -contains 5) {
        Add-Cause (New-Cause -Cause 'Windows service running as this account with a stale password' `
            -Confidence 'High' `
            -Evidence 'Logon type 5 (Service) - the Service Control Manager authenticated using a saved password' `
            -Remediation 'On the source machine open services.msc, sort by "Log On As", and find services running as this account. Update the password on each service''s Log On tab. Microsoft: the SCM caches service account passwords and retries the old one until updated.')
    }

    if ($types -contains 4) {
        Add-Cause (New-Cause -Cause 'Scheduled task with expired credentials' `
            -Confidence 'High' `
            -Evidence 'Logon type 4 (Batch) - a scheduled process authenticated on the user''s behalf' `
            -Remediation 'On the source machine run: schtasks /query /fo LIST /v | findstr /i "<account>" - or open Task Scheduler and check the "Run As User" column. Update the stored password on any task running as this account.')
    }

    if ($types -contains 10 -or $types -contains 12) {
        Add-Cause (New-Cause -Cause 'Disconnected Remote Desktop / Terminal Server session' `
            -Confidence 'High' `
            -Evidence 'Logon type 10 (RemoteInteractive) - an RDP session, possibly disconnected but still running' `
            -Remediation 'On the source machine run: quser (or query session) to list sessions, then logoff <id> for any disconnected session belonging to this account. Microsoft: a disconnected session can keep running processes that authenticate with outdated credentials.')
    }

    if ($types -contains 3 -or $types -contains 8) {
        Add-Cause (New-Cause -Cause 'Mapped network drive or stored credential using an old password' `
            -Confidence 'High' `
            -Evidence 'Logon type 3 (Network) - access to a file share or network resource' `
            -Remediation 'On the source machine run: net use (list mapped drives) and cmdkey /list (list stored credentials). Disconnect and re-map any drive holding an old password; delete stale entries from Credential Manager. Microsoft recommends net use /persistent:no to prevent recurrence.')
    }

    if ($types -contains 2 -or $types -contains 7 -or $types -contains 11 -or $types -contains 13) {
        Add-Cause (New-Cause -Cause 'Cached credentials on a console session after a password change' `
            -Confidence 'Medium' `
            -Evidence 'Logon type 2/7/11 (Interactive, Unlock, or CachedInteractive) - activity at the machine itself' `
            -Remediation 'Have the user lock and unlock the workstation (Win+L) to refresh the cached credential. If it persists, sign out fully and back in. Microsoft notes Windows prompts for a lock/unlock automatically when it detects a changed password.')
    }

    if ($types -contains 9) {
        Add-Cause (New-Cause -Cause 'RunAs /netonly or an application supplying explicit alternate credentials' `
            -Confidence 'Medium' `
            -Evidence 'Logon type 9 (NewCredentials) - a process cloned its token with different credentials for outbound connections' `
            -Remediation 'Look for shortcuts or scripts using runas /netonly, and for applications configured with explicit alternate credentials. Check cmdkey /list on the source machine.')
    }

    # --- Process names: names a specific thing to open -----------------------
    foreach ($p in @($ProcessNames | Where-Object { $_ } | Select-Object -Unique)) {
        $leaf = ($p -split '\\')[-1]
        if ($script:UninformativeProcesses -contains $leaf.ToLowerInvariant()) { continue }

        $match = $null
        foreach ($k in $script:CredentialHoldingApps.Keys) {
            if ($leaf -ieq $k) { $match = $script:CredentialHoldingApps[$k]; break }
        }

        if ($match) {
            Add-Cause (New-Cause -Cause "Application holding a stale credential: $match" `
                -Confidence 'Medium' `
                -Evidence "Failed logons were submitted by $leaf" `
                -Remediation "On the source machine, check $leaf for a saved password for this account. Microsoft: many programs cache credentials or keep active threads holding the old password after a change.")
        } else {
            Add-Cause (New-Cause -Cause "Application holding a stale credential: $leaf" `
                -Confidence 'Low' `
                -Evidence "Failed logons were submitted by $leaf" `
                -Remediation "Identify what $leaf is on the source machine and whether it stores this account's password. Check cmdkey /list for a matching stored credential.")
        }
    }

    # --- Device class: shapes where to look, not what to fix ----------------
    switch ($DeviceClass) {
        'NetworkDevice' {
            $v = if ($MacVendor) { $MacVendor } else { 'network equipment' }
            Add-Cause (New-Cause -Cause "Source is a gateway ($v) - the real device is behind it" `
                -Confidence 'High' `
                -Evidence "The source address belongs to $v, which typically NATs traffic for many devices" `
                -Remediation "Do not chase this address as an endpoint. Check the $v device's own logs (VPN sessions, NAT translation table) for the client that held this session, or look for a RADIUS/LDAP integration on it configured with this account's old password.")
        }
        'NonDomainDevice' {
            Add-Cause (New-Cause -Cause 'Personal or mobile device with an old saved password' `
                -Confidence 'Medium' `
                -Evidence 'The source resolved to a name with no Active Directory computer object' `
                -Remediation 'Typically a phone or tablet with a stale mail profile, or a personal laptop with a saved Wi-Fi/VPN credential. Have the user update or remove the saved account on their mobile devices.')
        }
        'Unknown' {
            Add-Cause (New-Cause -Cause 'Unidentified device - not in AD, DHCP or DNS' `
                -Confidence 'Low' `
                -Evidence 'No name could be resolved for this source from any available directory' `
                -Remediation 'Cross-reference the address or MAC against switch MAC address tables, RMM/Intune inventory, VPN concentrator logs, or wireless controller client lists. An unmanaged device is also worth treating as a security question, not just a lockout one.')
        }
        'DomainController' {
            Add-Cause (New-Cause -Cause 'Authentication relayed through a domain controller' `
                -Confidence 'Low' `
                -Evidence 'The source is itself a domain controller' `
                -Remediation 'The DC is usually relaying on behalf of another client rather than originating the attempt. Check for services or scheduled tasks on the DC running as this account, then look upstream for the real origin.')
        }
    }

    # --- Event mix -----------------------------------------------------------
    $ids = @($EventIds | Where-Object { $_ } | Select-Object -Unique)
    if ($ids -contains 4776 -and -not ($ids -contains 4625) -and -not ($ids -contains 4771)) {
        Add-Cause (New-Cause -Cause 'Legacy NTLM authentication only' `
            -Confidence 'Medium' `
            -Evidence 'Only event 4776 (NTLM credential validation) fired - no Kerberos and no interactive logon failures' `
            -Remediation 'NTLM-only usually means an older client, a share accessed by IP address rather than name, an appliance, or a non-Windows device. Note that 4776 carries no IP address at all, so the source name is the only identifier available.')
    }

    if ($ids -contains 4771 -and -not ($ids -contains 4625)) {
        Add-Cause (New-Cause -Cause 'Kerberos-only source - no workstation name available' `
            -Confidence 'Low' `
            -Evidence 'Only event 4771 fired, which records an IP address but no workstation name or logon type' `
            -Remediation 'Resolve the address via DHCP lease, reverse DNS or switch MAC table. Microsoft notes Kerberos network logons frequently carry no workstation information, so the IP is genuinely all the DC recorded.')
    }

    # --- Never return nothing ------------------------------------------------
    if ($causes.Count -eq 0) {
        Add-Cause (New-Cause -Cause 'Insufficient evidence to suggest a cause' `
            -Confidence 'Low' `
            -Evidence 'No logon type, process name or device classification was available for this source' `
            -Remediation 'Confirm failure auditing is enabled on the DCs (Test-ADAuditPolicy.ps1) - missing logon types often mean the events were never fully recorded. Otherwise inspect the source machine directly: net use, cmdkey /list, schtasks /query, services.msc, and quser.')
    }

    # High first, then Medium, then Low. Stable within a rank, so the strongest signal
    # (logon type, added first) stays on top.
    $order = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2 }
    return @($causes | Sort-Object -Property @{ Expression = { $order[$_.Confidence] } }, @{ Expression = { $causes.IndexOf($_) } })
}

function Test-LockoutThresholdTooLow {
    <#
    .SYNOPSIS
        Reports whether the lockout threshold is itself causing false lockouts.
    .DESCRIPTION
        Microsoft calls a low Bad Password Threshold "one of the most common
        misconfiguration issues" and recommends leaving it at the default of 10, because
        a lower value is exhausted by ordinary retry noise from programs holding a stale
        password - producing lockouts that look like attacks but are not.

        A threshold of 0 means lockout is DISABLED, which is a different condition
        entirely and must not be reported as "too low".
        https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2003/cc773155(v=ws.10)
    #>
    param([Parameter(Mandatory)][int]$Threshold)

    if ($Threshold -eq 0) {
        return [PSCustomObject]@{
            IsTooLow = $false
            Message  = 'Account lockout is disabled (threshold 0) - accounts never lock out, so lockouts are not the issue here.'
        }
    }

    if ($Threshold -lt 10) {
        return [PSCustomObject]@{
            IsTooLow = $true
            Message  = "Lockout threshold is $Threshold. Microsoft recommends the default of 10; a lower value is exhausted by ordinary stale-credential retries, producing false lockouts. Consider raising it to 10."
        }
    }

    return [PSCustomObject]@{
        IsTooLow = $false
        Message  = "Lockout threshold is $Threshold, at or above the Microsoft-recommended default of 10."
    }
}

function Get-CauseSentence {
    <#
    .SYNOPSIS
        The one-line answer, written the way a technician would say it out loud.
    .DESCRIPTION
        Everything else this toolkit produces is supporting evidence for this sentence.
        It deliberately names the device rather than the address wherever a name exists,
        because a technician acts on a machine name.
    #>
    param(
        [Parameter(Mandatory)][string]$Account,
        [string]$DeviceName,
        [Parameter(Mandatory)][string]$SourceKey,
        [Parameter(Mandatory)][string]$TopCause,
        [int]$FailureCount
    )

    $where = if (-not [string]::IsNullOrWhiteSpace($DeviceName)) {
        if ($DeviceName -ieq $SourceKey) { $DeviceName } else { "$DeviceName ($SourceKey)" }
    } elseif ($SourceKey -eq '(not recorded)') {
        'an unidentified source (no address or name was recorded)'
    } else {
        $SourceKey
    }

    # "alice, bob, carol (+ 25 more)'s failed authentications" reads badly, so a list of
    # several accounts is phrased as a plural rather than forced into a possessive.
    $subject = if ($Account -match ',|\+ \d+ more') {
        "$FailureCount failed authentications for $Account"
    } else {
        "$Account's failed authentications ($FailureCount)"
    }

    "$subject came from $where - most likely cause: $TopCause"
}

if ($LoadFunctionsOnly) { return }

# =============================================================================
# Main - classify an existing export
# =============================================================================

if ([string]::IsNullOrWhiteSpace($SourcesCsv)) {
    Write-Host ''
    Write-Host 'Get-LockoutCause.ps1 - ranks likely lockout causes from collected evidence.' -ForegroundColor White
    Write-Host ''
    Write-Host 'Supply an AuthSources CSV produced by Export-ADAuthSourceEvidence.ps1:' -ForegroundColor Gray
    Write-Host '  .\Get-LockoutCause.ps1 -SourcesCsv .\Reports\AuthSources_<timestamp>.csv' -ForegroundColor Gray
    Write-Host ''
    Write-Host 'Or dot-source it to use the functions directly:' -ForegroundColor Gray
    Write-Host '  . .\Get-LockoutCause.ps1 -LoadFunctionsOnly' -ForegroundColor Gray
    Write-Host '  Get-LockoutCause -LogonTypes 5 -DeviceClass Server' -ForegroundColor Gray
    Write-Host ''
    return
}

if (-not (Test-Path -LiteralPath $SourcesCsv)) {
    Write-Host "[FAIL] Sources CSV not found: $SourcesCsv" -ForegroundColor Red
    exit 1
}

$rows = @(Import-Csv -LiteralPath $SourcesCsv)
if ($rows.Count -eq 0) {
    Write-Host "[WARN] No rows in $SourcesCsv" -ForegroundColor Yellow
    exit 0
}

Write-Host ''
Write-Host "LIKELY CAUSES - $($rows.Count) source(s) from $(Split-Path $SourcesCsv -Leaf)" -ForegroundColor White
Write-Host ('=' * 78) -ForegroundColor DarkGray

$analysis = foreach ($r in $rows) {

    $numericTypes = ConvertFrom-LogonTypeText -Text $r.LogonTypes

    $eventIds = @()
    if ($r.EventIds) { $eventIds = @($r.EventIds -split ',' | ForEach-Object { [int]($_.Trim()) }) }

    $distinct = 0
    if ($r.DistinctAccounts) { [void][int]::TryParse($r.DistinctAccounts, [ref]$distinct) }

    $causes = Get-LockoutCause -LogonTypes $numericTypes `
                               -DeviceClass $r.DeviceClass `
                               -ProcessNames @() `
                               -EventIds $eventIds `
                               -MacVendor $r.MacVendor `
                               -DistinctAccounts $distinct `
                               -SourceKey $r.SourceKey

    $sentence = Get-CauseSentence -Account (Format-AccountList -Accounts $r.Accounts) `
                                  -DeviceName $r.ResolvedName `
                                  -SourceKey $r.SourceKey `
                                  -TopCause $causes[0].Cause `
                                  -FailureCount ([int]$r.FailureCount)

    Write-Host ''
    Write-Host $sentence -ForegroundColor Cyan
    foreach ($c in $causes) {
        $color = @{ High = 'Green'; Medium = 'Yellow'; Low = 'DarkGray' }[$c.Confidence]
        Write-Host ("  [{0,-6}] {1}" -f $c.Confidence, $c.Cause) -ForegroundColor $color
        Write-Host ("           evidence: {0}" -f $c.Evidence) -ForegroundColor DarkGray
        Write-Host ("           fix     : {0}" -f $c.Remediation) -ForegroundColor Gray
    }

    foreach ($c in $causes) {
        [PSCustomObject]@{
            SourceKey    = $r.SourceKey
            ResolvedName = $r.ResolvedName
            DeviceClass  = $r.DeviceClass
            FailureCount = $r.FailureCount
            Accounts     = $r.Accounts
            Cause        = $c.Cause
            Confidence   = $c.Confidence
            Evidence     = $c.Evidence
            Remediation  = $c.Remediation
        }
    }
}

if ($OutputPath) {
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $out = Join-Path $OutputPath ("LockoutCauses_{0}.csv" -f $stamp)
    @($analysis) | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8
    Write-Host ''
    Write-Host "[PASS] Causes written to $out" -ForegroundColor Green

    # The HTML page is what gets attached to a ticket; the CSV is what gets pivoted.
    $htmlOut = Join-Path $OutputPath ("LockoutCauses_{0}.html" -f $stamp)
    try {
        $html = New-CaseReportHtml -CauseRows @($analysis) -GeneratedOn (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') -Window 0
        Set-Content -Path $htmlOut -Value $html -Encoding UTF8 -ErrorAction Stop
        Write-Host "[PASS] Report written to $htmlOut" -ForegroundColor Green
    } catch {
        Write-Host "[WARN] Could not write HTML report: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host ''
