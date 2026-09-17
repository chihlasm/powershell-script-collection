#Requires -Version 5.1

<#
.SYNOPSIS
    Combines every report in a case folder into one tabbed HTML page.
.DESCRIPTION
    A finished investigation produces five or six separate HTML reports plus a handful of
    CSVs. Sorting them into named subfolders helped, but it still left the same question:
    WHICH FILE DO I OPEN FIRST? This answers it by removing the choice - one file, opened
    once, with the findings already on screen and everything else a click away.

    It does NOT re-render the reports. Each tool already produces a good page; this lifts
    the <body> out of each one and composes them into a single document, so the individual
    reports keep working standalone and there is still exactly one place where each report
    is generated.

    ORDERING IS BY INVESTIGATION, NOT BY FILENAME. The tabs run in the order the questions
    should be asked - can we trust this data, who is locking out, why this account, which
    device, what to fix - because a technician reading top to bottom should be following
    the investigation rather than an alphabetical listing.

    The page is self-contained: styles inlined, no external scripts, no CDN references. It
    gets attached to tickets and opened on machines with no internet access, where an
    external stylesheet renders it unstyled. Tabs are progressive enhancement - with
    JavaScript blocked every section is still present and readable.
.PARAMETER CaseFolder
    The case folder to combine. Defaults to the most recent Case_* folder under the
    "Account Lockout Diagnostics" folder beside this script.
.PARAMETER OutputPath
    Where to write the combined page. Defaults to the case folder itself.
.PARAMETER PassThru
    Return the path of the written file.
.EXAMPLE
    .\New-LockoutCaseReport.ps1
    Combine the most recent case.
.EXAMPLE
    .\New-LockoutCaseReport.ps1 -CaseFolder 'D:\Cases\Case_jdoe_2026-08-20_143022'
.NOTES
    Read-only with respect to the source reports: they are read, never modified.

    Invoke-ADLockoutInvestigation.ps1 runs this automatically as its last step, so a
    normal investigation produces the combined page without a separate command.
#>
[CmdletBinding()]
param(
    [string]$CaseFolder,
    [string]$OutputPath,

    # The account the investigation focused on, highlighted throughout the combined page.
    # Optional: a domain-wide survey has no focus account and renders unchanged.
    [string]$Identity,
    [switch]$PassThru,
    [switch]$LoadFunctionsOnly
)

$ErrorActionPreference = 'Stop'

function Write-Status {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('PASS','WARN','FAIL','INFO')][string]$Level = 'INFO'
    )
    $color = @{ PASS='Green'; WARN='Yellow'; FAIL='Red'; INFO='Cyan' }[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

$script:FallbackCss = @'
  :root { --bg:#15181c; --surface:#1d2126; --surface-2:#242931; --line:#333a44;
          --ink:#e8eaed; --ink-dim:#98a2b0; --ink-faint:#6d7885;
          --accent:#5dade2; --bad:#e2686a; --warn:#e0a458; --ok:#5fc98a; }
  * { box-sizing:border-box; }
  body { background:var(--bg); color:var(--ink); margin:0;
         font-family:'Segoe UI',system-ui,sans-serif; line-height:1.55; }
  h2 { font-size:19px; margin:34px 0 14px; }
  h3 { font-size:15px; margin:22px 0 10px; color:var(--ink-dim); }
  .verdict { border-left:5px solid var(--ink-faint); padding:4px 0 4px 20px; margin-bottom:26px; }
  .verdict.bad { border-left-color:var(--bad); } .verdict.warn { border-left-color:var(--warn); }
  .verdict.ok { border-left-color:var(--ok); }
  .verdict .label { font-size:11px; letter-spacing:.16em; text-transform:uppercase; color:var(--ink-faint); }
  .verdict .line { font-size:25px; line-height:1.25; font-weight:600; margin:6px 0 10px; }
  .verdict .next { font-size:15px; color:var(--ink-dim); margin:0; max-width:68ch; }
  .stats { display:flex; flex-wrap:wrap; gap:26px; margin:22px 0 28px; }
  .stat .n { font-size:30px; font-weight:700; line-height:1; }
  .stat .n.bad { color:var(--bad); } .stat .n.ok { color:var(--ok); }
  .stat .k { font-size:12px; color:var(--ink-faint); text-transform:uppercase;
             letter-spacing:.09em; margin-top:5px; }
  .card { background:var(--surface); border:1px solid var(--line); border-radius:8px;
          padding:18px; margin-bottom:14px; }
  .card.bad { border-color:var(--bad); } .card.ok { border-color:var(--ok); }
  .card-head { display:flex; align-items:baseline; gap:10px; flex-wrap:wrap; }
  .card-name { font-size:17px; font-weight:650; color:#fff; word-break:break-all; }
  .card-count { margin-left:auto; font-size:22px; font-weight:700; }
  .card-count small { font-size:13px; color:var(--ink-faint); font-weight:400; }
  .card-meta { color:var(--ink-faint); font-size:12.5px; }
  .kv { display:grid; grid-template-columns:minmax(120px,auto) 1fr; gap:6px 18px; margin:12px 0 0; }
  .kv dt { color:var(--ink-faint); font-size:12.5px; }
  .kv dd { margin:0; font-size:13.5px; }
  .alert { border:1px solid var(--warn); background:rgba(224,164,88,.1); border-radius:8px;
           padding:14px 18px; margin:18px 0; }
  .alert.stop { border-color:var(--bad); background:rgba(226,104,106,.12); }
  .alert-title { font-weight:700; color:var(--warn); }
  .alert.stop .alert-title { color:var(--bad); }
  .tag { display:inline-block; padding:2px 9px; border-radius:999px; font-size:11px; font-weight:600; }
  .tag.bad { background:rgba(226,104,106,.16); color:var(--bad); }
  .tag.ok { background:rgba(95,201,138,.16); color:var(--ok); }
  .tag.warn { background:rgba(224,164,88,.16); color:var(--warn); }
  details { border-top:1px solid var(--line); margin-top:26px; padding-top:16px; }
  summary { cursor:pointer; font-size:12px; letter-spacing:.15em; text-transform:uppercase;
            color:var(--ink-faint); }
  .tablewrap { overflow-x:auto; margin-top:14px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--ink-faint); text-transform:uppercase; font-size:11px; letter-spacing:.1em; }
  td.bad { color:var(--bad); } td.ok { color:var(--ok); }
'@

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Get-HtmlBody {
    <#
    .SYNOPSIS
        Lifts the content of a page's <body> out of a complete HTML document.
    .DESCRIPTION
        Each tool emits a full standalone page with its own <head> and <style>. Nesting
        those inside another document would mean repeated <html> elements and five copies
        of the same stylesheet fighting each other, so only the body content is kept.

        A fragment with no <body> tag is returned unchanged rather than treated as empty -
        silently dropping a report would be worse than including it awkwardly.
    #>
    param([string]$Html)

    if ([string]::IsNullOrWhiteSpace($Html)) { return '' }

    # Singleline so . spans newlines; IgnoreCase because tag casing varies.
    $m = [regex]::Match($Html, '<body[^>]*>(.*?)</body>',
        [System.Text.RegularExpressions.RegexOptions]::Singleline -bor
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    if ($m.Success) { return $m.Groups[1].Value }
    return $Html
}

function Get-TabDefinition {
    <#
    .SYNOPSIS
        Maps a report filename to its tab label and position.
    .DESCRIPTION
        Labels are written for someone who did not run the tools. "ADLockoutForensics"
        is meaningless to a technician picking up a ticket; "Which DC Or Forest" is not.

        An unrecognized report is placed at the end rather than dropped, so a new tool
        added later still appears without anyone remembering to update this table.
    #>
    param([Parameter(Mandatory)][string]$FileName)

    $map = @(
        @{ Match = 'ADAuditPolicy';          Order = 1; Label = 'Can We Trust This Data'
           Blurb = 'Whether the domain controllers are actually recording the events these reports depend on.' }
        @{ Match = 'DCSecurityLogRetention'; Order = 1; Label = 'Can We Trust This Data'
           Blurb = 'How far back the Security logs really reach.' }
        @{ Match = 'ADLockoutHistory';       Order = 2; Label = 'Who Is Locking Out'
           Blurb = 'Every account that locked out in the window, ranked by how often.' }
        @{ Match = '^ADLockout_';            Order = 3; Label = 'Why This Account'
           Blurb = 'Timeline and bad-password sources for the account under investigation.' }
        @{ Match = 'ADLockoutForensics';     Order = 4; Label = 'Which DC Or Forest'
           Blurb = 'Per-DC bad-password counters - works even when auditing is disabled.' }
        @{ Match = 'AuthSources';            Order = 5; Label = 'Which Device'
           Blurb = 'The physical machine behind each source address.' }
        @{ Match = 'LockoutCauses';          Order = 6; Label = 'What To Fix'
           Blurb = 'Ranked likely causes with the specific remediation for each.' }
    )

    foreach ($rule in $map) {
        if ($FileName -match $rule.Match) {
            return [PSCustomObject]@{ Order = $rule.Order; Label = $rule.Label; Blurb = $rule.Blurb }
        }
    }

    # Unknown report: keep it, at the end, labelled from its own filename.
    $name = [System.IO.Path]::GetFileNameWithoutExtension($FileName) -replace '_\d{4}-\d{2}-\d{2}.*$', ''
    return [PSCustomObject]@{ Order = 99; Label = $name; Blurb = 'Additional report.' }
}

function Get-BaseCss {
    <#
    .SYNOPSIS
        Returns the shared report stylesheet that every tool's page is written against.
    .DESCRIPTION
        This must be the SAME stylesheet the individual reports use, not a summary of it.

        The first version of this combiner hand-wrote a small stylesheet covering only the
        classes it happened to notice - .verdict, .card, table. The reports also use
        .stats/.stat for the headline number tiles and .kv/dt/dd for key-value blocks, so
        those rendered as bare stacked text: "0 / Not logging / 4 / Logging / 1 / DCs
        checked" running down the page instead of a row of tiles.

        Reading the real stylesheet means a class added to any report cannot silently lose
        its styling here. The inline fallback exists only for the case where
        LockoutReference.psd1 is missing entirely.
    #>
    foreach ($p in @(
        (Join-Path $PSScriptRoot 'LockoutReference.psd1'),
        (Join-Path (Split-Path $PSScriptRoot -Parent) 'AD-LockoutDiagnostics\LockoutReference.psd1')
    )) {
        if (Test-Path -LiteralPath $p) {
            try {
                $ref = Import-PowerShellDataFile -LiteralPath $p -ErrorAction Stop
                if ($ref.ReportCss) { return $ref.ReportCss }
            } catch { }
        }
    }
    return $script:FallbackCss
}

function Get-TabCss {
    # Tab chrome only. Everything else comes from the shared report stylesheet, so these
    # selectors are deliberately namespaced to things the reports never use.
    return @'
  .shell { max-width:1180px; margin-inline:auto; padding:0 clamp(16px,3vw,32px) 60px; }
  .masthead { border-bottom:1px solid var(--line); padding:24px 0 16px; margin-bottom:0; }
  .masthead h1 { font-size:15px; font-weight:700; letter-spacing:.14em; text-transform:uppercase;
                 color:var(--ink-dim); margin:0 0 6px; }
  .masthead .facts { color:var(--ink-faint); font-size:12.5px; display:flex; flex-wrap:wrap; gap:16px; }
  .tabs { display:flex; flex-wrap:wrap; gap:4px; border-bottom:1px solid var(--line);
          margin-bottom:26px; position:sticky; top:0; background:var(--bg); z-index:20;
          padding-top:10px; }
  .tab { background:none; border:none; border-bottom:2px solid transparent; color:var(--ink-faint);
         font:inherit; font-size:13px; font-weight:600; padding:10px 14px; cursor:pointer;
         white-space:nowrap; transition:color .12s, border-color .12s; }
  .tab:hover { color:var(--ink); }
  .tab.active { color:var(--accent); border-bottom-color:var(--accent); }
  .tab .num { color:var(--ink-faint); font-weight:400; margin-right:6px; }
  .tab.active .num { color:var(--accent); }
  .panel { display:none; }
  .panel.active { display:block; }
  .panel-intro { color:var(--ink-dim); font-size:14px; margin:0 0 22px; padding-left:14px;
                 border-left:3px solid var(--line); max-width:76ch; }
  /* The source pages open with their own .top masthead. Inside a tab that duplicates the
     combined page's header, so it is suppressed - the tab label already says which
     report this is. */
  .panel .top { display:none; }
  /* The account under investigation. The domain-wide steps deliberately report on every
     account, so the focus account needs to be findable at a glance rather than by
     scanning. Accent-tinted rather than a yellow marker highlight: this is a wayfinding
     aid, not a warning, and yellow already means "caution" elsewhere in these reports. */
  .focusbar { display:flex; flex-wrap:wrap; align-items:baseline; gap:6px 14px;
              background:linear-gradient(90deg, rgba(93,173,226,.14), transparent 70%);
              border-left:3px solid var(--accent); border-radius:0 8px 8px 0;
              padding:12px 18px; margin:0 0 26px; font-size:14px; color:var(--ink); }
  .focusbar strong { color:var(--accent); font-size:15px; letter-spacing:.01em; }
  .focusbar-note { color:var(--ink-dim); font-size:12.5px; }
  .focus { background:rgba(93,173,226,.18); color:var(--accent); font-weight:600;
           border-radius:3px; padding:1px 5px; box-shadow:inset 0 0 0 1px rgba(93,173,226,.35); }
  @media print { .focus { background:none; box-shadow:none; text-decoration:underline; } }
  .summary-pre { background:var(--surface); border:1px solid var(--line); border-radius:8px;
                 padding:22px 24px; font-family:Consolas,'Cascadia Mono',monospace; font-size:12.5px;
                 line-height:1.65; white-space:pre-wrap; word-break:break-word; color:var(--ink);
                 margin:0; overflow-x:auto; }
  .src { color:var(--ink-faint); font-size:11.5px; margin-top:30px; padding-top:12px;
         border-top:1px solid var(--line); }
  .empty { color:var(--ink-dim); background:var(--surface); border:1px solid var(--line);
           border-radius:8px; padding:24px; }
  .ns { background:rgba(224,164,88,.14); border:1px solid var(--warn); color:var(--warn);
        padding:12px 16px; border-radius:8px; margin:16px 0; font-size:13.5px; }
  /* Without script every panel is shown, so the tab strip is meaningless. */
  .no-js .tabs { display:none; }
  .no-js .panel { display:block; margin-bottom:52px; }
  .no-js .panel .top { display:block; }
  @media print {
    .tabs { display:none; }
    .panel { display:block !important; page-break-after:always; }
    .panel .top { display:block; }
  }
'@
}

function Add-FocusHighlight {
    # Wraps occurrences of the investigated account in <span class="focus"> so the reader
    # can find their account in the domain-wide tables without scanning.
    #
    # Three constraints make this less trivial than a string replace:
    #
    #   1. Only match OUTSIDE tags. Rewriting text inside an attribute (href="/users/jdoe"
    #      or class="jdoe-row") would corrupt the markup. The split below alternates
    #      between markup and text, and only text segments are touched.
    #   2. Only match WHOLE account names. Highlighting 'jdoe' inside 'jdoe2' or
    #      'bjdoevic' points the technician at the wrong row, which is worse than no
    #      highlight. The boundary check allows a following '@' so a sAMAccountName still
    #      matches inside its UPN.
    #   3. Never throw on odd input. Account names legitimately contain dots and hyphens,
    #      which are regex metacharacters, so the name is escaped.
    param(
        [string]$Html,
        [string]$Identity
    )

    if ([string]::IsNullOrWhiteSpace($Html) -or [string]::IsNullOrWhiteSpace($Identity)) {
        return $Html
    }

    # An identity may arrive as a UPN or DN; highlight on the leading account name.
    $name = $Identity.Trim()
    if ($name -match '^(?<n>[^@\\]+)@') { $name = $Matches['n'] }
    elseif ($name -match '\\(?<n>[^\\]+)$') { $name = $Matches['n'] }
    if ([string]::IsNullOrWhiteSpace($name)) { return $Html }

    # (?<![\w.-]) / (?![\w-]) bound the match to a complete name. '@' is deliberately
    # absent from the trailing class so "jdoe" matches within "jdoe@contoso.com".
    $pattern = '(?<![\w.-])' + [regex]::Escape($name) + '(?![\w-])'
    $rx = [regex]::new($pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    # Split into markup and text runs; '<...>' segments keep their original form.
    $parts = [regex]::Split($Html, '(<[^>]*>)')
    $sb = [System.Text.StringBuilder]::new()
    foreach ($part in $parts) {
        if ($part -like '<*>') {
            $null = $sb.Append($part)
        } else {
            $null = $sb.Append($rx.Replace($part, { param($m) '<span class="focus">' + $m.Value + '</span>' }))
        }
    }
    return $sb.ToString()
}

function New-CombinedReport {
    <#
    .SYNOPSIS
        Composes the section bodies into one tabbed page.
    .DESCRIPTION
        Tabs are plain buttons over sections that are ALL present in the document. That
        matters: locked-down environments and some preview panes block script, and a
        tabbed page that shows nothing without JavaScript would be worse than the pile of
        files it replaced. Without script every section simply renders in order, and a
        <noscript> note says so.
    #>
    param(
        [object[]]$Sections,
        [string]$Summary,
        [string]$GeneratedOn,
        [string]$CaseName,
        [string]$Identity
    )

    $ordered = @($Sections | Sort-Object Order, Label)
    $sb = New-Object System.Text.StringBuilder

    # Shared report stylesheet FIRST, tab chrome layered on top.
    $css = (Get-BaseCss) + "`n" + (Get-TabCss)

    $null = $sb.AppendLine('<!DOCTYPE html>')
    $null = $sb.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    $null = $sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    $null = $sb.AppendLine(("<title>Lockout Investigation - {0}</title>" -f (ConvertTo-HtmlSafe $CaseName)))
    $null = $sb.AppendLine("<style>$css</style></head>")
    # no-js is removed by script on load, so the fallback layout is what renders when
    # script never runs.
    $null = $sb.AppendLine('<body class="no-js"><div class="shell">')

    $null = $sb.AppendLine('<div class="masthead"><h1>Account Lockout Investigation</h1>')
    $null = $sb.AppendLine(("<div class='facts'><span>{0}</span><span>Generated {1}</span></div></div>" -f `
        (ConvertTo-HtmlSafe $CaseName), (ConvertTo-HtmlSafe $GeneratedOn)))

    # Say plainly which account this is about, and that the surrounding tables are
    # deliberately domain-wide. Without this the reader sees other accounts in the
    # results and reasonably wonders whether the filter failed.
    if (-not [string]::IsNullOrWhiteSpace($Identity)) {
        $null = $sb.AppendLine(("<div class='focusbar'>Investigating <strong>{0}</strong><span class='focusbar-note'>Highlighted throughout. Other accounts appear because the domain-wide steps are what give this account's evidence meaning.</span></div>" -f `
            (ConvertTo-HtmlSafe $Identity)))
    }

    $null = $sb.AppendLine('<noscript><p class="ns">JavaScript is disabled, so all sections are shown one after another instead of as tabs. Everything is still here.</p></noscript>')

    # --- Build the tab list ---
    $tabs = New-Object System.Collections.Generic.List[object]
    if (-not [string]::IsNullOrWhiteSpace($Summary)) {
        $tabs.Add([PSCustomObject]@{ Id='findings'; Label='Findings'; Blurb='The answer, and what to do about it. Everything else is the evidence behind it.'; Body=''; Source='SUMMARY.txt'; IsSummary=$true })
    }
    $i = 0
    foreach ($s in $ordered) {
        $i++
        $tabs.Add([PSCustomObject]@{ Id="sec$i"; Label=$s.Label; Blurb=$s.Blurb; Body=$s.Body; Source=$s.Source; IsSummary=$false })
    }

    if ($tabs.Count -eq 0) {
        $null = $sb.AppendLine('<div class="empty">No reports were found in this case folder. If that is unexpected, check whether the investigation completed and whether auditing is enabled on the domain controllers.</div>')
        $null = $sb.AppendLine('</div></body></html>')
        return $sb.ToString()
    }

    $null = $sb.AppendLine('<div class="tabs" role="tablist">')
    $n = 0
    foreach ($t in $tabs) {
        $n++
        $active = if ($n -eq 1) { ' active' } else { '' }
        $null = $sb.AppendLine(("<button class='tab{0}' role='tab' data-target='{1}'><span class='num'>{2}</span>{3}</button>" -f `
            $active, $t.Id, $n, (ConvertTo-HtmlSafe $t.Label)))
    }
    $null = $sb.AppendLine('</div>')

    $n = 0
    foreach ($t in $tabs) {
        $n++
        $active = if ($n -eq 1) { ' active' } else { '' }
        $null = $sb.AppendLine(("<section class='panel{0}' id='{1}' data-label='{2}'>" -f `
            $active, $t.Id, (ConvertTo-HtmlSafe $t.Label)))

        if ($t.Blurb) {
            $null = $sb.AppendLine(("<p class='panel-intro'>{0}</p>" -f (ConvertTo-HtmlSafe $t.Blurb)))
        }

        if ($t.IsSummary) {
            # SUMMARY.txt is plain text - escaped and preformatted, never parsed as markup.
            $null = $sb.AppendLine(("<pre class='summary-pre'>{0}</pre>" -f (ConvertTo-HtmlSafe $Summary)))
        } else {
            $null = $sb.AppendLine((Add-FocusHighlight -Html $t.Body -Identity $Identity))
        }

        if ($t.Source) {
            $null = $sb.AppendLine(("<p class='src'>Source: {0}</p>" -f (ConvertTo-HtmlSafe $t.Source)))
        }
        $null = $sb.AppendLine('</section>')
    }

    $null = $sb.AppendLine(@'
<script>
(function () {
  document.body.classList.remove('no-js');
  var tabs = document.querySelectorAll('.tab');
  var panels = document.querySelectorAll('.panel');
  function show(id) {
    panels.forEach(function (p) { p.classList.toggle('active', p.id === id); });
    tabs.forEach(function (t) { t.classList.toggle('active', t.dataset.target === id); });
    if (history.replaceState) { history.replaceState(null, '', '#' + id); }
  }
  tabs.forEach(function (t) {
    t.addEventListener('click', function () { show(t.dataset.target); });
  });
  // Deep link support, so a specific tab can be sent to someone directly.
  if (location.hash) {
    var target = location.hash.slice(1);
    if (document.getElementById(target)) { show(target); }
  }
})();
</script>
'@)

    $null = $sb.AppendLine('</div></body></html>')
    return $sb.ToString()
}

function Get-LatestCaseFolder {
    # Most recent Case_* folder, so the common invocation needs no arguments.
    param([string]$ScriptRoot)

    $parent = Join-Path $ScriptRoot 'Account Lockout Diagnostics'
    if (-not (Test-Path -LiteralPath $parent)) { return $null }

    return @(Get-ChildItem -LiteralPath $parent -Directory -Filter 'Case_*' -ErrorAction SilentlyContinue |
             Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}

if ($LoadFunctionsOnly) { return }

# =============================================================================
# Main
# =============================================================================

$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

if ([string]::IsNullOrWhiteSpace($CaseFolder)) {
    $CaseFolder = Get-LatestCaseFolder -ScriptRoot $scriptRoot
    if (-not $CaseFolder) {
        Write-Status "No case folder found. Run Invoke-ADLockoutInvestigation.ps1 first, or pass -CaseFolder." 'FAIL'
        exit 1
    }
    Write-Status "Using most recent case: $(Split-Path $CaseFolder -Leaf)" 'INFO'
}

if (-not (Test-Path -LiteralPath $CaseFolder)) {
    Write-Status "Case folder not found: $CaseFolder" 'FAIL'
    exit 1
}

# Recurse, because reports live in the numbered subfolders.
$htmlFiles = @(Get-ChildItem -LiteralPath $CaseFolder -Filter '*.html' -File -Recurse -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -notlike 'Investigation*' })   # never re-absorb our own output

$sections = foreach ($f in $htmlFiles) {
    try {
        $raw  = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
        $body = Get-HtmlBody -Html $raw
        if ([string]::IsNullOrWhiteSpace($body)) {
            Write-Status "$($f.Name) contained no readable body - skipped" 'WARN'
            continue
        }
        $tab = Get-TabDefinition -FileName $f.Name
        [PSCustomObject]@{
            Order  = $tab.Order
            Label  = $tab.Label
            Blurb  = $tab.Blurb
            Body   = $body
            Source = $f.Name
        }
    } catch {
        Write-Status "Could not read $($f.Name): $($_.Exception.Message)" 'WARN'
    }
}

$summary = ''
$summaryPath = Join-Path $CaseFolder 'SUMMARY.txt'
if (Test-Path -LiteralPath $summaryPath) {
    try { $summary = Get-Content -LiteralPath $summaryPath -Raw -ErrorAction Stop } catch { }
}

$html = New-CombinedReport -Sections @($sections) `
                           -Summary $summary `
                           -GeneratedOn (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') `
                           -CaseName (Split-Path $CaseFolder -Leaf) `
                           -Identity $Identity

if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = $CaseFolder }
if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Named to sort first in the folder, so the file to open is the file at the top.
$outFile = Join-Path $OutputPath 'Investigation Report.html'
Set-Content -Path $outFile -Value $html -Encoding UTF8

Write-Host ''
Write-Status "Combined $(@($sections).Count) report(s) into one page" 'PASS'
Write-Status $outFile 'PASS'
Write-Host ''

if ($PassThru) { return $outFile }
