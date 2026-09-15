#Requires -Version 5.1

<#
.SYNOPSIS
    Builds the single combined, tabbed HTML report a technician opens to read a drive-map
    investigation's findings.

.DESCRIPTION
    This is the REPORT for the drive-map diagnostics toolkit. Every earlier script in this
    toolkit COLLECTS or DECIDES; this one is the only one a technician actually opens, and it
    decides nothing new - it only renders what Invoke-DriveMapInvestigation.ps1 (Task 5) and
    Export-DriveMapEvidence.ps1 (Task 3) already produced, in a form that answers the
    investigation's five questions without scrolling or clicking to find the answer.

    THE FIVE QUESTIONS, IN TAB ORDER (design spec section 1):
      1. Can we trust this data?      - the readiness gate result and the evidence manifest's
                                         Collected/Empty/Failed breakdown.
      2. What should the user get?    - the GPO/domain-side intended state (Action, GPO audit).
      3. What do they actually have?  - the endpoint's live/persistent mount evidence.
      4. Who else is touching this letter? - logon-script deletions, scheduled tasks, Run keys,
                                         startup items that reference the drive letter.
      5. Why does it vanish?          - the ranked verdicts, most-confident first.

    THE THREE-STATE DISTINCTION MUST SURVIVE INTO THE HTML. Export-DriveMapEvidence.ps1's
    manifest sorts every collector into exactly one of Collected ('Found'), Empty
    ('EmptyButValid'), or Failed ('CouldNotCollect'). New-CollectionStateBadge is the single
    function responsible for keeping those three states visually distinct all the way to the
    rendered page - "we could not look" (CouldNotCollect) must never render as calmly as "we
    looked and found nothing" (EmptyButValid). Collapsing that distinction here would silently
    destroy the one thing every earlier script in this toolkit went out of its way to preserve.

    CONFIDENCE IS A VISIBLE TAG, NEVER A BURIED FIELD. Every verdict from
    Invoke-DriveMapInvestigation.ps1's Get-DriveMapVerdict carries a Confidence of 'High',
    'Medium', or 'Low'. This report renders it as a colored tag next to the cause on first
    paint - a guess must never be laid out so it reads as an established fact.

    A 'No cause identified' verdict renders as a real section (what was ruled out, and what
    to collect next), never as a blank page - Get-DriveMapVerdict already guarantees this
    verdict is never an empty array; this report's job is only to not discard that content.

    SECURITY: every interpolated value that can contain customer-environment text - UNC
    paths, logon-script lines, GPO names, event messages, failure reasons, verdict text -
    passes through ConvertTo-SafeHtml before it reaches the page. That function escapes '&'
    FIRST, then '<', '>', '"', so a literal '&lt;' in source text is never re-escaped into
    '&amp;lt;'.

    SELF-CONTAINED. No external stylesheet, font, script, or CDN reference - this file is
    attached to tickets and opened on machines with no internet access. Every style and
    script is inlined.

    VISUAL STYLE. Follows AD-GroupPolicy-DriveMaps\Audit-GPDriveMaps.ps1's existing report
    for component vocabulary (cards, badges, tables, metrics, back-to-top links) and
    AD-LockoutDiagnostics\New-LockoutCaseReport.ps1 for the tabbed-page chrome (a same-toolkit
    -family "Task 6" report already reviewed and shipped). Per this repository's CLAUDE.md
    design context, the page itself is DARK BY DEFAULT with the blue accent (#5dade2 range),
    with a light-mode toggle - Audit-GPDriveMaps.ps1's own report predates that design
    context and is light-only, so its literal palette is not copied; its component shapes and
    plain-English labeling are.

.PARAMETER CaseFolder
    The case folder produced by Invoke-DriveMapInvestigation.ps1 (or built by hand in the same
    shape): manifest.json, SUMMARY.txt, and optionally Verdicts.json. Defaults to the most
    recent DriveMapCase_* folder under a "Cases" folder beside this script.

.PARAMETER OutputPath
    Where to write the combined report. Defaults to the case folder itself.

.PARAMETER SkipBrowserOpen
    Do not open the generated report in the default browser after writing it.

.PARAMETER LoadFunctionsOnly
    Internal. Dot-sources the functions below without running the orchestration body, so
    Pester can test them directly. Must remain the last parameter.

.EXAMPLE
    .\New-DriveMapCaseReport.ps1 -CaseFolder 'D:\Cases\DriveMapCase_WKS042_X_2026-09-14_090000'

    Builds the combined report for that case folder and opens it in the default browser.

.EXAMPLE
    .\New-DriveMapCaseReport.ps1 -CaseFolder 'D:\Cases\...' -OutputPath 'D:\Cases\...' -SkipBrowserOpen

    Builds the report without opening a browser (used when this script is invoked as a child
    step by Invoke-DriveMapInvestigation.ps1).

.NOTES
    Files this script writes are UTF-8 WITH a byte-order mark, written via
    [System.IO.File]::WriteAllText with a UTF8Encoding(true) instance, because PowerShell 7's
    -Encoding UTF8 omits the BOM while Windows PowerShell 5.1's does not - the same approach
    used by every other script in this toolkit.

    Companion tools in this toolkit: Test-DriveMapLoggingReadiness.ps1,
    Export-DriveMapEvidence.ps1, Watch-DriveMapActivity.ps1, Invoke-DriveMapInvestigation.ps1.

    REFERENCES
      This script renders values already produced by Task 3 (Export-DriveMapEvidence.ps1) and
      Task 5 (Invoke-DriveMapInvestigation.ps1) rather than reading any new documented
      Microsoft fact of its own; it relies on those scripts' own verified citations
      (event IDs, registry paths, EnableLinkedConnections, NoBackgroundPolicy, etc. - see
      their own .NOTES REFERENCES blocks) rather than restating them here.
      HTML-encoding order (escape '&' before '<'/'>'/'"' to avoid double-escaping) follows the
      same convention documented in .NET's own encoder behavior:
        https://learn.microsoft.com/en-us/dotnet/api/system.net.webutility.htmlencode
#>
[CmdletBinding()]
param(
    [string]$CaseFolder,

    [string]$OutputPath,

    [switch]$SkipBrowserOpen,

    # Internal: dot-source the functions without running the orchestration body.
    [switch]$LoadFunctionsOnly
)

function Write-Status {
    param(
        [Parameter(Mandatory)][ValidateSet('PASS','WARN','FAIL','INFO')][string]$Level,
        [Parameter(Mandatory)][string]$Message
    )
    $color = @{ PASS='Green'; WARN='Yellow'; FAIL='Red'; INFO='Cyan' }[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

function ConvertTo-SafeHtml {
    <#
    .SYNOPSIS
        Escapes '&', '<', '>', '"' for safe interpolation into HTML text/attribute content.
    .DESCRIPTION
        Order matters: '&' MUST be replaced first. If '<' were escaped to '&lt;' before '&'
        were escaped, the '&' just introduced would itself be escaped on the next pass,
        turning '&lt;' into '&amp;lt;' (double-escaping). Escaping '&' first means the '&'
        introduced by the later replacements is never touched again.

        Every value in this report that can carry customer-environment text - UNC paths,
        logon-script lines, GPO names, event messages, verdict causes/evidence/remediation,
        collector failure reasons - must pass through this function before reaching the page.
    #>
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }
    $escaped = $Text.Replace('&', '&amp;')
    $escaped = $escaped.Replace('<', '&lt;')
    $escaped = $escaped.Replace('>', '&gt;')
    $escaped = $escaped.Replace('"', '&quot;')
    return $escaped
}

function New-ReportTab {
    <#
    .SYNOPSIS
        Wraps one section's content as a tab button + panel pair for the combined page.
    .DESCRIPTION
        $Index is 1-based and drives both the visible tab number and which tab starts active
        (index 1). $Content is trusted to already be safe HTML - this function does not
        escape it, because callers build $Content out of pieces that were each escaped at the
        point they were interpolated (see ConvertTo-SafeHtml). $Title IS escaped here, since
        titles are short plain-English labels defined by this script itself, not raw
        pass-through content - escaping it anyway costs nothing and keeps this function safe
        even if a future caller passes a dynamic title.
    #>
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
        [Parameter(Mandatory)][int]$Index
    )

    $id = "tab$Index"
    $activeClass = if ($Index -eq 1) { ' active' } else { '' }
    $safeTitle = ConvertTo-SafeHtml -Text $Title

    $button = "<button class='tab-btn{0}' role='tab' data-target='{1}' type='button'><span class='tab-num'>{2}</span>{3}</button>" -f `
        $activeClass, $id, $Index, $safeTitle
    $panel = "<section class='tab-panel{0}' id='{1}' role='tabpanel' data-label='{2}'>{3}</section>" -f `
        $activeClass, $id, $safeTitle, $Content

    return [PSCustomObject]@{ Button = $button; Panel = $panel }
}

function New-CollectionStateBadge {
    <#
    .SYNOPSIS
        Renders one of the toolkit's three collection states as a visually distinct HTML tag.
    .DESCRIPTION
        This function exists to enforce the single most important rendering requirement in
        this report: 'CouldNotCollect' must never look like a clean result. A technician
        scanning this report quickly must be able to tell "we looked and there was nothing"
        (EmptyButValid, a genuine finding) apart from "we could not look" (CouldNotCollect, an
        unknown that could still be hiding the real cause) without reading the label text -
        color and icon both differ - while the label text itself also says so explicitly, so
        the distinction does not depend on color alone (accessibility, printing in grayscale).
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('Found','EmptyButValid','CouldNotCollect')][string]$State
    )

    switch ($State) {
        'Found' {
            return "<span class='state-badge state-found' title='This was collected and has data.'><span class='state-icon' aria-hidden='true'>&#10003;</span>Found</span>"
        }
        'EmptyButValid' {
            return "<span class='state-badge state-empty' title='This was collected successfully - there was genuinely nothing there.'><span class='state-icon' aria-hidden='true'>&#8212;</span>Confirmed empty</span>"
        }
        'CouldNotCollect' {
            return "<span class='state-badge state-unknown' title='This could NOT be collected. Unknown - not a clean result. It may be hiding the actual cause.'><span class='state-icon' aria-hidden='true'>?</span>Could not look (unknown)</span>"
        }
    }
}

function Get-ConfidenceTagHtml {
    <#
    .SYNOPSIS
        Renders a verdict's Confidence as a visible, color-coded tag.
    .DESCRIPTION
        Confidence must never be a buried field the reader has to hunt for - a guess must
        never read as a fact. High renders as a strong/solid tag, Medium as a cautionary one,
        Low as a muted one, so the visual weight of the tag itself communicates how much to
        trust the cause next to it, even before the word is read.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Confidence)

    $cls = switch ($Confidence) {
        'High'   { 'confidence-high' }
        'Medium' { 'confidence-medium' }
        'Low'    { 'confidence-low' }
        default  { 'confidence-unknown' }
    }
    $label = if ([string]::IsNullOrWhiteSpace($Confidence)) { 'Unknown' } else { $Confidence }
    return "<span class='confidence-tag {0}'>Confidence: {1}</span>" -f $cls, (ConvertTo-SafeHtml -Text $label)
}

function Group-RepeatedEvidence {
    <#
    .SYNOPSIS
        Collapses near-identical evidence lines into one grouped finding with a count.
    .DESCRIPTION
        "This letter disappeared 14 times, all within 3 minutes of logon" is the finding;
        14 near-identical rows of evidence text is noise that buries it. This groups evidence
        strings by their exact text (case-sensitive - two lines differing only by drive
        letter or timestamp are legitimately different findings, and this function does not
        try to guess which differences are meaningful) and returns one row per distinct
        value, each carrying how many times it occurred, in first-seen order.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Items
    )

    $order = New-Object System.Collections.Generic.List[string]
    $counts = @{}
    foreach ($item in $Items) {
        $text = [string]$item
        if (-not $counts.ContainsKey($text)) {
            $counts[$text] = 0
            $order.Add($text)
        }
        $counts[$text]++
    }

    foreach ($text in $order) {
        [PSCustomObject]@{ Text = $text; Count = $counts[$text] }
    }
}

function New-VerdictSectionHtml {
    <#
    .SYNOPSIS
        Renders one verdict (Cause/Confidence/Evidence/Remediation) as a self-contained card.
    .DESCRIPTION
        Handles the 'No cause identified' verdict the same way as any other - Get-DriveMapVerdict
        (Task 5) already guarantees this is a real, populated verdict object (what was ruled
        out, what to collect next), never an empty result; this function's only job is not to
        special-case it into something thinner than every other verdict card. $Rank is 0 for
        the most-confident verdict (labeled MOST LIKELY CAUSE) and >0 for every other
        also-considered verdict, matching Get-DriveMapVerdict's most-confident-first order.
    #>
    param(
        [Parameter(Mandatory)][psobject]$Verdict,
        [Parameter(Mandatory)][int]$Rank,
        [Parameter(Mandatory)][string]$DriveLetter
    )

    $label = if ($Rank -eq 0) { 'MOST LIKELY CAUSE' } else { "Also considered ($($Rank + 1))" }
    $cardClass = if ($Rank -eq 0) { 'verdict-card verdict-primary' } else { 'verdict-card' }

    $evidenceGroups = @(Group-RepeatedEvidence -Items @($Verdict.Evidence))
    $evidenceHtml = if ($evidenceGroups.Count -eq 0) {
        "<p class='muted'>No supporting evidence was recorded for this cause.</p>"
    } else {
        $rows = foreach ($g in $evidenceGroups) {
            $countBadge = if ($g.Count -gt 1) { " <span class='repeat-count'>&times; $($g.Count)</span>" } else { '' }
            "<li>$(ConvertTo-SafeHtml -Text $g.Text)$countBadge</li>"
        }
        "<ul class='evidence-list'>$($rows -join '')</ul>"
    }

    $remediation = @($Verdict.Remediation)
    $remediationHtml = if ($remediation.Count -eq 0) {
        "<p class='muted'>No remediation steps were recorded.</p>"
    } else {
        $rows = $remediation | ForEach-Object { "<li>$(ConvertTo-SafeHtml -Text $_)</li>" }
        "<ol class='remediation-list'>$($rows -join '')</ol>"
    }

    @"
<div class='$cardClass'>
    <div class='verdict-head'>
        <span class='verdict-label'>$(ConvertTo-SafeHtml -Text $label)</span>
        $(Get-ConfidenceTagHtml -Confidence $Verdict.Confidence)
    </div>
    <p class='verdict-cause'>$(ConvertTo-SafeHtml -Text $Verdict.Cause)</p>
    <div class='verdict-body'>
        <div class='verdict-col'>
            <h4>Evidence</h4>
            $evidenceHtml
        </div>
        <div class='verdict-col'>
            <h4>What to do about it</h4>
            $remediationHtml
        </div>
    </div>
</div>
"@
}

function New-ManifestSectionHtml {
    <#
    .SYNOPSIS
        Renders the evidence manifest (Task 3's Collected/Empty/Failed breakdown) as the
        "Can we trust this data?" tab content.
    .DESCRIPTION
        $Manifest is the parsed manifest.json object (Collected/Empty/Failed arrays; Failed
        entries are {Collector; Reason} objects per Task 3). Every collector name appears
        exactly once, badged with its actual three-state result - this is where a
        CouldNotCollect collector must read as an unresolved unknown, never a clean pass.
    #>
    param(
        [AllowNull()][psobject]$Manifest
    )

    if ($null -eq $Manifest) {
        return "<div class='empty-state'><p>No evidence manifest was found for this case. Without it, this report cannot say which collectors ran, which found nothing, and which could not look at all - treat any verdict below with that in mind.</p></div>"
    }

    $collected = @($Manifest.Collected)
    $empty     = @($Manifest.Empty)
    $failed    = @($Manifest.Failed)

    $rows = New-Object System.Collections.Generic.List[string]
    foreach ($name in $collected) {
        $rows.Add("<tr><td>$(ConvertTo-SafeHtml -Text $name)</td><td>$(New-CollectionStateBadge -State 'Found')</td><td>&#8212;</td></tr>")
    }
    foreach ($name in $empty) {
        $rows.Add("<tr><td>$(ConvertTo-SafeHtml -Text $name)</td><td>$(New-CollectionStateBadge -State 'EmptyButValid')</td><td>&#8212;</td></tr>")
    }
    foreach ($f in $failed) {
        $collectorName = if ($f.PSObject.Properties['Collector']) { [string]$f.Collector } else { [string]$f }
        $reason = if ($f.PSObject.Properties['Reason']) { [string]$f.Reason } else { '' }
        $rows.Add("<tr class='row-unknown'><td>$(ConvertTo-SafeHtml -Text $collectorName)</td><td>$(New-CollectionStateBadge -State 'CouldNotCollect')</td><td>$(ConvertTo-SafeHtml -Text $reason)</td></tr>")
    }

    $tableHtml = if ($rows.Count -eq 0) {
        "<p class='muted'>The manifest listed no collectors.</p>"
    } else {
        "<div class='table-wrap'><table><thead><tr><th>Source</th><th>Result</th><th>Why (if unknown)</th></tr></thead><tbody>$($rows -join '')</tbody></table></div>"
    }

    $failedCallout = if ($failed.Count -gt 0) {
        "<div class='callout callout-warn'><strong>$($failed.Count) source$(if ($failed.Count -ne 1) { 's' }) could not be checked.</strong> Treat any verdict below as resting on incomplete evidence until these are resolved - an unknown is never the same as a clean result.</div>"
    } else {
        "<div class='callout callout-ok'>Every evidence source either returned data or was confirmed empty. No source was left unchecked.</div>"
    }

    @"
<p class='panel-intro'>Whether this investigation's evidence can be trusted starts here. A source that returned 'confirmed empty' genuinely found nothing; a source marked 'could not look' is an unknown that may be hiding the real cause - the two must never be read the same way.</p>
$failedCallout
<h3>Evidence sources ($($collected.Count + $empty.Count + $failed.Count) total)</h3>
$tableHtml
"@
}

function New-IntendedStateSectionHtml {
    <#
    .SYNOPSIS
        Renders the "What should the user get?" tab - the GPO/domain-side intended mapping.
    #>
    param(
        [string]$DriveLetter,
        [AllowNull()][string]$Action,
        [AllowNull()][string]$GpoAuditNote
    )

    $actionHtml = if ([string]::IsNullOrWhiteSpace($Action)) {
        "<p class='muted'>The intended Group Policy action (Create/Replace/Update/Delete) for ${DriveLetter}: was not established from the evidence collected for this case. Re-run Audit-GPDriveMaps.ps1 -TargetUser to fill this in.</p>"
    } else {
        "<div class='kv-row'><span class='kv-key'>Group Policy action</span><span class='kv-val'>$(ConvertTo-SafeHtml -Text $Action)</span></div>"
    }

    $noteHtml = if ([string]::IsNullOrWhiteSpace($GpoAuditNote)) { '' } else {
        "<p>$(ConvertTo-SafeHtml -Text $GpoAuditNote)</p>"
    }

    @"
<p class='panel-intro'>What Group Policy is actually configured to give this user for ${DriveLetter}: - the intended state, before comparing it against what the endpoint actually has.</p>
$actionHtml
$noteHtml
<p class='muted'>For full GPO precedence, conflicts, and item-level targeting detail, see Audit-GPDriveMaps.ps1's own report in this case folder.</p>
"@
}

function New-EndpointStateSectionHtml {
    <#
    .SYNOPSIS
        Renders the "What do they actually have?" tab - the endpoint's own mount evidence.
    #>
    param(
        [string]$DriveLetter,
        [AllowNull()][object]$DrivePresent,
        [AllowNull()][object]$InRegistry,
        [AllowNull()][object]$ElevatedVisible,
        [AllowNull()][object]$UnelevatedVisible
    )

    function Format-TriState {
        param([AllowNull()][object]$Value, [string]$TrueText, [string]$FalseText)
        if ($null -eq $Value) { return "<span class='state-badge state-unknown'><span class='state-icon' aria-hidden='true'>?</span>Not established</span>" }
        if ($Value -eq $true) { return "<span class='state-badge state-found'><span class='state-icon' aria-hidden='true'>&#10003;</span>$(ConvertTo-SafeHtml -Text $TrueText)</span>" }
        return "<span class='state-badge state-empty'><span class='state-icon' aria-hidden='true'>&#8212;</span>$(ConvertTo-SafeHtml -Text $FalseText)</span>"
    }

    @"
<p class='panel-intro'>What is actually true on the endpoint right now, independent of what Group Policy intends. A 'Not established' row is not the same as 'no' - it means this could not be checked in this run.</p>
<div class='kv-grid'>
    <div class='kv-row'><span class='kv-key'>${DriveLetter}: live right now</span><span class='kv-val'>$(Format-TriState -Value $DrivePresent -TrueText 'Present' -FalseText 'Absent')</span></div>
    <div class='kv-row'><span class='kv-key'>Registered to reconnect at logon (HKCU\Network)</span><span class='kv-val'>$(Format-TriState -Value $InRegistry -TrueText 'Registered' -FalseText 'Not registered')</span></div>
    <div class='kv-row'><span class='kv-key'>Visible in elevated session</span><span class='kv-val'>$(Format-TriState -Value $ElevatedVisible -TrueText 'Visible' -FalseText 'Not visible')</span></div>
    <div class='kv-row'><span class='kv-key'>Visible in standard (unelevated) session</span><span class='kv-val'>$(Format-TriState -Value $UnelevatedVisible -TrueText 'Visible' -FalseText 'Not visible')</span></div>
</div>
"@
}

function New-InterferenceSectionHtml {
    <#
    .SYNOPSIS
        Renders the "Who else is touching this letter?" tab - logon-script deletions,
        scheduled tasks, Run keys, and startup items that reference the drive letter.
    .DESCRIPTION
        Groups repeated script-deletion evidence rather than listing every occurrence, per
        the design requirement that 14 near-identical rows is noise and the grouped count is
        the finding.
    #>
    param(
        [string]$DriveLetter,
        [AllowNull()][object[]]$ScriptDeletions,
        [AllowNull()][object[]]$TargetingFailures
    )

    $deletionLines = @()
    if ($null -ne $ScriptDeletions) {
        $deletionLines = @($ScriptDeletions | ForEach-Object { "$($_.Source): $($_.Line)" })
    }

    $deletionsHtml = if ($null -eq $ScriptDeletions) {
        "<p class='muted'>Logon scripts, scheduled tasks, Run keys, and startup items were not searched for ${DriveLetter}: in this case (CouldNotCollect upstream) - this is an unknown, not a clean result.</p>"
    } elseif ($deletionLines.Count -eq 0) {
        "<p class='muted'>No script, task, or startup item referencing ${DriveLetter}: with a delete operation was found.</p>"
    } else {
        $groups = @(Group-RepeatedEvidence -Items $deletionLines)
        $rows = foreach ($g in $groups) {
            $countText = if ($g.Count -gt 1) { " <span class='repeat-count'>&times; $($g.Count)</span>" } else { '' }
            "<li>$(ConvertTo-SafeHtml -Text $g.Text)$countText</li>"
        }
        "<ul class='evidence-list evidence-danger'>$($rows -join '')</ul>"
    }

    $targetingHtml = if ($null -eq $TargetingFailures -or @($TargetingFailures).Count -eq 0) {
        ''
    } else {
        $rows = @($TargetingFailures) | ForEach-Object {
            $gpoText = if ($_.Gpo) { " (GPO: $(ConvertTo-SafeHtml -Text $_.Gpo))" } else { '' }
            "<li>Event $(ConvertTo-SafeHtml -Text ([string]$_.EventId))$gpoText</li>"
        }
        "<h4>Item-level targeting failures</h4><ul class='evidence-list'>$($rows -join '')</ul>"
    }

    @"
<p class='panel-intro'>Every other place that names ${DriveLetter}: - because a healthy Group Policy apply is not proof the drive stayed mapped. An unrelated logon script deleting a drive after Group Policy already mapped it is a documented Microsoft scenario, not a rare edge case.</p>
<h3>Script/task deletions referencing ${DriveLetter}:</h3>
$deletionsHtml
$targetingHtml
"@
}

function New-VerdictsSectionHtml {
    <#
    .SYNOPSIS
        Renders the "Why does it vanish?" tab - every ranked verdict, most-confident first.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Verdicts,
        [Parameter(Mandatory)][string]$DriveLetter
    )

    if ($Verdicts.Count -eq 0) {
        return "<div class='empty-state'><p>No verdict was produced for this case. This is a tooling gap, not a clean result - Get-DriveMapVerdict should always return at least a 'no cause identified' finding with next steps.</p></div>"
    }

    $cards = for ($i = 0; $i -lt $Verdicts.Count; $i++) {
        New-VerdictSectionHtml -Verdict $Verdicts[$i] -Rank $i -DriveLetter $DriveLetter
    }

    "<p class='panel-intro'>Every rule that matched the evidence, ranked most-confident first. More than one can be true at once - a machine can have more than one problem.</p>$($cards -join '')"
}

function ConvertTo-ReportSections {
    <#
    .SYNOPSIS
        Builds the tab-2/3/4 portion of New-DriveMapHtmlReport's -Sections hashtable from the
        flattened evidence object Invoke-DriveMapInvestigation.ps1 writes as Evidence.json.
    .DESCRIPTION
        Evidence.json holds the SAME object ConvertFrom-EvidenceBundle (in
        Invoke-DriveMapInvestigation.ps1) produced to build that case's verdicts - not
        recomputed here from the manifest/CSVs, so the three-state ($null = not established,
        never coerced to $false or to an empty array) handling that function is responsible
        for has exactly one implementation in this toolkit, with its own regression tests,
        rather than a second copy here that could silently drift from it.

        $Evidence may be $null (no Evidence.json was found for this case - an older case
        folder, or a bundle supplied by hand without one): every key below is then simply
        omitted from the returned hashtable, and New-DriveMapHtmlReport's tabs already render
        an absent key exactly like a $null value - their existing "not established" fallback
        text - so this is not a special case the caller needs to branch on.

        Every property is passed through EXACTLY as read: $null stays $null, and
        ScriptDeletions/TargetingFailures are only re-wrapped with @() to normalize
        PowerShell's single-item-vs-array unwrapping on the JSON read side, never to turn a
        $null (CouldNotCollect) reading into an empty (confirmed-nothing-found) array - those
        mean opposite things throughout this toolkit and this function must not be the place
        that collapses them.
    .PARAMETER Evidence
        The parsed Evidence.json object (or $null).
    #>
    param(
        [AllowNull()][psobject]$Evidence
    )

    $sections = @{}
    if ($null -eq $Evidence) { return $sections }

    $sections['Action']            = $Evidence.Action
    $sections['DrivePresent']      = $Evidence.DrivePresent
    $sections['InRegistry']        = $Evidence.InRegistry
    $sections['ElevatedVisible']   = $Evidence.ElevatedVisible
    $sections['UnelevatedVisible'] = $Evidence.UnelevatedVisible
    $sections['ScriptDeletions']   = if ($null -eq $Evidence.ScriptDeletions) { $null } else { @($Evidence.ScriptDeletions) }
    $sections['TargetingFailures'] = if ($null -eq $Evidence.TargetingFailures) { $null } else { @($Evidence.TargetingFailures) }
    # GpoAuditNote has no established source anywhere in this toolkit's evidence today -
    # deliberately left out of the hashtable (New-IntendedStateSectionHtml reads a missing
    # key as $null) rather than inventing placeholder text.

    $sections
}

function New-DriveMapHtmlReport {
    <#
    .SYNOPSIS
        Builds the complete, self-contained HTML case report.
    .DESCRIPTION
        Assembles the five tabs (Can we trust this data? / What should the user get? /
        What do they actually have? / Who else is touching this letter? / Why does it
        vanish?) in that fixed order, with the verdicts tab's headline finding visible on
        first paint (no scrolling, no click) via the page-top summary strip. Every value
        that can carry customer-environment text is escaped with ConvertTo-SafeHtml before
        being interpolated; verdict Cause/Evidence/Remediation are escaped inside
        New-VerdictSectionHtml, not here, since this function passes those objects through
        unmodified.
    .PARAMETER Verdicts
        Array of verdict objects (Cause; Confidence; Evidence; Remediation), already sorted
        most-confident first by Get-DriveMapVerdict. May be empty (an empty array here means
        no case data was supplied at all, not that Get-DriveMapVerdict itself returned
        nothing - that function is documented to never return an empty array).
    .PARAMETER Sections
        Hashtable of pre-built section context, all keys optional:
          Manifest            - parsed manifest.json (Collected/Empty/Failed) for tab 1.
          Action               - GPO-intended Drive Maps action (string) for tab 2.
          GpoAuditNote         - free-text note for tab 2.
          DrivePresent, InRegistry, ElevatedVisible, UnelevatedVisible - tri-state ($true/
                                  $false/$null) endpoint facts for tab 3.
          ScriptDeletions      - array of {Source; Line} (or $null if CouldNotCollect) for
                                  tab 4.
          TargetingFailures    - array of {EventId; Gpo} (or $null/empty) for tab 4.
    .PARAMETER DriveLetter
        The drive letter under investigation, shown throughout as data (never decoration).
    .PARAMETER Identity
        The user (SamAccountName) whose mapping is under investigation.
    .PARAMETER GeneratedOn
        Timestamp string (yyyy-MM-dd HH:mm:ss) shown in the report header.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Verdicts,
        [Parameter(Mandatory)][hashtable]$Sections,
        [Parameter(Mandatory)][string]$DriveLetter,
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][string]$GeneratedOn
    )

    $letter = $DriveLetter.Trim().TrimEnd(':').ToUpperInvariant()
    $safeLetter = ConvertTo-SafeHtml -Text $letter
    $safeIdentity = ConvertTo-SafeHtml -Text $Identity
    $safeGeneratedOn = ConvertTo-SafeHtml -Text $GeneratedOn

    $topVerdict = if ($Verdicts.Count -gt 0) { $Verdicts[0] } else { $null }

    # --- Build tab content -------------------------------------------------------------
    $tab1 = New-ManifestSectionHtml -Manifest $Sections['Manifest']
    $tab2 = New-IntendedStateSectionHtml -DriveLetter $letter -Action $Sections['Action'] -GpoAuditNote $Sections['GpoAuditNote']
    $tab3 = New-EndpointStateSectionHtml -DriveLetter $letter -DrivePresent $Sections['DrivePresent'] `
                -InRegistry $Sections['InRegistry'] -ElevatedVisible $Sections['ElevatedVisible'] `
                -UnelevatedVisible $Sections['UnelevatedVisible']
    $tab4 = New-InterferenceSectionHtml -DriveLetter $letter -ScriptDeletions $Sections['ScriptDeletions'] `
                -TargetingFailures $Sections['TargetingFailures']
    $tab5 = New-VerdictsSectionHtml -Verdicts $Verdicts -DriveLetter $letter

    $tabDefs = @(
        @{ Title = 'Can We Trust This Data'; Content = $tab1 }
        @{ Title = 'What Should The User Get'; Content = $tab2 }
        @{ Title = 'What Do They Actually Have'; Content = $tab3 }
        @{ Title = 'Who Else Is Touching This Letter'; Content = $tab4 }
        @{ Title = 'Why Does It Vanish'; Content = $tab5 }
    )

    $buttons = New-Object System.Collections.Generic.List[string]
    $panels  = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $tabDefs.Count; $i++) {
        $tab = New-ReportTab -Title $tabDefs[$i].Title -Content $tabDefs[$i].Content -Index ($i + 1)
        $buttons.Add($tab.Button)
        $panels.Add($tab.Panel)
    }

    # --- Findings-on-open summary strip: the headline verdict, visible without scrolling ---
    $summaryStripHtml = if ($null -eq $topVerdict) {
        "<div class='summary-strip summary-unknown'><span class='summary-kicker'>Verdict</span><span class='summary-line'>No verdict is available for this case.</span></div>"
    } else {
        "<div class='summary-strip'><span class='summary-kicker'>Most likely cause</span><span class='summary-line'>$(ConvertTo-SafeHtml -Text $topVerdict.Cause)</span>$(Get-ConfidenceTagHtml -Confidence $topVerdict.Confidence)</div>"
    }

    $css = Get-ReportCss

    $html = New-Object System.Text.StringBuilder
    $null = $html.AppendLine('<!DOCTYPE html>')
    $null = $html.AppendLine('<html lang="en">')
    $null = $html.AppendLine('<head>')
    $null = $html.AppendLine('<meta charset="utf-8">')
    $null = $html.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    $null = $html.AppendLine("<title>Drive Map Investigation - ${safeLetter}: - ${safeIdentity}</title>")
    $null = $html.AppendLine("<style>$css</style>")
    $null = $html.AppendLine('</head>')
    $null = $html.AppendLine('<body class="no-js">')
    $null = $html.AppendLine('<div class="shell">')

    $null = $html.AppendLine('<header class="masthead">')
    $null = $html.AppendLine('<div class="masthead-top">')
    $null = $html.AppendLine("<h1>Drive Map Investigation: ${safeLetter}: for ${safeIdentity}</h1>")
    $null = $html.AppendLine('<button id="theme-toggle" class="theme-toggle" type="button" title="Switch between dark and light">Light mode</button>')
    $null = $html.AppendLine('</div>')
    $null = $html.AppendLine("<div class='masthead-facts'><span>Drive letter: <strong>${safeLetter}:</strong></span><span>User: <strong>${safeIdentity}</strong></span><span>Generated: ${safeGeneratedOn}</span></div>")
    $null = $html.AppendLine('</header>')

    $null = $html.AppendLine($summaryStripHtml)

    $null = $html.AppendLine('<noscript><p class="ns">JavaScript is disabled, so every section is shown one after another instead of as tabs. Everything below is still complete.</p></noscript>')

    $null = $html.AppendLine('<div class="tabs" role="tablist">')
    $null = $html.AppendLine(($buttons -join "`n"))
    $null = $html.AppendLine('</div>')

    $null = $html.AppendLine(($panels -join "`n"))

    $null = $html.AppendLine((Get-ReportScript))
    $null = $html.AppendLine('</div>')
    $null = $html.AppendLine('</body>')
    $null = $html.AppendLine('</html>')

    return $html.ToString()
}

function Get-ReportCss {
    <#
    .SYNOPSIS
        The report's inlined stylesheet: dark by default (CLAUDE.md design context), blue
        accent in the #5dade2 range, with a light-mode toggle. Component vocabulary (cards,
        badges, tables, key/value rows) follows Audit-GPDriveMaps.ps1's existing report;
        tab chrome and the dark palette follow AD-LockoutDiagnostics\New-LockoutCaseReport.ps1,
        this toolkit family's own prior "Task 6" report.
    #>
    @'
:root {
    --bg: #15181c; --surface: #1d2126; --surface-2: #242931; --line: #333a44;
    --ink: #e8eaed; --ink-dim: #98a2b0; --ink-faint: #6d7885;
    --accent: #5dade2; --accent-ink: #0b2b3d;
    --bad: #e2686a; --warn: #e0a458; --ok: #5fc98a; --unknown: #9b7fd4;
}
:root[data-theme="light"] {
    --bg: #f4f6f8; --surface: #ffffff; --surface-2: #eef1f4; --line: #d7dde3;
    --ink: #1c2530; --ink-dim: #51606f; --ink-faint: #7c8894;
    --accent: #2f7dbf; --accent-ink: #ffffff;
    --bad: #c0392b; --warn: #9a6a1a; --ok: #237a4c; --unknown: #6a4fa0;
}
* { box-sizing: border-box; }
html, body { background: var(--bg); }
body {
    color: var(--ink); margin: 0; font-family: 'Segoe UI', system-ui, Tahoma, Geneva, sans-serif;
    line-height: 1.55; font-size: 14px;
}
.shell { max-width: 1180px; margin-inline: auto; padding: 0 clamp(16px,3vw,32px) 60px; }
h1 { font-size: 19px; margin: 0 0 6px; font-weight: 700; }
h2 { font-size: 18px; margin: 28px 0 12px; }
h3 { font-size: 15px; margin: 20px 0 10px; color: var(--ink-dim); }
h4 { font-size: 13px; margin: 14px 0 6px; color: var(--ink-dim); text-transform: uppercase; letter-spacing: .06em; }
p { margin: 0 0 10px; }
.muted { color: var(--ink-faint); }

.masthead { border-bottom: 1px solid var(--line); padding: 22px 0 14px; }
.masthead-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
.masthead-facts { color: var(--ink-faint); font-size: 12.5px; display: flex; flex-wrap: wrap; gap: 16px; margin-top: 4px; }
.masthead-facts strong { color: var(--ink); }

.theme-toggle {
    background: var(--surface-2); color: var(--ink); border: 1px solid var(--line);
    border-radius: 6px; padding: 7px 14px; font-size: 12.5px; font-weight: 600; cursor: pointer;
    transition: background .12s, border-color .12s, transform .05s;
}
.theme-toggle:hover { border-color: var(--accent); color: var(--accent); }
.theme-toggle:active { transform: translateY(1px); }

.summary-strip {
    display: flex; align-items: baseline; gap: 14px; flex-wrap: wrap;
    background: linear-gradient(90deg, rgba(93,173,226,.14), transparent 70%);
    border-left: 4px solid var(--accent); border-radius: 0 8px 8px 0;
    padding: 16px 20px; margin: 20px 0 22px;
}
.summary-strip.summary-unknown { border-left-color: var(--unknown); background: rgba(155,127,212,.10); }
.summary-kicker { font-size: 11px; letter-spacing: .14em; text-transform: uppercase; color: var(--ink-faint); }
.summary-line { font-size: 20px; font-weight: 700; color: var(--ink); }

.ns { background: rgba(224,164,88,.14); border: 1px solid var(--warn); color: var(--warn);
      padding: 12px 16px; border-radius: 8px; margin: 16px 0; font-size: 13.5px; }

.tabs {
    display: flex; flex-wrap: wrap; gap: 4px; border-bottom: 1px solid var(--line);
    margin-bottom: 22px; position: sticky; top: 0; background: var(--bg); z-index: 20;
    padding-top: 8px;
}
.tab-btn {
    background: none; border: none; border-bottom: 2px solid transparent; color: var(--ink-faint);
    font: inherit; font-size: 13px; font-weight: 600; padding: 10px 14px; cursor: pointer;
    white-space: nowrap; transition: color .12s, border-color .12s;
}
.tab-btn:hover { color: var(--ink); }
.tab-btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }
.tab-num { color: var(--ink-faint); font-weight: 400; margin-right: 6px; }
.tab-btn.active .tab-num { color: var(--accent); }

.tab-panel { display: none; }
.tab-panel.active { display: block; }
.panel-intro { color: var(--ink-dim); font-size: 14px; margin: 0 0 20px; padding-left: 14px;
               border-left: 3px solid var(--line); max-width: 78ch; }

.callout { border-radius: 8px; padding: 14px 18px; margin: 0 0 20px; font-size: 13.5px; }
.callout-warn { border: 1px solid var(--warn); background: rgba(224,164,88,.10); color: var(--ink); }
.callout-ok { border: 1px solid var(--ok); background: rgba(95,201,138,.10); color: var(--ink); }

.table-wrap { overflow-x: auto; margin: 10px 0 20px; border: 1px solid var(--line); border-radius: 8px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; background: var(--surface); }
th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--ink-faint); text-transform: uppercase; font-size: 11px; letter-spacing: .08em;
     background: var(--surface-2); position: sticky; top: 0; }
tr:last-child td { border-bottom: none; }
tr.row-unknown { background: rgba(155,127,212,.06); }

.state-badge {
    display: inline-flex; align-items: center; gap: 6px; padding: 3px 10px; border-radius: 999px;
    font-size: 12px; font-weight: 700; white-space: nowrap;
}
.state-icon { font-size: 11px; line-height: 1; }
.state-found   { background: rgba(95,201,138,.16); color: var(--ok); }
.state-empty   { background: rgba(152,162,176,.18); color: var(--ink-dim); }
.state-unknown { background: rgba(155,127,212,.20); color: var(--unknown); border: 1px dashed var(--unknown); }

.confidence-tag { display: inline-block; padding: 3px 12px; border-radius: 999px; font-size: 12px; font-weight: 700; }
.confidence-high     { background: rgba(226,104,106,.18); color: var(--bad); }
.confidence-medium   { background: rgba(224,164,88,.18); color: var(--warn); }
.confidence-low      { background: rgba(152,162,176,.18); color: var(--ink-dim); }
.confidence-unknown  { background: rgba(155,127,212,.18); color: var(--unknown); }

.kv-grid { background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 6px 4px; margin: 10px 0 20px; }
.kv-row { display: flex; align-items: center; justify-content: space-between; gap: 14px;
          padding: 10px 16px; border-bottom: 1px solid var(--line); flex-wrap: wrap; }
.kv-row:last-child { border-bottom: none; }
.kv-key { color: var(--ink-dim); font-size: 13px; }
.kv-val { font-weight: 600; }

.verdict-card { background: var(--surface); border: 1px solid var(--line); border-radius: 10px;
                padding: 20px 22px; margin: 0 0 18px; }
.verdict-primary { border-color: var(--accent); box-shadow: 0 0 0 1px rgba(93,173,226,.25); }
.verdict-head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 8px; }
.verdict-label { font-size: 11px; letter-spacing: .14em; text-transform: uppercase; color: var(--ink-faint); font-weight: 700; }
.verdict-cause { font-size: 18px; font-weight: 700; color: var(--ink); margin: 6px 0 14px; }
.verdict-body { display: grid; grid-template-columns: 1fr 1fr; gap: 22px; }
@media (max-width: 720px) { .verdict-body { grid-template-columns: 1fr; } }
.evidence-list, .remediation-list { margin: 0; padding-left: 20px; }
.evidence-list li, .remediation-list li { margin-bottom: 6px; font-size: 13.5px; }
.evidence-danger li { color: var(--bad); }
.repeat-count { color: var(--ink-faint); font-size: 12px; font-weight: 700; }

.empty-state { background: var(--surface); border: 1px dashed var(--line); border-radius: 8px;
               padding: 24px; color: var(--ink-dim); }

.no-js .tabs { display: none; }
.no-js .tab-panel { display: block; margin-bottom: 44px; }
@media print {
    .tabs, .theme-toggle { display: none; }
    .tab-panel { display: block !important; page-break-after: always; }
}
'@
}

function Get-ReportScript {
    <#
    .SYNOPSIS
        Inlined JavaScript: tab switching and the dark/light theme toggle. Progressive
        enhancement only - the 'no-js' body class (removed on load) means every panel and
        the tab strip already render correctly with script blocked or disabled.
    #>
    @'
<script>
(function () {
  document.body.classList.remove('no-js');
  var tabs = document.querySelectorAll('.tab-btn');
  var panels = document.querySelectorAll('.tab-panel');
  function show(id) {
    panels.forEach(function (p) { p.classList.toggle('active', p.id === id); });
    tabs.forEach(function (t) { t.classList.toggle('active', t.dataset.target === id); });
  }
  tabs.forEach(function (t) {
    t.addEventListener('click', function () { show(t.dataset.target); });
  });

  var toggle = document.getElementById('theme-toggle');
  if (toggle) {
    var root = document.documentElement;
    function applyTheme(theme) {
      if (theme === 'light') {
        root.setAttribute('data-theme', 'light');
        toggle.textContent = 'Dark mode';
      } else {
        root.removeAttribute('data-theme');
        toggle.textContent = 'Light mode';
      }
    }
    var saved = null;
    try { saved = window.localStorage.getItem('drivemap-report-theme'); } catch (e) { }
    applyTheme(saved === 'light' ? 'light' : 'dark');
    toggle.addEventListener('click', function () {
      var isLight = root.getAttribute('data-theme') === 'light';
      var next = isLight ? 'dark' : 'light';
      applyTheme(next);
      try { window.localStorage.setItem('drivemap-report-theme', next); } catch (e) { }
    });
  }
})();
</script>
'@
}

if ($LoadFunctionsOnly) { return }

# =============================================================================
# Orchestration
# =============================================================================

# Files must be UTF-8 WITH BOM on both PowerShell 5.1 and 7. PowerShell 7's -Encoding UTF8
# omits the BOM; Windows PowerShell 5.1's does not. Writing bytes directly with an explicit
# BOM makes behavior identical and deterministic on both (same approach as every other
# script in this toolkit).
$script:Utf8Bom = New-Object System.Text.UTF8Encoding($true)
function Write-Utf8BomFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, $script:Utf8Bom)
}

function Get-LatestCaseFolder {
    param([string]$ScriptRoot)
    $parent = Join-Path $ScriptRoot 'Cases'
    if (-not (Test-Path -LiteralPath $parent)) { return $null }
    return @(Get-ChildItem -LiteralPath $parent -Directory -Filter 'DriveMapCase_*' -ErrorAction SilentlyContinue |
             Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}

$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

if ([string]::IsNullOrWhiteSpace($CaseFolder)) {
    $CaseFolder = Get-LatestCaseFolder -ScriptRoot $scriptRoot
    if (-not $CaseFolder) {
        Write-Status FAIL 'No -CaseFolder supplied and no DriveMapCase_* folder found under .\Cases. Run Invoke-DriveMapInvestigation.ps1 first, or pass -CaseFolder.'
        exit 1
    }
    Write-Status INFO "Using most recent case folder: $CaseFolder"
}

if (-not (Test-Path -LiteralPath $CaseFolder)) {
    Write-Status FAIL "Case folder not found: $CaseFolder"
    exit 1
}

# ---------------------------------------------------------------------------
# Load the case's manifest.json (from the endpoint evidence bundle, if present in or under
# the case folder) and any verdicts recorded by Invoke-DriveMapInvestigation.ps1.
# ---------------------------------------------------------------------------
$manifest = $null
$manifestFile = Get-ChildItem -LiteralPath $CaseFolder -Filter 'manifest.json' -File -Recurse -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($manifestFile) {
    try {
        $manifest = Get-Content -LiteralPath $manifestFile.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
        Write-Status PASS "Loaded evidence manifest: $($manifestFile.FullName)"
    } catch {
        Write-Status WARN "Could not parse manifest.json: $($_.Exception.Message)"
    }
} else {
    Write-Status WARN 'No manifest.json found in the case folder - the trust tab will say so rather than guess.'
}

# Invoke-DriveMapInvestigation.ps1 does not currently persist verdicts as their own file
# (only SUMMARY.txt, plain text). If a machine-readable Verdicts.json is present (e.g. from
# a future orchestrator version, or supplied by hand), use it; otherwise render with no
# verdicts rather than parsing SUMMARY.txt's prose, which New-VerdictsSectionHtml already
# handles as a real "no verdict" section, not a blank page.
$verdicts = @()
$verdictsFile = Get-ChildItem -LiteralPath $CaseFolder -Filter 'Verdicts.json' -File -Recurse -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($verdictsFile) {
    try {
        $verdicts = @(Get-Content -LiteralPath $verdictsFile.FullName -Raw -ErrorAction Stop | ConvertFrom-Json)
        Write-Status PASS "Loaded verdicts: $($verdictsFile.FullName)"
    } catch {
        Write-Status WARN "Could not parse Verdicts.json: $($_.Exception.Message)"
    }
}

# Evidence.json (written by Invoke-DriveMapInvestigation.ps1 alongside Verdicts.json) is the
# SAME flattened evidence object ConvertFrom-EvidenceBundle produced to build those verdicts -
# not recomputed here from the manifest/CSVs, so the three-state ($null vs $false vs empty
# array) handling that function is responsible for has exactly one implementation in this
# toolkit. Older case folders (produced before this file existed, or a bundle supplied by
# hand without it) simply have no such file - $evidence stays $null and every tab-2/3/4 field
# below stays $null, which those tabs already render as their "not established" fallback
# text, not an error. This script must remain independently runnable against such a folder.
$evidence = $null
$evidenceFile = Get-ChildItem -LiteralPath $CaseFolder -Filter 'Evidence.json' -File -Recurse -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($evidenceFile) {
    try {
        $evidence = Get-Content -LiteralPath $evidenceFile.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
        Write-Status PASS "Loaded evidence: $($evidenceFile.FullName)"
    } catch {
        Write-Status WARN "Could not parse Evidence.json: $($_.Exception.Message)"
    }
}

# Best-effort drive letter / identity from the case folder name
# (DriveMapCase_<Computer>_<Letter>_<stamp>), falling back to '?' rather than throwing.
$driveLetter = '?'
$identity = '(not specified)'
$caseLeaf = Split-Path $CaseFolder -Leaf
if ($caseLeaf -match '^DriveMapCase_(?<computer>[^_]+)_(?<letter>[^_]+)_') {
    $driveLetter = $Matches['letter']
}
$summaryPath = Join-Path $CaseFolder 'SUMMARY.txt'
if (Test-Path -LiteralPath $summaryPath) {
    try {
        $summaryText = Get-Content -LiteralPath $summaryPath -Raw -ErrorAction Stop
        if ($summaryText -match 'User\s*:\s*(?<user>.+)') {
            $candidate = $Matches['user'].Trim()
            if ($candidate -and $candidate -ne '(not specified)') { $identity = $candidate }
        }
        if ($summaryText -match 'Drive letter\s*:\s*(?<letter>[A-Za-z]):?') {
            $driveLetter = $Matches['letter']
        }
    } catch { }
}

$sections = ConvertTo-ReportSections -Evidence $evidence
$sections['Manifest'] = $manifest

$generatedOn = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$reportHtml = New-DriveMapHtmlReport -Verdicts $verdicts -Sections $sections -DriveLetter $driveLetter `
                -Identity $identity -GeneratedOn $generatedOn

if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = $CaseFolder }
if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$outFile = Join-Path $OutputPath 'DriveMapInvestigationReport.html'
try {
    Write-Utf8BomFile -Path $outFile -Content $reportHtml
    Write-Status PASS "Case report written: $outFile"
} catch {
    Write-Status FAIL "Could not write the case report: $($_.Exception.Message)"
    exit 1
}

if (-not $SkipBrowserOpen) {
    try {
        Start-Process -FilePath $outFile -ErrorAction Stop
    } catch {
        Write-Status WARN "Could not open the report automatically: $($_.Exception.Message)"
    }
}

Write-Status PASS "Drive map case report complete: $outFile"
