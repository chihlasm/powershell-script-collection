<#
.SYNOPSIS
    Runs the squad unattended, for example overnight.

.DESCRIPTION
    Starts Claude Code in non-interactive mode, shows a short live progress readout, and
    saves the full event log to squad/logs/.
    Default: a build run (/squad:run). To stop a build run gracefully, create an empty file
    named STOP in the squad folder; the squad finishes cleanly and writes its report.
    With -Pick: lists the items a run could build and asks which to build; the ready items
    they depend on are added automatically. -Items SQ-014,SQ-018 picks without asking, and
    -Feature "Problem management" picks every ready item of a feature.
    Without either, a pick saved by /squad:pick in the last 24 hours applies, else every
    ready item is built.
    With -Ideate: a thinker-squad session (/squad:ideate), optionally focused with -Focus.
    Needs the Squad plugin installed and at least one interactive Claude Code session in this
    repo since the last plugin update (that session refreshes the scripts this launcher uses).

.EXAMPLE
    .\squad\Start-SquadRun.ps1

.EXAMPLE
    .\squad\Start-SquadRun.ps1 -Pick

.EXAMPLE
    .\squad\Start-SquadRun.ps1 -Items SQ-014,SQ-018

.EXAMPLE
    .\squad\Start-SquadRun.ps1 -Feature "Problem management"

.EXAMPLE
    .\squad\Start-SquadRun.ps1 -MaxItems 2

.EXAMPLE
    .\squad\Start-SquadRun.ps1 -Ideate -Focus "Performance tool"
#>
param(
    [int]$MaxItems = 0,
    [switch]$Pick,
    [string[]]$Items = @(),
    [string[]]$Feature = @(),
    [switch]$Ideate,
    [string]$Focus = ''
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root

if (-not (Get-Command claude -ErrorAction SilentlyContinue)) {
    throw 'The Claude Code CLI (claude) is not on PATH. Install it, sign in once interactively, then try again.'
}

$logDir = Join-Path $root 'squad/logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$stamp = Get-Date -Format 'yyyy-MM-dd-HHmm'
$kind = 'run'
$prompt = '/squad:run'
if ($Ideate) {
    $kind = 'ideate'
    # Double quotes would be mangled on the command line by Windows PowerShell 5.1.
    $prompt = ('/squad:ideate {0}' -f ($Focus -replace '"', '')).Trim()
}
$log = Join-Path $logDir "$kind-$stamp.jsonl"

if ($MaxItems -gt 0) { $env:SQUAD_MAX_ITEMS = [string]$MaxItems }

# The plugin keeps a stable copy of its scripts; the SessionStart hook records where.
$scriptsDir = $null
$pointer = Join-Path $root 'squad/.state/plugin.json'
if (Test-Path -LiteralPath $pointer) {
    try { $scriptsDir = [string](Get-Content -Raw -LiteralPath $pointer | ConvertFrom-Json).scriptsDir } catch { }
}
if (-not $scriptsDir -or -not (Test-Path -LiteralPath (Join-Path $scriptsDir 'squad-lib.ps1'))) {
    $found = Get-ChildItem -Path (Join-Path $HOME '.claude/plugins/data') -Filter 'squad-lib.ps1' -Recurse -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($found) { $scriptsDir = $found.DirectoryName }
}
if (-not $scriptsDir) {
    throw 'Could not find the Squad plugin scripts. Open Claude Code in this repo once (with the plugin enabled), then try again.'
}
. (Join-Path $scriptsDir 'squad-lib.ps1')
$config = Get-SquadConfig $root

# Which items this run builds: -Items, -Pick, a pick saved by /squad:pick, or every ready item.
if (-not $Ideate) {
    if (-not (Get-Command Get-SquadPickLines -ErrorAction SilentlyContinue)) {
        if ($Pick -or $Items.Count -gt 0 -or $Feature.Count -gt 0) { throw 'This version of the Squad plugin cannot pick items. Update the plugin, open Claude Code in this repo once, then try again.' }
    }
    elseif ($Feature.Count -gt 0 -and -not (Get-Command Get-SquadFeatureItemIds -ErrorAction SilentlyContinue)) {
        throw 'This version of the Squad plugin cannot pick features. Update the plugin, open Claude Code in this repo once, then try again.'
    }
    else {
        $backlog = Get-SquadItems $root
        $chosen = @()
        foreach ($name in @($Feature | Where-Object { $_ })) {
            $ids = @(Get-SquadFeatureItemIds $backlog $name)
            if ($ids.Count -eq 0) { throw ('No ready item belongs to a feature called "{0}".' -f $name) }
            $chosen += $ids
        }
        if ($Items.Count -gt 0) {
            $named = @([regex]::Matches(($Items -join ' '), '(?i)SQ-\d+') | ForEach-Object { $_.Value.ToUpperInvariant() })
            if ($named.Count -eq 0) { throw 'Name items like -Items SQ-014,SQ-018.' }
            $chosen += $named
        }
        if ($chosen.Count -eq 0 -and $Pick) {
            $lines = @(Get-SquadPickLines $backlog)
            if ($lines.Count -eq 0) { Write-Host 'Nothing is ready to build. Run /squad:plan first.' -ForegroundColor Yellow; return }
            Write-Host ''
            Write-Host 'Items a run can build (ID | priority | title | needs):' -ForegroundColor Cyan
            for ($n = 0; $n -lt $lines.Count; $n++) { Write-Host ('{0,3}. {1}' -f ($n + 1), $lines[$n]) }
            $features = @()
            if (Get-Command Get-SquadFeatureStatus -ErrorAction SilentlyContinue) { $features = @(Get-SquadFeatureStatus $backlog | Where-Object { $_.Ready -gt 0 }) }
            if ($features.Count -gt 0) {
                Write-Host 'Whole features (type F1, F2, ... to pick every ready item of one):' -ForegroundColor Cyan
                for ($n = 0; $n -lt $features.Count; $n++) { Write-Host ('  F{0}. {1} ({2} of {3} done, {4} ready)' -f ($n + 1), $features[$n].Name, $features[$n].Done, $features[$n].Total, $features[$n].Ready) }
            }
            Write-Host 'Picking an item also picks the ready items it needs.'
            $answer = Read-Host 'Numbers, F-numbers or IDs to build, separated by commas (Enter = every ready item)'
            if (-not $answer.Trim()) { Remove-SquadSelection $root }
            foreach ($word in @($answer -split '[,\s]+' | Where-Object { $_ })) {
                if ($word -match '^\d+$' -and [int]$word -ge 1 -and [int]$word -le $lines.Count) { $chosen += ($lines[[int]$word - 1] -split ' ')[0] }
                elseif ($word -match '(?i)^F(\d+)$' -and [int]$Matches[1] -ge 1 -and [int]$Matches[1] -le $features.Count) { $chosen += @(Get-SquadFeatureItemIds $backlog $features[[int]$Matches[1] - 1].Name) }
                elseif ($word -match '(?i)^SQ-\d+$') { $chosen += $word.ToUpperInvariant() }
                else { throw ('"{0}" is not a number from the list or an item ID.' -f $word) }
            }
        }
        if ($chosen.Count -gt 0) {
            $picked = Set-SquadSelection $root $chosen $backlog
            foreach ($s in @($picked.Skipped)) { Write-Host ('Skipped: {0}.' -f $s) -ForegroundColor Yellow }
            if (@($picked.Items).Count -eq 0) { throw 'None of the picked items can be built; nothing was started.' }
            Write-Host ('This run builds: {0}' -f (@($picked.Items) -join ', ')) -ForegroundColor Cyan
            if (@($picked.Added).Count -gt 0) { Write-Host ('  (added because a picked item needs them: {0})' -f (@($picked.Added) -join ', ')) }
            if ($Pick) {
                $go = Read-Host 'Start the run? [Y/n]'
                if ($go -match '^(n|no)$') { Remove-SquadSelection $root; Write-Host 'Not started; the pick was discarded.'; return }
            }
        }
        elseif (-not $Pick) {
            $saved = Get-SquadSelection $root
            $fresh = $false
            if ($saved) { try { $fresh = ([DateTimeOffset]::Now - [DateTimeOffset]::Parse([string]$saved.createdAt)).TotalHours -lt 24 } catch { } }
            if ($fresh) { Write-Host ('Using the pick saved by /squad:pick: {0}' -f (@($saved.items) -join ', ')) -ForegroundColor Cyan }
        }
    }
}
$contextWindow = 200000
if ($config -and $config.contextWindowTokens) { $contextWindow = [int]$config.contextWindowTokens }
$script:leadContextTokens = 0
$script:lastMeterAt = [DateTime]::MinValue
$script:lastMeterKey = ''

# One-line meter: run progress, current item and step, lead agent's context, elapsed, ETA.
function Write-SquadMeter([switch]$Force) {
    $p = Get-SquadProgress $root
    if (-not $p.Active) { return }
    $key = '{0}|{1}|{2}' -f $p.Processed, $p.CurrentItem, $p.CurrentStep
    $due = ([DateTime]::Now - $script:lastMeterAt).TotalSeconds -ge 60
    if (-not $Force -and -not $due -and $key -eq $script:lastMeterKey) { return }
    $script:lastMeterAt = [DateTime]::Now
    $script:lastMeterKey = $key

    $dot = ' ' + [char]0x00B7 + ' '
    $parts = @(('{0} {1}/{2} items' -f (Get-SquadBar $p.Fraction), $p.Processed, $p.Target))
    if ($p.CurrentItem) { $parts += ('{0} {1}' -f $p.CurrentItem, $p.CurrentStep) }
    if ($script:leadContextTokens -gt 0) {
        $pct = 100.0 * $script:leadContextTokens / $contextWindow
        $parts += ('ctx {0} {1}%' -f (Get-SquadBar ($pct / 100) 6), [int][Math]::Round($pct))
    }
    $parts += (Format-SquadDuration $p.Elapsed)
    if ($p.Eta) {
        $etaText = Format-SquadDuration $p.Eta
        if ($etaText.StartsWith('<')) { $parts += ('ETA {0}' -f $etaText) } else { $parts += ('ETA ~{0}' -f $etaText) }
    }
    Write-Host ('[{0}] {1}' -f (Get-Date -Format 'HH:mm'), ($parts -join $dot)) -ForegroundColor Cyan
}

Write-Host ''
if ($Ideate) { Write-Host "Thinker squad session started at $(Get-Date -Format t)." -ForegroundColor Cyan }
else { Write-Host "Squad run started at $(Get-Date -Format t)." -ForegroundColor Cyan }
Write-Host "Full log: $log"
if (-not $Ideate) { Write-Host 'Stop gracefully any time: create an empty file named STOP in the squad folder.' }
Write-Host ''

# Native stderr must not become terminating errors under Windows PowerShell 5.1.
$ErrorActionPreference = 'Continue'

& claude -p $prompt --permission-mode auto --output-format stream-json --verbose | ForEach-Object {
    $line = [string]$_
    Add-Content -LiteralPath $log -Value $line -Encoding UTF8

    $evt = $null
    try { $evt = $line | ConvertFrom-Json } catch { return }
    if (-not $evt) { return }

    # Track the lead agent's context from its own messages (subagent messages carry a parent id).
    if ($evt.type -eq 'assistant' -and -not $evt.parent_tool_use_id -and $evt.message -and $evt.message.usage) {
        $u = $evt.message.usage
        $script:leadContextTokens = [int]$u.input_tokens + [int]$u.cache_creation_input_tokens + [int]$u.cache_read_input_tokens
    }
    Write-SquadMeter

    if ($evt.type -eq 'assistant' -and $evt.message -and $evt.message.content) {
        foreach ($block in @($evt.message.content)) {
            if ($block.type -eq 'text' -and $block.text) {
                $text = ([string]$block.text -replace '\s+', ' ').Trim()
                if ($text.Length -gt 160) { $text = $text.Substring(0, 157) + '...' }
                Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm'), $text) -ForegroundColor Gray
            }
            elseif ($block.type -eq 'tool_use' -and $block.name -eq 'Agent' -and $block.input) {
                $who = [string]$block.input.subagent_type
                if ($who) { Write-Host ("[{0}] -> {1}" -f (Get-Date -Format 'HH:mm'), $who) -ForegroundColor DarkCyan }
            }
        }
    }
    elseif ($evt.type -eq 'result') {
        Write-Host ''
        if ($evt.is_error) { Write-Host 'Session ended with an error.' -ForegroundColor Red }
        else { Write-Host 'Session finished.' -ForegroundColor Green }
        if ($evt.total_cost_usd) { Write-Host ('Cost: ${0:N2}' -f [double]$evt.total_cost_usd) }
        if ($evt.duration_ms) { Write-Host ('Duration: {0:N0} min' -f ([double]$evt.duration_ms / 60000)) }
    }
}

$ErrorActionPreference = 'Stop'
Remove-Item Env:\SQUAD_MAX_ITEMS -ErrorAction SilentlyContinue

if ($Ideate) {
    $report = Get-ChildItem -LiteralPath (Join-Path $root 'squad/ideas/sessions') -Filter 'brief.md' -Recurse -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $next = 'Next: open Claude Code and run /squad:pitch.'
}
else {
    $report = Get-ChildItem -LiteralPath (Join-Path $root 'squad/reports') -Filter '*.md' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $next = 'Next: open Claude Code and run /squad:review.'
}
if ($report) {
    Write-Host ''
    Write-Host "Report: $($report.FullName)" -ForegroundColor Cyan
    Write-Host $next
}
