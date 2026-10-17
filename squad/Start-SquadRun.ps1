<#
.SYNOPSIS
    Runs the squad unattended, for example overnight.

.DESCRIPTION
    Starts Claude Code in non-interactive mode, shows a short live progress readout, and
    saves the full event log to squad/logs/.
    Default: a build run (/squad:run). To stop a build run gracefully, create an empty file
    named STOP in the squad folder; the squad finishes cleanly and writes its report.
    With -Ideate: a thinker-squad session (/squad:ideate), optionally focused with -Focus.
    Needs the Squad plugin installed and at least one interactive Claude Code session in this
    repo since the last plugin update (that session refreshes the scripts this launcher uses).

.EXAMPLE
    .\squad\Start-SquadRun.ps1

.EXAMPLE
    .\squad\Start-SquadRun.ps1 -MaxItems 2

.EXAMPLE
    .\squad\Start-SquadRun.ps1 -Ideate -Focus "Performance tool"
#>
param(
    [int]$MaxItems = 0,
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
