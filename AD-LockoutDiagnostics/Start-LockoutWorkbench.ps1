#Requires -Version 5.1

<#
.SYNOPSIS
    Interactive front end for the lockout toolkit: scan first, then pick an account.

.DESCRIPTION
    The toolkit's problem was never what it collects - it was that you had to know the
    answer before you could ask the question. Invoke-ADLockoutInvestigation.ps1 wants an
    -Identity, but at the start of a ticket the account name is often exactly what you do
    not have. That meant running a survey, opening a report, finding a name, then
    retyping a longer command.

    This removes that loop:

      1. Scans the domain for recent lockouts (event 4740 on the PDC emulator).
      2. Shows the top accounts, ranked, with how often, when last, and from where.
      3. You pick a number.
      4. It asks whether an Entra Connect server is involved, and lets you skip.
      5. It runs the full investigation and opens the report.

    It is a WRAPPER. Every piece of collection and analysis is done by the existing
    scripts - this only handles discovery and the prompts. Nothing about the documented
    event semantics is reimplemented here, because a second copy would drift.

.PARAMETER DaysBack
    How far back to scan for lockouts. Default 7.

.PARAMETER Top
    How many accounts to list. Default 10.

.PARAMETER OutputPath
    Parent folder for case bundles. Passed straight through to the investigation.

.PARAMETER LoadFunctionsOnly
    Internal: dot-source the helpers without running the menu, for tests.

.EXAMPLE
    .\Start-LockoutWorkbench.ps1
    Scan the last 7 days and choose from the top 10 accounts.

.EXAMPLE
    .\Start-LockoutWorkbench.ps1 -DaysBack 1 -Top 20
    A tighter window during an active incident.

.NOTES
    Read-only. Requires RSAT ActiveDirectory and permission to read the PDC Security log.

    REFERENCES
      Event 4740 (account lockout) - the caller machine is in TargetDomainName:
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 365)]
    [int]$DaysBack = 7,

    [ValidateRange(1, 50)]
    [int]$Top = 10,

    [string]$OutputPath,

    [switch]$LoadFunctionsOnly
)

function Write-Status {
    param(
        [ValidateSet('PASS','WARN','FAIL','INFO','STEP')][string]$Level,
        [string]$Message
    )
    $color = @{ PASS='Green'; WARN='Yellow'; FAIL='Red'; INFO='Cyan'; STEP='White' }[$Level]
    if ($Level -eq 'STEP') {
        Write-Host ''
        Write-Host $Message -ForegroundColor White
        Write-Host ('-' * $Message.Length) -ForegroundColor DarkGray
    } else {
        Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
    }
}

function Get-RankedAccounts {
    # Groups raw 4740 rows into one entry per account, ranked by how often it locked.
    # Pure - the caller supplies the events - so ranking is testable without a domain.
    param(
        [object[]]$Events,
        [int]$Top = 10
    )

    $rows = @($Events | Where-Object { $_ -and -not [string]::IsNullOrWhiteSpace($_.User) })
    if ($rows.Count -eq 0) { return @() }

    $ranked = $rows | Group-Object User | ForEach-Object {
        $sources = @($_.Group |
                     Select-Object -ExpandProperty CallerComputer -ErrorAction SilentlyContinue |
                     Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                     Select-Object -Unique)
        [PSCustomObject]@{
            User        = $_.Name
            Lockouts    = $_.Count
            LastLockout = @($_.Group.Time | Sort-Object -Descending)[0]
            Sources     = $sources
            LockedNow   = $false
        }
    }

    return @($ranked | Sort-Object Lockouts, LastLockout -Descending | Select-Object -First $Top)
}

function Format-AccountChoice {
    # One menu row. Density matters here - a technician scanning ten rows needs count,
    # recency and source without reading sentences.
    param(
        [int]$Index,
        [object]$Account
    )

    $when = if ($Account.LastLockout) {
        $span = (Get-Date) - $Account.LastLockout
        if ($span.TotalMinutes -lt 60)   { "{0,3} min ago" -f [int]$span.TotalMinutes }
        elseif ($span.TotalHours -lt 24) { "{0,3} hr ago"  -f [int]$span.TotalHours }
        else                             { "{0,3} days ago" -f [int]$span.TotalDays }
    } else { 'unknown' }

    $src = @($Account.Sources)
    $where = if ($src.Count -eq 0)      { 'no source recorded' }
             elseif ($src.Count -eq 1)  { $src[0] }
             elseif ($src.Count -le 3)  { $src -join ', ' }
             else                       { "$($src.Count) different sources" }

    $flag = if ($Account.LockedNow) { '  << LOCKED NOW' } else { '' }

    return ("  [{0,2}]  {1,-24} {2,3} lockouts   {3,-13} {4}{5}" -f `
            $Index, $Account.User, $Account.Lockouts, $when, $where, $flag)
}

function Read-MenuChoice {
    # Parses one line of menu input. Kept pure so the loop's behaviour is testable.
    param(
        [string]$InputText,
        [int]$Max
    )

    $t = ([string]$InputText).Trim()
    if ([string]::IsNullOrWhiteSpace($t)) {
        return [PSCustomObject]@{ Kind='None'; Index=0; Identity='' }
    }
    if ($t -in @('q','Q','quit','exit')) {
        return [PSCustomObject]@{ Kind='Quit'; Index=0; Identity='' }
    }
    if ($t -in @('r','R','rescan','refresh')) {
        return [PSCustomObject]@{ Kind='Rescan'; Index=0; Identity='' }
    }
    if ($t -match '^\d+$') {
        $n = [int]$t
        if ($n -ge 1 -and $n -le $Max) {
            return [PSCustomObject]@{ Kind='Account'; Index=$n; Identity='' }
        }
        return [PSCustomObject]@{ Kind='Invalid'; Index=0; Identity='' }
    }
    # Anything else is taken as an account name typed directly - a technician who already
    # knows who is locking out should not have to hunt for them in the list.
    return [PSCustomObject]@{ Kind='Account'; Index=0; Identity=$t }
}

function Resolve-EntraConnectChoice {
    # Interprets the answer to "which Entra Connect server?". Skipping must be effortless:
    # most techs will not know, and a wrong name is worse than none - it would query an
    # unrelated machine and report its silence as a healthy sync.
    param([string]$InputText)

    $t = ([string]$InputText).Trim()
    if ([string]::IsNullOrWhiteSpace($t) -or $t -in @('n','N','no','No','skip','Skip')) {
        return [PSCustomObject]@{ Server=''; Skipped=$true }
    }
    return [PSCustomObject]@{ Server=$t; Skipped=$false }
}

function Get-RecentLockoutEvents {
    # The only domain-facing function here. Reads 4740 from the PDC emulator, which
    # receives lockout events domain-wide.
    param([int]$DaysBack)

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        Write-Status FAIL "The ActiveDirectory module is not available: $($_.Exception.Message)"
        return $null
    }

    try {
        $pdc = (Get-ADDomain -ErrorAction Stop).PDCEmulator
    } catch {
        Write-Status FAIL "Could not determine the PDC emulator: $($_.Exception.Message)"
        return $null
    }

    Write-Status INFO "Scanning $pdc for lockouts in the last $DaysBack day(s)..."

    try {
        $raw = @(Get-WinEvent -ComputerName $pdc -FilterHashtable @{
                    LogName   = 'Security'
                    Id        = 4740
                    StartTime = (Get-Date).AddDays(-$DaysBack)
                 } -ErrorAction Stop)
    } catch {
        if ($_.Exception.Message -match 'No events were found') {
            return @()
        }
        Write-Status FAIL "Could not read the Security log on ${pdc}: $($_.Exception.Message)"
        return $null
    }

    # Reuse ConvertFrom-LockoutEvent from Get-ADLockoutHistory.ps1 rather than parsing
    # the 4740 XML again here. That function encodes a documented fact that is easy to
    # get wrong - the caller machine is in TargetDomainName, and there is no
    # CallerComputerName element despite Event Viewer's label - and it carries the
    # regression test that pins it. A second copy here would be a second place for that
    # to drift, which is exactly how the original bug survived so long.
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740
    if (-not (Get-Command ConvertFrom-LockoutEvent -ErrorAction SilentlyContinue)) {
        $historyScript = Join-Path $PSScriptRoot 'Get-ADLockoutHistory.ps1'
        if (-not (Test-Path -LiteralPath $historyScript)) {
            Write-Status FAIL "Get-ADLockoutHistory.ps1 was not found beside this script; it supplies the 4740 parser."
            return $null
        }
        . $historyScript -LoadFunctionsOnly
    }

    return @($raw | ForEach-Object {
        ConvertFrom-LockoutEvent -EventXml $_.ToXml() -DcName $pdc
    })
}

function Add-LockedNowFlag {
    # An account locked at this moment is someone waiting on you; one that locked three
    # times last week is a pattern. The menu should distinguish them.
    param([object[]]$Accounts)

    foreach ($a in $Accounts) {
        try {
            $u = Get-ADUser -Identity $a.User -Properties LockedOut -ErrorAction Stop
            $a.LockedNow = [bool]$u.LockedOut
        } catch {
            # Account may be in another domain or already renamed; not fatal.
            $a.LockedNow = $false
        }
    }
    return $Accounts
}

if ($LoadFunctionsOnly) { return }

# =============================================================================
# Main
# =============================================================================

$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$investigation = Join-Path $scriptRoot 'Invoke-ADLockoutInvestigation.ps1'

if (-not (Test-Path -LiteralPath $investigation)) {
    Write-Status FAIL "Invoke-ADLockoutInvestigation.ps1 was not found beside this script. The workbench drives it and cannot run without it."
    return
}

Write-Host ''
Write-Host '  ACCOUNT LOCKOUT WORKBENCH' -ForegroundColor White
Write-Host '  Scan the domain, pick an account, run the full investigation.' -ForegroundColor DarkGray

$accounts = @()
$rescan = $true

while ($true) {

    if ($rescan) {
        $rescan = $false
        Write-Status STEP "Scanning for lockouts (last $DaysBack day(s))"
        $events = Get-RecentLockoutEvents -DaysBack $DaysBack

        if ($null -eq $events) {
            Write-Host ''
            Write-Status WARN 'The scan could not run. You can still investigate an account by name.'
            $accounts = @()
        }
        elseif ($events.Count -eq 0) {
            Write-Host ''
            Write-Status INFO "No account lockouts were recorded on the PDC in the last $DaysBack day(s)."
            Write-Host ''
            Write-Host '  That means one of two things, and they are not the same:' -ForegroundColor DarkGray
            Write-Host '    - nothing is locking out, or' -ForegroundColor DarkGray
            Write-Host '    - lockout auditing is off, so nothing is being recorded.' -ForegroundColor DarkGray
            Write-Host '  Running an investigation will check auditing first and tell you which.' -ForegroundColor DarkGray
            $accounts = @()
        }
        else {
            $accounts = @(Get-RankedAccounts -Events $events -Top $Top)
            $accounts = @(Add-LockedNowFlag -Accounts $accounts)
            Write-Status PASS "$($events.Count) lockout event(s) across $($accounts.Count) account(s)."
        }
    }

    Write-Host ''
    if ($accounts.Count -gt 0) {
        Write-Host "  Accounts locking out (last $DaysBack day(s))" -ForegroundColor White
        Write-Host ''
        for ($i = 0; $i -lt $accounts.Count; $i++) {
            $line = Format-AccountChoice -Index ($i + 1) -Account $accounts[$i]
            if ($accounts[$i].LockedNow) {
                Write-Host $line -ForegroundColor Yellow
            } else {
                Write-Host $line
            }
        }
    }

    Write-Host ''
    Write-Host '  Enter a number, or type an account name.  [R] rescan   [Q] quit' -ForegroundColor DarkGray
    $answer = Read-Host '  Choice'
    $choice = Read-MenuChoice -InputText $answer -Max $accounts.Count

    switch ($choice.Kind) {
        'Quit'    { Write-Host ''; return }
        'Rescan'  { $rescan = $true; continue }
        'None'    { continue }
        'Invalid' {
            Write-Status WARN "Enter a number between 1 and $($accounts.Count), an account name, R to rescan, or Q to quit."
            continue
        }
    }

    $identity = if ($choice.Index -gt 0) { $accounts[$choice.Index - 1].User } else { $choice.Identity }

    Write-Host ''
    Write-Host "  Investigating: $identity" -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  Is this account synced to Microsoft Entra ID?' -ForegroundColor DarkGray
    Write-Host '  If you know the Entra Connect server, enter it to include hybrid evidence.' -ForegroundColor DarkGray
    Write-Host '  Leave blank to skip - a wrong name is worse than none.' -ForegroundColor DarkGray
    $entraAnswer = Read-Host '  Entra Connect server (blank to skip)'
    $entra = Resolve-EntraConnectChoice -InputText $entraAnswer

    $runArgs = @{ Identity = $identity; DaysBack = $DaysBack }
    if ($OutputPath)          { $runArgs['OutputPath'] = $OutputPath }
    if (-not $entra.Skipped)  { $runArgs['EntraConnectServer'] = $entra.Server }

    Write-Host ''
    Write-Status STEP "Running the full investigation for $identity"
    if ($entra.Skipped) {
        Write-Status INFO 'No Entra Connect server supplied - on-premises evidence only.'
    } else {
        Write-Status INFO "Including hybrid evidence from $($entra.Server)."
    }

    try {
        & $investigation @runArgs
    } catch {
        Write-Status FAIL "The investigation failed: $($_.Exception.Message)"
    }

    Write-Host ''
    Write-Host '  Investigate another account? [Enter] for the menu, [Q] to quit.' -ForegroundColor DarkGray
    if ((Read-Host '  ') -in @('q','Q','quit','exit')) { Write-Host ''; return }
}
