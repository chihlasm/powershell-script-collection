#Requires -Version 5.1
<#
.SYNOPSIS
    Runs a complete account lockout investigation in the right order and bundles the
    evidence into one folder.

.DESCRIPTION
    One command that sequences the tools in this folder so you do not have to remember
    which to run, in what order, or how to interpret an empty result.

    THE POINT OF THIS SCRIPT IS THE GATE.

    A lockout report can only find what the domain controllers actually recorded. If
    failure auditing is off, every report returns empty - and an empty report looks
    identical to a clean one. Investigations have been lost for days to exactly this.

    So this script checks audit policy FIRST and, if the DCs are not logging lockout
    events, STOPS and tells you rather than producing confident-looking empty reports.
    Use -Force to collect anyway (useful for documenting the gap on a ticket).

    Run order:

      1. Test-ADAuditPolicy.ps1          Is anything being logged?      <-- GATE
      2. Set-DCSecurityLogRetention.ps1  How far back can we see?       (read-only)
      3. Get-ADLockoutHistory.ps1        Who is locking out?            (domain-wide)
      4. Diagnose-ADAccountLockout.ps1   Why this account?              (needs -Identity)
      5. Invoke-ADLockoutForensics.ps1   Which DC/forest?               (with -MultiForest)

    Everything lands in one timestamped case folder with a SUMMARY.txt, ready to attach
    to a ticket.

.PARAMETER Identity
    Account to investigate. Omit for a domain-wide survey (steps 1-3 only).

.PARAMETER DaysBack
    Search window in days. Default 30.

.PARAMETER OutputPath
    Parent folder for the case bundle. Defaults to a "Reports" folder beside this script.
    Each run creates its own timestamped subfolder.

.PARAMETER MultiForest
    Also run Invoke-ADLockoutForensics.ps1, which auto-discovers trusted forests and polls
    per-DC bad-password counters. Slower, but it is the only step that finds evidence when
    auditing is disabled, because it reads directory attributes rather than event logs.

.PARAMETER Force
    Continue collecting even when the audit-policy gate fails. The reports will be empty
    or partial; use this when you want that documented on the ticket.

.PARAMETER SkipRetentionCheck
    Skip the Security log sizing check.

.EXAMPLE
    .\Invoke-ADLockoutInvestigation.ps1
    Domain-wide survey: audit policy, log retention, and who is locking out.

.EXAMPLE
    .\Invoke-ADLockoutInvestigation.ps1 -Identity jdoe
    Full investigation for one account.

.EXAMPLE
    .\Invoke-ADLockoutInvestigation.ps1 -Identity jdoe -MultiForest -DaysBack 7
    Adds cross-forest collection and per-DC counter polling.

.EXAMPLE
    .\Invoke-ADLockoutInvestigation.ps1 -Identity jdoe -Force
    Collects even though auditing is known to be off, to document the gap.

.NOTES
    Read-only. Requires RSAT ActiveDirectory, Security log read rights on the DCs, and
    WinRM for the audit-policy check.

    Shared constants live in LockoutReference.psd1 in this folder.
#>
[CmdletBinding()]
param(
    [string]$Identity,

    [ValidateRange(1, 365)]
    [int]$DaysBack = 30,

    [string]$OutputPath,

    [switch]$MultiForest,

    [switch]$Force,

    [switch]$SkipRetentionCheck,

    # Internal: dot-source the functions without running the orchestration body.
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

function Get-LockoutReference {
    # Loads the shared constants. Returns $null when unavailable - callers must degrade
    # rather than fail, since every tool also carries its own built-in copy.
    param([string]$ScriptRoot)
    $path = Join-Path $ScriptRoot 'LockoutReference.psd1'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try { return Import-PowerShellDataFile -Path $path -ErrorAction Stop }
    catch { return $null }
}

function Test-AuditGateResult {
    # Pure decision logic: given the audit-policy CSV rows a check produced, decide whether
    # collecting event-log evidence is worth doing.
    #
    # The gate fails only when the subcategory behind event 4740 is not logging, because
    # that is the event whose absence makes a lockout report meaningless. Other gaps
    # degrade the evidence but still leave something worth collecting.
    param(
        [object[]]$AuditRows,
        [object]$Reference
    )

    $result = [PSCustomObject]@{
        Ran            = $false
        Blocking       = $false
        CriticalGaps   = @()
        OtherGaps      = @()
        Message        = ''
    }

    $AuditRows = @($AuditRows)
    if ($AuditRows.Count -eq 0) {
        $result.Message = 'Audit policy could not be determined, so an empty lockout report proves nothing.'
        return $result
    }

    $result.Ran = $true

    # Which subcategory gates event 4740? Prefer the shared reference; fall back to the
    # documented name so the gate still works if the data file is missing.
    $lockoutSubcategory = 'User Account Management'
    if ($Reference -and $Reference.AuditSubcategories) {
        $match = @($Reference.AuditSubcategories | Where-Object { $_.Events -contains 4740 })
        if ($match.Count -gt 0) { $lockoutSubcategory = $match[0].Name }
    }

    foreach ($row in $AuditRows) {
        if ($row.Status -eq 'Pass') { continue }
        if ($row.Subcategory -eq $lockoutSubcategory) {
            $result.CriticalGaps += "$($row.DC): $($row.Subcategory) is '$($row.Setting)' - event 4740 is NOT being written"
        } else {
            $result.OtherGaps += "$($row.DC): $($row.Subcategory) is '$($row.Setting)' - event $($row.EventId) is NOT being written"
        }
    }

    if ($result.CriticalGaps.Count -gt 0) {
        $result.Blocking = $true
        $result.Message  = 'Account lockout events (4740) are not being recorded. Lockout reports cannot return meaningful data until this is fixed.'
    } elseif ($result.OtherGaps.Count -gt 0) {
        $result.Message = 'Lockout events are recorded, but some supporting evidence is not. Reports will be partial.'
    } else {
        $result.Message = 'All lockout-relevant auditing is enabled. An empty report would be a genuine result.'
    }

    return $result
}

function Invoke-Step {
    # Runs one child script in its own process so a failure inside it cannot terminate the
    # investigation. Returns a step-result row for the summary.
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ScriptPath,
        [hashtable]$Arguments = @{},
        [Parameter(Mandatory)][string]$CaseFolder
    )

    $row = [PSCustomObject]@{
        Step     = $Name
        Script   = Split-Path $ScriptPath -Leaf
        Ran      = $false
        ExitCode = $null
        Error    = ''
    }

    if (-not (Test-Path -LiteralPath $ScriptPath)) {
        $row.Error = "Script not found: $ScriptPath"
        Write-Status WARN $row.Error
        return $row
    }

    # Build a param string for a child powershell.exe invocation. Values are single-quoted
    # with embedded quotes doubled, so a path with spaces or an apostrophe cannot break out.
    $argParts = foreach ($k in $Arguments.Keys) {
        $v = $Arguments[$k]
        if ($v -is [switch] -or $v -is [bool]) {
            if ($v) { "-$k" }
        } elseif ($null -ne $v -and "$v" -ne '') {
            "-$k '" + ("$v" -replace "'", "''") + "'"
        }
    }
    $argLine = ($argParts | Where-Object { $_ }) -join ' '

    $logPath = Join-Path $CaseFolder ("{0}.log" -f ($Name -replace '[^a-zA-Z0-9]', '_'))

    try {
        # -NoProfile keeps a user's profile from altering behaviour on a DC.
        $cmd = "& '" + ($ScriptPath -replace "'", "''") + "' $argLine *>&1 | Tee-Object -FilePath '" + ($logPath -replace "'", "''") + "'"
        $proc = Start-Process -FilePath 'powershell.exe' `
                    -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $cmd) `
                    -NoNewWindow -Wait -PassThru -ErrorAction Stop
        $row.Ran      = $true
        $row.ExitCode = $proc.ExitCode
        if ($proc.ExitCode -ne 0) {
            $row.Error = "Exited with code $($proc.ExitCode). See $(Split-Path $logPath -Leaf)."
            Write-Status WARN $row.Error
        }
    } catch {
        $row.Error = $_.Exception.Message
        Write-Status WARN "Step '$Name' failed: $($row.Error)"
    }

    return $row
}

function New-CaseSummary {
    # Builds the plain-text SUMMARY.txt. Pure string work so it is testable.
    param(
        [string]$Identity,
        [int]$DaysBack,
        [object]$Gate,
        [object[]]$Steps,
        [string]$CaseFolder,
        [string]$GeneratedOn
    )

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('AD LOCKOUT INVESTIGATION - CASE SUMMARY')
    $null = $sb.AppendLine('=======================================')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("Generated : $GeneratedOn")
    $null = $sb.AppendLine("Account   : $(if ($Identity) { $Identity } else { '(domain-wide survey)' })")
    $null = $sb.AppendLine("Window    : $DaysBack day(s)")
    $null = $sb.AppendLine("Folder    : $CaseFolder")
    $null = $sb.AppendLine()

    $null = $sb.AppendLine('EVIDENCE QUALITY')
    $null = $sb.AppendLine('----------------')
    if (-not $Gate.Ran) {
        $null = $sb.AppendLine('UNKNOWN - audit policy could not be determined.')
        $null = $sb.AppendLine('An empty lockout report proves nothing in this state.')
    } elseif ($Gate.Blocking) {
        $null = $sb.AppendLine('*** NOT TRUSTWORTHY - LOCKOUT EVENTS ARE NOT BEING RECORDED ***')
        $null = $sb.AppendLine()
        $null = $sb.AppendLine($Gate.Message)
        $null = $sb.AppendLine()
        foreach ($g in $Gate.CriticalGaps) { $null = $sb.AppendLine("  - $g") }
        $null = $sb.AppendLine()
        $null = $sb.AppendLine('Any empty section in these reports is a COLLECTION GAP, not a clean result.')
    } else {
        $null = $sb.AppendLine('Lockout events (4740) are being recorded.')
        if ($Gate.OtherGaps.Count -gt 0) {
            $null = $sb.AppendLine('Some supporting evidence is not, so reports will be partial:')
            foreach ($g in $Gate.OtherGaps) { $null = $sb.AppendLine("  - $g") }
        } else {
            $null = $sb.AppendLine('All lockout-relevant auditing is enabled - an empty report is a genuine result.')
        }
    }
    $null = $sb.AppendLine()

    $null = $sb.AppendLine('STEPS RUN')
    $null = $sb.AppendLine('---------')
    foreach ($s in @($Steps)) {
        $state = if (-not $s.Ran) { 'SKIPPED' } elseif ($s.ExitCode -eq 0) { 'OK' } else { "EXIT $($s.ExitCode)" }
        $null = $sb.AppendLine(("  [{0,-7}] {1} ({2})" -f $state, $s.Step, $s.Script))
        if ($s.Error) { $null = $sb.AppendLine("            $($s.Error)") }
    }
    $null = $sb.AppendLine()

    # List what is actually on disk, in reading order, rather than describing reports by a
    # name that appears nowhere. Files are renamed with a NN_ prefix after collection so
    # the folder sorts into the order they should be read.
    $null = $sb.AppendLine('FILES IN THIS FOLDER (read top to bottom)')
    $null = $sb.AppendLine('-----------------------------------------')
    $reports = @()
    if ($CaseFolder -and (Test-Path -LiteralPath $CaseFolder)) {
        $reports = @(Get-ChildItem -LiteralPath $CaseFolder -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Extension -in '.html', '.csv' } |
                        Sort-Object Name)
    }
    if ($reports.Count -eq 0) {
        $null = $sb.AppendLine('  (no reports were produced - see STEPS RUN above)')
    } else {
        foreach ($f in $reports) {
            $what = switch -Regex ($f.Name) {
                'AuditPolicy'      { 'Which events the DCs are recording'; break }
                'LogRetention'     { 'How far back the Security log reaches'; break }
                'LockoutHistory'   { 'Every account that locked out, ranked by count'; break }
                'Forensics.*perdc' { 'Per-DC bad-password counters (works without auditing)'; break }
                'Forensics.*event' { 'Raw collected events'; break }
                'Forensics'        { 'Multi-forest forensics'; break }
                '^\d+_ADLockout_'  { 'Deep dive on the account'; break }
                default            { '' }
            }
            $null = $sb.AppendLine(("  {0,-52} {1}" -f $f.Name, $what))
        }
    }
    $null = $sb.AppendLine()

    $null = $sb.AppendLine('NEXT STEPS')
    $null = $sb.AppendLine('----------')
    if ($Gate.Blocking) {
        $null = $sb.AppendLine('1. Enable auditing on the domain controllers via Group Policy:')
        $null = $sb.AppendLine('     Computer Configuration > Policies > Windows Settings > Security Settings')
        $null = $sb.AppendLine('       > Advanced Audit Policy Configuration')
        $null = $sb.AppendLine('     - Account Management > Audit User Account Management -> Success   (event 4740)')
        $null = $sb.AppendLine('     - Account Logon > Audit Kerberos Authentication Service -> Success and Failure (4771)')
        $null = $sb.AppendLine('     - Logon/Logoff > Audit Logon -> Success and Failure (4625)')
        $null = $sb.AppendLine('     - Logon/Logoff > Audit Account Lockout -> Failure (no Success events exist)')
        $null = $sb.AppendLine('     - Security Options > "Force audit policy subcategory settings..." -> Enabled')
        $null = $sb.AppendLine('2. Run gpupdate /force on the DCs, then re-run Test-ADAuditPolicy.ps1 to confirm.')
        $null = $sb.AppendLine('3. Wait for the problem to recur, then re-run this investigation.')
    } else {
        $histFile = @($reports | Where-Object { $_.Name -match 'LockoutHistory.*\.html$' } |
                        Select-Object -First 1 -ExpandProperty Name)
        $deepFile = @($reports | Where-Object { $_.Name -match 'ADLockout_.*\.html$' } |
                        Select-Object -First 1 -ExpandProperty Name)
        $first = if ($histFile) { $histFile } elseif ($deepFile) { $deepFile } else { 'the HTML report above' }

        $null = $sb.AppendLine("1. Open $first and read the 'What this means' box at the top.")
        if ($deepFile -and $histFile) {
            $null = $sb.AppendLine("2. For the worst offender it names, open $deepFile.")
        } else {
            $null = $sb.AppendLine('2. Note the caller computer that appears most often.')
        }
        $null = $sb.AppendLine('3. On that machine, clear the stale credential:')
        $null = $sb.AppendLine('     cmdkey /list, mapped drives, scheduled tasks and services running as')
        $null = $sb.AppendLine('     the user, the Outlook profile, and any phone with a saved password.')
        $null = $sb.AppendLine('4. If the lockout threshold is 5 or lower, raise it to 10 over a 15-minute window.')
    }

    return $sb.ToString()
}

if ($LoadFunctionsOnly) { return }

# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$reference  = Get-LockoutReference -ScriptRoot $scriptRoot

Write-Host ''
Write-Host '  AD LOCKOUT INVESTIGATION' -ForegroundColor Cyan
Write-Host '  ========================' -ForegroundColor Cyan
Write-Host ''
if ($reference) {
    Write-Status INFO "Reference data loaded (verified $($reference.VerifiedOn))."
} else {
    Write-Status WARN 'LockoutReference.psd1 not found; each tool will use its own built-in constants.'
}
Write-Status INFO "Account: $(if ($Identity) { $Identity } else { '(domain-wide survey)' })  |  Window: $DaysBack day(s)"

# --- Case folder ---
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $scriptRoot 'Reports'
}
$stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$slug  = if ($Identity) { ($Identity -replace '[^a-zA-Z0-9._-]', '_') } else { 'survey' }
$caseFolder = Join-Path $OutputPath "Case_${slug}_$stamp"
try {
    New-Item -ItemType Directory -Path $caseFolder -Force -ErrorAction Stop | Out-Null
} catch {
    Write-Status FAIL "Could not create case folder ${caseFolder}: $($_.Exception.Message)"
    exit 1
}
Write-Status INFO "Case folder: $caseFolder"

$steps = New-Object System.Collections.ArrayList

# --- Step 1: audit policy (the gate) ---
Write-Status STEP 'STEP 1/5  Audit policy - is anything being logged?'
$null = $steps.Add((Invoke-Step -Name 'Audit policy' -CaseFolder $caseFolder `
    -ScriptPath (Join-Path $scriptRoot 'Test-ADAuditPolicy.ps1') `
    -Arguments @{ OutputPath = $caseFolder; Format = 'Both' }))

# Read back the CSV the check wrote and decide whether to continue.
$auditRows = @()
$auditCsv = Get-ChildItem -Path $caseFolder -Filter 'ADAuditPolicy_*.csv' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($auditCsv) {
    try { $auditRows = @(Import-Csv -Path $auditCsv.FullName -ErrorAction Stop) } catch { $auditRows = @() }
}

$gate = Test-AuditGateResult -AuditRows $auditRows -Reference $reference

Write-Host ''
if ($gate.Blocking) {
    Write-Status FAIL $gate.Message
    foreach ($g in $gate.CriticalGaps) { Write-Host "         $g" -ForegroundColor Red }
} elseif (-not $gate.Ran) {
    Write-Status WARN $gate.Message
} elseif ($gate.OtherGaps.Count -gt 0) {
    Write-Status WARN $gate.Message
    foreach ($g in $gate.OtherGaps) { Write-Host "         $g" -ForegroundColor Yellow }
} else {
    Write-Status PASS $gate.Message
}

$proceed = $true
if ($gate.Blocking -and -not $Force) {
    $proceed = $false
    Write-Host ''
    Write-Status WARN 'STOPPING before event-log collection.'
    Write-Status INFO 'Collecting now would produce empty reports that look like clean results.'
    Write-Status INFO 'Re-run with -Force to collect anyway and document the gap on the ticket.'
    if (-not $MultiForest) {
        Write-Status INFO 'Tip: -MultiForest still finds evidence without auditing - it polls per-DC'
        Write-Status INFO '     bad-password counters, which are directory attributes, not log events.'
    }
} elseif ($gate.Blocking -and $Force) {
    Write-Host ''
    Write-Status WARN '-Force supplied: collecting anyway. Empty sections are collection gaps, not clean results.'
}

# --- Step 2: log retention (read-only) ---
if ($proceed -and -not $SkipRetentionCheck) {
    Write-Status STEP 'STEP 2/5  Security log retention - how far back can we see?'
    $null = $steps.Add((Invoke-Step -Name 'Log retention' -CaseFolder $caseFolder `
        -ScriptPath (Join-Path $scriptRoot 'Set-DCSecurityLogRetention.ps1') `
        -Arguments @{ TargetDays = $DaysBack; OutputPath = $caseFolder }))
} else {
    $null = $steps.Add([PSCustomObject]@{ Step='Log retention'; Script='Set-DCSecurityLogRetention.ps1'
                                          Ran=$false; ExitCode=$null; Error='Skipped' })
}

# --- Step 3: domain-wide history ---
if ($proceed) {
    Write-Status STEP 'STEP 3/5  Domain-wide lockout history - who is locking out?'
    $null = $steps.Add((Invoke-Step -Name 'Lockout history' -CaseFolder $caseFolder `
        -ScriptPath (Join-Path $scriptRoot 'Get-ADLockoutHistory.ps1') `
        -Arguments @{ DaysBack = $DaysBack; OutputPath = $caseFolder; Format = 'Both' }))
} else {
    $null = $steps.Add([PSCustomObject]@{ Step='Lockout history'; Script='Get-ADLockoutHistory.ps1'
                                          Ran=$false; ExitCode=$null; Error='Skipped - audit gate' })
}

# --- Step 4: per-account deep dive ---
if ($proceed -and $Identity) {
    Write-Status STEP 'STEP 4/5  Per-account deep dive - why this account?'
    $null = $steps.Add((Invoke-Step -Name 'Account diagnostics' -CaseFolder $caseFolder `
        -ScriptPath (Join-Path $scriptRoot 'Diagnose-ADAccountLockout.ps1') `
        -Arguments @{ Identity = $Identity; DaysBack = $DaysBack; OutputPath = $caseFolder }))
} else {
    $reason = if (-not $Identity) { 'Skipped - no -Identity supplied' } else { 'Skipped - audit gate' }
    $null = $steps.Add([PSCustomObject]@{ Step='Account diagnostics'; Script='Diagnose-ADAccountLockout.ps1'
                                          Ran=$false; ExitCode=$null; Error=$reason })
}

# --- Step 5: multi-forest forensics ---
# Deliberately NOT gated on audit policy: it polls per-DC badPwdCount/badPasswordTime,
# which are directory attributes. This is the one step that still produces evidence when
# auditing is completely disabled.
if ($MultiForest) {
    Write-Status STEP 'STEP 5/5  Multi-forest forensics - which DC and forest?'
    if ($gate.Blocking) {
        Write-Status INFO 'Auditing is off, but per-DC counters are directory attributes - this step still works.'
    }
    $args5 = @{ DaysBack = [math]::Min($DaysBack, 365); OutputFolder = $caseFolder }
    if ($Identity) { $args5['Identity'] = $Identity }
    if ($gate.Blocking -and -not $Force) { $args5['SkipEventCollection'] = $true }
    $null = $steps.Add((Invoke-Step -Name 'Multi-forest forensics' -CaseFolder $caseFolder `
        -ScriptPath (Join-Path $scriptRoot 'Invoke-ADLockoutForensics.ps1') -Arguments $args5))
} else {
    $null = $steps.Add([PSCustomObject]@{ Step='Multi-forest forensics'; Script='Invoke-ADLockoutForensics.ps1'
                                          Ran=$false; ExitCode=$null; Error='Skipped - pass -MultiForest to include' })
}

# --- Put the outputs into reading order ---
# The child scripts name their own files, so a case folder ends up holding several
# similarly-named timestamped reports with no indication of which to open first. Prefix
# them with NN_ so the folder sorts into the order they should be read.
$order = @(
    @{ Match = 'ADAuditPolicy';                 Prefix = '01' }
    @{ Match = 'DCSecurityLogRetention';        Prefix = '02' }
    @{ Match = 'ADLockoutHistory';              Prefix = '03' }
    @{ Match = '^ADLockout_';                   Prefix = '04' }   # per-account deep dive
    @{ Match = 'ADLockoutForensics';            Prefix = '05' }
)
foreach ($file in @(Get-ChildItem -LiteralPath $caseFolder -File -ErrorAction SilentlyContinue)) {
    if ($file.Name -match '^\d\d_') { continue }                  # already prefixed
    if ($file.Extension -notin '.html', '.csv') { continue }      # leave .log and SUMMARY.txt
    $rule = @($order | Where-Object { $file.Name -match $_.Match }) | Select-Object -First 1
    if (-not $rule) { continue }
    try {
        Rename-Item -LiteralPath $file.FullName -NewName ("{0}_{1}" -f $rule.Prefix, $file.Name) -ErrorAction Stop
    } catch {
        Write-Status WARN "Could not rename $($file.Name): $($_.Exception.Message)"
    }
}

# --- Summary ---
$summary = New-CaseSummary -Identity $Identity -DaysBack $DaysBack -Gate $gate -Steps $steps `
    -CaseFolder $caseFolder -GeneratedOn (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
$summaryPath = Join-Path $caseFolder 'SUMMARY.txt'
try {
    Set-Content -Path $summaryPath -Value $summary -Encoding UTF8 -ErrorAction Stop
} catch {
    Write-Status WARN "Could not write SUMMARY.txt: $($_.Exception.Message)"
}

Write-Host ''
Write-Host $summary
Write-Status PASS "Case bundle: $caseFolder"
if ($gate.Blocking -and -not $Force) { exit 2 }
