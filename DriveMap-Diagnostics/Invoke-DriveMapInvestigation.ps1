#Requires -Version 5.1

<#
.SYNOPSIS
    Orchestrates a full drive-map investigation and names the ranked, most-likely cause.

.DESCRIPTION
    This is the ORCHESTRATOR for the drive-map diagnostics toolkit, and the home of the
    ranked-cause verdict logic (design spec section 6). Every other script in this toolkit
    COLLECTS evidence - the readiness gate, the endpoint collector, the activity watcher, and
    the two reused domain-side scripts (Audit-GPDriveMaps.ps1, Search-SYSVOLScripts.ps1).
    This script is the only one that DECIDES: it sequences the gate and the collectors,
    flattens their structured output into one evidence object, and runs every ranked-cause
    rule against it to produce a plain-English verdict a technician can act on.

    SEQUENCE:
      1. Run Test-DriveMapLoggingReadiness.ps1 (the gate). Unless -Force, stop when it
         reports the machine BLIND and say exactly which condition is blind - an empty
         report from a blind machine is indistinguishable from a healthy one, and printing
         a clean-looking verdict in that state would be the single most damaging failure
         mode in this toolkit.
      2. Collect endpoint evidence: either accept a pre-collected bundle via -EvidencePath
         (produced by hand, or pulled from a remote machine some other way), or run
         Export-DriveMapEvidence.ps1 directly against -ComputerName.
      3. Run Audit-GPDriveMaps.ps1 -TargetUser -TargetComputer for GPO-side precedence and
         conflict data, and Search-SYSVOLScripts.ps1 -SearchPattern for the drive letter, to
         cover section 3.5's documented trap: a logon script in an UNRELATED GPO deleting a
         drive Group Policy had already mapped successfully.
      4. Flatten the endpoint bundle's manifest + CSVs into the flat evidence object
         Get-DriveMapVerdict consumes (ConvertFrom-EvidenceBundle).
      5. Call Get-DriveMapVerdict, write SUMMARY.txt, and hand off to Task 6's HTML report
         script if it is present (skipped, with a note, if it is not yet deployed alongside
         this script).

    THE THREE-STATE DISTINCTION, PRESERVED THROUGH THE FLATTEN. Export-DriveMapEvidence.ps1's
    collectors each return New-CollectionResult's State of exactly 'Found', 'EmptyButValid',
    or 'CouldNotCollect'. ConvertFrom-EvidenceBundle must never collapse 'CouldNotCollect'
    into the same flat value as a confirmed-false/confirmed-empty finding: "we could not look"
    and "we looked and it was false" point to opposite conclusions, and collapsing them is
    exactly the confident-plausible-wrong-answer failure this toolkit exists to prevent. Every
    boolean/array property ConvertFrom-EvidenceBundle produces is $null when its source
    collector's State was 'CouldNotCollect' - never $false and never an empty array for that
    case - and Get-DriveMapVerdict treats $null as "not established", never as a negative
    finding: a rule that requires a condition to be true only fires when it is FOUND true, and
    a rule that would otherwise fire on a false reading is skipped (not confirmed) when that
    reading is unknown.

.PARAMETER Identity
    The user (SamAccountName) whose drive mapping is being investigated. Passed through to
    Audit-GPDriveMaps.ps1 -TargetUser for precedence simulation and used in the case summary
    and folder name.

.PARAMETER ComputerName
    The affected computer. Defaults to the local computer. Passed to the readiness gate, the
    evidence collector (unless -EvidencePath is supplied), and Audit-GPDriveMaps.ps1
    -TargetComputer.

.PARAMETER DriveLetter
    The drive letter reported missing or intermittently disappearing (e.g. "X"). Used to
    filter evidence and to build the SYSVOL search pattern.

.PARAMETER EvidencePath
    Optional. Path to an evidence bundle folder already produced by
    Export-DriveMapEvidence.ps1 (for example, collected by hand on an unreachable machine and
    copied back). When supplied, endpoint collection is skipped and this bundle is used
    instead.

.PARAMETER OutputPath
    Folder under which a timestamped case folder is created. Defaults to a "Cases" folder
    beside this script.

.PARAMETER Force
    Continue past the readiness gate even when it reports the machine BLIND. The verdict
    logic itself is unaffected - a blind machine simply tends to produce fewer 'Found'
    collectors and more 'CouldNotCollect' ones, which already renders correctly as
    unestablished evidence rather than a false negative.

.PARAMETER LoadFunctionsOnly
    Internal. Dot-sources the functions below without running the orchestration body, so
    Pester can test them directly. Must remain the last parameter.

.EXAMPLE
    .\Invoke-DriveMapInvestigation.ps1 -Identity jsmith -ComputerName WKS042 -DriveLetter X

    Runs the full investigation against WKS042 for user jsmith's missing X: drive: gate,
    endpoint collection, GPO audit, SYSVOL search, and a ranked verdict written to a case
    folder.

.EXAMPLE
    .\Invoke-DriveMapInvestigation.ps1 -Identity jsmith -ComputerName WKS042 -DriveLetter X `
        -EvidencePath 'D:\Cases\12345\DriveMapEvidence_WKS042_2026-09-14_090000'

    Skips endpoint collection and uses a bundle already collected by hand.

.EXAMPLE
    .\Invoke-DriveMapInvestigation.ps1 -Identity jsmith -ComputerName WKS042 -DriveLetter X -Force

    Continues past a BLIND readiness gate result instead of stopping.

.NOTES
    Reuses AD-GroupPolicy-DriveMaps\Audit-GPDriveMaps.ps1 and
    Search-SYSVOLScripts\Search-SYSVOLScripts.ps1 UNMODIFIED, via Resolve-CompanionScript and
    Invoke-Step (copied from AD-LockoutDiagnostics\Invoke-ADLockoutInvestigation.ps1's own
    functions of the same name, quoting logic intact).

    Files this script writes are UTF-8 WITH a byte-order mark, written via
    [System.IO.File]::WriteAllText with a UTF8Encoding(true) instance, because PowerShell 7's
    -Encoding UTF8 omits the BOM while Windows PowerShell 5.1's does not.

    Companion tools in this toolkit: Test-DriveMapLoggingReadiness.ps1,
    Export-DriveMapEvidence.ps1, Watch-DriveMapActivity.ps1, New-DriveMapCaseReport.ps1 (Task 6).

    REFERENCES
      Scenario guide documenting an unrelated GPO's logon script deleting a drive that Group
      Policy Preferences had already mapped successfully - every Group Policy event healthy,
      GPP trace showing the item applied, drive still absent:
        https://learn.microsoft.com/en-us/troubleshoot/windows-client/group-policy/scenario-guide-gpo-to-map-network-drive-doesn-t-apply-as-expected
      The Drive Maps CSE has NoBackgroundPolicy=1 (never called on background refresh) and
      only applies items during SYNCHRONOUS Group Policy processing; with Fast Logon
      Optimization enabled (asynchronous logon), the CSE declines and requests synchronous
      processing for the NEXT logon, so a Replace-mode map applies only every other logon.
      Setting NoBackgroundPolicy=0 is explicitly NOT recommended by Microsoft and does not
      reliably guarantee application:
        https://learn.microsoft.com/en-us/archive/technet-wiki/12221.group-policy-troubleshooting-drive-maps-preference-extension-replace-mode-only-maps-the-drive-every-other-logon
      "Always wait for the network at computer startup and logon" forces synchronous
      foreground processing every logon (Computer Configuration\Policies\Administrative
      Templates\System\Logon):
        https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj573586(v=ws.11)
      With UAC enabled, logon creates two linked logon sessions; drive mappings are per-
      session symbolic (DosDevices) links not shared between them, so a drive mapped in one
      context is genuinely absent from the other. EnableLinkedConnections=1 (DWORD, under
      HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System) writes mappings to both:
        https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command
      GPP preference-item events 4096/4098/4101/4105/4106/8194/8212 (Application log, source
      'Group Policy Drive Maps') are logged only when "Logging and tracing" is enabled -
      logging is OFF by default, so an empty Application log is never proof of "no failures":
        https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/information-group-policy-preferences-events
      Replace mode performs delete-then-create on every application (not an idempotent
      no-op); Update cannot change Location, Reconnect, or "Connect as":
        https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn581924(v=ws.11)
      Audit-GPDriveMaps.ps1 parameters (-OutputPath, -ExportFormat, -Domain, -Credential,
      -TargetUser, -TargetComputer, -SkipBrowserOpen, -SkipPathValidation, -CheckGroupOverlap,
      -LoadFunctionsOnly) and Search-SYSVOLScripts.ps1 parameters (-SearchPattern, -Path,
      -Regex, -AllFiles, -NoRecurse, -OutputPath) were read directly from those scripts in
      this repository, not assumed.
#>
[CmdletBinding()]
param(
    [string]$Identity,

    [string]$ComputerName = $env:COMPUTERNAME,

    [string]$DriveLetter,

    [string]$EvidencePath,

    [string]$OutputPath,

    [switch]$Force,

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

function Resolve-CompanionScript {
    # Finds a companion script whether the tools are laid out as sibling folders (the repo)
    # or flat in one directory (a distributed zip). Checking beside this script first means
    # a packaged copy works without any path assumptions. Copied from
    # AD-LockoutDiagnostics\Invoke-ADLockoutInvestigation.ps1's function of the same name
    # (lines ~218-232), with candidate paths adjusted to this toolkit's reused scripts.
    param([Parameter(Mandatory)][string]$FileName, [Parameter(Mandatory)][string]$ScriptRoot)

    foreach ($candidate in @(
        (Join-Path $ScriptRoot $FileName),
        (Join-Path $ScriptRoot "AD-GroupPolicy-DriveMaps\$FileName"),
        (Join-Path $ScriptRoot "Search-SYSVOLScripts\$FileName"),
        (Join-Path (Split-Path $ScriptRoot -Parent) "AD-GroupPolicy-DriveMaps\$FileName"),
        (Join-Path (Split-Path $ScriptRoot -Parent) "Search-SYSVOLScripts\$FileName")
    )) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return $null
}

function Invoke-Step {
    # Runs one child script in its own process so a failure inside it cannot terminate the
    # investigation. Returns a step-result row for the summary. Copied from
    # AD-LockoutDiagnostics\Invoke-ADLockoutInvestigation.ps1's function of the same name
    # (lines ~234-290); the quoting logic is kept intact exactly as-is, because it exists so
    # a path containing an apostrophe cannot break out of the child command.
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
        # -NoProfile keeps a user's profile from altering behaviour on the target machine.
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

function ConvertFrom-EvidenceBundle {
    <#
    .SYNOPSIS
        Flattens Task 3's structured evidence bundle (manifest.json + CSVs, built from
        New-CollectionResult's three-state contract) into the flat object Get-DriveMapVerdict
        consumes.

    .DESCRIPTION
        This function is the single place in the toolkit where the endpoint bundle and the
        domain-side data (GPO audit, SYSVOL search) meet and become one evidence object. It
        is also where the three-state contract either survives or is destroyed.

        THE RULE THIS FUNCTION EXISTS TO ENFORCE: a collector that returned 'CouldNotCollect'
        must flatten to $null on the corresponding output property, NEVER to $false and NEVER
        to an empty array. "We could not look" and "we looked and it was false" lead to
        opposite conclusions - collapsing them here would silently reintroduce the exact
        failure the three-state contract in Export-DriveMapEvidence.ps1 was built to prevent,
        one layer downstream of where that script's own tests can catch it.

        Property mapping (bundle source -> flat property):
          GppApplied              <- GppEvents: $true if any event's Category is 'Applied'
                                      (event 4096, per DriveMapReference.psd1), else $false if
                                      the collector was Found/EmptyButValid with no such event,
                                      else $null if CouldNotCollect.
          DrivePresent             <- LiveMounts_CurrentContext: $true if DriveLetter appears
                                      among its rows, $false if Found/EmptyButValid and it does
                                      not, $null if CouldNotCollect.
          ScriptDeletions          <- LogonScriptReferences, filtered to Operation -eq
                                      'Delete' and re-shaped to {Source; Line}. $null (not @())
                                      when the collector could not run.
          InRegistry               <- PersistentMounts: $true/$false by DriveLetter presence,
                                      $null if CouldNotCollect.
          InLiveMounts             <- LiveMounts_CurrentContext: same presence test as
                                      DrivePresent, kept as a separate property because
                                      Get-DriveMapVerdict's reconnect-failing rule needs both
                                      InRegistry and InLiveMounts independently.
          TargetingFailures        <- GppEvents, filtered to Category -eq 'TargetingFailed'
                                      (4105/4106/8212), re-shaped to {EventId; Gpo}. $null when
                                      GppEvents could not be collected.
          Action                   <- -Action if explicitly supplied, else read from
                                      -GpoActionCsvPath (Audit-GPDriveMaps.ps1's own CSV
                                      output for this drive letter's GPP action) when that
                                      path is supplied and readable. $null (never guessed)
                                      when neither source has it - Action comes from the
                                      domain side, not the endpoint gate, and this function
                                      never fabricates it.
          FastLogonOptimization,
          AlwaysWaitForNetwork,
          EnableLinkedConnections  <- -FastLogonOptimization / -AlwaysWaitForNetwork /
                                      -EnableLinkedConnections if explicitly supplied
                                      (non-$null), else read from -ReadinessJsonPath - the
                                      machine-readable companion Test-DriveMapLoggingReadiness.ps1
                                      writes alongside its .txt report. Each of that JSON's
                                      three-state records ({State; Value; Reason}) maps
                                      State 'Found' to its Value and State 'CouldNotCollect'
                                      to $null - NEVER to $false - exactly as the endpoint
                                      bundle's own CouldNotCollect collectors do above. When
                                      neither an explicit parameter nor a readable JSON file
                                      is available, the property is $null.
          ElevatedVisible,
          UnelevatedVisible        <- LiveMounts_CurrentContext / LiveMounts_OtherTokenContext.
                                      Both $null when the corresponding context could not be
                                      collected - see Export-DriveMapEvidence.ps1's own
                                      CouldNotCollect reasons for why a single run frequently
                                      cannot see both contexts.

        Every parameter below is [AllowNull()] and defaults to $null precisely so a caller
        that does not have a given signal yet (rather than guessing) produces the correct
        "not established" flat value instead of a fabricated one.
    #>
    param(
        [Parameter(Mandatory)][string]$DriveLetter,
        [Parameter(Mandatory)][hashtable]$Results,
        [AllowNull()][string]$Action = $null,
        [AllowNull()][object]$FastLogonOptimization = $null,
        [AllowNull()][object]$AlwaysWaitForNetwork = $null,
        [AllowNull()][object]$EnableLinkedConnections = $null,
        [AllowNull()][string]$ReadinessJsonPath = $null,
        [AllowNull()][string]$GpoActionCsvPath = $null
    )

    $letterUpper = $DriveLetter.Trim().TrimEnd(':').ToUpperInvariant()

    # Reads one of Test-DriveMapLoggingReadiness.ps1's JSON three-state records ({State;
    # Value; Reason}) and returns exactly $null for CouldNotCollect (never $false) or the
    # record's Value for Found/EmptyButValid - the same rule ConvertFrom-EvidenceBundle
    # applies to every endpoint-bundle collector above, applied here to the gate's own
    # machine-readable output.
    function Read-ReadinessValue {
        param($Record)
        if ($null -eq $Record -or $Record.State -eq 'CouldNotCollect') { return $null }
        return $Record.Value
    }

    $readinessData = $null
    if ($ReadinessJsonPath -and (Test-Path -LiteralPath $ReadinessJsonPath)) {
        try {
            $readinessData = Get-Content -LiteralPath $ReadinessJsonPath -Raw | ConvertFrom-Json
        } catch {
            # A malformed/unreadable readiness JSON must never be treated as "confirmed
            # absent risk" - leave $readinessData $null so every value below falls through
            # to $null exactly as if no JSON had been supplied at all.
            $readinessData = $null
        }
    }

    if ($null -eq $FastLogonOptimization -and $readinessData) {
        $FastLogonOptimization = Read-ReadinessValue -Record $readinessData.FastLogonOptimization
    }
    if ($null -eq $AlwaysWaitForNetwork -and $readinessData) {
        $AlwaysWaitForNetwork = Read-ReadinessValue -Record $readinessData.AlwaysWaitForNetwork
    }
    if ($null -eq $EnableLinkedConnections -and $readinessData) {
        $EnableLinkedConnections = Read-ReadinessValue -Record $readinessData.EnableLinkedConnections
    }

    if ([string]::IsNullOrEmpty($Action) -and $GpoActionCsvPath -and (Test-Path -LiteralPath $GpoActionCsvPath)) {
        try {
            $gpoRows = @(Import-Csv -LiteralPath $GpoActionCsvPath)
            # Audit-GPDriveMaps.ps1's own CSV column names are read defensively - if a
            # future version of that script renames or drops the Action/DriveLetter
            # columns, this must degrade to "not found" (Action stays $null), never throw
            # and never guess. Reused unmodified per this task's dispatch, so no assumption
            # about its schema is asserted here as a verified fact.
            $matchRow = $gpoRows | Where-Object {
                $_.PSObject.Properties['DriveLetter'] -and
                ([string]$_.DriveLetter).TrimEnd(':').ToUpperInvariant() -eq $letterUpper
            } | Select-Object -First 1
            if ($matchRow -and $matchRow.PSObject.Properties['Action']) {
                $Action = $matchRow.Action
            }
        } catch {
            # Could not read/parse the GPO audit CSV - Action stays whatever it already was
            # ($null unless explicitly supplied), never guessed.
        }
    }

    function Test-LetterPresent {
        param($Result, [string]$Letter)
        if ($null -eq $Result -or $Result.State -eq 'CouldNotCollect') { return $null }
        $rows = @($Result.Data)
        if ($rows.Count -eq 0) { return $false }
        [bool]($rows | Where-Object { ([string]$_.DriveLetter).TrimEnd(':').ToUpperInvariant() -eq $Letter })
    }

    $liveCurrent = $Results['LiveMounts_CurrentContext']
    $liveOther   = $Results['LiveMounts_OtherTokenContext']
    $persistent  = $Results['PersistentMounts']
    $gppEvents   = $Results['GppEvents']
    $logonRefs   = $Results['LogonScriptReferences']

    # DrivePresent / InLiveMounts / ElevatedVisible / UnelevatedVisible all derive from the
    # two live-mount collectors, but represent different questions:
    #   - DrivePresent / InLiveMounts: is the letter live in THIS process's own context?
    #   - ElevatedVisible / UnelevatedVisible: is it live in each UAC token context
    #     specifically? Export-DriveMapEvidence.ps1 always records the CURRENT context as
    #     LiveMounts_CurrentContext and (only when elevated) attempts the other context as
    #     LiveMounts_OtherTokenContext, which in practice comes back CouldNotCollect (see
    #     that script's own documented limitation) - so both properties are frequently $null,
    #     which is the correct "not established" answer, never a guessed $false.
    $currentContextPresent = Test-LetterPresent -Result $liveCurrent -Letter $letterUpper
    $otherContextPresent   = Test-LetterPresent -Result $liveOther -Letter $letterUpper

    $isElevatedRun = $null
    if ($liveCurrent -and $liveCurrent.State -ne 'CouldNotCollect') {
        # Export-DriveMapEvidence.ps1 records which context LiveMounts_CurrentContext IS via
        # its own elevation check; that flag is not itself in the bundle, so this function
        # cannot assert which physical context (elevated/filtered) CurrentContext represents
        # without that information. When only one live-mount collector produced data, assign
        # it to DrivePresent/InLiveMounts (the context-agnostic questions) and leave
        # ElevatedVisible/UnelevatedVisible unestablished rather than guess which one it was.
        $isElevatedRun = $false
    }

    $drivePresent = $currentContextPresent
    $inLiveMounts = $currentContextPresent
    $inRegistry   = Test-LetterPresent -Result $persistent -Letter $letterUpper

    # ElevatedVisible/UnelevatedVisible: only populated when BOTH contexts were actually
    # collected as data points in this run (both Found/EmptyButValid), since that is the only
    # case in which "elevated vs. unelevated" can be distinguished from this bundle alone.
    # Otherwise both remain $null - "not established" - rather than assuming the single
    # context collected represents one side or the other.
    $elevatedVisible   = $null
    $unelevatedVisible = $null
    if ($null -ne $currentContextPresent -and $null -ne $otherContextPresent) {
        # LiveMounts_CurrentContext is elevated when this collector ran elevated (recorded by
        # Export-DriveMapEvidence.ps1's own $isElevated check, not carried in the bundle) -
        # since that flag does not travel with the bundle today, treat CurrentContext as the
        # elevated view and OtherTokenContext as the filtered view, which matches the only
        # scenario in which Export-DriveMapEvidence.ps1 actually attempts to collect the
        # second context (it only tries when it is itself running elevated).
        $elevatedVisible   = $currentContextPresent
        $unelevatedVisible = $otherContextPresent
    }

    # GppApplied: did a 4096 ("Preference item applied successfully") event show up at all?
    # Absence of GPP events is NEVER treated as "did not apply" (section 6.1, trap 2) - it is
    # CouldNotCollect on the underlying GppEvents collector, which already yields $null here.
    $gppApplied = $null
    if ($gppEvents -and $gppEvents.State -ne 'CouldNotCollect') {
        $gppApplied = [bool](@($gppEvents.Data) | Where-Object { $_.Category -eq 'Applied' })
    }

    # TargetingFailures: 4105/4106/8212 rows, re-shaped to {EventId; Gpo}. GppEvents rows (see
    # Export-DriveMapEvidence.ps1) do not carry a GPO name today, so Gpo is left $null rather
    # than fabricated; EventId is the one field this bundle can actually support.
    $targetingFailures = $null
    if ($gppEvents -and $gppEvents.State -ne 'CouldNotCollect') {
        $targetingFailures = @(@($gppEvents.Data) | Where-Object { $_.Category -eq 'TargetingFailed' } | ForEach-Object {
            [PSCustomObject]@{ EventId = $_.Id; Gpo = $null }
        })
    }

    # ScriptDeletions: LogonScriptReferences rows whose Operation is 'Delete', re-shaped to
    # {Source; Line}. $null (never @()) when the collector itself could not run.
    $scriptDeletions = $null
    if ($logonRefs -and $logonRefs.State -ne 'CouldNotCollect') {
        $scriptDeletions = @(@($logonRefs.Data) | Where-Object { $_.Operation -eq 'Delete' } | ForEach-Object {
            [PSCustomObject]@{ Source = $_.ScriptPath; Line = $_.Line }
        })
    }

    [PSCustomObject]@{
        GppApplied              = $gppApplied
        DrivePresent            = $drivePresent
        ScriptDeletions         = $scriptDeletions
        InRegistry              = $inRegistry
        InLiveMounts            = $inLiveMounts
        TargetingFailures       = $targetingFailures
        Action                  = $Action
        FastLogonOptimization   = $FastLogonOptimization
        AlwaysWaitForNetwork    = $AlwaysWaitForNetwork
        ElevatedVisible         = $elevatedVisible
        UnelevatedVisible       = $unelevatedVisible
        EnableLinkedConnections = $EnableLinkedConnections
    }
}

function Get-DriveMapVerdict {
    <#
    .SYNOPSIS
        Implements the design spec's section 6 ranked-cause table: evaluates every rule
        against the flat evidence object, assigns a confidence, and returns the matches
        sorted most-confident first.

    .DESCRIPTION
        Every rule in this function is evaluated independently - a machine can have more
        than one problem at once (section 6: "Evaluate EVERY rule"), so this never
        short-circuits on the first match. Three properties are non-negotiable and each has
        a dedicated regression test:

          1. This function never returns an empty array. When no rule matches, it returns
             the explicit 'No cause identified' verdict listing what was ruled out and what
             to collect next - an unresolved case is a finding with a next step, never a
             blank page (section 6, final table row).
          2. No verdict's Remediation ever recommends setting NoBackgroundPolicy to 0.
             Microsoft explicitly advises against it and documents that it does not reliably
             work (section 3.3, remediation option 3; section 6.1, trap 4).
          3. Split-token visibility (elevated/unelevated mismatch with
             EnableLinkedConnections not 1) is reported as exactly that - a VISIBILITY
             ARTIFACT - never phrased as a disappearance, because diagnosing it as a Group
             Policy problem sends a technician to audit a GPO for a drive that was never
             missing (section 3.4; section 6.1, trap 3).

        THE THREE-STATE DISTINCTION IN THIS FUNCTION: every evidence property may be $null,
        meaning "not established" (the source collector returned CouldNotCollect somewhere
        upstream, in ConvertFrom-EvidenceBundle). A rule that needs a condition to be
        POSITIVELY true (e.g. "GPP applied") only fires when that property is exactly
        $true - never when it is $null. A rule that needs a condition to be POSITIVELY false
        (e.g. "drive absent") only fires when that property is exactly $false - never when it
        is $null. This is enforced throughout via explicit "-eq $true" / "-eq $false"
        comparisons rather than PowerShell's truthiness coercion, because $null is falsy in a
        boolean context and would otherwise silently satisfy a "-not $x" check meant only for
        a confirmed-false reading.

    .PARAMETER Evidence
        The flat evidence object (see ConvertFrom-EvidenceBundle's property list, or the
        test file for the exact contract): GppApplied, DrivePresent, ScriptDeletions,
        InRegistry, InLiveMounts, TargetingFailures, Action, FastLogonOptimization,
        AlwaysWaitForNetwork, ElevatedVisible, UnelevatedVisible, EnableLinkedConnections.
    #>
    param(
        [Parameter(Mandatory)][PSCustomObject]$Evidence
    )

    $verdicts = New-Object System.Collections.Generic.List[object]

    function Test-True  { param($Value) $null -ne $Value -and $Value -eq $true }
    function Test-False { param($Value) $null -ne $Value -and $Value -eq $false }

    # CRITICAL: @($null) is a ONE-element array in PowerShell ('@($null).Count' is 1, not
    # 0), so wrapping a $null property (meaning "this collector never ran / could not be
    # established") in @() before counting would make "not established" indistinguishable
    # from "found one real item" - exactly the confident-plausible-wrong-answer failure this
    # entire toolkit exists to prevent, in its own verdict engine. $null must be converted to
    # a genuinely empty array (Count 0) so it can never satisfy a "-gt 0" match; only an
    # ACTUAL populated array (Task 3's ScriptDeletions/TargetingFailures collectors already
    # emit $null - never @() - for a CouldNotCollect source; see ConvertFrom-EvidenceBundle
    # above) may cause a rule below to fire.
    $scriptDeletions = if ($null -eq $Evidence.ScriptDeletions) { @() } else { @($Evidence.ScriptDeletions) }
    $targetingFailures = if ($null -eq $Evidence.TargetingFailures) { @() } else { @($Evidence.TargetingFailures) }

    # ---------------------------------------------------------------------------------
    # Rule 1 (spec 6, row 1 / section 3.5): GPP applied OK + drive absent + a logon-script
    # deletion referencing this letter was found. Microsoft's own scenario guide documents
    # exactly this: every Group Policy event healthy, the drive still gone, because an
    # UNRELATED GPO's logon script deleted it afterward. Confidence High: an actual deletion
    # command was found, naming its source.
    # ---------------------------------------------------------------------------------
    # Defense in depth: even though $scriptDeletions is now guaranteed to be a real,
    # non-empty array whenever this branch is entered (see the $null-vs-empty-array guard
    # above), require at least one entry to actually carry a non-empty Source before
    # rendering the "found in: ..." text, so a malformed entry can never produce a garbled
    # "found in: " / ": " fragment in a real verdict.
    if ($scriptDeletions.Count -gt 0 -and (Test-False $Evidence.DrivePresent) -and (@($scriptDeletions | Where-Object { $_.Source }).Count -gt 0)) {
        $sources = ($scriptDeletions | ForEach-Object { $_.Source } | Where-Object { $_ }) -join ', '
        $lines   = ($scriptDeletions | ForEach-Object { "$($_.Source): $($_.Line)" })
        $verdicts.Add([PSCustomObject]@{
            Cause       = "A logon script deletes the drive after Group Policy maps it (found in: $sources)"
            Confidence  = 'High'
            Evidence    = @($lines)
            Remediation = @(
                "Identify and remove or fix the logon script/GPO named above ($sources) that runs a drive-delete command for ${DriveLetter}:.",
                "Confirm with 'gpresult /h' which GPO actually links that script, then unlink, edit, or deny it for the affected user/computer."
            )
        })
    }

    # ---------------------------------------------------------------------------------
    # Rule 2 (spec 6, row 2 / section 3.3): Replace action + Fast Logon Optimization on +
    # "Always wait for the network" off. The Drive Maps CSE has NoBackgroundPolicy=1 (never
    # called on background refresh) and only applies during SYNCHRONOUS processing; FLO makes
    # logon asynchronous, so the CSE declines and applies only every OTHER logon. This
    # presents exactly as "the drive keeps disappearing" with no configuration change.
    # Confidence High: this is documented as the single highest-value, most common finding
    # in this class of problem (section 3.3 heading).
    # https://learn.microsoft.com/en-us/archive/technet-wiki/12221.group-policy-troubleshooting-drive-maps-preference-extension-replace-mode-only-maps-the-drive-every-other-logon
    # ---------------------------------------------------------------------------------
    if ($Evidence.Action -eq 'Replace' -and (Test-True $Evidence.FastLogonOptimization) -and (Test-False $Evidence.AlwaysWaitForNetwork)) {
        $verdicts.Add([PSCustomObject]@{
            Cause       = 'The drive maps only every other logon (Fast Logon Optimization + Replace-mode CSE behavior)'
            Confidence  = 'High'
            Evidence    = @(
                "Drive Maps action is 'Replace'.",
                'Fast Logon Optimization is enabled, so Group Policy processes asynchronously at logon.',
                "'Always wait for the network at computer startup and logon' is not enabled.",
                'The Drive Maps client-side extension never runs during background refresh (NoBackgroundPolicy=1) and only applies items during synchronous processing, so it declines at this asynchronous logon and applies only on the next one.'
            )
            Remediation = @(
                "Enable 'Always wait for the network at computer startup and logon' (Computer Configuration\Policies\Administrative Templates\System\Logon) to force synchronous processing every logon.",
                'Or change the drive map action to Create with Reconnect enabled, so the mapping persists between logons instead of depending on the CSE reapplying it every time.'
            )
        })
    }

    # ---------------------------------------------------------------------------------
    # Rule 3 (spec 6, row 3): persistent mount recorded in HKCU\Network but absent from live
    # mounts. This means reconnect is FAILING at logon (the share was unreachable), a
    # different root cause and a different fix from Group Policy failing to apply the
    # preference item in the first place.
    # ---------------------------------------------------------------------------------
    if ((Test-True $Evidence.InRegistry) -and (Test-False $Evidence.InLiveMounts) -and (Test-False $Evidence.DrivePresent)) {
        $verdicts.Add([PSCustomObject]@{
            Cause       = 'The drive is registered to reconnect at logon, but the reconnect is failing'
            Confidence  = 'Medium'
            Evidence    = @(
                "${DriveLetter}: is present in HKCU:\Network (a persistent, reconnect-at-logon mapping).",
                "${DriveLetter}: is NOT present among live mounts - the mapping did not actually reconnect."
            )
            Remediation = @(
                'Check whether the target share/server (or DFS namespace) was reachable at the moment of logon - name resolution, network timing, and VPN/profile timing are the most common causes.',
                'Correlate with the network connection profile and any VPN connect/disconnect events around the logon time.'
            )
        })
    }

    # ---------------------------------------------------------------------------------
    # Rule 4 (spec 6, row 4 / section 3.4): visible unelevated, absent elevated, and
    # EnableLinkedConnections is not 1. THIS IS A VISIBILITY ARTIFACT, NOT A DISAPPEARANCE
    # (section 6.1, trap 3) - the wording below deliberately avoids "missing" or "gone" for
    # the drive itself, and instead names elevated-session visibility as the subject.
    # https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command
    # ---------------------------------------------------------------------------------
    # CRITICAL: EnableLinkedConnections must be a CONFIRMED non-1 reading, not merely
    # "anything other than the literal value 1" - native PowerShell comparison ($null -ne 1)
    # evaluates to $true, so an unread/denied registry value ($null, meaning "we could not
    # look") would otherwise satisfy this condition identically to a confirmed 0. Require the
    # value to be non-$null before comparing it to 1, so a genuinely unestablished reading
    # can never fire this rule.
    $enableLinkedConnectionsConfirmedNotOne = ($null -ne $Evidence.EnableLinkedConnections) -and ($Evidence.EnableLinkedConnections -ne 1)
    if ((Test-True $Evidence.UnelevatedVisible) -and (Test-False $Evidence.ElevatedVisible) -and $enableLinkedConnectionsConfirmedNotOne) {
        $verdicts.Add([PSCustomObject]@{
            Cause       = "The drive is not visible in elevated sessions (a visibility artifact of UAC's split token, not a disappearance)"
            Confidence  = 'High'
            Evidence    = @(
                "${DriveLetter}: is visible in the standard (unelevated) session.",
                "${DriveLetter}: is NOT visible in the elevated session.",
                "EnableLinkedConnections is $(if ($null -eq $Evidence.EnableLinkedConnections) { 'not set' } else { $Evidence.EnableLinkedConnections }), not 1."
            )
            Remediation = @(
                'Set EnableLinkedConnections (DWORD) to 1 under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, then restart, so mappings are written to both linked logon sessions.',
                'Do NOT treat this as a Group Policy failure - the drive was mapped successfully; it is only invisible from the elevated token context.',
                'Note: if UAC is set to Prompt for credentials, a third logon session is created in which previously established mappings remain unavailable even after this fix.'
            )
        })
    }

    # ---------------------------------------------------------------------------------
    # Rule 5 (spec 6, row 5): item-level targeting failure events (4105/4106/8212) were
    # recorded for this drive's GPO.
    # ---------------------------------------------------------------------------------
    # Defense in depth: $targetingFailures is guaranteed non-empty here (see the
    # $null-vs-empty-array guard above), but also require at least one entry to carry a
    # non-empty EventId before rendering, so a malformed entry can never produce a garbled
    # "Targeting-failure event(s) recorded: ." fragment in a real verdict.
    if ($targetingFailures.Count -gt 0 -and (@($targetingFailures | Where-Object { $_.EventId }).Count -gt 0)) {
        $gpoNames = @($targetingFailures | Where-Object { $_.Gpo } | ForEach-Object { $_.Gpo }) -join ', '
        $eventIds = ($targetingFailures | Where-Object { $_.EventId } | ForEach-Object { $_.EventId }) -join ', '
        $verdicts.Add([PSCustomObject]@{
            Cause       = 'An item-level targeting filter failed, so the drive-map preference item never applied'
            Confidence  = 'Medium'
            Evidence    = @(
                "Targeting-failure event(s) recorded: $eventIds$(if ($gpoNames) { " (GPO: $gpoNames)" })."
            )
            Remediation = @(
                'Resolve the affected user or computer''s group membership against the item-level targeting filter on the Drive Maps preference item.',
                'Cross-reference with Audit-GPDriveMaps.ps1 -CheckGroupOverlap to confirm the targeting groups are actually mutually exclusive for this user.'
            )
        })
    }

    # ---------------------------------------------------------------------------------
    # Fallback (spec 6, final table row): an unresolved case is a finding with a next step,
    # never a blank page. This function must NEVER return an empty array.
    # ---------------------------------------------------------------------------------
    if ($verdicts.Count -eq 0) {
        $ruledOut = New-Object System.Collections.Generic.List[string]
        if ($null -ne $Evidence.GppApplied)              { $ruledOut.Add("GPP applied: $($Evidence.GppApplied)") }
        if ($null -ne $Evidence.DrivePresent)             { $ruledOut.Add("Drive currently present: $($Evidence.DrivePresent)") }
        if ($null -ne $Evidence.InRegistry)               { $ruledOut.Add("Persistent (reconnect) mount registered: $($Evidence.InRegistry)") }
        if ($null -ne $Evidence.InLiveMounts)             { $ruledOut.Add("Live mount present: $($Evidence.InLiveMounts)") }
        if ($null -ne $Evidence.ElevatedVisible)          { $ruledOut.Add("Visible in the elevated session: $($Evidence.ElevatedVisible)") }
        if ($null -ne $Evidence.UnelevatedVisible)        { $ruledOut.Add("Visible in the unelevated session: $($Evidence.UnelevatedVisible)") }
        $ruledOut.Add("Script deletions found: $($scriptDeletions.Count)")
        $ruledOut.Add("Targeting failures found: $($targetingFailures.Count)")

        $toCollect = New-Object System.Collections.Generic.List[string]
        if ($null -eq $Evidence.GppApplied)        { $toCollect.Add('GPP logging/tracing was not confirmed on - re-run after enabling it (Test-DriveMapLoggingReadiness.ps1 -EnableLogging) and reproducing the fault.') }
        if ($null -eq $Evidence.ElevatedVisible -or $null -eq $Evidence.UnelevatedVisible) { $toCollect.Add('Collect live mounts in BOTH UAC token contexts (run Export-DriveMapEvidence.ps1 once elevated and once not) to rule split-token visibility fully in or out.') }
        $toCollect.Add('Run Watch-DriveMapActivity.ps1 to capture the actual disappearance transition and its timing, which a point-in-time snapshot cannot recover.')
        $toCollect.Add('Review Audit-GPDriveMaps.ps1 output for conflicting drive-letter mappings across GPOs, and Search-SYSVOLScripts.ps1 output for any other script referencing this letter.')

        $verdicts.Add([PSCustomObject]@{
            Cause       = 'No cause identified from the evidence collected so far'
            Confidence  = 'Low'
            Evidence    = @($ruledOut)
            Remediation = @($toCollect)
        })
    }

    # ---------------------------------------------------------------------------------
    # Sort most-confident first. Multiple verdicts at the same confidence keep their
    # original (rule-declaration) order via a stable sort key.
    # ---------------------------------------------------------------------------------
    $rank = @{ High = 0; Medium = 1; Low = 2 }
    $ordered = @($verdicts | Sort-Object -Property @{ Expression = { $rank[$_.Confidence] } })

    # Constraint 2 (section 6.1, trap 4): never recommend NoBackgroundPolicy=0, anywhere.
    foreach ($v in $ordered) {
        if (($v.Remediation -join ' ') -match 'NoBackgroundPolicy\s*=\s*0') {
            throw "Internal error: a verdict recommended NoBackgroundPolicy=0, which Get-DriveMapVerdict must never emit."
        }
    }

    return $ordered
}

function New-CaseSummary {
    <#
    .SYNOPSIS
        Builds the plain-text SUMMARY.txt for a case folder. Pure string work, so it is
        directly testable without a filesystem or a domain.
    #>
    param(
        [string]$DriveLetter,
        [string]$Identity,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Verdicts,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Steps,
        [string]$CaseFolder,
        [string]$GeneratedOn
    )

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('DRIVE MAP INVESTIGATION - CASE SUMMARY')
    $null = $sb.AppendLine('=======================================')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("Generated     : $GeneratedOn")
    $null = $sb.AppendLine("Drive letter  : $(if ($DriveLetter) { "${DriveLetter}:" } else { '(not specified)' })")
    $null = $sb.AppendLine("User          : $(if ($Identity) { $Identity } else { '(not specified)' })")
    $null = $sb.AppendLine("Case folder   : $CaseFolder")
    $null = $sb.AppendLine()

    $null = $sb.AppendLine('--- Verdict ---')
    if ($Verdicts.Count -eq 0) {
        $null = $sb.AppendLine('No verdict was produced. This is unexpected - Get-DriveMapVerdict should always return at least a No-cause-identified result. Treat this as a tooling failure, not a clean result.')
    } else {
        for ($i = 0; $i -lt $Verdicts.Count; $i++) {
            $v = $Verdicts[$i]
            $label = if ($i -eq 0) { 'MOST LIKELY CAUSE' } else { "Also considered ($($i + 1))" }
            $null = $sb.AppendLine("[$label - Confidence: $($v.Confidence)] $($v.Cause)")
            foreach ($e in @($v.Evidence)) { $null = $sb.AppendLine("    Evidence: $e") }
            foreach ($r in @($v.Remediation)) { $null = $sb.AppendLine("    Fix: $r") }
            $null = $sb.AppendLine()
        }
    }

    $null = $sb.AppendLine('--- Steps run ---')
    if ($Steps.Count -eq 0) {
        $null = $sb.AppendLine('No child steps were recorded for this case.')
    } else {
        foreach ($s in $Steps) {
            if ($s.Ran) {
                $exitText = if ($null -ne $s.ExitCode) { " (exit code $($s.ExitCode))" } else { '' }
                $status = if ($s.Error) { "COMPLETED WITH ISSUES$exitText" } else { "OK$exitText" }
            } else {
                $status = 'DID NOT RUN'
            }
            $null = $sb.AppendLine("  [$status] $($s.Step)")
            if ($s.Error) { $null = $sb.AppendLine("      $($s.Error)") }
        }
    }

    $sb.ToString()
}

if ($LoadFunctionsOnly) { return }

# =============================================================================
# Orchestration
# =============================================================================

# Files must be UTF-8 WITH BOM on both PowerShell 5.1 and 7. PowerShell 7's -Encoding UTF8
# omits the BOM; Windows PowerShell 5.1's does not. Writing bytes directly with an explicit
# BOM makes behavior identical and deterministic on both (same approach as every other script
# in this toolkit).
$script:Utf8Bom = New-Object System.Text.UTF8Encoding($true)
function Write-Utf8BomFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, $script:Utf8Bom)
}

Write-Status INFO "Starting drive-map investigation for ${DriveLetter}: on $ComputerName ..."
if ($Identity) { Write-Status INFO "User: $Identity" }

$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

$refPath = Join-Path $scriptRoot 'DriveMapReference.psd1'
try {
    # Loaded here as a fail-fast check: every other script in this toolkit depends on this
    # file, so an orchestration run should stop immediately - before creating a case folder
    # or running any child step - if it is missing or corrupt, rather than surfacing that
    # failure obliquely later inside a child process's own log.
    $ref = Import-PowerShellDataFile -Path $refPath -ErrorAction Stop
    Write-Status INFO "Reference data loaded (GPP source: '$($ref.GppLogSource)', GP Operational log: '$($ref.GpOperationalLogName)')."
} catch {
    Write-Status FAIL "Could not load DriveMapReference.psd1: $($_.Exception.Message)"
    exit 1
}

# ---------------------------------------------------------------------------
# Case folder
# ---------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $scriptRoot 'Cases'
}
$stamp      = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$caseName   = "DriveMapCase_${ComputerName}_${DriveLetter}_$stamp"
$caseFolder = Join-Path $OutputPath $caseName
try {
    New-Item -ItemType Directory -Path $caseFolder -Force -ErrorAction Stop | Out-Null
} catch {
    Write-Status FAIL "Could not create case folder ${caseFolder}: $($_.Exception.Message)"
    exit 1
}
Write-Status INFO "Case folder: $caseFolder"

$steps = New-Object System.Collections.Generic.List[object]

# ---------------------------------------------------------------------------
# Step 1: the readiness gate. Unless -Force, stop when it reports BLIND.
# ---------------------------------------------------------------------------
$gateScript = Join-Path $scriptRoot 'Test-DriveMapLoggingReadiness.ps1'
$gateBlind  = $false
$gateBlindReasons = @()
$readinessJsonPath = $null
if (Test-Path -LiteralPath $gateScript) {
    Write-Status INFO 'Running the logging-readiness gate ...'
    try {
        # Run the gate script as a CHILD PROCESS, exactly as a technician would from the
        # command line - never dot-sourced into this scope. Dot-sourcing a script that
        # declares its own [string]$DriveLetter / $ComputerName / $OutputPath parameters
        # would rebind those names in THIS script's scope to the gate's own (unset) defaults
        # the moment it returns, silently clobbering this orchestrator's own parameters. The
        # gate's console PASS/FAIL/WARN output is parsed for the definitive "CANNOT currently
        # produce trustworthy" statement it prints on a blind result, since re-running its
        # blind-condition function directly would require duplicating its own live
        # registry/event-log reads here.
        $gateLogPath = Join-Path $caseFolder 'ReadinessGate.log'
        $gateArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $gateScript, '-ComputerName', $ComputerName, '-OutputPath', $caseFolder)
        if ($DriveLetter) { $gateArgs += @('-DriveLetter', $DriveLetter) }
        $gateOutput = & powershell.exe @gateArgs 2>&1 | Tee-Object -FilePath $gateLogPath
        $gateText = ($gateOutput | Out-String)
        if ($gateText -match 'CANNOT currently produce trustworthy') {
            $gateBlind = $true
            $gateBlindReasons = @($gateOutput | Where-Object { "$_" -match '^\[FAIL\]\s+-' } | ForEach-Object { ("$_" -replace '^\[FAIL\]\s+-\s*', '').Trim() })
            if ($gateBlindReasons.Count -eq 0) { $gateBlindReasons = @('The readiness gate reported the machine BLIND; see ReadinessGate.log for details.') }
        }
        # The gate writes its machine-readable companion JSON into -OutputPath (this case
        # folder) beside its .txt report, named DriveMapLoggingReadiness_<stamp>.json. Take
        # the newest one so ConvertFrom-EvidenceBundle below can source
        # FastLogonOptimization / AlwaysWaitForNetwork / EnableLinkedConnections from it
        # rather than never populating those verdict-critical properties at all.
        $newestReadinessJson = Get-ChildItem -LiteralPath $caseFolder -Filter 'DriveMapLoggingReadiness_*.json' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($newestReadinessJson) { $readinessJsonPath = $newestReadinessJson.FullName }
        $steps.Add([PSCustomObject]@{ Step = 'Logging readiness gate'; Script = 'Test-DriveMapLoggingReadiness.ps1'; Ran = $true; ExitCode = $LASTEXITCODE; Error = '' })
    } catch {
        Write-Status WARN "Could not run the readiness gate: $($_.Exception.Message)"
        $steps.Add([PSCustomObject]@{ Step = 'Logging readiness gate'; Script = 'Test-DriveMapLoggingReadiness.ps1'; Ran = $false; ExitCode = $null; Error = $_.Exception.Message })
    }
} else {
    Write-Status WARN "Readiness gate script not found beside this script ($gateScript) - skipping. Evidence collected without running the gate first cannot be trusted to distinguish a blind machine from a healthy one."
    $steps.Add([PSCustomObject]@{ Step = 'Logging readiness gate'; Script = 'Test-DriveMapLoggingReadiness.ps1'; Ran = $false; ExitCode = $null; Error = 'Script not found.' })
}

if ($gateBlind -and -not $Force) {
    Write-Status FAIL 'The readiness gate reports this machine BLIND. Evidence collected now would be indistinguishable from a healthy machine.'
    foreach ($r in $gateBlindReasons) { Write-Status FAIL "  - $r" }
    Write-Status WARN 'Re-run with -Force to continue anyway, or resolve the blind condition(s) above first (see Test-DriveMapLoggingReadiness.ps1 -EnableLogging).'
    exit 1
} elseif ($gateBlind -and $Force) {
    Write-Status WARN '-Force supplied: continuing past a BLIND readiness result. Any resulting verdict will rely more heavily on evidence sources that do not depend on GPP logging/tracing.'
}

# ---------------------------------------------------------------------------
# Step 2: endpoint evidence - either a pre-collected bundle, or run the collector now.
# ---------------------------------------------------------------------------
$bundleFolder = $null
if ($EvidencePath) {
    if (Test-Path -LiteralPath $EvidencePath) {
        $bundleFolder = $EvidencePath
        Write-Status PASS "Using pre-collected evidence bundle: $bundleFolder"
    } else {
        Write-Status WARN "-EvidencePath '$EvidencePath' does not exist. Falling back to live collection."
    }
}
if (-not $bundleFolder) {
    $collectorScript = Join-Path $scriptRoot 'Export-DriveMapEvidence.ps1'
    if (Test-Path -LiteralPath $collectorScript) {
        Write-Status INFO 'Collecting endpoint evidence ...'
        $collectArgs = @{ ComputerName = $ComputerName; OutputPath = $caseFolder }
        if ($DriveLetter) { $collectArgs['DriveLetter'] = $DriveLetter }
        $step = Invoke-Step -Name 'Endpoint evidence collection' -ScriptPath $collectorScript -Arguments $collectArgs -CaseFolder $caseFolder
        $steps.Add($step)
        if ($step.Ran -and -not $step.Error) {
            $newest = Get-ChildItem -LiteralPath $caseFolder -Directory -Filter 'DriveMapEvidence_*' -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($newest) { $bundleFolder = $newest.FullName }
        }
    } else {
        Write-Status WARN "Evidence collector script not found beside this script ($collectorScript) - skipping endpoint collection."
        $steps.Add([PSCustomObject]@{ Step = 'Endpoint evidence collection'; Script = 'Export-DriveMapEvidence.ps1'; Ran = $false; ExitCode = $null; Error = 'Script not found.' })
    }
}

# ---------------------------------------------------------------------------
# Step 3: domain-side data - Audit-GPDriveMaps.ps1 and Search-SYSVOLScripts.ps1, reused
# unmodified. Section 3.5's documented trap (an unrelated GPO's logon script deleting the
# drive after a healthy GPP apply) is exactly what Search-SYSVOLScripts.ps1 exists to find.
# ---------------------------------------------------------------------------
$auditScript = Resolve-CompanionScript -FileName 'Audit-GPDriveMaps.ps1' -ScriptRoot $scriptRoot
$gpoActionCsvPath = $null
if ($auditScript) {
    $auditArgs = @{ OutputPath = $caseFolder; ExportFormat = 'CSV'; SkipBrowserOpen = $true }
    if ($Identity) { $auditArgs['TargetUser'] = $Identity }
    if ($ComputerName) { $auditArgs['TargetComputer'] = $ComputerName }
    $steps.Add((Invoke-Step -Name 'Domain drive maps (GPO audit)' -ScriptPath $auditScript -Arguments $auditArgs -CaseFolder $caseFolder))
    # Audit-GPDriveMaps.ps1 (reused unmodified) writes "<ReportName>-AllMappings.csv" with
    # DriveLetter/Action columns among others - this is the source ConvertFrom-EvidenceBundle
    # reads Action from below. Located by suffix rather than assuming the full report-name
    # timestamp pattern, since that naming is this reused script's own implementation detail.
    $mappingsCsv = Get-ChildItem -LiteralPath $caseFolder -Filter '*-AllMappings.csv' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($mappingsCsv) { $gpoActionCsvPath = $mappingsCsv.FullName }
} else {
    Write-Status WARN 'Audit-GPDriveMaps.ps1 was not found beside this script or in a sibling AD-GroupPolicy-DriveMaps folder - skipping the GPO-side audit.'
    $steps.Add([PSCustomObject]@{ Step = 'Domain drive maps (GPO audit)'; Script = 'Audit-GPDriveMaps.ps1'; Ran = $false; ExitCode = $null; Error = 'Script not found.' })
}

$sysvolScript = Resolve-CompanionScript -FileName 'Search-SYSVOLScripts.ps1' -ScriptRoot $scriptRoot
if ($sysvolScript -and $DriveLetter) {
    $sysvolArgs = @{ SearchPattern = "${DriveLetter}:"; OutputPath = $caseFolder }
    $steps.Add((Invoke-Step -Name 'SYSVOL script search' -ScriptPath $sysvolScript -Arguments $sysvolArgs -CaseFolder $caseFolder))
} elseif (-not $sysvolScript) {
    Write-Status WARN 'Search-SYSVOLScripts.ps1 was not found beside this script or in a sibling Search-SYSVOLScripts folder - skipping the SYSVOL search.'
    $steps.Add([PSCustomObject]@{ Step = 'SYSVOL script search'; Script = 'Search-SYSVOLScripts.ps1'; Ran = $false; ExitCode = $null; Error = 'Script not found.' })
} else {
    Write-Status WARN 'No -DriveLetter supplied - skipping the SYSVOL search (nothing to search for).'
    $steps.Add([PSCustomObject]@{ Step = 'SYSVOL script search'; Script = 'Search-SYSVOLScripts.ps1'; Ran = $false; ExitCode = $null; Error = 'No -DriveLetter supplied.' })
}

# ---------------------------------------------------------------------------
# Step 4: flatten the bundle and call the verdict logic.
# ---------------------------------------------------------------------------
$verdicts = @()
if ($bundleFolder) {
    $manifestPath = Join-Path $bundleFolder 'manifest.json'
    if (Test-Path -LiteralPath $manifestPath) {
        try {
            $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

            # Reconstruct a Results hashtable of New-CollectionResult-shaped objects from the
            # manifest + per-collector CSVs, so ConvertFrom-EvidenceBundle can consume it the
            # same way it would consume the collector's own in-memory $results hashtable.
            $bundleResults = @{}
            $csvMap = @{
                'PersistentMounts'             = 'PersistentMounts.csv'
                'LiveMounts_CurrentContext'    = 'LiveMounts_CurrentContext.csv'
                'GppEvents'                    = 'GppEvents.csv'
                'LogonScriptReferences'        = 'LogonScriptReferences.csv'
            }
            foreach ($name in @('PersistentMounts','LiveMounts_CurrentContext','LiveMounts_OtherTokenContext','GppEvents','LogonScriptReferences')) {
                $state = if ($manifest.Collected -contains $name) { 'Found' }
                         elseif ($manifest.Empty -contains $name) { 'EmptyButValid' }
                         else { 'CouldNotCollect' }
                $data = @()
                if ($state -eq 'Found' -and $csvMap.ContainsKey($name)) {
                    $csvPath = Join-Path $bundleFolder $csvMap[$name]
                    if (Test-Path -LiteralPath $csvPath) { $data = @(Import-Csv -LiteralPath $csvPath) }
                }
                $reason = $null
                if ($state -eq 'CouldNotCollect') {
                    $failedRow = @($manifest.Failed) | Where-Object { $_.Collector -eq $name } | Select-Object -First 1
                    $reason = if ($failedRow) { $failedRow.Reason } else { "Collector '$name' was not recorded in the evidence manifest." }
                }
                $bundleResults[$name] = [PSCustomObject]@{ State = $state; Data = $data; Reason = $reason }
            }

            $flatEvidence = ConvertFrom-EvidenceBundle -DriveLetter $DriveLetter -Results $bundleResults -ReadinessJsonPath $readinessJsonPath -GpoActionCsvPath $gpoActionCsvPath
            $verdicts = Get-DriveMapVerdict -Evidence $flatEvidence
        } catch {
            Write-Status WARN "Could not parse the evidence bundle's manifest.json: $($_.Exception.Message)"
        }
    } else {
        Write-Status WARN "No manifest.json found in $bundleFolder - cannot build a verdict from this bundle."
    }
} else {
    Write-Status WARN 'No evidence bundle was collected or supplied - producing a verdict from whatever was ruled out is not possible. Writing a no-cause-identified summary.'
    $verdicts = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
        GppApplied = $null; DrivePresent = $null; ScriptDeletions = $null
        InRegistry = $null; InLiveMounts = $null; TargetingFailures = $null
        Action = $null; FastLogonOptimization = $null; AlwaysWaitForNetwork = $null
        ElevatedVisible = $null; UnelevatedVisible = $null; EnableLinkedConnections = $null
    })
}

Write-Host ''
Write-Status INFO "Verdict: $($verdicts[0].Cause) (Confidence: $($verdicts[0].Confidence))"
foreach ($v in $verdicts) {
    $level = switch ($v.Confidence) { 'High' { 'FAIL' }; 'Medium' { 'WARN' }; default { 'INFO' } }
    Write-Status $level "[$($v.Confidence)] $($v.Cause)"
}

# ---------------------------------------------------------------------------
# Step 5: write SUMMARY.txt, then hand off to Task 6's HTML report if present.
# ---------------------------------------------------------------------------
$generatedOn = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$summaryText = New-CaseSummary -DriveLetter $DriveLetter -Identity $Identity -Verdicts $verdicts -Steps $steps.ToArray() -CaseFolder $caseFolder -GeneratedOn $generatedOn
$summaryPath = Join-Path $caseFolder 'SUMMARY.txt'
try {
    Write-Utf8BomFile -Path $summaryPath -Content $summaryText
    Write-Status PASS "Case summary written: $summaryPath"
} catch {
    Write-Status FAIL "Could not write SUMMARY.txt: $($_.Exception.Message)"
}

# Task 6's New-DriveMapCaseReport.ps1 looks for a machine-readable Verdicts.json in the case
# folder and renders the investigation's CONCLUSIONS from it; without this file the HTML
# report can show the evidence collected but never the verdicts reached, silently defeating
# "findings on screen at open" (spec section 7). Written even for the single 'No cause
# identified' verdict - that is a real finding the report must display, never an empty file.
# -InputObject @($verdicts) (not a bare pipeline) guarantees the JSON's top level is always
# an array, even for exactly one verdict - ConvertTo-Json only collapses a single PIPELINE
# item to a bare object, not a single element of an array passed via -InputObject, so this
# avoids ever writing a scalar object where the report expects an array. Property order
# within each verdict (Cause, Confidence, Evidence, Remediation) and verdict order
# (most-confident first, as Get-DriveMapVerdict already returns them) are both preserved
# exactly as produced.
$verdictsJsonPath = Join-Path $caseFolder 'Verdicts.json'
try {
    $verdictsJson = ConvertTo-Json -InputObject @($verdicts) -Depth 6
    Write-Utf8BomFile -Path $verdictsJsonPath -Content $verdictsJson
    Write-Status PASS "Verdicts written: $verdictsJsonPath"
} catch {
    Write-Status FAIL "Could not write Verdicts.json: $($_.Exception.Message)"
}

# Task 6's New-DriveMapCaseReport.ps1 renders tabs 2-4 (intended state, endpoint state,
# interference) from the SAME flattened evidence object used to produce the verdicts above
# ($flatEvidence, or - when no bundle was collected/supplied - the all-$null placeholder
# object built in that branch). Without persisting it, the report has no way to populate
# those tabs and they render their "not established" fallback text even on a fully
# successful run. Written here (not recomputed in the report) so ConvertFrom-EvidenceBundle's
# three-state handling - the $null-vs-$false / $null-vs-@() distinction that took two fix
# rounds to get right (see that function's own comments) - has exactly one implementation,
# with its own regression tests, rather than a second copy in the report script that could
# silently drift from it. $flatEvidence is guaranteed to be defined by this point: it is set
# in the "bundle collected" branch above, and the "no bundle" branch's else-clause builds the
# same-shaped all-$null object and passes it straight into Get-DriveMapVerdict without
# assigning it to $flatEvidence - so guard for that explicitly rather than assume.
if ($null -eq $flatEvidence) {
    $flatEvidence = [PSCustomObject]@{
        GppApplied = $null; DrivePresent = $null; ScriptDeletions = $null
        InRegistry = $null; InLiveMounts = $null; TargetingFailures = $null
        Action = $null; FastLogonOptimization = $null; AlwaysWaitForNetwork = $null
        ElevatedVisible = $null; UnelevatedVisible = $null; EnableLinkedConnections = $null
    }
}
$evidenceJsonPath = Join-Path $caseFolder 'Evidence.json'
try {
    # -InputObject (not a bare pipeline) preserves $null properties as JSON null rather than
    # ConvertTo-Json silently dropping them, and keeps a single-element array property (e.g.
    # ScriptDeletions with exactly one deletion - the most likely real-world shape) from being
    # unwrapped to a bare object by the pipeline the way Verdicts.json's own fix above already
    # had to guard against for the top-level array.
    $evidenceJson = ConvertTo-Json -InputObject $flatEvidence -Depth 6
    Write-Utf8BomFile -Path $evidenceJsonPath -Content $evidenceJson
    Write-Status PASS "Evidence written: $evidenceJsonPath"
} catch {
    Write-Status FAIL "Could not write Evidence.json: $($_.Exception.Message)"
}

$reportScript = Resolve-CompanionScript -FileName 'New-DriveMapCaseReport.ps1' -ScriptRoot $scriptRoot
if ($reportScript) {
    $reportArgs = @{ CaseFolder = $caseFolder; OutputPath = $caseFolder }
    $steps.Add((Invoke-Step -Name 'HTML case report' -ScriptPath $reportScript -Arguments $reportArgs -CaseFolder $caseFolder))
} else {
    Write-Status INFO "New-DriveMapCaseReport.ps1 (Task 6) was not found beside this script - skipping the HTML report. SUMMARY.txt above is still complete."
}

Write-Status PASS "Investigation complete. Case folder: $caseFolder"
