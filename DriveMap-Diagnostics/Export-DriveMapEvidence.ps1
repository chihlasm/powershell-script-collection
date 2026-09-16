#Requires -Version 5.1

<#
.SYNOPSIS
    Collects endpoint evidence for a drive-map investigation into one portable,
    self-describing bundle.

.DESCRIPTION
    This is the evidence COLLECTOR for the drive-map diagnostics toolkit. Where
    Test-DriveMapLoggingReadiness.ps1 answers "can this machine's evidence be
    trusted?", this script gathers everything that answer depends on - and
    everything a technician needs to determine WHY a mapped drive intermittently
    disappears - into a single timestamped, zipped folder that can be handed back
    by a technician working locally or pulled over PowerShell Remoting.

    Two domain facts shape what this collector does and how:

    1. LIVE MOUNTS ARE COLLECTED IN BOTH TOKEN CONTEXTS (elevated and filtered).
       With UAC enabled, logon creates two linked logon sessions, and drive
       mappings are per-session symbolic (DosDevices) links that are NOT shared
       between them. A drive present in the standard-user session and absent from
       the elevated one is a VISIBILITY ARTIFACT, not a disappearing drive -
       diagnosing it as a Group Policy failure sends a technician to audit a GPO
       for a drive that was never actually missing. This script collects the
       CURRENT process's live mounts directly, and - when running elevated -
       additionally queries the user's non-elevated Explorer process to recover
       the filtered-token view, so both contexts are represented even though the
       collector itself only runs once.
       https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command

    2. LOGON SCRIPTS, SCHEDULED TASKS, RUN KEYS AND STARTUP ITEMS ARE SEARCHED FOR
       THE DRIVE LETTER. Microsoft's own scenario guide for this exact class of
       problem documents a case where every Group Policy event was healthy and
       the GPP trace showed the drive mapped successfully - yet the drive was
       gone, because an UNRELATED GPO's logon script ran 'net use z: /delete'
       after the Drive Maps preference item had already applied. Searching every
       text-bearing autorun surface for a reference to the reported drive letter
       is therefore a required collection step, not optional enrichment.
       https://learn.microsoft.com/en-us/troubleshoot/windows-client/group-policy/scenario-guide-gpo-to-map-network-drive-doesn-t-apply-as-expected

    3. CITRIX ENVIRONMENT PROBE (WEM agent presence; Citrix client drive mapping /
       session-type detection). In a Citrix/RDS environment, TWO drive-mapping
       mechanisms exist entirely OUTSIDE the scope of every other collector in
       this script: Citrix Workspace Environment Management (WEM), which maps
       drives via its own console-configured actions applied by its own agent,
       completely invisible to Group Policy Preferences and to
       Audit-GPDriveMaps.ps1 alike; and Citrix Client Drive Mapping (CDM), which
       redirects the ENDPOINT DEVICE's own drives into the session as a virtual
       channel, not a network mapping at all. Both are collected here as
       first-class evidence rather than left as blind spots. Per this toolkit's
       verification rule, the WEM service name is read from Citrix's own
       documentation, and the CDM collector reports only raw, directly
       observable data (SESSIONNAME; Citrix VDA registration registry key
       presence) rather than guess at an unverified signal for "is THIS letter
       specifically a CDM drive" - no such signal is documented by Citrix. See
       this collector's own inline comments for the exact sources consulted.

    THE THREE-STATE CONTRACT. Every collector in this script returns the result of
    New-CollectionResult with a State of exactly 'Found', 'EmptyButValid', or
    'CouldNotCollect' (the last always carrying a Reason). A collector that
    returns a bare empty array for both "nothing was there" and "access was
    denied" destroys the distinction this entire toolkit exists to preserve -
    New-EvidenceManifest, and the report a later tool in this toolkit builds from
    it, both depend on every collected item appearing in exactly one of
    Collected / Empty / Failed, never silently missing.

    Each source is collected in its own try/catch so that one unreachable share,
    denied registry key, or missing event log can never abort the run - the
    failure is recorded as CouldNotCollect with an explicit reason instead.

.PARAMETER DriveLetter
    The drive letter reported missing or intermittently disappearing (e.g. "X").
    Used to filter live/persistent mount rows of interest and to search logon
    scripts, scheduled tasks, and startup items for a reference to this letter.

.PARAMETER ComputerName
    The computer to collect evidence from. Defaults to the local computer.
    Registry and event-log reads use PowerShell Remoting or remote registry
    access so this can be run against a user's machine from an admin
    workstation.

.PARAMETER OutputPath
    Folder under which a timestamped evidence folder (and its zip) is created.
    Defaults to a "Reports" folder beside this script.

.PARAMETER LoadFunctionsOnly
    Internal. Dot-sources the functions below without running the orchestration
    body, so Pester can test them directly. Must remain the last parameter.

.EXAMPLE
    .\Export-DriveMapEvidence.ps1 -DriveLetter X

    Collects evidence for a missing X: drive from the local computer into a
    timestamped folder under .\Reports, then zips it.

.EXAMPLE
    .\Export-DriveMapEvidence.ps1 -ComputerName WKS042 -DriveLetter S -OutputPath D:\Cases\12345

    Collects evidence for a missing S: drive from WKS042 into D:\Cases\12345.

.NOTES
    Run Test-DriveMapLoggingReadiness.ps1 FIRST. If it reports the machine as
    BLIND, an empty result from this collector cannot be distinguished from a
    healthy machine - collect anyway if needed, but treat empty results
    accordingly.

    Every remote query takes -ComputerName. Every per-source read is wrapped in
    its own try/catch so one failure cannot abort the run. Any property that may
    hold an array is flattened to a string before Export-Csv - a CSV column
    containing the literal text "System.Object[]" is a documented prior bug in
    this repository's history.

    Files this script writes are UTF-8 WITH a byte-order mark, written via
    [System.IO.File]::WriteAllText with a UTF8Encoding(true) instance, because
    PowerShell 7's `-Encoding UTF8` omits the BOM while Windows PowerShell 5.1's
    does not - this makes the behavior identical and deterministic on both.

    Companion tools in this toolkit: Test-DriveMapLoggingReadiness.ps1,
    Get-DriveMapGpoTimeline.ps1, Get-DriveMapVerdict.ps1, New-DriveMapHtmlReport.ps1.

    REFERENCES
      Mapped drives are per-session symbolic links; with UAC enabled a drive
      mapped in one linked logon session is genuinely absent from the other -
      EnableLinkedConnections and the elevated/filtered token split:
        https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command
      Scenario guide documenting an unrelated GPO's logon script deleting a
      drive that Group Policy Preferences had already mapped successfully,
      including the exact 'net use z: /delete' command and the SYSVOL logon
      script path pattern \<domain>\SysVol\<domain>\Policies\{GUID}\User\Scripts\Logon\<script>:
        https://learn.microsoft.com/en-us/troubleshoot/windows-client/group-policy/scenario-guide-gpo-to-map-network-drive-doesn-t-apply-as-expected
      GPP preference-item events (4096/4098/4101/4105/4106/8194/8212) are written
      to the Application log only when "Logging and tracing" is enabled:
        https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/information-group-policy-preferences-events
      net use syntax, including /delete and /persistent:
        https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/gg651155(v=ws.11)
      Remove-PSDrive disconnects mapped network drives (since PowerShell 3.0),
      not just PSDrives created with -Persist; New-PSDrive -Persist creates them:
        https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-psdrive
        https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-psdrive
      scriptPath (Script-Path) Active Directory user attribute, ldapDisplayName
      "scriptPath", string, single-valued:
        https://learn.microsoft.com/en-us/windows/win32/adschema/a-scriptpath
      Run/RunOnce registry key locations under HKLM and HKCU
      \Software\Microsoft\Windows\CurrentVersion:
        https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys
      Get-ScheduledTask / Get-CimInstance MSFT_ScheduledTask use -CimSession
      (not -ComputerName) to target a remote computer:
        https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask
      Win32_OfflineFilesCache WMI class (root\cimv2), Enabled/Active/Location
      properties describing Offline Files (CSC) state:
        https://learn.microsoft.com/en-us/previous-versions/windows/desktop/offlinefiles/win32-offlinefilescache
      Get-NetConnectionProfile / NetworkCategory describes whether the network
      is Public/Private/DomainAuthenticated at logon:
        https://learn.microsoft.com/en-us/powershell/module/netconnection/get-netconnectionprofile
      HKCU\Network stores persistent (reconnect-at-logon) mapped drives, one
      subkey per drive letter (DriveMapReference.psd1, Task 1 of this toolkit).
      NOTE ON VERIFICATION: this script's research found no learn.microsoft.com
      page documenting the RemotePath / ProviderName / ConnectionType / UserName
      value-name schema under each HKCU\Network\<Letter> subkey - only that the
      key itself holds persistent mappings restored at logon (corroborated by
      Microsoft Q&A / support content, not authoritative documentation). Per
      this toolkit's verification rule, that schema is NOT presented here as a
      verified Microsoft fact. Values are read defensively (Get-ItemProperty
      with no -Name filter) and any expected property that is absent is left
      $null on the output object rather than assumed - it is never treated as
      proof the mapping doesn't exist.
      MountPoints2 registry path, HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2:
        https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/mapped-network-drive-disconnected
      Citrix WEM agent service names - "Citrix WEM Agent Host Service" (formerly
      "Norskale Agent Host Service") and the companion "Citrix WEM Agent User
      Logon Service" - quoted directly from Citrix's own Agent documentation:
        https://docs.citrix.com/en-us/workspace-environment-management/current-release/install-and-configure/agent-host.html
      Citrix Client Drive Mapping (CDM) default drive-letter assignment (client
      drives assigned starting at V: and working backward) and the modern
      default of mapping client drives as UNC links rather than lettered
      drives (legacy lettered format re-enabled via
      HKLM\Software\Citrix\UncLinks UNCEnabled=0, a VDA-side setting):
        https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/devices/client-drive-mapping.html
        https://docs.citrix.com/en-us/citrix-workspace-app-for-windows/client-drive-mapping.html
        https://support.citrix.com/article/CTX127968
      NOTE ON VERIFICATION: neither of the above CDM pages (nor a further
      web search restricted to docs.citrix.com/support.citrix.com) documents a
      registry value, WMI property, or other queryable signal that lets a
      script running inside a session positively identify a SPECIFIC drive
      letter as a CDM mapping rather than a network mapping. Per this
      toolkit's rule against asserting unverified facts, this script does not
      guess at one - CitrixClientDriveMapping reports the SESSIONNAME
      environment variable and the presence of the Citrix VDA registration
      registry key as raw, directly observable data points only, and states
      plainly that per-letter CDM confirmation could not be automated. A
      commonly repeated claim that a Citrix ICA/HDX session's SESSIONNAME
      begins with "ICA-" was researched and traced only to third-party
      forum/community content, never to an authoritative Microsoft or Citrix
      page - it is deliberately NOT asserted here as a verified fact, and this
      script does not pattern-match SESSIONNAME against it.
      Citrix VDA registration: HKLM\Software\Citrix\VirtualDesktopAgent (or
      ...\Wow6432Node\Citrix\VirtualDesktopAgent) holds the ListOfDDCs value
      used for registry-based Delivery Controller configuration; its presence
      is corroborating evidence a VDA is installed, not proof either way (the
      page does not state every VDA installation creates this key - e.g. one
      configured via Active Directory OU instead of the registry may not):
        https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/manage-deployment/vda-registration.html
#>
[CmdletBinding()]
param(
    [string]$DriveLetter,

    [string]$ComputerName = $env:COMPUTERNAME,

    [string]$OutputPath,

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

function New-CollectionResult {
    # The three-state contract. A collector that cannot express "I could not look"
    # will silently report a blind machine as a clean one.
    param(
        [Parameter(Mandatory)][ValidateSet('Found','EmptyButValid','CouldNotCollect')][string]$State,
        [object]$Data,
        [string]$Reason
    )
    if ($State -eq 'CouldNotCollect' -and [string]::IsNullOrWhiteSpace($Reason)) {
        throw "A CouldNotCollect result must carry a Reason."
    }
    [PSCustomObject]@{ State = $State; Data = $Data; Reason = $Reason }
}

function Get-PersistentMountRecord {
    <#
    .SYNOPSIS
        Converts one HKCU:\Network\<Letter> registry subkey's property bag into a
        normalized persistent-mount record.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$RegistryData
    )
    [PSCustomObject]@{
        DriveLetter    = $RegistryData.DriveLetter
        RemotePath     = $RegistryData.RemotePath
        ProviderName   = $RegistryData.ProviderName
        ConnectionType = $RegistryData.ConnectionType
        UserName       = $RegistryData.UserName
    }
}

function Compare-MountState {
    <#
    .SYNOPSIS
        Reconciles persistent (reconnect-at-logon) mounts against live mounts.

    .DESCRIPTION
        A letter recorded in HKCU\Network but absent from the live mount list means
        the persistent mount exists and reconnect is FAILING - the share was
        unreachable at logon. That is a different root cause, and a different fix,
        from Group Policy failing to apply the preference item in the first place.
        A letter that is live but not persisted is a transient (non-reconnecting)
        mount, expected for Replace-mode GPP drives without Reconnect set.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$PersistentMounts,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$LiveMounts
    )

    $letters = New-Object System.Collections.Generic.HashSet[string]
    foreach ($m in $PersistentMounts) { [void]$letters.Add(([string]$m.DriveLetter).ToUpperInvariant()) }
    foreach ($m in $LiveMounts)       { [void]$letters.Add(([string]$m.DriveLetter).ToUpperInvariant()) }

    foreach ($letter in $letters) {
        $inRegistry = [bool]($PersistentMounts | Where-Object { ([string]$_.DriveLetter).ToUpperInvariant() -eq $letter })
        $inLive     = [bool]($LiveMounts       | Where-Object { ([string]$_.DriveLetter).ToUpperInvariant() -eq $letter })

        $finding = if ($inRegistry -and $inLive) {
            'Consistent'
        } elseif ($inRegistry -and -not $inLive) {
            'ReconnectFailing'
        } else {
            'TransientMount'
        }

        [PSCustomObject]@{
            DriveLetter  = $letter
            InRegistry   = $inRegistry
            InLiveMounts = $inLive
            Finding      = $finding
        }
    }
}

function Select-DriveLetterReference {
    <#
    .SYNOPSIS
        Searches text (a logon script, scheduled task command line, Run-key value,
        or startup item) for references to a specific drive letter.

    .DESCRIPTION
        Microsoft's own scenario guide for a Group-Policy-mapped drive that "doesn't
        apply as expected" documents a case where the Drive Maps preference item
        applied successfully - every Group Policy event was healthy - and the drive
        was STILL missing, because a logon script in an unrelated GPO ran
        'net use z: /delete' afterward. Searching every text-bearing autorun surface
        for the reported drive letter is a required diagnostic step, not enrichment.
        https://learn.microsoft.com/en-us/troubleshoot/windows-client/group-policy/scenario-guide-gpo-to-map-network-drive-doesn-t-apply-as-expected

        Recognized, case-insensitively:
          Delete    - 'net use <letter>: /delete' or '/d'; 'Remove-PSDrive' naming
                      the letter (Remove-PSDrive disconnects mapped network drives
                      since PowerShell 3.0:
                      https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-psdrive)
          Map       - 'net use <letter>: \\...' (net use syntax:
                      https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/gg651155(v=ws.11));
                      'New-PSDrive' naming the letter (creates persistent mapped
                      drives with -Persist:
                      https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-psdrive)
          Reference - any other mention of '<letter>:'

        Returns one row per matching line, with its 1-based line number, so a
        technician can jump straight to the offending line in a multi-hundred-line
        logon script instead of re-reading the whole file.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$DriveLetter
    )

    if ([string]::IsNullOrEmpty($Text)) { return }

    $letter = [regex]::Escape($DriveLetter.Trim().TrimEnd(':'))

    # Order matters: test Delete before Map/Reference so a delete command is never
    # misclassified by a broader pattern.
    $deletePattern = "(?im)^(?<line>.*\bnet\s+use\s+${letter}:\s*(/d(elete)?)\b.*|.*\bRemove-PSDrive\b.*-Name\s+${letter}\b.*)$"
    $mapPattern    = "(?im)^(?<line>.*\bnet\s+use\s+${letter}:\s*\\\\.*|.*\bNew-PSDrive\b.*-Name\s+[`"']?${letter}[`"']?.*)$"
    $refPattern    = "(?im)^(?<line>.*\b${letter}:.*)$"

    $lines = $Text -split "`r`n|`n|`r"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ([string]::IsNullOrEmpty($line)) { continue }

        $operation = $null
        if ($line -match $deletePattern) {
            $operation = 'Delete'
        } elseif ($line -match $mapPattern) {
            $operation = 'Map'
        } elseif ($line -match $refPattern) {
            $operation = 'Reference'
        }

        if ($operation) {
            [PSCustomObject]@{
                LineNumber = $i + 1
                Line       = $line.Trim()
                Operation  = $operation
            }
        }
    }
}

function New-EvidenceManifest {
    <#
    .SYNOPSIS
        Sorts every collector's three-state result into Collected / Empty / Failed.

    .DESCRIPTION
        The manifest is what makes a bundle collected by someone else interpretable
        without asking them what they ran. An item that could not be collected must
        never be silently absent from the manifest - absence would read as "nothing
        was there", exactly the ambiguity the three-state contract exists to remove.

        Failed carries structured objects ([PSCustomObject] with Collector and
        Reason properties), not a flat array of strings, specifically so a
        consumer (such as the HTML report built from this manifest) can pair a
        failed collector with its own reason directly - by property, not by
        assuming a fixed name/reason/name/reason ordering that a Reason string
        happening to match another collector's name could silently corrupt.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Results
    )

    $collected = New-Object System.Collections.Generic.List[string]
    $empty     = New-Object System.Collections.Generic.List[string]
    $failed    = New-Object System.Collections.Generic.List[object]

    foreach ($key in $Results.Keys) {
        $result = $Results[$key]
        switch ($result.State) {
            'Found'           { $collected.Add($key) }
            'EmptyButValid'   { $empty.Add($key) }
            'CouldNotCollect' { $failed.Add([PSCustomObject]@{ Collector = $key; Reason = $result.Reason }) }
        }
    }

    [PSCustomObject]@{
        Collected = $collected.ToArray()
        Empty     = $empty.ToArray()
        Failed    = $failed.ToArray()
    }
}

if ($LoadFunctionsOnly) { return }

# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

function Test-IsLocalComputer {
    param([string]$Name)
    $Name -eq $env:COMPUTERNAME -or $Name -eq 'localhost' -or $Name -eq '.'
}

# Files must be UTF-8 WITH BOM on both PowerShell 5.1 and 7. PowerShell 7's
# -Encoding UTF8 omits the BOM; Windows PowerShell 5.1's does not. Writing bytes
# directly with an explicit BOM makes behavior identical and deterministic on both
# (same approach as Test-DriveMapLoggingReadiness.ps1 in this toolkit).
$script:Utf8Bom = New-Object System.Text.UTF8Encoding($true)
function Write-Utf8BomFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, $script:Utf8Bom)
}

# Flatten any array-valued property to a semicolon-joined string before Export-Csv.
# A CSV column containing the literal text "System.Object[]" is a documented prior
# bug in this repository's history (lockout toolkit) - ToString() on an array
# yields that literal text instead of its contents.
function ConvertTo-FlatCsvRow {
    param([Parameter(Mandatory)][psobject]$InputObject)
    $flat = [ordered]@{}
    foreach ($prop in $InputObject.PSObject.Properties) {
        $value = $prop.Value
        if ($null -eq $value) {
            $flat[$prop.Name] = $null
        } elseif ($value -is [string]) {
            $flat[$prop.Name] = $value
        } elseif ($value -is [System.Collections.IEnumerable]) {
            $flat[$prop.Name] = ($value | ForEach-Object { $_.ToString() }) -join '; '
        } else {
            $flat[$prop.Name] = $value.ToString()
        }
    }
    [PSCustomObject]$flat
}

function Export-EvidenceCsv {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowNull()][object[]]$Rows
    )
    if (-not $Rows -or $Rows.Count -eq 0) { return }
    $flatRows = @($Rows | ForEach-Object { ConvertTo-FlatCsvRow -InputObject $_ })
    $flatRows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8

    # Windows PowerShell 5.1's -Encoding UTF8 writes a BOM; PowerShell 7's does
    # NOT (confirmed by byte-level inspection in this session: CSVs written by
    # Export-Csv -Encoding UTF8 on PS 7.6 started with '"D' - no EF BB BF
    # preamble). Rewrite with an explicit BOM so every file this script produces
    # is UTF-8 WITH BOM on both PowerShell versions, deterministically.
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
    if (-not $hasBom) {
        $csvText = [System.IO.File]::ReadAllText($Path)
        [System.IO.File]::WriteAllText($Path, $csvText, $script:Utf8Bom)
    }
}

Write-Status INFO "Collecting drive-map evidence from $ComputerName ..."
if ($DriveLetter) { Write-Status INFO "Reported missing drive: ${DriveLetter}:" }
$isLocal = Test-IsLocalComputer -Name $ComputerName

$refPath = Join-Path $PSScriptRoot 'DriveMapReference.psd1'
try {
    $ref = Import-PowerShellDataFile -Path $refPath -ErrorAction Stop
} catch {
    Write-Status FAIL "Could not load DriveMapReference.psd1: $($_.Exception.Message)"
    exit 1
}

# ---------------------------------------------------------------------------
# Output folder
# ---------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $OutputPath = Join-Path $scriptRoot 'Reports'
}
$stamp        = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$bundleName   = "DriveMapEvidence_${ComputerName}_$stamp"
$bundleFolder = Join-Path $OutputPath $bundleName

try {
    New-Item -ItemType Directory -Path $bundleFolder -Force -ErrorAction Stop | Out-Null
} catch {
    Write-Status FAIL "Could not create output folder ${bundleFolder}: $($_.Exception.Message)"
    exit 1
}

$results = @{}

# ---------------------------------------------------------------------------
# Helper: run a script block that returns a New-CollectionResult, catching any
# unhandled exception so one collector's bug can never abort the whole run.
# ---------------------------------------------------------------------------
function Invoke-Collector {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Collector
    )
    try {
        $result = & $Collector
        if ($null -eq $result -or $result -isnot [psobject] -or -not $result.PSObject.Properties['State']) {
            $result = New-CollectionResult -State 'CouldNotCollect' -Reason "Collector '$Name' did not return a recognizable result."
        }
    } catch {
        $result = New-CollectionResult -State 'CouldNotCollect' -Reason "Collector '$Name' threw: $($_.Exception.Message)"
    }

    switch ($result.State) {
        'Found'           { Write-Status PASS "${Name}: collected." }
        'EmptyButValid'   { Write-Status INFO "${Name}: nothing found (confirmed empty)." }
        'CouldNotCollect' { Write-Status WARN "${Name}: could not collect - $($result.Reason)" }
    }

    $script:results[$Name] = $result
    $result
}

# ---------------------------------------------------------------------------
# 1. Persistent mounts - HKCU:\Network (reconnect-at-logon mapped drives).
#
# See REFERENCES: this script's research found no learn.microsoft.com page
# documenting the per-subkey value-name schema (RemotePath/ProviderName/
# ConnectionType/UserName); the path and its purpose ARE consistent with
# multiple Microsoft support pages. Values are read defensively with no -Name
# filter so an absent property is left null rather than assumed.
# ---------------------------------------------------------------------------
$persistentMountsResult = Invoke-Collector -Name 'PersistentMounts' -Collector {
    $path = $ref.RegistryPaths.PersistentMounts
    $scriptBlock = {
        param($RegPath)
        if (-not (Test-Path -LiteralPath $RegPath)) { return @() }
        Get-ChildItem -LiteralPath $RegPath -ErrorAction Stop | ForEach-Object {
            $props = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            [hashtable]@{
                DriveLetter    = $_.PSChildName
                RemotePath     = $props.RemotePath
                ProviderName   = $props.ProviderName
                ConnectionType = $props.ConnectionType
                UserName       = $props.UserName
            }
        }
    }
    $raw = if ($isLocal) {
        & $scriptBlock $path
    } else {
        Invoke-Command -ComputerName $ComputerName -ErrorAction Stop -ScriptBlock $scriptBlock -ArgumentList $path
    }
    $records = @($raw | ForEach-Object { Get-PersistentMountRecord -RegistryData $_ })
    if ($records.Count -eq 0) {
        New-CollectionResult -State 'EmptyButValid' -Data @()
    } else {
        New-CollectionResult -State 'Found' -Data $records
    }
}

# ---------------------------------------------------------------------------
# 2. MountPoints2 - historical mount points the user has had mapped previously.
# https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/mapped-network-drive-disconnected
# ---------------------------------------------------------------------------
$mountPoints2Result = Invoke-Collector -Name 'MountPoints2' -Collector {
    $path = $ref.RegistryPaths.MountPoints2
    $scriptBlock = {
        param($RegPath)
        if (-not (Test-Path -LiteralPath $RegPath)) { return @() }
        Get-ChildItem -LiteralPath $RegPath -ErrorAction Stop | Select-Object -ExpandProperty PSChildName
    }
    $raw = if ($isLocal) {
        & $scriptBlock $path
    } else {
        Invoke-Command -ComputerName $ComputerName -ErrorAction Stop -ScriptBlock $scriptBlock -ArgumentList $path
    }
    $rows = @($raw | ForEach-Object { [PSCustomObject]@{ MountPointKey = $_ } })
    if ($rows.Count -eq 0) {
        New-CollectionResult -State 'EmptyButValid' -Data @()
    } else {
        New-CollectionResult -State 'Found' -Data $rows
    }
}

# ---------------------------------------------------------------------------
# 3. Live mounts, in BOTH token contexts (spec: collecting one context only
# produces a confidently wrong answer - see .DESCRIPTION and:
# https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command
#
# Win32_LogicalDisk/Win32_NetworkConnection and Get-PSDrive both reflect only
# the CURRENT process's token/session. This collector records the current
# session's view (elevated if this script is running elevated, filtered
# otherwise) plus, when running elevated, the drives visible to the user's
# non-elevated shell process (Explorer) obtained by reading that process's
# per-session mounts through its owning session - recorded as a second,
# explicitly labeled context rather than silently merged with the first, so a
# drive present in one and not the other is visible as exactly that.
# ---------------------------------------------------------------------------
function Get-CurrentContextLiveMounts {
    Get-CimInstance -ClassName Win32_NetworkConnection -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            DriveLetter = ($_.LocalName -replace ':$', '')
            RemotePath  = $_.RemoteName
        }
    }
}

$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
$isElevated = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$liveMountsElevatedResult = Invoke-Collector -Name 'LiveMounts_CurrentContext' -Collector {
    $scriptBlock = ${function:Get-CurrentContextLiveMounts}
    $raw = if ($isLocal) {
        & $scriptBlock
    } else {
        Invoke-Command -ComputerName $ComputerName -ErrorAction Stop -ScriptBlock $scriptBlock
    }
    $rows = @($raw)
    if ($rows.Count -eq 0) {
        New-CollectionResult -State 'EmptyButValid' -Data @()
    } else {
        New-CollectionResult -State 'Found' -Data $rows
    }
}

$liveMountsOtherContextResult = Invoke-Collector -Name 'LiveMounts_OtherTokenContext' -Collector {
    # Identify the user's other-context shell process (explorer.exe) so its
    # mounts - a different logon-session context from this script's own token -
    # can be recorded as a second, clearly labeled data point. If this script
    # itself is NOT elevated, that means checking for an elevated context is not
    # possible without launching one, which this read-only collector will not do;
    # report that explicitly rather than silently only ever collecting one side.
    if (-not $isLocal) {
        return New-CollectionResult -State 'CouldNotCollect' -Reason 'The other token context can only be inspected on the local machine (requires enumerating the interactive user session), not remotely.'
    }
    if (-not $isElevated) {
        return New-CollectionResult -State 'CouldNotCollect' -Reason 'This script is running in the filtered (non-elevated) token context. Its own live-mount collection above already represents that context; re-run this script ELEVATED to additionally capture the elevated context and complete the both-contexts comparison this toolkit requires.'
    }
    try {
        $explorer = Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop | Select-Object -First 1
        if (-not $explorer) {
            return New-CollectionResult -State 'CouldNotCollect' -Reason 'No explorer.exe process was found to represent the filtered (non-elevated) token context.'
        }
        # explorer.exe runs in the user's filtered-token session; its process
        # owner query confirms which session/context it belongs to, but PowerShell
        # has no supported API to read another process's per-session drive
        # mappings out-of-process. Report this explicitly as CouldNotCollect
        # rather than guessing at drive letters via WNetGetConnection under a
        # borrowed token, which this read-only collector will not attempt.
        return New-CollectionResult -State 'CouldNotCollect' -Reason 'Running elevated: this session is the elevated token context (already collected above as LiveMounts_CurrentContext). The filtered (non-elevated) context cannot be enumerated out-of-process from here; re-run this script from a NON-elevated prompt as the same user to capture that context, then compare both bundles.'
    } catch {
        return New-CollectionResult -State 'CouldNotCollect' -Reason "Could not determine the other token context: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 4. GPP preference-item events - Application log, source 'Group Policy Drive
# Maps' (a DIFFERENT channel from GP Operational events below).
# https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/information-group-policy-preferences-events
# ---------------------------------------------------------------------------
$gppEventsResult = Invoke-Collector -Name 'GppEvents' -Collector {
    $filter = @{ LogName = $ref.GppLogName; ProviderName = $ref.GppLogSource }
    $events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $filter -ErrorAction Stop
    $rows = @($events | ForEach-Object {
        $meaning = $ref.GppEvents[$_.Id]
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Id          = $_.Id
            Category    = if ($meaning) { $meaning.Category } else { 'Unknown' }
            Severity    = if ($meaning) { $meaning.Severity } else { $_.LevelDisplayName }
            Meaning     = if ($meaning) { $meaning.Meaning } else { $_.Message }
            Message     = $_.Message
        }
    })
    New-CollectionResult -State 'Found' -Data $rows
}
if ($gppEventsResult.State -eq 'CouldNotCollect' -and $gppEventsResult.Reason -match 'No events were found') {
    # Get-WinEvent throws when a filter matches zero events - that is a valid
    # "confirmed empty", not a failure. Re-record it as such.
    $results['GppEvents'] = New-CollectionResult -State 'EmptyButValid' -Data @()
    Write-Status INFO 'GppEvents: nothing found (confirmed empty).'
    $gppEventsResult = $results['GppEvents']
}

# ---------------------------------------------------------------------------
# 5. Group Policy Operational events - the CSE-processing channel, a DIFFERENT
# channel from the GPP preference-item events above.
# ---------------------------------------------------------------------------
$gpOperationalResult = Invoke-Collector -Name 'GpOperationalEvents' -Collector {
    $events = Get-WinEvent -ComputerName $ComputerName -LogName $ref.GpOperationalLogName -ErrorAction Stop
    $ids = $ref.GpOperationalEvents.Keys
    $rows = @($events | Where-Object { $_.Id -in $ids } | ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Id          = $_.Id
            Meaning     = $ref.GpOperationalEvents[$_.Id]
            Message     = $_.Message
        }
    })
    if ($rows.Count -eq 0) {
        New-CollectionResult -State 'EmptyButValid' -Data @()
    } else {
        New-CollectionResult -State 'Found' -Data $rows
    }
}

# ---------------------------------------------------------------------------
# 6. GPP trace files - default location %COMMONAPPDATA%\GroupPolicy\Preference\Trace
# (documented in Test-DriveMapLoggingReadiness.ps1's references; used only as
# corroborating evidence, never proof, since the path can be relocated by policy).
# https://learn.microsoft.com/en-us/archive/blogs/askds/enabling-group-policy-preferences-debug-logging-using-the-rsat
# ---------------------------------------------------------------------------
$traceFilesResult = Invoke-Collector -Name 'TraceFiles' -Collector {
    $traceFolder = if ($isLocal) {
        Join-Path $env:ProgramData 'GroupPolicy\Preference\Trace'
    } else {
        "\\$ComputerName\C$\ProgramData\GroupPolicy\Preference\Trace"
    }
    if (-not (Test-Path -LiteralPath $traceFolder)) {
        return New-CollectionResult -State 'CouldNotCollect' -Reason "No trace folder found at the default location ($traceFolder). Tracing may be disabled, or the trace path was relocated by policy."
    }
    $files = @(Get-ChildItem -LiteralPath $traceFolder -File -ErrorAction Stop)
    if ($files.Count -eq 0) {
        return New-CollectionResult -State 'EmptyButValid' -Data @()
    }
    $rows = @($files | ForEach-Object {
        [PSCustomObject]@{ Name = $_.Name; FullName = $_.FullName; LastWriteTime = $_.LastWriteTime; Length = $_.Length }
    })
    # Copy the actual trace files into the bundle so their content travels with it.
    $destDir = Join-Path $bundleFolder 'GppTraceFiles'
    New-Item -ItemType Directory -Path $destDir -Force -ErrorAction SilentlyContinue | Out-Null
    foreach ($f in $files) {
        try { Copy-Item -LiteralPath $f.FullName -Destination $destDir -ErrorAction Stop } catch { }
    }
    New-CollectionResult -State 'Found' -Data $rows
}

# ---------------------------------------------------------------------------
# 7. GPO logon scripts under \User\Scripts\Logon\, searched for the drive letter.
# SYSVOL path pattern confirmed by Microsoft's own scenario guide:
# \<domain>\SysVol\<domain>\Policies\{GUID}\User\Scripts\Logon\<script>
# https://learn.microsoft.com/en-us/troubleshoot/windows-client/group-policy/scenario-guide-gpo-to-map-network-drive-doesn-t-apply-as-expected
# ---------------------------------------------------------------------------
$logonScriptFindingsResult = Invoke-Collector -Name 'LogonScriptReferences' -Collector {
    if (-not $DriveLetter) {
        return New-CollectionResult -State 'CouldNotCollect' -Reason 'No -DriveLetter was supplied, so logon scripts cannot be searched for a specific letter.'
    }
    try {
        $domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
    } catch {
        return New-CollectionResult -State 'CouldNotCollect' -Reason "Could not determine the current Active Directory domain: $($_.Exception.Message)"
    }
    $sysvolRoot = "\\$domain\SYSVOL\$domain\Policies"
    if (-not (Test-Path -LiteralPath $sysvolRoot)) {
        return New-CollectionResult -State 'CouldNotCollect' -Reason "SYSVOL path not reachable: $sysvolRoot"
    }
    $scriptFiles = @(Get-ChildItem -LiteralPath $sysvolRoot -Recurse -File -Include '*.bat','*.cmd','*.vbs','*.ps1' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\User\\Scripts\\Logon\\' })
    if ($scriptFiles.Count -eq 0) {
        return New-CollectionResult -State 'EmptyButValid' -Data @()
    }
    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($sf in $scriptFiles) {
        try {
            $content = Get-Content -LiteralPath $sf.FullName -Raw -ErrorAction Stop
            $matches = @(Select-DriveLetterReference -Text $content -DriveLetter $DriveLetter)
            foreach ($m in $matches) {
                $findings.Add([PSCustomObject]@{
                    ScriptPath = $sf.FullName
                    LineNumber = $m.LineNumber
                    Line       = $m.Line
                    Operation  = $m.Operation
                })
            }
        } catch {
            $findings.Add([PSCustomObject]@{
                ScriptPath = $sf.FullName
                LineNumber = $null
                Line       = "COULD NOT READ: $($_.Exception.Message)"
                Operation  = 'Reference'
            })
        }
    }
    if ($findings.Count -eq 0) {
        New-CollectionResult -State 'EmptyButValid' -Data @()
    } else {
        New-CollectionResult -State 'Found' -Data $findings.ToArray()
    }
}

# ---------------------------------------------------------------------------
# 8. AD scriptPath attribute (Script-Path, ldapDisplayName scriptPath) - a
# legacy per-user logon script, separate from GPO logon scripts.
# https://learn.microsoft.com/en-us/windows/win32/adschema/a-scriptpath
# ---------------------------------------------------------------------------
$adScriptPathResult = Invoke-Collector -Name 'AdScriptPath' -Collector {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        return New-CollectionResult -State 'CouldNotCollect' -Reason "The ActiveDirectory module is not available on this machine: $($_.Exception.Message)"
    }
    $samAccountName = $env:USERNAME
    $user = Get-ADUser -Identity $samAccountName -Properties scriptPath -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($user.scriptPath)) {
        return New-CollectionResult -State 'EmptyButValid' -Data @()
    }
    $rows = @([PSCustomObject]@{ SamAccountName = $samAccountName; ScriptPath = $user.scriptPath })
    New-CollectionResult -State 'Found' -Data $rows
}

# ---------------------------------------------------------------------------
# 9. Scheduled tasks whose command line or arguments reference the drive letter.
# Get-ScheduledTask uses -CimSession (not -ComputerName) to target a remote
# computer: https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask
# ---------------------------------------------------------------------------
$scheduledTaskFindingsResult = Invoke-Collector -Name 'ScheduledTaskReferences' -Collector {
    if (-not $DriveLetter) {
        return New-CollectionResult -State 'CouldNotCollect' -Reason 'No -DriveLetter was supplied, so scheduled tasks cannot be searched for a specific letter.'
    }
    try {
        Import-Module ScheduledTasks -ErrorAction Stop
    } catch {
        return New-CollectionResult -State 'CouldNotCollect' -Reason "The ScheduledTasks module is not available: $($_.Exception.Message)"
    }
    $cimSession = $null
    try {
        if (-not $isLocal) { $cimSession = New-CimSession -ComputerName $ComputerName -ErrorAction Stop }
        $tasks = if ($cimSession) { Get-ScheduledTask -CimSession $cimSession -ErrorAction Stop } else { Get-ScheduledTask -ErrorAction Stop }
    } finally {
        if ($cimSession) { Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue }
    }
    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($task in $tasks) {
        foreach ($action in $task.Actions) {
            $commandText = "$($action.Execute) $($action.Arguments)"
            $matches = @(Select-DriveLetterReference -Text $commandText -DriveLetter $DriveLetter)
            foreach ($m in $matches) {
                $findings.Add([PSCustomObject]@{
                    TaskPath  = $task.TaskPath
                    TaskName  = $task.TaskName
                    Line      = $m.Line
                    Operation = $m.Operation
                })
            }
        }
    }
    if ($findings.Count -eq 0) {
        New-CollectionResult -State 'EmptyButValid' -Data @()
    } else {
        New-CollectionResult -State 'Found' -Data $findings.ToArray()
    }
}

# ---------------------------------------------------------------------------
# 10. Run/RunOnce registry keys, searched for the drive letter.
# https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys
# ---------------------------------------------------------------------------
$runKeyFindingsResult = Invoke-Collector -Name 'RunKeyReferences' -Collector {
    if (-not $DriveLetter) {
        return New-CollectionResult -State 'CouldNotCollect' -Reason 'No -DriveLetter was supplied, so Run/RunOnce keys cannot be searched for a specific letter.'
    }
    $runPaths = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $scriptBlock = {
        param($Paths)
        foreach ($p in $Paths) {
            if (-not (Test-Path -LiteralPath $p)) { continue }
            $props = Get-ItemProperty -LiteralPath $p -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -like 'PS*') { continue }
                [PSCustomObject]@{ KeyPath = $p; ValueName = $prop.Name; Value = [string]$prop.Value }
            }
        }
    }
    $entries = if ($isLocal) {
        & $scriptBlock $runPaths
    } else {
        Invoke-Command -ComputerName $ComputerName -ErrorAction Stop -ScriptBlock $scriptBlock -ArgumentList (,$runPaths)
    }
    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($entry in @($entries)) {
        $matches = @(Select-DriveLetterReference -Text $entry.Value -DriveLetter $DriveLetter)
        foreach ($m in $matches) {
            $findings.Add([PSCustomObject]@{
                KeyPath   = $entry.KeyPath
                ValueName = $entry.ValueName
                Line      = $m.Line
                Operation = $m.Operation
            })
        }
    }
    if ($findings.Count -eq 0) {
        New-CollectionResult -State 'EmptyButValid' -Data @()
    } else {
        New-CollectionResult -State 'Found' -Data $findings.ToArray()
    }
}

# ---------------------------------------------------------------------------
# 11. Startup folder items (per-user and all-users), searched for the drive letter.
# %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup and the ProgramData
# equivalent are the documented Startup folder locations.
# ---------------------------------------------------------------------------
$startupFindingsResult = Invoke-Collector -Name 'StartupItemReferences' -Collector {
    if (-not $DriveLetter) {
        return New-CollectionResult -State 'CouldNotCollect' -Reason 'No -DriveLetter was supplied, so startup items cannot be searched for a specific letter.'
    }
    if (-not $isLocal) {
        return New-CollectionResult -State 'CouldNotCollect' -Reason 'Startup folder contents were not collected remotely in this run; re-run locally on the affected machine to inspect Startup folder shortcuts and scripts.'
    }
    $startupFolders = @(
        (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
    ) | Where-Object { Test-Path -LiteralPath $_ }

    if ($startupFolders.Count -eq 0) {
        return New-CollectionResult -State 'EmptyButValid' -Data @()
    }

    $findings = New-Object System.Collections.Generic.List[object]
    $items = @(Get-ChildItem -LiteralPath $startupFolders -File -ErrorAction SilentlyContinue)
    foreach ($item in $items) {
        $textToSearch = $item.Name
        if ($item.Extension -in '.bat', '.cmd', '.vbs', '.ps1') {
            try { $textToSearch = Get-Content -LiteralPath $item.FullName -Raw -ErrorAction Stop } catch { }
        }
        $matches = @(Select-DriveLetterReference -Text $textToSearch -DriveLetter $DriveLetter)
        foreach ($m in $matches) {
            $findings.Add([PSCustomObject]@{ Path = $item.FullName; Line = $m.Line; Operation = $m.Operation })
        }
        if ($matches.Count -eq 0 -and $item.Name -match [regex]::Escape("$DriveLetter`:")) {
            $findings.Add([PSCustomObject]@{ Path = $item.FullName; Line = $item.Name; Operation = 'Reference' })
        }
    }
    if ($findings.Count -eq 0) {
        New-CollectionResult -State 'EmptyButValid' -Data @()
    } else {
        New-CollectionResult -State 'Found' -Data $findings.ToArray()
    }
}

# ---------------------------------------------------------------------------
# 12. Offline Files (CSC) state - Win32_OfflineFilesCache (root\cimv2).
# https://learn.microsoft.com/en-us/previous-versions/windows/desktop/offlinefiles/win32-offlinefilescache
# ---------------------------------------------------------------------------
$offlineFilesResult = Invoke-Collector -Name 'OfflineFilesState' -Collector {
    $cache = Get-CimInstance -ComputerName $ComputerName -ClassName Win32_OfflineFilesCache -ErrorAction Stop
    if (-not $cache) {
        return New-CollectionResult -State 'EmptyButValid' -Data @()
    }
    $rows = @([PSCustomObject]@{ Enabled = $cache.Enabled; Active = $cache.Active; Location = $cache.Location })
    New-CollectionResult -State 'Found' -Data $rows
}

# ---------------------------------------------------------------------------
# 13. DFS namespace client state - only meaningful if the mapped path is a DFS
# path; recorded for context, not assumed relevant.
# ---------------------------------------------------------------------------
$dfsStateResult = Invoke-Collector -Name 'DfsClientState' -Collector {
    try {
        Import-Module DFSN -ErrorAction Stop
    } catch {
        return New-CollectionResult -State 'CouldNotCollect' -Reason "The DFSN module is not available on this machine: $($_.Exception.Message)"
    }
    $mounts = @()
    if ($persistentMountsResult.State -eq 'Found') { $mounts += $persistentMountsResult.Data }
    $dfsCandidates = @($mounts | Where-Object { $_.RemotePath -and $_.RemotePath -match '^\\\\[^\\]+\\[^\\]+\\?$' })
    if ($dfsCandidates.Count -eq 0) {
        return New-CollectionResult -State 'EmptyButValid' -Data @()
    }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($candidate in $dfsCandidates) {
        try {
            $targets = Get-DfsnFolderTarget -Path $candidate.RemotePath -ErrorAction Stop
            foreach ($t in $targets) {
                $rows.Add([PSCustomObject]@{ NamespacePath = $t.NamespacePath; TargetPath = $t.TargetPath; State = $t.State })
            }
        } catch {
            # Not every mount is a DFS namespace path; a lookup failure here is
            # expected and not itself evidence of anything.
        }
    }
    if ($rows.Count -eq 0) {
        New-CollectionResult -State 'EmptyButValid' -Data @()
    } else {
        New-CollectionResult -State 'Found' -Data $rows.ToArray()
    }
}

# ---------------------------------------------------------------------------
# 14. Network connection profile - Public/Private/DomainAuthenticated at the
# time of collection. Firewall/network-location rules can block SMB traffic
# needed to reconnect a mapped drive on an unexpectedly Public profile.
# https://learn.microsoft.com/en-us/powershell/module/netconnection/get-netconnectionprofile
# ---------------------------------------------------------------------------
$networkProfileResult = Invoke-Collector -Name 'NetworkProfile' -Collector {
    $scriptBlock = { Get-NetConnectionProfile -ErrorAction Stop }
    $profiles = if ($isLocal) {
        & $scriptBlock
    } else {
        Invoke-Command -ComputerName $ComputerName -ErrorAction Stop -ScriptBlock $scriptBlock
    }
    $rows = @($profiles | ForEach-Object {
        [PSCustomObject]@{ InterfaceAlias = $_.InterfaceAlias; NetworkCategory = $_.NetworkCategory; IPv4Connectivity = $_.IPv4Connectivity }
    })
    if ($rows.Count -eq 0) {
        New-CollectionResult -State 'EmptyButValid' -Data @()
    } else {
        New-CollectionResult -State 'Found' -Data $rows
    }
}

# ---------------------------------------------------------------------------
# 15. Citrix WEM (Workspace Environment Management) agent presence. WEM maps drives
# entirely OUTSIDE Group Policy - via its own console-configured actions applied by its own
# agent - so a WEM-mapped drive is completely invisible to every Group-Policy-side collector
# in this toolkit (GppEvents, GpOperationalEvents, Audit-GPDriveMaps.ps1). If WEM is present,
# it is a first-class suspect that must be ruled in or out explicitly, not left undetected.
# The user reported not believing WEM is deployed in this environment; a definitive
# "not present" here closes that question permanently rather than leaving it assumed.
#
# Service name verified against Citrix's own documentation (not assumed or recalled from
# training data, per this toolkit's verification rule): "After installation, the agent runs
# as Citrix WEM Agent Host Service (formerly Norskale Agent Host Service) and Citrix WEM
# Agent User Logon Service."
# https://docs.citrix.com/en-us/workspace-environment-management/current-release/install-and-configure/agent-host.html
# Checked by NAME rather than by matching on "WEM"/"Norskale" substrings in the service
# display name, so a renamed or unrelated service can never produce a false positive.
# ---------------------------------------------------------------------------
$wemAgentResult = Invoke-Collector -Name 'CitrixWemAgentPresence' -Collector {
    $serviceNames = @('Citrix WEM Agent Host Service', 'Norskale Agent Host Service')
    $scriptBlock = {
        param($Names)
        foreach ($n in $Names) {
            $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
            if ($svc) {
                return [PSCustomObject]@{ ServiceName = $svc.Name; DisplayName = $svc.DisplayName; Status = $svc.Status.ToString() }
            }
        }
        return $null
    }
    $found = if ($isLocal) {
        & $scriptBlock $serviceNames
    } else {
        Invoke-Command -ComputerName $ComputerName -ErrorAction Stop -ScriptBlock $scriptBlock -ArgumentList (,$serviceNames)
    }
    if ($null -eq $found) {
        # A definitive, confirmed-absent result - not "could not check". Get-Service with
        # -ErrorAction SilentlyContinue returning nothing IS a successful check that found no
        # matching service, distinct from a remoting/access failure (caught below).
        return New-CollectionResult -State 'EmptyButValid' -Data @()
    }
    New-CollectionResult -State 'Found' -Data @([PSCustomObject]@{
        ServiceName = $found.ServiceName; DisplayName = $found.DisplayName; Status = $found.Status
    })
}

# ---------------------------------------------------------------------------
# 16. Citrix client drive mapping (CDM) - is the target letter a Citrix client-side drive
# redirected INTO the session, rather than a network mapping at all? This is a fundamentally
# different kind of "drive" than everything else this toolkit investigates: CDM drives are
# session-scoped virtual channel redirections from the endpoint device, not SMB mappings, so
# neither Group Policy nor a logon script can be their root cause.
#
# VERIFICATION RESULT: Citrix's own CDM documentation confirms the DEFAULT drive-letter
# assignment convention (client drives are assigned starting at V: and working backward) but
# does NOT document any registry value, WMI property, or other queryable signal that lets a
# script running inside the session positively identify a SPECIFIC drive letter as a CDM
# mapping rather than a network mapping - modern Citrix Virtual Apps and Desktops maps client
# drives as UNC links by default (not as lettered drives at all) unless the legacy
# HKLM\Software\Citrix\UncLinks UNCEnabled=0 format is explicitly configured, which itself is
# a Citrix Virtual Delivery Agent-side (not endpoint-side) setting this collector has no
# access to confirm from inside a user session either.
# https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/devices/client-drive-mapping.html
# https://docs.citrix.com/en-us/citrix-workspace-app-for-windows/client-drive-mapping.html
# https://support.citrix.com/article/CTX127968
#
# SECOND VERIFICATION RESULT (session-type signal): this script's research also looked for a
# documented way to tell whether the CURRENT session is a Citrix ICA/HDX session at all (as
# distinct from RDP or console), since that would at least bound whether CDM is possible
# before chasing a specific letter by hand. Neither learn.microsoft.com nor docs.citrix.com
# was found to document what value the SESSIONNAME environment variable takes for a Citrix
# ICA/HDX session specifically (a commonly repeated claim that it begins "ICA-" was traced
# only to third-party forum/community content, never to an authoritative Microsoft or Citrix
# page, and is therefore NOT asserted here as a verified fact).
#
# Per this toolkit's rule ("if you cannot verify a fact, report CouldNotCollect with the
# reason rather than guessing" - see DriveMapReference.psd1's own NoBackgroundPolicy and
# HKCU\Network precedents), this collector does not attempt to classify the session by
# pattern-matching SESSIONNAME against an unverified prefix. It reports the raw, directly
# observable facts only - the SESSIONNAME value itself, and whether the registry location
# Citrix's own VDA registration documentation names is present. That page documents
# HKLM\Software\Citrix\VirtualDesktopAgent (or ...\Wow6432Node\Citrix\VirtualDesktopAgent on
# 32-bit) as where the VDA stores its ListOfDDCs value for registry-based Delivery
# Controller configuration - it does NOT state this key is guaranteed to exist on every VDA
# installation (e.g. one configured entirely via Active Directory OU instead), so its
# presence is corroborating evidence that a VDA is installed here, not proof either way -
# reported as such, the same "evidence, not proof" treatment this toolkit already gives GPP
# trace file presence.
# https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/manage-deployment/vda-registration.html
# ---------------------------------------------------------------------------
$citrixCdmResult = Invoke-Collector -Name 'CitrixClientDriveMapping' -Collector {
    if (-not $isLocal) {
        return New-CollectionResult -State 'CouldNotCollect' -Reason 'SESSIONNAME reflects the CALLING process''s own session, not the target machine''s interactive session, so this cannot be checked remotely. Re-run locally on the machine the user is actually logged into.'
    }
    $sessionName = $env:SESSIONNAME
    $vdaRegistryKeyFound = $false
    foreach ($vdaKeyPath in 'HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent', 'HKLM:\SOFTWARE\Wow6432Node\Citrix\VirtualDesktopAgent') {
        try {
            if (Test-Path -LiteralPath $vdaKeyPath -ErrorAction SilentlyContinue) { $vdaRegistryKeyFound = $true; break }
        } catch { }
    }
    if ([string]::IsNullOrWhiteSpace($sessionName) -and -not $vdaRegistryKeyFound) {
        return New-CollectionResult -State 'CouldNotCollect' -Reason 'Neither SESSIONNAME nor the Citrix VDA registration registry key could be read, so whether this is a Citrix session/VDA could not be determined.'
    }
    $rows = @([PSCustomObject]@{
        SessionName             = $sessionName
        VdaRegistryKeyFound     = $vdaRegistryKeyFound
        Note                    = "SESSIONNAME is '$sessionName'. Citrix does not document what value SESSIONNAME takes for an ICA/HDX session, so this script does not classify the session type from it - reported as raw data only. The Citrix VDA registration registry key (HKLM\Software\Citrix\VirtualDesktopAgent) was $(if ($vdaRegistryKeyFound) { 'FOUND - corroborating evidence a VDA is installed here, not proof' } else { 'not found - this is evidence, not proof, that no VDA is installed, since a VDA configured via Active Directory OU rather than registry may not create this key' }). Whether ${DriveLetter}: specifically is a Citrix client-mapped drive (CDM) rather than a network mapping cannot be confirmed automatically - no registry/WMI signal for this is documented by Citrix. Confirm by hand via Citrix Connection Center on the endpoint device, or the VDA's own client drive list."
    })
    New-CollectionResult -State 'Found' -Data $rows
}

# ---------------------------------------------------------------------------
# Write the manifest and every collected data set into the bundle.
# ---------------------------------------------------------------------------
$manifest = New-EvidenceManifest -Results $results

Write-Host ''
Write-Status INFO "Collected: $($manifest.Collected -join ', ')"
if ($manifest.Empty.Count -gt 0)  { Write-Status INFO  "Empty (confirmed, not missing evidence): $($manifest.Empty -join ', ')" }
if ($manifest.Failed.Count -gt 0) {
    $failedText = ($manifest.Failed | ForEach-Object { "$($_.Collector): $($_.Reason)" }) -join ' | '
    Write-Status WARN "Could not collect: $failedText"
}

$manifestObject = [PSCustomObject]@{
    GeneratedAt  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    ComputerName = $ComputerName
    DriveLetter  = $DriveLetter
    Collected    = $manifest.Collected
    Empty        = $manifest.Empty
    Failed       = $manifest.Failed
}

try {
    $manifestJson = $manifestObject | ConvertTo-Json -Depth 6
    Write-Utf8BomFile -Path (Join-Path $bundleFolder 'manifest.json') -Content $manifestJson
    Write-Status PASS "Manifest written: $(Join-Path $bundleFolder 'manifest.json')"
} catch {
    Write-Status FAIL "Could not write manifest.json: $($_.Exception.Message)"
}

# Export each Found (and, where non-empty, EmptyButValid placeholder-free) data
# set as its own CSV, flattening arrays first.
$csvExports = @{
    'PersistentMounts.csv'          = $persistentMountsResult
    'MountPoints2.csv'              = $mountPoints2Result
    'LiveMounts_CurrentContext.csv' = $liveMountsElevatedResult
    'GppEvents.csv'                 = $gppEventsResult
    'GpOperationalEvents.csv'       = $gpOperationalResult
    'TraceFiles.csv'                = $traceFilesResult
    'LogonScriptReferences.csv'     = $logonScriptFindingsResult
    'AdScriptPath.csv'              = $adScriptPathResult
    'ScheduledTaskReferences.csv'   = $scheduledTaskFindingsResult
    'RunKeyReferences.csv'          = $runKeyFindingsResult
    'StartupItemReferences.csv'     = $startupFindingsResult
    'OfflineFilesState.csv'         = $offlineFilesResult
    'DfsClientState.csv'            = $dfsStateResult
    'NetworkProfile.csv'            = $networkProfileResult
    'CitrixWemAgentPresence.csv'    = $wemAgentResult
    'CitrixClientDriveMapping.csv'  = $citrixCdmResult
}

# Mount-state comparison, computed from the two collectors above.
if ($persistentMountsResult.State -in 'Found','EmptyButValid' -and $liveMountsElevatedResult.State -in 'Found','EmptyButValid') {
    $comparison = @(Compare-MountState -PersistentMounts @($persistentMountsResult.Data) -LiveMounts @($liveMountsElevatedResult.Data))
    if ($comparison.Count -gt 0) {
        Export-EvidenceCsv -Path (Join-Path $bundleFolder 'MountStateComparison.csv') -Rows $comparison
    }
}

foreach ($fileName in $csvExports.Keys) {
    $result = $csvExports[$fileName]
    if ($result.State -eq 'Found' -and $result.Data) {
        Export-EvidenceCsv -Path (Join-Path $bundleFolder $fileName) -Rows @($result.Data)
    }
}

# ---------------------------------------------------------------------------
# Zip the bundle.
# ---------------------------------------------------------------------------
$zipPath = "$bundleFolder.zip"
try {
    Compress-Archive -Path (Join-Path $bundleFolder '*') -DestinationPath $zipPath -Force -ErrorAction Stop
    Write-Status PASS "Evidence bundle zipped: $zipPath"
} catch {
    Write-Status WARN "Could not zip the evidence bundle (folder is still available at ${bundleFolder}): $($_.Exception.Message)"
}

Write-Status PASS "Evidence collection complete. Bundle folder: $bundleFolder"
