#Requires -Modules GroupPolicy, ActiveDirectory

<#
.SYNOPSIS
    Audits drive mappings configured in Group Policy Preferences.

.DESCRIPTION
    Scans all GPOs for drive map preferences and produces a detailed report:
    - Extracts every drive mapping with drive letter, UNC path, action, label,
      and item-level targeting (ILT) filters
    - Validates UNC paths are reachable on the network
    - Detects drive-letter conflicts (same letter, different paths)
    - Detects duplicate share paths across GPOs
    - Shows GPO link context (where each GPO is linked)
    - Simulates GPO precedence for a specific user/computer to show
      which mapping "wins" per drive letter

.PARAMETER OutputPath
    Directory where reports will be saved. Defaults to script directory.

.PARAMETER ExportFormat
    Export format for reports: HTML, CSV, or Both. Default: Both

.PARAMETER Domain
    Specific domain to audit. If not specified, uses current domain.

.PARAMETER Credential
    Credential for connecting to domain if needed.

.PARAMETER TargetUser
    Optional SamAccountName. When specified, the script resolves the user's
    OU and group memberships to simulate GPO precedence and show the
    effective (winning) drive mapping per drive letter.

.PARAMETER TargetComputer
    Optional computer name to include in the precedence simulation.
    Must be used together with -TargetUser.

.PARAMETER SkipBrowserOpen
    Do not open the HTML report in the default browser after generation.

.PARAMETER SkipPathValidation
    Skip UNC path reachability checks (faster, no network probes).

.EXAMPLE
    .\Audit-GPDriveMaps.ps1
    Runs full drive map audit with default settings.

.EXAMPLE
    .\Audit-GPDriveMaps.ps1 -TargetUser "jsmith" -TargetComputer "WS01"
    Audits drive maps and shows which mappings user jsmith would receive on WS01.

.EXAMPLE
    .\Audit-GPDriveMaps.ps1 -OutputPath "C:\Reports" -ExportFormat HTML
    Exports HTML-only report to C:\Reports.

.EXAMPLE
    .\Audit-GPDriveMaps.ps1 -SkipPathValidation -SkipBrowserOpen
    Fast audit without network probes or browser pop-up.

.NOTES
    Author: PowerShell Script Collection
    Version: 1.0
    Requires: GroupPolicy module, ActiveDirectory module (RSAT)
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = $PSScriptRoot,

    [Parameter()]
    [ValidateSet('HTML', 'CSV', 'Both')]
    [string]$ExportFormat = 'Both',

    [Parameter()]
    [string]$Domain,

    [Parameter()]
    [PSCredential]$Credential,

    [Parameter()]
    [string]$TargetUser,

    [Parameter()]
    [string]$TargetComputer,

    [Parameter()]
    [switch]$SkipBrowserOpen,

    [Parameter()]
    [switch]$SkipPathValidation,

    [Parameter()]
    [switch]$LoadFunctionsOnly
)

#region Script Configuration
$ErrorActionPreference = 'Continue'
$WarningPreference = 'Continue'

$ScriptVersion = "1.0"
$AuditDate = Get-Date
$ReportName = "DriveMap-Audit-$($AuditDate.ToString('yyyy-MM-dd-HHmmss'))"
#endregion

#region Helper Functions
function Write-AuditLog {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = switch ($Level) {
        'Info'    { '[i]' }
        'Warning' { '[!]' }
        'Error'   { '[!]' }
        'Success' { '[OK]' }
    }
    $colors = @{
        'Info'    = 'Cyan'
        'Warning' = 'Yellow'
        'Error'   = 'Red'
        'Success' = 'Green'
    }

    Write-Host "[$timestamp] $prefix $Message" -ForegroundColor $colors[$Level]
}

function Test-Prerequisites {
    Write-AuditLog "Checking prerequisites..." -Level Info

    $modules = @('GroupPolicy', 'ActiveDirectory')
    $missing = [System.Collections.Generic.List[string]]::new()

    foreach ($module in $modules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            $missing.Add($module)
        } else {
            Import-Module $module -ErrorAction SilentlyContinue
        }
    }

    if ($missing.Count -gt 0) {
        Write-AuditLog "Missing required modules: $($missing -join ', ')" -Level Error
        Write-AuditLog "Please install RSAT tools or run on a domain controller" -Level Error
        return $false
    }

    try {
        if ($Domain) {
            $domainInfo = Get-ADDomain -Server $Domain -Credential $Credential -ErrorAction Stop
        } else {
            $domainInfo = Get-ADDomain -ErrorAction Stop
        }
        Write-AuditLog "Connected to domain: $($domainInfo.DNSRoot)" -Level Success
        return $true
    }
    catch {
        Write-AuditLog "Failed to connect to domain: $_" -Level Error
        return $false
    }
}

function Get-CachedGPOReports {
    param(
        [array]$GPOs
    )

    Write-AuditLog "Caching GPO XML reports for all $($GPOs.Count) GPOs..." -Level Info

    $cache = @{}
    $count = 0

    foreach ($gpo in $GPOs) {
        $count++
        Write-Progress -Activity "Caching GPO Reports" -Status "Processing: $($gpo.DisplayName)" -PercentComplete (($count / $GPOs.Count) * 100)

        try {
            $gpoParams = @{
                Guid       = $gpo.Id
                ReportType = 'Xml'
            }
            if ($Domain) { $gpoParams['Domain'] = $Domain }

            $xmlString = Get-GPOReport @gpoParams
            $cache[$gpo.Id.ToString()] = @{
                XmlString = $xmlString
                XmlDoc    = [xml]$xmlString
            }
        }
        catch {
            Write-AuditLog "Error caching report for GPO '$($gpo.DisplayName)': $_" -Level Warning
        }
    }

    Write-Progress -Activity "Caching GPO Reports" -Completed
    Write-AuditLog "Cached $($cache.Count) of $($GPOs.Count) GPO reports" -Level Success

    return $cache
}

function Escape-Html {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '' }
    return [System.Security.SecurityElement]::Escape($Value)
}
#endregion

#region Item-Level Targeting Parser
function Get-ItemLevelTargeting {
    <#
    .SYNOPSIS
        Parses item-level targeting (ILT) filters from a GP Preferences Drive element.
    .DESCRIPTION
        Walks the <Filters> child element and returns a human-readable summary
        of all targeting conditions (security groups, users, OUs, IP ranges,
        computers, etc.).
    #>
    param(
        [System.Xml.XmlElement]$DriveElement
    )

    $filters = [System.Collections.Generic.List[string]]::new()
    $filterObjects = [System.Collections.Generic.List[object]]::new()

    $filtersNode = $DriveElement.Filters
    if (-not $filtersNode) {
        return @{
            Summary = 'No targeting (applies to all)'
            Filters = $filterObjects
        }
    }

    # Walk all child filter elements
    foreach ($child in $filtersNode.ChildNodes) {
        if ($child.NodeType -ne 'Element') { continue }

        $filterType = $child.LocalName
        $bool = if ($child.not -eq '1') { 'IS NOT' } else { 'IS' }

        $detail = switch -Wildcard ($filterType) {
            'FilterGroup' {
                $name = $child.name
                if (-not $name) { $name = $child.userContext }
                "Group $bool '$name'"
            }
            'FilterUser' {
                $name = $child.name
                "User $bool '$name'"
            }
            'FilterComputer' {
                $name = $child.name
                "Computer $bool '$name'"
            }
            'FilterOrgUnit' {
                $name = $child.name
                if (-not $name) { $name = $child.directMember }
                "OU $bool '$name'"
            }
            'FilterSite' {
                $name = $child.name
                "Site $bool '$name'"
            }
            'FilterNetworkAddress' {
                # IP address range filter
                $addr = $child.ipAddress
                if (-not $addr) { $addr = $child.name }
                "IP Range $bool '$addr'"
            }
            'FilterOperatingSystem' {
                $name = $child.name
                "OS $bool '$name'"
            }
            'FilterRunOnce' {
                "Run Once (apply only on first processing)"
            }
            'FilterCollection' {
                # Nested collection — recurse
                $nested = Get-FilterCollectionSummary -CollectionNode $child
                "Collection: ($nested)"
            }
            default {
                # Catch-all for less common filter types
                $name = $child.name
                if ($name) {
                    "$filterType $bool '$name'"
                } else {
                    "$filterType (details in XML)"
                }
            }
        }

        $filters.Add($detail)
        $filterObjects.Add([PSCustomObject]@{
            Type    = $filterType
            Bool    = $child.bool     # AND / OR connector
            Not     = $child.not -eq '1'
            Detail  = $detail
        })
    }

    $summary = if ($filters.Count -gt 0) { $filters -join '; ' } else { 'No targeting (applies to all)' }

    return @{
        Summary = $summary
        Filters = $filterObjects
    }
}

function Get-FilterCollectionSummary {
    param(
        [System.Xml.XmlElement]$CollectionNode
    )

    $parts = [System.Collections.Generic.List[string]]::new()

    foreach ($child in $CollectionNode.ChildNodes) {
        if ($child.NodeType -ne 'Element') { continue }

        $bool = if ($child.not -eq '1') { 'NOT' } else { '' }
        $name = $child.name

        switch -Wildcard ($child.LocalName) {
            'FilterGroup'          { $parts.Add("Group $bool '$name'") }
            'FilterUser'           { $parts.Add("User $bool '$name'") }
            'FilterComputer'       { $parts.Add("Computer $bool '$name'") }
            'FilterOrgUnit'        { $parts.Add("OU $bool '$name'") }
            'FilterSite'           { $parts.Add("Site $bool '$name'") }
            'FilterNetworkAddress' { $parts.Add("IP $bool '$($child.ipAddress)'") }
            'FilterCollection'     {
                $nested = Get-FilterCollectionSummary -CollectionNode $child
                $parts.Add("($nested)")
            }
            default { $parts.Add("$($child.LocalName) $bool '$name'") }
        }
    }

    $connector = if ($CollectionNode.bool -eq 'OR') { ' OR ' } else { ' AND ' }
    return $parts -join $connector
}
#endregion

#region Drive Map Extraction
function Get-AllDriveMaps {
    param(
        [array]$GPOs,
        [hashtable]$GPOCache
    )

    Write-AuditLog "Extracting drive map preferences from all GPOs..." -Level Info

    $allDriveMaps = [System.Collections.Generic.List[object]]::new()
    $count = 0

    foreach ($gpo in $GPOs) {
        $count++
        Write-Progress -Activity "Extracting Drive Maps" -Status "$($gpo.DisplayName)" -PercentComplete (($count / $GPOs.Count) * 100)

        $guid = $gpo.Id.ToString()
        if (-not $GPOCache.ContainsKey($guid)) { continue }

        $report = $GPOCache[$guid].XmlDoc

        foreach ($scope in @('Computer', 'User')) {
            $extensions = $report.GPO.$scope.ExtensionData
            if (-not $extensions) { continue }

            foreach ($ext in $extensions) {
                if ($ext.Extension.DriveMapSettings) {
                    Get-DriveMapItems -Node $ext.Extension.DriveMapSettings `
                        -GPO $gpo -Scope $scope -Results $allDriveMaps -GPOCache $GPOCache
                }
            }
        }
    }

    Write-Progress -Activity "Extracting Drive Maps" -Completed
    Write-AuditLog "Extracted $($allDriveMaps.Count) drive mappings from $($GPOs.Count) GPOs" -Level Success

    return $allDriveMaps
}

function Get-DriveMapItems {
    param(
        [System.Xml.XmlElement]$Node,
        [object]$GPO,
        [string]$Scope,
        [System.Collections.Generic.List[object]]$Results,
        [hashtable]$GPOCache
    )

    if ($Node.Drive) {
        foreach ($drive in $Node.Drive) {
            $props = $drive.Properties
            if (-not $props) { continue }

            # Parse item-level targeting
            $ilt = Get-ItemLevelTargeting -DriveElement $drive

            # Get GPO link info
            $guid = $GPO.Id.ToString()
            $links = @()
            if ($GPOCache.ContainsKey($guid)) {
                $rpt = $GPOCache[$guid].XmlDoc
                if ($rpt.GPO.LinksTo) {
                    $links = @($rpt.GPO.LinksTo | ForEach-Object {
                        [PSCustomObject]@{
                            SOMPath   = $_.SOMPath
                            Enabled   = $_.Enabled
                            Enforced  = $_.NoOverride
                            LinkOrder = $_.LinkOrder
                        }
                    })
                }
            }

            # Resolve the actual drive letter
            # thisDrive can be a letter (e.g. "H:") or "NOCHANGE"
            # When NOCHANGE, check the 'letter' or 'useLetter' attribute for the real letter
            $driveLetter = $props.thisDrive
            if ($driveLetter -eq 'NOCHANGE' -or [string]::IsNullOrWhiteSpace($driveLetter)) {
                if ($props.letter) { $driveLetter = $props.letter }
                elseif ($props.useLetter) { $driveLetter = $props.useLetter }
                elseif ($drive.letter) { $driveLetter = $drive.letter }
            }
            # Normalize: strip trailing colon for display consistency
            $driveLetterDisplay = if ($driveLetter -and $driveLetter -ne 'NOCHANGE') {
                $driveLetter.TrimEnd(':')
            } else {
                $driveLetter
            }

            $Results.Add([PSCustomObject]@{
                GPOName       = $GPO.DisplayName
                GPOId         = $GPO.Id
                GPOStatus     = $GPO.GpoStatus
                Configuration = $Scope
                Action        = $props.action
                DriveLetter   = $driveLetterDisplay
                UNCPath       = $props.path
                Label         = $props.label
                Reconnect     = $props.persistent
                ILTSummary    = $ilt.Summary
                ILTFilters    = $ilt.Filters
                GPOLinks      = $links
                GPOLinksText  = ($links | ForEach-Object { $_.SOMPath }) -join '; '
            })
        }
    }

    # Recurse into Collection folders
    if ($Node.Collection) {
        foreach ($collection in $Node.Collection) {
            Get-DriveMapItems -Node $collection -GPO $GPO -Scope $Scope -Results $Results -GPOCache $GPOCache
        }
    }
}
#endregion

#region UNC Path Validation
function Test-UNCPaths {
    param(
        [System.Collections.Generic.List[object]]$DriveMaps
    )

    # Get unique UNC paths
    $uniquePaths = $DriveMaps | Where-Object { $_.UNCPath } |
        Select-Object -ExpandProperty UNCPath -Unique

    if ($uniquePaths.Count -eq 0) {
        Write-AuditLog "No UNC paths to validate" -Level Info
        return @()
    }

    Write-AuditLog "Validating $($uniquePaths.Count) unique UNC paths..." -Level Info

    $results = [System.Collections.Generic.List[object]]::new()
    $count = 0

    foreach ($path in $uniquePaths) {
        $count++
        Write-Progress -Activity "Validating UNC Paths" -Status $path -PercentComplete (($count / $uniquePaths.Count) * 100)

        $reachable = $false
        $errorMsg = ''

        try {
            $reachable = Test-Path -Path $path -ErrorAction Stop
        }
        catch {
            $errorMsg = $_.Exception.Message
        }

        # Find all GPOs that reference this path
        $affectedGPOs = ($DriveMaps | Where-Object { $_.UNCPath -eq $path } |
            Select-Object -ExpandProperty GPOName -Unique) -join ', '
        $affectedLetters = ($DriveMaps | Where-Object { $_.UNCPath -eq $path } |
            Select-Object -ExpandProperty DriveLetter -Unique) -join ', '

        $results.Add([PSCustomObject]@{
            UNCPath        = $path
            Reachable      = $reachable
            Error          = $errorMsg
            AffectedGPOs   = $affectedGPOs
            DriveLetters   = $affectedLetters
            Severity       = if ($reachable) { 'OK' } else { 'High' }
            Recommendation = if ($reachable) {
                'Path is accessible'
            } else {
                "Path is UNREACHABLE — verify server is online and share exists. Error: $errorMsg"
            }
        })
    }

    Write-Progress -Activity "Validating UNC Paths" -Completed

    $unreachable = ($results | Where-Object { -not $_.Reachable }).Count
    Write-AuditLog "Path validation complete: $($results.Count) paths checked, $unreachable unreachable" -Level $(if ($unreachable -gt 0) { 'Warning' } else { 'Success' })

    return $results
}
#endregion

#region Conflict & Duplicate Detection
function Find-DriveMapConflicts {
    param(
        [System.Collections.Generic.List[object]]$DriveMaps
    )

    Write-AuditLog "Analyzing for drive map conflicts and duplicates..." -Level Info

    $conflicts = [System.Collections.Generic.List[object]]::new()
    $duplicates = [System.Collections.Generic.List[object]]::new()

    if ($DriveMaps.Count -eq 0) {
        Write-AuditLog "No drive maps to analyze" -Level Info
        return @{ Conflicts = $conflicts; Duplicates = $duplicates }
    }

    # Same drive letter mapped to different UNC paths
    # Exclude NOCHANGE (not a real letter assignment) and blank letters
    $realLetterMaps = $DriveMaps | Where-Object {
        $_.DriveLetter -and
        $_.DriveLetter -ne 'NOCHANGE' -and
        $_.DriveLetter.Trim() -ne ''
    }

    $byLetter = $realLetterMaps |
        Group-Object -Property DriveLetter |
        Where-Object {
            ($_.Group | Select-Object -ExpandProperty UNCPath -Unique).Count -gt 1
        }

    foreach ($group in $byLetter) {
        $maps = $group.Group
        $letter = $maps[0].DriveLetter

        # Build per-mapping detail: which GPO maps which path with which ILT
        $mappingDetails = [System.Collections.Generic.List[object]]::new()
        foreach ($map in $maps) {
            $mappingDetails.Add([PSCustomObject]@{
                GPOName    = $map.GPOName
                UNCPath    = $map.UNCPath
                ILTSummary = $map.ILTSummary
                Action     = $map.Action
                Label      = $map.Label
            })
        }

        # Check ILT overlap between mappings with different paths
        $hasRealConflict = $false
        $uniquePathMaps = @($maps | Sort-Object UNCPath | Group-Object UNCPath | ForEach-Object { $_.Group[0] })
        for ($i = 0; $i -lt $uniquePathMaps.Count; $i++) {
            for ($j = $i + 1; $j -lt $uniquePathMaps.Count; $j++) {
                $m1 = $uniquePathMaps[$i]
                $m2 = $uniquePathMaps[$j]

                # No ILT on either = applies to everyone = real conflict
                $m1HasILT = $m1.ILTFilters -and $m1.ILTFilters.Count -gt 0
                $m2HasILT = $m2.ILTFilters -and $m2.ILTFilters.Count -gt 0

                if (-not $m1HasILT -or -not $m2HasILT) {
                    $hasRealConflict = $true
                    break
                }

                # Both have ILT — check if group filters overlap
                $g1 = @($m1.ILTFilters | Where-Object { $_.Type -eq 'FilterGroup' -and -not $_.Not } |
                    ForEach-Object { if ($_.Detail -match "'(.+)'") { $Matches[1] } }) | Where-Object { $_ }
                $g2 = @($m2.ILTFilters | Where-Object { $_.Type -eq 'FilterGroup' -and -not $_.Not } |
                    ForEach-Object { if ($_.Detail -match "'(.+)'") { $Matches[1] } }) | Where-Object { $_ }

                if ($g1.Count -gt 0 -and $g2.Count -gt 0) {
                    $overlap = $g1 | Where-Object { $_ -in $g2 }
                    if ($overlap.Count -gt 0) { $hasRealConflict = $true; break }
                    # Different groups — no overlap for this pair, continue checking
                } else {
                    # Can't determine from groups alone, assume potential conflict
                    $hasRealConflict = $true
                    break
                }
            }
            if ($hasRealConflict) { break }
        }

        $severity = if ($hasRealConflict) { 'High' } else { 'Info' }
        $recommendation = if ($hasRealConflict) {
            "REAL CONFLICT: Drive ${letter}: has overlapping or no targeting — users may get unexpected mappings based on GPO precedence"
        } else {
            "Drive ${letter}: mapped to different shares but item-level targeting does NOT overlap — different users receive different mappings (no real conflict)"
        }

        $conflicts.Add([PSCustomObject]@{
            DriveLetter     = $letter
            MappingDetails  = $mappingDetails
            HasRealConflict = $hasRealConflict
            GPOCount        = ($maps | Select-Object -ExpandProperty GPOName -Unique).Count
            PathCount       = ($maps | Select-Object -ExpandProperty UNCPath -Unique).Count
            Severity        = $severity
            Recommendation  = $recommendation
        })
    }

    # Same UNC path in multiple GPOs
    $byPath = $DriveMaps | Where-Object { $_.UNCPath } |
        Group-Object -Property { $_.UNCPath.ToLower() } |
        Where-Object { ($_.Group | Select-Object -ExpandProperty GPOName -Unique).Count -gt 1 }

    foreach ($group in $byPath) {
        $maps = $group.Group
        $letters = ($maps | Select-Object -ExpandProperty DriveLetter -Unique) -join ', '
        $gpos = ($maps | Select-Object -ExpandProperty GPOName -Unique) -join ', '

        $duplicates.Add([PSCustomObject]@{
            UNCPath        = $maps[0].UNCPath
            DriveLetters   = $letters
            AffectedGPOs   = $gpos
            GPOCount       = ($maps | Select-Object -ExpandProperty GPOName -Unique).Count
            IsSameLetter   = ($maps | Select-Object -ExpandProperty DriveLetter -Unique).Count -eq 1
            Severity       = if (($maps | Select-Object -ExpandProperty DriveLetter -Unique).Count -gt 1) { 'Warning' } else { 'Info' }
            Recommendation = if (($maps | Select-Object -ExpandProperty DriveLetter -Unique).Count -gt 1) {
                "Same share mapped to different drive letters across GPOs — review for conflicts"
            } else {
                "Same share mapped identically in multiple GPOs — consider consolidating"
            }
        })
    }

    $realConflicts = ($conflicts | Where-Object { $_.HasRealConflict }).Count
    $iltResolved = ($conflicts | Where-Object { -not $_.HasRealConflict }).Count
    Write-AuditLog "Found $($conflicts.Count) letter conflicts ($realConflicts real, $iltResolved resolved by ILT) and $($duplicates.Count) duplicate paths" -Level $(if ($realConflicts -gt 0) { 'Warning' } else { 'Info' })

    return @{
        Conflicts  = $conflicts
        Duplicates = $duplicates
    }
}
#endregion

#region GPO Precedence Simulation
function Get-EffectiveDriveMaps {
    <#
    .SYNOPSIS
        Simulates GPO precedence for a target user (and optionally computer)
        to determine the winning drive mapping per drive letter.
    .DESCRIPTION
        1. Resolves the user's DN, OU path, and all group memberships (recursive)
        2. Optionally resolves the computer's DN, OU, and group memberships
        3. Builds the ordered list of GPOs that apply (domain → site → OU chain)
        4. Evaluates item-level targeting filters per mapping
        5. Returns the effective (winning) mapping per drive letter
    #>
    param(
        [string]$UserName,
        [string]$ComputerName,
        [System.Collections.Generic.List[object]]$AllDriveMaps,
        [array]$AllGPOs,
        [hashtable]$GPOCache
    )

    Write-AuditLog "Simulating GPO precedence for user '$UserName'..." -Level Info

    # --- Resolve User ---
    $adParams = @{}
    if ($Domain) { $adParams['Server'] = $Domain }
    if ($Credential) { $adParams['Credential'] = $Credential }

    try {
        $user = Get-ADUser -Identity $UserName -Properties MemberOf, DistinguishedName @adParams -ErrorAction Stop
    }
    catch {
        Write-AuditLog "Could not resolve user '$UserName': $_" -Level Error
        return $null
    }

    # Recursive group memberships (tokenGroups gives the full transitive set as SIDs)
    $userGroups = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    try {
        $userObj = Get-ADUser -Identity $UserName -Properties tokenGroups @adParams -ErrorAction Stop
        foreach ($sid in $userObj.tokenGroups) {
            try {
                $grp = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate(
                    [System.Security.Principal.NTAccount]
                ).Value
                [void]$userGroups.Add($grp)
                # Also add bare name (without domain prefix)
                if ($grp -match '\\(.+)$') { [void]$userGroups.Add($Matches[1]) }
            } catch { }
        }
    }
    catch {
        # Fallback: use MemberOf (non-recursive)
        foreach ($dn in $user.MemberOf) {
            try {
                $grpName = (Get-ADGroup -Identity $dn @adParams -ErrorAction SilentlyContinue).SamAccountName
                if ($grpName) { [void]$userGroups.Add($grpName) }
            } catch { }
        }
    }

    Write-AuditLog "User '$UserName' is in $($userGroups.Count) groups" -Level Info

    # --- Resolve Computer (optional) ---
    $computerGroups = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $computerDN = $null

    if ($ComputerName) {
        try {
            $comp = Get-ADComputer -Identity $ComputerName -Properties MemberOf, DistinguishedName @adParams -ErrorAction Stop
            $computerDN = $comp.DistinguishedName

            foreach ($dn in $comp.MemberOf) {
                try {
                    $grpName = (Get-ADGroup -Identity $dn @adParams -ErrorAction SilentlyContinue).SamAccountName
                    if ($grpName) { [void]$computerGroups.Add($grpName) }
                } catch { }
            }
            Write-AuditLog "Computer '$ComputerName' resolved, $($computerGroups.Count) groups" -Level Info
        }
        catch {
            Write-AuditLog "Could not resolve computer '$ComputerName': $_" -Level Warning
        }
    }

    # --- Build OU chain for user (child → parent → domain) ---
    $userDN = $user.DistinguishedName
    $ouChain = [System.Collections.Generic.List[string]]::new()
    $parts = $userDN -split ',(?=(?:OU|DC)=)'
    # Skip the CN=user part, accumulate OU chain from innermost to domain
    for ($i = 1; $i -lt $parts.Count; $i++) {
        $ouDN = ($parts[$i..($parts.Count - 1)]) -join ','
        $ouChain.Add($ouDN)
    }

    # Get domain DN (the DC= components)
    $domainDN = ($parts | Where-Object { $_ -match '^DC=' }) -join ','

    # --- Determine ordered GPO list ---
    # GP processing order: Domain GPOs → OU GPOs (outermost OU first → innermost OU last)
    # Last processed wins for GP Preferences (unless Replace action)
    # Enforced GPOs always win regardless of position

    $orderedGPOs = [System.Collections.Generic.List[object]]::new()

    # Reverse ouChain so domain-level is first, innermost OU is last
    $ouChainReversed = [System.Collections.Generic.List[string]]::new($ouChain)
    $ouChainReversed.Reverse()

    foreach ($gpo in $AllGPOs) {
        $guid = $gpo.Id.ToString()
        if (-not $GPOCache.ContainsKey($guid)) { continue }

        $report = $GPOCache[$guid].XmlDoc
        $links = $report.GPO.LinksTo
        if (-not $links) { continue }

        foreach ($link in $links) {
            $somPath = $link.SOMPath
            $linkEnabled = $link.Enabled -eq 'true'
            $enforced = $link.NoOverride -eq 'true'

            if (-not $linkEnabled) { continue }

            # Determine precedence order (lower = processed earlier = lower priority)
            $order = -1

            # Check if linked to domain
            if ($somPath -eq (Get-ADDomain @adParams).DNSRoot -or
                $somPath -match "^$([regex]::Escape((Get-ADDomain @adParams).DNSRoot))$") {
                $order = 0
            }

            # Check if linked to an OU in the user's chain
            for ($i = 0; $i -lt $ouChainReversed.Count; $i++) {
                $ouDN = $ouChainReversed[$i]
                # SOMPath in GPO XML uses the full LDAP path or friendly OU path
                if ($somPath -match [regex]::Escape($ouDN) -or
                    $ouDN -match [regex]::Escape($somPath)) {
                    $order = $i + 1
                    break
                }
            }

            if ($order -ge 0) {
                $orderedGPOs.Add([PSCustomObject]@{
                    GPO       = $gpo
                    GPOName   = $gpo.DisplayName
                    GPOId     = $gpo.Id
                    SOMPath   = $somPath
                    Order     = $order
                    LinkOrder = [int]$link.LinkOrder
                    Enforced  = $enforced
                })
            }
        }
    }

    # Sort: by Order (domain=0, outermost OU=1, ...innermost OU=N), then by LinkOrder descending
    # Higher Order + lower LinkOrder = higher priority (processed later = wins)
    $orderedGPOs = $orderedGPOs | Sort-Object -Property Order, @{Expression={$_.LinkOrder}; Descending=$true}

    # Move enforced GPOs to the end (they always win)
    $normalGPOs = $orderedGPOs | Where-Object { -not $_.Enforced }
    $enforcedGPOs = $orderedGPOs | Where-Object { $_.Enforced }
    $finalOrder = @($normalGPOs) + @($enforcedGPOs)

    # --- Evaluate each drive mapping ---
    # For each drive letter, the last GPO in processing order that has a mapping wins
    $effectiveMaps = @{}  # DriveLetter → winning mapping info

    foreach ($gpoEntry in $finalOrder) {
        $gpoId = $gpoEntry.GPOId.ToString()
        $relevantMaps = $AllDriveMaps | Where-Object { $_.GPOId.ToString() -eq $gpoId }

        foreach ($map in $relevantMaps) {
            # Evaluate ILT filters (simplified — check group membership)
            $iltMatch = Test-ILTMatch -Mapping $map -UserGroups $userGroups `
                -UserName $UserName -ComputerName $ComputerName `
                -ComputerGroups $computerGroups

            if (-not $iltMatch) { continue }

            $letter = $map.DriveLetter
            if (-not $letter) { continue }

            # Handle actions: Delete removes, Replace/Update/Create sets
            if ($map.Action -eq 'D') {
                # Delete action removes the mapping
                $effectiveMaps.Remove($letter)
            } else {
                $effectiveMaps[$letter] = [PSCustomObject]@{
                    DriveLetter   = $letter
                    UNCPath       = $map.UNCPath
                    Label         = $map.Label
                    Action        = $map.Action
                    WinningGPO    = $map.GPOName
                    WinningGPOId  = $map.GPOId
                    Enforced      = $gpoEntry.Enforced
                    LinkedTo      = $gpoEntry.SOMPath
                    ILTSummary    = $map.ILTSummary
                    Reason        = if ($gpoEntry.Enforced) {
                        "Enforced GPO linked to '$($gpoEntry.SOMPath)'"
                    } else {
                        "GPO linked to '$($gpoEntry.SOMPath)' (closest applicable scope)"
                    }
                }
            }
        }
    }

    $effective = [System.Collections.Generic.List[object]]::new()
    foreach ($val in $effectiveMaps.Values) { $effective.Add($val) }
    $effective = $effective | Sort-Object DriveLetter

    Write-AuditLog "Precedence simulation complete: $($effective.Count) effective drive mappings for '$UserName'" -Level Success

    return @{
        TargetUser      = $UserName
        TargetComputer  = $ComputerName
        UserDN          = $userDN
        UserGroups      = $userGroups
        EffectiveMaps   = $effective
        GPOsEvaluated   = $finalOrder.Count
    }
}

function Test-ILTMatch {
    <#
    .SYNOPSIS
        Evaluates whether a drive mapping's ILT filters match the target user/computer.
    .DESCRIPTION
        Checks group membership, user name, and computer name against the ILT filters.
        Returns $true if the mapping should apply, $false if filtered out.
        If no ILT filters exist, returns $true (applies to everyone).
    #>
    param(
        [object]$Mapping,
        [System.Collections.Generic.HashSet[string]]$UserGroups,
        [string]$UserName,
        [string]$ComputerName,
        [System.Collections.Generic.HashSet[string]]$ComputerGroups
    )

    # No ILT = applies to everyone
    if (-not $Mapping.ILTFilters -or $Mapping.ILTFilters.Count -eq 0) {
        return $true
    }

    # Evaluate each filter - simplified evaluation
    # For AND logic, all must pass. For OR logic, any must pass.
    $results = [System.Collections.Generic.List[bool]]::new()

    foreach ($filter in $Mapping.ILTFilters) {
        $match = $false

        switch -Wildcard ($filter.Type) {
            'FilterGroup' {
                # Check if user is in the group
                $groupName = $filter.Detail -replace "^Group\s+(IS|IS NOT)\s+'(.+)'$", '$2'
                if ($groupName) {
                    $match = $UserGroups.Contains($groupName) -or
                             $ComputerGroups.Contains($groupName)
                }
            }
            'FilterUser' {
                $userName2 = $filter.Detail -replace "^User\s+(IS|IS NOT)\s+'(.+)'$", '$2'
                if ($userName2) {
                    $match = $UserName -eq $userName2 -or $userName2 -match [regex]::Escape($UserName)
                }
            }
            'FilterComputer' {
                $compName = $filter.Detail -replace "^Computer\s+(IS|IS NOT)\s+'(.+)'$", '$2'
                if ($compName -and $ComputerName) {
                    $match = $ComputerName -eq $compName -or $compName -match [regex]::Escape($ComputerName)
                }
            }
            'FilterOrgUnit' {
                # OU filter — match if user's DN contains the OU
                $ouName = $filter.Detail -replace "^OU\s+(IS|IS NOT)\s+'(.+)'$", '$2'
                if ($ouName -and $Mapping) {
                    $match = $Mapping.GPOLinksText -match [regex]::Escape($ouName)
                }
            }
            default {
                # For filter types we can't evaluate (IP range, OS, site, etc.),
                # assume they match to avoid false negatives in simulation
                $match = $true
            }
        }

        # Handle NOT logic
        if ($filter.Not) { $match = -not $match }

        $results.Add($match)
    }

    if ($results.Count -eq 0) { return $true }

    # Check if any filter uses OR logic
    $hasOr = $Mapping.ILTFilters | Where-Object { $_.Bool -eq 'OR' }

    if ($hasOr) {
        # OR: any match is sufficient
        return ($results | Where-Object { $_ }).Count -gt 0
    } else {
        # AND: all must match
        return -not ($results | Where-Object { -not $_ })
    }
}
#endregion

#region Report Generation
function Export-HTMLReport {
    param(
        [hashtable]$AuditResults,
        [string]$OutputFile
    )

    Write-AuditLog "Generating HTML report..." -Level Info

    # Pre-compute values that are awkward to calculate inside the here-string
    $unreachableCount = if (-not $SkipPathValidation -and $AuditResults.PathValidation) {
        ($AuditResults.PathValidation | Where-Object { -not $_.Reachable }).Count
    } else { 0 }

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>GPO Drive Map Audit Report</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; color: #2c3e50; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; border-left: 4px solid #3498db; padding-left: 10px; }
        h3 { color: #7f8c8d; }
        .summary-box { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .metric { display: inline-block; margin: 10px 20px; text-align: center; }
        .metric-value { font-size: 36px; font-weight: bold; color: #3498db; }
        .metric-label { font-size: 14px; color: #7f8c8d; }
        table { border-collapse: collapse; width: 100%; margin: 15px 0; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); table-layout: fixed; }
        th, td { padding: 10px 8px; text-align: left; border-bottom: 1px solid #ddd; word-wrap: break-word; overflow-wrap: break-word; }
        th { background: #3498db; color: white; font-weight: 600; position: sticky; top: 0; }
        tr:hover { background: #f8f9fa; }
        .severity-high { color: #e74c3c; font-weight: bold; }
        .severity-warning { color: #f39c12; font-weight: bold; }
        .severity-info { color: #3498db; }
        .severity-ok { color: #27ae60; }
        .conflict { background: #fdf2f2; }
        .unreachable { background: #fdf2f2; }
        .recommendation { background: #fef9e7; padding: 10px; border-left: 4px solid #f39c12; margin: 10px 0; }
        .section { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; overflow-x: auto; }
        .footer { text-align: center; color: #7f8c8d; margin-top: 30px; padding: 20px; }
        .toc { background: #fff; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .toc a { color: #3498db; text-decoration: none; }
        .toc a:hover { text-decoration: underline; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; }
        .badge-danger { background: #e74c3c; color: white; }
        .badge-warning { background: #f39c12; color: white; }
        .badge-info { background: #3498db; color: white; }
        .badge-success { background: #27ae60; color: white; }
        .back-to-top { text-align: right; margin-top: 10px; font-size: 13px; }
        .back-to-top a { color: #3498db; text-decoration: none; }
        .back-to-top a:hover { text-decoration: underline; }
        td .multi-value { display: block; padding: 1px 0; }
        .ilt-tag { display: inline-block; background: #eaf2f8; color: #2c3e50; padding: 2px 8px; border-radius: 10px; font-size: 11px; margin: 2px; border: 1px solid #bdc3c7; }
        .enforced-tag { background: #e74c3c; color: white; padding: 2px 8px; border-radius: 10px; font-size: 11px; }
        .winner-row { background: #eafaf1; }
        .col-gpo { width: 15%; } .col-scope { width: 5%; } .col-action { width: 6%; }
        .col-drive { width: 5%; } .col-path { width: 22%; } .col-label { width: 8%; }
        .col-reconnect { width: 5%; } .col-ilt { width: 17%; } .col-links { width: 17%; font-size: 11px; }
    </style>
</head>
<body>
    <div class="container">
        <h1 id="top">GPO Drive Map Audit Report</h1>

        <div class="summary-box">
            <h3>Audit Summary</h3>
            <div class="metric">
                <div class="metric-value">$($AuditResults.TotalGPOs)</div>
                <div class="metric-label">GPOs Scanned</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($AuditResults.AllDriveMaps.Count)</div>
                <div class="metric-label">Drive Mappings</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($AuditResults.Issues.Conflicts.Count)</div>
                <div class="metric-label">Letter Conflicts</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($AuditResults.Issues.Duplicates.Count)</div>
                <div class="metric-label">Duplicate Paths</div>
            </div>
            $(if (-not $SkipPathValidation) {
                "<div class='metric'>
                    <div class='metric-value'>$unreachableCount</div>
                    <div class='metric-label'>Unreachable Paths</div>
                </div>"
            })
            <p><strong>Domain:</strong> $(Escape-Html $AuditResults.Domain) | <strong>Date:</strong> $(Escape-Html $AuditResults.AuditDate)</p>
            $(if ($AuditResults.Precedence) {
                "<p><strong>Target User:</strong> $(Escape-Html $AuditResults.Precedence.TargetUser)$(if ($AuditResults.Precedence.TargetComputer) { " | <strong>Target Computer:</strong> $(Escape-Html $AuditResults.Precedence.TargetComputer)" })</p>"
            })
        </div>

        <div class="toc">
            <h3>Table of Contents</h3>
            <ul>
                $(if ($AuditResults.Precedence) { '<li><a href="#effective">Effective Drive Maps (Winning GPOs)</a></li>' })
                <li><a href="#conflicts">Drive Letter Conflicts</a></li>
                <li><a href="#duplicates">Duplicate Share Paths</a></li>
                $(if (-not $SkipPathValidation) { '<li><a href="#pathvalidation">UNC Path Validation</a></li>' })
                <li><a href="#allmappings">All Drive Mappings</a></li>
            </ul>
        </div>

        $(if ($AuditResults.Precedence) {
            "<div class='section' id='effective'>
                <h2>Effective Drive Maps for '$(Escape-Html $AuditResults.Precedence.TargetUser)'</h2>
                <p>Showing the winning (effective) drive mapping per drive letter after GPO precedence evaluation.
                   <strong>$($AuditResults.Precedence.GPOsEvaluated)</strong> GPOs evaluated,
                   <strong>$($AuditResults.Precedence.UserGroups.Count)</strong> group memberships resolved.</p>
                $(if ($AuditResults.Precedence.EffectiveMaps.Count -gt 0) {
                    "<table>
                        <tr><th>Drive</th><th>UNC Path</th><th>Label</th><th>Winning GPO</th><th>Linked To</th><th>Enforced</th><th>Targeting</th><th>Reason</th></tr>
                        $($AuditResults.Precedence.EffectiveMaps | ForEach-Object {
                            $enforcedBadge = if ($_.Enforced) { "<span class='enforced-tag'>Enforced</span>" } else { 'No' }
                            "<tr class='winner-row'>
                                <td><strong>$(Escape-Html $_.DriveLetter)</strong></td>
                                <td>$(Escape-Html $_.UNCPath)</td>
                                <td>$(Escape-Html $_.Label)</td>
                                <td><strong>$(Escape-Html $_.WinningGPO)</strong></td>
                                <td>$(Escape-Html $_.LinkedTo)</td>
                                <td>$enforcedBadge</td>
                                <td><span class='ilt-tag'>$(Escape-Html $_.ILTSummary)</span></td>
                                <td>$(Escape-Html $_.Reason)</td>
                            </tr>"
                        })
                    </table>"
                } else {
                    "<p class='badge badge-warning'>No drive mappings would apply to this user.</p>"
                })
                <div class='back-to-top'><a href='#top'>Back to top</a></div>
            </div>"
        })

        <div class="section" id="conflicts">
            <h2>Drive Letter Conflicts</h2>
            $(if ($AuditResults.Issues.Conflicts.Count -gt 0) {
                "<p>Same drive letter mapped to different UNC paths across GPOs. Item-level targeting (ILT) is checked to determine if conflicts are real.</p>
                $($AuditResults.Issues.Conflicts | Sort-Object @{Expression={$_.HasRealConflict}; Descending=$true} | ForEach-Object {
                    $conflict = $_
                    $borderColor = if ($conflict.HasRealConflict) { '#e74c3c' } else { '#27ae60' }
                    $statusBadge = if ($conflict.HasRealConflict) { "<span class='badge badge-danger'>Real Conflict</span>" } else { "<span class='badge badge-success'>ILT Resolved</span>" }
                    "<div style='border-left: 4px solid $borderColor; padding: 12px; margin: 10px 0; background: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.08);'>
                        <h3 style='margin-top:0;'>Drive $(Escape-Html $conflict.DriveLetter): $statusBadge</h3>
                        <table>
                            <tr><th>GPO Name</th><th>UNC Path</th><th>Action</th><th>Label</th><th>Item-Level Targeting</th></tr>
                            $($conflict.MappingDetails | ForEach-Object {
                                $iltDisplay = if ($_.ILTSummary -eq 'No targeting (applies to all)') {
                                    "<span class='ilt-tag'>All users</span>"
                                } else {
                                    ($_.ILTSummary -split '; ' | ForEach-Object { "<span class='ilt-tag'>$(Escape-Html $_)</span>" }) -join ' '
                                }
                                "<tr>
                                    <td><strong>$(Escape-Html $_.GPOName)</strong></td>
                                    <td>$(Escape-Html $_.UNCPath)</td>
                                    <td>$(Escape-Html $_.Action)</td>
                                    <td>$(Escape-Html $_.Label)</td>
                                    <td>$iltDisplay</td>
                                </tr>"
                            })
                        </table>
                        <div class='recommendation'>$(Escape-Html $conflict.Recommendation)</div>
                    </div>"
                })"
            } else {
                "<p class='badge badge-success'>No drive letter conflicts found</p>"
            })
            <div class="back-to-top"><a href="#top">Back to top</a></div>
        </div>

        <div class="section" id="duplicates">
            <h2>Duplicate Share Paths</h2>
            $(if ($AuditResults.Issues.Duplicates.Count -gt 0) {
                "<p>Same UNC path mapped in multiple GPOs.</p>
                <table>
                    <tr><th>UNC Path</th><th>Drive Letters</th><th>Affected GPOs</th><th>Same Letter</th><th>Severity</th><th>Recommendation</th></tr>
                    $($AuditResults.Issues.Duplicates | ForEach-Object {
                        $severityClass = "severity-$($_.Severity.ToLower())"
                        "<tr>
                            <td>$(Escape-Html $_.UNCPath)</td>
                            <td>$(Escape-Html $_.DriveLetters)</td>
                            <td>$(($_.AffectedGPOs -split ', ' | ForEach-Object { "<span class='multi-value'>$(Escape-Html $_)</span>" }) -join '')</td>
                            <td>$($_.IsSameLetter)</td>
                            <td class='$severityClass'>$(Escape-Html $_.Severity)</td>
                            <td>$(Escape-Html $_.Recommendation)</td>
                        </tr>"
                    })
                </table>"
            } else {
                if ($AuditResults.AllDriveMaps.Count -eq 0) {
                    "<p class='badge badge-info'>No drive map preferences found in any GPO</p>"
                } else {
                    "<p class='badge badge-success'>No duplicate share paths found</p>"
                }
            })
            <div class="back-to-top"><a href="#top">Back to top</a></div>
        </div>

        $(if (-not $SkipPathValidation -and $AuditResults.PathValidation) {
            "<div class='section' id='pathvalidation'>
                <h2>UNC Path Validation</h2>
                <p>Each unique UNC path was tested for network reachability.</p>
                $(if ($AuditResults.PathValidation.Count -gt 0) {
                    "<table>
                        <tr><th>UNC Path</th><th>Reachable</th><th>Drive Letters</th><th>Affected GPOs</th><th>Recommendation</th></tr>
                        $($AuditResults.PathValidation | Sort-Object Reachable | ForEach-Object {
                            $rowClass = if (-not $_.Reachable) { 'unreachable' } else { '' }
                            $statusBadge = if ($_.Reachable) { "<span class='badge badge-success'>Yes</span>" } else { "<span class='badge badge-danger'>No</span>" }
                            "<tr class='$rowClass'>
                                <td>$(Escape-Html $_.UNCPath)</td>
                                <td>$statusBadge</td>
                                <td>$(Escape-Html $_.DriveLetters)</td>
                                <td>$(($_.AffectedGPOs -split ', ' | ForEach-Object { "<span class='multi-value'>$(Escape-Html $_)</span>" }) -join '')</td>
                                <td>$(Escape-Html $_.Recommendation)</td>
                            </tr>"
                        })
                    </table>"
                } else {
                    "<p class='badge badge-info'>No UNC paths to validate</p>"
                })
                <div class='back-to-top'><a href='#top'>Back to top</a></div>
            </div>"
        })

        <div class="section" id="allmappings">
            <h2>All Drive Mappings ($($AuditResults.AllDriveMaps.Count))</h2>
            $(if ($AuditResults.AllDriveMaps.Count -gt 0) {
                "<table>
                    <tr><th class='col-gpo'>GPO</th><th class='col-scope'>Scope</th><th class='col-action'>Action</th><th class='col-drive'>Drive</th><th class='col-path'>UNC Path</th><th class='col-label'>Label</th><th class='col-reconnect'>Reconnect</th><th class='col-ilt'>Item-Level Targeting</th><th class='col-links'>GPO Links</th></tr>
                    $($AuditResults.AllDriveMaps | Sort-Object DriveLetter, UNCPath | ForEach-Object {
                        $iltDisplay = if ($_.ILTSummary -eq 'No targeting (applies to all)') {
                            "<span class='ilt-tag'>All users</span>"
                        } else {
                            ($_.ILTSummary -split '; ' | ForEach-Object { "<span class='ilt-tag'>$(Escape-Html $_)</span>" }) -join ' '
                        }
                        $driveDisplay = if ($_.DriveLetter -and $_.DriveLetter -ne 'NOCHANGE') {
                            "<strong>$(Escape-Html $_.DriveLetter):</strong>"
                        } elseif ($_.DriveLetter -eq 'NOCHANGE') {
                            "<em style='color:#7f8c8d;'>Auto</em>"
                        } else {
                            "<em style='color:#7f8c8d;'>—</em>"
                        }
                        # Compact GPO links display
                        $linksDisplay = if ($_.GPOLinksText) {
                            ($_.GPOLinksText -split '; ' | ForEach-Object { "<span class='multi-value'>$(Escape-Html $_)</span>" }) -join ''
                        } else { '' }
                        "<tr>
                            <td>$(Escape-Html $_.GPOName)</td>
                            <td>$(Escape-Html $_.Configuration)</td>
                            <td>$(Escape-Html $_.Action)</td>
                            <td>$driveDisplay</td>
                            <td>$(Escape-Html $_.UNCPath)</td>
                            <td>$(Escape-Html $_.Label)</td>
                            <td>$(Escape-Html $_.Reconnect)</td>
                            <td>$iltDisplay</td>
                            <td style='font-size:11px;'>$linksDisplay</td>
                        </tr>"
                    })
                </table>"
            } else {
                "<p class='badge badge-info'>No drive map preferences found in any GPO</p>"
            })
            <div class="back-to-top"><a href="#top">Back to top</a></div>
        </div>

        <div class="footer">
            <p>Generated by GPO Drive Map Audit Tool v$ScriptVersion on $(Escape-Html $AuditResults.AuditDate)</p>
        </div>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-AuditLog "HTML report saved to: $OutputFile" -Level Success
}

function Export-CSVReports {
    param(
        [hashtable]$AuditResults,
        [string]$OutputPath,
        [string]$ReportName
    )

    Write-AuditLog "Generating CSV reports..." -Level Info

    if ($AuditResults.AllDriveMaps.Count -gt 0) {
        $AuditResults.AllDriveMaps | Select-Object GPOName, GPOId, Configuration, Action,
            DriveLetter, UNCPath, Label, Reconnect, ILTSummary, GPOLinksText |
            Export-Csv -Path "$OutputPath\$ReportName-AllMappings.csv" -NoTypeInformation -Encoding UTF8
    }

    if ($AuditResults.Issues.Conflicts.Count -gt 0) {
        $AuditResults.Issues.Conflicts |
            Export-Csv -Path "$OutputPath\$ReportName-Conflicts.csv" -NoTypeInformation -Encoding UTF8
    }

    if ($AuditResults.Issues.Duplicates.Count -gt 0) {
        $AuditResults.Issues.Duplicates |
            Export-Csv -Path "$OutputPath\$ReportName-Duplicates.csv" -NoTypeInformation -Encoding UTF8
    }

    if (-not $SkipPathValidation -and $AuditResults.PathValidation.Count -gt 0) {
        $AuditResults.PathValidation |
            Export-Csv -Path "$OutputPath\$ReportName-PathValidation.csv" -NoTypeInformation -Encoding UTF8
    }

    if ($AuditResults.Precedence -and $AuditResults.Precedence.EffectiveMaps.Count -gt 0) {
        $AuditResults.Precedence.EffectiveMaps |
            Export-Csv -Path "$OutputPath\$ReportName-EffectiveMaps.csv" -NoTypeInformation -Encoding UTF8
    }

    Write-AuditLog "CSV reports saved to: $OutputPath" -Level Success
}
#endregion

#region Main Execution
function Start-DriveMapAudit {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  GPO Drive Map Audit Tool v$ScriptVersion" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        Write-AuditLog "Prerequisites check failed. Exiting." -Level Error
        return
    }

    # Get domain info
    $adParams = @{}
    if ($Domain) { $adParams['Server'] = $Domain }
    if ($Credential) { $adParams['Credential'] = $Credential }

    $domainInfo = Get-ADDomain @adParams

    # Initialize results
    $auditResults = @{
        Domain          = $domainInfo.DNSRoot
        AuditDate       = $AuditDate.ToString('yyyy-MM-dd HH:mm:ss')
        TotalGPOs       = 0
        AllDriveMaps    = [System.Collections.Generic.List[object]]::new()
        Issues          = @{ Conflicts = @(); Duplicates = @() }
        PathValidation  = @()
        Precedence      = $null
    }

    # Get all GPOs
    Write-AuditLog "Retrieving all Group Policy Objects..." -Level Info
    $gpoParams = @{}
    if ($Domain) { $gpoParams['Domain'] = $Domain }
    $allGPOs = Get-GPO -All @gpoParams
    Write-AuditLog "Found $($allGPOs.Count) GPOs" -Level Success
    $auditResults.TotalGPOs = $allGPOs.Count

    # Cache all GPO reports once
    $gpoCache = Get-CachedGPOReports -GPOs $allGPOs

    # Filter to only linked GPOs — unlinked GPOs won't apply to anyone
    $linkedGPOs = @($allGPOs | Where-Object {
        $guid = $_.Id.ToString()
        if (-not $gpoCache.ContainsKey($guid)) { return $false }
        $report = $gpoCache[$guid].XmlDoc
        $links = $report.GPO.LinksTo
        $links -and $links.Count -gt 0
    })
    $skippedCount = $allGPOs.Count - $linkedGPOs.Count
    if ($skippedCount -gt 0) {
        Write-AuditLog "Skipped $skippedCount unlinked GPOs (not linked to any OU, domain, or site)" -Level Info
    }
    Write-AuditLog "Auditing $($linkedGPOs.Count) linked GPOs" -Level Success

    # Extract all drive mappings (from linked GPOs only)
    $auditResults.AllDriveMaps = Get-AllDriveMaps -GPOs $linkedGPOs -GPOCache $gpoCache

    # Conflict and duplicate detection
    $issues = Find-DriveMapConflicts -DriveMaps $auditResults.AllDriveMaps
    $auditResults.Issues = $issues

    # UNC path validation
    if (-not $SkipPathValidation) {
        $auditResults.PathValidation = Test-UNCPaths -DriveMaps $auditResults.AllDriveMaps
    }

    # GPO precedence simulation (if target user specified)
    if ($TargetUser) {
        $auditResults.Precedence = Get-EffectiveDriveMaps -UserName $TargetUser `
            -ComputerName $TargetComputer -AllDriveMaps $auditResults.AllDriveMaps `
            -AllGPOs $linkedGPOs -GPOCache $gpoCache
    }

    # Generate reports
    if (-not (Test-Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }

    $htmlReportPath = "$OutputPath\$ReportName.html"

    if ($ExportFormat -in @('HTML', 'Both')) {
        Export-HTMLReport -AuditResults $auditResults -OutputFile $htmlReportPath
    }

    if ($ExportFormat -in @('CSV', 'Both')) {
        Export-CSVReports -AuditResults $auditResults -OutputPath $OutputPath -ReportName $ReportName
    }

    # Display summary
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Drive Map Audit Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "  GPOs Scanned: $($auditResults.TotalGPOs)"
    Write-Host "  Total Drive Mappings: $($auditResults.AllDriveMaps.Count)"
    Write-Host "  Drive Letter Conflicts: $($auditResults.Issues.Conflicts.Count)"
    Write-Host "  Duplicate Paths: $($auditResults.Issues.Duplicates.Count)"

    if (-not $SkipPathValidation) {
        $unreachable = ($auditResults.PathValidation | Where-Object { -not $_.Reachable }).Count
        Write-Host ""
        Write-Host "Path Validation:" -ForegroundColor Cyan
        Write-Host "  Paths Checked: $($auditResults.PathValidation.Count)"
        Write-Host "  Reachable: $(($auditResults.PathValidation | Where-Object { $_.Reachable }).Count)"
        Write-Host "  Unreachable: $unreachable" -ForegroundColor $(if ($unreachable -gt 0) { 'Red' } else { 'Green' })
    }

    if ($auditResults.Precedence) {
        Write-Host ""
        Write-Host "GPO Precedence Simulation:" -ForegroundColor Cyan
        Write-Host "  Target User: $($auditResults.Precedence.TargetUser)"
        if ($auditResults.Precedence.TargetComputer) {
            Write-Host "  Target Computer: $($auditResults.Precedence.TargetComputer)"
        }
        Write-Host "  GPOs Evaluated: $($auditResults.Precedence.GPOsEvaluated)"
        Write-Host "  Effective Drive Maps: $($auditResults.Precedence.EffectiveMaps.Count)"
    }

    Write-Host ""
    Write-Host "Reports saved to: $OutputPath" -ForegroundColor Green
    Write-Host ""

    # Open report in browser unless skipped
    if (-not $SkipBrowserOpen -and ($ExportFormat -in @('HTML', 'Both')) -and (Test-Path $htmlReportPath)) {
        Write-AuditLog "Opening report in default browser..." -Level Info
        Start-Process $htmlReportPath
    }

    return $auditResults
}

# Run the audit
if (-not $LoadFunctionsOnly) {
    $results = Start-DriveMapAudit
}
#endregion
