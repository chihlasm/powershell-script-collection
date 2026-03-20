#Requires -Modules GroupPolicy, ActiveDirectory

<#
.SYNOPSIS
    Comprehensive Active Directory Group Policy Audit Tool.

.DESCRIPTION
    Audits AD Group Policy Objects for:
    - Duplicate policies (exact hash match and similar name detection)
    - Policy overlaps (conflicting or redundant registry settings across GPOs)
    - Optimization opportunities (empty, unlinked, stale, disabled GPOs)
    - GPOs with no security filtering (will not apply to anyone)
    - Security analysis and permission review
    - FSLogix configuration analysis (templates, registry keys, profiles)
    - GPO link analysis and inheritance review
    - Exports all GPO settings to XML for detailed comparison

    All GPO XML reports are fetched once and cached in memory to avoid
    redundant Get-GPOReport calls across analysis functions.

.PARAMETER OutputPath
    Directory where reports will be saved. Defaults to script directory.

.PARAMETER IncludeFSLogix
    Include FSLogix-specific policy audit. Default: $true

.PARAMETER ExportFormat
    Export format for reports: HTML, CSV, or Both. Default: Both

.PARAMETER ExportXML
    Export individual and combined GPO XML files. Default: $true

.PARAMETER Domain
    Specific domain to audit. If not specified, uses current domain.

.PARAMETER Credential
    Credential for connecting to domain if needed.

.PARAMETER SkipBrowserOpen
    Do not open the HTML report in the default browser after generation.

.EXAMPLE
    .\Audit-ADGroupPolicy.ps1
    Runs full audit with default settings.

.EXAMPLE
    .\Audit-ADGroupPolicy.ps1 -OutputPath "C:\Reports" -ExportFormat HTML
    Runs audit and exports HTML report to C:\Reports.

.EXAMPLE
    .\Audit-ADGroupPolicy.ps1 -Domain "contoso.com" -IncludeFSLogix $false
    Audits specific domain without FSLogix analysis.

.EXAMPLE
    .\Audit-ADGroupPolicy.ps1 -SkipBrowserOpen
    Runs full audit without opening the report in a browser.

.NOTES
    Author: PowerShell Script Collection
    Version: 2.0
    Requires: GroupPolicy module, ActiveDirectory module (RSAT)
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = $PSScriptRoot,

    [Parameter()]
    [bool]$IncludeFSLogix = $true,

    [Parameter()]
    [ValidateSet('HTML', 'CSV', 'Both')]
    [string]$ExportFormat = 'Both',

    [Parameter()]
    [bool]$ExportXML = $true,

    [Parameter()]
    [string]$Domain,

    [Parameter()]
    [PSCredential]$Credential,

    [Parameter()]
    [switch]$SkipBrowserOpen,

    [Parameter()]
    [switch]$IncludeUnlinked
)

#region Script Configuration
$ErrorActionPreference = 'Continue'
$WarningPreference = 'Continue'

$ScriptVersion = "2.0"
$AuditDate = Get-Date
$ReportName = "GPO-Audit-$($AuditDate.ToString('yyyy-MM-dd-HHmmss'))"

# FSLogix Registry Paths (all known locations where FSLogix settings may appear)
$FSLogixPaths = @{
    'Profiles'        = 'SOFTWARE\FSLogix\Profiles'
    'ODFC'            = 'SOFTWARE\Policies\FSLogix\ODFC'
    'Apps'            = 'SOFTWARE\FSLogix\Apps'
    'Logging'         = 'SOFTWARE\FSLogix\Logging'
    'CloudCacheAgent' = 'SYSTEM\CurrentControlSet\Services\frxccd\Parameters'
    'CloudCacheProxy' = 'SYSTEM\CurrentControlSet\Services\frxccds\Parameters'
}

# Regex pattern for matching FSLogix registry paths in GPO XML
# Matches Admin Templates (SOFTWARE\FSLogix, SOFTWARE\Policies\FSLogix) and
# GP Preferences registry items targeting the same keys, plus Cloud Cache services
$FSLogixPathPattern = 'FSLogix|frxccd\\\\Parameters|frxccds\\\\Parameters'

# Critical FSLogix settings - flagged in reports for extra visibility
$FSLogixCriticalSettings = @(
    'Enabled',
    'VHDLocations',
    'CCDLocations',
    'ProfileType',
    'SizeInMBs',
    'IsDynamic',
    'DeleteLocalProfileWhenVHDShouldApply',
    'FlipFlopProfileDirectoryName',
    'VolumeType',
    'LockedRetryCount',
    'LockedRetryInterval',
    'ReAttachIntervalSeconds',
    'ReAttachRetryCount',
    'PreventLoginWithFailure',
    'PreventLoginWithTempProfile',
    'AccessNetworkAsComputerObject',
    'SetTempToLocalPath',
    'RedirXMLSourceFolder',
    'RoamSearch',
    'VHDXSectorSize',
    'IncludeOfficeActivation',
    'IncludeOneDrive',
    'IncludeOutlook',
    'IncludeTeams',
    'CacheDirectory',
    'WriteCacheDirectory',
    'ClearCacheOnLogoff',
    'RefreshUserPolicy'
)
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

function Get-GPORegistrySettings {
    param(
        [Microsoft.GroupPolicy.Gpo]$GPO,
        [hashtable]$GPOCache
    )

    $registrySettings = [System.Collections.Generic.List[object]]::new()
    $guid = $GPO.Id.ToString()

    if (-not $GPOCache.ContainsKey($guid)) { return $registrySettings }

    try {
        $report = $GPOCache[$guid].XmlDoc

        foreach ($scope in @('Computer', 'User')) {
            $extensions = $report.GPO.$scope.ExtensionData
            if (-not $extensions) { continue }

            foreach ($ext in $extensions) {
                # Administrative Templates (Extension.Policy) - registry-based policies
                if ($ext.Extension.Policy) {
                    foreach ($reg in $ext.Extension.Policy) {
                        if ($reg -and $reg.RegistryKey) {
                            $registrySettings.Add([PSCustomObject]@{
                                GPOName       = $GPO.DisplayName
                                Configuration = $scope
                                Source        = 'AdminTemplate'
                                Name          = $reg.Name
                                State         = $reg.State
                                KeyPath       = $reg.RegistryKey
                                ValueName     = $reg.ValueName
                                Value         = $reg.Value
                                Type          = $reg.Type
                            })
                        }
                    }
                }

                # GP Preferences Registry Items - recurse into RegistrySettings
                # including Collection folders at any depth
                if ($ext.Extension.RegistrySettings) {
                    Get-RegistryPreferenceItems -Node $ext.Extension.RegistrySettings -GPOName $GPO.DisplayName -Scope $scope -Results $registrySettings
                }
            }
        }
    }
    catch {
        Write-AuditLog "Error extracting registry settings from '$($GPO.DisplayName)': $_" -Level Warning
    }

    return $registrySettings
}

function Get-RegistryPreferenceItems {
    param(
        [System.Xml.XmlElement]$Node,
        [string]$GPOName,
        [string]$Scope,
        [System.Collections.Generic.List[object]]$Results
    )

    # Process Registry items at this level
    if ($Node.Registry) {
        foreach ($reg in $Node.Registry) {
            $props = $reg.Properties
            if (-not $props) { continue }

            $ilt = Get-ItemLevelTargeting -PreferenceElement $reg

            $Results.Add([PSCustomObject]@{
                GPOName       = $GPOName
                Configuration = $Scope
                Source        = 'GPPreference'
                Name          = if ($props.name) { "$($props.key)\$($props.name)" } else { $props.key }
                State         = $props.action
                KeyPath       = $props.key
                ValueName     = $props.name
                Value         = $props.value
                Type          = $props.type
                ILTSummary    = $ilt.Summary
                ILTFilters    = $ilt.Filters
            })
        }
    }

    # Recurse into Collection folders (sub-folders in GP Preferences)
    if ($Node.Collection) {
        foreach ($collection in $Node.Collection) {
            Get-RegistryPreferenceItems -Node $collection -GPOName $GPOName -Scope $Scope -Results $Results
        }
    }
}

function Escape-Html {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '' }
    return [System.Security.SecurityElement]::Escape($Value)
}

function Get-ItemLevelTargeting {
    param([System.Xml.XmlElement]$PreferenceElement)

    $filters = [System.Collections.Generic.List[string]]::new()
    $filterObjects = [System.Collections.Generic.List[object]]::new()

    $filtersNode = $PreferenceElement.Filters
    if (-not $filtersNode) {
        return @{
            Summary = 'No targeting (applies to all)'
            Filters = $filterObjects
        }
    }

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
            'FilterUser' { "User $bool '$($child.name)'" }
            'FilterComputer' { "Computer $bool '$($child.name)'" }
            'FilterOrgUnit' {
                $name = $child.name
                if (-not $name) { $name = $child.directMember }
                "OU $bool '$name'"
            }
            'FilterSite' { "Site $bool '$($child.name)'" }
            'FilterNetworkAddress' {
                $addr = $child.ipAddress
                if (-not $addr) { $addr = $child.name }
                "IP Range $bool '$addr'"
            }
            'FilterOperatingSystem' { "OS $bool '$($child.name)'" }
            'FilterRunOnce' { "Run Once (apply only on first processing)" }
            'FilterCollection' {
                $nested = Get-FilterCollectionSummary -CollectionNode $child
                "Collection: ($nested)"
            }
            default {
                $name = $child.name
                if ($name) { "$filterType $bool '$name'" } else { "$filterType (details in XML)" }
            }
        }

        $filters.Add($detail)
        $filterObjects.Add([PSCustomObject]@{
            Type   = $filterType
            Bool   = $child.bool
            Not    = $child.not -eq '1'
            Detail = $detail
        })
    }

    $summary = if ($filters.Count -gt 0) { $filters -join '; ' } else { 'No targeting (applies to all)' }
    return @{ Summary = $summary; Filters = $filterObjects }
}

function Get-FilterCollectionSummary {
    param([System.Xml.XmlElement]$CollectionNode)

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
            'FilterCollection' {
                $nested = Get-FilterCollectionSummary -CollectionNode $child
                $parts.Add("($nested)")
            }
            default { $parts.Add("$($child.LocalName) $bool '$name'") }
        }
    }

    $connector = if ($CollectionNode.bool -eq 'OR') { ' OR ' } else { ' AND ' }
    return $parts -join $connector
}

function Get-DriveMapPreferenceItems {
    param(
        [System.Xml.XmlElement]$Node,
        [string]$GPOName,
        [object]$GPOId,
        [string]$Scope,
        [System.Collections.Generic.List[object]]$Results
    )

    if ($Node.Drive) {
        foreach ($drive in $Node.Drive) {
            $props = $drive.Properties
            if (-not $props) { continue }

            $ilt = Get-ItemLevelTargeting -PreferenceElement $drive

            # Resolve drive letter — thisDrive can be NOCHANGE
            $driveLetter = $props.thisDrive
            if ($driveLetter -eq 'NOCHANGE' -or [string]::IsNullOrWhiteSpace($driveLetter)) {
                if ($props.letter) { $driveLetter = $props.letter }
                elseif ($props.useLetter) { $driveLetter = $props.useLetter }
                elseif ($drive.letter) { $driveLetter = $drive.letter }
            }

            $Results.Add([PSCustomObject]@{
                GPOName       = $GPOName
                GPOId         = $GPOId
                Configuration = $Scope
                Action        = $props.action
                DriveLetter   = $driveLetter
                UNCPath       = $props.path
                Label         = $props.label
                Reconnect     = $props.persistent
                ILTSummary    = $ilt.Summary
                ILTFilters    = $ilt.Filters
            })
        }
    }

    if ($Node.Collection) {
        foreach ($collection in $Node.Collection) {
            Get-DriveMapPreferenceItems -Node $collection -GPOName $GPOName -GPOId $GPOId -Scope $Scope -Results $Results
        }
    }
}

function Get-PrinterPreferenceItems {
    param(
        [System.Xml.XmlElement]$Node,
        [string]$GPOName,
        [object]$GPOId,
        [string]$Scope,
        [System.Collections.Generic.List[object]]$Results
    )

    if ($Node.SharedPrinter) {
        foreach ($printer in $Node.SharedPrinter) {
            $props = $printer.Properties
            if (-not $props) { continue }

            $ilt = Get-ItemLevelTargeting -PreferenceElement $printer

            $Results.Add([PSCustomObject]@{
                GPOName       = $GPOName
                GPOId         = $GPOId
                Configuration = $Scope
                PrinterType   = 'Shared'
                Action        = $props.action
                Path          = $props.path
                Default       = $props.default
                Location      = $props.location
                Comment       = $props.comment
                ILTSummary    = $ilt.Summary
                ILTFilters    = $ilt.Filters
            })
        }
    }

    if ($Node.PortPrinter) {
        foreach ($printer in $Node.PortPrinter) {
            $props = $printer.Properties
            if (-not $props) { continue }

            $ilt = Get-ItemLevelTargeting -PreferenceElement $printer

            $Results.Add([PSCustomObject]@{
                GPOName       = $GPOName
                GPOId         = $GPOId
                Configuration = $Scope
                PrinterType   = 'TCP/IP Port'
                Action        = $props.action
                Path          = $props.ipAddress
                Default       = $props.default
                Location      = $props.location
                Comment       = $props.comment
                ILTSummary    = $ilt.Summary
                ILTFilters    = $ilt.Filters
            })
        }
    }

    if ($Node.Collection) {
        foreach ($collection in $Node.Collection) {
            Get-PrinterPreferenceItems -Node $collection -GPOName $GPOName -GPOId $GPOId -Scope $Scope -Results $Results
        }
    }
}
#endregion

#region Analysis Functions
function Find-DuplicateGPOs {
    param(
        [array]$GPOs,
        [hashtable]$GPOCache
    )

    Write-AuditLog "Analyzing for duplicate GPOs..." -Level Info

    $duplicates = [System.Collections.Generic.List[object]]::new()
    $gpoHashes = @{}
    $count = 0

    foreach ($gpo in $GPOs) {
        $count++
        Write-Progress -Activity "Checking Duplicates" -Status "$($gpo.DisplayName)" -PercentComplete (($count / $GPOs.Count) * 100)

        $guid = $gpo.Id.ToString()
        if (-not $GPOCache.ContainsKey($guid)) { continue }

        try {
            $reportText = $GPOCache[$guid].XmlString
            $hashBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes($reportText)
            )
            $hashString = [BitConverter]::ToString($hashBytes) -replace '-'

            if ($gpoHashes.ContainsKey($hashString)) {
                $duplicates.Add([PSCustomObject]@{
                    GPO1Name       = $gpoHashes[$hashString].DisplayName
                    GPO1Id         = $gpoHashes[$hashString].Id
                    GPO2Name       = $gpo.DisplayName
                    GPO2Id         = $gpo.Id
                    MatchType      = 'Exact Duplicate'
                    Recommendation = "Consider consolidating these GPOs or removing the duplicate"
                })
            } else {
                $gpoHashes[$hashString] = $gpo
            }
        }
        catch {
            Write-AuditLog "Error analyzing GPO '$($gpo.DisplayName)': $_" -Level Warning
        }
    }

    Write-Progress -Activity "Checking Duplicates" -Completed

    # Similar name detection
    $similarNames = [System.Collections.Generic.List[object]]::new()
    $gpoNames = $GPOs | Select-Object -ExpandProperty DisplayName

    for ($i = 0; $i -lt $gpoNames.Count; $i++) {
        for ($j = $i + 1; $j -lt $gpoNames.Count; $j++) {
            $name1 = $gpoNames[$i] -replace '[^a-zA-Z0-9]', ''
            $name2 = $gpoNames[$j] -replace '[^a-zA-Z0-9]', ''

            if ($name1 -eq $name2 -or $name1 -like "*$name2*" -or $name2 -like "*$name1*") {
                $similarNames.Add([PSCustomObject]@{
                    GPO1Name       = $gpoNames[$i]
                    GPO2Name       = $gpoNames[$j]
                    MatchType      = 'Similar Names'
                    Recommendation = "Review these GPOs for potential consolidation"
                })
            }
        }
    }

    Write-AuditLog "Found $($duplicates.Count) exact duplicates and $($similarNames.Count) similar named GPOs" -Level Info

    return @{
        ExactDuplicates = $duplicates
        SimilarNames    = $similarNames
    }
}

function Find-GPOOverlaps {
    param(
        [array]$GPOs,
        [hashtable]$GPOCache
    )

    Write-AuditLog "Analyzing for policy overlaps and conflicts..." -Level Info

    $overlaps = [System.Collections.Generic.List[object]]::new()
    $allRegistrySettings = [System.Collections.Generic.List[object]]::new()
    $count = 0

    foreach ($gpo in $GPOs) {
        $count++
        Write-Progress -Activity "Collecting Registry Settings" -Status "$($gpo.DisplayName)" -PercentComplete (($count / $GPOs.Count) * 100)

        $regSettings = Get-GPORegistrySettings -GPO $gpo -GPOCache $GPOCache
        foreach ($s in $regSettings) { $allRegistrySettings.Add($s) }
    }

    Write-Progress -Activity "Collecting Registry Settings" -Completed

    $groupedSettings = $allRegistrySettings | Group-Object -Property KeyPath, ValueName |
        Where-Object { $_.Count -gt 1 }

    foreach ($group in $groupedSettings) {
        $settings = $group.Group
        $uniqueValues = $settings | Select-Object -ExpandProperty Value -Unique

        $overlaps.Add([PSCustomObject]@{
            RegistryPath   = $settings[0].KeyPath
            ValueName      = $settings[0].ValueName
            AffectedGPOs   = ($settings | Select-Object -ExpandProperty GPOName -Unique) -join ', '
            GPOCount       = ($settings | Select-Object -ExpandProperty GPOName -Unique).Count
            UniqueValues   = $uniqueValues -join ' | '
            IsConflict     = $uniqueValues.Count -gt 1
            Severity       = if ($uniqueValues.Count -gt 1) { 'High' } else { 'Low' }
            Recommendation = if ($uniqueValues.Count -gt 1) {
                "CONFLICT: Different values set by multiple GPOs. Review and consolidate."
            } else {
                "Redundant: Same setting in multiple GPOs. Consider consolidation."
            }
        })
    }

    $conflicts = ($overlaps | Where-Object { $_.IsConflict }).Count
    $redundant = ($overlaps | Where-Object { -not $_.IsConflict }).Count

    Write-AuditLog "Found $conflicts conflicts and $redundant redundant settings" -Level Info

    return $overlaps
}

function Get-GPOOptimizations {
    param(
        [array]$GPOs,
        [hashtable]$GPOCache
    )

    Write-AuditLog "Analyzing GPO optimization opportunities..." -Level Info

    $optimizations = [System.Collections.Generic.List[object]]::new()
    $count = 0

    foreach ($gpo in $GPOs) {
        $count++
        Write-Progress -Activity "Checking Optimizations" -Status "$($gpo.DisplayName)" -PercentComplete (($count / $GPOs.Count) * 100)

        $issues = [System.Collections.Generic.List[string]]::new()
        $severity = 'Info'

        if ($gpo.GpoStatus -eq 'AllSettingsDisabled') {
            $issues.Add("GPO is completely disabled")
            $severity = 'Warning'
        }
        elseif ($gpo.GpoStatus -eq 'ComputerSettingsDisabled') {
            $issues.Add("Computer settings are disabled")
        }
        elseif ($gpo.GpoStatus -eq 'UserSettingsDisabled') {
            $issues.Add("User settings are disabled")
        }

        $guid = $gpo.Id.ToString()
        $report = if ($GPOCache.ContainsKey($guid)) { $GPOCache[$guid].XmlDoc } else { $null }

        $links = if ($report) { $report.GPO.LinksTo } else { $null }
        if (-not $links -or $links.Count -eq 0) {
            $issues.Add("GPO is not linked to any OU")
            $severity = 'Warning'
        }

        $hasComputerSettings = $report -and $report.GPO.Computer.ExtensionData -ne $null
        $hasUserSettings = $report -and $report.GPO.User.ExtensionData -ne $null

        if (-not $hasComputerSettings -and -not $hasUserSettings) {
            $issues.Add("GPO has no configured settings")
            $severity = 'High'
        }
        elseif (-not $hasComputerSettings -and $gpo.GpoStatus -ne 'ComputerSettingsDisabled') {
            $issues.Add("No computer settings but computer configuration is enabled - consider disabling")
        }
        elseif (-not $hasUserSettings -and $gpo.GpoStatus -ne 'UserSettingsDisabled') {
            $issues.Add("No user settings but user configuration is enabled - consider disabling")
        }

        $daysSinceModified = (Get-Date) - $gpo.ModificationTime
        if ($daysSinceModified.Days -gt 365) {
            $issues.Add("GPO hasn't been modified in over a year ($([int]$daysSinceModified.Days) days)")
        }

        if ($gpo.WmiFilter) {
            $issues.Add("Has WMI filter (potential performance impact): $($gpo.WmiFilter.Name)")
        }

        if ($issues.Count -gt 0) {
            $optimizations.Add([PSCustomObject]@{
                GPOName        = $gpo.DisplayName
                GPOId          = $gpo.Id
                Status         = $gpo.GpoStatus
                Created        = $gpo.CreationTime
                Modified       = $gpo.ModificationTime
                Issues         = $issues -join '; '
                Severity       = $severity
                LinkCount      = if ($links) { $links.Count } else { 0 }
                Recommendation = switch ($severity) {
                    'High'    { "Immediate action recommended - consider deleting empty GPO" }
                    'Warning' { "Review and clean up - GPO may not be needed" }
                    default   { "Minor optimization opportunity" }
                }
            })
        }
    }

    Write-Progress -Activity "Checking Optimizations" -Completed
    Write-AuditLog "Found $($optimizations.Count) GPOs with optimization opportunities" -Level Info

    return $optimizations
}

function Get-GPOLinkAnalysis {
    param(
        [array]$GPOs,
        [hashtable]$GPOCache
    )

    Write-AuditLog "Analyzing GPO links and inheritance..." -Level Info

    $linkAnalysis = [System.Collections.Generic.List[object]]::new()

    foreach ($gpo in $GPOs) {
        $guid = $gpo.Id.ToString()
        if (-not $GPOCache.ContainsKey($guid)) { continue }

        $report = $GPOCache[$guid].XmlDoc

        if ($report.GPO.LinksTo) {
            foreach ($link in $report.GPO.LinksTo) {
                $linkAnalysis.Add([PSCustomObject]@{
                    GPOName     = $gpo.DisplayName
                    GPOId       = $gpo.Id
                    LinkedTo    = $link.SOMPath
                    LinkEnabled = $link.Enabled
                    Enforced    = $link.NoOverride
                    LinkOrder   = $link.LinkOrder
                    SOMType     = switch -Regex ($link.SOMPath) {
                        '^[^/]+$'  { 'Domain' }
                        'OU='      { 'OU' }
                        'CN=Sites' { 'Site' }
                        default    { 'Unknown' }
                    }
                })
            }
        }
    }

    Write-AuditLog "Analyzed $($linkAnalysis.Count) GPO links" -Level Info

    return $linkAnalysis
}

function Get-SecurityAnalysis {
    param(
        [array]$GPOs
    )

    Write-AuditLog "Performing security analysis..." -Level Info

    $securityFindings = [System.Collections.Generic.List[object]]::new()
    $count = 0

    foreach ($gpo in $GPOs) {
        $count++
        Write-Progress -Activity "Security Analysis" -Status "$($gpo.DisplayName)" -PercentComplete (($count / $GPOs.Count) * 100)

        $gpoParams = @{ Guid = $gpo.Id }
        if ($Domain) { $gpoParams['Domain'] = $Domain }

        try {
            $permissions = Get-GPPermission @gpoParams -All

            $dangerousPerms = $permissions | Where-Object {
                $_.Permission -in @('GpoEditDeleteModifySecurity', 'GpoEdit') -and
                $_.Trustee.Name -notmatch 'Domain Admins|Enterprise Admins|SYSTEM'
            }

            if ($dangerousPerms) {
                foreach ($perm in $dangerousPerms) {
                    $securityFindings.Add([PSCustomObject]@{
                        GPOName        = $gpo.DisplayName
                        GPOId          = $gpo.Id
                        Finding        = "Non-standard edit permissions"
                        Details        = "$($perm.Trustee.Name) has $($perm.Permission)"
                        Severity       = 'Warning'
                        Recommendation = "Review if $($perm.Trustee.Name) should have edit access"
                    })
                }
            }

            $authUsersApply = $permissions | Where-Object {
                $_.Trustee.Name -eq 'Authenticated Users' -and
                $_.Permission -eq 'GpoApply'
            }

            if ($authUsersApply -and $gpo.DisplayName -match 'Admin|Server|Security|Restrict') {
                $securityFindings.Add([PSCustomObject]@{
                    GPOName        = $gpo.DisplayName
                    GPOId          = $gpo.Id
                    Finding        = "Potentially sensitive GPO applies to all Authenticated Users"
                    Details        = "GPO name suggests restricted use but applies broadly"
                    Severity       = 'Info'
                    Recommendation = "Review if this GPO should have security filtering"
                })
            }
        }
        catch {
            Write-AuditLog "Error checking permissions for '$($gpo.DisplayName)': $_" -Level Warning
        }
    }

    Write-Progress -Activity "Security Analysis" -Completed
    Write-AuditLog "Security analysis complete: $($securityFindings.Count) findings" -Level Info

    return $securityFindings
}

function Get-GPOsWithNoSecurityFiltering {
    param(
        [array]$GPOs
    )

    Write-AuditLog "Checking for GPOs with no security filtering..." -Level Info

    $noFilteringGPOs = [System.Collections.Generic.List[object]]::new()
    $count = 0

    foreach ($gpo in $GPOs) {
        $count++
        Write-Progress -Activity "Checking Security Filtering" -Status "$($gpo.DisplayName)" -PercentComplete (($count / $GPOs.Count) * 100)

        $gpoParams = @{ Guid = $gpo.Id }
        if ($Domain) { $gpoParams['Domain'] = $Domain }

        try {
            $permissions = Get-GPPermission @gpoParams -All
            $applyPermissions = $permissions | Where-Object { $_.Permission -eq 'GpoApply' }

            if (-not $applyPermissions -or $applyPermissions.Count -eq 0) {
                $noFilteringGPOs.Add([PSCustomObject]@{
                    GPOName        = $gpo.DisplayName
                    GPOId          = $gpo.Id
                    Status         = $gpo.GpoStatus
                    Created        = $gpo.CreationTime
                    Modified       = $gpo.ModificationTime
                    Issue          = "No security principals have Apply permission"
                    Severity       = 'High'
                    Recommendation = "GPO will not apply to anyone. Add security filtering or delete the GPO."
                })
            }
            else {
                $hasAuthUsers = $applyPermissions | Where-Object {
                    $_.Trustee.Name -eq 'Authenticated Users' -or
                    $_.Trustee.SidType -eq 'WellKnownGroup'
                }

                $onlySpecificTargets = $applyPermissions | Where-Object {
                    $_.Trustee.SidType -in @('User', 'Computer') -and
                    $_.Trustee.Name -notmatch 'Domain Computers|Domain Users|Authenticated Users'
                }

                if (-not $hasAuthUsers -and $onlySpecificTargets.Count -eq $applyPermissions.Count) {
                    $targets = ($applyPermissions | Select-Object -ExpandProperty Trustee |
                        Select-Object -ExpandProperty Name) -join ', '

                    $noFilteringGPOs.Add([PSCustomObject]@{
                        GPOName        = $gpo.DisplayName
                        GPOId          = $gpo.Id
                        Status         = $gpo.GpoStatus
                        Created        = $gpo.CreationTime
                        Modified       = $gpo.ModificationTime
                        Issue          = "Only specific targets: $targets"
                        Severity       = 'Info'
                        Recommendation = "Verify this limited security filtering is intentional"
                    })
                }

                $readOnly = $permissions | Where-Object {
                    $_.Permission -eq 'GpoRead' -and
                    $_.Trustee.Name -eq 'Authenticated Users'
                }
                $authUsersApply = $applyPermissions | Where-Object {
                    $_.Trustee.Name -eq 'Authenticated Users'
                }

                if ($readOnly -and -not $authUsersApply) {
                    $actualTargets = ($applyPermissions | Select-Object -ExpandProperty Trustee |
                        Select-Object -ExpandProperty Name) -join ', '

                    $noFilteringGPOs.Add([PSCustomObject]@{
                        GPOName        = $gpo.DisplayName
                        GPOId          = $gpo.Id
                        Status         = $gpo.GpoStatus
                        Created        = $gpo.CreationTime
                        Modified       = $gpo.ModificationTime
                        Issue          = "Authenticated Users removed from Apply. Current targets: $actualTargets"
                        Severity       = 'Warning'
                        Recommendation = "Ensure security filtering targets are correct and include Domain Computers for computer settings"
                    })
                }
            }
        }
        catch {
            Write-AuditLog "Error checking security filtering for '$($gpo.DisplayName)': $_" -Level Warning
        }
    }

    Write-Progress -Activity "Checking Security Filtering" -Completed
    Write-AuditLog "Found $($noFilteringGPOs.Count) GPOs with security filtering issues" -Level Info

    return $noFilteringGPOs
}

function Get-FSLogixAudit {
    param(
        [array]$GPOs,
        [hashtable]$GPOCache
    )

    Write-AuditLog "Auditing FSLogix configurations..." -Level Info

    $fslogixFindings = @{
        GPOSettings     = [System.Collections.Generic.List[object]]::new()
        Conflicts       = [System.Collections.Generic.List[object]]::new()
        Recommendations = [System.Collections.Generic.List[object]]::new()
        Summary         = @{}
    }

    $fslogixGPOs = [System.Collections.Generic.List[string]]::new()
    $allFSLogixSettings = [System.Collections.Generic.List[object]]::new()

    foreach ($gpo in $GPOs) {
        $regSettings = Get-GPORegistrySettings -GPO $gpo -GPOCache $GPOCache

        $fslogixSettings = $regSettings | Where-Object {
            $_.KeyPath -match $FSLogixPathPattern
        }

        if ($fslogixSettings) {
            $fslogixGPOs.Add($gpo.DisplayName)

            foreach ($setting in $fslogixSettings) {
                $settingInfo = [PSCustomObject]@{
                    GPOName      = $gpo.DisplayName
                    Configuration = $setting.Configuration
                    RegistryPath = $setting.KeyPath
                    ValueName    = $setting.ValueName
                    Value        = $setting.Value
                    Type         = $setting.Type
                    IsCritical   = $setting.ValueName -in $FSLogixCriticalSettings
                    Source       = $setting.Source
                    Category     = switch -Regex ($setting.KeyPath) {
                        'FSLogix\\Profiles'   { 'Profile Container' }
                        'FSLogix\\ODFC|Policies\\FSLogix\\ODFC' { 'Office Container' }
                        'FSLogix\\Apps'       { 'App Masking' }
                        'FSLogix\\Logging'    { 'Logging' }
                        'frxccd|frxccds'      { 'Cloud Cache' }
                        default               { 'Other' }
                    }
                }

                $allFSLogixSettings.Add($settingInfo)
                $fslogixFindings.GPOSettings.Add($settingInfo)
            }
        }
    }

    # Check for FSLogix conflicts
    $groupedFSLogix = $allFSLogixSettings | Group-Object -Property RegistryPath, ValueName |
        Where-Object { $_.Count -gt 1 }

    foreach ($group in $groupedFSLogix) {
        $settings = $group.Group
        $uniqueValues = $settings | Select-Object -ExpandProperty Value -Unique

        if ($uniqueValues.Count -gt 1) {
            $fslogixFindings.Conflicts.Add([PSCustomObject]@{
                Setting          = $settings[0].ValueName
                RegistryPath     = $settings[0].RegistryPath
                AffectedGPOs     = ($settings | Select-Object -ExpandProperty GPOName) -join ', '
                ConflictingValues = $uniqueValues -join ' vs '
                IsCritical       = $settings[0].IsCritical
                Impact           = if ($settings[0].IsCritical) {
                    "HIGH - Critical FSLogix setting with conflicting values"
                } else {
                    "Medium - FSLogix setting conflict"
                }
            })
        }
    }

    # Generate FSLogix recommendations
    $recommendations = [System.Collections.Generic.List[object]]::new()

    $vhdLocations = $allFSLogixSettings | Where-Object { $_.ValueName -eq 'VHDLocations' }
    if ($vhdLocations.Count -eq 0) {
        $recommendations.Add([PSCustomObject]@{
            Category       = 'Configuration'
            Finding        = 'No VHDLocations configured'
            Severity       = 'High'
            Recommendation = 'Configure VHDLocations to specify profile storage path'
        })
    }
    elseif ($vhdLocations.Count -gt 1) {
        $recommendations.Add([PSCustomObject]@{
            Category       = 'Configuration'
            Finding        = 'VHDLocations configured in multiple GPOs'
            Severity       = 'Warning'
            Recommendation = 'Consolidate VHDLocations to single GPO to avoid conflicts'
        })
    }

    $enabled = $allFSLogixSettings | Where-Object { $_.ValueName -eq 'Enabled' }
    if ($enabled.Count -eq 0) {
        $recommendations.Add([PSCustomObject]@{
            Category       = 'Configuration'
            Finding        = 'FSLogix Enabled setting not explicitly configured'
            Severity       = 'Info'
            Recommendation = 'Consider explicitly enabling FSLogix via GPO'
        })
    }

    $deleteLocal = $allFSLogixSettings | Where-Object { $_.ValueName -eq 'DeleteLocalProfileWhenVHDShouldApply' }
    if ($deleteLocal.Count -eq 0) {
        $recommendations.Add([PSCustomObject]@{
            Category       = 'Best Practice'
            Finding        = 'DeleteLocalProfileWhenVHDShouldApply not configured'
            Severity       = 'Info'
            Recommendation = 'Consider enabling to prevent local profile conflicts'
        })
    }

    $sizeLimit = $allFSLogixSettings | Where-Object { $_.ValueName -eq 'SizeInMBs' }
    if ($sizeLimit.Count -eq 0) {
        $recommendations.Add([PSCustomObject]@{
            Category       = 'Best Practice'
            Finding        = 'Profile size limit not configured'
            Severity       = 'Info'
            Recommendation = 'Consider setting SizeInMBs to prevent unbounded profile growth'
        })
    }

    $isDynamic = $allFSLogixSettings | Where-Object { $_.ValueName -eq 'IsDynamic' }
    if ($isDynamic.Count -eq 0) {
        $recommendations.Add([PSCustomObject]@{
            Category       = 'Performance'
            Finding        = 'IsDynamic not configured'
            Severity       = 'Info'
            Recommendation = 'Consider enabling dynamic VHD to optimize storage'
        })
    }

    $preventFailure = $allFSLogixSettings | Where-Object { $_.ValueName -eq 'PreventLoginWithFailure' }
    if ($preventFailure.Count -eq 0) {
        $recommendations.Add([PSCustomObject]@{
            Category       = 'Reliability'
            Finding        = 'PreventLoginWithFailure not configured'
            Severity       = 'Info'
            Recommendation = 'Consider setting to 1 to block login when profile fails to attach (prevents data loss to local profile)'
        })
    }

    $preventTemp = $allFSLogixSettings | Where-Object { $_.ValueName -eq 'PreventLoginWithTempProfile' }
    if ($preventTemp.Count -eq 0) {
        $recommendations.Add([PSCustomObject]@{
            Category       = 'Reliability'
            Finding        = 'PreventLoginWithTempProfile not configured'
            Severity       = 'Info'
            Recommendation = 'Consider setting to 1 to block login when a temp profile would be created'
        })
    }

    # Warn if FSLogix settings are split across Admin Templates and GP Preferences
    $sources = $allFSLogixSettings | Select-Object -ExpandProperty Source -Unique
    if ($sources.Count -gt 1) {
        $adminGPOs = ($allFSLogixSettings | Where-Object { $_.Source -eq 'AdminTemplate' } |
            Select-Object -ExpandProperty GPOName -Unique) -join ', '
        $prefGPOs = ($allFSLogixSettings | Where-Object { $_.Source -eq 'GPPreference' } |
            Select-Object -ExpandProperty GPOName -Unique) -join ', '

        $recommendations.Add([PSCustomObject]@{
            Category       = 'Consistency'
            Finding        = "FSLogix settings delivered via both Admin Templates and GP Preferences registry items"
            Severity       = 'Warning'
            Recommendation = "Admin Template GPOs: $adminGPOs. GP Preference GPOs: $prefGPOs. Standardize on one method to avoid confusion - note that GP Preferences registry items are NOT removed when the GPO is unlinked."
        })
    }

    $fslogixFindings.Recommendations = $recommendations

    $fslogixFindings.Summary = @{
        TotalGPOsWithFSLogix = $fslogixGPOs.Count
        GPONames             = $fslogixGPOs -join ', '
        TotalSettings        = $allFSLogixSettings.Count
        CriticalSettings     = ($allFSLogixSettings | Where-Object { $_.IsCritical }).Count
        Conflicts            = $fslogixFindings.Conflicts.Count
        Recommendations      = $recommendations.Count
    }

    Write-AuditLog "FSLogix audit complete: $($fslogixGPOs.Count) GPOs, $($fslogixFindings.Conflicts.Count) conflicts" -Level Info

    return $fslogixFindings
}

function Find-DuplicateDriveMaps {
    param(
        [array]$GPOs,
        [hashtable]$GPOCache
    )

    Write-AuditLog "Analyzing drive map preferences across GPOs..." -Level Info

    $allDriveMaps = [System.Collections.Generic.List[object]]::new()

    foreach ($gpo in $GPOs) {
        $guid = $gpo.Id.ToString()
        if (-not $GPOCache.ContainsKey($guid)) { continue }

        $report = $GPOCache[$guid].XmlDoc

        foreach ($scope in @('Computer', 'User')) {
            $extensions = $report.GPO.$scope.ExtensionData
            if (-not $extensions) { continue }

            foreach ($ext in $extensions) {
                # GP Preferences Drive Maps - recurse into Collections
                if ($ext.Extension.DriveMapSettings) {
                    Get-DriveMapPreferenceItems -Node $ext.Extension.DriveMapSettings -GPOName $gpo.DisplayName -GPOId $gpo.Id -Scope $scope -Results $allDriveMaps
                }
            }
        }
    }

    # Group by UNC path (case-insensitive) to find same share in multiple GPOs
    $duplicatesByPath = [System.Collections.Generic.List[object]]::new()
    $conflictsByLetter = [System.Collections.Generic.List[object]]::new()

    if ($allDriveMaps.Count -gt 0) {
        # Same UNC path in multiple GPOs
        $byPath = $allDriveMaps | Group-Object -Property { $_.UNCPath.ToLower() } |
            Where-Object { ($_.Group | Select-Object -ExpandProperty GPOName -Unique).Count -gt 1 }

        foreach ($group in $byPath) {
            $maps = $group.Group
            $letters = ($maps | Select-Object -ExpandProperty DriveLetter -Unique) -join ', '
            $gpos = ($maps | Select-Object -ExpandProperty GPOName -Unique) -join ', '

            $duplicatesByPath.Add([PSCustomObject]@{
                UNCPath        = $maps[0].UNCPath
                DriveLetters   = $letters
                AffectedGPOs   = $gpos
                GPOCount       = ($maps | Select-Object -ExpandProperty GPOName -Unique).Count
                IsSameLetter   = ($maps | Select-Object -ExpandProperty DriveLetter -Unique).Count -eq 1
                Severity       = if (($maps | Select-Object -ExpandProperty DriveLetter -Unique).Count -gt 1) { 'Warning' } else { 'Info' }
                Recommendation = if (($maps | Select-Object -ExpandProperty DriveLetter -Unique).Count -gt 1) {
                    "Same share mapped to different drive letters across GPOs - review for conflicts"
                } else {
                    "Same share mapped identically in multiple GPOs - consider consolidating"
                }
            })
        }

        # Same drive letter mapped to different paths (with ILT overlap check)
        $realLetterMaps = $allDriveMaps | Where-Object {
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

            # Per-mapping detail
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

            # Check ILT overlap
            $hasRealConflict = $false
            $uniquePathMaps = @($maps | Sort-Object UNCPath | Group-Object UNCPath | ForEach-Object { $_.Group[0] })
            for ($i = 0; $i -lt $uniquePathMaps.Count; $i++) {
                for ($j = $i + 1; $j -lt $uniquePathMaps.Count; $j++) {
                    $m1 = $uniquePathMaps[$i]
                    $m2 = $uniquePathMaps[$j]

                    $m1HasILT = $m1.ILTFilters -and $m1.ILTFilters.Count -gt 0
                    $m2HasILT = $m2.ILTFilters -and $m2.ILTFilters.Count -gt 0

                    if (-not $m1HasILT -or -not $m2HasILT) {
                        $hasRealConflict = $true; break
                    }

                    $g1 = @($m1.ILTFilters | Where-Object { $_.Type -eq 'FilterGroup' -and -not $_.Not } |
                        ForEach-Object { if ($_.Detail -match "'(.+)'") { $Matches[1] } }) | Where-Object { $_ }
                    $g2 = @($m2.ILTFilters | Where-Object { $_.Type -eq 'FilterGroup' -and -not $_.Not } |
                        ForEach-Object { if ($_.Detail -match "'(.+)'") { $Matches[1] } }) | Where-Object { $_ }

                    if ($g1.Count -gt 0 -and $g2.Count -gt 0) {
                        $overlap = $g1 | Where-Object { $_ -in $g2 }
                        if ($overlap.Count -gt 0) { $hasRealConflict = $true; break }
                    } else {
                        $hasRealConflict = $true; break
                    }
                }
                if ($hasRealConflict) { break }
            }

            $severity = if ($hasRealConflict) { 'High' } else { 'Info' }
            $recommendation = if ($hasRealConflict) {
                "REAL CONFLICT: Drive $letter mapped to different shares with overlapping or no targeting"
            } else {
                "ILT RESOLVED: Drive $letter mapped differently but item-level targeting does not overlap"
            }

            $conflictsByLetter.Add([PSCustomObject]@{
                DriveLetter     = $letter
                MappingDetails  = $mappingDetails
                HasRealConflict = $hasRealConflict
                ConflictPaths   = ($maps | Select-Object -ExpandProperty UNCPath -Unique) -join ' vs '
                AffectedGPOs    = ($maps | Select-Object -ExpandProperty GPOName -Unique) -join ', '
                GPOCount        = ($maps | Select-Object -ExpandProperty GPOName -Unique).Count
                Severity        = $severity
                Recommendation  = $recommendation
            })
        }
    }

    Write-AuditLog "Found $($allDriveMaps.Count) drive maps: $($duplicatesByPath.Count) duplicate paths, $($conflictsByLetter.Count) letter conflicts" -Level Info

    return @{
        AllDriveMaps       = $allDriveMaps
        DuplicatePaths     = $duplicatesByPath
        ConflictingLetters = $conflictsByLetter
    }
}

function Find-DuplicatePrinters {
    param(
        [array]$GPOs,
        [hashtable]$GPOCache
    )

    Write-AuditLog "Analyzing printer preferences across GPOs..." -Level Info

    $allPrinters = [System.Collections.Generic.List[object]]::new()

    foreach ($gpo in $GPOs) {
        $guid = $gpo.Id.ToString()
        if (-not $GPOCache.ContainsKey($guid)) { continue }

        $report = $GPOCache[$guid].XmlDoc

        foreach ($scope in @('Computer', 'User')) {
            $extensions = $report.GPO.$scope.ExtensionData
            if (-not $extensions) { continue }

            foreach ($ext in $extensions) {
                # GP Preferences Printers - recurse into Collections
                if ($ext.Extension.PrinterSettings) {
                    Get-PrinterPreferenceItems -Node $ext.Extension.PrinterSettings -GPOName $gpo.DisplayName -GPOId $gpo.Id -Scope $scope -Results $allPrinters
                }

                # Deployed Printers (pushed via Print Management, shows as policy)
                $deployedPrinters = $ext.Extension.Policy | Where-Object { $_.Category -match 'Printer|Print' }
                if ($deployedPrinters) {
                    foreach ($printer in $deployedPrinters) {
                        $allPrinters.Add([PSCustomObject]@{
                            GPOName       = $gpo.DisplayName
                            GPOId         = $gpo.Id
                            Configuration = $scope
                            PrinterType   = 'Deployed'
                            Action        = $printer.State
                            Path          = $printer.Name
                            Default       = ''
                            Location      = ''
                            Comment       = ''
                        })
                    }
                }
            }
        }
    }

    # Group by printer path to find duplicates
    $duplicatePrinters = [System.Collections.Generic.List[object]]::new()
    $defaultConflicts = [System.Collections.Generic.List[object]]::new()

    if ($allPrinters.Count -gt 0) {
        # Same printer path in multiple GPOs
        $byPath = $allPrinters | Where-Object { $_.Path } |
            Group-Object -Property { $_.Path.ToLower() } |
            Where-Object { ($_.Group | Select-Object -ExpandProperty GPOName -Unique).Count -gt 1 }

        foreach ($group in $byPath) {
            $printers = $group.Group
            $gpos = ($printers | Select-Object -ExpandProperty GPOName -Unique) -join ', '

            $duplicatePrinters.Add([PSCustomObject]@{
                PrinterPath    = $printers[0].Path
                PrinterType    = ($printers | Select-Object -ExpandProperty PrinterType -Unique) -join ', '
                AffectedGPOs   = $gpos
                GPOCount       = ($printers | Select-Object -ExpandProperty GPOName -Unique).Count
                Severity       = 'Info'
                Recommendation = "Same printer deployed by multiple GPOs - consider consolidating to reduce processing"
            })
        }

        # Multiple GPOs setting different default printers
        $defaults = $allPrinters | Where-Object { $_.Default -eq 'true' -or $_.Default -eq '1' }
        if ($defaults) {
            $byScope = $defaults | Group-Object -Property Configuration |
                Where-Object { ($_.Group | Select-Object -ExpandProperty Path -Unique).Count -gt 1 }

            foreach ($group in $byScope) {
                $printers = $group.Group
                $paths = ($printers | Select-Object -ExpandProperty Path -Unique) -join ' vs '
                $gpos = ($printers | Select-Object -ExpandProperty GPOName -Unique) -join ', '

                $defaultConflicts.Add([PSCustomObject]@{
                    Configuration  = $printers[0].Configuration
                    ConflictPaths  = $paths
                    AffectedGPOs   = $gpos
                    GPOCount       = ($printers | Select-Object -ExpandProperty GPOName -Unique).Count
                    Severity       = 'Warning'
                    Recommendation = "Multiple GPOs set different default printers for $($printers[0].Configuration) scope - only one will win based on precedence"
                })
            }
        }
    }

    Write-AuditLog "Found $($allPrinters.Count) printer mappings: $($duplicatePrinters.Count) duplicates, $($defaultConflicts.Count) default conflicts" -Level Info

    return @{
        AllPrinters        = $allPrinters
        DuplicatePrinters  = $duplicatePrinters
        DefaultConflicts   = $defaultConflicts
    }
}
#endregion

#region Report Generation
function Export-GPOsToXML {
    param(
        [array]$GPOs,
        [hashtable]$GPOCache,
        [string]$OutputPath
    )

    Write-AuditLog "Exporting all GPOs to XML..." -Level Info

    $xmlExportPath = Join-Path $OutputPath "GPO-XML-Export"
    if (-not (Test-Path $xmlExportPath)) {
        New-Item -Path $xmlExportPath -ItemType Directory -Force | Out-Null
    }

    $exportSummary = [System.Collections.Generic.List[object]]::new()
    $count = 0

    foreach ($gpo in $GPOs) {
        $count++
        Write-Progress -Activity "Exporting GPO XML" -Status "$($gpo.DisplayName)" -PercentComplete (($count / $GPOs.Count) * 100)

        $guid = $gpo.Id.ToString()

        try {
            if (-not $GPOCache.ContainsKey($guid)) {
                throw "GPO report not found in cache"
            }

            $xmlReport = $GPOCache[$guid].XmlString
            $safeName = $gpo.DisplayName -replace '[\\/:*?"<>|]', '_'
            $fileName = "$safeName-$($gpo.Id).xml"
            $filePath = Join-Path $xmlExportPath $fileName

            $xmlReport | Out-File -FilePath $filePath -Encoding UTF8

            $exportSummary.Add([PSCustomObject]@{
                GPOName  = $gpo.DisplayName
                GPOId    = $gpo.Id
                FileName = $fileName
                FilePath = $filePath
                FileSize = (Get-Item $filePath).Length
                Status   = 'Success'
            })
        }
        catch {
            Write-AuditLog "Error exporting GPO '$($gpo.DisplayName)' to XML: $_" -Level Warning
            $exportSummary.Add([PSCustomObject]@{
                GPOName  = $gpo.DisplayName
                GPOId    = $gpo.Id
                FileName = $null
                FilePath = $null
                FileSize = 0
                Status   = "Failed: $_"
            })
        }
    }

    Write-Progress -Activity "Exporting GPO XML" -Completed

    # Combined XML with all GPO metadata
    $combinedXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<GPOAuditExport>
    <ExportDate>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</ExportDate>
    <Domain>$(if ($Domain) { $Domain } else { (Get-ADDomain).DNSRoot })</Domain>
    <TotalGPOs>$($GPOs.Count)</TotalGPOs>
    <GPOs>
        $($GPOs | ForEach-Object {
            "        <GPO>
            <Name>$([System.Security.SecurityElement]::Escape($_.DisplayName))</Name>
            <Id>$($_.Id)</Id>
            <Status>$($_.GpoStatus)</Status>
            <Created>$($_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss'))</Created>
            <Modified>$($_.ModificationTime.ToString('yyyy-MM-dd HH:mm:ss'))</Modified>
            <Owner>$([System.Security.SecurityElement]::Escape($_.Owner))</Owner>
        </GPO>"
        })
    </GPOs>
</GPOAuditExport>
"@

    $combinedXml | Out-File -FilePath (Join-Path $xmlExportPath "GPO-Inventory.xml") -Encoding UTF8

    Write-AuditLog "Exported $($exportSummary.Count) GPOs to XML at: $xmlExportPath" -Level Success

    return @{
        ExportPath   = $xmlExportPath
        Summary      = $exportSummary
        SuccessCount = ($exportSummary | Where-Object { $_.Status -eq 'Success' }).Count
        FailedCount  = ($exportSummary | Where-Object { $_.Status -ne 'Success' }).Count
    }
}

function Export-HTMLReport {
    param(
        [hashtable]$AuditResults,
        [string]$OutputFile
    )

    Write-AuditLog "Generating HTML report..." -Level Info

    # Helper to escape all dynamic values in the report
    $e = { param($v) Escape-Html $v }

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>AD Group Policy Audit Report</title>
    <style>
        :root {
            --bg: #1a1d23; --bg-card: #23272e; --bg-hover: #2a2f38; --bg-detail: #1e2228;
            --text: #e0e0e0; --text-muted: #8b95a5; --text-heading: #f0f0f0;
            --border: #333a45; --accent: #5dade2; --accent-hover: #3498db;
            --table-header: #2980b9; --table-row-hover: #2a2f38;
            --shadow: rgba(0,0,0,0.3); --conflict-bg: #3a2020;
            --rec-bg: #3a3520; --rec-border: #f39c12;
            --ilt-bg: #1e3a4f; --ilt-border: #4a7a9b; --ilt-text: #b8d8f0;
            --search-bg: #2a2f38; --search-border: #444;
            --gpo-expanded: #1e3248; --gpo-hover: #252b35;
            --toggle-bg: #333a45;
        }
        body.light {
            --bg: #f5f5f5; --bg-card: #fff; --bg-hover: #f8f9fa; --bg-detail: #f9f9f9;
            --text: #2c3e50; --text-muted: #7f8c8d; --text-heading: #2c3e50;
            --border: #ddd; --accent: #3498db; --accent-hover: #2980b9;
            --table-header: #3498db; --table-row-hover: #f8f9fa;
            --shadow: rgba(0,0,0,0.1); --conflict-bg: #fdf2f2;
            --rec-bg: #fef9e7; --rec-border: #f39c12;
            --ilt-bg: #eaf2f8; --ilt-border: #bdc3c7; --ilt-text: #2c3e50;
            --search-bg: #fff; --search-border: #ddd;
            --gpo-expanded: #d5e8f7; --gpo-hover: #eaf2f8;
            --toggle-bg: #ddd;
        }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background: var(--bg); color: var(--text); transition: background 0.3s, color 0.3s; }
        .layout { display: flex; min-height: 100vh; }
        .sidebar { position: fixed; top: 0; left: 0; width: 260px; height: 100vh; background: var(--bg-card); border-right: 1px solid var(--border); overflow-y: auto; padding: 16px 0; z-index: 100; transition: background 0.3s, transform 0.3s; }
        .sidebar-header { padding: 12px 20px; font-size: 14px; font-weight: 700; color: var(--accent); text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); margin-bottom: 8px; }
        .sidebar a { display: flex; align-items: center; gap: 10px; padding: 10px 20px; color: var(--text-muted); text-decoration: none; font-size: 13px; transition: all 0.15s; border-left: 3px solid transparent; }
        .sidebar a:hover { color: var(--text); background: var(--bg-hover); }
        .sidebar a.active { color: var(--accent); background: var(--bg-hover); border-left-color: var(--accent); font-weight: 600; }
        .sidebar .nav-badge { font-size: 11px; padding: 2px 6px; border-radius: 10px; background: var(--bg-hover); color: var(--text-muted); margin-left: auto; }
        .sidebar a.active .nav-badge { background: var(--accent); color: white; }
        .main-content { margin-left: 260px; padding: 24px 32px; flex: 1; min-width: 0; }
        .container { max-width: 1400px; margin: 0 auto; }
        /* Mobile sidebar toggle */
        .sidebar-toggle { display: none; position: fixed; bottom: 20px; left: 20px; z-index: 200; background: var(--accent); color: white; border: none; border-radius: 50%; width: 48px; height: 48px; font-size: 20px; cursor: pointer; box-shadow: 0 2px 8px rgba(0,0,0,0.3); }
        @media (max-width: 900px) {
            .sidebar { transform: translateX(-100%); }
            .sidebar.open { transform: translateX(0); }
            .sidebar-toggle { display: block; }
            .main-content { margin-left: 0; padding: 20px; }
        }
        h1 { color: var(--text-heading); border-bottom: 3px solid var(--accent); padding-bottom: 10px; }
        h2 { color: var(--text-heading); margin-top: 20px; }
        h3 { color: var(--text-muted); }
        p { color: var(--text); }
        .summary-box { background: var(--bg-card); padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px var(--shadow); margin-bottom: 20px; }
        .metric { display: inline-block; margin: 10px 20px; text-align: center; }
        .metric-value { font-size: 36px; font-weight: bold; color: var(--accent); }
        .metric-label { font-size: 14px; color: var(--text-muted); }
        table { border-collapse: collapse; width: 100%; margin: 15px 0; background: var(--bg-card); box-shadow: 0 2px 4px var(--shadow); table-layout: fixed; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid var(--border); color: var(--text); word-wrap: break-word; overflow-wrap: break-word; word-break: break-word; }
        th { background: var(--table-header); color: white; font-weight: 600; }
        tr:hover { background: var(--table-row-hover); }
        .severity-high { color: #e74c3c; font-weight: bold; }
        .severity-warning { color: #f39c12; font-weight: bold; }
        .severity-info { color: var(--accent); }
        .severity-low { color: #27ae60; }
        .conflict { background: var(--conflict-bg); }
        .recommendation { background: var(--rec-bg); padding: 10px; border-left: 4px solid var(--rec-border); margin: 10px 0; color: var(--text); }
        .section { background: var(--bg-card); padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px var(--shadow); margin-bottom: 20px; display: none; overflow-x: auto; }
        .section.active { display: block; }
        .footer { text-align: center; color: var(--text-muted); margin-top: 30px; padding: 20px; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; }
        .badge-danger { background: #e74c3c; color: white; }
        .badge-warning { background: #f39c12; color: white; }
        .badge-info { background: var(--accent); color: white; }
        .badge-success { background: #27ae60; color: white; }
        td .multi-value { display: block; padding: 1px 0; }
        .ilt-tag { display: inline-block; background: var(--ilt-bg); color: var(--ilt-text); padding: 2px 8px; border-radius: 10px; font-size: 11px; margin: 2px; border: 1px solid var(--ilt-border); }
        /* Interactive settings browser */
        .settings-controls { display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }
        .settings-search { padding: 10px 16px; border: 1px solid var(--search-border); border-radius: 6px; font-size: 14px; width: 350px; background: var(--search-bg); color: var(--text); }
        .settings-search:focus { outline: none; border-color: var(--accent); }
        .gpo-row { cursor: pointer; transition: background 0.15s; }
        .gpo-row:hover { background: var(--gpo-hover) !important; }
        .gpo-row.expanded { background: var(--gpo-expanded); }
        .gpo-expand { display: inline-block; width: 18px; transition: transform 0.2s; }
        .gpo-row.expanded .gpo-expand { transform: rotate(90deg); }
        .gpo-detail { display: none; }
        .gpo-detail.show { display: table-row; }
        .gpo-detail td { padding: 0; }
        .gpo-detail-panel { padding: 12px 24px; background: var(--bg-detail); }
        .gpo-detail-search { padding: 8px 12px; border: 1px solid var(--search-border); border-radius: 4px; width: 250px; margin-bottom: 10px; font-size: 13px; background: var(--search-bg); color: var(--text); }
        .gpo-detail-search:focus { outline: none; border-color: var(--accent); }
        .inner-table { width: 100%; border-collapse: collapse; margin: 0; box-shadow: none; font-size: 13px; table-layout: auto; }
        .inner-table th { background: #217dbb; font-size: 12px; padding: 8px; cursor: pointer; }
        .inner-table th:hover { background: var(--accent-hover); }
        .inner-table td { padding: 8px; border-bottom: 1px solid var(--border); word-wrap: break-word; overflow-wrap: break-word; }
        .cat-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
        .cat-admin { background: #3d2050; color: #c39bd3; }
        .cat-reg { background: #1e4d2b; color: #82e0aa; }
        .cat-drive { background: #1b3a4b; color: #85c1e9; }
        .cat-printer { background: #4a3520; color: #f0c27a; }
        body.light .cat-admin { background: #ebdef0; color: #6c3483; }
        body.light .cat-reg { background: #d5f5e3; color: #1e8449; }
        body.light .cat-drive { background: #d6eaf8; color: #21618c; }
        body.light .cat-printer { background: #fdebd0; color: #b9770e; }
        /* Buttons */
        .btn { padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; transition: background 0.2s; }
        .btn-outline { background: transparent; border: 1px solid var(--accent); color: var(--accent); }
        .btn-outline:hover { background: var(--accent); color: white; }
        .btn-outline-danger { background: transparent; border: 1px solid #e74c3c; color: #e74c3c; }
        .btn-outline-danger:hover { background: #e74c3c; color: white; }
        .section h2 { border-left: 4px solid var(--accent); padding-left: 10px; }
    </style>
</head>
<body>
    <div class="layout">
    <nav class="sidebar" id="sidebar">
        <div class="sidebar-header">GPO Audit Report</div>
        <a href="#summary" class="nav-link active" data-section="summary">&#9670; Summary</a>
        <a href="#duplicates" class="nav-link" data-section="duplicates">&#9670; Duplicates <span class="nav-badge">$($AuditResults.Duplicates.ExactDuplicates.Count)</span></a>
        <a href="#overlaps" class="nav-link" data-section="overlaps">&#9670; Overlaps &amp; Conflicts <span class="nav-badge">$(($AuditResults.Overlaps | Where-Object { $_.IsConflict }).Count)</span></a>
        <a href="#optimizations" class="nav-link" data-section="optimizations">&#9670; Optimizations <span class="nav-badge">$($AuditResults.Optimizations.Count)</span></a>
        <a href="#security" class="nav-link" data-section="security">&#9670; Security <span class="nav-badge">$($AuditResults.SecurityFindings.Count)</span></a>
        <a href="#nofiltering" class="nav-link" data-section="nofiltering">&#9670; No Filtering <span class="nav-badge">$($AuditResults.NoSecurityFiltering.Count)</span></a>
        <a href="#links" class="nav-link" data-section="links">&#9670; Link Analysis</a>
        <a href="#drivemaps" class="nav-link" data-section="drivemaps">&#9670; Drive Maps</a>
        <a href="#printers" class="nav-link" data-section="printers">&#9670; Printers</a>
        $(if ($IncludeFSLogix) { '<a href="#fslogix" class="nav-link" data-section="fslogix">&#9670; FSLogix</a>' })
        $(if ($ExportXML) { '<a href="#xmlexport" class="nav-link" data-section="xmlexport">&#9670; XML Export</a>' })
        <a href="#gpobrowser" class="nav-link" data-section="gpobrowser">&#9670; Settings Browser <span class="nav-badge">$($AuditResults.AllSettings.Count)</span></a>
        <div style="padding: 16px 20px; margin-top: 12px; border-top: 1px solid var(--border);">
            <button class="btn btn-outline" onclick="toggleTheme()" style="width:100%; margin-bottom:8px;">
                <span id="themeIcon">&#9788;</span> <span id="themeLabel">Light</span> Mode
            </button>
        </div>
    </nav>
    <button class="sidebar-toggle" id="sidebarToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">&#9776;</button>
    <div class="main-content">
    <div class="container">
        <h1 id="top">Active Directory Group Policy Audit Report</h1>

        <div class="section active" id="summary">
            <h2>Audit Summary</h2>
            <div class="summary-box">
                <div class="metric">
                    <div class="metric-value">$($AuditResults.AuditedGPOCount)</div>
                    <div class="metric-label">GPOs Audited$(if ($AuditResults.SkippedUnlinked -gt 0) { " ($($AuditResults.SkippedUnlinked) unlinked skipped)" })</div>
                </div>
                <div class="metric">
                    <div class="metric-value">$($AuditResults.AllSettings.Count)</div>
                    <div class="metric-label">Total Settings</div>
                </div>
                <div class="metric">
                    <div class="metric-value">$($AuditResults.Duplicates.ExactDuplicates.Count)</div>
                    <div class="metric-label">Duplicates</div>
                </div>
                <div class="metric">
                    <div class="metric-value">$(($AuditResults.Overlaps | Where-Object { $_.IsConflict }).Count)</div>
                    <div class="metric-label">Conflicts</div>
                </div>
                <div class="metric">
                    <div class="metric-value">$($AuditResults.Optimizations.Count)</div>
                    <div class="metric-label">Optimization Opportunities</div>
                </div>
                <div class="metric">
                    <div class="metric-value">$($AuditResults.SecurityFindings.Count)</div>
                    <div class="metric-label">Security Findings</div>
                </div>
                <div class="metric">
                    <div class="metric-value">$($AuditResults.NoSecurityFiltering.Count)</div>
                    <div class="metric-label">No Security Filtering</div>
                </div>
            </div>
            <p><strong>Domain:</strong> $(Escape-Html $AuditResults.Domain) | <strong>Date:</strong> $(Escape-Html $AuditResults.AuditDate)</p>
        </div>

        <div class="section" id="duplicates">
            <h2>Duplicate GPOs</h2>
            $(if ($AuditResults.Duplicates.ExactDuplicates.Count -gt 0) {
                "<h3>Exact Duplicates <span class='badge badge-danger'>$($AuditResults.Duplicates.ExactDuplicates.Count)</span></h3>
                <table>
                    <tr><th>GPO 1</th><th>GPO 2</th><th>Recommendation</th></tr>
                    $($AuditResults.Duplicates.ExactDuplicates | ForEach-Object {
                        "<tr><td>$(Escape-Html $_.GPO1Name)</td><td>$(Escape-Html $_.GPO2Name)</td><td>$(Escape-Html $_.Recommendation)</td></tr>"
                    })
                </table>"
            } else {
                "<p class='badge badge-success'>No exact duplicates found</p>"
            })

            $(if ($AuditResults.Duplicates.SimilarNames.Count -gt 0) {
                "<h3>Similar Names <span class='badge badge-warning'>$($AuditResults.Duplicates.SimilarNames.Count)</span></h3>
                <table>
                    <tr><th>GPO 1</th><th>GPO 2</th><th>Recommendation</th></tr>
                    $($AuditResults.Duplicates.SimilarNames | ForEach-Object {
                        "<tr><td>$(Escape-Html $_.GPO1Name)</td><td>$(Escape-Html $_.GPO2Name)</td><td>$(Escape-Html $_.Recommendation)</td></tr>"
                    })
                </table>"
            })
        </div>

        <div class="section" id="overlaps">
            <h2>Policy Overlaps &amp; Conflicts</h2>
            $(if ($AuditResults.Overlaps.Count -gt 0) {
                "<table>
                    <tr><th>Registry Path</th><th>Value</th><th>Affected GPOs</th><th>Values</th><th>Severity</th><th>Recommendation</th></tr>
                    $($AuditResults.Overlaps | Sort-Object -Property Severity -Descending | ForEach-Object {
                        $rowClass = if ($_.IsConflict) { 'conflict' } else { '' }
                        $severityClass = "severity-$($_.Severity.ToLower())"
                        "<tr class='$rowClass'>
                            <td>$(Escape-Html $_.RegistryPath)</td>
                            <td>$(Escape-Html $_.ValueName)</td>
                            <td>$(($_.AffectedGPOs -split ', ' | ForEach-Object { "<span class='multi-value'>$(Escape-Html $_)</span>" }) -join '')</td>
                            <td>$(($_.UniqueValues -split ' \| ' | ForEach-Object { "<span class='multi-value'>$(Escape-Html $_)</span>" }) -join '')</td>
                            <td class='$severityClass'>$(Escape-Html $_.Severity)</td>
                            <td>$(Escape-Html $_.Recommendation)</td>
                        </tr>"
                    })
                </table>"
            } else {
                "<p class='badge badge-success'>No policy overlaps found</p>"
            })
        </div>

        <div class="section" id="optimizations">
            <h2>Optimization Opportunities</h2>
            $(if ($AuditResults.Optimizations.Count -gt 0) {
                "<table>
                    <tr><th>GPO Name</th><th>Status</th><th>Links</th><th>Last Modified</th><th>Issues</th><th>Severity</th></tr>
                    $($AuditResults.Optimizations | Sort-Object -Property Severity -Descending | ForEach-Object {
                        $severityClass = "severity-$($_.Severity.ToLower())"
                        "<tr>
                            <td>$(Escape-Html $_.GPOName)</td>
                            <td>$(Escape-Html $_.Status)</td>
                            <td>$($_.LinkCount)</td>
                            <td>$($_.Modified.ToString('yyyy-MM-dd'))</td>
                            <td>$(($_.Issues -split '; ' | ForEach-Object { "<span class='multi-value'>$(Escape-Html $_)</span>" }) -join '')</td>
                            <td class='$severityClass'>$(Escape-Html $_.Severity)</td>
                        </tr>"
                    })
                </table>"
            } else {
                "<p class='badge badge-success'>No optimization opportunities found</p>"
            })
        </div>

        <div class="section" id="security">
            <h2>Security Analysis</h2>
            $(if ($AuditResults.SecurityFindings.Count -gt 0) {
                "<table>
                    <tr><th>GPO Name</th><th>Finding</th><th>Details</th><th>Severity</th><th>Recommendation</th></tr>
                    $($AuditResults.SecurityFindings | Sort-Object -Property Severity -Descending | ForEach-Object {
                        $severityClass = "severity-$($_.Severity.ToLower())"
                        "<tr>
                            <td>$(Escape-Html $_.GPOName)</td>
                            <td>$(Escape-Html $_.Finding)</td>
                            <td>$(Escape-Html $_.Details)</td>
                            <td class='$severityClass'>$(Escape-Html $_.Severity)</td>
                            <td>$(Escape-Html $_.Recommendation)</td>
                        </tr>"
                    })
                </table>"
            } else {
                "<p class='badge badge-success'>No security issues found</p>"
            })
        </div>

        <div class="section" id="nofiltering">
            <h2>GPOs with No Security Filtering</h2>
            $(if ($AuditResults.NoSecurityFiltering.Count -gt 0) {
                "<table>
                    <tr><th>GPO Name</th><th>Status</th><th>Last Modified</th><th>Issue</th><th>Severity</th><th>Recommendation</th></tr>
                    $($AuditResults.NoSecurityFiltering | Sort-Object -Property Severity -Descending | ForEach-Object {
                        $severityClass = "severity-$($_.Severity.ToLower())"
                        "<tr>
                            <td>$(Escape-Html $_.GPOName)</td>
                            <td>$(Escape-Html $_.Status)</td>
                            <td>$($_.Modified.ToString('yyyy-MM-dd'))</td>
                            <td>$(Escape-Html $_.Issue)</td>
                            <td class='$severityClass'>$(Escape-Html $_.Severity)</td>
                            <td>$(Escape-Html $_.Recommendation)</td>
                        </tr>"
                    })
                </table>"
            } else {
                "<p class='badge badge-success'>All GPOs have proper security filtering</p>"
            })
        </div>

        <div class="section" id="links">
            <h2>GPO Link Analysis</h2>
            <table>
                <tr><th>GPO Name</th><th>Linked To</th><th>Type</th><th>Enabled</th><th>Enforced</th><th>Order</th></tr>
                $($AuditResults.LinkAnalysis | ForEach-Object {
                    "<tr>
                        <td>$(Escape-Html $_.GPOName)</td>
                        <td>$(Escape-Html $_.LinkedTo)</td>
                        <td>$(Escape-Html $_.SOMType)</td>
                        <td>$($_.LinkEnabled)</td>
                        <td>$($_.Enforced)</td>
                        <td>$($_.LinkOrder)</td>
                    </tr>"
                })
            </table>
        </div>

        <div class="section" id="drivemaps">
            <h2>Drive Map Analysis</h2>
            $(if ($AuditResults.DriveMaps.ConflictingLetters.Count -gt 0) {
                $realCount = ($AuditResults.DriveMaps.ConflictingLetters | Where-Object { $_.HasRealConflict }).Count
                $iltCount = ($AuditResults.DriveMaps.ConflictingLetters | Where-Object { -not $_.HasRealConflict }).Count
                "<h3>Drive Letter Conflicts <span class='badge badge-danger'>$realCount real</span> $(if ($iltCount -gt 0) { "<span class='badge badge-success'>$iltCount ILT resolved</span>" })</h3>
                <p>Same drive letter mapped to different UNC paths across GPOs.</p>"
                $AuditResults.DriveMaps.ConflictingLetters | Sort-Object { -not $_.HasRealConflict } | ForEach-Object {
                    $c = $_
                    $borderColor = if ($c.HasRealConflict) { '#e74c3c' } else { '#27ae60' }
                    $statusBadge = if ($c.HasRealConflict) { "<span class='badge badge-danger'>Real Conflict</span>" } else { "<span class='badge badge-success'>ILT Resolved</span>" }
                    "<div style='border-left:4px solid $borderColor; padding:12px; margin:10px 0; background:#fff; border-radius:4px;'>
                        <strong>Drive $(Escape-Html $c.DriveLetter):</strong> $statusBadge
                        <table style='margin-top:8px'>
                            <tr><th>GPO</th><th>UNC Path</th><th>Action</th><th>Label</th><th>Item-Level Targeting</th></tr>
                            $($c.MappingDetails | ForEach-Object {
                                $iltDisplay = if ($_.ILTSummary -eq 'No targeting (applies to all)') {
                                    "<span class='ilt-tag'>All users</span>"
                                } else {
                                    ($_.ILTSummary -split '; ' | ForEach-Object { "<span class='ilt-tag'>$(Escape-Html $_)</span>" }) -join ' '
                                }
                                "<tr>
                                    <td>$(Escape-Html $_.GPOName)</td>
                                    <td>$(Escape-Html $_.UNCPath)</td>
                                    <td>$(Escape-Html $_.Action)</td>
                                    <td>$(Escape-Html $_.Label)</td>
                                    <td>$iltDisplay</td>
                                </tr>"
                            })
                        </table>
                        <p style='color:#7f8c8d; font-size:13px; margin-top:8px;'>$(Escape-Html $c.Recommendation)</p>
                    </div>"
                }
            })

            $(if ($AuditResults.DriveMaps.DuplicatePaths.Count -gt 0) {
                "<h3>Duplicate Share Paths <span class='badge badge-warning'>$($AuditResults.DriveMaps.DuplicatePaths.Count)</span></h3>
                <p>Same UNC path mapped in multiple GPOs.</p>
                <table>
                    <tr><th>UNC Path</th><th>Drive Letters</th><th>Affected GPOs</th><th>Same Letter</th><th>Severity</th><th>Recommendation</th></tr>
                    $($AuditResults.DriveMaps.DuplicatePaths | ForEach-Object {
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
            })

            $(if ($AuditResults.DriveMaps.DuplicatePaths.Count -eq 0 -and $AuditResults.DriveMaps.ConflictingLetters.Count -eq 0) {
                if ($AuditResults.DriveMaps.AllDriveMaps.Count -eq 0) {
                    "<p class='badge badge-info'>No drive map preferences found in any GPO</p>"
                } else {
                    "<p class='badge badge-success'>No duplicate or conflicting drive maps found ($($AuditResults.DriveMaps.AllDriveMaps.Count) total mappings)</p>"
                }
            })

            $(if ($AuditResults.DriveMaps.AllDriveMaps.Count -gt 0) {
                "<h3>All Drive Mappings ($($AuditResults.DriveMaps.AllDriveMaps.Count))</h3>
                <table>
                    <tr><th>GPO</th><th>Scope</th><th>Action</th><th>Drive</th><th>UNC Path</th><th>Label</th><th>Item-Level Targeting</th></tr>
                    $($AuditResults.DriveMaps.AllDriveMaps | Sort-Object DriveLetter, UNCPath | ForEach-Object {
                        $iltDisplay = if ($_.ILTSummary -eq 'No targeting (applies to all)') {
                            "<span class='ilt-tag'>All users</span>"
                        } else {
                            ($_.ILTSummary -split '; ' | ForEach-Object { "<span class='ilt-tag'>$(Escape-Html $_)</span>" }) -join ' '
                        }
                        "<tr>
                            <td>$(Escape-Html $_.GPOName)</td>
                            <td>$(Escape-Html $_.Configuration)</td>
                            <td>$(Escape-Html $_.Action)</td>
                            <td><strong>$(Escape-Html $_.DriveLetter)</strong></td>
                            <td>$(Escape-Html $_.UNCPath)</td>
                            <td>$(Escape-Html $_.Label)</td>
                            <td>$iltDisplay</td>
                        </tr>"
                    })
                </table>"
            })
        </div>

        <div class="section" id="printers">
            <h2>Printer Analysis</h2>
            $(if ($AuditResults.Printers.DefaultConflicts.Count -gt 0) {
                "<h3>Default Printer Conflicts <span class='badge badge-danger'>$($AuditResults.Printers.DefaultConflicts.Count)</span></h3>
                <p>Multiple GPOs set different default printers.</p>
                <table>
                    <tr><th>Scope</th><th>Conflicting Printers</th><th>Affected GPOs</th><th>Severity</th><th>Recommendation</th></tr>
                    $($AuditResults.Printers.DefaultConflicts | ForEach-Object {
                        "<tr class='conflict'>
                            <td>$(Escape-Html $_.Configuration)</td>
                            <td>$(($_.ConflictPaths -split ' vs ' | ForEach-Object { "<span class='multi-value'>$(Escape-Html $_)</span>" }) -join '')</td>
                            <td>$(($_.AffectedGPOs -split ', ' | ForEach-Object { "<span class='multi-value'>$(Escape-Html $_)</span>" }) -join '')</td>
                            <td class='severity-warning'>$(Escape-Html $_.Severity)</td>
                            <td>$(Escape-Html $_.Recommendation)</td>
                        </tr>"
                    })
                </table>"
            })

            $(if ($AuditResults.Printers.DuplicatePrinters.Count -gt 0) {
                "<h3>Duplicate Printers <span class='badge badge-warning'>$($AuditResults.Printers.DuplicatePrinters.Count)</span></h3>
                <p>Same printer deployed by multiple GPOs.</p>
                <table>
                    <tr><th>Printer Path</th><th>Type</th><th>Affected GPOs</th><th>Severity</th><th>Recommendation</th></tr>
                    $($AuditResults.Printers.DuplicatePrinters | ForEach-Object {
                        "<tr>
                            <td>$(Escape-Html $_.PrinterPath)</td>
                            <td>$(Escape-Html $_.PrinterType)</td>
                            <td>$(($_.AffectedGPOs -split ', ' | ForEach-Object { "<span class='multi-value'>$(Escape-Html $_)</span>" }) -join '')</td>
                            <td class='severity-info'>$(Escape-Html $_.Severity)</td>
                            <td>$(Escape-Html $_.Recommendation)</td>
                        </tr>"
                    })
                </table>"
            })

            $(if ($AuditResults.Printers.DuplicatePrinters.Count -eq 0 -and $AuditResults.Printers.DefaultConflicts.Count -eq 0) {
                if ($AuditResults.Printers.AllPrinters.Count -eq 0) {
                    "<p class='badge badge-info'>No printer preferences found in any GPO</p>"
                } else {
                    "<p class='badge badge-success'>No duplicate or conflicting printers found ($($AuditResults.Printers.AllPrinters.Count) total)</p>"
                }
            })

            $(if ($AuditResults.Printers.AllPrinters.Count -gt 0) {
                "<h3>All Printer Mappings ($($AuditResults.Printers.AllPrinters.Count))</h3>
                <table>
                    <tr><th>GPO</th><th>Scope</th><th>Type</th><th>Action</th><th>Path</th><th>Default</th><th>Item-Level Targeting</th></tr>
                    $($AuditResults.Printers.AllPrinters | Sort-Object Path | ForEach-Object {
                        $iltDisplay = if ($_.ILTSummary -eq 'No targeting (applies to all)') {
                            "<span class='ilt-tag'>All users</span>"
                        } else {
                            ($_.ILTSummary -split '; ' | ForEach-Object { "<span class='ilt-tag'>$(Escape-Html $_)</span>" }) -join ' '
                        }
                        "<tr>
                            <td>$(Escape-Html $_.GPOName)</td>
                            <td>$(Escape-Html $_.Configuration)</td>
                            <td>$(Escape-Html $_.PrinterType)</td>
                            <td>$(Escape-Html $_.Action)</td>
                            <td>$(Escape-Html $_.Path)</td>
                            <td>$(Escape-Html $_.Default)</td>
                            <td>$iltDisplay</td>
                        </tr>"
                    })
                </table>"
            })
        </div>

        $(if ($IncludeFSLogix -and $AuditResults.FSLogix) {
            "<div class='section' id='fslogix'>
                <h2>FSLogix Configuration Audit</h2>

                <div class='summary-box'>
                    <h3>FSLogix Summary</h3>
                    <p><strong>GPOs with FSLogix Settings:</strong> $($AuditResults.FSLogix.Summary.TotalGPOsWithFSLogix)</p>
                    <p><strong>Total Settings:</strong> $($AuditResults.FSLogix.Summary.TotalSettings)</p>
                    <p><strong>Critical Settings:</strong> $($AuditResults.FSLogix.Summary.CriticalSettings)</p>
                    <p><strong>Conflicts:</strong> $($AuditResults.FSLogix.Summary.Conflicts)</p>
                </div>

                $(if ($AuditResults.FSLogix.Conflicts.Count -gt 0) {
                    "<h3>FSLogix Conflicts <span class='badge badge-danger'>$($AuditResults.FSLogix.Conflicts.Count)</span></h3>
                    <table>
                        <tr><th>Setting</th><th>Registry Path</th><th>Affected GPOs</th><th>Conflicting Values</th><th>Impact</th></tr>
                        $($AuditResults.FSLogix.Conflicts | ForEach-Object {
                            "<tr class='conflict'>
                                <td>$(Escape-Html $_.Setting)</td>
                                <td>$(Escape-Html $_.RegistryPath)</td>
                                <td>$(($_.AffectedGPOs -split ', ' | ForEach-Object { "<span class='multi-value'>$(Escape-Html $_)</span>" }) -join '')</td>
                                <td>$(($_.ConflictingValues -split ' vs ' | ForEach-Object { "<span class='multi-value'>$(Escape-Html $_)</span>" }) -join '')</td>
                                <td>$(Escape-Html $_.Impact)</td>
                            </tr>"
                        })
                    </table>"
                })

                $(if ($AuditResults.FSLogix.Recommendations.Count -gt 0) {
                    "<h3>FSLogix Recommendations</h3>
                    $($AuditResults.FSLogix.Recommendations | ForEach-Object {
                        "<div class='recommendation'>
                            <strong>$(Escape-Html $_.Category) - $(Escape-Html $_.Severity):</strong> $(Escape-Html $_.Finding)<br/>
                            <em>$(Escape-Html $_.Recommendation)</em>
                        </div>"
                    })"
                })

                <h3>All FSLogix Settings</h3>
                <table>
                    <tr><th>GPO</th><th>Source</th><th>Category</th><th>Registry Path</th><th>Setting</th><th>Value</th><th>Critical</th></tr>
                    $($AuditResults.FSLogix.GPOSettings | ForEach-Object {
                        $criticalBadge = if ($_.IsCritical) { "<span class='badge badge-warning'>Yes</span>" } else { 'No' }
                        $sourceBadge = if ($_.Source -eq 'GPPreference') { "<span class='badge badge-info'>Preference</span>" } else { 'Admin Template' }
                        "<tr>
                            <td>$(Escape-Html $_.GPOName)</td>
                            <td>$sourceBadge</td>
                            <td>$(Escape-Html $_.Category)</td>
                            <td>$(Escape-Html $_.RegistryPath)</td>
                            <td>$(Escape-Html $_.ValueName)</td>
                            <td>$(Escape-Html $_.Value)</td>
                            <td>$criticalBadge</td>
                        </tr>"
                    })
                </table>
            </div>"
        })

        $(if ($ExportXML -and $AuditResults.XMLExport) {
            "<div class='section' id='xmlexport'>
                <h2>XML Export Summary</h2>
                <div class='summary-box'>
                    <p><strong>Export Location:</strong> $(Escape-Html $AuditResults.XMLExport.ExportPath)</p>
                    <p><strong>Successfully Exported:</strong> $($AuditResults.XMLExport.SuccessCount) GPOs</p>
                    <p><strong>Failed:</strong> $($AuditResults.XMLExport.FailedCount) GPOs</p>
                </div>
                <p>Individual GPO XML files have been exported for detailed analysis and comparison. Use these files to:</p>
                <ul>
                    <li>Compare settings across GPOs using diff tools</li>
                    <li>Import into documentation systems</li>
                    <li>Create backups before making changes</li>
                    <li>Perform detailed setting searches</li>
                </ul>
                $(if ($AuditResults.XMLExport.FailedCount -gt 0) {
                    "<h3>Failed Exports</h3>
                    <table>
                        <tr><th>GPO Name</th><th>Status</th></tr>
                        $($AuditResults.XMLExport.Summary | Where-Object { $_.Status -ne 'Success' } | ForEach-Object {
                            "<tr><td>$(Escape-Html $_.GPOName)</td><td class='severity-high'>$(Escape-Html $_.Status)</td></tr>"
                        })
                    </table>"
                })
            </div>"
        })

        <div class="section" id="gpobrowser">
            <h2>GPO Settings Browser <span class="badge badge-info">$($AuditResults.AllSettings.Count) settings</span></h2>
            <p>Click any GPO to expand and see all its settings. Use the search box to filter across GPO names, settings, paths, and values.</p>

            <div class="settings-controls">
                <input type="text" id="gpoGlobalSearch" class="settings-search" placeholder="Search all GPO settings..." oninput="filterGPOs()">
                <button class="btn btn-outline" onclick="expandAllGPOs(true)">Expand All</button>
                <button class="btn btn-outline-danger" onclick="expandAllGPOs(false)">Collapse All</button>
            </div>

            <table id="gpoBrowserTable">
                <thead>
                    <tr>
                        <th onclick="sortGPOTable(0)" style="cursor:pointer">GPO Name &#x25B2;&#x25BC;</th>
                        <th onclick="sortGPOTable(1)" style="cursor:pointer; width:80px;">Settings &#x25B2;&#x25BC;</th>
                        <th onclick="sortGPOTable(2)" style="cursor:pointer; width:120px;">Categories</th>
                    </tr>
                </thead>
                <tbody id="gpoBrowserBody"></tbody>
            </table>
        </div>

        <script>
        var allSettingsData = $(
            $settingsJson = $AuditResults.AllSettings | ForEach-Object {
                [PSCustomObject]@{
                    g = [System.Security.SecurityElement]::Escape($_.GPOName)
                    s = [System.Security.SecurityElement]::Escape($_.Scope)
                    c = [System.Security.SecurityElement]::Escape($_.Category)
                    n = [System.Security.SecurityElement]::Escape($_.Setting)
                    st = [System.Security.SecurityElement]::Escape($_.State)
                    k = [System.Security.SecurityElement]::Escape($_.KeyPath)
                    v = [System.Security.SecurityElement]::Escape($_.Value)
                    i = [System.Security.SecurityElement]::Escape($_.ILT)
                }
            }
            $settingsJson | ConvertTo-Json -Depth 3 -Compress
        );

        function groupByGPO(data) {
            var groups = {};
            for (var i = 0; i < data.length; i++) {
                var d = data[i];
                if (!groups[d.g]) groups[d.g] = [];
                groups[d.g].push(d);
            }
            var result = [];
            for (var name in groups) {
                var items = groups[name];
                var cats = {};
                for (var j = 0; j < items.length; j++) cats[items[j].c] = true;
                result.push({ name: name, settings: items, categories: Object.keys(cats) });
            }
            result.sort(function(a, b) { return a.name.localeCompare(b.name); });
            return result;
        }

        var gpoGroups = groupByGPO(allSettingsData || []);
        var gpoSortCol = 0, gpoSortAsc = true;

        function catClass(cat) {
            if (cat.indexOf('Admin') >= 0) return 'cat-admin';
            if (cat.indexOf('Registry') >= 0) return 'cat-reg';
            if (cat.indexOf('Drive') >= 0) return 'cat-drive';
            if (cat.indexOf('Printer') >= 0) return 'cat-printer';
            return 'cat-reg';
        }

        function renderGPOBrowser(groups) {
            var body = document.getElementById('gpoBrowserBody');
            body.innerHTML = '';
            for (var i = 0; i < groups.length; i++) {
                var g = groups[i];
                var catBadges = g.categories.map(function(c) {
                    return '<span class="cat-badge ' + catClass(c) + '">' + c + '</span> ';
                }).join('');

                var row = document.createElement('tr');
                row.className = 'gpo-row';
                row.setAttribute('data-idx', i);
                row.innerHTML = '<td><span class="gpo-expand">&#9654;</span> ' + g.name + '</td>' +
                    '<td><strong>' + g.settings.length + '</strong></td>' +
                    '<td>' + catBadges + '</td>';
                row.onclick = (function(idx) { return function() { toggleGPODetail(idx); }; })(i);
                body.appendChild(row);

                var detailRow = document.createElement('tr');
                detailRow.className = 'gpo-detail';
                detailRow.id = 'gpo-detail-' + i;
                var td = document.createElement('td');
                td.colSpan = 3;
                var panel = document.createElement('div');
                panel.className = 'gpo-detail-panel';
                panel.innerHTML = '<input type="text" class="gpo-detail-search" placeholder="Search settings..." oninput="filterGPOSettings(' + i + ', this.value)">' +
                    '<table class="inner-table"><thead><tr>' +
                    '<th onclick="sortGPOSettings(' + i + ', 0)">Scope</th>' +
                    '<th onclick="sortGPOSettings(' + i + ', 1)">Category</th>' +
                    '<th onclick="sortGPOSettings(' + i + ', 2)">Setting</th>' +
                    '<th onclick="sortGPOSettings(' + i + ', 3)">State</th>' +
                    '<th onclick="sortGPOSettings(' + i + ', 4)">Key/Path</th>' +
                    '<th onclick="sortGPOSettings(' + i + ', 5)">Value</th>' +
                    '<th onclick="sortGPOSettings(' + i + ', 6)">ILT</th>' +
                    '</tr></thead><tbody id="gpo-settings-' + i + '"></tbody></table>';
                td.appendChild(panel);
                detailRow.appendChild(td);
                body.appendChild(detailRow);

                renderGPOSettings(i, g.settings);
            }
        }

        function renderGPOSettings(idx, settings) {
            var tbody = document.getElementById('gpo-settings-' + idx);
            if (!tbody) return;
            tbody.innerHTML = '';
            for (var j = 0; j < settings.length; j++) {
                var s = settings[j];
                var iltHtml = '';
                if (s.i && s.i !== '' && s.i !== 'No targeting (applies to all)') {
                    var parts = s.i.split('; ');
                    for (var p = 0; p < parts.length; p++) iltHtml += '<span class="ilt-tag">' + parts[p] + '</span> ';
                } else if (s.i === 'No targeting (applies to all)') {
                    iltHtml = '<span class="ilt-tag">All users</span>';
                }
                var tr = document.createElement('tr');
                tr.innerHTML = '<td>' + s.s + '</td>' +
                    '<td><span class="cat-badge ' + catClass(s.c) + '">' + s.c + '</span></td>' +
                    '<td>' + (s.n || '') + '</td>' +
                    '<td>' + (s.st || '') + '</td>' +
                    '<td style="font-size:12px; word-break:break-all;">' + (s.k || '') + '</td>' +
                    '<td>' + (s.v || '') + '</td>' +
                    '<td>' + iltHtml + '</td>';
                tbody.appendChild(tr);
            }
        }

        function toggleGPODetail(idx) {
            var row = document.querySelector('[data-idx="' + idx + '"]');
            var detail = document.getElementById('gpo-detail-' + idx);
            if (!row || !detail) return;
            var isOpen = detail.classList.contains('show');
            if (isOpen) {
                detail.classList.remove('show');
                row.classList.remove('expanded');
            } else {
                detail.classList.add('show');
                row.classList.add('expanded');
            }
        }

        function filterGPOs() {
            var term = document.getElementById('gpoGlobalSearch').value.toLowerCase();
            if (!term) {
                renderGPOBrowser(gpoGroups);
                return;
            }
            var filtered = gpoGroups.filter(function(g) {
                if (g.name.toLowerCase().indexOf(term) >= 0) return true;
                return g.settings.some(function(s) {
                    return (s.n && s.n.toLowerCase().indexOf(term) >= 0) ||
                           (s.k && s.k.toLowerCase().indexOf(term) >= 0) ||
                           (s.v && s.v.toLowerCase().indexOf(term) >= 0) ||
                           (s.c && s.c.toLowerCase().indexOf(term) >= 0) ||
                           (s.i && s.i.toLowerCase().indexOf(term) >= 0);
                });
            });
            renderGPOBrowser(filtered);
            for (var i = 0; i < filtered.length; i++) {
                var detail = document.getElementById('gpo-detail-' + i);
                var row = document.querySelector('[data-idx="' + i + '"]');
                if (detail && row) {
                    detail.classList.add('show');
                    row.classList.add('expanded');
                }
            }
        }

        function filterGPOSettings(idx, term) {
            var group = gpoGroups[idx];
            if (!group) return;
            term = term.toLowerCase();
            var filtered = term ? group.settings.filter(function(s) {
                return (s.n && s.n.toLowerCase().indexOf(term) >= 0) ||
                       (s.k && s.k.toLowerCase().indexOf(term) >= 0) ||
                       (s.v && s.v.toLowerCase().indexOf(term) >= 0) ||
                       (s.c && s.c.toLowerCase().indexOf(term) >= 0);
            }) : group.settings;
            renderGPOSettings(idx, filtered);
        }

        var gpoSettingsSortState = {};
        function sortGPOSettings(idx, col) {
            var key = idx + '-' + col;
            var asc = gpoSettingsSortState[key] !== false;
            gpoSettingsSortState[key] = !asc;
            var fields = ['s', 'c', 'n', 'st', 'k', 'v', 'i'];
            var field = fields[col];
            var group = gpoGroups[idx];
            if (!group) return;
            var sorted = group.settings.slice().sort(function(a, b) {
                var va = (a[field] || '').toLowerCase(), vb = (b[field] || '').toLowerCase();
                return asc ? va.localeCompare(vb) : vb.localeCompare(va);
            });
            renderGPOSettings(idx, sorted);
        }

        function sortGPOTable(col) {
            gpoSortAsc = (gpoSortCol === col) ? !gpoSortAsc : true;
            gpoSortCol = col;
            gpoGroups.sort(function(a, b) {
                if (col === 0) return gpoSortAsc ? a.name.localeCompare(b.name) : b.name.localeCompare(a.name);
                if (col === 1) return gpoSortAsc ? a.settings.length - b.settings.length : b.settings.length - a.settings.length;
                if (col === 2) {
                    var ca = a.categories.join(','), cb = b.categories.join(',');
                    return gpoSortAsc ? ca.localeCompare(cb) : cb.localeCompare(ca);
                }
                return 0;
            });
            renderGPOBrowser(gpoGroups);
        }

        function expandAllGPOs(expand) {
            var details = document.querySelectorAll('.gpo-detail');
            var rows = document.querySelectorAll('.gpo-row');
            for (var i = 0; i < details.length; i++) {
                if (expand) {
                    details[i].classList.add('show');
                    if (rows[i]) rows[i].classList.add('expanded');
                } else {
                    details[i].classList.remove('show');
                    if (rows[i]) rows[i].classList.remove('expanded');
                }
            }
        }

        renderGPOBrowser(gpoGroups);

        // Theme toggle
        function toggleTheme() {
            document.body.classList.toggle('light');
            var isLight = document.body.classList.contains('light');
            document.getElementById('themeIcon').innerHTML = isLight ? '&#9790;' : '&#9788;';
            document.getElementById('themeLabel').textContent = isLight ? 'Dark' : 'Light';
            localStorage.setItem('gpo-audit-theme', isLight ? 'light' : 'dark');
        }
        (function() {
            var saved = localStorage.getItem('gpo-audit-theme');
            if (saved === 'light') {
                document.body.classList.add('light');
                var icon = document.getElementById('themeIcon');
                var label = document.getElementById('themeLabel');
                if (icon) icon.innerHTML = '&#9790;';
                if (label) label.textContent = 'Dark';
            }
        })();

        // Sidebar navigation — show one section at a time
        (function() {
            var links = document.querySelectorAll('.nav-link');
            var sections = document.querySelectorAll('.section');

            function showSection(sectionId) {
                for (var i = 0; i < sections.length; i++) {
                    sections[i].classList.remove('active');
                }
                var target = document.getElementById(sectionId);
                if (target) target.classList.add('active');

                for (var j = 0; j < links.length; j++) {
                    links[j].classList.remove('active');
                    if (links[j].getAttribute('data-section') === sectionId) {
                        links[j].classList.add('active');
                    }
                }
                // Close mobile sidebar after navigation
                document.getElementById('sidebar').classList.remove('open');
                window.scrollTo(0, 0);
                // Save active section
                localStorage.setItem('gpo-audit-section', sectionId);
            }

            for (var i = 0; i < links.length; i++) {
                links[i].addEventListener('click', (function(link) {
                    return function(e) {
                        e.preventDefault();
                        showSection(link.getAttribute('data-section'));
                    };
                })(links[i]));
            }

            // Restore last viewed section
            var saved = localStorage.getItem('gpo-audit-section');
            if (saved && document.getElementById(saved)) {
                showSection(saved);
            }
        })();
        </script>

        <div class="footer">
            <p>Generated by AD Group Policy Audit Tool v$ScriptVersion on $(Escape-Html $AuditResults.AuditDate)</p>
        </div>
    </div>
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

    if ($AuditResults.Duplicates.ExactDuplicates.Count -gt 0) {
        $AuditResults.Duplicates.ExactDuplicates |
            Export-Csv -Path "$OutputPath\$ReportName-Duplicates.csv" -NoTypeInformation -Encoding UTF8
    }

    if ($AuditResults.Overlaps.Count -gt 0) {
        $AuditResults.Overlaps |
            Export-Csv -Path "$OutputPath\$ReportName-Overlaps.csv" -NoTypeInformation -Encoding UTF8
    }

    if ($AuditResults.Optimizations.Count -gt 0) {
        $AuditResults.Optimizations |
            Export-Csv -Path "$OutputPath\$ReportName-Optimizations.csv" -NoTypeInformation -Encoding UTF8
    }

    if ($AuditResults.SecurityFindings.Count -gt 0) {
        $AuditResults.SecurityFindings |
            Export-Csv -Path "$OutputPath\$ReportName-Security.csv" -NoTypeInformation -Encoding UTF8
    }

    if ($AuditResults.NoSecurityFiltering.Count -gt 0) {
        $AuditResults.NoSecurityFiltering |
            Export-Csv -Path "$OutputPath\$ReportName-NoSecurityFiltering.csv" -NoTypeInformation -Encoding UTF8
    }

    if ($AuditResults.LinkAnalysis.Count -gt 0) {
        $AuditResults.LinkAnalysis |
            Export-Csv -Path "$OutputPath\$ReportName-Links.csv" -NoTypeInformation -Encoding UTF8
    }

    if ($AuditResults.DriveMaps.AllDriveMaps.Count -gt 0) {
        $AuditResults.DriveMaps.AllDriveMaps |
            Export-Csv -Path "$OutputPath\$ReportName-DriveMaps.csv" -NoTypeInformation -Encoding UTF8
    }

    if ($AuditResults.Printers.AllPrinters.Count -gt 0) {
        $AuditResults.Printers.AllPrinters |
            Export-Csv -Path "$OutputPath\$ReportName-Printers.csv" -NoTypeInformation -Encoding UTF8
    }

    if ($ExportXML -and $AuditResults.XMLExport.Summary) {
        $AuditResults.XMLExport.Summary |
            Export-Csv -Path "$OutputPath\$ReportName-XMLExport.csv" -NoTypeInformation -Encoding UTF8
    }

    if ($IncludeFSLogix -and $AuditResults.FSLogix.GPOSettings.Count -gt 0) {
        $AuditResults.FSLogix.GPOSettings |
            Export-Csv -Path "$OutputPath\$ReportName-FSLogix.csv" -NoTypeInformation -Encoding UTF8

        if ($AuditResults.FSLogix.Conflicts.Count -gt 0) {
            $AuditResults.FSLogix.Conflicts |
                Export-Csv -Path "$OutputPath\$ReportName-FSLogix-Conflicts.csv" -NoTypeInformation -Encoding UTF8
        }
    }

    Write-AuditLog "CSV reports saved to: $OutputPath" -Level Success
}
#endregion

#region Main Execution
function Start-GPOAudit {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  AD Group Policy Audit Tool v$ScriptVersion" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        Write-AuditLog "Prerequisites check failed. Exiting." -Level Error
        return
    }

    # Get domain info
    $domainInfo = if ($Domain) {
        Get-ADDomain -Server $Domain
    } else {
        Get-ADDomain
    }

    # Initialize results
    $auditResults = @{
        Domain              = $domainInfo.DNSRoot
        AuditDate           = $AuditDate.ToString('yyyy-MM-dd HH:mm:ss')
        TotalGPOs           = 0
        AuditedGPOCount     = 0
        SkippedUnlinked     = 0
        Duplicates          = @{}
        Overlaps            = @()
        Optimizations       = @()
        SecurityFindings    = @()
        NoSecurityFiltering = @()
        LinkAnalysis        = @()
        DriveMaps           = @{}
        Printers            = @{}
        FSLogix             = @{}
        XMLExport           = @{}
        AllSettings         = [System.Collections.Generic.List[object]]::new()
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

    # Filter to linked GPOs only (unless -IncludeUnlinked)
    if (-not $IncludeUnlinked) {
        $linkedGPOs = @($allGPOs | Where-Object {
            $guid = $_.Id.ToString()
            if ($gpoCache.ContainsKey($guid)) {
                $rpt = $gpoCache[$guid].XmlDoc
                $rpt.GPO.LinksTo -and @($rpt.GPO.LinksTo).Count -gt 0
            } else { $false }
        })
        $skipped = $allGPOs.Count - $linkedGPOs.Count
        if ($skipped -gt 0) {
            Write-AuditLog "Filtered out $skipped unlinked GPOs (use -IncludeUnlinked to include them)" -Level Info
        }
        $auditResults.SkippedUnlinked = $skipped
    } else {
        $linkedGPOs = $allGPOs
    }
    $auditResults.AuditedGPOCount = $linkedGPOs.Count

    # Run audit functions — use linked GPOs for all except optimizations
    $auditResults.Duplicates = Find-DuplicateGPOs -GPOs $linkedGPOs -GPOCache $gpoCache
    $auditResults.Overlaps = Find-GPOOverlaps -GPOs $linkedGPOs -GPOCache $gpoCache
    $auditResults.Optimizations = Get-GPOOptimizations -GPOs $allGPOs -GPOCache $gpoCache  # needs all GPOs
    $auditResults.LinkAnalysis = Get-GPOLinkAnalysis -GPOs $linkedGPOs -GPOCache $gpoCache
    $auditResults.SecurityFindings = Get-SecurityAnalysis -GPOs $linkedGPOs
    $auditResults.NoSecurityFiltering = Get-GPOsWithNoSecurityFiltering -GPOs $linkedGPOs
    $auditResults.DriveMaps = Find-DuplicateDriveMaps -GPOs $linkedGPOs -GPOCache $gpoCache
    $auditResults.Printers = Find-DuplicatePrinters -GPOs $linkedGPOs -GPOCache $gpoCache

    # Collect ALL settings for searchable browser
    Write-AuditLog "Collecting all GPO settings for browsable report..." -Level Info
    foreach ($gpo in $linkedGPOs) {
        $guid = $gpo.Id.ToString()
        if (-not $gpoCache.ContainsKey($guid)) { continue }
        $report = $gpoCache[$guid].XmlDoc

        foreach ($scope in @('Computer', 'User')) {
            $extensions = $report.GPO.$scope.ExtensionData
            if (-not $extensions) { continue }

            foreach ($ext in $extensions) {
                # Admin Templates
                if ($ext.Extension.Policy) {
                    foreach ($pol in $ext.Extension.Policy) {
                        if ($pol -and $pol.Name) {
                            $auditResults.AllSettings.Add([PSCustomObject]@{
                                GPOName   = $gpo.DisplayName
                                GPOId     = $gpo.Id.ToString()
                                Scope     = $scope
                                Category  = 'Admin Template'
                                Setting   = $pol.Name
                                State     = $pol.State
                                KeyPath   = $pol.RegistryKey
                                Value     = $pol.Value
                                ILT       = ''
                            })
                        }
                    }
                }
                # GP Preferences Registry
                if ($ext.Extension.RegistrySettings) {
                    $regItems = [System.Collections.Generic.List[object]]::new()
                    Get-RegistryPreferenceItems -Node $ext.Extension.RegistrySettings -GPOName $gpo.DisplayName -Scope $scope -Results $regItems
                    foreach ($ri in $regItems) {
                        $auditResults.AllSettings.Add([PSCustomObject]@{
                            GPOName   = $gpo.DisplayName
                            GPOId     = $gpo.Id.ToString()
                            Scope     = $scope
                            Category  = 'Registry Preference'
                            Setting   = if ($ri.ValueName) { $ri.ValueName } else { $ri.KeyPath }
                            State     = $ri.State
                            KeyPath   = $ri.KeyPath
                            Value     = $ri.Value
                            ILT       = $ri.ILTSummary
                        })
                    }
                }
                # Drive Maps
                if ($ext.Extension.DriveMapSettings) {
                    $dmItems = [System.Collections.Generic.List[object]]::new()
                    Get-DriveMapPreferenceItems -Node $ext.Extension.DriveMapSettings -GPOName $gpo.DisplayName -GPOId $gpo.Id -Scope $scope -Results $dmItems
                    foreach ($dm in $dmItems) {
                        $letter = if ($dm.DriveLetter -and $dm.DriveLetter -ne 'NOCHANGE') { "$($dm.DriveLetter):" } else { 'Auto' }
                        $auditResults.AllSettings.Add([PSCustomObject]@{
                            GPOName   = $gpo.DisplayName
                            GPOId     = $gpo.Id.ToString()
                            Scope     = $scope
                            Category  = 'Drive Map'
                            Setting   = "Drive $letter -> $($dm.UNCPath)"
                            State     = $dm.Action
                            KeyPath   = $dm.UNCPath
                            Value     = $dm.Label
                            ILT       = $dm.ILTSummary
                        })
                    }
                }
                # Printers
                if ($ext.Extension.PrinterSettings) {
                    $prItems = [System.Collections.Generic.List[object]]::new()
                    Get-PrinterPreferenceItems -Node $ext.Extension.PrinterSettings -GPOName $gpo.DisplayName -GPOId $gpo.Id -Scope $scope -Results $prItems
                    foreach ($pr in $prItems) {
                        $auditResults.AllSettings.Add([PSCustomObject]@{
                            GPOName   = $gpo.DisplayName
                            GPOId     = $gpo.Id.ToString()
                            Scope     = $scope
                            Category  = "Printer ($($pr.PrinterType))"
                            Setting   = $pr.Path
                            State     = $pr.Action
                            KeyPath   = $pr.Path
                            Value     = if ($pr.Default -eq 'true' -or $pr.Default -eq '1') { 'Default' } else { '' }
                            ILT       = $pr.ILTSummary
                        })
                    }
                }
            }
        }
    }
    Write-AuditLog "Collected $($auditResults.AllSettings.Count) total settings across $($linkedGPOs.Count) GPOs" -Level Success

    # FSLogix audit
    if ($IncludeFSLogix) {
        $auditResults.FSLogix = Get-FSLogixAudit -GPOs $linkedGPOs -GPOCache $gpoCache
    }

    # XML Export
    if ($ExportXML) {
        $auditResults.XMLExport = Export-GPOsToXML -GPOs $allGPOs -GPOCache $gpoCache -OutputPath $OutputPath
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
    Write-Host "  Audit Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "  GPOs Audited: $($auditResults.AuditedGPOCount) of $($auditResults.TotalGPOs) total$(if ($auditResults.SkippedUnlinked -gt 0) { " ($($auditResults.SkippedUnlinked) unlinked skipped)" })"
    Write-Host "  Total Settings: $($auditResults.AllSettings.Count)"
    Write-Host "  Exact Duplicates: $($auditResults.Duplicates.ExactDuplicates.Count)"
    Write-Host "  Similar Named GPOs: $($auditResults.Duplicates.SimilarNames.Count)"
    Write-Host "  Policy Conflicts: $(($auditResults.Overlaps | Where-Object { $_.IsConflict }).Count)"
    Write-Host "  Redundant Settings: $(($auditResults.Overlaps | Where-Object { -not $_.IsConflict }).Count)"
    Write-Host "  Optimization Opportunities: $($auditResults.Optimizations.Count)"
    Write-Host "  Security Findings: $($auditResults.SecurityFindings.Count)"
    Write-Host "  No Security Filtering Issues: $($auditResults.NoSecurityFiltering.Count)"
    Write-Host ""
    Write-Host "Drive Maps:" -ForegroundColor Cyan
    Write-Host "  Total Mappings: $($auditResults.DriveMaps.AllDriveMaps.Count)"
    Write-Host "  Duplicate Paths: $($auditResults.DriveMaps.DuplicatePaths.Count)"
    $realConflicts = ($auditResults.DriveMaps.ConflictingLetters | Where-Object { $_.HasRealConflict }).Count
    $iltResolved = ($auditResults.DriveMaps.ConflictingLetters | Where-Object { -not $_.HasRealConflict }).Count
    Write-Host "  Drive Letter Conflicts: $realConflicts real, $iltResolved ILT-resolved"
    Write-Host ""
    Write-Host "Printers:" -ForegroundColor Cyan
    Write-Host "  Total Mappings: $($auditResults.Printers.AllPrinters.Count)"
    Write-Host "  Duplicate Printers: $($auditResults.Printers.DuplicatePrinters.Count)"
    Write-Host "  Default Printer Conflicts: $($auditResults.Printers.DefaultConflicts.Count)"

    if ($IncludeFSLogix) {
        Write-Host ""
        Write-Host "FSLogix:" -ForegroundColor Cyan
        Write-Host "  GPOs with FSLogix Settings: $($auditResults.FSLogix.Summary.TotalGPOsWithFSLogix)"
        Write-Host "  FSLogix Conflicts: $($auditResults.FSLogix.Summary.Conflicts)"
        Write-Host "  Recommendations: $($auditResults.FSLogix.Summary.Recommendations)"
    }

    if ($ExportXML) {
        Write-Host ""
        Write-Host "XML Export:" -ForegroundColor Cyan
        Write-Host "  Exported: $($auditResults.XMLExport.SuccessCount) GPOs"
        Write-Host "  Failed: $($auditResults.XMLExport.FailedCount) GPOs"
        Write-Host "  Location: $($auditResults.XMLExport.ExportPath)"
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
$results = Start-GPOAudit
#endregion
