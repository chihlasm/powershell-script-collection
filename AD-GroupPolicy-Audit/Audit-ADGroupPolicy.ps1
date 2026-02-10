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
    [switch]$SkipBrowserOpen
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
                # GP Preferences Drive Maps
                $drives = $ext.Extension.DriveMapSettings.Drive
                if (-not $drives) { continue }

                foreach ($drive in $drives) {
                    $props = $drive.Properties
                    if (-not $props) { continue }

                    $allDriveMaps.Add([PSCustomObject]@{
                        GPOName       = $gpo.DisplayName
                        GPOId         = $gpo.Id
                        Configuration = $scope
                        Action        = $props.action
                        DriveLetter   = $props.thisDrive
                        UNCPath       = $props.path
                        Label         = $props.label
                        Reconnect     = $props.persistent
                    })
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

        # Same drive letter mapped to different paths
        $byLetter = $allDriveMaps | Where-Object { $_.DriveLetter } |
            Group-Object -Property DriveLetter |
            Where-Object {
                ($_.Group | Select-Object -ExpandProperty UNCPath -Unique).Count -gt 1
            }

        foreach ($group in $byLetter) {
            $maps = $group.Group
            $paths = ($maps | Select-Object -ExpandProperty UNCPath -Unique) -join ' vs '
            $gpos = ($maps | Select-Object -ExpandProperty GPOName -Unique) -join ', '

            $conflictsByLetter.Add([PSCustomObject]@{
                DriveLetter    = $maps[0].DriveLetter
                ConflictPaths  = $paths
                AffectedGPOs   = $gpos
                GPOCount       = ($maps | Select-Object -ExpandProperty GPOName -Unique).Count
                Severity       = 'High'
                Recommendation = "Drive letter $($maps[0].DriveLetter): mapped to different shares - users may get unexpected mappings based on GPO precedence"
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
                # Shared Printers (GP Preferences)
                $sharedPrinters = $ext.Extension.PrinterSettings.SharedPrinter
                if ($sharedPrinters) {
                    foreach ($printer in $sharedPrinters) {
                        $props = $printer.Properties
                        if (-not $props) { continue }

                        $allPrinters.Add([PSCustomObject]@{
                            GPOName       = $gpo.DisplayName
                            GPOId         = $gpo.Id
                            Configuration = $scope
                            PrinterType   = 'Shared'
                            Action        = $props.action
                            Path          = $props.path
                            Default       = $props.default
                            Location      = $props.location
                            Comment       = $props.comment
                        })
                    }
                }

                # TCP/IP Port Printers (GP Preferences)
                $portPrinters = $ext.Extension.PrinterSettings.PortPrinter
                if ($portPrinters) {
                    foreach ($printer in $portPrinters) {
                        $props = $printer.Properties
                        if (-not $props) { continue }

                        $allPrinters.Add([PSCustomObject]@{
                            GPOName       = $gpo.DisplayName
                            GPOId         = $gpo.Id
                            Configuration = $scope
                            PrinterType   = 'TCP/IP Port'
                            Action        = $props.action
                            Path          = $props.ipAddress
                            Default       = $props.default
                            Location      = $props.location
                            Comment       = $props.comment
                        })
                    }
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
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; border-left: 4px solid #3498db; padding-left: 10px; }
        h3 { color: #7f8c8d; }
        .summary-box { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .metric { display: inline-block; margin: 10px 20px; text-align: center; }
        .metric-value { font-size: 36px; font-weight: bold; color: #3498db; }
        .metric-label { font-size: 14px; color: #7f8c8d; }
        table { border-collapse: collapse; width: 100%; margin: 15px 0; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #3498db; color: white; font-weight: 600; }
        tr:hover { background: #f8f9fa; }
        .severity-high { color: #e74c3c; font-weight: bold; }
        .severity-warning { color: #f39c12; font-weight: bold; }
        .severity-info { color: #3498db; }
        .severity-low { color: #27ae60; }
        .conflict { background: #fdf2f2; }
        .recommendation { background: #fef9e7; padding: 10px; border-left: 4px solid #f39c12; margin: 10px 0; }
        .section { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .footer { text-align: center; color: #7f8c8d; margin-top: 30px; padding: 20px; }
        .toc { background: #fff; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .toc a { color: #3498db; text-decoration: none; }
        .toc a:hover { text-decoration: underline; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; }
        .badge-danger { background: #e74c3c; color: white; }
        .badge-warning { background: #f39c12; color: white; }
        .badge-info { background: #3498db; color: white; }
        .badge-success { background: #27ae60; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Active Directory Group Policy Audit Report</h1>

        <div class="summary-box">
            <h3>Audit Summary</h3>
            <div class="metric">
                <div class="metric-value">$($AuditResults.TotalGPOs)</div>
                <div class="metric-label">Total GPOs</div>
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
            <p><strong>Domain:</strong> $(Escape-Html $AuditResults.Domain) | <strong>Date:</strong> $(Escape-Html $AuditResults.AuditDate)</p>
        </div>

        <div class="toc">
            <h3>Table of Contents</h3>
            <ul>
                <li><a href="#duplicates">Duplicate GPOs</a></li>
                <li><a href="#overlaps">Policy Overlaps &amp; Conflicts</a></li>
                <li><a href="#optimizations">Optimization Opportunities</a></li>
                <li><a href="#security">Security Analysis</a></li>
                <li><a href="#nofiltering">GPOs with No Security Filtering</a></li>
                <li><a href="#links">GPO Link Analysis</a></li>
                <li><a href="#drivemaps">Drive Map Analysis</a></li>
                <li><a href="#printers">Printer Analysis</a></li>
                $(if ($IncludeFSLogix) { '<li><a href="#fslogix">FSLogix Configuration</a></li>' })
                $(if ($ExportXML) { '<li><a href="#xmlexport">XML Export Summary</a></li>' })
            </ul>
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
                            <td>$(Escape-Html $_.AffectedGPOs)</td>
                            <td>$(Escape-Html $_.UniqueValues)</td>
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
                            <td>$(Escape-Html $_.Issues)</td>
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
                "<h3>Drive Letter Conflicts <span class='badge badge-danger'>$($AuditResults.DriveMaps.ConflictingLetters.Count)</span></h3>
                <p>Same drive letter mapped to different UNC paths across GPOs.</p>
                <table>
                    <tr><th>Drive Letter</th><th>Conflicting Paths</th><th>Affected GPOs</th><th>Severity</th><th>Recommendation</th></tr>
                    $($AuditResults.DriveMaps.ConflictingLetters | ForEach-Object {
                        "<tr class='conflict'>
                            <td>$(Escape-Html $_.DriveLetter)</td>
                            <td>$(Escape-Html $_.ConflictPaths)</td>
                            <td>$(Escape-Html $_.AffectedGPOs)</td>
                            <td class='severity-high'>$(Escape-Html $_.Severity)</td>
                            <td>$(Escape-Html $_.Recommendation)</td>
                        </tr>"
                    })
                </table>"
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
                            <td>$(Escape-Html $_.AffectedGPOs)</td>
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
                    <tr><th>GPO</th><th>Scope</th><th>Action</th><th>Drive</th><th>UNC Path</th><th>Label</th></tr>
                    $($AuditResults.DriveMaps.AllDriveMaps | Sort-Object UNCPath | ForEach-Object {
                        "<tr>
                            <td>$(Escape-Html $_.GPOName)</td>
                            <td>$(Escape-Html $_.Configuration)</td>
                            <td>$(Escape-Html $_.Action)</td>
                            <td>$(Escape-Html $_.DriveLetter)</td>
                            <td>$(Escape-Html $_.UNCPath)</td>
                            <td>$(Escape-Html $_.Label)</td>
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
                            <td>$(Escape-Html $_.ConflictPaths)</td>
                            <td>$(Escape-Html $_.AffectedGPOs)</td>
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
                            <td>$(Escape-Html $_.AffectedGPOs)</td>
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
                    <tr><th>GPO</th><th>Scope</th><th>Type</th><th>Action</th><th>Path</th><th>Default</th></tr>
                    $($AuditResults.Printers.AllPrinters | Sort-Object Path | ForEach-Object {
                        "<tr>
                            <td>$(Escape-Html $_.GPOName)</td>
                            <td>$(Escape-Html $_.Configuration)</td>
                            <td>$(Escape-Html $_.PrinterType)</td>
                            <td>$(Escape-Html $_.Action)</td>
                            <td>$(Escape-Html $_.Path)</td>
                            <td>$(Escape-Html $_.Default)</td>
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
                                <td>$(Escape-Html $_.AffectedGPOs)</td>
                                <td>$(Escape-Html $_.ConflictingValues)</td>
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

        <div class="footer">
            <p>Generated by AD Group Policy Audit Tool v$ScriptVersion on $(Escape-Html $AuditResults.AuditDate)</p>
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

    # Run audit functions
    $auditResults.Duplicates = Find-DuplicateGPOs -GPOs $allGPOs -GPOCache $gpoCache
    $auditResults.Overlaps = Find-GPOOverlaps -GPOs $allGPOs -GPOCache $gpoCache
    $auditResults.Optimizations = Get-GPOOptimizations -GPOs $allGPOs -GPOCache $gpoCache
    $auditResults.LinkAnalysis = Get-GPOLinkAnalysis -GPOs $allGPOs -GPOCache $gpoCache
    $auditResults.SecurityFindings = Get-SecurityAnalysis -GPOs $allGPOs
    $auditResults.NoSecurityFiltering = Get-GPOsWithNoSecurityFiltering -GPOs $allGPOs
    $auditResults.DriveMaps = Find-DuplicateDriveMaps -GPOs $allGPOs -GPOCache $gpoCache
    $auditResults.Printers = Find-DuplicatePrinters -GPOs $allGPOs -GPOCache $gpoCache

    # FSLogix audit
    if ($IncludeFSLogix) {
        $auditResults.FSLogix = Get-FSLogixAudit -GPOs $allGPOs -GPOCache $gpoCache
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
    Write-Host "  Total GPOs: $($auditResults.TotalGPOs)"
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
    Write-Host "  Drive Letter Conflicts: $($auditResults.DriveMaps.ConflictingLetters.Count)"
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
