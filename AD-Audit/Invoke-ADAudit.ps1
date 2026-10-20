#Requires -Version 5.1

<#
.SYNOPSIS
    Comprehensive Active Directory Audit Tool.

.DESCRIPTION
    Audits all major Active Directory areas including:
    - Domain overview (forest, FSMO roles, trusts, sites/subnets)
    - Domain controller health and replication status
    - User account analysis (stale, locked, password issues)
    - Group analysis (empty, large, nested, privileged)
    - Computer account analysis (stale, OS distribution, unsupported OS)
    - End of support: every enabled Windows Server with Microsoft's mainstream, extended
      and ESU end dates from a cited lifecycle table, days left, and last logon
    - Password policy review (default and fine-grained, NIST 800-63B)
    - Privileged access review (AdminSDHolder, delegation, Kerberoastable, AS-REP Roastable, RBCD)
    - Security findings (reversible encryption, DES, Legacy/Windows LAPS, DNS)
    - Infrastructure health (tombstone, Recycle Bin, schema, Sysvol replication, trust health)
    - OU structure analysis (empty OUs, no GPO links, nesting depth)

    Exports results as HTML report and/or CSV files. Returns results hashtable for pipeline use.

.PARAMETER OutputPath
    Directory where reports will be saved. Defaults to the current directory.

.PARAMETER ExportFormat
    Export format for reports: HTML, CSV, or Both. Default: Both

.PARAMETER Domain
    Specific domain to audit. If not specified, uses current domain.

.PARAMETER Credential
    Credential for connecting to domain if needed.

.PARAMETER DaysInactive
    Number of days without logon to consider an object stale. Default: 90

.PARAMETER SkipBrowserOpen
    Do not open the HTML report in the default browser after generation.

.PARAMETER IncludeSection
    Array of section names to include. Default: All. Valid values:
    DomainOverview, DomainControllers, Users, Groups, Computers, EndOfSupport,
    PasswordPolicy, PrivilegedAccess, Security, Infrastructure, OUStructure

.PARAMETER LogCallback
    Optional scriptblock called with each log message. Used by GUI wrapper.

.PARAMETER LoadFunctionsOnly
    Define the audit functions and return without running an audit. Used by the Pester
    tests (dot-source the script with -LoadFunctionsOnly).

.EXAMPLE
    .\Invoke-ADAudit.ps1
    Runs full audit with default settings.

.EXAMPLE
    .\Invoke-ADAudit.ps1 -OutputPath "C:\Reports" -DaysInactive 60
    Runs audit with 60-day stale threshold, exports to C:\Reports.

.EXAMPLE
    .\Invoke-ADAudit.ps1 -Domain "contoso.com" -ExportFormat HTML -SkipBrowserOpen
    Audits specific domain, HTML only, no browser open.

.EXAMPLE
    .\Invoke-ADAudit.ps1 -IncludeSection Users, Security, PrivilegedAccess
    Runs only user, security, and privileged access audits.

.EXAMPLE
    $results = .\Invoke-ADAudit.ps1 -SkipBrowserOpen
    Captures audit results hashtable for further processing.

.NOTES
    Author: PowerShell Script Collection
    Version: 2.2
    Requires: Windows PowerShell 5.1 (uses ::new()), ActiveDirectory module (RSAT).
    The ActiveDirectory module is imported at run time (not via #Requires -Modules) so
    servers that have RSAT cmdlets available but not formally registered still work.

    The Privileged Access section is a concise summary. For full nested-group path
    analysis use Find-PrivilegedAccessPaths\Get-DomainPrivilegedAccess.ps1.

    REFERENCES
    - Schema objectVersion -> OS mapping:
      https://learn.microsoft.com/windows-server/identity/ad-ds/deploy/find-active-directory-schema
    - Well-known SIDs / RIDs (Domain Admins -512, Schema Admins -518, Enterprise Admins
      -519, BUILTIN\Administrators S-1-5-32-544, Account Operators -548, Server Operators
      -549, Backup Operators -551):
      https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
    - trustAttributes bits (QUARANTINED_DOMAIN 0x4, FOREST_TRANSITIVE 0x8, WITHIN_FOREST
      0x20, TREAT_AS_EXTERNAL 0x40):
      https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c
    - SID filtering rules per trust boundary:
      https://learn.microsoft.com/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280
    - netdom trust /quarantine (Yes = accept only SIDs from the directly trusted domain):
      https://learn.microsoft.com/windows-server/administration/windows-commands/netdom-trust
    - Windows Server lifecycle dates (End of Support section; table last checked 2026-10-20):
      https://learn.microsoft.com/lifecycle/products/windows-server-2003-
      https://learn.microsoft.com/lifecycle/products/windows-server-2008
      https://learn.microsoft.com/lifecycle/products/windows-server-2008-r2
      https://learn.microsoft.com/lifecycle/products/windows-server-2012
      https://learn.microsoft.com/lifecycle/products/windows-server-2012-r2
      https://learn.microsoft.com/lifecycle/products/windows-server-2016
      https://learn.microsoft.com/lifecycle/products/windows-server-2019
      https://learn.microsoft.com/lifecycle/products/windows-server-2022
      https://learn.microsoft.com/lifecycle/products/windows-server-2025
    - lastLogonTimestamp (source of LastLogonDate) replicates only when older than
      msDS-LogonTimeSyncInterval, so last logon can lag by about 14 days:
      https://learn.microsoft.com/windows/win32/adschema/a-lastlogontimestamp
      https://learn.microsoft.com/windows/win32/adschema/a-msds-logontimesyncinterval
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter()]
    [ValidateSet('HTML', 'CSV', 'Both')]
    [string]$ExportFormat = 'Both',

    [Parameter()]
    [string]$Domain,

    [Parameter()]
    [PSCredential]$Credential,

    [Parameter()]
    [int]$DaysInactive = 90,

    [Parameter()]
    [switch]$SkipBrowserOpen,

    [Parameter()]
    [ValidateSet('All','DomainOverview','DomainControllers','Users','Groups','Computers',
        'EndOfSupport','PasswordPolicy','PrivilegedAccess','Security','Infrastructure','OUStructure')]
    [string[]]$IncludeSection = @('All'),

    [Parameter()]
    [scriptblock]$LogCallback,

    [Parameter()]
    [switch]$LoadFunctionsOnly
)

#region Script Configuration
$ErrorActionPreference = 'Continue'
$WarningPreference = 'Continue'

$ScriptVersion = "2.2"

# Section selection helper
$AllSections = @('DomainOverview','DomainControllers','Users','Groups','Computers',
    'EndOfSupport','PasswordPolicy','PrivilegedAccess','Security','Infrastructure','OUStructure')
if ($IncludeSection -contains 'All') { $IncludeSection = $AllSections }
function Test-SectionIncluded { param([string]$Name) $IncludeSection -contains $Name }
$AuditDate = Get-Date
$ReportName = "AD-Audit-$($AuditDate.ToString('yyyy-MM-dd-HHmmss'))"
$StaleDate = $AuditDate.AddDays(-$DaysInactive)

# Build common AD splat for Domain/Credential
$ADParams = @{}
if ($Domain) { $ADParams['Server'] = $Domain }
if ($Credential) { $ADParams['Credential'] = $Credential }
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
        'Info'    { '[INFO]' }
        'Warning' { '[WARN]' }
        'Error'   { '[FAIL]' }
        'Success' { '[PASS]' }
    }
    $colors = @{
        'Info'    = 'Cyan'
        'Warning' = 'Yellow'
        'Error'   = 'Red'
        'Success' = 'Green'
    }

    Write-Host "[$timestamp] $prefix $Message" -ForegroundColor $colors[$Level]
    if ($LogCallback) {
        try { $LogCallback.Invoke("[$timestamp] $prefix $Message") } catch {}
    }
}

function Escape-Html {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '' }
    return [System.Security.SecurityElement]::Escape($Value)
}

function ConvertTo-CsvSafeText {
    # A CSV cell starting with = + - @ tab or CR is read as a formula by Excel; prefix a quote.
    param([string]$Text)
    if (-not [string]::IsNullOrEmpty($Text) -and $Text -match '^[=+\-@\t\r]') { return ("'" + $Text) }
    return $Text
}

function Test-Prerequisites {
    Write-AuditLog "Checking prerequisites..." -Level Info

    # Runtime import instead of '#Requires -Modules' so servers with RSAT cmdlets that are
    # not formally registered still run (repo convention, see CLAUDE.md).
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-AuditLog "Missing required module: ActiveDirectory ($($_.Exception.Message))" -Level Error
        Write-AuditLog "Install RSAT (Install-WindowsFeature RSAT-AD-PowerShell) or run on a domain controller" -Level Error
        return $false
    }

    try {
        $null = Get-ADDomain @ADParams -ErrorAction Stop
        Write-AuditLog "Connected to domain successfully" -Level Success
        return $true
    }
    catch {
        Write-AuditLog "Failed to connect to domain: $_" -Level Error
        return $false
    }
}

function Get-PrivilegedGroupSet {
    <#
    Returns the privileged groups to audit as Name / Sid / Server objects.
    Groups are identified by well-known SID (locale-independent; the display names are
    localized and can be renamed):
      - Domain Admins          <domain SID>-512
      - Schema Admins          <forest ROOT domain SID>-518   (exists only in the root domain)
      - Enterprise Admins      <forest ROOT domain SID>-519   (exists only in the root domain)
      - Administrators         S-1-5-32-544
      - Account Operators      S-1-5-32-548
      - Server Operators       S-1-5-32-549
      - Backup Operators       S-1-5-32-551
    https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
    Server is set for the forest-root groups when the audited domain is a child domain.
    #>
    $domainSid = (Get-ADDomain @ADParams -ErrorAction Stop).DomainSID.Value
    $rootSid = $domainSid
    $rootServer = $null
    try {
        $rootName = (Get-ADForest @ADParams -ErrorAction Stop).RootDomain
        $rootParams = $ADParams.Clone()
        $rootParams['Server'] = $rootName
        $rootDomain = Get-ADDomain @rootParams -ErrorAction Stop
        if ($rootDomain.DomainSID.Value -ne $domainSid) {
            $rootSid = $rootDomain.DomainSID.Value
            $rootServer = $rootName
        }
    } catch {
        Write-AuditLog "Could not resolve forest root domain SID; Schema/Enterprise Admins assumed in the audited domain: $($_.Exception.Message)" -Level Warning
    }

    return @(
        [PSCustomObject]@{ Name = 'Domain Admins';     Sid = "$domainSid-512"; Server = $null }
        [PSCustomObject]@{ Name = 'Enterprise Admins'; Sid = "$rootSid-519";   Server = $rootServer }
        [PSCustomObject]@{ Name = 'Schema Admins';     Sid = "$rootSid-518";   Server = $rootServer }
        [PSCustomObject]@{ Name = 'Administrators';    Sid = 'S-1-5-32-544';   Server = $null }
        [PSCustomObject]@{ Name = 'Account Operators'; Sid = 'S-1-5-32-548';   Server = $null }
        [PSCustomObject]@{ Name = 'Backup Operators';  Sid = 'S-1-5-32-551';   Server = $null }
        [PSCustomObject]@{ Name = 'Server Operators';  Sid = 'S-1-5-32-549';   Server = $null }
    )
}

function Get-SchemaVersionOS {
    param([int]$Version)
    # https://learn.microsoft.com/windows-server/identity/ad-ds/deploy/find-active-directory-schema
    # Version 88 is shared by Server 2019 and 2022; Server 2025 is 91 (NOT 90 - no released
    # Windows Server uses 90).
    $schemaMap = @{
        30 = 'Windows Server 2003'
        31 = 'Windows Server 2003 R2'
        44 = 'Windows Server 2008'
        47 = 'Windows Server 2008 R2'
        56 = 'Windows Server 2012'
        69 = 'Windows Server 2012 R2'
        87 = 'Windows Server 2016'
        88 = 'Windows Server 2019/2022'
        91 = 'Windows Server 2025'
    }
    if ($schemaMap.ContainsKey($Version)) { return $schemaMap[$Version] }
    return "Unknown (version $Version)"
}

function Get-ServerLifecycleTable {
    <#
    Static Windows Server lifecycle table (no run-time fetch: output stays local).
    Every date was read from the Microsoft Learn lifecycle page cited above its row on the
    CheckedOn date. Learn shows each end as "<next day> 6:59:59 AM" (the start of the
    following day); the value stored here is the LAST COVERED calendar day, so
    "Extended End Date 1/13/2027 6:59:59 AM" is stored as 2027-01-12.
    EsuEnd is the latest end of ANY Extended Security Update offering (on-premises or
    Azure-only), so the report never rules out coverage that might exist. $null = Learn
    lists no ESU for the product.
    Rows are ordered newest first and every R2 row comes before its base release; the
    base-release patterns also refuse a following "R2", so 2012 R2 never resolves to 2012.
    Update: re-read each page, adjust the dates, and set CheckedOn to the day you checked.
    #>
    # Learn writes the trademark sign as (R) in some OS strings and AD can hold the real
    # character; (?:\(R\)|\W)* accepts either, plus any spacing, between "Server" and the year.
    $prefix = '^Windows Server(?:\(R\)|\W)*'

    return @{
        CheckedOn = '2026-10-20'
        Rows      = @(
            # https://learn.microsoft.com/lifecycle/products/windows-server-2025
            [PSCustomObject]@{ Product = 'Windows Server 2025'; Pattern = "${prefix}2025\b"
                MainstreamEnd = '2029-11-13'; ExtendedEnd = '2034-11-14'; EsuEnd = $null
                Source = 'https://learn.microsoft.com/lifecycle/products/windows-server-2025' }
            # https://learn.microsoft.com/lifecycle/products/windows-server-2022
            [PSCustomObject]@{ Product = 'Windows Server 2022'; Pattern = "${prefix}2022\b"
                MainstreamEnd = '2026-10-13'; ExtendedEnd = '2031-10-14'; EsuEnd = $null
                Source = 'https://learn.microsoft.com/lifecycle/products/windows-server-2022' }
            # https://learn.microsoft.com/lifecycle/products/windows-server-2019
            [PSCustomObject]@{ Product = 'Windows Server 2019'; Pattern = "${prefix}2019\b"
                MainstreamEnd = '2024-01-09'; ExtendedEnd = '2029-01-09'; EsuEnd = $null
                Source = 'https://learn.microsoft.com/lifecycle/products/windows-server-2019' }
            # https://learn.microsoft.com/lifecycle/products/windows-server-2016
            [PSCustomObject]@{ Product = 'Windows Server 2016'; Pattern = "${prefix}2016\b"
                MainstreamEnd = '2022-01-11'; ExtendedEnd = '2027-01-12'; EsuEnd = $null
                Source = 'https://learn.microsoft.com/lifecycle/products/windows-server-2016' }
            # https://learn.microsoft.com/lifecycle/products/windows-server-2012-r2
            # ESU Year 3 ends 10/14/2026 6:59:59 AM -> last covered day 2026-10-13.
            [PSCustomObject]@{ Product = 'Windows Server 2012 R2'; Pattern = "${prefix}2012\s*R2\b"
                MainstreamEnd = '2018-10-09'; ExtendedEnd = '2023-10-10'; EsuEnd = '2026-10-13'
                Source = 'https://learn.microsoft.com/lifecycle/products/windows-server-2012-r2' }
            # https://learn.microsoft.com/lifecycle/products/windows-server-2012
            # ESU Year 3 ends 10/14/2026 6:59:59 AM -> last covered day 2026-10-13.
            [PSCustomObject]@{ Product = 'Windows Server 2012'; Pattern = "${prefix}2012\b(?!\W*R2)"
                MainstreamEnd = '2018-10-09'; ExtendedEnd = '2023-10-10'; EsuEnd = '2026-10-13'
                Source = 'https://learn.microsoft.com/lifecycle/products/windows-server-2012' }
            # https://learn.microsoft.com/lifecycle/products/windows-server-2008-r2
            # ESU Year 4 (Azure only) ends 1/10/2024 6:59:59 AM -> last covered day 2024-01-09.
            [PSCustomObject]@{ Product = 'Windows Server 2008 R2'; Pattern = "${prefix}2008\s*R2\b"
                MainstreamEnd = '2015-01-13'; ExtendedEnd = '2020-01-14'; EsuEnd = '2024-01-09'
                Source = 'https://learn.microsoft.com/lifecycle/products/windows-server-2008-r2' }
            # https://learn.microsoft.com/lifecycle/products/windows-server-2008
            # ESU Year 4 (Azure only) ends 1/10/2024 6:59:59 AM -> last covered day 2024-01-09.
            [PSCustomObject]@{ Product = 'Windows Server 2008'; Pattern = "${prefix}2008\b(?!\W*R2)"
                MainstreamEnd = '2015-01-13'; ExtendedEnd = '2020-01-14'; EsuEnd = '2024-01-09'
                Source = 'https://learn.microsoft.com/lifecycle/products/windows-server-2008' }
            # https://learn.microsoft.com/lifecycle/products/windows-server-2003-
            # (the trailing hyphen is part of Microsoft's URL). AD records Server 2003 R2 as
            # "Windows Server 2003" too; the 2003 R2 page has the same mainstream/extended dates.
            [PSCustomObject]@{ Product = 'Windows Server 2003'; Pattern = "${prefix}2003\b"
                MainstreamEnd = '2010-07-13'; ExtendedEnd = '2015-07-14'; EsuEnd = $null
                Source = 'https://learn.microsoft.com/lifecycle/products/windows-server-2003-' }
        )
    }
}

function Resolve-ServerLifecycle {
    <#
    Returns the lifecycle row whose Pattern matches the AD OperatingSystem string, or $null
    when the OS is not in the table (Semi-Annual Channel, Storage Server, unknown years...).
    $null must never be read as "supported" - Get-EndOfSupportStatus turns it into Unknown.
    #>
    param(
        [string]$OperatingSystem,
        $Table = (Get-ServerLifecycleTable)
    )
    if ([string]::IsNullOrWhiteSpace($OperatingSystem)) { return $null }
    foreach ($row in @($Table.Rows)) {
        if ($OperatingSystem -match $row.Pattern) { return $row }
    }
    return $null
}

function ConvertFrom-LifecycleDate {
    # Lifecycle dates are stored as yyyy-MM-dd and parsed culture-independently.
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    return [datetime]::ParseExact($Value, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-EndOfSupportStatus {
    <#
    Plain-words support status for one lifecycle row on a given day.
    Dates are the last covered calendar day and comparisons are date-only (time of day on
    AsOf is ignored). DaysUntilExtendedEnd is signed: negative = days since extended
    support ended. Severity: No support = High, Extended support ended = Warning, Security
    updates only = Warning with 365 days or fewer left (Info otherwise), Mainstream = Low,
    Unknown (OS not in the table) = Warning.
    #>
    param(
        $Lifecycle,
        [datetime]$AsOf = (Get-Date)
    )

    if ($null -eq $Lifecycle) {
        return [PSCustomObject]@{
            Status               = 'Unknown'
            Severity             = 'Warning'
            Note                 = 'Not in the lifecycle table - check https://learn.microsoft.com/lifecycle manually.'
            DaysUntilExtendedEnd = $null
        }
    }

    $warningDays = 365
    $today       = $AsOf.Date
    $mainstream  = ConvertFrom-LifecycleDate $Lifecycle.MainstreamEnd
    $extended    = ConvertFrom-LifecycleDate $Lifecycle.ExtendedEnd
    $esu         = ConvertFrom-LifecycleDate $Lifecycle.EsuEnd
    $daysLeft    = [int]($extended - $today).TotalDays

    if ($today -le $mainstream) {
        $status   = 'Mainstream support'
        $severity = 'Low'
        $note     = "In mainstream support until $($Lifecycle.MainstreamEnd)."
    }
    elseif ($today -le $extended) {
        $status   = 'Security updates only'
        $severity = if ($daysLeft -le $warningDays) { 'Warning' } else { 'Info' }
        $dayWord  = if ($daysLeft -eq 1) { 'day' } else { 'days' }
        $note     = "Mainstream support ended. Security updates until $($Lifecycle.ExtendedEnd); $daysLeft $dayWord left."
    }
    elseif ($esu -and $today -le $esu) {
        # AD cannot tell whether the client bought ESU, so the wording hedges.
        $status   = 'Extended support ended'
        $severity = 'Warning'
        $note     = "Extended support ended on $($Lifecycle.ExtendedEnd); covered only if the client bought ESU (ESU available until $($Lifecycle.EsuEnd))."
    }
    else {
        $status   = 'No support'
        $severity = 'High'
        $note     = if ($esu) { "All support ended on $($Lifecycle.EsuEnd), including paid ESU." }
                    else      { "All support ended on $($Lifecycle.ExtendedEnd); no ESU was offered." }
    }

    return [PSCustomObject]@{
        Status               = $status
        Severity             = $severity
        Note                 = $note
        DaysUntilExtendedEnd = $daysLeft
    }
}

function Test-LifecycleTableAge {
    <#
    Returns a warning message when the lifecycle table was last checked more than 180 days
    before AsOf (Microsoft does change dates, e.g. new ESU offers), otherwise $null.
    #>
    param(
        [string]$CheckedOn,
        [datetime]$AsOf = (Get-Date)
    )
    $maxAgeDays = 180
    $checked = ConvertFrom-LifecycleDate $CheckedOn
    if ($null -eq $checked) {
        return 'Lifecycle table has no checked date - verify the dates at https://learn.microsoft.com/lifecycle before relying on this section.'
    }
    $age = [int]($AsOf.Date - $checked).TotalDays
    if ($age -le $maxAgeDays) { return $null }
    return "Lifecycle table last checked $CheckedOn ($age days ago) - verify the dates at https://learn.microsoft.com/lifecycle before relying on this section."
}

function Get-AuditRunStamp {
    # Who ran the audit and where. Only the account NAME of -Credential is recorded, never
    # the credential object (personal-data rules).
    $cred = if ($Credential) { $Credential } elseif ($ADParams -and $ADParams['Credential']) { $ADParams['Credential'] } else { $null }
    $runBy = "$env:USERDOMAIN\$env:USERNAME"
    if ($cred -and $cred.UserName) { $runBy += " (as $($cred.UserName))" }
    return [PSCustomObject]@{ RunBy = $runBy; RunOn = $env:COMPUTERNAME }
}
function Get-TrustSidFilteringState {
    <#
    Interprets a trust's SID filtering from the trustAttributes bits.
    Quarantine (0x4, TRUST_ATTRIBUTE_QUARANTINED_DOMAIN) set  = SID filtering ENFORCED
    (netdom /quarantine:Yes accepts only SIDs from the directly trusted domain). Clear = an
    external trust accepts any SID. The previous code inverted this.
    Other cases per MS-PAC 4.1.2.2 / MS-ADTS trustAttributes:
      - Within-forest trusts (0x20) are not filtered by default (WithinForest boundary).
      - Forest trusts (0x8) always get cross-forest filtering; TREAT_AS_EXTERNAL (0x40)
        relaxes that to external-trust filtering.
    https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c
    https://learn.microsoft.com/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280
    https://learn.microsoft.com/windows-server/administration/windows-commands/netdom-trust
    Returns State, Severity (Low/Warning/High) for the report.
    #>
    param(
        [int]$TrustAttributes,
        [bool]$IntraForest = $false,
        [string]$TrustType = ''
    )

    $quarantined      = ($TrustAttributes -band 0x4) -ne 0
    $forestTransitive = ($TrustAttributes -band 0x8) -ne 0
    $withinForest     = $IntraForest -or (($TrustAttributes -band 0x20) -ne 0)
    $treatAsExternal  = ($TrustAttributes -band 0x40) -ne 0

    if ($TrustType -eq 'MIT') {
        return [PSCustomObject]@{ State = 'Not applicable (non-Windows Kerberos realm)'; Severity = 'Low' }
    }
    if ($withinForest) {
        if ($quarantined) {
            return [PSCustomObject]@{ State = 'Enforced (quarantined within forest)'; Severity = 'Low' }
        }
        return [PSCustomObject]@{ State = 'Not applicable (within forest)'; Severity = 'Low' }
    }
    if ($forestTransitive) {
        if ($treatAsExternal) {
            return [PSCustomObject]@{ State = 'Relaxed (forest trust treated as external; SID history may pass)'; Severity = 'Warning' }
        }
        return [PSCustomObject]@{ State = 'Enforced (forest filtering)'; Severity = 'Low' }
    }
    if ($quarantined) {
        return [PSCustomObject]@{ State = 'Enforced (quarantined)'; Severity = 'Low' }
    }
    return [PSCustomObject]@{ State = 'DISABLED (external trust accepts any SID)'; Severity = 'High' }
}
#endregion

#region Audit Functions

function Get-DomainOverview {
    Write-AuditLog "Gathering domain overview..." -Level Info

    try {
        $domainInfo = Get-ADDomain @ADParams -ErrorAction Stop
        $forestInfo = Get-ADForest @ADParams -ErrorAction Stop

        # FSMO Roles
        $fsmoRoles = @(
            [PSCustomObject]@{ Role = 'Schema Master';         Holder = $forestInfo.SchemaMaster }
            [PSCustomObject]@{ Role = 'Domain Naming Master';  Holder = $forestInfo.DomainNamingMaster }
            [PSCustomObject]@{ Role = 'PDC Emulator';          Holder = $domainInfo.PDCEmulator }
            [PSCustomObject]@{ Role = 'RID Master';            Holder = $domainInfo.RIDMaster }
            [PSCustomObject]@{ Role = 'Infrastructure Master'; Holder = $domainInfo.InfrastructureMaster }
        )

        # Trusts
        $trusts = @()
        try {
            $trusts = Get-ADTrust -Filter * @ADParams -ErrorAction Stop | Select-Object Name, Direction, TrustType, IntraForest
        } catch {
            Write-AuditLog "Could not enumerate trusts: $_" -Level Warning
        }

        # Sites and Subnets
        $sites = @()
        $subnets = @()
        try {
            $configNC = (Get-ADRootDSE @ADParams).configurationNamingContext
            $sites = Get-ADReplicationSite -Filter * @ADParams -ErrorAction Stop | Select-Object Name, Description
            $subnets = Get-ADReplicationSubnet -Filter * @ADParams -ErrorAction Stop | Select-Object Name, Site, Location, Description
        } catch {
            Write-AuditLog "Could not enumerate sites/subnets: $_" -Level Warning
        }

        Write-AuditLog "Domain overview complete" -Level Success
        return @{
            DomainName       = $domainInfo.DNSRoot
            NetBIOSName      = $domainInfo.NetBIOSName
            DomainSID        = $domainInfo.DomainSID.Value
            ForestName       = $forestInfo.Name
            ForestMode       = $forestInfo.ForestMode.ToString()
            DomainMode       = $domainInfo.DomainMode.ToString()
            DomainControllers = $domainInfo.ReplicaDirectoryServers.Count + $domainInfo.ReadOnlyReplicaDirectoryServers.Count
            FSMORoles        = $fsmoRoles
            Trusts           = $trusts
            Sites            = $sites
            Subnets          = $subnets
        }
    }
    catch {
        Write-AuditLog "Failed to get domain overview: $_" -Level Error
        return @{}
    }
}

function Get-DomainControllerAudit {
    Write-AuditLog "Auditing domain controllers..." -Level Info

    try {
        $dcs = Get-ADDomainController -Filter * @ADParams -ErrorAction Stop
        $dcResults = [System.Collections.Generic.List[object]]::new()
        $replFailures = [System.Collections.Generic.List[object]]::new()

        $i = 0
        foreach ($dc in $dcs) {
            $i++
            Write-Progress -Activity "Auditing Domain Controllers" -Status $dc.HostName -PercentComplete (($i / $dcs.Count) * 100)

            $replStatus = "OK"
            try {
                $failures = Get-ADReplicationFailure -Target $dc.HostName @ADParams -ErrorAction Stop
                if ($failures) {
                    $replStatus = "Failures: $($failures.Count)"
                    foreach ($f in $failures) {
                        $replFailures.Add([PSCustomObject]@{
                            DomainController = $dc.HostName
                            Partner          = $f.Partner
                            FailureCount     = $f.FailureCount
                            FailureType      = $f.FailureType
                            FirstFailure     = $f.FirstFailureTime
                            LastError        = $f.LastError
                        })
                    }
                }
            } catch {
                $replStatus = "Unable to check"
            }

            $dcResults.Add([PSCustomObject]@{
                HostName          = $dc.HostName
                Site              = $dc.Site
                IPv4Address       = $dc.IPv4Address
                OperatingSystem   = $dc.OperatingSystem
                IsGlobalCatalog   = $dc.IsGlobalCatalog
                IsReadOnly        = $dc.IsReadOnly
                OperationMasterRoles = ($dc.OperationMasterRoles -join ', ')
                ReplicationStatus = $replStatus
            })
        }
        Write-Progress -Activity "Auditing Domain Controllers" -Completed

        Write-AuditLog "Domain controller audit complete ($($dcs.Count) DCs)" -Level Success
        return @{
            DomainControllers   = $dcResults
            ReplicationFailures = $replFailures
        }
    }
    catch {
        Write-AuditLog "Failed DC audit: $_" -Level Error
        return @{ DomainControllers = @(); ReplicationFailures = @() }
    }
}

function Get-UserAccountAudit {
    Write-AuditLog "Auditing user accounts..." -Level Info

    try {
        $users = Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, `
            PasswordNotRequired, LockedOut, SIDHistory, whenCreated, Description `
            @ADParams -ErrorAction Stop

        $totalUsers      = @($users).Count
        $enabledUsers    = @($users | Where-Object { $_.Enabled -eq $true })
        $disabledUsers   = @($users | Where-Object { $_.Enabled -eq $false })

        Write-AuditLog "Processing $totalUsers user accounts..." -Level Info

        $staleUsers = @($enabledUsers | Where-Object {
            $_.LastLogonDate -and $_.LastLogonDate -lt $StaleDate
        } | Select-Object Name, SamAccountName, LastLogonDate, PasswordLastSet, whenCreated, Description)

        $neverExpires = @($enabledUsers | Where-Object { $_.PasswordNeverExpires -eq $true } |
            Select-Object Name, SamAccountName, PasswordLastSet, whenCreated)

        $pwdNotRequired = @($enabledUsers | Where-Object { $_.PasswordNotRequired -eq $true } |
            Select-Object Name, SamAccountName, whenCreated)

        $neverLoggedOn = @($enabledUsers | Where-Object { -not $_.LastLogonDate } |
            Select-Object Name, SamAccountName, whenCreated, Description)

        $lockedOut = @($users | Where-Object { $_.LockedOut -eq $true } |
            Select-Object Name, SamAccountName, LastLogonDate)

        $sidHistory = @($users | Where-Object { $_.SIDHistory.Count -gt 0 } |
            Select-Object Name, SamAccountName, @{N='SIDHistoryCount';E={$_.SIDHistory.Count}})

        Write-AuditLog "User audit complete: $totalUsers total, $($enabledUsers.Count) enabled, $($disabledUsers.Count) disabled" -Level Success
        return @{
            TotalUsers       = $totalUsers
            EnabledCount     = $enabledUsers.Count
            DisabledCount    = $disabledUsers.Count
            StaleUsers       = $staleUsers
            PasswordNeverExpires = $neverExpires
            PasswordNotRequired  = $pwdNotRequired
            NeverLoggedOn    = $neverLoggedOn
            LockedOut        = $lockedOut
            SIDHistory       = $sidHistory
        }
    }
    catch {
        Write-AuditLog "Failed user audit: $_" -Level Error
        return @{ TotalUsers = 0; EnabledCount = 0; DisabledCount = 0; StaleUsers = @(); PasswordNeverExpires = @();
                  PasswordNotRequired = @(); NeverLoggedOn = @(); LockedOut = @(); SIDHistory = @() }
    }
}

function Get-GroupAudit {
    Write-AuditLog "Auditing groups..." -Level Info

    try {
        $groups = Get-ADGroup -Filter * -Properties Members, MemberOf, GroupCategory, GroupScope, Description @ADParams -ErrorAction Stop
        $totalGroups = @($groups).Count
        Write-AuditLog "Processing $totalGroups groups..." -Level Info

        $emptyGroups = @($groups | Where-Object { $_.Members.Count -eq 0 } |
            Select-Object Name, GroupCategory, GroupScope, Description)

        $largeGroups = @($groups | Where-Object { $_.Members.Count -gt 50 } |
            Select-Object Name, @{N='MemberCount';E={$_.Members.Count}}, GroupCategory, GroupScope)

        # Privileged groups are resolved by well-known SID, not by English name, so the audit
        # works on localized domains and still finds groups that were renamed.
        $privilegedMembers = [System.Collections.Generic.List[object]]::new()

        foreach ($pg in @(Get-PrivilegedGroupSet)) {
            try {
                $memberParams = $ADParams.Clone()
                if ($pg.Server) { $memberParams['Server'] = $pg.Server }
                $members = Get-ADGroupMember -Identity $pg.Sid @memberParams -ErrorAction Stop
                foreach ($m in $members) {
                    $privilegedMembers.Add([PSCustomObject]@{
                        Group       = $pg.Name
                        GroupSid    = $pg.Sid
                        Name        = $m.name
                        SamAccount  = $m.SamAccountName
                        ObjectClass = $m.objectClass
                    })
                }
            } catch {
                Write-AuditLog "Could not read members of $($pg.Name) ($($pg.Sid)): $($_.Exception.Message)" -Level Warning
            }
        }

        # Nested group depth check - find groups that are members of privileged groups
        $nestedWarnings = @($privilegedMembers | Where-Object { $_.ObjectClass -eq 'group' } |
            Select-Object Group, Name, SamAccount, @{N='Warning';E={"Nested group in privileged group '$($_.Group)'"}})

        Write-AuditLog "Group audit complete: $totalGroups total, $($emptyGroups.Count) empty, $($largeGroups.Count) large" -Level Success
        return @{
            TotalGroups      = $totalGroups
            EmptyGroups      = $emptyGroups
            LargeGroups      = $largeGroups
            PrivilegedMembers = $privilegedMembers
            NestedWarnings   = $nestedWarnings
        }
    }
    catch {
        Write-AuditLog "Failed group audit: $_" -Level Error
        return @{ TotalGroups = 0; EmptyGroups = @(); LargeGroups = @(); PrivilegedMembers = @(); NestedWarnings = @() }
    }
}

function Get-ComputerAccountAudit {
    Write-AuditLog "Auditing computer accounts..." -Level Info

    try {
        $computers = Get-ADComputer -Filter * -Properties Enabled, LastLogonDate, OperatingSystem, OperatingSystemVersion, `
            whenCreated, Description @ADParams -ErrorAction Stop

        $totalComputers   = @($computers).Count
        $enabledComputers = @($computers | Where-Object { $_.Enabled -eq $true })
        $disabledComputers = @($computers | Where-Object { $_.Enabled -eq $false })

        $staleComputers = @($enabledComputers | Where-Object {
            $_.LastLogonDate -and $_.LastLogonDate -lt $StaleDate
        } | Select-Object Name, OperatingSystem, LastLogonDate, whenCreated, Description)

        # OS distribution
        $osDistribution = @($computers | Where-Object { $_.OperatingSystem } |
            Group-Object OperatingSystem |
            Select-Object @{N='OperatingSystem';E={$_.Name}}, Count |
            Sort-Object Count -Descending)

        # Unsupported OS detection. Server entries come from the cited lifecycle table
        # (D-020): a server is listed once its extended support has ended on the audit
        # date (ESU window or no support at all). Servers whose OS is not in the table are
        # not guessed at here; the End of Support section shows them as Unknown.
        $clientUnsupportedPatterns = @('*Windows 7*', '*Windows 8*', '*Windows XP*', '*Windows Vista*')
        $lifecycleTable = Get-ServerLifecycleTable
        $unsupportedComputers = @($enabledComputers | Where-Object {
            $os = $_.OperatingSystem
            if (-not $os) { return $false }
            if ($os -like '*Windows Server*') {
                $lifecycle = Resolve-ServerLifecycle -OperatingSystem $os -Table $lifecycleTable
                if ($null -eq $lifecycle) { return $false }
                $status = (Get-EndOfSupportStatus -Lifecycle $lifecycle -AsOf $AuditDate).Status
                return ($status -eq 'Extended support ended' -or $status -eq 'No support')
            }
            foreach ($p in $clientUnsupportedPatterns) {
                if ($os -like $p) { return $true }
            }
            return $false
        } | Select-Object Name, OperatingSystem, LastLogonDate)

        Write-AuditLog "Computer audit complete: $totalComputers total, $($staleComputers.Count) stale, $($unsupportedComputers.Count) unsupported OS" -Level Success
        return @{
            TotalComputers      = $totalComputers
            EnabledCount        = $enabledComputers.Count
            DisabledCount       = $disabledComputers.Count
            StaleComputers      = $staleComputers
            OSDistribution      = $osDistribution
            UnsupportedComputers = $unsupportedComputers
        }
    }
    catch {
        Write-AuditLog "Failed computer audit: $_" -Level Error
        return @{ TotalComputers = 0; EnabledCount = 0; DisabledCount = 0;
                  StaleComputers = @(); OSDistribution = @(); UnsupportedComputers = @() }
    }
}

function Get-EndOfSupportAudit {
    <#
    One row per ENABLED Windows Server computer account with Microsoft's support end
    dates (Get-ServerLifecycleTable), days left, last logon and a stale flag. Each row is
    stamped with the audit date, audited domain, who ran it and from where, so two
    quarters' CSVs can be compared. Reads $AuditDate, $StaleDate, $ADParams, $Credential
    and $Domain from the script scope like the other audit functions.
    LastLogonDate comes from the replicated lastLogonTimestamp, which is only updated when
    it is older than msDS-LogonTimeSyncInterval (14 days by default), so it can lag:
    https://learn.microsoft.com/windows/win32/adschema/a-lastlogontimestamp
    https://learn.microsoft.com/windows/win32/adschema/a-msds-logontimesyncinterval
    #>
    Write-AuditLog "Checking Windows Server end of support..." -Level Info

    $table = Get-ServerLifecycleTable
    $stamp = Get-AuditRunStamp
    $staleTableWarning = Test-LifecycleTableAge -CheckedOn $table.CheckedOn -AsOf $AuditDate
    if ($staleTableWarning) { Write-AuditLog $staleTableWarning -Level Warning }

    $result = @{
        Servers           = @()
        PastEndCount      = 0
        StaleTableWarning = $staleTableWarning
        Error             = $null
        TableCheckedOn    = $table.CheckedOn
        RunBy             = $stamp.RunBy
        RunOn             = $stamp.RunOn
    }

    try {
        $computers = @(Get-ADComputer -Filter "OperatingSystem -like '*Windows Server*'" `
            -Properties OperatingSystem, OperatingSystemVersion, LastLogonDate, Enabled @ADParams -ErrorAction Stop)
    }
    catch {
        $result.Error = $_.Exception.Message
        Write-AuditLog "Failed end of support audit - could not read servers from AD: $($result.Error)" -Level Error
        return $result
    }

    $auditedDomain = $null
    try { $auditedDomain = (Get-ADDomain @ADParams -ErrorAction Stop).DNSRoot } catch { $auditedDomain = $null }
    if (-not $auditedDomain) { $auditedDomain = if ($Domain) { $Domain } else { $env:USERDNSDOMAIN } }

    $auditDateText = $AuditDate.ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    $rows = foreach ($c in @($computers | Where-Object { $_.Enabled -eq $true })) {
        $lifecycle = Resolve-ServerLifecycle -OperatingSystem $c.OperatingSystem -Table $table
        $status    = Get-EndOfSupportStatus -Lifecycle $lifecycle -AsOf $AuditDate
        $lastLogon = if ($c.LastLogonDate) { ([datetime]$c.LastLogonDate).ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture) } else { 'Never' }
        $stale     = (-not $c.LastLogonDate) -or ([datetime]$c.LastLogonDate -lt $StaleDate)

        # Property order is the CSV column order (AC12).
        [PSCustomObject]@{
            Name                   = $c.Name
            OperatingSystem        = $c.OperatingSystem
            OperatingSystemVersion = $c.OperatingSystemVersion
            Product                = if ($lifecycle) { $lifecycle.Product } else { '' }
            Status                 = $status.Status
            Severity               = $status.Severity
            DaysUntilExtendedEnd   = $status.DaysUntilExtendedEnd
            MainstreamEnd          = if ($lifecycle) { $lifecycle.MainstreamEnd } else { '' }
            ExtendedEnd            = if ($lifecycle) { $lifecycle.ExtendedEnd } else { '' }
            EsuEnd                 = if ($lifecycle -and $lifecycle.EsuEnd) { $lifecycle.EsuEnd } else { '' }
            Note                   = $status.Note
            LastLogonDate          = $lastLogon
            Stale                  = $stale
            Source                 = if ($lifecycle) { $lifecycle.Source } else { 'https://learn.microsoft.com/lifecycle' }
            TableCheckedOn         = $table.CheckedOn
            AuditDate              = $auditDateText
            AuditedDomain          = $auditedDomain
            RunBy                  = $stamp.RunBy
            RunOn                  = $stamp.RunOn
        }
    }

    # Most urgent first: furthest past extended end at the top, OS not in the table last.
    $result.Servers = @($rows | Sort-Object @{ Expression = { if ($null -eq $_.DaysUntilExtendedEnd) { [int]::MaxValue } else { $_.DaysUntilExtendedEnd } } }, Name)
    $result.PastEndCount = @($result.Servers | Where-Object { $_.Status -eq 'Extended support ended' -or $_.Status -eq 'No support' }).Count

    Write-AuditLog "End of support audit complete: $(@($result.Servers).Count) servers, $($result.PastEndCount) past end of support" -Level Success
    return $result
}

function Get-PasswordPolicyAudit {
    Write-AuditLog "Auditing password policies..." -Level Info

    try {
        $defaultPolicy = Get-ADDefaultDomainPasswordPolicy @ADParams -ErrorAction Stop

        $policyResult = [PSCustomObject]@{
            PolicyType          = 'Default Domain Policy'
            MinPasswordLength   = $defaultPolicy.MinPasswordLength
            PasswordHistoryCount = $defaultPolicy.PasswordHistoryCount
            MaxPasswordAge      = $defaultPolicy.MaxPasswordAge.Days
            MinPasswordAge      = $defaultPolicy.MinPasswordAge.Days
            ComplexityEnabled   = $defaultPolicy.ComplexityEnabled
            ReversibleEncryption = $defaultPolicy.ReversibleEncryptionEnabled
            LockoutThreshold    = $defaultPolicy.LockoutThreshold
            LockoutDuration     = if ($defaultPolicy.LockoutDuration) { $defaultPolicy.LockoutDuration.TotalMinutes } else { 'N/A' }
            LockoutObservationWindow = if ($defaultPolicy.LockoutObservationWindow) { $defaultPolicy.LockoutObservationWindow.TotalMinutes } else { 'N/A' }
        }

        # NIST 800-63B compliance checks
        $nistFindings = [System.Collections.Generic.List[object]]::new()

        if ($defaultPolicy.MinPasswordLength -lt 8) {
            $nistFindings.Add([PSCustomObject]@{
                Check = 'Minimum Password Length'
                Status = 'Fail'
                Current = "$($defaultPolicy.MinPasswordLength) characters"
                Recommendation = 'NIST recommends minimum 8 characters (prefer 12+)'
            })
        } else {
            $nistFindings.Add([PSCustomObject]@{
                Check = 'Minimum Password Length'
                Status = if ($defaultPolicy.MinPasswordLength -ge 12) { 'Pass' } else { 'Warning' }
                Current = "$($defaultPolicy.MinPasswordLength) characters"
                Recommendation = if ($defaultPolicy.MinPasswordLength -ge 12) { 'Meets NIST guidelines' } else { 'Consider increasing to 12+' }
            })
        }

        if ($defaultPolicy.MaxPasswordAge.Days -gt 0 -and $defaultPolicy.MaxPasswordAge.Days -lt 365) {
            $nistFindings.Add([PSCustomObject]@{
                Check = 'Password Expiration'
                Status = 'Warning'
                Current = "$($defaultPolicy.MaxPasswordAge.Days) days"
                Recommendation = 'NIST discourages mandatory periodic password changes unless compromise is suspected'
            })
        }

        if ($defaultPolicy.ReversibleEncryptionEnabled) {
            $nistFindings.Add([PSCustomObject]@{
                Check = 'Reversible Encryption'
                Status = 'Fail'
                Current = 'Enabled'
                Recommendation = 'Disable reversible encryption - stores passwords in recoverable form'
            })
        }

        # Fine-grained password policies
        $fgppResults = @()
        try {
            $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * @ADParams -ErrorAction Stop
            $fgppResults = @($fgpp | Select-Object Name, Precedence, MinPasswordLength, PasswordHistoryCount,
                @{N='MaxPasswordAgeDays';E={$_.MaxPasswordAge.Days}},
                ComplexityEnabled, ReversibleEncryptionEnabled, LockoutThreshold,
                @{N='AppliesTo';E={($_.AppliesTo | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' }) -join '; '}})
        } catch {
            Write-AuditLog "Could not retrieve fine-grained password policies: $_" -Level Warning
        }

        Write-AuditLog "Password policy audit complete" -Level Success
        return @{
            DefaultPolicy = $policyResult
            NISTFindings  = $nistFindings
            FineGrained   = $fgppResults
        }
    }
    catch {
        Write-AuditLog "Failed password policy audit: $_" -Level Error
        return @{ DefaultPolicy = $null; NISTFindings = @(); FineGrained = @() }
    }
}

function Get-PrivilegedAccessAudit {
    # Concise summary only. Nested group path analysis lives in the dedicated tool
    # Find-PrivilegedAccessPaths\Get-DomainPrivilegedAccess.ps1.
    Write-AuditLog "Auditing privileged access (summary; see Find-PrivilegedAccessPaths\Get-DomainPrivilegedAccess.ps1 for full nested-path analysis)..." -Level Info

    $results = @{
        AdminSDHolder    = @()
        Delegation       = @()
        KerberoastableAdmins = @()
        ASREPRoastable   = @()
    }

    try {
        # AdminSDHolder protected accounts
        $results.AdminSDHolder = @(Get-ADUser -Filter { AdminCount -eq 1 } `
            -Properties AdminCount, LastLogonDate, Enabled, MemberOf @ADParams -ErrorAction Stop |
            Select-Object Name, SamAccountName, Enabled, LastLogonDate,
                @{N='GroupCount';E={$_.MemberOf.Count}})

        Write-AuditLog "Found $($results.AdminSDHolder.Count) AdminSDHolder protected accounts" -Level Info
    } catch {
        Write-AuditLog "Could not check AdminSDHolder accounts: $_" -Level Warning
    }

    try {
        # Kerberos delegation
        $delegation = [System.Collections.Generic.List[object]]::new()

        # Unconstrained delegation (exclude DCs)
        $unconstrained = Get-ADComputer -Filter { TrustedForDelegation -eq $true } `
            -Properties TrustedForDelegation, servicePrincipalName @ADParams -ErrorAction SilentlyContinue
        foreach ($obj in $unconstrained) {
            $isDC = $false
            try { $isDC = (Get-ADDomainController $obj.Name @ADParams -ErrorAction SilentlyContinue) -ne $null } catch {}
            if (-not $isDC) {
                $delegation.Add([PSCustomObject]@{
                    Name = $obj.Name; Type = 'Unconstrained'; ObjectClass = 'Computer'
                    Details = 'Non-DC with unconstrained delegation - high risk'
                })
            }
        }

        # Unconstrained delegation on user accounts
        $unconstrainedUsers = Get-ADUser -Filter { TrustedForDelegation -eq $true } `
            -Properties TrustedForDelegation @ADParams -ErrorAction SilentlyContinue
        foreach ($obj in $unconstrainedUsers) {
            $delegation.Add([PSCustomObject]@{
                Name = $obj.SamAccountName; Type = 'Unconstrained'; ObjectClass = 'User'
                Details = 'User with unconstrained delegation - high risk'
            })
        }

        # Constrained delegation
        $constrained = Get-ADObject -Filter { msDS-AllowedToDelegateTo -like '*' } `
            -Properties 'msDS-AllowedToDelegateTo', Name, ObjectClass @ADParams -ErrorAction SilentlyContinue
        foreach ($obj in $constrained) {
            $delegation.Add([PSCustomObject]@{
                Name = $obj.Name; Type = 'Constrained'; ObjectClass = $obj.ObjectClass
                Details = ($obj.'msDS-AllowedToDelegateTo' -join '; ')
            })
        }

        $results.Delegation = $delegation

        Write-AuditLog "Found $($delegation.Count) delegation configurations" -Level Info
    } catch {
        Write-AuditLog "Could not check delegation: $_" -Level Warning
    }

    try {
        # Admin accounts with SPNs (Kerberoastable)
        $domainAdmins = @(Get-PrivilegedGroupSet | Where-Object { $_.Name -eq 'Domain Admins' })[0]
        $adminUsers = Get-ADGroupMember -Identity $domainAdmins.Sid @ADParams -ErrorAction SilentlyContinue |
            Where-Object { $_.objectClass -eq 'user' }

        $kerberoastable = [System.Collections.Generic.List[object]]::new()
        foreach ($admin in $adminUsers) {
            $user = Get-ADUser -Identity $admin.SamAccountName -Properties servicePrincipalName @ADParams -ErrorAction SilentlyContinue
            if ($user.servicePrincipalName.Count -gt 0) {
                $kerberoastable.Add([PSCustomObject]@{
                    Name = $user.Name
                    SamAccountName = $user.SamAccountName
                    SPNs = ($user.servicePrincipalName -join '; ')
                })
            }
        }
        $results.KerberoastableAdmins = $kerberoastable

        if ($kerberoastable.Count -gt 0) {
            Write-AuditLog "Found $($kerberoastable.Count) Kerberoastable admin accounts!" -Level Warning
        }
    } catch {
        Write-AuditLog "Could not check Kerberoastable admins: $_" -Level Warning
    }

    try {
        # AS-REP Roastable accounts (DoesNotRequirePreAuth)
        $asrepRoastable = @(Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } `
            -Properties DoesNotRequirePreAuth, Enabled, LastLogonDate @ADParams -ErrorAction Stop |
            Select-Object Name, SamAccountName, Enabled, LastLogonDate)
        $results.ASREPRoastable = $asrepRoastable

        if ($asrepRoastable.Count -gt 0) {
            Write-AuditLog "Found $($asrepRoastable.Count) AS-REP Roastable accounts!" -Level Warning
        }
    } catch {
        Write-AuditLog "Could not check AS-REP Roastable accounts: $_" -Level Warning
    }

    try {
        # Resource-Based Constrained Delegation (RBCD)
        $rbcdObjects = Get-ADObject -Filter { msDS-AllowedToActOnBehalfOfOtherIdentity -like '*' } `
            -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity', Name, ObjectClass @ADParams -ErrorAction SilentlyContinue
        foreach ($obj in $rbcdObjects) {
            $sd = $obj.'msDS-AllowedToActOnBehalfOfOtherIdentity'
            $allowedPrincipals = @()
            if ($sd -is [System.DirectoryServices.ActiveDirectorySecurity]) {
                $allowedPrincipals = @($sd.Access | ForEach-Object { $_.IdentityReference.Value })
            }
            $results.Delegation.Add([PSCustomObject]@{
                Name = $obj.Name; Type = 'RBCD'; ObjectClass = $obj.ObjectClass
                Details = "Allowed principals: $(($allowedPrincipals -join '; '))"
            })
        }
    } catch {
        Write-AuditLog "Could not check RBCD: $_" -Level Warning
    }

    Write-AuditLog "Privileged access audit complete" -Level Success
    return $results
}

function Get-SecurityAudit {
    Write-AuditLog "Running security audit..." -Level Info

    $findings = [System.Collections.Generic.List[object]]::new()

    try {
        # Accounts with reversible encryption
        $reversible = @(Get-ADUser -Filter { AllowReversiblePasswordEncryption -eq $true } `
            -Properties AllowReversiblePasswordEncryption @ADParams -ErrorAction SilentlyContinue)
        if ($reversible.Count -gt 0) {
            foreach ($u in $reversible) {
                $findings.Add([PSCustomObject]@{
                    Category = 'Reversible Encryption'
                    Severity = 'High'
                    Object   = $u.SamAccountName
                    Details  = 'Account stores password with reversible encryption'
                    Recommendation = 'Disable AllowReversiblePasswordEncryption'
                })
            }
        }
    } catch {
        Write-AuditLog "Could not check reversible encryption: $_" -Level Warning
    }

    try {
        # Accounts with DES-only Kerberos
        $desOnly = @(Get-ADUser -Filter { UseDESKeyOnly -eq $true } `
            -Properties UseDESKeyOnly @ADParams -ErrorAction SilentlyContinue)
        foreach ($u in $desOnly) {
            $findings.Add([PSCustomObject]@{
                Category = 'DES-Only Kerberos'
                Severity = 'High'
                Object   = $u.SamAccountName
                Details  = 'Account restricted to weak DES encryption'
                Recommendation = 'Disable UseDESKeyOnly flag'
            })
        }
    } catch {
        Write-AuditLog "Could not check DES-only accounts: $_" -Level Warning
    }

    try {
        # LAPS deployment status - check both Legacy LAPS and Windows LAPS
        $allComputers = @(Get-ADComputer -Filter { Enabled -eq $true } @ADParams -ErrorAction SilentlyContinue)
        $legacyLapsCount = 0
        $windowsLapsCount = 0

        # Legacy LAPS (ms-Mcs-AdmPwd)
        try {
            $legacyLapsCount = @(Get-ADComputer -Filter { Enabled -eq $true } `
                -Properties 'ms-Mcs-AdmPwd' @ADParams -ErrorAction Stop |
                Where-Object { $_.'ms-Mcs-AdmPwd' }).Count
        } catch {
            # Attribute may not exist if LAPS schema not extended
        }

        # Windows LAPS (msLAPS-PasswordExpirationTime as proxy - readable without admin rights)
        try {
            $windowsLapsCount = @(Get-ADComputer -Filter { Enabled -eq $true } `
                -Properties 'msLAPS-PasswordExpirationTime' @ADParams -ErrorAction Stop |
                Where-Object { $_.'msLAPS-PasswordExpirationTime' }).Count
        } catch {
            # Attribute may not exist if Windows LAPS schema not extended
        }

        $lapsTotal = $allComputers.Count
        $lapsEither = [math]::Max($legacyLapsCount, $windowsLapsCount)
        $lapsPercent = if ($lapsTotal -gt 0) { [math]::Round(($lapsEither / $lapsTotal) * 100, 1) } else { 0 }
        $lapsSeverity = if ($lapsPercent -ge 90) { 'Low' } elseif ($lapsPercent -ge 50) { 'Warning' } else { 'High' }

        $findings.Add([PSCustomObject]@{
            Category = 'LAPS Deployment (Legacy)'
            Severity = $lapsSeverity
            Object   = "Domain-wide"
            Details  = "$legacyLapsCount of $lapsTotal enabled computers have Legacy LAPS (ms-Mcs-AdmPwd)"
            Recommendation = if ($legacyLapsCount -eq 0) { 'Legacy LAPS not deployed or schema not extended' } else { 'Consider migrating to Windows LAPS' }
        })
        $findings.Add([PSCustomObject]@{
            Category = 'LAPS Deployment (Windows)'
            Severity = $lapsSeverity
            Object   = "Domain-wide"
            Details  = "$windowsLapsCount of $lapsTotal enabled computers have Windows LAPS"
            Recommendation = if ($windowsLapsCount -eq 0) { 'Deploy Windows LAPS for modern password management' } else { "Windows LAPS coverage: $([math]::Round(($windowsLapsCount/$lapsTotal)*100,1))%" }
        })
    } catch {
        Write-AuditLog "Could not check LAPS status: $_" -Level Warning
    }

    try {
        # Stale DNS records (if DnsServer module available)
        if (Get-Module -ListAvailable -Name DnsServer) {
            Import-Module DnsServer -ErrorAction SilentlyContinue
            $domainInfo = Get-ADDomain @ADParams -ErrorAction Stop
            $staleThreshold = $AuditDate.AddDays(-$DaysInactive)

            try {
                $dnsZone = $domainInfo.DNSRoot
                $records = Get-DnsServerResourceRecord -ZoneName $dnsZone -RRType A -ErrorAction Stop |
                    Where-Object { $_.Timestamp -and $_.Timestamp -lt $staleThreshold }
                $staleCount = @($records).Count

                if ($staleCount -gt 0) {
                    $findings.Add([PSCustomObject]@{
                        Category = 'Stale DNS Records'
                        Severity = 'Warning'
                        Object   = $dnsZone
                        Details  = "$staleCount DNS A records older than $DaysInactive days"
                        Recommendation = 'Review and clean up stale DNS records; enable DNS scavenging'
                    })
                }
            } catch {
                Write-AuditLog "Could not check DNS records: $_" -Level Warning
            }
        }
    } catch {
        Write-AuditLog "DnsServer module not available, skipping DNS check" -Level Warning
    }

    Write-AuditLog "Security audit complete: $($findings.Count) findings" -Level Success
    return @{ Findings = $findings }
}

function Get-ADInfrastructureAudit {
    Write-AuditLog "Auditing AD infrastructure health..." -Level Info

    $results = @{
        TombstoneLifetime = 'Unknown'
        RecycleBinEnabled = $false
        SchemaVersion     = 'Unknown'
        SchemaOS          = 'Unknown'
        SysvolReplication = 'Unknown'
        TrustHealth       = @()
    }

    try {
        # Tombstone lifetime
        $configNC = (Get-ADRootDSE @ADParams).configurationNamingContext
        $dsService = Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$configNC" `
            -Properties tombstoneLifetime @ADParams -ErrorAction Stop
        $results.TombstoneLifetime = if ($dsService.tombstoneLifetime) { "$($dsService.tombstoneLifetime) days" } else { '60 days (default)' }
    } catch {
        Write-AuditLog "Could not check tombstone lifetime: $_" -Level Warning
    }

    try {
        # AD Recycle Bin
        $recycleBin = Get-ADOptionalFeature -Filter { Name -like 'Recycle Bin Feature' } @ADParams -ErrorAction Stop
        $results.RecycleBinEnabled = ($recycleBin.EnabledScopes.Count -gt 0)
    } catch {
        Write-AuditLog "Could not check AD Recycle Bin: $_" -Level Warning
    }

    try {
        # Schema version
        $schemaNC = (Get-ADRootDSE @ADParams).schemaNamingContext
        $schema = Get-ADObject $schemaNC -Properties objectVersion @ADParams -ErrorAction Stop
        $results.SchemaVersion = $schema.objectVersion
        $results.SchemaOS = Get-SchemaVersionOS -Version ([int]$schema.objectVersion)
    } catch {
        Write-AuditLog "Could not check schema version: $_" -Level Warning
    }

    try {
        # Sysvol replication method (FRS vs DFSR)
        $configNC = (Get-ADRootDSE @ADParams).configurationNamingContext
        $domainDN = (Get-ADDomain @ADParams).DistinguishedName
        $dfsrCheck = Get-ADObject "CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,$domainDN" `
            @ADParams -ErrorAction SilentlyContinue
        $results.SysvolReplication = if ($dfsrCheck) { 'DFSR' } else { 'FRS (legacy - migrate to DFSR)' }
    } catch {
        $results.SysvolReplication = 'Unable to determine'
    }

    try {
        # Trust health validation
        $trustHealth = [System.Collections.Generic.List[object]]::new()
        $trusts = Get-ADTrust -Filter * -Properties TrustAttributes @ADParams -ErrorAction SilentlyContinue
        foreach ($trust in $trusts) {
            $attrs = 0
            if ($null -ne $trust.TrustAttributes) {
                $attrs = [int]$trust.TrustAttributes
            } else {
                # Attribute not returned: rebuild the bits we need from the cmdlet's booleans.
                if ($trust.SIDFilteringQuarantined) { $attrs = $attrs -bor 0x4 }
                if ($trust.ForestTransitive)        { $attrs = $attrs -bor 0x8 }
            }
            $sidState = Get-TrustSidFilteringState -TrustAttributes $attrs -IntraForest ([bool]$trust.IntraForest) -TrustType "$($trust.TrustType)"
            $trustHealth.Add([PSCustomObject]@{
                Name             = $trust.Name
                Direction        = $trust.Direction
                TrustType        = $trust.TrustType
                IntraForest      = $trust.IntraForest
                SelectiveAuth    = $trust.SelectiveAuthentication
                SIDFiltering     = $sidState.State
                SIDFilteringSeverity = $sidState.Severity
                TGTDelegation    = $trust.TGTDelegation
            })
        }
        $results.TrustHealth = $trustHealth
    } catch {
        Write-AuditLog "Could not validate trust health: $_" -Level Warning
    }

    Write-AuditLog "Infrastructure audit complete" -Level Success
    return $results
}

function Get-OUStructureAudit {
    Write-AuditLog "Auditing OU structure..." -Level Info

    try {
        $ous = Get-ADOrganizationalUnit -Filter * -Properties Description, gPLink @ADParams -ErrorAction Stop
        $totalOUs = @($ous).Count
        Write-AuditLog "Processing $totalOUs OUs..." -Level Info

        $ouResults = [System.Collections.Generic.List[object]]::new()
        $emptyOUs = [System.Collections.Generic.List[object]]::new()
        $noGPOLink = [System.Collections.Generic.List[object]]::new()
        $maxDepth = 0

        foreach ($ou in $ous) {
            # Calculate depth from DN
            $depth = ($ou.DistinguishedName -split '(?<!\\),OU=' ).Count - 1
            if ($depth -gt $maxDepth) { $maxDepth = $depth }

            # Check for child objects
            $childCount = @(Get-ADObject -SearchBase $ou.DistinguishedName -SearchScope OneLevel `
                -Filter * @ADParams -ErrorAction SilentlyContinue).Count

            $hasGPO = -not [string]::IsNullOrWhiteSpace($ou.gPLink)

            $ouResults.Add([PSCustomObject]@{
                Name            = $ou.Name
                DistinguishedName = $ou.DistinguishedName
                Depth           = $depth
                ChildObjects    = $childCount
                HasGPOLinks     = $hasGPO
                Description     = $ou.Description
            })

            if ($childCount -eq 0) {
                $emptyOUs.Add([PSCustomObject]@{
                    Name = $ou.Name
                    DistinguishedName = $ou.DistinguishedName
                    Depth = $depth
                    Description = $ou.Description
                })
            }

            if (-not $hasGPO) {
                $noGPOLink.Add([PSCustomObject]@{
                    Name = $ou.Name
                    DistinguishedName = $ou.DistinguishedName
                    Depth = $depth
                    ChildObjects = $childCount
                })
            }
        }

        Write-AuditLog "OU audit complete: $totalOUs OUs, $($emptyOUs.Count) empty, max depth $maxDepth" -Level Success
        return @{
            TotalOUs    = $totalOUs
            MaxDepth    = $maxDepth
            OUs         = $ouResults
            EmptyOUs    = $emptyOUs
            NoGPOLink   = $noGPOLink
        }
    }
    catch {
        Write-AuditLog "Failed OU structure audit: $_" -Level Error
        return @{ TotalOUs = 0; MaxDepth = 0; OUs = @(); EmptyOUs = @(); NoGPOLink = @() }
    }
}

#endregion

#region Report Generation

function Export-CSVReports {
    param([hashtable]$AuditResults, [string]$BasePath)

    Write-AuditLog "Exporting CSV reports..." -Level Info

    $csvMap = @{
        'DC-List'              = $AuditResults.DomainControllers.DomainControllers
        'DC-ReplicationFailures' = $AuditResults.DomainControllers.ReplicationFailures
        'Users-Stale'          = $AuditResults.Users.StaleUsers
        'Users-PwdNeverExpires' = $AuditResults.Users.PasswordNeverExpires
        'Users-PwdNotRequired' = $AuditResults.Users.PasswordNotRequired
        'Users-NeverLoggedOn'  = $AuditResults.Users.NeverLoggedOn
        'Users-LockedOut'      = $AuditResults.Users.LockedOut
        'Users-SIDHistory'     = $AuditResults.Users.SIDHistory
        'Groups-Empty'         = $AuditResults.Groups.EmptyGroups
        'Groups-Large'         = $AuditResults.Groups.LargeGroups
        'Groups-Privileged'    = $AuditResults.Groups.PrivilegedMembers
        'Groups-NestedWarnings' = $AuditResults.Groups.NestedWarnings
        'Computers-Stale'      = $AuditResults.Computers.StaleComputers
        'Computers-OS'         = $AuditResults.Computers.OSDistribution
        'Computers-Unsupported' = $AuditResults.Computers.UnsupportedComputers
        'EndOfSupport'         = @($AuditResults.EndOfSupport.Servers | Where-Object { $_ } | ForEach-Object {
            # AD-sourced cells are neutralised so a crafted name cannot run as a formula.
            $row = $_.PSObject.Copy()
            foreach ($p in 'Name', 'OperatingSystem', 'OperatingSystemVersion') { $row.$p = ConvertTo-CsvSafeText $row.$p }
            $row
        })
        'PasswordPolicy-NIST'  = $AuditResults.PasswordPolicy.NISTFindings
        'PasswordPolicy-FGPP'  = $AuditResults.PasswordPolicy.FineGrained
        'Privileged-AdminSDHolder' = $AuditResults.Privileged.AdminSDHolder
        'Privileged-Delegation' = $AuditResults.Privileged.Delegation
        'Privileged-Kerberoastable' = $AuditResults.Privileged.KerberoastableAdmins
        'Privileged-ASREPRoastable' = $AuditResults.Privileged.ASREPRoastable
        'Security-Findings'    = $AuditResults.Security.Findings
        'Infrastructure-TrustHealth' = $AuditResults.Infrastructure.TrustHealth
        'OU-Structure'         = $AuditResults.OUStructure.OUs
        'OU-Empty'             = $AuditResults.OUStructure.EmptyOUs
        'OU-NoGPOLink'         = $AuditResults.OUStructure.NoGPOLink
    }

    $exported = 0
    foreach ($kv in $csvMap.GetEnumerator()) {
        $data = @($kv.Value)
        if ($data.Count -gt 0) {
            $filePath = Join-Path $BasePath "$ReportName-$($kv.Key).csv"
            $data | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8
            $exported++
        }
    }

    Write-AuditLog "Exported $exported CSV files" -Level Success
}

function Export-HTMLReport {
    param([hashtable]$AuditResults, [string]$OutputFile)

    Write-AuditLog "Generating HTML report..." -Level Info

    $e = { param($v) Escape-Html $v }
    $overview = $AuditResults.Overview
    $users = $AuditResults.Users
    $groups = $AuditResults.Groups
    $computers = $AuditResults.Computers
    $pwPolicy = $AuditResults.PasswordPolicy
    $priv = $AuditResults.Privileged
    $security = $AuditResults.Security
    $eos = $AuditResults.EndOfSupport
    if (-not $eos) { $eos = @{ Servers = @(); PastEndCount = 0; StaleTableWarning = $null; Error = $null; Skipped = $true } }
    $eosServers = @($eos.Servers | Where-Object { $_ })
    $eosPastEnd = @($eosServers | Where-Object { $_.Status -eq 'Extended support ended' -or $_.Status -eq 'No support' }).Count

    # Count total findings for summary
    $totalFindings = @($security.Findings).Count + @($priv.KerberoastableAdmins).Count +
        @($priv.Delegation | Where-Object { $_.Type -eq 'Unconstrained' }).Count +
        @($groups.NestedWarnings).Count

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Active Directory Audit Report</title>
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
        .metric-value.warning { color: #f39c12; }
        .metric-value.danger { color: #e74c3c; }
        table { border-collapse: collapse; width: 100%; margin: 15px 0; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #3498db; color: white; font-weight: 600; }
        tr:hover { background: #f8f9fa; }
        .severity-high { color: #e74c3c; font-weight: bold; }
        .severity-warning { color: #f39c12; font-weight: bold; }
        .severity-info { color: #3498db; }
        .severity-low { color: #27ae60; }
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
        .back-to-top { text-align: right; margin-top: 10px; font-size: 13px; }
        .back-to-top a { color: #3498db; text-decoration: none; }
        .back-to-top a:hover { text-decoration: underline; }
        .info-grid { display: grid; grid-template-columns: 200px 1fr; gap: 8px; margin: 10px 0; }
        .info-label { font-weight: 600; color: #34495e; }
        .collapsible { cursor: pointer; user-select: none; }
        .collapsible::before { content: '\25BC '; font-size: 12px; }
        .collapsible.collapsed::before { content: '\25B6 '; }
        .collapsible-content { overflow: hidden; }
        .collapsible-content.collapsed { display: none; }
    </style>
    <script>
        function toggleSection(id) {
            var content = document.getElementById(id);
            var header = content.previousElementSibling;
            content.classList.toggle('collapsed');
            header.classList.toggle('collapsed');
        }
    </script>
</head>
<body>
    <div class="container">
        <h1 id="top">Active Directory Audit Report</h1>

        <div class="summary-box">
            <h3>Audit Summary</h3>
            <div class="metric">
                <div class="metric-value">$($users.TotalUsers)</div>
                <div class="metric-label">Total Users</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($groups.TotalGroups)</div>
                <div class="metric-label">Total Groups</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($computers.TotalComputers)</div>
                <div class="metric-label">Total Computers</div>
            </div>
            <div class="metric">
                <div class="metric-value$(if($users.StaleUsers.Count -gt 0){' warning'})">$($users.StaleUsers.Count)</div>
                <div class="metric-label">Stale Users</div>
            </div>
            <div class="metric">
                <div class="metric-value$(if($computers.StaleComputers.Count -gt 0){' warning'})">$($computers.StaleComputers.Count)</div>
                <div class="metric-label">Stale Computers</div>
            </div>
            <div class="metric">
                <div class="metric-value$(if($eosPastEnd -gt 0){' danger'})">$eosPastEnd</div>
                <div class="metric-label">Servers past end of support</div>
            </div>
            <div class="metric">
                <div class="metric-value$(if($totalFindings -gt 0){' danger'})">$totalFindings</div>
                <div class="metric-label">Security Findings</div>
            </div>
            <p><strong>Domain:</strong> $(Escape-Html $overview.DomainName) | <strong>Date:</strong> $($AuditDate.ToString('yyyy-MM-dd HH:mm')) | <strong>Stale Threshold:</strong> $DaysInactive days</p>
        </div>

        <div class="toc">
            <h3>Table of Contents</h3>
            <ul>
                <li><a href="#overview">Domain Overview</a></li>
                <li><a href="#dcs">Domain Controllers</a></li>
                <li><a href="#users">User Accounts</a></li>
                <li><a href="#groups">Group Analysis</a></li>
                <li><a href="#computers">Computer Accounts</a></li>
                <li><a href="#endofsupport">End of Support</a></li>
                <li><a href="#passwordpolicy">Password Policy</a></li>
                <li><a href="#privileged">Privileged Access</a></li>
                <li><a href="#security">Security Findings</a></li>
                <li><a href="#infrastructure">Infrastructure Health</a></li>
                <li><a href="#oustructure">OU Structure</a></li>
            </ul>
        </div>
"@

    #--- Domain Overview Section ---
    $html += @"

        <div class="section" id="overview">
            <h2>Domain Overview</h2>
            <div class="info-grid">
                <div class="info-label">Forest:</div><div>$(Escape-Html $overview.ForestName)</div>
                <div class="info-label">Domain:</div><div>$(Escape-Html $overview.DomainName)</div>
                <div class="info-label">NetBIOS Name:</div><div>$(Escape-Html $overview.NetBIOSName)</div>
                <div class="info-label">Forest Functional Level:</div><div>$(Escape-Html $overview.ForestMode)</div>
                <div class="info-label">Domain Functional Level:</div><div>$(Escape-Html $overview.DomainMode)</div>
                <div class="info-label">Domain Controllers:</div><div>$($overview.DomainControllers)</div>
            </div>

            <h3>FSMO Roles</h3>
            <table>
                <tr><th>Role</th><th>Holder</th></tr>
                $($overview.FSMORoles | ForEach-Object { "<tr><td>$(Escape-Html $_.Role)</td><td>$(Escape-Html $_.Holder)</td></tr>" })
            </table>
"@

    if (@($overview.Trusts).Count -gt 0) {
        $html += @"
            <h3>Domain Trusts</h3>
            <table>
                <tr><th>Name</th><th>Direction</th><th>Type</th><th>IntraForest</th></tr>
                $($overview.Trusts | ForEach-Object { "<tr><td>$(Escape-Html $_.Name)</td><td>$($_.Direction)</td><td>$($_.TrustType)</td><td>$($_.IntraForest)</td></tr>" })
            </table>
"@
    }

    if (@($overview.Sites).Count -gt 0) {
        $html += @"
            <h3>Sites <span class="badge badge-info">$(@($overview.Sites).Count)</span></h3>
            <table>
                <tr><th>Name</th><th>Description</th></tr>
                $($overview.Sites | ForEach-Object { "<tr><td>$(Escape-Html $_.Name)</td><td>$(Escape-Html $_.Description)</td></tr>" })
            </table>
"@
    }

    if (@($overview.Subnets).Count -gt 0) {
        $html += @"
            <h3>Subnets <span class="badge badge-info">$(@($overview.Subnets).Count)</span></h3>
            <table>
                <tr><th>Subnet</th><th>Site</th><th>Location</th><th>Description</th></tr>
                $($overview.Subnets | ForEach-Object {
                    $siteName = if ($_.Site) { ($_.Site -split ',')[0] -replace '^CN=' } else { 'Unassigned' }
                    "<tr><td>$(Escape-Html $_.Name)</td><td>$(Escape-Html $siteName)</td><td>$(Escape-Html $_.Location)</td><td>$(Escape-Html $_.Description)</td></tr>"
                })
            </table>
"@
    }

    $html += @"
            <div class="back-to-top"><a href="#top">Back to top</a></div>
        </div>
"@

    #--- Domain Controllers Section ---
    $dcData = $AuditResults.DomainControllers
    $html += @"

        <div class="section" id="dcs">
            <h2>Domain Controllers <span class="badge badge-info">$(@($dcData.DomainControllers).Count)</span></h2>
            <table>
                <tr><th>Hostname</th><th>Site</th><th>IP</th><th>OS</th><th>GC</th><th>RODC</th><th>FSMO Roles</th><th>Replication</th></tr>
                $($dcData.DomainControllers | ForEach-Object {
                    $replClass = if ($_.ReplicationStatus -ne 'OK') { 'severity-high' } else { 'severity-low' }
                    "<tr>
                        <td>$(Escape-Html $_.HostName)</td>
                        <td>$(Escape-Html $_.Site)</td>
                        <td>$($_.IPv4Address)</td>
                        <td>$(Escape-Html $_.OperatingSystem)</td>
                        <td>$($_.IsGlobalCatalog)</td>
                        <td>$($_.IsReadOnly)</td>
                        <td>$(Escape-Html $_.OperationMasterRoles)</td>
                        <td class='$replClass'>$(Escape-Html $_.ReplicationStatus)</td>
                    </tr>"
                })
            </table>
"@

    if (@($dcData.ReplicationFailures).Count -gt 0) {
        $html += @"
            <h3 class="collapsible" onclick="toggleSection('repl-failures')">Replication Failures <span class="badge badge-danger">$(@($dcData.ReplicationFailures).Count)</span></h3>
            <div id="repl-failures" class="collapsible-content">
            <table>
                <tr><th>DC</th><th>Partner</th><th>Failure Count</th><th>Type</th><th>First Failure</th><th>Last Error</th></tr>
                $($dcData.ReplicationFailures | ForEach-Object {
                    "<tr><td>$(Escape-Html $_.DomainController)</td><td>$(Escape-Html $_.Partner)</td><td>$($_.FailureCount)</td><td>$(Escape-Html $_.FailureType)</td><td>$($_.FirstFailure)</td><td>$($_.LastError)</td></tr>"
                })
            </table>
            </div>
"@
    }

    $html += @"
            <div class="back-to-top"><a href="#top">Back to top</a></div>
        </div>
"@

    #--- User Accounts Section ---
    $html += @"

        <div class="section" id="users">
            <h2>User Accounts</h2>
            <div class="metric">
                <div class="metric-value">$($users.TotalUsers)</div>
                <div class="metric-label">Total</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($users.EnabledCount)</div>
                <div class="metric-label">Enabled</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($users.DisabledCount)</div>
                <div class="metric-label">Disabled</div>
            </div>
"@

    if ($users.StaleUsers.Count -gt 0) {
        $html += @"
            <h3 class="collapsible" onclick="toggleSection('stale-users')">Stale Users (No logon in $DaysInactive days) <span class="badge badge-warning">$($users.StaleUsers.Count)</span></h3>
            <div id="stale-users" class="collapsible-content">
            <table>
                <tr><th>Name</th><th>SamAccountName</th><th>Last Logon</th><th>Password Last Set</th><th>Created</th></tr>
                $($users.StaleUsers | Sort-Object LastLogonDate | ForEach-Object {
                    "<tr><td>$(Escape-Html $_.Name)</td><td>$(Escape-Html $_.SamAccountName)</td><td>$($_.LastLogonDate)</td><td>$($_.PasswordLastSet)</td><td>$($_.whenCreated)</td></tr>"
                })
            </table>
            </div>
"@
    }

    if ($users.PasswordNeverExpires.Count -gt 0) {
        $html += @"
            <h3 class="collapsible" onclick="toggleSection('pwd-never')">Password Never Expires <span class="badge badge-warning">$($users.PasswordNeverExpires.Count)</span></h3>
            <div id="pwd-never" class="collapsible-content">
            <table>
                <tr><th>Name</th><th>SamAccountName</th><th>Password Last Set</th><th>Created</th></tr>
                $($users.PasswordNeverExpires | ForEach-Object {
                    "<tr><td>$(Escape-Html $_.Name)</td><td>$(Escape-Html $_.SamAccountName)</td><td>$($_.PasswordLastSet)</td><td>$($_.whenCreated)</td></tr>"
                })
            </table>
            </div>
"@
    }

    if ($users.PasswordNotRequired.Count -gt 0) {
        $html += @"
            <h3 class="collapsible" onclick="toggleSection('pwd-notrequired')">Password Not Required <span class="badge badge-danger">$($users.PasswordNotRequired.Count)</span></h3>
            <div id="pwd-notrequired" class="collapsible-content">
            <table>
                <tr><th>Name</th><th>SamAccountName</th><th>Created</th></tr>
                $($users.PasswordNotRequired | ForEach-Object {
                    "<tr><td>$(Escape-Html $_.Name)</td><td>$(Escape-Html $_.SamAccountName)</td><td>$($_.whenCreated)</td></tr>"
                })
            </table>
            </div>
"@
    }

    if ($users.NeverLoggedOn.Count -gt 0) {
        $html += @"
            <h3 class="collapsible" onclick="toggleSection('never-logon')">Never Logged On <span class="badge badge-info">$($users.NeverLoggedOn.Count)</span></h3>
            <div id="never-logon" class="collapsible-content">
            <table>
                <tr><th>Name</th><th>SamAccountName</th><th>Created</th><th>Description</th></tr>
                $($users.NeverLoggedOn | ForEach-Object {
                    "<tr><td>$(Escape-Html $_.Name)</td><td>$(Escape-Html $_.SamAccountName)</td><td>$($_.whenCreated)</td><td>$(Escape-Html $_.Description)</td></tr>"
                })
            </table>
            </div>
"@
    }

    if ($users.LockedOut.Count -gt 0) {
        $html += @"
            <h3>Locked Out Accounts <span class="badge badge-warning">$($users.LockedOut.Count)</span></h3>
            <table>
                <tr><th>Name</th><th>SamAccountName</th><th>Last Logon</th></tr>
                $($users.LockedOut | ForEach-Object {
                    "<tr><td>$(Escape-Html $_.Name)</td><td>$(Escape-Html $_.SamAccountName)</td><td>$($_.LastLogonDate)</td></tr>"
                })
            </table>
"@
    }

    if ($users.SIDHistory.Count -gt 0) {
        $html += @"
            <h3>Accounts with SID History <span class="badge badge-warning">$($users.SIDHistory.Count)</span></h3>
            <table>
                <tr><th>Name</th><th>SamAccountName</th><th>SID History Count</th></tr>
                $($users.SIDHistory | ForEach-Object {
                    "<tr><td>$(Escape-Html $_.Name)</td><td>$(Escape-Html $_.SamAccountName)</td><td>$($_.SIDHistoryCount)</td></tr>"
                })
            </table>
"@
    }

    $html += @"
            <div class="back-to-top"><a href="#top">Back to top</a></div>
        </div>
"@

    #--- Groups Section ---
    $html += @"

        <div class="section" id="groups">
            <h2>Group Analysis</h2>
            <div class="metric">
                <div class="metric-value">$($groups.TotalGroups)</div>
                <div class="metric-label">Total Groups</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($groups.EmptyGroups.Count)</div>
                <div class="metric-label">Empty Groups</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($groups.LargeGroups.Count)</div>
                <div class="metric-label">Large Groups (50+)</div>
            </div>

            <h3>Privileged Group Membership <span class="badge badge-info">$(@($groups.PrivilegedMembers).Count)</span></h3>
            $(if (@($groups.PrivilegedMembers).Count -gt 0) {
                "<table>
                    <tr><th>Group</th><th>Name</th><th>SamAccountName</th><th>Type</th></tr>
                    $($groups.PrivilegedMembers | Sort-Object Group, Name | ForEach-Object {
                        "<tr><td>$(Escape-Html $_.Group)</td><td>$(Escape-Html $_.Name)</td><td>$(Escape-Html $_.SamAccount)</td><td>$($_.ObjectClass)</td></tr>"
                    })
                </table>"
            } else {
                "<p class='badge badge-success'>No privileged group members found</p>"
            })
"@

    if (@($groups.NestedWarnings).Count -gt 0) {
        $html += @"
            <h3>Nested Group Warnings <span class="badge badge-warning">$(@($groups.NestedWarnings).Count)</span></h3>
            <table>
                <tr><th>Privileged Group</th><th>Nested Group</th><th>Warning</th></tr>
                $($groups.NestedWarnings | ForEach-Object {
                    "<tr><td>$(Escape-Html $_.Group)</td><td>$(Escape-Html $_.Name)</td><td>$(Escape-Html $_.Warning)</td></tr>"
                })
            </table>
"@
    }

    if ($groups.LargeGroups.Count -gt 0) {
        $html += @"
            <h3 class="collapsible" onclick="toggleSection('large-groups')">Large Groups <span class="badge badge-info">$($groups.LargeGroups.Count)</span></h3>
            <div id="large-groups" class="collapsible-content">
            <table>
                <tr><th>Name</th><th>Members</th><th>Category</th><th>Scope</th></tr>
                $($groups.LargeGroups | Sort-Object MemberCount -Descending | ForEach-Object {
                    "<tr><td>$(Escape-Html $_.Name)</td><td>$($_.MemberCount)</td><td>$($_.GroupCategory)</td><td>$($_.GroupScope)</td></tr>"
                })
            </table>
            </div>
"@
    }

    if ($groups.EmptyGroups.Count -gt 0) {
        $html += @"
            <h3 class="collapsible collapsed" onclick="toggleSection('empty-groups')">Empty Groups <span class="badge badge-info">$($groups.EmptyGroups.Count)</span></h3>
            <div id="empty-groups" class="collapsible-content collapsed">
            <table>
                <tr><th>Name</th><th>Category</th><th>Scope</th><th>Description</th></tr>
                $($groups.EmptyGroups | Sort-Object Name | ForEach-Object {
                    "<tr><td>$(Escape-Html $_.Name)</td><td>$($_.GroupCategory)</td><td>$($_.GroupScope)</td><td>$(Escape-Html $_.Description)</td></tr>"
                })
            </table>
            </div>
"@
    }

    $html += @"
            <div class="back-to-top"><a href="#top">Back to top</a></div>
        </div>
"@

    #--- Computer Accounts Section ---
    $html += @"

        <div class="section" id="computers">
            <h2>Computer Accounts</h2>
            <div class="metric">
                <div class="metric-value">$($computers.TotalComputers)</div>
                <div class="metric-label">Total</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($computers.EnabledCount)</div>
                <div class="metric-label">Enabled</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($computers.DisabledCount)</div>
                <div class="metric-label">Disabled</div>
            </div>

            <h3>OS Distribution</h3>
            $(if (@($computers.OSDistribution).Count -gt 0) {
                "<table>
                    <tr><th>Operating System</th><th>Count</th></tr>
                    $($computers.OSDistribution | ForEach-Object {
                        "<tr><td>$(Escape-Html $_.OperatingSystem)</td><td>$($_.Count)</td></tr>"
                    })
                </table>"
            } else {
                "<p>No OS data available</p>"
            })
"@

    if ($computers.UnsupportedComputers.Count -gt 0) {
        $html += @"
            <h3>Unsupported Operating Systems <span class="badge badge-danger">$($computers.UnsupportedComputers.Count)</span></h3>
            <table>
                <tr><th>Name</th><th>OS</th><th>Last Logon</th></tr>
                $($computers.UnsupportedComputers | ForEach-Object {
                    "<tr><td>$(Escape-Html $_.Name)</td><td>$(Escape-Html $_.OperatingSystem)</td><td>$($_.LastLogonDate)</td></tr>"
                })
            </table>
"@
    }

    if ($computers.StaleComputers.Count -gt 0) {
        $html += @"
            <h3 class="collapsible" onclick="toggleSection('stale-computers')">Stale Computers (No logon in $DaysInactive days) <span class="badge badge-warning">$($computers.StaleComputers.Count)</span></h3>
            <div id="stale-computers" class="collapsible-content">
            <table>
                <tr><th>Name</th><th>OS</th><th>Last Logon</th><th>Created</th></tr>
                $($computers.StaleComputers | Sort-Object LastLogonDate | ForEach-Object {
                    "<tr><td>$(Escape-Html $_.Name)</td><td>$(Escape-Html $_.OperatingSystem)</td><td>$($_.LastLogonDate)</td><td>$($_.whenCreated)</td></tr>"
                })
            </table>
            </div>
"@
    }

    $html += @"
            <div class="back-to-top"><a href="#top">Back to top</a></div>
        </div>
"@

    #--- End of Support Section ---
    $firstEos = if ($eosServers.Count -gt 0) { $eosServers[0] } else { $null }
    $eosCheckedOn = if ($eos.TableCheckedOn) { $eos.TableCheckedOn } elseif ($firstEos) { $firstEos.TableCheckedOn } else { (Get-ServerLifecycleTable).CheckedOn }
    $eosStamp = if ($eos.RunBy) { [PSCustomObject]@{ RunBy = $eos.RunBy; RunOn = $eos.RunOn } }
                elseif ($firstEos) { [PSCustomObject]@{ RunBy = $firstEos.RunBy; RunOn = $firstEos.RunOn } }
                else { Get-AuditRunStamp }
    $html += @"

        <div class="section" id="endofsupport">
            <h2>End of Support</h2>
            <p>Enabled Windows Server computer accounts and Microsoft's support end dates. Lifecycle dates last checked against Microsoft Learn on <strong>$(Escape-Html $eosCheckedOn)</strong>. Audit run by $(Escape-Html $eosStamp.RunBy) on $(Escape-Html $eosStamp.RunOn).</p>
            <p>A server past extended support is covered only if the client bought ESU (Extended Security Updates); AD cannot tell whether they did. Last logon comes from lastLogonTimestamp, which can be up to about 14 days behind.</p>
"@

    if ($eos.StaleTableWarning) {
        $html += @"
            <p class="severity-warning">$(Escape-Html $eos.StaleTableWarning)</p>
"@
    }

    if ($eos.Skipped) {
        $html += @"
            <p>This section was not selected for this run.</p>
"@
    }
    elseif ($eos.Error) {
        $html += @"
            <p class="severity-high">Could not read servers from AD: $(Escape-Html $eos.Error)</p>
"@
    }
    elseif ($eosServers.Count -eq 0) {
        $html += @"
            <p>No enabled Windows Server computer accounts found.</p>
"@
    }
    else {
        $html += @"
            <div class="metric">
                <div class="metric-value">$($eosServers.Count)</div>
                <div class="metric-label">Servers</div>
            </div>
            <div class="metric">
                <div class="metric-value$(if($eosPastEnd -gt 0){' danger'})">$eosPastEnd</div>
                <div class="metric-label">Past extended support</div>
            </div>
            <div class="metric">
                <div class="metric-value$(if(@($eosServers | Where-Object { $_.Status -eq 'Unknown' }).Count -gt 0){' warning'})">$(@($eosServers | Where-Object { $_.Status -eq 'Unknown' }).Count)</div>
                <div class="metric-label">Not in the lifecycle table</div>
            </div>
            <table>
                <tr><th>Server</th><th>Operating System (as AD records it)</th><th>Product</th><th>Support Status</th><th>What it means</th><th>Mainstream End</th><th>Extended End</th><th>ESU End</th><th>Days Until Extended End</th><th>Last Logon</th><th>Not Seen in $DaysInactive Days</th></tr>
                $($eosServers | ForEach-Object {
                    $sevClass = "severity-$(([string]$_.Severity).ToLower())"
                    $productCell = if ($_.Product) { "<a href=`"$(Escape-Html $_.Source)`">$(Escape-Html $_.Product)</a>" } else { "<a href=`"$(Escape-Html $_.Source)`">Check manually</a>" }
                    "<tr><td>$(Escape-Html $_.Name)</td><td>$(Escape-Html $_.OperatingSystem)</td><td>$productCell</td><td class='$sevClass'>$(Escape-Html $_.Status)</td><td>$(Escape-Html $_.Note)</td><td>$(Escape-Html $_.MainstreamEnd)</td><td>$(Escape-Html $_.ExtendedEnd)</td><td>$(Escape-Html $_.EsuEnd)</td><td>$(Escape-Html ([string]$_.DaysUntilExtendedEnd))</td><td>$(Escape-Html $_.LastLogonDate)</td><td>$(if ($_.Stale -eq $true) { 'Yes' } else { 'No' })</td></tr>"
                })
            </table>
            <p>Days Until Extended End: a negative number means extended support ended that many days ago. Each product links to the Microsoft Learn lifecycle page its dates came from.</p>
"@
    }

    $html += @"
            <div class="back-to-top"><a href="#top">Back to top</a></div>
        </div>
"@

    #--- Password Policy Section ---
    $html += @"

        <div class="section" id="passwordpolicy">
            <h2>Password Policy</h2>
            <h3>Default Domain Password Policy</h3>
"@

    if ($pwPolicy.DefaultPolicy) {
        $dp = $pwPolicy.DefaultPolicy
        $html += @"
            <div class="info-grid">
                <div class="info-label">Min Password Length:</div><div>$($dp.MinPasswordLength)</div>
                <div class="info-label">Password History:</div><div>$($dp.PasswordHistoryCount)</div>
                <div class="info-label">Max Password Age:</div><div>$($dp.MaxPasswordAge) days</div>
                <div class="info-label">Min Password Age:</div><div>$($dp.MinPasswordAge) days</div>
                <div class="info-label">Complexity Required:</div><div>$($dp.ComplexityEnabled)</div>
                <div class="info-label">Reversible Encryption:</div><div>$(if($dp.ReversibleEncryption){"<span class='severity-high'>Enabled</span>"}else{'Disabled'})</div>
                <div class="info-label">Lockout Threshold:</div><div>$($dp.LockoutThreshold)</div>
                <div class="info-label">Lockout Duration:</div><div>$($dp.LockoutDuration) min</div>
            </div>
"@
    }

    if (@($pwPolicy.NISTFindings).Count -gt 0) {
        $html += @"
            <h3>NIST 800-63B Compliance</h3>
            <table>
                <tr><th>Check</th><th>Status</th><th>Current Value</th><th>Recommendation</th></tr>
                $($pwPolicy.NISTFindings | ForEach-Object {
                    $statusClass = switch ($_.Status) { 'Fail' { 'severity-high' } 'Warning' { 'severity-warning' } 'Pass' { 'severity-low' } }
                    "<tr><td>$(Escape-Html $_.Check)</td><td class='$statusClass'>$($_.Status)</td><td>$(Escape-Html $_.Current)</td><td>$(Escape-Html $_.Recommendation)</td></tr>"
                })
            </table>
"@
    }

    if (@($pwPolicy.FineGrained).Count -gt 0) {
        $html += @"
            <h3>Fine-Grained Password Policies <span class="badge badge-info">$(@($pwPolicy.FineGrained).Count)</span></h3>
            <table>
                <tr><th>Name</th><th>Precedence</th><th>Min Length</th><th>History</th><th>Max Age (days)</th><th>Complexity</th><th>Lockout Threshold</th><th>Applies To</th></tr>
                $($pwPolicy.FineGrained | ForEach-Object {
                    "<tr><td>$(Escape-Html $_.Name)</td><td>$($_.Precedence)</td><td>$($_.MinPasswordLength)</td><td>$($_.PasswordHistoryCount)</td><td>$($_.MaxPasswordAgeDays)</td><td>$($_.ComplexityEnabled)</td><td>$($_.LockoutThreshold)</td><td>$(Escape-Html $_.AppliesTo)</td></tr>"
                })
            </table>
"@
    }

    $html += @"
            <div class="back-to-top"><a href="#top">Back to top</a></div>
        </div>
"@

    #--- Privileged Access Section ---
    $html += @"

        <div class="section" id="privileged">
            <h2>Privileged Access</h2>
            <p style="color:#666;font-size:0.9em">This section is a summary. For full nested-group path analysis of who can reach Domain Admins, run <code>Find-PrivilegedAccessPaths\Get-DomainPrivilegedAccess.ps1</code>.</p>

            <h3>AdminSDHolder Protected Accounts <span class="badge badge-info">$(@($priv.AdminSDHolder).Count)</span></h3>
            $(if (@($priv.AdminSDHolder).Count -gt 0) {
                "<table>
                    <tr><th>Name</th><th>SamAccountName</th><th>Enabled</th><th>Last Logon</th><th>Group Memberships</th></tr>
                    $($priv.AdminSDHolder | ForEach-Object {
                        "<tr><td>$(Escape-Html $_.Name)</td><td>$(Escape-Html $_.SamAccountName)</td><td>$($_.Enabled)</td><td>$($_.LastLogonDate)</td><td>$($_.GroupCount)</td></tr>"
                    })
                </table>"
            } else {
                "<p class='badge badge-success'>No AdminSDHolder protected accounts found</p>"
            })
"@

    if (@($priv.Delegation).Count -gt 0) {
        $html += @"
            <h3>Kerberos Delegation <span class="badge badge-warning">$(@($priv.Delegation).Count)</span></h3>
            <table>
                <tr><th>Name</th><th>Type</th><th>Object Class</th><th>Details</th></tr>
                $($priv.Delegation | ForEach-Object {
                    $typeClass = if ($_.Type -eq 'Unconstrained') { 'severity-high' } else { 'severity-warning' }
                    "<tr><td>$(Escape-Html $_.Name)</td><td class='$typeClass'>$($_.Type)</td><td>$($_.ObjectClass)</td><td>$(Escape-Html $_.Details)</td></tr>"
                })
            </table>
"@
    }

    if (@($priv.KerberoastableAdmins).Count -gt 0) {
        $html += @"
            <h3>Kerberoastable Admin Accounts <span class="badge badge-danger">$(@($priv.KerberoastableAdmins).Count)</span></h3>
            <table>
                <tr><th>Name</th><th>SamAccountName</th><th>SPNs</th></tr>
                $($priv.KerberoastableAdmins | ForEach-Object {
                    "<tr><td>$(Escape-Html $_.Name)</td><td>$(Escape-Html $_.SamAccountName)</td><td>$(Escape-Html $_.SPNs)</td></tr>"
                })
            </table>
"@
    }

    if (@($priv.ASREPRoastable).Count -gt 0) {
        $html += @"
            <h3>AS-REP Roastable Accounts <span class="badge badge-danger">$(@($priv.ASREPRoastable).Count)</span></h3>
            <table>
                <tr><th>Name</th><th>SamAccountName</th><th>Enabled</th><th>Last Logon</th></tr>
                $($priv.ASREPRoastable | ForEach-Object {
                    "<tr><td>$(Escape-Html $_.Name)</td><td>$(Escape-Html $_.SamAccountName)</td><td>$($_.Enabled)</td><td>$($_.LastLogonDate)</td></tr>"
                })
            </table>
"@
    }

    $html += @"
            <div class="back-to-top"><a href="#top">Back to top</a></div>
        </div>
"@

    #--- Security Findings Section ---
    $html += @"

        <div class="section" id="security">
            <h2>Security Findings</h2>
            $(if (@($security.Findings).Count -gt 0) {
                "<table>
                    <tr><th>Category</th><th>Severity</th><th>Object</th><th>Details</th><th>Recommendation</th></tr>
                    $($security.Findings | Sort-Object @{E={switch($_.Severity){'High'{0}'Warning'{1}'Low'{2}default{3}}}} | ForEach-Object {
                        $sevClass = "severity-$($_.Severity.ToLower())"
                        "<tr><td>$(Escape-Html $_.Category)</td><td class='$sevClass'>$(Escape-Html $_.Severity)</td><td>$(Escape-Html $_.Object)</td><td>$(Escape-Html $_.Details)</td><td>$(Escape-Html $_.Recommendation)</td></tr>"
                    })
                </table>"
            } else {
                "<p class='badge badge-success'>No security findings</p>"
            })
            <div class="back-to-top"><a href="#top">Back to top</a></div>
        </div>
"@

    #--- Infrastructure Health Section ---
    $infra = $AuditResults.Infrastructure
    $html += @"

        <div class="section" id="infrastructure">
            <h2>Infrastructure Health</h2>
            <div class="info-grid">
                <div class="info-label">Tombstone Lifetime:</div><div>$(Escape-Html $infra.TombstoneLifetime)</div>
                <div class="info-label">AD Recycle Bin:</div><div>$(if($infra.RecycleBinEnabled){"<span class='severity-low'>Enabled</span>"}else{"<span class='severity-high'>Disabled</span>"})</div>
                <div class="info-label">Schema Version:</div><div>$($infra.SchemaVersion) ($(Escape-Html $infra.SchemaOS))</div>
                <div class="info-label">Sysvol Replication:</div><div>$(if($infra.SysvolReplication -eq 'DFSR'){"<span class='severity-low'>DFSR</span>"}else{"<span class='severity-warning'>$(Escape-Html $infra.SysvolReplication)</span>"})</div>
            </div>
"@

    if (@($infra.TrustHealth).Count -gt 0) {
        $html += @"
            <h3>Trust Health <span class="badge badge-info">$(@($infra.TrustHealth).Count)</span></h3>
            <table>
                <tr><th>Name</th><th>Direction</th><th>Type</th><th>IntraForest</th><th>Selective Auth</th><th>SID Filtering</th><th>TGT Delegation</th></tr>
                $($infra.TrustHealth | ForEach-Object {
                    $sidClass = switch ($_.SIDFilteringSeverity) { 'High' { 'severity-high' } 'Warning' { 'severity-warning' } default { 'severity-low' } }
                    "<tr><td>$(Escape-Html $_.Name)</td><td>$($_.Direction)</td><td>$($_.TrustType)</td><td>$($_.IntraForest)</td><td>$($_.SelectiveAuth)</td><td class='$sidClass'>$(Escape-Html $_.SIDFiltering)</td><td>$($_.TGTDelegation)</td></tr>"
                })
            </table>
"@
    }

    $html += @"
            <div class="back-to-top"><a href="#top">Back to top</a></div>
        </div>
"@

    #--- OU Structure Section ---
    $ouData = $AuditResults.OUStructure
    $html += @"

        <div class="section" id="oustructure">
            <h2>OU Structure</h2>
            <div class="metric">
                <div class="metric-value">$($ouData.TotalOUs)</div>
                <div class="metric-label">Total OUs</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($ouData.MaxDepth)</div>
                <div class="metric-label">Max Depth</div>
            </div>
            <div class="metric">
                <div class="metric-value">$(@($ouData.EmptyOUs).Count)</div>
                <div class="metric-label">Empty OUs</div>
            </div>
            <div class="metric">
                <div class="metric-value">$(@($ouData.NoGPOLink).Count)</div>
                <div class="metric-label">No GPO Links</div>
            </div>
"@

    if (@($ouData.EmptyOUs).Count -gt 0) {
        $html += @"
            <h3 class="collapsible" onclick="toggleSection('empty-ous')">Empty OUs <span class="badge badge-info">$(@($ouData.EmptyOUs).Count)</span></h3>
            <div id="empty-ous" class="collapsible-content">
            <table>
                <tr><th>Name</th><th>Distinguished Name</th><th>Depth</th><th>Description</th></tr>
                $($ouData.EmptyOUs | Sort-Object DistinguishedName | ForEach-Object {
                    "<tr><td>$(Escape-Html $_.Name)</td><td>$(Escape-Html $_.DistinguishedName)</td><td>$($_.Depth)</td><td>$(Escape-Html $_.Description)</td></tr>"
                })
            </table>
            </div>
"@
    }

    if (@($ouData.NoGPOLink).Count -gt 0) {
        $html += @"
            <h3 class="collapsible collapsed" onclick="toggleSection('no-gpo-ous')">OUs Without GPO Links <span class="badge badge-info">$(@($ouData.NoGPOLink).Count)</span></h3>
            <div id="no-gpo-ous" class="collapsible-content collapsed">
            <table>
                <tr><th>Name</th><th>Distinguished Name</th><th>Depth</th><th>Child Objects</th></tr>
                $($ouData.NoGPOLink | Sort-Object DistinguishedName | ForEach-Object {
                    "<tr><td>$(Escape-Html $_.Name)</td><td>$(Escape-Html $_.DistinguishedName)</td><td>$($_.Depth)</td><td>$($_.ChildObjects)</td></tr>"
                })
            </table>
            </div>
"@
    }

    $html += @"
            <div class="back-to-top"><a href="#top">Back to top</a></div>
        </div>
"@

    #--- Footer ---
    $html += @"

        <div class="footer">
            <p>Generated by Invoke-ADAudit v$ScriptVersion on $($AuditDate.ToString('yyyy-MM-dd HH:mm:ss'))</p>
        </div>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-AuditLog "HTML report saved: $OutputFile" -Level Success
}

#endregion

#region Main Execution

# Tests dot-source the script with -LoadFunctionsOnly to get the functions without running an audit.
if ($LoadFunctionsOnly) { return }

# Prerequisites check
if (-not (Test-Prerequisites)) {
    return
}

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Write-AuditLog "Starting Active Directory Audit (v$ScriptVersion)" -Level Info
Write-AuditLog "Output: $OutputPath | Format: $ExportFormat | Stale threshold: $DaysInactive days" -Level Info

# Run selected audit sections
$emptyHash = @{}
$auditResults = @{
    Overview          = if (Test-SectionIncluded 'DomainOverview')    { Get-DomainOverview }          else { @{ DomainName = ''; ForestName = ''; DomainControllers = 0; FSMORoles = @(); Trusts = @(); Sites = @(); Subnets = @() } }
    DomainControllers = if (Test-SectionIncluded 'DomainControllers') { Get-DomainControllerAudit }   else { @{ DomainControllers = @(); ReplicationFailures = @() } }
    Users             = if (Test-SectionIncluded 'Users')             { Get-UserAccountAudit }         else { @{ TotalUsers = 0; EnabledCount = 0; DisabledCount = 0; StaleUsers = @(); PasswordNeverExpires = @(); PasswordNotRequired = @(); NeverLoggedOn = @(); LockedOut = @(); SIDHistory = @() } }
    Groups            = if (Test-SectionIncluded 'Groups')            { Get-GroupAudit }               else { @{ TotalGroups = 0; EmptyGroups = @(); LargeGroups = @(); PrivilegedMembers = @(); NestedWarnings = @() } }
    Computers         = if (Test-SectionIncluded 'Computers')         { Get-ComputerAccountAudit }     else { @{ TotalComputers = 0; EnabledCount = 0; DisabledCount = 0; StaleComputers = @(); OSDistribution = @(); UnsupportedComputers = @() } }
    EndOfSupport      = if (Test-SectionIncluded 'EndOfSupport')      { Get-EndOfSupportAudit }        else { @{ Servers = @(); PastEndCount = 0; StaleTableWarning = $null; Error = $null; Skipped = $true } }
    PasswordPolicy    = if (Test-SectionIncluded 'PasswordPolicy')    { Get-PasswordPolicyAudit }      else { @{ DefaultPolicy = $null; NISTFindings = @(); FineGrained = @() } }
    Privileged        = if (Test-SectionIncluded 'PrivilegedAccess')   { Get-PrivilegedAccessAudit }    else { @{ AdminSDHolder = @(); Delegation = @(); KerberoastableAdmins = @(); ASREPRoastable = @() } }
    Security          = if (Test-SectionIncluded 'Security')          { Get-SecurityAudit }            else { @{ Findings = @() } }
    Infrastructure    = if (Test-SectionIncluded 'Infrastructure')    { Get-ADInfrastructureAudit }    else { @{ TombstoneLifetime = 'Skipped'; RecycleBinEnabled = $false; SchemaVersion = 'Skipped'; SchemaOS = 'Skipped'; SysvolReplication = 'Skipped'; TrustHealth = @() } }
    OUStructure       = if (Test-SectionIncluded 'OUStructure')       { Get-OUStructureAudit }         else { @{ TotalOUs = 0; MaxDepth = 0; OUs = @(); EmptyOUs = @(); NoGPOLink = @() } }
}

# Export reports
if ($ExportFormat -in @('CSV', 'Both')) {
    Export-CSVReports -AuditResults $auditResults -BasePath $OutputPath
}

if ($ExportFormat -in @('HTML', 'Both')) {
    $htmlFile = Join-Path $OutputPath "$ReportName.html"
    Export-HTMLReport -AuditResults $auditResults -OutputFile $htmlFile

    if (-not $SkipBrowserOpen) {
        Start-Process $htmlFile
    }
}

Write-AuditLog "Active Directory Audit complete!" -Level Success
Write-AuditLog "Reports saved to: $OutputPath" -Level Info

# Return results for pipeline use
return $auditResults

#endregion
