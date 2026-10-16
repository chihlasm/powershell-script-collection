#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only audit of Microsoft Entra ID (M365) password policy for a tenant.

.DESCRIPTION
    Collects sync/hybrid status, per-domain expiration policy, smart lockout &
    password protection settings, Security Defaults state, and per-user
    password policy flags with effective expiration.

    Output is ONE .xlsx workbook when the ImportExcel module is installed (Excel itself is
    not needed). If ImportExcel is missing the script falls back to one UTF-8 CSV per
    sheet instead of failing. Nothing is installed automatically: if a required
    Microsoft Graph module is missing, the script prints the exact Install-Module command
    and exits.

    The script is read-only. It signs in interactively with delegated Graph permissions.

.PARAMETER TenantId
    Customer tenant ID or primary domain (use for GDAP/delegated access).

.PARAMETER OutputPath
    Directory for the report. Defaults to the current directory. For backward
    compatibility a value ending in .xlsx is treated as the full workbook path.

.PARAMETER LoadFunctionsOnly
    Define the functions and return without connecting or exporting (used by the Pester tests).

.EXAMPLE
    .\Get-EntraPasswordPolicy.ps1 -TenantId contoso.com
    Writes PasswordPolicy_contoso.com_<date>.xlsx (or .csv files) to the current directory.

.EXAMPLE
    .\Get-EntraPasswordPolicy.ps1 -TenantId 00000000-0000-0000-0000-000000000000 -OutputPath C:\Reports
    Audits a tenant by ID and writes the report to C:\Reports.

.NOTES
    Requires: Windows PowerShell 5.1 (Microsoft.Graph requires 5.1).
    Modules (install manually, CurrentUser scope is enough):
        Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement,
        Microsoft.Graph.Users          (or the whole Microsoft.Graph meta-module)
    Optional: ImportExcel (without it, CSV files are written instead of an .xlsx).

    Delegated Graph scopes requested (least privileged for each call):
        Organization.Read.All     GET /organization
        Domain.Read.All           GET /domains
        GroupSettings.Read.All    GET /groupSettings            (Password Rule Settings)
        Policy.Read.All           GET /policies/identitySecurityDefaultsEnforcementPolicy
        User.Read.All             GET /users

    Effective-expiration rules:
        - Synced (on-premises) users: governed by on-premises AD by default.
        - DisablePasswordExpiration user flag: never expires.
        - Domain passwordValidityPeriodInDays NOT set: Graph documents a 90-day default,
          so 90 is used (and labelled "default"). 2147483647 (Int32.MaxValue) is treated as
          "never"; that sentinel is the value tenants return in practice but is not stated
          on the Learn pages below.
    Not verified on Learn: the setting value names inside the 'Password Rule Settings'
    object (LockoutThreshold, LockoutDurationInSeconds, EnableBannedPasswordCheck,
    BannedPasswordList, EnableBannedPasswordCheckOnPremises, BannedPasswordCheckOnPremisesMode)
    and the organization property onPremisesLastPasswordSyncDateTime (not listed on the v1.0
    organization resource; the column is blank when Graph does not return it).

    REFERENCES
    - Password policy and expiration:
      https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy
    - Password expiration in M365 admin center:
      https://learn.microsoft.com/microsoft-365/admin/manage/set-password-expiration-policy
    - Graph domain resource (passwordValidityPeriodInDays: unset = 90 days; passwordNotificationWindowInDays: unset = 14):
      https://learn.microsoft.com/graph/api/resources/domain
    - Get domain (Domain.Read.All):
      https://learn.microsoft.com/graph/api/domain-get
    - Get organization (Organization.Read.All needed for all properties):
      https://learn.microsoft.com/graph/api/organization-get
    - List groupSettings (GroupSettings.Read.All) and directory settings templates:
      https://learn.microsoft.com/graph/api/group-list-settings
      https://learn.microsoft.com/graph/group-directory-settings
    - identitySecurityDefaultsEnforcementPolicy (Policy.Read.All):
      https://learn.microsoft.com/graph/api/identitysecuritydefaultsenforcementpolicy-get
    - User resource (passwordPolicies, lastPasswordChangeDateTime, onPremisesSyncEnabled; User.Read.All):
      https://learn.microsoft.com/graph/api/resources/user
      https://learn.microsoft.com/graph/api/user-get
    - Smart lockout defaults (10 attempts / 60 seconds in Azure Public):
      https://learn.microsoft.com/entra/identity/authentication/howto-password-smart-lockout
    - ImportExcel: https://www.powershellgallery.com/packages/ImportExcel
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,

    [string]$OutputPath = (Get-Location).Path,

    [switch]$LoadFunctionsOnly
)

$ErrorActionPreference = 'Stop'

# Int32.MaxValue: the value tenants return for "password never expires".
$NeverExpires = 2147483647
# Documented default when passwordValidityPeriodInDays is not set.
# https://learn.microsoft.com/graph/api/resources/domain
$DefaultValidityDays = 90

$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Users'
)

#region Functions

function Write-Status {
    param(
        [Parameter(Mandatory)][ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Level,
        [Parameter(Mandatory)][string]$Message
    )
    $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$Level]
    Write-Host ("[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message) -ForegroundColor $color
}

function Get-MissingModule {
    param([Parameter(Mandatory)][string[]]$Name)
    return @($Name | Where-Object { -not (Get-Module -ListAvailable -Name $_) })
}

function Get-EffectivePasswordExpiration {
    <#
    Works out what actually governs a user's password expiry.
      DomainDays   : the domain's passwordValidityPeriodInDays ($null = not set)
      DomainKnown  : $false when the UPN domain is not in the tenant's domain list
    #>
    param(
        [bool]$Synced,
        [bool]$NeverFlag,
        $DomainDays,
        [bool]$DomainKnown = $true,
        $LastPasswordChange,
        [datetime]$Now = (Get-Date)
    )

    $days = $null
    $label = $null
    $never = $false

    if ($Synced) {
        $label = 'On-prem AD governs'
    }
    elseif ($NeverFlag) {
        $label = 'Never (user flag)'
        $never = $true
    }
    elseif (-not $DomainKnown) {
        $label = 'Unknown (UPN domain not found in tenant)'
    }
    elseif ($null -ne $DomainDays -and [int64]$DomainDays -ge $NeverExpires) {
        $label = 'Never (domain policy)'
        $never = $true
    }
    elseif ($null -eq $DomainDays) {
        $days = $DefaultValidityDays
        $label = "$days days (domain default - not set)"
    }
    else {
        $days = [int]$DomainDays
        $label = "$days days (domain policy)"
    }

    $expiresOn = $null
    if ($null -ne $days -and $LastPasswordChange) {
        $expiresOn = ([datetime]$LastPasswordChange).AddDays($days)
    }

    return [PSCustomObject]@{
        Effective        = $label
        PasswordExpiresOn = $expiresOn
        CurrentlyExpired = [bool]($expiresOn -and $expiresOn -lt $Now)
        NeverExpires     = $never
    }
}

function Export-PolicyReport {
    <#
    Writes the sheets as one .xlsx (ImportExcel) or, when -UseExcel is not set, one UTF-8 CSV per sheet.
    Returns the list of files written.
    #>
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Sheets,
        [Parameter(Mandatory)][string]$BasePath,   # no extension
        [switch]$UseExcel
    )

    $written = @()
    if ($UseExcel) {
        $xlsx = "$BasePath.xlsx"
        if (Test-Path -LiteralPath $xlsx) { Remove-Item -LiteralPath $xlsx -Force }
        $xl = @{ Path = $xlsx; AutoSize = $true; FreezeTopRow = $true; BoldTopRow = $true }
        foreach ($name in $Sheets.Keys) {
            if ($name -eq 'Users') {
                @($Sheets[$name]) | Export-Excel @xl -WorksheetName $name -AutoFilter -TableName 'Users'
            }
            else {
                @($Sheets[$name]) | Export-Excel @xl -WorksheetName $name
            }
        }
        $written += $xlsx
    }
    else {
        foreach ($name in $Sheets.Keys) {
            $csv = "$BasePath-$name.csv"
            @($Sheets[$name]) | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
            $written += $csv
        }
    }
    return $written
}

#endregion

if ($LoadFunctionsOnly) { return }

#region Prerequisites

# Never install modules silently: tell the operator exactly what to run, then stop.
$missing = Get-MissingModule -Name $RequiredModules
if ($missing.Count -gt 0) {
    Write-Status FAIL "Missing required PowerShell module(s): $($missing -join ', ')"
    Write-Status INFO 'Install them (no admin rights needed) and run this script again:'
    Write-Host '    Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Users -Scope CurrentUser'
    Write-Host '    # or the whole SDK:  Install-Module Microsoft.Graph -Scope CurrentUser'
    exit 1
}

$useExcel = $false
if (Get-Module -ListAvailable -Name ImportExcel) {
    try { Import-Module ImportExcel -ErrorAction Stop; $useExcel = $true }
    catch { Write-Status WARN "ImportExcel is installed but failed to load ($($_.Exception.Message)); writing CSV files instead." }
}
else {
    Write-Status WARN 'ImportExcel module not found - writing one CSV per sheet instead of an .xlsx.'
    Write-Status INFO 'For a single workbook run:  Install-Module ImportExcel -Scope CurrentUser'
}

try {
    foreach ($m in $RequiredModules) { Import-Module $m -ErrorAction Stop }
}
catch {
    Write-Status FAIL "Could not import Microsoft Graph module: $($_.Exception.Message)"
    exit 1
}

#endregion

#region Output location

$fileStem = "PasswordPolicy_{0}_{1:yyyy-MM-dd_HHmmss}" -f ($TenantId -replace '[^\w\.-]', '_'), (Get-Date)
if ($OutputPath -like '*.xlsx') {
    $basePath = $OutputPath.Substring(0, $OutputPath.Length - '.xlsx'.Length)
    $outDir = Split-Path -Parent $basePath
    if (-not $outDir) { $outDir = (Get-Location).Path; $basePath = Join-Path $outDir $basePath }
}
else {
    $outDir = $OutputPath
    $basePath = Join-Path $outDir $fileStem
}
if (-not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

#endregion

try {
    Write-Status INFO "Connecting to Microsoft Graph for tenant $TenantId ..."
    Connect-MgGraph -TenantId $TenantId -NoWelcome -Scopes `
        'Organization.Read.All', 'Domain.Read.All', 'GroupSettings.Read.All', 'Policy.Read.All', 'User.Read.All' | Out-Null
    Write-Status PASS 'Connected.'

    # --- Tenant / hybrid status ---
    $org = Get-MgOrganization
    if ($org -is [array]) { $org = $org[0] }
    $lastPwSync = $null
    if ($org.PSObject.Properties['OnPremisesLastPasswordSyncDateTime']) { $lastPwSync = $org.OnPremisesLastPasswordSyncDateTime }
    $orgInfo = [PSCustomObject]@{
        TenantName            = $org.DisplayName
        TenantId              = $org.Id
        OnPremisesSyncEnabled = [bool]$org.OnPremisesSyncEnabled
        LastDirSync           = $org.OnPremisesLastSyncDateTime
        LastPasswordHashSync  = $lastPwSync
    }

    # --- Domain expiration policy ---
    $domainPolicy = @{}
    $domains = @(Get-MgDomain | ForEach-Object {
        $days = $_.PasswordValidityPeriodInDays
        $domainPolicy[$_.Id.ToLower()] = $days
        $display = if ($null -eq $days) { "$DefaultValidityDays (default - not set)" }
                   elseif ([int64]$days -ge $NeverExpires) { 'Never' }
                   else { $days }
        [PSCustomObject]@{
            Domain                 = $_.Id
            IsDefault              = $_.IsDefault
            IsVerified             = $_.IsVerified
            AuthenticationType     = $_.AuthenticationType
            PasswordExpirationDays = $display
            NotificationWindowDays = $_.PasswordNotificationWindowInDays
        }
    })

    # --- Smart lockout / password protection ---
    $pwRule = $null
    try {
        $pwRule = @((Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/groupSettings').value) |
            Where-Object { $_.displayName -eq 'Password Rule Settings' }
    }
    catch {
        Write-Status WARN "Could not read groupSettings (needs GroupSettings.Read.All): $($_.Exception.Message)"
    }
    if ($pwRule) {
        $vals = @{}; $pwRule.values | ForEach-Object { $vals[$_.name] = $_.value }
        $lockout = [PSCustomObject]@{
            Source                    = 'Custom (configured)'
            LockoutThreshold          = $vals.LockoutThreshold
            LockoutDurationSeconds    = $vals.LockoutDurationInSeconds
            CustomBannedListEnabled   = $vals.EnableBannedPasswordCheck
            CustomBannedPasswordCount = @(($vals.BannedPasswordList -split "`t") | Where-Object { $_ }).Count
            OnPremProtectionEnabled   = $vals.EnableBannedPasswordCheckOnPremises
            OnPremProtectionMode      = $vals.BannedPasswordCheckOnPremisesMode
        }
    }
    else {
        # Defaults: https://learn.microsoft.com/entra/identity/authentication/howto-password-smart-lockout
        $lockout = [PSCustomObject]@{
            Source                    = 'Microsoft defaults (no custom setting object)'
            LockoutThreshold          = 10
            LockoutDurationSeconds    = 60
            CustomBannedListEnabled   = $false
            CustomBannedPasswordCount = 0
            OnPremProtectionEnabled   = 'N/A'
            OnPremProtectionMode      = 'N/A'
        }
    }

    # --- Security Defaults ---
    $secDef = $null
    try {
        $secDef = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
    }
    catch {
        Write-Status WARN "Could not read Security Defaults (needs Policy.Read.All): $($_.Exception.Message)"
    }

    # --- Users with effective expiration ---
    Write-Status INFO 'Reading users ...'
    $now = Get-Date
    $users = @(Get-MgUser -All -Property UserPrincipalName, DisplayName, AccountEnabled, UserType, PasswordPolicies, LastPasswordChangeDateTime, OnPremisesSyncEnabled |
    ForEach-Object {
        $flags     = if ($_.PasswordPolicies) { $_.PasswordPolicies } else { 'None' }
        $neverFlag = [bool]($flags -match 'DisablePasswordExpiration')
        $domain    = ($_.UserPrincipalName -split '@')[-1].ToLower()
        $known     = $domainPolicy.ContainsKey($domain)
        $domDays   = if ($known) { $domainPolicy[$domain] } else { $null }
        $lastChange = $_.LastPasswordChangeDateTime

        $eff = Get-EffectivePasswordExpiration -Synced ([bool]$_.OnPremisesSyncEnabled) -NeverFlag $neverFlag `
            -DomainDays $domDays -DomainKnown $known -LastPasswordChange $lastChange -Now $now

        [PSCustomObject]@{
            UserPrincipalName      = $_.UserPrincipalName
            DisplayName            = $_.DisplayName
            AccountEnabled         = $_.AccountEnabled
            UserType               = $_.UserType
            Synced                 = [bool]$_.OnPremisesSyncEnabled
            PasswordPolicyFlags    = $flags
            NeverExpiresFlag       = $neverFlag
            StrongPasswordDisabled = [bool]($flags -match 'DisableStrongPassword')
            UpnDomain              = $domain
            EffectiveExpiration    = $eff.Effective
            LastPasswordChange     = $lastChange
            # The explicit else is required: without it, Windows PowerShell 5.1 keeps reading the
            # next line looking for one and fails to parse the whole script (7.x does not).
            PasswordAgeDays        = if ($lastChange) { [int]($now - $lastChange).TotalDays } else { $null }
            PasswordExpiresOn      = $eff.PasswordExpiresOn
            CurrentlyExpired       = $eff.CurrentlyExpired
        }
    })
    $members = @($users | Where-Object UserType -eq 'Member')

    # --- Summary sheet (key/value) ---
    $securityDefaultsState = if ($secDef) { $secDef.isEnabled } else { 'Unknown (not readable)' }
    $summary = [ordered]@{
        'Tenant'                               = $org.DisplayName
        'Report date'                          = $now.ToString('yyyy-MM-dd')
        'Directory sync (on-prem AD)'          = $orgInfo.OnPremisesSyncEnabled
        'Synced member accounts'               = "$(@($members | Where-Object Synced).Count) of $($members.Count)"
        'Complexity (fixed, cloud accounts)'   = 'Min 8 / max 256 chars; 3 of 4 character types; last password cannot be reused'
        'Default domain expiration'            = @($domains | Where-Object IsDefault)[0].PasswordExpirationDays
        'Smart lockout source'                 = $lockout.Source
        'Lockout threshold (attempts)'         = $lockout.LockoutThreshold
        'Lockout duration (seconds)'           = $lockout.LockoutDurationSeconds
        'Custom banned list enabled'           = "$($lockout.CustomBannedListEnabled) ($($lockout.CustomBannedPasswordCount) entries)"
        'Global banned list'                   = 'Always enforced'
        'Security Defaults enabled'            = $securityDefaultsState
        'Members - password never expires'     = @($members | Where-Object NeverExpiresFlag).Count
        'Members - strong password disabled'   = @($members | Where-Object StrongPasswordDisabled).Count
        'Members - password currently expired' = @($members | Where-Object CurrentlyExpired).Count
    }
    $summaryRows = @($summary.GetEnumerator() | ForEach-Object { [PSCustomObject]@{ Setting = $_.Key; Value = $_.Value } })

    $flagRef = @(
        [PSCustomObject]@{ Flag = 'None';                      Meaning = 'User follows the domain expiration policy and Entra complexity rules' }
        [PSCustomObject]@{ Flag = 'DisablePasswordExpiration'; Meaning = 'Password never expires for this user; overrides domain expiration policy' }
        [PSCustomObject]@{ Flag = 'DisableStrongPassword';     Meaning = 'User may set passwords that do not meet Entra complexity requirements' }
        [PSCustomObject]@{ Flag = 'Reference';                 Meaning = 'https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy' }
    )

    $sheets = [ordered]@{
        'Summary'            = $summaryRows
        'Tenant'             = @($orgInfo)
        'Domains'            = $domains
        'Lockout-Protection' = @($lockout)
        'Users'              = $users
        'Flag-Reference'     = $flagRef
    }
    $files = Export-PolicyReport -Sheets $sheets -BasePath $basePath -UseExcel:$useExcel

    $summaryRows | Format-Table -AutoSize
    foreach ($f in $files) { Write-Status PASS "Report written: $f" }
}
catch {
    Write-Status FAIL "Password policy audit failed: $($_.Exception.Message)"
    exit 1
}
finally {
    try { Disconnect-MgGraph | Out-Null } catch { Write-Verbose "Disconnect-MgGraph: $($_.Exception.Message)" }
}
