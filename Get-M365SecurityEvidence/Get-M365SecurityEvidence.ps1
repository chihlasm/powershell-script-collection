<#
.SYNOPSIS
    Collects MFA, password policy, and privileged-account hygiene evidence from a
    Microsoft 365 / Entra ID tenant for security attestation and audit response.

.DESCRIPTION
    Built for MSP multi-tenant use. Produces a timestamped evidence folder containing
    raw CSV exports plus an HTML summary that maps findings to three common
    attestation control families:

      1. MFA enforced on all users, on email/collaboration, with no exclusions
      2. Strong password policy (length, lockout threshold, lockout duration) with no exceptions
      3. Privileged accounts not used for day-to-day activity

    Deliberately depends on Microsoft.Graph.Authentication ONLY and calls Graph REST
    endpoints via Invoke-MgGraphRequest. This avoids the dependency/version conflicts
    common with the full Microsoft.Graph SDK on client jump boxes.

    Optional modules, used only if present and requested:
      - ActiveDirectory          (-IncludeOnPremPolicy)   on-prem password/lockout policy
      - ExchangeOnlineManagement (-IncludeMailboxTypes)   shared/room/equipment triage

.PARAMETER ClientName
    Client name used for output folder naming and report headers. Required.

.PARAMETER TenantId
    Target tenant ID or domain. Recommended when a technician has access to many tenants.

.PARAMETER OutputPath
    Root folder for evidence output. Defaults to the current directory.

.PARAMETER DaysBack
    Sign-in log lookback window in days. Default 30.
    NOTE: Entra ID Free retains sign-in logs for 7 days; P1/P2 retains 30.

.PARAMETER PrivilegedRoles
    Directory role display names treated as privileged. Defaults to a standard set.

.PARAMETER UseDeviceCode
    Authenticate via device code flow. Useful when working in an incognito/isolated
    browser session or on a server without a usable interactive browser.

.PARAMETER IncludeOnPremPolicy
    Collect on-prem AD default domain password policy and all fine-grained password
    policies. Must be run from a domain-joined host with RSAT AD PowerShell.

.PARAMETER IncludeMailboxTypes
    Connect to Exchange Online to classify accounts as Shared/Room/Equipment mailboxes.
    Dramatically reduces false positives in the MFA gap list.

.PARAMETER IncludePerUserMfaState
    Query legacy per-user MFA state for every enabled member account. Slow (one Graph
    call per user) but proves no account is stuck in a legacy "Enforced/Disabled" state.

.PARAMETER SkipSignInLogs
    Skip all sign-in log collection (useful for Entra ID Free tenants where the data
    is unavailable or too shallow to be meaningful).

.EXAMPLE
    .\Get-M365SecurityEvidence.ps1 -ClientName "Contoso Inc" -TenantId contoso.onmicrosoft.com -IncludeMailboxTypes

.EXAMPLE
    .\Get-M365SecurityEvidence.ps1 -ClientName "Contoso" -IncludeOnPremPolicy -IncludeMailboxTypes -DaysBack 30

.NOTES
    Author  : VC3 Service Delivery
    Target  : Windows PowerShell 5.1 and PowerShell 7.x
    Version : 1.0

    Required delegated Graph scopes (consented at connect time):
        Organization.Read.All, Directory.Read.All, Policy.Read.All,
        RoleManagement.Read.Directory, User.Read.All, AuditLog.Read.All,
        UserAuthenticationMethod.Read.All

    Reference documentation:
        Entra password policy (8-char cloud minimum, immutable):
          https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy
        Smart lockout (defaults 10 attempts / 60s; custom values require P1/P2):
          https://learn.microsoft.com/entra/identity/authentication/howto-password-smart-lockout
        User registration details report:
          https://learn.microsoft.com/graph/api/authenticationmethodsroot-list-userregistrationdetails
        Sign-in log retention by license tier:
          https://learn.microsoft.com/entra/identity/monitoring-health/reference-reports-data-retention
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ClientName,

    [string]$TenantId,

    [string]$OutputPath = (Get-Location).Path,

    [ValidateRange(1, 90)]
    [int]$DaysBack = 30,

    [string[]]$PrivilegedRoles = @(
        'Global Administrator',
        'Privileged Role Administrator',
        'Privileged Authentication Administrator',
        'User Administrator',
        'Exchange Administrator',
        'SharePoint Administrator',
        'Teams Administrator',
        'Security Administrator',
        'Conditional Access Administrator',
        'Application Administrator',
        'Cloud Application Administrator',
        'Intune Administrator',
        'Helpdesk Administrator',
        'Authentication Administrator',
        'Billing Administrator',
        'Global Reader'
    ),

    [switch]$UseDeviceCode,
    [switch]$DisableWam,
    [switch]$IncludeOnPremPolicy,
    [switch]$IncludeMailboxTypes,
    [switch]$IncludePerUserMfaState,
    [switch]$SkipSignInLogs
)

#region ---------------------------------------------------------------- Setup

$ErrorActionPreference = 'Stop'
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Warnings = New-Object System.Collections.Generic.List[string]
$script:GraphFailures = New-Object System.Collections.Generic.List[string]

function Write-Step {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Diagnostic trap. PowerShell's ConciseView error format frequently strips the
# line number on parameter-binding failures, which makes field troubleshooting
# guesswork. This surfaces the full position and call stack for any unhandled
# error, and leaves the record in $Error[0] for follow-up.
# ---------------------------------------------------------------------------
trap {
    Write-Host ""
    Write-Host "UNHANDLED ERROR" -ForegroundColor Red
    Write-Host "  Message : $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Type    : $($_.Exception.GetType().FullName)" -ForegroundColor Red
    if ($_.InvocationInfo) {
        Write-Host "  Line    : $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
        Write-Host "  Command : $($_.InvocationInfo.Line.Trim())" -ForegroundColor Red
    }
    if ($_.ScriptStackTrace) {
        Write-Host "  Stack   :" -ForegroundColor DarkGray
        $_.ScriptStackTrace -split "`n" | ForEach-Object { Write-Host "            $_" -ForegroundColor DarkGray }
    }
    Write-Host ""
    Write-Host "  Full record retained in `$Error[0]. Inspect with:" -ForegroundColor Yellow
    Write-Host "    `$Error[0] | Format-List * -Force" -ForegroundColor Gray
    Write-Host ""
    continue
}

function Write-Ok {
    param([string]$Message)
    Write-Host "    $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
    $script:Warnings.Add($Message)
}

function Add-Finding {
    <#
        Records a control result for the HTML summary.
        Status: Pass | Fail | Review | Info
    #>
    param(
        [string]$Control,
        [string]$Requirement,
        [ValidateSet('Pass', 'Fail', 'Review', 'Info')]
        [string]$Status,
        [string]$Detail,
        [string]$Evidence
    )
    $script:Findings.Add([pscustomobject]@{
        Control     = $Control
        Requirement = $Requirement
        Status      = $Status
        Detail      = $Detail
        Evidence    = $Evidence
    })
}

function Export-Evidence {
    <#
        Writes a CSV into the evidence folder. Empty datasets still produce a file
        so the auditor can see the query was executed and returned nothing.

        $Data is explicitly typed and decorated with AllowNull/AllowEmptyCollection
        because callers pass a mix of arrays, single objects, and
        System.Collections.Generic.List[object] - an empty generic List fails to
        bind to an untyped parameter with "Argument types do not match".
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Name,

        [Parameter(Position = 1)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Data
    )
    $file = Join-Path $script:EvidenceRoot "$Name.csv"
    $rows = @($Data | Where-Object { $null -ne $_ })

    if ($rows.Count -eq 0) {
        '"Result"' | Set-Content -Path $file -Encoding UTF8
        '"No records returned for this query."' | Add-Content -Path $file -Encoding UTF8
    }
    else {
        $rows | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
    }
    Write-Ok "-> $Name.csv  ($($rows.Count) rows)"
    return $file
}

function Invoke-GraphPaged {
    <#
        Wraps Invoke-MgGraphRequest and follows @odata.nextLink until exhausted.
        Returns a flat array. Non-terminating on failure so one bad endpoint
        does not abort the whole collection run.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [int]$MaxPages = 200,
        [switch]$Silent
    )

    $results = New-Object System.Collections.Generic.List[object]
    $page = 0
    $next = $Uri

    while ($next -and $page -lt $MaxPages) {
        try {
            $resp = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject -ErrorAction Stop
        }
        catch {
            $script:GraphFailures.Add($Uri)
            if (-not $Silent) {
                Write-Warn "Graph query failed: $Uri -- $($_.Exception.Message)"
            }
            break
        }

        if ($resp.PSObject.Properties.Name -contains 'value') {
            foreach ($item in $resp.value) { $results.Add($item) }
        }
        else {
            $results.Add($resp)
        }

        $next = $null
        if ($resp.PSObject.Properties.Name -contains '@odata.nextLink') {
            $next = $resp.'@odata.nextLink'
        }
        $page++
    }

    return $results.ToArray()
}

function Protect-Html {
    # Portable HTML encoding. System.Web is not reliably loadable on PowerShell 7.
    param($Value)
    $s = [string]$Value
    if ([string]::IsNullOrEmpty($s)) { return '' }
    return $s.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function Get-SafeCount {
    <#
        Returns an element count for anything: $null, a scalar, an array, or a
        generic collection.

        Do not use @($x).Count for this. The array subexpression operator throws
        "ArgumentException: Argument types do not match" when applied directly to a
        System.Collections.Generic.List[T]. Checking for ICollection first uses the
        collection's native Count and avoids the conversion entirely.
    #>
    param([Parameter(Position = 0)][AllowNull()]$InputObject)

    if ($null -eq $InputObject) { return 0 }
    if ($InputObject -is [string]) { return 1 }
    if ($InputObject -is [System.Collections.ICollection]) { return $InputObject.Count }

    $c = 0
    foreach ($item in $InputObject) { if ($null -ne $item) { $c++ } }
    return $c
}

function ConvertTo-FlatString {
    # Collapses arrays/objects into a single CSV-safe string.
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [System.Collections.IEnumerable]) {
        return (@($Value) -join '; ')
    }
    return [string]$Value
}

#endregion

#region ------------------------------------------------------------ Connect

Write-Host ""
Write-Host "==============================================================" -ForegroundColor White
Write-Host " M365 / Entra ID Security Evidence Collection" -ForegroundColor White
Write-Host " Client : $ClientName" -ForegroundColor White
Write-Host " Run    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') local" -ForegroundColor White
Write-Host "==============================================================" -ForegroundColor White
Write-Host ""

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw "Microsoft.Graph.Authentication is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$scopes = @(
    'Organization.Read.All'
    'Directory.Read.All'
    'Policy.Read.All'
    'RoleManagement.Read.Directory'
    'User.Read.All'
    'AuditLog.Read.All'
    'UserAuthenticationMethod.Read.All'
)

Write-Step "Connecting to Microsoft Graph..."

# WAM (Web Account Manager) is enabled by default on Windows and will silently
# prefer the technician's own work account. Disabling it forces the browser
# picker, which is what you want when signing into a client tenant.
if ($DisableWam) {
    try {
        Set-MgGraphOption -EnableLoginByWAM $false -ErrorAction Stop
        Write-Ok "WAM disabled - browser account picker will be used."
    }
    catch {
        Write-Warn "Could not disable WAM (older module version): $($_.Exception.Message)"
    }
}

# ContextScope Process keeps the client token out of the technician's persistent
# token cache - important when moving between tenants in one session.
$connectParams = @{ Scopes = $scopes; NoWelcome = $true; ContextScope = 'Process' }
if ($TenantId)     { $connectParams['TenantId'] = $TenantId }
if ($UseDeviceCode){ $connectParams['UseDeviceAuthentication'] = $true }

try {
    Connect-MgGraph @connectParams
}
catch {
    # NoWelcome / ContextScope are not present on all module versions.
    $connectParams.Remove('NoWelcome')     | Out-Null
    $connectParams.Remove('ContextScope')  | Out-Null
    Connect-MgGraph @connectParams
}

$ctx = Get-MgContext
if (-not $ctx) { throw "Failed to establish a Graph context." }
Write-Ok "Connected as $($ctx.Account) to tenant $($ctx.TenantId)"

# ---------------------------------------------------------------------------
# PREFLIGHT - do not proceed on a broken session.
#
# Connect-MgGraph and Get-MgContext can both succeed while every actual Graph
# call fails. The most common cause is the -UseDeviceCode NRE bug:
#   https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3495
#
# Continuing past this point would generate an evidence pack full of empty
# result sets that look like real findings ("no privileged accounts",
# "no Premium licensing"). For an attestation deliverable that is far worse
# than failing outright, so this aborts.
# ---------------------------------------------------------------------------
Write-Step "Preflight: verifying the Graph session can actually service requests..."
try {
    $preflight = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/organization?$select=displayName' `
        -OutputType PSObject -ErrorAction Stop

    if (-not $preflight.value) { throw "Query succeeded but returned no organization object." }
    Write-Ok "Preflight OK - tenant reachable: $($preflight.value[0].displayName)"
}
catch {
    $msg = $_.Exception.Message
    Write-Host ""
    Write-Host "PREFLIGHT FAILED - aborting before any evidence is written." -ForegroundColor Red
    Write-Host "  $msg" -ForegroundColor Red
    Write-Host ""

    if ($msg -match 'DeviceCodeCredential|Object reference not set') {
        Write-Host "  This matches a known Microsoft Graph SDK defect where device code" -ForegroundColor Yellow
        Write-Host "  authentication succeeds but every subsequent request throws a null" -ForegroundColor Yellow
        Write-Host "  reference exception (msgraph-sdk-powershell issue #3495)." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Remediation, in order:" -ForegroundColor Yellow
        Write-Host "    1. Disconnect-MgGraph" -ForegroundColor Gray
        Write-Host "    2. Re-run WITHOUT -UseDeviceCode (add -DisableWam to force the" -ForegroundColor Gray
        Write-Host "       browser picker so you can choose the client tenant account)." -ForegroundColor Gray
        Write-Host "    3. If it persists: Update-Module Microsoft.Graph.Authentication" -ForegroundColor Gray
        Write-Host "    4. Verify only one SDK version is loaded:" -ForegroundColor Gray
        Write-Host "       Get-Module Microsoft.Graph.Authentication -ListAvailable | Select Version, Path" -ForegroundColor Gray
    }
    else {
        Write-Host "  Verify the account holds the required read roles and that all" -ForegroundColor Yellow
        Write-Host "  requested scopes were consented at sign-in." -ForegroundColor Yellow
    }
    Write-Host ""
    throw "Graph preflight failed. No evidence folder was created."
}

# Build evidence folder
$stamp    = Get-Date -Format 'yyyyMMdd-HHmmss'
$safeName = ($ClientName -replace '[^\w\-\. ]', '') -replace '\s+', '_'
$script:EvidenceRoot = Join-Path $OutputPath "$($safeName)_SecurityEvidence_$stamp"
New-Item -Path $script:EvidenceRoot -ItemType Directory -Force | Out-Null
Write-Ok "Evidence folder: $script:EvidenceRoot"

#endregion

#region ------------------------------------------- 00 Tenant and licensing

Write-Step "Collecting tenant and licensing context..."

$org = Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/organization'
$tenantDisplayName = if ($org) { $org[0].displayName } else { 'Unknown' }
$verifiedDomains = if ($org -and $org[0].verifiedDomains) {
    ($org[0].verifiedDomains | ForEach-Object { $_.name }) -join '; '
} else { '' }

$skus = Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus'

$skuReport = foreach ($s in $skus) {
    [pscustomobject]@{
        SkuPartNumber = $s.skuPartNumber
        SkuId         = $s.skuId
        Enabled       = $s.prepaidUnits.enabled
        Consumed      = $s.consumedUnits
        Status        = $s.capabilityStatus
    }
}
Export-Evidence -Name '00_Tenant_Licensing' -Data $skuReport | Out-Null

# Entra ID P1/P2 detection drives what is technically possible in this tenant.
# Distinguish "query returned no premium SKU" from "query failed" - conflating
# the two produces a false finding.
$premiumPatterns = 'AAD_PREMIUM|AAD_PREMIUM_P2|ENTERPRISEPREMIUM|SPE_|EMS|M365_G5|M365_E5|IDENTITY_THREAT_PROTECTION'

if (-not $skus -or (Get-SafeCount $skus) -eq 0) {
    $hasPremium = $null
    Write-Warn "subscribedSkus returned no data. Licensing tier is UNKNOWN - do not report this as 'no Premium'. Verify manually in the Microsoft 365 admin center."
}
else {
    $hasPremium = [bool]($skus | Where-Object { $_.skuPartNumber -match $premiumPatterns })
    if ($hasPremium) {
        Write-Ok "Entra ID Premium detected - sign-in log retention 30 days, smart lockout customizable."
    }
    else {
        Write-Warn "No Entra ID Premium SKU detected. Sign-in logs retain only 7 days and smart lockout values CANNOT be customized (locked at 10 attempts / 60 seconds)."
    }
}

Add-Finding -Control 'Tenant' -Requirement 'Licensing capability baseline' `
    -Status 'Info' `
    -Detail "Tenant: $tenantDisplayName. Entra ID Premium present: $hasPremium. Verified domains: $verifiedDomains" `
    -Evidence '00_Tenant_Licensing.csv'

#endregion

#region ---------------------------------------- 01 Directory user inventory

Write-Step "Building directory user inventory (this is the join table for all triage)..."

$userSelect = 'id,userPrincipalName,displayName,userType,accountEnabled,onPremisesSyncEnabled,createdDateTime,assignedLicenses,mail,signInActivity'
$userUri = "https://graph.microsoft.com/v1.0/users?`$select=$userSelect&`$top=999"

$rawUsers = Invoke-GraphPaged -Uri $userUri
if (-not $rawUsers -or $rawUsers.Count -eq 0) {
    # signInActivity requires premium; retry without it so the run still succeeds.
    Write-Warn "User query failed with signInActivity. Retrying without sign-in activity data."
    $userSelect = 'id,userPrincipalName,displayName,userType,accountEnabled,onPremisesSyncEnabled,createdDateTime,assignedLicenses,mail'
    $userUri = "https://graph.microsoft.com/v1.0/users?`$select=$userSelect&`$top=999"
    $rawUsers = Invoke-GraphPaged -Uri $userUri
}

# Heuristic patterns for non-human accounts. Tune per client if needed.
$serviceAccountPattern = '(?i)(^|[._-])(svc|service|sync_|adsync|aadsync|admin|administrator|backup|scanner|scan|copier|printer|mfp|fax|relay|smtp|noreply|no-reply|donotreply|alert|alarm|siren|voicemail|voiceauth|kiosk|camera|cctv|monitor|monitoring|sql|api|integration|connector|test|temp|training)([._-]|$)'
$resourceNamePattern   = '(?i)(conference|conf ?room|meeting|boardroom|huddle|room|truck|vehicle|unit|engine|rescue|quint|calendar|resource|equipment)'

$userIndex = @{}
$userInventory = foreach ($u in $rawUsers) {
    $upn        = ConvertTo-FlatString $u.userPrincipalName
    $isGuest    = ($u.userType -eq 'Guest') -or ($upn -like '*#EXT#*')
    $licCount   = if ($u.assignedLicenses) { @($u.assignedLicenses).Count } else { 0 }
    $lastSignIn = $null
    if ($u.PSObject.Properties.Name -contains 'signInActivity' -and $u.signInActivity) {
        $lastSignIn = $u.signInActivity.lastSignInDateTime
    }

    $obj = [pscustomobject]@{
        Id                    = $u.id
        UserPrincipalName     = $upn
        DisplayName           = ConvertTo-FlatString $u.displayName
        UserType              = ConvertTo-FlatString $u.userType
        IsGuest               = $isGuest
        AccountEnabled        = $u.accountEnabled
        IsSynced              = [bool]$u.onPremisesSyncEnabled
        LicenseCount          = $licCount
        IsLicensed            = ($licCount -gt 0)
        Mail                  = ConvertTo-FlatString $u.mail
        CreatedDateTime       = $u.createdDateTime
        LastSignInDateTime    = $lastSignIn
        LooksLikeServiceAcct  = ($upn -match $serviceAccountPattern) -or ((ConvertTo-FlatString $u.displayName) -match $serviceAccountPattern)
        LooksLikeResourceAcct = ((ConvertTo-FlatString $u.displayName) -match $resourceNamePattern)
        MailboxType           = ''   # populated by Exchange Online section if requested
    }

    if ($upn) { $userIndex[$upn.ToLower()] = $obj }
    $obj
}

Write-Ok "Directory objects retrieved: $((Get-SafeCount $userInventory))"

# Cloud-only accounts are the ones that CANNOT meet a 14-character requirement,
# because the Entra cloud password policy minimum is fixed at 8 characters.
$cloudOnly = $userInventory | Where-Object { -not $_.IsSynced -and -not $_.IsGuest }
Export-Evidence -Name '01_Users_All' -Data $userInventory | Out-Null
Export-Evidence -Name '01b_Users_CloudOnly' -Data $cloudOnly | Out-Null

#endregion

#region ------------------------------------------- 02 Exchange mailbox types

if ($IncludeMailboxTypes) {
    Write-Step "Classifying mailbox types via Exchange Online (removes shared/room false positives)..."
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Warn "ExchangeOnlineManagement is not installed. Skipping mailbox classification. Install-Module ExchangeOnlineManagement -Scope CurrentUser"
    }
    else {
        try {
            Import-Module ExchangeOnlineManagement -ErrorAction Stop
            $eolParams = @{ ShowBanner = $false }
            if ($ctx.Account) { $eolParams['UserPrincipalName'] = $ctx.Account }
            Connect-ExchangeOnline @eolParams -ErrorAction Stop

            $mailboxes = Get-EXOMailbox -ResultSize Unlimited -ErrorAction Stop |
                         Select-Object UserPrincipalName, DisplayName, RecipientTypeDetails

            foreach ($mb in $mailboxes) {
                $key = ($mb.UserPrincipalName).ToLower()
                if ($userIndex.ContainsKey($key)) {
                    $userIndex[$key].MailboxType = $mb.RecipientTypeDetails
                }
            }
            Write-Ok "Mailbox types applied for $((Get-SafeCount $mailboxes)) mailboxes."
            Export-Evidence -Name '02_Mailbox_Types' -Data $mailboxes | Out-Null
        }
        catch {
            Write-Warn "Exchange Online classification failed: $($_.Exception.Message)"
        }
    }
}

#endregion

#region ------------------------------------------------- 03 MFA enforcement

Write-Step "Collecting MFA enforcement evidence..."

# --- 3a. Security defaults -------------------------------------------------
$secDefaults = Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' -Silent
$secDefaultsEnabled = if ($secDefaults) { [bool]$secDefaults[0].isEnabled } else { $null }
Export-Evidence -Name '03a_SecurityDefaults' -Data (
    [pscustomobject]@{ SecurityDefaultsEnabled = $secDefaultsEnabled }
) | Out-Null

# --- 3b. Conditional Access policies ---------------------------------------
$caPolicies = Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'

$caReport = foreach ($p in $caPolicies) {
    [pscustomobject]@{
        DisplayName          = $p.displayName
        State                = $p.state          # enabled | disabled | enabledForReportingButNotEnforced
        Id                   = $p.id
        IncludeUsers         = ConvertTo-FlatString $p.conditions.users.includeUsers
        ExcludeUsers         = ConvertTo-FlatString $p.conditions.users.excludeUsers
        IncludeGroups        = ConvertTo-FlatString $p.conditions.users.includeGroups
        ExcludeGroups        = ConvertTo-FlatString $p.conditions.users.excludeGroups
        IncludeRoles         = ConvertTo-FlatString $p.conditions.users.includeRoles
        ExcludeRoles         = ConvertTo-FlatString $p.conditions.users.excludeRoles
        IncludeApplications  = ConvertTo-FlatString $p.conditions.applications.includeApplications
        ExcludeApplications  = ConvertTo-FlatString $p.conditions.applications.excludeApplications
        ClientAppTypes       = ConvertTo-FlatString $p.conditions.clientAppTypes
        GrantControls        = ConvertTo-FlatString $p.grantControls.builtInControls
        GrantOperator        = ConvertTo-FlatString $p.grantControls.operator
        AuthStrength         = ConvertTo-FlatString $p.grantControls.authenticationStrength.displayName
        CreatedDateTime      = $p.createdDateTime
        ModifiedDateTime     = $p.modifiedDateTime
    }
}
Export-Evidence -Name '03b_ConditionalAccess_Policies' -Data $caReport | Out-Null

# Identify the policies that actually deliver MFA enforcement.
$mfaPolicies = $caReport | Where-Object {
    $_.GrantControls -match 'mfa' -or $_.AuthStrength
}
$enforcedMfaPolicies = $mfaPolicies | Where-Object { $_.State -eq 'enabled' }
$reportOnlyMfa       = $mfaPolicies | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }

if ($reportOnlyMfa) {
    Write-Warn "$((Get-SafeCount $reportOnlyMfa)) MFA policy/policies are in REPORT-ONLY mode. Report-only is not enforcement and will not satisfy an attestation."
}

# Resolve CA exclusion object IDs to human-readable names - this is the
# "no users are excluded" evidence an auditor actually reads.
$exclusionRows = New-Object System.Collections.Generic.List[object]
foreach ($p in $caPolicies) {
    if ($p.grantControls -and (ConvertTo-FlatString $p.grantControls.builtInControls) -notmatch 'mfa' -and -not $p.grantControls.authenticationStrength) {
        continue
    }

    foreach ($uid in @($p.conditions.users.excludeUsers)) {
        if (-not $uid) { continue }
        $resolved = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$uid" -Silent
        $exclusionRows.Add([pscustomobject]@{
            PolicyName    = $p.displayName
            PolicyState   = $p.state
            ExclusionType = 'User'
            ObjectId      = $uid
            ResolvedName  = if ($resolved) { "$($resolved[0].displayName) <$($resolved[0].userPrincipalName)>" } else { 'UNRESOLVED' }
        })
    }
    foreach ($gid in @($p.conditions.users.excludeGroups)) {
        if (-not $gid) { continue }
        $resolved = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/groups/$gid" -Silent
        $members  = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/groups/$gid/members?`$select=displayName,userPrincipalName" -Silent
        $exclusionRows.Add([pscustomobject]@{
            PolicyName    = $p.displayName
            PolicyState   = $p.state
            ExclusionType = 'Group'
            ObjectId      = $gid
            ResolvedName  = if ($resolved) { "$($resolved[0].displayName) [members: $((Get-SafeCount $members))] -> $((@($members) | ForEach-Object { $_.userPrincipalName }) -join ', ')" } else { 'UNRESOLVED' }
        })
    }
    foreach ($rid in @($p.conditions.users.excludeRoles)) {
        if (-not $rid) { continue }
        $exclusionRows.Add([pscustomobject]@{
            PolicyName    = $p.displayName
            PolicyState   = $p.state
            ExclusionType = 'DirectoryRole'
            ObjectId      = $rid
            ResolvedName  = 'Role template - see 05_Privileged_Role_Members.csv'
        })
    }
}
Export-Evidence -Name '03c_MFA_Policy_Exclusions' -Data $exclusionRows.ToArray() | Out-Null

# --- 3c. Authentication method registration report -------------------------
$regDetails = Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999'

$regReport = foreach ($r in $regDetails) {
    $upn = ConvertTo-FlatString $r.userPrincipalName
    $key = if ($upn) { $upn.ToLower() } else { '' }
    $u   = if ($key -and $userIndex.ContainsKey($key)) { $userIndex[$key] } else { $null }

    [pscustomobject]@{
        UserPrincipalName     = $upn
        DisplayName           = ConvertTo-FlatString $r.userDisplayName
        IsMfaCapable          = $r.isMfaCapable
        IsMfaRegistered       = $r.isMfaRegistered
        IsSsprCapable         = $r.isSsprCapable
        IsPasswordlessCapable = $r.isPasswordlessCapable
        DefaultMfaMethod      = ConvertTo-FlatString $r.defaultMfaMethod
        MethodsRegistered     = ConvertTo-FlatString $r.methodsRegistered
        LastUpdated           = $r.lastUpdatedDateTime
        # ---- joined directory context ----
        IsGuest               = if ($u) { $u.IsGuest } else { ($upn -like '*#EXT#*') }
        AccountEnabled        = if ($u) { $u.AccountEnabled } else { $null }
        IsLicensed            = if ($u) { $u.IsLicensed } else { $null }
        IsSynced              = if ($u) { $u.IsSynced } else { $null }
        MailboxType           = if ($u) { $u.MailboxType } else { '' }
        LastSignInDateTime    = if ($u) { $u.LastSignInDateTime } else { $null }
        LooksLikeServiceAcct  = if ($u) { $u.LooksLikeServiceAcct } else { $false }
        LooksLikeResourceAcct = if ($u) { $u.LooksLikeResourceAcct } else { $false }
    }
}
Export-Evidence -Name '03d_MFA_Registration_All' -Data $regReport | Out-Null

# --- 3d. Triage the gaps ---------------------------------------------------
# The whole point: separate "legitimately out of scope" from "real exposure".
$gapTriage = foreach ($r in ($regReport | Where-Object { $_.IsMfaCapable -ne $true })) {
    $category = switch ($true) {
        { $r.IsGuest -eq $true }                                       { 'Guest / B2B - scope decision required'; break }
        { $r.AccountEnabled -eq $false }                               { 'Disabled account - out of scope'; break }
        { $r.MailboxType -in @('SharedMailbox','RoomMailbox','EquipmentMailbox') } { "Non-user mailbox ($($r.MailboxType)) - out of scope if sign-in blocked"; break }
        { $r.LooksLikeServiceAcct -eq $true }                          { 'Likely service/system account - needs documented exception'; break }
        { $r.LooksLikeResourceAcct -eq $true }                         { 'Likely resource account - needs documented exception'; break }
        { $r.IsLicensed -eq $false }                                   { 'Unlicensed enabled account - review or disable'; break }
        default                                                        { 'ACTIVE LICENSED USER - REAL GAP' }
    }

    [pscustomobject]@{
        UserPrincipalName  = $r.UserPrincipalName
        DisplayName        = $r.DisplayName
        Category           = $category
        AccountEnabled     = $r.AccountEnabled
        IsLicensed         = $r.IsLicensed
        IsSynced           = $r.IsSynced
        IsGuest            = $r.IsGuest
        MailboxType        = $r.MailboxType
        LastSignInDateTime = $r.LastSignInDateTime
        MethodsRegistered  = $r.MethodsRegistered
    }
}
$gapTriage = $gapTriage | Sort-Object @{ Expression = { $_.Category -eq 'ACTIVE LICENSED USER - REAL GAP' }; Descending = $true }, Category, UserPrincipalName
Export-Evidence -Name '03e_MFA_Gaps_Triaged' -Data $gapTriage | Out-Null

$realGaps = @($gapTriage | Where-Object { $_.Category -eq 'ACTIVE LICENSED USER - REAL GAP' })

# Counts are materialised into typed locals first. Inline $(@(...).Count)
# subexpressions inside an interpolated string are a common source of obscure
# binding errors when the underlying variable is a generic List rather than an array.
[int]$enforcedCount   = Get-SafeCount $enforcedMfaPolicies
[int]$reportOnlyCount = Get-SafeCount $reportOnlyMfa
[int]$exclusionCount  = Get-SafeCount $exclusionRows
[int]$realGapCount    = Get-SafeCount $realGaps

[string]$mfaStatus = 'Review'
if ($enforcedCount -eq 0) { $mfaStatus = 'Fail' }
elseif ($realGapCount -eq 0) { $mfaStatus = 'Pass' }

[string]$mfaDetail = "Enforced MFA CA policies: $enforcedCount. " +
                     "Report-only: $reportOnlyCount. " +
                     "Security defaults enabled: $secDefaultsEnabled. " +
                     "Policy exclusion entries: $exclusionCount. " +
                     "Untriaged active licensed users without MFA capability: $realGapCount."

Add-Finding -Control 'MFA' `
    -Requirement 'MFA enforced on all user accounts; no users excluded' `
    -Status $mfaStatus `
    -Detail $mfaDetail `
    -Evidence '03b/03c/03e'

# --- 3e. MFA coverage of email and collaboration ---------------------------
# Explicit string array rather than hashtable .Keys enumeration. Keys come back
# loosely typed and static-method overload resolution against them is fragile.
[string[]]$collabAppIds = @(
    '00000002-0000-0ff1-ce00-000000000000'   # Exchange Online
    '00000003-0000-0ff1-ce00-000000000000'   # SharePoint Online
    'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe'   # Microsoft Teams Services
    '5e3ce6c0-2b1f-4285-8d4b-75ee78787346'   # Microsoft Teams
)

[bool]$collabCovered = $false
foreach ($p in @($enforcedMfaPolicies)) {
    [string]$apps = [string]$p.IncludeApplications
    if ([string]::IsNullOrWhiteSpace($apps)) { continue }

    if ($apps -eq 'All' -or $apps -like '*All*') { $collabCovered = $true; break }

    foreach ($appId in $collabAppIds) {
        if ($apps.IndexOf($appId, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $collabCovered = $true
            break
        }
    }
    if ($collabCovered) { break }
}

[string]$collabStatus = 'Review'
if ($collabCovered) { $collabStatus = 'Pass' }

[string]$collabDetail = 'No enforced MFA policy was found targeting All cloud apps or the Exchange/SharePoint/Teams service principals. Verify manually before reporting.'
if ($collabCovered) {
    $collabDetail = 'An enforced MFA policy targets All cloud apps or explicitly targets Exchange/SharePoint/Teams.'
}

Add-Finding -Control 'MFA' `
    -Requirement 'MFA enforced on email and collaboration suite' `
    -Status $collabStatus `
    -Detail $collabDetail `
    -Evidence '03b_ConditionalAccess_Policies.csv' 

# --- 3f. Legacy per-user MFA state (optional) ------------------------------
if ($IncludePerUserMfaState) {
    Write-Step "Querying legacy per-user MFA state (one call per enabled member account)..."
    $targets = $userInventory | Where-Object { $_.AccountEnabled -eq $true -and -not $_.IsGuest }
    $i = 0
    $perUser = foreach ($u in $targets) {
        $i++
        if ($i % 50 -eq 0) { Write-Host "    ... $i / $((Get-SafeCount $targets))" -ForegroundColor DarkGray }
        $state = Invoke-GraphPaged -Uri "https://graph.microsoft.com/beta/users/$($u.Id)/authentication/requirements" -Silent
        [pscustomobject]@{
            UserPrincipalName = $u.UserPrincipalName
            DisplayName       = $u.DisplayName
            PerUserMfaState   = if ($state) { $state[0].perUserMfaState } else { 'query failed' }
        }
    }
    Export-Evidence -Name '03f_PerUser_MFA_State' -Data $perUser | Out-Null
}

#endregion

#region ---------------------------------------------- 04 Password policies

Write-Step "Collecting password policy evidence..."

# --- 4a. Cloud smart lockout (directory setting: Password Rule Settings) ---
$dirSettings = Invoke-GraphPaged -Uri 'https://graph.microsoft.com/beta/settings' -Silent
$pwdSetting = $dirSettings | Where-Object { $_.displayName -eq 'Password Rule Settings' } | Select-Object -First 1

$lockoutThreshold = $null
$lockoutDuration  = $null
$cloudPwdRows = New-Object System.Collections.Generic.List[object]

if ($pwdSetting) {
    foreach ($v in $pwdSetting.values) {
        $cloudPwdRows.Add([pscustomobject]@{ Setting = $v.name; Value = $v.value })
        if ($v.name -eq 'LockoutThreshold')          { $lockoutThreshold = [int]$v.value }
        if ($v.name -eq 'LockoutDurationInSeconds')  { $lockoutDuration  = [int]$v.value }
    }
}
else {
    $cloudPwdRows.Add([pscustomobject]@{ Setting = 'PasswordRuleSettings'; Value = 'Not configured - tenant defaults apply (10 attempts / 60 seconds)' })
    $lockoutThreshold = 10
    $lockoutDuration  = 60
}
$cloudPwdRows.Add([pscustomobject]@{ Setting = 'CloudMinimumPasswordLength'; Value = '8 (fixed by Microsoft, not configurable)' })
$cloudPwdRows.Add([pscustomobject]@{ Setting = 'CloudComplexity'; Value = '3 of 4 character classes (fixed)' })
$cloudPwdRows.Add([pscustomobject]@{ Setting = 'SecurityDefaultsEnabled'; Value = $secDefaultsEnabled })
$cloudPwdRows.Add([pscustomobject]@{ Setting = 'SmartLockoutCustomizable'; Value = $hasPremium })
Export-Evidence -Name '04a_PasswordPolicy_Cloud' -Data $cloudPwdRows.ToArray() | Out-Null

# The 14-character requirement is unachievable for cloud-only accounts.
$cloudOnlyEnabled = @($cloudOnly | Where-Object { $_.AccountEnabled -eq $true })
Add-Finding -Control 'Password' -Requirement 'Minimum 14-character password, no exceptions' `
    -Status $(if ($cloudOnlyEnabled.Count -gt 0) { 'Fail' } else { 'Review' }) `
    -Detail "$($cloudOnlyEnabled.Count) enabled cloud-only account(s) exist. The Entra cloud password policy minimum is fixed at 8 characters and cannot be raised by any administrator, so these accounts cannot satisfy a 14-character requirement without moving them on-premises or compensating with phishing-resistant MFA. Synced accounts inherit the on-prem AD policy - see 04b." `
    -Evidence '01b_Users_CloudOnly.csv, 04a_PasswordPolicy_Cloud.csv'

Add-Finding -Control 'Password' -Requirement 'Lockout after 5 invalid attempts, 15+ minute duration' `
    -Status $(if ($lockoutThreshold -le 5 -and $lockoutDuration -ge 900) { 'Pass' } else { 'Review' }) `
    -Detail "Cloud smart lockout: threshold $lockoutThreshold attempts, duration $lockoutDuration seconds. Customization requires Entra ID P1/P2 (present: $hasPremium). On-prem AD governs synced accounts - see 04b." `
    -Evidence '04a_PasswordPolicy_Cloud.csv'

# --- 4b. On-premises AD policy --------------------------------------------
if ($IncludeOnPremPolicy) {
    Write-Step "Collecting on-premises AD password and lockout policy..."
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Warn "ActiveDirectory module not available. Run this switch from a domain-joined host with RSAT installed."
    }
    else {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $ddp = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
            $ddpRow = [pscustomobject]@{
                PolicyScope              = 'Default Domain Policy'
                Domain                   = (Get-ADDomain).DNSRoot
                MinPasswordLength        = $ddp.MinPasswordLength
                ComplexityEnabled        = $ddp.ComplexityEnabled
                LockoutThreshold         = $ddp.LockoutThreshold
                LockoutDurationMinutes   = $ddp.LockoutDuration.TotalMinutes
                LockoutObservationWindow = $ddp.LockoutObservationWindow.TotalMinutes
                MinPasswordAgeDays       = $ddp.MinPasswordAge.TotalDays
                MaxPasswordAgeDays       = $ddp.MaxPasswordAge.TotalDays
                PasswordHistoryCount     = $ddp.PasswordHistoryCount
                ReversibleEncryption     = $ddp.ReversibleEncryptionEnabled
                AppliesTo                = 'All domain users (unless overridden by a fine-grained policy)'
            }
            Export-Evidence -Name '04b_PasswordPolicy_OnPrem_Default' -Data $ddpRow | Out-Null

            # Fine-grained policies are the classic hidden exception.
            $fgpps = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue
            $fgppRows = foreach ($f in $fgpps) {
                [pscustomobject]@{
                    PolicyScope              = 'Fine-Grained'
                    Name                     = $f.Name
                    Precedence               = $f.Precedence
                    MinPasswordLength        = $f.MinPasswordLength
                    ComplexityEnabled        = $f.ComplexityEnabled
                    LockoutThreshold         = $f.LockoutThreshold
                    LockoutDurationMinutes   = $f.LockoutDuration.TotalMinutes
                    LockoutObservationWindow = $f.LockoutObservationWindow.TotalMinutes
                    MaxPasswordAgeDays       = $f.MaxPasswordAge.TotalDays
                    AppliesTo                = (@($f.AppliesTo) -join '; ')
                }
            }
            Export-Evidence -Name '04c_PasswordPolicy_OnPrem_FineGrained' -Data $fgppRows | Out-Null

            $weakFgpp = @($fgppRows | Where-Object { $_.MinPasswordLength -lt 14 -or $_.LockoutThreshold -gt 5 -or $_.LockoutThreshold -eq 0 -or $_.LockoutDurationMinutes -lt 15 })

            $onPremPass = ($ddp.MinPasswordLength -ge 14) -and
                          ($ddp.LockoutThreshold -le 5 -and $ddp.LockoutThreshold -gt 0) -and
                          ($ddp.LockoutDuration.TotalMinutes -ge 15 -or $ddp.LockoutDuration.TotalMinutes -eq 0) -and
                          ($weakFgpp.Count -eq 0)

            Add-Finding -Control 'Password' -Requirement 'On-premises AD policy meets 14 char / 5 attempts / 15 min, applied to all users' `
                -Status $(if ($onPremPass) { 'Pass' } else { 'Fail' }) `
                -Detail "Default Domain Policy: MinLength $($ddp.MinPasswordLength), LockoutThreshold $($ddp.LockoutThreshold), LockoutDuration $($ddp.LockoutDuration.TotalMinutes) min. Fine-grained policies found: $((Get-SafeCount $fgppRows)), of which $($weakFgpp.Count) weaken the baseline." `
                -Evidence '04b/04c'
        }
        catch {
            Write-Warn "On-prem AD collection failed: $($_.Exception.Message)"
        }
    }
}
else {
    Add-Finding -Control 'Password' -Requirement 'On-premises AD policy verification' `
        -Status 'Info' `
        -Detail 'Not collected. Re-run with -IncludeOnPremPolicy from a domain-joined host. For hybrid tenants the on-prem policy is authoritative for every synced account.' `
        -Evidence 'n/a'
}

#endregion

#region -------------------------------------------- 05 Privileged accounts

Write-Step "Collecting privileged role membership..."

# Helper: build a privileged-account row with directory context joined in.
function New-PrivRow {
    param(
        [string]$RoleName,
        [string]$AssignmentType,   # Active | Eligible
        [string]$AssignmentPath,   # Direct | via group '<name>'
        $Principal
    )

    $upn  = ConvertTo-FlatString $Principal.userPrincipalName
    $key  = if ($upn) { $upn.ToLower() } else { '' }
    $u    = if ($key -and $userIndex.ContainsKey($key)) { $userIndex[$key] } else { $null }
    $type = ConvertTo-FlatString $Principal.'@odata.type'

    $pType = switch -Wildcard ($type) {
        '*servicePrincipal*' { 'ServicePrincipal' }
        '*group*'            { 'Group' }
        '*user*'             { 'User' }
        default              { if ($upn) { 'User' } else { 'Unknown' } }
    }

    [pscustomobject]@{
        RoleName           = $RoleName
        AssignmentType     = $AssignmentType
        AssignmentPath     = $AssignmentPath
        PrincipalType      = $pType
        DisplayName        = ConvertTo-FlatString $Principal.displayName
        UserPrincipalName  = $upn
        ObjectId           = $Principal.id
        ObjectType         = $type
        AccountEnabled     = if ($u) { $u.AccountEnabled } else { $null }
        IsLicensed         = if ($u) { $u.IsLicensed } else { $null }
        IsSynced           = if ($u) { $u.IsSynced } else { $null }
        MailboxType        = if ($u) { $u.MailboxType } else { '' }
        LastSignInDateTime = if ($u) { $u.LastSignInDateTime } else { $null }
    }
}

$privRows = New-Object System.Collections.Generic.List[object]

# --- 5a. Active (standing) role assignments --------------------------------
# A role can be assigned to a role-assignable security group. In that case the
# members endpoint returns the GROUP, not the humans inside it. Expanding
# transitively is required or those admins are invisible to the whole review.
$roles = Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/directoryRoles'

foreach ($role in $roles) {
    if ($PrivilegedRoles -notcontains $role.displayName) { continue }
    $members = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members" -Silent

    foreach ($m in $members) {
        $mType = ConvertTo-FlatString $m.'@odata.type'

        if ($mType -like '*group*') {
            # Record the group itself for traceability...
            $privRows.Add((New-PrivRow -RoleName $role.displayName -AssignmentType 'Active' `
                                       -AssignmentPath 'Direct (group object)' -Principal $m))

            # ...then expand to the actual humans.
            $groupMembers = Invoke-GraphPaged -Silent `
                -Uri "https://graph.microsoft.com/v1.0/groups/$($m.id)/transitiveMembers?`$select=id,displayName,userPrincipalName"

            foreach ($gm in $groupMembers) {
                $privRows.Add((New-PrivRow -RoleName $role.displayName -AssignmentType 'Active' `
                                           -AssignmentPath "via group '$(ConvertTo-FlatString $m.displayName)'" -Principal $gm))
            }

            Write-Warn "Role '$($role.displayName)' is assigned to group '$(ConvertTo-FlatString $m.displayName)' - expanded $(Get-SafeCount $groupMembers) transitive member(s)."
        }
        else {
            $privRows.Add((New-PrivRow -RoleName $role.displayName -AssignmentType 'Active' `
                                       -AssignmentPath 'Direct' -Principal $m))
        }
    }
}

# --- 5b. PIM eligible + scheduled active assignments -----------------------
# Eligible assignments do NOT appear under /directoryRoles/{id}/members. Omitting
# them understates the privileged population in any tenant that uses PIM.
foreach ($pimSet in @(
    @{ Uri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal,roleDefinition'; Type = 'Eligible' },
    @{ Uri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal,roleDefinition'; Type = 'Active (PIM scheduled)' }
)) {
    $pimItems = Invoke-GraphPaged -Uri $pimSet.Uri -Silent
    foreach ($pi in $pimItems) {
        $roleName = ConvertTo-FlatString $pi.roleDefinition.displayName
        if (-not $roleName -or $PrivilegedRoles -notcontains $roleName) { continue }
        if (-not $pi.principal) { continue }
        $privRows.Add((New-PrivRow -RoleName $roleName -AssignmentType $pimSet.Type `
                                   -AssignmentPath 'PIM' -Principal $pi.principal))
    }
    if ((Get-SafeCount $pimItems) -gt 0) {
        Write-Ok "PIM $($pimSet.Type): $(Get-SafeCount $pimItems) schedule instance(s) retrieved."
    }
}

Export-Evidence -Name '05a_Privileged_Role_Members' -Data $privRows.ToArray() | Out-Null

# Only real user principals get sign-in analysis. Groups and service principals
# are reported separately rather than silently dropped.
$uniqueAdmins = @($privRows |
    Where-Object { $_.PrincipalType -eq 'User' -and $_.UserPrincipalName } |
    Select-Object -ExpandProperty UserPrincipalName -Unique)

$nonUserPrincipals = @($privRows | Where-Object { $_.PrincipalType -ne 'User' })

$licensedAdmins = @($privRows |
    Where-Object { $_.PrincipalType -eq 'User' -and $_.IsLicensed -eq $true } |
    Select-Object -ExpandProperty UserPrincipalName -Unique)

Write-Ok "Unique privileged USER accounts: $(Get-SafeCount $uniqueAdmins)  (licensed: $(Get-SafeCount $licensedAdmins))"
if ((Get-SafeCount $nonUserPrincipals) -gt 0) {
    Write-Warn "$(Get-SafeCount $nonUserPrincipals) privileged principal(s) are groups or service principals - reviewed separately, not via sign-in logs. See 05a."
}

Add-Finding -Control 'Admin Hygiene' -Requirement 'Privileged population fully enumerated' `
    -Status 'Info' `
    -Detail "Privileged user accounts: $(Get-SafeCount $uniqueAdmins) (licensed: $(Get-SafeCount $licensedAdmins)). Non-user privileged principals (groups/service principals): $(Get-SafeCount $nonUserPrincipals). Includes direct assignments, role-assignable group expansion, and PIM eligible/scheduled assignments." `
    -Evidence '05a_Privileged_Role_Members.csv' 

#endregion

#region -------------------------------------------------- 06 Sign-in logs

if ($SkipSignInLogs) {
    Add-Finding -Control 'Admin Hygiene' -Requirement 'Admin accounts not used day-to-day' `
        -Status 'Info' -Detail 'Sign-in log collection skipped by parameter.' -Evidence 'n/a'
}
else {
    Write-Step "Collecting sign-in logs for the last $DaysBack days..."

    if (-not $hasPremium) {
        Write-Warn "Without Entra ID Premium, sign-in logs retain only 7 days. A $DaysBack-day evidence window is not obtainable from the portal or Graph. Note this as a limitation in the deliverable."
    }

    $since = (Get-Date).ToUniversalTime().AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ')

    # --- 6a. Per-admin sign-in activity, with app breakdown ----------------
    # Interactive-app usage (Outlook, Teams, SharePoint, Office) by an admin
    # account is the disproving evidence for "not used day-to-day".
    $dayToDayAppPattern = '(?i)(outlook|exchange|teams|sharepoint|onedrive|office|word|excel|powerpoint|yammer|viva|copilot|substrate)'

    $adminSignIns = New-Object System.Collections.Generic.List[object]
    $adminSummary = New-Object System.Collections.Generic.List[object]

    foreach ($adminUpn in $uniqueAdmins) {
        $escaped = $adminUpn -replace "'", "''"
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=createdDateTime ge $since and userPrincipalName eq '$escaped'&`$top=200"
        $signIns = Invoke-GraphPaged -Uri $uri -MaxPages 10 -Silent

        foreach ($s in $signIns) {
            $adminSignIns.Add([pscustomobject]@{
                UserPrincipalName     = $s.userPrincipalName
                CreatedDateTime       = $s.createdDateTime
                AppDisplayName        = $s.appDisplayName
                ResourceDisplayName   = $s.resourceDisplayName
                ClientAppUsed         = $s.clientAppUsed
                IpAddress             = $s.ipAddress
                City                  = $s.location.city
                State                 = $s.location.state
                DeviceOS              = $s.deviceDetail.operatingSystem
                DeviceBrowser         = $s.deviceDetail.browser
                IsInteractive         = $s.isInteractive
                AuthRequirement       = $s.conditionalAccessStatus
                StatusCode            = $s.status.errorCode
                StatusFailureReason   = $s.status.failureReason
            })
        }

        $dayToDay = @($signIns | Where-Object { $_.appDisplayName -match $dayToDayAppPattern })
        $apps     = (@($signIns | Select-Object -ExpandProperty appDisplayName -Unique) -join '; ')

        $adminSummary.Add([pscustomobject]@{
            UserPrincipalName    = $adminUpn
            Roles                = (@($privRows | Where-Object { $_.UserPrincipalName -eq $adminUpn } | Select-Object -ExpandProperty RoleName) -join '; ')
            TotalSignIns         = (Get-SafeCount $signIns)
            DayToDayAppSignIns   = $dayToDay.Count
            DistinctApps         = $apps
            Verdict              = if ((Get-SafeCount $signIns) -eq 0) { 'No sign-ins in window - PASS (dedicated/unused)' }
                                   elseif ($dayToDay.Count -eq 0) { 'Admin-tool sign-ins only - PASS' }
                                   else { 'PRODUCTIVITY APP USE DETECTED - FAIL' }
        })
    }

    Export-Evidence -Name '05b_Admin_SignIns_Raw' -Data $adminSignIns.ToArray() | Out-Null
    Export-Evidence -Name '05c_Admin_SignIn_Summary' -Data $adminSummary.ToArray() | Out-Null

    $failingAdmins = @($adminSummary | Where-Object { $_.Verdict -like '*FAIL*' })

    Add-Finding -Control 'Admin Hygiene' -Requirement 'Accounts with admin rights are not used day-to-day' `
        -Status $(if ($failingAdmins.Count -eq 0) { 'Pass' } else { 'Fail' }) `
        -Detail "$((Get-SafeCount $uniqueAdmins)) privileged account(s) reviewed over $DaysBack days. $($failingAdmins.Count) show sign-ins to productivity applications (Outlook/Teams/SharePoint/Office), indicating day-to-day use. $($licensedAdmins.Count) privileged account(s) carry an assigned license." `
        -Evidence '05a/05b/05c'

    # --- 6b. Legacy authentication (bypasses CA MFA entirely) --------------
    $legacyUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=createdDateTime ge $since and (clientAppUsed eq 'Other clients' or clientAppUsed eq 'IMAP4' or clientAppUsed eq 'POP3' or clientAppUsed eq 'SMTP' or clientAppUsed eq 'Exchange ActiveSync' or clientAppUsed eq 'Authenticated SMTP')&`$top=200"
    $legacy = Invoke-GraphPaged -Uri $legacyUri -MaxPages 10 -Silent

    $legacyRows = foreach ($s in $legacy) {
        [pscustomobject]@{
            UserPrincipalName = $s.userPrincipalName
            CreatedDateTime   = $s.createdDateTime
            AppDisplayName    = $s.appDisplayName
            ClientAppUsed     = $s.clientAppUsed
            IpAddress         = $s.ipAddress
            StatusCode        = $s.status.errorCode
        }
    }
    Export-Evidence -Name '06a_LegacyAuth_SignIns' -Data $legacyRows | Out-Null

    $legacySuccess = @($legacyRows | Where-Object { $_.StatusCode -eq 0 })
    Add-Finding -Control 'MFA' -Requirement 'No authentication path bypasses MFA' `
        -Status $(if ($legacySuccess.Count -eq 0) { 'Pass' } else { 'Fail' }) `
        -Detail "$($legacySuccess.Count) SUCCESSFUL legacy-authentication sign-in(s) in the last $DaysBack days. Legacy auth protocols do not support modern authentication and bypass Conditional Access MFA entirely." `
        -Evidence '06a_LegacyAuth_SignIns.csv'
}

#endregion

#region ------------------------------------------------------ 07 Summary

Write-Step "Building summary report..."

$statusColor = @{
    'Pass'   = '#1a7f37'
    'Fail'   = '#b42318'
    'Review' = '#b54708'
    'Info'   = '#475467'
}

$rowsHtml = ($script:Findings | ForEach-Object {
    $c = $statusColor[$_.Status]
    @"
<tr>
  <td>$(Protect-Html $_.Control)</td>
  <td>$(Protect-Html $_.Requirement)</td>
  <td><span style="color:$c;font-weight:600;">$($_.Status.ToUpper())</span></td>
  <td>$(Protect-Html $_.Detail)</td>
  <td><code>$(Protect-Html $_.Evidence)</code></td>
</tr>
"@
}) -join "`n"

$warnHtml = if ($script:Warnings.Count -gt 0) {
    "<ul>" + (($script:Warnings | ForEach-Object { "<li>$(Protect-Html $_)</li>" }) -join '') + "</ul>"
} else { "<p>None.</p>" }

$integrityHtml = if ($script:GraphFailures.Count -gt 0) {
    $failList = ($script:GraphFailures | Select-Object -Unique | ForEach-Object { "<li><code>$(Protect-Html $_)</code></li>" }) -join ''
    @"
<div style="background:#fef3f2;border-left:4px solid #b42318;padding:12px 16px;margin:16px 0;">
<strong style="color:#b42318;">DATA INTEGRITY WARNING - DO NOT SUBMIT THIS PACK</strong>
<p style="font-size:13px;margin:8px 0;">$($script:GraphFailures.Count) Graph query/queries failed during collection.
Any control below that depends on the affected data is unreliable, and an empty result set here
means "not retrieved", not "does not exist". Resolve the failures and re-run before using this
pack as evidence.</p>
<ul style="font-size:12px;">$failList</ul>
</div>
"@
} else {
    '<div style="background:#ecfdf3;border-left:4px solid #1a7f37;padding:12px 16px;margin:16px 0;font-size:13px;"><strong style="color:#1a7f37;">Collection integrity: OK</strong> - all Graph queries returned successfully.</div>'
}

$html = @"
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>$ClientName - Security Evidence Summary</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#101828;}
 h1{font-size:22px;margin-bottom:4px;}
 h2{font-size:16px;margin-top:28px;border-bottom:1px solid #eaecf0;padding-bottom:6px;}
 .meta{color:#475467;font-size:13px;margin-bottom:20px;}
 table{border-collapse:collapse;width:100%;font-size:13px;}
 th{background:#f9fafb;text-align:left;padding:8px;border:1px solid #eaecf0;}
 td{padding:8px;border:1px solid #eaecf0;vertical-align:top;}
 code{background:#f2f4f7;padding:1px 4px;border-radius:3px;font-size:12px;}
 .note{background:#fffaeb;border-left:3px solid #f79009;padding:10px 14px;font-size:13px;margin-top:16px;}
</style></head><body>
<h1>$ClientName - M365 / Entra ID Security Evidence Summary</h1>
<div class="meta">
 Tenant: $tenantDisplayName ($($ctx.TenantId))<br/>
 Collected by: $($ctx.Account)<br/>
 Collected: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')<br/>
 Sign-in lookback: $DaysBack days | Entra ID Premium: $(if ($null -eq $hasPremium) { 'UNKNOWN (query failed)' } else { $hasPremium })
</div>

$integrityHtml

<h2>Control Results</h2>
<table>
<tr><th>Control</th><th>Requirement</th><th>Status</th><th>Detail</th><th>Evidence file</th></tr>
$rowsHtml
</table>

<h2>Collection Warnings</h2>
$warnHtml

<div class="note">
<strong>Reviewer notes.</strong> Automated status values are indicators, not conclusions.
Every <em>Review</em> and <em>Fail</em> row requires a technician to confirm against the raw CSV
before the result is presented to a client or auditor. Portal screenshots should accompany this
summary for any control where a visual artifact was requested.
</div>

</body></html>
"@

$summaryPath = Join-Path $script:EvidenceRoot '00_Summary.html'
$html | Set-Content -Path $summaryPath -Encoding UTF8

# Machine-readable copy for pipelines or ticket automation.
$script:Findings | Export-Csv -Path (Join-Path $script:EvidenceRoot '00_Summary.csv') -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "==============================================================" -ForegroundColor White
if ($script:GraphFailures.Count -gt 0) {
    Write-Host " Collection completed WITH ERRORS" -ForegroundColor Red
    Write-Host " $($script:GraphFailures.Count) Graph query/queries failed." -ForegroundColor Red
    Write-Host " This pack is NOT submittable as evidence. Resolve and re-run." -ForegroundColor Red
}
else {
    Write-Host " Collection complete - all queries succeeded" -ForegroundColor Green
}
Write-Host " Evidence : $script:EvidenceRoot" -ForegroundColor White
Write-Host " Summary  : $summaryPath" -ForegroundColor White
Write-Host "==============================================================" -ForegroundColor White
Write-Host ""

$script:Findings | Format-Table Control, Status, Requirement -AutoSize

#endregion
