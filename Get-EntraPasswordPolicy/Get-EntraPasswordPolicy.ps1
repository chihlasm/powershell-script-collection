<#
.SYNOPSIS
    Read-only audit of Microsoft Entra ID (M365) password policy for a tenant.
.DESCRIPTION
    Collects sync/hybrid status, per-domain expiration policy, smart lockout &
    password protection settings, Security Defaults state, and per-user
    password policy flags with effective expiration. Outputs ONE .xlsx workbook.
    Requires ImportExcel module (installs to CurrentUser if missing; Excel not needed).
    References:
      https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-policy
      https://learn.microsoft.com/en-us/microsoft-365/admin/manage/set-password-expiration-policy
      https://www.powershellgallery.com/packages/ImportExcel
.PARAMETER TenantId
    Customer tenant ID or primary domain (use for GDAP/delegated access).
.PARAMETER OutputPath
    Full path of the .xlsx to create. Defaults to .\PasswordPolicy_<tenant>_<date>.xlsx
.EXAMPLE
    .\Get-EntraPasswordPolicy.ps1 -TenantId contoso.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$NeverExpires = 2147483647

foreach ($m in 'Microsoft.Graph.Authentication','Microsoft.Graph.Identity.DirectoryManagement','Microsoft.Graph.Users','ImportExcel') {
    if (-not (Get-Module -ListAvailable $m)) { Install-Module $m -Scope CurrentUser -Force }
}
Import-Module ImportExcel

Connect-MgGraph -TenantId $TenantId -NoWelcome -Scopes `
    'Domain.Read.All','Directory.Read.All','Policy.Read.All','User.Read.All'

if (-not $OutputPath) {
    $OutputPath = Join-Path (Get-Location) ("PasswordPolicy_{0}_{1:yyyyMMdd}.xlsx" -f ($TenantId -replace '[^\w\.-]','_'), (Get-Date))
}
if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }

# --- Tenant / hybrid status ---
$org = Get-MgOrganization
$orgInfo = [pscustomobject]@{
    TenantName            = $org.DisplayName
    TenantId              = $org.Id
    OnPremisesSyncEnabled = [bool]$org.OnPremisesSyncEnabled
    LastDirSync           = $org.OnPremisesLastSyncDateTime
    LastPasswordHashSync  = $org.OnPremisesLastPasswordSyncDateTime
}

# --- Domain expiration policy ---
$domainPolicy = @{}
$domains = Get-MgDomain | ForEach-Object {
    $days = $_.PasswordValidityPeriodInDays
    $domainPolicy[$_.Id.ToLower()] = $days
    [pscustomobject]@{
        Domain                 = $_.Id
        IsDefault              = $_.IsDefault
        IsVerified             = $_.IsVerified
        AuthenticationType     = $_.AuthenticationType
        PasswordExpirationDays = if ($days -eq $NeverExpires -or -not $days) { 'Never' } else { $days }
        NotificationWindowDays = $_.PasswordNotificationWindowInDays
    }
}

# --- Smart lockout / password protection ---
$pwRule = (Invoke-MgGraphRequest -Method GET -Uri 'v1.0/groupSettings').value |
    Where-Object { $_.displayName -eq 'Password Rule Settings' }
if ($pwRule) {
    $vals = @{}; $pwRule.values | ForEach-Object { $vals[$_.name] = $_.value }
    $lockout = [pscustomobject]@{
        Source                    = 'Custom (configured)'
        LockoutThreshold          = $vals.LockoutThreshold
        LockoutDurationSeconds    = $vals.LockoutDurationInSeconds
        CustomBannedListEnabled   = $vals.EnableBannedPasswordCheck
        CustomBannedPasswordCount = (($vals.BannedPasswordList -split "`t") | Where-Object { $_ }).Count
        OnPremProtectionEnabled   = $vals.EnableBannedPasswordCheckOnPremises
        OnPremProtectionMode      = $vals.BannedPasswordCheckOnPremisesMode
    }
} else {
    $lockout = [pscustomobject]@{
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
$secDef = Invoke-MgGraphRequest -Method GET -Uri 'v1.0/policies/identitySecurityDefaultsEnforcementPolicy'

# --- Users with effective expiration ---
$now = Get-Date
$users = Get-MgUser -All -Property UserPrincipalName,DisplayName,AccountEnabled,UserType,PasswordPolicies,LastPasswordChangeDateTime,OnPremisesSyncEnabled |
ForEach-Object {
    $flags      = if ($_.PasswordPolicies) { $_.PasswordPolicies } else { 'None' }
    $neverFlag  = $flags -match 'DisablePasswordExpiration'
    $domain     = ($_.UserPrincipalName -split '@')[-1].ToLower()
    $domDays    = $domainPolicy[$domain]
    $domNever   = (-not $domDays) -or ($domDays -eq $NeverExpires)
    $lastChange = $_.LastPasswordChangeDateTime

    $effective = if ($_.OnPremisesSyncEnabled) { 'On-prem AD governs' }
                 elseif ($neverFlag)           { 'Never (user flag)' }
                 elseif ($domNever)            { 'Never (domain policy)' }
                 else                          { "$domDays days (domain policy)" }

    $expiresOn = if (-not $_.OnPremisesSyncEnabled -and -not $neverFlag -and -not $domNever -and $lastChange) { $lastChange.AddDays($domDays) }

    [pscustomobject]@{
        UserPrincipalName      = $_.UserPrincipalName
        DisplayName            = $_.DisplayName
        AccountEnabled         = $_.AccountEnabled
        UserType               = $_.UserType
        Synced                 = [bool]$_.OnPremisesSyncEnabled
        PasswordPolicyFlags    = $flags
        NeverExpiresFlag       = $neverFlag
        StrongPasswordDisabled = $flags -match 'DisableStrongPassword'
        UpnDomain              = $domain
        EffectiveExpiration    = $effective
        LastPasswordChange     = $lastChange
        # The explicit else is required: without it, Windows PowerShell 5.1 keeps reading the
        # next line looking for one and fails to parse the whole script (7.x does not).
        PasswordAgeDays        = if ($lastChange) { [int]($now - $lastChange).TotalDays } else { $null }
        PasswordExpiresOn      = $expiresOn
        CurrentlyExpired       = if ($expiresOn) { $expiresOn -lt $now } else { $false }
    }
}
$members = $users | Where-Object UserType -eq 'Member'

# --- Summary sheet (key/value) ---
$summary = [ordered]@{
    'Tenant'                               = $org.DisplayName
    'Report date'                          = $now.ToString('yyyy-MM-dd')
    'Directory sync (on-prem AD)'          = $orgInfo.OnPremisesSyncEnabled
    'Synced member accounts'               = "$(($members | Where-Object Synced).Count) of $($members.Count)"
    'Complexity (fixed, cloud accounts)'   = 'Min 8 / max 256 chars; 3 of 4 character types; last password cannot be reused'
    'Default domain expiration'            = ($domains | Where-Object IsDefault).PasswordExpirationDays
    'Smart lockout source'                 = $lockout.Source
    'Lockout threshold (attempts)'         = $lockout.LockoutThreshold
    'Lockout duration (seconds)'           = $lockout.LockoutDurationSeconds
    'Custom banned list enabled'           = "$($lockout.CustomBannedListEnabled) ($($lockout.CustomBannedPasswordCount) entries)"
    'Global banned list'                   = 'Always enforced'
    'Security Defaults enabled'            = $secDef.isEnabled
    'Members - password never expires'     = ($members | Where-Object NeverExpiresFlag).Count
    'Members - strong password disabled'   = ($members | Where-Object StrongPasswordDisabled).Count
    'Members - password currently expired' = ($members | Where-Object CurrentlyExpired).Count
}
$summaryRows = $summary.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Setting = $_.Key; Value = $_.Value } }

$flagRef = @(
    [pscustomobject]@{ Flag='None';                      Meaning='User follows the domain expiration policy and Entra complexity rules' }
    [pscustomobject]@{ Flag='DisablePasswordExpiration'; Meaning='Password never expires for this user; overrides domain expiration policy' }
    [pscustomobject]@{ Flag='DisableStrongPassword';     Meaning='User may set passwords that do not meet Entra complexity requirements' }
    [pscustomobject]@{ Flag='Reference';                 Meaning='https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-policy' }
)

# --- Export single workbook ---
$xl = @{ Path = $OutputPath; AutoSize = $true; FreezeTopRow = $true; BoldTopRow = $true }
$summaryRows | Export-Excel @xl -WorksheetName 'Summary'
$orgInfo     | Export-Excel @xl -WorksheetName 'Tenant'
$domains     | Export-Excel @xl -WorksheetName 'Domains'
$lockout     | Export-Excel @xl -WorksheetName 'Lockout-Protection'
$users       | Export-Excel @xl -WorksheetName 'Users' -AutoFilter -TableName 'Users'
$flagRef     | Export-Excel @xl -WorksheetName 'Flag-Reference'

$summaryRows | Format-Table -AutoSize
Write-Host "Workbook: $OutputPath" -ForegroundColor Green
Disconnect-MgGraph | Out-Null
