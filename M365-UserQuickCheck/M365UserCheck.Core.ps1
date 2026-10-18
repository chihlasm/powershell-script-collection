# 5.1 because the Graph stage needs Microsoft.Graph.Authentication, which requires Windows
# PowerShell 5.1 (root CLAUDE.md, version floors). Tests\PSVersionFloor.Tests.ps1 guards it.
#Requires -Version 5.1

<#
.SYNOPSIS
    Shared logic for M365-UserQuickCheck: the Graph reads, the "could we see it?" gates, and
    the verdict for "can this user sign in to Microsoft 365?".
.DESCRIPTION
    Dot-sourced by Get-M365UserQuickCheck.ps1 (and by the tests) with -LoadFunctionsOnly.
    Nothing here writes to the console, a file or the clipboard.

    READ-ONLY. Every Graph call goes through Invoke-M365GraphGet, the single place that calls
    Invoke-MgGraphRequest, always with -Method GET. The scopes in $script:M365Scopes are all
    .Read / .Read.All scopes, so even a Global Administrator's token cannot write through this
    tool (Tests\Get-M365UserQuickCheck.Tests.ps1, AC3, checks both statically).

    THE GATES. Each data source reports Available / NotLicensed / NotAllowed / Failed /
    NotChecked with a plain-English reason. The verdict reads the gate, never an empty result:
    a tenant without Entra ID P1 returns no sign-in rows because it cannot, not because the
    user has no sign-in problems, so it never gets a YES (owner decision D-006: PROBABLY YES).

    Graph objects are hashtables (Invoke-MgGraphRequest -OutputType HashTable), so an absent
    property is told apart from a null one with Test-M365Prop. That matters for
    appliedConditionalAccessPolicies, which Graph OMITS for a role that cannot read
    Conditional Access data.

    ON-PREMISES AD (SQ-011). Get-M365OnPremisesFacts imports ActiveDirectory at run time and
    only calls Get-ADUser; the address-conflict lookups are GETs on /users, /groups and
    /contacts, and the cloud-user-by-SID lookup a GET on /users. Get-M365OnPremisesAssessment compares the result with the cloud user. No
    domain controller, or no module, is the 'On-premises AD' gate's reason, never a failure
    of the check (owner decision D-014).
.NOTES
    REFERENCES
      onPremisesProvisioningError: category (only value PropertyConflict), occurredDateTime,
      propertyCausingError, value
        https://learn.microsoft.com/graph/api/resources/onpremisesprovisioningerror?view=graph-rest-1.0
      user.onPremisesSecurityIdentifier: the on-premises SID of a synced user (needs $select);
      user.onPremisesProvisioningErrors: sync errors (needs $select)
        https://learn.microsoft.com/graph/api/resources/user?view=graph-rest-1.0
      organization.onPremisesLastSyncDateTime: when the tenant last synced with on-premises
      AD, UTC
        https://learn.microsoft.com/graph/api/resources/organization?view=graph-rest-1.0
      $filter mail eq and proxyAddresses/any(p:p eq ...) on groups and orgContacts, and
      userPrincipalName / mail / proxyAddresses on users: "works by default" (no
      ConsistencyLevel: eventual, no $count) in the property tables. onPremisesSecurityIdentifier
      eq on users: also "works by default" in the user table (Find-M365UserBySid)
        https://learn.microsoft.com/graph/aad-advanced-queries
      user.onPremisesSecurityIdentifier: "Supports $filter (eq including on null values)"
        https://learn.microsoft.com/graph/api/resources/user?view=graph-rest-1.0
      Get-ADUser default property set includes SID (the example output lists it)
        https://learn.microsoft.com/powershell/module/activedirectory/get-aduser
      List groups (GET /groups) and List orgContacts (GET /contacts): Directory.Read.All is
      among the delegated permissions
        https://learn.microsoft.com/graph/api/group-list?view=graph-rest-1.0
        https://learn.microsoft.com/graph/api/orgcontact-list?view=graph-rest-1.0
      Entra Connect Sync: "By default every 30 minutes a synchronization cycle is run"
        https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-feature-scheduler
      Get-ADUser: -Identity takes a DN, GUID, SID or SAM account name; -LDAPFilter, -Properties
      (beyond the default set), -Server, -Credential
        https://learn.microsoft.com/powershell/module/activedirectory/get-aduser
      Block marker msDS-cloudExtensionAttribute10 = BlockCloudSignIn: the BlockCloudSignIn
      rule in M365-SyncedUserFixes/SyncedUserFixes.Core.ps1:111-112
      List signIns: v1.0 returns interactive user sign-ins (and successful federated ones),
      newest first; only $top, $skiptoken and $filter are documented (no $select, so rows are
      trimmed after they arrive); AuditLog.Read.All; roles Global Reader, Reports Reader,
      Security Administrator, Security Operator, Security Reader;
      appliedConditionalAccessPolicies is OMITTED unless the role can read CA data (Global
      Reader, Security Administrator, Security Reader, Conditional Access Administrator) and the
      app holds Policy.Read.All, Policy.Read.ConditionalAccess or
      Policy.ReadWrite.ConditionalAccess
        https://learn.microsoft.com/graph/api/signin-list?view=graph-rest-1.0
      signIn: userId supports $filter (eq); createdDateTime supports $filter (eq, le, ge), UTC
        https://learn.microsoft.com/graph/api/resources/signin?view=graph-rest-1.0
      signInStatus: errorCode, failureReason, additionalDetails
        https://learn.microsoft.com/graph/api/resources/signinstatus?view=graph-rest-1.0
      appliedConditionalAccessPolicy.result: success, failure, notApplied, notEnabled, ...
        https://learn.microsoft.com/graph/api/resources/appliedconditionalaccesspolicy?view=graph-rest-1.0
      "Neither tenant is B2C or tenant doesn't have premium license"
      (Authentication_RequestFromNonPremiumTenantOrB2CTenant) = no Entra ID P1/P2; can also
      occur when the token lacks Directory.Read.All, which is why it is requested
        https://learn.microsoft.com/troubleshoot/entra/entra-id/users-groups-entra-apis/b2c-or-tenant-premium-license-sign-in-activities
        https://learn.microsoft.com/entra/identity/monitoring-health/howto-analyze-activity-logs-with-microsoft-graph
      Sign-in retention: Entra ID Free seven days, P1/P2 30 days
        https://learn.microsoft.com/entra/identity/monitoring-health/reference-reports-data-retention
      Sign-in logs in the admin center: Entra ID > Monitoring & health > Sign-in logs
        https://learn.microsoft.com/entra/identity/monitoring-health/concept-sign-ins
      Error codes 50053, 50055, 50057, 50126, 53003, 530035 (the next-step map below)
        https://learn.microsoft.com/entra/identity-platform/reference-error-codes
      user: accountEnabled, assignedLicenses, licenseAssignmentStates, onPremisesSyncEnabled,
      onPremisesSecurityIdentifier, proxyAddresses (SMTP = primary), userPrincipalName (its
      domain must be one of the tenant's verified domains), userType
        https://learn.microsoft.com/graph/api/resources/user?view=graph-rest-1.0
      licenseAssignmentState.state: Active, ActiveWithError, Disabled, Error; error values
      CountViolation, MutuallyExclusiveViolation, DependencyViolation,
      ProhibitedInUsageLocationViolation, UniquenessViolation, Other
        https://learn.microsoft.com/graph/api/resources/licenseassignmentstate?view=graph-rest-1.0
        https://learn.microsoft.com/entra/identity/users/licensing-groups-resolve-problems
      $filter on users by userPrincipalName eq, mail eq and proxyAddresses/any(p:p eq ...) each
      works by default (no ConsistencyLevel header); Learn does not say the same for an "or" of
      them, so they are separate requests. OData cast on transitiveMemberOf needs
      ConsistencyLevel: eventual and $count=true; transitiveMemberOf returns directory roles held
      directly or through a group; least privilege for /me is User.Read (Directory.Read.All
      covers it)
        https://learn.microsoft.com/graph/aad-advanced-queries
        https://learn.microsoft.com/graph/api/user-list-transitivememberof?view=graph-rest-1.0
      CSV cells starting with = + - @ are neutralised with a leading ' (CSV injection)
        https://owasp.org/www-community/attacks/CSV_Injection
      OData string literals: a single quote is escaped by doubling it
        https://learn.microsoft.com/graph/query-parameters
      List users / domains / organization / transitiveMemberOf: Directory.Read.All covers each
        https://learn.microsoft.com/graph/api/user-list?view=graph-rest-1.0
        https://learn.microsoft.com/graph/api/domain-list?view=graph-rest-1.0
        https://learn.microsoft.com/graph/api/organization-list?view=graph-rest-1.0
      organization: displayName, verifiedDomains, onPremisesLastSyncDateTime
        https://learn.microsoft.com/graph/api/resources/organization?view=graph-rest-1.0
      List authentication methods: UserAuthenticationMethod.Read.All; roles Global Reader,
      Authentication Administrator, Privileged Authentication Administrator
        https://learn.microsoft.com/graph/api/authentication-list-methods?view=graph-rest-1.0
      Which methods count for MFA (password: primary only; email OTP: SSPR; QR code: primary)
        https://learn.microsoft.com/entra/identity/authentication/concept-authentication-methods
      Get riskyUser: requires Entra ID P2; IdentityRiskyUser.Read.All; roles Global Reader,
      Security Operator, Security Reader, Security Administrator. "Microsoft Graph: all risk
      reports" is P2 only. riskLevel low/medium/high/hidden/none; riskState none,
      confirmedSafe, remediated, dismissed, atRisk, confirmedCompromised
        https://learn.microsoft.com/graph/api/riskyuser-get?view=graph-rest-1.0
        https://learn.microsoft.com/graph/api/resources/riskyuser?view=graph-rest-1.0
        https://learn.microsoft.com/entra/id-protection/overview-identity-protection#license-requirements

    NOT VERIFIED ON LEARN
      - Which error GET /identityProtection/riskyUsers/{id} returns in a tenant WITHOUT Entra ID
        P2. Learn only says the API "requires a Microsoft Entra ID P2 license". The non-premium
        code is classified as NotLicensed; any other 403 is reported as "needs Entra ID P2, or
        a role that can read it", because the two cannot be told apart from Learn.
      - That a user ID that was never flagged returns 404 from riskyUsers/{id}. Treated as
        "not flagged" (Available), never as a failure.
      - Whether the proxyAddresses/any(p:p eq 'smtp:...') comparison ignores case. The value
        is sent with a lower-case smtp: prefix, as in Find-M365User; mail eq is also sent, so
        an object whose mail is the address is found either way.
#>

[CmdletBinding()]
param(
    # Lets the entry script and the tests dot-source the functions without running anything.
    [switch]$LoadFunctionsOnly
)

# =============================================================================
# Documented constants
# =============================================================================

$script:M365GraphRoot = 'https://graph.microsoft.com/v1.0'

# Delegated, read-only. Directory.Read.All: users, /domains, /organization, /me/memberOf, and the
# tenant licence lookup the sign-in API needs (b2c-or-tenant-premium-license-sign-in-activities).
# AuditLog.Read.All: sign-ins. UserAuthenticationMethod.Read.All: MFA methods.
# IdentityRiskyUser.Read.All: risky user. Policy.Read.All: without it Graph omits
# appliedConditionalAccessPolicies from every sign-in row (signin-list), so the blocking policy
# could never be named. signin-list accepts Policy.Read.All, Policy.Read.ConditionalAccess or
# Policy.ReadWrite.ConditionalAccess; the narrower Policy.Read.ConditionalAccess would do, but
# it does not END in .Read / .Read.All, and the read-only rule (AC3: every scope matches
# \.Read(\.All)?$) is what lets a reviewer see at a glance that this token cannot write. So
# Policy.Read.All stays.
# https://learn.microsoft.com/graph/api/signin-list?view=graph-rest-1.0
$script:M365Scopes = @(
    'Directory.Read.All'
    'AuditLog.Read.All'
    'UserAuthenticationMethod.Read.All'
    'IdentityRiskyUser.Read.All'
    'Policy.Read.All'
)

# One page of the newest sign-ins is enough for a live ticket (signin-list returns newest first).
$script:M365SignInPageSize = 50

# signin-list troubleshooting: the error a tenant without Entra ID P1/P2 gets.
$script:M365NonPremiumCode = 'Authentication_RequestFromNonPremiumTenantOrB2CTenant'
$script:M365NonPremiumText = "Neither tenant is B2C or tenant doesn't have premium license"

# Built-in roles Learn lists as least privilege for each read (see REFERENCES).
$script:M365SignInReaderRoles = 'Reports Reader, Security Reader, Security Operator, Security Administrator or Global Reader'
$script:M365CaReaderRoles = 'Global Reader, Security Reader, Security Administrator or Conditional Access Administrator'
$script:M365MfaReaderRoles = 'Global Reader, Authentication Administrator or Privileged Authentication Administrator'
$script:M365RiskReaderRoles = 'Global Reader, Security Reader, Security Operator or Security Administrator'

# Sign-in failures that stop the user on their own (Blocker = NO). The meaning shown to the user
# is always the log's own failureReason; these codes only pick the next step.
# https://learn.microsoft.com/entra/identity-platform/reference-error-codes
$script:M365BlockingCodes = @(50053, 50057, 50055, 53003, 530035)
$script:M365MeaningLabel = 'meaning per Microsoft, may change'

# Methods that are not a second factor (concept-authentication-methods): a password is primary
# only, email OTP is for self-service password reset, a QR code is primary only.
$script:M365NonMfaMethodTypes = @(
    '#microsoft.graph.passwordAuthenticationMethod'
    '#microsoft.graph.emailAuthenticationMethod'
    '#microsoft.graph.qrCodePinAuthenticationMethod'
)

$script:M365GateStates = @('Available', 'NotLicensed', 'NotAllowed', 'Failed', 'NotChecked')

# Owner decision D-006: the headline on a tenant without Entra ID P1 when nothing else blocks.
$script:M365NoP1VerdictNote = 'sign-in history not available (no Entra ID P1)'

# Next step when sign-in history could not be read. Free tenants keep seven days of sign-ins in
# the admin center (reference-reports-data-retention); the path is from concept-sign-ins.
$script:M365NoSignInHistoryStep = 'Look at their recent sign-ins in the Microsoft Entra admin center (Entra ID > Monitoring & health > Sign-in logs, filtered to this user). A tenant without Entra ID P1 keeps seven days of sign-ins there.'

# --- On-premises AD stage (SQ-011) ---------------------------------------------------------

# The M365-SyncedUserFixes block marker. That tool writes this value to this attribute, and its
# Entra Connect rule either flows accountEnabled False or filters the user out of sync (the
# account is then deleted from Microsoft 365). Source: the BlockCloudSignIn rule definition,
# M365-SyncedUserFixes/SyncedUserFixes.Core.ps1:111-112 (SourceAttribute, MarkerValue).
# Compared case-sensitively, as written by that tool.
$script:M365BlockMarkerAttribute = 'msDS-cloudExtensionAttribute10'
$script:M365BlockMarkerValue = 'BlockCloudSignIn'

# What the AD stage reads (Get-ADUser -Properties). Enabled, UserPrincipalName,
# DistinguishedName, SamAccountName and SID are in the default set but are named so the request
# says what it needs. SID is looked up in Microsoft 365 when no cloud user has the sign-in name
# (AC20b). pwdLastSet is shown in the details table only.
# https://learn.microsoft.com/powershell/module/activedirectory/get-aduser
$script:M365AdUserProperties = @(
    'Enabled', 'UserPrincipalName', 'SamAccountName', 'DisplayName', 'DistinguishedName', 'SID',
    'mail', 'proxyAddresses', 'pwdLastSet', $script:M365BlockMarkerAttribute
)

# Could not check sources the on-premises stage adds besides its gate (AC22c, AC20b).
$script:M365AddressCheckSource = 'Address conflicts'
$script:M365SidCheckSource = 'Microsoft 365 account by SID'

# Next step when the address-conflict lookup failed (AC22c). A 403 there means the signed-in
# account cannot list groups or contacts (group-list, orgcontact-list: Directory.Read.All).
$script:M365AddressCheckStep = 'Run the check again. If it keeps failing, search the AD account''s sign-in name and email address in the Microsoft 365 admin center (users, groups and contacts) for another object that holds them, or run the check with an account that can read groups and contacts.'

# Owner decision (SQ-011 review, D-006 pattern): the headline when the address-conflict lookup
# failed and nothing else blocks.
$script:M365AddressCheckVerdictNote = 'could not check whether another Microsoft 365 object holds its addresses'

# Entra Connect Sync runs a sync cycle every 30 minutes by default
# (how-to-connect-sync-feature-scheduler). More than 3 hours (six missed cycles) is stale;
# exactly 3 hours is not.
# https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-feature-scheduler
$script:M365SyncIntervalText = 'every 30 minutes'
$script:M365StaleSyncHours = 3

# =============================================================================
# Small helpers (pure)
# =============================================================================

function Test-M365Prop {
    # True when the object HAS the property, even with a null value. Graph omits some
    # properties entirely (appliedConditionalAccessPolicies for a role that cannot read CA).
    param([object]$Object, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) { return $Object.Contains($Name) }
    return ($null -ne $Object.PSObject.Properties[$Name])
}

function Get-M365Prop {
    # The property's value from a hashtable or an object; $null when absent.
    param([object]$Object, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function ConvertTo-M365UtcTime {
    # Graph times are ISO 8601 UTC strings; depending on the SDK they may arrive as DateTime or
    # DateTimeOffset instead. Returns a UTC DateTime, or $null when missing or unreadable.
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    $parsed = [DateTimeOffset]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([DateTimeOffset]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed.UtcDateTime
    }
    return $null
}

function Format-M365Time {
    # Always UTC and labelled: a ticket is often read later, in another time zone, and Graph
    # records UTC.
    param([object]$When)
    if ($null -eq $When) { return 'unknown time' }
    return ('{0} UTC' -f ([datetime]$When).ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture))
}

function ConvertTo-M365ODataLiteral {
    # OData string literal: wrap in single quotes, double any quote inside (o'brien -> 'o''brien').
    param([AllowEmptyString()][string]$Value)
    return ("'" + $Value.Replace("'", "''") + "'")
}

function ConvertTo-M365SafeText {
    # IP addresses out of text that leaves the local HTML (CSV). Uses the ticket-note kit's
    # redaction when it is loaded; otherwise a plain IPv4 / IPv6 replacement.
    param([AllowEmptyString()][AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return [string]$Text }
    if (Get-Command -Name Protect-TicketNoteText -CommandType Function -ErrorAction SilentlyContinue) {
        return (Protect-TicketNoteText -Line $Text)
    }
    $t = [regex]::Replace($Text, '(?<![\w.])\d{1,3}(\.\d{1,3}){3}(?![\w]|\.\d)', '[IP removed]')
    # IPv6 candidates are confirmed by IPAddress.TryParse, so a time such as 09:30:12 is kept.
    return [regex]::Replace($t, '(?<![\w:])[0-9A-Fa-f]{0,4}(:[0-9A-Fa-f]{0,4}){2,7}(?![\w:])', {
            param($m)
            $ip = $null
            if ([System.Net.IPAddress]::TryParse($m.Value, [ref]$ip) -and $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { '[IP removed]' } else { $m.Value }
        })
}

function ConvertTo-M365CsvValue {
    <#
    .SYNOPSIS
        One CSV cell: IP addresses removed (ConvertTo-M365SafeText), and a value that starts
        with = + - @, a tab or a carriage return prefixed with ' so a spreadsheet shows it as
        text instead of running it as a formula. Display names and failure reasons come from
        the client's tenant, so they are untrusted.
        https://owasp.org/www-community/attacks/CSV_Injection
    #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    $t = ConvertTo-M365SafeText -Text $Text
    if (-not [string]::IsNullOrEmpty($t) -and $t -match "^[=+\-@`t`r]") { return ("'" + $t) }
    return $t
}

function Select-M365SignInFields {
    <#
    .SYNOPSIS
        A sign-in row cut down to what the verdict and the report use: time, app, client app,
        status, Conditional Access results, city and country, and the IP address (local HTML
        report only). Device details, user agent and the rest are dropped on arrival.
    .DESCRIPTION
        appliedConditionalAccessPolicies is copied only when the row HAS it: its absence means
        the signed-in account cannot read Conditional Access data (signin-list), and that must
        survive the trim (Get-M365ConditionalAccessGate).
    #>
    param([Parameter(Mandatory = $true)][object]$Row)
    $status = Get-M365Prop -Object $Row -Name 'status'
    $loc = Get-M365Prop -Object $Row -Name 'location'
    $out = @{
        id = Get-M365Prop -Object $Row -Name 'id'
        createdDateTime = Get-M365Prop -Object $Row -Name 'createdDateTime'
        appDisplayName = Get-M365Prop -Object $Row -Name 'appDisplayName'
        clientAppUsed = Get-M365Prop -Object $Row -Name 'clientAppUsed'
        ipAddress = Get-M365Prop -Object $Row -Name 'ipAddress'
        status = @{
            errorCode = Get-M365Prop -Object $status -Name 'errorCode'
            failureReason = Get-M365Prop -Object $status -Name 'failureReason'
            additionalDetails = Get-M365Prop -Object $status -Name 'additionalDetails'
        }
        location = @{
            city = Get-M365Prop -Object $loc -Name 'city'
            countryOrRegion = Get-M365Prop -Object $loc -Name 'countryOrRegion'
        }
    }
    if (Test-M365Prop -Object $Row -Name 'appliedConditionalAccessPolicies') {
        $out['appliedConditionalAccessPolicies'] = @(@(Get-M365Prop -Object $Row -Name 'appliedConditionalAccessPolicies') | Where-Object { $null -ne $_ } | ForEach-Object {
                @{ id = Get-M365Prop -Object $_ -Name 'id'; displayName = Get-M365Prop -Object $_ -Name 'displayName'; result = Get-M365Prop -Object $_ -Name 'result' }
            })
    }
    return $out
}

# =============================================================================
# Gates (pure)
# =============================================================================

function New-M365Gate {
    <#
    .SYNOPSIS
        One data source and whether this run could read it.
    .DESCRIPTION
        Source is the display name used on the banner and in Could not check: 'Sign-in history',
        'Conditional Access detail', 'MFA methods', 'Risky user', 'On-premises AD'.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][ValidateSet('Available', 'NotLicensed', 'NotAllowed', 'Failed', 'NotChecked')][string]$State,
        [string]$Reason = ''
    )
    return [PSCustomObject]@{ Source = $Source; State = $State; Reason = $Reason }
}

function Get-M365ErrorText {
    # The text to classify: the exception message plus the response body. Invoke-MgGraphRequest
    # can carry the JSON error body in ErrorDetails rather than in the message.
    param([Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord)
    $parts = @([string]$ErrorRecord.Exception.Message)
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) { $parts += [string]$ErrorRecord.ErrorDetails.Message }
    return (($parts | Where-Object { $_ }) -join ' ')
}

function Get-M365GraphErrorCode {
    # "code" from a Graph JSON error body ({"error":{"code":"..."}}), or ''.
    param([AllowEmptyString()][string]$Message)
    $m = [regex]::Match([string]$Message, '"code"\s*:\s*"(?<c>[^"]+)"')
    if ($m.Success) { return $m.Groups['c'].Value }
    return ''
}

function Get-M365ErrorSummary {
    # A short, readable form of a Graph error for a "could not check" reason.
    param([AllowEmptyString()][string]$Message)
    $m = [regex]::Match([string]$Message, '"message"\s*:\s*"(?<m>[^"]+)"')
    $text = if ($m.Success) { $m.Groups['m'].Value } else { ([string]$Message -split '\r?\n')[0] }
    $text = $text.Trim()
    if ($text.Length -gt 200) { $text = $text.Substring(0, 200) + '...' }
    return $text
}

function Get-M365GateFromError {
    <#
    .SYNOPSIS
        Classifies a failed Graph read into a gate with a plain-English reason.
    .DESCRIPTION
        The non-premium error code (or its message text) is NotLicensed. A 403 is NotAllowed,
        with the roles that can read the source. For 'Risky user' a 404 means the user was
        never flagged, which is Available. Anything else is Failed.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [AllowEmptyString()][string]$Message
    )
    $msg = [string]$Message
    $code = Get-M365GraphErrorCode -Message $msg
    $nonPremium = ($code -eq $script:M365NonPremiumCode) -or ($msg -match [regex]::Escape($script:M365NonPremiumCode)) -or
        ($msg -match [regex]::Escape($script:M365NonPremiumText))
    $forbidden = ($msg -match '\bForbidden\b|\b403\b')
    $notFound = ($msg -match '\bNotFound\b|Not Found|\b404\b') -or ($code -eq 'Request_ResourceNotFound')

    switch ($Source) {
        'Sign-in history' {
            if ($nonPremium) { return (New-M365Gate -Source $Source -State NotLicensed -Reason 'this tenant has no Entra ID P1') }
            if ($forbidden) {
                return (New-M365Gate -Source $Source -State NotAllowed -Reason ("the signed-in account is not allowed to read sign-in history; that needs one of these roles: {0}, and consent to AuditLog.Read.All" -f $script:M365SignInReaderRoles))
            }
        }
        'Risky user' {
            if ($nonPremium) { return (New-M365Gate -Source $Source -State NotLicensed -Reason 'needs Entra ID P2') }
            if ($notFound) { return (New-M365Gate -Source $Source -State Available -Reason 'not flagged') }
            if ($forbidden) {
                # Learn does not say which error a tenant without P2 gets here, so a 403 can mean
                # either cause. Say both rather than guess.
                return (New-M365Gate -Source $Source -State NotAllowed -Reason ("needs Entra ID P2, and the signed-in account needs one of these roles: {0}; Microsoft returned 'not allowed' without saying which is missing" -f $script:M365RiskReaderRoles))
            }
        }
        'MFA methods' {
            if ($forbidden) {
                return (New-M365Gate -Source $Source -State NotAllowed -Reason ("the signed-in account cannot read authentication methods; that needs one of these roles: {0}" -f $script:M365MfaReaderRoles))
            }
        }
        default {
            if ($nonPremium) { return (New-M365Gate -Source $Source -State NotLicensed -Reason 'needs an Entra ID premium licence') }
            if ($forbidden) { return (New-M365Gate -Source $Source -State NotAllowed -Reason 'the signed-in account is not allowed to read it') }
        }
    }
    $summary = Get-M365ErrorSummary -Message $msg
    return (New-M365Gate -Source $Source -State Failed -Reason ("the request failed: {0}" -f $(if ($summary) { $summary } else { 'no error text' })))
}

function Format-M365SourceLine {
    # One banner line: "<Source>: available" or "<Source>: not available (<Reason>)".
    # On-premises AD reads "could not check (<Reason>)" instead: it is not a licence or a role
    # that is missing but a domain controller this computer could not reach (D-014).
    param([Parameter(Mandatory = $true)][object]$Gate)
    if ($Gate.State -eq 'Available') { return ('{0}: available' -f $Gate.Source) }
    $reason = if ($Gate.Reason) { $Gate.Reason } else { 'no reason given' }
    if ($Gate.Source -eq 'On-premises AD') { return ('{0}: could not check ({1})' -f $Gate.Source, $reason) }
    return ('{0}: not available ({1})' -f $Gate.Source, $reason)
}

function Format-M365CouldNotCheckLine {
    # One "Could not check" line: "<Source>: <Reason>", or for on-premises AD the same
    # "On-premises AD: could not check (<Reason>)" as the banner.
    param([Parameter(Mandatory = $true)][object]$Item)
    if ($Item.Source -eq 'On-premises AD') { return ('{0}: could not check ({1})' -f $Item.Source, $Item.Reason) }
    return ('{0}: {1}' -f $Item.Source, $Item.Reason)
}

function Get-M365ConditionalAccessGate {
    <#
    .SYNOPSIS
        Could this run see which Conditional Access policies applied?
    .DESCRIPTION
        Graph omits appliedConditionalAccessPolicies (the property, not just its value) when the
        signed-in role or the app cannot read CA data (signin-list). So: Available when at least
        one row carries the property, even as an empty list; NotAllowed when rows came back
        without it; Failed when there were no rows to read it from.
    #>
    param([object[]]$SignIns = @())
    $rows = @($SignIns | Where-Object { $null -ne $_ })
    $source = 'Conditional Access detail'
    if ($rows.Count -eq 0) {
        return (New-M365Gate -Source $source -State Failed -Reason 'no sign-ins in the window to read it from')
    }
    $withCa = @($rows | Where-Object { Test-M365Prop -Object $_ -Name 'appliedConditionalAccessPolicies' })
    if ($withCa.Count -gt 0) { return (New-M365Gate -Source $source -State Available) }
    return (New-M365Gate -Source $source -State NotAllowed -Reason ("the signed-in account's role cannot read which policies applied; that needs one of these roles: {0}" -f $script:M365CaReaderRoles))
}

# =============================================================================
# Assessment (pure)
# =============================================================================

function Test-M365UserSynced {
    # onPremisesSyncEnabled true = synced from on-premises AD; null, false or absent = cloud-only.
    param([object]$User)
    return ((Get-M365Prop -Object $User -Name 'onPremisesSyncEnabled') -eq $true)
}

function Test-M365BlockMarker {
    # True when the AD account carries the M365-SyncedUserFixes block marker.
    param([object]$AdUser)
    return ([string](Get-M365Prop -Object $AdUser -Name $script:M365BlockMarkerAttribute) -ceq $script:M365BlockMarkerValue)
}

function Get-M365PrimarySmtp {
    # The primary SMTP address: the proxyAddresses entry with the upper-case SMTP: prefix (user
    # resource, proxyAddresses), else mail. '' when neither is set.
    param([object]$Object)
    $primary = @(@(Get-M365Prop -Object $Object -Name 'proxyAddresses') | Where-Object { [string]$_ -cmatch '^SMTP:.' } | Select-Object -First 1)
    if ($primary.Count -gt 0) { return ([string]$primary[0]).Substring(5) }
    return [string](Get-M365Prop -Object $Object -Name 'mail')
}

function Format-M365Age {
    # "45 minutes", "4 hours", "3 days": whole units, rounded down.
    param([Parameter(Mandatory = $true)][TimeSpan]$Span)
    if ($Span.TotalHours -lt 1) { $n = [int][math]::Floor($Span.TotalMinutes); $unit = 'minute' }
    elseif ($Span.TotalHours -lt 48) { $n = [int][math]::Floor($Span.TotalHours); $unit = 'hour' }
    else { $n = [int][math]::Floor($Span.TotalDays); $unit = 'day' }
    return ('{0} {1}{2}' -f $n, $unit, $(if ($n -eq 1) { '' } else { 's' }))
}

function Get-M365OnPremisesAssessment {
    <#
    .SYNOPSIS
        The on-premises AD comparison part of the assessment (AC19-AC25), for
        Get-M365UserAssessment.
    .DESCRIPTION
        Reads the cloud user's provisioning errors (Graph data, so checked whatever the AD gate
        says), the tenant's last sync time (for synced users and for "no cloud user"), and,
        only when the On-premises AD gate is Available, the AD account and the address
        conflicts found in Microsoft 365.

        Returns { Reasons; Cleared; BlockedAction }: Reasons and Cleared in the assessment's
        shapes, and BlockedAction, the SignInBlocked next step to use when the AD account
        explains the block ($null keeps the default one).
    #>
    param([Parameter(Mandatory = $true)][object]$Facts)
    $reasons = New-Object System.Collections.Generic.List[object]
    $cleared = New-Object System.Collections.Generic.List[object]
    function Add-Reason($Level, $Code, $Message, $Action) {
        $reasons.Add([PSCustomObject]@{ Level = $Level; Code = $Code; Message = $Message; Action = $Action })
    }
    function Add-Pass($Code, $Message) {
        $cleared.Add([PSCustomObject]@{ Code = $Code; Message = $Message; CouldLook = $true })
    }
    function Add-AddressConflictReasons {
        # AC22: one Blocker per other object holding the AD account's UPN or primary SMTP address.
        # A failed lookup (AddressCheckError) is not a reason: Get-M365UserAssessment lists it
        # under Could not check and hedges the verdict (AC22c).
        $typeNames = @{ user = 'a cloud-only user'; group = 'a group'; contact = 'a contact' }
        foreach ($c in @(@(Get-M365Prop -Object $Facts -Name 'AddressConflicts') | Where-Object { $null -ne $_ })) {
            $type = [string](Get-M365Prop -Object $c -Name 'Type')
            $label = if ($typeNames.ContainsKey($type)) { $typeNames[$type] } else { "an object ($type)" }
            Add-Reason 'Blocker' 'AddressHeld' ("The address {0} is already held in Microsoft 365 by {1}, '{2}', so sync cannot give it to this account." -f `
                    [string](Get-M365Prop -Object $c -Name 'Address'), $label, [string](Get-M365Prop -Object $c -Name 'DisplayName')) `
                'Find that object in the Microsoft 365 admin center and remove the address from it (or delete it if it is a leftover copy), then wait for the next sync. Ask the senior engineer if you are not sure which one is right.'
        }
    }
    function New-Result($BlockedAction) {
        [PSCustomObject]@{ Reasons = $reasons.ToArray(); Cleared = $cleared.ToArray(); BlockedAction = $BlockedAction }
    }

    $user = $Facts.User
    $synced = Test-M365UserSynced -User $user
    $gate = Get-M365Prop -Object $Facts -Name 'OnPremisesGate'
    $adAvailable = ($null -ne $gate -and $gate.State -eq 'Available')
    $adUser = if ($adAvailable) { Get-M365Prop -Object $Facts -Name 'AdUser' } else { $null }
    $marker = Test-M365BlockMarker -AdUser $adUser
    $nowUtc = ConvertTo-M365UtcTime -Value $Facts.Now
    if (-not $nowUtc) { $nowUtc = [datetime]::UtcNow }
    $lastSync = ConvertTo-M365UtcTime -Value (Get-M365Prop -Object $Facts -Name 'TenantLastSync')
    $lastSyncText = if ($lastSync) { "The tenant last received changes from on-premises AD at $(Format-M365Time $lastSync)." } else { "The tenant's last sync time is not known." }
    $blockedAction = $null

    # --- No Microsoft 365 user, but an AD account (AC20) -------------------------------------
    # Get-M365OnPremisesFacts has already searched Microsoft 365 for the AD account's SID
    # (AC20b); a cloud user found that way is assessed instead, so it never reaches here. When
    # that search failed (CloudSidCheckError), a cloud account under another name cannot be
    # ruled out: PROBABLY NOT, never NO.
    if ($null -eq $user) {
        if ($adAvailable -and $null -ne $adUser) {
            $adUpn = [string](Get-M365Prop -Object $adUser -Name 'UserPrincipalName')
            $sidErr = [string](Get-M365Prop -Object $Facts -Name 'CloudSidCheckError')
            $level = if ($sidErr) { 'Probable' } else { 'Blocker' }
            $hedge = if ($sidErr) { ' Microsoft 365 could not be searched for its security identifier (SID), so a Microsoft 365 account it syncs to under another name is not ruled out.' } else { '' }
            if ($marker) {
                Add-Reason $level 'NeverSynced' (("This account exists in AD but not in Microsoft 365: it was removed from Microsoft 365 on purpose by M365-SyncedUserFixes (its AD account carries the block marker {0} = {1})." -f $script:M365BlockMarkerAttribute, $script:M365BlockMarkerValue) + $hedge) `
                    'If they should have Microsoft 365 again, remove the marker with M365-SyncedUserFixes and wait for the next sync. Their old mailbox and licences may already be gone; check with the senior engineer first.'
            } else {
                Add-Reason $level 'NeverSynced' (("This account exists in AD but not in Microsoft 365 (AD sign-in name {0}, in {1}). It has never synced, or it is no longer synced." -f $adUpn, [string](Get-M365Prop -Object $adUser -Name 'DistinguishedName')) + $hedge) `
                    'Check the sync scope: is the account in an OU that Entra Connect synchronizes (OU filtering), and is it excluded by a filtering rule? Then check on the Entra Connect server that sync is running and shows no export error for this account.'
            }
        }
    }

    # --- Provisioning errors on the cloud user (AC21) -----------------------------------------
    # onPremisesProvisioningError: category (PropertyConflict), propertyCausingError, value.
    # https://learn.microsoft.com/graph/api/resources/onpremisesprovisioningerror?view=graph-rest-1.0
    foreach ($e in @(@(Get-M365Prop -Object $user -Name 'onPremisesProvisioningErrors') | Where-Object { $null -ne $_ })) {
        $when = ConvertTo-M365UtcTime -Value (Get-M365Prop -Object $e -Name 'occurredDateTime')
        Add-Reason 'Blocker' 'ProvisioningError' ("Sync reports an error for this account: {0} on {1}, value '{2}'{3}. Changes from on-premises AD are not reaching Microsoft 365 for it." -f `
                [string](Get-M365Prop -Object $e -Name 'category'), [string](Get-M365Prop -Object $e -Name 'propertyCausingError'), [string](Get-M365Prop -Object $e -Name 'value'), $(if ($when) { " (since $(Format-M365Time $when))" } else { '' })) `
            'Another object already uses that value. Find it (Microsoft 365 admin center, or search the address in Exchange), remove or change the value on the wrong object, then wait for the next sync.'
    }

    # --- Tenant sync freshness (AC24), only where sync is involved -----------------------------
    if (($synced -or $null -eq $user) -and $lastSync) {
        $age = $nowUtc - $lastSync
        if ($age.TotalHours -gt $script:M365StaleSyncHours) {
            Add-Reason 'Warning' 'StaleTenantSync' ("Microsoft 365 last received changes from on-premises AD {0} ago (at {1})." -f (Format-M365Age -Span $age), (Format-M365Time $lastSync)) `
                "Sync normally runs $script:M365SyncIntervalText, so changes made in AD since then (enabling, unlocking, a new password) have not arrived. Check the Entra Connect server: is the sync service running and is the scheduler enabled?"
        } else {
            Add-Pass 'TenantSyncRecent' ('Sync from on-premises AD is running: last sync at {0}.' -f (Format-M365Time $lastSync))
        }
    }

    if (-not $adAvailable -or $null -eq $user) {
        if ($adAvailable) { Add-AddressConflictReasons }
        return (New-Result $blockedAction)
    }

    # --- Cloud-only user (AC19) ------------------------------------------------------------
    if (-not $synced) {
        if ($null -eq $adUser) {
            Add-Pass 'CloudOnly' 'Cloud-only account: sync is not involved.'
        } else {
            Add-Reason 'Warning' 'AdAccountNotSynced' ("This Microsoft 365 account is cloud-only, but an on-premises AD account has the same sign-in name ({0}). They are two separate accounts: a password change in AD does not reach this one." -f [string](Get-M365Prop -Object $adUser -Name 'UserPrincipalName')) `
                'Make sure the user signs in to Microsoft 365 with the cloud password. If the two should be one account, ask the senior engineer about matching them in Entra Connect.'
        }
        return (New-Result $blockedAction)
    }

    # --- Synced user: compare with the AD account ------------------------------------------
    if ($null -eq $adUser) {
        Add-Reason 'Warning' 'AdAccountNotFound' 'This account syncs from on-premises AD, but no AD account with its security identifier (SID) or sign-in name was found in the domain checked.' `
            'It may be in another domain or forest: run the check again with -Server <domain controller of that domain>. If it was deleted from AD, ask the senior engineer before anything else is changed.'
        return (New-Result $blockedAction)
    }

    $cloudEnabled = Get-M365Prop -Object $user -Name 'accountEnabled'
    $adEnabled = Get-M365Prop -Object $adUser -Name 'Enabled'
    if ($cloudEnabled -eq $false) {
        if ($marker) {
            Add-Reason 'Info' 'BlockedOnPurpose' ("Sign-in was blocked on purpose with M365-SyncedUserFixes: the AD account carries the block marker {0} = {1}." -f $script:M365BlockMarkerAttribute, $script:M365BlockMarkerValue) `
                'Ask who blocked it and why before changing anything (a leaver, a security incident).'
            $blockedAction = 'It was blocked on purpose with M365-SyncedUserFixes (block marker on the AD account). If that is wrong, remove the marker with M365-SyncedUserFixes, then wait for the next sync.'
        } elseif ($adEnabled -eq $false) {
            $blockedAction = 'The on-premises AD account is disabled, and sync carries that to Microsoft 365. If it should be in use, enable it in AD (AD-UserQuickCheck shows its state), then wait for the next sync.'
        } elseif ($adEnabled -eq $true) {
            Add-Reason 'Probable' 'AdEnabledMismatch' 'On-premises AD has this account enabled, but Microsoft 365 has sign-in blocked: AD and Microsoft 365 disagree.' `
                ("$lastSyncText If the AD account was enabled after that, wait for the next sync (normally $script:M365SyncIntervalText). If it stays blocked, check the Entra Connect server for a sync rule or an export error for this account.")
            $blockedAction = 'On-premises AD has the account enabled and without the M365-SyncedUserFixes block marker, so the block has not come from AD this sync: see "AD and Microsoft 365 disagree".'
        }
    } elseif ($cloudEnabled -eq $true -and $adEnabled -eq $false) {
        Add-Reason 'Warning' 'AdDisabledCloudEnabled' 'On-premises AD has this account disabled, but Microsoft 365 still allows sign-in: AD and Microsoft 365 disagree, and sync normally carries the AD state across.' `
            ("$lastSyncText If they should be able to sign in, enable the AD account (AD-UserQuickCheck shows its state).")
    }

    # --- UPN mismatch (AC25) -----------------------------------------------------------------
    $cloudUpn = [string](Get-M365Prop -Object $user -Name 'userPrincipalName')
    $adUpn = [string](Get-M365Prop -Object $adUser -Name 'UserPrincipalName')
    if ($adUpn -and $cloudUpn -and $adUpn -ne $cloudUpn) {
        Add-Reason 'Warning' 'UpnMismatch' ("The sign-in name differs: on-premises AD has {0}, Microsoft 365 has {1}." -f $adUpn, $cloudUpn) `
            ('They sign in to Microsoft 365 as {0}. If AD was changed recently, wait for the next sync; if it stays different, check that the AD sign-in name uses a domain verified in this tenant, then ask the senior engineer to look at the Entra Connect server.' -f $cloudUpn)
    }

    # --- SID mismatch (AC25b) ----------------------------------------------------------------
    # Found by sign-in name although Microsoft 365 holds an on-premises SID: the SID lookup found
    # nothing, so this AD account has a different SID and is probably not the one the cloud user
    # was synced from (an account deleted and created again gets a new SID). Nothing to compare
    # when Microsoft 365 holds no SID.
    $cloudSid = [string](Get-M365Prop -Object $user -Name 'onPremisesSecurityIdentifier')
    if ($cloudSid -and (Get-M365Prop -Object $Facts -Name 'AdMatchedBy') -ne 'SID') {
        $adSid = [string](Get-M365Prop -Object $adUser -Name 'SID')
        Add-Reason 'Warning' 'SidMismatch' ("AD account found by sign-in name, but its SID differs from the one Microsoft 365 holds (recreated account?). Microsoft 365 holds {0}{1}." -f $cloudSid, $(if ($adSid) { "; the AD account $([string](Get-M365Prop -Object $adUser -Name 'DistinguishedName')) has $adSid" } else { '' })) `
            'This AD account is probably not the one this Microsoft 365 account was synced from, so the comparison with it may not apply and changes to it may not reach Microsoft 365. Ask the senior engineer to check on the Entra Connect server which AD account this Microsoft 365 account is joined to before changing either one.'
    }

    Add-AddressConflictReasons
    if (@($reasons | Where-Object { $_.Code -in 'AdEnabledMismatch', 'UpnMismatch', 'AdDisabledCloudEnabled', 'SidMismatch' }).Count -eq 0) {
        Add-Pass 'AdAgrees' ('On-premises AD account found (matched by {0}) and agrees with Microsoft 365 on enabled state and sign-in name.' -f $(if ((Get-M365Prop -Object $Facts -Name 'AdMatchedBy') -eq 'SID') { 'security identifier' } else { 'sign-in name' }))
    }
    return (New-Result $blockedAction)
}

function Get-M365LookupLink {
    # Microsoft's live lookup for a sign-in error code.
    param([Parameter(Mandatory = $true)][object]$Code)
    return ('https://login.microsoftonline.com/error?code={0}' -f $Code)
}

function Get-M365SignInNextStep {
    <#
    .SYNOPSIS
        The next step for the six mapped sign-in error codes, or $null for any other code.
    .DESCRIPTION
        Built from the code's entry on reference-error-codes. The meaning shown to the tech is the
        log's failureReason; this only says what to do. Not a cached meaning table: an unmapped
        code gets no next step from the tool, only Microsoft's text and the lookup link.
        https://learn.microsoft.com/entra/identity-platform/reference-error-codes
    #>
    param([Parameter(Mandatory = $true)][int]$Code, [bool]$Synced = $false)
    switch ($Code) {
        50053 { return 'Microsoft gives two causes for this code: the account is locked after too many wrong passwords, or the sign-in came from an IP address with malicious activity. Open the failed sign-in in the Microsoft Entra admin center (Monitoring & health > Sign-in logs) and read its Failure reason to see which. If it is a lockout that keeps coming back, look for a phone or app still trying an old password.' }
        50057 {
            if ($Synced) { return 'The account is disabled. It syncs from on-premises AD, so check the AD account (AD-UserQuickCheck) and enable it there if it should be in use, then wait for the next sync.' }
            return 'The account is disabled. Check with their manager that it should be in use, then unblock sign-in for the user in the Microsoft 365 admin center.'
        }
        50055 {
            if ($Synced) { return 'The password has expired. The account syncs from on-premises AD, so check the AD password with AD-UserQuickCheck and have them change it, or reset it, in AD.' }
            return 'The password has expired. They can change it when the sign-in page offers, or an admin can reset it in the Microsoft 365 admin center. Get-EntraPasswordPolicy shows the cloud password policy.'
        }
        50126 {
            if ($Synced) { return 'Wrong user name or password (Microsoft expects some of these from typing mistakes). Confirm they are typing the right sign-in name and password; if they cannot remember it, reset it in on-premises AD, where this account comes from.' }
            return 'Wrong user name or password (Microsoft expects some of these from typing mistakes). Confirm they are typing the right sign-in name and password; if they cannot remember it, reset it in the Microsoft 365 admin center.'
        }
        53003 { return 'Conditional Access blocked the sign-in. Check the policy that applied (Microsoft Entra admin center > Conditional Access), or ask the client''s admin whether it should apply to this user, device or location.' }
        530035 { return 'Security defaults blocked the sign-in, usually because the app uses legacy authentication or the sign-in was judged unsafe. Have them use a current Outlook, Teams or a browser instead of an old mail app, or ask the client''s admin about security defaults.' }
        default { return $null }
    }
}

function Get-M365SignInRows {
    # The sign-in rows newest first, each with its parsed UTC time and error code.
    param([object[]]$SignIns = @())
    $rows = foreach ($s in @($SignIns | Where-Object { $null -ne $_ })) {
        $status = Get-M365Prop -Object $s -Name 'status'
        $codeRaw = Get-M365Prop -Object $status -Name 'errorCode'
        $code = 0
        if ($null -ne $codeRaw) { try { $code = [int]$codeRaw } catch { $code = -1 } }
        [PSCustomObject]@{
            Row = $s
            Time = ConvertTo-M365UtcTime -Value (Get-M365Prop -Object $s -Name 'createdDateTime')
            Code = $code
            FailureReason = [string](Get-M365Prop -Object $status -Name 'failureReason')
            App = [string](Get-M365Prop -Object $s -Name 'appDisplayName')
        }
    }
    return @($rows | Sort-Object -Property @{ Expression = { if ($_.Time) { $_.Time } else { [datetime]::MinValue } } } -Descending)
}

function Get-M365UserAssessment {
    <#
    .SYNOPSIS
        Turns the collected facts into a verdict plus plain-English reasons.
    .DESCRIPTION
        Same scale as AD-UserQuickCheck: Blocker -> NO, Probable -> PROBABLY NOT, Warning and Info
        never change the verdict. With neither, the answer is YES only when sign-in history was
        readable and the address-conflict lookup did not fail; otherwise PROBABLY YES with
        VerdictNote (owner decision D-006, and the SQ-011 review for the address lookup).

        Only the most recent sign-in decides: an older typo must not turn into NO. Older
        failures are summarised as Info by code and count.

        Passes are the strings shown under "Looks fine". Cleared holds the same checks as
        { Code; Message; CouldLook } for the ticket note. CouldNotCheck lists every gate that was
        not Available, with its reason. Nothing is ever cleared from a source that could not be
        read.

        Facts: User; SignInGate; ConditionalAccessGate; MfaGate; RiskGate; SignIns; MfaMethods;
        RiskyUser; Days; Now; and, from the on-premises AD stage (all optional, absent means
        not collected): OnPremisesGate; AdUser; AdMatchedBy; AddressConflicts;
        AddressCheckError; CloudSidCheckError; TenantLastSync. The AD facts are used only when
        OnPremisesGate is Available (Get-M365OnPremisesAssessment). AddressCheckError and
        CloudSidCheckError each add a Could not check entry ('Address conflicts',
        'Microsoft 365 account by SID').

        User may be $null when no Microsoft 365 user matched but an AD account did (AC20); the
        other gates are then NotChecked and add nothing. The entry script only assesses that
        case when the AD account was found.
    #>
    param([Parameter(Mandatory = $true)][object]$Facts)

    $reasons = New-Object System.Collections.Generic.List[object]
    $passes = New-Object System.Collections.Generic.List[string]
    $cleared = New-Object System.Collections.Generic.List[object]
    function Add-Reason($Level, $Code, $Message, $Action) {
        $reasons.Add([PSCustomObject]@{ Level = $Level; Code = $Code; Message = $Message; Action = $Action })
    }
    function Add-Pass($Code, $Message) {
        $passes.Add($Message)
        $cleared.Add([PSCustomObject]@{ Code = $Code; Message = $Message; CouldLook = $true })
    }

    $user = $Facts.User
    $synced = Test-M365UserSynced -User $user
    $days = if ($Facts.Days) { [int]$Facts.Days } else { 7 }
    # The on-premises comparison first: what it found in AD can explain a cloud block.
    $onPrem = Get-M365OnPremisesAssessment -Facts $Facts

    # --- Account blocked -------------------------------------------------------------------
    # accountEnabled false = sign-in blocked (user resource).
    if ((Get-M365Prop -Object $user -Name 'accountEnabled') -eq $false) {
        if ($synced -and $onPrem.BlockedAction) {
            $action = $onPrem.BlockedAction
        } elseif ($synced) {
            $action = 'This account syncs from on-premises AD, so the block comes from there: check whether the AD account is disabled (AD-UserQuickCheck), or whether it carries the M365-SyncedUserFixes block marker (msDS-cloudExtensionAttribute10 = BlockCloudSignIn). Change it in on-premises AD if it is wrong, then wait for the next sync.'
        } else {
            $action = 'Check with their manager that the account should be in use, then unblock sign-in for the user in the Microsoft 365 admin center.'
        }
        Add-Reason 'Blocker' 'SignInBlocked' 'Sign-in is blocked for this account in Microsoft 365.' $action
    } elseif (Test-M365Prop -Object $user -Name 'accountEnabled') {
        Add-Pass 'AccountEnabled' 'Account is turned on in Microsoft 365 (not blocked).'
    }

    # --- Licence ---------------------------------------------------------------------------
    if (Test-M365Prop -Object $user -Name 'assignedLicenses') {
        $assigned = @(Get-M365Prop -Object $user -Name 'assignedLicenses' | Where-Object { $null -ne $_ })
        $states = @(Get-M365Prop -Object $user -Name 'licenseAssignmentStates' | Where-Object { $null -ne $_ })
        $errors = @($states | Where-Object { [string](Get-M365Prop -Object $_ -Name 'state') -eq 'Error' })
        if ($assigned.Count -eq 0 -and $errors.Count -eq 0) {
            Add-Reason 'Probable' 'NoLicence' 'No licence is assigned to this account, so Microsoft 365 apps such as Outlook, Teams and OneDrive will not let them in.' `
                'If they should have one, assign the right licence (directly or through a licensing group) in the Microsoft 365 admin center.'
        } elseif ($errors.Count -gt 0) {
            $detail = ($errors | ForEach-Object {
                    $err = [string](Get-M365Prop -Object $_ -Name 'error')
                    if (-not $err) { $err = 'no error value' }
                    'error {0} (licence {1})' -f $err, [string](Get-M365Prop -Object $_ -Name 'skuId')
                }) -join '; '
            Add-Reason 'Probable' 'LicenceError' ("A licence could not be applied to this account: $detail.") `
                'Fix the licence assignment in the Microsoft 365 admin center. Microsoft explains each error value here: https://learn.microsoft.com/entra/identity/users/licensing-groups-resolve-problems'
        } else {
            Add-Pass 'Licensed' 'A licence is assigned and active.'
        }
    }

    # --- Guest -----------------------------------------------------------------------------
    if ([string](Get-M365Prop -Object $user -Name 'userType') -eq 'Guest') {
        Add-Reason 'Info' 'GuestAccount' 'This is a guest (B2B) account. It is checked like a member; problems in the guest''s own home organization are not checked here.' `
            'If everything here looks fine, ask the guest to check with their own IT department.'
    }

    # --- MFA methods -----------------------------------------------------------------------
    if ($Facts.MfaGate -and $Facts.MfaGate.State -eq 'Available') {
        $methods = @($Facts.MfaMethods | Where-Object { $null -ne $_ })
        $mfa = @($methods | Where-Object { $script:M365NonMfaMethodTypes -notcontains [string](Get-M365Prop -Object $_ -Name '@odata.type') })
        if ($mfa.Count -eq 0) {
            Add-Reason 'Warning' 'NoMfaMethod' 'No MFA method registered: this account only has a password.' `
                'If the tenant requires MFA they will be asked to set it up at sign-in, or be refused. Help them add Microsoft Authenticator on their Security info page (My Sign-Ins).'
        } else {
            $names = @($mfa | ForEach-Object { ([string](Get-M365Prop -Object $_ -Name '@odata.type')) -replace '^#microsoft\.graph\.', '' -replace 'AuthenticationMethod$', '' } | Sort-Object -Unique)
            Add-Pass 'MfaRegistered' ('An MFA method is registered ({0}).' -f ($names -join ', '))
        }
    }

    # --- Risky user ------------------------------------------------------------------------
    if ($Facts.RiskGate -and $Facts.RiskGate.State -eq 'Available') {
        $risky = $Facts.RiskyUser
        $level = [string](Get-M365Prop -Object $risky -Name 'riskLevel')
        $state = [string](Get-M365Prop -Object $risky -Name 'riskState')
        if ($null -ne $risky -and ($level -eq 'high' -or $level -eq 'medium' -or $state -eq 'atRisk' -or $state -eq 'confirmedCompromised')) {
            Add-Reason 'Warning' 'RiskyUser' ("Microsoft Entra ID Protection flags this user: risk level $level, risk state $state.") `
                'Treat it as a possible compromised account: involve the security lead before unblocking anything. A risk policy may block them or force a password change.'
        } else {
            Add-Pass 'NotRisky' 'Not flagged as a risky user by ID Protection.'
        }
    }

    # --- Sign-in history -------------------------------------------------------------------
    $signInGate = $Facts.SignInGate
    $caGate = $Facts.ConditionalAccessGate
    if ($signInGate -and $signInGate.State -eq 'Available') {
        $rows = @(Get-M365SignInRows -SignIns @($Facts.SignIns))
        if ($rows.Count -eq 0) {
            Add-Reason 'Info' 'NoSignInsInWindow' ("No sign-in attempts reached Microsoft 365 in the last $days days (interactive sign-ins).") `
                'If they see an error, it happens before Microsoft 365 sees them: check they type the right sign-in name, then the device, the app and the network.'
        } else {
            $latest = $rows[0]
            $run = 0
            foreach ($r in $rows) { if ($r.Code -ne 0) { $run++ } else { break } }
            if ($latest.Code -eq 0) {
                $app = if ($latest.App) { $latest.App } else { 'app not recorded' }
                Add-Pass 'LastSignInSucceeded' ('Last sign-in succeeded at {0} ({1}).' -f (Format-M365Time $latest.Time), $app)
            } else {
                $code = $latest.Code
                $link = Get-M365LookupLink -Code $code
                $failureReason = if ($latest.FailureReason) { $latest.FailureReason } else { '(no failure reason recorded)' }
                $count = if ($run -eq 1) { '1 failed sign-in' } else { "$run failed sign-ins in a row" }
                $app = if ($latest.App) { ", $($latest.App)" } else { '' }
                $message = "Their latest sign-in failed with error $code ($count, the latest at $(Format-M365Time $latest.Time)$app). Microsoft's reason: $failureReason"

                $policies = Get-M365Prop -Object $latest.Row -Name 'appliedConditionalAccessPolicies'
                $failedPolicies = @(@($policies) | Where-Object { $null -ne $_ -and [string](Get-M365Prop -Object $_ -Name 'result') -eq 'failure' } |
                        ForEach-Object { [string](Get-M365Prop -Object $_ -Name 'displayName') } | Where-Object { $_ })
                if ($failedPolicies.Count -gt 0) {
                    $message += ' Conditional Access policy that blocked it: ' + (($failedPolicies | ForEach-Object { "'$_'" }) -join ', ') + '.'
                } elseif ($code -eq 53003 -and -not ($caGate -and $caGate.State -eq 'Available')) {
                    $message += ' The policy cannot be named: Conditional Access detail is not visible to the signed-in account.'
                }

                $step = Get-M365SignInNextStep -Code $code -Synced $synced
                if ($null -eq $step) {
                    Add-Reason 'Probable' 'UnmappedSignInFailure' $message ("Look the code up in Microsoft's live lookup: $link")
                } else {
                    $action = '{0} ({1}: {2})' -f $step, $script:M365MeaningLabel, $link
                    $level = if ($script:M365BlockingCodes -contains $code) { 'Blocker' } else { 'Probable' }
                    $reasonCode = if ($level -eq 'Blocker') { 'BlockingSignInFailure' } else { 'LatestSignInFailed' }
                    # A block from days ago may have cleared on its own (a lockout ends, a CA
                    # condition changes): say how old it is before anyone acts on it.
                    $nowUtc = ConvertTo-M365UtcTime -Value $Facts.Now
                    if ($level -eq 'Blocker' -and $nowUtc -and $latest.Time -and ($nowUtc - $latest.Time).TotalHours -gt 24) {
                        $ago = [int][math]::Floor(($nowUtc - $latest.Time).TotalDays)
                        $message += ' This was {0} {1} ago - ask them to try again first.' -f $ago, $(if ($ago -eq 1) { 'day' } else { 'days' })
                    }
                    Add-Reason $level $reasonCode $message $action
                }
            }

            # Older failures (after the newest run of failures): Info only, by code and count.
            $older = @($rows | Select-Object -Skip ([math]::Max($run, 1)) | Where-Object { $_.Code -ne 0 })
            if ($older.Count -gt 0) {
                $groups = @($older | Group-Object -Property Code | Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, @{ Expression = 'Name'; Descending = $false })
                $summary = ($groups | ForEach-Object { '{0} ({1} {2})' -f $_.Name, $_.Count, $(if ($_.Count -eq 1) { 'time' } else { 'times' }) }) -join ', '
                Add-Reason 'Info' 'OlderSignInFailures' ("Earlier failed sign-ins in the last $days days, by error code: $summary.") `
                    ('These do not decide the answer. If one keeps coming back, look it up: {0}' -f (Get-M365LookupLink -Code $groups[0].Name))
            }
        }
    }

    # --- On-premises AD comparison (computed above) ----------------------------------------
    foreach ($r in @($onPrem.Reasons)) { $reasons.Add($r) }
    foreach ($c in @($onPrem.Cleared)) { $passes.Add($c.Message); $cleared.Add($c) }

    # --- Could not check -------------------------------------------------------------------
    $couldNot = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($Facts.SignInGate, $Facts.ConditionalAccessGate, $Facts.MfaGate, $Facts.RiskGate, $(Get-M365Prop -Object $Facts -Name 'OnPremisesGate'))) {
        if ($null -eq $g -or $g.State -eq 'Available') { continue }
        $couldNot.Add([PSCustomObject]@{ Source = $g.Source; Reason = $(if ($g.Reason) { $g.Reason } else { 'not available' }) })
    }
    # The on-premises stage's Graph lookups: read only when the AD gate was Available, and a
    # failure there is never cleared (AC22c, AC20b).
    $addressErr = [string](Get-M365Prop -Object $Facts -Name 'AddressCheckError')
    if ($addressErr) {
        $couldNot.Add([PSCustomObject]@{ Source = $script:M365AddressCheckSource; Reason = ("the search for another Microsoft 365 user, group or contact holding this account's sign-in name or email address failed ({0})" -f $addressErr) })
    }
    $sidErr = [string](Get-M365Prop -Object $Facts -Name 'CloudSidCheckError')
    if ($sidErr) {
        $couldNot.Add([PSCustomObject]@{ Source = $script:M365SidCheckSource; Reason = ("the search for a Microsoft 365 user holding the AD account's security identifier failed ({0})" -f $sidErr) })
    }

    # --- Verdict ---------------------------------------------------------------------------
    # A failed address-conflict lookup hedges a YES the same way missing sign-in history does
    # (D-006 pattern, owner decision in the SQ-011 review): another object holding the address
    # would be a Blocker, and it could not be ruled out.
    $blockers = @($reasons | Where-Object { $_.Level -eq 'Blocker' })
    $probables = @($reasons | Where-Object { $_.Level -eq 'Probable' })
    $signInReadable = ($signInGate -and $signInGate.State -eq 'Available')
    $note = ''
    if ($blockers.Count -gt 0) { $verdict = 'NO'; $exit = 1 }
    elseif ($probables.Count -gt 0) { $verdict = 'PROBABLY NOT'; $exit = 1 }
    elseif ($signInReadable -and -not $addressErr) { $verdict = 'YES'; $exit = 0 }
    else {
        $verdict = 'PROBABLY YES'; $exit = 0
        $notes = @()
        if (-not $signInReadable) {
            $notes += if ($signInGate -and $signInGate.State -eq 'NotLicensed') { $script:M365NoP1VerdictNote }
            elseif ($signInGate -and $signInGate.Reason) { 'sign-in history not available ({0})' -f $signInGate.Reason }
            else { 'sign-in history not available' }
        }
        if ($addressErr) { $notes += $script:M365AddressCheckVerdictNote }
        $note = $notes -join '; '
    }

    $order = @{ Blocker = 0; Probable = 1; Warning = 2; Info = 3 }
    $sorted = @($reasons | Sort-Object -Property @{ Expression = { $order[$_.Level] } })
    return [PSCustomObject]@{
        Verdict = $verdict; ExitCode = $exit; VerdictNote = $note
        Reasons = $sorted; Passes = $passes.ToArray(); Cleared = $cleared.ToArray(); CouldNotCheck = $couldNot.ToArray()
    }
}

# =============================================================================
# Graph access (GET only)
# =============================================================================

function Invoke-M365GraphGet {
    # The ONLY call to Invoke-MgGraphRequest in this tool: always GET (AC3 checks it statically).
    param([Parameter(Mandatory = $true)][string]$Uri, [hashtable]$Headers)
    $extra = @{}
    if ($Headers) { $extra['Headers'] = $Headers }
    return (Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType HashTable -ErrorAction Stop @extra)
}

function Get-M365TenantContext {
    <#
    .SYNOPSIS
        Which tenant and account this session is in: the banner's facts. Also the preflight.
    .DESCRIPTION
        GET /organization must answer, or this throws: Connect-MgGraph can succeed on a session
        whose every request then fails (Get-M365SecurityEvidence.ps1, preflight). The signed-in
        account's directory roles come from /me/transitiveMemberOf cast to directoryRole, so a
        role held through a role-assignable group is shown too; the cast needs ConsistencyLevel:
        eventual and $count=true (user-list-transitivememberof). Roles not readable is reported
        in RolesNote, never fatal.
    #>
    param([Parameter(Mandatory = $true)][object]$Context)
    $org = Invoke-M365GraphGet -Uri "$script:M365GraphRoot/organization?`$select=id,displayName,verifiedDomains,onPremisesLastSyncDateTime"
    $o = @(Get-M365Prop -Object $org -Name 'value')[0]
    if ($null -eq $o) { throw 'The organization request answered but returned no tenant.' }
    $verified = @(@(Get-M365Prop -Object $o -Name 'verifiedDomains') | Where-Object { $null -ne $_ })
    $default = @($verified | Where-Object { (Get-M365Prop -Object $_ -Name 'isDefault') -eq $true } | ForEach-Object { [string](Get-M365Prop -Object $_ -Name 'name') })
    $tenantId = [string](Get-M365Prop -Object $o -Name 'id')
    if (-not $tenantId) { $tenantId = [string]$Context.TenantId }

    $roles = @(); $rolesNote = ''
    try {
        $r = Invoke-M365GraphGet -Uri "$script:M365GraphRoot/me/transitiveMemberOf/microsoft.graph.directoryRole?`$count=true&`$select=displayName" -Headers @{ ConsistencyLevel = 'eventual' }
        $roles = @(@(Get-M365Prop -Object $r -Name 'value') | Where-Object {
                $null -ne $_ -and ((-not (Test-M365Prop -Object $_ -Name '@odata.type')) -or [string](Get-M365Prop -Object $_ -Name '@odata.type') -eq '#microsoft.graph.directoryRole')
            } | ForEach-Object { [string](Get-M365Prop -Object $_ -Name 'displayName') } | Where-Object { $_ } | Sort-Object -Unique)
    } catch {
        $rolesNote = 'could not read them: ' + (Get-M365ErrorSummary -Message (Get-M365ErrorText -ErrorRecord $_))
    }

    return [PSCustomObject]@{
        TenantId = $tenantId
        DisplayName = [string](Get-M365Prop -Object $o -Name 'displayName')
        DefaultDomain = $(if ($default.Count -gt 0) { $default[0] } else { '' })
        VerifiedDomains = @($verified | ForEach-Object { [string](Get-M365Prop -Object $_ -Name 'name') } | Where-Object { $_ })
        OnPremisesLastSyncDateTime = ConvertTo-M365UtcTime -Value (Get-M365Prop -Object $o -Name 'onPremisesLastSyncDateTime')
        Account = [string]$Context.Account
        Roles = $roles
        RolesNote = $rolesNote
    }
}

function Get-M365VerifiedDomain {
    # The tenant's verified domain names from GET /domains, falling back to the organization's
    # verifiedDomains when /domains cannot be read.
    param([string[]]$Fallback = @())
    try {
        $d = Invoke-M365GraphGet -Uri "$script:M365GraphRoot/domains?`$select=id,isVerified,isDefault"
        $names = @(@(Get-M365Prop -Object $d -Name 'value') | Where-Object { $null -ne $_ -and (Get-M365Prop -Object $_ -Name 'isVerified') -ne $false } |
                ForEach-Object { [string](Get-M365Prop -Object $_ -Name 'id') } | Where-Object { $_ })
        if ($names.Count -gt 0) { return $names }
    } catch {
        Write-Verbose "GET /domains failed, using the organization's verified domains: $($_.Exception.Message)"
    }
    return @($Fallback)
}

function Test-M365UpnInTenant {
    # A UPN's domain must be one of the tenant's verified domains (user resource,
    # userPrincipalName), so any other domain means the wrong tenant (or a guest's email).
    param([Parameter(Mandatory = $true)][string]$UserPrincipalName, [string[]]$VerifiedDomains = @())
    $at = $UserPrincipalName.LastIndexOf('@')
    if ($at -lt 0) { return $false }
    $domain = $UserPrincipalName.Substring($at + 1)
    return (@($VerifiedDomains | Where-Object { $_ -ieq $domain }).Count -gt 0)
}

$script:M365UserSelect = @(
    'id', 'displayName', 'userPrincipalName', 'accountEnabled', 'userType', 'assignedLicenses', 'licenseAssignmentStates',
    'onPremisesSyncEnabled', 'onPremisesLastSyncDateTime', 'onPremisesProvisioningErrors', 'onPremisesSecurityIdentifier',
    'onPremisesSamAccountName', 'onPremisesDomainName', 'onPremisesImmutableId', 'proxyAddresses', 'mail'
) -join ','

function Find-M365User {
    <#
    .SYNOPSIS
        Finds exactly one Microsoft 365 user, or reports NotFound / Ambiguous with candidates.
        Never guesses.
    .DESCRIPTION
        userPrincipalName eq first, then mail eq, then proxyAddresses/any(p:p eq 'smtp:<x>').
        Each of the three filters works by default, without advanced query headers
        (aad-advanced-queries, user properties table). The two fallbacks are separate requests,
        merged by id, because Learn does not say whether joining them with "or" in one filter
        still works without ConsistencyLevel: eventual. The value is an OData literal (quotes
        doubled) and URL-encoded, so a guest's #EXT# or an apostrophe cannot break the request.
        Errors are thrown to the caller.
    #>
    param([Parameter(Mandatory = $true)][string]$UserPrincipalName)
    $name = $UserPrincipalName.Trim()
    $lit = ConvertTo-M365ODataLiteral -Value $name
    $select = "&`$select=$script:M365UserSelect"
    $getUsers = {
        param([string]$Filter)
        $r = Invoke-M365GraphGet -Uri ("$script:M365GraphRoot/users?`$filter=" + [uri]::EscapeDataString($Filter) + $select)
        @(@(Get-M365Prop -Object $r -Name 'value') | Where-Object { $null -ne $_ })
    }

    $found = @(& $getUsers "userPrincipalName eq $lit")
    $matchedBy = 'UserPrincipalName'
    if ($found.Count -eq 0) {
        $smtp = ConvertTo-M365ODataLiteral -Value ("smtp:$name")
        $byId = [ordered]@{}
        foreach ($u in @(& $getUsers "mail eq $lit") + @(& $getUsers "proxyAddresses/any(p:p eq $smtp)")) {
            $key = [string](Get-M365Prop -Object $u -Name 'id')
            if (-not $key) { $key = [guid]::NewGuid().ToString() }
            if (-not $byId.Contains($key)) { $byId[$key] = $u }
        }
        $found = @($byId.Values)
        $matchedBy = 'mail or proxy address'
    }

    $status = 'Found'
    if ($found.Count -eq 0) { $status = 'NotFound'; $matchedBy = '' }
    elseif ($found.Count -gt 1) { $status = 'Ambiguous' }
    $candidates = @($found | ForEach-Object {
            [PSCustomObject]@{
                DisplayName = [string](Get-M365Prop -Object $_ -Name 'displayName')
                UserPrincipalName = [string](Get-M365Prop -Object $_ -Name 'userPrincipalName')
                AccountEnabled = ((Get-M365Prop -Object $_ -Name 'accountEnabled') -ne $false)
                Id = [string](Get-M365Prop -Object $_ -Name 'id')
            }
        })
    return [PSCustomObject]@{
        Status = $status; User = $(if ($found.Count -eq 1) { $found[0] } else { $null })
        Candidates = $candidates; MatchedBy = $matchedBy
    }
}

function Get-M365UserFacts {
    <#
    .SYNOPSIS
        Reads sign-ins, MFA methods and risky-user state for one user. Never throws: each read
        that fails becomes a gate with a reason.
    .DESCRIPTION
        Sign-ins: one page of $top=50, filtered on userId eq and createdDateTime ge (signin-list,
        signin). The call's own outcome is the gate (P-001): a licence label never overrides it.
        Each row keeps only the fields the verdict and the report need (Select-M365SignInFields);
        that includes ipAddress, for the local HTML report only. MFA methods keep only their
        type and id.

        -OnPremises is Get-M365OnPremisesFacts's result; its gate, AD account and address
        conflicts are copied into the facts. -OnPremisesGate alone (for -SkipOnPremises) sets
        only the gate. -TenantLastSync is the organization's onPremisesLastSyncDateTime.
    #>
    param(
        [Parameter(Mandatory = $true)][object]$User,
        [ValidateRange(1, 30)][int]$Days = 7,
        [datetime]$Now = [datetime]::UtcNow,
        [object]$OnPremisesGate,
        [object]$OnPremises,
        [object]$TenantLastSync
    )
    $id = [string](Get-M365Prop -Object $User -Name 'id')
    $idPath = [uri]::EscapeDataString($id)
    $nowUtc = ConvertTo-M365UtcTime -Value $Now
    $since = $nowUtc.AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)

    $signIns = @()
    try {
        $filter = 'userId eq {0} and createdDateTime ge {1}' -f (ConvertTo-M365ODataLiteral -Value $id), $since
        # No $select: signin-list documents only $top, $skiptoken and $filter for this request,
        # so the rows are trimmed here instead (Select-M365SignInFields).
        $r = Invoke-M365GraphGet -Uri ("$script:M365GraphRoot/auditLogs/signIns?`$filter=" + [uri]::EscapeDataString($filter) + "&`$top=$script:M365SignInPageSize")
        $signIns = @(@(Get-M365Prop -Object $r -Name 'value') | Where-Object { $null -ne $_ } | ForEach-Object { Select-M365SignInFields -Row $_ })
        $signInGate = New-M365Gate -Source 'Sign-in history' -State Available
    } catch {
        $signInGate = Get-M365GateFromError -Source 'Sign-in history' -Message (Get-M365ErrorText -ErrorRecord $_)
    }
    if ($signInGate.State -eq 'Available') {
        $caGate = Get-M365ConditionalAccessGate -SignIns $signIns
    } else {
        $caGate = New-M365Gate -Source 'Conditional Access detail' -State $signInGate.State -Reason 'sign-in history is not available'
    }

    $methods = @()
    try {
        $m = Invoke-M365GraphGet -Uri "$script:M365GraphRoot/users/$idPath/authentication/methods"
        # Only the method type is needed (is there a second factor?); phone numbers, email
        # addresses and device names are dropped as soon as they arrive (personal-data profile).
        $methods = @(@(Get-M365Prop -Object $m -Name 'value') | Where-Object { $null -ne $_ } | ForEach-Object {
                @{ '@odata.type' = Get-M365Prop -Object $_ -Name '@odata.type'; id = Get-M365Prop -Object $_ -Name 'id' }
            })
        $mfaGate = New-M365Gate -Source 'MFA methods' -State Available
    } catch {
        $mfaGate = Get-M365GateFromError -Source 'MFA methods' -Message (Get-M365ErrorText -ErrorRecord $_)
    }

    $risky = $null
    try {
        $risky = Invoke-M365GraphGet -Uri "$script:M365GraphRoot/identityProtection/riskyUsers/$idPath"
        $riskGate = New-M365Gate -Source 'Risky user' -State Available
    } catch {
        $riskGate = Get-M365GateFromError -Source 'Risky user' -Message (Get-M365ErrorText -ErrorRecord $_)
        $risky = $null
    }

    if ($OnPremises) { $OnPremisesGate = $OnPremises.Gate }
    if ($null -eq $OnPremisesGate) {
        $OnPremisesGate = New-M365Gate -Source 'On-premises AD' -State NotChecked -Reason 'not requested'
    }

    return [PSCustomObject]@{
        User = $User; SignInGate = $signInGate; ConditionalAccessGate = $caGate; MfaGate = $mfaGate; RiskGate = $riskGate
        OnPremisesGate = $OnPremisesGate
        AdUser = $(if ($OnPremises) { $OnPremises.AdUser }); AdMatchedBy = $(if ($OnPremises) { $OnPremises.AdMatchedBy } else { '' })
        AddressConflicts = $(if ($OnPremises) { @($OnPremises.AddressConflicts) } else { @() })
        AddressCheckError = $(if ($OnPremises) { $OnPremises.AddressCheckError } else { '' })
        CloudSidCheckError = $(if ($OnPremises) { $OnPremises.CloudSidCheckError } else { '' })
        TenantLastSync = $TenantLastSync
        SignIns = $signIns; MfaMethods = $methods; RiskyUser = $risky; Days = $Days; Now = $nowUtc
    }
}

function New-M365NoCloudUserFacts {
    <#
    .SYNOPSIS
        Facts for "no Microsoft 365 user matched, but the AD stage found the account" (AC20).
        Nothing is read from Graph for a user that does not exist: every cloud source is
        NotChecked with the reason, so none of them can add a reason or a pass.
    #>
    param(
        [Parameter(Mandatory = $true)][object]$OnPremises,
        [object]$TenantLastSync,
        [int]$Days = 7,
        [datetime]$Now = [datetime]::UtcNow
    )
    $nc = 'there is no Microsoft 365 user to read it for'
    return [PSCustomObject]@{
        User = $null
        SignInGate = (New-M365Gate -Source 'Sign-in history' -State NotChecked -Reason $nc)
        ConditionalAccessGate = (New-M365Gate -Source 'Conditional Access detail' -State NotChecked -Reason $nc)
        MfaGate = (New-M365Gate -Source 'MFA methods' -State NotChecked -Reason $nc)
        RiskGate = (New-M365Gate -Source 'Risky user' -State NotChecked -Reason $nc)
        OnPremisesGate = $OnPremises.Gate; AdUser = $OnPremises.AdUser; AdMatchedBy = $OnPremises.AdMatchedBy
        AddressConflicts = @($OnPremises.AddressConflicts); AddressCheckError = $OnPremises.AddressCheckError
        CloudSidCheckError = $OnPremises.CloudSidCheckError
        TenantLastSync = $TenantLastSync
        SignIns = @(); MfaMethods = @(); RiskyUser = $null; Days = $Days; Now = (ConvertTo-M365UtcTime -Value $Now)
    }
}

# =============================================================================
# On-premises AD access (read only: Get-ADUser, and GET on Graph for address conflicts)
# =============================================================================

function ConvertTo-LdapFilterValue {
    # RFC 4515 escaping so a name containing ( ) * \ cannot change the filter.
    # Copied from AD-UserQuickCheck/Get-ADUserQuickCheck.ps1 (self-contained folders).
    param([string]$Value)
    $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
}

function Test-M365AdNotFound {
    # Get-ADUser -Identity throws ADIdentityNotFoundException ("Cannot find an object with
    # identity ...") when nothing matches; that is "not found", not "no domain controller".
    param([Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord)
    return ($ErrorRecord.Exception.GetType().Name -match 'ADIdentityNotFound' -or
        [string]$ErrorRecord.Exception.Message -match '^Cannot find an object with identity')
}

function Find-M365AddressConflict {
    <#
    .SYNOPSIS
        Other Microsoft 365 objects that already hold one of the given addresses (AC22).
    .DESCRIPTION
        GET only. Each address is matched only against the fields that can hold it (AC22b): the
        AD sign-in name (-UserPrincipalName) against other users' userPrincipalName, nothing
        else (groups and contacts have no sign-in name); the primary email address
        (-PrimarySmtp) against mail and proxyAddresses of users, groups and organizational
        contacts (/contacts), never against a userPrincipalName. Another user whose sign-in name
        happens to equal this account's email address is not a conflict.

        Each of these $filter forms works by default, without ConsistencyLevel: eventual or
        $count (aad-advanced-queries: group, orgContact and user property tables). They are
        separate requests, never joined with "or", for the same reason as in Find-M365User.
        Directory.Read.All covers all three lists (user-list, group-list, orgcontact-list). The
        object with -ExcludeId (the cloud user itself) is never a conflict. Errors are thrown to
        the caller.
    #>
    param([string]$UserPrincipalName, [string]$PrimarySmtp, [string]$ExcludeId)
    $lookups = New-Object System.Collections.Generic.List[object]
    if ($UserPrincipalName) {
        $lookups.Add(@{ Address = $UserPrincipalName; Type = 'user'; Path = 'users'; Filter = 'userPrincipalName eq {0}' -f (ConvertTo-M365ODataLiteral -Value $UserPrincipalName) })
    }
    if ($PrimarySmtp) {
        $lit = ConvertTo-M365ODataLiteral -Value $PrimarySmtp
        $smtp = ConvertTo-M365ODataLiteral -Value ("smtp:$PrimarySmtp")
        foreach ($t in @(@{ Type = 'user'; Path = 'users' }, @{ Type = 'group'; Path = 'groups' }, @{ Type = 'contact'; Path = 'contacts' })) {
            $lookups.Add(@{ Address = $PrimarySmtp; Type = $t.Type; Path = $t.Path; Filter = "mail eq $lit" })
            $lookups.Add(@{ Address = $PrimarySmtp; Type = $t.Type; Path = $t.Path; Filter = "proxyAddresses/any(p:p eq $smtp)" })
        }
    }
    $byKey = [ordered]@{}
    foreach ($l in $lookups) {
        $r = Invoke-M365GraphGet -Uri ("$script:M365GraphRoot/$($l.Path)?`$filter=" + [uri]::EscapeDataString($l.Filter) + "&`$select=id,displayName")
        foreach ($o in @(@(Get-M365Prop -Object $r -Name 'value') | Where-Object { $null -ne $_ })) {
            $id = [string](Get-M365Prop -Object $o -Name 'id')
            if ($ExcludeId -and $id -eq $ExcludeId) { continue }
            $key = '{0}|{1}' -f $l.Type, $id
            if ($byKey.Contains($key)) { continue }
            $byKey[$key] = [PSCustomObject]@{ Type = $l.Type; DisplayName = [string](Get-M365Prop -Object $o -Name 'displayName'); Address = $l.Address; Id = $id }
        }
    }
    return @($byKey.Values)
}

function Find-M365UserBySid {
    <#
    .SYNOPSIS
        The Microsoft 365 users whose onPremisesSecurityIdentifier is the given SID (AC20b).
    .DESCRIPTION
        GET /users?$filter=onPremisesSecurityIdentifier eq '<SID>', with the same $select as
        Find-M365User so a user found this way can be assessed. The user resource documents
        "Supports $filter (eq including on null values)" for onPremisesSecurityIdentifier, and
        the aad-advanced-queries user table marks eq as working by default, so no
        ConsistencyLevel: eventual header or $count=true is needed. Errors are thrown to the
        caller.
        https://learn.microsoft.com/graph/api/resources/user?view=graph-rest-1.0
        https://learn.microsoft.com/graph/aad-advanced-queries
    #>
    param([Parameter(Mandatory = $true)][string]$Sid)
    $filter = 'onPremisesSecurityIdentifier eq {0}' -f (ConvertTo-M365ODataLiteral -Value $Sid)
    $r = Invoke-M365GraphGet -Uri ("$script:M365GraphRoot/users?`$filter=" + [uri]::EscapeDataString($filter) + "&`$select=$script:M365UserSelect")
    return @(@(Get-M365Prop -Object $r -Name 'value') | Where-Object { $null -ne $_ })
}

function Get-M365OnPremisesFacts {
    <#
    .SYNOPSIS
        The on-premises AD stage: finds the user's AD account and the Microsoft 365 objects that
        hold its addresses. Never throws: anything that stops it becomes the gate's reason.
    .DESCRIPTION
        ActiveDirectory is imported here at run time, in try/catch (no #Requires -Modules):
        without RSAT the Graph verdict still stands, with "On-premises AD: could not check".

        Synced user with onPremisesSecurityIdentifier: Get-ADUser -Identity <SID> (Identity
        takes a DN, GUID, SID or SAM account name, get-aduser). Not found there, or a cloud-only
        user, or no cloud user at all: one LDAP search on userPrincipalName (the name typed,
        or the cloud UPN when that differs), RFC 4515 escaped.
        -Server and -Credential reach Get-ADUser only when given. Any other Get-ADUser error
        means no domain controller answered (D-014), and the gate says so.

        No cloud user (-User $null) and an AD account found: its SID is looked up in Microsoft
        365 first (Find-M365UserBySid, AC20b). One cloud user holding it comes back as
        SyncedCloudUser, with nothing else looked up, for the caller to assess that user; a
        failed or ambiguous lookup is CloudSidCheckError.

        Address conflicts are looked up for a synced user or for no cloud user, not for a
        cloud-only one (its AD namesake is a separate account, and the cloud user holds its own
        addresses): the AD sign-in name as a userPrincipalName, the primary email address as
        mail or proxyAddresses (Find-M365AddressConflict, AC22b).

        Returns { Gate; AdUser; AdMatchedBy; AddressConflicts; AddressCheckError;
        SyncedCloudUser; CloudSidCheckError }.
    #>
    param(
        [object]$User,
        [Parameter(Mandatory = $true)][string]$UserPrincipalName,
        [string]$Server,
        [pscredential]$Credential
    )
    $source = 'On-premises AD'
    $out = [PSCustomObject]@{
        Gate = $null; AdUser = $null; AdMatchedBy = ''; AddressConflicts = @(); AddressCheckError = ''
        SyncedCloudUser = $null; CloudSidCheckError = ''
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
    } catch {
        $out.Gate = New-M365Gate -Source $source -State Failed -Reason ("the ActiveDirectory module is not available on this computer ({0}). Install the RSAT Active Directory tools, or run the check on a server that has them" -f (Get-M365ErrorSummary -Message $_.Exception.Message))
        return $out
    }

    # Pass-through only when given; the credential itself is never written anywhere.
    $ad = @{}
    if ($Server) { $ad['Server'] = $Server }
    if ($Credential) { $ad['Credential'] = $Credential }

    $synced = Test-M365UserSynced -User $User
    # onPremisesSecurityIdentifier: "the on-premises security identifier (SID) for the user that
    # was synchronized from on-premises to the cloud" (user resource; $select'ed by Find-M365User).
    # https://learn.microsoft.com/graph/api/resources/user?view=graph-rest-1.0
    $sid = [string](Get-M365Prop -Object $User -Name 'onPremisesSecurityIdentifier')
    # The name the tech typed, and the cloud user's UPN when it differs (a user found by an
    # email or proxy address): either can be the AD account's userPrincipalName.
    $names = @(@($UserPrincipalName.Trim(), [string](Get-M365Prop -Object $User -Name 'userPrincipalName')) | Where-Object { $_ } | Sort-Object -Unique)
    $upn = $names -join ' or '

    $adUser = $null
    try {
        if ($synced -and $sid) {
            try {
                $adUser = Get-ADUser -Identity $sid @ad -Properties $script:M365AdUserProperties -ErrorAction Stop
                $out.AdMatchedBy = 'SID'
            } catch {
                if (-not (Test-M365AdNotFound -ErrorRecord $_)) { throw }
            }
        }
        if ($null -eq $adUser) {
            $upnFilter = ($names | ForEach-Object { '(userPrincipalName={0})' -f (ConvertTo-LdapFilterValue $_) }) -join ''
            if ($names.Count -gt 1) { $upnFilter = "(|$upnFilter)" }
            $found = @(Get-ADUser @ad -LDAPFilter "(&(objectCategory=person)(objectClass=user)$upnFilter)" -Properties $script:M365AdUserProperties -ErrorAction Stop |
                    Where-Object { $null -ne $_ })
            if ($found.Count -gt 1) {
                $out.Gate = New-M365Gate -Source $source -State Failed -Reason ("{0} AD accounts have the sign-in name {1}, so the tool cannot tell which one syncs" -f $found.Count, $upn)
                return $out
            }
            if ($found.Count -eq 1) { $adUser = $found[0]; $out.AdMatchedBy = 'UserPrincipalName' }
        }
    } catch {
        $where = if ($Server) { "domain controller $Server did not answer" } else { 'no domain controller answered' }
        $out.Gate = New-M365Gate -Source $source -State Failed -Reason ("{0} ({1}). Run it on a domain-joined computer, or add -Server <domain controller> and -Credential" -f $where, (Get-M365ErrorSummary -Message $_.Exception.Message))
        return $out
    }
    $out.AdUser = $adUser
    $out.Gate = New-M365Gate -Source $source -State Available

    # No cloud user by the name typed, but an AD account: before "exists in AD but not in
    # Microsoft 365", is there a cloud user synced from it under another name (AC20b)? Exactly
    # one is handed back for the caller to assess instead; this stage then stops here, because
    # its address conflicts must be looked up for that user (its own id excluded).
    if ($null -eq $User -and $null -ne $adUser) {
        $adSid = [string](Get-M365Prop -Object $adUser -Name 'SID')
        if ($adSid) {
            try {
                $bySid = @(Find-M365UserBySid -Sid $adSid)
                if ($bySid.Count -eq 1) {
                    $out.SyncedCloudUser = $bySid[0]
                    return $out
                }
                if ($bySid.Count -gt 1) { $out.CloudSidCheckError = '{0} Microsoft 365 users hold it, so the tool cannot tell which one syncs' -f $bySid.Count }
            } catch {
                $out.CloudSidCheckError = Get-M365ErrorSummary -Message (Get-M365ErrorText -ErrorRecord $_)
            }
        }
    }

    if ($null -ne $adUser -and ($synced -or $null -eq $User)) {
        $conflictArgs = @{
            UserPrincipalName = [string](Get-M365Prop -Object $adUser -Name 'UserPrincipalName')
            PrimarySmtp = (Get-M365PrimarySmtp -Object $adUser)
            ExcludeId = [string](Get-M365Prop -Object $User -Name 'id')
        }
        try {
            $out.AddressConflicts = @(Find-M365AddressConflict @conflictArgs)
        } catch {
            $out.AddressCheckError = Get-M365ErrorSummary -Message (Get-M365ErrorText -ErrorRecord $_)
        }
    }
    return $out
}
if ($LoadFunctionsOnly) { return }
