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
.NOTES
    REFERENCES
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
    param([Parameter(Mandatory = $true)][object]$Gate)
    if ($Gate.State -eq 'Available') { return ('{0}: available' -f $Gate.Source) }
    $reason = if ($Gate.Reason) { $Gate.Reason } else { 'no reason given' }
    return ('{0}: not available ({1})' -f $Gate.Source, $reason)
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
        readable; otherwise PROBABLY YES with VerdictNote (owner decision D-006).

        Only the most recent sign-in decides: an older typo must not turn into NO. Older
        failures are summarised as Info by code and count.

        Passes are the strings shown under "Looks fine". Cleared holds the same checks as
        { Code; Message; CouldLook } for the ticket note. CouldNotCheck lists every gate that was
        not Available, with its reason. Nothing is ever cleared from a source that could not be
        read.

        Facts: User; SignInGate; ConditionalAccessGate; MfaGate; RiskGate; (OnPremisesGate);
        SignIns; MfaMethods; RiskyUser; Days; Now.
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

    # --- Account blocked -------------------------------------------------------------------
    # accountEnabled false = sign-in blocked (user resource).
    if ((Get-M365Prop -Object $user -Name 'accountEnabled') -eq $false) {
        if ($synced) {
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

    # --- Could not check -------------------------------------------------------------------
    $couldNot = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($Facts.SignInGate, $Facts.ConditionalAccessGate, $Facts.MfaGate, $Facts.RiskGate, $(Get-M365Prop -Object $Facts -Name 'OnPremisesGate'))) {
        if ($null -eq $g -or $g.State -eq 'Available') { continue }
        $couldNot.Add([PSCustomObject]@{ Source = $g.Source; Reason = $(if ($g.Reason) { $g.Reason } else { 'not available' }) })
    }

    # --- Verdict ---------------------------------------------------------------------------
    $blockers = @($reasons | Where-Object { $_.Level -eq 'Blocker' })
    $probables = @($reasons | Where-Object { $_.Level -eq 'Probable' })
    $note = ''
    if ($blockers.Count -gt 0) { $verdict = 'NO'; $exit = 1 }
    elseif ($probables.Count -gt 0) { $verdict = 'PROBABLY NOT'; $exit = 1 }
    elseif ($signInGate -and $signInGate.State -eq 'Available') { $verdict = 'YES'; $exit = 0 }
    else {
        $verdict = 'PROBABLY YES'; $exit = 0
        $note = if ($signInGate -and $signInGate.State -eq 'NotLicensed') { $script:M365NoP1VerdictNote }
        elseif ($signInGate -and $signInGate.Reason) { 'sign-in history not available ({0})' -f $signInGate.Reason }
        else { 'sign-in history not available' }
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
    #>
    param(
        [Parameter(Mandatory = $true)][object]$User,
        [ValidateRange(1, 30)][int]$Days = 7,
        [datetime]$Now = [datetime]::UtcNow,
        [object]$OnPremisesGate
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

    if ($null -eq $OnPremisesGate) {
        $OnPremisesGate = New-M365Gate -Source 'On-premises AD' -State NotChecked -Reason 'not checked in this version'
    }

    return [PSCustomObject]@{
        User = $User; SignInGate = $signInGate; ConditionalAccessGate = $caGate; MfaGate = $mfaGate; RiskGate = $riskGate
        OnPremisesGate = $OnPremisesGate
        SignIns = $signIns; MfaMethods = $methods; RiskyUser = $risky; Days = $Days; Now = $nowUtc
    }
}

if ($LoadFunctionsOnly) { return }
