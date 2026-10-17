<#
    Tests for M365-UserQuickCheck\M365UserCheck.Core.ps1 (Pester 5, run under pwsh).
    SQ-002, Graph stage: AC4-AC16. Pure assessment and gate classification; the one access
    function (Find-M365User) runs against a mocked Invoke-MgGraphRequest.

    Nothing here connects to Graph or AD. Synthetic data only (contoso.com, jdoe, 203.0.113.x).

    PINNED INTERFACE (the implementer must honour these names and shapes):
      New-M365Gate -Source <display name> -State Available|NotLicensed|NotAllowed|Failed [-Reason <text>]
          -> [PSCustomObject]{ Source; State; Reason }
          Source display names: 'Sign-in history', 'Conditional Access detail', 'MFA methods',
          'Risky user', 'On-premises AD'.
      Get-M365GateFromError -Source <display name> -Message <exception text>
          -> gate. Sign-in history: body code Authentication_RequestFromNonPremiumTenantOrB2CTenant
          = NotLicensed; any other 403 = NotAllowed; else Failed. Risky user: the same non-premium
          code = NotLicensed, 404 (NotFound) = Available (not flagged). MFA methods: 403 = NotAllowed.
      Format-M365SourceLine -Gate <gate> -> one banner line, "<Source>: available" or
          "<Source>: not available (<Reason>)".
      Get-M365ConditionalAccessGate -SignIns <rows> -> gate for 'Conditional Access detail'.
      Get-M365UserAssessment -Facts <facts> -> { Verdict; ExitCode; VerdictNote; Reasons; Passes;
          Cleared; CouldNotCheck }.  Reasons: { Level; Code; Message; Action }.
          CouldNotCheck: { Source; Reason }.
          Verdict: NO (any Blocker), PROBABLY NOT (any Probable), YES (sign-in history Available),
          otherwise 'PROBABLY YES' with VerdictNote 'sign-in history not available (no Entra ID P1)'
          for NotLicensed (owner decision D-006). Exit codes: NO / PROBABLY NOT = 1, others 0.
          Reason codes: SignInBlocked, NoLicence, LicenceError (Probable), NoMfaMethod, RiskyUser
          (Warning), BlockingSignInFailure (Blocker), UnmappedSignInFailure (Probable),
          OlderSignInFailures, NoSignInsInWindow (Info).
      Facts: { User; SignInGate; ConditionalAccessGate; MfaGate; RiskGate; SignIns; MfaMethods;
          RiskyUser; Days; Now }. Graph objects are HASHTABLES (what Invoke-MgGraphRequest returns
          by default); an absent key must be told apart from a null value. Dates are ISO strings.
      Find-M365User -UserPrincipalName <upn> -> { Status Found|NotFound|Ambiguous; User; Candidates
          (DisplayName, UserPrincipalName, AccountEnabled); MatchedBy }.

    Run:  Invoke-Pester .\M365-UserQuickCheck\Tests
#>

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:CorePath = Join-Path $script:Root 'M365UserCheck.Core.ps1'

    # Stub with the real parameter names (verified against Microsoft.Graph.Authentication).
    function Invoke-MgGraphRequest {
        [CmdletBinding()]
        param($Method, [uri]$Uri, $Body, $Headers, $OutputFilePath, $InputFilePath, [switch]$PassThru,
            [switch]$SkipHeaderValidation, $ContentType, $SessionVariable, $ResponseHeadersVariable,
            $StatusCodeVariable, [switch]$SkipHttpErrorCheck, $GraphRequestSession, $UserAgent, $OutputType)
    }

    if (Test-Path -LiteralPath $script:CorePath) { . $script:CorePath -LoadFunctionsOnly }

    $script:Now = New-Object DateTime -ArgumentList 2026, 10, 17, 14, 0, 0, ([DateTimeKind]::Utc)
    $script:NonP1Message = 'Response status code does not indicate success: Forbidden (Forbidden). {"error":{"code":"Authentication_RequestFromNonPremiumTenantOrB2CTenant","message":"Neither tenant is B2C or tenant doesn''t have premium license"}}'
    $script:ForbiddenMessage = 'Response status code does not indicate success: Forbidden (Forbidden). {"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."}}'
    $script:NotFoundMessage = 'Response status code does not indicate success: NotFound (Not Found). {"error":{"code":"Request_ResourceNotFound","message":"Resource not found."}}'

    function New-User {
        param([hashtable]$Set = @{})
        $u = @{
            id = 'aaaaaaaa-0000-0000-0000-000000000001'; displayName = 'Jane Doe'
            userPrincipalName = 'jdoe@contoso.com'; mail = 'jdoe@contoso.com'; accountEnabled = $true
            userType = 'Member'; onPremisesSyncEnabled = $null
            assignedLicenses = @(@{ skuId = 'bbbbbbbb-0000-0000-0000-000000000001'; disabledPlans = @() })
            licenseAssignmentStates = @(@{ skuId = 'bbbbbbbb-0000-0000-0000-000000000001'; state = 'Active'; error = 'None' })
            proxyAddresses = @('SMTP:jdoe@contoso.com')
        }
        foreach ($k in $Set.Keys) { $u[$k] = $Set[$k] }
        return $u
    }

    # $Policies = $null leaves appliedConditionalAccessPolicies ABSENT (a role that cannot read it).
    function New-SignInRow {
        param([TimeSpan]$Ago = (New-TimeSpan -Hours 1), [int]$Code = 0, [string]$FailureReason = 'Other.',
            [object]$Policies = $null, [string]$App = 'Office 365 Exchange Online')
        $row = @{
            id = [guid]::NewGuid().ToString()
            createdDateTime = ($script:Now - $Ago).ToString('yyyy-MM-ddTHH:mm:ssZ')
            appDisplayName = $App; clientAppUsed = 'Browser'; ipAddress = '203.0.113.7'
            location = @{ city = 'Springfield'; countryOrRegion = 'US' }
            status = @{ errorCode = $Code; failureReason = $FailureReason; additionalDetails = $null }
        }
        if ($null -ne $Policies) { $row['appliedConditionalAccessPolicies'] = @($Policies) }
        return $row
    }

    function New-Gates {
        $script:G = @{
            SignIn = (New-M365Gate -Source 'Sign-in history' -State Available)
            Ca     = (New-M365Gate -Source 'Conditional Access detail' -State Available)
            Mfa    = (New-M365Gate -Source 'MFA methods' -State Available)
            Risk   = (New-M365Gate -Source 'Risky user' -State Available)
        }
    }

    # A healthy account by default; override any Facts property.
    function New-Facts {
        param([hashtable]$Override = @{})
        New-Gates
        $f = @{
            User = (New-User); SignInGate = $script:G.SignIn; ConditionalAccessGate = $script:G.Ca
            MfaGate = $script:G.Mfa; RiskGate = $script:G.Risk
            SignIns = @((New-SignInRow -Ago (New-TimeSpan -Hours 1) -Code 0))
            MfaMethods = @(@{ '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod'; id = '28c10230-6103-485e-b985-444c60001490' },
                @{ '@odata.type' = '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'; id = 'cccccccc-0000-0000-0000-000000000001' })
            RiskyUser = $null; Days = 7; Now = $script:Now
        }
        foreach ($k in $Override.Keys) { $f[$k] = $Override[$k] }
        return [PSCustomObject]$f
    }

    function Get-Reason($A, [string]$Code) { @($A.Reasons | Where-Object { $_.Code -eq $Code })[0] }
    function Get-ReasonText($R) { '{0} {1}' -f $R.Message, $R.Action }
}

Describe 'core is present' {
    It 'AC0_CoreLoads: M365UserCheck.Core.ps1 exists and defines the pinned functions' {
        Test-Path -LiteralPath $script:CorePath | Should -BeTrue
        foreach ($fn in 'New-M365Gate', 'Get-M365GateFromError', 'Format-M365SourceLine', 'Get-M365ConditionalAccessGate', 'Get-M365UserAssessment', 'Find-M365User') {
            Get-Command -Name $fn -CommandType Function -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$fn is part of the pinned interface"
        }
    }
}

Describe 'AC4 finding the user' {
    BeforeEach {
        $script:UpnMatches = @(); $script:FallbackMatches = @(); $script:Uris = New-Object System.Collections.Generic.List[string]
        Mock Invoke-MgGraphRequest {
            $u = [uri]::UnescapeDataString([string]$Uri)
            $script:Uris.Add($u)
            if ($u -match 'userPrincipalName eq') { return @{ value = @($script:UpnMatches) } }
            return @{ value = @($script:FallbackMatches) }
        }
    }

    It 'AC4_UserNotFoundOrAmbiguous: no match at all -> NotFound' {
        $r = Find-M365User -UserPrincipalName 'jdoe@contoso.com'
        $r.Status | Should -Be 'NotFound'
        $r.User | Should -BeNullOrEmpty
    }

    It 'AC4_UserNotFoundOrAmbiguous: a UPN match is Found by UPN' {
        $script:UpnMatches = @(New-User)
        $r = Find-M365User -UserPrincipalName 'jdoe@contoso.com'
        $r.Status | Should -Be 'Found'
        $r.User.id | Should -Be 'aaaaaaaa-0000-0000-0000-000000000001'
        $r.MatchedBy | Should -Match 'UserPrincipalName'
    }

    It 'AC4_UserNotFoundOrAmbiguous: UPN misses, one mail/proxy match -> Found, not by UPN' {
        $script:FallbackMatches = @(New-User @{ userPrincipalName = 'jane.doe@contoso.onmicrosoft.com' })
        $r = Find-M365User -UserPrincipalName 'jdoe@contoso.com'
        $r.Status | Should -Be 'Found'
        $r.MatchedBy | Should -Not -Match '^UserPrincipalName$'
    }

    It 'AC4_UserNotFoundOrAmbiguous: fallback returns two users -> Ambiguous, candidates listed, none chosen' {
        $script:FallbackMatches = @(
            (New-User @{ id = '1'; displayName = 'Jane Doe'; userPrincipalName = 'jane@contoso.com'; accountEnabled = $true }),
            (New-User @{ id = '2'; displayName = 'Jane Doe (old)'; userPrincipalName = 'jane.old@contoso.com'; accountEnabled = $false }))
        $r = Find-M365User -UserPrincipalName 'jdoe@contoso.com'
        $r.Status | Should -Be 'Ambiguous'
        $r.User | Should -BeNullOrEmpty
        @($r.Candidates).Count | Should -Be 2
        @($r.Candidates | Where-Object { $_.UserPrincipalName -eq 'jane.old@contoso.com' })[0].AccountEnabled | Should -BeFalse
        @($r.Candidates)[0].DisplayName | Should -Be 'Jane Doe'
    }

    It 'Edge_ApostropheInUpnIsEscapedForOData: o''brien becomes o''''brien in the filter' {
        $null = Find-M365User -UserPrincipalName "o'brien@contoso.com"
        @($script:Uris | Where-Object { $_ -match "o''brien@contoso\.com" }).Count | Should -BeGreaterThan 0
        @($script:Uris | Where-Object { $_ -match "[^']o'brien" }).Count | Should -Be 0
    }
}

Describe 'AC5 blocked sign-in' {
    It 'AC5_SignInBlocked: synced user, accountEnabled false -> NO, next step points to on-premises AD' {
        $a = Get-M365UserAssessment -Facts (New-Facts @{ User = (New-User @{ accountEnabled = $false; onPremisesSyncEnabled = $true }) })
        $a.Verdict | Should -Be 'NO'
        $a.ExitCode | Should -Be 1
        $r = Get-Reason $a 'SignInBlocked'
        $r.Level | Should -Be 'Blocker'
        $r.Message | Should -Match 'Sign-in is blocked'
        $r.Action | Should -Match 'on-premises AD'
        $r.Action | Should -Match 'M365-SyncedUserFixes'
    }

    It 'AC5_SignInBlocked: cloud-only user -> NO, next step points to the admin center' {
        $a = Get-M365UserAssessment -Facts (New-Facts @{ User = (New-User @{ accountEnabled = $false; onPremisesSyncEnabled = $null }) })
        $a.Verdict | Should -Be 'NO'
        $r = Get-Reason $a 'SignInBlocked'
        $r.Message | Should -Match 'Sign-in is blocked'
        $r.Action | Should -Match 'admin center'
        $r.Action | Should -Not -Match 'on-premises'
    }
}

Describe 'AC6 licence' {
    It 'AC6_NoUsableLicence: no assigned licences -> PROBABLY NOT, names that case' {
        $a = Get-M365UserAssessment -Facts (New-Facts @{ User = (New-User @{ assignedLicenses = @(); licenseAssignmentStates = @() }) })
        $a.Verdict | Should -Be 'PROBABLY NOT'
        $a.ExitCode | Should -Be 1
        $r = Get-Reason $a 'NoLicence'
        $r.Level | Should -Be 'Probable'
        $r.Message | Should -Match '(?i)no licen[cs]e'
        Get-Reason $a 'LicenceError' | Should -BeNullOrEmpty
    }

    It 'AC6_NoUsableLicence: a licence in state Error -> PROBABLY NOT, names the error value' {
        $u = New-User @{ licenseAssignmentStates = @(@{ skuId = 'bbbbbbbb-0000-0000-0000-000000000001'; state = 'Error'; error = 'CountViolation' }) }
        $a = Get-M365UserAssessment -Facts (New-Facts @{ User = $u })
        $a.Verdict | Should -Be 'PROBABLY NOT'
        $r = Get-Reason $a 'LicenceError'
        $r.Level | Should -Be 'Probable'
        $r.Message | Should -Match 'CountViolation'
        Get-Reason $a 'NoLicence' | Should -BeNullOrEmpty
    }

    It 'AC6_NoUsableLicence: a licensed user with Active state raises neither' {
        $a = Get-M365UserAssessment -Facts (New-Facts)
        Get-Reason $a 'NoLicence' | Should -BeNullOrEmpty
        Get-Reason $a 'LicenceError' | Should -BeNullOrEmpty
    }
}

Describe 'AC7 MFA' {
    It 'AC7_NoMfaMethod: password only -> Warning, verdict unchanged (YES)' {
        $methods = @(@{ '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod'; id = '28c10230-6103-485e-b985-444c60001490' })
        $a = Get-M365UserAssessment -Facts (New-Facts @{ MfaMethods = $methods })
        $r = Get-Reason $a 'NoMfaMethod'
        $r.Level | Should -Be 'Warning'
        $r.Message | Should -Match 'No MFA method registered'
        $a.Verdict | Should -Be 'YES'
    }

    It 'AC7_NoMfaMethod: an authenticator app means no warning' {
        $a = Get-M365UserAssessment -Facts (New-Facts)
        Get-Reason $a 'NoMfaMethod' | Should -BeNullOrEmpty
    }

    It 'AC7_NoMfaMethod: MFA list not readable -> Could not check, no warning either way' {
        $gate = New-M365Gate -Source 'MFA methods' -State NotAllowed -Reason 'the signed-in account cannot read authentication methods'
        $a = Get-M365UserAssessment -Facts (New-Facts @{ MfaGate = $gate; MfaMethods = @() })
        Get-Reason $a 'NoMfaMethod' | Should -BeNullOrEmpty
        @($a.CouldNotCheck | Where-Object { $_.Source -eq 'MFA methods' }).Count | Should -Be 1
    }
}

Describe 'AC8 no Entra ID P1' {
    It 'AC8_NoP1IsCouldNotCheck: the non-premium error is classified NotLicensed' {
        $g = Get-M365GateFromError -Source 'Sign-in history' -Message $script:NonP1Message
        $g.State | Should -Be 'NotLicensed'
        $g.Source | Should -Be 'Sign-in history'
    }

    It 'AC8_NoP1IsCouldNotCheck: the banner line reads exactly as the spec says' {
        $g = Get-M365GateFromError -Source 'Sign-in history' -Message $script:NonP1Message
        Format-M365SourceLine -Gate $g | Should -Be 'Sign-in history: not available (this tenant has no Entra ID P1)'
    }

    It 'AC8_NoP1IsCouldNotCheck: Could not check lists sign-in history, no pass claims it is fine, verdict is PROBABLY YES (D-006)' {
        $g = Get-M365GateFromError -Source 'Sign-in history' -Message $script:NonP1Message
        $a = Get-M365UserAssessment -Facts (New-Facts @{ SignInGate = $g; SignIns = @(); ConditionalAccessGate = (New-M365Gate -Source 'Conditional Access detail' -State NotLicensed -Reason 'no sign-in rows') })
        @($a.CouldNotCheck | Where-Object { $_.Source -eq 'Sign-in history' }).Count | Should -Be 1
        @($a.CouldNotCheck | Where-Object { $_.Source -eq 'Sign-in history' })[0].Reason | Should -Match 'no Entra ID P1'
        (@($a.Passes) -join "`n") | Should -Not -Match '(?i)no .*sign-in.*(problem|fail|error)|sign-in history|last sign-in'
        @($a.Cleared | Where-Object { $_.CouldLook -eq $true -and $_.Message -match '(?i)sign-in (history|problem|fail)' }).Count | Should -Be 0
        $a.Verdict | Should -Be 'PROBABLY YES'
        $a.VerdictNote | Should -Match 'sign-in history not available \(no Entra ID P1\)'
        $a.ExitCode | Should -Be 0
    }

    It 'AC8_NoP1IsCouldNotCheck: a blocker still wins over the non-P1 label' {
        $g = Get-M365GateFromError -Source 'Sign-in history' -Message $script:NonP1Message
        $a = Get-M365UserAssessment -Facts (New-Facts @{ SignInGate = $g; SignIns = @(); User = (New-User @{ accountEnabled = $false }) })
        $a.Verdict | Should -Be 'NO'
    }

    It 'AC8_NoP1IsCouldNotCheck: a probable cause still wins over the non-P1 label' {
        $g = Get-M365GateFromError -Source 'Sign-in history' -Message $script:NonP1Message
        $a = Get-M365UserAssessment -Facts (New-Facts @{ SignInGate = $g; SignIns = @(); User = (New-User @{ assignedLicenses = @(); licenseAssignmentStates = @() }) })
        $a.Verdict | Should -Be 'PROBABLY NOT'
    }
}

Describe 'AC9 forbidden is not the same as no P1' {
    It 'AC9_ForbiddenIsDistinctFromNoP1: another 403 is NotAllowed with role names and a different reason' {
        $p1 = Get-M365GateFromError -Source 'Sign-in history' -Message $script:NonP1Message
        $g = Get-M365GateFromError -Source 'Sign-in history' -Message $script:ForbiddenMessage
        $g.State | Should -Be 'NotAllowed'
        $g.Reason | Should -Match 'not allowed to read sign-in history'
        $g.Reason | Should -Match 'Reports Reader'
        $g.Reason | Should -Match 'Security Reader'
        $g.Reason | Should -Not -Match 'P1'
        $g.Reason | Should -Not -Be $p1.Reason
        Format-M365SourceLine -Gate $g | Should -Match '^Sign-in history: not available \(.*not allowed to read sign-in history'
    }

    It 'AC9_ForbiddenIsDistinctFromNoP1: Could not check carries the role reason and the verdict is never YES' {
        $g = Get-M365GateFromError -Source 'Sign-in history' -Message $script:ForbiddenMessage
        $a = Get-M365UserAssessment -Facts (New-Facts @{ SignInGate = $g; SignIns = @() })
        @($a.CouldNotCheck | Where-Object { $_.Source -eq 'Sign-in history' })[0].Reason | Should -Match 'not allowed to read sign-in history'
        $a.Verdict | Should -Not -Be 'YES'
    }

    It 'AC9_ForbiddenIsDistinctFromNoP1: an unrelated failure is Failed, not NotLicensed or NotAllowed' {
        $g = Get-M365GateFromError -Source 'Sign-in history' -Message 'The operation has timed out.'
        $g.State | Should -Be 'Failed'
    }
}

Describe 'AC10 blocking failure codes' {
    It 'AC10_BlockingFailureCodeIsNo: <code> -> NO with code, Microsoft text, count, time, link and the cited label' -ForEach @(
        @{ code = 50053 }, @{ code = 50057 }, @{ code = 50055 }, @{ code = 53003 }, @{ code = 530035 }
    ) {
        $reason = "Synthetic Microsoft failure text for $code."
        $rows = @(
            (New-SignInRow -Ago (New-TimeSpan -Hours 2) -Code $code -FailureReason $reason),
            (New-SignInRow -Ago (New-TimeSpan -Hours 3) -Code $code -FailureReason $reason),
            (New-SignInRow -Ago (New-TimeSpan -Hours 4) -Code $code -FailureReason $reason))
        $a = Get-M365UserAssessment -Facts (New-Facts @{ SignIns = $rows })
        $a.Verdict | Should -Be 'NO'
        $a.ExitCode | Should -Be 1
        $r = Get-Reason $a 'BlockingSignInFailure'
        $r.Level | Should -Be 'Blocker'
        $text = Get-ReasonText $r
        $text | Should -Match ([regex]::Escape("$code"))
        $text | Should -Match ([regex]::Escape($reason))
        $text | Should -Match ([regex]::Escape("https://login.microsoftonline.com/error?code=$code"))
        $text | Should -Match '\b3\b'
        $text | Should -Match '2026-10-17'
        $text | Should -Match 'meaning per Microsoft, may change'
    }

    It 'AC10_BlockingFailureCodeIsNo: the rows may arrive oldest first; the newest still decides' {
        $rows = @(
            (New-SignInRow -Ago (New-TimeSpan -Hours 5) -Code 0),
            (New-SignInRow -Ago (New-TimeSpan -Hours 1) -Code 50053 -FailureReason 'Locked.'))
        (Get-M365UserAssessment -Facts (New-Facts @{ SignIns = $rows })).Verdict | Should -Be 'NO'
    }
}

Describe 'AC11 unmapped failure code' {
    It 'AC11_UnmappedFailureCodeShowsMicrosoftText: <code> -> PROBABLY NOT with only code, text and link' -ForEach @(
        @{ code = 50140 }, @{ code = 99999 }
    ) {
        $reason = 'Synthetic failure text from the log.'
        $a = Get-M365UserAssessment -Facts (New-Facts @{ SignIns = @((New-SignInRow -Code $code -FailureReason $reason)) })
        $a.Verdict | Should -Be 'PROBABLY NOT'
        $r = Get-Reason $a 'UnmappedSignInFailure'
        $r.Level | Should -Be 'Probable'
        $text = Get-ReasonText $r
        $text | Should -Match ([regex]::Escape("$code"))
        $text | Should -Match ([regex]::Escape($reason))
        $text | Should -Match ([regex]::Escape("https://login.microsoftonline.com/error?code=$code"))
        $text | Should -Not -Match 'meaning per Microsoft'
        Get-Reason $a 'BlockingSignInFailure' | Should -BeNullOrEmpty
    }
}

Describe 'AC12 Conditional Access policy named' {
    It 'AC12_ConditionalAccessPolicyNamed: 53003 names the policy whose result is failure, not the passing one' {
        $policies = @(
            @{ displayName = 'Block legacy auth - contoso'; result = 'failure'; enforcedGrantControls = @('Block') },
            @{ displayName = 'Require MFA for all users'; result = 'success'; enforcedGrantControls = @('Mfa') })
        $rows = @((New-SignInRow -Code 53003 -FailureReason 'Access has been blocked by Conditional Access policies.' -Policies $policies))
        $a = Get-M365UserAssessment -Facts (New-Facts @{ SignIns = $rows })
        $text = Get-ReasonText (Get-Reason $a 'BlockingSignInFailure')
        $text | Should -Match ([regex]::Escape('Block legacy auth - contoso'))
        $text | Should -Not -Match 'Require MFA for all users'
    }
}

Describe 'AC13 Conditional Access detail hidden' {
    It 'AC13_ConditionalAccessDetailHidden: rows without the property -> gate is not Available and says role' {
        $rows = @((New-SignInRow -Code 0), (New-SignInRow -Code 0 -Ago (New-TimeSpan -Hours 2)))
        $rows[0].ContainsKey('appliedConditionalAccessPolicies') | Should -BeFalse
        $g = Get-M365ConditionalAccessGate -SignIns $rows
        $g.Source | Should -Be 'Conditional Access detail'
        $g.State | Should -Not -Be 'Available'
        $g.Reason | Should -Match '(?i)role'
    }

    It 'AC13_ConditionalAccessDetailHidden: rows that carry the property (even an empty list) -> Available' {
        $rows = @((New-SignInRow -Code 0 -Policies @()))
        $rows[0].ContainsKey('appliedConditionalAccessPolicies') | Should -BeTrue
        (Get-M365ConditionalAccessGate -SignIns $rows).State | Should -Be 'Available'
    }

    It 'AC13_ConditionalAccessDetailHidden: Could not check lists it and nothing rules Conditional Access out' {
        $g = Get-M365ConditionalAccessGate -SignIns @((New-SignInRow -Code 0))
        $a = Get-M365UserAssessment -Facts (New-Facts @{ ConditionalAccessGate = $g })
        @($a.CouldNotCheck | Where-Object { $_.Source -eq 'Conditional Access detail' }).Count | Should -Be 1
        (@($a.Passes) -join "`n") | Should -Not -Match 'Conditional Access'
        @($a.Cleared | Where-Object { $_.CouldLook -eq $true -and $_.Message -match 'Conditional Access' }).Count | Should -Be 0
    }
}

Describe 'AC14 latest sign-in decides' {
    It 'AC14_LatestSuccessPasses: success after failures -> pass, Info summary by code and count, verdict YES' {
        $rows = @(
            (New-SignInRow -Ago (New-TimeSpan -Hours 1) -Code 0 -App 'Microsoft Teams'),
            (New-SignInRow -Ago (New-TimeSpan -Hours 2) -Code 50126 -FailureReason 'Invalid username or password.'),
            (New-SignInRow -Ago (New-TimeSpan -Hours 3) -Code 50126 -FailureReason 'Invalid username or password.'),
            (New-SignInRow -Ago (New-TimeSpan -Hours 4) -Code 50053 -FailureReason 'Locked.'))
        $a = Get-M365UserAssessment -Facts (New-Facts @{ SignIns = $rows })
        (@($a.Passes) -join "`n") | Should -Match 'Last sign-in succeeded at .*\(Microsoft Teams\)'
        $info = Get-Reason $a 'OlderSignInFailures'
        $info.Level | Should -Be 'Info'
        $info.Message | Should -Match '50126'
        $info.Message | Should -Match '50053'
        $info.Message | Should -Match '(50126[^\d]{1,12}2\b)|(\b2[^\d]{1,12}50126)'
        @($a.Reasons | Where-Object { $_.Level -in 'Blocker', 'Probable' }).Count | Should -Be 0
        $a.Verdict | Should -Be 'YES'
        $a.ExitCode | Should -Be 0
    }
}

Describe 'AC15 no sign-ins in the window' {
    It 'AC15_NoSignInsInWindow: history Available but empty -> Info line, not a pass' {
        $a = Get-M365UserAssessment -Facts (New-Facts @{ SignIns = @(); Days = 7 })
        $r = Get-Reason $a 'NoSignInsInWindow'
        $r.Level | Should -Be 'Info'
        $r.Message | Should -Match 'no sign-in attempts reached Microsoft 365 in the last 7 days'
        (@($a.Passes) -join "`n") | Should -Not -Match '(?i)last sign-in|attempt|no .*sign-in.*(problem|fail|error)'
        $a.Verdict | Should -Be 'YES'
    }

    It 'AC15_NoSignInsInWindow: the day count follows -Days' {
        $a = Get-M365UserAssessment -Facts (New-Facts @{ SignIns = @(); Days = 30 })
        (Get-Reason $a 'NoSignInsInWindow').Message | Should -Match 'last 30 days'
    }
}

Describe 'AC16 risky user' {
    It 'AC16_RiskyUserGatedOnP2: licence error -> NotLicensed, banner line and Could not check' {
        $g = Get-M365GateFromError -Source 'Risky user' -Message $script:NonP1Message
        $g.State | Should -Be 'NotLicensed'
        Format-M365SourceLine -Gate $g | Should -Be 'Risky user: not available (needs Entra ID P2)'
        $a = Get-M365UserAssessment -Facts (New-Facts @{ RiskGate = $g })
        @($a.CouldNotCheck | Where-Object { $_.Source -eq 'Risky user' }).Count | Should -Be 1
        Get-Reason $a 'RiskyUser' | Should -BeNullOrEmpty
    }

    It 'AC16_RiskyUserGatedOnP2: high risk or atRisk -> Warning naming level and state, verdict unchanged' {
        $a = Get-M365UserAssessment -Facts (New-Facts @{ RiskyUser = @{ id = 'aaaaaaaa-0000-0000-0000-000000000001'; riskLevel = 'high'; riskState = 'atRisk' } })
        $r = Get-Reason $a 'RiskyUser'
        $r.Level | Should -Be 'Warning'
        $r.Message | Should -Match 'high'
        $r.Message | Should -Match 'atRisk'
        $a.Verdict | Should -Be 'YES'
    }

    It 'Edge_RiskyUser404IsNotFlagged: NotFound means the user was never flagged (Available, no warning)' {
        $g = Get-M365GateFromError -Source 'Risky user' -Message $script:NotFoundMessage
        $g.State | Should -Be 'Available'
        $a = Get-M365UserAssessment -Facts (New-Facts @{ RiskGate = $g; RiskyUser = $null })
        Get-Reason $a 'RiskyUser' | Should -BeNullOrEmpty
        @($a.CouldNotCheck | Where-Object { $_.Source -eq 'Risky user' }).Count | Should -Be 0
    }
}

Describe 'Edge cases' {
    It 'Edge_SingleObjectCount: one sign-in row, one reason, still assessed (Windows PowerShell .Count trap)' {
        $a = Get-M365UserAssessment -Facts (New-Facts @{ SignIns = (New-SignInRow -Code 50053 -FailureReason 'Locked.') })
        $a.Verdict | Should -Be 'NO'
    }

    It 'Edge_MissingVersusNullProperty: a user with no onPremisesSyncEnabled key is cloud-only' {
        $u = New-User @{ accountEnabled = $false }
        $u.Remove('onPremisesSyncEnabled')
        $a = Get-M365UserAssessment -Facts (New-Facts @{ User = $u })
        (Get-Reason $a 'SignInBlocked').Action | Should -Match 'admin center'
    }
}
