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

    # SQ-011 review: a file-level Get-ADUser that THROWS. A test that forgets to mock it fails
    # loudly instead of reaching a domain controller (the Describes below shadow it with their
    # own stub and Mock). Real parameter names, as in the stubs below.
    function Get-ADUser {
        [CmdletBinding()]
        param($Identity, $LDAPFilter, $Filter, $Server, [pscredential]$Credential, $Properties, $SearchBase, $ResultSetSize)
        throw 'Get-ADUser was called without a Mock: a test must never reach a real domain controller.'
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

    It 'AC10_BlockingFailureOlderThanADay: the reason says how many days ago and to try again first' {
        $rows = @((New-SignInRow -Ago (New-TimeSpan -Days 3 -Hours 2) -Code 50053 -FailureReason 'Locked.'))
        $r = Get-Reason (Get-M365UserAssessment -Facts (New-Facts @{ SignIns = $rows })) 'BlockingSignInFailure'
        $r.Message | Should -Match 'This was 3 days ago - ask them to try again first'
    }

    It 'AC10_BlockingFailureWithinADay: a recent block carries no "days ago" note' {
        $rows = @((New-SignInRow -Ago (New-TimeSpan -Hours 23) -Code 50053 -FailureReason 'Locked.'))
        $r = Get-Reason (Get-M365UserAssessment -Facts (New-Facts @{ SignIns = $rows })) 'BlockingSignInFailure'
        $r.Message | Should -Not -Match 'days? ago'
    }
}

Describe 'Mapped but not blocking: 50126' {
    It 'LatestSignInFailed_50126: wrong password -> PROBABLY NOT, cited next step and the lookup link' {
        $rows = @((New-SignInRow -Code 50126 -FailureReason 'Error validating credentials due to invalid username or password.'))
        $a = Get-M365UserAssessment -Facts (New-Facts @{ SignIns = $rows })
        $a.Verdict | Should -Be 'PROBABLY NOT'
        $a.ExitCode | Should -Be 1
        $r = Get-Reason $a 'LatestSignInFailed'
        $r.Level | Should -Be 'Probable'
        $text = Get-ReasonText $r
        $text | Should -Match 'meaning per Microsoft, may change'
        $text | Should -Match ([regex]::Escape('https://login.microsoftonline.com/error?code=50126'))
        $text | Should -Match ([regex]::Escape('invalid username or password'))
        Get-Reason $a 'BlockingSignInFailure' | Should -BeNullOrEmpty
    }
}

Describe 'Personal data and CSV safety' {
    It 'Select-M365SignInFields: keeps the needed fields, drops device detail, keeps CA results' {
        $row = New-SignInRow -Code 53003 -Policies @(@{ id = 'p1'; displayName = 'Block'; result = 'failure'; enforcedGrantControls = @('Block') })
        $row['deviceDetail'] = @{ displayName = 'LAPTOP-123'; operatingSystem = 'Windows' }
        $row['userAgent'] = 'Mozilla/5.0'
        $t = Select-M365SignInFields -Row $row
        $t.ContainsKey('deviceDetail') | Should -BeFalse
        $t.ContainsKey('userAgent') | Should -BeFalse
        $t.status.errorCode | Should -Be 53003
        $t.location.city | Should -Be 'Springfield'
        $t.ipAddress | Should -Be '203.0.113.7'
        @($t.appliedConditionalAccessPolicies)[0].displayName | Should -Be 'Block'
        @($t.appliedConditionalAccessPolicies)[0].ContainsKey('enforcedGrantControls') | Should -BeFalse
    }

    It 'Select-M365SignInFields: a row WITHOUT appliedConditionalAccessPolicies stays without it (AC13 depends on absence)' {
        $t = Select-M365SignInFields -Row (New-SignInRow -Code 0)
        $t.ContainsKey('appliedConditionalAccessPolicies') | Should -BeFalse
        (Get-M365ConditionalAccessGate -SignIns @($t)).State | Should -Not -Be 'Available'
        $e = Select-M365SignInFields -Row (New-SignInRow -Code 0 -Policies @())
        $e.ContainsKey('appliedConditionalAccessPolicies') | Should -BeTrue
        (Get-M365ConditionalAccessGate -SignIns @($e)).State | Should -Be 'Available'
    }

    It 'ConvertTo-M365CsvValue: <in> -> <out>' -ForEach @(
        @{ in = '=1+1'; out = '''=1+1' }, @{ in = '+cmd'; out = '''+cmd' }, @{ in = '-2'; out = '''-2' },
        @{ in = '@SUM(A1)'; out = '''@SUM(A1)' }, @{ in = "`tx"; out = "'`tx" },
        @{ in = 'Jane Doe'; out = 'Jane Doe' }, @{ in = ''; out = '' },
        @{ in = 'from 203.0.113.7 today'; out = 'from [IP removed] today' }
    ) {
        ConvertTo-M365CsvValue -Text $in | Should -BeExactly $out
    }
}

Describe 'Fallback lookup requests' {
    It 'Find-M365User: mail and proxy address are separate requests, merged by id' {
        $script:Uris = New-Object System.Collections.Generic.List[string]
        Mock Invoke-MgGraphRequest {
            $u = [uri]::UnescapeDataString([string]$Uri)
            $script:Uris.Add($u)
            if ($u -match 'userPrincipalName eq') { return @{ value = @() } }
            return @{ value = @(@{ id = 'same-id'; displayName = 'Jane Doe'; userPrincipalName = 'jane@contoso.com'; accountEnabled = $true }) }
        }
        $r = Find-M365User -UserPrincipalName 'jdoe@contoso.com'
        $r.Status | Should -Be 'Found'
        # Compare the $filter part only: $select also names mail and proxyAddresses.
        $filters = @($script:Uris | ForEach-Object { [regex]::Match($_, '\$filter=(?<f>[^&]*)').Groups['f'].Value })
        @($filters | Where-Object { $_ -eq "mail eq 'jdoe@contoso.com'" }).Count | Should -Be 1
        @($filters | Where-Object { $_ -eq "proxyAddresses/any(p:p eq 'smtp:jdoe@contoso.com')" }).Count | Should -Be 1
        @($filters | Where-Object { $_ -match '\bor\b' }).Count | Should -Be 0
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

# =============================================================================
# SQ-011, on-premises AD comparison: AC18-AC25 (spec squad/specs/SQ-002.md Part B)
#
# PINNED INTERFACE ADDED BY SQ-011 (the implementer must honour these names and shapes):
#   Facts gains (all optional; read with Get-M365Prop, an absent key means "not collected"):
#     OnPremisesGate   gate for 'On-premises AD'. Only when State is Available are the AD facts used.
#     AdUser           $null, or the AD account as a hashtable/object with: Enabled, UserPrincipalName,
#                      mail, proxyAddresses, DistinguishedName, SamAccountName, pwdLastSet,
#                      'msDS-cloudExtensionAttribute10'.
#     AdMatchedBy      'SID' or 'UserPrincipalName'.
#     AddressConflicts array of [PSCustomObject]{ Type 'user'|'group'|'contact'; DisplayName; Address; Id }
#                      (objects OTHER than the cloud user that hold the AD user's UPN or primary SMTP).
#     TenantLastSync   ISO string, the organization's onPremisesLastSyncDateTime, or $null.
#   Facts.User may be $null (no Microsoft 365 user; AC20). Then the source gates other than
#   OnPremisesGate are NotChecked and must not add reasons.
#   Reason codes: NeverSynced (Blocker; the BlockCloudSignIn marker only changes its text),
#     ProvisioningError (Blocker), AddressHeld (Blocker), BlockedOnPurpose (Info),
#     AdEnabledMismatch (Probable), StaleTenantSync (Warning), UpnMismatch (Warning).
#     Pass codes in Cleared: CloudOnly, TenantSyncRecent.
#   Block marker: msDS-cloudExtensionAttribute10 = 'BlockCloudSignIn'
#     (M365-SyncedUserFixes/SyncedUserFixes.Core.ps1:111-112).
#   Stale means STRICTLY more than 3 hours old; exactly 3 hours is a pass.
#   Format-M365SourceLine for source 'On-premises AD' in any state but Available reads
#     "On-premises AD: could not check (<Reason>)" (other sources keep "not available (...)").
#   Get-M365OnPremisesFacts -User <cloud user or $null> -UserPrincipalName <upn> [-Server <string>]
#     [-Credential <pscredential>] -> [PSCustomObject]{ Gate; AdUser; AdMatchedBy; AddressConflicts }.
#     Runtime Import-Module ActiveDirectory in try/catch (failure -> Gate Failed, reason names the
#     module); Get-ADUser -Identity <SID> first (when the cloud user has onPremisesSecurityIdentifier),
#     else Get-ADUser -LDAPFilter with RFC 4515 escaping; -Properties includes
#     msDS-cloudExtensionAttribute10, proxyAddresses, mail, pwdLastSet, Enabled,
#     UserPrincipalName, DistinguishedName; -Server/-Credential passed through when given.
#     "Cannot find an object with identity" = not found (fall back / Available with AdUser $null);
#     any other Get-ADUser error = Gate Failed (no DC). Conflicts: GET only, users/groups/contacts
#     filtered on the AD UPN and primary SMTP (proxyAddresses entry starting 'SMTP:', else mail);
#     the cloud user's own id is never a conflict.
# =============================================================================

Describe 'SQ-011 on-premises comparison, pure assessment' {
    BeforeAll {
        $script:Sid = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
        function New-AdUser {
            param([hashtable]$Set = @{})
            $a = @{
                Enabled = $true; UserPrincipalName = 'jdoe@contoso.com'; mail = 'jdoe@contoso.com'
                proxyAddresses = @('SMTP:jdoe@contoso.com'); SamAccountName = 'jdoe'
                DistinguishedName = 'CN=Jane Doe,OU=Staff,DC=contoso,DC=com'; pwdLastSet = 133700000000000000
                'msDS-cloudExtensionAttribute10' = $null
            }
            foreach ($k in $Set.Keys) { $a[$k] = $Set[$k] }
            return $a
        }
        function New-SyncedUser {
            param([hashtable]$Set = @{})
            $s = @{ onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = $script:Sid; onPremisesProvisioningErrors = @() }
            foreach ($k in $Set.Keys) { $s[$k] = $Set[$k] }
            return (New-User $s)
        }
        function New-AdGate { param([string]$State = 'Available', [string]$Reason) New-M365Gate -Source 'On-premises AD' -State $State -Reason $Reason }
        # Synced, healthy, AD agrees. Override any Facts property.
        function New-HybridFacts {
            param([hashtable]$Override = @{}, [hashtable]$UserSet = @{})
            $o = @{
                User = (New-SyncedUser $UserSet); OnPremisesGate = (New-AdGate); AdUser = (New-AdUser); AdMatchedBy = 'SID'
                AddressConflicts = @(); TenantLastSync = ($script:Now - (New-TimeSpan -Minutes 20)).ToString('yyyy-MM-ddTHH:mm:ssZ')
            }
            foreach ($k in $Override.Keys) { $o[$k] = $Override[$k] }
            return (New-Facts $o)
        }
        function New-NoCloudUserFacts {
            param([object]$AdUser)
            $nc = 'no Microsoft 365 user'
            return (New-Facts @{
                    User = $null; OnPremisesGate = (New-AdGate); AdUser = $AdUser; AdMatchedBy = 'UserPrincipalName'
                    SignInGate = (New-M365Gate -Source 'Sign-in history' -State NotChecked -Reason $nc)
                    ConditionalAccessGate = (New-M365Gate -Source 'Conditional Access detail' -State NotChecked -Reason $nc)
                    MfaGate = (New-M365Gate -Source 'MFA methods' -State NotChecked -Reason $nc)
                    RiskGate = (New-M365Gate -Source 'Risky user' -State NotChecked -Reason $nc)
                    SignIns = @(); MfaMethods = @()
                })
        }
    }

    It 'AC18_AdStageUnavailableStillGivesVerdict: gate Failed -> still a verdict from Graph, AD under Could not check with its reason, no AD reasons' {
        $g = New-AdGate -State Failed -Reason 'no domain controller answered'
        $a = Get-M365UserAssessment -Facts (New-HybridFacts @{ OnPremisesGate = $g; AdUser = $null })
        $a.Verdict | Should -Be 'YES'
        $a.ExitCode | Should -Be 0
        $c = @($a.CouldNotCheck | Where-Object { $_.Source -eq 'On-premises AD' })
        $c.Count | Should -Be 1
        $c[0].Reason | Should -Match 'no domain controller answered'
        foreach ($code in 'NeverSynced', 'AdEnabledMismatch', 'UpnMismatch', 'AddressHeld', 'BlockedOnPurpose') { Get-Reason $a $code | Should -BeNullOrEmpty }
        ($a.Passes -join "`n") | Should -Not -Match 'Cloud-only'
    }

    It 'AC18_AdStageUnavailableStillGivesVerdict: the banner line reads "On-premises AD: could not check (<reason>)"' {
        $line = Format-M365SourceLine -Gate (New-AdGate -State Failed -Reason 'the ActiveDirectory module is not installed on this computer')
        $line | Should -Be 'On-premises AD: could not check (the ActiveDirectory module is not installed on this computer)'
        (Format-M365SourceLine -Gate (New-AdGate)) | Should -Be 'On-premises AD: available'
        (Format-M365SourceLine -Gate (New-M365Gate -Source 'Risky user' -State NotLicensed -Reason 'needs Entra ID P2')) | Should -Be 'Risky user: not available (needs Entra ID P2)'
    }

    It 'AC18_AdStageUnavailableStillGivesVerdict: -SkipOnPremises (NotChecked) is also Could not check, and a blocker still gives NO' {
        $g = New-AdGate -State NotChecked -Reason 'skipped with -SkipOnPremises'
        $a = Get-M365UserAssessment -Facts (New-HybridFacts @{ OnPremisesGate = $g; AdUser = $null } @{ accountEnabled = $false })
        $a.Verdict | Should -Be 'NO'
        @($a.CouldNotCheck | Where-Object { $_.Source -eq 'On-premises AD' }).Count | Should -Be 1
    }

    It 'AC19_CloudOnlySkipsAd: cloud-only user, AD searched and empty -> pass "Cloud-only account: sync is not involved"' {
        $f = New-Facts @{ OnPremisesGate = (New-AdGate); AdUser = $null; AddressConflicts = @(); TenantLastSync = $null }
        $a = Get-M365UserAssessment -Facts $f
        ($a.Passes -join "`n") | Should -Match 'Cloud-only account: sync is not involved'
        @($a.Cleared | Where-Object { $_.Code -eq 'CloudOnly' }).Count | Should -Be 1
        $a.Verdict | Should -Be 'YES'
        Get-Reason $a 'StaleTenantSync' | Should -BeNullOrEmpty
    }

    It 'AC19_CloudOnlySkipsAd: no cloud-only pass when AD was not searched (gate not Available)' {
        $f = New-Facts @{ OnPremisesGate = (New-AdGate -State NotChecked -Reason 'skipped with -SkipOnPremises'); AdUser = $null }
        $a = Get-M365UserAssessment -Facts $f
        ($a.Passes -join "`n") | Should -Not -Match 'Cloud-only'
    }

    It 'AC20_NeverSynced: no cloud user, AD user exists -> NO, "exists in AD but not in Microsoft 365", names sync scope (OU) and Entra Connect' {
        $a = Get-M365UserAssessment -Facts (New-NoCloudUserFacts -AdUser (New-AdUser))
        $a.Verdict | Should -Be 'NO'
        $a.ExitCode | Should -Be 1
        $r = Get-Reason $a 'NeverSynced'
        $r.Level | Should -Be 'Blocker'
        $r.Message | Should -Match 'This account exists in AD but not in Microsoft 365'
        (Get-ReasonText $r) | Should -Match '(?i)\bOU\b'
        (Get-ReasonText $r) | Should -Match 'Entra Connect'
        (Get-ReasonText $r) | Should -Not -Match 'on purpose'
    }

    It 'AC20_NeverSynced: AD user carries BlockCloudSignIn -> reason says removed from Microsoft 365 on purpose by M365-SyncedUserFixes' {
        $ad = New-AdUser @{ 'msDS-cloudExtensionAttribute10' = 'BlockCloudSignIn' }
        $a = Get-M365UserAssessment -Facts (New-NoCloudUserFacts -AdUser $ad)
        $a.Verdict | Should -Be 'NO'
        $r = Get-Reason $a 'NeverSynced'
        $r.Level | Should -Be 'Blocker'
        (Get-ReasonText $r) | Should -Match 'on purpose'
        (Get-ReasonText $r) | Should -Match 'M365-SyncedUserFixes'
        (Get-ReasonText $r) | Should -Not -Match 'OU filtering' -Because 'the marker replaces the sync-scope advice'
    }

    It 'AC21_ProvisioningErrorNamesConflict: onPremisesProvisioningErrors entry -> NO, reason shows category, property and value' {
        $err = @{ category = 'PropertyConflict'; propertyCausingError = 'ProxyAddresses'; value = 'smtp:jdoe@contoso.com'; occurredDateTime = '2026-10-16T09:00:00Z' }
        $a = Get-M365UserAssessment -Facts (New-HybridFacts -UserSet @{ onPremisesProvisioningErrors = @($err) })
        $a.Verdict | Should -Be 'NO'
        $r = Get-Reason $a 'ProvisioningError'
        $r.Level | Should -Be 'Blocker'
        $r.Message | Should -Match 'PropertyConflict'
        $r.Message | Should -Match 'ProxyAddresses'
        $r.Message | Should -Match 'smtp:jdoe@contoso\.com'
    }

    It 'AC21_ProvisioningErrorNamesConflict: an empty list, or no such key, adds no reason' {
        (Get-Reason (Get-M365UserAssessment -Facts (New-HybridFacts)) 'ProvisioningError') | Should -BeNullOrEmpty
        $u = New-SyncedUser; $u.Remove('onPremisesProvisioningErrors')
        (Get-Reason (Get-M365UserAssessment -Facts (New-HybridFacts @{ User = $u })) 'ProvisioningError') | Should -BeNullOrEmpty
    }

    It 'AC22_AddressHeldByAnotherObject: a group holds the address -> NO, reason names the type and display name' {
        $c = [PSCustomObject]@{ Type = 'group'; DisplayName = 'Sales Team'; Address = 'jdoe@contoso.com'; Id = 'eeeeeeee-0000-0000-0000-000000000001' }
        $a = Get-M365UserAssessment -Facts (New-HybridFacts @{ AddressConflicts = @($c) })
        $a.Verdict | Should -Be 'NO'
        $r = Get-Reason $a 'AddressHeld'
        $r.Level | Should -Be 'Blocker'
        $r.Message | Should -Match 'group'
        $r.Message | Should -Match 'Sales Team'
        $r.Message | Should -Match 'jdoe@contoso\.com'
    }

    It 'AC22_AddressHeldByAnotherObject: a cloud-only user and a contact are named too' {
        $c1 = [PSCustomObject]@{ Type = 'user'; DisplayName = 'Jane Doe (cloud copy)'; Address = 'jdoe@contoso.com'; Id = 'eeeeeeee-0000-0000-0000-000000000002' }
        $c2 = [PSCustomObject]@{ Type = 'contact'; DisplayName = 'J Doe External'; Address = 'jdoe@contoso.com'; Id = 'eeeeeeee-0000-0000-0000-000000000003' }
        $a = Get-M365UserAssessment -Facts (New-HybridFacts @{ AddressConflicts = @($c1, $c2) })
        $text = (@($a.Reasons | Where-Object { $_.Code -eq 'AddressHeld' }) | ForEach-Object { $_.Message }) -join "`n"
        $text | Should -Match 'Jane Doe \(cloud copy\)'
        $text | Should -Match 'J Doe External'
        $text | Should -Match 'contact'
    }

    It 'AC22_AddressHeldByAnotherObject: no conflicts -> no AddressHeld reason' {
        (Get-Reason (Get-M365UserAssessment -Facts (New-HybridFacts)) 'AddressHeld') | Should -BeNullOrEmpty
    }

    It 'AC22_AddressHeldByAnotherObject: the next step escalates and never tells tier 1 to remove or delete anything (D-017)' {
        foreach ($type in 'user', 'group', 'contact') {
            $c = [PSCustomObject]@{ Type = $type; DisplayName = 'Holder'; Address = 'jdoe@contoso.com'; Id = 'eeeeeeee-0000-0000-0000-000000000001'; Synced = $false }
            $r = Get-Reason (Get-M365UserAssessment -Facts (New-HybridFacts @{ AddressConflicts = @($c) })) 'AddressHeld'
            $r.Action | Should -Match ([regex]::Escape("Escalate to a senior engineer before removing the address or deleting anything (deleted groups and contacts can't be restored)"))
            $r.Action | Should -Not -Match '(?i)remove the address from it|delete it'
        }
    }

    It 'AC22_AddressHeldByAnotherObject: a user holding the address is labelled by its real sync state, not always "cloud-only"' {
        $synced = [PSCustomObject]@{ Type = 'user'; DisplayName = 'Jane Doe (old)'; Address = 'jdoe@contoso.com'; Id = 'eeeeeeee-0000-0000-0000-000000000002'; Synced = $true }
        $r = Get-Reason (Get-M365UserAssessment -Facts (New-HybridFacts @{ AddressConflicts = @($synced) })) 'AddressHeld'
        $r.Message | Should -Match 'a synced user'
        $r.Message | Should -Not -Match 'cloud-only'
        $cloud = [PSCustomObject]@{ Type = 'user'; DisplayName = 'Jane Doe (copy)'; Address = 'jdoe@contoso.com'; Id = 'eeeeeeee-0000-0000-0000-000000000003'; Synced = $false }
        (Get-Reason (Get-M365UserAssessment -Facts (New-HybridFacts @{ AddressConflicts = @($cloud) })) 'AddressHeld').Message | Should -Match 'a cloud-only user'
    }

    It 'AC22_AddressHeldByAnotherObject: a conflict found AND a failed lookup -> NO (the found Blocker decides) and "Address conflicts" under Could not check' {
        $c = [PSCustomObject]@{ Type = 'user'; DisplayName = 'Jane Doe (cloud copy)'; Address = 'jdoe@contoso.com'; Id = 'eeeeeeee-0000-0000-0000-000000000002'; Synced = $false }
        $a = Get-M365UserAssessment -Facts (New-HybridFacts @{ AddressConflicts = @($c); AddressCheckError = 'groups by mail: Insufficient privileges to complete the operation' })
        $a.Verdict | Should -Be 'NO'
        (Get-Reason $a 'AddressHeld').Message | Should -Match 'Jane Doe \(cloud copy\)'
        @($a.CouldNotCheck | Where-Object { $_.Source -eq 'Address conflicts' }).Count | Should -Be 1
    }

    It 'AC25b_SidMismatchWarns: fires only when the AD account was matched by sign-in name, not for any other AdMatchedBy value' {
        $a = Get-M365UserAssessment -Facts (New-HybridFacts @{ AdMatchedBy = '' })
        Get-Reason $a 'SidMismatch' | Should -BeNullOrEmpty
    }

    It 'AC23_EnabledMismatch: AD enabled + cloud blocked + marker -> Info "on purpose", blocker next step says remove the marker with M365-SyncedUserFixes' {
        $ad = New-AdUser @{ Enabled = $true; 'msDS-cloudExtensionAttribute10' = 'BlockCloudSignIn' }
        $a = Get-M365UserAssessment -Facts (New-HybridFacts @{ AdUser = $ad } @{ accountEnabled = $false })
        $a.Verdict | Should -Be 'NO'
        $i = Get-Reason $a 'BlockedOnPurpose'
        $i.Level | Should -Be 'Info'
        $i.Message | Should -Match 'on purpose'
        (Get-Reason $a 'AdEnabledMismatch') | Should -BeNullOrEmpty
        (Get-Reason $a 'SignInBlocked').Action | Should -Match 'remove the marker'
        (Get-Reason $a 'SignInBlocked').Action | Should -Match 'M365-SyncedUserFixes'
    }

    It 'AC23_EnabledMismatch: AD enabled + cloud blocked, no marker -> Probable "disagree" with the tenant last sync time' {
        $a = Get-M365UserAssessment -Facts (New-HybridFacts @{ TenantLastSync = '2026-10-17T13:40:00Z' } @{ accountEnabled = $false })
        $r = Get-Reason $a 'AdEnabledMismatch'
        $r.Level | Should -Be 'Probable'
        $r.Message | Should -Match 'disagree'
        (Get-ReasonText $r) | Should -Match '2026-10-17 13:40 UTC'
        (Get-Reason $a 'BlockedOnPurpose') | Should -BeNullOrEmpty
        $a.Verdict | Should -Be 'NO' -Because 'the cloud block is still a Blocker'
    }

    It 'AC23_EnabledMismatch: both sides disabled agree -> no mismatch reason' {
        $a = Get-M365UserAssessment -Facts (New-HybridFacts @{ AdUser = (New-AdUser @{ Enabled = $false }) } @{ accountEnabled = $false })
        (Get-Reason $a 'AdEnabledMismatch') | Should -BeNullOrEmpty
        (Get-Reason $a 'BlockedOnPurpose') | Should -BeNullOrEmpty
    }

    It 'AC24_StaleTenantSync: last sync 4 hours old -> Warning with its age and "every 30 minutes"; verdict unchanged' {
        $a = Get-M365UserAssessment -Facts (New-HybridFacts @{ TenantLastSync = ($script:Now - (New-TimeSpan -Hours 4)).ToString('yyyy-MM-ddTHH:mm:ssZ') })
        $r = Get-Reason $a 'StaleTenantSync'
        $r.Level | Should -Be 'Warning'
        $r.Message | Should -Match '4 hours'
        (Get-ReasonText $r) | Should -Match '30 minutes'
        $a.Verdict | Should -Be 'YES'
    }

    It 'AC24_StaleTenantSync: under 3 hours -> pass showing the time, no warning' {
        $a = Get-M365UserAssessment -Facts (New-HybridFacts @{ TenantLastSync = '2026-10-17T12:30:00Z' })
        Get-Reason $a 'StaleTenantSync' | Should -BeNullOrEmpty
        ($a.Passes -join "`n") | Should -Match '2026-10-17 12:30 UTC'
        @($a.Cleared | Where-Object { $_.Code -eq 'TenantSyncRecent' }).Count | Should -Be 1
    }

    It 'Edge_TenantSyncExactlyThreeHoursOld: not stale (more than 3 hours is the rule); one second over is' {
        $exact = Get-M365UserAssessment -Facts (New-HybridFacts @{ TenantLastSync = ($script:Now - (New-TimeSpan -Hours 3)).ToString('yyyy-MM-ddTHH:mm:ssZ') })
        Get-Reason $exact 'StaleTenantSync' | Should -BeNullOrEmpty
        $over = Get-M365UserAssessment -Facts (New-HybridFacts @{ TenantLastSync = ($script:Now - (New-TimeSpan -Hours 3 -Seconds 1)).ToString('yyyy-MM-ddTHH:mm:ssZ') })
        (Get-Reason $over 'StaleTenantSync').Level | Should -Be 'Warning'
    }

    It 'Edge_TenantSyncUnknown: no last-sync value -> no stale warning and no "recent" pass' {
        $a = Get-M365UserAssessment -Facts (New-HybridFacts @{ TenantLastSync = $null })
        Get-Reason $a 'StaleTenantSync' | Should -BeNullOrEmpty
        @($a.Cleared | Where-Object { $_.Code -eq 'TenantSyncRecent' }).Count | Should -Be 0
    }

    It 'AC25_UpnMismatch: AD UPN differs from the cloud UPN -> Warning showing both, verdict unchanged' {
        $ad = New-AdUser @{ UserPrincipalName = 'jane.doe@contoso.com' }
        $a = Get-M365UserAssessment -Facts (New-HybridFacts @{ AdUser = $ad })
        $r = Get-Reason $a 'UpnMismatch'
        $r.Level | Should -Be 'Warning'
        $r.Message | Should -Match 'jane\.doe@contoso\.com'
        $r.Message | Should -Match 'jdoe@contoso\.com'
        $a.Verdict | Should -Be 'YES'
    }

    It 'AC25_UpnMismatch: same UPN in different case -> no warning' {
        $ad = New-AdUser @{ UserPrincipalName = 'JDoe@Contoso.com' }
        Get-Reason (Get-M365UserAssessment -Facts (New-HybridFacts @{ AdUser = $ad })) 'UpnMismatch' | Should -BeNullOrEmpty
    }

    It 'AC25b_SidMismatchWarns: synced user, AD account found only by sign-in name -> Warning "SID differs", no AdAgrees pass, verdict unchanged' {
        $a = Get-M365UserAssessment -Facts (New-HybridFacts @{ AdMatchedBy = 'UserPrincipalName' })
        $r = Get-Reason $a 'SidMismatch'
        $r.Level | Should -Be 'Warning'
        $r.Message | Should -Match ([regex]::Escape('AD account found by sign-in name, but its SID differs from the one Microsoft 365 holds (recreated account?)'))
        @($a.Cleared | Where-Object { $_.Code -eq 'AdAgrees' }).Count | Should -Be 0
        ($a.Passes -join "`n") | Should -Not -Match 'agrees with Microsoft 365'
        $a.Verdict | Should -Be 'YES'
    }

    It 'AC25b_SidMismatchWarns: matched by SID -> no SID warning and the AdAgrees pass stays' {
        $a = Get-M365UserAssessment -Facts (New-HybridFacts)
        Get-Reason $a 'SidMismatch' | Should -BeNullOrEmpty
        @($a.Cleared | Where-Object { $_.Code -eq 'AdAgrees' }).Count | Should -Be 1
    }

    It 'AC25b_SidMismatchWarns: a synced user with no SID value to compare is not accused of a mismatch' {
        $u = New-SyncedUser; $u.Remove('onPremisesSecurityIdentifier')
        $a = Get-M365UserAssessment -Facts (New-HybridFacts @{ User = $u; AdMatchedBy = 'UserPrincipalName' })
        Get-Reason $a 'SidMismatch' | Should -BeNullOrEmpty
    }

    It 'AC22c_AddressCheckFailedIsCouldNotCheck: AddressCheckError -> CouldNotCheck lists "Address conflicts" with the error, not only an Info reason' {
        $a = Get-M365UserAssessment -Facts (New-HybridFacts @{ AddressCheckError = 'Forbidden: Insufficient privileges to complete the operation' })
        $c = @($a.CouldNotCheck | Where-Object { $_.Source -eq 'Address conflicts' })
        $c.Count | Should -Be 1
        $c[0].Reason | Should -Match 'Insufficient privileges'
        @($a.Reasons | Where-Object { $_.Code -eq 'AddressCheckFailed' -and $_.Level -eq 'Info' }).Count | Should -Be 0 -Because 'it is a Could not check item, not an Info reason'
    }

    It 'AC22c_AddressCheckFailedIsCouldNotCheck: no error -> no "Address conflicts" entry' {
        $a = Get-M365UserAssessment -Facts (New-HybridFacts)
        @($a.CouldNotCheck | Where-Object { $_.Source -eq 'Address conflicts' }).Count | Should -Be 0
    }

    It 'AC22c_AddressCheckFailedIsCouldNotCheck: the Could not check line reads "Address conflicts: <reason>"' {
        $line = Format-M365CouldNotCheckLine -Item ([PSCustomObject]@{ Source = 'Address conflicts'; Reason = 'the lookup failed' })
        $line | Should -Be 'Address conflicts: the lookup failed'
    }

    It 'AC22c_AddressCheckFailedHedgesVerdict: nothing else blocks but the address lookup failed -> PROBABLY YES (exit 0) with the reason as the note; with no sign-in history too, both notes' {
        $a = Get-M365UserAssessment -Facts (New-HybridFacts @{ AddressCheckError = 'Forbidden: Insufficient privileges to complete the operation' })
        $a.Verdict | Should -Be 'PROBABLY YES'
        $a.ExitCode | Should -Be 0
        $a.VerdictNote | Should -Be 'could not check whether another Microsoft 365 object holds its addresses'
        $noP1 = New-M365Gate -Source 'Sign-in history' -State NotLicensed -Reason 'this tenant has no Entra ID P1'
        $both = Get-M365UserAssessment -Facts (New-HybridFacts @{ AddressCheckError = 'Forbidden'; SignInGate = $noP1 })
        $both.Verdict | Should -Be 'PROBABLY YES'
        $both.VerdictNote | Should -Be 'sign-in history not available (no Entra ID P1); could not check whether another Microsoft 365 object holds its addresses'
        $blocked = Get-M365UserAssessment -Facts (New-HybridFacts @{ AddressCheckError = 'Forbidden'; AdUser = (New-AdUser @{ Enabled = $false }) } @{ accountEnabled = $false })
        $blocked.Verdict | Should -Be 'NO' -Because 'a blocker still decides'
    }

    It 'AC20b_NeverSyncedChecksSid: the SID lookup in Microsoft 365 failed -> PROBABLY NOT (not NO), "Microsoft 365 account by SID" under Could not check' {
        $f = New-NoCloudUserFacts -AdUser (New-AdUser)
        $f | Add-Member -NotePropertyName CloudSidCheckError -NotePropertyValue 'the request failed: Service unavailable'
        $a = Get-M365UserAssessment -Facts $f
        $r = Get-Reason $a 'NeverSynced'
        $r.Level | Should -Be 'Probable'
        $r.Message | Should -Match 'exists in AD but not in Microsoft 365'
        $r.Message | Should -Match 'not ruled out'
        $a.Verdict | Should -Be 'PROBABLY NOT'
        $c = @($a.CouldNotCheck | Where-Object { $_.Source -eq 'Microsoft 365 account by SID' })
        $c.Count | Should -Be 1
        $c[0].Reason | Should -Match 'Service unavailable'
    }

    It 'Edge_HealthyHybridAccount: synced, AD agrees, nothing held, recent sync -> YES with no AD reasons' {
        $a = Get-M365UserAssessment -Facts (New-HybridFacts)
        $a.Verdict | Should -Be 'YES'
        foreach ($code in 'NeverSynced', 'ProvisioningError', 'AddressHeld', 'AdEnabledMismatch', 'StaleTenantSync', 'UpnMismatch', 'BlockedOnPurpose') { Get-Reason $a $code | Should -BeNullOrEmpty }
        @($a.CouldNotCheck | Where-Object { $_.Source -eq 'On-premises AD' }).Count | Should -Be 0
    }

    It 'Edge_ExistingFactsWithoutAdKeys: Facts built before SQ-011 (no OnPremisesGate/AdUser keys) still assess' {
        $a = Get-M365UserAssessment -Facts (New-Facts)
        $a.Verdict | Should -Be 'YES'
    }
}

Describe 'SQ-011 Get-M365OnPremisesFacts (AD and Graph faked)' {
    BeforeAll {
        $script:Sid = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
        # Stub with the real parameter names (Get-ADUser: Identity, LDAPFilter, Filter, Server,
        # Credential, Properties, SearchBase, ResultSetSize; checked with Get-Command).
        function Get-ADUser {
            [CmdletBinding()]
            param($Identity, $LDAPFilter, $Filter, $Server, [pscredential]$Credential, $Properties, $SearchBase, $ResultSetSize)
        }
        function New-AdUserObj { @{ Enabled = $true; UserPrincipalName = 'jdoe@contoso.com'; mail = 'jdoe@contoso.com'; proxyAddresses = @('SMTP:jdoe@contoso.com', 'smtp:alias@contoso.com'); SamAccountName = 'jdoe'; DistinguishedName = 'CN=Jane Doe,OU=Staff,DC=contoso,DC=com'; 'msDS-cloudExtensionAttribute10' = $null } }
        $script:NotFoundAd = 'Cannot find an object with identity: ''S-1-5-21-1111111111-2222222222-3333333333-1105'' under: ''DC=contoso,DC=com''.'
        $script:NoDcAd = 'Unable to contact the server. This may be because this server does not exist, it is currently down, or it does not have the Active Directory Web Services running.'
    }
    BeforeEach {
        $script:AdCalls = New-Object System.Collections.Generic.List[hashtable]
        $script:ImportThrows = $false; $script:AdBySid = (New-AdUserObj); $script:AdByFilter = @(); $script:AdThrow = $null
        $script:GraphUris = New-Object System.Collections.Generic.List[string]
        $script:ConflictUsers = @(); $script:ConflictGroups = @(); $script:ConflictContacts = @()
        Mock Import-Module { if ($script:ImportThrows -and $Name -eq 'ActiveDirectory') { throw 'The specified module ''ActiveDirectory'' was not loaded because no valid module file was found in any module directory.' } }
        Mock Get-ADUser {
            $script:AdCalls.Add(@{ Identity = $Identity; LDAPFilter = $LDAPFilter; Server = $Server; Credential = $Credential; Properties = @($Properties) })
            if ($script:AdThrow) { throw $script:AdThrow }
            # Pester 5.7 leaves $PSBoundParameters empty in a mock body without param(); the
            # bound value is still in $Identity.
            if ($null -ne $Identity) {
                if ($null -eq $script:AdBySid) { throw $script:NotFoundAd }
                return $script:AdBySid
            }
            return @($script:AdByFilter)
        }
        Mock Invoke-MgGraphRequest {
            $u = [uri]::UnescapeDataString([string]$Uri)
            $script:GraphUris.Add("$Method $u")
            if ($u -match '/groups') { return @{ value = @($script:ConflictGroups) } }
            if ($u -match '/contacts') { return @{ value = @($script:ConflictContacts) } }
            if ($u -match '/users') { return @{ value = @($script:ConflictUsers) } }
            return @{ value = @() }
        }
    }

    It 'AC18_AdStageUnavailableStillGivesVerdict: ActiveDirectory module cannot be imported -> Gate Failed naming the module, Get-ADUser never called' {
        $script:ImportThrows = $true
        $r = Get-M365OnPremisesFacts -User (New-User @{ onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = $script:Sid }) -UserPrincipalName 'jdoe@contoso.com'
        $r.Gate.Source | Should -Be 'On-premises AD'
        $r.Gate.State | Should -Be 'Failed'
        $r.Gate.Reason | Should -Match 'ActiveDirectory'
        $r.AdUser | Should -BeNullOrEmpty
        Should -Invoke Get-ADUser -Times 0 -Exactly
    }

    It 'AC18_AdStageUnavailableStillGivesVerdict: no domain controller answers -> Gate Failed with a reason, no exception' {
        $script:AdThrow = $script:NoDcAd
        $r = Get-M365OnPremisesFacts -User (New-User @{ onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = $script:Sid }) -UserPrincipalName 'jdoe@contoso.com'
        $r.Gate.State | Should -Be 'Failed'
        $r.Gate.Reason | Should -Not -BeNullOrEmpty
        $r.Gate.Reason | Should -Match '(?i)domain controller|Active Directory Web Services|contact'
    }

    It 'AC25_UpnMismatch: matches by on-premises SID first (Get-ADUser -Identity <SID>), no UPN search needed' {
        $r = Get-M365OnPremisesFacts -User (New-User @{ onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = $script:Sid }) -UserPrincipalName 'jdoe@contoso.com'
        $r.Gate.State | Should -Be 'Available'
        $r.AdMatchedBy | Should -Be 'SID'
        $r.AdUser.SamAccountName | Should -Be 'jdoe'
        $script:AdCalls.Count | Should -Be 1
        $script:AdCalls[0].Identity | Should -Be $script:Sid
        foreach ($p in 'msDS-cloudExtensionAttribute10', 'proxyAddresses', 'mail', 'pwdLastSet', 'Enabled', 'UserPrincipalName', 'DistinguishedName') {
            $script:AdCalls[0].Properties | Should -Contain $p
        }
    }

    It 'AC25_UpnMismatch: SID not found in AD -> falls back to the UPN with an RFC 4515 escaped LDAP filter' {
        $script:AdBySid = $null; $script:AdByFilter = @((New-AdUserObj))
        $r = Get-M365OnPremisesFacts -User (New-User @{ onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = $script:Sid }) -UserPrincipalName 'j(doe)*@contoso.com'
        $r.AdMatchedBy | Should -Be 'UserPrincipalName'
        $r.Gate.State | Should -Be 'Available'
        $script:AdCalls.Count | Should -Be 2
        $script:AdCalls[1].LDAPFilter | Should -Match ([regex]::Escape('userPrincipalName=j\28doe\29\2a@contoso.com'))
    }

    It 'AC19_CloudOnlySkipsAd: cloud-only user -> exactly one Get-ADUser call (the UPN search, no -Identity); nothing found = Available with AdUser empty' {
        $r = Get-M365OnPremisesFacts -User (New-User) -UserPrincipalName 'jdoe@contoso.com'
        $r.Gate.State | Should -Be 'Available'
        $r.AdUser | Should -BeNullOrEmpty
        $script:AdCalls.Count | Should -Be 1
        $script:AdCalls[0].Identity | Should -BeNullOrEmpty
        $script:AdCalls[0].LDAPFilter | Should -Match 'userPrincipalName=jdoe@contoso\.com'
        @($r.AddressConflicts).Count | Should -Be 0
        @($script:GraphUris).Count | Should -Be 0 -Because 'with no AD account there is nothing to look up in Graph'
    }

    It 'AC20_NeverSynced: no cloud user (User $null) -> finds the AD account by UPN' {
        $script:AdByFilter = @((New-AdUserObj))
        $r = Get-M365OnPremisesFacts -User $null -UserPrincipalName 'jdoe@contoso.com'
        $r.AdUser.SamAccountName | Should -Be 'jdoe'
        $r.AdMatchedBy | Should -Be 'UserPrincipalName'
        $r.Gate.State | Should -Be 'Available'
    }

    It 'AC20b_NeverSyncedChecksSid: no cloud user, the AD account''s SID is held by one cloud user -> SyncedCloudUser, and no address lookup for the wrong (null) user' {
        $ad = New-AdUserObj; $ad['SID'] = New-Object System.Security.Principal.SecurityIdentifier ($script:Sid)
        $script:AdByFilter = @($ad)
        $script:SidCloud = New-User @{ userPrincipalName = 'jane.doe@contoso.com'; onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = $script:Sid }
        Mock Invoke-MgGraphRequest {
            $u = [uri]::UnescapeDataString([string]$Uri)
            $script:GraphUris.Add("$Method $u")
            if ($u -match '/users\?.*onPremisesSecurityIdentifier eq ') { return @{ value = @($script:SidCloud) } }
            return @{ value = @() }
        }
        $r = Get-M365OnPremisesFacts -User $null -UserPrincipalName 'jdoe@contoso.com'
        $r.SyncedCloudUser.userPrincipalName | Should -Be 'jane.doe@contoso.com'
        $r.CloudSidCheckError | Should -BeNullOrEmpty
        @($script:GraphUris).Count | Should -Be 1 -Because 'the address lookups belong to the cloud user, which the caller assesses next'
        $script:GraphUris[0] | Should -Match ("^GET .*/users\?\`$filter=onPremisesSecurityIdentifier eq '{0}'" -f [regex]::Escape($script:Sid))
        $script:GraphUris[0] | Should -Match 'onPremisesSecurityIdentifier,' -Because 'the user is selected with the fields the assessment needs'
    }

    It 'AC20b_NeverSyncedChecksSid: the SID lookup throws -> CloudSidCheckError set, gate still Available, address lookups still run' {
        $ad = New-AdUserObj; $ad['SID'] = New-Object System.Security.Principal.SecurityIdentifier ($script:Sid)
        $script:AdByFilter = @($ad)
        Mock Invoke-MgGraphRequest {
            $u = [uri]::UnescapeDataString([string]$Uri)
            $script:GraphUris.Add("$Method $u")
            if ($u -match 'onPremisesSecurityIdentifier eq ') { throw 'Response status code does not indicate success: ServiceUnavailable (Service Unavailable).' }
            return @{ value = @() }
        }
        $r = Get-M365OnPremisesFacts -User $null -UserPrincipalName 'jdoe@contoso.com'
        $r.Gate.State | Should -Be 'Available'
        $r.SyncedCloudUser | Should -BeNullOrEmpty
        $r.CloudSidCheckError | Should -Match 'ServiceUnavailable'
        @($script:GraphUris | Where-Object { $_ -match 'mail eq ' }).Count | Should -BeGreaterThan 0
    }

    It 'Edge_ServerAndCredentialPassThrough: -Server is passed to Get-ADUser; neither given means neither is passed' {
        $null = Get-M365OnPremisesFacts -User $null -UserPrincipalName 'jdoe@contoso.com' -Server 'dc01.contoso.com'
        $script:AdCalls[0].Server | Should -Be 'dc01.contoso.com'
        $script:AdCalls.Clear()
        $null = Get-M365OnPremisesFacts -User $null -UserPrincipalName 'jdoe@contoso.com'
        $script:AdCalls[0].Server | Should -BeNullOrEmpty
        $script:AdCalls[0].Credential | Should -BeNullOrEmpty
    }

    It 'AC22_AddressHeldByAnotherObject: groups, contacts and other users holding the address are returned (type, name, address); own id excluded; GET only' {
        $script:ConflictUsers = @(
            @{ id = 'aaaaaaaa-0000-0000-0000-000000000001'; displayName = 'Jane Doe'; userPrincipalName = 'jdoe@contoso.com' },
            @{ id = 'eeeeeeee-0000-0000-0000-000000000002'; displayName = 'Jane Doe (cloud copy)'; userPrincipalName = 'jdoe@contoso.com' })
        $script:ConflictGroups = @(@{ id = 'eeeeeeee-0000-0000-0000-000000000001'; displayName = 'Sales Team'; mail = 'jdoe@contoso.com' })
        $script:ConflictContacts = @(@{ id = 'eeeeeeee-0000-0000-0000-000000000003'; displayName = 'J Doe External'; mail = 'jdoe@contoso.com' })
        $r = Get-M365OnPremisesFacts -User (New-User @{ onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = $script:Sid }) -UserPrincipalName 'jdoe@contoso.com'
        $c = @($r.AddressConflicts)
        $c.Count | Should -Be 3
        @($c | Where-Object { $_.Id -eq 'aaaaaaaa-0000-0000-0000-000000000001' }).Count | Should -Be 0
        (@($c | Where-Object { $_.Type -eq 'group' })[0]).DisplayName | Should -Be 'Sales Team'
        (@($c | Where-Object { $_.Type -eq 'contact' })[0]).DisplayName | Should -Be 'J Doe External'
        (@($c | Where-Object { $_.Type -eq 'user' })[0]).DisplayName | Should -Be 'Jane Doe (cloud copy)'
        @($script:GraphUris | Where-Object { $_ -notmatch '^GET ' }).Count | Should -Be 0
        @($script:GraphUris | Where-Object { $_ -match '/groups' }).Count | Should -BeGreaterThan 0
        @($script:GraphUris | Where-Object { $_ -match '/contacts' }).Count | Should -BeGreaterThan 0
        @($script:GraphUris | Where-Object { $_ -match 'jdoe@contoso\.com' }).Count | Should -BeGreaterThan 0
    }

    It 'AC22_AddressHeldByAnotherObject: only the PRIMARY smtp address (SMTP:) is looked up, not secondary aliases' {
        $null = Get-M365OnPremisesFacts -User (New-User @{ onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = $script:Sid }) -UserPrincipalName 'jdoe@contoso.com'
        @($script:GraphUris | Where-Object { $_ -match 'alias@contoso\.com' }).Count | Should -Be 0
    }

    It 'AC22b_AddressConflictFieldsMatch: the AD UPN is looked up only as userPrincipalName; the primary SMTP only as mail/proxyAddresses' {
        # AD UPN differs from the primary SMTP, as in many tenants (jdoe@ vs jane.doe@).
        $script:AdBySid = @{ Enabled = $true; UserPrincipalName = 'jdoe@contoso.com'; mail = 'jane.doe@contoso.com'; proxyAddresses = @('SMTP:jane.doe@contoso.com'); SamAccountName = 'jdoe'; DistinguishedName = 'CN=Jane Doe,OU=Staff,DC=contoso,DC=com' }
        $null = Get-M365OnPremisesFacts -User (New-User @{ onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = $script:Sid }) -UserPrincipalName 'jdoe@contoso.com'
        $uris = @($script:GraphUris)
        $upnLookups = @($uris | Where-Object { $_ -match 'jdoe@contoso\.com' })
        $upnLookups.Count | Should -BeGreaterThan 0
        foreach ($u in $upnLookups) { $u | Should -Match '/users\?.*userPrincipalName eq ' -Because "the UPN is matched to userPrincipalName only: $u" }
        $smtpLookups = @($uris | Where-Object { $_ -match 'jane\.doe@contoso\.com' })
        $smtpLookups.Count | Should -BeGreaterThan 0
        foreach ($u in $smtpLookups) { $u | Should -Not -Match 'userPrincipalName eq' -Because "the primary SMTP is never matched to a UPN: $u" }
        @($smtpLookups | Where-Object { $_ -match 'mail eq ' }).Count | Should -BeGreaterThan 0
        @($smtpLookups | Where-Object { $_ -match 'proxyAddresses' }).Count | Should -BeGreaterThan 0
        @($uris | Where-Object { $_ -match '/(groups|contacts)' -and $_ -match 'jdoe@contoso\.com' }).Count | Should -Be 0 -Because 'groups and contacts have no sign-in name'
    }

    It 'AC22b_AddressConflictFieldsMatch: another user whose UPN equals this user''s primary SMTP is not a conflict; one whose mail equals it is' {
        $script:AdBySid = @{ Enabled = $true; UserPrincipalName = 'jdoe@contoso.com'; mail = 'jane.doe@contoso.com'; proxyAddresses = @('SMTP:jane.doe@contoso.com'); SamAccountName = 'jdoe'; DistinguishedName = 'CN=Jane Doe,OU=Staff,DC=contoso,DC=com' }
        # A fake that answers by the field in the $filter, as Graph does.
        Mock Invoke-MgGraphRequest {
            $u = [uri]::UnescapeDataString([string]$Uri)
            $script:GraphUris.Add("$Method $u")
            if ($u -match '/users\?.*userPrincipalName eq ''jane\.doe@contoso\.com''') { return @{ value = @(@{ id = 'eeeeeeee-0000-0000-0000-00000000000a'; displayName = 'Jane Doe (UPN only)' }) } }
            if ($u -match '/users\?.*mail eq ''jane\.doe@contoso\.com''') { return @{ value = @(@{ id = 'eeeeeeee-0000-0000-0000-00000000000b'; displayName = 'Jane Doe (mail holder)' }) } }
            return @{ value = @() }
        }
        $r = Get-M365OnPremisesFacts -User (New-User @{ onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = $script:Sid }) -UserPrincipalName 'jdoe@contoso.com'
        $names = @($r.AddressConflicts | ForEach-Object DisplayName)
        $names | Should -Not -Contain 'Jane Doe (UPN only)'
        $names | Should -Contain 'Jane Doe (mail holder)'
    }

    It 'AC25b_SidMismatchWarns: SID not found, UPN match -> the facts say AdMatchedBy UserPrincipalName, which the assessment warns on' {
        $script:AdBySid = $null; $script:AdByFilter = @((New-AdUserObj))
        $r = Get-M365OnPremisesFacts -User (New-User @{ onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = $script:Sid }) -UserPrincipalName 'jdoe@contoso.com'
        $r.AdMatchedBy | Should -Be 'UserPrincipalName'
        $r.AdUser | Should -Not -BeNullOrEmpty
        $facts = New-Facts @{ User = (New-User @{ onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = $script:Sid }); OnPremisesGate = $r.Gate; AdUser = $r.AdUser; AdMatchedBy = $r.AdMatchedBy }
        (Get-Reason (Get-M365UserAssessment -Facts $facts) 'SidMismatch').Level | Should -Be 'Warning'
    }

    It 'AC22_AddressHeldByAnotherObject: /users finds another user holding the AD sign-in name, then /groups is refused (403) -> the conflict is kept AND the failed lookups are recorded; the assessment says NO' {
        $script:ConflictUsers = @(@{ id = 'eeeeeeee-0000-0000-0000-000000000002'; displayName = 'Jane Doe (cloud copy)'; onPremisesSyncEnabled = $null })
        Mock Invoke-MgGraphRequest {
            $u = [uri]::UnescapeDataString([string]$Uri)
            $script:GraphUris.Add("$Method $u")
            if ($u -match '/groups') { throw $script:ForbiddenMessage }
            if ($u -match '/users') { return @{ value = @($script:ConflictUsers) } }
            return @{ value = @() }
        }
        $r = Get-M365OnPremisesFacts -User (New-User @{ onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = $script:Sid }) -UserPrincipalName 'jdoe@contoso.com'
        $r.Gate.State | Should -Be 'Available'
        @($r.AddressConflicts | Where-Object { $_.DisplayName -eq 'Jane Doe (cloud copy)' }).Count | Should -Be 1 -Because 'a conflict already found must not be thrown away by a later failed lookup'
        $r.AddressCheckError | Should -Match 'groups'
        $r.AddressCheckError | Should -Match 'Insufficient privileges'
        $r.AddressCheckError | Should -Not -Match 'users|contacts' -Because 'only the lookups that failed are named'
        @($script:GraphUris | Where-Object { $_ -match '/contacts' }).Count | Should -BeGreaterThan 0 -Because 'the lookups after the failed one still run'
        $facts = New-Facts @{ User = (New-User @{ onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = $script:Sid }); OnPremisesGate = $r.Gate; AdUser = $r.AdUser; AdMatchedBy = $r.AdMatchedBy
            AddressConflicts = @($r.AddressConflicts); AddressCheckError = $r.AddressCheckError }
        $a = Get-M365UserAssessment -Facts $facts
        $a.Verdict | Should -Be 'NO'
        (@($a.Reasons | Where-Object { $_.Code -eq 'AddressHeld' })[0]).Message | Should -Match 'Jane Doe \(cloud copy\)'
        @($a.CouldNotCheck | Where-Object { $_.Source -eq 'Address conflicts' }).Count | Should -Be 1
    }

    It 'AC22_AddressHeldByAnotherObject: the user lookups select onPremisesSyncEnabled, and the conflict carries the holder''s sync state' {
        $script:ConflictUsers = @(@{ id = 'eeeeeeee-0000-0000-0000-000000000002'; displayName = 'Jane Doe (old)'; onPremisesSyncEnabled = $true })
        $r = Get-M365OnPremisesFacts -User (New-User @{ onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = $script:Sid }) -UserPrincipalName 'jdoe@contoso.com'
        foreach ($u in @($script:GraphUris | Where-Object { $_ -match '/users\?' })) { $u | Should -Match 'select=id,displayName,onPremisesSyncEnabled' }
        $c = @($r.AddressConflicts | Where-Object { $_.Type -eq 'user' })
        $c.Count | Should -Be 1
        $c[0].Synced | Should -BeTrue
    }

    It 'AC20b_NeverSyncedChecksSid: the AD account came back without a SID -> CloudSidCheckError says so (never an unhedged NO), no SID search sent' {
        $script:AdByFilter = @((New-AdUserObj))
        $r = Get-M365OnPremisesFacts -User $null -UserPrincipalName 'jdoe@contoso.com'
        $r.Gate.State | Should -Be 'Available'
        $r.CloudSidCheckError | Should -Match ([regex]::Escape("the AD account's SID was not returned"))
        @($script:GraphUris | Where-Object { $_ -match 'onPremisesSecurityIdentifier' }).Count | Should -Be 0
    }

    It 'AC22c_AddressCheckFailedIsCouldNotCheck: a failing Graph lookup sets AddressCheckError and the assessment lists Address conflicts under Could not check' {
        Mock Invoke-MgGraphRequest { throw 'Response status code does not indicate success: Forbidden (Forbidden). {"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."}}' }
        $r = Get-M365OnPremisesFacts -User (New-User @{ onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = $script:Sid }) -UserPrincipalName 'jdoe@contoso.com'
        $r.Gate.State | Should -Be 'Available'
        $r.AddressCheckError | Should -Not -BeNullOrEmpty
        $facts = New-Facts @{ User = (New-User @{ onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = $script:Sid }); OnPremisesGate = $r.Gate; AdUser = $r.AdUser; AdMatchedBy = $r.AdMatchedBy; AddressCheckError = $r.AddressCheckError }
        $a = Get-M365UserAssessment -Facts $facts
        @($a.CouldNotCheck | Where-Object { $_.Source -eq 'Address conflicts' }).Count | Should -Be 1
    }
}

Describe 'SQ-011 test safety (core)' {
    It 'the file-level Get-ADUser stub throws when a test forgets to mock it' {
        { Get-ADUser -Identity 'jdoe' } | Should -Throw '*without a Mock*'
    }
}

Describe 'SQ-011 mocks cannot lie about Get-ADUser parameter names' {
    # SQUAD.md "Mocks can lie": where RSAT is installed, check the stub above and the core's
    # calls against the real Get-ADUser. Run in a child pwsh so this session keeps the stub.
    BeforeAll {
        $script:RealAdParams = @()
        # ADPS_LoadDefaultDrive = 0 stops the module mapping the AD: drive, which contacts a DC.
        $json = & pwsh -NoProfile -Command @'
$env:ADPS_LoadDefaultDrive = 0
$c = Get-Command Get-ADUser -Module ActiveDirectory -ErrorAction SilentlyContinue
if ($c) { @($c.Parameters.Keys) | ConvertTo-Json -Compress }
'@
        if ($json) { $script:RealAdParams = @($json | ConvertFrom-Json) }
    }

    It 'the Get-ADUser stub and every Get-ADUser call in the core use parameters the real cmdlet has' {
        if ($script:RealAdParams.Count -eq 0) { Set-ItResult -Skipped -Because 'the ActiveDirectory module (RSAT) is not installed'; return }
        foreach ($p in 'Identity', 'LDAPFilter', 'Filter', 'Server', 'Credential', 'Properties', 'SearchBase', 'ResultSetSize') {
            $script:RealAdParams | Should -Contain $p -Because "the stub declares -$p"
        }
        $tokens = $null; $errs = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:CorePath, [ref]$tokens, [ref]$errs)
        $calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Get-ADUser' }, $true))
        $calls.Count | Should -BeGreaterThan 0
        $real = @($script:RealAdParams) + [System.Management.Automation.PSCmdlet]::CommonParameters
        foreach ($c in $calls) {
            foreach ($e in @($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] })) {
                @($real | Where-Object { $_ -like "$($e.ParameterName)*" }).Count | Should -BeGreaterThan 0 -Because "line $($c.Extent.StartLineNumber) uses -$($e.ParameterName)"
            }
        }
    }
}
