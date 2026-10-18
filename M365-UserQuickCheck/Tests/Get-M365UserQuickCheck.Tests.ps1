<#
    Tests for M365-UserQuickCheck\Get-M365UserQuickCheck.ps1 (Pester 5, run under pwsh).
    SQ-002, Graph stage: AC1-AC3, AC17 and AC26-AC28, plus end-to-end checks of AC4, AC8, AC10.

    The script is RUN (never loaded) with Microsoft Graph and the clipboard faked:
      Connect-MgGraph, Get-MgContext, Disconnect-MgGraph, Invoke-MgGraphRequest, Import-Module,
      Set-Clipboard, Write-Host are mocked. Invoke-MgGraphRequest dispatches on -Uri to the
      synthetic scenario in $script:Scn. Nothing connects to Graph or AD; the real clipboard and
      the user profile are never touched (-NoClipboard, -OutputPath under $TestDrive).
      Synthetic data only (contoso.com, jdoe, 203.0.113.x).

    PINNED INTERFACE (the implementer must honour these):
      Parameters: -UserPrincipalName (position 0, mandatory), -TenantId, -DisableWam, -UseDeviceCode,
        -Days, -Server, -Credential, -SkipOnPremises, -OutputPath, -TicketNumber, -NoClipboard,
        -PassThru, -Quiet, -LoadFunctionsOnly. With -PassThru the script returns the result object
        INSTEAD of calling exit: { Status; ExitCode; Message; Candidates; Assessment; TicketNote }
        (same as Get-ADUserQuickCheck.ps1). Without it, exit <ExitCode>.
      Console: banner, source lines and verdict go through Write-Host (the tests capture it).
        Verdict line: "Can Jane Doe sign in to Microsoft 365?  <VERDICT>".
      Wrong tenant / not found messages: 'No Microsoft 365 user matched', and the UPN domain and
        the tenant display name in the wrong-tenant message.
      Graph calls: only Invoke-MgGraphRequest -Method GET; the scenario fakes return HASHTABLES.
      Report files: M365UserCheck_<safe-upn>_<yyyy-MM-dd_HHmmss>.html / .csv, safe-upn =
        UPN with [^\w.-] replaced by _ (jdoe_contoso.com). With -TicketNumber the folder is
        <OutputPath>\Ticket_<n> (as AD-UserQuickCheck), note file Note_*.txt from CaseKit.

    Run:  Invoke-Pester .\M365-UserQuickCheck\Tests
#>

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:Entry = Join-Path $script:Root 'Get-M365UserQuickCheck.ps1'

    # Stubs carry the real parameter names (Microsoft.Graph.Authentication; checked below).
    function Connect-MgGraph {
        [CmdletBinding()]
        param([string[]]$Scopes, [string]$TenantId, [string]$ClientId, $ContextScope, [string]$Environment,
            [switch]$UseDeviceCode, [double]$ClientTimeout, [switch]$NoWelcome)
    }
    function Get-MgContext { [CmdletBinding()] param() }
    function Disconnect-MgGraph { [CmdletBinding()] param() }
    function Invoke-MgGraphRequest {
        [CmdletBinding()]
        param($Method, [uri]$Uri, $Body, $Headers, $OutputFilePath, $InputFilePath, [switch]$PassThru,
            [switch]$SkipHeaderValidation, $ContentType, $SessionVariable, $ResponseHeadersVariable,
            $StatusCodeVariable, [switch]$SkipHttpErrorCheck, $GraphRequestSession, $UserAgent, $OutputType)
    }
    function Set-Clipboard { [CmdletBinding()] param([Parameter(ValueFromPipeline = $true)][AllowEmptyString()][string[]]$Value, [switch]$Append, [switch]$AsHtml) }
    # SQ-011 review: a file-level Get-ADUser that THROWS, so a test that forgets to mock it fails
    # loudly instead of reaching a domain controller (the AD Describe shadows it with its own stub
    # and Mock). Real parameter names.
    function Get-ADUser {
        [CmdletBinding()]
        param($Identity, $LDAPFilter, $Filter, $Server, [pscredential]$Credential, $Properties, $SearchBase, $ResultSetSize)
        throw 'Get-ADUser was called without a Mock: a test must never reach a real domain controller.'
    }

    $script:TenantId = '11111111-2222-3333-4444-555555555555'
    $script:UserId = 'aaaaaaaa-0000-0000-0000-000000000001'
    $script:NonP1Body = '{"error":{"code":"Authentication_RequestFromNonPremiumTenantOrB2CTenant","message":"Neither tenant is B2C or tenant doesn''t have premium license"}}'

    function New-User {
        param([hashtable]$Set = @{})
        $u = @{
            id = $script:UserId; displayName = 'Jane Doe'; userPrincipalName = 'jdoe@contoso.com'
            mail = 'jdoe@contoso.com'; accountEnabled = $true; userType = 'Member'; onPremisesSyncEnabled = $null
            assignedLicenses = @(@{ skuId = 'bbbbbbbb-0000-0000-0000-000000000001'; disabledPlans = @() })
            licenseAssignmentStates = @(@{ skuId = 'bbbbbbbb-0000-0000-0000-000000000001'; state = 'Active'; error = 'None' })
            proxyAddresses = @('SMTP:jdoe@contoso.com')
        }
        foreach ($k in $Set.Keys) { $u[$k] = $Set[$k] }
        $u
    }
    function New-SignInRow {
        param([int]$MinutesAgo = 60, [int]$Code = 0, [string]$FailureReason = 'Other.', [object]$Policies = @(), [string]$Ip = '203.0.113.7')
        $row = @{
            id = [guid]::NewGuid().ToString(); createdDateTime = ([datetime]::UtcNow.AddMinutes(-$MinutesAgo)).ToString('yyyy-MM-ddTHH:mm:ssZ')
            appDisplayName = 'Office 365 Exchange Online'; clientAppUsed = 'Browser'; ipAddress = $Ip
            location = @{ city = 'Springfield'; countryOrRegion = 'US' }
            status = @{ errorCode = $Code; failureReason = $FailureReason; additionalDetails = $null }
        }
        if ($null -ne $Policies) { $row['appliedConditionalAccessPolicies'] = @($Policies) }
        $row
    }
    function New-Scenario {
        param([hashtable]$Override = @{})
        $s = @{
            TenantName = 'Contoso Ltd'; Me = 'admin@contoso.com'; Roles = @('Global Administrator')
            Domains = @('contoso.com', 'contoso.onmicrosoft.com')
            UpnMatches = @((New-User)); FallbackMatches = @()
            SignIns = @((New-SignInRow)); SignInStatus = $null; SignInBody = $null
            MfaMethods = @(@{ '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod'; id = '28c10230-6103-485e-b985-444c60001490' },
                @{ '@odata.type' = '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'; id = 'cccccccc-0000-0000-0000-000000000001' })
            RiskyUser = $null; RiskyStatus = 'NotFound'; ThrowOnUsers = $false
            SidMatches = @(); ThrowOnGroups = $false
        }
        foreach ($k in $Override.Keys) { $s[$k] = $Override[$k] }
        $script:Scn = $s
    }
    function Get-FakeGraphError([string]$Status, [string]$Body) {
        'Response status code does not indicate success: {0} ({0}). {1}' -f $Status, $Body
    }

    function Invoke-Entry {
        param([hashtable]$Extra = @{})
        $script:Events = New-Object System.Collections.Generic.List[string]
        $splat = @{ UserPrincipalName = 'jdoe@contoso.com'; NoClipboard = $true; PassThru = $true; SkipOnPremises = $true }
        foreach ($k in $Extra.Keys) { $splat[$k] = $Extra[$k] }
        $script:LastError = $null
        # Dot-sourced, not '&': a script run with '&' gets its own script scope, and the mock
        # bodies above would then resolve $script:Events / $script:Scn in THAT scope (null).
        try { $out = @(. $script:Entry @splat) } catch { $script:LastError = $_; $out = @() }
        if ($out.Count -gt 0) { return $out[-1] }
        return $null
    }
    function Get-HostText { ($script:Events | Where-Object { $_ -like 'HOST:*' } | ForEach-Object { $_.Substring(5) }) -join "`n" }
    function Get-Section([string[]]$Lines, [string]$Header) {
        $i = [array]::IndexOf($Lines, $Header)
        if ($i -lt 0) { return @() }
        $out = @()
        for ($j = $i + 1; $j -lt $Lines.Count; $j++) {
            if ($Lines[$j] -match '^(Checked|Ruled out|Could not check|Next step):$' -or $Lines[$j] -eq '') { break }
            $out += $Lines[$j]
        }
        $out
    }
    # The Graph fake: dispatches on -Uri to the synthetic scenario in $script:Scn.
    $script:FakeGraph = {
        $u = [uri]::UnescapeDataString([string]$Uri)
        $script:Events.Add("GET $u")
        $s = $script:Scn
        switch -Regex ($u) {
            '/me/(transitive)?memberOf' { return @{ value = @($s.Roles | ForEach-Object { @{ '@odata.type' = '#microsoft.graph.directoryRole'; displayName = $_ } }) } }
            '/me\b' { return @{ id = 'dddddddd-0000-0000-0000-000000000001'; userPrincipalName = $s.Me; displayName = 'Admin Tech' } }
            '/organization' {
                return @{ value = @(@{ id = $script:TenantId; displayName = $s.TenantName; onPremisesLastSyncDateTime = $null
                            verifiedDomains = @($s.Domains | ForEach-Object { @{ name = $_; isDefault = ($_ -eq $s.Domains[0]); isInitial = ($_ -like '*.onmicrosoft.com') } }) }) }
            }
            '/domains' { return @{ value = @($s.Domains | ForEach-Object { @{ id = $_; isVerified = $true; isDefault = ($_ -eq $s.Domains[0]) } }) } }
            '/subscribedSkus' { return @{ value = @() } }
            '/auditLogs/signIns' {
                if ($s.SignInStatus) { throw (Get-FakeGraphError $s.SignInStatus $s.SignInBody) }
                return @{ value = @($s.SignIns) }
            }
            '/identityProtection/riskyUsers' {
                if ($s.RiskyStatus -eq 'NotFound' -and $null -eq $s.RiskyUser) { throw (Get-FakeGraphError 'NotFound' '{"error":{"code":"Request_ResourceNotFound"}}') }
                return $s.RiskyUser
            }
            '/authentication/methods' { return @{ value = @($s.MfaMethods) } }
            '/groups' {
                if ($s.ThrowOnGroups) { throw (Get-FakeGraphError 'Forbidden' '{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."}}') }
                return @{ value = @() }
            }
            '/users' {
                if ($s.ThrowOnUsers) { throw 'boom: synthetic failure while looking up the user' }
                if ($u -match 'onPremisesSecurityIdentifier eq') { return @{ value = @($s.SidMatches) } }
                if ($u -match 'userPrincipalName eq') { return @{ value = @($s.UpnMatches) } }
                return @{ value = @($s.FallbackMatches) }
            }
            default { return @{ value = @() } }
        }
    }
    function New-OutDir { $d = Join-Path $TestDrive ([guid]::NewGuid().ToString()); $null = New-Item -ItemType Directory -Path $d; $d }
}

Describe 'running the check' {
    BeforeEach {
        New-Scenario
        $script:Events = New-Object System.Collections.Generic.List[string]
        Mock Import-Module { }
        Mock Connect-MgGraph { $script:Events.Add('CONNECT') }
        Mock Get-MgContext { [PSCustomObject]@{ Account = $script:Scn.Me; TenantId = $script:TenantId; Scopes = @('Directory.Read.All'); AuthType = 'Delegated'; ContextScope = 'Process' } }
        Mock Disconnect-MgGraph { $script:Events.Add('DISCONNECT') }
        Mock Set-Clipboard { }
        Mock Write-Host { $script:Events.Add('HOST:' + ($Object -join ' ')) }
        Mock Invoke-MgGraphRequest -MockWith $script:FakeGraph
    }

    Context 'AC1 banner' {
        It 'AC1_BannerPrintsFirst: tenant, default domain, tenant ID, account and "This tool only reads" come before any /users request and the verdict' {
            $r = Invoke-Entry
            $script:LastError | Should -BeNullOrEmpty
            $firstUsers = -1
            for ($i = 0; $i -lt $script:Events.Count; $i++) { if ($script:Events[$i] -match '^GET .*/users') { $firstUsers = $i; break } }
            $firstUsers | Should -BeGreaterThan 0 -Because 'the script must look the user up'
            $before = ($script:Events[0..($firstUsers - 1)] | Where-Object { $_ -like 'HOST:*' } | ForEach-Object { $_.Substring(5) }) -join "`n"
            $before | Should -Match 'Contoso Ltd'
            $before | Should -Match 'contoso\.com'
            $before | Should -Match $script:TenantId
            $before | Should -Match 'admin@contoso\.com'
            $before | Should -Match 'Global Administrator'
            $before | Should -Match 'This tool only reads'
            $all = Get-HostText
            $all | Should -Match 'Can Jane Doe sign in to Microsoft 365\?\s+YES'
            $before | Should -Not -Match 'Can Jane Doe sign in'
        }
    }

    Context 'AC2 wrong tenant' {
        It 'AC2_WrongTenantStops: a UPN domain the tenant does not own -> message names both, no /users request, exit code 3' {
            $r = Invoke-Entry @{ UserPrincipalName = 'jdoe@fabrikam.com' }
            $r.ExitCode | Should -Be 3
            $text = (Get-HostText) + "`n" + $r.Message
            $text | Should -Match 'fabrikam\.com'
            $text | Should -Match 'Contoso Ltd'
            @($script:Events | Where-Object { $_ -match '^GET .*/users' }).Count | Should -Be 0
            @($script:Events | Where-Object { $_ -match 'signIns' }).Count | Should -Be 0
        }
    }

    Context 'AC4 end to end' {
        It 'AC4_UserNotFoundOrAmbiguous: nothing matches -> "No Microsoft 365 user matched", exit 2' {
            New-Scenario @{ UpnMatches = @(); FallbackMatches = @() }
            $r = Invoke-Entry
            $r.ExitCode | Should -Be 2
            ((Get-HostText) + "`n" + $r.Message) | Should -Match 'No Microsoft 365 user matched'
            @($script:Events | Where-Object { $_ -match 'signIns' }).Count | Should -Be 0
        }

        It 'AC4_UserNotFoundOrAmbiguous: two candidates are listed (name, UPN, enabled), exit 2, no guess' {
            New-Scenario @{ UpnMatches = @(); FallbackMatches = @(
                    (New-User @{ id = '1'; displayName = 'Jane Doe'; userPrincipalName = 'jane@contoso.com' }),
                    (New-User @{ id = '2'; displayName = 'Jane Doe (old)'; userPrincipalName = 'jane.old@contoso.com'; accountEnabled = $false })) }
            $r = Invoke-Entry
            $r.ExitCode | Should -Be 2
            $text = Get-HostText
            $text | Should -Match 'jane@contoso\.com'
            $text | Should -Match 'jane\.old@contoso\.com'
            $text | Should -Match 'Jane Doe \(old\)'
            @($script:Events | Where-Object { $_ -match 'signIns' }).Count | Should -Be 0
        }
    }

    Context 'AC8 and AC10 end to end' {
        It 'AC8_NoP1BannerInConsole: no P1 -> banner source line printed before the verdict, verdict PROBABLY YES' {
            New-Scenario @{ SignInStatus = 'Forbidden'; SignInBody = $script:NonP1Body; SignIns = @() }
            $r = Invoke-Entry
            $text = Get-HostText
            $text | Should -Match 'Sign-in history: not available \(this tenant has no Entra ID P1\)'
            $text.IndexOf('Sign-in history: not available') | Should -BeLessThan $text.IndexOf('Can Jane Doe sign in')
            $text | Should -Match 'Can Jane Doe sign in to Microsoft 365\?\s+PROBABLY YES'
            $r.ExitCode | Should -Be 0
        }

        It 'AC10_BlockingFailureCodeIsNo: latest sign-in failed with 53003 -> NO, exit 1, 3 failures counted' {
            New-Scenario @{ SignIns = @(
                    (New-SignInRow -MinutesAgo 10 -Code 53003 -FailureReason 'Blocked by CA.' -Policies @(@{ displayName = 'Block outside corp'; result = 'failure' })),
                    (New-SignInRow -MinutesAgo 20 -Code 53003 -FailureReason 'Blocked by CA.' -Policies @(@{ displayName = 'Block outside corp'; result = 'failure' })),
                    (New-SignInRow -MinutesAgo 30 -Code 53003 -FailureReason 'Blocked by CA.' -Policies @(@{ displayName = 'Block outside corp'; result = 'failure' }))) }
            $r = Invoke-Entry
            $r.ExitCode | Should -Be 1
            $text = Get-HostText
            $text | Should -Match 'Can Jane Doe sign in to Microsoft 365\?\s+NO'
            $text | Should -Match 'Block outside corp'
            $text | Should -Match 'https://login\.microsoftonline\.com/error\?code=53003'
        }

        It 'Edge_SignInRequestFiltersByUserAndWindow: userId filter, createdDateTime ge, $top=50, GET only' {
            $null = Invoke-Entry
            $req = @($script:Events | Where-Object { $_ -match '^GET .*/auditLogs/signIns' })
            $req.Count | Should -Be 1 -Because 'one page only'
            $req[0] | Should -Match "userId eq '$($script:UserId)'"
            $req[0] | Should -Match 'createdDateTime ge '
            $req[0] | Should -Match '\$top=50'
        }

        It 'Edge_CaDetailHiddenEndToEnd: rows without appliedConditionalAccessPolicies -> Could not check names it' {
            New-Scenario @{ SignIns = @((New-SignInRow -Policies $null)) }
            $null = Invoke-Entry
            (Get-HostText) | Should -Match 'Conditional Access detail'
            (Get-HostText) | Should -Not -Match '(?i)conditional access (was )?ruled out|no conditional access'
        }

        It 'AC16_RiskyUserBannerInConsole: risky user request fails for licence -> banner says needs Entra ID P2' {
            New-Scenario @{ RiskyStatus = 'Forbidden'; RiskyUser = $null }
            Mock Invoke-MgGraphRequest {
                $u = [uri]::UnescapeDataString([string]$Uri)
                $script:Events.Add("GET $u")
                $s = $script:Scn
                switch -Regex ($u) {
                    '/me/(transitive)?memberOf' { return @{ value = @() } }
                    '/me\b' { return @{ userPrincipalName = $s.Me } }
                    '/organization' { return @{ value = @(@{ id = $script:TenantId; displayName = $s.TenantName; verifiedDomains = @(@{ name = 'contoso.com'; isDefault = $true }) }) } }
                    '/domains' { return @{ value = @(@{ id = 'contoso.com'; isVerified = $true; isDefault = $true }) } }
                    '/auditLogs/signIns' { return @{ value = @($s.SignIns) } }
                    '/identityProtection/riskyUsers' { throw (Get-FakeGraphError 'Forbidden' $script:NonP1Body) }
                    '/authentication/methods' { return @{ value = @($s.MfaMethods) } }
                    '/users' { return @{ value = @($s.UpnMatches) } }
                    default { return @{ value = @() } }
                }
            }
            $null = Invoke-Entry
            (Get-HostText) | Should -Match 'Risky user: not available \(needs Entra ID P2\)'
        }
    }

    Context 'AC17 disconnect' {
        It 'AC17_DisconnectAlways: a throw after connecting still calls Disconnect-MgGraph exactly once' {
            New-Scenario @{ ThrowOnUsers = $true }
            $null = Invoke-Entry
            Should -Invoke Disconnect-MgGraph -Times 1 -Exactly -Scope It
            Should -Invoke Connect-MgGraph -Times 1 -Exactly -Scope It
        }

        It 'AC17_DisconnectAlways: Get-MgContext throwing after Connect-MgGraph still disconnects exactly once' {
            Mock Get-MgContext { throw 'synthetic failure reading the Graph context' }
            $r = Invoke-Entry
            $r.ExitCode | Should -Be 3
            Should -Invoke Connect-MgGraph -Times 1 -Exactly -Scope It
            Should -Invoke Disconnect-MgGraph -Times 1 -Exactly -Scope It
        }

        It 'AC17_DisconnectAlways: a normal run disconnects once too' {
            $null = Invoke-Entry
            Should -Invoke Disconnect-MgGraph -Times 1 -Exactly -Scope It
        }
    }

    Context 'AC26 ticket note' {
        It 'AC26_KitCopyShipsInFolder: CaseKit.ps1 sits in the tool folder (self-contained, parity-tested)' {
            Test-Path -LiteralPath (Join-Path $script:Root 'CaseKit.ps1') | Should -BeTrue
        }

        It 'AC26_TicketNoteGateAware: no P1 -> sign-in history under Could not check, never Ruled out; stamp names tenant, account, Changed anything: No' {
            New-Scenario @{ SignInStatus = 'Forbidden'; SignInBody = $script:NonP1Body; SignIns = @() }
            $out = New-OutDir
            $r = Invoke-Entry @{ TicketNumber = 'T1001'; OutputPath = $out }
            $noteFile = @(Get-ChildItem -LiteralPath (Join-Path $out 'Ticket_T1001') -Filter 'Note_*.txt' -ErrorAction SilentlyContinue)
            $noteFile.Count | Should -Be 1
            $lines = [System.IO.File]::ReadAllLines($noteFile[0].FullName)
            (Get-Section $lines 'Could not check:') -join "`n" | Should -Match '(?i)sign-in history'
            (Get-Section $lines 'Ruled out:') -join "`n" | Should -Not -Match '(?i)sign-in'
            $stamp = @($lines | Where-Object { $_ -match '^Tenant: ' })
            $stamp.Count | Should -Be 1
            $stamp[0] | Should -Match 'Contoso Ltd'
            $stamp[0] | Should -Match 'admin@contoso\.com'
            $stamp[0] | Should -Match 'Changed anything: No'
        }

        It 'AC26_TicketNoteGateAware: the note text holds no IP address even when sign-in rows carry one' {
            New-Scenario @{ SignIns = @((New-SignInRow -Code 50126 -FailureReason 'Bad password from 203.0.113.7.' -Ip '203.0.113.7')) }
            $out = New-OutDir
            $null = Invoke-Entry @{ TicketNumber = 'T1002'; OutputPath = $out }
            $noteFile = @(Get-ChildItem -LiteralPath (Join-Path $out 'Ticket_T1002') -Filter 'Note_*.txt' -ErrorAction SilentlyContinue)
            $noteFile.Count | Should -Be 1
            [System.IO.File]::ReadAllText($noteFile[0].FullName) | Should -Not -Match '203\.0\.113\.'
            (Get-HostText) | Should -Not -Match '203\.0\.113\.' -Because 'the console is screen-shared and pasted from; IPs belong in the local HTML only'
        }

        It 'AC26_FullDetailWarns: -FullDetail prints a [WARN] that the note will include IP addresses and share paths' {
            $null = Invoke-Entry @{ FullDetail = $true }
            @($script:Events | Where-Object { $_ -match '^HOST:\[WARN\] .*IP addresses and share paths' }).Count | Should -Be 1
        }

        It 'AC26_NoFullDetailNoWarning: without -FullDetail there is no such warning' {
            $null = Invoke-Entry
            @($script:Events | Where-Object { $_ -match 'IP addresses and share paths' }).Count | Should -Be 0
        }
    }

    Context 'AC27 and AC28 reports' {
        It 'AC27_HtmlEncodesGraphValues: script tags in display name, failureReason and policy name is encoded, never raw' {
            $evil = '<script>alert(1)</script>'
            New-Scenario @{
                UpnMatches = @((New-User @{ displayName = "Jane $evil" }))
                SignIns = @((New-SignInRow -Code 53003 -FailureReason "Blocked $evil" -Policies @(@{ displayName = "Policy $evil"; result = 'failure' })))
            }
            $out = New-OutDir
            $null = Invoke-Entry @{ OutputPath = $out }
            $html = @(Get-ChildItem -LiteralPath $out -Filter '*.html')
            $html.Count | Should -Be 1
            $text = [System.IO.File]::ReadAllText($html[0].FullName)
            $text | Should -Not -Match ([regex]::Escape($evil))
            $text | Should -Match ([regex]::Escape('&lt;script&gt;alert(1)&lt;/script&gt;'))
            ([regex]::Matches($text, [regex]::Escape('&lt;script&gt;alert(1)'))).Count | Should -BeGreaterOrEqual 3
        }

        It 'AC28_ReportFiles: -OutputPath writes the named HTML and a one-row CSV with no IP column' {
            $out = New-OutDir
            $null = Invoke-Entry @{ OutputPath = $out }
            $names = @(Get-ChildItem -LiteralPath $out -File | ForEach-Object Name)
            @($names | Where-Object { $_ -match '^M365UserCheck_jdoe_contoso\.com_\d{4}-\d{2}-\d{2}_\d{6}\.html$' }).Count | Should -Be 1
            $csvName = @($names | Where-Object { $_ -match '^M365UserCheck_jdoe_contoso\.com_\d{4}-\d{2}-\d{2}_\d{6}\.csv$' })
            $csvName.Count | Should -Be 1
            $csvPath = Join-Path $out $csvName[0]
            $rows = @(Import-Csv -LiteralPath $csvPath)
            $rows.Count | Should -Be 1
            @($rows[0].PSObject.Properties.Name | Where-Object { $_ -match '(?i)\bip\b|ipaddress|ip_address' }).Count | Should -Be 0
            [System.IO.File]::ReadAllText($csvPath) | Should -Not -Match '203\.0\.113\.'
            (Get-Content -LiteralPath (Get-ChildItem -LiteralPath $out -Filter '*.html')[0].FullName -Raw) | Should -Match '203\.0\.113\.7' -Because 'IPs belong in the local HTML only'
        }

        It 'AC28_ReportFiles: no -OutputPath and no -TicketNumber -> no file is written' {
            $dir = New-OutDir
            Push-Location -LiteralPath $dir
            try { $r = Invoke-Entry } finally { Pop-Location }
            $r | Should -Not -BeNullOrEmpty -Because "the check must run and return a result"
            @(Get-ChildItem -LiteralPath $dir -Recurse -File).Count | Should -Be 0
        }

        It 'AC28_ReportFiles: -TicketNumber without -OutputPath writes only the note, in the default ticket folder' {
            $script:DefaultRoot = New-OutDir
            # CaseKit.ps1 defines the real one when the script runs; the mock (an alias) wins over
            # it, so the user's Documents folder is never touched.
            function Get-TicketNoteDefaultRoot { }
            Mock Get-TicketNoteDefaultRoot { $script:DefaultRoot }
            $cwd = New-OutDir
            Push-Location -LiteralPath $cwd
            try { $r = Invoke-Entry @{ TicketNumber = 'T1003' } } finally { Pop-Location }
            $r | Should -Not -BeNullOrEmpty
            $r.TicketNote | Should -Not -BeNullOrEmpty
            $files = @(Get-ChildItem -LiteralPath $script:DefaultRoot -Recurse -File)
            @($files | Where-Object { $_.Name -like 'Note_*.txt' -and $_.Directory.Name -eq 'Ticket_T1003' }).Count | Should -Be 1
            @($files | Where-Object { $_.Name -like 'M365UserCheck_*' }).Count | Should -Be 0 -Because 'reports are written only with -OutputPath'
            $files.Count | Should -Be 1
            @(Get-ChildItem -LiteralPath $cwd -Recurse -File).Count | Should -Be 0
        }

        It 'AC28_ReportFiles: -TicketNumber with -OutputPath puts the reports and the note in <OutputPath>\Ticket_<n>' {
            $out = New-OutDir
            $null = Invoke-Entry @{ TicketNumber = 'T1004'; OutputPath = $out }
            $names = @(Get-ChildItem -LiteralPath (Join-Path $out 'Ticket_T1004') -File | ForEach-Object Name)
            @($names | Where-Object { $_ -like 'M365UserCheck_*.html' }).Count | Should -Be 1
            @($names | Where-Object { $_ -like 'M365UserCheck_*.csv' }).Count | Should -Be 1
            @($names | Where-Object { $_ -like 'Note_*.txt' }).Count | Should -Be 1
        }

        It 'AC28_CsvIsSafe: free text has no IP and a leading = + - @ is neutralised with a quote' {
            New-Scenario @{
                UpnMatches = @((New-User @{ displayName = '=HYPERLINK("http://example.com","x")'; mail = '@jdoe@contoso.com' }))
                SignIns = @((New-SignInRow -Code 99999 -FailureReason 'Rejected from 203.0.113.9.'))
            }
            $out = New-OutDir
            $null = Invoke-Entry @{ OutputPath = $out }
            $csv = @(Get-ChildItem -LiteralPath $out -Filter '*.csv')
            $csv.Count | Should -Be 1
            $row = @(Import-Csv -LiteralPath $csv[0].FullName)[0]
            $row.DisplayName | Should -BeExactly '''=HYPERLINK("http://example.com","x")'
            $row.Mail | Should -BeExactly '''@jdoe@contoso.com'
            foreach ($p in $row.PSObject.Properties) {
                $p.Value | Should -Not -Match '^[=+\-@]' -Because "column $($p.Name) must not start a formula"
            }
            [System.IO.File]::ReadAllText($csv[0].FullName) | Should -Not -Match '203\.0\.113\.'
        }
    }

    Context 'connect' {
        It 'Connect_DisableWamUsesDeviceCode: -DisableWam passes -UseDeviceCode to Connect-MgGraph' {
            $null = Invoke-Entry @{ DisableWam = $true }
            Should -Invoke Connect-MgGraph -Times 1 -Exactly -Scope It -ParameterFilter { $UseDeviceCode -eq $true }
        }

        It 'Connect_ContextScopeProcess: a normal run asks for ContextScope Process and NoWelcome' {
            $null = Invoke-Entry
            Should -Invoke Connect-MgGraph -Times 1 -Exactly -Scope It -ParameterFilter { [string]$ContextScope -eq 'Process' -and $NoWelcome -eq $true }
        }

        It 'Connect_ContextScopeNotProcessWarns: a session that is not Process-scoped gets a [WARN]' {
            Mock Get-MgContext { [PSCustomObject]@{ Account = $script:Scn.Me; TenantId = $script:TenantId; ContextScope = 'CurrentUser' } }
            $null = Invoke-Entry
            @($script:Events | Where-Object { $_ -match '^HOST:\[WARN\] .*not limited to this PowerShell window.*CurrentUser' }).Count | Should -Be 1
        }

        It 'Connect_ProcessScopeNoWarning: a Process-scoped session gets no such warning' {
            $null = Invoke-Entry
            @($script:Events | Where-Object { $_ -match 'not limited to this PowerShell window' }).Count | Should -Be 0
        }
    }

    Context 'tenant domains' {
        It 'AC2_DomainsUnreadableIsNotWrongTenant: an empty domain list stops with exit 3 and never blames the UPN' {
            New-Scenario @{ Domains = @() }
            $r = Invoke-Entry
            $r.ExitCode | Should -Be 3
            $r.Status | Should -Not -Be 'WrongTenant'
            $r.Message | Should -Match "could not read the tenant's domains"
            ((Get-HostText) + "`n" + $r.Message) | Should -Not -Match 'Wrong tenant'
            @($script:Events | Where-Object { $_ -match '^GET .*/users' }).Count | Should -Be 0
        }
    }

    Context 'data kept' {
        It 'PersonalData_MfaMethodsKeepTypeAndIdOnly: phone numbers and other method details are dropped' {
            New-Scenario @{ MfaMethods = @(@{ '@odata.type' = '#microsoft.graph.phoneAuthenticationMethod'; id = 'eeeeeeee-0000-0000-0000-000000000001'; phoneNumber = '+1 555 0100'; phoneType = 'mobile' }) }
            $r = Invoke-Entry
            @($r.Facts.MfaMethods).Count | Should -Be 1
            @(@($r.Facts.MfaMethods)[0].Keys | Sort-Object) | Should -Be @('@odata.type', 'id')
        }

        It 'Banner_RolesFromTransitiveMemberOf: the roles request uses transitiveMemberOf (roles held through a group count)' {
            $null = Invoke-Entry
            @($script:Events | Where-Object { $_ -match '^GET .*/me/transitiveMemberOf/microsoft\.graph\.directoryRole' }).Count | Should -Be 1
        }
    }
}

Describe 'older Microsoft.Graph.Authentication modules' {
    # Each Context defines its own Connect-MgGraph stub BEFORE it is mocked, because a mock keeps
    # the parameters of the command it replaced, and the script checks them with Get-Command.
    Context 'Connect-MgGraph without -NoWelcome' {
        BeforeAll {
            function Connect-MgGraph {
                [CmdletBinding()]
                param([string[]]$Scopes, [string]$TenantId, [string]$ClientId, $ContextScope, [string]$Environment,
                    [switch]$UseDeviceCode, [double]$ClientTimeout)
            }
        }
        BeforeEach {
            New-Scenario
            $script:Events = New-Object System.Collections.Generic.List[string]
            Mock Import-Module { }
            Mock Connect-MgGraph { $script:Events.Add('CONNECT') }
            Mock Get-MgContext { [PSCustomObject]@{ Account = $script:Scn.Me; TenantId = $script:TenantId; ContextScope = 'Process' } }
            Mock Disconnect-MgGraph { $script:Events.Add('DISCONNECT') }
            Mock Set-Clipboard { }
            Mock Write-Host { $script:Events.Add('HOST:' + ($Object -join ' ')) }
            Mock Invoke-MgGraphRequest -MockWith $script:FakeGraph
        }
            It 'Connect_OldModuleWithoutNoWelcome: NoWelcome is dropped, ContextScope Process is still passed' {
                $r = Invoke-Entry
                $script:LastError | Should -BeNullOrEmpty
                Should -Invoke Connect-MgGraph -Times 1 -Exactly -Scope It -ParameterFilter { [string]$ContextScope -eq 'Process' }
                $r.Status | Should -Be 'Ok'
            }
    }

    Context 'Connect-MgGraph without -ContextScope' {
        BeforeAll {
            function Connect-MgGraph {
                [CmdletBinding()]
                param([string[]]$Scopes, [string]$TenantId, [string]$ClientId, [string]$Environment, [switch]$UseDeviceCode, [switch]$NoWelcome)
            }
        }
        BeforeEach {
            New-Scenario
            $script:Events = New-Object System.Collections.Generic.List[string]
            Mock Import-Module { }
            Mock Connect-MgGraph { $script:Events.Add('CONNECT') }
            Mock Get-MgContext { [PSCustomObject]@{ Account = $script:Scn.Me; TenantId = $script:TenantId; ContextScope = 'Process' } }
            Mock Disconnect-MgGraph { $script:Events.Add('DISCONNECT') }
            Mock Set-Clipboard { }
            Mock Write-Host { $script:Events.Add('HOST:' + ($Object -join ' ')) }
            Mock Invoke-MgGraphRequest -MockWith $script:FakeGraph
        }
            It 'Connect_ModuleWithoutContextScopeStops: no sign-in, exit 3, a plain message to update the module' {
                $r = Invoke-Entry
                $r.ExitCode | Should -Be 3
                $r.Message | Should -Match 'Update-Module Microsoft\.Graph\.Authentication'
                Should -Invoke Connect-MgGraph -Times 0 -Exactly -Scope It
                @($script:Events | Where-Object { $_ -match '^GET ' }).Count | Should -Be 0
            }
    }
}

Describe 'AC3 read-only by construction' {
    BeforeAll {
        $script:Files = @(Get-ChildItem -LiteralPath $script:Root -Filter '*.ps1' -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName.Substring($script:Root.Length) -notmatch '[\\/]Tests[\\/]' })
        $script:Asts = @{}
        foreach ($f in $script:Files) {
            $tokens = $null; $errs = $null
            $script:Asts[$f.Name] = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errs)
        }
        function Get-Commands($ast) { $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) }

        # SQ-011 review: an ALLOWLIST, compared case-insensitively the way PowerShell resolves
        # commands, so Set-AdUser, set-aduser and ActiveDirectory\Set-ADUser cannot slip past a
        # case-sensitive denylist. Any command whose noun starts with AD must be Get-ADUser; any
        # whose noun starts with Mg must be one of the Graph session cmdlets below; nothing from
        # the AzureAD, MSOnline or Microsoft.Entra modules (AzureAD*, Msol*, Entra* nouns) is
        # used at all. Set-MgGraphOption is not allowed either: the script never calls it, and
        # it persists a client-side setting on the machine (SQ-011 review). Nouns that
        # start with the English word "Address" (the core's Add-AddressConflictReasons) are not
        # AD nouns: no ActiveDirectory cmdlet noun starts with it (checked against the real
        # module in the test below where RSAT is installed).
        $script:AllowedAdCommands = @('Get-ADUser')
        $script:AllowedMgCommands = @('Connect-MgGraph', 'Disconnect-MgGraph', 'Get-MgContext', 'Invoke-MgGraphRequest')
        function Test-ForbiddenCommand([string]$Name) {
            $bare = $Name -replace '^.*\\', ''
            if ($bare -notmatch '^(?<verb>\w+)-(?<noun>\w+)$') { return $false }
            $noun = $Matches['noun']
            if ($noun -match '^AD' -and $noun -notmatch '^Address') { return ($bare -notin $script:AllowedAdCommands) }
            if ($noun -match '^(AzureAD|Msol|Entra)') { return $true }
            if ($noun -match '^Mg') { return ($bare -notin $script:AllowedMgCommands) }
            return $false
        }
        # Constructs that would let a script write without a write cmdlet: running built text,
        # a command whose name is only known at run time, raw HTTP outside
        # Invoke-MgGraphRequest, and ADSI (DirectoryEntry.SetInfo / CommitChanges write straight
        # to AD).
        #
        # & or . with no static command name: the guard cannot see what runs, so it is a hit
        # unless every assignment to the invoked variable in the same file is a script block
        # literal (its body is scanned with the rest of the file) or, for dot-sourcing only,
        # Join-Path $PSScriptRoot '<name>.ps1' (a sibling script, scanned too). The production
        # scripts use exactly these: & $safe and & $getUsers, . $corePath and . $kit.
        function Test-ScannedInvocationTarget($ast, $command) {
            $target = $command.CommandElements[0]
            if ($target -isnot [System.Management.Automation.Language.VariableExpressionAst]) { return $false }
            $name = $target.VariablePath.UserPath
            $rhs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                        $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.Left.VariablePath.UserPath -eq $name }, $true) | ForEach-Object Right)
            if ($rhs.Count -eq 0) { return $false }
            foreach ($r in $rhs) {
                if ($r -is [System.Management.Automation.Language.PipelineAst] -and @($r.PipelineElements).Count -eq 1) { $r = $r.PipelineElements[0] }
                if ($r -is [System.Management.Automation.Language.CommandExpressionAst] -and $r.Expression -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) { continue }
                $isSiblingScript = ($command.InvocationOperator -eq 'Dot' -and $r -is [System.Management.Automation.Language.CommandAst] -and
                    $r.GetCommandName() -eq 'Join-Path' -and @($r.CommandElements).Count -eq 3 -and $r.CommandElements[1].Extent.Text -eq '$PSScriptRoot' -and
                    $r.CommandElements[2] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $r.CommandElements[2].Value -match '^[\w.-]+\.ps1$')
                if (-not $isSiblingScript) { return $false }
            }
            return $true
        }
        function Get-UnsafeConstruct($ast) {
            $hits = New-Object System.Collections.Generic.List[string]
            foreach ($c in @(Get-Commands $ast)) {
                $bare = ([string]$c.GetCommandName()) -replace '^.*\\', ''
                if ($bare -in 'Invoke-Expression', 'iex', 'Invoke-RestMethod', 'irm', 'Invoke-WebRequest', 'iwr', 'curl', 'wget') { $hits.Add("line $($c.Extent.StartLineNumber): $bare") }
                if ($bare -eq 'New-Object' -and $c.Extent.Text -match 'DirectoryEntry|DirectorySearcher|Net\.WebClient|Net\.Http\.HttpClient') { $hits.Add("line $($c.Extent.StartLineNumber): $($c.Extent.Text)") }
                if ($c.InvocationOperator -ne 'Unknown' -and $null -eq $c.GetCommandName() -and -not (Test-ScannedInvocationTarget $ast $c)) {
                    $hits.Add("line $($c.Extent.StartLineNumber): $($c.InvocationOperator) with no static command name ($($c.CommandElements[0].Extent.Text))")
                }
            }
            $types = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TypeExpressionAst] -or $n -is [System.Management.Automation.Language.TypeConstraintAst] }, $true)
            foreach ($t in @($types)) {
                if ($t.TypeName.FullName -match '^(adsi|adsisearcher|(System\.)?(DirectoryServices\.)?(DirectoryEntry|DirectorySearcher))$') { $hits.Add("line $($t.Extent.StartLineNumber): [$($t.TypeName.FullName)]") }
                if ($t.TypeName.FullName -match '^(System\.)?Net\.(WebClient|Http\.HttpClient)$') { $hits.Add("line $($t.Extent.StartLineNumber): [$($t.TypeName.FullName)]") }
            }
            # $ExecutionContext.InvokeCommand runs commands and script text by name.
            $refs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] -and
                    $n.Expression -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.Expression.VariablePath.UserPath -eq 'ExecutionContext' -and
                    $n.Member.Extent.Text.Trim('"', "'") -eq 'InvokeCommand' }, $true)
            foreach ($x in @($refs)) { $hits.Add("line $($x.Extent.StartLineNumber): `$ExecutionContext.InvokeCommand") }
            $members = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)
            foreach ($m in @($members)) {
                $member = [string]$m.Member.Extent.Text.Trim('"', "'")
                if ($member -in 'SetInfo', 'CommitChanges') { $hits.Add("line $($m.Extent.StartLineNumber): .$member()") }
                if ($member -eq 'Create' -and $m.Expression -is [System.Management.Automation.Language.TypeExpressionAst] -and $m.Expression.TypeName.FullName -match '^(scriptblock|System\.Management\.Automation\.ScriptBlock)$') {
                    $hits.Add("line $($m.Extent.StartLineNumber): [scriptblock]::Create")
                }
            }
            return $hits.ToArray()
        }
    }

    It 'AC3_ReadOnlyByConstruction: the entry script and the core exist to be scanned' {
        $names = @($script:Files | ForEach-Object Name)
        $names | Should -Contain 'Get-M365UserQuickCheck.ps1'
        $names | Should -Contain 'M365UserCheck.Core.ps1'
    }

    It 'AC3_ReadOnlyByConstruction: every Invoke-MgGraphRequest says -Method GET' {
        $calls = @()
        foreach ($name in $script:Asts.Keys) { $calls += @(Get-Commands $script:Asts[$name] | Where-Object { $_.GetCommandName() -eq 'Invoke-MgGraphRequest' }) }
        $calls.Count | Should -BeGreaterThan 0
        foreach ($c in $calls) {
            $els = @($c.CommandElements)
            $idx = -1
            for ($i = 0; $i -lt $els.Count; $i++) { if ($els[$i] -is [System.Management.Automation.Language.CommandParameterAst] -and $els[$i].ParameterName -eq 'Method') { $idx = $i } }
            $idx | Should -BeGreaterOrEqual 0 -Because "line $($c.Extent.StartLineNumber) must name -Method"
            $val = if ($els[$idx].Argument) { $els[$idx].Argument } else { $els[$idx + 1] }
            $val.Extent.Text.Trim('"', "'") | Should -BeExactly 'GET' -Because "line $($c.Extent.StartLineNumber)"
        }
    }

    It 'AC3_ReadOnlyByConstruction: no write cmdlet appears in any script (AD and Graph cmdlets allowlisted, any case, any module prefix)' {
        $hits = @()
        foreach ($name in $script:Asts.Keys) {
            $hits += @(Get-Commands $script:Asts[$name] | Where-Object { Test-ForbiddenCommand ([string]$_.GetCommandName()) } | ForEach-Object { "$name line $($_.Extent.StartLineNumber): $($_.GetCommandName())" })
        }
        $script:Asts.Count | Should -BeGreaterThan 0 -Because 'there must be scripts to scan'
        $hits | Should -BeNullOrEmpty
    }

    It 'AC3_ReadOnlyByConstruction: the allowlist catches AD and Graph write cmdlets in any case or module-qualified, and passes the read-only ones and the core''s own helpers' {
        $mustCatch = @(
            'Set-ADUser', 'New-ADUser', 'Remove-ADUser', 'Move-ADObject', 'Rename-ADObject', 'Add-ADGroupMember', 'Enable-ADAccount',
            'Disable-ADAccount', 'Unlock-ADAccount', 'Clear-ADAccountExpiration', 'Reset-ADServiceAccountPassword',
            'Set-AdUser', 'set-aduser', 'ActiveDirectory\Set-ADUser', 'Restore-ADObject', 'Set-ADAccountPassword', 'Set-ADDomain',
            'New-MgUser', 'Update-MgUser', 'Remove-MgUser', 'Invoke-MgDismissRiskyUser', 'Revoke-MgUserSignInSession',
            'Microsoft.Graph.Users\Update-MgUser', 'update-mguser', 'Set-MgGraphOption',
            'Set-AzureADUser', 'Remove-AzureADUser', 'Get-AzureADUser', 'Set-MsolUser', 'Set-MsolUserPassword', 'Remove-MsolUser',
            'Set-EntraUser', 'Remove-EntraUser', 'Microsoft.Entra.Users\Update-EntraUser')
        foreach ($w in $mustCatch) { Test-ForbiddenCommand $w | Should -BeTrue -Because "$w writes and must be caught" }
        foreach ($ok in 'Get-ADUser', 'get-aduser', 'ActiveDirectory\Get-ADUser', 'Add-AddressConflictReasons', 'Add-Reason', 'Invoke-MgGraphRequest',
            'Connect-MgGraph', 'Disconnect-MgGraph', 'Get-MgContext', 'Import-Module', 'Get-M365Prop') {
            Test-ForbiddenCommand $ok | Should -BeFalse -Because "$ok is read-only or a local helper"
        }
    }

    It 'AC3_ReadOnlyByConstruction: every real ActiveDirectory cmdlet except Get-ADUser is caught by the allowlist (where RSAT is installed)' {
        # A child pwsh keeps this session's stubs; with no pwsh on PATH the test skips, not throws.
        $pwsh = Get-Command -Name pwsh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $pwsh) { Set-ItResult -Skipped -Because 'pwsh is not on PATH, so the real module cannot be listed in a child session'; return }
        # ADPS_LoadDefaultDrive = 0 stops the module mapping the AD: drive, which contacts a DC.
        $json = & $pwsh.Source -NoProfile -Command @'
$env:ADPS_LoadDefaultDrive = 0
$c = @(Get-Command -Module ActiveDirectory -ErrorAction SilentlyContinue | ForEach-Object Name)
if ($c.Count -gt 0) { $c | ConvertTo-Json -Compress }
'@
        if (-not $json) { Set-ItResult -Skipped -Because 'the ActiveDirectory module (RSAT) is not installed'; return }
        $real = @($json | ConvertFrom-Json)
        foreach ($n in @($real | Where-Object { $_ -ne 'Get-ADUser' })) { Test-ForbiddenCommand $n | Should -BeTrue -Because "$n is an ActiveDirectory cmdlet" }
        Test-ForbiddenCommand 'Get-ADUser' | Should -BeFalse
    }

    It 'AC3_ReadOnlyByConstruction: no Invoke-Expression, [scriptblock]::Create, Invoke-RestMethod/Invoke-WebRequest, WebClient/HttpClient, $ExecutionContext.InvokeCommand, unscanned & / . call, ADSI type or SetInfo/CommitChanges call in the production scripts' {
        $hits = @()
        foreach ($name in $script:Asts.Keys) { $hits += @(Get-UnsafeConstruct $script:Asts[$name] | ForEach-Object { "${name} $_" }) }
        $names = @($script:Asts.Keys)
        $names | Should -Contain 'Get-M365UserQuickCheck.ps1'
        $names | Should -Contain 'M365UserCheck.Core.ps1'
        $hits | Should -BeNullOrEmpty
    }

    It 'AC3_ReadOnlyByConstruction: the unsafe-construct scan catches each construct' {
        $samples = [ordered]@{
            'Invoke-Expression'   = 'Invoke-Expression $text'
            'iex'                 = 'iex $text'
            'scriptblock Create'  = '$sb = [scriptblock]::Create($text)'
            'ScriptBlock full'    = '$sb = [System.Management.Automation.ScriptBlock]::Create($text)'
            'Invoke-RestMethod'   = 'Invoke-RestMethod -Method PATCH -Uri $u'
            'Invoke-WebRequest'   = 'Microsoft.PowerShell.Utility\Invoke-WebRequest -Uri $u'
            'adsi cast'           = '$e = [adsi]"LDAP://CN=x"'
            'DirectoryEntry type' = '$e = [System.DirectoryServices.DirectoryEntry]::new("LDAP://CN=x")'
            'New-Object'          = '$e = New-Object System.DirectoryServices.DirectoryEntry ("LDAP://CN=x")'
            'SetInfo'             = '$e.SetInfo()'
            'CommitChanges'       = '$e.CommitChanges()'
            'call by built name'  = '& (''Set-'' + ''ADUser'') -Identity jdoe'
            'call by string var'  = '$cmd = ''Set-ADUser''; & $cmd -Identity jdoe'
            'var reassigned'      = '$safe = { param($s) $s }; $safe = ''Set-ADUser''; & $safe -Identity jdoe'
            'call by command obj' = '& (Get-Command Set-ADUser) -Identity jdoe'
            'dot-source unknown'  = '. $env:TEMP\x.ps1'
            'dot-source built'    = '$p = Join-Path $env:TEMP ''x.ps1''; . $p'
            'unassigned variable' = '& $notAssignedHere'
            'WebClient type'      = '$w = [System.Net.WebClient]::new()'
            'WebClient short'     = '$w = [Net.WebClient]::new()'
            'HttpClient type'     = '$h = [System.Net.Http.HttpClient]::new()'
            'New-Object WebClient' = '$w = New-Object System.Net.WebClient'
            'InvokeCommand'       = '$ExecutionContext.InvokeCommand.InvokeScript($text)'
        }
        foreach ($k in $samples.Keys) {
            $tokens = $null; $errs = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseInput($samples[$k], [ref]$tokens, [ref]$errs)
            @(Get-UnsafeConstruct $ast).Count | Should -BeGreaterThan 0 -Because "$k must be caught"
        }
        $tokens = $null; $errs = $null
        $okAst = [System.Management.Automation.Language.Parser]::ParseInput('$r = Invoke-MgGraphRequest -Method GET -Uri $u; $x = [string]$y; $sb.Append("a")', [ref]$tokens, [ref]$errs)
        @(Get-UnsafeConstruct $okAst).Count | Should -Be 0
        # The shapes the production scripts use: a script block written in the same file, and a
        # sibling script dot-sourced by literal name.
        $okInvoke = [System.Management.Automation.Language.Parser]::ParseInput('$safe = { param($s) "$s" }; & $safe "x"; $kit = Join-Path $PSScriptRoot ''CaseKit.ps1''; . $kit', [ref]$tokens, [ref]$errs)
        @(Get-UnsafeConstruct $okInvoke) | Should -BeNullOrEmpty
    }

    It 'AC3_ReadOnlyByConstruction: every requested scope is a .Read / .Read.All scope, and the four expected scopes are requested' {
        $consts = @()
        foreach ($name in $script:Asts.Keys) {
            $consts += @($script:Asts[$name].FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) | ForEach-Object { $_.Value })
        }
        $scopeLike = @($consts | Where-Object { $_ -match '^[A-Za-z]+(\.[A-Za-z]+)*\.(Read|ReadWrite|Write|Manage|Send|Update|Delete|Create)(\.[A-Za-z]+)?$' } | Sort-Object -Unique)
        foreach ($want in 'Directory.Read.All', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All', 'IdentityRiskyUser.Read.All') {
            $scopeLike | Should -Contain $want
        }
        $notRead = @($scopeLike | Where-Object { $_ -notmatch '\.Read(\.All)?$' })
        $notRead | Should -BeNullOrEmpty
    }

    It 'AC3_ReadOnlyByConstruction: Policy.Read.All is requested (Conditional Access detail), not Policy.Read.ConditionalAccess' {
        # signin-list omits appliedConditionalAccessPolicies unless the app holds Policy.Read.All,
        # Policy.Read.ConditionalAccess or Policy.ReadWrite.ConditionalAccess. The narrower one
        # does not end in .Read / .Read.All, which the read-only rule above requires.
        $consts = @()
        foreach ($name in $script:Asts.Keys) {
            $consts += @($script:Asts[$name].FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) | ForEach-Object { $_.Value })
        }
        $consts | Should -Contain 'Policy.Read.All'
        $consts | Should -Not -Contain 'Policy.Read.ConditionalAccess'
    }
}

Describe 'Mocks cannot lie about parameter names' {
    BeforeAll {
        $script:RealParams = @{}
        # No pwsh on PATH: nothing to compare against, so the test below skips rather than throws.
        $pwsh = Get-Command -Name pwsh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        $json = if ($pwsh) {
            & $pwsh.Source -NoProfile -Command @'
$r = @{}
foreach ($n in 'Connect-MgGraph','Invoke-MgGraphRequest','Disconnect-MgGraph','Get-MgContext') {
  $c = Get-Command $n -Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
  if ($c) { $r[$n] = @($c.Parameters.Keys) }
}
$r | ConvertTo-Json -Compress
'@
        }
        if ($json) { $o = $json | ConvertFrom-Json; foreach ($p in $o.PSObject.Properties) { $script:RealParams[$p.Name] = @($p.Value) } }
    }

    It 'the stubs in this file use parameter names the real cmdlets have' {
        if ($script:RealParams.Count -eq 0) { Set-ItResult -Skipped -Because 'Microsoft.Graph.Authentication is not installed'; return }
        foreach ($cmd in 'Connect-MgGraph', 'Invoke-MgGraphRequest') {
            $stub = (Get-Command $cmd -CommandType Function).Parameters.Keys | Where-Object { $_ -notin [System.Management.Automation.PSCmdlet]::CommonParameters }
            foreach ($p in $stub) { $script:RealParams[$cmd] | Should -Contain $p -Because "$cmd has no -$p" }
        }
    }

    It 'the scripts call Connect-MgGraph and Invoke-MgGraphRequest only with parameters that exist' {
        if ($script:RealParams.Count -eq 0) { Set-ItResult -Skipped -Because 'Microsoft.Graph.Authentication is not installed'; return }
        $files = @(Get-ChildItem -LiteralPath $script:Root -Filter '*.ps1' -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName.Substring($script:Root.Length) -notmatch '[\\/]Tests[\\/]' })
        $files.Count | Should -BeGreaterThan 0 -Because 'there must be scripts to check'
        foreach ($f in $files) {
            $tokens = $null; $errs = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errs)
            $cmds = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in 'Connect-MgGraph', 'Invoke-MgGraphRequest', 'Disconnect-MgGraph' }, $true)
            foreach ($c in $cmds) {
                foreach ($e in $c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] }) {
                    $real = @($script:RealParams[$c.GetCommandName()]) + [System.Management.Automation.PSCmdlet]::CommonParameters
                    $matching = @($real | Where-Object { $_ -like "$($e.ParameterName)*" })
                    $matching.Count | Should -BeGreaterThan 0 -Because "$($f.Name) line $($c.Extent.StartLineNumber) uses -$($e.ParameterName)"
                }
            }
        }
    }
}

# =============================================================================
# SQ-011, on-premises AD stage, end to end: AC18 plus the AD call counts of AC19 and AC20.
# The entry is run WITHOUT -SkipOnPremises (Invoke-Entry defaults it on). Import-Module and
# Get-ADUser are faked; nothing reaches a domain controller. Pinned wording: the banner line and
# the Could not check line both read "On-premises AD: could not check (<reason>)".
# =============================================================================
Describe 'SQ-011 on-premises AD stage' {
    BeforeAll {
        $script:Sid = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
        # Stub with the real parameter names (Get-ADUser; checked with Get-Command).
        function Get-ADUser {
            [CmdletBinding()]
            param($Identity, $LDAPFilter, $Filter, $Server, [pscredential]$Credential, $Properties, $SearchBase, $ResultSetSize)
        }
        function New-AdAccount {
            param([hashtable]$Set = @{})
            $a = @{ Enabled = $true; UserPrincipalName = 'jdoe@contoso.com'; mail = 'jdoe@contoso.com'; proxyAddresses = @('SMTP:jdoe@contoso.com')
                SamAccountName = 'jdoe'; DistinguishedName = 'CN=Jane Doe,OU=Staff,DC=contoso,DC=com'; 'msDS-cloudExtensionAttribute10' = $null }
            foreach ($k in $Set.Keys) { $a[$k] = $Set[$k] }
            $a
        }
        function New-SyncedCloudUser { New-User @{ onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = $script:Sid; onPremisesProvisioningErrors = @() } }
        $script:NoDcMessage = 'Unable to contact the server. This may be because this server does not exist, it is currently down, or it does not have the Active Directory Web Services running.'
    }
    BeforeEach {
        New-Scenario
        $script:AdCalls = New-Object System.Collections.Generic.List[hashtable]
        $script:AdBySid = New-AdAccount; $script:AdByFilter = @(); $script:AdThrow = $null; $script:ImportAdThrows = $false
        $script:Events = New-Object System.Collections.Generic.List[string]
        Mock Import-Module { if ($script:ImportAdThrows -and $Name -eq 'ActiveDirectory') { throw 'The specified module ''ActiveDirectory'' was not loaded because no valid module file was found in any module directory.' } }
        Mock Connect-MgGraph { $script:Events.Add('CONNECT') }
        Mock Get-MgContext { [PSCustomObject]@{ Account = $script:Scn.Me; TenantId = $script:TenantId; Scopes = @('Directory.Read.All'); AuthType = 'Delegated'; ContextScope = 'Process' } }
        Mock Disconnect-MgGraph { $script:Events.Add('DISCONNECT') }
        Mock Set-Clipboard { }
        Mock Write-Host { $script:Events.Add('HOST:' + ($Object -join ' ')) }
        Mock Invoke-MgGraphRequest -MockWith $script:FakeGraph
        Mock Get-ADUser {
            $script:AdCalls.Add(@{ Identity = $Identity; LDAPFilter = $LDAPFilter; Server = $Server; Credential = $Credential })
            if ($script:AdThrow) { throw $script:AdThrow }
            # Pester 5.7 leaves $PSBoundParameters empty in a mock body without param(); the
            # bound value is still in $Identity.
            if ($null -ne $Identity) {
                if ($null -eq $script:AdBySid) { throw 'Cannot find an object with identity: ''S-1-5-21-1111111111-2222222222-3333333333-1105'' under: ''DC=contoso,DC=com''.' }
                return $script:AdBySid
            }
            return @($script:AdByFilter)
        }
    }

    It 'AC18_AdStageUnavailableStillGivesVerdict: ActiveDirectory module missing -> Graph verdict printed, banner and Could not check say "could not check (...)", exit code from Graph' {
        New-Scenario @{ UpnMatches = @((New-SyncedCloudUser)) }
        $script:ImportAdThrows = $true
        $r = Invoke-Entry @{ SkipOnPremises = $false }
        $script:LastError | Should -BeNullOrEmpty
        $r.ExitCode | Should -Be 0
        $text = Get-HostText
        $text | Should -Match 'Can Jane Doe sign in to Microsoft 365\?\s+YES'
        @([regex]::Matches($text, 'On-premises AD: could not check \(')).Count | Should -BeGreaterOrEqual 2 -Because 'once in the banner, once under Could not check'
        $text | Should -Match 'ActiveDirectory'
        $text.IndexOf('On-premises AD: could not check') | Should -BeLessThan $text.IndexOf('Can Jane Doe sign in')
        @($r.Assessment.CouldNotCheck | Where-Object { $_.Source -eq 'On-premises AD' }).Count | Should -Be 1
        $text | Should -Not -Match 'not checked in this version'
        Should -Invoke Get-ADUser -Times 0 -Exactly -Scope It
    }

    It 'AC18_AdStageUnavailableStillGivesVerdict: no DC answers (Get-ADUser throws) -> same, and a Graph blocker still exits 1' {
        New-Scenario @{ UpnMatches = @((New-User @{ onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = $script:Sid; accountEnabled = $false })) }
        $script:AdThrow = $script:NoDcMessage
        $r = Invoke-Entry @{ SkipOnPremises = $false }
        $script:LastError | Should -BeNullOrEmpty
        $r.ExitCode | Should -Be 1
        $text = Get-HostText
        $text | Should -Match 'Can Jane Doe sign in to Microsoft 365\?\s+NO'
        @([regex]::Matches($text, 'On-premises AD: could not check \(')).Count | Should -BeGreaterOrEqual 2
        $text | Should -Not -Match 'not checked in this version'
    }

    It 'AC18_AdStageUnavailableStillGivesVerdict: with -SkipOnPremises nothing is imported for AD and Get-ADUser is never called' {
        New-Scenario @{ UpnMatches = @((New-SyncedCloudUser)) }
        $r = Invoke-Entry @{ SkipOnPremises = $true }
        $r.ExitCode | Should -Be 0
        Should -Invoke Get-ADUser -Times 0 -Exactly -Scope It
        @($r.Assessment.CouldNotCheck | Where-Object { $_.Source -eq 'On-premises AD' }).Count | Should -Be 1
    }

    It 'AC19_CloudOnlySkipsAd: cloud-only user, no AD account has the UPN -> pass "Cloud-only account: sync is not involved", one Get-ADUser call (the UPN search)' {
        New-Scenario @{ UpnMatches = @((New-User)) }
        $r = Invoke-Entry @{ SkipOnPremises = $false }
        $r.ExitCode | Should -Be 0
        (Get-HostText) | Should -Match 'Cloud-only account: sync is not involved'
        $script:AdCalls.Count | Should -Be 1
        $script:AdCalls[0].LDAPFilter | Should -Match 'userPrincipalName='
        $script:AdCalls[0].Identity | Should -BeNullOrEmpty
        (Get-HostText) | Should -Match 'On-premises AD: available'
    }

    It 'AC20_NeverSynced: no Microsoft 365 user but the AD user exists -> NO, exit 1, "exists in AD but not in Microsoft 365"' {
        New-Scenario @{ UpnMatches = @(); FallbackMatches = @() }
        # A real AD account always has a SID; without one the SID search cannot run (CloudSidCheckError).
        $script:AdByFilter = @((New-AdAccount @{ SID = (New-Object System.Security.Principal.SecurityIdentifier ($script:Sid)) }))
        $r = Invoke-Entry @{ SkipOnPremises = $false }
        $r.ExitCode | Should -Be 1
        $text = Get-HostText
        $text | Should -Match 'This account exists in AD but not in Microsoft 365'
        $text | Should -Match 'Can .* sign in to Microsoft 365\?\s+NO'
        @($script:Events | Where-Object { $_ -match 'signIns|authentication/methods' }).Count | Should -Be 0 -Because 'there is no cloud user to read sign-ins for'
    }

    It 'AC4_UserNotFoundOrAmbiguous: nothing in Microsoft 365 and nothing in AD -> still "No Microsoft 365 user matched", exit 2' {
        New-Scenario @{ UpnMatches = @(); FallbackMatches = @() }
        $r = Invoke-Entry @{ SkipOnPremises = $false }
        $r.ExitCode | Should -Be 2
        ((Get-HostText) + "`n" + $r.Message) | Should -Match 'No Microsoft 365 user matched'
    }

    It 'AC4_UserNotFoundOrAmbiguous: nothing in Microsoft 365 and no DC answers -> exit 2, not a crash' {
        New-Scenario @{ UpnMatches = @(); FallbackMatches = @() }
        $script:AdThrow = $script:NoDcMessage
        $r = Invoke-Entry @{ SkipOnPremises = $false }
        $script:LastError | Should -BeNullOrEmpty
        $r.ExitCode | Should -Be 2
    }

    It 'AC25_UpnMismatch: synced user is matched by SID first (Get-ADUser -Identity <SID>), own Graph object is not an address conflict' {
        New-Scenario @{ UpnMatches = @((New-SyncedCloudUser)) }
        $r = Invoke-Entry @{ SkipOnPremises = $false }
        $script:AdCalls.Count | Should -Be 1
        $script:AdCalls[0].Identity | Should -Be $script:Sid
        $r.ExitCode | Should -Be 0 -Because 'the only /users hit for the AD address is the user itself'
        (Get-HostText) | Should -Match 'Can Jane Doe sign in to Microsoft 365\?\s+YES'
    }

    It 'AC25_UpnMismatch: AD UPN differs -> Warning with both values printed' {
        New-Scenario @{ UpnMatches = @((New-SyncedCloudUser)) }
        $script:AdBySid = New-AdAccount @{ UserPrincipalName = 'jane.doe@contoso.com' }
        $null = Invoke-Entry @{ SkipOnPremises = $false }
        $text = Get-HostText
        $text | Should -Match 'jane\.doe@contoso\.com'
        $text | Should -Match 'jdoe@contoso\.com'
    }

    It 'Edge_ServerParameterReachesGetADUser: -Server dc01.contoso.com is passed to Get-ADUser' {
        New-Scenario @{ UpnMatches = @((New-SyncedCloudUser)) }
        $null = Invoke-Entry @{ SkipOnPremises = $false; Server = 'dc01.contoso.com' }
        $script:AdCalls[0].Server | Should -Be 'dc01.contoso.com'
    }

    It 'Edge_CredentialNeverWritten: a supplied -Credential reaches Get-ADUser but its user name and password appear nowhere in the result, CSV, HTML, note or console' {
        $secret = 'Pa55w0rd-NotReal-9x'
        $account = 'CONTOSO\svc-m365check'
        $cred = New-Object System.Management.Automation.PSCredential ($account, (ConvertTo-SecureString $secret -AsPlainText -Force))
        New-Scenario @{ UpnMatches = @((New-SyncedCloudUser)) }
        $out = New-OutDir
        $r = Invoke-Entry @{ SkipOnPremises = $false; Credential = $cred; Server = 'dc01.contoso.com'; TicketNumber = 'T2001'; OutputPath = $out }
        $script:LastError | Should -BeNullOrEmpty
        $script:AdCalls[0].Credential | Should -Not -BeNullOrEmpty -Because 'the credential must be used, or this test proves nothing'
        $files = @(Get-ChildItem -LiteralPath $out -Recurse -File)
        @($files | Where-Object { $_.Extension -eq '.html' }).Count | Should -Be 1
        @($files | Where-Object { $_.Extension -eq '.csv' }).Count | Should -Be 1
        @($files | Where-Object { $_.Name -like 'Note_*.txt' }).Count | Should -Be 1
        $everything = @((Get-HostText), ($r | ConvertTo-Json -Depth 6 -WarningAction Ignore), ($r | Out-String -Width 4000)) + @($files | ForEach-Object { [System.IO.File]::ReadAllText($_.FullName) })
        foreach ($text in $everything) {
            $text | Should -Not -Match ([regex]::Escape($secret))
            $text | Should -Not -Match ([regex]::Escape('svc-m365check'))
        }
    }

    It 'Edge_CredentialNeverWritten: Get-ADUser fails with -Credential supplied -> its user name and password still appear nowhere in the result, CSV, HTML, note or console' {
        $secret = 'Pa55w0rd-NotReal-9x'
        $account = 'CONTOSO\svc-m365check'
        $cred = New-Object System.Management.Automation.PSCredential ($account, (ConvertTo-SecureString $secret -AsPlainText -Force))
        New-Scenario @{ UpnMatches = @((New-SyncedCloudUser)) }
        $script:AdThrow = 'The server has rejected the client credentials.'
        $out = New-OutDir
        $r = Invoke-Entry @{ SkipOnPremises = $false; Credential = $cred; Server = 'dc01.contoso.com'; TicketNumber = 'T2003'; OutputPath = $out }
        $script:LastError | Should -BeNullOrEmpty
        $script:AdCalls[0].Credential | Should -Not -BeNullOrEmpty -Because 'the credential must be used, or this test proves nothing'
        @($r.Assessment.CouldNotCheck | Where-Object { $_.Source -eq 'On-premises AD' }).Count | Should -Be 1 -Because 'this is the failure path'
        $files = @(Get-ChildItem -LiteralPath $out -Recurse -File)
        @($files | Where-Object { $_.Extension -eq '.html' }).Count | Should -Be 1
        @($files | Where-Object { $_.Extension -eq '.csv' }).Count | Should -Be 1
        @($files | Where-Object { $_.Name -like 'Note_*.txt' }).Count | Should -Be 1
        $everything = @((Get-HostText), ($r | ConvertTo-Json -Depth 6 -WarningAction Ignore), ($r | Out-String -Width 4000)) + @($files | ForEach-Object { [System.IO.File]::ReadAllText($_.FullName) })
        foreach ($text in $everything) {
            $text | Should -Not -Match ([regex]::Escape($secret))
            $text | Should -Not -Match ([regex]::Escape('svc-m365check'))
        }
    }

    It 'Edge_ServerIpNotOnConsole: -Server 192.0.2.10 and Get-ADUser fails -> the IP address is not printed anywhere on the console (banner included)' {
        New-Scenario @{ UpnMatches = @((New-SyncedCloudUser)) }
        $script:AdThrow = $script:NoDcMessage
        $r = Invoke-Entry @{ SkipOnPremises = $false; Server = '192.0.2.10' }
        $script:LastError | Should -BeNullOrEmpty
        $script:AdCalls[0].Server | Should -Be '192.0.2.10' -Because 'the server must be used, or this test proves nothing'
        $text = Get-HostText
        $text | Should -Match 'On-premises AD: could not check' -Because 'the failure is still reported'
        $text | Should -Not -Match ([regex]::Escape('192.0.2.10'))
    }

    It 'AC22_AddressHeldByAnotherObject: another user holds the address but the groups lookup is refused (403) -> still NO with the conflict shown, and "Address conflicts" under Could not check' {
        New-Scenario @{ UpnMatches = @((New-SyncedCloudUser)); ThrowOnGroups = $true }
        # The address lookups select only id,displayName(,onPremisesSyncEnabled); Find-M365User
        # selects the full user, so this answers only the conflict search on /users by mail.
        Mock Invoke-MgGraphRequest {
            $u = [uri]::UnescapeDataString([string]$Uri)
            if ($u -match '/users\?' -and $u -match "mail eq 'jdoe@contoso\.com'" -and $u -notmatch 'accountEnabled') {
                $script:Events.Add("GET $u")
                return @{ value = @(@{ id = 'eeeeeeee-0000-0000-0000-000000000002'; displayName = 'Jane Doe (cloud copy)'; onPremisesSyncEnabled = $null }) }
            }
            & $script:FakeGraph
        }
        $r = Invoke-Entry @{ SkipOnPremises = $false }
        $script:LastError | Should -BeNullOrEmpty
        $r.ExitCode | Should -Be 1
        $text = Get-HostText
        $text | Should -Match 'Can Jane Doe sign in to Microsoft 365\?\s+NO'
        $text | Should -Match 'Jane Doe \(cloud copy\)'
        @($r.Assessment.Reasons | Where-Object { $_.Code -eq 'AddressHeld' }).Count | Should -Be 1
        $c = @($r.Assessment.CouldNotCheck | Where-Object { $_.Source -eq 'Address conflicts' })
        $c.Count | Should -Be 1
        $c[0].Reason | Should -Match 'groups'
        $text | Should -Match 'Address conflicts: '
    }

    It 'AC20b_NeverSyncedChecksSid: no cloud user by the typed name, AD user exists, but a cloud user holds its SID -> that user is assessed, no "exists in AD but not in Microsoft 365"' {
        $sidObject = New-Object System.Security.Principal.SecurityIdentifier ($script:Sid)
        $script:AdByFilter = @((New-AdAccount @{ SID = $sidObject }))
        $cloud = New-User @{ userPrincipalName = 'jane.doe@contoso.com'; onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = $script:Sid; onPremisesProvisioningErrors = @() }
        New-Scenario @{ UpnMatches = @(); FallbackMatches = @(); SidMatches = @($cloud) }
        $r = Invoke-Entry @{ SkipOnPremises = $false }
        $script:LastError | Should -BeNullOrEmpty
        @($script:Events | Where-Object { $_ -match "^GET .*onPremisesSecurityIdentifier eq '$([regex]::Escape($script:Sid))'" }).Count | Should -BeGreaterThan 0 -Because 'the AD user''s SID is looked up in Graph first'
        $r.ExitCode | Should -Be 0
        $r.Status | Should -Be 'Ok'
        $text = Get-HostText
        $text | Should -Not -Match 'exists in AD but not in Microsoft 365'
        $text | Should -Match 'Can Jane Doe sign in to Microsoft 365\?\s+YES'
        $text | Should -Match 'jane\.doe@contoso\.com' -Because 'the cloud user found by SID is the one assessed'
    }

    It 'AC20b_NeverSyncedChecksSid: no cloud user holds the SID either -> still NO, "exists in AD but not in Microsoft 365"' {
        $sidObject = New-Object System.Security.Principal.SecurityIdentifier ($script:Sid)
        $script:AdByFilter = @((New-AdAccount @{ SID = $sidObject }))
        New-Scenario @{ UpnMatches = @(); FallbackMatches = @(); SidMatches = @() }
        $r = Invoke-Entry @{ SkipOnPremises = $false }
        @($script:Events | Where-Object { $_ -match 'onPremisesSecurityIdentifier eq' }).Count | Should -BeGreaterThan 0
        $r.ExitCode | Should -Be 1
        (Get-HostText) | Should -Match 'This account exists in AD but not in Microsoft 365'
    }

    It 'AC22c_AddressCheckFailedIsCouldNotCheck: the address lookup fails (Graph 403 on groups) -> "Address conflicts" under Could not check in the console and the ticket note' {
        New-Scenario @{ UpnMatches = @((New-SyncedCloudUser)); ThrowOnGroups = $true }
        $out = New-OutDir
        $r = Invoke-Entry @{ SkipOnPremises = $false; TicketNumber = 'T2002'; OutputPath = $out }
        $script:LastError | Should -BeNullOrEmpty
        @($r.Assessment.CouldNotCheck | Where-Object { $_.Source -eq 'Address conflicts' }).Count | Should -Be 1
        (Get-HostText) | Should -Match 'Address conflicts: '
        $noteFile = @(Get-ChildItem -LiteralPath (Join-Path $out 'Ticket_T2002') -Filter 'Note_*.txt' -ErrorAction SilentlyContinue)
        $noteFile.Count | Should -Be 1
        $lines = [System.IO.File]::ReadAllLines($noteFile[0].FullName)
        (Get-Section $lines 'Could not check:') -join "`n" | Should -Match '(?i)address conflicts'
        (Get-Section $lines 'Ruled out:') -join "`n" | Should -Not -Match '(?i)address conflict'
    }
}
