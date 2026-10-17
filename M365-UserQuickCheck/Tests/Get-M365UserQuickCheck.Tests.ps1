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
        Mock Invoke-MgGraphRequest {
            $u = [uri]::UnescapeDataString([string]$Uri)
            $script:Events.Add("GET $u")
            $s = $script:Scn
            switch -Regex ($u) {
                '/me/memberOf' { return @{ value = @($s.Roles | ForEach-Object { @{ '@odata.type' = '#microsoft.graph.directoryRole'; displayName = $_ } }) } }
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
                '/users' {
                    if ($s.ThrowOnUsers) { throw 'boom: synthetic failure while looking up the user' }
                    if ($u -match 'userPrincipalName eq') { return @{ value = @($s.UpnMatches) } }
                    return @{ value = @($s.FallbackMatches) }
                }
                default { return @{ value = @() } }
            }
        }
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
                    '/me/memberOf' { return @{ value = @() } }
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

    It 'AC3_ReadOnlyByConstruction: no write cmdlet appears in any script' {
        $bad = '^(New|Set|Update|Remove)-Mg|^Set-AD|^Enable-ADAccount$|^Unlock-ADAccount$|^Set-ADAccountPassword$'
        $hits = @()
        foreach ($name in $script:Asts.Keys) {
            $hits += @(Get-Commands $script:Asts[$name] | Where-Object { $_.GetCommandName() -match $bad } | ForEach-Object { "$name line $($_.Extent.StartLineNumber): $($_.GetCommandName())" })
        }
        $script:Asts.Count | Should -BeGreaterThan 0 -Because 'there must be scripts to scan'
        $hits | Should -BeNullOrEmpty
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
}

Describe 'Mocks cannot lie about parameter names' {
    BeforeAll {
        $script:RealParams = @{}
        $json = & pwsh -NoProfile -Command @'
$r = @{}
foreach ($n in 'Connect-MgGraph','Invoke-MgGraphRequest','Disconnect-MgGraph','Get-MgContext') {
  $c = Get-Command $n -Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
  if ($c) { $r[$n] = @($c.Parameters.Keys) }
}
$r | ConvertTo-Json -Compress
'@
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
