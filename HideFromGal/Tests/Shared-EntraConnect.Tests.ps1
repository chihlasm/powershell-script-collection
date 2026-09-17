BeforeAll {
    . "$PSScriptRoot\..\Shared-EntraConnect.ps1" -LoadFunctionsOnly
}

Describe 'Rule definitions (verified against Microsoft Learn)' {
    # Microsoft reserves precedence 1-99 for custom sync rules; out-of-box rules start
    # at 100. The original Block365SignIn-RuleBuilder.ps1 used 100, which collides with
    # Microsoft's reserved range. Regression guard so it cannot come back.
    # https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-change-the-configuration

    It 'keeps every custom rule precedence inside the reserved 1-99 range' {
        foreach ($key in @('BlockCloudSignIn', 'HideFromGAL')) {
            $def = Get-EntraConnectRuleDefinition -Key $key
            $def.Precedence | Should -BeGreaterThan 0
            $def.Precedence | Should -BeLessThan 100
        }
    }

    It 'does not reuse precedence 100, which belongs to the first out-of-box rule' {
        (Get-EntraConnectRuleDefinition -Key 'BlockCloudSignIn').Precedence | Should -Not -Be 100
    }

    It 'gives the two rules distinct precedence values' {
        # Precedence must be unique across sync rules in the system.
        $a = (Get-EntraConnectRuleDefinition -Key 'BlockCloudSignIn').Precedence
        $b = (Get-EntraConnectRuleDefinition -Key 'HideFromGAL').Precedence
        $a | Should -Not -Be $b
    }

    It 'blocks cloud sign-in by flowing to cloudFiltered' {
        $def = Get-EntraConnectRuleDefinition -Key 'BlockCloudSignIn'
        $def.Destination     | Should -Be 'cloudFiltered'
        $def.SourceAttribute | Should -Be 'msDS-cloudExtensionAttribute10'
    }

    It 'hides from the GAL by flowing to msExchHideFromAddressLists' {
        $def = Get-EntraConnectRuleDefinition -Key 'HideFromGAL'
        $def.Destination     | Should -Be 'msExchHideFromAddressLists'
        $def.SourceAttribute | Should -Be 'msDS-cloudExtensionAttribute1'
    }

    It 'references its own source attribute inside its expression' {
        foreach ($key in @('BlockCloudSignIn', 'HideFromGAL')) {
            $def = Get-EntraConnectRuleDefinition -Key $key
            $def.Expression | Should -Match ([regex]::Escape($def.SourceAttribute))
            $def.Expression | Should -Match ([regex]::Escape($def.MarkerValue))
        }
    }
}

Describe 'Test-EntraConnectRuleShape' {
    BeforeAll {
        $script:Def = Get-EntraConnectRuleDefinition -Key 'BlockCloudSignIn'

        function New-FakeRule {
            param(
                [string]$Name = 'Block cloud sign-in - contoso.local',
                [string]$Destination = 'cloudFiltered',
                [string]$Expression
            )
            if (-not $PSBoundParameters.ContainsKey('Expression')) {
                $Expression = (Get-EntraConnectRuleDefinition -Key 'BlockCloudSignIn').Expression
            }
            [PSCustomObject]@{
                Name       = $Name
                Identifier = [guid]::NewGuid().ToString()
                Precedence = 60
                Direction  = 'Inbound'
                AttributeFlowMappings = @(
                    [PSCustomObject]@{ Destination = $Destination; Expression = $Expression; FlowType = 'Expression' }
                )
            }
        }
    }

    It 'reports Present for a correctly configured rule' {
        $r = Test-EntraConnectRuleShape -Rule (New-FakeRule) -Definition $script:Def
        $r.State | Should -Be 'Present'
    }

    It 'reports Missing when no rule was found' {
        # This is the state the whole toolkit exists to catch: Entra Connect moved to a
        # new server and the custom rule was never recreated.
        $r = Test-EntraConnectRuleShape -Rule $null -Definition $script:Def
        $r.State  | Should -Be 'Missing'
        $r.Reason | Should -Match 'Nothing is enforcing'
    }

    It 'tolerates cosmetic whitespace differences in the expression' {
        $spaced = $script:Def.Expression -replace ',', ', '
        $r = Test-EntraConnectRuleShape -Rule (New-FakeRule -Expression $spaced) -Definition $script:Def
        $r.State | Should -Be 'Present'
    }

    It 'reports Misconfigured when the rule flows to the wrong destination' {
        $r = Test-EntraConnectRuleShape -Rule (New-FakeRule -Destination 'msExchHideFromAddressLists') -Definition $script:Def
        $r.State | Should -Be 'Misconfigured'
    }

    It 'accepts a hand-built rule whose expression differs but still reads the marker' {
        # Regression guard: a real production rule ("Block 365 Sign In", precedence 10)
        # enforced the same behavior with different expression text and was wrongly
        # reported as missing/broken. The tool verifies that enforcement exists - it is
        # not the author of the only acceptable rule.
        $custom = 'IIF([msDS-cloudExtensionAttribute10]="BlockCloudSignIn",True,NULL)'
        $r = Test-EntraConnectRuleShape -Rule (New-FakeRule -Expression $custom) -Definition $script:Def
        $r.State | Should -Be 'Present'
    }

    It 'accepts a rule driven by a scoping filter rather than the expression' {
        # The Synchronization Rules Editor commonly builds these with a scoping filter
        # on the attribute plus a constant flow to the destination.
        $rule = [PSCustomObject]@{
            Name       = 'Block 365 Sign In'
            Identifier = 'x'
            Precedence = 10
            Direction  = 'Inbound'
            AttributeFlowMappings = @(
                [PSCustomObject]@{ Destination = 'cloudFiltered'; Expression = 'True'; FlowType = 'Constant'; Source = '' }
            )
            ScopeConditions = @(
                [PSCustomObject]@{ Attribute = 'msDS-cloudExtensionAttribute10'; Operator = 'EQUAL'; Value = 'BlockCloudSignIn' }
            )
        }
        (Test-EntraConnectRuleShape -Rule $rule -Definition $script:Def).State | Should -Be 'Present'
    }

    It 'accepts a rule that blocks sign-in via accountEnabled instead of cloudFiltered' {
        # Regression guard for the real production rule on CWRADDCSRV:
        #   Name: 'Block 365 Sign In', Precedence 10, Direction Inbound
        #   Flow: accountEnabled <- Constant {False}
        #   Scope: msDS-cloudExtensionAttribute10 EQUAL BlockCloudSignIn
        # Checking only for cloudFiltered reported this working rule as "NOT FOUND" and
        # disabled the tool. Disabling the synced account blocks sign-in just as surely
        # as filtering the object out, and keeps licenses and the mailbox intact.
        $rule = [PSCustomObject]@{
            Name       = 'Block 365 Sign In'
            Identifier = 'x'
            Precedence = 10
            Direction  = 'Inbound'
            AttributeFlowMappings = @(
                [PSCustomObject]@{ Destination = 'accountEnabled'; Expression = ''; FlowType = 'Constant'; Source = 'False' }
            )
            ScopeConditions = @(
                [PSCustomObject]@{ Attribute = 'msDS-cloudExtensionAttribute10'; Operator = 'EQUAL'; Value = 'BlockCloudSignIn' }
            )
        }
        $r = Test-EntraConnectRuleShape -Rule $rule -Definition $script:Def
        $r.State  | Should -Be 'Present'
        $r.Reason | Should -Match 'disables the synced account'
    }

    It 'names which mechanism a cloudFiltered rule uses' {
        $r = Test-EntraConnectRuleShape -Rule (New-FakeRule) -Definition $script:Def
        $r.Reason | Should -Match 'removes the user from Entra ID'
    }

    It 'does not accept accountEnabled for the GAL rule' {
        # accountEnabled is only an alternative for BLOCKING sign-in. Hiding from the GAL
        # has exactly one correct destination.
        $galDef = Get-EntraConnectRuleDefinition -Key 'HideFromGAL'
        $rule = [PSCustomObject]@{
            Name = 'Something'; Identifier = 'x'; Precedence = 10; Direction = 'Inbound'
            AttributeFlowMappings = @(
                [PSCustomObject]@{ Destination = 'accountEnabled'; Expression = ''; FlowType = 'Constant'; Source = 'False' }
            )
        }
        (Test-EntraConnectRuleShape -Rule $rule -Definition $galDef).State | Should -Be 'Misconfigured'
    }

    It 'reports Misconfigured when the rule never references the marker attribute' {
        # Writing the destination is not enough - if nothing reads our marker, setting
        # the attribute changes nothing.
        $unrelated = 'IIF([userAccountControl]=514,True,NULL)'
        $r = Test-EntraConnectRuleShape -Rule (New-FakeRule -Expression $unrelated) -Definition $script:Def
        $r.State | Should -Be 'Misconfigured'
        $r.Reason | Should -Match 'could not find any reference'
    }

    It 'reports Misconfigured when the rule has no attribute flows at all' {
        $bare = [PSCustomObject]@{
            Name = 'Block cloud sign-in'; Identifier = 'x'; Precedence = 60
            Direction = 'Inbound'; AttributeFlowMappings = @()
        }
        (Test-EntraConnectRuleShape -Rule $bare -Definition $script:Def).State | Should -Be 'Misconfigured'
    }
}

Describe 'New-EntraConnectStatus enforcement gating' {
    # The single most important distinction in this toolkit: "we could not check" must
    # never be treated as "the rule is missing". Mixing them either blocks a healthy
    # system or silently permits an unenforced one.

    It 'allows enforcement only when the rule was positively verified' {
        (New-EntraConnectStatus -State 'Present').CanEnforce       | Should -BeTrue
        (New-EntraConnectStatus -State 'Missing').CanEnforce       | Should -BeFalse
        (New-EntraConnectStatus -State 'Misconfigured').CanEnforce | Should -BeFalse
        (New-EntraConnectStatus -State 'Unknown').CanEnforce       | Should -BeFalse
    }

    It 'blocks the tool only when the rule was positively confirmed broken' {
        (New-EntraConnectStatus -State 'Missing').ShouldBlock       | Should -BeTrue
        (New-EntraConnectStatus -State 'Misconfigured').ShouldBlock | Should -BeTrue
    }

    It 'does NOT block when the rule could not be checked' {
        # Regression guard: a helpdesk user without local admin on the Connect server,
        # or a WinRM failure, must not brick the tool.
        $s = New-EntraConnectStatus -State 'Unknown'
        $s.ShouldBlock | Should -BeFalse
        $s.CanEnforce  | Should -BeFalse
    }

    It 'never reports both CanEnforce and ShouldBlock at once' {
        foreach ($state in @('Present', 'Missing', 'Misconfigured', 'Unknown')) {
            $s = New-EntraConnectStatus -State $state
            ($s.CanEnforce -and $s.ShouldBlock) | Should -BeFalse
        }
    }
}

Describe 'Get-EntraConnectStatusPresentation' {
    It 'uses repo-standard status prefixes' {
        (Get-EntraConnectStatusPresentation -State 'Present').Prefix       | Should -Be '[PASS]'
        (Get-EntraConnectStatusPresentation -State 'Missing').Prefix       | Should -Be '[FAIL]'
        (Get-EntraConnectStatusPresentation -State 'Misconfigured').Prefix | Should -Be '[FAIL]'
        (Get-EntraConnectStatusPresentation -State 'Unknown').Prefix       | Should -Be '[WARN]'
    }

    It 'distinguishes unverifiable from broken by color' {
        # Amber for Unknown, red for broken - so the two are never confused at a glance.
        (Get-EntraConnectStatusPresentation -State 'Unknown').ConsoleColor | Should -Be 'Yellow'
        (Get-EntraConnectStatusPresentation -State 'Missing').ConsoleColor | Should -Be 'Red'
    }

    It 'returns a headline for every state' {
        foreach ($state in @('Present', 'Missing', 'Misconfigured', 'Unknown')) {
            (Get-EntraConnectStatusPresentation -State $state).Headline | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Settings cache' {
    BeforeAll {
        $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "ec-tests-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path $script:TempDir -Force | Out-Null
    }
    AfterAll {
        if (Test-Path $script:TempDir) { Remove-Item $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'round-trips a cached server name' {
        $p = Join-Path $script:TempDir 'settings.json'
        Write-EntraConnectSettings -Path $p -Server 'AADC02.contoso.local'
        (Read-EntraConnectSettings -Path $p).EntraConnectServer | Should -Be 'AADC02.contoso.local'
    }

    It 'returns null for a missing settings file' {
        Read-EntraConnectSettings -Path (Join-Path $script:TempDir 'nope.json') | Should -BeNullOrEmpty
    }

    It 'returns null rather than throwing on a corrupt settings file' {
        # A hand-edited cache must degrade to rediscovery, not take the GUI down.
        $p = Join-Path $script:TempDir 'corrupt.json'
        Set-Content -LiteralPath $p -Value '{ this is not json' -Encoding UTF8
        { Read-EntraConnectSettings -Path $p } | Should -Not -Throw
        Read-EntraConnectSettings -Path $p | Should -BeNullOrEmpty
    }
}

Describe 'Test-IsLocalMachine' {
    # The ADSync management interface is a WCF endpoint bound to
    # net.pipe://localhost/ADSyncManagement and refuses calls arriving over a PowerShell
    # remoting hop. Running Get-ADSyncRule via Invoke-Command against the local server
    # therefore fails with "no endpoint listening" even though the service is healthy.
    # Detecting "this is me" and calling directly is the only thing that works.
    # https://learn.microsoft.com/entra/identity/hybrid/connect/reference-connect-adsync

    It 'recognizes the local machine by short name' {
        Test-IsLocalMachine -ComputerName $env:COMPUTERNAME | Should -BeTrue
    }

    It 'recognizes the local machine by FQDN' {
        Test-IsLocalMachine -ComputerName "$env:COMPUTERNAME.contoso.local" | Should -BeTrue
    }

    It 'recognizes localhost aliases' {
        foreach ($alias in @('localhost', '.', '127.0.0.1', '::1')) {
            Test-IsLocalMachine -ComputerName $alias | Should -BeTrue
        }
    }

    It 'is case-insensitive and tolerates a trailing dot' {
        Test-IsLocalMachine -ComputerName $env:COMPUTERNAME.ToLower()  | Should -BeTrue
        Test-IsLocalMachine -ComputerName "$env:COMPUTERNAME."          | Should -BeTrue
    }

    It 'treats an empty target as local' {
        Test-IsLocalMachine -ComputerName '' | Should -BeTrue
    }

    It 'does not mistake a different server for the local machine' {
        Test-IsLocalMachine -ComputerName 'SOMEOTHERBOX99.contoso.local' | Should -BeFalse
    }

    It 'does not match a server whose name merely starts the same' {
        # "$me.*" must match an FQDN, not a longer hostname like MYBOX2.
        Test-IsLocalMachine -ComputerName "$($env:COMPUTERNAME)2" | Should -BeFalse
    }
}

Describe 'Invoke-AdSyncCommand' {
    It 'runs the scriptblock directly when the target is local, without remoting' {
        # Regression guard: routing a local call through Invoke-Command is what produced
        # the "no endpoint listening on net.pipe://localhost/ADSyncManagement" failure on
        # a server that WAS the Entra Connect server.
        Mock -CommandName Invoke-Command -MockWith { throw 'Invoke-Command must not be used for a local target' }

        $result = Invoke-AdSyncCommand -ComputerName $env:COMPUTERNAME `
                                       -ScriptBlock { param($x) "ran-locally:$x" } `
                                       -ArgumentList @('ok')

        $result | Should -Be 'ran-locally:ok'
        Should -Invoke Invoke-Command -Times 0
    }
}

Describe 'Test-AdSyncServer' {
    # Regression guard: the original probe returned $true whenever Get-CimInstance did
    # not throw, but a -Filter that matches nothing returns no object rather than an
    # error. That made every reachable server look like an Entra Connect server, so
    # discovery latched onto a domain controller and then failed with a SOAP
    # "no endpoint listening" fault when it tried to read sync rules there.

    It 'returns false when the host has no ADSync service' {
        Mock -CommandName Get-CimInstance -MockWith { }   # no match: returns nothing
        Test-AdSyncServer -ComputerName 'dc01.contoso.local' | Should -BeFalse
    }

    It 'returns true only when a service actually named ADSync comes back' {
        Mock -CommandName Get-CimInstance -MockWith {
            [PSCustomObject]@{ Name = 'ADSync'; State = 'Running' }
        }
        Test-AdSyncServer -ComputerName 'aadc02.contoso.local' | Should -BeTrue
    }

    It 'returns false rather than throwing when the host is unreachable' {
        Mock -CommandName Get-CimInstance -MockWith { throw 'RPC server is unavailable' }
        { Test-AdSyncServer -ComputerName 'gone.contoso.local' } | Should -Not -Throw
        Test-AdSyncServer -ComputerName 'gone.contoso.local' | Should -BeFalse
    }
}

Describe 'ConvertTo-ComparableExpression' {
    It 'strips all whitespace' {
        ConvertTo-ComparableExpression -Expression "IIF( a , b )" | Should -Be 'IIF(a,b)'
    }
    It 'returns empty string for null or blank input' {
        ConvertTo-ComparableExpression -Expression $null | Should -Be ''
        ConvertTo-ComparableExpression -Expression '   ' | Should -Be ''
    }
    It 'preserves case' {
        ConvertTo-ComparableExpression -Expression 'IsPresent' | Should -Be 'IsPresent'
    }
}
