<#
    Tests for SyncedUserFixes.Core.ps1 (Pester 5; Windows PowerShell 5.1 and PowerShell 7).

    Carries over every test of the retired Shared-EntraConnect.ps1 (Block 365 Sign-in and
    HideFromGal folders) and adds rule creation, the generated rule script, AD search filters
    and marker writes. ADSync and ActiveDirectory cmdlets are replaced by fakes/mocks.

    Expectations come from Microsoft Learn (see the Core script's REFERENCES): custom rules use
    precedence 1-99; NULL lets a lower-precedence rule write the attribute; cloudFiltered
    deletes the object from Entra ID; LDAP filter values escape \ * ( ) NUL.

    Run:  Invoke-Pester .\M365-SyncedUserFixes\Tests
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..\SyncedUserFixes.Core.ps1') -LoadFunctionsOnly

    # Stand-ins so Pester can mock cmdlets that do not exist on a dev machine. They declare the
    # real parameter names: a mock copies the stand-in's signature, and a -ParameterFilter can
    # only see parameters that signature declares.
    $standIns = @{
        'Get-ADUser'                     = 'Identity', 'LDAPFilter', 'Filter', 'Properties', 'ResultSetSize', 'SearchBase', 'Server'
        'Set-ADUser'                     = 'Identity', 'Replace', 'Clear', 'Server'
        'Get-ADSyncConnector'            = 'Name', 'Identifier'
        'Get-ADSyncRule'                 = 'Identifier'
        'New-ADSyncRule'                 = 'Name', 'Identifier', 'Description', 'Direction', 'Precedence', 'SourceObjectType', 'TargetObjectType', 'Connector', 'LinkType'
        'Add-ADSyncAttributeFlowMapping' = 'SynchronizationRule', 'Destination', 'FlowType', 'ValueMergeType', 'Expression'
        'Add-ADSyncRule'                 = 'SynchronizationRule'
        'Remove-ADSyncRule'              = 'Identifier'
    }
    # Always defined, even when a module of that name is installed: a function beats a cmdlet,
    # so the tests see the same signature everywhere (a test double of the AD module on one
    # machine lacked -ResultSize).
    foreach ($name in $standIns.Keys) {
        $params = ($standIns[$name] | ForEach-Object { "`$$_" }) -join ', '
        Set-Item -Path "function:global:$name" -Value ([scriptblock]::Create("[CmdletBinding()] param($params) throw '$name should be mocked'"))
    }

    function New-FlatRule {
        param(
            [string]$Name = 'Block cloud sign-in (disable account) - contoso.local',
            [string]$Destination = 'accountEnabled',
            [string]$Expression = 'IIF(IsPresent([msDS-cloudExtensionAttribute10]),IIF([msDS-cloudExtensionAttribute10]="BlockCloudSignIn",False,NULL),NULL)',
            [int]$Precedence = 60,
            [bool]$Disabled = $false,
            [object]$ReferencesMarker = $null
        )
        $r = [PSCustomObject]@{
            Name = $Name; Identifier = [guid]::NewGuid().ToString(); Precedence = $Precedence; Disabled = $Disabled
            AttributeFlowMappings = @([PSCustomObject]@{ Destination = $Destination; Expression = $Expression; FlowType = 'Expression'; Source = '' })
        }
        if ($null -ne $ReferencesMarker) { $r | Add-Member -NotePropertyName ReferencesMarker -NotePropertyValue $ReferencesMarker }
        $r
    }
}

Describe 'Fix and rule definitions (verified against Microsoft Learn)' {
    It 'keeps every custom rule precedence inside the reserved 1-99 range' {
        foreach ($key in 'BlockCloudSignIn', 'HideFromGAL') {
            $def = Get-EntraConnectRuleDefinition -Key $key
            $def.Precedence | Should -BeGreaterThan 0
            $def.Precedence | Should -BeLessThan 100
        }
    }
    It 'gives the two rules distinct precedence values' {
        (Get-EntraConnectRuleDefinition -Key 'BlockCloudSignIn').Precedence | Should -Not -Be (Get-EntraConnectRuleDefinition -Key 'HideFromGAL').Precedence
    }
    It 'keeps the same attributes and marker values as the retired tools, so existing marks still count' {
        (Get-SyncedUserFeature -Key 'BlockSignIn').Attribute   | Should -Be 'msDS-cloudExtensionAttribute10'
        (Get-SyncedUserFeature -Key 'BlockSignIn').MarkerValue | Should -BeExactly 'BlockCloudSignIn'
        (Get-SyncedUserFeature -Key 'HideFromGAL').Attribute   | Should -Be 'msDS-cloudExtensionAttribute1'
        (Get-SyncedUserFeature -Key 'HideFromGAL').MarkerValue | Should -BeExactly 'HideFromGAL'
    }
    It 'accepts both accountEnabled and cloudFiltered as ways to block sign-in' {
        (Get-EntraConnectRuleDefinition -Key 'BlockCloudSignIn').AcceptedDestinations | Should -Be @('accountEnabled', 'cloudFiltered')
    }
    It 'accepts only msExchHideFromAddressLists for hiding' {
        (Get-EntraConnectRuleDefinition -Key 'HideFromGAL').AcceptedDestinations | Should -Be @('msExchHideFromAddressLists')
    }
}

Describe 'Get-SyncRuleBlueprint' {
    It 'defaults blocking to disabling the account (accountEnabled), not deleting it' {
        $bp = Get-SyncRuleBlueprint -Key 'BlockCloudSignIn' -Domain 'contoso.local'
        $bp.Method        | Should -Be 'DisableSignIn'
        $bp.Destination   | Should -Be 'accountEnabled'
        $bp.IsDestructive | Should -BeFalse
    }
    It 'flows False for a marked user and NULL otherwise, so the out-of-box AccountEnabled rule still decides for everyone else' {
        # A True/False result for unmarked users would override every user's enabled state.
        $bp = Get-SyncRuleBlueprint -Key 'BlockCloudSignIn' -Method 'DisableSignIn' -Domain 'contoso.local'
        $bp.Expression | Should -BeExactly 'IIF(IsPresent([msDS-cloudExtensionAttribute10]),IIF([msDS-cloudExtensionAttribute10]="BlockCloudSignIn",False,NULL),NULL)'
        $bp.Expression | Should -Not -Match ',True,'
    }
    It 'marks the cloudFiltered variant as destructive' {
        $bp = Get-SyncRuleBlueprint -Key 'BlockCloudSignIn' -Method 'RemoveFromM365' -Domain 'contoso.local'
        $bp.Destination   | Should -Be 'cloudFiltered'
        $bp.IsDestructive | Should -BeTrue
        $bp.Consequence   | Should -Match 'DELETES'
        $bp.Expression    | Should -Match 'BlockCloudSignIn",True,NULL'
    }
    It 'names the rule after the method and the domain' {
        (Get-SyncRuleBlueprint -Key 'BlockCloudSignIn' -Domain 'contoso.local').Name | Should -Be 'Block cloud sign-in (disable account) - contoso.local'
        (Get-SyncRuleBlueprint -Key 'HideFromGAL' -Domain 'contoso.local').Name      | Should -Be 'Hide user from GAL - contoso.local'
    }
    It 'references its own marker in every expression, with the exact (case-sensitive) spelling' {
        foreach ($key in 'BlockCloudSignIn', 'HideFromGAL') {
            $def = Get-EntraConnectRuleDefinition -Key $key
            foreach ($m in $def.Methods.Keys) {
                $bp = Get-SyncRuleBlueprint -Key $key -Method $m -Domain 'x.local'
                $bp.Expression | Should -MatchExactly ([regex]::Escape("[$($def.SourceAttribute)]"))
                $bp.Expression | Should -MatchExactly ([regex]::Escape("`"$($def.MarkerValue)`""))
                $bp.Expression | Should -MatchExactly '^IIF\(IsPresent\('
            }
        }
    }
    It 'rejects a method that does not belong to the rule' {
        { Get-SyncRuleBlueprint -Key 'HideFromGAL' -Method 'RemoveFromM365' -Domain 'x.local' } | Should -Throw
    }
    It 'shows the destination and expression in the preview text' {
        $text = Format-SyncRuleBlueprint -Blueprint (Get-SyncRuleBlueprint -Key 'HideFromGAL' -Domain 'contoso.local')
        $text | Should -Match 'Writes\s+: msExchHideFromAddressLists'
        $text | Should -Match 'Precedence\s+: 50'
    }
}

Describe 'Test-EntraConnectRuleShape' {
    BeforeAll { $script:Def = Get-EntraConnectRuleDefinition -Key 'BlockCloudSignIn' }

    It 'reports Present for the toolkit''s own accountEnabled rule and names the mechanism' {
        $r = Test-EntraConnectRuleShape -Rule (New-FlatRule) -Definition $script:Def
        $r.State     | Should -Be 'Present'
        $r.Mechanism | Should -Be 'accountEnabled'
        $r.Reason    | Should -Match 'disables the Microsoft 365 account'
    }
    It 'reports Present for a cloudFiltered rule and says it removes the person' {
        $rule = New-FlatRule -Destination 'cloudFiltered' -Expression (Get-SyncRuleBlueprint -Key 'BlockCloudSignIn' -Method 'RemoveFromM365' -Domain 'x').Expression
        $r = Test-EntraConnectRuleShape -Rule $rule -Definition $script:Def
        $r.State     | Should -Be 'Present'
        $r.Mechanism | Should -Be 'cloudFiltered'
        $r.Reason    | Should -Match 'removes the person from Microsoft 365'
    }
    It 'reports Missing when no rule was found (the after-a-migration case)' {
        $r = Test-EntraConnectRuleShape -Rule $null -Definition $script:Def
        $r.State  | Should -Be 'Missing'
        $r.Reason | Should -Match 'Nothing is enforcing'
    }
    It 'accepts a hand-built rule driven by a scoping filter with a constant flow (regression)' {
        # Real production rule: "Block 365 Sign In", precedence 10, accountEnabled <- Constant False,
        # scope msDS-cloudExtensionAttribute10 EQUAL BlockCloudSignIn. Once reported as NOT FOUND.
        $rule = [PSCustomObject]@{
            Name = 'Block 365 Sign In'; Identifier = 'x'; Precedence = 10
            AttributeFlowMappings = @([PSCustomObject]@{ Destination = 'accountEnabled'; Expression = ''; FlowType = 'Constant'; Source = 'False' })
            ScopeConditions = @([PSCustomObject]@{ Attribute = 'msDS-cloudExtensionAttribute10'; Operator = 'EQUAL'; Value = 'BlockCloudSignIn' })
        }
        $r = Test-EntraConnectRuleShape -Rule $rule -Definition $script:Def
        $r.State  | Should -Be 'Present'
        $r.Reason | Should -Match 'disables the Microsoft 365 account'
    }
    It 'accepts a differently written expression that still reads the marker' {
        $r = Test-EntraConnectRuleShape -Rule (New-FlatRule -Expression 'IIF([msDS-cloudExtensionAttribute10]="BlockCloudSignIn",False,NULL)') -Definition $script:Def
        $r.State | Should -Be 'Present'
    }
    It 'reports Misconfigured when the rule writes the wrong destination' {
        (Test-EntraConnectRuleShape -Rule (New-FlatRule -Destination 'msExchHideFromAddressLists') -Definition $script:Def).State | Should -Be 'Misconfigured'
    }
    It 'reports Misconfigured when the rule never reads the marker' {
        $r = Test-EntraConnectRuleShape -Rule (New-FlatRule -Expression 'IIF([userAccountControl]=514,False,NULL)') -Definition $script:Def
        $r.State  | Should -Be 'Misconfigured'
        $r.Reason | Should -Match 'could not find any reference'
    }
    It 'trusts the server-side ReferencesMarker flag when present' {
        (Test-EntraConnectRuleShape -Rule (New-FlatRule -Expression 'True' -ReferencesMarker $true) -Definition $script:Def).State | Should -Be 'Present'
        (Test-EntraConnectRuleShape -Rule (New-FlatRule -ReferencesMarker $false) -Definition $script:Def).State | Should -Be 'Misconfigured'
    }
    It 'does not accept accountEnabled for the address-book rule' {
        (Test-EntraConnectRuleShape -Rule (New-FlatRule) -Definition (Get-EntraConnectRuleDefinition -Key 'HideFromGAL')).State | Should -Be 'Misconfigured'
    }
    It 'reports Misconfigured when the rule has no attribute flows' {
        $bare = [PSCustomObject]@{ Name = 'x'; Identifier = 'x'; Precedence = 60; AttributeFlowMappings = @() }
        (Test-EntraConnectRuleShape -Rule $bare -Definition $script:Def).State | Should -Be 'Misconfigured'
    }
}

Describe 'Select-EnforcingSyncRule' {
    It 'prefers an enabled rule that reads the marker over a disabled one' {
        $disabled = New-FlatRule -Name 'old' -Disabled $true -ReferencesMarker $true
        $live = New-FlatRule -Name 'live' -ReferencesMarker $true
        (Select-EnforcingSyncRule -Rules @($disabled, $live)).Name | Should -Be 'live'
    }
    It 'falls back to the first candidate so the caller can say what it found' {
        (Select-EnforcingSyncRule -Rules @((New-FlatRule -Name 'other' -ReferencesMarker $false))).Name | Should -Be 'other'
    }
    It 'returns nothing for no candidates' {
        Select-EnforcingSyncRule -Rules @() | Should -BeNullOrEmpty
    }
}

Describe 'Test-EntraConnectRule' {
    BeforeEach {
        Mock Find-EntraConnectServer { [PSCustomObject]@{ Server = 'AADC01'; Source = 'Explicit' } }
        Mock Write-EntraConnectSettings { }
    }

    It 'reports a disabled enforcing rule as broken' {
        Mock Invoke-AdSyncCommand { [PSCustomObject]@{ Outcome = 'Ok'; Rules = @((New-FlatRule -Disabled $true -ReferencesMarker $true)); AttributeImported = $true } }
        $s = Test-EntraConnectRule -RuleKey 'BlockCloudSignIn' -ComputerName 'AADC01'
        $s.State       | Should -Be 'Misconfigured'
        $s.Reason      | Should -Match 'DISABLED'
        $s.ShouldBlock | Should -BeTrue
    }
    It 'warns when more than one rule reacts to the marker' {
        Mock Invoke-AdSyncCommand { [PSCustomObject]@{ Outcome = 'Ok'; Rules = @((New-FlatRule -Name 'a' -ReferencesMarker $true), (New-FlatRule -Name 'b' -Destination 'cloudFiltered' -ReferencesMarker $true)); AttributeImported = $true } }
        $s = Test-EntraConnectRule -RuleKey 'BlockCloudSignIn' -ComputerName 'AADC01'
        $s.State    | Should -Be 'Present'
        $s.Warnings | Should -Match 'More than one sync rule'
    }
    It 'warns when the AD connector does not import the marker attribute' {
        Mock Invoke-AdSyncCommand { [PSCustomObject]@{ Outcome = 'Ok'; Rules = @((New-FlatRule -ReferencesMarker $true)); AttributeImported = $false } }
        (Test-EntraConnectRule -RuleKey 'BlockCloudSignIn' -ComputerName 'AADC01').Warnings | Should -Match 'does not import'
    }
    It 'does not warn when it could not tell whether the attribute is imported' {
        Mock Invoke-AdSyncCommand { [PSCustomObject]@{ Outcome = 'Ok'; Rules = @((New-FlatRule -ReferencesMarker $true)); AttributeImported = $null } }
        @((Test-EntraConnectRule -RuleKey 'BlockCloudSignIn' -ComputerName 'AADC01').Warnings).Count | Should -Be 0
    }
    It 'reports Missing, with a pointer to the sync rules page, when no rule exists' {
        Mock Invoke-AdSyncCommand { [PSCustomObject]@{ Outcome = 'Ok'; Rules = @(); AttributeImported = $true } }
        $s = Test-EntraConnectRule -RuleKey 'HideFromGAL' -ComputerName 'AADC01'
        $s.State       | Should -Be 'Missing'
        $s.Remediation | Should -Match 'Set up sync rules'
    }
    It 'reports the net.pipe refusal as Unknown, never Missing' {
        Mock Invoke-AdSyncCommand { [PSCustomObject]@{ Outcome = 'QueryFailed'; Error = 'There was no endpoint listening at net.pipe://localhost/ADSyncManagement'; Rules = @() } }
        $s = Test-EntraConnectRule -RuleKey 'BlockCloudSignIn' -ComputerName 'AADC01'
        $s.State       | Should -Be 'Unknown'
        $s.ShouldBlock | Should -BeFalse
        $s.Remediation | Should -Match 'does NOT mean the rule is missing'
    }
    It 'reports a connection failure as Unknown' {
        Mock Invoke-AdSyncCommand { throw 'WinRM cannot complete the operation' }
        (Test-EntraConnectRule -RuleKey 'BlockCloudSignIn' -ComputerName 'AADC01').State | Should -Be 'Unknown'
    }
    It 'reports Unknown when no server can be found' {
        Mock Find-EntraConnectServer { [PSCustomObject]@{ Server = $null; Source = 'NotFound' } }
        (Test-EntraConnectRule -RuleKey 'BlockCloudSignIn').State | Should -Be 'Unknown'
    }
}

Describe 'New-EntraConnectStatus enforcement gating' {
    It 'allows enforcement only when the rule was positively verified' {
        (New-EntraConnectStatus -State 'Present').CanEnforce       | Should -BeTrue
        (New-EntraConnectStatus -State 'Missing').CanEnforce       | Should -BeFalse
        (New-EntraConnectStatus -State 'Misconfigured').CanEnforce | Should -BeFalse
        (New-EntraConnectStatus -State 'Unknown').CanEnforce       | Should -BeFalse
    }
    It 'blocks only when the rule was confirmed missing or broken, never when it could not be checked' {
        (New-EntraConnectStatus -State 'Missing').ShouldBlock       | Should -BeTrue
        (New-EntraConnectStatus -State 'Misconfigured').ShouldBlock | Should -BeTrue
        (New-EntraConnectStatus -State 'Unknown').ShouldBlock       | Should -BeFalse
    }
    It 'never reports CanEnforce and ShouldBlock together' {
        foreach ($state in 'Present', 'Missing', 'Misconfigured', 'Unknown') {
            $s = New-EntraConnectStatus -State $state
            ($s.CanEnforce -and $s.ShouldBlock) | Should -BeFalse
        }
    }
}

Describe 'Get-EntraConnectStatusPresentation' {
    It 'uses repo-standard prefixes and tells "could not check" apart from "broken"' {
        (Get-EntraConnectStatusPresentation -State 'Present').Prefix | Should -Be '[PASS]'
        (Get-EntraConnectStatusPresentation -State 'Missing').Prefix | Should -Be '[FAIL]'
        (Get-EntraConnectStatusPresentation -State 'Unknown').Prefix | Should -Be '[WARN]'
        (Get-EntraConnectStatusPresentation -State 'Unknown').ConsoleColor | Should -Be 'Yellow'
        (Get-EntraConnectStatusPresentation -State 'Missing').ConsoleColor | Should -Be 'Red'
    }
}

Describe 'Rule creation block (runs on the Entra Connect server)' {
    BeforeAll {
        function Invoke-CreateBlock {
            param([object]$Blueprint, [bool]$Replace = $false, [bool]$Preview = $false)
            $a = Get-SyncRuleArgumentList -Blueprint $Blueprint -ReplaceExisting $Replace -PreviewOnly $Preview
            & $script:CreateSyncRuleBlock @a
        }
        $script:Bp = Get-SyncRuleBlueprint -Key 'BlockCloudSignIn' -Domain 'contoso.local'
    }
    BeforeEach {
        Mock Import-Module { } -ParameterFilter { $Name -eq 'ADSync' }
        Mock Get-ADSyncConnector { @([PSCustomObject]@{ Name = 'contoso.local'; Type = 'AD'; Identifier = 'conn-1'; AttributeInclusionList = @('msDS-cloudExtensionAttribute10', 'msDS-cloudExtensionAttribute1') },
                                    [PSCustomObject]@{ Name = 'contoso.onmicrosoft.com - AAD'; Type = 'Extensible2'; Identifier = 'conn-2' }) }
        Mock Get-ADSyncRule { @([PSCustomObject]@{ Name = 'In from AD - User Join'; Identifier = 'oob-1'; Precedence = 100; Direction = 'Inbound'; AttributeFlowMappings = @() }) }
        Mock New-ADSyncRule { [PSCustomObject]@{ Name = $Name; Identifier = $Identifier; Precedence = $Precedence } }
        Mock Add-ADSyncAttributeFlowMapping { $SynchronizationRule }
        Mock Add-ADSyncRule { }
        Mock Remove-ADSyncRule { }
    }

    It 'creates an inbound Join rule on the matching AD connector with the blueprint''s expression' {
        Mock Get-ADSyncRule -ParameterFilter { $Identifier } { [PSCustomObject]@{ Name = 'created'; Identifier = $Identifier; Precedence = 60 } }
        $r = Invoke-CreateBlock -Blueprint $script:Bp
        $r.Success | Should -BeTrue
        $r.Stage   | Should -Be 'Created'
        Should -Invoke New-ADSyncRule -Times 1 -Exactly -ParameterFilter { $Direction -eq 'Inbound' -and $LinkType -eq 'Join' -and $Connector -eq 'conn-1' -and $Precedence -eq 60 -and $SourceObjectType -eq 'user' -and $TargetObjectType -eq 'person' }
        Should -Invoke Add-ADSyncAttributeFlowMapping -Times 1 -Exactly -ParameterFilter { $Destination -eq 'accountEnabled' -and $FlowType -eq 'Expression' -and $Expression -eq $script:Bp.Expression }
    }
    It 'refuses to add a second rule when one already reacts to the marker' {
        Mock Get-ADSyncRule { @([PSCustomObject]@{ Name = 'Block 365 Sign In'; Identifier = 'r1'; Precedence = 10; Direction = 'Inbound'
                                                    AttributeFlowMappings = @([PSCustomObject]@{ Destination = 'cloudFiltered'; Expression = 'IIF([msDS-cloudExtensionAttribute10]="BlockCloudSignIn",True,NULL)' }) }) }
        $r = Invoke-CreateBlock -Blueprint $script:Bp
        $r.Success | Should -BeFalse
        $r.Stage   | Should -Be 'AlreadyExists'
        Should -Invoke New-ADSyncRule -Times 0
    }
    It 'replaces the existing rule only when asked' {
        Mock Get-ADSyncRule -ParameterFilter { -not $Identifier } { @([PSCustomObject]@{ Name = 'broken'; Identifier = 'r1'; Precedence = 60; Direction = 'Inbound'
                                                    AttributeFlowMappings = @([PSCustomObject]@{ Destination = 'accountEnabled'; Expression = '[msDS-cloudExtensionAttribute10]' }) }) }
        Mock Get-ADSyncRule -ParameterFilter { $Identifier } { [PSCustomObject]@{ Name = 'new'; Identifier = $Identifier; Precedence = 60 } }
        $r = Invoke-CreateBlock -Blueprint $script:Bp -Replace $true
        $r.Success | Should -BeTrue
        $r.Removed | Should -Be @('broken')
        Should -Invoke Remove-ADSyncRule -Times 1 -Exactly -ParameterFilter { $Identifier -eq 'r1' }
        # Its precedence is freed by the removal, so the preferred 60 is reused.
        Should -Invoke New-ADSyncRule -Times 1 -Exactly -ParameterFilter { $Precedence -eq 60 }
    }
    It 'moves to the nearest free precedence when the preferred one is taken, and says so' {
        Mock Get-ADSyncRule -ParameterFilter { -not $Identifier } { @([PSCustomObject]@{ Name = 'someone else'; Identifier = 'x'; Precedence = 60; Direction = 'Inbound'; AttributeFlowMappings = @() }) }
        Mock Get-ADSyncRule -ParameterFilter { $Identifier } { [PSCustomObject]@{ Name = 'new'; Identifier = $Identifier; Precedence = 59 } }
        $r = Invoke-CreateBlock -Blueprint $script:Bp
        $r.Rule.Precedence | Should -Be 59
        $r.Warnings        | Should -Match 'Precedence 60 is already used'
    }
    It 'changes nothing in preview mode' {
        $r = Invoke-CreateBlock -Blueprint $script:Bp -Preview $true
        $r.Stage | Should -Be 'Preview'
        $r.Rule.Connector | Should -Be 'contoso.local'
        Should -Invoke New-ADSyncRule -Times 0
        Should -Invoke Add-ADSyncRule -Times 0
    }
    It 'refuses to guess between several AD connectors that do not match the domain' {
        Mock Get-ADSyncConnector { @([PSCustomObject]@{ Name = 'forestA'; Type = 'AD'; Identifier = 'a' }, [PSCustomObject]@{ Name = 'forestB'; Type = 'AD'; Identifier = 'b' }) }
        $r = Invoke-CreateBlock -Blueprint $script:Bp
        $r.Stage | Should -Be 'MatchConnector'
        $r.Error | Should -Match 'forestA, forestB'
    }
    It 'warns when the AD connector does not import the marker attribute' {
        Mock Get-ADSyncConnector { @([PSCustomObject]@{ Name = 'contoso.local'; Type = 'AD'; Identifier = 'c'; AttributeInclusionList = @('mail') }) }
        $r = Invoke-CreateBlock -Blueprint $script:Bp -Preview $true
        $r.Warnings | Should -Match 'does not import'
    }
    It 'reports a missing ADSync module as "not the Entra Connect server"' {
        Mock Import-Module { throw 'module not found' } -ParameterFilter { $Name -eq 'ADSync' }
        $r = Invoke-CreateBlock -Blueprint $script:Bp
        $r.Stage | Should -Be 'ImportModule'
        $r.Error | Should -Match 'not the Entra Connect server'
    }
}

Describe 'Invoke-SyncRuleCreation' {
    It 'labels the net.pipe refusal as RemoteBlocked so the caller offers the script instead' {
        Mock Invoke-AdSyncCommand { throw 'There was no endpoint listening at net.pipe://localhost/ADSyncManagement' }
        $r = Invoke-SyncRuleCreation -Blueprint (Get-SyncRuleBlueprint -Key 'HideFromGAL' -Domain 'x') -ComputerName 'AADC01'
        $r.Success | Should -BeFalse
        $r.Stage   | Should -Be 'RemoteBlocked'
    }
}

Describe 'New-SyncRuleScriptText' {
    BeforeAll {
        $script:Text = New-SyncRuleScriptText -Blueprint (Get-SyncRuleBlueprint -Key 'BlockCloudSignIn' -Domain "o'brien.local")
        $script:Destructive = New-SyncRuleScriptText -Blueprint (Get-SyncRuleBlueprint -Key 'BlockCloudSignIn' -Method 'RemoveFromM365' -Domain 'contoso.local')
    }
    It 'produces a script that parses' {
        foreach ($t in $script:Text, $script:Destructive) {
            $tokens = $null; $errors = $null
            [void][System.Management.Automation.Language.Parser]::ParseInput($t, [ref]$tokens, [ref]$errors)
            @($errors).Count | Should -Be 0
        }
    }
    It 'offers -WhatIf and -Replace and needs elevation' {
        $script:Text | Should -Match '\[switch\]\$WhatIf'
        $script:Text | Should -Match '\[switch\]\$Replace'
        $script:Text | Should -Match '#Requires -RunAsAdministrator'
    }
    It 'embeds the exact expression and escapes quotes in literals' {
        $script:Text | Should -Match ([regex]::Escape("'o''brien.local'"))
        $script:Text | Should -Match ([regex]::Escape((Get-SyncRuleBlueprint -Key 'BlockCloudSignIn' -Domain 'x').Expression))
    }
    It 'warns loudly in the delete-from-Microsoft-365 variant only' {
        $script:Destructive | Should -Match 'WARNING: this rule REMOVES'
        $script:Text        | Should -Not -Match 'WARNING: this rule REMOVES'
    }
    It 'is ASCII, so it survives Windows PowerShell 5.1 even if saved without a BOM' {
        @($script:Text.ToCharArray() | Where-Object { [int]$_ -gt 127 }).Count | Should -Be 0
    }
}

Describe 'Get-FullSyncInstructions' {
    It 'asks for a review of pending exports and stresses it for the destructive rule' {
        Get-FullSyncInstructions -Server 'AADC01' | Should -Match 'Pending Export'
        Get-FullSyncInstructions -Server 'AADC01' -Destructive $true | Should -Match 'DELETES'
    }
}

Describe 'AD search filters' {
    BeforeAll { $script:Block = Get-SyncedUserFeature -Key 'BlockSignIn' }

    It 'escapes LDAP special characters (RFC 4515)' {
        ConvertTo-LdapFilterValue -Value 'a*b(c)d\e' | Should -BeExactly 'a\2ab\28c\29d\5ce'
        ConvertTo-LdapFilterValue -Value "x$([char]0)y" | Should -BeExactly 'x\00y'
    }
    It 'skips disabled accounts unless asked, using the ACCOUNTDISABLE bit' {
        New-SyncedUserLdapFilter -Feature $script:Block | Should -Match '\(!\(userAccountControl:1\.2\.840\.113556\.1\.4\.803:=2\)\)'
        New-SyncedUserLdapFilter -Feature $script:Block -IncludeDisabled | Should -Not -Match 'userAccountControl'
    }
    It 'limits to people who carry the marker when asked' {
        New-SyncedUserLdapFilter -Feature $script:Block -OnlyMarked | Should -Match '\(msDS-cloudExtensionAttribute10=BlockCloudSignIn\)'
    }
    It 'searches name, display name, username, UPN and mail with the text escaped' {
        $f = New-SyncedUserLdapFilter -Feature $script:Block -Search ' smith* '
        $f | Should -Match '\(sAMAccountName=\*smith\\2a\*\)'
        $f | Should -Match '\(mail=\*smith\\2a\*\)'
    }
}

Describe 'Get-OuFromDistinguishedName' {
    It 'shows the parent path top-down' {
        Get-OuFromDistinguishedName -DistinguishedName 'CN=Jane Doe,OU=Sales,OU=Staff,DC=contoso,DC=com' | Should -Be 'Staff/Sales'
    }
    It 'keeps escaped commas inside names' {
        Get-OuFromDistinguishedName -DistinguishedName 'CN=Doe\, Jane,OU=Smith\, Co,DC=contoso,DC=com' | Should -Be 'Smith, Co'
    }
    It 'handles objects at the domain root' {
        Get-OuFromDistinguishedName -DistinguishedName 'CN=x,DC=contoso,DC=com' | Should -Be '(domain root)'
    }
}

Describe 'Get-MarkerStatus' {
    BeforeAll { $script:Block = Get-SyncedUserFeature -Key 'BlockSignIn' }

    It 'never says Blocked when the rule is confirmed missing' {
        $s = Get-MarkerStatus -Feature $script:Block -Marked $true -RuleStatus (New-EntraConnectStatus -State 'Missing')
        $s.Kind | Should -Be 'Warn'
        $s.Text | Should -Be 'NOT blocked - rule missing'
    }
    It 'says Blocked only with a verified rule' {
        (Get-MarkerStatus -Feature $script:Block -Marked $true -RuleStatus (New-EntraConnectStatus -State 'Present')).Text | Should -Be 'Blocked'
    }
    It 'flags an unconfirmed block when the rule could not be checked' {
        (Get-MarkerStatus -Feature $script:Block -Marked $true -RuleStatus (New-EntraConnectStatus -State 'Unknown')).Kind | Should -Be 'Unverified'
        (Get-MarkerStatus -Feature $script:Block -Marked $true -RuleStatus $null).Kind | Should -Be 'Unverified'
    }
    It 'reports unmarked people plainly' {
        (Get-MarkerStatus -Feature (Get-SyncedUserFeature -Key 'HideFromGAL') -Marked $false -RuleStatus $null).Text | Should -Be 'Visible'
    }
}

Describe 'Get-SyncedUserRows' {
    It 'marks only the exact marker value, and fills readable columns' {
        Mock Get-ADUser {
            @([PSCustomObject]@{ Name = 'Doe, Jane'; displayName = 'Jane Doe'; SamAccountName = 'jdoe'; UserPrincipalName = 'jdoe@contoso.com'; Enabled = $true
                                 DistinguishedName = 'CN=Doe\, Jane,OU=Staff,DC=contoso,DC=com'; 'msDS-cloudExtensionAttribute10' = 'BlockCloudSignIn' },
              [PSCustomObject]@{ Name = 'Sam'; displayName = $null; SamAccountName = 'sam'; UserPrincipalName = 'sam@contoso.com'; Enabled = $false
                                 DistinguishedName = 'CN=Sam,OU=Leavers,DC=contoso,DC=com'; 'msDS-cloudExtensionAttribute10' = 'blockcloudsignin' })
        }
        $rows = @(Get-SyncedUserRows -FeatureKey 'BlockSignIn' -RuleStatus (New-EntraConnectStatus -State 'Present'))
        $rows.Count | Should -Be 2
        ($rows | Where-Object SamAccountName -eq 'jdoe').StatusText | Should -Be 'Blocked'
        ($rows | Where-Object SamAccountName -eq 'jdoe').OU | Should -Be 'Staff'
        ($rows | Where-Object SamAccountName -eq 'sam').Marked | Should -BeFalse
        ($rows | Where-Object SamAccountName -eq 'sam').AccountText | Should -Be 'Disabled in AD'
        ($rows | Where-Object SamAccountName -eq 'sam').Name | Should -Be 'Sam'
        Should -Invoke Get-ADUser -ParameterFilter { $LDAPFilter -like '(&(objectCategory=person)(objectClass=user)*' -and $ResultSetSize -eq 1000 }
    }
}

Describe 'Parameters passed to the real ActiveDirectory cmdlets' {
    # Regression: the user search once passed -ResultSize (the real name is -ResultSetSize).
    # Mocks copy the stand-in's signature, so a wrong name in both passed every unit test and
    # only failed against the real module. Check the names against the real cmdlets wherever
    # RSAT is installed.
    # https://learn.microsoft.com/powershell/module/activedirectory/get-aduser
    # https://learn.microsoft.com/powershell/module/activedirectory/set-aduser
    It 'uses only parameters that Get-ADUser and Set-ADUser really have' -Skip:(-not (Get-Module -ListAvailable -Name ActiveDirectory | Where-Object { $_.Path -like "$env:windir*" })) {
        $module = Get-Module -ListAvailable -Name ActiveDirectory | Where-Object { $_.Path -like "$env:windir*" } | Select-Object -First 1
        $ps = [powershell]::Create()
        [void]$ps.AddScript({
            param($path)
            $WarningPreference = 'SilentlyContinue'
            Import-Module $path -ErrorAction Stop 3>$null
            [PSCustomObject]@{
                Get = @((Get-Command Get-ADUser -CommandType Cmdlet).Parameters.Keys)
                Set = @((Get-Command Set-ADUser -CommandType Cmdlet).Parameters.Keys)
            }
        }).AddArgument($module.Path)
        $real = $ps.Invoke() | Select-Object -First 1
        $ps.Dispose()
        foreach ($p in 'Identity', 'LDAPFilter', 'Properties', 'ResultSetSize', 'SearchBase', 'Server') { $real.Get | Should -Contain $p }
        foreach ($p in 'Identity', 'Replace', 'Clear', 'Server') { $real.Set | Should -Contain $p }
    }
}

Describe 'Set-SyncedUserMarker' {
    BeforeEach {
        Mock Get-ADUser { [PSCustomObject]@{ SamAccountName = 'jdoe'; 'msDS-cloudExtensionAttribute10' = 'something-else' } }
        Mock Set-ADUser { }
    }
    It 'writes the marker with -Replace and records the old value' {
        $e = Set-SyncedUserMarker -FeatureKey 'BlockSignIn' -Action 'Apply' -Identity 'CN=jdoe,DC=x'
        $e.Result   | Should -Be 'Done'
        $e.OldValue | Should -Be 'something-else'
        $e.NewValue | Should -Be 'BlockCloudSignIn'
        $e.Action   | Should -Be 'Block sign-in'
        Should -Invoke Set-ADUser -Times 1 -Exactly -ParameterFilter { $Replace -and $Replace['msDS-cloudExtensionAttribute10'] -eq 'BlockCloudSignIn' }
    }
    It 'clears the marker to undo' {
        $e = Set-SyncedUserMarker -FeatureKey 'HideFromGAL' -Action 'Remove' -Identity 'jdoe'
        $e.Action | Should -Be 'Show again'
        Should -Invoke Set-ADUser -Times 1 -Exactly -ParameterFilter { $Clear -eq 'msDS-cloudExtensionAttribute1' }
    }
    It 'returns a Failed row instead of throwing, so one bad account does not stop the batch' {
        Mock Set-ADUser { throw 'Insufficient access rights' }
        $e = Set-SyncedUserMarker -FeatureKey 'BlockSignIn' -Action 'Apply' -Identity 'jdoe'
        $e.Result | Should -Be 'Failed'
        $e.Error  | Should -Match 'Insufficient access'
    }
    It 'honours -WhatIf' {
        $e = Set-SyncedUserMarker -FeatureKey 'BlockSignIn' -Action 'Apply' -Identity 'jdoe' -WhatIf
        $e.Result | Should -Be 'Skipped (WhatIf)'
        Should -Invoke Set-ADUser -Times 0
    }
}

Describe 'Write-SyncedUserChangeLog' {
    It 'appends to one CSV per day with a single header row' {
        $folder = Join-Path $TestDrive 'logs'
        $row = [PSCustomObject]@{ Time = 't'; User = 'jdoe'; Result = 'Done' }
        $p1 = Write-SyncedUserChangeLog -Entries @($row) -LogFolder $folder
        $p2 = Write-SyncedUserChangeLog -Entries @($row, $row) -LogFolder $folder
        $p1 | Should -Be $p2
        @(Import-Csv -LiteralPath $p1).Count | Should -Be 3
        @(Get-Content -LiteralPath $p1 | Where-Object { $_ -match '^"Time"' }).Count | Should -Be 1
    }
    It 'returns $null instead of throwing when the folder cannot be written' {
        Mock New-Item { throw 'Access denied' }
        Write-SyncedUserChangeLog -Entries @([PSCustomObject]@{ a = 1 }) -LogFolder (Join-Path $TestDrive 'nope\deeper') | Should -BeNullOrEmpty
    }
}

Describe 'Settings cache' {
    It 'round-trips, and tolerates missing or corrupt files' {
        $p = Join-Path $TestDrive 'settings.json'
        Write-EntraConnectSettings -Path $p -Server 'AADC02.contoso.local'
        (Read-EntraConnectSettings -Path $p).EntraConnectServer | Should -Be 'AADC02.contoso.local'
        Read-EntraConnectSettings -Path (Join-Path $TestDrive 'nope.json') | Should -BeNullOrEmpty
        Set-Content -LiteralPath $p -Value '{ not json' -Encoding UTF8
        { Read-EntraConnectSettings -Path $p } | Should -Not -Throw
        Read-EntraConnectSettings -Path $p | Should -BeNullOrEmpty
    }
}

Describe 'Test-IsLocalMachine' {
    # ADSync's endpoint (net.pipe://localhost/ADSyncManagement) refuses remoting hops, so
    # "this is me" must be detected and called directly.
    It 'recognises this machine by name, FQDN, alias, case and trailing dot' {
        foreach ($n in $env:COMPUTERNAME, "$env:COMPUTERNAME.contoso.local", 'localhost', '.', '127.0.0.1', '::1', $env:COMPUTERNAME.ToLower(), "$env:COMPUTERNAME.", '') {
            Test-IsLocalMachine -ComputerName $n | Should -BeTrue
        }
    }
    It 'does not match other servers or longer names' {
        Test-IsLocalMachine -ComputerName 'SOMEOTHERBOX99.contoso.local' | Should -BeFalse
        Test-IsLocalMachine -ComputerName "$($env:COMPUTERNAME)2" | Should -BeFalse
    }
}

Describe 'Invoke-AdSyncCommand' {
    It 'runs locally without remoting when the target is this machine (regression)' {
        Mock Invoke-Command { throw 'Invoke-Command must not be used for a local target' }
        Invoke-AdSyncCommand -ComputerName $env:COMPUTERNAME -ScriptBlock { param($x) "ran-locally:$x" } -ArgumentList @('ok') | Should -Be 'ran-locally:ok'
        Should -Invoke Invoke-Command -Times 0
    }
}

Describe 'Test-AdSyncServer' {
    It 'is false when no ADSync service comes back (regression: an empty result once counted as found)' {
        Mock Get-CimInstance { }
        Test-AdSyncServer -ComputerName 'dc01.contoso.local' | Should -BeFalse
    }
    It 'is true only for a service actually named ADSync' {
        Mock Get-CimInstance { [PSCustomObject]@{ Name = 'ADSync'; State = 'Running' } }
        Test-AdSyncServer -ComputerName 'aadc02.contoso.local' | Should -BeTrue
    }
    It 'is false rather than throwing when the host is unreachable' {
        Mock Get-CimInstance { throw 'RPC server is unavailable' }
        Test-AdSyncServer -ComputerName 'gone.contoso.local' | Should -BeFalse
    }
}

Describe 'ConvertTo-ComparableExpression' {
    It 'strips whitespace, keeps case, and handles blanks' {
        ConvertTo-ComparableExpression -Expression 'IIF( a , b )' | Should -Be 'IIF(a,b)'
        ConvertTo-ComparableExpression -Expression 'IsPresent' | Should -BeExactly 'IsPresent'
        ConvertTo-ComparableExpression -Expression '   ' | Should -Be ''
    }
}
