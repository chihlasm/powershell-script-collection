<#
    Tests for the Azure Virtual Desktop (AVD) host checks in Invoke-CitrixFSLogixTriage.ps1
    (SQ-012; Pester 5; runs under Windows PowerShell 5.1 and 7.x). Named AVD_AC1..AVD_AC8 because
    the triage suite already uses AC30.. names (SQ-010) and the temp-profile suite uses AC1..AC32.

    Nothing real is read. Every service, registry, event log and qwinsta read is mocked, against a
    pretend session host called AVD01 (remote, so the CIM / registry / event paths run):
      - services:  Get-CimInstance -ClassName Win32_Service. The AVD agent service
                   (RDAgentBootLoader) must be asked for with a -Filter that names it; the mock
                   answers per name, so a separate query or one combined query both work.
      - registry:  Get-AvdAgentRegistry -ComputerName -IsLocal   (new function, stubbed)
                   returns Found / Error / Values, like Get-FSLogixRegistrySnapshot's keys. Values
                   holds IsRegistered as text ('1' registered), as the registry reader does.
                   HKLM\SOFTWARE\Microsoft\RDInfraAgent.
      - events:    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ... } (existing seam).
      - listener:  Get-AvdStackListenerOutput -ComputerName -IsLocal   (new function, stubbed)
                   returns the lines of "qwinsta /server:<name>"; throws when it cannot run.

    Contract the tests rely on: every AVD evidence item has a Name starting 'AVD ':
      'AVD agent service', 'AVD host pool registration', 'AVD agent event' (one per finding),
      'AVD stack listener'. A read that fails is Warn with NotChecked, never Pass.

    Facts verified on Microsoft Learn (2026-10-20):
    https://learn.microsoft.com/troubleshoot/azure/virtual-desktop/troubleshoot-agent
      - RDAgentBootLoader (shown as "Remote Desktop Agent Loader") stopped = the agent is not running.
      - HKLM:\SOFTWARE\Microsoft\RDInfraAgent value IsRegistered must be 1 once registered.
      - Application event 3277 with INVALID_REGISTRATION_TOKEN or EXPIRED_MACHINE_TOKEN = the
        registration key is not valid (make a new key); INVALID_FORM = agent cannot reach the broker
        (firewall / DNS / ciphers); ENDPOINT_NOT_FOUND = broker found no usable session host
        (powered on, session limit, agent running, valid token); InstallMsiException = another
        installer is running or policy blocks msiexec.exe.
      - Event 3703 "RD Gateway Url: is not accessible" = gateway URLs blocked (Required URL list).
      - Event 3019 = web socket transport URLs blocked (Required URL list).
      - Event 3389 "MissingMethodException: Method not found" = agent update reverted, .NET lower
        than 4.7.2 (upgrade .NET).
      - qwinsta: STATE for rdp-sxs must be Listen; not listed or not Listen = stack issue.

    Run:  Invoke-Pester .\Citrix-FSLogix-Triage\Tests
#>

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:ScriptPath = Join-Path $script:Root 'Invoke-CitrixFSLogixTriage.ps1'
    . $script:ScriptPath -LoadFunctionsOnly

    $script:LearnAgentUrl = 'learn.microsoft.com/troubleshoot/azure/virtual-desktop/troubleshoot-agent'

    $script:QwinstaListen = @(
        ' SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE',
        ' services                                    0  Disc',
        ' console                                     1  Conn',
        ' rdp-tcp                                 65536  Listen',
        ' rdp-sxs2312010                          65537  Listen'
    )

    function New-RegKey {
        param([string]$SubKey, [hashtable]$Values, [switch]$Missing)
        $label = if ($SubKey -like 'SOFTWARE\Policies\*') { 'Policies path (not documented for profile settings)' } else { 'Profile settings' }
        if ($Missing) {
            return [PSCustomObject]@{ Label = $label; Path = "HKLM:\$SubKey"; Found = $false; Error = '' }
        }
        $ordered = [ordered]@{}
        foreach ($k in $Values.Keys) { $ordered[$k] = $Values[$k] }
        [PSCustomObject]@{ Label = $label; Path = "HKLM:\$SubKey"; Found = $true; Error = ''; Values = [PSCustomObject]$ordered }
    }

    function New-AvdEvent {
        param([int]$Id, [string]$Message)
        [PSCustomObject]@{
            Id               = $Id
            ProviderName     = 'RDAgentBootLoader'
            LevelDisplayName = 'Error'
            Message          = $Message
            TimeCreated      = (Get-Date)
        }
    }

    # Pretend session host. -Service: Running | Stopped | Absent | Throw.
    # -Registry: Registered | NotRegistered | NoValue | KeyMissing | Throw.
    # -Events: array of events, or 'Throw'. -Qwinsta: lines, or 'Throw'.
    function Set-AvdHost {
        param(
            [string]$Service = 'Running',
            [string]$Registry = 'Registered',
            $Events = @(),
            $Qwinsta = $script:QwinstaListen
        )
        $script:AvdService = $Service
        $script:AvdRegistry = $Registry
        $script:AvdEvents = $Events
        $script:AvdQwinsta = $Qwinsta

        Mock Test-Connection { $true }
        Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_Service' } {
            $out = @()
            if ($Filter -like '*frxsvc*') {
                $out += [PSCustomObject]@{ Name = 'frxsvc'; DisplayName = 'FSLogix Apps Services'; State = 'Running'; StartMode = 'Auto' }
                $out += [PSCustomObject]@{ Name = 'frxccds'; DisplayName = 'FSLogix Cloud Caching Service'; State = 'Running'; StartMode = 'Auto' }
            }
            if ($Filter -like '*RDAgentBootLoader*') {
                if ($script:AvdService -eq 'Throw') { throw 'The WinRM client cannot process the request.' }
                if ($script:AvdService -ne 'Absent') {
                    $out += [PSCustomObject]@{ Name = 'RDAgentBootLoader'; DisplayName = 'Remote Desktop Agent Loader'; State = $script:AvdService; StartMode = 'Auto' }
                }
            }
            $out
        }
        Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_LogicalDisk' } {
            [PSCustomObject]@{ DeviceID = 'C:'; Size = 200GB; FreeSpace = 120GB }
        }
        Mock Get-WinEvent {
            if ($FilterHashtable.LogName -eq 'Application') {
                if ($script:AvdEvents -is [string] -and $script:AvdEvents -eq 'Throw') { throw 'The RPC server is unavailable.' }
                if (@($script:AvdEvents).Count -eq 0) { throw 'No events were found that match the specified selection criteria.' }
                return @($script:AvdEvents)
            }
            throw 'No events were found that match the specified selection criteria.'
        }
        Mock Get-FSLogixRegistrySnapshot {
            @(
                New-RegKey -SubKey 'SOFTWARE\FSLogix\Profiles' -Values @{ Enabled = '1'; VHDLocations = '\\fs01\profiles' }
                New-RegKey -SubKey 'SOFTWARE\Policies\FSLogix\Profiles' -Missing
            )
        }
        Mock Get-AvdAgentRegistry {
            switch ($script:AvdRegistry) {
                'Throw' { throw 'The network path was not found.' }
                'KeyMissing' { return [PSCustomObject]@{ Found = $false; Error = '' } }
                'NoValue' { return [PSCustomObject]@{ Found = $true; Error = ''; Values = [PSCustomObject]@{} } }
                'NotRegistered' { return [PSCustomObject]@{ Found = $true; Error = ''; Values = [PSCustomObject]@{ IsRegistered = '0' } } }
                default { return [PSCustomObject]@{ Found = $true; Error = ''; Values = [PSCustomObject]@{ IsRegistered = '1' } } }
            }
        }
        Mock Get-AvdStackListenerOutput {
            if ($script:AvdQwinsta -is [string] -and $script:AvdQwinsta -eq 'Throw') { throw 'Access is denied.' }
            return @($script:AvdQwinsta)
        }
        Mock Invoke-Command { $true }
        Mock Test-Path { $true }
    }

    function Get-Evidence($Result, [string]$Pattern) { @($Result.Evidence | Where-Object { $_.Name -like $Pattern }) }
    function Get-AvdEvidence($Result) { @($Result.Evidence | Where-Object { $_.Name -like 'AVD *' }) }
}

Describe 'AVD host checks: detection' {
    It 'AVD_AC1_NotAvdAddsNothing: no RDAgentBootLoader and no RDInfraAgent key means no AVD evidence and no AVD reads' {
        Set-AvdHost -Service Absent -Registry KeyMissing
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        @(Get-AvdEvidence $r).Count | Should -Be 0
        $r.Status | Should -Be 'Pass'
        Should -Invoke Get-AvdStackListenerOutput -Times 0 -Exactly
        Should -Invoke Get-WinEvent -Times 0 -Exactly -ParameterFilter { $FilterHashtable.LogName -eq 'Application' }
    }

    It 'AVD_AC1_DetectedByAgentServiceAlone: the service without the registry key still runs the AVD checks' {
        Set-AvdHost -Service Running -Registry KeyMissing
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        (Get-Evidence $r 'AVD agent service').Count | Should -BeGreaterThan 0
        Should -Invoke Get-AvdStackListenerOutput -Times 1 -Exactly
    }

    It 'AVD_AC1_DetectedByRegistryKeyAlone: the RDInfraAgent key without the service still runs the AVD checks' {
        Set-AvdHost -Service Absent -Registry Registered
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        (Get-AvdEvidence $r).Count | Should -BeGreaterThan 0
    }

    It 'AVD_AC1_HealthyAvdHostPasses: a healthy AVD host reports Pass on every AVD item' {
        Set-AvdHost
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $items = @(Get-AvdEvidence $r)
        $items.Count | Should -BeGreaterThan 2
        @($items | Where-Object { $_.Status -ne 'Pass' }).Count | Should -Be 0
        $r.Status | Should -Be 'Pass'
    }
}

Describe 'AVD host checks: agent service' {
    It 'AVD_AC2_BootLoaderStoppedFails: RDAgentBootLoader Stopped is a Fail with the Learn link' {
        Set-AvdHost -Service Stopped
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD agent service')
        $e.Count | Should -Be 1
        $e[0].Status | Should -Be 'Fail'
        $e[0].Detail | Should -Match 'RDAgentBootLoader|Remote Desktop Agent Loader'
        $e[0].Detail | Should -Match 'Stopped'
        $e[0].Action | Should -Match ([regex]::Escape($script:LearnAgentUrl))
        $r.Status | Should -Be 'Fail'
    }

    It 'AVD_AC2_BootLoaderMissingFailsWhenKeyExists: no service but an RDInfraAgent key is a Fail, not a Pass' {
        Set-AvdHost -Service Absent -Registry Registered
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD agent service')
        $e.Count | Should -Be 1
        $e[0].Status | Should -Be 'Fail'
    }

    It 'AVD_AC2_BootLoaderRunningPasses' {
        Set-AvdHost -Service Running
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD agent service')
        $e.Count | Should -Be 1
        $e[0].Status | Should -Be 'Pass'
    }
}

Describe 'AVD host checks: host pool registration' {
    It 'AVD_AC3_IsRegisteredZeroFails: IsRegistered = 0 says the host is not registered to its host pool' {
        Set-AvdHost -Registry NotRegistered
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD host pool registration')
        $e.Count | Should -Be 1
        $e[0].Status | Should -Be 'Fail'
        $e[0].Detail | Should -Match 'not registered to its host pool'
        $e[0].Action | Should -Match ([regex]::Escape($script:LearnAgentUrl))
    }

    It 'AVD_AC3_IsRegisteredMissingFails: an RDInfraAgent key with no IsRegistered value is not "1" either' {
        Set-AvdHost -Registry NoValue
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD host pool registration')
        $e.Count | Should -Be 1
        $e[0].Status | Should -Be 'Fail'
    }

    It 'AVD_AC3_IsRegisteredOnePasses' {
        Set-AvdHost -Registry Registered
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD host pool registration')
        $e.Count | Should -Be 1
        $e[0].Status | Should -Be 'Pass'
    }

    It 'AVD_AC3_ReadsTheRemoteHost: the registry is read from the named host' {
        Set-AvdHost
        $null = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        Should -Invoke Get-AvdAgentRegistry -Times 1 -Exactly -ParameterFilter { $ComputerName -eq 'AVD01' }
    }
}

Describe 'AVD host checks: Application event 3277 (agent registration and install errors)' {
    It 'AVD_AC4_Event3277Token: <Token> is a Fail that names the error and its fix' -ForEach @(
        @{ Token = 'INVALID_REGISTRATION_TOKEN'; Fix = 'registration key' }
        @{ Token = 'EXPIRED_MACHINE_TOKEN'; Fix = 'registration key' }
        @{ Token = 'INVALID_FORM'; Fix = 'firewall|DNS' }
        @{ Token = 'ENDPOINT_NOT_FOUND'; Fix = 'powered on|session limit' }
        @{ Token = 'InstallMsiException'; Fix = 'msiexec|installer' }
    ) {
        Set-AvdHost -Events @(New-AvdEvent -Id 3277 -Message "Agent error: $Token (synthetic test event)")
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD agent event*' | Where-Object { $_.Detail -match [regex]::Escape($Token) })
        $e.Count | Should -Be 1
        $e[0].Status | Should -Be 'Fail'
        $e[0].Detail | Should -Match '3277'
        $e[0].Action | Should -Match $Fix
        $e[0].Action | Should -Match ([regex]::Escape($script:LearnAgentUrl))
        $r.Status | Should -Be 'Fail'
    }

    It 'AVD_AC4_NoMatchingEventPasses: no AVD events in the lookback window is a Pass on the events item' {
        Set-AvdHost -Events @()
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD agent event*')
        $e.Count | Should -BeGreaterThan 0
        @($e | Where-Object { $_.Status -ne 'Pass' }).Count | Should -Be 0
    }

    It 'AVD_AC4_ReadsApplicationLogOfTheHost: events come from the Application log of the named host' {
        Set-AvdHost
        $null = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        Should -Invoke Get-WinEvent -Times 1 -ParameterFilter { $FilterHashtable.LogName -eq 'Application' -and $ComputerName -eq 'AVD01' }
    }
}

Describe 'AVD host checks: events 3703, 3019 and 3389' {
    It 'AVD_AC5_EventMapped: event <Id> maps to its documented meaning and fix' -ForEach @(
        @{ Id = 3703; Message = 'RD Gateway Url: https://rdgateway.example.invalid is not accessible'; Meaning = 'gateway'; Fix = 'Required URL' }
        @{ Id = 3019; Message = 'Unable to connect to the web socket transport (synthetic test event)'; Meaning = 'web socket'; Fix = 'Required URL' }
        @{ Id = 3389; Message = 'MissingMethodException: Method not found (synthetic test event)'; Meaning = 'update|reverted|earlier version'; Fix = '4\.7\.2' }
    ) {
        Set-AvdHost -Events @(New-AvdEvent -Id $Id -Message $Message)
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD agent event*' | Where-Object { $_.Detail -match "\b$Id\b" })
        $e.Count | Should -Be 1
        $e[0].Status | Should -BeIn @('Warn', 'Fail')
        $e[0].Detail | Should -Match $Meaning
        $e[0].Action | Should -Match $Fix
        $e[0].Action | Should -Match ([regex]::Escape($script:LearnAgentUrl))
        $r.Status | Should -Not -Be 'Pass'
    }

    It 'AVD_AC5_SeveralEventsEachReported: two different findings stay two evidence items' {
        Set-AvdHost -Events @(
            (New-AvdEvent -Id 3703 -Message 'RD Gateway Url: https://rdgateway.example.invalid is not accessible'),
            (New-AvdEvent -Id 3019 -Message 'web socket transport blocked (synthetic test event)')
        )
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        @(Get-Evidence $r 'AVD agent event*' | Where-Object { $_.Status -ne 'Pass' }).Count | Should -BeGreaterOrEqual 2
    }
}

Describe 'AVD host checks: rdp-sxs stack listener (qwinsta)' {
    It 'AVD_AC6_ListenPasses: rdp-sxs in Listen state is a Pass' {
        Set-AvdHost -Qwinsta $script:QwinstaListen
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD stack listener')
        $e.Count | Should -Be 1
        $e[0].Status | Should -Be 'Pass'
    }

    It 'AVD_AC6_NotListeningFails: rdp-sxs in state <State> is a Fail' -ForEach @(
        @{ State = 'Down' }
        @{ State = 'Disc' }
    ) {
        $lines = @($script:QwinstaListen | Select-Object -First 4) + (" rdp-sxs2312010                          65537  $State")
        Set-AvdHost -Qwinsta $lines
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD stack listener')
        $e.Count | Should -Be 1
        $e[0].Status | Should -Be 'Fail'
        $e[0].Detail | Should -Match 'rdp-sxs'
        $e[0].Action | Should -Match ([regex]::Escape($script:LearnAgentUrl))
    }

    It 'AVD_AC6_NotListedFails: parseable output with no rdp-sxs row is a Fail (Learn: not listed = stack issue)' {
        Set-AvdHost -Qwinsta @($script:QwinstaListen | Select-Object -First 4)
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD stack listener')
        $e.Count | Should -Be 1
        $e[0].Status | Should -Be 'Fail'
    }

    It 'AVD_AC6_LocalizedStateIsCouldNotCheck: an rdp-sxs row whose state word is not English is Warn "could not check", never Pass' {
        $lines = @($script:QwinstaListen | Select-Object -First 4) + ' rdp-sxs2312010                          65537  Escucha'
        Set-AvdHost -Qwinsta $lines
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD stack listener')
        $e.Count | Should -Be 1
        $e[0].Status | Should -Be 'Warn'
        $e[0].NotChecked | Should -BeTrue
        $r.Status | Should -Not -Be 'Pass'
    }

    It 'AVD_AC6_GarbageOutputIsCouldNotCheck: unrecognizable qwinsta output is Warn, never Pass and never Fail' {
        Set-AvdHost -Qwinsta @('Error [5]:Access is denied')
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD stack listener')
        $e.Count | Should -Be 1
        $e[0].Status | Should -Be 'Warn'
        $e[0].NotChecked | Should -BeTrue
    }

    It 'AVD_AC6_AsksTheNamedServer: qwinsta runs against the host being triaged' {
        Set-AvdHost
        $null = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        Should -Invoke Get-AvdStackListenerOutput -Times 1 -Exactly -ParameterFilter { $ComputerName -eq 'AVD01' }
    }
}

Describe 'AVD host checks: a failed read is a Warn, never a Pass' {
    It 'AVD_AC7_ServiceReadFailure: the agent service cannot be read' {
        Set-AvdHost -Service Throw -Registry Registered
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD agent service')
        $e.Count | Should -Be 1
        $e[0].Status | Should -Be 'Warn'
        $e[0].NotChecked | Should -BeTrue
        $r.Status | Should -Not -Be 'Pass'
    }

    It 'AVD_AC7_RegistryReadFailure: the RDInfraAgent registry cannot be read' {
        Set-AvdHost -Service Running -Registry Throw
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD host pool registration')
        $e.Count | Should -Be 1
        $e[0].Status | Should -Be 'Warn'
        $e[0].NotChecked | Should -BeTrue
        $r.Status | Should -Not -Be 'Pass'
    }

    It 'AVD_AC7_EventReadFailure: the Application log cannot be read' {
        Set-AvdHost -Events 'Throw'
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD agent event*')
        $e.Count | Should -BeGreaterThan 0
        @($e | Where-Object { $_.Status -eq 'Pass' }).Count | Should -Be 0
        $e[0].Status | Should -Be 'Warn'
        $e[0].NotChecked | Should -BeTrue
        $r.Status | Should -Not -Be 'Pass'
    }

    It 'AVD_AC7_QwinstaFailure: qwinsta cannot run' {
        Set-AvdHost -Qwinsta 'Throw'
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD stack listener')
        $e.Count | Should -Be 1
        $e[0].Status | Should -Be 'Warn'
        $e[0].NotChecked | Should -BeTrue
        $r.Status | Should -Not -Be 'Pass'
    }
}

Describe 'AVD host checks: still PowerShell 3.0 compatible and pure ASCII' {
    BeforeAll {
        $script:AvdTokens = $null; $script:AvdParseErrors = $null
        $script:AvdAst = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$script:AvdTokens, [ref]$script:AvdParseErrors)
        $script:AvdText = [System.IO.File]::ReadAllText($script:ScriptPath)
    }

    It 'AVD_AC8_ScriptCarriesTheAvdChecks: the script looks for the AVD agent service and the rdp-sxs listener' {
        $script:AvdText | Should -Match 'RDAgentBootLoader'
        $script:AvdText | Should -Match 'rdp-sxs'
        $script:AvdText | Should -Match 'RDInfraAgent'
    }

    It 'AVD_AC8_Ps3Compatible: parses, requires no more than 3.0, no ::new(), no .Where()/.ForEach(), no classes' {
        @($script:AvdParseErrors).Count | Should -Be 0
        $script:AvdAst.ScriptRequirements.RequiredPSVersion | Should -BeLessOrEqual ([version]'3.0')
        $bad = $script:AvdAst.FindAll({
            $n = $args[0]
            ($n -is [System.Management.Automation.Language.TypeDefinitionAst]) -or
            ($n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and (
                ($n.Static -and $n.Member.Extent.Text -eq 'new') -or
                (-not $n.Static -and ('Where', 'ForEach') -contains $n.Member.Extent.Text)))
        }, $true)
        @($bad).Count | Should -Be 0
    }

    It 'AVD_AC8_PureAscii: no byte above 127 (no BOM needed under Windows PowerShell)' {
        $bytes = [System.IO.File]::ReadAllBytes($script:ScriptPath)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }

    It 'AVD_AC8_NoReadsOnThisMachine: the AVD seams are defined as functions so tests can mock them' {
        foreach ($name in 'Get-AvdAgentRegistry', 'Get-AvdStackListenerOutput') {
            Get-Command -Name $name -CommandType Function -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
}
