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

    # Pretend session host. -Service: Running | Stopped | Absent | Throw. -StartMode: the agent
    # service's start type (Auto, Manual, Disabled).
    # -Registry: Registered | NotRegistered | NoValue | KeyMissing | Throw.
    # -Events: array of events, or 'Throw'. -Qwinsta: lines, or 'Throw'.
    function Set-AvdHost {
        param(
            [string]$Service = 'Running',
            [string]$StartMode = 'Auto',
            [string]$Registry = 'Registered',
            $Events = @(),
            $Qwinsta = $script:QwinstaListen
        )
        $script:AvdService = $Service
        $script:AvdStartMode = $StartMode
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
                    $out += [PSCustomObject]@{ Name = 'RDAgentBootLoader'; DisplayName = 'Remote Desktop Agent Loader'; State = $script:AvdService; StartMode = $script:AvdStartMode }
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

    It 'AVD_AC8_SeamsAreMockableFunctions: the AVD seams are defined as functions so tests can mock them' {
        foreach ($name in 'Get-AvdAgentRegistry', 'Get-AvdStackListenerOutput') {
            Get-Command -Name $name -CommandType Function -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
}

# ---- Review round 1 (SQ-012) -------------------------------------------------------------

Describe 'AVD host checks: qwinsta user names stay out of every output (personal data)' {
    BeforeAll {
        # Columns as qwinsta prints them: USERNAME starts where its header does, ID is right-aligned.
        function New-QwinstaRow([string]$Session, [string]$User, [string]$Id, [string]$State, [switch]$Current) {
            $lead = if ($Current) { '>' } else { ' ' }
            $lead + $Session.PadRight(18) + $User.PadRight(20) + $Id.PadLeft(5) + '  ' + $State
        }
        function Get-QwinstaWithUsers([string]$ListenerState) {
            @(
                (' ' + 'SESSIONNAME'.PadRight(18) + 'USERNAME'.PadRight(20) + 'ID'.PadLeft(5) + '  STATE   TYPE        DEVICE'),
                (New-QwinstaRow 'services' '' '0' 'Disc'),
                (New-QwinstaRow 'console' '' '1' 'Conn'),
                (New-QwinstaRow 'rdp-sxs2312010#5' 'jdoe.smith' '2' 'Active' -Current),
                (New-QwinstaRow '' 'mary.major' '3' 'Disc'),
                (New-QwinstaRow 'rdp-tcp' '' '65536' 'Listen'),
                (New-QwinstaRow 'rdp-sxs2312010' '' '65537' $ListenerState)
            )
        }
        $script:UserNames = 'jdoe\.smith|mary\.major'
    }

    It 'AVD_PD_NoUserNamesAnywhere: listener <State> - no signed-in user name in RawOutput, Evidence, Errors, the report or the ticket note' -ForEach @(
        @{ State = 'Listen' }
        @{ State = 'Down' }
    ) {
        Set-AvdHost -Qwinsta (Get-QwinstaWithUsers $State)
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe

        ($r.RawOutput | ConvertTo-Json -Depth 12 -Compress) | Should -Not -Match $script:UserNames
        foreach ($e in @($r.Evidence)) {
            "$($e.Name) $($e.Detail) $($e.Action)" | Should -Not -Match $script:UserNames
        }
        ([string]$r.Error) | Should -Not -Match $script:UserNames
        ((ConvertTo-TriageText -Result $r) -join "`n") | Should -Not -Match $script:UserNames
        $note = ConvertTo-CitrixFSLogixTriageTicketNote -Result $r
        ((ConvertTo-TicketNoteText -Note $note) -join "`n") | Should -Not -Match $script:UserNames
    }

    It 'AVD_PD_ListenerFactsOnly: RawOutput keeps the rdp-sxs row state and a count of signed-in sessions, not the qwinsta text' {
        Set-AvdHost -Qwinsta (Get-QwinstaWithUsers 'Down')
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $facts = $r.RawOutput.Avd.Listener
        $facts.HeaderFound | Should -BeTrue
        $facts.SignedInSessions | Should -Be 2
        @($facts.Listeners).Count | Should -Be 1
        $facts.Listeners[0].Session | Should -Be 'rdp-sxs2312010'
        $facts.Listeners[0].State | Should -Be 'Down'
        ($facts | ConvertTo-Json -Depth 5 -Compress) | Should -Not -Match 'SESSIONNAME|rdp-tcp|console'
    }

    It 'AVD_PD_DownListenerEscalatesWithUserCount: the fix is an escalation that says how many users must sign out' {
        Set-AvdHost -Qwinsta (Get-QwinstaWithUsers 'Down')
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD stack listener')
        $e[0].Status | Should -Be 'Fail'
        $e[0].Action | Should -Match '^Users cannot connect while the AVD listener is down\. Escalate: put the host in drain mode, ask the 2 signed-in users to save their work and sign out, then restart it'
    }
}

Describe 'AVD host checks: review round 1 wording' {
    It 'AVD_R1_DisabledAgentEscalates: a Stopped agent with start type Disabled says Escalate and that it was disabled on purpose' {
        Set-AvdHost -Service Stopped -StartMode Disabled
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD agent service')
        $e[0].Status | Should -Be 'Fail'
        $e[0].Action | Should -Match '^Escalate: someone disabled the AVD agent on purpose'
        $e[0].Action | Should -Match ([regex]::Escape($script:LearnAgentUrl))
    }

    It 'AVD_R1_StoppedAgentEscalates: a Stopped agent (start type Auto) is left to an engineer to start' {
        Set-AvdHost -Service Stopped -StartMode Auto
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD agent service')
        $e[0].Action | Should -Match 'Escalate to an engineer to start'
        $e[0].Action | Should -Not -Match 'disabled'
    }

    It 'AVD_R1_LeftoverKeyWording: agent key present but no service asks whether the server is meant to be an AVD host' {
        Set-AvdHost -Service Absent -Registry Registered
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD agent service')
        $e[0].Action | Should -Match '^If this server is meant to be an AVD session host, escalate'
    }

    It 'AVD_R1_QwinstaErrorShown: an "Error [n]" from qwinsta is shown with a rights/RPC action, not blamed on the language' {
        Set-AvdHost -Qwinsta @('Error [5]:Access is denied.')
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD stack listener')
        $e[0].Status | Should -Be 'Warn'
        $e[0].NotChecked | Should -BeTrue
        $e[0].Detail | Should -Match 'Error \[5\]:Access is denied'
        $e[0].Detail | Should -Not -Match 'non-English'
        $e[0].Action | Should -Match 'administrator'
        $e[0].Action | Should -Match 'RPC'
    }

    It 'AVD_R1_DownloadMsiPointsAtTheDiskTools: DownloadMsiException reuses the disk advice (named tools or escalate)' {
        Set-AvdHost -Events @(New-AvdEvent -Id 3277 -Message 'DownloadMsiException (synthetic test event)')
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD agent event' | Where-Object { $_.Detail -match 'DownloadMsiException' })
        $e.Count | Should -Be 1
        $e[0].Action | Should -Match 'Run Drive-Storage-Report or Cleanup-CitrixVDAStorage on the server, or escalate'
        $e[0].Action | Should -Match 'ask an engineer to enlarge'
        $e[0].Action | Should -Not -Match '(?i)free up'
    }

    It 'AVD_R1_DotNetUpgradeEscalates: event 3389 asks an engineer to schedule the .NET upgrade and keeps the Learn link' {
        Set-AvdHost -Events @(New-AvdEvent -Id 3389 -Message 'MissingMethodException: Method not found (synthetic test event)')
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $e = @(Get-Evidence $r 'AVD agent event' | Where-Object { $_.Detail -match '3389' })
        $e.Count | Should -Be 1
        $e[0].Action | Should -Match '^Escalate to an engineer to schedule a \.NET Framework upgrade \(4\.7\.2 or later\) in a maintenance window; it needs a restart\. The host keeps working on the old agent meanwhile\.'
        $e[0].Action | Should -Match ([regex]::Escape($script:LearnAgentUrl))
    }
}

Describe 'AVD host checks: every disruptive fix says Escalate (D-017)' {
    It 'AVD_R1_DisruptiveVerbsEscalate: rule fixes and the service, registration and listener actions put Escalate before any restart/reinstall/upgrade/free-up/delete/clean-up' {
        $texts = New-Object System.Collections.Generic.List[object]
        foreach ($rule in @($script:AvdAgentEventRules)) { $texts.Add([PSCustomObject]@{ Case = "rule $($rule.Label)"; Text = $rule.Fix }) }

        $down = @($script:QwinstaListen | Select-Object -First 4) + ' rdp-sxs2312010                          65537  Down'
        $scenarios = @(
            @{ Case = 'service stopped'; Splat = @{ Service = 'Stopped' } }
            @{ Case = 'service disabled'; Splat = @{ Service = 'Stopped'; StartMode = 'Disabled' } }
            @{ Case = 'service missing, key present'; Splat = @{ Service = 'Absent'; Registry = 'Registered' } }
            @{ Case = 'not registered'; Splat = @{ Registry = 'NotRegistered' } }
            @{ Case = 'key missing'; Splat = @{ Registry = 'KeyMissing' } }
            @{ Case = 'listener down'; Splat = @{ Qwinsta = $down } }
            @{ Case = 'listener not listed'; Splat = @{ Qwinsta = @($script:QwinstaListen | Select-Object -First 4) } }
            @{ Case = 'reads fail'; Splat = @{ Service = 'Throw'; Events = 'Throw'; Qwinsta = 'Throw' } }
        )
        foreach ($scenario in $scenarios) {
            $splat = $scenario.Splat
            Set-AvdHost @splat
            $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
            foreach ($e in @(Get-AvdEvidence $r | Where-Object { $_.Action })) {
                $texts.Add([PSCustomObject]@{ Case = "$($scenario.Case): $($e.Name)"; Text = [string]$e.Action })
            }
        }
        $texts.Count | Should -BeGreaterThan 15

        $verb = '(?i)\b(restart\w*|reboot\w*|reinstall\w*|install|installs|upgrade\w*|free up|delete\w*|clean up)\b'
        $offenders = @(foreach ($t in $texts) {
                $m = [regex]::Match($t.Text, $verb)
                if (-not $m.Success) { continue }
                $before = $t.Text.Substring(0, $m.Index)
                $namedDiskTool = ($m.Value -match '(?i)^(free up|clean up)$') -and ($t.Text -match 'Drive-Storage-Report|Cleanup-CitrixVDAStorage')
                if ($before -notmatch '(?i)\bescalate' -and -not $namedDiskTool) { '{0}: "{1}" before Escalate in: {2}' -f $t.Case, $m.Value, $t.Text }
            })
        $offenders | Should -BeNullOrEmpty
    }
}

Describe 'AVD host checks: Application log query' {
    It 'AVD_R1_QueryFiltersByAgentSource: the first query asks for the agent sources, not just the IDs' {
        Set-AvdHost
        $null = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        Should -Invoke Get-WinEvent -Times 1 -Exactly -ParameterFilter {
            $FilterHashtable.LogName -eq 'Application' -and @($FilterHashtable.ProviderName) -contains 'WVD-Agent' -and
            @($FilterHashtable.ProviderName) -contains 'MsiInstaller' -and @($FilterHashtable.Id) -contains 3277
        }
    }

    It 'AVD_R1_FallbackKeepsOnlyAgentEvents: when the source filter is refused, the ID-only retry keeps agent events only and stores no message text' {
        Set-AvdHost
        Mock Get-WinEvent -ParameterFilter { $FilterHashtable.LogName -eq 'Application' } {
            if ($FilterHashtable.ContainsKey('ProviderName')) { throw 'There is not an event provider on the AVD01 computer that matches "WVD-Agent-Updater".' }
            @(
                [PSCustomObject]@{ Id = 3019; ProviderName = 'SomeOtherApp'; LevelDisplayName = 'Error'; Message = 'OTHERAPPMARKER private text'; TimeCreated = (Get-Date) }
                [PSCustomObject]@{ Id = 3703; ProviderName = 'WVD-Agent'; LevelDisplayName = 'Error'; Message = 'RD Gateway Url: https://gw.example.invalid is not accessible AGENTMARKER'; TimeCreated = (Get-Date) }
            )
        }
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        Should -Invoke Get-WinEvent -Times 2 -Exactly -ParameterFilter { $FilterHashtable.LogName -eq 'Application' }
        $found = @(Get-Evidence $r 'AVD agent event' | Where-Object { $_.Status -ne 'Pass' })
        $found.Count | Should -Be 1
        $found[0].Detail | Should -Match '3703'
        @(Get-Evidence $r 'AVD agent event*' | Where-Object { $_.Detail -match '3019' }).Count | Should -Be 0

        $raw = @($r.RawOutput.Avd.Events)
        $raw.Count | Should -Be 1
        $raw[0].Id | Should -Be 3703
        $raw[0].ProviderName | Should -Be 'WVD-Agent'
        $raw[0].Rule | Should -Be 'RD Gateway URL not accessible'
        $raw[0].PSObject.Properties.Name | Should -Not -Contain 'Message'
        ($r.RawOutput | ConvertTo-Json -Depth 12 -Compress) | Should -Not -Match 'OTHERAPPMARKER|AGENTMARKER'
    }
}

Describe 'AVD host checks: ticket note wording for checks that could not run' {
    BeforeAll {
        function Get-NoteText($Result) { (ConvertTo-TicketNoteText -Note (ConvertTo-CitrixFSLogixTriageTicketNote -Result $Result)) -join "`n" }
    }

    It 'AVD_R1_NoteUsesFixedWording: failed AVD reads appear in the note in fixed words, without the exception text; the report keeps it' {
        Set-AvdHost -Service Throw -Registry Registered -Events 'Throw' -Qwinsta 'Throw'
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        $note = Get-NoteText $r
        $note | Should -Match ([regex]::Escape('- Could not read the AVD agent service.'))
        $note | Should -Match ([regex]::Escape('- Could not read the Application log for AVD agent errors.'))
        $note | Should -Match ([regex]::Escape('- Could not check the AVD rdp-sxs listener.'))
        $note | Should -Not -Match 'WinRM client|RPC server is unavailable|Access is denied'
        $note | Should -Match 'the Azure Virtual Desktop agent\.' -Because 'the registration was read, so AVD was partly checked'

        $report = (ConvertTo-TriageText -Result $r) -join "`n"
        $report | Should -Match 'The WinRM client cannot process the request'
        ([string]$r.Error) | Should -Match 'Access is denied'
    }

    It 'AVD_R1_ScopeLineSaysCouldNotCheck: when every AVD item could not be checked, the scope line says so' {
        Set-AvdHost -Service Throw -Registry Registered -Events 'Throw' -Qwinsta 'Throw'
        $r = Invoke-CitrixFSLogixTriage -ComputerName AVD01 -UserName jdoe
        # Today a registration read that fails also hides the host from detection, so make every
        # AVD item NotChecked by hand to pin the wording.
        $evidence = @($r.Evidence | ForEach-Object {
                if ($_.Name -like 'AVD *' -and -not $_.NotChecked) { New-EvidenceItem -Name $_.Name -Status 'Warn' -NotChecked -Detail 'x' -Action 'y' } else { $_ }
            })
        $blind = [PSCustomObject]@{}
        foreach ($p in $r.PSObject.Properties) { $blind | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
        $blind.Evidence = $evidence
        $note = Get-NoteText $blind
        $note | Should -Match 'the Azure Virtual Desktop agent \(could not check\)\.'
        $note | Should -Match ([regex]::Escape('- Could not read the AVD host pool registration.'))
    }
}

Describe 'AVD host checks: static guards' {
    BeforeAll {
        $script:GuardAst = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$null)
        function Get-FunctionAst([string]$Name) {
            @($script:GuardAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true))[0]
        }
    }

    It 'AVD_R1_RegistryReadsOnlyIsRegistered: Get-AvdAgentRegistry only calls GetValue(IsRegistered), opens the key read-only and never lists values or names RegistrationToken' {
        $fn = Get-FunctionAst 'Get-AvdAgentRegistry'
        $fn | Should -Not -BeNullOrEmpty
        $calls = @($fn.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true))
        $members = @($calls | ForEach-Object { $_.Member.Extent.Text } | Sort-Object -Unique)
        foreach ($m in $members) { $m | Should -BeIn @('OpenBaseKey', 'OpenRemoteBaseKey', 'OpenSubKey', 'GetValue', 'Close') }
        $getValue = @($calls | Where-Object { $_.Member.Extent.Text -eq 'GetValue' })
        $getValue.Count | Should -BeGreaterThan 0
        foreach ($c in $getValue) {
            @($c.Arguments).Count | Should -Be 1
            $c.Arguments[0].Value | Should -Be 'IsRegistered'
        }
        foreach ($c in @($calls | Where-Object { $_.Member.Extent.Text -eq 'OpenSubKey' })) { @($c.Arguments).Count | Should -Be 1 -Because 'one argument = read-only' }
        $strings = @($fn.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) | ForEach-Object { $_.Value })
        $strings | Should -Not -Contain 'RegistrationToken'
        $strings | Should -Not -Contain 'GetValueNames'
    }

    It 'AVD_R1_OnlyNativeCallIsQwinsta: the only & invocation is qwinsta.exe with nothing but /server:<name>' {
        $amp = @($script:GuardAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Ampersand }, $true))
        $amp.Count | Should -Be 1
        $call = $amp[0]
        $call.CommandElements[0].Extent.Text | Should -Be '$qwinsta'
        @($call.CommandElements).Count | Should -Be 2
        $call.CommandElements[1].Extent.Text | Should -Be '@arguments'

        $fn = Get-FunctionAst 'Get-AvdStackListenerOutput'
        $call.Extent.StartOffset | Should -BeGreaterThan $fn.Extent.StartOffset
        $call.Extent.EndOffset | Should -BeLessThan $fn.Extent.EndOffset
        $assigns = @($fn.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true))
        $qwinstaSet = @($assigns | Where-Object { $_.Left.Extent.Text -eq '$qwinsta' })
        $qwinstaSet.Count | Should -Be 1
        $qwinstaSet[0].Right.Extent.Text | Should -Match "'\{0\}\\qwinsta\.exe'"
        $argumentSet = @($assigns | Where-Object { $_.Left.Extent.Text -eq '$arguments' } | ForEach-Object { $_.Right.Extent.Text })
        $argumentSet.Count | Should -Be 2
        $argumentSet | Should -Contain '@()'
        $argumentSet | Should -Contain "('/server:{0}' -f `$ComputerName)"

        $commands = @($script:GuardAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
        foreach ($banned in 'Start-Process', 'Invoke-Expression', 'iex', 'cmd', 'cmd.exe') { $commands | Should -Not -Contain $banned }
    }
}
