<#
    Pester 5 tests for ServerEventTimeline.Engine.ps1. Every remote call is mocked: no server
    is contacted, no real event log is read, $env:COMPUTERNAME is never a target.
    Run:  pwsh -File Tests\Invoke-AllTests.ps1 -Path .\Server-EventTimeline\Tests
#>

BeforeAll {
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'ServerEventTimeline.Engine.ps1')

    function New-Err {
        param([Exception]$Exception, [string]$Id = 'X')
        New-Object System.Management.Automation.ErrorRecord ($Exception, $Id, [System.Management.Automation.ErrorCategory]::NotSpecified, $null)
    }
    function New-RawEvent {
        param($Id = 7036, $Time = '2026-11-17 08:00:00')
        [PSCustomObject]@{
            TimeCreated = [datetime]::SpecifyKind([datetime]$Time, [DateTimeKind]::Utc).ToLocalTime()
            Id = $Id; ProviderName = 'Service Control Manager'; Level = 4; LogName = 'System'
            Message = 'The service entered the running state.'; RecordId = 1; UserId = $null; MachineName = 'srv-fake-01'
        }
    }
    $script:Start = [datetime]::SpecifyKind([datetime]'2026-11-17 07:45', [DateTimeKind]::Utc)
    $script:End = [datetime]::SpecifyKind([datetime]'2026-11-17 08:15', [DateTimeKind]::Utc)
}

Describe 'Invoke-ServerProbe' {
    BeforeEach {
        Mock Test-TcpPortQuick { $true }
        Mock Invoke-Command {
            [PSCustomObject]@{ UtcOffsetMinutes = -300; TimeZoneId = 'Eastern Standard Time'
                Channels = @([PSCustomObject]@{ Name = 'System'; IsEnabled = $true; RecordCount = 10 }) }
        }
        Mock Get-WinEvent { @([PSCustomObject]@{ LogName = 'System'; IsEnabled = $true; RecordCount = 10 }) }
        Mock Get-RpcUtcOffsetMinutes { 60 }
    }

    It 'uses WinRM when port 5985 answers' {
        $p = Invoke-ServerProbe -ComputerName srv-fake-01 -WindowStartLocal ([datetime]'2026-11-17 03:00')
        $p.Reachable | Should -BeTrue
        $p.Transport | Should -Be 'WinRM'
        $p.UtcOffsetMinutes | Should -Be -300
        @($p.Channels).Count | Should -Be 1
    }

    It 'uses the remote event log when 5985 is closed and 135 answers, without trying WinRM' {
        Mock Test-TcpPortQuick { $Port -eq 135 }
        $p = Invoke-ServerProbe -ComputerName srv-fake-01 -WindowStartLocal ([datetime]'2026-11-17 03:00')
        $p.Transport | Should -Be 'RPC'
        $p.UtcOffsetMinutes | Should -Be 60
        Should -Invoke Invoke-Command -Times 0
    }

    It 'falls back to the remote event log on a WinRM connection failure' {
        Mock Invoke-Command {
            $ex = New-Object System.Management.Automation.Remoting.PSRemotingTransportException 'WinRM cannot complete the operation.'
            $ex.ErrorCode = 53
            throw (New-Err $ex 'WinRMOperationTimeout,PSSessionStateBroken')
        }
        $p = Invoke-ServerProbe -ComputerName srv-fake-01 -WindowStartLocal ([datetime]'2026-11-17 03:00')
        $p.Transport | Should -Be 'RPC'
        $p.Reachable | Should -BeTrue
    }

    It 'reports access denied without retrying over the remote event log' {
        Mock Invoke-Command {
            $ex = New-Object System.Management.Automation.Remoting.PSRemotingTransportException 'Access is denied.'
            $ex.ErrorCode = 5
            throw (New-Err $ex 'AccessDenied,PSSessionStateBroken')
        }
        $p = Invoke-ServerProbe -ComputerName srv-fake-01 -WindowStartLocal ([datetime]'2026-11-17 03:00')
        $p.Reachable | Should -BeFalse
        $p.FailureKind | Should -Be 'AccessDenied'
        $p.Reason | Should -BeLike 'Access denied on srv-fake-01*'
        Should -Invoke Get-WinEvent -Times 0
    }

    It 'says both routes are unreachable when neither port answers' {
        Mock Test-TcpPortQuick { $false }
        $p = Invoke-ServerProbe -ComputerName srv-fake-01 -WindowStartLocal ([datetime]'2026-11-17 03:00')
        $p.Reachable | Should -BeFalse
        $p.Reason | Should -Be 'WinRM and remote event log are both unreachable from here.'
    }
}

Describe 'Invoke-LogQuery' {
    It 'marks a log Capped and trims to the cap when more than the cap come back' {
        Mock Get-WinEvent { 1..4 | ForEach-Object { New-RawEvent -Id $_ } }
        $r = Invoke-LogQuery -ComputerName srv-fake-01 -Transport RPC -LogName System -StartUtc $script:Start -EndUtc $script:End -Cap 3
        $r.Outcome | Should -Be 'Capped'
        $r.Count | Should -Be 3
        @($r.Events).Count | Should -Be 3
    }

    It 'asks for one more than the cap, oldest first, between the UTC times' {
        Mock Get-WinEvent { @() }
        Invoke-LogQuery -ComputerName srv-fake-01 -Transport RPC -LogName System -StartUtc $script:Start -EndUtc $script:End -Cap 3 | Out-Null
        Should -Invoke Get-WinEvent -Times 1 -ParameterFilter {
            $MaxEvents -eq 4 -and $Oldest -and $ComputerName -eq 'srv-fake-01' -and
            $FilterHashtable[0].LogName -eq 'System' -and $FilterHashtable[0].StartTime -eq $script:Start -and $FilterHashtable[0].EndTime -eq $script:End
        }
    }

    It 'treats "no events found" as an empty Read, not a failure' {
        Mock Get-WinEvent {
            throw (New-Err (New-Object System.Exception 'No events were found that match the specified selection criteria.') 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand')
        }
        $r = Invoke-LogQuery -ComputerName srv-fake-01 -Transport RPC -LogName System -StartUtc $script:Start -EndUtc $script:End -Cap 3
        $r.Outcome | Should -Be 'Read'
        $r.Count | Should -Be 0
    }

    It 'reports other errors as Failed with a plain reason' {
        Mock Get-WinEvent { throw (New-Err (New-Object System.Exception 'The log is corrupt.')) }
        $r = Invoke-LogQuery -ComputerName srv-fake-01 -Transport RPC -LogName System -StartUtc $script:Start -EndUtc $script:End -Cap 3
        $r.Outcome | Should -Be 'Failed'
        $r.Reason | Should -BeLike '*The log is corrupt*'
    }

    It 'projects events to plain objects with UTC time' {
        Mock Get-WinEvent { New-RawEvent -Id 7031 }
        $r = Invoke-LogQuery -ComputerName srv-fake-01 -Transport RPC -LogName System -StartUtc $script:Start -EndUtc $script:End -Cap 3
        $e = @($r.Events)[0]
        $e.Id | Should -Be 7031
        $e.TimeCreatedUtc | Should -Be ([datetime]'2026-11-17 08:00:00')
        $e.TimeCreatedUtc.Kind | Should -Be ([DateTimeKind]::Utc)
    }

    It 'runs the query on the server through Invoke-Command for WinRM' {
        Mock Invoke-Command { [PSCustomObject]@{ Events = @(); Capped = $false } }
        $r = Invoke-LogQuery -ComputerName srv-fake-01 -Transport WinRM -LogName System -StartUtc $script:Start -EndUtc $script:End -Cap 3
        $r.Outcome | Should -Be 'Read'
        Should -Invoke Invoke-Command -Times 1 -ParameterFilter { $ComputerName -eq 'srv-fake-01' }
    }
}

Describe 'Get-LogPlan' {
    BeforeAll {
        $script:Catalog = @(Get-TimelineLogCatalog)
        $script:Probe = [PSCustomObject]@{ Server = 'srv-fake-01'; Channels = @(
            [PSCustomObject]@{ Name = 'System'; IsEnabled = $true; RecordCount = 100 }
            [PSCustomObject]@{ Name = 'Microsoft-Windows-TaskScheduler/Operational'; IsEnabled = $false; RecordCount = 0 }
            [PSCustomObject]@{ Name = 'Some-Vendor/Admin'; IsEnabled = $true; RecordCount = 5 }
            [PSCustomObject]@{ Name = 'Empty-Log/Operational'; IsEnabled = $true; RecordCount = 0 }
        ) }
    }

    It 'queries present logs and skips missing and turned-off ones with plain reasons' {
        $plan = Get-LogPlan -Probe $script:Probe -Catalog $script:Catalog -SelectedNames @('System', 'Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-SMBServer/Operational')
        $plan.Query | Should -Be @('System')
        ($plan.Skipped | Where-Object Log -eq 'Microsoft-Windows-TaskScheduler/Operational').Reason | Should -BeLike "Task Scheduler log is turned off on srv-fake-01*off by default*"
        ($plan.Skipped | Where-Object Log -eq 'Microsoft-Windows-SMBServer/Operational').Reason | Should -Be "File share server (SMB) log doesn't exist on srv-fake-01"
    }

    It 'All logs adds only channels with records and no duplicates' {
        $plan = Get-LogPlan -Probe $script:Probe -Catalog $script:Catalog -SelectedNames @('System') -AllLogs $true
        $plan.Query | Should -Be @('System', 'Some-Vendor/Admin')
    }

    It 'queries the selected logs as-is when the channel list could not be read' {
        $probe = [PSCustomObject]@{ Server = 'srv-fake-01'; Channels = @() }
        (Get-LogPlan -Probe $probe -Catalog $script:Catalog -SelectedNames @('System', 'Application')).Query | Should -Be @('System', 'Application')
    }
}

Describe 'Real cmdlet parameter names' {
    It '<Command> has -<Parameter>' -ForEach @(
        @{ Command = 'Get-WinEvent'; Parameter = 'FilterHashtable' }, @{ Command = 'Get-WinEvent'; Parameter = 'MaxEvents' }
        @{ Command = 'Get-WinEvent'; Parameter = 'ComputerName' }, @{ Command = 'Get-WinEvent'; Parameter = 'Credential' }
        @{ Command = 'Get-WinEvent'; Parameter = 'ListLog' }, @{ Command = 'Get-WinEvent'; Parameter = 'Oldest' }
        @{ Command = 'Invoke-Command'; Parameter = 'ComputerName' }, @{ Command = 'Invoke-Command'; Parameter = 'ScriptBlock' }
        @{ Command = 'Invoke-Command'; Parameter = 'ArgumentList' }, @{ Command = 'Invoke-Command'; Parameter = 'Credential' }
        @{ Command = 'New-CimSession'; Parameter = 'ComputerName' }, @{ Command = 'New-CimSession'; Parameter = 'SessionOption' }
        @{ Command = 'New-CimSession'; Parameter = 'Credential' }, @{ Command = 'New-CimSessionOption'; Parameter = 'Protocol' }
        @{ Command = 'Get-CimInstance'; Parameter = 'CimSession' }, @{ Command = 'Get-CimInstance'; Parameter = 'ClassName' }
        @{ Command = 'Remove-CimSession'; Parameter = 'CimSession' }
    ) {
        (Get-Command $Command).Parameters.Keys | Should -Contain $Parameter
    }
}

Describe 'Invoke-ServerProbe: review fixes' {
    It 'keeps an RPC server reachable when WMI is blocked, and says the time zone was assumed' {
        Mock Test-TcpPortQuick { $Port -eq 135 }
        Mock Get-WinEvent { @([PSCustomObject]@{ LogName = 'System'; IsEnabled = $true; RecordCount = 10 }) }
        Mock Get-RpcUtcOffsetMinutes { throw 'The RPC server is unavailable.' }
        $p = Invoke-ServerProbe -ComputerName srv-fake-01 -WindowStartLocal ([datetime]'2026-11-17 03:00')
        $p.Reachable | Should -BeTrue
        $p.Transport | Should -Be 'RPC'
        $p.Note | Should -BeLike "*time zone*this workstation*"
        $p.UtcOffsetMinutes | Should -Be ([int][TimeZoneInfo]::Local.GetUtcOffset([datetime]'2026-11-17 03:00').TotalMinutes)
    }
}

Describe 'This computer: read directly' {
    BeforeEach {
        Mock Get-LocalComputerNames { @('WS01', 'ws01.contoso.local', 'localhost', '.', '127.0.0.1', '::1') }
        Mock Test-TcpPortQuick { $true }
        Mock Invoke-Command { throw 'must not be called for this computer' }
        Mock Get-RpcUtcOffsetMinutes { throw 'must not be called for this computer' }
    }

    It 'probes this computer without the network and always offers Security' {
        Mock Get-WinEvent { @([PSCustomObject]@{ LogName = 'System'; IsEnabled = $true; RecordCount = 10 }) }
        $p = Invoke-ServerProbe -ComputerName 'ws01' -WindowStartLocal ([datetime]'2026-11-17 03:00')
        $p.Reachable | Should -BeTrue
        $p.Transport | Should -Be 'Local'
        $p.UtcOffsetMinutes | Should -Be ([int][TimeZoneInfo]::Local.GetUtcOffset([datetime]'2026-11-17 03:00').TotalMinutes)
        @($p.Channels | ForEach-Object Name) | Should -Contain 'Security'
        Should -Invoke Test-TcpPortQuick -Times 0
        Should -Invoke Invoke-Command -Times 0
        Should -Invoke Get-WinEvent -Times 1 -ParameterFilter { $ListLog -and -not $ComputerName }
    }

    It 'reads a log on this computer without -ComputerName' {
        Mock Get-WinEvent { @() }
        $r = Invoke-LogQuery -ComputerName 'WS01' -Transport Local -LogName System -StartUtc $script:Start -EndUtc $script:End -Cap 3
        $r.Outcome | Should -Be 'Read'
        Should -Invoke Get-WinEvent -Times 1 -ParameterFilter { -not $ComputerName -and $FilterHashtable[0].LogName -eq 'System' }
    }

    It 'says to start as administrator when this computer''s Security log is denied' {
        Mock Get-WinEvent { throw (New-Err (New-Object UnauthorizedAccessException 'Attempted to perform an unauthorized operation.')) }
        $r = Invoke-LogQuery -ComputerName 'WS01' -Transport Local -LogName Security -StartUtc $script:Start -EndUtc $script:End -Cap 3
        $r.Outcome | Should -Be 'Failed'
        $r.Reason | Should -Be "Can't read the Security log here: start the tool as administrator."
    }
}
