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
        param($Id = 7036, $Time = '2026-11-17 08:00:00', $Level = 4, $RecordId = 1, $Keywords = 0)
        [PSCustomObject]@{
            TimeCreated = [datetime]::SpecifyKind([datetime]$Time, [DateTimeKind]::Utc).ToLocalTime()
            Id = $Id; ProviderName = 'Service Control Manager'; Level = $Level; LogName = 'System'; Keywords = $Keywords
            Message = 'The service entered the running state.'; RecordId = $RecordId; UserId = $null; MachineName = 'srv-fake-01'
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
        Mock Get-WinEvent { 1..4 | ForEach-Object { New-RawEvent -Id $_ -RecordId $_ } }
        $r = Invoke-LogQuery -ComputerName srv-fake-01 -Transport RPC -LogName System -StartUtc $script:Start -EndUtc $script:End -Cap 3
        $r.Outcome | Should -Be 'Capped'
        $r.Count | Should -Be 3
        @($r.Events).Count | Should -Be 3
    }

    It 'reads newest first (regression: oldest first dropped the end of the window)' {
        Mock Get-WinEvent { @() }
        Invoke-LogQuery -ComputerName srv-fake-01 -Transport RPC -LogName System -StartUtc $script:Start -EndUtc $script:End -Cap 3 | Out-Null
        Should -Invoke Get-WinEvent -Times 1 -ParameterFilter {
            $MaxEvents -eq 4 -and -not $Oldest -and $ComputerName -eq 'srv-fake-01' -and
            $FilterHashtable[0].LogName -eq 'System' -and $FilterHashtable[0].Level -ne $null
        }
    }

    It 'important read asks for levels 1-3 and the recognised IDs in chunks of at most 20' {
        $script:calls = @()
        Mock Get-WinEvent { $script:calls += , $FilterHashtable[0]; @() }
        Invoke-LogQuery -ComputerName srv-fake-01 -Transport RPC -LogName System -StartUtc $script:Start -EndUtc $script:End -Cap 3 -Part Important | Out-Null
        @($script:calls | Where-Object { $_.Level }).Count | Should -Be 1
        (@($script:calls | Where-Object { $_.Level })[0].Level) | Should -Be @(1, 2, 3)
        $idCalls = @($script:calls | Where-Object { $_.Id })
        foreach ($c in $idCalls) { @($c.Id).Count | Should -BeLessOrEqual 20 }
        $union = @($idCalls | ForEach-Object { $_.Id } | Sort-Object -Unique)
        $union | Should -Be @((Get-TimelineImportantRule -LogName System).Ids)
    }

    It 'important read for Security asks for audit failures and 4740' {
        $script:calls = @()
        Mock Get-WinEvent { $script:calls += , $FilterHashtable[0]; @() }
        Invoke-LogQuery -ComputerName srv-fake-01 -Transport RPC -LogName Security -StartUtc $script:Start -EndUtc $script:End -Cap 3 -Part Important | Out-Null
        @($script:calls | Where-Object { $_.Keywords -eq 4503599627370496 }).Count | Should -Be 1
        @($script:calls | Where-Object { $_.Id -contains 4740 }).Count | Should -Be 1
    }

    It 'important read merges the queries newest first, without duplicates, and caps' {
        Mock Get-WinEvent {
            if ($FilterHashtable[0].Level) { @((New-RawEvent -RecordId 5 -Level 2), (New-RawEvent -RecordId 3 -Level 2)) }
            else { @((New-RawEvent -RecordId 5 -Id 6005), (New-RawEvent -RecordId 4 -Id 6005)) }
        }
        $r = Invoke-LogQuery -ComputerName srv-fake-01 -Transport RPC -LogName System -StartUtc $script:Start -EndUtc $script:End -Cap 2 -Part Important
        $r.Outcome | Should -Be 'Capped'
        @($r.Events | ForEach-Object { $_.RecordId }) | Should -Be @(5, 4)
    }

    It 'routine read skips important events before the budget' {
        Mock Get-WinEvent {
            @((New-RawEvent -RecordId 9 -Id 6005), (New-RawEvent -RecordId 8), (New-RawEvent -RecordId 7), (New-RawEvent -RecordId 6))
        }
        $r = Invoke-LogQuery -ComputerName srv-fake-01 -Transport RPC -LogName System -StartUtc $script:Start -EndUtc $script:End -Cap 2 -Part Routine
        @($r.Events | ForEach-Object { $_.RecordId }) | Should -Be @(8, 7)
        $r.Outcome | Should -Be 'Capped'
        Should -Invoke Get-WinEvent -Times 1 -ParameterFilter { (@($FilterHashtable[0].Level) -join ',') -eq '0,4,5' }
    }

    It 'routine read of Security skips audit failures, 4740 and levels 1-3' {
        Mock Get-WinEvent {
            @((New-RawEvent -RecordId 4 -Id 4625 -Level 0 -Keywords 0x8010000000000000),
                (New-RawEvent -RecordId 3 -Id 4740 -Level 0 -Keywords 0x8020000000000000),
                (New-RawEvent -RecordId 2 -Id 4624 -Level 0 -Keywords 0x8020000000000000),
                (New-RawEvent -RecordId 1 -Id 4672 -Level 2 -Keywords 0x8020000000000000))
        }
        $r = Invoke-LogQuery -ComputerName srv-fake-01 -Transport RPC -LogName Security -StartUtc $script:Start -EndUtc $script:End -Cap 10 -Part Routine
        @($r.Events).Count | Should -Be 1
        @($r.Events)[0].Id | Should -Be 4624
    }

    It 'no matching events in every important query is an empty Read' {
        Mock Get-WinEvent {
            throw (New-Err (New-Object System.Exception 'No events were found that match the specified selection criteria.') 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand')
        }
        $r = Invoke-LogQuery -ComputerName srv-fake-01 -Transport RPC -LogName System -StartUtc $script:Start -EndUtc $script:End -Cap 3 -Part Important
        $r.Outcome | Should -Be 'Read'
        $r.Count | Should -Be 0
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

    It 'still queries Security when it is missing from the list, so an account that cannot see it gets "access denied", not "doesn''t exist"' {
        $plan = Get-LogPlan -Probe $script:Probe -Catalog $script:Catalog -SelectedNames @('System', 'Security')
        $plan.Query | Should -Be @('System', 'Security')
        @($plan.Skipped | Where-Object Log -eq 'Security').Count | Should -Be 0
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

Describe 'Time window survives Get-WinEvent' {
    # Get-WinEvent -FilterHashtable does StringToDateTime(value.ToString()) then
    # ToUniversalTime(): the DateTimeKind is lost and the text is read as LOCAL time on the
    # machine running the query. A UTC value would shift the window by the UTC offset.
    # https://github.com/PowerShell/PowerShell/blob/master/src/Microsoft.PowerShell.Commands.Diagnostics/GetEventCommand.cs
    It 'passes times that Get-WinEvent turns back into the intended UTC window' {
        $script:Seen = $null
        Mock Get-WinEvent { $script:Seen = $FilterHashtable[0]; @() }
        $null = Invoke-LogQuery -ComputerName srv-fake-01 -Transport RPC -LogName System -StartUtc $script:Start -EndUtc $script:End -Cap 3
        $asGetWinEventSees = { param($v) [datetime]::Parse($v.ToString(), [Globalization.CultureInfo]::CurrentCulture).ToUniversalTime() }
        (& $asGetWinEventSees $script:Seen.StartTime) | Should -Be $script:Start
        (& $asGetWinEventSees $script:Seen.EndTime) | Should -Be $script:End
    }
}
