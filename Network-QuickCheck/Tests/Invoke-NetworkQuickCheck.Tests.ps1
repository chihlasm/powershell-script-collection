<#
    Tests for Invoke-NetworkQuickCheck.ps1 (Pester 5; runs under Windows PowerShell 5.1 and 7.x).

    DNS, ping, port and route lookups are mocked for the verdict tests. Test-TcpPort itself is
    exercised for real against a listener on 127.0.0.1, so the timeout and endpoint handling
    are proven without touching the network.

    Run:  Invoke-Pester .\Network-QuickCheck\Tests
#>

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:ScriptPath = Join-Path $script:Root 'Invoke-NetworkQuickCheck.ps1'
    . $script:ScriptPath -LoadFunctionsOnly

    function Set-ReachableTarget {
        Mock Resolve-TargetName { [PSCustomObject]@{ Name = 'filesrv01.contoso.com'; Type = 'A'; IPAddress = '10.0.0.5'; NameHost = '' } }
        Mock Test-Connection { $true }
        Mock Test-TcpPort { [PSCustomObject]@{ Succeeded = $true; LocalAddress = '10.0.0.20:50000'; RemoteAddress = "10.0.0.5:$Port"; Error = '' } }
        Mock Get-NetRoute { [PSCustomObject]@{ DestinationPrefix = '0.0.0.0/0'; NextHop = '10.0.0.1'; InterfaceAlias = 'Ethernet'; RouteMetric = 0; ifIndex = 4 } }
    }

    function Get-Evidence($Result, [string]$Name) { @($Result.Evidence | Where-Object { $_.Name -eq $Name }) }
}

Describe 'Verdict' {
    BeforeEach { Set-ReachableTarget }

    It 'answers YES when DNS, ping and the port all work' {
        $r = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445
        $r.Status | Should -Be 'Pass'
        $r.Answer | Should -Be 'YES'
        (Get-Evidence $r 'Port 445 (file shares (SMB))').Status | Should -Be 'Pass'
    }

    It 'answers YES WITH WARNINGS when only ping is blocked (many servers block ping)' {
        Mock Test-Connection { $false }
        $r = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445
        $r.Status | Should -Be 'Warn'
        $r.Answer | Should -Be 'YES, WITH WARNINGS'
    }

    It 'answers PARTLY when one of two ports is closed' {
        Mock Test-TcpPort -ParameterFilter { $Port -eq 3389 } { [PSCustomObject]@{ Succeeded = $false; LocalAddress = ''; RemoteAddress = ''; Error = 'No answer within 3000 ms' } }
        $r = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445, 3389
        $r.Status | Should -Be 'Fail'
        $r.Answer | Should -Be 'PARTLY'
    }

    It 'answers NO when the port is closed' {
        Mock Test-TcpPort { [PSCustomObject]@{ Succeeded = $false; LocalAddress = ''; RemoteAddress = ''; Error = 'Connection refused' } }
        $r = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445
        $r.Answer | Should -Be 'NO'
        $r.Summary | Should -Match 'cannot reach filesrv01 on port 445'
    }

    It 'fails when the name is not in DNS' {
        Mock Resolve-TargetName { throw 'filesrv99 : DNS name does not exist' }
        $r = Invoke-NetworkQuickCheck -TargetAddress filesrv99 -Port 445
        (Get-Evidence $r 'Name lookup (DNS)').Status | Should -Be 'Fail'
    }

    It 'tests each port only once' {
        $null = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445, 445, 3389
        Should -Invoke Test-TcpPort -Times 2 -Exactly
    }
}

Describe 'IP addresses skip DNS (regression: an IP used to give a misleading DNS warning)' {
    BeforeEach { Set-ReachableTarget }

    It 'does not look up an IPv4 address' {
        $r = Invoke-NetworkQuickCheck -TargetAddress 10.0.0.5 -Port 445
        Should -Invoke Resolve-TargetName -Times 0 -Exactly
        (Get-Evidence $r 'Name lookup (DNS)').Status | Should -Be 'Pass'
        $r.Answer | Should -Be 'YES'
    }

    It 'recognises an IPv6 address' {
        Test-IsIpAddress -Value 'fe80::1' | Should -BeTrue
        Test-IsIpAddress -Value 'filesrv01' | Should -BeFalse
    }
}

Describe 'Result shape (kept from the retired workbench check)' {
    It 'has the fields callers read' {
        Set-ReachableTarget
        $r = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 443
        foreach ($name in 'CheckId', 'Name', 'Category', 'Status', 'Summary', 'Evidence', 'RecommendedNextSteps', 'RawOutput', 'StartedAt', 'FinishedAt', 'Error') {
            $r.PSObject.Properties.Name | Should -Contain $name
        }
        $r.CheckId | Should -Be 'network.quick'
        $r.RawOutput.Tcp[0].TcpTestSucceeded | Should -BeTrue
    }
}

Describe 'Test-TcpPort against a real local listener' {
    BeforeAll {
        $script:Listener = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Loopback), 0
        $script:Listener.Start()
        $script:OpenPort = $script:Listener.LocalEndpoint.Port
        # A port that was free a moment ago: bind, read the number, release.
        $probe = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Loopback), 0
        $probe.Start(); $script:ClosedPort = $probe.LocalEndpoint.Port; $probe.Stop()
    }
    AfterAll { $script:Listener.Stop() }

    It 'connects to an open port and reports plain IPv4 endpoints' {
        $t = Test-TcpPort -ComputerName '127.0.0.1' -Port $script:OpenPort -TimeoutMilliseconds 2000
        $t.Succeeded | Should -BeTrue
        $t.RemoteAddress | Should -Be "127.0.0.1:$($script:OpenPort)"
    }

    It 'reports a closed port as not reachable within the timeout' {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $t = Test-TcpPort -ComputerName '127.0.0.1' -Port $script:ClosedPort -TimeoutMilliseconds 1500
        $sw.Stop()
        $t.Succeeded | Should -BeFalse
        $t.Error | Should -Not -BeNullOrEmpty
        $sw.ElapsedMilliseconds | Should -BeLessThan 5000
    }
}

Describe 'Helpers' {
    It 'shows an IPv4-mapped IPv6 endpoint as plain IPv4' {
        Format-Endpoint -Endpoint '[::ffff:140.82.112.4]:443' | Should -Be '140.82.112.4:443'
        Format-Endpoint -Endpoint '[fe80::1]:445' | Should -Be '[fe80::1]:445'
    }
    It 'names well-known ports' {
        Get-PortLabel -Port 3389 | Should -Be '3389 (Remote Desktop)'
        Get-PortLabel -Port 12345 | Should -Be '12345'
    }
}

Describe 'Report output' {
    BeforeEach { Set-ReachableTarget }

    It 'leads with the question and the answer' {
        $r = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445
        (ConvertTo-NetworkText -Result $r)[0] | Should -Be ("Can {0} reach filesrv01 on port 445?  YES" -f $env:COMPUTERNAME)
    }

    It 'writes a text file and a CSV to -OutputPath' {
        $r = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445
        $files = @(Export-NetworkReport -Result $r -OutputPath (Join-Path $TestDrive 'out'))
        $files.Count | Should -Be 2
        foreach ($f in $files) { Test-Path -LiteralPath $f | Should -BeTrue }
    }

    It 'refuses to run without a target, instead of silently testing localhost' {
        $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:ScriptPath 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 2
        $out | Should -Match 'Name the server to test'
    }
}
