BeforeAll {
    . "$PSScriptRoot/../Export-RDSFSLogixEvents.ps1" -LoadFunctionsOnly
}

Describe 'Script loading' {
    It 'dot-sources with -LoadFunctionsOnly without starting a collection' {
        Get-Command Write-StatusLine -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe 'Test-IsLocalTarget' {
    # Get-WinEvent rejects a credential on a local connection, so this gate decides whether
    # -Credential is attached. -LocalName is injected so the assertions hold on any machine.
    It 'recognises the machine name' {
        Test-IsLocalTarget -ComputerName 'RDS01' -LocalName 'RDS01' | Should -BeTrue
    }

    It 'matches case-insensitively' {
        Test-IsLocalTarget -ComputerName 'rds01' -LocalName 'RDS01' | Should -BeTrue
    }

    It 'recognises loopback names' {
        Test-IsLocalTarget -ComputerName 'localhost' -LocalName 'RDS01' | Should -BeTrue
        Test-IsLocalTarget -ComputerName '.'         -LocalName 'RDS01' | Should -BeTrue
        Test-IsLocalTarget -ComputerName '127.0.0.1' -LocalName 'RDS01' | Should -BeTrue
    }

    It 'recognises the local machine by FQDN' {
        Test-IsLocalTarget -ComputerName 'RDS01.contoso.local' -LocalName 'RDS01' | Should -BeTrue
    }

    It 'treats another server as remote' {
        Test-IsLocalTarget -ComputerName 'RDS02' -LocalName 'RDS01' | Should -BeFalse
    }

    It 'treats another server FQDN as remote' {
        Test-IsLocalTarget -ComputerName 'RDS02.contoso.local' -LocalName 'RDS01' | Should -BeFalse
    }

    It 'does not call every host local when COMPUTERNAME is unset' {
        Test-IsLocalTarget -ComputerName 'RDS02' -LocalName '' | Should -BeFalse
    }
}

Describe 'Get-RemoteEventArgs' {
    BeforeAll {
        $script:cred = [System.Management.Automation.PSCredential]::new(
            'CONTOSO\svc', (ConvertTo-SecureString 'x' -AsPlainText -Force))
    }

    It 'returns no arguments for the local machine' {
        # Passing -ComputerName or -Credential for the local host is what broke the original
        # script; an empty splat is the whole point.
        $r = Get-RemoteEventArgs -ComputerName $env:COMPUTERNAME -Credential $null
        $r.Keys.Count | Should -Be 0
    }

    It 'returns no arguments for localhost even when a credential is supplied' {
        $r = Get-RemoteEventArgs -ComputerName 'localhost' -Credential $script:cred
        $r.Keys.Count | Should -Be 0
    }

    It 'targets a remote host by name' {
        $r = Get-RemoteEventArgs -ComputerName 'RDS99-REMOTE' -Credential $null
        $r['ComputerName'] | Should -Be 'RDS99-REMOTE'
        $r.ContainsKey('Credential') | Should -BeFalse
    }

    It 'attaches the credential for a remote host' {
        $r = Get-RemoteEventArgs -ComputerName 'RDS99-REMOTE' -Credential $script:cred
        $r['ComputerName'] | Should -Be 'RDS99-REMOTE'
        $r['Credential']   | Should -Be $script:cred
    }

    It 'does not clobber the $args automatic variable' {
        # A local named $args inside a non-advanced function is a real footgun.
        $r = Get-RemoteEventArgs -ComputerName 'RDS99-REMOTE' -Credential $null
        $r | Should -BeOfType ([hashtable])
    }
}

Describe 'Remote targeting is threaded through every query function' {
    # Regression guard for the original defect: the script accepted a ComputerName for the
    # report header while every query ran against the local machine.
    It 'exposes -ComputerName on <Name>' -ForEach @(
        @{ Name = 'Get-EventsFromLog'          }
        @{ Name = 'Get-RDSOperationalLogs'     }
        @{ Name = 'Get-RDSCategoryEvents'      }
        @{ Name = 'Get-FSLogixCategoryEvents'  }
        @{ Name = 'Get-SystemAppCategoryEvents'}
        @{ Name = 'Get-SecurityCategoryEvents' }
    ) {
        (Get-Command $Name).Parameters.Keys | Should -Contain 'ComputerName'
    }

    It 'exposes -Credential on <Name>' -ForEach @(
        @{ Name = 'Get-EventsFromLog'          }
        @{ Name = 'Get-RDSOperationalLogs'     }
        @{ Name = 'Get-RDSCategoryEvents'      }
        @{ Name = 'Get-FSLogixCategoryEvents'  }
        @{ Name = 'Get-SystemAppCategoryEvents'}
        @{ Name = 'Get-SecurityCategoryEvents' }
    ) {
        (Get-Command $Name).Parameters.Keys | Should -Contain 'Credential'
    }

    It 'accepts an array of computers at the script level' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Resolve-Path "$PSScriptRoot/../Export-RDSFSLogixEvents.ps1").Path, [ref]$null, [ref]$null)
        $p = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'ComputerName' }
        $p.StaticType.ToString() | Should -Be 'System.String[]'
    }

    It 'leaves no Get-WinEvent call without the remote splat' {
        $text = Get-Content (Resolve-Path "$PSScriptRoot/../Export-RDSFSLogixEvents.ps1").Path -Raw
        # Every invocation must carry @remote. Count invocations vs splats.
        $calls  = ([regex]::Matches($text, '(?m)^\s*.*Get-WinEvent\s+-(?:FilterHashtable|ListLog|ListProvider)')).Count
        $splats = ([regex]::Matches($text, '@remote')).Count
        $splats | Should -BeGreaterOrEqual $calls
    }
}

Describe 'Resolve-TimeWindow' {
    It 'defaults to the last 24 hours' {
        $w = Resolve-TimeWindow
        [math]::Round(($w.End - $w.Start).TotalHours) | Should -Be 24
    }

    It 'rejects -LastHours combined with -LastDays' {
        { Resolve-TimeWindow -LastHours 4 -LastDays 2 } | Should -Throw '*mutually exclusive*'
    }

    It 'rejects an inverted window' {
        { Resolve-TimeWindow -StartTime (Get-Date '2026-09-02') -EndTime (Get-Date '2026-09-01') } |
            Should -Throw '*must be earlier*'
    }
}
