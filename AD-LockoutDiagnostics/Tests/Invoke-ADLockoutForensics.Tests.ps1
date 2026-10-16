BeforeAll {
    . "$PSScriptRoot\..\Invoke-ADLockoutForensics.ps1" -LoadFunctionsOnly
}

Describe 'ConvertTo-SafeHtml' {
    It 'escapes the characters that would break out of an HTML attribute or element' {
        ConvertTo-SafeHtml -Text '<b>&</b>' | Should -Be '&lt;b&gt;&amp;&lt;/b&gt;'
    }

    It 'neutralises an injected script tag' {
        $out = ConvertTo-SafeHtml -Text '<script>alert(1)</script>'
        $out | Should -Not -Match '<script>'
        $out | Should -Match '&lt;script&gt;'
    }

    It 'escapes double quotes so attribute values cannot be broken out of' {
        ConvertTo-SafeHtml -Text 'a"b' | Should -Be 'a&quot;b'
    }

    It 'returns an empty string for null rather than throwing' {
        ConvertTo-SafeHtml -Text $null | Should -Be ''
    }
}

Describe 'Format-AdTimestamp' {
    It "renders AD's zero sentinel as Never, not 1601-01-01" {
        # A very common reporting bug: FromFileTime(0) is 1601-01-01, which reads as a
        # real date and misleads the investigator.
        Format-AdTimestamp -Value 0 | Should -Be 'Never'
    }

    It "renders AD's Int64 max sentinel as Never" {
        Format-AdTimestamp -Value ([int64]::MaxValue) | Should -Be 'Never'
    }

    It 'converts a real filetime to a readable local timestamp' {
        Format-AdTimestamp -Value 133000000000000000 | Should -Match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$'
    }

    It 'passes a DateTime through in the standard format' {
        Format-AdTimestamp -Value ([datetime]'2026-08-12T08:18:02') | Should -Be '2026-08-12 08:18:02'
    }

    It 'returns "Not set" for null' {
        Format-AdTimestamp -Value $null | Should -Be 'Not set'
    }
}

Describe 'Add-Finding' {
    BeforeEach {
        $script:Findings = New-Object System.Collections.ArrayList
    }

    It 'records severity, title, detail and action' {
        Add-Finding -Severity 'Critical' -Title 'T' -Detail 'D' -Action 'A'
        $script:Findings.Count    | Should -Be 1
        $script:Findings[0].Severity | Should -Be 'Critical'
        $script:Findings[0].Action   | Should -Be 'A'
    }

    It 'accumulates findings in order' {
        Add-Finding -Severity 'Info' -Title 'first' -Detail 'd'
        Add-Finding -Severity 'Warning' -Title 'second' -Detail 'd'
        $script:Findings[0].Title | Should -Be 'first'
        $script:Findings[1].Title | Should -Be 'second'
    }
}

Describe 'Add-LockoutPolicyFinding' {
    BeforeEach {
        $script:Findings = New-Object System.Collections.ArrayList
    }

    It 'warns on an aggressively low threshold' {
        # Threshold 3 is the real-world configuration that turns one stale credential
        # into a recurring lockout ticket.
        Add-LockoutPolicyFinding -ForestName 'test.local' -Policy ([pscustomobject]@{
            LockoutThreshold = 3; LockoutObservationWindow = '00:30:00'; LockoutDuration = '00:30:00' })
        $script:Findings[0].Severity | Should -Be 'Warning'
        $script:Findings[0].Title    | Should -Match '3'
    }

    It 'treats threshold 5 as still too low' {
        Add-LockoutPolicyFinding -ForestName 'test.local' -Policy ([pscustomobject]@{
            LockoutThreshold = 5; LockoutObservationWindow = '00:30:00'; LockoutDuration = '00:30:00' })
        $script:Findings[0].Severity | Should -Be 'Warning'
    }

    It 'reports a disabled lockout policy as Info, not a warning' {
        # Threshold 0 means accounts never lock. That is a different situation entirely:
        # any reported lockout must originate outside this domain.
        Add-LockoutPolicyFinding -ForestName 'test.local' -Policy ([pscustomobject]@{
            LockoutThreshold = 0; LockoutObservationWindow = '00:00:00'; LockoutDuration = '00:00:00' })
        $script:Findings[0].Severity | Should -Be 'Info'
        $script:Findings[0].Detail   | Should -Match 'never lock out'
    }

    It 'reports a healthy threshold as Good' {
        Add-LockoutPolicyFinding -ForestName 'test.local' -Policy ([pscustomobject]@{
            LockoutThreshold = 10; LockoutObservationWindow = '00:15:00'; LockoutDuration = '00:15:00' })
        $script:Findings[0].Severity | Should -Be 'Good'
    }

    It 'records nothing when no policy could be read' {
        Add-LockoutPolicyFinding -ForestName 'test.local' -Policy $null
        $script:Findings.Count | Should -Be 0
    }
}

Describe 'Get-ForestCred' {
    It 'returns null when no credential is configured for the forest' {
        $ForestCredential = @{}
        Get-ForestCred -ForestName 'a.local' | Should -BeNullOrEmpty
    }
}

Describe 'StatusCodes lookup table (verified against Microsoft Learn)' {
    # Regression guard for the 4776 bug: every 4776 was labelled a failure, so a machine
    # authenticating successfully was reported as a top source of bad passwords.
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4776
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4771

    It 'maps 0x0 to Success, not a failure' {
        $script:StatusCodes['0x0'] | Should -Match 'Success'
    }

    It 'maps the padded 0x00000000 form to Success as well' {
        # 4776 renders the code padded; 4771 does not. Both must resolve.
        $script:StatusCodes['0x00000000'] | Should -Match 'Success'
    }

    It 'never describes 0x0 as a failure of any kind' {
        $script:StatusCodes['0x0']        | Should -Not -Match '(?i)fail|bad|invalid|denied'
        $script:StatusCodes['0x00000000'] | Should -Not -Match '(?i)fail|bad|invalid|denied'
    }

    It 'maps Kerberos 0x18 to a bad password (the classic stale-credential signature)' {
        $script:StatusCodes['0x18'] | Should -Match '(?i)bad password'
    }

    It 'maps Kerberos 0x12 to revoked credentials including lockout' {
        # RFC 4120 KDC_ERR_CLIENT_REVOKED. Earlier text omitted the lockout meaning,
        # which is the case that matters most in a lockout investigation.
        $script:StatusCodes['0x12'] | Should -Match '(?i)revoked'
        $script:StatusCodes['0x12'] | Should -Match '(?i)locked out'
    }

    It 'maps NTLM 0xC0000234 to account locked out' {
        $script:StatusCodes['0xC0000234'] | Should -Match '(?i)locked out'
    }

    It 'maps NTLM 0xC000006A to a bad password' {
        $script:StatusCodes['0xC000006A'] | Should -Match '(?i)bad password'
    }

    It 'includes the documented NTLM codes that were previously missing' {
        # Present in Microsoft's Table 1 but absent from the original lookup, so these
        # rendered as raw hex in the report.
        foreach ($code in @('0xC000006D','0xC000006F','0xC0000070','0xC0000224','0xC0000371')) {
            $script:StatusCodes.ContainsKey($code) | Should -BeTrue -Because "$code is documented for event 4776"
        }
    }

    It 'includes the documented Kerberos codes that were previously missing' {
        foreach ($code in @('0xC','0x10','0x19')) {
            $script:StatusCodes.ContainsKey($code) | Should -BeTrue -Because "$code is documented for event 4771"
        }
    }

    It 'describes 0x10 as a certificate/smart-card issue rather than a bad password' {
        # Misreading 0x10 as a credential failure sends the investigator after the wrong
        # cause entirely - it is a PKI problem.
        $script:StatusCodes['0x10'] | Should -Match '(?i)smart.?card|certificate|PADATA'
        $script:StatusCodes['0x10'] | Should -Not -Match '(?i)bad password'
    }
}

Describe 'EventMeaning labels stay outcome-neutral' {
    It 'does not bake "failed" into events that are logged for both outcomes' {
        # 4776/4771/4768 are written for successes too. A label like "failed logon" on
        # these makes healthy machines look guilty in the report.
        foreach ($id in @(4776, 4771, 4768)) {
            $script:EventMeaning[$id] | Should -Not -Match '(?i)fail'
        }
    }

    It 'still labels 4625 as a failed logon, which it always is' {
        $script:EventMeaning[4625] | Should -Match '(?i)fail'
    }
}

Describe 'Get-EventCallerName (per-event source field)' {
    # REGRESSION: the loop used to try TargetDomainName first for EVERY event. It is the
    # caller computer for 4740 only (Learn's sample XML: TargetDomainName=WIN81); for 4768,
    # 4724/4723 and 4625 with a blank WorkstationName it is the account's DOMAIN, which then
    # ranked "CONTOSO" as the top source of failed authentication.
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740

    It '4740: reads the caller computer from TargetDomainName' {
        Get-EventCallerName -EventId 4740 -Data @{ TargetDomainName = 'WIN81' } | Should -Be 'WIN81'
    }
    It '4740: falls back to CallerComputerName when TargetDomainName is blank' {
        Get-EventCallerName -EventId 4740 -Data @{ TargetDomainName = ''; CallerComputerName = 'WIN81' } | Should -Be 'WIN81'
    }
    It '4768: uses the client IpAddress and never the account domain' {
        $d = @{ TargetDomainName = 'CONTOSO'; TargetUserName = 'jdoe'; IpAddress = '::ffff:10.1.2.3' }
        Get-EventCallerName -EventId 4768 -Data $d | Should -Be '::ffff:10.1.2.3'
    }
    It '4771: uses the client IpAddress and never the account domain' {
        Get-EventCallerName -EventId 4771 -Data @{ TargetDomainName = 'CONTOSO'; IpAddress = '10.1.2.3' } | Should -Be '10.1.2.3'
    }
    It '4625: prefers WorkstationName, and falls back to the IP (not the domain) when it is blank' {
        Get-EventCallerName -EventId 4625 -Data @{ TargetDomainName = 'CONTOSO'; WorkstationName = 'LAPTOP-7'; IpAddress = '10.1.2.3' } | Should -Be 'LAPTOP-7'
        Get-EventCallerName -EventId 4625 -Data @{ TargetDomainName = 'CONTOSO'; WorkstationName = '-'; IpAddress = '10.1.2.3' } | Should -Be '10.1.2.3'
        Get-EventCallerName -EventId 4625 -Data @{ TargetDomainName = 'CONTOSO'; WorkstationName = ''; IpAddress = '' } | Should -Be ''
    }
    It '4776: uses Workstation' {
        Get-EventCallerName -EventId 4776 -Data @{ Workstation = 'OLDPHONE'; TargetDomainName = 'CONTOSO' } | Should -Be 'OLDPHONE'
    }
    It '4724 / 4723: have no source-machine field, so the account domain is never reported' {
        Get-EventCallerName -EventId 4724 -Data @{ TargetDomainName = 'CONTOSO'; SubjectDomainName = 'CONTOSO' } | Should -Be ''
        Get-EventCallerName -EventId 4723 -Data @{ TargetDomainName = 'CONTOSO' } | Should -Be ''
    }
}

Describe 'Get-LockoutEvents (parsing end to end)' {
    BeforeAll {
        function New-FakeEvent {
            param([int]$Id, [hashtable]$Data)
            $inner = ($Data.GetEnumerator() | ForEach-Object { "<Data Name=`"$($_.Key)`">$($_.Value)</Data>" }) -join ''
            $xml = "<Event xmlns=`"http://schemas.microsoft.com/win/2004/08/events/event`"><System/><EventData>$inner</EventData></Event>"
            $o = New-Object PSObject -Property @{ Id = $Id; TimeCreated = (Get-Date); Xml = $xml }
            $o | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.Xml } -Force
            $o
        }
    }

    It 'does not rank the account domain as a failure source for 4768 (regression)' {
        Mock Get-WinEvent { New-FakeEvent -Id 4768 -Data @{ TargetUserName = 'jdoe'; TargetDomainName = 'CONTOSO'; IpAddress = '::ffff:10.1.2.3'; Status = '0x18' } }
        $rows = @(Get-LockoutEvents -ComputerName 'DC01' -ForestName 'a.local' -SamAccountName 'jdoe' -StartTime (Get-Date).AddDays(-1))
        $rows.Count | Should -Be 1
        $rows[0].CallerName | Should -Be '::ffff:10.1.2.3'
        $rows[0].CallerName | Should -Not -Be 'CONTOSO'
        $rows[0].Outcome    | Should -Be 'Failure'
    }

    It 'treats a padded 0x00000000 4625 SubStatus as "no sub-status" and keeps Status (regression)' {
        Mock Get-WinEvent { New-FakeEvent -Id 4625 -Data @{ TargetUserName = 'jdoe'; TargetDomainName = 'CONTOSO'; WorkstationName = 'LAPTOP-7'; Status = '0xC0000234'; SubStatus = '0x00000000' } }
        $rows = @(Get-LockoutEvents -ComputerName 'DC01' -ForestName 'a.local' -SamAccountName 'jdoe' -StartTime (Get-Date).AddDays(-1))
        $rows[0].StatusCode | Should -Be '0xC0000234'
        $rows[0].CallerName | Should -Be 'LAPTOP-7'
    }

    It 'still prefers a non-zero 4625 SubStatus' {
        Mock Get-WinEvent { New-FakeEvent -Id 4625 -Data @{ TargetUserName = 'jdoe'; WorkstationName = 'LAPTOP-7'; Status = '0xC000006D'; SubStatus = '0xC000006A' } }
        $rows = @(Get-LockoutEvents -ComputerName 'DC01' -ForestName 'a.local' -SamAccountName 'jdoe' -StartTime (Get-Date).AddDays(-1))
        $rows[0].StatusCode | Should -Be '0xC000006A'
    }

    It 'classifies a 4776 with the padded success code as Success' {
        Mock Get-WinEvent { New-FakeEvent -Id 4776 -Data @{ TargetUserName = 'jdoe'; Workstation = 'PC1'; Status = '0x00000000' } }
        $rows = @(Get-LockoutEvents -ComputerName 'DC01' -ForestName 'a.local' -SamAccountName 'jdoe' -StartTime (Get-Date).AddDays(-1))
        $rows[0].Outcome | Should -Be 'Success'
    }

    It 'describes codes that the old inline table lacked (0xC000005E, 0xC000015B, 0xC0000192, 0xC0000413)' {
        foreach ($code in '0xC000005E', '0xC000015B', '0xC0000192', '0xC0000413') {
            (Get-StatusMeaning -Code $code) | Should -Not -Match '^Unrecognized'
        }
    }
}

Describe 'Test-IsFailureStatus / ConvertFrom-AdFileTime in Forensics' {
    It 'treats every rendering of success as not-a-failure' {
        foreach ($c in '0x0', '0x00000000', '0', '', $null) { Test-IsFailureStatus -Code $c | Should -BeFalse }
        Test-IsFailureStatus -Code '0x18' | Should -BeTrue
    }
    It 'returns $null (never) for 0 and Int64.MaxValue instead of a 1601 date or an exception' {
        ConvertFrom-AdFileTime -Value 0 | Should -BeNullOrEmpty
        ConvertFrom-AdFileTime -Value ([int64]::MaxValue) | Should -BeNullOrEmpty
        ConvertFrom-AdFileTime -Value $null | Should -BeNullOrEmpty
        ConvertFrom-AdFileTime -Value 133000000000000000 | Should -BeOfType ([datetime])
    }
    It 'Invoke-Analysis survives a badPasswordTime of Int64.MaxValue (FromFileTime would throw) - regression' {
        $state = [pscustomobject]@{ Computer = 'DC01'; Forest = 'a.local'; Reachable = $true; Error = ''
                                    BadPwdCount = 0; BadPasswordTime = [int64]::MaxValue; LockoutTime = 0; PwdLastSet = 0 }
        { Invoke-Analysis -Topologies @() -AuditResults @() -LogHealth @() -Accounts @() `
                          -BadPwdStates @($state) -Events @() -RequestedDays 7 -EventsCollected $true } | Should -Not -Throw
    }
}
