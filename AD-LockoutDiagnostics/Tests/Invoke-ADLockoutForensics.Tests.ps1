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
