BeforeAll {
    . "$PSScriptRoot\..\Watch-ADLockoutActivity.ps1" -LoadFunctionsOnly
}

Describe 'Get-CounterDelta' {
    # badPwdCount is NOT replicated - each DC keeps its own copy - and it RESETS on that
    # DC when the user successfully authenticates there.
    # https://learn.microsoft.com/windows/win32/adschema/a-badpwdcount
    #
    # Both facts make naive subtraction wrong, and the errors are the damaging kind:
    # a reset would read as negative activity, and summing across DCs without tracking
    # them separately would double-count.

    It 'reports the increase when a counter climbs' {
        $prev = @{ 'DC01|jdoe' = 2 }
        $now  = @(
            [PSCustomObject]@{ DC='DC01'; Account='jdoe'; BadPwdCount=5; LockedOut=$false; BadPasswordTime=$null }
        )
        $d = Get-CounterDelta -Previous $prev -Current $now
        $d.Changes[0].Delta   | Should -Be 3
        $d.Changes[0].Account | Should -Be 'jdoe'
        $d.Changes[0].DC      | Should -Be 'DC01'
    }

    It 'treats a counter that dropped as a SUCCESSFUL logon, not negative activity' {
        # The counter resets on successful authentication against that DC. Reporting -4
        # would read as "the problem is fixing itself"; it means the user just got in.
        $prev = @{ 'DC01|jdoe' = 5 }
        $now  = @(
            [PSCustomObject]@{ DC='DC01'; Account='jdoe'; BadPwdCount=1; LockedOut=$false; BadPasswordTime=$null }
        )
        $d = Get-CounterDelta -Previous $prev -Current $now
        $d.Changes[0].Delta     | Should -Be 1
        $d.Changes[0].WasReset  | Should -BeTrue
        $d.Changes[0].Note      | Should -Match 'reset|success'
    }

    It 'counts a first sighting as the full value, not as unchanged' {
        # No previous reading means the whole counter is news. Treating it as zero delta
        # would hide an account that was already at 8 when the watch started.
        $d = Get-CounterDelta -Previous @{} -Current @(
            [PSCustomObject]@{ DC='DC01'; Account='jdoe'; BadPwdCount=8; LockedOut=$false; BadPasswordTime=$null }
        )
        $d.Changes[0].Delta      | Should -Be 8
        $d.Changes[0].FirstSight | Should -BeTrue
    }

    It 'tracks each DC separately because the attribute does not replicate' {
        # The same account climbing on two DCs is two separate counters. Keying only on
        # the account name would make one DC's reading overwrite the other's.
        $prev = @{ 'DC01|jdoe' = 1; 'DC02|jdoe' = 1 }
        $now  = @(
            [PSCustomObject]@{ DC='DC01'; Account='jdoe'; BadPwdCount=3; LockedOut=$false; BadPasswordTime=$null }
            [PSCustomObject]@{ DC='DC02'; Account='jdoe'; BadPwdCount=4; LockedOut=$false; BadPasswordTime=$null }
        )
        $d = Get-CounterDelta -Previous $prev -Current $now
        @($d.Changes).Count | Should -Be 2
        $d.TotalDelta       | Should -Be 5
    }

    It 'reports no changes when nothing moved' {
        $prev = @{ 'DC01|jdoe' = 3 }
        $now  = @([PSCustomObject]@{ DC='DC01'; Account='jdoe'; BadPwdCount=3; LockedOut=$false; BadPasswordTime=$null })
        $d = Get-CounterDelta -Previous $prev -Current $now
        @($d.Changes).Count | Should -Be 0
    }

    It 'raises a lockout as its own event, separate from counter movement' {
        $prev = @{ 'DC01|jdoe' = 9 }
        $now  = @([PSCustomObject]@{ DC='DC01'; Account='jdoe'; BadPwdCount=10; LockedOut=$true; BadPasswordTime=$null })
        $d = Get-CounterDelta -Previous $prev -Current $now
        $d.Lockouts       | Should -Not -BeNullOrEmpty
        $d.Lockouts[0].Account | Should -Be 'jdoe'
    }

    It 'builds a state table keyed by DC and account for the next poll' {
        $now = @(
            [PSCustomObject]@{ DC='DC01'; Account='jdoe';  BadPwdCount=3; LockedOut=$false; BadPasswordTime=$null }
            [PSCustomObject]@{ DC='DC02'; Account='asmith'; BadPwdCount=1; LockedOut=$false; BadPasswordTime=$null }
        )
        $d = Get-CounterDelta -Previous @{} -Current $now
        $d.NewState['DC01|jdoe']   | Should -Be 3
        $d.NewState['DC02|asmith'] | Should -Be 1
    }
}

Describe 'Format-WatchLine' {
    It 'renders a counter increase with the account, DC and delta' {
        $c = [PSCustomObject]@{ Account='jdoe'; DC='DC01'; Delta=3; NewValue=5
                                WasReset=$false; FirstSight=$false; Note='' }
        $line = Format-WatchLine -Change $c -Threshold 10
        $line | Should -Match 'jdoe'
        $line | Should -Match 'DC01'
        $line | Should -Match '\+3'
        $line | Should -Match '5'
    }

    It 'shows how close the account is to the lockout threshold' {
        # The number that matters during a live incident is how many attempts remain.
        $c = [PSCustomObject]@{ Account='jdoe'; DC='DC01'; Delta=1; NewValue=8
                                WasReset=$false; FirstSight=$false; Note='' }
        Format-WatchLine -Change $c -Threshold 10 | Should -Match '8/10'
    }

    It 'annotates a reset so a falling counter is not misread' {
        $c = [PSCustomObject]@{ Account='jdoe'; DC='DC01'; Delta=1; NewValue=1
                                WasReset=$true; FirstSight=$false; Note='counter reset - successful logon' }
        Format-WatchLine -Change $c -Threshold 10 | Should -Match 'reset|success'
    }
}

Describe 'Get-WatchSeverity' {
    # Colour and attention should track how close an account is to locking, not the raw
    # count - 8 of 10 is urgent, 8 of 50 is not.

    It 'treats an account near the threshold as critical' {
        Get-WatchSeverity -NewValue 9 -Threshold 10 -LockedOut $false | Should -Be 'Critical'
    }

    It 'treats a locked account as critical regardless of count' {
        Get-WatchSeverity -NewValue 0 -Threshold 10 -LockedOut $true | Should -Be 'Critical'
    }

    It 'treats the middle of the range as a warning' {
        Get-WatchSeverity -NewValue 5 -Threshold 10 -LockedOut $false | Should -Be 'Warning'
    }

    It 'treats early activity as informational' {
        Get-WatchSeverity -NewValue 1 -Threshold 10 -LockedOut $false | Should -Be 'Info'
    }

    It 'does not divide by zero when lockout is disabled' {
        # Threshold 0 means accounts never lock out. Any severity scaled against it would
        # divide by zero.
        Get-WatchSeverity -NewValue 5 -Threshold 0 -LockedOut $false | Should -Be 'Info'
    }
}

Describe 'Test-WatchInterval' {
    # A tight poll loop against every DC is the one way this tool could hurt a domain
    # controller. The floor is enforced in code, not left to the caller.

    It 'accepts a sensible interval' {
        (Test-WatchInterval -Seconds 30).Allowed | Should -BeTrue
    }

    It 'raises an interval below the floor rather than hammering the DCs' {
        $r = Test-WatchInterval -Seconds 1
        $r.Allowed  | Should -BeFalse
        $r.Adjusted | Should -BeGreaterOrEqual 5
        $r.Message  | Should -Match 'minimum|floor|raised'
    }
}
