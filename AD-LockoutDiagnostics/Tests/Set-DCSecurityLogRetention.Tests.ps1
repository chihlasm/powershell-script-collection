BeforeAll {
    . "$PSScriptRoot\..\Set-DCSecurityLogRetention.ps1" -LoadFunctionsOnly
}

Describe 'Get-RequiredLogSize' {
    It 'scales the current daily rate up to the target window with headroom' {
        # 128 MB consumed over 4 days = 32 MB/day. 60 days * 1.25 headroom = 2400 MB.
        $r = Get-RequiredLogSize -CurrentSizeBytes (128MB) -CurrentDays 4 -TargetDays 60 -MaxSizeGB 8
        $r.Calculable | Should -BeTrue
        [math]::Round($r.BytesPerDay / 1MB, 0) | Should -Be 32
        $r.RequiredMB | Should -Be 2400
    }

    It 'rounds the required size up to a 64 KB boundary' {
        # Windows requires the Security log maximum to be a multiple of 64 KB.
        $r = Get-RequiredLogSize -CurrentSizeBytes 12345678 -CurrentDays 3.3 -TargetDays 45 -MaxSizeGB 8
        ($r.RequiredBytes % 64KB) | Should -Be 0
    }

    It 'never exceeds the documented 4194240 KB maximum, even at -MaxSizeGB 4' {
        # A literal 4 GB is 4194304 KB - 64 KB ABOVE the documented range, so Windows
        # would reject it. The ceiling must be the documented value, not a round 4 GB.
        # https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2003/cc778402(v=ws.10)
        $r = Get-RequiredLogSize -CurrentSizeBytes (500MB) -CurrentDays 1 -TargetDays 365 -MaxSizeGB 4
        $r.RequiredBytes | Should -BeLessOrEqual 4194240KB
        ($r.RequiredBytes % 64KB) | Should -Be 0
    }

    It 'caps an over-large -MaxSizeGB request at the documented maximum' {
        $r = Get-RequiredLogSize -CurrentSizeBytes (500MB) -CurrentDays 1 -TargetDays 365 -MaxSizeGB 16
        $r.RequiredBytes | Should -BeLessOrEqual 4194240KB
    }

    It 'never returns a size below the documented 1 MB minimum' {
        $r = Get-RequiredLogSize -CurrentSizeBytes 1KB -CurrentDays 30 -TargetDays 1
        $r.RequiredBytes | Should -BeGreaterOrEqual 1MB
    }

    It 'clamps to the MaxSizeGB ceiling and says so' {
        # 500 MB/day * 365 days would be ~223 GB; must clamp to the 4 GB ceiling.
        $r = Get-RequiredLogSize -CurrentSizeBytes (500MB) -CurrentDays 1 -TargetDays 365 -MaxSizeGB 4
        $r.ClampedToMax | Should -BeTrue
        $r.RequiredBytes | Should -BeLessOrEqual (4GB)
        $r.Note | Should -Match 'exceeds'
    }

    It 'refuses to estimate from a window too short to be meaningful' {
        $r = Get-RequiredLogSize -CurrentSizeBytes (100MB) -CurrentDays 0.05 -TargetDays 60
        $r.Calculable | Should -BeFalse
        $r.Note       | Should -Match 'too short'
    }

    It 'does not divide by zero when the log has no history' {
        { Get-RequiredLogSize -CurrentSizeBytes (100MB) -CurrentDays 0 -TargetDays 60 } | Should -Not -Throw
        (Get-RequiredLogSize -CurrentSizeBytes (100MB) -CurrentDays 0 -TargetDays 60).Calculable | Should -BeFalse
    }

    It 'handles a zero-byte log without throwing' {
        $r = Get-RequiredLogSize -CurrentSizeBytes 0 -CurrentDays 5 -TargetDays 60
        $r.Calculable | Should -BeFalse
        $r.Note       | Should -Match 'zero'
    }

    It 'scales linearly with the target window' {
        $a = Get-RequiredLogSize -CurrentSizeBytes (64MB) -CurrentDays 4 -TargetDays 30 -MaxSizeGB 16
        $b = Get-RequiredLogSize -CurrentSizeBytes (64MB) -CurrentDays 4 -TargetDays 60 -MaxSizeGB 16
        # Doubling the window should roughly double the requirement (within 64 KB rounding).
        [math]::Abs(($b.RequiredBytes / $a.RequiredBytes) - 2) | Should -BeLessThan 0.01
    }

    It "reproduces the user's real-world case: 4.6 days retained, 60 wanted" {
        # A DC holding 4.6 days in a 128 MB log needs roughly 2 GB for 60 days.
        $r = Get-RequiredLogSize -CurrentSizeBytes (128MB) -CurrentDays 4.6 -TargetDays 60 -MaxSizeGB 8
        $r.Calculable | Should -BeTrue
        $r.RequiredMB | Should -BeGreaterThan 1500
        $r.RequiredMB | Should -BeLessThan 2500
    }
}
