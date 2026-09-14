BeforeAll {
    . "$PSScriptRoot\..\Watch-DriveMapActivity.ps1" -LoadFunctionsOnly
}

Describe 'Get-TransitionType' {
    It 'detects a disappearance' {
        Get-TransitionType -Previous $true -Current $false | Should -Be 'Disappeared'
    }
    It 'detects an appearance' {
        Get-TransitionType -Previous $false -Current $true | Should -Be 'Appeared'
    }
    It 'reports no change when the state is stable' {
        Get-TransitionType -Previous $true -Current $true   | Should -Be 'NoChange'
        Get-TransitionType -Previous $false -Current $false | Should -Be 'NoChange'
    }
}

Describe 'Get-DisappearanceTiming' {
    # Timing is what discriminates causes that look identical in a snapshot. A drive that
    # vanishes within minutes of logon implicates a logon script; one that vanishes at a
    # background refresh implicates policy processing. Same symptom, different fix.
    #
    # $logon is set in BeforeAll rather than directly in the Describe body: Pester v5
    # executes a Describe block's own body only during Discovery, and It blocks run later
    # during a separate Run phase that does not inherit Discovery-time variables - a
    # variable assigned directly in Describe reads back as $null inside It. This is a
    # mechanical fix for that Pester v5 behavior; the assertions below are unchanged from
    # the brief.
    BeforeAll {
        $logon = [datetime]'2026-09-14 08:00:00'
    }

    It 'attributes a disappearance within minutes of logon to logon processing' {
        $r = Get-DisappearanceTiming -TransitionTime ([datetime]'2026-09-14 08:02:00') `
                -LogonTime $logon -LastGpRefresh $null
        $r.Pattern | Should -Be 'AtLogon'
        $r.Implication | Should -Match 'logon script|logon'
    }

    It 'attributes a disappearance coinciding with a policy refresh to Group Policy' {
        $r = Get-DisappearanceTiming -TransitionTime ([datetime]'2026-09-14 09:31:00') `
                -LogonTime $logon -LastGpRefresh ([datetime]'2026-09-14 09:30:30')
        $r.Pattern | Should -Be 'AtGroupPolicyRefresh'
    }

    It 'reports unexplained when it matches neither' {
        $r = Get-DisappearanceTiming -TransitionTime ([datetime]'2026-09-14 11:47:00') `
                -LogonTime $logon -LastGpRefresh ([datetime]'2026-09-14 09:30:00')
        $r.Pattern | Should -Be 'Unexplained'
    }

    It 'reports minutes since logon' {
        $r = Get-DisappearanceTiming -TransitionTime ([datetime]'2026-09-14 08:30:00') `
                -LogonTime $logon -LastGpRefresh $null
        $r.MinutesSinceLogon | Should -Be 30
    }

    # An 'Unexplained' pattern is a real finding that narrows the search, not a failure
    # to classify. It must carry an implication the reader can act on.
    It 'gives an actionable implication even when unexplained' {
        $r = Get-DisappearanceTiming -TransitionTime ([datetime]'2026-09-14 11:47:00') `
                -LogonTime $logon -LastGpRefresh ([datetime]'2026-09-14 09:30:00')
        $r.Implication | Should -Not -BeNullOrEmpty
    }
}

Describe 'Format-TimelineEntry' {
    It 'formats with the repository timestamp convention' {
        $line = Format-TimelineEntry -Entry ([PSCustomObject]@{
            Timestamp  = [datetime]'2026-09-14 08:02:15'
            Transition = 'Disappeared'
            DriveLetter = 'X'
            Detail     = 'was \\srv\share'
        })
        $line | Should -Match '^2026-09-14 08:02:15'
        $line | Should -Match 'Disappeared'
        $line | Should -Match 'X'
    }
}
