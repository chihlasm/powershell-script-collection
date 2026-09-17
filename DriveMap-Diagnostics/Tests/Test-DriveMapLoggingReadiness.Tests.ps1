BeforeAll {
    . "$PSScriptRoot\..\Test-DriveMapLoggingReadiness.ps1" -LoadFunctionsOnly
}

Describe 'New-CollectionResult' {
    # The distinction this toolkit exists to preserve: "looked and found nothing" and
    # "could not look" produce identical empty data but opposite conclusions.
    It 'distinguishes EmptyButValid from CouldNotCollect' {
        $empty  = New-CollectionResult -State 'EmptyButValid' -Data @()
        $failed = New-CollectionResult -State 'CouldNotCollect' -Reason 'Access denied'

        $empty.State  | Should -Be 'EmptyButValid'
        $failed.State | Should -Be 'CouldNotCollect'
        $failed.Reason | Should -Be 'Access denied'
    }

    It 'rejects a state outside the three permitted values' {
        { New-CollectionResult -State 'Maybe' -Data @() } | Should -Throw
    }

    It 'requires a reason when it could not collect' {
        { New-CollectionResult -State 'CouldNotCollect' } | Should -Throw
    }
}

Describe 'Test-BlindCondition' {
    It 'reports blind when GPP logging is disabled' {
        $r = Test-BlindCondition -GppLoggingEnabled $false -TracingEnabled $false `
                -OldestEventAge ([timespan]::FromDays(30)) -FaultAge ([timespan]::FromHours(2))
        $r.IsBlind | Should -BeTrue
        ($r.BlindReasons -join ' ') | Should -Match 'logging'
    }

    # A log that only reaches back 6 hours cannot evidence a fault from yesterday. The
    # query returns empty and looks exactly like a clean machine.
    It 'reports blind when the log does not reach back to the fault' {
        $r = Test-BlindCondition -GppLoggingEnabled $true -TracingEnabled $true `
                -OldestEventAge ([timespan]::FromHours(6)) -FaultAge ([timespan]::FromHours(48))
        $r.IsBlind | Should -BeTrue
        ($r.BlindReasons -join ' ') | Should -Match 'retention|reach back'
    }

    It 'is not blind when logging is on and the log covers the fault' {
        $r = Test-BlindCondition -GppLoggingEnabled $true -TracingEnabled $true `
                -OldestEventAge ([timespan]::FromDays(14)) -FaultAge ([timespan]::FromHours(6))
        $r.IsBlind | Should -BeFalse
        $r.BlindReasons | Should -BeNullOrEmpty
    }

    It 'names every blind condition, not just the first' {
        $r = Test-BlindCondition -GppLoggingEnabled $false -TracingEnabled $false `
                -OldestEventAge ([timespan]::FromHours(1)) -FaultAge ([timespan]::FromDays(3))
        $r.BlindReasons.Count | Should -BeGreaterThan 1
    }
}

Describe 'Get-EveryOtherLogonRisk (verified against Microsoft Learn)' {
    # The Drive Maps CSE has NoBackgroundPolicy=1 and only applies items when Group
    # Policy runs synchronously. With Fast Logon Optimization on (the client default),
    # logon is asynchronous, so Replace-mode maps apply every OTHER logon. This presents
    # exactly as "the drive keeps disappearing" with no configuration change.
    # https://learn.microsoft.com/en-us/archive/technet-wiki/12221.group-policy-troubleshooting-drive-maps-preference-extension-replace-mode-only-maps-the-drive-every-other-logon

    It 'flags Replace + Fast Logon Optimization without always-wait as at risk' {
        $r = Get-EveryOtherLogonRisk -Action 'Replace' -FastLogonOptimization $true -AlwaysWaitForNetwork $false
        $r.AtRisk | Should -BeTrue
    }

    It 'clears the risk when always-wait-for-network is enabled' {
        $r = Get-EveryOtherLogonRisk -Action 'Replace' -FastLogonOptimization $true -AlwaysWaitForNetwork $true
        $r.AtRisk | Should -BeFalse
    }

    It 'recommends always-wait and Create+Reconnect' {
        $r = Get-EveryOtherLogonRisk -Action 'Replace' -FastLogonOptimization $true -AlwaysWaitForNetwork $false
        ($r.Remediations -join ' ') | Should -Match 'wait for the network'
        ($r.Remediations -join ' ') | Should -Match 'Reconnect'
    }

    # Microsoft explicitly advises against setting NoBackgroundPolicy=0, and notes it
    # does not reliably work. The toolkit must never suggest it.
    It 'never recommends setting NoBackgroundPolicy to 0' {
        $r = Get-EveryOtherLogonRisk -Action 'Replace' -FastLogonOptimization $true -AlwaysWaitForNetwork $false
        ($r.Remediations -join ' ') | Should -Not -Match 'NoBackgroundPolicy'
    }
}

Describe 'Get-SplitTokenRisk (verified against Microsoft Learn)' {
    # With UAC on, logon creates two linked sessions; drive mappings are per-session
    # symbolic links. A drive "missing" only when elevated was never missing - it is a
    # visibility artifact, and diagnosing it as a GPO problem wastes the investigation.
    # https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command

    It 'flags risk when EnableLinkedConnections is absent' {
        (Get-SplitTokenRisk -EnableLinkedConnections $null -UacPromptsForCredentials $false).AtRisk | Should -BeTrue
    }

    It 'flags risk when EnableLinkedConnections is 0' {
        (Get-SplitTokenRisk -EnableLinkedConnections 0 -UacPromptsForCredentials $false).AtRisk | Should -BeTrue
    }

    It 'clears the risk when EnableLinkedConnections is 1' {
        (Get-SplitTokenRisk -EnableLinkedConnections 1 -UacPromptsForCredentials $false).AtRisk | Should -BeFalse
    }

    # Documented caveat: with UAC set to prompt for credentials a THIRD session is
    # created, and previously created symbolic links are unavailable in it - so
    # EnableLinkedConnections=1 does not fully resolve that configuration.
    It 'still warns when UAC prompts for credentials even with the value set' {
        $r = Get-SplitTokenRisk -EnableLinkedConnections 1 -UacPromptsForCredentials $true
        $r.Explanation | Should -Match 'prompt'
    }
}

Describe 'Test-TraceEvidenceCoversFault' {
    # Trace-file existence alone is not evidence tracing is CURRENTLY on. A trace file
    # left over from six months ago must not corroborate tracing for a fault that
    # happened yesterday - the same "does the evidence reach back to the fault?"
    # reasoning already applied to Application log retention must apply here too.
    It 'does not treat a stale trace file as covering a more recent fault' {
        $covers = Test-TraceEvidenceCoversFault -TraceAge ([timespan]::FromDays(180)) -FaultAge ([timespan]::FromHours(24))
        $covers | Should -BeFalse
    }

    It 'treats a trace file newer than the fault as covering it' {
        $covers = Test-TraceEvidenceCoversFault -TraceAge ([timespan]::FromHours(1)) -FaultAge ([timespan]::FromHours(24))
        $covers | Should -BeTrue
    }
}
