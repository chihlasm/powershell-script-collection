BeforeAll {
    . "$PSScriptRoot\..\Invoke-DriveMapInvestigation.ps1" -LoadFunctionsOnly
}

Describe 'Get-DriveMapVerdict' {
    # Microsoft's documented scenario: every Group Policy event green, GPP trace showing
    # the drive mapped successfully, and the drive still gone - because a logon script in
    # an unrelated GPO deleted it afterwards. A report that stops at CSE success events
    # reports SUCCESS on a broken machine.
    # https://learn.microsoft.com/en-us/troubleshoot/windows-client/group-policy/scenario-guide-gpo-to-map-network-drive-doesn-t-apply-as-expected
    It 'identifies a logon script deleting what Group Policy created' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied        = $true
            DrivePresent      = $false
            ScriptDeletions   = @([PSCustomObject]@{ Source = 'DomainWideSettings'; Line = 'net use x: /delete' })
            InRegistry        = $false
            InLiveMounts      = $false
            TargetingFailures = @()
            Action            = 'Replace'
            FastLogonOptimization  = $false
            AlwaysWaitForNetwork   = $true
            ElevatedVisible   = $true
            UnelevatedVisible = $true
            EnableLinkedConnections = 1
        })
        $v[0].Cause | Should -Match 'script'
        $v[0].Confidence | Should -Be 'High'
        ($v[0].Evidence -join ' ') | Should -Match 'DomainWideSettings'
    }

    It 'identifies the every-other-logon mechanism' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $false; DrivePresent = $false; ScriptDeletions = @()
            InRegistry = $false; InLiveMounts = $false; TargetingFailures = @()
            Action = 'Replace'; FastLogonOptimization = $true; AlwaysWaitForNetwork = $false
            ElevatedVisible = $false; UnelevatedVisible = $false; EnableLinkedConnections = 1
        })
        ($v.Cause -join ' ') | Should -Match 'every other logon'
    }

    It 'identifies a failing reconnect' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $true; DrivePresent = $false; ScriptDeletions = @()
            InRegistry = $true; InLiveMounts = $false; TargetingFailures = @()
            Action = 'Create'; FastLogonOptimization = $false; AlwaysWaitForNetwork = $true
            ElevatedVisible = $false; UnelevatedVisible = $false; EnableLinkedConnections = 1
        })
        ($v.Cause -join ' ') | Should -Match 'reconnect'
    }

    # This is a visibility artifact, NOT a disappearing drive. Reporting it as a Group
    # Policy problem sends the technician to audit a GPO for a drive that was never gone.
    It 'identifies split-token visibility and does not call it a disappearance' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $true; DrivePresent = $true; ScriptDeletions = @()
            InRegistry = $true; InLiveMounts = $true; TargetingFailures = @()
            Action = 'Create'; FastLogonOptimization = $false; AlwaysWaitForNetwork = $true
            ElevatedVisible = $false; UnelevatedVisible = $true; EnableLinkedConnections = 0
        })
        $v[0].Cause | Should -Match 'elevated|visibility'
        ($v[0].Remediation -join ' ') | Should -Match 'EnableLinkedConnections'
    }

    It 'identifies item-level targeting failures' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $false; DrivePresent = $false; ScriptDeletions = @()
            InRegistry = $false; InLiveMounts = $false
            TargetingFailures = @([PSCustomObject]@{ EventId = 4105; Gpo = 'Map-X-Drive' })
            Action = 'Replace'; FastLogonOptimization = $false; AlwaysWaitForNetwork = $true
            ElevatedVisible = $false; UnelevatedVisible = $false; EnableLinkedConnections = 1
        })
        ($v.Cause -join ' ') | Should -Match 'targeting'
    }

    # An unresolved case is a finding with a next step, never a blank page.
    It 'returns an explicit no-cause-identified verdict when nothing matches' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $true; DrivePresent = $true; ScriptDeletions = @()
            InRegistry = $true; InLiveMounts = $true; TargetingFailures = @()
            Action = 'Create'; FastLogonOptimization = $false; AlwaysWaitForNetwork = $true
            ElevatedVisible = $true; UnelevatedVisible = $true; EnableLinkedConnections = 1
        })
        $v | Should -Not -BeNullOrEmpty
        $v[0].Cause | Should -Match 'No cause identified'
        $v[0].Remediation | Should -Not -BeNullOrEmpty
    }

    It 'orders verdicts most-confident first' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $true; DrivePresent = $false
            ScriptDeletions = @([PSCustomObject]@{ Source = 'GPO-A'; Line = 'net use x: /delete' })
            InRegistry = $true; InLiveMounts = $false; TargetingFailures = @()
            Action = 'Replace'; FastLogonOptimization = $true; AlwaysWaitForNetwork = $false
            ElevatedVisible = $false; UnelevatedVisible = $false; EnableLinkedConnections = 1
        })
        $v.Count | Should -BeGreaterThan 1
        $v[0].Confidence | Should -Be 'High'
    }

    # Microsoft explicitly advises against NoBackgroundPolicy=0 and it does not reliably
    # work. It must never appear in a remediation.
    It 'never recommends NoBackgroundPolicy=0 in any verdict' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $false; DrivePresent = $false; ScriptDeletions = @()
            InRegistry = $false; InLiveMounts = $false; TargetingFailures = @()
            Action = 'Replace'; FastLogonOptimization = $true; AlwaysWaitForNetwork = $false
            ElevatedVisible = $false; UnelevatedVisible = $false; EnableLinkedConnections = 1
        })
        ($v.Remediation -join ' ') | Should -Not -Match 'NoBackgroundPolicy'
    }
}

Describe 'ConvertFrom-EvidenceBundle' {
    # This is the single most important property in the whole toolkit: a collector that
    # came back CouldNotCollect must never flatten into $false. "We could not look" and "we
    # looked and it was false" lead to opposite conclusions - collapsing them here would
    # silently reintroduce the exact failure the three-state contract in
    # Export-DriveMapEvidence.ps1 exists to prevent, one layer downstream of that script's
    # own tests.
    It 'flattens a CouldNotCollect collector to $null, never to $false' {
        $results = @{
            PersistentMounts             = [PSCustomObject]@{ State = 'CouldNotCollect'; Data = $null; Reason = 'Access denied' }
            LiveMounts_CurrentContext    = [PSCustomObject]@{ State = 'CouldNotCollect'; Data = $null; Reason = 'Remoting unavailable' }
            LiveMounts_OtherTokenContext = [PSCustomObject]@{ State = 'CouldNotCollect'; Data = $null; Reason = 'Not elevated' }
            GppEvents                    = [PSCustomObject]@{ State = 'CouldNotCollect'; Data = $null; Reason = 'Logging disabled' }
            LogonScriptReferences        = [PSCustomObject]@{ State = 'CouldNotCollect'; Data = $null; Reason = 'SYSVOL unreachable' }
        }
        $flat = ConvertFrom-EvidenceBundle -DriveLetter 'X' -Results $results

        $flat.InRegistry         | Should -BeNullOrEmpty
        $flat.InRegistry         | Should -Not -Be $false
        $flat.DrivePresent       | Should -BeNullOrEmpty
        $flat.DrivePresent       | Should -Not -Be $false
        $flat.InLiveMounts       | Should -Not -Be $false
        $flat.GppApplied         | Should -BeNullOrEmpty
        $flat.GppApplied         | Should -Not -Be $false
        $flat.ScriptDeletions    | Should -BeNullOrEmpty
        $flat.TargetingFailures  | Should -BeNullOrEmpty
    }

    It 'flattens a confirmed-empty (EmptyButValid) collector to $false / an empty array, distinct from CouldNotCollect' {
        $results = @{
            PersistentMounts             = [PSCustomObject]@{ State = 'EmptyButValid'; Data = @(); Reason = $null }
            LiveMounts_CurrentContext    = [PSCustomObject]@{ State = 'EmptyButValid'; Data = @(); Reason = $null }
            LiveMounts_OtherTokenContext = [PSCustomObject]@{ State = 'CouldNotCollect'; Data = $null; Reason = 'Not elevated' }
            GppEvents                    = [PSCustomObject]@{ State = 'EmptyButValid'; Data = @(); Reason = $null }
            LogonScriptReferences        = [PSCustomObject]@{ State = 'EmptyButValid'; Data = @(); Reason = $null }
        }
        $flat = ConvertFrom-EvidenceBundle -DriveLetter 'X' -Results $results

        $flat.InRegistry   | Should -Be $false
        $flat.DrivePresent | Should -Be $false
        $flat.GppApplied   | Should -Be $false
        @($flat.ScriptDeletions).Count   | Should -Be 0
        @($flat.TargetingFailures).Count | Should -Be 0
    }
}

Describe 'Resolve-CompanionScript' {
    It 'returns null when the companion is absent' {
        Resolve-CompanionScript -FileName 'Nope-DoesNotExist.ps1' -ScriptRoot $TestDrive | Should -BeNullOrEmpty
    }

    It 'finds a companion sitting beside the script' {
        New-Item -Path (Join-Path $TestDrive 'Audit-GPDriveMaps.ps1') -ItemType File -Force | Out-Null
        Resolve-CompanionScript -FileName 'Audit-GPDriveMaps.ps1' -ScriptRoot $TestDrive | Should -Not -BeNullOrEmpty
    }
}

Describe 'New-CaseSummary' {
    It 'names the top verdict in the summary text' {
        $summary = New-CaseSummary -DriveLetter 'X' -Identity 'jsmith' `
            -Verdicts @([PSCustomObject]@{
                Cause = 'A logon script deletes the drive after Group Policy maps it'
                Confidence = 'High'; Evidence = @('GPO: DomainWideSettings'); Remediation = @('Remove the script')
            }) `
            -Steps @() -CaseFolder 'C:\Cases\X' -GeneratedOn '2026-09-14 10:00:00'
        $summary | Should -Match 'logon script'
        $summary | Should -Match 'jsmith'
        $summary | Should -Match 'X'
    }

    It 'states plainly when a step could not run' {
        $summary = New-CaseSummary -DriveLetter 'X' -Identity 'jsmith' -Verdicts @() `
            -Steps @([PSCustomObject]@{ Step = 'Domain drive maps'; Ran = $false; Error = 'Script not found' }) `
            -CaseFolder 'C:\Cases\X' -GeneratedOn '2026-09-14 10:00:00'
        $summary | Should -Match 'Script not found'
    }
}
