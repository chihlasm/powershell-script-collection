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

    # CRITICAL REGRESSION COVERAGE: @($null) is a ONE-element array in PowerShell
    # ('@($null).Count' is 1, not 0), so a rule that wraps a $null (unestablished) property
    # in @() before counting would treat "we could not look" identically to "we found
    # something" - fabricating a confident verdict from a collector that never ran. These
    # five tests exercise exactly the input space the original 12 tests never touched: every
    # property genuinely $null, and EnableLinkedConnections left unset.
    It 'returns exactly No cause identified when every evidence property is $null' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $null; DrivePresent = $null; ScriptDeletions = $null
            InRegistry = $null; InLiveMounts = $null; TargetingFailures = $null
            Action = $null; FastLogonOptimization = $null; AlwaysWaitForNetwork = $null
            ElevatedVisible = $null; UnelevatedVisible = $null; EnableLinkedConnections = $null
        })
        $v.Count | Should -Be 1
        $v[0].Cause | Should -Match 'No cause identified'
    }

    It 'does not fabricate a logon-script verdict when DrivePresent is $false but ScriptDeletions was never collected' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $null; DrivePresent = $false; ScriptDeletions = $null
            InRegistry = $null; InLiveMounts = $null; TargetingFailures = $null
            Action = $null; FastLogonOptimization = $null; AlwaysWaitForNetwork = $null
            ElevatedVisible = $null; UnelevatedVisible = $null; EnableLinkedConnections = $null
        })
        ($v.Cause -join ' ') | Should -Not -Match 'logon script'
    }

    It 'does not fire the split-token rule when EnableLinkedConnections was never read' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $null; DrivePresent = $null; ScriptDeletions = $null
            InRegistry = $null; InLiveMounts = $null; TargetingFailures = $null
            Action = $null; FastLogonOptimization = $null; AlwaysWaitForNetwork = $null
            ElevatedVisible = $false; UnelevatedVisible = $true; EnableLinkedConnections = $null
        })
        ($v.Cause -join ' ') | Should -Not -Match 'elevated|visibility'
    }

    It 'still fires the split-token rule when EnableLinkedConnections is a CONFIRMED 0 (proving the fix did not over-correct)' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $null; DrivePresent = $null; ScriptDeletions = $null
            InRegistry = $null; InLiveMounts = $null; TargetingFailures = $null
            Action = $null; FastLogonOptimization = $null; AlwaysWaitForNetwork = $null
            ElevatedVisible = $false; UnelevatedVisible = $true; EnableLinkedConnections = 0
        })
        ($v.Cause -join ' ') | Should -Match 'elevated|visibility'
    }

    It 'distinguishes a genuinely empty ScriptDeletions array from $null (no false verdict, no crash)' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $null; DrivePresent = $false; ScriptDeletions = @()
            InRegistry = $null; InLiveMounts = $null; TargetingFailures = $null
            Action = $null; FastLogonOptimization = $null; AlwaysWaitForNetwork = $null
            ElevatedVisible = $null; UnelevatedVisible = $null; EnableLinkedConnections = $null
        })
        ($v.Cause -join ' ') | Should -Not -Match 'logon script'
        $v.Count | Should -BeGreaterOrEqual 1
    }

    # ---------------------------------------------------------------------------------
    # Windows PowerShell 5.1 one-element array unwrapping (these scripts declare
    # #Requires -Version 5.1, so 5.1 is the contract - PS 7 is not).
    #
    # Assigning the result of an `if` EXPRESSION that yields a ONE-element array unwraps it
    # to the bare element on 5.1. PS 7 unifies `.Count` across scalars and arrays, so the bug
    # is completely invisible there: these exact cases passed on 7 while the rule silently
    # never fired on 5.1, turning a found deletion command into "no cause identified" - a
    # suppressed true positive presented as a clean result, with the 'net use X: /d' line
    # still visible in the report's own evidence tab.
    #
    # ONE element is the entire bug: zero-element stays empty and two-or-more stays an array,
    # so only the single-item case regresses - and one deleting logon script is both the most
    # common real-world shape and Microsoft's own documented scenario for this problem.
    # https://learn.microsoft.com/en-us/troubleshoot/windows-client/group-policy/scenario-guide-gpo-to-map-network-drive-doesn-t-apply-as-expected
    #
    # These must pass on BOTH runtimes; on 5.1 they fail without the [object[]] casts in
    # Get-DriveMapVerdict and the `return ,$ordered` array-wrap on its output.
    # ---------------------------------------------------------------------------------
    It 'fires the logon-script rule when ScriptDeletions holds EXACTLY ONE element (PS 5.1 array unwrapping)' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied        = $true
            DrivePresent      = $false
            ScriptDeletions   = @([PSCustomObject]@{ Source = 'GPO-A'; Line = 'net use X: /d' })
            InRegistry        = $null; InLiveMounts = $null; TargetingFailures = $null
            Action            = $null; FastLogonOptimization = $null; AlwaysWaitForNetwork = $null
            ElevatedVisible   = $null; UnelevatedVisible = $null; EnableLinkedConnections = $null
        })
        ($v.Cause -join ' ') | Should -Match 'logon script'
        ($v.Cause -join ' ') | Should -Match 'GPO-A'
        $v[0].Confidence | Should -Be 'High'
        # The Low "no cause identified" fallback must NOT be the headline when a real cause
        # was found - that is the exact user-visible symptom of the 5.1 regression.
        $v[0].Cause | Should -Not -Match 'No cause identified'
    }

    It 'fires the targeting rule when TargetingFailures holds EXACTLY ONE element (PS 5.1 array unwrapping)' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied        = $null; DrivePresent = $null; ScriptDeletions = $null
            InRegistry        = $null; InLiveMounts = $null
            TargetingFailures = @([PSCustomObject]@{ EventId = 8194; Gpo = 'GPO-B' })
            Action            = $null; FastLogonOptimization = $null; AlwaysWaitForNetwork = $null
            ElevatedVisible   = $null; UnelevatedVisible = $null; EnableLinkedConnections = $null
        })
        ($v.Cause -join ' ') | Should -Match 'targeting'
        ($v.Cause -join ' ') | Should -Not -Match '^No cause identified'
    }

    It 'renders the drive letter in remediation text instead of a bare colon' {
        # Regression: the rules referenced a bare $DriveLetter that was never a parameter of
        # this function. Under PowerShell's dynamic scoping it resolved to the script-level
        # -DriveLetter during a real run, but to nothing when the function was called in
        # isolation - emitting user-facing remediation reading "a drive-delete command for :."
        # with the letter silently missing. The letter is the single most load-bearing piece
        # of context in the whole report, so an empty one is a real defect, not cosmetic.
        $v = Get-DriveMapVerdict -DriveLetter 'X' -Evidence ([PSCustomObject]@{
            GppApplied        = $true
            DrivePresent      = $false
            ScriptDeletions   = @([PSCustomObject]@{ Source = 'GPO-A'; Line = 'net use X: /d' })
            InRegistry        = $null; InLiveMounts = $null; TargetingFailures = $null
            Action            = $null; FastLogonOptimization = $null; AlwaysWaitForNetwork = $null
            ElevatedVisible   = $null; UnelevatedVisible = $null; EnableLinkedConnections = $null
        })
        $remediation = @($v[0].Remediation) -join ' '
        $remediation | Should -Match 'X:'
        $remediation | Should -Not -Match 'command for :'
    }

    It 'normalizes a drive letter supplied as "x:" so verdict text never shows "X::"' {
        $v = Get-DriveMapVerdict -DriveLetter 'x:' -Evidence ([PSCustomObject]@{
            GppApplied        = $null; DrivePresent = $false
            ScriptDeletions   = @([PSCustomObject]@{ Source = 'GPO-A'; Line = 'net use X: /d' })
            InRegistry        = $null; InLiveMounts = $null; TargetingFailures = $null
            Action            = $null; FastLogonOptimization = $null; AlwaysWaitForNetwork = $null
            ElevatedVisible   = $null; UnelevatedVisible = $null; EnableLinkedConnections = $null
        })
        $remediation = @($v[0].Remediation) -join ' '
        $remediation | Should -Match 'X:'
        $remediation | Should -Not -Match 'X::'
    }

    It 'returns an array shape even for a single verdict, so .Count and indexing work on PS 5.1' {
        # Get-DriveMapVerdict is documented to ALWAYS return at least one verdict, so the
        # one-element return is the COMMON path. A bare `return $ordered` unwraps it on 5.1
        # and every caller that counts or indexes the result breaks while passing on 7.
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $null; DrivePresent = $null; ScriptDeletions = $null
            InRegistry = $null; InLiveMounts = $null; TargetingFailures = $null
            Action = $null; FastLogonOptimization = $null; AlwaysWaitForNetwork = $null
            ElevatedVisible = $null; UnelevatedVisible = $null; EnableLinkedConnections = $null
        })
        $v.Count | Should -Be 1
        ,$v | Should -BeOfType [System.Object[]]
        $v[0].Cause | Should -Match 'No cause identified'
    }
}

Describe 'ConvertFrom-EvidenceManifest' {
    # The reconstruction step that rebuilds the in-memory Results hashtable from a persisted
    # bundle is where the toolkit's three-state guarantee is easiest to lose: a collector the
    # manifest calls Found, whose rows cannot actually be read back, must degrade to
    # CouldNotCollect. Handing ConvertFrom-EvidenceBundle an empty Data array instead makes
    # Test-LetterPresent return a confident $false about data that was never persisted -
    # "I could not look" reported as "I looked and found nothing", fed to the verdict rules
    # as a real negative.
    It 'treats a Found collector with NO data file as CouldNotCollect, never as empty data' {
        # LiveMounts_OtherTokenContext is the only one of the 15 collectors with no CSV
        # export. Latent today (every branch of that collector returns CouldNotCollect) but
        # live the moment the other-token read is implemented.
        $manifest = [PSCustomObject]@{
            Collected = @('LiveMounts_OtherTokenContext')
            Empty     = @()
            Failed    = @()
        }
        $r = ConvertFrom-EvidenceManifest -Manifest $manifest -BundleFolder $TestDrive
        $r['LiveMounts_OtherTokenContext'].State | Should -Be 'CouldNotCollect'
        $r['LiveMounts_OtherTokenContext'].Reason | Should -Match 'no data file|cannot be read back'
    }

    It 'does not let a Found-but-unreadable collector fabricate a $false presence reading' {
        # The end-to-end property that actually matters: the fabricated-empty path must not
        # reach the flattened evidence as a confident $false.
        $manifest = [PSCustomObject]@{
            Collected = @('LiveMounts_OtherTokenContext')
            Empty     = @()
            Failed    = @()
        }
        $r = ConvertFrom-EvidenceManifest -Manifest $manifest -BundleFolder $TestDrive
        $flat = ConvertFrom-EvidenceBundle -DriveLetter 'X' -Results $r
        # Both UAC-context properties derive from the two live-mount collectors; with the
        # other context unreadable they must stay "not established", not become $false.
        $flat.UnelevatedVisible | Should -BeNullOrEmpty
        $flat.UnelevatedVisible | Should -Not -Be $false
    }

    It 'treats a Found collector whose CSV is missing from the bundle as CouldNotCollect' {
        $manifest = [PSCustomObject]@{
            Collected = @('PersistentMounts')
            Empty     = @()
            Failed    = @()
        }
        $r = ConvertFrom-EvidenceManifest -Manifest $manifest -BundleFolder $TestDrive
        $r['PersistentMounts'].State | Should -Be 'CouldNotCollect'
        $r['PersistentMounts'].Reason | Should -Match 'missing from the bundle'
    }

    It 'still reads a Found collector whose CSV IS present (proving the fix did not over-correct)' {
        $csv = Join-Path $TestDrive 'PersistentMounts.csv'
        [PSCustomObject]@{ DriveLetter = 'X'; RemotePath = '\\srv\share' } |
            Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
        $manifest = [PSCustomObject]@{
            Collected = @('PersistentMounts')
            Empty     = @()
            Failed    = @()
        }
        $r = ConvertFrom-EvidenceManifest -Manifest $manifest -BundleFolder $TestDrive
        $r['PersistentMounts'].State | Should -Be 'Found'
        @($r['PersistentMounts'].Data).Count | Should -Be 1
        $r['PersistentMounts'].Reason | Should -BeNullOrEmpty
    }

    It 'preserves EmptyButValid as a genuine confirmed-empty reading, distinct from CouldNotCollect' {
        $manifest = [PSCustomObject]@{
            Collected = @()
            Empty     = @('PersistentMounts')
            Failed    = @()
        }
        $r = ConvertFrom-EvidenceManifest -Manifest $manifest -BundleFolder $TestDrive
        $r['PersistentMounts'].State | Should -Be 'EmptyButValid'
    }

    It 'carries the manifest Failed reason through for a genuinely failed collector' {
        $manifest = [PSCustomObject]@{
            Collected = @()
            Empty     = @()
            Failed    = @([PSCustomObject]@{ Collector = 'GppEvents'; Reason = 'Access denied reading the event log.' })
        }
        $r = ConvertFrom-EvidenceManifest -Manifest $manifest -BundleFolder $TestDrive
        $r['GppEvents'].State | Should -Be 'CouldNotCollect'
        $r['GppEvents'].Reason | Should -Be 'Access denied reading the event log.'
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

    # Test-DriveMapLoggingReadiness.ps1 writes a machine-readable JSON companion alongside
    # its .txt report, carrying FastLogonOptimization / AlwaysWaitForNetwork /
    # EnableLinkedConnections as three-state records so the every-other-logon and
    # split-token verdict rules - the toolkit's two highest-value, most-documented
    # conclusions - can actually fire on a real run instead of always seeing $null.
    It 'populates FastLogonOptimization, AlwaysWaitForNetwork and EnableLinkedConnections from a readiness JSON fixture' {
        $readinessFixture = @{
            EnableLinkedConnections = @{ State = 'Found'; Value = 1; Reason = $null }
            FastLogonOptimization   = @{ State = 'Found'; Value = $true; Reason = $null }
            AlwaysWaitForNetwork    = @{ State = 'Found'; Value = $false; Reason = $null }
            NoBackgroundPolicy      = @{ State = 'Found'; Value = 1; Reason = $null }
            GppLoggingEnabled       = @{ State = 'CouldNotCollect'; Value = $null; Reason = 'Not documented by Microsoft' }
            TracingEnabled          = @{ State = 'Found'; Value = $false; Reason = 'Corroborating evidence only' }
            BlindCondition          = @{ IsBlind = $true; BlindReasons = @('Logging disabled') }
        }
        $jsonPath = Join-Path $TestDrive 'readiness.json'
        ($readinessFixture | ConvertTo-Json -Depth 6) | Set-Content -Path $jsonPath -Encoding UTF8

        $flat = ConvertFrom-EvidenceBundle -DriveLetter 'X' -Results @{} -ReadinessJsonPath $jsonPath

        $flat.EnableLinkedConnections | Should -Be 1
        $flat.FastLogonOptimization   | Should -Be $true
        $flat.AlwaysWaitForNetwork    | Should -Be $false
    }

    # THE CRITICAL CASE: a CouldNotCollect entry in the readiness JSON must become $null,
    # never $false. A gate that could not determine EnableLinkedConnections (for example, a
    # remote registry read denied) must not be silently read downstream as "confirmed not
    # set to 1" - that would fabricate a split-token finding the gate never actually made.
    It 'maps a CouldNotCollect entry in the readiness JSON to $null, not $false' {
        $readinessFixture = @{
            EnableLinkedConnections = @{ State = 'CouldNotCollect'; Value = $null; Reason = 'Access denied' }
            FastLogonOptimization   = @{ State = 'CouldNotCollect'; Value = $null; Reason = 'Not documented by Microsoft' }
            AlwaysWaitForNetwork    = @{ State = 'CouldNotCollect'; Value = $null; Reason = 'Not documented by Microsoft' }
        }
        $jsonPath = Join-Path $TestDrive 'readiness-blind.json'
        ($readinessFixture | ConvertTo-Json -Depth 6) | Set-Content -Path $jsonPath -Encoding UTF8

        $flat = ConvertFrom-EvidenceBundle -DriveLetter 'X' -Results @{} -ReadinessJsonPath $jsonPath

        $flat.EnableLinkedConnections | Should -BeNullOrEmpty
        $flat.EnableLinkedConnections | Should -Not -Be $false
        $flat.FastLogonOptimization   | Should -BeNullOrEmpty
        $flat.FastLogonOptimization   | Should -Not -Be $false
        $flat.AlwaysWaitForNetwork    | Should -BeNullOrEmpty
        $flat.AlwaysWaitForNetwork    | Should -Not -Be $false
    }

    It 'still returns a valid evidence object with $null properties when no readiness JSON is supplied' {
        $flat = ConvertFrom-EvidenceBundle -DriveLetter 'X' -Results @{}

        $flat.EnableLinkedConnections | Should -BeNullOrEmpty
        $flat.FastLogonOptimization   | Should -BeNullOrEmpty
        $flat.AlwaysWaitForNetwork    | Should -BeNullOrEmpty
        $flat.Action                  | Should -BeNullOrEmpty
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

Describe 'Verdicts.json serialization' {
    # Invoke-DriveMapInvestigation.ps1's orchestration writes Get-DriveMapVerdict's output as
    # Verdicts.json via 'ConvertTo-Json -InputObject @($verdicts) -Depth 6', which
    # New-DriveMapCaseReport.ps1 (Task 6) reads back to render the investigation's
    # conclusions. This exercises that EXACT serialization call against real verdict output,
    # including a verdict whose Evidence/Remediation arrays have multiple elements - a
    # single-element array is the one shape PowerShell's JSON conversion is known to degrade
    # to a bare scalar under some call patterns, so it must be proven NOT to happen here.
    It 'round-trips Cause, Confidence, Evidence and Remediation through ConvertTo-Json/ConvertFrom-Json intact' {
        $verdicts = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
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

        $verdicts.Count | Should -BeGreaterThan 0
        # The top-level verdict's Remediation array has 2 elements (see Rule 1) - confirm the
        # fixture actually exercises a multi-element array before trusting the round-trip.
        @($verdicts[0].Remediation).Count | Should -BeGreaterThan 1

        $json = ConvertTo-Json -InputObject @($verdicts) -Depth 6
        # Assign first, THEN wrap - mirroring New-DriveMapCaseReport.ps1's reader. Windows
        # PowerShell 5.1 emits a converted JSON array as a single pipeline object instead of
        # enumerating it, so '@($json | ConvertFrom-Json)' would produce a one-element array
        # containing the array, and $roundTripped[0].Cause would be empty. PowerShell 7
        # enumerates and hides the difference entirely. -NoEnumerate is the documented fix
        # but is PowerShell 6+ only, and these scripts declare #Requires -Version 5.1.
        # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertfrom-json
        $parsed = $json | ConvertFrom-Json
        $roundTripped = @($parsed)

        $roundTripped | Should -Not -BeNullOrEmpty
        $roundTripped.Count | Should -Be $verdicts.Count
        $roundTripped[0].Cause | Should -Be $verdicts[0].Cause
        $roundTripped[0].Confidence | Should -Be $verdicts[0].Confidence
        @($roundTripped[0].Evidence).Count | Should -Be @($verdicts[0].Evidence).Count
        @($roundTripped[0].Remediation).Count | Should -Be @($verdicts[0].Remediation).Count
        @($roundTripped[0].Remediation) -contains $verdicts[0].Remediation[0] | Should -Be $true
        @($roundTripped[0].Remediation) -contains $verdicts[0].Remediation[1] | Should -Be $true
    }

    It 'round-trips a single No-cause-identified verdict as a one-element JSON array, not a bare object' {
        $verdicts = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $true; DrivePresent = $true; ScriptDeletions = @()
            InRegistry = $true; InLiveMounts = $true; TargetingFailures = @()
            Action = 'Create'; FastLogonOptimization = $false; AlwaysWaitForNetwork = $true
            ElevatedVisible = $true; UnelevatedVisible = $true; EnableLinkedConnections = 1
        })
        $verdicts.Count | Should -Be 1

        $json = ConvertTo-Json -InputObject @($verdicts) -Depth 6
        # A bare object (not wrapped in []) would mean the report's own @(... | ConvertFrom-Json)
        # is doing the array-wrapping work instead of this write - fragile if that reader ever
        # changes. Assert the JSON text itself starts with '[', proving THIS write is
        # unconditionally array-shaped regardless of how many verdicts there are.
        $json.TrimStart() | Should -Match '^\['

        # Assign then wrap: on Windows PowerShell 5.1 ConvertFrom-Json does not enumerate an
        # array into the pipeline, so wrapping the pipe directly would nest the array one
        # level deep and leave $roundTripped[0].Cause empty. See the round-trip test above.
        $parsed = $json | ConvertFrom-Json
        $roundTripped = @($parsed)
        $roundTripped.Count | Should -Be 1
        $roundTripped[0].Cause | Should -Match 'No cause identified'
    }

    It 'reads a one-verdict Verdicts.json back with its Cause intact (PS 5.1 ConvertFrom-Json non-enumeration)' {
        # The shape New-DriveMapCaseReport.ps1 actually reads off disk. On Windows PowerShell
        # 5.1 ConvertFrom-Json hands a converted array to the pipeline as ONE object rather
        # than enumerating it, so the natural-looking '@($raw | ConvertFrom-Json)' nests the
        # array one level deep: $verdicts[0] is an Object[], $verdicts[0].Cause is empty, and
        # the report's headline verdict renders BLANK - on the declared target runtime, while
        # looking perfect on PowerShell 7. -NoEnumerate is the documented fix but is
        # PowerShell 6+ only. Assigning before wrapping is the portable form and is what the
        # reader now does.
        # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertfrom-json
        $path = Join-Path $TestDrive 'Verdicts.json'
        $json = ConvertTo-Json -InputObject @(
            [PSCustomObject]@{ Cause = 'A logon script deletes the drive'; Confidence = 'High'; Evidence = @('GPO-A: net use X: /d'); Remediation = @('Unlink it') }
        ) -Depth 6
        Set-Content -LiteralPath $path -Value $json -Encoding UTF8

        $parsed = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $verdicts = @($parsed)

        $verdicts.Count | Should -Be 1
        $verdicts[0].Cause | Should -Be 'A logon script deletes the drive'
        $verdicts[0].Confidence | Should -Be 'High'
        # The precise failure mode: a nested array instead of the verdict object.
        $verdicts[0] | Should -Not -BeOfType [System.Object[]]
    }
}

Describe 'Evidence.json serialization' {
    # Invoke-DriveMapInvestigation.ps1's orchestration writes the flattened evidence object
    # produced by ConvertFrom-EvidenceBundle (the SAME object handed to Get-DriveMapVerdict)
    # as Evidence.json via 'ConvertTo-Json -InputObject $flatEvidence -Depth 6', so
    # New-DriveMapCaseReport.ps1 (Task 6) can populate its tab-2/3/4 sections from it instead
    # of always rendering their "not established" fallback text. This exercises that EXACT
    # serialization call against real ConvertFrom-EvidenceBundle output.

    It 'round-trips a $null evidence property as $null, never as $false or an empty array' {
        # A CouldNotCollect source flattens to $null in ConvertFrom-EvidenceBundle - "we could
        # not look". If Evidence.json's round trip silently turned that into $false or @(),
        # New-DriveMapCaseReport.ps1 would render "not present" / "none found" instead of
        # "not established", which is exactly the confident-plausible-wrong-answer failure
        # this toolkit exists to prevent, now crossing one more (JSON) boundary than before.
        $results = @{
            LiveMounts_CurrentContext    = [PSCustomObject]@{ State = 'CouldNotCollect'; Data = @(); Reason = 'Access denied' }
            LiveMounts_OtherTokenContext = [PSCustomObject]@{ State = 'CouldNotCollect'; Data = @(); Reason = 'Access denied' }
            PersistentMounts             = [PSCustomObject]@{ State = 'CouldNotCollect'; Data = @(); Reason = 'Access denied' }
            GppEvents                    = [PSCustomObject]@{ State = 'CouldNotCollect'; Data = @(); Reason = 'Access denied' }
            LogonScriptReferences        = [PSCustomObject]@{ State = 'CouldNotCollect'; Data = @(); Reason = 'Access denied' }
        }
        $flatEvidence = ConvertFrom-EvidenceBundle -DriveLetter 'X' -Results $results

        # Sanity: confirm the fixture actually produces $null before trusting the round trip.
        $flatEvidence.DrivePresent | Should -Be $null
        $flatEvidence.ScriptDeletions | Should -Be $null
        $flatEvidence.InRegistry | Should -Be $null

        $json = ConvertTo-Json -InputObject $flatEvidence -Depth 6
        $roundTripped = $json | ConvertFrom-Json

        $roundTripped.DrivePresent | Should -Be $null
        ($null -eq $roundTripped.DrivePresent) | Should -Be $true
        ($roundTripped.DrivePresent -eq $false) | Should -Be $false
        $roundTripped.ScriptDeletions | Should -Be $null
        $roundTripped.InRegistry | Should -Be $null
        $roundTripped.TargetingFailures | Should -Be $null
    }

    It 'round-trips a single-element ScriptDeletions as an array, not a bare object' {
        # A single deleting logon script is the most likely real-world shape - Task 5's own
        # Verdicts.json fix had to specifically guard against PowerShell degrading a
        # one-element array to a scalar through ConvertTo-Json/ConvertFrom-Json, so this must
        # be proven for Evidence.json too, not assumed to behave the same way by inheritance.
        $results = @{
            LiveMounts_CurrentContext    = [PSCustomObject]@{ State = 'Found'; Data = @(); Reason = $null }
            LiveMounts_OtherTokenContext = [PSCustomObject]@{ State = 'CouldNotCollect'; Data = @(); Reason = 'Not elevated' }
            PersistentMounts             = [PSCustomObject]@{ State = 'Found'; Data = @(); Reason = $null }
            GppEvents                    = [PSCustomObject]@{ State = 'Found'; Data = @(); Reason = $null }
            LogonScriptReferences        = [PSCustomObject]@{
                State = 'Found'
                Data  = @([PSCustomObject]@{ ScriptPath = 'DomainWideSettings\logon.bat'; Line = 'net use x: /delete'; Operation = 'Delete' })
                Reason = $null
            }
        }
        $flatEvidence = ConvertFrom-EvidenceBundle -DriveLetter 'X' -Results $results

        @($flatEvidence.ScriptDeletions).Count | Should -Be 1

        $json = ConvertTo-Json -InputObject $flatEvidence -Depth 6
        $roundTripped = $json | ConvertFrom-Json

        $roundTripped.ScriptDeletions | Should -Not -BeNullOrEmpty
        @($roundTripped.ScriptDeletions).Count | Should -Be 1
        @($roundTripped.ScriptDeletions)[0].Source | Should -Be 'DomainWideSettings\logon.bat'
        @($roundTripped.ScriptDeletions)[0].Line | Should -Be 'net use x: /delete'
    }
}
