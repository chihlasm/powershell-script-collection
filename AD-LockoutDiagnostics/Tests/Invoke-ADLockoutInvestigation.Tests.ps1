BeforeAll {
    . "$PSScriptRoot\..\Invoke-ADLockoutInvestigation.ps1" -LoadFunctionsOnly
    $script:Ref = Import-PowerShellDataFile "$PSScriptRoot\..\LockoutReference.psd1"

    function New-AuditRow {
        param($DC, $Subcategory, $EventId, $Setting, $Status)
        [PSCustomObject]@{ DC=$DC; Subcategory=$Subcategory; EventId=$EventId
                           Needs='Success'; Setting=$Setting; Status=$Status; Detail='' }
    }
}

Describe 'LockoutReference.psd1' {
    It 'loads and carries a verification date' {
        $script:Ref                | Should -Not -BeNullOrEmpty
        $script:Ref.VerifiedOn     | Should -Match '^\d{4}-\d{2}-\d{2}$'
    }

    It 'attributes event 4740 to Audit User Account Management' {
        # The mapping that was wrong in Test-ADAuditPolicy.ps1. Centralising it here is the
        # whole point of the file.
        $sub = @($script:Ref.AuditSubcategories | Where-Object { $_.Events -contains 4740 })
        $sub.Count  | Should -Be 1
        $sub[0].Name  | Should -Be 'User Account Management'
        $sub[0].Needs | Should -Be 'Success'
    }

    It 'does not attribute 4740 to Audit Account Lockout' {
        $al = @($script:Ref.AuditSubcategories | Where-Object { $_.Name -eq 'Account Lockout' })
        $al[0].Events | Should -Not -Contain 4740
        $al[0].Needs  | Should -Be 'Failure'
    }

    It 'ranks User Account Management as the top-priority subcategory' {
        $top = @($script:Ref.AuditSubcategories | Sort-Object { $_.Priority })[0]
        $top.Name | Should -Be 'User Account Management'
    }

    It 'maps 0x0 to success in both status families' {
        $script:Ref.StatusCodes['0x0']        | Should -Match 'Success'
        $script:Ref.StatusCodes['0x00000000'] | Should -Match 'Success'
        $script:Ref.SuccessStatusCodes        | Should -Contain '0x0'
    }

    It 'lists the events that are written for both outcomes' {
        # Learn: 4776(S, F) and 4768(S, F).
        foreach ($id in @(4776, 4768)) {
            $script:Ref.DualOutcomeEvents | Should -Contain $id
        }
        $script:Ref.DualOutcomeEvents | Should -Not -Contain 4625
    }

    It 'does not list 4771 as dual-outcome (Learn: 4771(F) is Failure-only) - regression' {
        # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4771
        $script:Ref.DualOutcomeEvents | Should -Not -Contain 4771
    }

    It 'records which AD attributes do not replicate' {
        foreach ($a in @('badPwdCount','badPasswordTime','lockoutTime')) {
            $script:Ref.NonReplicatedAttributes | Should -Contain $a
        }
    }

    It 'keeps event labels outcome-neutral for dual-outcome events' {
        foreach ($id in $script:Ref.DualOutcomeEvents) {
            $script:Ref.EventMeaning[$id] | Should -Not -Match '(?i)fail'
        }
    }

    It 'includes logon types that identify the kind of stale credential' {
        $script:Ref.LogonTypes[3]  | Should -Match '(?i)network'
        $script:Ref.LogonTypes[5]  | Should -Match '(?i)service'
        $script:Ref.LogonTypes[10] | Should -Match '(?i)rdp|remote'
    }
}

Describe 'Test-AuditGateResult' {
    It 'BLOCKS when the 4740 subcategory is not logging' {
        # Contoso's real configuration: User Account Management = No Auditing.
        $rows = @(
            (New-AuditRow 'DC02' 'User Account Management' 4740 'No Auditing' 'Fail')
            (New-AuditRow 'DC02' 'Logon' 4625 'Success and Failure' 'Pass')
        )
        $gate = Test-AuditGateResult -AuditRows $rows -Reference $script:Ref
        $gate.Ran            | Should -BeTrue
        $gate.Blocking       | Should -BeTrue
        $gate.CriticalGaps.Count | Should -Be 1
        $gate.Message        | Should -Match '4740'
    }

    It 'does NOT block when only supporting evidence is missing' {
        # Kerberos off is bad, but 4740 still records the lockout, so collection is useful.
        $rows = @(
            (New-AuditRow 'DC01' 'User Account Management' 4740 'Success' 'Pass')
            (New-AuditRow 'DC01' 'Kerberos Authentication Service' 4771 'No Auditing' 'Fail')
        )
        $gate = Test-AuditGateResult -AuditRows $rows -Reference $script:Ref
        $gate.Blocking        | Should -BeFalse
        $gate.OtherGaps.Count | Should -Be 1
    }

    It 'reports a clean bill when everything is logging' {
        $rows = @(
            (New-AuditRow 'DC01' 'User Account Management' 4740 'Success' 'Pass')
            (New-AuditRow 'DC01' 'Logon' 4625 'Success and Failure' 'Pass')
        )
        $gate = Test-AuditGateResult -AuditRows $rows -Reference $script:Ref
        $gate.Blocking | Should -BeFalse
        $gate.Message  | Should -Match 'genuine result'
    }

    It 'does not claim health when no audit data was collected' {
        $gate = Test-AuditGateResult -AuditRows @() -Reference $script:Ref
        $gate.Ran      | Should -BeFalse
        $gate.Blocking | Should -BeFalse
        $gate.Message  | Should -Match 'proves nothing'
    }

    It 'still identifies the 4740 gap when the reference file is unavailable' {
        # Falls back to the documented subcategory name so the gate survives a missing psd1.
        $rows = @( (New-AuditRow 'DC01' 'User Account Management' 4740 'No Auditing' 'Fail') )
        $gate = Test-AuditGateResult -AuditRows $rows -Reference $null
        $gate.Blocking | Should -BeTrue
    }

    It 'treats an Unknown status as a gap rather than a pass' {
        $rows = @( (New-AuditRow 'DC01' 'User Account Management' 4740 '(not reported)' 'Unknown') )
        $gate = Test-AuditGateResult -AuditRows $rows -Reference $script:Ref
        $gate.Blocking | Should -BeTrue
    }
}

Describe 'New-CaseSummary' {
    BeforeAll {
        $script:Steps = @(
            [PSCustomObject]@{ Step='Audit policy'; Script='Test-ADAuditPolicy.ps1'; Ran=$true; ExitCode=0; Error='' }
            [PSCustomObject]@{ Step='Lockout history'; Script='Get-ADLockoutHistory.ps1'; Ran=$false; ExitCode=$null; Error='Skipped - audit gate' }
        )
    }

    It 'leads with the findings, so the answer is readable without opening a CSV' {
        # SUMMARY.txt is what gets attached to a ticket. The cause belongs at the top -
        # a reader who stops after ten lines should still know what to go and fix.
        $gate = [PSCustomObject]@{ Ran=$true; Blocking=$false; CriticalGaps=@(); OtherGaps=@(); Message='' }
        $findings = @(
            [PSCustomObject]@{ FailureCount=47
                               Sentence='svc_backup (47 failures from SQLSRV02 [10.0.0.50]) - Windows service running as this account with a stale password'
                               Confidence='High'
                               Remediation='On the source machine open services.msc, sort by "Log On As", and update the password on each service running as this account.' }
        )
        $out = New-CaseSummary -Identity 'svc_backup' -DaysBack 30 -Gate $gate -Steps $script:Steps `
                 -CaseFolder 'C:\x' -GeneratedOn '2026-08-20 10:00:00' -Findings $findings

        $out | Should -Match 'FINDINGS'
        $out | Should -Match 'SQLSRV02'
        $out | Should -Match 'services\.msc'
        $out | Should -Match 'High'
        # The findings block must come before the supporting evidence sections.
        $out.IndexOf('FINDINGS') | Should -BeLessThan $out.IndexOf('EVIDENCE QUALITY')
    }

    It 'omits the findings block entirely when there are none' {
        # An empty "FINDINGS" heading reads as "we found nothing wrong", which is not the
        # same as "the cause step did not run".
        $gate = [PSCustomObject]@{ Ran=$true; Blocking=$false; CriticalGaps=@(); OtherGaps=@(); Message='' }
        $out = New-CaseSummary -Identity 'jdoe' -DaysBack 30 -Gate $gate -Steps $script:Steps `
                 -CaseFolder 'C:\x' -GeneratedOn '2026-08-20 10:00:00' -Findings @()
        $out | Should -Not -Match 'FINDINGS'
    }

    It 'leads with a loud warning when evidence is not trustworthy' {
        $gate = [PSCustomObject]@{ Ran=$true; Blocking=$true
                                   CriticalGaps=@('DC02: User Account Management is No Auditing')
                                   OtherGaps=@(); Message='4740 not recorded.' }
        $out = New-CaseSummary -Identity 'jdoe' -DaysBack 30 -Gate $gate -Steps $script:Steps `
                 -CaseFolder 'C:\x' -GeneratedOn '2026-08-12 10:00:00'
        $out | Should -Match 'NOT TRUSTWORTHY'
        $out | Should -Match 'COLLECTION GAP'
        # Must tell the reader how to fix it, naming the correct subcategory.
        $out | Should -Match 'Audit User Account Management'
    }

    It 'states plainly when an empty report would be a real result' {
        $gate = [PSCustomObject]@{ Ran=$true; Blocking=$false; CriticalGaps=@(); OtherGaps=@()
                                   Message='All good.' }
        $out = New-CaseSummary -Identity 'jdoe' -DaysBack 30 -Gate $gate -Steps $script:Steps `
                 -CaseFolder 'C:\x' -GeneratedOn '2026-08-12 10:00:00'
        $out | Should -Match 'genuine result'
        $out | Should -Not -Match 'NOT TRUSTWORTHY'
    }

    It 'records skipped steps with their reason' {
        $gate = [PSCustomObject]@{ Ran=$true; Blocking=$false; CriticalGaps=@(); OtherGaps=@(); Message='ok' }
        $out = New-CaseSummary -Identity 'jdoe' -DaysBack 30 -Gate $gate -Steps $script:Steps `
                 -CaseFolder 'C:\x' -GeneratedOn '2026-08-12 10:00:00'
        $out | Should -Match 'SKIPPED'
        $out | Should -Match 'Skipped - audit gate'
    }

    It 'labels a run without an identity as a domain-wide survey' {
        $gate = [PSCustomObject]@{ Ran=$true; Blocking=$false; CriticalGaps=@(); OtherGaps=@(); Message='ok' }
        $out = New-CaseSummary -Identity '' -DaysBack 30 -Gate $gate -Steps $script:Steps `
                 -CaseFolder 'C:\x' -GeneratedOn '2026-08-12 10:00:00'
        $out | Should -Match 'domain-wide survey'
    }

    It 'recommends the Failure setting for Audit Account Lockout, which has no Success events' {
        $gate = [PSCustomObject]@{ Ran=$true; Blocking=$true; CriticalGaps=@('x'); OtherGaps=@(); Message='m' }
        $out = New-CaseSummary -Identity 'jdoe' -DaysBack 30 -Gate $gate -Steps $script:Steps `
                 -CaseFolder 'C:\x' -GeneratedOn '2026-08-12 10:00:00'
        $out | Should -Match 'Audit Account Lockout -> Failure'
    }
}

Describe 'Bugs found in the real Case_jdoe run' {
    # REGRESSION GUARDS from a live investigation. Every one of these degraded QUIETLY -
    # the run reported success and produced files. That is the failure mode that survives
    # unit tests, because nothing throws.

    Context 'SUMMARY.txt keeps its FINDINGS section' {
        # The findings lookup searched $caseFolder non-recursively, but the reports are
        # moved into numbered subfolders BEFORE that runs. It found nothing, and the
        # summary silently dropped the one section that states the answer.

        It 'searches recursively, because reports live in numbered subfolders' {
            $src = Get-Content -Raw "$PSScriptRoot\..\Invoke-ADLockoutInvestigation.ps1"
            $src | Should -Match "Filter '\*LockoutCauses_\*\.csv' -Recurse"
        }

        It 'renders a FINDINGS section when findings exist' {
            $gate = [PSCustomObject]@{ Ran=$true; Blocking=$false; CriticalGaps=@(); OtherGaps=@(); Message='ok' }
            $findings = @([PSCustomObject]@{
                FailureCount = 92
                Sentence     = 'jdoe (92 failures from 192.168.10.181) - stale credential'
                Confidence   = 'High'
                Remediation  = 'Check saved credentials on that device.'
            })
            $out = New-CaseSummary -Identity 'jdoe' -DaysBack 7 -Gate $gate -Steps @() `
                     -CaseFolder 'C:\x' -GeneratedOn 'now' -Findings $findings
            $out | Should -Match 'FINDINGS'
            $out | Should -Match '192\.168\.10\.181'
        }
    }

    Context 'Every produced report gets a description' {
        # Four of the newer reports listed with a blank description because the pattern
        # was anchored to a '^\d+_' filename prefix these files do not have.

        It 'describes the device-identity and cause reports' {
            $src = Get-Content -Raw "$PSScriptRoot\..\Invoke-ADLockoutInvestigation.ps1"
            foreach ($p in "'AuthSources'", "'AuthEvents'", "'LockoutCauses'", "'ADLockout_'") {
                $src | Should -Match ([regex]::Escape($p))
            }
        }

        It 'no longer anchors the account report to a numeric prefix' {
            $src = Get-Content -Raw "$PSScriptRoot\..\Invoke-ADLockoutInvestigation.ps1"
            $src | Should -Not -Match '\^\d\+_ADLockout_'
        }
    }
}

Describe 'Fixes found while writing the service desk guide' {
    BeforeAll {
        $script:OkGate = [PSCustomObject]@{ Ran=$true; Blocking=$false; CriticalGaps=@(); OtherGaps=@(); Message='' }
        $script:NoGate = [PSCustomObject]@{ Ran=$false; Blocking=$false; CriticalGaps=@(); OtherGaps=@(); Message='' }
    }

    It 'keeps the space after a word ending in a colon when wrapping the Fix text' {
        # The wrap loop used "line ends with ':'" to mean "nothing on this line yet", which
        # also fired after "run:" - so every summary printed "run:net use" and
        # "Microsoft:the SCM".
        $findings = @([PSCustomObject]@{ FailureCount=72; Sentence='x'; Confidence='High'
            Remediation='On the source machine run: net use (list mapped drives) and cmdkey /list. Microsoft: the SCM caches service account passwords and retries the old one until updated.' })
        $out = New-CaseSummary -Identity 'jdoe' -DaysBack 7 -Gate $script:OkGate -Steps @() `
                 -CaseFolder 'C:\x' -GeneratedOn 'now' -Findings $findings
        $out | Should -Match 'run: net use'
        $out | Should -Match 'Microsoft: the SCM'
        $out | Should -Not -Match 'run:net|Microsoft:the'
        $out | Should -Match 'Fix        : On the source'
    }

    It 'wraps a long Fix line without losing or doubling words' {
        $words = 1..60 | ForEach-Object { "word$_" }
        $findings = @([PSCustomObject]@{ FailureCount=1; Sentence='x'; Confidence='Low'; Remediation=($words -join ' ') })
        $out = New-CaseSummary -Identity 'jdoe' -DaysBack 7 -Gate $script:OkGate -Steps @() `
                 -CaseFolder 'C:\x' -GeneratedOn 'now' -Findings $findings
        foreach ($w in $words) { ([regex]::Matches($out, "\b$w\b")).Count | Should -Be 1 }
        foreach ($line in ($out -split "`r?`n")) { $line.Length | Should -BeLessOrEqual 96 }
    }

    It 'says lockout auditing is evidently working when the audit read failed but lockouts were found' {
        # A helpdesk account usually cannot run auditpol on the DCs. Collected 4740 events
        # still prove lockout auditing is on, and saying only "UNKNOWN" hid that.
        $out = New-CaseSummary -Identity 'jdoe' -DaysBack 7 -Gate $script:NoGate -Steps @() `
                 -CaseFolder 'C:\x' -GeneratedOn 'now' -LockoutEventsFound $true
        $out | Should -Match 'PARTLY CONFIRMED'
        $out | Should -Match 'administrator'
        $out | Should -Not -Match 'UNKNOWN'
    }

    It 'still says UNKNOWN, and why, when the audit read failed and nothing was found' {
        $out = New-CaseSummary -Identity 'jdoe' -DaysBack 7 -Gate $script:NoGate -Steps @() `
                 -CaseFolder 'C:\x' -GeneratedOn 'now' -LockoutEventsFound $false
        $out | Should -Match 'UNKNOWN'
        $out | Should -Match 'proves nothing'
        $out | Should -Match 'administrator on the domain controllers'
    }

    It 'explains the likely cause when audit policy could not be determined' {
        $gate = Test-AuditGateResult -AuditRows @() -Reference $null
        $gate.Message | Should -Match 'proves nothing'
        $gate.Message | Should -Match 'administrator'
    }

    It 'ships every companion script it resolves in the Service Desk bundle' {
        # The bundle copied Export-ADAuthSourceEvidence.ps1 but not Get-LockoutCause.ps1,
        # so step 7 was always skipped there: no "What To Fix" tab, no FINDINGS section.
        # The companions now live in this folder, which the bundle copies whole, so each
        # one must be in this folder and the folder must be in the manifest.
        $src      = Get-Content -Raw "$PSScriptRoot\..\Invoke-ADLockoutInvestigation.ps1"
        $manifest = Get-Content -Raw "$PSScriptRoot\..\..\ServiceDesk-Toolkit\Build-ServiceDeskToolkit.ps1"
        $manifest | Should -Match ([regex]::Escape("Source = 'AD-LockoutDiagnostics';"))
        $companions = @([regex]::Matches($src, "Resolve-CompanionScript -FileName '([^']+)'") | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
        $companions.Count | Should -BeGreaterThan 0
        foreach ($c in $companions) {
            Join-Path "$PSScriptRoot\.." $c | Should -Exist
        }
    }
}

Describe 'Step 8 - device timeline' {
    It 'puts a DEVICE TIMELINE section straight after the findings' {
        $gate = [PSCustomObject]@{ Ran=$true; Blocking=$false; CriticalGaps=@(); OtherGaps=@(); Message='' }
        $findings = @([PSCustomObject]@{ FailureCount=84; Sentence='mjohnson (84 failures from CON-LT-0142)'; Confidence='High'; Remediation='net use' })
        $rows = @([PSCustomObject]@{ Computer='CON-LT-0142'; Verdict='9 of 12 failures came within 5 minutes of CON-LT-0142 waking from sleep (9).'; Next='Something on it replays a saved password.' })
        $out = New-CaseSummary -Identity 'mjohnson' -DaysBack 7 -Gate $gate -Steps @() -CaseFolder 'C:\x' -GeneratedOn 'now' `
                 -Findings $findings -TimelineRows $rows
        $out | Should -Match 'DEVICE TIMELINE'
        $out | Should -Match 'waking from sleep'
        $out.IndexOf('FINDINGS') | Should -BeLessThan $out.IndexOf('DEVICE TIMELINE')
        $out.IndexOf('DEVICE TIMELINE') | Should -BeLessThan $out.IndexOf('EVIDENCE QUALITY')
    }

    It 'omits the section when step 8 produced nothing' {
        $gate = [PSCustomObject]@{ Ran=$true; Blocking=$false; CriticalGaps=@(); OtherGaps=@(); Message='' }
        New-CaseSummary -Identity 'x' -DaysBack 7 -Gate $gate -Steps @() -CaseFolder 'C:\x' -GeneratedOn 'now' | Should -Not -Match 'DEVICE TIMELINE'
    }

    It 'numbers every step out of 8' {
        $src = Get-Content -Raw "$PSScriptRoot\..\Invoke-ADLockoutInvestigation.ps1"
        $src | Should -Not -Match 'STEP \d/7'
        $src | Should -Match 'STEP 8/8'
    }

    It 'files the timeline into its own case subfolder' {
        $src = Get-Content -Raw "$PSScriptRoot\..\Invoke-ADLockoutInvestigation.ps1"
        $src | Should -Match "Match = 'SourceActivity';\s+Folder = '6 - Device Timeline'"
    }
}

Describe 'Credential Validation (4776) gap in the audit gate' {
    # DECISION: a missing Credential Validation subcategory is a WARNING (OtherGaps), not a
    # blocker. 4740 comes from User Account Management, so the lockout itself is still
    # recorded; only NTLM-only sources are missed. Event 4776 is 4776(S, F).
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4776
    It 'does not block, and is reported as a supporting-evidence gap naming event 4776' {
        $rows = @(
            (New-AuditRow 'DC01' 'User Account Management' 4740 'Success' 'Pass')
            (New-AuditRow 'DC01' 'Credential Validation' 4776 'No Auditing' 'Fail')
        )
        $gate = Test-AuditGateResult -AuditRows $rows -Reference $script:Ref
        $gate.Blocking        | Should -BeFalse
        $gate.CriticalGaps.Count | Should -Be 0
        $gate.OtherGaps.Count | Should -Be 1
        $gate.OtherGaps[0]    | Should -Match '4776'
        $gate.Message         | Should -Match 'partial'
    }

    It 'the shared reference lists Credential Validation with the verified GUID and event 4776' {
        $cv = @($script:Ref.AuditSubcategories | Where-Object { $_.Name -eq 'Credential Validation' })
        $cv.Count   | Should -Be 1
        $cv[0].Guid | Should -Be '{0CCE923F-69AE-11D9-BED3-505054503030}'
        $cv[0].Events | Should -Contain 4776
    }
}

Describe 'Get-DeviceStepArguments (step 6 scope)' {
    # Diagnose does not query 4776 and Export used to be unfiltered, so a default run never
    # examined NTLM evidence for the target account. Passing -Identity scopes step 6 to it.
    It 'passes the identity to Export-ADAuthSourceEvidence when one was given' {
        $a = Get-DeviceStepArguments -DaysBack 30 -OutputPath 'C:\case' -Identity 'jdoe'
        $a['Identity']   | Should -Be 'jdoe'
        $a['DaysBack']   | Should -Be 30
        $a['OutputPath'] | Should -Be 'C:\case'
    }
    It 'leaves the arguments unchanged (no Identity key) when no identity was given' {
        $a = Get-DeviceStepArguments -DaysBack 30 -OutputPath 'C:\case' -Identity ''
        $a.ContainsKey('Identity') | Should -BeFalse
        $a.Keys.Count | Should -Be 2
    }
    It 'still caps DaysBack at the exporter ceiling of 90' {
        (Get-DeviceStepArguments -DaysBack 365 -OutputPath 'C:\case')['DaysBack'] | Should -Be 90
    }
}

Describe 'SQ-006 encryption-type block in SUMMARY.txt (D-023)' {
    BeforeAll {
        $script:EGate = [PSCustomObject]@{ Ran=$true; Blocking=$false; CriticalGaps=@(); OtherGaps=@(); Message='' }
        $script:ESteps = @([PSCustomObject]@{ Step='Audit policy'; Script='Test-ADAuditPolicy.ps1'; Ran=$true; ExitCode=0; Error='' })
        $script:EFinding = @([PSCustomObject]@{ FailureCount=3; Sentence='svc_backup (3 failures from SQLSRV02) - stale password'
                                                Confidence='High'; Remediation='Update the service password.' })
        $script:ETimeline = @([PSCustomObject]@{ Computer='SQLSRV02'; Verdict='SQLSRV02 was on at the time'; Next='Check it.' })
    }

    It 'AC23_EtypeBlockFollowsFindings' {
        $etype = @([PSCustomObject]@{ Kind='Account'; Account='svc-scan'; ClientAddress=''
                                      Sentence='Not a password problem: encryption type blocked for svc-scan.'
                                      NextStep='Reset the password for svc-scan so it gets AES keys.' })
        $cant  = @([PSCustomObject]@{ DC='DC02'; Reason="couldn't reach DC02: RPC server is unavailable" })
        $out = New-CaseSummary -Identity 'jdoe' -DaysBack 7 -Gate $script:EGate -Steps $script:ESteps -CaseFolder 'C:\x' `
                 -GeneratedOn '2026-10-18 10:00:00' -Findings $script:EFinding -TimelineRows $script:ETimeline `
                 -EtypeFindings $etype -EtypeCantTell $cant
        $out | Should -Match '(?m)^ENCRYPTION-TYPE BLOCKS'
        $out | Should -Match 'Not a password problem: encryption type blocked for svc-scan\.'
        $out | Should -Match 'Reset the password for svc-scan so it gets AES keys\.'
        $out | Should -Match "DC02: couldn't reach DC02: RPC server is unavailable"
        $f = $out.IndexOf('FINDINGS'); $e = $out.IndexOf('ENCRYPTION-TYPE BLOCKS')
        $f | Should -BeGreaterThan -1
        $e | Should -BeGreaterThan $f
        $e | Should -BeLessThan $out.IndexOf('DEVICE TIMELINE')
        $e | Should -BeLessThan $out.IndexOf('EVIDENCE QUALITY')

        # Nothing to report: output identical to today's.
        $today = New-CaseSummary -Identity 'jdoe' -DaysBack 7 -Gate $script:EGate -Steps $script:ESteps -CaseFolder 'C:\x' `
                 -GeneratedOn '2026-10-18 10:00:00' -Findings $script:EFinding -TimelineRows $script:ETimeline
        $none  = New-CaseSummary -Identity 'jdoe' -DaysBack 7 -Gate $script:EGate -Steps $script:ESteps -CaseFolder 'C:\x' `
                 -GeneratedOn '2026-10-18 10:00:00' -Findings $script:EFinding -TimelineRows $script:ETimeline `
                 -EtypeFindings @() -EtypeCantTell @()
        $none | Should -BeExactly $today
        $none | Should -Not -Match 'ENCRYPTION-TYPE BLOCKS'
    }

    It 'AC23_ImportEtypeFindingsCsvSplitsFindingsFromCantTell' {
        $csv = Join-Path $TestDrive 'ADLockoutEtype_jdoe_2026-10-18_100000.csv'
        @(
            'Kind,Account,ClientAddress,DC,Sentence,NextStep,Reason'
            'Account,svc-scan,,DC01,Not a password problem: encryption type blocked for svc-scan.,Reset the password for svc-scan so it gets AES keys.,'
            'Client,jdoe,192.0.2.77,DC01,Not a password problem: encryption type blocked for 192.0.2.77.,Update or replace the device.,'
            "CantTell,,,DC02,,,couldn't reach DC02: RPC server is unavailable"
        ) | Set-Content -LiteralPath $csv -Encoding UTF8
        $r = Import-EtypeFindingsCsv -Path $csv
        @($r.Findings).Count | Should -Be 2
        $r.Findings[0].Kind          | Should -Be 'Account'
        $r.Findings[0].Account       | Should -Be 'svc-scan'
        $r.Findings[0].NextStep      | Should -Match 'AES keys'
        $r.Findings[1].Kind          | Should -Be 'Client'
        $r.Findings[1].ClientAddress | Should -Be '192.0.2.77'
        @($r.CantTell).Count | Should -Be 1
        $r.CantTell[0].DC     | Should -Be 'DC02'
        $r.CantTell[0].Reason | Should -Be "couldn't reach DC02: RPC server is unavailable"
    }
}
