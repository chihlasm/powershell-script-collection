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
        foreach ($id in @(4776, 4771, 4768)) {
            $script:Ref.DualOutcomeEvents | Should -Contain $id
        }
        $script:Ref.DualOutcomeEvents | Should -Not -Contain 4625
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
