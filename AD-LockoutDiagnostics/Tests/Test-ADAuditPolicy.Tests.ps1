BeforeAll {
    . "$PSScriptRoot\..\Test-ADAuditPolicy.ps1" -LoadFunctionsOnly
}

Describe 'Subcategory-to-event mapping (verified against Microsoft Learn)' {
    # Regression guard: 4740 was originally mapped to 'Audit Account Lockout' because of
    # the name. It is not produced by that subcategory. Checking the wrong setting would
    # declare a blind DC healthy - the exact failure this script exists to catch.
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-account-lockout
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740

    It 'maps event 4740 to Audit User Account Management, not Audit Account Lockout' {
        $uam = $script:LockoutSubcategories | Where-Object { $_.Name -eq 'User Account Management' }
        $uam.EventId | Should -Be 4740
        $uam.Needs   | Should -Be 'Success'
    }

    It 'does not claim Audit Account Lockout produces 4740' {
        $al = $script:LockoutSubcategories | Where-Object { $_.Name -eq 'Account Lockout' }
        $al.EventId | Should -Not -Be 4740
        $al.EventId | Should -Be 4625
    }

    It 'requires Failure auditing for Account Lockout, which has no Success events' {
        $al = $script:LockoutSubcategories | Where-Object { $_.Name -eq 'Account Lockout' }
        $al.Needs | Should -Be 'Failure'
    }

    It 'uses the documented locale-independent subcategory GUIDs' {
        $expected = @{
            'Account Lockout'                 = '{0CCE9217-69AE-11D9-BED3-505054503030}'
            'Logon'                           = '{0CCE9215-69AE-11D9-BED3-505054503030}'
            'Kerberos Authentication Service' = '{0CCE9242-69AE-11D9-BED3-505054503030}'
            'User Account Management'         = '{0CCE9235-69AE-11D9-BED3-505054503030}'
        }
        foreach ($name in $expected.Keys) {
            $row = $script:LockoutSubcategories | Where-Object { $_.Name -eq $name }
            $row.Guid | Should -Be $expected[$name]
        }
    }
}

Describe 'Test-SubcategorySetting' {
    It 'passes when Failure auditing is explicitly enabled' {
        (Test-SubcategorySetting -Setting 'Failure' -Needs 'Failure').Status | Should -Be 'Pass'
    }

    It 'passes when set to Success and Failure' {
        (Test-SubcategorySetting -Setting 'Success and Failure' -Needs 'Failure').Status | Should -Be 'Pass'
        (Test-SubcategorySetting -Setting 'Success and Failure' -Needs 'Success').Status | Should -Be 'Pass'
    }

    It 'FAILS when set to Success only but Failure is required' {
        # This is the exact misconfiguration that makes 4625/4771 invisible.
        $r = Test-SubcategorySetting -Setting 'Success' -Needs 'Failure'
        $r.Status | Should -Be 'Fail'
        $r.Logs   | Should -BeFalse
        $r.Detail | Should -Match 'NOT logged'
    }

    It 'fails on No Auditing and says events are not written at all' {
        $r = Test-SubcategorySetting -Setting 'No Auditing' -Needs 'Failure'
        $r.Status | Should -Be 'Fail'
        $r.Detail | Should -Match 'not written'
    }

    It 'reports Unknown rather than Pass when the setting is missing' {
        # Absence of data must never be reported as a healthy configuration.
        $r = Test-SubcategorySetting -Setting '' -Needs 'Failure'
        $r.Status | Should -Be 'Unknown'
        $r.Logs   | Should -BeFalse
    }

    It 'is case-insensitive about auditpol output casing' {
        (Test-SubcategorySetting -Setting 'success and failure' -Needs 'Failure').Status | Should -Be 'Pass'
        (Test-SubcategorySetting -Setting 'NO AUDITING' -Needs 'Failure').Status         | Should -Be 'Fail'
    }
}

Describe 'ConvertFrom-AuditPolCsv' {
    BeforeAll {
        # Shape matches `auditpol /get /category:* /r` on Windows Server.
        $script:Csv = @'
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
DC01,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success,No Auditing
DC01,System,Kerberos Authentication Service,{0CCE9242-69AE-11D9-BED3-505054503030},No Auditing,No Auditing
DC01,System,Account Lockout,{0CCE9217-69AE-11D9-BED3-505054503030},Success and Failure,No Auditing
DC01,System,User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},Success,No Auditing
'@
    }

    It 'parses each subcategory row with its GUID and setting' {
        $rows = ConvertFrom-AuditPolCsv -CsvText $script:Csv
        $rows.Count | Should -Be 4
        ($rows | Where-Object { $_.Guid -eq '{0CCE9215-69AE-11D9-BED3-505054503030}' }).Setting | Should -Be 'Success'
    }

    It 'returns an empty result for empty or malformed input rather than throwing' {
        @(ConvertFrom-AuditPolCsv -CsvText '').Count            | Should -Be 0
        { ConvertFrom-AuditPolCsv -CsvText 'not,a,valid csv' }   | Should -Not -Throw
    }
}

Describe 'Get-AuditPolicyVerdict' {
    BeforeAll {
        function New-SubRow {
            param($DC,$Name,$EventId,$Needs,$Setting)
            $eval = Test-SubcategorySetting -Setting $Setting -Needs $Needs
            [PSCustomObject]@{
                DC=$DC; Subcategory=$Name; EventId=$EventId; Needs=$Needs
                Setting=$Setting; Status=$eval.Status; Detail=$eval.Detail; Explains='x'
            }
        }
        function New-DCResult {
            param($DC,$LogonSetting,$KerbSetting,$Legacy=$false,$Retention=30)
            [PSCustomObject]@{
                DC=$DC; Reachable=$true
                Subcategories=@(
                    (New-SubRow $DC 'Account Lockout' 4740 'Failure' 'Success and Failure')
                    (New-SubRow $DC 'Logon' 4625 'Failure' $LogonSetting)
                    (New-SubRow $DC 'Kerberos Authentication Service' 4771 'Failure' $KerbSetting)
                    (New-SubRow $DC 'User Account Management' 4724 'Success' 'Success')
                )
                LegacyOverrideRisk=$Legacy; LogMaxMB=128; RetentionDays=$Retention; Errors=@()
            }
        }
    }

    It 'reports the domain-wide blind spot when every DC lacks failure auditing' {
        $r = @(
            (New-DCResult 'AD-01' 'Success' 'No Auditing')
            (New-DCResult 'AD-02' 'Success' 'No Auditing')
        )
        $v = Get-AuditPolicyVerdict -Results $r
        ($v -join ' ') | Should -Match 'ANY checked DC'
        ($v -join ' ') | Should -Match '4625'
    }

    It 'names the specific DCs when only some are misconfigured' {
        $r = @(
            (New-DCResult 'AD-01' 'Success and Failure' 'Success and Failure')
            (New-DCResult 'AD-02' 'Success' 'Success and Failure')
        )
        $v = Get-AuditPolicyVerdict -Results $r
        ($v -join ' ') | Should -Match 'AD-02'
        ($v -join ' ') | Should -Not -Match 'ANY checked DC'
    }

    It 'confirms an empty lockout report is meaningful when auditing is correct' {
        $r = @( (New-DCResult 'AD-01' 'Success and Failure' 'Success and Failure') )
        $v = Get-AuditPolicyVerdict -Results $r
        ($v -join ' ') | Should -Match 'genuinely did not occur on-prem'
    }

    It 'flags the legacy audit policy override risk' {
        $r = @( (New-DCResult 'AD-01' 'Success and Failure' 'Success and Failure' -Legacy $true) )
        $v = Get-AuditPolicyVerdict -Results $r
        ($v -join ' ') | Should -Match 'SCENoApplyLegacyAuditPolicy'
    }

    It 'flags short log retention even when auditing is correct' {
        $r = @( (New-DCResult 'AD-01' 'Success and Failure' 'Success and Failure' -Retention 4.6) )
        $v = Get-AuditPolicyVerdict -Results $r
        ($v -join ' ') | Should -Match 'under 7 days'
    }

    It 'does not claim health when no DC could be reached' {
        $r = @( [PSCustomObject]@{ DC='AD-01'; Reachable=$false; Subcategories=@()
                                   LegacyOverrideRisk=$null; LogMaxMB=$null; RetentionDays=$null
                                   Errors=@('unreachable') } )
        $v = Get-AuditPolicyVerdict -Results $r
        ($v -join ' ') | Should -Match 'proves nothing'
    }
}

Describe 'New-AuditPolicyHtml' {
    It 'renders findings and escapes HTML metacharacters' {
        $res = @([PSCustomObject]@{
            DC='AD-01'; Reachable=$true
            Subcategories=@([PSCustomObject]@{ DC='AD-01'; Subcategory='<script>x</script>'
                EventId=4625; Needs='Failure'; Setting='Success'; Status='Fail'
                Detail='A & B'; Explains='y' })
            LegacyOverrideRisk=$false; LogMaxMB=128; RetentionDays=30; Errors=@()
        })
        $html = New-AuditPolicyHtml -Results $res -Verdict @('Finding one')
        # The verdict is computed from the audit rows themselves, so assert the report
        # renders a verdict and escapes hostile field values rather than echoing the
        # caller-supplied string verbatim.
        $html | Should -Match 'What this means'
        $html | Should -Not -Match '<script>x'
        $html | Should -Match '&lt;script&gt;'
        $html | Should -Match 'A &amp; B'
    }
}
