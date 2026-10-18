#
# SQ-006: lockout tools recognise Kerberos encryption-type blocks (RC4 enforcement).
# One test per acceptance criterion (AC1..AC22), plus review regressions named after the AC
# they extend. AC23 (the SUMMARY.txt block, owner decision D-023) lives in
# Invoke-ADLockoutInvestigation.Tests.ps1.
#
# Microsoft facts used by the fixtures (verified on Learn / the KB on 2026-10-18):
#   * 4769 (Kerberos Service Ticket Operations) and 4768 (Kerberos Authentication Service) are
#     written for success AND failure; Status 0xE = KDC_ERR_ETYPE_NOTSUPP is a listed failure
#     code; XML field names TargetUserName, ServiceName, IpAddress, Status.
#     https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4769
#     https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4768
#   * Audit_AccountLogon_Kerberos (Kerberos Service Ticket Operations) =
#     0cce9240-69ae-11d9-bed3-505054503030
#     https://learn.microsoft.com/windows/win32/secauthz/auditing-constants
#   * StandardEventKeywords.AuditFailure = 4503599627370496 (0x10000000000000)
#     https://learn.microsoft.com/dotnet/api/system.diagnostics.eventing.reader.standardeventkeywords
#   * KB5073381 / CVE-2026-20833 (KDCSVC events in the System log, source "Kdcsvc"):
#     203 = KDC blocked: client only advertises RC4, service has no msds-SupportedEncryptionTypes
#     204 = KDC blocked: service account only has insecure (RC4) keys
#     208 = KDC denied: service is AES-only but the client does not advertise AES
#     209 = KDC denied: service is AES-only but the service account has no AES keys
#     So 204/209 are fixed on the ACCOUNT (reset password to generate AES keys) and 203/208 on
#     the CLIENT (device only offers RC4). The KB prints these as "Warning" type although the
#     comments call them "Error event"; 201/202/206/207 are the will-break-later warnings.
#     https://support.microsoft.com/topic/1ebcda33-720a-4da8-93c1-b0496e1910dc
#   NOT VERIFIED: the KB documents only the message text of the KDCSVC events, not the XML
#     EventData element names. The fixtures assume Data Name="AccountName" / "ServiceName" /
#     "ClientAddress"; if real events differ, the parser must be made tolerant and these
#     fixtures corrected.
#

BeforeAll {
    . "$PSScriptRoot\..\Diagnose-ADAccountLockout.ps1" -Identity '__pester__' -LoadFunctionsOnly
    $script:LockDir = Split-Path -Parent $PSScriptRoot
    $script:Ref     = Import-PowerShellDataFile -LiteralPath (Join-Path $script:LockDir 'LockoutReference.psd1')

    function New-KerbXml {
        param([int]$EventId = 4769, [string]$Status = '0xe', [string]$User = 'jdoe',
              [string]$Service = 'svc-scan', [string]$Ip = '::ffff:192.0.2.55')
@"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>$EventId</EventID><TimeCreated SystemTime="2026-10-17T09:30:00.000Z"/></System>
  <EventData>
    <Data Name="TargetUserName">$User</Data>
    <Data Name="ServiceName">$Service</Data>
    <Data Name="Status">$Status</Data>
    <Data Name="IpAddress">$Ip</Data>
    <Data Name="IpPort">49811</Data>
  </EventData>
</Event>
"@
    }

    function New-KdcsvcXml {
        param([int]$EventId = 204)
@"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><Provider Name="Kdcsvc"/><EventID>$EventId</EventID><Channel>System</Channel><TimeCreated SystemTime="2026-10-17T09:31:00.000Z"/></System>
  <EventData>
    <Data Name="AccountName">jdoe</Data>
    <Data Name="ServiceName">svc-scan</Data>
    <Data Name="ClientAddress">192.0.2.55</Data>
  </EventData>
</Event>
"@
    }

    function New-FakeEvent {
        param([int]$Id, [string]$Xml)
        $o = [pscustomobject]@{ Id = $Id; TimeCreated = [datetime]'2026-10-17T09:30:00Z'; Xml = $Xml }
        $o | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.Xml } -Force
        $o
    }

    function New-EtypeRow {
        param([string]$Account = 'jdoe', [string]$Service = 'svc-scan', [string]$Dc = 'DC01', [int]$EventId = 4769)
        [pscustomobject]@{ Time = [datetime]'2026-10-17T09:30:00Z'; EventId = $EventId; Account = $Account
                           Service = $Service; ClientAddress = '192.0.2.55'; Status = '0xE'; DC = $Dc }
    }

    function New-KdcsvcRow {
        param([int]$EventId, [string]$Who, [string]$Dc = 'DC01', [string]$Account = 'svc-scan')
        $e = $script:Ref.EncryptionTypeBlocks.KdcsvcEvents[$EventId]
        [pscustomobject]@{ Time = [datetime]'2026-10-17T09:31:00Z'; EventId = $EventId; DC = $Dc
                           Accounts = @($Account); ClientAddress = '192.0.2.77'
                           Who = $Who; NextStep = $e.NextStep }
    }

    function New-GateRow {
        param([string]$Dc = 'DC01', [bool]$Gap = $false, [string]$Reason = '')
        $s = if ($Gap) { "Can't tell" } else { 'Checked' }
        [pscustomobject]@{ DC = $Dc; KdcEvents = $s; KdcReason = $Reason; TicketFailures = $s; TicketReason = $Reason; Reason = $Reason }
    }

    $script:Policy = [pscustomobject]@{ LockoutThreshold = 10; Source = 'Default Domain Policy'
                                        LockoutObservationWindow = '00:15:00'; LockoutDuration = '00:15:00' }
    $script:LockRow = [pscustomobject]@{ Time = [datetime]'2026-10-17T09:00:00Z'; User = 'jdoe'; Domain = 'CONTOSO'
                                         CallerComputer = 'LAPTOP-7'; DC = 'DC01' }
    $script:BadRow  = [pscustomobject]@{ Time = [datetime]'2026-10-17T09:00:00Z'; EventId = 4771; User = 'jdoe'
                                         SourceHost = 'LAPTOP-7'; SourceIp = '192.0.2.10'; LogonType = '3'
                                         Status = '0x18 - Bad password'; DC = 'DC01' }
}

Describe 'Reference data' {
    It 'AC1_ReferenceHasEncryptionTypeBlocksSection' {
        $b = $script:Ref.EncryptionTypeBlocks
        $b | Should -Not -BeNullOrEmpty
        $b.StatusCode | Should -Be '0xE'
        $b.StatusName | Should -Be 'KDC_ERR_ETYPE_NOTSUPP'
        @($b.FailureEvents) | Should -Contain 4768
        @($b.FailureEvents) | Should -Contain 4769
        $b.KdcProvider | Should -Be 'Kdcsvc'
        $b.AuditSubcategoryGuid | Should -Be '{0CCE9240-69AE-11D9-BED3-505054503030}'
        $expectedWho = @{ 203 = 'Client'; 204 = 'Account'; 208 = 'Client'; 209 = 'Account' }
        @($b.KdcsvcEvents.Keys | Sort-Object) | Should -Be @(203, 204, 208, 209)
        foreach ($id in 203, 204, 208, 209) {
            $e = $b.KdcsvcEvents[$id]
            $e.Who      | Should -BeIn @('Account', 'Client', 'Unknown')
            $e.Who      | Should -Be $expectedWho[$id] -Because "KB5073381 event $id"
            $e.NextStep | Should -Not -BeNullOrEmpty
            $e.Reference | Should -Match '^https://(support|learn)\.microsoft\.com/'
        }
    }

    It 'AC2_StatusMeaningKnowsKerberos0xEInAnyCaseOrPadding' {
        $script:Ref.StatusCodes['0xE'] | Should -Match 'ETYPE_NOTSUPP'
        $want = $script:Ref.StatusCodes['0xE']
        foreach ($c in '0xE', '0xe', '0x0000000E') {
            Get-StatusMeaning -Code $c | Should -Be $want -Because $c
        }
    }
}

Describe 'Parsing' {
    It 'AC3_Parses4769WithStatus0xEIntoOneRow' {
        $rows = @(ConvertFrom-EtypeFailureEvent -EventXml (New-KerbXml -EventId 4769 -Status '0xe') -EventId 4769 -DcName 'DC01')
        $rows.Count | Should -Be 1
        $r = $rows[0]
        $r.EventId       | Should -Be 4769
        $r.Account       | Should -Be 'jdoe'
        $r.Service       | Should -Be 'svc-scan'
        $r.ClientAddress | Should -Be '192.0.2.55'
        $r.Status        | Should -Be '0xE'
        $r.DC            | Should -Be 'DC01'
        ([datetime]$r.Time).ToUniversalTime().ToString('yyyy-MM-dd HH:mm') | Should -Be '2026-10-17 09:30'
    }

    It 'AC4_OnlyStatus0xECountsAsEtypeRow' {
        foreach ($id in 4768, 4769) {
            foreach ($st in '0x0', '0x18', '0x12') {
                @(ConvertFrom-EtypeFailureEvent -EventXml (New-KerbXml -EventId $id -Status $st) -EventId $id -DcName 'DC01').Count |
                    Should -Be 0 -Because "$id status $st"
            }
            foreach ($st in '0xE', '0xe', '0x0000000E') {
                @(ConvertFrom-EtypeFailureEvent -EventXml (New-KerbXml -EventId $id -Status $st) -EventId $id -DcName 'DC01').Count |
                    Should -Be 1 -Because "$id status $st"
            }
        }
    }

    It 'AC5_ParsesKdcsvc204WithWhoAndNextStepFromReference' {
        $rows = @(ConvertFrom-KdcsvcEvent -EventXml (New-KdcsvcXml -EventId 204) -EventId 204 -DcName 'DC02')
        $rows.Count | Should -Be 1
        $r = $rows[0]
        $r.EventId | Should -Be 204
        $r.DC      | Should -Be 'DC02'
        @($r.Accounts) | Should -Contain 'jdoe'
        @($r.Accounts) | Should -Contain 'svc-scan'
        $r.Who      | Should -Be $script:Ref.EncryptionTypeBlocks.KdcsvcEvents[204].Who
        $r.NextStep | Should -Be $script:Ref.EncryptionTypeBlocks.KdcsvcEvents[204].NextStep
        ([datetime]$r.Time).ToUniversalTime().ToString('yyyy-MM-dd HH:mm') | Should -Be '2026-10-17 09:31'
    }

    It 'AC6_KdcsvcWarning201IsNotABlock' {
        @(ConvertFrom-KdcsvcEvent -EventXml (New-KdcsvcXml -EventId 201) -EventId 201 -DcName 'DC02').Count | Should -Be 0
    }

    It 'AC5_UnrecognisedElementNamesFallBackToMessageOrder' {
        # The KB documents only the rendered message, so real events may use element names the
        # parser doesn't know. With no name resolved and no message, the documented message
        # order is used: Account Name (0), Service Name (4), Client Address (11).
        $values = @('jdoe', 'CONTOSO.COM', '0x0', 'RC4', 'svc-scan', 'S-1-5-21-1-2-3-1105', '0x0', 'RC4',
                    '0x18', '0x24', 'AES256', '::ffff:192.0.2.55')
        $data = (0..($values.Count - 1) | ForEach-Object { "<Data Name=`"Param$($_ + 1)`">$($values[$_])</Data>" }) -join ''
        $xml = "<Event xmlns=`"http://schemas.microsoft.com/win/2004/08/events/event`"><System><Provider Name=`"Kdcsvc`"/><EventID>204</EventID><TimeCreated SystemTime=`"2026-10-17T09:31:00.000Z`"/></System><EventData>$data</EventData></Event>"
        $rows = @(ConvertFrom-KdcsvcEvent -EventXml $xml -EventId 204 -DcName 'DC02' -Message '')
        $rows.Count | Should -Be 1
        $rows[0].Account       | Should -Be 'jdoe'
        $rows[0].Service       | Should -Be 'svc-scan'
        $rows[0].ClientAddress | Should -Be '192.0.2.55'
        $rows[0].AccountNotRecorded | Should -BeFalse
    }

    It 'AC7_KdcsvcBlockWithNoReadableAccountIsKeptAndFlagged' {
        # A block row whose account can't be read must never be filtered out: dropping it
        # turns "a block was logged, check it" into a clean result.
        $xml = "<Event xmlns=`"http://schemas.microsoft.com/win/2004/08/events/event`"><System><Provider Name=`"Kdcsvc`"/><EventID>204</EventID><TimeCreated SystemTime=`"2026-10-17T09:31:00.000Z`"/></System><EventData><Data Name=`"Unknown1`"></Data></EventData></Event>"
        $rows = @(ConvertFrom-KdcsvcEvent -EventXml $xml -EventId 204 -DcName 'DC02' -Message '')
        $rows.Count | Should -Be 1
        $rows[0].AccountNotRecorded | Should -BeTrue

        $kept = @(Select-EtypeEvidenceForAccount -Rows @($rows[0], (New-EtypeRow -Account 'asmith')) -SamAccountName 'jdoe')
        $kept.Count | Should -Be 1
        $kept[0].AccountNotRecorded | Should -BeTrue

        $v = @(Get-LockoutVerdict -Lockouts @() -BadLogons @() -Policy $script:Policy -EtypeEvidence $kept -EtypeGate @(New-GateRow -Dc 'DC02'))
        $text = $v -join "`n"
        $text | Should -Match "an encryption-type block was logged on DC02 but the account couldn't be read - check the event"
        # It is not known to concern this account, so it must not become "not a password problem".
        $text | Should -Not -Match 'Not a password problem'
    }

    It 'AC17_UnreadableKdcsvcBlockShowsTheEventMessageInTheReport' {
        $row = [pscustomobject]@{ Time = [datetime]'2026-10-17T09:31:00Z'; EventId = 204; Account = ''; Service = ''
                                  Accounts = @(); ClientAddress = ''; Status = ''; DC = 'DC02'; Who = 'Account'
                                  NextStep = $script:Ref.EncryptionTypeBlocks.KdcsvcEvents[204].NextStep
                                  Message = 'The KDC blocked a ticket: <odd layout>'; AccountNotRecorded = $true }
        $user = [pscustomobject]@{ SamAccountName = 'jdoe'; DistinguishedName = 'CN=jdoe,OU=Users,DC=contoso,DC=com'
                                   LockedOut = $false; badPwdCount = 0; lockoutTime = 0; pwdLastSet = 0; LastBadPasswordAttempt = $null }
        $path = Write-LockoutReport -User $user -Policy $script:Policy -Lockouts @() -BadLogons @() -Resets @() `
            -Verdict @('x') -EntraConnectDiagnostics $null -OutputPath $TestDrive -DaysBack 7 -DcList @('DC02') -Pdc 'DC02' `
            -EtypeEvidence @($row) -EtypeGate @(New-GateRow -Dc 'DC02')
        $html = Get-Content -LiteralPath $path -Raw
        $section = $html.Substring($html.IndexOf('<h2>Encryption-type blocks</h2>'))
        $section | Should -Match 'The KDC blocked a ticket: &lt;odd layout&gt;'
        $section | Should -Match "account couldn't be read"
    }
}

Describe 'Matching the investigated account' {
    It 'AC7_KeepsOnlyRowsForTheInvestigatedAccount' {
        $rows = @(
            (New-EtypeRow -Account 'jdoe'),
            (New-EtypeRow -Account 'CONTOSO\jdoe'),
            (New-EtypeRow -Account 'JDoe@contoso.com'),
            (New-EtypeRow -Account 'svc-other' -Service 'jdoe'),
            (New-EtypeRow -Account 'asmith')
        )
        $kept = @(Select-EtypeEvidenceForAccount -Rows $rows -SamAccountName 'jdoe')
        $kept.Count | Should -Be 4
        @($kept | Where-Object { $_.Account -eq 'asmith' }).Count | Should -Be 0
    }
}

Describe 'Per-DC gate' {
    It 'AC8_UnreachableDcIsCantTellForBothFeatures' {
        $g = Get-EtypeGate -DcName 'DC02' -QueryError 'RPC server is unavailable'
        $g.DC             | Should -Be 'DC02'
        $g.KdcEvents      | Should -Be "Can't tell"
        $g.TicketFailures | Should -Be "Can't tell"
        $g.KdcReason      | Should -Be "couldn't reach DC02: RPC server is unavailable"
        $g.TicketReason   | Should -Be "couldn't reach DC02: RPC server is unavailable"
        $g.Reason         | Should -Match "couldn't reach DC02"
    }

    It 'AC9_ProviderWithoutEvent203IsCantTellNamingKB5073381' {
        $g = Get-EtypeGate -DcName 'DC03' -KdcEventIds @(201, 202, 204) -AuditSetting 'Success and Failure'
        $g.KdcEvents      | Should -Be "Can't tell"
        $g.KdcReason      | Should -Match 'KB5073381'
        $g.TicketFailures | Should -Be 'Checked' -Because 'the 4768/4769 feature is evaluated on its own'
    }

    It 'AC10_TicketAuditNotLoggingFailuresOrUnreadableIsCantTell' {
        $ids = @(203, 204, 208, 209)
        foreach ($setting in 'Success', 'No Auditing') {
            $g = Get-EtypeGate -DcName 'DC01' -KdcEventIds $ids -AuditSetting $setting
            $g.TicketFailures | Should -Be "Can't tell" -Because $setting
            $g.TicketReason   | Should -Match 'not logging failures' -Because $setting
            $g.KdcEvents      | Should -Be 'Checked' -Because 'KDC events are evaluated on their own'
        }
        $g = Get-EtypeGate -DcName 'DC01' -KdcEventIds $ids -AuditSetting $null
        $g.TicketFailures | Should -Be "Can't tell"
        $g.TicketReason   | Should -Be "audit policy couldn't be read - needs admin rights on the DC"
    }

    It 'AC11_ReachablePatchedDcWithFailureAuditingIsChecked' {
        foreach ($setting in 'Failure', 'Success and Failure') {
            $g = Get-EtypeGate -DcName 'DC01' -KdcEventIds @(203, 204, 208, 209) -AuditSetting $setting
            $g.KdcEvents      | Should -Be 'Checked' -Because $setting
            $g.TicketFailures | Should -Be 'Checked' -Because $setting
        }
    }
}

Describe 'Verdict' {
    It 'AC12_EtypeRowAloneBecomesTheHeadline' {
        $v = @(Get-LockoutVerdict -Lockouts @() -BadLogons @() -Policy $script:Policy -EtypeEvidence @(New-EtypeRow) -EtypeGate @(New-GateRow))
        $v.Count | Should -BeGreaterThan 0
        $v[0] | Should -BeLike 'Not a password problem: encryption type blocked*'
        $v[0] | Should -Match 'jdoe'
        $v[0] | Should -Match '(?i)next step|reset|update|replace'
        # A 4769 row does not say which side to fix, so the next step is the psd1 FailureNextStep.
        $v[0] | Should -Match ([regex]::Escape("Next step: $($script:Ref.EncryptionTypeBlocks.FailureNextStep)"))
        foreach ($line in $v) {
            if ($line -match 'no on-prem lockout or bad-password events') {
                $line | Should -Match '(?i)encryption type' -Because 'the empty-result line must also state the block'
            }
        }
    }

    It 'AC13_KdcsvcWhoDecidesTheNextStep' {
        # Who = Account (event 204): reset the password so the account gets AES keys.
        $acct = @(Get-LockoutVerdict -Lockouts @() -BadLogons @() -Policy $script:Policy `
            -EtypeEvidence @(New-KdcsvcRow -EventId 204 -Who 'Account') -EtypeGate @(New-GateRow))
        $acct[0] | Should -BeLike 'Not a password problem: encryption type blocked*'
        $acct[0] | Should -Match 'svc-scan'
        $acct[0] | Should -Match '(?i)reset'
        $acct[0] | Should -Match 'AES'
        $acct[0] | Should -Match ([regex]::Escape($script:Ref.EncryptionTypeBlocks.KdcsvcEvents[204].NextStep))

        # Who = Client (event 208): name the device/address, RC4-only, update or replace it;
        # the RC4 exception only as a last resort, needing sign-off (D-024).
        $cli = @(Get-LockoutVerdict -Lockouts @() -BadLogons @() -Policy $script:Policy `
            -EtypeEvidence @(New-KdcsvcRow -EventId 208 -Who 'Client') -EtypeGate @(New-GateRow))
        $text = $cli -join "`n"
        $cli[0] | Should -BeLike 'Not a password problem: encryption type blocked*'
        $text | Should -Match '192\.0\.2\.77'
        $text | Should -Match 'only offers RC4'
        $text | Should -Match '(?i)update or replace'
        $text | Should -Match '(?i)last resort'
        $text | Should -Match '(?i)sign-off'
        $text.IndexOf('update or replace', [StringComparison]::OrdinalIgnoreCase) |
            Should -BeLessThan $text.IndexOf('last resort', [StringComparison]::OrdinalIgnoreCase)
    }

    It 'AC14_RealLockoutsStayTheHeadlineAndEtypeIsListedLater' {
        $v = @(Get-LockoutVerdict -Lockouts @($script:LockRow) -BadLogons @($script:BadRow) -Policy $script:Policy `
            -EtypeEvidence @(New-EtypeRow) -EtypeGate @(New-GateRow))
        $v[0] | Should -BeLike 'Most lockouts*'
        $idx = -1
        for ($i = 1; $i -lt $v.Count; $i++) { if ($v[$i] -like '*encryption type blocked*') { $idx = $i; break } }
        $idx | Should -BeGreaterThan 0
    }

    It 'AC15_CantTellDcIsNamedAndNeverRuledOut' {
        $gate = @((New-GateRow -Dc 'DC01'), (New-GateRow -Dc 'DC02' -Gap $true -Reason "couldn't reach DC02: RPC server is unavailable"))
        $v = @(Get-LockoutVerdict -Lockouts @($script:LockRow) -BadLogons @() -Policy $script:Policy -EtypeEvidence @() -EtypeGate $gate)
        $hits = @($v | Where-Object { $_ -match 'DC02' })
        $hits.Count | Should -Be 1
        $hits[0] | Should -Match "couldn't reach DC02: RPC server is unavailable"
        @($v | Where-Object { $_ -match 'DC01' -and $_ -match "(?i)can't tell|couldn't" }).Count | Should -Be 0
        @($v | Where-Object { $_ -match '(?i)no encryption.type blocks|ruled out|not blocked|no blocks' }).Count | Should -Be 0
    }

    It 'AC16_CleanEtypeResultLeavesTheVerdictUnchanged' {
        $gate = @((New-GateRow -Dc 'DC01'), (New-GateRow -Dc 'DC02'))
        $inputs = @(
            @{ L = @($script:LockRow); B = @($script:BadRow) },
            @{ L = @();                B = @($script:BadRow) },
            @{ L = @();                B = @() }
        )
        foreach ($i in $inputs) {
            $today = @(Get-LockoutVerdict -Lockouts $i.L -BadLogons $i.B -Policy $script:Policy)
            $with  = @(Get-LockoutVerdict -Lockouts $i.L -BadLogons $i.B -Policy $script:Policy -EtypeEvidence @() -EtypeGate $gate)
            ($with -join "`n") | Should -BeExactly ($today -join "`n")
            $today.Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Report' {
    BeforeAll {
        function Invoke-Report {
            param($Verdict, $Evidence, $Gate, $Lockouts = @(), $BadLogons = @(), [string]$Name = 'jdoe')
            $user = [pscustomobject]@{ SamAccountName = $Name; DistinguishedName = "CN=$Name,OU=Users,DC=contoso,DC=com"
                                       LockedOut = $false; badPwdCount = 0; lockoutTime = 0; pwdLastSet = 0
                                       LastBadPasswordAttempt = $null }
            $path = Write-LockoutReport -User $user -Policy $script:Policy -Lockouts $Lockouts -BadLogons $BadLogons `
                -Resets @() -Verdict $Verdict -EntraConnectDiagnostics $null -OutputPath $TestDrive `
                -DaysBack 7 -DcList @('DC01') -Pdc 'DC01' -EtypeEvidence $Evidence -EtypeGate $Gate
            Get-Content -LiteralPath $path -Raw
        }
    }

    It 'AC17_ReportHasEncryptionTypeSectionWithEncodedEvidence' {
        $bad = '<script>x</script>'
        $gate = @((New-GateRow -Dc 'DC01'), (New-GateRow -Dc 'DC02' -Gap $true -Reason "couldn't reach DC02: RPC server is unavailable"))
        $html = Invoke-Report -Verdict @('Not a password problem: encryption type blocked') `
            -Evidence @(New-EtypeRow -Account $bad) -Gate $gate
        $html | Should -Match '<h2>Encryption-type blocks</h2>'
        foreach ($h in 'DC', 'KDC events', '4768/4769 failures', 'Reason') { $html | Should -Match "<th[^>]*>$([regex]::Escape($h))</th>" }
        $html | Should -Match "couldn't reach DC02"
        $html | Should -Match '&lt;script&gt;x&lt;/script&gt;'
        $html | Should -Not -Match '<script>x</script>'
    }

    It 'AC18_EtypeRowsWithoutLockoutsUseTheBadVerdictClass' {
        $html = Invoke-Report -Verdict @('Not a password problem: encryption type blocked') `
            -Evidence @(New-EtypeRow) -Gate @(New-GateRow)
        $html | Should -Match 'class="verdict bad"'
        $html | Should -Not -Match 'class="verdict warn"'
    }

    It 'AC19_EmptyStateAndGapsComeBeforeEvidence' {
        $html = Invoke-Report -Verdict @('No clear cause') -Evidence @() -Gate @((New-GateRow -Dc 'DC01'), (New-GateRow -Dc 'DC02'))
        $html | Should -Match 'None found on the 2 domain controller\(s\) checked'

        $gate = @((New-GateRow -Dc 'DC-EVID'), (New-GateRow -Dc 'DC-GAP' -Gap $true -Reason "couldn't reach DC-GAP: RPC server is unavailable"))
        $html2 = Invoke-Report -Verdict @('Not a password problem: encryption type blocked') `
            -Evidence @(New-EtypeRow -Service 'svc-unique-evidence' -Dc 'DC-EVID') -Gate $gate
        $section = $html2.Substring($html2.IndexOf('<h2>Encryption-type blocks</h2>'))
        $section.IndexOf('DC-GAP') | Should -BeGreaterThan -1
        $section.IndexOf('svc-unique-evidence') | Should -BeGreaterThan -1
        $section.IndexOf('DC-GAP') | Should -BeLessThan $section.IndexOf('svc-unique-evidence')
    }
}

Describe 'Collection' {
    BeforeAll {
        # CSV as `auditpol /get /subcategory:{GUID} /r` prints it (parsed by ConvertFrom-AuditPolCsv).
        function Get-AuditCsv {
            param([string]$Setting)
            "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting`r`n" +
            "DC,System,Kerberos Service Ticket Operations,{0CCE9240-69AE-11D9-BED3-505054503030},$Setting,"
        }
        $script:Calls = @()
        $script:SecurityFilter = $null
    }

    BeforeEach {
        $script:Calls = @()
        $script:SecurityFilter = $null
        $script:NoEventsMessage = 'No events were found that match the specified selection criteria.'
        Mock Invoke-Command { Get-AuditCsv -Setting 'Success and Failure' }
        Mock Get-WinEvent {
            $script:Calls += [pscustomobject]@{ Dc = $ComputerName; Kind = $(if ($ListProvider) { 'Provider' } else { $FilterHashtable.LogName }) }
            if ($ComputerName -eq 'DC02') { throw 'RPC server is unavailable' }
            if ($ListProvider) {
                return [pscustomobject]@{ Name = 'Kdcsvc'; Events = @(203, 204, 208, 209 | ForEach-Object { [pscustomobject]@{ Id = $_ } }) }
            }
            if ($FilterHashtable.LogName -eq 'Security') {
                $script:SecurityFilter = $FilterHashtable
                if ($script:SecurityThrowsNoEvents) { throw $script:NoEventsMessage }
                return @(New-FakeEvent -Id 4769 -Xml (New-KerbXml -EventId 4769 -Status '0xe' -User 'jdoe' -Service 'svc-scan'))
            }
            throw $script:NoEventsMessage
        }
        $script:SecurityThrowsNoEvents = $false
    }

    It 'AC20_OneUnreachableDcNeverHaltsTheSweep' {
        $r = Get-EtypeEvidence -DomainControllers @('DC01', 'DC02', 'DC03') -SamAccountName 'jdoe' -DaysBack 7
        $dcs = @($r.Rows | ForEach-Object { $_.DC } | Sort-Object -Unique)
        $dcs | Should -Contain 'DC01'
        $dcs | Should -Contain 'DC03'
        $dcs | Should -Not -Contain 'DC02'
        $g2 = @($r.Gate | Where-Object { $_.DC -eq 'DC02' })
        $g2.Count | Should -Be 1
        $g2[0].KdcEvents      | Should -Be "Can't tell"
        $g2[0].TicketFailures | Should -Be "Can't tell"
        $g2[0].KdcReason      | Should -Match 'RPC server is unavailable'
        @($r.Gate | Where-Object { $_.DC -in 'DC01', 'DC03' -and $_.KdcEvents -eq 'Checked' -and $_.TicketFailures -eq 'Checked' }).Count | Should -Be 2
    }

    It 'AC21_SecurityQueryUsesSystemFieldFilterAndNoXPath' {
        $null = Get-EtypeEvidence -DomainControllers @('DC01') -SamAccountName 'jdoe' -DaysBack 7
        $f = $script:SecurityFilter
        $f | Should -Not -BeNullOrEmpty
        $f.LogName | Should -Be 'Security'
        @($f.Id) | Should -Contain 4768
        @($f.Id) | Should -Contain 4769
        [long]@($f.Keywords)[0] | Should -Be 4503599627370496   # StandardEventKeywords.AuditFailure
        $f.StartTime | Should -BeOfType [datetime]
        # EventData XPath / Data filters force full log scans (Export-ADAuthSourceEvidence .NOTES).
        @($f.Keys | Where-Object { $_ -notin 'LogName', 'Id', 'Keywords', 'StartTime', 'EndTime' }).Count | Should -Be 0
        Should -Invoke Get-WinEvent -Times 0 -Exactly -ParameterFilter { $FilterXPath }
    }

    It 'AC22_NoEventsFoundIsReachableWithZeroEventsNotCantTell' {
        $script:SecurityThrowsNoEvents = $true
        $r = Get-EtypeEvidence -DomainControllers @('DC01') -SamAccountName 'jdoe' -DaysBack 7
        @($r.Rows).Count | Should -Be 0
        $g = @($r.Gate)[0]
        $g.KdcEvents      | Should -Be 'Checked'
        $g.TicketFailures | Should -Be 'Checked'
    }

    It 'AC9_ProviderListFailureStillReadsTheSystemLog' {
        # The -ListProvider probe only explains an empty result; it must never stop the
        # System-log read, or a real 204 is missed and the DC looks clean.
        Mock Get-WinEvent {
            if ($ListProvider) { throw 'The RPC server is too busy to complete this operation.' }
            if ($FilterHashtable.LogName -eq 'Security') { throw $script:NoEventsMessage }
            return @(New-FakeEvent -Id 204 -Xml (New-KdcsvcXml -EventId 204))
        }
        $r = Get-EtypeEvidence -DomainControllers @('DC01') -SamAccountName 'jdoe' -DaysBack 7
        @($r.Rows | Where-Object { $_.EventId -eq 204 }).Count | Should -Be 1
        @($r.Gate)[0].KdcEvents | Should -Be 'Checked'
        Should -Invoke Get-WinEvent -Times 1 -Exactly -ParameterFilter { $FilterHashtable -and $FilterHashtable.LogName -eq 'System' }
    }

    It 'AC9_EmptyProviderListWithNoEventsIsCantTellWithoutBlamingTheUpdate' {
        Mock Get-WinEvent {
            if ($ListProvider) { return [pscustomobject]@{ Name = 'Kdcsvc'; Events = @() } }
            throw $script:NoEventsMessage
        }
        $g = @((Get-EtypeEvidence -DomainControllers @('DC01') -SamAccountName 'jdoe' -DaysBack 7).Gate)[0]
        $g.KdcEvents | Should -Be "Can't tell"
        $g.KdcReason | Should -Match "couldn't read the Kdcsvc event list"
        $g.KdcReason | Should -Not -Match 'KB5073381'

        Mock Get-WinEvent {
            if ($ListProvider) { throw 'Access is denied' }
            throw $script:NoEventsMessage
        }
        $g = @((Get-EtypeEvidence -DomainControllers @('DC01') -SamAccountName 'jdoe' -DaysBack 7).Gate)[0]
        $g.KdcEvents | Should -Be "Can't tell"
        $g.KdcReason | Should -Match "couldn't read the Kdcsvc event list"
        $g.KdcReason | Should -Not -Match 'KB5073381'
    }

    It 'AC9_UnregisteredKdcsvcProviderNamesTheUpdate' {
        Mock Get-WinEvent {
            if ($ListProvider) { throw 'There is not an event provider on the DC01 computer that matches "Kdcsvc".' }
            if ($FilterHashtable.LogName -eq 'System') { throw 'There is not an event provider on the DC01 computer that matches "Kdcsvc".' }
            throw $script:NoEventsMessage
        }
        $g = @((Get-EtypeEvidence -DomainControllers @('DC01') -SamAccountName 'jdoe' -DaysBack 7).Gate)[0]
        $g.KdcEvents | Should -Be "Can't tell"
        $g.KdcReason | Should -Match 'KB5073381'
    }

    It 'AC20_MalformedSecurityEventDegradesThatDcToCantTell' {
        Mock Get-WinEvent {
            if ($ListProvider) {
                return [pscustomobject]@{ Name = 'Kdcsvc'; Events = @(203, 204, 208, 209 | ForEach-Object { [pscustomobject]@{ Id = $_ } }) }
            }
            if ($FilterHashtable.LogName -eq 'Security') {
                if ($ComputerName -eq 'DC01') { return @(New-FakeEvent -Id 4769 -Xml '<Event><broken') }
                return @(New-FakeEvent -Id 4769 -Xml (New-KerbXml -EventId 4769 -Status '0xe'))
            }
            throw $script:NoEventsMessage
        }
        $r = Get-EtypeEvidence -DomainControllers @('DC01', 'DC03') -SamAccountName 'jdoe' -DaysBack 7
        $g1 = @($r.Gate | Where-Object { $_.DC -eq 'DC01' })[0]
        $g1.TicketFailures | Should -Be "Can't tell"
        $g1.TicketReason   | Should -Match "couldn't read the 4768/4769 events on DC01"
        @($r.Rows | Where-Object { $_.DC -eq 'DC03' }).Count | Should -Be 1
        @($r.Gate | Where-Object { $_.DC -eq 'DC03' })[0].TicketFailures | Should -Be 'Checked'
    }
}

Describe 'Findings CSV' {
    It 'AC23_FindingsCsvCellsCannotRunAsFormulas' {
        # Account and service names come from the client's directory, so they are untrusted:
        # a cell starting with = + - @ (or tab/CR) must open in Excel as text.
        # https://owasp.org/www-community/attacks/CSV_Injection
        $f = [pscustomobject]@{ Kind = 'Account'; Account = '=HYPERLINK("http://x")'; ClientAddress = '+192.0.2.1'
                                DC = '@DC01'; Sentence = '-Not a password problem'; NextStep = 'Reset it.' }
        $g = New-GateRow -Dc "`tDC02" -Gap $true -Reason '=cmd'
        $path = Export-EtypeFindingsCsv -Findings @($f) -Gate @($g) -SamAccountName 'jdoe' -OutputPath $TestDrive
        $rows = @(Import-Csv -LiteralPath $path)
        $rows[0].Account       | Should -Be "'=HYPERLINK(`"http://x`")"
        $rows[0].ClientAddress | Should -Be "'+192.0.2.1"
        $rows[0].DC            | Should -Be "'@DC01"
        $rows[0].Sentence      | Should -Be "'-Not a password problem"
        $rows[0].NextStep      | Should -Be 'Reset it.'
        $rows[1].Kind          | Should -Be 'CantTell'
        $rows[1].Reason        | Should -Be "'=cmd"
        $rows[1].DC            | Should -Be "'`tDC02"
    }
}
