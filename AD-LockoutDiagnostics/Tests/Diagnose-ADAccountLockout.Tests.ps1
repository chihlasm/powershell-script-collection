BeforeAll {
    . "$PSScriptRoot\..\Diagnose-ADAccountLockout.ps1" -Identity '__pester__' -LoadFunctionsOnly
}

Describe 'ConvertFrom-LockoutEvent' {
    It 'extracts TargetUserName and CallerComputerName from event XML' {
        $xml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><TimeCreated SystemTime="2026-06-01T13:05:00.000Z"/></System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="TargetDomainName">CONTOSO</Data>
    <Data Name="CallerComputerName">LAPTOP-7</Data>
  </EventData>
</Event>
'@
        $row = ConvertFrom-LockoutEvent -EventXml $xml -DcName 'DC01'
        $row.User           | Should -Be 'jdoe'
        $row.CallerComputer | Should -Be 'LAPTOP-7'
        $row.DC             | Should -Be 'DC01'
    }
}

Describe 'lockoutTime interpretation (verified against MS-ADTS)' {
    # A non-zero lockoutTime does NOT mean the account is locked now. Per [MS-ADTS], the
    # ADS_UF_LOCKOUT bit is set only while the lockout duration has not elapsed, and AD
    # never clears lockoutTime on auto-unlock. Showing the raw timestamp reads as "still
    # locked" and sends the helpdesk to unlock a working account.
    # https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/b80798ae-1f8c-4d30-9d80-a1f3281e96e2
    BeforeAll {
        $script:Policy = [PSCustomObject]@{ Source='Default Domain Policy'; LockoutThreshold=3
                                            LockoutObservationWindow='00:30:00'; LockoutDuration='00:30:00' }
        function New-TestUser {
            param([bool]$LockedOut, $LockoutTime)
            [PSCustomObject]@{ SamAccountName='jdoe'; DistinguishedName='CN=jdoe,DC=x'
                               LockedOut=$LockedOut; badPwdCount=2
                               LastBadPasswordAttempt=(Get-Date); pwdLastSet=133000000000000000
                               lockoutTime=$LockoutTime }
        }
        function Get-ReportHtml {
            param($User)
            $out = Join-Path ([System.IO.Path]::GetTempPath()) ("lt-" + [guid]::NewGuid().ToString('N'))
            try {
                $p = Write-LockoutReport -User $User -Policy $script:Policy -Lockouts @() -BadLogons @() `
                        -Resets @() -Verdict @('test') -OutputPath $out -DaysBack 7 `
                        -DcList @('DC01') -Pdc 'DC01' -EntraConnectDiagnostics $null
                Get-Content -Raw -Path $p
            } finally { if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Recurse -Force } }
        }
    }

    It 'labels a stale lockoutTime as auto-unlocked when LockedOut is false' {
        $html = Get-ReportHtml -User (New-TestUser -LockedOut $false -LockoutTime 133000000000000000)
        $html | Should -Match 'has since auto-unlocked'
        $html | Should -Not -Match 'still locked'
    }

    It 'labels the timestamp as still locked when LockedOut is true' {
        $html = Get-ReportHtml -User (New-TestUser -LockedOut $true -LockoutTime 133000000000000000)
        $html | Should -Match 'still locked'
    }

    It 'renders a zero lockoutTime as "Never locked out", not 1601-01-01' {
        $html = Get-ReportHtml -User (New-TestUser -LockedOut $false -LockoutTime 0)
        $html | Should -Match 'Never locked out'
        $html | Should -Not -Match '1601-01-01'
    }
}

Describe 'ConvertFrom-BadLogonEvent status selection (verified against Microsoft Learn)' {
    # Regression guard: SubStatus was preferred whenever the field existed, but SubStatus
    # is often 0x0 ("no error") while Status carries the real reason. Microsoft's own
    # sample for a locked-out account is Status=0xC0000234 with SubStatus=0x0.
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625

    It 'falls back to Status when SubStatus is 0x0' {
        $xml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><TimeCreated SystemTime="2026-08-12T08:18:02.000Z"/></System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="WorkstationName">WKS-1</Data>
    <Data Name="IpAddress">10.0.0.5</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="Status">0xC0000234</Data>
    <Data Name="SubStatus">0x0</Data>
  </EventData>
</Event>
'@
        $row = ConvertFrom-BadLogonEvent -EventXml $xml -EventId 4625 -DcName 'DC01'
        # 0xC0000234 = account locked out. Reporting 0x0 would hide the reason entirely.
        $row.Status | Should -Be '0xC0000234'
    }

    It 'still prefers SubStatus when it carries a real reason' {
        $xml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><TimeCreated SystemTime="2026-08-12T08:18:02.000Z"/></System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="Status">0xC000006D</Data>
    <Data Name="SubStatus">0xC000006A</Data>
  </EventData>
</Event>
'@
        $row = ConvertFrom-BadLogonEvent -EventXml $xml -EventId 4625 -DcName 'DC01'
        # Status 0xC000006D is the generic "bad username or authentication info";
        # SubStatus 0xC000006A is the precise "bad password".
        $row.Status | Should -Be '0xC000006A'
    }

    It 'treats a padded zero SubStatus as empty too' {
        $xml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><TimeCreated SystemTime="2026-08-12T08:18:02.000Z"/></System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="Status">0xC0000234</Data>
    <Data Name="SubStatus">0x00000000</Data>
  </EventData>
</Event>
'@
        $row = ConvertFrom-BadLogonEvent -EventXml $xml -EventId 4625 -DcName 'DC01'
        $row.Status | Should -Be '0xC0000234'
    }
}

Describe 'ConvertFrom-BadLogonEvent' {
    It 'parses a 4625 failed-logon event into a normalized row' {
        $xml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><TimeCreated SystemTime="2026-06-01T09:00:00.000Z"/></System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="WorkstationName">LAPTOP-7</Data>
    <Data Name="IpAddress">192.168.1.50</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="SubStatus">0xC000006A</Data>
  </EventData>
</Event>
'@
        $row = ConvertFrom-BadLogonEvent -EventXml $xml -EventId 4625 -DcName 'DC01'
        $row.EventId    | Should -Be 4625
        $row.User       | Should -Be 'jdoe'
        $row.SourceHost | Should -Be 'LAPTOP-7'
        $row.SourceIp   | Should -Be '192.168.1.50'
        $row.LogonType  | Should -Be '3'
        $row.Status     | Should -Be '0xC000006A'
        $row.DC         | Should -Be 'DC01'
        $row.Time       | Should -BeOfType [datetime]
    }

    It 'parses a 4771 Kerberos pre-auth event and leaves ::ffff: addresses unchanged' {
        $xml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><TimeCreated SystemTime="2026-06-01T10:15:00.000Z"/></System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="IpAddress">::ffff:192.168.1.5</Data>
    <Data Name="Status">0x18</Data>
  </EventData>
</Event>
'@
        $row = ConvertFrom-BadLogonEvent -EventXml $xml -EventId 4771 -DcName 'DC02'
        $row.EventId    | Should -Be 4771
        $row.User       | Should -Be 'jdoe'
        $row.SourceIp   | Should -Be '::ffff:192.168.1.5'
        $row.SourceHost | Should -BeNullOrEmpty
        $row.LogonType  | Should -BeNullOrEmpty
        $row.Status     | Should -Be '0x18'
        $row.DC         | Should -Be 'DC02'
    }

    It 'normalizes a 4625 with IpAddress "-" to (local)' {
        $xml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><TimeCreated SystemTime="2026-06-01T11:00:00.000Z"/></System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="WorkstationName">SERVER-1</Data>
    <Data Name="IpAddress">-</Data>
    <Data Name="LogonType">2</Data>
    <Data Name="Status">0xC000006D</Data>
  </EventData>
</Event>
'@
        $row = ConvertFrom-BadLogonEvent -EventXml $xml -EventId 4625 -DcName 'DC01'
        $row.SourceIp | Should -Be '(local)'
    }

    It 'normalizes a 4625 with IpAddress ::1 to (local)' {
        $xml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><TimeCreated SystemTime="2026-06-01T11:30:00.000Z"/></System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="WorkstationName">SERVER-1</Data>
    <Data Name="IpAddress">::1</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="SubStatus">0xC000006A</Data>
  </EventData>
</Event>
'@
        $row = ConvertFrom-BadLogonEvent -EventXml $xml -EventId 4625 -DcName 'DC01'
        $row.SourceIp | Should -Be '(local)'
    }
}

Describe 'Get-LockoutVerdict' {
    It 'fingers the dominant caller computer' {
        $lockouts = @(
            [PSCustomObject]@{CallerComputer='LAPTOP-7'},
            [PSCustomObject]@{CallerComputer='LAPTOP-7'},
            [PSCustomObject]@{CallerComputer='PHONE-1'}
        )
        $v = Get-LockoutVerdict -Lockouts $lockouts -BadLogons @() -Policy ([PSCustomObject]@{LockoutThreshold=5})
        ($v -join ' ') | Should -Match 'LAPTOP-7'
    }
    It 'flags aggressive policy' {
        $v = Get-LockoutVerdict -Lockouts @() -BadLogons @() -Policy ([PSCustomObject]@{LockoutThreshold=3})
        ($v -join ' ') | Should -Match 'aggressive'
    }
    It 'notes no evidence' {
        $v = Get-LockoutVerdict -Lockouts @() -BadLogons @() -Policy ([PSCustomObject]@{LockoutThreshold=5})
        ($v -join ' ') | Should -Match 'no on-prem'
    }
    It 'points PHS-only synced accounts toward Entra sign-in evidence when AD has no evidence' {
        $v = Get-LockoutVerdict -Lockouts @() -BadLogons @() -Policy ([PSCustomObject]@{LockoutThreshold=5})
        ($v -join ' ') | Should -Match 'Password Hash Sync|PHS'
        ($v -join ' ') | Should -Match 'Entra'
    }
    It 'summarizes the bad-logon source with a plain-English logon type' {
        $bad = @(
            [PSCustomObject]@{SourceHost='LAPTOP-7'; SourceIp='192.168.1.50'; LogonType='3'},
            [PSCustomObject]@{SourceHost='LAPTOP-7'; SourceIp='192.168.1.50'; LogonType='3'}
        )
        $v = Get-LockoutVerdict -Lockouts @() -BadLogons $bad -Policy ([PSCustomObject]@{LockoutThreshold=5})
        ($v -join ' ') | Should -Match 'LAPTOP-7'
        ($v -join ' ') | Should -Match 'mapped drive'
    }
    It 'calls out PTA when bad-password attempts originate from an Entra Connect agent host' {
        $bad = @(
            [PSCustomObject]@{SourceHost='ENTRACONNECT01'; SourceIp='10.10.1.20'; LogonType='3'},
            [PSCustomObject]@{SourceHost='ENTRACONNECT01'; SourceIp='10.10.1.20'; LogonType='3'}
        )
        $v = Get-LockoutVerdict -Lockouts @() -BadLogons $bad -Policy ([PSCustomObject]@{LockoutThreshold=5})
        ($v -join ' ') | Should -Match 'Pass-through Authentication|PTA'
        ($v -join ' ') | Should -Match 'Entra Connect'
    }
    It 'returns an ordered array: dominant caller before policy note' {
        $lockouts = @(
            [PSCustomObject]@{CallerComputer='LAPTOP-7'},
            [PSCustomObject]@{CallerComputer='LAPTOP-7'}
        )
        $v = Get-LockoutVerdict -Lockouts $lockouts -BadLogons @() -Policy ([PSCustomObject]@{LockoutThreshold=2})
        $v[0] | Should -Match 'LAPTOP-7'
        ($v -join ' ') | Should -Match 'aggressive'
    }
    It 'tolerates null inputs without error' {
        $v = Get-LockoutVerdict -Lockouts $null -BadLogons $null -Policy ([PSCustomObject]@{LockoutThreshold=5})
        ($v -join ' ') | Should -Match 'no on-prem'
    }
    It 'flags possible compromise when many distinct callers and none dominate' {
        $lockouts = @(
            [PSCustomObject]@{CallerComputer='HOST-A'},
            [PSCustomObject]@{CallerComputer='HOST-B'},
            [PSCustomObject]@{CallerComputer='HOST-C'},
            [PSCustomObject]@{CallerComputer='HOST-D'},
            [PSCustomObject]@{CallerComputer='HOST-E'}
        )
        $v = Get-LockoutVerdict -Lockouts $lockouts -BadLogons @() -Policy ([PSCustomObject]@{LockoutThreshold=5})
        ($v -join ' ') | Should -Match 'compromised credential|password-guessing'
    }
    It 'keeps Entra Connect hints when no on-prem evidence is found' {
        $diag = [PSCustomObject]@{
            Server = 'ENTRACONNECT01'
            HybridAuthMode = 'PTA'
            Services = @([PSCustomObject]@{Name='AzureADConnectAuthenticationAgent'; Status='Running'; Detail='Service is running'})
            Events = @([PSCustomObject]@{AuthMode='PTA'; Status='Info'; EventId=12019; Meaning='Authentication Agent admin log event.'})
            Notes = @()
            Errors = @()
        }
        $v = Get-LockoutVerdict -Lockouts @() -BadLogons @() -Policy ([PSCustomObject]@{LockoutThreshold=5}) -EntraConnectDiagnostics $diag
        ($v -join ' ') | Should -Match 'Pass-through Authentication|PTA'
    }
}

Describe 'Get-EntraConnectEventClassification' {
    It 'classifies password hash sync heartbeat event 654 as healthy PHS evidence' {
        $c = Get-EntraConnectEventClassification -EventId 654 -LogName 'Application'
        $c.AuthMode | Should -Be 'PHS'
        $c.Status   | Should -Be 'Healthy'
        $c.Meaning  | Should -Match 'heartbeat'
    }

    It 'classifies password hash sync event 611 as an error' {
        $c = Get-EntraConnectEventClassification -EventId 611 -LogName 'Application'
        $c.AuthMode | Should -Be 'PHS'
        $c.Status   | Should -Be 'Error'
        $c.Meaning  | Should -Match 'domain'
    }

    It 'classifies Authentication Agent admin log events as PTA evidence' {
        $c = Get-EntraConnectEventClassification -EventId 12019 -LogName 'Microsoft-AzureADConnect-AuthenticationAgent/Admin'
        $c.AuthMode | Should -Be 'PTA'
        $c.Status   | Should -Be 'Info'
        $c.Meaning  | Should -Match 'Authentication Agent'
    }
}

Describe 'ConvertFrom-EntraConnectEvent' {
    It 'normalizes an Entra Connect event with classification details' {
        $xml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Directory Synchronization" />
    <EventID>654</EventID>
    <TimeCreated SystemTime="2026-06-01T12:30:00.000Z"/>
  </System>
  <EventData>
    <Data>End of password hash sync heartbeat</Data>
  </EventData>
</Event>
'@
        $row = ConvertFrom-EntraConnectEvent -EventXml $xml -EventId 654 -Server 'ENTRACONNECT01' -LogName 'Application' -Message 'Heartbeat observed'
        $row.Server   | Should -Be 'ENTRACONNECT01'
        $row.EventId  | Should -Be 654
        $row.AuthMode | Should -Be 'PHS'
        $row.Status   | Should -Be 'Healthy'
        $row.Provider | Should -Be 'Directory Synchronization'
        $row.Message  | Should -Be 'Heartbeat observed'
    }
}

Describe 'Get-EntraConnectVerdictHints' {
    It 'reports PHS errors and missing heartbeat diagnostics' {
        $diag = [PSCustomObject]@{
            Server = 'ENTRACONNECT01'
            HybridAuthMode = 'PHS'
            Services = @([PSCustomObject]@{Name='ADSync'; Status='Running'; Detail='Service is running'})
            Events = @([PSCustomObject]@{AuthMode='PHS'; Status='Error'; EventId=611; Meaning='Error during password hash sync for a domain.'})
            Notes = @('No PHS heartbeat event 654 found in the searched window.')
            Errors = @()
        }
        $hints = Get-EntraConnectVerdictHints -Diagnostics $diag
        ($hints -join ' ') | Should -Match 'Password Hash Sync|PHS'
        ($hints -join ' ') | Should -Match '611'
        ($hints -join ' ') | Should -Match 'heartbeat'
    }

    It 'reports PTA agent evidence as cloud sign-ins validated on-prem' {
        $diag = [PSCustomObject]@{
            Server = 'ENTRACONNECT01'
            HybridAuthMode = 'PTA'
            Services = @([PSCustomObject]@{Name='AzureADConnectAuthenticationAgent'; Status='Running'; Detail='Service is running'})
            Events = @([PSCustomObject]@{AuthMode='PTA'; Status='Info'; EventId=12019; Meaning='Authentication Agent admin log event.'})
            Notes = @()
            Errors = @()
        }
        $hints = Get-EntraConnectVerdictHints -Diagnostics $diag
        ($hints -join ' ') | Should -Match 'Pass-through Authentication|PTA'
        ($hints -join ' ') | Should -Match 'cloud sign-ins'
        ($hints -join ' ') | Should -Match 'on-prem'
    }

    It 'warns when the requested Entra Connect diagnostics could not reach the server' {
        $diag = [PSCustomObject]@{
            Server = 'ENTRACONNECT01'
            HybridAuthMode = 'Auto'
            Services = @()
            Events = @()
            Notes = @()
            Errors = @('Could not query ENTRACONNECT01: access denied')
        }
        $hints = Get-EntraConnectVerdictHints -Diagnostics $diag
        ($hints -join ' ') | Should -Match 'could not query'
        ($hints -join ' ') | Should -Match 'ENTRACONNECT01'
    }
}

Describe 'Get-EntraConnectDiagnostics' {
    It 'returns a not-run diagnostic object when no Entra Connect server is supplied' {
        $diag = Get-EntraConnectDiagnostics -EntraConnectServer $null -HybridAuthMode 'Auto' -DaysBack 7
        $diag.Checked | Should -BeFalse
        $diag.Notes[0] | Should -Match 'not run'
    }
}

Describe 'Write-LockoutReport hybrid diagnostics section' {
    It 'renders Entra Connect diagnostics rows in the HTML report' {
        $out = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([guid]::NewGuid().ToString())
        try {
            $user = [PSCustomObject]@{
                SamAccountName = 'jdoe'
                DistinguishedName = 'CN=John Doe,OU=Users,DC=contoso,DC=com'
                LockedOut = $true
                badPwdCount = 5
                LastBadPasswordAttempt = [datetime]'2026-06-01T12:00:00'
                pwdLastSet = [datetime]'2026-05-30T12:00:00'
                lockoutTime = [datetime]'2026-06-01T12:05:00'
            }
            $policy = [PSCustomObject]@{
                Source = 'Default Domain Policy'
                LockoutThreshold = 5
                LockoutObservationWindow = '00:15:00'
                LockoutDuration = '00:15:00'
            }
            $diag = [PSCustomObject]@{
                Server = 'ENTRACONNECT01'
                HybridAuthMode = 'PTA'
                Checked = $true
                Services = @([PSCustomObject]@{Name='AzureADConnectAuthenticationAgent'; Status='Running'; Detail='Service is running'})
                Events = @([PSCustomObject]@{Time=[datetime]'2026-06-01T12:00:00'; Server='ENTRACONNECT01'; LogName='Microsoft-AzureADConnect-AuthenticationAgent/Admin'; EventId=12019; AuthMode='PTA'; Status='Info'; Meaning='Authentication Agent admin log event.'; Provider='Microsoft-AzureADConnect-AuthenticationAgent'; Message='Agent event'})
                Notes = @('PTA diagnostics found one event.')
                Errors = @()
            }
            $path = Write-LockoutReport -User $user -Policy $policy -Lockouts @() -BadLogons @() -Resets @() `
                -Verdict @('Hybrid evidence found') -OutputPath $out -DaysBack 7 -DcList @('DC01') -Pdc 'DC01' `
                -EntraConnectDiagnostics $diag
            $html = Get-Content -Raw -Path $path
            # The section is now a collapsible disclosure rather than an <h2> heading.
            $html | Should -Match 'Entra Connect / hybrid authentication'
            $html | Should -Match 'AzureADConnectAuthenticationAgent'
            $html | Should -Match 'PTA'
            # The verdict must lead the document, ahead of any collapsed detail.
            $html.IndexOf('Most likely cause') | Should -BeLessThan $html.IndexOf('<details>')
        } finally {
            if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Recurse -Force }
        }
    }
}
