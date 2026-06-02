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
    It 'summarizes the bad-logon source with a plain-English logon type' {
        $bad = @(
            [PSCustomObject]@{SourceHost='LAPTOP-7'; SourceIp='192.168.1.50'; LogonType='3'},
            [PSCustomObject]@{SourceHost='LAPTOP-7'; SourceIp='192.168.1.50'; LogonType='3'}
        )
        $v = Get-LockoutVerdict -Lockouts @() -BadLogons $bad -Policy ([PSCustomObject]@{LockoutThreshold=5})
        ($v -join ' ') | Should -Match 'LAPTOP-7'
        ($v -join ' ') | Should -Match 'mapped drive'
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
}
