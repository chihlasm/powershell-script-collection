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
