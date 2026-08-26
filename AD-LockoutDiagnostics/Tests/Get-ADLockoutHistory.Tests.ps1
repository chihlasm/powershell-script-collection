BeforeAll {
    . "$PSScriptRoot\..\Get-ADLockoutHistory.ps1" -LoadFunctionsOnly
}

Describe 'ConvertFrom-LockoutEvent' {
    # REGRESSION GUARD. These tests previously fed synthetic XML containing a
    # CallerComputerName element, which real 4740 events do not have. The tests passed
    # while production returned null for every caller, rendering every lockout source as
    # "(not recorded)". The XML below matches Microsoft's documented event.
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740
    It 'reads the caller machine from TargetDomainName, as real 4740 events emit it' {
        $xml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><TimeCreated SystemTime="2026-08-01T13:05:00.000Z"/></System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="TargetDomainName">LAPTOP-7</Data>
    <Data Name="TargetSid">S-1-5-21-1-2-3-1104</Data>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">DC01$</Data>
    <Data Name="SubjectDomainName">CONTOSO</Data>
  </EventData>
</Event>
'@
        $row = ConvertFrom-LockoutEvent -EventXml $xml -DcName 'DC01'
        $row.User           | Should -Be 'jdoe'
        $row.CallerComputer | Should -Be 'LAPTOP-7'
        $row.Domain         | Should -Be 'CONTOSO'
        $row.DC             | Should -Be 'DC01'
    }

    It 'falls back to CallerComputerName when a producer does emit it' {
        $xml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><TimeCreated SystemTime="2026-08-01T13:05:00.000Z"/></System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="SubjectDomainName">CONTOSO</Data>
    <Data Name="CallerComputerName">LAPTOP-9</Data>
  </EventData>
</Event>
'@
        $row = ConvertFrom-LockoutEvent -EventXml $xml -DcName 'DC01'
        $row.CallerComputer | Should -Be 'LAPTOP-9'
    }
}

Describe 'Group-LockoutsByAccount' {
    BeforeAll {
        $script:Sample = @(
            [PSCustomObject]@{ Time=[datetime]'2026-08-01T09:00:00'; User='svc_backup'; CallerComputer='SQLSRV02'; DC='DC01' }
            [PSCustomObject]@{ Time=[datetime]'2026-08-02T09:00:00'; User='svc_backup'; CallerComputer='SQLSRV02'; DC='DC01' }
            [PSCustomObject]@{ Time=[datetime]'2026-08-03T09:00:00'; User='svc_backup'; CallerComputer='SQLSRV02'; DC='DC01' }
            [PSCustomObject]@{ Time=[datetime]'2026-08-01T10:00:00'; User='jdoe';       CallerComputer='PHONE-JD'; DC='DC01' }
            [PSCustomObject]@{ Time=[datetime]'2026-08-04T10:00:00'; User='jdoe';       CallerComputer='LAPTOP-JD';DC='DC01' }
            [PSCustomObject]@{ Time=[datetime]'2026-08-01T11:00:00'; User='msmith';     CallerComputer='';         DC='DC01' }
            [PSCustomObject]@{ Time=[datetime]'2026-08-01T12:00:00'; User='WKS01$';     CallerComputer='WKS01';    DC='DC01' }
        )
    }

    It 'ranks the most frequently locked-out account first' {
        $result = Group-LockoutsByAccount -Lockouts $script:Sample
        $result[0].User         | Should -Be 'svc_backup'
        $result[0].LockoutCount | Should -Be 3
    }

    It 'counts distinct caller computers per account' {
        $result = Group-LockoutsByAccount -Lockouts $script:Sample
        $jdoe = $result | Where-Object { $_.User -eq 'jdoe' }
        $jdoe.DistinctSources | Should -Be 2
        $jdoe.Sources         | Should -Be 'LAPTOP-JD, PHONE-JD'
    }

    It 'labels a blank CallerComputerName rather than leaving it empty' {
        $result = Group-LockoutsByAccount -Lockouts $script:Sample
        $ms = $result | Where-Object { $_.User -eq 'msmith' }
        $ms.Sources | Should -Be '(not recorded)'
    }

    It 'flags machine accounts so they can be told apart from user accounts' {
        $result = Group-LockoutsByAccount -Lockouts $script:Sample
        ($result | Where-Object { $_.User -eq 'WKS01$' }).IsComputer | Should -BeTrue
        ($result | Where-Object { $_.User -eq 'jdoe' }).IsComputer   | Should -BeFalse
    }

    It 'reports correct first and last seen timestamps' {
        $result = Group-LockoutsByAccount -Lockouts $script:Sample
        $jdoe = $result | Where-Object { $_.User -eq 'jdoe' }
        $jdoe.FirstSeen | Should -Be ([datetime]'2026-08-01T10:00:00')
        $jdoe.LastSeen  | Should -Be ([datetime]'2026-08-04T10:00:00')
    }

    It 'applies the MinLockouts filter' {
        $result = Group-LockoutsByAccount -Lockouts $script:Sample -MinLockouts 3
        $result.Count   | Should -Be 1
        $result[0].User | Should -Be 'svc_backup'
    }

    It 'returns an empty array for empty or null input' {
        @(Group-LockoutsByAccount -Lockouts @()).Count    | Should -Be 0
        @(Group-LockoutsByAccount -Lockouts $null).Count  | Should -Be 0
    }
}

Describe 'New-LockoutHistoryHtml' {
    BeforeAll {
        $script:Rows = @(
            [PSCustomObject]@{ Time=[datetime]'2026-08-01T09:00:00'; User='svc_backup'; CallerComputer='SQLSRV02'; DC='DC01' }
        )
        $script:Summary = Group-LockoutsByAccount -Lockouts $script:Rows
    }

    It 'warns prominently when the log does not cover the requested window' {
        $cov = [PSCustomObject]@{ DC='DC01'; CoverageDays=11.4; RequestedDays=30
                                  IsComplete=$false; Note='Only 11.4 days retained.' }
        $html = New-LockoutHistoryHtml -Summary $script:Summary -Lockouts $script:Rows `
            -Coverage $cov -DcName 'DC01' -DaysBack 30 -MinLockouts 1
        $html | Should -Match 'These results are incomplete'
        $html | Should -Match 'Only 11.4 days retained'
        # Must say plainly that empty != clean, which is the whole point of the warning.
        $html | Should -Match 'no data'
    }

    It 'stays quiet about coverage when the log reaches back far enough' {
        # A clean coverage result needs no banner - noise competes with the verdict.
        $cov = [PSCustomObject]@{ DC='DC01'; CoverageDays=90; RequestedDays=30
                                  IsComplete=$true; Note='' }
        $html = New-LockoutHistoryHtml -Summary $script:Summary -Lockouts $script:Rows `
            -Coverage $cov -DcName 'DC01' -DaysBack 30 -MinLockouts 1
        $html | Should -Not -Match 'These results are incomplete'
    }

    It 'leads with a plain-English verdict naming the account and the machine' {
        $cov = [PSCustomObject]@{ DC='DC01'; CoverageDays=90; RequestedDays=30; IsComplete=$true; Note='' }
        $html = New-LockoutHistoryHtml -Summary $script:Summary -Lockouts $script:Rows `
            -Coverage $cov -DcName 'DC01' -DaysBack 30 -MinLockouts 1
        $html | Should -Match 'What this means'
        $html | Should -Match 'svc_backup'
        $html | Should -Match 'SQLSRV02'
        # The verdict must appear before the raw table, not after it.
        $html.IndexOf('What this means') | Should -BeLessThan $html.IndexOf('<details>')
    }

    It 'says "once" rather than "1 times" for a single lockout' {
        $cov = [PSCustomObject]@{ DC='DC01'; CoverageDays=90; RequestedDays=30; IsComplete=$true; Note='' }
        $html = New-LockoutHistoryHtml -Summary $script:Summary -Lockouts $script:Rows `
            -Coverage $cov -DcName 'DC01' -DaysBack 30 -MinLockouts 1
        $html | Should -Match 'locked out once'
        $html | Should -Not -Match 'locked out 1 times'
    }

    It 'collapses the raw event table so the page opens short' {
        $cov = [PSCustomObject]@{ DC='DC01'; CoverageDays=90; RequestedDays=30; IsComplete=$true; Note='' }
        $html = New-LockoutHistoryHtml -Summary $script:Summary -Lockouts $script:Rows `
            -Coverage $cov -DcName 'DC01' -DaysBack 30 -MinLockouts 1
        $html | Should -Match '<details>'
        $html | Should -Not -Match '<details open'
    }

    It 'tells the reader to check audit policy when nothing was found' {
        # An empty result is ambiguous: quiet domain, or nothing being logged. The report
        # must not let the reader assume the former.
        $cov = [PSCustomObject]@{ DC='DC01'; CoverageDays=90; RequestedDays=30; IsComplete=$true; Note='' }
        $html = New-LockoutHistoryHtml -Summary @() -Lockouts @() `
            -Coverage $cov -DcName 'DC01' -DaysBack 30 -MinLockouts 1
        $html | Should -Match 'Test-ADAuditPolicy'
        $html | Should -Match 'not recording lockouts'
    }

    It 'names a systemic cause when no single account dominates' {
        $spread = @(
            [PSCustomObject]@{ User='a'; IsComputer=$false; LockoutCount=4; DistinctSources=2
                               Sources='X, Y'; FirstSeen=[datetime]'2026-08-01'; LastSeen=[datetime]'2026-08-02' }
            [PSCustomObject]@{ User='b'; IsComputer=$false; LockoutCount=3; DistinctSources=1
                               Sources='Z'; FirstSeen=[datetime]'2026-08-01'; LastSeen=[datetime]'2026-08-02' }
        )
        $cov = [PSCustomObject]@{ DC='DC01'; CoverageDays=90; RequestedDays=30; IsComplete=$true; Note='' }
        $html = New-LockoutHistoryHtml -Summary $spread -Lockouts $script:Rows `
            -Coverage $cov -DcName 'DC01' -DaysBack 30 -MinLockouts 1
        $html | Should -Match 'no single account standing out'
        $html | Should -Match 'lockout threshold'
    }

    It 'escapes HTML metacharacters in event data' {
        $evil = @([PSCustomObject]@{ Time=[datetime]'2026-08-01T09:00:00'
                                     User='<script>alert(1)</script>'; CallerComputer='A&B'; DC='DC01' })
        $cov  = [PSCustomObject]@{ DC='DC01'; CoverageDays=90; RequestedDays=30; IsComplete=$true; Note='' }
        $html = New-LockoutHistoryHtml -Summary (Group-LockoutsByAccount -Lockouts $evil) `
            -Lockouts $evil -Coverage $cov -DcName 'DC01' -DaysBack 30 -MinLockouts 1
        $html | Should -Not -Match '<script>alert'
        $html | Should -Match '&lt;script&gt;'
        $html | Should -Match 'A&amp;B'
    }

    It 'renders an empty-state message when no accounts qualify' {
        $cov  = [PSCustomObject]@{ DC='DC01'; CoverageDays=90; RequestedDays=30; IsComplete=$true; Note='' }
        $html = New-LockoutHistoryHtml -Summary @() -Lockouts @() `
            -Coverage $cov -DcName 'DC01' -DaysBack 30 -MinLockouts 5
        $html | Should -Match 'No accounts met the minimum of 5'
    }
}
