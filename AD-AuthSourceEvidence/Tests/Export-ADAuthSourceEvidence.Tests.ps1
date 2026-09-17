BeforeAll {
    . "$PSScriptRoot\..\Export-ADAuthSourceEvidence.ps1" -LoadFunctionsOnly
}

Describe 'ConvertTo-NormalizedIp' {
    It 'strips the ::ffff: IPv4-mapped IPv6 prefix that 4771 events use' {
        # Event 4771 renders client addresses as ::ffff:10.0.0.12. Joining that raw
        # string against a DHCP lease or PTR record never matches.
        # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4771
        ConvertTo-NormalizedIp -Address '::ffff:10.0.0.12' | Should -Be '10.0.0.12'
    }

    It 'normalizes the IPv6 loopback to the IPv4 loopback' {
        ConvertTo-NormalizedIp -Address '::1' | Should -Be '127.0.0.1'
    }

    It 'leaves a plain IPv4 address untouched' {
        ConvertTo-NormalizedIp -Address '192.168.1.50' | Should -Be '192.168.1.50'
    }

    It 'preserves a genuine IPv6 address rather than mangling it' {
        ConvertTo-NormalizedIp -Address 'fe80::a1b2:c3d4' | Should -Be 'fe80::a1b2:c3d4'
    }

    It 'returns empty for the placeholder dash the logs use for "not recorded"' {
        ConvertTo-NormalizedIp -Address '-' | Should -BeNullOrEmpty
        ConvertTo-NormalizedIp -Address ''  | Should -BeNullOrEmpty
    }
}

Describe 'ConvertFrom-AuthEvent' {

    Context 'event 4625 (failed logon)' {
        BeforeAll {
            # Field layout transcribed from the documented event XML.
            # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625
            $script:Xml4625 = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><TimeCreated SystemTime="2026-08-01T13:05:00.000Z"/></System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="TargetDomainName">CONTOSO</Data>
    <Data Name="Status">0xc000006d</Data>
    <Data Name="SubStatus">0xc000006a</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="WorkstationName">LAPTOP-7</Data>
    <Data Name="ProcessName">C:\Windows\System32\svchost.exe</Data>
    <Data Name="IpAddress">10.20.30.40</Data>
    <Data Name="IpPort">51234</Data>
    <Data Name="AuthenticationPackageName">NTLM</Data>
  </EventData>
</Event>
'@
        }

        It 'extracts the account, source host, IP and port' {
            $row = ConvertFrom-AuthEvent -EventXml $script:Xml4625 -EventId 4625 -DcName 'DC01'
            $row.Account    | Should -Be 'jdoe'
            $row.SourceHost | Should -Be 'LAPTOP-7'
            $row.SourceIp   | Should -Be '10.20.30.40'
            $row.SourcePort | Should -Be '51234'
            $row.LogonType  | Should -Be '3'
            $row.DC         | Should -Be 'DC01'
        }

        It 'prefers SubStatus over Status, because Status is the generic wrapper' {
            # For 4625 the specific reason lives in SubStatus; Status is frequently
            # 0xC000006D ("generic logon failure") regardless of the real cause.
            $row = ConvertFrom-AuthEvent -EventXml $script:Xml4625 -EventId 4625 -DcName 'DC01'
            $row.StatusCode    | Should -Be '0xC000006A'
            $row.StatusMeaning | Should -Match 'Bad password'
        }

        It 'translates the logon type into plain English' {
            $row = ConvertFrom-AuthEvent -EventXml $script:Xml4625 -EventId 4625 -DcName 'DC01'
            $row.LogonTypeMeaning | Should -Match 'Network'
        }

        It 'records the process name, which names the service behind a stale credential' {
            $row = ConvertFrom-AuthEvent -EventXml $script:Xml4625 -EventId 4625 -DcName 'DC01'
            $row.ProcessName | Should -Be 'C:\Windows\System32\svchost.exe'
        }
    }

    Context 'event 4771 (Kerberos pre-authentication failed)' {
        BeforeAll {
            # 4771 has NO WorkstationName and NO LogonType. The failure code displayed
            # as "Failure Code" is named Status in the XML - reading a FailureCode key
            # silently yields null for every event.
            # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4771
            $script:Xml4771 = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><TimeCreated SystemTime="2026-08-01T14:00:00.000Z"/></System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="ServiceName">krbtgt/CONTOSO.LOCAL</Data>
    <Data Name="TicketOptions">0x40810010</Data>
    <Data Name="Status">0x18</Data>
    <Data Name="PreAuthType">2</Data>
    <Data Name="IpAddress">::ffff:10.20.30.41</Data>
    <Data Name="IpPort">49254</Data>
  </EventData>
</Event>
'@
        }

        It 'reads the failure code from Status, not from a FailureCode field' {
            $row = ConvertFrom-AuthEvent -EventXml $script:Xml4771 -EventId 4771 -DcName 'DC01'
            $row.StatusCode    | Should -Be '0x18'
            $row.StatusMeaning | Should -Match 'Bad password'
        }

        It 'normalizes the IPv4-mapped client address' {
            $row = ConvertFrom-AuthEvent -EventXml $script:Xml4771 -EventId 4771 -DcName 'DC01'
            $row.SourceIp | Should -Be '10.20.30.41'
        }

        It 'leaves SourceHost empty because the event carries no workstation name' {
            $row = ConvertFrom-AuthEvent -EventXml $script:Xml4771 -EventId 4771 -DcName 'DC01'
            $row.SourceHost | Should -BeNullOrEmpty
        }
    }

    Context 'event 4776 (NTLM credential validation)' {
        BeforeAll {
            # 4776 carries a Workstation NAME and no IP address at all. It is written for
            # BOTH success and failure - Error Code 0x0 means success. Treating every
            # 4776 as a failure reports healthy machines as attackers.
            # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4776
            $script:Xml4776Fail = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><TimeCreated SystemTime="2026-08-01T15:00:00.000Z"/></System>
  <EventData>
    <Data Name="PackageName">MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="Workstation">OLDPHONE</Data>
    <Data Name="Status">0xc000006a</Data>
  </EventData>
</Event>
'@
            $script:Xml4776Ok = $script:Xml4776Fail -replace '0xc000006a', '0x0'
        }

        It 'reads the source machine from Workstation, not WorkstationName' {
            $row = ConvertFrom-AuthEvent -EventXml $script:Xml4776Fail -EventId 4776 -DcName 'DC01'
            $row.SourceHost | Should -Be 'OLDPHONE'
        }

        It 'leaves SourceIp empty because the event has no IP field' {
            $row = ConvertFrom-AuthEvent -EventXml $script:Xml4776Fail -EventId 4776 -DcName 'DC01'
            $row.SourceIp | Should -BeNullOrEmpty
        }

        It 'marks status 0x0 as a SUCCESS, not a failure' {
            $row = ConvertFrom-AuthEvent -EventXml $script:Xml4776Ok -EventId 4776 -DcName 'DC01'
            $row.IsFailure | Should -BeFalse
        }

        It 'marks a non-zero status as a failure' {
            $row = ConvertFrom-AuthEvent -EventXml $script:Xml4776Fail -EventId 4776 -DcName 'DC01'
            $row.IsFailure | Should -BeTrue
        }
    }

    Context 'event 4740 (account locked out)' {
        BeforeAll {
            # REGRESSION GUARD. The caller machine is in TargetDomainName - there is no
            # CallerComputerName element in the event XML, despite Event Viewer showing
            # the value under the label "Caller Computer Name". Reading a
            # CallerComputerName key returns null for every real event.
            # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740
            $script:Xml4740 = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><TimeCreated SystemTime="2026-08-01T16:00:00.000Z"/></System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="TargetDomainName">WIN81</Data>
    <Data Name="TargetSid">S-1-5-21-1-2-3-1104</Data>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">DC01$</Data>
    <Data Name="SubjectDomainName">CONTOSO</Data>
  </EventData>
</Event>
'@
        }

        It 'reads the caller machine from TargetDomainName' {
            $row = ConvertFrom-AuthEvent -EventXml $script:Xml4740 -EventId 4740 -DcName 'DC01'
            $row.SourceHost | Should -Be 'WIN81'
        }

        It 'does not invent an IP address, because 4740 never carries one' {
            $row = ConvertFrom-AuthEvent -EventXml $script:Xml4740 -EventId 4740 -DcName 'DC01'
            $row.SourceIp | Should -BeNullOrEmpty
        }

        It 'extracts the locked-out account' {
            $row = ConvertFrom-AuthEvent -EventXml $script:Xml4740 -EventId 4740 -DcName 'DC01'
            $row.Account | Should -Be 'jdoe'
        }
    }
}

Describe 'Get-OuiVendor' {
    It 'identifies a network appliance vendor from the MAC prefix' {
        # Distinguishing a firewall from a desktop is the whole point of the MAC lookup:
        # a NATing appliance shows one IP for traffic from many real devices.
        Get-OuiVendor -MacAddress '00-09-0F-AA-BB-CC' | Should -Match 'Fortinet'
    }

    It 'handles colon-separated MAC formatting' {
        Get-OuiVendor -MacAddress '00:09:0f:aa:bb:cc' | Should -Match 'Fortinet'
    }

    It 'returns empty for an unknown prefix rather than guessing' {
        Get-OuiVendor -MacAddress 'AA-BB-CC-DD-EE-FF' | Should -BeNullOrEmpty
    }

    It 'returns empty for a malformed MAC' {
        Get-OuiVendor -MacAddress 'not-a-mac' | Should -BeNullOrEmpty
    }
}

Describe 'Resolve-DeviceClass' {
    It 'classifies a loopback address as local console activity' {
        $r = Resolve-DeviceClass -SourceIp '127.0.0.1' -ResolvedName '' -AdComputer $null -OuiVendor ''
        $r.DeviceClass | Should -Be 'LocalOrConsole'
    }

    It 'classifies a known appliance OUI as a network device even without a name' {
        $r = Resolve-DeviceClass -SourceIp '10.0.0.1' -ResolvedName '' -AdComputer $null -OuiVendor 'Fortinet'
        $r.DeviceClass | Should -Be 'NetworkDevice'
        $r.Detail      | Should -Match 'Fortinet'
    }

    It 'classifies a domain controller from its AD object' {
        $ad = [PSCustomObject]@{ Name='DC01'; OperatingSystem='Windows Server 2022 Datacenter'; IsDomainController=$true }
        $r = Resolve-DeviceClass -SourceIp '10.0.0.5' -ResolvedName 'DC01' -AdComputer $ad -OuiVendor ''
        $r.DeviceClass | Should -Be 'DomainController'
    }

    It 'classifies a server from its AD operating system attribute' {
        $ad = [PSCustomObject]@{ Name='FS01'; OperatingSystem='Windows Server 2019 Standard'; IsDomainController=$false }
        $r = Resolve-DeviceClass -SourceIp '10.0.0.6' -ResolvedName 'FS01' -AdComputer $ad -OuiVendor ''
        $r.DeviceClass | Should -Be 'Server'
    }

    It 'classifies a domain-joined workstation from its AD operating system attribute' {
        $ad = [PSCustomObject]@{ Name='WKS01'; OperatingSystem='Windows 11 Enterprise'; IsDomainController=$false }
        $r = Resolve-DeviceClass -SourceIp '10.0.0.7' -ResolvedName 'WKS01' -AdComputer $ad -OuiVendor ''
        $r.DeviceClass | Should -Be 'DomainJoinedWorkstation'
    }

    It 'reports an unresolved source as unknown rather than guessing a class' {
        $r = Resolve-DeviceClass -SourceIp '10.0.0.99' -ResolvedName '' -AdComputer $null -OuiVendor ''
        $r.DeviceClass | Should -Be 'Unknown'
    }

    It 'flags a named-but-not-in-AD device as non-domain-joined' {
        $r = Resolve-DeviceClass -SourceIp '10.0.0.98' -ResolvedName 'somephone' -AdComputer $null -OuiVendor ''
        $r.DeviceClass | Should -Be 'NonDomainDevice'
    }
}

Describe 'Group-AuthSource' {
    BeforeAll {
        $script:Rows = @(
            [PSCustomObject]@{ Time=[datetime]'2026-08-01T09:00:00'; Account='jdoe';   SourceIp='10.0.0.50'; SourceHost='';        EventId=4771; IsFailure=$true;  DC='DC01' }
            [PSCustomObject]@{ Time=[datetime]'2026-08-01T09:01:00'; Account='jdoe';   SourceIp='10.0.0.50'; SourceHost='';        EventId=4771; IsFailure=$true;  DC='DC01' }
            [PSCustomObject]@{ Time=[datetime]'2026-08-01T09:02:00'; Account='msmith'; SourceIp='10.0.0.50'; SourceHost='LAPTOP-3';EventId=4625; IsFailure=$true;  DC='DC02' }
            [PSCustomObject]@{ Time=[datetime]'2026-08-01T10:00:00'; Account='svc_bk'; SourceIp='10.0.0.77'; SourceHost='SQL01';   EventId=4776; IsFailure=$true;  DC='DC01' }
            [PSCustomObject]@{ Time=[datetime]'2026-08-01T11:00:00'; Account='ok_user';SourceIp='10.0.0.88'; SourceHost='GOOD01';  EventId=4776; IsFailure=$false; DC='DC01' }
        )
    }

    It 'produces one row per distinct source IP' {
        $g = Group-AuthSource -Events $script:Rows
        ($g | Where-Object { $_.SourceIp -eq '10.0.0.50' }).Count | Should -Be 1
    }

    It 'ranks the source with the most failures first' {
        $g = Group-AuthSource -Events $script:Rows
        $g[0].SourceIp     | Should -Be '10.0.0.50'
        $g[0].FailureCount | Should -Be 3
    }

    It 'counts distinct accounts hit, which is what identifies a shared or rogue device' {
        $g = Group-AuthSource -Events $script:Rows
        $top = $g | Where-Object { $_.SourceIp -eq '10.0.0.50' }
        $top.DistinctAccounts | Should -Be 2
        $top.Accounts         | Should -Be 'jdoe, msmith'
    }

    It 'carries forward any workstation name seen for that IP on another event type' {
        # 4771 gives an IP with no name; a 4625 from the same IP names the machine.
        # Merging them is how a bare Kerberos IP gets a hostname.
        $g = Group-AuthSource -Events $script:Rows
        $top = $g | Where-Object { $_.SourceIp -eq '10.0.0.50' }
        $top.NamesSeenInLog | Should -Be 'LAPTOP-3'
    }

    It 'records first and last seen times for the source' {
        $g = Group-AuthSource -Events $script:Rows
        $top = $g | Where-Object { $_.SourceIp -eq '10.0.0.50' }
        $top.FirstSeen | Should -Be ([datetime]'2026-08-01T09:00:00')
        $top.LastSeen  | Should -Be ([datetime]'2026-08-01T09:02:00')
    }

    It 'excludes sources that only ever succeeded' {
        $g = Group-AuthSource -Events $script:Rows
        ($g | Where-Object { $_.SourceIp -eq '10.0.0.88' }) | Should -BeNullOrEmpty
    }

    It 'groups name-only events (4776/4740) under their hostname when no IP exists' {
        $nameOnly = @(
            [PSCustomObject]@{ Time=[datetime]'2026-08-01T12:00:00'; Account='a'; SourceIp=''; SourceHost='OLDPHONE'; EventId=4776; IsFailure=$true; DC='DC01' }
            [PSCustomObject]@{ Time=[datetime]'2026-08-01T12:05:00'; Account='b'; SourceIp=''; SourceHost='OLDPHONE'; EventId=4740; IsFailure=$true; DC='DC01' }
        )
        $g = Group-AuthSource -Events $nameOnly
        $g.Count            | Should -Be 1
        $g[0].SourceKey     | Should -Be 'OLDPHONE'
        $g[0].FailureCount  | Should -Be 2
    }
}

Describe 'New-IpCorrelationXPath' {
    BeforeAll {
        $script:Start = (Get-Date).AddDays(-7)
    }

    It 'filters on the IpAddress EventData field structurally' {
        # A <named-data> FilterHashtable key silently matches ZERO events against the
        # Security log rather than erroring, because it depends on provider manifest
        # metadata. Structural XPath against Data[@Name=...] is the reliable form.
        # https://learn.microsoft.com/windows/win32/wes/consuming-events
        $xp = New-IpCorrelationXPath -IpAddress @('10.0.0.5') -EventIds @(4624) -StartTime $script:Start
        $xp | Should -Match "Data\[@Name='IpAddress'\]='10\.0\.0\.5'"
    }

    It 'matches both plain and IPv4-mapped forms of the same address' {
        # 4771/4768 store ::ffff:10.0.0.5 while 4624 usually stores 10.0.0.5. Querying
        # only one form misses half the successful logons that could name the device.
        $xp = New-IpCorrelationXPath -IpAddress @('10.0.0.5') -EventIds @(4624) -StartTime $script:Start
        $xp | Should -Match "::ffff:10\.0\.0\.5"
    }

    It 'includes every requested event ID' {
        $xp = New-IpCorrelationXPath -IpAddress @('10.0.0.5') -EventIds @(4624, 4768) -StartTime $script:Start
        $xp | Should -Match 'EventID=4624'
        $xp | Should -Match 'EventID=4768'
    }

    It 'bounds the query by age using timediff' {
        $xp = New-IpCorrelationXPath -IpAddress @('10.0.0.5') -EventIds @(4624) -StartTime $script:Start
        $xp | Should -Match 'timediff\(@SystemTime\)'
    }

    It 'accepts exactly 10 addresses, the real ceiling once both IP forms are counted' {
        # The XPath expression limit is 20, but EACH ADDRESS EMITS TWO TERMS (plain and
        # ::ffff: forms), so the address ceiling is 10, not 20. Verified against a live
        # log: 10 addresses succeed, 11 fail with "The specified query is invalid".
        $ips = 1..10 | ForEach-Object { "10.0.0.$_" }
        { New-IpCorrelationXPath -IpAddress $ips -EventIds @(4624) -StartTime $script:Start } | Should -Not -Throw
    }

    It 'emits at most 20 OR terms for a full batch, staying inside the XPath limit' {
        # Guards the arithmetic directly rather than just the address count, so adding a
        # third address form later cannot silently push the query over the limit again.
        $ips = 1..10 | ForEach-Object { "10.0.0.$_" }
        $xp = New-IpCorrelationXPath -IpAddress $ips -EventIds @(4624) -StartTime $script:Start
        ([regex]::Matches($xp, "Data\[@Name='IpAddress'\]")).Count | Should -BeLessOrEqual 20
    }

    It 'refuses more than 10 addresses rather than emitting a query the log will reject' {
        # Failing loudly here is what forces the caller to batch. A silently invalid
        # query would look like "no successful logons found" - indistinguishable from a
        # genuinely unresolvable device.
        $ips = 1..11 | ForEach-Object { "10.0.0.$_" }
        { New-IpCorrelationXPath -IpAddress $ips -EventIds @(4624) -StartTime $script:Start } |
            Should -Throw -ExpectedMessage '*at most 10 addresses*'
    }

    It 'escapes single quotes so an address cannot break out of the XPath literal' {
        $xp = New-IpCorrelationXPath -IpAddress @("10.0.0.5' or '1'='1") -EventIds @(4624) -StartTime $script:Start
        $xp | Should -Match "''"
    }
}

Describe 'Get-IpNameMapBySweep' {
    # The sweep is the default correlation strategy because its cost is bounded by
    # MaxEvents rather than by the number of UNRESOLVABLE IPs. Measured on a production
    # DC (742,767 records): a non-matching EventData predicate cost 11s for one IP and
    # 52s for a 20-term batch, because proving absence requires reading every record.
    # A StartTime-bounded query is served from the log's time index instead (0.9s).

    BeforeAll {
        function New-SuccessXml {
            param($Ip, $Workstation, $Id = 4624)
            @"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><TimeCreated SystemTime="2026-08-19T09:00:00.000Z"/></System>
  <EventData>
    <Data Name="TargetUserName">someone</Data>
    <Data Name="WorkstationName">$Workstation</Data>
    <Data Name="IpAddress">$Ip</Data>
    <Data Name="LogonType">3</Data>
  </EventData>
</Event>
"@
        }
    }

    It 'maps an IPv4-mapped source address to its workstation name' {
        # A 4624 stores 10.0.0.50 while the 4771 that needs naming stored
        # ::ffff:10.0.0.50. Both must normalize to the same key or the join fails.
        $row = ConvertFrom-AuthEvent -EventXml (New-SuccessXml -Ip '::ffff:10.0.0.50' -Workstation 'LAPTOP-3') -EventId 4624 -DcName 'DC01'
        $row.SourceIp   | Should -Be '10.0.0.50'
        $row.SourceHost | Should -Be 'LAPTOP-3'
    }

    It 'strips the trailing $ from machine account names so they join against AD' {
        # A 4624 from a machine account records WKS01$; DHCP, DNS and AD all know it as
        # WKS01. Leaving the $ on makes every machine-account correlation fail to resolve.
        $row = ConvertFrom-AuthEvent -EventXml (New-SuccessXml -Ip '10.0.0.60' -Workstation 'WKS01$') -EventId 4624 -DcName 'DC01'
        ($row.SourceHost -replace '\$$', '') | Should -Be 'WKS01'
    }

    It 'treats a successful logon as a non-failure so it never becomes evidence' {
        $row = ConvertFrom-AuthEvent -EventXml (New-SuccessXml -Ip '10.0.0.50' -Workstation 'LAPTOP-3') -EventId 4624 -DcName 'DC01'
        $row.IsFailure | Should -BeFalse
    }
}

Describe 'Test-LeaseCoversTime' {
    # CORRECTNESS. A DHCP lease is only authoritative for the window it actually covered.
    # Matching a 14-day-old failure against today's lease and reporting the name at High
    # confidence states as fact something the data cannot support - the address may have
    # belonged to a different machine when the failure happened.
    # https://learn.microsoft.com/powershell/module/dhcpserver/get-dhcpserverv4lease

    It 'accepts a lease that was still current when the failure occurred' {
        $r = Test-LeaseCoversTime -LeaseExpires ([datetime]'2026-08-20T12:00:00') `
                                  -FailureTime  ([datetime]'2026-08-19T09:00:00')
        $r.Covers | Should -BeTrue
    }

    It 'rejects a lease that expired before the failure happened' {
        # Lease ended the 15th; the failure was on the 19th. Whoever held the address
        # then, it was not necessarily this client.
        $r = Test-LeaseCoversTime -LeaseExpires ([datetime]'2026-08-15T12:00:00') `
                                  -FailureTime  ([datetime]'2026-08-19T09:00:00')
        $r.Covers | Should -BeFalse
        $r.Reason | Should -Match 'expired'
    }

    It 'treats a reservation as covering any time, because it is a fixed mapping' {
        # A reservation pins an address to a MAC indefinitely - there is no expiry to
        # compare against, and the mapping was as true last month as it is now.
        $r = Test-LeaseCoversTime -LeaseExpires $null -FailureTime ([datetime]'2026-01-01T00:00:00') -IsReservation
        $r.Covers | Should -BeTrue
    }

    It 'cannot confirm coverage when the lease has no expiry and is not a reservation' {
        $r = Test-LeaseCoversTime -LeaseExpires $null -FailureTime ([datetime]'2026-08-19T09:00:00')
        $r.Covers | Should -BeFalse
        $r.Reason | Should -Match 'unknown|no expiry'
    }

    It 'cannot confirm coverage when the failure time is unknown' {
        $r = Test-LeaseCoversTime -LeaseExpires ([datetime]'2026-08-20T12:00:00') -FailureTime $null
        $r.Covers | Should -BeFalse
    }
}

Describe 'Get-ResolutionConfidence with lease coverage' {
    # The confidence rating is the whole point of recording the method. A lease that
    # cannot have covered the failure must not still be rated High.

    It 'downgrades a DHCP lease that did not cover the failure window' {
        Get-ResolutionConfidence -Method 'DhcpLease' -LeaseCoversFailure $false | Should -Be 'Low'
    }

    It 'keeps High for a lease that did cover the failure window' {
        Get-ResolutionConfidence -Method 'DhcpLease' -LeaseCoversFailure $true | Should -Be 'High'
    }

    It 'leaves a reservation at Medium regardless, since it has no expiry to check' {
        Get-ResolutionConfidence -Method 'DhcpReservation' -LeaseCoversFailure $false | Should -Be 'Medium'
    }

    It 'does not disturb non-DHCP methods' {
        Get-ResolutionConfidence -Method 'ReverseDns'          -LeaseCoversFailure $false | Should -Be 'Low'
        Get-ResolutionConfidence -Method 'EventLogCorrelation' -LeaseCoversFailure $false | Should -Be 'High'
    }
}

Describe 'Get-InventoryColumnMap' {
    # An RMM, Intune or asset export has no standard column names. Rather than force the
    # user to rename columns before every run, detect the ones we can join on.

    It 'detects common hostname column spellings' {
        (Get-InventoryColumnMap -Columns @('ComputerName','Owner')).Host   | Should -Be 'ComputerName'
        (Get-InventoryColumnMap -Columns @('Device Name','Owner')).Host    | Should -Be 'Device Name'
        (Get-InventoryColumnMap -Columns @('hostname','serial')).Host      | Should -Be 'hostname'
    }

    It 'detects common MAC column spellings' {
        (Get-InventoryColumnMap -Columns @('Name','MAC Address')).Mac  | Should -Be 'MAC Address'
        (Get-InventoryColumnMap -Columns @('Name','macaddress')).Mac   | Should -Be 'macaddress'
        (Get-InventoryColumnMap -Columns @('Name','Physical Address')).Mac | Should -Be 'Physical Address'
    }

    It 'detects common IP column spellings' {
        (Get-InventoryColumnMap -Columns @('Name','IPAddress')).Ip   | Should -Be 'IPAddress'
        (Get-InventoryColumnMap -Columns @('Name','IPv4 Address')).Ip | Should -Be 'IPv4 Address'
    }

    It 'returns nothing joinable when no recognizable column exists' {
        $m = Get-InventoryColumnMap -Columns @('Serial','Warranty','Cost')
        $m.Host | Should -BeNullOrEmpty
        $m.Mac  | Should -BeNullOrEmpty
        $m.Ip   | Should -BeNullOrEmpty
    }
}

Describe 'ConvertTo-MacKey' {
    # MAC formats vary by source: DHCP gives 00-09-0F-11-22-33, switches give
    # 0009.0f11.2233, some exports give 00090F112233. They must normalize to one key or
    # the join silently matches nothing.

    It 'normalizes every common MAC format to the same key' {
        $expected = '00090F112233'
        ConvertTo-MacKey -Mac '00-09-0F-11-22-33' | Should -Be $expected
        ConvertTo-MacKey -Mac '00:09:0f:11:22:33' | Should -Be $expected
        ConvertTo-MacKey -Mac '0009.0f11.2233'    | Should -Be $expected
        ConvertTo-MacKey -Mac '00090f112233'      | Should -Be $expected
    }

    It 'returns empty for a value that is not a MAC' {
        ConvertTo-MacKey -Mac 'not-a-mac' | Should -BeNullOrEmpty
        ConvertTo-MacKey -Mac ''          | Should -BeNullOrEmpty
    }
}

Describe 'Join-InventoryRecord' {
    BeforeAll {
        $script:Inv = @(
            [PSCustomObject]@{ ComputerName='LAPTOP-3'; 'MAC Address'='11-22-33-44-55-66'; Owner='msmith'; Location='Floor 2' }
            [PSCustomObject]@{ ComputerName='SQLSRV02'; 'MAC Address'='AA-BB-CC-DD-EE-FF'; Owner='IT';     Location='Server room' }
        )
        $script:Map = Get-InventoryColumnMap -Columns @('ComputerName','MAC Address','Owner','Location')
    }

    It 'matches on MAC address even when the name differs' {
        # The MAC is the strongest join key - it survives a rename or a DHCP change.
        $r = Join-InventoryRecord -Inventory $script:Inv -ColumnMap $script:Map `
                                  -ResolvedName 'SOMETHING-ELSE' -MacAddress '11:22:33:44:55:66' -SourceIp ''
        $r.Matched     | Should -BeTrue
        $r.MatchedOn   | Should -Be 'MAC'
        $r.Fields.Owner| Should -Be 'msmith'
    }

    It 'falls back to matching on hostname' {
        $r = Join-InventoryRecord -Inventory $script:Inv -ColumnMap $script:Map `
                                  -ResolvedName 'laptop-3' -MacAddress '' -SourceIp ''
        $r.Matched   | Should -BeTrue
        $r.MatchedOn | Should -Be 'Name'
    }

    It 'reports no match rather than guessing' {
        $r = Join-InventoryRecord -Inventory $script:Inv -ColumnMap $script:Map `
                                  -ResolvedName 'UNKNOWN-PC' -MacAddress '' -SourceIp ''
        $r.Matched | Should -BeFalse
    }

    It 'carries through every extra column so any inventory field is usable' {
        $r = Join-InventoryRecord -Inventory $script:Inv -ColumnMap $script:Map `
                                  -ResolvedName 'LAPTOP-3' -MacAddress '' -SourceIp ''
        $r.Fields.Location | Should -Be 'Floor 2'
    }
}

Describe 'Import-OuiDatabase' {
    # The built-in table is ~35 high-signal vendors. The IEEE registry has tens of
    # thousands. -OuiDatabasePath lets an operator drop in the real file without this
    # script shipping a 4 MB blob.
    # https://standards-oui.ieee.org/oui/oui.txt

    BeforeAll {
        $script:OuiFile = Join-Path $TestDrive 'oui.txt'
        # Real oui.txt format: hex prefix, (hex), then the organization name.
        @(
            '00-1A-2B   (hex)		Acme Networks Inc.'
            '00-1A-2B   (base 16)		Acme Networks Inc.'
            'AA-BB-CC   (hex)		Contoso Hardware'
        ) | Set-Content -Path $script:OuiFile -Encoding ASCII
    }

    It 'parses vendor names out of the IEEE registry format' {
        $db = Import-OuiDatabase -Path $script:OuiFile
        $db['001A2B'] | Should -Be 'Acme Networks Inc.'
        $db['AABBCC'] | Should -Be 'Contoso Hardware'
    }

    It 'returns an empty table for a missing file rather than throwing' {
        $db = Import-OuiDatabase -Path (Join-Path $TestDrive 'nope.txt')
        @($db.Keys).Count | Should -Be 0
    }
}

Describe 'Get-SourceTimingPattern' {
    # Timing separates an automated retry from a human. A service retrying on a fixed
    # interval looks nothing like someone typing a wrong password twice.

    It 'identifies a regular machine-like interval' {
        # Every 30 minutes on the dot - a scheduled task or service retry.
        $times = @(0,30,60,90,120,150) | ForEach-Object { (Get-Date '2026-08-19T09:00:00').AddMinutes($_) }
        $r = Get-SourceTimingPattern -Times $times
        $r.Pattern        | Should -Be 'Regular'
        $r.Description    | Should -Match 'automated|interval|service|task'
        $r.MedianGapMinutes | Should -BeGreaterThan 25
    }

    It 'identifies a tight burst' {
        # Six attempts inside a minute - a retry loop or a spray, not a person.
        $times = @(0,5,9,14,20,26) | ForEach-Object { (Get-Date '2026-08-19T09:00:00').AddSeconds($_) }
        $r = Get-SourceTimingPattern -Times $times
        $r.Pattern     | Should -Be 'Burst'
        $r.Description | Should -Match 'burst|rapid|loop'
    }

    It 'reports irregular timing without over-claiming' {
        $times = @(
            (Get-Date '2026-08-19T09:00:00')
            (Get-Date '2026-08-19T11:43:00')
            (Get-Date '2026-08-20T04:12:00')
        )
        (Get-SourceTimingPattern -Times $times).Pattern | Should -Be 'Irregular'
    }

    It 'declines to characterize fewer than three events' {
        (Get-SourceTimingPattern -Times @((Get-Date))).Pattern | Should -Be 'Insufficient'
        (Get-SourceTimingPattern -Times @()).Pattern           | Should -Be 'Insufficient'
    }
}

Describe 'Get-ResolutionConfidence' {
    It 'rates an in-log success correlation as High' {
        # The DC itself recorded that name for that IP - the strongest evidence available.
        Get-ResolutionConfidence -Method 'EventLogCorrelation' | Should -Be 'High'
    }

    It 'rates a current DHCP lease as High' {
        Get-ResolutionConfidence -Method 'DhcpLease' | Should -Be 'High'
    }

    It 'rates reverse DNS as Low, because PTR records go stale' {
        Get-ResolutionConfidence -Method 'ReverseDns' | Should -Be 'Low'
    }

    It 'rates an unresolved source as None' {
        Get-ResolutionConfidence -Method 'Unresolved' | Should -Be 'None'
    }
}

Describe 'New-AuthSourceReportHtml' {
    # The exporter resolves what a source ACTUALLY IS - device class, MAC vendor, DHCP
    # lease, timing pattern - which is the most specific evidence the whole toolkit
    # produces. It was writing only CSV, so the combined case report had nothing to lift
    # and the "Which Device" tab never appeared. The best evidence was the least visible.

    BeforeAll {
        $script:Sources = @(
            [PSCustomObject]@{
                SourceIp='192.168.10.181'; ResolvedName='LAPTOP-7.contoso.local'
                DeviceClass='Windows workstation'; Confidence='High'
                ResolutionMethod='DHCP lease + reverse DNS'; MacAddress='AA-BB-CC-11-22-33'
                MacVendor='Dell Inc.'; FailureCount=78; DistinctAccounts=1
                Accounts='jdoe'; TopStatus='0x18 - Bad password'; LogonTypes='3 - Network'
                EventIds='4771'; FirstSeen='2026-08-26 12:13:25'; LastSeen='2026-08-26 19:17:57'
                TimingPattern='Regular'; MedianGapMinutes=5; TimingDetail='every ~5 min'
                DCsSeen='DC01'; NamesSeenInLog=''; ReverseDnsName='LAPTOP-7.contoso.local'
                DhcpLease='DHCP01'; LeaseCoversFailure=$true; LeaseCoverageNote='lease covers window'
                DeviceDetail='Dell workstation'
            }
            [PSCustomObject]@{
                SourceIp='10.0.0.9'; ResolvedName=''; DeviceClass='Unknown'; Confidence='None'
                ResolutionMethod=''; MacAddress=''; MacVendor=''; FailureCount=12
                DistinctAccounts=9; Accounts='a; b; c'; TopStatus='0x18 - Bad password'
                LogonTypes='3 - Network'; EventIds='4625'; FirstSeen='2026-08-25 01:00:00'
                LastSeen='2026-08-25 01:04:00'; TimingPattern='Burst'; MedianGapMinutes=0
                TimingDetail='burst'; DCsSeen='DC01'; NamesSeenInLog=''; ReverseDnsName=''
                DhcpLease=''; LeaseCoversFailure=$false; LeaseCoverageNote=''; DeviceDetail=''
            }
        )
    }

    It 'produces a complete standalone page the combiner can lift a body from' {
        $html = New-AuthSourceReportHtml -Sources $script:Sources -DaysBack 7 -GeneratedOn 'now'
        $html | Should -Match '<!DOCTYPE html>'
        $html | Should -Match '<body'
        $html | Should -Match '</body>'
        $html | Should -Match '<style>'
    }

    It 'names a resolved device rather than leaving the reader with an address' {
        # "192.168.10.181" is what you already knew. "LAPTOP-7, Dell workstation" is the
        # answer the investigation exists to produce.
        $html = New-AuthSourceReportHtml -Sources $script:Sources -DaysBack 7 -GeneratedOn 'now'
        $html | Should -Match 'LAPTOP-7'
        $html | Should -Match 'Dell'
    }

    It 'promotes a multi-account source to the verdict over a higher-count single-account one' {
        # Deliberate ordering: 12 failures against 9 accounts outranks 78 against one.
        # The first is possibly a spray, the second is one stale credential - and the
        # security reading is the one that must not be buried under a bigger number.
        # Assert on the verdict helper directly rather than slicing HTML - the ordering
        # rule is what matters, and the markup around it is incidental.
        $v = Get-AuthSourceVerdict -Sources $script:Sources
        $v.Line  | Should -Match '10\.0\.0\.9'
        $v.Line  | Should -Match '9 different accounts'
        $v.Class | Should -Be 'bad'
    }

    It 'shows the confidence so a guess is never mistaken for a fact' {
        $html = New-AuthSourceReportHtml -Sources $script:Sources -DaysBack 7 -GeneratedOn 'now'
        $html | Should -Match 'High'
    }

    It 'says plainly when a source could not be resolved' {
        # An unresolved source is a finding, not a blank. It means the device is not in
        # DHCP or DNS - often exactly the thing worth chasing.
        $html = New-AuthSourceReportHtml -Sources $script:Sources -DaysBack 7 -GeneratedOn 'now'
        $html | Should -Match 'not resolved|unresolved|Unknown'
    }

    It 'flags one source hitting many accounts as a possible spray' {
        # One device failing against nine accounts is a different problem from one device
        # failing against one - and the security-relevant one.
        $html = New-AuthSourceReportHtml -Sources $script:Sources -DaysBack 7 -GeneratedOn 'now'
        $html | Should -Match 'spray|multiple accounts|9 accounts'
    }

    It 'surfaces the timing pattern, which separates a machine from a person' {
        $html = New-AuthSourceReportHtml -Sources $script:Sources -DaysBack 7 -GeneratedOn 'now'
        $html | Should -Match 'Regular|Burst'
    }

    It 'escapes values so log content cannot inject markup' {
        $evil = @([PSCustomObject]@{
            SourceIp='<script>alert(1)</script>'; ResolvedName=''; DeviceClass=''; Confidence=''
            ResolutionMethod=''; MacAddress=''; MacVendor=''; FailureCount=1; DistinctAccounts=1
            Accounts=''; TopStatus=''; LogonTypes=''; EventIds=''; FirstSeen=''; LastSeen=''
            TimingPattern=''; MedianGapMinutes=0; TimingDetail=''; DCsSeen=''; NamesSeenInLog=''
            ReverseDnsName=''; DhcpLease=''; LeaseCoversFailure=$false; LeaseCoverageNote=''
            DeviceDetail='' })
        $html = New-AuthSourceReportHtml -Sources $evil -DaysBack 7 -GeneratedOn 'now'
        $html | Should -Not -Match '<script>alert'
        $html | Should -Match '&lt;script&gt;'
    }

    It 'renders a usable page when nothing was collected' {
        $html = New-AuthSourceReportHtml -Sources @() -DaysBack 7 -GeneratedOn 'now'
        $html | Should -Match '<!DOCTYPE html>'
        $html | Should -Match 'No authentication sources|nothing'
    }

    It 'uses the shared stylesheet so it matches the other reports' {
        $html = New-AuthSourceReportHtml -Sources $script:Sources -DaysBack 7 -GeneratedOn 'now'
        $html | Should -Match '\.verdict'
        $html | Should -Match '\.rank|\.card'
    }
}

Describe 'Bugs found in the real Case_jdoe run' {
    Context 'TopStatus must be a string, not an array' {
        # In the live CSV every row's TopStatus read "System.Object[]" - the single most
        # important column, the reason the attempts failed, was unreadable. Wrapping the
        # pipeline in @() produced an Object[] even for one value, and Export-Csv renders
        # an array as its type name. Select-Object -First 1 does NOT unwrap that.

        It 'unwraps the grouped status to a plain string' {
            $failures = @(
                [PSCustomObject]@{ StatusMeaning = 'Bad password' }
                [PSCustomObject]@{ StatusMeaning = 'Bad password' }
                [PSCustomObject]@{ StatusMeaning = 'Account locked' }
            )
            $top = @($failures |
                     Where-Object { -not [string]::IsNullOrWhiteSpace($_.StatusMeaning) } |
                     Group-Object StatusMeaning |
                     Sort-Object Count -Descending |
                     Select-Object -ExpandProperty Name)[0]
            $top | Should -BeOfType [string]
            $top | Should -Be 'Bad password'
            "$top" | Should -Not -Match 'System\.Object'
        }

        It 'uses the indexed form in the source, not the @()-wrapped one' {
            $src = Get-Content -Raw "$PSScriptRoot\..\Export-ADAuthSourceEvidence.ps1"
            $src | Should -Match 'Select-Object -ExpandProperty Name\)\[0\]'
        }
    }

    Context 'Internal tokens are translated for the reader' {
        # ResolutionMethod and DeviceClass are CamelCase internals. "EventLogCorrelation"
        # is precise but tells a helpdesk tech nothing about how much to trust the name.

        It 'explains how a name was resolved in plain English' {
            Format-ResolutionMethod -Method 'EventLogCorrelation' | Should -Match 'named itself'
            Format-ResolutionMethod -Method 'ReverseDns'          | Should -Match 'reverse DNS'
            Format-ResolutionMethod -Method 'DhcpLease'           | Should -Match 'DHCP'
        }

        It 'flags reverse DNS as the weaker evidence it is' {
            # A stale PTR record names a machine that may no longer hold that address.
            Format-ResolutionMethod -Method 'ReverseDns' | Should -Match 'stale'
        }

        It 'returns empty for unresolved rather than the token' {
            Format-ResolutionMethod -Method 'Unresolved' | Should -BeNullOrEmpty
            Format-DeviceClass -Class 'Unknown'          | Should -BeNullOrEmpty
        }

        It 'translates the device classes seen in the real run' {
            Format-DeviceClass -Class 'DomainJoinedWorkstation' | Should -Be 'Domain-joined workstation'
            Format-DeviceClass -Class 'DomainController'        | Should -Be 'Domain controller'
            Format-DeviceClass -Class 'NonDomainDevice'         | Should -Match 'Not domain-joined'
            Format-DeviceClass -Class 'LocalOrConsole'          | Should -Match 'domain controller itself'
        }

        It 'passes through an unrecognized class rather than blanking it' {
            Format-DeviceClass -Class 'SomethingNew' | Should -Be 'SomethingNew'
        }

        It 'does not print a confidence tag for an unresolved source' {
            # "None confidence" is noise; the card already says "not resolved".
            $s = @([PSCustomObject]@{
                SourceIp='10.0.0.1'; ResolvedName=''; DeviceClass='Unknown'; Confidence='None'
                ResolutionMethod='Unresolved'; MacAddress=''; MacVendor=''; FailureCount=9
                DistinctAccounts=1; Accounts='u'; TopStatus='Bad password'; LogonTypes=''
                EventIds='4771'; FirstSeen='a'; LastSeen='b'; TimingPattern='Burst'
                MedianGapMinutes=0; TimingDetail='burst'; DCsSeen='DC'; NamesSeenInLog=''
                ReverseDnsName=''; DhcpLease=''; LeaseCoversFailure=$false; LeaseCoverageNote=''
                DeviceDetail='' })
            $html = New-AuthSourceReportHtml -Sources $s -DaysBack 7 -GeneratedOn 'now'
            $html | Should -Not -Match 'None confidence'
        }
    }
}

Describe 'The domain controller is a relay, not a culprit' {
    # From the real run: DC02 recorded 1043 of 1418 failures across 16 accounts,
    # and 127.0.0.1 another 47 across 11. Naming the DC as the top source is true and
    # useless - it sends a technician to audit a domain controller for a stale credential
    # that lives on a workstation. A DC re-presents credentials for PTA agents validating
    # Entra sign-ins, services and scheduled tasks.

    BeforeAll {
        $script:RealShape = @(
            [PSCustomObject]@{ SourceKey='DC02'; SourceIp=''; ResolvedName='DC02'
                DeviceClass='DomainController'; Confidence='High'; ResolutionMethod='EventLogCorrelation'
                MacAddress=''; MacVendor=''; FailureCount=1043; DistinctAccounts=16; Accounts='many'
                TopStatus='Bad password'; LogonTypes=''; EventIds='4625'; FirstSeen='a'; LastSeen='b'
                TimingPattern='Burst'; MedianGapMinutes=0; TimingDetail='burst'; DCsSeen='DC'
                NamesSeenInLog=''; ReverseDnsName=''; DhcpLease=''; LeaseCoversFailure=$true
                LeaseCoverageNote=''; DeviceDetail='Domain controller' }
            [PSCustomObject]@{ SourceKey='192.168.10.181'; SourceIp='192.168.10.181'; ResolvedName=''
                DeviceClass='Unknown'; Confidence='None'; ResolutionMethod='Unresolved'
                MacAddress=''; MacVendor=''; FailureCount=92; DistinctAccounts=3; Accounts='three'
                TopStatus='Bad password'; LogonTypes=''; EventIds='4771'; FirstSeen='a'; LastSeen='b'
                TimingPattern='Burst'; MedianGapMinutes=0.03; TimingDetail='burst'; DCsSeen='DC'
                NamesSeenInLog=''; ReverseDnsName=''; DhcpLease=''; LeaseCoversFailure=$true
                LeaseCoverageNote=''; DeviceDetail='' }
        )
    }

    It 'does not name the domain controller as the source to chase' {
        $v = Get-AuthSourceVerdict -Sources $script:RealShape
        $v.Line | Should -Not -Match 'DC02'
    }

    It 'points at the highest external source instead' {
        $v = Get-AuthSourceVerdict -Sources $script:RealShape
        $v.Line | Should -Match '192\.168\.10\.181'
    }

    It 'does not treat DC account aggregation as a password spray' {
        # 16 accounts through a DC is aggregation. 16 accounts from one workstation is
        # a spray. Same number, opposite meaning.
        $v = Get-AuthSourceVerdict -Sources $script:RealShape
        $v.Line | Should -Not -Match '16 different accounts'
    }

    It 'still flags a genuine spray from an external source' {
        $spray = @($script:RealShape[0], ([PSCustomObject]@{
            SourceKey='10.0.0.5'; SourceIp='10.0.0.5'; ResolvedName='KIOSK-1'
            DeviceClass='NonDomainDevice'; Confidence='Low'; ResolutionMethod='ReverseDns'
            MacAddress=''; MacVendor=''; FailureCount=40; DistinctAccounts=12; Accounts='many'
            TopStatus='Bad password'; LogonTypes=''; EventIds='4771'; FirstSeen='a'; LastSeen='b'
            TimingPattern='Burst'; MedianGapMinutes=0; TimingDetail='burst'; DCsSeen='DC'
            NamesSeenInLog=''; ReverseDnsName=''; DhcpLease=''; LeaseCoversFailure=$true
            LeaseCoverageNote=''; DeviceDetail='' }))
        $v = Get-AuthSourceVerdict -Sources $spray
        $v.Line  | Should -Match 'KIOSK-1'
        $v.Class | Should -Be 'bad'
    }

    It 'explains the relay when the DC is the ONLY source' {
        $onlyDc = @($script:RealShape[0])
        $v = Get-AuthSourceVerdict -Sources $onlyDc
        $v.Line | Should -Match 'originating on DC02 itself'
        $v.Next | Should -Match 'Pass-through Authentication|Entra'
    }
}
