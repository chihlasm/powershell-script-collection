#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
    Run with Pester 5:  Invoke-Pester .\Entra-DeviceActivityTimeline\Tests -Output Detailed
    Everything here is pure: no event log, auditpol or dsregcmd is touched.
#>

BeforeAll {
    $script:ScriptPath = Join-Path $PSScriptRoot '..\Get-DeviceActivityTimeline.ps1'
    . $script:ScriptPath -LoadFunctionsOnly

    function New-Act {
        param([string]$Kind, [string]$Time, [int]$EventId = 0, [string]$Sid = '', [string]$Source = '')
        [PSCustomObject]@{ Time = [datetime]$Time; Kind = $Kind; Label = $Kind; EventId = $EventId
                           Source = $(if ($Source) { $Source } else { "X $EventId $Kind" }); User = ''; UserSid = $Sid; Detail = ''
                           ClockFrom = $null; ClockTo = $null }
    }
    $script:Entra = 'S-1-12-1-1490293691-1170746386-2036445836-2183591547'
}

Describe 'Script file' {
    It 'is pure ASCII, so it needs no BOM for Windows PowerShell and passes Intune signature checks without one' {
        # Regression: a literal U+200B in a regex was decoded as ANSI by Windows PowerShell,
        # the pattern became invalid, and every System log event silently disappeared.
        $bytes = [System.IO.File]::ReadAllBytes($script:ScriptPath)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }
}

Describe 'ConvertFrom-ActivityEvent (event mapping verified against Microsoft Learn)' {
    It 'maps System events on provider AND id' {
        (ConvertFrom-ActivityEvent -LogName System -ProviderName 'Microsoft-Windows-Kernel-General' -EventId 12 -Time '2026-10-01 08:00').Kind | Should -Be 'Startup'
        (ConvertFrom-ActivityEvent -LogName System -ProviderName 'Microsoft-Windows-Kernel-Power' -EventId 107 -Time '2026-10-01 08:00').Kind | Should -Be 'Wake'
        ConvertFrom-ActivityEvent -LogName System -ProviderName 'Some-Other-Provider' -EventId 12 -Time '2026-10-01 08:00' | Should -BeNullOrEmpty
    }

    It 'strips the invisible marks Windows puts around dates in messages' {
        $msg = 'The operating system started at system time {0}2026{0}-{0}09{0}-{0}18T19:00:47Z.' -f [char]0x200E
        $r = ConvertFrom-ActivityEvent -LogName System -ProviderName 'Microsoft-Windows-Kernel-General' -EventId 12 -Time '2026-09-18 15:00' -Message $msg
        $r.Detail | Should -Be 'The operating system started at system time 2026-09-18T19:00:47Z.'
    }

    It 'classifies 4624 by logon type: 2/11 sign-in, 10 remote, 7/13 unlock' {
        foreach ($case in @(@{ T='2'; K='SignIn' }, @{ T='11'; K='SignIn' }, @{ T='10'; K='RemoteSignIn' }, @{ T='7'; K='Unlock' }, @{ T='13'; K='Unlock' })) {
            $d = @{ TargetUserSid = $script:Entra; TargetUserName = 'jdoe@contoso.com'; TargetDomainName = 'CONTOSO'; LogonType = $case.T }
            (ConvertFrom-ActivityEvent -LogName Security -ProviderName 'Microsoft-Windows-Security-Auditing' -EventId 4624 -Time '2026-10-01 08:00' -Data $d).Kind | Should -Be $case.K
        }
    }

    It 'ignores network, service and batch logons' {
        foreach ($t in '3', '4', '5', '9') {
            $d = @{ TargetUserSid = $script:Entra; TargetUserName = 'jdoe'; LogonType = $t }
            ConvertFrom-ActivityEvent -LogName Security -ProviderName 'Microsoft-Windows-Security-Auditing' -EventId 4624 -Time '2026-10-01 08:00' -Data $d | Should -BeNullOrEmpty
        }
    }

    It 'keeps Entra (S-1-12-1) and local/AD (S-1-5-21) accounts but drops system and per-session accounts' {
        $mk = { param($sid) ConvertFrom-ActivityEvent -LogName Security -ProviderName 'Microsoft-Windows-Security-Auditing' -EventId 4624 -Time '2026-10-01 08:00' -Data @{ TargetUserSid = $sid; TargetUserName = 'x'; LogonType = '2' } }
        & $mk $script:Entra | Should -Not -BeNullOrEmpty
        & $mk 'S-1-5-21-1-2-3-1001' | Should -Not -BeNullOrEmpty
        & $mk 'S-1-5-18' | Should -BeNullOrEmpty                # SYSTEM
        & $mk 'S-1-5-90-0-1' | Should -BeNullOrEmpty            # Window Manager\DWM-1
        & $mk 'S-1-5-96-0-1' | Should -BeNullOrEmpty            # Font Driver Host\UMFD-1
    }

    It 'reads 4800 account fields (TargetDomainName\TargetUserName)' {
        $d = @{ TargetUserSid = $script:Entra; TargetUserName = 'jdoe@contoso.com'; TargetDomainName = 'AzureAD' }
        $r = ConvertFrom-ActivityEvent -LogName Security -ProviderName 'Microsoft-Windows-Security-Auditing' -EventId 4800 -Time '2026-10-01 08:00' -Data $d
        $r.Kind | Should -Be 'Lock'
        $r.User | Should -Be 'AzureAD\jdoe@contoso.com'
    }

    It 'describes 4778 remote and console (fast user switching) sessions' {
        $remote = ConvertFrom-ActivityEvent -LogName Security -ProviderName 'Microsoft-Windows-Security-Auditing' -EventId 4778 -Time '2026-10-01 08:00' -Data @{ AccountName = 'jdoe'; AccountDomain = 'CONTOSO'; SessionName = 'RDP-Tcp#6'; ClientName = 'HOMEPC'; ClientAddress = '10.0.0.5' }
        $remote.Detail | Should -Match 'HOMEPC'
        $console = ConvertFrom-ActivityEvent -LogName Security -ProviderName 'Microsoft-Windows-Security-Auditing' -EventId 4778 -Time '2026-10-01 08:00' -Data @{ AccountName = 'jdoe'; SessionName = 'Console'; ClientName = 'Unknown'; ClientAddress = 'LOCAL' }
        $console.Detail | Should -Match 'switched user'
    }

    It 'keeps only clock changes of minutes or more, with old and new time from EventData' {
        $small = @{ OldTime = '2026-10-12T06:14:12.0000000Z'; NewTime = '2026-10-12T06:14:13.0000000Z' }
        ConvertFrom-ActivityEvent -LogName System -ProviderName 'Microsoft-Windows-Kernel-General' -EventId 1 -Time '2026-10-12 02:14' -Data $small | Should -BeNullOrEmpty
        $big = @{ OldTime = '2026-09-28T11:29:39.8903140Z'; NewTime = '2026-10-12T06:14:12.5000000Z' }
        $r = ConvertFrom-ActivityEvent -LogName System -ProviderName 'Microsoft-Windows-Kernel-General' -EventId 1 -Time '2026-10-12 02:14' -Data $big
        $r.Kind | Should -Be 'ClockChange'
        $r.ClockTo.ToUniversalTime() | Should -Be ([datetime]::new(2026, 10, 12, 6, 14, 12, 500, [DateTimeKind]::Utc))
    }
}

Describe 'ConvertFrom-ActivityEvent resume record (Power-Troubleshooter 1)' {
    BeforeAll {
        $script:Pt = {
            param([string]$Target, [string]$Effective, [string]$Text = '', [string]$Message = 'The system has returned from a low power state.')
            $d = @{ SleepTime = '2026-09-28T11:28:54.9845701Z'; WakeTime = '2026-10-12T06:14:12.9561807Z'
                    TargetState = $Target; EffectiveState = $Effective; WakeSourceText = $Text }
            ConvertFrom-ActivityEvent -LogName System -ProviderName 'Microsoft-Windows-Power-Troubleshooter' -EventId 1 -Time '2026-10-12 02:14:15' -Message $Message -Data $d
        }
    }

    It 'reads the real sleep and wake times (UTC) from the record' {
        $r = & $script:Pt '5' '5'
        $r.Kind | Should -Be 'ResumeRecord'
        $r.ClockTo.ToUniversalTime() | Should -Be ([datetime]::Parse('2026-10-12T06:14:12.9561807Z', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime())
    }

    It 'classifies the sleep type from SYSTEM_POWER_STATE (5 = hibernate, 6 = shutdown)' {
        (& $script:Pt '5' '5').ResumeType | Should -Be 'Hibernate'
        (& $script:Pt '6' '5').ResumeType | Should -Be 'FastStartup'
        (& $script:Pt '4' '4').ResumeType | Should -Be 'Sleep'
    }

    It 'keeps a known wake source and drops "Unknown"' {
        (& $script:Pt '4' '4' 'Power Button').WakeSource | Should -Be 'Power Button'
        (& $script:Pt '5' '5' '' "The system has returned from a low power state.`r`nWake Source: Unknown").WakeSource | Should -Be ''
    }
}

Describe 'Merge-ActivityEvent' {
    It 'keeps a clock reset and a resume record logged seconds apart (both are event 1)' {
        # Regression: both were "System 1" and the duplicate filter dropped the resume record.
        $clock = New-Act ClockChange '2026-10-15 22:55:22' 1 '' 'System 1 (Kernel-General)'
        $rec   = New-Act ResumeRecord '2026-10-15 22:55:24' 1 '' 'System 1 (Power-Troubleshooter)'
        @(Merge-ActivityEvent -Events @($clock, $rec)).Count | Should -Be 2
    }

    It 'treats a 4624 type 11 followed by type 7 two seconds later as one unlock (observed on Entra devices)' {
        $in = @(
            (New-Act SignIn '2026-10-15 22:55:31' 4624 $script:Entra 'Security 4624 type 11')
            (New-Act Unlock '2026-10-15 22:55:33' 4624 $script:Entra 'Security 4624 type 7')
        )
        $out = @(Merge-ActivityEvent -Events $in)
        $out.Count | Should -Be 1
        $out[0].Kind | Should -Be 'Unlock'
    }

    It 'keeps a genuine sign-in that has no unlock right after it' {
        $out = @(Merge-ActivityEvent -Events @((New-Act SignIn '2026-10-15 08:00:00' 4624 $script:Entra 'Security 4624 type 2')))
        $out.Count | Should -Be 1
        $out[0].Kind | Should -Be 'SignIn'
    }

    It 'collapses the elevated/standard pair an administrator sign-in writes' {
        $in = @(
            (New-Act SignIn '2026-10-15 08:00:00' 4624 $script:Entra 'Security 4624 type 2')
            (New-Act SignIn '2026-10-15 08:00:01' 4624 $script:Entra 'Security 4624 type 2')
        )
        @(Merge-ActivityEvent -Events $in).Count | Should -Be 1
    }

    It 'prefers a real 4801 over the 4624 unlock record for the same unlock' {
        $in = @(
            (New-Act Unlock '2026-10-15 09:00:00' 4801 $script:Entra 'Security 4801')
            (New-Act Unlock '2026-10-15 09:00:01' 4624 $script:Entra 'Security 4624 type 7')
        )
        $out = @(Merge-ActivityEvent -Events $in)
        $out.Count | Should -Be 1
        $out[0].EventId | Should -Be 4801
    }

    It 'does not merge different accounts' {
        $in = @(
            (New-Act SignIn '2026-10-15 08:00:00' 4624 $script:Entra 'Security 4624 type 11')
            (New-Act Unlock '2026-10-15 08:00:02' 4624 'S-1-12-1-9-9-9-9' 'Security 4624 type 7')
        )
        @(Merge-ActivityEvent -Events $in).Count | Should -Be 2
    }
}

Describe 'Repair-ResumeTime' {
    BeforeAll {
        # The real sequence from an Entra-joined Windows 11 laptop: sleep, a 107 stamped four
        # seconds later with the frozen clock, two weeks of silence, then the clock reset.
        $script:Seq = @(
            (New-Act Sleep '2026-09-28 07:29:35' 42)
            (New-Act Wake  '2026-09-28 07:29:39' 107)
            ([PSCustomObject]@{ Time = [datetime]'2026-10-12 02:14:12'; Kind = 'ClockChange'; Label = 'System clock changed'; EventId = 1
                                Source = 'System 1'; User = ''; UserSid = ''; Detail = ''
                                ClockFrom = [datetime]'2026-09-28 07:29:39'; ClockTo = [datetime]'2026-10-12 02:14:12' })
        )
    }

    It 'moves the wake to the clock-reset time and relabels the stale 107' {
        $out = @(Repair-ResumeTime -Events $script:Seq)
        $wakes = @($out | Where-Object { $_.Kind -eq 'Wake' })
        $wakes.Count | Should -Be 1
        $wakes[0].Time | Should -Be ([datetime]'2026-10-12 02:14:12')
        @($out | Where-Object { $_.Kind -eq 'ResumeLogged' }).Count | Should -Be 1
        @($out | Where-Object { $_.Kind -eq 'ClockChange' }).Count | Should -Be 0
    }

    It 'makes the days in between read as asleep, not on' {
        $out = Repair-ResumeTime -Events $script:Seq
        $days = @(Get-DailySummary -Events $out -From '2026-09-28' -To '2026-10-12 23:00')
        ($days | Where-Object { $_.Date -eq '2026-10-05' }).AllDay | Should -Match '^Asleep all day'
    }

    It 'prefers the resume record, and leaves the genuine standby exit from just before the hibernate alone' {
        # The full real sequence: leaves Modern Standby, hibernates, 107 stamped with the
        # stopped clock, then the clock reset and the resume record at the real time.
        $rec = [PSCustomObject]@{ Time = [datetime]'2026-10-12 02:14:15'; Kind = 'ResumeRecord'; Label = ''; EventId = 1; Source = 'System 1 (Power-Troubleshooter)'
                                  User = ''; UserSid = ''; Detail = ''; ClockFrom = [datetime]'2026-09-28 07:28:54'; ClockTo = [datetime]'2026-10-12 02:14:12'
                                  ResumeType = 'Hibernate'; WakeSource = '' }
        $seq = @(
            (New-Act StandbyExit '2026-09-28 07:28:54' 507)
            (New-Act Sleep '2026-09-28 07:29:35' 42)
            (New-Act Wake  '2026-09-28 07:29:39' 107)
        ) + @($script:Seq[2], $rec)
        $out = @(Repair-ResumeTime -Events $seq)
        $wakes = @($out | Where-Object { $_.Kind -eq 'Wake' })
        $wakes.Count | Should -Be 1
        $wakes[0].Time | Should -Be ([datetime]'2026-10-12 02:14:12')
        $wakes[0].Label | Should -Be 'Woke from hibernation'
        ($out | Where-Object { $_.EventId -eq 507 }).Kind | Should -Be 'StandbyExit'
        @($out | Where-Object { $_.Kind -in 'ClockChange', 'ResumeRecord' }).Count | Should -Be 0
    }

    It 'adds detail to an accurate wake row instead of duplicating it after a short sleep' {
        $rec = [PSCustomObject]@{ Time = [datetime]'2026-10-01 09:00:03'; Kind = 'ResumeRecord'; Label = ''; EventId = 1; Source = 'System 1 (Power-Troubleshooter)'
                                  User = ''; UserSid = ''; Detail = ''; ClockFrom = [datetime]'2026-10-01 08:30:00'; ClockTo = [datetime]'2026-10-01 09:00:00'
                                  ResumeType = 'Sleep'; WakeSource = 'Power Button' }
        $out = @(Repair-ResumeTime -Events @((New-Act Sleep '2026-10-01 08:30:00' 42), (New-Act Wake '2026-10-01 09:00:01' 107), $rec))
        $wakes = @($out | Where-Object { $_.Kind -eq 'Wake' })
        $wakes.Count | Should -Be 1
        $wakes[0].EventId | Should -Be 107
        $wakes[0].Detail | Should -Match 'Wake source: Power Button'
    }

    It 'turns a Fast Startup resume record into a start at the real time' {
        $rec = [PSCustomObject]@{ Time = [datetime]'2026-10-02 08:00:05'; Kind = 'ResumeRecord'; Label = ''; EventId = 1; Source = 'System 1 (Power-Troubleshooter)'
                                  User = ''; UserSid = ''; Detail = ''; ClockFrom = [datetime]'2026-10-01 17:30:00'; ClockTo = [datetime]'2026-10-02 08:00:00'
                                  ResumeType = 'FastStartup'; WakeSource = '' }
        $out = @(Repair-ResumeTime -Events @((New-Act Shutdown '2026-10-01 17:30:01' 13), (New-Act Startup '2026-10-01 17:30:20' 12), $rec))
        $starts = @($out | Where-Object { $_.Kind -eq 'Startup' })
        $starts.Count | Should -Be 1
        $starts[0].Time | Should -Be ([datetime]'2026-10-02 08:00:00')
        $starts[0].Label | Should -Be 'Windows started (Fast Startup)'
        ($out | Where-Object { $_.EventId -eq 12 }).Kind | Should -Be 'ResumeLogged'
        $days = @(Get-DailySummary -Events $out -From '2026-10-01' -To '2026-10-02 12:00')
        # New-Act labels rows with their kind; the point is the day ends on the shutdown, not
        # on the stale start that used to follow it.
        ($days | Where-Object { $_.Date -eq '2026-10-01' }).LastWhat | Should -Be 'Shutdown'
    }

    It 'falls back to the clock reset for a start after shutdown when there is no resume record' {
        $jump = [PSCustomObject]@{ Time = [datetime]'2026-10-02 08:00'; Kind = 'ClockChange'; Label = 'System clock changed'; EventId = 1; Source = 'System 1 (Kernel-General)'
                                   User = ''; UserSid = ''; Detail = ''; ClockFrom = [datetime]'2026-10-01 17:30:20'; ClockTo = [datetime]'2026-10-02 08:00' }
        $out = @(Repair-ResumeTime -Events @((New-Act Shutdown '2026-10-01 17:30:01' 13), (New-Act Startup '2026-10-01 17:30:20' 12), $jump))
        @($out | Where-Object { $_.Kind -eq 'Startup' })[0].Time | Should -Be ([datetime]'2026-10-02 08:00')
    }

    It 'leaves a clock jump with no sleep just before it as a clock change' {
        $jump = [PSCustomObject]@{ Time = [datetime]'2026-10-03 10:00'; Kind = 'ClockChange'; Label = 'System clock changed'; EventId = 1; Source = 'System 1'
                                   User = ''; UserSid = ''; Detail = ''; ClockFrom = [datetime]'2026-10-03 09:00'; ClockTo = [datetime]'2026-10-03 10:00' }
        $out = @(Repair-ResumeTime -Events @((New-Act Wake '2026-10-01 08:00' 107), $jump))
        @($out | Where-Object { $_.Kind -eq 'ClockChange' }).Count | Should -Be 1
        @($out | Where-Object { $_.Kind -eq 'Wake' }).Count | Should -Be 1
    }
}

Describe 'Test-UserMatch' {
    It 'always keeps machine events, filters user events by name or SID' {
        $machine = New-Act Startup '2026-10-01 08:00'
        $user = [PSCustomObject]@{ User = 'AzureAD\jdoe@contoso.com'; UserSid = $script:Entra }
        Test-UserMatch -Item $machine -UserName 'someone' | Should -BeTrue
        Test-UserMatch -Item $user -UserName 'JDOE' | Should -BeTrue
        Test-UserMatch -Item $user -UserName $script:Entra | Should -BeTrue
        Test-UserMatch -Item $user -UserName 'asmith' | Should -BeFalse
    }
}

Describe 'Get-DailySummary' {
    It 'reports first and last sign of use and counts per day' {
        $ev = @(
            (New-Act Startup '2026-10-01 07:58'); (New-Act Unlock '2026-10-01 08:01'); (New-Act Lock '2026-10-01 12:00')
            (New-Act Unlock '2026-10-01 12:45'); (New-Act Sleep '2026-10-01 17:42')
        )
        $d = @(Get-DailySummary -Events $ev -From '2026-10-01' -To '2026-10-01 23:59')
        $d.Count | Should -Be 1
        $d[0].FirstActivity | Should -Be '07:58'
        $d[0].LastActivity | Should -Be '17:42'
        $d[0].Unlocks | Should -Be 2
        $d[0].Locks | Should -Be 1
    }

    It 'says "off all day" after a shutdown and starts at the log coverage date' {
        $ev = @((New-Act Shutdown '2026-10-02 18:00'))
        $d = @(Get-DailySummary -Events $ev -From '2026-09-25' -To '2026-10-04 12:00' -CoverageStart '2026-10-02 00:00')
        $d[0].Date | Should -Be '2026-10-02'
        ($d | Where-Object { $_.Date -eq '2026-10-03' }).AllDay | Should -Match '^Off all day'
    }

    It 'uses events before the range only for the starting state, without counting them' {
        $ev = @((New-Act Sleep '2026-09-20 18:00'), (New-Act Wake '2026-10-02 08:00'))
        $d = @(Get-DailySummary -Events $ev -From '2026-10-01' -To '2026-10-02 23:00')
        $d[0].AllDay | Should -Match '^Asleep all day'
        $d[0].Sleeps | Should -Be 0
    }
}

Describe 'Audit setting' {
    It 'parses auditpol /r output by GUID' {
        $csv = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting`r`nPC1,System,Other Logon/Logoff Events,{0CCE921C-69AE-11D9-BED3-505054503030},No Auditing,"
        $row = @(ConvertFrom-AuditPolCsv -CsvText $csv)[0]
        $row.Guid | Should -Be '{0CCE921C-69AE-11D9-BED3-505054503030}'
        (Resolve-AuditSetting -Setting $row.Setting).State | Should -Be 'Off'
    }

    It 'treats Success and Success and Failure as on, Failure as off, other languages as unknown' {
        (Resolve-AuditSetting 'Success').State | Should -Be 'On'
        (Resolve-AuditSetting 'Success and Failure').State | Should -Be 'On'
        (Resolve-AuditSetting 'Failure').State | Should -Be 'Off'
        (Resolve-AuditSetting 'Erfolg').State | Should -Be 'Unknown'
    }

    It 'uses the Audit_Logon_Others GUID from Microsoft Learn' {
        $script:OtherLogonLogoffGuid | Should -Be '{0CCE921C-69AE-11D9-BED3-505054503030}'
    }

    It 'says lock/unlock is recorded when 4800/4801 exist, whatever auditpol says' {
        (Get-LockAuditReadiness -State 'Unknown' -LockEventCount 5 -SecurityReadable $true).Key | Should -Be 'Recording'
    }

    It 'says plainly when it is off, and never reports silence as "never locked"' {
        $r = Get-LockAuditReadiness -State 'Off' -LockEventCount 0 -SecurityReadable $true
        $r.Key | Should -Be 'Off'
        $r.Line | Should -Match 'NOT recorded'
        (Get-LockAuditReadiness -State 'On' -LockEventCount 0 -SecurityReadable $true).Key | Should -Be 'OnButEmpty'
        (Get-LockAuditReadiness -State 'On' -LockEventCount 0 -SecurityReadable $false).Key | Should -Be 'NoSecurityLog'
    }
}

Describe 'dsregcmd parsing' {
    It 'resolves join type per the Microsoft Learn device-state table' {
        $j = { param($az, $dom) Resolve-JoinType -Status (ConvertFrom-DsregcmdStatus -Text "  AzureAdJoined : $az`n  EnterpriseJoined : NO`n  DomainJoined : $dom") }
        & $j 'YES' 'NO'  | Should -Be 'Microsoft Entra joined'
        & $j 'YES' 'YES' | Should -Be 'Microsoft Entra hybrid joined'
        & $j 'NO'  'YES' | Should -Be 'Domain joined (not Entra)'
    }

    It 'keeps the first value when a key repeats and keeps colons inside values' {
        $s = ConvertFrom-DsregcmdStatus -Text "  TenantName : Contoso`n  MdmUrl : https://enrollment.manage.microsoft.com/x`n  TenantName : Other"
        $s['TenantName'] | Should -Be 'Contoso'
        $s['MdmUrl'] | Should -Be 'https://enrollment.manage.microsoft.com/x'
    }
}

Describe 'New-SecurityQueryXml' {
    It 'filters logon types inside the query and uses UTC times' {
        $x = New-SecurityQueryXml -StartTime ([datetime]::new(2026, 10, 1, 0, 0, 0, [DateTimeKind]::Utc)) -EndTime ([datetime]::new(2026, 10, 2, 0, 0, 0, [DateTimeKind]::Utc))
        { [xml]$x } | Should -Not -Throw
        $x | Should -Match "Data\[@Name='LogonType'\]='7'"
        $x | Should -Not -Match "LogonType'\]='5'"
        $x | Should -Match "2026-10-01T00:00:00.000Z"
        $x | Should -Match 'EventID=4800'
    }
}

Describe 'Format-IntuneSummary' {
    BeforeAll {
        $script:MkReport = {
            param([int]$Days)
            $to = [datetime]'2026-10-15 12:00'
            $ev = @(for ($i = 0; $i -lt $Days; $i++) { New-Act Unlock ($to.AddDays(-$i).Date.AddHours(8).ToString('s')) })
            [PSCustomObject]@{
                Device = [PSCustomObject]@{ ComputerName = 'PC1'; JoinType = 'Microsoft Entra joined'; UtcOffset = 'UTC-04:00' }
                From = $to.AddDays(-$Days); To = $to; UserName = ''; Audit = [PSCustomObject]@{ Key = 'Off' }
                Coverage = @([PSCustomObject]@{ LogName = 'System'; Oldest = $to.AddDays(-400) })
                Daily = Get-DailySummary -Events $ev -From $to.AddDays(-$Days) -To $to
                OutputHint = 'C:\Tools\Entra-DeviceActivityTimeline\Reports\DeviceActivity_PC1.zip'
            }
        }
    }

    It 'stays within the 2,048-character Remediation output limit even for a year' {
        $text = Format-IntuneSummary -Report (& $script:MkReport 365)
        $text.Length | Should -BeLessOrEqual 2048
        $text | Should -Match 'older days in the full report'
        $text | Should -Match 'DeviceActivity_PC1.zip$'
    }

    It 'leaves room for the SHA-256 line the script appends to the Intune output' {
        # The script formats with 80 characters held back, then adds "SHA256 <64 hex>".
        $text = Format-IntuneSummary -Report (& $script:MkReport 365) -MaxLength (2048 - 80)
        ($text + "`nSHA256 " + ('a' * 64)).Length | Should -BeLessOrEqual 2048
    }

    It 'shows every day when they fit' {
        $text = Format-IntuneSummary -Report (& $script:MkReport 14)
        $text | Should -Not -Match 'older days'
        $text | Should -Match 'NOT recorded'
    }
}

Describe 'New-ActivityHtml' {
    It 'escapes account names and shows the audit verdict' {
        $ev = @([PSCustomObject]@{ Time = [datetime]'2026-10-01 08:00'; Kind = 'Unlock'; Label = 'Unlocked'; EventId = 4624; Source = 'Security 4624 type 7'
                                   User = 'AzureAD\<script>x'; UserSid = $script:Entra; Detail = ''; ClockFrom = $null; ClockTo = $null })
        $report = [PSCustomObject]@{
            Device = [PSCustomObject]@{ ComputerName = 'PC1'; JoinType = 'Microsoft Entra joined'; TenantName = 'Contoso'; IntuneAgent = $true; OS = 'Windows 11'; LastBoot = $null; TimeZone = 'Eastern Standard Time'; UtcOffset = 'UTC-04:00' }
            From = [datetime]'2026-10-01'; To = [datetime]'2026-10-02'; UserName = ''
            Audit = Get-LockAuditReadiness -State 'Off' -LockEventCount 0 -SecurityReadable $true
            Coverage = @(); Daily = Get-DailySummary -Events $ev -From '2026-10-01' -To '2026-10-02'; Events = $ev; Notes = @(); GeneratedOn = '2026-10-02 09:00'
        }
        $html = New-ActivityHtml -Report $report
        $html | Should -Not -Match '<script>x'
        $html | Should -Match '&lt;script&gt;x'
        $html | Should -Match 'NOT recorded'
        $html | Should -Match 'UTC-04:00'
    }
}
