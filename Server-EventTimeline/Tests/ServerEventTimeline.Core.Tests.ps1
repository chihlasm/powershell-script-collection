<#
    Pester 5 tests for ServerEventTimeline.Core.ps1 (pure logic: no network, no UI, no real
    event logs). Run:  pwsh -File Tests\Invoke-AllTests.ps1 -Path .\Server-EventTimeline\Tests
#>

BeforeAll {
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'ServerEventTimeline.Core.ps1')
}

Describe 'ConvertTo-ServerList' {
    It 'splits, trims, drops empties and de-duplicates case-insensitively keeping the first spelling' {
        $text = "app01, APP01;sql01.contoso.local`n`n 10.0.0.5,"
        $result = @(ConvertTo-ServerList -Text $text)
        $result | Should -Be @('app01', 'sql01.contoso.local', '10.0.0.5')
    }

    It 'returns an empty array for blank input' {
        @(ConvertTo-ServerList -Text "  `n ,; ").Count | Should -Be 0
    }
}

Describe 'New-TimelineWindow' {
    It 'Around gives the time plus and minus the minutes, as server-local wall-clock' {
        $w = New-TimelineWindow -Mode Around -At ([datetime]'2026-11-17 03:00') -PlusMinusMinutes 15
        $w.StartLocal | Should -Be ([datetime]'2026-11-17 02:45')
        $w.EndLocal   | Should -Be ([datetime]'2026-11-17 03:15')
        $w.StartLocal.Kind | Should -Be ([DateTimeKind]::Unspecified)
    }

    It 'Range rejects From after To with a plain message' {
        { New-TimelineWindow -Mode Range -From ([datetime]'2026-11-17 04:00') -To ([datetime]'2026-11-17 03:00') } |
            Should -Throw -ExpectedMessage '*From must be before To*'
    }

    It 'Around without -At throws a plain message' {
        { New-TimelineWindow -Mode Around -PlusMinusMinutes 15 } | Should -Throw -ExpectedMessage '*time*'
    }

    It 'Range across the 2026-11-01 US DST change keeps the typed wall-clock values' {
        $w = New-TimelineWindow -Mode Range -From ([datetime]'2026-11-01 00:30') -To ([datetime]'2026-11-01 03:30')
        $w.StartLocal | Should -Be ([datetime]'2026-11-01 00:30')
        $w.EndLocal   | Should -Be ([datetime]'2026-11-01 03:30')
    }

    It 'Relative keeps the minutes' {
        (New-TimelineWindow -Mode Relative -LastMinutes 60).LastMinutes | Should -Be 60
    }
}

Describe 'ConvertTo-UtcWindow' {
    It 'subtracts the server UTC offset for Around/Range' {
        $w = New-TimelineWindow -Mode Around -At ([datetime]'2026-11-17 03:00') -PlusMinusMinutes 15
        $u = ConvertTo-UtcWindow -Window $w -UtcOffsetMinutes -300
        $u.StartUtc | Should -Be ([datetime]'2026-11-17 07:45')
        $u.EndUtc   | Should -Be ([datetime]'2026-11-17 08:15')
        $u.StartUtc.Kind | Should -Be ([DateTimeKind]::Utc)
    }

    It 'Relative counts back from NowUtc' {
        $w = New-TimelineWindow -Mode Relative -LastMinutes 60
        $now = [datetime]::SpecifyKind([datetime]'2026-11-17 12:00', [DateTimeKind]::Utc)
        $u = ConvertTo-UtcWindow -Window $w -UtcOffsetMinutes 120 -NowUtc $now
        $u.StartUtc | Should -Be ([datetime]'2026-11-17 11:00')
        $u.EndUtc   | Should -Be ([datetime]'2026-11-17 12:00')
    }
}

Describe 'Get-TimelineLogCatalog' {
    BeforeAll { $script:Catalog = @(Get-TimelineLogCatalog) }

    It 'has System and Application ticked by default' {
        ($script:Catalog | Where-Object Name -eq 'System').Default      | Should -BeTrue
        ($script:Catalog | Where-Object Name -eq 'Application').Default | Should -BeTrue
    }

    It 'has Security unticked by default' {
        ($script:Catalog | Where-Object Name -eq 'Security').Default | Should -BeFalse
    }

    It 'has at most 12 operational logs, all ticked by default' {
        $ops = @($script:Catalog | Where-Object Group -eq 'Operational')
        $ops.Count | Should -BeGreaterThan 0
        $ops.Count | Should -BeLessOrEqual 12
        @($ops | Where-Object { -not $_.Default }).Count | Should -Be 0
    }

    It 'has no duplicate names and every entry has a label' {
        $names = @($script:Catalog | ForEach-Object Name)
        @($names | Select-Object -Unique).Count | Should -Be $names.Count
        @($script:Catalog | Where-Object { -not $_.Label }).Count | Should -Be 0
    }
}

Describe 'Get-EventFlag' {
    It 'flags User32 1074 as a restart' {
        (Get-EventFlag -Log System -Provider User32 -Id 1074).Category | Should -Be 'Restart'
    }

    It 'does not flag the same ID from a different provider' {
        Get-EventFlag -Log System -Provider 'Some-Other' -Id 1074 | Should -BeNullOrEmpty
    }

    It 'flags Service Control Manager 7031 as a service crash' {
        (Get-EventFlag -Log System -Provider 'Service Control Manager' -Id 7031).Category | Should -Be 'ServiceCrash'
    }

    It 'flags Application Error 1000 in the Application log as an app crash' {
        (Get-EventFlag -Log Application -Provider 'Application Error' -Id 1000).Category | Should -Be 'AppCrash'
    }

    It 'tells the two 1001 events apart by log and provider' {
        (Get-EventFlag -Log System -Provider 'Microsoft-Windows-WER-SystemErrorReporting' -Id 1001).Category | Should -Be 'Bugcheck'
        (Get-EventFlag -Log Application -Provider 'Windows Error Reporting' -Id 1001).Category | Should -Be 'AppCrash'
    }

    It 'matches the controller driver for disk controller event 11 (stornvme, storahci)' {
        (Get-EventFlag -Log System -Provider 'stornvme' -Id 11).Category | Should -Be 'Disk'
        (Get-EventFlag -Log System -Provider 'storahci' -Id 11).Category | Should -Be 'Disk'
        Get-EventFlag -Log System -Provider 'Microsoft-Windows-Kernel-General' -Id 11 | Should -BeNullOrEmpty
    }

    It 'matches both spellings of the NTFS provider' {
        (Get-EventFlag -Log System -Provider 'Ntfs' -Id 55).Category | Should -Be 'Disk'
        (Get-EventFlag -Log System -Provider 'Microsoft-Windows-Ntfs' -Id 55).Category | Should -Be 'Disk'
    }

    It 'leaves dropped (unverified) IDs unflagged' {
        Get-EventFlag -Log System -Provider 'Service Control Manager' -Id 7023 | Should -BeNullOrEmpty
    }

    It 'every catalog entry has a category and a label' {
        @($script:FlagCatalog | Where-Object { -not $_.Category -or -not $_.Label }).Count | Should -Be 0
    }
}

Describe 'ConvertTo-TimelineRow' {
    BeforeAll {
        function New-FakeEvent {
            param($Level = 4, $Message = 'Line one', $Provider = 'Service Control Manager', $Id = 7036,
                  $Time = '2026-11-17 08:00:00', $Log = 'System', $RecordId = 1)
            [PSCustomObject]@{
                TimeCreatedUtc = [datetime]::SpecifyKind([datetime]$Time, [DateTimeKind]::Utc)
                Id = $Id; ProviderName = $Provider; Level = $Level; LogName = $Log; Message = $Message
                RecordId = $RecordId; UserSid = 'S-1-5-18'; MachineName = 'app01.contoso.local'
            }
        }
    }

    It 'maps numeric levels to names (never the localized display name)' {
        (ConvertTo-TimelineRow -Server APP01 -Event (New-FakeEvent -Level 1) -UtcOffsetMinutes 0).LevelName | Should -Be 'Critical'
        (ConvertTo-TimelineRow -Server APP01 -Event (New-FakeEvent -Level 2) -UtcOffsetMinutes 0).LevelName | Should -Be 'Error'
        (ConvertTo-TimelineRow -Server APP01 -Event (New-FakeEvent -Level 3) -UtcOffsetMinutes 0).LevelName | Should -Be 'Warning'
        (ConvertTo-TimelineRow -Server APP01 -Event (New-FakeEvent -Level 0) -UtcOffsetMinutes 0).LevelName | Should -Be 'Information'
        (ConvertTo-TimelineRow -Server APP01 -Event (New-FakeEvent -Level 4) -UtcOffsetMinutes 0).LevelName | Should -Be 'Information'
    }

    It 'explains a missing message instead of leaving it blank' {
        $row = ConvertTo-TimelineRow -Server SQL01 -Event (New-FakeEvent -Message $null -Provider MSSQLSERVER -Id 17883 -Log Application) -UtcOffsetMinutes 0
        $expected = "(No message text: the event's provider isn't installed on this workstation. Event 17883 from MSSQLSERVER.)"
        $row.Message | Should -Be $expected
        $row.MessageFirstLine | Should -Be $expected
    }

    It 'uses the first non-empty line as the short message' {
        $row = ConvertTo-TimelineRow -Server APP01 -Event (New-FakeEvent -Message "`r`n  `r`nFirst real line`r`nSecond") -UtcOffsetMinutes 0
        $row.MessageFirstLine | Should -Be 'First real line'
    }

    It 'shows server-local time as UTC plus the offset and fills the flag' {
        $row = ConvertTo-TimelineRow -Server APP01 -Event (New-FakeEvent -Provider User32 -Id 1074) -UtcOffsetMinutes -300
        $row.TimeServerLocal | Should -Be ([datetime]'2026-11-17 03:00:00')
        $row.TimeUtc | Should -Be ([datetime]'2026-11-17 08:00:00')
        $row.FlagCategory | Should -Be 'Restart'
        $row.Flag | Should -Not -BeNullOrEmpty
        $row.Server | Should -Be 'APP01'
        $row.EventId | Should -Be 1074
    }
}

Describe 'Merge-TimelineRows' {
    It 'orders rows from several servers by UTC time' {
        $mk = { param($s, $t) [PSCustomObject]@{ Server = $s; TimeUtc = [datetime]$t; RecordId = 1 } }
        $rows = @((& $mk 'SQL01' '2026-11-17 08:05'), (& $mk 'APP01' '2026-11-17 08:01'), (& $mk 'DC01' '2026-11-17 08:03'))
        (@(Merge-TimelineRows -Rows $rows) | ForEach-Object Server) | Should -Be @('APP01', 'DC01', 'SQL01')
    }
}
