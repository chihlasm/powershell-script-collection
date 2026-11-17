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
