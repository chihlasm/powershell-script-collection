<#
    End-to-end: runs the real Export-ADGroupMembership.ps1, in its own PowerShell process,
    against a stand-in ActiveDirectory module (Tests\FakeAD) and checks every output file.

    Why this exists: the unit tests call functions directly with hand-built arrays, and the
    HTML report still failed on a real Server 2019 run. The main flow passes a List[object],
    and @() on a List[object] throws "Argument types do not match" on PowerShell 5.1.26100
    and 7.6 - a failure only a whole-script run reproduces. The report step catches errors so
    the group CSV survives, which also means a broken report shows up only as a missing file
    and a [FAIL] log line; this test checks for both.

    The fake directory includes real-world quirks: a user whose primary group is a custom
    group (and is also returned by Get-ADGroupMember), a foreign security principal, a member
    whose details cannot be read, a nesting cycle, a gMSA, a computer and a disabled user.
#>

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:Out = Join-Path $TestDrive 'out'
    $null = New-Item -ItemType Directory -Path $script:Out -Force

    $exe = (Get-Process -Id $PID).Path
    $fake = Join-Path $PSScriptRoot 'FakeAD'
    $export = Join-Path $script:Root 'Export-ADGroupMembership.ps1'
    $command = "`$env:PSModulePath = '$fake;' + `$env:PSModulePath; " +
               "& '$export' -IncludeNested -ExcludeBuiltin -UserReport -OutputPath '$($script:Out)' *> `$null; exit `$LASTEXITCODE"
    & $exe -NoProfile -NonInteractive -Command $command
    $script:ExitCode = $LASTEXITCODE

    $script:Log      = Get-ChildItem $script:Out -Filter 'ADGroupMembership_*.log' | Select-Object -First 1
    $script:GroupCsv = Get-ChildItem $script:Out -Filter 'ADGroupMembership_*.csv' | Select-Object -First 1
    $script:Html     = Get-ChildItem $script:Out -Filter 'ADUserAccess_*.html' | Select-Object -First 1
    $script:UserCsv  = Get-ChildItem $script:Out -Filter 'ADUserAccess_*.csv' | Select-Object -First 1
}

Describe 'Export-ADGroupMembership.ps1 -UserReport, end to end' {

    It 'exits successfully' {
        $script:ExitCode | Should -Be 0
    }

    It 'writes all four files' {
        $script:Log | Should -Not -BeNullOrEmpty
        $script:GroupCsv | Should -Not -BeNullOrEmpty
        $script:Html | Should -Not -BeNullOrEmpty -Because 'a missing HTML report means the report step failed'
        $script:UserCsv | Should -Not -BeNullOrEmpty
    }

    It 'logs no failures' {
        $fails = @(Get-Content -LiteralPath $script:Log.FullName | Where-Object { $_ -match '\[FAIL\]' })
        $fails | Should -BeNullOrEmpty
    }

    Context 'report content' {
        BeforeAll {
            $text = [System.IO.File]::ReadAllText($script:Html.FullName)
            $m = [regex]::Match($text, '<script type="application/json" id="report-data">(.*?)</script>', 'Singleline')
            $script:Data = ConvertFrom-Json $m.Groups[1].Value
            function Find-G([string]$Name) { @($script:Data.groups | Where-Object { $_.n -eq $Name })[0] }
            function Id-Of([string]$Sam) {
                for ($i = 0; $i -lt @($script:Data.people).Count; $i++) { if ($script:Data.people[$i].s -eq $Sam) { return $i } }
                -1
            }
        }

        It 'embeds the group data, with builtin groups excluded' {
            @($script:Data.groups).Count | Should -Be 8
            Find-G 'Domain Users' | Should -BeNullOrEmpty
        }

        It 'counts a primary-group member once, as Primary (no false duplicate)' {
            $alice = Id-Of 'alice'
            $entries = @((Find-G 'RDS-Users').m | Where-Object { $_[0] -eq $alice })
            $entries.Count | Should -Be 1
            $entries[0][1] | Should -Be 1
            $row = Import-Csv -LiteralPath $script:UserCsv.FullName | Where-Object { $_.SamAccountName -eq 'alice' }
            $row.RedundantCount | Should -Be '0'
        }

        It 'records nesting and lists non-user members' {
            @((Find-G 'HR-Share-RW').k).Count | Should -BeGreaterThan 0
            @((Find-G 'HR-Share-RW').o | ForEach-Object { $_[1] }) | Should -Contain 'foreignSecurityPrincipal'
            @((Find-G 'Kiosks').o | ForEach-Object { $_[1] }) | Should -Contain 'computer'
        }

        It 'keeps a member whose details could not be read, and leaves out the disabled user' {
            Id-Of 'ghost' | Should -BeGreaterOrEqual 0
            Id-Of 'carol' | Should -Be -1
        }
    }
}
