<#
    Tests for TicketNote\Join-TicketNotes.ps1 (Pester 5, run under pwsh). SQ-001 AC15-AC17, AC26.

    The joiner runs in-process (`exit` in a script file only leaves that script). The clipboard
    is never touched: Set-Clipboard is mocked, or -NoClipboard is passed. Read-Host is mocked.
    Every folder lives under $TestDrive, and -OutputPath is always given so the real profile
    folder is never used.

    Run:  Invoke-Pester .\TicketNote\Tests\Join-TicketNotes.Tests.ps1
#>

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:RepoRoot = Split-Path -Parent $script:Root
    $script:Joiner = Join-Path $script:Root 'Join-TicketNotes.ps1'
    $utf8 = New-Object System.Text.UTF8Encoding($true)

    function New-TicketFolderWithNotes {
        param([string]$Root, [string]$Number = '482113')
        $dir = Join-Path $Root "Ticket_$Number"
        $null = New-Item -ItemType Directory -Path $dir -Force
        # Written out of order on purpose: name order is time order.
        [System.IO.File]::WriteAllText((Join-Path $dir 'Note_2026-10-17_101500_Network-QuickCheck.txt'), "NOTE-TWO-BODY`r`n", $utf8)
        [System.IO.File]::WriteAllText((Join-Path $dir 'Note_2026-10-17_093000_AD-UserQuickCheck.txt'), "NOTE-ONE-BODY`r`n", $utf8)
        [System.IO.File]::WriteAllText((Join-Path $dir 'Note_2026-10-17_111000_Citrix-FSLogix-Triage.txt'), "NOTE-THREE-BODY`r`n", $utf8)
        [System.IO.File]::WriteAllText((Join-Path $dir 'TicketNotes_Combined_2026-10-16_080000.txt'), "OLD-COMBINED-BODY`r`n", $utf8)
        $dir
    }
}

Describe 'Join-TicketNotes' {
    BeforeEach { $global:LASTEXITCODE = 0 }

    It 'AC15_JoinerCombines: writes one combined note, in timestamp order, and copies it once' {
        Mock Set-Clipboard { }
        $root = Join-Path $TestDrive 'ac15'
        $dir = New-TicketFolderWithNotes -Root $root
        & $script:Joiner -TicketNumber '482113' -OutputPath $root -UserReported 'S: missing' -TechTried 'gpupdate /force' 6>$null

        $new = @(Get-ChildItem -LiteralPath $dir -Filter 'TicketNotes_Combined_*.txt' | Where-Object { $_.Name -ne 'TicketNotes_Combined_2026-10-16_080000.txt' })
        $new.Count | Should -Be 1
        $new[0].Name | Should -Match '^TicketNotes_Combined_\d{4}-\d{2}-\d{2}_\d{6}\.txt$'
        $text = [System.IO.File]::ReadAllText($new[0].FullName, (New-Object System.Text.UTF8Encoding($true)))
        $lines = @($text -split "`r?`n")
        $head = @($lines | Where-Object { $_.Trim() } | Select-Object -First 3)
        $head[0] | Should -Be 'Ticket 482113 - 3 notes'
        $head[1] | Should -Be 'User reported: S: missing'
        $head[2] | Should -Be 'Tech tried by hand: gpupdate /force'

        $one = $text.IndexOf('NOTE-ONE-BODY'); $two = $text.IndexOf('NOTE-TWO-BODY'); $three = $text.IndexOf('NOTE-THREE-BODY')
        $one | Should -BeGreaterThan 0
        $two | Should -BeGreaterThan $one
        $three | Should -BeGreaterThan $two
        @($lines | Where-Object { $_ -eq '-----' }).Count | Should -BeGreaterOrEqual 2
        $text | Should -Not -Match 'OLD-COMBINED-BODY'

        Should -Invoke Set-Clipboard -Times 1 -Exactly
    }

    It 'AC16_JoinerPromptsAndAllowsBlank: omitted answers are asked for, and blank means (not given)' {
        Mock Set-Clipboard { }
        Mock Read-Host { '' }
        $root = Join-Path $TestDrive 'ac16'
        $dir = New-TicketFolderWithNotes -Root $root
        & $script:Joiner -TicketNumber '482113' -OutputPath $root -NoClipboard 6>$null

        Should -Invoke Read-Host -Times 1 -Exactly -ParameterFilter { $Prompt -like '*user report*' }
        Should -Invoke Read-Host -Times 1 -Exactly -ParameterFilter { $Prompt -like '*already try*' }
        $new = @(Get-ChildItem -LiteralPath $dir -Filter 'TicketNotes_Combined_*.txt' | Where-Object { $_.Name -ne 'TicketNotes_Combined_2026-10-16_080000.txt' })
        $new.Count | Should -Be 1
        $lines = @(Get-Content -LiteralPath $new[0].FullName -Encoding UTF8)
        $lines | Should -Contain 'User reported: (not given)'
        $lines | Should -Contain 'Tech tried by hand: (not given)'
    }

    It 'AC17_JoinerNothingToJoin: no folder -> [WARN] line, no file, exit 1' {
        $root = Join-Path $TestDrive 'ac17'
        $null = New-Item -ItemType Directory -Path $root
        $records = @(& $script:Joiner -TicketNumber '482113' -OutputPath $root -UserReported 'a' -TechTried 'b' -NoClipboard 6>&1)
        $code = $LASTEXITCODE
        $out = (@($records | ForEach-Object { $_.ToString() })) -join "`n"
        $folder = Join-Path $root 'Ticket_482113'
        $out | Should -Match ([regex]::Escape("[WARN] No ticket notes found for ticket 482113 in $folder."))
        $code | Should -Be 1
        @(Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue).Count | Should -Be 0
    }

    It 'AC17_JoinerNothingToJoin: a folder with only an old combined file also exits 1 and writes nothing new' {
        $root = Join-Path $TestDrive 'ac17b'
        $dir = Join-Path $root 'Ticket_482113'
        $null = New-Item -ItemType Directory -Path $dir -Force
        Set-Content -LiteralPath (Join-Path $dir 'TicketNotes_Combined_2026-10-16_080000.txt') -Value 'old'
        $null = & $script:Joiner -TicketNumber '482113' -OutputPath $root -UserReported 'a' -TechTried 'b' -NoClipboard 6>&1
        $LASTEXITCODE | Should -Be 1
        @(Get-ChildItem -LiteralPath $dir -File).Count | Should -Be 1
    }
}

Describe 'the bundle' {
    It 'AC26_BundleShipsJoiner: the ServiceDesk-Toolkit manifest has a TicketNote folder entry' {
        $build = Join-Path $script:RepoRoot 'ServiceDesk-Toolkit\Build-ServiceDeskToolkit.ps1'
        $text = Get-Content -LiteralPath $build -Raw
        $text | Should -Match "(?m)^\s*@\{\s*Source\s*=\s*'TicketNote'\s*;\s*Destination\s*=\s*'TicketNote'\s*\}"
    }
}
