<#
    Tests for TicketNote\CaseKit.ps1 (Pester 5, run under pwsh). SQ-001 acceptance criteria AC1-AC13.

    The clipboard is never touched for real: every test that reaches the clipboard code mocks
    Set-Clipboard and/or Invoke-WinFormsClipboard. All files are written under $TestDrive.
    Synthetic data only (contoso.com, jdoe, Jane Doe, 10.x addresses).

    Run:  Invoke-Pester .\TicketNote\Tests\CaseKit.Tests.ps1
#>

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:RepoRoot = Split-Path -Parent $script:Root
    $script:KitPath = Join-Path $script:Root 'CaseKit.ps1'
    . $script:KitPath
    . (Join-Path $script:RepoRoot 'Tests\PSVersionFloor.Analyzer.ps1')

    $script:Now = Get-Date -Year 2026 -Month 10 -Day 17 -Hour 9 -Minute 30 -Second 12 -Millisecond 0
    # The kit prints the machine's own UTC offset, so the expected text is computed, not hard-coded.
    $off = [TimeZoneInfo]::Local.GetUtcOffset($script:Now)
    $script:OffsetText = '{0}{1:00}:{2:00}' -f $(if ($off -lt [TimeSpan]::Zero) { '-' } else { '+' }), [math]::Abs($off.Hours), [math]::Abs($off.Minutes)

    function New-TestStamp {
        New-TicketNoteStamp -ScopeLabel Domain -Scope 'contoso.com' -Now $script:Now -UserName 'CONTOSO\jtech' -ComputerName 'WS-114'
    }
    function New-TestNote {
        param([object[]]$Items = @(), [string[]]$NextSteps = @(), [string[]]$Evidence = @(), [string]$Headline = 'Can Jane Doe sign in right now? NO')
        New-TicketNote -Tool 'AD-UserQuickCheck' -Headline $Headline -ScopeLine 'AD account jdoe in contoso.com.' `
            -Items $Items -NextSteps $NextSteps -Stamp (New-TestStamp) -EvidencePaths $Evidence
    }
    # Returns the message of whatever the script block throws, or $null when it does not throw.
    function Get-ThrownMessage([scriptblock]$Block) {
        try { & $Block | Out-Null } catch { return $_.Exception.Message }
        return $null
    }
}

Describe 'the gate' {
    It 'AC1_GatedOutCheckNeverRuledOut: a Clear item without -CouldLook is Could not check' {
        $none = New-TicketNoteItem -Kind Clear -Text 'No recent wrong-password attempts.'
        $false1 = New-TicketNoteItem -Kind Clear -Text 'Not locked out.' -CouldLook $false
        $note = New-TestNote -Items @($none, $false1)
        ($note.CouldNotCheck -join "`n") | Should -Match 'No recent wrong-password attempts\.'
        ($note.CouldNotCheck -join "`n") | Should -Match 'Not locked out\.'
        ($note.RuledOut -join "`n") | Should -Not -Match 'No recent wrong-password'
        ($note.RuledOut -join "`n") | Should -Not -Match 'Not locked out'
        $lines = ConvertTo-TicketNoteText -Note $note
        $ruled = [array]::IndexOf($lines, 'Ruled out:')
        $could = [array]::IndexOf($lines, 'Could not check:')
        @($lines[$ruled..($could - 1)] | Where-Object { $_ -match 'Not locked out' }).Count | Should -Be 0
        @($lines[$could..($lines.Count - 1)] | Where-Object { $_ -match 'Not locked out' }).Count | Should -BeGreaterThan 0
    }

    It 'AC2_ConfirmedClearIsRuledOut: a Clear item with -CouldLook $true is Ruled out only' {
        $item = New-TicketNoteItem -Kind Clear -Text 'Account is turned on.' -CouldLook $true
        $note = New-TestNote -Items @($item)
        ($note.RuledOut -join "`n") | Should -Match 'Account is turned on\.'
        ($note.CouldNotCheck -join "`n") | Should -Not -Match 'Account is turned on'
    }
}

Describe 'layout and stamp' {
    It 'AC3_NoteLayout: headline, four sections, prefixes, (none), stamp and evidence' {
        $items = @(
            (New-TicketNoteItem -Kind Info -Text 'i-text'),
            (New-TicketNoteItem -Kind Problem -Text 'p-text'),
            (New-TicketNoteItem -Kind Clear -Text 'clear-text' -CouldLook $true),
            (New-TicketNoteItem -Kind Warning -Text 'w-text'),
            (New-TicketNoteItem -Kind NotChecked -Text 'nc-text')
        )
        $note = New-TestNote -Items $items -NextSteps @('step one', 'step two') -Evidence @('C:\out\Report.html', 'C:\out\Report.csv')
        $lines = @(ConvertTo-TicketNoteText -Note $note)
        $stampLine = "Domain: contoso.com | Ran by: CONTOSO\jtech on WS-114 | 2026-10-17 09:30:12 (UTC$($script:OffsetText)) | Changed anything: No"
        $expected = @(
            '[Ticket note] AD-UserQuickCheck: Can Jane Doe sign in right now? NO'
            ''
            'Checked:'
            '- AD account jdoe in contoso.com.'
            '- PROBLEM: p-text'
            '- WARNING: w-text'
            '- INFO: i-text'
            'Ruled out:'
            '- clear-text'
            'Could not check:'
            '- nc-text'
            'Next step:'
            '- step one'
            '- step two'
            ''
            $stampLine
            'Evidence: Report.html, Report.csv'
        )
        ($lines -join "`n") | Should -Be ($expected -join "`n")

        $empty = @(ConvertTo-TicketNoteText -Note (New-TestNote))
        $at = [array]::IndexOf($empty, 'Ruled out:')
        $empty[$at + 1] | Should -Be '- (none)'
        $at = [array]::IndexOf($empty, 'Could not check:')
        $empty[$at + 1] | Should -Be '- (none)'
        $at = [array]::IndexOf($empty, 'Next step:')
        $empty[$at + 1] | Should -Be '- (none)'
    }

    It 'AC4_StampReadOnly: exact stamp line, and -RunAs adds (as <RunAs>)' {
        $note = New-TestNote
        $line = @(ConvertTo-TicketNoteText -Note $note | Where-Object { $_ -like 'Domain: *' })[0]
        $line | Should -Be "Domain: contoso.com | Ran by: CONTOSO\jtech on WS-114 | 2026-10-17 09:30:12 (UTC$($script:OffsetText)) | Changed anything: No"

        $stamp = New-TicketNoteStamp -ScopeLabel Domain -Scope 'contoso.com' -RunAs 'CONTOSO\svc-help' -Now $script:Now -UserName 'CONTOSO\jtech' -ComputerName 'WS-114'
        $note2 = New-TicketNote -Tool 'AD-UserQuickCheck' -Headline 'h' -ScopeLine 's' -Items @() -NextSteps @() -Stamp $stamp -EvidencePaths @()
        $line2 = @(ConvertTo-TicketNoteText -Note $note2 | Where-Object { $_ -like 'Domain: *' })[0]
        $line2 | Should -BeLike 'Domain: contoso.com | Ran by: CONTOSO\jtech on WS-114 (as CONTOSO\svc-help) | *'
    }

    It 'AC5_StampChangedNeedsLog: -Changed without -ChangeLogPath throws; with it the stamp says Yes' {
        $msg = Get-ThrownMessage { New-TicketNoteStamp -ScopeLabel Domain -Scope 'contoso.com' -Changed -Now $script:Now -UserName 'u' -ComputerName 'm' }
        $msg | Should -Not -BeNullOrEmpty
        $msg | Should -Not -Match 'not implemented'

        $stamp = New-TicketNoteStamp -ScopeLabel Domain -Scope 'contoso.com' -Changed -ChangeLogPath 'C:\logs\change.log' -Now $script:Now -UserName 'u' -ComputerName 'm'
        $note = New-TicketNote -Tool 'AD-UserQuickCheck' -Headline 'h' -ScopeLine 's' -Items @() -NextSteps @() -Stamp $stamp -EvidencePaths @()
        $line = @(ConvertTo-TicketNoteText -Note $note | Where-Object { $_ -like 'Domain: *' })[0]
        $line | Should -BeLike '*Changed anything: Yes - change log: C:\logs\change.log'
    }
}

Describe 'paste-safe redaction' {
    BeforeAll {
        function Get-RiskyItems { @(
            (New-TicketNoteItem -Kind Info -Text 'Reached 10.1.2.3 fine')
            (New-TicketNoteItem -Kind Info -Text 'Port open on 10.1.2.3:445')
            (New-TicketNoteItem -Kind Info -Text 'Link-local fe80::1 answered')
            (New-TicketNoteItem -Kind Info -Text 'Mapped [::ffff:10.0.0.5]:445 ok')
            (New-TicketNoteItem -Kind Info -Text 'Profile share \\fs01\profiles$\jdoe is slow')
        ) }
    }

    It 'AC6_PasteSafeRedaction: IPs, UNC paths and evidence directories are removed; headline is not' {
        $headline = 'Can Jane Doe reach 10.9.9.9?'
        $note = New-TestNote -Items (Get-RiskyItems) -Evidence @('C:\x\y\Report.html') -Headline $headline
        $safe = @(ConvertTo-TicketNoteText -Note $note -PasteSafe)
        $text = $safe -join "`n"
        $text | Should -Not -Match '10\.1\.2\.3'
        $text | Should -Not -Match '10\.0\.0\.5'
        $text | Should -Not -Match 'fe80'
        $text | Should -Not -Match '::ffff'
        $text | Should -Not -Match 'fs01'
        $text | Should -Match '\[IP removed\]'
        $text | Should -Match '\[share path removed\]'
        $text | Should -Match 'Evidence: Report\.html$'
        $text | Should -Not -Match 'C:\\x\\y'
        $safe[0] | Should -Be "[Ticket note] AD-UserQuickCheck: $headline"

        $full = @(ConvertTo-TicketNoteText -Note $note) -join "`n"
        $full | Should -Match '10\.1\.2\.3:445'
        $full | Should -Match 'fe80::1'
        $full | Should -Match '\[::ffff:10\.0\.0\.5\]:445'
        $full | Should -Match ([regex]::Escape('\\fs01\profiles$\jdoe'))
        $full | Should -Match 'Evidence: Report\.html$'
        $full | Should -Not -Match 'C:\\x\\y'
    }

    It 'AC6_PasteSafeRedaction: Protect-TicketNoteText redacts each form on its own' {
        (Protect-TicketNoteText -Line 'ip 10.1.2.3') | Should -Be 'ip [IP removed]'
        (Protect-TicketNoteText -Line 'ip 10.1.2.3:445') | Should -Not -Match '10\.1\.2\.3'
        (Protect-TicketNoteText -Line 'ip fe80::1') | Should -Not -Match 'fe80'
        (Protect-TicketNoteText -Line 'ip [::ffff:10.0.0.5]:445') | Should -Not -Match '10\.0\.0\.5'
        (Protect-TicketNoteText -Line 'at \\fs01\profiles$\jdoe now') | Should -Be 'at [share path removed] now'
    }
}

Describe 'saving the note' {
    It 'AC7_NoteFileUtf8Bom: the file starts with EF BB BF and keeps non-ASCII text' {
        $name = 'M' + [char]0x00FC + 'ller'
        $note = New-TestNote -Headline "Can $name sign in right now? YES"
        $folder = Join-Path $TestDrive 'bom'
        $null = New-Item -ItemType Directory -Path $folder
        $path = Save-TicketNote -Note $note -Folder $folder
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $bytes[0] | Should -Be 0xEF
        $bytes[1] | Should -Be 0xBB
        $bytes[2] | Should -Be 0xBF
        ([System.IO.File]::ReadAllText($path, (New-Object System.Text.UTF8Encoding($true)))) | Should -Match $name
    }

    It 'AC8_NoteFileNamesDoNotCollide: a second note with the same timestamp gets _2' {
        $folder = Join-Path $TestDrive 'collide'
        $null = New-Item -ItemType Directory -Path $folder
        $n1 = New-TestNote
        $n2 = New-TestNote
        $n2.CreatedAt = $n1.CreatedAt
        $p1 = Save-TicketNote -Note $n1 -Folder $folder
        $p2 = Save-TicketNote -Note $n2 -Folder $folder
        $names = @(Get-ChildItem -LiteralPath $folder -File | ForEach-Object Name | Sort-Object)
        $names.Count | Should -Be 2
        (Split-Path $p1 -Leaf) | Should -Match '^Note_\d{4}-\d{2}-\d{2}_\d{6}_AD-UserQuickCheck\.txt$'
        (Split-Path $p2 -Leaf) | Should -Match '^Note_\d{4}-\d{2}-\d{2}_\d{6}_AD-UserQuickCheck_2\.txt$'
    }
}

Describe 'clipboard' {
    It 'AC9_ClipboardFallback: no Set-Clipboard -> the WinForms wrapper is called once with the text' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Set-Clipboard' }
        Mock Set-Clipboard { }
        Mock Invoke-WinFormsClipboard { }
        $result = Copy-TicketNoteToClipboard -Text 'the whole note'
        $result | Should -BeTrue
        Should -Invoke Invoke-WinFormsClipboard -Times 1 -Exactly -ParameterFilter { $Text -eq 'the whole note' }
        Should -Invoke Set-Clipboard -Times 0 -Exactly
    }

    It 'AC10_ClipboardFailureIsNotFatal: both clipboards throw -> returns $false, does not throw' {
        Mock Set-Clipboard { throw 'no clipboard' }
        Mock Invoke-WinFormsClipboard { throw 'no desktop' }
        $result = $null
        { $script:result = Copy-TicketNoteToClipboard -Text 'x' } | Should -Not -Throw
        $script:result | Should -BeFalse
        $script:result | Should -Not -BeNullOrEmpty -Because 'it must return $false, not nothing'
    }

    It 'AC11_NeverClipExe: neither the kit nor the joiner calls clip.exe' {
        foreach ($f in @($script:KitPath, (Join-Path $script:Root 'Join-TicketNotes.ps1'))) {
            Test-Path -LiteralPath $f | Should -BeTrue
            $tokens = $null; $errs = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$tokens, [ref]$errs)
            # Comments may explain why clip.exe is avoided (the spec asks for that citation); code may not use it.
            $code = (@($tokens | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text }) -join ' ')
            $code | Should -Not -Match '(?i)clip\.exe'
            $code | Should -Not -Match '(?i)\|\s*clip(?![\w\-])'
        }
    }
}

Describe 'ticket folder' {
    It 'AC12_TicketFolder: creates Ticket_<n> and returns its path' {
        $path = Resolve-TicketFolder -TicketNumber '482113' -Root $TestDrive
        $path | Should -Be (Join-Path $TestDrive 'Ticket_482113')
        Test-Path -LiteralPath $path -PathType Container | Should -BeTrue
    }

    It 'AC12_TicketFolder: rejects traversal, slashes, empty and too-long numbers, creating nothing' {
        $root = Join-Path $TestDrive 'strict'
        $null = New-Item -ItemType Directory -Path $root
        foreach ($bad in @('..\x', '48/1', '', ('9' * 33))) {
            $b = $bad
            $msg = Get-ThrownMessage { Resolve-TicketFolder -TicketNumber $b -Root $root }
            $msg | Should -Not -BeNullOrEmpty -Because "'$bad' must be rejected"
            $msg | Should -Not -Match 'not implemented'
        }
        @(Get-ChildItem -LiteralPath $root -Force).Count | Should -Be 0
        (Test-Path -LiteralPath (Join-Path $TestDrive 'x')) | Should -BeFalse
    }
}

Describe 'the kit file itself' {
    It 'AC13_KitStaysOnPs3: declares #Requires -Version 3.0, floors at 3.0, and is pure ASCII' {
        Test-Path -LiteralPath $script:KitPath | Should -BeTrue
        $r = Get-PSVersionFloor -Path $script:KitPath
        $r.DeclaredVersion | Should -Be ([version]'3.0')
        $r.CodeFloor | Should -Be ([version]'3.0')
        $bytes = [System.IO.File]::ReadAllBytes($script:KitPath)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }
}
