<#
    Pester 5 tests for ServerEventTimeline.Workbook.ps1: the .xlsx writer and the timeline
    workbook. Files are written under $TestDrive and read back as zip + XML; no Excel needed
    (except the Integration-tagged open test, which is skipped where Excel isn't installed).
    Run:  pwsh -File Tests\Invoke-AllTests.ps1 -Path .\Server-EventTimeline\Tests
#>

BeforeAll {
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'ServerEventTimeline.Core.ps1')
    Add-Type -AssemblyName System.IO.Compression

    # Every entry of the package as name -> [xml].
    function Read-Xlsx {
        param([string]$Path)
        $parts = @{}
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            $zip = New-Object System.IO.Compression.ZipArchive -ArgumentList $fs, ([System.IO.Compression.ZipArchiveMode]::Read)
            foreach ($e in $zip.Entries) {
                $reader = New-Object System.IO.StreamReader -ArgumentList $e.Open(), ([System.Text.Encoding]::UTF8)
                try { $parts[$e.FullName] = [xml]$reader.ReadToEnd() } finally { $reader.Dispose() }
            }
            $zip.Dispose()
        }
        finally { $fs.Dispose() }
        $parts
    }
    $script:Ns = @{ x = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main' }
    # The text of every cell in a sheet part, row by row.
    function Get-SheetRows {
        param([xml]$Sheet)
        foreach ($row in @(Select-Xml -Xml $Sheet -XPath '//x:sheetData/x:row' -Namespace $script:Ns | ForEach-Object Node)) {
            , @(foreach ($c in @($row.ChildNodes)) { if ($c.is) { $c.is.InnerText + '' } else { [string]$c.v } })
        }
    }
    function New-Cols { @(@{ Header = 'Time'; Width = 20; Kind = 'Date' }, @{ Header = 'EventId'; Width = 8; Kind = 'Number' }, @{ Header = 'Message'; Width = 80; Kind = 'Text' }) }
    function Write-One {
        param([object[]]$Rows, [bool]$Filter = $true, [string]$Name = 'Events')
        $path = Join-Path $TestDrive ([guid]::NewGuid().ToString() + '.xlsx')
        Write-XlsxWorkbook -Path $path -Sheets @(@{ Name = $Name; Columns = (New-Cols); Rows = $Rows; Filter = $Filter })
        $path
    }
    function Cell { param([xml]$Sheet, [string]$Ref) Select-Xml -Xml $Sheet -XPath "//x:c[@r='$Ref']" -Namespace $script:Ns | ForEach-Object Node }
}

Describe 'Write-XlsxWorkbook' {
    It 'writes the parts Excel needs, and every part is well-formed XML' {
        $p = Write-One -Rows @(, @([datetime]'2026-11-18 17:49:03', 7036, 'hello'))
        $parts = Read-Xlsx $p
        @($parts.Keys | Sort-Object) | Should -Be (@('[Content_Types].xml', '_rels/.rels', 'xl/_rels/workbook.xml.rels', 'xl/styles.xml', 'xl/workbook.xml', 'xl/worksheets/sheet1.xml') | Sort-Object)
    }

    It 'names sheets in the order given and links each to its part' {
        $path = Join-Path $TestDrive 'three.xlsx'
        $sheets = foreach ($n in 'Summary', 'All servers', 'AD-01') { @{ Name = $n; Columns = (New-Cols); Rows = @(); Filter = $false } }
        Write-XlsxWorkbook -Path $path -Sheets @($sheets)
        $parts = Read-Xlsx $path
        @($parts['xl/workbook.xml'].workbook.sheets.sheet | ForEach-Object name) | Should -Be @('Summary', 'All servers', 'AD-01')
        foreach ($rel in @($parts['xl/_rels/workbook.xml.rels'].Relationships.Relationship)) {
            $parts.ContainsKey('xl/' + $rel.Target) | Should -BeTrue -Because $rel.Target
        }
    }

    It 'writes dates as serials with the date style, numbers as numbers, text inline' {
        $t = [datetime]'2026-11-18 17:49:03'
        $s = (Read-Xlsx (Write-One -Rows @(, @($t, 7036, 'hello'))))['xl/worksheets/sheet1.xml']
        (Cell $s 'A2').s | Should -Be '2'
        [double](Cell $s 'A2').v | Should -Be $t.ToOADate()
        (Cell $s 'B2').GetAttribute('t') | Should -Be ''
        (Cell $s 'B2').v | Should -Be '7036'
        (Cell $s 'C2').t | Should -Be 'inlineStr'
        (Cell $s 'A1').s | Should -Be '1'
    }

    It 'keeps a message that starts with = as text' {
        $s = (Read-Xlsx (Write-One -Rows @(, @([datetime]'2026-11-18', 1, "=cmd|' /C calc'!A0"))))['xl/worksheets/sheet1.xml']
        @(Select-Xml -Xml $s -XPath '//x:f' -Namespace $script:Ns).Count | Should -Be 0
        (Cell $s 'C2').is.InnerText | Should -Be "=cmd|' /C calc'!A0"
    }

    It 'removes characters XML forbids and keeps the rest' {
        $bad = 'a' + [char]1 + 'b' + [char]0xD800 + 'c' + [char]0xFFFE + 'd'
        $s = (Read-Xlsx (Write-One -Rows @(, @([datetime]'2026-11-18', 1, $bad))))['xl/worksheets/sheet1.xml']
        (Cell $s 'C2').is.InnerText | Should -Be 'abcd'
        Protect-XlsxText -Text ("tab`tline`r`nend") | Should -Be "tab`tline`r`nend"
        $pair = [char]::ConvertFromUtf32(0x1F600)
        Protect-XlsxText -Text ('x' + $pair) | Should -Be ('x' + $pair)
    }

    It 'keeps non-ASCII text' {
        $text = 'Ä — 日本'
        $s = (Read-Xlsx (Write-One -Rows @(, @([datetime]'2026-11-18', 1, $text))))['xl/worksheets/sheet1.xml']
        (Cell $s 'C2').is.InnerText | Should -Be $text
    }

    It 'cuts a cell at 32,767 characters' {
        (Protect-XlsxText -Text ('x' * 40000)).Length | Should -Be 32767
        # A surrogate pair straddling the limit is dropped whole, not split.
        $edge = ('x' * 32766) + [char]::ConvertFromUtf32(0x1F600)
        (Protect-XlsxText -Text $edge).Length | Should -Be 32766
    }

    It 'freezes the header and filters the data when asked' {
        $rows = @(@([datetime]'2026-11-18', 1, 'a'), @([datetime]'2026-11-18', 2, 'b'))
        $s = (Read-Xlsx (Write-One -Rows $rows))['xl/worksheets/sheet1.xml']
        $pane = Select-Xml -Xml $s -XPath '//x:pane' -Namespace $script:Ns | ForEach-Object Node
        $pane.state | Should -Be 'frozen'
        $pane.ySplit | Should -Be '1'
        (Select-Xml -Xml $s -XPath '//x:autoFilter' -Namespace $script:Ns | ForEach-Object Node).ref | Should -Be 'A1:C3'

        $plain = (Read-Xlsx (Write-One -Rows $rows -Filter $false))['xl/worksheets/sheet1.xml']
        @(Select-Xml -Xml $plain -XPath '//x:autoFilter | //x:pane' -Namespace $script:Ns).Count | Should -Be 0
    }

    It 'leaves a $null cell out and writes a header-only sheet with no rows' {
        $s = (Read-Xlsx (Write-One -Rows @(, @($null, 5, $null))))['xl/worksheets/sheet1.xml']
        Cell $s 'A2' | Should -BeNullOrEmpty
        (Cell $s 'B2').v | Should -Be '5'
        $empty = (Read-Xlsx (Write-One -Rows @()))['xl/worksheets/sheet1.xml']
        @(Get-SheetRows $empty).Count | Should -Be 1
    }
}

Describe 'ConvertTo-XlsxSheetName' {
    BeforeEach { $script:Taken = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase) }

    It 'replaces the characters Excel forbids and trims quotes' {
        ConvertTo-XlsxSheetName -Name 'a/b:c*?[d]' -Taken $script:Taken | Should -Be 'a_b_c___d_'
        ConvertTo-XlsxSheetName -Name "'quoted'" -Taken $script:Taken | Should -Be 'quoted'
        ConvertTo-XlsxSheetName -Name '' -Taken $script:Taken | Should -Be 'Sheet'
    }

    It 'keeps names to 31 characters' {
        (ConvertTo-XlsxSheetName -Name ('S' * 40) -Taken $script:Taken).Length | Should -Be 31
    }

    It 'makes clashing names unique, ignoring case, and still within 31 characters' {
        ConvertTo-XlsxSheetName -Name 'AD-01' -Taken $script:Taken | Should -Be 'AD-01'
        ConvertTo-XlsxSheetName -Name 'ad-01' -Taken $script:Taken | Should -Be 'ad-01 (2)'
        $a = ConvertTo-XlsxSheetName -Name ('server01.corp.example.com' + 'aaaaaaaaaaaaaaa') -Taken $script:Taken
        $b = ConvertTo-XlsxSheetName -Name ('server01.corp.example.com' + 'aaaaaaaaaaaaaab') -Taken $script:Taken
        $a.Length | Should -BeLessOrEqual 31
        $b.Length | Should -BeLessOrEqual 31
        $b | Should -Not -Be $a
        $b | Should -BeLike '* (2)'
    }
}

Describe 'Export-TimelineWorkbook' {
    BeforeAll {
        $script:WbRec = 0
        function New-WbRow {
            param([string]$Server = 'AD-01', [string]$Time = '2026-11-18 17:49', [string]$Provider = 'Disk', [int]$Id = 153, [int]$Level = 3)
            $script:WbRec++
            $e = [PSCustomObject]@{ TimeCreatedUtc = [datetime]::SpecifyKind([datetime]$Time, [DateTimeKind]::Utc); Id = $Id; ProviderName = $Provider
                Level = $Level; LogName = 'System'; Message = "The IO operation was retried. ($script:WbRec)"; RecordId = $script:WbRec; UserSid = ''; MachineName = $Server }
            ConvertTo-TimelineRow -Server $Server -EventRecord $e -UtcOffsetMinutes 0
        }
        function New-WbContext {
            param([string[]]$Servers = @('AD-01', 'AD-02'), [hashtable]$Counts = @{})
            @{
                WindowText = '2026-11-18 17:30 to 18:30 (each server''s local time)'; Servers = $Servers; Logs = @('System', 'Application')
                FiltersText = 'Level: All'; GeneratedAt = [datetime]'2026-11-18 18:40'; Summary = @('AD-01: 3 disk errors')
                ServerOutcomes = @(foreach ($s in $Servers) {
                        [PSCustomObject]@{ Server = $s; State = 'Done'; Transport = 'WinRM'; Reason = ''; EventCount = [int]$Counts[$s]
                            Logs = @([PSCustomObject]@{ Log = 'System'; Outcome = 'Read'; Count = 1; Reason = '' }) }
                    })
            }
        }
        function Get-Book {
            param([object[]]$Rows, [hashtable]$Context, [int]$Max = 1048575)
            $path = Join-Path $TestDrive ([guid]::NewGuid().ToString() + '.xlsx')
            Export-TimelineWorkbook -Rows $Rows -Context $Context -Path $path -MaxRowsPerSheet $Max
            $parts = Read-Xlsx $path
            $names = @($parts['xl/workbook.xml'].workbook.sheets.sheet | ForEach-Object name)
            $book = [ordered]@{}
            for ($i = 0; $i -lt $names.Count; $i++) { $book[$names[$i]] = @(Get-SheetRows $parts["xl/worksheets/sheet$($i + 1).xml"]) }
            $book
        }
        $script:Rows5 = @(
            (New-WbRow -Time '2026-11-18 17:49'), (New-WbRow -Time '2026-11-18 17:50:30'), (New-WbRow -Time '2026-11-18 17:52'),
            (New-WbRow -Server 'AD-02' -Time '2026-11-18 17:51' -Provider 'Service Control Manager' -Id 7036 -Level 4),
            (New-WbRow -Server 'AD-02' -Time '2026-11-18 17:53' -Provider 'Service Control Manager' -Id 7036 -Level 4)
        ) | Sort-Object TimeUtc
    }

    It 'has Summary, All servers, then one sheet per server in the order searched' {
        $book = Get-Book -Rows $script:Rows5 -Context (New-WbContext -Servers @('AD-02', 'AD-01'))
        @($book.Keys) | Should -Be @('Summary', 'All servers', 'AD-02', 'AD-01')
    }

    It 'puts each server''s rows on its own sheet and every row on All servers' {
        $book = Get-Book -Rows $script:Rows5 -Context (New-WbContext)
        $book['AD-01'].Count | Should -Be 4
        $book['AD-02'].Count | Should -Be 3
        $book['All servers'].Count | Should -Be 6
        $book['All servers'][0] | Should -Be @('TimeServerLocal', 'TimeUtc', 'Server', 'Log', 'Level', 'Flag', 'Provider', 'EventId', 'Message', 'RecordId', 'User', 'Machine')
        @($book['AD-02'] | Select-Object -Skip 1 | ForEach-Object { $_[2] }) | Should -Be @('AD-02', 'AD-02')
    }

    It 'gives a server with no events a header-only sheet, and writes a valid file with no rows at all' {
        $book = Get-Book -Rows $script:Rows5 -Context (New-WbContext -Servers @('AD-01', 'AD-02', 'AD-09'))
        $book['AD-09'].Count | Should -Be 1
        $none = Get-Book -Rows @() -Context (New-WbContext)
        @($none.Keys) | Should -Be @('Summary', 'All servers', 'AD-01', 'AD-02')
        $none['All servers'].Count | Should -Be 1
    }

    It 'summarises the search, the outcomes and what happened' {
        $book = Get-Book -Rows $script:Rows5 -Context (New-WbContext -Counts @{ 'AD-01' = 3; 'AD-02' = 2 })
        $values = @($book['Summary'] | ForEach-Object { $_[-1] })
        $values | Should -Contain '2026-11-18 17:30 to 18:30 (each server''s local time)'
        $values | Should -Contain 'AD-01: 3 disk errors'
        @($values | Where-Object { $_ -like 'Done (3 events)*' }).Count | Should -Be 1
        @($values | Where-Object { $_ -like 'Disk I/O had to be retried (3 in 3 min)*' }).Count | Should -Be 1
        @($book['Summary'] | ForEach-Object { $_[0] }) | Should -Contain 'What happened'
    }

    It 'cuts a sheet at the row limit and says so on the Summary' {
        $book = Get-Book -Rows $script:Rows5 -Context (New-WbContext) -Max 2
        $book['AD-01'].Count | Should -Be 3
        $book['AD-02'].Count | Should -Be 3
        $book['All servers'].Count | Should -Be 3
        $values = @($book['Summary'] | ForEach-Object { $_[-1] })
        $values | Should -Contain "AD-01: first 2 of 3 events (Excel's row limit)"
        $values | Should -Contain "All servers: first 2 of 5 events (Excel's row limit)"
    }

    # Timed under Windows PowerShell 5.1, the runtime the tool runs on: the same loop is several
    # times slower under PowerShell 7 (measured: 4 s on 5.1, ~25 s on 7.6 for 40,000 rows).
    It 'writes 40,000 rows in under 15 seconds on Windows PowerShell 5.1' -Skip:(-not (Get-Command powershell.exe -ErrorAction SilentlyContinue)) {
        $root = Split-Path -Parent $PSScriptRoot
        $out = Join-Path $TestDrive 'big.xlsx'
        $script = @'
param($Root, $Out)
$ErrorActionPreference = 'Stop'
. (Join-Path $Root 'ServerEventTimeline.Core.ps1')
$e = [PSCustomObject]@{ TimeCreatedUtc = [datetime]::SpecifyKind([datetime]'2026-11-18 17:49', 'Utc'); Id = 7036; ProviderName = 'Service Control Manager'
    Level = 4; LogName = 'System'; Message = 'The Windows Update service entered the running state.'; RecordId = 1; UserSid = ''; MachineName = 'AD-01' }
$rows = New-Object System.Collections.Generic.List[object]
for ($i = 0; $i -lt 40000; $i++) { $rows.Add((ConvertTo-TimelineRow -Server ('AD-0' + ($i % 4)) -EventRecord $e -UtcOffsetMinutes 0)) }
$ctx = @{ WindowText = 'w'; Servers = @('AD-00', 'AD-01', 'AD-02', 'AD-03'); Logs = @('System'); FiltersText = ''; GeneratedAt = (Get-Date); Summary = @(); ServerOutcomes = @() }
$t = Measure-Command { Export-TimelineWorkbook -Rows $rows.ToArray() -Context $ctx -Path $Out }
[int]$t.TotalSeconds
'@
        $file = Join-Path $TestDrive 'perf.ps1'
        Set-Content -LiteralPath $file -Value $script -Encoding UTF8
        $result = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $file -Root $root -Out $out 2>&1)
        $last = [string]$result[-1]
        $last | Should -Match '^\d+$' -Because ($result -join "`n")
        [int]$last | Should -BeLessThan 15
        Test-Path -LiteralPath $out | Should -BeTrue
    }
}
