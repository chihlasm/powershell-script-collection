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
