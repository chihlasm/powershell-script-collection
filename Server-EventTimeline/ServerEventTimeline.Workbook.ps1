#Requires -Version 5.1
<#
    The Excel workbook export: a small .xlsx writer (no Excel, no modules) and the timeline
    workbook built on it. Pure functions apart from the file write, dot-sourced by
    ServerEventTimeline.Core.ps1.

    An .xlsx is a zip of XML parts. The minimum is a workbook part listing its sheets (each
    with a sheet ID and a relationship ID) and one worksheet part per sheet whose sheetData
    element is required even when empty:
    https://learn.microsoft.com/office/open-xml/spreadsheet/structure-of-a-spreadsheetml-document
    https://learn.microsoft.com/office/open-xml/spreadsheet/working-with-sheets
    Worksheet children must follow the schema order (CT_Worksheet): sheetViews, cols,
    sheetData, then autoFilter.
    https://learn.microsoft.com/dotnet/api/documentformat.openxml.spreadsheet.worksheet

    Excel's limits: 1,048,576 rows per sheet, 32,767 characters per cell, sheet names of at most
    31 characters without \ / ? * [ ] and not starting or ending with '.
    https://learn.microsoft.com/fabric/data-factory/dataflow-gen2-data-destinations-excel-advanced#notes-and-limitations

    Dates are OLE Automation dates (days since 1899-12-30), the serial Excel stores:
    https://learn.microsoft.com/dotnet/api/system.datetime.tooadate
#>

$script:XlsxMaxCellChars = 32767
$script:XlsxMaxSheetName = 31
# Rows shared by two sheets (All servers and the server's own) keep their finished text for
# reuse, up to this many characters (~100 MB); rows past it are simply built again. Without a
# cap a 100,000-row export held ~370 MB extra until the end.
$script:XlsxCacheMaxChars = 50000000
# Characters XML 1.0 doesn't allow (control characters other than tab, LF and CR; U+FFFE and
# U+FFFF), then lone surrogate halves. Event messages can carry them, and one of them makes
# Excel call the whole file corrupt.
$script:XlsxBadChars = New-Object System.Text.RegularExpressions.Regex -ArgumentList '[\x00-\x08\x0B\x0C\x0E-\x1F￾￿]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]', ([System.Text.RegularExpressions.RegexOptions]::Compiled)

$script:XlsxNsMain = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
$script:XlsxNsRel = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'

function Protect-XlsxText {
    <#
        Cell text Excel will accept: characters XML 1.0 forbids removed, then cut to 32,767
        characters without splitting a surrogate pair.
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if (-not $Text) { return '' }
    $clean = $script:XlsxBadChars.Replace($Text, '')
    if ($clean.Length -gt $script:XlsxMaxCellChars) {
        $cut = $script:XlsxMaxCellChars
        if ([char]::IsHighSurrogate($clean[$cut - 1])) { $cut-- }
        $clean = $clean.Substring(0, $cut)
    }
    $clean
}

function ConvertTo-XlsxSheetName {
    <#
        A sheet name Excel accepts, unique within -Taken (compared ignoring case, as Excel does),
        and added to it. \ / ? * [ ] become _, and so does : (Excel's own sheet-name rule forbids
        it too); leading and trailing ' are trimmed; at most 31 characters; a clash gets " (2)",
        " (3)" ... with the base cut so the whole stays within 31.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Name,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$Taken
    )
    $base = ([regex]::Replace([string]$Name, '[\\/?*\[\]:]', '_')).Trim("'")
    if (-not $base) { $base = 'Sheet' }
    if ($base.Length -gt $script:XlsxMaxSheetName) { $base = $base.Substring(0, $script:XlsxMaxSheetName) }
    $candidate = $base
    $n = 1
    while ($Taken.Contains($candidate)) {
        $n++
        $suffix = ' ({0})' -f $n
        $room = $script:XlsxMaxSheetName - $suffix.Length
        $stem = if ($base.Length -gt $room) { $base.Substring(0, $room) } else { $base }
        $candidate = $stem.TrimEnd("'") + $suffix
    }
    [void]$Taken.Add($candidate)
    $candidate
}

function Write-XlsxPart {
    # One zip entry written through an XmlWriter; -Body gets the writer.
    param($Zip, [string]$Name, [scriptblock]$Body)
    $entry = $Zip.CreateEntry($Name, [System.IO.Compression.CompressionLevel]::Optimal)
    $stream = $entry.Open()
    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.Encoding = New-Object System.Text.UTF8Encoding $false
    $w = [System.Xml.XmlWriter]::Create($stream, $settings)
    try {
        $w.WriteStartDocument($true)
        & $Body $w
        $w.WriteEndDocument()
    }
    finally { $w.Dispose(); $stream.Dispose() }
}

function Write-XlsxWorkbook {
    <#
    .SYNOPSIS
        Writes an .xlsx file. No Excel or module needed.
    .DESCRIPTION
        -Sheets: hashtables with
          Name     the sheet name, already safe (ConvertTo-XlsxSheetName)
          Columns  @{ Header; Width; Kind = 'Text'|'Number'|'Date' } in order (at most 26: A-Z)
          Rows     object arrays, one value per column
          Filter   $true: the header row is frozen and AutoFilter covers the data
        Row 1 is the bold header. A [datetime] value is written as a date serial with a
        yyyy-mm-dd hh:mm:ss format; a value in a Number column as a number when it is one;
        everything else as inline text (never a formula). A $null value writes no cell.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object[]]$Sheets
    )
    try { Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop }
    catch { throw "This computer can't write zip files (System.IO.Compression is missing): $($_.Exception.Message)" }

    $written = $false
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $letters = [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $fs = New-Object System.IO.FileStream -ArgumentList $Path, ([System.IO.FileMode]::Create), ([System.IO.FileAccess]::ReadWrite), ([System.IO.FileShare]::None)
    try {
        $zip = New-Object System.IO.Compression.ZipArchive -ArgumentList $fs, ([System.IO.Compression.ZipArchiveMode]::Create)
        try {
            $count = @($Sheets).Count
            Write-XlsxPart $zip '[Content_Types].xml' {
                param($w)
                $w.WriteStartElement('Types', 'http://schemas.openxmlformats.org/package/2006/content-types')
                foreach ($d in @(@('rels', 'application/vnd.openxmlformats-package.relationships+xml'), @('xml', 'application/xml'))) {
                    $w.WriteStartElement('Default'); $w.WriteAttributeString('Extension', $d[0]); $w.WriteAttributeString('ContentType', $d[1]); $w.WriteEndElement()
                }
                $overrides = @(@('/xl/workbook.xml', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml'),
                    @('/xl/styles.xml', 'application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml'))
                for ($i = 1; $i -le $count; $i++) { $overrides += , @("/xl/worksheets/sheet$i.xml", 'application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml') }
                foreach ($o in $overrides) {
                    $w.WriteStartElement('Override'); $w.WriteAttributeString('PartName', $o[0]); $w.WriteAttributeString('ContentType', $o[1]); $w.WriteEndElement()
                }
                $w.WriteEndElement()
            }
            Write-XlsxPart $zip '_rels/.rels' {
                param($w)
                $w.WriteStartElement('Relationships', 'http://schemas.openxmlformats.org/package/2006/relationships')
                $w.WriteStartElement('Relationship'); $w.WriteAttributeString('Id', 'rId1')
                $w.WriteAttributeString('Type', "$script:XlsxNsRel/officeDocument"); $w.WriteAttributeString('Target', 'xl/workbook.xml'); $w.WriteEndElement()
                $w.WriteEndElement()
            }
            Write-XlsxPart $zip 'xl/_rels/workbook.xml.rels' {
                param($w)
                $w.WriteStartElement('Relationships', 'http://schemas.openxmlformats.org/package/2006/relationships')
                for ($i = 1; $i -le $count; $i++) {
                    $w.WriteStartElement('Relationship'); $w.WriteAttributeString('Id', "rId$i")
                    $w.WriteAttributeString('Type', "$script:XlsxNsRel/worksheet"); $w.WriteAttributeString('Target', "worksheets/sheet$i.xml"); $w.WriteEndElement()
                }
                $w.WriteStartElement('Relationship'); $w.WriteAttributeString('Id', ('rId{0}' -f ($count + 1)))
                $w.WriteAttributeString('Type', "$script:XlsxNsRel/styles"); $w.WriteAttributeString('Target', 'styles.xml'); $w.WriteEndElement()
                $w.WriteEndElement()
            }
            Write-XlsxPart $zip 'xl/workbook.xml' {
                param($w)
                $w.WriteStartElement('workbook', $script:XlsxNsMain)
                $w.WriteAttributeString('xmlns', 'r', $null, $script:XlsxNsRel)
                $w.WriteStartElement('sheets', $script:XlsxNsMain)
                $i = 0
                foreach ($s in @($Sheets)) {
                    $i++
                    $w.WriteStartElement('sheet', $script:XlsxNsMain)
                    $w.WriteAttributeString('name', [string]$s.Name); $w.WriteAttributeString('sheetId', [string]$i)
                    $w.WriteAttributeString('id', $script:XlsxNsRel, "rId$i")
                    $w.WriteEndElement()
                }
                $w.WriteEndElement()
                # Excel keeps each AutoFilter's range in a hidden defined name; giving it up front
                # matches what Excel writes itself.
                $names = @()
                $i = 0
                foreach ($s in @($Sheets)) {
                    if ($s.Filter -and @($s.Columns).Count -gt 0) {
                        $last = '{0}{1}' -f $letters[@($s.Columns).Count - 1], (@($s.Rows).Count + 1)
                        $names += , @($i, ("'{0}'!`$A`$1:`${1}`${2}" -f ([string]$s.Name).Replace("'", "''"), $last.Substring(0, 1), $last.Substring(1)))
                    }
                    $i++
                }
                if ($names.Count -gt 0) {
                    $w.WriteStartElement('definedNames', $script:XlsxNsMain)
                    foreach ($n in $names) {
                        $w.WriteStartElement('definedName', $script:XlsxNsMain)
                        $w.WriteAttributeString('name', '_xlnm._FilterDatabase'); $w.WriteAttributeString('localSheetId', [string]$n[0]); $w.WriteAttributeString('hidden', '1')
                        $w.WriteString($n[1]); $w.WriteEndElement()
                    }
                    $w.WriteEndElement()
                }
                $w.WriteEndElement()
            }
            Write-XlsxPart $zip 'xl/styles.xml' {
                param($w)
                # cellXfs: 0 = normal, 1 = bold (headers), 2 = date and time.
                # The root goes through the writer (it must see a root element); the fixed children are raw.
                $w.WriteStartElement('styleSheet', $script:XlsxNsMain)
                $w.WriteRaw('<numFmts count="1"><numFmt numFmtId="164" formatCode="yyyy-mm-dd hh:mm:ss"/></numFmts>' +
                    '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>' +
                    '<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>' +
                    '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>' +
                    '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>' +
                    '<cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>' +
                    '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>' +
                    '<xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/></cellXfs>' +
                    '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>')
                $w.WriteEndElement()
            }

            # Row strings by row object (reference), shared across sheets; see the row loop.
            $cache = New-Object 'System.Collections.Generic.Dictionary[object,string]'
            $cachedChars = [long]0
            $sb = New-Object System.Text.StringBuilder 4096
            $index = 0
            foreach ($s in @($Sheets)) {
                $index++
                $cols = @($s.Columns)
                if ($cols.Count -gt $letters.Length) { throw "Sheet '$($s.Name)' has $($cols.Count) columns; this writer handles up to $($letters.Length)." }
                $kinds = @($cols | ForEach-Object { [string]$_.Kind })
                $rows = @($s.Rows)
                $first = ($index -eq 1)
                Write-XlsxPart $zip "xl/worksheets/sheet$index.xml" {
                    param($w)
                    $w.WriteStartElement('worksheet', $script:XlsxNsMain)
                    $w.WriteStartElement('sheetViews'); $w.WriteStartElement('sheetView')
                    if ($first) { $w.WriteAttributeString('tabSelected', '1') }
                    $w.WriteAttributeString('workbookViewId', '0')
                    if ($s.Filter) {
                        $w.WriteStartElement('pane'); $w.WriteAttributeString('ySplit', '1'); $w.WriteAttributeString('topLeftCell', 'A2')
                        $w.WriteAttributeString('activePane', 'bottomLeft'); $w.WriteAttributeString('state', 'frozen'); $w.WriteEndElement()
                    }
                    $w.WriteEndElement(); $w.WriteEndElement()
                    if ($cols.Count -gt 0) {
                        $w.WriteStartElement('cols')
                        for ($c = 0; $c -lt $cols.Count; $c++) {
                            $width = if ($cols[$c].Width) { [double]$cols[$c].Width } else { 12 }
                            $w.WriteStartElement('col'); $w.WriteAttributeString('min', [string]($c + 1)); $w.WriteAttributeString('max', [string]($c + 1))
                            $w.WriteAttributeString('width', $width.ToString($inv)); $w.WriteAttributeString('customWidth', '1'); $w.WriteEndElement()
                        }
                        $w.WriteEndElement()
                    }
                    $w.WriteStartElement('sheetData')
                    # Header row.
                    $w.WriteStartElement('row'); $w.WriteAttributeString('r', '1')
                    for ($c = 0; $c -lt $cols.Count; $c++) {
                        $w.WriteStartElement('c'); $w.WriteAttributeString('r', "$($letters[$c])1"); $w.WriteAttributeString('s', '1'); $w.WriteAttributeString('t', 'inlineStr')
                        $w.WriteStartElement('is'); $w.WriteElementString('t', (Protect-XlsxText -Text ([string]$cols[$c].Header))); $w.WriteEndElement(); $w.WriteEndElement()
                    }
                    $w.WriteEndElement()
                    $r = 1
                    # Locals: a lookup up the scope chain on every cell was a large part of the cost.
                    $sbL = $sb; $cacheL = $cache; $invL = $inv; $bad = $script:XlsxBadChars; $maxChars = $script:XlsxMaxCellChars
                    $open = @(for ($c = 0; $c -lt $cols.Count; $c++) { '<c r="' + $letters[$c] + '<R>' })
                    $isNum = @(foreach ($k in $kinds) { $k -eq 'Number' })
                    # Speed: a row's cells are built once as one string (with <R> where the row
                    # number goes; escaped text can't contain "<") and written in one call. The
                    # same row object on two sheets (All servers and its server) reuses that
                    # string. The XmlWriter route cost ~55 s for 40,000 rows on two sheets.
                    foreach ($row in $rows) {
                        $r++
                        $rs = [string]$r
                        $frag = $null
                        if (-not $cacheL.TryGetValue($row, [ref]$frag)) {
                            [void]$sbL.Clear()
                            $cells = [object[]]$row
                            $n = [Math]::Min($cols.Count, $cells.Count)
                            for ($c = 0; $c -lt $n; $c++) {
                                $v = $cells[$c]
                                if ($null -eq $v) { continue }
                                if ($v -is [datetime]) {
                                    [void]$sbL.Append($open[$c] + '" s="2"><v>' + $v.ToOADate().ToString('R', $invL) + '</v></c>')
                                }
                                elseif ($isNum[$c] -and $v -is [ValueType] -and $v -isnot [bool]) {
                                    [void]$sbL.Append($open[$c] + '"><v>' + ([double]$v).ToString('R', $invL) + '</v></c>')
                                }
                                else {
                                    $text = [string]$v
                                    if ($text.Length -gt $maxChars) { $text = Protect-XlsxText -Text $text }
                                    $space = ''
                                    if ($text.Length -gt 0 -and ([char]::IsWhiteSpace($text[0]) -or [char]::IsWhiteSpace($text[$text.Length - 1]))) { $space = ' xml:space="preserve"' }
                                    [void]$sbL.Append($open[$c] + '" t="inlineStr"><is><t' + $space + '>' + [System.Security.SecurityElement]::Escape($text) + '</t></is></c>')
                                }
                            }
                            # Characters XML forbids, removed from the whole row at once (the
                            # markup itself has none). See Protect-XlsxText.
                            $frag = $bad.Replace($sbL.ToString(), '')
                            if ($cachedChars + $frag.Length -le $script:XlsxCacheMaxChars) { $cacheL[$row] = $frag; $cachedChars += $frag.Length }
                        }
                        $w.WriteRaw('<row r="' + $rs + '">' + $frag.Replace('<R>', $rs) + '</row>')
                    }
                    $w.WriteEndElement()
                    if ($s.Filter -and $cols.Count -gt 0) {
                        $w.WriteStartElement('autoFilter'); $w.WriteAttributeString('ref', ('A1:{0}{1}' -f $letters[$cols.Count - 1], $r)); $w.WriteEndElement()
                    }
                    $w.WriteEndElement()
                }
            }
            $written = $true
        }
        finally { $zip.Dispose() }
    }
    finally {
        $fs.Dispose()
        # A half-written file would sit in the save folder looking like a real export.
        if (-not $written) { Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue }
    }
}

function Export-TimelineWorkbook {
    <#
    .SYNOPSIS
        Saves the rows as an Excel workbook: Summary, All servers, then one sheet per server.
    .DESCRIPTION
        -Rows are the rows the other exports save (filters applied, repeats expanded).
        -Context is the export context (WindowText, Servers, Logs, FiltersText, GeneratedAt,
        Summary, ServerOutcomes), as the HTML report gets it. Server sheets follow
        Context.Servers; a server with no rows gets a header-only sheet. Event sheets have the
        CSV's columns (Export-TimelineCsv), with times as Excel dates and IDs as numbers.
        A sheet over -MaxRowsPerSheet data rows keeps the first ones, and the Summary says so.
    #>
    [CmdletBinding()]
    param(
        [object[]]$Rows,
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][string]$Path,
        [object[]]$ContextRows,
        # Excel's 1,048,576 rows per sheet, less the header row.
        [ValidateRange(1, 1048575)][int]$MaxRowsPerSheet = 1048575
    )
    if ($null -eq $Rows) { $Rows = @() }
    $eventColumns = @(
        @{ Header = 'TimeServerLocal'; Width = 19; Kind = 'Date' }, @{ Header = 'TimeUtc'; Width = 19; Kind = 'Date' }
        @{ Header = 'Server'; Width = 16; Kind = 'Text' }, @{ Header = 'Log'; Width = 14; Kind = 'Text' }
        @{ Header = 'Level'; Width = 11; Kind = 'Text' }, @{ Header = 'Flag'; Width = 30; Kind = 'Text' }
        @{ Header = 'Provider'; Width = 30; Kind = 'Text' }, @{ Header = 'EventId'; Width = 9; Kind = 'Number' }
        @{ Header = 'Message'; Width = 100; Kind = 'Text' }, @{ Header = 'RecordId'; Width = 11; Kind = 'Number' }
        @{ Header = 'User'; Width = 20; Kind = 'Text' }, @{ Header = 'Machine'; Width = 20; Kind = 'Text' }
    )

    # One pass: each row becomes its cells once, and lands in All servers and its server's list.
    $all = New-Object System.Collections.Generic.List[object]
    $byServer = @{}
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $cells = [object[]]@([datetime]$r.TimeServerLocal, [datetime]$r.TimeUtc, [string]$r.Server, [string]$r.Log, [string]$r.LevelName,
            [string]$r.Flag, [string]$r.Provider, $r.EventId, [string]$r.Message, $r.RecordId, [string]$r.User, [string]$r.Machine)
        # An empty field is no cell at all, so ISBLANK() and Go To Special > Blanks find it.
        for ($k = 2; $k -lt $cells.Length; $k++) { if ($cells[$k] -is [string] -and $cells[$k].Length -eq 0) { $cells[$k] = $null } }
        $all.Add($cells)
        $key = [string]$r.Server
        if (-not $byServer.ContainsKey($key)) { $byServer[$key] = New-Object System.Collections.Generic.List[object] }
        $byServer[$key].Add($cells)
    }

    $cutNotes = New-Object System.Collections.Generic.List[object]
    $limit = {
        param([string]$Name, $List)
        if ($List.Count -le $MaxRowsPerSheet) { return , $List.ToArray() }
        $cutNotes.Add([object[]]@('Cut short', ("{0}: first {1:N0} of {2:N0} events (Excel's row limit)" -f $Name, $MaxRowsPerSheet, $List.Count)))
        return , $List.GetRange(0, $MaxRowsPerSheet).ToArray()
    }

    $taken = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    [void](ConvertTo-XlsxSheetName -Name 'Summary' -Taken $taken)
    [void](ConvertTo-XlsxSheetName -Name 'All servers' -Taken $taken)
    $sheets = New-Object System.Collections.Generic.List[object]
    $sheets.Add(@{ Name = 'All servers'; Columns = $eventColumns; Rows = (& $limit 'All servers' $all); Filter = $true })
    # Servers in the order searched, then any the rows name that the request didn't (defensive).
    $order = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($s in @(@($Context.Servers) + @($byServer.Keys))) {
        if (-not $s -or $seen.ContainsKey([string]$s)) { continue }
        $seen[[string]$s] = $true; $order.Add([string]$s)
    }
    foreach ($s in $order) {
        # Not "$list = if (...) { ... }": that would unroll the list into its rows.
        $list = New-Object System.Collections.Generic.List[object]
        if ($byServer.ContainsKey($s)) { $list = $byServer[$s] }
        $name = ConvertTo-XlsxSheetName -Name $s -Taken $taken
        $sheets.Add(@{ Name = $name; Columns = $eventColumns; Rows = (& $limit $name $list); Filter = $true })
    }

    # The Summary: what was asked, what was found, how each server went, what happened.
    $sum = New-Object System.Collections.Generic.List[object]
    $sum.Add([object[]]@('Search window', [string]$Context.WindowText))
    $sum.Add([object[]]@('Servers', (@($Context.Servers) -join ', ')))
    $sum.Add([object[]]@('Logs', (@($Context.Logs) -join ', ')))
    $sum.Add([object[]]@('Filters', [string]$Context.FiltersText))
    $sum.Add([object[]]@('Generated', $(if ($Context.GeneratedAt) { [datetime]$Context.GeneratedAt } else { $null })))
    $sum.Add([object[]]@())
    $sum.Add([object[]]@('What was found', $null))
    foreach ($line in @($Context.Summary)) { if ($line) { $sum.Add([object[]]@($null, [string]$line)) } }
    $sum.Add([object[]]@())
    $sum.Add([object[]]@('How each server went', $null))
    foreach ($o in @($Context.ServerOutcomes)) {
        if ($null -eq $o) { continue }
        # The same details the HTML report lists (ConvertTo-TimelineHtml).
        $details = New-Object System.Collections.Generic.List[string]
        $details.Add(('{0} ({1} events)' -f $o.State, $o.EventCount))
        if ($o.Reason) { $details.Add([string]$o.Reason) }
        if ($o.Transport) { $details.Add("Read via $($o.Transport)") }
        foreach ($l in @($o.Logs | Where-Object { $_ -and $_.Outcome -ne 'Read' })) { $details.Add(('{0}: {1} {2}' -f $l.Log, $l.Outcome, $l.Reason).Trim()) }
        foreach ($line in @(Get-TimelineRoutineLogLines -Logs $o.Logs)) { $details.Add($line) }
        $sum.Add([object[]]@([string]$o.Server, ($details -join '; ')))
    }
    $sum.Add([object[]]@())
    $sum.Add([object[]]@('What happened', $null))
    $story = Get-TimelineStory -Rows $Rows -ContextRows $ContextRows
    foreach ($l in @($story.Lines | Where-Object { $_.Kind -eq 'Event' })) {
        $value = [string]$l.Text
        if ($l.Detail) { $value += ' - ' + $l.Detail }
        $sum.Add([object[]]@(('{0:yyyy-MM-dd HH:mm} {1}' -f [datetime]$l.TimeServerLocal, $l.Server), $value))
    }
    if ($story.MoreCount -gt 0) { $sum.Add([object[]]@($null, ('... and {0:N0} more that stood out' -f $story.MoreCount))) }
    if ($cutNotes.Count -gt 0) {
        $sum.Add([object[]]@())
        foreach ($n in $cutNotes) { $sum.Add($n) }
    }
    $summary = @{ Name = 'Summary'; Columns = @(@{ Header = 'Item'; Width = 26; Kind = 'Text' }, @{ Header = 'Value'; Width = 110; Kind = 'Text' }); Rows = $sum.ToArray(); Filter = $false }
    $sheets.Insert(0, $summary)

    Write-XlsxWorkbook -Path $Path -Sheets $sheets.ToArray()
}
