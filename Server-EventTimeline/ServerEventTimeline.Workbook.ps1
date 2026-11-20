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
                    foreach ($row in $rows) {
                        $r++
                        $rs = [string]$r
                        $w.WriteStartElement('row'); $w.WriteAttributeString('r', $rs)
                        $cells = @($row)
                        for ($c = 0; $c -lt $cols.Count -and $c -lt $cells.Count; $c++) {
                            $v = $cells[$c]
                            if ($null -eq $v) { continue }
                            $w.WriteStartElement('c'); $w.WriteAttributeString('r', $letters[$c] + $rs)
                            if ($v -is [datetime]) {
                                $w.WriteAttributeString('s', '2')
                                $w.WriteElementString('v', $v.ToOADate().ToString('R', $inv))
                            }
                            elseif ($kinds[$c] -eq 'Number' -and ($v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal] -or $v -is [uint32] -or $v -is [uint64] -or $v -is [int16] -or $v -is [single])) {
                                $w.WriteElementString('v', ([double]$v).ToString('R', $inv))
                            }
                            else {
                                $text = Protect-XlsxText -Text ([string]$v)
                                $w.WriteAttributeString('t', 'inlineStr')
                                $w.WriteStartElement('is'); $w.WriteStartElement('t')
                                if ($text.Length -gt 0 -and ([char]::IsWhiteSpace($text[0]) -or [char]::IsWhiteSpace($text[$text.Length - 1]))) {
                                    $w.WriteAttributeString('xml', 'space', $null, 'preserve')
                                }
                                $w.WriteString($text); $w.WriteEndElement(); $w.WriteEndElement()
                            }
                            $w.WriteEndElement()
                        }
                        $w.WriteEndElement()
                    }
                    $w.WriteEndElement()
                    if ($s.Filter -and $cols.Count -gt 0) {
                        $w.WriteStartElement('autoFilter'); $w.WriteAttributeString('ref', ('A1:{0}{1}' -f $letters[$cols.Count - 1], $r)); $w.WriteEndElement()
                    }
                    $w.WriteEndElement()
                }
            }
        }
        finally { $zip.Dispose() }
    }
    finally { $fs.Dispose() }
}
