# Server-EventTimeline Excel Workbook Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An "Export workbook" button (and a -NoGui file) that saves an .xlsx with a Summary sheet, an All servers sheet, and one sheet per server.

**Architecture:** A generic, pure .xlsx writer in a new `ServerEventTimeline.Workbook.ps1`, dot-sourced by Core like Story.ps1. It writes the Open XML parts straight into a `System.IO.Compression.ZipArchive`. `Export-TimelineWorkbook` in the same file turns timeline rows and the export context into sheet definitions. The window and -NoGui call it exactly where they call `Export-TimelineCsv` today.

**Tech Stack:** Windows PowerShell 5.1 and .NET 4.5 System.IO.Compression. Pester 5 under pwsh for the tests.

**Spec:** `docs/superpowers/specs/2026-11-19-timeline-workbook-design.md`

## Global Constraints

- `#Requires -Version 5.1` floor (the tool's). No new modules. No Excel needed to write the file.
- Save every edited .ps1 as UTF-8 **with BOM**, with CRLF line endings in the working copy.
- Excel limits, cited from https://learn.microsoft.com/fabric/data-factory/dataflow-gen2-data-destinations-excel-advanced#notes-and-limitations:
  - 1,048,576 rows per sheet
  - 32,767 characters per cell
  - Sheet names of at most 31 characters, with no `\ / ? * [ ]`, and not starting or ending with `'`
- Minimal package structure, cited from https://learn.microsoft.com/office/open-xml/spreadsheet/structure-of-a-spreadsheetml-document and https://learn.microsoft.com/office/open-xml/spreadsheet/working-with-sheets. `sheetData` is required. Worksheet child order: `sheetViews`, `cols`, `sheetData`, `autoFilter`.
- Dates are written as `[datetime]::ToOADate()` serials (cite https://learn.microsoft.com/dotnet/api/system.datetime.tooadate) with a `yyyy-mm-dd hh:mm:ss` number format.
- Text cells are written as `t="inlineStr"`. Never formulas.
- Zip entry names use forward slashes.
- Tests never write outside `$TestDrive` and never touch real servers.

## Review Focus

1. **Characters XML 1.0 forbids in event messages** (for example `\u0001` and lone surrogates). The file must still open and the text must survive minus those characters. Test it in Task 1.
2. **Server names that clash** once cleaned up or compared case-insensitively (`AD-01`, `ad-01`, and a 40-character FQDN). Every sheet name must be unique, valid, and 31 characters or fewer. Test it in Task 1.
3. **A message beginning with `=`, `+` or `@`** must stay text, never a formula. Test it in Task 1.
4. **Zero exported rows, or a server with no rows.** The workbook must still be valid and every server must get a header-only sheet. Test it in Task 2.
5. **Non-ASCII text** (`Ä`, `—`, CJK) must survive the round trip in UTF-8. Test it in Task 1.

---

### Task 1: Generic .xlsx writer

**Files:**
- Create: `Server-EventTimeline/ServerEventTimeline.Workbook.ps1`
- Modify: `Server-EventTimeline/ServerEventTimeline.Core.ps1` (dot-source Workbook.ps1 next to Story.ps1, line ~66)
- Modify: `Server-EventTimeline/Build-TestZip.ps1` (add the file to `$files`)
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.Workbook.Tests.ps1`

**Interfaces:**
- Produces:
  - `ConvertTo-XlsxSheetName -Name <string> -Taken <HashSet[string] (OrdinalIgnoreCase)> -> string`
    - Replaces `\ / ? * [ ] :` with `_` and trims leading and trailing `'`. Empty becomes `Sheet`.
    - Cuts the name to 31 characters. On a clash it appends ` (2)`, ` (3)` and so on, cutting the base so the result stays within 31.
    - Adds the result to `-Taken`.
    - `:` is included because Excel's own rule forbids it as well. Note this in a comment.
  - `Protect-XlsxText -Text <string> -> string`
    - Removes characters XML 1.0 forbids. Keeps tab, LF and CR, and keeps valid surrogate pairs.
    - Cuts the text to 32,767 characters, without splitting a surrogate pair.
  - `Write-XlsxWorkbook -Path <string> -Sheets <object[]>`. Each sheet is a hashtable:
    - `Name` (already safe)
    - `Columns`: an array of `@{ Header; Width; Kind = 'Text'|'Number'|'Date' }`
    - `Rows`: an array of object arrays, the cells in column order
    - `Filter` (bool): freeze the header row and add AutoFilter over the data

    Row 1 is the bold header. Writes `[Content_Types].xml`, `_rels/.rels`, `xl/workbook.xml`, `xl/_rels/workbook.xml.rels`, `xl/styles.xml` (cellXfs: 0 default, 1 bold, 2 date) and `xl/worksheets/sheet<N>.xml`. Each sheet is streamed through an `XmlWriter` over the zip entry stream. A `$null` cell is written as no cell.

- [ ] **Step 1: Write the failing tests.** In `Workbook.Tests.ps1`, dot-source Core. Add a helper `Read-Xlsx($path)` that opens the zip and returns a hashtable of entry name to `[xml]`. Write these tests:
  - `'writes the parts Excel needs, and every part is well-formed XML'`: entries equal the 6 names above for one sheet, and every entry casts to `[xml]`.
  - `'names sheets in the order given and links each to its part'`: workbook.xml sheet names equal `@('Summary','All servers','AD-01')`, and the rels targets exist in the zip.
  - `'writes dates as serials with the date style, numbers as numbers, text inline'`:
    - A2 has `s="2"` and `<v>` equal to `([datetime]'2026-11-18 17:49:03').ToOADate()`.
    - The EventId cell has no `t` and its `<v>` is `7036`.
    - The Message cell has `t="inlineStr"`.
  - `'keeps a message that starts with = as text'` (Review Focus 3): no `<f>` element anywhere, and the cell text is `=cmd|' /C calc'!A0`.
  - `'removes characters XML forbids and keeps the rest'` (Review Focus 1): ``"a`u{1}b`u{D800}c"`` becomes `abc`, and the part still parses.
  - `'keeps non-ASCII text'` (Review Focus 5): `Ä — 日本` round-trips.
  - `'cuts a cell at 32,767 characters'`: a 40,000-character string becomes 32,767.
  - `'freezes the header and filters the data when asked'`: `pane/@state` is `frozen`, `ySplit` is `1`, and `autoFilter/@ref` is `A1:C3` for 3 columns and 2 rows. Absent when `Filter` is `$false`.
  - `'makes sheet names Excel accepts'` (Review Focus 2):
    - `'a/b:c*?[d]'` becomes `'a_b_c___d_'`
    - `"'quoted'"` becomes `'quoted'`
    - A 40-character name becomes 31 characters
    - `AD-01` then `ad-01` gives `AD-01` then `ad-01 (2)`
    - Two 40-character names sharing their first 31 characters both stay at 31 characters or fewer and are different
- [ ] **Step 2: Run and watch them fail.** Run `pwsh -NoProfile -File Tests\Invoke-AllTests.ps1 -Path .\Server-EventTimeline\Tests\ServerEventTimeline.Workbook.Tests.ps1`. Expected: they fail with "not recognized" for the new functions.
- [ ] **Step 3: Implement the three functions and the dot-source.** Load `System.IO.Compression` with `Add-Type -AssemblyName System.IO.Compression` in a try/catch. Open the archive with `[System.IO.Compression.ZipArchive]` over a `FileStream` in Create mode, and dispose both in `finally`. Use column letters A–Z only: the tool has 12 columns, so state that limit in the help.
- [ ] **Step 4: Run again.** Expected: all pass. Also run `Tests\PSVersionFloor.Tests.ps1` and `Server-EventTimeline\Tests\ServerEventTimeline.Build.Tests.ps1`. The Build test checks that every .ps1 is in the zip list.
- [ ] **Step 5: Commit** with the message `feat: Server-EventTimeline writes .xlsx workbooks without Excel`.

### Task 2: The timeline workbook

**Files:**
- Modify: `Server-EventTimeline/ServerEventTimeline.Workbook.ps1`
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.Workbook.Tests.ps1`

**Interfaces:**
- Consumes: Task 1's functions. Also these existing functions: `Get-TimelineStory -Rows -ContextRows`, and the export context hashtable as built by `Get-ExportContext` (Start script, line ~1951). Its keys are WindowText, Servers, Logs, FiltersText, GeneratedAt, ServerOutcomes and Summary. Each `ServerOutcomes` item has Server, State, EventCount, Reason, Transport, and Logs (each with Log, Outcome and Reason).
- Produces: `Export-TimelineWorkbook -Rows <object[]> -Context <hashtable> -Path <string> [-ContextRows <object[]>] [-MaxRowsPerSheet <int> = 1048575]`. It returns nothing and writes the file.

Sheets:

- **Summary** (two columns, `Item` and `Value`, Text, no filter). Rows in this order:
  - Search window, Servers (comma-joined), Logs, Filters, Generated (as a Date)
  - A blank row, then `What was found` with each summary line in Value
  - A blank row, then `How each server went`: one row per outcome, with Item = server and Value = `"<State> (<N> events)"` plus the reason, the transport and any logs not read, joined with `; ` (the same text the HTML report builds, Core lines ~449-456)
  - A blank row, then `What happened`: one row per story Event line, with Item = `yyyy-MM-dd HH:mm` server local plus the server, and Value = the text plus ` - detail` when there is one. Then the `... and N more that stood out` line when MoreCount is above 0.
  - Last, any `Cut short` rows (see below).
- **All servers:** every row. The columns are the CSV's 12, in order (`Export-TimelineCsv`, Core line ~364): TimeServerLocal and TimeUtc as Date, EventId and RecordId as Number, the rest Text. Filter on.
- **One sheet per server,** in `Context.Servers` order, using `ConvertTo-XlsxSheetName`. The names `Summary` and `All servers` are reserved first. Each sheet has the same columns, holds that server's rows, and has Filter on.
- **A sheet over `-MaxRowsPerSheet` data rows** keeps the first N. The Summary gets a row with Item `Cut short` and Value `"<sheet>: first <N:N0> of <M:N0> events (Excel's row limit)"`.

- [ ] **Step 1: Write the failing tests:**
  - `'has Summary, All servers, then one sheet per server in the order searched'`: with Servers `@('AD-02','AD-01')`, the sheets are `Summary, All servers, AD-02, AD-01`.
  - `'puts each server''s rows on its own sheet and every row on All servers'`: with 3 rows for AD-01 and 2 for AD-02, the sheets have 4, 3 and 6 rows (header included).
  - `'gives a server with no events a header-only sheet, and writes a valid file with no rows at all'` (Review Focus 4).
  - `'summarises the search, the outcomes and what happened'`: Summary values include the WindowText, `OK (3 events)`, and the story line text `Disk I/O had to be retried (3 in 3 min)`.
  - `'cuts a sheet at the row limit and says so on the Summary'`: with `-MaxRowsPerSheet 2` and 3 AD-01 rows, AD-01 has 3 rows (header plus 2), and Summary contains `AD-01: first 2 of 3 events (Excel's row limit)`.
- [ ] **Step 2: Run and watch them fail** (`Export-TimelineWorkbook` not recognized).
- [ ] **Step 3: Implement `Export-TimelineWorkbook`.** Group the rows by server in a single pass into a hashtable of lists. Don't use `Where-Object` once per server: 40,000 rows times 10 servers is too slow on 5.1.
- [ ] **Step 4: Run again.** Expected: pass. Add a performance test, `'writes 40,000 rows in under 15 seconds'`, using `Measure-Command`.
- [ ] **Step 5: Commit** with the message `feat: Server-EventTimeline workbook with a sheet per server`.

### Task 3: Button, -NoGui, and docs

**Files:**
- Modify: `Server-EventTimeline/Start-ServerEventTimeline.ps1`. Lines to change:
  - XAML, next to `ExportHtmlButton` (line ~819)
  - The control-name list (~1593)
  - Enable/disable (~1874)
  - `Invoke-Export` (~1969)
  - Click wiring (~2374)
  - The -NoGui files (~1003)
  - The help text (lines ~27 and ~62)
- Modify: `Server-EventTimeline/README.md`, `ServiceDesk-Toolkit/README.md` (the Server-EventTimeline section) and the root `README.md` index line
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.Gui.Tests.ps1`

**Interfaces:**
- Consumes: Task 2's `Export-TimelineWorkbook`.
- Produces: `Invoke-Export -Kind Csv|Html|Xlsx`. The button is `ExportXlsxButton`, with Content `Export workbook` and ToolTip `Save an Excel workbook: a summary, every event, and a sheet for each server`.

- [ ] **Step 1: Write the failing tests:**
  - `'has an Export workbook button beside the other exports'` (STA only): the button exists, it is disabled at start, and its parent is the same panel as `ExportHtmlButton`.
  - `'wires the workbook export'` (source check): the source matches all of the following:
    - `ExportXlsxButton.add_Click\(\{ Invoke-Export -Kind Xlsx`
    - `ValidateSet\('Csv', 'Html', 'Xlsx'\)`
    - `\$ui.ExportXlsxButton.IsEnabled = \$has`
    - in the -NoGui block, `Export-TimelineWorkbook`
- [ ] **Step 2: Run and watch them fail.**
- [ ] **Step 3: Implement the changes:**
  - **In the window:** Xlsx writes `ServerEventTimeline_<stamp>.xlsx` via `Export-TimelineWorkbook -Rows $rows -Context (Get-ExportContext) -ContextRows $ui.Store.Rows.ToArray()`. Smoke mode records the same failure text as the other exports.
  - **In -NoGui:** write the .xlsx after the HTML, in its own try/catch, so a workbook failure still leaves the CSV and HTML and logs `[WARN]`.
  - **Docs:** update the help, the README "Files" section and the export mentions, and the toolkit and root index lines ("CSV/HTML/Excel export").
- [ ] **Step 4: Run the whole gate:**
  - The tool's suite: `pwsh -NoProfile -File Tests\Invoke-AllTests.ps1 -Path .\Server-EventTimeline\Tests`. Expected: 0 failed.
  - The parse check: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Tests\Test-ScriptParse.ps1`. Expected: `[PASS]`.
  - `Tests\ScriptEncoding.Tests.ps1` and `Tests\PSVersionFloor.Tests.ps1`.
- [ ] **Step 5: Run an open test, tagged `Integration`, on a machine with Excel.** In `Workbook.Tests.ps1`, open a generated workbook (written to `$TestDrive`) through `Excel.Application` COM with `Visible = $false` and `DisplayAlerts = $false`. Assert that `Worksheets.Count` is right and that cell A2 on All servers is a date. Then call `Quit()` and release the COM object. It is skipped when Excel isn't registered, and it stays out of the gate.
- [ ] **Step 6: Commit** with the message `feat: Server-EventTimeline Export workbook button and -NoGui workbook`.
