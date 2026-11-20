# Server-EventTimeline: Excel workbook export

**Status:** approved by Michael on 2026-11-19 (pending his review of this document)
**Size:** a small change. One new export function, one button, and a -NoGui file.

## Why

Engineers want a search's results organised by server, so they can work with them in Excel:
filter, sort, and run formulas (COUNTIFS by Event ID, the time between two events, and so
on). The files stay with the engineer. They are not meant to be sent to the server owners.

## What gets built

A third export, **Export workbook**, beside Export CSV and Export HTML report. It saves
`ServerEventTimeline_<yyyy-MM-dd_HHmmss>.xlsx` to the same folder as the other exports.
In -NoGui mode the workbook is written next to the CSV and the HTML report.

Sheets, in this order:

| Sheet | Contents |
|---|---|
| Summary | The search window, servers, logs and filters; "What was found"; how each server went (outcome, rows, any error); the What happened lines (time, server, text, detail) |
| All servers | Every exported row, with the same columns as the CSV |
| One sheet per server | That server's rows. Order follows the request's server list, and a server with no rows still gets a sheet with its header |

Event sheet columns are the same as the CSV, in the same order: TimeServerLocal, TimeUtc,
Server, Log, Level, Flag, Provider, EventId, Message, RecordId, User, Machine.

- **Times are real Excel dates** (serial numbers with a `yyyy-mm-dd hh:mm:ss` number format),
  so formulas and sorting work. EventId and RecordId are numbers. Everything else is text.
- **Each event sheet** gets a bold header row, the header frozen, and AutoFilter over its data.
  Column widths are sensible defaults, and Message is wide.
- **The rows** are the same rows the other two buttons export: the current filters apply, and
  collapsed repeats are expanded. This keeps all three exports consistent.

## Approaches considered

- **A. Write the .xlsx directly (chosen).** An .xlsx is a zip of XML parts. PowerShell 5.1 can
  write it with System.IO.Compression, which ships with .NET 4.5. It needs no Excel and no
  module, so it works on servers and in -NoGui mode.
- **B. Excel COM automation.** Rejected: Excel is rarely installed on servers, it is slow for
  tens of thousands of rows, and it leaves orphaned EXCEL.EXE processes when it fails.
- **C. Excel 2003 XML Spreadsheet.** Rejected: Excel warns on open, and the dates and filters
  are clumsier.
- The ImportExcel module would be an external dependency, which the self-contained-folder
  rule forbids. Per-server CSVs are not the workbook that was asked for.

## Constraints

- PowerShell 5.1 floor (the tool's existing `#Requires`). No new dependencies.
- Excel limits, per [Learn: Excel limits](https://learn.microsoft.com/fabric/data-factory/dataflow-gen2-data-destinations-excel-advanced#notes-and-limitations):
  - 1,048,576 rows per sheet
  - 32,767 characters per cell
  - Sheet names of at most 31 characters, with no `\ / ? * [ ]`, and not starting or ending with `'`

  The writer must:
  - **Sheet names:** replace the forbidden characters with `_`, trim the name to 31
    characters, and make duplicates unique with ` (2)`, ` (3)` and so on, compared case
    insensitively, staying within 31 characters.
  - **Long cells:** cut text at 32,767 characters.
  - **Long sheets:** stop a sheet at the row limit. The Summary then says the sheet was cut
    and how many rows were left out.
- **Characters XML 1.0 does not allow** (control characters other than tab, CR and LF, and lone
  surrogates) are removed from cell text. Event messages can contain them, and Excel reports
  the whole file as corrupt if they are left in.
- **Text cells** are inline strings, so a message beginning with `=` is never read as a formula.
- **Writing:** the file is streamed, part by part, with an XmlWriter or StringBuilder per sheet,
  so a 40,000-row search doesn't hold several copies in memory. Target: 40,000 rows in a few
  seconds on 5.1.
- The export changes nothing on any server. The workbook goes under -OutputPath only.

## Left to the builder

- Where the code lives: a new `ServerEventTimeline.Workbook.ps1` dot-sourced by Core,
  following the Story file's pattern, and added to the build zip and the toolkit file list
  if those list files.
- The exact minimal package parts (content types, rels, workbook, styles, sheets). These must
  be checked against the Open XML SDK / ECMA-376 documentation on Learn and cited.
- Tests:
  - Open the produced zip, check the parts and the sheet names, and check that every XML part
    parses.
  - One test for each limit rule.
  - A Compatibility check that it runs under Windows PowerShell 5.1.
- README and help text updates. The ServiceDesk-Toolkit README line gains "Excel workbook".

## Not in scope

- Charts, pivot tables, Excel tables (ListObjects), and conditional formatting.
- Per-server CSV or HTML files.
