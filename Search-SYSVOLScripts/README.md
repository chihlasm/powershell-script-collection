# Search-SYSVOLScripts

Searches script files in the SYSVOL `scripts` folder for a specified text or regex pattern. Auto-detects the domain's SYSVOL path, outputs color-coded results to the console, and exports all matches to a CSV report.

## Features

- Auto-detects SYSVOL path from the current domain, or accepts a custom path
- Searches `.ps1`, `.bat`, `.cmd`, `.vbs` by default with an option to search all files
- Literal text matching by default, regex with `-Regex` switch
- Recursive search by default, top-level only with `-NoRecurse`
- Color-coded console output with file/line/content detail
- CSV export with timestamped filename

## Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `-SearchPattern` | Yes | — | Text or regex pattern to search for |
| `-Path` | No | `\\<domain>\SYSVOL\<domain>\scripts` | Override the target folder |
| `-Regex` | No | Off | Treat the pattern as a regular expression |
| `-AllFiles` | No | Off | Search all file types, not just script extensions |
| `-NoRecurse` | No | Off | Search top-level files only |
| `-OutputPath` | No | Current directory | Where to save the CSV report |

## Examples

```powershell
# Search for "net use" in all logon scripts
.\Search-SYSVOLScripts.ps1 -SearchPattern "net use"

# Search all files for a server name
.\Search-SYSVOLScripts.ps1 -SearchPattern "\\fileserver01" -AllFiles

# Regex search for credentials
.\Search-SYSVOLScripts.ps1 -SearchPattern "password|credential" -Regex

# Target a specific path and save report elsewhere
.\Search-SYSVOLScripts.ps1 -SearchPattern "Map Drive" -Path "\\dc01\SYSVOL\contoso.com\scripts" -OutputPath "C:\Reports"

# Top-level only
.\Search-SYSVOLScripts.ps1 -SearchPattern "logon" -NoRecurse
```

## Requirements

- PowerShell 5.1+
- Network access to the SYSVOL share (or the specified path)
- Run from a domain-joined machine with read permissions to the target folder
