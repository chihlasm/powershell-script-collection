#Requires -Version 5.1

<#
.SYNOPSIS
    Searches script files in SYSVOL\scripts for a specified text or regex pattern.

.DESCRIPTION
    This script scans the SYSVOL scripts folder (or a custom path) for files containing
    a user-supplied search pattern. By default it searches .ps1, .bat, .cmd, and .vbs files
    recursively, with color-coded console output and CSV export of all matches.

    The SYSVOL path is auto-detected from the current domain, but can be overridden
    with the -Path parameter.

.PARAMETER SearchPattern
    The text or regex pattern to search for inside script files.

.PARAMETER Path
    Path to the scripts folder. If not specified, auto-detects from the domain:
    \\<domain>\SYSVOL\<domain>\scripts

.PARAMETER Regex
    Treat SearchPattern as a regular expression instead of a literal string match.

.PARAMETER AllFiles
    Search all files regardless of extension. By default, only .ps1, .bat, .cmd,
    and .vbs files are searched.

.PARAMETER NoRecurse
    Limit the search to top-level files only. By default the search is recursive.

.PARAMETER OutputPath
    Directory where the CSV report is saved. Defaults to the current directory.

.EXAMPLE
    .\Search-SYSVOLScripts.ps1 -SearchPattern "net use"
    Searches for the literal text "net use" in all script files under the domain's SYSVOL scripts folder.

.EXAMPLE
    .\Search-SYSVOLScripts.ps1 -SearchPattern "\\\\fileserver01" -AllFiles
    Searches all files (not just scripts) for references to \\fileserver01.

.EXAMPLE
    .\Search-SYSVOLScripts.ps1 -SearchPattern "password|credential" -Regex
    Uses regex to find lines containing "password" or "credential".

.EXAMPLE
    .\Search-SYSVOLScripts.ps1 -SearchPattern "Map Drive" -Path "\\dc01\SYSVOL\contoso.com\scripts" -OutputPath "C:\Reports"
    Searches a specific SYSVOL path and saves the CSV report to C:\Reports.

.EXAMPLE
    .\Search-SYSVOLScripts.ps1 -SearchPattern "logon" -NoRecurse
    Searches only top-level files in the scripts folder, not subfolders.

.NOTES
    Requires network access to the SYSVOL share (or the specified path).
    Run from a domain-joined machine with appropriate read permissions.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$SearchPattern,

    [string]$Path,

    [switch]$Regex,

    [switch]$AllFiles,

    [switch]$NoRecurse,

    [string]$OutputPath = (Get-Location).Path
)

# ── Logging ──────────────────────────────────────────────────────────────────

function Write-Log {
    param (
        [string]$Message,
        [ValidateSet('INFO', 'PASS', 'WARN', 'FAIL')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        'PASS' { 'Green'   }
        'WARN' { 'Yellow'  }
        'FAIL' { 'Red'     }
        default { 'Cyan'   }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

# ── Main ─────────────────────────────────────────────────────────────────────

try {
    # Resolve SYSVOL path
    if ($Path) {
        $scriptsPath = $Path
    }
    else {
        $domain = $env:USERDNSDOMAIN
        if (-not $domain) {
            throw "Unable to detect domain from `$env:USERDNSDOMAIN. Specify -Path manually."
        }
        $scriptsPath = "\\$domain\SYSVOL\$domain\scripts"
    }

    Write-Log "Search target: $scriptsPath"
    Write-Log "Search pattern: $SearchPattern"
    Write-Log "Mode: $(if ($Regex) { 'Regex' } else { 'Literal' })"

    if (-not (Test-Path $scriptsPath)) {
        throw "Path not found: $scriptsPath"
    }

    # Discover files
    $gciParams = @{
        Path        = $scriptsPath
        File        = $true
        ErrorAction = 'SilentlyContinue'
    }

    if (-not $NoRecurse) {
        $gciParams['Recurse'] = $true
    }

    $files = Get-ChildItem @gciParams

    # Always exclude binary files
    $excludedExtensions = @('.exe', '.msi')
    $files = $files | Where-Object { $_.Extension -notin $excludedExtensions }

    if (-not $AllFiles) {
        $allowedExtensions = @('.ps1', '.bat', '.cmd', '.vbs')
        $files = $files | Where-Object { $_.Extension -in $allowedExtensions }
    }

    if (-not $files -or $files.Count -eq 0) {
        Write-Log "No script files found in $scriptsPath" -Level 'WARN'
        return
    }

    Write-Log "Found $($files.Count) file(s) to search"

    # Search files
    $selectStringParams = @{
        Pattern     = $SearchPattern
        ErrorAction = 'SilentlyContinue'
    }

    if (-not $Regex) {
        $selectStringParams['SimpleMatch'] = $true
    }

    $searchResults = $files | Select-String @selectStringParams

    if (-not $searchResults -or @($searchResults).Count -eq 0) {
        Write-Log "No matches found for pattern: $SearchPattern" -Level 'WARN'

        # Still output summary
        Write-Host ""
        Write-Log "────────────────────────────────────────"
        Write-Log "Files scanned:  $($files.Count)"
        Write-Log "Files matched:  0"
        Write-Log "Total matches:  0"
        return
    }

    $matchList = @($searchResults)

    # Display results
    Write-Host ""
    Write-Log "────────────────── RESULTS ──────────────────"
    Write-Host ""

    $currentFile = ''
    foreach ($match in $matchList) {
        $filePath = $match.Path
        if ($filePath -ne $currentFile) {
            $currentFile = $filePath
            Write-Host ""
            Write-Host "  $filePath" -ForegroundColor White
            Write-Host "  $('-' * [Math]::Min($filePath.Length, 80))" -ForegroundColor DarkGray
        }
        $lineNum  = $match.LineNumber
        $lineText = $match.Line.Trim()
        Write-Host "    Line ${lineNum}: " -ForegroundColor DarkYellow -NoNewline
        Write-Host $lineText -ForegroundColor Gray
    }

    # Summary
    $filesMatched = ($matchList | Select-Object -ExpandProperty Path -Unique).Count
    Write-Host ""
    Write-Log "────────────────── SUMMARY ──────────────────"
    Write-Log "Files scanned:  $($files.Count)" -Level 'INFO'
    Write-Log "Files matched:  $filesMatched" -Level 'PASS'
    Write-Log "Total matches:  $($matchList.Count)" -Level 'PASS'

    # CSV export
    $timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $csvFileName = "SYSVOLScriptSearch_$timestamp.csv"
    $csvPath = Join-Path $OutputPath $csvFileName

    $csvData = $matchList | ForEach-Object {
        [PSCustomObject]@{
            FileName    = $_.Filename
            FilePath    = $_.Path
            LineNumber  = $_.LineNumber
            LineContent = $_.Line.Trim()
        }
    }

    $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "Report saved to: $csvPath" -Level 'PASS'
}
catch {
    $errMsg = $_.Exception.Message
    Write-Log "Script failed: $errMsg" -Level 'FAIL'
    exit 1
}
