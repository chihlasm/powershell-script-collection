# DNS Record Audit & Search Tool — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a browser-based PowerShell tool that searches, audits stale records, and compares DNS zones across domain controllers.

**Architecture:** Single self-contained PowerShell script using the HTTP Listener pattern from `FolderPermissionManager-GUI.ps1`. Embedded HTML/CSS/JS frontend communicates with PowerShell backend via REST API endpoints. All DNS queries use `DnsServer` module with `-ComputerName` for remote DC targeting.

**Tech Stack:** PowerShell 5.1, `System.Net.HttpListener`, `DnsServer` RSAT module, `ActiveDirectory` RSAT module (optional), vanilla HTML/CSS/JS (no frameworks).

**Design doc:** `docs/plans/2026-04-06-dns-record-audit-design.md`

**Reference implementation:** `FolderPermissionManager/FolderPermissionManager-GUI.ps1` — copy the exact structure: param block, helpers, API functions, route dispatcher, embedded HTML, listener loop.

---

## Task 1: Script Skeleton — Param Block, Module Loading, Helpers

**Files:**
- Create: `Search-DNSRecords/Search-DNSRecords-GUI.ps1`

**Step 1: Create the script file with param block and module loading**

Write the file with these sections, following repo conventions from `CLAUDE.md`:

```powershell
#Requires -Version 5.1

<#
.SYNOPSIS
    DNS Record Audit & Search Tool — Browser-based GUI.

.DESCRIPTION
    Starts a local web server and opens a browser-based interface for:
    - Searching DNS records by name, IP, type, or age across selected zones
    - Detecting stale DNS records (aged, static, AD-orphaned)
    - Comparing DNS zones between two domain controllers
    Produces color-coded results with CSV and HTML export.

.PARAMETER Port
    TCP port for the local web server. Default: 8080

.PARAMETER StaleThresholdDays
    Number of days after which a DNS record is considered stale. Default: 90

.PARAMETER OutputPath
    Directory where exported CSV and HTML files are saved. Defaults to the current directory.

.PARAMETER NoBrowserOpen
    Do not automatically open the browser on launch.

.EXAMPLE
    .\Search-DNSRecords-GUI.ps1

.EXAMPLE
    .\Search-DNSRecords-GUI.ps1 -Port 9090 -StaleThresholdDays 60

.EXAMPLE
    .\Search-DNSRecords-GUI.ps1 -OutputPath "C:\Reports" -NoBrowserOpen

.NOTES
    Requires RSAT DNS Server tools (DnsServer module).
    ActiveDirectory module is optional — enables AD orphan detection in stale mode.
    Must be run from a domain-joined machine with DNS read permissions.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1024, 65535)]
    [int]$Port = 8080,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StaleThresholdDays = 90,

    [Parameter()]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter()]
    [switch]$NoBrowserOpen
)

$ErrorActionPreference = 'Continue'
$baseUrl = "http://localhost:$Port/"

# --- Module Loading ---

$script:dnsModuleAvailable = $false
$script:adModuleAvailable = $false

try {
    Import-Module DnsServer -ErrorAction Stop
    $script:dnsModuleAvailable = $true
}
catch {
    Write-Host '[FAIL] The DnsServer PowerShell module is not available.' -ForegroundColor Red
    Write-Host '       Install RSAT DNS Server tools or run on a machine with the module.' -ForegroundColor Red
    Write-Host "       Error: $_" -ForegroundColor Yellow
    return
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $script:adModuleAvailable = $true
    Write-Host '[INFO] ActiveDirectory module loaded — AD orphan detection enabled.' -ForegroundColor Cyan
}
catch {
    Write-Host '[WARN] ActiveDirectory module not available — AD orphan detection will be skipped.' -ForegroundColor Yellow
}

# Store last results for export
$script:lastResults = @()
$script:lastMode = ''
```

**Step 2: Add the HTTP helper functions**

Directly below the module loading, add these helpers (identical pattern to FolderPermissionManager):

```powershell
# --- Helper Functions ---

function Send-Json {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [object]$Data
    )
    if ($null -eq $Data) { $Data = @() }
    $json = $Data | ConvertTo-Json -Depth 10 -Compress
    if ([string]::IsNullOrEmpty($json)) { $json = '[]' }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $Response.ContentType = 'application/json; charset=utf-8'
    $Response.ContentLength64 = $bytes.Length
    $Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Response.OutputStream.Close()
}

function Send-Html {
    param([System.Net.HttpListenerResponse]$Response)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($script:htmlContent)
    $Response.ContentType = 'text/html; charset=utf-8'
    $Response.ContentLength64 = $bytes.Length
    $Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Response.OutputStream.Close()
}

function Send-File {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [string]$Content,
        [string]$ContentType,
        [string]$FileName
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $Response.ContentType = $ContentType
    $Response.ContentLength64 = $bytes.Length
    $Response.AddHeader('Content-Disposition', "attachment; filename=`"$FileName`"")
    $Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Response.OutputStream.Close()
}

function Read-RequestBody {
    param([System.Net.HttpListenerRequest]$Request)
    $reader = [System.IO.StreamReader]::new($Request.InputStream, $Request.ContentEncoding)
    $json = $reader.ReadToEnd()
    $reader.Close()
    return $json | ConvertFrom-Json
}
```

**Step 3: Add a DNS record normalization helper**

This helper converts raw `Get-DnsServerResourceRecord` output into a flat object for consistent use across all modes:

```powershell
function Convert-DnsRecord {
    param(
        [object]$Record,
        [string]$ZoneName,
        [string]$DcName
    )
    $type = $Record.RecordType
    $data = switch ($type) {
        'A'     { $Record.RecordData.IPv4Address.IPAddressToString }
        'AAAA'  { $Record.RecordData.IPv6Address.IPAddressToString }
        'CNAME' { $Record.RecordData.HostNameAlias }
        'MX'    { "$($Record.RecordData.Preference) $($Record.RecordData.MailExchange)" }
        'PTR'   { $Record.RecordData.PtrDomainName }
        'SRV'   { "$($Record.RecordData.Priority) $($Record.RecordData.Weight) $($Record.RecordData.Port) $($Record.RecordData.DomainName)" }
        'TXT'   { ($Record.RecordData.DescriptiveText -join '; ') }
        'NS'    { $Record.RecordData.NameServer }
        'SOA'   { "$($Record.RecordData.PrimaryServer) $($Record.RecordData.ResponsiblePerson)" }
        default { $Record.RecordData.ToString() }
    }
    $ts = $Record.Timestamp
    $ageDays = if ($ts -and $ts -ne [datetime]::MinValue -and $ts.Year -gt 1) {
        [math]::Round(((Get-Date) - $ts).TotalDays, 1)
    } else { $null }
    $isStatic = ($null -eq $ts -or $ts -eq [datetime]::MinValue -or $ts.Year -le 1)

    [PSCustomObject]@{
        Zone      = $ZoneName
        Name      = $Record.HostName
        Type      = $type
        Data      = $data
        TTL       = $Record.TimeToLive.ToString()
        Timestamp = if ($isStatic) { 'Static' } else { $ts.ToString('yyyy-MM-dd HH:mm:ss') }
        AgeDays   = $ageDays
        IsStatic  = $isStatic
        DC        = $DcName
    }
}
```

**Step 4: Commit**

```bash
git add Search-DNSRecords/Search-DNSRecords-GUI.ps1
git commit -m "feat(dns-audit): scaffold script with param block, module loading, helpers"
```

---

## Task 2: API — Zone Discovery Endpoint

**Files:**
- Modify: `Search-DNSRecords/Search-DNSRecords-GUI.ps1`

**Step 1: Add the Get-DnsZones function**

Place after the helpers section:

```powershell
# --- API Endpoint Functions ---

function Get-DnsZones {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )
    $dc = $Request.QueryString['dc']
    if ([string]::IsNullOrWhiteSpace($dc)) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = 'Missing required parameter: dc' }
        return
    }
    try {
        $zones = Get-DnsServerZone -ComputerName $dc -ErrorAction Stop |
            Where-Object { $_.ZoneType -ne 'Forwarder' -and $_.ZoneName -ne 'TrustAnchors' } |
            ForEach-Object {
                $isReverse = $_.IsReverseLookupZone
                [PSCustomObject]@{
                    name       = $_.ZoneName
                    type       = $_.ZoneType.ToString()
                    isReverse  = $isReverse
                    recordCount = $null  # filled lazily if needed
                }
            } |
            Sort-Object -Property isReverse, name
        Send-Json $Response @{ dc = $dc; zones = @($zones) }
    }
    catch {
        $Response.StatusCode = 500
        Send-Json $Response @{ error = "Failed to query zones on ${dc}: $($_.Exception.Message)" }
    }
}
```

**Step 2: Add the status endpoint** (provides module availability info to frontend)

```powershell
function Get-Status {
    param([System.Net.HttpListenerResponse]$Response)
    Send-Json $Response @{
        dnsModule = $script:dnsModuleAvailable
        adModule  = $script:adModuleAvailable
        staleThresholdDays = $StaleThresholdDays
    }
}
```

**Step 3: Commit**

```bash
git add Search-DNSRecords/Search-DNSRecords-GUI.ps1
git commit -m "feat(dns-audit): add zone discovery and status API endpoints"
```

---

## Task 3: API — Search Mode Endpoint

**Files:**
- Modify: `Search-DNSRecords/Search-DNSRecords-GUI.ps1`

**Step 1: Add the Invoke-DnsSearch function**

```powershell
function Invoke-DnsSearch {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )
    $body = Read-RequestBody $Request
    $dc = $body.dc
    $zones = @($body.zones)
    $pattern = $body.pattern
    $recordType = $body.recordType       # '' means all types
    $useRegex = [bool]$body.useRegex
    $maxAgeDays = $body.maxAgeDays       # $null means no age filter

    if ([string]::IsNullOrWhiteSpace($dc) -or $zones.Count -eq 0) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = 'dc and zones[] are required' }
        return
    }

    $results = [System.Collections.Generic.List[object]]::new()
    $errors = [System.Collections.Generic.List[object]]::new()

    foreach ($zoneName in $zones) {
        try {
            $params = @{ ZoneName = $zoneName; ComputerName = $dc; ErrorAction = 'Stop' }
            if (-not [string]::IsNullOrWhiteSpace($recordType)) {
                $params['RRType'] = $recordType
            }
            $records = Get-DnsServerResourceRecord @params

            foreach ($rec in $records) {
                $converted = Convert-DnsRecord -Record $rec -ZoneName $zoneName -DcName $dc

                # Pattern filter
                if (-not [string]::IsNullOrWhiteSpace($pattern)) {
                    $matchTarget = "$($converted.Name) $($converted.Data)"
                    if ($useRegex) {
                        if ($matchTarget -notmatch $pattern) { continue }
                    } else {
                        if ($matchTarget -notlike "*$pattern*") { continue }
                    }
                }

                # Age filter
                if ($null -ne $maxAgeDays -and $maxAgeDays -gt 0) {
                    if ($null -eq $converted.AgeDays -or $converted.AgeDays -lt $maxAgeDays) { continue }
                }

                $results.Add($converted)
            }
        }
        catch {
            $errors.Add([PSCustomObject]@{ zone = $zoneName; error = $_.Exception.Message })
        }
    }

    $script:lastResults = $results
    $script:lastMode = 'search'
    Send-Json $Response @{ results = @($results); errors = @($errors); total = $results.Count }
}
```

**Step 2: Commit**

```bash
git add Search-DNSRecords/Search-DNSRecords-GUI.ps1
git commit -m "feat(dns-audit): add search mode API endpoint"
```

---

## Task 4: API — Stale Record Detection Endpoint

**Files:**
- Modify: `Search-DNSRecords/Search-DNSRecords-GUI.ps1`

**Step 1: Add the Invoke-StaleDetection function**

```powershell
function Invoke-StaleDetection {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )
    $body = Read-RequestBody $Request
    $dc = $body.dc
    $zones = @($body.zones)
    $thresholdDays = if ($body.thresholdDays) { [int]$body.thresholdDays } else { $StaleThresholdDays }
    $checkAge = if ($null -ne $body.checkAge) { [bool]$body.checkAge } else { $true }
    $checkStatic = if ($null -ne $body.checkStatic) { [bool]$body.checkStatic } else { $true }
    $checkAdOrphan = if ($null -ne $body.checkAdOrphan) { [bool]$body.checkAdOrphan } else { $true }

    if ([string]::IsNullOrWhiteSpace($dc) -or $zones.Count -eq 0) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = 'dc and zones[] are required' }
        return
    }

    # Pre-fetch AD computers into a HashSet for fast lookup
    $adComputers = @{}
    if ($checkAdOrphan -and $script:adModuleAvailable) {
        try {
            Get-ADComputer -Filter * -Properties Name -ErrorAction Stop | ForEach-Object {
                $adComputers[$_.Name.ToLower()] = $true
            }
        }
        catch {
            Write-Host "[WARN] Could not query AD computers: $_" -ForegroundColor Yellow
            $checkAdOrphan = $false
        }
    } elseif ($checkAdOrphan -and -not $script:adModuleAvailable) {
        $checkAdOrphan = $false
    }

    $results = [System.Collections.Generic.List[object]]::new()
    $errors = [System.Collections.Generic.List[object]]::new()

    foreach ($zoneName in $zones) {
        try {
            $records = Get-DnsServerResourceRecord -ZoneName $zoneName -ComputerName $dc -ErrorAction Stop

            foreach ($rec in $records) {
                $converted = Convert-DnsRecord -Record $rec -ZoneName $zoneName -DcName $dc
                $reasons = [System.Collections.Generic.List[string]]::new()

                # Check 1: Age-based
                if ($checkAge -and $null -ne $converted.AgeDays -and $converted.AgeDays -ge $thresholdDays) {
                    $reasons.Add("Aged ($([math]::Round($converted.AgeDays)) days)")
                }

                # Check 2: Static record
                if ($checkStatic -and $converted.IsStatic) {
                    $reasons.Add('Static (never scavenged)')
                }

                # Check 3: AD orphan (A records only)
                if ($checkAdOrphan -and $converted.Type -eq 'A' -and $converted.Name -ne '@') {
                    $hostname = $converted.Name.ToLower()
                    if (-not $adComputers.ContainsKey($hostname)) {
                        $reasons.Add('No matching AD computer')
                    }
                }

                if ($reasons.Count -gt 0) {
                    $converted | Add-Member -NotePropertyName 'StaleReasons' -NotePropertyValue ($reasons -join '; ')
                    $results.Add($converted)
                }
            }
        }
        catch {
            $errors.Add([PSCustomObject]@{ zone = $zoneName; error = $_.Exception.Message })
        }
    }

    $script:lastResults = $results
    $script:lastMode = 'stale'
    $summary = @{
        total     = $results.Count
        aged      = @($results | Where-Object { $_.StaleReasons -match 'Aged' }).Count
        static    = @($results | Where-Object { $_.StaleReasons -match 'Static' }).Count
        adOrphan  = @($results | Where-Object { $_.StaleReasons -match 'No matching AD' }).Count
    }
    Send-Json $Response @{ results = @($results); errors = @($errors); summary = $summary }
}
```

**Step 2: Commit**

```bash
git add Search-DNSRecords/Search-DNSRecords-GUI.ps1
git commit -m "feat(dns-audit): add stale record detection API endpoint"
```

---

## Task 5: API — DC Comparison Endpoint

**Files:**
- Modify: `Search-DNSRecords/Search-DNSRecords-GUI.ps1`

**Step 1: Add the Invoke-DcCompare function**

```powershell
function Invoke-DcCompare {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )
    $body = Read-RequestBody $Request
    $dc1 = $body.dc1
    $dc2 = $body.dc2
    $zones = @($body.zones)

    if ([string]::IsNullOrWhiteSpace($dc1) -or [string]::IsNullOrWhiteSpace($dc2) -or $zones.Count -eq 0) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = 'dc1, dc2, and zones[] are required' }
        return
    }

    $results = [System.Collections.Generic.List[object]]::new()
    $errors = [System.Collections.Generic.List[object]]::new()

    foreach ($zoneName in $zones) {
        $records1 = @{}
        $records2 = @{}

        # Fetch from DC1
        try {
            Get-DnsServerResourceRecord -ZoneName $zoneName -ComputerName $dc1 -ErrorAction Stop | ForEach-Object {
                $c = Convert-DnsRecord -Record $_ -ZoneName $zoneName -DcName $dc1
                $key = "$($c.Name)|$($c.Type)|$($c.Data)"
                $records1[$key] = $c
            }
        }
        catch {
            $errors.Add([PSCustomObject]@{ zone = $zoneName; dc = $dc1; error = $_.Exception.Message })
            continue
        }

        # Fetch from DC2
        try {
            Get-DnsServerResourceRecord -ZoneName $zoneName -ComputerName $dc2 -ErrorAction Stop | ForEach-Object {
                $c = Convert-DnsRecord -Record $_ -ZoneName $zoneName -DcName $dc2
                $key = "$($c.Name)|$($c.Type)|$($c.Data)"
                $records2[$key] = $c
            }
        }
        catch {
            $errors.Add([PSCustomObject]@{ zone = $zoneName; dc = $dc2; error = $_.Exception.Message })
            continue
        }

        # Find records only on DC1
        foreach ($key in $records1.Keys) {
            if (-not $records2.ContainsKey($key)) {
                $rec = $records1[$key]
                $rec | Add-Member -NotePropertyName 'CompareStatus' -NotePropertyValue "Only on $dc1" -Force
                $results.Add($rec)
            }
        }

        # Find records only on DC2
        foreach ($key in $records2.Keys) {
            if (-not $records1.ContainsKey($key)) {
                $rec = $records2[$key]
                $rec | Add-Member -NotePropertyName 'CompareStatus' -NotePropertyValue "Only on $dc2" -Force
                $results.Add($rec)
            }
        }

        # Find mismatched records (same Name+Type but different Data)
        $nameType1 = @{}
        foreach ($key in $records1.Keys) {
            $parts = $key -split '\|', 3
            $nt = "$($parts[0])|$($parts[1])"
            if (-not $nameType1.ContainsKey($nt)) { $nameType1[$nt] = [System.Collections.Generic.List[string]]::new() }
            $nameType1[$nt].Add($parts[2])
        }
        $nameType2 = @{}
        foreach ($key in $records2.Keys) {
            $parts = $key -split '\|', 3
            $nt = "$($parts[0])|$($parts[1])"
            if (-not $nameType2.ContainsKey($nt)) { $nameType2[$nt] = [System.Collections.Generic.List[string]]::new() }
            $nameType2[$nt].Add($parts[2])
        }
        foreach ($nt in $nameType1.Keys) {
            if ($nameType2.ContainsKey($nt)) {
                $data1 = ($nameType1[$nt] | Sort-Object) -join ','
                $data2 = ($nameType2[$nt] | Sort-Object) -join ','
                if ($data1 -ne $data2) {
                    $parts = $nt -split '\|', 2
                    $results.Add([PSCustomObject]@{
                        Zone          = $zoneName
                        Name          = $parts[0]
                        Type          = $parts[1]
                        Data          = "$dc1=$($nameType1[$nt] -join ',')  |  $dc2=$($nameType2[$nt] -join ',')"
                        TTL           = ''
                        Timestamp     = ''
                        AgeDays       = $null
                        IsStatic      = $false
                        DC            = 'MISMATCH'
                        CompareStatus = 'Data differs'
                    })
                }
            }
        }
    }

    $script:lastResults = $results
    $script:lastMode = 'compare'
    $summary = @{
        total     = $results.Count
        onlyDc1   = @($results | Where-Object { $_.CompareStatus -match "Only on $([regex]::Escape($dc1))" }).Count
        onlyDc2   = @($results | Where-Object { $_.CompareStatus -match "Only on $([regex]::Escape($dc2))" }).Count
        mismatch  = @($results | Where-Object { $_.CompareStatus -eq 'Data differs' }).Count
    }
    Send-Json $Response @{ results = @($results); errors = @($errors); summary = $summary; dc1 = $dc1; dc2 = $dc2 }
}
```

**Step 2: Commit**

```bash
git add Search-DNSRecords/Search-DNSRecords-GUI.ps1
git commit -m "feat(dns-audit): add DC comparison API endpoint"
```

---

## Task 6: API — Export Endpoints (CSV + HTML)

**Files:**
- Modify: `Search-DNSRecords/Search-DNSRecords-GUI.ps1`

**Step 1: Add the CSV export function**

```powershell
function Invoke-ExportCsv {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )
    if ($script:lastResults.Count -eq 0) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = 'No results to export. Run a search first.' }
        return
    }

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $fileName = "DNS-${script:lastMode}-${timestamp}.csv"
    $filePath = Join-Path $OutputPath $fileName

    $script:lastResults | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8

    # Also send as download
    $csvContent = Get-Content -Path $filePath -Raw -Encoding UTF8
    Send-File $Response $csvContent 'text/csv; charset=utf-8' $fileName
}
```

**Step 2: Add the HTML export function**

```powershell
function Invoke-ExportHtml {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )
    if ($script:lastResults.Count -eq 0) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = 'No results to export. Run a search first.' }
        return
    }

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $fileName = "DNS-${script:lastMode}-${timestamp}.html"
    $filePath = Join-Path $OutputPath $fileName

    # Build column headers from the first result's properties
    $columns = @($script:lastResults[0].PSObject.Properties.Name)

    $headerCells = ($columns | ForEach-Object { "<th>$_</th>" }) -join "`n"
    $rows = $script:lastResults | ForEach-Object {
        $row = $_
        $cells = ($columns | ForEach-Object {
            $val = $row.$_
            if ($null -eq $val) { $val = '' }
            "<td>$([System.Web.HttpUtility]::HtmlEncode($val.ToString()))</td>"
        }) -join ''
        "<tr>$cells</tr>"
    }
    $rowsHtml = $rows -join "`n"

    $htmlReport = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>DNS Audit Report - $($script:lastMode) - $timestamp</title>
<style>
  body { font-family: 'Segoe UI', sans-serif; background: #1a1d23; color: #e0e0e0; margin: 2em; }
  h1 { color: #5dade2; }
  .summary { margin-bottom: 1em; color: #8b95a5; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9em; }
  th { background: #2a2f38; padding: 8px 12px; text-align: left; position: sticky; top: 0; cursor: pointer; }
  td { padding: 6px 12px; border-bottom: 1px solid #2a2f38; }
  tr:hover { background: #23272e; }
  input#filter { width: 300px; padding: 8px; margin-bottom: 1em; background: #23272e; color: #e0e0e0; border: 1px solid #3a3f48; border-radius: 4px; }
</style>
</head>
<body>
<h1>DNS Audit Report &mdash; $($script:lastMode)</h1>
<p class="summary">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Records: $($script:lastResults.Count)</p>
<input type="text" id="filter" placeholder="Type to filter..." onkeyup="filterTable()">
<table id="results">
<thead><tr>$headerCells</tr></thead>
<tbody>$rowsHtml</tbody>
</table>
<script>
function filterTable(){var f=document.getElementById('filter').value.toLowerCase();var rows=document.querySelectorAll('#results tbody tr');rows.forEach(function(r){r.style.display=r.textContent.toLowerCase().includes(f)?'':'none'});}
document.querySelectorAll('#results th').forEach(function(th,i){th.onclick=function(){var tb=document.querySelector('#results tbody');var rows=Array.from(tb.rows);var asc=th.dataset.asc!=='true';th.dataset.asc=asc;rows.sort(function(a,b){var x=a.cells[i].textContent,y=b.cells[i].textContent;return asc?x.localeCompare(y,undefined,{numeric:true}):y.localeCompare(x,undefined,{numeric:true});});rows.forEach(function(r){tb.appendChild(r)});}});
</script>
</body>
</html>
"@
    [System.IO.File]::WriteAllText($filePath, $htmlReport, [System.Text.Encoding]::UTF8)

    Send-File $Response $htmlReport 'text/html; charset=utf-8' $fileName
}
```

**Step 3: Commit**

```bash
git add Search-DNSRecords/Search-DNSRecords-GUI.ps1
git commit -m "feat(dns-audit): add CSV and HTML export endpoints"
```

---

## Task 7: Route Dispatcher and HTTP Listener Loop

**Files:**
- Modify: `Search-DNSRecords/Search-DNSRecords-GUI.ps1`

**Step 1: Add the route dispatcher**

```powershell
# --- Route Dispatcher ---

function Invoke-Route {
    param([System.Net.HttpListenerContext]$Context)

    $request = $Context.Request
    $response = $Context.Response
    $path = $request.Url.AbsolutePath
    $method = $request.HttpMethod

    try {
        switch -Regex ("$method $path") {
            '^GET /$'                  { Send-Html $response }
            '^GET /api/status$'        { Get-Status $response }
            '^GET /api/zones$'         { Get-DnsZones $request $response }
            '^POST /api/search$'       { Invoke-DnsSearch $request $response }
            '^POST /api/stale$'        { Invoke-StaleDetection $request $response }
            '^POST /api/compare$'      { Invoke-DcCompare $request $response }
            '^GET /api/export/csv$'    { Invoke-ExportCsv $request $response }
            '^GET /api/export/html$'   { Invoke-ExportHtml $request $response }
            '^GET /api/shutdown$'      {
                Send-Json $response @{ status = 'shutting down' }
                $script:running = $false
            }
            default {
                $response.StatusCode = 404
                Send-Json $response @{ error = 'Not found' }
            }
        }
    }
    catch {
        $response.StatusCode = 500
        Send-Json $response @{ error = $_.Exception.Message }
    }
}
```

**Step 2: Add placeholder HTML and listener loop**

```powershell
# --- HTML Content (placeholder — replaced in Task 8) ---

$script:htmlContent = @"
<!DOCTYPE html>
<html><head><title>DNS Audit</title></head>
<body><h1>DNS Record Audit Tool</h1><p>Frontend loading in next task...</p></body>
</html>
"@

# --- Start HTTP Listener ---

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add($baseUrl)
try {
    $listener.Start()
    Write-Host "[INFO] DNS Record Audit Tool running at $baseUrl" -ForegroundColor Cyan
    Write-Host "[INFO] Press Ctrl+C to stop." -ForegroundColor Cyan
}
catch {
    Write-Error "Failed to start HTTP listener on port $Port. Is it already in use? Error: $_"
    exit 1
}

if (-not $NoBrowserOpen) {
    Start-Process $baseUrl
}

# --- Main Request Loop ---

$script:running = $true
try {
    while ($script:running) {
        $contextTask = $listener.GetContextAsync()
        while (-not $contextTask.IsCompleted) {
            Start-Sleep -Milliseconds 100
        }
        $context = $contextTask.Result
        Invoke-Route -Context $context
    }
}
finally {
    $listener.Stop()
    $listener.Close()
    Write-Host "[INFO] Server stopped." -ForegroundColor Yellow
}
```

**Step 3: Commit**

```bash
git add Search-DNSRecords/Search-DNSRecords-GUI.ps1
git commit -m "feat(dns-audit): add route dispatcher and HTTP listener loop"
```

---

## Task 8: Frontend — Full Embedded HTML/CSS/JS

**Files:**
- Modify: `Search-DNSRecords/Search-DNSRecords-GUI.ps1` — replace the placeholder `$script:htmlContent` with the full frontend

This is the largest task. The frontend must include:

**Layout:**
- Dark theme matching FolderPermissionManager (CSS variables: `--bg: #1a1d23`, `--bg-card: #23272e`, `--accent: #5dade2`)
- Top bar: DC input field, mode tabs (Search / Stale / Compare)
- Zone picker panel: fetched via `GET /api/zones?dc=`, checkboxes, "Select All Forward" / "Select All" buttons
- Mode-specific parameters panel that changes based on selected tab
- Results table with sortable headers, text filter, row count
- Export bar: CSV and HTML download buttons
- Status bar showing module availability (fetched from `GET /api/status`)

**Mode panels:**
- Search: pattern input, regex toggle checkbox, record type dropdown (A, AAAA, CNAME, MX, PTR, SRV, TXT, NS, or All), age filter input
- Stale: threshold days input (pre-filled from server), checkboxes for each detection method (Age, Static, AD Orphan), AD Orphan checkbox disabled if AD module unavailable
- Compare: second DC input field

**JavaScript behavior:**
- On DC input blur/enter: fetch zones, populate zone picker
- On mode tab click: show/hide the corresponding parameters panel
- On "Run" button click: POST to the appropriate `/api/*` endpoint with selected zones and params
- Results rendered into a `<table>` with sortable column headers and a text filter `<input>`
- Color-coding: stale mode rows colored by reason, compare mode rows colored by status
- Export buttons call `GET /api/export/csv` and `GET /api/export/html` via `window.location`

**Implementation note:** Write the full HTML as a PowerShell here-string (`@"..."@`). Escape any `$` characters that aren't PowerShell variables with a backtick. Keep JavaScript self-contained — no external CDN dependencies.

**Step 1: Replace the placeholder `$script:htmlContent` with the complete frontend**

The HTML should be ~600-900 lines. Use `FolderPermissionManager-GUI.ps1` lines 755-2527 as the reference for style, structure, and JS patterns. Key differences:
- Three mode tabs instead of a tree view
- Zone picker sidebar instead of folder browser
- Results table with mode-specific columns

**Step 2: Test manually by running the script on a domain-joined machine**

```powershell
.\Search-DNSRecords-GUI.ps1 -NoBrowserOpen
# Open http://localhost:8080 manually and verify:
# 1. Entering a DC name loads zones in the picker
# 2. Selecting Search mode and running returns results
# 3. Selecting Stale mode flags records with reasons
# 4. Selecting Compare mode with two DCs shows diff
# 5. Export CSV and HTML buttons download files
```

**Step 3: Commit**

```bash
git add Search-DNSRecords/Search-DNSRecords-GUI.ps1
git commit -m "feat(dns-audit): add full browser-based frontend with all three modes"
```

---

## Task 9: README

**Files:**
- Create: `Search-DNSRecords/README.md`

**Step 1: Write the README following repo conventions**

Cover: purpose, three modes, parameters, prerequisites (RSAT DnsServer, optional ActiveDirectory), usage examples, screenshots placeholder, notes about graceful degradation when AD module is missing.

Follow the style of existing READMEs in the repo (e.g., `DHCP-Audit/README.md`, `FolderPermissionManager/README.md`).

**Step 2: Commit**

```bash
git add Search-DNSRecords/README.md
git commit -m "docs(dns-audit): add README for DNS Record Audit tool"
```

---

## Task 10: Final Integration Commit

**Step 1: Verify folder structure**

```
Search-DNSRecords/
  Search-DNSRecords-GUI.ps1
  README.md
```

**Step 2: Run a final read-through of the script**

Check for:
- `[CmdletBinding()]` and typed params with validation attributes (**repo convention**)
- Comment-based help block with all required sections (**repo convention**)
- `Import-Module` with try/catch instead of `#Requires -Modules` (**repo convention**)
- All DNS cmdlets use `-ComputerName` (**repo convention: remote targeting**)
- No hardcoded server names (**repo convention: discovery over hardcoding**)
- Status prefixes `[PASS]`, `[WARN]`, `[FAIL]`, `[INFO]` in console output (**repo convention**)

**Step 3: Final commit if any fixes needed**

```bash
git add -A Search-DNSRecords/
git commit -m "feat: add DNS Record Audit & Search tool with browser GUI"
```
