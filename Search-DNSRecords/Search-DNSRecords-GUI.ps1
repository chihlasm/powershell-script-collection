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
                    name        = $_.ZoneName
                    type        = $_.ZoneType.ToString()
                    isReverse   = $isReverse
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

function Get-Status {
    param([System.Net.HttpListenerResponse]$Response)
    Send-Json $Response @{
        dnsModule          = $script:dnsModuleAvailable
        adModule           = $script:adModuleAvailable
        staleThresholdDays = $StaleThresholdDays
    }
}

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
            Get-ADComputer -Filter * -Properties Name -Server $dc -ErrorAction Stop | ForEach-Object {
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
                        $reasons.Add('AD orphan (no matching computer)')
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
        total    = $results.Count
        aged     = @($results | Where-Object { $_.StaleReasons -match 'Aged' }).Count
        static   = @($results | Where-Object { $_.StaleReasons -match 'Static' }).Count
        adOrphan = @($results | Where-Object { $_.StaleReasons -match 'AD orphan' }).Count
    }
    Send-Json $Response @{ results = @($results); errors = @($errors); summary = $summary }
}

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
        total    = $results.Count
        onlyDc1  = @($results | Where-Object { $_.CompareStatus -match "Only on $([regex]::Escape($dc1))" }).Count
        onlyDc2  = @($results | Where-Object { $_.CompareStatus -match "Only on $([regex]::Escape($dc2))" }).Count
        mismatch = @($results | Where-Object { $_.CompareStatus -eq 'Data differs' }).Count
    }
    Send-Json $Response @{ results = @($results); errors = @($errors); summary = $summary; dc1 = $dc1; dc2 = $dc2 }
}

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
            $escaped = $val.ToString().Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
            "<td>$escaped</td>"
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

# --- Route Dispatcher ---

function Invoke-Route {
    param([System.Net.HttpListenerContext]$Context)

    $request = $Context.Request
    $response = $Context.Response
    $path = $request.Url.AbsolutePath
    $method = $request.HttpMethod

    try {
        switch -Regex ("$method $path") {
            '^GET /$'                 { Send-Html $response }
            '^GET /api/status$'       { Get-Status $response }
            '^GET /api/zones$'        { Get-DnsZones $request $response }
            '^POST /api/search$'      { Invoke-DnsSearch $request $response }
            '^POST /api/stale$'       { Invoke-StaleDetection $request $response }
            '^POST /api/compare$'     { Invoke-DcCompare $request $response }
            '^GET /api/export/csv$'   { Invoke-ExportCsv $request $response }
            '^GET /api/export/html$'  { Invoke-ExportHtml $request $response }
            '^GET /api/shutdown$'     {
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

# --- Embedded HTML/CSS/JS Frontend ---

$script:htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DNS Record Audit Tool</title>
<style>
:root {
    --bg: #1a1d23;
    --bg-card: #23272e;
    --bg-hover: #2a2f38;
    --bg-input: #1e2229;
    --text: #e0e0e0;
    --text-muted: #8b95a5;
    --accent: #5dade2;
    --accent-hover: #4a9bd4;
    --border: #333a45;
    --success: #2ecc71;
    --warning: #f39c12;
    --danger: #e74c3c;
    --shadow: rgba(0,0,0,0.3);
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

/* Header */
.header {
    background: var(--bg-card);
    border-bottom: 1px solid var(--border);
    padding: 14px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.header h1 {
    font-size: 16px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--accent);
}
.status-indicator {
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 12px;
    color: var(--text-muted);
}
.status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
    margin-right: 4px;
}
.status-dot.ok { background: var(--success); }
.status-dot.err { background: var(--danger); }

/* Config bar */
.config-bar {
    background: var(--bg-card);
    border-bottom: 1px solid var(--border);
    padding: 10px 24px;
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
}
.config-bar label {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.config-bar input[type="text"] {
    background: var(--bg-input);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 7px 12px;
    border-radius: 4px;
    font-size: 13px;
    font-family: inherit;
    width: 200px;
}
.config-bar input[type="text"]:focus { outline: none; border-color: var(--accent); }
.config-bar .separator { width: 1px; height: 28px; background: var(--border); margin: 0 4px; }

/* Buttons */
.btn {
    background: var(--bg);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 7px 16px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
    font-family: inherit;
    transition: all 0.15s;
    white-space: nowrap;
}
.btn:hover:not(:disabled) { background: var(--bg-hover); border-color: var(--accent); color: var(--accent); }
.btn:disabled { opacity: 0.4; cursor: not-allowed; }
.btn.primary { background: var(--accent); color: #fff; border-color: var(--accent); }
.btn.primary:hover:not(:disabled) { background: var(--accent-hover); }
.btn.primary:disabled { opacity: 0.5; }
.btn.run-btn {
    background: var(--accent);
    color: #fff;
    border-color: var(--accent);
    padding: 10px 32px;
    font-size: 14px;
    font-weight: 600;
    letter-spacing: 0.5px;
}
.btn.run-btn:hover:not(:disabled) { background: var(--accent-hover); }

/* Mode tabs */
.mode-tabs {
    display: flex;
    gap: 0;
}
.mode-tab {
    background: none;
    border: 1px solid var(--border);
    color: var(--text-muted);
    padding: 7px 20px;
    cursor: pointer;
    font-size: 13px;
    font-family: inherit;
    font-weight: 500;
    transition: all 0.15s;
}
.mode-tab:first-child { border-radius: 4px 0 0 4px; }
.mode-tab:last-child { border-radius: 0 4px 4px 0; }
.mode-tab:not(:first-child) { border-left: none; }
.mode-tab:hover { color: var(--text); background: var(--bg-hover); }
.mode-tab.active { color: #fff; background: var(--accent); border-color: var(--accent); }

/* Main layout */
.main-layout {
    display: flex;
    flex: 1;
    overflow: hidden;
}

/* Zone sidebar */
.zone-sidebar {
    width: 280px;
    min-width: 280px;
    background: var(--bg-card);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    overflow: hidden;
}
.zone-sidebar-header {
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
}
.zone-sidebar-header h2 {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-muted);
    margin-bottom: 8px;
}
.zone-quick-btns {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
}
.zone-quick-btns .btn { padding: 4px 10px; font-size: 11px; }
.zone-list {
    flex: 1;
    overflow-y: auto;
    padding: 4px 0;
}
.zone-item {
    display: flex;
    align-items: center;
    padding: 5px 16px;
    font-size: 13px;
    cursor: pointer;
    transition: background 0.1s;
    gap: 8px;
}
.zone-item:hover { background: var(--bg-hover); }
.zone-item input[type="checkbox"] { accent-color: var(--accent); cursor: pointer; }
.zone-item .zone-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.zone-badge {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 3px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    background: rgba(93,173,226,0.1);
    color: var(--accent);
}
.zone-badge.reverse { background: rgba(243,156,18,0.1); color: var(--warning); }
.zone-empty {
    padding: 20px 16px;
    text-align: center;
    color: var(--text-muted);
    font-size: 13px;
}

/* Content area */
.content-area {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
}

/* Parameters panel */
.params-panel {
    background: var(--bg-card);
    border-bottom: 1px solid var(--border);
    padding: 12px 24px;
    display: flex;
    align-items: center;
    gap: 16px;
    flex-wrap: wrap;
}
.param-group {
    display: flex;
    align-items: center;
    gap: 6px;
}
.param-group label {
    font-size: 12px;
    color: var(--text-muted);
    white-space: nowrap;
}
.param-group input[type="text"],
.param-group input[type="number"] {
    background: var(--bg-input);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 6px 10px;
    border-radius: 4px;
    font-size: 13px;
    font-family: inherit;
    width: 140px;
}
.param-group input:focus { outline: none; border-color: var(--accent); }
.param-group select {
    background: var(--bg-input);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 6px 10px;
    border-radius: 4px;
    font-size: 13px;
    font-family: inherit;
}
.param-group select:focus { outline: none; border-color: var(--accent); }
.param-group input[type="checkbox"] { accent-color: var(--accent); cursor: pointer; }
.params-panel .hidden { display: none; }
.tooltip-wrap { position: relative; }
.tooltip-wrap .tooltip-text {
    display: none;
    position: absolute;
    bottom: 120%;
    left: 50%;
    transform: translateX(-50%);
    background: var(--bg-card);
    border: 1px solid var(--border);
    color: var(--text-muted);
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 11px;
    white-space: nowrap;
    z-index: 100;
}
.tooltip-wrap:hover .tooltip-text { display: block; }

/* Run bar */
.run-bar {
    padding: 12px 24px;
    display: flex;
    align-items: center;
    gap: 16px;
    background: var(--bg);
}
.spinner {
    display: none;
    width: 18px;
    height: 18px;
    border: 2px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }

/* Summary bar */
.summary-bar {
    padding: 8px 24px;
    background: var(--bg-card);
    border-bottom: 1px solid var(--border);
    display: none;
    align-items: center;
    gap: 16px;
    font-size: 13px;
    flex-wrap: wrap;
}
.summary-bar .count-item {
    color: var(--text-muted);
}
.summary-bar .count-item strong { color: var(--text); }

/* Error alerts */
.error-alerts {
    display: none;
    padding: 8px 24px;
}
.error-alert {
    background: rgba(243,156,18,0.1);
    border: 1px solid rgba(243,156,18,0.3);
    border-radius: 4px;
    padding: 6px 12px;
    margin-bottom: 4px;
    font-size: 12px;
    color: var(--warning);
}

/* Filter and export bar */
.results-toolbar {
    padding: 8px 24px;
    display: none;
    align-items: center;
    gap: 12px;
    background: var(--bg);
}
.results-toolbar input[type="text"] {
    background: var(--bg-input);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 6px 10px;
    border-radius: 4px;
    font-size: 13px;
    font-family: inherit;
    width: 250px;
}
.results-toolbar input[type="text"]:focus { outline: none; border-color: var(--accent); }
.row-count {
    font-size: 12px;
    color: var(--text-muted);
    margin-left: auto;
}
.export-btns { display: flex; gap: 6px; margin-left: 12px; }

/* Results table */
.results-wrap {
    flex: 1;
    overflow: auto;
    padding: 0;
}
.results-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}
.results-table th {
    text-align: left;
    padding: 10px 12px;
    background: var(--bg-card);
    border-bottom: 2px solid var(--border);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    position: sticky;
    top: 0;
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
    z-index: 2;
}
.results-table th:hover { color: var(--accent); }
.results-table th .sort-arrow { margin-left: 4px; font-size: 10px; }
.results-table td {
    padding: 7px 12px;
    border-bottom: 1px solid var(--border);
    word-break: break-word;
    max-width: 320px;
}
.results-table tr:hover td { background: var(--bg-hover); }

/* Status badges for compare mode */
.compare-match { color: var(--success); }
.compare-mismatch { color: var(--warning); }
.compare-missing { color: var(--danger); }

/* Stale reason badges */
.stale-reason {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: 600;
    margin-right: 4px;
    margin-bottom: 2px;
}
.stale-aged { background: rgba(243,156,18,0.15); color: var(--warning); }
.stale-static { background: rgba(93,173,226,0.15); color: var(--accent); }
.stale-orphan { background: rgba(231,76,60,0.15); color: var(--danger); }

/* Empty state */
.empty-state {
    padding: 60px 24px;
    text-align: center;
    color: var(--text-muted);
    font-size: 14px;
}
.empty-state .icon { font-size: 48px; margin-bottom: 12px; opacity: 0.3; }

/* Scrollbar */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }
</style>
</head>
<body>

<!-- Header -->
<div class="header">
    <h1>DNS Record Audit Tool</h1>
    <div class="status-indicator" id="statusArea">
        <span>Checking modules...</span>
    </div>
</div>

<!-- Config bar -->
<div class="config-bar">
    <label for="dcInput">Domain Controller</label>
    <input type="text" id="dcInput" placeholder="e.g. DC01.domain.local" />
    <button class="btn primary" id="loadZonesBtn" onclick="loadZones()">Load Zones</button>
    <div class="separator"></div>
    <div id="dc2Group" class="param-group" style="display:none;">
        <label for="dc2Input">Second DC</label>
        <input type="text" id="dc2Input" placeholder="e.g. DC02.domain.local" />
    </div>
    <div class="separator" id="dc2Sep" style="display:none;"></div>
    <div class="mode-tabs">
        <button class="mode-tab active" data-mode="search" onclick="switchMode('search')">Search</button>
        <button class="mode-tab" data-mode="stale" onclick="switchMode('stale')">Stale</button>
        <button class="mode-tab" data-mode="compare" onclick="switchMode('compare')">Compare</button>
    </div>
</div>

<!-- Main layout -->
<div class="main-layout">
    <!-- Zone sidebar -->
    <div class="zone-sidebar">
        <div class="zone-sidebar-header">
            <h2>DNS Zones</h2>
            <div class="zone-quick-btns">
                <button class="btn" onclick="selectAllZones(true)">Select All</button>
                <button class="btn" onclick="selectAllZones(false)">Deselect All</button>
                <button class="btn" onclick="selectForwardOnly()">Forward Only</button>
            </div>
        </div>
        <div class="zone-list" id="zoneList">
            <div class="zone-empty">Click "Load Zones" to populate</div>
        </div>
    </div>

    <!-- Content area -->
    <div class="content-area">
        <!-- Search params -->
        <div class="params-panel" id="searchParams">
            <div class="param-group">
                <label for="patternInput">Pattern</label>
                <input type="text" id="patternInput" placeholder="hostname or pattern" />
            </div>
            <div class="param-group">
                <input type="checkbox" id="regexToggle" />
                <label for="regexToggle">Regex</label>
            </div>
            <div class="param-group">
                <label for="recordType">Type</label>
                <select id="recordType">
                    <option value="">All</option>
                    <option value="A">A</option>
                    <option value="AAAA">AAAA</option>
                    <option value="CNAME">CNAME</option>
                    <option value="MX">MX</option>
                    <option value="PTR">PTR</option>
                    <option value="SRV">SRV</option>
                    <option value="TXT">TXT</option>
                    <option value="NS">NS</option>
                </select>
            </div>
            <div class="param-group">
                <label for="maxAgeDays">Older than (days)</label>
                <input type="number" id="maxAgeDays" placeholder="optional" style="width:90px;" />
            </div>
        </div>

        <!-- Stale params -->
        <div class="params-panel hidden" id="staleParams">
            <div class="param-group">
                <label for="thresholdDays">Threshold (days)</label>
                <input type="number" id="thresholdDays" value="90" style="width:90px;" />
            </div>
            <div class="param-group">
                <input type="checkbox" id="checkAge" checked />
                <label for="checkAge">Age-based</label>
            </div>
            <div class="param-group">
                <input type="checkbox" id="checkStatic" checked />
                <label for="checkStatic">Static records</label>
            </div>
            <div class="param-group tooltip-wrap">
                <input type="checkbox" id="checkAdOrphan" />
                <label for="checkAdOrphan">AD Orphans</label>
                <span class="tooltip-text" id="adOrphanTooltip">Requires AD module on server</span>
            </div>
        </div>

        <!-- Compare params (no extra params beyond DC2 in config bar) -->
        <div class="params-panel hidden" id="compareParams">
            <div class="param-group">
                <span style="color:var(--text-muted);font-size:13px;">Configure both Domain Controllers above, select zones, then run compare.</span>
            </div>
        </div>

        <!-- Run bar -->
        <div class="run-bar">
            <button class="btn run-btn" id="runBtn" onclick="runQuery()">Search</button>
            <div class="spinner" id="spinner"></div>
            <span id="runError" style="color:var(--danger);font-size:13px;"></span>
        </div>

        <!-- Summary bar -->
        <div class="summary-bar" id="summaryBar"></div>

        <!-- Error alerts -->
        <div class="error-alerts" id="errorAlerts"></div>

        <!-- Results toolbar -->
        <div class="results-toolbar" id="resultsToolbar">
            <input type="text" id="filterInput" placeholder="Filter results..." oninput="filterResults()" />
            <span class="row-count" id="rowCount"></span>
            <div class="export-btns">
                <button class="btn" id="exportCsvBtn" onclick="exportCsv()" disabled>Export CSV</button>
                <button class="btn" id="exportHtmlBtn" onclick="exportHtml()" disabled>Export HTML</button>
            </div>
        </div>

        <!-- Results table -->
        <div class="results-wrap" id="resultsWrap">
            <div class="empty-state" id="emptyState">
                <div class="icon">&#128269;</div>
                <div>Configure parameters and click the button above to run a query.</div>
            </div>
            <table class="results-table" id="resultsTable" style="display:none;">
                <thead id="tableHead"></thead>
                <tbody id="tableBody"></tbody>
            </table>
        </div>
    </div>
</div>

<script>
var currentMode = 'search';
var allResults = [];
var sortCol = -1;
var sortAsc = true;
var adModuleAvailable = false;
var staleThresholdDefault = 90;

function initApp() {
    fetchStatus();
}

function fetchStatus() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/status', true);
    xhr.onload = function() {
        if (xhr.status === 200) {
            var data = JSON.parse(xhr.responseText);
            var area = document.getElementById('statusArea');
            var dnsDot = data.dnsModule ? 'ok' : 'err';
            var adDot = data.adModule ? 'ok' : 'err';
            area.innerHTML = '<span><span class="status-dot ' + dnsDot + '"></span>DNS Module</span>' +
                '<span><span class="status-dot ' + adDot + '"></span>AD Module</span>';
            adModuleAvailable = data.adModule;
            if (data.staleThresholdDays) {
                staleThresholdDefault = data.staleThresholdDays;
                document.getElementById('thresholdDays').value = data.staleThresholdDays;
            }
            if (!adModuleAvailable) {
                document.getElementById('checkAdOrphan').disabled = true;
            }
        }
    };
    xhr.onerror = function() {
        document.getElementById('statusArea').innerHTML = '<span style="color:var(--danger)">Connection error</span>';
    };
    xhr.send();
}

function loadZones() {
    var dc = document.getElementById('dcInput').value.trim();
    if (!dc) {
        showRunError('Enter a Domain Controller name first.');
        return;
    }
    var btn = document.getElementById('loadZonesBtn');
    btn.disabled = true;
    btn.textContent = 'Loading...';
    var zoneList = document.getElementById('zoneList');
    zoneList.innerHTML = '<div class="zone-empty">Loading zones...</div>';

    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/zones?dc=' + encodeURIComponent(dc), true);
    xhr.onload = function() {
        btn.disabled = false;
        btn.textContent = 'Load Zones';
        if (xhr.status === 200) {
            var data = JSON.parse(xhr.responseText);
            renderZoneList(data.zones || []);
        } else {
            var errData = {};
            try { errData = JSON.parse(xhr.responseText); } catch(e) {}
            zoneList.innerHTML = '<div class="zone-empty" style="color:var(--danger);">Error: ' + escapeHtml(errData.error || 'Failed to load zones') + '</div>';
        }
    };
    xhr.onerror = function() {
        btn.disabled = false;
        btn.textContent = 'Load Zones';
        zoneList.innerHTML = '<div class="zone-empty" style="color:var(--danger);">Connection error</div>';
    };
    xhr.send();
}

function renderZoneList(zones) {
    var zoneList = document.getElementById('zoneList');
    if (zones.length === 0) {
        zoneList.innerHTML = '<div class="zone-empty">No zones found</div>';
        return;
    }
    var html = '';
    for (var i = 0; i < zones.length; i++) {
        var z = zones[i];
        var checked = z.isReverse ? '' : ' checked';
        var badgeClass = z.isReverse ? 'zone-badge reverse' : 'zone-badge';
        var badgeText = z.type || (z.isReverse ? 'Reverse' : 'Forward');
        html += '<label class="zone-item">' +
            '<input type="checkbox" class="zone-cb" value="' + escapeHtml(z.name) + '"' + checked + ' />' +
            '<span class="zone-name">' + escapeHtml(z.name) + '</span>' +
            '<span class="' + badgeClass + '">' + escapeHtml(badgeText) + '</span>' +
            '</label>';
    }
    zoneList.innerHTML = html;
}

function selectAllZones(check) {
    var cbs = document.querySelectorAll('.zone-cb');
    for (var i = 0; i < cbs.length; i++) {
        cbs[i].checked = check;
    }
}

function selectForwardOnly() {
    var items = document.querySelectorAll('.zone-item');
    for (var i = 0; i < items.length; i++) {
        var cb = items[i].querySelector('.zone-cb');
        var badge = items[i].querySelector('.zone-badge');
        if (badge && badge.classList.contains('reverse')) {
            cb.checked = false;
        } else {
            cb.checked = true;
        }
    }
}

function getSelectedZones() {
    var cbs = document.querySelectorAll('.zone-cb:checked');
    var zones = [];
    for (var i = 0; i < cbs.length; i++) {
        zones.push(cbs[i].value);
    }
    return zones;
}

function switchMode(mode) {
    currentMode = mode;
    var tabs = document.querySelectorAll('.mode-tab');
    for (var i = 0; i < tabs.length; i++) {
        tabs[i].classList.toggle('active', tabs[i].getAttribute('data-mode') === mode);
    }
    document.getElementById('searchParams').className = mode === 'search' ? 'params-panel' : 'params-panel hidden';
    document.getElementById('staleParams').className = mode === 'stale' ? 'params-panel' : 'params-panel hidden';
    document.getElementById('compareParams').className = mode === 'compare' ? 'params-panel' : 'params-panel hidden';

    var dc2Vis = mode === 'compare' ? '' : 'none';
    document.getElementById('dc2Group').style.display = dc2Vis;
    document.getElementById('dc2Sep').style.display = dc2Vis;

    var btnText = { search: 'Search', stale: 'Scan for Stale', compare: 'Compare DCs' };
    document.getElementById('runBtn').textContent = btnText[mode] || 'Run';
}

function showRunError(msg) {
    document.getElementById('runError').textContent = msg;
    setTimeout(function() { document.getElementById('runError').textContent = ''; }, 5000);
}

function runQuery() {
    var dc = document.getElementById('dcInput').value.trim();
    if (!dc) { showRunError('Enter a Domain Controller name.'); return; }
    var zones = getSelectedZones();
    if (zones.length === 0) { showRunError('Select at least one zone.'); return; }

    var url, body;
    if (currentMode === 'search') {
        url = '/api/search';
        body = {
            dc: dc,
            zones: zones,
            pattern: document.getElementById('patternInput').value,
            recordType: document.getElementById('recordType').value,
            useRegex: document.getElementById('regexToggle').checked,
            maxAgeDays: parseInt(document.getElementById('maxAgeDays').value) || 0
        };
    } else if (currentMode === 'stale') {
        url = '/api/stale';
        body = {
            dc: dc,
            zones: zones,
            thresholdDays: parseInt(document.getElementById('thresholdDays').value) || staleThresholdDefault,
            checkAge: document.getElementById('checkAge').checked,
            checkStatic: document.getElementById('checkStatic').checked,
            checkAdOrphan: document.getElementById('checkAdOrphan').checked
        };
    } else if (currentMode === 'compare') {
        var dc2 = document.getElementById('dc2Input').value.trim();
        if (!dc2) { showRunError('Enter a second Domain Controller for compare.'); return; }
        url = '/api/compare';
        body = {
            dc1: dc,
            dc2: dc2,
            zones: zones
        };
    }

    var btn = document.getElementById('runBtn');
    var spinner = document.getElementById('spinner');
    btn.disabled = true;
    spinner.style.display = 'inline-block';
    document.getElementById('runError').textContent = '';

    var xhr = new XMLHttpRequest();
    xhr.open('POST', url, true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.onload = function() {
        btn.disabled = false;
        spinner.style.display = 'none';
        if (xhr.status === 200) {
            var data = JSON.parse(xhr.responseText);
            renderResults(data);
        } else {
            var errData = {};
            try { errData = JSON.parse(xhr.responseText); } catch(e) {}
            showRunError(errData.error || 'Server returned status ' + xhr.status);
        }
    };
    xhr.onerror = function() {
        btn.disabled = false;
        spinner.style.display = 'none';
        showRunError('Connection error. Is the server running?');
    };
    xhr.send(JSON.stringify(body));
}

function renderResults(data) {
    allResults = data.results || [];
    sortCol = -1;
    sortAsc = true;

    /* Summary */
    var summaryBar = document.getElementById('summaryBar');
    var summaryHtml = '<span class="count-item"><strong>' + (data.total || allResults.length) + '</strong> total records</span>';
    if (currentMode === 'stale' && data.summary) {
        summaryHtml += '<span class="count-item">Aged: <strong>' + (data.summary.aged || 0) + '</strong></span>';
        summaryHtml += '<span class="count-item">Static: <strong>' + (data.summary.static || 0) + '</strong></span>';
        summaryHtml += '<span class="count-item">AD Orphan: <strong>' + (data.summary.adOrphan || 0) + '</strong></span>';
    }
    if (currentMode === 'compare' && data.summary) {
        summaryHtml += '<span class="count-item">Only ' + escapeHtml(data.dc1 || 'DC1') + ': <strong>' + (data.summary.onlyDc1 || 0) + '</strong></span>';
        summaryHtml += '<span class="count-item">Only ' + escapeHtml(data.dc2 || 'DC2') + ': <strong>' + (data.summary.onlyDc2 || 0) + '</strong></span>';
        summaryHtml += '<span class="count-item">Mismatch: <strong>' + (data.summary.mismatch || 0) + '</strong></span>';
    }
    summaryBar.innerHTML = summaryHtml;
    summaryBar.style.display = 'flex';

    /* Errors */
    var errorAlerts = document.getElementById('errorAlerts');
    var errors = data.errors || [];
    if (errors.length > 0) {
        var eHtml = '';
        for (var i = 0; i < errors.length; i++) {
            var e = errors[i];
            var eText = (typeof e === 'string') ? e : ((e.zone || '') + ': ' + (e.error || e.message || JSON.stringify(e)));
            eHtml += '<div class="error-alert">' + escapeHtml(eText) + '</div>';
        }
        errorAlerts.innerHTML = eHtml;
        errorAlerts.style.display = 'block';
    } else {
        errorAlerts.style.display = 'none';
    }

    /* Toolbar */
    document.getElementById('resultsToolbar').style.display = 'flex';
    document.getElementById('filterInput').value = '';
    document.getElementById('exportCsvBtn').disabled = allResults.length === 0;
    document.getElementById('exportHtmlBtn').disabled = allResults.length === 0;

    /* Table */
    document.getElementById('emptyState').style.display = allResults.length === 0 ? 'block' : 'none';
    document.getElementById('resultsTable').style.display = allResults.length > 0 ? 'table' : 'none';

    if (allResults.length > 0) {
        buildTable(allResults);
    }
}

function getColumns() {
    if (currentMode === 'search') {
        return [
            { key: 'Zone', label: 'Zone' },
            { key: 'Name', label: 'Name' },
            { key: 'Type', label: 'Type' },
            { key: 'Data', label: 'Data' },
            { key: 'TTL', label: 'TTL' },
            { key: 'Timestamp', label: 'Timestamp' },
            { key: 'AgeDays', label: 'Age (days)' },
            { key: 'DC', label: 'DC' }
        ];
    }
    if (currentMode === 'stale') {
        return [
            { key: 'Zone', label: 'Zone' },
            { key: 'Name', label: 'Name' },
            { key: 'Type', label: 'Type' },
            { key: 'Data', label: 'Data' },
            { key: 'Timestamp', label: 'Timestamp' },
            { key: 'AgeDays', label: 'Age (days)' },
            { key: 'StaleReasons', label: 'Stale Reasons' }
        ];
    }
    if (currentMode === 'compare') {
        return [
            { key: 'Zone', label: 'Zone' },
            { key: 'Name', label: 'Name' },
            { key: 'Type', label: 'Type' },
            { key: 'Data', label: 'Data' },
            { key: 'TTL', label: 'TTL' },
            { key: 'DC', label: 'DC' },
            { key: 'CompareStatus', label: 'Status' }
        ];
    }
    return [];
}

function buildTable(records) {
    var cols = getColumns();
    var thead = document.getElementById('tableHead');
    var hRow = '<tr>';
    for (var c = 0; c < cols.length; c++) {
        var arrow = '';
        if (c === sortCol) { arrow = sortAsc ? ' &#9650;' : ' &#9660;'; }
        hRow += '<th data-col="' + c + '" onclick="sortBy(' + c + ')">' + escapeHtml(cols[c].label) + '<span class="sort-arrow">' + arrow + '</span></th>';
    }
    hRow += '</tr>';
    thead.innerHTML = hRow;

    renderRows(records, cols);
}

function renderRows(records, cols) {
    if (!cols) cols = getColumns();
    var tbody = document.getElementById('tableBody');
    var html = '';
    for (var r = 0; r < records.length; r++) {
        var rec = records[r];
        html += '<tr>';
        for (var c = 0; c < cols.length; c++) {
            var val = rec[cols[c].key];
            if (val === undefined || val === null) val = '';
            var cellHtml = escapeHtml(String(val));

            if (cols[c].key === 'CompareStatus') {
                cellHtml = formatCompareStatus(String(val));
            } else if (cols[c].key === 'StaleReasons') {
                cellHtml = formatStaleReasons(String(val));
            }

            html += '<td>' + cellHtml + '</td>';
        }
        html += '</tr>';
    }
    tbody.innerHTML = html;
    updateRowCount(records.length, allResults.length);
}

function formatCompareStatus(status) {
    if (status.indexOf('Only on') === 0) {
        return '<span class="compare-missing">' + escapeHtml(status) + '</span>';
    }
    if (status.indexOf('differs') !== -1 || status.indexOf('mismatch') !== -1 || status.indexOf('Mismatch') !== -1) {
        return '<span class="compare-mismatch">' + escapeHtml(status) + '</span>';
    }
    if (status.indexOf('Match') !== -1 || status.indexOf('match') !== -1) {
        return '<span class="compare-match">' + escapeHtml(status) + '</span>';
    }
    return escapeHtml(status);
}

function formatStaleReasons(reasons) {
    if (!reasons) return '';
    var parts = reasons.split('; ');
    var html = '';
    for (var i = 0; i < parts.length; i++) {
        var r = parts[i].replace(/^\s+|\s+$/g, '');
        if (!r) continue;
        var cls = 'stale-reason';
        var lower = r.toLowerCase();
        if (lower.indexOf('age') !== -1 || lower.indexOf('old') !== -1) cls += ' stale-aged';
        else if (lower.indexOf('static') !== -1) cls += ' stale-static';
        else if (lower.indexOf('orphan') !== -1) cls += ' stale-orphan';
        else cls += ' stale-aged';
        html += '<span class="' + cls + '">' + escapeHtml(r) + '</span>';
    }
    return html;
}

function sortBy(colIdx) {
    if (sortCol === colIdx) {
        sortAsc = !sortAsc;
    } else {
        sortCol = colIdx;
        sortAsc = true;
    }
    var cols = getColumns();
    var key = cols[colIdx].key;
    allResults.sort(function(a, b) {
        var va = a[key], vb = b[key];
        if (va === undefined || va === null) va = '';
        if (vb === undefined || vb === null) vb = '';
        if (typeof va === 'number' && typeof vb === 'number') {
            return sortAsc ? va - vb : vb - va;
        }
        va = String(va).toLowerCase();
        vb = String(vb).toLowerCase();
        if (va < vb) return sortAsc ? -1 : 1;
        if (va > vb) return sortAsc ? 1 : -1;
        return 0;
    });
    buildTable(getFilteredResults());
}

function filterResults() {
    var filtered = getFilteredResults();
    renderRows(filtered);
}

function getFilteredResults() {
    var filter = document.getElementById('filterInput').value.toLowerCase();
    if (!filter) return allResults;
    var cols = getColumns();
    var filtered = [];
    for (var r = 0; r < allResults.length; r++) {
        var rec = allResults[r];
        var match = false;
        for (var c = 0; c < cols.length; c++) {
            var val = rec[cols[c].key];
            if (val !== undefined && val !== null && String(val).toLowerCase().indexOf(filter) !== -1) {
                match = true;
                break;
            }
        }
        if (match) filtered.push(rec);
    }
    return filtered;
}

function updateRowCount(showing, total) {
    document.getElementById('rowCount').textContent = 'Showing ' + showing + ' of ' + total + ' records';
}

function exportCsv() {
    window.location = '/api/export/csv';
}

function exportHtml() {
    window.location = '/api/export/html';
}

function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}

initApp();
</script>
</body>
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
