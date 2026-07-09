#Requires -Version 5.1

<#
.SYNOPSIS
    Starts the MSP Troubleshooting Workbench local browser GUI.

.DESCRIPTION
    Runs a localhost-only PowerShell HTTP server for creating troubleshooting
    cases, running diagnostic checks, and exporting ticket notes.

.PARAMETER Port
    TCP port for the local web server. Default is 8275.

.PARAMETER OutputPath
    Portable data root for cases, exports, logs, and config. Defaults to the script folder.

.PARAMETER NoBrowserOpen
    Do not automatically open the browser.

.EXAMPLE
    .\Start-MSPTroubleshootingWorkbench.ps1

.NOTES
    Run elevated when checks require administrative access.
#>
[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8275,

    [string]$OutputPath = $PSScriptRoot,

    [switch]$NoBrowserOpen
)

function Send-Json {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.HttpListenerContext]$Context,

        [AllowNull()]
        [object]$Body,

        [int]$StatusCode = 200
    )

    if ($null -eq $Body) {
        $json = "null"
    }
    else {
        $json = ConvertTo-Json -InputObject $Body -Depth 10 -Compress
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $Context.Response.StatusCode = $StatusCode
    $Context.Response.ContentType = "application/json; charset=utf-8"
    $Context.Response.ContentLength64 = $bytes.Length
    $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Context.Response.Close()
}

function Send-JsonError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.HttpListenerContext]$Context,

        [Parameter(Mandatory)]
        [string]$Message,

        [int]$StatusCode = 400
    )

    $body = [PSCustomObject]@{
        error = $Message
    }

    Send-Json -Context $Context -Body $body -StatusCode $StatusCode
}

function Send-Html {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.HttpListenerContext]$Context,

        [Parameter(Mandatory)]
        [string]$Html,

        [int]$StatusCode = 200
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Html)
    $Context.Response.StatusCode = $StatusCode
    $Context.Response.ContentType = "text/html; charset=utf-8"
    $Context.Response.ContentLength64 = $bytes.Length
    $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Context.Response.Close()
}

function Send-Text {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.HttpListenerContext]$Context,

        [Parameter(Mandatory)]
        [string]$Text,

        [int]$StatusCode = 200
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $Context.Response.StatusCode = $StatusCode
    $Context.Response.ContentType = "text/plain; charset=utf-8"
    $Context.Response.ContentLength64 = $bytes.Length
    $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Context.Response.Close()
}

function Read-RequestBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.HttpListenerRequest]$Request
    )

    $reader = New-Object System.IO.StreamReader($Request.InputStream, $Request.ContentEncoding)
    try {
        return $reader.ReadToEnd()
    }
    finally {
        $reader.Close()
    }
}

function Read-JsonRequestBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.HttpListenerRequest]$Request
    )

    $rawBody = Read-RequestBody -Request $Request
    if ([string]::IsNullOrWhiteSpace($rawBody)) {
        throw "Request body is required."
    }

    return ($rawBody | ConvertFrom-Json -ErrorAction Stop)
}

function Write-WorkbenchLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("PASS", "WARN", "FAIL", "INFO")]
        [string]$Level = "INFO",

        [string]$LogPath
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$timestamp [$Level] $Message"
    $color = switch ($Level) {
        "PASS" { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        default { "Cyan" }
    }

    Write-Host "[$Level] $Message" -ForegroundColor $color

    if ($LogPath) {
        try {
            Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            Write-Warning "Unable to write workbench log: $($_.Exception.Message)"
        }
    }
}

function New-CaseId {
    "CASE-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss')
}

function Get-CasePath {
    param([string]$CaseId)
    Join-Path (Join-Path $OutputPath 'cases') "$CaseId.json"
}

function Get-ResolvedPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    return [System.IO.Path]::GetFullPath($Path)
}

function Ensure-CaseStore {
    [CmdletBinding()]
    param()

    $caseRoot = Join-Path $OutputPath 'cases'
    if (-not (Test-Path -LiteralPath $caseRoot)) {
        New-Item -ItemType Directory -Path $caseRoot -Force -ErrorAction Stop | Out-Null
    }

    return $caseRoot
}

function Test-WorkbenchCaseId {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$CaseId
    )

    return ($CaseId -and ($CaseId -match '^CASE-\d{8}-\d{6}$'))
}

function Get-WorkbenchCasePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CaseId
    )

    if (-not (Test-WorkbenchCaseId -CaseId $CaseId)) {
        throw "Invalid case id."
    }

    $caseRoot = Ensure-CaseStore
    $casePath = Get-CasePath -CaseId $CaseId
    $trimChars = @([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $resolvedCaseRoot = (Get-ResolvedPath -Path $caseRoot).TrimEnd($trimChars)
    $resolvedCasePath = Get-ResolvedPath -Path $casePath
    $requiredPrefix = $resolvedCaseRoot + [System.IO.Path]::DirectorySeparatorChar

    if (-not $resolvedCasePath.StartsWith($requiredPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Case path must stay inside the case store."
    }

    return $resolvedCasePath
}

function Assert-NewWorkbenchCaseRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Body
    )

    $requiredFields = @('clientName', 'ticketNumber', 'issueType')
    foreach ($field in $requiredFields) {
        if (-not ($Body.PSObject.Properties.Name -contains $field)) {
            throw "clientName, ticketNumber, and issueType are required."
        }

        $value = [string]$Body.$field
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw "clientName, ticketNumber, and issueType are required."
        }
    }
}

function Save-WorkbenchCase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Case,

        [string]$ExpectedCaseId
    )

    if (-not ($Case.PSObject.Properties.Name -contains 'CaseId')) {
        throw "Case id is required."
    }

    $caseId = [string]$Case.CaseId
    if (-not (Test-WorkbenchCaseId -CaseId $caseId)) {
        throw "Invalid case id."
    }

    if ($ExpectedCaseId -and ($caseId -ne $ExpectedCaseId)) {
        throw "Case file does not match requested case id."
    }

    $casePath = Get-WorkbenchCasePath -CaseId $caseId
    $json = $Case | ConvertTo-Json -Depth 10 -ErrorAction Stop
    Set-Content -LiteralPath $casePath -Value $json -Encoding UTF8 -ErrorAction Stop
    return $Case
}

function Get-WorkbenchCase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CaseId
    )

    if (-not (Test-WorkbenchCaseId -CaseId $CaseId)) {
        return $null
    }

    $casePath = Get-WorkbenchCasePath -CaseId $CaseId
    if (-not (Test-Path -LiteralPath $casePath)) {
        return $null
    }

    $case = Get-Content -LiteralPath $casePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if (-not ($case.PSObject.Properties.Name -contains 'CaseId')) {
        throw "Case id is required."
    }

    if ([string]$case.CaseId -ne $CaseId) {
        throw "Case file does not match requested case id."
    }

    return $case
}

function Get-WorkbenchCases {
    [CmdletBinding()]
    param()

    $caseRoot = Ensure-CaseStore
    $cases = @()

    Get-ChildItem -LiteralPath $caseRoot -Filter 'CASE-*.json' -File -ErrorAction Stop | ForEach-Object {
        try {
            $cases += (Get-Content -LiteralPath $_.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
        }
        catch {
            Write-Warning "Unable to read case file '$($_.FullName)': $($_.Exception.Message)"
        }
    }

    return @($cases | Sort-Object -Property CreatedAt -Descending)
}

function New-WorkbenchCase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Body
    )

    Assert-NewWorkbenchCaseRequest -Body $Body

    $caseId = New-CaseId
    while (Test-Path -LiteralPath (Get-WorkbenchCasePath -CaseId $caseId)) {
        Start-Sleep -Seconds 1
        $caseId = New-CaseId
    }

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $case = [PSCustomObject]@{
        CaseId           = $caseId
        ClientName       = $Body.clientName
        TicketNumber     = $Body.ticketNumber
        IssueType        = $Body.issueType
        AffectedUser     = $Body.affectedUser
        AffectedDevice   = $Body.affectedDevice
        TargetPath       = $Body.targetPath
        TargetAddress    = $Body.targetAddress
        CreatedAt        = $timestamp
        UpdatedAt        = $timestamp
        Checks           = @()
        Notes            = @()
        GeneratedSummary = ''
    }

    Save-WorkbenchCase -Case $case
}

$resolvedOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$OutputPath = $resolvedOutputPath
$appPath = Join-Path $PSScriptRoot "app"
$indexPath = Join-Path $appPath "index.html"
$logRoot = Join-Path $resolvedOutputPath "logs"
$logFileName = "workbench_{0}.log" -f (Get-Date -Format "yyyy-MM-dd_HHmmss")
$logPath = Join-Path $logRoot $logFileName
$url = "http://localhost:$Port/"

if (-not (Test-Path -LiteralPath $resolvedOutputPath)) {
    New-Item -ItemType Directory -Path $resolvedOutputPath -Force | Out-Null
}

if (-not (Test-Path -LiteralPath $logRoot)) {
    New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($url)
$script:StopRequested = $false
$script:WorkbenchListener = $listener
$cancelHandler = [ConsoleCancelEventHandler]{
    param($Sender, $EventArgs)

    $EventArgs.Cancel = $true
    $script:StopRequested = $true

    if ($script:WorkbenchListener -and $script:WorkbenchListener.IsListening) {
        $script:WorkbenchListener.Stop()
    }
}

[Console]::add_CancelKeyPress($cancelHandler)

try {
    $listener.Start()
    Write-WorkbenchLog -Message "MSP Troubleshooting Workbench listening at $url" -Level "INFO" -LogPath $logPath
    Write-WorkbenchLog -Message "Output path: $resolvedOutputPath" -Level "INFO" -LogPath $logPath
    Write-Host "Press Ctrl+C to stop the server." -ForegroundColor Cyan

    if (-not $NoBrowserOpen) {
        try {
            Start-Process $url -ErrorAction Stop
        }
        catch {
            Write-WorkbenchLog -Message "Unable to open browser: $($_.Exception.Message)" -Level "WARN" -LogPath $logPath
        }
    }

    while ($listener.IsListening -and (-not $script:StopRequested)) {
        $context = $null

        try {
            $context = $listener.GetContext()
            $request = $context.Request
            $path = $request.Url.AbsolutePath
            $method = $request.HttpMethod

            Write-WorkbenchLog -Message "$method $path" -Level "INFO" -LogPath $logPath

            if ($method -ieq "GET" -and $path -eq "/") {
                if (Test-Path -LiteralPath $indexPath) {
                    $html = Get-Content -LiteralPath $indexPath -Raw
                    Send-Html -Context $context -Html $html
                }
                else {
                    Send-Text -Context $context -Text "Workbench UI not found." -StatusCode 404
                }
            }
            elseif ($method -ieq "GET" -and $path -eq "/api/status") {
                $status = [PSCustomObject]@{
                    appName = "MSP Troubleshooting Workbench"
                    version = "0.1.0"
                    port = $Port
                    outputPath = $resolvedOutputPath
                }

                Send-Json -Context $context -Body $status
            }
            elseif ($method -ieq "GET" -and $path -eq "/api/cases") {
                try {
                    $cases = @(Get-WorkbenchCases)
                    Send-Json -Context $context -Body $cases
                }
                catch {
                    Send-JsonError -Context $context -Message $_.Exception.Message -StatusCode 500
                }
            }
            elseif ($method -ieq "POST" -and $path -eq "/api/cases") {
                $requestIsValid = $false
                $body = $null
                try {
                    $body = Read-JsonRequestBody -Request $request
                    Assert-NewWorkbenchCaseRequest -Body $body
                    $requestIsValid = $true
                }
                catch {
                    Send-JsonError -Context $context -Message $_.Exception.Message -StatusCode 400
                }

                if ($requestIsValid) {
                    try {
                        $case = New-WorkbenchCase -Body $body
                        Send-Json -Context $context -Body $case -StatusCode 201
                    }
                    catch {
                        Send-JsonError -Context $context -Message $_.Exception.Message -StatusCode 500
                    }
                }
            }
            elseif ($method -ieq "GET" -and $path -match '^/api/cases/([^/]+)$') {
                $caseId = [System.Uri]::UnescapeDataString($Matches[1])
                if (-not (Test-WorkbenchCaseId -CaseId $caseId)) {
                    Send-JsonError -Context $context -Message "Invalid case id." -StatusCode 400
                }
                else {
                    try {
                        $case = Get-WorkbenchCase -CaseId $caseId
                        if ($null -eq $case) {
                            Send-JsonError -Context $context -Message "Case not found." -StatusCode 404
                        }
                        else {
                            Send-Json -Context $context -Body $case
                        }
                    }
                    catch {
                        Send-JsonError -Context $context -Message $_.Exception.Message -StatusCode 500
                    }
                }
            }
            elseif ($method -ieq "POST" -and $path -match '^/api/cases/([^/]+)/notes$') {
                $caseId = [System.Uri]::UnescapeDataString($Matches[1])
                if (-not (Test-WorkbenchCaseId -CaseId $caseId)) {
                    Send-JsonError -Context $context -Message "Invalid case id." -StatusCode 400
                }
                else {
                    $caseLoadFailed = $false
                    try {
                        $case = Get-WorkbenchCase -CaseId $caseId
                    }
                    catch {
                        Send-JsonError -Context $context -Message $_.Exception.Message -StatusCode 500
                        $caseLoadFailed = $true
                    }

                    if (-not $caseLoadFailed) {
                        if ($null -eq $case) {
                            Send-JsonError -Context $context -Message "Case not found." -StatusCode 404
                        }
                        else {
                            $requestIsValid = $false
                            $note = $null
                            $timestamp = $null

                            try {
                                $body = Read-JsonRequestBody -Request $request
                                $noteText = $null
                                if ($body.PSObject.Properties.Name -contains "note") {
                                    $noteText = [string]$body.note
                                }
                                elseif ($body.PSObject.Properties.Name -contains "text") {
                                    $noteText = [string]$body.text
                                }

                                if ([string]::IsNullOrWhiteSpace($noteText)) {
                                    throw "Note text is required."
                                }

                                $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                                $note = [PSCustomObject]@{
                                    CreatedAt = $timestamp
                                    Text      = $noteText.Trim()
                                }
                                $requestIsValid = $true
                            }
                            catch {
                                Send-JsonError -Context $context -Message $_.Exception.Message -StatusCode 400
                            }

                            if ($requestIsValid) {
                                try {
                                    $currentNotes = @()
                                    if ($case.PSObject.Properties.Name -contains "Notes") {
                                        if ($null -ne $case.Notes) {
                                            $currentNotes = @($case.Notes)
                                        }
                                    }

                                    $case.Notes = @($currentNotes + $note)
                                    $case.UpdatedAt = $timestamp
                                    Save-WorkbenchCase -Case $case -ExpectedCaseId $caseId | Out-Null
                                    Send-Json -Context $context -Body $case
                                }
                                catch {
                                    Send-JsonError -Context $context -Message $_.Exception.Message -StatusCode 500
                                }
                            }
                        }
                    }
                }
            }
            else {
                Send-Text -Context $context -Text "Not found." -StatusCode 404
            }
        }
        catch [System.Net.HttpListenerException] {
            if (-not $script:StopRequested) {
                Write-WorkbenchLog -Message $_.Exception.Message -Level "WARN" -LogPath $logPath
            }
        }
        catch {
            Write-WorkbenchLog -Message $_.Exception.Message -Level "FAIL" -LogPath $logPath

            if ($context -and $context.Response -and $context.Response.OutputStream.CanWrite) {
                Send-Text -Context $context -Text "Internal server error." -StatusCode 500
            }
        }
    }
}
catch {
    Write-WorkbenchLog -Message $_.Exception.Message -Level "FAIL" -LogPath $logPath
    throw
}
finally {
    if ($listener.IsListening) {
        $listener.Stop()
    }

    $listener.Close()
    [Console]::remove_CancelKeyPress($cancelHandler)
    Write-WorkbenchLog -Message "MSP Troubleshooting Workbench stopped." -Level "INFO" -LogPath $logPath
}
