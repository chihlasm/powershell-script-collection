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

$resolvedOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
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
                $cases = @()
                Send-Json -Context $context -Body $cases
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
