#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Robocopy Migration -- Browser-based GUI for server-to-server file migrations.

.DESCRIPTION
    Starts a local web server and opens a browser-based interface for:
    - Configuring robocopy migration jobs with presets (Full, Data Only, Mirror)
    - Previewing what will be copied before executing
    - Managing a job queue with sequential or parallel execution
    - Monitoring live progress with log output and stats

.PARAMETER Port
    TCP port for the local web server. Default: 8272

.PARAMETER NoBrowserOpen
    Do not automatically open the browser on launch.

.EXAMPLE
    .\RobocopyMigration-GUI.ps1

.EXAMPLE
    .\RobocopyMigration-GUI.ps1 -Port 9090 -NoBrowserOpen

.NOTES
    Must run as Administrator for permission-preserving copies.
    Press Ctrl+C in the PowerShell window to stop the server.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1024, 65535)]
    [int]$Port = 8272,

    [Parameter()]
    [switch]$NoBrowserOpen
)

$ErrorActionPreference = 'Continue'
$baseUrl = "http://localhost:$Port/"

# Default log directory lives next to this script so log files travel with it.
$script:scriptRoot = $PSScriptRoot
if (-not $script:scriptRoot) { $script:scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
$script:defaultLogDir = Join-Path $script:scriptRoot 'Logs'

# --- Drive Mapping Cache ---
# Elevated PowerShell can't see mapped drives -- enumerate via WMI and net use

$script:driveMappings = @{}
try {
    Get-WmiObject -Class Win32_MappedLogicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
        $script:driveMappings[$_.DeviceID.TrimEnd(':').ToUpper()] = $_.ProviderName
    }
    $netUse = net use 2>$null | Where-Object { $_ -match '^\s*(OK|Disconnected|Unavailable)\s+([A-Z]:)\s+(\\\\[^\s]+)' }
    foreach ($line in $netUse) {
        if ($line -match '^\s*(?:OK|Disconnected|Unavailable)\s+([A-Z]:)\s+(\\\\[^\s]+)') {
            $letter = $Matches[1].TrimEnd(':').ToUpper()
            if (-not $script:driveMappings.ContainsKey($letter)) {
                $script:driveMappings[$letter] = $Matches[2]
            }
        }
    }
    if ($script:driveMappings.Count -gt 0) {
        Write-Host "[INFO] Found $($script:driveMappings.Count) mapped drive(s): $(($script:driveMappings.GetEnumerator() | ForEach-Object { "$($_.Key): -> $($_.Value)" }) -join ', ')" -ForegroundColor Cyan
    }
}
catch {
    Write-Host "[WARN] Could not enumerate mapped drives: $_" -ForegroundColor Yellow
}

# --- Job Queue State ---
$script:jobs = [ordered]@{}
$script:jobLogBuffers = @{}
$script:jobProcesses = @{}
$script:jobStats = @{}
$script:queueMode = 'sequential'
$script:jobLogFiles = @{}
$script:jobLogFilePos = @{}

# --- Helper Functions ---

function Send-Json {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [object]$Data
    )
    if ($null -eq $Data) { $Data = @() }
    $json = ConvertTo-Json -InputObject $Data -Depth 10 -Compress
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

function Read-RequestBody {
    param([System.Net.HttpListenerRequest]$Request)
    $reader = [System.IO.StreamReader]::new($Request.InputStream, $Request.ContentEncoding)
    $json = $reader.ReadToEnd()
    $reader.Close()
    return $json | ConvertFrom-Json
}

function Resolve-MappedDrive {
    param([string]$Path)
    if ($Path -match '^([A-Za-z]):\\') {
        $letter = $Matches[1]
        $mapping = $script:driveMappings[$letter.ToUpper()]
        if ($mapping) {
            return $Path -replace "^$letter`:\\", "$mapping\"
        }
    }
    return $Path
}

function Resolve-LogFilePath {
    # Turn the "Save log to file" input into an absolute .log path.
    # Rules:
    #   empty            -> default dir + auto name
    #   path ending \    -> that dir + auto name
    #   existing dir     -> that dir + auto name
    #   *.log / *.txt    -> use as-is
    #   anything else    -> treat as directory, append auto name
    param(
        [string]$UserInput,
        [string]$Source,
        [string]$Destination,
        [string]$Preset
    )

    function _Sanitize {
        param([string]$Name)
        if (-not $Name) { return 'root' }
        # Strip drive letters, UNC prefixes, and any path separators
        $leaf = Split-Path -Leaf $Name.TrimEnd('\','/')
        if (-not $leaf) { $leaf = ($Name -replace '[\\/]', '_').Trim('_') }
        # Kill characters illegal in filenames
        return ($leaf -replace '[<>:"/\\|?*]', '_')
    }

    $srcLeaf = _Sanitize $Source
    $dstLeaf = _Sanitize $Destination
    $stamp = (Get-Date).ToString('yyyy-MM-dd_HHmmss')
    $autoName = "${srcLeaf}_to_${dstLeaf}_${Preset}_${stamp}.log"

    $trimmed = $null
    if ($UserInput) { $trimmed = $UserInput.Trim() }

    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        return (Join-Path $script:defaultLogDir $autoName)
    }

    # Explicit directory: ends with a slash
    if ($trimmed -match '[\\/]$') {
        return (Join-Path $trimmed.TrimEnd('\','/') $autoName)
    }

    # Already-existing directory
    if (Test-Path -LiteralPath $trimmed -PathType Container) {
        return (Join-Path $trimmed $autoName)
    }

    # Looks like a full filename
    if ($trimmed -match '\.(log|txt)$') {
        return $trimmed
    }

    # Fallback: treat as a directory that doesn't exist yet
    return (Join-Path $trimmed $autoName)
}

# --- API Endpoint Functions ---

function Get-Drives {
    param([System.Net.HttpListenerResponse]$Response)

    $drives = [System.Collections.Generic.List[object]]::new()
    Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root } | ForEach-Object {
        $usedGB = [math]::Round($_.Used / 1GB, 1)
        $freeGB = [math]::Round($_.Free / 1GB, 1)
        $driveLabel = $_.Name + ':\'
        if ($_.Description) { $driveLabel = $_.Name + ':\' + ' - ' + $_.Description }
        $drives.Add([PSCustomObject]@{
            name     = $_.Name
            root     = $_.Root
            label    = $driveLabel
            usedGB   = $usedGB
            freeGB   = $freeGB
            provider = 'FileSystem'
            isMapped = $false
        })
    }

    foreach ($letter in $script:driveMappings.Keys) {
        $existing = $drives | Where-Object { $_.name -eq $letter }
        if (-not $existing) {
            $unc = $script:driveMappings[$letter]
            $drives.Add([PSCustomObject]@{
                name     = $letter
                root     = $letter + ':\'
                label    = "$letter ($unc)"
                usedGB   = 0
                freeGB   = 0
                provider = 'FileSystem'
                isMapped = $true
                uncPath  = $unc
            })
        }
    }

    Send-Json $Response @($drives)
}

function Get-Children {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $folderPath = Resolve-MappedDrive $Request.QueryString['path']
    if (-not $folderPath -or -not (Test-Path $folderPath -PathType Container)) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Invalid or missing path parameter" }
        return
    }

    try {
        $items = Get-ChildItem -Path $folderPath -Directory -Force -ErrorAction Stop
    }
    catch [System.UnauthorizedAccessException] {
        $Response.StatusCode = 403
        Send-Json $Response @{ error = "Access denied to '$folderPath'." }
        return
    }
    catch {
        $Response.StatusCode = 500
        Send-Json $Response @{ error = "Failed to list '$folderPath': $($_.Exception.Message)" }
        return
    }

    $children = @($items | ForEach-Object {
        $hasChildren = $false
        try {
            $hasChildren = @(Get-ChildItem -Path $_.FullName -Directory -Force -ErrorAction SilentlyContinue | Select-Object -First 1).Count -gt 0
        } catch {}

        [PSCustomObject]@{
            name        = $_.Name
            path        = $_.FullName
            hasChildren = $hasChildren
        }
    })
    if ($null -eq $children) { $children = @() }
    Send-Json $Response $children
}

function Invoke-Validate {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $body = Read-RequestBody $Request
    $source = Resolve-MappedDrive $body.source
    $destination = Resolve-MappedDrive $body.destination

    $sourceExists = $false
    $destWritable = $false
    $error_msg = $null

    if ($source) {
        $sourceExists = Test-Path $source -PathType Container
    }
    if (-not $sourceExists) {
        $error_msg = "Source path does not exist or is not accessible"
    }

    if ($destination -and $null -eq $error_msg) {
        $destParent = Split-Path -Path $destination -Parent
        if ($destParent -and (Test-Path $destParent -PathType Container)) {
            $destWritable = $true
        } elseif (Test-Path $destination -PathType Container) {
            $destWritable = $true
        } else {
            # Try to reach the root (for UNC paths like \\server\share)
            try {
                $destWritable = Test-Path (Split-Path $destination -Qualifier -ErrorAction SilentlyContinue) -ErrorAction SilentlyContinue
            } catch {
                $destWritable = $false
            }
            if (-not $destWritable) {
                $error_msg = "Destination parent path is not reachable"
            }
        }
    }

    Send-Json $Response @{
        valid        = ($sourceExists -and $destWritable)
        sourceExists = $sourceExists
        destWritable = $destWritable
        error        = $error_msg
    }
}

function Build-RobocopyArgs {
    param(
        [string]$Source,
        [string]$Destination,
        [string]$Preset,
        [object]$Overrides
    )

    $roboArgList = [System.Collections.Generic.List[string]]::new()
    $roboArgList.Add("`"$Source`"")
    $roboArgList.Add("`"$Destination`"")

    # Preset-specific flags
    switch ($Preset) {
        'mirror' {
            $roboArgList.Add('/MIR')
            $roboArgList.Add('/COPY:DATSO')
        }
        'incremental' {
            $roboArgList.Add('/S')
            $roboArgList.Add('/E')
            $roboArgList.Add('/COPY:DATSO')
            $roboArgList.Add('/XO')
            $roboArgList.Add('/XX')
        }
        'dataonly' {
            $roboArgList.Add('/S')
            $roboArgList.Add('/E')
            $roboArgList.Add('/COPY:DAT')
        }
        default {
            # 'full' -- Full Migration
            $roboArgList.Add('/S')
            $roboArgList.Add('/E')
            $roboArgList.Add('/COPY:DATSO')
        }
    }

    $roboArgList.Add('/DCOPY:DAT')
    $roboArgList.Add('/NP')
    $roboArgList.Add('/NDL')
    $roboArgList.Add('/V')
    $roboArgList.Add('/BYTES')

    # Retries and wait
    $retries = 3
    $wait = 5
    if ($Overrides -and $null -ne $Overrides.retries) { $retries = $Overrides.retries }
    if ($Overrides -and $null -ne $Overrides.waitTime) { $wait = $Overrides.waitTime }
    $roboArgList.Add("/R:$retries")
    $roboArgList.Add("/W:$wait")

    # Advanced overrides
    if ($Overrides) {
        # Backup mode: /B uses SeBackupPrivilege to bypass file ACLs (fixes Error 5).
        # /ZB tries normal mode first, falls back to backup mode per file.
        # These are mutually exclusive; /B wins if both set.
        if ($Overrides.backupMode -eq 'b') {
            $roboArgList.Add('/B')
        }
        elseif ($Overrides.backupMode -eq 'zb') {
            $roboArgList.Add('/ZB')
        }
        if ($Overrides.ipg -and [int]$Overrides.ipg -gt 0) {
            $roboArgList.Add("/IPG:$($Overrides.ipg)")
        }
        if ($Overrides.mtEnabled -and $Overrides.mtCount) {
            $roboArgList.Add("/MT:$($Overrides.mtCount)")
        }
        if ($Overrides.excludeFiles) {
            $patterns = ($Overrides.excludeFiles -split '\s+') | Where-Object { $_ }
            if ($patterns) {
                $roboArgList.Add('/XF')
                foreach ($p in $patterns) { $roboArgList.Add($p) }
            }
        }
        if ($Overrides.excludeDirs) {
            $patterns = ($Overrides.excludeDirs -split '\s+') | Where-Object { $_ }
            if ($patterns) {
                $roboArgList.Add('/XD')
                foreach ($p in $patterns) { $roboArgList.Add($p) }
            }
        }
    }

    # Always log to a file. If the user set a resolved path on the overrides,
    # use it; otherwise the caller (Invoke-RunJob) will set it before this runs.
    if ($Overrides -and $Overrides.resolvedLogFilePath) {
        $roboArgList.Add("/LOG:`"$($Overrides.resolvedLogFilePath)`"")
        $roboArgList.Add('/TEE')
    }

    return ,$roboArgList
}

function Invoke-Preview {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $body = Read-RequestBody $Request
    $source = Resolve-MappedDrive $body.source
    $destination = Resolve-MappedDrive $body.destination
    $preset = 'full'
    if ($body.preset) { $preset = $body.preset }

    if (-not $source -or -not (Test-Path $source -PathType Container)) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Invalid source path" }
        return
    }

    try {
        # Build args with /L for list-only mode
        $destArg = $destination
        if (-not $destArg) { $destArg = 'NUL' }
        $roboArgs = Build-RobocopyArgs -Source $source -Destination $destArg -Preset $preset -Overrides $body.overrides
        $roboArgs.Add('/L')

        $argString = $roboArgs -join ' '
        $output = cmd /c "robocopy $argString" 2>&1
        $summary = ($output | Out-String).Trim()

        # Parse summary lines
        $dirs = 0; $files = 0; $bytes = 0
        if ($summary -match 'Dirs\s*:\s*(\d+)') { $dirs = [int]$Matches[1] }
        if ($summary -match 'Files\s*:\s*(\d+)') { $files = [int]$Matches[1] }
        if ($summary -match 'Bytes\s*:\s*(\d+)') { $bytes = [long]$Matches[1] }

        $sizeDisplay = "$bytes B"
        if ($bytes -gt 1GB) { $sizeDisplay = "$([math]::Round($bytes / 1GB, 2)) GB" }
        elseif ($bytes -gt 1MB) { $sizeDisplay = "$([math]::Round($bytes / 1MB, 1)) MB" }
        elseif ($bytes -gt 1KB) { $sizeDisplay = "$([math]::Round($bytes / 1KB, 0)) KB" }

        Send-Json $Response @{
            dirs        = $dirs
            files       = $files
            bytes       = $bytes
            sizeDisplay = $sizeDisplay
            rawSummary  = $summary
        }
    }
    catch {
        $Response.StatusCode = 500
        Send-Json $Response @{ error = "Preview failed: $($_.Exception.Message)" }
    }
}

function Invoke-AddJob {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $body = Read-RequestBody $Request
    $source = $body.source
    $destination = $body.destination
    $preset = 'full'
    if ($body.preset) { $preset = $body.preset }
    $overrides = $body.overrides

    if (-not $source -or -not $destination) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Source and destination are required" }
        return
    }

    $id = [guid]::NewGuid().ToString()
    $job = [PSCustomObject]@{
        id          = $id
        source      = $source
        destination = $destination
        preset      = $preset
        overrides   = $overrides
        status      = 'pending'
        exitCode    = $null
        exitMeaning = $null
        createdAt   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        startedAt   = $null
        finishedAt  = $null
    }

    $script:jobs[$id] = $job
    $script:jobLogBuffers[$id] = [System.Collections.Generic.List[string]]::new()
    $script:jobStats[$id] = @{
        filesCopied    = 0
        filesSkipped   = 0
        filesFailed    = 0
        bytesCopied    = 0
        elapsedSeconds = 0
        currentFile    = ''
        status         = 'pending'
    }

    Write-Host "[INFO] Job added: $id ($preset) $source -> $destination" -ForegroundColor Cyan

    Send-Json $Response $job
}

function Get-JobList {
    param([System.Net.HttpListenerResponse]$Response)

    $jobArray = @($script:jobs.Values)
    Send-Json $Response $jobArray
}

function Invoke-CancelJob {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response,
        [string]$JobId
    )

    if (-not $script:jobs.Contains($JobId)) {
        $Response.StatusCode = 404
        Send-Json $Response @{ error = "Job not found" }
        return
    }

    $job = $script:jobs[$JobId]
    if ($job.status -ne 'running') {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Job is not running" }
        return
    }

    if ($script:jobProcesses.ContainsKey($JobId)) {
        try {
            $proc = $script:jobProcesses[$JobId]
            if (-not $proc.HasExited) {
                $proc.Kill()
            }
        } catch {}
        $script:jobProcesses.Remove($JobId)
    }

    $job.status = 'cancelled'
    $job.finishedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $script:jobStats[$JobId].status = 'cancelled'

    Write-Host "[WARN] Job cancelled: $JobId" -ForegroundColor Yellow

    Send-Json $Response $job
}

function Remove-MigrationJob {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response,
        [string]$JobId
    )

    if (-not $script:jobs.Contains($JobId)) {
        $Response.StatusCode = 404
        Send-Json $Response @{ error = "Job not found" }
        return
    }

    $job = $script:jobs[$JobId]
    if ($job.status -eq 'running') {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Cannot remove a running job. Cancel it first." }
        return
    }

    $script:jobs.Remove($JobId)
    $script:jobLogBuffers.Remove($JobId)
    $script:jobProcesses.Remove($JobId)
    $script:jobStats.Remove($JobId)

    Send-Json $Response @{ removed = $true }
}

function Get-JobLog {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response,
        [string]$JobId
    )

    if (-not $script:jobs.Contains($JobId)) {
        $Response.StatusCode = 404
        Send-Json $Response @{ error = "Job not found" }
        return
    }

    $fromIndex = 0
    $fromParam = $Request.QueryString['from']
    if ($fromParam) {
        $fromIndex = [int]$fromParam
    }

    $buffer = $script:jobLogBuffers[$JobId]
    $newLines = @()
    if ($buffer -and $fromIndex -lt $buffer.Count) {
        $newLines = @($buffer.GetRange($fromIndex, $buffer.Count - $fromIndex))
    }

    $stats = $script:jobStats[$JobId]
    $job = $script:jobs[$JobId]
    $totalLines = 0
    if ($buffer) { $totalLines = $buffer.Count }

    Send-Json $Response @{
        lines      = $newLines
        fromIndex  = $fromIndex
        totalLines = $totalLines
        stats      = $stats
        status     = $job.status
    }
}

function Start-RobocopyJob {
    param([string]$JobId)

    $job = $script:jobs[$JobId]
    $source = Resolve-MappedDrive $job.source
    $destination = Resolve-MappedDrive $job.destination

    $roboArgs = Build-RobocopyArgs -Source $source -Destination $destination -Preset $job.preset -Overrides $job.overrides
    $argString = $roboArgs -join ' '

    # Ensure destination parent exists
    $destParent = Split-Path -Path $destination -Parent
    if ($destParent -and -not (Test-Path $destParent -PathType Container)) {
        try {
            New-Item -Path $destParent -ItemType Directory -Force | Out-Null
        } catch {}
    }

    # Ensure log file directory exists if specified
    if ($job.overrides -and $job.overrides.logFilePath) {
        $logDir = Split-Path -Path $job.overrides.logFilePath -Parent
        if ($logDir -and -not (Test-Path $logDir -PathType Container)) {
            try { New-Item -Path $logDir -ItemType Directory -Force | Out-Null } catch {}
        }
    }

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo.FileName = 'robocopy.exe'
    $proc.StartInfo.Arguments = $argString
    $proc.StartInfo.UseShellExecute = $false
    $proc.StartInfo.RedirectStandardOutput = $true
    $proc.StartInfo.RedirectStandardError = $true
    $proc.StartInfo.CreateNoWindow = $true

    $job.status = 'running'
    $job.startedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $script:jobStats[$JobId].status = 'running'

    $script:jobLogBuffers[$JobId].Add("=== Robocopy Migration Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===")
    $script:jobLogBuffers[$JobId].Add("Command: robocopy $argString")
    $script:jobLogBuffers[$JobId].Add("")

    try {
        $proc.Start() | Out-Null
        # Output is read synchronously in Update-RunningJobs via Peek()/ReadLine()
        $script:jobProcesses[$JobId] = $proc

        Write-Host "[INFO] Job started: $JobId - robocopy $argString" -ForegroundColor Cyan
    }
    catch {
        $job.status = 'failed'
        $job.finishedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $script:jobStats[$JobId].status = 'failed'
        $script:jobLogBuffers[$JobId].Add("ERROR: Failed to start robocopy: $($_.Exception.Message)")
        Write-Host "[FAIL] Job failed to start: $JobId - $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Invoke-RunJob {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response,
        [string]$JobId
    )

    if (-not $script:jobs.Contains($JobId)) {
        $Response.StatusCode = 404
        Send-Json $Response @{ error = "Job not found" }
        return
    }

    $job = $script:jobs[$JobId]
    if ($job.status -ne 'pending') {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Job is not pending (status: $($job.status))" }
        return
    }

    $source = Resolve-MappedDrive $job.source
    $destination = Resolve-MappedDrive $job.destination

    # Resolve the log file path (applies defaults, expands dir-only inputs,
    # auto-names if user gave nothing or just a directory) and make sure the
    # parent directory exists so robocopy doesn't fail writing the log.
    $userLogInput = $null
    if ($job.overrides -and $job.overrides.logFilePath) { $userLogInput = $job.overrides.logFilePath }
    $resolvedLog = Resolve-LogFilePath -UserInput $userLogInput -Source $job.source -Destination $job.destination -Preset $job.preset
    $logParent = Split-Path -Path $resolvedLog -Parent
    if ($logParent -and -not (Test-Path -LiteralPath $logParent -PathType Container)) {
        try { New-Item -Path $logParent -ItemType Directory -Force | Out-Null }
        catch { Write-Host "[WARN] Could not create log directory '$logParent': $_" -ForegroundColor Yellow }
    }
    # Attach the resolved path so Build-RobocopyArgs picks it up via /LOG + /TEE.
    if ($job.overrides) {
        $job.overrides | Add-Member -NotePropertyName resolvedLogFilePath -NotePropertyValue $resolvedLog -Force
    }
    else {
        $job | Add-Member -NotePropertyName overrides -NotePropertyValue ([PSCustomObject]@{ resolvedLogFilePath = $resolvedLog }) -Force
    }
    $job | Add-Member -NotePropertyName logFilePath -NotePropertyValue $resolvedLog -Force

    $roboArgs = Build-RobocopyArgs -Source $source -Destination $destination -Preset $job.preset -Overrides $job.overrides
    $argString = $roboArgs -join ' '

    # Ensure destination parent exists before launching robocopy.
    $destParent = Split-Path -Path $destination -Parent
    if ($destParent -and -not (Test-Path -LiteralPath $destParent -PathType Container)) {
        try { New-Item -Path $destParent -ItemType Directory -Force | Out-Null } catch {}
    }

    # Write robocopy output to a temp file so we can tail it without blocking
    $logTempFile = Join-Path $env:TEMP "robomig_$JobId.log"
    $script:jobLogFiles[$JobId] = $logTempFile
    $script:jobLogFilePos[$JobId] = 0

    $job.status = 'running'
    $job.startedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $script:jobStats[$JobId].status = 'running'

    $script:jobLogBuffers[$JobId].Add("=== Robocopy Migration Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===")
    $script:jobLogBuffers[$JobId].Add("Log file: $resolvedLog")
    $script:jobLogBuffers[$JobId].Add("Command: robocopy $argString")
    $script:jobLogBuffers[$JobId].Add("")

    Write-Host "[INFO] Job running: $JobId - log: $resolvedLog" -ForegroundColor Cyan

    try {
        # Launch robocopy as a background process, redirect output to temp file
        $proc = Start-Process -FilePath 'cmd.exe' -ArgumentList "/c robocopy $argString > `"$logTempFile`" 2>&1" -WindowStyle Hidden -PassThru
        $script:jobProcesses[$JobId] = $proc

        # Return immediately -- Update-RunningJobs will monitor progress
        Send-Json $Response @{ started = $true; id = $JobId }
    }
    catch {
        $job.status = 'failed'
        $job.finishedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $script:jobStats[$JobId].status = 'failed'
        $script:jobLogBuffers[$JobId].Add("ERROR: $($_.Exception.Message)")
        Write-Host "[FAIL] Job failed: $JobId - $($_.Exception.Message)" -ForegroundColor Red
        $Response.StatusCode = 500
        Send-Json $Response @{ error = "Job failed: $($_.Exception.Message)" }
    }
}

function Update-JobStats {
    param(
        [string]$JobId,
        [string]$Line
    )

    $stats = $script:jobStats[$JobId]

    # Robocopy verbose output patterns:
    # New File: lines contain "New File" and the size + filename
    # Newer: similar pattern
    # *EXTRA File: file exists at dest but not source
    # same: file is identical
    # Older/Changed: various statuses

    if ($Line -match '^\s*(New File|Newer|Older|Changed)\s+(\d+)\s+(.+)$') {
        $stats.filesCopied++
        $stats.bytesCopied += [long]$Matches[2]
        $stats.currentFile = $Matches[3].Trim()
    }
    elseif ($Line -match '^\s*same\s+\d+\s+(.+)$') {
        $stats.filesSkipped++
    }
    elseif ($Line -match '^\s*\*EXTRA File\s+') {
        $stats.filesSkipped++
    }
    elseif ($Line -match 'ERROR\s') {
        $stats.filesFailed++
    }
}

function Update-RunningJobs {
    foreach ($id in @($script:jobProcesses.Keys)) {
        $proc = $script:jobProcesses[$id]
        $job = $script:jobs[$id]

        if (-not $job -or $job.status -ne 'running') { continue }

        # Read new lines from the temp log file
        $logFile = $script:jobLogFiles[$id]
        if ($logFile -and (Test-Path $logFile)) {
            try {
                $fs = [System.IO.FileStream]::new($logFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                $pos = $script:jobLogFilePos[$id]
                if ($fs.Length -gt $pos) {
                    $fs.Position = $pos
                    $reader = [System.IO.StreamReader]::new($fs)
                    $newContent = $reader.ReadToEnd()
                    $script:jobLogFilePos[$id] = $fs.Length
                    $reader.Close()

                    foreach ($line in ($newContent -split "`n")) {
                        $trimmed = $line.TrimEnd("`r")
                        if ($trimmed) {
                            $script:jobLogBuffers[$id].Add($trimmed)
                            Update-JobStats -JobId $id -Line $trimmed
                        }
                    }
                }
                else {
                    $fs.Close()
                }
            } catch {}
        }

        # Update elapsed time
        if ($job.startedAt) {
            $started = [datetime]::ParseExact($job.startedAt, 'yyyy-MM-dd HH:mm:ss', $null)
            $script:jobStats[$id].elapsedSeconds = [int]((Get-Date) - $started).TotalSeconds
        }

        # Check if process has exited
        if ($proc.HasExited) {
            # Read any final output from the log file
            Start-Sleep -Milliseconds 200
            if ($logFile -and (Test-Path $logFile)) {
                try {
                    $fs = [System.IO.FileStream]::new($logFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                    $pos = $script:jobLogFilePos[$id]
                    if ($fs.Length -gt $pos) {
                        $fs.Position = $pos
                        $reader = [System.IO.StreamReader]::new($fs)
                        $newContent = $reader.ReadToEnd()
                        $reader.Close()
                        foreach ($line in ($newContent -split "`n")) {
                            $trimmed = $line.TrimEnd("`r")
                            if ($trimmed) {
                                $script:jobLogBuffers[$id].Add($trimmed)
                                Update-JobStats -JobId $id -Line $trimmed
                            }
                        }
                    }
                    else { $fs.Close() }
                } catch {}

                # Clean up temp file
                try { Remove-Item $logFile -Force -ErrorAction SilentlyContinue } catch {}
            }

            $exitCode = $proc.ExitCode
            $job.exitCode = $exitCode
            # Robocopy exit codes are bit flags:
            #   1  = files copied, 2 = extras detected, 4 = mismatches,
            #   8  = errors (some files could not be copied),
            #   16 = fatal usage/init error
            if ($exitCode -eq 0) {
                $job.exitMeaning = 'No files copied - source and destination are identical'
            }
            elseif ($exitCode -ge 16) {
                $job.exitMeaning = "Fatal error (code $exitCode) - no files were copied"
            }
            else {
                $parts = @()
                if ($exitCode -band 1) { $parts += 'files copied' }
                if ($exitCode -band 2) { $parts += 'extra files at destination' }
                if ($exitCode -band 4) { $parts += 'mismatched files' }
                if ($exitCode -band 8) { $parts += 'errors (some files could not be copied)' }
                $job.exitMeaning = "Exit $exitCode - " + ($parts -join ' + ')
            }
            $job.finishedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

            if ($exitCode -lt 4) {
                $job.status = 'complete'
                Write-Host "[PASS] Job complete: $id (exit $exitCode - $($job.exitMeaning))" -ForegroundColor Green
            }
            elseif ($exitCode -lt 8) {
                $job.status = 'warning'
                Write-Host "[WARN] Job completed with warnings: $id (exit $exitCode - $($job.exitMeaning))" -ForegroundColor Yellow
            }
            else {
                $job.status = 'failed'
                Write-Host "[FAIL] Job failed: $id (exit $exitCode - $($job.exitMeaning))" -ForegroundColor Red
            }

            $script:jobStats[$id].status = $job.status
            $script:jobLogBuffers[$id].Add("")
            $script:jobLogBuffers[$id].Add("=== Finished: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Exit code $exitCode ($($job.exitMeaning)) ===")

            $script:jobProcesses.Remove($id)
            $script:jobLogFiles.Remove($id)
            $script:jobLogFilePos.Remove($id)
        }
    }
}

# --- Route Dispatcher ---

function Invoke-Route {
    param(
        [System.Net.HttpListenerContext]$Context
    )

    $request = $Context.Request
    $response = $Context.Response
    $path = $request.Url.AbsolutePath
    $method = $request.HttpMethod

    try {
        switch -Regex ("$method $path") {
            '^GET /$'                { Send-Html $response }
            '^GET /api/drives$'      { Get-Drives $response }
            '^GET /api/children$'    { Get-Children $request $response }
            '^POST /api/validate$'   { Invoke-Validate $request $response }
            '^POST /api/preview$'    { Invoke-Preview $request $response }
            '^POST /api/job/add$'    { Invoke-AddJob $request $response }
            '^GET /api/job/list$'    { Get-JobList $response }
            '^POST /api/job/run/' {
                $jobId = $path -replace '^/api/job/run/', ''
                Invoke-RunJob $request $response $jobId
            }
            '^POST /api/job/cancel/' {
                $jobId = $path -replace '^/api/job/cancel/', ''
                Invoke-CancelJob $request $response $jobId
            }
            '^GET /api/job/.+/log$' {
                $jobId = ($path -replace '^/api/job/' -replace '/log$', '')
                Get-JobLog $request $response $jobId
            }
            '^DELETE /api/job/' {
                $jobId = $path -replace '^/api/job/', ''
                Remove-MigrationJob $request $response $jobId
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

# --- HTML Content ---

$script:htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Robocopy Migration</title>
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
    --danger-hover: #c0392b;
    --shadow: rgba(0,0,0,0.3);
}
body.light {
    --bg: #f5f5f5;
    --bg-card: #ffffff;
    --bg-hover: #e8ecf0;
    --bg-input: #ffffff;
    --text: #2c3e50;
    --text-muted: #7f8c8d;
    --accent: #3498db;
    --accent-hover: #2980b9;
    --border: #dce1e8;
    --shadow: rgba(0,0,0,0.1);
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: var(--bg); color: var(--text); height: 100vh; display: flex; flex-direction: column; overflow: hidden; }

/* Topbar */
.topbar { display: flex; align-items: center; justify-content: space-between; padding: 8px 16px; background: var(--bg-card); border-bottom: 1px solid var(--border); flex-shrink: 0; }
.topbar h1 { font-size: 14px; font-weight: 600; color: var(--accent); letter-spacing: 0.03em; }
.topbar-right { display: flex; align-items: center; gap: 8px; }

/* Main content */
.main-content { flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 16px; }

/* Panel */
.panel { background: var(--bg-card); border-radius: 6px; border: 1px solid var(--border); padding: 16px; }
.panel-title { font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 12px; }

/* Builder rows */
.builder-row { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
.builder-row label { width: 100px; flex-shrink: 0; font-size: 13px; color: var(--text-muted); }
.builder-row input, .builder-row select { flex: 1; background: var(--bg-input); border: 1px solid var(--border); border-radius: 4px; padding: 6px 10px; color: var(--text); font-size: 13px; outline: none; }
.builder-row input:focus, .builder-row select:focus { border-color: var(--accent); }
.builder-row select option { background: var(--bg-card); }
.builder-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border); }

/* Advanced section */
details summary { cursor: pointer; font-size: 13px; color: var(--text-muted); padding: 8px 0; user-select: none; list-style: none; display: flex; align-items: center; gap: 6px; }
details summary::-webkit-details-marker { display: none; }
details summary::before { content: '▶'; font-size: 10px; transition: transform 0.15s; display: inline-block; }
details[open] summary::before { transform: rotate(90deg); }
.advanced-grid { display: grid; grid-template-columns: 140px 1fr; gap: 8px 12px; padding: 12px 0; align-items: center; }
.advanced-grid label { font-size: 12px; color: var(--text-muted); }
.advanced-grid input[type="text"], .advanced-grid input[type="number"] { background: var(--bg-input); border: 1px solid var(--border); border-radius: 4px; padding: 5px 8px; color: var(--text); font-size: 12px; outline: none; width: 100%; }
.advanced-grid input:focus { border-color: var(--accent); }
.advanced-grid .checkbox-row { display: flex; align-items: center; gap: 8px; }
.advanced-grid input[type="checkbox"] { accent-color: var(--accent); width: 14px; height: 14px; cursor: pointer; }

/* Buttons */
.btn { padding: 6px 14px; border-radius: 4px; font-size: 13px; font-weight: 500; cursor: pointer; border: none; transition: all 0.15s; font-family: inherit; }
.btn-primary { background: var(--accent); color: #fff; }
.btn-primary:hover:not(:disabled) { background: var(--accent-hover); }
.btn-secondary { background: transparent; border: 1px solid var(--accent); color: var(--accent); }
.btn-secondary:hover:not(:disabled) { background: var(--bg-hover); }
.btn-danger { background: var(--danger); color: #fff; }
.btn-danger:hover:not(:disabled) { background: var(--danger-hover); }
.btn-icon { background: transparent; border: none; color: var(--text-muted); cursor: pointer; padding: 4px 8px; font-size: 14px; border-radius: 3px; transition: color 0.15s; }
.btn-icon:hover { color: var(--text); }
.btn:disabled { opacity: 0.5; cursor: not-allowed; }

/* Warning elements */
.warning-badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; background: var(--danger); color: #fff; margin-left: 8px; vertical-align: middle; }
.warning-banner { padding: 8px 12px; background: rgba(231, 76, 60, 0.15); border: 1px solid var(--danger); border-radius: 4px; font-size: 12px; color: var(--danger); margin-bottom: 8px; }
.warning-banner-orange { padding: 8px 12px; background: rgba(243, 156, 18, 0.15); border: 1px solid var(--warning); border-radius: 4px; font-size: 12px; color: var(--warning); margin-bottom: 8px; }

/* Preview panel */
.preview-panel { background: var(--bg-card); border-radius: 6px; border: 1px solid var(--border); padding: 16px; }
.preview-stats { display: flex; gap: 24px; padding: 12px 0; }
.preview-stat { text-align: center; }
.preview-stat .value { font-size: 20px; font-weight: 700; color: var(--accent); }
.preview-stat .label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }

/* Queue header */
.queue-header { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
.queue-header .panel-title { margin-bottom: 0; flex: 1; }

/* Queue table */
.queue-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.queue-table th { text-align: left; padding: 8px 10px; font-weight: 600; color: var(--text-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); }
.queue-table td { padding: 8px 10px; border-bottom: 1px solid var(--border); }
.queue-table tr.job-row:hover { background: var(--bg-hover); cursor: pointer; }
.queue-table .path-cell { max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: 'Consolas', monospace; font-size: 12px; }

/* Status badges */
.status { display: inline-flex; align-items: center; gap: 4px; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; }
.status-pending { background: rgba(139, 149, 165, 0.15); color: var(--text-muted); }
.status-running { background: rgba(93, 173, 226, 0.15); color: var(--accent); animation: pulse 1.5s ease-in-out infinite; }
.status-complete { background: rgba(46, 204, 113, 0.15); color: var(--success); }
.status-warning { background: rgba(243, 156, 18, 0.15); color: var(--warning); }
.status-failed { background: rgba(231, 76, 60, 0.15); color: var(--danger); }
.status-cancelled { background: rgba(139, 149, 165, 0.15); color: var(--text-muted); text-decoration: line-through; }

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}

/* Log row */
.job-log-row td { padding: 0; }
.job-log-container { padding: 12px; background: var(--bg-hover); border-bottom: 1px solid var(--border); }
.stats-bar { display: flex; gap: 16px; padding: 8px 12px; background: var(--bg); border-radius: 4px; margin-bottom: 8px; font-size: 12px; flex-wrap: wrap; }
.stat-item { display: flex; gap: 4px; align-items: center; }
.stat-value { font-weight: 600; font-family: 'Consolas', monospace; }
.stat-label { color: var(--text-muted); }
.job-log { max-height: 300px; overflow-y: auto; background: #0d1117; color: #e0e0e0; padding: 12px; border-radius: 4px; font-family: 'Consolas', monospace; font-size: 12px; line-height: 1.5; white-space: pre-wrap; word-break: break-all; }

/* Empty state */
.empty-state { text-align: center; padding: 32px; color: var(--text-muted); font-size: 13px; }

/* Modal */
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.6); display: flex; align-items: center; justify-content: center; z-index: 1000; }
.modal-overlay.hidden { display: none; }
.modal { background: var(--bg-card); border-radius: 8px; border: 1px solid var(--border); width: 500px; max-height: 70vh; display: flex; flex-direction: column; box-shadow: 0 8px 32px var(--shadow); }
.modal-header { display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; border-bottom: 1px solid var(--border); }
.modal-header h3 { font-size: 14px; font-weight: 600; }
.modal-body { flex: 1; overflow-y: auto; padding: 8px; }
.modal-footer { display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; border-top: 1px solid var(--border); }
.selected-path { font-size: 12px; color: var(--text-muted); font-family: 'Consolas', monospace; overflow: hidden; text-overflow: ellipsis; max-width: 300px; white-space: nowrap; }

/* Tree nodes */
.tree-node { display: flex; align-items: center; gap: 4px; padding: 5px 8px; border-radius: 4px; cursor: pointer; user-select: none; font-size: 13px; }
.tree-node:hover { background: var(--bg-hover); }
.tree-node.selected { background: rgba(93, 173, 226, 0.15); color: var(--accent); }
.tree-node .toggle { width: 16px; font-size: 10px; color: var(--text-muted); flex-shrink: 0; text-align: center; }
.tree-node .icon { flex-shrink: 0; }
.tree-node .name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tree-children { padding-left: 20px; }
.tree-loading { padding: 4px 8px 4px 44px; font-size: 12px; color: var(--text-muted); font-style: italic; }

/* Scrollbar styling */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

/* Theme toggle button */
#themeToggle { background: transparent; border: 1px solid var(--border); color: var(--text-muted); border-radius: 4px; padding: 4px 10px; font-size: 12px; cursor: pointer; transition: all 0.15s; }
#themeToggle:hover { border-color: var(--accent); color: var(--accent); }

/* Preset row with inline badge */
.preset-row { display: flex; align-items: center; gap: 8px; }
.preset-row select { flex: 1; }
</style>
</head>
<body>

<!-- Topbar -->
<div class="topbar">
  <h1>&#128228; Robocopy Migration</h1>
  <div class="topbar-right">
    <button id="themeToggle">&#9728; Light</button>
  </div>
</div>

<!-- Main content -->
<div class="main-content">

  <!-- Job Builder Panel -->
  <div class="panel">
    <div class="panel-title">New Migration Job</div>

    <div class="builder-row">
      <label>Source</label>
      <input type="text" id="sourcePath" placeholder="\\server\share\folder or C:\path\to\folder" spellcheck="false" autocomplete="off">
      <button class="btn btn-secondary" id="sourceBrowse">Browse</button>
    </div>
    <div class="builder-row">
      <label>Destination</label>
      <input type="text" id="destPath" placeholder="\\server\share\folder or D:\path\to\folder" spellcheck="false" autocomplete="off">
      <button class="btn btn-secondary" id="destBrowse">Browse</button>
    </div>
    <div class="builder-row">
      <label>Preset</label>
      <div class="preset-row" style="flex:1;">
        <select id="presetSelect">
          <option value="full">Full Migration (files + permissions + timestamps)</option>
          <option value="incremental">Incremental (only new or updated files)</option>
          <option value="dataonly">Data Only (files + timestamps, no permissions)</option>
          <option value="mirror">Mirror (exact copy -- deletes extra files at destination)</option>
        </select>
        <span class="warning-badge" id="mirrorWarning" style="display:none;">DELETES</span>
      </div>
    </div>

    <!-- Advanced Options -->
    <details id="advancedDetails">
      <summary>Advanced Options</summary>
      <div class="advanced-grid">
        <label>Retries on failure</label>
        <input type="number" id="retries" value="3" min="0" max="99" style="width:80px;">

        <label>Wait between retries (sec)</label>
        <input type="number" id="waitTime" value="5" min="0" max="300" style="width:80px;">

        <label>Inter-packet gap (ms)</label>
        <input type="number" id="ipg" value="0" min="0" max="999999" style="width:100px;">

        <label>Multi-threaded copy</label>
        <div class="checkbox-row">
          <input type="checkbox" id="mtEnabled">
          <input type="number" id="mtCount" value="8" min="1" max="128" disabled style="width:60px;">
          <span style="font-size:12px;color:var(--text-muted);">threads</span>
        </div>

        <label>Backup mode</label>
        <div class="checkbox-row" style="gap:6px;">
          <select id="backupMode" style="background:var(--bg-input);border:1px solid var(--border);border-radius:4px;padding:4px 6px;color:var(--text);font-size:12px;">
            <option value="">Off (respect file permissions)</option>
            <option value="zb">Restartable + Backup fallback (/ZB)</option>
            <option value="b">Backup mode (/B) &mdash; bypasses ACLs</option>
          </select>
          <span style="font-size:11px;color:var(--text-muted);">Fixes "Error 5 Access Denied"</span>
        </div>

        <label>Exclude files (patterns)</label>
        <input type="text" id="excludeFiles" placeholder="*.tmp *.log thumbs.db">

        <label>Exclude folders (patterns)</label>
        <input type="text" id="excludeDirs" placeholder=".git node_modules temp">

        <label>Save log to</label>
        <input type="text" id="logFilePath" placeholder="(blank = default: <script folder>\Logs) &mdash; or enter a folder, or a full .log path">
        <label></label>
        <div style="font-size:11px;color:var(--text-muted);line-height:1.5;">
          A log is always saved. Leave blank to use the default folder next to the script with an auto-generated filename.
          Enter a folder path (ending in <code>\</code> or an existing folder) to use that folder with an auto name, or enter a full <code>.log</code> path for an exact filename.
        </div>
      </div>
    </details>

    <div class="builder-actions">
      <button class="btn btn-secondary" id="previewBtn">&#128269; Preview</button>
      <button class="btn btn-primary" id="addJobBtn">&#43; Add to Queue</button>
    </div>
  </div>

  <!-- Preview Results Panel (hidden until triggered) -->
  <div class="preview-panel" id="previewResults" style="display:none;">
    <div class="panel-title">Preview Results</div>
    <div id="previewContent"></div>
  </div>

  <!-- Job Queue Panel -->
  <div class="panel">
    <div class="queue-header">
      <div class="panel-title">Job Queue</div>
      <button class="btn btn-secondary" id="clearDoneBtn">Clear Done</button>
    </div>
    <table class="queue-table">
      <thead>
        <tr>
          <th style="width:36px;">#</th>
          <th>Source</th>
          <th>Destination</th>
          <th style="width:130px;">Preset</th>
          <th style="width:120px;">Status</th>
          <th style="width:80px;">Action</th>
        </tr>
      </thead>
      <tbody id="queueBody">
        <tr><td colspan="6" class="empty-state">No jobs in queue. Add a migration job above.</td></tr>
      </tbody>
    </table>
  </div>

</div><!-- /main-content -->

<!-- Folder Picker Modal -->
<div class="modal-overlay hidden" id="modalOverlay">
  <div class="modal">
    <div class="modal-header">
      <h3>&#128193; Select Folder</h3>
      <button class="btn-icon" id="modalClose">&#10005;</button>
    </div>
    <div class="modal-body" id="modalBody">
      <div class="tree-loading">Loading drives...</div>
    </div>
    <div class="modal-footer">
      <span class="selected-path" id="selectedPathDisplay">No folder selected</span>
      <button class="btn btn-primary" id="modalSelect" disabled>Select</button>
    </div>
  </div>
</div>

<script>
// --- Theme toggle ---
var themeBtn = document.getElementById('themeToggle');
themeBtn.onclick = function() {
    document.body.classList.toggle('light');
    var isLight = document.body.classList.contains('light');
    localStorage.setItem('theme', isLight ? 'light' : 'dark');
    themeBtn.textContent = isLight ? '\u2600 Dark' : '\u2600 Light';
};
if (localStorage.getItem('theme') === 'light') {
    document.body.classList.add('light');
    themeBtn.textContent = '\u2600 Dark';
}

// --- Element references ---
var sourcePath = document.getElementById('sourcePath');
var destPath = document.getElementById('destPath');
var sourceBrowse = document.getElementById('sourceBrowse');
var destBrowse = document.getElementById('destBrowse');
var presetSelect = document.getElementById('presetSelect');
var mirrorWarning = document.getElementById('mirrorWarning');
var previewBtn = document.getElementById('previewBtn');
var addJobBtn = document.getElementById('addJobBtn');
var previewResults = document.getElementById('previewResults');
var previewContent = document.getElementById('previewContent');
var clearDoneBtn = document.getElementById('clearDoneBtn');
var modalOverlay = document.getElementById('modalOverlay');
var modalBody = document.getElementById('modalBody');
var modalClose = document.getElementById('modalClose');
var modalSelect = document.getElementById('modalSelect');
var selectedPathDisplay = document.getElementById('selectedPathDisplay');

// --- Preset warning ---
presetSelect.onchange = function() {
    mirrorWarning.style.display = presetSelect.value === 'mirror' ? 'inline-block' : 'none';
};

// --- Advanced: MT checkbox ---
document.getElementById('mtEnabled').onchange = function() {
    document.getElementById('mtCount').disabled = !this.checked;
};

// --- Folder Picker Modal ---
var activeInput = null;
var selectedFolderPath = null;

sourceBrowse.onclick = function() {
    activeInput = sourcePath;
    openModal();
};
destBrowse.onclick = function() {
    activeInput = destPath;
    openModal();
};
modalClose.onclick = closeModal;
modalOverlay.onclick = function(e) {
    if (e.target === modalOverlay) closeModal();
};

function openModal() {
    selectedFolderPath = null;
    selectedPathDisplay.textContent = 'No folder selected';
    modalSelect.disabled = true;
    modalBody.innerHTML = '<div class="tree-loading">Loading drives...</div>';
    modalOverlay.classList.remove('hidden');
    fetch('/api/drives')
        .then(function(r) { return r.json(); })
        .then(function(drives) { renderDrives(drives); })
        .catch(function() { modalBody.innerHTML = '<div class="tree-loading">Failed to load drives.</div>'; });
}

function closeModal() {
    modalOverlay.classList.add('hidden');
}

function renderDrives(drives) {
    modalBody.innerHTML = '';
    drives.forEach(function(drive) {
        var wrapper = document.createElement('div');
        var node = document.createElement('div');
        node.className = 'tree-node';
        node.dataset.path = drive.root;
        node.innerHTML = '<span class="toggle">&#9654;</span><span class="icon">&#128190;</span><span class="name">' + escapeHtml(drive.label) + '</span>';
        var children = document.createElement('div');
        children.className = 'tree-children';
        children.style.display = 'none';
        var expanded = false;

        node.onclick = function(e) {
            e.stopPropagation();
            selectFolder(drive.root);
            if (!expanded) {
                expanded = true;
                node.querySelector('.toggle').innerHTML = '&#9660;';
                children.style.display = 'block';
                loadChildren(drive.root, children);
            } else {
                expanded = false;
                node.querySelector('.toggle').innerHTML = '&#9654;';
                children.style.display = 'none';
            }
            document.querySelectorAll('.tree-node.selected').forEach(function(n) { n.classList.remove('selected'); });
            node.classList.add('selected');
        };

        wrapper.appendChild(node);
        wrapper.appendChild(children);
        modalBody.appendChild(wrapper);
    });
}

function loadChildren(path, parentEl) {
    parentEl.innerHTML = '<div class="tree-loading">Loading...</div>';
    fetch('/api/children?path=' + encodeURIComponent(path))
        .then(function(r) { return r.json(); })
        .then(function(items) {
            parentEl.innerHTML = '';
            if (!items || items.length === 0) {
                parentEl.innerHTML = '<div class="tree-loading">Empty folder</div>';
                return;
            }
            items.forEach(function(item) {
                var wrapper = document.createElement('div');
                var node = document.createElement('div');
                node.className = 'tree-node';
                node.dataset.path = item.path;
                var toggleHtml = item.hasChildren ? '<span class="toggle">&#9654;</span>' : '<span class="toggle"></span>';
                node.innerHTML = toggleHtml + '<span class="icon">&#128193;</span><span class="name">' + escapeHtml(item.name) + '</span>';
                var children = document.createElement('div');
                children.className = 'tree-children';
                children.style.display = 'none';
                var expanded = false;

                node.onclick = function(e) {
                    e.stopPropagation();
                    selectFolder(item.path);
                    document.querySelectorAll('.tree-node.selected').forEach(function(n) { n.classList.remove('selected'); });
                    node.classList.add('selected');
                    if (item.hasChildren) {
                        if (!expanded) {
                            expanded = true;
                            node.querySelector('.toggle').innerHTML = '&#9660;';
                            children.style.display = 'block';
                            loadChildren(item.path, children);
                        } else {
                            expanded = false;
                            node.querySelector('.toggle').innerHTML = '&#9654;';
                            children.style.display = 'none';
                        }
                    }
                };

                wrapper.appendChild(node);
                wrapper.appendChild(children);
                parentEl.appendChild(wrapper);
            });
        })
        .catch(function() {
            parentEl.innerHTML = '<div class="tree-loading">Failed to load.</div>';
        });
}

function selectFolder(path) {
    selectedFolderPath = path;
    selectedPathDisplay.textContent = path;
    modalSelect.disabled = false;
}

modalSelect.onclick = function() {
    if (selectedFolderPath && activeInput) {
        activeInput.value = selectedFolderPath;
    }
    closeModal();
};

// --- getOverrides helper ---
function getOverrides() {
    return {
        retries: parseInt(document.getElementById('retries').value) || 3,
        waitTime: parseInt(document.getElementById('waitTime').value) || 5,
        ipg: parseInt(document.getElementById('ipg').value) || 0,
        mtEnabled: document.getElementById('mtEnabled').checked,
        mtCount: parseInt(document.getElementById('mtCount').value) || 8,
        backupMode: document.getElementById('backupMode').value,
        excludeFiles: document.getElementById('excludeFiles').value.trim(),
        excludeDirs: document.getElementById('excludeDirs').value.trim(),
        logFilePath: document.getElementById('logFilePath').value.trim()
    };
}

// --- Preview button ---
previewBtn.onclick = function() {
    var source = sourcePath.value.trim();
    var dest = destPath.value.trim();
    if (!source) { alert('Enter a source path'); return; }

    previewBtn.disabled = true;
    previewBtn.textContent = 'Scanning...';

    fetch('/api/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: source, destination: dest || 'NUL', preset: presetSelect.value, overrides: getOverrides() })
    })
    .then(function(res) { return res.json(); })
    .then(function(data) {
        if (data.error) { alert(data.error); return; }
        previewResults.style.display = 'block';
        previewContent.innerHTML =
            '<div class="preview-stats">' +
            '<div class="preview-stat"><div class="value">' + data.files + '</div><div class="label">Files</div></div>' +
            '<div class="preview-stat"><div class="value">' + data.dirs + '</div><div class="label">Folders</div></div>' +
            '<div class="preview-stat"><div class="value">' + escapeHtml(data.sizeDisplay) + '</div><div class="label">Total Size</div></div>' +
            '</div>' +
            '<details><summary style="font-size:12px;color:var(--text-muted);cursor:pointer;">Raw output</summary>' +
            '<pre style="font-size:11px;max-height:200px;overflow:auto;margin-top:8px;padding:8px;background:var(--bg);border-radius:4px;">' + escapeHtml(data.rawSummary) + '</pre></details>';
    })
    .catch(function(e) { alert('Preview failed: ' + e.message); })
    .finally(function() {
        previewBtn.disabled = false;
        previewBtn.textContent = '\uD83D\uDD0D Preview';
    });
};

// --- Add to Queue ---
addJobBtn.onclick = function() {
    var source = sourcePath.value.trim();
    var dest = destPath.value.trim();
    if (!source || !dest) { alert('Enter both source and destination paths'); return; }

    if (presetSelect.value === 'mirror') {
        if (!confirm('Mirror mode will DELETE files at the destination that don\'t exist at the source. Continue?')) return;
    }

    fetch('/api/job/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: source, destination: dest, preset: presetSelect.value, overrides: getOverrides() })
    })
    .then(function(res) { return res.json(); })
    .then(function(data) {
        if (data.error) { alert(data.error); return; }
        renderQueue();
    })
    .catch(function(e) { alert('Failed to add job: ' + e.message); });
};

// --- Queue rendering ---
var expandedJobId = null;
var logIntervals = {};
var logPositions = {};
var logCache = {};
var statsCache = {};

function renderQueue() {
    return fetch('/api/job/list')
        .then(function(res) { return res.json(); })
        .then(function(jobs) {
            if (!Array.isArray(jobs)) jobs = jobs ? [jobs] : [];
            var tbody = document.getElementById('queueBody');

            var html = '';
            jobs.forEach(function(job, i) {
                var presetLabels = { full: 'Full Migration', incremental: 'Incremental', dataonly: 'Data Only', mirror: 'Mirror' };
                var label = presetLabels[job.preset] || job.preset;
                html += '<tr class="job-row" data-id="' + escapeHtml(job.id) + '">' +
                    '<td>' + (i + 1) + '</td>' +
                    '<td class="path-cell" title="' + escapeHtml(job.source) + '">' + escapeHtml(truncatePath(job.source, 40)) + '</td>' +
                    '<td class="path-cell" title="' + escapeHtml(job.destination) + '">' + escapeHtml(truncatePath(job.destination, 40)) + '</td>' +
                    '<td>' + escapeHtml(label) + '</td>' +
                    '<td><span class="status status-' + escapeHtml(job.status) + '">' + statusIcon(job.status) + ' ' + escapeHtml(job.status) + '</span></td>' +
                    '<td>' + actionButtons(job) + '</td>' +
                    '</tr>';
                if (expandedJobId === job.id) {
                    html += '<tr class="job-log-row"><td colspan="6"><div class="job-log-container">' +
                        '<div class="stats-bar" id="stats-' + escapeHtml(job.id) + '"></div>' +
                        '<div class="job-log" id="log-' + escapeHtml(job.id) + '"></div>' +
                        '</div></td></tr>';
                }
            });

            if (jobs.length === 0) {
                html = '<tr><td colspan="6" class="empty-state">No jobs in queue. Add a migration job above.</td></tr>';
            }

            tbody.innerHTML = html;

            // Restore cached log text and stats for the expanded job, so re-renders
            // during a running job don't wipe the visible output.
            if (expandedJobId) {
                var logEl = document.getElementById('log-' + expandedJobId);
                if (logEl && logCache[expandedJobId]) {
                    logEl.textContent = logCache[expandedJobId];
                    logEl.scrollTop = logEl.scrollHeight;
                }
                var statsEl = document.getElementById('stats-' + expandedJobId);
                if (statsEl && statsCache[expandedJobId]) {
                    statsEl.innerHTML = statsCache[expandedJobId];
                }
            }

            document.querySelectorAll('.job-row').forEach(function(row) {
                row.onclick = function(e) {
                    if (e.target.closest('button')) return;
                    var id = row.dataset.id;
                    if (expandedJobId === id) {
                        expandedJobId = null;
                        stopLogPolling(id);
                    } else {
                        if (expandedJobId) stopLogPolling(expandedJobId);
                        expandedJobId = id;
                    }
                    renderQueue().then(function() {
                        if (expandedJobId) startLogPolling(expandedJobId);
                    });
                };
            });

            setTimeout(function() {
                document.querySelectorAll('.job-log').forEach(function(el) {
                    if (!el.dataset.scrollBound) {
                        el.dataset.scrollBound = 'true';
                        el.onscroll = function() {
                            var atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 30;
                            el.dataset.userScrolled = atBottom ? '' : 'true';
                        };
                    }
                });
            }, 50);
        })
        .catch(function() {});
}

// --- Log polling ---
function startLogPolling(jobId) {
    if (logIntervals[jobId]) return;
    if (typeof logPositions[jobId] !== 'number') logPositions[jobId] = 0;
    // Seed the visible log div from cache in case this is a re-expand after collapse.
    var logEl = document.getElementById('log-' + jobId);
    if (logEl && logCache[jobId]) {
        logEl.textContent = logCache[jobId];
        logEl.scrollTop = logEl.scrollHeight;
    }
    var statsEl = document.getElementById('stats-' + jobId);
    if (statsEl && statsCache[jobId]) {
        statsEl.innerHTML = statsCache[jobId];
    }
    pollLog(jobId);
    logIntervals[jobId] = setInterval(function() { pollLog(jobId); }, 1000);
}

function stopLogPolling(jobId) {
    if (logIntervals[jobId]) {
        clearInterval(logIntervals[jobId]);
        delete logIntervals[jobId];
    }
}

function pollLog(jobId) {
    var from = logPositions[jobId] || 0;
    fetch('/api/job/' + jobId + '/log?from=' + from)
        .then(function(res) { return res.json(); })
        .then(function(data) {
            var logEl = document.getElementById('log-' + jobId);
            var statsEl = document.getElementById('stats-' + jobId);

            if (data.lines && data.lines.length > 0) {
                var appended = data.lines.join('\n') + '\n';
                logCache[jobId] = (logCache[jobId] || '') + appended;
                logPositions[jobId] = data.totalLines;
                if (logEl) {
                    logEl.textContent = logCache[jobId];
                    if (!logEl.dataset.userScrolled) {
                        logEl.scrollTop = logEl.scrollHeight;
                    }
                }
            }

            if (data.stats) {
                var s = data.stats;
                var statsHtml =
                    '<div class="stat-item"><span class="stat-value">' + (s.filesCopied || 0) + '</span><span class="stat-label">&nbsp;copied</span></div>' +
                    '<div class="stat-item"><span class="stat-value">' + (s.filesSkipped || 0) + '</span><span class="stat-label">&nbsp;skipped</span></div>' +
                    '<div class="stat-item"><span class="stat-value">' + (s.filesFailed || 0) + '</span><span class="stat-label">&nbsp;failed</span></div>' +
                    '<div class="stat-item"><span class="stat-value">' + formatBytes(s.bytesCopied || 0) + '</span><span class="stat-label">&nbsp;transferred</span></div>' +
                    '<div class="stat-item"><span class="stat-value">' + formatDuration(s.elapsedSeconds || 0) + '</span><span class="stat-label">&nbsp;elapsed</span></div>';
                statsCache[jobId] = statsHtml;
                if (statsEl) { statsEl.innerHTML = statsHtml; }
            }

            // Update only the status cell in place so the log div doesn't get wiped.
            var row = document.querySelector('.job-row[data-id="' + jobId + '"]');
            if (row && data.status) {
                var statusCell = row.cells[4];
                if (statusCell) {
                    var cur = statusCell.querySelector('.status');
                    var curStatus = cur ? cur.textContent.trim().split(/\s+/).pop() : '';
                    if (curStatus !== data.status) {
                        statusCell.innerHTML = '<span class="status status-' + data.status + '">' + statusIcon(data.status) + ' ' + data.status + '</span>';
                    }
                }
            }

            if (data.status && data.status !== 'running' && data.status !== 'pending') {
                stopLogPolling(jobId);
                renderQueue();
            }
        })
        .catch(function() {});
}

// --- Clear Done ---
clearDoneBtn.onclick = function() {
    fetch('/api/job/list')
        .then(function(res) { return res.json(); })
        .then(function(jobs) {
            if (!Array.isArray(jobs)) jobs = jobs ? [jobs] : [];
            var toRemove = jobs.filter(function(j) {
                return j.status === 'complete' || j.status === 'warning' || j.status === 'failed' || j.status === 'cancelled';
            });
            var p = Promise.resolve();
            toRemove.forEach(function(job) {
                p = p.then(function() {
                    return fetch('/api/job/' + job.id, { method: 'DELETE' });
                });
            });
            return p;
        })
        .then(function() { renderQueue(); })
        .catch(function() {});
};

// --- Action buttons helper ---
function actionButtons(job) {
    var btns = '';
    if (job.status === 'pending') {
        btns += '<button class="btn btn-primary" style="padding:3px 10px;font-size:12px;" onclick="runJob(\'' + escapeAttr(job.id) + '\')">&#9654; Run</button> ';
    }
    if (job.status === 'running') {
        btns += '<span style="color:var(--accent);font-size:12px;">Running...</span>';
    }
    if (job.status !== 'running') {
        btns += '<button class="btn-icon" onclick="removeJob(\'' + escapeAttr(job.id) + '\')" title="Remove">&#10005;</button>';
    }
    return btns;
}

function runJob(id) {
    // Reset any cached log/stats from a previous run of this job id.
    logCache[id] = '';
    statsCache[id] = '';
    logPositions[id] = 0;

    // Launch the job (returns immediately, runs in background)
    fetch('/api/job/run/' + id, { method: 'POST' })
        .then(function(res) { return res.json(); })
        .then(function(data) {
            if (data.error) { alert(data.error); return; }
            // Expand the job log; pollLog updates status in place and triggers
            // a final renderQueue() when the job finishes.
            if (expandedJobId && expandedJobId !== id) stopLogPolling(expandedJobId);
            expandedJobId = id;
            renderQueue().then(function() {
                startLogPolling(id);
            });
        })
        .catch(function(e) {
            alert('Failed to start job: ' + e.message);
            renderQueue();
        });
}

function removeJob(id) {
    if (expandedJobId === id) { expandedJobId = null; stopLogPolling(id); }
    delete logCache[id];
    delete statsCache[id];
    delete logPositions[id];
    fetch('/api/job/' + id, { method: 'DELETE' })
        .then(function() { renderQueue(); });
}

// --- Utility functions ---
function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escapeAttr(str) {
    if (!str) return '';
    return String(str).replace(/'/g, "\\'");
}

function truncatePath(path, max) {
    if (!path || path.length <= max) return path;
    var start = path.substring(0, 15);
    var end = path.substring(path.length - (max - 18));
    return start + '...' + end;
}

function formatBytes(bytes) {
    bytes = bytes || 0;
    if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(1) + ' GB';
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(0) + ' KB';
    return bytes + ' B';
}

function formatDuration(sec) {
    if (!sec) return '0:00';
    var h = Math.floor(sec / 3600);
    var m = Math.floor((sec % 3600) / 60);
    var s = sec % 60;
    if (h > 0) return h + ':' + String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0');
    return m + ':' + String(s).padStart(2, '0');
}

function statusIcon(status) {
    var icons = { pending: '\u25cb', running: '\u25c9', complete: '\u2713', warning: '\u26a0', failed: '\u2715', cancelled: '\u2298' };
    return icons[status] || '?';
}

// --- Initial render ---
renderQueue();
</script>
</body>
</html>
"@

# --- Start HTTP Listener ---

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add($baseUrl)
try {
    $listener.Start()
    Write-Host "[INFO] Robocopy Migration running at $baseUrl" -ForegroundColor Cyan
    Write-Host "[INFO] Press Ctrl+C to stop." -ForegroundColor Cyan
}
catch {
    Write-Error "Failed to start HTTP listener on port $Port. Is it already in use? Error: $_"
    exit 1
}

if (-not $NoBrowserOpen) {
    try {
        Start-Process $baseUrl
    }
    catch {
        # Fallback: use explorer to open the URL
        try { Start-Process "explorer.exe" $baseUrl } catch {}
        Write-Host "[WARN] Could not auto-open browser. Navigate to $baseUrl manually." -ForegroundColor Yellow
    }
    Write-Host "[INFO] If the browser did not open, navigate to $baseUrl" -ForegroundColor Cyan
}

# --- Main Request Loop ---

$script:running = $true
try {
    while ($script:running) {
        # Handle HTTP requests
        $contextTask = $listener.GetContextAsync()
        while (-not $contextTask.IsCompleted) {
            Start-Sleep -Milliseconds 50

            # Process running jobs -- read output, check completion
            Update-RunningJobs
        }
        $context = $contextTask.Result
        Invoke-Route -Context $context

        # Always process running jobs after handling a request
        Update-RunningJobs
    }
}
finally {
    # Kill any running job processes
    foreach ($id in @($script:jobProcesses.Keys)) {
        try {
            $proc = $script:jobProcesses[$id]
            if (-not $proc.HasExited) { $proc.Kill() }
        } catch {}
    }
    $listener.Stop()
    $listener.Close()
    Write-Host "[INFO] Server stopped." -ForegroundColor Yellow
}