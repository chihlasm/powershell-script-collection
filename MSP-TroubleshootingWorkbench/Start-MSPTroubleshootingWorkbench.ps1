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

.PARAMETER LibraryMode
    Define the workbench functions and resolve OutputPath, then return without
    starting the HTTP listener. Used by the test suite to load this script as a
    function library via dot-sourcing.

.EXAMPLE
    .\Start-MSPTroubleshootingWorkbench.ps1

.NOTES
    Run elevated when checks require administrative access.
#>
[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8275,

    [string]$OutputPath = "",

    [switch]$NoBrowserOpen,

    [switch]$LibraryMode
)

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = $PSScriptRoot
}

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

function Get-WorkbenchExportDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CaseId
    )

    if (-not (Test-WorkbenchCaseId -CaseId $CaseId)) {
        throw "Invalid case id."
    }

    $exportRoot = Join-Path $OutputPath 'exports'
    if (-not (Test-Path -LiteralPath $exportRoot)) {
        New-Item -ItemType Directory -Path $exportRoot -Force -ErrorAction Stop | Out-Null
    }

    $trimChars = @([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $resolvedExportRoot = (Get-ResolvedPath -Path $exportRoot).TrimEnd($trimChars)
    $exportDirectory = Get-ResolvedPath -Path (Join-Path $resolvedExportRoot $CaseId)
    $requiredPrefix = $resolvedExportRoot + [System.IO.Path]::DirectorySeparatorChar

    if (-not $exportDirectory.StartsWith($requiredPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Export path must stay inside the export store."
    }

    if (-not (Test-Path -LiteralPath $exportDirectory)) {
        New-Item -ItemType Directory -Path $exportDirectory -Force -ErrorAction Stop | Out-Null
    }

    return $exportDirectory
}

function Get-WorkbenchExportFilePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CaseId,

        [Parameter(Mandatory)]
        [ValidateSet("ticket-notes.md", "report.html", "evidence.json")]
        [string]$FileName
    )

    $exportDirectory = Get-WorkbenchExportDirectory -CaseId $CaseId
    $trimChars = @([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $resolvedExportDirectory = (Get-ResolvedPath -Path $exportDirectory).TrimEnd($trimChars)
    $filePath = Get-ResolvedPath -Path (Join-Path $resolvedExportDirectory $FileName)
    $requiredPrefix = $resolvedExportDirectory + [System.IO.Path]::DirectorySeparatorChar

    if (-not $filePath.StartsWith($requiredPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Export file path must stay inside the case export folder."
    }

    return $filePath
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

function Get-CheckCatalog {
    [CmdletBinding()]
    param()

    $checksRoot = Join-Path $PSScriptRoot 'checks'
    $manifestPath = Join-Path $checksRoot 'manifest.json'

    if (-not (Test-Path -LiteralPath $manifestPath)) {
        throw "Check manifest was not found."
    }

    $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($manifest.schemaVersion -ne 1) {
        throw "Unsupported check manifest schema version."
    }

    $trimChars = @([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $resolvedChecksRoot = (Get-ResolvedPath -Path $checksRoot).TrimEnd($trimChars)
    $requiredPrefix = $resolvedChecksRoot + [System.IO.Path]::DirectorySeparatorChar
    $catalog = @()

    foreach ($check in @($manifest.checks)) {
        foreach ($field in @('checkId', 'name', 'category', 'script')) {
            if (-not ($check.PSObject.Properties.Name -contains $field)) {
                throw "Check manifest entry is missing '$field'."
            }

            if ([string]::IsNullOrWhiteSpace([string]$check.$field)) {
                throw "Check manifest entry field '$field' is blank."
            }
        }

        $scriptName = [string]$check.script
        if ([System.IO.Path]::IsPathRooted($scriptName)) {
            throw "Check script path must be relative to the checks folder."
        }

        $scriptPath = Get-ResolvedPath -Path (Join-Path $resolvedChecksRoot $scriptName)
        if (-not $scriptPath.StartsWith($requiredPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Check script path must stay inside the checks folder."
        }

        if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
            throw "Check script '$scriptName' was not found."
        }

        $catalog += [PSCustomObject]@{
            CheckId     = [string]$check.checkId
            Name        = [string]$check.name
            Category    = [string]$check.category
            Script      = $scriptName
            Description = [string]$check.description
            ReadOnly    = [bool]$check.readOnly
            Inputs      = @($check.inputs)
            ScriptPath  = $scriptPath
        }
    }

    return @($catalog)
}

function New-WorkbenchCheckFailureResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Check,

        [Parameter(Mandatory)]
        [string]$Message,

        [bool]$TimedOut = $false,

        [int]$TimeoutSeconds = 0,

        [string]$JobState = ""
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    [PSCustomObject]@{
        CheckId              = [string]$Check.CheckId
        Name                 = [string]$Check.Name
        Category             = [string]$Check.Category
        Status               = "Fail"
        Summary              = "Check could not complete: $Message"
        Evidence             = @([PSCustomObject]@{
            Name   = "Check execution"
            Status = "Fail"
            Detail = $Message
        })
        RecommendedNextSteps = @("Review the check error, confirm the inputs, and run the check again.")
        RawOutput            = [PSCustomObject]@{
            Error          = $Message
            TimedOut       = [bool]$TimedOut
            TimeoutSeconds = [int]$TimeoutSeconds
            JobState       = [string]$JobState
        }
        StartedAt            = $timestamp
        FinishedAt           = $timestamp
        Error                = $Message
    }
}

function ConvertTo-WorkbenchPlainValue {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if (
        ($Value -is [string]) -or
        ($Value -is [bool]) -or
        ($Value -is [int]) -or
        ($Value -is [long]) -or
        ($Value -is [double]) -or
        ($Value -is [decimal])
    ) {
        return $Value
    }

    if ($Value -is [datetime]) {
        return $Value.ToString("yyyy-MM-dd HH:mm:ss")
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $convertedDictionary = [ordered]@{}
        foreach ($key in $Value.Keys) {
            $convertedDictionary[[string]$key] = ConvertTo-WorkbenchPlainValue -Value $Value[$key]
        }

        return [PSCustomObject]$convertedDictionary
    }

    if (($Value -is [System.Collections.IEnumerable]) -and (-not ($Value -is [string]))) {
        $convertedItems = @()
        foreach ($item in @($Value)) {
            $convertedItems += ConvertTo-WorkbenchPlainValue -Value $item
        }

        return ,@($convertedItems)
    }

    $properties = @($Value.PSObject.Properties | Where-Object {
        $_.Name -notin @("PSComputerName", "RunspaceId", "PSShowComputerName")
    })

    if ($properties.Count -eq 0) {
        return [string]$Value
    }

    $duplicateCaseNames = @($properties.Name | Group-Object { $_.ToLowerInvariant() } | Where-Object { $_.Count -gt 1 })
    if ($duplicateCaseNames.Count -gt 0) {
        return [string]$Value
    }

    $convertedObject = [ordered]@{}
    foreach ($property in $properties) {
        $convertedObject[$property.Name] = ConvertTo-WorkbenchPlainValue -Value $property.Value
    }

    return [PSCustomObject]$convertedObject
}

function ConvertTo-WorkbenchScriptParameterName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$InputName
    )

    if ($InputName.Length -eq 1) {
        return $InputName.ToUpperInvariant()
    }

    return ("{0}{1}" -f $InputName.Substring(0, 1).ToUpperInvariant(), $InputName.Substring(1))
}

function ConvertTo-WorkbenchCheckInputValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$InputName,

        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $inputKey = $InputName.ToLowerInvariant()
    if ($inputKey -eq "port") {
        $portText = [string]$Value
        if ([string]::IsNullOrWhiteSpace($portText)) {
            return $null
        }

        $port = 0
        if (-not [int]::TryParse($portText, [ref]$port)) {
            throw "Port must be a number."
        }

        if ($port -lt 1 -or $port -gt 65535) {
            throw "Port must be between 1 and 65535."
        }

        return $port
    }

    if ($inputKey -eq "daysback") {
        $daysBackText = [string]$Value
        if ([string]::IsNullOrWhiteSpace($daysBackText)) {
            return $null
        }

        $daysBack = 0
        if (-not [int]::TryParse($daysBackText, [ref]$daysBack)) {
            throw "DaysBack must be a number."
        }

        if ($daysBack -lt 1 -or $daysBack -gt 90) {
            throw "DaysBack must be between 1 and 90."
        }

        return $daysBack
    }

    if ($inputKey -eq "domaincontroller") {
        $domainControllers = @()
        foreach ($item in @($Value)) {
            $itemText = [string]$item
            if ([string]::IsNullOrWhiteSpace($itemText)) {
                continue
            }

            $domainControllers += @($itemText -split "," | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }

        if ($domainControllers.Count -eq 0) {
            return $null
        }

        return ,@($domainControllers)
    }

    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) {
            return $null
        }

        return [string]$Value
    }

    return $Value
}

function New-WorkbenchCheckParameters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Check,

        [Parameter(Mandatory)]
        [object]$Body
    )

    $parameters = @{}
    $bodyPropertyNames = @($Body.PSObject.Properties.Name)

    foreach ($inputName in @($Check.Inputs)) {
        if ([string]::IsNullOrWhiteSpace([string]$inputName)) {
            continue
        }

        $inputText = [string]$inputName
        $bodyProperty = @($bodyPropertyNames | Where-Object { $_ -ieq $inputText } | Select-Object -First 1)
        if ($bodyProperty.Count -eq 0) {
            continue
        }

        $convertedValue = ConvertTo-WorkbenchCheckInputValue -InputName $inputText -Value $Body.($bodyProperty[0])
        if ($null -eq $convertedValue) {
            continue
        }

        $parameterName = ConvertTo-WorkbenchScriptParameterName -InputName $inputText
        $parameters[$parameterName] = $convertedValue
    }

    return $parameters
}

function Invoke-WorkbenchCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CheckId,

        [Parameter(Mandatory)]
        [object]$Body,

        [ValidateRange(1, 3600)]
        [int]$TimeoutSeconds = 60
    )

    $check = @(Get-CheckCatalog | Where-Object { $_.CheckId -eq $CheckId } | Select-Object -First 1)
    if ($check.Count -eq 0) {
        throw "Check not found."
    }

    $selectedCheck = $check[0]
    $invokeParams = New-WorkbenchCheckParameters -Check $selectedCheck -Body $Body
    $job = $null

    try {
        $job = Start-Job -ScriptBlock {
            param(
                [string]$ScriptPath,
                [hashtable]$Parameters
            )

            & $ScriptPath @Parameters
        } -ArgumentList $selectedCheck.ScriptPath, $invokeParams -ErrorAction Stop

        $completedJob = Wait-Job -Job $job -Timeout $TimeoutSeconds -ErrorAction Stop
        if ($null -eq $completedJob) {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            $message = "Check timed out after $TimeoutSeconds second(s)."
            return (New-WorkbenchCheckFailureResult -Check $selectedCheck -Message $message -TimedOut $true -TimeoutSeconds $TimeoutSeconds -JobState "TimedOut")
        }

        $result = Receive-Job -Job $job -ErrorAction Stop
    }
    catch {
        $jobState = ""
        if ($job) {
            $jobState = [string]$job.State
        }

        return (New-WorkbenchCheckFailureResult -Check $selectedCheck -Message $_.Exception.Message -TimedOut $false -TimeoutSeconds $TimeoutSeconds -JobState $jobState)
    }
    finally {
        if ($job) {
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }

    if ($null -eq $result) {
        return (New-WorkbenchCheckFailureResult -Check $selectedCheck -Message "Check did not return a result." -TimedOut $false -TimeoutSeconds $TimeoutSeconds -JobState "Completed")
    }

    if ($result -is [array]) {
        $result = @($result | Select-Object -Last 1)[0]
    }

    return (ConvertTo-WorkbenchPlainValue -Value $result)
}

function Add-TicketNotesLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Text.StringBuilder]$Builder,

        [AllowNull()]
        [string]$Line = ""
    )

    [void]$Builder.AppendLine($Line)
}

function Add-TicketNotesBullet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Text.StringBuilder]$Builder,

        [AllowNull()]
        [string]$Text
    )

    if (-not [string]::IsNullOrWhiteSpace($Text)) {
        Add-TicketNotesLine -Builder $Builder -Line ("- {0}" -f $Text.Trim())
    }
}

function New-TicketNotesMarkdown {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Case
    )

    $builder = New-Object System.Text.StringBuilder
    $checks = @()
    $notes = @()

    if ($Case.PSObject.Properties.Name -contains "Checks" -and $null -ne $Case.Checks) {
        $checks = @($Case.Checks)
    }

    if ($Case.PSObject.Properties.Name -contains "Notes" -and $null -ne $Case.Notes) {
        $notes = @($Case.Notes)
    }

    Add-TicketNotesLine -Builder $builder -Line "Issue:"
    Add-TicketNotesBullet -Builder $builder -Text ("Client: {0}" -f $Case.ClientName)
    Add-TicketNotesBullet -Builder $builder -Text ("Ticket: {0}" -f $Case.TicketNumber)
    Add-TicketNotesBullet -Builder $builder -Text ("Issue type: {0}" -f $Case.IssueType)
    Add-TicketNotesBullet -Builder $builder -Text ("Affected user: {0}" -f $Case.AffectedUser)
    Add-TicketNotesBullet -Builder $builder -Text ("Affected device: {0}" -f $Case.AffectedDevice)
    Add-TicketNotesBullet -Builder $builder -Text ("Target path: {0}" -f $Case.TargetPath)
    Add-TicketNotesBullet -Builder $builder -Text ("Target address: {0}" -f $Case.TargetAddress)
    if ($notes.Count -gt 0) {
        Add-TicketNotesBullet -Builder $builder -Text ("Reported detail: {0}" -f [string]$notes[0].Text)
    }
    Add-TicketNotesLine -Builder $builder

    Add-TicketNotesLine -Builder $builder -Line "Actions Taken:"
    if ($checks.Count -gt 0) {
        foreach ($check in $checks) {
            $finishedAt = ""
            if ($check.PSObject.Properties.Name -contains "FinishedAt") {
                $finishedAt = [string]$check.FinishedAt
            }

            $action = "Ran {0}" -f $check.Name
            if (-not [string]::IsNullOrWhiteSpace($finishedAt)) {
                $action = "$action at $finishedAt"
            }

            Add-TicketNotesBullet -Builder $builder -Text $action
        }
    }
    else {
        Add-TicketNotesBullet -Builder $builder -Text "No automated checks have been run yet."
    }

    foreach ($note in $notes) {
        $noteLine = [string]$note.Text
        if ($note.PSObject.Properties.Name -contains "CreatedAt" -and -not [string]::IsNullOrWhiteSpace([string]$note.CreatedAt)) {
            $noteLine = "{0}: {1}" -f $note.CreatedAt, $note.Text
        }

        Add-TicketNotesBullet -Builder $builder -Text $noteLine
    }
    Add-TicketNotesLine -Builder $builder

    Add-TicketNotesLine -Builder $builder -Line "Findings:"
    if ($checks.Count -gt 0) {
        foreach ($check in $checks) {
            Add-TicketNotesBullet -Builder $builder -Text ("{0} [{1}]: {2}" -f $check.Name, $check.Status, $check.Summary)
        }
    }
    else {
        Add-TicketNotesBullet -Builder $builder -Text "Findings are pending additional checks."
    }
    Add-TicketNotesLine -Builder $builder

    Add-TicketNotesLine -Builder $builder -Line "Evidence:"
    $evidenceCount = 0
    foreach ($check in $checks) {
        if ($check.PSObject.Properties.Name -contains "Evidence" -and $null -ne $check.Evidence) {
            foreach ($evidence in @($check.Evidence)) {
                $evidenceCount++
                Add-TicketNotesBullet -Builder $builder -Text ("{0} - {1}: {2}" -f $evidence.Name, $evidence.Status, $evidence.Detail)
            }
        }
    }

    if ($evidenceCount -eq 0) {
        Add-TicketNotesBullet -Builder $builder -Text "No evidence has been captured yet."
    }
    Add-TicketNotesLine -Builder $builder

    Add-TicketNotesLine -Builder $builder -Line "Likely Cause:"
    $problemChecks = @($checks | Where-Object { ([string]$_.Status) -in @("Warn", "Fail") })
    if ($problemChecks.Count -gt 0) {
        Add-TicketNotesBullet -Builder $builder -Text ("Likely related to: {0}" -f (($problemChecks | ForEach-Object { $_.Summary }) -join "; "))
    }
    elseif ($checks.Count -gt 0) {
        Add-TicketNotesBullet -Builder $builder -Text "No failing automated check has identified a likely cause yet."
    }
    else {
        Add-TicketNotesBullet -Builder $builder -Text "Likely cause is pending diagnostic evidence."
    }
    Add-TicketNotesLine -Builder $builder

    Add-TicketNotesLine -Builder $builder -Line "Next Steps:"
    $nextSteps = @()
    foreach ($check in $checks) {
        if ($check.PSObject.Properties.Name -contains "RecommendedNextSteps" -and $null -ne $check.RecommendedNextSteps) {
            $nextSteps += @($check.RecommendedNextSteps)
        }
    }

    $nextSteps = @($nextSteps | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
    if ($nextSteps.Count -gt 0) {
        foreach ($step in $nextSteps) {
            Add-TicketNotesBullet -Builder $builder -Text ([string]$step)
        }
    }
    else {
        Add-TicketNotesBullet -Builder $builder -Text "Run the relevant troubleshooting checks and document the result."
    }
    Add-TicketNotesLine -Builder $builder

    Add-TicketNotesLine -Builder $builder -Line "Customer-Facing Summary:"
    if ($problemChecks.Count -gt 0) {
        $customerNextAction = "continue troubleshooting with the captured evidence."
        if ($nextSteps.Count -gt 0) {
            $customerNextAction = [string]$nextSteps[0]
        }

        Add-TicketNotesBullet -Builder $builder -Text ("We reviewed the reported {0} issue and found evidence requiring follow-up. Next action: {1}" -f $Case.IssueType, $customerNextAction)
    }
    elseif ($checks.Count -gt 0) {
        Add-TicketNotesBullet -Builder $builder -Text ("We reviewed the reported {0} issue and the completed checks did not identify a current failure." -f $Case.IssueType)
    }
    else {
        Add-TicketNotesBullet -Builder $builder -Text ("We opened the {0} troubleshooting case and are gathering diagnostic evidence." -f $Case.IssueType)
    }

    return $builder.ToString().TrimEnd()
}

function ConvertTo-WorkbenchReportHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Case,

        [Parameter(Mandatory)]
        [string]$Markdown
    )

    $title = "MSP Troubleshooting Report - {0}" -f $Case.CaseId
    $encodedTitle = [System.Net.WebUtility]::HtmlEncode($title)
    $encodedMarkdown = [System.Net.WebUtility]::HtmlEncode($Markdown)

    return @"
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>$encodedTitle</title>
  <style>
    body { background: #10151c; color: #edf3f8; font-family: Segoe UI, Arial, sans-serif; margin: 32px; line-height: 1.5; }
    main { max-width: 980px; margin: 0 auto; }
    h1 { font-size: 24px; margin: 0 0 16px; }
    pre { white-space: pre-wrap; background: #171f29; border: 1px solid #2a3746; border-radius: 6px; padding: 18px; }
  </style>
</head>
<body>
  <main>
    <h1>$encodedTitle</h1>
    <pre>$encodedMarkdown</pre>
  </main>
</body>
</html>
"@
}

function Export-WorkbenchCaseEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Case
    )

    $caseId = [string]$Case.CaseId
    if (-not (Test-WorkbenchCaseId -CaseId $caseId)) {
        throw "Invalid case id."
    }

    $markdown = New-TicketNotesMarkdown -Case $Case
    $markdownPath = Get-WorkbenchExportFilePath -CaseId $caseId -FileName "ticket-notes.md"
    $reportPath = Get-WorkbenchExportFilePath -CaseId $caseId -FileName "report.html"
    $evidencePath = Get-WorkbenchExportFilePath -CaseId $caseId -FileName "evidence.json"
    $reportHtml = ConvertTo-WorkbenchReportHtml -Case $Case -Markdown $markdown
    $evidence = [PSCustomObject]@{
        CaseId     = $caseId
        ExportedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Case       = $Case
        Checks     = @($Case.Checks)
        Notes      = @($Case.Notes)
    }

    Set-Content -LiteralPath $markdownPath -Value $markdown -Encoding UTF8 -NoNewline -ErrorAction Stop
    Set-Content -LiteralPath $reportPath -Value $reportHtml -Encoding UTF8 -ErrorAction Stop
    Set-Content -LiteralPath $evidencePath -Value ($evidence | ConvertTo-Json -Depth 10 -ErrorAction Stop) -Encoding UTF8 -ErrorAction Stop

    [PSCustomObject]@{
        CaseId       = $caseId
        MarkdownPath = $markdownPath
        ReportPath   = $reportPath
        EvidencePath = $evidencePath
    }
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

if ($LibraryMode) {
    return
}

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
            elseif ($method -ieq "GET" -and $path -eq "/api/checks") {
                try {
                    $checks = @(Get-CheckCatalog | Select-Object CheckId, Name, Category, Script, Description, ReadOnly, Inputs)
                    Send-Json -Context $context -Body $checks
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
            elseif ($method -ieq "POST" -and $path -match '^/api/cases/([^/]+)/checks/([^/]+)/run$') {
                $caseId = [System.Uri]::UnescapeDataString($Matches[1])
                $checkId = [System.Uri]::UnescapeDataString($Matches[2])

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
                            $body = $null

                            try {
                                $body = Read-JsonRequestBody -Request $request
                                $requestIsValid = $true
                            }
                            catch {
                                Send-JsonError -Context $context -Message $_.Exception.Message -StatusCode 400
                            }

                            if ($requestIsValid) {
                                try {
                                    $checkResult = Invoke-WorkbenchCheck -CheckId $checkId -Body $body
                                    $currentChecks = @()
                                    if ($case.PSObject.Properties.Name -contains "Checks") {
                                        if ($null -ne $case.Checks) {
                                            $currentChecks = @($case.Checks)
                                        }
                                    }
                                    else {
                                        Add-Member -InputObject $case -MemberType NoteProperty -Name "Checks" -Value @()
                                    }

                                    $case.Checks = @($currentChecks + $checkResult)
                                    $case.UpdatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                                    Save-WorkbenchCase -Case $case -ExpectedCaseId $caseId | Out-Null
                                    Send-Json -Context $context -Body $case
                                }
                                catch {
                                    $statusCode = 500
                                    if ($_.Exception.Message -eq "Check not found.") {
                                        $statusCode = 404
                                    }

                                    Send-JsonError -Context $context -Message $_.Exception.Message -StatusCode $statusCode
                                }
                            }
                        }
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
            elseif ($method -ieq "POST" -and $path -match '^/api/cases/([^/]+)/generate-notes$') {
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
                            try {
                                $markdown = New-TicketNotesMarkdown -Case $case
                                if ($case.PSObject.Properties.Name -contains "GeneratedSummary") {
                                    $case.GeneratedSummary = $markdown
                                }
                                else {
                                    Add-Member -InputObject $case -MemberType NoteProperty -Name "GeneratedSummary" -Value $markdown
                                }

                                $case.UpdatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                                Save-WorkbenchCase -Case $case -ExpectedCaseId $caseId | Out-Null
                                Send-Json -Context $context -Body ([PSCustomObject]@{
                                    caseId   = $caseId
                                    markdown = $markdown
                                    case     = $case
                                })
                            }
                            catch {
                                Send-JsonError -Context $context -Message $_.Exception.Message -StatusCode 500
                            }
                        }
                    }
                }
            }
            elseif ($method -ieq "POST" -and $path -match '^/api/cases/([^/]+)/export$') {
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
                            try {
                                $markdown = New-TicketNotesMarkdown -Case $case
                                if ($case.PSObject.Properties.Name -contains "GeneratedSummary") {
                                    $case.GeneratedSummary = $markdown
                                }
                                else {
                                    Add-Member -InputObject $case -MemberType NoteProperty -Name "GeneratedSummary" -Value $markdown
                                }

                                $case.UpdatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                                Save-WorkbenchCase -Case $case -ExpectedCaseId $caseId | Out-Null
                                $export = Export-WorkbenchCaseEvidence -Case $case
                                Send-Json -Context $context -Body $export
                            }
                            catch {
                                Send-JsonError -Context $context -Message $_.Exception.Message -StatusCode 500
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
