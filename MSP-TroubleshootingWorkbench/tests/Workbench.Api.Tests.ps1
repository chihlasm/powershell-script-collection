#Requires -Version 5.1

<#
.SYNOPSIS
    End-to-end API test: boots a real server on a random port and exercises the
    full case lifecycle over HTTP, including the session-token gate.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

# Pin discovery to the shipped module path. A broken third-party module elsewhere on
# PSModulePath that exports wildcard cmdlets can shadow built-ins like Write-Host.
$env:PSModulePath = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\Modules"

$script:Failures = @()

function Assert-True {
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,

        [Parameter(Mandatory)]
        [string]$Message
    )

    if (-not $Condition) {
        $script:Failures += $Message
        Write-Host "[FAIL] $Message" -ForegroundColor Red
    }
    else {
        Write-Host "[PASS] $Message" -ForegroundColor Green
    }
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$serverPath = Join-Path $repoRoot "MSP-TroubleshootingWorkbench\Start-MSPTroubleshootingWorkbench.ps1"
$tempRoot = Join-Path $env:TEMP ("wb-api-{0}" -f ([guid]::NewGuid().ToString("N")))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
$port = Get-Random -Minimum 20000 -Maximum 40000
$baseUrl = "http://localhost:$port"
$serverProcess = $null

try {
    $serverProcess = Start-Process -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$serverPath`"", "-Port", $port, "-OutputPath", "`"$tempRoot`"", "-NoBrowserOpen") `
        -PassThru -WindowStyle Hidden

    # Wait up to 20s for the server to answer.
    $ready = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        try {
            $status = Invoke-RestMethod -Uri "$baseUrl/api/status" -TimeoutSec 2
            if ($status.appName) { $ready = $true; break }
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    }

    Assert-True -Condition $ready -Message "Server answers /api/status."
    if (-not $ready) { throw "Server never became ready; aborting." }

    # Scrape the session token from the served page.
    $page = (Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/").Content
    $tokenMatch = [regex]::Match($page, 'name="workbench-token" content="([0-9a-f]{32})"')
    Assert-True -Condition $tokenMatch.Success -Message "Served page contains an injected session token."
    $token = $tokenMatch.Groups[1].Value
    $headers = @{ "X-Workbench-Token" = $token }

    # POST without the token is rejected.
    $blockedStatus = 0
    try {
        Invoke-RestMethod -Method Post -Uri "$baseUrl/api/cases" -Body '{"clientName":"X","ticketNumber":"1","issueType":"Network"}' -ContentType "application/json" | Out-Null
    }
    catch {
        $blockedStatus = [int]$_.Exception.Response.StatusCode
    }
    Assert-True -Condition ($blockedStatus -eq 403) -Message "POST without token returns 403."

    # Full lifecycle with the token.
    $caseBody = '{"clientName":"Contoso","ticketNumber":"10545","issueType":"Network","affectedUser":"jdoe","affectedDevice":"","targetPath":"","targetAddress":"localhost"}'
    $case = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/cases" -Body $caseBody -ContentType "application/json" -Headers $headers
    Assert-True -Condition ($case.CaseId -match '^CASE-\d{8}-\d{6}$') -Message "Case creation returns a well-formed case id."

    # Invoke-RestMethod hands a JSON array to the pipeline as a single item on PS 5.1,
    # so @() around it yields a 1-element array of arrays. Flatten before counting.
    $checks = @(Invoke-RestMethod -Uri "$baseUrl/api/checks" | ForEach-Object { $_ })
    Assert-True -Condition ($checks.Count -ge 3) -Message "Check catalog lists at least three checks."

    $adCheck = @($checks | Where-Object { $_.CheckId -eq "ad.lockout" })
    Assert-True -Condition ($adCheck.Count -eq 1) -Message "Catalog includes ad.lockout."
    Assert-True -Condition ([int]$adCheck[0].TimeoutSeconds -gt 120) -Message "Catalog exposes a TimeoutSeconds above the AD child-process timeout."

    $runBody = ('{{"targetAddress":"localhost","port":"{0}"}}' -f $port)
    $updatedCase = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/cases/$($case.CaseId)/checks/network.quick/run" -Body $runBody -ContentType "application/json" -Headers $headers -TimeoutSec 120
    $lastCheck = @($updatedCase.Checks)[-1]
    Assert-True -Condition ($lastCheck.CheckId -eq "network.quick") -Message "Check run is recorded on the case."
    Assert-True -Condition ($null -ne $lastCheck.InputsUsed) -Message "Check result records the inputs used."
    Assert-True -Condition ([string]$lastCheck.InputsUsed.TargetAddress -eq "localhost") -Message "InputsUsed captures the target address."

    $noteCase = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/cases/$($case.CaseId)/notes" -Body '{"note":"User reports slow logins."}' -ContentType "application/json" -Headers $headers
    Assert-True -Condition (@($noteCase.Notes).Count -eq 1) -Message "Note is stored on the case."

    $notes = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/cases/$($case.CaseId)/generate-notes" -Body '{}' -ContentType "application/json" -Headers $headers
    Assert-True -Condition ($notes.markdown -match 'Ran Network Quick Check \(') -Message "Generated notes include the check inputs."
    Assert-True -Condition ($notes.markdown -notmatch '(?m)^- Target path:\s*$') -Message "Generated notes omit blank case fields."

    $export = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/cases/$($case.CaseId)/export" -Body '{}' -ContentType "application/json" -Headers $headers
    Assert-True -Condition (Test-Path -LiteralPath $export.MarkdownPath) -Message "Export writes ticket-notes.md."
    Assert-True -Condition (Test-Path -LiteralPath $export.ReportPath) -Message "Export writes report.html."
    Assert-True -Condition (Test-Path -LiteralPath $export.EvidencePath) -Message "Export writes evidence.json."
}
finally {
    if ($serverProcess -and -not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
    }

    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:Failures.Count -gt 0) {
    throw ("API integration tests failed: {0}" -f ($script:Failures -join "; "))
}

Write-Host "[PASS] API integration tests completed." -ForegroundColor Green
