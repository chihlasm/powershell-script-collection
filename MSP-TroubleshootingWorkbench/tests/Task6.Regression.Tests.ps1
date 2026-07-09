#Requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
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

function Import-WorkbenchFunctions {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)

    if ($parseErrors.Count -gt 0) {
        throw "Unable to parse workbench script: $($parseErrors[0].Message)"
    }

    $functions = $ast.FindAll({
        param($Node)
        $Node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $true)

    foreach ($function in $functions) {
        Invoke-Expression ("function global:{0} {1}" -f $function.Name, $function.Body.Extent.Text)
    }
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$workbenchRoot = Join-Path $repoRoot "MSP-TroubleshootingWorkbench"
$checksRoot = Join-Path $workbenchRoot "checks"
$manifestPath = Join-Path $checksRoot "manifest.json"
$lockoutCheckPath = Join-Path $checksRoot "Invoke-ADLockoutCheck.ps1"
$serverPath = Join-Path $workbenchRoot "Start-MSPTroubleshootingWorkbench.ps1"

$manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
$lockoutEntry = @($manifest.checks | Where-Object { $_.checkId -eq "ad.lockout" }) | Select-Object -First 1

Assert-True -Condition ($null -ne $lockoutEntry) -Message "Manifest includes ad.lockout."
Assert-True -Condition ($lockoutEntry.script -eq "Invoke-ADLockoutCheck.ps1") -Message "Manifest points ad.lockout at the wrapper script."
Assert-True -Condition (@($lockoutEntry.inputs) -contains "affectedUser") -Message "Manifest includes affectedUser input."
Assert-True -Condition (@($lockoutEntry.inputs) -contains "daysBack") -Message "Manifest includes daysBack input."
Assert-True -Condition (@($lockoutEntry.inputs) -contains "domainController") -Message "Manifest includes domainController input."

$tokens = $null
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile($lockoutCheckPath, [ref]$tokens, [ref]$parseErrors) | Out-Null
Assert-True -Condition ($parseErrors.Count -eq 0) -Message "AD lockout wrapper parses cleanly."

$wrapperSource = Get-Content -LiteralPath $lockoutCheckPath -Raw -ErrorAction Stop
Assert-True -Condition (($wrapperSource -match "Diagnose-ADAccountLockout\.ps1") -and ($wrapperSource -like "*Test-Path -LiteralPath `$diagnosticScript*")) -Message "Wrapper preflights the AD diagnostics script path."
Assert-True -Condition ($wrapperSource -match "Import-Module\s+ActiveDirectory") -Message "Wrapper preflights the ActiveDirectory module."

$tempRoot = Join-Path $env:TEMP ("WorkbenchTask6Tests_{0}" -f ([guid]::NewGuid().ToString("N")))
$tempChecksRoot = Join-Path $tempRoot "MSP-TroubleshootingWorkbench\checks"
New-Item -ItemType Directory -Path $tempChecksRoot -Force | Out-Null
$tempWrapperPath = Join-Path $tempChecksRoot "Invoke-ADLockoutCheck.ps1"
Copy-Item -LiteralPath $lockoutCheckPath -Destination $tempWrapperPath -Force

$result = & $tempWrapperPath -AffectedUser "jdoe" -DaysBack 3
Assert-True -Condition ($result.CheckId -eq "ad.lockout") -Message "Wrapper returns ad.lockout CheckId."
Assert-True -Condition ($result.Status -eq "Warn") -Message "Wrapper returns Warn instead of throwing when the AD diagnostics script is missing."
Assert-True -Condition ($result.Summary -match "diagnostics script") -Message "Wrapper warning summary names the missing diagnostics script."
Assert-True -Condition ($result.Error -eq "") -Message "Preflight warning does not populate a thrown-error value."

$expectedFields = @(
    "CheckId",
    "Name",
    "Category",
    "Status",
    "Summary",
    "Evidence",
    "RecommendedNextSteps",
    "RawOutput",
    "StartedAt",
    "FinishedAt",
    "Error"
)

foreach ($field in $expectedFields) {
    Assert-True -Condition ($result.PSObject.Properties.Name -contains $field) -Message "Wrapper result includes $field."
}

Import-WorkbenchFunctions -Path $serverPath

$runnerTempRoot = Join-Path $env:TEMP ("WorkbenchTask6RunnerTests_{0}" -f ([guid]::NewGuid().ToString("N")))
$runnerChecksRoot = Join-Path $runnerTempRoot "checks"
New-Item -ItemType Directory -Path $runnerChecksRoot -Force | Out-Null

try {
    $captureScript = Join-Path $runnerChecksRoot "Invoke-CaptureADLikeCheck.ps1"
    @'
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$AffectedUser,

    [Parameter(Mandatory)]
    [int]$DaysBack,

    [string[]]$DomainController
)

[PSCustomObject]@{
    CheckId = "test.adlike"
    Name = "AD-like Capture Check"
    Category = "Test"
    Status = "Pass"
    Summary = "Captured runner parameters."
    Evidence = @()
    RecommendedNextSteps = @()
    RawOutput = [PSCustomObject]@{
        AffectedUser = $AffectedUser
        DaysBack = $DaysBack
        DomainController = @($DomainController)
    }
    StartedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    FinishedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Error = ""
}
'@ | Set-Content -LiteralPath $captureScript -Encoding UTF8

    function Get-CheckCatalog {
        [PSCustomObject]@{
            CheckId     = "test.adlike"
            Name        = "AD-like Capture Check"
            Category    = "Test"
            Script      = "Invoke-CaptureADLikeCheck.ps1"
            Description = "Captures generic manifest input parameter forwarding."
            ReadOnly    = $true
            Inputs      = @("affectedUser", "daysBack", "domainController")
            ScriptPath  = $captureScript
        }
    }

    $runnerBody = [PSCustomObject]@{
        affectedUser     = "jdoe"
        daysBack         = 14
        domainController = "DC01, DC02"
    }

    $runnerResult = Invoke-WorkbenchCheck -CheckId "test.adlike" -Body $runnerBody -TimeoutSeconds 10
    Assert-True -Condition ($runnerResult.Status -eq "Pass") -Message "Runner executes AD-like check with manifest-defined inputs."
    Assert-True -Condition ($runnerResult.RawOutput.AffectedUser -eq "jdoe") -Message "Runner maps affectedUser to AffectedUser."
    Assert-True -Condition ($runnerResult.RawOutput.DaysBack -eq 14) -Message "Runner maps daysBack to DaysBack."
    Assert-True -Condition ((@($runnerResult.RawOutput.DomainController) -join "|") -eq "DC01|DC02") -Message "Runner maps comma-separated domainController to DomainController array."
}
finally {
    if (Test-Path -LiteralPath $runnerTempRoot) {
        Remove-Item -LiteralPath $runnerTempRoot -Recurse -Force
    }
}

if ($script:Failures.Count -gt 0) {
    throw ("Task 6 regression harness failed: {0}" -f ($script:Failures -join "; "))
}

if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
}

Write-Host "[PASS] Task 6 regression harness completed." -ForegroundColor Green
