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

function Test-IsScalarValue {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return $true
    }

    return (
        ($Value -is [string]) -or
        ($Value -is [bool]) -or
        ($Value -is [int]) -or
        ($Value -is [long]) -or
        ($Value -is [double]) -or
        ($Value -is [decimal])
    )
}

function Test-ObjectHasOnlyScalarLeaves {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return $true
    }

    if (Test-IsScalarValue -Value $Value) {
        return $true
    }

    if ($Value -is [System.Array]) {
        foreach ($item in @($Value)) {
            if (-not (Test-ObjectHasOnlyScalarLeaves -Value $item)) {
                return $false
            }
        }

        return $true
    }

    foreach ($property in @($Value.PSObject.Properties)) {
        if (-not (Test-IsScalarValue -Value $property.Value)) {
            return $false
        }
    }

    return $true
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

function Test-NetConnection {
    param(
        [string]$ComputerName,
        [int]$Port,
        [string]$InformationLevel,
        [System.Management.Automation.ActionPreference]$WarningAction
    )

    [PSCustomObject]@{
        ComputerName      = $ComputerName
        RemoteAddress    = [System.Net.IPAddress]::Parse("127.0.0.1")
        RemotePort       = $Port
        InterfaceAlias   = "Loopback"
        SourceAddress    = [PSCustomObject]@{
            IPAddress = "127.0.0.1"
            Adapter   = [PSCustomObject]@{
                Name = "Large object that must not be serialized"
            }
        }
        PingSucceeded    = $true
        TcpTestSucceeded = $true
    }
}

function Test-Connection {
    param(
        [string]$ComputerName,
        [int]$Count,
        [switch]$Quiet
    )

    return $true
}

function Resolve-DnsName {
    param([string]$Name)

    [PSCustomObject]@{
        Name      = $Name
        Type      = "A"
        IPAddress = "127.0.0.1"
        NameHost  = $null
    }
}

function Get-NetRoute {
    param([string]$DestinationPrefix)

    [PSCustomObject]@{
        DestinationPrefix = $DestinationPrefix
        NextHop           = "0.0.0.0"
        InterfaceAlias    = "Loopback"
        RouteMetric       = 1
        ifIndex           = 1
    }
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$workbenchRoot = Join-Path $repoRoot "MSP-TroubleshootingWorkbench"
$networkCheckPath = Join-Path $workbenchRoot "checks\Invoke-NetworkQuickCheck.ps1"
$serverPath = Join-Path $workbenchRoot "Start-MSPTroubleshootingWorkbench.ps1"

$networkResult = & $networkCheckPath -TargetAddress "localhost" -Port 443
Assert-True -Condition (Test-ObjectHasOnlyScalarLeaves -Value $networkResult.RawOutput.Tcp) -Message "network.quick RawOutput.Tcp contains scalar values only."

Import-WorkbenchFunctions -Path $serverPath

$tempRoot = Join-Path $env:TEMP ("WorkbenchTask4Tests_{0}" -f ([guid]::NewGuid().ToString("N")))
$tempChecks = Join-Path $tempRoot "checks"
New-Item -ItemType Directory -Path $tempChecks -Force | Out-Null

try {
    $hangScript = Join-Path $tempChecks "Invoke-HangingCheck.ps1"
    @'
#Requires -Version 5.1
Start-Sleep -Seconds 15
[PSCustomObject]@{
    CheckId = "test.hang"
    Name = "Hanging Check"
    Category = "Test"
    Status = "Pass"
    Summary = "Unexpected completion."
    Evidence = @()
    RecommendedNextSteps = @()
    RawOutput = [PSCustomObject]@{}
    StartedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    FinishedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Error = ""
}
'@ | Set-Content -LiteralPath $hangScript -Encoding UTF8

    function Get-CheckCatalog {
        [PSCustomObject]@{
            CheckId     = "test.hang"
            Name        = "Hanging Check"
            Category    = "Test"
            Script      = "Invoke-HangingCheck.ps1"
            Description = "Sleeps long enough to prove timeout behavior."
            ReadOnly    = $true
            Inputs      = @()
            ScriptPath  = $hangScript
        }
    }

    $body = [PSCustomObject]@{}
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $hangResult = Invoke-WorkbenchCheck -CheckId "test.hang" -Body $body -TimeoutSeconds 1
    $stopwatch.Stop()

    Assert-True -Condition ($stopwatch.Elapsed.TotalSeconds -lt 5) -Message "Invoke-WorkbenchCheck returns before a hanging check can block the server."
    Assert-True -Condition ($hangResult.Status -eq "Fail") -Message "Invoke-WorkbenchCheck returns a normalized failure result for timed out checks."
    Assert-True -Condition ($hangResult.Error -match "timed out") -Message "Timeout result includes a controlled error message."
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}

if ($script:Failures.Count -gt 0) {
    throw ("Task 4 regression harness failed: {0}" -f ($script:Failures -join "; "))
}

Write-Host "[PASS] Task 4 regression harness completed." -ForegroundColor Green
