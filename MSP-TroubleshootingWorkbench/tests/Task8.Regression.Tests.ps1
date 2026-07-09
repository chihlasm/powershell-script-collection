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

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$workbenchRoot = Join-Path $repoRoot "MSP-TroubleshootingWorkbench"
$launcherRoot = Join-Path $workbenchRoot "launcher"
$launcherSourcePath = Join-Path $launcherRoot "MSPWorkbenchLauncher.cs"
$buildScriptPath = Join-Path $launcherRoot "build.ps1"
$readmePath = Join-Path $workbenchRoot "README.md"

Assert-True -Condition (Test-Path -LiteralPath $launcherSourcePath -PathType Leaf) -Message "C# launcher source exists."
Assert-True -Condition (Test-Path -LiteralPath $buildScriptPath -PathType Leaf) -Message "Launcher build script exists."

if (Test-Path -LiteralPath $launcherSourcePath -PathType Leaf) {
    $launcherSource = Get-Content -LiteralPath $launcherSourcePath -Raw -ErrorAction Stop
    Assert-True -Condition ($launcherSource -match "powershell\.exe") -Message "Launcher starts powershell.exe."
    Assert-True -Condition ($launcherSource -match "-NoProfile -ExecutionPolicy Bypass -File") -Message "Launcher uses the supported PowerShell startup flags."
    Assert-True -Condition ($launcherSource -match "Start-MSPTroubleshootingWorkbench\.ps1") -Message "Launcher targets the workbench PowerShell entry point."
    Assert-True -Condition ($launcherSource -match "AppDomain\.CurrentDomain\.BaseDirectory") -Message "Launcher resolves paths from the executable directory."
    Assert-True -Condition ($launcherSource -match "Directory\.GetParent") -Message "Launcher can also locate the entry point from a launcher subfolder build."
    Assert-True -Condition ($launcherSource -match "WorkingDirectory\s*=\s*exeDirectory") -Message "Launcher starts PowerShell with the executable directory as the working directory."
}

if (Test-Path -LiteralPath $buildScriptPath -PathType Leaf) {
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($buildScriptPath, [ref]$tokens, [ref]$parseErrors) | Out-Null
    Assert-True -Condition ($parseErrors.Count -eq 0) -Message "Launcher build script parses cleanly."

    $buildSource = Get-Content -LiteralPath $buildScriptPath -Raw -ErrorAction Stop
    Assert-True -Condition ($buildSource -match "#Requires -Version 5\.1") -Message "Build script declares PowerShell 5.1 requirement."
    Assert-True -Condition ($buildSource -match "\[CmdletBinding\(\)\]") -Message "Build script uses CmdletBinding."
    Assert-True -Condition ($buildSource -match '\[string\]\s*\$OutputPath') -Message "Build script exposes a typed OutputPath parameter."
    Assert-True -Condition ($buildSource -match "\.SYNOPSIS" -and $buildSource -match "\.DESCRIPTION" -and $buildSource -match "\.PARAMETER" -and $buildSource -match "\.EXAMPLE" -and $buildSource -match "\.NOTES") -Message "Build script includes comment-based help."
    Assert-True -Condition ($buildSource -match "Add-Type" -or $buildSource -match "csc\.exe") -Message "Build script uses Add-Type or csc.exe compiler support."
    Assert-True -Condition ($buildSource -match "MSPWorkbench\.exe") -Message "Build script outputs MSPWorkbench.exe."
    Assert-True -Condition ($buildSource -match '"PASS"' -and $buildSource -match '"WARN"' -and $buildSource -match '"FAIL"' -and $buildSource -match '"INFO"' -and $buildSource -match '\[\{0\}\]') -Message "Build script uses standard status prefixes."
}

$readme = Get-Content -LiteralPath $readmePath -Raw -ErrorAction Stop
Assert-True -Condition ($readme -match "MSPWorkbench\.exe") -Message "README documents the launcher executable."
Assert-True -Condition ($readme -match "Start-MSPTroubleshootingWorkbench\.ps1") -Message "README keeps the PowerShell entry point fallback documented."

if ($script:Failures.Count -gt 0) {
    throw ("Task 8 regression harness failed: {0}" -f ($script:Failures -join "; "))
}

Write-Host "[PASS] Task 8 regression harness completed." -ForegroundColor Green
