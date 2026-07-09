#Requires -Version 5.1
<#
.SYNOPSIS
Builds the MSP Troubleshooting Workbench launcher executable.

.DESCRIPTION
Compiles MSPWorkbenchLauncher.cs into MSPWorkbench.exe for the portable workbench folder. The script discovers a local .NET Framework csc.exe compiler at runtime and leaves the PowerShell entry point supported when no compiler is available.

.PARAMETER OutputPath
Directory where MSPWorkbench.exe should be written. Defaults to the portable workbench root.

.EXAMPLE
.\build.ps1

Builds MSPWorkbench.exe into the MSP-TroubleshootingWorkbench folder.

.EXAMPLE
.\build.ps1 -OutputPath C:\Temp\Workbench

Builds MSPWorkbench.exe into a custom output folder.

.NOTES
The generated launcher starts powershell.exe -NoProfile -ExecutionPolicy Bypass -File Start-MSPTroubleshootingWorkbench.ps1.
If no C# compiler is available, run Start-MSPTroubleshootingWorkbench.ps1 directly as the supported fallback.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"

function Write-Status {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("PASS", "WARN", "FAIL", "INFO")]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message
    )

    $color = switch ($Level) {
        "PASS" { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        "INFO" { "Cyan" }
    }

    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

function Get-CSharpCompilerPath {
    $candidatePaths = @(
        (Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
        (Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe"),
        (Join-Path $env:WINDIR "Microsoft.NET\Framework64\v3.5\csc.exe"),
        (Join-Path $env:WINDIR "Microsoft.NET\Framework\v3.5\csc.exe")
    )

    foreach ($candidatePath in $candidatePaths) {
        if (Test-Path -LiteralPath $candidatePath -PathType Leaf) {
            return $candidatePath
        }
    }

    $pathCompiler = Get-Command -Name "csc.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $pathCompiler) {
        return $pathCompiler.Source
    }

    return $null
}

$sourcePath = Join-Path $PSScriptRoot "MSPWorkbenchLauncher.cs"
if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    Write-Status -Level "FAIL" -Message ("Launcher source not found: {0}" -f $sourcePath)
    throw "Launcher source not found."
}

if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
    Write-Status -Level "INFO" -Message ("Creating output directory: {0}" -f $OutputPath)
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$resolvedOutputPath = (Resolve-Path -LiteralPath $OutputPath).Path
$outputExePath = Join-Path $resolvedOutputPath "MSPWorkbench.exe"
$compilerPath = Get-CSharpCompilerPath

if ([string]::IsNullOrWhiteSpace($compilerPath)) {
    Write-Status -Level "WARN" -Message "No csc.exe compiler was found. MSPWorkbench.exe was not built."
    Write-Status -Level "INFO" -Message "Fallback remains supported: run .\Start-MSPTroubleshootingWorkbench.ps1 from the workbench folder."
    return
}

Write-Status -Level "INFO" -Message ("Using compiler: {0}" -f $compilerPath)
Write-Status -Level "INFO" -Message ("Writing launcher: {0}" -f $outputExePath)

$compilerArguments = @(
    "/nologo",
    "/target:winexe",
    "/optimize+",
    "/platform:anycpu",
    "/reference:System.dll",
    "/reference:System.Windows.Forms.dll",
    ("/out:{0}" -f $outputExePath),
    $sourcePath
)

$compilerOutput = & $compilerPath @compilerArguments 2>&1
if ($LASTEXITCODE -ne 0) {
    foreach ($line in @($compilerOutput)) {
        Write-Status -Level "FAIL" -Message ([string]$line)
    }

    throw ("Compiler failed with exit code {0}." -f $LASTEXITCODE)
}

if (-not (Test-Path -LiteralPath $outputExePath -PathType Leaf)) {
    Write-Status -Level "FAIL" -Message "Compiler finished but MSPWorkbench.exe was not created."
    throw "Launcher executable was not created."
}

Write-Status -Level "PASS" -Message ("Built {0}" -f $outputExePath)
