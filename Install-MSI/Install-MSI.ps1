#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Installs an MSI package from a network share.

.DESCRIPTION
    Discovers and installs MSI packages from a UNC network share path. The script copies
    the MSI locally before installing for reliability, supports transform files (.mst),
    custom MSI properties, and additional msiexec arguments. Works both interactively
    and silently for RMM deployment.

.PARAMETER SharePath
    UNC path to the folder containing the MSI file(s). Example: \\server\share\apps

.PARAMETER MsiName
    Optional filter or wildcard to select a specific MSI. Example: Agent*.msi

.PARAMETER TransformPath
    Optional path to an MST transform file (UNC or local).

.PARAMETER MsiProperties
    Optional array of MSI property strings in KEY=VALUE format.
    Example: -MsiProperties "INSTALLDIR=C:\MyApp", "ADDLOCAL=ALL"

.PARAMETER AdditionalArguments
    Optional raw string of additional msiexec arguments.

.PARAMETER Silent
    Suppress all interactive prompts. Required for RMM/unattended deployment.
    When used with multiple MSIs found, -MsiName must be specified to avoid ambiguity.

.PARAMETER WhatIf
    Preview mode. Shows what the script would do without making changes.

.PARAMETER LogFile
    Override the default script log path. Default: C:\Temp\Logs\Install-MSI.log

.EXAMPLE
    .\Install-MSI.ps1 -SharePath "\\fileserver\software\7zip"
    Discovers and installs the MSI from the specified share interactively.

.EXAMPLE
    .\Install-MSI.ps1 -SharePath "\\fileserver\software" -MsiName "Agent*.msi" -Silent
    Silently installs the matching MSI (for RMM deployment).

.EXAMPLE
    .\Install-MSI.ps1 -SharePath "\\fileserver\software" -TransformPath "\\fileserver\software\custom.mst" -MsiProperties "INSTALLDIR=D:\Apps"
    Installs with a transform file and custom install directory.

.EXAMPLE
    .\Install-MSI.ps1 -SharePath "\\fileserver\software\app" -WhatIf
    Shows what would be installed without making any changes.
#>

param (
    [Parameter(Mandatory = $true, HelpMessage = "UNC path to the folder containing MSI file(s)")]
    [string]$SharePath,

    [string]$MsiName,

    [string]$TransformPath,

    [string[]]$MsiProperties,

    [string]$AdditionalArguments,

    [switch]$Silent,

    [switch]$WhatIf,

    [string]$LogFile = "C:\Temp\Logs\Install-MSI.log"
)

# ── Helper Functions ──────────────────────────────────────────────────────────

function Write-Log {
    param (
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp [$Level] $Message"

    # Always write to log file
    $entry | Out-File -FilePath $LogFile -Append -Encoding UTF8

    # Write to console unless silent
    if (-not $Silent) {
        switch ($Level) {
            "ERROR" { Write-Host $entry -ForegroundColor Red }
            "WARN"  { Write-Host $entry -ForegroundColor Yellow }
            default { Write-Host $entry }
        }
    }
}

# ── Main Script ───────────────────────────────────────────────────────────────

$tempDir = "C:\Temp\Install-MSI"
$exitCode = 1

try {
    # Ensure log directory exists
    $logDir = Split-Path -Path $LogFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    Write-Log "=========================================="
    Write-Log "Install-MSI started"
    Write-Log "SharePath: $SharePath"
    Write-Log "=========================================="

    # ── Validate share access ─────────────────────────────────────────────
    if (-not (Test-Path $SharePath)) {
        Write-Log "Cannot access share path: $SharePath" -Level ERROR
        Write-Log "Verify the path exists and this machine has network access." -Level ERROR
        exit 1
    }

    # ── Discover MSI files ────────────────────────────────────────────────
    $filter = if ($MsiName) { $MsiName } else { "*.msi" }
    $msiFiles = @(Get-ChildItem -Path $SharePath -Filter $filter -File -ErrorAction Stop)

    if ($msiFiles.Count -eq 0) {
        Write-Log "No MSI files found in '$SharePath' matching filter '$filter'" -Level ERROR
        exit 1
    }

    Write-Log "Found $($msiFiles.Count) MSI file(s)"

    # ── Select MSI ────────────────────────────────────────────────────────
    $selectedMsi = $null

    if ($msiFiles.Count -eq 1) {
        $selectedMsi = $msiFiles[0]
        Write-Log "Auto-selected: $($selectedMsi.Name)"
    }
    elseif ($Silent) {
        Write-Log "Multiple MSIs found and -Silent is set. Use -MsiName to specify which MSI to install." -Level ERROR
        foreach ($msi in $msiFiles) {
            Write-Log "  Available: $($msi.Name)" -Level ERROR
        }
        exit 1
    }
    else {
        Write-Log "Multiple MSI files found. Please select one:"
        for ($i = 0; $i -lt $msiFiles.Count; $i++) {
            $size = [math]::Round($msiFiles[$i].Length / 1MB, 1)
            Write-Host "  [$($i + 1)] $($msiFiles[$i].Name) ($size MB)"
        }
        Write-Host ""

        do {
            $selection = Read-Host "Enter selection (1-$($msiFiles.Count))"
            $selNum = 0
            $valid = [int]::TryParse($selection, [ref]$selNum) -and $selNum -ge 1 -and $selNum -le $msiFiles.Count
            if (-not $valid) {
                Write-Host "Invalid selection. Enter a number between 1 and $($msiFiles.Count)." -ForegroundColor Yellow
            }
        } while (-not $valid)

        $selectedMsi = $msiFiles[$selNum - 1]
        Write-Log "User selected: $($selectedMsi.Name)"
    }

    # ── Copy MSI locally ──────────────────────────────────────────────────
    if (-not (Test-Path $tempDir)) {
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
    }

    $localMsiPath = Join-Path $tempDir $selectedMsi.Name
    Write-Log "Copying MSI to $localMsiPath"
    Copy-Item -Path $selectedMsi.FullName -Destination $localMsiPath -Force -ErrorAction Stop
    Write-Log "Copy complete"

    # Copy transform file if specified
    $localMstPath = $null
    if ($TransformPath) {
        if (-not (Test-Path $TransformPath)) {
            Write-Log "Transform file not found: $TransformPath" -Level ERROR
            exit 1
        }
        $mstFileName = Split-Path -Path $TransformPath -Leaf
        $localMstPath = Join-Path $tempDir $mstFileName
        Write-Log "Copying transform file to $localMstPath"
        Copy-Item -Path $TransformPath -Destination $localMstPath -Force -ErrorAction Stop
    }

    # ── Build msiexec arguments ───────────────────────────────────────────
    $msiLogName = [System.IO.Path]::GetFileNameWithoutExtension($selectedMsi.Name)
    $msiLogPath = Join-Path (Split-Path $LogFile -Parent) "$msiLogName-install.log"

    $msiArgs = @(
        "/i `"$localMsiPath`""
        "/qn"
        "/norestart"
        "/l*v `"$msiLogPath`""
    )

    if ($localMstPath) {
        $msiArgs += "TRANSFORMS=`"$localMstPath`""
    }

    if ($MsiProperties) {
        foreach ($prop in $MsiProperties) {
            $msiArgs += $prop
        }
    }

    if ($AdditionalArguments) {
        $msiArgs += $AdditionalArguments
    }

    $argString = $msiArgs -join " "
    Write-Log "msiexec command: msiexec.exe $argString"

    # ── WhatIf check ──────────────────────────────────────────────────────
    if ($WhatIf) {
        Write-Log "WhatIf: Would execute — msiexec.exe $argString"
        Write-Log "WhatIf: No changes made."
        $exitCode = 0
        return
    }

    # ── Execute installation ──────────────────────────────────────────────
    Write-Log "Starting MSI installation..."
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $argString -Wait -PassThru -NoNewWindow
    $exitCode = $process.ExitCode

    switch ($exitCode) {
        0    { Write-Log "Installation completed successfully (exit code 0)" }
        3010 { Write-Log "Installation completed successfully — reboot required (exit code 3010)" -Level WARN }
        1602 { Write-Log "Installation cancelled by user (exit code 1602)" -Level WARN }
        1603 { Write-Log "Fatal error during installation (exit code 1603). Check MSI log: $msiLogPath" -Level ERROR }
        1618 { Write-Log "Another installation is in progress (exit code 1618)" -Level ERROR }
        default { Write-Log "Installation finished with exit code $exitCode. Check MSI log: $msiLogPath" -Level WARN }
    }
}
catch [System.UnauthorizedAccessException] {
    Write-Log "Access denied: $($_.Exception.Message)" -Level ERROR
    Write-Log "Ensure the script is running with administrator privileges and has access to the share." -Level ERROR
}
catch [System.IO.IOException] {
    Write-Log "I/O error: $($_.Exception.Message)" -Level ERROR
    Write-Log "Check network connectivity and disk space." -Level ERROR
}
catch {
    Write-Log "Unexpected error: $($_.Exception.Message)" -Level ERROR
}
finally {
    # ── Cleanup ───────────────────────────────────────────────────────────
    if (Test-Path $tempDir) {
        Write-Log "Cleaning up temp files in $tempDir"
        try {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction Stop
            Write-Log "Cleanup complete"
        }
        catch {
            Write-Log "Could not remove temp directory: $($_.Exception.Message)" -Level WARN
        }
    }

    Write-Log "Install-MSI finished with exit code $exitCode"
    Write-Log "=========================================="
    exit $exitCode
}
