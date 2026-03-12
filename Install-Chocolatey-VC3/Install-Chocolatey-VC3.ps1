#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs Chocolatey and configures the VC3 private MyGet repository source.

.DESCRIPTION
    - Installs the latest version of Chocolatey CLI
    - Adds the vc3protected MyGet source (priority 20)
    - Removes the legacy "streamedapps" source if present
    - Validates connectivity to the VC3 feed

.NOTES
    Run this script in an elevated (Administrator) PowerShell session.
    Updated: 2026-03-12
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# --- Configuration ---
$VC3SourceName     = 'vc3protected'
$VC3SourceUrl      = 'https://www.myget.org/F/vc3-choco-protected/auth/c1f6fbb4-259f-4b72-bdcf-7dfd14a47875/api/v2'
$VC3SourcePriority = 20
$LegacySource      = 'streamedapps'
$ChocoExePath      = 'C:\ProgramData\Chocolatey\bin\choco.exe'

# --- Helper ---
function Write-Step {
    param([string]$Message)
    Write-Host "`n>> $Message" -ForegroundColor Cyan
}

# ============================================================
# Step 1: Install Chocolatey (latest version)
# ============================================================
Write-Step 'Checking for existing Chocolatey installation...'

if (Test-Path $ChocoExePath) {
    $currentVersion = & $ChocoExePath --version 2>$null
    Write-Host "   Chocolatey $currentVersion is already installed." -ForegroundColor Yellow
    Write-Host '   Upgrading to latest version...' -ForegroundColor Yellow
    & $ChocoExePath upgrade chocolatey -y --no-progress | Out-Null
    $newVersion = & $ChocoExePath --version 2>$null
    Write-Host "   Chocolatey is now at version $newVersion." -ForegroundColor Green
}
else {
    Write-Step 'Installing Chocolatey (latest)...'
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

    # Refresh PATH for this session
    $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                [System.Environment]::GetEnvironmentVariable('Path', 'User')

    if (Test-Path $ChocoExePath) {
        $installedVersion = & $ChocoExePath --version 2>$null
        Write-Host "   Chocolatey $installedVersion installed successfully." -ForegroundColor Green
    }
    else {
        Write-Error 'Chocolatey installation failed. choco.exe not found at expected path.'
    }
}

# ============================================================
# Step 2: Remove legacy "streamedapps" source if present
# ============================================================
Write-Step "Checking for legacy '$LegacySource' source..."

$existingSources = & $ChocoExePath source list --limit-output 2>$null
if ($existingSources -match "^$LegacySource\|") {
    Write-Host "   Removing legacy '$LegacySource' source..." -ForegroundColor Yellow
    & $ChocoExePath source remove -n=$LegacySource | Out-Null
    Write-Host "   '$LegacySource' source removed." -ForegroundColor Green
}
else {
    Write-Host "   No '$LegacySource' source found. Nothing to remove." -ForegroundColor DarkGray
}

# ============================================================
# Step 3: Add VC3 protected source
# ============================================================
Write-Step "Configuring '$VC3SourceName' source..."

if ($existingSources -match "^$VC3SourceName\|") {
    Write-Host "   '$VC3SourceName' source already exists. Updating..." -ForegroundColor Yellow
    & $ChocoExePath source remove -n=$VC3SourceName | Out-Null
}

& $ChocoExePath source add `
    -n=$VC3SourceName `
    -s $VC3SourceUrl `
    -priority=$VC3SourcePriority

Write-Host "   '$VC3SourceName' source added (priority $VC3SourcePriority)." -ForegroundColor Green

# ============================================================
# Step 4: Validate connectivity to the VC3 feed
# ============================================================
Write-Step 'Testing connectivity to VC3 MyGet feed...'

try {
    $response = Invoke-WebRequest -Uri $VC3SourceUrl -UseBasicParsing -TimeoutSec 15
    if ($response.StatusCode -eq 200) {
        Write-Host '   Feed is reachable. Status: 200 OK' -ForegroundColor Green
    }
    else {
        Write-Host "   Feed returned status: $($response.StatusCode). Verify the URL and auth token." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "   WARNING: Could not reach the VC3 feed. Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host '   The source has been added but may not work until connectivity is resolved.' -ForegroundColor Red
}

# ============================================================
# Step 5: Summary
# ============================================================
Write-Step 'Final source configuration:'
& $ChocoExePath source list

Write-Host "`n>> Setup complete!" -ForegroundColor Green
Write-Host '   You can now install packages from the VC3 feed, e.g.:' -ForegroundColor DarkGray
Write-Host '   choco install <package-name> -s vc3protected' -ForegroundColor DarkGray
Write-Host ''