#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Uninstalls Adobe Acrobat products from a Citrix VDA environment and optionally installs a replacement package.

.DESCRIPTION
    This script performs the following actions:
    1. Detects Adobe Acrobat product installations using WMI and registry
    2. Uninstalls Adobe Acrobat products using MSI uninstallation (preserves other Adobe products like Creative Cloud)
    3. Performs cleanup of remaining Acrobat files and registry entries
    4. Optionally installs a replacement Adobe Acrobat package from a network share
    5. Designed for Citrix Virtual Desktop Agent environments

.PARAMETER Force
    Forces uninstallation even if Adobe processes are running.

.PARAMETER InstallPackage
    Path to Adobe Acrobat installation package (MSI/EXE) to install after uninstallation.
    Supports tab completion for local paths and UNC paths.

.PARAMETER DownloadUrl
    Direct download URL for Adobe Acrobat enterprise installer (ZIP or EXE file).
    The script will automatically download, extract (if ZIP), and install the package.

.EXAMPLE
    .\Migrate-AdobeProducts.ps1 -InstallPackage "\\server\share\AdobeAcrobat.msi"

.EXAMPLE
    .\Migrate-AdobeProducts.ps1 -Force -InstallPackage "\\server\share\AdobeAcrobat.msi"

.EXAMPLE
    .\Migrate-AdobeProducts.ps1 -InstallPackage "\\server\share\AdobeAcrobatSetup.exe"
#>

param (
    [Parameter(Mandatory = $false)]
    [switch]$Force,
    [Parameter(Mandatory = $false)]
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        Get-ChildItem "$wordToComplete*" | Where-Object { !$_.PSIsContainer } | ForEach-Object { $_.FullName } | Sort-Object
    })]
    [string]$InstallPackage,
    [Parameter(Mandatory = $false)]
    [ValidateScript({$_ -match '^https?://'})]
    [string]$DownloadUrl
)

# Function to write log messages
function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message"
}

# Function to check if Adobe products are installed
function Get-AdobeProducts {
    Write-Log "Checking for Adobe product installations..."

    $adobeProducts = @()

    # Check using WMI for installed products
    $wmiProducts = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*Adobe Acrobat*" -and $_.Name -notlike "*Adobe Refresh Manager*" }

    if ($wmiProducts) {
        Write-Log "Found Adobe products via WMI:"
        foreach ($product in $wmiProducts) {
            Write-Log "  - $($product.Name) (Version: $($product.Version), ProductCode: $($product.IdentifyingNumber))"
            $adobeProducts += @{
                Name = $product.Name
                Version = $product.Version
                ProductCode = $product.IdentifyingNumber
                Type = "WMI"
                Object = $product
            }
        }
    }

    # Also check registry for Adobe installations
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            $adobeKeys = Get-ChildItem $path -ErrorAction SilentlyContinue |
                Where-Object {
                    $displayName = (Get-ItemProperty -Path $_.PSPath -Name DisplayName -ErrorAction SilentlyContinue).DisplayName
                    $displayName -like "*Adobe Acrobat*" -and $displayName -notlike "*Adobe Refresh Manager*"
                }

            if ($adobeKeys) {
                Write-Log "Found Adobe products in registry:"
                foreach ($key in $adobeKeys) {
                    $properties = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
                    Write-Log "  - $($properties.DisplayName) (Version: $($properties.DisplayVersion), UninstallString: $($properties.UninstallString))"
                    $adobeProducts += @{
                        Name = $properties.DisplayName
                        Version = $properties.DisplayVersion
                        UninstallString = $properties.UninstallString
                        Type = "Registry"
                        Object = $key
                    }
                }
            }
        }
    }

    if ($adobeProducts.Count -eq 0) {
        Write-Log "No Adobe products detected"
        return $null
    }

    Write-Log "Total Adobe products found: $($adobeProducts.Count)"
    return $adobeProducts
}

# Function to check if Adobe processes are running
function Test-AdobeProcessesRunning {
    $adobeProcesses = Get-Process -Name "*Adobe*" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notlike "*AdobeARM*" -and $_.Name -notlike "*AdobeIPCBroker*" }

    if ($adobeProcesses) {
        Write-Log "Adobe processes are currently running:"
        foreach ($process in $adobeProcesses) {
            Write-Log "  - $($process.Name) (PID: $($process.Id))"
        }
        return $true
    }
    return $false
}

# Function to stop Adobe processes
function Stop-AdobeProcesses {
    Write-Log "Stopping Adobe processes..."
    try {
        $adobeProcesses = Get-Process -Name "*Adobe*" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notlike "*AdobeARM*" -and $_.Name -notlike "*AdobeIPCBroker*" }

        foreach ($process in $adobeProcesses) {
            Write-Log "Stopping process: $($process.Name) (PID: $($process.Id))"
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 5
        Write-Log "Adobe processes stopped"
    }
    catch {
        Write-Log "Error stopping Adobe processes: $_"
        throw
    }
}

# Function to uninstall Adobe product using MSI
function Uninstall-AdobeMSI {
    param ([string]$ProductCode, [string]$ProductName)

    Write-Log "Uninstalling $ProductName using MSI (ProductCode: $ProductCode)..."

    try {
        $logFile = "C:\temp\Adobe_Uninstall_$((Get-Date).ToString('yyyyMMdd_HHmmss')).log"
        $arguments = "/x $ProductCode /quiet /norestart /l*v `"$logFile`""
        Write-Log "Running: msiexec.exe $arguments"

        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru -NoNewWindow

        if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
            Write-Log "MSI uninstallation completed successfully (Exit code: $($process.ExitCode))"
            return $true
        }
        else {
            Write-Log "MSI uninstallation failed with exit code: $($process.ExitCode)"
            Write-Log "Check log file: $logFile"
            return $false
        }
    }
    catch {
        Write-Log "Error during MSI uninstallation: $_"
        return $false
    }
}

# Function to uninstall Adobe product using registry uninstall string
function Uninstall-AdobeRegistry {
    param ([string]$UninstallString, [string]$ProductName)

    Write-Log "Uninstalling $ProductName using registry uninstall string..."

    try {
        # Parse the uninstall string - it might be msiexec or setup.exe
        if ($UninstallString -match "msiexec\.exe") {
            # Extract product code from msiexec command
            if ($UninstallString -match "/x\s*(\{[^}]+\})") {
                $productCode = $matches[1]
                return Uninstall-AdobeMSI -ProductCode $productCode -ProductName $ProductName
            }
        }
        elseif ($UninstallString -match "setup\.exe|Adobe.*\.exe") {
            # Run the setup.exe with uninstall arguments
            Write-Log "Running uninstall command: $UninstallString"
            $process = Start-Process -FilePath $UninstallString -ArgumentList "/s /uninstall" -Wait -PassThru -NoNewWindow

            if ($process.ExitCode -eq 0) {
                Write-Log "Setup uninstallation completed successfully"
                return $true
            }
            else {
                Write-Log "Setup uninstallation failed with exit code: $($process.ExitCode)"
                return $false
            }
        }
        else {
            Write-Log "Unknown uninstall string format: $UninstallString"
            return $false
        }
    }
    catch {
        Write-Log "Error during registry uninstallation: $_"
        return $false
    }
}

# Function to uninstall all Adobe products
function Uninstall-AllAdobeProducts {
    param ([array]$AdobeProducts)

    Write-Log "Starting uninstallation of all Adobe products..."

    $uninstallResults = @()
    $overallSuccess = $true

    foreach ($product in $AdobeProducts) {
        Write-Log "Processing: $($product.Name)"

        $success = $false

        if ($product.Type -eq "WMI") {
            # WMI object - use MSI uninstall
            $success = Uninstall-AdobeMSI -ProductCode $product.ProductCode -ProductName $product.Name
        }
        elseif ($product.Type -eq "Registry") {
            # Registry key - use uninstall string
            if ($product.UninstallString) {
                $success = Uninstall-AdobeRegistry -UninstallString $product.UninstallString -ProductName $product.Name
            }
            else {
                Write-Log "No uninstall string found for $($product.Name)"
            }
        }

        $uninstallResults += @{
            Name = $product.Name
            Success = $success
        }

        if (-not $success) {
            $overallSuccess = $false
        }
    }

    Write-Log "Uninstallation summary:"
    foreach ($result in $uninstallResults) {
        $status = if ($result.Success) { "SUCCESS" } else { "FAILED" }
        Write-Log "  - $($result.Name): $status"
    }

    return $overallSuccess
}

# Function to clean up Adobe remnants
function Remove-AdobeRemnants {
    Write-Log "Cleaning up Adobe remnants..."

    # Common Adobe installation paths
    $adobePaths = @(
        "${env:ProgramFiles}\Adobe",
        "${env:ProgramFiles(x86)}\Adobe",
        "$env:APPDATA\Adobe",
        "$env:LOCALAPPDATA\Adobe",
        "$env:ALLUSERSPROFILE\Adobe"
    )

    foreach ($path in $adobePaths) {
        if (Test-Path $path) {
            try {
                Write-Log "Removing directory: $path"
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                Write-Log "Successfully removed: $path"
            }
            catch {
                Write-Log "Warning: Could not remove $path - $_"
            }
        }
    }

    # Clean up registry entries
    $registryCleanupPaths = @(
        "HKCU:\Software\Adobe",
        "HKLM:\SOFTWARE\Adobe",
        "HKLM:\SOFTWARE\WOW6432Node\Adobe"
    )

    foreach ($regPath in $registryCleanupPaths) {
        if (Test-Path $regPath) {
            try {
                Write-Log "Removing registry key: $regPath"
                Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
                Write-Log "Successfully removed registry key: $regPath"
            }
            catch {
                Write-Log "Warning: Could not remove registry key $regPath - $_"
            }
        }
    }

    Write-Log "Cleanup completed"
}

# Function to set permissions on PDF file association registry key
function Set-PdfFileAssociationPermissions {
    Write-Log "Setting permissions on PDF file association registry key..."

    $pdfKey = "HKCR:\.pdf"

    if (Test-Path $pdfKey) {
        try {
            Write-Log "Granting Administrators full control on $pdfKey"

            # Get the current ACL
            $acl = Get-Acl $pdfKey

            # Create a new rule for Administrators with FullControl
            $adminGroup = New-Object System.Security.Principal.NTAccount("Administrators")
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
                $adminGroup,
                "FullControl",
                "ContainerInherit,ObjectInherit",
                "None",
                "Allow"
            )

            # Add the rule to the ACL
            $acl.SetAccessRule($rule)

            # Apply the ACL to the registry key
            Set-Acl -Path $pdfKey -AclObject $acl

            Write-Log "Successfully granted Administrators full control on $pdfKey"
        }
        catch {
            Write-Log "Warning: Could not set permissions on $pdfKey - $_"
        }
    }
    else {
        Write-Log "PDF file association key $pdfKey does not exist - skipping permission setting"
    }
}

# Function to check if Citrix VDA is installed
function Test-CitrixVDAInstalled {
    $citrixPaths = @(
        "${env:ProgramFiles}\Citrix",
        "${env:ProgramFiles(x86)}\Citrix",
        "HKLM:\SOFTWARE\Citrix",
        "HKLM:\SOFTWARE\WOW6432Node\Citrix"
    )

    foreach ($path in $citrixPaths) {
        if (Test-Path $path) {
            Write-Log "Citrix VDA detected"
            return $true
        }
    }

    Write-Log "Citrix VDA not detected - install mode commands will be skipped"
    return $false
}

# Function to change Citrix server to install mode
function Set-CitrixInstallMode {
    Write-Log "Changing Citrix server to install mode..."

    try {
        # Try "change user /install" as specified by user
        try {
            Write-Log "Trying change user /install"
            $process = Start-Process -FilePath "change" -ArgumentList "user", "/install" -Wait -PassThru -NoNewWindow -ErrorAction Stop
            if ($process.ExitCode -eq 0) {
                Write-Log "Citrix server set to install mode using change user /install"
                return $true
            }
        } catch {
            Write-Log "change user /install failed, trying other methods"
        }

        # Try running changemode directly (may be in PATH)
        try {
            Write-Log "Trying changemode /install directly"
            $process = Start-Process -FilePath "changemode" -ArgumentList "/install" -Wait -PassThru -NoNewWindow -ErrorAction Stop
            if ($process.ExitCode -eq 0) {
                Write-Log "Citrix server set to install mode using changemode (PATH)"
                return $true
            }
        } catch {
            Write-Log "changemode not found in PATH, trying other methods"
        }

        # Use Citrix PowerShell cmdlets if available
        if (Get-Command -Name "Set-XAServerMode" -ErrorAction SilentlyContinue) {
            Write-Log "Using Citrix PowerShell cmdlet: Set-XAServerMode -Mode Install"
            Set-XAServerMode -Mode Install
            Write-Log "Citrix server set to install mode using PowerShell cmdlet"
            return $true
        }
        # Fallback to changemode.exe
        elseif (Test-Path "${env:ProgramFiles}\Citrix\System32\changemode.exe") {
            Write-Log "Using changemode.exe to set install mode"
            $process = Start-Process -FilePath "${env:ProgramFiles}\Citrix\System32\changemode.exe" -ArgumentList "install" -Wait -PassThru -NoNewWindow
            if ($process.ExitCode -eq 0) {
                Write-Log "Citrix server set to install mode using changemode.exe"
                return $true
            }
            else {
                Write-Log "Failed to set install mode using changemode.exe (Exit code: $($process.ExitCode))"
                return $false
            }
        }
        elseif (Test-Path "${env:ProgramFiles(x86)}\Citrix\System32\changemode.exe") {
            Write-Log "Using changemode.exe (x86) to set install mode"
            $process = Start-Process -FilePath "${env:ProgramFiles(x86)}\Citrix\System32\changemode.exe" -ArgumentList "install" -Wait -PassThru -NoNewWindow
            if ($process.ExitCode -eq 0) {
                Write-Log "Citrix server set to install mode using changemode.exe (x86)"
                return $true
            }
            else {
                Write-Log "Failed to set install mode using changemode.exe (x86) (Exit code: $($process.ExitCode))"
                return $false
            }
        }
        else {
            Write-Log "Warning: Citrix changemode.exe not found. Installing in execute mode may cause issues."
            Write-Log "Recommendation: Manually set server to install mode before running this script."
            return $false
        }
    }
    catch {
        Write-Log "Error setting Citrix install mode: $_"
        Write-Log "Installation will proceed in current mode"
        return $false
    }
}

# Function to change Citrix server back to execute mode
function Set-CitrixExecuteMode {
    Write-Log "Changing Citrix server back to execute mode..."

    try {
        # Try "change user /execute" as specified by user
        try {
            Write-Log "Trying change user /execute"
            $process = Start-Process -FilePath "change" -ArgumentList "user", "/execute" -Wait -PassThru -NoNewWindow -ErrorAction Stop
            if ($process.ExitCode -eq 0) {
                Write-Log "Citrix server set to execute mode using change user /execute"
                return $true
            }
        } catch {
            Write-Log "change user /execute failed, trying other methods"
        }

        # Try running changemode directly (may be in PATH)
        try {
            Write-Log "Trying changemode /execute directly"
            $process = Start-Process -FilePath "changemode" -ArgumentList "/execute" -Wait -PassThru -NoNewWindow -ErrorAction Stop
            if ($process.ExitCode -eq 0) {
                Write-Log "Citrix server set to execute mode using changemode (PATH)"
                return $true
            }
        } catch {
            Write-Log "changemode not found in PATH, trying other methods"
        }

        # Use Citrix PowerShell cmdlets if available
        if (Get-Command -Name "Set-XAServerMode" -ErrorAction SilentlyContinue) {
            Write-Log "Using Citrix PowerShell cmdlet: Set-XAServerMode -Mode Execute"
            Set-XAServerMode -Mode Execute
            Write-Log "Citrix server set to execute mode using PowerShell cmdlet"
            return $true
        }
        # Fallback to changemode.exe
        elseif (Test-Path "${env:ProgramFiles}\Citrix\System32\changemode.exe") {
            Write-Log "Using changemode.exe to set execute mode"
            $process = Start-Process -FilePath "${env:ProgramFiles}\Citrix\System32\changemode.exe" -ArgumentList "execute" -Wait -PassThru -NoNewWindow
            if ($process.ExitCode -eq 0) {
                Write-Log "Citrix server set to execute mode using changemode.exe"
                return $true
            }
            else {
                Write-Log "Failed to set execute mode using changemode.exe (Exit code: $($process.ExitCode))"
                return $false
            }
        }
        elseif (Test-Path "${env:ProgramFiles(x86)}\Citrix\System32\changemode.exe") {
            Write-Log "Using changemode.exe (x86) to set execute mode"
            $process = Start-Process -FilePath "${env:ProgramFiles(x86)}\Citrix\System32\changemode.exe" -ArgumentList "execute" -Wait -PassThru -NoNewWindow
            if ($process.ExitCode -eq 0) {
                Write-Log "Citrix server set to execute mode using changemode.exe (x86)"
                return $true
            }
            else {
                Write-Log "Failed to set execute mode using changemode.exe (x86) (Exit code: $($process.ExitCode))"
                return $false
            }
        }
        else {
            Write-Log "Warning: Citrix changemode.exe not found. Server may remain in install mode."
            Write-Log "Recommendation: Manually set server back to execute mode after installation."
            return $false
        }
    }
    catch {
        Write-Log "Error setting Citrix execute mode: $_"
        Write-Log "Server may remain in install mode - manual intervention may be required"
        return $false
    }
}

# Function to install replacement Adobe package
function Install-AdobePackage {
    param ([string]$PackagePath)

    Write-Log "Installing replacement Adobe package from: $PackagePath"

    if (-not (Test-Path $PackagePath)) {
        Write-Log "Error: Package file not found at $PackagePath"
        return $false
    }

    $citrixVDAInstalled = Test-CitrixVDAInstalled
    $installModeSet = $false

    try {
        # Set Citrix server to install mode if Citrix VDA is detected
        if ($citrixVDAInstalled) {
            $installModeSet = Set-CitrixInstallMode
        }

        $extension = [System.IO.Path]::GetExtension($PackagePath).ToLower()

        if ($extension -eq ".msi") {
            # MSI installation
            $logFile = "C:\temp\Adobe_Install_$((Get-Date).ToString('yyyyMMdd_HHmmss')).log"
            $installArgs = "/i `"$PackagePath`" /l*v `"$logFile`""
            Write-Log "Running: msiexec.exe $installArgs"

            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru -NoNewWindow

            if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
                Write-Log "MSI installation completed successfully (Exit code: $($process.ExitCode))"
                $installSuccess = $true
            }
            else {
                Write-Log "MSI installation failed with exit code: $($process.ExitCode)"
                Write-Log "Check log file: $logFile"
                $installSuccess = $false
            }
        }
        elseif ($extension -eq ".exe") {
            # EXE installation
            Write-Log "Running: $PackagePath"
            $process = Start-Process -FilePath $PackagePath -Wait -PassThru -NoNewWindow

            if ($process.ExitCode -eq 0) {
                Write-Log "EXE installation completed successfully"
                $installSuccess = $true
            }
            else {
                Write-Log "EXE installation failed with exit code: $($process.ExitCode)"
                $installSuccess = $false
            }
        }
        else {
            Write-Log "Error: Unsupported package type: $extension"
            $installSuccess = $false
        }

        # Set Citrix server back to execute mode if it was changed
        if ($citrixVDAInstalled -and $installModeSet) {
            Set-CitrixExecuteMode
        }

        return $installSuccess
    }
    catch {
        Write-Log "Error during package installation: $_"

        # Attempt to set back to execute mode even on failure
        if ($citrixVDAInstalled -and $installModeSet) {
            Write-Log "Attempting to set server back to execute mode after installation error..."
            Set-CitrixExecuteMode
        }

        return $false
    }
}

# Main script execution
try {
    Write-Log "Starting Adobe products uninstallation script for Citrix VDA"

    # Handle download URL if provided
    if ($DownloadUrl) {
        $urlExtension = [System.IO.Path]::GetExtension($DownloadUrl).ToLower()
        Write-Log "Downloading Acrobat installer from: $DownloadUrl"
        try {
            if ($urlExtension -eq ".zip") {
                $tempZip = "$env:TEMP\AcrobatInstaller_$((Get-Date).ToString('yyyyMMdd_HHmmss')).zip"
                $tempDir = "$env:TEMP\AcrobatExtract_$((Get-Date).ToString('yyyyMMdd_HHmmss'))"
                Invoke-WebRequest -Uri $DownloadUrl -OutFile $tempZip -UseBasicParsing
                Write-Log "Download completed: $tempZip"
                # Extract ZIP
                Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force
                Write-Log "Extraction completed to: $tempDir"
                # Find setup.exe
                $setupExe = Get-ChildItem -Path $tempDir -Recurse -Filter "setup.exe" | Select-Object -First 1
                if ($setupExe) {
                    $InstallPackage = $setupExe.FullName
                    Write-Log "Found setup.exe: $InstallPackage"
                } else {
                    Write-Log "Error: setup.exe not found in extracted files"
                    exit 1
                }
            } elseif ($urlExtension -eq ".exe") {
                $tempExe = "$env:TEMP\AcrobatInstaller_$((Get-Date).ToString('yyyyMMdd_HHmmss')).exe"
                Invoke-WebRequest -Uri $DownloadUrl -OutFile $tempExe -UseBasicParsing
                Write-Log "Download completed: $tempExe"
                $InstallPackage = $tempExe
                Write-Log "Downloaded EXE: $InstallPackage"
            } else {
                Write-Log "Error: Unsupported download URL extension: $urlExtension"
                exit 1
            }
        } catch {
            Write-Log "Failed to download or extract: $_"
            exit 1
        }
    }

    # Check if Adobe products are installed
    $adobeProducts = Get-AdobeProducts

    if (-not $adobeProducts) {
        Write-Log "No Adobe products detected. Nothing to uninstall."
        if ($InstallPackage) {
            Write-Log "Proceeding with installation of replacement package..."
            $installSuccess = Install-AdobePackage -PackagePath $InstallPackage
            if ($installSuccess) {
                Write-Log "Replacement package installation completed successfully"
                exit 0
            }
            else {
                Write-Log "Replacement package installation failed"
                exit 1
            }
        }
        exit 0
    }

    # Check for running processes
    if (Test-AdobeProcessesRunning) {
        if ($Force) {
            Write-Log "Force flag specified, stopping Adobe processes..."
            Stop-AdobeProcesses
        }
        else {
            Write-Log "Adobe processes are running. Use -Force parameter to stop them automatically, or close Adobe applications manually."
            exit 1
        }
    }

    # Uninstall all Adobe products
    $uninstallSuccess = Uninstall-AllAdobeProducts -AdobeProducts $adobeProducts

    # Perform cleanup regardless of uninstall success
    Remove-AdobeRemnants

    # Verify uninstallation
    $remainingProducts = Get-AdobeProducts
    if ($remainingProducts) {
        Write-Log "Warning: Some Adobe products may still be present after cleanup"
        $uninstallSuccess = $false
    }

    # Install replacement package if specified
    if ($InstallPackage) {
        # Set permissions on PDF file association before installation
        Set-PdfFileAssociationPermissions

        Write-Log "Installing replacement Adobe package..."
        $installSuccess = Install-AdobePackage -PackagePath $InstallPackage

        if (-not $installSuccess) {
            Write-Log "Warning: Replacement package installation failed"
            if ($uninstallSuccess) {
                exit 1  # Uninstallation succeeded but installation failed
            }
        }
        elseif ($uninstallSuccess) {
            Write-Log "Adobe products uninstallation and replacement installation completed successfully"
            exit 0
        }
        else {
            Write-Log "Replacement package installed successfully, but some Adobe products may still be present"
            exit 1
        }
    }

    # Final status
    if ($uninstallSuccess) {
        Write-Log "Adobe products uninstallation completed successfully"
        exit 0
    }
    else {
        Write-Log "Adobe products uninstallation completed with warnings - manual verification recommended"
        exit 1
    }
}
catch {
    Write-Log "Script failed with error: $_"
    exit 1
}
