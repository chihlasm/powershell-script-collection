<#
.SYNOPSIS
    Retrieves and exports password policies from Active Directory Domain and Azure AD Tenant.

.DESCRIPTION
    This script connects to Active Directory and/or Azure AD to retrieve password policies,
    formats them with descriptions, and exports to CSV, HTML, or text format.

.PARAMETER OutputPath
    Path where the output file will be saved. Default is current directory.

.PARAMETER OutputFormat
    Format for the output file: CSV, HTML, or TXT. Default is CSV.

.PARAMETER IncludeAD
    Include Active Directory domain password policy. Default is $true.

.PARAMETER IncludeAzureAD
    Include Azure AD tenant password policy. Default is $true.

.PARAMETER AzureADCredential
    PSCredential object for Azure AD authentication. If not provided, will prompt.

.EXAMPLE
    .\Get-PasswordPolicies.ps1 -OutputPath "C:\Reports" -OutputFormat HTML

.EXAMPLE
    .\Get-PasswordPolicies.ps1 -IncludeAD $false -OutputFormat TXT
#>

param (
    [string]$OutputPath = (Get-Location).Path,
    [ValidateSet("CSV", "HTML", "TXT")]
    [string]$OutputFormat = "CSV",
    [bool]$IncludeAD = $true,
    [bool]$IncludeAzureAD = $true,
    [PSCredential]$AzureADCredential
)

# Function to get Active Directory password policy
function Get-ADPasswordPolicy {
    try {
        # Check if ActiveDirectory module is available
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            throw "ActiveDirectory module not found. Please install RSAT tools."
        }

        Import-Module ActiveDirectory

        # Get domain password policy
        $domainPolicy = Get-ADDefaultDomainPasswordPolicy

        # Create array of custom objects with descriptions
        $policyData = @()
        $policyData += [PSCustomObject]@{
            "Policy Type" = "Active Directory Domain"
            "Setting" = "Minimum Password Length"
            "Value" = $domainPolicy.MinPasswordLength
            "Description" = "Minimum number of characters required in a password"
        }

        $policyData += [PSCustomObject]@{
            "Policy Type" = "Active Directory Domain"
            "Setting" = "Password History Count"
            "Value" = $domainPolicy.PasswordHistoryCount
            "Description" = "Number of previous passwords remembered to prevent reuse"
        }

        $policyData += [PSCustomObject]@{
            "Policy Type" = "Active Directory Domain"
            "Setting" = "Maximum Password Age"
            "Value" = $domainPolicy.MaxPasswordAge
            "Description" = "Maximum time a password can be used before requiring change"
        }

        $policyData += [PSCustomObject]@{
            "Policy Type" = "Active Directory Domain"
            "Setting" = "Minimum Password Age"
            "Value" = $domainPolicy.MinPasswordAge
            "Description" = "Minimum time that must pass before a password can be changed"
        }

        $policyData += [PSCustomObject]@{
            "Policy Type" = "Active Directory Domain"
            "Setting" = "Password Complexity"
            "Value" = $domainPolicy.ComplexityEnabled
            "Description" = "Whether password must meet complexity requirements (uppercase, lowercase, numbers, symbols)"
        }

        $policyData += [PSCustomObject]@{
            "Policy Type" = "Active Directory Domain"
            "Setting" = "Lockout Threshold"
            "Value" = $domainPolicy.LockoutThreshold
            "Description" = "Number of failed login attempts before account is locked"
        }

        $policyData += [PSCustomObject]@{
            "Policy Type" = "Active Directory Domain"
            "Setting" = "Lockout Duration"
            "Value" = $domainPolicy.LockoutDuration
            "Description" = "How long an account remains locked after lockout threshold is reached"
        }

        $policyData += [PSCustomObject]@{
            "Policy Type" = "Active Directory Domain"
            "Setting" = "Lockout Observation Window"
            "Value" = $domainPolicy.LockoutObservationWindow
            "Description" = "Time window during which failed login attempts are counted toward lockout"
        }

        return $policyData
    }
    catch {
        Write-Warning "Failed to retrieve Active Directory password policy: $($_.Exception.Message)"
        return $null
    }
}

# Function to get Azure AD password policy
function Get-AzureADPasswordPolicy {
    try {
        # Check if running in PowerShell ISE which may have issues with Azure AD authentication
        if ($host.Name -eq "Windows PowerShell ISE Host") {
            Write-Warning "Running in PowerShell ISE may cause Azure AD authentication issues. Consider using regular PowerShell console."
        }

        # Check if AzureAD or MSOnline module is available, prefer MSOnline
        $azureModule = $null
        if (Get-Module -Name MSOnline -ListAvailable) {
            $azureModule = "MSOnline"
        }
        elseif (Get-Module -Name AzureAD -ListAvailable) {
            $azureModule = "AzureAD"
        }
        else {
            # Try to install MSOnline module
            Write-Host "Required modules not found. Attempting to install MSOnline module..."
            try {
                # Set PSGallery to trusted temporarily for installation
                $originalPolicy = (Get-PSRepository -Name PSGallery).InstallationPolicy
                if ($originalPolicy -ne 'Trusted') {
                    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
                    Write-Host "Temporarily set PSGallery to trusted for module installation."
                }

                Install-Module -Name MSOnline -Scope CurrentUser -Force -ErrorAction Stop
                $azureModule = "MSOnline"
                Write-Host "MSOnline module installed successfully."

                # Restore original policy
                if ($originalPolicy -ne 'Trusted') {
                    Set-PSRepository -Name PSGallery -InstallationPolicy $originalPolicy
                    Write-Host "Restored PSGallery installation policy."
                }
            }
            catch {
                throw "Failed to install MSOnline module: $($_.Exception.Message). Please install manually with: Install-Module MSOnline -Scope CurrentUser -Force"
            }
        }

        Import-Module $azureModule

        # Connect to Azure AD
        try {
            if ($AzureADCredential) {
                Write-Host "Connecting to Azure AD using provided credentials..."
                if ($azureModule -eq "AzureAD") {
                    Connect-AzureAD -Credential $AzureADCredential -ErrorAction Stop | Out-Null
                }
                else {
                    Connect-MsolService -Credential $AzureADCredential -ErrorAction Stop | Out-Null
                }
            }
            else {
                Write-Host "Connecting to Azure AD interactively (use -AzureADCredential parameter to avoid prompts)..."
                if ($azureModule -eq "AzureAD") {
                    Connect-AzureAD -ErrorAction Stop | Out-Null
                }
                else {
                    Connect-MsolService -ErrorAction Stop | Out-Null
                }
            }
            Write-Host "Successfully connected to Azure AD."
        }
        catch {
            throw "Failed to connect to Azure AD: $($_.Exception.Message)"
        }

        # Get password policy
        try {
            if ($azureModule -eq "AzureAD") {
                # Note: AzureAD module may not have direct password policy cmdlet
                # This might need to be updated based on available cmdlets
                if (Get-Command Get-AzureADPasswordPolicy -ErrorAction SilentlyContinue) {
                    $passwordPolicy = Get-AzureADPasswordPolicy
                }
                else {
                    throw "Get-AzureADPasswordPolicy cmdlet not available. Consider using MSOnline module or Microsoft Graph."
                }
            }
            else {
                $passwordPolicy = Get-MsolPasswordPolicy
            }
        }
        catch {
            throw "Failed to retrieve password policy: $($_.Exception.Message)"
        }

        # Create array of custom objects with descriptions
        $policyData = @()
        $policyData += [PSCustomObject]@{
            "Policy Type" = "Azure AD Tenant"
            "Setting" = "Password Lifetime"
            "Value" = $passwordPolicy.PasswordLifetime
            "Description" = "Maximum time a password can be used before requiring change"
        }

        $policyData += [PSCustomObject]@{
            "Policy Type" = "Azure AD Tenant"
            "Setting" = "Password History Count"
            "Value" = $passwordPolicy.PasswordHistoryCount
            "Description" = "Number of previous passwords remembered to prevent reuse"
        }

        $policyData += [PSCustomObject]@{
            "Policy Type" = "Azure AD Tenant"
            "Setting" = "Minimum Password Length"
            "Value" = $passwordPolicy.MinimumPasswordLength
            "Description" = "Minimum number of characters required in a password"
        }

        $policyData += [PSCustomObject]@{
            "Policy Type" = "Azure AD Tenant"
            "Setting" = "Password Complexity"
            "Value" = $passwordPolicy.PasswordComplexity
            "Description" = "Whether password must meet complexity requirements"
        }

        return $policyData
    }
    catch {
        Write-Warning "Failed to retrieve Azure AD password policy: $($_.Exception.Message)"
        return $null
    }
}

# Function to export data
function Export-PasswordPolicyData {
    param (
        [Parameter(Mandatory = $true)]
        [array]$PolicyData,
        [string]$Path,
        [string]$Format
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "PasswordPolicies_$timestamp"

    switch ($Format) {
        "CSV" {
            $outputFile = Join-Path $Path "$filename.csv"
            $PolicyData | Export-Csv -Path $outputFile -NoTypeInformation
        }
        "HTML" {
            $outputFile = Join-Path $Path "$filename.html"
            $html = $PolicyData | ConvertTo-Html -Title "Password Policy Report" -PreContent "<h1>Password Policy Audit Report</h1><p>Generated on $(Get-Date)</p>"
            $html | Out-File $outputFile
        }
        "TXT" {
            $outputFile = Join-Path $Path "$filename.txt"
            $PolicyData | Format-Table -AutoSize | Out-File $outputFile
        }
    }

    Write-Host "Password policy report exported to: $outputFile"
}

# Main script logic
$allPolicyData = @()

if ($IncludeAD) {
    Write-Host "Retrieving Active Directory password policy..."
    $adPolicy = Get-ADPasswordPolicy
    if ($adPolicy) {
        $allPolicyData += $adPolicy
    }
}

if ($IncludeAzureAD) {
    Write-Host "Retrieving Azure AD password policy..."
    $azurePolicy = Get-AzureADPasswordPolicy
    if ($azurePolicy) {
        $allPolicyData += $azurePolicy
    }
}

if ($allPolicyData.Count -eq 0) {
    Write-Warning "No password policy data could be retrieved. Check module installations and permissions."
    exit 1
}

# Export the data
Export-PasswordPolicyData -PolicyData $allPolicyData -Path $OutputPath -Format $OutputFormat

Write-Host "Password policy audit completed successfully."
