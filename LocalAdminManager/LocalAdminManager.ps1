<#
.SYNOPSIS
    Manages local administrators group on Windows computers by adding or removing domain users/groups.

.DESCRIPTION
    This script allows you to add or remove domain users or groups to/from the local Administrators group on Windows desktops.
    It can be run locally or remotely (requires appropriate permissions).

.PARAMETER Action
    The action to perform: 'Add' or 'Remove'.

.PARAMETER Member
    The domain user or group to add/remove in the format 'DOMAIN\Username' or 'DOMAIN\GroupName'.

.PARAMETER ComputerName
    The name of the computer to manage. Defaults to localhost.

.EXAMPLE
    # Add a domain user to local admins on the local computer
    .\LocalAdminManager.ps1 -Action Add -Member "CONTOSO\JohnDoe"

.EXAMPLE
    # Remove a domain group from local admins on a remote computer
    .\LocalAdminManager.ps1 -Action Remove -Member "CONTOSO\DomainAdmins" -ComputerName "RemotePC01"

.EXAMPLE
    # Add a domain group to local admins
    .\LocalAdminManager.ps1 -Action Add -Member "CONTOSO\ITSupport"

.NOTES
    - Must be run with administrator privileges.
    - For remote computers, ensure you have administrative access and that PowerShell remoting is enabled if needed.
    - Domain users/groups must exist in Active Directory.
#>

param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("Add", "Remove")]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [string]$Member,

    [Parameter(Mandatory = $false)]
    [string]$ComputerName = $env:COMPUTERNAME
)

# Function to check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to add member to local administrators
function Add-LocalAdmin {
    param (
        [string]$Member,
        [string]$ComputerName
    )

    try {
        Add-LocalGroupMember -Group "Administrators" -Member $Member -ComputerName $ComputerName
        Write-Host "Successfully added $Member to local Administrators group on $ComputerName" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to add $Member to local Administrators group on $ComputerName. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to remove member from local administrators
function Remove-LocalAdmin {
    param (
        [string]$Member,
        [string]$ComputerName
    )

    try {
        Remove-LocalGroupMember -Group "Administrators" -Member $Member -ComputerName $ComputerName
        Write-Host "Successfully removed $Member from local Administrators group on $ComputerName" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to remove $Member from local Administrators group on $ComputerName. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Main script logic
if (-not (Test-Administrator)) {
    Write-Host "This script must be run as an administrator." -ForegroundColor Red
    exit 1
}

Write-Host "Managing local administrators on $ComputerName..." -ForegroundColor Cyan

switch ($Action) {
    "Add" {
        Add-LocalAdmin -Member $Member -ComputerName $ComputerName
    }
    "Remove" {
        Remove-LocalAdmin -Member $Member -ComputerName $ComputerName
    }
}

Write-Host "Operation completed." -ForegroundColor Cyan
