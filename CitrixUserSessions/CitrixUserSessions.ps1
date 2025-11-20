<#
.SYNOPSIS
    CitrixUserSessions.ps1 - Shows users logged into Citrix VDA servers and their local machine names.

.DESCRIPTION
    This script queries Citrix Virtual Desktop Agent (VDA) sessions and displays
    which users are logged into which VDA servers, along with their local machine names.

.PARAMETER VdaMachineName
    Target VDA machine name (optional). If omitted, queries all sessions in the site.

.EXAMPLE
    .\CitrixUserSessions.ps1
    # Show all active user sessions

.EXAMPLE
    .\CitrixUserSessions.ps1 -VdaMachineName "DOMAIN\VDAMachine01"
    # Show sessions on specific VDA

.NOTES
    Requires Citrix Virtual Apps and Desktops PowerShell modules.
    Run from Citrix Delivery Controller or Studio server.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$VdaMachineName
)

# Load Citrix modules
$citrixLoaded = $false

# Try PSSnapin first (legacy)
try {
    if (-not (Get-PSSnapin -Name Citrix.Broker.Admin.V2 -ErrorAction SilentlyContinue)) {
        Add-PSSnapin Citrix.Broker.Admin.V2 -ErrorAction Stop
    }
    $citrixLoaded = $true
}
catch {
    # Try Import-Module (newer versions)
    try {
        if (-not (Get-Module -Name Citrix.Broker.Admin.V2 -ErrorAction SilentlyContinue)) {
            Import-Module Citrix.Broker.Admin.V2 -ErrorAction Stop
        }
        $citrixLoaded = $true
    }
    catch {
        Write-Error "Citrix PowerShell modules not found. Run this from a Citrix Delivery Controller or install Citrix SDK."
        exit 1
    }
}

# Query sessions
try {
    if ($VdaMachineName) {
        $sessions = Get-BrokerSession -MachineName $VdaMachineName -ErrorAction Stop
    }
    else {
        $sessions = Get-BrokerSession -ErrorAction Stop
    }
}
catch {
    Write-Error "Failed to query sessions: $_"
    exit 1
}

# Filter to active sessions and display
$sessions | Where-Object { $_.SessionState -eq "Active" } | ForEach-Object {
    [PSCustomObject]@{
        UserName     = $_.UserName
        VDAServer    = $_.MachineName
        LocalMachine = $_.ClientName
    }
} | Format-Table -AutoSize
