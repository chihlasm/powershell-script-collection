<#
.SYNOPSIS
    Get-CitrixSessions.ps1 - Retrieves and displays Citrix VDA sessions with optional CSV export.

.DESCRIPTION
    This script queries Citrix Virtual Desktop Agent (VDA) sessions using the Citrix Broker SDK.
    It displays session details in a table format and optionally exports to CSV.

.PARAMETER VdaMachineName
    Target VDA machine name (optional). If omitted, queries all sessions in the site.

.PARAMETER OutputPath
    Path for CSV export file. If omitted, no CSV export is performed.

.EXAMPLE
    .\Get-CitrixSessions.ps1
    # Get all active sessions in the site

.EXAMPLE
    .\Get-CitrixSessions.ps1 -VdaMachineName "DOMAIN\VDAMachine01"
    # Get sessions on specific VDA

.EXAMPLE
    .\Get-CitrixSessions.ps1 -OutputPath "C:\Reports\Sessions.csv"
    # Export all sessions to CSV

.NOTES
    Requires Citrix Virtual Apps and Desktops PowerShell modules.
    Run as administrator or with appropriate Citrix permissions.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$VdaMachineName,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

# Check for Citrix PowerShell modules and load them
$citrixLoaded = $false

# First, try to load via snap-in (legacy method, most common)
try {
    if (-not (Get-PSSnapin -Name Citrix.Broker.Admin.V2 -ErrorAction SilentlyContinue)) {
        Add-PSSnapin Citrix.Broker.Admin.V2 -ErrorAction Stop
        Write-Verbose "Loaded Citrix modules via PSSnapin"
    }
    $citrixLoaded = $true
}
catch {
    Write-Verbose "PSSnapin Citrix.Broker.Admin.V2 not available: $_"
}

# If snap-in failed, try Import-Module (newer Citrix versions)
if (-not $citrixLoaded) {
    try {
        if (-not (Get-Module -Name Citrix.Broker.Admin.V2 -ErrorAction SilentlyContinue)) {
            Import-Module Citrix.Broker.Admin.V2 -ErrorAction Stop
            Write-Verbose "Loaded Citrix modules via Import-Module"
        }
        $citrixLoaded = $true
    }
    catch {
        Write-Verbose "Import-Module Citrix.Broker.Admin.V2 failed: $_"
    }
}

# If both failed, provide installation guidance
if (-not $citrixLoaded) {
    Write-Error "Citrix PowerShell modules are not installed. Please install Citrix Virtual Apps & Desktops PowerShell SDK from the Citrix Delivery Controller or use a machine with Citrix VDA/Citrix Server installed."
    Write-Error "You can also run this from a Citrix Delivery Controller where the SDK is installed."
    exit 1
}

# Query sessions with error handling
try {
    if ($VdaMachineName) {
        Write-Verbose "Querying sessions on VDA: $VdaMachineName"
        $sessions = Get-BrokerSession -MachineName $VdaMachineName -ErrorAction Stop
    }
    else {
        Write-Verbose "Querying all sessions in the site"
        $sessions = Get-BrokerSession -ErrorAction Stop
    }
}
catch {
    Write-Error "Failed to query Citrix sessions: $_"
    exit 1
}

# Check if any sessions were found
if (!$sessions -or $sessions.Count -eq 0) {
    Write-Host "No active sessions found." -ForegroundColor Yellow
    exit 0
}

# Process session data efficiently using ForEach-Object instead of foreach
$sessionList = $sessions | ForEach-Object {
    [PSCustomObject]@{
        UserName          = $_.UserName
        FullName          = $_.UserFullName
        MachineName       = $_.MachineName
        SessionState      = $_.SessionState
        SessionStateRaw   = $_.SessionStatus
        ClientName        = $_.ClientName
        LogonTime         = $_.BrokeringTime
        IdleDuration      = $_.IdleDuration
        DeliveryGroup     = $_.DesktopGroupName
        ClientAddress     = $_.ClientAddress
        ClientVersion     = $_.ClientVersion
        Protocol          = $_.Protocol
        EstablishmentTime = $_.EstablishmentTime
    }
}

# Display results
$sessionList | Format-Table -AutoSize

# Optional CSV export
if ($OutputPath) {
    try {
        $sessionList | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Host "Session data exported to: $OutputPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to export CSV to $OutputPath : $_"
    }
}
