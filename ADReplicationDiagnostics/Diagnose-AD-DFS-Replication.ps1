<#
.SYNOPSIS
    Diagnose-AD-DFS-Replication.ps1 - Comprehensive diagnostic tool for AD replication and DFS/DFSR issues.

.DESCRIPTION
    This script diagnoses Active Directory replication and DFS/DFSR issues across multiple domain controllers.
    It checks replication status, service health, backlog, and reports any problems.

.EXAMPLE
    .\Diagnose-AD-DFS-Replication.ps1

.NOTES
    Requires ActiveDirectory and DFSReplication modules. Run as administrator with domain admin privileges.
#>

#Requires -Modules ActiveDirectory

param(
    [string[]]$DomainControllers = @(),  # Optional: specify specific DCs, otherwise auto-detect all
    [string]$LogFile = ""  # Optional: specify log file path, otherwise no logging
)

# Function to write colored output and optionally log to file
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color

    # Log to file if specified
    if ($LogFile) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$timestamp [$Color] $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    }
}

# Initialize logging
if ($LogFile) {
    $logDir = Split-Path -Path $LogFile -Parent
    if (-not (Test-Path -Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    $startTime = Get-Date
    $header = @"
AD/DFS Replication Diagnostic Log
Started: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))
Computer: $($env:COMPUTERNAME)
User: $($env:USERNAME)
Parameters: DomainControllers=$($DomainControllers -join ',') LogFile=$LogFile

"@
    $header | Out-File -FilePath $LogFile -Encoding UTF8
    Write-ColorOutput "Logging enabled. Output will be saved to: $LogFile" "Cyan"
}

# Get domain controllers
if ($DomainControllers.Count -eq 0) {
    try {
        $DCs = Get-ADDomainController -Filter *
        Write-ColorOutput "Auto-detected $($DCs.Count) domain controllers:" "Green"
    } catch {
        Write-ColorOutput "Failed to retrieve domain controllers: $_" "Red"
        exit 1
    }
} else {
    $DCs = @()
    foreach ($dc in $DomainControllers) {
        try {
            $DCs += Get-ADDomainController -Identity $dc
        } catch {
            Write-ColorOutput "Failed to find domain controller: $dc" "Red"
        }
    }
    if ($DCs.Count -eq 0) {
        Write-ColorOutput "No valid domain controllers specified." "Red"
        exit 1
    }
}

$DCs | ForEach-Object { Write-ColorOutput "  $($_.HostName)" "Cyan" }

Write-ColorOutput "`n=== ACTIVE DIRECTORY REPLICATION DIAGNOSTICS ===" "Yellow"

# Check AD replication failures
try {
    $failures = Get-ADReplicationFailure -Scope Domain
    if ($failures) {
        Write-ColorOutput "`nReplication Failures Found:" "Red"
        $failures | Format-Table -AutoSize
    } else {
        Write-ColorOutput "`nNo AD replication failures detected." "Green"
    }
} catch {
    Write-ColorOutput "Failed to check AD replication failures: $_" "Red"
}

# Check AD replication metadata for each DC
$replicationStatus = @()
foreach ($DC in $DCs) {
    try {
        $partners = Get-ADReplicationPartnerMetadata -Target $DC.HostName
        foreach ($partner in $partners) {
            $status = [PSCustomObject]@{
                SourceDC                = $DC.HostName
                TargetDC                = $partner.Partner
                Partition               = $partner.Partition
                LastReplicationAttempt  = $partner.LastReplicationAttempt
                LastReplicationSuccess  = $partner.LastReplicationSuccess
                ConsecutiveFailures     = $partner.ConsecutiveReplicationFailures
                Status                  = if ($partner.LastReplicationSuccess -gt (Get-Date).AddHours(-24)) { "OK" } else { "Stale" }
            }
            $replicationStatus += $status
        }
    } catch {
        Write-ColorOutput "Failed to get replication metadata for $($DC.HostName): $_" "Red"
    }
}

Write-ColorOutput "`nAD Replication Status:" "Cyan"
$replicationStatus | Format-Table -AutoSize

# AD Summary
$stale = $replicationStatus | Where-Object { $_.Status -eq "Stale" }
if ($stale) {
    Write-ColorOutput "`nWarning: $($stale.Count) AD replication partnerships are stale (no success in last 24 hours)." "Red"
} else {
    Write-ColorOutput "`nAll AD replication partnerships appear healthy." "Green"
}

Write-ColorOutput "`n=== DFS/DFSR DIAGNOSTICS ===" "Yellow"

# Check DFS Replication service status on each DC
Write-ColorOutput "`nDFS Replication Service Status:" "Cyan"
foreach ($DC in $DCs) {
    try {
        $service = Get-Service -Name DFSR -ComputerName $DC.HostName
        $status = if ($service.Status -eq 'Running') { "Running" } else { "Not Running" }
        $color = if ($service.Status -eq 'Running') { "Green" } else { "Red" }
        Write-ColorOutput "  $($DC.HostName): $status" $color
    } catch {
        Write-ColorOutput "  $($DC.HostName): Failed to check service - $_" "Red"
    }
}

# Get DFS Replication Groups
try {
    $dfsGroups = Get-DfsReplicationGroup
    if ($dfsGroups) {
        Write-ColorOutput "`nFound $($dfsGroups.Count) DFS Replication Groups:" "Green"
        $dfsGroups | Select-Object GroupName, DomainName, Description | Format-Table -AutoSize
    } else {
        Write-ColorOutput "`nNo DFS Replication Groups found." "Yellow"
    }
} catch {
    Write-ColorOutput "Failed to retrieve DFS Replication Groups: $_" "Red"
    $dfsGroups = @()
}

# Check DFS Replication Group Members and Connections
foreach ($group in $dfsGroups) {
    Write-ColorOutput "`nDFS Replication Group: $($group.GroupName)" "Cyan"

    try {
        $members = Get-DfsReplicationGroupMember -GroupName $group.GroupName
        Write-ColorOutput "  Members:" "White"
        $members | Select-Object ComputerName, DomainName | Format-Table -AutoSize
    } catch {
        Write-ColorOutput "  Failed to get members: $_" "Red"
    }

    try {
        $connections = Get-DfsReplicationGroupConnection -GroupName $group.GroupName
        Write-ColorOutput "  Connections:" "White"
        $connections | Select-Object SourceComputerName, DestinationComputerName, State, RdcEnabled | Format-Table -AutoSize
    } catch {
        Write-ColorOutput "  Failed to get connections: $_" "Red"
    }
}

# Check DFS Replication Backlog
Write-ColorOutput "`nDFS Replication Backlog:" "Cyan"
$backlogIssues = @()

foreach ($group in $dfsGroups) {
    try {
        $members = Get-DfsReplicationGroupMember -GroupName $group.GroupName
        foreach ($member in $members) {
            foreach ($otherMember in $members | Where-Object { $_.ComputerName -ne $member.ComputerName }) {
                try {
                    $backlog = Get-DfsReplicationBacklog -GroupName $group.GroupName -SourceComputerName $member.ComputerName -DestinationComputerName $otherMember.ComputerName
                    $backlogCount = $backlog.Count
                    if ($backlogCount -gt 0) {
                        Write-ColorOutput "  $($member.ComputerName) -> $($otherMember.ComputerName): $backlogCount files in backlog" "Red"
                        $backlogIssues += [PSCustomObject]@{
                            GroupName = $group.GroupName
                            Source = $member.ComputerName
                            Destination = $otherMember.ComputerName
                            BacklogCount = $backlogCount
                        }
                    } else {
                        Write-ColorOutput "  $($member.ComputerName) -> $($otherMember.ComputerName): No backlog" "Green"
                    }
                } catch {
                    Write-ColorOutput "  Failed to check backlog $($member.ComputerName) -> $($otherMember.ComputerName): $_" "Red"
                }
            }
        }
    } catch {
        Write-ColorOutput "  Failed to check backlog for group $($group.GroupName): $_" "Red"
    }
}

# Check DFS Namespaces
try {
    $namespaces = Get-DfsNamespace
    if ($namespaces) {
        Write-ColorOutput "`nDFS Namespaces:" "Cyan"
        $namespaces | Select-Object NamespacePath, State, Description | Format-Table -AutoSize

        foreach ($ns in $namespaces) {
            try {
                $targets = Get-DfsReplicationTarget -NamespacePath $ns.NamespacePath
                if ($targets) {
                    Write-ColorOutput "  Targets for $($ns.NamespacePath):" "White"
                    $targets | Select-Object TargetPath, State, ReferralPriorityClass, ReferralPriorityRank | Format-Table -AutoSize
                }
            } catch {
                Write-ColorOutput "  Failed to get targets for $($ns.NamespacePath): $_" "Red"
            }
        }
    } else {
        Write-ColorOutput "`nNo DFS Namespaces found." "Yellow"
    }
} catch {
    Write-ColorOutput "Failed to retrieve DFS Namespaces: $_" "Red"
}

# Final Summary
Write-ColorOutput "`n=== DIAGNOSTIC SUMMARY ===" "Yellow"

$issues = @()

if ($stale) {
    $issues += "AD Replication: $($stale.Count) stale partnerships"
}

if ($backlogIssues.Count -gt 0) {
    $issues += "DFSR: $($backlogIssues.Count) replication backlogs detected"
}

# Check for stopped DFSR services
$stoppedServices = @()
foreach ($DC in $DCs) {
    try {
        $service = Get-Service -Name DFSR -ComputerName $DC.HostName
        if ($service.Status -ne 'Running') {
            $stoppedServices += $DC.HostName
        }
    } catch {
        $stoppedServices += $DC.HostName
    }
}
if ($stoppedServices.Count -gt 0) {
    $issues += "DFSR Service: Stopped on $($stoppedServices -join ', ')"
}

if ($issues.Count -eq 0) {
    Write-ColorOutput "No major issues detected. All systems appear healthy." "Green"
} else {
    Write-ColorOutput "Issues found:" "Red"
    $issues | ForEach-Object { Write-ColorOutput "  - $_" "Red" }
}

# Log completion if logging is enabled
if ($LogFile) {
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $footer = @"


Diagnostic completed: $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))
Duration: $($duration.TotalSeconds.ToString('F2')) seconds
Total issues found: $($issues.Count)
Log saved to: $LogFile
"@
    $footer | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

Write-ColorOutput "`nDiagnostic complete." "Green"
