<#
.SYNOPSIS
    Example usage of Export-MultipleADGroupMembers.ps1 script

.DESCRIPTION
    This script demonstrates various ways to use the Export-MultipleADGroupMembers.ps1
    script for exporting Active Directory group members.

.NOTES
    Make sure to run this as Administrator and have the Active Directory module available
#>

# Example 1: Export members from specific groups to individual CSV files
Write-Host "Example 1: Exporting Domain Admins and Enterprise Admins to separate files..." -ForegroundColor Yellow
.\Export-MultipleADGroupMembers.ps1 -GroupNames "Domain Admins", "Enterprise Admins"

# Example 2: Export members from multiple groups to a combined CSV file
Write-Host "`nExample 2: Exporting multiple groups to a single combined file..." -ForegroundColor Yellow
.\Export-MultipleADGroupMembers.ps1 -GroupNames "IT Support", "Help Desk", "System Administrators" -CombinedOutput

# Example 3: Export with nested group members included
Write-Host "`nExample 3: Exporting with nested group members included..." -ForegroundColor Yellow
.\Export-MultipleADGroupMembers.ps1 -GroupNames "All Employees" -IncludeNestedGroups

# Example 4: Export to a specific directory with group information
Write-Host "`nExample 4: Exporting to specific directory with group information..." -ForegroundColor Yellow
.\Export-MultipleADGroupMembers.ps1 -GroupNames "Project Team A", "Project Team B" -OutputPath "C:\AD_Exports" -IncludeGroupInfo

# Example 5: Export with all options combined
Write-Host "`nExample 5: Exporting with all options (nested groups, group info, combined output)..." -ForegroundColor Yellow
.\Export-MultipleADGroupMembers.ps1 -GroupNames "Department A", "Department B" -OutputPath "C:\Reports" -CombinedOutput -IncludeNestedGroups -IncludeGroupInfo

# Example 6: Using variables for dynamic group names
Write-Host "`nExample 6: Using variables for dynamic group processing..." -ForegroundColor Yellow
$groupsToExport = @("Sales Team", "Marketing Team", "HR Department")
.\Export-MultipleADGroupMembers.ps1 -GroupNames $groupsToExport -CombinedOutput -OutputPath "C:\GroupReports"

Write-Host "`nAll examples completed! Check the output directory for CSV files and log files." -ForegroundColor Green
