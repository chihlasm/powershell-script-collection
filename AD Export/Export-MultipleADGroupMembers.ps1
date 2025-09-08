<#
.SYNOPSIS
    Export users from multiple Active Directory groups to CSV files

.DESCRIPTION
    This script allows you to export user members from multiple Active Directory groups.
    It supports both security groups and distribution groups, and can export to individual
    CSV files per group or a combined CSV file.

.PARAMETER GroupNames
    Array of group names to export members from

.PARAMETER OutputPath
    Path where CSV files will be saved (default: current directory)

.PARAMETER CombinedOutput
    Switch to create a single combined CSV file instead of individual files

.PARAMETER IncludeNestedGroups
    Switch to include members of nested groups (recursive membership)

.PARAMETER IncludeGroupInfo
    Switch to include group information in the output

.EXAMPLE
    # Export from specific groups to individual CSV files
    .\Export-MultipleADGroupMembers.ps1 -GroupNames "Domain Admins", "Enterprise Admins"

.EXAMPLE
    # Export from groups to a combined CSV file
    .\Export-MultipleADGroupMembers.ps1 -GroupNames "Group1", "Group2" -CombinedOutput

.EXAMPLE
    # Export with nested group members included
    .\Export-MultipleADGroupMembers.ps1 -GroupNames "Group1" -IncludeNestedGroups

.NOTES
    Requires Active Directory module and appropriate permissions
    Author: AI Assistant
    Date: 2025-08-29
#>

param(
    [Parameter(Mandatory = $true, HelpMessage = "Array of group names to export members from")]
    [string[]]$GroupNames,

    [Parameter(Mandatory = $false, HelpMessage = "Output path for CSV files")]
    [string]$OutputPath = (Get-Location),

    [Parameter(Mandatory = $false, HelpMessage = "Create a single combined CSV file")]
    [switch]$CombinedOutput,

    [Parameter(Mandatory = $false, HelpMessage = "Include members of nested groups")]
    [switch]$IncludeNestedGroups,

    [Parameter(Mandatory = $false, HelpMessage = "Include group information in output")]
    [switch]$IncludeGroupInfo
)

#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    $logMessage | Out-File -FilePath "$OutputPath\ADGroupExport.log" -Append
}

function Get-GroupMembers {
    param(
        [string]$GroupName,
        [bool]$Recursive = $false
    )

    try {
        Write-Log "Processing group: $GroupName"

        # Check if group exists
        $group = Get-ADGroup -Identity $GroupName -ErrorAction Stop

        $members = @()

        if ($Recursive) {
            # Get recursive members (includes nested groups)
            $groupMembers = Get-ADGroupMember -Identity $GroupName -Recursive -ErrorAction Stop
        } else {
            # Get direct members only
            $groupMembers = Get-ADGroupMember -Identity $GroupName -ErrorAction Stop
        }

        foreach ($member in $groupMembers) {
            if ($member.objectClass -eq "user") {
                # Get detailed user information
                $user = Get-ADUser -Identity $member.SamAccountName -Properties DisplayName, SamAccountName, UserPrincipalName, EmailAddress, Department, Title, Office, Enabled, LastLogonDate, PasswordLastSet -ErrorAction SilentlyContinue

                if ($user) {
                    $memberInfo = [PSCustomObject]@{
                        GroupName = $GroupName
                        DisplayName = $user.DisplayName
                        SamAccountName = $user.SamAccountName
                        UserPrincipalName = $user.UserPrincipalName
                        EmailAddress = $user.EmailAddress
                        Department = $user.Department
                        Title = $user.Title
                        Office = $user.Office
                        Enabled = $user.Enabled
                        LastLogonDate = $user.LastLogonDate
                        PasswordLastSet = $user.PasswordLastSet
                        ExportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                    $members += $memberInfo
                }
            }
        }

        Write-Log "Found $($members.Count) user members in group '$GroupName'"
        return $members

    } catch {
        Write-Log "Error processing group '$GroupName': $($_.Exception.Message)" "ERROR"
        return @()
    }
}

function Export-GroupMembers {
    param(
        [string]$GroupName,
        [array]$Members,
        [string]$OutputPath,
        [bool]$IncludeGroupInfo = $false
    )

    if ($Members.Count -eq 0) {
        Write-Log "No members found for group '$GroupName', skipping export"
        return
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $fileName = "ADGroupMembers_$($GroupName -replace '[^\w\d]', '')_$timestamp.csv"
    $fullPath = Join-Path -Path $OutputPath -ChildPath $fileName

    try {
        if ($IncludeGroupInfo) {
            # Add group information to each member record
            $groupInfo = Get-ADGroup -Identity $GroupName -Properties Description, GroupCategory, GroupScope, Created, Modified
            $Members | ForEach-Object {
                $_ | Add-Member -MemberType NoteProperty -Name "GroupDescription" -Value $groupInfo.Description -Force
                $_ | Add-Member -MemberType NoteProperty -Name "GroupCategory" -Value $groupInfo.GroupCategory -Force
                $_ | Add-Member -MemberType NoteProperty -Name "GroupScope" -Value $groupInfo.GroupScope -Force
                $_ | Add-Member -MemberType NoteProperty -Name "GroupCreated" -Value $groupInfo.Created -Force
                $_ | Add-Member -MemberType NoteProperty -Name "GroupModified" -Value $groupInfo.Modified -Force
            }
        }

        $Members | Export-Csv -Path $fullPath -NoTypeInformation -Encoding UTF8
        Write-Log "Exported $($Members.Count) members to: $fullPath"
    } catch {
        Write-Log "Error exporting members for group '$GroupName': $($_.Exception.Message)" "ERROR"
    }
}

# Main script execution
Write-Log "=== Starting AD Group Members Export ==="
Write-Log "Groups to process: $($GroupNames -join ', ')"
Write-Log "Output path: $OutputPath"
Write-Log "Combined output: $CombinedOutput"
Write-Log "Include nested groups: $IncludeNestedGroups"
Write-Log "Include group info: $IncludeGroupInfo"

# Validate output path
if (!(Test-Path $OutputPath)) {
    try {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        Write-Log "Created output directory: $OutputPath"
    } catch {
        Write-Log "Error creating output directory: $($_.Exception.Message)" "ERROR"
        exit 1
    }
}

# Check if Active Directory module is available
if (!(Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Log "Active Directory module imported successfully"
    } catch {
        Write-Log "Failed to import Active Directory module. Please ensure RSAT is installed." "ERROR"
        exit 1
    }
}

# Process each group
$allMembers = @()
$processedGroups = 0
$successfulGroups = 0

foreach ($groupName in $GroupNames) {
    $processedGroups++
    Write-Log "Processing group $processedGroups of $($GroupNames.Count): $groupName"

    $members = Get-GroupMembers -GroupName $groupName -Recursive $IncludeNestedGroups

    if ($members.Count -gt 0) {
        $successfulGroups++

        if ($CombinedOutput) {
            # Add to combined results
            $allMembers += $members
        } else {
            # Export individual file
            Export-GroupMembers -GroupName $groupName -Members $members -OutputPath $OutputPath -IncludeGroupInfo $IncludeGroupInfo
        }
    }
}

# Export combined results if requested
if ($CombinedOutput -and $allMembers.Count -gt 0) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $fileName = "ADGroupMembers_Combined_$timestamp.csv"
    $fullPath = Join-Path -Path $OutputPath -ChildPath $fileName

    try {
        if ($IncludeGroupInfo) {
            # Add group information to combined export
            $allMembers | ForEach-Object {
                $groupInfo = Get-ADGroup -Identity $_.GroupName -Properties Description, GroupCategory, GroupScope, Created, Modified -ErrorAction SilentlyContinue
                if ($groupInfo) {
                    $_ | Add-Member -MemberType NoteProperty -Name "GroupDescription" -Value $groupInfo.Description -Force
                    $_ | Add-Member -MemberType NoteProperty -Name "GroupCategory" -Value $groupInfo.GroupCategory -Force
                    $_ | Add-Member -MemberType NoteProperty -Name "GroupScope" -Value $groupInfo.GroupScope -Force
                    $_ | Add-Member -MemberType NoteProperty -Name "GroupCreated" -Value $groupInfo.Created -Force
                    $_ | Add-Member -MemberType NoteProperty -Name "GroupModified" -Value $groupInfo.Modified -Force
                }
            }
        }

        $allMembers | Export-Csv -Path $fullPath -NoTypeInformation -Encoding UTF8
        Write-Log "Exported combined results ($($allMembers.Count) total members) to: $fullPath"
    } catch {
        Write-Log "Error exporting combined results: $($_.Exception.Message)" "ERROR"
    }
}

# Summary
Write-Log "=== Export Summary ==="
Write-Log "Groups processed: $processedGroups"
Write-Log "Successful groups: $successfulGroups"
Write-Log "Total members exported: $($allMembers.Count)"
Write-Log "Output location: $OutputPath"
Write-Log "=== Export Complete ==="

# Display results to console
Write-Host "`n=== Export Summary ===" -ForegroundColor Green
Write-Host "Groups processed: $processedGroups" -ForegroundColor Cyan
Write-Host "Successful groups: $successfulGroups" -ForegroundColor Cyan
Write-Host "Total members exported: $($allMembers.Count)" -ForegroundColor Cyan
Write-Host "Output location: $OutputPath" -ForegroundColor Cyan
Write-Host "Log file: $OutputPath\ADGroupExport.log" -ForegroundColor Cyan
Write-Host "=== Export Complete ===" -ForegroundColor Green
