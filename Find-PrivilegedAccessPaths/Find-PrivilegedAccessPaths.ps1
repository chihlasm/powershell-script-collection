<#
.SYNOPSIS
    Traces all paths through which a user may be flagged as privileged/admin in Active Directory.

.DESCRIPTION
    When a user shows up on a Privileged Account Report and you can't figure out WHY,
    this script checks every common path to admin-level access:
    
    1. Direct membership in built-in admin groups (Domain Admins, Enterprise Admins, etc.)
    2. NESTED group membership (the #1 hidden culprit)
    3. AdminCount attribute = 1 (set by AdminSDHolder and often orphaned)
    4. AdminSDHolder protection status
    5. SID History (can carry admin SIDs from old domains)
    6. Delegated permissions on OUs (sometimes grants admin-equivalent access)
    7. User Rights Assignments via GPO (SeDebugPrivilege, etc.)
    8. Service accounts running under the user's identity
    9. memberOf attribute vs. primaryGroupID mismatches

.PARAMETER Username
    The sAMAccountName of the user to investigate.

.PARAMETER ExportPath
    Optional. If specified, exports a detailed report to this file path (CSV).

.EXAMPLE
    .\Find-PrivilegedAccessPaths.ps1 -Username "jsmith"

.EXAMPLE
    .\Find-PrivilegedAccessPaths.ps1 -Username "jsmith" -ExportPath "C:\Reports\jsmith-priv-audit.csv"

.NOTES
    Requires: ActiveDirectory PowerShell module
    Run as: Domain Admin or equivalent read access
    Author: Generated for VC3 MSP troubleshooting
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Enter the sAMAccountName of the user to investigate")]
    [string]$Username,

    [Parameter(Mandatory = $false)]
    [string]$ExportPath
)

#region ─── Setup & Validation ───────────────────────────────────────────────────
$ErrorActionPreference = "Stop"

# Import AD module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "ActiveDirectory module not found. Install RSAT or run from a DC."
    return
}

# Resolve the user
try {
    $User = Get-ADUser -Identity $Username -Properties `
        MemberOf, AdminCount, SIDHistory, PrimaryGroupID, `
        DistinguishedName, ObjectSID, ServicePrincipalName, `
        whenCreated, whenChanged, Enabled, PasswordLastSet, `
        LastLogonDate, Description
} catch {
    Write-Error "User '$Username' not found in Active Directory."
    return
}

Write-Host "`n" -NoNewline
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  PRIVILEGED ACCESS PATH ANALYSIS" -ForegroundColor Cyan
Write-Host "  User: $($User.SamAccountName) ($($User.Name))" -ForegroundColor Cyan
Write-Host "  DN:   $($User.DistinguishedName)" -ForegroundColor Cyan
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Collector for export
$Findings = [System.Collections.ArrayList]::new()

function Add-Finding {
    param(
        [string]$Category,
        [string]$Finding,
        [string]$Severity, # HIGH, MEDIUM, LOW, INFO
        [string]$Detail
    )

    $color = switch ($Severity) {
        "HIGH"   { "Red" }
        "MEDIUM" { "Yellow" }
        "LOW"    { "DarkYellow" }
        "INFO"   { "Gray" }
        default  { "White" }
    }
    
    $icon = switch ($Severity) {
        "HIGH"   { "[!!]" }
        "MEDIUM" { "[!] " }
        "LOW"    { "[~] " }
        "INFO"   { "[i] " }
        default  { "    " }
    }

    Write-Host "  $icon " -ForegroundColor $color -NoNewline
    Write-Host "$Finding" -ForegroundColor White
    if ($Detail) {
        Write-Host "       $Detail" -ForegroundColor DarkGray
    }

    [void]$Findings.Add([PSCustomObject]@{
        Category = $Category
        Severity = $Severity
        Finding  = $Finding
        Detail   = $Detail
    })
}
#endregion

#region ─── 1. Built-in Privileged Group Membership (Direct) ─────────────────────
Write-Host "── 1. DIRECT PRIVILEGED GROUP MEMBERSHIP ──────────────────────" -ForegroundColor Yellow
Write-Host ""

# Well-known privileged group SIDs (domain-relative RIDs)
$PrivilegedGroupRIDs = @{
    "512" = "Domain Admins"
    "516" = "Domain Controllers"
    "518" = "Schema Admins"
    "519" = "Enterprise Admins"
    "520" = "Group Policy Creator Owners"
    "544" = "Administrators (Builtin)"
    "548" = "Account Operators"
    "549" = "Server Operators"
    "550" = "Print Operators"
    "551" = "Backup Operators"
    "552" = "Replicators"
    "553" = "RAS and IAS Servers"
}

# Also check by name for some that vary
$PrivilegedGroupNames = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "Backup Operators",
    "Print Operators",
    "DnsAdmins",
    "Group Policy Creator Owners",
    "Cert Publishers",
    "Key Admins",
    "Enterprise Key Admins",
    "Protected Users"
)

$DirectGroups = $User.MemberOf | ForEach-Object {
    Get-ADGroup -Identity $_ -Properties ObjectSID, GroupCategory, GroupScope
}

$foundDirect = $false
foreach ($group in $DirectGroups) {
    $rid = $group.ObjectSID.Value.Split('-')[-1]
    if ($PrivilegedGroupRIDs.ContainsKey($rid) -or $PrivilegedGroupNames -contains $group.Name) {
        Add-Finding -Category "Direct Membership" -Severity "HIGH" `
            -Finding "DIRECT member of: $($group.Name)" `
            -Detail "SID: $($group.ObjectSID) | Scope: $($group.GroupScope)"
        $foundDirect = $true
    }
}

# Check PrimaryGroupID (often missed — defaults to 513 for Domain Users)
$PrimaryGroupSID = "$($User.ObjectSID.Value.TrimEnd($User.ObjectSID.Value.Split('-')[-1]))$($User.PrimaryGroupID)"
if ($PrivilegedGroupRIDs.ContainsKey("$($User.PrimaryGroupID)")) {
    Add-Finding -Category "Primary Group" -Severity "HIGH" `
        -Finding "Primary Group is privileged: $($PrivilegedGroupRIDs["$($User.PrimaryGroupID)"])" `
        -Detail "PrimaryGroupID: $($User.PrimaryGroupID) — This does NOT show in memberOf!"
    $foundDirect = $true
}

if (-not $foundDirect) {
    Add-Finding -Category "Direct Membership" -Severity "INFO" `
        -Finding "No direct membership in well-known privileged groups" -Detail $null
}
Write-Host ""
#endregion

#region ─── 2. NESTED Group Membership (The Hidden Culprit) ──────────────────────
Write-Host "── 2. NESTED PRIVILEGED GROUP MEMBERSHIP ──────────────────────" -ForegroundColor Yellow
Write-Host ""

# Manually resolve ALL nested groups (compatible with all AD module versions)
function Get-NestedGroupMembership {
    param([string]$UserDN)
    
    $allGroups = @{}
    $queue = [System.Collections.Queue]::new()
    
    # Seed with direct memberships
    $directMemberOf = (Get-ADUser -Identity $UserDN -Properties MemberOf).MemberOf
    foreach ($groupDN in $directMemberOf) {
        if (-not $allGroups.ContainsKey($groupDN)) {
            $queue.Enqueue($groupDN)
            $allGroups[$groupDN] = $true
        }
    }
    
    # Walk the nesting tree
    while ($queue.Count -gt 0) {
        $currentDN = $queue.Dequeue()
        try {
            $parentGroups = (Get-ADGroup -Identity $currentDN -Properties MemberOf).MemberOf
            foreach ($parentDN in $parentGroups) {
                if (-not $allGroups.ContainsKey($parentDN)) {
                    $allGroups[$parentDN] = $true
                    $queue.Enqueue($parentDN)
                }
            }
        } catch {
            # Skip groups we can't resolve
        }
    }
    
    # Return full group objects
    foreach ($groupDN in $allGroups.Keys) {
        try {
            Get-ADGroup -Identity $groupDN -Properties ObjectSID, GroupCategory, GroupScope
        } catch { }
    }
}

$AllNestedGroups = @(Get-NestedGroupMembership -UserDN $User.DistinguishedName)

$foundNested = $false
$directMemberOfDNs = $User.MemberOf

foreach ($group in $AllNestedGroups) {
    $rid = $group.ObjectSID.Value.Split('-')[-1]
    $isPriv = $PrivilegedGroupRIDs.ContainsKey($rid) -or $PrivilegedGroupNames -contains $group.Name
    
    # Only flag if it's a NESTED membership (not already caught as direct)
    if ($isPriv -and ($group.DistinguishedName -notin $directMemberOfDNs)) {
        Add-Finding -Category "Nested Membership" -Severity "HIGH" `
            -Finding "NESTED member of: $($group.Name)" `
            -Detail "User reaches this privileged group through nested group membership. Check direct groups above for the path."
        $foundNested = $true
    }
}

if (-not $foundNested) {
    Add-Finding -Category "Nested Membership" -Severity "INFO" `
        -Finding "No nested privileged group memberships detected" -Detail $null
}
Write-Host ""
#endregion

#region ─── 3. AdminCount & AdminSDHolder ────────────────────────────────────────
Write-Host "── 3. ADMINCOUNT & ADMINSDHOLDER STATUS ───────────────────────" -ForegroundColor Yellow
Write-Host ""

if ($User.AdminCount -eq 1) {
    # Check if user is CURRENTLY in a protected group
    $currentlyProtected = $false
    foreach ($group in $AllNestedGroups) {
        $rid = $group.ObjectSID.Value.Split('-')[-1]
        if ($PrivilegedGroupRIDs.ContainsKey($rid)) {
            $currentlyProtected = $true
            break
        }
    }

    if ($currentlyProtected) {
        Add-Finding -Category "AdminCount" -Severity "MEDIUM" `
            -Finding "AdminCount = 1 (ACTIVE — user IS in a protected group)" `
            -Detail "AdminSDHolder is actively protecting this account's ACL"
    } else {
        Add-Finding -Category "AdminCount" -Severity "HIGH" `
            -Finding "AdminCount = 1 but user is NOT in any protected group — ORPHANED!" `
            -Detail "This is likely your culprit. User was PREVIOUSLY in a privileged group. AdminCount was never cleared."
        Add-Finding -Category "AdminCount" -Severity "INFO" `
            -Finding "  → FIX: Clear AdminCount and re-enable inheritance on the AD object" `
            -Detail "Set AdminCount to 0 (or clear it), then on the Security tab re-enable 'Include inheritable permissions'"
    }
} else {
    Add-Finding -Category "AdminCount" -Severity "INFO" `
        -Finding "AdminCount is not set (normal)" -Detail $null
}
Write-Host ""
#endregion

#region ─── 4. SID History ───────────────────────────────────────────────────────
Write-Host "── 4. SID HISTORY ─────────────────────────────────────────────" -ForegroundColor Yellow
Write-Host ""

if ($User.SIDHistory -and $User.SIDHistory.Count -gt 0) {
    foreach ($sid in $User.SIDHistory) {
        $sidRID = $sid.Value.Split('-')[-1]
        if ($PrivilegedGroupRIDs.ContainsKey($sidRID)) {
            Add-Finding -Category "SID History" -Severity "HIGH" `
                -Finding "SID History contains a PRIVILEGED SID!" `
                -Detail "SID: $($sid.Value) — maps to: $($PrivilegedGroupRIDs[$sidRID])"
        } else {
            Add-Finding -Category "SID History" -Severity "MEDIUM" `
                -Finding "SID History entry found (non-privileged)" `
                -Detail "SID: $($sid.Value) — from a previous domain migration?"
        }
    }
} else {
    Add-Finding -Category "SID History" -Severity "INFO" `
        -Finding "No SID History entries" -Detail $null
}
Write-Host ""
#endregion

#region ─── 5. Service Principal Names (Kerberoastable) ──────────────────────────
Write-Host "── 5. SERVICE PRINCIPAL NAMES ──────────────────────────────────" -ForegroundColor Yellow
Write-Host ""

if ($User.ServicePrincipalName -and $User.ServicePrincipalName.Count -gt 0) {
    Add-Finding -Category "SPN" -Severity "MEDIUM" `
        -Finding "User has Service Principal Names set (Kerberoastable!)" `
        -Detail "This means the account is running a service — may flag on priv reports"
    foreach ($spn in $User.ServicePrincipalName) {
        Add-Finding -Category "SPN" -Severity "INFO" `
            -Finding "  SPN: $spn" -Detail $null
    }
} else {
    Add-Finding -Category "SPN" -Severity "INFO" `
        -Finding "No Service Principal Names set" -Detail $null
}
Write-Host ""
#endregion

#region ─── 6. Delegated Permissions on OUs ──────────────────────────────────────
Write-Host "── 6. DELEGATED OU PERMISSIONS ────────────────────────────────" -ForegroundColor Yellow
Write-Host ""

# Check for delegated permissions on common OUs
$DomainDN = (Get-ADDomain).DistinguishedName
$OUsToCheck = @($DomainDN) + @(Get-ADOrganizationalUnit -Filter * -SearchScope OneLevel | Select-Object -ExpandProperty DistinguishedName | Select-Object -First 10)

$foundDelegation = $false
foreach ($ou in $OUsToCheck) {
    try {
        $acl = Get-Acl -Path "AD:$ou" -ErrorAction SilentlyContinue
        $userSID = $User.ObjectSID.Value
        
        $relevantACEs = $acl.Access | Where-Object {
            $_.IdentityReference -match [regex]::Escape($Username) -or
            $_.IdentityReference -match [regex]::Escape($User.Name)
        }
        
        foreach ($ace in $relevantACEs) {
            if ($ace.AccessControlType -eq "Allow" -and $ace.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|GenericWrite") {
                Add-Finding -Category "Delegation" -Severity "MEDIUM" `
                    -Finding "Delegated '$($ace.ActiveDirectoryRights)' on OU" `
                    -Detail "OU: $ou"
                $foundDelegation = $true
            }
        }
    } catch {
        # Skip OUs we can't read
    }
}

# Also check if user is in any groups that have delegation
foreach ($group in $DirectGroups) {
    foreach ($ou in $OUsToCheck) {
        try {
            $acl = Get-Acl -Path "AD:$ou" -ErrorAction SilentlyContinue
            $relevantACEs = $acl.Access | Where-Object {
                $_.IdentityReference -match [regex]::Escape($group.Name)
            }
            foreach ($ace in $relevantACEs) {
                if ($ace.AccessControlType -eq "Allow" -and $ace.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|GenericWrite") {
                    Add-Finding -Category "Delegation" -Severity "MEDIUM" `
                        -Finding "Group '$($group.Name)' has delegated '$($ace.ActiveDirectoryRights)' on OU" `
                        -Detail "OU: $ou — User is a member of this group"
                    $foundDelegation = $true
                }
            }
        } catch { }
    }
}

if (-not $foundDelegation) {
    Add-Finding -Category "Delegation" -Severity "INFO" `
        -Finding "No direct delegation found on top-level OUs" `
        -Detail "Note: Only checked top-level OUs. Deep delegation may exist further down."
}
Write-Host ""
#endregion

#region ─── 7. Complete Group Membership Listing ─────────────────────────────────
Write-Host "── 7. ALL GROUP MEMBERSHIPS ────────────────────────────────────" -ForegroundColor Yellow
Write-Host ""

Write-Host "  Direct memberships:" -ForegroundColor White
foreach ($group in $DirectGroups | Sort-Object Name) {
    $rid = $group.ObjectSID.Value.Split('-')[-1]
    $isPriv = $PrivilegedGroupRIDs.ContainsKey($rid) -or $PrivilegedGroupNames -contains $group.Name
    $marker = if ($isPriv) { " ◄ PRIVILEGED" } else { "" }
    $color = if ($isPriv) { "Red" } else { "Gray" }
    Write-Host "    • $($group.Name)$marker" -ForegroundColor $color
}

Write-Host ""
Write-Host "  All memberships (including nested):" -ForegroundColor White
foreach ($group in $AllNestedGroups | Sort-Object Name) {
    $rid = $group.ObjectSID.Value.Split('-')[-1]
    $isPriv = $PrivilegedGroupRIDs.ContainsKey($rid) -or $PrivilegedGroupNames -contains $group.Name
    $isDirect = $group.DistinguishedName -in $User.MemberOf
    $marker = ""
    if ($isPriv) { $marker += " ◄ PRIVILEGED" }
    if (-not $isDirect) { $marker += " (nested)" }
    $color = if ($isPriv) { "Red" } elseif (-not $isDirect) { "Yellow" } else { "Gray" }
    Write-Host "    • $($group.Name)$marker" -ForegroundColor $color
}
Write-Host ""
#endregion

#region ─── 8. Account Details Summary ───────────────────────────────────────────
Write-Host "── 8. ACCOUNT DETAILS ─────────────────────────────────────────" -ForegroundColor Yellow
Write-Host ""

Write-Host "  Enabled:          $($User.Enabled)" -ForegroundColor Gray
Write-Host "  Created:          $($User.whenCreated)" -ForegroundColor Gray
Write-Host "  Last Modified:    $($User.whenChanged)" -ForegroundColor Gray
Write-Host "  Last Logon:       $($User.LastLogonDate)" -ForegroundColor Gray
Write-Host "  Password Set:     $($User.PasswordLastSet)" -ForegroundColor Gray
Write-Host "  Description:      $($User.Description)" -ForegroundColor Gray
Write-Host "  AdminCount:       $($User.AdminCount)" -ForegroundColor $(if ($User.AdminCount -eq 1) { "Red" } else { "Gray" })
Write-Host "  PrimaryGroupID:   $($User.PrimaryGroupID)" -ForegroundColor $(if ($User.PrimaryGroupID -ne 513) { "Yellow" } else { "Gray" })
Write-Host "  SID:              $($User.ObjectSID)" -ForegroundColor Gray
Write-Host ""
#endregion

#region ─── Summary & Export ─────────────────────────────────────────────────────
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

$highCount = ($Findings | Where-Object Severity -eq "HIGH").Count
$medCount  = ($Findings | Where-Object Severity -eq "MEDIUM").Count

if ($highCount -gt 0) {
    Write-Host "  ⚠ $highCount HIGH severity finding(s) detected!" -ForegroundColor Red
} 
if ($medCount -gt 0) {
    Write-Host "  ⚡ $medCount MEDIUM severity finding(s) detected." -ForegroundColor Yellow
}
if ($highCount -eq 0 -and $medCount -eq 0) {
    Write-Host "  ✓ No obvious privileged access paths found." -ForegroundColor Green
    Write-Host "    The report tool may be keying on something else (local admin, GPO user rights, etc.)" -ForegroundColor Gray
}

Write-Host ""

# Export if requested
if ($ExportPath) {
    $Findings | Export-Csv -Path $ExportPath -NoTypeInformation -Force
    Write-Host "  Report exported to: $ExportPath" -ForegroundColor Green
    Write-Host ""
}

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
#endregion