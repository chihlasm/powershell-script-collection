<#
.SYNOPSIS
    Domain-wide Privileged Access Audit — finds every user with any form of admin
    access and explains exactly HOW they got it.

.DESCRIPTION
    Scans the entire domain for users who have elevated privileges through ANY path:
    
    • Direct membership in built-in privileged groups
    • Nested (indirect) membership in privileged groups
    • Orphaned AdminCount = 1 (previously privileged, never cleaned up)
    • SID History carrying privileged SIDs from old domains
    • Service Principal Names (Kerberoastable service accounts)
    • Non-standard PrimaryGroupID (hidden privilege that doesn't show in memberOf)
    
    Outputs a color-coded console report AND exports to CSV for documentation.

.PARAMETER ExportPath
    Path for the CSV export. Defaults to Desktop\PrivilegedAccessAudit_<date>.csv

.PARAMETER IncludeDisabled
    If specified, includes disabled accounts in the audit.

.EXAMPLE
    .\Get-DomainPrivilegedAccess.ps1

.EXAMPLE
    .\Get-DomainPrivilegedAccess.ps1 -ExportPath "C:\Reports\priv-audit.csv" -IncludeDisabled

.NOTES
    Requires: ActiveDirectory PowerShell module
    Run as:   Domain Admin or equivalent read access
    Time:     ~1-5 minutes depending on domain size
    Author:   Generated for VC3 MSP operations
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ExportPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabled
)

#region ─── Setup ────────────────────────────────────────────────────────────────
$ErrorActionPreference = "Stop"

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "ActiveDirectory module not found. Install RSAT or run from a DC."
    return
}

$Domain = Get-ADDomain
$DomainSID = $Domain.DomainSID.Value
$DomainDN = $Domain.DistinguishedName
$DomainName = $Domain.NetBIOSName
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

if (-not $ExportPath) {
    $ExportPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "PrivilegedAccessAudit_$Timestamp.csv"
}

# Master results collection
$Results = [System.Collections.ArrayList]::new()

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  DOMAIN-WIDE PRIVILEGED ACCESS AUDIT" -ForegroundColor Cyan
Write-Host "  Domain:  $DomainName ($($Domain.DNSRoot))" -ForegroundColor Cyan
Write-Host "  Date:    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "  Export:  $ExportPath" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
#endregion

#region ─── Define Privileged Groups ─────────────────────────────────────────────

# Built-in privileged groups by well-known RID
# These are the groups that AdminSDHolder protects and that any PAM tool flags
$PrivilegedGroups = [ordered]@{
    # Domain-specific (SID = DomainSID-RID)
    "$DomainSID-512"  = @{ Name = "Domain Admins";                  Risk = "CRITICAL"; Note = "Full domain control" }
    "$DomainSID-518"  = @{ Name = "Schema Admins";                  Risk = "CRITICAL"; Note = "Can modify AD schema (forest-wide)" }
    "$DomainSID-519"  = @{ Name = "Enterprise Admins";              Risk = "CRITICAL"; Note = "Full forest control" }
    "$DomainSID-520"  = @{ Name = "Group Policy Creator Owners";    Risk = "HIGH";     Note = "Can create/edit GPOs" }
    
    # Builtin groups (SID = S-1-5-32-RID)
    "S-1-5-32-544"    = @{ Name = "Administrators";                 Risk = "CRITICAL"; Note = "Local admin on DCs = domain admin" }
    "S-1-5-32-548"    = @{ Name = "Account Operators";              Risk = "HIGH";     Note = "Can manage most AD accounts and groups" }
    "S-1-5-32-549"    = @{ Name = "Server Operators";               Risk = "HIGH";     Note = "Can log on to DCs, manage services and shares" }
    "S-1-5-32-550"    = @{ Name = "Print Operators";                Risk = "MEDIUM";   Note = "Can log on to DCs, load drivers" }
    "S-1-5-32-551"    = @{ Name = "Backup Operators";               Risk = "HIGH";     Note = "Can back up/restore any file, log on to DCs" }
    "S-1-5-32-552"    = @{ Name = "Replicators";                    Risk = "MEDIUM";   Note = "File replication support" }
}

# Additional groups to check by name (not always well-known SIDs)
$AdditionalPrivGroups = @(
    @{ Name = "DnsAdmins";              Risk = "HIGH";   Note = "Can load arbitrary DLLs on DCs via DNS service — privilege escalation path" }
    @{ Name = "Cert Publishers";        Risk = "MEDIUM"; Note = "Can publish certificates to AD" }
    @{ Name = "Key Admins";             Risk = "MEDIUM"; Note = "Can perform admin actions on key objects" }
    @{ Name = "Enterprise Key Admins";  Risk = "MEDIUM"; Note = "Forest-wide key administration" }
    @{ Name = "Protected Users";        Risk = "INFO";   Note = "Security hardening group — not a privilege, but notable" }
    @{ Name = "DHCP Administrators";    Risk = "MEDIUM"; Note = "Full DHCP management" }
    @{ Name = "Hyper-V Administrators"; Risk = "HIGH";   Note = "Can compromise VMs including virtual DCs" }
    @{ Name = "Remote Desktop Users";   Risk = "LOW";    Note = "RDP access — check if applied to DCs" }
    @{ Name = "Remote Management Users";Risk = "MEDIUM"; Note = "WinRM/PowerShell remoting access" }
)

# Resolve additional groups to SIDs where they exist
foreach ($grp in $AdditionalPrivGroups) {
    try {
        $adGroup = Get-ADGroup -Filter "Name -eq '$($grp.Name)'" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($adGroup) {
            $PrivilegedGroups[$adGroup.SID.Value] = @{
                Name = $grp.Name
                Risk = $grp.Risk
                Note = $grp.Note
            }
        }
    } catch { }
}

Write-Host "  Tracking $($PrivilegedGroups.Count) privileged groups..." -ForegroundColor Gray
Write-Host ""
#endregion

#region ─── Resolve All Privileged Group Members (Direct + Nested) ───────────────
Write-Host "── PHASE 1: RESOLVING GROUP MEMBERSHIPS ───────────────────────" -ForegroundColor Yellow
Write-Host ""

# For each privileged group, get all members (recursive) and track the path
$GroupMembershipMap = @{}  # Key = user DN, Value = list of { GroupName, MembershipType, Risk, Note }

$groupCount = 0
foreach ($sid in $PrivilegedGroups.Keys) {
    $groupInfo = $PrivilegedGroups[$sid]
    $groupCount++
    
    try {
        $group = Get-ADGroup -Identity $sid -ErrorAction Stop
    } catch {
        # Group doesn't exist in this domain (e.g., Enterprise Admins in child domain)
        continue
    }
    
    Write-Host "  [$groupCount/$($PrivilegedGroups.Count)] $($groupInfo.Name)..." -ForegroundColor Gray -NoNewline
    
    # Get direct members
    $directMembers = @()
    try {
        $directMembers = Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction Stop |
            Where-Object { $_.objectClass -eq "user" }
    } catch { }
    
    foreach ($member in $directMembers) {
        if (-not $GroupMembershipMap.ContainsKey($member.distinguishedName)) {
            $GroupMembershipMap[$member.distinguishedName] = [System.Collections.ArrayList]::new()
        }
        [void]$GroupMembershipMap[$member.distinguishedName].Add(@{
            GroupName      = $groupInfo.Name
            GroupSID       = $sid
            MembershipType = "Direct"
            Risk           = $groupInfo.Risk
            Note           = $groupInfo.Note
        })
    }
    
    # Get nested members (recursive)
    $nestedMembers = @()
    try {
        $nestedMembers = Get-ADGroupMember -Identity $group.DistinguishedName -Recursive -ErrorAction Stop |
            Where-Object { $_.objectClass -eq "user" }
    } catch { }
    
    # Find users who are only in the nested set (not direct)
    $directSIDs = $directMembers | ForEach-Object { $_.SID.Value }
    $nestedOnly = $nestedMembers | Where-Object { $_.SID.Value -notin $directSIDs }
    
    foreach ($member in $nestedOnly) {
        if (-not $GroupMembershipMap.ContainsKey($member.distinguishedName)) {
            $GroupMembershipMap[$member.distinguishedName] = [System.Collections.ArrayList]::new()
        }
        [void]$GroupMembershipMap[$member.distinguishedName].Add(@{
            GroupName      = $groupInfo.Name
            GroupSID       = $sid
            MembershipType = "Nested"
            Risk           = $groupInfo.Risk
            Note           = $groupInfo.Note
        })
    }
    
    $totalForGroup = $directMembers.Count + $nestedOnly.Count
    Write-Host " $($directMembers.Count) direct, $($nestedOnly.Count) nested" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  Found $($GroupMembershipMap.Count) unique users with privileged group access." -ForegroundColor White
Write-Host ""
#endregion

#region ─── Scan for AdminCount Orphans & SID History ────────────────────────────
Write-Host "── PHASE 2: SCANNING FOR ADMINCOUNT, SID HISTORY & SPNs ──────" -ForegroundColor Yellow
Write-Host ""

# Get all users with AdminCount = 1
$AdminCountFilter = if ($IncludeDisabled) {
    { AdminCount -eq 1 }
} else {
    { AdminCount -eq 1 -and Enabled -eq $true }
}

$AdminCountUsers = Get-ADUser -Filter $AdminCountFilter -Properties AdminCount, MemberOf, SIDHistory, `
    ServicePrincipalName, PrimaryGroupID, Enabled, LastLogonDate, whenCreated, Description, PasswordLastSet

Write-Host "  Found $($AdminCountUsers.Count) users with AdminCount = 1" -ForegroundColor Gray

# Get all users with SID History
$SIDHistoryUsers = Get-ADUser -Filter * -Properties SIDHistory -ErrorAction SilentlyContinue |
    Where-Object { $_.SIDHistory.Count -gt 0 }

Write-Host "  Found $(($SIDHistoryUsers | Measure-Object).Count) users with SID History" -ForegroundColor Gray

# Get all users with SPNs (service accounts on user objects)
$SPNFilter = if ($IncludeDisabled) {
    { ServicePrincipalName -like "*" }
} else {
    { ServicePrincipalName -like "*" -and Enabled -eq $true }
}

$SPNUsers = Get-ADUser -Filter $SPNFilter -Properties ServicePrincipalName, Enabled, LastLogonDate, Description

Write-Host "  Found $(($SPNUsers | Measure-Object).Count) users with Service Principal Names" -ForegroundColor Gray

# Get users with non-standard PrimaryGroupID
$PrimaryGroupUsers = Get-ADUser -Filter * -Properties PrimaryGroupID -ErrorAction SilentlyContinue |
    Where-Object { $_.PrimaryGroupID -ne 513 -and $_.PrimaryGroupID -ne 514 }
    # 513 = Domain Users, 514 = Domain Guests — anything else is unusual

Write-Host "  Found $(($PrimaryGroupUsers | Measure-Object).Count) users with non-standard PrimaryGroupID" -ForegroundColor Gray
Write-Host ""
#endregion

#region ─── Build Master User List ───────────────────────────────────────────────
Write-Host "── PHASE 3: BUILDING MASTER REPORT ────────────────────────────" -ForegroundColor Yellow
Write-Host ""

# Collect all unique user DNs we need to report on
$AllFlaggedDNs = [System.Collections.Generic.HashSet[string]]::new()

foreach ($dn in $GroupMembershipMap.Keys) { [void]$AllFlaggedDNs.Add($dn) }
foreach ($u in $AdminCountUsers)          { [void]$AllFlaggedDNs.Add($u.DistinguishedName) }
foreach ($u in $SIDHistoryUsers)          { [void]$AllFlaggedDNs.Add($u.DistinguishedName) }
foreach ($u in $SPNUsers)                 { [void]$AllFlaggedDNs.Add($u.DistinguishedName) }
foreach ($u in $PrimaryGroupUsers)        { [void]$AllFlaggedDNs.Add($u.DistinguishedName) }

Write-Host "  Total unique flagged users: $($AllFlaggedDNs.Count)" -ForegroundColor White
Write-Host ""

# Now build the full report for each user
$userCount = 0
foreach ($dn in $AllFlaggedDNs) {
    $userCount++
    
    try {
        $adUser = Get-ADUser -Identity $dn -Properties `
            SamAccountName, Name, Enabled, AdminCount, SIDHistory, `
            ServicePrincipalName, PrimaryGroupID, MemberOf, `
            LastLogonDate, PasswordLastSet, whenCreated, Description, Title, Department
    } catch {
        continue
    }
    
    # Skip disabled unless requested
    if (-not $IncludeDisabled -and -not $adUser.Enabled) { continue }
    
    # ── Determine all flags for this user ──
    $flags = [System.Collections.ArrayList]::new()
    $highestRisk = "INFO"
    $riskOrder = @{ "CRITICAL" = 4; "HIGH" = 3; "MEDIUM" = 2; "LOW" = 1; "INFO" = 0 }
    
    # Flag 1: Privileged group memberships
    if ($GroupMembershipMap.ContainsKey($dn)) {
        foreach ($membership in $GroupMembershipMap[$dn]) {
            $flagText = "$($membership.MembershipType) member of $($membership.GroupName)"
            [void]$flags.Add(@{
                Category = "Group Membership"
                Flag     = $flagText
                Risk     = $membership.Risk
                Detail   = "$($membership.Note)"
            })
            if ($riskOrder[$membership.Risk] -gt $riskOrder[$highestRisk]) {
                $highestRisk = $membership.Risk
            }
        }
    }
    
    # Flag 2: Orphaned AdminCount
    if ($adUser.AdminCount -eq 1) {
        $inProtectedGroup = $GroupMembershipMap.ContainsKey($dn)
        if (-not $inProtectedGroup) {
            [void]$flags.Add(@{
                Category = "Orphaned AdminCount"
                Flag     = "AdminCount = 1 but NOT in any privileged group"
                Risk     = "HIGH"
                Detail   = "Was previously privileged. Clear AdminCount and re-enable ACL inheritance."
            })
            if ($riskOrder["HIGH"] -gt $riskOrder[$highestRisk]) { $highestRisk = "HIGH" }
        } else {
            [void]$flags.Add(@{
                Category = "AdminCount"
                Flag     = "AdminCount = 1 (active — currently in protected group)"
                Risk     = "INFO"
                Detail   = "Expected behavior for current privileged users"
            })
        }
    }
    
    # Flag 3: SID History
    if ($adUser.SIDHistory -and $adUser.SIDHistory.Count -gt 0) {
        foreach ($sid in $adUser.SIDHistory) {
            $sidStr = $sid.Value
            $sidRID = $sidStr.Split('-')[-1]
            $isPrivSID = $PrivilegedGroups.Keys | Where-Object { $_ -match "$sidRID$" }
            
            if ($isPrivSID) {
                [void]$flags.Add(@{
                    Category = "SID History"
                    Flag     = "Carries privileged SID: $sidStr"
                    Risk     = "CRITICAL"
                    Detail   = "Old SID grants admin access from a previous domain"
                })
                if ($riskOrder["CRITICAL"] -gt $riskOrder[$highestRisk]) { $highestRisk = "CRITICAL" }
            } else {
                [void]$flags.Add(@{
                    Category = "SID History"
                    Flag     = "SID History present: $sidStr"
                    Risk     = "LOW"
                    Detail   = "Non-privileged old SID — from domain migration"
                })
            }
        }
    }
    
    # Flag 4: SPNs
    if ($adUser.ServicePrincipalName -and $adUser.ServicePrincipalName.Count -gt 0) {
        $spnList = ($adUser.ServicePrincipalName | Select-Object -First 3) -join "; "
        $spnRisk = if ($GroupMembershipMap.ContainsKey($dn)) { "HIGH" } else { "MEDIUM" }
        [void]$flags.Add(@{
            Category = "Service Principal Name"
            Flag     = "Has SPNs set — Kerberoastable"
            Risk     = $spnRisk
            Detail   = "SPNs: $spnList"
        })
        if ($riskOrder[$spnRisk] -gt $riskOrder[$highestRisk]) { $highestRisk = $spnRisk }
    }
    
    # Flag 5: Non-standard PrimaryGroupID
    if ($adUser.PrimaryGroupID -notin @(513, 514)) {
        $pgRisk = "MEDIUM"
        $pgName = switch ($adUser.PrimaryGroupID) {
            512 { $pgRisk = "CRITICAL"; "Domain Admins" }
            516 { $pgRisk = "CRITICAL"; "Domain Controllers" }
            518 { $pgRisk = "CRITICAL"; "Schema Admins" }
            519 { $pgRisk = "CRITICAL"; "Enterprise Admins" }
            544 { $pgRisk = "CRITICAL"; "Administrators" }
            548 { $pgRisk = "HIGH";     "Account Operators" }
            549 { $pgRisk = "HIGH";     "Server Operators" }
            550 { $pgRisk = "MEDIUM";   "Print Operators" }
            551 { $pgRisk = "HIGH";     "Backup Operators" }
            default { "Unknown (RID: $($adUser.PrimaryGroupID))" }
        }
        [void]$flags.Add(@{
            Category = "PrimaryGroupID"
            Flag     = "Non-standard PrimaryGroupID: $($adUser.PrimaryGroupID) ($pgName)"
            Risk     = $pgRisk
            Detail   = "This membership is HIDDEN from the memberOf attribute!"
        })
        if ($riskOrder[$pgRisk] -gt $riskOrder[$highestRisk]) { $highestRisk = $pgRisk }
    }
    
    # ── Add to Results ──
    foreach ($flag in $flags) {
        [void]$Results.Add([PSCustomObject]@{
            Username         = $adUser.SamAccountName
            DisplayName      = $adUser.Name
            Enabled          = $adUser.Enabled
            HighestRisk      = $highestRisk
            FlagCategory     = $flag.Category
            Flag             = $flag.Flag
            FlagRisk         = $flag.Risk
            Detail           = $flag.Detail
            Title            = $adUser.Title
            Department       = $adUser.Department
            Description      = $adUser.Description
            LastLogon        = $adUser.LastLogonDate
            PasswordLastSet  = $adUser.PasswordLastSet
            AccountCreated   = $adUser.whenCreated
            DistinguishedName = $adUser.DistinguishedName
        })
    }
}
#endregion

#region ─── Console Report ───────────────────────────────────────────────────────
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  RESULTS" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Group results by user for readable output
$UserGroups = $Results | Group-Object Username | Sort-Object { 
    $riskOrder[($_.Group | Select-Object -First 1).HighestRisk] 
} -Descending

foreach ($userGroup in $UserGroups) {
    $first = $userGroup.Group | Select-Object -First 1
    $riskColor = switch ($first.HighestRisk) {
        "CRITICAL" { "Red" }
        "HIGH"     { "Yellow" }
        "MEDIUM"   { "DarkYellow" }
        "LOW"      { "Gray" }
        default    { "White" }
    }
    $enabledStr = if ($first.Enabled) { "" } else { " [DISABLED]" }
    
    Write-Host "  ┌─ " -ForegroundColor DarkGray -NoNewline
    Write-Host "$($first.Username)" -ForegroundColor White -NoNewline
    Write-Host " ($($first.DisplayName))$enabledStr" -ForegroundColor DarkGray -NoNewline
    Write-Host " [$($first.HighestRisk)]" -ForegroundColor $riskColor
    
    if ($first.Title -or $first.Department) {
        $titleDept = (@($first.Title, $first.Department) | Where-Object { $_ }) -join " / "
        Write-Host "  │  $titleDept" -ForegroundColor DarkGray
    }
    if ($first.LastLogon) {
        Write-Host "  │  Last logon: $($first.LastLogon)" -ForegroundColor DarkGray
    }
    
    foreach ($row in $userGroup.Group) {
        $flagIcon = switch ($row.FlagRisk) {
            "CRITICAL" { "🔴" }
            "HIGH"     { "🟠" }
            "MEDIUM"   { "🟡" }
            "LOW"      { "🔵" }
            default    { "⚪" }
        }
        $flagColor = switch ($row.FlagRisk) {
            "CRITICAL" { "Red" }
            "HIGH"     { "Yellow" }
            "MEDIUM"   { "DarkYellow" }
            "LOW"      { "Gray" }
            default    { "DarkGray" }
        }
        
        Write-Host "  │  $flagIcon " -NoNewline
        Write-Host "[$($row.FlagRisk.PadRight(8))] " -ForegroundColor $flagColor -NoNewline
        Write-Host "$($row.Flag)" -ForegroundColor White
        if ($row.Detail) {
            Write-Host "  │     └─ $($row.Detail)" -ForegroundColor DarkGray
        }
    }
    Write-Host "  └──────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
}
#endregion

#region ─── Summary Stats ────────────────────────────────────────────────────────
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

$uniqueUsers = $Results | Select-Object -Unique Username
$critUsers = ($Results | Where-Object HighestRisk -eq "CRITICAL" | Select-Object -Unique Username).Count
$highUsers = ($Results | Where-Object HighestRisk -eq "HIGH" | Select-Object -Unique Username).Count
$medUsers  = ($Results | Where-Object HighestRisk -eq "MEDIUM" | Select-Object -Unique Username).Count
$orphanedAdminCount = ($Results | Where-Object FlagCategory -eq "Orphaned AdminCount" | Select-Object -Unique Username).Count
$nestedOnly = ($Results | Where-Object { $_.Flag -match "^Nested member" } | Select-Object -Unique Username).Count

Write-Host "  Total privileged users found:  $($uniqueUsers.Count)" -ForegroundColor White
Write-Host ""
Write-Host "  Risk Breakdown:" -ForegroundColor White
Write-Host "    CRITICAL:  $critUsers users" -ForegroundColor Red
Write-Host "    HIGH:      $highUsers users" -ForegroundColor Yellow
Write-Host "    MEDIUM:    $medUsers users" -ForegroundColor DarkYellow
Write-Host ""
Write-Host "  Notable Findings:" -ForegroundColor White
Write-Host "    Orphaned AdminCount (stale):     $orphanedAdminCount users" -ForegroundColor $(if ($orphanedAdminCount -gt 0) { "Yellow" } else { "Gray" })
Write-Host "    Nested-only privileged access:    $nestedOnly users" -ForegroundColor $(if ($nestedOnly -gt 0) { "Yellow" } else { "Gray" })
Write-Host ""

# Group membership breakdown
Write-Host "  Privileged Group Membership Counts:" -ForegroundColor White
$groupCounts = $Results | Where-Object FlagCategory -eq "Group Membership" | 
    ForEach-Object { ($_.Flag -replace "^(Direct|Nested) member of ", "") } |
    Group-Object | Sort-Object Count -Descending

foreach ($gc in $groupCounts) {
    $gcRisk = ($PrivilegedGroups.Values | Where-Object Name -eq $gc.Name | Select-Object -First 1).Risk
    $gcColor = switch ($gcRisk) {
        "CRITICAL" { "Red" }
        "HIGH"     { "Yellow" }
        "MEDIUM"   { "DarkYellow" }
        default    { "Gray" }
    }
    Write-Host "    $($gc.Name): " -ForegroundColor $gcColor -NoNewline
    Write-Host "$($gc.Count) users" -ForegroundColor White
}
Write-Host ""
#endregion

#region ─── Export ────────────────────────────────────────────────────────────────
try {
    $Results | Export-Csv -Path $ExportPath -NoTypeInformation -Force
    Write-Host "  ✅ Report exported to: $ExportPath" -ForegroundColor Green
} catch {
    Write-Warning "Failed to export CSV: $_"
    # Try fallback to temp
    $fallback = Join-Path $env:TEMP "PrivilegedAccessAudit_$Timestamp.csv"
    try {
        $Results | Export-Csv -Path $fallback -NoTypeInformation -Force
        Write-Host "  ✅ Report exported to fallback: $fallback" -ForegroundColor Green
    } catch {
        Write-Warning "Could not export report. Results displayed above."
    }
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  AUDIT COMPLETE" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
#endregion