# Find-PrivilegedAccessPaths

Tools for investigating and auditing privileged access in Active Directory. Two scripts: one explains why a single user is flagged as privileged, the other audits the whole domain.

## Scripts

### Find-PrivilegedAccessPaths.ps1

Traces every path through which a specific user may be flagged as privileged or admin. Use it when a user appears on a Privileged Account Report and you need to find out **why**.

Checks performed:
- Direct membership in privileged groups (Domain Admins, Enterprise Admins, Backup Operators, ...)
- Nested (indirect) membership, with the path: `user -> Helpdesk -> IT-Admins -> Domain Admins`
- Privileged **primary group** (`primaryGroupID`), which never appears in `memberOf`
- `adminCount = 1`, and whether the user is still in a group AdminSDHolder protects (orphaned or active)
- SID History carrying privileged SIDs from an old domain
- Service Principal Names (service accounts / Kerberoastable)
- Delegated permissions on the domain root and up to 10 top-level OUs, matched by SID against the user and every group they are in

```powershell
.\Find-PrivilegedAccessPaths.ps1 -Username "jsmith"

.\Find-PrivilegedAccessPaths.ps1 -Username "jsmith" -OutputPath "C:\Reports"

.\Find-PrivilegedAccessPaths.ps1 -Username "jsmith" -Server dc01.contoso.com -Credential (Get-Credential)
```

### Get-DomainPrivilegedAccess.ps1

Domain-wide audit: finds every user with any form of admin access and explains how they got it. Prints a colour-coded console report and writes a CSV.

```powershell
.\Get-DomainPrivilegedAccess.ps1

.\Get-DomainPrivilegedAccess.ps1 -OutputPath "C:\Reports" -IncludeDisabled

.\Get-DomainPrivilegedAccess.ps1 -Server dc01.contoso.com -Credential (Get-Credential) -MaxNestingDepth 15
```

The CSV has one row per finding, including a `NestedVia` column holding the nesting path (for example `IT-Admins -> Helpdesk`). A user whose primary group is the privileged group shows as `Primary-group member of ...`; a user who reaches it through a nested group's primary group shows `Nested member of ...` with `(primary group)` at the end of the path.

## Parameters

### Find-PrivilegedAccessPaths.ps1

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-Username` | Yes | sAMAccountName of the user to investigate |
| `-OutputPath` | No | Export the findings as CSV. A directory, or a full path ending in `.csv`. Alias: `-ExportPath` (the old name still works). Nothing is exported when omitted. |
| `-Server` | No | DC or domain to query (passed to every AD cmdlet and the OU ACL reads) |
| `-Credential` | No | Credential for every AD query |
| `-MaxNestingDepth` | No | Parent-group levels to follow (default 10) |
| `-LoadFunctionsOnly` | No | Define the functions and exit (used by the tests) |

### Get-DomainPrivilegedAccess.ps1

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-OutputPath` | No | Directory (file name `PrivilegedAccessAudit_<timestamp>.csv` is generated) or a full `.csv` path. Defaults to the **current directory** (it used to be the Desktop). Alias: `-ExportPath`. |
| `-Server` | No | DC or domain to query |
| `-Credential` | No | Credential for every AD query |
| `-IncludeDisabled` | No | Include disabled accounts |
| `-MaxNestingDepth` | No | Nested-group levels to follow below each privileged group (default 10) |
| `-LoadFunctionsOnly` | No | Define the functions and exit (used by the tests) |

## How privileged groups are recognised

Groups are matched by **well-known SID / RID**, never by name, so a localized domain (for example `Domaenen-Admins` or `Administratoren`) is audited correctly, and a group someone merely *named* "Domain Admins" is not mistaken for the real one.

| Matched by SID | Groups |
|----------------|--------|
| `<domain>-RID` | 512 Domain Admins, 516 Domain Controllers, 517 Cert Publishers, 518 Schema Admins, 519 Enterprise Admins, 520 Group Policy Creator Owners, 521 Read-only Domain Controllers, 525 Protected Users, 526 Key Admins, 527 Enterprise Key Admins, 553 RAS and IAS Servers |
| `S-1-5-32-RID` | 544 Administrators, 548 Account Operators, 549 Server Operators, 550 Print Operators, 551 Backup Operators, 552 Replicators, 555 Remote Desktop Users, 578 Hyper-V Administrators, 580 Remote Management Users |
| By name (no well-known SID) | DnsAdmins, DHCP Administrators |

The two name-only groups are created when the role is installed and get an ordinary RID, so they are not found if renamed or localized. Source: [Understand security identifiers](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers). The forest-wide groups (518, 519, 526, 527) are also looked up under the forest root domain SID, because that page lists Key Admins and Enterprise Key Admins under the opposite scope from how AD creates them.

"Active" `adminCount` is judged against the groups AdminSDHolder protects ([Appendix C](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)), not every privileged group.

## How membership is resolved

- Nesting is walked by hand, one level at a time, breadth-first, with a visited set so circular nesting terminates. The recorded path is the shortest one. `Get-ADGroupMember -Recursive` is deliberately not used: it returns only leaf members and drops the path.
- `primaryGroupID` is merged in. It holds the RID of the user's primary group and is not a linked attribute, so primary-group members are not in any group's `member` attribute ([Primary-Group-ID](https://learn.microsoft.com/windows/win32/adschema/a-primarygroupid)). For every group reached, users whose `primaryGroupID` equals the group's RID are added. A user who is both a member and has it as primary group appears once, as Primary.
- If a privileged group has Domain Users (RID 513) nested inside it, every user is reported; that is accurate, just large.

## Requirements

- Windows PowerShell 3.0 or later (`#Requires -Version 3.0`; no `::new()` or other 4.0+/5.x syntax)
- ActiveDirectory module (RSAT), imported at runtime with a try/catch
- Domain Admin or equivalent read access

## Tests

```powershell
Invoke-Pester .\Tests\PrivilegedAccess.Tests.ps1   # Pester 5
```

The tests replace the AD cmdlets with in-memory fakes and cover the nesting path, circular nesting, primary-group members, localized group names, a decoy group named "Domain Admins", `-Server` propagation, and that the helper functions shared by the two scripts stay identical.
