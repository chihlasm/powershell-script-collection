# AD Group Membership Export

Exports Active Directory groups and the users inside them to a single flat CSV — one row per group-member pair. Built for access reviews, client handoff documentation, and "who has access to what" tickets.

Add `-UserReport` to flip the same data around and get a **user-centric** view: one entry per person listing every group they hold, how they got it, and — critically — which groups they hold by more than one path.

## For non-technical users: just double-click

Hand someone the whole folder and tell them to double-click **`Run-AccessReport.bat`**. No parameters, no PowerShell knowledge.

They get a plain-English menu:

```text
   What would you like to find out?

     [1] Who has access to what?
         Every person and the groups they belong to.
         Best choice if you are not sure.

     [2] Who is in specific groups?
     [3] One department or area only
     [Q] Quit without running anything
```

Option 1 needs zero typing and runs the full access review — `-IncludeNested -ExcludeBuiltin -UserReport` are always applied, so they get the good report without knowing those flags exist. Option 3 lists the OUs found in the directory as a numbered menu rather than asking for a distinguished name.

What the launcher handles for them:

- **Checks prerequisites first**, before asking anything. Missing RSAT or an unreachable DC produces a plain-English explanation and the exact command for IT to run — not a red stack trace.
- **Saves to `C:\ADReports\<timestamp>\`, never a synced folder.** Files written into OneDrive can become placeholders — the file exists but its content is in the cloud, so copying it produces an empty file. A cloud-synced destination is refused outright, falling back to Documents if `C:\` is not writable.
- **Verifies the files are not empty**, then offers to zip them. A zip cannot arrive as a half-synced placeholder — it transfers whole or fails loudly — so it is the recommended handoff format.
- **Never closes on an error.** Every failure path ends with what to do next and waits for Enter.
- **Offers to open the report** in the default browser when it is done.

Requirements are the same as the script's: PowerShell 5.1, RSAT, and directory read access. Administrator rights are not needed.

## Quick start

```powershell
# Every group in the domain, direct members only
.\Export-ADGroupMembership.ps1

# The usual access-review run: real groups, nested membership expanded
.\Export-ADGroupMembership.ps1 -IncludeNested -ExcludeBuiltin -OutputPath C:\Reports

# Same run, plus the user-centric HTML report and CSV
.\Export-ADGroupMembership.ps1 -IncludeNested -ExcludeBuiltin -UserReport -OutputPath C:\Reports
```

Produces `ADGroupMembership_<timestamp>.csv` plus a matching `.log` in the output folder. With `-UserReport`, also `ADUserAccess_<timestamp>.html` and `ADUserAccess_<timestamp>.csv`.

## The user-centric report (`-UserReport`)

Answers "what does this person have access to, and how did they get it?" — the question a manager review or an offboarding check actually asks.

**One HTML file**, self-contained (no CDN, no network access, opens on an isolated server and survives being emailed). One collapsible card per user, dark by default with a light toggle, a live filter box, and a "show only duplicate access" filter.

**One CSV**, one row per user, for pivoting and filtering in Excel.

### Duplicate access paths are the headline finding

Nesting routinely grants the same group by several routes at once — directly *and* through a nested chain, or through two branches that both lead to the same place. A report that quietly de-duplicates hides this, and the cost is a failed access removal: the account is pulled from one group, the ticket closes, and the user still has the access through the route nobody saw.

So each group appears once per user, but a group reachable more than once is flagged:

```text
● VPN-Users                                    DUPLICATE ×2    direct
  Direct member
  ┌ ALSO REACHABLE BY
  └ IT-Staff → Helpdesk → VPN-Users
```

The headline path is the strongest one (Direct beats Primary beats shallowest Nested); every other route is listed beneath it. Nothing is discarded.

This surfaces at three levels so it can't be missed:

| Level | What you see |
|---|---|
| Per group | `DUPLICATE ×N` badge, amber row, every alternate route listed |
| Per user | Count of duplicate groups and total surplus paths in the card header |
| Per report | Header stat, a banner, and users ranked by surplus paths so the worst cases sort first |
| Console | A `[WARN]` at the end of the run naming the count |

**Severity is surplus paths, not affected groups.** A group reachable three ways needs two removals before access actually stops, so it outranks a group reachable twice.

### User report parameters

| Parameter | Purpose |
|---|---|
| `-UserReport` | Write the user-centric HTML + CSV alongside the group CSV. |
| `-IncludeDisabled` | Include disabled accounts. Default is enabled accounts only. |

### User CSV columns

`SamAccountName`, `DisplayName`, `UserPrincipalName`, `EmailAddress`, `Department`, `Title`, `Enabled`, `GroupCount`, `DirectCount`, `NestedCount`, `PrimaryCount`, `RedundantCount`, `SurplusPathCount`, `Groups`, `RedundantGroups`, `LastLogonDate`, `PasswordLastSet`, `MemberDN`, `ExportDate`

`Groups` is semicolon-delimited with the path annotated per group; `RedundantGroups` spells out every route for the duplicated ones. Filter or sort on `SurplusPathCount` to triage.

### Two things to know

- **`-UserReport` wants `-IncludeNested`.** Without it there are no inherited paths, so duplicates cannot exist and the report understates access. The script warns rather than refusing.
- **A narrowed run gives a partial view.** With `-SearchBase` or `-GroupName`, each person's list covers only the groups scanned — not their full domain membership. The HTML says so in a banner when the run was narrowed, so a partial view is never mistaken for a complete one.

## Why not just `Get-ADGroupMember`?

Three things a naive loop gets wrong. Each one produces a confident, plausible, wrong answer rather than an error — which is the dangerous kind of bug in an access review.

### 1. `-Recursive` throws away the nesting path

Microsoft's documentation is explicit that `-Recursive` *"gets all members in the hierarchy of the group that do not contain child objects."* It returns **leaves only**. If `App-Admins` contains `IT-Staff` which contains `jdoe`, you get `jdoe` — with nothing recording that the access came via `IT-Staff`. For an audit, *how* someone got access is the finding.

This script walks the tree one level at a time and records `MembershipType`, `NestingDepth`, and `NestedVia` (`IT-Staff -> Helpdesk`).

### 2. "Domain Users" appears empty

A user's primary group is stored in the **user's** `primaryGroupID` attribute — *"the relative identifier (RID) for the primary group of the user. By default, this is the RID for the Domain Users group."* It is **not a linked attribute**, so it is never written into the group's `member` attribute.

The practical result: `Get-ADGroupMember "Domain Users"` returns essentially nothing on a perfectly healthy domain. A report that says "Domain Users: 0 members" looks like a finding and is actually a bug.

This script reconstructs those members by matching `primaryGroupID` against the group's RID and tags them `MembershipType = Primary`. Disable with `-SkipPrimaryGroupMembers` on very large domains where the extra query is expensive.

### 3. Non-user members get silently dropped

Group members *"can be users, groups, and computers."* Filtering to `objectClass -eq 'user'` makes a group whose members are all nested groups export as empty. This script keeps all three by default; use `-UserMembersOnly` when you explicitly want just users.

## Parameters

| Parameter | Purpose |
|---|---|
| `-Server` | DC or domain to query. Defaults to the auto-discovered DC. |
| `-Credential` | Credentials for the AD queries. |
| `-GroupName` | Group name(s), wildcards supported (`'HR-*'`). Matches Name and SamAccountName. Omit for all groups. |
| `-SearchBase` | Restrict to an OU by distinguished name. |
| `-GroupCategory` | `Security` or `Distribution`. |
| `-GroupScope` | `DomainLocal`, `Global`, or `Universal`. |
| `-ExcludeBuiltin` | Skip `CN=Builtin` groups and well-known principals (RID < 1000). |
| `-IncludeNested` | Expand nested groups and record the nesting path. |
| `-MaxNestingDepth` | Recursion limit, default 10. Circular nesting is detected regardless. |
| `-UserMembersOnly` | Emit only user members. |
| `-SkipPrimaryGroupMembers` | Skip primary-group reconstruction. |
| `-IncludeEmptyGroups` | Emit a placeholder row so empty groups still appear. |
| `-UserReport` | Also write the user-centric HTML report and CSV. |
| `-IncludeDisabled` | Include disabled accounts in the user report. |
| `-OutputPath` | Output directory, defaults to current directory. |

## CSV columns

**Group:** `GroupName`, `GroupSamAccountName`, `GroupCategory`, `GroupScope`, `GroupDescription`, `GroupDN`

**Member:** `MemberName`, `MemberSamAccountName`, `MemberType`, `MemberDN`

**How the membership arises:** `MembershipType`, `NestingDepth`, `NestedVia`

**User detail:** `DisplayName`, `UserPrincipalName`, `EmailAddress`, `Department`, `Title`, `Enabled`, `LastLogonDate`, `PasswordLastSet`

**Run metadata:** `ExportDate`

### `MembershipType` values

| Value | Meaning |
|---|---|
| `Direct` | Listed in the group's `member` attribute. |
| `Nested` | Inherited through a nested group. `NestedVia` shows the path. Only with `-IncludeNested`. |
| `Primary` | Membership via the user's `primaryGroupID`. Invisible to `Get-ADGroupMember`. |
| `EmptyGroup` | Placeholder for a group with no members. Only with `-IncludeEmptyGroups`. |

## Common recipes

```powershell
# Who is in the privileged groups, including via nesting?
.\Export-ADGroupMembership.ps1 -GroupName 'Domain Admins','Enterprise Admins','Schema Admins' -IncludeNested

# One OU's groups, users only, for a department manager to review
.\Export-ADGroupMembership.ps1 -SearchBase 'OU=Groups,OU=HR,DC=contoso,DC=com' -UserMembersOnly -IncludeNested

# Full inventory including groups nobody is in (finds stale groups)
.\Export-ADGroupMembership.ps1 -IncludeEmptyGroups -ExcludeBuiltin

# Distribution lists only
.\Export-ADGroupMembership.ps1 -GroupCategory Distribution -IncludeNested

# Against a specific DC in another domain
.\Export-ADGroupMembership.ps1 -Server DC01.contoso.com -Credential (Get-Credential)
```

### Pivoting the result

The flat shape is designed for Excel. Insert a PivotTable, put `GroupName` in Rows and `MemberSamAccountName` in Values (Count) for group sizes; swap them to find which user is in the most groups. Filter `MembershipType = Nested` to review only inherited access.

## Requirements

- PowerShell 5.1
- `ActiveDirectory` RSAT module — imported at runtime, so the script starts even where the module isn't formally registered:
  ```powershell
  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
  ```
- Directory **read** access. Administrator rights are not required.

## Known limits

- **Cross-forest members.** `Get-ADGroupMember` *"does not work when a group has members located in a different forest, and the forest does not have Active Directory Web Service running."* Affected groups are logged as a `[WARN]` and skipped; the rest of the run continues.
- **Foreign security principals** appear by DN without resolved detail.
- **Large domains.** Every group in the domain with `-IncludeNested` is a lot of LDAP traffic. Narrow with `-SearchBase` or `-GroupName`, or use `-SkipPrimaryGroupMembers`.
- **On-prem only.** Entra ID / Microsoft 365 groups (Unified, cloud security, mail-enabled security, distribution lists) are **not** covered — that's a separate planned tool, since DLs and mail-enabled security groups need Exchange Online PowerShell and Graph cannot enumerate their membership reliably.

## References

Verified against Microsoft documentation:

- [Get-ADGroupMember](https://learn.microsoft.com/powershell/module/activedirectory/get-adgroupmember) — `-Recursive` leaf-only behavior, member object classes, cross-forest limitation
- [Get-ADGroup](https://learn.microsoft.com/powershell/module/activedirectory/get-adgroup) — `-Filter`/`-SearchBase` syntax, `GroupCategory` and `GroupScope` values
- [Primary-Group-ID attribute](https://learn.microsoft.com/windows/win32/adschema/a-primarygroupid) — RID semantics, default to Domain Users, non-linked attribute
