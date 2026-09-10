# AD-GroupPolicy-GroupUsage — Design

**Date:** 2026-08-14
**Status:** Approved. XML shape verified against a real sample (see Verified XML Shape).
**Tool folder:** `AD-GroupPolicy-GroupUsage/`

## Problem

Group information in Group Policy is scattered across unrelated places, and no
existing tool in this collection collects it. `Audit-ADGroupPolicy.ps1` reads
`Get-GPPermission` but only surfaces trustees when something looks wrong — it
never simply lists who a GPO applies to. `Audit-GPDriveMaps.ps1` parses
item-level targeting, but only for drive mappings. Nothing in the repo reads the
`SecuritySettings` extension at all, so GPOs that *push* group membership
(Restricted Groups) or grant group-scoped logon rights (User Rights Assignment)
are invisible.

The question this tool answers: **which Active Directory groups are involved in
Group Policy, where, and in what capacity?**

## Goal

One report, organized by group, that says for each group: which GPOs reference
it, through which mechanism, and what that reference does. Secondary GPO-centric
cross-reference for reviewing one policy at a time.

## Non-goals

- Not a replacement for `AD-GroupMembership-Export` — that tool answers "who is
  in this group"; this one answers "where is this group used in GP".
- No RSoP / effective-policy simulation. `Audit-GPDriveMaps.ps1` already does
  precedence simulation for drive maps; generalizing that is a separate project.
- On-premises AD only. No Entra ID / Intune policy.

## Architecture

Seven independent collectors feed **one flat row list**. Every collector emits
the same shape:

| Field | Meaning |
|---|---|
| `GroupName` | Resolved principal name |
| `GroupSid` | SID string, when available |
| `SourceType` | Which mechanism (see below) |
| `GPOName` / `GPOId` | Owning GPO |
| `Scope` | Computer / User / N-A |
| `Detail` | Human-readable specifics of the reference |
| `Severity` | Info / Warning / High |

`SourceType` values: `SecurityFilter`, `Delegation`, `ItemLevelTargeting`,
`RestrictedGroups`, `LocalUsersAndGroups`, `UserRightsAssignment`, `WmiFilter`.

Flow:

```
Get-GPO -All
  → cache Get-GPOReport XML once per GPO   (existing pattern, both current tools use it)
  → 7 collectors append to one flat list
  → normalize principals (SID ↔ name)
  → resolve AD membership per unique group (cached)
  → pivot → group-centric index + GPO-centric cross-reference
  → HTML + CSV
```

Flat-then-pivot rather than building nested structures directly: collectors stay
independent and individually testable, an eighth source is purely additive, and
both report views are groupings of one list rather than parallel code paths that
can drift.

## Collectors

### Low risk — reuse proven machinery

**SecurityFilter** — `Get-GPPermission -All` per GPO, filtered to `GpoApply`
trustees. This is who the GPO actually hits.

**Delegation** — read from the cached XML at
`SecurityDescriptor/Permissions/TrusteePermissions`, using the friendly
`<GPOGroupedAccessEnum>` value. No extra cmdlet call (see Verified XML Shape).

Delegation matters because it is the only source answering "who can *change*
Group Policy" — the highest-privilege group relationship in the system, and a
known privilege-escalation path.

**ItemLevelTargeting** — lifts `Get-ItemLevelTargeting` from
`Audit-GPDriveMaps.ps1`, but sweeps every preference extension rather than only
`DriveMapSettings`: printers, shortcuts, scheduled tasks, files, folders,
registry, services, and Local Users and Groups.

One structural change from the original: that parser recovers group names by
regexing its own display string (`$_.Detail -match "'(.+)'"`), discarding the
`sid` attribute the XML carries. This version returns the SID as a first-class
field so ILT groups can be matched to other sources by SID rather than by string.

### Needs sample-XML verification before implementation

**RestrictedGroups** — `__Members` and `__Memberof` are opposite directions and
MUST stay distinct:

- `GroupName__Members = <list>` — the listed principals become the members of
  `GroupName`.
- `GroupName__Memberof = <list>` — `GroupName` becomes a member of each listed
  group.

Reversing these reports "Domain Admins contains Helpdesk" when the policy
actually says "Helpdesk is a member of Domain Admins" — a confident, plausible,
inverted answer. Regression test required.

Verified: [MS-GPSB Group Membership](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/b73d8bae-ed22-48aa-acba-7065ab52d709)

**LocalUsersAndGroups** — the GP Preferences successor to Restricted Groups.
Carries its own action semantics (Create/Replace/Update/Delete) and its own ILT
filters, so these rows can also carry targeting.

**UserRightsAssignment** — 44 `Se*` constants mapped to friendly names. The five
`SeDeny*` rights are marked higher severity, since a group appearing in one is
usually the finding.

Verified: [MS-GPSB Privilege Rights](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/3413b381-a445-4d17-b77e-5bbfadda253b)
and [User Rights Assignment](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment)

**WmiFilter** — name and query text per GPO. Does not reference groups directly,
but gates whether a GPO applies at all, so it is attached as context on the
GPO-centric view rather than emitted as group rows.

## Verified XML shape

Verified against a real `Get-GPOReport -ReportType Xml` sample (Default Domain
Controllers Policy, `contoso.local`, 36 `UserRightsAssignment` elements /
119 `Member` elements). The findings below **supersede** assumptions made before
the sample was available.

### Principals arrive pre-resolved

`Get-GPOReport` emits each principal as a `<SID>` + `<Name>` pair:

```xml
<q1:UserRightsAssignment>
  <q1:Name>SeAssignPrimaryTokenPrivilege</q1:Name>
  <q1:Member>
    <SID xmlns="...Types">S-1-5-20</SID>
    <Name xmlns="...Types">NT AUTHORITY\NETWORK SERVICE</Name>
  </q1:Member>
</q1:UserRightsAssignment>
```

The `*S-1-5-...` prefix and bare-name forms specified in MS-GPSB are the on-disk
`GptTmpl.inf` format; `Get-GPOReport` has already normalized them and they never
appear at this layer. **The planned principal normalizer is therefore dropped** —
index on the `<SID>` directly, carry `<Name>` for display.

### Orphan SIDs present as a missing `<Name>` child

8 of 119 members in the sample have a `<SID>` but **no `<Name>` element** (all
`S-1-5-82-*`, the IIS AppPool virtual-account authority):

```xml
<q1:Member><SID xmlns="...Types">S-1-5-82-1036420768-...</SID></q1:Member>
```

Detection MUST test for the absence of the `<Name>` **child node**. Reading
`$member.Name` in PowerShell returns the *element's own tag name* ("Member"),
which is always truthy — a naive check silently drops every orphan. This exact
mistake was made and caught during sample analysis; it is a required regression
test.

### Namespaces are mandatory

Three namespaces are in play, and children sit in a *different* namespace than
their parents:

| Namespace | Used by |
|---|---|
| `.../GroupPolicy/Settings` | root `<GPO>` |
| `.../GroupPolicy/Settings/Security` | `q1:UserRightsAssignment`, `q1:Member`, `q1:Name` |
| `.../GroupPolicy/Types` | the `<SID>` / `<Name>` children inside `q1:Member` |

All `SelectNodes` / `SelectSingleNode` calls require a populated
`XmlNamespaceManager`. Dot-notation traversal works for simple paths but not for
the cross-namespace child lookups.

### Encoding trap

The file declares `encoding="utf-16"` but is written **without a BOM**. Strict
parsers reject it (Python's `utf-16` codec raises `UnicodeError`). PowerShell's
`Get-Content -Raw` piped into `[xml]` handles it correctly. Do not "fix" the read
path to an explicit encoding.

### Delegation is available in-XML

`SecurityDescriptor/Permissions/TrusteePermissions` carries each trustee with a
friendly `<GPOGroupedAccessEnum>` value ("Edit, delete, modify security",
"Read"). Delegation is therefore read from the **already-cached XML** rather than
a separate `Get-GPPermission` call — one fewer round-trip per GPO.

Security filtering still requires `Get-GPPermission`, because `GpoApply` is a
distinct ACE and must not be inferred from the delegation entries.

### Still unverified

The sample contains **no Restricted Groups** (its single `<Group>` element is a
delegation trustee, not a Group Membership entry) and no Local Users and Groups
preference. Those two collectors remain written against the MS-GPSB spec and are
sequenced last; they need a second sample from a GPO that configures them.

## Membership resolution

Runs once per unique group across the whole index — a group referenced by 20 GPOs
costs one lookup, not 20. Adds member count, nesting depth, and flags for
empty or nonexistent groups.

On by default. `-SkipMembership` disables it for large domains where the extra
LDAP traffic is unwelcome.

## Output

| File | Contents |
|---|---|
| `GPGroupUsage-<timestamp>.html` | Full report, both views |
| `*-GroupIndex.csv` | Primary group-centric pivot |
| `*-BySource.csv` | Flat rows, one per reference |
| `*-GPOCrossRef.csv` | GPO-centric cross-reference |
| `*-Findings.csv` | Orphan SIDs, deny-rights, delegation anomalies |

## Testing

Pester, following the existing pattern: a `-LoadFunctionsOnly` switch guards the
main run so tests dot-source without needing a domain.

Each parser is tested against inline XML fixtures derived from the verified
sample. Regression tests lock in the failure modes that would otherwise produce
silent wrong answers:

1. A `<Member>` with no `<Name>` child is reported as an orphan SID, not dropped
   — the naive `$member.Name` truthiness check must not return.
2. Cross-namespace `<SID>` / `<Name>` children resolve correctly via
   `XmlNamespaceManager`.
3. `__Members` vs `__Memberof` direction is not inverted.
4. `SeDeny*` rights are classified higher severity than grant rights.
5. A BOM-less utf-16 report parses without error.

## Open risk

The sample verified User Rights Assignment and delegation. **Restricted Groups
and Local Users and Groups remain unverified** — the sample GPO configures
neither. Those two collectors are sequenced last, written against the MS-GPSB
spec, and need a second sample from a GPO that configures them:

```powershell
Get-GPOReport -Name "<a GPO with Restricted Groups>" -ReportType Xml |
    Out-File "$env:TEMP\gpo-restricted-sample.xml" -Encoding UTF8
```

Everything else can proceed now.

## References

- [MS-GPSB Group Membership](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/b73d8bae-ed22-48aa-acba-7065ab52d709) — `__Members` / `__Memberof` ABNF, `*SID` prefix
- [MS-GPSB Privilege Rights](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/3413b381-a445-4d17-b77e-5bbfadda253b) — the 44 `Se*` constants, SidList format
- [MS-GPSB Security Extension Overview](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/5828a2ed-cf34-486a-b04d-92a707ca48ac) — GptTmpl.inf location in SYSVOL
- [User Rights Assignment](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment) — constant-to-friendly-name mapping
- [Get-ADGroupMember](https://learn.microsoft.com/powershell/module/activedirectory/get-adgroupmember) — `-Recursive` returns leaves only
