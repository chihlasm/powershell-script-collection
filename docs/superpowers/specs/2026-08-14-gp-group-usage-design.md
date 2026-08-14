# AD-GroupPolicy-GroupUsage — Design

**Date:** 2026-08-14
**Status:** Approved, pending sample-XML verification
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

**SecurityFilter** and **Delegation** — one `Get-GPPermission -All` call per GPO
serves both. `GpoApply` trustees are security filtering (who the GPO hits);
`GpoEdit` and `GpoEditDeleteModifySecurity` are delegation (who can change
policy). The trustee object exposes `.Sid` and `.SidType` directly, so principal
normalization is free.

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

## Principal normalization

Sources disagree on principal format:

| Source | Format |
|---|---|
| `Get-GPPermission` | Resolved name + SID + SidType |
| Security template | `*S-1-5-32-544` **or** a bare name |
| ILT filters | Name, plus a `sid` XML attribute |

Per MS-GPSB, the `*` prefix (ABNF `%d42`) marks a SID string; without it the
value is a literal principal name.

All principals pass through one normalizer returning `{Name, Sid, Resolved}`,
with a translation cache so each unique SID resolves once. Index grouping keys on
SID when available, falling back to name — otherwise `BUILTIN\Administrators` and
`Administrators` split into two entries for the same group.

Unresolvable SIDs are reported as their own finding: a GPO referencing a deleted
group is dead configuration, and sometimes evidence of a restore gone wrong.

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

Each parser is tested against inline XML fixtures. Regression tests lock in the
failure modes that would otherwise produce silent wrong answers:

1. `__Members` vs `__Memberof` direction is not inverted.
2. SID-and-name references to the same group collapse to one index entry.
3. `*`-prefixed SIDs are parsed as SIDs; bare names are not.
4. `SeDeny*` rights are classified higher severity than grant rights.
5. Unresolvable SIDs produce a finding rather than being dropped.

## Open risk

The `Get-GPOReport` XML element shape for `SecuritySettings` is not documented on
Microsoft Learn — only the underlying `GptTmpl.inf` format is (MS-GPSB, verified
above). The four security-settings collectors will be written against a real
sample supplied by the user:

```powershell
Get-GPOReport -Name "Default Domain Controllers Policy" -ReportType Xml |
    Out-File "$env:TEMP\gpo-sample.xml" -Encoding UTF8
```

Implementation of those four is blocked on that sample. The three low-risk
collectors, the normalizer, the index, and the report can proceed in parallel.

## References

- [MS-GPSB Group Membership](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/b73d8bae-ed22-48aa-acba-7065ab52d709) — `__Members` / `__Memberof` ABNF, `*SID` prefix
- [MS-GPSB Privilege Rights](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/3413b381-a445-4d17-b77e-5bbfadda253b) — the 44 `Se*` constants, SidList format
- [MS-GPSB Security Extension Overview](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/5828a2ed-cf34-486a-b04d-92a707ca48ac) — GptTmpl.inf location in SYSVOL
- [User Rights Assignment](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment) — constant-to-friendly-name mapping
- [Get-ADGroupMember](https://learn.microsoft.com/powershell/module/activedirectory/get-adgroupmember) — `-Recursive` returns leaves only
