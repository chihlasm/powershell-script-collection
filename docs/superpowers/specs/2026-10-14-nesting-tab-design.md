# AD access report: Nesting tab

Date: 2026-10-14 · Tool: `AD-GroupMembership-Export/Export-ADGroupMembership.ps1 -UserReport`
Status: design agreed in conversation; awaiting spec review.
Builds on: `2026-10-14-group-report-tabs-design.md` (People / Groups / Overlap tabs).

## Goal

A troubleshooting view of group nesting. List every group that is inside another group or contains one; selecting a group shows its full chain upward ("is inside") and downward ("contains"), however deep — 10+ levels — and makes loops obvious.

Example: Group B is a member of Group A, and A is a member of C. Selecting B shows `B ← A ← C` upward; selecting C shows `C → A → B` downward.

## Decisions

| Topic | Decision |
|---|---|
| Chain extent | **Full chain**, including groups outside the export (built-in, other OUs, filtered out), fetched from AD |
| Placement | Fourth tab, **Nesting**, list + detail layout (same as Groups) |
| Visualisation | **Indented trees** ("Is inside" and "Contains") plus an **every-path list** underneath |
| Loops | Drawn once where they close (`↻ Helpdesk — loops back`), never expanded further |
| Diamonds (same group via two branches) | Second appearance shows `↗ shown above`, not the subtree again |
| Limits | 50 child groups per tree level (`+ N more`), 100 paths per direction (`+ N more`) |
| Protected groups | Highlighted; identified by SID, not name (locale-independent) |
| Copy | "Copy paths" button, plain text, for tickets |
| Browser support | ES5 JavaScript (IE 10/11 on Server 2012 / 2012 R2), as the other tabs |

## Data collection (PowerShell)

### Downward edges — no extra queries
`Resolve-GroupMembership` already sees every group-in-group membership while walking. Record each direct edge `parentDN → childDN` in a script-level set, **including the edge that closes a loop** (today only a `[WARN]`; it must also be recorded so the report can show the loop). Without `-IncludeNested` only depth-0 edges of exported groups are known; the tab says so.

### Upward edges — option A
- Exported groups: add `MemberOf` to the properties `Get-TargetGroup` already requests — no extra query.
- Any parent DN not in the export: `Get-ADGroup -Identity <DN> -Properties MemberOf, GroupCategory, GroupScope, SID` (read-only), breadth-first upward until no new parents.
- A visited set prevents re-querying; a **cap of 1,000 extra lookups** bounds pathological domains. If hit, the report shows "Upward chains incomplete: lookup limit reached".
- A lookup that fails (deleted object, no read access, other forest) records the parent as *unresolved* and continues; one bad parent never aborts the run.
- `memberOf` is a back-link (Link-Id 3) held on the DC queried, so nesting into groups in **other domains** of a multi-domain forest may not appear. Stated in the tab.

### Node data
Per group: name, category, scope, readable OU path, `inExport` (true / fetched only to complete a chain), `protected` (true/false), `builtin` (in CN=Builtin or RID < 1000).

### Protected groups — by SID
From Microsoft's *Appendix C: Protected Accounts and Groups* (groups only; Administrator and Krbtgt are accounts), with SIDs from *Security Identifiers*:

| Group | SID |
|---|---|
| Administrators | S-1-5-32-544 |
| Account Operators | S-1-5-32-548 |
| Server Operators | S-1-5-32-549 |
| Print Operators | S-1-5-32-550 |
| Backup Operators | S-1-5-32-551 |
| Replicator | S-1-5-32-552 |
| Domain Admins | S-1-5-21-*domain*-512 |
| Domain Controllers | S-1-5-21-*domain*-516 |
| Schema Admins | S-1-5-21-*root*-518 |
| Enterprise Admins | S-1-5-21-*root*-519 |
| Read-only Domain Controllers | S-1-5-21-*domain*-521 |
| Key Admins | S-1-5-21-*domain*-526 |
| Enterprise Key Admins | S-1-5-21-*root*-527 |

Domain-relative entries match by RID on any `S-1-5-21-…` SID, so forest-root groups seen from a child domain are recognised too.

### Embedded data
A separate block alongside the existing group data:
```
nest: {
  nodes: [ { n, c, sc, ou, x: inExport, p: protected, b: builtin, u: unresolved } ],
  up:    [ [parentIds] ],      // index = node id; direct parents only
  down:  [ [childIds] ],       // direct children only
  flags: { nestedExpanded, capReached }
}
```
Only groups with at least one edge are included. Trees, depth, loops and paths are computed in the browser.

## Nesting tab (browser)

- **Tab label** shows the number of groups involved in nesting.
- **Summary strip**: groups involved · deepest chain (levels) · loops (amber when > 0) · groups nested into protected groups (amber when > 0). The last two are clickable filters.
- **List (left)**: every group with a parent or child, including dashed fetched-only groups. Row: name, deepest level, markers `loop` and `→ protected`. Filters: search, *Only loops*, *Only nested into protected groups*. Sort: deepest first (default) or name.
- **Detail (right)**:
  - Header: name, type, location, "in export" vs "fetched to complete the chain".
  - **Is inside** tree — parents to the top, level-numbered.
  - **Contains** tree — children to the bottom, level-numbered.
  - **All paths** — upward and downward complete routes, one per line, plus **Copy paths**.
  - Clicking any group name selects it.
- **Cross-links**: Groups-tab detail shows "Nesting: inside N, contains M — view chain"; a *Contains* pair on the Overlap tab links here.
- **Notices**: without `-IncludeNested` ("downward chains show one level"); lookup cap reached; multi-domain caveat.

## Algorithms (OverlapCore-style pure JS, Node-tested)

- `tree(nodeId, direction, limits)` — DFS carrying the current path: a node already on the path → **loop** marker, stop; a node already expanded elsewhere in this tree → **shown above** marker, stop; > 50 children → first 50 + "more" count.
- `paths(nodeId, direction, limit)` — DFS enumerating complete routes to a root/leaf, a loop ends a path with a loop marker, stop after 100 and report the remainder count.
- `depth` (longest acyclic chain through the node) and loop membership are computed once per report for the list and summary (cycle detection on the full edge graph).

## Testing

- **PowerShell (5.1 + 7)**: edge recording incl. the loop-closing edge; upward BFS follows parents outside the export, stops at roots, never revisits, honours the cap, survives a failing lookup; protected detection by SID (renamed group still detected).
- **End-to-end** (`Tests/EndToEnd.Tests.ps1`, FakeAD extended with `MemberOf`): a group nested into built-in Administrators, a 10-deep chain, the existing loop; assert the embedded `nest` data.
- **Node**: trees, paths, loop and shown-above markers, depth, limits, 10-deep chain.
- Existing guards: PS 3.0 floor, encoding, IE-safe JS syntax.
- **Browser**: sample report with deep chains, loops and protected nesting, clicked through.

## Out of scope

- Graph/diagram rendering (option B rejected: does not scale to wide or 10-deep structures).
- Querying a Global Catalog for cross-domain back-links.
- Changing group membership (the tool stays read-only).

## References

- memberOf (Is-Member-Of-DL, back-link, Link-Id 3): https://learn.microsoft.com/windows/win32/adschema/a-memberof
- Protected groups: https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
- Well-known SIDs: https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
