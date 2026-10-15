# AD access report: Groups and Overlap tabs

Date: 2026-10-14 · Tool: `AD-GroupMembership-Export/Export-ADGroupMembership.ps1 -UserReport`
Status: design agreed in conversation; implementation requested directly (spec review step skipped at the user's request).

## Goal

The HTML user report answers "what can this person access?". Add two tabs so the same report also answers:

- **Members by group** — who is in each group and how they got there.
- **Overlap** — which groups share people, for three equally important jobs: cleanup (near-duplicate groups), access review (who holds a risky combination), and understanding structure (how groups relate).

Group counts vary from <30 to hundreds per client, so layouts must adapt and everything must be filterable.

## Decisions

| Topic | Decision |
|---|---|
| Approach | Embed a compact data model in the HTML; the browser computes overlap. No extra AD queries. |
| Tabs | People (existing, unchanged behaviour) · Groups · Overlap |
| Groups layout | List (left) + detail (right) |
| Overlap layout | Sub-views: Overlapping pairs · Grid · Check a combination |
| Nesting | Toggle **Effective** (incl. nested) / **Direct** (members added to the group, incl. primary group). Default Effective. |
| What overlap counts | People (user accounts) only, same enabled/disabled rule as the People tab. Groups tab still lists computers and nested groups. |
| Percent | shared ÷ smaller group's size |
| Labels | Near-duplicate: shared ÷ larger ≥ 90%. Subset: smaller group 100% inside. Contains: one group is nested in the other (any depth) — greyed, sorted last. Partial: the rest. |
| Pair list defaults | Minimum overlap 50% (25/50/75/90), at least 2 shared people, first 200 shown + "show more" |
| Large groups | "Hide groups with 90%+ of users" — on by default, Overlap tab only |
| Grid | Shown when the filter leaves ≤ 40 groups; cell = shared count, shade = percent, diagonal = size; click lists people |
| Combination check | 2–5 groups via type-ahead; lists people holding all; follows the toggle |
| Shared filters | Search (group name/SAM *or* member name/username), type, scope, toggle — shared by Groups and Overlap |
| Cross-links | Near-duplicate badge on a group jumps to its pairs on the Overlap tab |
| Scale guard | Estimate pair work (Σ k(k−1)/2 over people); above the limit, ask the user to narrow instead of freezing |
| Browser support | ES5 JavaScript only (no arrow functions, `let`/`const`, `NodeList.forEach`, `Map`/`Set`), so the report works in IE 10/11 on Server 2012 / 2012 R2 |
| PowerShell | Stays 3.0-compatible (repo-wide floor test) |

## Data model (embedded JSON)

```
people: [ { n: display name, s: username, d: department, t: title, e: enabled } ]   // index = person id
groups: [ { n, s, c: category, sc: scope, ds: description, ou: readable OU path, ow: owner name,
            m: [ [personId, how(0 direct | 1 primary | 2 nested), via] ],   // strongest path per person
            o: [ [name, type, how, via] ],                                  // non-user members
            k: [ groupId ] } ]                                              // groups this one contains (any depth, within the export)
```

Direct set = `m` with how 0/1; Effective = all of `m`. Strings are escaped for safe embedding inside `<script type="application/json">` (`<`, `>`, `&`, U+2028/2029 as `\uXXXX`).

## Components

- `ConvertTo-GroupAccessModel` (PowerShell, pure): rows + group objects → model above.
- `ConvertTo-ReportJson` (PowerShell, pure): model → safe JSON text. Hand-written encoder (not `ConvertTo-Json`) for predictable escaping on PS 3.0–7.
- `OverlapCore` (JavaScript, pure, no DOM): member sets, pair counting, labels, work estimate, grid matrix, combination intersection. Exported for Node when `module` exists, so it is unit-tested.
- UI script (JavaScript, DOM): tabs, filters, rendering, cross-links.
- `New-UserAccessHtml` gains `-GroupModel` and the tab shell.

## Testing

- Pester (5.1 and 7): model (direct vs effective, primary = direct, disabled rule, nesting at depth, computers listed not counted, empty groups), encoder (hostile strings round-trip), HTML contains parseable data block and all three tabs.
- Node (skipped if Node is absent): `OverlapCore` labels, thresholds, 2-shared rule, work estimate, grid, combination.
- Manual: generate a synthetic report (duplicates, subsets, nesting, empty group, hostile name, 40+ groups) and click through it in a browser.
