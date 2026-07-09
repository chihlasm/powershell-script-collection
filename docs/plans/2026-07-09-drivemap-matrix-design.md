# Drive Map Matrix - Interactive Group/User x Drive Letter View

**Date:** 2026-07-09
**Script:** `AD-GroupPolicy-DriveMaps/Audit-GPDriveMaps.ps1`
**Status:** Design approved, pending implementation plan

## Problem

The current audit report presents drive-map conflicts as per-letter cards. That
answers "is drive Z: a conflict?" but not the question operators actually ask:
"who gets what drive mapping?" A matrix view - rows of principals against columns
of drive letters - is a far better fit for scanning that relationship and spotting
where the same letter resolves differently for different groups/users.

## Goals

- A visual matrix of **who gets which drive mapping**, readable at a glance.
- Surface problems (unreachable targets, overlaps/conflicts) directly in the grid.
- Support drilling from group level down to individual AD users.
- Stay a **single self-contained HTML file** - no external libraries, no build step,
  no CDN (scripts deploy directly to servers and open straight in a browser).

## Chosen Approach

**Interactive matrix (Approach B):** an embedded-JSON + vanilla-JS grid rendered as a
new section in the existing HTML report. Chosen over a static pivot table because the
user wants eventual user-level drill-down, where filtering/search/expansion earn their
keep at scale. Interactivity is inline vanilla JS + CSS only, to honor the
self-contained constraint.

### Row axis

- **Rows = security groups** by default (from GPP item-level targeting; always available,
  no AD query required). A synthetic `(all users)` row represents mappings with no ILT.
- **Rows = users** in an alternate view, populated only when AD membership has been
  resolved (`-CheckGroupOverlap`). Group rows also expand in place (indented sub-rows)
  to show their member users when user data exists.

### Columns

- Columns = drive letters, sorted.

### Cell content

- Cell shows the short share name; full UNC path on hover (`title`).
- Color-coded by status, computed server-side (PowerShell) from data already collected:
  - `ok` (green) - path reachable
  - `unreachable` (red) - path failed validation
  - `overlap` (amber) - letter shared with another group, OR this group has 2+ paths
    for this letter
  - `remove` (grey) - Delete action
  - empty - group gets no mapping for that letter
- **Multi-path cell:** when a group targets one letter with multiple paths, the cell
  stacks all paths vertically, each with a small GPO badge, whole cell amber. This is a
  genuine per-group ambiguity (winner decided by GPP processing order) and must stand out.

## Data Model

New function `Build-DriveMapMatrix -DriveMaps <maps> -PathValidation <pv> -GroupOverlap <ov>`
runs after existing analysis and consumes already-computed data (no new GPO parsing).
It emits a structure serialized to JSON and embedded in the HTML:

```json
{
  "letters": ["F","H","M","O","Z"],
  "groups": [
    {
      "name": "Fire",
      "cells": {
        "M": [ { "path": "\\\\srv\\fire", "gpo": "GPO-Restrict",
                 "action": "Create", "status": "ok" } ],
        "Z": [ { "path": "\\\\a\\z", "gpo": "G1", "action": "Create", "status": "overlap" },
               { "path": "\\\\b\\z", "gpo": "G2", "action": "Create", "status": "overlap" } ]
      },
      "users": ["jsmith","adoe"]
    }
  ],
  "hasUserData": true
}
```

- `groups` is a pivot of `$AllDriveMaps` by ILT group name x `DriveLetter`.
- `users` per group is omitted unless AD membership was resolved.
- The `Get-ADGroupMember` lookup is refactored so the overlap check and the matrix
  **share one cached membership resolution** rather than querying AD twice.

## Rendering & Interactivity

New HTML section `id="matrix"`, added to the TOC, with an embedded `<script>` carrying
the JSON blob and vanilla JS.

- **Sticky** first column (name) and header row (letters) via `position: sticky`.
- **Toolbar controls:**
  - Live search box (filter rows by group/user name).
  - Letter filter (show only selected columns).
  - "Problems only" toggle (rows with any unreachable/overlap cell).
  - View toggle Groups <-> Users; disabled with a note when `hasUserData` is false
    ("Run with -CheckGroupOverlap to resolve user-level mappings").
  - Per-group expander to reveal member users inline.
  - Column-header click sorts rows by that letter's status (problems first); name-column
    click sorts alphabetically.
- **Scale:** JS renders only visible rows. User view caps initial render at 500 rows with
  a "N more - refine with search" notice (no virtualization library, to stay
  self-contained). Search/filter is the intended way to navigate large user sets.

## CSV Companion

- `*-Matrix.csv`: rows = groups, columns = drive letters, cell = path(s) or blank, for
  Excel pivoting. Mirrors the group-level view.

## Out of Scope (YAGNI / future)

- User-level CSV variant - deferred until the user view proves out.
- Full row virtualization - the cap + search is sufficient for realistic domains.
- External datagrid libraries / JS frameworks - excluded by the self-contained constraint.

## Constraints & Conventions

- ASCII-only source (Windows PowerShell 5.1 reads BOM-less .ps1 as ANSI).
- Reuse existing report CSS classes/badges where possible.
- No new mandatory parameters; the matrix always renders at group level, and richens
  when `-CheckGroupOverlap` data is present.
