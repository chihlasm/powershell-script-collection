# FolderPermissionManager GUI v2 — Design Spec

**Date:** 2026-04-07  
**Scope:** Improve UX and add file-level permission support to `FolderPermissionManager/FolderPermissionManager-GUI.ps1`

---

## Summary

The tool is used equally for ACL auditing and permission remediation. This redesign adds file-level ACL inspection and batch file operations without touching the proven PowerShell backend logic. The frontend (embedded HTML/JS) is rewritten around a context-aware 2-panel layout.

---

## Layout & Navigation

**2-panel layout — context-aware right panel.**

- **Left panel:** folder tree (unchanged — drive list → expandable folder hierarchy, same API calls)
- **Right panel:** switches content based on selection:
  - **Folder selected** → two stacked sections:
    1. **Folder ACL section** (top) — owner, ACE table, add/remove ACE, take ownership, replicate permissions buttons — identical behavior to v1
    2. **Files section** (below) — compact rows: checkbox | filename | size | last modified. "Select all" checkbox in header. Each row has an expand toggle (▶) that opens an inline ACL view for that file.
  - **File(s) checked** → a sticky action bar slides up at the bottom of the right panel:
    - "X file(s) selected" count
    - Action buttons: **Add ACE** | **Remove ACE** | **Take Ownership** | **Copy to...**
    - If selected files have differing ACLs: yellow advisory banner — "ACLs differ across selected files — this operation applies uniformly"

---

## File ACL Operations

Operations available when one or more files are checked:

| Operation | Behavior |
| --- | --- |
| **View ACL** | Click a single file row (▶) to expand its ACL inline — identity, rights, type, inherited flag |
| **Add ACE** | Same dialog as folder add — identity text input, rights dropdown, allow/deny toggle. Applied to all checked files. |
| **Remove ACE** | Identity picker drawn from the combined list of unique identities across all checked files' ACLs. Applied to all checked files. |
| **Take Ownership** | Runs `takeown /F <file>` per file, then sets owner via .NET `SetOwner()` using the resolved current identity. Results shown per-file (success/error). |
| **Copy to...** | Opens modal with destination folder input (browseable via folder tree). Fires `POST /api/robocopy-files`. Shows robocopy output summary. |

**ACL diff advisory:** Before firing any batch operation, the frontend compares ACE lists across selected files. If they differ, the yellow banner is shown. The operation still proceeds — it is advisory only, not a blocker.

---

## Backend — New API Endpoints

All existing endpoints are unchanged. Three new endpoints are added:

### `GET /api/file-acl?path=<file>`

Returns ACL for a single file.

- Validates path with `Test-Path -PathType Leaf`
- Returns: `{ path, owner, areAccessRulesProtected, entries[] }`
- Errors: 400 (invalid path), 403 (access denied), 500 (ACL read failure)

### `POST /api/file-acl/add`

Adds an ACE to one or more files.

- Body: `{ paths: string[], identity: string, rights: string, type: "Allow"|"Deny" }`
- Each path in `paths[]` validated with `Test-Path -PathType Leaf` before operating — invalid paths skipped with per-entry error, not a full abort
- Same `FileSystemAccessRule` logic as `Invoke-AddAce` but iterates `paths[]`
- Returns: `{ status, results: [{ path, status, message }] }`

### `POST /api/file-acl/remove`

Removes an ACE from one or more files.

- Body: `{ paths: string[], identity: string, rights: string, type: "Allow"|"Deny" }`
- Each path in `paths[]` validated with `Test-Path -PathType Leaf` before operating — invalid paths skipped with per-entry error, not a full abort
- Same `RemoveAccessRuleAll` logic as `Invoke-RemoveAce` but iterates `paths[]`
- Returns: `{ status, results: [{ path, status, message }] }`

### `POST /api/file-acl/take-ownership`

Takes ownership of one or more files.

- Body: `{ paths: string[] }`
- Resolve the current identity once at the start of the function using `[System.Security.Principal.WindowsIdentity]::GetCurrent().Name` — do not use `$env:USERNAME` (unreliable under SYSTEM/service accounts) or `%USERNAME%` (CMD variable, not valid in PowerShell)
- Per file: `takeown /F <file>` (forces OS-level ownership grant), then `Get-Acl` / `SetOwner()` / `Set-Acl` using the resolved identity — same pattern as `Invoke-TakeOwnership` for folders
- Log the resolved identity in the per-file result message so it's visible in the UI
- All paths validated with `Test-Path -PathType Leaf` before operating
- Returns: `{ status, results: [{ path, status, message }] }`

### `POST /api/robocopy-files`

Copies specific files to a destination folder, preserving ACLs.

- Body: `{ sourceDir: string, destDir: string, files: string[], extraFlags?: string }`
- Reject with 400 if `files` is null, missing, or empty — an empty array must never fall through to a full directory copy
- All paths in `files` validated with `Test-Path -PathType Leaf` before invoking robocopy
- Command: `robocopy "<sourceDir>" "<destDir>" "file1" "file2" /COPY:DATSO /SECFIX /ZB /NP /R:3 /W:5`
- `/SECFIX` is required for files — without it, robocopy skips ACL copying on unchanged files
- Use `/COPY:DATSO` (drop the `U` auditing flag) — `U` requires `SeSecurityPrivilege` (Backup Operator or higher); silently skipping or partially failing in standard MSP environments is worse than not requesting it. Document this decision in a comment.
- Returns same summary shape as existing `Invoke-Robocopy`: `{ success, exitCode, message, command, output }`

**Note:** `/SECFIX` must always be paired with a `/COPY:` flag that includes `S` (security). `/COPY:DATSO` satisfies this. Omitting `/COPY:S` causes robocopy to error: `"ERROR: /SECFIX specified, without specifying WHICH security info to copy."`

**Note on robocopy version variance:** `/SECFIX` behavior is consistent across Windows 10 (build 1607+) and Windows 11. If targeting pre-1607 systems, `/SECFIX` is unavailable — not expected in this MSP environment but worth noting.

---

## Robocopy Tab Changes

The existing Robocopy tab gains a **mode toggle** at the top: `Folder copy` / `File copy`.

- **Folder copy mode** — unchanged (existing UI and `POST /api/robocopy` endpoint)
- **File copy mode** — source becomes: source folder path input + file list with checkboxes (populated via `GET /api/files`). Destination folder input unchanged. Fires `POST /api/robocopy-files`.

---

## Error Handling

Follows existing conventions — no new patterns introduced:

| Scenario | Behavior |
| --- | --- |
| Access denied on file ACL read | 403: `"Access denied to '<file>'. Try taking ownership first."` |
| File path not found | 400: path validated with `Test-Path -PathType Leaf` |
| Mixed ACLs across selected files | Frontend-only yellow advisory banner — not a blocker |
| Robocopy file copy failures | Reuses existing exit code table (0–16 already mapped in `Invoke-Robocopy`) |
| Take ownership on locked file | Error surfaced per-file in results list (same pattern as recursive ownership) |

---

## What Is NOT Changing

- Robocopy folder copy flow
- Replicate permissions feature
- CSV export (stays folder-scoped)
- Drive discovery / mapped drive logic
- PowerShell HTTP server loop and listener
- Script stays a single self-contained `.ps1` file

---

## Robocopy Flag Reference

| Scenario | Command shape |
| --- | --- |
| Folder copy (existing) | `robocopy "<src>" "<dst>" /E /COPY:DATSOU /DCOPY:DAT /ZB /NP /R:3 /W:5` |
| File copy (new) | `robocopy "<srcDir>" "<dstDir>" "f1" "f2" /COPY:DATSO /SECFIX /ZB /NP /R:3 /W:5` |

Both are supported on Windows 10 and Windows 11.
