# Risk profile: bulk and destructive operations

Applies to deletes, overwrites, bulk updates, file migrations, permission changes, and
directory writes: anything that is hard to undo. In this repo that means DeleteOldFolders,
Storage Space Clean-up, the FSLogix repair and cleanup tools, RobocopyMigration,
CopyFileToServer, FolderPermissionManager, LocalAdminManager, and M365-SyncedUserFixes
(the only tool that writes to Active Directory). These run with admin rights against
client servers and client AD; a bug repeats across every target.

- The user sees the scope before confirming: which servers, how many folders/files/users,
  total size ("this will delete 312 folders, 48 GB, on FS01"). GUIs show it in the
  confirmation dialog; console scripts print it with `[WARN]` before acting.
- Every destructive script or function supports `-WhatIf` (`SupportsShouldProcess`) and calls
  `$PSCmdlet.ShouldProcess` per target, so a dry run shows exactly what would happen.
  Confirmation prompts can be bypassed only with an explicit `-Force` (CLAUDE.md convention).
- Destructive actions are visually distinct in GUIs (destructive button styling, verb in the
  label: "Delete 312 folders", not "OK") and never the default button.
- Work is reversible where possible: ACLs are exported (`Get-Acl` / SDDL) before `Set-Acl`;
  AD attributes are recorded with their previous value before `Set-ADUser -Replace/-Clear`
  (see M365-SyncedUserFixes' change log); robocopy `/MIR` and `/PURGE` are never introduced
  without a preview and an explicit opt-in.
- Each change is written to a log file with timestamp (`yyyy-MM-dd HH:mm:ss`), target, old
  value and new value, enough to audit and undo it.
- Bulk work over many servers or objects is per-target try/catch with `continue`: one
  unreachable server or locked file is recorded and skipped, not fatal. Long migrations stay
  resumable (RobocopyMigration/CopyFileToServer `State/` folders).
- AD writes stay on one domain controller for the whole operation (`-Server` on every
  cmdlet), and verify the cmdlet parameter names against the real RSAT module or Microsoft
  Learn: mocks can share a wrong parameter name with the code.
- Tests cover partial failure, the "zero items" and "all items" edges, and that `-WhatIf`
  performs no change. Every write cmdlet (`Remove-Item`, `Set-Acl`, `Set-ADUser`,
  `Add-/Remove-ADGroupMember`, robocopy) is mocked in Pester; any test that could touch a
  real file share, real AD or the real file system outside `$TestDrive` is a blocker.
