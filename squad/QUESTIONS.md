# Open questions for the owner

Questions the squad could not settle on its own. Each one names the blocked item and
the options. `/squad:review` (or `/squad:plan`) walks you through them in one batch
and moves the answers into DECISIONS.md.

Format:
### Q-### · SQ-### · one-line question
- status: open
- context: why this came up, in plain words
- options: A) ... (recommended)  B) ...  C) ...
- consequence: what each option changes for users

---

### Q-001 · SQ-001 · Should the ticket note skip Windows clipboard history and cloud clipboard?
- status: answered (D-033)
- context: The note is copied to the clipboard by default. `Set-Clipboard` (the spec's first
  choice) puts plain text on the clipboard, so the note (client user names, DC names, findings)
  lands in Win+V clipboard history and, if "Sync across devices" is on, is uploaded to the tech's
  Microsoft account. The WinForms fallback now marks the copy with Windows' documented
  "do not keep in history / do not upload" formats, but it only runs when Set-Clipboard is missing
  or fails. SQ-001 is otherwise ready for review; READMEs document the behaviour and `-NoClipboard`.
- blocks: SQ-001 is marked blocked on this answer. Everything else in it passed review (branch squad/SQ-001-ticket-note, gates green). The personal-data reviewer says: pass if B is recorded as an owner decision; with A or C, a test that the WinForms path runs first closes it.
- options: A) Make the WinForms copy (with the exclusion formats) the first choice and keep
  Set-Clipboard as the fallback (recommended). B) Keep the current order and rely on the README
  and `-NoClipboard`. C) Turn the clipboard off by default and make it opt-in.
- consequence: A) Notes stop appearing in clipboard history/cloud sync in normal use; pasting works
  the same. Needs an STA host (Windows PowerShell console is STA by default). B) No change; client
  data can reach the tech's Microsoft account when cloud clipboard is on. C) Techs must add a
  switch or open the note file to paste.

### Q-002 · SQ-014 · Should whole-tree take ownership refuse drive roots and Windows folders?
- status: answered (D-036)
- context: Recursive take ownership (GUI and, since SQ-014, the CLI with `-Force` and no prompt)
  will run on any folder, including `C:\`, `C:\Windows`, `C:\Program Files` or a share root. On OS
  folders it replaces TrustedInstaller/SYSTEM ownership across the tree; undoing it means replaying
  a very large owner snapshot. This existed before SQ-014. It does not block SQ-014 (in review).
- options: A) Refuse volume roots and anything under %SystemRoot%, %ProgramFiles%, %ProgramData%
  unless an extra explicit switch (e.g. `-AllowSystemFolder`) is given; the GUI shows a plain
  refusal (recommended). B) Warn loudly but allow. C) Leave as is.
- related: `takeown /D Y` on folders the account can't list replaces their permissions with full
  control for the tech. SQ-014 fix round 2 backs up their SDDL where readable and warns. Option D)
  switch to `/D N`, which skips those folders (result Partly done) and leaves their permissions.
- consequence: A) A tech who picks the wrong folder can't break the OS; a real need takes one
  extra switch. B) Relies on the tech reading the warning. C) No change.

### Q-003 · SQ-014 · How should whole-tree take ownership handle folders it can't open?
- status: answered (D-034)
- blocks: SQ-014 (blocked after two fix rounds; branch `squad/SQ-014-fpm-tree-cli`, gates green).
- context: `takeown /R /D Y` replaces the permissions of any folder the tech can't open with
  "full control for you only" (documented on Learn). SQ-014 now backs those permissions up first
  where `Get-Acl` can read them and warns in the CLI before asking. Two gaps remain. (1) The GUI's
  confirm dialog only shows the path, so a GUI tech learns after the change which folders lost their
  permissions. In the most common real case (a home or redirected folder locked to the user and
  SYSTEM), `Get-Acl` can't read the permissions either, so they are lost with no backup and the
  user is locked out of their own folder. (2) Folders inside such a folder can't be seen beforehand
  and may also get replaced permissions; Learn doesn't say.
- options: A) Switch to `takeown /D N` (Q-002 option D): those folders are skipped, their
  permissions stay, the result is Partly done and names them, and the tech escalates
  (recommended; also removes gap 2). B) Keep `/D Y` and add a read-only preview to the GUI before
  the confirm (item count, folders that can't be opened, which can't be backed up, links), with a
  destructive-styled confirm when any permissions would be lost; still leaves gap 2.
  C) Keep `/D Y` and refuse the action when any folder's permissions can't be backed up.
- consequence: A) No permissions are ever replaced; locked folders need a separate, deliberate step.
  B) The tech sees the damage before clicking but can still cause it. C) Safe, but the action fails
  on exactly the folders it is usually run for.

### Q-004 · SQ-015 · Should the old CLI still copy the top folder's permissions onto every subfolder?
- status: answered (D-035)
- blocks: SQ-015 (blocked after two fix rounds; branch `squad/SQ-015-fpm-recursive-copy`, gates
  green; the GUI copy is fixed and passes review).
- context: SQ-015 made the GUI's "Copy Permissions To..." add-only with one Set-Acl per target
  (D-031). The old CLI `FolderPermissionManager.ps1` has its own step 3 that writes the top folder's
  own rules onto every subfolder at every depth as explicit rules. The squad stopped it duplicating
  rules a subfolder already inherits and made it skip folders that block inheritance, but it still
  stamps rules that were never meant to reach subfolders: "this folder only" rules (e.g. Domain
  Users: List/Create folders on a home-drive root) end up on every user's folder, and "no
  propagate" rules reach deeper than set. Because they are explicit, removing them from the root
  later doesn't remove them below. This behaviour predates SQ-015.
- options: A) Remove the CLI's copy-to-subfolders step; one add on the top folder already reaches
  every subfolder that inherits (recommended; matches D-031). B) Keep the step but copy only rules
  that would reach each subfolder by inheritance (ContainerInherit, NoPropagate only for direct
  children), skip unreadable folders too, and list any left-out rules before the confirm.
  C) Keep it as is with a louder warning.
- consequence: A) The CLI does ownership plus a view of permissions; to grant access you add it
  once on the top folder. B) Same reach as inheritance with more code to trust. C) Access can
  silently widen across a share.

### Q-005 · SQ-014 · Which reparse points count as "links" when taking ownership of a whole tree?
- status: answered (D-040)
- blocks: SQ-014 (blocked after two fix rounds; branch `squad/SQ-014-fpm-tree-cli` at 33d09c5, gates green).
- context: SQ-014 now refuses a whole-tree take ownership when a link inside the folder leads into a
  protected folder (D-036) or somewhere it can't work out. In fix round 2 the squad narrowed "link"
  to reparse points with the name-surrogate bit (junctions, symbolic links), so that Data
  Deduplication files and OneDrive/cloud placeholders, which are also reparse points, don't refuse
  every tree on a dedup file server. The final destructive-operations review found that this lets
  DFS links through (tag 0x8000000A has no surrogate bit): on `\\contoso.com\Shares`, a DFS link
  to `\\dc01\NETLOGON` or `\\app01\C$\Program Files\X` would be walked and re-owned. This comes from
  reading the SMB2 spec; nobody has tested it against a real DFS root. Every other check passes:
  admin shares, system shares, 8.3 names, `\\?\` paths, junctions on the folder and inside the
  tree, and 32-bit hosts.
- options: A) Allowlist: only known redirect-free tags (Dedup, WOF, the cloud/OneDrive family,
  HSM, SIS) count as plain files; every other reparse point, DFS included, counts as a link and is
  checked or refused (recommended). B) Go back to "every reparse point is a link": the safest, but
  whole-tree take ownership refuses any tree with a deduplicated file or a OneDrive placeholder.
  C) Option A, and also refuse any link whose target is outside the chosen folder, so the change
  can never leave the tree you picked. This also covers links nested inside link targets.
- consequence: A) DFS links are refused, and dedup and OneDrive trees still work; it needs a
  maintained list of tag values cited from Learn. B) Nothing is missed, but the tool can't be used
  on dedup volumes. C) Like A, and it also closes the two-hop case (a link to an allowed folder
  that contains a link to C:\Windows). It also refuses harmless links that point elsewhere on the
  same share.

### Q-006 · SQ-014 · Should app-execution links and Azure File Sync tiered files count as plain files?
- status: open
- blocks: nothing. SQ-014 continues and refuses these trees safely (fail closed) until you answer.
- context: Under D-040 only the allowlisted reparse types are plain files. The run's
  destructive-operations reviewer pointed out two common types that don't redirect anywhere but
  now refuse whole-tree take ownership:
  - `IO_REPARSE_TAG_APPEXECLINK` (0x8000001B): the app-execution aliases under
    `AppData\Local\Microsoft\WindowsApps` in every local profile, so taking ownership of a profile
    folder is refused.
  - `IO_REPARSE_TAG_STORAGE_SYNC` (0x8000001E): Azure File Sync files tiered to the cloud, so any
    folder on an Azure File Sync server with cloud tiering is refused.
  The refusal now names the reparse type and no longer suggests `-AllowSystemFolder` for these.
- options: A) Add both to the allowlist, with Learn citations and one test each (recommended).
  B) Add only STORAGE_SYNC; profile folders stay refused, which suits "don't take ownership of
  profiles". C) Leave both refused.
- consequence: A) Profile folders and Azure File Sync shares work; the aliases are taken over like
  any file, which is harmless. B) Azure File Sync works; profiles are refused with a clear message.
  C) Both are refused; techs fix those folders one level down or escalate.
