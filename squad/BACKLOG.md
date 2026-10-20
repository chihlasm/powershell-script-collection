# Squad backlog

Items are built top to bottom within each priority, so order matters. Add new work
at the bottom with `status: new`, or just tell Claude "add this to the squad backlog".
`/squad:plan` turns `new` items into build-ready specs and asks you everything up front.

Statuses: new, needs-answers, ready, in-progress, review, blocked, done, dropped.

<!--
Template (copy below the line, give it the next number):

## SQ-EXAMPLE · Short title in plain words
- status: new
- priority: P2
- type: feature
- branch:
- spec:

Describe what you want in your own words: what a user should be able to do,
why it matters, and anything you already know (screens, edge cases, examples).
-->

---

## SQ-001 · Ticket note from every quick check (kit, joiner, AD-UserQuickCheck)
- status: done
- priority: P1
- type: feature
- branch: squad/SQ-001-clipboard-history
- spec: squad/specs/SQ-001.md (Part A, AC1-AC26)
- idea: squad/ideas/sessions/2026-10-16/cards/I-03-ticket-note.md

Every verdict tool ends by writing the same four-part note (Checked / Ruled out / Could not
check / Next step) to a text file and the clipboard, ready to paste into ConnectWise. It carries
a stamp (tenant or domain, who ran it, machine, time, changed anything). `-TicketNumber` puts all
of a ticket's notes in one folder, and a small joiner concatenates them. A check lands under
"Ruled out" only when its gate confirms it could look. This part delivers `CaseKit.ps1`, the
joiner, the parity test, and AD-UserQuickCheck adopting the note (plus `-PassThru`/`-Quiet`).
Approved by Michael in the 2026-10-17 pitch session; split per D-004.

## SQ-002 · M365 user check: can this user sign in? (Graph stage)
- status: done
- priority: P1
- type: feature
- branch: squad/SQ-002-m365-user-check
- spec: squad/specs/SQ-002.md (AC1-AC17, AC26-AC29)
- idea: squad/ideas/sessions/2026-10-16/cards/I-01-m365-user-signin-check.md

The cloud version of AD-UserQuickCheck: one UPN in, a verdict out, with the reason and a next
step. Covers blocked, unlicensed, no MFA method, CA failure, smart lockout and decoded sign-in
failures. A banner prints first with tenant, signed-in account and what the tool can see. On a
tenant without Entra ID P1 the headline is PROBABLY YES with "sign-in history not available"
(D-006). Read-only whatever account is used. Builds after SQ-001. Split per D-004.

## SQ-011 · M365 user check: is it a sync problem? (on-prem AD comparison)
- status: done
- priority: P1
- type: feature
- branch: squad/SQ-011-m365-sync-check
- spec: squad/specs/SQ-002.md (AC18-AC25)
- idea: squad/ideas/sessions/2026-10-16/cards/I-01-m365-user-signin-check.md

Second stage of the M365 user check: never synced, provisioning errors, an address held by
another object, an enabled mismatch (with the M365-SyncedUserFixes block marker), stale tenant
sync, and a UPN mismatch. Says "could not check" when no DC answers (D-014). Builds after SQ-002.
Split from SQ-002 per D-004.


## SQ-019 · M365 user check: blocked synced user advice must escalate, not "change it" (D-017)
- status: review
- priority: P1
- type: fix
- branch: squad/SQ-019-m365-blocked-escalate
- spec: squad/specs/SQ-019.md

Found in the SQ-011 destructive-operations review (2026-10-18), pre-existing from SQ-002.
`M365UserCheck.Core.ps1` SignInBlocked next step for a synced user when no AD comparison ran
(no RSAT, -SkipOnPremises, AD failed) tells tier 1 "...block marker... Change it in on-premises AD
if it is wrong". With AD data the same case already says "Check with the senior engineer".
Reword it the D-017 way. Widen D017_NoRemovalStepForTier1 to catch reversal verbs too (clear,
change it, undo, enable, anything that mentions the block marker) across the with-AD and no-AD
branches, and add a regression test for the no-AD synced-blocked path. Same pass:
AdDisabledCloudEnabled "enable the AD account" gets the manager/ticket check used for
cloud-only users. Builds on SQ-011 (same files).

## SQ-003 · "Why did this user get a temporary profile?" one-user VDI verdict
- status: done
- priority: P1
- type: feature
- branch: squad/SQ-003-temp-profile-verdict
- spec: squad/specs/SQ-003.md
- idea: squad/ideas/sessions/2026-10-16/cards/I-08-vdi-temp-profile-verdict.md

Enter a username and a session host (or a Delivery Controller to find the host through Citrix).
The tool runs the existing FSLogix checks on that host and asks the profile file server which
machine holds the user's disk open (`Get-SmbOpenFile`). It returns one ranked cause and the next
step, with the evidence for each candidate cause. A second entry script in Citrix-FSLogix-Triage
(D-015). Destructive fixes say "Escalate" plus the reason (D-017). Builds after SQ-001.

## SQ-008 · FolderPermissionManager: back up permissions and log every change (single items)
- status: done
- priority: P1
- type: fix
- branch: squad/SQ-008-fpm-backup-log
- spec: squad/specs/SQ-008.md (ACs 1-13 and 21)
- idea: squad/ideas/sessions/2026-10-16/brief.md (I-12, "Worth a look")

FolderPermissionManager calls `Set-Acl` without saving the previous permissions and keeps no
change log, which breaks `squad/risks/destructive-operations.md`. This part adds the core file,
the shared change-log format (D-030), and SDDL backup plus logging for every single-item change
in the GUI. A change whose backup can't be written is refused. Split per D-004.

## SQ-014 · FolderPermissionManager: whole-tree actions and the CLI script
- status: done
- revision: D-040 allowlist for reparse tags (spec SQ-008.md Revision notes 2026-10-18, AC20a-d)
- priority: P1
- type: fix
- branch: squad/SQ-014-fpm-tree-cli
- spec: squad/specs/SQ-008.md (ACs 16-20, minus the copy case of AC17; see Revision notes)
- idea: squad/ideas/sessions/2026-10-16/brief.md (I-12, "Worth a look")

Recursive take-ownership gets an owner snapshot first, and sets the owner by full account name
rather than a bare `$env:USERNAME`. Unreadable items are recorded as "Could not read" (D-027).
The copy-permissions tree backup is no longer needed (D-031). The old CLI
`FolderPermissionManager.ps1` gets backups and logging, `-WhatIf`, confirmation before taking
ownership, `-Force` and a help block (D-010). Builds after SQ-008. Split per D-004.

## SQ-015 · FolderPermissionManager: fix recursive copy permissions
- status: done
- priority: P1
- type: fix
- branch: squad/SQ-015-fpm-recursive-copy (stacked on SQ-014; SQ-014's tip 33d09c5 merged in at 43ca5a3, owner 2026-10-19, D-041)
- spec: squad/specs/SQ-015.md

Bugs found while planning SQ-008: the recursive copy maps rights with `switch -Wildcard` and no
`break` (ReadAndExecute also matches Read, producing a malformed `icacls /grant`), and runs
`icacls /reset /T`, which wipes explicit permissions down the tree. Also: the non-recursive copy
turns inherited rules into explicit ones, and handlers use `-Path`, which breaks on names with
`[ ]`. Copy becomes add-only with the checkbox dropped: one `Set-Acl` on the target, locked
subfolders untouched (D-031). Fix with a regression test for each. Builds after SQ-014 (D-011).

## SQ-017 · FolderPermissionManager as a WPF app: the window, browsing and viewing (read-only)
- status: done
- priority: P1
- type: feature
- branch: squad/SQ-017-fpm-wpf-window (stacked: create it from squad/SQ-015-fpm-recursive-copy as SQ-015 finishes this run, not from main; D-041)
- spec: squad/specs/SQ-017.md (AC1-AC25)

Rewrite FolderPermissionManager-GUI.ps1 as a WPF window in the style of RobocopyMigration-GUI.ps1,
replacing the HttpListener web server (owner, 2026-10-18: performance and a cleaner tool; the
server handles one request at a time and listens on localhost with no origin check or token).
This first half changes nothing: startup (STA/UAC relaunch, single instance, -LogFolder, -WhatIf,
mapped drives), runspace-pool background reads with busy state and stale-result guard, drives,
tree, folder and file permissions, path header, log-folder banner, export CSV. Core reused
unchanged. The browser version is renamed FolderPermissionManager-WebGUI.ps1 (D-038) and stays
until the owner's lab test. Robocopy tab and Copy Files To are dropped (D-037). Builds after
SQ-014 and SQ-015 (same core and GUI file). Split per D-039.

## SQ-018 · FolderPermissionManager WPF app: every change, confirmations and results
- status: review
- revision: owner lab test 2026-10-19, AC55-AC57 (spec SQ-017.md "Revision notes, SQ-018 (owner lab test ...)"); earlier D-043/D-044/D-045 AC47-AC54
- priority: P1
- type: feature
- branch: squad/SQ-018-fpm-wpf-changes (stacked: create it from squad/SQ-017-fpm-wpf-window as SQ-017 finishes this run; D-041)
- spec: squad/specs/SQ-017.md (AC26-AC46)

Second half of the WPF rewrite: add/remove permission (folders and files), take ownership
(folder, files, whole tree with an item count before the confirm and the D-036 refusal), copy
permissions, a themed confirm dialog (verb on the button, Cancel default), one change at a time,
closing blocked while a change runs, result-status parity with the browser GUI, -WhatIf end to
end, README and root README. Destructive-operations checklist applies in full. Builds after
SQ-017. Split from SQ-017 per D-039. Follow-up after the owner's lab test (not planned): remove
FolderPermissionManager-WebGUI.ps1 and its two test files, then add FolderPermissionManager
(GUI, CLI, core, README; no Tests/Logs) to the ServiceDesk-Toolkit bundle manifest and its
README as "Changes anything? Yes" (owner, 2026-10-19: distribute only once the WPF app can
make changes, via the toolkit bundle).

## SQ-020 · Whole-tree take ownership: WindowsApps aliases and Azure File Sync files count as plain files (D-042)
- status: done
- priority: P1
- type: fix
- branch: squad/SQ-020-allowlist-appexec-storagesync
- spec: squad/specs/SQ-020.md

Add IO_REPARSE_TAG_APPEXECLINK and IO_REPARSE_TAG_STORAGE_SYNC to the D-040 allowlist so profile folders and Azure File Sync shares can be taken over as a whole tree. Branch from main after SQ-014 merges.

## SQ-010 · Ticket note in Network-QuickCheck and Citrix-FSLogix-Triage
- status: done
- priority: P2
- type: feature
- branch: squad/SQ-010-ticket-note-network-triage
- spec: squad/specs/SQ-001.md (Part B, AC27-AC33)
- idea: squad/ideas/sessions/2026-10-16/cards/I-03-ticket-note.md

Both tools adopt the SQ-001 ticket note through the same interface, and their "could not run"
results are marked so they land under "Could not check", not "Ruled out". Builds after SQ-001.
Split from SQ-001 per D-004.

## SQ-004 · "Can this user open this folder?" access evidence and hedged verdict
- status: done
- priority: P2
- type: feature
- branch: squad/SQ-004-folder-access-check
- spec: squad/specs/SQ-004.md (ACs 1-27)
- idea: squad/ideas/sessions/2026-10-16/cards/I-07-folder-access-evidence.md

Enter a user and a UNC path. The tool shows the chain that decides access (share entries, NTFS
entries, which of the user's groups match, any Deny) and gives PROBABLY YES / PROBABLY NO /
CAN'T TELL, always ending with "confirm in Effective Access". `-Access Read` by default, Modify
optional (D-018); DFS namespace paths are detected (D-019). Read-only, with a regression test for
the past primary-group bug. Split per D-004.

## SQ-013 · Folder access: what to do about it
- status: done
- priority: P2
- type: feature
- branch: squad/SQ-013-folder-access-next-step
- spec: squad/specs/SQ-004.md (ACs 28-36)
- idea: squad/ideas/sessions/2026-10-16/cards/I-07-folder-access-evidence.md

The narrowest existing group that grants access (never Everyone, Authenticated Users or a direct
user entry), a warning when that group is privileged elsewhere, the stale-token check, the SQ-001
ticket note, and a next step pointing to FolderPermissionManager. Builds after SQ-004 and SQ-001.
Split from SQ-004 per D-004.

## SQ-006 · Lockout tools recognize Kerberos encryption-type blocks (RC4 enforcement)
- status: done
- priority: P2
- type: feature
- branch: squad/SQ-006-kerberos-etype-block
- spec: squad/specs/SQ-006.md
- idea: squad/ideas/sessions/2026-10-16/cards/I-06-kerberos-enforcement-check.md

Since the 2026 RC4 changes (KB5073381), some authentication failures look like lockouts but are
an encryption-type block. AD-LockoutDiagnostics recognizes this as its own cause ("not a
password problem, encryption type blocked") with the next step, in the report and SUMMARY.txt
(D-022, D-023, D-024). Per-DC gate says "can't tell" where a DC can't log the events. Read-only.

## SQ-007 · Mailbox check: the facts, with "do NOT reset yet" on takeover signs
- status: review
- revision: merge to main failed one test at review 2026-10-18 (see spec Revision notes)
- priority: P2
- type: feature
- branch: squad/SQ-007-mailbox-check
- spec: squad/specs/SQ-007.md
- idea: squad/ideas/sessions/2026-10-16/cards/I-02-mailbox-check.md

One mailbox in, one read-only report out: delegates, forwarding, inbox rules (including hidden),
size, archive, hold, shared or not, and a recent message trace. On a takeover sign the first line
reads "Possible account takeover: do NOT reset the password or delete the rule yet. Escalate.",
with "Check CIPP's BEC report" as the next step. Subjects stay out of the ticket note (D-025).
Second entry script in the SQ-002 folder; builds after SQ-002.

## SQ-016 · Mailbox check: when were rules, forwarding and delegates added?
- status: review
- waiting: SQ-007 (stacked on it; SQ-007 went back to ready at review 2026-10-18). Owner approved
  the merge; merge right after SQ-007 lands.
- priority: P2
- type: feature
- branch: squad/SQ-016-mailbox-audit-log (stacked on squad/SQ-007-mailbox-check; merge SQ-007 first)
- spec: squad/specs/SQ-016.md
- idea: squad/ideas/sessions/2026-10-16/cards/I-02-mailbox-check.md

Follow-up to SQ-007 (D-008): search the unified audit log for recently created or changed inbox
rules, forwarding and mailbox permissions (default 14 days), feeding the "recently added"
takeover sign. Every rule, forwarding or delegate change in the window triggers the "Escalate"
line, with when, who and whether it was the user's own account (D-032). "Could not check" when
the audit role is missing or auditing is off. Builds after SQ-007.

## SQ-009 · LocalAdminManager: make remote changes work, and log every add and remove
- status: done
- priority: P2
- type: fix
- branch: squad/SQ-009-localadmin-remote-log
- spec: squad/specs/SQ-009.md
- idea: squad/ideas/sessions/2026-10-16/brief.md (I-12, "Worth a look")

LocalAdminManager changes local Administrators membership without logging anything, and its
`-ComputerName` has never worked (the Local*GroupMember cmdlets have no such parameter; to be
confirmed on Learn). Find the group by SID, change it through ADSI, run remotely with
Invoke-Command (D-005), and log every change in the shared format (D-030). Fail closed if the log
can't be written (D-029).

## SQ-012 · AVD host checks in Citrix-FSLogix-Triage
- status: review
- priority: P2
- type: feature
- branch: squad/SQ-012-avd-host-checks
- spec: squad/specs/SQ-003.md (section "Proposed split: SQ-012 · AVD host checks")
- idea: squad/ideas/sessions/2026-10-16/cards/I-08-vdi-temp-profile-verdict.md

Detect an AVD session host and check RDAgentBootLoader, the RDInfraAgent IsRegistered value, the
documented event 3277 errors, events 3703/3019/3389 and the rdp-sxs listener, each linked to the
Learn fix. No new folder. Split from SQ-003 per D-004; P2 per D-016.

## SQ-005 · End-of-support section in AD-Audit
- status: review
- priority: P3
- type: feature
- branch: squad/SQ-005-end-of-support
- spec: squad/specs/SQ-005.md
- idea: squad/ideas/sessions/2026-10-16/cards/I-11-end-of-support-in-ad-audit.md

AD-Audit gains an "End of support" section listing every Windows Server by OS version with
Microsoft's lifecycle end date (cited per row from Learn), days left or since, and last logon,
hedged for ESU. The existing Unsupported OS list draws its server entries from the same table
(D-020). Dated CSV; no automatic comparison in v1 (D-021).

## SQ-021 · FolderPermissionManager: admin-share route skips the server-side junction check
- status: dropped
- priority: P2
- type: follow-up
- found-in: SQ-018
- branch:
- merged-into: SQ-023 (2026-10-19 plan; the ACs in squad/specs/SQ-021.md are built there)

When NetShareGetInfo fails, Get-ShareTreeRefusal tells the tech to open the folder by its
administrative share path (\\server\D$\...). The D-045 server-side junction check
(Get-ServerSideLinkRefusal) only runs for ordinary shares, so that advice sends the tech down
the one route that skips it: a whole-tree takeown on \\fs01\D$\Shares\Data where Shares is a
server-side junction into C:\Windows or C:\Users would go ahead. Either run the junction check
for whole-tree changes on \\server\X$\... paths too, or change the advice to "run the tool on
the server itself, or ask a senior admin". (Advisory review of SQ-018 rev2, major.)

## SQ-022 · FolderPermissionManager: D-044 copy refusals and confirms only exist in the WPF app
- status: ready
- priority: P2
- type: follow-up
- found-in: SQ-018
- branch:
- spec: squad/specs/SQ-022.md
- depends-on: SQ-018

The D-044 protections (protected Copy targets refused, Deny/root confirms) live only in
FolderPermissionManager-GUI.ps1. The core work function Copy-FolderPermission accepts any
target, so the browser GUI and any CLI copy path can still copy Deny entries onto ADMIN$,
SYSVOL, C:\Windows or C:\Users. Move Get-CopyTargetRefusal (with path resolution) into the core
and enforce it inside Copy-FolderPermission. Moot for the browser GUI once it is removed after
the SQ-018 lab test, but the CLI still needs it. (Destructive-operations review of SQ-018 rev2, major.)

## SQ-024 · FolderPermissionManager: a typed `..` in a share path makes the checks look at a different folder
- status: ready
- priority: P2
- type: follow-up
- found-in: SQ-018
- branch:
- spec: squad/specs/SQ-024.md
- depends-on: SQ-018

Get-ShareTreeRefusal builds the server-side path from the typed rest of a UNC path, and
ConvertTo-ComparablePath resolves `..` against the server's folder, so it can climb above the
share's own folder (it keeps only `\\server\X$`). Windows stops `..` at `\\server\share`.
Get-ChangeTarget never rejects `.` or `..` segments. Example: AppShare is
C:\ProgramData\App\Share and the tech types `\\fs01\AppShare\..\..\..\Data`. D-036, the
high-impact check and D-045 look at `\\fs01\C$\Data`, while takeown and icacls change
C:\ProgramData\App\Share\Data, inside a D-036 folder. Refuse typed paths with `.` or `..`
segments in Get-ChangeTarget, or normalise the client UNC first (stopping `..` at
`\\server\share`), then map to the server. Fix the comment in Get-ServerSideLinkRefusal that
says `.`/`..` segments do not skip the check, and add a regression test.
(Destructive-operations re-review of SQ-018 fix round 1, major.)

## SQ-023 · FolderPermissionManager: CLI and browser whole-tree paths lack the D-045 and resolved high-impact checks
- status: ready
- priority: P2
- type: follow-up
- found-in: SQ-018
- branch:
- spec: squad/specs/SQ-023.md (includes SQ-021)
- depends-on: SQ-018, SQ-024

The D-045 server-side junction check and the resolved-path high-impact check run only in the
WPF app's lookup. Through the CLI or the browser GUI, a whole-tree take ownership on
\\server\share whose server-side folder is reached through a junction lands on an unchecked
server folder. Move Get-ShareTreeRefusal, Get-ServerSideLinkRefusal, Get-RemoteShareLocalPath
and Get-AppReparseInfo into the core and call them from Get-TreeOwnershipTargetRefusal.
(Destructive-operations review of SQ-018 rev2, major.)

## SQ-025 · FolderPermissionManager WPF app: change an existing permission in place
- status: ready
- priority: P1
- type: feature
- branch:
- spec: squad/specs/SQ-025.md
- depends-on: SQ-018

Owner request during the SQ-018 lab test (2026-10-19): turning an Allow entry for `chihlas`
into a Deny meant adding a second entry and retyping the whole account name. Add **Change
Permission** for an explicit entry (folders and files): a button, and double-click on a row,
open a dialog pre-filled with the entry's account (shown, not editable), permission level and
Allow/Deny. Changing to Deny gets the AC47 destructive confirm (red button, real location).
The old entry is replaced by the new one in a single ACL write after the usual backup and log,
so a failure never leaves the account with no entry; read back and report like Add/Remove,
-WhatIf end to end. Inherited entries cannot be changed here: the dialog says which folder above
they come from. Destructive-operations checklist applies.

## SQ-026 · FolderPermissionManager: Copy targets on a remote share get the file-server checks
- status: new
- priority: P2
- type: follow-up
- found-in: SQ-022 (D-053)
- depends-on: SQ-023
- branch:

A Copy Permissions target on a remote share is checked only on the client side: `\\fs01\Win`
pointing at C:\Windows on the server is not refused. After SQ-023 moves the share helpers
(Get-ShareTreeRefusal, Get-ServerSideLinkRefusal, Get-RemoteShareLocalPath) into the core, run
them for every remote Copy target: the share's real server folder against D-036 and the
high-impact roots, and the D-045 junction walk, failing closed. Same as whole-tree takeown
(D-045), extended to Copy (D-053).

## SQ-027 · M365 user check: a blocked risky user must escalate to the security lead, not the manager path
- status: new
- priority: P2
- type: follow-up
- found-in: SQ-019
- branch:

D-050 limits the "check with their manager, note who approved it, then unblock/enable" step to a
plain blocked account (no block marker, not a risky user). `M365UserCheck.Core.ps1` picks the
SignInBlocked step (cloud-only, :831) and both 50057 steps (:738/:739) without looking at the
ID Protection result. A user flagged atRisk/confirmedCompromised whom an admin blocked during an
incident gets "involve the security lead before unblocking" (RiskyUser, a Warning) next to
"check with their manager ... then unblock sign-in" (SignInBlocked, a Blocker), and only the
Blocker's step reaches the ticket note. Tier 1 could unblock a compromised account. When
RiskGate is Available and the user is risky, those steps should escalate to the security lead.
Add a blocked + risky scenario test. Same pass: the synced 50057 step should not say "enable it
in AD" when AD was read and the account carries the block marker (conflicts with the :678
escalation on the same ticket).

## SQ-028 · FolderPermissionManager: a bare account name on a network folder must not resolve to this workstation's local account
- status: new
- priority: P2
- type: follow-up
- found-in: SQ-018
- branch:

Add Permission resolves a bare name such as `micha` on the workstation (NTAccount.Translate /
LookupAccountName), which checks the local machine's accounts before the domain
(https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-lookupaccountnamew). If the
workstation has a local `micha` and the domain also has one, a grant on `\fs01\share` goes to
the workstation's local SID: an orphan entry the server cannot use, reported as Done. SQ-018's
AC56 lookup now even shows it as "found". On a target that is not on this computer, refuse or
warn when the resolved SID is in this computer's account domain (machine SID prefix), and show
which account (DOMAIN\name) will be used before the change starts. Related: lab-test whether
the AC55 advice "Type the server's name instead, for example FS01\name" resolves from a
workstation at all; if not, reword it (domain group, or run the tool on the server).
Destructive-operations checklist applies.
Same pass (found in the SQ-018 fix-round re-review): `Test-AddTargetOnThisComputer` decides
"this computer" for `.\name` from the drive type only, so `D:\Link` where `D:\Link` is a
directory symbolic link to `\FS01\Data` (Fixed drive) still rewrites `.\micha` to
`PC01\micha` and writes a workstation-local SID onto FS01's folder (reported Done). Refuse when
any folder from the target up to its root is a reparse point not known to be local, or cannot be
read (Get-AppReparseInfo throws, so fail closed); test with a mocked symlink tag 0xA000000C.
