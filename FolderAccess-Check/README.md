# FolderAccess-Check

**"I get Access denied on a folder."** Give it a user and the network path of the folder. It works out which share permissions and folder permissions apply to that person, through which of their groups, and whether anything denies them. Then it gives a careful answer with the reason and what to do next.

It only reads. It never changes permissions, groups or anything else.

## When to use it

- A user gets "Access denied" or "You don't have permission" opening a network folder.
- You need to know *which* layer is stopping them (share or folder permissions) before you change anything.
- You want the evidence for the ticket (add `-OutputPath`).

## The one command

```powershell
.\Get-FolderAccessCheck.ps1 -Identity jdoe -Path '\\FS01\Finance\Budgets 2027'
```

`-Path` must be the **full network path**. A mapped drive letter (`S:\Budgets`) won't work: this machine can't see the user's drive mappings. Ask the user to right-click the drive in File Explorer, or run `net use` on their PC, to get the `\\server\share` part.

`-Identity` takes a sign-in name (`jdoe`), `jdoe@contoso.com`, `CONTOSO\jdoe`, a distinguished name, or as a last resort a display name (`"Jane Doe"`). It finds people the same way as AD-UserQuickCheck.

Other options:

| Option | What it does |
|---|---|
| `-Access Modify` | Check "can they change files in it?" instead of the default "can they open it?" (`Read`). |
| `-OutputPath C:\Temp` | Also saves an HTML report and a CSV of the evidence named `FolderAccessCheck_<name>_<date>_<time>`. Without it, console only. |
| `-Server DC01` | Run the Active Directory lookups against a specific domain controller or domain. |
| `-Credential (Get-Credential)` | Use a different account for Active Directory and for the connection to the file server. |
| `-MaxNestingDepth 15` | Follow group paths further up (default 10). Matching is always complete; this only affects how much of the path is shown, and how far up a suggested group is checked for privileged groups (deeper than this, it asks for senior approval). |
| `-TicketNumber 482113` | Saves the HTML, the CSV and the ticket note together in `Ticket_482113` (under `-OutputPath`, or `Documents\TicketNotes` without it). |
| `-NoClipboard` | Don't copy the ticket note to the clipboard. |
| `-FullDetail` | Keep the folder path in the ticket note. By default it is removed so the note is safe to paste. |
| `-PassThru` / `-Quiet` | For scripts: return the result object instead of an exit code / write nothing to the console (and leave the clipboard alone). |

Needs the ActiveDirectory (RSAT) PowerShell module. Reading the **share** permissions needs administrator rights on the file server (over WinRM, or WMI/DCOM if WinRM is off). Works on Windows PowerShell 3.0 and later.

## How to read the answer

The first line is the answer:

```
Can Jane Doe open \\FS01\Finance\Budgets 2027?  PROBABLY NO
Limited by: folder permissions
```

| Answer | Meaning |
|---|---|
| **PROBABLY YES** | Both the share permissions and the folder permissions let them in. If they still can't, check the exact path they use. |
| **PROBABLY NO** | The folder permissions or the share permissions don't let them in, or a Deny entry blocks them. "Limited by" says which. |
| **CAN'T TELL** | Something that decides the answer couldn't be read. The reason says what, and the next steps say what to do instead. This is a normal answer, not an error. |

It never says a plain YES or NO. The last next step is always **Properties > Security > Advanced > Effective Access** for the user: that is Windows' own final word, and it covers things this tool doesn't (see below).

Below the answer you see the evidence: every share and folder permission entry **in the order Windows checks them**, whether it matches the user, through which group (for example `FIN-Staff -> FIN-All`, or `Domain Users (primary group) -> FS01\Users`), and what effect it has:

| Effect | Meaning |
|---|---|
| allows | This entry lets them in. |
| allows part of what is needed | It matches, but on its own it isn't enough (for example "Traverse folder only"). |
| applies (on a Deny) | This Deny blocks them. |
| overridden by an earlier allow | A Deny that matches them, but Windows had already let them in from an earlier entry, so it never counts. |
| applies below this folder only | Only for subfolders and files inside ("inherit only"); it doesn't count for opening this folder. |
| not checked: ... | An unknown account, or a local group on the server whose members couldn't be read. The answer is CAN'T TELL only if that entry could change it. |

## What to do about it

**PROBABLY NO: which group should they be in?** The next steps name the **narrowest existing group** that would let them in:

```
Narrowest existing group that grants this: FIN-Managers (12 direct members). If the folder's owner agrees, add jdoe to it in Active Directory, then have them sign out and back in.
```

- "Narrowest" means the fewest direct members. A group that a Deny would still block (on the group, or on a group it is in), or that the share permissions would still stop, is skipped.
- It never suggests Everyone, Authenticated Users, Domain Users, Domain Computers, a `BUILTIN` or server-local group, or a user account, even when those entries are on the folder.
- **A privileged group itself is never suggested** (Domain Admins, Enterprise Admins, Schema Admins, Domain Controllers, Enterprise Read-only Domain Controllers, Group Policy Creator Owners, `BUILTIN\Administrators`, DnsAdmins, DHCP Administrators, the Exchange groups Exchange Windows Permissions, Exchange Trusted Subsystem and Organization Management, and the like). If only those would let them in, as on a typical home folder, the next step is *"Only privileged groups grant this. Escalate to a senior engineer: ..."*.
- **Groups nested in a privileged group come last, and need senior approval.** If the only group that works is nested in Domain Admins (or another privileged group), the step starts with the approval: *"Narrowest existing group that grants this: FIN-Admins (5 direct members). Get senior approval first, then add jdoe to FIN-Admins ..."*, followed by *"Warning: FIN-Admins is also in Domain Admins. Adding jdoe gives them domain admin rights. Get senior approval first."* A group with `adminCount = 1` is flagged as *protected by AdminSDHolder*: it is, or was, in a privileged group.
- **If its groups can't all be read, it assumes the worst.** When a group above the candidate can't be read (or is deeper than `-MaxNestingDepth`), the tool can't confirm it isn't privileged: it is ranked after the groups it could confirm, and says *"Couldn't confirm FIN-Managers is not in a privileged group. Get senior approval first."*
- **In a forest with more than one domain, or with any trust, it can't confirm any group.** A group's `memberOf` read from the user's domain leaves out groups of other domains and forests (the forest root's `BUILTIN\Administrators`, for one), so every suggestion then needs senior approval, as above. The same happens when the forest or its trusts can't be read. The step after the warning adds that the group *may also not work if a group it belongs to is denied*: confirm with Effective Access after the change.
- If no existing group grants it, the next step says so: ask who owns the folder which group should have access, then add that **group** (not the user) with FolderPermissionManager, which logs the change.

This tool never changes anything itself: adding someone to a group is done in Active Directory Users and Computers, after the folder's owner agrees.

**PROBABLY YES, but they still get Access denied?** A new group membership only counts after the user signs in again. If every group that grants the access was joined **after their last sign-in**, the answer reads:

```
Can Jane Doe open \\FS01\Finance\Budgets 2027?  PROBABLY YES after jdoe signs out and back in
```

with the finding *"added to FIN-Staff on 2026-10-15, after their last sign-in on 2026-10-10"*, and the next step: *"Ask them to sign out of Windows and any Citrix/RDS session, then sign in again (locking and unlocking is not enough)"*.

- "When they joined" comes from the directory's replication data for that membership (for the primary group, when it was last set). "Last sign-in" is the newest `lastLogon` across **every** domain controller, because each DC keeps its own.
- If either time can't be read (no rights to the replication data, a DC that didn't answer, or no sign-in recorded), "when jdoe was added to the group" is listed under "Couldn't check" and no such claim is made.
- If any group that grants the access is older than their last sign-in, there is no sign-out finding.

## The ticket note

Every run ends with a short four-part note for the ticket (**Checked**, **Ruled out**, **Could not check**, **Next step**), copied to the clipboard. With `-TicketNumber` it is also saved as `Note_<time>_FolderAccess-Check.txt` beside the HTML and the CSV, and `TicketNote\Join-TicketNotes.ps1` can join it with the other tools' notes for the same ticket.

- A layer is only **ruled out** when it was really read and the answer is PROBABLY YES or PROBABLY NO. An unreadable folder or share, an administrative share or a DFS path goes under **Could not check**, never "Ruled out".
- The note is **paste-safe** by default: it says "the folder" instead of the path, and any path in an error message becomes `[share path removed]` (the path you checked, its share and the share name are removed by name; any other path by the paste-safe filter). Add `-FullDetail` to keep the path. The HTML and the CSV always keep the full path.
- The note is built by `CaseKit.ps1` in this folder (a copy of `TicketNote\CaseKit.ps1`). If it is missing, the check still runs without a note.

## When it says CAN'T TELL

| Reason | What to do |
|---|---|
| Your account can't read this folder's permissions | Run it again as an account that can (for example a file server admin). |
| Couldn't read the share permissions on FS01 | WinRM and WMI (DCOM) both refused, or you aren't an admin there. Both errors are listed. Check the share in Computer Management on the server. |
| The share's permission list came back empty or unreadable | The server answered, but without a permission list this tool can safely interpret. Check the share in Computer Management on the server. |
| Administrative share (`C$`, `D$`, `ADMIN$`) | Run it again with the path the user actually opens, not an admin share. |
| This is a DFS path | The server part is your domain name (`\\contoso.com\...`), so the real file server isn't known. Find it on the folder's **Properties > DFS** tab and run it again with that path. The folder permissions are still shown. |
| Claims-based conditions | The folder uses Dynamic Access Control conditions. Only Effective Access can evaluate them. |
| A local group on the server whose members couldn't be read | Check that group's members in Computer Management on the server. |
| An unknown account | An entry shown only as a SID: usually a deleted account, or one from another domain. |

If the folder permissions alone already rule the user out, the answer is PROBABLY NO even when the share permissions couldn't be read, because access needs both. "share permissions: not read" is listed under "Couldn't check".

## Things worth knowing

- **Order matters.** Windows checks entries top to bottom and stops as soon as it has an answer. An explicit Allow above an inherited Deny wins; a Deny above an Allow wins. The tool walks the list the same way rather than treating any Deny as "no".
- **Groups come from the directory's own list of every group the user is in** (`tokenGroups`), including nested groups and the primary group, so nothing is missed. The path shown next to each match is from walking the user's groups upward; if a group is too deep, it shows "nested (path not traced)".
- **Local groups on the file server** (for example `BUILTIN\Users`, which by default contains Domain Users) are read from that server, that group only. If they can't be read (the server can't be reached, it's a DFS path, or the server didn't answer for the group), the entry is listed under "Couldn't check", and the answer is CAN'T TELL when that entry could change it. Local user accounts on the server are recognised and never match a domain user.
- **Standalone DFS paths** (`\\FS01\Public\Link`, where `FS01` is the namespace server) look like ordinary share paths. The share permissions shown are the namespace root's share, not the share the link points to. If in doubt, use the real server path from the folder's **Properties > DFS** tab.
- **Exit codes** (for scripts): `0` PROBABLY YES (also "after they sign out and back in"), `1` PROBABLY NO, `2` bad path or user not found or ambiguous, `3` AD module or connection failure, or an unusable `-TicketNumber`, `4` CAN'T TELL.
- **Rights**: the "when were they added" check reads the directory's replication data, which Domain Users can normally read. If your account can't, it is listed under "Couldn't check".

## What it does not check

- Files and subfolders inside the folder, and the folders above it.
- Central access policy (Dynamic Access Control), ownership rights, integrity labels, offline files.
- Access-based enumeration: it only hides what the user can't open anyway, so it doesn't change the answer.
- Users or groups from other forests beyond matching their SIDs.
- For a standalone DFS namespace path, the share behind the link (see above).

## The saved reports hold client data

The HTML and CSV from `-OutputPath` contain the client's group memberships (with SIDs), server, share and folder names and paths. Attach them to the ticket, then delete the local copy. They are ignored by git (`FolderAccessCheck_*`) so they can't be committed by accident.

## Tests

```powershell
Invoke-Pester .\FolderAccess-Check\Tests
```

The tests run against a fake ActiveDirectory module (`Tests\FakeAD`) and mocked CIM and `Get-Acl` calls built from synthetic SDDL, so no domain or file server is needed. Before relying on a change to the evaluation, compare the result with Effective Access on a lab share.
