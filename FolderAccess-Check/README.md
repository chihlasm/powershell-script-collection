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
| `-MaxNestingDepth 15` | Follow group paths further up (default 10). Matching is always complete; this only affects how much of the path is shown. |

Needs the ActiveDirectory (RSAT) PowerShell module. Reading the **share** permissions needs administrator rights on the file server (over WinRM, or WMI/DCOM if WinRM is off). Works on Windows PowerShell 3.0 and later.

## How to read the answer

The first line is the answer:

```
Can Jane Doe open \\FS01\Finance\Budgets 2027?  PROBABLY NO
Limited by: folder permissions
```

| Answer | Meaning |
|---|---|
| **PROBABLY YES** | Both the share permissions and the folder permissions let them in. If they still can't, check the exact path they use, and whether they were added to a group since they last signed in. |
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

## When it says CAN'T TELL

| Reason | What to do |
|---|---|
| Your account can't read this folder's permissions | Run it again as an account that can (for example a file server admin). |
| Couldn't read the share permissions on FS01 | WinRM and WMI (DCOM) both refused, or you aren't an admin there. Both errors are listed. Check the share in Computer Management on the server. |
| Administrative share (`C$`, `D$`, `ADMIN$`) | Run it again with the path the user actually opens, not an admin share. |
| This is a DFS path | The server part is your domain name (`\\contoso.com\...`), so the real file server isn't known. Find it on the folder's **Properties > DFS** tab and run it again with that path. The folder permissions are still shown. |
| Claims-based conditions | The folder uses Dynamic Access Control conditions. Only Effective Access can evaluate them. |
| A local group on the server whose members couldn't be read | Check that group's members in Computer Management on the server. |
| An unknown account | An entry shown only as a SID: usually a deleted account, or one from another domain. |

If the folder permissions alone already rule the user out, the answer is PROBABLY NO even when the share permissions couldn't be read, because access needs both. "share permissions: not read" is listed under "Couldn't check".

## Things worth knowing

- **Order matters.** Windows checks entries top to bottom and stops as soon as it has an answer. An explicit Allow above an inherited Deny wins; a Deny above an Allow wins. The tool walks the list the same way rather than treating any Deny as "no".
- **Groups come from the directory's own list of every group the user is in** (`tokenGroups`), including nested groups and the primary group, so nothing is missed. The path shown next to each match is from walking the user's groups upward; if a group is too deep, it shows "nested (path not traced)".
- **Local groups on the file server** (for example `BUILTIN\Users`, which by default contains Domain Users) are read from that server, that group only. If the server can't be reached at all, those entries are listed under "Couldn't check".
- **Recently added to a group?** The user's sign-in still carries the old groups until they sign out and back in (locking and unlocking is not enough).
- **Exit codes** (for scripts): `0` PROBABLY YES, `1` PROBABLY NO, `2` bad path or user not found or ambiguous, `3` AD module or connection failure, `4` CAN'T TELL.

## What it does not check

- Files and subfolders inside the folder, and the folders above it.
- Central access policy (Dynamic Access Control), ownership rights, integrity labels, offline files.
- Access-based enumeration: it only hides what the user can't open anyway, so it doesn't change the answer.
- Users or groups from other forests beyond matching their SIDs.
- To change permissions, use FolderPermissionManager, and add a **group** rather than the user.

## Tests

```powershell
Invoke-Pester .\FolderAccess-Check\Tests
```

The tests run against a fake ActiveDirectory module (`Tests\FakeAD`) and mocked CIM and `Get-Acl` calls built from synthetic SDDL, so no domain or file server is needed. Before relying on a change to the evaluation, compare the result with Effective Access on a lab share.
