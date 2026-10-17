# I-07 · "Can this user open this folder?" access evidence (share plus NTFS, never a bare YES)
- Champion: user-in-the-moment, security, market-analyst
- Score: 26 (F 4, T 3, D 3, E 3, R 3)

## The pitch
Enter a user and a UNC path. The tool shows the full chain that decides access: the share
permission entries, the NTFS entries on the folder, which of the user's groups (nested and
primary) match each entry, and any Deny. It then gives a hedged verdict ("PROBABLY YES via
FIN-Readers", "PROBABLY NO: no entry matches", "CAN'T TELL: claims-based policy on this share"),
names the narrowest existing group that would grant the access, and tells the tech to confirm in
Windows' Effective Access tab. It also flags a stale token when the user was added to the group
after their last sign-in.

## A day with it
A user can map `\\FS01\Finance` but gets "Access denied" on `Budgets 2027`. The tech runs the
check. It shows the share grants Authenticated Users Change, but the folder has broken
inheritance and only `FIN-Managers` has Modify; the user is in `FIN-Staff`. Verdict: "PROBABLY
NO: no NTFS entry matches. Narrowest group that already grants this: FIN-Managers (not
privileged elsewhere). Confirm in Advanced Security > Effective Access for jdoe." The tech
escalates with the evidence instead of asking the client to "try again" or adding the user
directly to the folder.

## Why us, why now
- **Owner signals:** SIGNALS 2026-10-16 [files][drive-maps]: file access is a recurring time
  sink. Techs click through ADUC and folder security dialogs by hand ("Where techs leave the
  tools").
- **Gap in the bundle:** the access report in `ServiceDesk-Toolkit/README.md` is group-only.
  FolderPermissionManager edits ACLs but gives no verdict. This is the natural next step after
  DriveMap-Diagnostics rules out the mapping.
- **Market gap:** free NTFS auditors gate export behind Pro editions ($199-$1,249, recon-market
  pain 8; e.g. [NTFS Permissions Auditor FAQ](https://albusbit.com/help/ntfs-permissions-auditor/faq.html)).
  SolarWinds Permissions Analyzer and NTFSSecurity's `Get-NTFSEffectiveAccess` need installs and
  produce no ticket output.
- **Code leverage:** AD-GroupMembership-Export nesting with the fixed primary-group resolution,
  FolderPermissionManager ACL reading, SMBTest, and Find-PrivilegedAccessPaths for the "is that
  group privileged elsewhere?" warning.

## The strongest objection
A YES/NO here means re-implementing Windows access evaluation in PowerShell: deny ordering,
inheritance, CREATOR OWNER, share intersected with NTFS, nested and primary groups, claims and
central access policy, token staleness. This is the exact area where the repo has already
shipped a confident wrong answer (the access report flagging primary-group members as duplicate
access, SIGNALS 2026-10-14). Windows already has a supported evaluator for free, the Effective
Access tab, which reports whether access is limited by the share or the file permissions. The
only remote API, `AuthzInitializeRemoteResourceManager`, needs Server 2012+ targets and
hand-written P/Invoke with no PowerShell surface
([Learn](https://learn.microsoft.com/windows/win32/api/authz/nf-authz-authzinitializeremoteresourcemanager)).

**Answer:** v1 never prints a bare YES and never re-implements the evaluator. It shows the
chain, hedges the verdict, and sends the tech to Effective Access for the final word. Its value
is what Effective Access does not show: which group grants it, the narrowest group to use
instead of a direct entry, and the stale-token finding. Effective Access's own behaviour is
known only from forum threads
([Q&A](https://learn.microsoft.com/en-us/answers/questions/2122114/architecture-of-file-shares-in-windows-how-resulta),
[TechNet archive](https://learn.microsoft.com/en-us/archive/msdn-technet-forums/d1248276-3955-4c68-9027-c8f1a82185b4)),
and one thread reports stale results, so the tool should not claim more than it can see either.

## Cost and risk
- **Size:** M for the evidence-and-hedged-verdict v1. A real YES/NO would be L and is out of
  scope.
- **Reads:** share entries via `Get-SmbShareAccess` / `MSFT_SmbShareAccess` on Server 2012+,
  `Win32_LogicalShareSecuritySetting` on older servers (both to verify on Learn before coding);
  NTFS entries via `Get-Acl`; group expansion via the existing fixed code.
- **Rules:** never suggest Everyone, Authenticated Users or a direct per-user entry. Warn when the
  recommended group is privileged elsewhere. "CAN'T TELL" with the reason for ABE, claims or
  central access policy, and unreadable folders.
- **Hand-off to FolderPermissionManager** waits on that tool's change log (the I-12 BACKLOG item),
  so the fix it leads to is recorded.
- **Floor:** 3.0 where the WMI fallback is used.
- **What could go wrong:** a missed Deny or nested-group path producing a wrong PROBABLY;
  regression of the primary-group bug (add a test for it).
- **Risk profiles:** personal-data (group membership and folder names). Read-only.

## Score reasoning
- Frequency 4: file and folder access is one of the owner's named recurring ticket drivers.
- Time saved 3: Effective Access already answers the yes/no; the tool saves the group-chain hunt
  and gives the narrowest group, maybe 10-15 minutes per ticket.
- Differentiation 3: free auditors lock export behind paid tiers and give no ticket output, but
  Windows' own evaluator covers the core answer.
- Effort 3: M for v1, with a real Windows-version split for share permissions.
- Risk 3: read-only, but this is the area of a past confident wrong answer; hedged wording and
  regression tests keep it at medium.
