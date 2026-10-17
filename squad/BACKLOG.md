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

## SQ-001 · Ticket note from every quick check
- status: new
- priority: P1
- type: feature
- branch:
- spec:
- idea: squad/ideas/sessions/2026-10-16/cards/I-03-ticket-note.md

Every verdict tool ends by writing the same four-part note (Checked / Ruled out / Could not
check / Next step) to a text file and the clipboard, ready to paste into ConnectWise. It carries
a stamp (tenant or domain, who ran it, machine, time, changed anything). `-TicketNumber` puts all
of a ticket's notes in one folder, and a small joiner concatenates them. A check lands under
"Ruled out" only when its gate confirms it could look. First slice: AD-UserQuickCheck (plus
`-PassThru`), Network-QuickCheck, Citrix-FSLogix-Triage, via a shared `CaseKit.ps1` copied into
each folder with a parity test. Approved by Michael in the 2026-10-17 pitch session.
## SQ-002 · M365 user check: can this user sign in, and is it a sync problem?
- status: new
- priority: P1
- type: feature
- branch:
- spec:
- idea: squad/ideas/sessions/2026-10-16/cards/I-01-m365-user-signin-check.md

The cloud version of AD-UserQuickCheck: one UPN in, YES / NO / PROBABLY NOT out, with the reason
and a next step. It covers blocked, unlicensed, no MFA method, CA failure, smart lockout and
decoded sign-in failures, plus sync (never synced, stale, address held by another object). A
banner prints first with tenant, signed-in account and what the tool can see. About half of
clients have no Entra ID P1, so "sign-in logs: not available" is a normal path, never a false
all-clear. Techs often sign in with the client's global admin account. The tool stays read-only
regardless, and the banner guards against wrong-tenant runs. Follow the build conditions on the
card (failureReason plus Microsoft's error link, no cached AADSTS table; risky user is P2-only).
The Entra Connect server stage is a second release. Plugs into the SQ-001 ticket note. Approved
by Michael in the 2026-10-17 pitch session.
## SQ-003 · "Why did this user get a temporary profile?" one-user VDI verdict, plus AVD host checks
- status: new
- priority: P1
- type: feature
- branch:
- spec:
- idea: squad/ideas/sessions/2026-10-16/cards/I-08-vdi-temp-profile-verdict.md

Enter a username and a session host (or a Delivery Controller to find the host through Citrix).
The tool runs the existing FSLogix collectors on that host and asks the profile file server
which machine holds the user's disk open (`Get-SmbOpenFile`). It returns one ranked cause and
the next step, with the evidence for each candidate cause. It replaces the bundle's profile row
instead of adding one. It recommends a logoff but never performs one. A second part adds AVD
host checks to Citrix-FSLogix-Triage (agent registered, RDAgentBootLoader, documented 3277
errors, listener state), each linked to the Learn fix; no new folder. RDS/AVD session discovery
and Azure Files lock holders are out of v1. Approved by Michael in the 2026-10-17 pitch session.
## SQ-004 · "Can this user open this folder?" access evidence
- status: new
- priority: P2
- type: feature
- branch:
- spec:
- idea: squad/ideas/sessions/2026-10-16/cards/I-07-folder-access-evidence.md

Enter a user and a UNC path. The tool shows the chain that decides access: share entries, NTFS
entries on the folder, which of the user's groups (nested and primary) match each entry, and any
Deny. It gives a hedged verdict (PROBABLY YES / PROBABLY NO / CAN'T TELL with the reason) and
never a bare YES. It names the narrowest existing group that would grant access and warns if
that group is privileged elsewhere. It flags a stale token, and tells the tech to confirm in
Effective Access. It never suggests Everyone, Authenticated Users or a direct per-user entry.
Read-only. Add a regression test for the past primary-group bug. Approved by Michael in the
2026-10-17 pitch session.
## SQ-005 · End-of-support section in AD-Audit
- status: new
- priority: P3
- type: feature
- branch:
- spec:
- idea: squad/ideas/sessions/2026-10-16/cards/I-11-end-of-support-in-ad-audit.md

AD-Audit gains an "End of support" section listing every Windows Server by OS version with
Microsoft's lifecycle end date (cited per row from Learn, with the date the table was last
checked), days left or since, and last logon. Wording is hedged: "extended support ended;
covered only if the client bought ESU". The CSV is dated and records who ran it, so audits can
be compared quarter to quarter. Test the date edge cases. AD-Audit only; no new remoting.
Approved by Michael in the 2026-10-17 pitch session.
## SQ-006 · Lockout tools recognize Kerberos encryption-type blocks (RC4 enforcement)
- status: new
- priority: P2
- type: feature
- branch:
- spec:
- idea: squad/ideas/sessions/2026-10-16/cards/I-06-kerberos-enforcement-check.md

Since the 2026 RC4 changes (KB5073381), some authentication failures look like lockouts but are
an encryption-type block. AD-LockoutDiagnostics (and AD-UserQuickCheck where it fits) should
recognize this as its own cause: "not a password problem, encryption type blocked". It should
then give the next step (reset the password to create AES keys, or the device is RC4-only).
Evidence: 4769 failure 0xE and KDCSVC 203/204/208/209 errors. A per-DC gate says "can't tell"
where a DC can't log them. Re-verify every event ID and value on Learn and the KB before coding;
Microsoft's guidance is inconsistent, and Learn's 0x0 row is stale for patched DCs. Read-only.
The full domain-wide scan is parked. Approved (reshaped to this slice) by Michael in the
2026-10-17 pitch session.
## SQ-007 · Mailbox check: the facts, with "do NOT reset yet" on takeover signs
- status: new
- priority: P2
- type: feature
- branch:
- spec:
- idea: squad/ideas/sessions/2026-10-16/cards/I-02-mailbox-check.md

One mailbox in, one read-only report out. It covers Full Access, Send As and Send on Behalf;
forwarding; inbox rules, including hidden ones (`Get-InboxRule -IncludeHidden`); size, archive,
hold and shared or not; and a recent message trace (`Get-MessageTraceV2` within its limits). On
any takeover sign (external forwarding, rules that hide or delete mail, recently added rules or
delegates), the first line reads "Possible account takeover: do NOT reset the password or
delete the rule yet. Escalate.", with "Check CIPP's BEC report" as the next step. It does not
score takeover risk itself, because the MSP runs CIPP. It never shows message bodies, has no
remediation switches, and gives "partly checked" when a role or licence is missing. Second entry
script in the SQ-002 folder, built after SQ-002. The leaver mode stays parked. Approved
(reshaped) by Michael in the 2026-10-17 pitch session.
## SQ-008 · FolderPermissionManager: back up permissions and log every change
- status: new
- priority: P1
- type: fix
- branch:
- spec:
- idea: squad/ideas/sessions/2026-10-16/brief.md (I-12, "Worth a look")

FolderPermissionManager calls `Set-Acl` without saving the previous permissions and keeps no
change log. That breaks `squad/risks/destructive-operations.md`, which requires an SDDL export
before `Set-Acl` and a change log with old and new values. Save the folder's SDDL before every
change, and write a change-log CSV in the M365-SyncedUserFixes format (who, when, path, old,
new). That makes every change provable and reversible. SQ-004 (folder access evidence) hands off
here, and the SQ-001 note stamp can then say "Changed anything: Yes" with the log path.
Approved by Michael in the 2026-10-17 pitch session.

## SQ-009 · LocalAdminManager: log every add and remove
- status: new
- priority: P2
- type: fix
- branch:
- spec:
- idea: squad/ideas/sessions/2026-10-16/brief.md (I-12, "Worth a look")

LocalAdminManager changes local Administrators membership without logging anything, which
breaks the destructive-operations risk profile. Log every add or remove with who, when,
computer, and the old and new member lists, in the same change-log format as SQ-008. Approved by
Michael in the 2026-10-17 pitch session.