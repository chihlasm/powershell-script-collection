# M365-UserQuickCheck

**"I can't sign in to Outlook / Teams."** Run this while the user is waiting. It tells you, in plain English, whether their Microsoft 365 account can sign in, and if not, why and what to do next.

It only reads. It never unblocks, resets, assigns licences or changes anything, even when you sign in as the client's Global Administrator: every request is a read (GET) and every permission it asks for is a read-only permission.

## When to use it

- A user cannot get into Outlook, Teams, OneDrive or the Microsoft 365 portal.
- You want Microsoft's own reason for a failed sign-in (the error code and its text) without opening the Entra admin center.
- You want something to paste into the ticket: the [ticket note](#ticket-note) is on your clipboard after every run.

- The user syncs from on-premises AD and you want to know whether it is a sync problem (see [Is it a sync problem?](#is-it-a-sync-problem)).

For the on-premises account's own state (locked out, password expired in AD), use [AD-UserQuickCheck](../AD-UserQuickCheck/).

For **"mail is going missing" / "who can see this mailbox?"**, the same folder has the [mailbox check](#mailbox-check-get-m365mailboxcheckps1).

## Before the first run

Install the Graph sign-in module once (no admin rights needed):

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

Works on Windows PowerShell 5.1 and PowerShell 7.

For the on-premises AD comparison you also need the RSAT Active Directory module (the `ActiveDirectory` PowerShell module) and a domain controller that answers. You can run the tool in two places:

- **On a client server** (domain-joined, with RSAT and the Graph module): both parts run.
- **On your own workstation**: the Microsoft 365 part always runs. Add `-Server <client domain controller> -Credential <client admin>` for the AD part; without a domain controller that answers, the AD part says "On-premises AD: could not check (why)" and the answer comes from Microsoft 365 alone.

## The one command

```powershell
.\Get-M365UserQuickCheck.ps1 -UserPrincipalName jdoe@contoso.com -TenantId contoso.onmicrosoft.com
```

A browser window opens. **Sign in with an account in the client's tenant.**

**At the permissions prompt, consent for yourself only. Leave "Consent on behalf of your organization" unticked.** The tool asks for these read-only permissions: `Directory.Read.All`, `AuditLog.Read.All`, `UserAuthenticationMethod.Read.All`, `IdentityRiskyUser.Read.All`, `Policy.Read.All` (without the last one Microsoft hides which Conditional Access policy applied). Microsoft also accepts the narrower `Policy.Read.ConditionalAccess` for that, but the tool keeps to permissions whose names end in `.Read` or `.Read.All`, so anyone can see at a glance that it cannot change anything.

Other options:

| Option | What it does |
|---|---|
| `-TenantId contoso.onmicrosoft.com` | Sign in to this tenant. Recommended when you have access to many clients. |
| `-Days 30` | Read 30 days of sign-ins instead of 7 (1 to 30). |
| `-DisableWam` | Windows keeps picking your own work account? This signs in with a device code instead, so you choose the account. |
| `-UseDeviceCode` | Sign in with a device code (for example from a server without a browser). |
| `-OutputPath C:\Temp` | Also saves an HTML report and a one-row CSV named `M365UserCheck_<sign-in name>_<date>_<time>`. Without it, no report is written. |
| `-TicketNumber 482113` | Save the ticket note in the ticket's folder (and the HTML and CSV too, when `-OutputPath` is given). See [Ticket note](#ticket-note). |
| `-NoClipboard` | Do not copy the ticket note to the clipboard. |
| `-FullDetail` | Keep IP addresses and share paths in the ticket note (removed by default). The tool prints a warning to check the note before pasting it. |
| `-PassThru` / `-Quiet` | For scripts: return the result object instead of an exit code, and write nothing to the console. |
| `-Server dc01.contoso.local` | The domain controller to read the on-premises AD account from (from a workstation outside the client's domain, or for a user in another domain). |
| `-Credential (Get-Credential)` | An account that can read the client's AD. Used for Get-ADUser only, never written anywhere. |
| `-SkipOnPremises` | Do not look at on-premises AD at all. |

## How to read the answer

First comes the banner. **Check it before anything else**: it shows the tenant name, its default domain, the tenant ID, the account you are signed in as and its admin roles, and what this run could see:

```
 Microsoft 365 user check. This tool only reads: it changes nothing.
 Tenant      : Contoso Ltd   (default domain contoso.com)
 Tenant ID   : 11111111-2222-3333-4444-555555555555
 Signed in as: admin@contoso.com
 Admin roles : Global Administrator

What this run could see:
  Sign-in history: not available (this tenant has no Entra ID P1)
  Conditional Access detail: not available (sign-in history is not available)
  MFA methods: available
  Risky user: not available (needs Entra ID P2)
  On-premises AD: could not check (no domain controller answered (...). Run it on a domain-joined computer, or add -Server <domain controller> and -Credential)

Can Jane Doe sign in to Microsoft 365?  PROBABLY YES
  sign-in history not available (no Entra ID P1)
```

If the sign-in name's domain is not one of that tenant's domains, the tool stops with **"Wrong tenant?"** before looking anyone up.

| Answer | Meaning |
|---|---|
| **YES** | Nothing found that stops them, and the sign-in history was readable. If they still cannot get in, look at the device, the app, the network, or the on-premises account. |
| **NO** | At least one definite blocker: sign-in is blocked, their latest sign-in failed with a code that stops them (50053, 50055, 50057, 53003, 530035), the account is in AD but not in Microsoft 365, sync reports an error for it, or another object holds its address. |
| **PROBABLY NOT** | No licence, a licence that failed to apply, their latest sign-in failed with another code, AD has the account enabled while Microsoft 365 blocks it, or the account is in AD and Microsoft 365 could not be searched for its SID. |
| **PROBABLY YES** | Nothing blocking was found, but the sign-in history could not be read (no Entra ID P1, or your role cannot read it), or the search for another object holding the account's addresses failed. There is no evidence either way: the line under the answer says which. For sign-ins, look in the Entra admin center (Entra ID > Monitoring & health > Sign-in logs); a tenant without P1 keeps seven days of them. |

Under the answer: **Why not** (each with a "What to do" line), **Worth knowing** (warnings and information), **Looks fine**, **Could not check** (with the reason), a detail table, and the recent sign-ins.

## What each reason means

| You see | What it means | What to do |
|---|---|---|
| Sign-in is blocked | The account is blocked in Microsoft 365. | Synced user: check with the senior engineer before undoing it. The block comes from on-premises AD: either the AD account is disabled, or it was blocked on purpose with M365-SyncedUserFixes (the block marker). The tool tells you which when it can read AD; if it could not, run the check again where it can read AD (on a client server, or with `-Server` and `-Credential`) to see which kind of block it is. Cloud-only user: Check with their manager that the account should be back in use, note on the ticket who approved it, then unblock it in the Microsoft 365 admin center. |
| No licence is assigned | Apps such as Outlook and Teams will not let them in. | Assign the right licence, if they should have one. |
| A licence could not be applied | A licence is in the `Error` state, with Microsoft's error value (for example `CountViolation`). | Fix the assignment; the link in the reason explains each value. |
| Their latest sign-in failed with error N | Shows the code, Microsoft's own reason from the sign-in log, how many failed in a row, the time, the app, the Conditional Access policy that blocked it (when visible), and the link `https://login.microsoftonline.com/error?code=N`. | For 50053, 50055, 50057, 50126, 53003 and 530035 the tool gives a next step, and the reason marks it as based on Microsoft's documented meaning ("meaning per Microsoft, may change"). For any other code it shows only Microsoft's text and the lookup link. |
| Earlier failed sign-ins (info) | Older failures by code and count. Only the latest sign-in decides the answer. | Look one up if it keeps coming back. |
| No sign-in attempts reached Microsoft 365 (info) | Sign-in history was readable but empty for the window. | The problem is before Microsoft 365: the sign-in name, the device, the app or the network. |
| No MFA method registered (warning) | Only a password. | If the tenant requires MFA, help them set up Microsoft Authenticator. |
| ID Protection flags this user (warning) | Risk level and state from Entra ID P2. | Treat as possibly compromised; involve the security lead. |

## Is it a sync problem?

For a user synced from on-premises AD (and for a user who is in AD but not in Microsoft 365), the tool reads the AD account with `Get-ADUser` and compares. It finds the AD account by the on-premises security identifier (SID) Microsoft 365 holds for the user, and otherwise by sign-in name. For a cloud-only user it only searches AD for the sign-in name.

When no Microsoft 365 user has the name you typed but an AD account does, the tool first searches Microsoft 365 for that AD account's SID. A Microsoft 365 user that holds it (synced under another sign-in name) is the one checked, so you get its answer instead of "exists in AD but not in Microsoft 365".

| You see | What it means | What to do |
|---|---|---|
| This account exists in AD but not in Microsoft 365 | No Microsoft 365 user matched, not even by the AD account's SID, but an AD account has that sign-in name. It never synced, or no longer syncs. If Microsoft 365 could not be searched for the SID (or AD did not return the account's SID), the answer is PROBABLY NOT and "Microsoft 365 account by SID" is under Could not check. | Check the sync scope (is the account in an OU that Entra Connect synchronizes, or filtered out?) and the Entra Connect server. |
| ... removed from Microsoft 365 on purpose by M365-SyncedUserFixes | Same, but the AD account carries the block marker `msDS-cloudExtensionAttribute10 = BlockCloudSignIn`. | Check with the senior engineer before removing the marker with M365-SyncedUserFixes, even if they should have Microsoft 365 again: the old mailbox and licences may be gone. |
| Sync reports an error for this account | Microsoft 365 reports a provisioning error: the category (for example `PropertyConflict`), the property and its value. | Escalate to a senior engineer: another object already uses that value. Tell them the property and value shown. |
| The address ... is already held in Microsoft 365 by ... | Another user already has the AD account's sign-in name as its sign-in name, or a user, group or contact already has its primary email address as an email or proxy address. The reason names the type (a synced user, a cloud-only user, a group or a contact) and the display name. Another user whose sign-in name merely equals this account's email address is not a conflict. | Escalate to a senior engineer before removing the address or deleting anything (deleted groups and contacts can't be restored). |
| Address conflicts: ... (could not check) | One or more of the searches for another object holding the addresses failed (often a role that cannot read groups or contacts); the line names which. A conflict found by the searches that did answer is still shown and still gives NO; otherwise nothing is ruled out, and a YES becomes PROBABLY YES. | Run it again; if it keeps failing, search the addresses in the Microsoft 365 admin center. |
| Sign-in was blocked on purpose with M365-SyncedUserFixes (info) | Microsoft 365 blocks sign-in and the AD account carries the block marker. | Ask who blocked it and why. Check with the senior engineer who blocked it whether to remove the marker with M365-SyncedUserFixes. |
| AD and Microsoft 365 disagree | AD has the account enabled, Microsoft 365 blocks it, and there is no block marker. Shows when the tenant last synced. | Wait for the next sync if AD was changed after that; otherwise check the Entra Connect server. |
| AD has the account disabled, Microsoft 365 still allows sign-in (warning) | AD has the account disabled, but Microsoft 365 still lets them sign in. Shows when the tenant last synced. | Check with their manager whether they should still be able to sign in. If not (a leaver), Microsoft 365 blocks sign-in at the next sync; if it stays allowed after that, check the Entra Connect server. If they should, note on the ticket who approved it, then enable the AD account (AD-UserQuickCheck shows its state). |
| Microsoft 365 last received changes from on-premises AD N hours ago (warning) | The tenant's last sync is more than 3 hours old. Sync normally runs every 30 minutes. | Check the Entra Connect server: is the sync service running and the scheduler enabled? |
| The sign-in name differs (warning) | AD and Microsoft 365 have different sign-in names; both are shown. | They sign in with the Microsoft 365 one. Wait for the next sync if AD was changed recently. |
| AD account found by sign-in name, but its SID differs from the one Microsoft 365 holds (warning) | No AD account has the SID Microsoft 365 holds, but one has the sign-in name: probably a recreated account, not the one this Microsoft 365 account synced from. Both SIDs are shown. | Ask the senior engineer to check on the Entra Connect server which AD account it is joined to before changing either one. |
| Cloud-only account: sync is not involved (looks fine) | The user is not synced and no AD account has that sign-in name. | Nothing to do on the AD side. |
| On-premises AD: could not check (...) | The ActiveDirectory module is missing or no domain controller answered. Nothing about AD is ruled out. | Run it on a client server, or add `-Server` and `-Credential`. |

The tool never changes AD: it only runs `Get-ADUser`. The address lookups in Microsoft 365 are reads (GET) on users, groups and contacts.

## Ticket note

Every run ends with a short note on the clipboard (or printed, when there is no clipboard), ready to paste:

```
[Ticket note] M365-UserQuickCheck: Can Jane Doe sign in to Microsoft 365? PROBABLY YES - sign-in history not available (no Entra ID P1)

Checked:
- Microsoft 365 account jdoe@contoso.com in Contoso Ltd, sign-ins from the last 7 days.
Ruled out:
- Account is turned on in Microsoft 365 (not blocked).
- A licence is assigned and active.
- An MFA method is registered (microsoftAuthenticator).
Could not check:
- Sign-in history: this tenant has no Entra ID P1
- Conditional Access detail: sign-in history is not available
- Risky user: needs Entra ID P2
- On-premises AD: could not check (no domain controller answered (...))
Next step:
- Look at their recent sign-ins in the Microsoft Entra admin center (...)

Tenant: Contoso Ltd (contoso.com) | Ran by: CONTOSO\jtech on WS-114 (as admin@contoso.com) | 2026-10-17 09:30:12 (UTC+01:00) | Changed anything: No
Evidence: (none saved)
```

- **Ruled out** only lists checks the tool could really make. Without Entra ID P1, nothing about sign-ins is ever ruled out.
- The stamp names the tenant and the account you signed in as.
- IP addresses are removed from the note and the console by default (`-FullDetail` keeps them in the note). They are in the HTML report only, never in the CSV. CSV cells that start with `=`, `+`, `-` or `@` get a leading `'`, so a spreadsheet never runs a client-supplied name as a formula.
- **Where the files go:**

  | You give | Files written |
  |---|---|
  | `-TicketNumber 482113 -OutputPath C:\Temp` | HTML, CSV and note in `C:\Temp\Ticket_482113` |
  | `-TicketNumber 482113` | Only the note, in `%USERPROFILE%\Documents\TicketNotes\Ticket_482113`. No report: the HTML and CSV hold client data, so they are written only when you ask with `-OutputPath`. |
  | `-OutputPath C:\Temp` | HTML, CSV and note in `C:\Temp` |
  | neither | No files. The note goes to the clipboard (or is printed). |
- Ran several tools on the same ticket? `..\TicketNote\Join-TicketNotes.ps1 -TicketNumber 482113` joins their notes.
- The note is built by `CaseKit.ps1` in this folder. Keep it next to the script.

## Things worth knowing

- **Sign-in history is interactive sign-ins only** (what Microsoft's v1.0 sign-in API returns). Background sign-ins by apps are not included.
- **Sign-in history needs Entra ID P1** and one of these roles: Reports Reader, Security Reader, Security Operator, Security Administrator or Global Reader. The tool says which one is missing; the two give different reasons.
- **Conditional Access detail** (which policy blocked them) needs Global Reader, Security Reader, Security Administrator or Conditional Access Administrator. Without it the policy cannot be named, and nothing says Conditional Access was ruled out.
- **Risky user needs Entra ID P2.** Microsoft does not document which error a tenant without P2 returns, so a "not allowed" answer is reported as "needs Entra ID P2, or a role that can read it".
- **Guests** are checked like members and labelled; their home organization is not examined.
- The Graph session is opened for this PowerShell process only and closed at the end of every run. If your Graph module is too old to do that, the tool stops and asks you to update it (`Update-Module Microsoft.Graph.Authentication`) rather than leave the client's sign-in in your token cache.
- **Admin roles** in the banner include roles held through a group, not only roles assigned to the account directly.
- **Exit codes** (for scripts): `0` can sign in (YES or PROBABLY YES), `1` cannot or probably not, `2` no user matched (in Microsoft 365, and in AD or AD could not be checked) or the address matches several users (they are listed), `3` could not run (Graph module missing or too old, sign-in failed, the tenant's domains could not be read, wrong tenant, or a ticket number that does not fit).  A missing ActiveDirectory module or an unreachable domain controller never changes the exit code.

## What it does not check

- The on-premises AD account's own state: locked out, password expired, bad-password counts (run AD-UserQuickCheck)
- The Entra Connect server itself: OU scope, filtering rules, the scheduler and staging mode (the next steps point there)
- Cloud password expiry (use `Get-EntraPasswordPolicy`)
- Non-interactive and service-principal sign-ins
- The mailbox itself (use the [mailbox check](#mailbox-check-get-m365mailboxcheckps1))

## Mailbox check (Get-M365MailboxCheck.ps1)

**"Mail is going missing."** / **"Who can see this mailbox?"** / **"Is this mailbox compromised?"** One read-only report with what you would otherwise click through the Exchange admin center for, and a clear warning when anything looks like an account takeover.

It only reads. It never removes a rule, forwarding or permission, never resets a password, never blocks sign-in and never opens a message, whatever account you sign in with (also the client's Global Administrator). There are no switches that change anything.

### Before the first run

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

Version 3.7.0 or later is needed for the message trace (`Update-Module ExchangeOnlineManagement` if yours is older; the rest of the check works without it). Windows PowerShell 5.1 or PowerShell 7.

### The one command

```powershell
.\Get-M365MailboxCheck.ps1 -Identity accounts@contoso.com
```

A sign-in window opens: **sign in with an account in the client's tenant.** The check uses Exchange Online PowerShell only, so there is no Microsoft Graph permissions prompt. If a Microsoft prompt ever asks for consent, consent for yourself only and leave **"Consent on behalf of your organization"** unticked (owner decision D-007).

If an Exchange Online session is already open in the window, the tool uses it and leaves it open. Otherwise it signs in and, when it finishes, closes only the connection it opened (a Security & Compliance session you had open stays open). If more than one Exchange Online connection is open, the banner warns you: close the others or use a new window.

| Option | What it does |
|---|---|
| `-TraceDays 3` | Read 3 days of message trace instead of 7 (1 to 10; one Microsoft query covers at most 10 days). |
| `-NoTrace` | Skip the message trace. |
| `-RecentDays 30` | Search 30 days of the audit log for rule, forwarding and delegate changes instead of 14 (1 to 90). |
| `-NoRecentChanges` | Skip the audit log search (when it is too slow). The report then says **Recent changes: could not check (skipped)** and the verdict is **PARTLY CHECKED** at best. |
| `-OutputPath C:\Temp` | Save an HTML report and three CSVs (`_rules`, `_delegates`, `_trace`) named `MailboxCheck_<mailbox>_<date>_<time>`. **Rule conditions and message subjects are only in these files.** Without it no report is written. |
| `-TicketNumber 482113` | Save the ticket note in the ticket's folder (and the reports too, when `-OutputPath` is given). Same rules as the [ticket note](#ticket-note) above. |
| `-NoClipboard` / `-FullDetail` | As for the sign-in check. |
| `-PassThru` / `-Quiet` | For scripts: return the result object instead of an exit code, and write nothing to the console. |

### How to read it

First comes the banner with the tenant (its `.onmicrosoft.com` name and tenant ID) and the account you signed in as, **before any mailbox is read**. If it is the wrong client, press Ctrl+C.

Then the verdict, in one of three forms:

| You see | Meaning | What to do |
|---|---|---|
| **Possible account takeover: do NOT reset the password or delete the rule yet. Escalate.** | At least one takeover sign, each listed in plain English underneath (for example "Mail is forwarded to an outside address at gmail.com"). | **Don't touch anything.** Escalate, and check CIPP's BEC report for this user. Resetting the password or deleting the rule first destroys what the investigation needs. |
| **PARTLY CHECKED - no takeover signs in what could be read, but these could not be checked: ...** | Some sections could not be read; each is named with the reason and the role that can read it. | Nothing is ruled out. Run it again with an account that has the role, or look at those sections in the Exchange admin center. |
| **No takeover signs found in the checks below.** | Every section was read and none showed a sign. This wording only ever appears when nothing failed. | If mail still goes missing, look at the message trace in the report. |

The takeover signs are:

- **Mail forwarded outside the tenant**, by the mailbox's own forwarding or by an inbox rule (forward, forward as attachment, redirect). "Outside" means the address is not in one of the tenant's accepted domains; an accepted domain of type ExternalRelay counts as outside. A subdomain counts as inside only when it is itself an accepted domain or falls under a wildcard one (`*.contoso.com`); any other subdomain of an accepted domain cannot be judged, so a rule forwarding there is a sign and mailbox forwarding there is listed under **Could not check**. When the mailbox forwards to a recipient in the tenant (for example a mail contact), the tool looks up where that recipient delivers, so a contact pointing at gmail.com is a sign. A mail contact or mail user is judged only by its external address, never by its address in the tenant; one without an external address is listed under **Could not check**. The sign names the domain and whether a copy stays in the mailbox. If that recipient cannot be looked up, forwarding is listed under **Could not check**.
- **An inbox rule that forwards to a recipient the tool cannot classify** as inside or outside (for example a bare name). It is a sign until someone looks at it.
- **An inbox rule that deletes mail.**
- **An inbox rule that hides mail**: it moves mail to RSS Feeds, RSS Subscriptions, Conversation History, Deleted Items, Junk Email or Archive, or moves it anywhere and marks it read.
- **A recent change** (owner decision D-032): any inbox rule created or changed, forwarding turned on, or Full Access, Send As or Send on Behalf given in the last 14 days (`-RecentDays`), found in the Microsoft 365 audit log. The sign says when ("2 days ago") and whether it was done by the mailbox's own account or by another account, for example "Inbox rule 'xx' was created 2 days ago by the mailbox's own account. This rule no longer exists." A rule created and then deleted still counts: that is a known way to hide a takeover.
- **A hidden inbox rule** (one Exchange only lists when asked for hidden rules). The built-in junk-mail rule is hidden too; it is listed but is not a sign, as long as it does none of the things above (a rule with that name that forwards, deletes or moves mail is a sign). A rule Exchange returns without an identity is a sign too, because the tool cannot tell whether it is hidden.

A rule that is turned off still counts (someone made it); the sign says it is off.

Under the verdict come the facts: mailbox type (user, shared, room, equipment), forwarding, total size and the prohibit-send quota, archive on/off and its size, litigation hold and other holds (eDiscovery holds and retention policies are labelled), who has **Full Access**, **Send As** and **Send on Behalf**, every inbox rule (hidden ones marked), and the message trace (sent and received). The console shows rule actions but not their conditions, and trace rows without subjects; both are in the HTML and CSV report.

### Recent changes (the audit log)

The **Recent changes (last 14 days)** section lists, newest first, every inbox rule that was created or changed (in Outlook on the web, PowerShell or the Outlook client), forwarding that was turned on or off, and Full Access, Send As or Send on Behalf that was given. Each row has the time (this computer's local time, with UTC in brackets), what changed, who did it, whether that was the mailbox's own account, and the client IP and app when the audit record has them. Turning forwarding off is listed so you can see a clean-up, but it is not a sign. When nothing changed it says `No inbox rules, forwarding or mailbox access were added or changed in the last 14 days.`

- **It can take a minute or more** on a large tenant: the tool asks Microsoft for every rule, forwarding and permission change in the tenant for those days (up to 50,000 records) and picks out this mailbox's on your computer, so a change made with any form of the mailbox's name is found. Use a smaller `-RecentDays`, or `-NoRecentChanges` to skip it.
- **Changes from the last hour or two may not be there yet.** Microsoft says Exchange audit records are typically searchable 60 to 90 minutes after the change and does not promise a time. The section says so every time.
- **Recent changes: could not check** means the verdict is **PARTLY CHECKED** at best, never the all-clear. The reason is one of:
  - *your account needs the View-Only Audit Logs role in Exchange Online*: the audit search is not available to the account you signed in with (see the roles below);
  - *audit logging is turned off in this tenant*: nobody can search changes from while it was off. An admin with the Audit Logs role (the Organization Management or Compliance Management role group) can turn it on in the Microsoft Purview portal (Audit). This tool never turns it on; ask the client's admin or escalate;
  - *results were cut off*: more than 50,000 matching records in the window. Run it again with a smaller `-RecentDays`;
  - *could not tell whether audit logging is on*: the tenant's audit setting did not come back. The search still runs and anything it finds is still a sign, but finding nothing proves nothing;
  - *N audit record(s) could not be read*: some records came back damaged and were skipped. One of them could be the change you are looking for;
  - *skipped (-NoRecentChanges)*;
  - the error from the search itself (for example a timeout). When it fails part-way, the changes from the pages already read are still listed and still count as signs.
- **Rule changes made in Outlook: could not check** means mailbox auditing is turned off for the organization, or bypassed for this mailbox's account (or the tool could not tell). Rule changes made in the Outlook client are then not recorded; changes made by admins, in Outlook on the web or with PowerShell still are, and are still listed.

For pulling large amounts of audit data regularly, Microsoft recommends the Office 365 Management Activity API instead of `Search-UnifiedAuditLog`; this tool runs one bounded search per check, which is what the cmdlet is meant for.

### Roles it needs

From Microsoft Learn (cited in the scripts). Owner decision D-026: these are confirmed once against a real tenant with the Integration test before the tool goes into the bundle.

| Section | Exchange Online role group that can read it |
|---|---|
| Mailbox, forwarding, size, holds, Full Access, Send As | Recipient Management or Organization Management (View-Only Organization Management can view these) |
| Inbox rules | Recipient Management or Organization Management. **Global Reader and View-Only Organization Management cannot read inbox rules** (Microsoft says so on the Get-InboxRule page). |
| Message trace | Organization Management, Compliance Management or Help Desk; also Exchange Administrator or Global Administrator in Entra ID |
| Accepted domains | Organization Management (View-Only Organization Management can view them) |
| Recent changes (audit log) | **View-Only Audit Logs** or Audit Logs in Exchange Online (Microsoft: "To access audit cmdlets, you must be assigned the Audit Logs or View-Only Audit Logs roles in the Exchange admin center"). By default the Organization Management and Compliance Management role groups have them. Whether that role alone also reads the mailbox audit setting and audit bypass is confirmed by the Integration test (D-026); if it does not, **Rule changes made in Outlook** is listed under **Could not check**. |

Because inbox rules cannot be read with a read-only role, the account you use can change mailboxes. This tool never does: a test reads the script's own commands and fails if any of them could change something.

A section your role cannot read shows up under **Could not check** with the role named, and the verdict is **PARTLY CHECKED**, never the all-clear.

### Ticket note

Same four-part note as the sign-in check, written to the clipboard (and to the ticket folder with `-TicketNumber`). It carries the verdict, the sign kinds (for example `ExternalRuleForward`), rule names and the **outside domain only** (`gmail.com`, never the full address). A recent change is written as its kind, the date (UTC), the rule name, and "by the mailbox's own account" or "by another account": who did it, from which IP and app, and the delegate's name stay in the local report. The note names the checked mailbox, but never a forwarding, delegate or message-trace address. Rule conditions, delegate names and message-trace rows never go into the note (owner decision D-025); they stay in the local HTML and CSV. A section that could not be read is listed under **Could not check**, never under **Ruled out**, with a fixed reason (the role it needs, or "see the report"): the Exchange error text itself stays in the console and the HTML report. Rule names have line breaks and other control characters removed and are cut to 100 characters.

### Exit codes

`0` no takeover signs and every section read, `1` possible takeover, `2` partly checked, `3` could not run (module missing, sign-in failed, no mailbox found, or a ticket number that does not fit).

### Known limits

- Folders are recognised by their English names (`RSS Feeds`, `Deleted Items`, ...). In a mailbox with folders in another language a "hides mail" rule is listed but not flagged.
- The built-in junk-mail rule is recognised by its English name, `Junk E-mail Rule`. In another language it shows up as a hidden-rule sign: a false alarm, never a missed one.
- One message-trace query returns at most 5000 messages. When a direction hits that, the report says `results were cut off at 5000; rerun with a smaller -TraceDays`.

## Tests

```powershell
Invoke-Pester .\M365-UserQuickCheck\Tests
```

The tests fake Microsoft Graph, Exchange Online, Active Directory and the clipboard, so no tenant or domain is needed.

To confirm the mailbox check's roles against a real tenant (once, before bundling; D-026), sign in with an account that has only the roles listed above and run:

```powershell
$env:MAILBOXCHECK_IT_IDENTITY = 'someone@client.com'
Invoke-Pester .\M365-UserQuickCheck\Tests\MailboxCheck.Tests.ps1 -TagFilter Integration
```
