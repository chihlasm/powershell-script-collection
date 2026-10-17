# M365-UserQuickCheck

**"I can't sign in to Outlook / Teams."** Run this while the user is waiting. It tells you, in plain English, whether their Microsoft 365 account can sign in, and if not, why and what to do next.

It only reads. It never unblocks, resets, assigns licences or changes anything, even when you sign in as the client's Global Administrator: every request is a read (GET) and every permission it asks for is a read-only permission.

## When to use it

- A user cannot get into Outlook, Teams, OneDrive or the Microsoft 365 portal.
- You want Microsoft's own reason for a failed sign-in (the error code and its text) without opening the Entra admin center.
- You want something to paste into the ticket: the [ticket note](#ticket-note) is on your clipboard after every run.

- The user syncs from on-premises AD and you want to know whether it is a sync problem (see [Is it a sync problem?](#is-it-a-sync-problem)).

For the on-premises account's own state (locked out, password expired in AD), use [AD-UserQuickCheck](../AD-UserQuickCheck/).

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
| **PROBABLY NOT** | No licence, a licence that failed to apply, their latest sign-in failed with another code, or AD has the account enabled while Microsoft 365 blocks it. |
| **PROBABLY YES** | Nothing blocking was found, but the sign-in history could not be read (no Entra ID P1, or your role cannot read it). There is no evidence either way: look at their sign-ins in the Entra admin center (Entra ID > Monitoring & health > Sign-in logs). A tenant without P1 keeps seven days of them. |

Under the answer: **Why not** (each with a "What to do" line), **Worth knowing** (warnings and information), **Looks fine**, **Could not check** (with the reason), a detail table, and the recent sign-ins.

## What each reason means

| You see | What it means | What to do |
|---|---|---|
| Sign-in is blocked | The account is blocked in Microsoft 365. | Synced user: the block comes from on-premises AD (a disabled account, or the M365-SyncedUserFixes block marker). Cloud-only user: unblock it in the Microsoft 365 admin center if it should be in use. |
| No licence is assigned | Apps such as Outlook and Teams will not let them in. | Assign the right licence, if they should have one. |
| A licence could not be applied | A licence is in the `Error` state, with Microsoft's error value (for example `CountViolation`). | Fix the assignment; the link in the reason explains each value. |
| Their latest sign-in failed with error N | Shows the code, Microsoft's own reason from the sign-in log, how many failed in a row, the time, the app, the Conditional Access policy that blocked it (when visible), and the link `https://login.microsoftonline.com/error?code=N`. | For 50053, 50055, 50057, 50126, 53003 and 530035 the tool gives a next step, marked "meaning per Microsoft, may change". For any other code it shows only Microsoft's text and the lookup link. |
| Earlier failed sign-ins (info) | Older failures by code and count. Only the latest sign-in decides the answer. | Look one up if it keeps coming back. |
| No sign-in attempts reached Microsoft 365 (info) | Sign-in history was readable but empty for the window. | The problem is before Microsoft 365: the sign-in name, the device, the app or the network. |
| No MFA method registered (warning) | Only a password. | If the tenant requires MFA, help them set up Microsoft Authenticator. |
| ID Protection flags this user (warning) | Risk level and state from Entra ID P2. | Treat as possibly compromised; involve the security lead. |

## Is it a sync problem?

For a user synced from on-premises AD (and for a user who is in AD but not in Microsoft 365), the tool reads the AD account with `Get-ADUser` and compares. It finds the AD account by the on-premises security identifier (SID) Microsoft 365 holds for the user, and otherwise by sign-in name. For a cloud-only user it only searches AD for the sign-in name.

| You see | What it means | What to do |
|---|---|---|
| This account exists in AD but not in Microsoft 365 | No Microsoft 365 user matched, but an AD account has that sign-in name. It never synced, or no longer syncs. | Check the sync scope (is the account in an OU that Entra Connect synchronizes, or filtered out?) and the Entra Connect server. |
| ... removed from Microsoft 365 on purpose by M365-SyncedUserFixes | Same, but the AD account carries the block marker `msDS-cloudExtensionAttribute10 = BlockCloudSignIn`. | Remove the marker with M365-SyncedUserFixes only if they should have Microsoft 365 again; the old mailbox and licences may be gone. |
| Sync reports an error for this account | Microsoft 365 reports a provisioning error: the category (for example `PropertyConflict`), the property and its value. | Another object uses that value. Remove it from the wrong object, then wait for the next sync. |
| The address ... is already held in Microsoft 365 by ... | A cloud-only user, a group or a contact already has the AD account's sign-in name or primary email address. The reason names the type and the display name. | Remove the address from that object (or delete a leftover copy), then wait for the next sync. |
| Sign-in was blocked on purpose with M365-SyncedUserFixes (info) | Microsoft 365 blocks sign-in and the AD account carries the block marker. | Ask who blocked it and why. If it is wrong, remove the marker with M365-SyncedUserFixes. |
| AD and Microsoft 365 disagree | AD has the account enabled, Microsoft 365 blocks it, and there is no block marker. Shows when the tenant last synced. | Wait for the next sync if AD was changed after that; otherwise check the Entra Connect server. |
| Microsoft 365 last received changes from on-premises AD N hours ago (warning) | The tenant's last sync is more than 3 hours old. Sync normally runs every 30 minutes. | Check the Entra Connect server: is the sync service running and the scheduler enabled? |
| The sign-in name differs (warning) | AD and Microsoft 365 have different sign-in names; both are shown. | They sign in with the Microsoft 365 one. Wait for the next sync if AD was changed recently. |
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
- The mailbox itself

## Tests

```powershell
Invoke-Pester .\M365-UserQuickCheck\Tests
```

The tests fake Microsoft Graph, Active Directory and the clipboard, so no tenant or domain is needed.
