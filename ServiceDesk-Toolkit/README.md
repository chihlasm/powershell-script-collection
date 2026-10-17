# Service Desk Escalation Toolkit — START HERE

A small set of tested PowerShell tools for the escalation tickets we see most: account
lockouts, "who has access to what", missing mapped drives, slow or broken Citrix/RDS sessions, FSLogix profile
problems, hiding people from the address book, and blocking Microsoft 365 sign-in.

Every tool writes a report (HTML and/or CSV) you can attach to the ticket.

---

## Which tool do I run?

| The ticket says...                                                  | Go to                                                        | Changes anything? |
|---------------------------------------------------------------------|--------------------------------------------------------------|-------------------|
| "I can't sign in" / "Is my account OK?" (start here)               | [AD-UserQuickCheck](#cant-sign-in)                           | No                |
| "I can't sign in to Microsoft 365 / Outlook / Teams"                | [M365-UserQuickCheck](#cant-sign-in-to-microsoft-365)        | No                |
| "My account keeps locking out"                                      | [AD-LockoutDiagnostics](#account-keeps-locking-out)          | No                |
| "Who has access to what?" / "Who is in Domain Admins?" / offboarding check | [AD-GroupMembership-Export](#who-has-access-to-what)  | No                |
| "My H: / S: / X: drive is missing" (or only shows up sometimes)     | [DriveMap-Diagnostics](#mapped-drive-is-missing)             | No                |
| "Citrix is slow" — for one server or the whole farm                 | [Citrix-FSLogix-HealthCollector](#citrix-or-rds-is-slow)     | No                |
| "Which Citrix servers are overloaded / low on disk?"                | [Get-CitrixVDAResources](#citrix-or-rds-is-slow)             | No                |
| "The server's memory is maxed out — who is using it?"               | [Get-RAM-Usage](#server-memory-is-high--who-is-using-it)      | No                |
| "My profile didn't load" / "temp profile" / "I got logged straight back out" | [Citrix-FSLogix-Triage](#profile-or-logon-problems-on-citrix-or-rds), then [RDS-FSLogix-EventExport](#profile-or-logon-problems-on-citrix-or-rds) | No                |
| "I can't reach the server" / "the app won't connect" / "is port 445 open?" | [Network-QuickCheck](#cant-reach-a-server-or-app)            | No                |
| "Hide this person from the address book (GAL)"                      | [M365-SyncedUserFixes](#hide-someone-from-the-address-book)  | **Yes — AD**      |
| "Block this user from Microsoft 365 but keep their PC login"        | [M365-SyncedUserFixes](#block-someone-from-microsoft-365)    | **Yes — AD**      |
| Ran several checks on one ticket and want one note to paste         | [TicketNote](#one-note-for-the-whole-ticket)                 | No                |

Each folder has its own `README.md` with the full detail. This page covers when to use
each tool and the one command to start with.

---

## One-time setup (do this before your first run)

1. **Copy the whole `ServiceDesk-Toolkit` folder to your own machine**, e.g. `C:\Tools\ServiceDesk-Toolkit`.
   Do not run the tools straight out of a synced SharePoint/OneDrive folder. Several of them
   write reports *next to the scripts*, which would sync client data back to SharePoint.
   Keep the folder names as they are. Some tools look for each other by folder name.

2. **Unblock the files.** Files downloaded from SharePoint are marked "from the internet",
   and PowerShell will refuse to run them. Open PowerShell and run:

   ```powershell
   Get-ChildItem 'C:\Tools\ServiceDesk-Toolkit' -Recurse | Unblock-File
   ```

3. **Use Windows PowerShell 5.1, run as Administrator.** Right-click
   *Windows PowerShell* → *Run as administrator*. (PowerShell 7 works for most tools, but
   5.1 is what they're built and tested on.)

4. **Install RSAT Active Directory tools** if you haven't already. The lockout, drive-map,
   GAL and M365 tools all need them:

   ```powershell
   # Windows 10/11
   Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
   Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
   ```

   These download from Windows Update. If your machine gets updates from WSUS and the install
   fails, use *Settings → System → Optional features → Add a feature* and search "RSAT" instead.
   ([Microsoft: RSAT for Windows](https://learn.microsoft.com/troubleshoot/windows-server/system-management-components/remote-server-administration-tools),
   [Features on Demand capability names](https://learn.microsoft.com/windows-hardware/manufacture/desktop/features-on-demand-non-language-fod))

5. `cd` into the tool's folder before running it. All examples below assume you're in that folder.

---

## Can't sign in

**Folder:** `AD-UserQuickCheck`  **Run from:** any domain-joined machine with RSAT (Active
Directory). Administrator rights are **not** needed. It only reads; it changes nothing.

Run this first for any "I can't log in" ticket. It answers **"Can this person sign in right
now?"** with a YES or NO, gives the reason in plain English, and tells you what to do next:

```powershell
.\Get-ADUserQuickCheck.ps1 -Identity jdoe
```

It checks whether the account is disabled, locked out (and when it unlocks by itself),
expired, or has an expired password or one that must be changed. It also shows the last
sign-in across every domain controller, and any restrictions on which computers or hours the
person can sign in.

Add `-OutputPath C:\Temp` to save an HTML report you can attach to the ticket.

When it finishes, a **ticket note** is on your clipboard, ready to paste into the ticket:
what was checked, what is ruled out, what it could not check, and the next step. Add
`-TicketNumber 482113` to save the report and the note in that ticket's folder
(`Documents\TicketNotes\Ticket_482113`). See [One note for the whole ticket](#one-note-for-the-whole-ticket).

**Things to know:**
- If it says the account is **locked out** and the user keeps getting locked again, go to
  [Account keeps locking out](#account-keeps-locking-out) to find the device causing it.
- It checks the **on-premises** account only. A user who can sign in to their PC but not to
  Microsoft 365 needs the cloud-side check: see
  [Can't sign in to Microsoft 365](#cant-sign-in-to-microsoft-365).
- If it warns that it **couldn't reach a domain controller**, the last-sign-in and
  bad-password numbers may be incomplete. Don't treat them as final.

---

## Can't sign in to Microsoft 365

**Folder:** `M365-UserQuickCheck`  **Run from:** your own workstation (or a client server) with
the `Microsoft.Graph.Authentication` module. It only reads; it changes nothing, even when you
sign in as the client's Global Administrator. Install the module once with
`Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`.

Run this when Outlook, Teams or the Microsoft 365 portal will not let someone in. It answers
**"Can this person sign in to Microsoft 365?"** with the reason in plain English and what to
do next:

```powershell
.\Get-M365UserQuickCheck.ps1 -UserPrincipalName jdoe@contoso.com -TenantId contoso.onmicrosoft.com
```

A browser window opens: **sign in to the client's tenant**. At the permissions prompt, consent
for yourself only and **leave "Consent on behalf of your organization" unticked**.

Before the answer it prints which tenant and account you are signed in as. **Check that it is
the right client.** If the sign-in name's domain does not belong to that tenant, it stops with
"Wrong tenant?" instead of guessing.

It checks whether sign-in is blocked, whether a licence is assigned and working, the user's
latest sign-in (the error code, Microsoft's own reason, and which Conditional Access policy
blocked it), MFA methods, and whether ID Protection flags the user as risky.

For a synced user it also asks **"is it a sync problem?"**: does the on-premises AD account
agree, did sync report an error, does another user, group or contact already hold their
address, has sync run in the last 3 hours, and was the account blocked on purpose with
M365-SyncedUserFixes. If the user is not in Microsoft 365 at all but is in AD, it says so
("exists in AD but not in Microsoft 365"). This part needs RSAT and a domain controller: run
it on a client server, or add `-Server <domain controller> -Credential <client admin>`.
Without them the answer still comes, with "On-premises AD: could not check".

Add `-TicketNumber 482113` to save the [ticket note](#one-note-for-the-whole-ticket) in the
ticket's folder, and `-OutputPath C:\Temp` to also save an HTML report and a CSV (with both, all
three go into `C:\Temp\Ticket_482113`). Without `-OutputPath` no report is written.

**Things to know:**
- **PROBABLY YES** means nothing blocking was found, but the tenant has no Entra ID P1, so
  Microsoft does not let tools read sign-in history. Look at the user's sign-ins in the Entra
  admin center (it keeps seven days of them). This is normal for about half of our clients.
- Anything listed under **Could not check** was not checked, so it is not ruled out.
- If Windows signs you in with your own work account instead of the client's, run it again
  with `-DisableWam` (it then uses a device code, where you choose the account).
- It compares the AD account with Microsoft 365 but does not check its state in depth (locked
  out, password expired). For a synced user who is blocked, run
  [AD-UserQuickCheck](#cant-sign-in) too.

---

## Account keeps locking out

**Folder:** `AD-LockoutDiagnostics`  **Run from:** a domain-joined machine with RSAT, as an
account that can read the domain controllers' Security logs.

**Start with the menu.** You don't need the account name yet:

```powershell
.\Start-LockoutWorkbench.ps1
```

It scans the domain, lists who has been locking out, and lets you pick one. It then runs the
full investigation and saves a case folder with a `SUMMARY.txt` you can attach to the ticket.

If you already know the account:

```powershell
.\Invoke-ADLockoutInvestigation.ps1 -Identity jdoe
```

If the account syncs to Microsoft 365 (most do), name the Entra Connect server so cloud-side
causes are checked too:

```powershell
.\Invoke-ADLockoutInvestigation.ps1 -Identity jdoe -EntraConnectServer AADCONNECT01
```

**While you're on the phone with the user**, watch the bad-password count live on every DC
(read-only; press Ctrl+C to stop):

```powershell
.\Watch-ADLockoutActivity.ps1 -Identity jdoe
```

**Things to know:**
- If it says **STOPPING** because the DCs aren't logging lockout events, that's a real finding,
  not a bug. It means the domain can't tell us who is causing the lockouts. Put that in the
  ticket and escalate the audit-policy fix. `-Force` collects anyway if you need something today.
- **An empty report does not mean "nothing is wrong."** Run `.\Test-ADAuditPolicy.ps1` before
  closing a ticket on an empty result.
- `Set-DCSecurityLogRetention.ps1` only reports unless you add `-Apply`. **Don't use
  `-Apply`** without a senior engineer's OK, because it changes domain controller settings.

---

## Who has access to what

**Folder:** `AD-GroupMembership-Export`  **Run from:** any domain-joined machine with RSAT
(Active Directory). Administrator rights are **not** needed, and it works on Windows Server
2012 and newer.

Double-click **`Run-AccessReport.bat`** and pick from the menu:

- **1** for everyone and every group (best if you are not sure)
- **2** for named groups, e.g. `Domain Admins, HR-*`
- **3** for one department or area

When it finishes, it packages everything into one `.zip` in `C:\ADReports` and opens File
Explorer with that file selected. Attach it to the ticket. Open the `.html` file in it to
read the report. It has four tabs: **People**, **Groups**, **Overlap** and **Nesting**.

**Things to know:**
- **DUPLICATE ×2** next to a group means the person gets that group in two ways. Removing
  them from one group does **not** remove the access.
- **Disabled accounts are left out.** A leaver whose account is already disabled won't appear,
  but that does not mean their groups were removed.
- It shows group membership, **not** folder or file-share permissions.
- **New to it?** Read `AD Access Report - Quick Guide.docx` (one page) or the illustrated
  `AD Access Report - User Guide.docx` in the folder.

---

## Mapped drive is missing

**Folder:** `DriveMap-Diagnostics`  **Run from:** a domain-joined machine with RSAT (Active
Directory + Group Policy).

You need three things from the ticket: the **username**, the **computer** they log on to, and
the **drive letter**.

```powershell
.\Invoke-DriveMapInvestigation.ps1 -Identity jsmith -ComputerName WS01 -DriveLetter X
```

You get a case folder with a plain-English verdict and an HTML report.

**Things to know:**
- **Citrix/RDS users:** `-ComputerName` must be the **Citrix/RDS server the user is logged on
  to** (look it up in Citrix Director or Studio), not their own laptop and not a domain controller.
- **"Drive shows up every other logon"** is a known Windows behaviour that the tool
  **cannot confirm automatically**. A "No cause identified" result does not rule it out. See
  *"If the drive disappears on some logons but not others"* in the folder README.
- If it says the machine is **BLIND**, Group Policy logging is off on that PC. `-Force`
  collects anyway; the README explains how to turn logging on.
- Can't reach the PC remotely? Have someone run `.\Export-DriveMapEvidence.ps1` locally on it,
  then pass the folder it creates with `-EvidencePath` (see the folder README).

**Also in this folder, runnable on their own:**
- `Audit-GPDriveMaps.ps1` lists **every** drive map in the domain, with conflicts and dead
  server paths. Useful for "what drives *should* people get?" See `README-Audit-GPDriveMaps.md`.
- `Search-SYSVOLScripts.ps1` searches logon scripts for text, e.g. `-SearchPattern "net use"`.
  See `README-Search-SYSVOLScripts.md`.
- `Watch-DriveMapActivity.ps1 -Install` **installs a monitoring task** on the target, so check
  with a senior engineer before using `-Install`.

---

## Citrix or RDS is slow

**For slowness and errors (performance and event logs together):**
`Citrix-FSLogix-HealthCollector`

```powershell
# Every Citrix server in the site
.\Get-CitrixFSLogixHealth.ps1 -DeliveryController DDC01

# Specific servers (RDS, file servers, anything; no Citrix needed)
.\Get-CitrixFSLogixHealth.ps1 -ComputerName RDS01, RDS02, FS01
```

You get one verdict per machine (Healthy / Degraded / Critical / Unreachable) with the reasons
in plain English. By default it samples performance for 30 seconds per machine, so a big
farm takes a while. Add `-SampleSeconds 0` for a quick first look.

**For "which servers are running out of CPU, memory or disk right now":**
`Get-CitrixVDAResources`

```powershell
.\Get-CitrixVDAResources.ps1 -DeliveryController DDC01
```

This one runs faster and covers the whole farm. It sorts the worst machines to the top. Run it
first to find the bad server, then use the Health Collector on that server.

**Both need:** the Citrix PowerShell SDK (run them on a Delivery Controller, or a machine with
Citrix Studio installed), plus admin rights on the servers. `-ComputerName` on the Health
Collector doesn't need Citrix at all.

---

## Server memory is high — who is using it?

**Folder:** `Get-RAM-Usage`  **Run from:** Windows PowerShell **as Administrator** (it won't
work otherwise).

Ranks every logged-on user by how much RAM they're using, and shows which programs are using it.
Use it when one of the Citrix tools above flags a server for memory, or when a user says
"it's slow for everyone on this server."

```powershell
# The server you're logged on to
.\Get-RAMUsage.ps1

# Other servers, report saved to a folder
.\Get-RAMUsage.ps1 -ComputerName CTXVDA01, CTXVDA02 -OutputPath C:\Reports
```

**Things to know:**
- If the heavy memory isn't going to users, add `-IncludeSystemProcesses` to break down the
  service accounts too: antivirus, Citrix services, and so on.
- It **only reports.** Don't end anyone's programs based on it without talking to the user first.
- Checking other servers needs WinRM (PowerShell remoting) on them.

---

## Profile or logon problems on Citrix or RDS

**Start with:** `Citrix-FSLogix-Triage`

Checks the server the user signs in to and tells you in plain English whether FSLogix is
healthy there: services running, profiles switched on, the profile share setting correct and
reachable, recent FSLogix errors, and free disk space. Every finding comes with a "What to do".

```powershell
.\Invoke-CitrixFSLogixTriage.ps1 -ComputerName CTXVDA01 -UserName jdoe

# Save a text report you can paste into the ticket
.\Invoke-CitrixFSLogixTriage.ps1 -ComputerName CTXVDA01 -UserName jdoe -OutputPath C:\Temp
```

If it says **LOOKS HEALTHY**, the problem is more likely the user's own profile disk. Escalate
with the report.

**Then, for the detail:** `RDS-FSLogix-EventExport`

Pulls the Remote Desktop and FSLogix event-log errors for a time window into one report.
Use it when the user gets a temporary profile, a "profile failed to attach" error, or is
logged straight back out.

```powershell
# Last 4 hours on the server the user was on
.\Export-RDSFSLogixEvents.ps1 -ComputerName CTXVDA01 -LastHours 4

# Several servers into one report
.\Export-RDSFSLogixEvents.ps1 -ComputerName CTXVDA01, CTXVDA02, CTXVDA03 -LastHours 8
```

Ask the user roughly **when** it happened and set the window to cover it. Add
`-IncludeSecurity` to include logon/unlock events (needs admin).

---

## Hide someone from the address book

**Folder:** `M365-SyncedUserFixes`  **This changes AD.**

For accounts that come from AD, where the Microsoft 365 admin center won't let you hide them.
Double-click **`Start M365 Synced User Fixes.cmd`** and choose **Hide from address book** (or use
`Launch-HideFromGAL.cmd`, which opens that page directly). Find the person, tick them, click **Hide**.

**Things to know:**
- **Read the coloured card at the top first.**
  - Green: good to go.
  - Red: the Entra Connect rule that does the actual hiding is missing, so hiding is switched off. Escalate.
  - Amber: the tool couldn't check. Hiding still works, but you get no confirmation.
- Run it **on the Entra Connect server** if you can. That's the only place the card can
  confirm the rule properly.
- Changes take effect after the next sync. Outlook's offline address book can take **up to
  24 hours** to catch up, so tell the customer that.
- **Leave "Set up sync rules" to a senior engineer.** It builds Entra Connect rules.

---

## Block someone from Microsoft 365

**Folder:** `M365-SyncedUserFixes`  **This changes AD.**

Blocks Microsoft 365 sign-in while leaving the user's PC login and file shares working.
Common for leavers on their last day, or for a compromised cloud account.

Double-click **`Start M365 Synced User Fixes.cmd`** (it opens on **Block Microsoft 365 sign-in**).
Find the person, tick them, click **Block sign-in**, and let it run a sync when asked.

**Things to know:**
- **Read the card before blocking anyone.** It says what blocking does at this client:
  - "disables the Microsoft 365 account": **licences and mailbox are kept.**
  - A red line saying blocking **DELETES** the person: the mailbox and licences go too.
    If the ticket only asked for a temporary block, stop and check with a senior engineer.
- People already signed in can stay signed in until their session ends. For an immediate
  cut-off, also revoke their sessions in the Entra admin center.
- **Restore sign-in** always works, whatever the card says.
- Every change is logged in the tool's `Logs` folder.
---

## Can't reach a server or app

**Folder:** `Network-QuickCheck`

Run it **on the computer that has the problem**. It answers "can this computer reach that
server on that port?" with YES / PARTLY / NO, and checks the name lookup, ping, each port
and the default gateway.

```powershell
# File shares (a mapped drive won't connect)
.\Invoke-NetworkQuickCheck.ps1 -TargetAddress FILESRV01 -Port 445

# Several ports at once, with a report for the ticket
.\Invoke-NetworkQuickCheck.ps1 -TargetAddress rds.contoso.com -Port 443,3389 -OutputPath C:\Temp
```

Common ports: **445** file shares, **3389** Remote Desktop, **443** websites and most cloud
apps, **1494 / 2598** Citrix, **1433** SQL Server. A failed **ping** on its own is usually
fine, because many servers block it. A failed **port** is what matters.

---

## One note for the whole ticket

**Folder:** `TicketNote`  It only writes one text file in the ticket folder; it changes nothing.

Run the quick checks with the same `-TicketNumber`, then join their notes:

```powershell
..\AD-UserQuickCheck\Get-ADUserQuickCheck.ps1 -Identity jdoe -TicketNumber 482113
.\Join-TicketNotes.ps1 -TicketNumber 482113
```

It asks "What did the user report?" and "What did you already try by hand?" (press Enter to
skip), then saves `TicketNotes_Combined_<date>_<time>.txt` in
`Documents\TicketNotes\Ticket_482113` and copies it to the clipboard.

**Things to know:**
- Read **Could not check** before closing the ticket. Those checks did not happen, so they
  are not ruled out.
- IP addresses and share paths are removed from the note by default, so it is safe to paste.
  Add `-FullDetail` to the tool to keep them.
- Add `-NoClipboard` to leave your clipboard alone.

---

## When something goes wrong with the tool itself

| You see | Do this |
|---|---|
| "...cannot be loaded because running scripts is disabled" / "not digitally signed" | You skipped [Unblock-File](#one-time-setup-do-this-before-your-first-run), or run `Set-ExecutionPolicy -Scope Process Bypass` in that window |
| "The term 'Get-ADUser' is not recognized" / ActiveDirectory module missing | Install RSAT (setup step 4) |
| "Access is denied" against a server | Run PowerShell as Administrator, and use an account with admin rights on that server |
| Citrix tools say the Broker SDK isn't found | Run from a Delivery Controller, or a machine with Citrix Studio installed |
| A report comes back **empty** | Don't assume "all clear." Read the tool's warnings: most of these tools tell you when they *couldn't look* rather than *found nothing*. |
| Anything else | Send the console output and the report folder to whoever owns the toolkit |
