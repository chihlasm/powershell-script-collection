# Service Desk Escalation Toolkit — START HERE

A small set of tested PowerShell tools for the escalation tickets we see most: account
lockouts, "who has access to what", missing mapped drives, slow or broken Citrix/RDS sessions, FSLogix profile
problems, hiding people from the address book, and blocking Microsoft 365 sign-in.

Every tool writes a report (HTML and/or CSV) you can attach to the ticket.

---

## Which tool do I run?

| The ticket says...                                                  | Go to                                                        | Changes anything? |
|---------------------------------------------------------------------|--------------------------------------------------------------|-------------------|
| "My account keeps locking out"                                      | [AD-LockoutDiagnostics](#account-keeps-locking-out)          | No                |
| "Who has access to what?" / "Who is in Domain Admins?" / offboarding check | [AD-GroupMembership-Export](#who-has-access-to-what)  | No                |
| "My H: / S: / X: drive is missing" (or only shows up sometimes)     | [DriveMap-Diagnostics](#mapped-drive-is-missing)             | No                |
| "Citrix is slow" — for one server or the whole farm                 | [Citrix-FSLogix-HealthCollector](#citrix-or-rds-is-slow)     | No                |
| "Which Citrix servers are overloaded / low on disk?"                | [Get-CitrixVDAResources](#citrix-or-rds-is-slow)             | No                |
| "The server's memory is maxed out — who is using it?"               | [Get-RAM-Usage](#server-memory-is-high--who-is-using-it)      | No                |
| "My profile didn't load" / "temp profile" / "I got logged straight back out" | [RDS-FSLogix-EventExport](#profile-or-logon-problems-on-citrix-or-rds) | No                |
| "Hide this person from the address book (GAL)"                      | [HideFromGal](#hide-someone-from-the-address-book)           | **Yes — AD**      |
| "Block this user from Microsoft 365 but keep their PC login"        | [Block 365 Sign-in](#block-someone-from-microsoft-365)       | **Yes — AD**      |
| Not sure yet / want everything on one case page                     | [MSP-TroubleshootingWorkbench](#not-sure-where-to-start)     | No                |

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

**Folder:** `RDS-FSLogix-EventExport`

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

**Folder:** `HideFromGal`  **This changes AD.**

Double-click **`Launch-HideFromGAL.vbs`** (not the `.ps1`). Find the person, tick them, hide.

**Things to know:**
- **Read the coloured banner at the top first.**
  - 🟢 Green: good to go.
  - 🔴 Red: the Entra Connect rule that does the actual hiding is missing, so hiding won't work. Escalate.
  - 🟡 Yellow: the tool couldn't check. Hiding still works, but you get no confirmation.
- Run it **on the Entra Connect server** if you can. That's the only place the banner can
  confirm the rule properly.
- Changes take effect after the next sync. Outlook's offline address book can take **up to
  24 hours** to catch up, so tell the customer that.
- **Don't run `HideFromGal-RuleBuilder.ps1`.** That's a one-time setup step for a senior engineer.

---

## Block someone from Microsoft 365

**Folder:** `Block 365 Sign-in`  **This changes AD.**

Blocks Microsoft 365 sign-in while leaving the user's PC login and file shares working.
Common for leavers on their last day, or for a compromised cloud account.

Double-click **`Launch-CloudSignInMgr.vbs`**. Find the person, tick them, click
**Block cloud sign-in**, and let it run a sync when asked.

**Things to know:**
- **Read the banner before blocking anyone.** It tells you which kind of rule the client uses:
  - `accountEnabled`: the account is disabled in the cloud. **Licenses and mailbox are kept.**
  - `cloudFiltered`: the cloud account is **deleted**, and **the mailbox and licenses go with it.**
    If the banner says this and the ticket only asked for a temporary block, stop and check with
    a senior engineer.
- **Never run `Block365SignIn-RuleBuilder.ps1`** unless a senior engineer tells you to. On a client
  that already has a rule, it creates a second one that deletes cloud accounts.
- **Restore cloud sign-in** always works, whatever the banner says.
- Run it on the Entra Connect server if you can (same reason as HideFromGal above).

---

## Not sure where to start

**Folder:** `MSP-TroubleshootingWorkbench`

A browser-based case page: create a case for the ticket, run checks (network, account
lockout, Citrix/FSLogix), add your notes, then click **Generate Notes** for ready-to-paste
ticket notes.

```powershell
.\Start-MSPTroubleshootingWorkbench.ps1
```

(Or double-click `MSPWorkbench.exe`. If Windows SmartScreen blocks it, use the `.ps1`.)

It opens at `http://localhost:8275/`. Press **Ctrl+C** in the PowerShell window to stop it.
Every check it runs is read-only. It uses the `AD-LockoutDiagnostics` and
`Citrix-FSLogix-HealthCollector` folders next to it, so keep the toolkit together.

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
