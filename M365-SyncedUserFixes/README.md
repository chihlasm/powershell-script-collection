# M365-SyncedUserFixes

**For Microsoft 365 jobs the admin center won't let you do because the account comes from
Active Directory.** The admin center says *"This user is synchronized with your on-premises
directory"* and greys the option out. This tool makes the change in AD instead and lets Entra
Connect carry it to Microsoft 365.

| You need to... | Section |
|---|---|
| Stop a leaver or a compromised account signing in to Outlook, Teams and Microsoft 365, but keep their PC login | **Block Microsoft 365 sign-in** |
| Remove someone from the Outlook address book (GAL), such as a leaver, shared mailbox or service account | **Hide from address book** |
| Check or build the Entra Connect rules that make both of the above work (sysadmins) | **Set up sync rules** |

## Start it

Double-click **`Start M365 Synced User Fixes.cmd`**.

- Find a person by name, username or email, tick them (click anywhere on the row), then press
  the button at the bottom right.
- When asked, let it run a sync. The change then reaches Microsoft 365 in a few minutes,
  instead of up to 30.
- **Read the coloured card at the top first.** It tells you whether the Entra Connect rule is
  in place (green), missing (red) or could not be checked (amber).

`Launch-CloudSignInMgr.cmd` and `Launch-HideFromGAL.cmd` open the same window straight on
the Block or Hide page, for anyone used to the old tools.

## What the card at the top means

| Card | Meaning | What happens |
|---|---|---|
| Green: **Sync rule in place** | The Entra Connect rule exists and reads this tool's marker | Normal. The card says what the rule does on this server |
| Red: **Sync rule NOT FOUND** / **is broken** | Checked, and nothing is enforcing the fix | Block / Hide is switched off: it would look like it worked while changing nothing. Press **Open sync rules** |
| Amber: **Could not check the sync rule** | The check itself could not run (usually because the tool is not running on the Entra Connect server) | Everything still works; the card says why it could not check |

**Restore sign-in** and **Show again** are never switched off.

On the Block page, read the card's last line. If it says blocking **DELETES** the person
from Microsoft 365, that server's rule removes the account, mailbox and licences instead of
just disabling sign-in. Check with a senior engineer before blocking anyone who only needs a
temporary block.

## What the status column means

| Status | Meaning |
|---|---|
| `Blocked` / `Hidden` | Marked in AD, and a working rule was confirmed |
| `Can sign in` / `Visible` | Not marked |
| `NOT blocked - rule missing` | Marked in AD, but there is no rule, so **they can still sign in** (or are still visible) |
| `Blocked (unconfirmed)` | Marked in AD; the rule could not be checked from here |

## Things to know

- **Blocked people may stay signed in for a while.** Existing sessions last until their tokens
  expire. For an immediate cut-off, also revoke their sessions in the Entra admin center.
- **Hidden people can take up to a day to vanish in Outlook.** Outlook's offline address book
  updates on Microsoft's schedule.
- **Every change is logged** to `Logs\Changes_<date>.csv` next to the tool: who made it,
  when, which person, and the old and new value.
- Copy the folder to your own machine first. If it runs from a synced SharePoint folder, the
  logs sync back to SharePoint.

---

## Set up sync rules (sysadmins)

Each fix writes a marker attribute on the user in AD. **The marker does nothing on its own.**
A custom inbound sync rule inside Entra Connect turns it into the change in Microsoft 365:

| Fix | Marker in AD | The rule writes |
|---|---|---|
| Block Microsoft 365 sign-in | `msDS-cloudExtensionAttribute10 = BlockCloudSignIn` | `accountEnabled = False` (recommended) or `cloudFiltered = True` |
| Hide from address book | `msDS-cloudExtensionAttribute1 = HideFromGAL` | `msExchHideFromAddressLists = True` |

**Custom sync rules are not copied when Entra Connect is moved to a new server.** After any
migration, open this page and check both cards. If a rule did not survive, everyone
"blocked" can sign in again, and nothing else warns you.

### Two ways to block sign-in

| Option | What happens to a blocked person | Mailbox and licences |
|---|---|---|
| **Disable the Microsoft 365 account** (recommended) | The synced account is disabled | **Kept.** Restoring sign-in puts everything back |
| **Remove the person from Microsoft 365** | Entra Connect stops syncing them and Microsoft 365 **deletes** the account | **Deleted** with the account; licences may need reassigning after a restore |

The tool accepts an existing rule of either kind, and says which one is in force. The old
`Block365SignIn-RuleBuilder.ps1` could only build the delete-from-Microsoft-365 rule.

### Building a rule

1. On the **Set up sync rules** page, type or find the Entra Connect server and press **Check rules**.
2. Under **Build a rule**, pick the fix (and, for blocking, what it should do). The box shows
   the exact rule: name, precedence, the attribute it reads and writes, and the expression.
3. Either:
   - **Create the rule on <server>.** This works when the tool runs **on** the Entra Connect
     server. Entra Connect refuses rule changes over a remote connection.
   - **Save as script for the Entra Connect server.** Copy the `.ps1` there and run it in an
     elevated window, first with `-WhatIf`, then without. The script makes the same safety checks.
4. **Run a Full Synchronization and review it before exporting.** A new rule applies to
   nobody until then. The tool prints the steps:
   Synchronization Service Manager > Connectors > AD connector > Run > Full Synchronization.
   Then on the Microsoft Entra connector, Search Connector Space with scope *Pending Export*,
   check the list, and Run > Export.

Safety checks:
- It refuses to create a second rule when one already reacts to the marker.
- It replaces a broken rule only when you tick **Replace**.
- It picks a free precedence number between 1 and 99, the range Microsoft reserves for custom rules.
- It warns if the AD connector does not import the marker attribute. Until that is fixed, no
  rule can see the marker. To fix it: Synchronization Service Manager > Connectors > AD
  connector > Properties > Select Attributes.

### From the command line

```powershell
.\New-SyncedUserRule.ps1 -Rule BlockCloudSignIn                        # is it in place?
.\New-SyncedUserRule.ps1 -Rule BlockCloudSignIn -Create -WhatIf        # what would be created
.\New-SyncedUserRule.ps1 -Rule BlockCloudSignIn -Create                # create (run ON the Connect server)
.\New-SyncedUserRule.ps1 -Rule BlockCloudSignIn -BlockMethod RemoveFromM365 -Create   # the delete variant
.\New-SyncedUserRule.ps1 -Rule HideFromGAL -ExportScript C:\Temp\New-HideRule.ps1     # script to run there
```

Exit codes: 0 = in place / created / exported, 1 = missing, broken or failed, 2 = could not check.

### Where to run it

Running it **on the Entra Connect server** gives the most: the green or red check, and rule
creation. The reason is a real limit. Entra Connect's management interface is bound to
`net.pipe://localhost/ADSyncManagement` and refuses requests that arrive over PowerShell
remoting. From any other machine, blocking and hiding still work; the card just shows amber.

---

## Window options

`Start-M365SyncedUserFixes.ps1` parameters (the `.cmd` launchers pass any you add):

| Parameter | Purpose |
|---|---|
| `-Tab BlockSignIn\|HideFromGAL\|SyncRules` | Page to open first |
| `-EntraConnectServer <name>` | Name the Entra Connect server instead of finding it |
| `-Credential` | Different credentials for the Entra Connect server |
| `-SearchBase <OU DN>` | Only list people in one OU |
| `-SkipRuleCheck` | Break-glass: allow Block / Hide even when the rule is confirmed missing |
| `-LogFolder <path>` | Where the change log goes (default: `Logs` next to the script) |

The Entra Connect server it finds is cached in `EntraConnectSettings.json`. Delete that file
to force a fresh search after a migration.

## Requirements

- Windows PowerShell 3.0 or later (Server 2012 and up) or PowerShell 7, with the
  **ActiveDirectory** module (RSAT, or run it on a DC).
- Rights to change `msDS-cloudExtensionAttribute1` and `msDS-cloudExtensionAttribute10` on users.
- Checking and creating rules: local administrator (or `ADSyncAdmins`) on the Entra Connect server.
- Light and dark themes: the button at the top right switches between them.

## Troubleshooting

| You see | Do this |
|---|---|
| Nothing happens when you double-click | Right-click the `.cmd` > **Run as administrator**, or open PowerShell and run `.\Start-M365SyncedUserFixes.ps1` to see the error. Files copied from SharePoint may need `Get-ChildItem <folder> \| Unblock-File` |
| "The ActiveDirectory PowerShell module could not be loaded" | Install RSAT (Active Directory module for Windows PowerShell) or run on a DC |
| Amber: "cannot be read from this computer" | You are not on the Entra Connect server. Run the tool there for the green or red check. Blocking and hiding still work |
| Amber: "No Entra Connect server could be found" | Type the server name on **Set up sync rules**, and delete `EntraConnectSettings.json` |
| Red: NOT FOUND, but you can see a rule in the Rules Editor | That rule does not read this tool's marker. Check what it uses: `$r = Get-ADSyncRule \| Where-Object Name -eq '<name>'; $r.AttributeFlowMappings; $r.ScopeFilter.ScopeConditionList` |
| A blocked person can still sign in | Wait for the sync to finish; revoke sessions for an immediate cut-off; check the card is green |
| Someone was blocked and their mailbox disappeared | That server's rule uses `cloudFiltered`. Restore sign-in and sync to bring the account back (reassign licences), and consider rebuilding the rule as **Disable the Microsoft 365 account** |

## Files

| File | Purpose |
|---|---|
| `Start M365 Synced User Fixes.cmd` | **Start here.** Opens the window without a console |
| `Launch-CloudSignInMgr.cmd`, `Launch-HideFromGAL.cmd` | Open straight on the Block or Hide page |
| `Start-M365SyncedUserFixes.ps1` | The window |
| `New-SyncedUserRule.ps1` | Command-line rule check, creation and export |
| `SyncedUserFixes.Core.ps1` | Shared logic. **Required** by both scripts |
| `Tests\` | Pester tests |

## Moving from the old tools

This replaces two folders, `Block 365 Sign-in` and `HideFromGal`. It uses the **same
attributes and marker values**, so everyone already blocked or hidden stays that way, and
existing rules are recognised.

| Old | New |
|---|---|
| `Launch-CloudSignInMgr.vbs` / `CloudSignInMgr.ps1` | `Launch-CloudSignInMgr.cmd`, or the Block page |
| `Launch-HideFromGAL.vbs` / `HideFromGAL.ps1` | `Launch-HideFromGAL.cmd`, or the Hide page |
| `Block365SignIn-RuleBuilder.ps1`, `HideFromGal-RuleBuilder.ps1` | **Set up sync rules**, or `New-SyncedUserRule.ps1` |
| `Shared-EntraConnect.ps1` (two identical copies) | `SyncedUserFixes.Core.ps1` |

Why the `.vbs` launchers went:
- **They hid failures.** They started PowerShell with every window hidden, so a script that
  could not start showed nothing at all. Both old scripts required PowerShell 5.1, so on a
  Server 2012 or 2012 R2 box (PowerShell 3.0 / 4.0) a double-click did nothing.
- **VBScript is going away.** It still works on Server 2012 to 2025, but Microsoft has
  deprecated it and will remove it from a future Windows release.

The new window needs only PowerShell 3.0 and reports any startup problem in a message box.

## Tests

```powershell
Invoke-Pester .\M365-SyncedUserFixes\Tests
```

## References

- [Make a change to the default configuration](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-change-the-configuration): custom rules, precedence 1 to 99
- [Fix modified default rules](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-fix-default-rules): cloudFiltered, NULL lets lower-precedence rules contribute, filtered objects are deleted
- [Configure filtering](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-configure-filtering): attribute-based filtering with custom inbound rules
- [Understanding the default configuration](https://learn.microsoft.com/entra/identity/hybrid/connect/concept-azure-ad-connect-sync-default-configuration): precedence and the AccountEnabled rule
- [Import and export Connect configuration](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-import-export-config): custom rules are not migrated
- [Features removed or no longer developed in Windows Server](https://learn.microsoft.com/windows-server/get-started/removed-deprecated-features-windows-server): VBScript is a Feature on Demand in Server 2025, to be removed later
