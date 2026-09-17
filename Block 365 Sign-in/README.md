# Block 365 Sign-in Manager

Blocks and restores Microsoft 365 sign-in for Active Directory users, without touching
their on-premises domain access. A user who is blocked can still log in to their PC and
reach file shares; they just cannot sign in to Microsoft 365.

**Quick start:** double-click `Launch-CloudSignInMgr.vbs`, find the person, tick their
row, click **Block cloud sign-in**.

---

## How this works

The tool works in two halves, and **they may run on two different servers**:

| Half | Where it runs | What it does |
|---|---|---|
| **The marker** | This tool | Writes `msDS-cloudExtensionAttribute10 = "BlockCloudSignIn"` on the user in AD |
| **The enforcement** | A custom sync rule *inside Entra Connect* | Notices that marker and acts on it during sync |

**The marker alone does nothing.** It is just a flag on the AD user object. Something in
Entra Connect has to be watching for it. If that rule is missing, setting the attribute
changes nobody's access — which is why this tool refuses to write the marker when it can
prove the rule is gone.

### Two valid enforcement mechanisms

There is more than one correct way to build the enforcement rule, and they behave
**differently**. Know which one your environment uses:

| Rule flows to | What happens to the user | Licenses & mailbox |
|---|---|---|
| `accountEnabled` ← `False` | The synced Entra ID account is disabled | **Kept** |
| `cloudFiltered` ← `True` | The user stops syncing; the Entra ID object is **deleted** | **Lost** |

Both block sign-in. `accountEnabled` is the gentler option and is usually what you want
for temporarily cutting off access. `cloudFiltered` is destructive — deleting the cloud
object takes the mailbox and licenses with it.

The tool accepts either and **names which one is in force** in its status banner. Read
that banner before blocking anyone, especially the first time on an unfamiliar server.

> **This server (CWRADDCSRV / warner-robins.cwr)** uses a rule named
> **"Block 365 Sign In"** at precedence 10, flowing `accountEnabled ← False`. It keeps
> licenses and mailboxes. Do **not** run the rule builder here — see
> [Do not create a second rule](#do-not-create-a-second-rule).

---

## The status banner

The GUI checks the enforcement rule at startup and shows one of four states:

| Banner | Meaning | What happens |
|---|---|---|
| 🟢 **Enforcement rule verified** | Rule found, and it reads our marker | Normal operation. The banner names the rule and its mechanism |
| 🔴 **Enforcement rule NOT FOUND** | Checked successfully; nothing is enforcing | **Blocking is disabled.** Click *How to fix* |
| 🔴 **Enforcement rule is broken** | A rule exists but will not respond to our marker | **Blocking is disabled.** Click *How to fix* |
| 🟡 **Could not verify enforcement rule** | The check itself could not run | Tool still works; banner explains why it could not check |

**"Could not verify" is not the same as "rule is missing."** A permissions problem or an
unreachable server is a different fault from a missing rule, and the tool will not
disable itself over one. It tells you what it could not do and lets you proceed.

**Restoring sign-in is never blocked**, whatever the banner says. Giving someone their
access back must always be possible.

---

## Where you can run this

**Run it on the Entra Connect server when you can.** That is the simplest and most
reliable option.

The reason is a real constraint, not a preference: Entra Connect exposes its management
interface as a WCF endpoint bound to `net.pipe://localhost/ADSyncManagement`, and it
**rejects calls that arrive over a PowerShell remoting hop** — even a hop back to the
same machine. So `Get-ADSyncRule` cannot be reliably called from another server.

The tool detects when it is running on the Connect server and calls the ADSync cmdlets
directly, which works. Run it elsewhere and rule verification will usually report
🟡 *"cannot be read from this machine"* — everything else still works, you just do not
get the green/red confirmation.

### Requirements

**To list users and set the marker attribute**
- Domain-joined Windows machine with the `ActiveDirectory` module (RSAT)
- Rights to modify user attributes in AD
- PowerShell 5.1+

**Additionally, to verify the enforcement rule**
- Run it on the Entra Connect server itself (see above)
- Local administrator rights there, or membership of the local `ADSyncAdmins` group

---

## Running the tool

Double-click **`Launch-CloudSignInMgr.vbs`**.

Use the `.vbs`, not the `.ps1` — launching the `.ps1` directly leaves a blue PowerShell
console window behind the GUI. The launcher starts it with no console at all.

To make a desktop shortcut: right-click the `.vbs` → *Send to* → *Desktop*. To have it
always run elevated, open the shortcut's *Properties* → *Advanced* → *Run as
administrator*.

Command-line parameters (pass these to `CloudSignInMgr.ps1` directly if needed):

| Parameter | Purpose |
|---|---|
| `-EntraConnectServer` | Name the Connect server instead of auto-discovering it |
| `-Credential` | Different credentials for the Connect server connection |
| `-SearchBase` | Limit the user list to one OU |
| `-SkipRuleCheck` | Break-glass: allow blocking without verification |

### Day-to-day use

1. Type part of a name or username in **Find a person**
2. Tick the rows you want (clicking anywhere on a row toggles it)
3. Click **Block cloud sign-in** or **Restore cloud sign-in**
4. Confirm the dialog
5. When asked, let it run a sync so the change reaches Microsoft 365

The **Cloud sign-in** column shows the truth as the tool understands it:

| Column value | Meaning |
|---|---|
| `Allowed` | Not marked. Normal access |
| `Blocked` | Marked, and a working rule was verified |
| `Marked - NOT enforced` | Marked, but the rule is missing or broken — **they can still sign in** |
| `Marked - enforcement unverified` | Marked, but the rule could not be checked |

---

## Setting up enforcement on a NEW server

Only needed where no enforcement rule exists yet.

### Do not create a second rule

**Check the banner first.** If it is green, enforcement already exists — stop. Running
the rule builder anyway creates a *second* rule using `cloudFiltered`, which **deletes
cloud objects**, conflicting with an existing `accountEnabled` rule. That is a
destructive mistake and hard to undo.

Only proceed when the banner says **NOT FOUND**.

### Creating the rule

On the Entra Connect server:

```powershell
.\Block365SignIn-RuleBuilder.ps1 -WhatIf     # preview, changes nothing
.\Block365SignIn-RuleBuilder.ps1             # create it
```

It is idempotent — if a correct rule already exists it says so and stops. `-Force`
replaces a broken one.

**The rule it creates uses `cloudFiltered`**, which removes users from Entra ID and takes
their licenses and mailboxes with them. If you want the gentler `accountEnabled`
behavior, build that rule by hand in the Synchronization Rules Editor instead — the tool
verifies either.

### After creating it: run a Full Synchronization

A new sync rule does not apply to existing users until a full sync recalculates them.
The script prints these steps rather than running them, because a `cloudFiltered` rule
can stage a large number of deletions:

1. On the Connect server, open **Synchronization Service Manager**
2. **Connectors** tab → select the Active Directory connector
3. **Actions → Run → Full Synchronization → OK**
4. Right-click the **Microsoft Entra** connector → **Search Connector Space**
5. Set **Scope** to *Pending Export* and **review the staged changes**
6. Right-click the Microsoft Entra connector → **Run → Export**

Step 5 is not optional ceremony. It is your last chance to catch a rule that matches more
users than you intended, before anything is deleted in the cloud.

---

## Troubleshooting

**Blue PowerShell window appears behind the GUI**
You launched the `.ps1`. Use `Launch-CloudSignInMgr.vbs` instead.

**"The term '...\Shared-EntraConnect.ps1' is not recognized"**
`Shared-EntraConnect.ps1` is missing from the folder. All the files listed below must
travel together. If they were copied from a network share, unblock them:

```powershell
Get-ChildItem "<folder>\*.ps1" | Unblock-File
```

**🟡 "cannot be read from this machine"**
You are not running on the Entra Connect server. Entra Connect only answers these queries
locally. Run the tool on the sync server, or verify by hand there:

```powershell
Get-ADSyncRule | Where-Object Direction -eq 'Inbound' | Select-Object Name, Precedence
```

**🟡 "no Entra Connect server could be found"**
Auto-discovery probes AD server objects for the `ADSync` service and found none
reachable. Name it explicitly with `-EntraConnectServer <name>`, and delete
`EntraConnectSettings.json` to clear any stale cached value. To find the server:

```powershell
Get-ADComputer -Filter * | ForEach-Object {
  if (Get-Service -Name ADSync -ComputerName $_.DNSHostName -ErrorAction SilentlyContinue) { $_.DNSHostName }
}
```

**🔴 "NOT FOUND" but you can see the rule in the Rules Editor**
The tool looks for an inbound rule that flows to `accountEnabled` or `cloudFiltered`
*and* references `msDS-cloudExtensionAttribute10`. A rule driven by a different attribute
will not respond to this tool's marker. Check what it actually uses:

```powershell
$r = Get-ADSyncRule | Where-Object { $_.Name -eq '<rule name>' }
$r.AttributeFlowMappings | Format-List Destination, FlowType, Source, Expression
$r.ScopeFilter.ScopeConditionList | Format-List Attribute, ComparisonOperator, ComparisonValue
```

**A user shows "Marked - NOT enforced"**
The attribute is set but nothing is acting on it — **they can still sign in.** Fix the
enforcement rule, then run a sync.

**Blocked users can still sign in**
Three usual causes, in order of likelihood:
1. The change has not synced yet — run a sync and wait for it to finish
2. Existing sessions and refresh tokens survive until they expire. For an immediate
   cutoff, revoke the user's sessions in the Entra admin center
3. The enforcement rule is missing or broken — check the banner

**Someone was blocked and their mailbox disappeared**
That is `cloudFiltered` behavior: the Entra ID object was deleted, taking the mailbox and
licenses. Restore sign-in and re-sync; the object is recreated, though licenses may need
reassigning. If this is not what you want, the rule should use `accountEnabled` instead.

---

## Files

| File | Purpose |
|---|---|
| `Launch-CloudSignInMgr.vbs` | **Start here.** Launches the GUI with no console window |
| `CloudSignInMgr.ps1` | The GUI |
| `Block365SignIn-RuleBuilder.ps1` | Creates the enforcement rule. Only for servers that have none |
| `Shared-EntraConnect.ps1` | Discovery, verification, and sync helpers. **Required** |
| `Tests\` | Pester tests for the verification logic |
| `EntraConnectSettings.json` | Auto-created cache of the last verified server. Safe to delete |

`Shared-EntraConnect.ps1` is **duplicated** in the `HideFromGal` folder, which has the
same architecture. The repo convention is flat, self-contained tool folders with no
shared module, so it is copied rather than imported. **Changes must be mirrored to both
copies.**

Run the tests with:

```powershell
Invoke-Pester -Path .\Tests -Output Detailed
```

---

## About the marker attribute

`msDS-cloudExtensionAttribute10` is a general-purpose AD attribute Microsoft provides for
exactly this kind of use. This toolkit's convention:

| Attribute | Used by | Marker value |
|---|---|---|
| `msDS-cloudExtensionAttribute10` | Block 365 Sign-in | `BlockCloudSignIn` |
| `msDS-cloudExtensionAttribute1` | HideFromGal | `HideFromGAL` |

Before repurposing either attribute for something else, check whether these tools are in
use — they would start blocking or hiding people unintentionally.

---

## A note on Entra Connect migrations

Custom synchronization rules are **not** carried over when Entra Connect is moved, swung,
or rebuilt on a new server. Microsoft's guidance is that they must be recreated manually.

So after any Connect server move, **open this tool and check the banner.** If it went from
green to red, the enforcement rule did not survive and everyone previously blocked can
sign in again. That failure is silent without this check, which is why the banner exists.

---

## References

- [Make a change to the default configuration](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-change-the-configuration) — custom rules, precedence 1–99 reserved for custom rules, expression syntax
- [Import and export Connect configuration](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-import-export-config) — custom rules are not migrated automatically
- [ADSync PowerShell reference](https://learn.microsoft.com/entra/identity/hybrid/connect/reference-connect-adsync)
- [Connect sync scheduler](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-feature-scheduler)
