# HideFromGal Scripts

This collection of PowerShell scripts provides a solution for hiding Active Directory users from the Global Address List (GAL) in Exchange Online using Entra Connect (formerly Azure AD Connect) synchronization rules.

---

## Read this first: the tool depends on a rule that lives somewhere else

These scripts work in two halves, running on **two different servers**:

| Half | Where it runs | What it does |
|---|---|---|
| **The marker** | `HideFromGAL.ps1`, on a DC or admin workstation | Writes `msDS-cloudExtensionAttribute1 = "HideFromGAL"` on the user in AD |
| **The enforcement** | A custom sync rule *inside Entra Connect* | Flows that marker to `msExchHideFromAddressLists`, hiding the user from the GAL |

**The marker alone does nothing.** If the sync rule is missing, setting the attribute
hides no one.

Custom synchronization rules are **not** carried over when Entra Connect is moved,
swung, or rebuilt on a new server — Microsoft's guidance is that they must be recreated
manually. See
[Import and export Connect configuration](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-import-export-config).

> **After any Entra Connect server move, run `HideFromGal-RuleBuilder.ps1` against the
> new server, or this tool will silently stop hiding anyone.**

`HideFromGAL.ps1` verifies the rule at startup and shows a status banner naming the
server it checked. When the rule is confirmed missing or broken, hiding is disabled and
the banner offers a *How to fix* button. When the check simply cannot run, the tool still
works and says so: **"could not verify" is treated differently from "rule is missing"**.
Unhiding is never blocked.

### Run it on the Entra Connect server

Entra Connect exposes its management interface as a WCF endpoint bound to
`net.pipe://localhost/ADSyncManagement`, and it **rejects calls arriving over a
PowerShell remoting hop** — even a hop back to the same machine. So `Get-ADSyncRule`
cannot be reliably called from another server.

The scripts detect when they are running on the Connect server and call the ADSync
cmdlets directly, which works. Run them elsewhere and rule verification will usually
report 🟡 *"cannot be read from this machine"* — everything else still works, you just do
not get the green/red confirmation.

Both scripts accept `-EntraConnectServer` to name the sync server, and auto-discover it
otherwise. The discovered name is cached in `EntraConnectSettings.json`; delete that file
to force rediscovery after a migration.

### Launching

Double-click **`Launch-HideFromGAL.vbs`**, not the `.ps1` — launching the `.ps1` directly
leaves a blue PowerShell console window behind the GUI.

Run the tests with `Invoke-Pester -Path .\Tests`.

> `Shared-EntraConnect.ps1` is **duplicated** from the `Block 365 Sign-in` folder, which
> has the same architecture and the same dependency. Changes must be mirrored to both
> copies. It is **required** — without it the GUI throws "term not recognized" errors at
> startup.

### Common problems

**"The term '...\Shared-EntraConnect.ps1' is not recognized"**
That file is missing from the folder. All files must travel together. If copied from a
network share, unblock them: `Get-ChildItem "<folder>\*.ps1" | Unblock-File`

**🔴 "NOT FOUND" but you can see the rule in the Rules Editor**
The tool looks for an inbound rule flowing to `msExchHideFromAddressLists` that also
references `msDS-cloudExtensionAttribute1`. Check what the rule actually uses:

```powershell
$r = Get-ADSyncRule | Where-Object { $_.Name -eq '<rule name>' }
$r.AttributeFlowMappings | Format-List Destination, FlowType, Source, Expression
$r.ScopeFilter.ScopeConditionList | Format-List Attribute, ComparisonOperator, ComparisonValue
```

**A user shows "Marked - NOT hidden"**
The attribute is set but nothing is acting on it — they are still visible in the GAL. Fix
the enforcement rule, then run a sync.

**Hidden users still appear in the GAL**
The change has not synced yet, or Outlook is using a cached offline address book. The OAB
regenerates on Microsoft's schedule; Outlook may take up to 24 hours to pick it up even
after the sync completes.

---

## Scripts Overview

### HideFromGal-RuleBuilder.ps1
- **Purpose**: Creates a custom Entra Connect synchronization rule to map the `msDS-cloudExtensionAttribute1` attribute to `msExchHideFromAddressLists`.
- **When to Run**: Once per Entra Connect server/domain setup. This rule enables the hiding mechanism.
- **Execution Context**: Run on the Entra Connect server with administrative privileges.

### HideFromGAL.ps1
- **Purpose**: GUI-based tool for managing user visibility in the GAL by setting/clearing the `msDS-cloudExtensionAttribute1` attribute on AD user accounts.
- **When to Run**: Ongoing management - use this script to hide or unhide users as needed.
- **Execution Context**: Run on a domain-joined machine with Active Directory administrative access.

## Prerequisites

1. **Entra Connect Server**:
   - Azure AD Connect installed and configured
   - Administrative access to the server
   - ADSync module available

2. **Domain-Joined Machine** (for HideFromGAL.ps1):
   - Windows with PowerShell
   - Active Directory module for Windows PowerShell
   - Administrative privileges
   - Domain join status

3. **Permissions**:
   - Domain Admin or equivalent rights for AD modifications
   - Access to modify synchronization rules (Entra Connect server)

## Usage Instructions

### Step 1: Set Up the Synchronization Rule

**Only needed when no enforcement rule exists yet - check the status banner first.**
Creating a second rule for the same attribute causes conflicting sync behavior.

1. Copy the whole folder to your Entra Connect server (the RuleBuilder needs
   `Shared-EntraConnect.ps1` alongside it).
2. Open PowerShell as Administrator on the Entra Connect server.
3. Navigate to the script location and run:
   ```powershell
   PowerShell -ExecutionPolicy Bypass -File .\HideFromGal-RuleBuilder.ps1 -WhatIf   # preview
   PowerShell -ExecutionPolicy Bypass -File .\HideFromGal-RuleBuilder.ps1           # create
   ```
4. The script will:
   - Automatically detect the local AD domain
   - Find the corresponding AD connector
   - Create a new synchronization rule with a unique identifier
   - Configure attribute mapping: `msDS-cloudExtensionAttribute1` → `msExchHideFromAddressLists`
   - Enable the rule

5. Verify the rule was created successfully by checking the output.

### Step 2: Manage User GAL Visibility

1. Copy the **whole folder** to the target machine - `HideFromGAL.ps1`,
   `Shared-EntraConnect.ps1`, and `Launch-HideFromGAL.vbs` must stay together. Copying
   only the .ps1 produces "term not recognized" errors at startup.
   Prefer the Entra Connect server, so rule verification can run (see
   [Run it on the Entra Connect server](#run-it-on-the-entra-connect-server)).
2. Double-click **`Launch-HideFromGAL.vbs`** (no console window), or right-click it and
   choose *Run as administrator*.

4. The GUI will open with the following features:
   - **Search**: Filter users by name or username
   - **Select Users**: Check boxes to select users for bulk operations
   - **Hide from GAL**: Sets `msDS-cloudExtensionAttribute1 = "HideFromGAL"`
   - **Unhide from GAL**: Clears the `msDS-cloudExtensionAttribute1` attribute
   - **Sync to Entra**: Triggers a delta synchronization cycle

### Step 3: Verify Changes

After hiding/unhiding users:
- The synchronization rule will automatically apply during the next sync cycle
- Users with `msDS-cloudExtensionAttribute1 = "HideFromGAL"` will be hidden from Exchange Online GAL
- Changes typically take 15-30 minutes to propagate to Exchange Online

## How It Works

1. **Rule Creation**: The synchronization rule maps the AD attribute `msDS-cloudExtensionAttribute1` to the Exchange Online attribute `msExchHideFromAddressLists` using an expression that evaluates to `True` when the attribute equals "HideFromGAL".

2. **User Management**: The GUI script modifies the `msDS-cloudExtensionAttribute1` attribute on selected AD users.

3. **Synchronization**: Entra Connect syncs the attribute value, which controls GAL visibility in Exchange Online.

## Important Notes

- **One-Time Setup**: Run `HideFromGal-RuleBuilder.ps1` only once per Entra Connect server/domain combination.
- **Attribute Usage**: `msDS-cloudExtensionAttribute1` is a cloud extension attribute that syncs to Azure AD but doesn't conflict with on-premises usage.
- **Synchronization Timing**: Changes require a sync cycle to take effect. The script includes a manual sync trigger.
- **Logging**: `HideFromGAL.ps1` creates log files in `C:\Temp\` for auditing.
- **Error Handling**: Both scripts include error checking and user-friendly messages.
- **Testing**: Test in a non-production environment first.
- **Backup**: Ensure you have AD backups before making bulk changes.

## Troubleshooting

See [Common problems](#common-problems) above for the issues seen most often
(missing `Shared-EntraConnect.ps1`, a rule the tool cannot see, users marked but not
hidden). Additionally:

- **Rule Creation Fails**: Verify the ADSync module is available and you have permission to create sync rules. Rule creation must run ON the Entra Connect server.
- **Connector Not Found**: Ensure the Entra Connect server is domain-joined and the connector name matches the domain.
- **AD Modifications Fail**: Check domain admin rights and AD connectivity.
- **GAL Changes Not Visible**: Wait for the sync cycle to finish, then allow for offline address book caching in Outlook.

## Security Considerations

- Run scripts with least privilege required
- Audit log files for compliance
- Use secure PowerShell execution policies
- Store scripts in secure locations

## Support

For issues or questions:
- Check PowerShell error messages
- Review log files in `C:\Temp\`
- Verify Entra Connect health
- Consult Microsoft documentation for sync rules and GAL management
