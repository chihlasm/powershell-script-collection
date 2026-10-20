# Risk profile: read-only verdict tools that tell a tech what to do

Applies to tools labelled "Changes anything? No" that give a verdict and a next step:
AD-UserQuickCheck, M365-UserQuickCheck (including the mailbox check), FolderAccess-Check,
Network-QuickCheck, Citrix-FSLogix-Triage, and the shared TicketNote kit. The code writes
nothing, but a tier 1 tech acts on the next step with admin rights, so the advice is a
change path too. A wrong or over-broad step repeats on every ticket.

## Advice
- A next step that removes or deletes anything, re-enables a disabled account, or undoes a
  deliberate block (sign-in block, marker, lockout policy) says "Escalate" plus the reason
  (D-017, P-004). This holds on every branch, with and without AD or tenant data. A test
  enumerates every reason code and action string and checks them, using a wide verb list
  (remove, delete, clear, re-enable, unblock, reset, take ownership, unlock, restore, turn
  back on, free up space, clean up), not only remove/delete. "Free up space" and "clean up"
  count as deletes. Starting or enabling a service whose start type is Disabled undoes a
  deliberate block.
- Naming a "Changes anything? Yes" tool (Cleanup-CitrixVDAStorage) counts as escalation only
  when the step says a senior engineer runs it.
- Installs, upgrades and reinstalls (.NET, agents, stacks) as next steps say Escalate or name
  a maintenance window.
- A risky or compromised user (ID Protection atRisk/confirmedCompromised) always escalates to
  the security lead before any unblock, re-enable or password-reset step, whatever path a
  plain disabled account takes (D-050).
- The steps that reach the ticket note (Blocker/Probable) carry the escalation themselves. An
  escalation that lives only in a Warning or Info reason does not reach the ticket.
- One report never gives conflicting next steps for the same account: a manager or plain step
  next to an escalation from another reason. Tests cover the combinations (risky + blocked,
  block marker + 50057), not only each step string on its own.
- Advice to remove an entry whose account "can't be looked up" first checks where the SID
  belongs (another computer's local SIDs cannot be translated remotely and are not orphans).
  It tells short-lived causes (trust or DC outage, a foreign domain SID) apart from a deleted
  account.
- A step that grants access never names a well-known privileged or computer group (Domain
  Admins, Enterprise/Schema Admins, Administrators, Account/Server/Backup/Print Operators,
  Domain Controllers, RODC/ERODC (498), Exchange groups). The list is canonical, kept in one
  place, tested for parity and checked against Learn.
- The privilege check fails closed. Unreadable parents, the depth limit, a multi-domain
  forest or trusts, FSPs, a non-GC `memberOf`, or a failed lookup put an approval gate
  ("Get senior approval first") on the step instead of silently dropping or allowing it.
  Name-based detection of groups without a well-known RID is listed as a known limitation.
- A step that widens access on a folder with inheritance names the effect on the subtree.
- A failed or partial check gives "Can't tell"/"could not check", never an all-clear, and
  the next step matches that (P-001).

## Read-only by construction
- A static AST test allowlists every command and .NET method the tool calls. It is
  case-insensitive and module-prefix-aware, and it is an allowlist, not a denylist regex.
- It covers dynamic invocation (`&`, `Invoke-Expression`, `[scriptblock]::Create`,
  `Start-Process`, child `powershell.exe`), ADSI/DirectoryServices writes, the `AD:`
  provider, `Invoke-RestMethod`/`Invoke-WebRequest` and Graph wrappers (GET only),
  `Invoke-CimMethod`/`Invoke-WmiMethod`, `Set-/New-/Remove-CimInstance`, and .NET writers
  (`File.Delete`, `RegistryKey.SetValue`, `ServiceController.Stop`, `.SetAccessControl()`).
  It also covers every directory module the tool may load (ActiveDirectory, Microsoft.Graph,
  Microsoft.Entra, AzureAD, MSOnline, ExchangeOnlineManagement, Az).
- The scan covers every file the tool dot-sources or runs (companions, the shared CaseKit
  copy) and every script block sent to a remote host, not just the entry script.
- Commands that persist client-side settings (`Set-MgGraphOption`) are not allowlisted.
- Delegated Graph tokens carry every scope already consented, so "read-only scopes" do not
  count as a write control. GET-only calls plus the static guard are the control.
- A call by variable (`& $path`, where `GetCommandName()` is null) is resolved and
  allowlisted, never skipped.
- When more than one guard covers a folder (a folder-wide guard and a tool's own), the specs
  say which guard covers which command family (AD/Graph, Exchange Online writes, dynamic
  invocation), so every dot-sourced file is checked by a guard that knows its write cmdlets.
  A test that pins a form for another guard applies that guard's real rule, or calls it.

## Shared kit files
- A change to a parity-copied kit file (`TicketNote/CaseKit.ps1`) reaches every tool that
  ships a copy. Each copy's write surface is checked, and the kit's own suite carries the
  behaviour tests.

## Reading production hosts
- Live log, lock and VHD files are opened with a non-exclusive share mode
  (`FileShare.ReadWrite` or `ReadWrite|Delete`).
- CIM sessions and PSSessions opened against client servers are closed in `finally` on every
  return path, with a test for the failure path.
- When the tool connects with `-Credential` or the tech's logon to a host named in user
  input, the name is the one the tech typed. There is no silent fallback to another name or
  to NTLM against an unverified host.
- A recommended lossy action (log off, reset a session) first checks the state (Disconnected
  vs Active) and says to save work or ask the user.
- Restarting or rebooting a whole host or a service affects every session: on multi-session
  hosts the step carries the signed-in-user warning, and any user count is framed as a
  point-in-time observation.

## Tests
- Every external read cmdlet is mocked; tests never run the tool against the real domain,
  tenant or this machine (see SQUAD.md Testing).
