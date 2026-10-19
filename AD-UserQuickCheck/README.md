# AD-UserQuickCheck

**"I can't log in."** Run this while you have the user on the phone. It tells you, in plain English, whether their Active Directory account can sign in right now, and if not, why and what to do next.

It only reads. It never unlocks, resets or changes anything.

## When to use it

- A user says they cannot sign in, get "wrong password", or keep getting locked out.
- You want the answer before you open Active Directory Users and Computers.
- You want something to paste into the ticket: the [ticket note](#ticket-note) is on your clipboard after every run (add `-OutputPath` for an HTML report too).

## The one command

```powershell
.\Get-ADUserQuickCheck.ps1 -Identity jdoe
```

`-Identity` takes a sign-in name (`jdoe`), an email-style sign-in (`jdoe@contoso.com`), `CONTOSO\jdoe`, a full distinguished name, or as a last resort a display name (`"Jane Doe"`).

Other options:

| Option | What it does |
|---|---|
| `-OutputPath C:\Temp` | Also saves an HTML report and a one-row CSV named `UserQuickCheck_<name>_<date>_<time>`. Without it, console only. |
| `-Server DC01` | Run the lookup against a specific domain controller or domain. |
| `-Credential (Get-Credential)` | Use a different account for the lookups. |
| `-DomainController DC01,DC02` | Check only these DCs instead of all of them. |
| `-TicketNumber 482113` | Save the HTML, the CSV and the ticket note in the ticket's folder. See [Ticket note](#ticket-note). A number that does not fit (letters, digits, `-` or `_`, up to 32 characters) is refused with a `[FAIL]` line before anything is checked. |
| `-NoClipboard` | Do not copy the ticket note to the clipboard (see the clipboard note under [Ticket note](#ticket-note)). |
| `-FullDetail` | Keep IP addresses and share paths in the ticket note (removed by default). |
| `-PassThru` / `-Quiet` | For scripts: return the result object instead of an exit code, and write nothing to the console. `-Quiet` also leaves the clipboard alone. |

Needs the ActiveDirectory (RSAT) PowerShell module. Works on Windows PowerShell 3.0 and later.

## How to read the answer

The first line is the answer:

```
Can Jane Doe sign in right now?  NO
```

| Answer | Meaning |
|---|---|
| **YES** | Nothing found that stops them. Warnings may still be listed (password expiring soon, and so on). If they still cannot sign in, the problem is not in the AD account: look at the device, network, VPN, or Microsoft 365. |
| **NO** | At least one definite blocker. Fix it and they can sign in. |
| **PROBABLY NOT** | The account is restricted (certain computers, certain hours, or smart card only). Whether it blocks them depends on what they are doing. |

Under the answer, each reason has a **What to do** line. Below that is a "Looks fine" list and a detail table with everything the check read.

## What each reason means

| You see | What it means | What to do |
|---|---|---|
| Account is turned off (disabled) | Someone disabled the account. | Confirm with the manager it should be on, then enable it. |
| Account is locked | Too many wrong passwords. Says when it unlocks by itself, or that someone must unlock it. | Unlock it. Ask about old passwords saved on phones, laptops and mapped drives. If it locks again, use the AD-LockoutDiagnostics tools. |
| Account expired | The account has an end date that has passed (contractors, temps). | Ask the manager. Extend or clear the date if they should still have access. |
| Password expired | The password's maximum age has passed. | Reset it or have them change it from a signed-in PC. |
| Must set a new password at next sign-in | An admin forced a password change. A PC sign-in will prompt them, but Outlook, VPN and similar may just fail without asking. | Have them sign in at a PC and choose a new password first. |
| Can only sign in to certain computers | The account has a computer list. | Check they are on one of the listed computers. |
| Sign-in hours restrictions | The account can only sign in at certain times. | Check the time. Hours are on the Account tab in Users and Computers. |
| Needs a smart card | Passwords will not work. | Use the smart card, or arrange a replacement. |
| Password / account expires soon (warning) | Not a problem yet. | Tell them before it happens. |
| Wrong passwords recorded (info or warning) | Shows which DCs saw failures and how close to lockout the highest count is. | Ask if they changed their password recently. |
| Couldn't check DC02 (warning) | That domain controller did not answer. Wrong-password counts and last sign-in are kept per DC, so the picture may be incomplete. | Check the DC is online and re-run if it matters. |
| Many groups (warning) | Hundreds of nested groups can make the sign-in token too big for some apps. | Only act if they see odd "request header too long" or access errors. |

## Ticket note

Every run ends with a short note on the clipboard, ready to paste into the ticket:

```
[Ticket note] AD-UserQuickCheck: Can Jane Doe sign in right now? NO

Checked:
- AD account jdoe in contoso.com, on 3 of 4 domain controllers.
- PROBLEM: Their password expired on 2026-10-10.
Ruled out:
- Account is turned on.
- Account does not expire.
Could not check:
- DC03.contoso.com: wrong-password count and last sign-in (could not reach it).
Next step:
- Reset their password (Set-ADAccountPassword) or have them change it from a signed-in PC. ...

Domain: contoso.com | Ran by: CONTOSO\jtech on WS-114 | 2026-10-17 09:30:12 (UTC+01:00) | Changed anything: No
Evidence: UserQuickCheck_jdoe_2026-10-17_093012.html, UserQuickCheck_jdoe_2026-10-17_093012.csv
```

- **Ruled out** only lists checks the tool really managed to make. If a domain controller did not answer, "no wrong passwords" moves to **Could not check**. If the PDC emulator could not be read, "not locked out" moves there too, because lockout status from another DC can be out of date.
- If the user is not found, or the name matches several people, you still get a note. It says why, and that the account checks did not run.
- **Where the files go:**
  - `-TicketNumber 482113`: the HTML, the CSV and `Note_<date>_<time>_AD-UserQuickCheck.txt` go into `Ticket_482113` under `-OutputPath`, or under `%USERPROFILE%\Documents\TicketNotes` when `-OutputPath` is not given.
  - `-OutputPath` alone: the note is saved next to the reports.
  - Neither: no files. The note goes to the clipboard, or is printed on the console if the clipboard is not available (for example on a server with no desktop).
- IP addresses and share paths are replaced by `[IP removed]` / `[share path removed]`, so the note is safe to paste. Add `-FullDetail` to keep them. Evidence shows file names only.
- `-Credential` shows as `(as CONTOSO\name)` in the stamp. The password never goes into the note.
- Ran several tools on the same ticket? `..\TicketNote\Join-TicketNotes.ps1 -TicketNumber 482113` joins their notes into one.
- **The clipboard is not private.** The note is copied with the Windows Forms clipboard and marked to stay out of clipboard history (Win+V) and the cloud clipboard (synced to the user's other devices, if turned on). Only if that fails (for example in a PowerShell window started with `-Mta`) is `Set-Clipboard` used instead, and that cannot opt out, so the note can land in both. In a Remote Desktop session the clipboard is shared with the PC you connected from (RDP clipboard redirection). The note names the user, so add `-NoClipboard` when that matters; the note file is still saved when a folder is in play.
- If the name matches more than five people, the note lists the first five (name and sign-in name) and says how many more, so refine the search.
- The note is built by `CaseKit.ps1` in this folder. Keep it next to the script. Without it the check still runs, with no note, and `-TicketNumber` is ignored (the warning says so).

## Things worth knowing

- **Last sign-in** is the newest time across every DC, with the DC named. The shared copy (`lastLogonTimestamp`) is only updated every so often (up to about 14 days by default), so it can be days behind. Do not use it to prove someone has not signed in today.
- **Locked now** is asked of the PDC emulator, which learns about lockouts first. If it cannot be reached, you get a warning and the answer may be out of date.
- **Exit codes** (for scripts): `0` can sign in, `1` cannot or probably not, `2` user not found or the name matches several people (the candidates are listed, nothing is guessed), `3` could not run (AD module missing, connection failure, or a ticket number that does not fit).

## What it does not check

This looks at the **on-premises Active Directory account only**. It does not check:

- Microsoft 365 / Entra ID cloud sign-in, MFA, or Conditional Access
- Cloud password expiry (use `Get-EntraPasswordPolicy` in this repository)
- The user's device, network, VPN or licensing
- Why an account keeps locking (use the AD-LockoutDiagnostics tools)
- Kerberos encryption-type blocks: since the 2026 RC4 changes, a domain controller can refuse a sign-in because the account or the device only uses RC4, with nothing wrong with the password. Everything here can look fine while the user still can't sign in. `AD-LockoutDiagnostics\Diagnose-ADAccountLockout.ps1 -Identity <user>` (or the lockout workbench) checks every domain controller for this and says "Not a password problem: encryption type blocked" with the next step.

## Tests

```powershell
Invoke-Pester .\AD-UserQuickCheck\Tests
```

The tests run against a fake ActiveDirectory module (`Tests\FakeAD`), so no domain is needed.
