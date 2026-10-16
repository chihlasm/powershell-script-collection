# AD-UserQuickCheck

**"I can't log in."** Run this while you have the user on the phone. It tells you, in plain English, whether their Active Directory account can sign in right now, and if not, why and what to do next.

It only reads. It never unlocks, resets or changes anything.

## When to use it

- A user says they cannot sign in, get "wrong password", or keep getting locked out.
- You want the answer before you open Active Directory Users and Computers.
- You want something to paste into the ticket (add `-OutputPath`).

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

## Things worth knowing

- **Last sign-in** is the newest time across every DC, with the DC named. The shared copy (`lastLogonTimestamp`) is only updated every so often (up to about 14 days by default), so it can be days behind. Do not use it to prove someone has not signed in today.
- **Locked now** is asked of the PDC emulator, which learns about lockouts first. If it cannot be reached, you get a warning and the answer may be out of date.
- **Exit codes** (for scripts): `0` can sign in, `1` cannot or probably not, `2` user not found or the name matches several people (the candidates are listed, nothing is guessed), `3` AD module or connection failure.

## What it does not check

This looks at the **on-premises Active Directory account only**. It does not check:

- Microsoft 365 / Entra ID cloud sign-in, MFA, or Conditional Access
- Cloud password expiry (use `Get-EntraPasswordPolicy` in this repository)
- The user's device, network, VPN or licensing
- Why an account keeps locking (use the AD-LockoutDiagnostics tools)

## Tests

```powershell
Invoke-Pester .\AD-UserQuickCheck\Tests
```

The tests run against a fake ActiveDirectory module (`Tests\FakeAD`), so no domain is needed.
