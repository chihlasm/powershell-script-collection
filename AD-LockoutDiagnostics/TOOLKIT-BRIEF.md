# AD Account Lockout Toolkit — Domain Brief

**Audience:** a developer building an MSP workbench in C#, who wants to reimplement or
absorb this functionality. This is a summary of *what the toolkit does and why*, with
emphasis on the domain knowledge that is expensive to rediscover.

**Origin:** a working PowerShell toolkit (14 scripts, 430 unit tests) used against live
customer domains. Every "trap" below cost real debugging time or shipped as a bug.

---

## 1. The problem it solves

A user's AD account keeps locking out. Somewhere on the network, something is presenting
a stale password — a mapped drive, a saved credential, a service account, a phone with an
old Exchange password, a scheduled task. The lockout is the *symptom*; the goal is to name
the **device** and the **specific credential store** on it.

The investigation answers five questions in order. That order matters: each answer changes
how you read the next.

| # | Question | Evidence |
|---|----------|----------|
| 1 | **Can we trust this data?** | Audit policy on every DC |
| 2 | **Who is locking out?** | Event 4740 on the PDC emulator |
| 3 | **Why this account?** | 4625/4771/4776/4724 across all DCs + account state |
| 4 | **Which device?** | Source IP → DHCP lease → DNS → AD computer object → MAC vendor |
| 5 | **What do we fix?** | Ranked causes mapped to remediation |

---

## 2. THE CENTRAL DESIGN CONSTRAINT

> **An empty report and a healthy domain look identical.**

This is the single most important idea in the toolkit. If failure auditing is disabled on
the DCs, every query returns zero rows — and a report saying "no bad passwords found"
reads exactly like a clean bill of health. Investigations have been lost for days to this.

**Consequence for your design:** the audit-policy check is a *gate*, not a step. It runs
first, and when the DCs are not recording lockout events the run **stops** and says so
rather than producing confident-looking empty reports. There is a `-Force` to collect
anyway (useful for documenting the gap on a ticket).

Generalize this: **any collector must distinguish "I looked and found nothing" from "I
could not look."** Those produce identical empty result sets and opposite conclusions.
This distinction recurs constantly below — it is the source of most of the bugs found.

In C#, consider modelling it in the type system rather than by convention:

```csharp
public abstract record CollectionResult<T>
{
    public sealed record Found(IReadOnlyList<T> Items) : CollectionResult<T>;
    public sealed record EmptyButValid : CollectionResult<T>;      // looked, nothing there
    public sealed record CouldNotCollect(string Reason) : CollectionResult<T>;
}
```

A caller that pattern-matches cannot accidentally treat `CouldNotCollect` as "all clear".

---

## 3. Windows Security event facts (verified against Microsoft Learn)

These are the highest-value part of this document. **Do not write them from memory** —
several are counter-intuitive and each produced a real bug here. Cite the source in code
comments.

### Event 4740 — account locked out

- Written to the **PDC emulator**, which receives lockout events domain-wide. Query the
  PDC, not every DC.
- **The caller machine is in `TargetDomainName`.** There is *no* `CallerComputerName`
  element in the XML, even though Event Viewer displays the value under the label "Caller
  Computer Name."
- The account's own domain is in `SubjectDomainName`.

This one shipped as a bug: the code read `CallerComputerName`, got `null` for every event,
and rendered every lockout source as "(not recorded)". Worse, the *unit tests passed*,
because they fed synthetic XML containing the element that real events do not have.

> **Lesson:** build test fixtures from Microsoft's documented sample XML, not from your own
> mental model of the schema.

<https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740>

### Event 4625 — failed logon

- Source host in `WorkstationName`, IP in `IpAddress`, `LogonType` present.
- Prefer **`SubStatus`** over `Status` — `Status` is frequently the generic
  `0xC000006D`. **But** `SubStatus` is often `0x0`, which means *no error*; only prefer it
  when non-zero. Reporting `0x0` as the reason hides the real cause.

### Event 4771 — Kerberos pre-authentication failed

- **No `WorkstationName` and no `LogonType` at all.** Only `IpAddress`.
- The failure code shown as "Failure Code" is named **`Status`** in the XML.
- IPs arrive IPv4-mapped: `::ffff:10.0.0.12`. Normalize before joining against DHCP or DNS
  or nothing ever matches. `::1` → `127.0.0.1`.

Because 4771 carries no hostname, **address resolution is the only route to a device
name** for Kerberos failures — which is most of them in a modern domain.

### Event 4776 — NTLM credential validation

- Source machine is in **`Workstation`** (not `WorkstationName`). No IP field at all.
- **Written for BOTH success and failure.** `Status` `0x0` means *success*.

Treating every 4776 as a failure reports healthy machines as attackers. This is the
canonical example of why "the event fired" is not the same as "something went wrong."

### Status codes worth encoding

| Code | Meaning | Note |
|------|---------|------|
| `0x18` | Bad password (Kerberos) | the actual cause |
| `0x12` | Credentials revoked — disabled, expired, **or locked out** | a *consequence*, not a cause |
| `0x17` | Password expired | |
| `0x6`  | Username does not exist | |
| `0xC`  | Rejected by KDC policy (logon hours / workstation restriction) | |
| `0xC000006A` | Bad password (NTLM) | |
| `0x0` | **Success** | on 4776 and 4771 |

**`0x18` vs `0x12` is a real distinction.** In a live run, one IP produced 92 failures: a
handful of `0x18` (the bad passwords that caused the lockout) and the rest `0x12` (retries
against an account that was *already* locked). Merging them hides which attempts actually
drove the lockout. Group by status, never collapse it away.

### Audit subcategories

Event 4740 comes from **Audit User Account Management** (Success), *not* from the
similarly-named "Audit Account Lockout" — that one logs 4625 for logons against an
already-locked account and has **no Success events at all**. Checking the wrong subcategory
declares a blind DC healthy.

**Match on GUID, not display name** — display names are localized and matching by name
fails on a non-English DC. GUIDs are invariant:

```
{0CCE9235-…}  User Account Management        Success   → 4740, 4724
{0CCE9215-…}  Logon                          Failure   → 4625
{0CCE9242-…}  Kerberos Authentication Service Failure  → 4771
{0CCE923F-…}  Credential Validation          Failure   → 4776
{0CCE9217-…}  Account Lockout                Failure   → 4625 against locked account
```

Also check `SCENoApplyLegacyAuditPolicy`. Without it, legacy audit settings can override
Advanced Audit Policy, so `auditpol` reports correct values while the *effective* policy
differs.

---

## 4. Active Directory attribute semantics

**`badPwdCount`, `badPasswordTime`, and `lockoutTime` do NOT replicate.** Each DC holds
only what it personally processed. Consequences:

- To count bad passwords domain-wide you must poll **every DC** and sum, keyed by
  `(DC, Account)`. Keying by account alone makes one DC's reading overwrite another's.
- `badPwdCount` **resets** on that DC when the user successfully authenticates *there*. A
  falling counter means a successful logon, not negative activity. Naive subtraction
  reports `-4`, which reads as "the problem is fixing itself."
- These are *directory attributes*, so they work **even when auditing is completely
  disabled** — the one evidence source that survives a blind DC.

**`lockoutTime` is not a boolean.** A non-zero value does *not* mean currently locked. Per
[MS-ADTS], the `ADS_UF_LOCKOUT` bit is set only while the lockout duration has not
elapsed, and AD never clears `lockoutTime` on auto-unlock. Showing the raw timestamp reads
as "still locked" and sends helpdesk to unlock a working account. Sentinel values `0` and
`Int64.MaxValue` mean "never" — **not** `1601-01-01`.

Effective lockout policy must resolve **Fine-Grained Password Policy** via
`Get-ADUserResultantPasswordPolicy`, falling back to the default domain policy. An
aggressively low `LockoutThreshold` (3) is itself a common root cause.

---

## 5. Device identification — the highest-value step

Given a source IP, resolve what the machine actually *is*. Ranked by reliability:

| Method | Confidence | Caveat |
|--------|-----------|--------|
| Machine named itself in the event log | High | 4625/4776 only |
| AD computer object match | High | |
| DHCP lease covering the failure timestamp | High | **see below** |
| Reverse DNS | **Low** | a stale PTR names a machine that may no longer hold that address |
| MAC vendor (IEEE OUI) | Low | last resort, but often the only lead |

**DHCP trap:** `Get-DhcpServerv4Lease` returns only **ACTIVE** leases without `-AllLeases`.
Expired leases are exactly what you need for a failure that happened yesterday. Also check
the lease *covers the failure time* — an IP reassigned since then names the wrong device.
Reservations have no expiry, so the "expires" field is nullable.

**An unresolved source is a finding, not a blank.** No DHCP lease + no reverse DNS + no AD
computer object is informative: unmanaged devices, personal phones, and network appliances
all look exactly like that. Say so, and point at MAC vendor and switch ARP tables.

**Timing pattern separates a machine from a person.** Median gap between attempts:
sub-second bursts are a retry loop or an account sweep; irregular multi-hour gaps are
human. Same failure count, completely different remediation.

---

## 6. Two traps that produce confidently wrong answers

### The relay problem

In a real run the domain controller itself was the top source: **1,043 of 1,418 failures
across 16 accounts**, plus 47 more from `127.0.0.1`.

That is true and useless. A DC **re-presents credentials on behalf of other things** —
Pass-through Authentication agents validating Entra sign-ins, services, scheduled tasks —
so failures are recorded as originating there while the real device is elsewhere. Naming
the DC sends a technician to audit a domain controller for a stale credential that is not
on it.

**Treat DCs and loopback as relays:** exclude them from "top source", and exclude them
from spray detection. *16 accounts through a DC is aggregation; 16 accounts from one
workstation is a password spray.* Same number, opposite meaning.

### One source, many accounts

One device failing against many accounts is a **different problem** from one device
failing against one:

- Many accounts from an **unknown** device → possible password spray (security incident)
- Many accounts from a **domain-joined server** → one shared misconfigured credential
- Many accounts from a **gateway/NAT/PTA agent** → aggregated traffic, meaningless

The security reading must not be buried under a bigger failure count from a benign source.

---

## 7. Hybrid identity (Entra Connect)

Relevant because in a PTA environment the on-prem evidence is misleading on its own.

- **PTA agents validate passwords via the Win32 `LogonUser` API**, so cloud sign-in
  failures surface on a DC as ordinary 4625/4771 **sourced from the agent host**. Cloud
  brute-force looks like on-prem failures from your own server.
- **Password Hash Sync** logs to the **Application** log under source
  `Directory Synchronization`, event IDs `601`–`668`. Event **654** is the heartbeat,
  logged every ~30 min; Microsoft's own check looks for one **within three hours**.
  - Searching a 7-day window and only alarming when the *whole window* is empty means PHS
    could have died yesterday and still report healthy.
  - Events `0, 611, 652, 655` are documented together as **connectivity** problems — the
    sync server can't reach a DC. That *inverts* the conclusion: the server is not sending
    bad passwords, it is failing to read hashes.
- **Check whether PHS is even enabled** (`Get-ADSyncAADCompanyFeature`) before judging its
  health. A PTA-only tenant has no heartbeat *by design* — warning about it sends someone
  to fix a healthy server. Also check `StagingModeEnabled`, which suppresses PHS silently.
- Event IDs in the 600s are **not unique** to PHS in a shared Application log. Filter by
  provider name or an unrelated app's event 611 gets reported as a sync failure.

The Entra Connect server **cannot be discovered from AD** — it is not marked as such.
Guessing wrong queries an unrelated machine and reports its silence as a healthy sync, so
this must be operator-supplied and *skippable*.

---

## 8. Service-state semantics

"Not running" collapses three states that mean different things:

| State | Meaning |
|-------|---------|
| `NotFound` | not installed — for a PTA agent on a PHS-only server this is **correct** |
| `Error` | query failed — state is **unknown**, do not assert one |
| `Stopped` | queried successfully, genuinely down — **this is the finding** |

Reporting the first two as faults sends someone to fix a healthy server. Same principle as
§2: absence of evidence is not evidence of absence.

---

## 9. Output design

- **One combined HTML report.** Five separate reports plus CSVs produced a real complaint:
  *"which file do I open first?"* Tabs ordered by the investigation, findings on screen at
  open.
- **CSV for pivoting, HTML for reading.** A collector that emits only CSV effectively
  disappears from the report — that happened here, and the toolkit's best evidence was
  also its least visible for weeks.
- **Highlight the account under investigation.** Domain-wide steps deliberately report on
  every account (context is what makes one account's evidence interpretable), but say so,
  and mark which rows are the subject's.
- **Group repeated evidence.** 78 near-identical rows differing only by second is noise;
  the finding is "one source, one status, this many attempts, over this span" — one line,
  with raw events available underneath.
- **Never show a guess as a fact.** Confidence is a visible tag, not a buried field.

---

## 10. Mixed audience

Helpdesk staff and senior sysadmins use the same output. Plain-English labels, no internal
tokens (`EventLogCorrelation` → "the machine named itself in the event log"), but full
density and precision for people who run it daily. Every conclusion should name the
evidence behind it so an expert can audit the reasoning.

---

## 11. If you reimplement in C#

- `System.Diagnostics.Eventing.Reader.EventLogQuery` / `EventLogReader` for remote event
  log reads; `System.DirectoryServices.Protocols` or `System.DirectoryServices.AccountManagement`
  for AD.
- **Push filtering to the server.** Fetching everything and filtering client-side across a
  WAN is the difference between seconds and minutes. One measured trap: an XPath predicate
  on `EventData` that matches nothing forces a **full log scan** (742,767 records → 52s),
  while a time-bounded query is served from the time index. Prefer time bounds + event ID,
  filter fields in memory.
- Wrap every per-server call in its own try/catch — one unreachable DC must not abort the
  run. Record *which* server failed and surface it; a silently skipped DC is a hole in the
  evidence that looks like clean data.
- Parallelize per-DC collection; the work is IO-bound and embarrassingly parallel.

---

## 12. Test strategy that actually caught things

- **Pure functions for every interpretation step** (classification, ranking, verdicts,
  formatting) so they test without a domain.
- **Regression tests that encode the *documented fact*, with the source URL in a comment.**
  When docs contradict the code, fix the code and add a test so the wrong version cannot
  silently return.
- **Fixtures from Microsoft's published sample XML**, not from memory — the 4740 bug
  survived precisely because a hand-written fixture agreed with the wrong code.
- **Assert on real-world shapes.** Several bugs (`System.Object[]` in a CSV column, a
  non-recursive file lookup after files were moved into subfolders) only appeared against
  real output. They all degraded *quietly* — the run reported success.

If there is one habit worth carrying over: **for every collector, ask what it emits when it
could not look, and make that different from what it emits when it looked and found
nothing.** Nearly every bug in this toolkit's history was a variation of that.
