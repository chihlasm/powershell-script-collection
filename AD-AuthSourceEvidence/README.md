# AD Authentication Source Evidence

Exports authentication failure evidence from every domain controller and resolves each
source IP address to an actual device — hostname, MAC address, hardware vendor, and
domain membership.

Answers **"which physical device is generating these bad passwords?"** across the whole
domain, so you can match an IP address in a security log to a machine you can go and fix.

## Why this exists

The Windows Security log records authentication failures, but no single event gives you
both a reliable IP address *and* a machine name:

| Event | What it gives you | What it does **not** give you |
|-------|-------------------|-------------------------------|
| **4625** Failed logon | `WorkstationName`, `IpAddress`, `IpPort`, `LogonType`, `ProcessName` | — (richest event) |
| **4771** Kerberos pre-auth failed | `IpAddress`, `IpPort` | **No workstation name. No logon type.** |
| **4776** NTLM credential validation | `Workstation` **name** | **No IP address at all.** |
| **4740** Account locked out | Caller machine **name** | **No IP address — ever**, even for non-domain devices. |

So a Kerberos-only source shows up as a bare IP with no name, and an NTLM-only source
shows up as a bare name with no address. Correlating the two — and then resolving what's
left against DHCP, DNS and AD — is what this script does.

## How a source gets identified

Every distinct source IP runs through independent resolution sources in order, stopping
at the first that answers. The method that answered is recorded alongside the result, so
you know how much to trust the name.

| # | Source | What it adds | Confidence |
|---|--------|--------------|------------|
| 1 | **DHCP lease / reservation** | Hostname **and MAC address**, lease expiry, scope | High / Medium |
| 2 | **Reverse DNS (PTR)** | Hostname | **Low** — PTR records go stale |
| 3 | **AD computer object** | OS, OU, last logon, enabled state | Medium |
| — | *Event log correlation* — a successful 4624/4768 from the same IP | Machine name recorded by the DC itself | **High**, but **off by default** — see below |

The MAC address matters most: it survives a DHCP renewal, it matches a switch MAC table,
and its OUI prefix identifies the hardware vendor. A Fortinet or SonicWall OUI tells you
the address is a **gateway**, not the culprit — the real device is NATed behind it. The
script calls this out explicitly, because chasing a phantom desktop at the firewall's
address is the most expensive wrong turn available in a lockout investigation.

Each source is then classified: `DomainJoinedWorkstation`, `Server`, `DomainController`,
`NetworkDevice`, `NonDomainDevice`, `LocalOrConsole`, or `Unknown`.

### Why event-log correlation is off by default

Naming a bare IP from successful logons is the highest-confidence resolution available,
and it was this script's original centrepiece. It is disabled anyway, because on a real
production DC it made the export unusable.

Measured on a DC holding **742,767 Security records** (1 GB circular log, 4.2 days
retention, ~29 unnamed IPs over a 7-day window):

| Query shape | Time |
|---|---|
| `FilterHashtable` Id=4624 + StartTime | 0.9s — indexed time seek |
| XPath with `timediff()` time bound | 0.9s — **not** the culprit |
| XPath `EventData` IP filter, no match | **11.2s** — full log scan |
| XPath `timediff` + 10 IPs (20 OR terms), no match | **52.0s** — full log scan |
| `FilterXml`, SystemTime range + EventData, no match | **52.9s** — full log scan |
| Trivial 5-event query | 0.3s — remoting is fine |

An `EventData` predicate that matches **nothing** cannot stop early — the log must read
every record to prove absence. So cost scales with the number of addresses you *cannot*
resolve, which is exactly the population the pass exists to serve. A single
`StartTime`-bounded sweep was written to replace it and still stalled on this DC, so
reading 4624 events at all is expensive here for reasons query shape doesn't explain.

Correlation is **enrichment, not evidence.** DHCP supplies a hostname *and* the MAC
address, and an unresolved source still carries its full failure counts, account list and
timestamps. Blocking an evidence export on an optional nicety is the wrong trade.

Turn it on with `-EnableCorrelation` where reading successful logons is known to be fast.

## Usage

```powershell
# Last 7 days, all DCs, both CSVs into .\Reports\
.\Export-ADAuthSourceEvidence.ps1

# Two weeks, only sources responsible for 5+ failures
.\Export-ADAuthSourceEvidence.ps1 -DaysBack 14 -MinFailures 5

# Explicit targeting
.\Export-ADAuthSourceEvidence.ps1 -DomainController DC01,DC02 -DhcpServer DHCP01 -OutputPath C:\Evidence

# AD lookups only — no DHCP or DNS dependency
.\Export-ADAuthSourceEvidence.ps1 -SkipDhcp -SkipDns

# Also name bare IPs from successful logons (slow on busy DCs — read the note below)
.\Export-ADAuthSourceEvidence.ps1 -EnableCorrelation
```

### Parameters

| Parameter | Default | Notes |
|-----------|---------|-------|
| `-DaysBack` | 7 | 1–90. Large windows on a busy domain produce very large exports. |
| `-OutputPath` | `.\Reports\` | Beside the script, not the working directory. |
| `-DomainController` | auto-discovered | Overrides `Get-ADDomainController -Filter *`. |
| `-DhcpServer` | auto-discovered | Overrides `Get-DhcpServerInDC`. Use when DHCP runs on unregistered or non-Windows equipment. |
| `-SkipDhcp` | off | Skip DHCP entirely. |
| `-SkipDns` | off | Skip reverse DNS. Saves a timeout per unresolvable IP. |
| `-EnableCorrelation` | **off** | Name bare IPs from successful logons. Off by default — stalls on busy DCs. |
| `-CorrelationMaxEvents` | 20000 | Caps the correlation sweep per DC. Only with `-EnableCorrelation`. |
| `-UseTargetedCorrelation` | off | Legacy per-IP correlation queries. Only with `-EnableCorrelation`. |
| `-IncludeSuccesses` | off | Include successful logons in the events CSV. Reads 4624 events, so it carries the same slowness risk as correlation. |
| `-MinFailures` | 1 | Minimum failures for a source to appear in the sources CSV. |
| `-ThrottleLimit` | 4 | How many DCs to query at once. Set 1 for serial collection when diagnosing a slow DC. |
| `-InventoryCsv` | — | Join against your own RMM/Intune/asset export. Columns are auto-detected. |
| `-OuiDatabasePath` | — | Local copy of IEEE `oui.txt` for full MAC vendor coverage. |

## Output

Two CSVs, both timestamped `yyyy-MM-dd_HHmmss`:

**`AuthSources_<timestamp>.csv`** — the short list you actually work from. One row per
distinct source device, ranked by failure count:

> `SourceKey`, `SourceIp`, `ResolvedName`, `DeviceClass`, `Confidence`,
> `ResolutionMethod`, `MacAddress`, `MacVendor`, `FailureCount`, `DistinctAccounts`,
> `Accounts`, `TopStatus`, `LogonTypes`, `EventIds`, `FirstSeen`, `LastSeen`, `DCsSeen`,
> `NamesSeenInLog`, `ReverseDnsName`, `DhcpLease`, `DeviceDetail`, `AdOperatingSystem`,
> `AdLastLogonDate`, `AdEnabled`, `AdDescription`, `AdDistinguishedName`, `TotalEvents`

**`AuthEvents_<timestamp>.csv`** — raw evidence, one row per event, with the resolution
columns joined on so you can pivot on device *or* account:

> `Time`, `DC`, `EventId`, `Account`, `AccountDomain`, `SourceHost`, `SourceIp`,
> `SourcePort`, `ResolvedName`, `DeviceClass`, `Confidence`, `MacAddress`, `MacVendor`,
> `LogonType`, `LogonTypeMeaning`, `StatusCode`, `StatusMeaning`, `IsFailure`,
> `ProcessName`, `AuthPackage`, `ServiceName`, `TargetSid`

`DistinctAccounts` is the field worth sorting on after `FailureCount`: one device hitting
many accounts is a shared machine with a stale credential, a scanner, or a gateway — a
different problem from one device hitting one account.

## Read this before trusting an empty result

**An empty export and a clean domain look identical.** If failure auditing is disabled on
the DCs, these events were never written, and no search window will find them.

Run [`Test-ADAuditPolicy.ps1`](../AD-LockoutDiagnostics/Test-ADAuditPolicy.ps1) **first**.

The script also reports how far back each DC's Security log actually reaches. A 30-day
request against a log that holds 4 days returns 4 days and warns you it did — use
[`Set-DCSecurityLogRetention.ps1`](../AD-LockoutDiagnostics/Set-DCSecurityLogRetention.ps1)
to size the logs for longer investigations.

## Watching a lockout live

Everything else here is retrospective. `Watch-ADLockoutActivity.ps1` shows attempts **as
they happen** — the thing to leave running on a second monitor while a user retries:

```powershell
# Watch everyone with bad-password activity, all DCs, every 15s
.\Watch-ADLockoutActivity.ps1

# Watch one account closely and record what you see
.\Watch-ADLockoutActivity.ps1 -Identity jdoe -IntervalSeconds 5 -LogPath .\watch.csv

# Run for half an hour then stop
.\Watch-ADLockoutActivity.ps1 -DurationMinutes 30
```

```
TIME      ACCOUNT              DC                 NEW  COUNT
16:21:14  jdoe                 DC01               +3   (5/10)
16:21:44  jdoe                 DC02               +3   (3/10)  [first reading]
16:22:14  jdoe                 DC01               +1   (1/10)  [counter reset - successful logon, then new failures]
16:22:44  jdoe                 DC02               +7   (10/10)  *** LOCKED OUT ***
```

**It polls `badPwdCount`, not the event log.** Two consequences worth knowing:

1. **It works when auditing is off** — `badPwdCount` is a directory attribute, so this
   still sees attempts in the exact situation that makes every other report here empty.
2. **It's cheap and bounded** — one LDAP read per account per DC per poll. Nothing touches
   an event log, which is what made correlation unusable on a busy DC.

Two documented facts about `badPwdCount` shape the output, and both are easy to get wrong:

- **It doesn't replicate.** Each DC keeps its own counter, so all DCs are polled and
  tracked separately — which also tells you *which DC* is receiving the attempts.
- **It resets on successful logon to that DC.** A falling counter means the user just got
  in, not that the problem fixed itself. Shown as `[counter reset]`, never as negative
  activity.

The poll interval has a hard 5-second floor, enforced in code — a tighter loop against
every DC is the one way this tool could put load on a domain controller.

## Cross-referencing your own inventory

`-InventoryCsv` joins each source against records you already hold — an RMM export, an
Intune device list, an asset spreadsheet, a switch MAC table:

```powershell
.\Export-ADAuthSourceEvidence.ps1 -InventoryCsv C:\Exports
mm-devices.csv
```

**Column names are detected, not required.** Hostname (`ComputerName`, `Device Name`,
`Hostname`, `Machine`...), MAC (`MAC Address`, `macaddress`, `Physical Address`...) and IP
(`IPAddress`, `IPv4 Address`...) are recognized in any capitalization or spacing. Every
column of a matched row is added to the sources CSV prefixed `Inv_`, so whatever your
inventory carries — owner, location, asset tag, last check-in — comes along.

Matching is strongest-first, and the key that matched is recorded in `InventoryMatchedOn`:

| Key | Why | Caveat |
|---|---|---|
| **MAC** | Survives renames, re-imaging and DHCP changes | Needs DHCP to have supplied it |
| **Name** | Reliable when both sides agree | Misses a machine renamed since the export |
| **IP** | Last resort | Addresses get reassigned — weakest key |

MAC formats are normalized, so a Cisco-style `0009.0f11.2233` in a switch table matches a
DHCP `00-09-0F-11-22-33`.

## Timing patterns

Each source is classified by the rhythm of its failures, which separates a machine from a
person before any other evidence is considered:

- **Regular** — evenly spaced (e.g. every 30 minutes): a service, scheduled task, or sync
  client retrying on a timer. People don't retry on the dot.
- **Burst** — many attempts within moments: a retry loop, or a spray working an account list.
- **Irregular** — no rhythm; consistent with human activity.

Fewer than three events reports `Insufficient` rather than guessing.

## Multi-user lockouts

**No username is needed anywhere in this toolkit.** Both scripts work from the source
*device* and the accounts it hit, so a domain-wide run and a single-user investigation
take exactly the same path.

That matters, because when one device is hitting many accounts the account count is
raised as the *first* finding — it reframes everything under it:

| Evidence | Reading | Fix |
|---|---|---|
| 28 accounts, unknown device | **Possible password spray** — a security concern | Identify and isolate the device; review for compromise |
| 14 accounts, domain-joined file server | One shared misconfiguration | Find the *single* stale service/task/login-script credential |
| 12 accounts, Fortinet gateway | Aggregated traffic from many real clients | Check NAT/VPN logs; check RADIUS/LDAP integration for a stale credential |
| 1 account, workstation | Ordinary per-user stale credential | `net use`, `cmdkey /list` on that machine |

The middle row is the one that saves the most time: thirty users with thirty stale mapped
drives is thirty tickets, but thirty users behind one server with a stale scheduled task
is **one**.

Microsoft notes a password spray
"[looks like an isolated failed login](https://learn.microsoft.com/security/operations/incident-response-playbook-password-spray)"
from any individual user's perspective — which is exactly why a per-account investigation
can't see it, and a per-device view can.

## Lease-time accuracy

A DHCP lease is only authoritative for the window it covered. Matching a two-week-old
failure against *today's* lease would state as fact something the data can't support — on a
busy scope that address may have belonged to a different machine at the time.

Each source's lease is therefore checked against its last failure time. A lease that
expired before the failure is **downgraded to Low confidence**, with the reason recorded in
`LeaseCoverageNote`. Reservations are exempt — they're fixed mappings with no expiry.

Collection also uses `-AllLeases`, because `Get-DhcpServerv4Lease` returns only *active*
leases by default — and an expired lease is exactly what an old failure needs.

## If the export stalls

Two diagnostics ship beside the script. Both cap every query with a timeout, so neither
can hang the way the export did:

```powershell
# Times each query shape against the real Security log
.\Debug-CorrelationQuery.ps1 -ComputerName DC01

# Tests whether MATCHING EventData queries are fast on this DC
.\Debug-CorrelationQuery2.ps1 -ComputerName DC01
```

A default run reads only 4625/4771/4776/4740. If *that* stalls, narrow it down:

```powershell
.\Export-ADAuthSourceEvidence.ps1 -SkipDhcp -SkipDns   # DC collection + AD only
```

## Companion tools

This script deliberately does **not** judge — it emits evidence for cross-referencing
against inventory you already hold (RMM, Intune, switch MAC tables, VPN logs). For ranked
verdicts, see [`AD-LockoutDiagnostics`](../AD-LockoutDiagnostics/):

| Tool | Question it answers |
|------|---------------------|
| `Test-ADAuditPolicy.ps1` | Is anything being logged? **Run first.** |
| `Get-ADLockoutHistory.ps1` | Which *accounts* are locking out, domain-wide? |
| `Diagnose-ADAccountLockout.ps1` | Why is *this* account locking out? |
| `Invoke-ADLockoutForensics.ps1` | Which DC/forest is receiving the bad passwords? |
| **`Export-ADAuthSourceEvidence.ps1`** | **Which *device* is the source?** |
| **`Watch-ADLockoutActivity.ps1`** | **Is it happening right now, and on which DC?** |
| **`Get-LockoutCause.ps1`** | **What should be fixed?** |

## Requirements

- PowerShell 5.1+
- RSAT `ActiveDirectory` module
- RSAT `DhcpServer` module (optional — skipped gracefully if absent)
- Permission to read the Security event log on each domain controller
- Read access to DHCP servers for lease lookups

Read-only. Makes no changes to AD, DHCP or DNS.

## Tests

```powershell
Invoke-Pester -Path .\Tests -Output Detailed
```

41 tests covering event field extraction for all four event IDs, IP normalization,
OUI vendor lookup, device classification, source grouping, and confidence rating.

The event-parsing tests exist specifically to lock in field names transcribed from
Microsoft Learn. Three of them guard against mistakes that have already caused real
misreporting:

- **4740's caller machine is in `TargetDomainName`** — there is no `CallerComputerName`
  element, despite Event Viewer displaying that label.
- **4776 status `0x0` means success** — the event is written for both outcomes; treating
  its presence as failure reports healthy machines as the top attacker.
- **4771 client addresses arrive as `::ffff:10.0.0.12`** — unnormalized, they never match
  a DHCP lease or PTR record.

## References

Every documented constant in this script is transcribed from Microsoft Learn, not recalled.
Verified 2026-08-20.

- [Event 4625 — An account failed to log on](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625)
- [Event 4771 — Kerberos pre-authentication failed](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4771)
- [Event 4776 — The computer attempted to validate the credentials for an account](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4776)
- [Event 4740 — A user account was locked out](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740)
- [Event 4624 — An account was successfully logged on](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624)
- [NTSTATUS values](https://learn.microsoft.com/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [Get-DhcpServerInDC](https://learn.microsoft.com/powershell/module/dhcpserver/get-dhcpserverindc)
- [Get-DhcpServerv4Lease](https://learn.microsoft.com/powershell/module/dhcpserver/get-dhcpserverv4lease)
- [IEEE OUI registry](https://standards-oui.ieee.org/oui/oui.txt)
