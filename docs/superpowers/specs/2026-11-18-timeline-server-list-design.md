# Server Event Timeline: the server list

Date: 2026-11-18. Owner: Michael. Tool: `Server-EventTimeline/`.

## Why

The "WHICH SERVERS?" card is one 58 px free-text box with three buttons below it, and it feels
cramped and unclear. Problems with it today:

- **You can't see what you've got.** There's no count, no sign of which name is a typo, and
  the only way to remove a server is to edit the text.
- **It doesn't say whether IP addresses work.** They do, but slowly (see "IP addresses").
- **AD search adds results blind.** "Pick from AD... > Find servers by name..." opens a VB
  InputBox and appends every match (up to 200) without showing them. Michael wants to find
  servers and then choose which to add.

The intent: add one server at a time with autocomplete, and use a pop-up dialog for adding or
importing many at once.

## Goals

- Add one server at a time. Type a name or IP, get suggestions, and press Enter or click Add.
- Show the chosen servers as a list (layout B, chosen over a chip/tag layout). There's one row
  per server: the name, a short muted note, and an × to remove it. A count goes in the card
  header ("3 servers"), and a Clear button empties the list.
- Autocomplete from Active Directory. Every enabled server computer object is loaded once, in
  the background, when the window opens (option 1). Typing filters that list instantly.
  Servers searched before (from the Recent lists) are suggested too.
- Make IP addresses first-class. An IP is accepted, a reverse DNS lookup finds its name, the
  row shows `10.0.4.21` with the note `IP · is SQL01`, and the search uses the name.
- "Add several..." opens a dialog with three tabs: **Paste**, **Find in AD** and **From a
  file**. All three fill one result list with tick boxes, and an "Add N servers" button adds
  the ticked ones.
- Keep **This computer** and **Recent** as buttons under the list.
- Add a **Domain** choice, so autocomplete and Find in AD can read a client's AD from an
  MSP-joined workstation over VPN (Michael's choice, option b below).
- Build everything in this document. Nothing is planned to slip: Michael said there's
  plenty of time before Friday.

## Non-goals

- Per-server export files. Michael asked about them, but they're a separate small change after
  this one: a "One file / One file per server" choice beside the export buttons, with
  combined as the default.
- Changing how servers are read (the engine, transports, time zones).
- Saved named server groups per client. Recent lists keep doing that job.
- Autocomplete from anything other than AD and Recent (no DNS zone walking, no RMM).

## Anti-goals (this would be a failure even if it works)

- The window freezes while AD or DNS is slow. On a VPN to a client's domain, every AD and DNS
  call must run off the UI thread.
- You can't add a server that isn't in AD. Typed names and IPs are always accepted. Lookups
  only add notes, never block.
- The card grows so tall that the event grid loses noticeable space.
- Lookups fail without saying so. If AD can't be reached, a note says so ("Suggestions from
  Active Directory aren't available: (reason)"), and typing still works.

## Constraints

- **PowerShell 5.1** (`#Requires -Version 5.1` on all three scripts). WPF XAML in
  `Start-ServerEventTimeline.ps1`. Logic goes in `ServerEventTimeline.Core.ps1` as pure
  functions with Pester tests. The window code stays thin.
- **Self-contained folder.** Nothing outside built-in Windows/RSAT. The ActiveDirectory module
  is imported at run time in try/catch, as `Get-AdServerCandidates` already does. Where RSAT
  isn't installed, AD features are disabled with a tooltip explaining why, as the "Pick from
  AD" button does today.
- **Background work** uses a runspace (the engine already uses a RunspacePool in
  `ServerEventTimeline.Engine.ps1`). The existing 250 ms DispatcherTimer heartbeat collects
  the results.
- **Tests never touch AD, DNS or the clipboard.** Mock `Get-ADComputer`,
  `Get-ADDomainController` and the DNS lookup, with stub functions using the real parameter
  names.
- **The smoke test must still pass**: no control cut off, the new controls built, no AD
  query in smoke mode.
- **Plain English** in every label. Dark theme brushes from the existing resources (`Card`,
  `Input`, `Line`, `Muted`, `Accent`, `Warn`, `Danger`).
- **The deadline is Friday 2026-11-20.**

## Approaches considered (autocomplete source)

1. **Load all servers from AD once when the window opens (chosen).** One `Get-ADComputer`
   query in the background, then local filtering while typing, so it's instant even over VPN.
   The cost is that a server added to AD while the window is open isn't suggested, though it
   can still be typed in full.
2. **Query AD each time typing pauses.** Always fresh, but laggy over VPN, with many queries.
3. **No AD while typing; Recent only, with AD only in the dialog.** Simplest, but weakest the
   first time you work on a client.

Michael picked option 1 because it feels instant on a remote client's network.

## Approaches considered (which domain to read)

- **(a) Always the workstation's own domain.** Simplest. Wrong when the tech is on an
  MSP-joined machine on a VPN into a client's network: it would suggest the MSP's servers.
- **(b) A Domain choice, defaulting to the workstation's domain (chosen).** The tech can type
  a client's domain or DC. The load uses that target and the Run as account, and reloads
  when either changes.

## Design

### The card (layout B)

```text
WHICH SERVERS?                                   3 servers
┌───────────────────────────────────────────┐ ┌─────┐
│ Type a server name or IP address          │ │ Add │
└───────────────────────────────────────────┘ └─────┘
  ┌ suggestions (as you type) ─────────────────┐
  │ FS01.contoso.local          Server 2019    │
  │ FS02.contoso.local          Server 2012 R2 │
  └────────────────────────────────────────────┘
┌───────────────────────────────────────────────────┐
│ DC01.contoso.local        domain controller    ×  │
│ DESKTOP-VMF5I1C           this computer        ×  │
│ 10.0.4.21                 IP · is SQL01        ×  │
└───────────────────────────────────────────────────┘
[Add several...] [This computer] [Recent ▾] [Clear]
```

- **Input:** a single-line TextBox with a watermark ("Type a server name or IP address").
  - **Enter** or **Add** adds what's typed. Pasting text that contains commas, spaces or new
    lines adds each name (run through `ConvertTo-ServerList`).
  - **Down/Up** move through the suggestions, **Enter** takes the highlighted one, and **Esc**
    closes them.
- **Suggestions:** a Popup under the input showing up to 8 matches. A suggestion matches when
  the typed text is contained in the name (case-insensitive), and names starting with the
  text come first. Each row shows the DNS name and the OS, or "searched before" for a Recent
  entry. There are no suggestions until AD has loaded; Recent entries show straight away.
- **List:** a ListBox with an item template showing the name, the note and an × button.
  - It's about 4 rows tall and scrolls after that. The card height shouldn't grow beyond
    today's roughly 110 px of content by more than about 40 px.
  - Duplicates are ignored, case-insensitively, the same way local names are folded today
    (localhost, `.`, the FQDN and 127.0.0.1 all become this computer).
- **Domain:** a small line under the card header: `Suggestions from: contoso.local
  (412 servers) [Change...]`.
  - "Change..." takes a domain name or a DC name, and an empty value means the workstation's
    own domain. The value is remembered per user in settings.json, next to SaveFolder.
  - On a workstation joined to no domain, the line reads `Suggestions from: no domain
    [Choose...]`, and only Recent suggestions are shown until a domain is chosen.
  - While loading, it reads `Loading servers from contoso.local...`. On failure it reads
    `Couldn't read contoso.local: <reason>`, in the Warn colour.
- **Notes**, worked out off the UI thread and filled in when ready:
  - `domain controller`, `this computer`, or the OS from AD
  - `IP · is <name>` when a reverse lookup succeeds, or `IP · no name found` when it doesn't
  - `not in AD` when AD is loaded and no computer account has that name. This uses the Warn
    colour; it's only a heads-up, and the server is still searched.
    - It's checked only for short names and for full names whose DNS suffix is the loaded
      domain. A full name in another domain gets no note, so servers from a domain that
      isn't loaded aren't all flagged.
    - Disabled accounts get the note `disabled in AD`, in the Warn colour.
  - Empty while a lookup is still running
- **Count** goes in the header ("1 server" / "N servers"). **Clear** empties the list. With
  more than 3 servers it asks first. Not sure; see the open calls.
- **Recent ▾** keeps its menu. Picking a list **replaces** the list, as today.
- **Search** reads the list, not a text box. The internal interface stays a string array:
  build the text that `ConvertFrom-TimelineInputs -ServersText` takes from the list, so the
  validation and local-name folding are reused unchanged.
- **IP addresses at search time.** The reverse lookup's name is trusted only if a forward
  lookup of that name returns the same IP (Claude's call: a stale PTR record must never
  search the wrong server).
  - **Trusted:** the row shows `10.0.4.21 → SQL01.contoso.local`. The search, results,
    exports and Recent all use the full DNS name, so Kerberos and WinRM work.
  - **Not trusted, or no name:** the row shows `IP · no name found` or `IP · name doesn't
    match`, and the search uses the IP. The engine falls back to the remote event log (RPC),
    which accepts an IP with the signed-in account. WinRM with an IP needs TrustedHosts or
    HTTPS, plus an explicit credential
    (<https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_remote_troubleshooting#how-to-use-an-ip-address-in-a-remote-command>).
- `-ComputerName` on the command line pre-fills the list, as it pre-fills the box today.

### "Add several servers" dialog

A modal WPF window owned by the main window, about 460 × 520, with three tabs. All three fill
one shared results list:

```text
┌ Add several servers ───────────────────────────┐
│ [Paste] [Find in AD] [From a file]             │
│ ...tab content...                              │
│ ┌───────────────────────────────────────────┐  │
│ │ ☑ FS01.contoso.local          in AD       │  │
│ │ ☑ 10.0.4.21                   IP · SQL01  │  │
│ │ ☐ PRNT-01   not found in AD or DNS        │  │
│ └───────────────────────────────────────────┘  │
│ [Tick all] [Tick none]   4 of 5 ticked  [Add 4 servers] [Cancel] │
└────────────────────────────────────────────────┘
```

- **Paste:** a multi-line box. Its text is parsed with `ConvertTo-ServerList`, and the results
  list updates when you pause typing or press "Check names". Each name is checked against the
  loaded AD list, then DNS.
  - Names found are ticked.
  - Names found in neither AD nor DNS are **unticked**, with the reason "not found in AD or
    DNS". You can still tick them.
- **Find in AD:** a search box and three scope choices: **All servers** (the default),
  **Domain controllers**, and **In an OU...** (pick the OU from a list of the domain's OUs).
  - Results come from the list already loaded at window open, filtered locally. The OU scope
    filters on the DistinguishedName, so there's no new query.
  - Each row shows the DNS name and OS. Rows are ticked by default, except accounts with no
    sign-in for more than 30 days, which are unticked with the note "no sign-in for N days".
  - `lastLogonTimestamp` only updates when the old value is more than
    `msDS-LogonTimeSyncInterval` (14 days by default, less a random 0–5) out of date
    (<https://learn.microsoft.com/windows/win32/adschema/a-lastlogontimestamp>). So "N days"
    is accurate to roughly two weeks, which is why the threshold is 30 days and not less.
- **From a file:** "Choose file..." for a .txt or .csv.
  - A .txt has one name or IP per line; blank lines and lines starting with # are skipped.
  - For a .csv, the first header matching Name, ComputerName, DNSHostName, HostName, Server or
    IPAddress is used, case-insensitively. That precedence is a builder's call to refine.
    If none matches, a column picker lists the headers.
  - Results are then checked like Paste.
- **Add N servers** appends the ticked names to the main list, skipping duplicates, and closes
  the dialog. The old "more than 25, are you sure?" prompt goes away, because ticking replaces
  it.

### Background lookups

- **AD load at window open**, in one runspace, against the chosen Domain (`-Server`) with the
  Run as credential when one is set. It reloads when the Domain or Run as changes.
  - Query: `Get-ADComputer -Filter * -Properties DNSHostName, OperatingSystem,
    lastLogonTimestamp, DistinguishedName, Enabled`. Every computer account is loaded
    (Claude's call), so "not in AD" means the account really doesn't exist.
  - Suggestions and Find in AD's "All servers" show only enabled accounts whose
    OperatingSystem contains "Server". The paste and file checks use the whole set.
  - Also `Get-ADDomainController -Filter *` to mark the DCs.
  - Parameters to verify on Learn while building, as the repo requires. `-ResultSetSize` is
    the real name; the mock-parameter lesson from `Get-ADUser` applies.
  - Kept in memory for the window's life. The status line says "Loaded N servers from Active
    Directory" or why it couldn't load.
  - Not run in `-SmokeTest`.
- **DNS:** a reverse lookup for IPs (`[System.Net.Dns]::GetHostEntry`) and a forward check for
  names not found in AD. Both run in the background with a short timeout, and results update
  each row's note.
- **Heartbeat:** the existing 250 ms timer returns early when no search is running. It must
  also collect the AD load and DNS results when no search is running.

## Left to the builder (marked as Claude's calls; Michael can override)

- The exact CSV header precedence, and whether to strip a `\\` or a domain prefix such as
  `CONTOSO\` from file entries.
- Whether Clear asks first above 3 servers. The proposal is yes, because it's one click away
  from losing a hand-built list.
- The OU picker's form: a flat list of OU paths with a filter box is enough.
- How long the DNS timeout is, and how many lookups run at once.
- Removing the VB InputBox code path ("Find servers by name...") and `Get-AdServerCandidates`
  once the dialog replaces them. Keep `Add-ServerNames` if it's still useful.

## Testing

- Pure functions in Core, with Pester tests:
  - matching and ranking suggestions
  - CSV/TXT parsing with header detection
  - building notes from AD, DNS and local data
  - list add/remove/dedupe, including local-name folding
  - the 30-day stale check
- AD and DNS are mocked; no real directory is touched.
- The smoke test checks the new controls exist and nothing is cut off at the right edge.
- The README section "Which servers?" is updated, including the plain-English IP explanation.
