# Server Event Timeline Server List Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the "WHICH SERVERS?" free-text box with a server list. The list is filled
one server at a time with autocomplete from a chosen domain's AD, accepts IP addresses, and
has an "Add several servers" dialog with Paste, Find in AD and From a file tabs.

**Architecture:** The logic goes in a new `ServerEventTimeline.ServerList.ps1`: directory
entries, suggestions, notes, the list model, file parsing, and background AD and DNS jobs.
It is dot-sourced by `ServerEventTimeline.Core.ps1`, so the engine, the window and the tests
all get it. The dialog goes in a new `ServerEventTimeline.AddServersDialog.ps1`, dot-sourced
by `Start-ServerEventTimeline.ps1`. The window keeps the list as a collection of item
objects, and turns it into the same server-text string that `ConvertFrom-TimelineInputs`
already validates. Background AD and DNS work runs in its own runspace, and the existing
250 ms heartbeat collects it.

**Tech Stack:** Windows PowerShell 5.1 / PowerShell 7, WPF (XAML via XamlReader), RSAT
ActiveDirectory imported at run time, Pester 5.

**Spec:** `docs/superpowers/specs/2026-11-18-timeline-server-list-design.md`

## Global Constraints

- `#Requires -Version 5.1` on every new script; no `#Requires -Modules`. ActiveDirectory is
  imported at run time with `Import-Module ActiveDirectory -ErrorAction Stop` inside
  try/catch.
- Never block the UI thread on AD or DNS. All lookups run in a runspace and are collected by
  the DispatcherTimer.
- Typed names and IPs are always accepted. Lookups only add notes.
- Tests never touch AD, DNS, the clipboard, or real settings. Inject fake loader and lookup
  scriptblocks (the same pattern as the engine's `-ProbeScript`/`-LogScript`). Point settings
  paths at `$TestDrive`.
- AD cmdlet parameters (verified with `Get-Command`):
  - `Get-ADComputer -Server -Credential -Filter -Properties -ResultSetSize`
  - `Get-ADDomainController -Server -Credential -Filter`
  - `Get-ADDomain -Server -Credential`
- `lastLogonTimestamp` updates only when the old value is more than
  `msDS-LogonTimeSyncInterval` (14 days by default, less 0–5) out of date. Cite
  <https://learn.microsoft.com/windows/win32/adschema/a-lastlogontimestamp>. A value of 0,
  null or Int64.MaxValue means never (repo `CLAUDE.md`). The stale threshold is **30 days**.
- WinRM with an IP needs TrustedHosts or HTTPS plus `-Credential`. Cite
  <https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_remote_troubleshooting#how-to-use-an-ip-address-in-a-remote-command>.
- UI copy, exactly:
  - watermark "Type a server name or IP address"
  - header count "1 server" / "N servers"
  - `Suggestions from: <domain> (<N> servers)`, `Loading servers from <domain>...`,
    `Couldn't read <domain>: <reason>`, `Suggestions from: no domain`
  - notes `domain controller`, `this computer`, `<OS>`, `IP → <fqdn>` (the row text, see
    Task 2), `IP · no name found`, `IP · name doesn't match`, `not in AD`, `disabled in AD`,
    `no sign-in for N days`, `not found in AD or DNS`
  - button "Add N servers"
- Brushes from the existing XAML resources only: `Card`, `Input`, `Line`, `LineStrong`,
  `Text`, `Muted`, `Accent`, `Warn`, `Danger`.
- Save any file containing a non-ASCII character (such as `→` or `·`) as UTF-8 **with BOM**
  (`Tests/ScriptEncoding.Tests.ps1`).
- Gates:
  - `pwsh -File Tests\Invoke-AllTests.ps1 -Path .\Server-EventTimeline\Tests`
  - `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Tests\Test-ScriptParse.ps1`
  - `-SmokeTest` on both `powershell` and `pwsh`
  - full suite at the end

## Review Focus

1. **Pasting "FS01, FS02\nFS03" into the single-line input.** It should add three rows, not
   one row named "FS01, FS02 FS03". Pinned in Task 5.
2. **An AD load that is still running, or that failed, when the tech types or opens the
   dialog.** Suggestions should fall back to Recent, and the dialog's Find in AD tab should
   say AD isn't loaded. Neither should throw. Pinned in Tasks 1 and 7.
3. **Changing the Domain or Run as while a load is running.** The old load's result must be
   discarded, never shown under the new domain's name. Pinned in Task 4 (a generation
   number).
4. **A CSV with a BOM, quoted values, or a "Name" column that holds full names with a
   domain prefix (`CONTOSO\FS01`).** It should read cleanly and strip the `DOMAIN\` prefix.
   Pinned in Task 3.
5. **`this computer` given as localhost, 127.0.0.1, its FQDN or its short name.** It should
   become one row with the note `this computer`, never two. Pinned in Task 2.

---

## File Structure

- Create `Server-EventTimeline/ServerEventTimeline.ServerList.ps1`: the pure server-list logic
  and the background AD and DNS jobs. It is dot-sourced at the end of
  `ServerEventTimeline.Core.ps1`.
- Create `Server-EventTimeline/ServerEventTimeline.AddServersDialog.ps1`: the dialog's XAML
  and its `Show-AddServersDialog` function. It is dot-sourced by
  `Start-ServerEventTimeline.ps1` after the engine.
- Modify `Server-EventTimeline/ServerEventTimeline.Core.ps1`:
  - add the dot-source;
  - extend `Read-TimelineSettings`/`Save-TimelineSettings` with `AdTarget`;
  - delete `Get-AdServerCandidates` (Task 8).
- Modify `Server-EventTimeline/Start-ServerEventTimeline.ps1`: the card XAML, its wiring, the
  heartbeat, and the smoke checks.
- Create `Server-EventTimeline/Tests/ServerEventTimeline.ServerList.Tests.ps1`.
- Modify `Server-EventTimeline/Tests/ServerEventTimeline.Gui.Tests.ps1`.
- Modify `Server-EventTimeline/Tests/ServerEventTimeline.Core.Tests.ps1`: the settings and
  removed-function tests.
- Modify `Server-EventTimeline/README.md`.

---

### Task 1: Directory entries and suggestions

**Files:**
- Create: `Server-EventTimeline/ServerEventTimeline.ServerList.ps1`
- Modify: `Server-EventTimeline/ServerEventTimeline.Core.ps1` (add
  `. (Join-Path $PSScriptRoot 'ServerEventTimeline.ServerList.ps1')` after the CaseKit
  dot-source)
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.ServerList.Tests.ps1` (dot-sources
  Core)

**Interfaces:**
- Produces:
  - `ConvertTo-DirectoryEntry -Computer <object> -DomainControllers <string[]> -Now <datetime>`
    returns `[PSCustomObject]` with these properties:
    - `Name` (short)
    - `DnsName` (DNSHostName, or Name if that's empty)
    - `OS`
    - `Enabled` [bool]
    - `IsServer` [bool], meaning OS -like `*Server*`
    - `IsDC` [bool], meaning DnsName or Name is in DomainControllers, case-insensitive
    - `DaysSinceLogon` ([int] or `$null` for never)
    - `DistinguishedName`
    - `OU`: the DN without its first RDN, or '' if it has none
  - `Find-ServerSuggestions -Directory <object[]> -Recent <string[]> -Text <string> -Max 8`
    returns `[PSCustomObject]` with `Name` (what gets added: the DnsName for AD entries, the
    text as saved for Recent) and `Detail` (the OS, or 'searched before').

- [ ] **Step 1: Write the failing tests**

```powershell
Describe 'ConvertTo-DirectoryEntry' {
    It 'reads a server computer object' {
        $c = [PSCustomObject]@{ Name='FS01'; DNSHostName='FS01.contoso.local'; OperatingSystem='Windows Server 2019 Standard'; Enabled=$true
            lastLogonTimestamp=[datetime]::new(2026,11,8,0,0,0,'Utc').ToFileTimeUtc(); DistinguishedName='CN=FS01,OU=Servers,DC=contoso,DC=local' }
        $e = ConvertTo-DirectoryEntry -Computer $c -DomainControllers @('dc01.contoso.local') -Now ([datetime]::new(2026,11,18,0,0,0,'Utc'))
        $e.DnsName | Should -Be 'FS01.contoso.local'; $e.IsServer | Should -BeTrue; $e.IsDC | Should -BeFalse
        $e.DaysSinceLogon | Should -Be 10; $e.OU | Should -Be 'OU=Servers,DC=contoso,DC=local'
    }
    It 'treats 0, missing and Int64.MaxValue lastLogonTimestamp as never' {
        foreach ($v in 0, $null, [Int64]::MaxValue) {
            $c = [PSCustomObject]@{ Name='X'; DNSHostName=''; OperatingSystem=''; Enabled=$true; lastLogonTimestamp=$v; DistinguishedName='CN=X,DC=c' }
            (ConvertTo-DirectoryEntry -Computer $c -DomainControllers @() -Now (Get-Date)).DaysSinceLogon | Should -BeNullOrEmpty
        }
    }
    It 'marks a DC by short or DNS name and falls back to Name when DNSHostName is empty' { }  # assert IsDC for 'DC01' vs @('DC01.contoso.local') and DnsName -eq 'X'
}
Describe 'Find-ServerSuggestions' {
    # Directory: FS01, FS02 (enabled servers), PRINTFS (enabled server), FSOLD (disabled server), WS-FS9 (enabled, Windows 11)
    It 'puts names starting with the text first, then names containing it, max 8' { }  # 'fs' -> FS01, FS02 before PRINTFS
    It 'never suggests disabled accounts or non-servers' { }                          # FSOLD and WS-FS9 absent
    It 'adds Recent names marked "searched before" and does not repeat one already suggested' { }
    It 'returns Recent matches only when the directory is empty (AD not loaded)' { }
    It 'returns nothing for blank text' { }
}
```

Fill in each empty `It` with the assertion named in its comment.

- [ ] **Step 2: Run, and expect a FAIL with "ConvertTo-DirectoryEntry is not recognized"**

Run: `pwsh -NoProfile -File Tests\Invoke-AllTests.ps1 -Path .\Server-EventTimeline\Tests\ServerEventTimeline.ServerList.Tests.ps1`

- [ ] **Step 3: Implement both functions**
  - Recent entries come from `RecentServerLists` split with `ConvertTo-ServerList`.
  - Matching is case-insensitive. Rank prefix matches on Name or DnsName first, then
    contains matches. Sort by name within each group.

- [ ] **Step 4: Run again; expect PASS**

- [ ] **Step 5: Commit** `feat: Server-EventTimeline directory entries and server suggestions`

---

### Task 2: The list model, notes and the names to search

**Files:**
- Modify: `ServerEventTimeline.ServerList.ps1`
- Test: `ServerEventTimeline.ServerList.Tests.ps1`

**Interfaces:**
- Consumes: directory entries from Task 1, and `Get-LocalComputerNames` /
  `Test-IsLocalComputer` (Core).
- Produces:
  - `Test-IpAddress -Text <string>` returns `[bool]` (IPv4 or IPv6, via
    `[System.Net.IPAddress]::TryParse`; a plain number such as '5' is not an IP).
  - `New-ServerListItem -Name <string> -LocalNames <string[]>` returns `[PSCustomObject]`:
    - `Name`: what was typed, or `LocalNames[0]` for any local alias
    - `Display`: Name, or `<ip> → <fqdn>` once trusted
    - `Note`, `NoteKind` ('Info' | 'Warn'), `IsIp`, `IsLocal`
    - `SearchName`: Name until a trusted IP lookup sets the FQDN
    - `Lookup` ('Pending' | 'Done')
  - `Add-ServerListItems -Items <System.Collections.ObjectModel.ObservableCollection[object]> -Names <string[]> -LocalNames <string[]>`
    returns `[string[]]` (the names actually added). It splits each input with
    `ConvertTo-ServerList`, strips a leading `DOMAIN\`, and skips anything whose `Name`
    already matches case-insensitively.
  - `Update-ServerListNote -Item <object> -Directory <object[]> -LoadedDomain <string> -Lookup <object>`
    sets `Note`, `NoteKind`, `Display` and `SearchName` following the spec's rules.
    - `-Lookup` is a Task 4 DNS result or `$null`.
    - The order of rules:
      1. local → `this computer`
      2. IP → the `Lookup` rules
      3. in directory: DC → `domain controller`; disabled → `disabled in AD` (Warn); else the OS
      4. not in directory, and the directory is loaded, and (short name, or the suffix equals
         `LoadedDomain`) → `not in AD` (Warn)
      5. otherwise ''
  - `Get-ServerSearchText -Items <object[]>` returns `[string]`: the items' `SearchName`
    joined with ', '. This is fed to `ConvertFrom-TimelineInputs -ServersText`.

- [ ] **Step 1: Write the failing tests** (`Describe 'Server list'`)
  - `Add-ServerListItems` with `'FS01, FS02' + "`n" + 'FS03'` adds 3 rows, in order.
  - `'localhost'`, `'127.0.0.1'`, `'.'`, and this computer's FQDN and short name (from a
    mocked `Get-LocalComputerNames` returning `@('APP02','app02.contoso.local','localhost','.','127.0.0.1','::1')`)
    give **one** row named `APP02` with the note `this computer`.
  - `'CONTOSO\FS01'` adds `FS01`. Adding `fs01` again adds nothing and returns `@()`.
  - Notes: a DC gives `domain controller`; disabled gives `disabled in AD` (Warn); a server
    gives its OS.
    - `FS9` against a loaded directory gives `not in AD` (Warn).
    - `fs9.fabrikam.com` with `LoadedDomain` 'contoso.local' gives ''.
    - Any name with an empty directory gives ''.
  - IPs:
    - a Lookup with `PtrName='SQL01.contoso.local'; ForwardMatches=$true` gives `Display`
      `'10.0.4.21 → SQL01.contoso.local'` and `SearchName` `'SQL01.contoso.local'`;
    - `ForwardMatches=$false` gives the note `IP · name doesn't match` (Warn), and the
      `SearchName` stays the IP;
    - no PtrName gives `IP · no name found`;
    - a `$null` Lookup leaves the note '' and `Lookup` 'Pending'.
  - `Get-ServerSearchText` of [FS01, the trusted IP above] is `'FS01, SQL01.contoso.local'`.
  - `Test-IpAddress '10.0.4.21'`, `'fe80::1'` and `'5'` give true, true, false.

- [ ] **Step 2: Run; expect FAIL (not recognized)**
- [ ] **Step 3: Implement**. Keep `→` and `·` in the strings, and save the file with a BOM.
- [ ] **Step 4: Run; expect PASS**, and also `pwsh -File Tests\Invoke-AllTests.ps1 -Path .\Tests\ScriptEncoding.Tests.ps1`
- [ ] **Step 5: Commit** `feat: Server-EventTimeline server list model and notes`

---

### Task 3: Reading a server list file

**Files:** `ServerEventTimeline.ServerList.ps1`, `ServerEventTimeline.ServerList.Tests.ps1`

**Interfaces:**
- Produces:
  - `Select-ServerNameColumn -Headers <string[]>` returns `[string]`: the first header,
    case-insensitively, in the order Name, ComputerName, DNSHostName, HostName, Server,
    IPAddress. Returns '' if none match.
  - `Read-ServerListFile -Path <string> [-Column <string>]` returns
    `[PSCustomObject]@{ Names=[string[]]; Column=[string]; Headers=[string[]]; NeedsColumn=[bool] }`.
    - **.txt:** one entry per line; lines that are blank or start with `#` are skipped.
    - **.csv:** `Import-Csv`, then the `-Column` given, or `Select-ServerNameColumn`. If
      neither gives a column, `NeedsColumn=$true` and `Names` is empty.
    - Values are trimmed, and a `DOMAIN\` prefix is stripped. Throws a plain message for any
      other extension.

- [ ] **Step 1: Write the failing tests**. Write fixtures to `$TestDrive`:
  - a .txt with blank and `#` lines;
  - a UTF-8-with-BOM CSV with header `"Name","OperatingSystem"` and a quoted `"CONTOSO\FS01"`;
  - a CSV with header `Host,Site`, which gives `NeedsColumn` true and `Headers` `Host,Site`;
  - the same file read with `-Column Host`, which gives its names;
  - `Select-ServerNameColumn @('ipaddress','dnshostname')`, which gives `'dnshostname'`.
- [ ] **Step 2: Run; expect FAIL**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run; expect PASS**
- [ ] **Step 5: Commit** `feat: Server-EventTimeline reads server lists from txt and csv`

---

### Task 4: Background AD load, DNS lookups and the remembered domain

**Files:** `ServerEventTimeline.ServerList.ps1`, `ServerEventTimeline.Core.ps1` (settings),
`ServerEventTimeline.ServerList.Tests.ps1`, `ServerEventTimeline.Core.Tests.ps1`

**Interfaces:**
- Consumes: `ConvertTo-DirectoryEntry` (Task 1).
- Produces:
  - `$script:DefaultDirectoryLoader` (a scriptblock with params `$ListPath, $Server, $Credential`):
    1. dot-sources `$ListPath`, the ServerList file, so the runspace has
       `ConvertTo-DirectoryEntry`;
    2. imports ActiveDirectory;
    3. runs `Get-ADDomain`, `Get-ADDomainController -Filter *`, and
       `Get-ADComputer -Filter * -Properties DNSHostName,OperatingSystem,lastLogonTimestamp,DistinguishedName,Enabled`,
       passing `-Server`/`-Credential` only when they're given;
    4. returns `@{ Domain = $domain.DNSRoot; Entries = [object[]] }`.
  - `Start-DirectoryLoad -Server <string> -Credential <pscredential> -Generation <int> [-Loader <scriptblock>]`
    returns a job `[PSCustomObject]@{ PowerShell; Handle; Generation; Target }`, in a
    dedicated runspace.
  - `Receive-DirectoryLoad -Job <object>` returns `$null` while it's running. Otherwise it
    returns `[PSCustomObject]@{ Generation; Ok=[bool]; Domain; Entries; Error=[string] }`.
    `Error` is the first error record's message, or the exception message. Receiving
    disposes the PowerShell.
  - `$script:DefaultNameLookup` (params `$Names`): returns one result per name:
    - for an IP: `@{ Name; IsIp=$true; PtrName; ForwardMatches }`, from
      `[System.Net.Dns]::GetHostEntry($ip).HostName`, then `GetHostAddresses(PtrName)`
      containing the IP;
    - for a name: `@{ Name; IsIp=$false; Resolves=[bool] }`, from
      `GetHostAddresses(name)`.
    - Each lookup is in try/catch. A failure gives an empty PtrName or `Resolves=$false`.
  - `Start-NameLookups -Names <string[]> [-Lookup <scriptblock>]` and
    `Receive-NameLookups -Job` mirror the directory job; the result is a `[hashtable]` keyed
    by Name.
  - `Read-TimelineSettings` gains `AdTarget` ('' when it's missing).
    `Save-TimelineSettings -AdTarget` keeps whatever isn't given, as it does today.

- [ ] **Step 1: Write the failing tests**
  - Start and receive with a fake `-Loader { param($ListPath,$Server,$Credential) @{ Domain='contoso.local'; Entries=@([PSCustomObject]@{ Name='FS01' }) } }`.
    Poll `Receive-DirectoryLoad` until it's non-null (5 s timeout). It should give `Ok`,
    the Domain 'contoso.local', and `Generation` echoed back.
  - A loader that does `throw 'The server is not operational'` gives `Ok=$false`, and
    `Error` contains 'not operational'.
  - A fake loader that echoes `$Server` back as Domain receives 'dc01.contoso.local' when
    started with `-Server dc01.contoso.local`.
  - `Start-NameLookups` with a fake lookup gives a hashtable keyed by name.
  - Settings: save `-AdTarget 'contoso.local'`, then read it back. Saving
    `-SaveFolder 'X'` afterwards keeps AdTarget. All under `$TestDrive`.
  - No test uses the default loader or lookup.
- [ ] **Step 2: Run; expect FAIL**
- [ ] **Step 3: Implement**
  - Use `[powershell]::Create()` with its own runspace, as the engine's
    `Start-PendingTimelineTasks` does, but without a pool.
  - Add the Learn citations from Global Constraints next to the default loader's query and
    the stale check.
- [ ] **Step 4: Run; expect PASS**
- [ ] **Step 5: Commit** `feat: Server-EventTimeline loads AD servers and resolves names in the background`

---

### Task 5: The server card (layout B) and the search reading the list

**Files:** `Start-ServerEventTimeline.ps1`, `ServerEventTimeline.Gui.Tests.ps1`

**Interfaces:**
- Consumes: Task 2 (`New-ServerListItem`, `Add-ServerListItems`, `Get-ServerSearchText`).
- Produces these named XAML controls, which replace `ServersBox`, `PickFromAdButton` and
  `ThisComputerButton`'s old placement:
  - `ServerInput` (TextBox)
  - `AddServerButton`
  - `ServerCountText` (TextBlock, in the header row, right-aligned)
  - `DomainText` (TextBlock)
  - `ChangeDomainButton`
  - `ServerList` (ListBox, MaxHeight 112, ItemsSource = `$ui.ServerItems`, an
    `ObservableCollection[object]`). Its item template has three columns: `Display`, then
    `Note` (Muted, or Warn when `NoteKind` is Warn, via a DataTrigger), then a `×` Button
    whose `Tag` is bound to the item.
  - `SuggestPopup` (Popup, PlacementTarget ServerInput) holding `SuggestList` (ListBox)
  - `AddSeveralButton`, `ThisComputerButton`, `RecentButton`, `ClearServersButton`
- Window functions (inside `Show-ServerEventTimeline`):
  - `Add-ServersToList -Names <string[]>`: adds the names, refreshes the count and notes,
    and calls `Update-InputState`.
  - `Update-ServerCount`
  - `Get-InputRequest` now passes `-ServersText (Get-ServerSearchText -Items $ui.ServerItems)`.

- [ ] **Step 1: Write the failing tests** (Gui.Tests, STA-only, like the existing layout tests)
  - 'loads in WPF with every named control': update the names list. It should contain the
    new names and no longer `ServersBox` or `PickFromAdButton`.
  - 'the server list shows the note column and a remove button': load the XAML, set
    `ServerList.ItemsSource` to one item, call `UpdateLayout` on a measured window, and find
    a Button with Content '×' in the visual tree. If WPF won't realize the template headless,
    assert instead that the template's XAML (from `New-TimelineWindowXaml`) contains
    `Binding Note` and `Content="×"`.
  - `ServerInput`'s watermark text is 'Type a server name or IP address'. Implement it as a
    TextBlock overlay with `IsHitTestVisible=False`, collapsed when the text isn't empty.
    Assert the overlay's Text.
- [ ] **Step 2: Run; expect FAIL**
- [ ] **Step 3: Implement the XAML and wiring**
  - The left column widens from 340 to 380. Keep the comment about the smoke test.
  - Enter in `ServerInput` with the popup closed, or a click on Add, runs
    `Add-ServersToList @($ServerInput.Text)` and clears the input. A pasted multi-name text is
    split by `Add-ServerListItems`.
  - The × button's Click removes its Tag item.
  - **Clear:** with more than 3 items it asks `Remove all N servers from the list?` (a
    YesNo MessageBox).
  - **This computer** adds `(Get-LocalComputerNames)[0]`.
  - **Recent:** a click clears the list and adds the saved list.
  - **Start-up:** `-ComputerName` pre-fills the list. With no `-ComputerName`, the list
    starts with this computer, as today.
  - The `Get-InputRequest` change above.
  - `Update-InputState` uses `$ui.ServerItems.Count -gt 0` for `serversOk`.
  - **Smoke:** add the check `if ($ui.ServerItems.Count -lt 1) { 'the server list was not filled' }`.
    `Get-ClippedRowItems` must still find nothing cut off.
- [ ] **Step 4: Run** the Gui tests and `-SmokeTest` on powershell and pwsh. Expect PASS and
  `[PASS] ... window opened`.
- [ ] **Step 5: Commit** `feat: Server-EventTimeline server list replaces the free-text box`

---

### Task 6: Autocomplete, the domain line, and notes filled in the background

**Files:** `Start-ServerEventTimeline.ps1`, `ServerEventTimeline.Gui.Tests.ps1`

**Interfaces:**
- Consumes: Task 1 `Find-ServerSuggestions`; Task 4 `Start-/Receive-DirectoryLoad`,
  `Start-/Receive-NameLookups`, `AdTarget`; Task 2 `Update-ServerListNote`.
- Produces this window state:
  - `$ui.Directory` (`[object[]]`, empty until loaded)
  - `$ui.LoadedDomain`
  - `$ui.DirectoryJob`
  - `$ui.DirectoryGeneration` [int]
  - `$ui.LookupJob`
  - `$ui.Lookups` (a hashtable that accumulates results by name)
  - `Start-WindowDirectoryLoad`: increments the generation; starts the load with the
    remembered AdTarget (`''` means no `-Server`) and `$ui.Credential`; sets DomainText to
    `Loading servers from <target or "this domain">...`.

- [ ] **Step 1: Write the failing tests**
  - Extract the text of the domain line into a Core-level pure function in ServerList.ps1:
    `Get-DomainLineText -State <'Loading'|'Loaded'|'Failed'|'NoDomain'> -Domain <string> -Count <int> -Error <string>`.
  - Test all four exact strings from Global Constraints. 'Loaded' with a Count of 412 gives
    `Suggestions from: contoso.local (412 servers)`.
  - Test `Test-StaleDirectoryResult -Result <obj> -CurrentGeneration <int>`, which returns
    true when the generation differs (that result is ignored).
- [ ] **Step 2: Run; expect FAIL**
- [ ] **Step 3: Implement**
  - At window open (not in smoke mode), call `Start-WindowDirectoryLoad`. If
    `Get-Module -ListAvailable ActiveDirectory` finds nothing, set DomainText to
    `Suggestions from: no domain`, and give ChangeDomainButton the existing RSAT tooltip
    with IsEnabled false.
  - The workstation joined to no domain is caught by the load failing on
    `Get-ADDomain` with no `-Server`, so it shows `NoDomain` when AdTarget is empty.
  - **Heartbeat:** **before** the `if (-not $ui.Engine -or $ui.Finished) { return }` line,
    collect `DirectoryJob` and `LookupJob`. Drop a result whose generation is stale. When a
    load finishes, store the Directory and LoadedDomain, update DomainText, and rerun
    `Update-ServerListNote` on every item.
  - After every `Add-ServersToList`, start a `Start-NameLookups` for the newly added IPs,
    and for names not found in the directory. Keep a queue while a job is running; one job
    at a time is enough. When it finishes, merge into `$ui.Lookups`, then refresh the notes.
    For a name with `Resolves=$false` that isn't in AD, the note stays `not in AD`. The
    dialog uses Resolves for its own wording (Task 7).
  - **ChangeDomainButton:** a VB InputBox with the prompt `Domain or domain controller to
    read servers from (leave empty for this computer's domain):`. Save AdTarget and reload.
  - **RunAsButton:** after setting `$ui.Credential`, reload.
  - **Autocomplete:** on `ServerInput.TextChanged`, set `SuggestList.ItemsSource` to
    `Find-ServerSuggestions` (Max 8). The popup is open when there's at least one result.
    - Each item shows `Name` and `Detail`.
    - PreviewKeyDown: Down/Up move `SuggestList.SelectedIndex`; Enter with a selection adds
      `SelectedItem.Name`; Esc closes the popup.
    - A mouse click on a suggestion adds it.
    - Closing: the popup closes on LostKeyboardFocus, unless focus moved into the popup.
- [ ] **Step 4: Run** the Gui and ServerList tests and `-SmokeTest` on both hosts (no load
  in smoke). Expect PASS.
- [ ] **Step 5: Commit** `feat: Server-EventTimeline autocompletes servers from a chosen domain`

---

### Task 7: The "Add several servers" dialog

**Files:**
- Create: `Server-EventTimeline/ServerEventTimeline.AddServersDialog.ps1`, dot-sourced in
  `Start-ServerEventTimeline.ps1` after the Engine line.
- Modify: `ServerEventTimeline.ServerList.ps1` (the pure candidate logic),
  `Start-ServerEventTimeline.ps1` (AddSeveralButton)
- Test: `ServerEventTimeline.ServerList.Tests.ps1`, `ServerEventTimeline.Gui.Tests.ps1`

**Interfaces:**
- Consumes: Tasks 1–4.
- Produces (pure, in ServerList.ps1):
  - `Get-DirectoryOUs -Directory <object[]>` returns the sorted, unique `OU` values of
    entries that are enabled servers. This deviates from the spec's "list of the domain's
    OUs": deriving them from the loaded computers needs no extra query, and only lists OUs
    that hold servers.
  - `Find-DirectoryServers -Directory <object[]> -Text <string> -Scope <'All'|'DomainControllers'|'OU'> -OU <string>`
    returns entries that are enabled servers. `-Text` is a case-insensitive contains match
    on Name or DnsName, and empty text matches all. The OU scope matches the entry's OU
    exactly, or any OU beneath it (the DN ends with `,<OU>`).
  - `New-AddCandidate -Name <string> -Directory <object[]> -Lookup <object> -StaleDays 30`
    returns `[PSCustomObject]@{ Name; Note; NoteKind; Ticked=[bool] }`:
    - in AD, enabled, and DaysSinceLogon ≤ 30 or never → `in AD`, ticked (the OS is shown
      on Find in AD rows: Note = OS);
    - DaysSinceLogon > 30 → `no sign-in for N days`, Warn, unticked;
    - disabled → `disabled in AD`, Warn, unticked;
    - an IP → the Task 2 IP wording, ticked;
    - not in AD, with `Lookup.Resolves` true → `found in DNS`, ticked;
    - not in AD, with `Resolves` false → `not found in AD or DNS`, Warn, unticked;
    - `Lookup` `$null` → `checking...`, ticked.
  - `Show-AddServersDialog -Owner <Window> -Directory <object[]> -DirectoryState <string> -LocalNames <string[]>`
    returns `[string[]]`: the ticked names, or `@()` on Cancel.
- The dialog:
  - Size 460×520, `WindowStartupLocation=CenterOwner`, the same dark resources, copied into
    its XAML (the folder is self-contained, so no shared resource file).
  - A TabControl with **Paste**, **Find in AD** and **From a file**, then one shared
    results ListBox with a CheckBox per row, bound to `Ticked`.
  - **Tick all** / **Tick none** buttons, the text `N of M ticked`, **Add N servers** (the
    default button, disabled at 0), and **Cancel**.
  - **Paste:** a multi-line TextBox. A 400 ms DispatcherTimer after the last keystroke, or
    the "Check names" button, rebuilds the candidates. DNS runs through its own
    `Start-NameLookups` and a dialog-local 250 ms timer.
  - **Find in AD:**
    - a search TextBox, and three RadioButtons: All servers, Domain controllers, and In an
      OU..., where the OU choice enables a ComboBox filled by `Get-DirectoryOUs`;
    - results update as you type;
    - if `DirectoryState` isn't 'Loaded', the tab shows `Active Directory isn't loaded yet
      (<DomainText>). Use Paste or From a file.` and nothing else.
  - **From a file:**
    - "Choose file..." uses `Microsoft.Win32.OpenFileDialog` with the filter
      `Server lists (*.txt;*.csv)|*.txt;*.csv`;
    - the chosen path is shown;
    - when `NeedsColumn` is set, a ComboBox of the headers appears, and choosing one
      re-reads the file with `-Column`;
    - the names are checked as in Paste.
  - Switching tabs clears the results list. Add returns only the current tab's ticked names.

- [ ] **Step 1: Write the failing tests**
  - Pure: `Get-DirectoryOUs` dedupes and sorts. `Find-DirectoryServers`:
    - 'sql' finds SQL01 and SQL-REPORT but not the disabled SQLOLD;
    - the DomainControllers scope only returns IsDC;
    - the OU scope `OU=Servers,DC=c` includes `CN=A,OU=SQL,OU=Servers,DC=c`.
  - `New-AddCandidate`: one test per bullet above, with its exact note text, ticked state
    and NoteKind.
  - GUI (STA): `New-AddServersDialogXaml` parses, and has the named controls `PasteBox`,
    `FindBox`, `ScopeAll`, `ScopeDcs`, `ScopeOu`, `OuCombo`, `FileButton`, `FilePathText`,
    `ColumnCombo`, `ResultList`, `TickAllButton`, `TickNoneButton`, `TickedText`, `AddButton`
    and `CancelButton`.
- [ ] **Step 2: Run; expect FAIL**
- [ ] **Step 3: Implement**
  - AddSeveralButton opens the dialog with `$window` as Owner, the current Directory, and
    its state. It passes the result to `Add-ServersToList`.
  - In smoke mode, the dialog's XAML is parsed with its window not shown, and a failure is
    added to SmokeFailures. Show-ServerEventTimeline's smoke handler calls
    `New-AddServersDialogXaml | XamlReader.Parse` inside try/catch.
- [ ] **Step 4: Run** all Server-EventTimeline tests and `-SmokeTest` on both hosts. Expect
  PASS.
- [ ] **Step 5: Commit** `feat: Server-EventTimeline "Add several servers" dialog`

---

### Task 8: Remove the old paths, then the docs and the full gate

**Files:** `ServerEventTimeline.Core.ps1`, `Start-ServerEventTimeline.ps1`,
`ServerEventTimeline.Core.Tests.ps1`, `README.md`

- [ ] **Step 1: Write the failing test**. In Core.Tests:
  `Get-Command Get-AdServerCandidates -ErrorAction SilentlyContinue | Should -BeNullOrEmpty`.
  Also delete the existing tests for `Get-AdServerCandidates`, and for `Add-ServerNames` if
  nothing uses it any more (check with `Grep`).
- [ ] **Step 2: Run; expect FAIL**
- [ ] **Step 3: Remove** `Get-AdServerCandidates`, the `$adMenu`/`$miFind`/InputBox code, and
  `Add-ServerNames` if it's unused.
  - Update the comment-based help: `.DESCRIPTION` covers the list, IPs and the domain line.
    `.NOTES` gets REFERENCES for the two Learn pages in Global Constraints, and the Files
    line lists the two new files.
  - README "Which servers?":
    - the new card and the dialog, in plain English;
    - IPs: they work; the tool looks up the name; without a trustworthy name, the search
      reads through the remote event log; WinRM with an IP needs TrustedHosts plus Run as;
    - the domain line, and where it's remembered;
    - the file list section gains the two new files.
- [ ] **Step 4: Run**
  - `pwsh -NoProfile -ExecutionPolicy Bypass -File Tests\Invoke-AllTests.ps1` (full). Expect
    0 failures apart from the 7 known ORR-eDiscovery compatibility failures, which fail on
    main without this work.
  - `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Tests\Test-ScriptParse.ps1`
  - `pwsh -File Tests\Invoke-AllTests.ps1 -Path .\Tests\PSVersionFloor.Tests.ps1,.\Tests\ScriptEncoding.Tests.ps1`
  - `-SmokeTest` on both hosts
- [ ] **Step 5: Commit** `docs: Server-EventTimeline server list in help and README`
