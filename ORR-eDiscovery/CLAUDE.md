# ORR-eDiscovery: project conventions

Guidance for future sessions working in this folder. The repository's root `CLAUDE.md` still
applies (verify Microsoft facts on Learn and cite them, help blocks, logging prefixes, commit
style). Where this file is more specific, this file wins for `ORR-eDiscovery/`.

## What this is

A tool for VC3 technicians that runs municipal open records requests (ORRs) through Microsoft
Purview eDiscovery using Microsoft Graph, across many client tenants. A technician signs in to
one client tenant, loads a validated request ("ORR spec"), previews the query, creates the
case and search, reads the estimate, and optionally starts an export.

Unlike the rest of this repository, this tool is a small multi-file project, not a single
script:

```
src/ORR.Core/ORR.Core.psm1   all rules and (from phase 2) all Graph calls; no UI code
src/ORR.Core/ORR.Core.psd1
src/ORR-GUI.ps1              phase 3: WPF front end; calls ORR.Core only
src/ORR-Runner.ps1           placeholder; headless runner is not built
config/clients.example.json  copy to clients.json (gitignored) and edit
schemas/orr-spec.v1.schema.json
tests/                       Pester 5; run under PowerShell 7
docs/                        phase 4: README.md, SETUP.md
```

## Build phases

1. **Done:** scaffold, spec schema, client config, spec validation, KQL builder, tests.
2. Graph functions in ORR.Core (connect, resolve custodians, case, search, sources, estimate,
   export, poll) plus JSONL logging. Mocked tests.
3. WPF GUI wired to ORR.Core.
4. Summary generator, README/SETUP, polish.

Stop after each phase for Michael's review.

## Hard safety rules (enforced in ORR.Core and by tests)

- **Allow-listed operations only:** create case, create/update search, add sources to a
  search, estimate statistics, export, read status. Never purge, delete, close or reopen a
  case, create custodians, or apply/remove/release a hold. `tests/Safety.Tests.ps1` scans
  every file under `src/` as text, comments included, against an allow-list of Graph command
  names and a list of banned operation names. Do not weaken it to get a change through; if a
  comment trips it, reword the comment.
- **Act only on a validated spec.** `Test-OrrSpec` is the single entry point for both pasted
  JSON and form input. Every function that acts on a spec starts with
  `Assert-OrrValidatedSpec`, which refuses anything that did not come from `Test-OrrSpec` in
  this module instance or was changed afterwards. A background runspace has its own module
  instance: pass it the spec JSON and validate again there, do not pass the object.
- **Editing the query in the GUI** means putting the edited text in `kqlOverride` and
  validating the spec again. There is no path that sends free text to Graph.
- **Never send an empty query.** An empty eDiscovery query returns everything.
- **Never use tenant-wide scope.** Searches name their sources one by one.
- **Export needs a completed estimate on the same search plus an explicit confirmation.**
- **Case names are deterministic** (`<Prefix>-<ticket>-<yyyyMMdd>`); never create a duplicate
  silently.
- **No client data in git:** `config/clients.json`, logs and exports are ignored by
  `ORR-eDiscovery/.gitignore`. Never log or display an export download URL.

## Conventions

- Windows PowerShell 5.1 **and** PowerShell 7. No `Test-Json`, `-AsHashtable`, ternaries or
  `??`. `tests/Compatibility.Tests.ps1` runs the module under `powershell.exe` and compares
  the answers with PowerShell 7.
- Source files are plain ASCII. Write non-ASCII characters as `[char]0x201C`.
- String comparisons that decide anything are ordinal or regex, never the culture-sensitive
  `StartsWith('x')` / `LastIndexOf('x')` overloads (a th-TH test caught one).
- Only `Microsoft.Graph.Authentication` and `Microsoft.Graph.Security`. They are checked at
  run time, not listed in `RequiredModules`. User lookup uses `Invoke-MgGraphRequest`
  (`Get-MgUser` is in a third module).
- Approved verbs, comment-based help with `.NOTES` REFERENCES on every exported function,
  `Write-Verbose` throughout.
- Messages are written for a technician mid-ticket: say what is wrong and what to do.
- JSON arrays: read values with `.PSObject.Properties[...]` or a table, never through a
  function return, so a one-item list stays a list on 5.1.

## Running the tests

```powershell
pwsh -NoProfile -File Tests\Invoke-AllTests.ps1 -Path .\ORR-eDiscovery\tests   # from the repo root
powershell.exe -NoProfile -ExecutionPolicy Bypass -File Tests\Test-ScriptParse.ps1
```

Tests never sign in, never contact a tenant, and write only under `$TestDrive`.

## ORR spec v1

Contract: `schemas/orr-spec.v1.schema.json`. `Test-OrrSpec` implements it by hand (5.1 has no
`Test-Json`) and adds the rules a schema cannot express; `tests/Spec.Tests.ps1` runs a table
of cases through both under PowerShell 7 and checks that field lists and patterns are
identical. Two deliberate differences: the code accepts only a whole-number literal for
`ticketNumber` (the schema's "integer" also allows `1.0`), and it trims keywords.

Two fields were added to the original design because of what the documentation says:

- `sites`: SharePoint site addresses. A site can only be searched by its address, so
  `"sharepoint"` in `locations` requires at least one.
- `teamMailboxes`: email addresses of teams/groups. Channel messages live in the team's group
  mailbox, not in members' mailboxes.

`locations` records what was requested. It cannot be honoured exactly: Graph adds a person as
one source covering mailbox **and** OneDrive, and Teams chats are stored in the mailbox.
`Test-OrrSpec` warns when the search will cover more than was requested.

## What the documentation says (verified on Microsoft Learn, November 2026)

Each fact was read on the page cited and checked a second time by an independent pass. Module
facts were checked with `Get-Command` against Microsoft.Graph.Security 2.36.0.

### Query (KQL)

- An empty query returns all content in the selected sources. `contentQuery` is optional in
  the Graph API. <https://learn.microsoft.com/purview/edisc-search-query>
- `AND`, `OR`, `NOT`, `NEAR` must be uppercase; lowercase is treated as a keyword. A space
  between terms means **OR** in eDiscovery (SharePoint KQL says AND). Same page.
- No escape character exists. `+ - = : ! @ # % ^ & , ; _ / ? ( ) [ ] { }` are replaced by a
  space or cause an error. <https://learn.microsoft.com/purview/edisc-condition-builder>
- Nested quotes are not supported. <https://learn.microsoft.com/purview/edisc-keyword-query-language>
- Prefix wildcards only, at least 3 letters first; 10,000 characters and 100 Boolean
  operators per query, shared with search permission filters.
  <https://learn.microsoft.com/purview/edisc-ref-limits>
- All searches are evaluated in UTC. <https://learn.microsoft.com/purview/edisc-search-query>
- `date` is the one date condition for both mail and documents. The metadata reference says
  it means sent date for mail, last-modified for documents, start for meetings, and that
  drafts can match. <https://learn.microsoft.com/purview/edisc-ref-document-metadata-fields>
  The condition builder page defines it differently for mail ("created or imported from a
  PST file"). Which applies in search is open question 7.
- Site URLs "must use the standard `.sharepoint.com` format".
  <https://learn.microsoft.com/graph/api/security-ediscoverycase-post-noncustodialdatasources?view=graph-rest-1.0>

### Graph API (for phase 2)

- Scope a search to named people and sites by POSTing each one to
  `.../searches/{id}/additionalSources` with `-BodyParameter` and an `@odata.type`
  (`userSource` with `email`, or `siteSource` with `site.webUrl`). The cmdlet has no
  `-Email`/`-Site` parameter. The key is the SMTP address. Needs `eDiscovery.ReadWrite.All`.
  <https://learn.microsoft.com/graph/api/security-ediscoverysearch-post-additionalsources?view=graph-rest-1.0>
- Creating a custodian returns `holdStatus: applied` in Microsoft's samples. Never create one.
- `List ediscoveryCases` documents no `$filter`; list everything and match the name locally.
  An eDiscovery Manager only sees cases they created, so "not found" is not "does not exist".
- **The estimate returns totals only** (`indexedItemCount`, `indexedItemsSize`,
  `unindexedItemCount`, `unindexedItemsSize`, `mailboxCount`, `siteCount`). Per-location
  counts exist only in the process report CSV.
  <https://learn.microsoft.com/graph/api/resources/security-ediscoveryestimateoperation?view=graph-rest-1.0>
- `Invoke-MgEstimateSecurityCaseEdiscoveryCaseSearchStatistics` has no `-BodyParameter`,
  although Learn's example passes one. Sending `statisticsOptions` needs
  `Invoke-MgGraphRequest`. The async cmdlets return only a Boolean; the operation comes from
  the `Location` header.
- Operation status values: `notStarted`, `submissionFailed`, `running`, `succeeded`,
  `partiallySucceeded`, `failed`. `exportResult`/`exportReport` action values are only
  returned with the header `Prefer: include-unknown-enum-members`.
- `exportResult` requires `exportCriteria`, `exportFormat` (`pst` or `msg`; `eml` is
  deprecated) and `additionalOptions`.
- **The export cannot be downloaded with the Graph token.** It needs a separate token for the
  MicrosoftPurviewEDiscovery app; the only documented method is app-only with MSAL.PS. The
  tool stops at "export ready" and sends the technician to the Purview portal. Packages expire
  14 days after creation. <https://learn.microsoft.com/purview/edisc-ref-api-guide>
- A 404 right after creating a search is **not documented**. Any retry is a defensive guess;
  bound it and say so in the comment.
- There is no documented deep link to a case in the Purview portal. Show the case name, the
  case ID and the click path.

### Tenant prerequisites (for SETUP.md)

- Delegated `eDiscovery.ReadWrite.All` needs admin consent; a Cloud Application Administrator
  can grant it. The technician also needs the **eDiscovery Manager** role group in Purview
  (it includes Export; Compliance Administrator and Global Administrator do not).
- E3-class tenants: delegated sign-in only, and **export requires Purview pay-as-you-go
  billing**. App-only sign-in requires premium (E5) cases.
  <https://learn.microsoft.com/graph/api/resources/security-ediscovery-apioverview?view=graph-rest-1.0>
- GDAP lists no eDiscovery support and guest accounts are limited to the Reviewer role; plan
  on a member account in each client tenant.
- `Connect-MgGraph`: always pass `-TenantId` and `-ContextScope Process`; `-LoginHint` is on
  Learn but not in 2.36.0. FIDO2 keys only work under PowerShell 7.

## Open questions that need a real tenant (phase 2)

The documentation is silent or contradicts itself on these. Do not present them as facts.

1. Does `date<2024-04-01` cut off at 00:00 UTC, and does `date<=` include the whole day?
2. Does estimate/export accept a search with `dataSourceScopes: none` and only additional
   sources?
3. Is the Graph auth context shared between runspaces in one process (5.1 and 7)?
4. Which `@odata.type` does a team/group address need as an additional source?
5. Does `-ResponseHeadersVariable` expose `Location` on a 202?
6. Do the Graph eDiscovery calls work on Business Premium tenants at all?
7. For email, is `date` the sent date or the created/PST-import date?

## Decisions from the phase 1 review (do not undo without a reason)

- **JSON is read by the module's own strict reader** (`ConvertFrom-OrrStrictJson`), not
  `ConvertFrom-Json`. The built-in parsers keep the last of two repeated fields without
  complaint, accept comments and trailing commas, and PowerShell 7 reads `0123` as octal,
  unwraps a one-item list and turns timestamp-like text into dates.
- **Never write `.Keys` or `.Count` on a table built from JSON.** If the data has a field
  named `Keys`, PowerShell returns that field. Use `.get_Keys()` / `Get-OrrSortedKeys`.
- **Allow-lists are compared ordinally** (`Test-OrrInList`), and patterns with `-cmatch`.
  `-contains` and `-match` are linguistic and culture-sensitive.
- **Custodians, team mailboxes, sites and locations are not trimmed**; a stray space is an
  error, as in the schema. Keywords are trimmed.
- **A validated spec is tied to the client settings it was checked against** (`ClientStamp`
  in the fingerprint). `CustodiansResolved` is deliberately outside the fingerprint; in
  phase 2 keep the resolved state inside the module, keyed by `ValidationId`, rather than
  trusting that writable property.
- **A keyword or query with no letter or digit is refused** as an empty search.
- **Phase 2 must write request methods as a literal `GET` or `POST`** and escape any address
  placed in a URL with `[uri]::EscapeDataString`. The safety scan rejects a variable method,
  `Invoke-RestMethod`/`Invoke-WebRequest`/`HttpClient`, and code built at run time.
- Known and accepted: `Test-OrrKql` is a pre-flight check, not a parser. It does not flag
  nested quotes or an operator glued to a quote (`"a"OR"b"`).
