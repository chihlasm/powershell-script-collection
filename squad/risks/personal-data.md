# Risk profile: client data and secrets

Applies to code that collects, stores, displays, logs, exports, or transmits data about the
MSP's clients and their users: security evidence exports (Get-M365SecurityEvidence),
lockout and drive-map case folders (AD-LockoutDiagnostics, DriveMap-Diagnostics), group
membership exports, device activity timelines, and FSLogix-Profile-Backup, which handles
browser saved passwords.

- Collect only what the diagnosis needs; nothing extra "just in case".
- Passwords, tokens, client secrets, `PSCredential` objects and browser credential stores are
  never written to logs, transcripts, CSV/HTML reports or the console, and never persisted in
  plain text. Credential backups are encrypted, and the README says how.
- Output stays on the machine it ran on (HTML/CSV in `-OutputPath`). Nothing is uploaded,
  emailed, or sent to an external service; this collection has no cloud backend by design.
- HTML reports encode every value taken from AD, event logs or Graph (user names, paths,
  descriptions) so client data cannot inject markup into a report a tech opens.
- Client-data output folders are covered by `.gitignore` (see the "Customer data" section);
  a new tool that writes case or evidence folders adds its pattern there in the same change.
- Graph and Exchange connections request the least-privileged read scopes that work, verified
  on Microsoft Learn and cited, and disconnect when done.
- Tests use synthetic data only (`contoso.com`, `jdoe`, made-up SIDs and GUIDs); no real
  client names, tenants, user names or event exports in fixtures.

## Ticket notes and the clipboard (added 2026-10-18)
The ticket note is the one output that deliberately leaves the machine: it is pasted into
ConnectWise Manage. "Output stays on the machine" above means everything else.
- The note is paste-safe by default (D-009, P-005). It removes IPs (including
  `*.ipv6-literal.net` names), share and profile paths, SIDs (including `S-1-12-`) and paths
  inside error text. Prefer building note text from known-safe fields and literally
  scrubbing paths the tool already knows over regex stripping afterwards.
- Raw exception text (AD/ADWS, Graph, MSAL, EXO) and free text controlled by the client or
  an attacker (rule names, display names, subjects, folder names) never go into the note or
  the clipboard. They map to fixed wording. Control characters, CR/LF and ANSI escapes are
  stripped before such text reaches the console.
- No third-party data in the note: other users' addresses, delegates, forwarding targets,
  trace recipients, rule conditions, ambiguous-match candidate lists, or run-as admin
  account names. The stamp line's allowed identifiers (server, domain) follow D-009.
- Aggregators and joiners re-apply the redaction; they never trust their inputs.
- The shared filter has behaviour tests in `TicketNote/Tests` against awkward names
  (apostrophe then space or punctuation, spaces in the last segment, parentheses, commas,
  quoted and unquoted, uppercase or alternative IP forms). Each tool that uses it has at
  least one end-to-end paste-safe test.
- The clipboard copy opts out of clipboard history and the cloud clipboard
  (CanIncludeInClipboardHistory = 0, CanUploadToCloudClipboard = 0, D-033,
  https://learn.microsoft.com/windows/win32/dataxchg/clipboard-formats). A fallback that
  cannot opt out warns at run time. There is a way to skip the clipboard (`-NoClipboard`),
  and the README mentions RDP clipboard redirection.
- Names written by tenant or domain admins (Conditional Access policy names, sign-in failure
  reasons, GPO names) count as client-controlled free text and stay out of the note unless the
  item's spec says otherwise. The same goes for directory identifiers (DistinguishedName/OU
  path, SIDs) and DC or host names that appear inside error text.
- Text the tech can copy by hand (selectable status or path boxes in a GUI) is either
  paste-safe or documented in the README as raw.

## Exports, logs and returned objects (added 2026-10-18)
- CSV cells taken from AD, event logs or Graph that start with `=`, `+`, `-`, `@`, tab or CR
  are neutralised (leading `'`), with a test for every column that carries client-controlled
  text, including file and folder names. Reuse the existing helper
  (FolderPermissions.Core.ps1, FolderAccess-Check, M365-UserQuickCheck).
- HTML encoding fits the context: values in attributes need quote escaping, and a
  `& < >`-only encoder is safe only in element content. Browser GUIs insert client values with
  `textContent` or encoding, never `innerHTML`.
- Client-data logs, change logs, backups and fallback copies default to local fixed storage.
  When the script runs from a UNC share, mapped drive, synced SharePoint/OneDrive folder or
  removable drive, a `$PSScriptRoot`-relative default falls back to
  `%LOCALAPPDATA%\<Tool>`, and the tool warns when an explicit location is not local. Every
  location (default, fallback, explicit, relative) is resolved to a full path.
- The README says what client data each saved file holds, that output folders inherit the
  folder's ACL, and when to delete it (ticket only; delete the local copy and any `%TEMP%`
  fallback). If a change adds client data to an output whose default location is inside the
  repo tree, that location is gitignored with a repo-wide (`**/`) pattern.
- `-PassThru` and result objects carry only the fields the verdict uses, not whole AD users
  or raw Graph rows. Bulk fetches of other users' data (tenant-wide audit searches) are
  filtered in memory and never persisted, logged or returned.
- Filter on the remote side where the API allows it, so other users' data is not shipped
  back to the tech's PC; trim responses as they arrive where `$select` is not supported.
- When a tool filters host-wide logs to one user, it matches on SID or `DOMAIN\sam` with
  proper delimiters, with a test for a similar name (`jdoe` vs `jdoe.smith`).
- Secrets inside configuration values or quoted log lines (`AccountKey=`,
  `SharedAccessSignature=`, `sig=`) are never echoed into findings or validation messages,
  including when the value is malformed.
- A credential passed in has a test proving it never appears in the result object, CSV,
  HTML or note, on the failure path as well as the success path.
- Output file names built from client data are sanitised against path traversal and
  reserved characters.
- Graph sign-in uses `Connect-MgGraph -ContextScope Process` where available, and a
  compatibility fallback that drops a protective option warns or refuses.

## Saved files, command lines and raw output (added 2026-10-20)
- Exports a tech saves through a dialog default to local storage too. Documents and Desktop
  under OneDrive Known Folder Move or folder redirection are not local, although they sit on a
  fixed disk.
- Synced OneDrive/SharePoint folders are detected from the OneDrive client's registered sync
  roots, with a test each. Environment variables miss library sync roots and belong to the
  wrong user in an elevated or alternate-admin process.
- Tool-private diagnostic logs (`%LOCALAPPDATA%\<Tool>\*-errors.log`) that can hold raw
  exception text with client paths have a retention or size cap, stated in the README.
- Client data passed on a command line (relaunch or elevation arguments) is limited to
  infrastructure identifiers (server, share, local path): never credentials, user names or
  ticket numbers. Event 4688, Sysmon and EDR record command lines and ship them off the machine.
- Advice that tells someone to run a command that saves client data (`icacls /save`,
  `Export-*`) uses a full, unique path on local fixed storage, never a bare file name, and the
  README says what the file holds and when to delete it.
- Raw command output that lists sessions or users (qwinsta, quser, `Get-BrokerSession`) is
  trimmed to the rows the verdict needs before it is stored in RawOutput or returned. The
  fixture includes another user's row and asserts it does not leak.
- RawOutput from one tool nested in another tool's result is re-trimmed by the outer tool
  (it is a joiner), not passed through whole.
- Registry keys that hold secrets next to the diagnosed value (RDInfraAgent
  RegistrationToken, Cloud Cache connection strings) are read by named value only, never
  enumerated, with a test pinning that.
- Event log queries by an ID that is not unique to one provider filter on the provider before
  anything is stored, not only before evidence is built.
