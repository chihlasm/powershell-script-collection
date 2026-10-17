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
