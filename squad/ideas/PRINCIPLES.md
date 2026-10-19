# Product principles

Rules that ideas must respect. Seeded by /squad:setup, then grown from the owner's verdicts
in /squad:pitch and changes made with /squad:configure. Ideators read this before proposing
anything; the critic enforces it.

## Who the product is for
Michael and the team at his MSP: helpdesk techs working tickets with a client waiting, and
senior sysadmins running audits and deep diagnostics across client environments. Success is
faster troubleshooting and faster, more accurate data collection.

## Scope boundaries
- No cloud or SaaS backend. Output stays on the machine the tool ran on (HTML/CSV); nothing
  is uploaded, emailed, or sent to telemetry.
- Self-contained, copy-and-run tool folders are the default. A shared piece is allowed when
  it clearly earns its place (less duplication, one fix reaches many tools), as long as each
  tool still runs from its folder or the ServiceDesk-Toolkit bundle with nothing to install.

## Principles
- **P-001 Accurate over plausible.** Event IDs, status codes, attribute semantics, GUIDs and
  cmdlet parameters are verified on Microsoft Learn and cited. A confident wrong answer is
  worse than "unknown"; when evidence is missing, the tool says so.
- **P-002 Verdict first.** Every tool leads with a plain-English answer and the next step a
  tech should take, with the evidence underneath for the sysadmin who wants to check it.
- **P-003 Runs where the problem is.** Works on the oldest supported server (PowerShell 3.0
  floor where possible), needs no installs, and targets remote machines with
  `-ComputerName` rather than assuming it runs on the target.
- **P-004 Tier 1 never gets a destructive or privileged step.** When the fix removes,
  deletes, re-enables, unblocks or grants privileged access, the next step is "Escalate" plus
  the reason. When privilege can't be established, the step carries an approval gate
  ("Get senior approval first"). From D-017, D-024, SQ-013 and SQ-019.
- **P-005 Anything bound for a ticket is paste-safe by default.** Notes and clipboard text
  carry the verdict, checks and next step. IPs, paths, raw error text and third-party data
  stay in the local reports, and no new files are left on client servers. `-FullDetail` is
  the explicit opt-out. From D-009, D-013, D-025 and D-033.
