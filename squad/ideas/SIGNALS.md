# Real-world signals

The single biggest lever on idea quality. The thinker squad weights anything here above
its own reasoning. Drop in raw notes whenever something happens; a rough line is better
than nothing.

## How to write an entry

`- YYYY-MM-DD · source · [area] · strength: what happened`

- **source:** `owner` (Michael) | `tech:<name>` | `client:<code>` | `ticket:<id>` | `repo-history`
- **area:** `lockout` `sign-in` `drive-maps` `files` `citrix` `fslogix` `avd` `rds` `entra`
  `m365` `network` `bundle` `escalation` `reporting`
- **strength:** `once` (seen one time) | `recurring` (keeps happening) | `measured` (give the number)

Write **what happened, not the fix**. "Tech spent 20 min reading Event Viewer on three DCs"
beats "add a DC event viewer". Leave solutions to the squad.

Rules for the squad:
- `owner` and `measured` entries outweigh `repo-history` and `once` entries.
- When an idea answers a signal, cite the signal's date and area in the idea card.
- Known bugs belong in `squad/BACKLOG.md`, not here.

---

## The core problem

- 2026-10-16 · owner · [escalation] · recurring: Techs escalate mostly because they don't
  know how to resolve the issue, not because a tool failed. The tools exist to help a tech
  reach the conclusion themselves, and to help when they do escalate and when they explain
  the problem to the client.
- 2026-10-16 · owner · [escalation] · recurring: On escalation, Michael wants to see what
  the tech did and how they reached their conclusion: what they checked, how they ruled
  things out, and how they gathered the information. Today that reasoning is not captured.
- 2026-10-16 · owner · [escalation] · recurring: The most useful things a tool could produce
  for an escalation are a handoff summary (checked, ruled out, evidence) and a
  ready-to-paste ticket note. The PSA is ConnectWise Manage.

## Ticket drivers

- 2026-10-16 · owner · [lockout] [sign-in] [drive-maps] [files] [citrix] [fslogix] [avd]
  [entra] [m365] · recurring: All of these are big time sinks for the helpdesk: lockouts and
  sign-in failures, drive maps and file access, Citrix/FSLogix/AVD, and M365/Entra/mailbox.
- 2026-10-16 · owner · [citrix] [fslogix] [avd] [entra] [m365] · recurring:
  Citrix/FSLogix/AVD and M365/Entra/mailbox tickets usually take longer than the others.

## Where techs leave the tools

- 2026-10-16 · owner · recurring: Techs still check by hand in all of these places:
  - Admin portals: Entra, M365 and Exchange admin centers, sign-in logs.
  - Event Viewer on servers, remoting to DCs or VDAs to read logs.
  - Citrix and AVD consoles: Studio, Director, the Azure portal for session hosts.
  - ADUC and GPMC, clicking through users, groups and GPOs.

## Adoption

- 2026-10-16 · owner · [bundle] · recurring: Michael runs most of the tools himself; techs
  rarely run them yet.
- 2026-10-16 · owner · [bundle] · recurring: What keeps techs from running them: they don't
  know which tools exist or when to use each one; the output is too technical and needs
  interpreting; and the bundle is new, so it isn't a habit yet.
- 2026-10-16 · repo-history · [bundle] · recurring: Consolidation rounds (PRs #11-#16)
  merged or retired many near-duplicate tools because it was unclear which one to run. The
  root README needed a "retired tools -> use instead" table.

## Trust breakers (wrong or confusing output)

- 2026-09-14 · repo-history · recurring: The drive-map verdict engine made up findings from
  null evidence, and Windows PowerShell 5.1 array-shape bugs hid true findings.
- 2026-10-14 · repo-history · once: The access report flagged primary-group members as
  duplicate access.
- 2026-10-16 · repo-history · recurring: Several fixes corrected lockout evidence merging and
  audit-policy wording. A confident wrong answer is the most costly failure (see P-001).

## Client environment facts

- 2026-10-16 · owner · recurring: The client mix is mixed and mostly hybrid: on-prem AD plus
  Entra/M365 at most clients.
- 2026-10-16 · owner · recurring: Clients run all of Citrix, AVD and RDS, and some have
  little or no VDI. No single platform can be assumed.
- 2026-10-14 · repo-history · recurring: Server 2012/2012 R2 still turns up; several tools
  were lowered to a PS 3.0/4.0 floor so they run there.

## Manual chores

- 2026-10-16 · owner · [bundle] · recurring: Rebuilding the ServiceDesk-Toolkit bundle
  (`Build-ServiceDeskToolkit.ps1 -Zip`) and uploading it to SharePoint by hand.
- 2026-10-16 · owner · [reporting] · recurring: Explaining to techs what a report means.
- 2026-10-16 · owner · [reporting] · recurring: Turning tool output into something a
  client can read.
- 2026-10-16 · repo-history · [bundle] · recurring: User guides such as the
  M365-SyncedUserFixes quickstart .docx are built by hand outside the repo, in a gitignored
  `dist/`.

## Feedback and requests

Word-for-word quotes from techs and clients ("I just use ADUC because..."). None recorded yet.

## Open questions (answer when known; each answer becomes a signal)

- Rough ticket counts per area from ConnectWise. Which area is really the largest?
- Which bundle tools get run at all once techs start using it?
- A recent escalation where the tech's reasoning was missing: what would have helped?
