# I-03 · Ticket note from every quick check: "Checked / Ruled out / Could not check / Next step"
- Champion: manager-or-buyer, architect (with user-in-the-moment, security)
- Score: 30.5 (F 5, T 3, D 3, E 4, R 4)

## The pitch
Every verdict tool ends by writing the same four-part note to a text file and the clipboard,
ready to paste into ConnectWise: Checked, Ruled out, Could not check, Next step. Each note has
a stamp (tenant or domain, account that ran it, machine, time, "Changed anything: No/Yes") and
the paths to the evidence. With `-TicketNumber`, every tool's note lands in one ticket folder,
and a small joiner concatenates them with two free-text lines (what the user reported, what the
tech tried by hand). Michael sees on escalation what the tech checked and how they ruled things out.

## A day with it
A tier-1 tech has a user who says the S: drive is missing. She runs AD-UserQuickCheck and
DriveMap-Diagnostics with `-TicketNumber 482113`. Each prints its verdict and drops a note into
`482113\`. She runs the joiner, types "user says S: vanished after Monday's reboot" and "tried
gpupdate /force", and pastes the result into the ticket. When she escalates, Michael reads
"Ruled out: account locked, password expired. Could not check: GPO result on PC-114 (WinRM
refused). Next step: run DriveMap-Diagnostics on the PC itself." and continues from there
without calling her back.

## Why us, why now
- **Owner signals, best in the session:** all three SIGNALS 2026-10-16 [escalation] entries
  ask for this. Techs escalate because they don't know how to resolve the issue. Michael wants
  to see what they checked and ruled out, and that reasoning is not captured today. A handoff
  summary and a pasteable note are named as the most useful outputs. The PSA is ConnectWise
  Manage.
- SIGNALS [reporting]: Michael spends time explaining reports to techs. A plain four-part note
  is the explanation.
- **Code leverage (recon-code):**
  - Only the lockout orchestrator writes a SUMMARY.txt "for pasting into a ticket".
  - The CheckId result shape exists in only two tools, and AD-UserQuickCheck has no `-PassThru`.
  - `ConvertTo-HtmlSafe` is redefined in 6-8 files.
  - The precedent for a copied shared file plus a parity test is
    `Tests/SharedReferenceParity.Tests.ps1`.
- **Market gap:** RMMs, PingCastle-style scanners and portal tools produce reports or
  dashboards, not a "checked / ruled out / could not check" handoff for a PSA ticket (recon-market).
- PRINCIPLES fit: the note is a local file plus clipboard. Nothing goes to the PSA through an
  API, and nothing leaves the machine.

## The strongest objection
A note that fills "Ruled out" automatically writes a permanent claim into ConnectWise. A check
that "passed" because it was blind would become "ruled out" in the ticket history. That is
exactly the confident wrong answer P-001 forbids, and this repo has shipped that failure before:
the drive-map engine made up findings from null evidence (SIGNALS 2026-09-14), and lockout
evidence-merge bugs followed (2026-10-16). The note also does not fix the first adoption
blocker: techs do not run the tools at all (SIGNALS [bundle]).

**Answer:** a check counts as "Ruled out" only when its gate reported that it could look.
Everything else goes under "Could not check". A unit test proves that a gated-out check never
lands under "Ruled out". On adoption: the note does not create the habit, but it gives a tech a
reason to run a tool (it writes their ticket note for them), and it is the shared format that
I-01 and I-08 plug into.

## Cost and risk
- **Size:** S-M. A `CaseKit.ps1` (`New-TicketNote`, result writer, HTML-safe encoding, report
  shell) copied into each tool folder, with a parity test. The joiner is S and stays a plain
  concatenation; anything that runs tools in sequence is the killed I-04.
- **First slice:** AD-UserQuickCheck (also gets `-PassThru`), Network-QuickCheck,
  Citrix-FSLogix-Triage. Then AD-LockoutDiagnostics and DriveMap-Diagnostics.
- **Clipboard:** `Set-Clipboard` on 5.0+. On 3.0/4.0, use
  `[System.Windows.Forms.Clipboard]::SetText()` (powershell.exe is STA by default since 3.0),
  wrapped in try/catch for `-Mta` and non-interactive hosts. Never pipe to `clip.exe`: Windows
  PowerShell encodes piped text with `$OutputEncoding`, which defaults to ASCII in 5.1, so
  "Müller" arrives as "M?ller"
  ([about_Preference_Variables](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-5.1),
  [about_PowerShell_exe](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1),
  [Set-Clipboard](https://learn.microsoft.com/powershell/module/microsoft.powershell.management/set-clipboard?view=powershell-5.1)).
  The text file is the guaranteed output.
- **Paste-safe mode:** leaves out raw IPs, rule contents and profile paths, because ConnectWise
  notes can be visible MSP-wide and sometimes to the client.
- **What could go wrong:** the "Ruled out" leak above; a 3.0-floor tool picking up a 5.0
  feature through the kit (caught by `Tests/PSVersionFloor.Tests.ps1`); kit copies drifting
  (caught by the parity test).
- **Risk profiles:** personal-data (notes and ticket folders hold client names, hosts and
  findings; stay local, and follow the gitignore rule for output folders). Read-only otherwise.

## Score reasoning
- Frequency 5: every quick-check run and every escalation produces a note.
- Time saved 3: saves writing the note (a few minutes) and saves Michael the call-back on
  escalation; it does not shorten the diagnosis itself.
- Differentiation 3: no market tool writes a gate-aware handoff for a PSA, but it is a format
  rather than new diagnostic capability.
- Effort 4: S-M; a kit plus parity test and small edits to three tools for the first slice.
- Risk 4: read-only and local; the one real risk ("blind check written as ruled out") has a
  named test that prevents it.
