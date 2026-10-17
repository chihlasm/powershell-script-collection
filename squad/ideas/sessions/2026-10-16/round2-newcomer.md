# Round 2: the newcomer lens (cross-pollination)

Lens: first month on the service desk. I don't know which of 60 folders to open, and error codes
mean nothing to me yet. I read all six round-1 lists with one question: at the moment a new tech
picks up the ticket, which of these ideas would they actually reach, understand and trust?

Where the lenses agree: five of six proposed the cloud sign-in check, four proposed a mailbox
check, and four proposed a front door (newcomer "Start a ticket", user-in-the-moment "Look up this
person", manager "Start Here", architect "What's the problem?"). I don't add another copy of
those. The three entries below change how they get built, so that a new tech can use them.

---

### One verified "what this code means" table, used by every verdict and searchable by the tech
`COMBINES "What does this error mean?" (newcomer) + "Cloud sign-in check" (architect, all five versions) + "Shared case kit" (architect)`

- Pitch: Build the error-code meanings once, as one cited reference file: AADSTS sign-in errors,
  NTLM/Kerberos status codes, lockout event fields, FSLogix status codes, and the Kerberos RC4
  KDCSVC events. Each entry has a plain-English meaning, "real problem or harmless?", a next step,
  and the bundle tool to run. The cloud sign-in check, the lockout tools, the FSLogix
  temp-profile investigation and the RC4/NTLM scan all read their verdict wording from it. A tech
  can also paste a code from a screenshot into a small lookup and get the same sentence.
- Who and when: A new tech on day three, looking at a user's screenshot that says "AADSTS50076"
  or "0xC000006A". They can't choose a tool until they know whether this is a password, MFA,
  network or profile problem. The same sentence then shows up in the sign-in check's verdict, so
  the tech learns one vocabulary and doesn't have to reconcile two.
- Evidence: The architect says the real work in the cloud sign-in check is "the sign-in
  error-code table (it must be cited on Learn, P-001)". The temp-profile investigation (architect)
  and the RC4/NTLM scan (manager, market, security, architect) each need their own table too. If
  each tool writes its own, that is three or four copies of the hardest-to-verify content. The
  repo already copies reference data across folders safely: `LockoutReference.psd1`, with
  `SharedReferenceParity.Tests.ps1` failing when a copy drifts (recon-code engine 5). Trust
  breakers (SIGNALS 2026-10-16 repo-history) were all wrong or confusing meanings: 4776 `0x0`
  read as failure, and the audit-policy wording. A single cited table fixes a meaning once for
  every tool. Recon-market pain 11: Microsoft says FSLogix event 26 on Entra-only devices can be
  ignored. "Harmless" entries are what stop a new tech chasing the wrong cause. SIGNALS [bundle]:
  "output is too technical and needs interpreting", and [reporting]: Michael spends time
  "explaining to techs what a report means". A shared table writes that explanation once.
- Builds on: `AD-LockoutDiagnostics/LockoutReference.psd1` (already cited),
  `DriveMap-Diagnostics/DriveMapReference.psd1`, the parity test, and the bundle builder's
  manifest, which ships the file inside each folder that uses it. This is the same
  copy-per-folder model the architect's case kit uses. Unlike the HTML shell, this is the piece
  of the kit where drift does real harm.
- Size guess: S for the file plus the lookup, seeded from the lockout codes that are already
  verified. Each new tool adds its own section as it is built, verified on Learn
  (`learn.microsoft.com/entra/identity-platform/reference-error-codes` for AADSTS. The FSLogix
  and KDCSVC pages still need confirming).
- Why this order: It must exist before the cloud sign-in check is written. Otherwise the AADSTS
  meanings get hard-coded into that tool and copied again into the next one.

### A front door that is honest about doors that don't exist yet, and records the manual checks too
`BUILDS ON "Start a ticket" / "Start Here" / "What's the problem?" / "Look up this person" (newcomer, manager, architect, user-in-the-moment)`

- Pitch: Ship the front door now, over the tools that exist. Where a symptom has no tool yet
  (Outlook/Teams sign-in, mailbox, AVD, "PC is slow"), don't hide that symptom and don't
  pretend. Show a short, specific manual check, for example: "Open Entra admin center > Users >
  [user] > Sign-in logs. Copy the error code from the latest failure." Ask the tech what they
  found, and paste the code into the lookup above. Every manual answer goes into the ticket note
  next to the automated results, marked "checked by hand". When a real tool ships for that
  symptom, it replaces the manual step.
- Who and when: The new tech in the first weeks, on the slow ticket types SIGNALS names
  (M365/Entra/mailbox, AVD). Those are the tickets where the toolkit has no answer today, and
  where a new tech most often escalates with nothing written down. A senior skips the questions
  with `-Identity -ComputerName -Symptom` and gets the same note.
- Evidence: The manager's version admits it: "Without those [new quick checks], about half of
  the doors lead nowhere." All four front doors are sized L because they wait on new tools. But
  SIGNALS 2026-10-16 "Where techs leave the tools" shows techs already do these checks by hand in
  the portals. What's missing is any record of them: "Today that reasoning is not captured"
  ([escalation]). A front door that records manual checks answers the owner's top request on the
  first day. It doesn't need to wait for the cloud, mailbox and AVD tools. "Look up this person"
  runs everything and puts a combined "most likely problem" at the top. For a new tech, a guessed
  combined cause across six systems is exactly the confident wrong answer P-001 forbids, and it
  can't ship until all six tools exist. Asking the symptom first, then running one door, keeps
  each verdict tied to the tool that produced it. `ServiceDesk-Toolkit/README.md` "Can't sign in"
  already sends this case to the portal in prose. This turns that prose into a step whose result
  gets recorded.
- Builds on: the CheckId contract (a manual step is just a check with `Status` filled in by the
  tech and `Evidence` = what they typed), `Run-AccessReport.bat` and `Start-LockoutWorkbench.ps1`
  menus, the PerfTriage child-process runner, the manager's Handoff Builder for the note, and the
  START HERE table as the symptom list. Output is a local text file and clipboard only.
- Size guess: M for the first cut (four existing tools plus manual steps for the uncovered
  symptoms). It is not L, because the missing tools become later upgrades, not blockers.
- Not a tutorial: the manual step is one or two lines pointing at a portal, and the tech can
  skip it. Nothing is hidden from seniors. Every underlying tool still runs on its own.

### Mailbox check that always looks for a takeover, because a new tech can't tell which ticket they have
`COMBINES "Mailbox quick check" (newcomer, user-in-the-moment, manager, market, architect) + "Compromised-account first look" (security)`

- Pitch: Make one mailbox tool, not two. Every run checks the takeover signs first: forwarding
  to an outside address, inbox rules that delete, move or mark mail as read, recently added MFA
  methods, and recent app consents. If any are found, the top of the report says "Possible
  account takeover. Do NOT reset the password or delete the rule yet. Escalate now. Evidence is
  saved." Only after that does it answer the everyday questions: who has access, is it full, is
  it shared, did the message arrive.
- Who and when: The new tech whose ticket says "I'm not getting some emails" or "my emails are
  going missing". They will treat it as a mailbox problem, because nothing on the ticket says
  "hacked". Security's version runs only when someone already suspects compromise. A new tech
  would never pick that tool for this ticket, so the evidence is lost when they "fix" the rule.
- Evidence: Security notes that "the natural first instinct (reset password, revoke sessions)
  destroys or muddies evidence". A new tech is the person most likely to act on that instinct.
  The manager's version already puts "possible compromise: escalate now" at the top. My round 1
  noted that external forwarding rules signal compromise. That makes three lenses describing the
  same check from different directions. SIGNALS [bundle]: techs don't know which tool to run.
  Splitting one ticket symptom across two tools makes that worse, which is why PRs #11-#16 merged
  near-duplicate tools (SIGNALS repo-history). Market: the old `Get-MessageTrace` is deprecated in
  favour of `Get-MessageTraceV2` (market analyst, Learn link), so community scripts a tech might
  find are broken.
- Builds on: `Get-M365SecurityEvidence`'s Exchange Online connection and Graph REST calls, the
  zip and SHA-256 evidence pattern from `Entra-DeviceActivityTimeline`, and security's
  guardrails, which carry over unchanged (read-only scopes, tenant name printed at the top,
  "could not check" when a role or licence is missing, output in the gitignored case folder).
- Size guess: M. It is one tool where there were two Ms, and the takeover checks are the reason
  it exists.
- Open for the critic: sign-in risk and location checks need sign-in log access (P1, from the
  cloud sign-in check discussion). Without P1, the takeover section must say "partly checked:
  mailbox rules yes, sign-ins could not look". It must not say "no signs of takeover".
