# I-08 · "Why did this user get a temporary profile?" one-user VDI verdict (plus AVD host checks)
- Champion: architect, user-in-the-moment (AVD host checks: market-analyst, architect, newcomer)
- Score: 29 (F 3, T 4, D 4, E 3, R 4)

This card carries two ideas the critic sent to the same place. The main idea is I-08, the
temporary-profile investigation. The second is I-09, which the critic did not want as a new
folder; it becomes an AVD check set inside Citrix-FSLogix-Triage, the tool I-08 runs. The score
is for I-08; I-09 is a small add-on (see Cost and risk).

## The pitch
Enter a username and a session host (or a Delivery Controller to find the host through
Citrix). The tool runs the existing FSLogix collectors against that host, checks which machine
holds the user's profile disk open, and returns one ranked cause with the next step: disk
locked by another host or a stuck session, share permission, Cloud Cache unreachable, frxsvc
stopped or crashed, an existing local profile, or disk full. On AVD hosts the same triage also
explains why a host shows Unavailable or refuses connections, without an Azure sign-in.

## A day with it
Jane calls at 08:40: her desktop is empty and her Outlook wants to set up again. The tech runs
the check with `-Identity jane -DeliveryController CTX-DDC01`. It finds Jane on CTX-07 and reads
the FSLogix logs there. `Get-SmbOpenFile` on the profile file server shows her VHDX held open by
CTX-04. The verdict: "Jane has a stuck disconnected session on CTX-04 holding her profile disk.
Log it off, then have her sign in again." The I-03 note goes into the ticket. Before, this meant
remoting to two VDAs, Director and the file server, and running two reports.

## Why us, why now
- **Owner signals:** SIGNALS 2026-10-16 [citrix][fslogix][avd]: these are among the slowest
  tickets, and techs remote to VDAs and use Studio, Director and the Azure portal by hand.
  Clients run all of Citrix, AVD and RDS (client facts 2026-10-16).
- **Real-world pain:** at least five Microsoft Q&A threads with different causes of temporary
  FSLogix profiles (recon-market pain 11), for example
  [1](https://learn.microsoft.com/en-us/answers/questions/5552219/temporary-fslogix-profile-issue),
  [2](https://learn.microsoft.com/en-us/answers/questions/2007705/keep-getting-temporary-profile-with-fslogix-enable),
  [3](https://learn.microsoft.com/en-us/answers/questions/736507/fslogix-profiles-not-loading-for-users).
  The FSLogix known-issues page documents that event 26 is expected on Entra-only devices and
  that an frxsvc crash causes temporary profiles
  ([known issues](https://learn.microsoft.com/fslogix/troubleshooting-known-issues)). The
  built-in Profile Status tool can't filter by user or time (recon-market pain 7).
- **Market gap:** ControlUp's FSLogix actions are paid
  ([ControlUp](https://www.controlup.com/blog/controlup-script-actions-for-fslogix-profile-container/)).
  FSLogixDoctor decodes codes but is a gallery install whose code was not reviewed
  ([gallery](https://www.powershellgallery.com/packages/FSLogixDoctor/1.6.0)). Nobody free
  gives one user, one cause, with the lock holder.
- **Code leverage:** Citrix-FSLogix-Triage (CheckId output, AVD deployment mode already
  present), Parse-FSLogixLogs, Get-FSLogixStorageEvents, RDS-FSLogix-EventExport,
  Get-CitrixSessions, and the gate -> collect -> verdict -> SUMMARY pattern from the lockout and
  drive-map tools.
- **Verified:** `Get-SmbOpenFile -CimSession <fileserver> -ClientUserName <user>` returns open
  files with the client computer
  ([Get-SmbOpenFile](https://learn.microsoft.com/powershell/module/smbshare/get-smbopenfile)).
  AVD agent events, registry and fixes:
  [troubleshoot-agent](https://learn.microsoft.com/troubleshoot/azure/virtual-desktop/troubleshoot-agent),
  [session host statuses and health checks](https://learn.microsoft.com/azure/virtual-desktop/troubleshoot-statuses-checks).

## The strongest objection
The bundle already has this path: "Citrix-FSLogix-Triage, then RDS-FSLogix-EventExport". The gain
is one verdict instead of two reports, and the cost is a third copy of the gate -> collect ->
verdict orchestrator (recon-code engine 3) in a repo with no shared module. The appealing "find
the user on any platform" part is an L-sized session finder across the Citrix Broker SDK, RDS
and AVD, each with its own prerequisites and rights. For the AVD half, the AVD agent already
runs health checks that the portal shows, Microsoft ships `WVDAgentUrlTool.exe`, and an
Unavailable host is a senior-engineer incident rather than a tier-1 ticket; there is no
AVD-specific ticket count.

**Answer:** the two-step path leaves the tech to correlate two reports and still doesn't say
who holds the disk; the lock holder and a ranked cause are what close the ticket. v1 limits
discovery to `-ComputerName` or the Citrix lookup and leaves RDS/AVD discovery for later. The
tool replaces the bundle's profile row instead of adding one. The third orchestrator copy is a
real cost and should be accepted knowingly. The AVD part is cut to a check set in an existing
tool, with no new folder or bundle row, which matches its weaker evidence.

## Cost and risk
- **Size:** M for the I-08 orchestrator over the existing collectors. S-M for the I-09 AVD check
  set in Citrix-FSLogix-Triage:
  - RDAgentBootLoader running
  - `HKLM\SOFTWARE\Microsoft\RDInfraAgent\IsRegistered`
  - Application event 3277 with INVALID_REGISTRATION_TOKEN, EXPIRED_MACHINE_TOKEN, INVALID_FORM,
    ENDPOINT_NOT_FOUND or InstallMsiException
  - events 3703, 3019 and 3389
  - `qwinsta` rdp-sxs Listen state
  - each finding links to the Learn fix
- **Touches:** a new folder for the orchestrator; Citrix-FSLogix-Triage (new checks); the
  ServiceDesk-Toolkit profile row (replaced).
- **FSLogix code table:** lives in this tool's reference psd1 with Learn citations and a parity
  test (this is the FSLogix part of I-05).
- **Out of v1:** Azure Files lock holders (need Az); RDS and AVD session discovery.
- **Floor:** collectors stay at their current floors; `Get-SmbOpenFile` needs a Server 2012+ file
  server, and older ones get "can't tell who holds the disk".
- **What could go wrong:** ranking the wrong cause when two are present (show the evidence for
  each); reading a stale lock after the session ended; event-ID meanings drifting across FSLogix
  versions (cite each).
- **Risk profiles:** personal-data (user names, session and profile paths in output; paste-safe
  note drops profile paths). Read-only; it recommends a logoff but never performs one.

## Score reasoning
- Frequency 3: Citrix/FSLogix/AVD are the slowest ticket area, but temporary profiles are one
  symptom within it and some clients have no VDI.
- Time saved 4: replaces remoting to several VDAs, Director and the file server plus two reports
  with one verdict that names the lock holder.
- Differentiation 4: paid (ControlUp) or code-decoding only (FSLogixDoctor); no free one-user
  verdict with the lock holder.
- Effort 3: M; a third orchestrator copy, though every collector exists.
- Risk 4: read-only; the risk is a confidently wrong ranked cause, handled by showing evidence per
  cause and "can't tell" when a collector fails.
