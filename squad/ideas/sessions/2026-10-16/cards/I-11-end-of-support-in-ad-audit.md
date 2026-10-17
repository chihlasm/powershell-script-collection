# I-11 · End-of-support section in AD-Audit
- Champion: manager-or-buyer, market-analyst
- Score: 25.5 (F 2, T 3, D 2, E 5, R 5)

## The pitch
AD-Audit gains an "End of support" section that lists every Windows Server in the domain by OS
version with Microsoft's lifecycle end date, how many days are left (or how long ago support
ended), and last logon. The CSV is dated and records who ran it, so the next audit can be
compared with this one ("4 unsupported servers in July, 1 now"). No new tool: it is a cited date
table and a section in a tool seniors already run.

## A day with it
Michael runs AD-Audit for a client ahead of a quarterly meeting. The new section shows two
Server 2012 R2 boxes whose last ESU year ended on 2026-10-13, and five Server 2016 servers with
extended support ending 2027-01-12, under 90 days away. He forwards the section to the account
manager as the start of a migration conversation, instead of building the list by hand from
the computer export and the lifecycle site.

## Why us, why now
- **Timing:** Server 2012 R2 ESU Year 3 ended 2026-10-14 06:59 PT, i.e. end of 2026-10-13
  ([Server 2012 R2 lifecycle](https://learn.microsoft.com/lifecycle/products/windows-server-2012-r2)).
  Server 2016 extended support ends 2027-01-13 06:59 PT, i.e. end of 2027-01-12
  ([Server 2016 lifecycle](https://learn.microsoft.com/lifecycle/products/windows-server-2016)).
- **Signals:** SIGNALS 2026-10-14 (repo-history): Server 2012/2012 R2 still turns up at clients.
  SIGNALS [reporting]: turning output into something a client can read is a recurring chore.
- **Market:** third parties sell Server 2016 end-of-support assessments for around $2,950
  ([example](https://o365hq.com/services/windows-server-2016-end-of-support-assessment)), though
  they do more than this section. Insurers ask whether clients run unsupported operating systems
  (manager-or-buyer lens; no source beyond the lens).
- **Code leverage:** AD-Audit already enumerates computers and OS versions; its dark-theme HTML
  renderer and CSV export are reused.

## The strongest objection
This is sales and lifecycle reporting, not the product's stated purpose of faster
troubleshooting and more accurate data collection for the service desk. There is no helpdesk
ticket signal for it. AD-Audit already lists OS versions, and every RMM reports them, so the only
new data is the end date and a quarter-to-quarter comparison. The richer version (roles, tasks
and services running as domain accounts) means remoting into exactly the oldest, least reachable
servers.

**Answer:** the objection holds against the original "quarterly client risk review" bundle, which
is dropped. What remains is an S-sized section in an existing senior-engineer audit tool, which
fits "audits across client environments" in PRINCIPLES. It adds no remoting. Services and tasks
running as domain accounts are kept only as a possible optional feature of the lockout tools,
where they help troubleshooting.

## Cost and risk
- **Size:** S. A psd1 of OS version -> end dates with a Learn lifecycle citation per row, a section
  in the AD-Audit report and CSV, and tests for date edge cases (ESU vs extended end; the "06:59
  PT next day" boundary).
- **Touches:** AD-Audit only.
- **What could go wrong:** wrong or stale dates (cite each, and show the date the table was last
  checked); ESU-covered servers shown as unsupported (say "extended support ended; covered only
  if the client bought ESU", since AD can't tell).
- **Risk profiles:** none beyond AD-Audit's existing ones. Read-only, AD-only.

## Score reasoning
- Frequency 2: per-client audits, quarterly at most; no ticket driver.
- Time saved 3: saves building a server-by-lifecycle list by hand for each client audit.
- Differentiation 2: RMMs report OS; paid assessments exist; only the cited dates and comparison
  are new.
- Effort 5: S; a cited table and a report section in one existing tool.
- Risk 5: read-only, no new remoting, no new permissions.
