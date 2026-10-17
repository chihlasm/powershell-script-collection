# I-01 · M365 user check: "Can this user sign in to Microsoft 365, and is it a sync problem?"
- Champion: all six lenses (user-in-the-moment, manager-or-buyer, architect, newcomer, security,
  market-analyst); stage design from architect r2
- Score: 29.5 (F 4, T 4, D 3, E 3, R 4)

## The pitch
This is the cloud version of AD-UserQuickCheck: enter one user and get YES / NO / PROBABLY NOT
for Microsoft 365, with the reason and a "What to do" line. It covers sign-in blocked, no
licence, no MFA method, Conditional Access failure, smart lockout and other decoded sign-in
failures, and on the sync side "never synced", "cloud copy three days stale" and "another
object holds this address". The first line always states what the tool could and could not
see in this tenant, so a tenant without Entra ID P1 gets "Sign-in logs: not available" instead
of a false all-clear.

## A day with it
A user at a hybrid client says Outlook keeps asking for a password. The tech runs the check
with the user's UPN. The banner reads "Tenant: contoso.onmicrosoft.com · signed in as
tech@msp · Sign-in logs: available (P1) · CA detail: available". The verdict says "NO: last 6
sign-ins failed with 50053 (account locked by smart lockout). failureReason: '...'. Next step:
wait for the lockout window or find the source of the bad passwords; see
https://login.microsoftonline.com/error?code=50053". The AD comparison shows on-prem is fine.
Without the tool, the tech would have opened the Entra sign-in logs, filtered by user and read
the raw rows.

## Why us, why now
- **Owner signals:** SIGNALS 2026-10-16 [entra][m365]: these tickets are among the slowest, and
  techs work them by hand in the Entra, M365 and Exchange admin centers and sign-in logs. Client
  facts 2026-10-16: most clients are hybrid.
- **Gap in the bundle:** `ServiceDesk-Toolkit/README.md` "Can't sign in" sends the cloud side to
  the portal. Recon-code found no per-user cloud sign-in lookup anywhere in the repo.
- **Market gap:** Entra's sign-in diagnostic is portal-only
  ([sign-in diagnostics](https://learn.microsoft.com/entra/identity/monitoring-health/howto-use-sign-in-diagnostics)).
  MSOnline's `Get-MsolUser -HasErrorsOnly` was retired with no replacement (K-r1). Sync
  "healthy" while users are missing is a common Q&A complaint (recon-market pain 13;
  [tshoot-connect-objectsync](https://learn.microsoft.com/entra/identity/hybrid/connect/tshoot-connect-objectsync)).
  CIPP has a per-user view, but it is a separate web app the MSP would have to run (open
  question below).
- **Code leverage:**
  - `Get-M365SecurityEvidence.ps1`: per-user signIns call (around line 1080), CA calls,
    `Invoke-MgGraphRequest` with only Microsoft.Graph.Authentication.
  - `Get-EntraPasswordPolicy`: per-user expiry and smart lockout.
  - AD-UserQuickCheck: verdict wording and the AD lookups for stage 2.
  - `SyncedUserFixes.Core.ps1` (`Get-ADSyncRule` / `Get-ADSyncConnector`) and
    `Test-EntraConnectReadiness.ps1` (scheduler and staging state) for stage 3.
  - The core/UI split from M365-SyncedUserFixes.
- **Facts verified by the critic on Learn:**
  - `GET /auditLogs/signIns` and `signInActivity` fail with
    `Authentication_RequestFromNonPremiumTenantOrB2CTenant` without P1/P2. Request
    `Directory.Read.All` together with `AuditLog.Read.All`. Readers: Global Reader, Reports
    Reader, Security Admin/Operator/Reader. `appliedConditionalAccessPolicies` only appears for
    roles that can read CA
    ([signin-list](https://learn.microsoft.com/graph/api/signin-list?view=graph-rest-1.0),
    [premium-licence troubleshooting](https://learn.microsoft.com/troubleshoot/entra/entra-id/users-groups-entra-apis/b2c-or-tenant-premium-license-sign-in-activities)).
  - Risky user needs **P2** ([riskyuser-get](https://learn.microsoft.com/graph/api/riskyuser-get?view=graph-rest-1.0)).
  - Reading MFA methods needs `UserAuthenticationMethod.Read.All` plus Global Reader or an
    authentication admin role
    ([authentication-list-methods](https://learn.microsoft.com/graph/api/authentication-list-methods?view=graph-rest-1.0)).
  - Sync fields (`onPremisesSyncEnabled`, `onPremisesLastSyncDateTime`,
    `onPremisesProvisioningErrors`) are on the user resource
    ([user](https://learn.microsoft.com/graph/api/resources/user?view=graph-rest-1.0)).

## The strongest objection
The headline answer depends on a licence and on consent that many client tenants may not have.
Without Entra ID P1, smart lockout, CA failures and decoded sign-in errors are invisible,
because they only appear in the sign-in logs. In a Business Standard tenant the tool falls back
to account state, licence and sync, which is roughly what the M365 admin center already shows.
Every client tenant also has to consent to the Graph app for `AuditLog.Read.All`,
`Directory.Read.All` and `UserAuthenticationMethod.Read.All`, and every tech workstation needs
Microsoft.Graph.Authentication installed. Nobody yet knows what share of clients have P1.

**Answer:** partly. The sync half (stages 1-3) works without P1, and for a mostly hybrid client
base "is it a sync problem?" is a slow, by-hand question on its own. The tenant gate turns the
licence gap into an honest "could not check" in the first line instead of a false all-clear
(P-001). Whether the sign-in half is worth it depends on the P1 share and on GDAP consent, which
are open questions for Michael.

## Cost and risk
- **Size:** M for the core, the tenant gate and the sign-in verdict (stages 1-2). Stage 3, the
  Entra Connect server look (OU scope, filtering rule, scheduler and staging state), follows in a
  second release.
- **Packaging:** one new folder with two entry scripts over one core: this check and the mailbox
  check (I-02). The sign-in check runs with Global Reader. The mailbox stage needs a higher
  Exchange role and must be able to fail on its own while this verdict still prints. Add one
  bundle row; the START HERE "Can't sign in" row points here.
- **Build conditions from the critic:**
  - The tenant and admin banner prints first, so nobody runs it against the wrong client.
  - Explain sign-in failures from the log's own `status.failureReason`, plus a link to
    `https://login.microsoftonline.com/error?code=<n>`. Do not ship a cached AADSTS table:
    Microsoft says codes "are subject to change at any time"
    ([reference-error-codes](https://learn.microsoft.com/entra/identity-platform/reference-error-codes)).
    A small cited "what to do next" map for 50053, 50126, 50057, 50055, 53003 and 530035 is
    allowed, marked "meaning per Microsoft, may change". (This is the AADSTS part of I-05.)
  - Mark risky user as P2-only.
  - Stage 3 says "can't tell" on a staging-mode Connect server, never "out of scope".
- **Floor:** PS 5.1, which root CLAUDE.md allows for Graph tools. This runs on the tech
  workstation, not on client servers, so the install of Microsoft.Graph.Authentication is the
  same one Get-M365SecurityEvidence already needs.
- **What could go wrong:** wrong-tenant runs (banner), "no problems found" on a non-P1 tenant
  (gate plus test), intermittent licence errors if `Directory.Read.All` is missing (request
  both scopes).
- **Risk profiles:** personal-data (sign-in logs carry IPs and locations; keep output local,
  paste-safe note omits raw IPs). Read-only; no destructive or system-configuration exposure.

## Score reasoning
- Frequency 4: M365 and sign-in tickets are named recurring time sinks at mostly hybrid clients.
- Time saved 4: replaces a tour of the Entra sign-in logs, admin center and Connect server; it
  drops toward 2 on tenants without P1, where only the sync half adds much.
- Differentiation 3: portal-only diagnostics, retired MSOnline and no local verdict tool, but
  CIPP's per-user view covers part of it if the MSP runs CIPP.
- Effort 3: M; Graph consent, a tenant gate and a new folder, though most calls already exist in
  Get-M365SecurityEvidence.
- Risk 4: read-only with a least-privilege role; the main risk (false all-clear on a blind
  tenant) is handled by the gate.
