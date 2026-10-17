# I-06 · "Is Kerberos/NTLM enforcement breaking this?" scan across all DCs
- Champion: manager-or-buyer, architect, security, market-analyst
- Score: 24 (F 2, T 4, D 3, E 3, R 3)

## The pitch
One run across every DC finds the accounts, services and devices that the 2026 Kerberos RC4
changes and NTLM auditing are blocking or warning about right now, and gives each a plain
verdict: reset the password (no AES keys), set the encryption type on this service account, or
retire the device. A per-DC, per-feature gate says "can't tell" for any DC that cannot log the
event, instead of reporting "no problems". It never writes `msDS-SupportedEncryptionTypes`.

## A day with it
A client's scan-to-folder and an old line-of-business app both stopped authenticating after
April's updates, and the helpdesk has been treating it as lockouts. A senior engineer runs the
scan. It reads KDCSVC errors and 4769 failures with code 0xE on all four DCs and says:
"svc-scan has no AES keys: reset its password to create them. NAS01 (appliance) requests RC4
only: retire or update it, or set 0x24 on its account as Microsoft's documented RC4 exception."
DC04 (Server 2016 without the January 2025 update) is listed as "can't tell".

## Why us, why now
- **Timing (verified by the critic):**
  - KB5073381 (CVE-2026-20833): KDCSVC events 201-209 from 2026-01-13; accounts without
    `msDS-SupportedEncryptionTypes` default to AES-SHA1 only (0x18) from the 2026-04-14 updates;
    the rollback value is removed in July 2026; warnings 201/202/206/207 become errors
    203/204/208/209 ([KB5073381](https://support.microsoft.com/help/5073381)).
  - KB5021131 is the separate November 2022 change, not a conflict.
  - Learn's enctype table still says `0x0` defaults to RC4, which is out of date for DCs patched
    after April 2026, so the verdict must depend on each DC's patch level
    ([detect-remediate-rc4](https://learn.microsoft.com/windows-server/security/kerberos/detect-remediate-rc4-kerberos)).
  - NTLM auditing events 4020-4033 reach Server 2019/2022 DCs from 2026-10-13
    ([KB5064479](https://support.microsoft.com/help/5064479)).
- **Signals:** SIGNALS 2026-10-14: Server 2012/R2 DCs still turn up. These failures look like
  lockouts (market-analyst r1), and lockouts are an owner-named ticket driver; the existing
  lockout tools could misread them.
- **Market:** Microsoft links two free scripts (`Get-KerbEncryptionUsage.ps1`,
  `List-AccountKeys.ps1`) that work one DC at a time, print raw rows and give no verdict.
  ADAudit Plus sells RC4 reporting
  ([ManageEngine](https://www.manageengine.com/products/active-directory-audit/blog/rc4-encryption-being-phased-out-adaudit-plus-helps-audit-usage.html)).
  The gap is the domain-wide, patch-aware verdict, not detection.
- **Code leverage:** the lockout engine's multi-DC `Get-WinEvent`, the `Test-ADAuditPolicy`
  gate, and the cited reference psd1 plus parity test pattern.

## The strongest objection
There is no ticket signal for this, and the timing has moved: on 2026-10-16 it is no longer
"readiness". Clients either broke in April and fixed it, or are breaking now. The NTLMv1 half of
the original idea cannot be seen from DCs at all: `BlockNTLMv1SSO` (KB5066470) is a client-side
setting on Windows 11 24H2+/Server 2025, applies only without Credential Guard, only affects
MSCHAPv2 Wi-Fi/VPN SSO, and logs 4024/4025 on the endpoint
([KB5066470](https://support.microsoft.com/help/5066470)). And Microsoft's own free scripts
already do the detection.

**Answer:** reframed as "what is enforcement breaking now", with NTLMv1 SSO dropped. The value
left is a domain-wide verdict that respects each DC's patch level, which Microsoft's per-DC
scripts do not give. The fastest route to techs is shipping the 0xE / 203-209 check first as a
cause inside AD-UserQuickCheck or AD-LockoutDiagnostics ("not a password problem: encryption type
blocked"), with the full scan as a senior-engineer audit after.

## Cost and risk
- **Size:** M for the full scan; S for the first slice as a lockout/user-check cause.
- **Reads per DC:** KDCSVC errors 203/204/208/209 and warnings 201/202/206/207; 4769 failure code
  0xE (KDC_ERR_ETYPE_NOTSUPP); NTLM/Operational 4031/4033 on updated 2019/2022 DCs;
  `RC4DefaultDisablementPhase` and `DefaultDomainSupportedEncTypes`. Every ID and value is
  re-verified on Learn or the KB before coding, per root CLAUDE.md.
- **Per-feature gate:** KDCSVC events exist on 2012/2012 R2 only with ESU; 4768/4769 key fields on
  2019+, and on 2016 only with the January 2025 CU; 4030-4033 on 2019/2022 only after the October
  2026 updates; KB5064479 is inconsistent about 2016, so "can't tell" there.
- **KDCSVC/Kerberos/NTLM code table:** in this tool's reference psd1 with citations and a parity
  test (the on-prem part of I-05).
- **What could go wrong:** Microsoft's guidance is itself inconsistent (KB5073381 on whether
  enforcement starts in April or July; Learn's stale 0x0 row), so a confident verdict could be
  wrong; recommending 0x24 keeps RC4 alive and must be worded as an exception, not a fix.
- **Risk profiles:** read-only. It recommends account changes but makes none.

## Score reasoning
- Frequency 2: no ticket signal; hits only clients with RC4-only accounts or devices, though it
  can hide inside lockout tickets.
- Time saved 4: replaces reading KDCSVC and 4769 events on every DC by hand, or running
  Microsoft's scripts per DC and interpreting raw rows.
- Differentiation 3: free per-DC detection exists; the patch-aware, domain-wide verdict does not
  outside paid ADAudit Plus.
- Effort 3: M; per-DC, per-feature gating across 2012-2025 is fiddly.
- Risk 3: read-only, but built on shifting and partly inconsistent Microsoft guidance.
