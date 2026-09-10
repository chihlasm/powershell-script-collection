#
# LockoutReference.psd1
#
# Single source of truth for the documented Microsoft facts the lockout tools depend on:
# event IDs, status codes, and audit subcategory mappings.
#
# WHY THIS FILE EXISTS
# --------------------
# These constants were previously duplicated across five scripts, and the copies drifted.
# Two real defects resulted:
#   * Event 4740 was mapped to the 'Audit Account Lockout' subcategory in one script and
#     to 'Audit User Account Management' in another. The first is wrong, and it would have
#     declared a DC with no lockout auditing "healthy".
#   * Event 4776 status 0x0 was labelled a failure in one script, which reported a healthy
#     workstation as the top source of failed authentication.
# Fixing a value here fixes it everywhere.
#
# THIS IS A DATA FILE, NOT A MODULE. The repo convention is self-contained scripts with no
# shared modules; this is a deliberate narrow exception, scoped to this one folder, because
# duplicated documentation-derived constants have already produced wrong answers twice.
# Load with:  $Ref = Import-PowerShellDataFile "$PSScriptRoot\LockoutReference.psd1"
# Scripts degrade gracefully to their own built-in copies if this file is missing.
#
# EVERY VALUE HERE IS TRANSCRIBED FROM MICROSOFT LEARN. Do not edit from memory - follow
# the URL, confirm, and update the VerifiedOn date.
#
@{
    VerifiedOn = '2026-08-12'

    # -------------------------------------------------------------------------
    # Shared report stylesheet.
    #
    # Every report in this folder follows the same reading order:
    #   verdict (what this means + what to do)  ->  headline numbers  ->  detail
    #   ->  raw evidence, collapsed behind <details>
    #
    # The verdict is the largest text on the page because it is the only part many
    # readers will read. Raw tables are collapsed so a page opens short rather than
    # dumping hundreds of rows. A clean result stays quiet - a green "all fine" banner
    # only competes with the finding that matters.
    #
    # Kept here so a change applies to all four reports at once. Scripts fall back to
    # their own copy if this file is unavailable.
    # -------------------------------------------------------------------------
    ReportCss = @'
  :root {
    --bg:#15181c; --surface:#1d2126; --surface-2:#242931; --line:#333a44;
    --ink:#e8eaed; --ink-dim:#98a2b0; --ink-faint:#6d7885;
    --accent:#5dade2; --bad:#e2686a; --warn:#e0a458; --ok:#5fc98a;
    --space: clamp(20px, 4vw, 40px);
  }
  * { box-sizing:border-box; }
  body { background:var(--bg); color:var(--ink); margin:0; padding:var(--space);
         font-family:'Segoe UI',system-ui,sans-serif; line-height:1.55;
         max-width:1100px; margin-inline:auto; }
  .top { display:flex; flex-wrap:wrap; gap:8px 20px; align-items:baseline;
         padding-bottom:14px; border-bottom:1px solid var(--line); margin-bottom:var(--space); }
  .top h1 { font-size:15px; font-weight:700; letter-spacing:.14em; text-transform:uppercase;
            color:var(--ink-dim); margin:0; }
  .top .facts { color:var(--ink-faint); font-size:12.5px; display:flex; flex-wrap:wrap; gap:14px; }
  .top .facts b { color:var(--ink-dim); font-weight:600; }
  .verdict { border-left:5px solid var(--ink-faint); padding:4px 0 4px 20px; margin-bottom:26px; }
  .verdict.bad     { border-left-color:var(--bad); }
  .verdict.warn    { border-left-color:var(--warn); }
  .verdict.ok      { border-left-color:var(--ok); }
  .verdict.unknown { border-left-color:var(--ink-faint); }
  .verdict .label { font-size:11px; letter-spacing:.16em; text-transform:uppercase;
                    color:var(--ink-faint); margin-bottom:6px; }
  .verdict .line { font-size:clamp(20px, 3.4vw, 27px); line-height:1.25; font-weight:600;
                   color:#fff; margin:0 0 12px; letter-spacing:-.01em; }
  .verdict .next { font-size:15px; color:var(--ink-dim); margin:0; max-width:68ch; }
  .verdict ol { margin:10px 0 0; padding-left:20px; color:var(--ink-dim); font-size:15px;
                max-width:68ch; }
  .verdict li { margin:7px 0; }
  .alert { background:color-mix(in srgb, var(--warn) 12%, var(--surface));
           border:1px solid color-mix(in srgb, var(--warn) 45%, var(--line));
           border-radius:8px; padding:14px 18px; margin-bottom:24px; }
  .alert.stop { background:color-mix(in srgb, var(--bad) 12%, var(--surface));
                border-color:color-mix(in srgb, var(--bad) 45%, var(--line)); }
  .alert-title { font-weight:700; color:var(--warn); font-size:14px; margin-bottom:4px; }
  .alert.stop .alert-title { color:var(--bad); }
  .alert p { margin:4px 0; font-size:13.5px; color:var(--ink-dim); }
  .alert-sub { color:var(--ink-faint) !important; }
  .note { color:var(--ink-faint); font-size:13px; margin-bottom:24px; }
  .stats { display:flex; flex-wrap:wrap; gap:10px; margin-bottom:30px; }
  .stat { background:var(--surface); border:1px solid var(--line); border-radius:8px;
          padding:12px 18px; min-width:132px; flex:1 1 132px; }
  .stat .n { font-size:26px; font-weight:700; color:#fff; line-height:1.1;
             font-variant-numeric:tabular-nums; }
  .stat .n.bad { color:var(--bad); }
  .stat .n.ok  { color:var(--ok); }
  .stat .k { font-size:11.5px; color:var(--ink-faint); text-transform:uppercase;
             letter-spacing:.09em; margin-top:3px; }
  h2 { font-size:12px; letter-spacing:.15em; text-transform:uppercase; color:var(--ink-faint);
       margin:30px 0 14px; font-weight:700; }
  h3 { font-size:13px; color:var(--ink-dim); margin:18px 0 8px; font-weight:650; }
  .card { background:var(--surface); border:1px solid var(--line); border-radius:8px;
          padding:14px 18px; margin-bottom:10px; }
  .card.bad  { border-color:color-mix(in srgb, var(--bad) 40%, var(--line));
               background:color-mix(in srgb, var(--bad) 6%, var(--surface)); }
  .card.ok   { border-color:color-mix(in srgb, var(--ok) 30%, var(--line)); }
  .card-head { display:flex; align-items:baseline; gap:10px; flex-wrap:wrap; }
  .card-name { font-size:17px; font-weight:650; color:#fff; word-break:break-all; }
  .card-count { margin-left:auto; font-size:22px; font-weight:700; color:var(--ink);
                font-variant-numeric:tabular-nums; }
  .card-count small { font-size:13px; color:var(--ink-faint); font-weight:400; }
  .tag { font-size:10.5px; text-transform:uppercase; letter-spacing:.08em;
         color:var(--ink-faint); border:1px solid var(--line); border-radius:99px;
         padding:1px 8px; }
  .tag.bad  { color:var(--bad);  border-color:color-mix(in srgb, var(--bad) 50%, var(--line)); }
  .tag.ok   { color:var(--ok);   border-color:color-mix(in srgb, var(--ok) 50%, var(--line)); }
  .tag.warn { color:var(--warn); border-color:color-mix(in srgb, var(--warn) 50%, var(--line)); }
  .bar { height:3px; background:var(--surface-2); border-radius:99px; overflow:hidden;
         margin:10px 0 12px; }
  .bar span { display:block; height:100%; background:var(--accent); border-radius:99px; }
  .card.bad .bar span { background:var(--bad); }
  .kv { display:grid; grid-template-columns:auto 1fr; gap:3px 14px; margin:0; font-size:13px; }
  .kv dt { color:var(--ink-faint); white-space:nowrap; }
  .kv dd { margin:0; color:var(--ink-dim); word-break:break-word; }

  /* Ranked account cards (Get-ADLockoutHistory). These live HERE rather than only in
     that script because the combined case report discards each page's own <style> and
     builds on this sheet - a class defined only in the generator renders as unstyled
     text once combined. That failed twice: first .stats/.kv, then these. */
  .rank { background:var(--surface); border:1px solid var(--line); border-radius:8px;
          padding:14px 18px; margin-bottom:10px; }
  .rank:first-of-type { border-color:color-mix(in srgb, var(--bad) 40%, var(--line));
                        background:color-mix(in srgb, var(--bad) 6%, var(--surface)); }
  .rank-head { display:flex; align-items:baseline; gap:10px 12px; flex-wrap:wrap; }
  .rank-name { font-size:16px; font-weight:650; color:#fff; word-break:break-all;
               font-family:Consolas,'Cascadia Mono',monospace; letter-spacing:-.01em; }
  .rank-count { margin-left:auto; font-size:22px; font-weight:700; color:var(--ink);
                font-variant-numeric:tabular-nums; }
  .rank-count small { font-size:13px; color:var(--ink-faint); font-weight:400; }
  /* Two columns on anything wider than a phone: three label/value pairs stacked in one
     column is what made these cards read as a wall of text. */
  .rank-meta { display:grid; grid-template-columns:max-content 1fr; gap:4px 14px;
               margin:0; font-size:13px; align-items:baseline; }
  @media (min-width:680px) {
    .rank-meta { grid-template-columns:max-content minmax(0,1fr) max-content minmax(0,1fr); }
  }
  .rank-meta dt { color:var(--ink-faint); white-space:nowrap; font-size:11px;
                  text-transform:uppercase; letter-spacing:.07em; }
  .rank-meta dd { margin:0; color:var(--ink-dim); word-break:break-word;
                  font-variant-numeric:tabular-nums; }
  .meta { color:var(--ink-faint); font-size:13px; margin:0 0 18px; max-width:76ch; }

  /* Per-column sizing. Left to itself the browser sizes by content, which wrapped a
     14-character IP address onto two lines while a status sentence took a third of the
     width. Identifiers the reader scans for - IP, time, host - must never wrap; prose
     columns absorb the slack instead. */
  .c-ip, .c-time, .c-num, .c-span { white-space:nowrap; font-variant-numeric:tabular-nums; }
  .c-ip   { font-family:Consolas,'Cascadia Mono',monospace; color:var(--ink); width:1%; }
  .c-time { color:var(--ink-dim); width:1%; }
  .c-num  { text-align:right; font-weight:650; color:var(--ink); width:1%; }
  .c-span { color:var(--ink-faint); width:1%; }
  .c-host { font-family:Consolas,'Cascadia Mono',monospace; word-break:break-word;
            min-width:14ch; }
  .c-dc   { color:var(--ink-faint); font-size:12px; word-break:break-word; min-width:12ch; }
  .c-type { color:var(--ink-dim); min-width:10ch; }
  .c-status { color:var(--ink-dim); }
  th.c-num { text-align:right; }
  details { border-top:1px solid var(--line); margin-top:26px; padding-top:16px; }
  summary { cursor:pointer; font-size:12px; letter-spacing:.15em; text-transform:uppercase;
            color:var(--ink-faint); font-weight:700; list-style:none; }
  summary::-webkit-details-marker { display:none; }
  summary::before { content:'\25B8'; display:inline-block; margin-right:8px;
                    transition:transform .15s ease-out; }
  details[open] summary::before { transform:rotate(90deg); }
  summary:hover { color:var(--ink-dim); }
  .tablewrap { overflow-x:auto; margin-top:14px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  thead th { text-align:left; padding:8px 10px; font-weight:600; color:var(--ink-faint);
             border-bottom:1px solid var(--line); white-space:nowrap;
             font-size:11px; letter-spacing:.07em; text-transform:uppercase; }
  td { padding:7px 10px; border-bottom:1px solid var(--surface-2); vertical-align:top;
       word-break:break-word; }
  tbody tr:hover { background:var(--surface); }
  td.bad { color:var(--bad); font-weight:600; }
  td.ok  { color:var(--ok);  font-weight:600; }
  td.warn{ color:var(--warn);font-weight:600; }
  .empty { color:var(--ink-faint); font-style:italic; }
  footer { color:var(--ink-faint); font-size:12.5px; margin-top:34px;
           border-top:1px solid var(--line); padding-top:16px; }
  code { background:var(--surface-2); padding:2px 7px; border-radius:4px;
         color:var(--accent); font-size:12.5px; }
  ul.fix { margin:10px 0; padding-left:20px; font-size:14px; color:var(--ink-dim); }
  ul.fix li { margin:6px 0; }
  ul.fix b { color:var(--ink); }
  @media print {
    body { background:#fff; color:#000; max-width:none; }
    details { display:block; }
    details > summary { display:none; }
    .card, .stat { break-inside:avoid; }
  }
'@

    # -------------------------------------------------------------------------
    # Audit subcategories that gate lockout evidence.
    #
    # GUIDs are used rather than display names because display names are localized -
    # matching on the name fails on a non-English DC. GUIDs are invariant.
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings
    # -------------------------------------------------------------------------
    AuditSubcategories = @(
        @{
            Name     = 'User Account Management'
            Guid     = '{0CCE9235-69AE-11D9-BED3-505054503030}'
            Category = 'Account Management'
            Events   = @(4740, 4724)
            Needs    = 'Success'
            Priority = 1
            Explains = 'Account lockout events (4740) - the lockout timeline itself - and admin password resets (4724)'
            # THE most important setting for lockout work. 4740 comes from HERE, not from
            # the similarly-named 'Audit Account Lockout' subcategory.
            # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740
            Reference = 'https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740'
        }
        @{
            Name     = 'Kerberos Authentication Service'
            Guid     = '{0CCE9242-69AE-11D9-BED3-505054503030}'
            Category = 'Account Logon'
            Events   = @(4771, 4768)
            Needs    = 'Failure'
            Priority = 2
            Explains = 'Kerberos pre-authentication failures (4771) - where most modern domain-joined bad passwords appear'
            Reference = 'https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4771'
        }
        @{
            Name     = 'Logon'
            Guid     = '{0CCE9215-69AE-11D9-BED3-505054503030}'
            Category = 'Logon/Logoff'
            Events   = @(4625)
            Needs    = 'Failure'
            Priority = 3
            Explains = 'Failed logons (4625) - the source host, IP and logon type behind a bad password'
            Reference = 'https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625'
        }
        @{
            Name     = 'Credential Validation'
            Guid     = '{0CCE923F-69AE-11D9-BED3-505054503030}'
            Category = 'Account Logon'
            Events   = @(4776)
            Needs    = 'Failure'
            Priority = 4
            Explains = 'NTLM credential validation (4776) - catches legacy clients, mapped drives and cached credentials'
            Reference = 'https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4776'
        }
        @{
            Name     = 'Account Lockout'
            Guid     = '{0CCE9217-69AE-11D9-BED3-505054503030}'
            Category = 'Logon/Logoff'
            Events   = @(4625)
            Needs    = 'Failure'
            Priority = 5
            Explains = 'Logon attempts against an ALREADY locked-out account (4625) - shows what keeps retrying after the lock'
            # Microsoft: "This subcategory doesn't have Success events, so there is no
            # recommendation to enable Success auditing." Enabling Success here does nothing.
            # It does NOT produce event 4740 despite the name.
            Reference = 'https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-account-lockout'
        }
    )

    # -------------------------------------------------------------------------
    # Event meanings. Deliberately OUTCOME-NEUTRAL for events written on both success and
    # failure - the status code is the only discriminator. Baking "failed" into a label for
    # 4776/4771/4768 makes healthy machines look guilty in a report.
    # -------------------------------------------------------------------------
    EventMeaning = @{
        4740 = 'Account locked out'
        4724 = 'Admin/helpdesk password reset'
        4723 = 'User-initiated password change'
        4625 = 'Failed logon'                  # always a failure
        4771 = 'Kerberos pre-authentication'   # success or failure
        4768 = 'Kerberos TGT request'          # success or failure
        4776 = 'NTLM credential validation'    # success or failure
    }

    # Events that are logged for BOTH outcomes. Callers must inspect the status code
    # rather than assuming the event's presence implies failure.
    DualOutcomeEvents = @(4776, 4771, 4768)

    # -------------------------------------------------------------------------
    # Status / error codes.
    #
    # Kerberos (4771/4768) uses RFC 4120 KDC error codes:
    #   https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4771
    # NTLM (4776/4625) uses Winlogon error codes:
    #   https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4776
    #
    # 0x0 means SUCCESS in both families.
    # -------------------------------------------------------------------------
    StatusCodes = @{
        # --- Kerberos (4771 / 4768) ---
        '0x0'        = 'Success (KDC_ERR_NONE)'
        '0x6'        = 'Username does not exist (KDC_ERR_C_PRINCIPAL_UNKNOWN)'
        '0xC'        = 'KDC policy rejects request (KDC_ERR_POLICY) - e.g. logon hours or workstation restriction'
        '0x10'       = 'KDC has no support for PADATA type (KDC_ERR_PADATA_TYPE_NOSUPP) - usually a smart-card/certificate problem'
        '0x12'       = 'Client credentials revoked (KDC_ERR_CLIENT_REVOKED) - account disabled, expired, or LOCKED OUT'
        '0x17'       = 'Password has expired (KDC_ERR_KEY_EXPIRED)'
        '0x18'       = 'Bad password - pre-authentication failed (KDC_ERR_PREAUTH_FAILED)'
        '0x19'       = 'Additional pre-authentication required (KDC_ERR_PREAUTH_REQUIRED)'
        '0x25'       = 'Clock skew too great (KRB_AP_ERR_SKEW)'

        # --- NTLM (4776 / 4625), Winlogon error codes ---
        '0x00000000' = 'Success (no errors)'
        '0xC000005E' = 'No logon servers available to service the logon request'
        '0xC0000064' = 'Username does not exist'
        '0xC000006A' = 'Bad password'
        '0xC000006D' = 'Generic logon failure - bad username/password, or a LAN Manager authentication level mismatch'
        '0xC000006F' = 'Logon outside authorized hours'
        '0xC0000070' = 'Logon from unauthorized workstation'
        '0xC0000071' = 'Password expired'
        '0xC0000072' = 'Account disabled'
        '0xC000015B' = 'User has not been granted the requested logon type at this machine'
        '0xC0000192' = 'Netlogon service was not started'
        '0xC0000193' = 'Account expired'
        '0xC0000224' = 'Change password at next logon is flagged'
        '0xC0000234' = 'Account locked out'
        '0xC0000371' = 'Local account store has no secret material for this account'
        '0xC0000413' = 'Machine is protected by an authentication firewall; account not allowed to authenticate to it'
    }

    # Status values meaning "no error", in every form the logs render them.
    SuccessStatusCodes = @('0x0', '0x00000000', '0', '')

    # -------------------------------------------------------------------------
    # Logon types (4625 'LogonType'). These identify WHAT KIND of stale credential is
    # retrying, which is usually the fastest route to the actual fix.
    # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625
    # -------------------------------------------------------------------------
    LogonTypes = @{
        2  = 'Interactive - someone typed credentials at the console'
        3  = 'Network - mapped drive, file share, or service account connection'
        4  = 'Batch - scheduled task'
        5  = 'Service - a Windows service running as this account'
        7  = 'Unlock - workstation unlock'
        8  = 'NetworkCleartext - credentials sent unhashed (often IIS basic auth)'
        9  = 'NewCredentials - RunAs /netonly'
        10 = 'RemoteInteractive - RDP / Terminal Services'
        11 = 'CachedInteractive - logged on with locally cached credentials'
    }

    # -------------------------------------------------------------------------
    # AD attributes that are NOT replicated between domain controllers. Each DC holds its
    # own copy reflecting only the authentications it personally handled.
    #
    # This is why querying "the domain" gives inconsistent answers, and why polling every
    # DC individually finds the source even when auditing is completely disabled.
    # https://learn.microsoft.com/windows/win32/adschema/a-badpwdcount
    # -------------------------------------------------------------------------
    NonReplicatedAttributes = @('badPwdCount', 'badPasswordTime', 'lockoutTime', 'logonCount', 'lastLogon')

    # AD large-integer "never" sentinels. Rendering these through FromFileTime yields
    # 1601-01-01, which reads as a real date and misleads the investigator.
    NeverSentinels = @(0, 9223372036854775807)

    # -------------------------------------------------------------------------
    # Lockout policy guidance. Microsoft's baseline is 10 attempts over a 15-minute
    # observation window. A threshold at or below 5 is exhausted by ordinary stale-
    # credential noise - one phone with an old mail profile - producing lockouts that
    # look like attacks but are not.
    # https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/account-lockout-threshold
    # -------------------------------------------------------------------------
    PolicyGuidance = @{
        RecommendedThreshold         = 10
        RecommendedObservationMinutes = 15
        AggressiveThresholdAtOrBelow = 5
    }
}
