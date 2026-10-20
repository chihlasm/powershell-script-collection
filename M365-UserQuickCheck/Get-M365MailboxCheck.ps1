# 5.1 because ExchangeOnlineManagement requires Windows PowerShell 5.1 (root CLAUDE.md, version
# floors). Tests\PSVersionFloor.Tests.ps1 guards it.
#Requires -Version 5.1

<#
.SYNOPSIS
    "Mail is going missing" / "who can see this mailbox?" - one read-only report with the
    mailbox facts, and "do NOT reset yet" when anything looks like an account takeover.
.DESCRIPTION
    Built for the service desk, mid-ticket. Sign in to the client's Exchange Online and the tool
    prints, in this order:

      1. A banner: which tenant (its initial .onmicrosoft.com domain and tenant ID) and which
         account you are signed in as, before any mailbox is read, so a wrong-tenant run can be
         stopped with Ctrl+C.
      2. The verdict block, in one of three forms:
           Possible account takeover: do NOT reset the password or delete the rule yet. Escalate.
             (each sign in plain English, then "Next step: Check CIPP's BEC report for this user.")
           PARTLY CHECKED - no takeover signs in what could be read, but these could not be
             checked: <sections and why, with the role that can read them>.
           No takeover signs found in the checks below.
             (only when every section was read)
      3. The facts: mailbox type, forwarding, size against the quota, archive, holds; who has
         Full Access, Send As and Send on Behalf; every inbox rule (hidden ones marked); the
         message trace (sent and received, last -TraceDays days); and the recent changes from
         the audit log (last -RecentDays days): when an inbox rule, forwarding or a delegate
         was added or changed, by whom, and from where.

    TAKEOVER SIGNS
      - Mailbox forwarding to an address outside the tenant's accepted domains, directly or
        through a forwarding recipient (a mail contact or mail user) that delivers outside
      - An inbox rule that forwards, forwards as an attachment or redirects mail outside, or to
        a recipient the tool cannot classify as inside or outside
      - An inbox rule that deletes mail
      - An inbox rule that moves mail to RSS Feeds, RSS Subscriptions, Conversation History,
        Deleted Items, Junk Email or Archive, or moves it and marks it read
      - A hidden inbox rule other than the built-in junk-mail rule
      - Any inbox rule, forwarding or delegate change in the last -RecentDays days, found in
        the unified audit log (owner decision D-032), each with when, who, and whether it was
        the mailbox's own account
    The tool does not score the risk; every sign leads to CIPP's BEC report (owner decision
    D-003).

    RECENT CHANGES. Search-UnifiedAuditLog for New-InboxRule, Set-InboxRule, UpdateInboxRules,
    Add-MailboxPermission, Add-RecipientPermission and Set-Mailbox, matched to this mailbox on
    this computer. It needs the View-Only Audit Logs (or Audit Logs) role; without it, with
    auditing turned off in the tenant, with -NoRecentChanges, or when the search returns more
    than 50,000 records, the section is "could not check" and the verdict is PARTLY CHECKED at
    best. When mailbox auditing is off or bypassed for this mailbox, rule changes made in the
    Outlook client are not recorded, and that is listed as "could not check" too. Changes from
    the last hour or two may not be in the audit log yet. The tool never changes audit settings.

    READ-ONLY, whatever the account. Even signed in as the client's Global Administrator
    (owner decision D-002) the tool only runs Get- cmdlets: it never removes a rule, forwarding
    or permission, never resets a password and never reads a message body.
    Tests\MailboxCheck.Tests.ps1 (AC21) checks that statically.
.PARAMETER Identity
    The mailbox to check: its email address (accounts@contoso.com) or any value Get-EXOMailbox
    accepts.
.PARAMETER TraceDays
    How many days of message trace to read, 1 to 10 (default 7). One Get-MessageTraceV2 query
    covers at most 10 days, so the tool never goes further back.
.PARAMETER OutputPath
    Optional folder. When given, an HTML report and three CSVs (rules, delegates, trace) named
    MailboxCheck_<mailbox>_<yyyy-MM-dd_HHmmss> are written there. Rule conditions and message
    subjects are in these files only. Without it no report is written. With -TicketNumber, this
    is the folder that holds Ticket_<number>, and the reports go into Ticket_<number>.
.PARAMETER TicketNumber
    Optional ticket number (letters, digits, - or _, up to 32 characters). The ticket note is
    saved in <root>\Ticket_<number>, where root is -OutputPath if given, else
    %USERPROFILE%\Documents\TicketNotes. A number that does not fit is refused with a [FAIL]
    line and exit code 3, before anything is read.
.PARAMETER NoTrace
    Do not read the message trace.
.PARAMETER RecentDays
    How many days of the audit log to search for rule, forwarding and delegate changes, 1 to 90
    (default 14). The search can take a minute or more on a large tenant.
.PARAMETER NoRecentChanges
    Do not search the audit log (when it is too slow). The report then says "Recent changes:
    could not check (skipped)" and the verdict is PARTLY CHECKED at best.
.PARAMETER NoClipboard
    Do not copy the ticket note to the clipboard.
.PARAMETER FullDetail
    Keep IP addresses and share paths in the ticket note (removed by default, owner decision
    D-009). The note never carries rule conditions, full addresses or trace rows either way.
.PARAMETER PassThru
    Return the result object (Status, ExitCode, Identity, Message, Tenant, Facts, Assessment,
    Files, TicketNote) instead of setting an exit code. Facts holds rule conditions and the
    message trace: treat it as client data.
.PARAMETER Quiet
    Do not write the console report (and leave the clipboard alone). Combine with -PassThru or
    -OutputPath.
.PARAMETER LoadFunctionsOnly
    Define the functions and return without connecting or reading anything (used by the tests).
.EXAMPLE
    .\Get-M365MailboxCheck.ps1 -Identity accounts@contoso.com
    Sign in to Exchange Online, check the banner, read the verdict and the facts.
.EXAMPLE
    .\Get-M365MailboxCheck.ps1 accounts@contoso.com -TicketNumber 482113 -OutputPath C:\Temp
    The HTML, the three CSVs and the ticket note go into C:\Temp\Ticket_482113.
.EXAMPLE
    .\Get-M365MailboxCheck.ps1 accounts@contoso.com -TraceDays 2 -OutputPath C:\Temp
    A busy mailbox whose trace was cut off at 5000 messages: read two days instead.
.EXAMPLE
    .\Get-M365MailboxCheck.ps1 accounts@contoso.com -RecentDays 30
    Look 30 days back in the audit log for rule, forwarding and delegate changes.
.NOTES
    Exit codes (without -PassThru): 0 = no takeover signs and every section read, 1 = possible
    takeover, 2 = partly checked (no sign in what could be read), 3 = could not run (module
    missing, sign-in failed, no such mailbox, or an unusable -TicketNumber).

    Needs the ExchangeOnlineManagement module, 3.7.0 or later for the message trace
    (Install-Module ExchangeOnlineManagement -Scope CurrentUser). Roles: see README.md. If an
    Exchange Online session is already open in this window it is reused and left open;
    otherwise the tool connects and, when it finishes, closes only the connection it opened.

    TICKET NOTE. Every run ends with a four-part note (Checked, Ruled out, Could not check, Next
    step) built by CaseKit.ps1 in this folder. It names sign kinds, rule names and outside
    domains only (owner decision D-025: subjects never go into the note). The note names the
    checked mailbox, but never a forwarding, delegate or message-trace address. A section that could not be read gets a fixed reason in the note (the role it needs, or
    "see the report"); the Exchange error itself stays in the console and the HTML report. The
    stamp names the tenant and the signed-in account and says "Changed anything: No".

    REFERENCES
      Connect-ExchangeOnline -ShowBanner:$false ("To hide the banner, use this exact syntax")
        https://learn.microsoft.com/powershell/module/exchangepowershell/connect-exchangeonline
      Get-ConnectionInformation (module 3.0.0 or later): State, UserPrincipalName, TenantID,
      IsEopSession for each REST connection in this PowerShell window
        https://learn.microsoft.com/powershell/module/exchangepowershell/get-connectioninformation
      Disconnect-ExchangeOnline "disconnects any connections and clears the cache", so it only
      runs when this tool opened the connection, and then with -ConnectionId (the GUID from
      Get-ConnectionInformation that "uniquely identifies a connection, even if you have
      multiple connections open"; module 3.2.0 or later) for the connections this run added
        https://learn.microsoft.com/powershell/module/exchangepowershell/disconnect-exchangeonline
      Get-EXORecipient -Identity -Properties ExternalEmailAddress, PrimarySmtpAddress,
      RecipientTypeDetails: where a ForwardingAddress recipient delivers (read-only)
        https://learn.microsoft.com/powershell/module/exchangepowershell/get-exorecipient
      Accepted domain types (ExternalRelay = outside the organization's control)
        https://learn.microsoft.com/powershell/module/exchangepowershell/set-accepteddomain
      Get-AcceptedDomain (the tenant's own list of internal domains)
        https://learn.microsoft.com/powershell/module/exchangepowershell/get-accepteddomain
      Get-OrganizationConfig (tenant name when the accepted domains cannot be read)
        https://learn.microsoft.com/powershell/module/exchangepowershell/get-organizationconfig
      Get-EXOMailbox -Identity -PropertySets (Minimum, Delivery, Archive, Hold, Quota)
        https://learn.microsoft.com/powershell/module/exchangepowershell/get-exomailbox
        https://learn.microsoft.com/powershell/exchange/cmdlet-property-sets
      Get-EXOMailboxStatistics -Identity [-Archive]
        https://learn.microsoft.com/powershell/module/exchangepowershell/get-exomailboxstatistics
      Get-EXOMailboxPermission -Identity -ResultSize
        https://learn.microsoft.com/powershell/module/exchangepowershell/get-exomailboxpermission
      Get-EXORecipientPermission -Identity -AccessRights SendAs -ResultSize
        https://learn.microsoft.com/powershell/module/exchangepowershell/get-exorecipientpermission
      Get-InboxRule -Mailbox -IncludeHidden -ResultSize Unlimited (default 1000); not for
      View-Only Organization Management or Global Reader
        https://learn.microsoft.com/powershell/module/exchangepowershell/get-inboxrule
      Get-MessageTraceV2 -SenderAddress / -RecipientAddress -StartDate -EndDate -ResultSize:
      90 days of data, at most 10 days per query, ResultSize 1 to 5000 (default 1000), at most
      100 queries in a 5-minute window, output times in UTC; module 3.7.0 or later
        https://learn.microsoft.com/powershell/module/exchangepowershell/get-messagetracev2
        https://learn.microsoft.com/exchange/monitoring/trace-an-email-message/message-trace-modern-eac
      Search-UnifiedAuditLog -StartDate -EndDate (UTC) -Operations -SessionId -SessionCommand
      ReturnLargeSet (paging up to 50,000 results) -ResultSize (maximum 5,000); Learn points
      bulk, repeated downloads to the Management Activity API instead
        https://learn.microsoft.com/powershell/module/exchangepowershell/search-unifiedauditlog
      Get-AdminAuditLogConfig (UnifiedAuditLogIngestionEnabled, accurate in Exchange Online
      PowerShell only), Get-OrganizationConfig AuditDisabled, Get-MailboxAuditBypassAssociation
      -Identity (AuditBypassEnabled)
        https://learn.microsoft.com/powershell/module/exchangepowershell/get-adminauditlogconfig
        https://learn.microsoft.com/purview/audit-mailboxes
        https://learn.microsoft.com/powershell/module/exchangepowershell/get-mailboxauditbypassassociation
      Audit roles (View-Only Audit Logs or Audit Logs) and search latency
        https://learn.microsoft.com/purview/audit-search
      Roles per section, hold prefixes, the rule-action properties and the audit record fields:
      see the REFERENCES in MailboxCheck.Core.ps1
      Ticket note clipboard (WinForms first, D-033): see CaseKit.ps1

    NOT VERIFIED ON LEARN
      - The text of Get-EXOMailbox's error for a mailbox that does not exist. Treated as "no
        mailbox" when it says the object "couldn't be found" (or ManagementObjectNotFound);
        any other error is "could not run", never "no mailbox".
      - Whether StartDate / EndDate are read as local time or UTC. They are passed as DateTime
        values (not strings), so no regional date format is involved.
      - That View-Only Audit Logs also covers Get-AdminAuditLogConfig and
        Get-MailboxAuditBypassAssociation. A lookup the role does not allow is listed under
        Could not check (never an all-clear); the Integration test settles it (D-026).
      - That Recipient Management alone can run Get-InboxRule. Learn names the roles per feature
        (feature-permissions) and says Global Reader cannot; the Integration test in
        Tests\MailboxCheck.Tests.ps1 confirms the README's roles against a real tenant (D-026).
      - Junk-mail rule name, folder names, SoftDeleteMessage: see MailboxCheck.Core.ps1.
#>
[CmdletBinding(DefaultParameterSetName = 'Check')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Check', Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Identity,

    [ValidateRange(1, 10)]
    [int]$TraceDays = 7,

    [string]$OutputPath,

    # Checked in the script body (Test-TicketNumber in CaseKit.ps1), not with ValidatePattern,
    # so a mistyped number gets a plain-English [FAIL] line instead of a parameter-binding error.
    [string]$TicketNumber,

    [switch]$NoTrace,

    [ValidateRange(1, 90)]
    [int]$RecentDays = 14,

    [switch]$NoRecentChanges,

    [switch]$NoClipboard,

    [switch]$FullDetail,

    [switch]$PassThru,

    [switch]$Quiet,

    [Parameter(ParameterSetName = 'Load')]
    [switch]$LoadFunctionsOnly
)

# No global $ErrorActionPreference change here (the functions are dot-sourced by the tests):
# every call that must stop says -ErrorAction Stop.

# Dot-sourcing runs M365UserCheck.Core.ps1's param block in THIS scope, so its
# -LoadFunctionsOnly would overwrite ours: remember ours first.
$entryLoadOnly = [bool]$LoadFunctionsOnly
foreach ($coreName in 'MailboxCheck.Core.ps1', 'M365UserCheck.Core.ps1') {
    if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $coreName))) {
        Write-Host "[FAIL] $coreName is missing from $PSScriptRoot. Keep all the files in the folder together." -ForegroundColor Red
        if ($PassThru) { return [PSCustomObject]@{ Status = 'Error'; ExitCode = 3; Identity = $Identity; Message = "$coreName is missing."; TicketNote = $null } }
        exit 3
    }
}
$mailboxCorePath = Join-Path $PSScriptRoot 'MailboxCheck.Core.ps1'
. $mailboxCorePath
# For ConvertTo-M365CsvValue (CSV formula guard, IPs out of CSV cells), shared with the user check.
$userCorePath = Join-Path $PSScriptRoot 'M365UserCheck.Core.ps1'
. $userCorePath -LoadFunctionsOnly
$LoadFunctionsOnly = $entryLoadOnly

# Get-EXOMailbox's error for a mailbox that does not exist (NOT VERIFIED, see .NOTES).
$script:MailboxNotFoundPattern = "(?i)couldn't be found|could not be found|ManagementObjectNotFound"

# =============================================================================
# Small helpers
# =============================================================================

function Write-Status {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Level = 'INFO'
    )
    $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

function Get-M365MailboxSafeFileName {
    # accounts@contoso.com -> accounts_contoso.com
    param([string]$Value)
    return (([string]$Value) -replace '[^\w\.\-]', '_')
}

function Get-M365MailboxErrorText {
    param([Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord)
    $parts = @([string]$ErrorRecord.Exception.Message)
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) { $parts += [string]$ErrorRecord.ErrorDetails.Message }
    return (($parts | Where-Object { $_ }) -join ' ')
}

function Get-M365ConnectionList {
    # Every REST connection in this window (Exchange Online and Security & Compliance).
    return @(Get-ConnectionInformation -ErrorAction Stop | Where-Object { $_ })
}

function Select-M365ExchangeConnection {
    # The open Exchange Online (not Security & Compliance) connections in a connection list.
    param([AllowEmptyCollection()][object[]]$Connection = @())
    return @($Connection | Where-Object { $_ -and [string]$_.State -eq 'Connected' -and $_.IsEopSession -ne $true })
}

function Get-M365ConnectionId {
    # The ConnectionId values (GUIDs, get-connectioninformation) in a connection list.
    param([AllowEmptyCollection()][object[]]$Connection = @())
    return @($Connection | ForEach-Object { [string]$_.ConnectionId } | Where-Object { $_ })
}

# =============================================================================
# Run the check
# =============================================================================

function Write-M365MailboxBanner {
    # Always first: where you are, as whom, and that nothing is changed (D-002).
    param([Parameter(Mandatory = $true)][object]$Tenant, [int]$ConnectionCount = 1)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkGray
    Write-Host ' Microsoft 365 mailbox check. This tool only reads: it changes nothing.' -ForegroundColor White
    Write-Host (' Tenant      : {0}' -f $Tenant.Name) -ForegroundColor White
    Write-Host (' Tenant ID   : {0}' -f $(if ($Tenant.TenantId) { $Tenant.TenantId } else { 'not reported' })) -ForegroundColor White
    Write-Host (' Signed in as: {0}' -f $(if ($Tenant.Account) { $Tenant.Account } else { 'not reported' })) -ForegroundColor White
    if ($ConnectionCount -gt 1) {
        Write-Status ('{0} Exchange Online connections are open in this window. The tenant ID and account above may belong to a different one than the tenant the check reads. Close the others (Disconnect-ExchangeOnline) or run the check in a new PowerShell window.' -f $ConnectionCount) 'WARN'
    }
    Write-Host ' Wrong client? Press Ctrl+C now.' -ForegroundColor Gray
    Write-Host ('=' * 70) -ForegroundColor DarkGray
}

function Get-RecentMailboxChanges {
    <#
    .SYNOPSIS
        The Recent changes section (SQ-016): audit role, audit settings, then the paged audit
        search. Returns Gates, Facts (the Facts.RecentChanges object, or $null when the search
        did not run) and Signs.
    .DESCRIPTION
        One try/catch, like every section: a failure becomes a 'Recent changes' Could not check
        with the error, and the rest of the check still stands. In order:
          1. Get-Command Search-UnifiedAuditLog. Exchange Online only offers the cmdlets a role
             allows, so a missing cmdlet means the account lacks View-Only Audit Logs.
          2. Get-AdminAuditLogConfig: UnifiedAuditLogIngestionEnabled False = no audit log, so no
             search. Missing or not True = not known: the search still runs and its signs stand,
             but the section is Could not check.
          3. Mailbox auditing (Get-OrganizationConfig AuditDisabled, Get-MailboxAuditBypassAssociation
             AuditBypassEnabled). Off, bypassed or not known = 'Rule changes made in Outlook' is
             Could not check (UpdateInboxRules is a mailbox-audit record); a failure here never
             fails the section, because admin-cmdlet records still come from the unified log.
          4. Search-UnifiedAuditLog, filtered on the server by date and operations only, paged
             with one SessionId and ReturnLargeSet until a page is empty or the page's highest
             ResultIndex reaches ResultCount (an unknown ResultCount keeps paging, up to the
             page cap). A ResultIndex at the 50,000 cap = results were cut off. A page that
             fails keeps the records read before it, and unreadable records are counted: both
             make the section Could not check, with any signs found still raised.
        Read-only: the tool never changes an audit setting (AC19).
    #>
    param(
        [Parameter(Mandatory = $true)][object]$Mailbox,
        [Parameter(Mandatory = $true)][string]$Address,
        [AllowEmptyCollection()][object[]]$Rule = @(),
        [switch]$RuleListUnavailable,
        [object]$OrganizationConfig,
        [int]$RecentDays = 14,
        [datetime]$Now = [datetime]::UtcNow,
        [switch]$Quiet
    )
    $source = 'Recent changes'
    $out = [PSCustomObject]@{ Gates = @(); Facts = $null; Signs = @() }
    try {
        if (-not (Get-Command -Name Search-UnifiedAuditLog -ErrorAction SilentlyContinue)) {
            $out.Gates = @(New-MailboxGate -Source $source -State CouldNotCheck `
                    -Reason ('Search-UnifiedAuditLog is not available to the signed-in account, so it cannot search the audit log: your account needs {0}.' -f $script:MailboxAuditRoles) `
                    -NoteReason ('the signed-in account cannot search the audit log; it needs {0}.' -f $script:MailboxAuditRoles))
            return $out
        }

        # Every reason the read below is not complete; merged into one 'Recent changes' gate.
        $partial = New-Object System.Collections.Generic.List[object]
        $config = @(Get-AdminAuditLogConfig -ErrorAction Stop | Where-Object { $_ }) | Select-Object -First 1
        $ingestion = Get-MailboxCheckValue $config 'UnifiedAuditLogIngestionEnabled'
        if ($ingestion -eq $false) {
            # https://learn.microsoft.com/purview/audit-log-enable-disable: the Audit Logs role
            # (Organization Management, Compliance Management) turns it on. This tool never does.
            $out.Gates = @(New-MailboxGate -Source $source -State CouldNotCheck `
                    -Reason 'audit logging is turned off in this tenant (UnifiedAuditLogIngestionEnabled is False). An admin with the Audit Logs role (Organization Management or Compliance Management) can turn it on in the Microsoft Purview portal; this tool never changes it.' `
                    -NoteReason 'audit logging is turned off in this tenant.')
            return $out
        }
        if ($ingestion -ne $true) {
            # Unknown is not "off": search anyway and keep what is found, but an empty result
            # cannot prove that nothing changed.
            $partial.Add((New-MailboxGate -Source $source -State CouldNotCheck `
                        -Reason 'could not tell whether audit logging is on in this tenant (Get-AdminAuditLogConfig did not return UnifiedAuditLogIngestionEnabled), so finding no changes does not prove nothing changed.' `
                        -NoteReason 'could not tell whether audit logging is on in this tenant.'))
        }

        # Mailbox auditing: a gap here only hides rule changes made in the Outlook client.
        $outlook = New-Object System.Collections.Generic.List[string]
        $org = $OrganizationConfig
        if ($null -eq $org) {
            try { $org = Get-OrganizationConfig -ErrorAction Stop } catch { $outlook.Add(('could not tell whether mailbox auditing is on in this tenant: {0}' -f (Get-MailboxErrorSummary -Message (Get-M365MailboxErrorText $_)))) }
        }
        if ($null -ne $org) {
            $disabled = Get-MailboxCheckValue $org 'AuditDisabled'
            if ($disabled -eq $true) {
                $outlook.Add('mailbox auditing is turned off for the whole organization (AuditDisabled is True), so rule changes made in Outlook are not being recorded for this mailbox')
            } elseif ($null -eq $disabled) {
                $outlook.Add('could not tell whether mailbox auditing is on in this tenant (Get-OrganizationConfig did not return AuditDisabled)')
            }
        }
        $account = @([string]$Mailbox.UserPrincipalName, $Address) | Where-Object { $_ } | Select-Object -First 1
        if ($account) {
            # Never without -Identity: "$null ... returns all objects" (get-mailboxauditbypassassociation).
            try {
                $bypass = @(Get-MailboxAuditBypassAssociation -Identity $account -ErrorAction Stop | Where-Object { $_ })
                if (@($bypass | Where-Object { $_.AuditBypassEnabled -eq $true }).Count -gt 0) {
                    $outlook.Add("mailbox audit bypass is on for this mailbox's account, so rule changes made in Outlook are not being recorded for this mailbox")
                }
            } catch {
                $outlook.Add(('could not tell whether mailbox audit bypass is on for this account: {0}' -f (Get-MailboxErrorSummary -Message (Get-M365MailboxErrorText $_))))
            }
        }

        $end = ConvertTo-MailboxUtcTime -When $Now
        $start = $end.AddDays(-$RecentDays)
        if (-not $Quiet) { Write-Status ('Searching the audit log for the last {0} days (this can take a minute)...' -f $RecentDays) 'INFO' }
        $sessionId = 'M365MailboxCheck_' + [guid]::NewGuid().ToString()
        $records = New-Object System.Collections.Generic.List[object]
        $cutOff = $false
        # 50,000 / 5,000 = 10 pages; one more guards against a ResultIndex that never reaches ResultCount.
        $maxPages = [int]($script:MailboxAuditLargeSetCap / $script:MailboxAuditPageSize) + 1
        $pageNo = 0
        # Its own try/catch: a page that fails after others were read keeps the records (and so
        # the signs) already read; the section is then Could not check, never an all-clear.
        try {
            for ($pageNo = 1; ; $pageNo++) {
                # ForEach-Object flattens a page that arrives as one array object.
                $page = @(Search-UnifiedAuditLog -StartDate $start -EndDate $end -Operations $script:MailboxRecentOperations -SessionId $sessionId -SessionCommand ReturnLargeSet -ResultSize $script:MailboxAuditPageSize -ErrorAction Stop | ForEach-Object { $_ } | Where-Object { $_ })
                if ($page.Count -eq 0) { break }
                foreach ($r in $page) { $records.Add($r) }
                # ReturnLargeSet pages are unsorted, so progress is the page's highest ResultIndex.
                # A missing or non-numeric ResultIndex / ResultCount is unknown (-1): an unknown
                # ResultCount never ends the search early; an empty page or the page cap does.
                $index = -1; $count = -1
                foreach ($r in $page) {
                    $n = 0
                    if ([int]::TryParse([string](Get-MailboxCheckValue $r 'ResultIndex'), [ref]$n) -and $n -gt $index) { $index = $n }
                    if ([int]::TryParse([string](Get-MailboxCheckValue $r 'ResultCount'), [ref]$n) -and $n -gt $count) { $count = $n }
                }
                if ($index -ge $script:MailboxAuditLargeSetCap) { $cutOff = $true; break }
                if ($count -ge 0 -and $index -ge $count) { break }
                if ($pageNo -ge $maxPages) { $cutOff = $true; break }
            }
        } catch {
            $failed = Get-M365MailboxErrorText $_
            $what = if ($records.Count -gt 0) { 'The audit log search failed on page {0}, so only the {1} record(s) read before it were checked: ' -f $pageNo, $records.Count } else { 'The audit log search failed: ' }
            $partial.Add((Get-MailboxGateFromError -Source $source -Message ($what + $failed)))
        }

        $found = Get-RecentChangeSigns -AuditRecord $records.ToArray() -Mailbox $Mailbox -Rule $Rule -RuleListUnavailable:$RuleListUnavailable -Now $Now
        if ($found.Skipped -gt 0 -and -not $Quiet) { Write-Status ('{0} audit record(s) could not be read and were skipped.' -f $found.Skipped) 'WARN' }
        $out.Facts = [PSCustomObject]@{ Changes = @($found.Changes); Skipped = [int]$found.Skipped; CutOff = [bool]$cutOff; Days = $RecentDays; Start = $start; End = $end }
        $out.Signs = @($found.Signs)
        if ($cutOff) {
            $partial.Add((New-MailboxGate -Source $source -State CouldNotCheck `
                        -Reason ('results were cut off: the audit search reached its limit of {0:N0} records for these {1} days, so changes may be missing. Run the check again with a smaller -RecentDays.' -f $script:MailboxAuditLargeSetCap, $RecentDays) `
                        -NoteReason 'results were cut off at the audit search limit; run the check again with a smaller -RecentDays.'))
        }
        if ($found.Skipped -gt 0) {
            # A record that cannot be read may be the very change being looked for.
            $partial.Add((New-MailboxGate -Source $source -State CouldNotCheck `
                        -Reason ('{0} audit record(s) could not be read (their AuditData is not valid JSON), so changes in them may be missing.' -f $found.Skipped) `
                        -NoteReason 'some audit record(s) could not be read (see the report).'))
        }
        $gates = New-Object System.Collections.Generic.List[object]
        if ($partial.Count -eq 0) {
            $gates.Add((New-MailboxGate -Source $source -State Checked))
        } elseif ($partial.Count -eq 1) {
            $gates.Add($partial[0])
        } else {
            $gates.Add((New-MailboxGate -Source $source -State CouldNotCheck `
                        -Reason ((@($partial | ForEach-Object { ([string]$_.Reason).Trim().TrimEnd('.') }) -join '; ') + '.') `
                        -NoteReason ((@($partial | ForEach-Object { ([string]$_.NoteReason).Trim().TrimEnd('.') }) -join '; ') + '.')))
        }
        if ($outlook.Count -gt 0) {
            $note = if (@($outlook | Where-Object { $_ -match 'not being recorded' }).Count -gt 0) { 'rule changes made in Outlook are not being recorded for this mailbox (mailbox auditing is off or bypassed).' } else { 'could not tell whether rule changes made in Outlook are recorded for this mailbox (see the report).' }
            $gates.Add((New-MailboxGate -Source 'Rule changes made in Outlook' -State CouldNotCheck -Reason ((($outlook | Select-Object -Unique) -join '; ') + '.') -NoteReason $note))
        }
        $out.Gates = $gates.ToArray()
    } catch {
        $out.Gates = @(Get-MailboxGateFromError -Source $source -Message ('The audit log search failed: ' + (Get-M365MailboxErrorText $_)))
        $out.Facts = $null
        $out.Signs = @()
    }
    return $out
}

function Invoke-M365MailboxCheck {
    <#
    .SYNOPSIS
        Banner, find the mailbox, read every section, assess. Assumes an Exchange Online
        connection. Never calls exit; returns a result object with ExitCode.
    .DESCRIPTION
        One try/catch per section: a section that fails becomes a CouldNotCheck gate with the
        reason, and the rest still runs. The banner is written before Get-EXOMailbox.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Identity,
        [Parameter(Mandatory = $true)][object]$Connection,
        [int]$ConnectionCount = 1,
        [int]$TraceDays = 7,
        [switch]$NoTrace,
        [int]$RecentDays = 14,
        [switch]$NoRecentChanges,
        [switch]$Quiet,
        [datetime]$Now = [datetime]::UtcNow
    )
    $id = $Identity.Trim()
    $result = [PSCustomObject]@{
        Status = 'Error'; ExitCode = 3; Identity = $id; Message = ''; Tenant = $null
        Facts = $null; Assessment = $null; Files = $null; TicketNote = $null; Now = $Now
    }
    $gates = New-Object System.Collections.Generic.List[object]

    # --- Tenant: accepted domains (internal = these) and the initial domain for the banner ---
    $domains = @()
    $tenantName = ''
    $orgConfig = $null
    try {
        $accepted = @(Get-AcceptedDomain -ErrorAction Stop | Where-Object { $_ })
        # ExternalRelay domains relay to "an external email system that's completely outside of
        # your control", so they do not count as inside (set-accepteddomain, DomainType).
        $domains = @($accepted | Where-Object { [string]$_.DomainType -ne 'ExternalRelay' } | ForEach-Object { $n = [string]$_.DomainName; if (-not $n) { $n = [string]$_.Name }; $n } | Where-Object { $_ })
        $initial = @($accepted | Where-Object { $_.InitialDomain -eq $true })
        if ($initial.Count -gt 0) { $tenantName = [string]$initial[0].DomainName }
        if (-not $tenantName) { $tenantName = [string](@($domains | Where-Object { $_ -match '\.onmicrosoft\.com$' -and $_ -notmatch '\.mail\.onmicrosoft\.com$' }) | Select-Object -First 1) }
        $gates.Add((New-MailboxGate -Source 'Accepted domains' -State Checked))
    } catch {
        $gates.Add((Get-MailboxGateFromError -Source 'Accepted domains' -Message (Get-M365MailboxErrorText $_)))
    }
    if (-not $tenantName) {
        try {
            $orgConfig = @(Get-OrganizationConfig -ErrorAction Stop) | Select-Object -First 1
            $tenantName = [string]$orgConfig.Name
        } catch { Write-Verbose "Get-OrganizationConfig: $($_.Exception.Message)" }
    }
    $tenant = [PSCustomObject]@{
        Name = $(if ($tenantName) { $tenantName } else { 'not known' })
        TenantId = [string]$Connection.TenantID
        Account = [string]$Connection.UserPrincipalName
        AcceptedDomains = $domains
    }
    $result.Tenant = $tenant
    if (-not $Quiet) { Write-M365MailboxBanner -Tenant $tenant -ConnectionCount $ConnectionCount }

    # --- The mailbox (no mailbox = nothing else to read) ---
    $mbx = $null
    try {
        # ExchangeGuid is in no property set the check needs otherwise (StatisticsSeed), so it is
        # asked for by name: mailbox-audit records name the mailbox by it (cmdlet-property-sets).
        $mbx = @(Get-EXOMailbox -Identity $id -PropertySets Minimum, Delivery, Archive, Hold, Quota -Properties ExchangeGuid -ErrorAction Stop | Where-Object { $_ }) | Select-Object -First 1
    } catch {
        $msg = Get-M365MailboxErrorText $_
        if ($msg -notmatch $script:MailboxNotFoundPattern) {
            $result.Message = "Could not read the mailbox '$id' in tenant $($tenant.Name): $(Get-MailboxErrorSummary -Message $msg)"
            return $result
        }
    }
    if (-not $mbx) {
        $result.Status = 'NotFound'
        $result.Message = "No mailbox found for '$id' in tenant $($tenant.Name)."
        return $result
    }
    $address = @([string]$mbx.PrimarySmtpAddress, [string]$mbx.UserPrincipalName, $id) | Where-Object { $_ } | Select-Object -First 1

    if ($domains.Count -eq 0) {
        # Without the tenant's list, judge "outside" against the mailbox's own address domains;
        # the Accepted domains gate keeps the verdict at PARTLY CHECKED at best.
        $domains = @(@($mbx.EmailAddresses) + @($address) | ForEach-Object { Get-MailboxAddressDomain -Address ([string]$_) } | Where-Object { $_ } | Select-Object -Unique)
    }

    # --- Forwarding: ForwardingAddress is a recipient object (a mail contact can point
    # outside), so look up where it delivers. Read-only (get-exorecipient).
    $forwardingRecipient = $null
    $forwardingLookupError = ''
    if (Test-MailboxCheckValue $mbx.ForwardingAddress) {
        try {
            $forwardingRecipient = @(Get-EXORecipient -Identity ([string]$mbx.ForwardingAddress) -Properties ExternalEmailAddress, PrimarySmtpAddress, RecipientTypeDetails -ErrorAction Stop | Where-Object { $_ }) | Select-Object -First 1
        } catch {
            $forwardingLookupError = Get-M365MailboxErrorText $_
        }
    }
    $gates.Add((Get-MailboxForwardingGate -Mailbox $mbx -ForwardingRecipient $forwardingRecipient -LookupError $forwardingLookupError -AcceptedDomain $domains))

    # --- Size and archive ---
    $stats = $null
    try {
        $stats = @(Get-EXOMailboxStatistics -Identity $address -ErrorAction Stop) | Select-Object -First 1
        $gates.Add((New-MailboxGate -Source 'Mailbox size' -State Checked))
    } catch {
        $gates.Add((Get-MailboxGateFromError -Source 'Mailbox size' -Message (Get-M365MailboxErrorText $_)))
    }
    $archiveStats = $null
    if (Test-MailboxArchiveEnabled -Mailbox $mbx) {
        try {
            $archiveStats = @(Get-EXOMailboxStatistics -Identity $address -Archive -ErrorAction Stop) | Select-Object -First 1
            $gates.Add((New-MailboxGate -Source 'Archive size' -State Checked))
        } catch {
            $gates.Add((Get-MailboxGateFromError -Source 'Archive size' -Message (Get-M365MailboxErrorText $_)))
        }
    }

    # --- Delegates ---
    $fullAccess = $null
    try {
        $fullAccess = @(Get-MailboxDelegates -Kind FullAccess -Permission @(Get-EXOMailboxPermission -Identity $address -ResultSize Unlimited -ErrorAction Stop))
        $gates.Add((New-MailboxGate -Source 'Full Access' -State Checked))
    } catch {
        $gates.Add((Get-MailboxGateFromError -Source 'Full Access' -Message (Get-M365MailboxErrorText $_)))
    }
    $sendAs = $null
    try {
        $sendAs = @(Get-MailboxDelegates -Kind SendAs -Permission @(Get-EXORecipientPermission -Identity $address -AccessRights SendAs -ResultSize Unlimited -ErrorAction Stop))
        $gates.Add((New-MailboxGate -Source 'Send As' -State Checked))
    } catch {
        $gates.Add((Get-MailboxGateFromError -Source 'Send As' -Message (Get-M365MailboxErrorText $_)))
    }
    $sendOnBehalf = @(Get-MailboxDelegates -Kind SendOnBehalf -Permission @($mbx.GrantSendOnBehalfTo))

    # --- Inbox rules: hidden = returned with -IncludeHidden but not without it. The signs come
    # from the -IncludeHidden set; if the second call fails, they still do, and only telling
    # the hidden rules apart becomes Could not check ---
    $rules = @()
    $rulesUnavailable = $false
    try {
        $all = @(Get-InboxRule -Mailbox $address -IncludeHidden -ResultSize Unlimited -ErrorAction Stop | Where-Object { $_ })
        $visible = @()
        $visibleFailed = $false
        try {
            $visible = @(Get-InboxRule -Mailbox $address -ResultSize Unlimited -ErrorAction Stop | Where-Object { $_ })
        } catch {
            $visibleFailed = $true
            $gates.Add((Get-MailboxGateFromError -Source 'Hidden inbox rules' -Message ('Could not tell which rules are hidden (Get-InboxRule without -IncludeHidden failed): ' + (Get-M365MailboxErrorText $_))))
        }
        $rules = @(ConvertTo-MailboxRuleList -Rule $all -VisibleRule $visible -VisibleRuleUnavailable:$visibleFailed)
        $gates.Add((New-MailboxGate -Source 'Inbox rules' -State Checked))
    } catch {
        $rulesUnavailable = $true
        $gates.Add((Get-MailboxGateFromError -Source 'Inbox rules' -Message (Get-M365MailboxErrorText $_)))
    }

    # --- Message trace: one window per direction, never more than 10 days (get-messagetracev2) ---
    $trace = $null
    if (-not $NoTrace) {
        if (-not (Get-Command -Name Get-MessageTraceV2 -ErrorAction SilentlyContinue)) {
            $gates.Add((New-MailboxGate -Source 'Message trace' -State CouldNotCheck -Reason ('Get-MessageTraceV2 is not available in this session. It needs ExchangeOnlineManagement 3.7.0 or later (Update-Module ExchangeOnlineManagement, then a new PowerShell window) and {0}.' -f $script:MailboxSectionRoles['Message trace']) -NoteReason 'Get-MessageTraceV2 is not available in this session; it needs ExchangeOnlineManagement 3.7.0 or later.'))
        } else {
            try {
                # The window ends at this run's $Now (one clock read for the whole result), passed
                # as local time as before (UTC or local reading is NOT VERIFIED, see .NOTES).
                $end = if ($Now.Kind -eq [DateTimeKind]::Utc) { $Now.ToLocalTime() } else { $Now }
                $start = $end.AddDays(-$TraceDays)
                $max = $script:MailboxTraceMaxResults
                $sent = @(Get-MessageTraceV2 -SenderAddress $address -StartDate $start -EndDate $end -ResultSize $max -ErrorAction Stop | Where-Object { $_ })
                $received = @(Get-MessageTraceV2 -RecipientAddress $address -StartDate $start -EndDate $end -ResultSize $max -ErrorAction Stop | Where-Object { $_ })
                $cutOff = @()
                if ($sent.Count -ge $max) { $cutOff += 'mail sent by this mailbox' }
                if ($received.Count -ge $max) { $cutOff += 'mail received by this mailbox' }
                $trace = [PSCustomObject]@{
                    Days = $TraceDays; Start = $start.ToUniversalTime(); End = $end.ToUniversalTime(); MaxResults = $max
                    Sent = @(ConvertTo-MailboxTraceRows -Row $sent -Direction Sent)
                    Received = @(ConvertTo-MailboxTraceRows -Row $received -Direction Received)
                    CutOff = $cutOff
                }
                $gates.Add((New-MailboxGate -Source 'Message trace' -State Checked))
            } catch {
                $gates.Add((Get-MailboxGateFromError -Source 'Message trace' -Message (Get-M365MailboxErrorText $_)))
            }
        }
    }

    # --- Recent changes from the audit log (SQ-016). Last: the search can take a minute ---
    $recent = $null
    if ($NoRecentChanges) {
        $gates.Add((New-MailboxGate -Source 'Recent changes' -State CouldNotCheck -Reason 'skipped (-NoRecentChanges).' -NoteReason 'skipped (-NoRecentChanges).'))
    } else {
        $recent = Get-RecentMailboxChanges -Mailbox $mbx -Address $address -Rule $rules -RuleListUnavailable:$rulesUnavailable -OrganizationConfig $orgConfig -RecentDays $RecentDays -Now $Now -Quiet:$Quiet
        foreach ($g in @($recent.Gates)) { $gates.Add($g) }
    }

    # --- Assess ---
    $signs = @(Get-ForwardingSigns -Mailbox $mbx -ForwardingRecipient $forwardingRecipient -AcceptedDomain $domains) + @(Get-InboxRuleSigns -Rule $rules -AcceptedDomain $domains)
    if ($recent) { $signs += @($recent.Signs) }
    $assessment = Get-MailboxCheckAssessment -Signs $signs -Gate $gates.ToArray()
    $result.Facts = [PSCustomObject]@{
        Mailbox = $mbx; Address = $address; ForwardingRecipient = $forwardingRecipient
        FactRows = @(Get-MailboxFactRows -Mailbox $mbx -Statistics $stats -ArchiveStatistics $archiveStats -ForwardingRecipient $forwardingRecipient)
        FullAccess = $fullAccess; SendAs = $sendAs; SendOnBehalf = $sendOnBehalf
        Rules = $rules; Trace = $trace; RecentChanges = $(if ($recent) { $recent.Facts } else { $null }); Gates = $gates.ToArray()
    }
    $result.Identity = $address
    $result.Assessment = $assessment
    $result.Status = 'Ok'
    $result.ExitCode = $assessment.ExitCode
    return $result
}

# =============================================================================
# Output
# =============================================================================

function Write-M365MailboxCheckConsole {
    # Rule conditions and message subjects are not printed (local HTML/CSV only): a console is
    # often screen-shared or pasted from.
    param([Parameter(Mandatory = $true)][object]$Result)
    if ($Result.Status -ne 'Ok') {
        Write-Status $Result.Message 'FAIL'
        if ($Result.Status -eq 'NotFound') { Write-Status 'Check the spelling, and that the banner shows the right client tenant.' 'INFO' }
        return
    }
    $a = $Result.Assessment; $f = $Result.Facts
    $color = switch ($a.Verdict) { 'TakeoverSigns' { 'Red' } 'AllChecked' { 'Green' } default { 'Yellow' } }
    Write-Host ''
    foreach ($l in @($a.Lines)) { Write-Host $l -ForegroundColor $color }
    Write-Host ('=' * 70) -ForegroundColor DarkGray

    Write-Host ''
    Write-Host ("Mailbox: {0}" -f $Result.Identity) -ForegroundColor White
    foreach ($r in @($f.FactRows)) { Write-Host ("  {0,-22} {1}" -f $r.Item, $r.Value) -ForegroundColor Gray }

    Write-Host ''
    Write-Host 'Who can open it or send as it:' -ForegroundColor White
    $gateOf = { param($s) @($f.Gates | Where-Object { $_.Source -eq $s })[0] }
    foreach ($d in @(@('Full Access', $f.FullAccess), @('Send As', $f.SendAs))) {
        $g = & $gateOf $d[0]
        $v = if ($g -and $g.State -ne 'Checked') { 'could not check' } else { Format-MailboxDelegateList -Delegate @($d[1]) }
        Write-Host ("  {0,-22} {1}" -f $d[0], $v) -ForegroundColor Gray
    }
    Write-Host ("  {0,-22} {1}" -f 'Send on Behalf', (Format-MailboxDelegateList -Delegate @($f.SendOnBehalf))) -ForegroundColor Gray

    Write-Host ''
    $rg = & $gateOf 'Inbox rules'
    if ($rg -and $rg.State -ne 'Checked') {
        Write-Status "Inbox rules: could not check ($($rg.Reason))" 'WARN'
    } else {
        $rules = @($f.Rules)
        Write-Host ("Inbox rules: {0} ({1} hidden)" -f $rules.Count, @($rules | Where-Object { $_.IsHidden }).Count) -ForegroundColor White
        foreach ($r in $rules) {
            $flags = @()
            if ($r.IsHidden) { $flags += 'hidden' } elseif ($r.HiddenState -eq 'Unknown') { $flags += 'hidden: unknown' }
            if ($r.Enabled -eq $false) { $flags += 'off' }
            $flagText = if ($flags.Count -gt 0) { ' [' + ($flags -join ', ') + ']' } else { '' }
            Write-Host ("  {0}{1}: {2}" -f $r.Name, $flagText, (Get-InboxRuleActionText -Rule $r)) -ForegroundColor Gray
        }
    }

    Write-Host ''
    $tg = & $gateOf 'Message trace'
    if ($null -eq $f.Trace -and -not $tg) {
        Write-Status 'Message trace: not read (-NoTrace).' 'INFO'
    } elseif ($tg -and $tg.State -ne 'Checked') {
        Write-Status "Message trace: could not check ($($tg.Reason))" 'WARN'
    } else {
        $tr = $f.Trace
        Write-Host ("Message trace, last {0} days: {1} sent, {2} received (subjects in the HTML and CSV report only)" -f $tr.Days, @($tr.Sent).Count, @($tr.Received).Count) -ForegroundColor White
        foreach ($cut in @($tr.CutOff)) { Write-Status ("results were cut off at {0}; rerun with a smaller -TraceDays ({1})." -f $tr.MaxResults, $cut) 'WARN' }
        $recent = @(@($tr.Sent) + @($tr.Received) | Sort-Object -Property { try { [datetime]$_.Received } catch { [datetime]::MinValue } } -Descending | Select-Object -First 10)
        foreach ($m in $recent) {
            $other = if ($m.Direction -eq 'Sent') { 'to ' + $m.RecipientAddress } else { 'from ' + $m.SenderAddress }
            Write-Host ("  {0}  {1,-8} {2,-40} {3}" -f (Format-MailboxCheckTime $m.Received), $m.Direction, $other, $m.Status) -ForegroundColor Gray
        }
    }

    # Recent changes: who did what and when. Client IPs and apps are in the HTML report only.
    Write-Host ''
    $cg = & $gateOf 'Recent changes'
    $og = & $gateOf 'Rule changes made in Outlook'
    $rc = $f.RecentChanges
    if ($cg -and $cg.State -ne 'Checked') { Write-Status "Recent changes: could not check ($($cg.Reason))" 'WARN' }
    if ($og) { Write-Status "Rule changes made in Outlook: could not check ($($og.Reason))" 'WARN' }
    if ($rc) {
        $changes = @($rc.Changes)
        if ($changes.Count -eq 0) {
            # "Nothing changed" needs a complete read: no cut-off, no unreadable record, no failed page.
            if (-not ($cg -and $cg.State -ne 'Checked') -and -not $rc.CutOff -and [int]$rc.Skipped -eq 0) { Write-Host ($script:MailboxRecentNoChangesFormat -f $rc.Days) -ForegroundColor White }
        } else {
            Write-Host ("Recent changes, last {0} days, newest first (local time, UTC in brackets; IPs and apps in the HTML report):" -f $rc.Days) -ForegroundColor White
            foreach ($c in $changes) {
                $when = if ($c.Time) { Format-MailboxChangeTime -When $c.Time } else { 'unknown time' }
                Write-Host ("  {0}  {1}" -f $when, $c.Text) -ForegroundColor $(if ($c.IsSign) { 'Yellow' } else { 'Gray' })
            }
        }
        Write-Status $script:MailboxAuditLatencyLine 'INFO'
    }
}

function Save-M365MailboxCsv {
    # Export-Csv writes nothing for zero rows, so an empty section still gets its header line.
    # Every text cell goes through ConvertTo-M365CsvValue (formula guard, IPs removed).
    param([AllowEmptyCollection()][object[]]$Rows = @(), [Parameter(Mandatory = $true)][string[]]$Columns, [Parameter(Mandatory = $true)][string]$Path)
    $clean = foreach ($r in @($Rows)) {
        $o = [ordered]@{}
        foreach ($c in $Columns) {
            $v = $r.$c
            $o[$c] = if ($v -is [string]) { ConvertTo-M365CsvValue -Text $v } else { $v }
        }
        [PSCustomObject]$o
    }
    if (@($clean).Count -gt 0) {
        @($clean) | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
    } else {
        $header = ($Columns | ForEach-Object { '"{0}"' -f $_ }) -join ','
        [System.IO.File]::WriteAllText($Path, $header + "`r`n", (New-Object System.Text.UTF8Encoding($true)))
    }
}

function Save-M365MailboxCheckReport {
    # MailboxCheck_<safe-mailbox>_<yyyy-MM-dd_HHmmss>.html plus _rules.csv, _delegates.csv and
    # _trace.csv (no trace CSV with -NoTrace or a trace that could not be read).
    param([Parameter(Mandatory = $true)][object]$Result, [Parameter(Mandatory = $true)][string]$OutputPath)
    if (-not (Test-Path -LiteralPath $OutputPath)) { $null = New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop }
    $f = $Result.Facts
    $stamp = ([datetime]$Result.Now).ToLocalTime().ToString('yyyy-MM-dd_HHmmss')
    $stem = Join-Path $OutputPath ('MailboxCheck_{0}_{1}' -f (Get-M365MailboxSafeFileName $Result.Identity), $stamp)
    $files = [PSCustomObject]@{ Html = "$stem.html"; RulesCsv = "${stem}_rules.csv"; DelegatesCsv = "${stem}_delegates.csv"; TraceCsv = $null }

    [System.IO.File]::WriteAllText($files.Html, (ConvertTo-MailboxCheckHtml -Result $Result), (New-Object System.Text.UTF8Encoding($true)))

    $ruleRows = foreach ($r in @($f.Rules)) {
        $ruleSigns = @($Result.Assessment.Signs | Where-Object { $_.RuleName -eq $r.Name } | ForEach-Object { $_.Kind } | Select-Object -Unique)
        [PSCustomObject]@{
            Name = $r.Name; Enabled = $r.Enabled; Hidden = $r.HiddenState; Priority = $r.Priority
            Signs = ($ruleSigns -join ', '); Actions = (Get-InboxRuleActionText -Rule $r)
            ForwardTo = (@($r.ForwardTo) -join '; '); ForwardAsAttachmentTo = (@($r.ForwardAsAttachmentTo) -join '; '); RedirectTo = (@($r.RedirectTo) -join '; ')
            MoveToFolder = $r.MoveToFolder; DeleteMessage = $r.DeleteMessage; SoftDeleteMessage = $r.SoftDeleteMessage; MarkAsRead = $r.MarkAsRead
            Conditions = $r.Description
        }
    }
    Save-M365MailboxCsv -Rows @($ruleRows) -Path $files.RulesCsv -Columns Name, Enabled, Hidden, Priority, Signs, Actions, ForwardTo, ForwardAsAttachmentTo, RedirectTo, MoveToFolder, DeleteMessage, SoftDeleteMessage, MarkAsRead, Conditions

    $delegateRows = New-Object System.Collections.Generic.List[object]
    foreach ($d in @(@('Full Access', $f.FullAccess), @('Send As', $f.SendAs), @('Send on Behalf', $f.SendOnBehalf))) {
        $g = @($f.Gates | Where-Object { $_.Source -eq $d[0] })[0]
        if ($g -and $g.State -ne 'Checked') { $delegateRows.Add([PSCustomObject]@{ Permission = $d[0]; Who = 'could not check' }); continue }
        foreach ($who in @($d[1] | Where-Object { $_ })) { $delegateRows.Add([PSCustomObject]@{ Permission = $d[0]; Who = $who }) }
    }
    Save-M365MailboxCsv -Rows $delegateRows.ToArray() -Path $files.DelegatesCsv -Columns Permission, Who

    if ($f.Trace) {
        $files.TraceCsv = "${stem}_trace.csv"
        $traceRows = foreach ($m in @(@($f.Trace.Sent) + @($f.Trace.Received))) {
            [PSCustomObject]@{
                ReceivedUtc = (Format-MailboxCheckTime $m.Received); Direction = $m.Direction; SenderAddress = $m.SenderAddress
                RecipientAddress = $m.RecipientAddress; Subject = $m.Subject; Status = $m.Status; Size = $m.Size
            }
        }
        Save-M365MailboxCsv -Rows @($traceRows) -Path $files.TraceCsv -Columns ReceivedUtc, Direction, SenderAddress, RecipientAddress, Subject, Status, Size
    }
    return $files
}

# The ticket-note kit ships beside this script (a copy of TicketNote\CaseKit.ps1). Without it
# the check still runs; only the note is skipped.
$kit = Join-Path $PSScriptRoot 'CaseKit.ps1'
if (Test-Path -LiteralPath $kit) { . $kit } else { $script:CaseKitMissing = $true }

if ($LoadFunctionsOnly) { return }

# =============================================================================
# Main
# =============================================================================

# A result for the cases where the check cannot start (-PassThru callers get it instead of exit 3).
function New-M365MailboxStartFailure([string]$Message) {
    [PSCustomObject]@{
        Status = 'Error'; ExitCode = 3; Identity = $Identity; Message = $Message; Tenant = $null
        Facts = $null; Assessment = $null; Files = $null; TicketNote = $null; Now = [datetime]::UtcNow
    }
}

if ($TicketNumber -and $script:CaseKitMissing) {
    if (-not $Quiet) { Write-Status "CaseKit.ps1 is missing from this folder, so -TicketNumber $TicketNumber was ignored: the reports go to -OutputPath (if given) and there is no ticket note this time." 'WARN' }
    $TicketNumber = ''
    $script:CaseKitWarned = $true
}
if ($TicketNumber -and -not (Test-TicketNumber -TicketNumber $TicketNumber)) {
    $msg = "'$TicketNumber' is not a usable ticket number. Use letters, digits, - or _ (up to 32 characters, starting with a letter or digit), for example 482113."
    if (-not $Quiet) { Write-Status $msg 'FAIL' }
    if ($PassThru) { return (New-M365MailboxStartFailure $msg) }
    exit 3
}

try {
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
} catch {
    $msg = "The ExchangeOnlineManagement module is not available: $($_.Exception.Message)"
    if (-not $Quiet) {
        Write-Status $msg 'FAIL'
        Write-Status 'Install it once with: Install-Module ExchangeOnlineManagement -Scope CurrentUser' 'INFO'
    }
    if ($PassThru) { return (New-M365MailboxStartFailure $msg) }
    exit 3
}

if ($FullDetail -and -not $Quiet) {
    # Owner decision D-009: paste-safe by default; -FullDetail opts out, so say what that means.
    Write-Status '-FullDetail: the ticket note will include IP addresses and share paths. Check it before you paste it anywhere the client or a third party can read.' 'WARN'
}

$result = $null
$weConnected = $false
$idsBefore = @()
$hadConnection = $true
try {
    try {
        $before = @(Get-M365ConnectionList)
        $idsBefore = @(Get-M365ConnectionId -Connection $before)
        $hadConnection = ($before.Count -gt 0)
        $connections = @(Select-M365ExchangeConnection -Connection $before)
        if ($connections.Count -eq 0) {
            if (-not $Quiet) { Write-Status 'Signing in to Exchange Online (sign in with an account in the client''s tenant)...' 'INFO' }
            # Set before connecting, so a half-finished sign-in is still cleaned up below.
            $weConnected = $true
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
            $connections = @(Select-M365ExchangeConnection -Connection @(Get-M365ConnectionList))
            if ($connections.Count -eq 0) { throw 'Connect-ExchangeOnline finished without an Exchange Online connection.' }
        } elseif (-not $Quiet) {
            Write-Status 'Using the Exchange Online session already open in this window (it stays open afterwards).' 'INFO'
        }
    } catch {
        $result = New-M365MailboxStartFailure "Could not connect to Exchange Online: $($_.Exception.Message)"
    }
    if (-not $result) {
        try {
            $result = Invoke-M365MailboxCheck -Identity $Identity -Connection $connections[0] -ConnectionCount $connections.Count -TraceDays $TraceDays -NoTrace:$NoTrace -RecentDays $RecentDays -NoRecentChanges:$NoRecentChanges -Quiet:$Quiet
        } catch {
            $result = New-M365MailboxStartFailure "The check stopped unexpectedly: $($_.Exception.Message)"
        }
    }
} finally {
    # Disconnect only what this run connected (AC22). Without -ConnectionId,
    # Disconnect-ExchangeOnline closes every connection in the window, so it is only used bare
    # when there was none before; otherwise only the new ConnectionIds are closed, and a tech's
    # own session (an EOP / Security & Compliance one too) survives.
    if ($weConnected) {
        try {
            $ours = @()
            try { $ours = @(Get-M365ConnectionId -Connection @(Get-M365ConnectionList) | Where-Object { $idsBefore -notcontains $_ }) } catch { Write-Verbose "Get-ConnectionInformation: $($_.Exception.Message)" }
            if ($ours.Count -gt 0) {
                Disconnect-ExchangeOnline -ConnectionId $ours -Confirm:$false -ErrorAction Stop | Out-Null
            } elseif (-not $hadConnection) {
                Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop | Out-Null
            } elseif (-not $Quiet) {
                Write-Status 'Could not tell which Exchange Online connection this run opened, so none was closed. Close it with Disconnect-ExchangeOnline when you are done.' 'WARN'
            }
        } catch { Write-Verbose "Disconnect-ExchangeOnline: $($_.Exception.Message)" }
    }
}

if (-not $Quiet) { Write-M365MailboxCheckConsole -Result $result }

# Where the files go (same rules as Get-M365UserQuickCheck.ps1): the HTML and CSVs only when
# -OutputPath is given, so nothing with client data is written unasked. With -TicketNumber the
# note (and, with -OutputPath, the reports) go into Ticket_<n> (owner decision D-012); with
# neither, no files (the note goes to the clipboard, or the console, D-013). When the check did
# not run, no file is written outside a ticket folder.
$reportFolder = $OutputPath
$folder = $OutputPath
if ($TicketNumber) {
    $root = if ($OutputPath) { $OutputPath } else { Get-TicketNoteDefaultRoot }
    try {
        $folder = Resolve-TicketFolder -TicketNumber $TicketNumber -Root $root
        if ($OutputPath) { $reportFolder = $folder }
    } catch {
        if (-not $Quiet) { Write-Status "Could not create the ticket folder under ${root}: $($_.Exception.Message)" 'WARN' }
    }
} elseif ($result.Status -ne 'Ok') {
    $folder = $null
}

$evidence = @()
if ($reportFolder -and $result.Status -eq 'Ok') {
    try {
        $files = Save-M365MailboxCheckReport -Result $result -OutputPath $reportFolder
        $result.Files = $files
        $evidence = @($files.Html, $files.RulesCsv, $files.DelegatesCsv, $files.TraceCsv | Where-Object { $_ })
        if (-not $Quiet) {
            Write-Host ''
            Write-Status "Report saved: $($files.Html)" 'PASS'
            Write-Status "CSVs saved  : $([System.IO.Path]::GetFileName($files.RulesCsv)), $([System.IO.Path]::GetFileName($files.DelegatesCsv))$(if ($files.TraceCsv) { ', ' + [System.IO.Path]::GetFileName($files.TraceCsv) })" 'PASS'
        }
    } catch {
        if (-not $Quiet) { Write-Status "Could not write the report to ${reportFolder}: $($_.Exception.Message)" 'WARN' }
    }
} elseif ($result.Status -eq 'Ok' -and -not $Quiet) {
    Write-Host ''
    Write-Status 'No report saved. Add -OutputPath to save the HTML report and CSVs (rule conditions and message subjects are only in those).' 'INFO'
}

$note = $null
if ($script:CaseKitMissing) {
    if (-not $Quiet -and -not $script:CaseKitWarned) { Write-Status 'CaseKit.ps1 is missing from this folder - no ticket note this time.' 'WARN' }
} else {
    # The note is extra: a failure while building or saving it never changes the answer or the
    # exit code.
    try {
        $note = Get-MailboxCheckNote -Result $result -EvidencePaths $evidence
        if ($Quiet) {
            if ($folder) { $null = Save-TicketNote -Note $note -Folder $folder -PasteSafe:(-not $FullDetail) }
        } else {
            Write-Host ''
            $null = Publish-TicketNote -Note $note -Folder $folder -PasteSafe:(-not $FullDetail) -NoClipboard:$NoClipboard
        }
    } catch {
        if (-not $Quiet) { Write-Status "Could not make the ticket note: $($_.Exception.Message). The check above is still valid." 'WARN' }
        $note = $null
    }
}
$result.TicketNote = $note

if ($PassThru) { return $result }
exit $result.ExitCode
