# 5.1 because ExchangeOnlineManagement needs Windows PowerShell 5.1 (root CLAUDE.md, version floors).
# Tests\PSVersionFloor.Tests.ps1 guards it.
#Requires -Version 5.1

<#
.SYNOPSIS
    Shared logic for Get-M365MailboxCheck.ps1: delegates, forwarding, inbox-rule takeover signs,
    mailbox facts, the verdict, the HTML report and the ticket note.
.DESCRIPTION
    Dot-sourced by Get-M365MailboxCheck.ps1 (and by the tests). Every function here is pure: no
    Exchange cmdlet, no console, no file, no clipboard. The entry script reads Exchange Online and
    hands the objects in. Get-MailboxCheckNote needs CaseKit.ps1 (the entry script loads it).

    THE GATES. Every section the entry script reads reports Checked or CouldNotCheck with a
    plain-English reason. The verdict reads the gates, never an empty result: an inbox-rule list
    that could not be read is not a clean inbox-rule list, so "No takeover signs found" is only
    ever written when every section was read (Get-MailboxCheckAssessment).

    TAKEOVER SIGNS. Mail forwarded outside the tenant (the mailbox's ForwardingSmtpAddress, a
    ForwardingAddress recipient such as a mail contact that points outside, or an inbox rule
    that forwards, forwards as an attachment, or redirects), a rule that forwards to a recipient
    the tool cannot classify, a rule that deletes mail, a rule that hides mail (moves it to RSS
    Feeds, RSS Subscriptions, Conversation History, Deleted Items, Junk Email or Archive, or
    moves it and marks it read), and a hidden rule other than the built-in junk-mail rule. The
    tool does not score the risk: CIPP's BEC report does that (owner decision D-003), so every
    sign leads to the same next step.

    INSIDE, OUTSIDE OR UNKNOWN (Get-MailboxAddressScope). An address is Internal only when it is
    positively inside: its domain is an accepted domain of the tenant (or a subdomain of one), or
    it is an Exchange object reference (EX:/o=... legacy DN). An SMTP address in any other domain
    is External. Anything else (a bare display name, an address that does not parse) is Unknown,
    and Unknown is never treated as inside: for a rule it is a sign, for mailbox forwarding the
    section is Could not check.

    PERSONAL DATA (D-025). Rule conditions (Description), full forwarding addresses and the
    message trace (with subjects) go only into the local HTML and CSV. Sign messages name the
    rule and the outside DOMAIN, never the full address, because they go into the ticket note.
    Raw Exchange error text stays in the console and the HTML too: the note gives each section
    a fixed reason (NoteReason). Rule names are written by whoever controls the mailbox, so
    control characters are removed and they are cut to 100 characters before they are shown.
.NOTES
    REFERENCES
      Get-InboxRule: -Mailbox, -IncludeHidden ("whether to include hidden Inbox rules in the
      results"), -ResultSize (default 1000, "unlimited" for all); does not work for the
      View-Only Organization Management role group or the Global Reader role
        https://learn.microsoft.com/powershell/module/exchangepowershell/get-inboxrule
      New-InboxRule: the action properties ForwardTo, ForwardAsAttachmentTo, RedirectTo,
      DeleteMessage (moves the message to Deleted Items), SoftDeleteMessage, MoveToFolder
      (syntax MailboxID:\ParentFolder[\SubFolder]) and MarkAsRead
        https://learn.microsoft.com/powershell/module/exchangepowershell/new-inboxrule
      Get-EXOMailbox property sets: Delivery (ForwardingSmtpAddress, ForwardingAddress,
      DeliverToMailboxAndForward, GrantSendOnBehalfTo), Archive (ArchiveStatus, ArchiveGuid),
      Hold (LitigationHoldEnabled, InPlaceHolds), Quota (ProhibitSendQuota), Minimum
      (RecipientTypeDetails, PrimarySmtpAddress, EmailAddresses); Get-EXOMailboxStatistics
      Minimum (TotalItemSize, ItemCount)
        https://learn.microsoft.com/powershell/exchange/cmdlet-property-sets
      Mailbox forwarding: ForwardingAddress is a recipient in the organization (any value that
      identifies it: name, alias, DN, email address, GUID); when both it and
      ForwardingSmtpAddress are set, ForwardingSmtpAddress is ignored
        https://learn.microsoft.com/powershell/module/exchangepowershell/set-mailbox
      Get-EXORecipient -Identity -Properties: the recipient's RecipientTypeDetails and
      PrimarySmtpAddress (and, by name, ExternalEmailAddress: where a mail contact or mail user
      sends the mail)
        https://learn.microsoft.com/powershell/module/exchangepowershell/get-exorecipient
        https://learn.microsoft.com/powershell/exchange/cmdlet-property-sets
      Accepted domain types: Authoritative, InternalRelay, ExternalRelay ("relayed to an external
      email system that's completely outside of your control"); ExternalRelay domains are not
      treated as inside
        https://learn.microsoft.com/powershell/module/exchangepowershell/set-accepteddomain
      Get-EXOMailboxPermission output: User, AccessRights, IsInherited, Deny; FullAccess and
      ReadPermission are directly assigned to NT AUTHORITY\SELF by default
        https://learn.microsoft.com/powershell/module/exchangepowershell/get-exomailboxpermission
      Get-EXORecipientPermission: SendAs is the only AccessRights value
        https://learn.microsoft.com/powershell/module/exchangepowershell/get-exorecipientpermission
      InPlaceHolds prefixes: UniH = eDiscovery hold, no prefix or cld = In-Place Hold, mbx / skp
      = Microsoft 365 retention policy, -mbx = excluded from an organization-wide retention
      policy, grp = retention policy for Microsoft 365 groups
        https://learn.microsoft.com/purview/ediscovery-identify-a-hold-on-an-exchange-online-mailbox
      Roles. Mailbox settings and recipients: Organization Management or Recipient Management;
      View-Only Organization Management can view them. Message trace: Organization Management,
      Compliance Management or Help Desk. Domains: Organization Management
        https://learn.microsoft.com/exchange/permissions-exo/feature-permissions
      Message trace in Exchange Online: Global Administrator or Exchange Administrator in Entra
      ID also grant it; Get-MessageTraceV2 needs ExchangeOnlineManagement 3.7.0 or later
        https://learn.microsoft.com/exchange/monitoring/trace-an-email-message/message-trace-modern-eac
      CSV cells starting with = + - @ are neutralised with a leading ' (CSV injection); the entry
      script uses ConvertTo-M365CsvValue from M365UserCheck.Core.ps1
        https://owasp.org/www-community/attacks/CSV_Injection

    NOT VERIFIED ON LEARN
      - How the built-in junk-mail rule appears. Learn documents -IncludeHidden but no IsHidden
        property and no name for the system rule. Hidden = returned with -IncludeHidden but not
        without it (the entry script compares the two lists), and the junk-mail rule is
        recognised by its name, 'Junk E-mail Rule'. A tenant where that rule has another name
        (another language) shows it as a HiddenRule sign: a false alarm, never a missed one.
      - The well-known folders are matched by their English names in MoveToFolder. Learn gives
        MoveToFolder only as MailboxID:\ParentFolder[\SubFolder], with no folder type, so a
        mailbox with localized folder names is not matched (the rule is still listed).
      - SoftDeleteMessage: Learn's description is a placeholder. Treated as "deletes mail".
      - Get-AcceptedDomain output properties (DomainName, InitialDomain, DomainType) are not
        listed on its Learn page; the names used are the ones the cmdlet returns.
      - Get-EXORecipient -Properties ExternalEmailAddress: ExternalEmailAddress is in none of the
        Get-EXORecipient property sets (it is a Get-Recipient property of mail contacts and mail
        users). -Properties takes any property name, so it is asked for by name. A recipient that
        comes back without a usable address leaves Mailbox forwarding at Could not check.
      - The junk-mail rule exemption also needs the rule to have none of the actions this check
        reads (forward, redirect, delete, move, mark as read). If the real built-in rule ever
        shows one of them, it is reported as a hidden rule: a false alarm, never a missed one.
#>

# =============================================================================
# Documented constants and fixed wording
# =============================================================================

# Exact wording from the approved backlog item (SQ-007, AC15).
$script:MailboxTakeoverLine = 'Possible account takeover: do NOT reset the password or delete the rule yet. Escalate.'
$script:MailboxTakeoverNextStep = "Check CIPP's BEC report for this user."
$script:MailboxCleanLine = 'No takeover signs found in the checks below.'

# Owner decision D-008: recent rule and delegate changes need the unified audit log (SQ-016).
$script:MailboxRecentChangesLine = "Recent rule, forwarding and delegate changes: not checked here, see CIPP's BEC report."

# The built-in hidden junk-mail rule (NOT VERIFIED on Learn, see .NOTES).
$script:MailboxJunkRuleName = 'Junk E-mail Rule'

# Folders a rule can use to keep mail out of the user's sight (English names, see .NOTES).
# One place to extend.
$script:MailboxHidingFolders = @('RSS Feeds', 'RSS Subscriptions', 'Conversation History', 'Deleted Items', 'Junk Email', 'Junk E-mail', 'Archive')

# Get-MessageTraceV2: "returns up to 1000 results, with a maximum of 5000"; "You can only return
# 10 days worth of data per query".
# https://learn.microsoft.com/powershell/module/exchangepowershell/get-messagetracev2
$script:MailboxTraceMaxResults = 5000

# Who can read each section (feature-permissions, get-inboxrule, message-trace-modern-eac).
$script:MailboxRecipientRoles = 'the Recipient Management or Organization Management role group (View-Only Organization Management can view it)'
$script:MailboxSectionRoles = @{
    'Inbox rules'      = 'the Recipient Management or Organization Management role group; Global Reader and View-Only Organization Management cannot read inbox rules'
    'Hidden inbox rules' = 'the Recipient Management or Organization Management role group; Global Reader and View-Only Organization Management cannot read inbox rules'
    'Message trace'    = 'the Organization Management, Compliance Management or Help Desk role group, or Exchange Administrator in Entra ID'
    'Accepted domains' = 'the Organization Management role group (View-Only Organization Management can view it)'
}

# Errors that mean "the signed-in account may not do this". Exchange Online only offers the
# cmdlets a role allows, so a cmdlet that "is not recognized" also means a missing role.
# The ticket note's reason for a section that failed without a role error. The raw error stays
# in the console and the HTML: it can carry addresses and tenant details.
$script:MailboxNoteReasonDefault = 'could not be read (see the report)'

# Fixed headline of a PARTLY CHECKED ticket note (the reasons are under Could not check).
$script:MailboxPartlyNoteHeadline = 'PARTLY CHECKED - see Could not check'

# Rule names are shown at most this long (console, signs, note).
$script:MailboxRuleNameMaxLength = 100

$script:MailboxAccessErrorPattern = "(?i)access is denied|isn't assigned to any management roles|not assigned to any management role|not allowed|insufficient|unauthori[sz]ed|forbidden|does not allow|is not recognized|isn't recognized"

# =============================================================================
# Small helpers (pure)
# =============================================================================

function Get-MailboxCheckValue {
    # The property's value from an object or a hashtable; $null when absent.
    param([object]$Object, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Test-MailboxCheckValue {
    # True when the value is something: not $null, not blank, not an empty list.
    param([object]$Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [string]) { return -not [string]::IsNullOrWhiteSpace($Value) }
    if ($Value -is [System.Collections.IEnumerable]) {
        return (@($Value | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0)
    }
    return $true
}

function ConvertTo-MailboxSafeText {
    <#
    .SYNOPSIS
        Text written by whoever controls the mailbox (rule names, folders), made safe to show:
        every run of control characters becomes one space, and with -MaxLength the text is cut
        (ending in '...').
    .DESCRIPTION
        A line break in a rule name would forge a line (or a whole section) of the ticket note;
        an ESC sequence would rewrite the console.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Text, [int]$MaxLength = 0)
    $t = ([regex]::Replace([string]$Text, '\p{Cc}+', ' ')).Trim()
    if ($MaxLength -gt 3 -and $t.Length -gt $MaxLength) { $t = $t.Substring(0, $MaxLength - 3).TrimEnd() + '...' }
    return $t
}

function Get-MailboxAddressFromText {
    <#
    .SYNOPSIS
        The SMTP address in an Exchange recipient string, or ''.
    .DESCRIPTION
        Accepts 'x@gmail.com', 'smtp:x@gmail.com', 'SMTP:x@gmail.com' and the inbox-rule form
        '"Name" [SMTP:x@gmail.com]'. The [SMTP:...] part wins over a display name that looks
        like an address ('"boss@contoso.com" [SMTP:x@gmail.com]' is x@gmail.com). A recipient
        without an SMTP address (an internal object such as '"Jane Doe" [EX:/o=...]') returns ''.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $bracket = [regex]::Match($Text, '(?i)\[smtp:(?<a>[^\s\[\]"<>:;,()]+@[^\s\[\]"<>:;,()]+)\]')
    if ($bracket.Success) { return $bracket.Groups['a'].Value.TrimEnd('.') }
    # An object reference: the quoted part is a display name, not an address.
    if ($Text -match '(?i)\[(EX|X500):') { return '' }
    $m =[regex]::Match($Text, '(?i)(?:smtp:)?(?<a>[^\s\[\]"<>:;,()]+@[^\s\[\]"<>:;,()]+)')
    if (-not $m.Success) { return '' }
    return $m.Groups['a'].Value.TrimEnd('.')
}

function Get-MailboxAddressDomain {
    # 'x@Gmail.com' -> 'gmail.com'; '' when there is no SMTP address.
    param([AllowEmptyString()][AllowNull()][string]$Address)
    $a = Get-MailboxAddressFromText -Text $Address
    if (-not $a) { return '' }
    return $a.Substring($a.LastIndexOf('@') + 1).ToLowerInvariant()
}

function Get-MailboxAddressScope {
    <#
    .SYNOPSIS
        'Internal', 'External' or 'Unknown' for an Exchange recipient string.
    .DESCRIPTION
        Internal: the SMTP domain is an accepted domain or a subdomain of one (case-insensitive;
        a leading '*.' on an accepted domain is ignored), or the value is an Exchange object
        reference ('"Jane Doe" [EX:/o=...]', '/o=...'). External: an SMTP address in any other
        domain. Unknown: anything else, such as a bare display name or an address that does not
        parse. Unknown is never inside: callers raise a sign or mark the section Could not check.
        'evilcontoso.com' is not a subdomain of 'contoso.com': only a whole label before the
        accepted domain counts ('mail.contoso.com').
    #>
    param([AllowEmptyString()][AllowNull()][string]$Address, [AllowEmptyCollection()][string[]]$AcceptedDomain = @())
    if ([string]::IsNullOrWhiteSpace($Address)) { return 'Unknown' }
    $domain = Get-MailboxAddressDomain -Address $Address
    if (-not $domain) {
        if ($Address -match '(?i)\[EX:/o=' -or $Address.Trim() -match '(?i)^(EX:)?/o=') { return 'Internal' }
        return 'Unknown'
    }
    foreach ($accepted in @($AcceptedDomain)) {
        if ([string]::IsNullOrWhiteSpace($accepted)) { continue }
        $a = $accepted.Trim().ToLowerInvariant()
        if ($a.StartsWith('*.')) { $a = $a.Substring(2) }
        $a = $a.Trim('.')
        if (-not $a) { continue }
        if ($domain -eq $a -or $domain.EndsWith('.' + $a)) { return 'Internal' }
    }
    return 'External'
}

function Test-ExternalAddress {
    <#
    .SYNOPSIS
        True when Get-MailboxAddressScope says External. False for Internal AND for Unknown, so
        never use this to decide that something is inside: the check itself uses
        Get-MailboxAddressScope.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Address, [AllowEmptyCollection()][string[]]$AcceptedDomain = @())
    return ((Get-MailboxAddressScope -Address $Address -AcceptedDomain $AcceptedDomain) -eq 'External')
}

function New-MailboxSign {
    # One takeover sign. Message is plain English and names only the rule and the outside domain.
    param(
        [Parameter(Mandatory = $true)][ValidateSet('ExternalForwarding', 'ExternalRuleForward', 'UnclassifiedRuleForward', 'RuleDeletesMail', 'RuleHidesMail', 'HiddenRule')][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$Domain = '',
        [string]$RuleName = '',
        [bool]$KeepsCopy = $false
    )
    return [PSCustomObject]@{ Kind = $Kind; Message = $Message; Domain = $Domain; RuleName = $RuleName; KeepsCopy = $KeepsCopy }
}

function New-MailboxGate {
    <#
    .SYNOPSIS
        One section of the check and whether this run could read it.
    .DESCRIPTION
        Sources: 'Accepted domains', 'Mailbox forwarding', 'Mailbox size', 'Archive size',
        'Full Access', 'Send As', 'Inbox rules', 'Hidden inbox rules', 'Message trace'.
        Reason is for the console and the HTML (it may hold the raw error). NoteReason is the
        fixed plain-English reason for the ticket note; it never carries Exchange text.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][ValidateSet('Checked', 'CouldNotCheck')][string]$State,
        [string]$Reason = '',
        [string]$NoteReason = ''
    )
    return [PSCustomObject]@{ Source = $Source; State = $State; Reason = $Reason; NoteReason = $NoteReason }
}

function Get-MailboxErrorSummary {
    # The first line of an error message, at most 300 characters.
    param([AllowEmptyString()][AllowNull()][string]$Message)
    $text = ([string]$Message -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
    $text = ([string]$text).Trim()
    if ($text.Length -gt 300) { $text = $text.Substring(0, 300) + '...' }
    if (-not $text) { $text = 'no error text' }
    return $text
}

function Get-MailboxGateFromError {
    <#
    .SYNOPSIS
        A CouldNotCheck gate for a section whose read failed, with the error and, when it looks
        like a missing role, the role that can read the section.
    #>
    param([Parameter(Mandatory = $true)][string]$Source, [AllowEmptyString()][AllowNull()][string]$Message)
    $summary = Get-MailboxErrorSummary -Message $Message
    $reason = $summary
    $noteReason = $script:MailboxNoteReasonDefault
    if ([string]$Message -match $script:MailboxAccessErrorPattern) {
        $roles = if ($script:MailboxSectionRoles.ContainsKey($Source)) { $script:MailboxSectionRoles[$Source] } else { $script:MailboxRecipientRoles }
        $reason = '{0}. Reading this needs {1}.' -f $summary.TrimEnd('.'), $roles
        $noteReason = 'the signed-in account may not read this. Reading it needs {0}.' -f $roles
    }
    return (New-MailboxGate -Source $Source -State CouldNotCheck -Reason $reason -NoteReason $noteReason)
}

# =============================================================================
# Delegates (pure)
# =============================================================================

function Get-MailboxDelegates {
    <#
    .SYNOPSIS
        Who holds Full Access, Send As or Send on Behalf, as a list of names.
    .DESCRIPTION
        FullAccess: Get-EXOMailboxPermission entries (User, AccessRights, IsInherited, Deny).
        SendAs: Get-EXORecipientPermission entries (Trustee, AccessRights, AccessControlType).
        SendOnBehalf: the GrantSendOnBehalfTo values. NT AUTHORITY\SELF (the owner's own
        access), inherited entries and Deny entries are dropped: only explicit grants are
        delegates.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('FullAccess', 'SendAs', 'SendOnBehalf')][string]$Kind,
        [AllowEmptyCollection()][object[]]$Permission = @()
    )
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($p in @($Permission)) {
        if ($null -eq $p) { continue }
        # if/elseif, not switch: 'continue' inside a switch would only leave the switch.
        $rights = @(Get-MailboxCheckValue $p 'AccessRights') -join ','
        if ($Kind -eq 'SendOnBehalf') {
            $who = [string]$p
        } elseif ($Kind -eq 'FullAccess') {
            if ((Get-MailboxCheckValue $p 'IsInherited') -eq $true -or (Get-MailboxCheckValue $p 'Deny') -eq $true) { continue }
            if ($rights -notmatch '(?i)\bFullAccess\b') { continue }
            $who = [string](Get-MailboxCheckValue $p 'User')
        } else {
            if ((Get-MailboxCheckValue $p 'IsInherited') -eq $true -or [string](Get-MailboxCheckValue $p 'AccessControlType') -eq 'Deny') { continue }
            if ($rights -notmatch '(?i)\bSendAs\b') { continue }
            $who = [string](Get-MailboxCheckValue $p 'Trustee')
        }
        $who = $who.Trim()
        if (-not $who -or $who -match '^(?i)NT AUTHORITY\\SELF$') { continue }
        if (-not $names.Contains($who)) { $names.Add($who) }
    }
    return $names.ToArray()
}

function Format-MailboxDelegateList {
    # 'Nobody' for an empty list, else the names joined with ', '.
    param([AllowEmptyCollection()][string[]]$Delegate = @())
    $list = @($Delegate | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($list.Count -eq 0) { return 'Nobody' }
    return ($list -join ', ')
}

# =============================================================================
# Forwarding and inbox-rule signs (pure)
# =============================================================================

function Get-ForwardingRecipientAddress {
    <#
    .SYNOPSIS
        Where a ForwardingAddress recipient (from Get-EXORecipient) sends the mail: its
        ExternalEmailAddress when it has one (a mail contact or mail user), else its
        PrimarySmtpAddress. '' when it has neither.
    #>
    param([object]$Recipient)
    foreach ($n in 'ExternalEmailAddress', 'PrimarySmtpAddress') {
        $v = [string](Get-MailboxCheckValue $Recipient $n)
        if (-not [string]::IsNullOrWhiteSpace($v)) { return $v.Trim() }
    }
    return ''
}

function Get-ForwardingRecipientTypeText {
    # The recipient's type in plain words. Its name can be client data, so signs name the type only.
    param([object]$Recipient)
    switch ([string](Get-MailboxCheckValue $Recipient 'RecipientTypeDetails')) {
        'MailContact' { return 'a mail contact' }
        'MailUser' { return 'a mail user' }
        'GuestMailUser' { return 'a guest mail user' }
        default { return 'a recipient' }
    }
}

function Get-ForwardingSigns {
    <#
    .SYNOPSIS
        ExternalForwarding signs when the mailbox's own forwarding sends mail outside the
        tenant, naming the domain and whether a copy is kept.
    .DESCRIPTION
        ForwardingSmtpAddress is judged directly. ForwardingAddress is a recipient object; it is
        judged by where that recipient sends the mail (-ForwardingRecipient, the Get-EXORecipient
        result), so a mail contact pointing at gmail.com is a sign. Whether every target could be
        judged is Get-MailboxForwardingGate's job: this function only raises signs.
    #>
    param([object]$Mailbox, [object]$ForwardingRecipient, [AllowEmptyCollection()][string[]]$AcceptedDomain = @())
    $signs = New-Object System.Collections.Generic.List[object]
    $keeps = ((Get-MailboxCheckValue $Mailbox 'DeliverToMailboxAndForward') -eq $true)
    $copy = if ($keeps) { 'a copy is kept in the mailbox' } else { 'no copy is kept in the mailbox, so the user never sees it' }

    $smtp = [string](Get-MailboxCheckValue $Mailbox 'ForwardingSmtpAddress')
    if ((Get-MailboxAddressScope -Address $smtp -AcceptedDomain $AcceptedDomain) -eq 'External') {
        $domain = Get-MailboxAddressDomain -Address $smtp
        $signs.Add((New-MailboxSign -Kind ExternalForwarding -Domain $domain -KeepsCopy $keeps -Message ('Mail is forwarded to an outside address at {0} ({1}).' -f $domain, $copy)))
    }

    if ((Test-MailboxCheckValue (Get-MailboxCheckValue $Mailbox 'ForwardingAddress')) -and $null -ne $ForwardingRecipient) {
        $target = Get-ForwardingRecipientAddress -Recipient $ForwardingRecipient
        if ((Get-MailboxAddressScope -Address $target -AcceptedDomain $AcceptedDomain) -eq 'External') {
            $domain = Get-MailboxAddressDomain -Address $target
            $type = Get-ForwardingRecipientTypeText -Recipient $ForwardingRecipient
            $signs.Add((New-MailboxSign -Kind ExternalForwarding -Domain $domain -KeepsCopy $keeps -Message ('Mail is forwarded to {0} in this tenant that sends it to an outside address at {1} ({2}).' -f $type, $domain, $copy)))
        }
    }
    return $signs.ToArray()
}

function Get-MailboxForwardingGate {
    <#
    .SYNOPSIS
        The 'Mailbox forwarding' gate: Checked only when every forwarding target could be
        judged inside or outside.
    .DESCRIPTION
        CouldNotCheck when ForwardingSmtpAddress is set but is not an address the tool can
        judge, or when ForwardingAddress is set and its recipient could not be looked up
        (-LookupError), was not found (no -ForwardingRecipient), or has no address the tool can
        judge. An unjudged forward is never reported as "nothing is forwarded outside".
    #>
    param(
        [object]$Mailbox,
        [object]$ForwardingRecipient,
        [AllowEmptyString()][AllowNull()][string]$LookupError = '',
        [AllowEmptyCollection()][string[]]$AcceptedDomain = @()
    )
    $source = 'Mailbox forwarding'
    $reasons = New-Object System.Collections.Generic.List[string]
    $noteReasons = New-Object System.Collections.Generic.List[string]

    $smtp = [string](Get-MailboxCheckValue $Mailbox 'ForwardingSmtpAddress')
    if ((Test-MailboxCheckValue $smtp) -and (Get-MailboxAddressScope -Address $smtp -AcceptedDomain $AcceptedDomain) -eq 'Unknown') {
        $reasons.Add(("The forwarding address '{0}' is not an email address this tool can judge; look at the mailbox's forwarding in the Exchange admin center" -f $smtp))
        $noteReasons.Add('the forwarding address could not be judged (see the report)')
    }

    $fwd = [string](Get-MailboxCheckValue $Mailbox 'ForwardingAddress')
    if (Test-MailboxCheckValue $fwd) {
        if (-not [string]::IsNullOrWhiteSpace($LookupError)) {
            $g = Get-MailboxGateFromError -Source $source -Message $LookupError
            $reasons.Add(("Could not look up the forwarding recipient '{0}': {1}" -f $fwd, $g.Reason.TrimEnd('.')))
            $noteReasons.Add(('the forwarding recipient could not be looked up: {0}' -f $g.NoteReason.TrimEnd('.')))
        } elseif ($null -eq $ForwardingRecipient) {
            $reasons.Add(("The forwarding recipient '{0}' was not found, so where the mail goes is not known" -f $fwd))
            $noteReasons.Add('the forwarding recipient was not found (see the report)')
        } elseif ((Get-MailboxAddressScope -Address (Get-ForwardingRecipientAddress -Recipient $ForwardingRecipient) -AcceptedDomain $AcceptedDomain) -eq 'Unknown') {
            $reasons.Add(("The forwarding recipient '{0}' has no email address this tool can judge; look at it in the Exchange admin center" -f $fwd))
            $noteReasons.Add('the forwarding recipient could not be judged (see the report)')
        }
    }

    if ($reasons.Count -eq 0) { return (New-MailboxGate -Source $source -State Checked) }
    return (New-MailboxGate -Source $source -State CouldNotCheck -Reason (($reasons -join '; ') + '.') -NoteReason (($noteReasons -join '; ') + '.'))
}

function Get-InboxRuleFolderName {
    # 'accounts@contoso.com:\RSS Feeds\Old' -> 'RSS Feeds' (the top folder of MoveToFolder).
    param([AllowEmptyString()][AllowNull()][string]$MoveToFolder)
    if ([string]::IsNullOrWhiteSpace($MoveToFolder)) { return '' }
    $path = $MoveToFolder
    $i = $path.IndexOf(':\')
    if ($i -ge 0) { $path = $path.Substring($i + 2) }
    return (@($path.Trim('\').Split('\'))[0]).Trim()
}

function Get-InboxRuleSigns {
    <#
    .SYNOPSIS
        Takeover signs in a list of inbox rules: ExternalRuleForward, RuleDeletesMail,
        RuleHidesMail and HiddenRule.
    .DESCRIPTION
        One ExternalRuleForward per rule and action (ForwardTo, ForwardAsAttachmentTo,
        RedirectTo) with an outside address, and one UnclassifiedRuleForward per rule and action
        with a recipient Get-MailboxAddressScope calls Unknown. RuleHidesMail for a move to one
        of $script:MailboxHidingFolders, or any move plus mark as read. HiddenRule for a rule
        with IsHidden $true, or with IdentityMissing $true (its hidden state could not be told,
        see ConvertTo-MailboxRuleList), other than the built-in junk-mail rule; that rule is
        exempt only while it has none of the actions this check reads. A rule that is turned
        off still raises its signs, marked as turned off: someone created it. Rule names lose
        control characters and are cut to 100 characters (ConvertTo-MailboxSafeText).
    #>
    param([AllowEmptyCollection()][object[]]$Rule = @(), [AllowEmptyCollection()][string[]]$AcceptedDomain = @())
    $signs = New-Object System.Collections.Generic.List[object]
    $forwardActions = [ordered]@{ ForwardTo = 'forwards mail'; ForwardAsAttachmentTo = 'forwards mail as an attachment'; RedirectTo = 'redirects mail' }
    foreach ($r in @($Rule)) {
        if ($null -eq $r) { continue }
        $name = ConvertTo-MailboxSafeText -Text ([string](Get-MailboxCheckValue $r 'Name')) -MaxLength $script:MailboxRuleNameMaxLength
        $off = if ((Get-MailboxCheckValue $r 'Enabled') -eq $false) { ' (the rule is turned off)' } else { '' }

        foreach ($prop in $forwardActions.Keys) {
            $targets = @(@(Get-MailboxCheckValue $r $prop) | Where-Object { Test-MailboxCheckValue $_ } | ForEach-Object { [string]$_ })
            $scopes = @($targets | ForEach-Object { [PSCustomObject]@{ Address = $_; Scope = (Get-MailboxAddressScope -Address $_ -AcceptedDomain $AcceptedDomain) } })
            $domains = @($scopes | Where-Object { $_.Scope -eq 'External' } | ForEach-Object { Get-MailboxAddressDomain -Address $_.Address } | Select-Object -Unique)
            if ($domains.Count -gt 0) {
                $where = if ($domains.Count -eq 1) { 'an outside address at ' + $domains[0] } else { 'outside addresses at ' + ($domains -join ', ') }
                $signs.Add((New-MailboxSign -Kind ExternalRuleForward -RuleName $name -Domain ($domains -join ', ') -Message ("Inbox rule '{0}' {1} to {2}{3}." -f $name, $forwardActions[$prop], $where, $off)))
            }
            if (@($scopes | Where-Object { $_.Scope -eq 'Unknown' }).Count -gt 0) {
                # Not judged inside. The recipient text is not repeated: it can be client data.
                $signs.Add((New-MailboxSign -Kind UnclassifiedRuleForward -RuleName $name -Message ("Inbox rule '{0}' {1} to a recipient this tool could not classify as inside or outside the tenant (see the report){2}." -f $name, $forwardActions[$prop], $off)))
            }
        }

        if ((Get-MailboxCheckValue $r 'DeleteMessage') -eq $true) {
            $signs.Add((New-MailboxSign -Kind RuleDeletesMail -RuleName $name -Message ("Inbox rule '{0}' deletes mail (moves it to Deleted Items){1}." -f $name, $off)))
        } elseif ((Get-MailboxCheckValue $r 'SoftDeleteMessage') -eq $true) {
            $signs.Add((New-MailboxSign -Kind RuleDeletesMail -RuleName $name -Message ("Inbox rule '{0}' deletes mail{1}." -f $name, $off)))
        }

        $folder = Get-InboxRuleFolderName -MoveToFolder ([string](Get-MailboxCheckValue $r 'MoveToFolder'))
        $read = ((Get-MailboxCheckValue $r 'MarkAsRead') -eq $true)
        $hiding = @($script:MailboxHidingFolders | Where-Object { $_ -eq $folder })
        if ($folder -and $hiding.Count -gt 0) {
            $signs.Add((New-MailboxSign -Kind RuleHidesMail -RuleName $name -Message ("Inbox rule '{0}' moves mail to {1}{2}{3}." -f $name, $hiding[0], $(if ($read) { ' and marks it read' } else { '' }), $off)))
        } elseif ($folder -and $read) {
            # The folder name itself can be client data, so the message does not repeat it.
            $signs.Add((New-MailboxSign -Kind RuleHidesMail -RuleName $name -Message ("Inbox rule '{0}' moves mail to another folder and marks it read{1}." -f $name, $off)))
        }

        # The built-in junk-mail rule is exempt only while it does none of the things this check
        # looks at: a rule named like it that forwards, deletes, moves or marks mail is not it.
        $exempt = ($name -eq $script:MailboxJunkRuleName -and -not (Test-InboxRuleHasAction -Rule $r))
        if (-not $exempt) {
            if ((Get-MailboxCheckValue $r 'IsHidden') -eq $true) {
                $signs.Add((New-MailboxSign -Kind HiddenRule -RuleName $name -Message ("Inbox rule '{0}' is hidden: Exchange only lists it when asked for hidden rules{1}." -f $name, $off)))
            } elseif ((Get-MailboxCheckValue $r 'IdentityMissing') -eq $true) {
                $signs.Add((New-MailboxSign -Kind HiddenRule -RuleName $name -Message ("Inbox rule '{0}' may be hidden: Exchange returned it without an identity, so the tool could not tell if it is hidden{1}." -f $name, $off)))
            }
        }
    }
    return $signs.ToArray()
}

function Test-InboxRuleHasAction {
    # True when the rule forwards, redirects, deletes, moves or marks mail read.
    param([Parameter(Mandatory = $true)][object]$Rule)
    foreach ($n in 'ForwardTo', 'ForwardAsAttachmentTo', 'RedirectTo', 'MoveToFolder') {
        if (Test-MailboxCheckValue (Get-MailboxCheckValue $Rule $n)) { return $true }
    }
    foreach ($n in 'DeleteMessage', 'SoftDeleteMessage', 'MarkAsRead') {
        if ((Get-MailboxCheckValue $Rule $n) -eq $true) { return $true }
    }
    return $false
}

function ConvertTo-MailboxRuleList {
    <#
    .SYNOPSIS
        The rule list for the report: every rule from Get-InboxRule -IncludeHidden, each with
        HiddenState 'Hidden' when the plain Get-InboxRule (without -IncludeHidden) did not
        return it, 'Visible' when it did, and 'Unknown' when that could not be told.
    .DESCRIPTION
        Rules are matched on RuleIdentity, then Identity; never on the name, which anyone can
        copy. A rule with neither is Unknown and IdentityMissing (Get-InboxRuleSigns raises a
        HiddenRule sign for it). -VisibleRuleUnavailable (the plain call failed) makes every rule
        Unknown without IdentityMissing; the entry script records that as a Could not check
        section instead. IsHidden is $true only for 'Hidden'. Names lose control characters and
        are cut to 100 characters. Only the properties the check and the report use are kept.
    #>
    param(
        [AllowEmptyCollection()][object[]]$Rule = @(),
        [AllowEmptyCollection()][object[]]$VisibleRule = @(),
        [switch]$VisibleRuleUnavailable
    )
    $key = {
        param($r)
        foreach ($n in 'RuleIdentity', 'Identity') {
            $v = [string](Get-MailboxCheckValue $r $n)
            if ($v) { return "$n=$v" }
        }
        return ''
    }
    $visible = @{}
    foreach ($v in @($VisibleRule)) {
        if ($null -eq $v) { continue }
        $k = & $key $v
        if ($k) { $visible[$k] = $true }
    }
    $out = foreach ($r in @($Rule)) {
        if ($null -eq $r) { continue }
        $k = & $key $r
        $state = if (-not $k -or $VisibleRuleUnavailable) { 'Unknown' } elseif ($visible.ContainsKey($k)) { 'Visible' } else { 'Hidden' }
        [PSCustomObject]@{
            Name = ConvertTo-MailboxSafeText -Text ([string](Get-MailboxCheckValue $r 'Name')) -MaxLength $script:MailboxRuleNameMaxLength
            Enabled = Get-MailboxCheckValue $r 'Enabled'
            Priority = Get-MailboxCheckValue $r 'Priority'
            Identity = [string](Get-MailboxCheckValue $r 'Identity')
            IsHidden = ($state -eq 'Hidden')
            HiddenState = $state
            IdentityMissing = (-not $k)
            ForwardTo = @(Get-MailboxCheckValue $r 'ForwardTo' | Where-Object { $_ })
            ForwardAsAttachmentTo = @(Get-MailboxCheckValue $r 'ForwardAsAttachmentTo' | Where-Object { $_ })
            RedirectTo = @(Get-MailboxCheckValue $r 'RedirectTo' | Where-Object { $_ })
            DeleteMessage = ((Get-MailboxCheckValue $r 'DeleteMessage') -eq $true)
            SoftDeleteMessage = ((Get-MailboxCheckValue $r 'SoftDeleteMessage') -eq $true)
            MoveToFolder = [string](Get-MailboxCheckValue $r 'MoveToFolder')
            MarkAsRead = ((Get-MailboxCheckValue $r 'MarkAsRead') -eq $true)
            Description = [string](Get-MailboxCheckValue $r 'Description')
        }
    }
    return @($out)
}

function Get-InboxRuleActionText {
    # What the rule does, for the local report (full addresses; never for the ticket note).
    param([Parameter(Mandatory = $true)][object]$Rule)
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($pair in @(@('ForwardTo', 'Forwards to'), @('ForwardAsAttachmentTo', 'Forwards as attachment to'), @('RedirectTo', 'Redirects to'))) {
        $v = @(Get-MailboxCheckValue $Rule $pair[0] | Where-Object { $_ })
        if ($v.Count -gt 0) { $parts.Add(('{0}: {1}' -f $pair[1], ($v -join ', '))) }
    }
    if ((Get-MailboxCheckValue $Rule 'DeleteMessage') -eq $true) { $parts.Add('Deletes (to Deleted Items)') }
    if ((Get-MailboxCheckValue $Rule 'SoftDeleteMessage') -eq $true) { $parts.Add('Deletes (soft delete)') }
    $move = [string](Get-MailboxCheckValue $Rule 'MoveToFolder')
    if ($move) { $parts.Add("Moves to: $move") }
    if ((Get-MailboxCheckValue $Rule 'MarkAsRead') -eq $true) { $parts.Add('Marks as read') }
    if ($parts.Count -eq 0) { return 'none of the actions this check looks at (forward, redirect, delete, move, mark as read)' }
    # Addresses and folder names come from the mailbox: no control characters on the console.
    return (ConvertTo-MailboxSafeText -Text ($parts -join '; '))
}

# =============================================================================
# Facts (pure)
# =============================================================================

function Test-MailboxArchiveEnabled {
    # ArchiveStatus 'Active', or an ArchiveGuid that is not all zeros.
    param([object]$Mailbox)
    if ([string](Get-MailboxCheckValue $Mailbox 'ArchiveStatus') -eq 'Active') { return $true }
    $guid = [string](Get-MailboxCheckValue $Mailbox 'ArchiveGuid')
    return ($guid -and $guid -notmatch '^[0-]+$')
}

function Get-MailboxHoldText {
    # One InPlaceHolds value with its kind (ediscovery-identify-a-hold-on-an-exchange-online-mailbox).
    param([Parameter(Mandatory = $true)][string]$Hold)
    $kind = switch -Regex ($Hold) {
        '^UniH' { 'eDiscovery hold'; break }
        '^-mbx' { 'excluded from an organization-wide retention policy'; break }
        '^(mbx|skp)' { 'retention policy'; break }
        '^grp' { 'retention policy for groups'; break }
        '^cld' { 'In-Place Hold'; break }
        '^[0-9a-fA-F]{32}$' { 'In-Place Hold'; break }
        default { '' }
    }
    if ($kind) { return ('{0} ({1})' -f $Hold, $kind) }
    return $Hold
}

function Get-MailboxTypeText {
    param([AllowEmptyString()][AllowNull()][string]$RecipientTypeDetails)
    switch ($RecipientTypeDetails) {
        'UserMailbox' { return 'User mailbox' }
        'SharedMailbox' { return 'Shared mailbox' }
        'RoomMailbox' { return 'Room mailbox' }
        'EquipmentMailbox' { return 'Equipment mailbox' }
        'DiscoveryMailbox' { return 'Discovery mailbox' }
        default {
            if ([string]::IsNullOrWhiteSpace($RecipientTypeDetails)) { return 'not available' }
            return $RecipientTypeDetails
        }
    }
}

function Get-MailboxForwardingText {
    # The mailbox's own forwarding as a fact (full address: local report and console only).
    param([object]$Mailbox, [object]$ForwardingRecipient)
    $parts = New-Object System.Collections.Generic.List[string]
    $rawSmtp = [string](Get-MailboxCheckValue $Mailbox 'ForwardingSmtpAddress')
    $smtp = Get-MailboxAddressFromText -Text $rawSmtp
    if ($smtp) { $parts.Add("to $smtp") } elseif (Test-MailboxCheckValue $rawSmtp) { $parts.Add("to '$rawSmtp' (not an address this tool can judge)") }
    $recipient = [string](Get-MailboxCheckValue $Mailbox 'ForwardingAddress')
    if ($recipient) {
        if ($null -ne $ForwardingRecipient) {
            $target = Get-MailboxAddressFromText -Text (Get-ForwardingRecipientAddress -Recipient $ForwardingRecipient)
            $parts.Add(("to the recipient '{0}' ({1}), which delivers to {2}" -f $recipient, (Get-ForwardingRecipientTypeText -Recipient $ForwardingRecipient), $(if ($target) { $target } else { 'an address this tool could not read' })))
        } else {
            $parts.Add("to the recipient '$recipient' (not looked up: if it is a mail contact, the mail leaves the tenant)")
        }
    }
    if ($parts.Count -eq 0) { return 'None' }
    $copy = if ((Get-MailboxCheckValue $Mailbox 'DeliverToMailboxAndForward') -eq $true) { 'a copy is kept in the mailbox' } else { 'no copy is kept in the mailbox' }
    return ('Forwarded {0}; {1}' -f ($parts -join ' and '), $copy)
}

function Get-MailboxFactRows {
    <#
    .SYNOPSIS
        Item/Value rows: mailbox type, forwarding, size, quota, archive, holds. A value that is
        missing reads 'not available' (never 0 or blank); no archive reads 'No archive'.
    #>
    param([object]$Mailbox, [object]$Statistics, [object]$ArchiveStatistics, [object]$ForwardingRecipient)
    $na = 'not available'
    $rows = New-Object System.Collections.Generic.List[object]
    $add = { param($Item, $Value) $rows.Add([PSCustomObject]@{ Item = $Item; Value = $(if (Test-MailboxCheckValue $Value) { [string]$Value } else { $na }) }) }

    & $add 'Mailbox type' (Get-MailboxTypeText -RecipientTypeDetails ([string](Get-MailboxCheckValue $Mailbox 'RecipientTypeDetails')))
    & $add 'Mail forwarding' (Get-MailboxForwardingText -Mailbox $Mailbox -ForwardingRecipient $ForwardingRecipient)
    $size = [string](Get-MailboxCheckValue $Statistics 'TotalItemSize')
    $count = Get-MailboxCheckValue $Statistics 'ItemCount'
    if ($size -and $null -ne $count) { $size = '{0}, {1} items' -f $size, $count }
    & $add 'Total size' $size
    & $add 'Prohibit-send quota' ([string](Get-MailboxCheckValue $Mailbox 'ProhibitSendQuota'))

    $hasStatus = $null -ne (Get-MailboxCheckValue $Mailbox 'ArchiveStatus') -or $null -ne (Get-MailboxCheckValue $Mailbox 'ArchiveGuid')
    if (Test-MailboxArchiveEnabled -Mailbox $Mailbox) {
        & $add 'Archive' 'On'
        & $add 'Archive size' ([string](Get-MailboxCheckValue $ArchiveStatistics 'TotalItemSize'))
    } elseif ($hasStatus) {
        & $add 'Archive' 'No archive'
        & $add 'Archive size' 'No archive'
    } else {
        & $add 'Archive' $na
        & $add 'Archive size' $na
    }

    $lit = Get-MailboxCheckValue $Mailbox 'LitigationHoldEnabled'
    & $add 'Litigation hold' $(if ($lit -eq $true) { 'On' } elseif ($lit -eq $false) { 'Off' } else { $na })
    if ($null -eq $Mailbox -or $null -eq $Mailbox.PSObject.Properties['InPlaceHolds']) {
        & $add 'Other holds' $na
    } else {
        $holds = @(@(Get-MailboxCheckValue $Mailbox 'InPlaceHolds') | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { Get-MailboxHoldText -Hold ([string]$_) })
        & $add 'Other holds' $(if ($holds.Count -gt 0) { $holds -join ', ' } else { 'None' })
    }
    return $rows.ToArray()
}

function ConvertTo-MailboxTraceRows {
    # Message trace rows cut down to what the report shows. Received is UTC (get-messagetracev2).
    param([AllowEmptyCollection()][object[]]$Row = @(), [Parameter(Mandatory = $true)][ValidateSet('Sent', 'Received')][string]$Direction)
    $out = foreach ($r in @($Row)) {
        if ($null -eq $r) { continue }
        [PSCustomObject]@{
            Received = Get-MailboxCheckValue $r 'Received'
            Direction = $Direction
            SenderAddress = [string](Get-MailboxCheckValue $r 'SenderAddress')
            RecipientAddress = [string](Get-MailboxCheckValue $r 'RecipientAddress')
            Subject = [string](Get-MailboxCheckValue $r 'Subject')
            Status = [string](Get-MailboxCheckValue $r 'Status')
            Size = Get-MailboxCheckValue $r 'Size'
        }
    }
    return @($out)
}

function Format-MailboxCheckTime {
    # UTC and labelled: a ticket is often read later, in another time zone.
    param([object]$When)
    if ($null -eq $When -or [string]::IsNullOrWhiteSpace([string]$When)) { return 'unknown time' }
    try { $d = [datetime]$When } catch { return [string]$When }
    if ($d.Kind -eq [DateTimeKind]::Local) { $d = $d.ToUniversalTime() }
    return ('{0} UTC' -f $d.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture))
}

# =============================================================================
# Verdict (pure)
# =============================================================================

function Get-MailboxCheckAssessment {
    <#
    .SYNOPSIS
        The verdict block: TakeoverSigns (exit 1), PartlyChecked (exit 2) or AllChecked (exit 0).
    .DESCRIPTION
        Any sign -> line 1 is the takeover line, then each sign, then what could not be checked,
        then "Next step: Check CIPP's BEC report for this user." No sign and any section that
        could not be read -> PARTLY CHECKED, naming each section and why. Only when every
        section was read and none raised a sign does it say "No takeover signs found".
    #>
    param([AllowEmptyCollection()][object[]]$Signs = @(), [AllowEmptyCollection()][object[]]$Gate = @())
    $signList = @($Signs | Where-Object { $null -ne $_ })
    $couldNot = @($Gate | Where-Object { $null -ne $_ -and $_.State -ne 'Checked' } | ForEach-Object { [PSCustomObject]@{ Source = [string]$_.Source; Reason = [string]$_.Reason; NoteReason = [string](Get-MailboxCheckValue $_ 'NoteReason') } })
    $lines = New-Object System.Collections.Generic.List[string]

    if ($signList.Count -gt 0) {
        $verdict = 'TakeoverSigns'; $exit = 1; $next = $script:MailboxTakeoverNextStep
        $lines.Add($script:MailboxTakeoverLine)
        foreach ($s in $signList) { $lines.Add([string]$s.Message) }
        foreach ($c in $couldNot) { $lines.Add(('Could not check: {0}: {1}' -f $c.Source, $c.Reason)) }
    } elseif ($couldNot.Count -gt 0) {
        $verdict = 'PartlyChecked'; $exit = 2
        $what = ($couldNot | ForEach-Object { '{0} ({1})' -f $_.Source, $_.Reason.TrimEnd('.') }) -join '; '
        $lines.Add(('PARTLY CHECKED - no takeover signs in what could be read, but these could not be checked: {0}.' -f $what))
        $next = 'Run the check again with an account that can read the sections above (the role is named with each), or look at them in the Exchange admin center. Until then, nothing here rules out a takeover.'
    } else {
        $verdict = 'AllChecked'; $exit = 0
        $lines.Add($script:MailboxCleanLine)
        $next = "Nothing in this mailbox points to a takeover. If you still suspect one, check CIPP's BEC report for this user."
    }
    $lines.Add($script:MailboxRecentChangesLine)
    $lines.Add("Next step: $next")

    return [PSCustomObject]@{
        Verdict = $verdict; ExitCode = $exit; Lines = $lines.ToArray(); Signs = $signList
        CouldNotCheck = $couldNot; NextStep = $next
    }
}

# =============================================================================
# HTML report (pure)
# =============================================================================

function ConvertTo-MailboxCheckHtml {
    <#
    .SYNOPSIS
        The local HTML report: verdict first, then the stamp (tenant, account, time), what could
        not be checked, facts, delegates, inbox rules (with conditions) and the message trace
        (with subjects). Every value from Exchange is HTML-encoded: rule names, conditions and
        subjects are written by whoever controls the mailbox, including an attacker.
    #>
    param([Parameter(Mandatory = $true)][object]$Result)
    function Enc([object]$s) { [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $a = $Result.Assessment; $f = $Result.Facts; $t = $Result.Tenant
    $cls = switch ($a.Verdict) { 'TakeoverSigns' { 'bad' } 'AllChecked' { 'ok' } default { 'warn' } }
    $lines = @($a.Lines)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine("<title>Mailbox check - $(Enc $Result.Identity)</title>")
    [void]$sb.AppendLine('<style>body{background:#15181c;color:#e8eaed;font-family:"Segoe UI",sans-serif;max-width:1180px;margin:0 auto;padding:32px;line-height:1.5}' +
        '.banner{border:1px solid #333a44;border-radius:4px;padding:10px 14px;margin-bottom:20px;font-size:13px;color:#c3cad4}.banner b{color:#e8eaed}' +
        '.verdict{border-left:6px solid;padding:6px 0 6px 18px;margin-bottom:24px}.verdict h1{margin:0 0 6px 0;font-size:24px}' +
        '.ok{border-color:#5fc98a}.bad{border-color:#e2686a}.warn{border-color:#e0a458}' +
        '.reason{background:#1d2126;border:1px solid #333a44;border-radius:4px;padding:10px 14px;margin:8px 0}' +
        'table{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}' +
        'td,th{padding:6px 10px;border-bottom:1px solid #242931;text-align:left;vertical-align:top}th{color:#98a2b0}h2{font-size:15px;letter-spacing:.1em;text-transform:uppercase;color:#98a2b0;margin-top:32px}' +
        '.FAIL{color:#e2686a}.WARN{color:#e0a458}.INFO{color:#5dade2}.PASS{color:#5fc98a}</style></head><body>')

    # Verdict first (assumed by the squad: in HTML and the note the verdict leads, the stamp follows).
    [void]$sb.AppendLine("<div class=`"verdict $cls`"><h1>$(Enc $lines[0])</h1>")
    foreach ($l in @($lines | Select-Object -Skip 1)) { [void]$sb.AppendLine("<div>$(Enc $l)</div>") }
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine("<div class=`"banner`"><b>This tool only reads: it changed nothing.</b><br>Mailbox: <b>$(Enc $Result.Identity)</b><br>Tenant: <b>$(Enc $t.Name)</b>, tenant ID $(Enc $t.TenantId)<br>Signed in as: <b>$(Enc $t.Account)</b><br>Checked $(Enc (Format-MailboxCheckTime $Result.Now))</div>")

    if (@($a.CouldNotCheck).Count -gt 0) {
        [void]$sb.AppendLine('<h2>Could not check</h2>')
        foreach ($c in $a.CouldNotCheck) { [void]$sb.AppendLine("<div class=`"reason`"><span class=`"WARN`">[WARN]</span> $(Enc $c.Source): $(Enc $c.Reason)</div>") }
    }

    [void]$sb.AppendLine('<h2>Mailbox</h2><table>')
    foreach ($r in @($f.FactRows)) { [void]$sb.AppendLine("<tr><th>$(Enc $r.Item)</th><td>$(Enc $r.Value)</td></tr>") }
    [void]$sb.AppendLine('</table>')

    [void]$sb.AppendLine('<h2>Who can open it or send as it</h2><table>')
    foreach ($d in @(@('Full Access (open the mailbox)', 'Full Access', $f.FullAccess), @('Send As', 'Send As', $f.SendAs), @('Send on Behalf', '', $f.SendOnBehalf))) {
        $gate = if ($d[1]) { @($f.Gates | Where-Object { $_.Source -eq $d[1] })[0] } else { $null }
        $value = if ($gate -and $gate.State -ne 'Checked') { 'could not check' } else { Format-MailboxDelegateList -Delegate @($d[2]) }
        [void]$sb.AppendLine("<tr><th>$(Enc $d[0])</th><td>$(Enc $value)</td></tr>")
    }
    [void]$sb.AppendLine('</table>')

    $rulesGate = @($f.Gates | Where-Object { $_.Source -eq 'Inbox rules' })[0]
    $rules = @($f.Rules)
    [void]$sb.AppendLine("<h2>Inbox rules ($(Enc $rules.Count), $(Enc @($rules | Where-Object { $_.IsHidden }).Count) hidden)</h2>")
    if ($rulesGate -and $rulesGate.State -ne 'Checked') {
        [void]$sb.AppendLine("<p class=`"WARN`">Could not read the inbox rules: $(Enc $rulesGate.Reason)</p>")
    } elseif ($rules.Count -eq 0) {
        [void]$sb.AppendLine('<p>No inbox rules.</p>')
    } else {
        [void]$sb.AppendLine('<table><tr><th>Name</th><th>On</th><th>Hidden</th><th>What it does</th><th>Conditions (Exchange description)</th></tr>')
        foreach ($r in $rules) {
            $on = if ($r.Enabled -eq $false) { 'Off' } else { 'On' }
            $hidden = if ($r.IsHidden) { 'Hidden' } elseif ($r.HiddenState -eq 'Unknown') { 'Unknown' } else { '' }
            [void]$sb.AppendLine("<tr><td>$(Enc $r.Name)</td><td>$(Enc $on)</td><td>$(Enc $hidden)</td><td>$(Enc (Get-InboxRuleActionText -Rule $r))</td><td>$(Enc $r.Description)</td></tr>")
        }
        [void]$sb.AppendLine('</table>')
    }

    $traceGate = @($f.Gates | Where-Object { $_.Source -eq 'Message trace' })[0]
    if ($null -eq $f.Trace -and -not $traceGate) {
        [void]$sb.AppendLine('<h2>Message trace</h2><p>Not read (-NoTrace).</p>')
    } elseif ($traceGate -and $traceGate.State -ne 'Checked') {
        [void]$sb.AppendLine("<h2>Message trace</h2><p class=`"WARN`">Could not read the message trace: $(Enc $traceGate.Reason)</p>")
    } else {
        $tr = $f.Trace
        [void]$sb.AppendLine("<h2>Message trace, last $(Enc $tr.Days) days ($(Enc @($tr.Sent).Count) sent, $(Enc @($tr.Received).Count) received)</h2>")
        foreach ($cut in @($tr.CutOff)) { [void]$sb.AppendLine("<p class=`"WARN`">[WARN] results were cut off at $(Enc $tr.MaxResults); rerun with a smaller -TraceDays ($(Enc $cut)).</p>") }
        $all = @(@($tr.Sent) + @($tr.Received) | Sort-Object -Property { try { [datetime]$_.Received } catch { [datetime]::MinValue } } -Descending)
        if ($all.Count -eq 0) {
            [void]$sb.AppendLine('<p>No messages in this window.</p>')
        } else {
            [void]$sb.AppendLine('<table><tr><th>Received (UTC)</th><th>Direction</th><th>From</th><th>To</th><th>Subject</th><th>Status</th></tr>')
            foreach ($m in $all) {
                [void]$sb.AppendLine("<tr><td>$(Enc (Format-MailboxCheckTime $m.Received))</td><td>$(Enc $m.Direction)</td><td>$(Enc $m.SenderAddress)</td><td>$(Enc $m.RecipientAddress)</td><td>$(Enc $m.Subject)</td><td>$(Enc $m.Status)</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        }
    }
    [void]$sb.AppendLine("<p class=`"INFO`">$(Enc $script:MailboxRecentChangesLine) Message bodies and attachments are never read.</p></body></html>")
    return $sb.ToString()
}

# =============================================================================
# Ticket note (CaseKit.ps1)
# =============================================================================

function Get-MailboxCheckNote {
    <#
    .SYNOPSIS
        Maps a check result to a CaseKit ticket note.
    .DESCRIPTION
        Paste-safe by construction (D-025 and the squad's paste-safe assumption): the checked
        mailbox, sign kinds, rule names and outside DOMAINS only. The note names the checked
        mailbox, but never a forwarding, delegate or message-trace address, and carries no rule
        conditions and no raw Exchange error text: a section that could not be read gets its
        fixed NoteReason (the raw reason stays in the console and the HTML), and the headline is
        fixed text for every verdict. Every section that could not be read goes under Could not
        check, never Ruled out; a check is ruled out only when its sections (and the accepted
        domains it is judged against) were read.
    #>
    param([Parameter(Mandatory = $true)][object]$Result, [string[]]$EvidencePaths = @())
    $items = New-Object System.Collections.Generic.List[object]
    $next = New-Object System.Collections.Generic.List[string]
    $t = $Result.Tenant
    $tenantName = if ($t -and $t.Name) { [string]$t.Name } else { 'not known' }

    if ($Result.Status -eq 'Ok') {
        $a = $Result.Assessment; $f = $Result.Facts
        # Fixed text: the PARTLY CHECKED verdict line carries the raw reasons (console and HTML).
        $headline = switch ($a.Verdict) {
            'TakeoverSigns' { $script:MailboxTakeoverLine }
            'AllChecked' { $script:MailboxCleanLine }
            default { $script:MailboxPartlyNoteHeadline }
        }
        $traceText = if ($f.Trace) { ', message trace for the last {0} days' -f $f.Trace.Days } else { '' }
        $scopeLine = 'Mailbox {0} in {1}: delegates, forwarding, inbox rules (hidden ones included), size, archive and holds{2}.' -f $Result.Identity, $tenantName, $traceText

        foreach ($s in @($a.Signs)) { $items.Add((New-TicketNoteItem -Kind Problem -Text ('{0}: {1}' -f $s.Kind, $s.Message))) }
        foreach ($c in @($a.CouldNotCheck)) {
            $why = if ($c.NoteReason) { [string]$c.NoteReason } else { $script:MailboxNoteReasonDefault }
            $items.Add((New-TicketNoteItem -Kind NotChecked -Text ('{0}: {1}' -f $c.Source, $why)))
        }
        $items.Add((New-TicketNoteItem -Kind NotChecked -Text $script:MailboxRecentChangesLine))

        $checked = @{}
        foreach ($g in @($f.Gates)) { $checked[[string]$g.Source] = ($g.State -eq 'Checked') }
        $kinds = @($a.Signs | ForEach-Object { $_.Kind })
        if ($checked['Mailbox forwarding'] -and $checked['Accepted domains'] -and $kinds -notcontains 'ExternalForwarding') {
            $items.Add((New-TicketNoteItem -Kind Clear -CouldLook $true -Text 'Mailbox forwarding: nothing is forwarded outside the tenant.'))
        }
        $ruleKinds = @('ExternalRuleForward', 'UnclassifiedRuleForward', 'RuleDeletesMail', 'RuleHidesMail', 'HiddenRule')
        # 'Hidden inbox rules' is a gate only when telling hidden rules apart failed.
        if ($checked['Inbox rules'] -and $checked['Accepted domains'] -and $checked['Hidden inbox rules'] -ne $false -and @($kinds | Where-Object { $ruleKinds -contains $_ }).Count -eq 0) {
            $n = @($f.Rules).Count
            $items.Add((New-TicketNoteItem -Kind Clear -CouldLook $true -Text ('Inbox rules: {0} rule(s), hidden ones included; no rule matched the checks this tool runs (English folder names).' -f $n)))
        }
        $counts = foreach ($d in @(@('Full Access', $f.FullAccess), @('Send As', $f.SendAs))) {
            if ($checked[$d[0]]) { '{0}: {1}' -f $d[0], @($d[1]).Count }
        }
        $counts = @($counts) + @('Send on Behalf: {0}' -f @($f.SendOnBehalf).Count)
        $items.Add((New-TicketNoteItem -Kind Info -Text ('Delegates: {0} (names in the console and the HTML report).' -f ($counts -join ', '))))
        if ($f.Trace -and $checked['Message trace']) {
            $items.Add((New-TicketNoteItem -Kind Info -Text ('Message trace, last {0} days: {1} sent, {2} received (details in the HTML and CSV report).' -f $f.Trace.Days, @($f.Trace.Sent).Count, @($f.Trace.Received).Count)))
        }
        $next.Add($a.NextStep)
    } else {
        if ($Result.Status -eq 'NotFound') {
            $headline = "Mailbox check did not run - no mailbox found for '$($Result.Identity)'"
            $next.Add('Check the spelling and that you signed in to the right tenant (see the stamp), then run the check again.')
        } else {
            $headline = "Mailbox check for '$($Result.Identity)' did not run - could not read Exchange Online"
            # Fixed text: the error itself can carry addresses, so it stays in the console.
            $items.Add((New-TicketNoteItem -Kind Problem -Text 'The check could not read Exchange Online; the error is in the console.'))
            $next.Add('Check the sign-in, the ExchangeOnlineManagement module and your Exchange role, then run the check again.')
        }
        $scopeLine = "Looked up the mailbox '$($Result.Identity)' in $tenantName."
        $items.Add((New-TicketNoteItem -Kind NotChecked -Text 'The mailbox checks did not run (delegates, forwarding, inbox rules, size, holds, message trace).'))
    }

    $stampArgs = @{ ScopeLabel = 'Tenant'; Scope = $tenantName }
    if ($Result.Now -is [datetime]) { $stampArgs['Now'] = ([datetime]$Result.Now).ToLocalTime() }
    if ($t -and $t.Account) { $stampArgs['RunAs'] = [string]$t.Account }
    $stamp = New-TicketNoteStamp @stampArgs

    return New-TicketNote -Tool 'M365-MailboxCheck' -Headline $headline -ScopeLine $scopeLine -Items $items.ToArray() `
        -NextSteps $next.ToArray() -Stamp $stamp -EvidencePaths $EvidencePaths
}
