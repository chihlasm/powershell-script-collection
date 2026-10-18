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

    TAKEOVER SIGNS. Mail forwarded outside the tenant (mailbox forwarding or an inbox rule that
    forwards, forwards as an attachment, or redirects), a rule that deletes mail, a rule that
    hides mail (moves it to RSS Feeds, RSS Subscriptions, Conversation History, Deleted Items,
    Junk Email or Archive, or moves it and marks it read), and a hidden rule other than the
    built-in junk-mail rule. "Outside" means the address's domain is neither an accepted domain
    of the tenant nor a subdomain of one. The tool does not score the risk: CIPP's BEC report
    does that (owner decision D-003), so every sign leads to the same next step.

    PERSONAL DATA (D-025). Rule conditions (Description), full forwarding addresses and the
    message trace (with subjects) go only into the local HTML and CSV. Sign messages name the
    rule and the outside DOMAIN, never the full address, because they go into the ticket note.
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
      - Get-AcceptedDomain output properties (DomainName, InitialDomain) are not listed on its
        Learn page; the names used are the ones the cmdlet returns.
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
    'Message trace'    = 'the Organization Management, Compliance Management or Help Desk role group, or Exchange Administrator in Entra ID'
    'Accepted domains' = 'the Organization Management role group (View-Only Organization Management can view it)'
}

# Errors that mean "the signed-in account may not do this". Exchange Online only offers the
# cmdlets a role allows, so a cmdlet that "is not recognized" also means a missing role.
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

function Get-MailboxAddressFromText {
    <#
    .SYNOPSIS
        The SMTP address in an Exchange recipient string, or ''.
    .DESCRIPTION
        Accepts 'x@gmail.com', 'smtp:x@gmail.com', 'SMTP:x@gmail.com' and the inbox-rule form
        '"Name" [SMTP:x@gmail.com]'. A recipient without an SMTP address (an internal object
        such as '"Jane Doe" [EX:/o=...]') returns ''.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $m = [regex]::Match($Text, '(?i)(?:smtp:)?(?<a>[^\s\[\]"<>:;,()]+@[^\s\[\]"<>:;,()]+)')
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

function Test-ExternalAddress {
    <#
    .SYNOPSIS
        True when the address is outside the tenant: its domain is neither an accepted domain
        nor a subdomain of one. Case-insensitive; a leading '*.' on an accepted domain is
        ignored. A value without an SMTP address (a recipient object) is not external.
    .DESCRIPTION
        'evilcontoso.com' is not a subdomain of 'contoso.com': only a whole label before the
        accepted domain counts ('mail.contoso.com').
    #>
    param([AllowEmptyString()][AllowNull()][string]$Address, [AllowEmptyCollection()][string[]]$AcceptedDomain = @())
    $domain = Get-MailboxAddressDomain -Address $Address
    if (-not $domain) { return $false }
    foreach ($accepted in @($AcceptedDomain)) {
        if ([string]::IsNullOrWhiteSpace($accepted)) { continue }
        $a = $accepted.Trim().ToLowerInvariant()
        if ($a.StartsWith('*.')) { $a = $a.Substring(2) }
        $a = $a.Trim('.')
        if (-not $a) { continue }
        if ($domain -eq $a -or $domain.EndsWith('.' + $a)) { return $false }
    }
    return $true
}

function New-MailboxSign {
    # One takeover sign. Message is plain English and names only the rule and the outside domain.
    param(
        [Parameter(Mandatory = $true)][ValidateSet('ExternalForwarding', 'ExternalRuleForward', 'RuleDeletesMail', 'RuleHidesMail', 'HiddenRule')][string]$Kind,
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
        'Full Access', 'Send As', 'Inbox rules', 'Message trace'.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][ValidateSet('Checked', 'CouldNotCheck')][string]$State,
        [string]$Reason = ''
    )
    return [PSCustomObject]@{ Source = $Source; State = $State; Reason = $Reason }
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
    if ([string]$Message -match $script:MailboxAccessErrorPattern) {
        $roles = if ($script:MailboxSectionRoles.ContainsKey($Source)) { $script:MailboxSectionRoles[$Source] } else { $script:MailboxRecipientRoles }
        $reason = '{0}. Reading this needs {1}.' -f $summary.TrimEnd('.'), $roles
    }
    return (New-MailboxGate -Source $Source -State CouldNotCheck -Reason $reason)
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

function Get-ForwardingSigns {
    <#
    .SYNOPSIS
        An ExternalForwarding sign when the mailbox's own forwarding (ForwardingSmtpAddress)
        sends mail outside the tenant, naming the domain and whether a copy is kept.
    .DESCRIPTION
        ForwardingAddress is a recipient object in the tenant, so it is a fact, not a sign
        (Get-MailboxFactRows shows it).
    #>
    param([object]$Mailbox, [AllowEmptyCollection()][string[]]$AcceptedDomain = @())
    $smtp = [string](Get-MailboxCheckValue $Mailbox 'ForwardingSmtpAddress')
    if (-not (Test-ExternalAddress -Address $smtp -AcceptedDomain $AcceptedDomain)) { return @() }
    $domain = Get-MailboxAddressDomain -Address $smtp
    $keeps = ((Get-MailboxCheckValue $Mailbox 'DeliverToMailboxAndForward') -eq $true)
    $copy = if ($keeps) { 'a copy is kept in the mailbox' } else { 'no copy is kept in the mailbox, so the user never sees it' }
    return @(New-MailboxSign -Kind ExternalForwarding -Domain $domain -KeepsCopy $keeps -Message ('Mail is forwarded to an outside address at {0} ({1}).' -f $domain, $copy))
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
        RedirectTo) with an outside address. RuleHidesMail for a move to one of
        $script:MailboxHidingFolders, or any move plus mark as read. HiddenRule for a rule with
        IsHidden $true other than the built-in junk-mail rule. A rule that is turned off still
        raises its signs, marked as turned off: someone created it.
    #>
    param([AllowEmptyCollection()][object[]]$Rule = @(), [AllowEmptyCollection()][string[]]$AcceptedDomain = @())
    $signs = New-Object System.Collections.Generic.List[object]
    $forwardActions = [ordered]@{ ForwardTo = 'forwards mail'; ForwardAsAttachmentTo = 'forwards mail as an attachment'; RedirectTo = 'redirects mail' }
    foreach ($r in @($Rule)) {
        if ($null -eq $r) { continue }
        $name = [string](Get-MailboxCheckValue $r 'Name')
        $off = if ((Get-MailboxCheckValue $r 'Enabled') -eq $false) { ' (the rule is turned off)' } else { '' }

        foreach ($prop in $forwardActions.Keys) {
            $domains = @(@(Get-MailboxCheckValue $r $prop) | Where-Object { Test-ExternalAddress -Address ([string]$_) -AcceptedDomain $AcceptedDomain } |
                    ForEach-Object { Get-MailboxAddressDomain -Address ([string]$_) } | Select-Object -Unique)
            if ($domains.Count -eq 0) { continue }
            $where = if ($domains.Count -eq 1) { 'an outside address at ' + $domains[0] } else { 'outside addresses at ' + ($domains -join ', ') }
            $signs.Add((New-MailboxSign -Kind ExternalRuleForward -RuleName $name -Domain ($domains -join ', ') -Message ("Inbox rule '{0}' {1} to {2}{3}." -f $name, $forwardActions[$prop], $where, $off)))
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

        if ((Get-MailboxCheckValue $r 'IsHidden') -eq $true -and $name -ne $script:MailboxJunkRuleName) {
            $signs.Add((New-MailboxSign -Kind HiddenRule -RuleName $name -Message ("Inbox rule '{0}' is hidden: Exchange only lists it when asked for hidden rules{1}." -f $name, $off)))
        }
    }
    return $signs.ToArray()
}

function ConvertTo-MailboxRuleList {
    <#
    .SYNOPSIS
        The rule list for the report: every rule from Get-InboxRule -IncludeHidden, each with
        IsHidden $true when the plain Get-InboxRule (without -IncludeHidden) did not return it.
    .DESCRIPTION
        Rules are matched on RuleIdentity, then Identity, then Name. Only the properties the
        check and the report use are kept.
    #>
    param([AllowEmptyCollection()][object[]]$Rule = @(), [AllowEmptyCollection()][object[]]$VisibleRule = @())
    $key = {
        param($r)
        foreach ($n in 'RuleIdentity', 'Identity', 'Name') {
            $v = [string](Get-MailboxCheckValue $r $n)
            if ($v) { return "$n=$v" }
        }
        return ''
    }
    $visible = @{}
    foreach ($v in @($VisibleRule)) { if ($null -ne $v) { $visible[(& $key $v)] = $true } }
    $out = foreach ($r in @($Rule)) {
        if ($null -eq $r) { continue }
        [PSCustomObject]@{
            Name = [string](Get-MailboxCheckValue $r 'Name')
            Enabled = Get-MailboxCheckValue $r 'Enabled'
            Priority = Get-MailboxCheckValue $r 'Priority'
            Identity = [string](Get-MailboxCheckValue $r 'Identity')
            IsHidden = (-not $visible.ContainsKey((& $key $r)))
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
    return ($parts -join '; ')
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
    param([object]$Mailbox)
    $parts = New-Object System.Collections.Generic.List[string]
    $smtp = Get-MailboxAddressFromText -Text ([string](Get-MailboxCheckValue $Mailbox 'ForwardingSmtpAddress'))
    if ($smtp) { $parts.Add("to $smtp") }
    $recipient = [string](Get-MailboxCheckValue $Mailbox 'ForwardingAddress')
    if ($recipient) { $parts.Add("to the recipient '$recipient' in this tenant (if it is a mail contact, the mail still leaves the tenant)") }
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
    param([object]$Mailbox, [object]$Statistics, [object]$ArchiveStatistics)
    $na = 'not available'
    $rows = New-Object System.Collections.Generic.List[object]
    $add = { param($Item, $Value) $rows.Add([PSCustomObject]@{ Item = $Item; Value = $(if (Test-MailboxCheckValue $Value) { [string]$Value } else { $na }) }) }

    & $add 'Mailbox type' (Get-MailboxTypeText -RecipientTypeDetails ([string](Get-MailboxCheckValue $Mailbox 'RecipientTypeDetails')))
    & $add 'Mail forwarding' (Get-MailboxForwardingText -Mailbox $Mailbox)
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
    $couldNot = @($Gate | Where-Object { $null -ne $_ -and $_.State -ne 'Checked' } | ForEach-Object { [PSCustomObject]@{ Source = [string]$_.Source; Reason = [string]$_.Reason } })
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
            $hidden = if ($r.IsHidden) { 'Hidden' } else { '' }
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
        Paste-safe by construction (D-025 and the squad's paste-safe assumption): sign kinds,
        rule names and outside DOMAINS only. No rule conditions, no full forwarding addresses,
        no delegate names and no message-trace rows; those stay in the local HTML and CSV.
        Every section that could not be read goes under Could not check, never Ruled out; a
        check is ruled out only when its sections (and the accepted domains it is judged
        against) were read.
    #>
    param([Parameter(Mandatory = $true)][object]$Result, [string[]]$EvidencePaths = @())
    $items = New-Object System.Collections.Generic.List[object]
    $next = New-Object System.Collections.Generic.List[string]
    $t = $Result.Tenant
    $tenantName = if ($t -and $t.Name) { [string]$t.Name } else { 'not known' }

    if ($Result.Status -eq 'Ok') {
        $a = $Result.Assessment; $f = $Result.Facts
        $headline = @($a.Lines)[0]
        $traceText = if ($f.Trace) { ', message trace for the last {0} days' -f $f.Trace.Days } else { '' }
        $scopeLine = 'Mailbox {0} in {1}: delegates, forwarding, inbox rules (hidden ones included), size, archive and holds{2}.' -f $Result.Identity, $tenantName, $traceText

        foreach ($s in @($a.Signs)) { $items.Add((New-TicketNoteItem -Kind Problem -Text ('{0}: {1}' -f $s.Kind, $s.Message))) }
        foreach ($c in @($a.CouldNotCheck)) { $items.Add((New-TicketNoteItem -Kind NotChecked -Text ('{0}: {1}' -f $c.Source, $c.Reason))) }
        $items.Add((New-TicketNoteItem -Kind NotChecked -Text $script:MailboxRecentChangesLine))

        $checked = @{}
        foreach ($g in @($f.Gates)) { $checked[[string]$g.Source] = ($g.State -eq 'Checked') }
        $kinds = @($a.Signs | ForEach-Object { $_.Kind })
        if ($checked['Mailbox forwarding'] -and $checked['Accepted domains'] -and $kinds -notcontains 'ExternalForwarding') {
            $items.Add((New-TicketNoteItem -Kind Clear -CouldLook $true -Text 'Mailbox forwarding: nothing is forwarded outside the tenant.'))
        }
        $ruleKinds = @('ExternalRuleForward', 'RuleDeletesMail', 'RuleHidesMail', 'HiddenRule')
        if ($checked['Inbox rules'] -and $checked['Accepted domains'] -and @($kinds | Where-Object { $ruleKinds -contains $_ }).Count -eq 0) {
            $n = @($f.Rules).Count
            $items.Add((New-TicketNoteItem -Kind Clear -CouldLook $true -Text ('Inbox rules: {0} rule(s), hidden ones included; none forwards outside, deletes or hides mail.' -f $n)))
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
            if ($Result.Message) { $items.Add((New-TicketNoteItem -Kind Problem -Text $Result.Message)) }
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
