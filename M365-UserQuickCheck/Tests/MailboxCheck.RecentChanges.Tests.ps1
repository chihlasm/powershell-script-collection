<#
    Tests for the recent-changes lookup of Get-M365MailboxCheck.ps1 + MailboxCheck.Core.ps1
    (Pester 5, pwsh). SQ-016: AC1-AC20. Extends SQ-007's mailbox check (MailboxCheck.Tests.ps1).

    Nothing connects to a tenant: Exchange Online, the audit log, the clipboard and the console
    are faked (stub functions with the REAL parameter names, then Mock). Synthetic data only
    (contoso.com, jdoe, 203.0.113.x documentation IPs, made-up GUIDs). "Now" is injected.

    Parameter names, from Microsoft Learn (re-checked by AC20):
      Search-UnifiedAuditLog   https://learn.microsoft.com/powershell/module/exchangepowershell/search-unifiedauditlog
        -StartDate -EndDate -Operations -SessionId -SessionCommand -ResultSize (ReturnLargeSet pages
        up to 50,000 results; ResultSize max 5,000; dates are UTC when given without a zone)
      Get-AdminAuditLogConfig  https://learn.microsoft.com/powershell/module/exchangepowershell/get-adminauditlogconfig
        (-DomainController only; UnifiedAuditLogIngestionEnabled is accurate in Exchange Online PowerShell)
      Get-MailboxAuditBypassAssociation  https://learn.microsoft.com/powershell/module/exchangepowershell/get-mailboxauditbypassassociation
        -Identity -ResultSize -DomainController; output AuditBypassEnabled
      Get-OrganizationConfig   output AuditDisabled (mailbox auditing on by default)
        https://learn.microsoft.com/purview/audit-mailboxes

    PINNED INTERFACE (the implementer must honour these; SQ-007's interface is unchanged):
      Entry Get-M365MailboxCheck.ps1: new parameters -RecentDays ([int], [ValidateRange(1,90)],
        default 14) and -NoRecentChanges ([switch]).
        Invoke-M365MailboxCheck gets -RecentDays, -NoRecentChanges (same names) and already has -Now.
        Search window: StartDate = Now - RecentDays, EndDate = Now, passed as [datetime] with
        Kind Utc (or Local), never Unspecified. -Operations = exactly New-InboxRule, Set-InboxRule,
        UpdateInboxRules, Add-MailboxPermission, Add-RecipientPermission, Set-Mailbox; -SessionCommand
        ReturnLargeSet; -ResultSize 5000; one non-empty -SessionId reused on every page.
        Paging stops on an empty page or when the last record's ResultIndex reaches ResultCount.
        CUT OFF = the last record read has ResultIndex >= 50000 (the ReturnLargeSet cap).
        Collection order: Get-Command Search-UnifiedAuditLog (missing -> role reason, no search),
        Get-AdminAuditLogConfig (UnifiedAuditLogIngestionEnabled -eq $false -> no search),
        Get-OrganizationConfig (AuditDisabled) and Get-MailboxAuditBypassAssociation -Identity
        (AuditBypassEnabled), then the search. -NoRecentChanges calls none of these.
        Facts.RecentChanges = { Changes; Skipped ([int], records with unreadable AuditData);
        CutOff ([bool]); Days } where Changes are the rows below (newest first).
        Gates (New-MailboxGate): Source 'Recent changes' (State CouldNotCheck: Reason names the
        cause, NoteReason is fixed text with no raw error) and Source 'Rule changes made in
        Outlook' (CouldNotCheck, Reason matches 'not being recorded'). Reasons: no cmdlet ->
        'View-Only Audit Logs'; ingestion off -> 'audit logging is turned off in this tenant';
        -NoRecentChanges -> 'skipped (-NoRecentChanges)'; cut off -> 'results were cut off';
        a search that throws -> the error text. Healthy: a 'Recent changes' gate with State Checked.
        The D-008 line "... not checked here, see CIPP's BEC report" is gone from verdict lines.
      Core (MailboxCheck.Core.ps1, pure):
        Get-MailboxIdentifierSet -Mailbox -> [string[]]: Alias, Name, DisplayName, UPN, primary SMTP,
          every EmailAddresses entry without its smtp:/SMTP: prefix, ExchangeGuid,
          ExternalDirectoryObjectId.
        ConvertFrom-AuditRecord -Record <raw Search-UnifiedAuditLog row> -> $null when AuditData is not
          valid JSON, else { Id; Operation; Time ([datetime], UTC, from AuditData.CreationTime);
          UserId; ClientIP (ClientIP or ClientIPAddress); ClientApp (ClientInfoString);
          ObjectId; MailboxOwnerUPN; MailboxGuid; Parameters ([hashtable] Name -> Value string,
          a JSON null value reads as '') }.
        Test-AuditRecordTargetsMailbox -Record <parsed> -IdentifierSet <string[]> -> [bool]
          (exact, case-insensitive; no substring matches).
        Get-RecentChangeSigns -AuditRecord <raw rows> -Mailbox -Rule <current rules> -Now ->
          { Changes; Signs; Skipped }. Dedups on Id, drops records for other mailboxes.
          Change row: { Time; Kind (RecentRuleChange | RecentDelegateChange | RecentForwardingChange
          | ForwardingOff); IsSign; Text; Actor; OwnAccount; ClientIP; ClientApp; RuleName;
          RuleGone; Delegate; Right; Domain; Operation; Id }.
          Sign: the Changes row fields above plus Message (plain English with a relative age such
          as '2 days ago', 'no longer exists' for a gone rule; NEVER the actor address or IP).
          Rule name = the part of ObjectId after '\', else the Name parameter. Delegate = User
          (Add-MailboxPermission) or Trustee (Add-RecipientPermission) or the GrantSendOnBehalfTo
          value. Right = AccessRights, or 'SendAs' / 'SendOnBehalf'. Forwarding domain = the part
          after '@' of ForwardingSmtpAddress. A cleared forwarding value ('', '$null' or JSON
          null) is a ForwardingOff row with no sign. Other Set-Mailbox parameters are ignored.
        ConvertTo-MailboxCheckHtml: a 'Recent changes (last N days)' section; Get-MailboxCheckNote:
          sign kind, UTC date (yyyy-MM-dd), rule name and "by the mailbox's own account" / "by
          another account"; never the actor, the IP or the delegate address.

    Run:  Invoke-Pester .\M365-UserQuickCheck\Tests\MailboxCheck.RecentChanges.Tests.ps1
#>

# Discovery-time: AC20 skips when the module is absent.
$script:HasExo = [bool](Get-Module -ListAvailable -Name ExchangeOnlineManagement)

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:Entry = Join-Path $script:Root 'Get-M365MailboxCheck.ps1'
    $script:Core = Join-Path $script:Root 'MailboxCheck.Core.ps1'
    $script:Now = [datetime]::new(2026, 10, 17, 12, 0, 0, [DateTimeKind]::Utc)
    $script:TakeoverLine = 'Possible account takeover: do NOT reset the password or delete the rule yet. Escalate.'
    $script:CleanLine = 'No takeover signs found in the checks below.'
    $script:ExchangeGuid = '8f1c2a3b-0000-4000-8000-00000000a001'
    $script:EntraId = '4d5e6f70-0000-4000-8000-00000000b002'

    # Stub spec: real parameter names (AC20). Params = value parameters, Switches = [switch].
    $script:StubSpec = [ordered]@{
        'Connect-ExchangeOnline'            = @{ Params = @('UserPrincipalName', 'DelegatedOrganization', 'Organization'); Switches = @('ShowBanner', 'Device', 'DisableWAM') }
        'Disconnect-ExchangeOnline'         = @{ Params = @('ConnectionId', 'ModulePrefix'); Switches = @('Confirm') }
        'Get-ConnectionInformation'         = @{ Params = @('ConnectionId', 'ModulePrefix'); Switches = @() }
        'Get-EXOMailbox'                    = @{ Params = @('Identity', 'Properties', 'PropertySets', 'ResultSize', 'RecipientTypeDetails'); Switches = @() }
        'Get-EXOMailboxStatistics'          = @{ Params = @('Identity', 'Properties'); Switches = @('Archive') }
        'Get-EXORecipient'                  = @{ Params = @('Identity', 'Properties', 'PropertySets', 'ResultSize', 'RecipientTypeDetails'); Switches = @() }
        'Get-EXOMailboxPermission'          = @{ Params = @('Identity', 'User', 'ResultSize'); Switches = @() }
        'Get-EXORecipientPermission'        = @{ Params = @('Identity', 'Trustee', 'AccessRights', 'ResultSize'); Switches = @() }
        'Get-InboxRule'                     = @{ Params = @('Identity', 'Mailbox', 'ResultSize'); Switches = @('IncludeHidden') }
        'Get-MessageTraceV2'                = @{ Params = @('StartDate', 'EndDate', 'SenderAddress', 'RecipientAddress', 'ResultSize', 'Status'); Switches = @() }
        'Get-AcceptedDomain'                = @{ Params = @('Identity', 'ResultSize'); Switches = @() }
        'Get-OrganizationConfig'            = @{ Params = @('Identity'); Switches = @() }
        # SQ-016
        'Search-UnifiedAuditLog'            = @{ Params = @('StartDate', 'EndDate', 'Operations', 'SessionId', 'SessionCommand', 'ResultSize'); Switches = @() }
        'Get-AdminAuditLogConfig'           = @{ Params = @(); Switches = @() }
        'Get-MailboxAuditBypassAssociation' = @{ Params = @('Identity'); Switches = @() }
    }
    # Learn parameter lists for the proxy cmdlets that exist only after a connection (AC20).
    $script:LearnParams = @{
        'Search-UnifiedAuditLog'            = @('EndDate', 'Formatted', 'FreeText', 'HighCompleteness', 'IPAddresses', 'LegacyFlow', 'LongerRetentionEnabled', 'ObjectIds', 'Operations', 'RecordType', 'ResultSize', 'SessionCommand', 'SessionId', 'SiteIds', 'StartDate', 'UserIds')
        'Get-AdminAuditLogConfig'           = @('DomainController')
        'Get-MailboxAuditBypassAssociation' = @('DomainController', 'Identity', 'ResultSize')
        'Get-InboxRule'                     = @('BypassScopeCheck', 'DescriptionTimeFormat', 'DescriptionTimeZone', 'DomainController', 'Identity', 'IncludeHidden', 'Mailbox', 'ResultSize', 'SkipCount', 'SweepRules', 'UseCustomRouting')
        'Get-MessageTraceV2'                = @('EndDate', 'FromIP', 'MessageId', 'MessageTraceId', 'RecipientAddress', 'ResultSize', 'SenderAddress', 'StartDate', 'StartingRecipientAddress', 'Status', 'Subject', 'SubjectFilterType', 'ToIP')
        'Get-AcceptedDomain'                = @('DomainController', 'Identity', 'ResultSize')
        'Get-OrganizationConfig'            = @('ErrorAction', 'Identity', 'DomainController')
    }
    foreach ($name in $script:StubSpec.Keys) {
        $spec = $script:StubSpec[$name]
        $decl = @($spec.Params | ForEach-Object { "`$$_" }) + @($spec.Switches | ForEach-Object { "[switch]`$$_" })
        . ([scriptblock]::Create("function $name { [CmdletBinding()] param($($decl -join ', ')) }"))
    }
    function Set-Clipboard { [CmdletBinding()] param([Parameter(ValueFromPipeline = $true)][AllowEmptyString()][string[]]$Value, [switch]$Append, [switch]$AsHtml) }
    function Invoke-WinFormsClipboard { param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text) }

    # ---- fixtures -------------------------------------------------------------------------
    function New-Mbx {
        param([hashtable]$Set = @{})
        $m = [ordered]@{
            DisplayName = 'Jane Doe'; Alias = 'jdoe'; Name = 'jdoe'
            PrimarySmtpAddress = 'jdoe@contoso.com'; UserPrincipalName = 'jdoe@contoso.com'
            EmailAddresses = @('SMTP:jdoe@contoso.com', 'smtp:j.doe@contoso.com', 'smtp:jdoe@contoso.onmicrosoft.com')
            ExchangeGuid = $script:ExchangeGuid; ExternalDirectoryObjectId = $script:EntraId
            RecipientTypeDetails = 'UserMailbox'; ForwardingSmtpAddress = $null; ForwardingAddress = $null
            DeliverToMailboxAndForward = $false; GrantSendOnBehalfTo = @(); ArchiveStatus = 'None'
            LitigationHoldEnabled = $false; InPlaceHolds = @(); ProhibitSendQuota = '49.5 GB (53,150,220,288 bytes)'
        }
        foreach ($k in $Set.Keys) { $m[$k] = $Set[$k] }
        [PSCustomObject]$m
    }
    function New-Rule {
        param([hashtable]$Set = @{})
        $r = [ordered]@{
            Name = 'Projects'; Enabled = $true; Priority = 1; Identity = '1'; IsHidden = $false
            ForwardTo = $null; ForwardAsAttachmentTo = $null; RedirectTo = $null
            DeleteMessage = $false; SoftDeleteMessage = $false; MoveToFolder = $null; MarkAsRead = $false
            SubjectContainsWords = $null; Description = 'If the message: ...'
        }
        foreach ($k in $Set.Keys) { $r[$k] = $Set[$k] }
        [PSCustomObject]$r
    }
    function New-TraceRow([string]$From, [string]$To, [string]$Subject = 'Hello') {
        [PSCustomObject]@{ Received = [datetime]::UtcNow.AddHours(-3); SenderAddress = $From; RecipientAddress = $To; Subject = $Subject; Status = 'Delivered'; Size = 1200; MessageId = '<' + [guid]::NewGuid() + '@contoso.com>' }
    }

    # One Search-UnifiedAuditLog row. Top = extra/overriding AuditData fields (a $null value
    # removes the field); Param = the cmdlet parameters as Name -> Value.
    function New-AuditRecord {
        param(
            [Parameter(Mandatory = $true)][string]$Operation,
            [string]$Id = ([guid]::NewGuid().ToString()),
            [string]$UserId = 'jdoe@contoso.com',
            [datetime]$Time = ([datetime]::new(2026, 10, 15, 9, 12, 0, [DateTimeKind]::Utc)),
            [hashtable]$Top = @{},
            [System.Collections.IDictionary]$Param = $null,
            [switch]$MailboxAudit,
            [int]$Index = 1, [int]$Count = 1
        )
        $d = [ordered]@{
            CreationTime = $Time.ToString('s'); Id = $Id; Operation = $Operation; OrganizationId = '11111111-2222-3333-4444-555555555555'
            RecordType = $(if ($MailboxAudit) { 2 } else { 1 }); ResultStatus = 'True'; UserKey = 'S-1-0'; UserType = 0; Version = 1
            Workload = 'Exchange'; UserId = $UserId; ObjectId = 'other-object-id'
        }
        if ($MailboxAudit) {
            $d['ClientIPAddress'] = '203.0.113.7'; $d['ClientInfoString'] = 'Client=OWA;Action=ViaProxy'
        } else {
            $d['ClientIP'] = '203.0.113.7'
        }
        foreach ($k in $Top.Keys) { if ($null -eq $Top[$k]) { $d.Remove($k) } else { $d[$k] = $Top[$k] } }
        if ($Param) { $d['Parameters'] = @($Param.Keys | ForEach-Object { [ordered]@{ Name = $_; Value = $Param[$_] } }) }
        [PSCustomObject]@{
            RecordType = $(if ($MailboxAudit) { 'ExchangeItem' } else { 'ExchangeAdmin' }); CreationDate = $Time; UserIds = $UserId
            Operations = $Operation; AuditData = ($d | ConvertTo-Json -Depth 6 -Compress); ResultIndex = $Index; ResultCount = $Count; Identity = $Id
        }
    }
    function New-RuleRecord {
        param([string]$RuleName = 'xx', [string]$Operation = 'New-InboxRule', [string]$UserId = 'jdoe@contoso.com',
            [datetime]$Time = ([datetime]::new(2026, 10, 15, 9, 12, 0, [DateTimeKind]::Utc)), [string]$Id = ([guid]::NewGuid().ToString()), [int]$Index = 1, [int]$Count = 1)
        New-AuditRecord -Operation $Operation -Id $Id -UserId $UserId -Time $Time -Top @{ ObjectId = "jdoe\$RuleName" } -Param ([ordered]@{ Name = $RuleName; ForwardTo = 'x@gmail.com' }) -Index $Index -Count $Count
    }
    function Get-ChangeSigns {
        param([object[]]$Record, [object]$Mailbox = (New-Mbx), [object[]]$Rule = @((New-Rule)))
        Get-RecentChangeSigns -AuditRecord $Record -Mailbox $Mailbox -Rule $Rule -Now $script:Now
    }

    # ---- end-to-end harness ----------------------------------------------------------------
    function New-Scenario {
        param([hashtable]$Override = @{})
        $s = @{
            Session = $false
            Tenant = 'contoso.onmicrosoft.com'; Me = 'admin@contoso.onmicrosoft.com'; TenantGuid = '11111111-2222-3333-4444-555555555555'
            Accepted = @(
                [PSCustomObject]@{ DomainName = 'contoso.com'; Name = 'contoso.com'; InitialDomain = $false; Default = $true; DomainType = 'Authoritative' },
                [PSCustomObject]@{ DomainName = 'contoso.onmicrosoft.com'; Name = 'contoso.onmicrosoft.com'; InitialDomain = $true; Default = $false; DomainType = 'Authoritative' })
            Mailbox = (New-Mbx)
            MbxPerms = @([PSCustomObject]@{ User = 'NT AUTHORITY\SELF'; AccessRights = @('FullAccess'); IsInherited = $false; Deny = $false })
            RecipPerms = @([PSCustomObject]@{ Trustee = 'NT AUTHORITY\SELF'; AccessRights = @('SendAs'); AccessControlType = 'Allow'; IsInherited = $false })
            Rules = @((New-Rule))
            Stats = [PSCustomObject]@{ TotalItemSize = '1.5 GB (1,610,612,736 bytes)'; ItemCount = 1200 }
            Sent = @((New-TraceRow 'jdoe@contoso.com' 'vendor@fabrikam.com' 'Wire details'))
            Received = @((New-TraceRow 'vendor@fabrikam.com' 'jdoe@contoso.com' 'Re: Wire details'))
            # SQ-016
            UalEnabled = $true; OrgAuditDisabled = $false; Bypass = $false; BypassThrow = $null
            Pages = @(); SearchThrow = $null
        }
        foreach ($k in $Override.Keys) { $s[$k] = $Override[$k] }
        $script:Scn = $s
        $script:Connected = [bool]$s.Session
    }
    # Runs Invoke-M365MailboxCheck directly (so -Now is injected). Also builds the ticket note.
    function Invoke-Check {
        param([hashtable]$Extra = @{}, [string]$SaveTo)
        . $script:Entry -LoadFunctionsOnly
        $script:Events = New-Object System.Collections.Generic.List[string]
        $script:SearchCalls = New-Object System.Collections.Generic.List[object]
        $splat = @{
            Identity = 'jdoe@contoso.com'; Quiet = $true; Now = $script:Now
            Connection = [PSCustomObject]@{ TenantID = $script:Scn.TenantGuid; UserPrincipalName = $script:Scn.Me; State = 'Connected' }
        }
        foreach ($k in $Extra.Keys) { $splat[$k] = $Extra[$k] }
        if ($splat.ContainsKey('Quiet') -and -not $splat['Quiet']) { $splat.Remove('Quiet') }
        $r = Invoke-M365MailboxCheck @splat
        if ($r.Status -eq 'Ok') {
            if ($SaveTo) { $r.Files = Save-M365MailboxCheckReport -Result $r -OutputPath $SaveTo }
            $r.TicketNote = Get-MailboxCheckNote -Result $r
        }
        return $r
    }
    function Invoke-Entry {
        param([hashtable]$Extra = @{})
        $script:Events = New-Object System.Collections.Generic.List[string]
        $script:SearchCalls = New-Object System.Collections.Generic.List[object]
        $splat = @{ Identity = 'jdoe@contoso.com'; NoClipboard = $true; PassThru = $true }
        foreach ($k in $Extra.Keys) { $splat[$k] = $Extra[$k] }
        $script:LastError = $null
        try { $out = @(. $script:Entry @splat) } catch { $script:LastError = $_; $out = @() }
        if ($out.Count -gt 0) { return $out[-1] }
        return $null
    }
    function Get-Source($Result, [string]$Source) { @($Result.Assessment.CouldNotCheck | Where-Object { $_.Source -eq $Source }) }
    function Get-Page($Records, [int]$Start = 1, [int]$Count = 0) {
        $i = $Start
        $recs = @($Records)
        if ($Count -eq 0) { $Count = $recs.Count + $Start - 1 }
        foreach ($r in $recs) { $r.ResultIndex = $i; $r.ResultCount = $Count; $i++ }
        , $recs
    }
}

Describe 'recent changes: pure functions' {
    BeforeAll { . $script:Core }

    Context 'AC3 matching records to the mailbox' {
        It 'AC3_IdentifierSetHoldsEveryFormOfTheMailbox' {
            $set = @(Get-MailboxIdentifierSet -Mailbox (New-Mbx))
            foreach ($v in 'jdoe', 'jdoe@contoso.com', 'j.doe@contoso.com', 'Jane Doe', $script:ExchangeGuid, $script:EntraId) {
                @($set | Where-Object { $_ -ieq $v }).Count | Should -BeGreaterThan 0 -Because "'$v' must be in the identifier set"
            }
        }

        It 'AC3_RecordsAreKeptOnlyWhenTheirTargetIsAnIdentifier: <Form>' -ForEach @(
            @{ Form = 'ObjectId alias'; Op = 'Set-Mailbox'; Top = @{ ObjectId = 'jdoe' }; Param = $null; Mbx = $false; Match = $true }
            @{ Form = 'ObjectId alias, other case'; Op = 'Set-Mailbox'; Top = @{ ObjectId = 'JDoe' }; Param = $null; Mbx = $false; Match = $true }
            @{ Form = 'ObjectId UPN, mixed case'; Op = 'Set-Mailbox'; Top = @{ ObjectId = 'JDoe@Contoso.com' }; Param = $null; Mbx = $false; Match = $true }
            @{ Form = 'ObjectId secondary proxy'; Op = 'Set-Mailbox'; Top = @{ ObjectId = 'j.doe@contoso.com' }; Param = $null; Mbx = $false; Match = $true }
            @{ Form = 'ObjectId display name'; Op = 'Set-Mailbox'; Top = @{ ObjectId = 'Jane Doe' }; Param = $null; Mbx = $false; Match = $true }
            @{ Form = 'ObjectId ExchangeGuid'; Op = 'Set-Mailbox'; Top = @{ ObjectId = '8f1c2a3b-0000-4000-8000-00000000a001' }; Param = $null; Mbx = $false; Match = $true }
            @{ Form = 'ObjectId ExternalDirectoryObjectId'; Op = 'Set-Mailbox'; Top = @{ ObjectId = '4d5e6f70-0000-4000-8000-00000000b002' }; Param = $null; Mbx = $false; Match = $true }
            @{ Form = 'Identity parameter'; Op = 'Add-MailboxPermission'; Top = @{}; Param = [ordered]@{ Identity = 'jdoe@contoso.com'; User = 'h@contoso.com' }; Mbx = $false; Match = $true }
            @{ Form = 'Mailbox parameter'; Op = 'New-InboxRule'; Top = @{ ObjectId = 'xx' }; Param = [ordered]@{ Mailbox = 'JDOE'; Name = 'xx' }; Mbx = $false; Match = $true }
            @{ Form = 'rule ObjectId mailbox\Rule'; Op = 'New-InboxRule'; Top = @{ ObjectId = 'jdoe\RuleName' }; Param = $null; Mbx = $false; Match = $true }
            @{ Form = 'MailboxOwnerUPN'; Op = 'UpdateInboxRules'; Top = @{ MailboxOwnerUPN = 'JDOE@contoso.com' }; Param = $null; Mbx = $true; Match = $true }
            @{ Form = 'MailboxGuid'; Op = 'UpdateInboxRules'; Top = @{ MailboxGuid = '8F1C2A3B-0000-4000-8000-00000000A001' }; Param = $null; Mbx = $true; Match = $true }
            @{ Form = 'other mailbox ObjectId'; Op = 'Set-Mailbox'; Top = @{ ObjectId = 'asmith@contoso.com' }; Param = $null; Mbx = $false; Match = $false }
            @{ Form = 'other mailbox rule'; Op = 'New-InboxRule'; Top = @{ ObjectId = 'asmith\RuleName' }; Param = $null; Mbx = $false; Match = $false }
            @{ Form = 'other mailbox Identity parameter'; Op = 'Add-MailboxPermission'; Top = @{}; Param = [ordered]@{ Identity = 'asmith@contoso.com' }; Mbx = $false; Match = $false }
            @{ Form = 'other MailboxOwnerUPN'; Op = 'UpdateInboxRules'; Top = @{ MailboxOwnerUPN = 'asmith@contoso.com' }; Param = $null; Mbx = $true; Match = $false }
            @{ Form = 'look-alike (no substring match)'; Op = 'Set-Mailbox'; Top = @{ ObjectId = 'xjdoe@contoso.com' }; Param = $null; Mbx = $false; Match = $false }
        ) {
            $raw = New-AuditRecord -Operation $Op -Top $Top -Param $Param -MailboxAudit:$Mbx
            $rec = ConvertFrom-AuditRecord -Record $raw
            $rec | Should -Not -BeNullOrEmpty
            $set = @(Get-MailboxIdentifierSet -Mailbox (New-Mbx))
            (Test-AuditRecordTargetsMailbox -Record $rec -IdentifierSet $set) | Should -Be $Match
        }
    }

    Context 'AC4 rule signs' {
        It 'AC4_NewInboxRuleThatNoLongerExistsIsASignMarkedGone; Set-InboxRule on an existing rule is a sign without the mark' {
            $new = New-RuleRecord -RuleName 'xx' -Operation 'New-InboxRule'
            $res = Get-ChangeSigns -Record @($new) -Rule @((New-Rule @{ Name = 'Projects' }))
            @($res.Signs).Count | Should -Be 1
            $s = @($res.Signs)[0]
            $s.Kind | Should -Be 'RecentRuleChange'
            $s.RuleName | Should -Be 'xx'
            $s.Actor | Should -Be 'jdoe@contoso.com'
            ([datetime]$s.Time).ToUniversalTime() | Should -Be ([datetime]::new(2026, 10, 15, 9, 12, 0, [DateTimeKind]::Utc))
            $s.RuleGone | Should -BeTrue
            $s.Message | Should -Match 'no longer exists'

            $set = New-RuleRecord -RuleName 'Projects' -Operation 'Set-InboxRule'
            $res2 = Get-ChangeSigns -Record @($set) -Rule @((New-Rule @{ Name = 'Projects' }))
            @($res2.Signs).Count | Should -Be 1
            $s2 = @($res2.Signs)[0]
            $s2.Kind | Should -Be 'RecentRuleChange'
            $s2.RuleName | Should -Be 'Projects'
            $s2.RuleGone | Should -BeFalse
            $s2.Message | Should -Not -Match 'no longer exists'
        }

        It 'AC4_SignMessageNeverCarriesTheActorOrTheIp (it goes into the ticket note)' {
            $res = Get-ChangeSigns -Record @((New-RuleRecord -RuleName 'xx' -UserId 'admin@contoso.com'))
            $m = @($res.Signs)[0].Message
            $m | Should -Not -Match 'admin@contoso\.com'
            $m | Should -Not -Match '203\.0\.113\.7'
        }
    }

    Context 'AC5 mailbox-audit rule updates' {
        It 'AC5_UpdateInboxRulesIsASignWithTimeActorIpAndApp' {
            $raw = New-AuditRecord -Operation 'UpdateInboxRules' -MailboxAudit -UserId 'jdoe@contoso.com' `
                -Top @{ MailboxOwnerUPN = 'jdoe@contoso.com'; MailboxGuid = $script:ExchangeGuid; ObjectId = $null }
            $res = Get-ChangeSigns -Record @($raw)
            @($res.Signs).Count | Should -Be 1
            $s = @($res.Signs)[0]
            $s.Kind | Should -Be 'RecentRuleChange'
            $s.Actor | Should -Be 'jdoe@contoso.com'
            ([datetime]$s.Time).ToUniversalTime() | Should -Be ([datetime]::new(2026, 10, 15, 9, 12, 0, [DateTimeKind]::Utc))
            $row = @($res.Changes)[0]
            $row.ClientIP | Should -Be '203.0.113.7'
            $row.ClientApp | Should -Match 'OWA'
        }
    }

    Context 'AC6 delegates' {
        It 'AC6_FullAccessAndSendAsGrantsAreTwoDelegateSigns' {
            $fa = New-AuditRecord -Operation 'Add-MailboxPermission' -UserId 'admin@contoso.com' -Top @{ ObjectId = 'jdoe' } `
                -Param ([ordered]@{ Identity = 'jdoe'; User = 'helpdesk@contoso.com'; AccessRights = 'FullAccess' }) `
                -Time ([datetime]::new(2026, 10, 13, 11, 2, 0, [DateTimeKind]::Utc))
            $sa = New-AuditRecord -Operation 'Add-RecipientPermission' -UserId 'admin@contoso.com' -Top @{ ObjectId = 'jdoe' } `
                -Param ([ordered]@{ Identity = 'jdoe'; Trustee = 'ops@contoso.com'; AccessRights = 'SendAs' }) `
                -Time ([datetime]::new(2026, 10, 14, 8, 0, 0, [DateTimeKind]::Utc))
            $res = Get-ChangeSigns -Record @($fa, $sa)
            $signs = @($res.Signs)
            $signs.Count | Should -Be 2
            @($signs | Where-Object { $_.Kind -ne 'RecentDelegateChange' }).Count | Should -Be 0
            $f = @($signs | Where-Object { $_.Delegate -eq 'helpdesk@contoso.com' })
            $f.Count | Should -Be 1
            $f[0].Right | Should -Be 'FullAccess'
            $f[0].Message | Should -Match 'helpdesk@contoso\.com'
            $f[0].Message | Should -Match 'Full Access|FullAccess'
            $a = @($signs | Where-Object { $_.Delegate -eq 'ops@contoso.com' })
            $a.Count | Should -Be 1
            $a[0].Right | Should -Be 'SendAs'
            $a[0].Message | Should -Match 'Send As|SendAs'
        }
    }

    Context 'AC7 Set-Mailbox' {
        It 'AC7_SetMailboxIsJudgedByWhatItSets: <Case>' -ForEach @(
            @{ Case = 'ForwardingSmtpAddress set'; Param = [ordered]@{ ForwardingSmtpAddress = 'smtp:x@gmail.com' }; Signs = 1; Kind = 'RecentForwardingChange'; Domain = 'gmail.com'; Rows = 1; Off = $false }
            @{ Case = 'ForwardingAddress set'; Param = [ordered]@{ ForwardingAddress = 'Fred Contact' }; Signs = 1; Kind = 'RecentForwardingChange'; Domain = $null; Rows = 1; Off = $false }
            @{ Case = 'GrantSendOnBehalfTo set'; Param = [ordered]@{ GrantSendOnBehalfTo = 'helpdesk' }; Signs = 1; Kind = 'RecentDelegateChange'; Domain = $null; Rows = 1; Off = $false }
            @{ Case = 'forwarding cleared (empty string)'; Param = [ordered]@{ ForwardingSmtpAddress = '' }; Signs = 0; Kind = $null; Domain = $null; Rows = 1; Off = $true }
            @{ Case = 'forwarding cleared ($null text)'; Param = [ordered]@{ ForwardingSmtpAddress = '$null' }; Signs = 0; Kind = $null; Domain = $null; Rows = 1; Off = $true }
            @{ Case = 'forwarding cleared (JSON null)'; Param = [ordered]@{ ForwardingAddress = $null }; Signs = 0; Kind = $null; Domain = $null; Rows = 1; Off = $true }
            @{ Case = 'only a quota changed'; Param = [ordered]@{ ProhibitSendQuota = '50GB' }; Signs = 0; Kind = $null; Domain = $null; Rows = 0; Off = $false }
            @{ Case = 'forwarding and quota together'; Param = [ordered]@{ ForwardingSmtpAddress = 'smtp:x@gmail.com'; ProhibitSendQuota = '50GB' }; Signs = 1; Kind = 'RecentForwardingChange'; Domain = 'gmail.com'; Rows = 1; Off = $false }
        ) {
            $raw = New-AuditRecord -Operation 'Set-Mailbox' -UserId 'admin@contoso.com' -Top @{ ObjectId = 'jdoe' } -Param $Param
            $res = Get-ChangeSigns -Record @($raw)
            @($res.Signs).Count | Should -Be $Signs
            @($res.Changes).Count | Should -Be $Rows
            if ($Signs -gt 0) {
                @($res.Signs)[0].Kind | Should -Be $Kind
                if ($Domain) {
                    @($res.Signs)[0].Domain | Should -Be $Domain
                    @($res.Signs)[0].Message | Should -Match ([regex]::Escape($Domain))
                }
            }
            if ($Off) {
                $row = @($res.Changes)[0]
                $row.Kind | Should -Be 'ForwardingOff'
                $row.IsSign | Should -BeFalse
                $row.Text | Should -Match 'Forwarding turned off'
            }
        }
    }

    Context 'AC15 duplicates and edge cases' {
        It 'AC15_TheSameAuditIdIsListedOnceAndRaisesOneSign' {
            $a = New-RuleRecord -Id 'rec-1' -Index 1 -Count 2
            $b = New-RuleRecord -Id 'rec-1' -Index 2 -Count 2
            $res = Get-ChangeSigns -Record @($a, $b)
            @($res.Changes).Count | Should -Be 1
            @($res.Signs).Count | Should -Be 1
        }

        It 'Edge_AuditDataThatIsNotJsonIsSkippedAndCounted' {
            $bad = [PSCustomObject]@{ RecordType = 'ExchangeAdmin'; CreationDate = $script:Now; UserIds = 'x'; Operations = 'Set-Mailbox'; AuditData = '{not json'; ResultIndex = 1; ResultCount = 2; Identity = 'bad' }
            (ConvertFrom-AuditRecord -Record $bad) | Should -BeNullOrEmpty
            $res = Get-ChangeSigns -Record @($bad, (New-RuleRecord))
            $res.Skipped | Should -Be 1
            @($res.Signs).Count | Should -Be 1
        }

        It 'Edge_ASingleRecordAndMissingParametersAreHandled' {
            $res = Get-ChangeSigns -Record (New-RuleRecord)
            @($res.Signs).Count | Should -Be 1
            $noParams = New-AuditRecord -Operation 'Set-Mailbox' -Top @{ ObjectId = 'jdoe' }
            $res2 = Get-ChangeSigns -Record @($noParams)
            @($res2.Signs).Count | Should -Be 0
            @($res2.Changes).Count | Should -Be 0
        }

        It 'Edge_ChangesAreNewestFirst and an unmatched mailbox is dropped' {
            $old = New-RuleRecord -RuleName 'old' -Time ([datetime]::new(2026, 10, 10, 8, 0, 0, [DateTimeKind]::Utc))
            $new = New-RuleRecord -RuleName 'new' -Time ([datetime]::new(2026, 10, 16, 8, 0, 0, [DateTimeKind]::Utc))
            $other = New-AuditRecord -Operation 'Set-InboxRule' -Top @{ ObjectId = 'asmith\zz' } -Param ([ordered]@{ Name = 'zz' })
            $res = Get-ChangeSigns -Record @($old, $new, $other)
            @($res.Changes).Count | Should -Be 2
            @($res.Changes)[0].RuleName | Should -Be 'new'
            @($res.Changes)[1].RuleName | Should -Be 'old'
        }
    }

    Context 'Review fixes (SQ-016 fix round 1): Send on Behalf removals and neutral note wording' {
        It 'Fix_SendOnBehalfOnlyRemovedIsAFactNotASign: <Case>' -ForEach @(
            @{ Case = 'remove= only'; Value = 'remove=helpdesk' }
            @{ Case = 'remove= in a hashtable'; Value = '@{remove="helpdesk"}' }
            @{ Case = 'Remove= mixed case'; Value = '@{Remove=helpdesk@contoso.com}' }
        ) {
            $raw = New-AuditRecord -Operation 'Set-Mailbox' -UserId 'admin@contoso.com' -Top @{ ObjectId = 'jdoe' } -Param ([ordered]@{ GrantSendOnBehalfTo = $Value })
            $res = Get-ChangeSigns -Record @($raw)
            @($res.Signs).Count | Should -Be 0 -Because 'taking Send on Behalf away is not a takeover sign'
            @($res.Changes).Count | Should -Be 1 -Because 'it is still listed so a tech can see it'
            $row = @($res.Changes)[0]
            $row.IsSign | Should -BeFalse
            $row.Text | Should -Match 'Send on Behalf'
            $row.Text | Should -Match 'removed'
        }

        It 'Fix_SendOnBehalfAddedInAHashtableIsASignNamingTheDelegate' {
            $raw = New-AuditRecord -Operation 'Set-Mailbox' -UserId 'admin@contoso.com' -Top @{ ObjectId = 'jdoe' } -Param ([ordered]@{ GrantSendOnBehalfTo = '@{add="helpdesk"; remove="old"}' })
            $res = Get-ChangeSigns -Record @($raw)
            @($res.Signs).Count | Should -Be 1
            @($res.Signs)[0].Kind | Should -Be 'RecentDelegateChange'
            @($res.Signs)[0].Delegate | Should -Be 'helpdesk'
        }

        It 'Fix_ForwardingAddressNoteTextIsNeutral (does not claim the recipient is in this tenant)' {
            $raw = New-AuditRecord -Operation 'Set-Mailbox' -UserId 'admin@contoso.com' -Top @{ ObjectId = 'jdoe' } -Param ([ordered]@{ ForwardingAddress = 'Fred Contact' })
            $res = Get-ChangeSigns -Record @($raw)
            $note = @($res.Signs)[0].NoteText
            $note | Should -Match ([regex]::Escape('forwarding turned on to a recipient object'))
            $note | Should -Match ([regex]::Escape('(see the report)'))
            $note | Should -Not -Match 'in this tenant'
            $note | Should -Not -Match 'Fred Contact' -Because 'the note never names a forwarding recipient'
        }
    }
}

Describe 'recent changes: running the check' {
    BeforeAll { . $script:Core }
    BeforeEach {
        New-Scenario
        $script:Events = New-Object System.Collections.Generic.List[string]
        $script:SearchCalls = New-Object System.Collections.Generic.List[object]
        $script:AuditConfigCalls = 0
        Mock Import-Module { }
        Mock Connect-ExchangeOnline { $script:Events.Add('CONNECT'); $script:Connected = $true }
        Mock Disconnect-ExchangeOnline { $script:Events.Add('DISCONNECT'); $script:Connected = $false }
        Mock Get-ConnectionInformation {
            if ($script:Connected) { [PSCustomObject]@{ State = 'Connected'; Name = 'ExchangeOnline_1'; UserPrincipalName = $script:Scn.Me; TenantID = $script:Scn.TenantGuid } }
        }
        Mock Get-OrganizationConfig { [PSCustomObject]@{ Name = $script:Scn.Tenant; Identity = $script:Scn.Tenant; AuditDisabled = $script:Scn.OrgAuditDisabled } }
        Mock Get-AcceptedDomain { $script:Scn.Accepted }
        Mock Get-EXOMailbox { $script:Scn.Mailbox }
        Mock Get-EXOMailboxStatistics { $script:Scn.Stats }
        Mock Get-EXORecipient { $null }
        Mock Get-EXOMailboxPermission { $script:Scn.MbxPerms }
        Mock Get-EXORecipientPermission { $script:Scn.RecipPerms }
        Mock Get-InboxRule { $script:Scn.Rules }
        Mock Get-MessageTraceV2 { if ($SenderAddress) { $script:Scn.Sent } else { $script:Scn.Received } }
        Mock Set-Clipboard { }
        Mock Invoke-WinFormsClipboard { }
        Mock Write-Host { $script:Events.Add('HOST:' + ($Object -join ' ')) }
        Mock Get-AdminAuditLogConfig {
            $script:AuditConfigCalls++
            [PSCustomObject]@{ UnifiedAuditLogIngestionEnabled = $script:Scn.UalEnabled }
        }
        Mock Get-MailboxAuditBypassAssociation {
            if ($script:Scn.BypassThrow) { throw $script:Scn.BypassThrow }
            [PSCustomObject]@{ Name = 'jdoe'; AuditBypassEnabled = $script:Scn.Bypass }
        }
        Mock Search-UnifiedAuditLog {
            $script:SearchCalls.Add(@{ StartDate = $StartDate; EndDate = $EndDate; Operations = @($Operations); SessionCommand = $SessionCommand; ResultSize = $ResultSize; SessionId = $SessionId })
            if ($script:Scn.SearchThrow) { throw $script:Scn.SearchThrow }
            $i = $script:SearchCalls.Count - 1
            $pages = @($script:Scn.Pages)
            if ($i -lt $pages.Count) { , @($pages[$i]) }
        }
    }

    Context 'AC1 parameters' {
        It 'AC1_RecentDaysDefaultsTo14AndIsValidatedFrom1To90' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Entry, [ref]$null, [ref]$null)
            $p = @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'RecentDays' })
            $p.Count | Should -Be 1 -Because '-RecentDays must be a parameter of the entry script'
            $p[0].DefaultValue.Extent.Text | Should -Be '14'
            $range = @($p[0].Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateRange' })
            $range.Count | Should -Be 1
            @($range[0].PositionalArguments | ForEach-Object { $_.Extent.Text }) | Should -Be @('1', '90')
            foreach ($bad in 0, 91) {
                $script:LastError = $null
                try { $null = @(. $script:Entry -Identity 'jdoe@contoso.com' -RecentDays $bad -NoClipboard -PassThru) } catch { $script:LastError = $_ }
                "$($script:LastError)" | Should -Match 'RecentDays' -Because "-RecentDays $bad must be rejected"
                "$($script:LastError)" | Should -Match 'range|1 and 90|Cannot validate' -Because "-RecentDays $bad must fail validation, not binding"
            }
        }
    }

    Context 'AC2 the audit search' {
        It 'AC2_SearchWindowOperationsAndPagingAreExact: -RecentDays 14, Now = 2026-10-17 12:00' {
            New-Scenario @{ Pages = @(
                    (Get-Page @((New-RuleRecord -Id 'a'), (New-RuleRecord -Id 'b')) -Count 3),
                    (Get-Page @((New-RuleRecord -Id 'c')) -Start 3 -Count 3),
                    (Get-Page @((New-RuleRecord -Id 'd')) -Start 4 -Count 4)) }
            $null = Invoke-Check @{ RecentDays = 14 }
            $script:SearchCalls.Count | Should -Be 2 -Because 'paging stops when the last ResultIndex reaches ResultCount'
            foreach ($c in $script:SearchCalls) {
                ([datetime]$c.StartDate).Kind | Should -Not -Be ([DateTimeKind]::Unspecified)
                ([datetime]$c.EndDate).Kind | Should -Not -Be ([DateTimeKind]::Unspecified)
                ([datetime]$c.StartDate).ToUniversalTime() | Should -Be ([datetime]::new(2026, 10, 3, 12, 0, 0, [DateTimeKind]::Utc))
                ([datetime]$c.EndDate).ToUniversalTime() | Should -Be ([datetime]::new(2026, 10, 17, 12, 0, 0, [DateTimeKind]::Utc))
                (@($c.Operations) | Sort-Object) | Should -Be (@('Add-MailboxPermission', 'Add-RecipientPermission', 'New-InboxRule', 'Set-InboxRule', 'Set-Mailbox', 'UpdateInboxRules') | Sort-Object)
                $c.SessionCommand | Should -Be 'ReturnLargeSet'
                $c.ResultSize | Should -Be 5000
            }
            $ids = @($script:SearchCalls | ForEach-Object { [string]$_.SessionId } | Select-Object -Unique)
            $ids.Count | Should -Be 1
            $ids[0] | Should -Not -BeNullOrEmpty
        }

        It 'AC2_PagingStopsOnAnEmptyPage; a page smaller than ResultSize does not stop it' {
            New-Scenario @{ Pages = @(
                    (Get-Page @((New-RuleRecord -Id 'a')) -Count 5),
                    (Get-Page @((New-RuleRecord -Id 'b')) -Start 2 -Count 5),
                    @()) }
            $null = Invoke-Check
            $script:SearchCalls.Count | Should -Be 3
        }

        It 'AC2_ResultCountZeroOnTheFirstPageIsOneCall' {
            New-Scenario @{ Pages = @(, @()) }
            $r = Invoke-Check
            $script:SearchCalls.Count | Should -Be 1
            (Get-Source $r 'Recent changes').Count | Should -Be 0
        }

        It 'AC2_TheEntryScriptPassesRecentDaysOn: -RecentDays 30' {
            $null = Invoke-Entry @{ RecentDays = 30 }
            $script:LastError | Should -BeNullOrEmpty
            $script:SearchCalls.Count | Should -BeGreaterThan 0
            $c = $script:SearchCalls[0]
            (([datetime]$c.EndDate) - ([datetime]$c.StartDate)).TotalDays | Should -BeGreaterThan 29.99
            (([datetime]$c.EndDate) - ([datetime]$c.StartDate)).TotalDays | Should -BeLessThan 30.01
        }

        It 'AC2_ConsoleSaysTheSearchCanTakeAMinute (not quiet)' {
            $null = Invoke-Check @{ Quiet = $false }
            ($script:Events -join "`n") | Should -Match ([regex]::Escape('[INFO] Searching the audit log for the last 14 days (this can take a minute)...'))
        }
    }

    Context 'AC8 to AC12, AC14 cannot-check states' {
        It 'AC8_NoSearchCmdletMeansTheAuditRoleIsMissing: PARTLY CHECKED, naming View-Only Audit Logs, exit 2' {
            Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Search-UnifiedAuditLog' }
            $r = Invoke-Check
            $c = Get-Source $r 'Recent changes'
            $c.Count | Should -Be 1
            $c[0].Reason | Should -Match 'View-Only Audit Logs'
            @($r.Assessment.Lines)[0] | Should -Match '^PARTLY CHECKED'
            $r.ExitCode | Should -Be 2
            Should -Invoke Search-UnifiedAuditLog -Times 0 -Exactly
        }

        It 'AC9_AuditingTurnedOffInTheTenant: no search, audit logging is turned off in this tenant' {
            New-Scenario @{ UalEnabled = $false }
            $r = Invoke-Check
            Should -Invoke Search-UnifiedAuditLog -Times 0 -Exactly
            $c = Get-Source $r 'Recent changes'
            $c.Count | Should -Be 1
            $c[0].Reason | Should -Match 'audit logging is turned off in this tenant'
            $r.ExitCode | Should -Be 2
        }

        It 'AC10_MailboxAuditingOffStillReadsAdminRecords: <Cause>' -ForEach @(
            @{ Cause = 'organization AuditDisabled'; Over = @{ OrgAuditDisabled = $true } }
            @{ Cause = 'mailbox audit bypass'; Over = @{ Bypass = $true } }
        ) {
            $adminRec = New-AuditRecord -Operation 'Set-Mailbox' -UserId 'admin@contoso.com' -Top @{ ObjectId = 'jdoe' } -Param ([ordered]@{ ForwardingSmtpAddress = 'smtp:x@gmail.com' })
            # No sign: only the (non-sign) clearing of forwarding is in the log.
            $clearRec = New-AuditRecord -Operation 'Set-Mailbox' -UserId 'admin@contoso.com' -Top @{ ObjectId = 'jdoe' } -Param ([ordered]@{ ForwardingSmtpAddress = '' })
            $over = $Over.Clone(); $over['Pages'] = @(, (Get-Page @($clearRec)))
            New-Scenario $over
            $r = Invoke-Check
            $script:SearchCalls.Count | Should -BeGreaterThan 0 -Because 'admin-cmdlet records are still read'
            @($r.Facts.RecentChanges.Changes).Count | Should -Be 1 -Because 'admin-cmdlet records are still evaluated'
            (Get-Source $r 'Rule changes made in Outlook').Count | Should -Be 1
            (Get-Source $r 'Rule changes made in Outlook')[0].Reason | Should -Match 'not being recorded'
            (Get-Source $r 'Recent changes').Count | Should -Be 0
            @($r.Assessment.Lines)[0] | Should -Match '^PARTLY CHECKED'
            $r.ExitCode | Should -Be 2

            # With a sign the takeover line wins, and the Outlook gap is still listed.
            $over['Pages'] = @(, (Get-Page @($adminRec)))
            New-Scenario $over
            $r2 = Invoke-Check
            @($r2.Assessment.Lines)[0] | Should -BeExactly $script:TakeoverLine
            (Get-Source $r2 'Rule changes made in Outlook').Count | Should -Be 1
            $r2.ExitCode | Should -Be 1
        }

        It 'AC10_AFailedBypassLookupDoesNotFailTheSection' {
            New-Scenario @{ BypassThrow = 'Access is denied'; Pages = @(, @()) }
            $r = Invoke-Check
            $script:SearchCalls.Count | Should -BeGreaterThan 0
            (Get-Source $r 'Recent changes').Count | Should -Be 0
        }

        It 'AC11_ASearchThatThrowsIsCouldNotCheckAndTheRestStillRuns' {
            New-Scenario @{ SearchThrow = 'The search timed out after 600 seconds.' }
            $r = Invoke-Check
            $r.Status | Should -Be 'Ok'
            $c = Get-Source $r 'Recent changes'
            $c.Count | Should -Be 1
            $c[0].Reason | Should -Match 'search timed out after 600 seconds'
            $c[0].NoteReason | Should -Not -BeNullOrEmpty
            $c[0].NoteReason | Should -Not -Match 'timed out after 600'
            @($r.Facts.FactRows).Count | Should -BeGreaterThan 0
            @($r.Facts.Rules).Count | Should -Be 1
            $r.ExitCode | Should -Be 2
        }

        It 'AC12_ResultsCutOffAtTheLargeSetLimit: warn, could not check, signs kept, takeover line first' {
            $first = New-RuleRecord -RuleName 'xx' -Id 'sign-1'
            $first.ResultIndex = 49999; $first.ResultCount = 61000
            $last = New-AuditRecord -Operation 'Set-Mailbox' -Top @{ ObjectId = 'asmith@contoso.com' } -Param ([ordered]@{ ProhibitSendQuota = '1GB' })
            $last.ResultIndex = 50000; $last.ResultCount = 61000
            New-Scenario @{ Pages = @(@($first, $last), @((New-RuleRecord -Id 'beyond'))) }
            $r = Invoke-Check
            $script:SearchCalls.Count | Should -Be 1 -Because 'the cap is reached; there is nothing more to page through'
            $c = Get-Source $r 'Recent changes'
            $c.Count | Should -Be 1
            $c[0].Reason | Should -Match 'results were cut off'
            @($r.Assessment.Signs | Where-Object { $_.Kind -eq 'RecentRuleChange' }).Count | Should -Be 1
            @($r.Assessment.Lines)[0] | Should -BeExactly $script:TakeoverLine
            $r.ExitCode | Should -Be 1
            $r.Facts.RecentChanges.CutOff | Should -BeTrue
            (ConvertTo-MailboxCheckHtml -Result $r) | Should -Match '\[WARN\][^<]*results were cut off'
        }

        It 'AC12_CutOffWithNoSignIsPartlyChecked' {
            $last = New-AuditRecord -Operation 'Set-Mailbox' -Top @{ ObjectId = 'asmith@contoso.com' } -Param ([ordered]@{ ProhibitSendQuota = '1GB' })
            $last.ResultIndex = 50000; $last.ResultCount = 61000
            New-Scenario @{ Pages = @(, @($last)) }
            $r = Invoke-Check
            @($r.Assessment.Lines)[0] | Should -Match '^PARTLY CHECKED'
            $r.ExitCode | Should -Be 2
        }

        It 'AC14_NoRecentChangesSkipsTheLookup: nothing is called, skipped, exit 2' {
            $r = Invoke-Check @{ NoRecentChanges = $true }
            Should -Invoke Search-UnifiedAuditLog -Times 0 -Exactly
            Should -Invoke Get-AdminAuditLogConfig -Times 0 -Exactly
            $c = Get-Source $r 'Recent changes'
            $c.Count | Should -Be 1
            $c[0].Reason | Should -Match ([regex]::Escape('skipped (-NoRecentChanges)'))
            $r.ExitCode | Should -Be 2
        }

        It 'AC14_NoRecentChangesThroughTheEntryScript: switch exists and the exit code is 2' {
            $r = Invoke-Entry @{ NoRecentChanges = $true }
            $script:LastError | Should -BeNullOrEmpty
            $r.ExitCode | Should -Be 2
            $script:SearchCalls.Count | Should -Be 0
        }

        It 'AC14_NoRecentChangesDoesNotHideAFoundSign' {
            New-Scenario @{ Mailbox = (New-Mbx @{ ForwardingSmtpAddress = 'smtp:x@gmail.com' }) }
            $r = Invoke-Check @{ NoRecentChanges = $true }
            $r.ExitCode | Should -Be 1
            @($r.Assessment.Lines)[0] | Should -BeExactly $script:TakeoverLine
        }
    }

    Context 'Review fixes (SQ-016 fix round 1): no all-clear from a partial read' {
        BeforeAll {
            function New-BadRecord([string]$Id = 'bad-1') {
                [PSCustomObject]@{ RecordType = 'ExchangeAdmin'; CreationDate = $script:Now; UserIds = 'x'; Operations = 'Set-Mailbox'; AuditData = '{not json'; ResultIndex = 1; ResultCount = 1; Identity = $Id }
            }
        }

        It 'Fix_UnreadableAuditRecordsMeanRecentChangesCouldNotBeChecked (no sign: PARTLY CHECKED, no clean wording)' {
            New-Scenario @{ Pages = @(, (Get-Page @((New-BadRecord 'bad-1'), (New-BadRecord 'bad-2')))) }
            $r = Invoke-Check
            $r.Facts.RecentChanges.Skipped | Should -Be 2
            $c = Get-Source $r 'Recent changes'
            $c.Count | Should -Be 1
            $c[0].Reason | Should -Match ([regex]::Escape('2 audit record(s) could not be read'))
            $c[0].NoteReason | Should -Match ([regex]::Escape('audit record(s) could not be read'))
            @($r.Assessment.Lines)[0] | Should -Match '^PARTLY CHECKED'
            $r.ExitCode | Should -Be 2
            $html = ConvertTo-MailboxCheckHtml -Result $r
            $html | Should -Not -Match ([regex]::Escape('No inbox rules, forwarding or mailbox access were added or changed'))
            . (Join-Path $script:Root 'CaseKit.ps1')
            $text = (ConvertTo-TicketNoteText -Note $r.TicketNote -PasteSafe:$false) -join "`n"
            $text | Should -Not -Match ([regex]::Escape('no rule, forwarding or delegate change was found'))
            $text | Should -Match 'Recent changes'
        }

        It 'Fix_UnreadableAuditRecordsKeepTheSignsFound (takeover line first, still could not check)' {
            New-Scenario @{ Pages = @(, (Get-Page @((New-BadRecord), (New-RuleRecord -RuleName 'xx' -Id 'sign-1')))) }
            $r = Invoke-Check
            @($r.Assessment.Lines)[0] | Should -BeExactly $script:TakeoverLine
            @($r.Assessment.Signs | Where-Object { $_.Kind -eq 'RecentRuleChange' }).Count | Should -Be 1
            (Get-Source $r 'Recent changes').Count | Should -Be 1
            $r.ExitCode | Should -Be 1
        }

        It 'Fix_ASearchThatFailsOnALaterPageKeepsTheSignsAlreadyRead' {
            $script:Page1 = Get-Page @((New-RuleRecord -RuleName 'xx' -Id 'sign-1')) -Count 5
            Mock Search-UnifiedAuditLog {
                $script:SearchCalls.Add(@{ SessionId = $SessionId })
                if ($script:SearchCalls.Count -eq 1) { return , @($script:Page1) }
                throw 'The search timed out after 600 seconds.'
            }
            $r = Invoke-Check
            $script:SearchCalls.Count | Should -Be 2
            @($r.Assessment.Lines)[0] | Should -BeExactly $script:TakeoverLine
            @($r.Assessment.Signs | Where-Object { $_.Kind -eq 'RecentRuleChange' }).Count | Should -Be 1
            @($r.Facts.RecentChanges.Changes).Count | Should -Be 1
            $c = Get-Source $r 'Recent changes'
            $c.Count | Should -Be 1
            $c[0].Reason | Should -Match 'search timed out after 600 seconds'
            $c[0].NoteReason | Should -Not -BeNullOrEmpty
            $c[0].NoteReason | Should -Not -Match 'timed out after 600'
            ($r.Assessment.Lines -join "`n") | Should -Match 'Could not check: Recent changes'
            $r.ExitCode | Should -Be 1
            (ConvertTo-MailboxCheckHtml -Result $r) | Should -Not -Match ([regex]::Escape('No inbox rules, forwarding or mailbox access were added or changed'))
        }

        It 'Fix_MissingResultIndexAndResultCountKeepPagingUntilAnEmptyPage' {
            $a = New-RuleRecord -Id 'a'; $b = New-RuleRecord -Id 'b'; $c = New-RuleRecord -Id 'c'
            foreach ($x in $a, $b, $c) { $x.ResultIndex = $null; $x.ResultCount = $null }
            $b.ResultCount = 'not a number'
            New-Scenario @{ Pages = @(@($a, $b), @(, $c), @()) }
            $r = Invoke-Check
            $script:SearchCalls.Count | Should -Be 3 -Because 'an unknown ResultCount never ends the search early'
            @($r.Facts.RecentChanges.Changes).Count | Should -Be 3
            (Get-Source $r 'Recent changes').Count | Should -Be 0
        }

        It 'Fix_AnUnsortedPageIsJudgedByItsHighestResultIndex' {
            $a = New-RuleRecord -Id 'a' -Index 3 -Count 3
            $b = New-RuleRecord -Id 'b' -Index 1 -Count 3
            $c = New-RuleRecord -Id 'c' -Index 2 -Count 3
            New-Scenario @{ Pages = @(@($a, $b, $c), @((New-RuleRecord -Id 'beyond'))) }
            $null = Invoke-Check
            $script:SearchCalls.Count | Should -Be 1 -Because 'the highest ResultIndex on the page already reached ResultCount'
        }

        It 'Fix_UnknownAuditLogSettingIsCouldNotCheckButStillSearches: <Case>' -ForEach @(
            @{ Case = 'UnifiedAuditLogIngestionEnabled is null'; Missing = $false }
            @{ Case = 'UnifiedAuditLogIngestionEnabled is missing'; Missing = $true }
        ) {
            if ($Missing) {
                Mock Get-AdminAuditLogConfig { [PSCustomObject]@{ Name = 'Admin Audit Log Settings' } }
            } else {
                Mock Get-AdminAuditLogConfig { [PSCustomObject]@{ UnifiedAuditLogIngestionEnabled = $null } }
            }
            New-Scenario @{ Pages = @(, (Get-Page @((New-RuleRecord -RuleName 'xx' -Id 'sign-1')))) }
            $r = Invoke-Check
            $script:SearchCalls.Count | Should -BeGreaterThan 0 -Because 'an unknown setting is not a reason to skip the search'
            $c = Get-Source $r 'Recent changes'
            $c.Count | Should -Be 1
            $c[0].Reason | Should -Match 'could not tell whether audit logging is on'
            $c[0].NoteReason | Should -Match 'could not tell whether audit logging is on'
            @($r.Assessment.Signs | Where-Object { $_.Kind -eq 'RecentRuleChange' }).Count | Should -Be 1
            @($r.Assessment.Lines)[0] | Should -BeExactly $script:TakeoverLine

            New-Scenario @{ Pages = @(, @()) }
            $r2 = Invoke-Check
            @($r2.Assessment.Lines)[0] | Should -Match '^PARTLY CHECKED'
            $r2.ExitCode | Should -Be 2
        }
    }

    Context 'AC13 nothing changed' {
        It 'AC13_CleanSectionVerdictAndExitCode' {
            New-Scenario @{ Pages = @(, @()) }
            $r = Invoke-Check
            @($r.Assessment.Lines)[0] | Should -BeExactly $script:CleanLine
            ($r.Assessment.Lines -join "`n") | Should -Not -Match 'not checked here'
            $r.ExitCode | Should -Be 0
            @($r.Facts.Gates | Where-Object { $_.Source -eq 'Recent changes' -and $_.State -eq 'Checked' }).Count | Should -Be 1
            $html = ConvertTo-MailboxCheckHtml -Result $r
            $html | Should -Match 'Recent changes \(last 14 days\)'
            $a = $html.IndexOf('No inbox rules, forwarding or mailbox access were added or changed in the last 14 days.')
            $b = $html.IndexOf('Changes from the last few hours may not be in the audit log yet.')
            $a | Should -BeGreaterThan -1
            $b | Should -BeGreaterThan $a
        }
    }

    Context 'AC15 paging and duplicates, end to end' {
        It 'AC15_ARecordOnTwoPagesIsListedOnceAndRaisesOneSign' {
            New-Scenario @{ Pages = @(
                    (Get-Page @((New-RuleRecord -Id 'same')) -Count 2),
                    (Get-Page @((New-RuleRecord -Id 'same')) -Start 2 -Count 2)) }
            $r = Invoke-Check
            @($r.Facts.RecentChanges.Changes).Count | Should -Be 1
            @($r.Assessment.Signs | Where-Object { $_.Kind -eq 'RecentRuleChange' }).Count | Should -Be 1
        }

        It 'Edge_ASingleRecordReturnedByTheSearchIsHandled (no .Count on a lone object)' {
            New-Scenario @{ Pages = @(, (New-RuleRecord -Id 'lone')) }
            $r = Invoke-Check
            @($r.Assessment.Signs | Where-Object { $_.Kind -eq 'RecentRuleChange' }).Count | Should -Be 1
        }
    }

    Context 'AC16 verdict' {
        It 'AC16_OneRecentRuleChangeOpensWithTheTakeoverLineAndTheBecNextStep' {
            New-Scenario @{ Pages = @(, (Get-Page @((New-RuleRecord -RuleName 'xx'))) ) }
            $r = Invoke-Check
            $lines = @($r.Assessment.Lines)
            $lines[0] | Should -BeExactly $script:TakeoverLine
            (($lines | Select-Object -Skip 1) -join "`n") | Should -Match "'xx'.*2 days ago|2 days ago.*'xx'"
            $lines | Should -Contain "Next step: Check CIPP's BEC report for this user."
            $r.Assessment.NextStep | Should -BeExactly "Check CIPP's BEC report for this user."
            ($lines -join "`n") | Should -Not -Match 'not checked here'
            $r.ExitCode | Should -Be 1
        }
    }

    Context 'AC17 ticket note' {
        It 'AC17_NoteHasKindsDatesAndRuleNameButNeitherActorNorIpNorDelegateAddress' {
            $rule = New-RuleRecord -RuleName 'Forward-Invoices' -UserId 'jdoe@contoso.com' -Time ([datetime]::new(2026, 10, 15, 12, 0, 0, [DateTimeKind]::Utc))
            $deleg = New-AuditRecord -Operation 'Add-MailboxPermission' -UserId 'admin@contoso.com' -Top @{ ObjectId = 'jdoe' } `
                -Param ([ordered]@{ Identity = 'jdoe'; User = 'helpdesk@contoso.com'; AccessRights = 'FullAccess' }) `
                -Time ([datetime]::new(2026, 10, 13, 12, 0, 0, [DateTimeKind]::Utc))
            New-Scenario @{ Pages = @(, (Get-Page @($rule, $deleg))) }
            $r = Invoke-Check
            $r.TicketNote | Should -Not -BeNullOrEmpty
            @($r.Facts.RecentChanges.Changes)[0].Time | Should -BeGreaterThan @($r.Facts.RecentChanges.Changes)[1].Time -Because 'newest first'
            . (Join-Path $script:Root 'CaseKit.ps1')
            foreach ($paste in @($false, $true)) {
                $text = (ConvertTo-TicketNoteText -Note $r.TicketNote -PasteSafe:$paste) -join "`n"
                $text | Should -Match 'RecentRuleChange'
                $text | Should -Match 'RecentDelegateChange'
                $text | Should -Match '2026-10-15'
                $text | Should -Match '2026-10-13'
                $text | Should -Match 'Forward-Invoices'
                $text | Should -Match "by the mailbox's own account"
                $text | Should -Match 'by another account'
                $text | Should -Not -Match '203\.0\.113\.7'
                $text | Should -Not -Match 'admin@contoso\.com'
                $text | Should -Not -Match 'helpdesk@contoso\.com' -Because 'the note never names a delegate address'
                $text | Should -Not -Match 'not checked here'
            }
        }

        It 'AC17_ACouldNotCheckRecentChangesNoteUsesFixedTextNotTheRawError' {
            New-Scenario @{ SearchThrow = 'Access is denied for admin@contoso.com at 203.0.113.9' }
            $r = Invoke-Check
            . (Join-Path $script:Root 'CaseKit.ps1')
            $text = (ConvertTo-TicketNoteText -Note $r.TicketNote -PasteSafe:$false) -join "`n"
            $text | Should -Match 'Recent changes'
            $text | Should -Not -Match '203\.0\.113\.9'
            $text | Should -Not -Match 'admin@contoso\.com'
        }
    }

    Context 'AC5 and AC18 the local report' {
        It 'AC5_ClientIpAndAppAreInTheLocalReportRow' {
            $raw = New-AuditRecord -Operation 'UpdateInboxRules' -MailboxAudit -Top @{ MailboxOwnerUPN = 'jdoe@contoso.com'; MailboxGuid = $script:ExchangeGuid; ObjectId = $null }
            New-Scenario @{ Pages = @(, (Get-Page @($raw))) }
            $r = Invoke-Check
            $html = ConvertTo-MailboxCheckHtml -Result $r
            $html | Should -Match '203\.0\.113\.7'
            $html | Should -Match 'OWA'
            $html | Should -Match 'jdoe@contoso\.com'
        }

        It 'AC18_RuleNameAndActorAreHtmlEncoded: no raw <script> or <b> from the audit record' {
            $rec = New-AuditRecord -Operation 'New-InboxRule' -UserId 'x<b>y@contoso.com' -Top @{ ObjectId = 'jdoe\<script>alert(1)</script>' } `
                -Param ([ordered]@{ Name = '<script>alert(1)</script>' })
            New-Scenario @{ Pages = @(, (Get-Page @($rec))) }
            $dir = Join-Path $TestDrive ([guid]::NewGuid().ToString())
            $r = Invoke-Check -SaveTo $dir
            $r.Status | Should -Be 'Ok'
            $body = Get-Content -LiteralPath $r.Files.Html -Raw
            $body | Should -Match ([regex]::Escape('&lt;script&gt;alert(1)&lt;/script&gt;'))
            $body | Should -Match ([regex]::Escape('x&lt;b&gt;y@contoso.com'))
            $body | Should -Not -Match '<script'
            $body | Should -Not -Match ([regex]::Escape('x<b>y'))
        }
    }
}

Describe 'AC19 recent changes are read-only by construction' {
    BeforeAll {
        $kit = Join-Path $script:Root 'CaseKit.ps1'
        $files = @($script:Entry, $script:Core, $kit)
        $script:Cmds = @()
        $script:LocalFns = @()
        foreach ($p in $files) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$null, [ref]$null)
            $script:LocalFns += @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
            $script:Cmds += @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                    Where-Object { $_.GetCommandName() } | ForEach-Object { [PSCustomObject]@{ Name = $_.GetCommandName(); File = $p } })
        }
        $script:Kit = $kit
        # SQ-007's AC21 allowlist, UNCHANGED (copied from MailboxCheck.Tests.ps1): SQ-016 may not add to it.
        $script:Allow = 'New-Object', 'New-Item', 'Add-Member', 'Set-Clipboard', 'Set-Content', 'Add-Content'
        $script:LocalHelpers = @(
            'Save-M365MailboxCheckReport', 'Save-M365MailboxCsv', 'New-MailboxSign', 'New-MailboxGate', 'New-M365MailboxStartFailure',
            'New-TicketNoteItem', 'New-TicketNoteStamp', 'New-TicketNote', 'New-TicketNoteClipboardData', 'Save-TicketNote',
            'Save-TicketNoteLines', 'Publish-TicketNote', 'Copy-TicketNoteToClipboard', 'Resolve-TicketFolder', 'Add-Section')
    }

    It 'AC19_TheLookupUsesOnlyTheFourReadCmdlets' {
        $names = @($script:Cmds | ForEach-Object { $_.Name })
        foreach ($n in 'Search-UnifiedAuditLog', 'Get-AdminAuditLogConfig', 'Get-OrganizationConfig', 'Get-MailboxAuditBypassAssociation') {
            $names | Should -Contain $n
        }
        foreach ($n in 'Set-AdminAuditLogConfig', 'Set-OrganizationConfig', 'Enable-OrganizationCustomization', 'Set-MailboxAuditBypassAssociation', 'Set-Mailbox') {
            $names | Should -Not -Contain $n
        }
    }

    It 'AC19_NoNewWriteVerbCommandOrHelperIsNeeded: SQ-007 AC21 still passes with its allowlist unchanged' {
        $bad = @($script:Cmds | Where-Object {
                $_.Name -match '^(Set|New|Remove|Add|Enable|Disable|Update|Clear|Restore|Start|Stop)-' -and $_.Name -notin $script:Allow -and $_.Name -notin $script:LocalHelpers -and
                -not ($_.File -eq $script:Kit -and $_.Name -eq 'Add-Type')
            } | ForEach-Object { $_.Name } | Sort-Object -Unique)
        $bad | Should -BeNullOrEmpty -Because ('write-verb commands found: ' + ($bad -join ', '))
        # Guard against scanning nothing: the new lookup must be in the scanned files.
        @($script:Cmds | Where-Object { $_.Name -eq 'Search-UnifiedAuditLog' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'AC20 stub parameter names are real' {
    It 'AC20_StubParametersExistOnTheRealCmdlets (module installed; falls back to the Learn list for proxy cmdlets that need a session)' -Skip:(-not $script:HasExo) {
        $targets = 'Search-UnifiedAuditLog', 'Get-AdminAuditLogConfig', 'Get-MailboxAuditBypassAssociation'
        $names = ($targets | ForEach-Object { "'$_'" }) -join ','
        $cmd = "Import-Module ExchangeOnlineManagement -ErrorAction Stop; `$o = @{}; foreach (`$n in @($names)) { `$c = Get-Command `$n -ErrorAction SilentlyContinue; if (`$c) { `$o[`$n] = @(`$c.Parameters.Keys) } }; `$o | ConvertTo-Json -Compress"
        $json = & pwsh -NoProfile -NonInteractive -Command $cmd
        $real = if ($json) { $json | ConvertFrom-Json } else { $null }
        foreach ($name in $targets) {
            $mine = @($script:StubSpec[$name].Params) + @($script:StubSpec[$name].Switches)
            $known = if ($real -and $real.PSObject.Properties[$name] -and @($real.$name).Count -gt 0) { @($real.$name) } else { @($script:LearnParams[$name]) }
            $known | Should -Not -BeNullOrEmpty -Because "$name has no real parameter list to compare with"
            foreach ($p in $mine) { $known | Should -Contain $p -Because "$name -$p must exist" }
        }
    }

    It 'AC20_ProductionCallsUseRealParameterNames: every named parameter passed to the three audit cmdlets exists' {
        $common = 'ErrorAction', 'Verbose', 'Debug', 'WarningAction', 'InformationAction', 'ErrorVariable', 'OutVariable', 'WhatIf', 'Confirm'
        $seen = 0
        foreach ($p in $script:Entry, $script:Core) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$null, [ref]$null)
            foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                $name = $c.GetCommandName()
                if ($name -notin 'Search-UnifiedAuditLog', 'Get-AdminAuditLogConfig', 'Get-MailboxAuditBypassAssociation') { continue }
                $seen++
                foreach ($e in $c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] }) {
                    ($script:LearnParams[$name] + $common) | Should -Contain $e.ParameterName -Because "$name -$($e.ParameterName) in $(Split-Path -Leaf $p)"
                }
            }
        }
        $seen | Should -BeGreaterOrEqual 3 -Because 'the scripts must call the three audit cmdlets'
    }
}
