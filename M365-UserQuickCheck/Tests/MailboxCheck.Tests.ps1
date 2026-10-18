<#
    Tests for M365-UserQuickCheck\Get-M365MailboxCheck.ps1 + MailboxCheck.Core.ps1 (Pester 5, pwsh).
    SQ-007, mailbox check: AC1-AC25. (AC26, the audit-log search, is implemented by SQ-016.)

    The entry script is RUN (dot-sourced, never '&') with Exchange Online and the clipboard
    faked: Import-Module, Connect-/Disconnect-ExchangeOnline, Get-ConnectionInformation,
    Get-OrganizationConfig, Get-AcceptedDomain, Get-EXOMailbox, Get-EXOMailboxStatistics,
    Get-EXOMailboxPermission, Get-EXORecipientPermission, Get-InboxRule, Get-MessageTraceV2,
    Set-Clipboard, Invoke-WinFormsClipboard and Write-Host are mocked. Nothing connects to a
    tenant; the real clipboard and user profile are never touched (-NoClipboard, files under
    $TestDrive). Synthetic data only (contoso.com, jdoe, fabrikam.com).

    The stubs carry the REAL parameter names (ExchangeOnlineManagement 3.9.0 via Get-Command;
    proxy cmdlets not in the module file: the Microsoft Learn pages for get-inboxrule,
    get-messagetracev2, get-accepteddomain). AC23 re-checks them.

    PINNED INTERFACE (the implementer must honour these):
      Entry Get-M365MailboxCheck.ps1: -Identity (position 0, mandatory), -TraceDays
        ([ValidateRange(1,10)], default 7), -OutputPath, -TicketNumber, -NoTrace, -NoClipboard,
        -FullDetail, -PassThru, -Quiet, -LoadFunctionsOnly. With -PassThru it RETURNS (no exit)
        a result { Status ('Ok'|'NotFound'|'Error'); ExitCode; Identity; Message; Tenant;
        Facts; Assessment; Files; TicketNote }. Without -PassThru it exits with ExitCode.
        Exit codes: 0 clean, 1 possible takeover, 2 partly checked, 3 could not run / no mailbox.
        Facts.FactRows = the Get-MailboxFactRows rows. Facts.Rules = every inbox rule (from Get-InboxRule -IncludeHidden), each carrying
        IsHidden ([bool], true when -IncludeHidden returns it and the plain call does not).
        Files = { Html; RulesCsv; DelegatesCsv; TraceCsv } when -OutputPath is given:
        MailboxCheck_<safe-identity>_<yyyy-MM-dd_HHmmss>.html and ..._rules.csv / _delegates.csv /
        _trace.csv (safe = [^\w.-] -> _). With -TicketNumber the folder is <OutputPath>\Ticket_<n>.
        Console: banner (tenant = the initial *.onmicrosoft.com domain from Get-AcceptedDomain,
        then the TenantID and UserPrincipalName from Get-ConnectionInformation) is written
        through Write-Host BEFORE the first Get-EXOMailbox. Verdict block lines go through
        Write-Host too. Connect: Connect-ExchangeOnline -ShowBanner:$false, only when
        Get-ConnectionInformation shows no session; Disconnect-ExchangeOnline only then.
      Core (dot-source MailboxCheck.Core.ps1; pure, no console, no cmdlet calls):
        Test-ExternalAddress -Address <string> -AcceptedDomain <string[]> -> [bool]. Accepts
          'smtp:x@gmail.com', 'SMTP:x@gmail.com', '"Name" [SMTP:x@gmail.com]', plain addresses;
          domain match is case-insensitive; equal to or a subdomain of an accepted domain (a
          leading '*.' on an accepted domain is ignored) is internal.
        Get-MailboxDelegates -Kind FullAccess|SendAs|SendOnBehalf -Permission <objects> -> [string[]]
          FullAccess entries: User, AccessRights, IsInherited, Deny (Get-EXOMailboxPermission);
          SendAs entries: Trustee, AccessRights, AccessControlType (Get-EXORecipientPermission);
          SendOnBehalf entries: the GrantSendOnBehalfTo values (strings).
          Drops NT AUTHORITY\SELF, inherited and Deny entries.
        Format-MailboxDelegateList -Delegate <string[]> -> 'Nobody' when empty, else joined ', '.
        Get-ForwardingSigns -Mailbox <obj> -AcceptedDomain <string[]> -> sign objects.
        Get-InboxRuleSigns -Rule <objs> -AcceptedDomain <string[]> -> sign objects.
          A sign: { Kind; Message (plain English); Domain; RuleName; KeepsCopy }.
          Kinds: ExternalForwarding, ExternalRuleForward, RuleDeletesMail, RuleHidesMail, HiddenRule.
        Get-MailboxFactRows -Mailbox -Statistics -ArchiveStatistics -> rows { Item; Value } with
          Items 'Mailbox type', 'Mail forwarding', 'Total size', 'Prohibit-send quota',
          'Archive', 'Archive size', 'Litigation hold', 'Other holds'; a missing value reads
          'not available' (never 0 or blank); no archive reads 'No archive'.
        Get-MailboxCheckAssessment -Signs <signs> -Gate <gates> -> { Verdict
          ('TakeoverSigns'|'PartlyChecked'|'AllChecked'); ExitCode; Lines (the verdict block,
          line 1 first); Signs; CouldNotCheck ({ Source; Reason }); NextStep }.
          A gate is { Source; State ('Checked'|'CouldNotCheck'); Reason }.
        ConvertTo-MailboxCheckHtml -Result <result>; Get-MailboxCheckNote -Result <result>
          -EvidencePaths (returns a CaseKit note). The ticket note carries sign kinds, rule
          names and external domains only (D-025, assumed paste-safe note).

    Run:  Invoke-Pester .\M365-UserQuickCheck\Tests\MailboxCheck.Tests.ps1
#>

# Discovery-time: AC23 skips when the module is absent.
$script:HasExo = [bool](Get-Module -ListAvailable -Name ExchangeOnlineManagement)

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:Entry = Join-Path $script:Root 'Get-M365MailboxCheck.ps1'
    $script:Core = Join-Path $script:Root 'MailboxCheck.Core.ps1'
    $script:RepoRoot = Split-Path -Parent $script:Root

    # Stub spec: real parameter names (checked in AC23). Params = value parameters,
    # Switches = [switch] parameters.
    $script:StubSpec = [ordered]@{
        'Connect-ExchangeOnline'       = @{ Params = @('UserPrincipalName', 'DelegatedOrganization', 'Organization'); Switches = @('ShowBanner', 'Device', 'DisableWAM') }
        'Disconnect-ExchangeOnline'    = @{ Params = @('ConnectionId', 'ModulePrefix'); Switches = @('Confirm') }
        'Get-ConnectionInformation'    = @{ Params = @('ConnectionId', 'ModulePrefix'); Switches = @() }
        'Get-EXOMailbox'               = @{ Params = @('Identity', 'Properties', 'PropertySets', 'ResultSize', 'RecipientTypeDetails'); Switches = @() }
        'Get-EXOMailboxStatistics'     = @{ Params = @('Identity', 'Properties'); Switches = @('Archive') }
        # https://learn.microsoft.com/powershell/module/exchangepowershell/get-exorecipient
        'Get-EXORecipient'             = @{ Params = @('Identity', 'Properties', 'PropertySets', 'ResultSize', 'RecipientTypeDetails'); Switches = @() }
        'Get-EXOMailboxPermission'     = @{ Params = @('Identity', 'User', 'ResultSize'); Switches = @() }
        'Get-EXORecipientPermission'   = @{ Params = @('Identity', 'Trustee', 'AccessRights', 'ResultSize'); Switches = @() }
        'Get-InboxRule'                = @{ Params = @('Identity', 'Mailbox', 'ResultSize'); Switches = @('IncludeHidden') }
        'Get-MessageTraceV2'           = @{ Params = @('StartDate', 'EndDate', 'SenderAddress', 'RecipientAddress', 'ResultSize', 'Status'); Switches = @() }
        'Get-AcceptedDomain'           = @{ Params = @('Identity', 'ResultSize'); Switches = @() }
        'Get-OrganizationConfig'       = @{ Params = @('Identity'); Switches = @() }
        # SQ-016 (the audit-log lookup runs by default; its own tests are in MailboxCheck.RecentChanges.Tests.ps1)
        'Search-UnifiedAuditLog'            = @{ Params = @('StartDate', 'EndDate', 'Operations', 'SessionId', 'SessionCommand', 'ResultSize'); Switches = @() }
        'Get-AdminAuditLogConfig'           = @{ Params = @(); Switches = @() }
        'Get-MailboxAuditBypassAssociation' = @{ Params = @('Identity'); Switches = @() }
    }
    # From Microsoft Learn (these are proxy cmdlets that exist only after a connection).
    # https://learn.microsoft.com/powershell/module/exchangepowershell/get-inboxrule
    # https://learn.microsoft.com/powershell/module/exchangepowershell/get-messagetracev2
    # https://learn.microsoft.com/powershell/module/exchangepowershell/get-accepteddomain
    # https://learn.microsoft.com/powershell/module/exchangepowershell/get-organizationconfig
    $script:LearnParams = @{
        'Get-InboxRule'          = @('BypassScopeCheck', 'DescriptionTimeFormat', 'DescriptionTimeZone', 'DomainController', 'Identity', 'IncludeHidden', 'Mailbox', 'ResultSize', 'SkipCount', 'SweepRules', 'UseCustomRouting')
        'Get-MessageTraceV2'     = @('EndDate', 'FromIP', 'MessageId', 'MessageTraceId', 'RecipientAddress', 'ResultSize', 'SenderAddress', 'StartDate', 'StartingRecipientAddress', 'Status', 'Subject', 'SubjectFilterType', 'ToIP')
        'Get-AcceptedDomain'     = @('DomainController', 'Identity', 'ResultSize')
        'Get-OrganizationConfig' = @('ErrorAction', 'Identity', 'DomainController')
        # https://learn.microsoft.com/powershell/module/exchangepowershell/search-unifiedauditlog
        # https://learn.microsoft.com/powershell/module/exchangepowershell/get-adminauditlogconfig
        # https://learn.microsoft.com/powershell/module/exchangepowershell/get-mailboxauditbypassassociation
        'Search-UnifiedAuditLog'            = @('EndDate', 'Formatted', 'FreeText', 'HighCompleteness', 'IPAddresses', 'LegacyFlow', 'LongerRetentionEnabled', 'ObjectIds', 'Operations', 'RecordType', 'ResultSize', 'SessionCommand', 'SessionId', 'SiteIds', 'StartDate', 'UserIds')
        'Get-AdminAuditLogConfig'           = @('DomainController')
        'Get-MailboxAuditBypassAssociation' = @('DomainController', 'Identity', 'ResultSize')
    }
    foreach ($name in $script:StubSpec.Keys) {
        $spec = $script:StubSpec[$name]
        $decl = @($spec.Params | ForEach-Object { "`$$_" }) + @($spec.Switches | ForEach-Object { "[switch]`$$_" })
        . ([scriptblock]::Create("function $name { [CmdletBinding()] param($($decl -join ', ')) }"))
    }
    function Set-Clipboard { [CmdletBinding()] param([Parameter(ValueFromPipeline = $true)][AllowEmptyString()][string[]]$Value, [switch]$Append, [switch]$AsHtml) }
    # CaseKit defines this once the script runs; the stub lets it be mocked (D-033).
    function Invoke-WinFormsClipboard { param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text) }

    # ---- fixtures -------------------------------------------------------------------------
    function New-Mbx {
        param([hashtable]$Set = @{})
        $m = [ordered]@{
            DisplayName = 'Accounts'; PrimarySmtpAddress = 'accounts@contoso.com'; UserPrincipalName = 'accounts@contoso.com'
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
    function New-Sign([string]$Kind) { [PSCustomObject]@{ Kind = $Kind; Message = "sign $Kind"; Domain = ''; RuleName = ''; KeepsCopy = $false } }
    function New-GateFix([string]$Source, [string]$State = 'Checked', [string]$Reason = '') { [PSCustomObject]@{ Source = $Source; State = $State; Reason = $Reason } }
    function New-TraceRow([string]$From, [string]$To, [string]$Subject = 'Hello') {
        [PSCustomObject]@{ Received = [datetime]::UtcNow.AddHours(-3); SenderAddress = $From; RecipientAddress = $To; Subject = $Subject; Status = 'Delivered'; Size = 1200; MessageId = '<' + [guid]::NewGuid() + '@contoso.com>' }
    }
    function New-Scenario {
        param([hashtable]$Override = @{})
        $s = @{
            Session = $false
            Tenant = 'contoso.onmicrosoft.com'; Me = 'admin@contoso.onmicrosoft.com'; TenantGuid = '11111111-2222-3333-4444-555555555555'
            Accepted = @(
                [PSCustomObject]@{ DomainName = 'contoso.com'; Name = 'contoso.com'; InitialDomain = $false; Default = $true; DomainType = 'Authoritative' },
                [PSCustomObject]@{ DomainName = 'contoso.onmicrosoft.com'; Name = 'contoso.onmicrosoft.com'; InitialDomain = $true; Default = $false; DomainType = 'Authoritative' })
            Mailbox = (New-Mbx); MailboxThrow = $null
            Recipient = $null; RecipientThrow = $null
            MbxPerms = @(
                [PSCustomObject]@{ User = 'NT AUTHORITY\SELF'; AccessRights = @('FullAccess'); IsInherited = $false; Deny = $false },
                [PSCustomObject]@{ User = 'jdoe@contoso.com'; AccessRights = @('FullAccess'); IsInherited = $false; Deny = $false })
            RecipPerms = @(
                [PSCustomObject]@{ Trustee = 'NT AUTHORITY\SELF'; AccessRights = @('SendAs'); AccessControlType = 'Allow'; IsInherited = $false },
                [PSCustomObject]@{ Trustee = 'jdoe@contoso.com'; AccessRights = @('SendAs'); AccessControlType = 'Allow'; IsInherited = $false })
            PermsThrow = $null
            Rules = @((New-Rule)); HiddenRules = @(); RulesThrow = $null
            Stats = [PSCustomObject]@{ TotalItemSize = '1.5 GB (1,610,612,736 bytes)'; ItemCount = 1200 }
            ArchiveStats = $null
            Sent = @((New-TraceRow 'accounts@contoso.com' 'vendor@fabrikam.com' 'Wire details'))
            Received = @((New-TraceRow 'vendor@fabrikam.com' 'accounts@contoso.com' 'Re: Wire details'))
            TraceThrow = $null
        }
        foreach ($k in $Override.Keys) { $s[$k] = $Override[$k] }
        $script:Scn = $s
        $script:Connected = [bool]$s.Session
    }
    function Invoke-Entry {
        param([hashtable]$Extra = @{})
        $script:Events = New-Object System.Collections.Generic.List[string]
        $script:TraceCalls = New-Object System.Collections.Generic.List[object]
        $script:RuleCalls = New-Object System.Collections.Generic.List[object]
        $splat = @{ Identity = 'accounts@contoso.com'; NoClipboard = $true; PassThru = $true }
        foreach ($k in $Extra.Keys) { $splat[$k] = $Extra[$k] }
        $script:LastError = $null
        # Dot-sourced, not '&', so the mock bodies resolve $script:Events / $script:Scn in this scope.
        try { $out = @(. $script:Entry @splat) } catch { $script:LastError = $_; $out = @() }
        if ($out.Count -gt 0) { return $out[-1] }
        return $null
    }
    function Get-HostText { ($script:Events | Where-Object { $_ -like 'HOST:*' } | ForEach-Object { $_.Substring(5) }) -join "`n" }
    function New-OutDir { $d = Join-Path $TestDrive ([guid]::NewGuid().ToString()); $null = New-Item -ItemType Directory -Path $d; $d }
}

Describe 'running the check' {
    BeforeEach {
        New-Scenario
        $script:Events = New-Object System.Collections.Generic.List[string]
        $script:TraceCalls = New-Object System.Collections.Generic.List[object]
        $script:RuleCalls = New-Object System.Collections.Generic.List[object]
        Mock Import-Module { }
        Mock Connect-ExchangeOnline { $script:Events.Add('CONNECT'); $script:Connected = $true }
        Mock Disconnect-ExchangeOnline { $script:Events.Add('DISCONNECT'); $script:Connected = $false }
        Mock Get-ConnectionInformation {
            if ($script:Connected) { [PSCustomObject]@{ State = 'Connected'; Name = 'ExchangeOnline_1'; UserPrincipalName = $script:Scn.Me; TenantID = $script:Scn.TenantGuid } }
        }
        Mock Get-OrganizationConfig { [PSCustomObject]@{ Name = $script:Scn.Tenant; Identity = $script:Scn.Tenant; AuditDisabled = $false } }
        # SQ-016: auditing on, no bypass, an audit search that finds nothing.
        Mock Get-AdminAuditLogConfig { [PSCustomObject]@{ UnifiedAuditLogIngestionEnabled = $true } }
        Mock Get-MailboxAuditBypassAssociation { [PSCustomObject]@{ Name = 'accounts'; AuditBypassEnabled = $false } }
        Mock Search-UnifiedAuditLog { }
        Mock Get-AcceptedDomain { $script:Scn.Accepted }
        Mock Get-EXOMailbox {
            $script:Events.Add('EXO-MAILBOX')
            if ($script:Scn.MailboxThrow) { throw $script:Scn.MailboxThrow }
            $script:Scn.Mailbox
        }
        Mock Get-EXOMailboxStatistics { if ($Archive) { $script:Scn.ArchiveStats } else { $script:Scn.Stats } }
        Mock Get-EXORecipient { if ($script:Scn.RecipientThrow) { throw $script:Scn.RecipientThrow }; $script:Scn.Recipient }
        Mock Get-EXOMailboxPermission { if ($script:Scn.PermsThrow) { throw $script:Scn.PermsThrow }; $script:Scn.MbxPerms }
        Mock Get-EXORecipientPermission { if ($script:Scn.PermsThrow) { throw $script:Scn.PermsThrow }; $script:Scn.RecipPerms }
        Mock Get-InboxRule {
            $script:RuleCalls.Add(@{ IncludeHidden = [bool]$IncludeHidden })
            if ($script:Scn.RulesThrow) { throw $script:Scn.RulesThrow }
            if ($IncludeHidden) { @($script:Scn.Rules) + @($script:Scn.HiddenRules) } else { $script:Scn.Rules }
        }
        Mock Get-MessageTraceV2 {
            $script:TraceCalls.Add(@{ SenderAddress = $SenderAddress; RecipientAddress = $RecipientAddress; StartDate = $StartDate; EndDate = $EndDate; ResultSize = $ResultSize })
            if ($script:Scn.TraceThrow) { throw $script:Scn.TraceThrow }
            if ($SenderAddress) { $script:Scn.Sent } else { $script:Scn.Received }
        }
        Mock Set-Clipboard { }
        Mock Invoke-WinFormsClipboard { }
        Mock Write-Host { $script:Events.Add('HOST:' + ($Object -join ' ')) }
    }

    Context 'AC1 banner' {
        It 'AC1_BannerNamesTenantAndAccountBeforeFirstMailboxCmdlet' {
            $null = Invoke-Entry
            $script:LastError | Should -BeNullOrEmpty
            $i = $script:Events.IndexOf('EXO-MAILBOX')
            $i | Should -BeGreaterThan 0 -Because 'the mailbox must be read, and something must be written before it'
            $before = ($script:Events[0..($i - 1)] | Where-Object { $_ -like 'HOST:*' } | ForEach-Object { $_.Substring(5) }) -join "`n"
            $before | Should -Match 'contoso\.onmicrosoft\.com'
            $before | Should -Match 'admin@contoso\.onmicrosoft\.com'
        }
    }

    Context 'AC2 no such mailbox' {
        It 'AC2_NoMailboxFound: FAIL line, no verdict or report, exit 3 (cmdlet returns nothing)' {
            New-Scenario @{ Mailbox = $null }
            $out = New-OutDir
            $r = Invoke-Entry @{ Identity = 'nobody@contoso.com'; OutputPath = $out }
            $r.ExitCode | Should -Be 3
            (Get-HostText) | Should -Match ([regex]::Escape("[FAIL] No mailbox found for 'nobody@contoso.com' in tenant contoso.onmicrosoft.com."))
            (Get-HostText) | Should -Not -Match 'Possible account takeover|PARTLY CHECKED|No takeover signs found'
            $r.Assessment | Should -BeNullOrEmpty
            @(Get-ChildItem -LiteralPath $out -Recurse -File).Count | Should -Be 0
        }

        It 'AC2_NoMailboxFound: also when Get-EXOMailbox throws "couldn''t be found"' {
            New-Scenario @{ MailboxThrow = "The operation couldn't be performed because object 'nobody@contoso.com' couldn't be found on 'X'." }
            $r = Invoke-Entry @{ Identity = 'nobody@contoso.com' }
            $r.ExitCode | Should -Be 3
            (Get-HostText) | Should -Match ([regex]::Escape("[FAIL] No mailbox found for 'nobody@contoso.com' in tenant contoso.onmicrosoft.com."))
        }
    }

    Context 'AC11 hidden rules, end to end' {
        It 'AC11_HiddenRulesIncludedAndMarked: Get-InboxRule -IncludeHidden is called; junk rule and one other hidden rule are marked; only the other raises HiddenRule' {
            New-Scenario @{
                Rules = @((New-Rule @{ Name = 'Projects' }))
                HiddenRules = @((New-Rule @{ Name = 'Junk E-mail Rule'; Identity = 'h1' }), (New-Rule @{ Name = 'x'; Identity = 'h2' }))
            }
            $r = Invoke-Entry
            @($script:RuleCalls | Where-Object { $_.IncludeHidden }).Count | Should -BeGreaterThan 0
            $hidden = @($r.Facts.Rules | Where-Object { $_.IsHidden })
            @($hidden | ForEach-Object { $_.Name }) | Should -Contain 'Junk E-mail Rule'
            @($hidden | ForEach-Object { $_.Name }) | Should -Contain 'x'
            @($r.Facts.Rules | Where-Object { $_.Name -eq 'Projects' -and $_.IsHidden }).Count | Should -Be 0
            $signs = @($r.Assessment.Signs | Where-Object { $_.Kind -eq 'HiddenRule' })
            $signs.Count | Should -Be 1
            $signs[0].RuleName | Should -Be 'x'
        }
    }

    Context 'AC13 / AC14 message trace' {
        It 'AC13_TraceQueriedTwiceWithWindowAndMaxResultSize: sender query and recipient query, 7 days ending now, ResultSize 5000' {
            $null = Invoke-Entry @{ TraceDays = 7 }
            $script:TraceCalls.Count | Should -Be 2
            $by = @($script:TraceCalls | Where-Object { $_.SenderAddress })
            $to = @($script:TraceCalls | Where-Object { $_.RecipientAddress })
            $by.Count | Should -Be 1
            $to.Count | Should -Be 1
            $by[0].SenderAddress | Should -Be 'accounts@contoso.com'
            $to[0].RecipientAddress | Should -Be 'accounts@contoso.com'
            foreach ($c in $script:TraceCalls) {
                ([datetime]$c.EndDate - [datetime]$c.StartDate).TotalDays | Should -BeGreaterThan 6.99
                ([datetime]$c.EndDate - [datetime]$c.StartDate).TotalDays | Should -BeLessThan 7.01
                [math]::Abs(([datetime]$c.EndDate).ToUniversalTime().Subtract([datetime]::UtcNow).TotalMinutes) | Should -BeLessThan 5
                $c.ResultSize | Should -Be 5000
            }
        }

        It 'AC13_TraceDaysAbove10IsRejected: -TraceDays 11 fails parameter validation and nothing is read' {
            $null = Invoke-Entry @{ TraceDays = 11 }
            $script:LastError | Should -Not -BeNullOrEmpty
            "$($script:LastError)" | Should -Match 'TraceDays'
            $script:Events | Should -Not -Contain 'EXO-MAILBOX'
        }

        It 'AC14_TraceCutOffWarns: a query that returns the maximum count -> [WARN] results were cut off at 5000' {
            $many = @(New-TraceRow 'a@fabrikam.com' 'accounts@contoso.com') * 5000
            New-Scenario @{ Received = $many }
            $r = Invoke-Entry @{ TraceDays = 7 }
            (Get-HostText) | Should -Match ([regex]::Escape('[WARN] results were cut off at 5000; rerun with a smaller -TraceDays'))
        }

        It 'Edge_ZeroTraceRowsIsAFactNotAFailure' {
            New-Scenario @{ Sent = @(); Received = @() }
            $r = Invoke-Entry
            @($r.Assessment.CouldNotCheck | Where-Object { $_.Source -match 'trace' }).Count | Should -Be 0
            $r.ExitCode | Should -Be 0
        }
    }

    Context 'AC15 to AC18 verdict, end to end' {
        It 'AC15_TakeoverVerdictWordingAndExitCode: external forwarding -> exact first line, sign, exact next step, exit 1' {
            New-Scenario @{ Mailbox = (New-Mbx @{ ForwardingSmtpAddress = 'smtp:x@gmail.com'; DeliverToMailboxAndForward = $true }) }
            $r = Invoke-Entry
            $r.ExitCode | Should -Be 1
            $lines = @($r.Assessment.Lines)
            $lines[0] | Should -BeExactly 'Possible account takeover: do NOT reset the password or delete the rule yet. Escalate.'
            (($lines | Select-Object -Skip 1) -join "`n") | Should -Match 'gmail\.com'
            $lines | Should -Contain "Next step: Check CIPP's BEC report for this user."
            $r.Assessment.NextStep | Should -BeExactly "Check CIPP's BEC report for this user."
            (Get-HostText) | Should -Match ([regex]::Escape('Possible account takeover: do NOT reset the password or delete the rule yet. Escalate.'))
        }

        It 'AC16_InboxRulesDeniedIsPartlyChecked: access denied, no other sign -> PARTLY CHECKED naming Inbox rules and the reason, never the all-clear, exit 2' {
            New-Scenario @{ RulesThrow = "The user 'admin@contoso.onmicrosoft.com' isn't assigned to any management roles. Access is denied." }
            $r = Invoke-Entry
            $r.ExitCode | Should -Be 2
            $lines = @($r.Assessment.Lines)
            $lines[0] | Should -Match '^PARTLY CHECKED'
            ($lines -join "`n") | Should -Match 'Inbox rules'
            ($lines -join "`n") | Should -Match 'Access is denied'
            ($lines -join "`n") | Should -Not -Match 'No takeover signs found'
            (Get-HostText) | Should -Not -Match 'No takeover signs found'
        }

        It 'AC17_AllSectionsCheckedAndNoSignIsClean: exact wording, exit 0' {
            $r = Invoke-Entry
            $r.ExitCode | Should -Be 0
            @($r.Assessment.Lines)[0] | Should -BeExactly 'No takeover signs found in the checks below.'
            @($r.Assessment.Signs).Count | Should -Be 0
        }

        It 'AC18_TakeoverStaysFirstWhenTraceFails: external forwarding + failed trace -> takeover first, trace under could-not-check' {
            New-Scenario @{ Mailbox = (New-Mbx @{ ForwardingSmtpAddress = 'smtp:x@gmail.com' }); TraceThrow = 'Get-MessageTraceV2 : The role assigned to you does not allow this.' }
            $r = Invoke-Entry
            @($r.Assessment.Lines)[0] | Should -BeExactly 'Possible account takeover: do NOT reset the password or delete the rule yet. Escalate.'
            @($r.Assessment.CouldNotCheck | Where-Object { $_.Source -match 'trace' }).Count | Should -Be 1
            ($r.Assessment.Lines -join "`n") | Should -Match 'trace'
            $r.ExitCode | Should -Be 1
        }
    }

    Context 'AC19 ticket note' {
        It 'AC19_NoteHasKindsAndDomainButNoConditionsAddressesOrTraceRows; failed section is "Could not check", never "Ruled out"' {
            New-Scenario @{
                Rules = @((New-Rule @{ Name = 'Move stuff'; ForwardTo = @('x@gmail.com'); SubjectContainsWords = @('invoice'); Description = 'If the message: Subject contains "invoice" Do: forward to x@gmail.com' }))
                Sent = @((New-TraceRow 'accounts@contoso.com' 'vendor@fabrikam.com' 'Wire details'))
                Received = @((New-TraceRow 'vendor@fabrikam.com' 'accounts@contoso.com' 'Wire details'))
            }
            $r = Invoke-Entry
            $r.TicketNote | Should -Not -BeNullOrEmpty
            # The kit is loaded inside Invoke-Entry's scope only; load it here to render the note.
            . (Join-Path $script:Root 'CaseKit.ps1')
            foreach ($paste in @($false, $true)) {
                $text = (ConvertTo-TicketNoteText -Note $r.TicketNote -PasteSafe:$paste) -join "`n"
                $text | Should -Match 'ExternalRuleForward'
                $text | Should -Match 'gmail\.com'
                $text | Should -Not -Match 'invoice'
                $text | Should -Not -Match 'x@gmail\.com'
                $text | Should -Not -Match 'vendor@fabrikam'
                $text | Should -Not -Match 'Wire details'
            }
            New-Scenario @{ TraceThrow = 'trace denied' }
            $r2 = Invoke-Entry
            ($r2.TicketNote.CouldNotCheck -join "`n") | Should -Match 'trace'
            ($r2.TicketNote.RuledOut -join "`n") | Should -Not -Match 'trace'
        }

        It 'Edge_NoteIsWrittenToFileAndClipboardForATicket: -TicketNumber puts the note in Ticket_<n>, one WinForms clipboard copy' {
            $out = New-OutDir
            $null = Invoke-Entry @{ OutputPath = $out; TicketNumber = 'T100'; NoClipboard = $false }
            @(Get-ChildItem -LiteralPath (Join-Path $out 'Ticket_T100') -Filter 'Note_*.txt' -ErrorAction SilentlyContinue).Count | Should -Be 1
            Should -Invoke Invoke-WinFormsClipboard -Times 1 -Exactly
            Should -Invoke Set-Clipboard -Times 0 -Exactly
        }
    }

    Context 'AC20 HTML encoding' {
        It 'AC20_RuleNameIsHtmlEncoded: no raw <script> tag in the report' {
            New-Scenario @{ Rules = @((New-Rule @{ Name = '<script>alert(1)</script>' })) }
            $out = New-OutDir
            $null = Invoke-Entry @{ OutputPath = $out }
            $html = @(Get-ChildItem -LiteralPath $out -Filter 'MailboxCheck_*.html')
            $html.Count | Should -Be 1
            $body = Get-Content -LiteralPath $html[0].FullName -Raw
            $body | Should -Match ([regex]::Escape('&lt;script&gt;alert(1)&lt;/script&gt;'))
            $body | Should -Not -Match '<script'
        }

        It 'Edge_ReportAndCsvsAreWrittenUnderOutputPath' {
            $out = New-OutDir
            $r = Invoke-Entry @{ OutputPath = $out }
            foreach ($p in @($r.Files.Html, $r.Files.RulesCsv, $r.Files.DelegatesCsv, $r.Files.TraceCsv)) { Test-Path -LiteralPath $p | Should -BeTrue }
            [IO.Path]::GetFileName($r.Files.Html) | Should -Match '^MailboxCheck_accounts_contoso\.com_\d{4}-\d{2}-\d{2}_\d{6}\.html$'
        }
    }

    Context 'AC22 connect and disconnect' {
        It 'AC22_DisconnectsWhatItConnected: no session -> Connect-ExchangeOnline -ShowBanner:$false once, Disconnect once' {
            New-Scenario @{ Session = $false }
            $null = Invoke-Entry
            Should -Invoke Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter { -not $ShowBanner }
            Should -Invoke Disconnect-ExchangeOnline -Times 1 -Exactly
        }

        It 'AC22_ReusesAnExistingSessionAndLeavesItOpen' {
            New-Scenario @{ Session = $true }
            $null = Invoke-Entry
            Should -Invoke Connect-ExchangeOnline -Times 0 -Exactly
            Should -Invoke Disconnect-ExchangeOnline -Times 0 -Exactly
            $script:Events | Should -Contain 'EXO-MAILBOX'
        }
    }

    Context 'AC24 load functions only' {
        It 'AC24_LoadFunctionsOnlyDefinesFunctionsAndConnectsToNothing' {
            . $script:Entry -LoadFunctionsOnly
            foreach ($f in 'Get-MailboxDelegates', 'Test-ExternalAddress', 'Get-InboxRuleSigns', 'Get-ForwardingSigns', 'Get-MailboxCheckAssessment', 'ConvertTo-MailboxCheckHtml', 'Get-MailboxCheckNote') {
                Get-Command -Name $f -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$f must be defined"
            }
            Should -Invoke Connect-ExchangeOnline -Times 0 -Exactly
            Should -Invoke Get-EXOMailbox -Times 0 -Exactly
            Should -Invoke Get-EXOMailboxStatistics -Times 0 -Exactly
            Should -Invoke Get-EXOMailboxPermission -Times 0 -Exactly
            Should -Invoke Get-EXORecipientPermission -Times 0 -Exactly
        }
    }

    Context 'edge cases, end to end' {
        It 'Edge_SingleObjectPermissionResultsAreHandled (no .Count on a lone object)' {
            New-Scenario @{
                MbxPerms = [PSCustomObject]@{ User = 'jdoe@contoso.com'; AccessRights = @('FullAccess'); IsInherited = $false; Deny = $false }
                RecipPerms = [PSCustomObject]@{ Trustee = 'jdoe@contoso.com'; AccessRights = @('SendAs'); AccessControlType = 'Allow'; IsInherited = $false }
                Rules = (New-Rule)
            }
            $r = Invoke-Entry
            $r.ExitCode | Should -Be 0
            @($r.Facts.Rules).Count | Should -Be 1
        }

        It 'Edge_SharedMailboxWithoutArchiveReadsAsFacts' {
            New-Scenario @{ Mailbox = (New-Mbx @{ RecipientTypeDetails = 'SharedMailbox' }) }
            $r = Invoke-Entry
            $r.ExitCode | Should -Be 0
            ($r.Facts.FactRows | Where-Object { $_.Item -eq 'Mailbox type' }).Value | Should -Match 'Shared'
            ($r.Facts.FactRows | Where-Object { $_.Item -eq 'Archive' }).Value | Should -Match 'No archive'
        }

        It 'Edge_MailboxStatisticsFailureIsListedAsCouldNotCheck' {
            Mock Get-EXOMailboxStatistics { throw 'stats denied' }
            $r = Invoke-Entry
            @($r.Assessment.CouldNotCheck | Where-Object { $_ }).Count | Should -BeGreaterThan 0 -Because 'a section that failed is always listed (AC18, AC19 spirit)'
            $size = @($r.Assessment.CouldNotCheck | Where-Object { $_.Source -eq 'Mailbox size' })
            $size.Count | Should -Be 1 -Because 'the failed section is named'
            $size[0].Reason | Should -Match 'stats denied' -Because 'the reason is the error'
            ($r.Facts.FactRows | Where-Object { $_.Item -eq 'Total size' }).Value | Should -Be 'not available'
            $r.ExitCode | Should -Be 2 -Because 'a section that could not be read never gives the all-clear'
            ($r.Assessment.Lines -join "`n") | Should -Not -Match 'No takeover signs found'
            (ConvertTo-Json -InputObject @($r.TicketNote.RuledOut) -Compress) | Should -Not -Match '(?i)size'
        }

        It 'Edge_AcceptedDomainsFailureNeverGivesTheAllClear' {
            Mock Get-AcceptedDomain { throw 'The accepted domains could not be read.' }
            $r = Invoke-Entry
            $r.Status | Should -Be 'Ok'
            $r.Assessment.Verdict | Should -Not -Be 'AllChecked'
            $r.ExitCode | Should -Be 2
            @($r.Assessment.CouldNotCheck | Where-Object { $_.Source -eq 'Accepted domains' }).Count | Should -Be 1
            ($r.Assessment.Lines -join "`n") | Should -Not -Match 'No takeover signs found'
        }

        It 'Edge_ExternalRelayDomainIsOutside: a rule forwarding to an ExternalRelay accepted domain is a sign' {
            $accepted = @($script:Scn.Accepted) + @([PSCustomObject]@{ DomainName = 'fabrikam.com'; Name = 'fabrikam.com'; InitialDomain = $false; Default = $false; DomainType = 'ExternalRelay' })
            New-Scenario @{ Accepted = $accepted; Rules = @((New-Rule @{ Name = 'Relay'; ForwardTo = @('"A" [SMTP:a@fabrikam.com]') })) }
            $r = Invoke-Entry
            $s = @($r.Assessment.Signs | Where-Object { $_.Kind -eq 'ExternalRuleForward' })
            $s.Count | Should -Be 1
            $s[0].Domain | Should -Be 'fabrikam.com'
            @($r.Tenant.AcceptedDomains) | Should -Not -Contain 'fabrikam.com'
        }

        It 'Edge_RuleNamesLoseControlCharactersAndAreCutTo100' {
            $esc = [string][char]27
            $long = 'L' * 300
            New-Scenario @{ Rules = @(
                    (New-Rule @{ Name = "Evil`r`nRuled out: all clear"; Identity = 'a'; DeleteMessage = $true }),
                    (New-Rule @{ Name = "Wipe$esc[2J"; Identity = 'b'; DeleteMessage = $true }),
                    (New-Rule @{ Name = $long; Identity = 'c'; DeleteMessage = $true })) }
            $r = Invoke-Entry
            foreach ($rule in @($r.Facts.Rules)) {
                $rule.Name | Should -Not -Match '\p{Cc}'
                $rule.Name.Length | Should -BeLessOrEqual 100
            }
            foreach ($s in @($r.Assessment.Signs)) {
                $s.RuleName | Should -Not -Match '\p{Cc}'
                $s.RuleName.Length | Should -BeLessOrEqual 100
                $s.Message | Should -Not -Match '\p{Cc}'
            }
            @($r.Assessment.Signs).Count | Should -Be 3
            (Get-HostText) | Should -Not -Match ([regex]::Escape($esc))
            @((Get-HostText) -split "`n" | Where-Object { $_ -match '^Ruled out: all clear' }).Count | Should -Be 0
            . (Join-Path $script:Root 'CaseKit.ps1')
            foreach ($paste in @($false, $true)) {
                $lines = @(ConvertTo-TicketNoteText -Note $r.TicketNote -PasteSafe:$paste)
                @($lines | ForEach-Object { $_ -split '\r?\n' } | Where-Object { $_ -match '^Ruled out:' }).Count | Should -Be 1 -Because 'a rule name must not forge a note section'
                ($lines -join "`n") | Should -Not -Match ([regex]::Escape($esc))
            }
        }

        It 'Edge_TraceWindowEndsAtTheRunTime ($Now), not a second clock read' {
            . $script:Entry -LoadFunctionsOnly
            $now = [datetime]::SpecifyKind([datetime]'2026-03-01T12:00:00', [DateTimeKind]::Utc)
            $conn = [PSCustomObject]@{ State = 'Connected'; UserPrincipalName = $script:Scn.Me; TenantID = $script:Scn.TenantGuid }
            $r = Invoke-M365MailboxCheck -Identity 'accounts@contoso.com' -Connection $conn -TraceDays 3 -Now $now -Quiet
            $r.Status | Should -Be 'Ok'
            $script:TraceCalls.Count | Should -Be 2
            foreach ($c in $script:TraceCalls) {
                ([datetime]$c.EndDate).ToUniversalTime() | Should -Be $now
                ([datetime]$c.StartDate).ToUniversalTime() | Should -Be $now.AddDays(-3)
            }
        }

        It 'Edge_HiddenListFailureKeepsTheSignsAndMarksHiddenUnknown' {
            New-Scenario @{ Rules = @((New-Rule @{ Name = 'Fwd'; ForwardTo = @('x@gmail.com') })) }
            Mock Get-InboxRule {
                $script:RuleCalls.Add(@{ IncludeHidden = [bool]$IncludeHidden })
                if (-not $IncludeHidden) { throw 'The server is busy.' }
                @($script:Scn.Rules)
            }
            $r = Invoke-Entry
            @($r.Assessment.Signs | ForEach-Object { $_.Kind }) | Should -Contain 'ExternalRuleForward'
            @($r.Assessment.CouldNotCheck | Where-Object { $_.Source -eq 'Hidden inbox rules' }).Count | Should -Be 1
            @($r.Facts.Rules)[0].HiddenState | Should -Be 'Unknown'

            New-Scenario
            $r2 = Invoke-Entry
            $r2.ExitCode | Should -Be 2 -Because 'hidden rules were not told apart, so nothing is ruled out'
            ($r2.TicketNote.RuledOut -join "`n") | Should -Not -Match 'Inbox rules'
        }

        It 'Edge_NoteRuledOutLineSaysWhatWasMatched' {
            $r = Invoke-Entry
            ($r.TicketNote.RuledOut -join "`n") | Should -Match ([regex]::Escape('no rule matched the checks this tool runs (English folder names)'))
        }
    }

    Context 'ForwardingAddress (a recipient object)' {
        It 'AC6_ForwardingAddressToAnOutsideMailContactIsExternalForwarding: resolved read-only with Get-EXORecipient' {
            New-Scenario @{
                Mailbox = (New-Mbx @{ ForwardingAddress = 'Outside Contact' })
                Recipient = [PSCustomObject]@{ Name = 'Outside Contact'; RecipientTypeDetails = 'MailContact'; ExternalEmailAddress = 'SMTP:x@gmail.com'; PrimarySmtpAddress = 'x@gmail.com' }
            }
            $r = Invoke-Entry
            Should -Invoke Get-EXORecipient -Times 1 -Exactly -ParameterFilter { $Identity -eq 'Outside Contact' -and @($Properties) -contains 'ExternalEmailAddress' -and @($Properties) -contains 'PrimarySmtpAddress' -and @($Properties) -contains 'RecipientTypeDetails' }
            $s = @($r.Assessment.Signs | Where-Object { $_.Kind -eq 'ExternalForwarding' })
            $s.Count | Should -Be 1
            $s[0].Domain | Should -Be 'gmail.com'
            $s[0].Message | Should -Not -Match 'Outside Contact|x@gmail'
            $r.ExitCode | Should -Be 1
            ($r.TicketNote.RuledOut -join "`n") | Should -Not -Match 'Mailbox forwarding'
        }

        It 'AC7_ForwardingAddressToAnInternalMailboxIsAFact: all clear' {
            New-Scenario @{
                Mailbox = (New-Mbx @{ ForwardingAddress = 'Jane Doe' })
                Recipient = [PSCustomObject]@{ Name = 'Jane Doe'; RecipientTypeDetails = 'UserMailbox'; ExternalEmailAddress = $null; PrimarySmtpAddress = 'jane@contoso.com' }
            }
            $r = Invoke-Entry
            $r.ExitCode | Should -Be 0
            ($r.TicketNote.RuledOut -join "`n") | Should -Match 'Mailbox forwarding'
        }

        It 'Edge_ForwardingAddressThatCannotBeJudgedIsCouldNotCheck, never the "nothing is forwarded" line' {
            $cases = @(
                @{ Recipient = $null; RecipientThrow = "The operation couldn't be performed because object 'Outside Contact' couldn't be found." },
                @{ Recipient = $null; RecipientThrow = $null },
                @{ Recipient = [PSCustomObject]@{ Name = 'Odd'; RecipientTypeDetails = 'MailContact'; ExternalEmailAddress = 'X500:/o=Other'; PrimarySmtpAddress = $null }; RecipientThrow = $null })
            foreach ($c in $cases) {
                New-Scenario @{ Mailbox = (New-Mbx @{ ForwardingAddress = 'Outside Contact' }); Recipient = $c.Recipient; RecipientThrow = $c.RecipientThrow }
                $r = Invoke-Entry
                @($r.Assessment.CouldNotCheck | Where-Object { $_.Source -eq 'Mailbox forwarding' }).Count | Should -Be 1
                $r.ExitCode | Should -Be 2
                ($r.TicketNote.RuledOut -join "`n") | Should -Not -Match 'Mailbox forwarding|nothing is forwarded'
            }
        }

        It 'Edge_ForwardingSmtpAddressThatIsNotAnAddressIsCouldNotCheck' {
            New-Scenario @{ Mailbox = (New-Mbx @{ ForwardingSmtpAddress = 'smtp:not-an-address' }) }
            $r = Invoke-Entry
            @($r.Assessment.CouldNotCheck | Where-Object { $_.Source -eq 'Mailbox forwarding' }).Count | Should -Be 1
            $r.ExitCode | Should -Be 2
        }
    }

    Context 'AC19 the note never carries raw error text' {
        It 'AC19_RawErrorTextNeverReachesTheNote: fixed reasons per section, fixed PARTLY CHECKED headline' {
            New-Scenario @{
                RulesThrow = "Access is denied. The user x@gmail.com isn't assigned to any management roles."
                TraceThrow = 'The request for vendor@fabrikam.com timed out.'
            }
            $r = Invoke-Entry
            ($r.Assessment.Lines -join "`n") | Should -Match 'x@gmail\.com' -Because 'the console and the HTML keep the raw reason'
            . (Join-Path $script:Root 'CaseKit.ps1')
            foreach ($paste in @($false, $true)) {
                $lines = @(ConvertTo-TicketNoteText -Note $r.TicketNote -PasteSafe:$paste)
                $text = $lines -join "`n"
                $text | Should -Not -Match 'x@gmail\.com'
                $text | Should -Not -Match 'vendor@fabrikam\.com'
                $lines[0] | Should -BeExactly '[Ticket note] M365-MailboxCheck: PARTLY CHECKED - see Could not check'
            }
            $cnc = $r.TicketNote.CouldNotCheck -join "`n"
            $cnc | Should -Match 'Inbox rules: .*Recipient Management'
            $cnc | Should -Match ([regex]::Escape('Message trace: could not be read (see the report)'))

            New-Scenario @{ MailboxThrow = 'Server error while reading x@gmail.com' }
            $r2 = Invoke-Entry
            $r2.Status | Should -Be 'Error'
            foreach ($paste in @($false, $true)) {
                (ConvertTo-TicketNoteText -Note $r2.TicketNote -PasteSafe:$paste) -join "`n" | Should -Not -Match 'x@gmail\.com'
            }
        }

        It 'AC19_ForwardingRecipientLookupErrorNeverReachesTheNote: neither the error nor the ForwardingAddress' {
            New-Scenario @{
                Mailbox = (New-Mbx @{ ForwardingAddress = 'leak.target@fabrikam.com' })
                RecipientThrow = 'The server could not resolve secret.person@gmail.com right now.'
            }
            $r = Invoke-Entry
            $r.ExitCode | Should -Be 2
            $gate = @($r.Assessment.CouldNotCheck | Where-Object { $_.Source -eq 'Mailbox forwarding' })
            $gate.Count | Should -Be 1
            $gate[0].Reason | Should -Match 'secret\.person@gmail\.com' -Because 'the console and the HTML keep the raw reason'
            $gate[0].Reason | Should -Match 'leak\.target@fabrikam\.com'
            . (Join-Path $script:Root 'CaseKit.ps1')
            foreach ($paste in @($false, $true)) {
                $text = (ConvertTo-TicketNoteText -Note $r.TicketNote -PasteSafe:$paste) -join "`n"
                $text | Should -Not -Match 'secret\.person|gmail\.com'
                $text | Should -Not -Match 'leak\.target|fabrikam\.com'
                $text | Should -Match 'Mailbox forwarding: the forwarding recipient could not be looked up'
            }
        }

        It 'AC19_HiddenRulesErrorNeverReachesTheNote: the second Get-InboxRule fails with an address in the error' {
            Mock Get-InboxRule {
                $script:RuleCalls.Add(@{ IncludeHidden = [bool]$IncludeHidden })
                if (-not $IncludeHidden) { throw 'Mailbox hidden.person@gmail.com is busy; try again later.' }
                @($script:Scn.Rules)
            }
            $r = Invoke-Entry
            $r.ExitCode | Should -Be 2
            $gate = @($r.Assessment.CouldNotCheck | Where-Object { $_.Source -eq 'Hidden inbox rules' })
            $gate.Count | Should -Be 1
            $gate[0].Reason | Should -Match 'hidden\.person@gmail\.com'
            . (Join-Path $script:Root 'CaseKit.ps1')
            foreach ($paste in @($false, $true)) {
                $text = (ConvertTo-TicketNoteText -Note $r.TicketNote -PasteSafe:$paste) -join "`n"
                $text | Should -Not -Match 'hidden\.person|gmail\.com'
                $text | Should -Match ([regex]::Escape('Hidden inbox rules: could not be read (see the report)'))
            }
        }
    }

    Context 'AC22 only this run''s connection' {
        It 'AC22_DisconnectsOnlyItsOwnConnection: an existing EOP-only session stays open' {
            New-Scenario @{ Session = $false }
            Mock Get-ConnectionInformation {
                [PSCustomObject]@{ State = 'Connected'; Name = 'ExchangeOnlineProtection_1'; ConnectionId = 'eop-1'; IsEopSession = $true; UserPrincipalName = $script:Scn.Me; TenantID = $script:Scn.TenantGuid }
                if ($script:Connected) { [PSCustomObject]@{ State = 'Connected'; Name = 'ExchangeOnline_2'; ConnectionId = 'exo-2'; IsEopSession = $false; UserPrincipalName = $script:Scn.Me; TenantID = $script:Scn.TenantGuid } }
            }
            $r = Invoke-Entry
            $r.Status | Should -Be 'Ok'
            Should -Invoke Connect-ExchangeOnline -Times 1 -Exactly
            Should -Invoke Disconnect-ExchangeOnline -Times 1 -Exactly
            Should -Invoke Disconnect-ExchangeOnline -Times 1 -Exactly -ParameterFilter { @($ConnectionId) -contains 'exo-2' -and @($ConnectionId) -notcontains 'eop-1' }
        }

        It 'AC22_MoreThanOneExchangeConnectionWarnsInTheBanner' {
            Mock Get-ConnectionInformation {
                [PSCustomObject]@{ State = 'Connected'; Name = 'ExchangeOnline_1'; ConnectionId = 'a'; IsEopSession = $false; UserPrincipalName = $script:Scn.Me; TenantID = $script:Scn.TenantGuid }
                [PSCustomObject]@{ State = 'Connected'; Name = 'ExchangeOnline_2'; ConnectionId = 'b'; IsEopSession = $false; UserPrincipalName = 'admin@fabrikam.onmicrosoft.com'; TenantID = '99999999-2222-3333-4444-555555555555' }
            }
            $null = Invoke-Entry
            $i = $script:Events.IndexOf('EXO-MAILBOX')
            $i | Should -BeGreaterThan 0
            $before = ($script:Events[0..($i - 1)] | Where-Object { $_ -like 'HOST:*' }) -join "`n"
            $before | Should -Match '\[WARN\] 2 Exchange Online connections'
            Should -Invoke Disconnect-ExchangeOnline -Times 0 -Exactly
        }
    }
}

Describe 'pure functions (MailboxCheck.Core.ps1)' {
    BeforeAll { . $script:Core }

    Context 'AC3 to AC5 delegates' {
        It 'AC3_FullAccessListsOnlyExplicitAllowedGrants: SELF, inherited and Deny entries are dropped' {
            $perm = @(
                [PSCustomObject]@{ User = 'NT AUTHORITY\SELF'; AccessRights = @('FullAccess'); IsInherited = $false; Deny = $false },
                [PSCustomObject]@{ User = 'inherited@contoso.com'; AccessRights = @('FullAccess'); IsInherited = $true; Deny = $false },
                [PSCustomObject]@{ User = 'denied@contoso.com'; AccessRights = @('FullAccess'); IsInherited = $false; Deny = $true },
                [PSCustomObject]@{ User = 'jdoe@contoso.com'; AccessRights = @('FullAccess'); IsInherited = $false; Deny = $false })
            @(Get-MailboxDelegates -Kind FullAccess -Permission $perm) | Should -Be @('jdoe@contoso.com')
        }

        It 'AC4_SendAsListsOnlyTheGrantedTrustee' {
            $perm = @(
                [PSCustomObject]@{ Trustee = 'NT AUTHORITY\SELF'; AccessRights = @('SendAs'); AccessControlType = 'Allow'; IsInherited = $false },
                [PSCustomObject]@{ Trustee = 'jdoe@contoso.com'; AccessRights = @('SendAs'); AccessControlType = 'Allow'; IsInherited = $false })
            @(Get-MailboxDelegates -Kind SendAs -Permission $perm) | Should -Be @('jdoe@contoso.com')
        }

        It 'AC5_SendOnBehalfListsTheRecipient_AndEmptyReadsNobody' {
            @(Get-MailboxDelegates -Kind SendOnBehalf -Permission @('jdoe@contoso.com')) | Should -Be @('jdoe@contoso.com')
            $none = @(Get-MailboxDelegates -Kind SendOnBehalf -Permission @())
            $none.Count | Should -Be 0
            Format-MailboxDelegateList -Delegate $none | Should -Be 'Nobody'
            Format-MailboxDelegateList -Delegate @('jdoe@contoso.com') | Should -Be 'jdoe@contoso.com'
        }
    }

    Context 'AC6 and AC7 mailbox forwarding' {
        It 'AC6_ExternalForwardingRaisesASignNamingTheDomainAndCopy' {
            foreach ($keep in $true, $false) {
                $m = New-Mbx @{ ForwardingSmtpAddress = 'smtp:x@gmail.com'; DeliverToMailboxAndForward = $keep }
                $signs = @(Get-ForwardingSigns -Mailbox $m -AcceptedDomain @('contoso.com'))
                $signs.Count | Should -Be 1
                $signs[0].Kind | Should -Be 'ExternalForwarding'
                $signs[0].Domain | Should -Be 'gmail.com'
                $signs[0].Message | Should -Match 'gmail\.com'
                $signs[0].Message | Should -Match 'copy'
                $signs[0].KeepsCopy | Should -Be $keep
            }
        }

        It 'AC7_InternalForwardingIsAFactNotASign' {
            $m = New-Mbx @{ ForwardingSmtpAddress = 'smtp:colleague@mail.CONTOSO.com'; DeliverToMailboxAndForward = $true }
            @(Get-ForwardingSigns -Mailbox $m -AcceptedDomain @('contoso.com')).Count | Should -Be 0
            $rows = @(Get-MailboxFactRows -Mailbox $m -Statistics $null -ArchiveStatistics $null)
            ($rows | Where-Object { $_.Item -eq 'Mail forwarding' }).Value | Should -Match 'colleague@mail\.CONTOSO\.com'
        }

        It 'Edge_ForwardingAddressRecipientObjectIsInternalAndShown' {
            $m = New-Mbx @{ ForwardingAddress = 'Jane Doe' }
            @(Get-ForwardingSigns -Mailbox $m -AcceptedDomain @('contoso.com')).Count | Should -Be 0
            $rows = @(Get-MailboxFactRows -Mailbox $m -Statistics $null -ArchiveStatistics $null)
            ($rows | Where-Object { $_.Item -eq 'Mail forwarding' }).Value | Should -Match 'Jane Doe'
        }

        It 'Edge_TestExternalAddress: case, subdomains, wildcard accepted domains and address formats' {
            Test-ExternalAddress -Address 'x@gmail.com' -AcceptedDomain @('contoso.com') | Should -BeTrue
            Test-ExternalAddress -Address 'smtp:x@gmail.com' -AcceptedDomain @('contoso.com') | Should -BeTrue
            Test-ExternalAddress -Address '"X Y" [SMTP:x@gmail.com]' -AcceptedDomain @('contoso.com') | Should -BeTrue
            Test-ExternalAddress -Address 'a@CONTOSO.com' -AcceptedDomain @('contoso.com') | Should -BeFalse
            Test-ExternalAddress -Address 'a@mail.contoso.com' -AcceptedDomain @('Contoso.com') | Should -BeFalse
            Test-ExternalAddress -Address 'a@fabrikam.com' -AcceptedDomain @('*.fabrikam.com') | Should -BeFalse
            Test-ExternalAddress -Address 'a@evilcontoso.com' -AcceptedDomain @('contoso.com') | Should -BeTrue -Because 'a longer name that merely ends with the accepted text is another domain'
        }

        It 'Edge_AddressScope: Internal only when positively internal, Unknown for anything unparseable' {
            $acc = @('contoso.com')
            Get-MailboxAddressScope -Address 'x@gmail.com' -AcceptedDomain $acc | Should -BeExactly 'External'
            Get-MailboxAddressScope -Address 'a@mail.contoso.com' -AcceptedDomain $acc | Should -BeExactly 'Unknown' -Because 'a subdomain that is not itself accepted is not positively inside'
            Get-MailboxAddressScope -Address '"Jane Doe" [EX:/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=abc-jane]' -AcceptedDomain $acc | Should -BeExactly 'Internal'
            Get-MailboxAddressScope -Address '/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=abc-jane' -AcceptedDomain $acc | Should -BeExactly 'Internal'
            Get-MailboxAddressScope -Address '"x@gmail.com" [EX:/o=ExchangeLabs/cn=Recipients/cn=abc]' -AcceptedDomain $acc | Should -BeExactly 'Internal' -Because 'the display name is not the address'
            Get-MailboxAddressScope -Address 'Jane Doe' -AcceptedDomain $acc | Should -BeExactly 'Unknown'
            Get-MailboxAddressScope -Address 'smtp:not-an-address' -AcceptedDomain $acc | Should -BeExactly 'Unknown'
            Get-MailboxAddressScope -Address '' -AcceptedDomain $acc | Should -BeExactly 'Unknown'
            Test-ExternalAddress -Address 'Jane Doe' -AcceptedDomain $acc | Should -BeFalse
        }

        It 'Edge_SubdomainIsInternalOnlyWhenAcceptedItselfOrByAWildcard' {
            Get-MailboxAddressScope -Address 'a@mail.contoso.com' -AcceptedDomain @('contoso.com', 'mail.contoso.com') | Should -BeExactly 'Internal'
            Get-MailboxAddressScope -Address 'a@MAIL.contoso.com' -AcceptedDomain @('*.contoso.com') | Should -BeExactly 'Internal'
            Get-MailboxAddressScope -Address 'a@deep.mail.contoso.com' -AcceptedDomain @('*.contoso.com') | Should -BeExactly 'Internal'
            Get-MailboxAddressScope -Address 'a@contoso.com' -AcceptedDomain @('*.contoso.com') | Should -BeExactly 'Internal'
            Get-MailboxAddressScope -Address 'a@mail.contoso.com' -AcceptedDomain @('contoso.com') | Should -BeExactly 'Unknown'
            Get-MailboxAddressScope -Address 'a@evilcontoso.com' -AcceptedDomain @('*.contoso.com') | Should -BeExactly 'External'
            # Unknown is never inside: a rule forwarding there is a sign, mailbox forwarding there is Could not check.
            $rule = New-Rule @{ Name = 'Sub'; ForwardTo = @('a@mail.contoso.com') }
            @(Get-InboxRuleSigns -Rule @($rule) -AcceptedDomain @('contoso.com') | ForEach-Object { $_.Kind }) | Should -Contain 'UnclassifiedRuleForward'
            (Get-MailboxForwardingGate -Mailbox (New-Mbx @{ ForwardingSmtpAddress = 'smtp:a@mail.contoso.com' }) -AcceptedDomain @('contoso.com')).State | Should -Be 'CouldNotCheck'
        }

        It 'Edge_DomainWithControlCharactersIsUnknown' {
            foreach ($cc in @([char]0x1B, [char]0x00, [char]0x07, [char]0x7F)) {
                $addr = 'x@contoso.com' + $cc + 'evil'
                Get-MailboxAddressDomain -Address $addr | Should -BeExactly ''
                Get-MailboxAddressScope -Address $addr -AcceptedDomain @('contoso.com') | Should -BeExactly 'Unknown'
            }
            Get-MailboxAddressDomain -Address ('x@' + [char]0x1B + 'gmail.com') | Should -BeExactly ''
        }

        It 'Edge_MailUserAndContactAreJudgedByExternalAddressOnly (a tenant PrimarySmtpAddress is never a false Internal)' {
            $acc = @('contoso.com')
            $m = New-Mbx @{ ForwardingAddress = 'Partner' }
            foreach ($type in 'MailUser', 'MailContact', 'GuestMailUser') {
                $noExternal = [PSCustomObject]@{ Name = 'Partner'; RecipientTypeDetails = $type; ExternalEmailAddress = $null; PrimarySmtpAddress = 'partner@contoso.com' }
                Get-ForwardingRecipientAddress -Recipient $noExternal | Should -BeExactly ''
                @(Get-ForwardingSigns -Mailbox $m -ForwardingRecipient $noExternal -AcceptedDomain $acc).Count | Should -Be 0
                $g = Get-MailboxForwardingGate -Mailbox $m -ForwardingRecipient $noExternal -AcceptedDomain $acc
                $g.State | Should -Be 'CouldNotCheck' -Because "$type delivers to its ExternalEmailAddress; without one, where the mail goes is not known"
                $g.NoteReason | Should -BeExactly 'the forwarding recipient has no external address to judge (see the report).'
                $g.NoteReason | Should -Not -Match 'Partner|contoso'
            }

            $contact = [PSCustomObject]@{ Name = 'Partner'; RecipientTypeDetails = 'MailContact'; ExternalEmailAddress = 'SMTP:x@gmail.com'; PrimarySmtpAddress = 'partner@contoso.com' }
            $signs = @(Get-ForwardingSigns -Mailbox $m -ForwardingRecipient $contact -AcceptedDomain $acc)
            $signs.Count | Should -Be 1
            $signs[0].Kind | Should -Be 'ExternalForwarding'
            $signs[0].Domain | Should -Be 'gmail.com'
            (Get-MailboxForwardingGate -Mailbox $m -ForwardingRecipient $contact -AcceptedDomain $acc).State | Should -Be 'Checked'

            $mailbox = [PSCustomObject]@{ Name = 'Jane'; RecipientTypeDetails = 'UserMailbox'; ExternalEmailAddress = $null; PrimarySmtpAddress = 'jane@contoso.com' }
            Get-ForwardingRecipientAddress -Recipient $mailbox | Should -BeExactly 'jane@contoso.com'
            @(Get-ForwardingSigns -Mailbox $m -ForwardingRecipient $mailbox -AcceptedDomain $acc).Count | Should -Be 0
            (Get-MailboxForwardingGate -Mailbox $m -ForwardingRecipient $mailbox -AcceptedDomain $acc).State | Should -Be 'Checked'
        }

        It 'Edge_SmtpGroupWinsOverAnAddressLookingDisplayName' {
            Get-MailboxAddressFromText -Text '"boss@contoso.com" [SMTP:x@gmail.com]' | Should -Be 'x@gmail.com'
            Get-MailboxAddressScope -Address '"boss@contoso.com" [SMTP:x@gmail.com]' -AcceptedDomain @('contoso.com') | Should -BeExactly 'External'
            $rule = New-Rule @{ Name = 'Disguised'; RedirectTo = @('"boss@contoso.com" [SMTP:x@gmail.com]') }
            @(Get-InboxRuleSigns -Rule @($rule) -AcceptedDomain @('contoso.com') | Where-Object { $_.Kind -eq 'ExternalRuleForward' }).Count | Should -Be 1
        }

        It 'AC6_ForwardingRecipientOutsideRaisesExternalForwarding; the gate is Checked only when every forwarding target was judged' {
            $m = New-Mbx @{ ForwardingAddress = 'Outside Contact'; DeliverToMailboxAndForward = $true }
            $contact = [PSCustomObject]@{ Name = 'Outside Contact'; RecipientTypeDetails = 'MailContact'; ExternalEmailAddress = 'SMTP:x@gmail.com'; PrimarySmtpAddress = 'x@gmail.com' }
            $signs = @(Get-ForwardingSigns -Mailbox $m -ForwardingRecipient $contact -AcceptedDomain @('contoso.com'))
            $signs.Count | Should -Be 1
            $signs[0].Kind | Should -Be 'ExternalForwarding'
            $signs[0].Domain | Should -Be 'gmail.com'
            $signs[0].KeepsCopy | Should -BeTrue
            (Get-MailboxForwardingGate -Mailbox $m -ForwardingRecipient $contact -AcceptedDomain @('contoso.com')).State | Should -Be 'Checked'

            $internal = [PSCustomObject]@{ Name = 'Jane'; RecipientTypeDetails = 'UserMailbox'; ExternalEmailAddress = $null; PrimarySmtpAddress = 'jane@contoso.com' }
            @(Get-ForwardingSigns -Mailbox $m -ForwardingRecipient $internal -AcceptedDomain @('contoso.com')).Count | Should -Be 0
            (Get-MailboxForwardingGate -Mailbox $m -ForwardingRecipient $internal -AcceptedDomain @('contoso.com')).State | Should -Be 'Checked'

            (Get-MailboxForwardingGate -Mailbox $m -AcceptedDomain @('contoso.com')).State | Should -Be 'CouldNotCheck' -Because 'an unresolved recipient is not judged'
            $denied = Get-MailboxForwardingGate -Mailbox $m -LookupError 'Access is denied.' -AcceptedDomain @('contoso.com')
            $denied.State | Should -Be 'CouldNotCheck'
            $denied.Reason | Should -Match 'Recipient Management'
            (Get-MailboxForwardingGate -Mailbox (New-Mbx @{ ForwardingSmtpAddress = 'smtp:garbage' }) -AcceptedDomain @('contoso.com')).State | Should -Be 'CouldNotCheck'
            (Get-MailboxForwardingGate -Mailbox (New-Mbx) -AcceptedDomain @('contoso.com')).State | Should -Be 'Checked'
        }
    }

    Context 'AC8 to AC11 inbox rule signs' {
        It 'AC8_ExternalRuleForwardForEachActionProperty (ForwardTo, ForwardAsAttachmentTo, RedirectTo)' {
            foreach ($prop in 'ForwardTo', 'ForwardAsAttachmentTo', 'RedirectTo') {
                $rule = New-Rule @{ Name = "R-$prop"; $prop = @('"X" [SMTP:x@gmail.com]') }
                $signs = @(Get-InboxRuleSigns -Rule @($rule) -AcceptedDomain @('contoso.com'))
                @($signs | Where-Object { $_.Kind -eq 'ExternalRuleForward' -and $_.RuleName -eq "R-$prop" }).Count | Should -Be 1 -Because $prop
            }
            $internal = New-Rule @{ Name = 'Internal'; ForwardTo = @('colleague@contoso.com') }
            @(Get-InboxRuleSigns -Rule @($internal) -AcceptedDomain @('contoso.com')).Count | Should -Be 0
        }

        It 'AC9_DeleteActionsRaiseRuleDeletesMail' {
            foreach ($prop in 'DeleteMessage', 'SoftDeleteMessage') {
                $rule = New-Rule @{ Name = "D-$prop"; $prop = $true }
                $signs = @(Get-InboxRuleSigns -Rule @($rule) -AcceptedDomain @('contoso.com'))
                @($signs | Where-Object { $_.Kind -eq 'RuleDeletesMail' -and $_.RuleName -eq "D-$prop" }).Count | Should -Be 1 -Because $prop
            }
        }

        It 'AC10_MovesToHidingFoldersRaiseRuleHidesMail; an ordinary folder does not' {
            foreach ($folder in 'RSS Feeds', 'RSS Subscriptions', 'Conversation History', 'Deleted Items', 'Junk Email', 'Archive') {
                $rule = New-Rule @{ Name = "M-$folder"; MoveToFolder = "accounts@contoso.com:\$folder" }
                $signs = @(Get-InboxRuleSigns -Rule @($rule) -AcceptedDomain @('contoso.com'))
                @($signs | Where-Object { $_.Kind -eq 'RuleHidesMail' }).Count | Should -Be 1 -Because $folder
            }
            $readMove = New-Rule @{ Name = 'MoveRead'; MoveToFolder = 'accounts@contoso.com:\Projects'; MarkAsRead = $true }
            @(Get-InboxRuleSigns -Rule @($readMove) -AcceptedDomain @('contoso.com') | Where-Object { $_.Kind -eq 'RuleHidesMail' }).Count | Should -Be 1
            $plain = New-Rule @{ Name = 'MovePlain'; MoveToFolder = 'accounts@contoso.com:\Projects' }
            @(Get-InboxRuleSigns -Rule @($plain) -AcceptedDomain @('contoso.com')).Count | Should -Be 0
        }

        It 'AC11_OnlyNonSystemHiddenRulesRaiseHiddenRule: the built-in junk rule is listed but raises nothing' {
            $junk = New-Rule @{ Name = 'Junk E-mail Rule'; IsHidden = $true }
            $other = New-Rule @{ Name = 'x'; IsHidden = $true }
            $signs = @(Get-InboxRuleSigns -Rule @($junk, $other) -AcceptedDomain @('contoso.com'))
            @($signs | Where-Object { $_.Kind -eq 'HiddenRule' }).Count | Should -Be 1
            @($signs | Where-Object { $_.Kind -eq 'HiddenRule' })[0].RuleName | Should -Be 'x'
        }

        It 'AC11_JunkRuleNameWithActionsIsNotExempt' {
            foreach ($set in @(@{ ForwardTo = @('x@gmail.com') }, @{ RedirectTo = @('colleague@contoso.com') }, @{ DeleteMessage = $true }, @{ MoveToFolder = 'accounts@contoso.com:\Projects' }, @{ MarkAsRead = $true })) {
                $set['Name'] = 'Junk E-mail Rule'; $set['IsHidden'] = $true
                $signs = @(Get-InboxRuleSigns -Rule @((New-Rule $set)) -AcceptedDomain @('contoso.com'))
                @($signs | Where-Object { $_.Kind -eq 'HiddenRule' }).Count | Should -Be 1 -Because ($set.Keys -join ',')
            }
        }

        It 'AC11_RuleWithoutAnIdentityIsHiddenUnknown (no match on the name)' {
            $all = @((New-Rule @{ Name = 'Same'; Identity = $null }))
            $visible = @((New-Rule @{ Name = 'Same'; Identity = $null }))
            $list = @(ConvertTo-MailboxRuleList -Rule $all -VisibleRule $visible)
            $list[0].IsHidden | Should -BeFalse
            $list[0].HiddenState | Should -Be 'Unknown'
            $list[0].IdentityMissing | Should -BeTrue
            $signs = @(Get-InboxRuleSigns -Rule $list -AcceptedDomain @('contoso.com') | Where-Object { $_.Kind -eq 'HiddenRule' })
            $signs.Count | Should -Be 1
            $signs[0].Message | Should -Match 'could not tell if .*hidden'

            $known = @(ConvertTo-MailboxRuleList -Rule @((New-Rule @{ Identity = '7' }), (New-Rule @{ Name = 'H'; Identity = '8' })) -VisibleRule @((New-Rule @{ Identity = '7' })))
            @($known | ForEach-Object { $_.HiddenState }) | Should -Be @('Visible', 'Hidden')
            $unknown = @(ConvertTo-MailboxRuleList -Rule @((New-Rule @{ Identity = '7' })) -VisibleRuleUnavailable)
            $unknown[0].HiddenState | Should -Be 'Unknown'
            $unknown[0].IdentityMissing | Should -BeFalse
            @(Get-InboxRuleSigns -Rule $unknown -AcceptedDomain @('contoso.com')).Count | Should -Be 0 -Because 'a failed second call is a could-not-check gate, not a sign per rule'
        }

        It 'AC8_UnclassifiableRuleRecipientRaisesASign' {
            foreach ($prop in 'ForwardTo', 'ForwardAsAttachmentTo', 'RedirectTo') {
                $rule = New-Rule @{ Name = "U-$prop"; $prop = @('Jane Doe') }
                $signs = @(Get-InboxRuleSigns -Rule @($rule) -AcceptedDomain @('contoso.com'))
                $signs.Count | Should -Be 1 -Because $prop
                $signs[0].RuleName | Should -Be "U-$prop"
                $signs[0].Message | Should -Match "Inbox rule 'U-$prop' .*to a recipient this tool could not classify"
            }
            $ex = New-Rule @{ Name = 'Internal EX'; ForwardTo = @('"Jane Doe" [EX:/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=abc-jane]') }
            @(Get-InboxRuleSigns -Rule @($ex) -AcceptedDomain @('contoso.com')).Count | Should -Be 0
        }

        It 'Edge_NoRulesRaiseNothing; a rule with several actions raises each sign' {
            @(Get-InboxRuleSigns -Rule @() -AcceptedDomain @('contoso.com')).Count | Should -Be 0
            $rule = New-Rule @{ Name = 'Multi'; ForwardTo = @('x@gmail.com'); DeleteMessage = $true }
            $kinds = @(Get-InboxRuleSigns -Rule @($rule) -AcceptedDomain @('contoso.com') | ForEach-Object { $_.Kind })
            $kinds | Should -Contain 'ExternalRuleForward'
            $kinds | Should -Contain 'RuleDeletesMail'
        }
    }

    Context 'AC12 facts' {
        It 'AC12_FactsShowTypeSizeQuotaArchiveAndHolds' {
            $m = New-Mbx @{ RecipientTypeDetails = 'UserMailbox'; ArchiveStatus = 'Active'; LitigationHoldEnabled = $true; InPlaceHolds = @('mbx0123abcd', 'UniH4567') }
            $stats = [PSCustomObject]@{ TotalItemSize = '1.5 GB (1,610,612,736 bytes)' }
            $arch = [PSCustomObject]@{ TotalItemSize = '3.2 GB (3,435,973,837 bytes)' }
            $rows = @(Get-MailboxFactRows -Mailbox $m -Statistics $stats -ArchiveStatistics $arch)
            function Val($n) { ($rows | Where-Object { $_.Item -eq $n }).Value }
            Val 'Mailbox type' | Should -Match 'User'
            Val 'Total size' | Should -Match '1\.5 GB'
            Val 'Prohibit-send quota' | Should -Match '49\.5 GB'
            Val 'Archive' | Should -Match '^(On|Yes|Enabled)'
            Val 'Archive size' | Should -Match '3\.2 GB'
            Val 'Litigation hold' | Should -Match '^(On|Yes|Enabled)'
            Val 'Other holds' | Should -Match 'mbx0123abcd'
            Val 'Other holds' | Should -Match 'UniH4567'
        }

        It 'AC12_MissingValuesReadNotAvailable_NeverZeroOrBlank' {
            $m = New-Mbx @{ ProhibitSendQuota = $null; ArchiveStatus = 'Active' }
            $rows = @(Get-MailboxFactRows -Mailbox $m -Statistics $null -ArchiveStatistics $null)
            ($rows | Where-Object { $_.Item -eq 'Total size' }).Value | Should -Be 'not available'
            ($rows | Where-Object { $_.Item -eq 'Prohibit-send quota' }).Value | Should -Be 'not available'
            ($rows | Where-Object { $_.Item -eq 'Archive size' }).Value | Should -Be 'not available'
            foreach ($row in $rows) { [string]$row.Value | Should -Not -BeNullOrEmpty -Because $row.Item; [string]$row.Value | Should -Not -Be '0' -Because $row.Item }
        }

        It 'Edge_ArchiveNotEnabledReadsNoArchive_AndRoomEquipmentTypesAreNamed' {
            $rows = @(Get-MailboxFactRows -Mailbox (New-Mbx @{ ArchiveStatus = 'None' }) -Statistics $null -ArchiveStatistics $null)
            ($rows | Where-Object { $_.Item -eq 'Archive' }).Value | Should -Match 'No archive'
            $room = @(Get-MailboxFactRows -Mailbox (New-Mbx @{ RecipientTypeDetails = 'RoomMailbox' }) -Statistics $null -ArchiveStatistics $null)
            ($room | Where-Object { $_.Item -eq 'Mailbox type' }).Value | Should -Match 'Room'
            $eq = @(Get-MailboxFactRows -Mailbox (New-Mbx @{ RecipientTypeDetails = 'EquipmentMailbox' }) -Statistics $null -ArchiveStatistics $null)
            ($eq | Where-Object { $_.Item -eq 'Mailbox type' }).Value | Should -Match 'Equipment'
        }
    }

    Context 'AC15 to AC18 assessment (pure)' {
        It 'AC15_TakeoverSignsGiveTheExactBlockAndExitCode1' {
            $a = Get-MailboxCheckAssessment -Signs @((New-Sign 'ExternalForwarding')) -Gate @((New-GateFix 'Inbox rules'), (New-GateFix 'Mailbox forwarding'))
            $a.Verdict | Should -Be 'TakeoverSigns'
            $a.ExitCode | Should -Be 1
            @($a.Lines)[0] | Should -BeExactly 'Possible account takeover: do NOT reset the password or delete the rule yet. Escalate.'
            @($a.Lines) | Should -Contain 'sign ExternalForwarding'
            $a.NextStep | Should -BeExactly "Check CIPP's BEC report for this user."
            @($a.Lines) | Should -Contain "Next step: Check CIPP's BEC report for this user."
        }

        It 'AC16_UnreadableSignSectionIsPartlyCheckedNeverAllClear' {
            $a = Get-MailboxCheckAssessment -Signs @() -Gate @((New-GateFix 'Inbox rules' 'CouldNotCheck' 'Access is denied'), (New-GateFix 'Mailbox forwarding'))
            $a.Verdict | Should -Be 'PartlyChecked'
            $a.ExitCode | Should -Be 2
            @($a.Lines)[0] | Should -Match '^PARTLY CHECKED'
            ($a.Lines -join "`n") | Should -Match 'Inbox rules'
            ($a.Lines -join "`n") | Should -Match 'Access is denied'
            ($a.Lines -join "`n") | Should -Not -Match 'No takeover signs found'
            @($a.CouldNotCheck | Where-Object { $_.Source -eq 'Inbox rules' }).Count | Should -Be 1
        }

        It 'AC17_AllCheckedAndNoSignIsTheCleanWording' {
            $a = Get-MailboxCheckAssessment -Signs @() -Gate @((New-GateFix 'Inbox rules'), (New-GateFix 'Mailbox forwarding'), (New-GateFix 'Accepted domains'))
            $a.Verdict | Should -Be 'AllChecked'
            $a.ExitCode | Should -Be 0
            @($a.Lines)[0] | Should -BeExactly 'No takeover signs found in the checks below.'
        }

        It 'AC18_TakeoverLineStaysFirstAndFailedTraceIsListed' {
            $a = Get-MailboxCheckAssessment -Signs @((New-Sign 'ExternalForwarding')) -Gate @((New-GateFix 'Message trace' 'CouldNotCheck' 'role missing'))
            @($a.Lines)[0] | Should -BeExactly 'Possible account takeover: do NOT reset the password or delete the rule yet. Escalate.'
            @($a.CouldNotCheck | Where-Object { $_.Source -eq 'Message trace' }).Count | Should -Be 1
            ($a.Lines -join "`n") | Should -Match 'Message trace'
        }
    }
}

Describe 'AC21 read-only by construction' {
    BeforeAll {
        # The entry script, the mailbox core and the ticket-note kit it dot-sources.
        $script:Kit = Join-Path $script:Root 'CaseKit.ps1'
        $script:ScannedFiles = @($script:Entry, $script:Core, $script:Kit)
        $script:Asts = @{}
        foreach ($p in $script:ScannedFiles) {
            $tokens = $null; $errs = $null
            $script:Asts[$p] = [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$tokens, [ref]$errs)
        }
        $script:LocalFns = @()
        foreach ($p in $script:ScannedFiles) {
            $script:LocalFns += @($script:Asts[$p].FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
        }
        $script:Cmds = @()
        foreach ($p in $script:ScannedFiles) {
            $script:Cmds += @($script:Asts[$p].FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                    Where-Object { $_.GetCommandName() } | ForEach-Object { [PSCustomObject]@{ Name = $_.GetCommandName(); File = $p; Ast = $_ } })
        }
        $script:CmdNames = @($script:Cmds | ForEach-Object { $_.Name })
        # The spec's allowlist (AC21). Export-Csv is NOT here: it is allowed only inside
        # Save-M365MailboxCsv (AC21 amendment, see the Export-Csv test below).
        $script:Allow = 'New-Object', 'New-Item', 'Add-Member', 'Set-Clipboard', 'Set-Content', 'Add-Content'
        # Local helpers with a write verb (or that write the tool's own files), by name. Each one
        # builds an object or writes this tool's report / CSV / ticket note; none touches Exchange.
        # A name here must be a function defined in the scanned files (checked below), so an
        # Exchange cmdlet can never be allowed by adding its name.
        $script:LocalHelpers = @(
            'Save-M365MailboxCheckReport', 'Save-M365MailboxCsv', 'New-MailboxSign', 'New-MailboxGate', 'New-M365MailboxStartFailure',
            # CaseKit.ps1 writer and builder functions
            'New-TicketNoteItem', 'New-TicketNoteStamp', 'New-TicketNote', 'New-TicketNoteClipboardData', 'Save-TicketNote',
            'Save-TicketNoteLines', 'Publish-TicketNote', 'Copy-TicketNoteToClipboard', 'Resolve-TicketFolder', 'Add-Section')
        # CaseKit.ps1 only: Add-Type loads the WinForms assembly for the clipboard (D-033).
        $script:KitOnly = @('Add-Type')
        $script:WriteVerb = '^(Set|New|Remove|Add|Enable|Disable|Update|Clear|Restore|Start|Stop)-'
    }

    It 'AC21_ReadOnlyByConstruction: the scripts read mailboxes (guards against scanning nothing)' {
        $script:CmdNames | Should -Contain 'Get-EXOMailbox'
        $script:CmdNames | Should -Contain 'Get-EXORecipient'
        $script:CmdNames | Should -Contain 'Get-InboxRule'
        $script:CmdNames | Should -Contain 'Get-MessageTraceV2'
        $script:CmdNames | Should -Contain 'New-TicketNote' -Because 'CaseKit.ps1 is scanned too'
    }

    It 'AC21_ReadOnlyByConstruction: every named local helper is a function defined here' {
        foreach ($h in $script:LocalHelpers) { $script:LocalFns | Should -Contain $h -Because "$h is allowed only as a local function" }
    }

    It 'AC21_ReadOnlyByConstruction: no command uses a write verb outside the allowlist and the named local helpers' {
        $bad = @($script:Cmds | Where-Object {
                $_.Name -match $script:WriteVerb -and $_.Name -notin $script:Allow -and $_.Name -notin $script:LocalHelpers -and
                -not ($_.File -eq $script:Kit -and $_.Name -in $script:KitOnly)
            } | ForEach-Object { '{0} ({1})' -f $_.Name, (Split-Path -Leaf $_.File) } | Sort-Object -Unique)
        $bad | Should -BeNullOrEmpty -Because ('write-verb commands found: ' + ($bad -join ', '))
    }

    It 'AC21_ReadOnlyByConstruction: Export-Csv appears only inside Save-M365MailboxCsv' {
        $exports = @($script:Cmds | Where-Object { $_.Name -eq 'Export-Csv' })
        $exports.Count | Should -BeGreaterThan 0 -Because 'the CSV writer must be found (guards against scanning nothing)'
        foreach ($e in $exports) {
            $fn = $e.Ast.Parent
            while ($fn -and $fn -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $fn = $fn.Parent }
            $fn | Should -Not -BeNullOrEmpty -Because 'Export-Csv outside any function is not allowed'
            $fn.Name | Should -BeExactly 'Save-M365MailboxCsv'
        }
    }

    It 'AC21_ReadOnlyByConstruction: no body-reading or exporting cmdlet appears' {
        $bad = @($script:CmdNames | Where-Object { $_ -in 'Search-Mailbox', 'New-ComplianceSearch', 'Get-MessageTraceDetailV2', 'Get-MessageTraceDetail' -or ($_ -like 'Export-*' -and $_ -ne 'Export-Csv') } | Sort-Object -Unique)
        $bad | Should -BeNullOrEmpty
        $consts = @()
        foreach ($p in $script:ScannedFiles) {
            $consts += @($script:Asts[$p].FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) | ForEach-Object { $_.Value })
        }
        @($consts | Where-Object { $_ -match '/messages' }).Count | Should -Be 0
    }
}

Describe 'AC23 stub parameter names are real' {
    It 'AC23_StubParametersExistOnTheRealCmdlets' -Skip:(-not $script:HasExo) {
        $names = ($script:StubSpec.Keys | ForEach-Object { "'$_'" }) -join ','
        $cmd = "Import-Module ExchangeOnlineManagement -ErrorAction Stop; `$o = @{}; foreach (`$n in @($names)) { `$c = Get-Command `$n -ErrorAction SilentlyContinue; if (`$c) { `$o[`$n] = @(`$c.Parameters.Keys) } }; `$o | ConvertTo-Json -Compress"
        $json = & pwsh -NoProfile -NonInteractive -Command $cmd
        $real = $json | ConvertFrom-Json
        $checkedReal = 0
        foreach ($name in $script:StubSpec.Keys) {
            $mine = @($script:StubSpec[$name].Params) + @($script:StubSpec[$name].Switches)
            $known = if ($real.PSObject.Properties[$name]) { $checkedReal++; @($real.$name) } elseif ($script:LearnParams.ContainsKey($name)) { $script:LearnParams[$name] } else { $null }
            $known | Should -Not -BeNullOrEmpty -Because "$name has no real parameter list to compare with"
            foreach ($p in $mine) { $known | Should -Contain $p -Because "$name -$p must exist" }
        }
        $checkedReal | Should -BeGreaterThan 3 -Because 'the module cmdlets must have been compared'
    }

    It 'AC23_ProductionCallsUseRealParameterNames: every named parameter the scripts pass to an Exchange cmdlet exists' {
        $known = @{}
        foreach ($n in $script:StubSpec.Keys) { $known[$n] = @($script:StubSpec[$n].Params) + @($script:StubSpec[$n].Switches) }
        foreach ($n in $script:LearnParams.Keys) { $known[$n] = @($script:LearnParams[$n]) + $known[$n] }
        $common = 'ErrorAction', 'Verbose', 'Debug', 'WarningAction', 'InformationAction', 'ErrorVariable', 'OutVariable', 'WhatIf', 'Confirm'
        $seen = 0
        foreach ($p in $script:Entry, $script:Core) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$null, [ref]$null)
            foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                $name = $c.GetCommandName()
                if (-not $name -or -not $known.ContainsKey($name)) { continue }
                $seen++
                foreach ($e in $c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] }) {
                    ($known[$name] + $common) | Should -Contain $e.ParameterName -Because "$name -$($e.ParameterName) in $(Split-Path -Leaf $p)"
                }
            }
        }
        $seen | Should -BeGreaterThan 5 -Because 'the scripts must actually call the Exchange cmdlets'
    }
}

Describe 'docs: what the ticket note names' {
    It 'Docs_NoteNamesTheCheckedMailboxButNoOtherAddress (help, folder README, ServiceDesk README)' {
        $sentence = [regex]::Escape('names the checked mailbox, but never a forwarding, delegate or message-trace address')
        foreach ($doc in @($script:Entry, (Join-Path $script:Root 'README.md'), (Join-Path $script:RepoRoot 'ServiceDesk-Toolkit\README.md'))) {
            ((Get-Content -LiteralPath $doc -Raw) -replace '\s+', ' ') | Should -Match $sentence -Because (Split-Path -Leaf (Split-Path -Parent $doc))
        }
    }
}

Describe 'AC25 gitignore' {
    It 'AC25_OutputPatternIsListedUnderCustomerData' {
        $lines = @(Get-Content -LiteralPath (Join-Path $script:RepoRoot '.gitignore'))
        $start = [array]::FindIndex($lines, [Predicate[string]] { param($l) $l -match 'Customer data' })
        $start | Should -BeGreaterOrEqual 0
        $end = $lines.Count
        for ($i = $start + 1; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^# ---') { $end = $i; break } }
        $section = $lines[($start + 1)..($end - 1)]
        @($section | Where-Object { $_ -match '^\*\*/MailboxCheck_\*\.html$' }).Count | Should -Be 1
        @($section | Where-Object { $_ -match '^\*\*/MailboxCheck_\*\.csv$' }).Count | Should -Be 1
    }
}

Describe 'minimum Exchange roles (D-026)' -Tag 'Integration' {
    # Runs the real tool against a real tenant in a CHILD process (this file's stubs would shadow
    # the real cmdlets). Michael runs it once before the tool goes into the bundle:
    #   $env:MAILBOXCHECK_IT_IDENTITY = 'someone@client.com'; Invoke-Pester <this file> -TagFilter Integration
    # Sign in with the account that has ONLY the roles the README lists; the check must come back
    # without a role/permission "could not check" reason.
    It 'IntegrationRoles_MinimumRolesAreEnoughToReadEverySection' -Skip:(-not $env:MAILBOXCHECK_IT_IDENTITY) {
        $json = & pwsh -NoProfile -NonInteractive -Command ". '$($script:Entry)' -Identity '$($env:MAILBOXCHECK_IT_IDENTITY)' -NoClipboard -PassThru | Select-Object Status, ExitCode, @{n='Cnc';e={@(`$_.Assessment.CouldNotCheck | ForEach-Object { `$_.Source + ': ' + `$_.Reason })}} | ConvertTo-Json -Compress -Depth 4"
        $r = $json | ConvertFrom-Json
        $r.Status | Should -Be 'Ok'
        ($r.Cnc -join "`n") | Should -Not -Match 'role|permission|denied|not recognized|parameter'
    }
}
