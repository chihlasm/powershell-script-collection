# 3.0 so the GUI also opens on Server 2012 (PS 3.0) / 2012 R2 (PS 4.0) domain controllers as shipped.
# Tests\PSVersionFloor.Tests.ps1 guards it. The ADSync script blocks below run ON the Entra Connect
# server, which always has PowerShell 5.x (Entra Connect V2 requires it).
#Requires -Version 3.0

<#
.SYNOPSIS
    Shared logic for M365-SyncedUserFixes: the two fixes, their Entra Connect sync rules,
    rule verification and creation, Active Directory user search and updates.
.DESCRIPTION
    Dot-sourced by Start-M365SyncedUserFixes.ps1 (the window) and New-SyncedUserRule.ps1
    (the command-line rule builder). Nothing here draws UI.

    HOW THE FIXES WORK
    A synced user's Microsoft 365 settings cannot be changed in the cloud, so each fix
    writes a marker attribute on the user in Active Directory:

        Block Microsoft 365 sign-in   msDS-cloudExtensionAttribute10 = BlockCloudSignIn
        Hide from address book        msDS-cloudExtensionAttribute1  = HideFromGAL

    The marker does nothing on its own. A custom inbound sync rule inside Entra Connect,
    usually on a DIFFERENT server, turns it into a change in Microsoft 365. Custom sync rules
    are NOT carried over when Entra Connect is moved to a new server, so every check here
    reports "could not check" (Unknown) separately from "rule is missing" (Missing).

.NOTES
    Formerly Shared-EntraConnect.ps1, duplicated in the retired "Block 365 Sign-in" and
    HideFromGal folders. Merged here so there is one copy.

    REFERENCES
    - Custom rules, precedence 1-99 reserved for custom rules, case-sensitive expressions:
      https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-change-the-configuration
    - Expression language (NULL, True/False, case sensitivity):
      https://learn.microsoft.com/entra/identity/hybrid/connect/concept-azure-ad-connect-sync-declarative-provisioning-expressions
    - cloudFiltered set by a custom inbound rule; returning NULL lets a lower-precedence rule
      write the attribute; filtered-out objects are DELETED from Entra ID and password hash
      sync stops for them:
      https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-fix-default-rules
    - Attribute-based filtering with a custom inbound rule, precedence below 100:
      https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-configure-filtering
    - Lower precedence number wins attribute flow conflicts; accountEnabled is set by the
      out-of-box "In from AD - User AccountEnabled" rule:
      https://learn.microsoft.com/entra/identity/hybrid/connect/concept-azure-ad-connect-sync-default-configuration
    - Custom rules are not migrated with an exported configuration:
      https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-import-export-config
    - ADSync PowerShell reference:
      https://learn.microsoft.com/entra/identity/hybrid/connect/reference-connect-adsync
    - Delta vs full sync cycles:
      https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-feature-scheduler
    - LDAP filter escaping (\2a \28 \29 \5c \00) and the bitwise matching rule
      1.2.840.113556.1.4.803 used to skip disabled accounts:
      https://learn.microsoft.com/windows/win32/adsi/search-filter-syntax
    - userAccountControl ACCOUNTDISABLE = 0x2:
      https://learn.microsoft.com/windows/win32/adschema/a-useraccountcontrol

    NOT VERIFIED ON LEARN
    - That a custom inbound rule flowing False to accountEnabled disables the synced
      account. It follows from the documented precedence rules above and matches a working
      production rule, but Learn does not describe this exact recipe.
    - The AttributeInclusionList property of Get-ADSyncConnector, used to warn when the AD
      connector does not import the marker attribute. If the property is absent the check
      is skipped, never reported as a problem.
#>

[CmdletBinding()]
param(
    # Lets the tests and the GUI dot-source the functions without running anything.
    [switch]$LoadFunctionsOnly
)

#region Fix and rule definitions

# The two fixes, as the service desk sees them.
$script:SyncedUserFeatures = @{
    'BlockSignIn' = [PSCustomObject]@{
        Key          = 'BlockSignIn'
        RuleKey      = 'BlockCloudSignIn'
        Title        = 'Block Microsoft 365 sign-in'
        Attribute    = 'msDS-cloudExtensionAttribute10'
        MarkerValue  = 'BlockCloudSignIn'
        ApplyVerb    = 'Block sign-in'
        RemoveVerb   = 'Restore sign-in'
        MarkedText   = 'Blocked'
        UnmarkedText = 'Can sign in'
        # Restoring access must always be possible, whatever the rule status.
        ApplyIsRisky = $true
    }
    'HideFromGAL' = [PSCustomObject]@{
        Key          = 'HideFromGAL'
        RuleKey      = 'HideFromGAL'
        Title        = 'Hide from address book'
        Attribute    = 'msDS-cloudExtensionAttribute1'
        MarkerValue  = 'HideFromGAL'
        ApplyVerb    = 'Hide'
        RemoveVerb   = 'Show again'
        MarkedText   = 'Hidden'
        UnmarkedText = 'Visible'
        ApplyIsRisky = $false
    }
}

# How each rule must look. Verification accepts any rule that writes an accepted destination
# AND references the marker attribute; creation builds the toolkit's own version.
#
# Precedence: Microsoft reserves 1-99 for custom rules; out-of-box rules start at 100.
# https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-change-the-configuration
$script:EntraConnectRuleDefinitions = @{
    'BlockCloudSignIn' = [PSCustomObject]@{
        Key                  = 'BlockCloudSignIn'
        NamePrefix           = 'Block cloud sign-in'
        SourceAttribute      = 'msDS-cloudExtensionAttribute10'
        MarkerValue          = 'BlockCloudSignIn'
        # Default destination for verification messages; the creation method decides the real one.
        Destination          = 'cloudFiltered'
        # Two legitimate ways to block sign-in from the marker:
        #   accountEnabled - flows False, disabling the synced account; the cloud object,
        #                    licences, mailbox and group memberships survive.
        #   cloudFiltered  - filters the user out of sync; Entra ID DELETES the object and
        #                    password hash sync stops for it.
        # Verification accepts either. Checking only cloudFiltered once reported a real,
        # working accountEnabled rule as "NOT FOUND" and disabled the tool.
        AcceptedDestinations = @('accountEnabled', 'cloudFiltered')
        Precedence           = 60
        Methods              = @{
            'DisableSignIn' = [PSCustomObject]@{
                Key         = 'DisableSignIn'
                Label       = 'Disable the Microsoft 365 account (recommended)'
                Destination = 'accountEnabled'
                NameSuffix  = 'disable account'
                # NULL when the marker is absent so the out-of-box AccountEnabled rule still
                # decides for everyone else (a NULL from a higher-precedence rule lets a
                # lower-precedence rule write the attribute).
                Expression  = 'IIF(IsPresent([msDS-cloudExtensionAttribute10]),IIF([msDS-cloudExtensionAttribute10]="BlockCloudSignIn",False,NULL),NULL)'
                Description = 'If msDS-cloudExtensionAttribute10 is BlockCloudSignIn, disable the synced Microsoft 365 account. Mailbox, licences and group memberships are kept.'
                Consequence = 'The person cannot sign in to Microsoft 365. Their mailbox, licences, OneDrive and group memberships are kept, so restoring sign-in puts everything back.'
            }
            'RemoveFromM365' = [PSCustomObject]@{
                Key         = 'RemoveFromM365'
                Label       = 'Remove the person from Microsoft 365'
                Destination = 'cloudFiltered'
                NameSuffix  = 'remove from Microsoft 365'
                Expression  = 'IIF(IsPresent([msDS-cloudExtensionAttribute10]),IIF([msDS-cloudExtensionAttribute10]="BlockCloudSignIn",True,NULL),NULL)'
                Description = 'If msDS-cloudExtensionAttribute10 is BlockCloudSignIn, filter the user out of sync. Entra ID deletes the account, taking the mailbox and licences with it.'
                Consequence = 'Entra Connect stops syncing the person and Microsoft 365 DELETES their account. The mailbox, licences and group memberships go with it. Restoring sign-in recreates the account, but licences may need reassigning.'
            }
        }
        DefaultMethod        = 'DisableSignIn'
    }
    'HideFromGAL' = [PSCustomObject]@{
        Key                  = 'HideFromGAL'
        NamePrefix           = 'Hide user from GAL'
        SourceAttribute      = 'msDS-cloudExtensionAttribute1'
        MarkerValue          = 'HideFromGAL'
        Destination          = 'msExchHideFromAddressLists'
        AcceptedDestinations = @('msExchHideFromAddressLists')
        Precedence           = 50
        Methods              = @{
            'Hide' = [PSCustomObject]@{
                Key         = 'Hide'
                Label       = 'Hide from the address book'
                Destination = 'msExchHideFromAddressLists'
                NameSuffix  = ''
                Expression  = 'IIF(IsPresent([msDS-cloudExtensionAttribute1]),IIF([msDS-cloudExtensionAttribute1]="HideFromGAL",True,False),NULL)'
                Description = 'If msDS-cloudExtensionAttribute1 is HideFromGAL, hide the user from the Exchange Online address book.'
                Consequence = 'The person disappears from the Outlook address book. Mail to them still works.'
            }
        }
        DefaultMethod        = 'Hide'
    }
}

function Get-SyncedUserFeature {
    <#
    .SYNOPSIS
        Returns one of the two fixes (BlockSignIn or HideFromGAL).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('BlockSignIn', 'HideFromGAL')]
        [string]$Key
    )
    $script:SyncedUserFeatures[$Key]
}

function Get-EntraConnectRuleDefinition {
    <#
    .SYNOPSIS
        Returns the expected shape of a fix's sync rule.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('BlockCloudSignIn', 'HideFromGAL')]
        [string]$Key
    )
    $script:EntraConnectRuleDefinitions[$Key]
}

function Get-SyncRuleBlueprint {
    <#
    .SYNOPSIS
        Builds the exact rule the toolkit would create: name, precedence, destination, expression.
    .PARAMETER Key
        BlockCloudSignIn or HideFromGAL.
    .PARAMETER Method
        For BlockCloudSignIn: DisableSignIn (default) or RemoveFromM365. HideFromGAL has one method.
    .PARAMETER Domain
        AD domain DNS name; used in the rule name and to pick the AD connector.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('BlockCloudSignIn', 'HideFromGAL')]
        [string]$Key,

        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Domain
    )

    $definition = Get-EntraConnectRuleDefinition -Key $Key
    if ([string]::IsNullOrWhiteSpace($Method)) { $Method = $definition.DefaultMethod }
    if (-not $definition.Methods.ContainsKey($Method)) {
        throw "Method '$Method' is not valid for $Key. Valid: $(@($definition.Methods.Keys) -join ', ')"
    }
    $m = $definition.Methods[$Method]

    $name = $definition.NamePrefix
    if ($m.NameSuffix) { $name = "$name ($($m.NameSuffix))" }
    $name = "$name - $Domain"

    [PSCustomObject]@{
        Key                  = $Key
        Method               = $Method
        MethodLabel          = $m.Label
        Name                 = $name
        Description          = $m.Description
        Consequence          = $m.Consequence
        Precedence           = $definition.Precedence
        SourceAttribute      = $definition.SourceAttribute
        MarkerValue          = $definition.MarkerValue
        Destination          = $m.Destination
        Expression           = $m.Expression
        AcceptedDestinations = @($definition.AcceptedDestinations)
        Domain               = $Domain
        IsDestructive        = ($m.Destination -eq 'cloudFiltered')
    }
}

function Format-SyncRuleBlueprint {
    <#
    .SYNOPSIS
        Plain-text preview of a blueprint, for the GUI and the console.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Blueprint)

    @(
        "Rule name      : $($Blueprint.Name)"
        "Direction      : Inbound (from Active Directory)"
        "Applies to     : AD user -> metaverse person, link type Join"
        "Connector      : the AD connector for $($Blueprint.Domain)"
        "Precedence     : $($Blueprint.Precedence) (or the nearest free number 1-99)"
        "Reads          : $($Blueprint.SourceAttribute) = `"$($Blueprint.MarkerValue)`""
        "Writes         : $($Blueprint.Destination)"
        "Expression     : $($Blueprint.Expression)"
        ''
        "What it does   : $($Blueprint.Consequence)"
    ) -join "`r`n"
}

#endregion

#region Rule verification (pure, unit tested)

function ConvertTo-ComparableExpression {
    <#
    .SYNOPSIS
        Normalizes a sync-rule expression for comparison (whitespace only).
    .DESCRIPTION
        Case is NOT normalized: the sync engine is case-sensitive for function and attribute
        names, so a case difference is a real defect.
        https://learn.microsoft.com/entra/identity/hybrid/connect/concept-azure-ad-connect-sync-declarative-provisioning-expressions
    #>
    [CmdletBinding()]
    param([string]$Expression)

    if ([string]::IsNullOrWhiteSpace($Expression)) { return '' }
    ($Expression -replace '\s', '')
}

function Get-SyncRuleMechanismText {
    <#
    .SYNOPSIS
        Plain-English consequence of a rule destination.
    #>
    [CmdletBinding()]
    param([string]$Destination)

    switch ($Destination) {
        'cloudFiltered'              { 'removes the person from Microsoft 365 entirely (mailbox and licences go with it)' }
        'accountEnabled'             { 'disables the Microsoft 365 account, keeping the mailbox and licences' }
        'msExchHideFromAddressLists' { 'hides the person from the address book' }
        default                      { "writes '$Destination'" }
    }
}

function Test-EntraConnectRuleShape {
    <#
    .SYNOPSIS
        Decides whether a retrieved sync rule actually enforces what the fix expects.
    .DESCRIPTION
        Pure: takes an already-retrieved (flattened) rule or $null plus the expected
        definition. Returns State (Present | Missing | Misconfigured), Reason and Mechanism
        (the destination in force, or $null).
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Rule,

        [Parameter(Mandatory)]
        [object]$Definition
    )

    $accepted = if ($Definition.PSObject.Properties.Name -contains 'AcceptedDestinations') {
        @($Definition.AcceptedDestinations)
    } else {
        @($Definition.Destination)
    }

    if ($null -eq $Rule) {
        return [PSCustomObject]@{
            State     = 'Missing'
            Reason    = "No sync rule that reads '$($Definition.SourceAttribute)' and writes '$($accepted -join "' or '")' was found on the Entra Connect server. Nothing is enforcing this fix."
            Mechanism = $null
        }
    }

    $flow = $null
    if ($Rule.PSObject.Properties.Name -contains 'AttributeFlowMappings') {
        $flow = @($Rule.AttributeFlowMappings | Where-Object { $accepted -contains $_.Destination }) | Select-Object -First 1
    }

    if ($null -eq $flow) {
        return [PSCustomObject]@{
            State     = 'Misconfigured'
            Reason    = "Sync rule '$($Rule.Name)' exists but does not write '$($accepted -join "' or '")'. It is not enforcing this fix."
            Mechanism = $null
        }
    }

    # The marker can be referenced in the flow expression, the flow source, or a scoping
    # filter. All three enforce identically. An earlier version compared only the expression
    # text and wrongly condemned a hand-built rule driven by a scoping filter.
    $referencesMarker = if ($Rule.PSObject.Properties.Name -contains 'ReferencesMarker') {
        [bool]$Rule.ReferencesMarker
    } else {
        $haystack = @()
        $haystack += @($Rule.AttributeFlowMappings | ForEach-Object { "$($_.Expression) $($_.Source)" })
        if ($Rule.PSObject.Properties.Name -contains 'ScopeConditions') {
            $haystack += @($Rule.ScopeConditions | ForEach-Object { "$($_.Attribute) $($_.Value)" })
        }
        (($haystack -join ' ') -match [regex]::Escape($Definition.SourceAttribute))
    }

    if (-not $referencesMarker) {
        return [PSCustomObject]@{
            State     = 'Misconfigured'
            Reason    = "Sync rule '$($Rule.Name)' (precedence $($Rule.Precedence)) writes '$($flow.Destination)', but could not find any reference to '$($Definition.SourceAttribute)' in it. This fix's marker will not trigger it."
            Mechanism = $flow.Destination
        }
    }

    [PSCustomObject]@{
        State     = 'Present'
        Reason    = "Sync rule '$($Rule.Name)' (precedence $($Rule.Precedence)) is in place: it $(Get-SyncRuleMechanismText -Destination $flow.Destination)."
        Mechanism = $flow.Destination
    }
}

function New-EntraConnectStatus {
    <#
    .SYNOPSIS
        Builds the status object every caller reads.
    .DESCRIPTION
        CanEnforce  - $true ONLY when the rule was positively verified present.
        ShouldBlock - $true ONLY when the rule was positively confirmed absent or broken.
        Unknown ("we could not check") must NEVER block the tool.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Present', 'Missing', 'Misconfigured', 'Unknown')]
        [string]$State,

        [string]$Server,
        [string]$Reason,
        [string]$Remediation,
        [string]$Mechanism,
        [string]$RuleName,
        [string[]]$Warnings = @()
    )

    [PSCustomObject]@{
        State       = $State
        Server      = $Server
        Reason      = $Reason
        Remediation = $Remediation
        Mechanism   = $Mechanism
        RuleName    = $RuleName
        Warnings    = @($Warnings)
        CanEnforce  = ($State -eq 'Present')
        ShouldBlock = ($State -eq 'Missing' -or $State -eq 'Misconfigured')
        CheckedAt   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    }
}

function Get-EntraConnectStatusPresentation {
    <#
    .SYNOPSIS
        Console prefix, colors and headline for a status state.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Present', 'Missing', 'Misconfigured', 'Unknown', 'Checking')]
        [string]$State
    )

    switch ($State) {
        'Present'       { [PSCustomObject]@{ Prefix = '[PASS]'; ConsoleColor = 'Green';  Accent = '#3FB950'; Headline = 'Sync rule in place' } }
        'Missing'       { [PSCustomObject]@{ Prefix = '[FAIL]'; ConsoleColor = 'Red';    Accent = '#F85149'; Headline = 'Sync rule NOT FOUND' } }
        'Misconfigured' { [PSCustomObject]@{ Prefix = '[FAIL]'; ConsoleColor = 'Red';    Accent = '#F85149'; Headline = 'Sync rule is broken' } }
        'Unknown'       { [PSCustomObject]@{ Prefix = '[WARN]'; ConsoleColor = 'Yellow'; Accent = '#D29922'; Headline = 'Could not check the sync rule' } }
        'Checking'      { [PSCustomObject]@{ Prefix = '[INFO]'; ConsoleColor = 'Cyan';   Accent = '#58A6FF'; Headline = 'Checking the sync rule...' } }
    }
}

#endregion

#region Local vs remote, discovery and cache

function Test-IsLocalMachine {
    <#
    .SYNOPSIS
        $true when the named computer is this machine.
    .DESCRIPTION
        The ADSync management interface is a WCF endpoint bound to
        net.pipe://localhost/ADSyncManagement and does NOT accept calls arriving over a
        PowerShell remoting hop, even a hop to the same machine. So when the target is this
        machine the ADSync cmdlets must be called directly.
    #>
    [CmdletBinding()]
    param([string]$ComputerName)

    if ([string]::IsNullOrWhiteSpace($ComputerName)) { return $true }

    # Check the aliases BEFORE trimming trailing dots: '.' is itself a valid local target.
    $raw = $ComputerName.Trim()
    if (@('.', 'localhost', '127.0.0.1', '::1') -contains $raw) { return $true }

    $target = $raw.TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($target)) { return $true }

    $me = $env:COMPUTERNAME
    if ($target -eq $me) { return $true }
    if ($target -like "$me.*") { return $true }

    try {
        $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
        if ($fqdn -and $target -eq $fqdn.TrimEnd('.')) { return $true }
    } catch {
        Write-Verbose "Could not resolve local FQDN: $($_.Exception.Message)"
    }

    return $false
}

function Invoke-AdSyncCommand {
    <#
    .SYNOPSIS
        Runs a scriptblock against the Entra Connect server: directly when it is this machine,
        through Invoke-Command otherwise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @(),
        [System.Management.Automation.PSCredential]$Credential
    )

    if (Test-IsLocalMachine -ComputerName $ComputerName) {
        return & $ScriptBlock @ArgumentList
    }

    $icmArgs = @{
        ComputerName = $ComputerName
        ScriptBlock  = $ScriptBlock
        ArgumentList = $ArgumentList
        ErrorAction  = 'Stop'
    }
    if ($Credential) { $icmArgs['Credential'] = $Credential }
    Invoke-Command @icmArgs
}

function Get-EntraConnectSettingsPath {
    [CmdletBinding()]
    param([string]$ScriptRoot = $PSScriptRoot)
    Join-Path -Path $ScriptRoot -ChildPath 'EntraConnectSettings.json'
}

function Read-EntraConnectSettings {
    <#
    .SYNOPSIS
        Reads the cached Entra Connect server, tolerating a missing or corrupt file.
    #>
    [CmdletBinding()]
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Verbose "Ignoring unreadable settings file '$Path': $($_.Exception.Message)"
        $null
    }
}

function Write-EntraConnectSettings {
    <#
    .SYNOPSIS
        Caches the verified Entra Connect server so the next launch skips discovery.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Server
    )

    $payload = [PSCustomObject]@{
        EntraConnectServer = $Server
        VerifiedAt         = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Note               = 'Written automatically after a successful check. Delete this file to force rediscovery after an Entra Connect migration.'
    }
    try {
        if ($PSCmdlet.ShouldProcess($Path, 'Cache Entra Connect server name')) {
            $payload | ConvertTo-Json | Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
        }
    } catch {
        # Caching is an optimization. A read-only folder must not break the tool.
        Write-Verbose "Could not write settings file '$Path': $($_.Exception.Message)"
    }
}

function Test-AdSyncServer {
    <#
    .SYNOPSIS
        $true when the named server runs the ADSync service.
    .DESCRIPTION
        @() and an explicit Name check: a -Filter that matches nothing returns no object
        rather than an error. A bare "did not throw" test once made every reachable server
        look like an Entra Connect server.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [int]$TimeoutSeconds = 5
    )

    try {
        $cimArgs = @{ ClassName = 'Win32_Service'; Filter = "Name='ADSync'"; OperationTimeoutSec = $TimeoutSeconds; ErrorAction = 'Stop' }
        if (-not (Test-IsLocalMachine -ComputerName $ComputerName)) { $cimArgs['ComputerName'] = $ComputerName }
        $svc = @(Get-CimInstance @cimArgs)
        return ($svc.Count -gt 0 -and $svc[0].Name -eq 'ADSync')
    } catch {
        Write-Verbose "ADSync probe failed on '$ComputerName': $($_.Exception.Message)"
        return $false
    }
}

function Find-EntraConnectServer {
    <#
    .SYNOPSIS
        Finds the Entra Connect server: explicit name, then this machine, then the cached
        name (re-probed), then AD server objects probed for the ADSync service.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName,
        [string]$SettingsPath,
        [int]$MaxCandidates = 40
    )

    if (-not [string]::IsNullOrWhiteSpace($ComputerName)) {
        return [PSCustomObject]@{ Server = $ComputerName; Source = 'Explicit' }
    }

    # Running on the Connect server itself is the best case: rules can be read directly.
    if (Test-AdSyncServer -ComputerName $env:COMPUTERNAME -TimeoutSeconds 3) {
        return [PSCustomObject]@{ Server = $env:COMPUTERNAME; Source = 'ThisMachine' }
    }

    $settings = Read-EntraConnectSettings -Path $SettingsPath
    if ($settings -and -not [string]::IsNullOrWhiteSpace($settings.EntraConnectServer)) {
        $cached = $settings.EntraConnectServer
        if (Test-AdSyncServer -ComputerName $cached) {
            return [PSCustomObject]@{ Server = $cached; Source = 'Cache' }
        }
        Write-Verbose "Cached server '$cached' no longer runs ADSync - rediscovering."
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
        # Enabled servers, most recently logged on first: a live Connect server is active daily.
        $candidates = @(Get-ADComputer -Filter "OperatingSystem -like '*Server*' -and Enabled -eq 'True'" `
                                       -Properties OperatingSystem, LastLogonDate -ErrorAction Stop |
                        Sort-Object LastLogonDate -Descending |
                        Select-Object -First $MaxCandidates)

        foreach ($c in $candidates) {
            if ($c.DNSHostName -and (Test-AdSyncServer -ComputerName $c.DNSHostName -TimeoutSeconds 3)) {
                return [PSCustomObject]@{ Server = $c.DNSHostName; Source = 'Discovered' }
            }
        }
    } catch {
        Write-Verbose "AD-based discovery failed: $($_.Exception.Message)"
    }

    [PSCustomObject]@{ Server = $null; Source = 'NotFound' }
}

#endregion

#region Remote rule reading

# Runs ON the Entra Connect server (PowerShell 5.x there). Returns every inbound rule that
# writes one of the accepted destinations, flattened to plain properties, plus whether the
# AD connector imports the marker attribute. Rich ADSync types do not survive a remoting
# boundary cleanly, so everything is reduced here.
$script:ReadSyncRulesBlock = {
    param($Destinations, $SourceAttribute)

    try {
        Import-Module ADSync -ErrorAction Stop
    } catch {
        return [PSCustomObject]@{ Outcome = 'NoModule'; Error = $_.Exception.Message; Rules = @(); AttributeImported = $null }
    }

    try {
        $inbound = @(Get-ADSyncRule -ErrorAction Stop | Where-Object { [string]$_.Direction -eq 'Inbound' })
        $candidates = @($inbound | Where-Object {
            $r = $_
            @($r.AttributeFlowMappings | Where-Object { $Destinations -contains $_.Destination }).Count -gt 0
        })

        $flat = @()
        foreach ($r in $candidates) {
            # Serialize the whole rule and search the text: the scoping-filter shape varies by
            # Entra Connect version, and guessing property names once read nothing and declared
            # a working rule missing.
            $dump = ''
            try {
                $dump = [System.Management.Automation.PSSerializer]::Serialize($r, 6)
            } catch {
                try { $dump = ($r.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' ' } catch { $dump = '' }
            }

            $scopes = @()
            foreach ($propName in @('ScopeFilter', 'ScopeFilters')) {
                if ($r.PSObject.Properties.Name -notcontains $propName) { continue }
                foreach ($group in @($r.$propName)) {
                    foreach ($listName in @('ScopeConditionList', 'ConditionBase')) {
                        if ($group.PSObject.Properties.Name -notcontains $listName) { continue }
                        foreach ($cond in @($group.$listName)) {
                            if ($null -eq $cond) { continue }
                            $scopes += [PSCustomObject]@{
                                Attribute = [string]$cond.Attribute
                                Operator  = [string]$cond.ComparisonOperator
                                Value     = (@($cond.ComparisonValue) -join ',')
                            }
                        }
                    }
                }
            }

            $flat += [PSCustomObject]@{
                Name             = [string]$r.Name
                Identifier       = [string]$r.Identifier
                Precedence       = $r.Precedence
                Disabled         = [bool]$r.Disabled
                AttributeFlowMappings = @($r.AttributeFlowMappings | ForEach-Object {
                    [PSCustomObject]@{
                        Destination = [string]$_.Destination
                        Expression  = [string]$_.Expression
                        FlowType    = [string]$_.FlowType
                        Source      = (@($_.Source) -join ',')
                    }
                })
                ScopeConditions  = $scopes
                ReferencesMarker = ($dump -match [regex]::Escape($SourceAttribute))
            }
        }

        # Does any AD connector import the marker attribute? $null = could not tell.
        $imported = $null
        try {
            $adConnectors = @(Get-ADSyncConnector -ErrorAction Stop | Where-Object { [string]$_.Type -eq 'AD' })
            $lists = @($adConnectors | Where-Object { $_.PSObject.Properties.Name -contains 'AttributeInclusionList' })
            if ($lists.Count -gt 0) {
                $imported = (@($lists | Where-Object { @($_.AttributeInclusionList) -contains $SourceAttribute }).Count -gt 0)
            }
        } catch { $imported = $null }

        return [PSCustomObject]@{ Outcome = 'Ok'; Error = $null; Rules = $flat; AttributeImported = $imported }
    } catch {
        return [PSCustomObject]@{ Outcome = 'QueryFailed'; Error = $_.Exception.Message; Rules = @(); AttributeImported = $null }
    }
}

function Select-EnforcingSyncRule {
    <#
    .SYNOPSIS
        From the flattened candidates, picks the rule to judge: an enabled rule that
        references the marker, else any rule that references it, else the first candidate.
    #>
    [CmdletBinding()]
    param([object[]]$Rules)

    $all = @($Rules | Where-Object { $null -ne $_ })
    if ($all.Count -eq 0) { return $null }
    $live = @($all | Where-Object { $_.ReferencesMarker -and -not ($_.PSObject.Properties.Name -contains 'Disabled' -and $_.Disabled) })
    if ($live.Count -gt 0) { return $live[0] }
    $marked = @($all | Where-Object { $_.ReferencesMarker })
    if ($marked.Count -gt 0) { return $marked[0] }
    return $all[0]
}

function Test-EntraConnectRule {
    <#
    .SYNOPSIS
        Verifies a fix's sync rule on the Entra Connect server. Returns a status object whose
        State is Present, Missing, Misconfigured or Unknown.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('BlockCloudSignIn', 'HideFromGAL')]
        [string]$RuleKey,

        [string]$ComputerName,
        [string]$SettingsPath,
        [System.Management.Automation.PSCredential]$Credential
    )

    $definition = Get-EntraConnectRuleDefinition -Key $RuleKey
    $found      = Find-EntraConnectServer -ComputerName $ComputerName -SettingsPath $SettingsPath

    if (-not $found.Server) {
        return New-EntraConnectStatus -State 'Unknown' -Server $null `
            -Reason 'No Entra Connect server could be found. Searched Active Directory for a server running the ADSync service and found none reachable.' `
            -Remediation 'Type the Entra Connect server name in "Set up sync rules", or run the tool with -EntraConnectServer <name>.'
    }
    $server = $found.Server

    try {
        # Build the argument array explicitly: the first argument is itself an array, and
        # inline construction would spread it into separate arguments.
        $remoteArgs = New-Object object[] 2
        $remoteArgs[0] = @($definition.AcceptedDestinations)
        $remoteArgs[1] = $definition.SourceAttribute
        $result = Invoke-AdSyncCommand -ComputerName $server -ScriptBlock $script:ReadSyncRulesBlock `
                                       -ArgumentList $remoteArgs -Credential $Credential
    } catch {
        return New-EntraConnectStatus -State 'Unknown' -Server $server `
            -Reason "Could not connect to '$server': $($_.Exception.Message)" `
            -Remediation "This is a connection or permissions problem, not proof the rule is missing. Check WinRM (Test-WSMan $server) and that you are a local administrator on $server."
    }

    switch ($result.Outcome) {
        'NoModule' {
            return New-EntraConnectStatus -State 'Unknown' -Server $server `
                -Reason "'$server' does not have the ADSync module, so it is not the Entra Connect server." `
                -Remediation 'Entra Connect may have moved. Delete EntraConnectSettings.json to force rediscovery, or type the right server name.'
        }
        'QueryFailed' {
            # The ADSync endpoint (net.pipe://localhost/ADSyncManagement) refuses remoting hops:
            # this means "cannot be read from here", not "wrong server".
            if ($result.Error -match 'no endpoint listening|net\.pipe|net\.tcp|ADSyncManagement') {
                return New-EntraConnectStatus -State 'Unknown' -Server $server `
                    -Reason "The sync rules on '$server' cannot be read from this computer. Entra Connect only answers these questions locally." `
                    -Remediation "This does NOT mean the rule is missing. To check it, run this tool on $server itself. Blocking and hiding still work from here."
            }
            return New-EntraConnectStatus -State 'Unknown' -Server $server `
                -Reason "Reached '$server' but could not read its sync rules: $($result.Error)" `
                -Remediation "Reading sync rules needs local administrator rights (or ADSyncAdmins membership) on $server."
        }
    }

    $chosen  = Select-EnforcingSyncRule -Rules @($result.Rules)
    $verdict = Test-EntraConnectRuleShape -Rule $chosen -Definition $definition

    $warnings = @()
    if ($verdict.State -eq 'Present' -and $chosen.PSObject.Properties.Name -contains 'Disabled' -and $chosen.Disabled) {
        $verdict = [PSCustomObject]@{
            State     = 'Misconfigured'
            Reason    = "Sync rule '$($chosen.Name)' would enforce this fix, but it is DISABLED in Entra Connect."
            Mechanism = $verdict.Mechanism
        }
    }
    $enforcing = @($result.Rules | Where-Object { $_.ReferencesMarker })
    if ($enforcing.Count -gt 1) {
        $names = ($enforcing | ForEach-Object { "'$($_.Name)'" }) -join ', '
        $warnings += "More than one sync rule reacts to this marker: $names. Keep only one, so it is clear what happens to the person."
    }
    if ($result.AttributeImported -eq $false) {
        $warnings += "The AD connector does not import '$($definition.SourceAttribute)'. Until it does, no rule can see the marker. In Synchronization Service Manager: Connectors > AD connector > Properties > Select Attributes > tick it."
    }

    if ($verdict.State -eq 'Present' -and $SettingsPath) {
        Write-EntraConnectSettings -Path $SettingsPath -Server $server
    }

    $remediation = $null
    if ($verdict.State -ne 'Present') {
        $remediation = "Open 'Set up sync rules' to create or replace the rule, then run a Full Synchronization. Custom sync rules are not carried over when Entra Connect moves to a new server, so this is expected after a migration."
    }

    New-EntraConnectStatus -State $verdict.State -Server $server -Reason $verdict.Reason -Remediation $remediation `
        -Mechanism $verdict.Mechanism -RuleName $(if ($chosen) { $chosen.Name } else { $null }) -Warnings $warnings
}

function Get-BothRuleStatuses {
    <#
    .SYNOPSIS
        Finds the Entra Connect server once and checks both rules against it. Lives here (not
        in the window script) because the window runs it in a background runspace that loads
        only this file.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName,
        [string]$SettingsPath,
        [System.Management.Automation.PSCredential]$Credential
    )

    $found = Find-EntraConnectServer -ComputerName $ComputerName -SettingsPath $SettingsPath
    if (-not $found.Server) {
        $s = New-EntraConnectStatus -State 'Unknown' -Server $null `
            -Reason 'No Entra Connect server could be found. Searched this computer, the last server found, and Active Directory for a server running the ADSync service.' `
            -Remediation 'Type the Entra Connect server name in "Set up sync rules", or run the tool with -EntraConnectServer <name>.'
        return [PSCustomObject]@{ BlockCloudSignIn = $s; HideFromGAL = $s }
    }
    [PSCustomObject]@{
        BlockCloudSignIn = Test-EntraConnectRule -RuleKey 'BlockCloudSignIn' -ComputerName $found.Server -SettingsPath $SettingsPath -Credential $Credential
        HideFromGAL      = Test-EntraConnectRule -RuleKey 'HideFromGAL' -ComputerName $found.Server -SettingsPath $SettingsPath -Credential $Credential
    }
}

function Invoke-EntraConnectDeltaSync {
    <#
    .SYNOPSIS
        Starts a delta sync on the Entra Connect server. A delta sync picks up attribute
        changes on already-synced users; a NEW rule needs a full sync instead.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )

    $remote = {
        try {
            Import-Module ADSync -ErrorAction Stop
            $r = Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Stop
            return [PSCustomObject]@{ Success = $true; Detail = "$($r.Result)"; Error = $null }
        } catch {
            return [PSCustomObject]@{ Success = $false; Detail = $null; Error = $_.Exception.Message }
        }
    }

    if (-not $PSCmdlet.ShouldProcess($ComputerName, 'Start ADSync delta sync cycle')) {
        return [PSCustomObject]@{ Success = $false; Detail = 'Skipped (WhatIf)'; Error = $null }
    }

    try {
        Invoke-AdSyncCommand -ComputerName $ComputerName -ScriptBlock $remote -Credential $Credential
    } catch {
        [PSCustomObject]@{ Success = $false; Detail = $null; Error = $_.Exception.Message }
    }
}

#endregion

#region Rule creation

# Runs ON the Entra Connect server. Self-contained so the same text can be shipped as a
# standalone script for servers that refuse remote ADSync calls.
$script:CreateSyncRuleBlock = {
    param($Domain, $Name, $Description, $Destination, $Expression, $Precedence, $SourceAttribute, $AcceptedDestinations, $ReplaceExisting, $PreviewOnly)

    $warnings = @()
    try {
        Import-Module ADSync -ErrorAction Stop
    } catch {
        return [PSCustomObject]@{ Success = $false; Stage = 'ImportModule'; Error = "The ADSync module is not on this computer, so it is not the Entra Connect server. $($_.Exception.Message)"; Warnings = $warnings; Rule = $null; Removed = @() }
    }

    try {
        $adConnectors = @(Get-ADSyncConnector -ErrorAction Stop | Where-Object { [string]$_.Type -eq 'AD' })
    } catch {
        return [PSCustomObject]@{ Success = $false; Stage = 'GetConnector'; Error = $_.Exception.Message; Warnings = $warnings; Rule = $null; Removed = @() }
    }

    # Match the AD connector by domain; fall back to the only AD connector; never guess between several.
    $connector = @($adConnectors | Where-Object { $_.Name -like "*$Domain*" }) | Select-Object -First 1
    if (-not $connector -and $adConnectors.Count -eq 1) { $connector = $adConnectors[0] }
    if (-not $connector) {
        $names = ($adConnectors | ForEach-Object { $_.Name }) -join ', '
        return [PSCustomObject]@{ Success = $false; Stage = 'MatchConnector'; Error = "No AD connector matched domain '$Domain'. AD connectors on this server: $names"; Warnings = $warnings; Rule = $null; Removed = @() }
    }

    if ($connector.PSObject.Properties.Name -contains 'AttributeInclusionList' -and @($connector.AttributeInclusionList) -notcontains $SourceAttribute) {
        $warnings += "The AD connector '$($connector.Name)' does not import '$SourceAttribute', so the rule will not see the marker yet. Synchronization Service Manager > Connectors > '$($connector.Name)' > Properties > Select Attributes > tick '$SourceAttribute' > OK."
    }

    try {
        $allRules = @(Get-ADSyncRule -ErrorAction Stop)
    } catch {
        return [PSCustomObject]@{ Success = $false; Stage = 'ReadRules'; Error = $_.Exception.Message; Warnings = $warnings; Rule = $null; Removed = @() }
    }

    # Rules that already react to this marker by writing an accepted destination.
    $existing = @($allRules | Where-Object {
        $r = $_
        ([string]$r.Direction -eq 'Inbound') -and
        (@($r.AttributeFlowMappings | Where-Object { $AcceptedDestinations -contains $_.Destination }).Count -gt 0) -and
        ([System.Management.Automation.PSSerializer]::Serialize($r, 6) -match [regex]::Escape($SourceAttribute))
    })

    if ($existing.Count -gt 0 -and -not $ReplaceExisting) {
        $names = ($existing | ForEach-Object { "'$($_.Name)' (precedence $($_.Precedence))" }) -join ', '
        return [PSCustomObject]@{ Success = $false; Stage = 'AlreadyExists'; Error = "A rule that reacts to this marker already exists: $names. Nothing was changed. Replace it only if it is broken."; Warnings = $warnings; Rule = $null; Removed = @() }
    }

    # Precedence must be unused. Keep the preferred value if free, else the nearest free 1-99.
    $removeIds = @($existing | ForEach-Object { [string]$_.Identifier })
    $taken = @($allRules | Where-Object { $removeIds -notcontains [string]$_.Identifier } | ForEach-Object { [int]$_.Precedence })
    $chosenPrecedence = $null
    $order = @($Precedence) + @(($Precedence - 1)..1) + @(($Precedence + 1)..99)
    foreach ($p in $order) {
        if ($p -ge 1 -and $p -le 99 -and $taken -notcontains $p) { $chosenPrecedence = $p; break }
    }
    if ($null -eq $chosenPrecedence) {
        return [PSCustomObject]@{ Success = $false; Stage = 'Precedence'; Error = 'Every precedence number from 1 to 99 is already used by another sync rule.'; Warnings = $warnings; Rule = $null; Removed = @() }
    }
    if ($chosenPrecedence -ne $Precedence) {
        $warnings += "Precedence $Precedence is already used, so the rule uses $chosenPrecedence instead."
    }

    $plan = [PSCustomObject]@{ Name = $Name; Identifier = $null; Precedence = $chosenPrecedence; Connector = $connector.Name }
    $removedNames = @($existing | ForEach-Object { [string]$_.Name })

    if ($PreviewOnly) {
        return [PSCustomObject]@{ Success = $true; Stage = 'Preview'; Error = $null; Warnings = $warnings; Rule = $plan; Removed = $removedNames }
    }

    if ($ReplaceExisting) {
        try {
            foreach ($s in $existing) { Remove-ADSyncRule -Identifier $s.Identifier -ErrorAction Stop | Out-Null }
        } catch {
            return [PSCustomObject]@{ Success = $false; Stage = 'RemoveExisting'; Error = $_.Exception.Message; Warnings = $warnings; Rule = $null; Removed = @() }
        }
    }

    try {
        $ruleGuid = [guid]::NewGuid().ToString()
        # ImmutableTag is deliberately not set: it belongs only to Microsoft's out-of-box rules.
        $rule = New-ADSyncRule -Name $Name -Identifier $ruleGuid -Description $Description `
                               -Direction 'Inbound' -Precedence $chosenPrecedence `
                               -SourceObjectType 'user' -TargetObjectType 'person' `
                               -Connector $connector.Identifier -LinkType 'Join' -ErrorAction Stop
        $rule = Add-ADSyncAttributeFlowMapping -SynchronizationRule $rule -Destination $Destination `
                                               -FlowType 'Expression' -ValueMergeType 'Update' `
                                               -Expression $Expression -ErrorAction Stop
        Add-ADSyncRule -SynchronizationRule $rule -ErrorAction Stop | Out-Null
        $created = Get-ADSyncRule -Identifier $ruleGuid -ErrorAction Stop
        $plan.Identifier = [string]$created.Identifier
        $plan.Precedence = $created.Precedence
        return [PSCustomObject]@{ Success = $true; Stage = 'Created'; Error = $null; Warnings = $warnings; Rule = $plan; Removed = $removedNames }
    } catch {
        return [PSCustomObject]@{ Success = $false; Stage = 'CreateRule'; Error = $_.Exception.Message; Warnings = $warnings; Rule = $null; Removed = $removedNames }
    }
}

function Get-SyncRuleArgumentList {
    <#
    .SYNOPSIS
        Positional arguments for $script:CreateSyncRuleBlock, in its parameter order.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Blueprint,
        [bool]$ReplaceExisting = $false,
        [bool]$PreviewOnly = $false
    )

    $a = New-Object object[] 10
    $a[0] = $Blueprint.Domain
    $a[1] = $Blueprint.Name
    $a[2] = $Blueprint.Description
    $a[3] = $Blueprint.Destination
    $a[4] = $Blueprint.Expression
    $a[5] = [int]$Blueprint.Precedence
    $a[6] = $Blueprint.SourceAttribute
    $a[7] = @($Blueprint.AcceptedDestinations)
    $a[8] = $ReplaceExisting
    $a[9] = $PreviewOnly
    return ,$a
}

function Invoke-SyncRuleCreation {
    <#
    .SYNOPSIS
        Creates (or previews) a fix's sync rule on the Entra Connect server.
    .OUTPUTS
        The block's result object: Success, Stage, Error, Warnings, Rule, Removed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Blueprint,
        [Parameter(Mandatory)][string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential,
        [switch]$ReplaceExisting,
        [switch]$PreviewOnly
    )

    $argList = Get-SyncRuleArgumentList -Blueprint $Blueprint -ReplaceExisting ([bool]$ReplaceExisting) -PreviewOnly ([bool]$PreviewOnly)
    try {
        Invoke-AdSyncCommand -ComputerName $ComputerName -ScriptBlock $script:CreateSyncRuleBlock -ArgumentList $argList -Credential $Credential
    } catch {
        $msg = $_.Exception.Message
        $stage = if ($msg -match 'no endpoint listening|net\.pipe|ADSyncManagement') { 'RemoteBlocked' } else { 'Connect' }
        [PSCustomObject]@{ Success = $false; Stage = $stage; Error = $msg; Warnings = @(); Rule = $null; Removed = @() }
    }
}

function Get-FullSyncInstructions {
    <#
    .SYNOPSIS
        The steps that make a NEW rule apply to existing users.
    #>
    [CmdletBinding()]
    param(
        [string]$Server,
        [bool]$Destructive = $false
    )

    $where = if ($Server) { "On $Server" } else { 'On the Entra Connect server' }
    $lines = @(
        "NEXT STEP - required before the rule does anything:"
        ''
        "$where, run a Full Synchronization and review it before exporting:"
        '  1. Open Synchronization Service Manager (Start > Synchronization Service).'
        '  2. Connectors tab > select the Active Directory connector.'
        '  3. Actions > Run > Full Synchronization > OK. Wait for it to finish.'
        '  4. Right-click the Microsoft Entra connector > Search Connector Space.'
        '     Set Scope to "Pending Export" and REVIEW what is about to change.'
        '  5. Right-click the Microsoft Entra connector > Run > Export.'
    )
    if ($Destructive) {
        $lines += ''
        $lines += 'Step 4 matters: this rule DELETES matching people from Microsoft 365. Make sure only'
        $lines += 'the people you expect are listed before you export.'
    }
    $lines -join "`r`n"
}

function New-SyncRuleScriptText {
    <#
    .SYNOPSIS
        A standalone, ready-to-run script that creates the rule. For Entra Connect servers
        that refuse remote ADSync calls: copy it there and run it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Blueprint)

    function ConvertTo-PsLiteral([string]$s) { "'" + ($s -replace "'", "''") + "'" }

    $accepted = (@($Blueprint.AcceptedDestinations) | ForEach-Object { ConvertTo-PsLiteral $_ }) -join ', '
    $steps    = (Get-FullSyncInstructions -Destructive $Blueprint.IsDestructive) -replace "'", "''"
    $stamp    = Get-Date -Format 'yyyy-MM-dd HH:mm'
    $warnText = if ($Blueprint.IsDestructive) {
        "# WARNING: this rule REMOVES matching people from Microsoft 365 (cloudFiltered). Entra ID deletes`r`n# the account, mailbox and licences. Review pending exports before exporting."
    } else { '#' }

@"
#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
    Creates the Entra Connect sync rule for: $($Blueprint.MethodLabel)
    Generated by M365-SyncedUserFixes on $stamp.

    Run this ON the Entra Connect server, in an elevated PowerShell window:
        .\$(Get-SyncRuleScriptFileName -Blueprint $Blueprint) -WhatIf    # preview, changes nothing
        .\$(Get-SyncRuleScriptFileName -Blueprint $Blueprint)            # create the rule

    It stops without changing anything if a rule for this marker already exists.
    Use -Replace only to replace a broken one.

$($Blueprint.Consequence -replace '(.{1,90})(\s|$)', "    `$1`r`n")#>
$warnText
[CmdletBinding()]
param(
    [switch]`$WhatIf,
    [switch]`$Replace
)

`$createBlock = {
$($script:CreateSyncRuleBlock.ToString())
}

`$result = & `$createBlock $(ConvertTo-PsLiteral $Blueprint.Domain) $(ConvertTo-PsLiteral $Blueprint.Name) $(ConvertTo-PsLiteral $Blueprint.Description) $(ConvertTo-PsLiteral $Blueprint.Destination) $(ConvertTo-PsLiteral $Blueprint.Expression) $([int]$Blueprint.Precedence) $(ConvertTo-PsLiteral $Blueprint.SourceAttribute) @($accepted) ([bool]`$Replace) ([bool]`$WhatIf)

foreach (`$w in @(`$result.Warnings)) { Write-Host "[WARN] `$w" -ForegroundColor Yellow }
if (-not `$result.Success) {
    Write-Host "[FAIL] `$(`$result.Error)" -ForegroundColor Red
    exit 1
}
if (`$result.Stage -eq 'Preview') {
    Write-Host "[INFO] WhatIf: would create '`$(`$result.Rule.Name)' at precedence `$(`$result.Rule.Precedence) on connector '`$(`$result.Rule.Connector)'." -ForegroundColor Cyan
    foreach (`$n in @(`$result.Removed)) { Write-Host "[INFO] WhatIf: would remove existing rule '`$n'." -ForegroundColor Cyan }
    exit 0
}
foreach (`$n in @(`$result.Removed)) { Write-Host "[INFO] Removed existing rule '`$n'." -ForegroundColor Cyan }
Write-Host "[PASS] Created '`$(`$result.Rule.Name)' (precedence `$(`$result.Rule.Precedence), connector '`$(`$result.Rule.Connector)')." -ForegroundColor Green
Write-Host ''
Write-Host '$steps' -ForegroundColor Yellow
"@
}

function Get-SyncRuleScriptFileName {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Blueprint)
    "New-SyncRule_$($Blueprint.Key)_$($Blueprint.Method).ps1"
}

#endregion

#region Active Directory users

function ConvertTo-LdapFilterValue {
    <#
    .SYNOPSIS
        Escapes text for an LDAP filter value (RFC 4515): \ * ( ) and NUL.
        https://learn.microsoft.com/windows/win32/adsi/search-filter-syntax
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Value)

    if ($null -eq $Value) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        switch ($ch) {
            '\'      { [void]$sb.Append('\5c') }
            '*'      { [void]$sb.Append('\2a') }
            '('      { [void]$sb.Append('\28') }
            ')'      { [void]$sb.Append('\29') }
            ([char]0) { [void]$sb.Append('\00') }
            default  { [void]$sb.Append($ch) }
        }
    }
    $sb.ToString()
}

function New-SyncedUserLdapFilter {
    <#
    .SYNOPSIS
        LDAP filter for the user list: people only, optional text search, optional
        enabled-only, optional marked-only.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Feature,
        [string]$Search,
        [switch]$IncludeDisabled,
        [switch]$OnlyMarked
    )

    $parts = @('(objectCategory=person)', '(objectClass=user)')
    if (-not $IncludeDisabled) {
        # Bit 0x2 (ACCOUNTDISABLE) not set, via the LDAP_MATCHING_RULE_BIT_AND rule.
        $parts += '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
    }
    if ($OnlyMarked) {
        $parts += "($($Feature.Attribute)=$(ConvertTo-LdapFilterValue $Feature.MarkerValue))"
    }
    $text = ''
    if ($Search) { $text = $Search.Trim() }
    if ($text) {
        $v = ConvertTo-LdapFilterValue $text
        $parts += "(|(name=*$v*)(displayName=*$v*)(sAMAccountName=*$v*)(userPrincipalName=*$v*)(mail=*$v*))"
    }
    '(&' + ($parts -join '') + ')'
}

function Get-OuFromDistinguishedName {
    <#
    .SYNOPSIS
        Readable parent path of a DN: "CN=Jane,OU=Sales,OU=Staff,DC=contoso,DC=com" -> "Staff/Sales".
    #>
    [CmdletBinding()]
    param([string]$DistinguishedName)

    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return '' }
    # Split on commas that are not escaped (\,) so names like "Doe\, Jane" stay intact.
    $rdns = [regex]::Split($DistinguishedName, '(?<!\\),')
    $names = @()
    for ($i = 1; $i -lt $rdns.Count; $i++) {
        if ($rdns[$i] -match '^(OU|CN)=(.+)$') { $names += ($Matches[2] -replace '\\,', ',') }
    }
    [array]::Reverse($names)
    if ($names.Count -eq 0) { return '(domain root)' }
    $names -join '/'
}

function Get-MarkerStatus {
    <#
    .SYNOPSIS
        What a person's row should say, from their marker AND the rule status. A marked person
        on a server with no working rule is NOT blocked/hidden, and must not be shown as such.
    .OUTPUTS
        PSCustomObject: Text, Kind (On | Off | Warn | Unverified)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Feature,
        [bool]$Marked,
        [AllowNull()][object]$RuleStatus
    )

    if (-not $Marked) { return [PSCustomObject]@{ Text = $Feature.UnmarkedText; Kind = 'Off' } }
    if ($RuleStatus -and $RuleStatus.CanEnforce) { return [PSCustomObject]@{ Text = $Feature.MarkedText; Kind = 'On' } }
    if ($RuleStatus -and $RuleStatus.ShouldBlock) { return [PSCustomObject]@{ Text = "NOT $($Feature.MarkedText.ToLower()) - rule missing"; Kind = 'Warn' } }
    [PSCustomObject]@{ Text = "$($Feature.MarkedText) (unconfirmed)"; Kind = 'Unverified' }
}

function Get-SyncedUserRows {
    <#
    .SYNOPSIS
        Searches AD and returns one row per person for the list.
    .OUTPUTS
        PSCustomObject: IsSelected, Name, SamAccountName, UserPrincipalName, Enabled, OU,
        DistinguishedName, Marked, StatusText, StatusKind. A final property on the batch is
        not possible, so the caller compares the count with -ResultSize to spot truncation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('BlockSignIn', 'HideFromGAL')]
        [string]$FeatureKey,

        [string]$Search,
        [switch]$IncludeDisabled,
        [switch]$OnlyMarked,
        [string]$SearchBase,
        [string]$Server,
        [AllowNull()][object]$RuleStatus,
        [int]$ResultSize = 1000
    )

    $feature = Get-SyncedUserFeature -Key $FeatureKey
    $filter  = New-SyncedUserLdapFilter -Feature $feature -Search $Search -IncludeDisabled:$IncludeDisabled -OnlyMarked:$OnlyMarked

    # -ResultSetSize caps the number of objects returned (it is not "-ResultSize").
    # https://learn.microsoft.com/powershell/module/activedirectory/get-aduser
    $params = @{
        LDAPFilter    = $filter
        Properties    = @('displayName', 'userPrincipalName', $feature.Attribute)
        ResultSetSize = $ResultSize
        ErrorAction   = 'Stop'
    }
    if ($SearchBase) { $params['SearchBase'] = $SearchBase }
    if ($Server)     { $params['Server'] = $Server }

    $rows = @()
    foreach ($u in @(Get-ADUser @params)) {
        $marked = ([string]$u.($feature.Attribute) -ceq $feature.MarkerValue)
        $status = Get-MarkerStatus -Feature $feature -Marked $marked -RuleStatus $RuleStatus
        $display = if ($u.displayName) { [string]$u.displayName } else { [string]$u.Name }
        $rows += [PSCustomObject]@{
            IsSelected        = $false
            Name              = $display
            SamAccountName    = [string]$u.SamAccountName
            UserPrincipalName = [string]$u.UserPrincipalName
            Enabled           = [bool]$u.Enabled
            AccountText       = $(if ($u.Enabled) { 'Enabled' } else { 'Disabled in AD' })
            OU                = Get-OuFromDistinguishedName -DistinguishedName ([string]$u.DistinguishedName)
            DistinguishedName = [string]$u.DistinguishedName
            Marked            = $marked
            StatusText        = $status.Text
            StatusKind        = $status.Kind
        }
    }
    @($rows | Sort-Object Name)
}

function Set-SyncedUserMarker {
    <#
    .SYNOPSIS
        Applies or removes a fix's marker on one AD user. Never throws; returns a result row
        that is also the change-log entry.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('BlockSignIn', 'HideFromGAL')]
        [string]$FeatureKey,

        [Parameter(Mandatory)]
        [ValidateSet('Apply', 'Remove')]
        [string]$Action,

        [Parameter(Mandatory)][string]$Identity,
        [string]$Server,
        [AllowNull()][object]$RuleStatus
    )

    $feature = Get-SyncedUserFeature -Key $FeatureKey
    $verb = if ($Action -eq 'Apply') { $feature.ApplyVerb } else { $feature.RemoveVerb }
    $entry = [ordered]@{
        Time               = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Technician         = "$env:USERDOMAIN\$env:USERNAME"
        Computer           = $env:COMPUTERNAME
        Action             = $verb
        User               = $Identity
        Attribute          = $feature.Attribute
        OldValue           = ''
        NewValue           = $(if ($Action -eq 'Apply') { $feature.MarkerValue } else { '' })
        Result             = ''
        Error              = ''
        RuleState          = $(if ($RuleStatus) { $RuleStatus.State } else { 'NotChecked' })
        EntraConnectServer = $(if ($RuleStatus) { $RuleStatus.Server } else { '' })
    }

    $adArgs = @{ Identity = $Identity; ErrorAction = 'Stop' }
    if ($Server) { $adArgs['Server'] = $Server }

    try {
        $before = Get-ADUser @adArgs -Properties $feature.Attribute
        $entry.OldValue = [string]$before.($feature.Attribute)
        $entry.User = [string]$before.SamAccountName

        if ($PSCmdlet.ShouldProcess($entry.User, $verb)) {
            # -Replace, not -Add: the attribute is single-valued, and -Replace also overwrites
            # an unrelated value someone else left there (it is shown in OldValue).
            if ($Action -eq 'Apply') {
                Set-ADUser @adArgs -Replace @{ $feature.Attribute = $feature.MarkerValue }
            } else {
                Set-ADUser @adArgs -Clear $feature.Attribute
            }
            $entry.Result = 'Done'
        } else {
            $entry.Result = 'Skipped (WhatIf)'
        }
    } catch {
        $entry.Result = 'Failed'
        $entry.Error = $_.Exception.Message
    }

    [PSCustomObject]$entry
}

function Invoke-SyncedUserMarkerBatch {
    <#
    .SYNOPSIS
        Applies or removes a marker for several people. One result row per person; a failure
        for one does not stop the rest. Lives here (not in the window script) because the
        window runs it in a background runspace that loads only this file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('BlockSignIn', 'HideFromGAL')][string]$FeatureKey,
        [Parameter(Mandatory)][ValidateSet('Apply', 'Remove')][string]$Action,
        [Parameter(Mandatory)][string[]]$Identities,
        [AllowNull()][object]$RuleStatus
    )
    foreach ($id in $Identities) {
        Set-SyncedUserMarker -FeatureKey $FeatureKey -Action $Action -Identity $id -RuleStatus $RuleStatus
    }
}

function Write-SyncedUserChangeLog {
    <#
    .SYNOPSIS
        Appends change rows to Changes_<yyyy-MM-dd>.csv in the log folder. Returns the path,
        or $null when the folder cannot be written (the change itself already happened).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Entries,
        [Parameter(Mandatory)][string]$LogFolder
    )

    try {
        if (-not (Test-Path -LiteralPath $LogFolder)) { New-Item -ItemType Directory -Path $LogFolder -Force -ErrorAction Stop | Out-Null }
        $path = Join-Path $LogFolder ("Changes_{0}.csv" -f (Get-Date -Format 'yyyy-MM-dd'))
        $exists = Test-Path -LiteralPath $path
        $csv = @($Entries | ConvertTo-Csv -NoTypeInformation)
        if ($exists) { $csv = $csv | Select-Object -Skip 1 }
        Add-Content -LiteralPath $path -Value $csv -Encoding UTF8 -ErrorAction Stop
        return $path
    } catch {
        Write-Verbose "Could not write change log: $($_.Exception.Message)"
        return $null
    }
}

#endregion

if ($LoadFunctionsOnly) { return }
