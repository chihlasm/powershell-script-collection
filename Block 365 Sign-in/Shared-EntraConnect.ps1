<#
.SYNOPSIS
    Shared Entra Connect discovery, sync-rule verification, and remote sync helpers.
.DESCRIPTION
    Dot-sourced by the attribute-marker tools that depend on a custom Entra Connect
    synchronization rule for enforcement (Block 365 Sign-in, HideFromGal).

    THE PROBLEM THIS SOLVES
    Those tools write a marker attribute to a user object in AD. The marker does nothing
    on its own - enforcement comes from a custom inbound sync rule running inside Entra
    Connect, usually on a DIFFERENT server. Custom sync rules are NOT migrated when Entra
    Connect is moved or swung to a new server; Microsoft's guidance is that they must be
    recreated manually. When that recreation is missed, the marker tool keeps reporting
    success while enforcing nothing.
    https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-import-export-config

    These helpers make that cross-server dependency visible: find the Connect server,
    verify the rule actually exists there, and report UNKNOWN separately from MISSING so
    a permissions or WinRM failure is never mistaken for a broken rule.

.NOTES
    DUPLICATED FILE - keep in sync with:
        HideFromGal\Shared-EntraConnect.ps1
    The repository convention is flat, self-contained tool folders with no shared module,
    so this file is deliberately copied rather than imported across folders. Any change
    here must be mirrored to the twin.

    The ADSync PowerShell module exists ONLY on the Entra Connect server, so every call
    that touches it runs through Invoke-Command against that server.

    REFERENCES
    - Make a change to the default configuration (custom rules, precedence 1-99, cloudFiltered):
      https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-change-the-configuration
    - Import and export Connect configuration (custom rules are not migrated automatically):
      https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-import-export-config
    - ADSync PowerShell reference:
      https://learn.microsoft.com/entra/identity/hybrid/connect/reference-connect-adsync
    - Accounts and permissions (MSOL_ account lives in forest root Users container):
      https://learn.microsoft.com/entra/identity/hybrid/connect/reference-connect-accounts-permissions
#>

[CmdletBinding()]
param(
    # Lets Pester dot-source the pure functions without executing discovery.
    [switch]$LoadFunctionsOnly
)

#region Rule definitions

# The single source of truth for what each tool's enforcement rule must look like.
# Verification compares against these, so a rule that was renamed, re-pointed at a
# different attribute, or had its expression edited is treated as broken - not merely
# a name match.
#
# Precedence: Microsoft reserves 1-99 for custom sync rules; out-of-box rules start at
# 100. A custom rule at 100+ collides with Microsoft's range.
# https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-change-the-configuration
$script:EntraConnectRuleDefinitions = @{
    'BlockCloudSignIn' = [PSCustomObject]@{
        Key             = 'BlockCloudSignIn'
        NamePrefix      = 'Block cloud sign-in'
        SourceAttribute = 'msDS-cloudExtensionAttribute10'
        MarkerValue     = 'BlockCloudSignIn'
        Destination     = 'cloudFiltered'
        # There is more than one legitimate way to block cloud sign-in from a marker
        # attribute, and a rule using any of them is doing the job:
        #
        #   cloudFiltered  - excludes the user from syncing at all. The Entra ID object
        #                    is deleted, taking licenses, mailbox and group membership
        #                    with it. This is what this toolkit's rule builder creates.
        #   accountEnabled - flows False into the synced account, disabling sign-in while
        #                    the cloud object (and its licenses/mailbox) survives.
        #
        # Verification accepts either. Checking only for cloudFiltered reported a real,
        # working accountEnabled rule as "NOT FOUND" and disabled the tool.
        AcceptedDestinations = @('cloudFiltered', 'accountEnabled')
        Precedence      = 60
        Description     = 'If msDS-cloudExtensionAttribute10 is set to BlockCloudSignIn, filter the user from syncing to Entra ID (blocks cloud sign-in).'
        Expression      = 'IIF(IsPresent([msDS-cloudExtensionAttribute10]),IIF([msDS-cloudExtensionAttribute10]="BlockCloudSignIn",True,False),NULL)'
    }
    'HideFromGAL' = [PSCustomObject]@{
        Key             = 'HideFromGAL'
        NamePrefix      = 'Hide user from GAL'
        SourceAttribute = 'msDS-cloudExtensionAttribute1'
        MarkerValue     = 'HideFromGAL'
        Destination     = 'msExchHideFromAddressLists'
        AcceptedDestinations = @('msExchHideFromAddressLists')
        Precedence      = 50
        Description     = 'If msDS-cloudExtensionAttribute1 is set to HideFromGAL, hide the user from the Exchange Online GAL.'
        Expression      = 'IIF(IsPresent([msDS-cloudExtensionAttribute1]),IIF([msDS-cloudExtensionAttribute1]="HideFromGAL",True,False),NULL)'
    }
}

function Get-EntraConnectRuleDefinition {
    <#
    .SYNOPSIS
        Returns the expected shape of a tool's enforcement sync rule.
    .PARAMETER Key
        Which rule definition to return: BlockCloudSignIn or HideFromGAL.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('BlockCloudSignIn', 'HideFromGAL')]
        [string]$Key
    )
    $script:EntraConnectRuleDefinitions[$Key]
}

#endregion

#region Pure helpers (no remoting - unit tested)

function ConvertTo-ComparableExpression {
    <#
    .SYNOPSIS
        Normalizes a sync-rule expression for comparison.
    .DESCRIPTION
        The Synchronization Rules Editor and PowerShell both accept expressions with
        differing whitespace, so a raw string comparison produces false mismatches.
        Case is NOT normalized: the sync engine is case-sensitive for both function
        names and attribute names, so a case difference is a genuine defect worth
        surfacing rather than smoothing over.
        https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-change-the-configuration
    #>
    [CmdletBinding()]
    param([string]$Expression)

    if ([string]::IsNullOrWhiteSpace($Expression)) { return '' }
    ($Expression -replace '\s', '')
}

function Test-EntraConnectRuleShape {
    <#
    .SYNOPSIS
        Decides whether a retrieved sync rule actually enforces what the tool expects.
    .DESCRIPTION
        Pure function: takes an already-retrieved rule object (or $null) plus the
        expected definition, and returns a verdict. Kept free of remoting so the
        decision logic can be unit tested against captured rule shapes.

        Returns a PSCustomObject with:
          State  - Present | Missing | Misconfigured
          Reason - plain-English explanation suitable for a GUI banner
    .PARAMETER Rule
        The rule object returned by Get-ADSyncRule, or $null when none was found.
    .PARAMETER Definition
        The expected rule definition from Get-EntraConnectRuleDefinition.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Rule,

        [Parameter(Mandatory)]
        [object]$Definition
    )

    if ($null -eq $Rule) {
        return [PSCustomObject]@{
            State  = 'Missing'
            Reason = "No sync rule flowing to '$($Definition.Destination)' from '$($Definition.SourceAttribute)' was found on the Entra Connect server. Nothing is enforcing this setting."
        }
    }

    # Any of the accepted destinations counts. Blocking cloud sign-in can be done by
    # filtering the user out of Entra ID (cloudFiltered) or by disabling the synced
    # account (accountEnabled), and both are legitimate.
    $accepted = if ($Definition.PSObject.Properties.Name -contains 'AcceptedDestinations') {
        @($Definition.AcceptedDestinations)
    } else {
        @($Definition.Destination)
    }

    $flow = $null
    if ($Rule.PSObject.Properties.Name -contains 'AttributeFlowMappings') {
        $flow = $Rule.AttributeFlowMappings |
                Where-Object { $accepted -contains $_.Destination } |
                Select-Object -First 1
    }

    if ($null -eq $flow) {
        $list = $accepted -join "' or '"
        return [PSCustomObject]@{
            State  = 'Misconfigured'
            Reason = "Sync rule '$($Rule.Name)' exists but has no attribute flow to '$list'. It is not enforcing this setting."
        }
    }

    # Does the rule reference the marker attribute ANYWHERE - the flow expression, the
    # flow source, or a scoping filter? All three are legitimate ways to build this
    # rule, and they enforce identically.
    #
    # An earlier version compared only the flow expression against our own generated
    # one and reported anything different as broken. That wrongly condemned a
    # hand-built rule ("Block 365 Sign In", precedence 10) that drove the same
    # behavior through a scoping filter. The tool verifies that enforcement EXISTS;
    # it is not the author of the only acceptable rule.
    # ReferencesMarker is computed on the sync server by serializing the whole rule
    # object, so it sees the attribute wherever it lives regardless of the scoping-filter
    # shape in that Entra Connect version. Fall back to inspecting the flattened fields
    # when it is absent (unit tests construct rules by hand without it).
    $referencesMarker = if ($Rule.PSObject.Properties.Name -contains 'ReferencesMarker') {
        [bool]$Rule.ReferencesMarker
    } else {
        $haystack = @()
        $haystack += ($Rule.AttributeFlowMappings | ForEach-Object { "$($_.Expression) $($_.Source)" })
        if ($Rule.PSObject.Properties.Name -contains 'ScopeConditions') {
            $haystack += ($Rule.ScopeConditions | ForEach-Object { "$($_.Attribute) $($_.Value)" })
        }
        (($haystack -join ' ') -match [regex]::Escape($Definition.SourceAttribute))
    }

    if (-not $referencesMarker) {
        return [PSCustomObject]@{
            State  = 'Misconfigured'
            Reason = "A sync rule named '$($Rule.Name)' (precedence $($Rule.Precedence)) does flow to '$($Definition.Destination)', but this tool could not find any reference to '$($Definition.SourceAttribute)' in it. If that rule is driven by a different attribute, this tool's marker will not trigger it - open it in the Synchronization Rules Editor to confirm which attribute it uses."
        }
    }

    # An exact match to our generated expression is reported, but any rule that both
    # writes the destination and reads the marker counts as present.
    $actual   = ConvertTo-ComparableExpression -Expression $flow.Expression
    $expected = ConvertTo-ComparableExpression -Expression $Definition.Expression
    $exact    = ($actual -ceq $expected)

    # Name the mechanism: the two accepted destinations have materially different
    # consequences, and an admin should know which one is in force.
    $mechanism = switch ($flow.Destination) {
        'cloudFiltered'  { 'removes the user from Entra ID entirely (licenses and mailbox go with it)' }
        'accountEnabled' { 'disables the synced account, leaving licenses and mailbox intact' }
        default          { "flows to '$($flow.Destination)'" }
    }
    $detail = if ($exact) { '' } else { ' Built differently from this toolkit''s default, which is fine.' }

    [PSCustomObject]@{
        State  = 'Present'
        Reason = "Sync rule '$($Rule.Name)' (precedence $($Rule.Precedence)) is enforcing this: it $mechanism.$detail"
    }
}

function New-EntraConnectStatus {
    <#
    .SYNOPSIS
        Builds the status object the GUI and console tools consume.
    .DESCRIPTION
        Pure constructor. Centralizes the contract so every caller reads the same
        fields, and so the critical distinction below is enforced in one place:

          CanEnforce  - $true ONLY when the rule was positively verified present.
          ShouldBlock - $true ONLY when we positively confirmed the rule is absent or
                        broken. An unreachable server or a permissions failure yields
                        Unknown, which must NEVER block the tool: "we could not check"
                        is not "it is broken".
    .PARAMETER State
        Present | Missing | Misconfigured | Unknown
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Present', 'Missing', 'Misconfigured', 'Unknown')]
        [string]$State,

        [string]$Server,
        [string]$Reason,
        [string]$Remediation
    )

    [PSCustomObject]@{
        State       = $State
        Server      = $Server
        Reason      = $Reason
        Remediation = $Remediation
        CanEnforce  = ($State -eq 'Present')
        ShouldBlock = ($State -in @('Missing', 'Misconfigured'))
        CheckedAt   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    }
}

function Get-EntraConnectStatusPresentation {
    <#
    .SYNOPSIS
        Maps a status state to its console prefix and GUI banner colors.
    .DESCRIPTION
        Pure lookup so console and GUI render the same states identically, and so the
        color/prefix mapping is unit testable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Present', 'Missing', 'Misconfigured', 'Unknown')]
        [string]$State
    )

    switch ($State) {
        'Present' {
            [PSCustomObject]@{
                Prefix = '[PASS]'; ConsoleColor = 'Green'
                BannerBack = '#1B3A2A'; BannerFore = '#7EE2A8'
                Headline = 'Enforcement rule verified'
            }
        }
        'Missing' {
            [PSCustomObject]@{
                Prefix = '[FAIL]'; ConsoleColor = 'Red'
                BannerBack = '#3A1B1B'; BannerFore = '#FF8A8A'
                Headline = 'Enforcement rule NOT FOUND'
            }
        }
        'Misconfigured' {
            [PSCustomObject]@{
                Prefix = '[FAIL]'; ConsoleColor = 'Red'
                BannerBack = '#3A1B1B'; BannerFore = '#FF8A8A'
                Headline = 'Enforcement rule is broken'
            }
        }
        'Unknown' {
            [PSCustomObject]@{
                Prefix = '[WARN]'; ConsoleColor = 'Yellow'
                BannerBack = '#3A331B'; BannerFore = '#F2D06B'
                Headline = 'Could not verify enforcement rule'
            }
        }
    }
}

function Test-IsLocalMachine {
    <#
    .SYNOPSIS
        Returns $true when the named computer is the machine we are running on.
    .DESCRIPTION
        This matters more than it looks. The ADSync management interface is a WCF
        endpoint bound to net.pipe://localhost/ADSyncManagement, and it does NOT accept
        calls that arrive over a PowerShell remoting hop - even a hop to the same
        machine. Running Get-ADSyncRule inside Invoke-Command against the local server
        therefore fails with "There is no endpoint listening on
        net.pipe://localhost/ADSyncManagement", despite the service running perfectly.

        So whenever the target is this machine, the ADSync cmdlets must be called
        directly rather than through Invoke-Command. Accepts short name, FQDN,
        'localhost', '.', and the loopback address.
    #>
    [CmdletBinding()]
    param([string]$ComputerName)

    if ([string]::IsNullOrWhiteSpace($ComputerName)) { return $true }

    # Check the aliases BEFORE trimming trailing dots: '.' is itself a valid local
    # target and TrimEnd('.') would reduce it to an empty string.
    $raw = $ComputerName.Trim()
    if ($raw -in @('.', 'localhost', '127.0.0.1', '::1')) { return $true }

    $target = $raw.TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($target)) { return $true }

    $me = $env:COMPUTERNAME
    if ($target -eq $me) { return $true }
    if ($target -like "$me.*") { return $true }

    # Compare against this machine's own FQDN as AD knows it.
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
        Runs a scriptblock against the Entra Connect server, locally when possible.
    .DESCRIPTION
        Centralizes the local-vs-remote decision so every ADSync call makes it the same
        way. Running locally is not merely an optimization: the ADSync WCF endpoint
        rejects calls arriving over a remoting hop, so a local direct call is the only
        thing that works when this IS the Connect server.
    .PARAMETER ComputerName
        Target server.
    .PARAMETER ScriptBlock
        Work to run. Must return an object; it should not rely on caller variables.
    .PARAMETER ArgumentList
        Arguments passed positionally to the scriptblock.
    .PARAMETER Credential
        Optional credential, used only for genuinely remote calls.
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
    <#
    .SYNOPSIS
        Path to the cache file holding the last known good Connect server.
    #>
    [CmdletBinding()]
    param([string]$ScriptRoot = $PSScriptRoot)
    Join-Path -Path $ScriptRoot -ChildPath 'EntraConnectSettings.json'
}

function Read-EntraConnectSettings {
    <#
    .SYNOPSIS
        Reads the cached Connect server, tolerating a missing or corrupt file.
    #>
    [CmdletBinding()]
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        # A hand-edited or truncated cache must not take the tool down; rediscovery follows.
        Write-Verbose "Ignoring unreadable settings file '$Path': $($_.Exception.Message)"
        $null
    }
}

function Write-EntraConnectSettings {
    <#
    .SYNOPSIS
        Caches the verified Connect server so the next launch skips discovery.
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
        # Caching is an optimization. A read-only script folder must not break the tool.
        Write-Verbose "Could not write settings file '$Path': $($_.Exception.Message)"
    }
}

#endregion

#region Remote operations

function Test-AdSyncServer {
    <#
    .SYNOPSIS
        Returns $true when the named server is running the ADSync service.
    .DESCRIPTION
        The ADSync service is the definitive local marker of an Entra Connect
        installation. Checked over CIM/WMI first because it needs no WinRM.
        https://learn.microsoft.com/entra/identity/hybrid/connect/concept-adsync-service-account
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [int]$TimeoutSeconds = 5
    )

    try {
        # @() so a no-match result is an empty array rather than $null, and check the
        # returned service's Name explicitly. A bare "$null -ne $result" test wrongly
        # passed servers with no ADSync service at all - which is how discovery landed
        # on a domain controller and then failed with a SOAP "no endpoint listening"
        # error when it tried to query sync rules there.
        $svc = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='ADSync'" `
                                 -ComputerName $ComputerName -OperationTimeoutSec $TimeoutSeconds `
                                 -ErrorAction Stop)
        return ($svc.Count -gt 0 -and $svc[0].Name -eq 'ADSync')
    } catch {
        Write-Verbose "ADSync probe failed on '$ComputerName': $($_.Exception.Message)"
        return $false
    }
}

function Find-EntraConnectServer {
    <#
    .SYNOPSIS
        Locates the Entra Connect server, newest-information-first.
    .DESCRIPTION
        There is no single authoritative AD attribute naming the Connect server, so
        discovery is layered and the first hit wins:

          1. An explicitly supplied -ComputerName (always authoritative)
          2. The cached server from the last successful check, re-probed before trust
          3. Auto-discovery: AD server computer objects probed for the ADSync service
          4. $null - the caller prompts the user

        Re-probing the cache is what lets the tools survive an Entra Connect migration
        without a code change: a stale cached name simply fails its probe and falls
        through to discovery.
    .PARAMETER ComputerName
        Explicit server name. Skips all discovery.
    .PARAMETER SettingsPath
        Cache file to read and update.
    .PARAMETER MaxCandidates
        Upper bound on servers probed during auto-discovery.
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

    # Layer 2: cached value, re-probed so a stale entry cannot silently mislead.
    $settings = Read-EntraConnectSettings -Path $SettingsPath
    if ($settings -and -not [string]::IsNullOrWhiteSpace($settings.EntraConnectServer)) {
        $cached = $settings.EntraConnectServer
        if (Test-AdSyncServer -ComputerName $cached) {
            return [PSCustomObject]@{ Server = $cached; Source = 'Cache' }
        }
        Write-Verbose "Cached server '$cached' is no longer running ADSync - rediscovering."
    }

    # Layer 3: probe AD server computer objects for the ADSync service.
    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        # Query AD for candidates rather than hardcoding names, per repo convention.
        # Enabled servers only, most-recently-logged-on first: a live Connect server is
        # active daily, so this ordering finds it within the first few probes.
        $candidates = Get-ADComputer -Filter "OperatingSystem -like '*Server*' -and Enabled -eq 'True'" `
                                     -Properties OperatingSystem, LastLogonDate -ErrorAction Stop |
                      Sort-Object LastLogonDate -Descending |
                      Select-Object -First $MaxCandidates

        foreach ($c in $candidates) {
            if (Test-AdSyncServer -ComputerName $c.DNSHostName -TimeoutSeconds 3) {
                return [PSCustomObject]@{ Server = $c.DNSHostName; Source = 'Discovered' }
            }
        }
    } catch {
        Write-Verbose "AD-based discovery failed: $($_.Exception.Message)"
    }

    [PSCustomObject]@{ Server = $null; Source = 'NotFound' }
}

function Test-EntraConnectRule {
    <#
    .SYNOPSIS
        Verifies a tool's enforcement sync rule on the Entra Connect server.
    .DESCRIPTION
        Runs Get-ADSyncRule remotely (the ADSync module exists only on the Connect
        server) and classifies the result into exactly one of four states:

          Present       - rule found and its expression matches what the tool expects
          Missing       - reached the server, ADSync answered, no matching rule exists
          Misconfigured - a rule exists but does not enforce the expected behavior
          Unknown       - could not check (server not found, WinRM blocked, no rights)

        Unknown is deliberately distinct from Missing. Treating an unreachable server
        as a missing rule would block a perfectly healthy system.
    .PARAMETER RuleKey
        BlockCloudSignIn or HideFromGAL.
    .PARAMETER ComputerName
        Explicit Connect server; omit to auto-discover.
    .PARAMETER SettingsPath
        Cache file for the discovered server name.
    .PARAMETER Credential
        Optional credential for the remote call, when the current user lacks local
        admin on the Connect server.
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
            -Remediation "Re-run with -EntraConnectServer <name> to name the sync server directly. If Entra Connect was recently moved, the new server may not be reachable from here."
    }

    $server = $found.Server

    # Marshal only the primitives needed on the far side; the remote session cannot see
    # local variables. Filtering by destination rather than name catches a renamed rule.
    $remote = {
        param($Destinations, $SourceAttribute)

        try {
            Import-Module ADSync -ErrorAction Stop
        } catch {
            return [PSCustomObject]@{ Outcome = 'NoModule'; Error = $_.Exception.Message; Rule = $null }
        }

        try {
            $inbound = @(Get-ADSyncRule -ErrorAction Stop | Where-Object { $_.Direction -eq 'Inbound' })

            # Match on any ACCEPTED DESTINATION. A rule can drive the marker through a
            # scoping filter with a constant flow rather than naming the attribute in an
            # expression, and can block sign-in via either cloudFiltered or
            # accountEnabled. All of those enforce the intent. Filtering on one
            # destination and on expression text rejected a real, working rule
            # ("Block 365 Sign In", precedence 10, accountEnabled <- False).
            $candidates = @($inbound | Where-Object {
                @($_.AttributeFlowMappings | Where-Object { $Destinations -contains $_.Destination }).Count -gt 0
            })

            # Flatten scoping filters too, so the caller can see how the rule is driven.
            # Rich ADSync types do not always deserialize cleanly across a remoting
            # boundary, so everything is reduced to plain properties here.
            $flatten = {
                param($r)

                # Serialize the ENTIRE rule object to text and search that, instead of
                # reaching for property names. The scoping-filter structure varies by
                # Entra Connect version (ScopeFilter / ScopeFilters, ConditionBase and
                # its nesting), and guessing wrong meant reading nothing and declaring a
                # real, working rule missing. A depth-limited CliXml dump captures every
                # nested attribute name whatever the shape, which is all that is needed
                # to answer "does this rule reference our marker attribute?".
                $dump = ''
                try {
                    $dump = [System.Management.Automation.PSSerializer]::Serialize($r, 6)
                } catch {
                    # Last-resort fallback: property-by-property ToString().
                    try {
                        $dump = ($r.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' '
                    } catch { $dump = '' }
                }

                # Best-effort structured view of the scoping filters, when the shape is
                # one we recognize. Used for display only - matching relies on $dump.
                # Confirmed shape on Entra Connect: rule.ScopeFilter is a collection whose
                # members expose ScopeConditionList (NOT ConditionBase, which was a wrong
                # guess that read nothing). Both are tried, plus the serialized dump above
                # as the real safety net.
                $scopes = @()
                foreach ($propName in @('ScopeFilter', 'ScopeFilters')) {
                    if ($r.PSObject.Properties.Name -notcontains $propName) { continue }
                    foreach ($group in @($r.$propName)) {
                        $conds = @()
                        foreach ($listName in @('ScopeConditionList', 'ConditionBase')) {
                            if ($group.PSObject.Properties.Name -contains $listName) {
                                $conds += @($group.$listName)
                            }
                        }
                        foreach ($cond in $conds) {
                            if ($null -eq $cond) { continue }
                            $scopes += [PSCustomObject]@{
                                Attribute  = [string]$cond.Attribute
                                Operator   = [string]$cond.ComparisonOperator
                                Value      = ($cond.ComparisonValue -join ',')
                            }
                        }
                    }
                }
                [PSCustomObject]@{
                    Name       = $r.Name
                    Identifier = $r.Identifier
                    Precedence = $r.Precedence
                    Direction  = $r.Direction
                    AttributeFlowMappings = @(
                        $r.AttributeFlowMappings | ForEach-Object {
                            [PSCustomObject]@{
                                Destination = $_.Destination
                                Expression  = $_.Expression
                                FlowType    = [string]$_.FlowType
                                Source      = (@($_.Source) -join ',')
                            }
                        }
                    )
                    ScopeConditions = $scopes
                    # True when the marker attribute appears ANYWHERE in the rule -
                    # expression, flow source, scoping filter, at any nesting depth.
                    ReferencesMarker = ($dump -match [regex]::Escape($SourceAttribute))
                }
            }

            # Prefer a rule that references the marker attribute anywhere; otherwise fall
            # back to the first rule writing this destination, so the caller can report
            # what it found rather than claiming nothing exists.
            $flatAll   = @($candidates | ForEach-Object { & $flatten $_ })
            $preferred = $flatAll | Where-Object { $_.ReferencesMarker } | Select-Object -First 1

            $chosen = if ($preferred) { $preferred } else { $flatAll | Select-Object -First 1 }

            return [PSCustomObject]@{
                Outcome        = 'Ok'
                Error          = $null
                Rule           = $chosen
                CandidateCount = $flatAll.Count
            }
        } catch {
            return [PSCustomObject]@{ Outcome = 'QueryFailed'; Error = $_.Exception.Message; Rule = $null; CandidateCount = 0 }
        }
    }

    try {
        $acceptedDestinations = if ($definition.PSObject.Properties.Name -contains 'AcceptedDestinations') {
            @($definition.AcceptedDestinations)
        } else {
            @($definition.Destination)
        }
        # Build the argument array explicitly: the first argument is itself an array, and
        # inline construction would splat it into separate positional arguments.
        $remoteArgs = New-Object object[] 2
        $remoteArgs[0] = $acceptedDestinations
        $remoteArgs[1] = $definition.SourceAttribute

        $result = Invoke-AdSyncCommand -ComputerName $server -ScriptBlock $remote `
                                       -ArgumentList $remoteArgs `
                                       -Credential $Credential
    } catch {
        # WinRM refused, host unreachable, or access denied. Explicitly NOT 'Missing'.
        return New-EntraConnectStatus -State 'Unknown' -Server $server `
            -Reason "Could not query Entra Connect on '$server': $($_.Exception.Message)" `
            -Remediation "This is a connection or permissions problem, not proof the rule is missing. Confirm WinRM is reachable (Test-WSMan $server) and that your account is a local administrator on $server."
    }

    switch ($result.Outcome) {
        'NoModule' {
            return New-EntraConnectStatus -State 'Unknown' -Server $server `
                -Reason "The ADSync module is not installed on '$server', so it is not an Entra Connect server. ($($result.Error))" `
                -Remediation "Entra Connect may have moved. Delete the cached settings file to force rediscovery, or re-run with -EntraConnectServer <name>."
        }
        'QueryFailed' {
            # The ADSync management interface is a WCF endpoint bound to
            # net.pipe://localhost/ADSyncManagement. It refuses calls that arrive over a
            # PowerShell remoting hop, so this error means "cannot be queried from here",
            # NOT "this is the wrong server" - the service is very often running fine.
            # https://learn.microsoft.com/entra/identity/hybrid/connect/reference-connect-adsync
            $endpointBlocked = $result.Error -match 'no endpoint listening|net\.pipe|net\.tcp|ADSyncManagement'

            if ($endpointBlocked) {
                return New-EntraConnectStatus -State 'Unknown' -Server $server `
                    -Reason "The sync rules on '$server' cannot be read from this machine. Entra Connect only accepts these queries locally, not over a remote connection." `
                    -Remediation "This does NOT mean the rule is missing - it means it could not be checked from here.`r`n`r`nTo verify it, run this tool while logged on to $server, or run this there:`r`n    Get-ADSyncRule | Where-Object { `$_.Direction -eq 'Inbound' } | Select-Object Name, Precedence`r`n`r`nEverything else in this tool works normally."
            }

            return New-EntraConnectStatus -State 'Unknown' -Server $server `
                -Reason "Reached '$server' but could not read its sync rules: $($result.Error)" `
                -Remediation "Reading sync rules requires local administrator rights (or ADSyncAdmins membership) on $server."
        }
    }

    $verdict = Test-EntraConnectRuleShape -Rule $result.Rule -Definition $definition

    if ($verdict.State -eq 'Present' -and $SettingsPath) {
        Write-EntraConnectSettings -Path $SettingsPath -Server $server
    }

    $remediation = $null
    if ($verdict.State -ne 'Present') {
        $builder = if ($RuleKey -eq 'BlockCloudSignIn') { 'Block365SignIn-RuleBuilder.ps1' } else { 'HideFromGal-RuleBuilder.ps1' }
        $remediation = "A sysadmin must recreate the rule, then run a Full Synchronization:`r`n" +
                       "    .\$builder -EntraConnectServer $server`r`n`r`n" +
                       "Custom sync rules are not carried over when Entra Connect is moved to a new server, so this is expected after a migration."
    }

    New-EntraConnectStatus -State $verdict.State -Server $server -Reason $verdict.Reason -Remediation $remediation
}

function Invoke-EntraConnectDeltaSync {
    <#
    .SYNOPSIS
        Triggers a delta sync cycle on the Entra Connect server.
    .DESCRIPTION
        Runs Start-ADSyncSyncCycle remotely. A delta sync is the correct cycle for
        picking up an attribute change on already-synced users; creating a NEW sync
        rule instead requires a full synchronization, which this function deliberately
        does not perform.
        https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-feature-scheduler
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

if ($LoadFunctionsOnly) { return }
