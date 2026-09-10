<#
.SYNOPSIS
    Creates the Entra Connect sync rule that enforces Hide From GAL.
.DESCRIPTION
    HideFromGAL.ps1 marks users by writing msDS-cloudExtensionAttribute1 =
    "HideFromGAL" in Active Directory. That marker does nothing by itself. This
    script creates the custom inbound synchronization rule inside Entra Connect that
    turns the marker into enforcement, by flowing it to msExchHideFromAddressLists so
    the user is hidden from the Exchange Online global address list.

    Run this ONCE per Entra Connect server. You must run it again after Entra Connect is
    moved, swung, or rebuilt on a new server: custom synchronization rules are NOT
    carried over by the configuration export/import, and Microsoft's guidance is that
    they must be recreated manually on the new server.
    https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-import-export-config

    The ADSync module exists only on the Entra Connect server, so when this script is run
    from anywhere else, supply -EntraConnectServer and the work is performed remotely.

    Best run ON the Entra Connect server. The ADSync management interface is a WCF
    endpoint bound to net.pipe://localhost/ADSyncManagement and rejects calls arriving
    over a PowerShell remoting hop, so remote rule creation can fail with "no endpoint
    listening" even when the service is healthy. Run locally on the sync server when you
    can; the script detects that and calls the cmdlets directly.

    This script is idempotent: if a matching rule already exists it reports it and makes
    no changes unless -Force is supplied.
.PARAMETER EntraConnectServer
    Entra Connect server on which to create the rule. Omit to auto-discover it, or to
    use the local machine when ADSync is installed here.
.PARAMETER Credential
    Optional credential for the remote connection, when the current user is not a local
    administrator on the Entra Connect server.
.PARAMETER Force
    Replace an existing matching rule instead of leaving it untouched.
.PARAMETER OutputPath
    Folder for the transcript log. Defaults to the current directory.
.EXAMPLE
    .\HideFromGal-RuleBuilder.ps1 -EntraConnectServer AADC02
    Create the rule on AADC02 from an admin workstation or domain controller.
.EXAMPLE
    .\HideFromGal-RuleBuilder.ps1
    Auto-discover the Entra Connect server and create the rule there.
.EXAMPLE
    .\HideFromGal-RuleBuilder.ps1 -EntraConnectServer AADC02 -WhatIf
    Show what would be created without changing anything.
.NOTES
    Requires local administrator rights on the Entra Connect server.

    After the rule is created you MUST run a Full Synchronization for it to apply to
    existing users. This script prints those steps rather than running them: a full sync
    on a production Connect server can stage a large number of exports, and Microsoft's
    documented procedure is to review pending exports before exporting them.

    REFERENCES
    - Custom rules, precedence 1-99 reserved, expression syntax:
      https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-change-the-configuration
    - Custom rules are not migrated automatically:
      https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-import-export-config
    - ADSync PowerShell reference:
      https://learn.microsoft.com/entra/identity/hybrid/connect/reference-connect-adsync
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$EntraConnectServer,

    [System.Management.Automation.PSCredential]$Credential,

    [switch]$Force,

    [string]$OutputPath = (Get-Location).Path
)

. "$PSScriptRoot\Shared-EntraConnect.ps1" -LoadFunctionsOnly

$definition   = Get-EntraConnectRuleDefinition -Key 'HideFromGAL'
$settingsPath = Get-EntraConnectSettingsPath -ScriptRoot $PSScriptRoot
$logLines     = @()

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')]
        [string]$Level = 'INFO'
    )
    $color = switch ($Level) {
        'PASS' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } default { 'Cyan' }
    }
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Write-Host "[$Level] $Message" -ForegroundColor $color
    $script:logLines += $line
}

Write-Host ''
Write-Host '=== Hide From GAL: Entra Connect rule builder ===' -ForegroundColor White
Write-Host ''

# --- Resolve the domain -------------------------------------------------------
# Get-ADDomain rather than $env:USERDNSDOMAIN: that variable is empty when the script
# runs as SYSTEM or under a scheduled task, which silently produced a rule named
# "Hide user from GAL - " and a connector match against every AD connector.
$targetDomain = $null
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $targetDomain = (Get-ADDomain -ErrorAction Stop).DNSRoot
    Write-Status "Target domain: $targetDomain" -Level 'INFO'
} catch {
    Write-Status "Could not determine the AD domain: $($_.Exception.Message)" -Level 'FAIL'
    Write-Status "Run this on a domain-joined machine with the ActiveDirectory module (RSAT) available." -Level 'INFO'
    return
}

# --- Locate the Entra Connect server ------------------------------------------
$found = Find-EntraConnectServer -ComputerName $EntraConnectServer -SettingsPath $settingsPath
if (-not $found.Server) {
    Write-Status 'No Entra Connect server could be found.' -Level 'FAIL'
    Write-Status 'Searched Active Directory for a server running the ADSync service and found none reachable.' -Level 'INFO'
    Write-Status 'Re-run with -EntraConnectServer <name> to name the sync server directly.' -Level 'INFO'
    return
}
$server = $found.Server
Write-Status "Entra Connect server: $server (found via: $($found.Source))" -Level 'INFO'

# --- Check whether the rule already exists ------------------------------------
$existing = Test-EntraConnectRule -RuleKey 'HideFromGAL' -ComputerName $server `
                                  -SettingsPath $settingsPath -Credential $Credential

if ($existing.State -eq 'Unknown') {
    Write-Status $existing.Reason -Level 'FAIL'
    if ($existing.Remediation) { Write-Status $existing.Remediation -Level 'INFO' }
    return
}

if ($existing.State -eq 'Present' -and -not $Force) {
    Write-Status $existing.Reason -Level 'PASS'
    Write-Status 'The enforcement rule already exists. Nothing to do. Use -Force to replace it.' -Level 'INFO'
    return
}

if ($existing.State -eq 'Misconfigured') {
    Write-Status $existing.Reason -Level 'WARN'
    if (-not $Force) {
        Write-Status 'Re-run with -Force to replace the existing rule with a correct one.' -Level 'INFO'
        return
    }
}

# --- Create the rule ----------------------------------------------------------
if (-not $PSCmdlet.ShouldProcess($server, "Create sync rule '$($definition.NamePrefix) - $targetDomain'")) {
    Write-Status 'WhatIf: no changes made.' -Level 'INFO'
    return
}

$remote = {
    param($Domain, $NamePrefix, $Description, $Destination, $Expression, $Precedence, $ReplaceExisting, $SourceAttribute)

    try {
        Import-Module ADSync -ErrorAction Stop
    } catch {
        return [PSCustomObject]@{ Success = $false; Stage = 'ImportModule'; Error = $_.Exception.Message; Rule = $null }
    }

    # The AD connector for this forest. Matching on Name is unreliable across
    # multi-forest topologies, so fall back to the sole AD connector when exactly
    # one exists, and report ambiguity rather than guessing.
    try {
        $adConnectors = @(Get-ADSyncConnector -ErrorAction Stop | Where-Object { $_.Type -eq 'AD' })
    } catch {
        return [PSCustomObject]@{ Success = $false; Stage = 'GetConnector'; Error = $_.Exception.Message; Rule = $null }
    }

    $connector = $adConnectors | Where-Object { $_.Name -like "*$Domain*" } | Select-Object -First 1
    if (-not $connector -and $adConnectors.Count -eq 1) { $connector = $adConnectors[0] }

    if (-not $connector) {
        $names = ($adConnectors | ForEach-Object { $_.Name }) -join ', '
        return [PSCustomObject]@{
            Success = $false; Stage = 'MatchConnector'
            Error = "No AD connector matched domain '$Domain'. Available AD connectors: $names"
            Rule = $null
        }
    }

    if ($ReplaceExisting) {
        try {
            $stale = Get-ADSyncRule -ErrorAction Stop | Where-Object {
                $_.Direction -eq 'Inbound' -and
                ($_.AttributeFlowMappings | Where-Object {
                    $_.Destination -eq $Destination -and $_.Expression -match [regex]::Escape($SourceAttribute)
                })
            }
            foreach ($s in $stale) { Remove-ADSyncRule -Identifier $s.Identifier -ErrorAction Stop }
        } catch {
            return [PSCustomObject]@{ Success = $false; Stage = 'RemoveExisting'; Error = $_.Exception.Message; Rule = $null }
        }
    }

    try {
        $ruleGuid = [guid]::NewGuid().ToString()

        # ImmutableTag is deliberately not set: that property belongs only to Microsoft's
        # out-of-box rules.
        $rule = New-ADSyncRule -Name "$NamePrefix - $Domain" `
                               -Identifier $ruleGuid `
                               -Description $Description `
                               -Direction 'Inbound' `
                               -Precedence $Precedence `
                               -SourceObjectType 'user' `
                               -TargetObjectType 'person' `
                               -Connector $connector.Identifier `
                               -LinkType 'Join' `
                               -ErrorAction Stop

        $rule = Add-ADSyncAttributeFlowMapping -SynchronizationRule $rule `
                                               -Destination $Destination `
                                               -FlowType 'Expression' `
                                               -ValueMergeType 'Update' `
                                               -Expression $Expression `
                                               -ErrorAction Stop

        Add-ADSyncRule -SynchronizationRule $rule -ErrorAction Stop | Out-Null

        $created = Get-ADSyncRule -Identifier $ruleGuid -ErrorAction Stop
        return [PSCustomObject]@{
            Success = $true; Stage = 'Created'; Error = $null
            Rule = [PSCustomObject]@{
                Name = $created.Name; Identifier = $created.Identifier
                Precedence = $created.Precedence; Connector = $connector.Name
            }
        }
    } catch {
        return [PSCustomObject]@{ Success = $false; Stage = 'CreateRule'; Error = $_.Exception.Message; Rule = $null }
    }
}

$argList = @(
    $targetDomain, $definition.NamePrefix, $definition.Description, $definition.Destination,
    $definition.Expression, $definition.Precedence, [bool]$Force, $definition.SourceAttribute
)

try {
    # Invoke-AdSyncCommand runs locally when the target is this machine. That is
    # required, not just faster: the ADSync WCF endpoint is bound to
    # net.pipe://localhost/ADSyncManagement and rejects calls arriving over a remoting
    # hop, so remoting to your own server fails with "no endpoint listening".
    $result = Invoke-AdSyncCommand -ComputerName $server -ScriptBlock $remote `
                                   -ArgumentList $argList -Credential $Credential
} catch {
    Write-Status "Could not reach '$server': $($_.Exception.Message)" -Level 'FAIL'
    Write-Status "Confirm WinRM is reachable (Test-WSMan $server) and that you are a local administrator on that server." -Level 'INFO'
    return
}

if (-not $result.Success) {
    Write-Status "Rule creation failed at stage '$($result.Stage)': $($result.Error)" -Level 'FAIL'
    if ($result.Stage -eq 'ImportModule') {
        Write-Status "'$server' does not have the ADSync module, so it is not an Entra Connect server." -Level 'INFO'
    }
} else {
    Write-Status "Created sync rule '$($result.Rule.Name)'" -Level 'PASS'
    Write-Status "  Identifier : $($result.Rule.Identifier)" -Level 'INFO'
    Write-Status "  Precedence : $($result.Rule.Precedence)" -Level 'INFO'
    Write-Status "  Connector  : $($result.Rule.Connector)" -Level 'INFO'

    Write-EntraConnectSettings -Path $settingsPath -Server $server

    # A new rule does not apply to already-synced users until a full synchronization
    # recalculates them. Printed, not executed: this stages exports on a production
    # server and should be watched by the admin running it.
    Write-Host ''
    Write-Host 'NEXT STEP - required for the rule to take effect:' -ForegroundColor Yellow
    Write-Host ''
    Write-Host "  On $server, run a Full Synchronization:" -ForegroundColor White
    Write-Host '    1. Open Synchronization Service Manager (Start > Synchronization Service)'
    Write-Host '    2. Connectors tab > select the Active Directory connector'
    Write-Host '    3. Actions > Run > Full Synchronization > OK'
    Write-Host '    4. Right-click the Microsoft Entra connector > Search Connector Space'
    Write-Host '       Set Scope to "Pending Export" and REVIEW the staged changes before exporting'
    Write-Host '    5. Right-click the Microsoft Entra connector > Run > Export'
    Write-Host ''
    Write-Host '  Reviewing pending exports before running Export is Microsoft''s documented' -ForegroundColor Gray
    Write-Host '  procedure and is worth doing: this rule changes GAL visibility for every' -ForegroundColor Gray
    Write-Host '  matching user, so an unexpected match here is important to catch first.' -ForegroundColor Gray
    Write-Host ''
}

# --- Log ----------------------------------------------------------------------
try {
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null
    }
    $logFile = Join-Path $OutputPath "HideFromGal-RuleBuilder_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').log"
    $logLines | Set-Content -LiteralPath $logFile -Encoding UTF8 -ErrorAction Stop
    Write-Host "Log written to: $logFile" -ForegroundColor Gray
} catch {
    Write-Host "Could not write log file: $($_.Exception.Message)" -ForegroundColor Yellow
}
