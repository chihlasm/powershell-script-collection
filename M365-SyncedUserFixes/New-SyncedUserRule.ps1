# 3.0 so it runs from Server 2012 / 2012 R2 management boxes; the ADSync work itself runs on the
# Entra Connect server (PowerShell 5.x there). Tests\PSVersionFloor.Tests.ps1 guards it.
#Requires -Version 3.0

<#
.SYNOPSIS
    Checks, previews, creates or exports the Entra Connect sync rule behind one of the
    M365-SyncedUserFixes fixes.
.DESCRIPTION
    The command-line twin of the "Set up sync rules" page.

    By default it checks whether the rule exists. Add -Create to build it, -WhatIf with
    -Create to see what would change, or -ExportScript to write a standalone script you can
    copy to the Entra Connect server and run there (needed when Entra Connect refuses remote
    requests, which it usually does).

    It refuses to add a second rule for the same fix. A broken rule is replaced only with
    -Replace.

    After creating a rule you MUST run a Full Synchronization before it applies to anyone;
    the script prints the steps rather than running them, because Microsoft's documented
    procedure is to review pending exports first.
.PARAMETER Rule
    BlockCloudSignIn or HideFromGAL.
.PARAMETER BlockMethod
    For BlockCloudSignIn only. DisableSignIn (default) disables the Microsoft 365 account and
    keeps the mailbox and licences. RemoveFromM365 filters the person out of sync, which
    DELETES the Microsoft 365 account.
.PARAMETER EntraConnectServer
    Entra Connect server. Omit to find it (this computer, the cached server, then AD).
.PARAMETER Credential
    Optional credential for the Entra Connect server.
.PARAMETER Create
    Create the rule. Without it the script only checks.
.PARAMETER Replace
    With -Create: replace an existing rule that reacts to the same marker.
.PARAMETER ExportScript
    Write a standalone rule script to this path instead of connecting anywhere.
.PARAMETER Domain
    AD domain DNS name for the rule name and connector match. Defaults to the current domain.
.PARAMETER OutputPath
    Folder for the log file. Defaults to the current directory.
.EXAMPLE
    .\New-SyncedUserRule.ps1 -Rule BlockCloudSignIn
    Is the block rule in place?
.EXAMPLE
    .\New-SyncedUserRule.ps1 -Rule BlockCloudSignIn -Create -WhatIf
    Show what would be created (precedence, connector, rules it would replace).
.EXAMPLE
    .\New-SyncedUserRule.ps1 -Rule HideFromGAL -ExportScript C:\Temp\New-HideRule.ps1
    Write a script to run on the Entra Connect server.
.NOTES
    Exit codes: 0 = rule in place / created / exported, 1 = rule missing or broken (check
    mode) or creation failed, 2 = could not check.

    Replaces Block365SignIn-RuleBuilder.ps1 and HideFromGal-RuleBuilder.ps1. The old block
    builder could only create the cloudFiltered (delete from Microsoft 365) rule.

    REFERENCES: see SyncedUserFixes.Core.ps1.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateSet('BlockCloudSignIn', 'HideFromGAL')]
    [string]$Rule,

    [ValidateSet('DisableSignIn', 'RemoveFromM365')]
    [string]$BlockMethod = 'DisableSignIn',

    [string]$EntraConnectServer,

    [System.Management.Automation.PSCredential]$Credential,

    [switch]$Create,

    [switch]$Replace,

    [string]$ExportScript,

    [string]$Domain,

    [string]$OutputPath = (Get-Location).Path
)

. (Join-Path $PSScriptRoot 'SyncedUserFixes.Core.ps1') -LoadFunctionsOnly

$script:LogLines = @()
function Write-Status {
    param([string]$Message, [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Level = 'INFO')
    $color = switch ($Level) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } default { 'Cyan' } }
    Write-Host "[$Level] $Message" -ForegroundColor $color
    $script:LogLines += "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
}

function Save-Log {
    try {
        if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null }
        $path = Join-Path $OutputPath "New-SyncedUserRule_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').log"
        $script:LogLines | Set-Content -LiteralPath $path -Encoding UTF8 -ErrorAction Stop
        Write-Host "Log: $path" -ForegroundColor Gray
    } catch {
        Write-Host "Could not write the log: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

$method = if ($Rule -eq 'HideFromGAL') { 'Hide' } else { $BlockMethod }

if (-not $Domain) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
        $Domain = (Get-ADDomain -ErrorAction Stop).DNSRoot
    } catch {
        # $env:USERDNSDOMAIN is empty under SYSTEM and scheduled tasks; ask instead of guessing.
        Write-Status "Could not work out the AD domain: $($_.Exception.Message). Pass -Domain contoso.local." -Level 'FAIL'
        exit 2
    }
}

$blueprint = Get-SyncRuleBlueprint -Key $Rule -Method $method -Domain $Domain
Write-Host ''
Write-Host "=== M365 Synced User Fixes: $($blueprint.MethodLabel) ===" -ForegroundColor White
Write-Host ''
Write-Host (Format-SyncRuleBlueprint -Blueprint $blueprint) -ForegroundColor Gray
Write-Host ''

# --- Export: no connection needed ------------------------------------------------------
if ($ExportScript) {
    $folder = Split-Path -Parent $ExportScript
    if ($folder -and -not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
    # UTF-8 with BOM so Windows PowerShell 5.1 reads it correctly.
    [System.IO.File]::WriteAllText($ExportScript, (New-SyncRuleScriptText -Blueprint $blueprint), (New-Object System.Text.UTF8Encoding $true))
    Write-Status "Saved $ExportScript" -Level 'PASS'
    Write-Status "Copy it to the Entra Connect server and run it in an elevated window: first with -WhatIf, then without." -Level 'INFO'
    Save-Log
    exit 0
}

# --- Check -------------------------------------------------------------------------------
$settingsPath = Get-EntraConnectSettingsPath -ScriptRoot $PSScriptRoot
$status = Test-EntraConnectRule -RuleKey $Rule -ComputerName $EntraConnectServer -SettingsPath $settingsPath -Credential $Credential
$look = Get-EntraConnectStatusPresentation -State $status.State
Write-Status "Entra Connect server: $(if ($status.Server) { $status.Server } else { 'not found' })" -Level 'INFO'
Write-Status "$($look.Headline). $($status.Reason)" -Level $look.Prefix.Trim('[', ']')
foreach ($w in @($status.Warnings)) { Write-Status $w -Level 'WARN' }

if (-not $Create) {
    if ($status.Remediation) { Write-Status $status.Remediation -Level 'INFO' }
    Save-Log
    exit $(switch ($status.State) { 'Present' { 0 } 'Unknown' { 2 } default { 1 } })
}

# --- Create ------------------------------------------------------------------------------
if (-not $status.Server) {
    Write-Status 'No Entra Connect server to create the rule on. Use -EntraConnectServer, or -ExportScript and run the script there.' -Level 'FAIL'
    Save-Log
    exit 2
}
if ($status.State -eq 'Present' -and -not $Replace) {
    Write-Status 'A rule for this fix is already in place. Nothing to do. (Creating another would conflict with it.)' -Level 'INFO'
    Save-Log
    exit 0
}
if ($status.State -eq 'Misconfigured' -and -not $Replace) {
    Write-Status 'The existing rule is broken. Re-run with -Replace to replace it.' -Level 'INFO'
    Save-Log
    exit 1
}

$previewOnly = -not $PSCmdlet.ShouldProcess($status.Server, "Create sync rule '$($blueprint.Name)'")
if (-not $previewOnly -and $blueprint.IsDestructive) {
    Write-Status 'This rule DELETES blocked people from Microsoft 365 (cloudFiltered).' -Level 'WARN'
}

$result = Invoke-SyncRuleCreation -Blueprint $blueprint -ComputerName $status.Server -Credential $Credential -ReplaceExisting:$Replace -PreviewOnly:$previewOnly
foreach ($w in @($result.Warnings)) { Write-Status $w -Level 'WARN' }

if (-not $result.Success) {
    if ($result.Stage -eq 'RemoteBlocked') {
        Write-Status "$($status.Server) refused the request over a remote connection (Entra Connect only accepts it locally)." -Level 'WARN'
        Write-Status "Run this script ON $($status.Server), or use -ExportScript and run the exported script there." -Level 'INFO'
    } elseif ($result.Stage -eq 'AlreadyExists') {
        Write-Status $result.Error -Level 'INFO'
    } else {
        Write-Status "Failed at '$($result.Stage)': $($result.Error)" -Level 'FAIL'
    }
    Save-Log
    exit 1
}

if ($result.Stage -eq 'Preview') {
    Write-Status "WhatIf: would create '$($result.Rule.Name)' at precedence $($result.Rule.Precedence) on connector '$($result.Rule.Connector)'." -Level 'INFO'
    foreach ($n in @($result.Removed)) { Write-Status "WhatIf: would remove the existing rule '$n'." -Level 'INFO' }
    Save-Log
    exit 0
}

foreach ($n in @($result.Removed)) { Write-Status "Removed the old rule '$n'." -Level 'INFO' }
Write-Status "Created '$($result.Rule.Name)' (precedence $($result.Rule.Precedence), connector '$($result.Rule.Connector)')." -Level 'PASS'
Write-EntraConnectSettings -Path $settingsPath -Server $status.Server
Write-Host ''
Write-Host (Get-FullSyncInstructions -Server $status.Server -Destructive $blueprint.IsDestructive) -ForegroundColor Yellow
Write-Host ''
Save-Log
exit 0
