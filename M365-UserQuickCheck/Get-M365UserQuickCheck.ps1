# 5.1 because Microsoft.Graph.Authentication requires Windows PowerShell 5.1 (root CLAUDE.md,
# version floors). Tests\PSVersionFloor.Tests.ps1 guards it.
#Requires -Version 5.1

<#
.SYNOPSIS
    "I can't sign in to Outlook / Teams" - answers in plain English whether a Microsoft 365 user
    can sign in, and why not.
.DESCRIPTION
    Built for the service desk, mid-ticket. Sign in to the client's tenant in the browser and the
    tool prints, in this order:

      1. A banner: which tenant (name, default domain, tenant ID) and which account you are signed
         in as, with its admin roles, "This tool only reads", then what this run could see:
         sign-in history, Conditional Access detail, MFA methods, risky user, on-premises AD,
         each "available" or "not available (why)".
      2. The answer:   Can Jane Doe sign in to Microsoft 365?  YES / NO / PROBABLY NOT / PROBABLY YES
      3. Why not (with "What to do"), Also worth knowing, Looks fine, Could not check, then a
         detail table and the recent sign-ins for sysadmins.

    WHAT IT CHECKS
      1. Sign-in blocked in Microsoft 365 (and, for a synced user, that the fix is in AD)
      2. No licence, or a licence that failed to apply
      3. The latest sign-in in the last -Days days: its error code, Microsoft's own reason, how
         many failed in a row, the Conditional Access policy that blocked it, and a link to
         Microsoft's live lookup. Older failures are summarised, never decisive.
      4. MFA methods registered (warning when there is only a password)
      5. Risky user (Entra ID P2 tenants)
      6. Is it a sync problem? (on-premises AD, unless -SkipOnPremises)
         - a synced user's AD account, found by its on-premises SID (else by sign-in name):
           does AD agree on enabled and sign-in name, and does it carry the
           M365-SyncedUserFixes block marker (blocked on purpose)?
         - sync errors Microsoft 365 reports for the account (onPremisesProvisioningErrors)
         - another Microsoft 365 user, group or contact already holding the AD account's
           sign-in name or primary email address
         - when the tenant last received changes from AD (stale after more than 3 hours)
         - no Microsoft 365 user at all, but an AD account with that sign-in name: it never
           synced, or was removed from Microsoft 365 on purpose
         - a cloud-only user: "sync is not involved" once AD has no account with that name
         When no domain controller answers (or the ActiveDirectory module is missing) this
         part says "On-premises AD: could not check (why)", and the answer and exit code come
         from the Microsoft 365 checks alone.

    VERDICT
      NO            sign-in blocked, the latest sign-in failed with 50053, 50055, 50057,
                    53003 or 530035, the account exists in AD but not in Microsoft 365, sync
                    reports an error for it, or another object holds its address
      PROBABLY NOT  no licence, a licence error, the latest sign-in failed with another code,
                    or AD has the account enabled while Microsoft 365 blocks it
      YES           none of the above, and sign-in history was readable
      PROBABLY YES  none of the above, but sign-in history could not be read (a tenant without
                    Entra ID P1, or a role that cannot read it): there is no evidence either way

    A source that could not be read is never treated as clean: it goes under "Could not check"
    with the reason, and the ticket note never lists it as ruled out.

    READ-ONLY. Every Graph request is a GET, and every permission asked for is a .Read scope, so
    nothing can be changed even when you sign in as the client's Global Administrator. On-premises
    AD is only read, with Get-ADUser.
.PARAMETER UserPrincipalName
    The user's sign-in name, for example jdoe@contoso.com. If no user has that sign-in name, the
    tool looks for it as an email or proxy address. If that finds more than one user, the
    candidates are listed and the tool exits with code 2 rather than guessing. If no Microsoft
    365 user matches, on-premises AD is searched for that sign-in name.
.PARAMETER TenantId
    The client's tenant ID or domain (contoso.onmicrosoft.com). Recommended when you have access
    to many tenants.
.PARAMETER DisableWam
    Use when Windows keeps signing you in with your own work account (Web Account Manager)
    instead of the client account. The tool then signs in with a device code, where you choose
    the account yourself. It does not change the Graph module's WAM setting: Microsoft documents
    that Set-MgGraphOption -DisableLoginByWAM only works with a custom app and persists across
    sessions.
.PARAMETER UseDeviceCode
    Sign in with a device code instead of a browser window.
.PARAMETER Days
    How many days of sign-ins to read (1 to 30, default 7). Tenants keep 7 days of sign-ins
    without Entra ID P1 and 30 days with it.
.PARAMETER Server
    A domain controller (or domain name) of the client's AD, for the on-premises comparison. Use
    it on a workstation that is not in the client's domain, or for a user in another domain.
    Without it Get-ADUser uses the computer's own domain.
.PARAMETER Credential
    An account that can read the client's AD, for the on-premises comparison (usually with
    -Server). It is passed to Get-ADUser only and never written anywhere.
.PARAMETER SkipOnPremises
    Do not look at on-premises AD. On-premises AD is then listed under "Could not check"
    (skipped), and a user missing from Microsoft 365 is reported as not found.
.PARAMETER OutputPath
    Optional folder. When given, an HTML report and a one-row CSV named
    M365UserCheck_<sign-in name>_<yyyy-MM-dd_HHmmss> are written there. When omitted no report
    is written (only the ticket note, when -TicketNumber is given). With -TicketNumber, this is
    the folder that holds Ticket_<number>, and the reports go into Ticket_<number>.
.PARAMETER TicketNumber
    Optional ticket number (letters, digits, - or _, up to 32 characters). The ticket note is
    saved in <root>\Ticket_<number>, where root is -OutputPath if given, else
    %USERPROFILE%\Documents\TicketNotes. The HTML and the CSV are saved there too, but only when
    -OutputPath is given. A number that does not fit is refused with a [FAIL] line and exit code
    3, before anything is checked.
.PARAMETER NoClipboard
    Do not copy the ticket note to the clipboard.
.PARAMETER FullDetail
    Keep IP addresses and share paths in the ticket note. By default the note is paste-safe
    (owner decision D-009). The tool prints a [WARN] line as a reminder.
.PARAMETER PassThru
    Return the result object (Status, ExitCode, UserPrincipalName, Message, Candidates, MatchedBy,
    Tenant, User, Facts, Assessment, Now, TicketNote) instead of setting an exit code.
    Facts.SignIns holds the trimmed sign-in rows, including each row's ipAddress (the HTML
    report shows it): treat the object as client data and do not log or export it as is.
.PARAMETER Quiet
    Do not write the console report. Combine with -PassThru or -OutputPath. Also leaves the
    clipboard alone, because another script is the caller.
.PARAMETER LoadFunctionsOnly
    Define the functions and return without running a check (used by the tests).
.EXAMPLE
    .\Get-M365UserQuickCheck.ps1 -UserPrincipalName jdoe@contoso.com
    Sign in to the tenant in the browser, then answer "can jdoe sign in to Microsoft 365?".
.EXAMPLE
    .\Get-M365UserQuickCheck.ps1 jdoe@contoso.com -TenantId contoso.onmicrosoft.com -Days 30 -OutputPath C:\Temp
    Same, in a named tenant, reading 30 days of sign-ins, and saving an HTML report and a CSV row.
.EXAMPLE
    .\Get-M365UserQuickCheck.ps1 jdoe@contoso.com -Server dc01.contoso.local -Credential (Get-Credential CONTOSO\admin)
    From a workstation outside the client's domain: the Microsoft 365 checks, plus the
    on-premises AD comparison against that domain controller.
.EXAMPLE
    .\Get-M365UserQuickCheck.ps1 jdoe@contoso.com -TicketNumber 482113
    The ticket note goes into %USERPROFILE%\Documents\TicketNotes\Ticket_482113 and onto the
    clipboard. No report is written.
.EXAMPLE
    .\Get-M365UserQuickCheck.ps1 jdoe@contoso.com -TicketNumber 482113 -OutputPath C:\Temp
    The HTML, the CSV and the ticket note go into C:\Temp\Ticket_482113.
.NOTES
    Exit codes (without -PassThru): 0 = can sign in (YES or PROBABLY YES), 1 = cannot / probably
    not (including "exists in AD but not in Microsoft 365"), 2 = user not found in Microsoft 365
    (and not in AD, or AD could not be checked) or ambiguous, 3 = could not run (Graph module
    missing or too old to keep the sign-in to this window, sign-in or preflight failed, the
    tenant's domains could not be read, the sign-in name's domain is not in this tenant, or an
    unusable -TicketNumber). The ActiveDirectory module or a domain controller being
    unavailable never changes the exit code.

    Needs the Microsoft.Graph.Authentication module (Install-Module Microsoft.Graph.Authentication
    -Scope CurrentUser) and an account in the client's tenant that can read users. Sign-in history
    needs Entra ID P1 and a reports role; risky user needs Entra ID P2. Missing either is reported,
    not fatal. The on-premises comparison needs the ActiveDirectory module (RSAT), imported at
    run time, and a domain controller that answers; without them it is "could not check".

    At the consent prompt, consent for yourself only. Leave "Consent on behalf of your
    organization" unticked (owner decision D-007).

    TICKET NOTE. Every run ends with a four-part note (Checked, Ruled out, Could not check, Next
    step) built by CaseKit.ps1 in this folder (a copy of TicketNote\CaseKit.ps1). The stamp names
    the tenant and the signed-in account and says "Changed anything: No". If CaseKit.ps1 is
    missing the check still runs, without a note.

    REFERENCES
      Connect-MgGraph: -Scopes, -TenantId, -ContextScope Process (this process only, so the
      client's token stays out of your persistent cache), -UseDeviceCode, -NoWelcome
        https://learn.microsoft.com/powershell/module/microsoft.graph.authentication/connect-mggraph
      Get-MgContext: reports the session's ContextScope
        https://learn.microsoft.com/powershell/module/microsoft.graph.authentication/get-mgcontext
      Invoke-MgGraphRequest (-Method, -Uri, -Headers, -OutputType)
        https://learn.microsoft.com/powershell/module/microsoft.graph.authentication/invoke-mggraphrequest
      Set-MgGraphOption -DisableLoginByWAM: only takes effect with a custom ClientId; persists
      across sessions
        https://learn.microsoft.com/powershell/module/microsoft.graph.authentication/set-mggraphoption
      Disconnect-MgGraph
        https://learn.microsoft.com/powershell/module/microsoft.graph.authentication/disconnect-mggraph
      Graph reads, scopes, roles, licence errors, the error-code map and the on-premises AD
      comparison (Get-ADUser, provisioning errors, address filters, sync interval): see the
      REFERENCES in M365UserCheck.Core.ps1
      pwdLastSet (details table): 100-ns intervals since 1601 UTC; 0 = must set a new password
      at next logon unless the password never expires
        https://learn.microsoft.com/windows/win32/adschema/a-pwdlastset
      Ticket note clipboard (in CaseKit.ps1): see TicketNote\CaseKit.ps1
#>
[CmdletBinding(DefaultParameterSetName = 'Check')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Check', Position = 0)]
    [Alias('Identity')]
    [ValidateNotNullOrEmpty()]
    [string]$UserPrincipalName,

    [string]$TenantId,

    [switch]$DisableWam,

    [switch]$UseDeviceCode,

    [ValidateRange(1, 30)]
    [int]$Days = 7,

    [string]$Server,

    [System.Management.Automation.PSCredential]$Credential,

    [switch]$SkipOnPremises,

    [string]$OutputPath,

    # Checked in the script body (Test-TicketNumber in CaseKit.ps1), not with ValidatePattern,
    # so a mistyped number gets a plain-English [FAIL] line instead of a parameter-binding error.
    [string]$TicketNumber,

    [switch]$NoClipboard,

    [switch]$FullDetail,

    [switch]$PassThru,

    [switch]$Quiet,

    [Parameter(ParameterSetName = 'Load')]
    [switch]$LoadFunctionsOnly
)

# No global $ErrorActionPreference change here (the functions are dot-sourced by the tests):
# every call that must stop says -ErrorAction Stop.

# Dot-sourcing runs the core's param block in THIS scope, so its -LoadFunctionsOnly would
# overwrite ours: remember ours first.
$entryLoadOnly = [bool]$LoadFunctionsOnly
$corePath = Join-Path $PSScriptRoot 'M365UserCheck.Core.ps1'
if (-not (Test-Path -LiteralPath $corePath)) {
    Write-Host "[FAIL] M365UserCheck.Core.ps1 is missing from $PSScriptRoot. Keep all the files in the folder together." -ForegroundColor Red
    if ($PassThru) { return [PSCustomObject]@{ Status = 'Error'; ExitCode = 3; UserPrincipalName = $UserPrincipalName; Message = 'M365UserCheck.Core.ps1 is missing.'; TicketNote = $null } }
    exit 3
}
. $corePath -LoadFunctionsOnly
$LoadFunctionsOnly = $entryLoadOnly

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

function Get-M365SafeFileName {
    # jdoe@contoso.com -> jdoe_contoso.com
    param([string]$Value)
    return (([string]$Value) -replace '[^\w\.\-]', '_')
}

# =============================================================================
# Run the check
# =============================================================================

function Write-M365CheckBanner {
    # Always first: where you are, as whom, and that nothing is changed (D-002).
    param([Parameter(Mandatory = $true)][object]$Tenant)
    $roles = if (@($Tenant.Roles).Count -gt 0) { @($Tenant.Roles) -join ', ' } elseif ($Tenant.RolesNote) { $Tenant.RolesNote } else { 'none (no active directory role, directly or through a group)' }
    $domain = if ($Tenant.DefaultDomain) { $Tenant.DefaultDomain } else { 'not known' }
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkGray
    Write-Host ' Microsoft 365 user check. This tool only reads: it changes nothing.' -ForegroundColor White
    Write-Host (' Tenant      : {0}   (default domain {1})' -f $Tenant.DisplayName, $domain) -ForegroundColor White
    Write-Host (' Tenant ID   : {0}' -f $Tenant.TenantId) -ForegroundColor White
    Write-Host (' Signed in as: {0}' -f $Tenant.Account) -ForegroundColor White
    Write-Host (' Admin roles : {0}' -f $roles) -ForegroundColor White
    Write-Host ('=' * 70) -ForegroundColor DarkGray
}

function Invoke-M365UserQuickCheck {
    <#
    .SYNOPSIS
        Banner, wrong-tenant guard, find the user, read, assess. Assumes Connect-MgGraph has run.
        Never calls exit; returns a result object with ExitCode.
    .DESCRIPTION
        The banner is written before any user is looked up, and the wrong-tenant guard runs
        before the first /users request, so a tech signed in to the wrong client sees it first.

        The on-premises AD stage (unless -SkipOnPremises) runs for every user found, and also
        when no Microsoft 365 user matched: an AD account with that sign-in name is then the
        answer ("exists in AD but not in Microsoft 365", AC20). Exit code 2 stays for "nothing
        in Microsoft 365, and nothing (or no answer) in AD". When no domain controller answers,
        the Graph verdict and its exit code stand (D-014).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$UserPrincipalName,
        [Parameter(Mandatory = $true)][object]$Context,
        [int]$Days = 7,
        [switch]$SkipOnPremises,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential,
        [switch]$Quiet,
        [datetime]$Now = [datetime]::UtcNow
    )
    $upn = $UserPrincipalName.Trim()
    $result = [PSCustomObject]@{
        Status = 'Error'; ExitCode = 3; UserPrincipalName = $upn; Message = ''; Candidates = @(); MatchedBy = ''
        Tenant = $null; User = $null; Facts = $null; Assessment = $null; OnPremises = $null; Now = $Now
    }
    $adArgs = @{}
    if ($Server) { $adArgs['Server'] = $Server }
    if ($Credential) { $adArgs['Credential'] = $Credential }

    try {
        $tenant = Get-M365TenantContext -Context $Context
    } catch {
        $msg = Get-M365ErrorText -ErrorRecord $_
        $result.Message = "The Graph session cannot answer requests, so nothing was checked: $(Get-M365ErrorSummary -Message $msg)"
        if ($msg -match 'DeviceCodeCredential|Object reference not set') {
            # Known SDK defect: device-code sign-in succeeds, then every request throws.
            # https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3495
            $result.Message += ' This matches a known Graph module problem with -UseDeviceCode: update Microsoft.Graph.Authentication (Update-Module Microsoft.Graph.Authentication), or run again without -UseDeviceCode / -DisableWam.'
        }
        return $result
    }
    $result.Tenant = $tenant
    if (-not $Quiet) { Write-M365CheckBanner -Tenant $tenant }

    # --- Wrong tenant? (before any user lookup) ---
    if ($upn.IndexOf('@') -lt 1) {
        $result.Message = "'$upn' is not a full sign-in name. Use the form jdoe@contoso.com."
        return $result
    }
    $domains = @(Get-M365VerifiedDomain -Fallback @($tenant.VerifiedDomains))
    if ($domains.Count -eq 0) {
        # No domain list means no evidence either way: never call the UPN wrong.
        $result.Message = "Could not read the tenant's domains for $($tenant.DisplayName), so the tool cannot tell whether $upn belongs to this tenant. Nothing was checked. Run it again; if it keeps happening, check that the signed-in account can read the directory (Directory.Read.All)."
        return $result
    }
    if (-not (Test-M365UpnInTenant -UserPrincipalName $upn -VerifiedDomains $domains)) {
        $upnDomain = $upn.Substring($upn.LastIndexOf('@') + 1)
        $list = if ($domains.Count -gt 0) { ' (' + (($domains | Select-Object -First 6) -join ', ') + $(if ($domains.Count -gt 6) { ', ...' } else { '' }) + ')' } else { '' }
        $result.Status = 'WrongTenant'
        $result.Message = ("Wrong tenant? {0} is not a domain of {1}{2}, so {3} cannot be a sign-in name here. Sign in to the right client (add -TenantId {0}). For a guest, use their sign-in name in this tenant (it contains #EXT#)." -f $upnDomain, $tenant.DisplayName, $list, $upn)
        return $result
    }

    # --- Find the user ---
    try {
        $found = Find-M365User -UserPrincipalName $upn
    } catch {
        $result.Message = "Could not look the user up in Microsoft 365: $(Get-M365ErrorSummary -Message (Get-M365ErrorText -ErrorRecord $_))"
        return $result
    }
    $result.MatchedBy = $found.MatchedBy
    if ($found.Status -eq 'NotFound') {
        # Never synced? An AD account with this sign-in name turns "not found" into an answer.
        if (-not $SkipOnPremises) {
            $onPrem = Get-M365OnPremisesFacts -User $null -UserPrincipalName $upn @adArgs
            $result.OnPremises = $onPrem
            if ($null -ne $onPrem.SyncedCloudUser) {
                # A cloud user holds the AD account's SID (AC20b): it syncs under another name,
                # so that user is the one to assess, never "exists in AD but not in Microsoft 365".
                $found = [PSCustomObject]@{ Status = 'Found'; User = $onPrem.SyncedCloudUser; Candidates = @(); MatchedBy = 'the security identifier (SID) of the AD account with that sign-in name' }
                $result.MatchedBy = $found.MatchedBy
            } elseif ($onPrem.Gate.State -eq 'Available' -and $null -ne $onPrem.AdUser) {
                $facts = New-M365NoCloudUserFacts -OnPremises $onPrem -TenantLastSync $tenant.OnPremisesLastSyncDateTime -Days $Days -Now $Now
                $assessment = Get-M365UserAssessment -Facts $facts
                $result.Status = 'Ok'; $result.ExitCode = $assessment.ExitCode; $result.MatchedBy = 'on-premises AD sign-in name'
                $result.Facts = $facts; $result.Assessment = $assessment
                return $result
            }
        }
        if ($found.Status -eq 'NotFound') {
            $result.Status = 'NotFound'; $result.ExitCode = 2
            $result.Message = "No Microsoft 365 user matched '$upn' in $($tenant.DisplayName) (by sign-in name, email or proxy address). Check the spelling, or that this is the right tenant."
            if ($result.OnPremises) {
                $g = $result.OnPremises.Gate
                $adPart = if ($g.State -eq 'Available') { 'No on-premises AD account has that sign-in name either.' } else { "$(Format-M365SourceLine -Gate $g)." }
                $result.Message += " $adPart"
            }
            return $result
        }
    }
    if ($found.Status -eq 'Ambiguous') {
        $result.Status = 'Ambiguous'; $result.ExitCode = 2; $result.Candidates = @($found.Candidates)
        $result.Message = "'$upn' is an email or proxy address of $(@($found.Candidates).Count) users. Run it again with the sign-in name of the right one."
        return $result
    }
    $result.User = $found.User

    # --- Read and assess ---
    $factArgs = @{ User = $found.User; Days = $Days; Now = $Now; TenantLastSync = $tenant.OnPremisesLastSyncDateTime }
    if ($SkipOnPremises) {
        $factArgs['OnPremisesGate'] = New-M365Gate -Source 'On-premises AD' -State NotChecked -Reason 'skipped with -SkipOnPremises'
    } else {
        $result.OnPremises = Get-M365OnPremisesFacts -User $found.User -UserPrincipalName $upn @adArgs
        $factArgs['OnPremises'] = $result.OnPremises
    }
    $facts = Get-M365UserFacts @factArgs
    $assessment = Get-M365UserAssessment -Facts $facts
    $result.Status = 'Ok'; $result.ExitCode = $assessment.ExitCode
    $result.Facts = $facts; $result.Assessment = $assessment
    return $result
}

# =============================================================================
# Output
# =============================================================================

function Get-M365SourceGates {
    # The five sources in banner order.
    param([Parameter(Mandatory = $true)][object]$Facts)
    return @($Facts.SignInGate, $Facts.ConditionalAccessGate, $Facts.MfaGate, $Facts.RiskGate, $Facts.OnPremisesGate | Where-Object { $null -ne $_ })
}

function Test-M365AddressCheckFailed {
    # True when the assessment lists the address-conflict lookup under Could not check (AC22c).
    param([Parameter(Mandatory = $true)][object]$Assessment)
    return (@($Assessment.CouldNotCheck | Where-Object { $_.Source -eq $script:M365AddressCheckSource }).Count -gt 0)
}

function Get-M365UserDisplayName {
    # The cloud display name, else the AD one (no cloud user, AC20), else the sign-in name.
    param([object]$Result)
    $name = [string](Get-M365Prop -Object $Result.User -Name 'displayName')
    if (-not $name -and $Result.Facts) { $name = [string](Get-M365Prop -Object (Get-M365Prop -Object $Result.Facts -Name 'AdUser') -Name 'DisplayName') }
    if (-not $name) { $name = [string]$Result.UserPrincipalName }
    return $name
}

function Get-M365AdDetail {
    # The on-premises AD rows of the details table, or none when AD was not read.
    param([Parameter(Mandatory = $true)][object]$Facts)
    $gate = Get-M365Prop -Object $Facts -Name 'OnPremisesGate'
    $rows = New-Object System.Collections.Generic.List[object]
    function Add-Row($Item, $Value) { $rows.Add([PSCustomObject]@{ Item = $Item; Value = [string]$Value }) }
    $last = ConvertTo-M365UtcTime -Value (Get-M365Prop -Object $Facts -Name 'TenantLastSync')
    if ($last) { Add-Row 'Tenant last synced' (Format-M365Time $last) }
    if (-not $gate -or $gate.State -ne 'Available') { return $rows.ToArray() }
    $ad = Get-M365Prop -Object $Facts -Name 'AdUser'
    if ($null -eq $ad) { Add-Row 'On-premises AD account' 'none found'; return $rows.ToArray() }
    $by = if ((Get-M365Prop -Object $Facts -Name 'AdMatchedBy') -eq 'SID') { 'security identifier' } else { 'sign-in name' }
    Add-Row 'On-premises AD account' ('{0} (matched by {1})' -f (Get-M365Prop -Object $ad -Name 'DistinguishedName'), $by)
    Add-Row 'AD sign-in name' (Get-M365Prop -Object $ad -Name 'UserPrincipalName')
    $enabled = Get-M365Prop -Object $ad -Name 'Enabled'
    Add-Row 'AD account enabled' $(if ($enabled -eq $true) { 'Yes' } elseif ($enabled -eq $false) { 'No (disabled)' } else { 'not recorded' })
    $marker = [string](Get-M365Prop -Object $ad -Name $script:M365BlockMarkerAttribute)
    Add-Row ('AD ' + $script:M365BlockMarkerAttribute) $(if ($marker) { $marker } else { 'not set' })
    # pwdLastSet: 100-ns intervals since 1601-01-01 UTC; 0 without DONT_EXPIRE_PASSWD means the
    # user must set a new password at next logon (a-pwdlastset).
    # https://learn.microsoft.com/windows/win32/adschema/a-pwdlastset
    $pls = Get-M365Prop -Object $ad -Name 'pwdLastSet'
    $plsText = 'not recorded'
    if ($null -ne $pls) {
        try {
            $v = [int64]$pls
            $plsText = if ($v -eq 0) { '0 (must set a new password at next sign-in, unless the password never expires)' } else { Format-M365Time ([datetime]::FromFileTimeUtc($v)) }
        } catch { $plsText = 'not readable' }
    }
    Add-Row 'AD password last set' $plsText
    return $rows.ToArray()
}

function Get-M365UserCheckDetail {
    # Compact Item/Value table for sysadmins (console, HTML). No IP addresses.
    param([Parameter(Mandatory = $true)][object]$Result)
    $u = $Result.User; $f = $Result.Facts
    $rows = New-Object System.Collections.Generic.List[object]
    function Add-Row($Item, $Value) { $rows.Add([PSCustomObject]@{ Item = $Item; Value = [string]$Value }) }

    if ($null -eq $u) {
        # No Microsoft 365 user (AC20): only the AD side has anything to show.
        Add-Row 'Microsoft 365 account' ("none matched '{0}'" -f $Result.UserPrincipalName)
        if ($f) { foreach ($d in (Get-M365AdDetail -Facts $f)) { $rows.Add($d) } }
        return $rows.ToArray()
    }

    Add-Row 'Name' (Get-M365Prop -Object $u -Name 'displayName')
    Add-Row 'Sign-in name' (Get-M365Prop -Object $u -Name 'userPrincipalName')
    Add-Row 'Email' (Get-M365Prop -Object $u -Name 'mail')
    Add-Row 'Found by' $Result.MatchedBy
    $type = [string](Get-M365Prop -Object $u -Name 'userType')
    Add-Row 'Account type' $(if ($type -eq 'Guest') { 'Guest account (B2B)' } elseif ($type) { $type } else { 'not recorded' })
    $enabled = Get-M365Prop -Object $u -Name 'accountEnabled'
    Add-Row 'Sign-in allowed' $(if ($enabled -eq $false) { 'No (blocked)' } elseif ($enabled -eq $true) { 'Yes' } else { 'not recorded' })
    if (Test-M365UserSynced -User $u) {
        $last = ConvertTo-M365UtcTime -Value (Get-M365Prop -Object $u -Name 'onPremisesLastSyncDateTime')
        $onPremName = @((Get-M365Prop -Object $u -Name 'onPremisesDomainName'), (Get-M365Prop -Object $u -Name 'onPremisesSamAccountName')) | Where-Object { $_ }
        Add-Row 'Synced from on-premises AD' ("Yes{0}{1}" -f $(if ($onPremName) { ' (' + ($onPremName -join '\') + ')' } else { '' }), $(if ($last) { ', last synced ' + (Format-M365Time $last) } else { '' }))
    } else {
        Add-Row 'Synced from on-premises AD' 'No (cloud-only)'
    }
    $lic = @(Get-M365Prop -Object $u -Name 'assignedLicenses' | Where-Object { $null -ne $_ })
    $states = @(Get-M365Prop -Object $u -Name 'licenseAssignmentStates' | Where-Object { $null -ne $_ })
    $stateText = (@($states | ForEach-Object { [string](Get-M365Prop -Object $_ -Name 'state') } | Where-Object { $_ } | Group-Object | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name })) -join ', '
    Add-Row 'Licences' ("{0} assigned{1}" -f $lic.Count, $(if ($stateText) { " ($stateText)" } else { '' }))
    if ($f) {
        $mfa = if ($f.MfaGate.State -eq 'Available') {
            $types = @($f.MfaMethods | ForEach-Object { ([string](Get-M365Prop -Object $_ -Name '@odata.type')) -replace '^#microsoft\.graph\.', '' -replace 'AuthenticationMethod$', '' } | Where-Object { $_ } | Sort-Object -Unique)
            if ($types.Count -gt 0) { $types -join ', ' } else { 'none' }
        } else { 'could not check' }
        Add-Row 'Authentication methods' $mfa
        $risk = if ($f.RiskGate.State -ne 'Available') { 'could not check' }
        elseif (-not [string](Get-M365Prop -Object $f.RiskyUser -Name 'riskLevel')) { 'not flagged' }
        else { 'risk level {0}, risk state {1}' -f (Get-M365Prop -Object $f.RiskyUser -Name 'riskLevel'), (Get-M365Prop -Object $f.RiskyUser -Name 'riskState') }
        Add-Row 'Risky user' $risk
        $si = if ($f.SignInGate.State -eq 'Available') { '{0} read from the last {1} days (interactive sign-ins only; at most {2})' -f @($f.SignIns).Count, $f.Days, $script:M365SignInPageSize } else { 'could not check' }
        Add-Row 'Sign-ins' $si
        foreach ($d in (Get-M365AdDetail -Facts $f)) { $rows.Add($d) }
    }
    return $rows.ToArray()
}

function Get-M365SignInTable {
    # Recent sign-in rows for the console and HTML. IP addresses only with -IncludeIp (HTML).
    param([Parameter(Mandatory = $true)][object]$Facts, [switch]$IncludeIp)
    $out = foreach ($r in @(Get-M365SignInRows -SignIns @($Facts.SignIns))) {
        $row = $r.Row
        $loc = Get-M365Prop -Object $row -Name 'location'
        $place = (@((Get-M365Prop -Object $loc -Name 'city'), (Get-M365Prop -Object $loc -Name 'countryOrRegion')) | Where-Object { $_ }) -join ', '
        $hasCa = Test-M365Prop -Object $row -Name 'appliedConditionalAccessPolicies'
        $ca = if (-not $hasCa) { 'not visible' } else {
            $failed = @(@(Get-M365Prop -Object $row -Name 'appliedConditionalAccessPolicies') | Where-Object { $null -ne $_ -and [string](Get-M365Prop -Object $_ -Name 'result') -eq 'failure' } | ForEach-Object { [string](Get-M365Prop -Object $_ -Name 'displayName') })
            if ($failed.Count -gt 0) { 'blocked by: ' + ($failed -join ', ') } else { '-' }
        }
        $item = [ordered]@{
            Time = Format-M365Time $r.Time
            App = $r.App
            Client = [string](Get-M365Prop -Object $row -Name 'clientAppUsed')
            Result = $(if ($r.Code -eq 0) { 'Success' } else { "Failed $($r.Code)" })
            Reason = $(if ($r.Code -eq 0) { '' } else { $r.FailureReason })
            ConditionalAccess = $ca
            Location = $place
        }
        if ($IncludeIp) { $item['IpAddress'] = [string](Get-M365Prop -Object $row -Name 'ipAddress') }
        [PSCustomObject]$item
    }
    return @($out)
}

function Write-M365UserCheckConsole {
    # Text from the tenant (reasons quote the log's failureReason, which can hold an IP address)
    # goes through ConvertTo-M365SafeText: IPs belong in the local HTML report only, and a
    # console is often screen-shared or pasted from.
    param([Parameter(Mandatory = $true)][object]$Result)
    $safe = { param($s) ConvertTo-M365SafeText -Text ([string]$s) }

    if ($Result.Status -eq 'Ambiguous') {
        Write-Status (& $safe $Result.Message) 'FAIL'
        foreach ($c in @($Result.Candidates)) {
            Write-Host ("       {0,-30} {1,-40} {2}" -f $c.DisplayName, $c.UserPrincipalName, $(if ($c.AccountEnabled) { 'sign-in allowed' } else { 'sign-in blocked' })) -ForegroundColor Gray
        }
        return
    }
    if ($Result.Status -ne 'Ok') { Write-Status (& $safe $Result.Message) 'FAIL'; return }

    $f = $Result.Facts; $a = $Result.Assessment
    Write-Host ''
    Write-Host 'What this run could see:' -ForegroundColor White
    foreach ($g in (Get-M365SourceGates -Facts $f)) {
        # A gate's reason can name the -Server given (an IP address): same filter as below.
        Write-Host ('  ' + (& $safe (Format-M365SourceLine -Gate $g))) -ForegroundColor $(if ($g.State -eq 'Available') { 'Gray' } else { 'Yellow' })
    }

    $color = switch ($a.Verdict) { 'YES' { 'Green' } 'NO' { 'Red' } default { 'Yellow' } }
    Write-Host ''
    Write-Host ("Can {0} sign in to Microsoft 365?  {1}" -f (Get-M365UserDisplayName $Result), $a.Verdict) -ForegroundColor $color
    if ($a.VerdictNote) { Write-Host ("  {0}" -f $a.VerdictNote) -ForegroundColor $color }
    Write-Host ('=' * 70) -ForegroundColor DarkGray

    $block = @($a.Reasons | Where-Object { $_.Level -eq 'Blocker' -or $_.Level -eq 'Probable' })
    $notes = @($a.Reasons | Where-Object { $_.Level -eq 'Warning' -or $_.Level -eq 'Info' })
    if ($block.Count -gt 0) {
        Write-Host 'Why not:' -ForegroundColor White
        foreach ($r in $block) {
            Write-Status (& $safe $r.Message) $(if ($r.Level -eq 'Blocker') { 'FAIL' } else { 'WARN' })
            Write-Host ("       What to do: {0}" -f (& $safe $r.Action)) -ForegroundColor Gray
        }
    }
    if ($notes.Count -gt 0) {
        Write-Host ''
        Write-Host $(if ($block.Count -gt 0) { 'Also worth knowing:' } else { 'Worth knowing:' }) -ForegroundColor White
        foreach ($r in $notes) {
            Write-Status (& $safe $r.Message) $(if ($r.Level -eq 'Warning') { 'WARN' } else { 'INFO' })
            Write-Host ("       What to do: {0}" -f (& $safe $r.Action)) -ForegroundColor Gray
        }
    }
    if (@($a.Passes).Count -gt 0) {
        Write-Host ''
        Write-Host 'Looks fine:' -ForegroundColor White
        foreach ($p in $a.Passes) { Write-Status (& $safe $p) 'PASS' }
    }
    if (@($a.CouldNotCheck).Count -gt 0) {
        Write-Host ''
        Write-Host 'Could not check:' -ForegroundColor White
        foreach ($c in $a.CouldNotCheck) { Write-Status (& $safe (Format-M365CouldNotCheckLine -Item $c)) 'WARN' }
        if ($Result.User -and $f.SignInGate.State -ne 'Available') { Write-Host ("       What to do: {0}" -f $script:M365NoSignInHistoryStep) -ForegroundColor Gray }
        if (Test-M365AddressCheckFailed -Assessment $a) { Write-Host ("       What to do: {0}" -f $script:M365AddressCheckStep) -ForegroundColor Gray }
    }

    Write-Host ''
    Write-Host 'Details' -ForegroundColor White
    Write-Host ('-' * 70) -ForegroundColor DarkGray
    foreach ($d in (Get-M365UserCheckDetail -Result $Result)) { Write-Host ("{0,-28} {1}" -f $d.Item, (& $safe $d.Value)) -ForegroundColor Gray }

    if ($f.SignInGate.State -eq 'Available' -and @($f.SignIns).Count -gt 0) {
        Write-Host ''
        Write-Host 'Recent sign-ins (newest first, IP addresses in the HTML report only)' -ForegroundColor White
        Write-Host ('-' * 70) -ForegroundColor DarkGray
        foreach ($s in @(Get-M365SignInTable -Facts $f | Select-Object -First 10)) {
            Write-Host ("{0,-21} {1,-14} {2,-30} {3}" -f $s.Time, $s.Result, (& $safe $s.App), (& $safe $s.Location)) -ForegroundColor $(if ($s.Result -eq 'Success') { 'Gray' } else { 'Yellow' })
        }
    }
    Write-Host ''
    Write-Status 'Sign-in history here is interactive sign-ins only. Cloud password expiry: Get-EntraPasswordPolicy. On-premises account state: AD-UserQuickCheck.' 'INFO'
}

function Get-M365UserCheckCsvRow {
    # One row for the ticket. Never an IP address, and never a formula: every text column goes
    # through ConvertTo-M365CsvValue (IPs removed, a leading = + - @ neutralised) at the end.
    param([Parameter(Mandatory = $true)][object]$Result)
    $u = $Result.User; $f = $Result.Facts; $a = $Result.Assessment; $t = $Result.Tenant
    $rows = @(Get-M365SignInRows -SignIns @($f.SignIns))
    $latest = if ($rows.Count -gt 0) { $rows[0] } else { $null }
    $row = [PSCustomObject]@{
        CheckedAt = (Format-M365Time $Result.Now)
        Tenant = $t.DisplayName; TenantId = $t.TenantId; SignedInAs = $t.Account
        Verdict = $a.Verdict; VerdictNote = $a.VerdictNote
        Reasons = ((@($a.Reasons | Where-Object { $_.Level -eq 'Blocker' -or $_.Level -eq 'Probable' } | ForEach-Object { $_.Message })) -join ' | ')
        Warnings = ((@($a.Reasons | Where-Object { $_.Level -eq 'Warning' } | ForEach-Object { $_.Message })) -join ' | ')
        CouldNotCheck = (@($a.CouldNotCheck | ForEach-Object { Format-M365CouldNotCheckLine -Item $_ }) -join ' | ')
        DisplayName = [string](Get-M365Prop -Object $u -Name 'displayName')
        UserPrincipalName = [string](Get-M365Prop -Object $u -Name 'userPrincipalName')
        Mail = [string](Get-M365Prop -Object $u -Name 'mail')
        UserType = [string](Get-M365Prop -Object $u -Name 'userType')
        AccountEnabled = Get-M365Prop -Object $u -Name 'accountEnabled'
        SyncedFromOnPremises = (Test-M365UserSynced -User $u)
        LicencesAssigned = @(Get-M365Prop -Object $u -Name 'assignedLicenses' | Where-Object { $null -ne $_ }).Count
        SignInHistory = $f.SignInGate.State
        SignInsRead = $(if ($f.SignInGate.State -eq 'Available') { @($f.SignIns).Count } else { $null })
        LatestSignIn = $(if ($latest) { Format-M365Time $latest.Time })
        LatestSignInErrorCode = $(if ($latest) { $latest.Code })
        LatestSignInApp = $(if ($latest) { $latest.App })
        MfaMethods = $f.MfaGate.State
        RiskyUser = $(if ($f.RiskGate.State -ne 'Available') { $f.RiskGate.State } elseif ($null -eq $f.RiskyUser) { 'NotFlagged' } else { '{0}/{1}' -f (Get-M365Prop -Object $f.RiskyUser -Name 'riskLevel'), (Get-M365Prop -Object $f.RiskyUser -Name 'riskState') })
        DaysChecked = $f.Days
        OnPremisesAD = $(if ($f.OnPremisesGate) { $f.OnPremisesGate.State })
        AdMatchedBy = [string]$f.AdMatchedBy
        AdUserPrincipalName = [string](Get-M365Prop -Object $f.AdUser -Name 'UserPrincipalName')
        AdEnabled = Get-M365Prop -Object $f.AdUser -Name 'Enabled'
        AdBlockMarker = (Test-M365BlockMarker -AdUser $f.AdUser)
        TenantLastSync = $(if ($f.TenantLastSync) { Format-M365Time (ConvertTo-M365UtcTime -Value $f.TenantLastSync) })
    }
    foreach ($p in $row.PSObject.Properties) {
        if ($p.Value -is [string]) { $p.Value = ConvertTo-M365CsvValue -Text $p.Value }
    }
    return $row
}

function ConvertTo-M365UserCheckHtml {
    # Every value from Graph is HTML-encoded (AC27): names, failure reasons and policy names can
    # contain markup.
    param([Parameter(Mandatory = $true)][object]$Result)
    function Enc([object]$s) { [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $f = $Result.Facts; $a = $Result.Assessment; $t = $Result.Tenant
    $name = Get-M365UserDisplayName $Result
    $cls = switch ($a.Verdict) { 'YES' { 'ok' } 'NO' { 'bad' } default { 'warn' } }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine("<title>Microsoft 365 sign-in check - $(Enc $name)</title>")
    [void]$sb.AppendLine('<style>body{background:#15181c;color:#e8eaed;font-family:"Segoe UI",sans-serif;max-width:1080px;margin:0 auto;padding:32px;line-height:1.5}' +
        '.banner{border:1px solid #333a44;border-radius:4px;padding:10px 14px;margin-bottom:20px;font-size:13px;color:#c3cad4}.banner b{color:#e8eaed}' +
        '.verdict{border-left:6px solid;padding:6px 0 6px 18px;margin-bottom:24px}.verdict h1{margin:0;font-size:26px}' +
        '.ok{border-color:#5fc98a}.bad{border-color:#e2686a}.warn{border-color:#e0a458}.v{font-weight:700}' +
        '.reason{background:#1d2126;border:1px solid #333a44;border-radius:4px;padding:10px 14px;margin:8px 0}' +
        '.reason small{display:block;color:#98a2b0}table{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}' +
        'td,th{padding:6px 10px;border-bottom:1px solid #242931;text-align:left;vertical-align:top}th{color:#98a2b0}h2{font-size:15px;letter-spacing:.1em;text-transform:uppercase;color:#98a2b0;margin-top:32px}' +
        '.FAIL{color:#e2686a}.WARN{color:#e0a458}.INFO{color:#5dade2}.PASS{color:#5fc98a}</style></head><body>')
    $roles = if (@($t.Roles).Count -gt 0) { @($t.Roles) -join ', ' } elseif ($t.RolesNote) { $t.RolesNote } else { 'none' }
    [void]$sb.AppendLine("<div class=`"banner`"><b>This tool only reads: it changed nothing.</b><br>Tenant: <b>$(Enc $t.DisplayName)</b> (default domain $(Enc $t.DefaultDomain)), tenant ID $(Enc $t.TenantId)<br>Signed in as: <b>$(Enc $t.Account)</b>, admin roles: $(Enc $roles)<br>")
    foreach ($g in (Get-M365SourceGates -Facts $f)) {
        [void]$sb.AppendLine("<span class=`"$(if ($g.State -eq 'Available') { 'PASS' } else { 'WARN' })`">$(Enc (Format-M365SourceLine -Gate $g))</span><br>")
    }
    [void]$sb.AppendLine('</div>')
    $note = if ($a.VerdictNote) { "<div>$(Enc $a.VerdictNote)</div>" } else { '' }
    [void]$sb.AppendLine("<div class=`"verdict $cls`"><h1>Can $(Enc $name) sign in to Microsoft 365? <span class=`"v`">$(Enc $a.Verdict)</span></h1>$note<div>Checked $(Enc (Format-M365Time $Result.Now))</div></div>")
    foreach ($r in $a.Reasons) {
        $tag = switch ($r.Level) { 'Blocker' { 'FAIL' } 'Probable' { 'WARN' } 'Warning' { 'WARN' } default { 'INFO' } }
        [void]$sb.AppendLine("<div class=`"reason`"><span class=`"$tag`">[$tag]</span> $(Enc $r.Message)<small>What to do: $(Enc $r.Action)</small></div>")
    }
    foreach ($p in $a.Passes) { [void]$sb.AppendLine("<div class=`"reason`"><span class=`"PASS`">[PASS]</span> $(Enc $p)</div>") }
    if (@($a.CouldNotCheck).Count -gt 0) {
        [void]$sb.AppendLine('<h2>Could not check</h2>')
        foreach ($c in $a.CouldNotCheck) { [void]$sb.AppendLine("<div class=`"reason`"><span class=`"WARN`">[WARN]</span> $(Enc (Format-M365CouldNotCheckLine -Item $c))</div>") }
        if ($Result.User -and $f.SignInGate.State -ne 'Available') { [void]$sb.AppendLine("<p class=`"INFO`">$(Enc $script:M365NoSignInHistoryStep)</p>") }
        if (Test-M365AddressCheckFailed -Assessment $a) { [void]$sb.AppendLine("<p class=`"INFO`">$(Enc $script:M365AddressCheckStep)</p>") }
    }
    [void]$sb.AppendLine('<h2>Details</h2><table>')
    foreach ($d in (Get-M365UserCheckDetail -Result $Result)) { [void]$sb.AppendLine("<tr><th>$(Enc $d.Item)</th><td>$(Enc $d.Value)</td></tr>") }
    [void]$sb.AppendLine('</table>')
    if ($f.SignInGate.State -eq 'Available') {
        [void]$sb.AppendLine('<h2>Recent sign-ins (newest first, interactive only)</h2><table><tr><th>Time</th><th>App</th><th>Client</th><th>Result</th><th>Reason</th><th>Conditional Access</th><th>Location</th><th>IP address</th></tr>')
        foreach ($s in @(Get-M365SignInTable -Facts $f -IncludeIp)) {
            [void]$sb.AppendLine("<tr><td>$(Enc $s.Time)</td><td>$(Enc $s.App)</td><td>$(Enc $s.Client)</td><td class=`"$(if ($s.Result -eq 'Success') { 'PASS' } else { 'WARN' })`">$(Enc $s.Result)</td><td>$(Enc $s.Reason)</td><td>$(Enc $s.ConditionalAccess)</td><td>$(Enc $s.Location)</td><td>$(Enc $s.IpAddress)</td></tr>")
        }
        [void]$sb.AppendLine('</table>')
    }
    [void]$sb.AppendLine('<p class="INFO">Sign-in history here is interactive sign-ins only. Cloud password expiry: Get-EntraPasswordPolicy. On-premises account state: AD-UserQuickCheck.</p></body></html>')
    return $sb.ToString()
}

function Export-M365UserCheckReport {
    # Writes M365UserCheck_<safe-upn>_<yyyy-MM-dd_HHmmss>.html and .csv. Returns the two paths.
    param([Parameter(Mandatory = $true)][object]$Result, [Parameter(Mandatory = $true)][string]$OutputPath)
    if (-not (Test-Path -LiteralPath $OutputPath)) { $null = New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop }
    $upn = [string](Get-M365Prop -Object $Result.User -Name 'userPrincipalName')
    if (-not $upn) { $upn = $Result.UserPrincipalName }
    $stamp = ([datetime]$Result.Now).ToLocalTime().ToString('yyyy-MM-dd_HHmmss')
    $stem = Join-Path $OutputPath ("M365UserCheck_{0}_{1}" -f (Get-M365SafeFileName $upn), $stamp)
    $csv = "$stem.csv"; $html = "$stem.html"
    Get-M365UserCheckCsvRow -Result $Result | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    [System.IO.File]::WriteAllText($html, (ConvertTo-M365UserCheckHtml -Result $Result), (New-Object System.Text.UTF8Encoding($true)))
    return [PSCustomObject]@{ Html = $html; Csv = $csv }
}

# =============================================================================
# Ticket note (CaseKit.ps1)
# =============================================================================

function ConvertTo-M365UserCheckTicketNote {
    <#
    .SYNOPSIS
        Maps a check result to a ticket note. The gate decisions for this tool live here.
    .DESCRIPTION
        Blocker -> PROBLEM, Probable and Warning -> WARNING, Info -> INFO. Every source that could
        not be read -> Could not check, with its reason; Cleared checks go to Ruled out only with
        CouldLook (the assessment never clears anything from an unreadable source). Next steps
        are the Blocker and Probable actions, plus the admin-center step when sign-in history
        could not be read. The stamp names the tenant and the signed-in account.
    #>
    param([Parameter(Mandatory = $true)][object]$Result, [string[]]$EvidencePaths = @())
    $items = New-Object System.Collections.Generic.List[object]
    $next = New-Object System.Collections.Generic.List[string]
    $upn = [string]$Result.UserPrincipalName
    $t = $Result.Tenant

    if ($Result.Status -eq 'Ok') {
        $a = $Result.Assessment; $f = $Result.Facts
        $headline = 'Can {0} sign in to Microsoft 365? {1}' -f (Get-M365UserDisplayName $Result), $a.Verdict
        if ($a.VerdictNote) { $headline += " - $($a.VerdictNote)" }
        $scopeLine = if ($Result.User) {
            'Microsoft 365 account {0} in {1}, sign-ins from the last {2} days.' -f [string](Get-M365Prop -Object $Result.User -Name 'userPrincipalName'), $t.DisplayName, $f.Days
        } else {
            "No Microsoft 365 user matched '$upn' in $($t.DisplayName); the on-premises AD account with that sign-in name was checked."
        }
        $adGate = Get-M365Prop -Object $f -Name 'OnPremisesGate'
        if ($Result.User -and $adGate -and $adGate.State -eq 'Available') { $scopeLine += ' Compared with the on-premises AD account.' }
        foreach ($r in @($a.Reasons)) {
            $kind = switch ($r.Level) { 'Blocker' { 'Problem' } 'Info' { 'Info' } default { 'Warning' } }
            $items.Add((New-TicketNoteItem -Kind $kind -Text $r.Message))
        }
        foreach ($c in @($a.CouldNotCheck)) { $items.Add((New-TicketNoteItem -Kind NotChecked -Text (Format-M365CouldNotCheckLine -Item $c))) }
        foreach ($c in @($a.Cleared)) { $items.Add((New-TicketNoteItem -Kind Clear -Text $c.Message -CouldLook ([bool]$c.CouldLook))) }

        foreach ($r in @($a.Reasons | Where-Object { $_.Level -eq 'Blocker' -or $_.Level -eq 'Probable' })) { $next.Add($r.Action) }
        if ($Result.User -and $f.SignInGate.State -ne 'Available') { $next.Add($script:M365NoSignInHistoryStep) }
        if (Test-M365AddressCheckFailed -Assessment $a) { $next.Add($script:M365AddressCheckStep) }
        if ($next.Count -eq 0 -and $a.Verdict -eq 'YES') {
            $next.Add('No Microsoft 365 account problem found. Look at the device, the app or the network next, and at the on-premises account with AD-UserQuickCheck.')
        }
    } else {
        $notRun = 'The Microsoft 365 account checks did not run (blocked, licence, sign-ins, MFA, risk).'
        switch ($Result.Status) {
            'NotFound' {
                $headline = "Microsoft 365 sign-in check did not run - no user matched '$upn'"
                $adGate = if ($Result.OnPremises) { $Result.OnPremises.Gate } else { $null }
                if ($adGate -and $adGate.State -eq 'Available') {
                    $items.Add((New-TicketNoteItem -Kind Info -Text 'No on-premises AD account has that sign-in name either.'))
                } elseif ($adGate) {
                    $items.Add((New-TicketNoteItem -Kind NotChecked -Text (Format-M365SourceLine -Gate $adGate)))
                }
                $next.Add('Check the spelling and that this is the right tenant, then run the check again.')
            }
            'Ambiguous' {
                $headline = "Microsoft 365 sign-in check did not run - '$upn' matches $(@($Result.Candidates).Count) users"
                foreach ($c in @($Result.Candidates | Select-Object -First 5)) {
                    $items.Add((New-TicketNoteItem -Kind Info -Text ('Matches {0} ({1}).' -f $c.DisplayName, $c.UserPrincipalName)))
                }
                $next.Add('Run it again with the sign-in name of the right user.')
            }
            'WrongTenant' {
                $headline = "Microsoft 365 sign-in check did not run - '$upn' is not in this tenant"
                if ($Result.Message) { $items.Add((New-TicketNoteItem -Kind Problem -Text $Result.Message)) }
                $next.Add('Sign in to the right client tenant (-TenantId) and run the check again.')
            }
            default {
                $headline = "Microsoft 365 sign-in check for '$upn' did not run - could not read Microsoft 365"
                if ($Result.Message) { $items.Add((New-TicketNoteItem -Kind Problem -Text $Result.Message)) }
                $next.Add('Check the sign-in and the Microsoft.Graph.Authentication module, then run the check again.')
            }
        }
        $scopeLine = if ($t) { "Looked up '$upn' in $($t.DisplayName)." } else { "Looked up '$upn' in Microsoft 365." }
        $items.Add((New-TicketNoteItem -Kind NotChecked -Text $notRun))
    }

    $scope = if ($t) { '{0}{1}' -f $t.DisplayName, $(if ($t.DefaultDomain) { " ($($t.DefaultDomain))" } else { '' }) } else { 'not known' }
    $stampArgs = @{ ScopeLabel = 'Tenant'; Scope = $scope }
    if ($Result.Now -is [datetime]) { $stampArgs['Now'] = ([datetime]$Result.Now).ToLocalTime() }
    if ($t -and $t.Account) { $stampArgs['RunAs'] = $t.Account }
    $stamp = New-TicketNoteStamp @stampArgs

    return New-TicketNote -Tool 'M365-UserQuickCheck' -Headline $headline -ScopeLine $scopeLine -Items $items.ToArray() `
        -NextSteps $next.ToArray() -Stamp $stamp -EvidencePaths $EvidencePaths
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
function New-M365CheckStartFailure([string]$Message) {
    [PSCustomObject]@{
        Status = 'Error'; ExitCode = 3; UserPrincipalName = $UserPrincipalName; Message = $Message; Candidates = @(); MatchedBy = ''
        Tenant = $null; User = $null; Facts = $null; Assessment = $null; Now = [datetime]::UtcNow; TicketNote = $null
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
    if ($PassThru) { return (New-M365CheckStartFailure $msg) }
    exit 3
}

try {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
} catch {
    $msg = "The Microsoft.Graph.Authentication module is not available: $($_.Exception.Message)"
    if (-not $Quiet) {
        Write-Status $msg 'FAIL'
        Write-Status 'Install it once with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser' 'INFO'
    }
    if ($PassThru) { return (New-M365CheckStartFailure $msg) }
    exit 3
}

if ($FullDetail -and -not $Quiet) {
    # Owner decision D-009: paste-safe by default; -FullDetail opts out, so say what that means.
    Write-Status '-FullDetail: the ticket note will include IP addresses and share paths. Check it before you paste it anywhere the client or a third party can read.' 'WARN'
}

if ($DisableWam -and -not $UseDeviceCode) {
    # Set-MgGraphOption -DisableLoginByWAM is not used: Microsoft documents that it only takes
    # effect with a custom ClientId (this tool uses the default one) and that it persists
    # across sessions, so it would change the tech's module settings and still not help
    # (set-mggraphoption). It is also a Set-Mg* command, which this read-only tool never runs.
    # Device code sign-in never uses WAM, so it lets the tech choose the account.
    $UseDeviceCode = [switch]$true
    if (-not $Quiet) { Write-Status '-DisableWam: signing in with a device code instead, so you can choose the client account (Windows would otherwise pick your own account).' 'INFO' }
}

# ContextScope Process keeps the client's token out of the tech's persistent token cache
# ("This accepts Process for the current process, or CurrentUser for all sessions started by
# user", connect-mggraph). Without it this tool does not sign in at all: a client's Global
# Administrator token must never be left behind for the tech's later sessions. -NoWelcome only
# hides a banner, so an older module without it just shows the banner.
$connectCommand = Get-Command -Name Connect-MgGraph -ErrorAction SilentlyContinue
if (-not $connectCommand -or -not $connectCommand.Parameters.ContainsKey('ContextScope')) {
    $msg = 'The installed Microsoft.Graph.Authentication module cannot keep the sign-in to this PowerShell window (it has no Connect-MgGraph -ContextScope), so the tool did not sign in: the client''s token would stay in your token cache. Update the module (Update-Module Microsoft.Graph.Authentication), open a new PowerShell window and run it again.'
    if (-not $Quiet) { Write-Status $msg 'FAIL' }
    if ($PassThru) { return (New-M365CheckStartFailure $msg) }
    exit 3
}
$connectParams = @{ Scopes = $script:M365Scopes; ContextScope = 'Process' }
if ($connectCommand.Parameters.ContainsKey('NoWelcome')) { $connectParams['NoWelcome'] = $true }
if ($TenantId) { $connectParams['TenantId'] = $TenantId }
if ($UseDeviceCode) { $connectParams['UseDeviceCode'] = $true }

$result = $null
$connectAttempted = $false
try {
    try {
        if (-not $Quiet) { Write-Status 'Signing in to Microsoft Graph (read-only permissions; consent for yourself only)...' 'INFO' }
        $connectAttempted = $true
        Connect-MgGraph @connectParams -ErrorAction Stop | Out-Null
        $context = Get-MgContext
        if (-not $context) { throw 'Connect-MgGraph finished without a Graph context.' }
        # Get-MgContext reports the session's ContextScope (get-mgcontext). Anything but Process
        # means the token may outlive this window; the finally block below still signs out.
        $scopeNow = [string](Get-M365Prop -Object $context -Name 'ContextScope')
        if ($scopeNow -ne 'Process' -and -not $Quiet) {
            Write-Status ("The Graph sign-in is not limited to this PowerShell window (ContextScope {0}), so the client's token may be kept for your later sessions. The tool signs out when it finishes; if it is stopped early, run Disconnect-MgGraph." -f $(if ($scopeNow) { $scopeNow } else { 'not reported' })) 'WARN'
        }
    } catch {
        $result = New-M365CheckStartFailure "Could not sign in to Microsoft Graph: $($_.Exception.Message)"
    }
    if (-not $result) {
        try {
            $checkArgs = @{ UserPrincipalName = $UserPrincipalName; Context = $context; Days = $Days; SkipOnPremises = $SkipOnPremises; Quiet = $Quiet }
            if ($Server) { $checkArgs['Server'] = $Server }
            if ($Credential) { $checkArgs['Credential'] = $Credential }
            $result = Invoke-M365UserQuickCheck @checkArgs
        } catch {
            $result = New-M365CheckStartFailure "The check stopped unexpectedly: $($_.Exception.Message)"
        }
    }
} finally {
    # Always sign out, whatever happened above (Get-EntraPasswordPolicy pattern).
    if ($connectAttempted) {
        try { Disconnect-MgGraph -ErrorAction Stop | Out-Null } catch { Write-Verbose "Disconnect-MgGraph: $($_.Exception.Message)" }
    }
}

if (-not $Quiet) { Write-M365UserCheckConsole -Result $result }

# Where the files go (AC28): the HTML and CSV only when -OutputPath is given, so nothing with
# client data is written unasked. With -TicketNumber and -OutputPath, reports and note go into
# <OutputPath>\Ticket_<n>; with -TicketNumber alone, only the note, in
# <default root>\Ticket_<n> (owner decision D-012); with -OutputPath alone, everything in that
# folder; with neither, no files (the note goes to the clipboard, or the console, D-013).
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
}

$evidence = @()
if ($reportFolder -and $result.Status -eq 'Ok') {
    try {
        $files = Export-M365UserCheckReport -Result $result -OutputPath $reportFolder
        $evidence = @($files.Html, $files.Csv)
        if (-not $Quiet) {
            Write-Status "Report saved: $($files.Html)" 'PASS'
            Write-Status "CSV saved   : $($files.Csv)" 'PASS'
        }
    } catch {
        if (-not $Quiet) { Write-Status "Could not write the report to ${reportFolder}: $($_.Exception.Message)" 'WARN' }
    }
}

$note = $null
if ($script:CaseKitMissing) {
    if (-not $Quiet -and -not $script:CaseKitWarned) { Write-Status 'CaseKit.ps1 is missing from this folder - no ticket note this time.' 'WARN' }
} else {
    # The note is extra: a failure while building or saving it never changes the answer or the
    # exit code.
    try {
        $note = ConvertTo-M365UserCheckTicketNote -Result $result -EvidencePaths $evidence
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
$result | Add-Member -NotePropertyName TicketNote -NotePropertyValue $note -Force

if ($PassThru) { return $result }
exit $result.ExitCode
