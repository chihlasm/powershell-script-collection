#Requires -Version 5.1

<#
.SYNOPSIS
    Multi-forest Active Directory account lockout forensics.

.DESCRIPTION
    Collects the evidence needed to root-cause account lockouts in environments where a
    single Entra ID tenant is fed by more than one on-premises forest (account forest +
    resource/hosted forest joined by mail / Email user-matching).

    Single-forest lockout tooling systematically misses these environments: the bad
    password attempts land in one forest while the investigator queries the other, and
    every report comes back empty.

    This script answers four questions in one pass:

      1. IS AUDITING EVEN ON?      Reads the effective audit policy on every DC in every
                                   forest. If failure auditing is off, no amount of log
                                   collection will ever produce 4625/4771 - and an empty
                                   report is a tooling artifact, not a clean result.

      2. HOW FAR BACK DO LOGS GO?  Reports Security log size, mode and true oldest event
                                   per DC, so a "0 events in 60 days" result can be
                                   distinguished from "the log only holds 5 days".

      3. WHERE ARE THE ATTEMPTS?   Polls badPwdCount / badPasswordTime on EVERY DC in
                                   EVERY forest. These are NON-REPLICATED attributes, so
                                   each DC holds its own local counter. This pinpoints the
                                   DC (and therefore the forest) receiving the bad
                                   passwords EVEN IF AUDITING IS COMPLETELY DISABLED.
                                   This is the highest-value part of the script.

      4. ARE THE PASSWORDS DRIFTING? Locates the same human's account in every forest via
                                   mail / proxyAddresses (mirroring how Entra Connect
                                   joins them) and compares pwdLastSet side by side. Two
                                   accounts, two passwords, one cloud login is a classic
                                   lockout engine.

    Read-only. Makes no changes to Active Directory.

.PARAMETER Identity
    User to investigate. Accepts sAMAccountName, UPN, or email address. The script
    resolves the account in the first forest that knows it, then pivots on the mail
    attribute to find linked accounts in the remaining forests.
    Omit to run in survey mode (health + policy only, no per-user analysis).

.PARAMETER Forest
    Forest FQDNs to interrogate. If omitted, the script starts from the current domain
    and auto-discovers additional forests from Active Directory trusts.

.PARAMETER ForestCredential
    Hashtable of per-forest credentials for forests the current user cannot read.
    A trust makes a credential presentable; it does not grant rights. If the current
    account has no permissions in the far forest, supply one here.

        $c = Get-Credential 'CORP-ES\svc-audit'
        -ForestCredential @{ 'CORP-ES.EXAMPLE.COM' = $c }

.PARAMETER DaysBack
    Event log search window in days. Default 7. The script reports whether each DC's log
    actually reaches back this far rather than silently returning fewer results.

.PARAMETER OutputFolder
    Where to write the HTML report and CSV extracts, created if missing. Defaults to a
    "Reports" folder beside this script, matching the other tools in this folder, so
    reports land in the same place regardless of the current working directory.

.PARAMETER SkipEventCollection
    Skip Security log queries. Runs the audit-policy check, log health check and the
    per-DC badPwdCount poll only. Fast triage - completes in well under a minute even in
    large environments, and still answers questions 1, 2 and 3 above.

.EXAMPLE
    .\Invoke-ADLockoutForensics.ps1 -Identity janelle.mccall -DaysBack 7

    Auto-discovers trusted forests, investigates the account across all of them.

.EXAMPLE
    $es = Get-Credential 'CORP-ES\svc-audit'
    .\Invoke-ADLockoutForensics.ps1 -Identity janelle.mccall `
        -Forest 'corp.example.com','CORP-ES.EXAMPLE.COM' `
        -ForestCredential @{ 'CORP-ES.EXAMPLE.COM' = $es } `
        -DaysBack 14 -OutputFolder C:\Temp

.EXAMPLE
    .\Invoke-ADLockoutForensics.ps1 -SkipEventCollection

    Fast environment survey: audit policy and log retention across every DC in every
    trusted forest. Run this first - it tells you whether deeper collection is even
    worth doing.

.NOTES
    Author  : VC3 - MSP tooling
    Version : 1.1
    Requires: RSAT ActiveDirectory module, imported at runtime with try/catch rather than
              via #Requires -Modules, which refuses to start on servers where the RSAT
              cmdlets work but are not formally registered.
              Remote Security log read rights on target DCs (Event Log Readers or
              equivalent). WinRM to DCs for the audit policy check - if WinRM is
              unavailable the script degrades gracefully and flags it in the report.

    Companion tools in this folder: Test-ADAuditPolicy.ps1 (single-forest audit check),
    Get-ADLockoutHistory.ps1 (domain-wide triage), Diagnose-ADAccountLockout.ps1
    (per-account deep dive), Set-DCSecurityLogRetention.ps1 (log sizing).

    REFERENCES
      Event 4740 - A user account was locked out
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740
      Event 4625 - An account failed to log on
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625
      Event 4771 - Kerberos pre-authentication failed
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4771
      Event 4776 - Credential validation (NTLM)
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4776
      Event 4724 - An attempt was made to reset an account's password
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4724
      badPwdCount is non-replicated (per-DC)
        https://learn.microsoft.com/windows/win32/adschema/a-badpwdcount
      Advanced audit policy subcategory GUIDs
        https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings
      Account lockout threshold guidance
        https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/account-lockout-threshold
      Entra Connect Pass-through Authentication
        https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-pta
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Identity,

    [string[]]$Forest,

    [hashtable]$ForestCredential = @{},

    [ValidateRange(1, 365)]
    [int]$DaysBack = 7,

    # Resolved in the Main region to a Reports folder beside this script when omitted.
    [string]$OutputFolder,

    [switch]$SkipEventCollection,

    # Internal: dot-source the functions without running the collection.
    # Used by the Pester tests so they can load helpers on a box without RSAT.
    [switch]$LoadFunctionsOnly
)

$ErrorActionPreference = 'Continue'

#region ----------------------------------------------------------- Constants

# Audit subcategories referenced by GUID rather than display name so the check is
# locale-independent - display names are localised, GUIDs are not.
$script:AuditSubcategories = [ordered]@{
    'Logon'                            = @{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Events = '4624 / 4625'; Why = 'Failed interactive/network logons (4625). Without Failure auditing here you will never see which machine sent a bad password.' }
    'Account Lockout'                  = @{ Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Events = '4625 (lockout)'; Why = 'Logon failures specifically caused by an already-locked account.' }
    'Kerberos Authentication Service'  = @{ Guid = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Events = '4768 / 4771'; Why = 'Kerberos pre-auth failures (4771). This is where most modern domain-joined bad passwords appear.' }
    'Credential Validation'            = @{ Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Events = '4776'; Why = 'NTLM validation failures (4776). Catches legacy clients, mapped drives and cached credentials.' }
    'User Account Management'          = @{ Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Events = '4740 / 4724'; Why = 'Lockout events (4740) and admin password resets (4724). Success auditing is required here.' }
}

# Subcategories where Failure auditing is the critical setting vs Success
$script:NeedsFailure = @('Logon', 'Account Lockout', 'Kerberos Authentication Service', 'Credential Validation')
$script:NeedsSuccess = @('User Account Management')

# Event descriptions are deliberately OUTCOME-NEUTRAL. 4776, 4771 and 4768 are written
# for BOTH successful and failed authentications - the status code is the only
# discriminator. Baking "failed" into the label makes healthy machines look guilty.
$script:EventMeaning = @{
    4740 = 'Account locked out'
    4625 = 'Failed logon'
    4771 = 'Kerberos pre-authentication'
    4768 = 'Kerberos TGT request'
    4776 = 'NTLM credential validation'
    4724 = 'Admin/helpdesk password reset'
    4723 = 'User-initiated password change'
}

# Kerberos (4771/4768) and NTLM (4776/4625) status codes, transcribed from the Microsoft
# Learn tables rather than from memory. A wrong description here is dangerous: it reads as
# authoritative in the report and sends the investigator after the wrong cause.
#
# Kerberos codes are RFC 4120 KDC error codes:
#   https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4771
# NTLM codes are the Winlogon error codes in Table 1 of:
#   https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4776
#
# 0x0 means SUCCESS in both families. 4776/4771/4768 are written for successful
# authentications too, so the status code is the only discriminator.
$script:StatusCodes = @{
    # --- Kerberos (4771 / 4768) ---
    '0x0'        = 'Success (KDC_ERR_NONE)'
    '0x6'        = 'Username does not exist (KDC_ERR_C_PRINCIPAL_UNKNOWN)'
    '0xC'        = 'KDC policy rejects request (KDC_ERR_POLICY) - e.g. logon hours or workstation restriction'
    '0x10'       = 'KDC has no support for PADATA type (KDC_ERR_PADATA_TYPE_NOSUPP) - usually a smart-card/certificate problem'
    '0x12'       = 'Client credentials revoked (KDC_ERR_CLIENT_REVOKED) - account disabled, expired, or LOCKED OUT'
    '0x17'       = 'Password has expired (KDC_ERR_KEY_EXPIRED)'
    '0x18'       = 'Bad password - pre-authentication failed (KDC_ERR_PREAUTH_FAILED)'
    '0x19'       = 'Additional pre-authentication required (KDC_ERR_PREAUTH_REQUIRED)'
    '0x25'       = 'Clock skew too great (KRB_AP_ERR_SKEW)'

    # --- NTLM (4776), Winlogon error codes ---
    '0x00000000' = 'Success (no errors)'
    '0xC0000064' = 'Username does not exist'
    '0xC000006A' = 'Bad password'
    '0xC000006D' = 'Generic logon failure - bad username/password, or a LAN Manager authentication level mismatch'
    '0xC000006F' = 'Logon outside authorized hours'
    '0xC0000070' = 'Logon from unauthorized workstation'
    '0xC0000071' = 'Password expired'
    '0xC0000072' = 'Account disabled'
    '0xC0000193' = 'Account expired'
    '0xC0000224' = 'Change password at next logon is flagged'
    '0xC0000234' = 'Account locked out'
    '0xC0000371' = 'Local account store has no secret material for this account'
}

$script:Findings = New-Object System.Collections.ArrayList
#endregion

#region ----------------------------------------------------------- Helpers

function Write-Step {
    param([string]$Message, [string]$Level = 'Info')
    $stamp = (Get-Date).ToString('HH:mm:ss')
    switch ($Level) {
        'Ok'    { Write-Host "[$stamp] $Message" -ForegroundColor Green }
        'Warn'  { Write-Host "[$stamp] $Message" -ForegroundColor Yellow }
        'Error' { Write-Host "[$stamp] $Message" -ForegroundColor Red }
        default { Write-Host "[$stamp] $Message" -ForegroundColor Gray }
    }
}

function Add-Finding {
    <# .SYNOPSIS Records an analysis finding for the report's Findings section. #>
    param(
        [ValidateSet('Critical', 'Warning', 'Info', 'Good')]
        [string]$Severity,
        [string]$Title,
        [string]$Detail,
        [string]$Action = ''
    )
    $null = $script:Findings.Add([pscustomobject]@{
        Severity = $Severity
        Title    = $Title
        Detail   = $Detail
        Action   = $Action
    })
}

function Get-ForestCred {
    <# .SYNOPSIS Returns the credential for a forest, or $null to use the current context. #>
    param([string]$ForestName)
    foreach ($key in $ForestCredential.Keys) {
        if ($key -eq $ForestName) { return $ForestCredential[$key] }
    }
    return $null
}

function Invoke-ADCommand {
    <#
    .SYNOPSIS
        Invokes an AD cmdlet by name, splatting -Credential only when one exists for the
        target forest. Keeps every call site free of duplicated credential branching.
    .NOTES
        Takes the cmdlet NAME rather than a scriptblock on purpose: splatting a hashtable
        into a scriptblock does not bind named parameters reliably, whereas
        "& 'Get-ADUser' @hashtable" binds exactly as a direct call would.
    #>
    param(
        [Parameter(Mandatory)][string]$Cmdlet,
        [Parameter(Mandatory)][hashtable]$Arguments,
        [string]$ForestName
    )
    $cred = Get-ForestCred -ForestName $ForestName
    if ($cred) { $Arguments['Credential'] = $cred }
    return & $Cmdlet @Arguments
}

function ConvertTo-SafeHtml {
    param([object]$Text)
    if ($null -eq $Text) { return '' }
    $s = [string]$Text
    return ($s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;')
}

function Format-AdTimestamp {
    <#
    .SYNOPSIS
        Converts AD's large-integer time attributes into readable dates.
        0 and 9223372036854775807 are AD's "never" sentinels and must not be rendered
        as 1601-01-01, which is a common and confusing reporting bug.
    #>
    param([object]$Value)
    if ($null -eq $Value) { return 'Not set' }
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd HH:mm:ss') }
    try { $n = [int64]$Value } catch { return [string]$Value }
    if ($n -eq 0 -or $n -eq [int64]::MaxValue) { return 'Never' }
    try { return ([datetime]::FromFileTime($n)).ToString('yyyy-MM-dd HH:mm:ss') }
    catch { return [string]$Value }
}
#endregion

#region ----------------------------------------------------------- Forest discovery

function Resolve-TargetForest {
    <#
    .SYNOPSIS
        Builds the list of forests to interrogate, auto-discovering across trusts when
        the caller did not name them explicitly.
    .DESCRIPTION
        Auto-discovery is what makes this script correct by default in multi-forest
        environments. Investigators routinely do not know a second forest exists.
    #>
    param([string[]]$Explicit)

    $result = New-Object System.Collections.ArrayList

    if ($Explicit -and $Explicit.Count -gt 0) {
        foreach ($f in $Explicit) { $null = $result.Add($f) }
        Write-Step "Using $($result.Count) forest(s) supplied on the command line."
        return $result
    }

    try {
        $localDomain = Get-ADDomain -ErrorAction Stop
        $null = $result.Add($localDomain.DNSRoot)
        Write-Step "Current domain: $($localDomain.DNSRoot)" -Level Ok
    }
    catch {
        throw "Cannot contact the local domain. Run this from a domain-joined machine or supply -Forest explicitly. $($_.Exception.Message)"
    }

    try {
        $trusts = Get-ADTrust -Filter * -ErrorAction Stop
        foreach ($t in $trusts) {
            if ($result -notcontains $t.Target) {
                $null = $result.Add($t.Target)
                $dir = switch ($t.Direction) {
                    'BiDirectional' { 'two-way' }
                    'Inbound'       { 'inbound only' }
                    'Outbound'      { 'outbound only' }
                    default         { [string]$t.Direction }
                }
                Write-Step "Discovered trusted forest: $($t.Target) ($($t.TrustType), $dir)" -Level Ok

                if ($t.Direction -ne 'BiDirectional') {
                    Add-Finding -Severity 'Warning' `
                        -Title "Trust to $($t.Target) is $dir" `
                        -Detail "A one-way trust may prevent this script from reading the far forest. If that forest returns access errors below, supply a credential with -ForestCredential." `
                        -Action "Verify read rights in $($t.Target)."
                }
            }
        }
    }
    catch {
        Write-Step "Could not enumerate trusts: $($_.Exception.Message)" -Level Warn
    }

    return $result
}

function Add-LockoutPolicyFinding {
    <#
    .SYNOPSIS
        Assesses a domain's lockout policy and records a finding.
    .DESCRIPTION
        Split out from Get-ForestTopology so the threshold assessment is unit-testable
        without a live directory.

        Microsoft's current baseline is a threshold of 10 over a 15-minute observation
        window. A threshold at or below 5 is exhausted by ordinary stale-credential noise
        (one phone with an old Wi-Fi or mail profile) and produces lockouts that look like
        attacks but are not.
        https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/account-lockout-threshold
    #>
    param(
        [string]$ForestName,
        [object]$Policy
    )

    if (-not $Policy) { return }

    $threshold = [int]$Policy.LockoutThreshold

    if ($threshold -eq 0) {
        Add-Finding -Severity 'Info' `
            -Title "$ForestName has lockout disabled (threshold 0)" `
            -Detail 'Accounts in this domain never lock out. Lockouts affecting these users must originate elsewhere - another forest, or Entra ID Smart Lockout.' `
            -Action 'Confirm this is intentional. If users report lockouts, the source is not this domain.'
    }
    elseif ($threshold -le 5) {
        Add-Finding -Severity 'Warning' `
            -Title "$ForestName lockout threshold is $threshold" `
            -Detail "Observation window $($Policy.LockoutObservationWindow), lockout duration $($Policy.LockoutDuration). A threshold of $threshold is aggressively low - a single device holding a stale credential exhausts it in seconds. Microsoft's baseline is 10 attempts over a 15-minute window." `
            -Action 'Raise the threshold to 10 and set the observation window to 15 minutes in the Default Domain Policy.'
    }
    else {
        Add-Finding -Severity 'Good' `
            -Title "$ForestName lockout threshold is $threshold" `
            -Detail "Observation window $($Policy.LockoutObservationWindow), lockout duration $($Policy.LockoutDuration). This is within normal guidance and is unlikely to be causing false lockouts on its own."
    }
}

function Get-ForestTopology {
    <# .SYNOPSIS Enumerates every DC in a forest plus the PDC emulator and lockout policy. #>
    param([string]$ForestName)

    $topo = [pscustomobject]@{
        Forest       = $ForestName
        Reachable    = $false
        Error        = ''
        NetBIOSName  = ''
        PDCEmulator  = ''
        DomainControllers = @()
        Policy       = $null
    }

    try {
        $domain = Invoke-ADCommand -ForestName $ForestName -Cmdlet 'Get-ADDomain' `
                    -Arguments @{ Identity = $ForestName; Server = $ForestName; ErrorAction = 'Stop' }

        $topo.Reachable   = $true
        $topo.NetBIOSName = $domain.NetBIOSName
        $topo.PDCEmulator = $domain.PDCEmulator

        $dcs = Invoke-ADCommand -ForestName $ForestName -Cmdlet 'Get-ADDomainController' `
                 -Arguments @{ Filter = '*'; Server = $ForestName; ErrorAction = 'Stop' }

        $topo.DomainControllers = @($dcs | Select-Object -ExpandProperty HostName | Sort-Object)

        $pol = Invoke-ADCommand -ForestName $ForestName -Cmdlet 'Get-ADDefaultDomainPasswordPolicy' `
                 -Arguments @{ Identity = $ForestName; Server = $ForestName; ErrorAction = 'Stop' }
        $topo.Policy = $pol

        Write-Step "$ForestName - $($topo.DomainControllers.Count) DC(s), PDC = $($topo.PDCEmulator)" -Level Ok

        Add-LockoutPolicyFinding -ForestName $ForestName -Policy $pol
    }
    catch {
        $topo.Error = $_.Exception.Message
        Write-Step "$ForestName unreachable: $($topo.Error)" -Level Error
        Add-Finding -Severity 'Critical' `
            -Title "Cannot query forest $ForestName" `
            -Detail $topo.Error `
            -Action "Supply credentials with -ForestCredential @{ '$ForestName' = (Get-Credential) }, or run the script again from a server inside that forest."
    }

    return $topo
}
#endregion

#region ----------------------------------------------------------- DC health

function Get-DCAuditPolicy {
    <#
    .SYNOPSIS
        Reads effective advanced audit policy for the lockout-relevant subcategories.
    .DESCRIPTION
        THE most important check in this script. If Failure auditing is off, the Security
        log contains no 4625/4771 no matter how long the retention is - and every lockout
        report ever run against this environment has been silently meaningless.

        Uses auditpol.exe via WinRM. Subcategories are referenced by GUID for locale
        independence.
    #>
    param([string]$ComputerName, [string]$ForestName)

    $out = [pscustomobject]@{
        Computer    = $ComputerName
        Queried     = $false
        Error       = ''
        Settings    = @{}
    }

    $sb = {
        param($guidMap)
        $results = @{}
        foreach ($name in $guidMap.Keys) {
            $guid = $guidMap[$name]
            try {
                $raw = & auditpol.exe /get /subcategory:"$guid" /r 2>$null
                $parsed = $raw | ConvertFrom-Csv
                $row = $parsed | Where-Object { $_.'Subcategory GUID' -and $_.'Inclusion Setting' } | Select-Object -First 1
                if ($row) { $results[$name] = $row.'Inclusion Setting' }
                else      { $results[$name] = 'Unknown' }
            }
            catch { $results[$name] = 'Query failed' }
        }
        return $results
    }

    $guidMap = @{}
    foreach ($k in $script:AuditSubcategories.Keys) { $guidMap[$k] = $script:AuditSubcategories[$k].Guid }

    $icmArgs = @{
        ComputerName = $ComputerName
        ScriptBlock  = $sb
        ArgumentList = $guidMap
        ErrorAction  = 'Stop'
    }
    $cred = Get-ForestCred -ForestName $ForestName
    if ($cred) { $icmArgs['Credential'] = $cred }

    try {
        $res = Invoke-Command @icmArgs
        $out.Queried  = $true
        # Invoke-Command returns a deserialised hashtable; normalise it.
        $tbl = @{}
        foreach ($k in $guidMap.Keys) {
            if ($res.ContainsKey($k)) { $tbl[$k] = [string]$res[$k] } else { $tbl[$k] = 'Unknown' }
        }
        $out.Settings = $tbl
    }
    catch {
        $out.Error = $_.Exception.Message
    }

    return $out
}

function Get-DCLogHealth {
    <#
    .SYNOPSIS
        Reports Security log configuration and the true oldest retained event.
    .DESCRIPTION
        Separates "there were no lockouts" from "the log rolled over before you looked".
        The oldest-event timestamp is the only trustworthy measure of real coverage;
        configured size is not, because event volume varies wildly per DC.
    #>
    param([string]$ComputerName, [string]$ForestName, [int]$RequestedDays)

    $out = [pscustomobject]@{
        Computer       = $ComputerName
        Reachable      = $false
        Error          = ''
        MaxSizeMB      = 0
        CurrentSizeMB  = 0
        LogMode        = ''
        RecordCount    = 0
        OldestEvent    = $null
        CoverageDays   = 0
        CoversWindow   = $false
    }

    $cred = Get-ForestCred -ForestName $ForestName

    try {
        $listArgs = @{ ListLog = 'Security'; ComputerName = $ComputerName; ErrorAction = 'Stop' }
        if ($cred) { $listArgs['Credential'] = $cred }
        $log = Get-WinEvent @listArgs

        $out.Reachable     = $true
        $out.MaxSizeMB     = [math]::Round($log.MaximumSizeInBytes / 1MB, 0)
        $out.CurrentSizeMB = [math]::Round($log.FileSize / 1MB, 0)
        $out.LogMode       = [string]$log.LogMode
        $out.RecordCount   = $log.RecordCount

        $oldArgs = @{ LogName = 'Security'; ComputerName = $ComputerName; MaxEvents = 1; Oldest = $true; ErrorAction = 'Stop' }
        if ($cred) { $oldArgs['Credential'] = $cred }
        $oldest = Get-WinEvent @oldArgs

        if ($oldest) {
            $out.OldestEvent  = $oldest.TimeCreated
            $out.CoverageDays = [math]::Round(((Get-Date) - $oldest.TimeCreated).TotalDays, 1)
            $out.CoversWindow = ($out.CoverageDays -ge $RequestedDays)
        }
    }
    catch {
        $out.Error = $_.Exception.Message
    }

    return $out
}

function Get-PerDCBadPasswordState {
    <#
    .SYNOPSIS
        Polls badPwdCount / badPasswordTime / lockoutTime on a specific DC.
    .DESCRIPTION
        badPwdCount, badPasswordTime and lockoutTime are NON-REPLICATED attributes - each
        DC maintains its own copy reflecting only the authentications it personally
        handled. Querying "the domain" returns whichever DC the client happened to bind
        to, which is why single-DC tooling produces inconsistent and misleading results.

        Polling every DC individually reveals which DC is actually receiving the bad
        passwords. Critically, this works even when auditing is disabled entirely -
        making it the most reliable signal available in a poorly-audited environment.
    #>
    param([string]$ComputerName, [string]$SamAccountName, [string]$ForestName)

    $props = @('badPwdCount', 'badPasswordTime', 'lockoutTime', 'pwdLastSet', 'lastLogonTimestamp', 'logonCount')

    try {
        $u = Invoke-ADCommand -ForestName $ForestName -Cmdlet 'Get-ADUser' -Arguments @{
            Identity    = $SamAccountName
            Server      = $ComputerName
            Properties  = $props
            ErrorAction = 'Stop'
        }

        return [pscustomobject]@{
            Computer        = $ComputerName
            Forest          = $ForestName
            Reachable       = $true
            Error           = ''
            BadPwdCount     = $u.badPwdCount
            BadPasswordTime = $u.badPasswordTime
            LockoutTime     = $u.lockoutTime
            PwdLastSet      = $u.pwdLastSet
        }
    }
    catch {
        return [pscustomobject]@{
            Computer        = $ComputerName
            Forest          = $ForestName
            Reachable       = $false
            Error           = $_.Exception.Message
            BadPwdCount     = $null
            BadPasswordTime = $null
            LockoutTime     = $null
            PwdLastSet      = $null
        }
    }
}
#endregion

#region ----------------------------------------------------------- Account resolution

function Find-AccountAcrossForests {
    <#
    .SYNOPSIS
        Locates the same human's account in every forest.
    .DESCRIPTION
        Mirrors how Entra Connect joins identities when userMatchingPolicy is Email:
        resolve the account wherever it is known, take its mail attribute, then search
        the remaining forests by mail and proxyAddresses.

        Two accounts in two forests with two independently-managed passwords behind one
        cloud login is a primary lockout cause and is invisible to single-forest tooling.
    #>
    param([string]$Id, [object[]]$Topologies)

    $found = New-Object System.Collections.ArrayList
    $props = @(
        'SamAccountName','DistinguishedName','UserPrincipalName','mail','proxyAddresses',
        'LockedOut','badPwdCount','badPasswordTime','lockoutTime','pwdLastSet',
        'Enabled','PasswordNeverExpires','PasswordExpired','whenCreated','whenChanged',
        'lastLogonTimestamp','msDS-UserPasswordExpiryTimeComputed','userAccountControl'
    )

    $anchorMail = $null

    # Pass 1 - direct resolution by sAMAccountName / UPN / mail in each forest.
    foreach ($topo in $Topologies) {
        if (-not $topo.Reachable) { continue }

        $ldap = "(&(objectClass=user)(objectCategory=person)(|(sAMAccountName=$Id)(userPrincipalName=$Id)(mail=$Id)(proxyAddresses=smtp:$Id)))"
        try {
            $hits = Invoke-ADCommand -ForestName $topo.Forest -Cmdlet 'Get-ADUser' -Arguments @{
                LDAPFilter  = $ldap
                Server      = $topo.Forest
                Properties  = $props
                ErrorAction = 'Stop'
            }
            foreach ($h in @($hits)) {
                $null = $found.Add([pscustomobject]@{ Forest = $topo.Forest; User = $h; MatchedBy = 'Direct' })
                if (-not $anchorMail -and $h.mail) { $anchorMail = $h.mail }
                Write-Step "Found $($h.SamAccountName) in $($topo.Forest)" -Level Ok
            }
        }
        catch {
            Write-Step "Search failed in $($topo.Forest): $($_.Exception.Message)" -Level Warn
        }
    }

    # Pass 2 - pivot on mail to catch linked accounts whose sAMAccountName differs.
    if ($anchorMail) {
        foreach ($topo in $Topologies) {
            if (-not $topo.Reachable) { continue }
            $already = @($found | Where-Object { $_.Forest -eq $topo.Forest })
            if ($already.Count -gt 0) { continue }

            $ldap2 = "(&(objectClass=user)(objectCategory=person)(|(mail=$anchorMail)(proxyAddresses=smtp:$anchorMail)(proxyAddresses=SMTP:$anchorMail)))"
            try {
                $hits = Invoke-ADCommand -ForestName $topo.Forest -Cmdlet 'Get-ADUser' -Arguments @{
                    LDAPFilter  = $ldap2
                    Server      = $topo.Forest
                    Properties  = $props
                    ErrorAction = 'Stop'
                }
                foreach ($h in @($hits)) {
                    $null = $found.Add([pscustomobject]@{ Forest = $topo.Forest; User = $h; MatchedBy = "Email ($anchorMail)" })
                    Write-Step "Found linked account $($h.SamAccountName) in $($topo.Forest) via mail" -Level Ok
                }
            }
            catch {
                Write-Step "Email pivot failed in $($topo.Forest): $($_.Exception.Message)" -Level Warn
            }
        }
    }

    return $found
}
#endregion

#region ----------------------------------------------------------- Event collection

function Get-LockoutEvents {
    <#
    .SYNOPSIS
        Pulls lockout-relevant Security events from one DC, optionally filtered to a user.
    .DESCRIPTION
        Uses a single FilterHashtable query per DC rather than one query per event ID.
        On a busy DC this is the difference between seconds and many minutes.
    #>
    param(
        [string]$ComputerName,
        [string]$ForestName,
        [string]$SamAccountName,
        [datetime]$StartTime
    )

    $collected = New-Object System.Collections.ArrayList
    $cred = Get-ForestCred -ForestName $ForestName

    $filter = @{
        LogName   = 'Security'
        ID        = @(4740, 4625, 4771, 4768, 4776, 4724, 4723)
        StartTime = $StartTime
    }

    $qArgs = @{ FilterHashtable = $filter; ComputerName = $ComputerName; ErrorAction = 'Stop' }
    if ($cred) { $qArgs['Credential'] = $cred }

    try {
        $events = Get-WinEvent @qArgs
    }
    catch {
        if ($_.Exception.Message -match 'No events were found') { return $collected }
        Write-Step "Event query failed on $ComputerName : $($_.Exception.Message)" -Level Warn
        return $collected
    }

    foreach ($e in $events) {
        # XML parsing is used rather than regex against the rendered message because
        # rendered text is localised and reformats between OS versions.
        try   { $x = [xml]$e.ToXml() } catch { continue }

        $d = @{}
        foreach ($node in $x.Event.EventData.Data) {
            if ($node.Name) { $d[$node.Name] = [string]$node.'#text' }
        }

        $target = ''
        foreach ($k in 'TargetUserName', 'TargetAccount') {
            if ($d.ContainsKey($k) -and $d[$k]) { $target = $d[$k]; break }
        }

        # Filter to the account under investigation when one was supplied.
        if ($SamAccountName -and $target -and ($target -ne $SamAccountName)) { continue }
        # 4776 uses a different field name for the account.
        if ($SamAccountName -and -not $target) { continue }

        $caller = ''
        foreach ($k in 'TargetDomainName', 'WorkstationName', 'Workstation', 'CallerComputerName', 'IpAddress') {
            if ($d.ContainsKey($k) -and $d[$k] -and $d[$k] -ne '-') { $caller = $d[$k]; break }
        }
        # Prefer an explicit source machine when several are present.
        foreach ($k in 'CallerComputerName', 'WorkstationName', 'Workstation') {
            if ($d.ContainsKey($k) -and $d[$k] -and $d[$k] -ne '-') { $caller = $d[$k]; break }
        }

        $ip = ''
        if ($d.ContainsKey('IpAddress') -and $d['IpAddress'] -and $d['IpAddress'] -ne '-') { $ip = $d['IpAddress'] }

        $status = ''
        foreach ($k in 'Status', 'FailureCode') {
            if ($d.ContainsKey($k) -and $d[$k]) { $status = $d[$k]; break }
        }
        # 4625 carries the real reason in SubStatus; Status is often a generic 0xC000006D.
        if ($e.Id -eq 4625 -and $d.ContainsKey('SubStatus') -and $d['SubStatus'] -and $d['SubStatus'] -ne '0x0') {
            $status = $d['SubStatus']
        }

        # OUTCOME DETERMINATION - do not skip this.
        # 4776/4771/4768 are logged for successful authentications too. A status of 0x0
        # means SUCCESS. Reporting every 4776 as a failure points the investigation at
        # machines that are working correctly, which is worse than reporting nothing.
        $isSuccessCode = ($status -eq '0x0' -or $status -eq '0x00000000' -or $status -eq '0' -or $status -eq '')

        $outcome = 'Failure'
        if     ($e.Id -eq 4740) { $outcome = 'Lockout' }
        elseif ($e.Id -eq 4724) { $outcome = 'Admin reset' }
        elseif ($e.Id -eq 4723) { $outcome = 'Password change' }
        elseif ($e.Id -eq 4625) { $outcome = 'Failure' }
        elseif ($isSuccessCode) { $outcome = 'Success' }

        $statusText = ''
        if ($status -and $script:StatusCodes.ContainsKey($status)) { $statusText = $script:StatusCodes[$status] }

        $meaning = 'Other'
        if ($script:EventMeaning.ContainsKey($e.Id)) { $meaning = $script:EventMeaning[$e.Id] }

        $null = $collected.Add([pscustomobject]@{
            Time         = $e.TimeCreated
            DC           = $ComputerName
            Forest       = $ForestName
            EventID      = $e.Id
            Meaning      = $meaning
            Outcome      = $outcome
            Account      = $target
            CallerName   = $caller
            IPAddress    = $ip
            StatusCode   = $status
            StatusText   = $statusText
        })
    }

    return $collected
}
#endregion

#region ----------------------------------------------------------- Analysis

function Invoke-Analysis {
    <# .SYNOPSIS Turns raw collection into ranked findings. #>
    param(
        [object[]]$Topologies,
        [object[]]$AuditResults,
        [object[]]$LogHealth,
        [object[]]$Accounts,
        [object[]]$BadPwdStates,
        [object[]]$Events,
        [int]$RequestedDays,
        [bool]$EventsCollected
    )

    # --- Audit policy gaps -------------------------------------------------
    $auditGaps = New-Object System.Collections.ArrayList
    foreach ($a in $AuditResults) {
        if (-not $a.Queried) { continue }
        foreach ($sub in $script:NeedsFailure) {
            if ($a.Settings.ContainsKey($sub)) {
                $val = $a.Settings[$sub]
                if ($val -notmatch 'Failure') {
                    $null = $auditGaps.Add("$($a.Computer): '$sub' = $val")
                }
            }
        }
        foreach ($sub in $script:NeedsSuccess) {
            if ($a.Settings.ContainsKey($sub)) {
                $val = $a.Settings[$sub]
                if ($val -notmatch 'Success') {
                    $null = $auditGaps.Add("$($a.Computer): '$sub' = $val")
                }
            }
        }
    }

    if ($auditGaps.Count -gt 0) {
        Add-Finding -Severity 'Critical' `
            -Title 'Failure auditing is NOT enabled on one or more domain controllers' `
            -Detail ("This is a root-cause blocker. Without these subcategories the Security log will never contain 4625/4771 events, so every lockout investigation in this environment returns empty results regardless of log retention. Gaps found:`n" + ($auditGaps -join "`n")) `
            -Action 'Enable Success AND Failure for Logon, Kerberos Authentication Service, Credential Validation and Account Lockout, plus Success for User Account Management, via the Default Domain Controllers Policy. Then wait for the next lockout and re-run this script.'
    }
    elseif (($AuditResults | Where-Object { $_.Queried }).Count -gt 0) {
        Add-Finding -Severity 'Good' `
            -Title 'Audit policy is correctly configured on all reachable DCs' `
            -Detail 'Failure auditing is enabled for the lockout-relevant subcategories. An empty event result is therefore a genuine finding, not a collection gap.'
    }

    # A dedicated, unmissable finding for the single most consequential gap: if
    # User Account Management lacks Success auditing, event 4740 is never written, and
    # EVERY lockout-history report against this environment is structurally empty. That
    # is a tooling artifact masquerading as "no lockouts occurred".
    $no4740 = @($AuditResults | Where-Object {
        $_.Queried -and $_.Settings.ContainsKey('User Account Management') -and
        $_.Settings['User Account Management'] -notmatch 'Success'
    })
    if ($no4740.Count -gt 0) {
        Add-Finding -Severity 'Critical' `
            -Title 'Event 4740 is NOT being written - lockout history is structurally unavailable' `
            -Detail ("'User Account Management' lacks Success auditing on: " + (($no4740 | Select-Object -ExpandProperty Computer) -join ', ') + ".`n`nEvent 4740 (account locked out) is generated by this subcategory. With it disabled the DC never records a lockout at all, so any 'lockout history' report - over any window, at any retention - returns zero rows. Past empty reports are therefore NOT evidence that lockouts did not happen.") `
            -Action 'Enable Success for Audit User Account Management in the Default Domain Controllers Policy, run gpupdate /force on each DC, then confirm with: auditpol /get /subcategory:"{0CCE9235-69AE-11D9-BED3-505054503030}"'
    }

    $noKerb = @($AuditResults | Where-Object {
        $_.Queried -and $_.Settings.ContainsKey('Kerberos Authentication Service') -and
        $_.Settings['Kerberos Authentication Service'] -eq 'No Auditing'
    })
    if ($noKerb.Count -gt 0) {
        Add-Finding -Severity 'Critical' `
            -Title 'Kerberos auditing is fully disabled - the primary bad-password vector is invisible' `
            -Detail ("'Kerberos Authentication Service' = No Auditing on: " + (($noKerb | Select-Object -ExpandProperty Computer) -join ', ') + ".`n`nDomain-joined Windows clients authenticate with Kerberos, not NTLM. Event 4771 is where the majority of bad-password attempts appear. With this subcategory off, a bad password can update badPasswordTime on the account while leaving NO event behind - which looks like a contradiction in the data but is simply an audit gap.") `
            -Action 'Enable Success and Failure for Audit Kerberos Authentication Service in the Default Domain Controllers Policy.'
    }

    $unqueried = @($AuditResults | Where-Object { -not $_.Queried })
    if ($unqueried.Count -gt 0) {
        Add-Finding -Severity 'Warning' `
            -Title "Audit policy could not be read on $($unqueried.Count) DC(s)" `
            -Detail ("Usually WinRM is not enabled or reachable. Affected: " + (($unqueried | Select-Object -ExpandProperty Computer) -join ', ')) `
            -Action 'Run "auditpol /get /category:"Logon/Logoff","Account Logon","Account Management"" locally on each of these DCs.'
    }

    # --- Log retention -----------------------------------------------------
    $shortLogs = @($LogHealth | Where-Object { $_.Reachable -and -not $_.CoversWindow })
    if ($shortLogs.Count -gt 0) {
        $lines = $shortLogs | ForEach-Object { "$($_.Computer): $($_.CoverageDays) day(s) retained, $($_.MaxSizeMB) MB max" }
        Add-Finding -Severity 'Warning' `
            -Title "Security log does not cover the requested $RequestedDays-day window on $($shortLogs.Count) DC(s)" `
            -Detail ("Older events have already been overwritten and cannot be recovered.`n" + ($lines -join "`n")) `
            -Action 'Increase the Security log maximum size to at least 1 GB on all DCs (Computer Configuration > Policies > Windows Settings > Event Log). Consider forwarding to a SIEM for durable retention.'
    }

    # --- Cross-forest account drift ----------------------------------------
    if ($Accounts.Count -gt 1) {
        $forests = @($Accounts | Select-Object -ExpandProperty Forest -Unique)
        if ($forests.Count -gt 1) {
            $detail = New-Object System.Collections.ArrayList
            foreach ($a in $Accounts) {
                $null = $detail.Add("$($a.Forest): $($a.User.SamAccountName) | password last set $(Format-AdTimestamp $a.User.pwdLastSet) | enabled=$($a.User.Enabled) | matched by $($a.MatchedBy)")
            }

            # Compare password-set times across forests. Divergence means the two
            # accounts hold different passwords - the classic multi-forest lockout cause.
            $setTimes = @()
            foreach ($a in $Accounts) {
                try {
                    $n = [int64]$a.User.pwdLastSet
                    if ($n -gt 0 -and $n -ne [int64]::MaxValue) { $setTimes += [datetime]::FromFileTime($n) }
                } catch { }
            }

            # Which forests show ANY sign of authentication activity against this account?
            # badPwdCount/badPasswordTime are the ground truth. An account with a stale
            # password that has NEVER received a bad password is dormant, not dangerous -
            # escalating it wastes the technician's time chasing a decoy.
            $liveForests = New-Object System.Collections.ArrayList
            foreach ($fname in $forests) {
                $ev = @($BadPwdStates | Where-Object {
                    $_.Forest -eq $fname -and $_.Reachable -and (
                        ($_.BadPwdCount -and [int]$_.BadPwdCount -gt 0) -or
                        ($_.BadPasswordTime -and [int64]$_.BadPasswordTime -gt 0)
                    )
                })
                if ($ev.Count -gt 0) { $null = $liveForests.Add($fname) }
            }

            $spread = 0
            if ($setTimes.Count -gt 1) {
                $spread = ([datetime]($setTimes | Measure-Object -Maximum).Maximum - [datetime]($setTimes | Measure-Object -Minimum).Minimum).TotalDays
            }

            $sev = 'Info'
            $extra = ''
            if ($spread -gt 1 -and $liveForests.Count -gt 1) {
                # Drift AND authentication activity in more than one forest: genuine.
                $sev = 'Critical'
                $extra = "`n`nPASSWORD DRIFT WITH ACTIVITY IN BOTH FORESTS: passwords were last set $([math]::Round($spread,1)) day(s) apart, and bad-password activity is present in more than one forest ($($liveForests -join ', ')). These accounts hold different passwords and both are being authenticated against."
            }
            elseif ($spread -gt 1) {
                # Drift but activity in only one place - the other account is dormant.
                $sev = 'Info'
                $dormant = @($forests | Where-Object { $liveForests -notcontains $_ })
                $extra = "`n`nPasswords were last set $([math]::Round($spread,1)) day(s) apart, BUT authentication activity is confined to $($liveForests -join ', '). The account(s) in $($dormant -join ', ') show badPwdCount 0 and no recorded bad-password time, so they are dormant and are NOT the lockout source. Note the stale password as hygiene, not as root cause."
            }
            else {
                $extra = "`n`nPasswords are in sync across forests; no drift detected."
            }

            Add-Finding -Severity $sev `
                -Title "This user has accounts in $($forests.Count) forests" `
                -Detail (($detail -join "`n") + $extra) `
                -Action 'Confirm which forest account is the live cloud identity (check Entra Connect OU scoping and the mail attribute) before changing anything. Only align passwords across forests if both accounts are genuinely in use.'
        }
    }

    # --- Per-DC bad password localisation ----------------------------------
    $hot = @($BadPwdStates | Where-Object { $_.Reachable -and $_.BadPwdCount -and [int]$_.BadPwdCount -gt 0 })
    if ($hot.Count -gt 0) {
        $lines = $hot | Sort-Object { [int]$_.BadPwdCount } -Descending | ForEach-Object {
            "$($_.Computer): badPwdCount=$($_.BadPwdCount), last bad password $(Format-AdTimestamp $_.BadPasswordTime)"
        }

        # Microsoft: "To get an accurate value for the user's total bad password attempts
        # in the domain, each domain controller in the domain must be queried and the sum
        # of the values should be used." Without the sum you cannot compare against the
        # lockout threshold, which is what decides whether the next attempt locks.
        # https://learn.microsoft.com/windows/win32/adschema/a-badpwdcount
        $totalBad = ($hot | ForEach-Object { [int]$_.BadPwdCount } | Measure-Object -Sum).Sum
        $thresholds = @($Topologies | Where-Object { $_.Policy } |
                          ForEach-Object { [int]$_.Policy.LockoutThreshold } | Where-Object { $_ -gt 0 })
        $threshText = ''
        if ($thresholds.Count -gt 0) {
            $minT = ($thresholds | Measure-Object -Minimum).Minimum
            $remaining = $minT - $totalBad
            $threshText = if ($remaining -le 0) {
                "`n`nDomain-wide total: $totalBad bad password(s) against a lockout threshold of $minT. The account is at or past the threshold - it is locking out right now."
            } else {
                "`n`nDomain-wide total: $totalBad bad password(s) against a lockout threshold of $minT - roughly $remaining more before the account locks. Note that these counters reset per DC on a successful logon and after the observation window, so this is a snapshot, not a running total."
            }
        } else {
            $threshText = "`n`nDomain-wide total: $totalBad bad password(s) across all reachable DCs."
        }

        Add-Finding -Severity 'Critical' `
            -Title 'Live bad-password counters found - these DCs are receiving the failed attempts' `
            -Detail ("badPwdCount is non-replicated, so a non-zero value proves the attempt was processed by that specific DC. This localises the problem even when auditing is disabled.`n" + ($lines -join "`n") + $threshText) `
            -Action 'Focus event collection and network tracing on the DC(s) listed above. If they are in a different forest than expected, that is your answer.'
    }

    $recent = @($BadPwdStates | Where-Object {
        $_.Reachable -and $_.BadPasswordTime -and ([int64]$_.BadPasswordTime) -gt 0
    })
    if ($recent.Count -gt 0 -and $EventsCollected) {
        $latest = ($recent | ForEach-Object { [datetime]::FromFileTime([int64]$_.BadPasswordTime) } | Measure-Object -Maximum).Maximum
        $failEvents = @($Events | Where-Object { $_.EventID -in @(4625, 4771, 4768, 4776) })

        # A recent bad-password timestamp with no matching failure event is the
        # signature of disabled auditing - retention cannot explain a gap of hours.
        if ($latest -gt (Get-Date).AddDays(-$RequestedDays) -and $failEvents.Count -eq 0) {
            Add-Finding -Severity 'Critical' `
                -Title 'Bad password recorded, but NO matching failure event exists' `
                -Detail "Active Directory recorded a bad password attempt at $($latest.ToString('yyyy-MM-dd HH:mm:ss')), which is inside the $RequestedDays-day search window, yet zero 4625/4771/4776 events were found on any DC. Log retention cannot explain this. The overwhelmingly likely cause is that failure auditing is disabled." `
                -Action 'Treat the audit policy finding above as the top priority. Until failure auditing is on, no lockout investigation in this environment can succeed.'
        }
    }

    # --- Source machine ranking - FAILURES ONLY ----------------------------
    # Scoped to Outcome 'Failure' so successful authentications are never presented as
    # the culprit.
    if ($Events.Count -gt 0) {
        $failures = @($Events | Where-Object { $_.CallerName -and $_.Outcome -eq 'Failure' })
        if ($failures.Count -gt 0) {
            $sources = $failures | Group-Object CallerName | Sort-Object Count -Descending | Select-Object -First 5
            $lines = $sources | ForEach-Object { "$($_.Name): $($_.Count) failed attempt(s)" }
            Add-Finding -Severity 'Critical' `
                -Title 'Sources of FAILED authentication' `
                -Detail ('These machines submitted bad passwords - usually where a stale cached credential, mapped drive, scheduled task or mobile device profile lives.' + "`n" + ($lines -join "`n")) `
                -Action 'On each: cmdkey /list for saved credentials, check services and scheduled tasks running as this user, check mapped drives, and clear the Credential Manager entry.'
        }
        else {
            $succ = @($Events | Where-Object { $_.Outcome -eq 'Success' })
            if ($succ.Count -gt 0) {
                Add-Finding -Severity 'Info' `
                    -Title "No FAILED authentications in the collected events ($($succ.Count) successful)" `
                    -Detail 'Every authentication event retrieved in this window succeeded. Combined with the audit gaps above, the failed attempts are almost certainly occurring via a vector that is not being logged - most commonly Kerberos (4771) when that subcategory is disabled.' `
                    -Action 'Close the audit gaps, then re-run after the next lockout.'
            }
        }

        # --- Authentication storm detection --------------------------------
        # A machine firing many authentications within seconds is a latent lockout bomb:
        # while the stored credential is valid these all succeed and look harmless, but
        # the moment it goes stale the burst blows straight through a low lockout
        # threshold before the user can react. This is worth flagging even when every
        # event in the burst succeeded.
        $storms = New-Object System.Collections.ArrayList
        foreach ($g in ($Events | Where-Object { $_.CallerName } | Group-Object CallerName)) {
            $times = @($g.Group | Select-Object -ExpandProperty Time | Sort-Object)
            $peak = 0
            $peakAt = $null
            for ($i = 0; $i -lt $times.Count; $i++) {
                $limit = $times[$i].AddSeconds(10)
                $inWindow = @($times | Where-Object { $_ -ge $times[$i] -and $_ -le $limit })
                if ($inWindow.Count -gt $peak) { $peak = $inWindow.Count; $peakAt = $times[$i] }
            }
            if ($peak -ge 5) {
                $null = $storms.Add([pscustomobject]@{ Source = $g.Name; Peak = $peak; At = $peakAt; Total = $times.Count })
            }
        }

        if ($storms.Count -gt 0) {
            $lines = $storms | Sort-Object Peak -Descending | ForEach-Object {
                "$($_.Source): $($_.Peak) authentication(s) within 10 seconds starting $($_.At.ToString('yyyy-MM-dd HH:mm:ss')) ($($_.Total) total in window)"
            }
            $thresholds = @($Topologies | Where-Object { $_.Policy } | ForEach-Object { [int]$_.Policy.LockoutThreshold } | Where-Object { $_ -gt 0 })
            $minT = 0
            if ($thresholds.Count -gt 0) { $minT = ($thresholds | Measure-Object -Minimum).Minimum }
            $risk = ''
            if ($minT -gt 0) {
                $risk = "`n`nWith a lockout threshold of $minT, a burst of this size exhausts the threshold in under a second the moment the stored credential becomes stale. The account would lock before the user finished typing."
            }
            Add-Finding -Severity 'Warning' `
                -Title 'Authentication storm detected - latent lockout risk' `
                -Detail ('One or more machines are firing repeated authentications for this account within seconds. Regardless of whether they currently succeed, this is the mechanism that turns a single stale credential into an instant lockout.' + "`n" + ($lines -join "`n") + $risk) `
                -Action 'Identify what on that machine is authenticating in a loop - mapped drives, Outlook/Exchange profile, a service or scheduled task, or a saved Credential Manager entry. Fix the loop as well as the credential.'
        }
    }
}
#endregion

#region ----------------------------------------------------------- Reporting

function New-HtmlReport {
    param(
        [string]$Path,
        [string]$Id,
        [int]$RequestedDays,
        [object[]]$Topologies,
        [object[]]$AuditResults,
        [object[]]$LogHealth,
        [object[]]$Accounts,
        [object[]]$BadPwdStates,
        [object[]]$Events,
        [bool]$EventsCollected
    )

    $sb = New-Object System.Text.StringBuilder
    $add = { param($t) $null = $sb.AppendLine($t) }


    # Shared stylesheet keeps all four reports consistent; minimal fallback if missing.
    $css = $null
    $refPath = Join-Path $PSScriptRoot 'LockoutReference.psd1'
    if (Test-Path -LiteralPath $refPath) {
        try { $css = (Import-PowerShellDataFile -Path $refPath -ErrorAction Stop).ReportCss } catch { $css = $null }
    }
    if (-not $css) {
        $css = @'
  body { background:#15181c; color:#e8eaed; font-family:'Segoe UI',system-ui,sans-serif;
         margin:0; padding:32px; max-width:1100px; margin-inline:auto; line-height:1.55; }
  .verdict { border-left:5px solid #e2686a; padding:4px 0 4px 20px; margin-bottom:26px; }
  .verdict .line { font-size:25px; font-weight:600; color:#fff; margin:0 0 12px; }
  .card { background:#1d2126; border:1px solid #333a44; border-radius:8px;
          padding:14px 18px; margin-bottom:10px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  td, th { padding:7px 10px; border-bottom:1px solid #242931; text-align:left; }
'@
    }

    & $add '<!DOCTYPE html>'
    & $add '<html lang="en">'
    & $add '<head>'
    & $add '<meta charset="utf-8">'
    & $add '<meta name="viewport" content="width=device-width, initial-scale=1">'
    & $add '<title>Lockout Forensics</title>'
    & $add "<style>$css</style>"
    & $add '</head>'
    & $add '<body>'

    $idText = if ($Id) { ConvertTo-SafeHtml $Id } else { 'Environment survey' }
    $forestList = ConvertTo-SafeHtml (($Topologies | Select-Object -ExpandProperty Forest) -join ', ')
    & $add '<div class="top">'
    & $add '  <h1>Lockout Forensics</h1>'
    & $add "  <div class=`"facts`"><span>Account <b>$idText</b></span><span>Last <b>$RequestedDays days</b></span><span>Forests <b>$forestList</b></span><span><b>$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))</b></span></div>"
    & $add '</div>'

    # --- Verdict: the highest-severity finding becomes the headline. ---
    $order = @{ Critical = 0; Warning = 1; Info = 2; Good = 3 }
    $sorted = @($script:Findings | Sort-Object { $order[$_.Severity] })

    if ($sorted.Count -eq 0) {
        & $add '<div class="verdict unknown"><div class="label">What this means</div>'
        & $add '<p class="line">Nothing conclusive was found.</p>'
        & $add '<p class="next">No findings were generated. If you expected evidence here, confirm the account name and that the domain controllers are reachable and auditing lockouts.</p></div>'
    }
    else {
        $lead = $sorted[0]
        $vClass = switch ($lead.Severity) { 'Critical' { 'bad' } 'Warning' { 'warn' } 'Good' { 'ok' } default { 'unknown' } }
        & $add "<div class=`"verdict $vClass`"><div class=`"label`">What this means</div>"
        & $add "<p class=`"line`">$(ConvertTo-SafeHtml $lead.Title)</p>"
        & $add "<p class=`"next`">$(ConvertTo-SafeHtml $lead.Detail)</p>"
        if ($lead.Action) {
            & $add "<p class=`"next`" style=`"margin-top:10px;`"><b>Do this:</b> $(ConvertTo-SafeHtml $lead.Action)</p>"
        }
        & $add '</div>'
    }

    # Headline counts
    $critCount = @($script:Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $warnCount = @($script:Findings | Where-Object { $_.Severity -eq 'Warning' }).Count
    $forestCount = @($Topologies).Count
    $critClass = if ($critCount -gt 0) { 'bad' } else { 'ok' }
    & $add '<div class="stats">'
    & $add "  <div class=`"stat`"><div class=`"n $critClass`">$critCount</div><div class=`"k`">Critical</div></div>"
    & $add "  <div class=`"stat`"><div class=`"n`">$warnCount</div><div class=`"k`">Warnings</div></div>"
    & $add "  <div class=`"stat`"><div class=`"n`">$forestCount</div><div class=`"k`">Forests</div></div>"
    & $add '</div>'

    # Remaining findings as cards, worst first. The lead one is already the verdict above.
    $rest = if ($sorted.Count -gt 1) { $sorted[1..($sorted.Count - 1)] } else { @() }
    if ($rest.Count -gt 0) {
        & $add '<h2>Other findings</h2>'
        foreach ($f in $rest) {
            $cls = switch ($f.Severity) { 'Critical' { 'bad' } 'Good' { 'ok' } default { '' } }
            $tag = switch ($f.Severity) { 'Critical' { 'bad' } 'Warning' { 'warn' } 'Good' { 'ok' } default { '' } }
            & $add "<article class=`"card $cls`">"
            & $add "  <div class=`"card-head`"><span class=`"card-name`">$(ConvertTo-SafeHtml $f.Title)</span><span class=`"tag $tag`">$($f.Severity)</span></div>"
            & $add "  <p style=`"color:var(--ink-dim);font-size:13.5px;margin:8px 0 0;white-space:pre-wrap;`">$(ConvertTo-SafeHtml $f.Detail)</p>"
            if ($f.Action) {
                & $add "  <p style=`"color:var(--ink);font-size:13.5px;margin:8px 0 0;`"><b>Do this:</b> $(ConvertTo-SafeHtml $f.Action)</p>"
            }
            & $add '</article>'
        }
    }
    # Forest topology
    & $add '<details><summary>Forest topology and lockout policy</summary><div class="tablewrap">'
    & $add '<table><thead><tr><th>Forest</th><th>Status</th><th>PDC Emulator</th><th>DCs</th><th>Threshold</th><th>Observation</th><th>Duration</th></tr></thead><tbody>'
    foreach ($t in $Topologies) {
        if ($t.Reachable) {
            $th = if ($t.Policy) { $t.Policy.LockoutThreshold } else { '?' }
            $ow = if ($t.Policy) { $t.Policy.LockoutObservationWindow } else { '?' }
            $du = if ($t.Policy) { $t.Policy.LockoutDuration } else { '?' }
            $thCls = if ($t.Policy -and $t.Policy.LockoutThreshold -gt 0 -and $t.Policy.LockoutThreshold -le 5) { ' class="bad"' } else { '' }
            & $add "<tr><td>$(ConvertTo-SafeHtml $t.Forest)</td><td class=`"ok`">Reachable</td><td>$(ConvertTo-SafeHtml $t.PDCEmulator)</td><td>$($t.DomainControllers.Count)</td><td$thCls>$th</td><td>$ow</td><td>$du</td></tr>"
        }
        else {
            & $add "<tr><td>$(ConvertTo-SafeHtml $t.Forest)</td><td class=`"bad`">Unreachable</td><td colspan=`"5`">$(ConvertTo-SafeHtml $t.Error)</td></tr>"
        }
    }
    & $add '</tbody></table></div></details>'

    # Audit policy
    & $add '<details><summary>Audit policy per domain controller</summary><div class="tablewrap">'
    & $add '<p class="meta">If Failure auditing is missing below, the Security log physically cannot contain the evidence a lockout investigation depends on.</p>'
    if ($AuditResults.Count -eq 0) {
        & $add '<p class="empty">No audit policy data collected.</p>'
    }
    else {
        & $add '<table><thead><tr><th>Domain Controller</th>'
        foreach ($k in $script:AuditSubcategories.Keys) { & $add "<th>$(ConvertTo-SafeHtml $k)</th>" }
        & $add '</tr></thead><tbody>'
        foreach ($a in $AuditResults) {
            & $add "<tr><td>$(ConvertTo-SafeHtml $a.Computer)</td>"
            if (-not $a.Queried) {
                & $add "<td colspan=`"$($script:AuditSubcategories.Count)`" class=`"bad`">Not readable - $(ConvertTo-SafeHtml $a.Error)</td>"
            }
            else {
                foreach ($k in $script:AuditSubcategories.Keys) {
                    $v = if ($a.Settings.ContainsKey($k)) { $a.Settings[$k] } else { 'Unknown' }
                    $need = if ($script:NeedsFailure -contains $k) { 'Failure' } else { 'Success' }
                    $cls = if ($v -match $need) { 'ok' } else { 'bad' }
                    & $add "<td class=`"$cls`">$(ConvertTo-SafeHtml $v)</td>"
                }
            }
            & $add '</tr>'
        }
        & $add '</tbody></table>'
        & $add '<h3>What each subcategory captures</h3><table><thead><tr><th>Subcategory</th><th>Events</th><th>Why it matters</th></tr></thead><tbody>'
        foreach ($k in $script:AuditSubcategories.Keys) {
            & $add "<tr><td>$(ConvertTo-SafeHtml $k)</td><td>$(ConvertTo-SafeHtml $script:AuditSubcategories[$k].Events)</td><td>$(ConvertTo-SafeHtml $script:AuditSubcategories[$k].Why)</td></tr>"
        }
        & $add '</tbody></table>'
    }
    & $add '</div></details>'

    # Log health
    & $add '<details><summary>Security log coverage per domain controller</summary><div class="tablewrap">'
    if ($LogHealth.Count -eq 0) {
        & $add '<p class="empty">No log health data collected.</p>'
    }
    else {
        & $add '<table><thead><tr><th>Domain Controller</th><th>Max Size</th><th>Current</th><th>Mode</th><th>Records</th><th>Oldest Event</th><th>Actual Coverage</th></tr></thead><tbody>'
        foreach ($l in $LogHealth) {
            if (-not $l.Reachable) {
                & $add "<tr><td>$(ConvertTo-SafeHtml $l.Computer)</td><td colspan=`"6`" class=`"bad`">$(ConvertTo-SafeHtml $l.Error)</td></tr>"
                continue
            }
            $cls = if ($l.CoversWindow) { 'ok' } else { 'bad' }
            $oldest = if ($l.OldestEvent) { $l.OldestEvent.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Unknown' }
            & $add "<tr><td>$(ConvertTo-SafeHtml $l.Computer)</td><td>$($l.MaxSizeMB) MB</td><td>$($l.CurrentSizeMB) MB</td><td>$(ConvertTo-SafeHtml $l.LogMode)</td><td>$($l.RecordCount)</td><td>$oldest</td><td class=`"$cls`">$($l.CoverageDays) day(s)</td></tr>"
        }
        & $add '</tbody></table>'
    }
    & $add '</div></details>'

    # Accounts
    if ($Accounts.Count -gt 0) {
        & $add '<details><summary>Linked accounts across forests</summary><div class="tablewrap">'
        & $add '<table><thead><tr><th>Forest</th><th>sAMAccountName</th><th>UPN</th><th>Mail</th><th>Enabled</th><th>Locked</th><th>Password Last Set</th><th>Matched By</th></tr></thead><tbody>'
        foreach ($a in $Accounts) {
            $lk = if ($a.User.LockedOut) { '<span class="bad">Yes</span>' } else { 'No' }
            & $add "<tr><td>$(ConvertTo-SafeHtml $a.Forest)</td><td>$(ConvertTo-SafeHtml $a.User.SamAccountName)</td><td>$(ConvertTo-SafeHtml $a.User.UserPrincipalName)</td><td>$(ConvertTo-SafeHtml $a.User.mail)</td><td>$($a.User.Enabled)</td><td>$lk</td><td>$(Format-AdTimestamp $a.User.pwdLastSet)</td><td>$(ConvertTo-SafeHtml $a.MatchedBy)</td></tr>"
        }
        & $add '</tbody></table>'
        & $add '<h3>Distinguished Names</h3><table><tbody>'
        foreach ($a in $Accounts) {
            & $add "<tr><th>$(ConvertTo-SafeHtml $a.Forest)</th><td>$(ConvertTo-SafeHtml $a.User.DistinguishedName)</td></tr>"
        }
        & $add '</tbody></table></div></details>'
    }

    # Per-DC bad password state
    if ($BadPwdStates.Count -gt 0) {
        & $add '<details open><summary>Per-DC bad password counters</summary><div class="tablewrap">'
        & $add '<p class="meta">badPwdCount and badPasswordTime are non-replicated - each DC holds only what it personally processed. A non-zero value proves that specific DC received the failed attempt. This works even when auditing is disabled.</p>'
        & $add '<table><thead><tr><th>Domain Controller</th><th>badPwdCount</th><th>Last Bad Password</th><th>Lockout Time</th><th>Password Last Set</th></tr></thead><tbody>'
        foreach ($b in ($BadPwdStates | Sort-Object @{ E = { if ($_.BadPwdCount) { [int]$_.BadPwdCount } else { 0 } }; Descending = $true })) {
            if (-not $b.Reachable) {
                & $add "<tr><td>$(ConvertTo-SafeHtml $b.Computer)</td><td colspan=`"4`" class=`"bad`">$(ConvertTo-SafeHtml $b.Error)</td></tr>"
                continue
            }
            $cnt = if ($null -ne $b.BadPwdCount) { [int]$b.BadPwdCount } else { 0 }
            $cls = if ($cnt -gt 0) { ' class="bad"' } else { '' }
            & $add "<tr><td>$(ConvertTo-SafeHtml $b.Computer)</td><td$cls>$cnt</td><td>$(Format-AdTimestamp $b.BadPasswordTime)</td><td>$(Format-AdTimestamp $b.LockoutTime)</td><td>$(Format-AdTimestamp $b.PwdLastSet)</td></tr>"
        }
        & $add '</tbody></table></div></details>'
    }

    # Events
    & $add '<details><summary>Security events collected</summary><div class="tablewrap">'
    if (-not $EventsCollected) {
        & $add '<p class="empty">Event collection was skipped (-SkipEventCollection).</p>'
    }
    elseif ($Events.Count -eq 0) {
        & $add '<p class="empty">No lockout-related events found in the search window. Check the audit policy and log coverage sections above before concluding this is a genuine result.</p>'
    }
    else {
        & $add "<p class=`"meta`">$($Events.Count) event(s) collected across all forests.</p>"
        $failCount = @($Events | Where-Object { $_.Outcome -eq 'Failure' }).Count
        $succCount = @($Events | Where-Object { $_.Outcome -eq 'Success' }).Count
        & $add "<p class=`"meta`">Breakdown: <b>$failCount</b> failure(s), <b>$succCount</b> success(es). A status of 0x0 means the authentication SUCCEEDED - 4776/4771/4768 are logged for both outcomes.</p>"
        & $add '<table><thead><tr><th>Time</th><th>Forest</th><th>DC</th><th>Event</th><th>Meaning</th><th>Outcome</th><th>Account</th><th>Source</th><th>IP</th><th>Status</th></tr></thead><tbody>'
        foreach ($e in ($Events | Sort-Object Time -Descending)) {
            $st = $e.StatusCode
            if ($e.StatusText) { $st = "$($e.StatusCode) - $($e.StatusText)" }
            $oc = 'ok'
            if ($e.Outcome -eq 'Failure' -or $e.Outcome -eq 'Lockout') { $oc = 'bad' }
            & $add "<tr><td>$($e.Time.ToString('yyyy-MM-dd HH:mm:ss'))</td><td>$(ConvertTo-SafeHtml $e.Forest)</td><td>$(ConvertTo-SafeHtml $e.DC)</td><td>$($e.EventID)</td><td>$(ConvertTo-SafeHtml $e.Meaning)</td><td class=`"$oc`">$(ConvertTo-SafeHtml $e.Outcome)</td><td>$(ConvertTo-SafeHtml $e.Account)</td><td>$(ConvertTo-SafeHtml $e.CallerName)</td><td>$(ConvertTo-SafeHtml $e.IPAddress)</td><td>$(ConvertTo-SafeHtml $st)</td></tr>"
        }
        & $add '</tbody></table>'
    }
    & $add '</div></details>'

    & $add @'
<footer>
  Read-only collection - no Active Directory objects were modified.<br>
  References:
  <a href="https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740">4740</a> |
  <a href="https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625">4625</a> |
  <a href="https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4771">4771</a> |
  <a href="https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4776">4776</a> |
  <a href="https://learn.microsoft.com/windows/win32/adschema/a-badpwdcount">badPwdCount is non-replicated</a> |
  <a href="https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/account-lockout-threshold">Lockout threshold guidance</a>
</footer>
</body>
</html>
'@

    $sb.ToString() | Out-File -FilePath $Path -Encoding UTF8
}
#endregion

#region ----------------------------------------------------------- Main

# Tests dot-source this script to load the pure helpers without running the collection.
if ($LoadFunctionsOnly) { return }

Write-Host ''
Write-Host '  AD Lockout Forensics - multi-forest' -ForegroundColor Cyan
Write-Host '  ----------------------------------' -ForegroundColor Cyan
Write-Host ''

# Runtime import rather than "#Requires -Modules ActiveDirectory": the #Requires
# directive refuses to start the script when the module is not in a standard path, which
# is common on servers where the RSAT cmdlets work but are not formally registered.
try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Step "Could not load the ActiveDirectory module (RSAT). $($_.Exception.Message)" -Level Error
    Write-Step "Install with: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -Level Info
    exit 1
}

# Default the output folder to a Reports folder beside this script (resolved from
# $PSScriptRoot, not the caller's working directory) so every tool in this folder writes
# to the same place. Falls back to the current directory when $PSScriptRoot is empty.
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $scriptRoot   = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $OutputFolder = Join-Path $scriptRoot 'Reports'
}

if (-not (Test-Path -LiteralPath $OutputFolder)) {
    $null = New-Item -Path $OutputFolder -ItemType Directory -Force
}

$startTime = (Get-Date).AddDays(-$DaysBack)

# 1. Forests -----------------------------------------------------------------
$targetForests = Resolve-TargetForest -Explicit $Forest
if ($targetForests.Count -eq 0) { throw 'No forests to interrogate.' }

$topologies = New-Object System.Collections.ArrayList
foreach ($f in $targetForests) {
    $null = $topologies.Add((Get-ForestTopology -ForestName $f))
}

$reachable = @($topologies | Where-Object { $_.Reachable })
if ($reachable.Count -eq 0) { throw 'No forests could be contacted. Check credentials and connectivity.' }

if ($reachable.Count -gt 1) {
    Add-Finding -Severity 'Info' `
        -Title "Multi-forest environment: $($reachable.Count) forests interrogated" `
        -Detail (($reachable | ForEach-Object { "$($_.Forest) - $($_.DomainControllers.Count) DC(s), PDC $($_.PDCEmulator)" }) -join "`n") `
        -Action 'Single-forest lockout tooling will miss evidence in this environment. Always collect from every forest.'
}

# 2. DC health ---------------------------------------------------------------
$auditResults = New-Object System.Collections.ArrayList
$logHealth    = New-Object System.Collections.ArrayList

foreach ($topo in $reachable) {
    foreach ($dc in $topo.DomainControllers) {
        Write-Step "Checking audit policy on $dc ..."
        $null = $auditResults.Add((Get-DCAuditPolicy -ComputerName $dc -ForestName $topo.Forest))

        Write-Step "Checking Security log coverage on $dc ..."
        $null = $logHealth.Add((Get-DCLogHealth -ComputerName $dc -ForestName $topo.Forest -RequestedDays $DaysBack))
    }
}

# 3. Account resolution ------------------------------------------------------
$accounts     = New-Object System.Collections.ArrayList
$badPwdStates = New-Object System.Collections.ArrayList

if ($Identity) {
    Write-Step "Resolving '$Identity' across all forests ..."
    $found = Find-AccountAcrossForests -Id $Identity -Topologies $reachable
    foreach ($a in $found) { $null = $accounts.Add($a) }

    if ($accounts.Count -eq 0) {
        Add-Finding -Severity 'Critical' `
            -Title "Account '$Identity' not found in any forest" `
            -Detail 'Tried sAMAccountName, userPrincipalName, mail and proxyAddresses in every reachable forest.' `
            -Action 'Verify the identifier, or supply credentials for forests that returned access errors.'
    }
    else {
        # Poll every DC in the forest(s) where the account exists.
        foreach ($a in $accounts) {
            $topo = $reachable | Where-Object { $_.Forest -eq $a.Forest } | Select-Object -First 1
            if (-not $topo) { continue }
            foreach ($dc in $topo.DomainControllers) {
                Write-Step "Polling bad password counters on $dc for $($a.User.SamAccountName) ..."
                $null = $badPwdStates.Add((Get-PerDCBadPasswordState -ComputerName $dc -SamAccountName $a.User.SamAccountName -ForestName $a.Forest))
            }
        }
    }
}
else {
    Write-Step 'No -Identity supplied - running environment survey only.' -Level Warn
}

# 4. Events ------------------------------------------------------------------
$events = New-Object System.Collections.ArrayList

if (-not $SkipEventCollection) {
    foreach ($topo in $reachable) {
        # Filter events to the account in THIS forest - sAMAccountName may differ
        # between forests for the same human.
        $sam = ''
        $acct = $accounts | Where-Object { $_.Forest -eq $topo.Forest } | Select-Object -First 1
        if ($acct) { $sam = $acct.User.SamAccountName }

        foreach ($dc in $topo.DomainControllers) {
            Write-Step "Collecting events from $dc (last $DaysBack day(s)) ..."
            $found = Get-LockoutEvents -ComputerName $dc -ForestName $topo.Forest -SamAccountName $sam -StartTime $startTime
            foreach ($e in $found) { $null = $events.Add($e) }
        }
    }
    Write-Step "Collected $($events.Count) event(s)." -Level Ok
}
else {
    Write-Step 'Event collection skipped.' -Level Warn
}

# 5. Analysis ----------------------------------------------------------------
Write-Step 'Analysing ...'
Invoke-Analysis -Topologies $reachable -AuditResults $auditResults -LogHealth $logHealth `
                -Accounts $accounts -BadPwdStates $badPwdStates -Events $events `
                -RequestedDays $DaysBack -EventsCollected (-not $SkipEventCollection)

# 6. Output ------------------------------------------------------------------
$stamp    = (Get-Date).ToString('yyyyMMdd-HHmmss')
$slug     = if ($Identity) { ($Identity -replace '[^a-zA-Z0-9._-]', '_') } else { 'survey' }
$htmlPath = Join-Path $OutputFolder "ADLockoutForensics_${slug}_$stamp.html"

New-HtmlReport -Path $htmlPath -Id $Identity -RequestedDays $DaysBack `
               -Topologies $topologies -AuditResults $auditResults -LogHealth $logHealth `
               -Accounts $accounts -BadPwdStates $badPwdStates -Events $events `
               -EventsCollected (-not $SkipEventCollection)

if ($events.Count -gt 0) {
    $csvPath = Join-Path $OutputFolder "ADLockoutForensics_${slug}_$stamp`_events.csv"
    $events | Sort-Object Time -Descending | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Step "Events CSV: $csvPath" -Level Ok
}

if ($badPwdStates.Count -gt 0) {
    $bpPath = Join-Path $OutputFolder "ADLockoutForensics_${slug}_$stamp`_perdc.csv"
    $badPwdStates | Export-Csv -Path $bpPath -NoTypeInformation -Encoding UTF8
    Write-Step "Per-DC counters CSV: $bpPath" -Level Ok
}

Write-Host ''
Write-Step "Report: $htmlPath" -Level Ok
Write-Host ''

# Console summary so the answer is visible without opening the report.
Write-Host '  FINDINGS' -ForegroundColor Cyan
foreach ($f in ($script:Findings | Sort-Object { @{ Critical = 0; Warning = 1; Info = 2; Good = 3 }[$_.Severity] })) {
    $color = switch ($f.Severity) {
        'Critical' { 'Red' }
        'Warning'  { 'Yellow' }
        'Good'     { 'Green' }
        default    { 'Gray' }
    }
    Write-Host "  [$($f.Severity.ToUpper())] $($f.Title)" -ForegroundColor $color
}
Write-Host ''

#endregion


