# 3.0 so this runs on Server 2012 (PS 3.0) / 2012 R2 (PS 4.0) as shipped; Tests\PSVersionFloor.Tests.ps1 guards it.
#Requires -Version 3.0

<#
.SYNOPSIS
    "I can't log in" - answers in plain English whether an Active Directory user can sign in right now, and why not.
.DESCRIPTION
    Built for the service desk, on the phone with a user. The first line of output is the answer:

        Can Jane Doe sign in right now?  YES / NO / PROBABLY NOT

    Each reason follows, with a one-line "What to do" next step. A compact detail table
    follows for sysadmins. The tool is READ-ONLY: it reads directory attributes and changes
    nothing.

    WHAT IT CHECKS

      1. Account turned off (disabled)
      2. Locked out RIGHT NOW (asked of the PDC emulator), and when it unlocks by itself
      3. Wrong-password counts on EVERY domain controller, and how close to lockout
      4. Account expiry date
      5. Password: must change at next sign-in, expired, expires soon
      6. Last sign-in (newest across every DC) and which DC saw it
      7. Limits on where/when they can sign in: allowed computers, sign-in hours, smart card
      8. Group count (direct, and total including nested) - very large counts can break Kerberos
      9. Who the account is: name, UPN, mail, department, title, manager, OU, dates

    VERDICT
      NO            account disabled, locked out, account expired, password expired, or the user
                    must set a new password at next sign-in
      PROBABLY NOT  sign-in is limited to certain computers / hours, or needs a smart card
      YES           none of the above (warnings are still listed)

    Domain controllers that cannot be reached are reported as a WARNING and never as clean:
    bad-password counts and last-logon are kept per DC, so a missing DC means incomplete data.

    WHAT THIS DOES NOT CHECK: cloud sign-in (Entra ID / Microsoft 365), MFA, Conditional
    Access, or the user's device. See Get-EntraPasswordPolicy for cloud password expiry.
.PARAMETER Identity
    The user: sAMAccountName, UserPrincipalName, DistinguishedName, or (as a fallback) a
    display name. If a name search finds no one or more than one person, the candidates are
    listed and the tool exits with code 2 rather than guessing.
.PARAMETER Server
    Optional domain controller or domain to run the lookup against.
.PARAMETER Credential
    Optional credential for the directory queries.
.PARAMETER DomainController
    Optional list of DCs to check instead of discovering every DC in the domain.
.PARAMETER OutputPath
    Optional folder. When given, an HTML report and a one-row CSV named
    UserQuickCheck_<sam>_<yyyy-MM-dd_HHmmss> are written there. When omitted the tool is
    console-only. With -TicketNumber, this is the folder that holds Ticket_<number>.
.PARAMETER TicketNumber
    Optional ticket number (letters, digits, - or _, up to 32 characters). The HTML, the CSV and
    the ticket note are saved in <root>\Ticket_<number>, where root is -OutputPath if given,
    else %USERPROFILE%\Documents\TicketNotes. TicketNote\Join-TicketNotes.ps1 later joins
    every tool's note in that folder into one. A number that does not fit is refused with a
    [FAIL] line and exit code 3, before anything is checked.
.PARAMETER NoClipboard
    Do not copy the ticket note to the clipboard. Without it the note goes to the clipboard,
    where it can enter clipboard history (Win+V) or the cloud clipboard on Windows PowerShell
    5.0 and later, and travels over RDP clipboard redirection.
.PARAMETER FullDetail
    Keep IP addresses and share paths in the ticket note. By default the note is paste-safe:
    they are replaced by [IP removed] / [share path removed]. The question at the top is
    never changed.
.PARAMETER PassThru
    Return the result object (Status, ExitCode, Identity, Message, Candidates, MatchedBy, Facts,
    Assessment, Now, TicketNote) instead of setting an exit code.
.PARAMETER Quiet
    Do not write the console report. Combine with -PassThru or -OutputPath. Also leaves the
    clipboard alone, because another script is the caller.
.PARAMETER LoadFunctionsOnly
    Define the functions and return without running a check (used by the tests).
.EXAMPLE
    .\Get-ADUserQuickCheck.ps1 -Identity jdoe
    Answer "can jdoe sign in?" on the console.
.EXAMPLE
    .\Get-ADUserQuickCheck.ps1 -Identity jane.doe@contoso.com -OutputPath C:\Temp
    Same, and save an HTML report and a CSV row for the ticket.
.EXAMPLE
    .\Get-ADUserQuickCheck.ps1 -Identity "Jane Doe" -DomainController DC01,DC02
    Find by display name and check only two DCs.
.EXAMPLE
    .\Get-ADUserQuickCheck.ps1 -Identity jdoe -TicketNumber 482113
    Same answer; the HTML, the CSV and the ticket note go into
    %USERPROFILE%\Documents\TicketNotes\Ticket_482113, and the note is copied to the clipboard.
.NOTES
    Exit codes (without -PassThru): 0 = can sign in, 1 = cannot / probably not, 2 = user not
    found or ambiguous, 3 = could not run (ActiveDirectory module missing, connectivity
    failure, or an unusable -TicketNumber).

    TICKET NOTE. Every run ends with a four-part note (Checked, Ruled out, Could not check,
    Next step) copied to the clipboard. It is also saved as Note_<time>_AD-UserQuickCheck.txt
    when -TicketNumber or -OutputPath is given. A check is only "Ruled out" when it could
    really be made: with a domain controller unreachable, "no wrong passwords" is listed under
    "Could not check", and so is "not locked out" when the PDC emulator could not be read.
    The note is built by CaseKit.ps1 in this folder (a copy of TicketNote\CaseKit.ps1). If it
    is missing the check still runs, without a note.

    Needs the ActiveDirectory (RSAT) module and permission to read user attributes. Domain
    Users can normally read everything used here.

    Companion tools: AD-LockoutDiagnostics (why does it keep locking), Get-EntraPasswordPolicy
    (cloud password expiry).

    REFERENCES
      userAccountControl flags (ACCOUNTDISABLE 0x2, PASSWD_NOTREQD 0x20, DONT_EXPIRE_PASSWD 0x10000, SMARTCARD_REQUIRED 0x40000)
        https://learn.microsoft.com/windows/win32/adschema/a-useraccountcontrol
      msDS-User-Account-Control-Computed (constructed; UF_LOCKOUT 0x10, UF_PASSWORD_EXPIRED 0x800000)
        https://learn.microsoft.com/windows/win32/adschema/a-msds-user-account-control-computed
      lockoutTime - zero = not locked; may be non-zero while not locked (lockout duration expired)
        https://learn.microsoft.com/windows/win32/adschema/a-lockouttime
      Account lockout duration - 0 = locked until an administrator unlocks it
        https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/account-lockout-duration
      badPwdCount / badPasswordTime - NOT replicated, kept per DC
        https://learn.microsoft.com/windows/win32/adschema/a-badpwdcount
        https://learn.microsoft.com/windows/win32/adschema/a-badpasswordtime
      accountExpires - 0 and 0x7FFFFFFFFFFFFFFF both mean never
        https://learn.microsoft.com/windows/win32/adschema/a-accountexpires
      pwdLastSet - 0 without DONT_EXPIRE_PASSWD = must change password at next logon
        https://learn.microsoft.com/windows/win32/adschema/a-pwdlastset
      msDS-UserPasswordExpiryTimeComputed - 0x7FFFFFFFFFFFFFFF when smart card required / password never expires /
      max password age 0; 0 when pwdLastSet is 0 or null; otherwise pwdLastSet + effective max password age (honours PSOs)
        https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/f9e9b7e2-c7ac-4db6-ba38-71d9696981e9
        https://learn.microsoft.com/windows/win32/adschema/a-msds-userpasswordexpirytimecomputed
      lastLogon - NOT replicated; the largest value across all DCs is the true last logon
        https://learn.microsoft.com/windows/win32/adschema/a-lastlogon
      lastLogonTimestamp / msDS-LogonTimeSyncInterval - only updated when older than the sync interval
        https://learn.microsoft.com/windows/win32/adschema/a-lastlogontimestamp
        https://learn.microsoft.com/windows/win32/adschema/a-msds-logontimesyncinterval
      userWorkstations - Microsoft advises against using it; Allow/Deny log on locally is preferred
        https://learn.microsoft.com/windows/win32/adschema/a-userworkstations
      logonHours
        https://learn.microsoft.com/windows/win32/adschema/a-logonhours
      tokenGroups - constructed, BASE-scope query only, expensive on DCs (read once, from the PDC emulator)
        https://learn.microsoft.com/windows/win32/adschema/a-tokengroups
      Kerberos token size (MaxTokenSize 48,000 bytes on Server 2012+; "more than 120 universal groups" guidance)
        https://learn.microsoft.com/troubleshoot/windows-server/windows-security/kerberos-authentication-problems-if-user-belongs-to-groups
      Get-ADUserResultantPasswordPolicy (msDS-ResultantPSO); LockoutDuration is a TimeSpan
        https://learn.microsoft.com/powershell/module/activedirectory/get-aduserresultantpasswordpolicy
      Get-ADDefaultDomainPasswordPolicy, Get-ADDomain (PDCEmulator), Get-ADUser -Properties
        https://learn.microsoft.com/powershell/module/activedirectory/get-addefaultdomainpasswordpolicy
        https://learn.microsoft.com/powershell/module/activedirectory/get-addomain
        https://learn.microsoft.com/powershell/module/activedirectory/get-aduser
      Ticket note clipboard (in CaseKit.ps1): Set-Clipboard is 5.0, so it is used behind a
      Get-Command check with a WinForms fallback; STA is the default since 3.0; never clip.exe,
      because $OutputEncoding is ASCII in 5.1 and would mangle non-ASCII names
        https://learn.microsoft.com/powershell/scripting/whats-new/what-s-new-in-windows-powershell-50
        https://learn.microsoft.com/powershell/module/microsoft.powershell.management/set-clipboard?view=powershell-5.1
        https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1
        https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-5.1
      Clipboard history / cloud clipboard opt-out formats (CanIncludeInClipboardHistory,
      CanUploadToCloudClipboard; set by the kit's WinForms path, not by Set-Clipboard)
        https://learn.microsoft.com/windows/win32/dataxchg/clipboard-formats

    NOT VERIFIED ON LEARN: that msDS-LogonTimeSyncInterval defaults to 14 days. The
    lastLogonTimestamp page documents "14 days minus random percentage of 5 days" only for
    the initial update after a functional-level raise; the wording shown to the user is
    therefore "up to about 14 days by default".
#>
[CmdletBinding(DefaultParameterSetName = 'Check')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Check', Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Identity,

    [string]$Server,

    [System.Management.Automation.PSCredential]$Credential,

    [string[]]$DomainController,

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

# --- Documented constants ------------------------------------------------------------------
# userAccountControl flags: https://learn.microsoft.com/windows/win32/adschema/a-useraccountcontrol
$script:UF_ACCOUNTDISABLE     = 0x2
$script:UF_PASSWD_NOTREQD     = 0x20
$script:UF_DONT_EXPIRE_PASSWD = 0x10000
$script:UF_SMARTCARD_REQUIRED = 0x40000
# msDS-User-Account-Control-Computed bits (constructed, not stored; the lockout bit already
# accounts for the lockout duration having run out):
# https://learn.microsoft.com/windows/win32/adschema/a-msds-user-account-control-computed
$script:UF_LOCKOUT          = 0x10
$script:UF_PASSWORD_EXPIRED = 0x800000

# Large-integer "never": accountExpires 0 or 0x7FFFFFFFFFFFFFFF (a-accountexpires);
# msDS-UserPasswordExpiryTimeComputed 0x7FFFFFFFFFFFFFFF = never expires, 0 = must change (MS-ADTS 3.1.1.4.5.33).
# Same sentinels as NeverSentinels in AD-LockoutDiagnostics\LockoutReference.psd1.
$script:FileTimeNever = [int64]::MaxValue

$script:AccountExpiryWarnDays  = 7
$script:PasswordExpiryWarnDays = 14
# Learn (Kerberos token size): "if the user belongs to more than 120 universal groups, the
# default MaxTokenSize value does not create a large enough buffer". Used as a WARN-only
# early signal on the total (nested) group count, never as a blocker.
$script:TokenBloatWarnGroups = 120

# A display-name search returns at most this many people (Get-ADUser -ResultSetSize); when it
# is reached there may be more, so the ticket note says "25 or more".
$script:NameSearchLimit = 25
# The ticket note lists this many of an ambiguous search's candidates, then "...and N more".
$script:NoteCandidateLimit = 5

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

function ConvertFrom-AdFileTime {
    <#
    .SYNOPSIS
        Converts an AD large-integer time (FILETIME) to a local DateTime, or $null for "never"/"unknown".
    .DESCRIPTION
        0 and Int64.MaxValue are sentinels, not 1601-01-01 / year 30828, and
        [datetime]::FromFileTime(Int64.MaxValue) throws, so every caller goes through here.
        https://learn.microsoft.com/windows/win32/adschema/a-accountexpires
        https://learn.microsoft.com/windows/win32/adschema/a-lockouttime
    #>
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }
    $n = [int64]0
    try { $n = [int64]$Value } catch { return $null }
    if ($n -le 0 -or $n -ge [int64]::MaxValue) { return $null }
    try { return [datetime]::FromFileTime($n) } catch { return $null }
}

function ConvertTo-LdapFilterValue {
    # RFC 4515 escaping so a name containing ( ) * \ cannot change the filter.
    param([string]$Value)
    $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
}

function Get-AdSplat {
    param([string]$Server, [System.Management.Automation.PSCredential]$Credential)
    $h = @{}
    if ($Server) { $h['Server'] = $Server }
    if ($Credential) { $h['Credential'] = $Credential }
    return $h
}

function Format-When {
    # "2026-10-16 09:30 (in 3 days)" / "(2 hours ago)"
    param([object]$When, [datetime]$Now = (Get-Date))
    if ($null -eq $When) { return 'never / not recorded' }
    $span = $When - $Now
    $abs = [math]::Abs($span.TotalMinutes)
    if ($abs -lt 1) { $rel = 'just now' }
    else {
        if ($abs -lt 90) { $n = [int][math]::Round($abs); $unit = 'minute' }
        elseif ($abs -lt 2880) { $n = [int][math]::Round($abs / 60); $unit = 'hour' }
        else { $n = [int][math]::Floor($abs / 1440); $unit = 'day' }
        $u = if ($n -eq 1) { $unit } else { "${unit}s" }
        $rel = if ($span.TotalMinutes -gt 0) { "in $n $u" } else { "$n $u ago" }
    }
    return ('{0} ({1})' -f $When.ToString('yyyy-MM-dd HH:mm'), $rel)
}

function Get-DomainDnsFromDn {
    param([string]$DistinguishedName)
    $parts = @(($DistinguishedName -split '(?<!\\),') | Where-Object { $_ -match '^\s*DC=' } | ForEach-Object { ($_ -replace '^\s*DC=', '').Trim() })
    return ($parts -join '.')
}

function Get-ParentContainer {
    param([string]$DistinguishedName)
    $i = 0
    while ($true) {
        $i = $DistinguishedName.IndexOf(',', $i)
        if ($i -lt 0) { return '' }
        if ($i -gt 0 -and $DistinguishedName[$i - 1] -eq '\') { $i++; continue }
        return $DistinguishedName.Substring($i + 1)
    }
}

# =============================================================================
# Pure interpretation (no AD calls - unit tested directly)
# =============================================================================

function Get-AccountExpiryState {
    <#
    .SYNOPSIS
        accountExpires -> Never / date / expired.
    .DESCRIPTION
        0 and 0x7FFFFFFFFFFFFFFF both mean the account never expires.
        https://learn.microsoft.com/windows/win32/adschema/a-accountexpires
    #>
    param([object]$AccountExpires, [datetime]$Now = (Get-Date))
    $when = ConvertFrom-AdFileTime -Value $AccountExpires
    $never = ($null -eq $when)
    $expired = $false
    $days = $null
    if (-not $never) {
        $expired = ($when -le $Now)
        $days = [math]::Floor(($when - $Now).TotalDays)
    }
    return [PSCustomObject]@{ Never = $never; Expires = $when; Expired = $expired; DaysLeft = $days }
}

function Get-PasswordState {
    <#
    .SYNOPSIS
        pwdLastSet / msDS-UserPasswordExpiryTimeComputed / UF bits -> must-change, expired, expiry date.
    .DESCRIPTION
        pwdLastSet 0 without DONT_EXPIRE_PASSWD = must change at next logon (a-pwdlastset).
        msDS-UserPasswordExpiryTimeComputed (MS-ADTS 3.1.1.4.5.33): 0x7FFFFFFFFFFFFFFF when
        smart card required / DONT_EXPIRE_PASSWD / max password age is 0 (never expires);
        0 when pwdLastSet is 0 or null; otherwise pwdLastSet + effective max password age,
        which honours fine-grained policy.
        https://learn.microsoft.com/windows/win32/adschema/a-pwdlastset
        https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/f9e9b7e2-c7ac-4db6-ba38-71d9696981e9
    #>
    param(
        [object]$PwdLastSet,
        [object]$ExpiryComputed,
        [int]$UserAccountControl,
        [bool]$ExpiredBit,
        [datetime]$Now = (Get-Date)
    )
    $flagNever = (($UserAccountControl -band $script:UF_DONT_EXPIRE_PASSWD) -ne 0)
    $pls = [int64]0
    if ($null -ne $PwdLastSet) { try { $pls = [int64]$PwdLastSet } catch { $pls = [int64]0 } }
    $mustChange = ($pls -eq 0 -and -not $flagNever)

    $raw = $null
    if ($null -ne $ExpiryComputed) { try { $raw = [int64]$ExpiryComputed } catch { $raw = $null } }

    $never = $flagNever
    if ($null -ne $raw -and $raw -ge $script:FileTimeNever) { $never = $true }

    $expiry = $null
    if (-not $never -and -not $mustChange -and $null -ne $raw -and $raw -gt 0) {
        $expiry = ConvertFrom-AdFileTime -Value $raw
    }

    $expired = $false
    if (-not $mustChange -and -not $never) {
        if ($ExpiredBit) { $expired = $true }
        elseif ($null -ne $expiry -and $expiry -le $Now) { $expired = $true }
    }
    $days = $null
    if ($null -ne $expiry) { $days = [math]::Floor(($expiry - $Now).TotalDays) }

    return [PSCustomObject]@{
        MustChange = $mustChange; NeverExpires = $never; Expiry = $expiry
        Expired = $expired; DaysLeft = $days
        PwdLastSet = (ConvertFrom-AdFileTime -Value $pls)
    }
}

function Test-LogonHoursRestricted {
    # logonHours is a 21-byte bitmap (one bit per hour of the week). Not set, or every bit
    # set, means no restriction. https://learn.microsoft.com/windows/win32/adschema/a-logonhours
    param([object]$LogonHours)
    if ($null -eq $LogonHours) { return $false }
    $bytes = @($LogonHours)
    if ($bytes.Count -eq 0) { return $false }
    $notFull = @($bytes | Where-Object { [int]$_ -ne 255 })
    return ($notFull.Count -gt 0)
}

function Get-QuickCheckAssessment {
    <#
    .SYNOPSIS
        Turns the collected facts into a verdict plus plain-English reasons.
    .DESCRIPTION
        Blocker  -> NO. Probable -> PROBABLY NOT. Warning/Info never change the verdict.

        Passes are the plain strings shown under "Looks fine". Cleared holds the same checks as
        { Code; Message; CouldLook } for the ticket note, where CouldLook says whether the
        check could really be made: lockout status read from a DC other than the PDC emulator
        may be stale, and wrong-password counts are per DC (badPwdCount is not replicated), so
        a missing DC means those two are not confirmed.
        https://learn.microsoft.com/windows/win32/adschema/a-badpwdcount
    #>
    param([Parameter(Mandatory = $true)][object]$Facts, [datetime]$Now = (Get-Date))

    $reasons = New-Object System.Collections.Generic.List[object]
    $passes = New-Object System.Collections.Generic.List[string]
    $cleared = New-Object System.Collections.Generic.List[object]
    function Add-Reason($Level, $Code, $Message, $Action) {
        $reasons.Add([PSCustomObject]@{ Level = $Level; Code = $Code; Message = $Message; Action = $Action })
    }
    function Add-Pass($Code, $Message, [bool]$CouldLook = $true) {
        $passes.Add($Message)
        $cleared.Add([PSCustomObject]@{ Code = $Code; Message = $Message; CouldLook = $CouldLook })
    }

    # 1. Disabled
    if (-not $Facts.Enabled) {
        Add-Reason 'Blocker' 'Disabled' 'Their account is turned off (disabled).' `
            "Check with their manager that the account should be back in use, then enable it (Enable-ADAccount or Active Directory Users and Computers)."
    } else { Add-Pass 'Enabled' 'Account is turned on.' }

    # 2. Locked out
    if ($Facts.LockedOut) {
        $until = ''
        if ($Facts.UnlockTime) {
            if ($Facts.UnlockTime -gt $Now) { $until = " It will unlock by itself at $(Format-When $Facts.UnlockTime $Now)." }
            else { $until = ' It should be unlocking by itself any moment now.' }
        } elseif ($Facts.LockoutDurationKnown) {
            $until = ' It will NOT unlock by itself - someone has to unlock it.'
        }
        Add-Reason 'Blocker' 'LockedOut' ("Their account is locked because of too many wrong passwords.$until") `
            "Unlock it (Unlock-ADAccount). Then ask whether an old password is saved on a phone, laptop or mapped drive - if it locks again, run AD-LockoutDiagnostics\Diagnose-ADAccountLockout.ps1."
    } else { Add-Pass 'NotLocked' 'Not locked out.' (-not $Facts.PdcNote) }

    # 4. Account expiry
    $ax = $Facts.AccountExpiry
    if ($ax.Expired) {
        Add-Reason 'Blocker' 'AccountExpired' ("Their account expired on $($ax.Expires.ToString('yyyy-MM-dd HH:mm')).") `
            "Ask their manager whether they should still have access. If so, extend or clear the account expiry date."
    } elseif (-not $ax.Never -and $ax.DaysLeft -le $script:AccountExpiryWarnDays) {
        Add-Reason 'Warning' 'AccountExpiresSoon' ("Their account expires $(Format-When $ax.Expires $Now).") `
            "If they should keep working past that date, ask their manager to request an extension before then."
    } else { Add-Pass 'AccountNotExpired' $(if ($ax.Never) { 'Account does not expire.' } else { "Account expires $(Format-When $ax.Expires $Now)." }) }

    # 5. Password
    $pw = $Facts.Password
    if ($pw.MustChange) {
        Add-Reason 'Blocker' 'MustChangePassword' 'They must set a new password at next sign-in.' `
            "Have them sign in at a PC and choose a new password when prompted. Until then things like Outlook or VPN may simply fail instead of asking."
    } elseif ($pw.Expired) {
        $on = if ($pw.Expiry) { " on $($pw.Expiry.ToString('yyyy-MM-dd'))" } else { '' }
        Add-Reason 'Blocker' 'PasswordExpired' "Their password expired$on." `
            "Reset their password (Set-ADAccountPassword) or have them change it from a signed-in PC. Tell them to update it on their phone too."
    } elseif ($pw.NeverExpires) {
        Add-Pass 'PasswordOk' 'Password is set not to expire.'
    } elseif ($pw.Expiry -and $pw.DaysLeft -le $script:PasswordExpiryWarnDays) {
        Add-Reason 'Warning' 'PasswordExpiresSoon' ("Their password expires $(Format-When $pw.Expiry $Now).") `
            "Ask them to change it soon (Ctrl+Alt+Del, then Change a password), then update it on their phone and any saved connections."
    } else { Add-Pass 'PasswordOk' $(if ($pw.Expiry) { "Password is fine until $($pw.Expiry.ToString('yyyy-MM-dd'))." } else { 'Password is not expired.' }) }

    # 7. Restrictions
    $ws = @($Facts.Workstations)
    if ($ws.Count -gt 0) {
        Add-Reason 'Probable' 'WorkstationRestriction' ("They can only sign in to these computers: " + ($ws -join ', ') + '.') `
            "Check they are on one of those computers. If they need another, add it to the user's Log On To list (or ask the AD team)."
    }
    if ($Facts.LogonHoursRestricted) {
        Add-Reason 'Probable' 'LogonHours' 'This account has sign-in hours restrictions (it can only sign in at certain times).' `
            "If they are trying outside their allowed hours, sign-in is refused. Check Logon Hours on the Account tab of the user in Active Directory Users and Computers."
    }
    if ($Facts.SmartcardRequired) {
        Add-Reason 'Probable' 'SmartCard' 'This account must sign in with a smart card - a password will not work.' `
            "Make sure they are using their smart card. If it is lost or broken, arrange a replacement."
    }
    if ($ws.Count -eq 0 -and -not $Facts.LogonHoursRestricted -and -not $Facts.SmartcardRequired) {
        Add-Pass 'NoSignInLimits' 'No limits on where, when or how they sign in.'
    }

    # 3. Bad passwords (information and warning only - never changes the verdict)
    $answered = @($Facts.DcResults | Where-Object { $_.Reachable })
    $seen = @($answered | Where-Object { $_.BadPwdCount -gt 0 })
    if ($seen.Count -gt 0) {
        $top = @($seen | Sort-Object -Property BadPwdCount -Descending)[0]
        $dcs = ($seen | ForEach-Object { "$($_.DC) ($($_.BadPwdCount))" }) -join ', '
        $thr = [int]$Facts.LockoutThreshold
        if ($thr -gt 0) {
            $left = $thr - $top.BadPwdCount
            $msg = "Wrong passwords were recorded on: $dcs. The highest is $($top.BadPwdCount) of $thr allowed before lockout."
            $lvl = if ($left -le 2 -and -not $Facts.LockedOut) { 'Warning' } else { 'Info' }
        } else {
            $msg = "Wrong passwords were recorded on: $dcs. This domain does not lock accounts for wrong passwords."
            $lvl = 'Info'
        }
        Add-Reason $lvl 'BadPasswords' $msg `
            "Ask if they recently changed their password. An old one saved on a phone, laptop or mapped drive keeps retrying and causes lockouts."
    } elseif ($answered.Count -gt 0) {
        Add-Pass 'NoBadPasswords' 'No recent wrong-password attempts on the domain controllers checked.' (@($Facts.UnreachableDCs).Count -eq 0)
    }

    # Unreachable DCs / PDC fallback
    foreach ($dc in @($Facts.UnreachableDCs)) {
        Add-Reason 'Warning' 'DcUnreachable' "Couldn't check $dc - last-logon and bad-password counts may be incomplete." `
            "If this matters, check that $dc is online and re-run. The other results are still valid."
    }
    if ($Facts.PdcNote) {
        Add-Reason 'Warning' 'PdcFallback' $Facts.PdcNote `
            "Lockout status can lag on a DC other than the PDC emulator. Re-run when the PDC emulator is reachable."
    }

    # 8. Groups
    if ($null -ne $Facts.EffectiveGroupCount -and $Facts.EffectiveGroupCount -ge $script:TokenBloatWarnGroups) {
        Add-Reason 'Warning' 'ManyGroups' ("They are in $($Facts.EffectiveGroupCount) groups once nested groups are counted. Very large numbers can stop some apps and shares from accepting their sign-in (Kerberos token too big).") `
            "Only matters if they see 'request header too long' or odd access errors. If so, ask the AD team to review their group memberships."
    }

    # Verdict
    $blockers = @($reasons | Where-Object { $_.Level -eq 'Blocker' })
    $probables = @($reasons | Where-Object { $_.Level -eq 'Probable' })
    if ($blockers.Count -gt 0) { $verdict = 'NO'; $exit = 1 }
    elseif ($probables.Count -gt 0) { $verdict = 'PROBABLY NOT'; $exit = 1 }
    else { $verdict = 'YES'; $exit = 0 }

    $order = @{ Blocker = 0; Probable = 1; Warning = 2; Info = 3 }
    $sorted = @($reasons | Sort-Object -Property @{ Expression = { $order[$_.Level] } })
    return [PSCustomObject]@{ Verdict = $verdict; ExitCode = $exit; Reasons = $sorted; Passes = $passes.ToArray(); Cleared = $cleared.ToArray() }
}

# =============================================================================
# Directory access
# =============================================================================

function Resolve-QuickCheckUser {
    <#
    .SYNOPSIS
        Finds exactly one user, or reports NotFound / Ambiguous with candidates. Never guesses.
    .DESCRIPTION
        Order: distinguished name -> exact sAMAccountName / UPN -> name search (ANR or exact
        displayName). A name search that finds exactly one person is accepted; zero or more
        than one is reported back. Connectivity errors are thrown to the caller (exit 3).
    #>
    param([string]$Identity, [string]$Server, [System.Management.Automation.PSCredential]$Credential)

    $ad = Get-AdSplat -Server $Server -Credential $Credential
    $props = @('DisplayName', 'SamAccountName', 'UserPrincipalName', 'DistinguishedName', 'Department', 'userAccountControl')
    $id = $Identity.Trim()
    $found = @()
    $matchedBy = ''

    if ($id -match '^(?i)CN=.+,(OU|DC|CN)=') {
        try {
            $found = @(Get-ADUser -Identity $id @ad -Properties $props -ErrorAction Stop)
            $matchedBy = 'distinguished name'
        } catch {
            if ($_.Exception.GetType().Name -notmatch 'ADIdentityNotFound') { throw }
        }
    } else {
        $name = $id
        if ($name -match '^[^\\@]+\\(.+)$') { $name = $Matches[1] }   # DOMAIN\user -> user
        $e = ConvertTo-LdapFilterValue $name
        $found = @(Get-ADUser @ad -LDAPFilter "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=$e)(userPrincipalName=$e)))" -Properties $props -ErrorAction Stop)
        $matchedBy = 'sign-in name'
        if ($found.Count -eq 0) {
            $e2 = ConvertTo-LdapFilterValue $id
            $found = @(Get-ADUser @ad -LDAPFilter "(&(objectCategory=person)(objectClass=user)(|(anr=$e2)(displayName=$e2)))" -Properties $props -ResultSetSize $script:NameSearchLimit -ErrorAction Stop)
            $matchedBy = 'name search'
        }
    }

    $status = 'Found'
    if ($found.Count -eq 0) { $status = 'NotFound' }
    elseif ($found.Count -gt 1) { $status = 'Ambiguous' }
    return [PSCustomObject]@{
        Status = $status; User = $(if ($found.Count -eq 1) { $found[0] } else { $null })
        Candidates = @($found); MatchedBy = $matchedBy
    }
}

function Get-QuickCheckDcList {
    # Discovery over hardcoding: ask AD for the domain's DCs unless the caller supplied some.
    param([string[]]$DomainController, [string]$DomainDns, [string]$Server, [System.Management.Automation.PSCredential]$Credential)
    if ($DomainController -and @($DomainController).Count -gt 0) { return @($DomainController) }
    $ad = Get-AdSplat -Server $(if ($Server) { $Server } else { $DomainDns }) -Credential $Credential
    $list = @(Get-ADDomainController -Filter * @ad -ErrorAction Stop | Select-Object -ExpandProperty HostName | Sort-Object)
    return $list
}

function Get-UserDcSnapshot {
    # The attributes that are NOT replicated, read from one DC. Throws if the DC cannot answer.
    # https://learn.microsoft.com/windows/win32/adschema/a-badpwdcount
    # https://learn.microsoft.com/windows/win32/adschema/a-lastlogon
    param([string]$ComputerName, [string]$UserDn, [System.Management.Automation.PSCredential]$Credential)
    $ad = Get-AdSplat -Server $ComputerName -Credential $Credential
    $u = Get-ADUser -Identity $UserDn @ad -Properties @('badPwdCount', 'badPasswordTime', 'lastLogon', 'lockoutTime') -ErrorAction Stop
    return [PSCustomObject]@{
        DC = $ComputerName; Reachable = $true; Error = ''
        BadPwdCount = [int]$u.badPwdCount
        BadPasswordTime = ConvertFrom-AdFileTime -Value $u.badPasswordTime
        LastLogon = ConvertFrom-AdFileTime -Value $u.lastLogon
    }
}

function Get-QuickCheckFacts {
    <#
    .SYNOPSIS
        Reads everything the assessment needs. Returns Facts, or throws only when no DC can answer at all.
    #>
    param(
        [Parameter(Mandatory = $true)][object]$ResolvedUser,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential,
        [string[]]$DomainController,
        [datetime]$Now = (Get-Date)
    )

    $dn = [string]$ResolvedUser.DistinguishedName
    $domainDns = Get-DomainDnsFromDn -DistinguishedName $dn
    $notes = New-Object System.Collections.Generic.List[string]

    # --- Which DCs ---
    $dcs = @(Get-QuickCheckDcList -DomainController $DomainController -DomainDns $domainDns -Server $Server -Credential $Credential)
    if ($dcs.Count -eq 0) { throw 'No domain controllers were found to check.' }

    # --- PDC emulator (authoritative for lockout; lockout is urgently replicated to it) ---
    $pdc = $null
    try {
        $adD = Get-AdSplat -Server $(if ($Server) { $Server } else { $dcs[0] }) -Credential $Credential
        $dom = Get-ADDomain -Identity $domainDns @adD -ErrorAction Stop
        $pdc = [string]$dom.PDCEmulator
    } catch { $notes.Add("PDC emulator not identified: $($_.Exception.Message)") }

    # --- Primary read: full attribute set from the PDC, falling back to the other DCs ---
    $primaryProps = @(
        'DisplayName', 'UserPrincipalName', 'SamAccountName', 'mail', 'Department', 'Title', 'Manager', 'DistinguishedName',
        'whenCreated', 'whenChanged', 'userAccountControl', 'msDS-User-Account-Control-Computed', 'LockedOut', 'PasswordExpired',
        'lockoutTime', 'accountExpires', 'pwdLastSet', 'msDS-UserPasswordExpiryTimeComputed', 'lastLogonTimestamp',
        'badPwdCount', 'badPasswordTime', 'lastLogon', 'logonHours', 'userWorkstations', 'memberOf', 'primaryGroupID')
    $candidates = @()
    if ($pdc) { $candidates += $pdc }
    $candidates += @($dcs | Where-Object { $_ -ine $pdc })
    $u = $null
    $primaryServer = $null
    foreach ($c in $candidates) {
        try {
            $adC = Get-AdSplat -Server $c -Credential $Credential
            $u = Get-ADUser -Identity $dn @adC -Properties $primaryProps -ErrorAction Stop
            $primaryServer = $c
            break
        } catch { Write-Verbose "Primary read from $c failed: $($_.Exception.Message)" }
    }
    if (-not $u) { throw "None of the domain controllers could be read for $dn." }
    $pdcNote = $null
    if ($pdc -and $primaryServer -ine $pdc) {
        $pdcNote = "Couldn't reach the PDC emulator ($pdc) - lockout status was read from $primaryServer and may be out of date."
    } elseif (-not $pdc) {
        $pdcNote = "Couldn't identify the PDC emulator - lockout status was read from $primaryServer and may be out of date."
    }

    # --- Every DC: non-replicated attributes ---
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($dc in $dcs) {
        if ($dc -ieq $primaryServer) {
            $rows.Add([PSCustomObject]@{
                DC = $dc; Reachable = $true; Error = ''
                BadPwdCount = [int]$u.badPwdCount
                BadPasswordTime = ConvertFrom-AdFileTime -Value $u.badPasswordTime
                LastLogon = ConvertFrom-AdFileTime -Value $u.lastLogon
            })
            continue
        }
        try {
            $rows.Add((Get-UserDcSnapshot -ComputerName $dc -UserDn $dn -Credential $Credential))
        } catch {
            $rows.Add([PSCustomObject]@{ DC = $dc; Reachable = $false; Error = $_.Exception.Message; BadPwdCount = 0; BadPasswordTime = $null; LastLogon = $null })
            continue
        }
    }
    $dcRows = $rows.ToArray()
    $unreachable = @($dcRows | Where-Object { -not $_.Reachable } | ForEach-Object { $_.DC })

    # --- Policy: fine-grained (msDS-ResultantPSO) first, else the domain policy ---
    # https://learn.microsoft.com/powershell/module/activedirectory/get-aduserresultantpasswordpolicy
    $adP = Get-AdSplat -Server $primaryServer -Credential $Credential
    $policy = $null; $policySource = ''
    try {
        $pso = Get-ADUserResultantPasswordPolicy -Identity $dn @adP -ErrorAction Stop
        if ($pso) { $policy = $pso; $policySource = "fine-grained policy '$($pso.Name)'" }
    } catch { Write-Verbose "Resultant PSO lookup failed (continuing with domain policy): $($_.Exception.Message)" }
    if (-not $policy) {
        try {
            $policy = Get-ADDefaultDomainPasswordPolicy -Identity $domainDns @adP -ErrorAction Stop
            $policySource = 'domain policy'
        } catch { $notes.Add("Lockout policy not readable: $($_.Exception.Message)") }
    }
    $threshold = 0; $duration = $null; $durationKnown = $false
    if ($policy) {
        $threshold = [int]$policy.LockoutThreshold
        if ($null -ne $policy.LockoutDuration) { $duration = [TimeSpan]$policy.LockoutDuration; $durationKnown = $true }
    }

    # --- Decode the single primary read ---
    $uac = 0; if ($null -ne $u.userAccountControl) { $uac = [int]$u.userAccountControl }
    $comp = $u.'msDS-User-Account-Control-Computed'
    if ($null -ne $comp) {
        $lockedOut = ((([int]$comp) -band $script:UF_LOCKOUT) -ne 0)
        $pwExpiredBit = ((([int]$comp) -band $script:UF_PASSWORD_EXPIRED) -ne 0)
    } else {
        # Constructed attribute not returned: use the cmdlet's own computed properties.
        $lockedOut = [bool]$u.LockedOut
        $pwExpiredBit = [bool]$u.PasswordExpired
    }
    $lockoutTime = ConvertFrom-AdFileTime -Value $u.lockoutTime
    $unlockTime = $null
    # Duration 0 = stays locked until an admin unlocks it:
    # https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/account-lockout-duration
    if ($lockedOut -and $lockoutTime -and $durationKnown -and $duration.TotalSeconds -gt 0) { $unlockTime = $lockoutTime + $duration }

    $axState = Get-AccountExpiryState -AccountExpires $u.accountExpires -Now $Now
    $pwState = Get-PasswordState -PwdLastSet $u.pwdLastSet -ExpiryComputed $u.'msDS-UserPasswordExpiryTimeComputed' `
        -UserAccountControl $uac -ExpiredBit $pwExpiredBit -Now $Now

    # --- Last logon: newest lastLogon across every DC that answered ---
    $best = $null
    foreach ($r in $dcRows) { if ($r.Reachable -and $r.LastLogon -and (-not $best -or $r.LastLogon -gt $best.LastLogon)) { $best = $r } }
    $lastLogonTs = ConvertFrom-AdFileTime -Value $u.lastLogonTimestamp

    # --- Restrictions ---
    $wsList = @()
    if ($u.userWorkstations) { $wsList = @(([string]$u.userWorkstations -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }

    # --- Groups: direct memberOf + primary group; effective via tokenGroups (BASE-scope, once) ---
    $direct = @($u.memberOf).Count + 1
    $effective = $null
    try {
        $tg = Get-ADUser -Identity $dn @adP -Properties tokenGroups -ErrorAction Stop
        $effective = @($tg.tokenGroups).Count
    } catch { $notes.Add("Total group count not available: $($_.Exception.Message)") }

    # --- Manager name ---
    $managerName = ''
    if ($u.Manager) {
        try { $m = Get-ADUser -Identity $u.Manager @adP -Properties DisplayName -ErrorAction Stop; $managerName = if ($m.DisplayName) { [string]$m.DisplayName } else { [string]$m.Name } }
        catch { $managerName = (([string]$u.Manager -split ',')[0] -replace '^CN=', '') }
    }

    $display = if ($u.DisplayName) { [string]$u.DisplayName } else { [string]$u.SamAccountName }

    return [PSCustomObject]@{
        DisplayName = $display; SamAccountName = [string]$u.SamAccountName; UserPrincipalName = [string]$u.UserPrincipalName
        Mail = [string]$u.mail; Department = [string]$u.Department; Title = [string]$u.Title; Manager = $managerName
        DistinguishedName = $dn; OU = (Get-ParentContainer $dn); WhenCreated = $u.whenCreated; WhenChanged = $u.whenChanged
        Enabled = (($uac -band $script:UF_ACCOUNTDISABLE) -eq 0)
        LockedOut = $lockedOut; LockoutTime = $lockoutTime; UnlockTime = $unlockTime
        LockoutThreshold = $threshold; LockoutDuration = $duration; LockoutDurationKnown = $durationKnown; PolicySource = $policySource
        AccountExpiry = $axState; Password = $pwState
        PasswordNotRequired = (($uac -band $script:UF_PASSWD_NOTREQD) -ne 0)
        SmartcardRequired = (($uac -band $script:UF_SMARTCARD_REQUIRED) -ne 0)
        LogonHoursRestricted = (Test-LogonHoursRestricted -LogonHours $u.logonHours)
        Workstations = $wsList
        DcResults = $dcRows; UnreachableDCs = $unreachable; DcsChecked = @($dcRows | Where-Object { $_.Reachable }).Count; DcsTotal = $dcRows.Count
        LastLogon = $(if ($best) { $best.LastLogon } else { $null }); LastLogonDC = $(if ($best) { $best.DC } else { '' })
        LastLogonTimestamp = $lastLogonTs
        DirectGroupCount = $direct; EffectiveGroupCount = $effective
        PdcEmulator = $pdc; PdcNote = $pdcNote; ReadFrom = $primaryServer; Notes = $notes.ToArray()
    }
}

function Invoke-UserQuickCheck {
    <#
    .SYNOPSIS
        Resolve, collect, assess. Never calls exit; returns a result object with ExitCode.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Identity,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential,
        [string[]]$DomainController,
        [datetime]$Now = (Get-Date)
    )

    $result = [PSCustomObject]@{
        Status = 'Error'; ExitCode = 3; Identity = $Identity; Message = ''; Candidates = @(); MatchedBy = ''
        Facts = $null; Assessment = $null; Now = $Now
    }
    try {
        $res = Resolve-QuickCheckUser -Identity $Identity -Server $Server -Credential $Credential
    } catch {
        $result.Message = "Could not query Active Directory: $($_.Exception.Message)"
        return $result
    }
    $result.MatchedBy = $res.MatchedBy
    if ($res.Status -eq 'NotFound') {
        $result.Status = 'NotFound'; $result.ExitCode = 2
        $result.Message = "No user matched '$Identity'. Check the spelling, or try their sign-in name (for example jdoe or jdoe@contoso.com)."
        return $result
    }
    if ($res.Status -eq 'Ambiguous') {
        $result.Status = 'Ambiguous'; $result.ExitCode = 2; $result.Candidates = @($res.Candidates)
        $result.Message = "'$Identity' matches $(@($res.Candidates).Count) people. Run it again with the exact sign-in name of the right one."
        return $result
    }
    try {
        $facts = Get-QuickCheckFacts -ResolvedUser $res.User -Server $Server -Credential $Credential -DomainController $DomainController -Now $Now
    } catch {
        $result.Message = "Could not read the account from Active Directory: $($_.Exception.Message)"
        return $result
    }
    $assessment = Get-QuickCheckAssessment -Facts $facts -Now $Now
    $result.Status = 'Ok'; $result.ExitCode = $assessment.ExitCode
    $result.Facts = $facts; $result.Assessment = $assessment
    return $result
}

# =============================================================================
# Output
# =============================================================================

function Get-QuickCheckDetail {
    # Compact Item/Value table for sysadmins (console, HTML).
    param([Parameter(Mandatory = $true)][object]$Facts, [datetime]$Now = (Get-Date))
    $f = $Facts
    $rows = New-Object System.Collections.Generic.List[object]
    function Add-Row($Item, $Value) { $rows.Add([PSCustomObject]@{ Item = $Item; Value = [string]$Value }) }

    Add-Row 'Name' $f.DisplayName
    Add-Row 'Sign-in name' "$($f.SamAccountName)   $($f.UserPrincipalName)"
    Add-Row 'Email' $f.Mail
    Add-Row 'Department / title' ("$($f.Department) / $($f.Title)")
    Add-Row 'Manager' $f.Manager
    Add-Row 'Location (OU)' $f.OU
    Add-Row 'Created / changed' ("$(if ($f.WhenCreated) { ([datetime]$f.WhenCreated).ToString('yyyy-MM-dd') }) / $(if ($f.WhenChanged) { ([datetime]$f.WhenChanged).ToString('yyyy-MM-dd') })")
    Add-Row 'Account on' $(if ($f.Enabled) { 'Yes' } else { 'No (disabled)' })
    $lock = if ($f.LockedOut) { 'LOCKED OUT' } else { 'No' }
    if ($f.LockedOut -and $f.UnlockTime) { $lock += " - unlocks $(Format-When $f.UnlockTime $Now)" }
    elseif ($f.LockedOut -and $f.LockoutDurationKnown) { $lock += ' - stays locked until an admin unlocks it' }
    elseif (-not $f.LockedOut -and $f.LockoutTime) { $lock += " (last locked $(Format-When $f.LockoutTime $Now); that lockout has ended)" }
    Add-Row 'Locked out now' $lock
    $thr = if ($f.LockoutThreshold -gt 0) { "$($f.LockoutThreshold) wrong passwords" } else { 'lockout is off' }
    $dur = if (-not $f.LockoutDurationKnown) { 'unknown' } elseif ($f.LockoutDuration.TotalSeconds -le 0) { 'until an admin unlocks' } else { "$([int]$f.LockoutDuration.TotalMinutes) minutes" }
    Add-Row 'Lockout policy' "$thr, locked for: $dur ($($f.PolicySource))"
    Add-Row 'Account expires' $(if ($f.AccountExpiry.Never) { 'Never' } else { Format-When $f.AccountExpiry.Expires $Now })
    $pwv = if ($f.Password.MustChange) { 'Must change at next sign-in' } elseif ($f.Password.NeverExpires) { 'Never expires' } elseif ($f.Password.Expiry) { "Expires $(Format-When $f.Password.Expiry $Now)" } else { 'Unknown' }
    if ($f.Password.Expired) { $pwv = "EXPIRED - $pwv" }
    Add-Row 'Password' $pwv
    Add-Row 'Password last set' $(if ($f.Password.PwdLastSet) { Format-When $f.Password.PwdLastSet $Now } else { 'not set' })
    Add-Row 'Password not required' $(if ($f.PasswordNotRequired) { 'Yes (account can have a blank password)' } else { 'No' })
    Add-Row 'Smart card required' $(if ($f.SmartcardRequired) { 'Yes' } else { 'No' })
    Add-Row 'Sign-in hours limited' $(if ($f.LogonHoursRestricted) { 'Yes' } else { 'No' })
    Add-Row 'Allowed computers' $(if (@($f.Workstations).Count -gt 0) { @($f.Workstations) -join ', ' } else { 'Any' })
    if ($f.LastLogon) { Add-Row 'Last sign-in (newest)' "$(Format-When $f.LastLogon $Now) via $($f.LastLogonDC)" }
    else { Add-Row 'Last sign-in (newest)' 'not recorded on any DC checked' }
    Add-Row 'Last sign-in (shared copy)' $(if ($f.LastLogonTimestamp) { "$(Format-When $f.LastLogonTimestamp $Now) - only copied between DCs every so often (up to about 14 days by default), so it can be days behind" } else { 'not recorded' })
    $hi = @($f.DcResults | Where-Object { $_.Reachable } | Sort-Object -Property BadPwdCount -Descending)
    $hiTxt = if ($hi.Count -gt 0) { "$($hi[0].BadPwdCount) (on $($hi[0].DC))" } else { 'unknown' }
    Add-Row 'Highest wrong-password count' $hiTxt
    Add-Row 'Groups' $(if ($null -ne $f.EffectiveGroupCount) { "$($f.DirectGroupCount) direct (including primary group), $($f.EffectiveGroupCount) in total including nested" } else { "$($f.DirectGroupCount) direct (including primary group); total not available" })
    Add-Row 'Domain controllers checked' "$($f.DcsChecked) of $($f.DcsTotal)$(if (@($f.UnreachableDCs).Count -gt 0) { ' - could not check: ' + (@($f.UnreachableDCs) -join ', ') })"
    Add-Row 'Lockout status read from' "$($f.ReadFrom)$(if ($f.PdcEmulator) { ' (PDC emulator: ' + $f.PdcEmulator + ')' })"
    return $rows.ToArray()
}

function Write-QuickCheckConsole {
    param([Parameter(Mandatory = $true)][object]$Result)

    if ($Result.Status -eq 'NotFound') { Write-Status $Result.Message 'FAIL'; return }
    if ($Result.Status -eq 'Ambiguous') {
        Write-Status $Result.Message 'FAIL'
        foreach ($c in @($Result.Candidates)) {
            $en = if ($null -ne $c.userAccountControl -and (([int]$c.userAccountControl) -band 2)) { 'disabled' } else { 'enabled' }
            Write-Host ("       {0,-28} {1,-20} {2,-32} {3}" -f $c.DisplayName, $c.SamAccountName, $c.UserPrincipalName, $en) -ForegroundColor Gray
        }
        return
    }
    if ($Result.Status -ne 'Ok') { Write-Status $Result.Message 'FAIL'; return }

    $f = $Result.Facts; $a = $Result.Assessment; $now = $Result.Now
    $color = switch ($a.Verdict) { 'YES' { 'Green' } 'NO' { 'Red' } default { 'Yellow' } }
    Write-Host ''
    Write-Host ("Can {0} sign in right now?  {1}" -f $f.DisplayName, $a.Verdict) -ForegroundColor $color
    Write-Host ('=' * 70) -ForegroundColor DarkGray

    $block = @($a.Reasons | Where-Object { $_.Level -eq 'Blocker' -or $_.Level -eq 'Probable' })
    $notes = @($a.Reasons | Where-Object { $_.Level -eq 'Warning' -or $_.Level -eq 'Info' })
    if ($block.Count -gt 0) {
        Write-Host 'Why not:' -ForegroundColor White
        foreach ($r in $block) {
            Write-Status $r.Message $(if ($r.Level -eq 'Blocker') { 'FAIL' } else { 'WARN' })
            Write-Host ("       What to do: {0}" -f $r.Action) -ForegroundColor Gray
        }
    }
    if ($notes.Count -gt 0) {
        Write-Host ''
        Write-Host $(if ($block.Count -gt 0) { 'Also worth knowing:' } else { 'Worth knowing:' }) -ForegroundColor White
        foreach ($r in $notes) {
            Write-Status $r.Message $(if ($r.Level -eq 'Warning') { 'WARN' } else { 'INFO' })
            Write-Host ("       What to do: {0}" -f $r.Action) -ForegroundColor Gray
        }
    }
    if (@($a.Passes).Count -gt 0) {
        Write-Host ''
        Write-Host 'Looks fine:' -ForegroundColor White
        foreach ($p in $a.Passes) { Write-Status $p 'PASS' }
    }
    Write-Host ''
    Write-Host 'Details' -ForegroundColor White
    Write-Host ('-' * 70) -ForegroundColor DarkGray
    foreach ($d in (Get-QuickCheckDetail -Facts $f -Now $now)) {
        Write-Host ("{0,-28} {1}" -f $d.Item, $d.Value) -ForegroundColor Gray
    }
    Write-Host ''
    Write-Host 'Per domain controller' -ForegroundColor White
    Write-Host ('-' * 70) -ForegroundColor DarkGray
    Write-Host ("{0,-34} {1,-8} {2,-18} {3}" -f 'DC', 'Wrong pw', 'Last wrong pw', 'Last sign-in here') -ForegroundColor DarkGray
    foreach ($r in @($f.DcResults)) {
        if ($r.Reachable) {
            $bt = if ($r.BadPasswordTime) { $r.BadPasswordTime.ToString('yyyy-MM-dd HH:mm') } else { '-' }
            $ll = if ($r.LastLogon) { $r.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { '-' }
            Write-Host ("{0,-34} {1,-8} {2,-18} {3}" -f $r.DC, $r.BadPwdCount, $bt, $ll) -ForegroundColor Gray
        } else {
            Write-Host ("{0,-34} {1}" -f $r.DC, 'COULD NOT CHECK') -ForegroundColor Yellow
        }
    }
    foreach ($n in @($f.Notes)) { Write-Status $n 'INFO' }
    Write-Host ''
    Write-Status 'This checks the on-premises account only. It does not check Microsoft 365 / Entra sign-in, MFA or Conditional Access.' 'INFO'
}

function Get-QuickCheckCsvRow {
    param([Parameter(Mandatory = $true)][object]$Result)
    $f = $Result.Facts; $a = $Result.Assessment
    $fmt = 'yyyy-MM-dd HH:mm:ss'
    $hi = @($f.DcResults | Where-Object { $_.Reachable } | Sort-Object -Property BadPwdCount -Descending)
    return [PSCustomObject]@{
        CheckedAt = $Result.Now.ToString($fmt)
        Verdict = $a.Verdict
        Reasons = (@($a.Reasons | Where-Object { $_.Level -eq 'Blocker' -or $_.Level -eq 'Probable' } | ForEach-Object { $_.Message }) -join ' | ')
        Warnings = (@($a.Reasons | Where-Object { $_.Level -eq 'Warning' } | ForEach-Object { $_.Message }) -join ' | ')
        DisplayName = $f.DisplayName; SamAccountName = $f.SamAccountName; UserPrincipalName = $f.UserPrincipalName
        Mail = $f.Mail; Department = $f.Department; Title = $f.Title; Manager = $f.Manager
        OU = $f.OU; WhenCreated = $(if ($f.WhenCreated) { ([datetime]$f.WhenCreated).ToString($fmt) }); WhenChanged = $(if ($f.WhenChanged) { ([datetime]$f.WhenChanged).ToString($fmt) })
        Enabled = $f.Enabled; LockedOut = $f.LockedOut
        UnlockTime = $(if ($f.UnlockTime) { $f.UnlockTime.ToString($fmt) })
        AccountExpires = $(if ($f.AccountExpiry.Never) { 'Never' } else { $f.AccountExpiry.Expires.ToString($fmt) })
        PasswordState = $(if ($f.Password.MustChange) { 'MustChangeAtNextSignIn' } elseif ($f.Password.Expired) { 'Expired' } elseif ($f.Password.NeverExpires) { 'NeverExpires' } else { 'OK' })
        PasswordExpires = $(if ($f.Password.Expiry) { $f.Password.Expiry.ToString($fmt) })
        PasswordDaysLeft = $f.Password.DaysLeft
        PasswordNotRequired = $f.PasswordNotRequired; SmartcardRequired = $f.SmartcardRequired
        LogonHoursRestricted = $f.LogonHoursRestricted; AllowedComputers = (@($f.Workstations) -join ';')
        LastLogon = $(if ($f.LastLogon) { $f.LastLogon.ToString($fmt) }); LastLogonDC = $f.LastLogonDC
        LastLogonTimestamp = $(if ($f.LastLogonTimestamp) { $f.LastLogonTimestamp.ToString($fmt) })
        HighestBadPwdCount = $(if ($hi.Count -gt 0) { $hi[0].BadPwdCount } else { $null })
        LockoutThreshold = $f.LockoutThreshold
        DirectGroups = $f.DirectGroupCount; EffectiveGroups = $f.EffectiveGroupCount
        DcsChecked = $f.DcsChecked; DcsTotal = $f.DcsTotal; DcsUnreachable = (@($f.UnreachableDCs) -join ';')
    }
}

function ConvertTo-QuickCheckHtml {
    param([Parameter(Mandatory = $true)][object]$Result)
    function Enc([object]$s) { [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $f = $Result.Facts; $a = $Result.Assessment
    $cls = switch ($a.Verdict) { 'YES' { 'ok' } 'NO' { 'bad' } default { 'warn' } }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine("<title>Sign-in check - $(Enc $f.DisplayName)</title>")
    [void]$sb.AppendLine('<style>body{background:#15181c;color:#e8eaed;font-family:"Segoe UI",sans-serif;max-width:980px;margin:0 auto;padding:32px;line-height:1.5}' +
        '.verdict{border-left:6px solid;padding:6px 0 6px 18px;margin-bottom:24px}.verdict h1{margin:0;font-size:26px}' +
        '.ok{border-color:#5fc98a}.bad{border-color:#e2686a}.warn{border-color:#e0a458}.v{font-weight:700}' +
        '.reason{background:#1d2126;border:1px solid #333a44;border-radius:4px;padding:10px 14px;margin:8px 0}' +
        '.reason small{display:block;color:#98a2b0}table{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}' +
        'td,th{padding:6px 10px;border-bottom:1px solid #242931;text-align:left}th{color:#98a2b0}h2{font-size:15px;letter-spacing:.1em;text-transform:uppercase;color:#98a2b0;margin-top:32px}' +
        '.FAIL{color:#e2686a}.WARN{color:#e0a458}.INFO{color:#5dade2}.PASS{color:#5fc98a}</style></head><body>')
    [void]$sb.AppendLine("<div class=`"verdict $cls`"><h1>Can $(Enc $f.DisplayName) sign in right now? <span class=`"v`">$(Enc $a.Verdict)</span></h1><div>Checked $(Enc $Result.Now.ToString('yyyy-MM-dd HH:mm'))</div></div>")
    foreach ($r in $a.Reasons) {
        $tag = switch ($r.Level) { 'Blocker' { 'FAIL' } 'Probable' { 'WARN' } 'Warning' { 'WARN' } default { 'INFO' } }
        [void]$sb.AppendLine("<div class=`"reason`"><span class=`"$tag`">[$tag]</span> $(Enc $r.Message)<small>What to do: $(Enc $r.Action)</small></div>")
    }
    foreach ($p in $a.Passes) { [void]$sb.AppendLine("<div class=`"reason`"><span class=`"PASS`">[PASS]</span> $(Enc $p)</div>") }
    [void]$sb.AppendLine('<h2>Details</h2><table>')
    foreach ($d in (Get-QuickCheckDetail -Facts $f -Now $Result.Now)) { [void]$sb.AppendLine("<tr><th>$(Enc $d.Item)</th><td>$(Enc $d.Value)</td></tr>") }
    [void]$sb.AppendLine('</table><h2>Per domain controller</h2><table><tr><th>DC</th><th>Wrong passwords</th><th>Last wrong password</th><th>Last sign-in here</th></tr>')
    foreach ($r in @($f.DcResults)) {
        if ($r.Reachable) {
            [void]$sb.AppendLine("<tr><td>$(Enc $r.DC)</td><td>$(Enc $r.BadPwdCount)</td><td>$(Enc $(if ($r.BadPasswordTime) { $r.BadPasswordTime.ToString('yyyy-MM-dd HH:mm') } else { '-' }))</td><td>$(Enc $(if ($r.LastLogon) { $r.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { '-' }))</td></tr>")
        } else {
            [void]$sb.AppendLine("<tr><td>$(Enc $r.DC)</td><td colspan=`"3`" class=`"WARN`">COULD NOT CHECK</td></tr>")
        }
    }
    [void]$sb.AppendLine('</table><p class="INFO">This checks the on-premises account only. It does not check Microsoft 365 / Entra sign-in, MFA or Conditional Access.</p></body></html>')
    return $sb.ToString()
}

function Export-QuickCheckReport {
    # Writes UserQuickCheck_<sam>_<yyyy-MM-dd_HHmmss>.html and .csv. Returns the two paths.
    param([Parameter(Mandatory = $true)][object]$Result, [Parameter(Mandatory = $true)][string]$OutputPath)
    if (-not (Test-Path -LiteralPath $OutputPath)) { $null = New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop }
    $sam = ([string]$Result.Facts.SamAccountName) -replace '[^\w\.\-]', '_'
    $stem = Join-Path $OutputPath ("UserQuickCheck_{0}_{1}" -f $sam, $Result.Now.ToString('yyyy-MM-dd_HHmmss'))
    $csv = "$stem.csv"; $html = "$stem.html"
    Get-QuickCheckCsvRow -Result $Result | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    [System.IO.File]::WriteAllText($html, (ConvertTo-QuickCheckHtml -Result $Result), (New-Object System.Text.UTF8Encoding($true)))
    return [PSCustomObject]@{ Html = $html; Csv = $csv }
}

# =============================================================================
# Ticket note (CaseKit.ps1)
# =============================================================================

function ConvertTo-UserQuickCheckTicketNote {
    <#
    .SYNOPSIS
        Maps a quick-check result to a ticket note. The gate decisions for this tool live here.
    .DESCRIPTION
        Blocker -> PROBLEM, Probable and Warning -> WARNING, Info -> INFO. An unreachable DC, the
        PDC fallback and each Facts.Notes entry (something not readable) -> Could not check.
        Cleared checks go to Ruled out only when the assessment says it could look (see
        Get-QuickCheckAssessment). Next steps are the Blocker and Probable actions.

        When the account was never read (Error / NotFound / Ambiguous) the note says why in
        the headline, rules nothing out, and says the account checks did not run.

        -Credential only contributes its user name, shown as "(as <name>)" in the stamp.
    #>
    param(
        [Parameter(Mandatory = $true)][object]$Result,
        [string[]]$EvidencePaths = @(),
        [System.Management.Automation.PSCredential]$Credential
    )
    $items = New-Object System.Collections.Generic.List[object]
    $next = New-Object System.Collections.Generic.List[string]
    $id = [string]$Result.Identity
    $domain = ''

    if ($Result.Status -eq 'Ok') {
        $f = $Result.Facts; $a = $Result.Assessment
        $domain = Get-DomainDnsFromDn -DistinguishedName $f.DistinguishedName
        $headline = 'Can {0} sign in right now? {1}' -f $f.DisplayName, $a.Verdict
        $scopeLine = 'AD account {0} in {1}, on {2} of {3} domain controllers.' -f $f.SamAccountName, $domain, $f.DcsChecked, $f.DcsTotal

        foreach ($r in @($a.Reasons)) {
            switch ($r.Code) {
                # Listed per DC below, in the note's own words.
                'DcUnreachable' { continue }
                'PdcFallback' { $items.Add((New-TicketNoteItem -Kind NotChecked -Text $r.Message)); continue }
                default {
                    $kind = switch ($r.Level) { 'Blocker' { 'Problem' } 'Info' { 'Info' } default { 'Warning' } }
                    $items.Add((New-TicketNoteItem -Kind $kind -Text $r.Message))
                }
            }
        }
        foreach ($dc in @($f.UnreachableDCs)) {
            $items.Add((New-TicketNoteItem -Kind NotChecked -Text ('{0}: wrong-password count and last sign-in (could not reach it).' -f $dc)))
        }
        foreach ($n in @($f.Notes)) { $items.Add((New-TicketNoteItem -Kind NotChecked -Text $n)) }
        foreach ($c in @($a.Cleared)) { $items.Add((New-TicketNoteItem -Kind Clear -Text $c.Message -CouldLook ([bool]$c.CouldLook))) }

        foreach ($r in @($a.Reasons | Where-Object { $_.Level -eq 'Blocker' -or $_.Level -eq 'Probable' })) { $next.Add($r.Action) }
        if ($next.Count -eq 0 -and $a.Verdict -eq 'YES') {
            $next.Add('No account problem found. Look at the device, the network or the app next (DriveMap-Diagnostics, Network-QuickCheck).')
        }
    } else {
        $notRun = 'The account checks did not run (turned on, locked out, expiry, password, sign-in limits, wrong passwords).'
        switch ($Result.Status) {
            'NotFound' {
                $headline = "Sign-in check did not run - no user matched '$id'"
                $next.Add('Check the spelling, or try their sign-in name (for example jdoe or jdoe@contoso.com), then run the check again.')
            }
            'Ambiguous' {
                $cands = @($Result.Candidates)
                # The name search stops at $script:NameSearchLimit, so a full page means "or more".
                $howMany = if ($cands.Count -ge $script:NameSearchLimit) { "$($script:NameSearchLimit) or more" } else { [string]$cands.Count }
                $headline = "Sign-in check did not run - '$id' matches $howMany people"
                # Enough to recognise the right person; not a directory dump in the ticket.
                foreach ($c in @($cands | Select-Object -First $script:NoteCandidateLimit)) {
                    $items.Add((New-TicketNoteItem -Kind Info -Text ('Matches {0} ({1}).' -f $c.DisplayName, $c.SamAccountName)))
                }
                if ($cands.Count -gt $script:NoteCandidateLimit) {
                    $more = if ($cands.Count -ge $script:NameSearchLimit) { "at least $($cands.Count - $script:NoteCandidateLimit)" } else { [string]($cands.Count - $script:NoteCandidateLimit) }
                    $items.Add((New-TicketNoteItem -Kind Info -Text "...and $more more (refine the search)."))
                }
                if ($cands.Count -gt 0) { $domain = Get-DomainDnsFromDn -DistinguishedName ([string]$cands[0].DistinguishedName) }
                $next.Add('Run it again with the exact sign-in name of the right person.')
            }
            default {
                $headline = "Sign-in check for '$id' did not run - could not read Active Directory"
                if ($Result.Message) { $items.Add((New-TicketNoteItem -Kind Problem -Text $Result.Message)) }
                $next.Add('Check that this PC can reach a domain controller (and that -Server / -Credential are right), then run the check again.')
            }
        }
        $scopeLine = "Looked up '$id' in Active Directory."
        $items.Add((New-TicketNoteItem -Kind NotChecked -Text $notRun))
    }

    if (-not $domain) { $domain = if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN.ToLower() } else { 'not known' } }
    $stampArgs = @{ ScopeLabel = 'Domain'; Scope = $domain }
    if ($Result.Now -is [datetime]) { $stampArgs['Now'] = $Result.Now }
    if ($Credential) { $stampArgs['RunAs'] = $Credential.UserName }
    $stamp = New-TicketNoteStamp @stampArgs

    return New-TicketNote -Tool 'AD-UserQuickCheck' -Headline $headline -ScopeLine $scopeLine -Items $items.ToArray() `
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
function New-QuickCheckStartFailure([string]$Message) {
    [PSCustomObject]@{
        Status = 'Error'; ExitCode = 3; Identity = $Identity; Message = $Message
        Candidates = @(); MatchedBy = ''; Facts = $null; Assessment = $null; Now = (Get-Date); TicketNote = $null
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
    if ($PassThru) { return (New-QuickCheckStartFailure $msg) }
    exit 3
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    $msg = "The ActiveDirectory PowerShell module is not available: $($_.Exception.Message)"
    if (-not $Quiet) {
        Write-Status $msg 'FAIL'
        Write-Status 'Install the RSAT Active Directory tools, or run this on a domain controller / admin server.' 'INFO'
    }
    if ($PassThru) { return (New-QuickCheckStartFailure $msg) }
    exit 3
}

$result = Invoke-UserQuickCheck -Identity $Identity -Server $Server -Credential $Credential -DomainController $DomainController
if (-not $Quiet) { Write-QuickCheckConsole -Result $result }

# Where the files go: with -TicketNumber, <OutputPath or the default root>\Ticket_<n> (reports
# and note together, so the note's evidence names sit beside it); with only -OutputPath, that
# folder; with neither, no files (the note goes to the clipboard, or the console).
$folder = $OutputPath
if ($TicketNumber) {
    $root = if ($OutputPath) { $OutputPath } else { Get-TicketNoteDefaultRoot }
    try {
        $folder = Resolve-TicketFolder -TicketNumber $TicketNumber -Root $root
    } catch {
        if (-not $Quiet) { Write-Status "Could not create the ticket folder under ${root}: $($_.Exception.Message)" 'WARN' }
    }
}

$evidence = @()
if ($folder -and $result.Status -eq 'Ok') {
    try {
        $files = Export-QuickCheckReport -Result $result -OutputPath $folder
        $evidence = @($files.Html, $files.Csv)
        if (-not $Quiet) {
            Write-Status "Report saved: $($files.Html)" 'PASS'
            Write-Status "CSV saved   : $($files.Csv)" 'PASS'
        }
    } catch {
        if (-not $Quiet) { Write-Status "Could not write the report to ${folder}: $($_.Exception.Message)" 'WARN' }
    }
}

$note = $null
if ($script:CaseKitMissing) {
    if (-not $Quiet -and -not $script:CaseKitWarned) { Write-Status 'CaseKit.ps1 is missing from this folder - no ticket note this time.' 'WARN' }
} else {
    # The note is extra: a failure while building or saving it never changes the answer or the
    # exit code. The check's own result above stands.
    try {
        $note = ConvertTo-UserQuickCheckTicketNote -Result $result -EvidencePaths $evidence -Credential $Credential
        if ($Quiet) {
            # Another script is the caller: no console and no clipboard. The note is still saved
            # when a folder is in play, and it is always on the result object.
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
