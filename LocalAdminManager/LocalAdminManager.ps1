<#
.SYNOPSIS
    Adds or removes a domain user or group in the local Administrators group of a computer,
    locally or remotely, and logs every attempt to a daily change-log CSV.

.DESCRIPTION
    Changes membership of the built-in local Administrators group on the local computer or on a
    remote computer, and records who did it, when, from which machine, on which computer, and
    the full member list before and after the change.

    How it reaches the group:
      - The group is found by its well-known SID S-1-5-32-544, so it works on non-English
        Windows where the group is called, for example, "Administratoren".
      - Membership is read and changed through the ADSI WinNT provider. On the local computer
        this runs in-process; on a remote computer the same script block runs there through
        Invoke-Command (PowerShell remoting / WinRM).
      - The member is matched by its SID, translated on the target computer, so
        'contoso\jsmith' and 'CONTOSO\JSmith' are the same member. The name is only compared
        when the account cannot be translated.
      - The LocalAccounts cmdlets (Add-LocalGroupMember, ...) are not used: they have no
        -ComputerName parameter and need PowerShell 5.1 on the target. An earlier version of
        this script passed -ComputerName to them, so every run failed.

    Safety:
      - Before anything changes, a [WARN] line shows the member, the group, the computer and
        the current member count, followed by a confirmation prompt. -Force skips the prompt;
        -WhatIf shows what would happen, changes nothing and writes no log.
      - If today's change log cannot be opened for writing, nothing is changed (fail closed).
        If it fails only after the change was made, a [FAIL] line says so, the entry is shown
        on screen and saved to %TEMP%\LocalAdminManager_Changes_<yyyy-MM-dd>.csv, and the
        script exits 1.
      - The member list is read again from the computer after the change, so the log shows
        what actually happened. A change that is not visible in that re-read is Failed.

    Every attempt (done, no change, failed, declined) is one row in
    <LogFolder>\Changes_<yyyy-MM-dd>.csv with the columns Time, Technician, Computer, Action,
    Target, ItemType, Detail, OldValue, NewValue, Result, Error, BackupFile. "Computer" is the
    machine the tool ran on; the changed computer and group are in "Target". The log holds
    client account names: keep it with the ticket, not in source control.

    Exit code 0 when the change was made or was not needed; 1 when it failed, was declined, or
    could not be logged.

.PARAMETER Action
    'Add' or 'Remove'.

.PARAMETER Member
    The user or group, as 'DOMAIN\Username' or 'DOMAIN\GroupName'. A name without a domain is
    a local account on the target computer. A SID (S-1-5-21-...) also works, which is how a
    deleted account that only shows as a SID is removed. A user principal name
    (user@contoso.com) is not accepted.

.PARAMETER ComputerName
    The computer to change. Defaults to this computer. A remote computer needs PowerShell
    remoting (WinRM) enabled and your account must be an administrator on it.

.PARAMETER LogFolder
    Folder for the daily change log. Defaults to the Logs folder next to this script (not the
    current directory, which is System32 in an elevated prompt). When the script runs from a
    share, a mapped network drive or a removable disk, the default is
    %LOCALAPPDATA%\LocalAdminManager\Logs instead, so client account names stay on this
    computer.

.PARAMETER Force
    Make the change without the confirmation prompt (for batch files).

.PARAMETER LoadFunctionsOnly
    Internal: define the functions and stop, without changing anything. Used by the tests.

.EXAMPLE
    .\LocalAdminManager.ps1 -Action Add -Member "CONTOSO\JohnDoe"

    Adds a domain user to the local Administrators group on this computer, after confirmation.

.EXAMPLE
    .\LocalAdminManager.ps1 -Action Remove -Member "CONTOSO\TempAdmins" -ComputerName "RemotePC01"

    Removes a domain group from the local Administrators group on RemotePC01 through WinRM.

.EXAMPLE
    .\LocalAdminManager.ps1 -Action Add -Member "CONTOSO\ITSupport" -ComputerName "RemotePC01" -WhatIf

    Shows the current member count and what would change on RemotePC01, and changes nothing.

.EXAMPLE
    .\LocalAdminManager.ps1 -Action Remove -Member "S-1-5-21-1004336348-1177238915-682003330-1105" -ComputerName "RemotePC01"

    Removes a deleted account that the group only shows as its SID.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File LocalAdminManager.ps1 -Action Add -Member "CONTOSO\User1" -ComputerName PC01 -Force

    Batch use: no prompt; the exit code is 1 if the change failed.

.NOTES
    - Run from an elevated PowerShell prompt.
    - Remote computers: PowerShell remoting (WinRM) must be enabled on the target, and your
      account must be a local administrator there.
    - The change log holds client account names (client data). Logs are never deleted
      automatically and inherit the permissions of their folder: keep the tool in a folder
      only administrators can read.

    REFERENCES
    - Add-LocalGroupMember / Remove-LocalGroupMember / Get-LocalGroupMember have no
      -ComputerName parameter (the cause of the original "always fails" bug):
      https://learn.microsoft.com/powershell/module/microsoft.powershell.localaccounts/add-localgroupmember
      https://learn.microsoft.com/powershell/module/microsoft.powershell.localaccounts/remove-localgroupmember
      https://learn.microsoft.com/powershell/module/microsoft.powershell.localaccounts/get-localgroupmember
    - Well-known SID S-1-5-32-544 is the built-in Administrators group:
      https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
    - IADsGroup Add / Remove / Members, and the serverless SID ADsPath WinNT://S-1-5-21-...
      accepted by Add and Remove:
      https://learn.microsoft.com/windows/win32/api/iads/nn-iads-iadsgroup
      https://learn.microsoft.com/windows/win32/api/iads/nf-iads-iadsgroup-add
      https://learn.microsoft.com/windows/win32/api/iads/nf-iads-iadsgroup-remove
    - WinNT ADsPath forms (WinNT://<server>/<object name>,<object class>, WinNT://<domain>/<object name>):
      https://learn.microsoft.com/windows/win32/adsi/winnt-adspath
    - Invoke-Command -ComputerName / -ScriptBlock / -ArgumentList:
      https://learn.microsoft.com/powershell/module/microsoft.powershell.core/invoke-command
    - IPGlobalProperties.DomainName (this computer's DNS domain; empty outside a domain):
      https://learn.microsoft.com/dotnet/api/system.net.networkinformation.ipglobalproperties.domainname
    - FileMode.Append (opens or creates a file for writing at its end; needs Append permission):
      https://learn.microsoft.com/dotnet/api/system.io.filemode
    - DriveInfo.DriveType (fixed vs network/removable drives):
      https://learn.microsoft.com/dotnet/api/system.io.driveinfo.drivetype
    - PowerShell versions shipped with Windows Server (3.0 floor):
      https://learn.microsoft.com/powershell/scripting/install/powershell-support-lifecycle
#>

#Requires -Version 3.0
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("Add", "Remove")]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [string]$Member,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ComputerName = $env:COMPUTERNAME,

    [string]$LogFolder,

    [switch]$Force,

    # Internal: dot-source the functions without running the main body.
    [switch]$LoadFunctionsOnly
)

# Set here, as Start-M365SyncedUserFixes.ps1 does, not as a parameter default: Windows
# PowerShell 5.1 leaves $PSScriptRoot empty while binding parameter defaults when the script
# is dot-sourced by a relative path, and Join-Path then fails before anything runs.
# Resolve-ChangeLogFolder decides whether this default is used (see -LogFolder).
$script:DefaultLogFolder = Join-Path $PSScriptRoot 'Logs'

#region Script blocks that run on the target computer

# These blocks run on the target through Invoke-Command, so they must be self-contained: no
# calls to the functions in this script. They also avoid [PSCustomObject] and [ordered] so
# that a target still on PowerShell 2.0 can run them.

# Well-known SID of the built-in Administrators group. The group's NAME is localized
# ("Administratoren" on German Windows), the SID is not.
# https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
$script:AdministratorsSid = 'S-1-5-32-544'

# Translates a SID string to 'DOMAIN\Name' on the computer it runs on.
$script:SidToAccountScript = {
    param([string]$Sid)
    (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
}

# Reads ('Get'), resolves a member ('Resolve') or changes ('Add', 'Remove') the built-in
# Administrators group through the ADSI WinNT provider.
#   'Get'     -> one object { Group; Members = { Name; Sid }...; MemberSid }
#   'Resolve' -> the SID of -Member on this computer, or '' when it cannot be translated
# MemberPathFunction is the text of ConvertTo-WinNTMemberPath, passed in so the ADsPath is
# built by the same (tested) code on the target.
# IADsGroup Members/Add/Remove: https://learn.microsoft.com/windows/win32/api/iads/nn-iads-iadsgroup
# ADsPath forms: https://learn.microsoft.com/windows/win32/adsi/winnt-adspath
$script:LocalAdminGroupScript = {
    param([string]$Operation, [string]$AdministratorsSid, [string]$Member, [string]$MemberPathFunction)

    $ErrorActionPreference = 'Stop'
    try {
        $account = (New-Object System.Security.Principal.SecurityIdentifier($AdministratorsSid)).Translate([System.Security.Principal.NTAccount]).Value
        $groupName = $account.Substring($account.IndexOf('\') + 1)
        $group = [ADSI]("WinNT://$env:COMPUTERNAME/$groupName,group")

        # The member's SID, translated here so a domain or local name means what it means on
        # the target. A SID given as text is used as it is: a deleted account cannot be
        # translated, and that is exactly the member someone wants to remove.
        $memberSid = ''
        if ($Member -and ($Operation -eq 'Get' -or $Operation -eq 'Resolve')) {
            try {
                if ($Member -match '^S-1-\d+(-\d+)+$') {
                    $memberSid = (New-Object System.Security.Principal.SecurityIdentifier($Member)).Value
                } else {
                    $accountName = $Member
                    if ($Member -notmatch '\\') { $accountName = "$env:COMPUTERNAME\$Member" }
                    $memberSid = (New-Object System.Security.Principal.NTAccount($accountName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
            } catch { $memberSid = '' }
        }
        if ($Operation -eq 'Resolve') { return $memberSid }

        if ($Operation -eq 'Get') {
            $members = @(foreach ($m in @($group.psbase.Invoke('Members'))) {
                $path = [string]$m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
                $sidText = ''
                $name = ''
                try {
                    $sidBytes = $m.GetType().InvokeMember('objectSid', 'GetProperty', $null, $m, $null)
                    $sidText = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
                } catch { $sidText = '' }
                if ($sidText) {
                    # An orphaned SID (deleted account) cannot be translated; Name stays empty
                    # and the caller shows the SID instead.
                    try { $name = (New-Object System.Security.Principal.SecurityIdentifier($sidText)).Translate([System.Security.Principal.NTAccount]).Value } catch { $name = '' }
                } else {
                    $sidText = $path
                }
                New-Object PSObject -Property @{ Name = $name; Sid = $sidText }
            })
            return (New-Object PSObject -Property @{ Group = $groupName; Members = $members; MemberSid = $memberSid })
        }

        $toPath = [scriptblock]::Create($MemberPathFunction)
        $memberPath = [string](& $toPath $Member $env:COMPUTERNAME)
        if ($Operation -eq 'Add') { [void]$group.psbase.Invoke('Add', $memberPath) }
        elseif ($Operation -eq 'Remove') { [void]$group.psbase.Invoke('Remove', $memberPath) }
        else { throw "Unknown operation '$Operation'." }
    } catch {
        # ADSI wraps the real reason ("Access is denied.") in invocation exceptions.
        $e = $_.Exception
        while ($e.InnerException) { $e = $e.InnerException }
        throw $e.Message
    }
}

#endregion

#region Console and environment

function Write-Status {
    param(
        [ValidateSet('PASS','WARN','FAIL','INFO')][string]$Level,
        [string]$Message
    )
    $color = @{ PASS='Green'; WARN='Yellow'; FAIL='Red'; INFO='Cyan' }[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

#endregion

#region Transport

function Get-LocalComputerFqdn {
    # This computer's DNS name (pc01.contoso.com), or just the host name outside a domain.
    # IPGlobalProperties reads the local configuration; it does not query DNS.
    # https://learn.microsoft.com/dotnet/api/system.net.networkinformation.ipglobalproperties.domainname
    $properties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    if ($properties.DomainName) { return "$($properties.HostName).$($properties.DomainName)" }
    $properties.HostName
}

function Test-IsLocalComputer {
    # True when the name means this computer, so the work runs in-process without remoting.
    # A DNS name counts only when it is this computer's own FQDN: pc01.otherdomain.tld is a
    # different computer that happens to share the host name.
    param([AllowEmptyString()][AllowNull()][string]$ComputerName)

    $name = "$ComputerName".Trim()
    if (-not $name -or $name -eq '.' -or $name -eq 'localhost' -or $name -eq '127.0.0.1' -or $name -eq '::1') { return $true }
    if ($name -eq $env:COMPUTERNAME) { return $true }
    if ($name -notmatch '\.' -or $name -match '^\d+(\.\d+){3}$') { return $false }
    try { $fqdn = [string](Get-LocalComputerFqdn) } catch { return $false }
    [bool]$fqdn -and $name -eq $fqdn
}

function Invoke-OnTarget {
    <#
    .SYNOPSIS
        Runs a script block on the target: in-process for this computer, otherwise through
        Invoke-Command -ComputerName (WinRM). The only function that touches the transport.
        https://learn.microsoft.com/powershell/module/microsoft.powershell.core/invoke-command
    #>
    param([string]$ComputerName, [scriptblock]$ScriptBlock, [object[]]$ArgumentList)

    if (Test-IsLocalComputer -ComputerName $ComputerName) {
        if ($ArgumentList) { return & $ScriptBlock @ArgumentList }
        return & $ScriptBlock
    }

    $remote = @{ ComputerName = $ComputerName; ScriptBlock = $ScriptBlock; ErrorAction = 'Stop' }
    if ($ArgumentList -and $ArgumentList.Count -gt 0) { $remote['ArgumentList'] = $ArgumentList }
    Invoke-Command @remote
}

#endregion

#region Reading and changing the group

function Resolve-BuiltinAdministratorsName {
    <#
    .SYNOPSIS
        Returns the localized name of the built-in Administrators group ("Administratoren"),
        found from its well-known SID. The translator gets the SID string and returns an NT
        account such as 'BUILTIN\Administratoren'; by default it translates on this computer.
    #>
    param([scriptblock]$Translator)

    if (-not $Translator) { $Translator = $script:SidToAccountScript }
    $account = [string](& $Translator $script:AdministratorsSid)
    if (-not $account) { throw "The built-in administrators group ($($script:AdministratorsSid)) was not found." }
    $account.Substring($account.IndexOf('\') + 1)
}

function ConvertTo-WinNTMemberPath {
    # The ADsPath for -Member on the computer named -ComputerName:
    #   'DOMAIN\Name' -> WinNT://DOMAIN/Name
    #   'Name'        -> WinNT://<computer>/Name (a local account on the target)
    #   'S-1-5-...'   -> WinNT://S-1-5-... (serverless SID path, documented for IADsGroup Add
    #                    and Remove; it is how an orphaned SID is removed)
    # https://learn.microsoft.com/windows/win32/adsi/winnt-adspath
    # https://learn.microsoft.com/windows/win32/api/iads/nf-iads-iadsgroup-remove
    # Its text is passed to LocalAdminGroupScript and run on the target: keep it self-contained.
    param([string]$Member, [string]$ComputerName)

    if ($Member -match '^S-1-\d+(-\d+)+$') { return "WinNT://$Member" }
    if ($Member -match '\\') { return 'WinNT://' + ($Member -replace '\\', '/') }
    "WinNT://$ComputerName/$Member"
}

function Test-IsUserPrincipalName {
    # True for user@contoso.com. The WinNT provider and NTAccount need DOMAIN\Name, so a UPN
    # is refused before anything is read or changed.
    param([AllowEmptyString()][string]$Member)
    $Member -notmatch '\\' -and $Member -match '^[^@\s]+@[^@\s]+$'
}

function Get-LocalAdminGroupName {
    # The localized name of the built-in Administrators group on the target computer.
    param([string]$ComputerName)
    Resolve-BuiltinAdministratorsName -Translator {
        param($sid)
        Invoke-OnTarget -ComputerName $ComputerName -ScriptBlock $script:SidToAccountScript -ArgumentList @($sid)
    }
}

function Get-LocalAdminGroup {
    # One round trip: the localized group name, its members ({ Name, Sid }) and, when -Member
    # is given, that member's SID on the target ('' when it cannot be translated).
    param([string]$ComputerName, [string]$Member)
    Invoke-OnTarget -ComputerName $ComputerName -ScriptBlock $script:LocalAdminGroupScript -ArgumentList @('Get', $script:AdministratorsSid, $Member, '')
}

function Get-LocalAdminMember {
    # Members of the built-in Administrators group on the target, as { Name, Sid } objects.
    # Name is empty for a member whose SID cannot be resolved.
    param([string]$ComputerName)
    $info = Get-LocalAdminGroup -ComputerName $ComputerName
    if ($info) { @($info.Members | Where-Object { $null -ne $_ }) }
}

function Resolve-LocalAdminMemberSid {
    # The SID of -Member as the target computer resolves it, or '' when it cannot.
    param([string]$ComputerName, [string]$Member)
    [string](Invoke-OnTarget -ComputerName $ComputerName -ScriptBlock $script:LocalAdminGroupScript -ArgumentList @('Resolve', $script:AdministratorsSid, $Member, ''))
}

function Add-LocalAdminMember {
    param([string]$ComputerName, [string]$Member)
    $pathFunction = ${function:ConvertTo-WinNTMemberPath}.ToString()
    Invoke-OnTarget -ComputerName $ComputerName -ScriptBlock $script:LocalAdminGroupScript -ArgumentList @('Add', $script:AdministratorsSid, $Member, $pathFunction) | Out-Null
}

function Remove-LocalAdminMember {
    param([string]$ComputerName, [string]$Member)
    $pathFunction = ${function:ConvertTo-WinNTMemberPath}.ToString()
    Invoke-OnTarget -ComputerName $ComputerName -ScriptBlock $script:LocalAdminGroupScript -ArgumentList @('Remove', $script:AdministratorsSid, $Member, $pathFunction) | Out-Null
}

function Format-MemberList {
    # Member names (the SID when the name cannot be resolved), sorted case-insensitively and
    # joined with '; '. An empty group gives an empty string.
    param([AllowEmptyCollection()][AllowNull()][object[]]$Members)

    $names = @($Members | Where-Object { $null -ne $_ } | ForEach-Object {
        if ($_.Name) { [string]$_.Name } else { [string]$_.Sid }
    } | Sort-Object)
    $names -join '; '
}

function Test-IsAdminMember {
    # True when Member is in the list. With -MemberSid (the member translated on the target)
    # only the SID counts. Without it (the account could not be translated) the text is
    # compared with each SID and, case-insensitively, each name; a name without a domain is a
    # local account on the target.
    param([AllowEmptyCollection()][object[]]$Members, [string]$Member, [string]$ComputerName, [string]$MemberSid)

    $list = @($Members | Where-Object { $null -ne $_ })
    if ($MemberSid) {
        foreach ($m in $list) { if ($m.Sid -and [string]$m.Sid -eq $MemberSid) { return $true } }
        return $false
    }
    $localName = "$($ComputerName.Split('.')[0])\$Member"
    foreach ($m in $list) {
        if ($m.Sid -and [string]$m.Sid -eq $Member) { return $true }
        if ($m.Name -and ([string]$m.Name -eq $Member -or ($Member -notmatch '\\' -and [string]$m.Name -eq $localName))) { return $true }
    }
    $false
}

function New-LocalAdminChangeEntry {
    # One change-log row in the shared format (D-030; squad SQ-008 "Change-log format").
    param([string]$Action, [string]$Member, [string]$Target)
    [ordered]@{
        Time       = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Technician = "$env:USERDOMAIN\$env:USERNAME"
        Computer   = $env:COMPUTERNAME
        Action     = $(if ($Action -eq 'Add') { 'Add administrator' } else { 'Remove administrator' })
        Target     = $Target
        ItemType   = 'Local group'
        Detail     = $Member
        OldValue   = ''
        NewValue   = ''
        Result     = ''
        Error      = ''
        BackupFile = ''
    }
}

function Set-LocalAdminMembership {
    <#
    .SYNOPSIS
        Adds or removes one member of the built-in Administrators group on one computer.
        Never throws; returns the change-log entry, with the member list read before and
        read again after the change.
    .PARAMETER Preview
        The Get-LocalAdminGroup result the caller already read and showed (group name,
        members, member SID). Saves reading the group again; without it the group is read here.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([ValidateSet('Add','Remove')][string]$Action, [string]$Member, [string]$ComputerName, [object]$Preview)

    $entry = New-LocalAdminChangeEntry -Action $Action -Member $Member -Target $ComputerName

    if (Test-IsUserPrincipalName -Member $Member) {
        $entry.Result = 'Failed'
        $entry.Error = "$Member is a user principal name. Give the member as DOMAIN\Name (for example CONTOSO\JSmith). Nothing was changed."
        return [PSCustomObject]$entry
    }

    try {
        if ($Preview) {
            $group = [string]$Preview.Group
            $before = @($Preview.Members | Where-Object { $null -ne $_ })
            $memberSid = [string]$Preview.MemberSid
        } else {
            $group = Get-LocalAdminGroupName -ComputerName $ComputerName
            $before = @(Get-LocalAdminMember -ComputerName $ComputerName)
            $memberSid = Resolve-LocalAdminMemberSid -ComputerName $ComputerName -Member $Member
        }
        $entry.Target = "$ComputerName\$group"
    } catch {
        $entry.Result = 'Failed'
        $entry.Error = "Could not read the local administrators group on ${ComputerName}: $($_.Exception.Message)"
        return [PSCustomObject]$entry
    }
    $entry.OldValue = Format-MemberList -Members $before

    $isMember = Test-IsAdminMember -Members $before -Member $Member -ComputerName $ComputerName -MemberSid $memberSid
    if ($Action -eq 'Add' -and $isMember) {
        $entry.NewValue = $entry.OldValue
        $entry.Result = 'No change (already a member)'
        return [PSCustomObject]$entry
    }
    if ($Action -eq 'Remove' -and -not $isMember) {
        $entry.NewValue = $entry.OldValue
        if ($memberSid) {
            $entry.Result = 'No change (not a member)'
        } else {
            # Not "No change": an account that cannot be found may still be in the group
            # under another name, so saying "not a member" could be wrong.
            $entry.Result = 'Failed'
            $entry.Error = "$Member could not be found on $ComputerName, and no member of $group has that name. Nothing was removed. Check the spelling, or give the member's SID (S-1-5-...) as it appears in the member list."
        }
        return [PSCustomObject]$entry
    }

    try {
        $confirmed = $PSCmdlet.ShouldProcess("$group on $ComputerName", "$Action $Member")
    } catch {
        # A run with -NonInteractive cannot show the confirmation prompt.
        $entry.NewValue = $entry.OldValue
        $entry.Result = 'Failed'
        $entry.Error = "Confirmation not possible in a non-interactive session; use -Force. ($($_.Exception.Message))"
        return [PSCustomObject]$entry
    }
    if (-not $confirmed) {
        $entry.NewValue = $entry.OldValue
        $entry.Result = $(if ($WhatIfPreference) { 'Skipped (WhatIf)' } else { 'Skipped (not confirmed)' })
        return [PSCustomObject]$entry
    }

    try {
        if ($Action -eq 'Add') {
            Add-LocalAdminMember -ComputerName $ComputerName -Member $Member
        } else {
            Remove-LocalAdminMember -ComputerName $ComputerName -Member $Member
        }
        $entry.Result = 'Done'
    } catch {
        $entry.Result = 'Failed'
        $entry.Error = $_.Exception.Message
    }

    # Read again rather than compute, so the log shows what the computer actually holds.
    try {
        $after = @(Get-LocalAdminMember -ComputerName $ComputerName)
        $entry.NewValue = Format-MemberList -Members $after
        if ($entry.Result -eq 'Done') {
            $nowMember = Test-IsAdminMember -Members $after -Member $Member -ComputerName $ComputerName -MemberSid $memberSid
            if (($Action -eq 'Add') -ne $nowMember) {
                $state = if ($nowMember) { 'is still in' } else { 'is not in' }
                $entry.Result = 'Failed'
                $entry.Error = "Change not visible after re-read: $Member $state $group on $ComputerName. Check the group on that computer."
            }
        }
    } catch {
        $entry.NewValue = ''
        if ($entry.Result -eq 'Done') {
            $entry.Error = "The change was made, but the group could not be read again afterwards: $($_.Exception.Message)"
        }
    }

    [PSCustomObject]$entry
}

#endregion

#region Change log

function ConvertTo-CsvSafeText {
    # Prefixes text that Excel would run as a formula (starts with = + - @, tab or carriage
    # return) with a single quote, as FolderPermissions.Core.ps1 does for its change log.
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ($Text -match '^[=+\-@\t\r]') { "'" + $Text } else { $Text }
}

function Test-LocalFixedPath {
    <#
    .SYNOPSIS
        True when the path is on a local fixed disk: not a UNC path, not a mapped network
        drive, not a removable or optical drive. Copied from FolderPermissions.Core.ps1.
        https://learn.microsoft.com/dotnet/api/system.io.driveinfo.drivetype
    #>
    param([AllowEmptyString()][string]$Path)

    if ($Path -match '^(\\\\|//)') { return $false }
    if ($Path -match '^([A-Za-z]):') { $letter = $Matches[1] } else { return $false }
    try {
        (New-Object System.IO.DriveInfo -ArgumentList $letter).DriveType -eq [System.IO.DriveType]::Fixed
    } catch {
        $false
    }
}

function Get-LocalAppDataFolder {
    # %LOCALAPPDATA%, or the same folder from Windows when the variable is missing (some
    # service and scheduled-task sessions). Empty when neither is known.
    if ($env:LOCALAPPDATA) { return $env:LOCALAPPDATA }
    [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
}

function Resolve-ChangeLogFolder {
    <#
    .SYNOPSIS
        Picks the change-log folder: -LogFolder as given, else Logs next to the script when
        that is on a local fixed disk, else %LOCALAPPDATA%\LocalAdminManager\Logs.
    .DESCRIPTION
        Mirrors FolderPermissions.Core.ps1. Techs often run tools from a share: a log there
        would put client account names wherever the share is readable. Throws a plain message
        when there is no local folder to fall back to.
    #>
    param([string]$LogFolder, [string]$DefaultFolder)

    if ($LogFolder) { return $LogFolder }
    if (Test-LocalFixedPath -Path $DefaultFolder) { return $DefaultFolder }
    $local = Get-LocalAppDataFolder
    if (-not $local) {
        throw "There is no folder on this computer to save the change log in, so no change was made. Start the tool again with -LogFolder and a local folder you can write to, for example -LogFolder 'C:\Temp\LocalAdminManager'."
    }
    Join-Path $local 'LocalAdminManager\Logs'
}

function Get-ChangeLogFolderNotice {
    # The [WARN] lines to print about the log folder (none when all is well).
    param([string]$LogFolder, [string]$ResolvedFolder, [string]$DefaultFolder)

    if ($LogFolder) {
        if (-not (Test-LocalFixedPath -Path $LogFolder)) {
            "The log folder $LogFolder is on a network drive or share. The change log holds client account names: anyone who can read that folder can read them."
        }
    } elseif ($ResolvedFolder -ne $DefaultFolder) {
        "This script is running from a network or removable location, so the change log goes to $ResolvedFolder on this computer instead of $DefaultFolder."
    }
}

function Get-ChangeLogPath {
    # Today's log file: <folder>\<prefix><yyyy-MM-dd>.csv
    param([string]$LogFolder, [string]$FileNamePrefix = 'Changes_')
    Join-Path $LogFolder ("{0}{1}.csv" -f $FileNamePrefix, (Get-Date -Format 'yyyy-MM-dd'))
}

function Get-FallbackLogFolder {
    # Where an entry goes when the change log cannot be written after a change: %TEMP%.
    [System.IO.Path]::GetTempPath()
}

function Test-LogFolderWritable {
    # Creates the folder if needed and opens today's change log for appending, the same
    # write the log needs: a folder that takes new files but not changes to today's log, or a
    # log held open by Excel, is caught here. Checked before any change: if the change cannot
    # be logged, it is not made (D-029). Opening for append creates an empty file when there
    # is none; Export-Csv -Append still writes the header into it.
    # https://learn.microsoft.com/dotnet/api/system.io.filemode
    param([string]$LogFolder)

    try {
        if (-not (Test-Path -LiteralPath $LogFolder -PathType Container)) {
            New-Item -ItemType Directory -Path $LogFolder -Force -ErrorAction Stop -Confirm:$false -WhatIf:$false | Out-Null
        }
        $path = Get-ChangeLogPath -LogFolder $LogFolder
        $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
        $stream.Dispose()
        return $true
    } catch {
        Write-Verbose "The change log in $LogFolder cannot be written: $($_.Exception.Message)"
        return $false
    }
}

function Write-LocalAdminChangeLog {
    <#
    .SYNOPSIS
        Appends change rows to <prefix><yyyy-MM-dd>.csv in the log folder (one file per day,
        one header). Returns the path, or $null when nothing could be written.
    #>
    param([AllowEmptyCollection()][object[]]$Entries, [string]$LogFolder, [string]$FileNamePrefix = 'Changes_')

    $rows = @($Entries | Where-Object { $null -ne $_ } | ForEach-Object {
        $safe = [ordered]@{}
        foreach ($property in $_.PSObject.Properties) {
            $safe[$property.Name] = if ($property.Value -is [string]) { ConvertTo-CsvSafeText $property.Value } else { $property.Value }
        }
        [PSCustomObject]$safe
    })
    if ($rows.Count -eq 0) { return $null }

    try {
        if (-not (Test-Path -LiteralPath $LogFolder)) {
            New-Item -ItemType Directory -Path $LogFolder -Force -ErrorAction Stop -Confirm:$false -WhatIf:$false | Out-Null
        }
        $path = Get-ChangeLogPath -LogFolder $LogFolder -FileNamePrefix $FileNamePrefix
        # -Append writes the header only when the file is new or empty.
        $rows | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 -Append -ErrorAction Stop -Confirm:$false -WhatIf:$false
        return $path
    } catch {
        Write-Verbose "Could not write change log: $($_.Exception.Message)"
        return $null
    }
}

#endregion

#region Main

function Invoke-LocalAdminManagerMain {
    <#
    .SYNOPSIS
        The script body. Returns the exit code (0 done or no change needed, 1 otherwise).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Action,
        [string]$Member,
        [string]$ComputerName,
        [string]$LogFolder,
        [string]$DefaultLogFolder = $script:DefaultLogFolder,
        [switch]$Force
    )

    if (-not (Test-Administrator)) {
        Write-Status -Level FAIL -Message 'This script must be run from an elevated PowerShell prompt (Run as administrator).'
        return 1
    }
    if (Test-IsUserPrincipalName -Member $Member) {
        Write-Status -Level FAIL -Message "$Member is a user principal name. Give the member as DOMAIN\Name (for example CONTOSO\JSmith). Nothing was changed."
        return 1
    }

    $target = if (Test-IsLocalComputer -ComputerName $ComputerName) { $env:COMPUTERNAME } else { $ComputerName }
    $dryRun = [bool]$WhatIfPreference

    try {
        $folder = Resolve-ChangeLogFolder -LogFolder $LogFolder -DefaultFolder $DefaultLogFolder
    } catch {
        Write-Status -Level FAIL -Message $_.Exception.Message
        return 1
    }
    foreach ($notice in @(Get-ChangeLogFolderNotice -LogFolder $LogFolder -ResolvedFolder $folder -DefaultFolder $DefaultLogFolder)) {
        Write-Status -Level WARN -Message $notice
    }

    if ($dryRun) {
        Write-Status -Level INFO -Message 'Dry run (-WhatIf): nothing will be changed and no change log is written.'
    } elseif (-not (Test-LogFolderWritable -LogFolder $folder)) {
        # Fail closed (D-029): a change that cannot be logged is not made.
        Write-Status -Level FAIL -Message "Cannot write the change log in $folder. Nothing was changed. Use -LogFolder to choose a folder you can write to."
        return 1
    }

    $verb = if ($Action -eq 'Add') { 'add' } else { 'remove' }
    $direction = if ($Action -eq 'Add') { 'to' } else { 'from' }
    $preview = $null
    try {
        $preview = Get-LocalAdminGroup -ComputerName $target -Member $Member
        $count = @($preview.Members | Where-Object { $null -ne $_ }).Count
        Write-Status -Level WARN -Message "This will $verb $Member $direction the local administrators group ($($preview.Group)) on $target (currently $count members)."
    } catch {
        # Set-LocalAdminMembership reads the group again and records the failure.
        $preview = $null
        Write-Status -Level INFO -Message "Could not read the local administrators group on ${target}: $($_.Exception.Message)"
    }

    if ($Force) { $ConfirmPreference = 'None' }
    $change = @{ Action = $Action; Member = $Member; ComputerName = $target }
    if ($preview) { $change['Preview'] = $preview }
    $entry = Set-LocalAdminMembership @change

    $group = "$($entry.Target)" -replace '^[^\\]*\\', ''
    if (-not $group) { $group = 'the local administrators group' }

    if ($dryRun) {
        # Nothing was changed, so nothing is logged.
        switch -Wildcard ($entry.Result) {
            'Skipped (WhatIf)' { Write-Status -Level INFO -Message "Dry run: would $verb $Member $direction $group on $target. Nothing was changed."; return 0 }
            'No change*'       { Write-Status -Level INFO -Message "Dry run: nothing to do, $Member $(if ($Action -eq 'Add') { 'is already a member of' } else { 'is not a member of' }) $group on $target. Nothing was changed."; return 0 }
            default            { Write-Status -Level INFO -Message "Dry run: could not $verb $Member $direction $group on ${target}: $($entry.Error) Nothing was changed."; return 1 }
        }
    }

    $logPath = Write-LocalAdminChangeLog -Entries @($entry) -LogFolder $folder
    if (-not $logPath) {
        if ($entry.Result -eq 'Done') {
            Write-Status -Level FAIL -Message "The change WAS made on $target, but it could not be written to the change log in $folder."
        } else {
            Write-Status -Level FAIL -Message "The result ($($entry.Result)) could not be written to the change log in $folder."
        }
        foreach ($field in 'Target', 'Detail', 'OldValue', 'NewValue', 'Result') {
            Write-Status -Level INFO -Message ("{0}: {1}" -f $field, $entry.$field)
        }
        $fallbackFolder = Get-FallbackLogFolder
        $fallbackPath = $null
        if ($fallbackFolder) { $fallbackPath = Write-LocalAdminChangeLog -Entries @($entry) -LogFolder $fallbackFolder -FileNamePrefix 'LocalAdminManager_Changes_' }
        if ($fallbackPath) {
            Write-Status -Level INFO -Message "The entry was saved to $fallbackPath instead. Copy it into the change log or the ticket."
        } else {
            Write-Status -Level FAIL -Message "The entry could not be saved to $fallbackFolder either. Copy the lines above into the ticket."
        }
        return 1
    }
    $logText = " Logged to $logPath"

    switch -Wildcard ($entry.Result) {
        'Done' {
            $past = if ($Action -eq 'Add') { 'Added' } else { 'Removed' }
            $text = "$past $Member $direction $group on $target."
            if ($entry.Error) { $text += " $($entry.Error)" }
            Write-Status -Level PASS -Message ($text + $logText)
            return 0
        }
        'No change*' {
            $why = if ($Action -eq 'Add') { 'is already a member of' } else { 'is not a member of' }
            Write-Status -Level PASS -Message ("No change: $Member $why $group on $target." + $logText)
            return 0
        }
        'Skipped*' {
            Write-Status -Level WARN -Message ("Not confirmed: $Member was not changed on $target." + $logText)
            return 1
        }
        default {
            Write-Status -Level FAIL -Message ("Could not $verb $Member $direction $group on ${target}: $($entry.Error)" + $logText)
            return 1
        }
    }
}

#endregion

if ($LoadFunctionsOnly) { return }

exit (Invoke-LocalAdminManagerMain -Action $Action -Member $Member -ComputerName $ComputerName -LogFolder $LogFolder -Force:$Force -WhatIf:$WhatIfPreference)
