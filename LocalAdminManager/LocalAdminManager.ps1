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
      - The LocalAccounts cmdlets (Add-LocalGroupMember, ...) are not used: they have no
        -ComputerName parameter and need PowerShell 5.1 on the target. An earlier version of
        this script passed -ComputerName to them, so every run failed.

    Safety:
      - Before anything changes, a [WARN] line shows the member, the group, the computer and
        the current member count, followed by a confirmation prompt. -Force skips the prompt;
        -WhatIf shows what would happen and changes nothing.
      - If the change log cannot be written, nothing is changed (fail closed).
      - The member list is read again from the computer after the change, so the log shows
        what actually happened.

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
    The domain user or group, as 'DOMAIN\Username' or 'DOMAIN\GroupName'. A name without a
    domain is a local account on the target computer.

.PARAMETER ComputerName
    The computer to change. Defaults to this computer. A remote computer needs PowerShell
    remoting (WinRM) enabled and your account must be an administrator on it.

.PARAMETER LogFolder
    Folder for the daily change log. Defaults to the Logs folder next to this script (not the
    current directory, which is System32 in an elevated prompt).

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
    powershell.exe -ExecutionPolicy Bypass -File LocalAdminManager.ps1 -Action Add -Member "CONTOSO\User1" -ComputerName PC01 -Force

    Batch use: no prompt; the exit code is 1 if the change failed.

.NOTES
    - Run from an elevated PowerShell prompt.
    - Remote computers: PowerShell remoting (WinRM) must be enabled on the target, and your
      account must be a local administrator there.
    - The change log under LocalAdminManager\Logs holds client account names (client data).

    REFERENCES
    - Add-LocalGroupMember / Remove-LocalGroupMember / Get-LocalGroupMember have no
      -ComputerName parameter (the cause of the original "always fails" bug):
      https://learn.microsoft.com/powershell/module/microsoft.powershell.localaccounts/add-localgroupmember
      https://learn.microsoft.com/powershell/module/microsoft.powershell.localaccounts/remove-localgroupmember
      https://learn.microsoft.com/powershell/module/microsoft.powershell.localaccounts/get-localgroupmember
    - Well-known SID S-1-5-32-544 is the built-in Administrators group:
      https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
    - IADsGroup Add / Remove / Members:
      https://learn.microsoft.com/windows/win32/api/iads/nn-iads-iadsgroup
    - WinNT ADsPath forms (WinNT://<server>/<object name>,<object class>, WinNT://<domain>/<object name>):
      https://learn.microsoft.com/windows/win32/adsi/winnt-adspath
    - Invoke-Command -ComputerName / -ScriptBlock / -ArgumentList:
      https://learn.microsoft.com/powershell/module/microsoft.powershell.core/invoke-command
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
    [string]$ComputerName = $env:COMPUTERNAME,

    [string]$LogFolder,

    [switch]$Force,

    # Internal: dot-source the functions without running the main body.
    [switch]$LoadFunctionsOnly
)

# Set here, as Start-M365SyncedUserFixes.ps1 does, not as the parameter default: Windows
# PowerShell 5.1 leaves $PSScriptRoot empty while binding parameter defaults when the script
# is dot-sourced by a relative path, and Join-Path then fails before anything runs.
if (-not $LogFolder) { $LogFolder = Join-Path $PSScriptRoot 'Logs' }

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

# Reads ('Get') or changes ('Add', 'Remove') the built-in Administrators group through the
# ADSI WinNT provider. IADsGroup Members/Add/Remove:
# https://learn.microsoft.com/windows/win32/api/iads/nn-iads-iadsgroup
# ADsPath forms WinNT://<server>/<name>,group and WinNT://<domain>/<name>:
# https://learn.microsoft.com/windows/win32/adsi/winnt-adspath
$script:LocalAdminGroupScript = {
    param([string]$Operation, [string]$AdministratorsSid, [string]$Member)

    $ErrorActionPreference = 'Stop'
    try {
        $account = (New-Object System.Security.Principal.SecurityIdentifier($AdministratorsSid)).Translate([System.Security.Principal.NTAccount]).Value
        $groupName = $account.Substring($account.IndexOf('\') + 1)
        $group = [ADSI]("WinNT://$env:COMPUTERNAME/$groupName,group")

        if ($Operation -eq 'Get') {
            foreach ($m in @($group.psbase.Invoke('Members'))) {
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
            }
            return
        }

        # 'DOMAIN\Name' -> WinNT://DOMAIN/Name; a bare name is a local account on this computer.
        if ($Member -match '\\') {
            $memberPath = 'WinNT://' + ($Member -replace '\\', '/')
        } else {
            $memberPath = "WinNT://$env:COMPUTERNAME/$Member"
        }
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

function Test-IsLocalComputer {
    # True when the name means this computer, so the work runs in-process without remoting.
    param([AllowEmptyString()][AllowNull()][string]$ComputerName)

    $name = "$ComputerName".Trim()
    if (-not $name -or $name -eq '.' -or $name -eq 'localhost' -or $name -eq '127.0.0.1' -or $name -eq '::1') { return $true }
    if ($name -eq $env:COMPUTERNAME) { return $true }
    # FQDN of this computer (PC01.contoso.com).
    return ($name.Split('.')[0] -eq $env:COMPUTERNAME -and $name -notmatch '^\d+(\.\d+){3}$')
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

function Get-LocalAdminGroupName {
    # The localized name of the built-in Administrators group on the target computer.
    param([string]$ComputerName)
    Resolve-BuiltinAdministratorsName -Translator {
        param($sid)
        Invoke-OnTarget -ComputerName $ComputerName -ScriptBlock $script:SidToAccountScript -ArgumentList @($sid)
    }
}

function Get-LocalAdminMember {
    # Members of the built-in Administrators group on the target, as { Name, Sid } objects.
    # Name is empty for a member whose SID cannot be resolved.
    param([string]$ComputerName)
    Invoke-OnTarget -ComputerName $ComputerName -ScriptBlock $script:LocalAdminGroupScript -ArgumentList @('Get', $script:AdministratorsSid, '')
}

function Add-LocalAdminMember {
    param([string]$ComputerName, [string]$Member)
    Invoke-OnTarget -ComputerName $ComputerName -ScriptBlock $script:LocalAdminGroupScript -ArgumentList @('Add', $script:AdministratorsSid, $Member) | Out-Null
}

function Remove-LocalAdminMember {
    param([string]$ComputerName, [string]$Member)
    Invoke-OnTarget -ComputerName $ComputerName -ScriptBlock $script:LocalAdminGroupScript -ArgumentList @('Remove', $script:AdministratorsSid, $Member) | Out-Null
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
    # True when Member is in the list: by SID when a SID was given, otherwise by name
    # (case-insensitive). A name without a domain is a local account on the target.
    param([AllowEmptyCollection()][object[]]$Members, [string]$Member, [string]$ComputerName)

    $localName = "$($ComputerName.Split('.')[0])\$Member"
    foreach ($m in @($Members | Where-Object { $null -ne $_ })) {
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
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([ValidateSet('Add','Remove')][string]$Action, [string]$Member, [string]$ComputerName)

    $entry = New-LocalAdminChangeEntry -Action $Action -Member $Member -Target $ComputerName

    try {
        $group = Get-LocalAdminGroupName -ComputerName $ComputerName
        $entry.Target = "$ComputerName\$group"
        $before = @(Get-LocalAdminMember -ComputerName $ComputerName)
    } catch {
        $entry.Result = 'Failed'
        $entry.Error = "Could not read the local administrators group on ${ComputerName}: $($_.Exception.Message)"
        return [PSCustomObject]$entry
    }
    $entry.OldValue = Format-MemberList -Members $before

    $isMember = Test-IsAdminMember -Members $before -Member $Member -ComputerName $ComputerName
    if ($Action -eq 'Add' -and $isMember) {
        $entry.NewValue = $entry.OldValue
        $entry.Result = 'No change (already a member)'
        return [PSCustomObject]$entry
    }
    if ($Action -eq 'Remove' -and -not $isMember) {
        $entry.NewValue = $entry.OldValue
        $entry.Result = 'No change (not a member)'
        return [PSCustomObject]$entry
    }

    if (-not $PSCmdlet.ShouldProcess("$group on $ComputerName", "$Action $Member")) {
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
        $entry.NewValue = Format-MemberList -Members @(Get-LocalAdminMember -ComputerName $ComputerName)
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

function Test-LogFolderWritable {
    # Creates the folder if needed and probes it with a temporary file. Checked before any
    # change: if the change cannot be logged, it is not made (D-029).
    param([string]$LogFolder)

    try {
        if (-not (Test-Path -LiteralPath $LogFolder -PathType Container)) {
            New-Item -ItemType Directory -Path $LogFolder -Force -ErrorAction Stop -WhatIf:$false | Out-Null
        }
        $probe = Join-Path $LogFolder ('.write-test-{0}.tmp' -f [guid]::NewGuid().ToString('N'))
        New-Item -ItemType File -Path $probe -Force -ErrorAction Stop -WhatIf:$false | Out-Null
        Remove-Item -LiteralPath $probe -Force -ErrorAction Stop -WhatIf:$false
        return $true
    } catch {
        Write-Verbose "Log folder is not writable: $($_.Exception.Message)"
        return $false
    }
}

function Write-LocalAdminChangeLog {
    <#
    .SYNOPSIS
        Appends change rows to Changes_<yyyy-MM-dd>.csv in the log folder (one file per day,
        one header). Returns the path, or $null when nothing could be written.
    #>
    param([AllowEmptyCollection()][object[]]$Entries, [string]$LogFolder)

    $rows = @($Entries | Where-Object { $null -ne $_ } | ForEach-Object {
        $safe = [ordered]@{}
        foreach ($property in $_.PSObject.Properties) {
            $safe[$property.Name] = if ($property.Value -is [string]) { ConvertTo-CsvSafeText $property.Value } else { $property.Value }
        }
        [PSCustomObject]$safe
    })
    if ($rows.Count -eq 0) { return $null }

    try {
        if (-not (Test-Path -LiteralPath $LogFolder)) { New-Item -ItemType Directory -Path $LogFolder -Force -ErrorAction Stop | Out-Null }
        $path = Join-Path $LogFolder ("Changes_{0}.csv" -f (Get-Date -Format 'yyyy-MM-dd'))
        # -Append writes the header only when the file is new.
        $rows | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 -Append -ErrorAction Stop
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
    param([string]$Action, [string]$Member, [string]$ComputerName, [string]$LogFolder, [switch]$Force)

    if (-not (Test-Administrator)) {
        Write-Status -Level FAIL -Message 'This script must be run from an elevated PowerShell prompt (Run as administrator).'
        return 1
    }

    $target = if (Test-IsLocalComputer -ComputerName $ComputerName) { $env:COMPUTERNAME } else { $ComputerName }
    $dryRun = [bool]$WhatIfPreference

    if ($dryRun) {
        Write-Status -Level INFO -Message 'Dry run (-WhatIf): nothing will be changed and no change log is written.'
    } elseif (-not (Test-LogFolderWritable -LogFolder $LogFolder)) {
        # Fail closed (D-029): a change that cannot be logged is not made.
        Write-Status -Level FAIL -Message "Cannot write the change log in $LogFolder. Nothing was changed. Use -LogFolder to choose a folder you can write to."
        return 1
    }

    $verb = if ($Action -eq 'Add') { 'add' } else { 'remove' }
    $direction = if ($Action -eq 'Add') { 'to' } else { 'from' }
    try {
        $group = Get-LocalAdminGroupName -ComputerName $target
        $count = @(Get-LocalAdminMember -ComputerName $target).Count
        Write-Status -Level WARN -Message "This will $verb $Member $direction the local administrators group ($group) on $target (currently $count members)."
    } catch {
        # Set-LocalAdminMembership reads the group again and records the failure.
        Write-Status -Level INFO -Message "Could not read the local administrators group on ${target}: $($_.Exception.Message)"
    }

    if ($Force) { $ConfirmPreference = 'None' }
    $entry = Set-LocalAdminMembership -Action $Action -Member $Member -ComputerName $target

    if ($entry.Result -like 'Skipped (WhatIf)*') {
        Write-Status -Level INFO -Message "WhatIf: would $verb $Member $direction the local administrators group on $target. Nothing was changed."
        return 0
    }

    $logPath = Write-LocalAdminChangeLog -Entries @($entry) -LogFolder $LogFolder
    $logText = if ($logPath) { " Logged to $logPath" } else { " The change log could not be written in $LogFolder." }

    switch -Wildcard ($entry.Result) {
        'Done' {
            $past = if ($Action -eq 'Add') { 'Added' } else { 'Removed' }
            $text = "$past $Member $direction $($entry.Target) on $target."
            if ($entry.Error) { $text += " $($entry.Error)" }
            if (-not $logPath) { Write-Status -Level FAIL -Message ($text + $logText); return 1 }
            Write-Status -Level PASS -Message ($text + $logText)
            return 0
        }
        'No change*' {
            $why = if ($Action -eq 'Add') { 'is already a member of' } else { 'is not a member of' }
            $text = "No change: $Member $why $($entry.Target)."
            if (-not $logPath) { Write-Status -Level FAIL -Message ($text + $logText); return 1 }
            Write-Status -Level PASS -Message ($text + $logText)
            return 0
        }
        'Skipped*' {
            Write-Status -Level WARN -Message ("Not confirmed: $Member was not changed on $target." + $logText)
            return 1
        }
        default {
            Write-Status -Level FAIL -Message ("Could not $verb $Member $direction the local administrators group on ${target}: $($entry.Error)" + $logText)
            return 1
        }
    }
}

#endregion

if ($LoadFunctionsOnly) { return }

exit (Invoke-LocalAdminManagerMain -Action $Action -Member $Member -ComputerName $ComputerName -LogFolder $LogFolder -Force:$Force -WhatIf:$WhatIfPreference)
