# 3.0 so the command-line script can share this file on old file servers (Server 2012 ships
# PowerShell 3.0). No ::new(), classes or .ForEach()/.Where() here; Tests\PSVersionFloor.Tests.ps1
# guards it. The GUI that dot-sources it declares 5.1 on its own.
#Requires -Version 3.0

<#
.SYNOPSIS
    Shared logic for FolderPermissionManager: permission backups, the change log, the
    single-item permission changes (add, remove, take ownership, copy), and taking ownership
    of a whole folder tree.
.DESCRIPTION
    Dot-sourced by FolderPermissionManager-GUI.ps1 and FolderPermissionManager.ps1. Nothing
    here draws UI.

    EVERY CHANGE IS BACKED UP AND LOGGED
    Before a change, the current permissions of every item about to change are saved as SDDL
    to <LogFolder>\Backups\<yyyy-MM-dd_HHmmss>_<Action>.csv (columns Path, ItemType, Sddl),
    and the file is read back to check it. If that fails, nothing is changed. An item whose
    permissions cannot be read is not changed either, except by Take ownership, which exists
    for folders you are locked out of. As each item completes, one row is appended to
    <LogFolder>\Changes_<yyyy-MM-dd>.csv with the SDDL before and after
    (Invoke-LoggedPermissionChange), so an interrupted batch still leaves a log.

    Taking ownership of a folder and all its subfolders and files (Set-ItemOwnerToCurrentUser
    -Recurse) first saves the owner of every item to
    <LogFolder>\Backups\<yyyy-MM-dd_HHmmss>_TakeOwnership.csv (Path, ItemType, Owner,
    OwnerSid), because icacls /save does not store owners. It logs one row for the whole
    folder (ItemType 'Folder tree', Result Done, Partly done or Failed).

    The change-log columns are shared with other tools that change things (LocalAdminManager):
    Time, Technician, Computer, Action, Target, ItemType, Detail, OldValue, NewValue, Result,
    Error, BackupFile.

    The change functions never throw: each returns one row per item, and that row is also the
    change-log entry (same pattern as Set-SyncedUserMarker in M365-SyncedUserFixes).
.PARAMETER LoadFunctionsOnly
    Define the functions and return (used by the GUI and the tests).
.EXAMPLE
    . .\FolderPermissions.Core.ps1 -LoadFunctionsOnly
    $result = Invoke-LoggedPermissionChange -LogFolder $log -Change {
        Add-FolderPermission -Path 'D:\Data\HR' -Identity 'CONTOSO\HR-Staff' -Rights Modify -LogFolder $log
    }
    Get-ChangeResultMessage -Entries $result.Entries -LogPath $result.LogPath -LogFolder $log
.NOTES
    REFERENCES
    - Get-Acl: -LiteralPath takes the path exactly as typed (no wildcards, so "HR [old]"
      works); the Sddl property holds the whole security descriptor as text; the SACL is only
      read with -Audit, so these backups hold owner, group and DACL:
      https://learn.microsoft.com/powershell/module/microsoft.powershell.security/get-acl
    - Set-Acl: -LiteralPath, -AclObject, -WhatIf:
      https://learn.microsoft.com/powershell/module/microsoft.powershell.security/set-acl
    - Export-Csv -NoClobber (never overwrite an existing backup) and Import-Csv (read it back):
      https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/export-csv
      https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/import-csv
    - ObjectSecurity.SetSecurityDescriptorSddlForm (restoring a backed-up SDDL onto an ACL
      object) and GetSecurityDescriptorSddlForm:
      https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.objectsecurity.setsecuritydescriptorsddlform
      https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.objectsecurity.getsecuritydescriptorsddlform
    - RemoveAccessRuleAll removes every rule for the rule's account, whatever its rights:
      https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.filesystemsecurity.removeaccessruleall
      https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.commonobjectsecurity.removeaccessruleall
    - takeown /F /R /A /D Y (/R recursive over all files in the directory and subdirectories;
      /A gives ownership to the Administrators group; /D Y answers "take ownership" for
      folders the account cannot list, and is documented for use with /R; the page lists no
      exit codes, so anything but 0 is treated as a failure):
      https://learn.microsoft.com/windows-server/administration/windows-commands/takeown
    - SeRestorePrivilege is what lets an account set any user or group as the owner:
      https://learn.microsoft.com/windows/win32/secauthz/privilege-constants
    - icacls (/save stores DACLs only, so owners need their own snapshot; /restore takes the
      parent directory; /setowner changes the owner of all matching files; /T includes
      subfolders and files; /C continues after file errors; /Q suppresses success messages;
      a SID is given as *S-1-...):
      https://learn.microsoft.com/windows-server/administration/windows-commands/icacls
      NOT VERIFIED: the page documents neither icacls exit codes nor its closing line
      "Successfully processed N files; Failed processing M files". Invoke-TreeOwnershipChange
      reads both defensively (see the comment there).
    - ObjectSecurity.GetOwner (SecurityIdentifier always; NTAccount throws
      IdentityNotMappedException for a deleted account) and WindowsIdentity.Name
      (DOMAIN\USERNAME):
      https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.objectsecurity.getowner
      https://learn.microsoft.com/dotnet/api/system.security.principal.windowsidentity.name
    - Get-ChildItem -Force (hidden and system items too, no security override):
      https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-childitem
    - DriveInfo.DriveType (Fixed, Network, Removable, ...) and
      Environment.SpecialFolder.LocalApplicationData, used to pick a local log folder:
      https://learn.microsoft.com/dotnet/api/system.io.driveinfo.drivetype
      https://learn.microsoft.com/dotnet/api/system.environment.specialfolder
#>
[CmdletBinding()]
param(
    [switch]$LoadFunctionsOnly
)

#region Log folder

function Test-LogFolderWritable {
    <#
    .SYNOPSIS
        True when a file can be created in the folder (the folder is created if missing).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    try {
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null }
        $probe = Join-Path $Path ('.write-test-{0}.tmp' -f [guid]::NewGuid().ToString('N'))
        Set-Content -LiteralPath $probe -Value '' -ErrorAction Stop
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        Write-Verbose "Log folder '$Path' is not writable: $($_.Exception.Message)"
        return $false
    }
}

function Test-LocalFixedPath {
    <#
    .SYNOPSIS
        True when the path is on a local fixed disk: not a UNC path, not a mapped network
        drive, not a removable or optical drive.
        https://learn.microsoft.com/dotnet/api/system.io.driveinfo.drivetype
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)

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
        Picks the folder for backups and the change log: -LogFolder as given, else Logs next to
        the script, else %LOCALAPPDATA%\FolderPermissionManager\Logs.
    .DESCRIPTION
        The Logs folder next to the script is only used when it is on a local fixed disk and
        can be written to. Techs often run the tool from a share or a bundle copy: backups are
        fail-closed, so an unwritable folder would block every change, and logs on a share
        would put client paths and account names wherever the share is readable.
        Throws a plain message when there is no local folder to fall back to.
    #>
    [CmdletBinding()]
    param(
        [string]$LogFolder,
        [string]$DefaultFolder = (Join-Path $PSScriptRoot 'Logs')
    )

    if ($LogFolder) { return $LogFolder }
    if ((Test-LocalFixedPath -Path $DefaultFolder) -and (Test-LogFolderWritable -Path $DefaultFolder)) { return $DefaultFolder }
    $local = Get-LocalAppDataFolder
    if (-not $local) {
        throw "There is no folder on this computer to save permission backups and the change log in, so no change could be made safely. Start the tool again with -LogFolder and a local folder you can write to, for example -LogFolder 'C:\Temp\FolderPermissionManager'."
    }
    Join-Path $local 'FolderPermissionManager\Logs'
}

function Get-ChangeLogFolderNotice {
    <#
    .SYNOPSIS
        The [WARN] lines to print at startup about the log folder (empty when all is well).
    #>
    [CmdletBinding()]
    param(
        [string]$LogFolder,
        [Parameter(Mandatory)][string]$ResolvedFolder,
        [Parameter(Mandatory)][string]$DefaultFolder
    )

    if ($LogFolder) {
        if (-not (Test-LocalFixedPath -Path $LogFolder)) {
            "The log folder $LogFolder is on a network drive or share. Backups and the change log hold client paths and account names, and every change is refused while that folder cannot be written."
        }
    } elseif ($ResolvedFolder -ne $DefaultFolder) {
        if (-not (Test-LocalFixedPath -Path $DefaultFolder)) {
            "This script is running from a network or removable location, so backups and the change log go to $ResolvedFolder on this computer instead of $DefaultFolder."
        } else {
            "The Logs folder next to this script ($DefaultFolder) cannot be written to, so backups and the change log go to $ResolvedFolder instead."
        }
    }
}

#endregion

#region Change entries, backups and the native-tool wrapper

function ConvertTo-CsvSafeText {
    <#
    .SYNOPSIS
        Prefixes text that Excel would run as a formula (starts with = + - @, tab or carriage
        return) with a single quote. Used for every text value written to the log and backups:
        a target typed as "=1+1" must not run when the CSV is opened.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ($Text -match '^[=+\-@\t\r]') { "'" + $Text } else { $Text }
}

function ConvertFrom-CsvSafeText {
    # The reverse of ConvertTo-CsvSafeText: drops the quote only when it guards one of those characters.
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ($Text -match "^'[=+\-@\t\r]") { $Text.Substring(1) } else { $Text }
}

function Format-Sentence {
    # Trimmed, and ending in a full stop, so it can be followed by another sentence.
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $t = "$Text".Trim()
    if ($t -and $t -notmatch '[.!?]$') { $t += '.' }
    $t
}

function New-PermissionChangeEntry {
    <#
    .SYNOPSIS
        One change-log row with the shared column set, in the shared order.
    .DESCRIPTION
        Values are kept as they are; Write-PermissionChangeLog makes them safe for Excel when
        it writes the file, so the GUI shows the real path and error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Target,
        [Parameter(Mandatory)][string]$ItemType,
        [string]$Detail = '',
        [string]$OldValue = '',
        [string]$NewValue = '',
        [string]$Result = '',
        # Not $Error: that is PowerShell's automatic error list. -Error still works.
        [Alias('Error')][string]$ErrorText = '',
        [string]$BackupFile = ''
    )

    [PSCustomObject][ordered]@{
        Time       = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        # Not $env:USERDOMAIN\$env:USERNAME: those are wrong under SYSTEM and service accounts.
        Technician = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Computer   = $env:COMPUTERNAME
        Action     = $Action
        Target     = $Target
        ItemType   = $ItemType
        Detail     = $Detail
        OldValue   = $OldValue
        NewValue   = $NewValue
        Result     = $Result
        Error      = $ErrorText
        BackupFile = $BackupFile
    }
}

function Invoke-AclTool {
    <#
    .SYNOPSIS
        Runs icacls.exe or takeown.exe and returns ExitCode and Output. A thin wrapper so the
        tests can mock native commands.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('icacls', 'takeown')][string]$Tool,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    $exe = Join-Path $env:SystemRoot "System32\$Tool.exe"
    $output = & $exe @Arguments 2>&1
    [PSCustomObject]@{
        ExitCode = $LASTEXITCODE
        Output   = (@($output) | ForEach-Object { "$_" }) -join "`r`n"
    }
}

function Get-AclItemType {
    # 'Folder', 'File', or $null when the path is empty or does not exist.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if (Test-Path -LiteralPath $Path -PathType Container) { return 'Folder' }
    if (Test-Path -LiteralPath $Path -PathType Leaf) { return 'File' }
    $null
}

function Get-ItemSddl {
    # The item's SDDL, or 'Could not read'. -LiteralPath: with -Path, "HR [old]" is read as a
    # wildcard and matches nothing. The SACL is only read with -Audit, so this is owner, group
    # and DACL. https://learn.microsoft.com/powershell/module/microsoft.powershell.security/get-acl
    param([Parameter(Mandatory)][string]$Path)
    try { (Get-Acl -LiteralPath $Path -ErrorAction Stop).Sddl } catch { 'Could not read' }
}

function New-BackupFilePath {
    <#
    .SYNOPSIS
        A new, unused <LogFolder>\Backups\<yyyy-MM-dd_HHmmss>_<ActionSlug>.csv path (the
        Backups folder is created if missing). Throws when the folder cannot be created.
    #>
    param(
        [Parameter(Mandatory)][string]$LogFolder,
        [Parameter(Mandatory)][string]$ActionSlug
    )

    $folder = Join-Path $LogFolder 'Backups'
    if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop | Out-Null }

    # Two actions in the same second must not overwrite each other's backup; the callers'
    # Export-Csv -NoClobber makes sure of it even if another copy of the tool creates the same
    # name in between.
    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $file = Join-Path $folder ('{0}_{1}.csv' -f $stamp, $ActionSlug)
    $n = 2
    while (Test-Path -LiteralPath $file) {
        $file = Join-Path $folder ('{0}_{1}_{2}.csv' -f $stamp, $ActionSlug, $n)
        $n++
    }
    $file
}

function Save-AclBackup {
    <#
    .SYNOPSIS
        Saves the current SDDL of each item to <LogFolder>\Backups\<yyyy-MM-dd_HHmmss>_<ActionSlug>.csv
        (Path, ItemType, Sddl), reads the file back to check it, and returns its path. Throws
        when the file cannot be written or does not hold what was read; callers must then
        change nothing.
    .DESCRIPTION
        An item whose permissions cannot be read is listed with Sddl 'Could not read' and does
        not stop the backup of the others (owner decision D-027). It cannot be restored from
        this backup.

        A Path starting with = + - @, tab or carriage return is saved with a leading single
        quote (ConvertTo-CsvSafeText); the README restore steps remove it.

        Restore one item: $acl = Get-Acl -LiteralPath $p; $acl.SetSecurityDescriptorSddlForm($sddl);
        Set-Acl -LiteralPath $p -AclObject $acl
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Path,
        [Parameter(Mandatory)][string]$ActionSlug,
        [Parameter(Mandatory)][string]$LogFolder
    )

    $rows = @(foreach ($p in $Path) {
        [PSCustomObject][ordered]@{ Path = $p; ItemType = (Get-AclItemType -Path $p); Sddl = (Get-ItemSddl -Path $p) }
    })

    $file = New-BackupFilePath -LogFolder $LogFolder -ActionSlug $ActionSlug

    $rows | ForEach-Object { [PSCustomObject][ordered]@{ Path = (ConvertTo-CsvSafeText $_.Path); ItemType = $_.ItemType; Sddl = $_.Sddl } } |
        Export-Csv -LiteralPath $file -NoTypeInformation -Encoding UTF8 -NoClobber -ErrorAction Stop

    # A backup that cannot be read back is no backup: check it before anything changes.
    $saved = @(Import-Csv -LiteralPath $file -ErrorAction Stop)
    if ($saved.Count -ne $rows.Count) {
        throw "the backup file $file holds $($saved.Count) of $($rows.Count) items"
    }
    for ($i = 0; $i -lt $rows.Count; $i++) {
        if ((ConvertFrom-CsvSafeText $saved[$i].Path) -cne $rows[$i].Path -or $saved[$i].Sddl -cne $rows[$i].Sddl) {
            throw "the backup file $file does not hold the permissions read from $($rows[$i].Path)"
        }
    }
    $file
}

function Get-BackupFailureText {
    param([Parameter(Mandatory)][string]$LogFolder, [Parameter(Mandatory)][string]$Reason)
    "Could not save a backup of the current permissions to $(Join-Path $LogFolder 'Backups'): $($Reason.Trim().TrimEnd('.')). Nothing was changed."
}

function Get-ItemOwner {
    <#
    .SYNOPSIS
        The item's owner as Owner (account name) and OwnerSid, or Owner 'Could not read' and an
        empty OwnerSid.
    .DESCRIPTION
        GetOwner([SecurityIdentifier]) always works once the security descriptor is read;
        GetOwner([NTAccount]) throws IdentityNotMappedException for an owner whose account was
        deleted, and then the SID is used as the name.
        https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.objectsecurity.getowner
    #>
    param([Parameter(Mandatory)][string]$Path)

    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $sid = "$($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value)"
    } catch {
        $sid = ''
    }
    if (-not $sid) { return [PSCustomObject]@{ Owner = 'Could not read'; OwnerSid = '' } }
    try { $name = "$($acl.GetOwner([System.Security.Principal.NTAccount]).Value)" } catch { $name = '' }
    if (-not $name) { $name = $sid }
    [PSCustomObject]@{ Owner = $name; OwnerSid = $sid }
}

function Save-OwnerSnapshot {
    <#
    .SYNOPSIS
        Saves the owner of a folder and of every folder and file under it to
        <LogFolder>\Backups\<yyyy-MM-dd_HHmmss>_TakeOwnership.csv (Path, ItemType, Owner,
        OwnerSid), reads the file back to check it, and returns File, Count, Unreadable and
        Unlisted. Throws when the file cannot be written or does not hold what was read;
        callers must then change nothing.
    .DESCRIPTION
        Needed because icacls /save stores DACLs only, not owners.
        https://learn.microsoft.com/windows-server/administration/windows-commands/icacls

        An item whose owner cannot be read is listed with Owner 'Could not read' and does not
        stop the snapshot (owner decision D-027); Unreadable counts them. A folder that cannot
        be opened is in the snapshot, but what is inside it is not; Unlisted counts those
        folders. -Force includes hidden and system files, which takeown /R also changes.
        https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-childitem

        Restore: see "Undo a change" in the README (Set-Acl with the saved OwnerSid, or
        icacls <path> /setowner *<OwnerSid>).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$LogFolder
    )

    $listErrors = $null
    $children = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable listErrors)
    $rows = @(
        $owner = Get-ItemOwner -Path $Path
        [PSCustomObject][ordered]@{ Path = $Path; ItemType = 'Folder'; Owner = $owner.Owner; OwnerSid = $owner.OwnerSid }
        foreach ($child in $children) {
            $owner = Get-ItemOwner -Path $child.FullName
            $type = if ($child.PSIsContainer) { 'Folder' } else { 'File' }
            [PSCustomObject][ordered]@{ Path = $child.FullName; ItemType = $type; Owner = $owner.Owner; OwnerSid = $owner.OwnerSid }
        }
    )

    $file = New-BackupFilePath -LogFolder $LogFolder -ActionSlug 'TakeOwnership'
    $rows | ForEach-Object {
        [PSCustomObject][ordered]@{ Path = (ConvertTo-CsvSafeText $_.Path); ItemType = $_.ItemType; Owner = (ConvertTo-CsvSafeText $_.Owner); OwnerSid = $_.OwnerSid }
    } | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding UTF8 -NoClobber -ErrorAction Stop

    # A backup that cannot be read back is no backup: check it before anything changes.
    $saved = @(Import-Csv -LiteralPath $file -ErrorAction Stop)
    if ($saved.Count -ne $rows.Count) {
        throw "the backup file $file holds $($saved.Count) of $($rows.Count) items"
    }
    for ($i = 0; $i -lt $rows.Count; $i++) {
        if ((ConvertFrom-CsvSafeText $saved[$i].Path) -cne $rows[$i].Path -or $saved[$i].OwnerSid -cne $rows[$i].OwnerSid) {
            throw "the backup file $file does not hold the owner read from $($rows[$i].Path)"
        }
    }
    [PSCustomObject]@{
        File       = $file
        Count      = $rows.Count
        Unreadable = @($rows | Where-Object { $_.Owner -eq 'Could not read' }).Count
        Unlisted   = @($listErrors | Where-Object { $null -ne $_ }).Count
    }
}

function Get-AclToolSummary {
    <#
    .SYNOPSIS
        The part of a native tool's output worth showing and logging: blank lines and per-item
        "SUCCESS:" lines (takeown prints one per item) dropped, and at most -MaxLines lines,
        always keeping the last one (icacls ends with its "Successfully processed ..." count).
    #>
    param([AllowNull()][AllowEmptyString()][string]$Output, [int]$MaxLines = 5)

    $lines = @("$Output" -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^SUCCESS:' })
    if ($lines.Count -gt $MaxLines) {
        $hidden = $lines.Count - $MaxLines
        $lines = @($lines[0..($MaxLines - 2)]) + "(and $hidden more lines)" + $lines[-1]
    }
    $lines -join ' '
}

#endregion

#region Single-item changes

function Invoke-SingleItemAclChange {
    <#
    .SYNOPSIS
        The shared flow of every single-item change: skip missing items, ask ShouldProcess per
        item, refuse items whose permissions cannot be read (unless -ProceedWhenUnreadable),
        back up everything that will change (or change nothing), then change and read back
        each item. One row per item, written to the pipeline as each item completes; a
        failure on one item does not stop the rest.
    .PARAMETER Change
        Script block run per item with ($Path, $ItemType) that makes the change and throws on
        failure. It runs in a child scope of the calling change function, so it can use that
        function's parameters.
    .PARAMETER ProceedWhenUnreadable
        Change items whose current permissions cannot be read; the backup lists them as
        'Could not read' (D-027). Only Take ownership uses this: it exists for folders the
        administrator is locked out of.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Management.Automation.PSCmdlet]$Cmdlet,
        [Parameter(Mandatory)][AllowEmptyString()][AllowEmptyCollection()][string[]]$Path,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$ActionSlug,
        [Parameter(Mandatory)][string]$Detail,
        [Parameter(Mandatory)][string]$LogFolder,
        [Parameter(Mandatory)][scriptblock]$Change,
        [switch]$ProceedWhenUnreadable
    )

    $items = @(foreach ($p in $Path) {
        $itemType = Get-AclItemType -Path $p
        $state = if (-not $itemType) { 'NotFound' }
                 elseif ($Cmdlet.ShouldProcess($p, "$Action ($Detail)")) { 'Change' }
                 else { 'WhatIf' }
        $readError = $null
        if ($state -eq 'Change' -and -not $ProceedWhenUnreadable) {
            try { $null = Get-Acl -LiteralPath $p -ErrorAction Stop } catch { $state = 'Unreadable'; $readError = $_.Exception.Message }
        }
        [PSCustomObject]@{ Path = $p; ItemType = $itemType; State = $state; ReadError = $readError }
    })
    $toChange = @($items | Where-Object { $_.State -eq 'Change' })

    $backupFile = ''
    $backupError = $null
    if ($toChange.Count -gt 0) {
        try {
            $backupFile = Save-AclBackup -Path @($toChange | ForEach-Object { $_.Path }) -ActionSlug $ActionSlug -LogFolder $LogFolder
        } catch {
            $backupError = Get-BackupFailureText -LogFolder $LogFolder -Reason $_.Exception.Message
        }
    }

    foreach ($item in $items) {
        if ($item.State -eq 'NotFound') {
            $why = if ([string]::IsNullOrWhiteSpace($item.Path)) { 'No path was given.' } else { 'The folder or file does not exist.' }
            New-PermissionChangeEntry -Action $Action -Target "$($item.Path)" -ItemType 'Unknown' -Detail $Detail `
                -Result 'Skipped (not found)' -ErrorText $why
            continue
        }
        if ($item.State -eq 'WhatIf') {
            New-PermissionChangeEntry -Action $Action -Target $item.Path -ItemType $item.ItemType -Detail $Detail -Result 'Skipped (WhatIf)'
            continue
        }
        if ($item.State -eq 'Unreadable') {
            New-PermissionChangeEntry -Action $Action -Target $item.Path -ItemType $item.ItemType -Detail $Detail `
                -OldValue 'Could not read' -Result 'Failed' `
                -ErrorText ("Could not read the current permissions, so nothing was changed. $(Format-Sentence $item.ReadError)".Trim())
            continue
        }
        if ($backupError) {
            New-PermissionChangeEntry -Action $Action -Target $item.Path -ItemType $item.ItemType -Detail $Detail `
                -Result 'Failed' -ErrorText $backupError
            continue
        }

        $old = Get-ItemSddl -Path $item.Path
        try {
            $null = & $Change $item.Path $item.ItemType
        } catch {
            # Say what state the item was left in: a change can fail half-way (takeown gave the
            # folder to Administrators, then setting the final owner failed).
            $after = Get-ItemSddl -Path $item.Path
            $text = Format-Sentence $_.Exception.Message
            if ($after -eq 'Could not read') {
                $text += ' The permissions could not be read afterwards, so check whether anything was changed.'
            } elseif ($after -cne $old) {
                $text += ' The permissions were partly changed and no longer match the backup.'
            }
            New-PermissionChangeEntry -Action $Action -Target $item.Path -ItemType $item.ItemType -Detail $Detail `
                -OldValue $old -NewValue $after -Result 'Failed' -ErrorText $text -BackupFile $backupFile
            continue
        }
        New-PermissionChangeEntry -Action $Action -Target $item.Path -ItemType $item.ItemType -Detail $Detail `
            -OldValue $old -NewValue (Get-ItemSddl -Path $item.Path) -Result 'Done' -BackupFile $backupFile
    }
}

function New-PermissionRule {
    # Folders get ContainerInherit, ObjectInherit (this folder, subfolders and files); files get
    # no inheritance flags. Same rules the GUI has always added.
    param([string]$Identity, [string]$Rights, [string]$Type, [string]$ItemType)
    $inheritance = if ($ItemType -eq 'Folder') { 'ContainerInherit, ObjectInherit' } else { 'None' }
    New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
        (New-Object System.Security.Principal.NTAccount -ArgumentList $Identity),
        [System.Security.AccessControl.FileSystemRights]$Rights,
        [System.Security.AccessControl.InheritanceFlags]$inheritance,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]$Type)
}

function Add-FolderPermission {
    <#
    .SYNOPSIS
        Adds an Allow or Deny rule to each folder or file. Backed up first; one row per item.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][AllowEmptyCollection()][string[]]$Path,
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][string]$Rights,
        [ValidateSet('Allow', 'Deny')][string]$Type = 'Allow',
        [Parameter(Mandatory)][string]$LogFolder
    )

    Invoke-SingleItemAclChange -Cmdlet $PSCmdlet -Path $Path -Action 'Add permission' -ActionSlug 'AddPermission' `
        -Detail "$Type $Rights for $Identity" -LogFolder $LogFolder -Change {
        param($p, $itemType)
        $acl = Get-Acl -LiteralPath $p -ErrorAction Stop
        $acl.AddAccessRule((New-PermissionRule -Identity $Identity -Rights $Rights -Type $Type -ItemType $itemType))
        Set-Acl -LiteralPath $p -AclObject $acl -ErrorAction Stop
    }
}

function Remove-FolderPermission {
    <#
    .SYNOPSIS
        Removes the identity's Allow or Deny rules from each folder or file. Backed up first;
        one row per item.
    .DESCRIPTION
        Uses RemoveAccessRuleAll, as the GUI always has: every explicit rule of that type
        (Allow or Deny) for the identity goes, whatever its rights; -Rights only names what the
        technician asked for and is recorded in Detail. Inherited rules are not affected.
        https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.filesystemsecurity.removeaccessruleall
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][AllowEmptyCollection()][string[]]$Path,
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][string]$Rights,
        [ValidateSet('Allow', 'Deny')][string]$Type = 'Allow',
        [Parameter(Mandatory)][string]$LogFolder
    )

    Invoke-SingleItemAclChange -Cmdlet $PSCmdlet -Path $Path -Action 'Remove permission' -ActionSlug 'RemovePermission' `
        -Detail "$Type $Rights for $Identity" -LogFolder $LogFolder -Change {
        param($p, $itemType)
        $acl = Get-Acl -LiteralPath $p -ErrorAction Stop
        $acl.RemoveAccessRuleAll((New-PermissionRule -Identity $Identity -Rights $Rights -Type $Type -ItemType $itemType))
        Set-Acl -LiteralPath $p -AclObject $acl -ErrorAction Stop
    }
}

function Set-ItemOwnerToCurrentUser {
    <#
    .SYNOPSIS
        Takes ownership of each folder or file for the account running the tool: this item
        only, or with -Recurse the folder and everything under it. Backed up first.
    .DESCRIPTION
        This item only (one row per item): takeown /A first gives ownership to Administrators,
        which lets an administrator open an item they are locked out of; the owner is then set
        to the current account with Set-Acl. If that second step fails after takeown succeeded,
        the item is left owned by Administrators and the row says so. An item whose permissions
        could not be read beforehand is still changed and is listed as 'Could not read' in the
        backup (D-027).

        -Recurse (one row per folder, see Invoke-TreeOwnershipChange): the owner of every item
        is saved to an owner snapshot first, then takeown /R and icacls /setowner /T change the
        whole tree.
        https://learn.microsoft.com/windows-server/administration/windows-commands/takeown
    .PARAMETER Recurse
        Take ownership of each folder and of all its subfolders and files.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][AllowEmptyCollection()][string[]]$Path,
        [Parameter(Mandatory)][string]$LogFolder,
        [switch]$Recurse
    )

    if ($Recurse) {
        foreach ($p in $Path) { Invoke-TreeOwnershipChange -Cmdlet $PSCmdlet -Path $p -LogFolder $LogFolder }
        return
    }
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    Invoke-SingleItemAclChange -Cmdlet $PSCmdlet -Path $Path -Action 'Take ownership' -ActionSlug 'TakeOwnership' `
        -Detail "Owner set to $($me.Name)" -LogFolder $LogFolder -ProceedWhenUnreadable -Change {
        param($p, $itemType)
        # Same arguments the GUI has always used. A takeown failure is not fatal on its own:
        # Set-Acl below is what sets the final owner, and an administrator who already has
        # access does not need takeown.
        $tool = Invoke-AclTool -Tool takeown -Arguments @('/F', $p, '/A', '/D', 'Y')
        try {
            $acl = Get-Acl -LiteralPath $p -ErrorAction Stop
            $acl.SetOwner($me.User)
            Set-Acl -LiteralPath $p -AclObject $acl -ErrorAction Stop
        } catch {
            $reason = Format-Sentence $_.Exception.Message
            if ($tool.ExitCode -eq 0) {
                throw "Ownership was given to Administrators by takeown but could not be set to $($me.Name): $reason"
            }
            $said = if ("$($tool.Output)".Trim()) { " takeown also failed (exit code $($tool.ExitCode)): $(Format-Sentence $tool.Output)" } else { " takeown also failed (exit code $($tool.ExitCode))." }
            throw "$reason$said"
        }
    }
}

function Copy-FolderPermission {
    <#
    .SYNOPSIS
        Copies the source folder's rules onto each target (this folder only): rules the target
        does not already have are added, nothing is removed. Backed up first; one row per target.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$SourcePath,
        [Parameter(Mandatory)][AllowEmptyString()][AllowEmptyCollection()][string[]]$TargetPath,
        [Parameter(Mandatory)][string]$LogFolder
    )

    $detail = "Permissions copied from $SourcePath"
    try {
        if ([string]::IsNullOrWhiteSpace($SourcePath)) { throw 'No source folder was given.' }
        $sourceAcl = Get-Acl -LiteralPath $SourcePath -ErrorAction Stop
    } catch {
        $reason = "Could not read the permissions of the source folder $($SourcePath): $(Format-Sentence $_.Exception.Message) Nothing was changed."
        foreach ($t in $TargetPath) {
            $itemType = Get-AclItemType -Path $t
            if (-not $itemType) { $itemType = 'Unknown' }
            New-PermissionChangeEntry -Action 'Copy permissions' -Target "$t" -ItemType $itemType -Detail $detail -Result 'Failed' -ErrorText $reason
        }
        return
    }
    $sourceRules = @($sourceAcl.Access)

    Invoke-SingleItemAclChange -Cmdlet $PSCmdlet -Path $TargetPath -Action 'Copy permissions' -ActionSlug 'CopyPermissions' `
        -Detail $detail -LogFolder $LogFolder -Change {
        param($p, $itemType)
        $acl = Get-Acl -LiteralPath $p -ErrorAction Stop
        foreach ($rule in $sourceRules) {
            $exists = @($acl.Access | Where-Object {
                $_.IdentityReference -eq $rule.IdentityReference -and
                $_.FileSystemRights -eq $rule.FileSystemRights -and
                $_.AccessControlType -eq $rule.AccessControlType -and
                $_.InheritanceFlags -eq $rule.InheritanceFlags -and
                $_.PropagationFlags -eq $rule.PropagationFlags
            })
            if ($exists.Count -eq 0) { $acl.AddAccessRule($rule) }
        }
        Set-Acl -LiteralPath $p -AclObject $acl -ErrorAction Stop
    }
}

#endregion

#region Whole-tree changes

function Test-TreeChangeEntry {
    # True for the row of a whole-tree action ("... (all subfolders and files)"): one row for
    # the whole folder, with the full before-state in the backup file instead of OldValue.
    param([Parameter(Mandatory)][AllowNull()][object]$Entry)
    $null -ne $Entry -and "$($Entry.Action)" -like '* (all subfolders and files)'
}

function Invoke-TreeOwnershipChange {
    <#
    .SYNOPSIS
        Takes ownership of a folder and everything under it for the account running the tool,
        after saving every item's owner. Returns one row for the whole folder and never throws.
    .DESCRIPTION
        1. ShouldProcess once for the folder (-WhatIf: nothing is read, written or changed).
        2. Save-OwnerSnapshot: if it cannot be written and checked, nothing is changed.
        3. takeown /F <dir> /R /A /D Y gives every item to Administrators, so an administrator
           can open items they are locked out of.
        4. icacls <dir> /setowner <DOMAIN\user> /T /C /Q makes the current account the owner.
           The full name from WindowsIdentity, not $env:USERNAME, which has no domain and is
           wrong under SYSTEM and service accounts.
        Both tools run even if takeown reports errors (as the GUI always did): icacls is what
        sets the final owner. Result is Done when both succeed, Partly done when one of them
        reported errors but something was changed, and Failed when nothing succeeded. Error
        holds the tools' own summary.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Management.Automation.PSCmdlet]$Cmdlet,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Path,
        [Parameter(Mandatory)][string]$LogFolder
    )

    $action = 'Take ownership (all subfolders and files)'
    # WindowsIdentity.Name is the logon name in DOMAIN\USERNAME form.
    # https://learn.microsoft.com/dotnet/api/system.security.principal.windowsidentity.name
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $detail = "Owner set to $me on the folder and all subfolders and files"

    $itemType = Get-AclItemType -Path $Path
    if (-not $itemType) {
        $why = if ([string]::IsNullOrWhiteSpace($Path)) { 'No path was given.' } else { 'The folder does not exist.' }
        return New-PermissionChangeEntry -Action $action -Target "$Path" -ItemType 'Unknown' -Detail $detail `
            -Result 'Skipped (not found)' -ErrorText $why
    }
    if ($itemType -eq 'File') {
        return New-PermissionChangeEntry -Action $action -Target $Path -ItemType 'File' -Detail $detail -Result 'Failed' `
            -ErrorText "$Path is a file, not a folder: take ownership of this item only instead. Nothing was changed."
    }
    if (-not $Cmdlet.ShouldProcess($Path, "$action ($detail)")) {
        return New-PermissionChangeEntry -Action $action -Target $Path -ItemType 'Folder tree' -Detail $detail -Result 'Skipped (WhatIf)'
    }

    try {
        $snapshot = Save-OwnerSnapshot -Path $Path -LogFolder $LogFolder
    } catch {
        return New-PermissionChangeEntry -Action $action -Target $Path -ItemType 'Folder tree' -Detail $detail -Result 'Failed' `
            -ErrorText (Get-BackupFailureText -LogFolder $LogFolder -Reason $_.Exception.Message)
    }
    # Read back by Get-UnrestorableItemCount: keep the wording in step with it.
    if ($snapshot.Unreadable -gt 0) { $detail += ". $($snapshot.Unreadable) item(s) had no readable owner before the change" }
    if ($snapshot.Unlisted -gt 0) { $detail += ". $($snapshot.Unlisted) folder(s) could not be opened, so what is in them is not in the backup" }
    $common = @{ Action = $action; Target = $Path; ItemType = 'Folder tree'; Detail = $detail; OldValue = "Saved in $($snapshot.File)"; BackupFile = $snapshot.File }

    # takeown: /R recursive, /A owner = Administrators, /D Y answers "yes" for folders the
    # account cannot list (documented for use with /R). Learn lists no exit codes for takeown,
    # so anything but 0 is treated as "not every item" (NOT VERIFIED beyond that).
    # https://learn.microsoft.com/windows-server/administration/windows-commands/takeown
    $takeown = Invoke-AclTool -Tool takeown -Arguments @('/F', $Path, '/R', '/A', '/D', 'Y')
    # icacls: /setowner changes the owner of all matching files, /T includes subfolders and
    # files, /C continues after file errors (still shown), /Q hides success messages.
    # https://learn.microsoft.com/windows-server/administration/windows-commands/icacls
    $icacls = Invoke-AclTool -Tool icacls -Arguments @($Path, '/setowner', $me, '/T', '/C', '/Q')

    # NOT VERIFIED: Learn documents neither icacls exit codes nor its closing line
    # "Successfully processed N files; Failed processing M files" (English Windows; other
    # languages translate it). Both are read defensively: a non-zero exit code or a non-zero
    # "Failed processing" count is a problem, and a non-zero "Successfully processed" count
    # means something was changed. When the line is not found, only the exit codes count.
    $icaclsText = "$($icacls.Output)"
    $icaclsSet = if ($icaclsText -match 'Successfully processed (\d+) files') { [int]$Matches[1] } else { 0 }
    $icaclsFailed = if ($icaclsText -match 'Failed processing (\d+) files') { [int]$Matches[1] } else { 0 }

    $problems = New-Object System.Collections.Generic.List[string]
    if ($takeown.ExitCode -ne 0) {
        $problems.Add((Get-AclToolProblem -What 'takeown could not give every item to Administrators' -Result $takeown))
    }
    if ($icacls.ExitCode -ne 0 -or $icaclsFailed -gt 0) {
        $problems.Add((Get-AclToolProblem -What "icacls could not make $me the owner of every item" -Result $icacls))
    }
    if ($problems.Count -eq 0) {
        return New-PermissionChangeEntry @common -NewValue "Owner: $me" -Result 'Done'
    }

    $somethingChanged = $takeown.ExitCode -eq 0 -or ($icacls.ExitCode -eq 0) -or $icaclsSet -gt 0
    if ($somethingChanged) {
        New-PermissionChangeEntry @common -NewValue "Owner: $me on some items" -Result 'Partly done' -ErrorText ($problems -join ' ')
    } else {
        # Not read back: a tree is too big to check item by item, so the state is unknown.
        New-PermissionChangeEntry @common -NewValue 'Not checked' -Result 'Failed' -ErrorText ($problems -join ' ')
    }
}

function Get-AclToolProblem {
    # One sentence for a native tool that reported errors: what failed, the exit code, and the
    # tool's own summary (Get-AclToolSummary).
    param([Parameter(Mandatory)][string]$What, [Parameter(Mandatory)][object]$Result)
    $summary = Get-AclToolSummary -Output "$($Result.Output)"
    if ($summary) { Format-Sentence "$What (exit code $($Result.ExitCode)): $summary" }
    else { "$What (exit code $($Result.ExitCode))." }
}

#endregion

#region Change log and messages

function Write-PermissionChangeLog {
    <#
    .SYNOPSIS
        Appends change rows to Changes_<yyyy-MM-dd>.csv in the log folder. Returns the path,
        or $null when the folder cannot be written (the change itself already happened) or
        there is nothing to write.
    .DESCRIPTION
        Text that Excel would run as a formula is written with a leading single quote
        (ConvertTo-CsvSafeText); the rows passed in are not modified.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries,
        [Parameter(Mandatory)][string]$LogFolder
    )

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
        $exists = Test-Path -LiteralPath $path
        $csv = @($rows | ConvertTo-Csv -NoTypeInformation)
        if ($exists) { $csv = $csv | Select-Object -Skip 1 }
        Add-Content -LiteralPath $path -Value $csv -Encoding UTF8 -ErrorAction Stop
        return $path
    } catch {
        Write-Verbose "Could not write change log: $($_.Exception.Message)"
        return $null
    }
}

function Invoke-LoggedPermissionChange {
    <#
    .SYNOPSIS
        Runs a change function and appends each row to the change log as soon as that item is
        done, so a batch that is interrupted still leaves a log of what it changed. Returns
        Entries (all rows) and LogPath ($null if any row could not be logged).
    .PARAMETER Change
        Script block that calls one change function, e.g.
        { Add-FolderPermission -Path $paths -Identity $id -Rights Modify -LogFolder $log }.
        It runs in a child scope of the caller, so it can use the caller's variables.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$Change,
        [Parameter(Mandatory)][string]$LogFolder
    )

    $logged = New-Object System.Collections.Generic.List[object]
    $logFile = $null
    $logFailed = $false
    & $Change | ForEach-Object {
        if ($null -eq $_) { return }
        $logged.Add($_)
        $written = Write-PermissionChangeLog -Entries @($_) -LogFolder $LogFolder
        if ($written) { $logFile = $written } else { $logFailed = $true }
    }
    [PSCustomObject]@{
        Entries = $logged.ToArray()
        LogPath = $(if ($logFailed) { $null } else { $logFile })
    }
}

function Get-FailedChangeState {
    <#
    .SYNOPSIS
        For a Failed row: 'Unchanged' (nothing was touched), 'Partly' (the permissions read back
        differ from before) or 'Unknown' (they could not be read back).
    #>
    param([Parameter(Mandatory)][object]$Entry)
    if (-not $Entry.NewValue) { return 'Unchanged' }
    # A whole-tree row is not read back item by item ('Not checked').
    if ($Entry.NewValue -eq 'Could not read' -or (Test-TreeChangeEntry $Entry)) { return 'Unknown' }
    if ($Entry.NewValue -ceq $Entry.OldValue) { return 'Unchanged' }
    'Partly'
}

function Get-PlainErrorText {
    <#
    .SYNOPSIS
        The plain-English version of a raw Windows/.NET error for the status bar. Messages the
        core composed itself are returned as they are. The raw text stays in the change log.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $t = Format-Sentence $Text
    $own = 'Could not save a backup*', 'Could not read the current permissions*', 'Could not read the permissions of the source folder*', 'Ownership was given to Administrators*'
    foreach ($prefix in $own) { if ($t -like $prefix) { return $t } }
    if ($t -match 'Access to the path.*is denied|Access is denied|unauthorized operation|UnauthorizedAccess') {
        return 'You do not have permission to change this item. Run the tool as administrator or take ownership first.'
    }
    if ($t -match 'identity references could not be translated') {
        return 'Windows could not find that user or group. Check the name, for example CONTOSO\HR-Staff.'
    }
    if ($t -match 'not allowed to be the owner') {
        return 'Windows would not make this account the owner. Run the tool as administrator.'
    }
    $t
}

function Get-UnrestorableItemCount {
    <#
    .SYNOPSIS
        How many changed items cannot be put back from their backup because their permissions
        or owner could not be read first: a Done row with OldValue 'Could not read', plus the
        count a whole-tree row records in its Detail (Invoke-TreeOwnershipChange).
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries)

    $count = 0
    foreach ($e in @($Entries | Where-Object { $null -ne $_ })) {
        if (Test-TreeChangeEntry $e) {
            if (@('Done', 'Partly done') -contains $e.Result -and "$($e.Detail)" -match '(\d+) item\(s\) had no readable owner') { $count += [int]$Matches[1] }
        } elseif ($e.Result -eq 'Done' -and $e.OldValue -eq 'Could not read') {
            $count++
        }
    }
    $count
}

function Get-TreeChangeResultMessage {
    <#
    .SYNOPSIS
        The status line for whole-tree rows (Get-ChangeResultMessage hands them over): one
        sentence per folder, the items that cannot be restored, then where the backup and the
        log are.
    #>
    param(
        [Parameter(Mandatory)][object[]]$Entries,
        [AllowNull()][string]$LogPath,
        [Parameter(Mandatory)][string]$LogFolder
    )

    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($e in $Entries) {
        $what = "ownership of $($e.Target) and all subfolders and files"
        $restore = "The owners before the change are in $($e.BackupFile); see ""Undo a change"" in the README to put them back."
        switch ($e.Result) {
            'Done'                { $parts.Add("Took $what.") }
            'Partly done'         { $parts.Add("Partly done: took $what, but not on every item. $(Format-Sentence $e.Error) $restore") }
            'Skipped (WhatIf)'    { $parts.Add("WhatIf: nothing was changed (would take $what).") }
            'Skipped (not found)' { $parts.Add("$($e.Target) does not exist.") }
            default {
                if ((Get-FailedChangeState $e) -eq 'Unchanged') {
                    # The error already ends "Nothing was changed."
                    $parts.Add("Could not take $($what): $(Format-Sentence $e.Error)")
                } else {
                    $parts.Add("Could not take $($what): $(Format-Sentence $e.Error) Some items may still have changed. $restore")
                }
            }
        }
        if ("$($e.Detail)" -match '(\d+) folder\(s\) could not be opened') {
            $parts.Add("$($Matches[1]) folder(s) could not be opened, so what is in them is not in the backup.")
        }
    }
    $unreadable = Get-UnrestorableItemCount -Entries $Entries
    if ($unreadable -gt 0) {
        $parts.Add("$unreadable item(s) had no readable permissions before the change and cannot be restored from this backup.")
    }

    $changed = @($Entries | Where-Object { $_.Result -eq 'Done' -or $_.Result -eq 'Partly done' -or ($_.Result -eq 'Failed' -and (Get-FailedChangeState $_) -ne 'Unchanged') })
    $allDone = @($Entries | Where-Object { $_.Result -ne 'Done' }).Count -eq 0
    $whatIfOnly = @($Entries | Where-Object { $_.Result -ne 'Skipped (WhatIf)' }).Count -eq 0
    $backup = @($Entries | Where-Object { $_.BackupFile } | ForEach-Object { $_.BackupFile } | Select-Object -First 1)
    if ($changed.Count -gt 0 -and -not $LogPath) {
        $parts.Add("The change was made, but the change log could not be written to $LogFolder.$(if ($backup.Count -gt 0) { " The backup is at $($backup[0])." })")
    } elseif ($allDone -and $LogPath) {
        $parts.Add("Backed up to $($backup[0]) and logged to $LogPath.")
    } elseif ($LogPath) {
        $parts.Add("Logged to $LogPath.")
    } elseif (-not $whatIfOnly) {
        $parts.Add("The change log could not be written to $LogFolder.")
    }
    $parts -join ' '
}

function Get-ChangeResultMessage {
    <#
    .SYNOPSIS
        The plain-English status line for a change: what was done and where, how many items
        failed (with the first error), whether anything was left partly changed, and where the
        backup and the log are.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries,
        [AllowNull()][string]$LogPath,
        [Parameter(Mandatory)][string]$LogFolder
    )

    $all = @($Entries | Where-Object { $null -ne $_ })
    if ($all.Count -eq 0) { return 'Nothing was changed.' }
    if (@($all | Where-Object { -not (Test-TreeChangeEntry $_) }).Count -eq 0) {
        return Get-TreeChangeResultMessage -Entries $all -LogPath $LogPath -LogFolder $LogFolder
    }
    $done     = @($all | Where-Object { $_.Result -eq 'Done' })
    $failed   = @($all | Where-Object { $_.Result -eq 'Failed' })
    $notFound = @($all | Where-Object { $_.Result -eq 'Skipped (not found)' })
    $whatIf   = @($all | Where-Object { $_.Result -eq 'Skipped (WhatIf)' })
    $touched  = @($failed | Where-Object { (Get-FailedChangeState $_) -ne 'Unchanged' })
    $first = $all[0]

    # The backup failed: nothing was touched, and the error already says so.
    $backupFailed = @($failed | Where-Object { $_.Error -like 'Could not save a backup*' })
    if ($done.Count -eq 0 -and $backupFailed.Count -gt 0) { return $backupFailed[0].Error }

    $phrase, $preposition = switch ($first.Action) {
        'Add permission'    { "Added $($first.Detail)", 'on' }
        'Remove permission' {
            # RemoveAccessRuleAll removes every rule of that type for the account, not only the
            # rights that were picked, so say what really happened.
            if ($first.Detail -match '^(Allow|Deny) (.+?) for (.+)$') { "Removed all $($Matches[1]) permissions for $($Matches[3]) (asked: $($Matches[2]))", 'from' }
            else { "Removed $($first.Detail)", 'from' }
        }
        'Take ownership'    { 'Took ownership', 'of' }
        'Copy permissions'  { $first.Detail, 'to' }
        default             { $first.Action, 'on' }
    }
    $types = @($all | ForEach-Object { $_.ItemType } | Where-Object { $_ -ne 'Unknown' } | Sort-Object -Unique)
    $noun = if ($types.Count -eq 1 -and $types[0] -eq 'File') { 'files' } elseif ($types.Count -eq 1 -and $types[0] -eq 'Folder') { 'folders' } else { 'items' }
    $backup = @($all | Where-Object { $_.BackupFile } | ForEach-Object { $_.BackupFile } | Select-Object -First 1)
    $backupPath = if ($backup.Count -gt 0) { $backup[0] } else { '' }

    $parts = New-Object System.Collections.Generic.List[string]
    if ($failed.Count -gt 0) {
        $f = $failed[0]
        $err = if ((Get-FailedChangeState $f) -eq 'Unchanged') { Get-PlainErrorText $f.Error } else { Format-Sentence $f.Error }
    }
    if ($done.Count -gt 0) {
        $where = if ($all.Count -eq 1) { $first.Target } else { "$($done.Count) of $($all.Count) $noun" }
        $parts.Add("$phrase $preposition $where.")
    } elseif ($whatIf.Count -eq $all.Count) {
        $parts.Add("WhatIf: nothing was changed ($($all.Count) $noun would be).")
    } elseif ($all.Count -eq 1 -and $failed.Count -eq 1) {
        $state = Get-FailedChangeState $first
        if ($state -eq 'Partly') {
            $parts.Add("$($first.Action) failed on $($first.Target), and it was partly changed: $err")
        } elseif ($state -eq 'Unknown') {
            $parts.Add("$($first.Action) failed on $($first.Target): $err")
        } elseif ($err -match 'nothing was changed') {
            $parts.Add("$($first.Action) failed on $($first.Target): $err")
        } else {
            $parts.Add("$($first.Action) failed on $($first.Target): $err Nothing was changed.")
        }
    } elseif ($touched.Count -eq 0) {
        $parts.Add('Nothing was changed.')
    }
    if ($failed.Count -gt 0 -and $all.Count -gt 1) {
        $parts.Add("$($failed.Count) failed. First error ($($f.Target)): $err")
    }
    if ($touched.Count -gt 0) {
        $restore = if ($backupPath) { " Their permissions before the change are in $backupPath; see ""Undo a change"" in the README to put them back." } else { '' }
        if ($all.Count -eq 1) {
            if ($backupPath) { $parts.Add("Its permissions before the change are in $backupPath; see ""Undo a change"" in the README to put them back.") }
        } else {
            $parts.Add("$($touched.Count) item(s) were partly changed or could not be checked.$restore")
        }
    }
    if ($notFound.Count -gt 0) {
        if ($all.Count -eq 1) { $parts.Add("$($first.Target) does not exist.") }
        else { $parts.Add("$($notFound.Count) not found and skipped.") }
    }
    $unreadable = @($done | Where-Object { $_.OldValue -eq 'Could not read' })
    if ($unreadable.Count -gt 0) {
        $parts.Add("$($unreadable.Count) item(s) had no readable permissions before the change and cannot be restored from this backup.")
    }

    $backupNote = if ($backupPath) { " The backup is at $backupPath." } else { '' }
    if ($done.Count -gt 0 -and -not $LogPath) {
        $parts.Add("The change was made, but the change log could not be written to $LogFolder.$backupNote")
    } elseif ($touched.Count -gt 0 -and -not $LogPath) {
        $parts.Add("The change log could not be written to $LogFolder.")
    } elseif ($done.Count -gt 0) {
        $parts.Add("Backed up to $backupPath and logged to $LogPath.")
    } elseif ($LogPath) {
        $parts.Add("Logged to $LogPath.")
    } elseif ($whatIf.Count -ne $all.Count) {
        $parts.Add("The change log could not be written to $LogFolder.")
    }

    $parts -join ' '
}

#endregion

if ($LoadFunctionsOnly) { return }
