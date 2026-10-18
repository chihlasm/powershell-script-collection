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
    OwnerSid), because icacls /save does not store owners. Folders that cannot be opened are
    skipped (takeown /D N) and keep their permissions; the result names them so they can be
    escalated. Afterwards it reads every owner back. It logs one row for the whole folder
    (ItemType 'Folder tree', Result Done, Partly done or Failed). The root of a drive and the
    Windows system folders are refused unless the caller passes -AllowSystemFolder.

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
    - takeown /F /R /A /D N (/R recursive over all files in the directory and subdirectories;
      /A gives ownership to the Administrators group instead of the current user; /D answers
      the prompt for a folder the account has no List Folder and Read permission on and must
      be used with /R: N is "Skip the directory", while Y means "the directory permissions are
      replaced with permission granting the user full control only", so N is used and such
      folders are left as they were (D-034); the page lists no exit codes, so anything but 0
      is treated as a failure; it says nothing about junctions or symbolic links):
      https://learn.microsoft.com/windows-server/administration/windows-commands/takeown
    - SeRestorePrivilege is what lets an account set any user or group as the owner:
      https://learn.microsoft.com/windows/win32/secauthz/privilege-constants
    - icacls (/save stores DACLs only, so owners need their own snapshot; /restore takes the
      parent directory; /setowner changes the owner of all matching files; /T includes
      subfolders and files; /C continues after file errors; /Q suppresses success messages;
      /L works on a symbolic link itself "instead of its destination", so without /L a
      symbolic link's destination is changed; a SID is given as *S-1-...):
      https://learn.microsoft.com/windows-server/administration/windows-commands/icacls
      NOT VERIFIED: whether /T (or takeown /R) goes into junctions and symbolic links. A tree
      that contains any is reported as incomplete, never as a plain success.
      NOT VERIFIED: the page documents neither icacls exit codes nor its closing line
      "Successfully processed N files; Failed processing M files". So the result of taking
      ownership of a tree comes from reading every owner back (Get-OwnerReadBack); exit
      codes only stop it from being reported better than the tools say, and the output is
      shown, never parsed for counts.
    - ObjectSecurity.GetOwner (SecurityIdentifier always; NTAccount throws
      IdentityNotMappedException for a deleted account), WindowsIdentity.Name
      (DOMAIN\USERNAME) and WindowsIdentity.User (the account's SID):
      https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.objectsecurity.getowner
      https://learn.microsoft.com/dotnet/api/system.security.principal.windowsidentity.name
      https://learn.microsoft.com/dotnet/api/system.security.principal.windowsidentity.user
    - S-1-5-32-544 is the built-in Administrators group (what takeown /A sets):
      https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
    - Get-ChildItem -Force (hidden and system items too, no security override); each folder is
      listed on its own and FileAttributes.ReparsePoint marks junctions and symbolic links,
      which the owner snapshot lists but does not go into:
      https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-childitem
      https://learn.microsoft.com/dotnet/api/system.io.fileattributes
    - PathIntrinsics.GetUnresolvedProviderPathFromPSPath (a relative path made full against the
      PowerShell location, without wildcard expansion):
      https://learn.microsoft.com/dotnet/api/system.management.automation.pathintrinsics.getunresolvedproviderpathfrompspath
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

function Get-PermissionChangeColumn {
    # The shared change-log columns, in order (owner decision D-030). Write-PermissionChangeLog
    # writes exactly these: a row can carry extra counts for the messages (a whole-tree row's
    # Unreadable, Unlisted, ...), and they must not change the file format.
    'Time', 'Technician', 'Computer', 'Action', 'Target', 'ItemType', 'Detail', 'OldValue', 'NewValue', 'Result', 'Error', 'BackupFile'
}

function New-PermissionChangeEntry {
    <#
    .SYNOPSIS
        One change-log row with the shared column set, in the shared order
        (Get-PermissionChangeColumn).
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

function Resolve-AclTargetPath {
    <#
    .SYNOPSIS
        The full file-system path for a folder given relative to the PowerShell location
        ('.\HR') or with a trailing backslash ('D:\Shares\HR Team\'). A root ('D:\') keeps its
        backslash. A blank path is returned as it is.
    .DESCRIPTION
        Resolved once, so the owner snapshot, takeown, icacls and the change log all name the
        same folder: native tools resolve a relative path against the process folder, which is
        not the PowerShell location, and a quoted argument ending in \" ("D:\HR Team\") is
        read by them as an escaped quote. The path does not have to exist, and [ ] are kept
        as they are (no wildcards).
        https://learn.microsoft.com/dotnet/api/system.management.automation.pathintrinsics.getunresolvedproviderpathfrompspath
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    try {
        $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    } catch {
        return $Path
    }
    $root = [System.IO.Path]::GetPathRoot($full)
    if ($full -match '[\\/]$' -and $full -ne $root) {
        $trimmed = $full.TrimEnd('\', '/')
        if ($trimmed.Length -ge "$root".TrimEnd('\', '/').Length) { $full = $trimmed }
    }
    $full
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
    Export-SddlBackupFile -Rows $rows -File $file
    $file
}

function Export-SddlBackupFile {
    <#
    .SYNOPSIS
        Writes Path, ItemType, Sddl rows to a new CSV file (never over an existing one) and reads
        it back to check it. Throws when the file cannot be written or does not hold the rows.
    .DESCRIPTION
        Used by Save-AclBackup, so every SDDL backup has the same columns, the same Excel-formula escaping (ConvertTo-CsvSafeText) and the same check.
        https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/export-csv
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][string]$File
    )

    $Rows | ForEach-Object { [PSCustomObject][ordered]@{ Path = (ConvertTo-CsvSafeText $_.Path); ItemType = $_.ItemType; Sddl = $_.Sddl } } |
        Export-Csv -LiteralPath $File -NoTypeInformation -Encoding UTF8 -NoClobber -ErrorAction Stop

    # A backup that cannot be read back is no backup: check it before anything changes.
    $saved = @(Import-Csv -LiteralPath $File -ErrorAction Stop)
    if ($saved.Count -ne $Rows.Count) {
        throw "the backup file $File holds $($saved.Count) of $($Rows.Count) items"
    }
    for ($i = 0; $i -lt $Rows.Count; $i++) {
        if ((ConvertFrom-CsvSafeText $saved[$i].Path) -cne $Rows[$i].Path -or $saved[$i].Sddl -cne $Rows[$i].Sddl) {
            throw "the backup file $File does not hold the permissions read from $($Rows[$i].Path)"
        }
    }
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

function Get-OwnerTreeItem {
    <#
    .SYNOPSIS
        The folder and every folder and file under it, for the owner snapshot: Items (Path,
        ItemType), Unlisted (the folders that could not be opened) and Links (the junctions and
        symbolic links found, the folder itself included).
    .DESCRIPTION
        -Force includes hidden and system items, which takeown /R also changes.
        A junction or symbolic link is listed as an item but not gone into: what it points to
        can be outside the folder, or loop back into it. Each folder is listed on its own
        (not Get-ChildItem -Recurse), so links are never followed, whatever the PowerShell
        version. Links are also returned on their own because Microsoft's documentation does
        not say whether takeown /R or icacls /T go into them, and icacls changes what a
        symbolic link points to unless /L is given.
        A folder that cannot be opened is listed, but what is inside it is not.
        https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-childitem
        https://learn.microsoft.com/dotnet/api/system.io.fileattributes
        https://learn.microsoft.com/windows-server/administration/windows-commands/icacls
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $items = New-Object System.Collections.Generic.List[object]
    $unlisted = New-Object System.Collections.Generic.List[string]
    $links = New-Object System.Collections.Generic.List[string]
    $pending = New-Object System.Collections.Generic.Queue[string]
    $items.Add([PSCustomObject]@{ Path = $Path; ItemType = 'Folder' })
    $top = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($top -and ($top.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { $links.Add($Path) }
    $pending.Enqueue($Path)
    while ($pending.Count -gt 0) {
        $folder = $pending.Dequeue()
        try {
            $children = @(Get-ChildItem -LiteralPath $folder -Force -ErrorAction Stop)
        } catch {
            $unlisted.Add($folder)
            continue
        }
        foreach ($child in $children) {
            $type = if ($child.PSIsContainer) { 'Folder' } else { 'File' }
            $items.Add([PSCustomObject]@{ Path = $child.FullName; ItemType = $type })
            $isLink = ($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
            if ($isLink) { $links.Add($child.FullName) }
            if ($child.PSIsContainer -and -not $isLink) { $pending.Enqueue($child.FullName) }
        }
    }
    [PSCustomObject]@{ Items = $items.ToArray(); Unlisted = $unlisted.ToArray(); Links = $links.ToArray() }
}

function Save-OwnerSnapshot {
    <#
    .SYNOPSIS
        Saves the owner of a folder and of every folder and file under it to
        <LogFolder>\Backups\<yyyy-MM-dd_HHmmss>_TakeOwnership.csv (Path, ItemType, Owner,
        OwnerSid), reads the file back to check it, and returns File, Count, Items (the rows),
        Unreadable, Unlisted and UnlistedFolders. Throws when the file cannot be written or does
        not hold what was read; callers must then change nothing.
    .DESCRIPTION
        Needed because icacls /save stores DACLs only, not owners.
        https://learn.microsoft.com/windows-server/administration/windows-commands/icacls

        An item whose owner cannot be read is listed with Owner 'Could not read' and does not
        stop the snapshot (owner decision D-027); Unreadable counts them. A folder that cannot
        be opened is in the snapshot, but what is inside it is not: Unlisted counts those
        folders and UnlistedFolders names them. Junctions and symbolic links are listed but not
        gone into (Get-OwnerTreeItem).

        Restore: see "Undo a change" in the README (icacls <path> /setowner *<OwnerSid>).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$LogFolder
    )

    $tree = Get-OwnerTreeItem -Path $Path
    $rows = @(foreach ($item in $tree.Items) {
        $owner = Get-ItemOwner -Path $item.Path
        [PSCustomObject][ordered]@{ Path = $item.Path; ItemType = $item.ItemType; Owner = $owner.Owner; OwnerSid = $owner.OwnerSid }
    })

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
        File            = $file
        Count           = $rows.Count
        Items           = $rows
        Unreadable      = @($rows | Where-Object { $_.Owner -eq 'Could not read' }).Count
        Unlisted        = @($tree.Unlisted).Count
        UnlistedFolders = @($tree.Unlisted)
        Links           = @($tree.Links).Count
        LinkPaths       = @($tree.Links)
    }
}

function Get-OwnerReadBack {
    <#
    .SYNOPSIS
        After a whole-tree change, reads the owner of every item in the owner snapshot again and
        counts Mine (owned by -Sid), NotMine, Unchecked (owner could not be read) and Changed
        (owner differs from the snapshot), plus AdministratorsOnly: true when nothing is
        owned by -Sid and every item that is not is owned by Administrators (S-1-5-32-544).
        https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Items,
        [Parameter(Mandatory)][string]$Sid
    )

    $mine = 0; $notMine = 0; $unchecked = 0; $changed = 0; $admins = 0
    foreach ($item in $Items) {
        $now = Get-ItemOwner -Path $item.Path
        if (-not $now.OwnerSid) { $unchecked++; continue }
        if ($now.OwnerSid -eq $Sid) { $mine++ } else { $notMine++ }
        if ($now.OwnerSid -eq 'S-1-5-32-544' -and $now.OwnerSid -ne $Sid) { $admins++ }
        if ($now.OwnerSid -ne $item.OwnerSid) { $changed++ }
    }
    [PSCustomObject]@{
        Mine               = $mine
        NotMine            = $notMine
        Unchecked          = $unchecked
        Changed            = $changed
        AdministratorsOnly = ($mine -eq 0 -and $notMine -gt 0 -and $admins -eq $notMine)
    }
}

function Get-TreeOwnershipRefusal {
    <#
    .SYNOPSIS
        Why taking ownership of everything under -Path is refused, or $null when it is allowed
        (D-036). Refused: the root of a drive (D:\) and %SystemRoot%, %ProgramFiles%,
        %ProgramFiles(x86)% and %ProgramData%, the folders themselves and anything under them.
        The root of a share (\\fs01\share) is allowed.
    .DESCRIPTION
        Text only, nothing is read from disk: -Path should already be a full path
        (Resolve-AclTargetPath). Compared case-insensitively on whole path segments, so
        C:\Windows\System32 is refused and C:\WindowsOld is not. The variables are read when
        called, not when the file is loaded. The text names the path and does not say what to do
        about it: each caller adds its own next step (the command line has -AllowSystemFolder,
        the GUI has no override).
    #>
    param([Parameter(Mandatory)][string]$Path)

    $normalized = $Path.Trim().Replace('/', '\')
    if ($normalized -match '^[A-Za-z]:\\*$') {
        return "$Path is the root of a drive. Taking ownership of a whole drive also changes the owner of Windows and program files on it, which cannot easily be undone. Choose the folder that needs fixing instead."
    }
    $normalized = $normalized.TrimEnd('\')
    foreach ($name in @('SystemRoot', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramData')) {
        $protected = "$([Environment]::GetEnvironmentVariable($name))".Trim().Replace('/', '\').TrimEnd('\')
        if (-not $protected) { continue }
        if ($normalized.Equals($protected, [System.StringComparison]::OrdinalIgnoreCase) -or
            $normalized.StartsWith("$protected\", [System.StringComparison]::OrdinalIgnoreCase)) {
            return "$Path is in a Windows system folder (%$name%, $protected). Changing the owner of everything in it can stop Windows or installed programs from working, and cannot easily be undone. Choose the folder that needs fixing instead."
        }
    }
    $null
}

function Test-AclToolErrorLine {
    # True for a native-tool output line that looks like an error in any Windows language:
    # icacls reports a failed item as "<path>: <reason>", so a line starting with the target
    # folder counts (with /Q it prints nothing for items that succeeded); English error words
    # are a further hint, but only outside paths: "D:\Failed jobs" or a quoted "...\Errors\x"
    # is a name, not an error.
    param([AllowEmptyString()][string]$Line, [AllowEmptyString()][string]$Path)
    if ($Path -and $Line.StartsWith($Path, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    $words = $Line -replace '"[^"]*"', ' ' -replace '(?:[A-Za-z]:\\|\\\\)[^"]*?(?=:\s|$)', ' '
    $words -match '(?i)\b(error|denied|failed|cannot|unable|invalid)\b'
}

function Test-AclToolSuccessLine {
    # True for a takeown line reporting an item that succeeded ("SUCCESS: The file (or folder):
    # ... now owned by ..."). English only: in other languages no line is skipped as a success.
    param([AllowEmptyString()][string]$Line)
    $Line -match '^SUCCESS\b'
}

function Get-AclToolSummary {
    <#
    .SYNOPSIS
        The part of a native tool's output worth showing and logging: the lines that look like
        errors (Test-AclToolErrorLine), at most -MaxLines in all, then always the last line
        (icacls ends with its count of processed and failed files). When no line looks like an
        error, the last line that does not report a success (Test-AclToolSuccessLine), or the
        last line when every line does.
    .DESCRIPTION
        Not tied to English: what was changed is decided by reading the owners back
        (Get-OwnerReadBack), so this text only supports the result. takeown prints one line
        per item that succeeded; those are left out, so a tool that failed (Get-AclToolProblem
        adds its exit code) is not summed up by a line saying an item succeeded.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Output, [string]$Path = '', [int]$MaxLines = 5)

    $lines = @("$Output" -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($lines.Count -eq 0) { return '' }
    $last = $lines[-1]
    $errors = @($lines | Select-Object -First ($lines.Count - 1) | Where-Object { Test-AclToolErrorLine -Line $_ -Path $Path })
    if ($errors.Count -eq 0 -and -not (Test-AclToolErrorLine -Line $last -Path $Path)) {
        $other = @($lines | Where-Object { -not (Test-AclToolSuccessLine -Line $_) })
        if ($other.Count -gt 0) { return $other[-1] }
        return $last
    }
    $shown = @($errors | Select-Object -First ([Math]::Max(0, $MaxLines - 1)))
    $parts = @($shown)
    if ($errors.Count -gt $shown.Count) { $parts += "(and $($errors.Count - $shown.Count) more lines)" }
    $parts += $last
    $parts -join ' '
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
        whole tree. The root of a drive and the Windows system folders are refused
        (Get-TreeOwnershipRefusal) unless -AllowSystemFolder is given.
        https://learn.microsoft.com/windows-server/administration/windows-commands/takeown
    .PARAMETER Recurse
        Take ownership of each folder and of all its subfolders and files.
    .PARAMETER AllowSystemFolder
        With -Recurse: also take ownership of the root of a drive or of a folder in
        %SystemRoot%, %ProgramFiles%, %ProgramFiles(x86)% or %ProgramData%, which is refused
        otherwise (D-036). Only the command line offers this; the GUI never passes it.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][AllowEmptyCollection()][string[]]$Path,
        [Parameter(Mandatory)][string]$LogFolder,
        [switch]$Recurse,
        [switch]$AllowSystemFolder
    )

    if ($Recurse) {
        foreach ($p in $Path) { Invoke-TreeOwnershipChange -Cmdlet $PSCmdlet -Path $p -LogFolder $LogFolder -AllowSystemFolder:$AllowSystemFolder }
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

function Add-TreeEntryCount {
    <#
    .SYNOPSIS
        Attaches the counts of a whole-tree change to its row as the member set TreeCounts
        ($row.TreeCounts.Unlisted). A member set is not a property, so the row keeps exactly
        the shared log columns (Get-PermissionChangeColumn) for the log file and the tests,
        and nothing has to be parsed back out of Detail.
    #>
    param([Parameter(Mandatory)][object]$Entry, [Parameter(Mandatory)][System.Collections.IDictionary]$Counts)
    $members = New-Object System.Collections.ObjectModel.Collection[System.Management.Automation.PSMemberInfo]
    foreach ($name in $Counts.Keys) {
        $members.Add((New-Object System.Management.Automation.PSNoteProperty -ArgumentList $name, $Counts[$name]))
    }
    $Entry.PSObject.Members.Add((New-Object System.Management.Automation.PSMemberSet -ArgumentList 'TreeCounts', $members))
}

function Get-TreeEntryCount {
    # One of the counts a whole-tree row carries (Add-TreeEntryCount: Unreadable, Unlisted,
    # Unchecked, NotOwned, Changed, ItemCount), or 0 when the row has none (it stopped before
    # the snapshot).
    param([Parameter(Mandatory)][AllowNull()][object]$Entry, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Entry -or -not $Entry.PSObject.Members['TreeCounts']) { return 0 }
    [int]$Entry.TreeCounts.$Name
}

function Test-TreeEntryIncomplete {
    # True for a whole-tree row whose result could not be checked everywhere: folders that could
    # not be opened (what is inside them is in no backup), owners that could not be read back,
    # or junctions and symbolic links (Microsoft's documentation does not say whether takeown /R
    # and icacls /T go into them). Such a row is never reported as a plain success.
    param([Parameter(Mandatory)][AllowNull()][object]$Entry)
    (Test-TreeChangeEntry $Entry) -and (
        (Get-TreeEntryCount $Entry 'Unlisted') -gt 0 -or
        (Get-TreeEntryCount $Entry 'Unchecked') -gt 0 -or
        (Get-TreeEntryCount $Entry 'Links') -gt 0)
}

function Format-AclToolCommand {
    # The command line as it could be pasted into a console, for the change log. Paths (D:\...,
    # \\server\...) are always quoted, so the folder reads the same in every row; other
    # arguments only when they contain a space.
    param([Parameter(Mandatory)][string]$Tool, [Parameter(Mandatory)][string[]]$Arguments)
    $quoted = @($Arguments | ForEach-Object { if ($_ -match '\s' -or $_ -match '^(?:[A-Za-z]:\\|\\\\)') { '"{0}"' -f $_ } else { $_ } })
    "$Tool $($quoted -join ' ')"
}

function Invoke-TreeOwnershipChange {
    <#
    .SYNOPSIS
        Takes ownership of a folder and everything under it for the account running the tool,
        after saving every item's owner. Returns one row for the whole folder and never throws.
    .DESCRIPTION
        1. The path is made a full path once (Resolve-AclTargetPath) and used for everything.
        2. The root of a drive and the Windows system folders are refused
           (Get-TreeOwnershipRefusal, D-036) unless -AllowSystemFolder: nothing is read,
           written or changed.
        3. ShouldProcess once for the folder (-WhatIf: nothing is read, written or changed).
        4. Save-OwnerSnapshot: if it cannot be written and checked, nothing is changed.
        5. takeown /F <dir> /R /A /D N gives every item to Administrators, so an administrator
           can open items they are locked out of. A folder the account cannot list (no List
           Folder and Read permission) is skipped by /D N and keeps its permissions (D-034);
           /D Y would replace them with full control for the user only. The read-back then
           shows it is not owned, and the message tells the technician to escalate it.
        6. icacls <dir> /setowner <DOMAIN\user> /T /C /Q makes the current account the owner.
           The full name from WindowsIdentity, not $env:USERNAME, which has no domain and is
           wrong under SYSTEM and service accounts.
        7. The owner of every item in the snapshot is read again (Get-OwnerReadBack).
        Both tools run even if takeown reports errors (as the GUI always did): icacls is what
        sets the final owner.

        Result comes from reading the owners back: Done when every item that can be read is
        now owned by the current account, Partly done when some are (or when no owner at all
        could be read back, so nothing is known), Failed when none are. A
        tool that reports errors (exit code not 0) also keeps the result from being better than
        the tools say (Partly done when the other tool succeeded, Failed when neither did),
        because its errors may concern items the snapshot could not see. NewValue says what the
        owners are now; Error holds the read-back count and the tools' own summary.

        The row also carries, in its TreeCounts member set (Add-TreeEntryCount), for the messages
        and not for the log file: ItemCount, Unreadable (no readable owner before), Unlisted and
        UnlistedFolders (folders that could not be opened, which takeown skipped), Links and
        LinkPaths (junctions and symbolic links, listed but not gone into),
        Unchecked (no readable owner afterwards), NotOwned (still not owned by the current
        account) and Changed (owner differs from the snapshot).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Management.Automation.PSCmdlet]$Cmdlet,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Path,
        [Parameter(Mandatory)][string]$LogFolder,
        [switch]$AllowSystemFolder
    )

    $action = 'Take ownership (all subfolders and files)'
    # WindowsIdentity.Name is the logon name in DOMAIN\USERNAME form; .User is its SID.
    # https://learn.microsoft.com/dotnet/api/system.security.principal.windowsidentity.name
    # https://learn.microsoft.com/dotnet/api/system.security.principal.windowsidentity.user
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $me = $identity.Name
    $mySid = $identity.User.Value
    $detail = "Owner set to $me on the folder and all subfolders and files"
    $Path = Resolve-AclTargetPath -Path $Path

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
    if (-not $AllowSystemFolder) {
        $refusal = Get-TreeOwnershipRefusal -Path $Path
        if ($refusal) {
            return New-PermissionChangeEntry -Action $action -Target $Path -ItemType 'Folder tree' -Detail $detail -Result 'Failed' `
                -ErrorText "$refusal Nothing was changed."
        }
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

    # takeown: /R "performs a recursive operation on all files in the specified directory and
    # subdirectories"; /A "gives ownership to the Administrators group instead of the current
    # user"; /D answers the prompt shown "when the current user does not have the List Folder
    # and Read permissions on a specified directory" and must be used with /R. N is "Skip the
    # directory"; Y would take it and replace its permissions "with permission granting the
    # user full control only", so N leaves such a folder as it was (D-034).
    # Learn lists no exit codes for takeown, so anything but 0 is treated as "not every item"
    # (NOT VERIFIED beyond that).
    # https://learn.microsoft.com/windows-server/administration/windows-commands/takeown
    $takeownArgs = @('/F', $Path, '/R', '/A', '/D', 'N')
    # icacls: /setowner changes the owner of all matching files, /T includes subfolders and
    # files, /C continues after file errors (still shown), /Q hides success messages.
    # https://learn.microsoft.com/windows-server/administration/windows-commands/icacls
    $icaclsArgs = @($Path, '/setowner', $me, '/T', '/C', '/Q')

    # Detail is for the log reader; the messages use the counts on the row instead.
    $notes = @(
        "$detail."
        $(if ($snapshot.Unreadable -gt 0) { "$($snapshot.Unreadable) item(s) had no readable owner before the change." })
        $(if ($snapshot.Unlisted -gt 0) { "$($snapshot.Unlisted) folder(s) could not be opened, so takeown /D N skipped them and the owners inside them are not in the backup: $(@($snapshot.UnlistedFolders) -join '; ')." })
        $(if ($snapshot.Links -gt 0) { "$($snapshot.Links) junction(s) or symbolic link(s) were listed but not gone into: $(@($snapshot.LinkPaths) -join '; ')." })
        "Ran: $(Format-AclToolCommand -Tool takeown -Arguments $takeownArgs); $(Format-AclToolCommand -Tool icacls -Arguments $icaclsArgs)"
    ) | Where-Object { $_ }
    $common = @{ Action = $action; Target = $Path; ItemType = 'Folder tree'; Detail = ($notes -join ' '); OldValue = "Saved in $($snapshot.File)"; BackupFile = $snapshot.File }

    $takeown = Invoke-AclTool -Tool takeown -Arguments $takeownArgs
    $icacls = Invoke-AclTool -Tool icacls -Arguments $icaclsArgs
    $check = Get-OwnerReadBack -Items $snapshot.Items -Sid $mySid
    $total = $snapshot.Count

    # What the owners are now, from the read-back.
    $newValue = if ($check.Mine -eq $total) { "Owner: $me" }
                elseif ($check.Mine -gt 0) { "Owner: $me on $($check.Mine) of $total items" }
                elseif ($check.AdministratorsOnly -and $takeown.ExitCode -eq 0) { 'Owner: Administrators (icacls failed)' }
                elseif ($check.NotMine -eq 0) { 'Not checked' }
                elseif ($check.Changed -eq 0) { 'Owner unchanged' }
                else { "Owner: $me on 0 of $total items" }
    # No owner read back at all is not a success: nothing is known about the result.
    $readBackResult = if ($check.Mine -eq 0 -and $check.NotMine -eq 0) { 'Partly done' }
                      elseif ($check.NotMine -eq 0) { 'Done' }
                      elseif ($check.Mine -eq 0) { 'Failed' }
                      else { 'Partly done' }

    # The tools' exit codes and output support the read-back; their output is not parsed for
    # counts (icacls' closing line is translated, and Learn documents neither it nor the exit
    # codes).
    $problems = New-Object System.Collections.Generic.List[string]
    if ($check.NotMine -gt 0) {
        $problems.Add("$($check.NotMine) of $total items are not owned by $me after the change (read back).")
    }
    if ($takeown.ExitCode -ne 0) {
        $problems.Add((Get-AclToolProblem -What 'takeown could not give every item to Administrators' -Result $takeown -Path $Path))
    }
    if ($icacls.ExitCode -ne 0) {
        $problems.Add((Get-AclToolProblem -What "icacls could not make $me the owner of every item" -Result $icacls -Path $Path))
    }
    $toolResult = if ($takeown.ExitCode -eq 0 -and $icacls.ExitCode -eq 0) { 'Done' }
                  elseif ($takeown.ExitCode -eq 0 -or $icacls.ExitCode -eq 0) { 'Partly done' }
                  else { 'Failed' }
    $order = @('Done', 'Partly done', 'Failed')
    $result = $order[[Math]::Max([array]::IndexOf($order, $readBackResult), [array]::IndexOf($order, $toolResult))]

    $row = New-PermissionChangeEntry @common -NewValue $newValue -Result $result -ErrorText ($problems -join ' ')
    Add-TreeEntryCount -Entry $row -Counts ([ordered]@{
        ItemCount       = $total
        Unreadable      = $snapshot.Unreadable
        Unlisted        = $snapshot.Unlisted
        UnlistedFolders = @($snapshot.UnlistedFolders)
        Links           = $snapshot.Links
        LinkPaths       = @($snapshot.LinkPaths)
        Unchecked       = $check.Unchecked
        NotOwned        = $check.NotMine
        Changed         = $check.Changed
    })
    $row
}

function Get-AclToolProblem {
    # One sentence for a native tool that reported errors: what failed, the exit code, and the
    # tool's own summary (Get-AclToolSummary).
    param([Parameter(Mandatory)][string]$What, [Parameter(Mandatory)][object]$Result, [string]$Path = '')
    $summary = Get-AclToolSummary -Output "$($Result.Output)" -Path $Path
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
        Only the shared columns are written (Get-PermissionChangeColumn); extra properties on a
        row are left out. Text that Excel would run as a formula is written with a leading
        single quote (ConvertTo-CsvSafeText); the rows passed in are not modified.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries,
        [Parameter(Mandatory)][string]$LogFolder
    )

    $columns = @(Get-PermissionChangeColumn)
    $rows = @($Entries | Where-Object { $null -ne $_ } | ForEach-Object {
        $entry = $_
        $safe = [ordered]@{}
        foreach ($name in $columns) {
            $value = $entry.$name
            $safe[$name] = if ($value -is [string]) { ConvertTo-CsvSafeText $value } else { $value }
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
    .DESCRIPTION
        A whole-tree row is judged by its read-back counts (Invoke-TreeOwnershipChange):
        Unchanged only when every owner in the snapshot was read back unchanged and no folder
        was left unopened.
    #>
    param([Parameter(Mandatory)][object]$Entry)
    if (-not $Entry.NewValue) { return 'Unchanged' }
    if (Test-TreeChangeEntry $Entry) {
        if (Test-TreeEntryIncomplete $Entry) { return 'Unknown' }
        if ($Entry.NewValue -eq 'Not checked') { return 'Unknown' }
        if ((Get-TreeEntryCount $Entry 'Changed') -eq 0) { return 'Unchanged' }
        return 'Partly'
    }
    if ($Entry.NewValue -eq 'Could not read') { return 'Unknown' }
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
        or owner could not be read first: a Done row with OldValue 'Could not read', plus a
        whole-tree row's Unreadable count (Invoke-TreeOwnershipChange) when the row is Done,
        Partly done, or Failed with something changed or not known (Get-FailedChangeState).
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries)

    $count = 0
    foreach ($e in @($Entries | Where-Object { $null -ne $_ })) {
        if (Test-TreeChangeEntry $e) {
            $changed = (@('Done', 'Partly done') -contains $e.Result) -or ($e.Result -eq 'Failed' -and (Get-FailedChangeState $e) -ne 'Unchanged')
            if ($changed) { $count += Get-TreeEntryCount $e 'Unreadable' }
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
        sentence per folder, the folders that could not be opened and the items that could not
        be checked or cannot be restored, then where the backup and the log are.
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
            'Partly done'         {
                if ($e.NewValue -eq 'Not checked') {
                    $parts.Add("Partly done: ran takeown and icacls on $($e.Target), but no owner could be read back afterwards, so it is not known whether ownership was taken. $(Format-Sentence $e.Error) $restore".Replace('  ', ' '))
                } else {
                    $parts.Add("Partly done: took $what, but not on every item ($($e.NewValue)). $(Format-Sentence $e.Error) $restore")
                }
            }
            'Skipped (WhatIf)'    { $parts.Add("WhatIf: nothing was changed (would take $what).") }
            'Skipped (not found)' { $parts.Add("$($e.Target) does not exist.") }
            default {
                $err = Format-Sentence $e.Error
                $state = Get-FailedChangeState $e
                if ($state -eq 'Unchanged') {
                    if ($err -notmatch 'Nothing was changed') { $err += ' No owner was changed.' }
                    $parts.Add("Could not take $($what): $err")
                } elseif ($state -eq 'Partly') {
                    $parts.Add("Could not take $($what): $err Some owners were changed ($($e.NewValue)). $restore")
                } else {
                    $parts.Add("Could not take $($what): $err Some items may still have changed. $restore")
                }
            }
        }

        $unlisted = Get-TreeEntryCount $e 'Unlisted'
        if ($unlisted -gt 0) {
            $names = @($e.TreeCounts.UnlistedFolders | Select-Object -First 3)
            $more = if ($unlisted -gt $names.Count) { " and $($unlisted - $names.Count) more" } else { '' }
            $parts.Add("$unlisted folder(s) could not be opened ($($names -join '; ')$more), so the owners of what is inside them were not saved and cannot be restored from this backup.")
            # takeown /D N skips a folder it cannot open (D-034): its permissions are as they
            # were, and the next step is to escalate it.
            # https://learn.microsoft.com/windows-server/administration/windows-commands/takeown
            $parts.Add("Escalate: $unlisted folder(s) could not be opened, so they were left alone.")
        }
        $links = Get-TreeEntryCount $e 'Links'
        if ($links -gt 0) {
            $linkNames = @($e.TreeCounts.LinkPaths | Select-Object -First 3)
            $linkMore = if ($links -gt $linkNames.Count) { " and $($links - $linkNames.Count) more" } else { '' }
            $parts.Add("$links junction(s) or symbolic link(s) ($($linkNames -join '; ')$linkMore) were listed but not gone into. Microsoft's documentation does not say whether takeown and icacls follow them, and icacls changes what a symbolic link points to, so check them and what they point to.")
        }
        $unchecked = Get-TreeEntryCount $e 'Unchecked'
        if ($unchecked -gt 0 -and $e.Result -ne 'Skipped (WhatIf)') {
            $parts.Add("$unchecked item(s) could not be read after the change, so it is not known who owns them now; check them.")
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
