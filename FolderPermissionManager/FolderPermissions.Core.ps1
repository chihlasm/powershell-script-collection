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
    skipped (takeown /D N) and keep their permissions; the result is then at best Partly done,
    names them so they can be escalated, and lists them all in <yyyy-MM-dd_HHmmss>_NotOpened.txt
    next to the snapshot. Afterwards it reads every owner back. It logs one row for the whole
    folder (ItemType 'Folder tree', Result Done, Partly done or Failed). The root of a drive,
    the Windows system folders and the SYSVOL, NETLOGON and PRINT$ shares are refused, under
    any spelling and through junctions and symbolic links (also those inside the folder),
    unless the caller passes -AllowSystemFolder.

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
    - Copy permissions (Copy-FolderPermission, add only, owner decision D-031):
      FileSystemAccessRule (account, rights, Allow/Deny and how the rule is propagated),
      AuthorizationRule.IsInherited (explicitly set or inherited from the parent; the SDDL ACE
      flag "ID" is INHERITED_ACE), InheritanceFlags and PropagationFlags, and
      FileSystemSecurity.AddAccessRule (adds a rule, never removes one):
      https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.filesystemaccessrule
      https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.authorizationrule.isinherited
      https://learn.microsoft.com/windows/win32/secauthz/ace-strings
      https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.inheritanceflags
      https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.propagationflags
      https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.filesystemsecurity.addaccessrule
      FileSystemRights (Synchronize "is automatically set when allowing access and
      automatically excluded when denying access", so it is left out of the rights shown):
      https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.filesystemrights
      Setting a DACL propagates inheritable ACEs to existing child objects; a child whose DACL
      is protected (SE_DACL_PROTECTED, "inheritance disabled") is not modified by inheritable
      ACEs, so subfolders that block inheritance are left as they are:
      https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow
      https://learn.microsoft.com/windows/win32/secauthz/security-descriptor-control
      NOT VERIFIED: which Win32 call Set-Acl uses (Learn does not say).
      What a child inherits: "inherit only" is dropped and "no propagate" clears the
      inheritance flags on the child, and generic rights (GA, GR, GW, GX) are mapped to file
      rights in the entry that applies to the child, so an inherited copy of a source rule is
      matched by account, Allow/Deny and rights after mapping (Test-InheritedCopyOfRule):
      https://learn.microsoft.com/windows/win32/secauthz/ace-inheritance-rules
      https://learn.microsoft.com/windows/win32/secauthz/generic-access-rights
      https://learn.microsoft.com/windows/win32/fileio/file-security-and-access-rights
      https://learn.microsoft.com/windows/win32/fileio/file-access-rights-constants
    - -LiteralPath on Test-Path, Get-Item, Get-ChildItem, Get-Acl and Set-Acl: with -Path, [ ]
      is a wildcard character range, so "HR [old]" matches "HR o" and not itself:
      https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_wildcards
      https://learn.microsoft.com/powershell/module/microsoft.powershell.management/test-path
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
      listed on its own and FileAttributes.ReparsePoint marks reparse points; those whose tag
      has the name surrogate bit (junctions, symbolic links, mounted folders) are links, which
      the owner snapshot lists but does not go into. FindFirstFile's dwReserved0 holds the tag
      when the item is a reparse point; Data Deduplication (0x80000013) and cloud placeholder
      tags are not name surrogates:
      https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-childitem
      https://learn.microsoft.com/dotnet/api/system.io.fileattributes
      https://learn.microsoft.com/windows/win32/fileio/reparse-point-tags
      https://learn.microsoft.com/windows/win32/api/minwinbase/ns-minwinbase-win32_find_dataw
      https://learn.microsoft.com/windows/win32/api/winnt/nf-winnt-isreparsetagnamesurrogate
    - PathIntrinsics.GetUnresolvedProviderPathFromPSPath (a relative path made full against the
      PowerShell location, without wildcard expansion):
      https://learn.microsoft.com/dotnet/api/system.management.automation.pathintrinsics.getunresolvedproviderpathfrompspath
    - Refusing drive roots and Windows folders under any spelling (D-036): \\?\, \\.\ and
      trailing dots and spaces (naming-a-file); %ProgramW6432% in a 32-bit process (WOW64);
      <letter>$ and ADMIN$ administrative shares, SYSVOL and NETLOGON ("used on domain
      controllers") and PRINT$ ("used during the remote administration of printers"); junctions, symbolic links and 8.3 names
      resolved with CreateFile (no access rights, FILE_FLAG_BACKUP_SEMANTICS),
      GetFinalPathNameByHandle and GetLongPathName:
      https://learn.microsoft.com/windows/win32/fileio/naming-a-file
      https://learn.microsoft.com/windows/win32/winprog64/wow64-implementation-details
      https://learn.microsoft.com/troubleshoot/windows-server/networking/remove-administrative-shares
      https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilew
      https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew
      https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getlongpathnamew
    - An Excel cell holds at most 32,767 characters, so the change log's Detail names at most 20
      folders per list:
      https://support.microsoft.com/office/excel-specifications-and-limits-1672b34d-7043-467e-8e27-269d656771c3
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
        Only reparse points that stand for another name are links (Test-LinkReparsePoint): a
        deduplicated file or a cloud placeholder folder is an ordinary item.
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
    if ($top -and (Test-LinkReparsePoint -Item $top)) { $links.Add($Path) }
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
            $isLink = Test-LinkReparsePoint -Item $child
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

    $backupFolder = Join-Path $LogFolder 'Backups'
    $newFolder = -not (Test-Path -LiteralPath $backupFolder)
    $file = New-BackupFilePath -LogFolder $LogFolder -ActionSlug 'TakeOwnership'
    try {
        $rows | ForEach-Object {
            [PSCustomObject][ordered]@{ Path = (ConvertTo-CsvSafeText $_.Path); ItemType = $_.ItemType; Owner = (ConvertTo-CsvSafeText $_.Owner); OwnerSid = $_.OwnerSid }
        } | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding UTF8 -NoClobber -ErrorAction Stop
    } catch {
        # Nothing will be changed, so leave no empty Backups folder suggesting otherwise. Only
        # a folder this call created, and only while it is empty: a file in it may be another
        # run's backup (-NoClobber fails exactly when one appeared in between), so no file is
        # ever deleted here. Directory.Delete with recursive $false never prompts and throws
        # instead of deleting a folder that is not empty.
        # https://learn.microsoft.com/dotnet/api/system.io.directory.delete
        if ($newFolder) {
            try { [System.IO.Directory]::Delete($backupFolder, $false) } catch { Write-Verbose "Left $backupFolder in place: $($_.Exception.Message)" }
        }
        throw
    }

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
    .PARAMETER Watch
        Paths to report on one by one (the folders that could not be opened): WatchedChanged
        lists those this change gave a new owner, that is whose owner now differs from the
        snapshot and is -Sid or Administrators, the only owners takeown /A and icacls set;
        WatchedUnchecked lists those whose owner was read for the snapshot but cannot be read
        afterwards, so it is not known whether this change touched them. A folder whose owner
        could be read neither before nor after shows no sign of a change and is in neither list.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Items,
        [Parameter(Mandatory)][string]$Sid,
        [AllowEmptyCollection()][string[]]$Watch = @()
    )

    $mine = 0; $notMine = 0; $unchecked = 0; $changed = 0; $admins = 0
    $watched = @{}
    foreach ($w in $Watch) { $watched[$w] = $true }
    $watchedChanged = New-Object System.Collections.Generic.List[string]
    $watchedUnchecked = New-Object System.Collections.Generic.List[string]
    foreach ($item in $Items) {
        $now = Get-ItemOwner -Path $item.Path
        if (-not $now.OwnerSid) {
            $unchecked++
            if ($watched.ContainsKey($item.Path) -and $item.OwnerSid) { $watchedUnchecked.Add($item.Path) }
            continue
        }
        if ($now.OwnerSid -eq $Sid) { $mine++ } else { $notMine++ }
        if ($now.OwnerSid -eq 'S-1-5-32-544' -and $now.OwnerSid -ne $Sid) { $admins++ }
        if ($now.OwnerSid -ne $item.OwnerSid) {
            $changed++
            if ($watched.ContainsKey($item.Path) -and ($now.OwnerSid -eq $Sid -or $now.OwnerSid -eq 'S-1-5-32-544')) {
                $watchedChanged.Add($item.Path)
            }
        }
    }
    [PSCustomObject]@{
        Mine               = $mine
        NotMine            = $notMine
        Unchecked          = $unchecked
        Changed            = $changed
        AdministratorsOnly = ($mine -eq 0 -and $notMine -gt 0 -and $admins -eq $notMine)
        WatchedChanged     = $watchedChanged.ToArray()
        WatchedUnchecked   = $watchedUnchecked.ToArray()
    }
}

function ConvertTo-ComparablePath {
    <#
    .SYNOPSIS
        One spelling of a path for comparing it with a protected folder (D-036), text only:
        D:\..., \\server\share\..., or Volume{...}\... Returns '' for a blank path.
    .DESCRIPTION
        Windows reads several spellings as the same folder, so each is turned into one:
        - \\?\ and \\.\ in front of a path are dropped and \\?\UNC\server\share becomes
          \\server\share ("\\?\" sends the rest of the string straight to the file system;
          "\\.\" is the device namespace, which also reaches C:\ through CreateFile).
        - Trailing dots and spaces are trimmed from every segment: Windows drops them from a
          name ("Do not end a file or directory name with a space or a period"), so
          C:\Windows. is C:\Windows. With \\?\ they are kept by the file system and name a
          different folder, but refusing that too is the safe side.
        - '.' segments are dropped and '..' removes the segment before it (never the drive or
          the \\server\share part); / is read as \ and repeated \ as one.
        https://learn.microsoft.com/windows/win32/fileio/naming-a-file
    #>
    param([AllowNull()][AllowEmptyString()][string]$Path)

    $p = "$Path".Trim().Replace('/', '\')
    if ($p -match '^\\\\[?.]\\UNC\\(.*)$') { $p = '\\' + $Matches[1] }
    elseif ($p -match '^\\\\[?.]\\(.*)$') { $p = $Matches[1] }
    $unc = $p.StartsWith('\\')
    $segments = New-Object System.Collections.Generic.List[string]
    foreach ($raw in @($p.TrimStart('\') -split '\\+')) {
        if ($raw -eq '.' -or $raw -eq '') { continue }
        if ($raw -eq '..') {
            $keep = if ($unc) { 2 } else { 1 }
            if ($segments.Count -gt $keep) { $segments.RemoveAt($segments.Count - 1) }
            continue
        }
        $name = $raw.TrimEnd('.', ' ')
        if ($name) { $segments.Add($name) }
    }
    if ($segments.Count -eq 0) { return '' }
    if ($unc) { return '\\' + ($segments.ToArray() -join '\') }
    if ($segments.Count -eq 1 -and $segments[0] -match '^[A-Za-z]:$') { return "$($segments[0])\" }
    $segments.ToArray() -join '\'
}

function Get-TreeOwnershipRefusal {
    <#
    .SYNOPSIS
        Why taking ownership of everything under -Path is refused, or $null when it is allowed
        (D-036). Refused: the root of a drive (D:\, \\?\D:\, \\server\D$) and %SystemRoot%,
        %ProgramFiles%, %ProgramW6432%, %ProgramFiles(x86)% and %ProgramData%, the folders
        themselves and anything under them; on another computer, its ADMIN$, SYSVOL, NETLOGON
        and PRINT$ shares and \\server\<letter>$\Windows, Program Files, Program Files (x86) and
        ProgramData. The root of any other share (\\fs01\share, \\fs01\Users$) is allowed.
    .DESCRIPTION
        Text only, nothing is read from disk (Get-TreeOwnershipTargetRefusal adds what only the
        disk can tell: junctions, symbolic links and 8.3 short names). The path and the
        protected folders are compared in one spelling (ConvertTo-ComparablePath),
        case-insensitively on whole path segments, so C:\Windows\System32 and \\?\C:\Windows.
        are refused and C:\WindowsOld is not. The variables are read when called, not when the
        file is loaded. %ProgramW6432% is the 64-bit Program Files folder seen from a 32-bit
        process, whose %ProgramFiles% is the x86 folder; it is empty on 32-bit Windows and then
        skipped. Another computer's variables cannot be read from here, so its standard folder
        names are used. The text names the path and does not say what to do about it: each
        caller adds its own next step (the command line has -AllowSystemFolder, the GUI has no
        override).
        WOW64: a 32-bit process has ProgramFiles=%ProgramFiles(x86)% and ProgramW6432=%ProgramFiles%.
        https://learn.microsoft.com/windows/win32/winprog64/wow64-implementation-details
        <DriveLetter>$ "is a shared root partition or volume"; ADMIN$ "is a resource that is
        used during remote administration of a computer". That ADMIN$ is the Windows folder is
        NOT VERIFIED on Learn; it is refused whatever it points to. NETLOGON and SYSVOL are "used
        on domain controllers" ("special administrative shares", not hidden) and PRINT$ "is used
        during the remote administration of printers": owners changed there touch Group Policy,
        logon scripts and printer drivers for every computer that uses them.
        https://learn.microsoft.com/troubleshoot/windows-server/networking/remove-administrative-shares
    #>
    param([Parameter(Mandatory)][string]$Path)

    $tail = 'Changing the owner of everything in it can stop Windows or installed programs from working, and cannot easily be undone. Choose the folder that needs fixing instead.'
    $driveTail = 'Taking ownership of a whole drive also changes the owner of Windows and program files on it, which cannot easily be undone. Choose the folder that needs fixing instead.'
    $normalized = ConvertTo-ComparablePath -Path $Path
    if ($normalized -match '^[A-Za-z]:\\$' -or $normalized -match '^Volume\{[^\\]*\}$') {
        return "$Path is the root of a drive. $driveTail"
    }

    # \\server\D$ is the root of drive D: on the server and ADMIN$ is used to administer it
    # remotely (administrative shares). An ordinary share root is allowed.
    if ($normalized -match '^\\\\([^\\]+)\\([^\\]+)(?:\\(.*))?$') {
        $server = $Matches[1]; $share = $Matches[2]; $rest = "$($Matches[3])"
        if ($share -ieq 'ADMIN$') {
            return "$Path is on the ADMIN`$ administrative share of $server, which is used to administer Windows remotely. $tail"
        }
        if ($share -ieq 'SYSVOL' -or $share -ieq 'NETLOGON') {
            return "$Path is on the $share share of $server, which domain controllers use for Group Policy and logon scripts. $tail"
        }
        if ($share -ieq 'PRINT$') {
            return "$Path is on the PRINT`$ share of $server, which holds the printer drivers it hands out. $tail"
        }
        if ($share -match '^([A-Za-z])\$$') {
            $drive = $Matches[1].ToUpperInvariant()
            if (-not $rest) {
                return "$Path is the root of drive $($drive): on $server (the $($drive)`$ administrative share). $driveTail"
            }
            $top = ($rest -split '\\')[0]
            foreach ($name in @('Windows', 'Program Files', 'Program Files (x86)', 'ProgramData')) {
                if ($top -ieq $name) {
                    return "$Path is in a Windows system folder on $server ($($drive):\$name). $tail"
                }
            }
        }
        return $null
    }

    foreach ($name in @('SystemRoot', 'ProgramFiles', 'ProgramW6432', 'ProgramFiles(x86)', 'ProgramData')) {
        $protected = ConvertTo-ComparablePath -Path ([Environment]::GetEnvironmentVariable($name))
        if (-not $protected) { continue }
        $protected = $protected.TrimEnd('\')
        if ($normalized.Equals($protected, [System.StringComparison]::OrdinalIgnoreCase) -or
            $normalized.StartsWith("$protected\", [System.StringComparison]::OrdinalIgnoreCase)) {
            return "$Path is in a Windows system folder (%$name%, $([Environment]::GetEnvironmentVariable($name))). $tail"
        }
    }
    $null
}

function Get-Win32PathName {
    <#
    .SYNOPSIS
        What Windows itself calls an existing folder: -Kind Final follows every junction and
        symbolic link in the path (the folder's own and its parents') and gives long names;
        -Kind Long only expands 8.3 short names (PROGRA~1). $null when it cannot be told (the
        path does not exist, cannot be opened, or the API cannot be loaded).
    .DESCRIPTION
        Final: CreateFile with no access rights ("can query certain metadata ... even if
        GENERIC_READ access would have been denied") and FILE_FLAG_BACKUP_SEMANTICS (needed to
        open a directory), then GetFinalPathNameByHandle ("for a symbolic link named
        C:\tmp\mydir that points to D:\yourdir, the final path would be D:\yourdir"; the result
        uses the \\?\ syntax). Over SMB it can fail with access denied on a parent folder.
        Long: GetLongPathName (fails when the path does not exist).
        https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilew
        https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew
        https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getlongpathnamew
    #>
    param([Parameter(Mandatory)][string]$Path, [ValidateSet('Final', 'Long')][string]$Kind = 'Final')

    try {
        if (-not ('FolderPermissionManager.Win32Path' -as [type])) {
            Add-Type -Namespace FolderPermissionManager -Name Win32Path -ErrorAction Stop -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint GetFinalPathNameByHandleW(Microsoft.Win32.SafeHandles.SafeFileHandle hFile, System.Text.StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint GetLongPathNameW(string lpszShortPath, System.Text.StringBuilder lpszLongPath, uint cchBuffer);
'@
        }
        $buffer = New-Object System.Text.StringBuilder -ArgumentList 32768
        if ($Kind -eq 'Long') {
            $length = [FolderPermissionManager.Win32Path]::GetLongPathNameW($Path, $buffer, [uint32]$buffer.Capacity)
        } else {
            # 7 = share read, write and delete; 3 = OPEN_EXISTING; 0x02000000 =
            # FILE_FLAG_BACKUP_SEMANTICS. Flags 0 = FILE_NAME_NORMALIZED and VOLUME_NAME_DOS.
            $handle = [FolderPermissionManager.Win32Path]::CreateFileW($Path, 0, 7, [IntPtr]::Zero, 3, 0x02000000, [IntPtr]::Zero)
            try {
                if ($handle.IsInvalid) { return $null }
                $length = [FolderPermissionManager.Win32Path]::GetFinalPathNameByHandleW($handle, $buffer, [uint32]$buffer.Capacity, 0)
            } finally { $handle.Dispose() }
        }
        if ($length -eq 0 -or $length -ge $buffer.Capacity) { return $null }
        $buffer.ToString()
    } catch {
        $null
    }
}

function Get-ReparsePointTag {
    <#
    .SYNOPSIS
        The reparse point tag of an existing item (for example 0xA0000003 for a junction), or
        $null when the item is not a reparse point or its tag cannot be read.
    .DESCRIPTION
        "To retrieve the reparse point tag, use the FindFirstFile function. If the
        dwFileAttributes member includes the FILE_ATTRIBUTE_REPARSE_POINT attribute, then the
        dwReserved0 member specifies the reparse point." A path with no wildcard finds the item
        itself; the \\?\ form is tried when the plain path fails (a path longer than MAX_PATH).
        Reads the directory entry only.
        https://learn.microsoft.com/windows/win32/fileio/reparse-point-tags
        https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-findfirstfilew
        https://learn.microsoft.com/windows/win32/api/minwinbase/ns-minwinbase-win32_find_dataw
    #>
    param([Parameter(Mandatory)][string]$Path)

    try {
        if (-not ('FolderPermissionManager.Win32Find' -as [type])) {
            Add-Type -Namespace FolderPermissionManager -Name Win32Find -ErrorAction Stop -MemberDefinition @'
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct FindData {
    public uint dwFileAttributes;
    public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
    public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
    public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
    public uint nFileSizeHigh;
    public uint nFileSizeLow;
    public uint dwReserved0;
    public uint dwReserved1;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string cFileName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string cAlternateFileName;
}
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern IntPtr FindFirstFileW(string lpFileName, out FindData lpFindFileData);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool FindClose(IntPtr hFindFile);
'@
        }
        $plain = $Path.TrimEnd('\')
        $candidates = @($plain)
        if ($plain -match '^[A-Za-z]:\\') { $candidates += "\\?\$plain" }
        elseif ($plain -match '^\\\\[^?.\\]') { $candidates += "\\?\UNC\$($plain.Substring(2))" }
        foreach ($candidate in $candidates) {
            $data = New-Object FolderPermissionManager.Win32Find+FindData
            $handle = [FolderPermissionManager.Win32Find]::FindFirstFileW($candidate, [ref]$data)
            # INVALID_HANDLE_VALUE is -1.
            if ($handle -eq [IntPtr]::Zero -or $handle -eq [IntPtr](-1)) { continue }
            $null = [FolderPermissionManager.Win32Find]::FindClose($handle)
            # 0x400 = FILE_ATTRIBUTE_REPARSE_POINT
            if (($data.dwFileAttributes -band 0x400) -eq 0) { return $null }
            return [uint32]$data.dwReserved0
        }
        $null
    } catch {
        $null
    }
}

function Test-LinkReparsePoint {
    <#
    .SYNOPSIS
        True when an item (from Get-Item or Get-ChildItem) is a junction, a symbolic link or
        another reparse point that stands for a different name, which takeown and icacls may
        follow. False for an ordinary item and for reparse points that do not (Data
        Deduplication, OneDrive and other cloud placeholders). A reparse point whose tag cannot
        be read counts as a link.
    .DESCRIPTION
        "Name surrogate bit. If this bit is set, the file or directory represents another named
        entity in the system" (bit 29, 0x20000000; IsReparseTagNameSurrogate). It is set in
        IO_REPARSE_TAG_MOUNT_POINT (0xA0000003, junctions and mounted folders) and
        IO_REPARSE_TAG_SYMLINK (0xA000000C), not in IO_REPARSE_TAG_DEDUP (0x80000013).
        https://learn.microsoft.com/windows/win32/fileio/reparse-point-tags
        https://learn.microsoft.com/windows/win32/api/winnt/nf-winnt-isreparsetagnamesurrogate
    #>
    param([Parameter(Mandatory)][object]$Item)
    if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) { return $false }
    $tag = Get-ReparsePointTag -Path "$($Item.FullName)"
    if ($null -eq $tag) { return $true }
    ($tag -band 0x20000000) -ne 0
}

function Test-PathThroughLink {
    # True when the folder or any folder above it is a junction or symbolic link
    # (Test-LinkReparsePoint). Reads attributes only. -LiteralPath throughout, so a folder
    # name with [ ] is read as it is; Split-Path -LiteralPath returns the parent ('' above
    # the root).
    # https://learn.microsoft.com/dotnet/api/system.io.fileattributes
    # https://learn.microsoft.com/powershell/module/microsoft.powershell.management/split-path
    param([Parameter(Mandatory)][string]$Path)
    $current = $Path
    while ($current) {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction SilentlyContinue
        if ($item -and (Test-LinkReparsePoint -Item $item)) { return $true }
        $parent = Split-Path -LiteralPath $current
        if (-not $parent -or $parent -eq $current) { break }
        $current = $parent
    }
    $false
}

function Get-TreeOwnershipTargetRefusal {
    <#
    .SYNOPSIS
        Get-TreeOwnershipRefusal for a folder as Windows will really reach it: also refused when
        -Path leads into a protected folder through a junction or symbolic link (on the folder
        or on any folder above it) or is spelt with 8.3 short names (C:\PROGRA~1). The text
        names -Path as given. $null when it is allowed.
    .DESCRIPTION
        Reads the disk (Get-Win32PathName, attributes only; nothing is opened for reading or
        changed). A path that does not exist is checked as text only. Also refused, because
        takeown and icacls would go to a place nobody checked:
        - the folder is, or is inside, a junction or symbolic link, and its final path is
          unknown or no different from the path as given. On a share the server follows its
          own junctions, so the final path the client gets back is the path itself and where
          the junction leads cannot be seen.
        - a segment looks like an 8.3 short name (~1) and neither the final nor the long path
          can be read, so the real path cannot be checked.
    #>
    param([Parameter(Mandatory)][string]$Path)

    $refusal = Get-TreeOwnershipRefusal -Path $Path
    if ($refusal) { return $refusal }
    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    $final = Get-Win32PathName -Path $Path -Kind Final
    $long = Get-Win32PathName -Path $Path -Kind Long
    $given = ConvertTo-ComparablePath -Path $Path
    $finalLeadsElsewhere = $false
    foreach ($form in @($final, $long)) {
        if (-not $form) { continue }
        $comparable = ConvertTo-ComparablePath -Path $form
        if ($comparable -ieq $given) { continue }
        if ($form -ceq $final) { $finalLeadsElsewhere = $true }
        $refusal = Get-TreeOwnershipRefusal -Path $comparable
        if ($refusal) {
            return "$Path leads to $comparable (through a junction, a symbolic link or a short name). $refusal"
        }
    }
    if (-not $final -and -not $long -and @($given -split '\\' | Where-Object { $_ -match '~\d' }).Count -gt 0) {
        return "$Path looks like a short (8.3) name and Windows could not tell its full name, so the tool could not check the real path against the Windows system folders. Type the folder's full name instead."
    }
    if (-not $finalLeadsElsewhere -and (Test-PathThroughLink -Path $Path)) {
        return "$Path is, or is inside, a junction or symbolic link, and where it leads could not be found out, so it cannot be checked against the Windows system folders. Choose the real folder it points to instead."
    }
    $null
}

function Get-TreeLinkRefusal {
    <#
    .SYNOPSIS
        Why a junction or symbolic link found inside -Path (Save-OwnerSnapshot LinkPaths,
        Get-OwnerTreeItem Links) stops taking ownership of the whole tree, or $null when none
        does. A link is refused when it leads into a protected folder or where it leads cannot
        be found out (Get-TreeOwnershipTargetRefusal, D-036).
    .DESCRIPTION
        Microsoft's documentation does not say whether takeown /R or icacls /T follow links,
        and icacls changes what a symbolic link points to unless /L is given, so a link inside
        the tree is checked like the folder itself. A link whose final path cannot be read at
        all (it points nowhere, or somewhere this account cannot open) is refused too. -Path
        itself is skipped: the caller checks it.
        https://learn.microsoft.com/windows-server/administration/windows-commands/icacls
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [AllowEmptyCollection()][string[]]$LinkPaths = @()
    )

    foreach ($link in @($LinkPaths)) {
        if (-not $link -or $link -eq $Path) { continue }
        $refusal = Get-TreeOwnershipTargetRefusal -Path $link
        if (-not $refusal -and -not (Get-Win32PathName -Path $link -Kind Final)) {
            $refusal = "$link is a junction or symbolic link, and where it leads could not be found out, so it cannot be checked against the Windows system folders."
        }
        if ($refusal) {
            return "$Path contains a junction or symbolic link that takeown and icacls may follow out of the folder. $refusal"
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
        function's parameters. It may output an object with Detail (what it really changed,
        instead of the planned Detail) and/or Result (it found nothing left to change and wrote
        nothing; the row gets that Result). Only Copy permissions uses this.
    .PARAMETER ProceedWhenUnreadable
        Change items whose current permissions cannot be read; the backup lists them as
        'Could not read' (D-027). Only Take ownership uses this: it exists for folders the
        administrator is locked out of.
    .PARAMETER Plan
        Optional script block run per existing item with ($Path, $ItemType), before
        ShouldProcess and without changing anything. It returns $null to go ahead with -Detail,
        or an object with Detail (this item's Detail instead of -Detail) and/or Result and
        ErrorText (the item is not changed or backed up, and its row gets that Result). A Plan
        that cannot read the item's permissions should return $null, so the normal flow refuses
        the item as unreadable; any exception it throws makes the row Failed with that error,
        and the item is not changed. Only Copy permissions uses this.
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
        [switch]$ProceedWhenUnreadable,
        [scriptblock]$Plan
    )

    $items = @(foreach ($p in $Path) {
        $itemType = Get-AclItemType -Path $p
        $planned = $null
        if ($itemType -and $Plan) {
            try {
                $planned = & $Plan $p $itemType
            } catch {
                $planned = [PSCustomObject]@{ Result = 'Failed'; ErrorText = "$(Format-Sentence $_.Exception.Message) Nothing was changed." }
            }
        }
        $itemDetail = if ($planned -and $planned.Detail) { "$($planned.Detail)" } else { $Detail }
        $state = if (-not $itemType) { 'NotFound' }
                 elseif ($planned -and $planned.Result) { 'Planned' }
                 elseif ($Cmdlet.ShouldProcess($p, "$Action ($itemDetail)")) { 'Change' }
                 else { 'WhatIf' }
        $readError = $null
        if ($state -eq 'Change' -and -not $ProceedWhenUnreadable) {
            try { $null = Get-Acl -LiteralPath $p -ErrorAction Stop } catch { $state = 'Unreadable'; $readError = $_.Exception.Message }
        }
        [PSCustomObject]@{ Path = $p; ItemType = $itemType; State = $state; ReadError = $readError; Detail = $itemDetail; Planned = $planned }
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
            New-PermissionChangeEntry -Action $Action -Target "$($item.Path)" -ItemType 'Unknown' -Detail $item.Detail `
                -Result 'Skipped (not found)' -ErrorText $why
            continue
        }
        if ($item.State -eq 'Planned') {
            New-PermissionChangeEntry -Action $Action -Target $item.Path -ItemType $item.ItemType -Detail $item.Detail `
                -Result "$($item.Planned.Result)" -ErrorText "$($item.Planned.ErrorText)"
            continue
        }
        if ($item.State -eq 'WhatIf') {
            New-PermissionChangeEntry -Action $Action -Target $item.Path -ItemType $item.ItemType -Detail $item.Detail -Result 'Skipped (WhatIf)'
            continue
        }
        if ($item.State -eq 'Unreadable') {
            New-PermissionChangeEntry -Action $Action -Target $item.Path -ItemType $item.ItemType -Detail $item.Detail `
                -OldValue 'Could not read' -Result 'Failed' `
                -ErrorText ("Could not read the current permissions, so nothing was changed. $(Format-Sentence $item.ReadError)".Trim())
            continue
        }
        if ($backupError) {
            New-PermissionChangeEntry -Action $Action -Target $item.Path -ItemType $item.ItemType -Detail $item.Detail `
                -Result 'Failed' -ErrorText $backupError
            continue
        }

        $old = Get-ItemSddl -Path $item.Path
        try {
            $outcome = @(& $Change $item.Path $item.ItemType | Where-Object {
                $null -ne $_ -and ($_.PSObject.Properties['Result'] -or $_.PSObject.Properties['Detail'])
            }) | Select-Object -Last 1
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
            New-PermissionChangeEntry -Action $Action -Target $item.Path -ItemType $item.ItemType -Detail $item.Detail `
                -OldValue $old -NewValue $after -Result 'Failed' -ErrorText $text -BackupFile $backupFile
            continue
        }
        $doneDetail = if ($outcome -and $outcome.Detail) { "$($outcome.Detail)" } else { $item.Detail }
        if ($outcome -and $outcome.Result) {
            # Nothing was left to change when it came to it (the item changed since the plan).
            New-PermissionChangeEntry -Action $Action -Target $item.Path -ItemType $item.ItemType -Detail $doneDetail -Result "$($outcome.Result)"
            continue
        }
        New-PermissionChangeEntry -Action $Action -Target $item.Path -ItemType $item.ItemType -Detail $doneDetail `
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
        (Get-TreeOwnershipTargetRefusal) unless -AllowSystemFolder is given.
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
        # No /D: "You must use this option in conjunction with the /r option" (takeown), and
        # its Y answer replaces a folder's permissions with full control for the user only. A
        # takeown failure is not fatal on its own: Set-Acl below is what sets the final owner,
        # and an administrator who already has access does not need takeown.
        # https://learn.microsoft.com/windows-server/administration/windows-commands/takeown
        $tool = Invoke-AclTool -Tool takeown -Arguments @('/F', $p, '/A')
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

function Format-PermissionRights {
    <#
    .SYNOPSIS
        File-system rights in the words the Add permission dialog uses ('Full control', 'Modify',
        'Read & execute', 'Read', 'Write'); any other combination as the .NET name
        ('ReadData, AppendData').
    .DESCRIPTION
        Synchronize is left out: Windows sets it on every Allow rule and leaves it off Deny rules,
        so 'Modify, Synchronize' is what Explorer and the dialog call Modify.
        https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.filesystemrights
    #>
    param([Parameter(Mandatory)][System.Security.AccessControl.FileSystemRights]$Rights)

    $fs = [System.Security.AccessControl.FileSystemRights]
    $sync = [int]$fs::Synchronize
    # Generic rights (a rule set as GA, GR, GW or GX) are shown as the file rights they stand
    # for; after mapping the value fits in an Int32 again.
    $value = [int](ConvertTo-SpecificFileRight $Rights) -band (-bnot $sync)
    if ($value -eq 0) { return $Rights.ToString() }
    $labels = [ordered]@{ FullControl = 'Full control'; Modify = 'Modify'; ReadAndExecute = 'Read & execute'; Read = 'Read'; Write = 'Write' }
    foreach ($name in $labels.Keys) {
        if ($value -eq ([int][System.Security.AccessControl.FileSystemRights]$name -band (-bnot $sync))) { return $labels[$name] }
    }
    # Enum.ToObject, not a cast: a cast refuses a value with bits that have no enum name.
    ([System.Enum]::ToObject($fs, $value)).ToString()
}

function Format-PermissionRule {
    # 'Allow Modify for BUILTIN\Users': one rule in the words of the change log and status bar.
    param([Parameter(Mandatory)][System.Security.AccessControl.FileSystemAccessRule]$Rule)
    "$($Rule.AccessControlType) $(Format-PermissionRights $Rule.FileSystemRights) for $($Rule.IdentityReference.Value)"
}

function Test-PathWithin {
    <#
    .SYNOPSIS
        True when Path is Root itself or a folder or file under it. Full paths, compared without
        regard to case and only at a backslash, so D:\HR2 is not under D:\HR. Nothing is read.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Root
    )
    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Root)) { return $false }
    $p = (Resolve-AclTargetPath -Path $Path).TrimEnd('\', '/')
    $r = (Resolve-AclTargetPath -Path $Root).TrimEnd('\', '/')
    $p.Equals($r, [System.StringComparison]::OrdinalIgnoreCase) -or
        $p.StartsWith("$r\", [System.StringComparison]::OrdinalIgnoreCase)
}

function ConvertTo-SpecificFileRight {
    <#
    .SYNOPSIS
        The access mask of file-system rights as a non-negative number, with the generic rights
        (GA, GR, GW, GX) replaced by the file and folder rights they stand for.
    .DESCRIPTION
        GENERIC_ALL (0x10000000) is "all possible access rights" (FILE_ALL_ACCESS, FullControl);
        GENERIC_READ (0x80000000), GENERIC_WRITE (0x40000000) and GENERIC_EXECUTE (0x20000000)
        map to FILE_GENERIC_READ, FILE_GENERIC_WRITE and FILE_GENERIC_EXECUTE. Windows does
        the same mapping when a child inherits a rule as an effective ACE.
        https://learn.microsoft.com/windows/win32/secauthz/generic-access-rights
        https://learn.microsoft.com/windows/win32/fileio/file-security-and-access-rights
        https://learn.microsoft.com/windows/win32/fileio/file-access-rights-constants
        https://learn.microsoft.com/windows/win32/secauthz/ace-inheritance-rules
    #>
    param([Parameter(Mandatory)][System.Security.AccessControl.FileSystemRights]$Rights)

    $fs = [System.Security.AccessControl.FileSystemRights]
    # GENERIC_READ is the sign bit of the Int32 enum, so work in Int64 without the sign.
    $value = [int64][int]$Rights -band [int64]4294967295
    $map = @(
        @{ Generic = [int64]0x10000000; Specific = [int64][int]$fs::FullControl }
        # FILE_GENERIC_READ: FILE_READ_DATA, FILE_READ_EA, FILE_READ_ATTRIBUTES,
        # STANDARD_RIGHTS_READ (READ_CONTROL), SYNCHRONIZE.
        @{ Generic = [int64]2147483648; Specific = [int64][int]($fs::Read -bor $fs::Synchronize) }
        # FILE_GENERIC_WRITE: FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_EA,
        # FILE_WRITE_ATTRIBUTES, STANDARD_RIGHTS_WRITE (READ_CONTROL), SYNCHRONIZE.
        @{ Generic = [int64]0x40000000; Specific = [int64][int]($fs::Write -bor $fs::ReadPermissions -bor $fs::Synchronize) }
        # FILE_GENERIC_EXECUTE: FILE_EXECUTE, FILE_READ_ATTRIBUTES, STANDARD_RIGHTS_EXECUTE
        # (READ_CONTROL), SYNCHRONIZE.
        @{ Generic = [int64]0x20000000; Specific = [int64][int]($fs::ExecuteFile -bor $fs::ReadAttributes -bor $fs::ReadPermissions -bor $fs::Synchronize) }
    )
    $result = $value
    foreach ($m in $map) {
        if ($value -band $m.Generic) { $result = ($result -band (-bnot $m.Generic)) -bor $m.Specific }
    }
    $result
}

function Test-InheritedCopyOfRule {
    <#
    .SYNOPSIS
        True when Ace is an inherited entry that a child gets from Rule (a rule that applies to
        subfolders): same account, same Allow/Deny, and at least Rule's rights.
    .DESCRIPTION
        The inherited entry does not carry the source rule's exact flags or rights: Windows
        removes "inherit only" (INHERIT_ONLY_ACE) on the child, clears the inheritance flags for
        "this folder and its direct children only" (NO_PROPAGATE_INHERIT_ACE), and maps generic
        rights to specific ones in the entry that applies to the child (splitting it from an
        inherit-only entry that keeps the generic rights). So the flags are not compared, and
        the rights are compared after mapping generic rights on both sides.
        https://learn.microsoft.com/windows/win32/secauthz/ace-inheritance-rules
    #>
    param(
        [Parameter(Mandatory)][System.Security.AccessControl.FileSystemAccessRule]$Ace,
        [Parameter(Mandatory)][System.Security.AccessControl.FileSystemAccessRule]$Rule
    )

    $containerInherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
    if (-not $Ace.IsInherited -or -not ($Rule.InheritanceFlags -band $containerInherit)) { return $false }
    if ($Ace.AccessControlType -ne $Rule.AccessControlType -or $Ace.IdentityReference -ne $Rule.IdentityReference) { return $false }
    $need = ConvertTo-SpecificFileRight $Rule.FileSystemRights
    ((ConvertTo-SpecificFileRight $Ace.FileSystemRights) -band $need) -eq $need
}

function Get-PermissionCopyPlan {
    <#
    .SYNOPSIS
        Adds to the target's ACL object, in memory only, each rule it does not already have.
        Returns Acl (the same object, changed, for Set-Acl) and Added (only the rules that
        really changed it; empty when nothing would change).
    .DESCRIPTION
        A rule matches when the account, rights, Allow/Deny and the inheritance and propagation
        flags are all the same. By default only the target's OWN (explicit) rules count: a rule
        set on the target itself stays when the parent changes, an inherited one does not.
        With -CountInherited (the target is the source or under it), an inherited match counts
        too: the target already gets that rule from the source, and adding it again as its own
        would leave it behind when the rule is later removed from the source. An inherited rule
        is matched as Windows writes it on the child, not by exact flags (Test-InheritedCopyOfRule:
        "inherit only", "this folder and direct children only" and generic rights all look
        different on the child).
        AddAccessRule only adds, and can merge a rule into an existing one for the same account
        (Read into an existing Modify), so each rule counts as added only when it changed the
        security descriptor.
        https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.filesystemsecurity.addaccessrule
        https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.authorizationrule.isinherited
    #>
    param(
        [Parameter(Mandatory)][System.Security.AccessControl.FileSystemSecurity]$Acl,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rule,
        [switch]$CountInherited
    )

    $added = @(foreach ($r in $Rule) {
        $exists = @($Acl.Access | Where-Object {
            ($CountInherited -or -not $_.IsInherited) -and
            $_.IdentityReference -eq $r.IdentityReference -and
            $_.FileSystemRights -eq $r.FileSystemRights -and
            $_.AccessControlType -eq $r.AccessControlType -and
            $_.InheritanceFlags -eq $r.InheritanceFlags -and
            $_.PropagationFlags -eq $r.PropagationFlags
        })
        if ($exists.Count -eq 0 -and $CountInherited) {
            $exists = @($Acl.Access | Where-Object { Test-InheritedCopyOfRule -Ace $_ -Rule $r })
        }
        if ($exists.Count -eq 0) {
            $before = $Acl.Sddl
            $Acl.AddAccessRule($r)
            if ($Acl.Sddl -cne $before) { $r }
        }
    })
    [PSCustomObject]@{ Acl = $Acl; Added = $added }
}

function Get-CopyDetail {
    # A Done Copy permissions row's Detail: the source and the rules added to that target.
    param([Parameter(Mandatory)][string]$SourcePath, [Parameter(Mandatory)][object[]]$Added)
    "Copied from $($SourcePath): $((@($Added | ForEach-Object { Format-PermissionRule $_ })) -join '; ')"
}

function Get-CopySourceText {
    # The source folder named in a Copy permissions row's Detail ("Copied from <source>: ..."),
    # or '' for other rows. A Windows path cannot contain ':' followed by a space.
    param([AllowNull()][object]$Entry)
    if ($null -ne $Entry -and "$($Entry.Detail)" -match '^Copied from (.+?): ') { return $Matches[1] }
    ''
}

function Copy-FolderPermission {
    <#
    .SYNOPSIS
        Adds the permissions set directly on the source folder to each target folder. Nothing is
        removed, and nothing below a target is written. Backed up first; one row per target.
    .DESCRIPTION
        Owner decision D-031 (add only):
        - Only the source's own (explicit) rules are copied. Rules it inherits from its parent
          are not: copied onto the target they would become the target's own rules, and later
          changes higher up the share would no longer reach it. When the source has none, every
          target is 'Skipped (nothing to copy)' and nothing is read or changed.
        - Each rule is added as the source's own FileSystemAccessRule object, so the rights,
          Allow/Deny and "applies to" (inheritance and propagation flags) arrive exactly as they
          are, with no translation to icacls.
          https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.filesystemaccessrule
          https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.inheritanceflags
          https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.propagationflags
        - Rules already on the target stay. A target that already has every rule is
          'Skipped (nothing to copy)' and is not written. For a target that is the source or
          under it, a rule it inherits counts as already there: it comes from the source, and
          copying it as the target's own would keep it there after it is removed from the
          source. For any other target only its own rules count.
        - One Set-Acl on the target folder. Windows then passes the new inheritable rules down to
          the subfolders and files that inherit permissions ("the system automatically
          propagates any inheritable access control entries (ACEs) to existing child objects"),
          and not to those that block inheritance (SE_DACL_PROTECTED "prevents the DACL of the
          security descriptor from being modified by inheritable ACEs"), which are left as they
          are.
          https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow
          https://learn.microsoft.com/windows/win32/secauthz/security-descriptor-control
          NOT VERIFIED: Learn does not say which Win32 call Set-Acl uses to write a folder's
          permissions; Add permission has always relied on the same propagation.
        - A target that is a file is refused: the copied rules are for folders.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$SourcePath,
        [Parameter(Mandatory)][AllowEmptyString()][AllowEmptyCollection()][string[]]$TargetPath,
        [Parameter(Mandatory)][string]$LogFolder
    )

    $action = 'Copy permissions'
    $detail = "Copy the permissions set on $SourcePath"
    try {
        if ([string]::IsNullOrWhiteSpace($SourcePath)) { throw 'No source folder was given.' }
        $sourceAcl = Get-Acl -LiteralPath $SourcePath -ErrorAction Stop
    } catch {
        $reason = "Could not read the permissions of the source folder $($SourcePath): $(Format-Sentence $_.Exception.Message) Nothing was changed."
        foreach ($t in $TargetPath) {
            $itemType = Get-AclItemType -Path $t
            if (-not $itemType) { $itemType = 'Unknown' }
            New-PermissionChangeEntry -Action $action -Target "$t" -ItemType $itemType -Detail $detail -Result 'Failed' -ErrorText $reason
        }
        return
    }
    $allRules = @($sourceAcl.Access)
    $sourceRules = @($allRules | Where-Object { -not $_.IsInherited })

    if ($sourceRules.Count -eq 0) {
        $nothing = "Nothing to copy: $SourcePath has no permissions of its own."
        # Split-Path -Parent is a string operation: no wildcards, nothing is read.
        $parent = Split-Path -Path $SourcePath -Parent
        if ($allRules.Count -gt 0 -and $parent) { $nothing += " All of its permissions come from $parent." }
        foreach ($t in $TargetPath) {
            $itemType = Get-AclItemType -Path $t
            if (-not $itemType) {
                # A missing target is still reported as missing; the Detail says why nothing
                # would have been copied anyway.
                $why = if ([string]::IsNullOrWhiteSpace($t)) { 'No path was given.' } else { 'The folder or file does not exist.' }
                New-PermissionChangeEntry -Action $action -Target "$t" -ItemType 'Unknown' -Detail $nothing -Result 'Skipped (not found)' -ErrorText $why
                continue
            }
            New-PermissionChangeEntry -Action $action -Target "$t" -ItemType $itemType -Detail $nothing -Result 'Skipped (nothing to copy)'
        }
        return
    }

    # A target that is the source or under it already inherits the source's inheritable rules;
    # those count as present, or they would be frozen onto it as its own (Get-PermissionCopyPlan).
    $already = 'Already has these permissions; nothing changed.'
    Invoke-SingleItemAclChange -Cmdlet $PSCmdlet -Path $TargetPath -Action $action -ActionSlug 'CopyPermissions' `
        -Detail $detail -LogFolder $LogFolder -Plan {
        param($p, $itemType)
        if ($itemType -eq 'File') {
            return [PSCustomObject]@{ Result = 'Failed'; ErrorText = "$p is a file. Copy permissions copies to folders only." }
        }
        # A target that cannot be read is left to the normal flow, which refuses it.
        try { $acl = Get-Acl -LiteralPath $p -ErrorAction Stop } catch { return $null }
        $copy = Get-PermissionCopyPlan -Acl $acl -Rule $sourceRules -CountInherited:(Test-PathWithin -Path $p -Root $SourcePath)
        if ($copy.Added.Count -eq 0) {
            return [PSCustomObject]@{ Result = 'Skipped (nothing to copy)'; Detail = $already }
        }
        [PSCustomObject]@{ Detail = Get-CopyDetail -SourcePath $SourcePath -Added $copy.Added }
    } -Change {
        param($p, $itemType)
        # Read again: the target may have changed since it was checked. The row then says what
        # was really added, or that nothing was left to add.
        $acl = Get-Acl -LiteralPath $p -ErrorAction Stop
        $copy = Get-PermissionCopyPlan -Acl $acl -Rule $sourceRules -CountInherited:(Test-PathWithin -Path $p -Root $SourcePath)
        if ($copy.Added.Count -eq 0) {
            return [PSCustomObject]@{ Result = 'Skipped (nothing to copy)'; Detail = $already }
        }
        Set-Acl -LiteralPath $p -AclObject $copy.Acl -ErrorAction Stop
        [PSCustomObject]@{ Detail = Get-CopyDetail -SourcePath $SourcePath -Added $copy.Added }
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
        2. The root of a drive and the Windows system folders are refused, also when reached
           through a junction, a symbolic link or a short name (Get-TreeOwnershipTargetRefusal,
           D-036), unless -AllowSystemFolder: only the folder's name and attributes are read,
           and nothing is written or changed.
        3. ShouldProcess once for the folder (-WhatIf: no owner is read, nothing is written or
           changed).
        4. Save-OwnerSnapshot: if it cannot be written and checked, nothing is changed.
        5. Unless -AllowSystemFolder, every junction and symbolic link the snapshot found inside
           the folder is checked like the folder (Get-TreeLinkRefusal): one that leads into a
           protected folder, or whose destination cannot be found out, refuses the whole tree.
           The folder itself is checked again too, so a junction swapped in after step 2 is
           caught. A refused tree is Failed and nothing is changed; the snapshot is kept (the
           row names it, so it is not taken for an interrupted run) and needs no restoring.
        6. takeown /F <dir> /R /A /D N gives every item to Administrators, so an administrator
           can open items they are locked out of. A folder the account cannot list (no List
           Folder and Read permission) is skipped by /D N and keeps its permissions (D-034);
           /D Y would replace them with full control for the user only. The tree is then at
           best Partly done, the folders are listed in <stamp>_NotOpened.txt next to the
           snapshot (Save-NotOpenedList), and the message tells the technician to escalate them.
        7. icacls <dir> /setowner <DOMAIN\user> /T /C /Q makes the current account the owner.
           The full name from WindowsIdentity, not $env:USERNAME, which has no domain and is
           wrong under SYSTEM and service accounts.
        8. The owner of every item in the snapshot is read again (Get-OwnerReadBack).
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
        UnlistedFolders (folders that could not be opened, which takeown skipped),
        UnlistedChanged and UnlistedChangedFolders (those of them whose owner was changed
        anyway), UnlistedUnchecked and UnlistedUncheckedFolders (those of them whose owner
        could not be read afterwards), NotOpenedFile (the full list of them, or ''), Links and
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
        $refusal = Get-TreeOwnershipTargetRefusal -Path $Path
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

    # D-036 for what only the listing shows: a junction or symbolic link inside the folder
    # that leads into a protected folder, or somewhere that cannot be checked. Then the folder
    # itself once more, as late as possible, in case a junction was swapped in since the first
    # check. The snapshot is kept and named, so it is not mistaken for an interrupted run.
    if (-not $AllowSystemFolder) {
        $refusal = Get-TreeLinkRefusal -Path $Path -LinkPaths @($snapshot.LinkPaths)
        if (-not $refusal) { $refusal = Get-TreeOwnershipTargetRefusal -Path $Path }
        if ($refusal) {
            return New-PermissionChangeEntry -Action $action -Target $Path -ItemType 'Folder tree' -Detail $detail -Result 'Failed' `
                -OldValue "Saved in $($snapshot.File)" -BackupFile $snapshot.File `
                -ErrorText "$refusal The owners read before this check were kept in $($snapshot.File); nothing needs to be put back from it. Nothing was changed."
        }
    }

    $takeown = Invoke-AclTool -Tool takeown -Arguments $takeownArgs
    $icacls = Invoke-AclTool -Tool icacls -Arguments $icaclsArgs
    # A folder takeown skipped may still get a new owner: icacls /setowner /T is run on the
    # whole tree and may set the owner of the skipped folder itself (NOT VERIFIED on Learn,
    # which says nothing about it). So its owner is read back like every other item, and the
    # message says "left alone" only when it did not change.
    $check = Get-OwnerReadBack -Items $snapshot.Items -Sid $mySid -Watch @($snapshot.UnlistedFolders)
    $total = $snapshot.Count
    $unlistedChanged = @($check.WatchedChanged)
    $unlistedUnchecked = @($check.WatchedUnchecked)

    # What the owners are now, from the read-back.
    $newValue = if ($check.Mine -eq $total) { "Owner: $me" }
                elseif ($check.Mine -gt 0) { "Owner: $me on $($check.Mine) of $total items" }
                elseif ($check.AdministratorsOnly -and $takeown.ExitCode -eq 0) { 'Owner: Administrators (icacls failed)' }
                elseif ($check.NotMine -eq 0) { 'Not checked' }
                elseif ($check.Changed -eq 0) { 'Owner unchanged' }
                else { "Owner: $me on 0 of $total items" }
    # No owner read back at all is not a success: nothing is known about the result. A folder
    # that could not be opened was skipped with what is inside it, so the tree is at best
    # Partly done (D-034), even when every item that was read back is owned.
    $readBackResult = if ($check.Mine -eq 0 -and $check.NotMine -eq 0) { 'Partly done' }
                      elseif ($check.NotMine -eq 0 -and $snapshot.Unlisted -gt 0) { 'Partly done' }
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

    # Written after the tools ran, so the owner snapshot is the only file in Backups while
    # anything changes; it is a list for the escalation, not a backup.
    $notOpenedFile = ''
    if ($snapshot.Unlisted -gt 0) {
        $notOpenedFile = Save-NotOpenedList -SnapshotFile $snapshot.File -Path $Path -Folder @($snapshot.UnlistedFolders) -OwnerChanged $unlistedChanged -OwnerUnchecked $unlistedUnchecked
    }

    # Detail is for the log reader; the messages use the counts on the row instead. At most
    # 20 names per list: an Excel cell holds 32,767 characters, and the full list of folders
    # that could not be opened is in its own file.
    # https://support.microsoft.com/office/excel-specifications-and-limits-1672b34d-7043-467e-8e27-269d656771c3
    $fullList = if ($notOpenedFile) { " (full list: $notOpenedFile)" } else { ' (the full list could not be saved to a file)' }
    $notes = @(
        "$detail."
        $(if ($snapshot.Unreadable -gt 0) { "$($snapshot.Unreadable) item(s) had no readable owner before the change." })
        $(if ($snapshot.Unlisted -gt 0) { "$($snapshot.Unlisted) folder(s) could not be opened, so takeown /D N skipped them and the owners inside them are not in the backup: $(Format-PathList -Path @($snapshot.UnlistedFolders) -First 20 -More $fullList)." })
        $(if ($unlistedChanged.Count -gt 0) { "The owner of $($unlistedChanged.Count) of them was changed anyway (read back), but not their permissions: $(Format-PathList -Path $unlistedChanged -First 20)." })
        $(if ($unlistedUnchecked.Count -gt 0) { "The owner of $($unlistedUnchecked.Count) of them could not be read afterwards, so it is not known whether it changed: $(Format-PathList -Path $unlistedUnchecked -First 20)." })
        $(if ($snapshot.Links -gt 0) { "$($snapshot.Links) junction(s) or symbolic link(s) were listed but not gone into: $(Format-PathList -Path @($snapshot.LinkPaths) -First 20)." })
        "Ran: $(Format-AclToolCommand -Tool takeown -Arguments $takeownArgs); $(Format-AclToolCommand -Tool icacls -Arguments $icaclsArgs)"
    ) | Where-Object { $_ }

    $row = New-PermissionChangeEntry -Action $action -Target $Path -ItemType 'Folder tree' -Detail ($notes -join ' ') `
        -OldValue "Saved in $($snapshot.File)" -NewValue $newValue -Result $result -ErrorText ($problems -join ' ') -BackupFile $snapshot.File
    Add-TreeEntryCount -Entry $row -Counts ([ordered]@{
        ItemCount                = $total
        Unreadable               = $snapshot.Unreadable
        Unlisted                 = $snapshot.Unlisted
        UnlistedFolders          = @($snapshot.UnlistedFolders)
        UnlistedChanged          = $unlistedChanged.Count
        UnlistedChangedFolders   = $unlistedChanged
        UnlistedUnchecked        = $unlistedUnchecked.Count
        UnlistedUncheckedFolders = $unlistedUnchecked
        NotOpenedFile            = $notOpenedFile
        Links                    = $snapshot.Links
        LinkPaths                = @($snapshot.LinkPaths)
        Unchecked                = $check.Unchecked
        NotOwned                 = $check.NotMine
        Changed                  = $check.Changed
    })
    $row
}

function Format-PathList {
    # "a; b; c and 2 more": the first -First paths, then how many were left out and -More (for
    # example " (full list: <file>)"), which is only added when some were left out.
    param([AllowEmptyCollection()][string[]]$Path = @(), [int]$First = 3, [string]$More = '')
    $all = @($Path)
    $shown = @($all | Select-Object -First $First)
    $text = $shown -join '; '
    if ($all.Count -gt $shown.Count) { $text += " and $($all.Count - $shown.Count) more$More" }
    $text
}

function Save-NotOpenedList {
    <#
    .SYNOPSIS
        Writes every folder that could not be opened while taking ownership of -Path to
        <stamp>_NotOpened.txt next to the owner snapshot (one path per line, after a heading),
        for the escalation. Returns the file, or '' when it cannot be written: the change is
        already made, and the change log still names the first 20 folders.
    #>
    param(
        [Parameter(Mandatory)][string]$SnapshotFile,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Folder,
        [AllowEmptyCollection()][string[]]$OwnerChanged = @(),
        [AllowEmptyCollection()][string[]]$OwnerUnchecked = @()
    )

    $name = (Split-Path -Leaf $SnapshotFile) -replace '_TakeOwnership(_\d+)?\.csv$', '_NotOpened$1.txt'
    $file = Join-Path (Split-Path -Parent $SnapshotFile) $name
    $changed = @{}
    foreach ($c in $OwnerChanged) { $changed[$c] = $true }
    $unchecked = @{}
    foreach ($u in $OwnerUnchecked) { $unchecked[$u] = $true }
    $lines = @(
        "Folders that could not be opened while taking ownership of $Path ($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))."
        'takeown skipped them, so their permissions were not changed. Ask a senior engineer to take ownership of them with an account that can open them.'
        $(if ($changed.Count -gt 0) { 'A folder marked (owner changed) has a new owner, but not new permissions.' })
        $(if ($unchecked.Count -gt 0) { 'A folder marked (owner could not be checked) could not be read afterwards, so it is not known whether its owner changed.' })
        ''
        $(foreach ($f in $Folder) {
            if ($changed.ContainsKey($f)) { "$f`t(owner changed)" }
            elseif ($unchecked.ContainsKey($f)) { "$f`t(owner could not be checked)" }
            else { $f }
        })
    ) | Where-Object { $null -ne $_ }
    try {
        Set-Content -LiteralPath $file -Value $lines -Encoding UTF8 -ErrorAction Stop
        $file
    } catch {
        Write-Verbose "Could not write the list of folders that could not be opened: $($_.Exception.Message)"
        ''
    }
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

function Get-NotOpenedEscalation {
    <#
    .SYNOPSIS
        The next step for the folders a whole-tree row could not open (D-034), as one passage:
        "Escalate: <n> folder(s) could not be opened, so they were left alone." (or, for those
        whose owner was read back changed, that their owner was changed but not their
        permissions, and for those whose owner could not be read back, that it could not be
        checked), the first three names and the file with all of them (or that it could not be
        saved), who to hand them to, and that what is inside them cannot be restored from the
        snapshot.
    .DESCRIPTION
        takeown /D N skips a folder it cannot open, so its permissions stay as they were; its
        owner is read back, because icacls /setowner /T may still change it (NOT VERIFIED).
        https://learn.microsoft.com/windows-server/administration/windows-commands/takeown
    #>
    param([Parameter(Mandatory)][object]$Entry)

    $count = Get-TreeEntryCount $Entry 'Unlisted'
    $changed = @($Entry.TreeCounts.UnlistedChangedFolders)
    $unchecked = @($Entry.TreeCounts.UnlistedUncheckedFolders)
    $opening = if ($changed.Count -eq 0 -and $unchecked.Count -eq 0) {
        "Escalate: $count folder(s) could not be opened, so they were left alone."
    } elseif ($unchecked.Count -eq 0 -and $changed.Count -ge $count -and $count -eq 1) {
        'Escalate: 1 folder(s) could not be opened: its owner was changed, but its permissions were not.'
    } elseif ($unchecked.Count -eq 0 -and $changed.Count -ge $count) {
        "Escalate: $count folder(s) could not be opened: their owners were changed, but their permissions were not."
    } elseif ($unchecked.Count -eq 0) {
        "Escalate: $count folder(s) could not be opened. $($changed.Count) of them had their owner changed, but not their permissions ($(Format-PathList -Path $changed -First 3)); the other $($count - $changed.Count) were left alone."
    } elseif ($changed.Count -eq 0 -and $unchecked.Count -ge $count -and $count -eq 1) {
        'Escalate: 1 folder(s) could not be opened, and its owner could not be checked afterwards.'
    } elseif ($changed.Count -eq 0 -and $unchecked.Count -ge $count) {
        "Escalate: $count folder(s) could not be opened, and their owners could not be checked afterwards."
    } else {
        # A folder that is neither changed nor unchecked was read back with its old owner.
        $alone = $count - $changed.Count - $unchecked.Count
        @(
            "Escalate: $count folder(s) could not be opened."
            $(if ($changed.Count -gt 0) { "$($changed.Count) of them had their owner changed, but not their permissions ($(Format-PathList -Path $changed -First 3))." })
            "The owner of $($unchecked.Count) of them could not be checked afterwards ($(Format-PathList -Path $unchecked -First 3))."
            $(if ($alone -gt 0) { "The other $alone were left alone." })
        ) -join ' '
    }
    $file = "$($Entry.TreeCounts.NotOpenedFile)"
    @(
        $opening
        "Not opened: $(Format-PathList -Path @($Entry.TreeCounts.UnlistedFolders) -First 3)."
        $(if ($file) { "Full list: $file." }
          elseif ($count -gt 3) { 'The full list could not be saved to a file; the change log names up to 20 of them, and the command-line script prints them all.' })
        'Ask a senior engineer to take ownership of them with an account that can open them.'
        'The owners of what is inside them were not saved and cannot be restored from this backup.'
    ) -join ' '
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
        $unlisted = Get-TreeEntryCount $e 'Unlisted'
        switch ($e.Result) {
            'Done'                { $parts.Add("Took $what.") }
            'Partly done'         {
                if ($unlisted -gt 0 -and -not $e.Error -and (Get-TreeEntryCount $e 'NotOwned') -eq 0 -and $e.NewValue -ne 'Not checked') {
                    # Partly done only because folders could not be opened (D-034): everything
                    # else is owned now, and the escalation below names what was skipped.
                    $parts.Add("Took ownership of $($e.Target) and every subfolder and file that could be opened. $restore")
                } elseif ($e.NewValue -eq 'Not checked') {
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

        if ($unlisted -gt 0) {
            $parts.Add((Get-NotOpenedEscalation -Entry $e))
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
    .PARAMETER NoInheritanceNote
        Leave out, for a copy, the sentence that subfolders and files that inherit get the
        permissions too and those that block inheritance were not changed. It is true when every
        target got one Set-Acl and the items below it were left to Windows (the GUI), and when
        the caller left out the folders that block inheritance (the command line skips them).
        A caller that writes to such folders, or to the items below a target, must pass it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries,
        [AllowNull()][string]$LogPath,
        [Parameter(Mandatory)][string]$LogFolder,
        [switch]$NoInheritanceNote
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
        'Copy permissions'  {
            # Each Done row's Detail lists the rules added to that target; the line names the source.
            $source = Get-CopySourceText @($done)[0]
            if ($source) { "Permissions copied from $source", 'to' } else { $first.Detail, 'to' }
        }
        default             { $first.Action, 'on' }
    }
    $upToDate = @($all | Where-Object { $_.Result -eq 'Skipped (nothing to copy)' })
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
        if ($first.Action -eq 'Copy permissions' -and -not $NoInheritanceNote) {
            # One Set-Acl on each target: Windows passes the new rules to the items below that
            # inherit, never to those that block inheritance (see Copy-FolderPermission).
            $parts.Add('Subfolders and files that inherit permissions get them too. Any that block inheritance were not changed.')
            $parts.Add('That is expected: Windows passes permissions down only to the items that inherit them, as Explorer does.')
        }
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
    } elseif ($touched.Count -eq 0 -and $upToDate.Count -lt $all.Count) {
        $parts.Add('Nothing was changed.')
    }
    # The source has no permissions of its own: every row carries the same sentence (missing
    # targets too, which are still reported as not found below).
    $noOwn = @($all | Where-Object { $_.Action -eq 'Copy permissions' -and $_.Detail -like 'Nothing to copy:*' })
    if ($noOwn.Count -gt 0) {
        $parts.Add($noOwn[0].Detail)
        $parts.Add('Open a folder that has its own permissions, or use Add Permission.')
    }
    if ($upToDate.Count -gt 0) {
        $already = @($upToDate | Where-Object { $_.Detail -notlike 'Nothing to copy:*' })
        if ($already.Count -gt 0) {
            if ($all.Count -eq 1) { $parts.Add("$($first.Target) already has these permissions, so nothing was changed.") }
            else { $parts.Add("$($already.Count) folder(s) already had these permissions and were not changed.") }
        }
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
