#Requires -Version 5.1

<#
.SYNOPSIS
    Folder Permission Manager -- Windows app (WPF) for viewing and changing NTFS folder and file
    permissions.

.DESCRIPTION
    Opens a desktop window for:
      - Browsing local and mapped drives and typed paths (\\server\share) in a folder tree
      - Seeing who owns a folder and who has access to it (User or Group, Permission Level,
        Allow/Deny, Inherited), and whether it gets permissions from the folder above
      - Seeing the files in a folder (name, size, modified) and who has access to the selected
        files, with a warning when the selected files have different permissions
      - Changing them, one change at a time: Add Permission and Remove Permission (folder or
        selected files), Take Ownership (this folder only, selected files, or the folder and
        all its subfolders and files), and Copy Permissions To... (adds only)
      - Exporting a permission report for a folder and all its subfolders to CSV

    Every change is made by FolderPermissions.Core.ps1, the same code the command-line script
    uses: the permissions are backed up first (nothing is changed when the backup cannot be
    saved) and each item is written to the change log. Before a change starts, a "Started" row
    is logged for each item. Where a change will really land (the share behind a mapped drive,
    the server behind a DFS path) is worked out in the background before anything is asked, and
    shown in the dialogs. Destructive changes ask first in a dialog that names the path, its
    real location and how many items, with Cancel as the default button. Afterwards each item
    is read again: a change that did not leave the intended permissions or owner is reported as
    "Done, with items to check". Taking ownership of a whole folder tree is refused on the root
    of a drive, on Windows system folders and shares (D-036), on the folder that holds every
    user profile, and in System Volume Information and $Recycle.Bin, checked on the real
    location (for a share, the folder on the server).

    Everything slow (opening a folder on a busy share, reading permissions, a change, the
    export) runs in the background, so the window never freezes; a busy line shows what is
    running and for how long. The window cannot be closed while a change runs. Nothing listens
    on the network.

    The window needs administrator rights. Started without them, it asks Windows for them (UAC)
    and opens again; mapped drives are passed on, because an elevated window usually cannot see
    them. Only one window per log folder can be open at a time.

.PARAMETER LogFolder
    Folder for permission backups and the change log. Defaults to the Logs folder next to this
    script; if the script is on a network share or any drive that is not a local fixed disk,
    inside a OneDrive or SharePoint sync folder, or that folder is read-only,
    %LOCALAPPDATA%\FolderPermissionManager\Logs is used instead. A folder passed here is used as
    given (the window warns when it is on the network or in a sync folder). The window shows
    which folder is used and has an "Open log folder" button.

.PARAMETER DriveMap
    Used by the tool itself when it opens again as administrator: the mapped drives of the
    first, non-elevated window. Leave it out.

.PARAMETER LoadFunctionsOnly
    Define the script's functions and return without opening the window. Used by the Pester
    tests.

.EXAMPLE
    .\FolderPermissionManager-GUI.ps1
    Opens the window (asks for administrator rights first if needed).

.EXAMPLE
    .\FolderPermissionManager-GUI.ps1 -LogFolder 'D:\Tickets\12345\PermissionChanges'
    Opens the window and keeps backups and the change log in the ticket folder.

.EXAMPLE
    .\FolderPermissionManager-GUI.ps1 -WhatIf
    Dry run: the window says "Dry run (WhatIf): nothing will be changed", and every change
    reports "WhatIf: nothing was changed (<n> items would be)." Nothing is backed up or logged:
    no Started or result rows are written and the change log is not created.

.NOTES
    Requires: Windows PowerShell 5.1 (or PowerShell 7 on Windows), run as administrator (the
    window asks for it). FolderPermissions.Core.ps1 must stay next to this script: it holds the
    permission reading, backup and change-log logic shared with the command-line script and
    the browser version.

    Files written:
      <log folder>  At startup, even with -WhatIf: the Logs folder next to this script is
                    created (when it is on a local fixed disk and not in a OneDrive
                    or SharePoint sync folder) and a small probe file is written
                    and deleted there, to check it can be written. Each change writes its
                    "Started" rows, its backup (Backups\) and its result rows
                    (Changes_<yyyy-MM-dd>.csv) here, plus a "Done, with items to check" row for
                    an item whose read-back did not show the intended state; with -WhatIf
                    nothing is written.
      %LOCALAPPDATA%\FolderPermissionManager\Logs\Unlogged_<yyyy-MM-dd>.csv   only when the
                    change log could not be written after a change: the result rows, so what
                    was changed is not lost (the status line names the file)
      %LOCALAPPDATA%\FolderPermissionManager\settings.json   theme (dark or light)
      %LOCALAPPDATA%\FolderPermissionManager\gui-errors.log  unexpected errors with their raw
                    text (may name client folders), for support; trimmed to the last 1 MB at
                    startup
      The export CSV where you save it (the Save dialog starts in Documents when that is a local
      fixed disk outside OneDrive, else %LOCALAPPDATA%\FolderPermissionManager\Exports). It
      holds the folder paths, owners and account names of the whole tree.

    REFERENCES
    - WPF windows need a single-threaded apartment (STA); powershell.exe -STA starts one:
      https://learn.microsoft.com/dotnet/desktop/wpf/advanced/threading-model
      https://learn.microsoft.com/dotnet/api/system.threading.thread.setapartmentstate
      https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe
    - XamlReader.Parse / XamlReader.Load (the window is built from XAML text):
      https://learn.microsoft.com/dotnet/api/system.windows.markup.xamlreader.parse
      https://learn.microsoft.com/dotnet/api/system.windows.markup.xamlreader.load
    - DispatcherTimer (its Tick runs on the UI thread, so results are shown from there):
      https://learn.microsoft.com/dotnet/api/system.windows.threading.dispatchertimer
    - RunspaceFactory.CreateRunspacePool, InitialSessionState (functions and execution policy
      for the pool), PowerShell.BeginInvoke / EndInvoke / BeginStop:
      https://learn.microsoft.com/dotnet/api/system.management.automation.runspaces.runspacefactory.createrunspacepool
      https://learn.microsoft.com/dotnet/api/system.management.automation.runspaces.initialsessionstate
      https://learn.microsoft.com/dotnet/api/system.management.automation.runspaces.sessionstatefunctionentry
      https://learn.microsoft.com/dotnet/api/system.management.automation.runspaces.initialsessionstate.executionpolicy
      https://learn.microsoft.com/dotnet/api/system.management.automation.powershell.begininvoke
      https://learn.microsoft.com/dotnet/api/system.management.automation.powershell.endinvoke
      https://learn.microsoft.com/dotnet/api/system.management.automation.powershell.beginstop
    - WindowsPrincipal.IsInRole(WindowsBuiltInRole.Administrator) and Start-Process -Verb RunAs
      (the UAC prompt):
      https://learn.microsoft.com/dotnet/api/system.security.principal.windowsprincipal.isinrole
      https://learn.microsoft.com/powershell/module/microsoft.powershell.management/start-process
    - How a command line is split into arguments (a backslash before a closing quote escapes
      it, so trailing backslashes are doubled):
      https://learn.microsoft.com/cpp/c-language/parsing-c-command-line-arguments
    - Named Mutex (createdNew says whether this call created it) and the Global\ prefix (one
      name for every session on the computer); Path.GetFullPath makes one spelling of the log
      folder (".." and "/" resolved) before the name is hashed:
      https://learn.microsoft.com/dotnet/api/system.threading.mutex.-ctor
      https://learn.microsoft.com/windows/win32/termserv/kernel-object-namespaces
      https://learn.microsoft.com/dotnet/api/system.io.path.getfullpath
    - A relative -LogFolder is made full against the PowerShell location before a relaunch
      (the elevated copy starts elsewhere):
      https://learn.microsoft.com/dotnet/api/system.management.automation.pathintrinsics.getunresolvedproviderpathfrompspath
    - Start-Process -Verb RunAs fails with Win32 error 1223 (ERROR_CANCELLED) when the UAC
      prompt is declined; any other error is shown with its text:
      https://learn.microsoft.com/windows/win32/debug/system-error-codes--1000-1299-
    - Mapped drives are not available in an elevated process (UAC gives the elevated session
      its own logon session), and Win32_MappedLogicalDisk.ProviderName is the UNC path:
      https://learn.microsoft.com/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command
      https://learn.microsoft.com/windows/win32/cimwin32prov/win32-mappedlogicaldisk
    - Remembered (persistent) drive mappings are kept in the user profile; the fallback reads
      them read-only from HKCU:\Network\<letter>, value RemotePath, with Get-ItemProperty.
      Learn documents remembered connections and Get-ItemProperty, but not that key's layout
      (DriveMap-Diagnostics reads the same key), so every value is checked as a plain
      \\server\share path before it is used. A remembered mapping can be stale, so the live
      mappings of this process and those the first window passed on win; a remembered one only
      fills a letter neither has and is shown as "(remembered mapping)":
      https://learn.microsoft.com/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection2w
      https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-itemproperty
    - A name ending in a space or a period, and "/" in a share path, are refused in drive map
      values; \\?\ and \\.\ device paths are refused for -LogFolder:
      https://learn.microsoft.com/windows/win32/fileio/naming-a-file
    - Before the UAC relaunch, a script or -LogFolder on a drive letter the elevated copy cannot
      see (not fixed or removable, not a known mapped drive, or a SUBST letter whose DOS device
      target is not a \Device\ volume) is refused. Drive letters a normal caller defines are
      local to its logon session:
      https://learn.microsoft.com/dotnet/api/system.io.drivetype
      https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-querydosdevicew
      https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-definedosdevicew
    - OneDrive sync roots (HKCU:\Software\SyncEngines\Providers\OneDrive\*\MountPoint and
      HKCU:\Software\Microsoft\OneDrive\Accounts\*\UserFolder) are UNDOCUMENTED on Learn; they
      are only read, and a folder starting "OneDrive" in another user's profile is flagged too.
    - -NoExit keeps the console open after the script, so the process is not ended then:
      https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe
    - RunspacePool.BeginClose closes the pool without blocking the window thread, and
      Environment.Exit ends the process even while a runspace thread is stuck in I/O:
      https://learn.microsoft.com/dotnet/api/system.management.automation.runspaces.runspacepool.beginclose
      https://learn.microsoft.com/dotnet/api/system.environment.exit
    - DataGridCheckBoxColumn (the tick box per file, bound to the row's IsSelected):
      https://learn.microsoft.com/dotnet/api/system.windows.controls.datagridcheckboxcolumn
    - AutomationProperties.LiveSetting (Polite: screen readers announce a new status message;
      it needs .NET Framework 4.7.1 or later, so it is set only where it exists):
      https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.livesetting
    - Contrast of the selection colours, checked by the tests: WCAG 2 contrast ratio
      (3:1 for the selection fill and focus ring, 4.5:1 for text):
      https://learn.microsoft.com/windows/apps/design/accessibility/accessible-text-requirements
    - Known Folder Move puts Documents inside OneDrive, so exports do not default there:
      https://learn.microsoft.com/sharepoint/redirect-known-folders
    - Get-PSDrive -PSProvider FileSystem lists fixed drives and mapped network drives:
      https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-psdrive
    - Microsoft.Win32.SaveFileDialog (OverwritePrompt) and MessageBox.Show:
      https://learn.microsoft.com/dotnet/api/microsoft.win32.savefiledialog
      https://learn.microsoft.com/dotnet/api/system.windows.messagebox.show
    - Well-known SID S-1-5-32-544 (BUILTIN\Administrators):
      https://learn.microsoft.com/windows/win32/secauthz/well-known-sids
    - ObjectSecurity.GetOwner and CommonObjectSecurity.GetAccessRules (read directly, so the
      result does not depend on PowerShell's Owner/Access type extensions being loaded):
      https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.objectsecurity.getowner
      https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.commonobjectsecurity.getaccessrules
    - Export-Csv -NoTypeInformation -Encoding UTF8:
      https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/export-csv
    - XAML namespace names are identifiers, not addresses that are fetched:
      https://learn.microsoft.com/dotnet/desktop/xaml-services/namespaces
    - -LiteralPath on every Test-Path, Get-ChildItem and Get-Acl call: with -Path, [ ] is a
      wildcard range, so a folder named "HR [old]" would not be found:
      https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_wildcards
    - Loopback names in a \\server\share path: Uri.IsLoopback is true for 127.0.0.1, loopback
      and localhost; IPAddress.IsLoopback for a parsed address. An IPv6 address in a UNC name
      is written with '-' for ':' plus ".ipv6-literal.net" (MS-DTYP 2.2.57 UNC, and
      WNetAddConnection2). This computer's own names come from Environment.MachineName and
      IPGlobalProperties (HostName, DomainName, GetUnicastAddresses), which are read locally:
      https://learn.microsoft.com/dotnet/api/system.uri.isloopback
      https://learn.microsoft.com/dotnet/api/system.net.ipaddress.isloopback
      https://learn.microsoft.com/openspecs/windows_protocols/ms-dtyp/62e862f4-2a51-452e-8eeb-dc4ff5ee33cc
      https://learn.microsoft.com/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection2w
      https://learn.microsoft.com/dotnet/api/system.environment.machinename
      https://learn.microsoft.com/dotnet/api/system.net.networkinformation.ipglobalproperties
    - A share on this computer reached by one of its own names is checked by its local folder:
      Win32_Share.Path is "Local path of the Windows share":
      https://learn.microsoft.com/windows/win32/cimwin32prov/win32-share
    - DFS namespace paths are looked up with NetDfsGetClientInfo (level 3, every target; error
      2662 NERR_DfsNoSuchVolume = not in a DFS namespace; the buffer is freed with
      NetApiBufferFree). The core's Get-DfsTarget is used when the core has it:
      https://learn.microsoft.com/windows/win32/api/lmdfs/nf-lmdfs-netdfsgetclientinfo
      https://learn.microsoft.com/windows/win32/api/lmdfs/ns-lmdfs-dfs_info_3
      https://learn.microsoft.com/windows/win32/api/lmdfs/ns-lmdfs-dfs_storage_info
      https://learn.microsoft.com/windows/win32/api/lmapibuf/nf-lmapibuf-netapibufferfree
      https://learn.microsoft.com/windows/win32/netmgmt/network-management-error-codes
    - A ':' after the drive or share part of a path names an alternate data stream (file:stream),
      not a folder or file, so such a path is refused before any change:
      https://learn.microsoft.com/windows/win32/fileio/file-streams
    - A script relaunched through a remembered mapping is compared with the running copy, file
      by file (this script and FolderPermissions.Core.ps1, which it loads): the sizes first,
      then SHA-256 (Get-FileHash). This check connects to the server the remembered mapping
      names, to read those two files there:
      https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash
    - A share on another server is checked, for a whole-tree change, by the folder it is on that
      server: NetShareGetInfo level 2 returns SHARE_INFO_2, whose shi2_path is "the local path
      for the shared resource"; the buffer "must be freed using the NetApiBufferFree function".
      Level 2 needs Administrator, Power User, Print Operator or Server Operator membership on
      that server for a non-interactive caller, so a server that refuses is refused here too:
      https://learn.microsoft.com/windows/win32/api/lmshare/nf-lmshare-netsharegetinfo
      https://learn.microsoft.com/windows/win32/api/lmshare/ns-lmshare-share_info_2
      https://learn.microsoft.com/windows/win32/api/lmapibuf/nf-lmapibuf-netapibufferfree
      Each folder on the way to that server-side folder is then read over the administrative
      share (FindFirstFileW); FILE_ATTRIBUTE_REPARSE_POINT (0x400) is "A file or directory that
      has an associated reparse point, or a file that is a symbolic link" (D-045):
      https://learn.microsoft.com/windows/win32/fileio/file-attribute-constants
    - An entry whose SID cannot be looked up: icacls /save <ACLfile> "Stores DACLs for all
      matching files into an access control list (ACL) file for later use with /restore", then
      /remove[:g|:d] *SID removes it:
      https://learn.microsoft.com/windows-server/administration/windows-commands/icacls
    - Button.IsDefault (Enter presses it); a Deny add and Remove are never the default:
      https://learn.microsoft.com/dotnet/api/system.windows.controls.button.isdefault
    - The folder that holds every user profile (Get-AppProfilesDirectory, in the core):
      GetProfilesDirectory ("C:\Users" on Windows 7 and later) and the ProfilesDirectory
      setting ("normally C:\Users", %SYSTEMDRIVE%\Users, can be moved to another volume). The
      registry value behind it
      (HKLM\...\ProfileList\ProfilesDirectory) is NOT documented on Learn (searched 2026-10-19),
      so the documented function is used:
      https://learn.microsoft.com/windows/win32/api/userenv/nf-userenv-getprofilesdirectoryw
      https://learn.microsoft.com/windows-hardware/customize/desktop/unattend/microsoft-windows-shell-setup-folderlocations-profilesdirectory
    - A DFS namespace on this computer keeps each DFS folder as a reparse point with the tag
      IO_REPARSE_TAG_DFS (0x8000000A, "Used by the DFS filter ... Server-side interpretation
      only", MS-FSCC 2.1.2.1); the tag is read from the directory entry with FindFirstFileW
      (dwReserved0 holds it when FILE_ATTRIBUTE_REPARSE_POINT is set):
      https://learn.microsoft.com/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4
      https://learn.microsoft.com/windows/win32/fileio/reparse-point-tags
      https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-findfirstfilew
      https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-
    - Results are read back with ObjectSecurity.GetOwner, CommonObjectSecurity.GetAccessRules
      (by SecurityIdentifier) and NTAccount.Translate:
      https://learn.microsoft.com/dotnet/api/system.security.principal.ntaccount.translate
    - IPv4-mapped IPv6 addresses (IPAddress.IsIPv4MappedToIPv6, MapToIPv4) and the IPv6 scope
      ID (IPAddress.ScopeId), which does not change which address it is:
      https://learn.microsoft.com/dotnet/api/system.net.ipaddress.isipv4mappedtoipv6
      https://learn.microsoft.com/dotnet/api/system.net.ipaddress.maptoipv4
      https://learn.microsoft.com/dotnet/api/system.net.ipaddress.scopeid
    - ShowWindow SW_SHOW (5) shows the console again while the tool waits for a change to finish:
      https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-showwindow
    - AutomationLiveSetting.Assertive (a validation error in a dialog interrupts the screen
      reader), Polite for the status line:
      https://learn.microsoft.com/dotnet/api/system.windows.automation.automationlivesetting
    - Window.DialogResult, Button.IsDefault and Button.IsCancel (the confirm dialog: Cancel is
      the default and the Esc button; the action button sets DialogResult):
      https://learn.microsoft.com/dotnet/api/system.windows.window.dialogresult
      https://learn.microsoft.com/dotnet/api/system.windows.controls.button.isdefault
      https://learn.microsoft.com/dotnet/api/system.windows.controls.button.iscancel
    - Every core change call passes -WhatIf:$WhatIf and -Confirm:$false explicitly: a pool
      runspace starts with its own $WhatIfPreference (false), and the window's dialog is the
      confirmation (about_CommonParameters, about_Preference_Variables):
      https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_commonparameters
      https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_preference_variables
    - See FolderPermissions.Core.ps1 for Get-Acl, the permission wording and the log folder.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$LogFolder,

    [Parameter()]
    [string]$DriveMap,

    [Parameter()]
    [switch]$LoadFunctionsOnly
)

$ErrorActionPreference = 'Continue'

# This file is deliberately pure ASCII. Windows PowerShell 5.1 reads a BOM-less file as ANSI,
# so any non-ASCII character could silently corrupt a string. XAML uses &#x....; entities and
# display text uses [char] codes.

$script:ScriptRoot = $PSScriptRoot
if (-not $script:ScriptRoot) { $script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
$script:ScriptPath = $PSCommandPath
if (-not $script:ScriptPath) { $script:ScriptPath = $MyInvocation.MyCommand.Path }
$script:AppTitle = 'Folder Permission Manager'
$script:Dash = [string][char]0x2014

# Permission reading, backups and the change log live in the core (testable without a window).
$script:CorePath = Join-Path $script:ScriptRoot 'FolderPermissions.Core.ps1'
if (-not (Test-Path -LiteralPath $script:CorePath -PathType Leaf)) {
    $missing = "FolderPermissions.Core.ps1 is missing from $($script:ScriptRoot). Keep all the files of the FolderPermissionManager folder together, then start the tool again."
    if ($LoadFunctionsOnly) { throw $missing }
    Write-Host "[FAIL] $missing" -ForegroundColor Red
    try {
        Add-Type -AssemblyName PresentationFramework
        [void][System.Windows.MessageBox]::Show($missing, $script:AppTitle, 'OK', 'Error')
    }
    catch { }
    exit 1
}
. $script:CorePath -LoadFunctionsOnly

$script:AppDataFolder = Get-LocalAppDataFolder
if (-not $script:AppDataFolder) { $script:AppDataFolder = $env:TEMP }
$script:AppDataFolder = Join-Path $script:AppDataFolder 'FolderPermissionManager'
$script:SettingsPath = Join-Path $script:AppDataFolder 'settings.json'
$script:ErrorLogPath = Join-Path $script:AppDataFolder 'gui-errors.log'

#region Pure helpers

function Write-AppError {
    # Unexpected errors go to a small log for support; the window shows a plain message.
    param([string]$Message)
    Write-Verbose $Message
    try {
        if (-not (Test-Path -LiteralPath $script:AppDataFolder -PathType Container)) {
            New-Item -ItemType Directory -Path $script:AppDataFolder -Force -WhatIf:$false -ErrorAction Stop | Out-Null
        }
        $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
        Add-Content -LiteralPath $script:ErrorLogPath -Value $line -Encoding UTF8 -WhatIf:$false -ErrorAction Stop
    }
    catch { }
}

function Limit-AppErrorLog {
    # Keeps gui-errors.log small: when it is larger than MaxBytes, only the newest entries are
    # kept, starting at a whole line. Run once at startup. Never throws.
    param([Parameter(Mandatory)][string]$Path, [long]$MaxBytes = 1MB)
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -le $MaxBytes) { return }
        $start = $bytes.Length - $MaxBytes
        # Begin after the first line break in the kept part, so no entry is cut in half.
        while ($start -lt $bytes.Length -and $bytes[$start - 1] -ne 10) { $start++ }
        $kept = New-Object byte[] ($bytes.Length - $start)
        [Array]::Copy($bytes, $start, $kept, 0, $kept.Length)
        [System.IO.File]::WriteAllBytes($Path, $kept)
    }
    catch {
        Write-Verbose "Could not trim ${Path}: $($_.Exception.Message)"
    }
}

function Show-AppQuestion {
    # A Yes/No question; No is the default button. $true only for Yes. Tests replace it.
    # https://learn.microsoft.com/dotnet/api/system.windows.messagebox.show
    param(
        [Parameter(Mandatory)][string]$Message,
        [string]$Title = $script:AppTitle
    )
    $answer = [System.Windows.MessageBox]::Show($Message, $Title, 'YesNo', 'Warning', 'No')
    "$answer" -eq 'Yes'
}

function Show-AppMessage {
    # Every message box goes through here, so the tests can replace it.
    param(
        [Parameter(Mandatory)][string]$Message,
        [string]$Title = $script:AppTitle,
        [ValidateSet('Information', 'Warning', 'Error')][string]$Icon = 'Information'
    )
    try {
        [void][System.Windows.MessageBox]::Show($Message, $Title, 'OK', $Icon)
    }
    catch {
        # PresentationFramework is not loaded yet (very early in startup).
        $prefix = if ($Icon -eq 'Information') { '[INFO]' } elseif ($Icon -eq 'Warning') { '[WARN]' } else { '[FAIL]' }
        Write-Host "$prefix $Message"
    }
}

function Get-StartupAction {
    # WPF needs STA first; elevation is asked for once the window can show a message.
    param(
        [Parameter(Mandatory)][bool]$IsSta,
        [Parameter(Mandatory)][bool]$IsAdmin
    )
    if (-not $IsSta) { return 'RelaunchSta' }
    if (-not $IsAdmin) { return 'RelaunchElevated' }
    'Continue'
}

function ConvertTo-QuotedArgument {
    # "D:\Logs\" would end in \" , which the command line reads as an escaped quote; doubled
    # trailing backslashes stay backslashes.
    # https://learn.microsoft.com/cpp/c-language/parsing-c-command-line-arguments
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    $trail = [regex]::Match($Value, '\\+$').Value
    '"' + $Value + $trail + '"'
}

function Test-UncSharePath {
    # True only for a plain \\server\share path (optionally with folders below it). Device and
    # long-path forms (\\?\, \\.\), a server without a share, "/" anywhere, and a server, share
    # or folder name ending in "." or " " (which covers "." and "..") are refused, so a drive map
    # value can never point the tool somewhere unexpected. Windows strips a trailing dot or space
    # from a name, so "share." would open "share":
    # https://learn.microsoft.com/windows/win32/fileio/naming-a-file
    param([AllowNull()][AllowEmptyString()][string]$Path)
    if (-not $Path -or $Path.Contains('/') -or $Path -notmatch '^\\\\[^\\?.][^\\]*\\[^\\]+(\\.*)?$') { return $false }
    foreach ($segment in $Path.Substring(2).Split('\')) {
        if ($segment.EndsWith('.') -or $segment.EndsWith(' ')) { return $false }
    }
    $true
}

function Get-ValidDriveMap {
    # Only single drive letters that point at a plain \\server\share; anything else is dropped
    # (that letter then shows unresolved).
    param([hashtable]$DriveMap)
    $clean = @{}
    if (-not $DriveMap) { return $clean }
    foreach ($k in $DriveMap.Keys) {
        $value = "$($DriveMap[$k])"
        if ("$k" -match '^[A-Za-z]$' -and (Test-UncSharePath -Path $value)) { $clean["$k".ToUpper()] = $value }
    }
    $clean
}

function ConvertTo-DriveMapArgument {
    # The mapped drives as one command-line word: Base64 of JSON, so spaces and quotes in share
    # names cannot break the command line.
    param([hashtable]$DriveMap)
    $valid = Get-ValidDriveMap -DriveMap $DriveMap
    $clean = [ordered]@{}
    foreach ($k in ($valid.Keys | Sort-Object)) { $clean[$k] = $valid[$k] }
    $json = ConvertTo-Json -InputObject ([PSCustomObject]$clean) -Compress
    [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
}

function ConvertFrom-DriveMapArgument {
    # The reverse of ConvertTo-DriveMapArgument; anything unreadable gives an empty map, and
    # entries that are not a plain \\server\share are dropped.
    param([AllowNull()][AllowEmptyString()][string]$Argument)
    $map = @{}
    if (-not $Argument) { return $map }
    try {
        $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Argument.Trim().Trim('"')))
        $obj = ConvertFrom-Json -InputObject $json -ErrorAction Stop
        foreach ($p in $obj.PSObject.Properties) { $map[$p.Name] = "$($p.Value)" }
    }
    catch { $map = @{} }
    Get-ValidDriveMap -DriveMap $map
}

function Resolve-DriveMapSet {
    # One letter -> UNC map from three sources, each entry tagged with where it came from, in
    # this order: Live (this process's own mapped drives, CIM), PassedOn (the -DriveMap of the
    # first, non-elevated window, which saw the user's live drives), Remembered (the registry).
    # A remembered mapping can be stale (H: remapped to a new server since), so it only fills a
    # letter neither of the others has, and the path header says it is remembered.
    param([hashtable]$Live, [hashtable]$PassedOn, [hashtable]$Remembered)
    $map = @{}
    $source = @{}
    foreach ($s in @(@('Live', $Live), @('PassedOn', $PassedOn), @('Remembered', $Remembered))) {
        $valid = Get-ValidDriveMap -DriveMap $s[1]
        foreach ($k in $valid.Keys) {
            if ($map.ContainsKey($k)) { continue }
            $map[$k] = $valid[$k]
            $source[$k] = $s[0]
        }
    }
    [PSCustomObject]@{ Map = $map; Source = $source }
}

function Merge-DriveMap {
    # Drives this process can see win; the passed-on map fills in the letters it cannot see, and
    # remembered mappings only the letters neither has (see Resolve-DriveMapSet).
    param([hashtable]$Primary, [hashtable]$Secondary, [hashtable]$Remembered)
    (Resolve-DriveMapSet -Live $Primary -PassedOn $Secondary -Remembered $Remembered).Map
}

function Get-LiveDriveMap {
    # Letter -> UNC path of the mapped network drives this process can see. Throws when CIM
    # cannot be asked. Values that are not a plain \\server\share are dropped.
    # https://learn.microsoft.com/windows/win32/cimwin32prov/win32-mappedlogicaldisk
    $map = @{}
    foreach ($d in @(Get-CimInstance -ClassName Win32_MappedLogicalDisk -ErrorAction Stop)) {
        if ($d.DeviceID -and $d.ProviderName) { $map["$($d.DeviceID)".TrimEnd(':')] = "$($d.ProviderName)" }
    }
    Get-ValidDriveMap -DriveMap $map
}

function Get-RememberedDriveMap {
    # The remembered (persistent) mappings of this user: HKCU:\Network\<letter>, value
    # RemotePath. Only read; never throws. Learn documents remembered connections but not this
    # key's layout, so every value is checked as a plain \\server\share path before it is used.
    # https://learn.microsoft.com/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection2w
    # https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-itemproperty
    $map = @{}
    try {
        foreach ($key in @(Get-ChildItem -LiteralPath 'HKCU:\Network' -ErrorAction Stop)) {
            $letter = "$($key.PSChildName)"
            if ($letter -notmatch '^[A-Za-z]$') { continue }
            $remote = $null
            try { $remote = (Get-ItemProperty -LiteralPath "HKCU:\Network\$letter" -Name RemotePath -ErrorAction Stop).RemotePath } catch { }
            if (Test-UncSharePath -Path "$remote") { $map[$letter.ToUpper()] = "$remote" }
        }
    }
    catch { }
    $map
}

function Get-DriveMapSet {
    # The window's drive map at startup: this process's live mappings, then the ones the first
    # window passed on (-DriveMap), then the remembered ones (Resolve-DriveMapSet). When CIM
    # fails, the remembered mappings still fill in, tagged Remembered.
    param([AllowNull()][AllowEmptyString()][string]$DriveMapArgument)
    $live = @{}
    try { $live = Get-LiveDriveMap } catch { Write-Verbose "Mapped drives could not be read with CIM: $($_.Exception.Message)" }
    Resolve-DriveMapSet -Live $live -PassedOn (ConvertFrom-DriveMapArgument -Argument $DriveMapArgument) -Remembered (Get-RememberedDriveMap)
}

function Get-MappedDriveTable {
    # Letter -> UNC path: the drives this process can see (CIM), plus the remembered mappings for
    # letters CIM does not list. No passed-on map; the window itself uses Get-DriveMapSet.
    $live = @{}
    try { $live = Get-LiveDriveMap } catch { }
    (Resolve-DriveMapSet -Live $live -Remembered (Get-RememberedDriveMap)).Map
}

function Resolve-LogFolderArgument {
    # A -LogFolder value as a full path, made against the PowerShell location it was typed in
    # (an elevated copy starts in System32, where a relative path would point somewhere else).
    # Empty stays empty. Throws a plain message for a value it cannot pass on safely.
    # https://learn.microsoft.com/dotnet/api/system.management.automation.pathintrinsics.getunresolvedproviderpathfrompspath
    param([AllowNull()][AllowEmptyString()][string]$LogFolder)
    if (-not $LogFolder) { return $LogFolder }
    $invalid = "Start the tool again with -LogFolder set to a full folder path, for example -LogFolder 'D:\Tickets\12345\PermissionChanges'."
    if ($LogFolder.Contains('"')) { throw "The -LogFolder value cannot contain a double quote (`"). $invalid" }
    # Device and long-path forms (\\?\C:\..., \\.\C:\...) skip Windows' path checks and would give
    # the same folder a second spelling (and a second single-instance key):
    # https://learn.microsoft.com/windows/win32/fileio/naming-a-file
    if ($LogFolder -match '^[\\/]{2}[?.][\\/]') { throw "The -LogFolder value '$LogFolder' is a device path (\\?\ or \\.\). $invalid" }
    try {
        if ($LogFolder -match '^([A-Za-z]:[\\/]|\\\\|//)') {
            # Already full (possibly on a mapped drive this process cannot see): only tidied.
            # https://learn.microsoft.com/dotnet/api/system.io.path.getfullpath
            $full = [System.IO.Path]::GetFullPath($LogFolder)
        }
        else {
            $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogFolder)
        }
    }
    catch { throw "The -LogFolder value '$LogFolder' is not a folder path this tool can use. $invalid" }
    if ("$full" -notmatch '^([A-Za-z]:\\|\\\\)') { throw "The -LogFolder value '$LogFolder' is not a folder on a disk or share. $invalid" }
    $full
}

function Get-RelaunchArgumentList {
    # powershell.exe arguments to start this script again (in STA, or elevated), passing on
    # -LogFolder (as a full path), -WhatIf and the mapped drives. The script and log folder go
    # as UNC paths when they are on a mapped drive, because the elevated copy cannot see it.
    # Mappings tagged Remembered in -DriveMapSource are used for those paths but not passed on:
    # the next copy reads the registry itself and tags them again, so they never pose as live.
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [string]$LogFolder,
        [switch]$WhatIfMode,
        [hashtable]$DriveMap,
        [hashtable]$DriveMapSource
    )
    $LogFolder = Resolve-LogFolderArgument -LogFolder $LogFolder
    $list = [System.Collections.Generic.List[string]]::new()
    foreach ($a in '-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File') { $list.Add($a) }
    $list.Add((ConvertTo-QuotedArgument (Resolve-MappedDrive -Path $ScriptPath -DriveMap $DriveMap)))
    if ($LogFolder) {
        $list.Add('-LogFolder')
        $list.Add((ConvertTo-QuotedArgument (Resolve-MappedDrive -Path $LogFolder -DriveMap $DriveMap)))
    }
    if ($WhatIfMode) { $list.Add('-WhatIf') }
    $passOn = @{}
    if ($DriveMap) {
        foreach ($k in $DriveMap.Keys) {
            if ($DriveMapSource -and "$($DriveMapSource[$k])" -eq 'Remembered') { continue }
            $passOn[$k] = $DriveMap[$k]
        }
    }
    if ((Get-ValidDriveMap -DriveMap $passOn).Count -gt 0) {
        $list.Add('-DriveMap')
        $list.Add((ConvertTo-DriveMapArgument -DriveMap $passOn))
    }
    $list.ToArray()
}

function Get-DriveLetterType {
    # The DriveType of a drive letter as this process sees it ('Fixed', 'Removable', 'Network',
    # 'NoRootDirectory' for a letter that does not exist here, ...). Tests replace it.
    # https://learn.microsoft.com/dotnet/api/system.io.drivetype
    param([Parameter(Mandatory)][string]$Letter)
    try { "$((New-Object System.IO.DriveInfo -ArgumentList $Letter).DriveType)" } catch { 'Unknown' }
}

function Get-DosDeviceTarget {
    # What a drive letter points at in this session's MS-DOS device names (QueryDosDevice, only
    # read): a real volume is \Device\HarddiskVolumeN; a SUBST drive points at a folder instead.
    # $null when it cannot be read. Tests replace it.
    # https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-querydosdevicew
    param([Parameter(Mandatory)][string]$Letter)
    try {
        if (-not ('FolderPermissionManager.DosDevice' -as [type])) {
            Add-Type -Namespace FolderPermissionManager -Name DosDevice -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, int ucchMax);
'@
        }
        $sb = New-Object System.Text.StringBuilder 1024
        if ([FolderPermissionManager.DosDevice]::QueryDosDevice("$($Letter.ToUpper()):", $sb, $sb.Capacity) -eq 0) { return $null }
        $sb.ToString()
    }
    catch { $null }
}

function Get-RelaunchPathProblem {
    # $null when the administrator copy can reach this path; otherwise a plain message. A drive
    # letter is fine when it is a local fixed or removable disk, or a mapped drive in the map
    # (it is passed on as its UNC path). Anything else exists only in this logon session: a
    # SUBST drive (its letter points at a folder, not a volume) or a drive mapped without the
    # tool seeing it. Drive letters a non-LocalSystem caller defines are local to its session:
    # https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-definedosdevicew
    # https://learn.microsoft.com/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command
    param(
        [AllowNull()][AllowEmptyString()][string]$Path,
        [hashtable]$DriveMap,
        [ValidateSet('Script', 'LogFolder')][string]$Kind = 'Script'
    )
    if (-not $Path -or $Path -notmatch '^([A-Za-z]):') { return $null }
    $letter = $Matches[1].ToUpper()
    if ((Get-ValidDriveMap -DriveMap $DriveMap).ContainsKey($letter)) { return $null }
    $type = Get-DriveLetterType -Letter $letter
    if ($type -eq 'Fixed' -or $type -eq 'Removable') {
        $target = Get-DosDeviceTarget -Letter $letter
        # Learn's example of a volume target is \Device\HarddiskVolume1; SUBST gives a folder.
        if (-not $target -or $target.StartsWith('\Device\', [StringComparison]::OrdinalIgnoreCase)) { return $null }
    }
    $why = "${letter}: is not a local disk and not a mapped drive this tool knows about (for example a SUBST drive, or a drive mapped only in this window), so the administrator copy of the tool cannot see it."
    if ($Kind -eq 'LogFolder') {
        return "The -LogFolder $Path is on drive ${letter}:. $why Start the tool again with -LogFolder set to a folder on a local disk or a \\server\share path."
    }
    "Folder Permission Manager is on drive ${letter}: ($Path). $why Copy the FolderPermissionManager folder to a local disk, or start it from its \\server\share path."
}

function Get-WindowsPowerShellPath {
    Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
}

function Get-RelaunchFileHash {
    # SHA-256 of a file, or $null when it cannot be read. Only read. Tests replace it.
    # https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash
    param([Parameter(Mandatory)][string]$Path)
    try { (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $null }
}

function Get-RelaunchFileSize {
    # The size of a file in bytes, or $null when it cannot be read. Only read. Tests replace it.
    param([Parameter(Mandatory)][string]$Path)
    try { [long](Get-Item -LiteralPath $Path -Force -ErrorAction Stop).Length } catch { $null }
}

function Get-RelaunchFileList {
    # Every file the relaunched copy loads: this script and the files it dot-sources from its
    # own folder (only the core today). Keep in step with the dot-sourcing at the top.
    # Text only (System.IO.Path, not Split-Path/Join-Path): the script's drive letter may be one
    # this process cannot see, and those cmdlets fail on a drive that does not exist here.
    param([Parameter(Mandatory)][string]$ScriptPath)
    $folder = [System.IO.Path]::GetDirectoryName($ScriptPath)
    @($ScriptPath, [System.IO.Path]::Combine($folder, 'FolderPermissions.Core.ps1'))
}

function Get-RelaunchScriptProblem {
    # $null when the copy started again will run these same files; otherwise a plain message.
    # The relaunch starts the script from the \\server\share path behind its drive letter. When
    # only a remembered (registry) mapping explains that letter, it may be out of date and point
    # at another server, so every file the copy loads (Get-RelaunchFileList) must be byte for
    # byte the one running: the sizes are compared first (a mismatch is refused without reading
    # the files), then SHA-256. This connects to the server the mapping names.
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [hashtable]$DriveMap,
        [hashtable]$DriveMapSource
    )
    if ($ScriptPath -notmatch '^([A-Za-z]):') { return $null }
    $letter = $Matches[1].ToUpper()
    if (-not $DriveMapSource -or "$($DriveMapSource[$letter])" -ne 'Remembered') { return $null }
    if ((Resolve-MappedDrive -Path $ScriptPath -DriveMap $DriveMap) -eq $ScriptPath) { return $null }
    foreach ($file in @(Get-RelaunchFileList -ScriptPath $ScriptPath)) {
        $unc = Resolve-MappedDrive -Path $file -DriveMap $DriveMap
        $what = $null
        $runningSize = Get-RelaunchFileSize -Path $file
        $thereSize = Get-RelaunchFileSize -Path $unc
        if ($null -ne $runningSize -and $null -ne $thereSize -and $runningSize -ne $thereSize) {
            $what = 'is not the same file as the one running (its size differs)'
        }
        else {
            $running = Get-RelaunchFileHash -Path $file
            $there = Get-RelaunchFileHash -Path $unc
            if (-not $running) { $what = "could not be compared, because the running copy $file could not be read" }
            elseif (-not $there) { $what = 'could not be read' }
            elseif ($running -ne $there) { $what = 'is not the same file as the one running' }
        }
        if ($what) {
            return "Folder Permission Manager is running from $ScriptPath. Drive ${letter}: is only a remembered mapping (Windows remembers it, but this window could not see it live), and the file behind it, $unc, $what. " +
            'The copy started again would run from there, so it was not started. Copy the FolderPermissionManager folder to a local disk, or start it from its \\server\share path.'
        }
    }
    $null
}

function Request-Elevation {
    # Asks Windows for administrator rights (UAC) by starting this script again elevated.
    # $true: the elevated copy was started. $false: declined or failed; the user was told why.
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [string]$LogFolder,
        [switch]$WhatIfMode,
        [hashtable]$DriveMap,
        [hashtable]$DriveMapSource
    )
    try {
        $arguments = Get-RelaunchArgumentList -ScriptPath $ScriptPath -LogFolder $LogFolder -WhatIfMode:$WhatIfMode -DriveMap $DriveMap -DriveMapSource $DriveMapSource
    }
    catch {
        Show-AppMessage -Icon Error -Message $_.Exception.Message
        return $false
    }
    # The elevated copy runs in another logon session: a path on a drive only this session has
    # would not be found there, so say so now instead of failing after the UAC prompt.
    $problem = Get-RelaunchPathProblem -Path $ScriptPath -DriveMap $DriveMap -Kind Script
    if (-not $problem) { $problem = Get-RelaunchPathProblem -Path (Resolve-LogFolderArgument -LogFolder $LogFolder) -DriveMap $DriveMap -Kind LogFolder }
    if (-not $problem) { $problem = Get-RelaunchScriptProblem -ScriptPath $ScriptPath -DriveMap $DriveMap -DriveMapSource $DriveMapSource }
    if ($problem) {
        Show-AppMessage -Icon Error -Message $problem
        return $false
    }
    try {
        Start-Process -FilePath (Get-WindowsPowerShellPath) -Verb RunAs -ArgumentList $arguments -ErrorAction Stop
        return $true
    }
    catch {
        $text = 'Folder Permission Manager needs to run as administrator to read and change permissions on folders it does not own. ' +
        'Start it again and choose Yes when Windows asks, or right-click PowerShell, choose "Run as administrator", and start the script from there.'
        # 1223 (ERROR_CANCELLED) is the tech choosing No; anything else is worth showing.
        # https://learn.microsoft.com/windows/win32/debug/system-error-codes--1000-1299-
        $cancelled = $false
        $e = $_.Exception
        while ($e) {
            if ($e -is [System.ComponentModel.Win32Exception] -and $e.NativeErrorCode -eq 1223) { $cancelled = $true }
            $e = $e.InnerException
        }
        if (-not $cancelled) { $text += " (Windows said: $(Get-InnermostErrorText $_))" }
        Show-AppMessage -Icon Warning -Message $text
        return $false
    }
}

function Get-InstanceMutexName {
    # One name per log folder (case and trailing backslash ignored), in the Global\ namespace so
    # a second window in another session on the same computer is refused too.
    # https://learn.microsoft.com/windows/win32/termserv/kernel-object-namespaces
    param([Parameter(Mandatory)][string]$LogFolder, [hashtable]$DriveMap)
    # One spelling per folder: a mapped drive letter becomes its UNC path (so H:\X and
    # \\fs01\home\X share one key), and GetFullPath resolves "..", "." and "/" before the name
    # is hashed. The log folder is already a full path here, so the process directory plays no
    # part. Short and fully qualified server names (fs01, fs01.contoso.com) still give two keys.
    # https://learn.microsoft.com/dotnet/api/system.io.path.getfullpath
    $full = (Resolve-MappedDrive -Path $LogFolder.Trim() -DriveMap $DriveMap)
    try { $full = [System.IO.Path]::GetFullPath($full) } catch { }
    $norm = $full.TrimEnd('\', '/').ToLowerInvariant()
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($norm)) }
    finally { $sha.Dispose() }
    $hex = -join ($bytes[0..7] | ForEach-Object { $_.ToString('x2') })
    "Global\FolderPermissionManagerGUI_$hex"
}

function Enter-SingleInstance {
    # Two windows must never append to the same change log at once. $false (and a message)
    # when another window already uses this log folder; the mutex is kept in
    # $script:InstanceMutex until the window closes.
    param([Parameter(Mandatory)][string]$LogFolder, [hashtable]$DriveMap)
    $name = Get-InstanceMutexName -LogFolder $LogFolder -DriveMap $DriveMap
    $createdNew = $false
    $mutex = $null
    try {
        # initiallyOwned is only granted when this call creates the mutex; createdNew says so.
        # https://learn.microsoft.com/dotnet/api/system.threading.mutex.-ctor
        $mutex = [System.Threading.Mutex]::new($true, $name, [ref]$createdNew)
    }
    catch {
        # Another user's window created it and this account may not open it: still in use.
        $createdNew = $false
    }
    if (-not $createdNew) {
        if ($mutex) { $mutex.Dispose() }
        Show-AppMessage -Message 'Folder Permission Manager is already open (possibly in another session on this computer). Use that window, or close it first.'
        return $false
    }
    $script:InstanceMutex = $mutex
    $true
}

function Resolve-MappedDrive {
    # An elevated process does not see the user's mapped drives, so drive letters are turned
    # into the UNC path they point at. Anything else is returned unchanged, and so is a letter
    # whose map entry is not a plain \\server\share (it stays unresolved).
    param([string]$Path, [hashtable]$DriveMap)
    if ($Path -and $DriveMap -and $Path -match '^([A-Za-z]):(\\.*)?$') {
        $unc = $DriveMap[$Matches[1].ToUpper()]
        $rest = $Matches[2]
        if (-not $rest) { $rest = '' }
        if (Test-UncSharePath -Path "$unc") {
            return ("$unc".TrimEnd('\') + $rest)
        }
    }
    $Path
}

function Get-PathHeaderModel {
    # The path as the tech sees it, and the real location behind a mapped drive letter
    # ($null when there is none). Nothing is shortened. When that mapping only came from the
    # remembered (registry) mappings, RealPathNote says so: it may be out of date.
    param([string]$Path, [hashtable]$DriveMap, [hashtable]$DriveMapSource)
    $real = Resolve-MappedDrive -Path $Path -DriveMap $DriveMap
    if ($real -eq $Path) { $real = $null }
    $note = $null
    if ($real -and $DriveMapSource -and $Path -match '^([A-Za-z]):' -and "$($DriveMapSource[$Matches[1].ToUpper()])" -eq 'Remembered') {
        $note = '(remembered mapping)'
    }
    [PSCustomObject]@{ Path = $Path; RealPath = $real; RealPathNote = $note }
}

function Join-DisplayPath {
    param([Parameter(Mandatory)][string]$Parent, [Parameter(Mandatory)][string]$Name)
    $Parent.TrimEnd('\') + '\' + $Name
}

function Get-PathLeaf {
    # 'HR' for D:\Data\HR, 'D:\' for D:\, the share for \\fs01\share.
    param([string]$Path)
    $parts = @("$Path".Split('\') | Where-Object { $_ })
    if ($parts.Count -eq 0) { return $Path }
    if ($parts.Count -eq 1 -and $Path -match '^[A-Za-z]:') { return $Path }
    $parts[$parts.Count - 1]
}

function Get-DriveListModel {
    # Drive tree roots: local drives (with their label) and mapped drives (with the UNC path
    # behind them), each letter once. Get-PSDrive in an elevated process misses the user's
    # mapped drives, so those come from the map.
    # https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-psdrive
    param([hashtable]$DriveMap)
    $DriveMap = Get-ValidDriveMap -DriveMap $DriveMap
    $rows = [System.Collections.Generic.List[object]]::new()
    $seen = @{}
    foreach ($d in @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
        $name = "$($d.Name)"
        # Single letters only: PowerShell also has drives such as Temp: that are just folders.
        if (-not $d.Root -or $name -notmatch '^[A-Za-z]$') { continue }
        $name = $name.ToUpper()
        if ($seen[$name]) { continue }
        $seen[$name] = $true
        $unc = $null
        if ($DriveMap -and $DriveMap[$name]) { $unc = "$($DriveMap[$name])" }
        elseif ("$($d.DisplayRoot)" -like '\\*') { $unc = "$($d.DisplayRoot)" }
        if ($unc) {
            $rows.Add([PSCustomObject]@{ Name = $name; Root = "${name}:\"; Label = "${name}: ($unc)"; IsMapped = $true; UncPath = $unc })
        }
        else {
            # [char]0x2014 (em dash) rather than $script:Dash: this also runs in a background runspace.
            $label = if ($d.Description) { "${name}:\ $([char]0x2014) $($d.Description)" } else { "${name}:\" }
            $rows.Add([PSCustomObject]@{ Name = $name; Root = "${name}:\"; Label = $label; IsMapped = $false; UncPath = $null })
        }
    }
    if ($DriveMap) {
        foreach ($k in ($DriveMap.Keys | Sort-Object)) {
            $name = "$k".ToUpper()
            if ($seen[$name]) { continue }
            $seen[$name] = $true
            $unc = "$($DriveMap[$k])"
            $rows.Add([PSCustomObject]@{ Name = $name; Root = "${name}:\"; Label = "${name}: ($unc)"; IsMapped = $true; UncPath = $unc })
        }
    }
    @($rows | Sort-Object Name)
}

function Get-InnermostErrorText {
    param($ErrorRecord)
    $e = $ErrorRecord.Exception
    while ($e -and $e.InnerException) { $e = $e.InnerException }
    $text = if ($e) { $e.Message } else { "$ErrorRecord" }
    "$text".Trim()
}

function Test-AccessDeniedError {
    param($ErrorRecord)
    $e = $ErrorRecord.Exception
    while ($e) {
        if ($e -is [System.UnauthorizedAccessException]) { return $true }
        $e = $e.InnerException
    }
    "$($ErrorRecord.CategoryInfo.Category)" -eq 'PermissionDenied'
}

function Get-AccessDeniedMessage {
    # The plain next step for an item that cannot be opened: the owner (or Administrators, which
    # an elevated tech is part of) only needs a permission; anyone else must take ownership first.
    # S-1-5-32-544 is BUILTIN\Administrators: https://learn.microsoft.com/windows/win32/secauthz/well-known-sids
    param(
        [Parameter(Mandatory)][string]$Path,
        $Owner,
        [ValidateSet('Folder', 'File')][string]$ItemKind = 'Folder'
    )
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isMine = $false
    if ($Owner) {
        if ($Owner.Owner -and $Owner.Owner -eq $me.Name) { $isMine = $true }
        if ($Owner.OwnerSid -and ($Owner.OwnerSid -eq $me.User.Value -or $Owner.OwnerSid -eq 'S-1-5-32-544')) { $isMine = $true }
    }
    if ($isMine) {
        return "You own '$Path' but have no permission to open it. Use Add Permission to give yourself access."
    }
    if ($ItemKind -eq 'File') {
        return "Access denied to '$Path'. Take ownership of the file first, then use Add Permission to give yourself access."
    }
    "Access denied to '$Path'. Take ownership (this folder only) first, then use Add Permission to give yourself access."
}

function Get-AclOwnerName {
    # Read with GetOwner, not the Owner property PowerShell adds, so it also works in a fresh
    # runspace. An owner whose account was deleted is shown as its SID.
    # https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.objectsecurity.getowner
    param([Parameter(Mandatory)]$Acl)
    try { return "$($Acl.GetOwner([System.Security.Principal.NTAccount]).Value)" } catch { }
    try { return "$($Acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value)" } catch { }
    'Could not read'
}

function ConvertTo-AclViewModel {
    # Owner, inheritance and one row per permission entry, in the order the ACL holds them.
    # https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.commonobjectsecurity.getaccessrules
    param([Parameter(Mandatory)]$Acl)
    $rules = @($Acl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount]))
    # The same entries, in the same order, by SID: Remove Permission is keyed on the SID, so two
    # names for one account (or a renamed one) are one choice.
    $sids = @($Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    $rows = @(for ($i = 0; $i -lt $rules.Count; $i++) {
            $r = $rules[$i]
            [PSCustomObject]@{
                Identity        = "$($r.IdentityReference.Value)"
                Sid             = $(if ($i -lt $sids.Count) { "$($sids[$i].IdentityReference.Value)" } else { '' })
                PermissionLevel = Format-PermissionRights -Rights $r.FileSystemRights
                Rights          = "$($r.FileSystemRights)"
                Type            = "$($r.AccessControlType)"
                IsInherited     = [bool]$r.IsInherited
                InheritedText   = $(if ($r.IsInherited) { 'Inherited' } else { '' })
            }
        })
    [PSCustomObject]@{
        Owner                   = Get-AclOwnerName -Acl $Acl
        AreAccessRulesProtected = [bool]$Acl.AreAccessRulesProtected
        Rows                    = $rows
    }
}

function Read-ItemAclModel {
    # Reads one folder's or file's permissions. Never throws: Ok = $false with a plain message.
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('Folder', 'File')][string]$ItemKind = 'Folder'
    )
    $type = if ($ItemKind -eq 'Folder') { 'Container' } else { 'Leaf' }
    $fail = { param($text) [PSCustomObject]@{ Ok = $false; Path = $Path; Owner = $null; AreAccessRulesProtected = $false; Rows = @(); Error = $text } }
    if (-not (Test-Path -LiteralPath $Path -PathType $type)) {
        return (& $fail "'$Path' was not found. It may have been moved, renamed or deleted; press Refresh.")
    }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    }
    catch {
        if (Test-AccessDeniedError $_) { return (& $fail (Get-AccessDeniedMessage -Path $Path -Owner (Get-ItemOwner -Path $Path) -ItemKind $ItemKind)) }
        return (& $fail "Could not read the permissions of '$Path': $(Get-InnermostErrorText $_)")
    }
    $m = ConvertTo-AclViewModel -Acl $acl
    [PSCustomObject]@{ Ok = $true; Path = $Path; Owner = $m.Owner; AreAccessRulesProtected = $m.AreAccessRulesProtected; Rows = $m.Rows; Error = $null }
}

function Format-FileSize {
    # The size text the browser version shows.
    param([long]$Bytes)
    if ($Bytes -gt 1GB) { return "$([math]::Round($Bytes / 1GB, 2)) GB" }
    if ($Bytes -gt 1MB) { return "$([math]::Round($Bytes / 1MB, 1)) MB" }
    if ($Bytes -gt 1KB) { return "$([math]::Round($Bytes / 1KB, 1)) KB" }
    "$Bytes B"
}

function ConvertTo-FileRows {
    param([AllowEmptyCollection()][AllowNull()][object[]]$Item)
    @($Item | Where-Object { $null -ne $_ } | Sort-Object Name | ForEach-Object {
            [PSCustomObject]@{
                Name     = $_.Name
                Path     = $_.FullName
                Length   = [long]$_.Length
                SizeText = Format-FileSize -Bytes $_.Length
                Modified = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
            }
        })
}

function Get-FileAclSignature {
    # Order does not matter; who, what level and Allow/Deny do (as in the browser version).
    param($Model)
    (@($Model.Rows | ForEach-Object { '{0}|{1}|{2}' -f $_.Identity, $_.PermissionLevel, $_.Type }) | Sort-Object) -join "`n"
}

function Test-FileAclDiffers {
    # True when at least two loaded files have different permissions.
    param([AllowEmptyCollection()][AllowNull()][object[]]$Model)
    $loaded = @($Model | Where-Object { $null -ne $_ })
    if ($loaded.Count -lt 2) { return $false }
    $first = Get-FileAclSignature $loaded[0]
    foreach ($m in $loaded[1..($loaded.Count - 1)]) {
        if ((Get-FileAclSignature $m) -cne $first) { return $true }
    }
    $false
}

function Get-FileAclDiffWarning {
    "Selected files have different permissions $($script:Dash) this operation applies uniformly to all"
}

function Get-FileAclDiffWarningText {
    # The line under the selected files: says it is a warning, and how many of the selected
    # files were compared when not all of them have been read.
    param([Parameter(Mandatory)][int]$Checked, [Parameter(Mandatory)][int]$Selected)
    $text = "Warning: $(Get-FileAclDiffWarning)"
    if ($Checked -lt $Selected) { $text += " (checked $Checked of $Selected selected files)" }
    $text
}

function Get-DefaultExportFileName {
    param([Parameter(Mandatory)][string]$Path)
    $safe = $Path.TrimEnd('\', '/') -replace '[\\/:*?"<>|]', '_'
    'Permissions-{0}_{1}.csv' -f $safe, (Get-Date -Format 'yyyy-MM-dd_HHmmss')
}

function Get-OneDriveSyncRoot {
    # Every folder the OneDrive client syncs for this user, including SharePoint libraries
    # (which are not under %OneDrive%): HKCU:\Software\SyncEngines\Providers\OneDrive\<id>,
    # value MountPoint, and HKCU:\Software\Microsoft\OneDrive\Accounts\<account>, value
    # UserFolder. Only read, with Get-ChildItem and Get-ItemProperty; never throws.
    # UNDOCUMENTED: Learn does not describe these keys (searched 2026-10-19), so only values
    # that are full local paths (C:\...) are used.
    # https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-itemproperty
    $roots = [System.Collections.Generic.List[string]]::new()
    $sources = @(
        @('HKCU:\Software\SyncEngines\Providers\OneDrive', 'MountPoint'),
        @('HKCU:\Software\Microsoft\OneDrive\Accounts', 'UserFolder')
    )
    foreach ($s in $sources) {
        $keys = @()
        try { $keys = @(Get-ChildItem -LiteralPath $s[0] -ErrorAction Stop) } catch { continue }
        foreach ($k in $keys) {
            $value = $null
            try { $value = (Get-ItemProperty -LiteralPath $k.PSPath -Name $s[1] -ErrorAction Stop).($s[1]) } catch { continue }
            if ("$value" -match '^[A-Za-z]:\\' -and -not $roots.Contains("$value")) { $roots.Add("$value") }
        }
    }
    $roots.ToArray()
}

function Get-OneDriveFolder {
    # The folders this user's OneDrive client syncs: the environment variables it sets, plus
    # its sync roots in the registry (SharePoint libraries too). Anything saved under one is
    # uploaded to the cloud.
    $all = @($env:OneDrive, $env:OneDriveCommercial, $env:OneDriveConsumer) + @(Get-OneDriveSyncRoot)
    @($all | Where-Object { "$_".Trim() } | Select-Object -Unique)
}

function Test-OneDriveLikePath {
    # Backstop for OneDrive folders this account's settings do not describe (another user's
    # profile): a folder whose name starts with "OneDrive" inside C:\Users\<name>\. Profiles
    # whose sync folders are known are judged by those folders only, so a local folder named
    # like one ("OneDrive - Contoso2" next to "OneDrive - Contoso") is not flagged there.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path, [AllowEmptyCollection()][string[]]$KnownRoot)
    if ($Path -notmatch '^([A-Za-z]:\\Users\\[^\\]+)\\(.+)$') { return $false }
    $profileRoot = $Matches[1]
    $rest = $Matches[2]
    foreach ($r in @($KnownRoot)) {
        if ($r -and (Test-PathWithin -Path $r -Root $profileRoot)) { return $false }
    }
    foreach ($segment in $rest.Split('\')) {
        if ($segment.StartsWith('OneDrive', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    $false
}

function Get-ExportLocationInfo {
    # Whether a chosen export file is on this computer's local fixed disk, outside OneDrive.
    # The report holds client paths, owners and account names, so a share, a mapped, network or
    # removable drive, or a synced OneDrive folder gets a warning naming the location.
    # https://learn.microsoft.com/dotnet/api/system.io.driveinfo.drivetype (Test-LocalFixedPath, in the core)
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path, [hashtable]$DriveMap)
    $warning = $null
    if ($Path -match '^(\\\\|//)') {
        $warning = "$Path is on a network share."
    }
    elseif ($Path -match '^([A-Za-z]):' -and $DriveMap -and $DriveMap[$Matches[1].ToUpper()]) {
        $warning = "$Path is on mapped drive $($Matches[1].ToUpper()): ($($DriveMap[$Matches[1].ToUpper()]))."
    }
    elseif (-not (Test-LocalFixedPath -Path $Path)) {
        $warning = "$Path is on a network, mapped or removable drive, not this computer's own disk."
    }
    else {
        $roots = @(Get-OneDriveFolder)
        foreach ($od in $roots) {
            if (Test-PathWithin -Path $Path -Root $od) { $warning = "$Path is inside the OneDrive sync folder $od (OneDrive or a synced SharePoint library), so it is uploaded to the cloud."; break }
        }
        if (-not $warning -and (Test-OneDriveLikePath -Path $Path -KnownRoot $roots)) {
            $warning = "$Path looks like a OneDrive folder (a folder starting with OneDrive in a user profile), so it may be uploaded to the cloud."
        }
    }
    [PSCustomObject]@{ Path = $Path; IsLocal = ($null -eq $warning); Warning = $warning }
}

function Get-DefaultExportFolder {
    # Where the Save dialog starts: Documents when it is a local fixed disk outside OneDrive
    # (Known Folder Move and folder redirection often move it), else a local folder for exports.
    # https://learn.microsoft.com/sharepoint/redirect-known-folders
    param(
        [string]$DocumentsPath = [Environment]::GetFolderPath([Environment+SpecialFolder]::MyDocuments),
        [string]$LocalAppDataPath = (Get-LocalAppDataFolder)
    )
    if ($DocumentsPath -and (Get-ExportLocationInfo -Path $DocumentsPath).IsLocal) { return $DocumentsPath }
    if (-not $LocalAppDataPath) { $LocalAppDataPath = $env:TEMP }
    Join-Path $LocalAppDataPath 'FolderPermissionManager\Exports'
}

function Confirm-ExportLocation {
    # $true when the export may be written there: a local fixed disk outside OneDrive, or the
    # tech said Yes after the warning. The warning also goes to the status line.
    param([Parameter(Mandatory)][string]$Path)
    $info = Get-ExportLocationInfo -Path $Path -DriveMap $script:MappedDrives
    if ($info.IsLocal) { return $true }
    Set-Status -Kind Warning -Text "$($info.Warning) The report holds client folder paths, owners and account names."
    $question = "$($info.Warning)`n`nThe report holds client folder paths, owners and account names for the whole folder tree. " +
    "Save it on this computer instead (for example in Documents, if that is not in OneDrive), attach it to the ticket, then delete it.`n`nSave it here anyway?"
    Show-AppQuestion -Message $question
}

function Get-LogFolderBanner {
    # The lines the window shows under the title bar (they replace the console [INFO]/[WARN]).
    param(
        [Parameter(Mandatory)][string]$LogFolder,
        [AllowEmptyCollection()][AllowNull()][string[]]$Notice,
        [switch]$WhatIfMode
    )
    $rows = [System.Collections.Generic.List[object]]::new()
    if ($WhatIfMode) { $rows.Add([PSCustomObject]@{ Level = 'Warning'; Text = 'Dry run (WhatIf): nothing will be changed.' }) }
    $rows.Add([PSCustomObject]@{ Level = 'Info'; Text = "Changes are backed up and logged to $LogFolder" })
    foreach ($n in @($Notice | Where-Object { $_ })) { $rows.Add([PSCustomObject]@{ Level = 'Warning'; Text = $n }) }
    $rows.ToArray()
}

function Get-PaneState {
    # What a pane shows while loading, when empty, on error (never blank) and when loaded.
    param(
        [Parameter(Mandatory)][ValidateSet('TreeNode', 'FolderPermissions', 'Files', 'FilePermissions')][string]$Pane,
        [Parameter(Mandatory)][ValidateSet('Loading', 'Loaded', 'Failed')][string]$Phase,
        [int]$Count = 0,
        [string]$ErrorText
    )
    $texts = @{
        TreeNode          = @{ Empty = 'No subfolders'; Error = 'This folder could not be opened, and Windows gave no reason. Press Refresh to try again.' }
        FolderPermissions = @{ Empty = 'This folder has no permission entries: nobody can open it. Its owner can still add permissions.'; Error = 'The permissions of this folder could not be read, and Windows gave no reason. Press Refresh to try again.' }
        Files             = @{ Empty = 'No files in this folder'; Error = 'The files in this folder could not be listed, and Windows gave no reason. Press Refresh to try again.' }
        FilePermissions   = @{ Empty = 'This file has no permission entries: nobody can open it. Its owner can still add permissions.'; Error = 'The permissions of this file could not be read, and Windows gave no reason. Press Refresh to try again.' }
    }
    switch ($Phase) {
        'Loading' { return [PSCustomObject]@{ State = 'Loading'; Text = 'Loading...' } }
        'Failed' {
            $text = if ("$ErrorText".Trim()) { "$ErrorText".Trim() } else { $texts[$Pane].Error }
            return [PSCustomObject]@{ State = 'Error'; Text = $text }
        }
        default {
            if ($Count -le 0) { return [PSCustomObject]@{ State = 'Empty'; Text = $texts[$Pane].Empty } }
            return [PSCustomObject]@{ State = 'Loaded'; Text = '' }
        }
    }
}

function Format-Elapsed {
    param([Parameter(Mandatory)][TimeSpan]$Elapsed)
    $ts = [TimeSpan]::FromSeconds([Math]::Max(0, [Math]::Floor($Elapsed.TotalSeconds)))
    if ($ts.TotalHours -ge 1) { return ('{0}h {1:D2}m' -f [int][Math]::Floor($ts.TotalHours), $ts.Minutes) }
    if ($ts.TotalMinutes -ge 1) { return ('{0}m {1:D2}s' -f $ts.Minutes, $ts.Seconds) }
    '{0}s' -f $ts.Seconds
}

function Get-BusyLine {
    # "Opening folder D:\Data\HR... (3s)": the action is the start of a sentence that the path
    # completes.
    param([Parameter(Mandatory)][string]$Action, [string]$Path, [Parameter(Mandatory)][TimeSpan]$Elapsed)
    if ($Path) { return ('{0} {1}... ({2})' -f $Action, $Path, (Format-Elapsed -Elapsed $Elapsed)) }
    '{0}... ({1})' -f $Action, (Format-Elapsed -Elapsed $Elapsed)
}

function Get-StatusText {
    # Warnings and errors say so in words, not only in colour. A change result that already
    # starts with its own words for it ("Partly done: ", "Done, with items to check: ",
    # Get-ChangeStatus) is not prefixed again.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [ValidateSet('Info', 'Success', 'Warning', 'Error')][string]$Kind = 'Info')
    $prefix = @{ Warning = 'Warning: '; Error = 'Error: ' }[$Kind]
    if (-not $prefix -or $Text.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return $Text }
    if ($Kind -eq 'Warning' -and ($Text.StartsWith('Partly done: ') -or $Text.StartsWith('Done, with items to check: '))) { return $Text }
    $prefix + $Text
}

function Get-ThemeToggleText {
    # The theme button names what it does.
    param([Parameter(Mandatory)][ValidateSet('Dark', 'Light')][string]$Current)
    if ($Current -eq 'Dark') { return "$([char]0x2600)  Switch to light" }
    "$([char]0x263E)  Switch to dark"
}

function Get-SavedTheme {
    # Dark unless the settings file says Light; a missing or unreadable file means Dark.
    param([Parameter(Mandatory)][string]$SettingsPath)
    try {
        if (-not (Test-Path -LiteralPath $SettingsPath -PathType Leaf)) { return 'Dark' }
        $s = Get-Content -LiteralPath $SettingsPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ("$($s.theme)" -eq 'Light') { return 'Light' }
    }
    catch { }
    'Dark'
}

function Set-SavedTheme {
    # Remembers the theme; other settings in the file are kept. Never throws.
    param(
        [Parameter(Mandatory)][ValidateSet('Dark', 'Light')][string]$Theme,
        [Parameter(Mandatory)][string]$SettingsPath
    )
    try {
        $settings = [ordered]@{}
        if (Test-Path -LiteralPath $SettingsPath -PathType Leaf) {
            try {
                $old = Get-Content -LiteralPath $SettingsPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                foreach ($p in $old.PSObject.Properties) { $settings[$p.Name] = $p.Value }
            }
            catch { }
        }
        $settings['theme'] = $Theme
        $dir = Split-Path -Parent $SettingsPath
        if ($dir -and -not (Test-Path -LiteralPath $dir -PathType Container)) {
            New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false -ErrorAction Stop | Out-Null
        }
        ConvertTo-Json -InputObject ([PSCustomObject]$settings) | Set-Content -LiteralPath $SettingsPath -Encoding UTF8 -WhatIf:$false -ErrorAction Stop
    }
    catch {
        Write-AppError "Could not save the theme to ${SettingsPath}: $($_.Exception.Message)"
    }
}

function Test-ChangeTaskRunning {
    # True when a task started as a change (Kind Change) has not finished yet.
    param([AllowNull()]$Task)
    $null -ne $Task -and "$($Task.Kind)" -eq 'Change' -and -not ($Task.Handle -and $Task.Handle.IsCompleted)
}

function Test-CanClose {
    # Asked by the window's Closing handler before anything is stopped. A change has no cancel:
    # stopping takeown or a batch midway would leave it half done, so the window stays open
    # (and says why) while one runs. Reads and the export can always be dropped.
    # "Running" is the task's own state (Test-ChangeTaskRunning), so a change whose result has
    # not been shown yet does not keep the window open for ever. A change that is being started
    # (no task object yet) counts as running.
    $running = $null
    $current = $script:ChangeTask
    if ($current -and (-not $current.Task -or (Test-ChangeTaskRunning $current.Task))) { $running = $current }
    if (-not $running) {
        $task = @($script:BgTasks | Where-Object { Test-ChangeTaskRunning $_ }) | Select-Object -First 1
        if ($task) { $running = [PSCustomObject]@{ Path = $(if ($current) { $current.Path } else { $null }) } }
    }
    if (-not $running) { return $true }
    $where = if ($running.Path) { $running.Path } else { 'a folder' }
    Show-AppMessage -Icon Warning -Message "A permission change is still running on $where. Wait for it to finish: closing now could leave it half done."
    $false
}

function Get-FatalErrorMessage {
    # What the window says when it has to close after an unexpected error. It never says
    # "Nothing was changed" when a change ran this session or is still running.
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$ErrorText,
        [Parameter(Mandatory)][AllowEmptyString()][string]$ErrorLogPath,
        [Parameter(Mandatory)][AllowEmptyString()][string]$ChangeLogFolder,
        [bool]$ChangeRunning,
        [bool]$ChangeStarted
    )
    $text = "Folder Permission Manager hit an error and has to close:`n`n$ErrorText`n`nDetails were written to $ErrorLogPath."
    if ($ChangeRunning) {
        $text += " A change may still be running or may have been made; check the change log in $ChangeLogFolder. The tool closes when it finishes."
    }
    elseif ($ChangeStarted) {
        $text += " A change may have been made in this session; check the change log in $ChangeLogFolder."
    }
    else { $text += ' Nothing was changed.' }
    $text
}

function Test-OwnProcess {
    # True when this PowerShell process was started just to run this script (-File <script>, as
    # the tool's own relaunch does), so ending the process cannot close a tech's console. Not
    # with -NoExit before -File: then the console is meant to stay open after the script.
    # https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe
    param([AllowEmptyCollection()][string[]]$CommandLineArgs, [Parameter(Mandatory)][string]$ScriptPath)
    $leaf = Split-Path -Leaf $ScriptPath
    $words = @($CommandLineArgs)
    for ($i = 0; $i -lt $words.Count - 1; $i++) {
        # Words after -File belong to the script, so only the ones before it are checked.
        if ("$($words[$i])" -match '^[-/]noe(x|xi|xit)?$') { return $false }
        if ($words[$i] -eq '-File') { return ((Split-Path -Leaf "$($words[$i + 1])".Trim('"')) -eq $leaf) }
    }
    $false
}

function Invoke-AppShutdown {
    # Closing must never hang on a background read stuck in network I/O, and must never cut a
    # change short:
    #   0. while a change task (Kind Change) is still running, nothing at all is done: no task is
    #      stopped, the mutex and the pool are kept and the process does not exit (Deferred).
    #      The caller waits for it first (Wait-ChangeTasks);
    #   1. release the single-instance mutex, so the tool can be opened again straight away;
    #   2. ask every read to stop and close the pool without blocking (BeginClose);
    #   3. wait a bounded time for the pool; if it did not close, end the process, which a stuck
    #      runspace thread would otherwise keep alive. With -ExitWhenDone the process also ends
    #      when the pool closed in time (only used when the process exists just for this window).
    # https://learn.microsoft.com/dotnet/api/system.management.automation.runspaces.runspacepool.beginclose
    # https://learn.microsoft.com/dotnet/api/system.environment.exit
    param(
        $Pool,
        $Mutex,
        [AllowEmptyCollection()][object[]]$Tasks,
        [int]$WaitMilliseconds = 3000,
        [switch]$ExitWhenDone,
        # Non-zero after a fatal error, so whoever started the tool can tell it failed.
        [int]$ExitCode = 0,
        [scriptblock]$ExitAction = { param([int]$Code) [Environment]::Exit($Code) }
    )
    if (@($Tasks | Where-Object { Test-ChangeTaskRunning $_ }).Count -gt 0) {
        return [PSCustomObject]@{ PoolClosed = $false; Exited = $false; Deferred = $true }
    }
    if ($Mutex) {
        try { $Mutex.ReleaseMutex() } catch { }
        try { $Mutex.Dispose() } catch { }
    }
    foreach ($t in @($Tasks)) {
        # A finished change task has nothing left to stop; only reads are asked to stop.
        if ($t -and $t.PS -and "$($t.Kind)" -ne 'Change') { try { [void]$t.PS.BeginStop($null, $null) } catch { } }
    }
    $closed = $true
    if ($Pool) {
        $closed = $false
        try {
            $handle = $Pool.BeginClose($null, $null)
            $closed = [bool]$handle.AsyncWaitHandle.WaitOne($WaitMilliseconds)
        }
        catch { $closed = $false }
    }
    if ($closed -and $Pool) { try { $Pool.Dispose() } catch { } }
    $exited = (-not $closed) -or [bool]$ExitWhenDone
    if ($exited) { & $ExitAction $ExitCode }
    [PSCustomObject]@{ PoolClosed = $closed; Exited = $exited; Deferred = $false }
}

function Wait-ChangeTasks {
    # Waits until every change task (Kind Change) has finished; reads are not waited for. $true
    # when they all finished, $false when -TimeoutMilliseconds (0 = no limit) ran out first.
    # Nothing is ever stopped: a change interrupted midway is worse than a late close.
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Tasks,
        [int]$PollMilliseconds = 200,
        [int]$TimeoutMilliseconds = 0
    )
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        if (@($Tasks | Where-Object { Test-ChangeTaskRunning $_ }).Count -eq 0) { return $true }
        if ($TimeoutMilliseconds -gt 0 -and $clock.ElapsedMilliseconds -ge $TimeoutMilliseconds) { return $false }
        Start-Sleep -Milliseconds ([Math]::Max(1, $PollMilliseconds))
    }
}

function Select-TaskResult {
    # A work block returns one result object (it has an Ok property). Stray output from a
    # command inside it must not be taken for it: the object with Ok wins, else the last one.
    param([AllowNull()][AllowEmptyCollection()][object[]]$Output)
    $items = @($Output | Where-Object { $null -ne $_ })
    if ($items.Count -eq 0) { return $null }
    $withOk = @($items | Where-Object { $_.PSObject.Properties['Ok'] })
    if ($withOk.Count -gt 0) { return $withOk[$withOk.Count - 1] }
    $items[$items.Count - 1]
}

function Enable-LiveRegion {
    # Marks an element as a live region, so screen readers announce new text: Polite for the
    # status line, Assertive (interrupts) for a dialog's validation error. LiveSetting exists
    # from .NET Framework 4.7.1; on older frameworks nothing is set ($false).
    # https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.livesetting
    # https://learn.microsoft.com/dotnet/api/system.windows.automation.automationlivesetting
    param([Parameter(Mandatory)]$Element, [ValidateSet('Polite', 'Assertive')][string]$Setting = 'Polite')
    $field = [System.Windows.Automation.AutomationProperties].GetField('LiveSettingProperty')
    if (-not $field) { return $false }
    $dp = $field.GetValue($null)
    $Element.SetValue($dp, [Enum]::Parse($dp.PropertyType, $Setting))
    $true
}

function Send-LiveRegionChanged {
    # Tells screen readers a live region's text changed (.NET Framework 4.7.1 and later).
    param([Parameter(Mandatory)]$Element)
    try {
        $peer = [System.Windows.Automation.Peers.UIElementAutomationPeer]::CreatePeerForElement($Element)
        if ($peer) { $peer.RaiseAutomationEvent([System.Windows.Automation.Peers.AutomationEvents]::LiveRegionChanged) }
    }
    catch { }
}

#endregion

#region View state (stale results are dropped)

# Each pane counts its requests; a result that is not for the latest request is ignored, so a
# slow folder never overwrites the one selected after it.
$script:PaneRequests = @{}
$script:ViewState = @{ FolderPermissions = $null; Files = $null }
$script:FileAclCache = @{}
$script:FileAclPending = @{}
$script:BusyEntries = [ordered]@{}
# A change being prepared (its target looked up, its tree counted, its dialog or confirm open):
# $null, or Action, Path and Step (Start-ChangePrepRead). While it is set, as while a change
# runs, the change buttons are off and new change clicks are refused.
$script:ChangePending = $null
$script:ChangeButtonTips = @{}
# Set once a change task has started in this window (the fatal-error text depends on it).
$script:ChangeMadeThisSession = $false
$script:MaxFileDetails = 20
$script:MaxFileAclAutoLoad = 50

function New-PaneRequest {
    param([Parameter(Mandatory)][string]$Pane)
    $script:PaneRequests[$Pane] = 1 + [int]$script:PaneRequests[$Pane]
    $script:PaneRequests[$Pane]
}

function Test-CurrentRequest {
    param([Parameter(Mandatory)][string]$Pane, [Parameter(Mandatory)][int]$Request)
    [int]$script:PaneRequests[$Pane] -eq $Request
}

function Set-FolderPermissionsResult {
    # $true when the result was for the latest request and is now shown; $false when stale.
    param([AllowNull()]$Result, [Parameter(Mandatory)][int]$Request)
    if (-not (Test-CurrentRequest -Pane 'FolderPermissions' -Request $Request)) { return $false }
    $ok = [bool]($Result -and $Result.Ok)
    $err = $null
    if (-not $ok) { $err = if ($Result) { "$($Result.Error)" } else { '' } }
    $script:ViewState.FolderPermissions = [PSCustomObject]@{
        Ok                      = $ok
        Path                    = $(if ($Result) { $Result.Path } else { $null })
        Owner                   = $(if ($Result) { $Result.Owner } else { $null })
        AreAccessRulesProtected = $(if ($Result) { [bool]$Result.AreAccessRulesProtected } else { $false })
        Rows                    = $(if ($Result) { @($Result.Rows) } else { @() })
        Error                   = $err
    }
    Show-FolderPermissions
    $true
}

function Set-FilesResult {
    param([AllowNull()]$Result, [Parameter(Mandatory)][int]$Request)
    if (-not (Test-CurrentRequest -Pane 'Files' -Request $Request)) { return $false }
    $ok = [bool]($Result -and $Result.Ok)
    $script:ViewState.Files = [PSCustomObject]@{
        Ok    = $ok
        Path  = $(if ($Result) { $Result.Path } else { $null })
        Rows  = $(if ($ok) { @($Result.Files) } else { @() })
        Error = $(if ($ok) { $null } elseif ($Result) { "$($Result.Error)" } else { '' })
    }
    Show-Files
    $true
}

function Set-FileAclResult {
    # File permissions arrive for the folder's file list they were asked for (Files request).
    param([AllowNull()]$Result, [Parameter(Mandatory)][int]$Request, [string[]]$Paths)
    if (-not (Test-CurrentRequest -Pane 'Files' -Request $Request)) { return $false }
    foreach ($p in @($Paths)) { $script:FileAclPending.Remove($p) }
    if ($Result -and $Result.Ok) {
        foreach ($i in @($Result.Items)) { if ($i) { $script:FileAclCache[$i.Path] = $i } }
    }
    else {
        $err = if ($Result) { "$($Result.Error)" } else { '' }
        foreach ($p in @($Paths)) {
            # A failed retry never replaces permissions that were already read for that file.
            $known = $script:FileAclCache[$p]
            if ($known -and $known.Ok) { continue }
            $script:FileAclCache[$p] = [PSCustomObject]@{ Ok = $false; Path = $p; Owner = $null; AreAccessRulesProtected = $false; Rows = @(); Error = $err }
        }
    }
    Show-FileDetails
    $true
}

#endregion

#region Background work (blocks run in the runspace pool; they return plain data)

# App functions the work blocks call. They and every function of the core are copied into the
# pool's session state once, when the pool opens (Initialize-BackgroundPool), so a work block
# does not load the core again on every call. $CorePath is only a fallback for a runspace that
# does not have the core. Tests run the blocks directly with $CorePath = $null.
$script:WorkHelperFunctions = 'Get-InnermostErrorText', 'Test-AccessDeniedError', 'Get-AccessDeniedMessage',
'Get-AclOwnerName', 'ConvertTo-AclViewModel', 'Read-ItemAclModel', 'Format-FileSize', 'ConvertTo-FileRows',
'Get-DriveListModel', 'Get-ValidDriveMap', 'Test-UncSharePath', 'Write-ChangeStartedLog', 'New-ChangeWorkResult',
'New-ChangeNotStartedResult', 'Invoke-AppChange', 'Add-ChangeReadBack', 'Get-ReadBackProblem', 'ConvertTo-IdentitySid',
'Save-UnloggedChangeRows', 'ConvertTo-SidAccountName', 'Get-RemoveIdentityProblem', 'New-ChangeRefusedResult',
'Get-ResolvedRootRefusal', 'Get-TreeLinkTargetRefusal',
# Where a change lands (Resolve-ChangeTargetSet and everything it calls), looked up in the pool.
'Resolve-ChangeTargetSet', 'Get-ChangeTarget', 'New-ChangeTarget', 'Get-StreamRefusal', 'Resolve-MappedDrive',
'Test-ThisComputerName', 'Get-ThisComputerNames', 'ConvertFrom-Ipv6LiteralName', 'Test-SameIPAddress',
'Get-LocalSharePath', 'Get-AppDfsTarget', 'Get-DfsClientTarget', 'Find-DfsReparsePoint', 'Get-AppReparseInfo',
'Get-RemoteShareLocalPath', 'Get-ShareTreeRefusal', 'Get-ServerSideLinkRefusal', 'Get-CopyTargetRefusal', 'Get-TargetRootKind',
'Complete-AppChangeWork'

function Write-ChangeStartedLog {
    # One 'Started' row per item in the change log before the change runs, so a change that is
    # cut off (the process killed, the computer restarted) still shows what was being changed;
    # the core adds each item's result row as it completes. $true when written. Under -WhatIf
    # nothing is written and nothing claimed ($true). $false when the log cannot be written: the
    # caller then changes nothing, as the core does when it cannot save a backup.
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Detail,
        [AllowEmptyCollection()][string[]]$Path,
        [Parameter(Mandatory)][string]$LogFolder,
        [bool]$WhatIfMode
    )
    if ($WhatIfMode) { return $true }
    $rows = @(foreach ($p in @($Path)) {
            $type = Get-AclItemType -Path $p
            if (-not $type) { $type = 'Unknown' }
            New-PermissionChangeEntry -Action $Action -Target $p -ItemType $type -Detail $Detail -Result 'Started'
        })
    if ($rows.Count -eq 0) { return $true }
    [bool](Write-PermissionChangeLog -Entries $rows -LogFolder $LogFolder)
}

function New-ChangeWorkResult {
    # What a change work block returns: the core's rows (with the read-back's CheckProblem and
    # NothingRemoved notes, Add-ChangeReadBack), the log file, the core's message, and where the
    # rows went when the log could not be written (UnloggedPath), and whether the read-back's
    # "Done, with items to check" rows could not be written to the log (ReadBackUnlogged) and
    # where they went instead (ReadBackUnloggedPath).
    param(
        [AllowEmptyCollection()][AllowNull()][object[]]$Entries,
        [AllowNull()][string]$LogPath,
        [Parameter(Mandatory)][string]$LogFolder,
        [AllowNull()][string]$UnloggedPath,
        [bool]$ReadBackUnlogged,
        [AllowNull()][string]$ReadBackUnloggedPath
    )
    $all = @($Entries | Where-Object { $null -ne $_ })
    $path = if ($LogPath) { $LogPath } else { $null }
    [PSCustomObject]@{
        Ok           = $true
        Entries      = $all
        LogPath      = $path
        Message      = Get-ChangeResultMessage -Entries $all -LogPath $path -LogFolder $LogFolder
        UnloggedPath = $(if ($UnloggedPath) { $UnloggedPath } else { $null })
        ReadBackUnlogged     = $ReadBackUnlogged
        ReadBackUnloggedPath = $(if ($ReadBackUnloggedPath) { $ReadBackUnloggedPath } else { $null })
        Error        = $null
    }
}

function Invoke-AppChange {
    # Runs one core change function (the -Change block). Normally through
    # Invoke-LoggedPermissionChange, which logs each row as soon as that item is done. Under
    # -WhatIfMode the core function is called directly (the block passes it -WhatIf too), so
    # nothing is logged and the log folder is not created: "-WhatIf never writes or claims a
    # log" (destructive-operations profile).
    # The -Change block runs in a child scope of this function (and of Invoke-LoggedPermissionChange)
    # and reads the work block's variables, so these parameter names must not hide theirs.
    param([Parameter(Mandatory)][scriptblock]$Change, [Parameter(Mandatory)][string]$LogFolder, [bool]$WhatIfMode)
    if ($WhatIfMode) {
        return [PSCustomObject]@{ Entries = @(& $Change | Where-Object { $null -ne $_ }); LogPath = $null }
    }
    Invoke-LoggedPermissionChange -LogFolder $LogFolder -Change $Change
}

function ConvertTo-IdentitySid {
    # The SID of a user or group name (or of a SID written as text), or $null when Windows cannot
    # translate it. https://learn.microsoft.com/dotnet/api/system.security.principal.ntaccount.translate
    param([AllowNull()][AllowEmptyString()][string]$Identity)
    $id = "$Identity".Trim()
    if (-not $id) { return $null }
    try {
        if ($id -match '^S-1-\d+(-\d+)+$') { return ([System.Security.Principal.SecurityIdentifier]$id).Value }
        (New-Object System.Security.Principal.NTAccount -ArgumentList $id).Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch { $null }
}

function ConvertTo-SidAccountName {
    # The account name a SID stands for now, or $null when Windows cannot translate it (the
    # account was deleted, or its domain cannot be reached).
    # https://learn.microsoft.com/dotnet/api/system.security.principal.securityidentifier.translate
    param([AllowNull()][AllowEmptyString()][string]$Sid)
    $s = "$Sid".Trim()
    if (-not $s) { return $null }
    try { ([System.Security.Principal.SecurityIdentifier]$s).Translate([System.Security.Principal.NTAccount]).Value }
    catch { $null }
}

function Get-RemoveIdentityProblem {
    # The core removes by name (Remove-FolderPermission builds an NTAccount from -Identity and
    # calls RemoveAccessRuleAll), so the name is looked up again when the change runs. Before it
    # does, this checks that the name still stands for the SID of the entry chosen in the remove
    # dialog: "the change acts on the same identifier it matched (the SID), not a name that could
    # resolve differently" (destructive-operations profile). Returns Problem (the text, or $null)
    # and Sid (the SID the name stands for).
    #   - The entry's SID cannot be looked up from here (shown as S-1-...): refused; the core
    #     cannot remove it by name. That does not prove the account is gone: it may be deleted,
    #     or local to the server (another computer's local group, which this computer cannot
    #     translate). icacls removes it by SID: "/remove[:g|:d] Sid" removes all occurrences of
    #     the SID's granted (g) or denied (d) rights, and "If you use a numerical form, affix
    #     the wildcard character * to the beginning of the SID". The hint starts with
    #     "/save <ACLfile>", which "Stores DACLs for all matching files into an access control
    #     list (ACL) file for later use with /restore", so the entry can be put back.
    #     https://learn.microsoft.com/windows-server/administration/windows-commands/icacls
    #   - The name no longer looks up, though the SID does under another name (renamed, or the
    #     name is local to the server): refused, with the same wording.
    #   - The name now stands for another SID (a domain migration, a rename and a new account
    #     with the old name): refused.
    # Without -Sid (no entry was chosen) only the name is translated.
    # https://learn.microsoft.com/dotnet/api/system.security.principal.ntaccount.translate
    param(
        [Parameter(Mandatory)][string]$Identity,
        [string]$Sid,
        [AllowEmptyCollection()][string[]]$Path,
        [string]$Type
    )
    $lookUp = "Windows can't look up this account from here (it may be deleted, or local to the server)"
    $orphan = {
        param($sidText)
        $switch = if ($Type -eq 'Deny') { '/remove:d' } else { '/remove:g' }
        $first = @($Path | Where-Object { $_ })[0]
        $command = "icacls `"$first`" /save acl-backup.txt, then icacls `"$first`" $switch *$sidText"
        $howTo = if (@($Path).Count -gt 1) { "for each item, for example $command" } else { $command }
        "${lookUp}: $sidText. This tool can't remove entries for an account it can't look up; ask a senior admin to back up the permissions and remove it by SID ($howTo). Nothing was changed."
    }
    $id = $Identity.Trim()
    if ($id -match '^S-1-\d+(-\d+)+$') { return [PSCustomObject]@{ Problem = (& $orphan $(if ($Sid) { $Sid } else { $id })); Sid = $null } }
    $now = ConvertTo-IdentitySid -Identity $id
    if (-not $Sid) {
        if (-not $now) { return [PSCustomObject]@{ Problem = "Windows could not find the account $id, so nothing was changed. Check the name, or ask a senior admin."; Sid = $null } }
        return [PSCustomObject]@{ Problem = $null; Sid = $now }
    }
    if (-not $now) {
        $current = ConvertTo-SidAccountName -Sid $Sid
        if (-not $current) { return [PSCustomObject]@{ Problem = (& $orphan $Sid); Sid = $null } }
        return [PSCustomObject]@{ Problem = "${lookUp}: $id. The account of the entry you chose ($Sid) is now called $current (it may have been renamed), so nothing was changed. Press Refresh and choose it again."; Sid = $null }
    }
    if ($now -ne $Sid) {
        return [PSCustomObject]@{ Problem = "$id now resolves to a different account than the entry you chose (for example after a domain migration or rename), so nothing was changed. Ask a senior admin. (The entry is $Sid; the name is now $now.)"; Sid = $null }
    }
    [PSCustomObject]@{ Problem = $null; Sid = $Sid }
}

function Get-ReadBackProblem {
    # Reads one item again after a change and says what is not as intended, or $null when it is.
    # Throws when the item cannot be read. Entries are compared by SID (GetAccessRules with
    # SecurityIdentifier), never by name; rights are compared after mapping generic rights and
    # without Synchronize, which Windows adds to Allow entries only (core ConvertTo-SpecificFileRight).
    #   Add:    an explicit entry for the SID, of that type, with at least those rights;
    #   Remove: no explicit entry for the SID of that type is left;
    #   Owner:  the owner is the account running the tool;
    #   Copy:   every explicit entry of the source is on the target (an inherited one counts when
    #           the target is under the source, as Copy-FolderPermission counts it).
    # https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.commonobjectsecurity.getaccessrules
    # https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.objectsecurity.getowner
    param(
        [Parameter(Mandatory)][ValidateSet('Add', 'Remove', 'Owner', 'Copy')][string]$Kind,
        [Parameter(Mandatory)][string]$Path,
        [string]$Identity,
        [string]$Sid,
        [string]$Rights,
        [string]$Type,
        [string]$MySid,
        [AllowEmptyCollection()][object[]]$SourceRules,
        [string]$SourcePath
    )
    $sidType = [System.Security.Principal.SecurityIdentifier]
    $noSync = -bnot [int64]0x100000
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    switch ($Kind) {
        'Owner' {
            $owner = "$($acl.GetOwner($sidType).Value)"
            if ($owner -eq $MySid) { return $null }
            $name = $owner
            try { $name = ([System.Security.Principal.SecurityIdentifier]$owner).Translate([System.Security.Principal.NTAccount]).Value } catch { }
            return "its owner is $name afterwards, not you"
        }
        'Add' {
            $need = (ConvertTo-SpecificFileRight ([System.Security.AccessControl.FileSystemRights]$Rights)) -band $noSync
            foreach ($r in @($acl.GetAccessRules($true, $false, $sidType))) {
                if ("$($r.IdentityReference.Value)" -ne $Sid -or "$($r.AccessControlType)" -ne $Type) { continue }
                if (((ConvertTo-SpecificFileRight $r.FileSystemRights) -band $need) -eq $need) { return $null }
            }
            return "no explicit $Type $Rights entry for $Identity was found on it afterwards"
        }
        'Remove' {
            $left = @($acl.GetAccessRules($true, $false, $sidType) | Where-Object { "$($_.IdentityReference.Value)" -eq $Sid -and "$($_.AccessControlType)" -eq $Type })
            if ($left.Count -eq 0) { return $null }
            return "$Identity still has an explicit $Type entry on it afterwards"
        }
        'Copy' {
            $within = [bool](Test-PathWithin -Path $Path -Root $SourcePath)
            $have = @($acl.GetAccessRules($true, $within, $sidType))
            $missing = 0
            foreach ($s in @($SourceRules)) {
                $need = (ConvertTo-SpecificFileRight $s.FileSystemRights) -band $noSync
                $found = @($have | Where-Object {
                        "$($_.IdentityReference.Value)" -eq "$($s.IdentityReference.Value)" -and $_.AccessControlType -eq $s.AccessControlType -and
                        (((ConvertTo-SpecificFileRight $_.FileSystemRights) -band $need) -eq $need) })
                if ($found.Count -eq 0) { $missing++ }
            }
            if ($missing -eq 0) { return $null }
            return "$missing of the $(@($SourceRules).Count) permission(s) set on $SourcePath are not on it afterwards"
        }
    }
}

function Add-ChangeReadBack {
    # The core reports Done once Set-Acl returned; this reads each Done item again and checks the
    # intended state is there ("Done/PASS only after reading the result back", destructive-
    # operations profile). Never throws. A row that fails gets a CheckProblem note (shown as
    # "Done, with items to check") and a 'Done, with items to check' row in the change log; the
    # core's row itself is not changed. A remove whose permissions are byte for byte the same
    # before and after (OldValue = NewValue) and whose SID has no explicit entry of that type
    # gets NothingRemoved instead: there was nothing to remove.
    # Returns $null, or, when those check rows could not be written to the change log, Unlogged
    # and UnloggedPath: the rows went to the Unlogged_ file instead (Save-UnloggedChangeRows;
    # $null when that failed too).
    param(
        [Parameter(Mandatory)][ValidateSet('Add', 'Remove', 'Owner', 'Copy')][string]$Kind,
        [AllowEmptyCollection()][AllowNull()][object[]]$Entries,
        [string]$Identity,
        [string]$Sid,
        [string]$Rights,
        [string]$Type,
        [string]$SourcePath,
        [string]$LogFolder
    )
    $done = @($Entries | Where-Object { $null -ne $_ -and $_.Result -eq 'Done' })
    if ($done.Count -eq 0) { return }
    $setupProblem = $null
    $mySid = $null
    $sourceRules = @()
    try {
        switch ($Kind) {
            'Owner' { $mySid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
            'Copy' {
                $source = Get-Acl -LiteralPath $SourcePath -ErrorAction Stop
                $sourceRules = @($source.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
            }
            default {
                if (-not $Sid) { $Sid = ConvertTo-IdentitySid -Identity $Identity }
                if (-not $Sid) { $setupProblem = "Windows could not find the account $Identity to check the change afterwards" }
            }
        }
    }
    catch { $setupProblem = "the permissions of $SourcePath could not be read again to check the change ($(Get-InnermostErrorText $_))" }
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($e in $done) {
        $problem = $setupProblem
        if (-not $problem) {
            try {
                $problem = Get-ReadBackProblem -Kind $Kind -Path "$($e.Target)" -Identity $Identity -Sid $Sid -Rights $Rights -Type $Type `
                    -MySid $mySid -SourceRules $sourceRules -SourcePath $SourcePath
            }
            catch { $problem = "it could not be read again to check the change ($(Get-InnermostErrorText $_))" }
        }
        if (-not $problem -and $Kind -eq 'Remove' -and "$($e.OldValue)" -and "$($e.OldValue)" -ne 'Could not read' -and "$($e.OldValue)" -ceq "$($e.NewValue)") {
            $e | Add-Member -NotePropertyName NothingRemoved -NotePropertyValue $true -Force
            continue
        }
        if ($problem) {
            $e | Add-Member -NotePropertyName CheckProblem -NotePropertyValue $problem -Force
            $itemType = if ("$($e.ItemType)") { "$($e.ItemType)" } else { 'Unknown' }
            $rows.Add((New-PermissionChangeEntry -Action "$($e.Action)" -Target "$($e.Target)" -ItemType $itemType -Detail "$($e.Detail)" `
                        -OldValue "$($e.OldValue)" -NewValue "$($e.NewValue)" -Result 'Done, with items to check' `
                        -ErrorText "Read back after the change: $problem." -BackupFile "$($e.BackupFile)"))
        }
    }
    if ($rows.Count -gt 0 -and $LogFolder -and -not (Write-PermissionChangeLog -Entries $rows.ToArray() -LogFolder $LogFolder)) {
        return [PSCustomObject]@{ Unlogged = $true; UnloggedPath = (Save-UnloggedChangeRows -Entries $rows.ToArray()) }
    }
}

function Save-UnloggedChangeRows {
    # The change log could not be written after a change: the result rows go to
    # Unlogged_<yyyy-MM-dd>.csv (the change log's columns) in %LOCALAPPDATA%\FolderPermissionManager\Logs,
    # so what was changed is not lost. Returns the file, or $null when that fails too.
    param([AllowEmptyCollection()][AllowNull()][object[]]$Entries, [string]$Folder)
    $rows = @($Entries | Where-Object { $null -ne $_ })
    if ($rows.Count -eq 0) { return $null }
    if (-not $Folder) {
        $base = Get-LocalAppDataFolder
        if (-not $base) { return $null }
        $Folder = Join-Path $base 'FolderPermissionManager\Logs'
    }
    $columns = @(Get-PermissionChangeColumn)
    $safe = @(foreach ($e in $rows) {
            $o = [ordered]@{}
            foreach ($n in $columns) { $v = $e.$n; $o[$n] = if ($v -is [string]) { ConvertTo-CsvSafeText $v } else { $v } }
            [PSCustomObject]$o
        })
    try {
        if (-not (Test-Path -LiteralPath $Folder -PathType Container)) { New-Item -ItemType Directory -Path $Folder -Force -WhatIf:$false -ErrorAction Stop | Out-Null }
        $path = Join-Path $Folder ('Unlogged_{0}.csv' -f (Get-Date -Format 'yyyy-MM-dd'))
        $csv = @($safe | ConvertTo-Csv -NoTypeInformation)
        if (Test-Path -LiteralPath $path -PathType Leaf) { $csv = @($csv | Select-Object -Skip 1) }
        Add-Content -LiteralPath $path -Value $csv -Encoding UTF8 -WhatIf:$false -ErrorAction Stop
        $path
    }
    catch { $null }
}

function Complete-AppChangeWork {
    # The end of every single-item change work block: read back (not under -WhatIf), save the
    # rows elsewhere when the change log could not be written, and build the result.
    param(
        [Parameter(Mandatory)]$Done,
        [Parameter(Mandatory)][string]$LogFolder,
        [bool]$WhatIfMode,
        [hashtable]$ReadBack
    )
    $entries = @($Done.Entries | Where-Object { $null -ne $_ })
    $checkRows = $null
    if (-not $WhatIfMode -and $ReadBack) { $checkRows = Add-ChangeReadBack @ReadBack -Entries $entries -LogFolder $LogFolder }
    $unlogged = $null
    if (-not $WhatIfMode -and -not $Done.LogPath -and $entries.Count -gt 0) { $unlogged = Save-UnloggedChangeRows -Entries $entries }
    New-ChangeWorkResult -Entries $entries -LogPath $Done.LogPath -LogFolder $LogFolder -UnloggedPath $unlogged `
        -ReadBackUnlogged ([bool]$checkRows) -ReadBackUnloggedPath $(if ($checkRows) { $checkRows.UnloggedPath } else { $null })
}

function New-ChangeNotStartedResult {
    # The 'Started' rows could not be written, so nothing was changed (Write-ChangeStartedLog).
    param([Parameter(Mandatory)][string]$LogFolder)
    [PSCustomObject]@{
        Ok         = $false
        NotStarted = $true
        Entries    = @()
        LogPath    = $null
        Message    = $null
        Error      = "Nothing was changed: the change log in $LogFolder could not be written, so the change was not started. Check that you can write to that folder, or start the tool again with -LogFolder set to another folder."
    }
}

function New-ChangeRefusedResult {
    # A work block refused the change before anything was written or changed (the text says why).
    param([Parameter(Mandatory)][string]$Text)
    [PSCustomObject]@{ Ok = $false; NotStarted = $true; Entries = @(); LogPath = $null; Message = $null; Error = $Text }
}

function Get-CoreFunctionNames {
    # The functions FolderPermissions.Core.ps1 defines at its top level (not nested ones).
    param([Parameter(Mandatory)][string]$CorePath)
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($CorePath, [ref]$null, [ref]$null)
    @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) | ForEach-Object { $_.Name })
}

function Get-CoreScriptVariableNames {
    # The $script: variables FolderPermissions.Core.ps1 assigns at its top level (the D-040 reparse
    # allowlist, tag constants, message markers). The pool copies them next to the functions:
    # without them a pool-run guard sees $null, and the allowlist would count every reparse point
    # as a link.
    param([Parameter(Mandatory)][string]$CorePath)
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($CorePath, [ref]$null, [ref]$null)
    @($ast.EndBlock.Statements |
        Where-Object { $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                       $_.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                       $_.Left.VariablePath.IsScript } |
        ForEach-Object { $_.Left.VariablePath.UserPath -replace '^script:', '' } | Select-Object -Unique)
}

$script:DrivesWork = {
    param([hashtable]$DriveMap, [string]$CorePath)
    try {
        if ($CorePath -and -not (Get-Command -Name Get-ItemOwner -CommandType Function -ErrorAction SilentlyContinue)) { . $CorePath -LoadFunctionsOnly }
        [PSCustomObject]@{ Ok = $true; Drives = @(Get-DriveListModel -DriveMap $DriveMap); Error = $null }
    }
    catch {
        [PSCustomObject]@{ Ok = $false; Drives = @(); Error = "The drives could not be listed: $($_.Exception.Message)" }
    }
}

$script:ListChildrenWork = {
    param([string]$Path, [string]$CorePath)
    try {
        if ($CorePath -and -not (Get-Command -Name Get-ItemOwner -CommandType Function -ErrorAction SilentlyContinue)) { . $CorePath -LoadFunctionsOnly }
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
            return [PSCustomObject]@{ Ok = $false; Path = $Path; Children = @(); Error = "'$Path' was not found. It may have been moved, renamed or deleted; press Refresh." }
        }
        try {
            $items = @(Get-ChildItem -LiteralPath $Path -Directory -Force -ErrorAction Stop)
        }
        catch {
            $text = if (Test-AccessDeniedError $_) { Get-AccessDeniedMessage -Path $Path -Owner (Get-ItemOwner -Path $Path) } else { "Could not open '$Path': $(Get-InnermostErrorText $_)" }
            return [PSCustomObject]@{ Ok = $false; Path = $Path; Children = @(); Error = $text }
        }
        # Always a list, even for one subfolder (regression b900061).
        $children = @($items | Sort-Object Name | ForEach-Object { [PSCustomObject]@{ Name = $_.Name; Path = $_.FullName } })
        [PSCustomObject]@{ Ok = $true; Path = $Path; Children = $children; Error = $null }
    }
    catch {
        [PSCustomObject]@{ Ok = $false; Path = $Path; Children = @(); Error = "Could not open '$Path': $($_.Exception.Message)" }
    }
}

$script:FolderAclWork = {
    param([string]$Path, [string]$CorePath)
    try {
        if ($CorePath -and -not (Get-Command -Name Get-ItemOwner -CommandType Function -ErrorAction SilentlyContinue)) { . $CorePath -LoadFunctionsOnly }
        Read-ItemAclModel -Path $Path -ItemKind Folder
    }
    catch {
        [PSCustomObject]@{ Ok = $false; Path = $Path; Owner = $null; AreAccessRulesProtected = $false; Rows = @(); Error = "Could not read the permissions of '$Path': $($_.Exception.Message)" }
    }
}

$script:FilesWork = {
    param([string]$Path, [string]$CorePath)
    try {
        if ($CorePath -and -not (Get-Command -Name Get-ItemOwner -CommandType Function -ErrorAction SilentlyContinue)) { . $CorePath -LoadFunctionsOnly }
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
            return [PSCustomObject]@{ Ok = $false; Path = $Path; Files = @(); Error = "'$Path' was not found. It may have been moved, renamed or deleted; press Refresh." }
        }
        try {
            $items = @(Get-ChildItem -LiteralPath $Path -File -Force -ErrorAction Stop)
        }
        catch {
            $text = if (Test-AccessDeniedError $_) { Get-AccessDeniedMessage -Path $Path -Owner (Get-ItemOwner -Path $Path) } else { "Could not list the files in '$Path': $(Get-InnermostErrorText $_)" }
            return [PSCustomObject]@{ Ok = $false; Path = $Path; Files = @(); Error = $text }
        }
        [PSCustomObject]@{ Ok = $true; Path = $Path; Files = @(ConvertTo-FileRows -Item $items); Error = $null }
    }
    catch {
        [PSCustomObject]@{ Ok = $false; Path = $Path; Files = @(); Error = "Could not list the files in '$Path': $($_.Exception.Message)" }
    }
}

$script:FileAclWork = {
    param([string[]]$Paths, [string]$CorePath)
    try {
        if ($CorePath -and -not (Get-Command -Name Get-ItemOwner -CommandType Function -ErrorAction SilentlyContinue)) { . $CorePath -LoadFunctionsOnly }
        $items = @(foreach ($p in $Paths) { Read-ItemAclModel -Path $p -ItemKind File })
        [PSCustomObject]@{ Ok = $true; Items = $items; Error = $null }
    }
    catch {
        [PSCustomObject]@{ Ok = $false; Items = @(); Error = "Could not read the permissions of the selected files: $($_.Exception.Message)" }
    }
}

$script:ExportWork = {
    # The folder and every subfolder: one row per permission entry, or one ERROR row for a
    # folder whose permissions could not be read or that could not be opened. Every cell goes
    # through the core's formula guard (ConvertTo-CsvSafeText).
    param([string]$Path, [string]$OutputPath, [string]$CorePath)
    try {
        if ($CorePath -and -not (Get-Command -Name Get-ItemOwner -CommandType Function -ErrorAction SilentlyContinue)) { . $CorePath -LoadFunctionsOnly }
        $row = {
            param($Folder, $Owner, $Identity, $Rights, $AccessType, $IsInherited, $InheritanceFlags)
            [PSCustomObject]@{
                Path             = ConvertTo-CsvSafeText "$Folder"
                Owner            = ConvertTo-CsvSafeText "$Owner"
                Identity         = ConvertTo-CsvSafeText "$Identity"
                Rights           = ConvertTo-CsvSafeText "$Rights"
                AccessType       = ConvertTo-CsvSafeText "$AccessType"
                IsInherited      = ConvertTo-CsvSafeText "$IsInherited"
                InheritanceFlags = ConvertTo-CsvSafeText "$InheritanceFlags"
            }
        }
        $rows = [System.Collections.Generic.List[object]]::new()
        $listErrors = $null
        # -Force: hidden and system subfolders are part of the report too.
        $subfolders = @(Get-ChildItem -LiteralPath $Path -Recurse -Directory -Force -ErrorAction SilentlyContinue -ErrorVariable listErrors | ForEach-Object { $_.FullName })
        foreach ($folder in @($Path) + $subfolders) {
            try {
                $acl = Get-Acl -LiteralPath $folder -ErrorAction Stop
                $owner = Get-AclOwnerName -Acl $acl
                foreach ($entry in $acl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])) {
                    $rows.Add((& $row $folder $owner $entry.IdentityReference.Value $entry.FileSystemRights $entry.AccessControlType $entry.IsInherited $entry.InheritanceFlags))
                }
            }
            catch {
                $rows.Add((& $row $folder 'ERROR' '' '' '' '' (Get-InnermostErrorText $_)))
            }
        }
        foreach ($e in @($listErrors)) {
            if (-not $e) { continue }
            $where = if ($e.TargetObject) { "$($e.TargetObject)" } else { $Path }
            $rows.Add((& $row $where 'ERROR' '' '' '' '' "Could not open this folder: $(Get-InnermostErrorText $e)"))
        }
        if ($rows.Count -gt 0) {
            $rows | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8 -WhatIf:$false -ErrorAction Stop
        }
        else {
            Set-Content -LiteralPath $OutputPath -Value '"Path","Owner","Identity","Rights","AccessType","IsInherited","InheritanceFlags"' -Encoding UTF8 -WhatIf:$false -ErrorAction Stop
        }
        [PSCustomObject]@{ Ok = $true; RowCount = $rows.Count; OutputPath = $OutputPath; Error = $null }
    }
    catch {
        [PSCustomObject]@{ Ok = $false; RowCount = 0; OutputPath = $OutputPath; Error = "The report could not be saved to '$OutputPath': $(Get-InnermostErrorText $_)" }
    }
}

# The changes. Only Start-ChangeTask runs these (one at a time). Each one:
#   1. writes a 'Started' row per item to the change log, or changes nothing if it cannot
#      (under -WhatIf nothing is written);
#   2. calls one core change function through Invoke-AppChange: normally through
#      Invoke-LoggedPermissionChange, which backs up first and logs each item as soon as it is
#      done; under -WhatIf directly, so nothing is logged. -WhatIf:$WhatIf is passed explicitly:
#      a pool runspace starts with $WhatIfPreference false, so the launch's -WhatIf would not
#      reach the core otherwise. -Confirm:$false: the window's own dialog was the confirmation,
#      and a runspace has no host to ask;
#   3. reads each item that was done again and checks the intended state (Add-ChangeReadBack;
#      the core does not), and saves the rows elsewhere if the change log could not be written;
#   4. returns the core's rows and its message (Get-ChangeResultMessage).
# The -Change block runs in a child scope of Invoke-AppChange and Invoke-LoggedPermissionChange
# and reads this block's parameters ($Paths, $Identity, ...), so their names must not hide them
# (the browser version relies on the same rule, see Complete-PermissionChange there).
$script:AddPermissionWork = {
    param([string[]]$Paths, [string]$Identity, [string]$Rights, [string]$Type, [string]$LogFolder, [bool]$WhatIf, [string]$CorePath)
    try {
        if ($CorePath -and -not (Get-Command -Name Get-ItemOwner -CommandType Function -ErrorAction SilentlyContinue)) { . $CorePath -LoadFunctionsOnly }
        $Paths = @($Paths | Where-Object { "$_".Trim() })
        if (-not (Write-ChangeStartedLog -Action 'Add permission' -Detail "$Type $Rights for $Identity" -Path $Paths -LogFolder $LogFolder -WhatIfMode $WhatIf)) {
            return (New-ChangeNotStartedResult -LogFolder $LogFolder)
        }
        $done = Invoke-AppChange -LogFolder $LogFolder -WhatIfMode $WhatIf -Change {
            Add-FolderPermission -Path $Paths -Identity $Identity -Rights $Rights -Type $Type -LogFolder $LogFolder -Confirm:$false -WhatIf:$WhatIf
        }
        Complete-AppChangeWork -Done $done -LogFolder $LogFolder -WhatIfMode $WhatIf -ReadBack @{ Kind = 'Add'; Identity = $Identity; Rights = $Rights; Type = $Type }
    }
    catch {
        [PSCustomObject]@{ Ok = $false; Entries = @(); LogPath = $null; Message = $null; Error = Get-InnermostErrorText $_ }
    }
}

# -Sid: the account chosen in the remove dialog. The core removes by name
# (Remove-FolderPermission -Identity), so before it runs the name must still stand for that SID
# and the entry must not be an orphaned SID (Get-RemoveIdentityProblem); otherwise nothing is
# logged or changed. The read-back checks the SID. Empty means the name is translated.
$script:RemovePermissionWork = {
    param([string[]]$Paths, [string]$Identity, [string]$Rights, [string]$Type, [string]$LogFolder, [bool]$WhatIf, [string]$Sid, [string]$CorePath)
    try {
        if ($CorePath -and -not (Get-Command -Name Get-ItemOwner -CommandType Function -ErrorAction SilentlyContinue)) { . $CorePath -LoadFunctionsOnly }
        $Paths = @($Paths | Where-Object { "$_".Trim() })
        $match = Get-RemoveIdentityProblem -Identity $Identity -Sid $Sid -Path $Paths -Type $Type
        if ($match.Problem) { return (New-ChangeRefusedResult -Text $match.Problem) }
        $Sid = $match.Sid
        if (-not (Write-ChangeStartedLog -Action 'Remove permission' -Detail "$Type $Rights for $Identity" -Path $Paths -LogFolder $LogFolder -WhatIfMode $WhatIf)) {
            return (New-ChangeNotStartedResult -LogFolder $LogFolder)
        }
        $done = Invoke-AppChange -LogFolder $LogFolder -WhatIfMode $WhatIf -Change {
            Remove-FolderPermission -Path $Paths -Identity $Identity -Rights $Rights -Type $Type -LogFolder $LogFolder -Confirm:$false -WhatIf:$WhatIf
        }
        Complete-AppChangeWork -Done $done -LogFolder $LogFolder -WhatIfMode $WhatIf -ReadBack @{ Kind = 'Remove'; Identity = $Identity; Sid = $Sid; Rights = $Rights; Type = $Type }
    }
    catch {
        [PSCustomObject]@{ Ok = $false; Entries = @(); LogPath = $null; Message = $null; Error = Get-InnermostErrorText $_ }
    }
}

# This item only, or with $Recurse the folder and everything under it (the core's whole-tree
# take ownership, Invoke-TreeOwnershipChange: owner snapshot first, takeown /R /A /D N, D-034;
# it refuses the root of a drive and the Windows system folders itself, D-036, and reads every
# owner back itself, so only this-item-only changes are read back here).
$script:TakeOwnershipWork = {
    param([string[]]$Paths, [bool]$Recurse, [string]$LogFolder, [bool]$WhatIf, [string]$CorePath)
    try {
        if ($CorePath -and -not (Get-Command -Name Get-ItemOwner -CommandType Function -ErrorAction SilentlyContinue)) { . $CorePath -LoadFunctionsOnly }
        $Paths = @($Paths | Where-Object { "$_".Trim() })
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $action = if ($Recurse) { 'Take ownership (all subfolders and files)' } else { 'Take ownership' }
        $detail = if ($Recurse) { "Owner set to $me on the folder and all subfolders and files" } else { "Owner set to $me" }
        if (-not (Write-ChangeStartedLog -Action $action -Detail $detail -Path $Paths -LogFolder $LogFolder -WhatIfMode $WhatIf)) {
            return (New-ChangeNotStartedResult -LogFolder $LogFolder)
        }
        $done = Invoke-AppChange -LogFolder $LogFolder -WhatIfMode $WhatIf -Change {
            Set-ItemOwnerToCurrentUser -Path $Paths -LogFolder $LogFolder -Recurse:$Recurse -Confirm:$false -WhatIf:$WhatIf
        }
        $readBack = if ($Recurse) { $null } else { @{ Kind = 'Owner' } }
        Complete-AppChangeWork -Done $done -LogFolder $LogFolder -WhatIfMode $WhatIf -ReadBack $readBack
    }
    catch {
        [PSCustomObject]@{ Ok = $false; Entries = @(); LogPath = $null; Message = $null; Error = Get-InnermostErrorText $_ }
    }
}

# Adds the source folder's own permissions to each target (D-031: adds only, one Set-Acl per
# target; Windows passes them to the items below that inherit).
$script:CopyPermissionsWork = {
    param([string]$SourcePath, [string[]]$TargetPaths, [string]$LogFolder, [bool]$WhatIf, [string]$CorePath)
    try {
        if ($CorePath -and -not (Get-Command -Name Get-ItemOwner -CommandType Function -ErrorAction SilentlyContinue)) { . $CorePath -LoadFunctionsOnly }
        $TargetPaths = @($TargetPaths | Where-Object { "$_".Trim() })
        if (-not (Write-ChangeStartedLog -Action 'Copy permissions' -Detail "Copy the permissions set on $SourcePath" -Path $TargetPaths -LogFolder $LogFolder -WhatIfMode $WhatIf)) {
            return (New-ChangeNotStartedResult -LogFolder $LogFolder)
        }
        $done = Invoke-AppChange -LogFolder $LogFolder -WhatIfMode $WhatIf -Change {
            Copy-FolderPermission -SourcePath $SourcePath -TargetPath $TargetPaths -LogFolder $LogFolder -Confirm:$false -WhatIf:$WhatIf
        }
        Complete-AppChangeWork -Done $done -LogFolder $LogFolder -WhatIfMode $WhatIf -ReadBack @{ Kind = 'Copy'; SourcePath = $SourcePath }
    }
    catch {
        [PSCustomObject]@{ Ok = $false; Entries = @(); LogPath = $null; Message = $null; Error = Get-InnermostErrorText $_ }
    }
}

# Read only, before any change: where the change would land and whether it is refused
# (Resolve-ChangeTargetSet: mapped drives, this computer's own names and shares, DFS, D-036 and
# the high-impact roots for a whole tree, the protected folders for a Copy target). Its lookups (DFS, Win32_Share, NetShareGetInfo, this
# computer's addresses, reparse points) can wait on the network, so they never run on the
# window's thread.
$script:ChangeTargetWork = {
    # $RefuseProtected comes after $CorePath so callers that pass the first seven keep working.
    param([string[]]$Paths, [hashtable]$DriveMap, [hashtable]$DriveMapSource, [bool]$WholeTree, [string]$FolderDisplayPath, [string]$FolderRealPath,
        [string]$CorePath, [bool]$RefuseProtected = $false)
    try {
        if ($CorePath -and -not (Get-Command -Name Get-ItemOwner -CommandType Function -ErrorAction SilentlyContinue)) { . $CorePath -LoadFunctionsOnly }
        Resolve-ChangeTargetSet -Path $Paths -DriveMap $DriveMap -DriveMapSource $DriveMapSource -WholeTree:$WholeTree `
            -FolderDisplayPath $FolderDisplayPath -FolderRealPath $FolderRealPath -RefuseProtected:$RefuseProtected
    }
    catch {
        [PSCustomObject]@{ Ok = $false; Targets = @(); Refusal = "Could not work out where the change would land, so nothing was changed: $(Get-InnermostErrorText $_)" }
    }
}
# Read only: what a whole-tree take ownership would cover, counted the way the core's owner
# snapshot lists it (Get-OwnerTreeItem: hidden and system items too, links listed but not gone
# into, folders that cannot be opened counted but not what is inside them). Folders includes
# the chosen folder itself. LinkRefusal: why a junction or symbolic link in it stops the change
# (Get-TreeLinkTargetRefusal), checked here so the confirm never opens for it.
$script:TreeCountWork = {
    param([string]$Path, [string]$CorePath)
    try {
        if ($CorePath -and -not (Get-Command -Name Get-ItemOwner -CommandType Function -ErrorAction SilentlyContinue)) { . $CorePath -LoadFunctionsOnly }
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
            return [PSCustomObject]@{ Ok = $false; Path = $Path; Folders = 0; Files = 0; NotOpened = 0; Links = 0; LinkRefusal = $null; Error = "'$Path' was not found. It may have been moved, renamed or deleted; press Refresh." }
        }
        $tree = Get-OwnerTreeItem -Path $Path
        [PSCustomObject]@{
            Ok          = $true
            Path        = $Path
            Folders     = @($tree.Items | Where-Object { $_.ItemType -eq 'Folder' }).Count
            Files       = @($tree.Items | Where-Object { $_.ItemType -eq 'File' }).Count
            NotOpened   = @($tree.Unlisted).Count
            Links       = @($tree.Links).Count
            LinkRefusal = Get-TreeLinkTargetRefusal -Path $Path -LinkPaths @($tree.Links)
            Error       = $null
        }
    }
    catch {
        [PSCustomObject]@{ Ok = $false; Path = $Path; Folders = 0; Files = 0; NotOpened = 0; Links = 0; LinkRefusal = $null; Error = "Could not count what is in '$Path': $(Get-InnermostErrorText $_)" }
    }
}

function Initialize-BackgroundPool {
    # One pool of 1-4 runspaces for every read and the one change at a time; workers never
    # touch the window.
    # -FunctionOverride (name -> function body) replaces those definitions in the pool, or adds
    # them: a test hook, so a pool run can be given recording stand-ins for the write cmdlets
    # (a function is found before a cmdlet or an .exe of the same name). The window never
    # passes it.
    # https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_command_precedence
    param([hashtable]$FunctionOverride)
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    # The pool only runs this script's own work blocks and the core next to it, which the
    # window has already loaded; the process policy may not reach a new runspace.
    $iss.ExecutionPolicy = [Microsoft.PowerShell.ExecutionPolicy]::Bypass
    # The core was loaded once when the window started; its functions are copied from there.
    $names = @($script:WorkHelperFunctions) + @(Get-CoreFunctionNames -CorePath $script:CorePath) | Select-Object -Unique
    $definitions = [ordered]@{}
    foreach ($name in $names) {
        $definitions[$name] = (Get-Command -Name $name -CommandType Function -ErrorAction Stop).Definition
    }
    if ($FunctionOverride) {
        foreach ($name in $FunctionOverride.Keys) { $definitions["$name"] = "$($FunctionOverride[$name])" }
    }
    foreach ($name in $definitions.Keys) {
        $iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($name, $definitions[$name]))
    }
    # The core's top-level $script: variables, with the values this window loaded. In a pool
    # runspace the copied functions' script scope is the session (global) scope, which is where
    # SessionStateVariableEntry puts them.
    # https://learn.microsoft.com/dotnet/api/system.management.automation.runspaces.sessionstatevariableentry
    foreach ($varName in @(Get-CoreScriptVariableNames -CorePath $script:CorePath)) {
        $value = (Get-Variable -Name $varName -Scope Script -ErrorAction Stop).Value
        $iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new($varName, $value, ''))
    }
    $script:BgPool =[System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, 4, $iss, $Host)
    $script:BgPool.Open()
    $script:BgTasks = [System.Collections.Generic.List[object]]::new()
}

function Start-BgTask {
    param([scriptblock]$Work, [object[]]$ArgumentList, [scriptblock]$OnDone, $State, [ValidateSet('Read', 'Change')][string]$Kind = 'Read')
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.RunspacePool = $script:BgPool
    [void]$ps.AddScript($Work.ToString())
    foreach ($a in $ArgumentList) { [void]$ps.AddArgument($a) }
    $task = [PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke(); OnDone = $OnDone; State = $State; Stopped = $false; Kind = $Kind }
    $script:BgTasks.Add($task)
    $task
}

function Stop-BgTask {
    # Asks the task to stop without waiting; its completion still runs (with Stopped = $true).
    param([Parameter(Mandatory)]$Task)
    $Task.Stopped = $true
    try { [void]$Task.PS.BeginStop($null, $null) } catch { }
}

function Update-BgTasks {
    # Runs on the UI thread (timer): hands each finished task's result to its callback. A task
    # that failed or was stopped still calls back, so no pane is left on "Loading...".
    if (-not $script:BgTasks) { return }
    foreach ($t in @($script:BgTasks)) {
        if (-not $t.Handle.IsCompleted) { continue }
        # A callback that shows a dialog (the whole-tree confirm) runs a nested message loop in
        # which the timer calls this again; a task the inner call already handled is skipped,
        # so no callback ever runs twice.
        if (-not $script:BgTasks.Remove($t)) { continue }
        $result = $null
        try {
            $out = $t.PS.EndInvoke($t.Handle)
            $result = Select-TaskResult -Output @($out)
            if ($null -eq $result) {
                $why = @($t.PS.Streams.Error | Select-Object -First 1)
                $text = if ($why.Count -gt 0) { "$($why[0])" } else { 'The background task returned nothing.' }
                $result = [PSCustomObject]@{ Ok = $false; Stopped = [bool]$t.Stopped; Error = $text }
            }
        }
        catch {
            $text = if ($t.Stopped) { 'Stopped.' } else { Get-InnermostErrorText $_ }
            $result = [PSCustomObject]@{ Ok = $false; Stopped = [bool]$t.Stopped; Error = $text }
        }
        finally { $t.PS.Dispose() }
        try { & $t.OnDone $result $t.State }
        catch {
            Write-AppError "Background task callback: $($_.Exception.Message)"
            Set-Status -Kind Error -Text "Something went wrong while showing a result: $($_.Exception.Message) Press Refresh to try again."
        }
    }
}

#endregion

#region Window markup and themes

# Selection: an accent fill at least 3:1 against the row (Card, CardHover) and the tree (Input),
# text on it at least 4.5:1, plus a 2px bar (SelBar) at the left of a selected row. FocusRing
# marks keyboard focus and differs from every fill it sits on. The tests compute these ratios
# (WCAG 2): https://learn.microsoft.com/windows/apps/design/accessibility/accessible-text-requirements
$script:Themes = @{
    Dark  = @{
        Bg = '#16181D'; Panel = '#101216'; Card = '#1C1F26'; CardHover = '#232833'
        SelBg = '#3276AB'; SelText = '#FFFFFF'; SelBar = '#BFE3FA'; FocusRing = '#FFFFFF'
        Input = '#0F1115'; Border = '#262A33'; BorderStrong = '#343A46'
        BtnBg = '#232731'; BtnHover = '#2C313D'; BtnPressed = '#1B1F27'
        Text = '#D7DBE2'; TextStrong = '#F0F3F6'; Muted = '#8B949E'
        Accent = '#5DADE2'; AccentBtn = '#2A7AB0'; AccentBtnHover = '#236D9F'; OnAccent = '#FFFFFF'
        Danger = '#F08A7C'; Ok = '#6FD39B'; Warn = '#F2CC60'
        PillWarnBg = '#463A12'; BannerBg = '#14202A'; BannerBorder = '#22384A'
        Track = '#2B303A'; ScrollThumb = '#3C4350'
    }
    Light = @{
        Bg = '#F3F4F6'; Panel = '#FFFFFF'; Card = '#FFFFFF'; CardHover = '#F2F6FA'
        SelBg = '#1F6FA8'; SelText = '#FFFFFF'; SelBar = '#05080C'; FocusRing = '#0F1318'
        Input = '#FFFFFF'; Border = '#DDE1E7'; BorderStrong = '#C5CBD3'
        BtnBg = '#FFFFFF'; BtnHover = '#EEF1F5'; BtnPressed = '#E2E6EC'
        Text = '#2A2F37'; TextStrong = '#0F1318'; Muted = '#5F6875'
        Accent = '#1F6FA8'; AccentBtn = '#1F6FA8'; AccentBtnHover = '#185C8C'; OnAccent = '#FFFFFF'
        Danger = '#B83227'; Ok = '#1D7A44'; Warn = '#8A5A00'
        PillWarnBg = '#FBEFCC'; BannerBg = '#EAF3FB'; BannerBorder = '#C9DDEE'
        Track = '#E3E7EC'; ScrollThumb = '#C3C9D1'
    }
}

# The WPF and XAML namespace names. They are identifiers that only look like web addresses:
# nothing is fetched from them. The no-network test (AC6) exempts exactly these two strings.
# https://learn.microsoft.com/dotnet/desktop/xaml-services/namespaces
$script:XamlNamespaces = 'xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"'

$script:StylesXaml = @'
<FontFamily x:Key="Mono">Cascadia Mono, Consolas</FontFamily>
<FontFamily x:Key="Sym">Segoe UI Symbol</FontFamily>

<ControlTemplate x:Key="BtnTemplate" TargetType="Button">
  <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
          BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="3" Padding="{TemplateBinding Padding}" SnapsToDevicePixels="True">
    <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" RecognizesAccessKey="True"/>
  </Border>
  <ControlTemplate.Triggers>
    <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="{DynamicResource BtnHover}"/></Trigger>
    <Trigger Property="IsPressed" Value="True"><Setter TargetName="b" Property="Background" Value="{DynamicResource BtnPressed}"/></Trigger>
    <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="{DynamicResource FocusRing}"/></Trigger>
    <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/></Trigger>
  </ControlTemplate.Triggers>
</ControlTemplate>

<Style x:Key="Btn" TargetType="Button">
  <Setter Property="Background" Value="{DynamicResource BtnBg}"/>
  <Setter Property="Foreground" Value="{DynamicResource Text}"/>
  <Setter Property="BorderBrush" Value="{DynamicResource BorderStrong}"/>
  <Setter Property="BorderThickness" Value="1"/>
  <Setter Property="Padding" Value="12,6"/>
  <Setter Property="FontWeight" Value="SemiBold"/>
  <Setter Property="FontSize" Value="12.5"/>
  <Setter Property="Cursor" Value="Hand"/>
  <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
  <Setter Property="Template" Value="{StaticResource BtnTemplate}"/>
</Style>
<Style x:Key="DangerBtn" TargetType="Button" BasedOn="{StaticResource Btn}">
  <Setter Property="Foreground" Value="{DynamicResource Danger}"/>
</Style>
<Style x:Key="GhostBtn" TargetType="Button" BasedOn="{StaticResource Btn}">
  <Setter Property="Background" Value="Transparent"/>
  <Setter Property="BorderBrush" Value="Transparent"/>
  <Setter Property="Padding" Value="8,4"/>
</Style>
<Style x:Key="PrimaryBtn" TargetType="Button" BasedOn="{StaticResource Btn}">
  <Setter Property="Background" Value="{DynamicResource AccentBtn}"/>
  <Setter Property="BorderBrush" Value="{DynamicResource AccentBtn}"/>
  <Setter Property="Foreground" Value="{DynamicResource OnAccent}"/>
  <Setter Property="Template">
    <Setter.Value>
      <ControlTemplate TargetType="Button">
        <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="3" Padding="{TemplateBinding Padding}" SnapsToDevicePixels="True">
          <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" RecognizesAccessKey="True"/>
        </Border>
        <ControlTemplate.Triggers>
          <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="{DynamicResource AccentBtnHover}"/></Trigger>
          <Trigger Property="IsPressed" Value="True"><Setter TargetName="b" Property="Opacity" Value="0.85"/></Trigger>
          <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="{DynamicResource FocusRing}"/></Trigger>
          <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/></Trigger>
        </ControlTemplate.Triggers>
      </ControlTemplate>
    </Setter.Value>
  </Setter>
</Style>

<Style TargetType="TextBox">
  <Setter Property="Background" Value="{DynamicResource Input}"/>
  <Setter Property="Foreground" Value="{DynamicResource TextStrong}"/>
  <Setter Property="BorderBrush" Value="{DynamicResource BorderStrong}"/>
  <Setter Property="BorderThickness" Value="1"/>
  <Setter Property="Padding" Value="7,5"/>
  <Setter Property="FontSize" Value="12.5"/>
  <Setter Property="CaretBrush" Value="{DynamicResource TextStrong}"/>
  <Setter Property="SelectionBrush" Value="{DynamicResource AccentBtn}"/>
  <Setter Property="Template">
    <Setter.Value>
      <ControlTemplate TargetType="TextBox">
        <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="3" SnapsToDevicePixels="True">
          <ScrollViewer x:Name="PART_ContentHost" Focusable="False" Padding="{TemplateBinding Padding}"
                        HorizontalScrollBarVisibility="{TemplateBinding HorizontalScrollBarVisibility}"
                        VerticalScrollBarVisibility="{TemplateBinding VerticalScrollBarVisibility}"/>
        </Border>
        <ControlTemplate.Triggers>
          <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="{DynamicResource Muted}"/></Trigger>
          <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="{DynamicResource FocusRing}"/></Trigger>
          <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/></Trigger>
        </ControlTemplate.Triggers>
      </ControlTemplate>
    </Setter.Value>
  </Setter>
</Style>
<!-- Read-only text that can be selected and copied (paths, the status message). -->
<Style x:Key="SelectableText" TargetType="TextBox">
  <Setter Property="IsReadOnly" Value="True"/>
  <Setter Property="Background" Value="Transparent"/>
  <Setter Property="BorderThickness" Value="0"/>
  <Setter Property="Padding" Value="0"/>
  <Setter Property="TextWrapping" Value="Wrap"/>
  <Setter Property="Foreground" Value="{DynamicResource TextStrong}"/>
  <Setter Property="SelectionBrush" Value="{DynamicResource AccentBtn}"/>
  <Setter Property="Template">
    <Setter.Value>
      <ControlTemplate TargetType="TextBox">
        <ScrollViewer x:Name="PART_ContentHost" Focusable="False" Padding="{TemplateBinding Padding}"
                      VerticalScrollBarVisibility="{TemplateBinding VerticalScrollBarVisibility}"/>
      </ControlTemplate>
    </Setter.Value>
  </Setter>
</Style>

<!-- The change dialogs' lists use the Windows look, so their text is dark in both themes. -->
<Style TargetType="ComboBox">
  <Setter Property="Foreground" Value="#16181D"/>
  <Setter Property="Padding" Value="7,5"/>
  <Setter Property="FontSize" Value="12.5"/>
</Style>

<Style TargetType="CheckBox">
  <Setter Property="Foreground" Value="{DynamicResource Text}"/>
  <Setter Property="Cursor" Value="Hand"/>
  <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
  <Setter Property="Template">
    <Setter.Value>
      <ControlTemplate TargetType="CheckBox">
        <StackPanel Orientation="Horizontal" Background="Transparent">
          <!-- Muted, not BorderStrong: an empty box's edge must reach 3:1 against the box and the row. -->
          <Border x:Name="box" Width="16" Height="16" CornerRadius="3" BorderThickness="1" VerticalAlignment="Center"
                  BorderBrush="{DynamicResource Muted}" Background="{DynamicResource Input}">
            <Path x:Name="tick" Data="M3,8 L6.5,11.5 L13,4.5" Stroke="{DynamicResource OnAccent}" StrokeThickness="2" Visibility="Collapsed"/>
          </Border>
          <ContentPresenter Margin="8,0,0,0" VerticalAlignment="Center"/>
        </StackPanel>
        <ControlTemplate.Triggers>
          <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="box" Property="BorderBrush" Value="{DynamicResource Accent}"/></Trigger>
          <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="box" Property="BorderBrush" Value="{DynamicResource FocusRing}"/></Trigger>
          <Trigger Property="IsChecked" Value="True">
            <Setter TargetName="box" Property="Background" Value="{DynamicResource AccentBtn}"/>
            <Setter TargetName="box" Property="BorderBrush" Value="{DynamicResource OnAccent}"/>
            <Setter TargetName="tick" Property="Visibility" Value="Visible"/>
          </Trigger>
          <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/></Trigger>
        </ControlTemplate.Triggers>
      </ControlTemplate>
    </Setter.Value>
  </Setter>
</Style>

<Style x:Key="ThumbStyle" TargetType="Thumb">
  <Setter Property="Template">
    <Setter.Value>
      <ControlTemplate TargetType="Thumb">
        <Border CornerRadius="4" Background="{DynamicResource ScrollThumb}"/>
      </ControlTemplate>
    </Setter.Value>
  </Setter>
</Style>
<Style TargetType="ScrollBar">
  <Setter Property="Width" Value="10"/>
  <Setter Property="MinWidth" Value="10"/>
  <Setter Property="Template">
    <Setter.Value>
      <ControlTemplate TargetType="ScrollBar">
        <Grid Background="Transparent">
          <Track x:Name="PART_Track" IsDirectionReversed="True">
            <Track.Thumb><Thumb Style="{StaticResource ThumbStyle}" Margin="2"/></Track.Thumb>
          </Track>
        </Grid>
      </ControlTemplate>
    </Setter.Value>
  </Setter>
  <Style.Triggers>
    <Trigger Property="Orientation" Value="Horizontal">
      <Setter Property="Width" Value="Auto"/>
      <Setter Property="MinWidth" Value="0"/>
      <Setter Property="Height" Value="10"/>
      <Setter Property="MinHeight" Value="10"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ScrollBar">
            <Grid Background="Transparent">
              <Track x:Name="PART_Track" IsDirectionReversed="False">
                <Track.Thumb><Thumb Style="{StaticResource ThumbStyle}" Margin="2"/></Track.Thumb>
              </Track>
            </Grid>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Trigger>
  </Style.Triggers>
</Style>

<!-- Splitters are dragged with the mouse; they take no Tab stop. -->
<Style TargetType="GridSplitter">
  <Setter Property="Background" Value="{DynamicResource Border}"/>
  <Setter Property="IsTabStop" Value="False"/>
  <Setter Property="HorizontalAlignment" Value="Stretch"/>
  <Setter Property="VerticalAlignment" Value="Stretch"/>
</Style>

<Style TargetType="ProgressBar">
  <Setter Property="Foreground" Value="{DynamicResource Accent}"/>
  <Setter Property="Background" Value="{DynamicResource Track}"/>
  <Setter Property="BorderThickness" Value="0"/>
  <Setter Property="Height" Value="6"/>
</Style>

<Style x:Key="Lbl" TargetType="TextBlock">
  <Setter Property="Foreground" Value="{DynamicResource Muted}"/>
  <Setter Property="FontSize" Value="11"/>
  <Setter Property="FontWeight" Value="SemiBold"/>
  <Setter Property="Margin" Value="0,14,0,5"/>
</Style>
<Style x:Key="Hint" TargetType="TextBlock">
  <Setter Property="Foreground" Value="{DynamicResource Muted}"/>
  <Setter Property="FontSize" Value="11.5"/>
  <Setter Property="TextWrapping" Value="Wrap"/>
  <Setter Property="Margin" Value="0,4,0,0"/>
</Style>
<Style x:Key="PaneState" TargetType="TextBlock">
  <Setter Property="Foreground" Value="{DynamicResource Muted}"/>
  <Setter Property="TextWrapping" Value="Wrap"/>
  <Setter Property="Margin" Value="12,40,12,0"/>
  <Setter Property="HorizontalAlignment" Value="Center"/>
  <Setter Property="VerticalAlignment" Value="Top"/>
  <Setter Property="TextAlignment" Value="Center"/>
  <Setter Property="MaxWidth" Value="520"/>
</Style>

<Style x:Key="BaseGrid" TargetType="DataGrid">
  <Setter Property="AutoGenerateColumns" Value="False"/>
  <Setter Property="IsReadOnly" Value="True"/>
  <Setter Property="CanUserAddRows" Value="False"/>
  <Setter Property="CanUserDeleteRows" Value="False"/>
  <Setter Property="CanUserResizeRows" Value="False"/>
  <Setter Property="SelectionUnit" Value="FullRow"/>
  <Setter Property="HeadersVisibility" Value="Column"/>
  <Setter Property="GridLinesVisibility" Value="Horizontal"/>
  <Setter Property="HorizontalGridLinesBrush" Value="{DynamicResource Border}"/>
  <Setter Property="Background" Value="Transparent"/>
  <Setter Property="RowBackground" Value="Transparent"/>
  <Setter Property="AlternatingRowBackground" Value="Transparent"/>
  <Setter Property="Foreground" Value="{DynamicResource Text}"/>
  <Setter Property="BorderThickness" Value="0"/>
  <Setter Property="RowHeight" Value="30"/>
  <Setter Property="EnableRowVirtualization" Value="True"/>
  <Setter Property="ColumnHeaderStyle">
    <Setter.Value>
      <Style TargetType="DataGridColumnHeader">
        <Setter Property="Background" Value="{DynamicResource Panel}"/>
        <Setter Property="Foreground" Value="{DynamicResource Muted}"/>
        <Setter Property="FontWeight" Value="SemiBold"/>
        <Setter Property="Padding" Value="10,7"/>
        <Setter Property="BorderBrush" Value="{DynamicResource Border}"/>
        <Setter Property="BorderThickness" Value="0,0,0,1"/>
      </Style>
    </Setter.Value>
  </Setter>
  <Setter Property="CellStyle">
    <Setter.Value>
      <Style TargetType="DataGridCell">
        <Setter Property="BorderThickness" Value="0"/>
        <Setter Property="Template">
          <Setter.Value>
            <ControlTemplate TargetType="DataGridCell">
              <Border Background="Transparent" Padding="10,0">
                <ContentPresenter VerticalAlignment="Center"/>
              </Border>
            </ControlTemplate>
          </Setter.Value>
        </Setter>
      </Style>
    </Setter.Value>
  </Setter>
</Style>
<!-- One row look for both grids: a selected row gets the accent fill, its text colour and a
     2px bar at the left; the row holding keyboard focus gets a FocusRing border. -->
<ControlTemplate x:Key="RowTemplate" TargetType="DataGridRow">
  <Border x:Name="rowBorder" Background="{TemplateBinding Background}" BorderBrush="Transparent" BorderThickness="1" SnapsToDevicePixels="True">
    <Grid>
      <DataGridCellsPresenter ItemsPanel="{TemplateBinding ItemsPanel}" SnapsToDevicePixels="{TemplateBinding SnapsToDevicePixels}"/>
      <Rectangle x:Name="selBar" Width="2" HorizontalAlignment="Left" Fill="{DynamicResource SelBar}" Visibility="Collapsed"/>
    </Grid>
  </Border>
  <ControlTemplate.Triggers>
    <Trigger Property="IsSelected" Value="True"><Setter TargetName="selBar" Property="Visibility" Value="Visible"/></Trigger>
    <Trigger Property="IsKeyboardFocusWithin" Value="True"><Setter TargetName="rowBorder" Property="BorderBrush" Value="{DynamicResource FocusRing}"/></Trigger>
  </ControlTemplate.Triggers>
</ControlTemplate>
<Style x:Key="AclGrid" TargetType="DataGrid" BasedOn="{StaticResource BaseGrid}">
  <Setter Property="SelectionMode" Value="Single"/>
  <Setter Property="RowStyle">
    <Setter.Value>
      <Style TargetType="DataGridRow">
        <Setter Property="Background" Value="Transparent"/>
        <Setter Property="Foreground" Value="{DynamicResource Text}"/>
        <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
        <Setter Property="Template" Value="{StaticResource RowTemplate}"/>
        <Style.Triggers>
          <DataTrigger Binding="{Binding Type}" Value="Deny"><Setter Property="Foreground" Value="{DynamicResource Danger}"/></DataTrigger>
          <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="{DynamicResource CardHover}"/></Trigger>
          <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource SelBg}"/><Setter Property="Foreground" Value="{DynamicResource SelText}"/></Trigger>
        </Style.Triggers>
      </Style>
    </Setter.Value>
  </Setter>
</Style>
<Style x:Key="FileGrid" TargetType="DataGrid" BasedOn="{StaticResource BaseGrid}">
  <Setter Property="SelectionMode" Value="Extended"/>
  <Setter Property="RowStyle">
    <Setter.Value>
      <Style TargetType="DataGridRow">
        <Setter Property="Background" Value="Transparent"/>
        <Setter Property="Foreground" Value="{DynamicResource Text}"/>
        <Setter Property="Cursor" Value="Hand"/>
        <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
        <Setter Property="Template" Value="{StaticResource RowTemplate}"/>
        <Style.Triggers>
          <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="{DynamicResource CardHover}"/></Trigger>
          <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource SelBg}"/><Setter Property="Foreground" Value="{DynamicResource SelText}"/></Trigger>
        </Style.Triggers>
      </Style>
    </Setter.Value>
  </Setter>
</Style>
'@

function Get-AppResourcesXaml {
    # The theme brushes (dark, the default; Set-AppTheme replaces them) and the shared styles.
    # StaticResource references are resolved while the XAML is parsed, so every window carries
    # the styles in its own resources.
    $brushes = foreach ($key in ($script:Themes.Dark.Keys | Sort-Object)) {
        '<SolidColorBrush x:Key="{0}" Color="{1}"/>' -f $key, $script:Themes.Dark[$key]
    }
    ($brushes -join "`n") + "`n" + $script:StylesXaml
}

function Get-MainWindowXaml {
    $ns = $script:XamlNamespaces
    $res = Get-AppResourcesXaml
    @"
<Window $ns
        Title="Folder Permission Manager" Width="1320" Height="860" MinWidth="1000" MinHeight="560"
        WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" FontSize="13"
        Background="{DynamicResource Bg}" Foreground="{DynamicResource Text}"
        UseLayoutRounding="True" TextOptions.TextFormattingMode="Display">
  <Window.Resources>
$res
  </Window.Resources>
  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="56"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Title bar -->
    <Border Grid.Row="0" Background="{DynamicResource Panel}" BorderBrush="{DynamicResource Border}" BorderThickness="0,0,0,1">
      <DockPanel Margin="16,0" LastChildFill="False">
        <StackPanel DockPanel.Dock="Left" Orientation="Horizontal" VerticalAlignment="Center">
          <Border Width="30" Height="30" CornerRadius="4" Background="{DynamicResource AccentBtn}">
            <TextBlock Text="&#x1F512;" FontFamily="{StaticResource Sym}" FontSize="15" Foreground="{DynamicResource OnAccent}"
                       HorizontalAlignment="Center" VerticalAlignment="Center"/>
          </Border>
          <TextBlock Text="Folder Permission Manager" FontSize="16" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}"
                     Margin="10,0,0,0" VerticalAlignment="Center"/>
          <Border x:Name="DryRunPill" Visibility="Collapsed" CornerRadius="10" Padding="10,3" Margin="12,0,0,0" VerticalAlignment="Center"
                  Background="{DynamicResource PillWarnBg}">
            <TextBlock Text="Dry run (WhatIf)" FontSize="11.5" FontWeight="SemiBold" Foreground="{DynamicResource Warn}"/>
          </Border>
        </StackPanel>
        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
          <Button x:Name="ThemeToggle" Style="{StaticResource GhostBtn}" VerticalAlignment="Center" Margin="0,0,10,0"
                  ToolTip="Switch between dark and light. The choice is remembered."/>
          <Button x:Name="OpenLogFolderBtn" Style="{StaticResource Btn}" VerticalAlignment="Center"
                  ToolTip="Open the folder where backups and the change log are kept.">
            <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x1F4C1;"/><Run Text="  Open log folder"/></TextBlock>
          </Button>
        </StackPanel>
      </DockPanel>
    </Border>

    <!-- Where changes are logged, dry run -->
    <Border Grid.Row="1" Background="{DynamicResource BannerBg}" BorderBrush="{DynamicResource BannerBorder}" BorderThickness="0,0,0,1" Padding="16,8">
      <StackPanel>
        <StackPanel x:Name="BannerPanel"/>
        <TextBlock Foreground="{DynamicResource Muted}" TextWrapping="Wrap" Margin="0,2,0,0"
                   Text="To copy files with their permissions, use RobocopyMigration."/>
      </StackPanel>
    </Border>

    <!-- Path header: always shows where you are -->
    <Border Grid.Row="2" Background="{DynamicResource Panel}" BorderBrush="{DynamicResource Border}" BorderThickness="0,0,0,1" Padding="16,8">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Grid.Column="0" Text="FOLDER" Style="{StaticResource Lbl}" Margin="0,2,12,0" VerticalAlignment="Center"/>
        <TextBox x:Name="PathText" Grid.Row="0" Grid.Column="1" Style="{StaticResource SelectableText}" FontFamily="{StaticResource Mono}"
                 FontSize="13" Text="No folder chosen yet. Choose one on the left."/>
        <TextBlock x:Name="RealPathLabel" Grid.Row="1" Grid.Column="0" Text="REAL LOCATION" Style="{StaticResource Lbl}" Margin="0,4,12,0"
                   VerticalAlignment="Center" Visibility="Collapsed"/>
        <DockPanel Grid.Row="1" Grid.Column="1" LastChildFill="True">
          <!-- Shown when the mapping behind the letter is only remembered by Windows (registry),
               not seen live: it may point at an old server. -->
          <TextBlock x:Name="RealPathNote" DockPanel.Dock="Right" Text="(remembered mapping)" Foreground="{DynamicResource Warn}"
                     FontSize="12" Margin="8,4,0,0" VerticalAlignment="Center" Visibility="Collapsed"
                     ToolTip="Windows remembers this drive mapping, but this window could not see it live. It may be out of date: check the path."/>
          <TextBox x:Name="RealPathText" Style="{StaticResource SelectableText}" FontFamily="{StaticResource Mono}"
                   FontSize="12" Foreground="{DynamicResource Muted}" Margin="0,4,0,0" Visibility="Collapsed"/>
        </DockPanel>
        <Button x:Name="RefreshBtn" Grid.Row="0" Grid.RowSpan="2" Grid.Column="2" Style="{StaticResource Btn}" VerticalAlignment="Center" Margin="12,0,0,0"
                ToolTip="Read this folder again: its subfolders, permissions and files (F5)." IsEnabled="False">
          <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x21BB;"/><Run Text="  Refresh"/></TextBlock>
        </Button>
      </Grid>
    </Border>

    <!-- Busy line -->
    <Border x:Name="BusyBar" Grid.Row="3" Visibility="Collapsed" Background="{DynamicResource Card}" BorderBrush="{DynamicResource Border}"
            BorderThickness="0,0,0,1" Padding="16,6">
      <DockPanel>
        <Button x:Name="StopExportBtn" DockPanel.Dock="Right" Style="{StaticResource DangerBtn}" Padding="10,3" Margin="12,0,0,0" Visibility="Collapsed"
                ToolTip="Stop the export. A file that was already being written is incomplete.">
          <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x25A0;"/><Run Text="  Stop export"/></TextBlock>
        </Button>
        <ProgressBar x:Name="BusyProgress" DockPanel.Dock="Left" Width="140" IsIndeterminate="True" VerticalAlignment="Center" Margin="0,0,12,0"/>
        <TextBlock x:Name="BusyText" Foreground="{DynamicResource Text}" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
      </DockPanel>
    </Border>

    <Grid Grid.Row="4">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="330" MinWidth="220"/>
        <ColumnDefinition Width="5"/>
        <ColumnDefinition Width="*" MinWidth="520"/>
      </Grid.ColumnDefinitions>

      <!-- Folder tree -->
      <Grid Grid.Column="0" Margin="12,10,8,10">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <DockPanel Grid.Row="0">
          <Button x:Name="RefreshDrivesBtn" DockPanel.Dock="Right" Style="{StaticResource GhostBtn}" Content="Reload drives"
                  ToolTip="List the drives again, for example after mapping a new one."/>
          <TextBlock Text="FOLDERS" Style="{StaticResource Lbl}" Margin="0" VerticalAlignment="Center"/>
        </DockPanel>
        <Grid Grid.Row="1" Margin="0,8,0,0">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBox x:Name="GoBox" Grid.Column="0" FontFamily="{StaticResource Mono}" ToolTip="Type a folder or share, such as \\fs01\Data, and press Enter."/>
          <Button x:Name="GoBtn" Grid.Column="1" Style="{StaticResource Btn}" Content="Open" Margin="6,0,0,0"/>
        </Grid>
        <TextBlock Grid.Row="2" Style="{StaticResource Hint}" Margin="0,4,0,8"
                   Text="Type a path like \\fs01\Data and press Enter, or pick a drive below. Folders open in the background, so a slow server won't freeze this window."/>
        <!-- Its selection colours are set from the theme by Set-AppTheme. -->
        <TreeView x:Name="FolderTree" Grid.Row="3" Background="{DynamicResource Input}" BorderBrush="{DynamicResource BorderStrong}"
                  Foreground="{DynamicResource Text}" Padding="4"/>
      </Grid>

      <GridSplitter Grid.Column="1" ResizeDirection="Columns" ResizeBehavior="PreviousAndNext"/>

      <Grid Grid.Column="2">
        <!-- Nothing chosen yet -->
        <StackPanel x:Name="EmptyState" VerticalAlignment="Center" HorizontalAlignment="Center" MaxWidth="420">
          <TextBlock Text="&#x1F4C1;" FontFamily="{StaticResource Sym}" FontSize="40" Foreground="{DynamicResource Track}" HorizontalAlignment="Center"/>
          <TextBlock Text="Choose a folder to see who has access" FontSize="15" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}"
                     HorizontalAlignment="Center" Margin="0,10,0,0"/>
          <TextBlock Style="{StaticResource Hint}" TextAlignment="Center" Margin="0,6,0,0"
                     Text="Pick a drive or type a share on the left. You will see who owns the folder, who can open it, and the files inside."/>
        </StackPanel>

        <Grid x:Name="FolderView" Visibility="Collapsed" Margin="16,10,16,10">
          <Grid.RowDefinitions>
            <RowDefinition Height="*" MinHeight="170"/>
            <RowDefinition Height="5"/>
            <RowDefinition Height="*" MinHeight="200"/>
          </Grid.RowDefinitions>

          <!-- Folder permissions -->
          <Grid Grid.Row="0" Margin="0,0,0,8">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="*"/>
              <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            <StackPanel Grid.Row="0">
              <TextBlock x:Name="FolderAclTitle" FontSize="16" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}" TextTrimming="CharacterEllipsis"/>
              <WrapPanel Margin="0,4,0,6">
                <TextBlock Text="Who owns this? " Foreground="{DynamicResource Muted}"/>
                <TextBlock x:Name="OwnerText" Foreground="{DynamicResource TextStrong}" FontWeight="SemiBold" Margin="0,0,18,0"/>
                <TextBlock x:Name="InheritText" Foreground="{DynamicResource Muted}" TextWrapping="Wrap"/>
              </WrapPanel>
            </StackPanel>
            <Border Grid.Row="1" Background="{DynamicResource Card}" BorderBrush="{DynamicResource Border}" BorderThickness="1" CornerRadius="4">
              <Grid>
                <DataGrid x:Name="FolderAclGrid" Style="{StaticResource AclGrid}">
                  <DataGrid.Columns>
                    <DataGridTextColumn Header="User or Group" Binding="{Binding Identity}" Width="2*"/>
                    <DataGridTextColumn Header="Permission Level" Binding="{Binding PermissionLevel}" Width="1.4*"/>
                    <DataGridTextColumn Header="Allow/Deny" Binding="{Binding Type}" Width="100"/>
                    <DataGridTextColumn Header="Inherited" Binding="{Binding InheritedText}" Width="100"/>
                  </DataGrid.Columns>
                </DataGrid>
                <TextBlock x:Name="FolderAclState" Style="{StaticResource PaneState}" Visibility="Collapsed"/>
              </Grid>
            </Border>
            <WrapPanel Grid.Row="2" Margin="0,8,0,0">
              <Button x:Name="AddPermissionBtn" Style="{StaticResource PrimaryBtn}" Margin="0,0,8,6" IsEnabled="False"
                      ToolTipService.ShowOnDisabled="True" ToolTip="Give a user or group access to this folder. Its current permissions are backed up first.">
                <TextBlock><Run Text="+" FontWeight="Bold"/><Run Text="  Add Permission"/></TextBlock>
              </Button>
              <Button x:Name="RemovePermissionBtn" Style="{StaticResource DangerBtn}" Margin="0,0,8,6" IsEnabled="False"
                      ToolTipService.ShowOnDisabled="True" ToolTip="Remove a user or group from this folder. Asks first; its current permissions are backed up first.">
                <TextBlock><Run Text="&#x2212;" FontWeight="Bold"/><Run Text="  Remove Permission"/></TextBlock>
              </Button>
              <Button x:Name="TakeOwnershipBtn" Style="{StaticResource Btn}" Margin="0,0,8,6" IsEnabled="False"
                      ToolTipService.ShowOnDisabled="True" ToolTip="Make yourself the owner of this folder only (not what is in it). Asks first.">
                <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x1F464;"/><Run Text="  Take Ownership (this folder only)"/></TextBlock>
              </Button>
              <Button x:Name="TakeOwnershipTreeBtn" Style="{StaticResource DangerBtn}" Margin="0,0,8,6" IsEnabled="False"
                      ToolTipService.ShowOnDisabled="True" ToolTip="Make yourself the owner of this folder and everything in it. Counts the items and asks first; the current owners are saved first.">
                <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x1F464;"/><Run Text="  Take Ownership of all subfolders and files"/></TextBlock>
              </Button>
              <Button x:Name="CopyPermissionsBtn" Style="{StaticResource Btn}" Margin="0,0,8,6" IsEnabled="False"
                      ToolTipService.ShowOnDisabled="True" ToolTip="Add this folder&apos;s own permissions to other folders. Nothing is removed.">
                <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x2398;"/><Run Text="  Copy Permissions To..."/></TextBlock>
              </Button>
              <Button x:Name="ExportBtn" Style="{StaticResource Btn}" Margin="0,0,8,6"
                      ToolTip="Save the permissions of this folder and all its subfolders to a CSV file.">
                <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x2B73;"/><Run Text="  Export to CSV..."/></TextBlock>
              </Button>
            </WrapPanel>
          </Grid>

          <GridSplitter Grid.Row="1" ResizeDirection="Rows" ResizeBehavior="PreviousAndNext"/>

          <!-- Files and the permissions of the selected files -->
          <Grid Grid.Row="2" Margin="0,10,0,0">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="3*" MinWidth="300"/>
              <ColumnDefinition Width="5"/>
              <ColumnDefinition Width="2*" MinWidth="220"/>
            </Grid.ColumnDefinitions>

            <Grid Grid.Column="0" Margin="0,0,8,0">
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
                <RowDefinition Height="Auto"/>
              </Grid.RowDefinitions>
              <DockPanel Grid.Row="0" Margin="0,0,0,2">
                <CheckBox x:Name="SelectAllCheck" DockPanel.Dock="Right" Content="Select all" IsEnabled="False" VerticalAlignment="Center"/>
                <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                  <TextBlock Text="FILES" Style="{StaticResource Lbl}" Margin="0"/>
                  <TextBlock x:Name="FilesCountText" Foreground="{DynamicResource Muted}" FontSize="11" Margin="8,0,0,0"/>
                </StackPanel>
              </DockPanel>
              <TextBlock x:Name="FilesHint" Grid.Row="1" Style="{StaticResource Hint}" Margin="0,0,0,6"
                         Text="Tick files, or Ctrl-click / Shift-click to select several."/>
              <Border Grid.Row="2" Background="{DynamicResource Card}" BorderBrush="{DynamicResource Border}" BorderThickness="1" CornerRadius="4">
                <Grid>
                  <DataGrid x:Name="FilesGrid" Style="{StaticResource FileGrid}">
                    <DataGrid.Columns>
                      <!-- A tick box per file, bound to the row's selection both ways. The grid's own check box
                           cannot be clicked; this one can, so a tick adds the file to the selection. It takes no
                           Tab stop: the row has the keyboard focus (Space or Ctrl+Space selects). -->
                      <DataGridCheckBoxColumn Width="40" CanUserSort="False" CanUserResize="False"
                                              Binding="{Binding Path=IsSelected, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged, RelativeSource={RelativeSource AncestorType={x:Type DataGridRow}}}">
                        <DataGridCheckBoxColumn.ElementStyle>
                          <Style TargetType="CheckBox" BasedOn="{StaticResource {x:Type CheckBox}}">
                            <Setter Property="IsHitTestVisible" Value="True"/>
                            <Setter Property="Focusable" Value="False"/>
                            <Setter Property="AutomationProperties.Name" Value="Select file"/>
                            <Setter Property="HorizontalAlignment" Value="Center"/>
                            <Setter Property="VerticalAlignment" Value="Center"/>
                          </Style>
                        </DataGridCheckBoxColumn.ElementStyle>
                      </DataGridCheckBoxColumn>
                      <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="2*"/>
                      <DataGridTextColumn Header="Size" Binding="{Binding SizeText}" SortMemberPath="Length" Width="90"/>
                      <DataGridTextColumn Header="Modified" Binding="{Binding Modified}" Width="150"/>
                    </DataGrid.Columns>
                  </DataGrid>
                  <TextBlock x:Name="FilesState" Style="{StaticResource PaneState}" Visibility="Collapsed"/>
                </Grid>
              </Border>
              <Border x:Name="FileActionBar" Grid.Row="3" Visibility="Collapsed" Margin="0,8,0,0" Padding="10,8" CornerRadius="4"
                      Background="{DynamicResource BannerBg}" BorderBrush="{DynamicResource BorderStrong}" BorderThickness="1">
                <StackPanel>
                  <WrapPanel>
                    <TextBlock x:Name="SelectedCountText" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}" VerticalAlignment="Center" Margin="0,0,14,6"/>
                    <Button x:Name="AddFilePermissionBtn" Style="{StaticResource PrimaryBtn}" Margin="0,0,8,6" IsEnabled="False"
                            ToolTipService.ShowOnDisabled="True" ToolTip="Give a user or group access to the selected files. Their current permissions are backed up first.">
                      <TextBlock><Run Text="+" FontWeight="Bold"/><Run Text="  Add Permission"/></TextBlock>
                    </Button>
                    <Button x:Name="RemoveFilePermissionBtn" Style="{StaticResource DangerBtn}" Margin="0,0,8,6" IsEnabled="False"
                            ToolTipService.ShowOnDisabled="True" ToolTip="Remove a user or group from the selected files. Asks first.">
                      <TextBlock><Run Text="&#x2212;" FontWeight="Bold"/><Run Text="  Remove Permission"/></TextBlock>
                    </Button>
                    <Button x:Name="TakeFileOwnershipBtn" Style="{StaticResource Btn}" Margin="0,0,8,6" IsEnabled="False"
                            ToolTipService.ShowOnDisabled="True" ToolTip="Make yourself the owner of the selected files. Asks first.">
                      <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x1F464;"/><Run Text="  Take Ownership"/></TextBlock>
                    </Button>
                  </WrapPanel>
                  <TextBlock x:Name="DiffWarning" Visibility="Collapsed" Foreground="{DynamicResource Warn}" TextWrapping="Wrap"/>
                </StackPanel>
              </Border>
            </Grid>

            <GridSplitter Grid.Column="1" ResizeDirection="Columns" ResizeBehavior="PreviousAndNext"/>

            <Grid Grid.Column="2" Margin="8,0,0,0">
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>
              <TextBlock x:Name="FileAclTitle" Grid.Row="0" Text="WHO HAS ACCESS TO THE SELECTED FILES" Style="{StaticResource Lbl}" Margin="0,4,0,8"
                         TextTrimming="CharacterEllipsis"/>
              <Border Grid.Row="1" Background="{DynamicResource Card}" BorderBrush="{DynamicResource Border}" BorderThickness="1" CornerRadius="4">
                <Grid>
                  <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel x:Name="FileAclPanel" Margin="10"/>
                  </ScrollViewer>
                  <TextBlock x:Name="FileAclState" Style="{StaticResource PaneState}" Text="Select one or more files to see who has access to them."/>
                </Grid>
              </Border>
            </Grid>
          </Grid>
        </Grid>
      </Grid>
    </Grid>

    <!-- Status: the message can be selected and copied -->
    <Border Grid.Row="5" Background="{DynamicResource Panel}" BorderBrush="{DynamicResource Border}" BorderThickness="0,1,0,0" Padding="16,8">
      <TextBox x:Name="StatusText" Style="{StaticResource SelectableText}" Foreground="{DynamicResource Text}" MaxHeight="90"
               VerticalScrollBarVisibility="Auto" Text="Ready. Choose a folder on the left."/>
    </Border>
  </Grid>
</Window>
"@
}

function Get-PermissionDialogXaml {
    # Add and remove permission (folder or selected files). Remove mode hides the level and lists
    # only explicit entries (Show-PermissionDialog). Submit is the default button only for an
    # Allow add (Set-PermissionSubmitStyle).
    $ns = $script:XamlNamespaces
    $res = Get-AppResourcesXaml
    @"
<Window $ns
        Title="Add Permission Entry" Width="520" SizeToContent="Height" ResizeMode="NoResize"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False" FontFamily="Segoe UI" FontSize="13"
        Background="{DynamicResource Bg}" Foreground="{DynamicResource Text}"
        UseLayoutRounding="True" TextOptions.TextFormattingMode="Display">
  <Window.Resources>
$res
  </Window.Resources>
  <StackPanel Margin="20,16,20,16">
    <TextBlock x:Name="PermDialogTitle" Text="Add Permission Entry" FontSize="16" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}"/>
    <TextBox x:Name="PermDialogTarget" Style="{StaticResource SelectableText}" FontFamily="{StaticResource Mono}" FontSize="12"
             Foreground="{DynamicResource Muted}" Margin="0,6,0,0" MaxHeight="90" VerticalScrollBarVisibility="Auto"/>
    <TextBlock Style="{StaticResource Lbl}" Text="USER OR GROUP"/>
    <TextBox x:Name="PermIdentityBox" FontFamily="{StaticResource Mono}"/>
    <ComboBox x:Name="PermIdentityCombo" Visibility="Collapsed"/>
    <TextBlock x:Name="PermIdentityHint" Style="{StaticResource Hint}" Text="For example CONTOSO\HR-Staff."/>
    <TextBlock x:Name="PermRightsLabel" Style="{StaticResource Lbl}" Text="PERMISSION LEVEL"/>
    <ComboBox x:Name="PermRightsCombo" SelectedIndex="1">
      <ComboBoxItem Content="Full Control" Tag="FullControl"/>
      <ComboBoxItem Content="Modify" Tag="Modify"/>
      <ComboBoxItem Content="Read &amp; Execute" Tag="ReadAndExecute"/>
      <ComboBoxItem Content="Read" Tag="Read"/>
      <ComboBoxItem Content="Write" Tag="Write"/>
    </ComboBox>
    <TextBlock Style="{StaticResource Lbl}" Text="ALLOW OR DENY"/>
    <ComboBox x:Name="PermTypeCombo" SelectedIndex="0">
      <ComboBoxItem Content="Allow" Tag="Allow"/>
      <ComboBoxItem Content="Deny" Tag="Deny"/>
    </ComboBox>
    <TextBlock x:Name="PermDialogError" Foreground="{DynamicResource Danger}" TextWrapping="Wrap" Margin="0,10,0,0" Visibility="Collapsed"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,18,0,0">
      <Button x:Name="PermCancelBtn" Style="{StaticResource Btn}" Content="Cancel" IsCancel="True" Margin="0,0,8,0"/>
      <Button x:Name="PermSubmitBtn" Style="{StaticResource PrimaryBtn}" Content="Add Permission" IsDefault="True"/>
    </StackPanel>
  </StackPanel>
</Window>
"@
}

function Get-CopyPermissionsDialogXaml {
    # Copy Permissions To... (adds only, D-031; no recursive option, SQ-015). The list box takes
    # Enter for new lines (AcceptsReturn), so the default button only answers Enter elsewhere.
    $ns = $script:XamlNamespaces
    $res = Get-AppResourcesXaml
    @"
<Window $ns
        Title="Copy Permissions To..." Width="560" SizeToContent="Height" ResizeMode="NoResize"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False" FontFamily="Segoe UI" FontSize="13"
        Background="{DynamicResource Bg}" Foreground="{DynamicResource Text}"
        UseLayoutRounding="True" TextOptions.TextFormattingMode="Display">
  <Window.Resources>
$res
  </Window.Resources>
  <StackPanel Margin="20,16,20,16">
    <TextBlock Text="Copy Permissions To..." FontSize="16" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}"/>
    <TextBlock Style="{StaticResource Lbl}" Text="COPY FROM"/>
    <TextBox x:Name="CopySourceText" Style="{StaticResource SelectableText}" FontFamily="{StaticResource Mono}" FontSize="12"/>
    <TextBlock Margin="0,10,0,0" TextWrapping="Wrap" Text="Adds this folder's own permissions to each folder you list. Nothing is removed."/>
    <TextBlock Style="{StaticResource Hint}" Text="Subfolders that inherit permissions get them too. Subfolders that block inheritance (folders with inheritance turned off) are not changed."/>
    <TextBlock x:Name="CopyDenyNote" Foreground="{DynamicResource Warn}" TextWrapping="Wrap" Margin="0,8,0,0" Visibility="Collapsed"/>
    <TextBlock Style="{StaticResource Lbl}" Text="FOLDERS TO COPY TO (ONE PER LINE)"/>
    <TextBox x:Name="CopyTargetsBox" FontFamily="{StaticResource Mono}" AcceptsReturn="True" TextWrapping="NoWrap" Height="120"
             VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"/>
    <TextBlock x:Name="CopyError" Foreground="{DynamicResource Danger}" TextWrapping="Wrap" Margin="0,10,0,0" Visibility="Collapsed"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,18,0,0">
      <Button x:Name="CopyCancelBtn" Style="{StaticResource Btn}" Content="Cancel" IsCancel="True" Margin="0,0,8,0"/>
      <Button x:Name="CopySubmitBtn" Style="{StaticResource PrimaryBtn}" Content="Copy Permissions" IsDefault="True"/>
    </StackPanel>
  </StackPanel>
</Window>
"@
}

function Get-ConfirmDialogXaml {
    # Asks before a destructive change: names the path(s) and how many items; Cancel is the
    # default and the action button carries a verb (Set-ConfirmDialog, Show-ConfirmDialog).
    $ns = $script:XamlNamespaces
    $res = Get-AppResourcesXaml
    @"
<Window $ns
        Title="Check before you go ahead" Width="560" SizeToContent="Height" ResizeMode="NoResize"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False" FontFamily="Segoe UI" FontSize="13"
        Background="{DynamicResource Bg}" Foreground="{DynamicResource Text}"
        UseLayoutRounding="True" TextOptions.TextFormattingMode="Display">
  <Window.Resources>
$res
  </Window.Resources>
  <StackPanel Margin="20,16,20,16">
    <TextBlock x:Name="ConfirmTitle" FontSize="16" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}" TextWrapping="Wrap"/>
    <TextBox x:Name="ConfirmBody" Style="{StaticResource SelectableText}" Margin="0,10,0,0" MaxHeight="320"
             VerticalScrollBarVisibility="Auto" Foreground="{DynamicResource Text}"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,18,0,0">
      <Button x:Name="ConfirmCancelBtn" Style="{StaticResource Btn}" Content="Cancel" IsDefault="True" IsCancel="True" Margin="0,0,8,0"/>
      <Button x:Name="ConfirmActionBtn" Style="{StaticResource Btn}"/>
    </StackPanel>
  </StackPanel>
</Window>
"@
}

function Set-ThemeBrushes {
    # Puts a palette's brushes into a window's resources (the main window, or a dialog so it
    # opens in the theme the main window has).
    param([Parameter(Mandatory)]$Resources, [Parameter(Mandatory)][ValidateSet('Dark', 'Light')][string]$Name)
    $palette = $script:Themes[$Name]
    foreach ($key in $palette.Keys) {
        $brush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($palette[$key]))
        $brush.Freeze()
        $Resources[$key] = $brush
    }
}

function Set-AppTheme {
    # Every colour is a DynamicResource, so replacing the brushes recolours the window in place.
    param([Parameter(Mandatory)][ValidateSet('Dark', 'Light')][string]$Name)
    $palette = $script:Themes[$Name]
    Set-ThemeBrushes -Resources $script:Window.Resources -Name $Name
    $script:CurrentTheme = $Name
    if ($script:UI -and $script:UI.ThemeToggle) { $script:UI.ThemeToggle.Content = Get-ThemeToggleText -Current $Name }
    if ($script:UI -and $script:UI.FolderTree) {
        # The tree's default item template draws selection with these system brush keys; they
        # are replaced with the theme's selection colours (active and inactive look the same).
        $sel = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($palette.SelBg))
        $selText = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($palette.SelText))
        $sel.Freeze()
        $selText.Freeze()
        $res = $script:UI.FolderTree.Resources
        $res[[System.Windows.SystemColors]::HighlightBrushKey] = $sel
        $res[[System.Windows.SystemColors]::HighlightTextBrushKey] = $selText
        $res[[System.Windows.SystemColors]::InactiveSelectionHighlightBrushKey] = $sel
        $res[[System.Windows.SystemColors]::InactiveSelectionHighlightTextBrushKey] = $selText
    }
}

#endregion

#region Window behaviour (runs on the UI thread)

function Set-Status {
    # The status line: colour by kind; the text can be selected and copied.
    param([Parameter(Mandatory)][string]$Text, [ValidateSet('Info', 'Success', 'Warning', 'Error')][string]$Kind = 'Info')
    if (-not ($script:UI -and $script:UI.StatusText)) { return }
    $key = @{ Info = 'Text'; Success = 'Ok'; Warning = 'Warn'; Error = 'Danger' }[$Kind]
    $box = $script:UI.StatusText
    $box.Text = Get-StatusText -Text $Text -Kind $Kind
    $box.SetResourceReference([System.Windows.Controls.Control]::ForegroundProperty, $key)
    if ($script:StatusIsLiveRegion) { Send-LiveRegionChanged -Element $box }
}

function Get-BusyLineEntry {
    # The entry the busy line shows: the running change when there is one (it matters most and
    # must not hide behind reads), otherwise the newest read. $null when nothing runs.
    param([System.Collections.IDictionary]$Entries, [string]$ChangeKey)
    if (-not $Entries -or $Entries.Count -eq 0) { return $null }
    if ($ChangeKey -and $Entries.Contains($ChangeKey)) { return $Entries[$ChangeKey] }
    @($Entries.Values)[$Entries.Count - 1]
}

function Set-PaneStateView {
    # Shows a pane's loading, empty or error text over the pane; hides it once loaded.
    param([Parameter(Mandatory)]$Target, [Parameter(Mandatory)]$State)
    if ($State.State -eq 'Loaded') { $Target.Visibility = 'Collapsed'; return }
    $Target.Text = $State.Text
    $key = if ($State.State -eq 'Error') { 'Danger' } else { 'Muted' }
    $Target.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, $key)
    $Target.Visibility = 'Visible'
}

function Update-BusyLine {
    # The running change, or else the newest running read, with its elapsed time; hidden when
    # nothing runs.
    if (-not ($script:UI -and $script:UI.BusyBar)) { return }
    $count = $script:BusyEntries.Count
    $changeKey = if ($script:ChangeTask) { "$($script:ChangeTask.Key)" } else { $null }
    $shown = Get-BusyLineEntry -Entries $script:BusyEntries -ChangeKey $changeKey
    if (-not $shown) { $script:UI.BusyBar.Visibility = 'Collapsed'; return }
    $line = Get-BusyLine -Action $shown.Action -Path $shown.Path -Elapsed ([DateTime]::UtcNow - $shown.Started)
    if ($count -gt 1) { $line += "  (and $($count - 1) more)" }
    $script:UI.BusyText.Text = $line
    $script:UI.BusyBar.Visibility = 'Visible'
}

function Start-ReadTask {
    # A background read that shows on the busy line until its result has been shown.
    param(
        [Parameter(Mandatory)][string]$Action,
        [string]$Path,
        [Parameter(Mandatory)][scriptblock]$Work,
        [object[]]$ArgumentList,
        [Parameter(Mandatory)][scriptblock]$OnDone,
        $State
    )
    # Every way out calls OnDone exactly once with a result (a failed one if need be), so no
    # pane is left on "Loading..." and the busy line is always cleared.
    $key = [guid]::NewGuid().ToString('N')
    $script:BusyEntries[$key] = [PSCustomObject]@{ Action = $Action; Path = $Path; Started = [DateTime]::UtcNow }
    Update-BusyLine
    $taskState = @{ Key = $key; OnDone = $OnDone; State = $State; Action = $Action; Path = $Path }
    $finish = {
        param($result, $s)
        $script:BusyEntries.Remove($s.Key)
        try { & $s.OnDone $result $s.State }
        catch {
            # Showing the result failed: say so, and let the same callback put its pane into
            # its Failed state with that error.
            $why = "$($_.Exception.Message)"
            Write-AppError "Showing the result of '$($s.Action) $($s.Path)': $why"
            Set-Status -Kind Error -Text "Something went wrong while showing the result ($($s.Action) $($s.Path)): $why Press Refresh to try again."
            try { & $s.OnDone ([PSCustomObject]@{ Ok = $false; Path = $s.Path; Error = $why }) $s.State }
            catch { Write-AppError "Showing the failure of '$($s.Action) $($s.Path)': $($_.Exception.Message)" }
        }
        finally { Update-BusyLine }
    }
    try {
        Start-BgTask -Work $Work -ArgumentList $ArgumentList -State $taskState -OnDone $finish
    }
    catch {
        $why = "Could not start in the background: $(Get-InnermostErrorText $_)"
        Write-AppError "Starting '$Action $Path': $why"
        $null = & $finish ([PSCustomObject]@{ Ok = $false; Path = $Path; Error = $why }) $taskState
        return $null
    }
}

function New-TreeInfoItem {
    # A line in the tree that is not a folder: "Loading...", "No subfolders", an error.
    param([Parameter(Mandatory)][string]$Text, [string]$ColorKey = 'Muted')
    $i = [System.Windows.Controls.TreeViewItem]::new()
    $tb = [System.Windows.Controls.TextBlock]::new()
    $tb.Text = $Text
    $tb.TextWrapping = 'Wrap'
    $tb.MaxWidth = 420
    $i.Header = $tb
    $i.IsEnabled = $false
    $i.Focusable = $false
    $i.SetResourceReference([System.Windows.Controls.Control]::ForegroundProperty, $ColorKey)
    $i
}

function New-FolderNode {
    # Every folder gets an expander until it turns out to have no subfolders (as Explorer does
    # on network paths), instead of opening each child just to find out.
    param([Parameter(Mandatory)]$Parent, [Parameter(Mandatory)][string]$Label, [Parameter(Mandatory)][string]$Path, [string]$Icon)
    if (-not $Icon) { $Icon = [char]::ConvertFromUtf32(0x1F4C1) }
    $item = [System.Windows.Controls.TreeViewItem]::new()
    $sp = [System.Windows.Controls.StackPanel]::new()
    $sp.Orientation = 'Horizontal'
    $ic = [System.Windows.Controls.TextBlock]::new()
    $ic.Text = $Icon
    $ic.SetResourceReference([System.Windows.Controls.TextBlock]::FontFamilyProperty, 'Sym')
    $ic.Margin = [System.Windows.Thickness]::new(0, 0, 6, 0)
    $tx = [System.Windows.Controls.TextBlock]::new()
    $tx.Text = $Label
    [void]$sp.Children.Add($ic)
    [void]$sp.Children.Add($tx)
    $item.Header = $sp
    $item.ToolTip = $Path
    $item.Tag = [PSCustomObject]@{ Path = $Path; State = 'NotLoaded' }
    $item.SetResourceReference([System.Windows.Controls.Control]::ForegroundProperty, 'Text')
    $item.Padding = [System.Windows.Thickness]::new(2, 3, 2, 3)
    [void]$item.Items.Add((New-TreeInfoItem -Text 'Loading...'))
    [void]$Parent.Items.Add($item)
    $item
}

function Expand-FolderNode {
    # Lists a folder's subfolders in the background the first time it is expanded.
    param($Node)
    if (-not ($Node -is [System.Windows.Controls.TreeViewItem]) -or -not $Node.Tag -or $Node.Tag.State -ne 'NotLoaded') { return }
    $Node.Tag.State = 'Loading'
    $real = Resolve-MappedDrive -Path $Node.Tag.Path -DriveMap $script:MappedDrives
    [void](Start-ReadTask -Action 'Opening folder' -Path $Node.Tag.Path -Work $script:ListChildrenWork -ArgumentList @($real, $script:CorePath) -State $Node -OnDone {
            param($result, $node)
            Set-FolderNodeChildren -Node $node -Result $result
        })
}

function Set-FolderNodeChildren {
    param([Parameter(Mandatory)]$Node, [AllowNull()]$Result)
    $Node.Items.Clear()
    if (-not ($Result -and $Result.Ok)) {
        $Node.Tag.State = 'Failed'
        $err = if ($Result) { "$($Result.Error)" } else { '' }
        $state = Get-PaneState -Pane TreeNode -Phase Failed -ErrorText $err
        [void]$Node.Items.Add((New-TreeInfoItem -Text $state.Text -ColorKey 'Danger'))
        return
    }
    $Node.Tag.State = 'Loaded'
    # No subfolders: the node keeps no children, so its expander disappears.
    foreach ($c in @($Result.Children)) {
        [void](New-FolderNode -Parent $Node -Label $c.Name -Path (Join-DisplayPath -Parent $Node.Tag.Path -Name $c.Name))
    }
}

function Update-DriveList {
    $tree = $script:UI.FolderTree
    $tree.Items.Clear()
    [void]$tree.Items.Add((New-TreeInfoItem -Text 'Loading drives...'))
    [void](Start-ReadTask -Action 'Loading the drive list' -Work $script:DrivesWork -ArgumentList @($script:MappedDrives, $script:CorePath) -OnDone {
            param($result, $s)
            $tree = $script:UI.FolderTree
            $tree.Items.Clear()
            if (-not ($result -and $result.Ok)) {
                $text = if ($result -and $result.Error) { $result.Error } else { 'The drives could not be listed.' }
                [void]$tree.Items.Add((New-TreeInfoItem -Text $text -ColorKey 'Danger'))
                Set-Status -Text "$text Type a path above instead, or press Reload drives." -Kind Error
                return
            }
            foreach ($d in @($result.Drives)) {
                $icon = if ($d.IsMapped) { [char]::ConvertFromUtf32(0x1F5A7) } else { [string][char]0x25A3 }
                [void](New-FolderNode -Parent $tree -Label $d.Label -Path $d.Root -Icon $icon)
            }
        })
}

function Open-TypedPath {
    $p = $script:UI.GoBox.Text.Trim().Trim('"')
    if (-not $p) { return }
    $tree = $script:UI.FolderTree
    $node = $null
    foreach ($i in $tree.Items) {
        if ($i -is [System.Windows.Controls.TreeViewItem] -and $i.Tag -and [string]::Equals($i.Tag.Path, $p, [StringComparison]::OrdinalIgnoreCase)) { $node = $i; break }
    }
    if (-not $node) {
        $node = New-FolderNode -Parent $tree -Label $p -Path $p
        $tree.Items.Remove($node)
        $tree.Items.Insert(0, $node)
    }
    $node.IsSelected = $true
    $node.IsExpanded = $true
    $node.BringIntoView()
}

function Select-Folder {
    # Shows a folder: the path header, then its permissions and files, loaded in the background.
    param([Parameter(Mandatory)]$Node)
    $ui = $script:UI
    $display = $Node.Tag.Path
    $real = Resolve-MappedDrive -Path $display -DriveMap $script:MappedDrives
    $script:CurrentNode = $Node
    $script:Current = [PSCustomObject]@{ DisplayPath = $display; RealPath = $real }
    Update-ChangeControls

    $header = Get-PathHeaderModel -Path $display -DriveMap $script:MappedDrives -DriveMapSource $script:MappedDriveSources
    $ui.PathText.Text = $header.Path
    if ($header.RealPath) {
        $ui.RealPathText.Text = $header.RealPath
        $ui.RealPathNote.Text = $header.RealPathNote
        $ui.RealPathNote.Visibility = if ($header.RealPathNote) { 'Visible' } else { 'Collapsed' }
        $ui.RealPathText.Visibility = 'Visible'
        $ui.RealPathLabel.Visibility = 'Visible'
    }
    else {
        $ui.RealPathText.Visibility = 'Collapsed'
        $ui.RealPathNote.Visibility = 'Collapsed'
        $ui.RealPathLabel.Visibility = 'Collapsed'
    }
    $ui.RefreshBtn.IsEnabled = $true
    $ui.EmptyState.Visibility = 'Collapsed'
    $ui.FolderView.Visibility = 'Visible'
    $ui.FolderAclTitle.Text = "Folder permissions: $(Get-PathLeaf $display)"
    $ui.OwnerText.Text = '...'
    $ui.InheritText.Text = ''
    $ui.FolderAclGrid.ItemsSource = $null
    Set-PaneStateView -Target $ui.FolderAclState -State (Get-PaneState -Pane FolderPermissions -Phase Loading)

    $ui.FilesGrid.ItemsSource = $null
    $ui.FilesCountText.Text = ''
    $ui.SelectAllCheck.IsChecked = $false
    $ui.SelectAllCheck.IsEnabled = $false
    $script:FileAclCache = @{}
    $script:FileAclPending = @{}
    Set-PaneStateView -Target $ui.FilesState -State (Get-PaneState -Pane Files -Phase Loading)
    Update-FileSelection

    $aclRequest = New-PaneRequest -Pane 'FolderPermissions'
    [void](Start-ReadTask -Action 'Loading the permissions of' -Path $display -Work $script:FolderAclWork -ArgumentList @($real, $script:CorePath) -State $aclRequest -OnDone {
            param($result, $request)
            [void](Set-FolderPermissionsResult -Result $result -Request $request)
        })
    $filesRequest = New-PaneRequest -Pane 'Files'
    [void](Start-ReadTask -Action 'Listing the files in' -Path $display -Work $script:FilesWork -ArgumentList @($real, $script:CorePath) -State $filesRequest -OnDone {
            param($result, $request)
            [void](Set-FilesResult -Result $result -Request $request)
        })
}

function Reset-FolderNode {
    # Lists a tree entry's subfolders again: now if it is open, else when it is next opened.
    param([Parameter(Mandatory)]$Node)
    if (-not $Node.Tag -or $Node.Tag.State -eq 'NotLoaded' -or $Node.Tag.State -eq 'Loading') { return }
    $Node.Items.Clear()
    [void]$Node.Items.Add((New-TreeInfoItem -Text 'Loading...'))
    $Node.Tag.State = 'NotLoaded'
    if ($Node.IsExpanded) { Expand-FolderNode -Node $Node }
}

function Update-CurrentFolder {
    # Refresh: read the current folder's subfolders, permissions and files again.
    $node = $script:CurrentNode
    if (-not $node) { return }
    Reset-FolderNode -Node $node
    Select-Folder -Node $node
}

function Show-FolderPermissions {
    if (-not ($script:UI -and $script:UI.FolderAclGrid)) { return }
    $ui = $script:UI
    $v = $script:ViewState.FolderPermissions
    if (-not $v) { return }
    if (-not $v.Ok) {
        $ui.FolderAclGrid.ItemsSource = $null
        $ui.OwnerText.Text = 'could not be read'
        $ui.InheritText.Text = ''
        Set-PaneStateView -Target $ui.FolderAclState -State (Get-PaneState -Pane FolderPermissions -Phase Failed -ErrorText $v.Error)
        return
    }
    $ui.OwnerText.Text = $v.Owner
    $ui.InheritText.Text = if ($v.AreAccessRulesProtected) {
        'Inheritance is turned off: this folder does not get the permissions of the folder above it.'
    }
    else {
        'Also gets the permissions of the folder above it (shown as Inherited).'
    }
    $rows = @($v.Rows)
    $ui.FolderAclGrid.ItemsSource = $rows
    Set-PaneStateView -Target $ui.FolderAclState -State (Get-PaneState -Pane FolderPermissions -Phase Loaded -Count $rows.Count)
}

function Show-Files {
    if (-not ($script:UI -and $script:UI.FilesGrid)) { return }
    $ui = $script:UI
    $v = $script:ViewState.Files
    if (-not $v) { return }
    if (-not $v.Ok) {
        $ui.FilesGrid.ItemsSource = $null
        $ui.FilesCountText.Text = ''
        $ui.SelectAllCheck.IsEnabled = $false
        Set-PaneStateView -Target $ui.FilesState -State (Get-PaneState -Pane Files -Phase Failed -ErrorText $v.Error)
        Update-FileSelection
        return
    }
    $rows = @($v.Rows)
    $ui.FilesGrid.ItemsSource = $rows
    $ui.FilesCountText.Text = if ($rows.Count -eq 1) { '1 file' } else { "$($rows.Count) files" }
    $ui.SelectAllCheck.IsEnabled = $rows.Count -gt 0
    Set-PaneStateView -Target $ui.FilesState -State (Get-PaneState -Pane Files -Phase Loaded -Count $rows.Count)
    Update-FileSelection
}

function Get-SelectedFileRows {
    if (-not ($script:UI -and $script:UI.FilesGrid)) { return @() }
    @($script:UI.FilesGrid.SelectedItems | ForEach-Object { $_ })
}

function Update-FileSelection {
    # The "N file(s) selected" bar, Select all, and the permissions of the selected files
    # (loaded in the background, at most $script:MaxFileAclAutoLoad at a time).
    if (-not ($script:UI -and $script:UI.FilesGrid)) { return }
    $ui = $script:UI
    $selected = @(Get-SelectedFileRows)
    $total = @($ui.FilesGrid.Items).Count
    $ui.SelectedCountText.Text = if ($selected.Count -eq 1) { '1 file selected' } else { "$($selected.Count) files selected" }
    $ui.FileActionBar.Visibility = if ($selected.Count -gt 0) { 'Visible' } else { 'Collapsed' }
    $ui.SelectAllCheck.IsChecked = ($total -gt 0 -and $selected.Count -eq $total)

    $missing = @($selected | Where-Object { -not $script:FileAclCache.ContainsKey($_.Path) -and -not $script:FileAclPending.ContainsKey($_.Path) } |
            Select-Object -First $script:MaxFileAclAutoLoad | ForEach-Object { $_.Path })
    if ($missing.Count -gt 0 -and $script:Current) {
        foreach ($p in $missing) { $script:FileAclPending[$p] = $true }
        $request = [int]$script:PaneRequests['Files']
        $label = if ($missing.Count -eq 1) { "1 file in $($script:Current.DisplayPath)" } else { "$($missing.Count) files in $($script:Current.DisplayPath)" }
        [void](Start-ReadTask -Action 'Loading the permissions of' -Path $label -Work $script:FileAclWork -ArgumentList @([string[]]$missing, $script:CorePath) `
                -State @{ Request = $request; Paths = [string[]]$missing } -OnDone {
                param($result, $s)
                [void](Set-FileAclResult -Result $result -Request $s.Request -Paths $s.Paths)
            })
    }
    Show-FileDetails
}

function New-FileAclCard {
    # One selected file: its name, owner and permission entries (or loading / error).
    param([Parameter(Mandatory)]$Row, $Model)
    $card = [System.Windows.Controls.Border]::new()
    $card.BorderThickness = [System.Windows.Thickness]::new(0, 0, 0, 1)
    $card.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, 'Border')
    $card.Padding = [System.Windows.Thickness]::new(0, 6, 0, 8)
    $sp = [System.Windows.Controls.StackPanel]::new()
    $card.Child = $sp
    $add = {
        param([string]$Text, [string]$Key, [bool]$Bold = $false, [bool]$Mono = $false)
        $tb = [System.Windows.Controls.TextBlock]::new()
        $tb.Text = $Text
        $tb.TextWrapping = 'Wrap'
        $tb.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, $Key)
        if ($Bold) { $tb.FontWeight = 'SemiBold' }
        if ($Mono) { $tb.SetResourceReference([System.Windows.Controls.TextBlock]::FontFamilyProperty, 'Mono') }
        [void]$sp.Children.Add($tb)
    }
    & $add $Row.Name 'TextStrong' $true
    if (-not $Model) {
        & $add (Get-PaneState -Pane FilePermissions -Phase Loading).Text 'Muted'
        return $card
    }
    if (-not $Model.Ok) {
        & $add (Get-PaneState -Pane FilePermissions -Phase Failed -ErrorText $Model.Error).Text 'Danger'
        return $card
    }
    & $add "Who owns this? $($Model.Owner)" 'Muted'
    if ($Model.AreAccessRulesProtected) { & $add 'Inheritance is turned off for this file.' 'Muted' }
    $rows = @($Model.Rows)
    if ($rows.Count -eq 0) {
        & $add (Get-PaneState -Pane FilePermissions -Phase Loaded -Count 0).Text 'Muted'
        return $card
    }
    foreach ($r in $rows) {
        $inherited = if ($r.IsInherited) { '  (inherited)' } else { '' }
        $key = if ($r.Type -eq 'Deny') { 'Danger' } else { 'Text' }
        & $add ('{0,-5} {1,-15} {2}{3}' -f $r.Type, $r.PermissionLevel, $r.Identity, $inherited) $key $false $true
    }
    $card
}

function Show-FileDetails {
    if (-not ($script:UI -and $script:UI.FileAclPanel)) { return }
    $ui = $script:UI
    $selected = @(Get-SelectedFileRows)
    $ui.FileAclPanel.Children.Clear()
    if ($selected.Count -eq 0) {
        $ui.FileAclTitle.Text = 'WHO HAS ACCESS TO THE SELECTED FILES'
        $ui.FileAclState.Text = 'Select one or more files to see who has access to them.'
        $ui.FileAclState.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'Muted')
        $ui.FileAclState.Visibility = 'Visible'
        $ui.DiffWarning.Visibility = 'Collapsed'
        return
    }
    $ui.FileAclState.Visibility = 'Collapsed'
    $shown = @($selected | Select-Object -First $script:MaxFileDetails)
    $ui.FileAclTitle.Text = if ($selected.Count -gt $shown.Count) {
        "WHO HAS ACCESS (FIRST $($shown.Count) OF $($selected.Count) SELECTED FILES)"
    }
    else { 'WHO HAS ACCESS TO THE SELECTED FILES' }
    foreach ($row in $shown) {
        $model = $script:FileAclCache[$row.Path]
        [void]$ui.FileAclPanel.Children.Add((New-FileAclCard -Row $row -Model $model))
    }
    $models = @($selected | ForEach-Object { $script:FileAclCache[$_.Path] } | Where-Object { $_ -and $_.Ok })
    if (Test-FileAclDiffers -Model $models) {
        $ui.DiffWarning.Text = Get-FileAclDiffWarningText -Checked $models.Count -Selected $selected.Count
        $ui.DiffWarning.Visibility = 'Visible'
    }
    else { $ui.DiffWarning.Visibility = 'Collapsed' }
}

function Start-PermissionExport {
    # Save dialog, then the report for the folder and all its subfolders in the background.
    if (-not $script:Current) { Set-Status -Text 'Choose a folder first, then export its permissions.' -Kind Warning; return }
    if ($script:ExportTask) { Set-Status -Text 'An export is already running. Wait for it to finish, or stop it.' -Kind Warning; return }
    $display = $script:Current.DisplayPath
    $real = $script:Current.RealPath
    # https://learn.microsoft.com/dotnet/api/microsoft.win32.savefiledialog
    $dlg = [Microsoft.Win32.SaveFileDialog]::new()
    $dlg.Title = "Save the permission report for $display"
    $dlg.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
    $dlg.DefaultExt = '.csv'
    $dlg.AddExtension = $true
    $dlg.OverwritePrompt = $true
    # Documents only when it is this computer's own disk and not synced to OneDrive; otherwise
    # a local Exports folder (created here, so the dialog can open in it).
    $start = Get-DefaultExportFolder
    if (-not (Test-Path -LiteralPath $start -PathType Container)) {
        try { New-Item -ItemType Directory -Path $start -Force -WhatIf:$false -ErrorAction Stop | Out-Null }
        catch { Write-AppError "Could not create the export folder ${start}: $($_.Exception.Message)" }
    }
    $dlg.InitialDirectory = $start
    $dlg.FileName = Get-DefaultExportFileName -Path $display
    if (-not $dlg.ShowDialog($script:Window)) { return }
    $out = $dlg.FileName
    # A share, a mapped, network or removable drive, or OneDrive: warn and ask first.
    if (-not (Confirm-ExportLocation -Path $out)) {
        Set-Status -Text "Export cancelled: nothing was saved to $out." -Kind Info
        return
    }

    $where = Get-ExportLocationInfo -Path $out -DriveMap $script:MappedDrives
    $script:UI.ExportBtn.IsEnabled = $false
    $script:UI.StopExportBtn.Visibility = 'Visible'
    if ($where.IsLocal) { Set-Status -Text "Exporting the permissions of $display and all its subfolders to $out..." -Kind Info }
    else { Set-Status -Text "Exporting the permissions of $display and all its subfolders to $out... $($where.Warning)" -Kind Warning }
    $script:ExportTask = Start-ReadTask -Action 'Exporting the permissions (with all subfolders) of' -Path $display -Work $script:ExportWork `
        -ArgumentList @($real, $out, $script:CorePath) -State @{ Display = $display; Out = $out } -OnDone {
        param($result, $s)
        $script:ExportTask = $null
        $script:UI.ExportBtn.IsEnabled = $true
        $script:UI.StopExportBtn.Visibility = 'Collapsed'
        if ($result -and $result.Ok) {
            Set-Status -Text ("Exported $($result.RowCount) permission row(s) for $($s.Display) and its subfolders to $($result.OutputPath). " +
                'It holds client folder paths, owners and account names: attach it to the ticket, then delete it.') -Kind Success
        }
        elseif ($result -and $result.Stopped) {
            Set-Status -Text "Export stopped. If $($s.Out) was created, it is incomplete: delete it or export again." -Kind Warning
        }
        else {
            $err = if ($result -and $result.Error) { $result.Error } else { 'No reason was given.' }
            Set-Status -Text "The export did not finish. $err" -Kind Error
        }
    }
}

function Stop-PermissionExport {
    if ($script:ExportTask) {
        Stop-BgTask -Task $script:ExportTask
        Set-Status -Text 'Stopping the export...' -Kind Info
    }
}

function Open-LogFolder {
    $folder = $script:ChangeLogFolder
    if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
        Set-Status -Text "The log folder $folder does not exist yet: nothing has been backed up or logged there. It is created when the first change is backed up." -Kind Info
        return
    }
    try { Start-Process -FilePath 'explorer.exe' -ArgumentList (ConvertTo-QuotedArgument $folder) -ErrorAction Stop }
    catch { Set-Status -Text "Could not open $folder in Explorer: $($_.Exception.Message)" -Kind Error }
}

function Show-Banner {
    param([object[]]$Rows)
    $panel = $script:UI.BannerPanel
    $panel.Children.Clear()
    foreach ($r in $Rows) {
        $tb = [System.Windows.Controls.TextBlock]::new()
        $tb.Text = $r.Text
        $tb.TextWrapping = 'Wrap'
        $key = if ($r.Level -eq 'Warning') { 'Warn' } else { 'Text' }
        $tb.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, $key)
        $tb.Margin = [System.Windows.Thickness]::new(0, 1, 0, 1)
        [void]$panel.Children.Add($tb)
    }
}

function Invoke-Tick {
    try { Update-BgTasks } catch { Write-AppError "Tick: $($_.Exception.Message)" }
    try { Update-BusyLine } catch { Write-AppError "Busy line: $($_.Exception.Message)" }
}

function Hide-OwnConsole {
    # Double-clicking the script opens a console just for it; hide that so only the window
    # shows. A console shared with other processes (someone's open terminal) is left alone.
    try {
        if (-not ('FolderPermissionManager.AppConsoleWin' -as [type])) {
            Add-Type -Namespace FolderPermissionManager -Name AppConsoleWin -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("kernel32.dll")] public static extern uint GetConsoleProcessList(uint[] list, uint count);
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
'@
        }
        $list = New-Object uint32[] 8
        $count = [FolderPermissionManager.AppConsoleWin]::GetConsoleProcessList($list, 8)
        $hwnd = [FolderPermissionManager.AppConsoleWin]::GetConsoleWindow()
        if ($count -le 1 -and $hwnd -ne [IntPtr]::Zero) {
            # SW_HIDE (0). https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-showwindow
            [void][FolderPermissionManager.AppConsoleWin]::ShowWindow($hwnd, 0)
            $script:HiddenConsole = $hwnd
        }
    }
    catch { }
}

function Show-OwnConsole {
    # Shows the console Hide-OwnConsole hid, so a wait after the window has gone (a change still
    # finishing) is visible instead of a process running with nothing on screen. SW_SHOW (5).
    # https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-showwindow
    if (-not $script:HiddenConsole) { return }
    try { [void][FolderPermissionManager.AppConsoleWin]::ShowWindow($script:HiddenConsole, 5) } catch { }
}

function Initialize-PermissionWindow {
    # Builds the main window and wires its events; nothing is shown.
    $win = [System.Windows.Markup.XamlReader]::Parse((Get-MainWindowXaml))
    $script:Window = $win
    $script:UI = @{}
    $names = 'ThemeToggle', 'OpenLogFolderBtn', 'DryRunPill', 'BannerPanel', 'PathText', 'RealPathLabel', 'RealPathText', 'RealPathNote',
    'RefreshBtn', 'BusyBar', 'BusyText', 'BusyProgress', 'StopExportBtn', 'RefreshDrivesBtn', 'GoBox', 'GoBtn', 'FolderTree',
    'EmptyState', 'FolderView', 'FolderAclTitle', 'OwnerText', 'InheritText', 'FolderAclGrid', 'FolderAclState',
    'AddPermissionBtn', 'RemovePermissionBtn', 'TakeOwnershipBtn', 'TakeOwnershipTreeBtn', 'CopyPermissionsBtn', 'ExportBtn',
    'SelectAllCheck', 'FilesCountText', 'FilesGrid', 'FilesState', 'FileActionBar', 'SelectedCountText',
    'AddFilePermissionBtn', 'RemoveFilePermissionBtn', 'TakeFileOwnershipBtn', 'DiffWarning',
    'FileAclTitle', 'FileAclPanel', 'FileAclState', 'StatusText'
    foreach ($n in $names) {
        $script:UI[$n] = $win.FindName($n)
        if ($null -eq $script:UI[$n]) { throw "XAML element '$n' not found." }
    }
    $ui = $script:UI

    # Fit smaller screens.
    $wa = [System.Windows.SystemParameters]::WorkArea
    if ($win.Height -gt $wa.Height - 20) { $win.Height = [Math]::Max($win.MinHeight, $wa.Height - 20) }
    if ($win.Width -gt $wa.Width - 20) { $win.Width = [Math]::Max($win.MinWidth, $wa.Width - 20) }

    Set-AppTheme -Name (Get-SavedTheme -SettingsPath $script:SettingsPath)
    try { $script:StatusIsLiveRegion = Enable-LiveRegion -Element $ui.StatusText } catch { $script:StatusIsLiveRegion = $false }
    Show-Banner -Rows (Get-LogFolderBanner -LogFolder $script:ChangeLogFolder -Notice $script:LogFolderNotice -WhatIfMode:$script:WhatIfMode)
    if ($script:WhatIfMode) { $ui.DryRunPill.Visibility = 'Visible' }

    # --- Events ---
    $ui.ThemeToggle.Add_Click({
            $next = if ($script:CurrentTheme -eq 'Dark') { 'Light' } else { 'Dark' }
            Set-AppTheme -Name $next
            Set-SavedTheme -Theme $next -SettingsPath $script:SettingsPath
        })
    $ui.OpenLogFolderBtn.Add_Click({ Open-LogFolder })
    $ui.RefreshDrivesBtn.Add_Click({ Update-DriveList })
    $ui.GoBtn.Add_Click({ Open-TypedPath })
    $ui.GoBox.Add_KeyDown({ param($s, $e) if ($e.Key -eq 'Return') { Open-TypedPath; $e.Handled = $true } })
    $ui.RefreshBtn.Add_Click({ Update-CurrentFolder })
    $ui.ExportBtn.Add_Click({ Start-PermissionExport })
    $ui.StopExportBtn.Add_Click({ Stop-PermissionExport })
    # The changes. Each click first works out in the background where the change would land
    # (Open-*: never on this thread), then asks where it must, then runs it, one at a time.
    $ui.AddPermissionBtn.Add_Click({ Invoke-UiAction { Open-AddPermission -Scope Folder } })
    $ui.RemovePermissionBtn.Add_Click({ Invoke-UiAction { Open-RemovePermission -Scope Folder } })
    $ui.TakeOwnershipBtn.Add_Click({ Invoke-UiAction { Open-TakeOwnership -Scope Folder } })
    $ui.TakeOwnershipTreeBtn.Add_Click({ Invoke-UiAction { Open-TakeOwnership -Scope Tree } })
    $ui.CopyPermissionsBtn.Add_Click({ Invoke-UiAction { Open-CopyPermissions } })
    $ui.AddFilePermissionBtn.Add_Click({ Invoke-UiAction { Open-AddPermission -Scope Files } })
    $ui.RemoveFilePermissionBtn.Add_Click({ Invoke-UiAction { Open-RemovePermission -Scope Files } })
    $ui.TakeFileOwnershipBtn.Add_Click({ Invoke-UiAction { Open-TakeOwnership -Scope Files } })
    Update-ChangeControls
    $ui.FolderTree.AddHandler([System.Windows.Controls.TreeViewItem]::ExpandedEvent, [System.Windows.RoutedEventHandler] {
            param($s, $e)
            Expand-FolderNode -Node $e.OriginalSource
        })
    $ui.FolderTree.Add_SelectedItemChanged({
            param($s, $e)
            $item = $s.SelectedItem
            if ($item -is [System.Windows.Controls.TreeViewItem] -and $item.Tag) { Select-Folder -Node $item }
        })
    $ui.FilesGrid.Add_SelectionChanged({ Update-FileSelection })
    # Click, not Checked: setting IsChecked from code (to match the selection) must not select.
    $ui.SelectAllCheck.Add_Click({
            if ($script:UI.SelectAllCheck.IsChecked) { $script:UI.FilesGrid.SelectAll() } else { $script:UI.FilesGrid.UnselectAll() }
        })
    $win.Add_PreviewKeyDown({
            param($s, $e)
            if ($e.Key -eq 'F5') { Update-CurrentFolder; $e.Handled = $true }
        })
    $win.Add_Closing({
            param($s, $e)
            # Asked first, before anything is stopped: while a change runs the window stays open.
            if (-not (Test-CanClose)) { $e.Cancel = $true; return }
            # Reads and the export can simply be dropped. A change task (Kind Change) is never
            # stopped: stopping takeown or a batch midway would leave it half done.
            foreach ($t in @($script:BgTasks)) { if ($t -and "$($t.Kind)" -ne 'Change') { try { [void]$t.PS.BeginStop($null, $null) } catch { } } }
        })
    $win.Add_ContentRendered({ Hide-OwnConsole })
}

function Start-PermissionWindow {
    Initialize-PermissionWindow
    $win = $script:Window
    Update-DriveList

    # https://learn.microsoft.com/dotnet/api/system.windows.threading.dispatchertimer
    $timer = [System.Windows.Threading.DispatcherTimer]::new()
    $timer.Interval = [TimeSpan]::FromMilliseconds(200)
    $timer.Add_Tick({ Invoke-Tick })
    $timer.Start()

    [void]$win.ShowDialog()
    $timer.Stop()
}

#endregion

#region Changes (one at a time, asked first, run in the background)

# Messages shown when the tech has to give or choose something first.
$script:NoFilesSelectedText = 'Select at least one file.'
$script:NoTargetPathText = 'Enter at least one target path: the folders to copy the permissions to, one per line.'

function Get-ChangeControlNames {
    # The buttons that start a change. They are switched off while a change runs (and until a
    # folder is chosen); browsing, Refresh and the export stay usable.
    'AddPermissionBtn', 'RemovePermissionBtn', 'TakeOwnershipBtn', 'TakeOwnershipTreeBtn', 'CopyPermissionsBtn',
    'AddFilePermissionBtn', 'RemoveFilePermissionBtn', 'TakeFileOwnershipBtn'
}

function Get-ChangeControlState {
    # Whether the change buttons are on now and, when they are off, why (their tooltip says it).
    if ($script:ChangeTask) {
        return [PSCustomObject]@{ Enabled = $false; Reason = "A change is running on $($script:ChangeTask.Path). Wait for it to finish." }
    }
    if ($script:ChangePending) {
        return [PSCustomObject]@{
            Enabled = $false
            Reason  = "A change on $($script:ChangePending.Path) is being prepared (checking where it is, counting what is in it, or waiting for your answer). Wait for it to finish, or close its dialog."
        }
    }
    if (-not $script:Current) { return [PSCustomObject]@{ Enabled = $false; Reason = 'Choose a folder first.' } }
    [PSCustomObject]@{ Enabled = $true; Reason = $null }
}

function Update-ChangeControls {
    # Change buttons are on when a folder is chosen and no change runs or is being prepared.
    # While they are off, their tooltip says why (the buttons show tooltips when disabled);
    # their own tooltip comes back when they are on. Names the window does not have are skipped.
    if (-not $script:UI) { return }
    $state = Get-ChangeControlState
    foreach ($name in Get-ChangeControlNames) {
        $control = $script:UI[$name]
        if (-not $control) { continue }
        $control.IsEnabled = $state.Enabled
        if ($control.PSObject.Properties['ToolTip']) {
            if (-not $script:ChangeButtonTips.ContainsKey($name)) { $script:ChangeButtonTips[$name] = $control.ToolTip }
            $control.ToolTip = if ($state.Enabled) { $script:ChangeButtonTips[$name] } else { $state.Reason }
        }
    }
}

function Enter-ChangePending {
    # A click starts preparing a change: $true, and the change buttons stay off until
    # Exit-ChangePending (Start-ChangePrepRead calls it when the last step is done). $false,
    # after saying why, when a change runs or another one is being prepared.
    param([Parameter(Mandatory)][string]$Action, [string]$Path)
    if ($script:ChangeTask) {
        Set-Status -Kind Warning -Text "Another change is still running on $($script:ChangeTask.Path). Wait for it to finish."
        return $false
    }
    if ($script:ChangePending) {
        Set-Status -Kind Warning -Text (Get-ChangeControlState).Reason
        return $false
    }
    $script:ChangePending = [PSCustomObject]@{ Action = $Action; Path = $Path; Step = 0 }
    Update-ChangeControls
    $true
}

function Exit-ChangePending {
    $script:ChangePending = $null
    Update-ChangeControls
}

function Start-ChangePrepRead {
    # A background read a change being prepared waits for: the target lookup, the whole-tree
    # count, the selected files' permissions. OnDone ($result, $State) runs on the window's
    # thread; when it returns or throws, the pending change ends (buttons back) unless OnDone
    # handed it on to another such read (the step moved on). So every way out, a refusal, a
    # cancelled dialog, an error, ends it.
    param(
        [Parameter(Mandatory)][string]$Action,
        [string]$Path,
        [Parameter(Mandatory)][scriptblock]$Work,
        [object[]]$ArgumentList,
        [Parameter(Mandatory)][scriptblock]$OnDone,
        $State
    )
    if (-not $script:ChangePending) { $script:ChangePending = [PSCustomObject]@{ Action = $Action; Path = $Path; Step = 0 } }
    $script:ChangePending.Step++
    Update-ChangeControls
    Start-ReadTask -Action $Action -Path $Path -Work $Work -ArgumentList $ArgumentList -State @{ Step = $script:ChangePending.Step; OnDone = $OnDone; State = $State } -OnDone {
        param($result, $s)
        try { & $s.OnDone $result $s.State }
        finally {
            if ($script:ChangePending -and $script:ChangePending.Step -eq $s.Step) { Exit-ChangePending }
        }
    }
}

function Invoke-UiAction {
    # Runs a button's action; an unexpected error is shown and logged instead of closing the
    # window. A change it began preparing, but had not handed to a background read yet, ends.
    param([Parameter(Mandatory)][scriptblock]$Action)
    $pendingBefore = $script:ChangePending
    try { & $Action }
    catch {
        Write-AppError "Action: $($_.Exception.Message)`n$($_.ScriptStackTrace)"
        Set-Status -Kind Error -Text "Something went wrong: $(Get-InnermostErrorText $_) Nothing was started. Press Refresh and try again."
        if ($script:ChangePending -and -not [object]::ReferenceEquals($pendingBefore, $script:ChangePending) -and $script:ChangePending.Step -eq 0) { Exit-ChangePending }
    }
}
function Start-ChangeTask {
    # The only way a change starts. One at a time: while one runs, another is refused with a
    # message and nothing starts. The change buttons are switched off and the busy line shows
    # "<Action> <Path>... (elapsed)". When the work is done, OnDone is called with
    # ($result, $State) on the window's thread. Whatever happens (the work threw, OnDone threw,
    # the task could not even start) the busy state is cleared and the buttons come back. When
    # the work failed, what it touched is read again too (a refresh state as -State).
    # $true when the task started.
    param(
        [Parameter(Mandatory)][string]$Action,
        [string]$Path,
        [Parameter(Mandatory)][scriptblock]$Work,
        [object[]]$ArgumentList,
        [Parameter(Mandatory)][scriptblock]$OnDone,
        $State
    )
    if ($script:ChangeTask) {
        Set-Status -Kind Warning -Text "Another change is still running on $($script:ChangeTask.Path). Wait for it to finish."
        return $false
    }
    $key = [guid]::NewGuid().ToString('N')
    $script:ChangeTask = [PSCustomObject]@{ Action = $Action; Path = $Path; Key = $key; Started = [DateTime]::UtcNow; Task = $null }
    Update-ChangeControls
    $script:BusyEntries[$key] = [PSCustomObject]@{ Action = $Action; Path = $Path; Started = [DateTime]::UtcNow }
    Update-BusyLine
    $taskState = @{ Key = $key; OnDone = $OnDone; State = $State; Action = $Action; Path = $Path }
    $finish = {
        param($result, $s)
        try {
            if (-not ($result -and $result.Ok)) {
                $why = if ($result -and "$($result.Error)".Trim()) { "$($result.Error)".Trim() } else { 'No reason was given.' }
                if ($result -and $result.NotStarted) { Set-Status -Kind Error -Text $why }
                else { Set-Status -Kind Error -Text "The change may or may not have been made. Check the folder's permissions. ($why)" }
                # Show what is there now, so the tech checks the real state, not the old view.
                if ($s.State -is [System.Collections.IDictionary] -and $s.State['Scope']) {
                    try { Invoke-ChangeRefresh -State $s.State }
                    catch { Write-AppError "Refreshing after a failed change '$($s.Action) $($s.Path)': $($_.Exception.Message)" }
                }
            }
            else {
                try { & $s.OnDone $result $s.State }
                catch {
                    $why = "$($_.Exception.Message)"
                    Write-AppError "Showing the result of '$($s.Action) $($s.Path)': $why"
                    Set-Status -Kind Error -Text "The change finished, but its result could not be shown ($why). Check the change log in $($script:ChangeLogFolder) and press Refresh."
                }
            }
        }
        finally {
            $script:BusyEntries.Remove($s.Key)
            $script:ChangeTask = $null
            Update-ChangeControls
            Update-BusyLine
        }
    }
    try {
        $task = Start-BgTask -Work $Work -ArgumentList $ArgumentList -State $taskState -OnDone $finish -Kind Change
        $script:ChangeTask.Task = $task
        # From here on a change may have been made in this session (Get-FatalErrorMessage).
        $script:ChangeMadeThisSession = $true
    }
    catch {
        $script:BusyEntries.Remove($key)
        $script:ChangeTask = $null
        Update-ChangeControls
        Update-BusyLine
        Write-AppError "Starting '$Action $Path': $($_.Exception.Message)"
        Set-Status -Kind Error -Text "The change could not be started, so nothing was changed: $(Get-InnermostErrorText $_)"
        return $false
    }
    $true
}

function Complete-ChangeTask {
    # A change finished: show the core's message as the browser version did (Get-ChangeStatus,
    # with what the read-back found), say where the rows went when the change log could not be
    # written, then read again what it changed. $State is $null when there is nothing to refresh.
    param([Parameter(Mandatory)]$Result, $State)
    $entries = @($Result.Entries | Where-Object { $null -ne $_ })
    $message = if ("$($Result.Message)".Trim()) { "$($Result.Message)" } else { 'The change finished.' }
    $status = Get-ChangeStatus -Entries $entries -LogPath $Result.LogPath -Message $message
    $kind = $status.Kind
    $text = $status.Text
    $whatIfOnly = @($entries | Where-Object { $_.Result -ne 'Skipped (WhatIf)' }).Count -eq 0
    if ($Result.UnloggedPath) {
        $text += " The results were saved to $($Result.UnloggedPath) instead: attach that file to the ticket."
        if ($kind -eq 'Success' -or $kind -eq 'Info') { $kind = 'Warning' }
    }
    elseif (-not $Result.LogPath -and $entries.Count -gt 0 -and -not $whatIfOnly) {
        $text += ' The results could not be saved to a file either: copy this message into the ticket.'
    }
    if ($Result.PSObject.Properties['ReadBackUnlogged'] -and $Result.ReadBackUnlogged) {
        $text += if ($Result.ReadBackUnloggedPath) { " The 'Done, with items to check' rows could not be written to the change log, so they were saved to $($Result.ReadBackUnloggedPath) instead: attach that file to the ticket." }
        else { " The 'Done, with items to check' rows could not be written to the change log or to a file: copy this message into the ticket." }
        if ($kind -eq 'Success' -or $kind -eq 'Info') { $kind = 'Warning' }
    }
    Set-Status -Kind $kind -Text $text
    if ($State) { Invoke-ChangeRefresh -State $State }
}
function Invoke-ChangeRefresh {
    # Reads again what a change touched (Get-RefreshPlan), for the folder shown now.
    param([Parameter(Mandatory)]$State)
    $current = if ($script:Current) { $script:Current.DisplayPath } else { $null }
    $shown = @(Get-SelectedFileRows | ForEach-Object { "$($_.Path)" })
    $reloadFolder = $false
    $resetNode = $false
    $reloadFileAcl = $false
    foreach ($p in @($State.Paths)) {
        $plan = Get-RefreshPlan -Scope $State.Scope -Path $p -CurrentPath $current -ChangedFiles @($State.ChangedFiles) -ShownFiles $shown
        if (@($plan.DropFileAcl).Count -gt 0) { Remove-CachedFileAcl -Path $plan.DropFileAcl }
        if ($plan.ReloadPermissions -or $plan.ReloadFiles) { $reloadFolder = $true }
        if ($plan.RefreshTreeEntry) { $resetNode = $true }
        if (@($plan.ReloadFileAcl).Count -gt 0) { $reloadFileAcl = $true }
    }
    if ($reloadFolder) { Update-CurrentFolder; return }
    if ($resetNode -and $State.Node) { Reset-FolderNode -Node $State.Node }
    if ($reloadFileAcl) { Update-FileSelection }
}

function Get-ThisComputerNames {
    # This computer's own names, read locally (no DNS query): the NetBIOS and host names, the
    # fully qualified name and its own IP addresses. Loopback names (Uri.IsLoopback) are
    # checked separately (Test-ThisComputerName).
    # https://learn.microsoft.com/dotnet/api/system.environment.machinename
    # https://learn.microsoft.com/dotnet/api/system.net.networkinformation.ipglobalproperties
    $names = [System.Collections.Generic.List[string]]::new()
    $add = { param($n) $t = "$n".Trim().TrimEnd('.'); if ($t -and -not $names.Contains($t)) { $names.Add($t) } }
    & $add ([Environment]::MachineName)
    & $add $env:COMPUTERNAME
    try {
        $g = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        & $add $g.HostName
        if ($g.HostName -and $g.DomainName) { & $add "$($g.HostName).$($g.DomainName)" }
        foreach ($a in @($g.GetUnicastAddresses())) { & $add $a.Address.ToString() }
    }
    catch { Write-Verbose "This computer's names could not all be read: $($_.Exception.Message)" }
    $names.ToArray()
}

function ConvertFrom-Ipv6LiteralName {
    # The IP address in an "ipv6-literal.net" server name ('-' for ':'), or $null. MS-DTYP and
    # WNetAddConnection2 describe the form; the scope ID written as 's' (fe80--1s4) is NOT
    # VERIFIED on Learn and is decoded as '%'.
    # https://learn.microsoft.com/openspecs/windows_protocols/ms-dtyp/62e862f4-2a51-452e-8eeb-dc4ff5ee33cc
    param([AllowEmptyString()][string]$Name)
    $suffix = '.ipv6-literal.net'
    if (-not $Name.EndsWith($suffix, [StringComparison]::OrdinalIgnoreCase)) { return $null }
    $literal = $Name.Substring(0, $Name.Length - $suffix.Length).Replace('-', ':').Replace('s', '%').Replace('S', '%')
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($literal, [ref]$ip)) { return $ip }
    $null
}

function Test-SameIPAddress {
    # True when two addresses are the same address: an IPv4-mapped IPv6 address (::ffff:10.0.0.5)
    # is read as its IPv4 address, and an IPv6 scope ID is ignored (fe80::1%4 and fe80::1%7 are
    # the same address seen through two interfaces).
    # https://learn.microsoft.com/dotnet/api/system.net.ipaddress.isipv4mappedtoipv6
    # https://learn.microsoft.com/dotnet/api/system.net.ipaddress.maptoipv4
    # https://learn.microsoft.com/dotnet/api/system.net.ipaddress.scopeid
    param([Parameter(Mandatory)][System.Net.IPAddress]$A, [Parameter(Mandatory)][System.Net.IPAddress]$B)
    if ($A.IsIPv4MappedToIPv6) { $A = $A.MapToIPv4() }
    if ($B.IsIPv4MappedToIPv6) { $B = $B.MapToIPv4() }
    if ($A.AddressFamily -ne $B.AddressFamily) { return $false }
    [BitConverter]::ToString($A.GetAddressBytes()) -eq [BitConverter]::ToString($B.GetAddressBytes())
}

function Test-ThisComputerName {
    # True when a \\server name is this computer: a loopback name or address (Uri.IsLoopback:
    # 127.0.0.1, loopback and the local host name; IPAddress.IsLoopback, also for an
    # IPv4-mapped IPv6 address such as ::ffff:127.0.0.1), an ipv6-literal.net loopback, or one
    # of this computer's own names or addresses (Get-ThisComputerNames; an IPv6 address matches
    # whatever its scope ID). A DNS alias (CNAME) or an extra NetBIOS name of this computer is
    # NOT detected: such a name is treated as another computer, so its paths get the remote
    # checks (DFS lookup, the share's folder on the server), never the local ones.
    # https://learn.microsoft.com/dotnet/api/system.uri.isloopback
    # https://learn.microsoft.com/dotnet/api/system.net.ipaddress.isloopback
    param([AllowEmptyString()][string]$Name)
    $n = "$Name".Trim().TrimEnd('.')
    if (-not $n) { return $false }
    $ip = ConvertFrom-Ipv6LiteralName -Name $n
    if (-not $ip) {
        $parsed = $null
        if ([System.Net.IPAddress]::TryParse($n.Trim('[', ']'), [ref]$parsed)) { $ip = $parsed }
    }
    if ($ip) {
        $plain = if ($ip.IsIPv4MappedToIPv6) { $ip.MapToIPv4() } else { $ip }
        if ([System.Net.IPAddress]::IsLoopback($plain)) { return $true }
    }
    else {
        try { if (([uri]"file://$n/").IsLoopback) { return $true } } catch { }
    }
    foreach ($own in @(Get-ThisComputerNames)) {
        if (-not $own) { continue }
        $ownIp = $null
        if ($ip -and [System.Net.IPAddress]::TryParse($own, [ref]$ownIp)) {
            if (Test-SameIPAddress -A $ip -B $ownIp) { return $true }
            continue
        }
        if ($n -ieq $own) { return $true }
    }
    $false
}
function Get-LocalSharePath {
    # The local folder of a share on this computer (Win32_Share.Path), only read. Throws when it
    # cannot be told. Tests replace it.
    # https://learn.microsoft.com/windows/win32/cimwin32prov/win32-share
    param([Parameter(Mandatory)][string]$Name)
    $escaped = $Name.Replace('\', '\\').Replace("'", "\'")
    $share = @(Get-CimInstance -ClassName Win32_Share -Filter "Name='$escaped'" -ErrorAction Stop) | Select-Object -First 1
    if (-not $share -or -not "$($share.Path)".Trim()) { throw "this computer has no share named $Name with a folder behind it" }
    "$($share.Path)"
}

function Get-DfsClientTarget {
    # Where a network path in a DFS namespace really is: every target's \\server\share plus the
    # rest of the path. Nothing when Windows says it is in no DFS namespace (NERR_DfsNoSuchVolume,
    # 2662); throws when the lookup fails. NetDfsGetClientInfo level 3 reads the DFS client's
    # cache, so the folder is touched first to put its referral there
    # (https://stackoverflow.com/a/68071399). A copy of SQ-014's Get-DfsTarget, used only when
    # the core does not have it (Get-AppDfsTarget).
    # https://learn.microsoft.com/windows/win32/api/lmdfs/nf-lmdfs-netdfsgetclientinfo
    # https://learn.microsoft.com/windows/win32/api/lmdfs/ns-lmdfs-dfs_info_3
    # https://learn.microsoft.com/windows/win32/api/lmdfs/ns-lmdfs-dfs_storage_info
    # https://learn.microsoft.com/windows/win32/api/lmapibuf/nf-lmapibuf-netapibufferfree
    # https://learn.microsoft.com/windows/win32/netmgmt/network-management-error-codes
    param([Parameter(Mandatory)][string]$Path)
    if (-not ('FolderPermissionManager.AppDfsClient' -as [type])) {
        Add-Type -Namespace FolderPermissionManager -Name AppDfsClient -ErrorAction Stop -MemberDefinition @'
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct DfsInfo3 {
    [MarshalAs(UnmanagedType.LPWStr)] public string EntryPath;
    [MarshalAs(UnmanagedType.LPWStr)] public string Comment;
    public uint State;
    public uint NumberOfStorages;
    public IntPtr Storage;
}
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct DfsStorageInfo {
    public uint State;
    [MarshalAs(UnmanagedType.LPWStr)] public string ServerName;
    [MarshalAs(UnmanagedType.LPWStr)] public string ShareName;
}
[DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
private static extern uint NetDfsGetClientInfo(string DfsEntryPath, string ServerName, string ShareName, uint Level, out IntPtr Buffer);
[DllImport("netapi32.dll")]
public static extern uint NetApiBufferFree(IntPtr Buffer);
public static uint GetClientInfo3(string dfsEntryPath, out IntPtr buffer) {
    return NetDfsGetClientInfo(dfsEntryPath, null, null, 3, out buffer);
}
'@
    }
    $unc = ConvertTo-ComparablePath -Path $Path
    if (-not $unc.StartsWith('\\')) { return }
    $null = [System.IO.Directory]::Exists($unc)
    $buffer = [IntPtr]::Zero
    $status = [FolderPermissionManager.AppDfsClient]::GetClientInfo3($unc, [ref]$buffer)
    try {
        if ($status -eq 2662) { return }
        if ($status -ne 0) {
            $why = (New-Object System.ComponentModel.Win32Exception -ArgumentList ([int]$status)).Message
            throw "Windows could not look up the DFS target of $unc (error $($status): $why)"
        }
        $info = [System.Runtime.InteropServices.Marshal]::PtrToStructure($buffer, [type][FolderPermissionManager.AppDfsClient+DfsInfo3])
        # A client returns the entry path with one leading backslash (https://stackoverflow.com/a/21334006).
        $entry = ConvertTo-ComparablePath -Path ('\\' + "$($info.EntryPath)".TrimStart('\'))
        if (-not ($unc -ieq $entry -or $unc.StartsWith("$entry\", [StringComparison]::OrdinalIgnoreCase))) {
            throw "Windows gave the DFS entry $entry for $unc, which is not above it"
        }
        if ($info.NumberOfStorages -eq 0) { throw "Windows reported no DFS target for $entry" }
        $rest = $unc.Substring($entry.Length).TrimStart('\')
        $size = [System.Runtime.InteropServices.Marshal]::SizeOf([type][FolderPermissionManager.AppDfsClient+DfsStorageInfo])
        for ($i = 0; $i -lt $info.NumberOfStorages; $i++) {
            $at = New-Object System.IntPtr -ArgumentList ($info.Storage.ToInt64() + $i * $size)
            $storage = [System.Runtime.InteropServices.Marshal]::PtrToStructure($at, [type][FolderPermissionManager.AppDfsClient+DfsStorageInfo])
            if (-not $storage.ServerName -or -not $storage.ShareName) { throw "Windows reported a DFS target of $entry with no server or share name" }
            $target = "\\$($storage.ServerName)\$($storage.ShareName)"
            if ($rest) { $target += "\$rest" }
            $target
        }
    }
    finally {
        if ($buffer -ne [IntPtr]::Zero) { $null = [FolderPermissionManager.AppDfsClient]::NetApiBufferFree($buffer) }
    }
}

function Get-AppDfsTarget {
    # The real \\server\share path(s) behind a DFS namespace path; nothing when the path is not
    # in a DFS namespace; throws when it cannot be told (callers refuse: fail closed). The
    # core's Get-DfsTarget (SQ-014) is used when the core has it, else the copy above. Tests
    # replace it.
    param([Parameter(Mandatory)][string]$Path)
    if (Get-Command -Name Get-DfsTarget -CommandType Function -ErrorAction SilentlyContinue) { return @(Get-DfsTarget -Path $Path) }
    @(Get-DfsClientTarget -Path $Path)
}

function New-ChangeTarget {
    param([bool]$Ok, [string]$Refusal, [string]$DisplayPath, [string]$ResolvedPath, [bool]$IsRemembered, [bool]$IsLocal)
    [PSCustomObject]@{
        Ok           = $Ok
        Refusal      = $(if ($Refusal) { $Refusal } else { $null })
        DisplayPath  = $DisplayPath
        ResolvedPath = $ResolvedPath
        IsRemembered = $IsRemembered
        IsLocal      = $IsLocal
    }
}

function Get-AppReparseInfo {
    # Whether an item exists and is a reparse point, and its tag, read from its directory entry
    # only (FindFirstFileW: "If the dwFileAttributes member includes the
    # FILE_ATTRIBUTE_REPARSE_POINT attribute, then the dwReserved0 member specifies the reparse
    # point" tag). Unlike the core's Get-ReparsePointTag it tells "not there" (ERROR_FILE_NOT_FOUND
    # 2, ERROR_PATH_NOT_FOUND 3) apart from "could not be read" (throws), so a check built on it
    # fails closed. Find-DfsReparsePoint compares the tag with IO_REPARSE_TAG_DFS (0x8000000A,
    # "Used by the DFS filter ... Server-side interpretation only", MS-FSCC 2.1.2.1 Reparse Tags).
    # Tests replace it.
    # https://learn.microsoft.com/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4
    # https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-findfirstfilew
    # https://learn.microsoft.com/windows/win32/api/minwinbase/ns-minwinbase-win32_find_dataw
    # https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-
    param([Parameter(Mandatory)][string]$Path)
    if (-not ('FolderPermissionManager.AppReparseFind' -as [type])) {
        Add-Type -Namespace FolderPermissionManager -Name AppReparseFind -ErrorAction Stop -MemberDefinition @'
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
    $p = $Path.TrimEnd('\')
    # A long local path needs the \\?\ form (no MAX_PATH limit).
    if ($p.Length -ge 248 -and $p -match '^[A-Za-z]:\\') { $p = "\\?\$p" }
    $data = New-Object FolderPermissionManager.AppReparseFind+FindData
    $handle = [FolderPermissionManager.AppReparseFind]::FindFirstFileW($p, [ref]$data)
    if ($handle -eq [IntPtr]::Zero -or $handle -eq [IntPtr](-1)) {
        $code = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($code -eq 2 -or $code -eq 3) { return [PSCustomObject]@{ Exists = $false; IsReparsePoint = $false; Tag = $null } }
        $why = (New-Object System.ComponentModel.Win32Exception -ArgumentList ([int]$code)).Message
        throw "Windows could not read $Path (error $($code): $why)"
    }
    $null = [FolderPermissionManager.AppReparseFind]::FindClose($handle)
    # 0x400 = FILE_ATTRIBUTE_REPARSE_POINT
    $isReparse = ($data.dwFileAttributes -band 0x400) -ne 0
    [PSCustomObject]@{ Exists = $true; IsReparsePoint = $isReparse; Tag = $(if ($isReparse) { [uint32]$data.dwReserved0 } else { $null }) }
}

function Find-DfsReparsePoint {
    # The first folder, from -Path up to (not including) its drive root, that is a DFS folder:
    # a reparse point with the tag IO_REPARSE_TAG_DFS (0x8000000A, "Used by the DFS filter ...
    # Server-side interpretation only", MS-FSCC 2.1.2.1). A DFS namespace hosted on this
    # computer keeps each DFS folder as such a reparse point in the namespace root's folder;
    # changing it in place would change the reparse point, not the folder it stands for.
    # $null when there is none; throws when an entry cannot be read (Get-AppReparseInfo).
    # https://learn.microsoft.com/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4
    param([Parameter(Mandatory)][string]$Path)
    # 0x8000000A, written as a number: a hex literal that large is a negative Int32 in PowerShell.
    $dfsTag = [uint32]2147483658
    $current = "$Path".TrimEnd('\')
    $root = "$([System.IO.Path]::GetPathRoot($Path))".TrimEnd('\')
    while ($current -and $current.Length -gt $root.Length) {
        $info = Get-AppReparseInfo -Path $current
        if ($info.Exists -and $info.IsReparsePoint -and $null -ne $info.Tag -and [uint32]$info.Tag -eq $dfsTag) { return $current }
        $parent = [System.IO.Path]::GetDirectoryName($current)
        if (-not $parent -or $parent.Length -ge $current.Length) { break }
        $current = $parent.TrimEnd('\')
    }
    $null
}

function Get-RemoteShareLocalPath {
    # The folder a share is on its server: NetShareGetInfo level 2, SHARE_INFO_2.shi2_path ("the
    # local path for the shared resource"), the buffer freed with NetApiBufferFree. Level 2
    # needs Administrator, Power User, Print Operator or Server Operator membership on that
    # server for a caller who is not logged on there. Throws when the server does not say.
    # Only read. Tests replace it.
    # https://learn.microsoft.com/windows/win32/api/lmshare/nf-lmshare-netsharegetinfo
    # https://learn.microsoft.com/windows/win32/api/lmshare/ns-lmshare-share_info_2
    # https://learn.microsoft.com/windows/win32/api/lmapibuf/nf-lmapibuf-netapibufferfree
    param([Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Share)
    if (-not ('FolderPermissionManager.AppNetShare' -as [type])) {
        Add-Type -Namespace FolderPermissionManager -Name AppNetShare -ErrorAction Stop -MemberDefinition @'
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct ShareInfo2 {
    [MarshalAs(UnmanagedType.LPWStr)] public string NetName;
    public uint Type;
    [MarshalAs(UnmanagedType.LPWStr)] public string Remark;
    public uint Permissions;
    public uint MaxUses;
    public uint CurrentUses;
    [MarshalAs(UnmanagedType.LPWStr)] public string Path;
    [MarshalAs(UnmanagedType.LPWStr)] public string Password;
}
[DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
private static extern uint NetShareGetInfo(string servername, string netname, uint level, out IntPtr bufptr);
[DllImport("netapi32.dll")]
public static extern uint NetApiBufferFree(IntPtr Buffer);
public static uint GetInfo2(string server, string share, out IntPtr buffer) {
    return NetShareGetInfo(server, share, 2, out buffer);
}
'@
    }
    $buffer = [IntPtr]::Zero
    $status = [FolderPermissionManager.AppNetShare]::GetInfo2($Server, $Share, [ref]$buffer)
    try {
        if ($status -ne 0) {
            $why = (New-Object System.ComponentModel.Win32Exception -ArgumentList ([int]$status)).Message
            throw "$Server did not say which folder its share $Share is (error $($status): $why)"
        }
        $info = [System.Runtime.InteropServices.Marshal]::PtrToStructure($buffer, [type][FolderPermissionManager.AppNetShare+ShareInfo2])
        if (-not "$($info.Path)".Trim()) { throw "$Server gave no folder for its share $Share" }
        "$($info.Path)"
    }
    finally {
        if ($buffer -ne [IntPtr]::Zero) { $null = [FolderPermissionManager.AppNetShare]::NetApiBufferFree($buffer) }
    }
}

function Get-ServerSideLinkRefusal {
    # D-045: a whole-tree change on a share reaches the folder the share is on its server, and the
    # server follows its own junctions and symbolic links before this computer sees anything, so
    # Get-ResolvedRootRefusal cannot see them. Each folder of -ServerPath (the share's folder on
    # the server, \\server\<letter>$\..., Get-ShareTreeRefusal) is read over the administrative
    # share with Get-AppReparseInfo, from the top of the drive down: one that is a reparse point
    # (FILE_ATTRIBUTE_REPARSE_POINT 0x400, "A file or directory that has an associated reparse
    # point, or a file that is a symbolic link") is refused, and so is one that is not there or
    # cannot be read ("a guard that cannot resolve the path fails closed", destructive-operations
    # profile). $null when every folder on the way is an ordinary folder.
    # https://learn.microsoft.com/windows/win32/fileio/file-attribute-constants
    param([Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$ServerPath)
    $next = 'Nothing was changed. Run the tool on the server itself, or ask a senior admin.'
    if ($ServerPath -notmatch '^(\\\\[^\\]+\\[A-Za-z]\$)((?:\\[^\\]+)+)$') { return $null }
    $current = $Matches[1]
    foreach ($name in ($Matches[2].TrimStart('\') -split '\\')) {
        $current += "\$name"
        try { $info = Get-AppReparseInfo -Path $current }
        catch {
            $why = (Get-InnermostErrorText $_).TrimEnd('.')
            return "Windows could not check whether $current on $Server is a junction or symbolic link ($why), so it cannot tell where the change would really land. $next"
        }
        if (-not ($info -and $info.Exists)) {
            return "$current was not found on $Server, so it could not be checked for junctions and symbolic links, and where the change would really land is not known. $next"
        }
        if ($info.IsReparsePoint) {
            $kind = Format-LinkKindWithArticle -Kind (Get-LinkKindName -Tag $info.Tag)
            return "$current on $Server is $kind, so the folder may really be somewhere else on that server, where it cannot be checked against the root of a drive, the Windows system folders and the user profiles folder. $next"
        }
    }
    $null
}

function Get-CopyTargetRefusal {
    # D-044 (AC50): why a folder cannot be a Copy permissions target, or $null. -Path is where the
    # copy really lands (ResolvedPath). Refused: the administrative shares (\\server\X$ itself,
    # ADMIN$, IPC$, PRINT$), SYSVOL and NETLOGON, the D-036 folders (the root of a drive, the
    # Windows folders, here and through \\server\X$; Get-TreeOwnershipRefusal) and the high-impact
    # roots (a Users folder or this computer's profiles folder, System Volume Information,
    # $Recycle.Bin; Get-HighImpactRootRefusal). A folder inside \\server\X$ and the root of an
    # ordinary share are allowed (the root gets the destructive confirm, AC49). Text only, apart
    # from reading this computer's profiles folder.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)
    $p = ConvertTo-ComparablePath -Path $Path
    if (-not $p) { return $null }
    $what = $null
    if ($p -match '^\\\\([^\\]+)\\([^\\]+)(?:\\(.*))?$') {
        $server = $Matches[1]; $share = $Matches[2]; $rest = "$($Matches[3])"
        if ($share -ieq 'IPC$') { $what = "the IPC`$ share of $server, which Windows uses for remote administration; it is not a folder" }
        elseif ($share -ieq 'ADMIN$') { $what = "on the ADMIN`$ administrative share of $server, which is used to administer Windows remotely" }
        elseif ($share -ieq 'PRINT$') { $what = "on the PRINT`$ share of $server, which holds the printer drivers it hands out" }
        elseif ($share -ieq 'SYSVOL' -or $share -ieq 'NETLOGON') { $what = "on the $($share.ToUpperInvariant()) share of $server, which domain controllers use for Group Policy and logon scripts" }
        elseif ($share -match '^[A-Za-z]\$$' -and -not $rest) { $what = "the $($share.ToUpperInvariant()) administrative share of $server, the root of a whole drive" }
    }
    if (-not $what) {
        if ((Get-TargetRootKind -Path $p) -eq 'DriveRoot') { $what = 'the root of a whole drive' }
        elseif (Get-TreeOwnershipRefusal -Path $p) { $what = 'in a Windows system folder' }
        elseif (Get-HighImpactRootRefusal -Path $p) {
            $what = if ($p -match '(?i)(^|\\)(System Volume Information|\$Recycle\.Bin)(\\|$)') { 'in System Volume Information or $Recycle.Bin, which Windows keeps for itself' }
            else { 'a folder that holds every user profile' }
        }
    }
    if (-not $what) { return $null }
    "Permissions can't be copied to ${Path}: it is $what, and adding permissions there could let people into it who should not have access. Choose the folder that needs these permissions instead. Nothing was changed."
}

function Get-ResolvedRootRefusal {
    # A whole-tree change on -Path, checked where Windows really reaches it: the final path (the
    # core's Get-Win32PathName -Kind Final follows every junction and symbolic link on the way,
    # and gives long names) and the long-name form (-Kind Long expands 8.3 short names such as
    # PROGRA~1). Each form that differs from -Path gets D-036 (Get-TreeOwnershipRefusal) and the
    # high-impact roots (Get-HighImpactRootRefusal). A final path that cannot be told is refused:
    # "a guard that cannot resolve the path fails closed" (destructive-operations profile). On a
    # share the server follows its own junctions, so the final path seen from here is the share
    # path itself. $null when it is allowed.
    param([Parameter(Mandatory)][string]$Path)
    $final = Get-Win32PathName -Path $Path -Kind Final
    if (-not $final) {
        return "Windows could not tell where $Path really is (it may have been moved or deleted, or this account cannot open it), so it cannot be checked against the root of a drive, the Windows system folders and the user profiles folder. Nothing was changed. If the folder is on a server, run the tool on the server itself, or ask a senior admin."
    }
    $long = Get-Win32PathName -Path $Path -Kind Long
    $given = ConvertTo-ComparablePath -Path $Path
    foreach ($form in @($final, $long)) {
        if (-not $form) { continue }
        $c = ConvertTo-ComparablePath -Path $form
        if (-not $c -or $c -ieq $given) { continue }
        $refusal = Get-TreeOwnershipRefusal -Path $c
        if (-not $refusal) { $refusal = Get-HighImpactRootRefusal -Path $c }
        if ($refusal) { return "$Path leads to $c (through a junction, a symbolic link or a short name). $refusal" }
    }
    $null
}

function Get-TreeLinkTargetRefusal {
    # The junctions and symbolic links inside a whole tree (Get-OwnerTreeItem Links), checked
    # before the confirm opens: the core's own check (Get-TreeLinkRefusal: D-036 on where each
    # link leads, and a link whose destination cannot be found out), then the high-impact roots
    # on the link and on where it leads (Get-ResolvedRootRefusal). -Path itself is checked by the
    # lookup before the count. $null when every link is allowed.
    param([Parameter(Mandatory)][string]$Path, [AllowEmptyCollection()][string[]]$LinkPaths = @())
    $links = @($LinkPaths | Where-Object { $_ -and $_ -ne $Path })
    if ($links.Count -eq 0) { return $null }
    $refusal = Get-TreeLinkRefusal -Path $Path -LinkPaths $links
    if ($refusal) { return $refusal }
    foreach ($link in $links) {
        $r = Get-HighImpactRootRefusal -Path $link
        if (-not $r) { $r = Get-ResolvedRootRefusal -Path $link }
        if ($r) { return "$Path contains a junction or symbolic link that takeown and icacls may follow out of the folder ($link). $r" }
    }
    $null
}

function Get-ShareTreeRefusal {
    # A whole-tree change on \\server\share\... (not an administrative share): the share's folder
    # on the server (Get-RemoteShareLocalPath), checked as the server's own path
    # \\server\<letter>$\..., so D-036 (the root of a drive, the Windows folders) and the
    # high-impact roots see where it really is, and every folder on the way there is checked for
    # a junction or symbolic link on the server (Get-ServerSideLinkRefusal, D-045). A share whose
    # folder cannot be found out is refused: "a guard that cannot resolve the path fails closed"
    # (destructive-operations profile). $null when it is allowed.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Share, [string]$Rest)
    $instead = "Open it by its administrative share path instead (for example \\$Server\D`$\...), or ask a senior admin."
    try { $local = Get-RemoteShareLocalPath -Server $Server -Share $Share }
    catch {
        $why = (Get-InnermostErrorText $_).TrimEnd('.')
        return "Windows could not tell which folder on $Server the share $Share is ($why), so $Path cannot be checked against the root of a drive, the Windows system folders and the user profiles folder. $instead"
    }
    if ("$local" -notmatch '^([A-Za-z]):(\\.*)?$') {
        return "The share $Share on $Server is $local, not a folder on a drive, so $Path cannot be checked against the root of a drive and the Windows system folders. $instead"
    }
    $serverPath = "\\$Server\$($Matches[1].ToUpper())`$" + "$($Matches[2])".TrimEnd('\')
    if ($Rest) { $serverPath += "\$Rest" }
    $refusal = Get-TreeOwnershipRefusal -Path $serverPath
    if (-not $refusal) { $refusal = Get-HighImpactRootRefusal -Path $serverPath }
    # D-045: a junction or symbolic link on the server, on the way to that folder.
    if (-not $refusal) { $refusal = Get-ServerSideLinkRefusal -Server $Server -ServerPath $serverPath }
    if ($refusal) { return "$Path is $local on $Server ($serverPath). $refusal" }
    $null
}

function Get-StreamRefusal {
    # A ':' after the drive or share part names an alternate data stream (file:stream), not a
    # folder or file. https://learn.microsoft.com/windows/win32/fileio/file-streams
    param([Parameter(Mandatory)][string]$Path)
    $where = if ($Path.StartsWith('\\')) { 'the share name' } else { 'the drive' }
    "$Path contains a ':' after $where, so it points at hidden data inside a file (an alternate data stream), not at a folder or file. Nothing was changed."
}

function Get-ChangeTarget {
    <#
        Where a change will really land, worked out before anything is asked or started, and
        whether it is refused. The window runs it in the background (Resolve-ChangeTargetSet
        in $script:ChangeTargetWork), because apart from the text checks it asks: this computer's
        names (Get-ThisComputerNames), DFS (Get-AppDfsTarget), the folder of a share on this
        computer (Get-LocalSharePath, Win32_Share) and whether it is a DFS folder
        (Find-DfsReparsePoint), and for a whole tree the folder of a share on another server
        (Get-ShareTreeRefusal) and this computer's profiles folder. The path does not have to
        exist.
        - A mapped drive letter becomes its \\server\share path; IsRemembered when that mapping
          only came from Windows' remembered mappings (it may be out of date).
        - Refused: a device path (\\?\, \\.\), a path that is not a full local or UNC path, and
          an alternate data stream (a ':' after the drive or share part).
        - A \\server name that is this computer (loopback, its own names) sets IsLocal; its X$
          share becomes X:\..., another share its local folder. When that folder is, or is
          inside, a DFS folder of a namespace this computer hosts, it is looked up in DFS like a
          path on another server (or refused when that fails).
        - Any other UNC path is looked up in DFS; a lookup that fails is refused (fail closed),
          as is a DFS folder with more than one target (which one would change is not known).
        - With -WholeTree, on the resolved path, never the display path: D-036 (the core's
          Get-TreeOwnershipRefusal: drive roots, X$ roots, ADMIN$, SYSVOL, NETLOGON, PRINT$,
          Windows folders) plus IPC$, which is not a folder at all; the high-impact roots
          (Get-HighImpactRootRefusal); for an ordinary share on a server, the same checks on
          the folder it is on that server, and no junction or symbolic link on the way there
          on the server (Get-ShareTreeRefusal, D-045); then both again on where Windows really
          reaches the path, through junctions, symbolic links and 8.3 names
          (Get-ResolvedRootRefusal). That last check reads the disk and needs the folder to
          exist.
        - With -RefuseProtected (a Copy permissions target, D-044), on the resolved path: the
          administrative shares, SYSVOL, NETLOGON, the D-036 folders and the high-impact roots
          (Get-CopyTargetRefusal).
    #>
    param([Parameter(Mandatory)][string]$Path, [hashtable]$DriveMap, [hashtable]$DriveMapSource, [switch]$WholeTree, [switch]$RefuseProtected)
    if (-not $PSBoundParameters.ContainsKey('DriveMap')) { $DriveMap = $script:MappedDrives }
    if (-not $PSBoundParameters.ContainsKey('DriveMapSource')) { $DriveMapSource = $script:MappedDriveSources }
    $display = $Path.Trim()
    $refuse = { param($text, $resolved, $local) New-ChangeTarget -Ok $false -Refusal $text -DisplayPath $display -ResolvedPath $resolved -IsRemembered $remembered -IsLocal ([bool]$local) }
    $remembered = $false
    $systemShares = @('ADMIN$', 'IPC$', 'SYSVOL', 'NETLOGON', 'PRINT$')
    $useRealPath = 'Open the folder by its real \\server\share path instead (Properties > DFS tab in Explorer shows it).'

    if (-not $display) { return (& $refuse 'No folder or file was chosen, so nothing was changed.' $display $false) }
    if ($display -match '^[\\/]{2}[?.][\\/]') {
        return (& $refuse "$display is a device path (\\?\ or \\.\). Open the folder by its normal path (D:\... or \\server\share\...) instead." $display $false)
    }
    if ($display.Contains('/') -or $display -notmatch '^([A-Za-z]:\\|\\\\[^\\]+\\[^\\]+)') {
        return (& $refuse "$display is not a full path to a folder or file on a drive or share (for example D:\Data or \\fs01\Data), so nothing was changed." $display $false)
    }
    if ($display.Substring(2).Contains(':')) { return (& $refuse (Get-StreamRefusal -Path $display) $display $false) }
    if ($display -match '^([A-Za-z]):' -and $DriveMapSource -and "$($DriveMapSource[$Matches[1].ToUpper()])" -eq 'Remembered' -and
        $DriveMap -and $DriveMap[$Matches[1].ToUpper()]) {
        $remembered = $true
    }
    $resolved = Resolve-MappedDrive -Path $display -DriveMap $DriveMap
    $local = $false

    if ($resolved -match '^\\\\([^\\]+)\\([^\\]+)(\\.*)?$') {
        $unc = $resolved
        $server = $Matches[1]; $share = $Matches[2]; $rest = "$($Matches[3])".TrimStart('\')
        $askDfs = $true
        $dfsFolder = $null
        if (Test-ThisComputerName -Name $server) {
            $local = $true
            $askDfs = $false
            $localPath = $null
            if ($share -match '^([A-Za-z])\$$') {
                # The administrative share of drive X: on this computer is X:\.
                $localPath = "$($Matches[1].ToUpper()):\" + $rest
            }
            elseif ($systemShares -notcontains $share.ToUpperInvariant()) {
                $folder = $null
                try { $folder = Get-LocalSharePath -Name $share } catch { $folder = $null }
                if ($folder) { $localPath = if ($rest) { $folder.TrimEnd('\') + '\' + $rest } else { $folder } }
                elseif ($WholeTree) {
                    return (& $refuse "$display is a share on this computer, and the folder behind it could not be found, so it cannot be checked against the Windows system folders. Open the folder by its local path (for example D:\Shares\Data) instead." $resolved $true)
                }
                else {
                    # The folder behind the share is not known: check the path as another
                    # server's would be (it may be a DFS namespace this computer hosts).
                    $askDfs = $true
                }
            }
            if ($localPath) {
                $resolved = $localPath
                try { $dfsFolder = Find-DfsReparsePoint -Path $localPath }
                catch {
                    $why = (Get-InnermostErrorText $_).TrimEnd('.')
                    return (& $refuse "Windows could not tell whether $display is a DFS folder on this computer ($why), so nothing was changed. $useRealPath" $resolved $true)
                }
                if ($dfsFolder) { $askDfs = $true }
            }
        }
        if ($askDfs) {
            try { $targets = @(Get-AppDfsTarget -Path $unc | Where-Object { "$_".Trim() }) }
            catch {
                $why = (Get-InnermostErrorText $_).TrimEnd('.')
                return (& $refuse "Windows could not tell whether $unc is in a DFS namespace ($why), so nothing was changed. $useRealPath" $unc $false)
            }
            if ($targets.Count -gt 1) {
                return (& $refuse "$display is a DFS folder that points to $($targets.Count) servers ($($targets -join '; ')), and the change would land on only one of them. Open the folder on the server you want to change (one of those paths) and try again." $unc $false)
            }
            if ($targets.Count -eq 1) {
                $resolved = "$($targets[0])"
                $local = $false
            }
            elseif ($dfsFolder) {
                return (& $refuse "$display is a DFS folder on this computer ($dfsFolder), and Windows did not say which server it points to, so nothing was changed. $useRealPath" $unc $false)
            }
        }
    }

    if ($RefuseProtected) {
        $refusal = Get-CopyTargetRefusal -Path $resolved
        if ($refusal) {
            if ($resolved -ne $display) { $refusal = "$display is $resolved. $refusal" }
            return (& $refuse $refusal $resolved $local)
        }
    }
    if ($WholeTree) {
        $refusal = $null
        if ($resolved -match '^\\\\([^\\]+)\\IPC\$(\\|$)') {
            $refusal = "$resolved is the IPC`$ share of $($Matches[1]), which Windows uses for remote administration; it is not a folder. Choose the folder that needs fixing instead."
        }
        if (-not $refusal) { $refusal = Get-TreeOwnershipRefusal -Path $resolved }
        if (-not $refusal) { $refusal = Get-HighImpactRootRefusal -Path $resolved }
        if (-not $refusal -and $resolved -match '^\\\\([^\\]+)\\([^\\]+)(?:\\(.*))?$') {
            $tServer = $Matches[1]; $tShare = $Matches[2]; $tRest = "$($Matches[3])"
            if ($tShare -notmatch '^[A-Za-z]\$$' -and $systemShares -notcontains $tShare.ToUpperInvariant()) {
                $refusal = Get-ShareTreeRefusal -Path $resolved -Server $tServer -Share $tShare -Rest $tRest
            }
        }
        if (-not $refusal) { $refusal = Get-ResolvedRootRefusal -Path $resolved }
        if ($refusal) {
            if ($resolved -ne $display) { $refusal = "$display is $resolved. $refusal" }
            return (& $refuse $refusal $resolved $local)
        }
    }
    New-ChangeTarget -Ok $true -DisplayPath $display -ResolvedPath $resolved -IsRemembered $remembered -IsLocal $local
}

function Resolve-ChangeTargetSet {
    # Get-ChangeTarget for each path (blank ones dropped), as one answer: Ok and Targets, or Ok
    # $false and Refusal (the refused paths' reasons, the first three of them). With
    # -FolderDisplayPath and -FolderRealPath (the folder the selected files are in), a file in
    # that folder takes the folder's resolved location, so the folder is looked up once for the
    # whole batch. Runs in the background ($script:ChangeTargetWork).
    param(
        [AllowEmptyCollection()][AllowNull()][string[]]$Path,
        [hashtable]$DriveMap,
        [hashtable]$DriveMapSource,
        [switch]$WholeTree,
        [string]$FolderDisplayPath,
        [string]$FolderRealPath,
        # Copy permissions targets (D-044): passed on to Get-ChangeTarget.
        [switch]$RefuseProtected
    )
    $paths = @($Path | Where-Object { "$_".Trim() })
    if ($paths.Count -eq 0) { return [PSCustomObject]@{ Ok = $false; Targets = @(); Refusal = 'No folder or file was chosen, so nothing was changed.' } }
    $folder = $null
    $prefix = $null
    if ($FolderDisplayPath -and $FolderRealPath) {
        $folder = Get-ChangeTarget -Path $FolderDisplayPath -DriveMap $DriveMap -DriveMapSource $DriveMapSource
        if ($folder.Ok) { $prefix = $FolderRealPath.TrimEnd('\') + '\' }
    }
    $targets = [System.Collections.Generic.List[object]]::new()
    $refusals = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $paths) {
        if ($prefix -and $p.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            $rest = $p.Substring($prefix.Length)
            if ($rest.Contains(':')) { $refusals.Add((Get-StreamRefusal -Path $p)); continue }
            $targets.Add((New-ChangeTarget -Ok $true -DisplayPath ($folder.DisplayPath.TrimEnd('\') + '\' + $rest) -ResolvedPath ($folder.ResolvedPath.TrimEnd('\') + '\' + $rest) `
                        -IsRemembered $folder.IsRemembered -IsLocal $folder.IsLocal))
            continue
        }
        $t = Get-ChangeTarget -Path $p -DriveMap $DriveMap -DriveMapSource $DriveMapSource -WholeTree:$WholeTree -RefuseProtected:$RefuseProtected
        if ($t.Ok) { $targets.Add($t) } else { $refusals.Add("$($t.Refusal)") }
    }
    if ($refusals.Count -gt 0) {
        $text = @($refusals | Select-Object -First 3) -join "`n"
        if ($refusals.Count -gt 3) { $text += "`n... and $($refusals.Count - 3) more were refused too." }
        return [PSCustomObject]@{ Ok = $false; Targets = @(); Refusal = $text }
    }
    [PSCustomObject]@{ Ok = $true; Targets = $targets.ToArray(); Refusal = $null }
}

function Show-ChangeRefusal {
    # A refused change: the reason in the status line and in a message box, so it is not missed.
    param([Parameter(Mandatory)][string]$Text)
    Set-Status -Kind Error -Text $Text
    Show-AppMessage -Icon Warning -Message $Text
}

function Get-CurrentChangeTarget {
    # The chosen folder as a change target, or $null after saying why there is none. Looks it up
    # on this thread: the window's buttons do that in the background instead (Open-*); this is
    # for Invoke-* called without -Targets (the tests).
    param([switch]$WholeTree)
    if (-not $script:Current) { Set-Status -Kind Warning -Text 'Choose a folder first.'; return $null }
    $set = Resolve-ChangeTargetSet -Path @($script:Current.DisplayPath) -DriveMap $script:MappedDrives -DriveMapSource $script:MappedDriveSources -WholeTree:$WholeTree
    if (-not $set.Ok) { Show-ChangeRefusal -Text $set.Refusal; return $null }
    $set.Targets[0]
}

function Get-SelectedFileTargets {
    # The selected files as change targets (blank entries dropped), or $null after saying why.
    # Files in the chosen folder take its real location (one DFS lookup for the whole batch).
    # Like Get-CurrentChangeTarget, only for Invoke-* called without -Targets.
    $paths = @(Get-SelectedFileRows | ForEach-Object { "$($_.Path)" } | Where-Object { $_.Trim() })
    if ($paths.Count -eq 0) { Set-Status -Kind Warning -Text $script:NoFilesSelectedText; return $null }
    $display = if ($script:Current) { $script:Current.DisplayPath } else { $null }
    $real = if ($script:Current) { $script:Current.RealPath } else { $null }
    $set = Resolve-ChangeTargetSet -Path $paths -DriveMap $script:MappedDrives -DriveMapSource $script:MappedDriveSources -FolderDisplayPath $display -FolderRealPath $real
    if (-not $set.Ok) { Show-ChangeRefusal -Text $set.Refusal; return $null }
    , @($set.Targets)
}
function Format-ItemCount {
    # "1 file", "3 files", "12,408 items" (the number in this computer's format).
    param([Parameter(Mandatory)][long]$Count, [Parameter(Mandatory)][string]$Singular, [Parameter(Mandatory)][string]$Plural)
    $word = if ($Count -eq 1) { $Singular } else { $Plural }
    '{0} {1}' -f $Count.ToString('N0'), $word
}

function Get-ConfirmTargetText {
    # One line per target with its real location when that differs, at most $Max lines.
    param([Parameter(Mandatory)][object[]]$Targets, [int]$Max = 20)
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($t in @($Targets | Select-Object -First $Max)) {
        $lines.Add("  $($t.DisplayPath)")
        if ($t.ResolvedPath -and $t.ResolvedPath -ne $t.DisplayPath) { $lines.Add("    real location: $($t.ResolvedPath)") }
    }
    if (@($Targets).Count -gt $Max) { $lines.Add("  ... and $(@($Targets).Count - $Max) more") }
    $lines -join "`n"
}

function Get-TargetLocationText {
    # "\\fs01\A (real location: \\fs03\A), \\fs01\B": each path with its real location when that
    # differs, at most -Max of them. For the status line.
    param([Parameter(Mandatory)][object[]]$Targets, [int]$Max = 5)
    $all = @($Targets | Where-Object { $_ })
    $parts = @(foreach ($t in @($all | Select-Object -First $Max)) {
            if ($t.ResolvedPath -and $t.ResolvedPath -ne $t.DisplayPath) { "$($t.DisplayPath) (real location: $($t.ResolvedPath))" } else { "$($t.DisplayPath)" }
        })
    $text = $parts -join ', '
    if ($all.Count -gt $Max) { $text += " and $($all.Count - $Max) more" }
    $text
}

function Get-ConfirmSpec {
    # What the confirm dialog says for a change: a title, a body that names every path (and the
    # real location behind a mapped drive or DFS path) and how many items, a button label with a
    # verb, and whether it is destructive (danger style). A target on a remembered mapping adds
    # a warning. Add and Copy are destructive (D-044) for a Deny add, a copy of a folder with
    # explicit Deny entries (or whose entries could not be checked), and a target that is the
    # root of a drive or share (Get-TargetRootKind).
    param(
        [Parameter(Mandatory)][ValidateSet('AddPermission', 'RemovePermission', 'TakeOwnershipFolder', 'TakeOwnershipFiles', 'TakeOwnershipTree', 'CopyPermissions')][string]$Action,
        [Parameter(Mandatory)][object[]]$Targets,
        $Counts,
        [string]$Detail,
        # Copy permissions: the folder copied from.
        $Source,
        # Add permission: the type of the permission being added; Deny is destructive (AC47).
        [ValidateSet('Allow', 'Deny')][string]$Type = 'Allow',
        # Copy permissions: the source folder's explicit Deny entries, one text per entry (AC48).
        [string[]]$DenyEntries = @(),
        # Copy permissions: the source folder's entries could not be checked for Deny entries.
        [switch]$DenyUnchecked
    )
    $n = @($Targets).Count
    $where = Get-ConfirmTargetText -Targets $Targets
    $backup = 'The current permissions are saved to a backup first.'
    $denyNote = 'A Deny blocks access even where another permission allows it, and it reaches every subfolder and file that inherits from there.'
    $rootNote = if ($Action -eq 'AddPermission' -or $Action -eq 'CopyPermissions') { Get-ConfirmRootText -Targets $Targets } else { $null }
    switch ($Action) {
        'AddPermission' {
            $title = if ($Type -eq 'Deny') { 'Add a Deny permission?' } else { 'Add a permission?' }
            $what = if ($n -eq 1) { 'to:' } else { "to these $(Format-ItemCount $n 'item' 'items'):" }
            $body = "Add this permission:`n  $Detail`n`n$what`n$where"
            if ($Type -eq 'Deny') { $body += "`n`n$denyNote" }
            if ($rootNote) { $body += "`n`n$rootNote" }
            $body += "`n`n$backup"
            $verb = if ($Type -eq 'Deny') { 'Add Deny permission' } else { 'Add permission' }
            $label = if ($n -eq 1) { $verb } else { "$verb to $(Format-ItemCount $n 'item' 'items')" }
            $destructive = ($Type -eq 'Deny') -or [bool]$rootNote
        }
        'RemovePermission' {
            $title = 'Remove a permission?'
            # Every explicit entry of the type goes, whatever its level, so no level is named.
            $entryWord = 'entry of that type'
            $asked = $Detail
            if ($Detail -match '^(Allow|Deny) (.+?) for (.+)$') {
                $asked = "all $($Matches[1]) permissions for $($Matches[3])"
                $entryWord = "$($Matches[1]) entry"
            }
            $what = if ($n -eq 1) { 'from:' } else { "from these $(Format-ItemCount $n 'item' 'items'):" }
            $body = "Remove $asked $what`n$where`n`nEvery explicit $entryWord for that user or group is removed, whatever its level. Inherited entries stay. $backup"
            $label = if ($n -eq 1) { 'Remove permission' } else { "Remove permission from $(Format-ItemCount $n 'item' 'items')" }
            $destructive = $true
        }
        'TakeOwnershipFolder' {
            $title = 'Take ownership of this folder?'
            $body = "Take ownership of:`n$where`n`nYou become the owner of this folder only, not of what is in it. The current owner and permissions are saved to a backup first."
            $label = 'Take ownership'
            $destructive = $true
        }
        'TakeOwnershipFiles' {
            $files = Format-ItemCount $n 'file' 'files'
            $title = "Take ownership of $files?"
            $body = "Take ownership of $files`:`n$where`n`nYou become the owner of each one. The current owners and permissions are saved to a backup first."
            $label = "Take ownership of $files"
            $destructive = $true
        }
        'TakeOwnershipTree' {
            $title = 'Take ownership of everything in this folder?'
            # The scope first, counted just now (destructive-operations profile); browser text kept.
            if ($Counts) {
                $folders = [long]$Counts.Folders
                $fileCount = [long]$Counts.Files
                $first = "This will change ownership on $(Format-ItemCount ($folders + $fileCount) 'item' 'items') ($(Format-ItemCount $folders 'folder' 'folders') and $(Format-ItemCount $fileCount 'file' 'files')) under:"
                $notes = [System.Collections.Generic.List[string]]::new()
                $notes.Add('Counted just now, the folder itself included.')
                $notOpened = [long]$Counts.NotOpened
                if ($notOpened -gt 0) { $notes.Add("$(Format-ItemCount $notOpened 'folder' 'folders') in it could not be opened, so what is inside them was not counted.") }
                $links = [long]$Counts.Links
                if ($links -gt 0) {
                    $notes.Add("$(Format-ItemCount $links 'junction or symbolic link' 'junctions or symbolic links') in it are listed but not gone into; nothing is changed if one leads into a Windows folder or somewhere that cannot be checked.")
                }
                $scope = $notes -join ' '
            }
            else {
                $first = 'This will change ownership on ALL files and subfolders under:'
                $scope = 'The folders and files in it could not be counted.'
            }
            $body = "$first`n$where`n`n$scope`n`n" +
            "You become the owner. The current owners will be saved to a backup first.`n`n" +
            'Any folder in it that cannot be opened is skipped and left alone; the result names those folders so you can ask a senior admin to open them.'
            $label = if ($Counts) { "Take ownership of $(Format-ItemCount ([long]$Counts.Folders + [long]$Counts.Files) 'item' 'items')" } else { 'Take ownership of everything' }
            $destructive = $true
        }
        'CopyPermissions' {
            $folders = Format-ItemCount $n 'folder' 'folders'
            $title = 'Copy permissions?'
            $from = "  $Detail"
            if ($Source -and $Source.ResolvedPath -and $Source.ResolvedPath -ne $Source.DisplayPath) { $from += "`n    real location: $($Source.ResolvedPath)" }
            $body = "Add the permissions set directly on:`n$from`n`nto $(if ($n -eq 1) { 'this folder' } else { "these $folders" }):`n$where"
            $denies = @($DenyEntries | Where-Object { "$_".Trim() })
            if ($denies.Count -gt 0) {
                $body += "`n`nThe folder you copy from has $(Format-ItemCount $denies.Count 'Deny permission' 'Deny permissions') of its own, and they are copied too:`n" +
                (@($denies | ForEach-Object { "  $_" }) -join "`n") + "`n$denyNote"
            }
            elseif ($DenyUnchecked) {
                $body += "`n`nThe permissions of the folder you copy from are not loaded in this window, so it could not be checked for Deny permissions of its own. Any it has are copied too. $denyNote"
            }
            if ($rootNote) { $body += "`n`n$rootNote" }
            $body += "`n`n" + 'Nothing is removed. Subfolders that inherit permissions get them too; subfolders that block inheritance are not changed. The current permissions of each folder are saved to a backup first.'
            $label = "Copy permissions to $folders"
            $destructive = ($denies.Count -gt 0) -or [bool]$DenyUnchecked -or [bool]$rootNote
        }
    }
    $rememberedTargets = @(@($Targets) + @($Source) | Where-Object { $_ -and $_.IsRemembered })
    if ($rememberedTargets.Count -gt 0) {
        $body += "`n`nWarning: $($rememberedTargets[0].DisplayPath) is on a remembered drive mapping. Windows remembers where that drive letter pointed, but this window could not see the mapping live, so the real location shown may be out of date. Check it before you go ahead."
    }
    if ($script:WhatIfMode) { $body += "`n`nDry run (WhatIf): nothing will be changed." }
    [PSCustomObject]@{ Title = $title; Body = $body; ActionLabel = $label; IsDestructive = $destructive }
}
function Get-TargetRootKind {
    # Whether a path is the very top of a drive or a share (D-044, AC49): 'DriveRoot' (X:\, or a
    # volume GUID path's root), 'AdminShareRoot' (\\server\X$) or 'ShareRoot' (\\server\share),
    # else $null. A permission set there reaches everything on the drive or share that inherits.
    # Text only, in the spelling ConvertTo-ComparablePath gives (\\?\ dropped, trailing \ too).
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)
    $p = ConvertTo-ComparablePath -Path $Path
    if (-not $p) { return $null }
    if ($p -match '^[A-Za-z]:\\$' -or $p -match '^Volume\{[^\\]*\}$') { return 'DriveRoot' }
    if ($p -match '^\\\\[^\\]+\\([^\\]+)$') {
        if ($Matches[1] -match '^[A-Za-z]\$$') { return 'AdminShareRoot' }
        return 'ShareRoot'
    }
    $null
}

function Get-ConfirmRootText {
    # The confirm's warning for targets that are the root of a drive or share (AC49), naming each
    # one's real location; $null when there is none. The typed path is checked too, so a mapped
    # letter's root (H:\) is caught whatever it points at.
    param([Parameter(Mandatory)][object[]]$Targets)
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($t in @($Targets | Where-Object { $_ })) {
        $kind = Get-TargetRootKind -Path "$($t.ResolvedPath)"
        if (-not $kind) { $kind = Get-TargetRootKind -Path "$($t.DisplayPath)" }
        if (-not $kind) { continue }
        $what = switch ($kind) {
            'DriveRoot' { 'the root of a whole drive' }
            'AdminShareRoot' { 'the root of a whole drive (an administrative share)' }
            default { 'the top of a share' }
        }
        $real = if ($t.ResolvedPath) { "$($t.ResolvedPath)" } else { "$($t.DisplayPath)" }
        $lines.Add("  $real is $what")
    }
    if ($lines.Count -eq 0) { return $null }
    "Warning: a permission set at the top of a drive or share reaches every folder and file on it that inherits permissions.`n" + ($lines -join "`n")
}

function Get-CopySourceDenyEntries {
    # The explicit (not inherited) Deny entries of the folder a copy reads from, as the window
    # loaded them for the chosen folder ($script:ViewState.FolderPermissions, the rows the copy
    # dialog's note uses): Only the folder's own entries are copied (Copy-FolderPermission), so
    # inherited ones are left out. Checked $false when those rows are not loaded, could not be
    # read, or are for another folder than -Source: the caller then confirms as if it had some.
    param([Parameter(Mandatory)]$Source)
    $v = $script:ViewState.FolderPermissions
    $known = $v -and $v.Ok -and $script:Current -and "$($v.Path)" -eq "$($script:Current.RealPath)" -and
    "$($script:Current.DisplayPath)" -eq "$($Source.DisplayPath)"
    if (-not $known) { return [PSCustomObject]@{ Checked = $false; Entries = @() } }
    $entries = @($v.Rows | Where-Object { -not $_.IsInherited -and "$($_.Type)" -eq 'Deny' } | ForEach-Object { "$($_.Identity) (Deny, $($_.Rights))" })
    [PSCustomObject]@{ Checked = $true; Entries = $entries }
}

function Test-TargetResolvedElsewhere {
    # $true when a change target really lands somewhere other than the typed path (a mapped drive,
    # DFS, this computer's own share or admin share), compared in one spelling (AC51).
    param([Parameter(Mandatory)]$Target)
    if (-not $Target.ResolvedPath) { return $false }
    (ConvertTo-ComparablePath -Path "$($Target.ResolvedPath)") -ine (ConvertTo-ComparablePath -Path "$($Target.DisplayPath)")
}

function Set-PermissionSubmitStyle {
    # The add/remove dialog's submit button (AC47, D-044). Remove, and Add with type Deny: the
    # danger style and never the default button, so Enter does not submit them. Add with Allow:
    # the normal style and the default button. Show-PermissionDialog calls it when the dialog
    # opens and whenever the Allow/Deny choice changes.
    # https://learn.microsoft.com/dotnet/api/system.windows.controls.button.isdefault
    param(
        [Parameter(Mandatory)][ValidateSet('Add', 'Remove')][string]$Mode,
        [Parameter(Mandatory)][ValidateSet('Allow', 'Deny')][string]$Type,
        [Parameter(Mandatory)]$Button,
        $DangerStyle,
        $NormalStyle
    )
    $danger = $Mode -eq 'Remove' -or $Type -eq 'Deny'
    $Button.Style = if ($danger) { $DangerStyle } else { $NormalStyle }
    $Button.IsDefault = -not $danger
}

function Set-ConfirmDialog {
    # Fills in the confirm dialog. The action button carries the verb, gets the danger style for
    # a destructive change, and is never the default button (Cancel is, in the XAML).
    param([Parameter(Mandatory)]$Spec, [Parameter(Mandatory)]$TitleBlock, [Parameter(Mandatory)]$BodyBox, [Parameter(Mandatory)]$ActionButton, $DangerStyle, $NormalStyle)
    $TitleBlock.Text = $Spec.Title
    $BodyBox.Text = $Spec.Body
    $ActionButton.Content = $Spec.ActionLabel
    $ActionButton.Style = if ($Spec.IsDestructive) { $DangerStyle } else { $NormalStyle }
    $ActionButton.IsDefault = $false
}

function New-AppDialog {
    # A dialog window from XAML, owned by the main window and in its theme. Not shown.
    param([Parameter(Mandatory)][string]$Xaml)
    $dlg = [System.Windows.Markup.XamlReader]::Parse($Xaml)
    if ($script:Window) { $dlg.Owner = $script:Window }
    if ($script:CurrentTheme) { Set-ThemeBrushes -Resources $dlg.Resources -Name $script:CurrentTheme }
    $dlg
}

function Show-ConfirmDialog {
    # $true only when the tech pressed the action button. Enter and Esc both mean Cancel.
    # https://learn.microsoft.com/dotnet/api/system.windows.window.dialogresult
    param([Parameter(Mandatory)]$Spec)
    $dlg = New-AppDialog -Xaml (Get-ConfirmDialogXaml)
    $dlg.Title = $Spec.Title
    $action = $dlg.FindName('ConfirmActionBtn')
    Set-ConfirmDialog -Spec $Spec -TitleBlock $dlg.FindName('ConfirmTitle') -BodyBox $dlg.FindName('ConfirmBody') -ActionButton $action `
        -DangerStyle $dlg.Resources['DangerBtn'] -NormalStyle $dlg.Resources['PrimaryBtn']
    $action.Add_Click({ param($s, $e) [System.Windows.Window]::GetWindow($s).DialogResult = $true })
    $dlg.Add_ContentRendered({ param($s, $e) $s.FindName('ConfirmCancelBtn').Focus() | Out-Null })
    $dlg.ShowDialog() -eq $true
}

function Get-ChangeStatus {
    # The status line for a change result, as the browser version showed it
    # (changeStatusType / showChangeResult and ConvertTo-ChangeResultRow there):
    #   - a whole-tree result that was only partly done or could not be checked everywhere: Warning;
    #   - something failed and nothing was done: Error (also when other items were already up
    #     to date);
    #   - every item already had what was asked (Skipped (nothing to copy)): Info;
    #   - something failed or was not found (every item not found too), the log was not
    #     written, or items cannot be restored from the backup: Warning; else Success.
    # A Warning starts "Partly done: " when some items were done and others failed or were not
    # found, "Nothing was changed: " when nothing was done (every item not found), else "Done,
    # with items to check: ", unless the message already starts "Partly done:".
    # Deliberate deviation: a dry run (every row Skipped (WhatIf)) is Info; the browser showed it
    # as an error.
    # Added by the app's read-back (Add-ChangeReadBack), which the browser did not have: an item
    # whose read-back did not show the intended state (CheckProblem) makes a Success or Info a
    # Warning and is named after "Check this: <path> - <reason>"; a remove that had nothing to
    # remove anywhere (NothingRemoved on every row) is Info "Nothing was removed: ...", and one
    # that had nothing to remove on some items only is a Warning that names them.
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries,
        [AllowNull()][string]$LogPath,
        [Parameter(Mandatory)][string]$Message
    )
    $all = @($Entries | Where-Object { $null -ne $_ })
    $result = { param($kind, $text) [PSCustomObject]@{ Kind = $kind; Text = $text } }
    if ($all.Count -eq 0) { return (& $result 'Info' $Message) }
    if (@($all | Where-Object { $_.Result -ne 'Skipped (WhatIf)' }).Count -eq 0) { return (& $result 'Info' $Message) }

    $noops = @($all | Where-Object { $_.PSObject.Properties['NothingRemoved'] -and $_.NothingRemoved })
    $problems = @($all | Where-Object { $_.PSObject.Properties['CheckProblem'] -and "$($_.CheckProblem)" })
    $who = 'that user or group'; $type = 'Allow or Deny'
    if ($noops.Count -gt 0 -and "$($noops[0].Detail)" -match '^(Allow|Deny) (.+?) for (.+)$') { $type = $Matches[1]; $who = $Matches[3] }
    if ($noops.Count -gt 0 -and $noops.Count -eq $all.Count) {
        $names = @($noops | Select-Object -First 3 | ForEach-Object { "$($_.Target)" }) -join ', '
        if ($noops.Count -gt 3) { $names += " and $($noops.Count - 3) more" }
        $text = if ($all.Count -eq 1) { "Nothing was removed: $who had no explicit $type entry here. $names was left as it was." }
        else { "Nothing was removed: $who had no explicit $type entry on any of these $($all.Count) items ($names)." }
        $text += ' It may be inherited: remove it on the folder above.'
        if ($LogPath) { $text += " Logged to $LogPath." }
        return (& $result 'Info' $text)
    }

    $done = @($all | Where-Object { $_.Result -eq 'Done' }).Count
    $notFound = @($all | Where-Object { $_.Result -eq 'Skipped (not found)' }).Count
    $unchanged = @($all | Where-Object { $_.Result -eq 'Skipped (nothing to copy)' }).Count
    $failed = $all.Count - $done - $notFound - $unchanged
    $incomplete = @($all | Where-Object { Test-TreeEntryIncomplete $_ }).Count
    $doneOrPartly = @($all | Where-Object { $_.Result -eq 'Done' -or $_.Result -eq 'Partly done' }).Count
    $partly = @($all | Where-Object { $_.Result -eq 'Partly done' }).Count
    # The browser's single-folder 'partial': every row Done or Partly done, and not all clean.
    $partial = $doneOrPartly -eq $all.Count -and ($partly -gt 0 -or $incomplete -gt 0)

    $kind = if ($partial) { 'Warning' }
    elseif ($failed -gt 0 -and $done -eq 0) { 'Error' }
    elseif ($unchanged -eq $all.Count) { 'Info' }
    elseif ($failed -gt 0 -or $notFound -gt 0 -or -not $LogPath -or (Get-UnrestorableItemCount -Entries $all) -gt 0) { 'Warning' }
    else { 'Success' }
    if (($problems.Count -gt 0 -or $noops.Count -gt 0) -and ($kind -eq 'Success' -or $kind -eq 'Info')) { $kind = 'Warning' }

    $text = $Message
    if ($noops.Count -gt 0) {
        $names = @($noops | Select-Object -First 3 | ForEach-Object { "$($_.Target)" }) -join ', '
        if ($noops.Count -gt 3) { $names += " and $($noops.Count - 3) more" }
        $text += " Nothing was removed from $($names): $who had no explicit $type entry there. It may be inherited: remove it on the folder above."
    }
    if ($problems.Count -gt 0) {
        $named = @($problems | Select-Object -First 3 | ForEach-Object { "$($_.Target) - $($_.CheckProblem)" }) -join '; '
        if ($problems.Count -gt 3) { $named += " (and $($problems.Count - 3) more)" }
        $text += " Check this: $named. Press Refresh to see what is there now. If it is still wrong after Refresh, check the change log or ask a senior admin."
    }
    if ($kind -eq 'Warning' -and -not $Message.StartsWith('Partly done:')) {
        $someDone = $done -gt 0
        $someShort = $failed -gt 0 -or $notFound -gt 0
        $prefix = if ($someDone -and $someShort) { 'Partly done: ' } elseif (-not $someDone -and $partly -eq 0) { 'Nothing was changed: ' } else { 'Done, with items to check: ' }
        $text = $prefix + $text
    }
    & $result $kind $text
}
function Get-RefreshPlan {
    # What to read again after a change, given the folder shown now (-CurrentPath):
    #   Folder: that folder's permissions and files when it is still shown; its tree entry always.
    #   Tree:   the same for the shown folder when it is the changed folder or inside it.
    #   Files:  drop the changed files' cached permissions; read again those still shown in the
    #           changed folder.
    param(
        [Parameter(Mandatory)][ValidateSet('Folder', 'Files', 'Tree')][string]$Scope,
        [Parameter(Mandatory)][string]$Path,
        [AllowNull()][string]$CurrentPath,
        [string[]]$ChangedFiles,
        [string[]]$ShownFiles
    )
    $p = "$Path".Trim().TrimEnd('\', '/')
    $c = "$CurrentPath".Trim().TrimEnd('\', '/')
    $same = [bool]$c -and $p.Equals($c, [StringComparison]::OrdinalIgnoreCase)
    $inside = $same -or ([bool]$c -and [bool]$p -and $c.StartsWith("$p\", [StringComparison]::OrdinalIgnoreCase))
    $reload = $false; $tree = $false
    $drop = [string[]]@(); $again = [string[]]@()
    switch ($Scope) {
        'Folder' { $reload = $same; $tree = $true }
        'Tree' { $reload = $inside; $tree = $true }
        'Files' {
            $drop = [string[]]@($ChangedFiles | Where-Object { $_ })
            if ($same) { $again = [string[]]@($drop | Where-Object { @($ShownFiles) -contains $_ }) }
        }
    }
    [PSCustomObject]@{ ReloadPermissions = $reload; ReloadFiles = $reload; RefreshTreeEntry = $tree; DropFileAcl = $drop; ReloadFileAcl = $again }
}

function Remove-CachedFileAcl {
    # Forgets the permissions read for these files, so they are read again when shown.
    param([Parameter(Mandatory)][string[]]$Path)
    foreach ($p in $Path) {
        if ($p -and $script:FileAclCache.ContainsKey($p)) { $script:FileAclCache.Remove($p) }
    }
}

function ConvertTo-RightsName {
    # Rights as the core takes them (a FileSystemRights name) without Synchronize, which Windows
    # adds to every Allow entry ('Modify, Synchronize' is Modify). Empty or unreadable gives
    # FullControl: Remove-FolderPermission removes every explicit entry of the type whatever its
    # rights and only records them in the log's Detail.
    # https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.filesystemrights
    param([AllowNull()][AllowEmptyString()][string]$Rights)
    if (-not "$Rights".Trim()) { return 'FullControl' }
    try { $r = [System.Security.AccessControl.FileSystemRights]"$Rights" } catch { return 'FullControl' }
    $value = [int]$r -band (-bnot [int][System.Security.AccessControl.FileSystemRights]::Synchronize)
    if ($value -eq 0) { return "$r" }
    "$([System.Enum]::ToObject([System.Security.AccessControl.FileSystemRights], $value))"
}

function Get-RemoveIdentityChoices {
    # Who can be removed: only EXPLICIT entries (an inherited one is removed on the folder above,
    # not here), one choice per account, keyed by its SID (a renamed account, or two names for
    # one SID, is one choice), in table order, with the types (Allow, Deny) it has explicit
    # entries of and their rights. For the folder, its permission table; for the selected
    # files, the union of their loaded permissions, plus the files whose permissions are not
    # loaded yet (NotLoaded), to be read first. Identities: each name once, for the status line.
    param([Parameter(Mandatory)][ValidateSet('Folder', 'Files')][string]$Scope)
    $choices = [ordered]@{}
    $notLoaded = [System.Collections.Generic.List[string]]::new()
    $addRow = {
        param($r)
        if ($null -eq $r -or $r.IsInherited) { return }
        $id = "$($r.Identity)".Trim()
        if (-not $id) { return }
        $sid = "$($r.Sid)".Trim()
        $key = if ($sid) { "sid:$sid" } else { "name:$($id.ToLowerInvariant())" }
        if (-not $choices.Contains($key)) {
            $choices[$key] = [PSCustomObject]@{ Key = $key; Sid = $sid; Identity = $id; Types = [System.Collections.Generic.List[string]]::new(); Rights = @{} }
        }
        $c = $choices[$key]
        $type = "$($r.Type)"
        if (@('Allow', 'Deny') -contains $type) {
            if (-not $c.Types.Contains($type)) { $c.Types.Add($type) }
            if (-not $c.Rights.ContainsKey($type)) { $c.Rights[$type] = ConvertTo-RightsName -Rights "$($r.Rights)" }
        }
    }
    if ($Scope -eq 'Folder') {
        $v = $script:ViewState.FolderPermissions
        if ($v) { foreach ($r in @($v.Rows)) { & $addRow $r } }
    }
    else {
        foreach ($p in @(Get-SelectedFileRows | ForEach-Object { "$($_.Path)" } | Where-Object { $_.Trim() })) {
            if (-not $script:FileAclCache.ContainsKey($p)) { $notLoaded.Add($p); continue }
            foreach ($r in @($script:FileAclCache[$p].Rows)) { & $addRow $r }
        }
    }
    $list = @(foreach ($c in $choices.Values) {
            $types = @(@('Allow', 'Deny') | Where-Object { $c.Types.Contains($_) })
            $label = if ($types.Count -eq 2) { "$($c.Identity) (Allow and Deny)" } elseif ($types.Count -eq 1) { "$($c.Identity) ($($types[0]))" } else { $c.Identity }
            [PSCustomObject]@{
                Key         = $c.Key
                Sid         = $c.Sid
                Identity    = $c.Identity
                Types       = $types
                Rights      = $c.Rights
                Label       = $label
                DefaultType = $(if ($types -contains 'Allow' -or $types.Count -eq 0) { 'Allow' } else { 'Deny' })
            }
        })
    $ids = [System.Collections.Generic.List[string]]::new()
    foreach ($c in $list) { if (-not ($ids | Where-Object { $_ -ieq $c.Identity })) { $ids.Add($c.Identity) } }
    [PSCustomObject]@{ Identities = $ids.ToArray(); Choices = $list; NotLoaded = $notLoaded.ToArray() }
}

function Get-RemoveTypeChoice {
    # Which of Allow and Deny the remove dialog lets the tech pick for a user or group, and
    # which is selected: only the types it has explicit entries of, so a Deny-only account gives
    # Deny; Allow when it has both.
    param([Parameter(Mandatory)]$Choice)
    $allowed = @(@($Choice.Types) | Where-Object { $_ })
    if ($allowed.Count -eq 0) { $allowed = @('Allow', 'Deny') }
    $default = if ($allowed -contains 'Allow') { 'Allow' } else { 'Deny' }
    [PSCustomObject]@{ Default = $default; Allowed = $allowed }
}
function Get-PermissionInputError {
    # $null when the add dialog's user or group can be used; otherwise what to fix.
    param([AllowNull()][AllowEmptyString()][string]$Identity)
    if (-not "$Identity".Trim()) { return 'Enter a user or group, for example CONTOSO\HR-Staff.' }
    $null
}

function Get-ChangeScopeTargets {
    # The chosen folder, or the selected files, as change targets; $null after saying why not.
    param([Parameter(Mandatory)][ValidateSet('Folder', 'Files')][string]$Scope)
    if ($Scope -eq 'Folder') {
        $t = Get-CurrentChangeTarget
        if ($t) { return , @($t) }
        return $null
    }
    Get-SelectedFileTargets
}

function Get-ChangeLabel {
    # How the busy line and the "still running" texts name what a change is on.
    param([Parameter(Mandatory)][ValidateSet('Folder', 'Files')][string]$Scope, [Parameter(Mandatory)][object[]]$Targets)
    if ($Scope -eq 'Folder') { return $Targets[0].DisplayPath }
    $files = Format-ItemCount @($Targets).Count 'file' 'files'
    if ($script:Current) { return "$files in $($script:Current.DisplayPath)" }
    $files
}

function New-ChangeRefreshState {
    # What Invoke-ChangeRefresh needs once the change is done.
    param([Parameter(Mandatory)][ValidateSet('Folder', 'Files', 'Tree')][string]$Scope, [string[]]$Paths, [string[]]$ChangedFiles)
    @{ Scope = $Scope; Paths = @($Paths); ChangedFiles = @($ChangedFiles); Node = $script:CurrentNode }
}

function Get-ScopeRefreshState {
    param([Parameter(Mandatory)][ValidateSet('Folder', 'Files')][string]$Scope, [Parameter(Mandatory)][object[]]$Targets)
    if ($Scope -eq 'Folder') { return (New-ChangeRefreshState -Scope Folder -Paths @($Targets[0].DisplayPath)) }
    $folder = if ($script:Current) { $script:Current.DisplayPath } else { '' }
    New-ChangeRefreshState -Scope Files -Paths @($folder) -ChangedFiles @(Get-SelectedFileRows | ForEach-Object { "$($_.Path)" } | Where-Object { $_.Trim() })
}

function Test-NoOtherChangePending {
    # Invoke-* called without -Targets starts a change of its own: $false (after saying why)
    # while another one is being prepared.
    if (-not $script:ChangePending) { return $true }
    Set-Status -Kind Warning -Text (Get-ChangeControlState).Reason
    $false
}

function Invoke-AddPermission {
    # Adds a permission to the chosen folder or the selected files. For a plain Allow on ordinary
    # folders the add dialog is the confirmation (as in the browser version). The confirm dialog
    # opens first, with the real locations, for a Deny (AC47) or a target that is the root of a
    # drive or share (AC49), both destructive (D-044), and for a target on a remembered mapping.
    # -Targets: where the change lands, worked out in the
    # background before the dialog opened (Open-AddPermission), with -Label and -RefreshState
    # fixed at the click. Without -Targets they are worked out here, on this thread: only the
    # tests call it that way.
    param(
        [Parameter(Mandatory)][ValidateSet('Folder', 'Files')][string]$Scope,
        [string]$Identity,
        [string]$Rights,
        [ValidateSet('Allow', 'Deny')][string]$Type = 'Allow',
        [object[]]$Targets,
        [string]$Label,
        [hashtable]$RefreshState
    )
    $problem = Get-PermissionInputError -Identity $Identity
    if ($problem) { Set-Status -Kind Warning -Text $problem; return }
    $Identity = $Identity.Trim()
    if (-not $PSBoundParameters.ContainsKey('Targets')) {
        if (-not (Test-NoOtherChangePending)) { return }
        $Targets = Get-ChangeScopeTargets -Scope $Scope
        if (-not $Targets) { return }
    }
    if (-not $Label) { $Label = Get-ChangeLabel -Scope $Scope -Targets $Targets }
    if (-not $RefreshState) { $RefreshState = Get-ScopeRefreshState -Scope $Scope -Targets $Targets }
    $detail = "$Type $Rights for $Identity"
    $remembered = @($Targets | Where-Object { $_.IsRemembered }).Count -gt 0
    if ($remembered -or $Type -eq 'Deny' -or (Get-ConfirmRootText -Targets $Targets)) {
        if (-not (Show-ConfirmDialog -Spec (Get-ConfirmSpec -Action AddPermission -Targets $Targets -Detail $detail -Type $Type))) {
            Set-Status -Text 'Cancelled: nothing was changed.'
            return
        }
    }
    $paths = [string[]]@($Targets | ForEach-Object { $_.ResolvedPath })
    $started = Start-ChangeTask -Action 'Adding a permission on' -Path $Label -Work $script:AddPermissionWork `
        -ArgumentList @($paths, $Identity, $Rights, $Type, $script:ChangeLogFolder, [bool]$script:WhatIfMode, $script:CorePath) `
        -State $RefreshState -OnDone { param($result, $state) Complete-ChangeTask -Result $result -State $state }
    if ($started) {
        $text = if ($Scope -eq 'Files') { "Backing up and adding the permission to $(Format-ItemCount $paths.Count 'file' 'files')..." } else { "Backing up and adding the permission to $(Get-TargetLocationText -Targets $Targets)..." }
        Set-Status -Text $text
    }
}

function Invoke-RemovePermission {
    # Removes a user or group's explicit Allow or Deny entries from the chosen folder or the
    # selected files, after the confirm dialog. -Sid: the account chosen in the remove dialog
    # (the core removes by name; the read-back checks this SID). -Targets, -Label and
    # -RefreshState as for Invoke-AddPermission.
    param(
        [Parameter(Mandatory)][ValidateSet('Folder', 'Files')][string]$Scope,
        [string]$Identity,
        [string]$Rights,
        [ValidateSet('Allow', 'Deny')][string]$Type = 'Allow',
        [string]$Sid,
        [object[]]$Targets,
        [string]$Label,
        [hashtable]$RefreshState
    )
    if (-not $PSBoundParameters.ContainsKey('Targets')) {
        if (-not (Test-NoOtherChangePending)) { return }
        $Targets = Get-ChangeScopeTargets -Scope $Scope
        if (-not $Targets) { return }
    }
    $problem = Get-PermissionInputError -Identity $Identity
    if ($problem) { Set-Status -Kind Warning -Text $problem; return }
    $Identity = $Identity.Trim()
    if (-not $Label) { $Label = Get-ChangeLabel -Scope $Scope -Targets $Targets }
    if (-not $RefreshState) { $RefreshState = Get-ScopeRefreshState -Scope $Scope -Targets $Targets }
    if (-not "$Rights".Trim()) { $Rights = 'FullControl' }
    $detail = "$Type $Rights for $Identity"
    if (-not (Show-ConfirmDialog -Spec (Get-ConfirmSpec -Action RemovePermission -Targets $Targets -Detail $detail))) {
        Set-Status -Text 'Cancelled: nothing was changed.'
        return
    }
    $paths = [string[]]@($Targets | ForEach-Object { $_.ResolvedPath })
    $started = Start-ChangeTask -Action 'Removing a permission from' -Path $Label -Work $script:RemovePermissionWork `
        -ArgumentList @($paths, $Identity, $Rights, $Type, $script:ChangeLogFolder, [bool]$script:WhatIfMode, "$Sid", $script:CorePath) `
        -State $RefreshState -OnDone { param($result, $state) Complete-ChangeTask -Result $result -State $state }
    if ($started) {
        $text = if ($Scope -eq 'Files') { "Backing up and removing the permission from $(Format-ItemCount $paths.Count 'file' 'files')..." } else { "Backing up and removing the permission from $(Get-TargetLocationText -Targets $Targets)..." }
        Set-Status -Text $text
    }
}

function Invoke-TakeOwnership {
    # Take ownership of the chosen folder only, of the selected files, or (Tree) of the folder
    # and everything in it. Tree: refused on drive roots, Windows folders and the high-impact
    # roots (D-036, on the real location), then the items are counted in the background while
    # the change is pending (no other change can start), then the confirm dialog shows the
    # count, then the change runs. Nothing starts if the tech says no. -Targets, -Label and
    # -RefreshState as for Invoke-AddPermission.
    param(
        [Parameter(Mandatory)][ValidateSet('Folder', 'Files', 'Tree')][string]$Scope,
        [object[]]$Targets,
        [string]$Label,
        [hashtable]$RefreshState
    )
    $fromLookup = $PSBoundParameters.ContainsKey('Targets')
    if ($Scope -eq 'Tree') {
        if ($fromLookup) { $target = @($Targets)[0] }
        else {
            if (-not (Test-NoOtherChangePending)) { return }
            $target = Get-CurrentChangeTarget -WholeTree
            if (-not $target) { return }
        }
        if ($script:ChangeTask) {
            Set-Status -Kind Warning -Text "Another change is still running on $($script:ChangeTask.Path). Wait for it to finish."
            return
        }
        # Pending from the click's lookup already; a direct call starts its own.
        if (-not $fromLookup -and -not (Enter-ChangePending -Action 'Take Ownership of all subfolders and files' -Path $target.DisplayPath)) { return }
        $node = if ($RefreshState -and $RefreshState.Node) { $RefreshState.Node } else { $script:CurrentNode }
        Set-Status -Text "Counting the folders and files in $($target.DisplayPath) before asking. Nothing has been changed."
        [void](Start-ChangePrepRead -Action 'Counting the folders and files in' -Path $target.DisplayPath -Work $script:TreeCountWork `
                -ArgumentList @($target.ResolvedPath, $script:CorePath) -State @{ Target = $target; Node = $node } -OnDone {
                param($result, $s)
                Confirm-TreeOwnership -Count $result -Target $s.Target -Node $s.Node
            })
        return
    }
    if (-not $fromLookup) {
        if (-not (Test-NoOtherChangePending)) { return }
        $Targets = Get-ChangeScopeTargets -Scope $Scope
        if (-not $Targets) { return }
    }
    if (-not $Label) { $Label = Get-ChangeLabel -Scope $Scope -Targets $Targets }
    if (-not $RefreshState) { $RefreshState = Get-ScopeRefreshState -Scope $Scope -Targets $Targets }
    $action = if ($Scope -eq 'Files') { 'TakeOwnershipFiles' } else { 'TakeOwnershipFolder' }
    if (-not (Show-ConfirmDialog -Spec (Get-ConfirmSpec -Action $action -Targets $Targets))) {
        Set-Status -Text 'Cancelled: nothing was changed.'
        return
    }
    $paths = [string[]]@($Targets | ForEach-Object { $_.ResolvedPath })
    $started = Start-ChangeTask -Action 'Taking ownership of' -Path $Label -Work $script:TakeOwnershipWork `
        -ArgumentList @($paths, $false, $script:ChangeLogFolder, [bool]$script:WhatIfMode, $script:CorePath) `
        -State $RefreshState -OnDone { param($result, $state) Complete-ChangeTask -Result $result -State $state }
    if ($started) {
        $text = if ($Scope -eq 'Files') { "Backing up and taking ownership of $(Format-ItemCount $paths.Count 'file' 'files')..." } else { "Backing up and taking ownership of $(Get-TargetLocationText -Targets $Targets)..." }
        Set-Status -Text $text
    }
}
function Confirm-TreeOwnership {
    # The count for a whole-tree take ownership arrived: ask with it, then start the change.
    # When the count failed, or a link in the tree is refused (LinkRefusal), nothing goes ahead
    # and no confirm opens (the scope must be shown before confirming).
    param([AllowNull()]$Count, [Parameter(Mandatory)]$Target, $Node)
    if (-not ($Count -and $Count.Ok)) {
        $why = if ($Count -and "$($Count.Error)".Trim()) { "$($Count.Error)".Trim() } else { 'No reason was given.' }
        Set-Status -Kind Error -Text "Could not count what is in $($Target.DisplayPath), so nothing was changed. $why"
        return
    }
    # A junction or symbolic link in it leads into a protected folder, or nobody can tell where.
    if ($Count.PSObject.Properties['LinkRefusal'] -and "$($Count.LinkRefusal)".Trim()) {
        Show-ChangeRefusal -Text "$("$($Count.LinkRefusal)".Trim()) Nothing was changed."
        return
    }
    if ($script:ChangeTask) {
        Set-Status -Kind Warning -Text "Another change is still running on $($script:ChangeTask.Path). Wait for it to finish."
        return
    }
    if (-not (Show-ConfirmDialog -Spec (Get-ConfirmSpec -Action TakeOwnershipTree -Targets @($Target) -Counts $Count))) {
        Set-Status -Text 'Cancelled: nothing was changed.'
        return
    }
    $state = @{ Scope = 'Tree'; Paths = @($Target.DisplayPath); ChangedFiles = @(); Node = $Node }
    $started = Start-ChangeTask -Action 'Taking ownership of everything in' -Path $Target.DisplayPath -Work $script:TakeOwnershipWork `
        -ArgumentList @([string[]]@($Target.ResolvedPath), $true, $script:ChangeLogFolder, [bool]$script:WhatIfMode, $script:CorePath) `
        -State $state -OnDone { param($result, $state) Complete-ChangeTask -Result $result -State $state }
    if ($started) { Set-Status -Text 'Saving the current owners and taking ownership of everything in this folder. This can take a while...' }
}

function ConvertTo-TargetPathList {
    # The copy dialog's text as a list of paths: one per line, trimmed, blank lines dropped.
    param([AllowNull()][AllowEmptyString()][string]$Text)
    , [string[]]@("$Text" -split "`r?`n" | ForEach-Object { $_.Trim().Trim('"') } | Where-Object { $_ })
}

function Invoke-CopyPermissions {
    # Copies the chosen folder's own permissions to each folder listed (adds only, D-031).
    # Refused, before anything is asked, when a target is an administrative share, SYSVOL,
    # NETLOGON, a D-036 folder or a high-impact root (AC50, Get-CopyTargetRefusal). The copy
    # dialog is the confirmation only when every target resolves to itself and nothing below
    # applies; otherwise the confirm dialog opens first with the real locations (D-044): the
    # source has explicit Deny entries or they could not be checked (AC48), a target is the root
    # of a drive or share (AC49), a target really lands somewhere other than what was typed
    # (AC51), or a folder is on a remembered mapping. -Source and -Targets: where the change
    # lands, worked out in the background (Open-CopyPermissions: the source before the dialog,
    # the typed folders after it); the status line names their real locations. Without them
    # they are worked out here from -TargetText: only the tests do that.
    param([AllowNull()][AllowEmptyString()][string]$TargetText, $Source, [object[]]$Targets)
    if (-not $PSBoundParameters.ContainsKey('Targets')) {
        $lines = ConvertTo-TargetPathList -Text $TargetText
        if ($lines.Count -eq 0) { Set-Status -Kind Warning -Text $script:NoTargetPathText; return }
        if (-not (Test-NoOtherChangePending)) { return }
        $Source = Get-CurrentChangeTarget
        if (-not $Source) { return }
        $set = Resolve-ChangeTargetSet -Path $lines -DriveMap $script:MappedDrives -DriveMapSource $script:MappedDriveSources -RefuseProtected
        if (-not $set.Ok) { Show-ChangeRefusal -Text $set.Refusal; return }
        $Targets = @($set.Targets)
    }
    if (@($Targets).Count -eq 0) { Set-Status -Kind Warning -Text $script:NoTargetPathText; return }
    # The lookup refused these already; checked again on what is about to be changed (text only).
    $refused = @(foreach ($t in @($Targets)) {
            $r = Get-CopyTargetRefusal -Path "$($t.ResolvedPath)"
            if ($r) { if ($t.ResolvedPath -ne $t.DisplayPath) { "$($t.DisplayPath) is $($t.ResolvedPath). $r" } else { $r } }
        })
    if ($refused.Count -gt 0) { Show-ChangeRefusal -Text (@($refused | Select-Object -First 3) -join "`n"); return }
    $deny = Get-CopySourceDenyEntries -Source $Source
    $remembered = @(@($Source) + @($Targets) | Where-Object { $_.IsRemembered }).Count -gt 0
    $elsewhere = @($Targets | Where-Object { Test-TargetResolvedElsewhere -Target $_ }).Count -gt 0
    if ($remembered -or $elsewhere -or -not $deny.Checked -or @($deny.Entries).Count -gt 0 -or (Get-ConfirmRootText -Targets $Targets)) {
        $spec = Get-ConfirmSpec -Action CopyPermissions -Targets $Targets -Detail $Source.DisplayPath -Source $Source `
            -DenyEntries @($deny.Entries) -DenyUnchecked:(-not $deny.Checked)
        if (-not (Show-ConfirmDialog -Spec $spec)) {
            Set-Status -Text 'Cancelled: nothing was changed.'
            return
        }
    }
    $state = @{ Scope = 'Tree'; Paths = @($Targets | ForEach-Object { $_.DisplayPath }); ChangedFiles = @(); Node = $null }
    $started = Start-ChangeTask -Action 'Copying permissions from' -Path $Source.DisplayPath -Work $script:CopyPermissionsWork `
        -ArgumentList @($Source.ResolvedPath, [string[]]@($Targets | ForEach-Object { $_.ResolvedPath }), $script:ChangeLogFolder, [bool]$script:WhatIfMode, $script:CorePath) `
        -State $state -OnDone { param($result, $state) Complete-ChangeTask -Result $result -State $state }
    if ($started) {
        Set-Status -Text "Backing up and copying the permissions of $(Get-TargetLocationText -Targets @($Source)) to $(Get-TargetLocationText -Targets $Targets)..."
    }
}

function Get-SyncFolderOf {
    # The OneDrive or SharePoint sync folder a local path is in, or $null: one of -SyncRoot
    # (Get-OneDriveFolder), or a folder starting with OneDrive in a user profile
    # (Test-OneDriveLikePath). Text only.
    param([AllowNull()][AllowEmptyString()][string]$Path, [AllowEmptyCollection()][AllowNull()][string[]]$SyncRoot)
    if (-not $Path) { return $null }
    $roots = @($SyncRoot | Where-Object { "$_".Trim() })
    foreach ($r in $roots) { if (Test-PathWithin -Path $Path -Root $r) { return $r } }
    if (Test-OneDriveLikePath -Path $Path -KnownRoot $roots) { return 'a OneDrive folder' }
    $null
}

function Get-AppDefaultLogFolder {
    # The default log folder: the Logs folder next to the script, unless that is inside a
    # OneDrive or SharePoint sync folder. Backups and the change log hold client folder paths
    # and account names and must not be uploaded, so %LOCALAPPDATA%\FolderPermissionManager\Logs
    # (the folder the core falls back to) is the default then. Resolve-ChangeLogFolder checks
    # it as usual.
    param([Parameter(Mandatory)][string]$ScriptLogsFolder, [AllowNull()][AllowEmptyString()][string]$LocalAppData, [AllowEmptyCollection()][AllowNull()][string[]]$SyncRoot)
    if ($LocalAppData -and (Get-SyncFolderOf -Path $ScriptLogsFolder -SyncRoot $SyncRoot)) {
        return (Join-Path $LocalAppData 'FolderPermissionManager\Logs')
    }
    $ScriptLogsFolder
}

function Get-SyncedLogFolderNotice {
    # The banner warnings about a log folder and the OneDrive or SharePoint sync folders: a
    # -LogFolder inside one is used as given, with a warning; a script inside one logs to
    # %LOCALAPPDATA% instead (Get-AppDefaultLogFolder), and the banner says why; when
    # %LOCALAPPDATA% is not known either, the script's own Logs folder is used and the banner
    # warns that it is uploaded. -LogFolder is the folder the change log really goes to (startup
    # passes the resolved one); a relative path is made full against the current location
    # first, so it is compared with the sync folders where it really is.
    # https://learn.microsoft.com/dotnet/api/system.management.automation.pathintrinsics.getunresolvedproviderpathfrompspath
    param(
        [AllowNull()][AllowEmptyString()][string]$LogFolder,
        [Parameter(Mandatory)][string]$ScriptLogsFolder,
        [Parameter(Mandatory)][string]$DefaultFolder,
        [AllowEmptyCollection()][AllowNull()][string[]]$SyncRoot
    )
    if ($LogFolder) {
        if ($LogFolder -notmatch '^([A-Za-z]:\\|\\\\)') {
            try { $LogFolder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogFolder) } catch { Write-Verbose "Could not make $LogFolder a full path: $($_.Exception.Message)" }
        }
        $where = Get-SyncFolderOf -Path $LogFolder -SyncRoot $SyncRoot
        if (-not $where) { return @() }
        return , @("The log folder $LogFolder is inside $where (OneDrive or a synced SharePoint library), so backups and the change log, which hold client folder paths and account names, are uploaded to the cloud. Start the tool again with -LogFolder set to a local folder outside OneDrive.")
    }
    $where = Get-SyncFolderOf -Path $ScriptLogsFolder -SyncRoot $SyncRoot
    if (-not $where) { return @() }
    if ($DefaultFolder -ne $ScriptLogsFolder) {
        return , @("This script is inside $where (OneDrive or a synced SharePoint library), so backups and the change log go to $DefaultFolder on this computer instead of $($ScriptLogsFolder): they hold client folder paths and account names and must not be uploaded.")
    }
    , @("This script is inside $where (OneDrive or a synced SharePoint library), and this session has no %LOCALAPPDATA% folder to use instead, so backups and the change log go to $ScriptLogsFolder and are uploaded to the cloud. They hold client folder paths and account names: start the tool again with -LogFolder set to a local folder outside OneDrive.")
}
function Get-LogFolderMappingNotice {
    # A warning for the window's banner when -LogFolder is on a drive letter that only Windows'
    # remembered mappings explain: backups and the change log would go to a place this window
    # could not see live, which may be out of date.
    param([string]$LogFolder, [hashtable]$DriveMap, [hashtable]$DriveMapSource)
    if (-not $LogFolder -or $LogFolder -notmatch '^([A-Za-z]):') { return @() }
    $letter = $Matches[1].ToUpper()
    if (-not $DriveMapSource -or "$($DriveMapSource[$letter])" -ne 'Remembered' -or -not $DriveMap -or -not $DriveMap[$letter]) { return @() }
    , @("The log folder $LogFolder is on drive ${letter}:, which only Windows' remembered mappings point at $($DriveMap[$letter]) (this window could not see the mapping live, so it may be out of date). " +
        "Check that backups and the change log should go to $(Resolve-MappedDrive -Path $LogFolder -DriveMap $DriveMap), or start the tool again with -LogFolder set to a local folder or a \\server\share path.")
}

#endregion

#region Change dialogs (window only)

function Show-DialogError {
    # A validation error in a dialog: shown, announced at once (an Assertive live region), and
    # the control to fix gets the focus. Hidden again when the tech types (Add_TextChanged).
    param([Parameter(Mandatory)]$ErrorBlock, [Parameter(Mandatory)][string]$Text, $FocusTarget)
    $ErrorBlock.Text = $Text
    $ErrorBlock.Visibility = 'Visible'
    Send-LiveRegionChanged -Element $ErrorBlock
    if ($FocusTarget) { [void]$FocusTarget.Focus() }
}

function Set-RemoveTypeCombo {
    # Remove mode: only the Allow/Deny types the chosen user or group has explicit entries of can
    # be picked, and the one it has is selected (Get-RemoveTypeChoice).
    param([Parameter(Mandatory)]$Dialog)
    $combo = $Dialog.FindName('PermIdentityCombo')
    $typeCombo = $Dialog.FindName('PermTypeCombo')
    $choice = if ($combo.SelectedIndex -ge 0) { @($Dialog.Tag.Choices)[$combo.SelectedIndex] } else { $null }
    if (-not $choice) { return }
    $types = Get-RemoveTypeChoice -Choice $choice
    $select = $null
    foreach ($item in $typeCombo.Items) {
        $item.IsEnabled = @($types.Allowed) -contains "$($item.Tag)"
        if ("$($item.Tag)" -eq $types.Default) { $select = $item }
    }
    if ($select) { $typeCombo.SelectedItem = $select }
}

function Show-PermissionDialog {
    # The add or remove dialog. Returns Identity, Rights (a FileSystemRights name), Type and Sid,
    # or $null when cancelled. Add: a typed user or group, checked before the dialog closes;
    # Enter submits an Allow, never a Deny (Set-PermissionSubmitStyle). Remove: one of -Choices (Get-RemoveIdentityChoices: explicit entries, by
    # SID), with only the types it has offered and the level not asked (every explicit entry of
    # the type goes); Remove is never the default button.
    param(
        [Parameter(Mandatory)][ValidateSet('Add', 'Remove')][string]$Mode,
        [Parameter(Mandatory)][ValidateSet('Folder', 'Files')][string]$Scope,
        [Parameter(Mandatory)][string]$TargetText,
        [object[]]$Choices
    )
    $dlg = New-AppDialog -Xaml (Get-PermissionDialogXaml)
    $title = switch ("$Mode$Scope") {
        'AddFolder' { 'Add Permission Entry' }
        'AddFiles' { 'Add Permission to Selected Files' }
        'RemoveFolder' { 'Remove Permission Entry' }
        default { 'Remove Permission from Selected Files' }
    }
    $dlg.Title = $title
    $dlg.Tag = @{ Choices = @($Choices); Answer = $null }
    $dlg.FindName('PermDialogTitle').Text = $title
    $dlg.FindName('PermDialogTarget').Text = $TargetText
    try { [void](Enable-LiveRegion -Element $dlg.FindName('PermDialogError') -Setting Assertive) } catch { }
    $submit = $dlg.FindName('PermSubmitBtn')
    if ($Mode -eq 'Remove') {
        $dlg.FindName('PermIdentityBox').Visibility = 'Collapsed'
        # RemoveAccessRuleAll takes every explicit entry of the type, whatever its level, so the
        # level is not asked.
        $dlg.FindName('PermRightsLabel').Visibility = 'Collapsed'
        $dlg.FindName('PermRightsCombo').Visibility = 'Collapsed'
        $combo = $dlg.FindName('PermIdentityCombo')
        $combo.ItemsSource = @($Choices | ForEach-Object { $_.Label })
        $combo.Visibility = 'Visible'
        $combo.Add_SelectionChanged({ param($s, $e) $w = [System.Windows.Window]::GetWindow($s); if ($w) { $w.FindName('PermDialogError').Visibility = 'Collapsed'; Set-RemoveTypeCombo -Dialog $w } })
        $combo.SelectedIndex = 0
        Set-RemoveTypeCombo -Dialog $dlg
        $dlg.FindName('PermIdentityHint').Text = 'Only entries set on this item itself are listed. Every one of the chosen type is removed, whatever its level. Inherited entries stay: remove them on the folder above.'
        $submit.Content = 'Remove Permission'
        $submit.Style = $dlg.Resources['DangerBtn']
        $submit.IsDefault = $false
    }
    else {
        $dlg.FindName('PermIdentityBox').Add_TextChanged({ param($s, $e) $w = [System.Windows.Window]::GetWindow($s); if ($w) { $w.FindName('PermDialogError').Visibility = 'Collapsed' } })
        # A Deny is destructive (D-044): danger style, and Enter no longer submits it.
        $typeCombo = $dlg.FindName('PermTypeCombo')
        $type = if ("$($typeCombo.SelectedItem.Tag)" -eq 'Deny') { 'Deny' } else { 'Allow' }
        Set-PermissionSubmitStyle -Mode Add -Type $type -Button $submit -DangerStyle $dlg.Resources['DangerBtn'] -NormalStyle $dlg.Resources['PrimaryBtn']
        $typeCombo.Add_SelectionChanged({
                param($s, $e)
                $w = [System.Windows.Window]::GetWindow($s)
                if (-not $w) { return }
                $chosen = if ("$($s.SelectedItem.Tag)" -eq 'Deny') { 'Deny' } else { 'Allow' }
                Set-PermissionSubmitStyle -Mode Add -Type $chosen -Button $w.FindName('PermSubmitBtn') -DangerStyle $w.Resources['DangerBtn'] -NormalStyle $w.Resources['PrimaryBtn']
            })
    }
    $submit.Add_Click({
            param($s, $e)
            $w = [System.Windows.Window]::GetWindow($s)
            $box = $w.FindName('PermIdentityBox')
            $err = $w.FindName('PermDialogError')
            $type = "$($w.FindName('PermTypeCombo').SelectedItem.Tag)"
            if ($box.Visibility -eq 'Visible') {
                $identity = $box.Text
                $problem = Get-PermissionInputError -Identity $identity
                if ($problem) { Show-DialogError -ErrorBlock $err -Text $problem -FocusTarget $box; return }
                $w.Tag.Answer = [PSCustomObject]@{ Identity = $identity.Trim(); Rights = "$($w.FindName('PermRightsCombo').SelectedItem.Tag)"; Type = $type; Sid = $null }
            }
            else {
                $combo = $w.FindName('PermIdentityCombo')
                $choice = if ($combo.SelectedIndex -ge 0) { @($w.Tag.Choices)[$combo.SelectedIndex] } else { $null }
                if (-not $choice) { Show-DialogError -ErrorBlock $err -Text 'Choose the user or group to remove.' -FocusTarget $combo; return }
                $rights = if ($choice.Rights -and $choice.Rights[$type]) { "$($choice.Rights[$type])" } else { 'FullControl' }
                $w.Tag.Answer = [PSCustomObject]@{ Identity = $choice.Identity; Rights = $rights; Type = $type; Sid = $choice.Sid }
            }
            $w.DialogResult = $true
        })
    $dlg.Add_ContentRendered({
            param($s, $e)
            $box = $s.FindName('PermIdentityBox')
            if ($box.Visibility -eq 'Visible') { [void]$box.Focus() } else { [void]$s.FindName('PermIdentityCombo').Focus() }
        })
    if ($dlg.ShowDialog() -eq $true) { return $dlg.Tag.Answer }
    $null
}

function Get-DialogTargetText {
    # What the add and remove dialogs say they work on: each path and, when it differs, its real
    # location, as the background lookup found it before the dialog opened.
    param([Parameter(Mandatory)][ValidateSet('Folder', 'Files')][string]$Scope, [Parameter(Mandatory)][object[]]$Targets)
    $all = @($Targets | Where-Object { $_ })
    if ($Scope -eq 'Folder') {
        $t = $all[0]
        $text = "$($t.DisplayPath)"
        if ($t.ResolvedPath -and $t.ResolvedPath -ne $t.DisplayPath) { $text += "`nReal location: $($t.ResolvedPath)" }
        if ($t.IsRemembered) { $text += "`n(remembered mapping: it may be out of date)" }
        return $text
    }
    $shown = @($all | Select-Object -First 10)
    $lines = @(foreach ($t in $shown) {
            $line = "$($t.DisplayPath)"
            if ($t.ResolvedPath -and $t.ResolvedPath -ne $t.DisplayPath) { $line += "  (real location: $($t.ResolvedPath))" }
            $line
        })
    $text = "$(Format-ItemCount $all.Count 'file' 'files'):`n" + ($lines -join "`n")
    if ($all.Count -gt $shown.Count) { $text += "`n... and $($all.Count - $shown.Count) more" }
    $text
}

function Get-CopyDialogSourceText {
    # The copy dialog's "Copy from" line: the folder and the real location the work will read,
    # the same ResolvedPath it is given.
    param([Parameter(Mandatory)]$Source)
    $text = "$($Source.DisplayPath)"
    if ($Source.ResolvedPath -and $Source.ResolvedPath -ne $Source.DisplayPath) { $text += "  (real location: $($Source.ResolvedPath))" }
    $text
}

function Test-ReadyForChange {
    # $false (after saying why) when no folder or file is chosen, or a change is running or
    # being prepared.
    param([Parameter(Mandatory)][ValidateSet('Folder', 'Files')][string]$Scope)
    if (-not $script:Current) { Set-Status -Kind Warning -Text 'Choose a folder first.'; return $false }
    if ($Scope -eq 'Files' -and @(Get-SelectedFileRows).Count -eq 0) { Set-Status -Kind Warning -Text $script:NoFilesSelectedText; return $false }
    if ($script:ChangeTask) { Set-Status -Kind Warning -Text "Another change is still running on $($script:ChangeTask.Path). Wait for it to finish."; return $false }
    if ($script:ChangePending) { Set-Status -Kind Warning -Text (Get-ChangeControlState).Reason; return $false }
    $true
}

function Get-ChangeRequest {
    # What a click asks the background lookup to check, taken from the window at the click: the
    # chosen folder, or the selected files and the folder they are in; plus the label for the
    # busy line and what to refresh afterwards (the tech may browse elsewhere meanwhile).
    param([Parameter(Mandatory)][ValidateSet('Folder', 'Files')][string]$Scope)
    $display = "$($script:Current.DisplayPath)"
    if ($Scope -eq 'Folder') {
        return @{
            Scope             = $Scope
            CurrentPath       = $display
            FilesRequest      = [int]$script:PaneRequests['Files']
            Paths             = [string[]]@($display)
            FolderDisplayPath = $null
            FolderRealPath    = $null
            Label             = $display
            RefreshState      = (New-ChangeRefreshState -Scope Folder -Paths @($display))
        }
    }
    $paths = [string[]]@(Get-SelectedFileRows | ForEach-Object { "$($_.Path)" } | Where-Object { $_.Trim() })
    @{
        Scope             = $Scope
        CurrentPath       = $display
        FilesRequest      = [int]$script:PaneRequests['Files']
        Paths             = $paths
        FolderDisplayPath = $display
        FolderRealPath    = "$($script:Current.RealPath)"
        Label             = "$(Format-ItemCount $paths.Count 'file' 'files') in $display"
        RefreshState      = (New-ChangeRefreshState -Scope Files -Paths @($display) -ChangedFiles $paths)
    }
}

function Get-ChangeRequestStaleReason {
    # Why a click's lookup no longer fits what the window shows, or $null when it still does:
    # another folder is open, or (for files) the file list was read again or other files are
    # selected now than at the click.
    param([Parameter(Mandatory)][hashtable]$Request)
    if (-not $script:Current -or "$($script:Current.DisplayPath)" -ne "$($Request.CurrentPath)") { return 'Folder' }
    if ($Request.Scope -eq 'Files') {
        if ([int]$script:PaneRequests['Files'] -ne [int]$Request.FilesRequest) { return 'Files' }
        $now = [string[]]@(Get-SelectedFileRows | ForEach-Object { "$($_.Path)" } | Where-Object { $_.Trim() })
        if (($now -join "`n") -ne (@($Request.Paths) -join "`n")) { return 'Files' }
    }
    $null
}

function Test-ChangeRequestCurrent {
    # The stale-request guard for a click's lookup: true when the window still shows what the
    # click asked about (the same folder and, for files, the same file list and the same files
    # selected). A lookup that comes back for anything else is dropped, so no dialog opens for a
    # folder or files that are no longer what the tech chose.
    param([Parameter(Mandatory)][hashtable]$Request)
    -not (Get-ChangeRequestStaleReason -Request $Request)
}

function Start-ChangeLookup {
    # Works out where a change would land in the background ($script:ChangeTargetWork), with
    # "Checking where <path> really is..." on the busy line, while the change is pending. Then
    # -OnResolved ($targets, $State) runs on the window's thread to open the dialog or the
    # confirm; a refusal or a failed lookup is shown instead and nothing goes ahead. With
    # -Request (Get-ChangeRequest), a result that comes back after the tech moved to another
    # folder is dropped (Test-ChangeRequestCurrent). -RefuseProtected: the paths are Copy
    # permissions targets (Get-CopyTargetRefusal). -OnRefused ($State) runs after a refusal or a
    # failed lookup has been shown (the copy dialog opens again with what was typed).
    param(
        [Parameter(Mandatory)][string[]]$Paths,
        [Parameter(Mandatory)][string]$Label,
        [switch]$WholeTree,
        [switch]$RefuseProtected,
        [string]$FolderDisplayPath,
        [string]$FolderRealPath,
        [hashtable]$Request,
        [Parameter(Mandatory)][scriptblock]$OnResolved,
        [scriptblock]$OnRefused,
        $State
    )
    $verb = if (@($Paths).Count -gt 1) { 'are' } else { 'is' }
    Set-Status -Text "Checking where $Label really $verb. Nothing has been changed yet."
    Start-ChangePrepRead -Action 'Checking where' -Path "$Label really $verb" -Work $script:ChangeTargetWork `
        -ArgumentList @([string[]]$Paths, $script:MappedDrives, $script:MappedDriveSources, [bool]$WholeTree, $FolderDisplayPath, $FolderRealPath, $script:CorePath, [bool]$RefuseProtected) `
        -State @{ OnResolved = $OnResolved; OnRefused = $OnRefused; State = $State; Label = $Label; Verb = $verb; Request = $Request } -OnDone {
        param($result, $s)
        $stale = if ($s.Request) { Get-ChangeRequestStaleReason -Request $s.Request } else { $null }
        if ($stale -eq 'Files') {
            Set-Status -Text "The files selected when you clicked are not the ones selected now ($($s.Label) was being checked), so nothing was changed. Select the files again and click the button again."
            return
        }
        if ($stale) {
            Set-Status -Text "Another folder was opened while $($s.Label) was being checked, so nothing was changed. Open it again and click the button again."
            return
        }
        if (-not ($result -and $result.Ok)) {
            $text = if ($result -and "$($result.Refusal)".Trim()) { "$($result.Refusal)" }
            else {
                $why = if ($result -and "$($result.Error)".Trim()) { " ($("$($result.Error)".Trim()))" } else { '' }
                "Could not check where $($s.Label) really $($s.Verb), so nothing was changed.$why Press Refresh and try again."
            }
            Show-ChangeRefusal -Text $text
            if ($s.OnRefused) { & $s.OnRefused $s.State }
            return
        }
        & $s.OnResolved @($result.Targets) $s.State
    }
}

function Open-AddPermission {
    # Add Permission: where it lands is looked up in the background first, then the dialog
    # shows the real location; its submit is the confirmation for a plain Allow on ordinary
    # folders (Invoke-AddPermission asks again for the rest).
    param([Parameter(Mandatory)][ValidateSet('Folder', 'Files')][string]$Scope)
    if (-not (Test-ReadyForChange -Scope $Scope)) { return }
    $request = Get-ChangeRequest -Scope $Scope
    if (-not (Enter-ChangePending -Action 'Add Permission' -Path $request.Label)) { return }
    [void](Start-ChangeLookup -Paths $request.Paths -Label $request.Label -FolderDisplayPath $request.FolderDisplayPath -FolderRealPath $request.FolderRealPath `
            -Request $request -State @{ Scope = $Scope; Request = $request } -OnResolved {
            param($targets, $s)
            $answer = Show-PermissionDialog -Mode Add -Scope $s.Scope -TargetText (Get-DialogTargetText -Scope $s.Scope -Targets $targets)
            if (-not $answer) { Set-Status -Text 'Cancelled: nothing was changed.'; return }
            Invoke-AddPermission -Scope $s.Scope -Identity $answer.Identity -Rights $answer.Rights -Type $answer.Type `
                -Targets $targets -Label $s.Request.Label -RefreshState $s.Request.RefreshState
        })
}

function Open-RemovePermission {
    # The remove dialog lists who can be removed (explicit entries only). For files whose
    # permissions are not loaded yet, those are read first (-AfterLoad: once only, still the same
    # pending change); then where it lands is looked up, then the dialog and the confirm.
    param([Parameter(Mandatory)][ValidateSet('Folder', 'Files')][string]$Scope, [switch]$AfterLoad)
    if (-not $AfterLoad -and -not (Test-ReadyForChange -Scope $Scope)) { return }
    if (-not $script:Current) { Set-Status -Kind Warning -Text 'Choose a folder first.'; return }
    if ($Scope -eq 'Folder') {
        $v = $script:ViewState.FolderPermissions
        if (-not $v -or $v.Path -ne $script:Current.RealPath) {
            Set-Status -Kind Warning -Text 'The permissions of this folder are still loading. Wait a moment, then try again.'
            return
        }
        if (-not $v.Ok) {
            Set-Status -Kind Warning -Text "The permissions of this folder could not be read, so there is nothing to choose from. $($v.Error)"
            return
        }
    }
    $choices = Get-RemoveIdentityChoices -Scope $Scope
    if (@($choices.NotLoaded).Count -gt 0) {
        if ($AfterLoad) {
            Set-Status -Kind Warning -Text 'The permissions of some selected files could not be loaded. Press Remove Permission again.'
            return
        }
        $missing = [string[]]@($choices.NotLoaded)
        if (-not (Enter-ChangePending -Action 'Remove Permission' -Path (Format-ItemCount $missing.Count 'file' 'files'))) { return }
        foreach ($p in $missing) { $script:FileAclPending[$p] = $true }
        $request = [int]$script:PaneRequests['Files']
        Set-Status -Text "Reading the permissions of $(Format-ItemCount $missing.Count 'selected file' 'selected files') first..."
        [void](Start-ChangePrepRead -Action 'Loading the permissions of' -Path (Format-ItemCount $missing.Count 'file' 'files') -Work $script:FileAclWork `
                -ArgumentList @($missing, $script:CorePath) -State @{ Request = $request; Paths = $missing } -OnDone {
                param($result, $s)
                if (Set-FileAclResult -Result $result -Request $s.Request -Paths $s.Paths) { Open-RemovePermission -Scope Files -AfterLoad }
            })
        return
    }
    if (@($choices.Choices).Count -eq 0) {
        $what = if ($Scope -eq 'Folder') { 'This folder has' } else { 'The selected files have' }
        Set-Status -Kind Warning -Text "$what no permission entries of their own that could be read, so there is nothing to remove here. Inherited entries come from the folder above: remove them there."
        return
    }
    $request = Get-ChangeRequest -Scope $Scope
    if (-not $AfterLoad -and -not (Enter-ChangePending -Action 'Remove Permission' -Path $request.Label)) { return }
    [void](Start-ChangeLookup -Paths $request.Paths -Label $request.Label -FolderDisplayPath $request.FolderDisplayPath -FolderRealPath $request.FolderRealPath `
            -Request $request -State @{ Scope = $Scope; Request = $request; Choices = @($choices.Choices) } -OnResolved {
            param($targets, $s)
            $answer = Show-PermissionDialog -Mode Remove -Scope $s.Scope -TargetText (Get-DialogTargetText -Scope $s.Scope -Targets $targets) -Choices $s.Choices
            if (-not $answer) { Set-Status -Text 'Cancelled: nothing was changed.'; return }
            Invoke-RemovePermission -Scope $s.Scope -Identity $answer.Identity -Rights $answer.Rights -Type $answer.Type -Sid $answer.Sid `
                -Targets $targets -Label $s.Request.Label -RefreshState $s.Request.RefreshState
        })
}

function Open-TakeOwnership {
    # Take ownership (this folder only, the selected files, or the whole tree): where it lands is
    # looked up in the background first (for the whole tree with the D-036 and high-impact
    # checks), then the confirm (after the count, for the whole tree).
    param([Parameter(Mandatory)][ValidateSet('Folder', 'Files', 'Tree')][string]$Scope)
    $kind = if ($Scope -eq 'Files') { 'Files' } else { 'Folder' }
    if (-not (Test-ReadyForChange -Scope $kind)) { return }
    $request = Get-ChangeRequest -Scope $kind
    $action = 'Take Ownership'
    if ($Scope -eq 'Tree') {
        $request.RefreshState = New-ChangeRefreshState -Scope Tree -Paths @($script:Current.DisplayPath)
        $action = 'Take Ownership of all subfolders and files'
    }
    if (-not (Enter-ChangePending -Action $action -Path $request.Label)) { return }
    [void](Start-ChangeLookup -Paths $request.Paths -Label $request.Label -WholeTree:($Scope -eq 'Tree') `
            -FolderDisplayPath $request.FolderDisplayPath -FolderRealPath $request.FolderRealPath -Request $request -State @{ Scope = $Scope; Request = $request } -OnResolved {
            param($targets, $s)
            Invoke-TakeOwnership -Scope $s.Scope -Targets $targets -Label $s.Request.Label -RefreshState $s.Request.RefreshState
        })
}

function Show-CopyPermissionsDialog {
    # The copy dialog, for -Source (looked up before it opened). Returns the typed text, or
    # $null when cancelled. Blank input is caught before the dialog closes. -TypedText: the list
    # the tech typed last time, put back in the box when the dialog opens again after a typed
    # folder was refused (Open-CopyTargets), so it does not have to be typed again.
    param([Parameter(Mandatory)]$Source, [AllowNull()][AllowEmptyString()][string]$TypedText)
    $dlg = New-AppDialog -Xaml (Get-CopyPermissionsDialogXaml)
    $dlg.FindName('CopySourceText').Text = Get-CopyDialogSourceText -Source $Source
    if ($TypedText) { $dlg.FindName('CopyTargetsBox').Text = $TypedText }
    try { [void](Enable-LiveRegion -Element $dlg.FindName('CopyError') -Setting Assertive) } catch { }
    # Only the folder's own permissions are copied, so only its own Deny entries are copied.
    $note = $dlg.FindName('CopyDenyNote')
    $v = $script:ViewState.FolderPermissions
    if (-not $v -or -not $v.Ok -or $v.Path -ne $script:Current.RealPath) {
        $note.Text = 'The permissions of this folder are not loaded, so it cannot be checked for Deny permissions of its own. Wait a moment or open the folder again before copying.'
        $note.Visibility = 'Visible'
    }
    else {
        $denies = @($v.Rows | Where-Object { -not $_.IsInherited -and $_.Type -eq 'Deny' })
        if ($denies.Count -gt 0) {
            $note.Text = "This folder has $($denies.Count) Deny permission(s) of its own ($(@($denies | ForEach-Object { $_.Identity }) -join ', ')). They are copied too, and a Deny blocks access even where another permission allows it. You are asked to confirm before anything is copied."
            $note.Visibility = 'Visible'
        }
    }
    $dlg.FindName('CopyTargetsBox').Add_TextChanged({ param($s, $e) $w = [System.Windows.Window]::GetWindow($s); if ($w) { $w.FindName('CopyError').Visibility = 'Collapsed' } })
    $dlg.FindName('CopySubmitBtn').Add_Click({
            param($s, $e)
            $w = [System.Windows.Window]::GetWindow($s)
            $box = $w.FindName('CopyTargetsBox')
            if ((ConvertTo-TargetPathList -Text $box.Text).Count -eq 0) {
                Show-DialogError -ErrorBlock $w.FindName('CopyError') -Text $script:NoTargetPathText -FocusTarget $box
                return
            }
            $w.Tag = $box.Text
            $w.DialogResult = $true
        })
    $dlg.Add_ContentRendered({ param($s, $e) [void]$s.FindName('CopyTargetsBox').Focus() })
    if ($dlg.ShowDialog() -eq $true) { return "$($dlg.Tag)" }
    $null
}

function Open-CopyPermissions {
    # Copy Permissions To...: the source is looked up in the background first (the dialog shows
    # its real location), then the typed folders after the dialog (Open-CopyTargets), then the
    # change.
    if (-not (Test-ReadyForChange -Scope Folder)) { return }
    $request = Get-ChangeRequest -Scope Folder
    if (-not (Enter-ChangePending -Action 'Copy Permissions' -Path $request.Label)) { return }
    [void](Start-ChangeLookup -Paths $request.Paths -Label $request.Label -Request $request -State @{ Request = $request } -OnResolved {
            param($targets, $s)
            Open-CopyTargets -Source @($targets)[0]
        })
}

function Open-CopyTargets {
    # The copy dialog for -Source, then the typed folders looked up in the background, the
    # protected ones refused (-RefuseProtected, AC50). When one is refused, or the lookup fails,
    # the reason is shown and the dialog opens again with what was typed (-TypedText, AC53), still
    # the same pending change; Cancel ends it.
    param([Parameter(Mandatory)]$Source, [AllowNull()][AllowEmptyString()][string]$TypedText)
    $text = Show-CopyPermissionsDialog -Source $Source -TypedText $TypedText
    if ($null -eq $text) { Set-Status -Text 'Cancelled: nothing was changed.'; return }
    $lines = ConvertTo-TargetPathList -Text $text
    if ($lines.Count -eq 0) { Set-Status -Kind Warning -Text $script:NoTargetPathText; return }
    $label = if ($lines.Count -eq 1) { $lines[0] } else { "the $($lines.Count) folders you listed" }
    [void](Start-ChangeLookup -Paths $lines -Label $label -RefuseProtected -State @{ Source = $Source; Text = $text } -OnResolved {
            param($copyTargets, $s2)
            Invoke-CopyPermissions -Source $s2.Source -Targets $copyTargets
        } -OnRefused {
            param($s2)
            Open-CopyTargets -Source $s2.Source -TypedText $s2.Text
        })
}
#endregion

if ($LoadFunctionsOnly) { return }

#region Startup

# -WhatIf (SupportsShouldProcess) is captured here and passed on explicitly; it must not turn
# the window's own small writes (settings, error log) into dry runs.
$script:WhatIfMode = [bool]$WhatIfPreference
$WhatIfPreference = $false

Limit-AppErrorLog -Path $script:ErrorLogPath

# A relative -LogFolder is made full now, against the location it was typed in: a relaunched
# copy starts in another folder.
try { $LogFolder = Resolve-LogFolderArgument -LogFolder $LogFolder }
catch {
    Show-AppMessage -Icon Error -Message $_.Exception.Message
    return
}

# The drives this process sees live win, then the ones the first (non-elevated) window passed
# on, then the remembered ones (tagged, and shown as "(remembered mapping)").
# Not $script:DriveMap: at script scope that IS the -DriveMap parameter (a string).
$script:DriveMapSet = Get-DriveMapSet -DriveMapArgument $DriveMap
$script:MappedDrives = $script:DriveMapSet.Map
$script:MappedDriveSources = $script:DriveMapSet.Source

$isSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
$principal = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
$action = Get-StartupAction -IsSta $isSta -IsAdmin $isAdmin

if ($action -eq 'RelaunchSta') {
    # WPF needs a single-threaded apartment; start again in one.
    try {
        $relaunch = Get-RelaunchArgumentList -ScriptPath $script:ScriptPath -LogFolder $LogFolder -WhatIfMode:$script:WhatIfMode -DriveMap $script:MappedDrives -DriveMapSource $script:MappedDriveSources
        # The copy runs from the \\server\share path; through a remembered mapping it must be
        # this same script.
        $problem = Get-RelaunchScriptProblem -ScriptPath $script:ScriptPath -DriveMap $script:MappedDrives -DriveMapSource $script:MappedDriveSources
        if ($problem) {
            Show-AppMessage -Icon Error -Message $problem
            return
        }
        Start-Process -FilePath (Get-WindowsPowerShellPath) -ArgumentList $relaunch -ErrorAction Stop
    }
    catch { Show-AppMessage -Icon Error -Message "Folder Permission Manager could not start a window: $($_.Exception.Message)" }
    return
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

if ($action -eq 'RelaunchElevated') {
    # Elevation is checked here rather than with #Requires so the tests can load the functions,
    # and so "Run with PowerShell" from Explorer just works after a UAC prompt.
    [void](Request-Elevation -ScriptPath $script:ScriptPath -LogFolder $LogFolder -WhatIfMode:$script:WhatIfMode -DriveMap $script:MappedDrives -DriveMapSource $script:MappedDriveSources)
    return
}

# A -LogFolder on a mapped drive is used by its UNC path: this elevated window may not see the
# letter, and the path then follows the same live-first map as everything else. A letter only
# a remembered mapping explains gets a warning in the banner (it may be out of date).
$mappingNotice = @(Get-LogFolderMappingNotice -LogFolder $LogFolder -DriveMap $script:MappedDrives -DriveMapSource $script:MappedDriveSources)
$LogFolder = Resolve-MappedDrive -Path $LogFolder -DriveMap $script:MappedDrives

# Not $script:LogFolder: at script scope that IS the -LogFolder parameter.
# The Logs folder next to the script, unless the script is in a OneDrive or SharePoint sync
# folder: then %LOCALAPPDATA% (backups and the change log must not be uploaded).
$script:ScriptLogsFolder = Join-Path $script:ScriptRoot 'Logs'
$syncRoots = @(Get-OneDriveFolder)
$script:DefaultLogFolder = Get-AppDefaultLogFolder -ScriptLogsFolder $script:ScriptLogsFolder -LocalAppData (Get-LocalAppDataFolder) -SyncRoot $syncRoots
try {
    $script:ChangeLogFolder = Resolve-ChangeLogFolder -LogFolder $LogFolder -DefaultFolder $script:DefaultLogFolder
}
catch {
    Show-AppMessage -Icon Error -Message $_.Exception.Message
    return
}
# The sync-folder check looks at the folder the change log really goes to, when one was given.
$explicitLogFolder = if ($LogFolder) { $script:ChangeLogFolder } else { $null }
$script:LogFolderNotice = @(Get-ChangeLogFolderNotice -LogFolder $LogFolder -ResolvedFolder $script:ChangeLogFolder -DefaultFolder $script:DefaultLogFolder) +
@(Get-SyncedLogFolderNotice -LogFolder $explicitLogFolder -ScriptLogsFolder $script:ScriptLogsFolder -DefaultFolder $script:DefaultLogFolder -SyncRoot $syncRoots) + $mappingNotice

if (-not (Enter-SingleInstance -LogFolder $script:ChangeLogFolder -DriveMap $script:MappedDrives)) { return }

#endregion

#region Main

$script:FatalError = $false
try {
    Initialize-BackgroundPool
    Start-PermissionWindow
}
catch {
    $script:FatalError = $true
    Write-AppError "Fatal: $($_.Exception.Message)`n$($_.ScriptStackTrace)"
    # Never "Nothing was changed" when a change ran this session or is still running.
    $changeRunning = @($script:BgTasks | Where-Object { Test-ChangeTaskRunning $_ }).Count -gt 0
    Show-AppMessage -Icon Error -Message (Get-FatalErrorMessage -ErrorText "$($_.Exception.Message)" -ErrorLogPath "$($script:ErrorLogPath)" `
            -ChangeLogFolder "$($script:ChangeLogFolder)" -ChangeRunning $changeRunning -ChangeStarted ([bool]$script:ChangeMadeThisSession))
}
finally {
    # A change still running in the pool (only possible after a fatal error: the window refuses
    # to close during one) is never stopped and the process never ends under it: wait for it
    # first, however long it takes. The core logs each item as it completes. The window is gone
    # by now, so the console the window hid is shown again with what is happening.
    if (@($script:BgTasks | Where-Object { Test-ChangeTaskRunning $_ }).Count -gt 0) {
        Show-OwnConsole
        Write-Host "[WARN] A permission change is still running. Waiting for it to finish before closing; do not close this window. Its results go to the change log in $($script:ChangeLogFolder)." -ForegroundColor Yellow
    }
    $null = Wait-ChangeTasks -Tasks @($script:BgTasks)
    # Then the mutex, then the pool without blocking; a read stuck in network I/O ends with the
    # process instead of keeping it alive. A tech's own console is only closed in that case.
    $ownProcess = Test-OwnProcess -CommandLineArgs ([Environment]::GetCommandLineArgs()) -ScriptPath $script:ScriptPath
    $exitCode = if ($script:FatalError) { 1 } else { 0 }
    $null = Invoke-AppShutdown -Pool $script:BgPool -Mutex $script:InstanceMutex -Tasks @($script:BgTasks) -ExitWhenDone:$ownProcess -ExitCode $exitCode
}
# Reached when the process was not ended above (a tech's own console): the script still ends
# with a non-zero exit code after a fatal error.
if ($script:FatalError) { exit 1 }

#endregion
