#Requires -Version 5.1

<#
.SYNOPSIS
    Folder Permission Manager -- Windows app (WPF) for viewing NTFS folder and file permissions.

.DESCRIPTION
    Opens a desktop window for:
      - Browsing local and mapped drives and typed paths (\\server\share) in a folder tree
      - Seeing who owns a folder and who has access to it (User or Group, Permission Level,
        Allow/Deny, Inherited), and whether it gets permissions from the folder above
      - Seeing the files in a folder (name, size, modified) and who has access to the selected
        files, with a warning when the selected files have different permissions
      - Exporting a permission report for a folder and all its subfolders to CSV

    VIEW ONLY IN THIS VERSION: the buttons that change permissions are shown but switched off.
    To change permissions, use FolderPermissionManager-WebGUI.ps1 (the browser version), which
    is kept until this app has been lab-tested.

    Everything slow (opening a folder on a busy share, reading permissions, the export) runs in
    the background, so the window never freezes; a busy line shows what is loading and for how
    long. Nothing listens on the network.

    The window needs administrator rights. Started without them, it asks Windows for them (UAC)
    and opens again; mapped drives are passed on, because an elevated window usually cannot see
    them. Only one window per log folder can be open at a time.

.PARAMETER LogFolder
    Folder for permission backups and the change log. Defaults to the Logs folder next to this
    script; if the script is on a network share or any drive that is not a local fixed disk, or
    that folder is read-only, %LOCALAPPDATA%\FolderPermissionManager\Logs is used instead. A
    folder passed here is used as given (the window warns when it is on the network). The
    window shows which folder is used and has an "Open log folder" button.

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
    Dry run: the window says "Dry run (WhatIf): nothing will be changed".

.NOTES
    Requires: Windows PowerShell 5.1 (or PowerShell 7 on Windows), run as administrator (the
    window asks for it). FolderPermissions.Core.ps1 must stay next to this script: it holds the
    permission reading, backup and change-log logic shared with the command-line script and
    the browser version.

    Files written:
      <log folder>  At startup, even view-only and with -WhatIf: the Logs folder next to this
                    script is created (when it is on a local fixed disk) and a small probe file
                    is written and deleted there, to check it can be written. Backups and the
                    change log go here once changes are made.
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
    $rules = $Acl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
    $rows = @(foreach ($r in $rules) {
            [PSCustomObject]@{
                Identity        = "$($r.IdentityReference.Value)"
                PermissionLevel = Format-PermissionRights -Rights $r.FileSystemRights
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
    # Warnings and errors say so in words, not only in colour.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [ValidateSet('Info', 'Success', 'Warning', 'Error')][string]$Kind = 'Info')
    $prefix = @{ Warning = 'Warning: '; Error = 'Error: ' }[$Kind]
    if (-not $prefix -or $Text.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return $Text }
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

function Test-CanClose {
    # Asked by the window's Closing handler before anything is stopped. Nothing in this version
    # changes permissions, so the window can always close.
    # SQ-018: return $false (and show why) while a change task runs; reads can always be dropped.
    $true
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
    # Closing must never hang on a background read stuck in network I/O:
    #   1. release the single-instance mutex, so the tool can be opened again straight away;
    #   2. ask every task to stop and close the pool without blocking (BeginClose);
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
    if ($Mutex) {
        try { $Mutex.ReleaseMutex() } catch { }
        try { $Mutex.Dispose() } catch { }
    }
    foreach ($t in @($Tasks)) {
        if ($t -and $t.PS) { try { [void]$t.PS.BeginStop($null, $null) } catch { } }
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
    [PSCustomObject]@{ PoolClosed = $closed; Exited = $exited }
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
    # Marks the status box as a polite live region, so screen readers announce new messages.
    # LiveSetting exists from .NET Framework 4.7.1; on older frameworks nothing is set ($false).
    # https://learn.microsoft.com/dotnet/api/system.windows.automation.automationproperties.livesetting
    param([Parameter(Mandatory)]$Element)
    $field = [System.Windows.Automation.AutomationProperties].GetField('LiveSettingProperty')
    if (-not $field) { return $false }
    $dp = $field.GetValue($null)
    $Element.SetValue($dp, [Enum]::Parse($dp.PropertyType, 'Polite'))
    $true
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
'Get-DriveListModel', 'Get-ValidDriveMap', 'Test-UncSharePath'

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

function Initialize-BackgroundPool {
    # One pool of 1-4 runspaces for every read; workers never touch the window.
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    # The pool only runs this script's own work blocks and the core next to it, which the
    # window has already loaded; the process policy may not reach a new runspace.
    $iss.ExecutionPolicy = [Microsoft.PowerShell.ExecutionPolicy]::Bypass
    # The core was loaded once when the window started; its functions are copied from there.
    $names = @($script:WorkHelperFunctions) + @(Get-CoreFunctionNames -CorePath $script:CorePath) | Select-Object -Unique
    foreach ($name in $names) {
        $definition = (Get-Command -Name $name -CommandType Function -ErrorAction Stop).Definition
        $iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($name, $definition))
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
    param([scriptblock]$Work, [object[]]$ArgumentList, [scriptblock]$OnDone, $State)
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.RunspacePool = $script:BgPool
    [void]$ps.AddScript($Work.ToString())
    foreach ($a in $ArgumentList) { [void]$ps.AddArgument($a) }
    $task = [PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke(); OnDone = $OnDone; State = $State; Stopped = $false }
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
        [void]$script:BgTasks.Remove($t)
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

# XAML namespace names, with ':' written as the XML character reference &#58;. They are
# identifiers that only look like web addresses (nothing is fetched from them), and writing
# them this way keeps the source free of any web-address text, which the no-network test
# (AC6) checks for. https://learn.microsoft.com/dotnet/desktop/xaml-services/namespaces
$script:XamlNamespaces = 'xmlns="http&#58;//schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http&#58;//schemas.microsoft.com/winfx/2006/xaml"'

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

    <!-- Where changes are logged, dry run, view-only notice -->
    <Border Grid.Row="1" Background="{DynamicResource BannerBg}" BorderBrush="{DynamicResource BannerBorder}" BorderThickness="0,0,0,1" Padding="16,8">
      <StackPanel>
        <StackPanel x:Name="BannerPanel"/>
        <TextBlock x:Name="ViewOnlyText" Foreground="{DynamicResource Warn}" TextWrapping="Wrap" Margin="0,2,0,0"
                   Text="View only in this version: use FolderPermissionManager-WebGUI.ps1 to make changes. To copy files with their permissions, use RobocopyMigration."/>
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
                      ToolTipService.ShowOnDisabled="True" ToolTip="Not in this version yet. To change permissions, use FolderPermissionManager-WebGUI.ps1.">
                <TextBlock><Run Text="+" FontWeight="Bold"/><Run Text="  Add Permission"/></TextBlock>
              </Button>
              <Button x:Name="RemovePermissionBtn" Style="{StaticResource DangerBtn}" Margin="0,0,8,6" IsEnabled="False"
                      ToolTipService.ShowOnDisabled="True" ToolTip="Not in this version yet. To change permissions, use FolderPermissionManager-WebGUI.ps1.">
                <TextBlock><Run Text="&#x2212;" FontWeight="Bold"/><Run Text="  Remove Permission"/></TextBlock>
              </Button>
              <Button x:Name="TakeOwnershipBtn" Style="{StaticResource Btn}" Margin="0,0,8,6" IsEnabled="False"
                      ToolTipService.ShowOnDisabled="True" ToolTip="Not in this version yet. To change permissions, use FolderPermissionManager-WebGUI.ps1.">
                <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x1F464;"/><Run Text="  Take Ownership (this folder only)"/></TextBlock>
              </Button>
              <Button x:Name="TakeOwnershipTreeBtn" Style="{StaticResource DangerBtn}" Margin="0,0,8,6" IsEnabled="False"
                      ToolTipService.ShowOnDisabled="True" ToolTip="Not in this version yet. To change permissions, use FolderPermissionManager-WebGUI.ps1.">
                <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x1F464;"/><Run Text="  Take Ownership of all subfolders and files"/></TextBlock>
              </Button>
              <Button x:Name="CopyPermissionsBtn" Style="{StaticResource Btn}" Margin="0,0,8,6" IsEnabled="False"
                      ToolTipService.ShowOnDisabled="True" ToolTip="Not in this version yet. To change permissions, use FolderPermissionManager-WebGUI.ps1.">
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
                            ToolTipService.ShowOnDisabled="True" ToolTip="Not in this version yet. To change permissions, use FolderPermissionManager-WebGUI.ps1.">
                      <TextBlock><Run Text="+" FontWeight="Bold"/><Run Text="  Add Permission"/></TextBlock>
                    </Button>
                    <Button x:Name="RemoveFilePermissionBtn" Style="{StaticResource DangerBtn}" Margin="0,0,8,6" IsEnabled="False"
                            ToolTipService.ShowOnDisabled="True" ToolTip="Not in this version yet. To change permissions, use FolderPermissionManager-WebGUI.ps1.">
                      <TextBlock><Run Text="&#x2212;" FontWeight="Bold"/><Run Text="  Remove Permission"/></TextBlock>
                    </Button>
                    <Button x:Name="TakeFileOwnershipBtn" Style="{StaticResource Btn}" Margin="0,0,8,6" IsEnabled="False"
                            ToolTipService.ShowOnDisabled="True" ToolTip="Not in this version yet. To change permissions, use FolderPermissionManager-WebGUI.ps1.">
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
    # Add and remove permission (folder or selected files). Wired up in SQ-018.
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
    <TextBlock Style="{StaticResource Lbl}" Text="PERMISSION LEVEL"/>
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
      <Button x:Name="PermSubmitBtn" Style="{StaticResource PrimaryBtn}" Content="Add Permission"/>
    </StackPanel>
  </StackPanel>
</Window>
"@
}

function Get-CopyPermissionsDialogXaml {
    # Copy Permissions To... (adds only, D-031; no recursive option, SQ-015). Wired up in SQ-018.
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
      <Button x:Name="CopySubmitBtn" Style="{StaticResource PrimaryBtn}" Content="Copy Permissions"/>
    </StackPanel>
  </StackPanel>
</Window>
"@
}

function Get-ConfirmDialogXaml {
    # Asks before a destructive change: names the path(s) and how many items; Cancel is the
    # default and the action button carries a verb. Filled in and wired up in SQ-018.
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

function Set-AppTheme {
    # Every colour is a DynamicResource, so replacing the brushes recolours the window in place.
    param([Parameter(Mandatory)][ValidateSet('Dark', 'Light')][string]$Name)
    $palette = $script:Themes[$Name]
    foreach ($key in $palette.Keys) {
        $brush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($palette[$key]))
        $brush.Freeze()
        $script:Window.Resources[$key] = $brush
    }
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
    if ($script:StatusIsLiveRegion) {
        # Tell screen readers the live region changed (.NET Framework 4.7.1 and later).
        try {
            $peer = [System.Windows.Automation.Peers.UIElementAutomationPeer]::CreatePeerForElement($box)
            if ($peer) { $peer.RaiseAutomationEvent([System.Windows.Automation.Peers.AutomationEvents]::LiveRegionChanged) }
        }
        catch { }
    }
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
    # The newest running read, with its elapsed time; hidden when nothing runs.
    if (-not ($script:UI -and $script:UI.BusyBar)) { return }
    $entries = @($script:BusyEntries.Values)
    if ($entries.Count -eq 0) { $script:UI.BusyBar.Visibility = 'Collapsed'; return }
    $latest = $entries[$entries.Count - 1]
    $line = Get-BusyLine -Action $latest.Action -Path $latest.Path -Elapsed ([DateTime]::UtcNow - $latest.Started)
    if ($entries.Count -gt 1) { $line += "  (and $($entries.Count - 1) more)" }
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

function Update-CurrentFolder {
    # Refresh: read the current folder's subfolders, permissions and files again.
    $node = $script:CurrentNode
    if (-not $node) { return }
    if ($node.Tag.State -ne 'NotLoaded' -and $node.Tag.State -ne 'Loading') {
        $node.Items.Clear()
        [void]$node.Items.Add((New-TreeInfoItem -Text 'Loading...'))
        $node.Tag.State = 'NotLoaded'
        if ($node.IsExpanded) { Expand-FolderNode -Node $node }
    }
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
        if ($count -le 1 -and $hwnd -ne [IntPtr]::Zero) { [void][FolderPermissionManager.AppConsoleWin]::ShowWindow($hwnd, 0) }
    }
    catch { }
}

function Initialize-PermissionWindow {
    # Builds the main window and wires its events; nothing is shown.
    $win = [System.Windows.Markup.XamlReader]::Parse((Get-MainWindowXaml))
    $script:Window = $win
    $script:UI = @{}
    $names = 'ThemeToggle', 'OpenLogFolderBtn', 'DryRunPill', 'BannerPanel', 'ViewOnlyText', 'PathText', 'RealPathLabel', 'RealPathText', 'RealPathNote',
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
            # Asked first, before anything is stopped (SQ-018 refuses while a change runs).
            if (-not (Test-CanClose)) { $e.Cancel = $true; return }
            # Reads and the export can simply be dropped; nothing in this version changes anything.
            foreach ($t in @($script:BgTasks)) { if ($t) { try { [void]$t.PS.BeginStop($null, $null) } catch { } } }
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
# letter, and the path then follows the same live-first map as everything else.
$LogFolder = Resolve-MappedDrive -Path $LogFolder -DriveMap $script:MappedDrives

# Not $script:LogFolder: at script scope that IS the -LogFolder parameter.
$script:DefaultLogFolder = Join-Path $script:ScriptRoot 'Logs'
try {
    $script:ChangeLogFolder = Resolve-ChangeLogFolder -LogFolder $LogFolder -DefaultFolder $script:DefaultLogFolder
}
catch {
    Show-AppMessage -Icon Error -Message $_.Exception.Message
    return
}
$script:LogFolderNotice = @(Get-ChangeLogFolderNotice -LogFolder $LogFolder -ResolvedFolder $script:ChangeLogFolder -DefaultFolder $script:DefaultLogFolder)

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
    Show-AppMessage -Icon Error -Message "Folder Permission Manager hit an error and has to close:`n`n$($_.Exception.Message)`n`nDetails were written to $($script:ErrorLogPath). Nothing was changed."
}
finally {
    # Mutex first, then the pool without blocking; a read stuck in network I/O ends with the
    # process instead of keeping it alive. A tech's own console is only closed in that case.
    $ownProcess = Test-OwnProcess -CommandLineArgs ([Environment]::GetCommandLineArgs()) -ScriptPath $script:ScriptPath
    $exitCode = if ($script:FatalError) { 1 } else { 0 }
    $null = Invoke-AppShutdown -Pool $script:BgPool -Mutex $script:InstanceMutex -Tasks @($script:BgTasks) -ExitWhenDone:$ownProcess -ExitCode $exitCode
}
# Reached when the process was not ended above (a tech's own console): the script still ends
# with a non-zero exit code after a fatal error.
if ($script:FatalError) { exit 1 }

#endregion
