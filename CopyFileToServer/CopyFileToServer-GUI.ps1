#Requires -Version 5.1

<#
.SYNOPSIS
    Copy Files to Servers -- native Windows GUI for copying files and folders to many servers.

.DESCRIPTION
    Opens a desktop window (WPF) that copies one or more files or folders into the same folder on
    a list of servers:
      - Build the server list by typing, pasting a list (one per line, or separated by commas or
        spaces), or importing a .txt/.csv file. Each server can be renamed, unticked or removed.
      - The list, destination folder and options are remembered between runs.
      - "Check connection" tests every server (name lookup, file-sharing port, share access)
        before anything is copied.
      - Copies run in the background, several servers at a time, with a live status per server.
      - Failed servers can be retried with one click; results can be exported to CSV.

    Files written next to this script:
      Logs\    one log per copy run (CopyToServers_yyyy-MM-dd_HHmmss.log)
      State\   settings.json (server list, destination, options), gui-errors.log

    For scripted / unattended use, CopyFileToServer.ps1 in the same folder does the same copy
    from the command line.

.PARAMETER LoadFunctionsOnly
    Define the script's functions and return without opening the window. Used by the Pester
    tests.

.EXAMPLE
    .\CopyFileToServer-GUI.ps1
    Opens the window.

.NOTES
    Version : 1.0.0
    Requires: Windows PowerShell 5.1 (or PowerShell 7 on Windows). Does not need to run as
              administrator locally; the account needs write access to the destination share on
              each server (admin shares such as C$ need admin rights on that server).

    REFERENCES
    - File.Copy(String, String, Boolean): throws UnauthorizedAccessException when the destination
      is read-only, or when overwriting a hidden destination with a non-hidden source.
      https://learn.microsoft.com/dotnet/api/system.io.file.copy
    - SMB is directly hosted on TCP 445 (Windows Vista / Server 2008 and later).
      https://learn.microsoft.com/troubleshoot/windows-server/networking/direct-hosting-of-smb-over-tcpip
    - System error codes 5, 32, 53, 64, 67, 112 and 1326.
      https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-
      https://learn.microsoft.com/windows/win32/debug/system-error-codes--1300-1699-
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$LoadFunctionsOnly
)

$ScriptVersion = '1.0.0'
$ErrorActionPreference = 'Continue'

# This file is deliberately pure ASCII. Windows PowerShell 5.1 reads a BOM-less file as ANSI,
# so any non-ASCII character can silently corrupt a string. Icons in the XAML are written as
# &#x....; entities and display text uses [char] codes.

$script:ScriptRoot = $PSScriptRoot
if (-not $script:ScriptRoot) { $script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
$script:LogDir = Join-Path $script:ScriptRoot 'Logs'
$script:StateDir = Join-Path $script:ScriptRoot 'State'
$script:SettingsPath = Join-Path $script:StateDir 'settings.json'
$script:ErrorLogPath = Join-Path $script:StateDir 'gui-errors.log'

#region Pure helpers

function Write-GuiError {
    # The timer runs several times a second, so each kind of error is written once a minute at
    # most. Digits are ignored when comparing, so the same error with a changing number counts once.
    param([string]$Message)
    if (-not $script:GuiErrorSeen) { $script:GuiErrorSeen = @{} }
    $key = $Message -replace '\d+', '#'
    $last = $script:GuiErrorSeen[$key]
    if ($last -and ((Get-Date) - $last).TotalSeconds -lt 60) { return }
    $script:GuiErrorSeen[$key] = Get-Date
    try {
        if (-not (Test-Path -LiteralPath $script:StateDir)) { New-Item -ItemType Directory -Path $script:StateDir -Force | Out-Null }
        $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
        Add-Content -LiteralPath $script:ErrorLogPath -Value $line -Encoding UTF8
    }
    catch { }
}

function Format-Bytes {
    param([double]$Bytes)
    if ($Bytes -ge 1TB) { return ('{0:N2} TB' -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ('{0:N1} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N0} KB' -f ($Bytes / 1KB)) }
    return ('{0:N0} B' -f $Bytes)
}

function Format-Duration {
    param([double]$Seconds)
    if ($Seconds -lt 0) { $Seconds = 0 }
    $ts = [TimeSpan]::FromSeconds([Math]::Round($Seconds))
    if ($ts.TotalHours -ge 1) { return ('{0}h {1:D2}m' -f [int][Math]::Floor($ts.TotalHours), $ts.Minutes) }
    if ($ts.TotalMinutes -ge 1) { return ('{0}m {1:D2}s' -f $ts.Minutes, $ts.Seconds) }
    return ('{0}s' -f $ts.Seconds)
}

function Format-Count {
    # "1 file" / "3 files"
    param([long]$Count, [string]$Singular, [string]$Plural)
    if (-not $Plural) { $Plural = $Singular + 's' }
    if ($Count -eq 1) { return "1 $Singular" }
    return ('{0:N0} {1}' -f $Count, $Plural)
}

function Test-ServerName {
    # DNS host names, NetBIOS names (underscores are common in old environments) and IPv4
    # addresses. Anything with a backslash, space or share name is rejected.
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name) -or $Name.Length -gt 253) { return $false }
    return $Name -match '^[A-Za-z0-9_]([A-Za-z0-9_\-]{0,62})(\.[A-Za-z0-9_]([A-Za-z0-9_\-]{0,62}))*$'
}

function ConvertTo-ServerNames {
    # Splits typed or pasted text into server names. Accepts one per line, or separated by
    # commas, semicolons, spaces or tabs. "# ..." starts a comment. A pasted UNC path keeps only
    # the server part. Duplicates are dropped (case-insensitive), first spelling wins.
    param([AllowEmptyString()][string]$Text)
    $valid = [System.Collections.Generic.List[string]]::new()
    $invalid = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($Text) {
        foreach ($line in ($Text -split '\r?\n')) {
            $line = $line -replace '#.*$', ''
            foreach ($token in ($line -split '[\s,;]+')) {
                $t = $token.Trim().Trim('"', "'")
                if (-not $t) { continue }
                if ($t -match '^\\\\([^\\]+)') { $t = $Matches[1] }
                $t = $t.TrimEnd('.')
                if (-not $seen.Add($t)) { continue }
                if (Test-ServerName $t) { $valid.Add($t) } else { $invalid.Add($t) }
            }
        }
    }
    return [PSCustomObject]@{ Valid = $valid.ToArray(); Invalid = $invalid.ToArray() }
}

function ConvertFrom-ServerFile {
    # A .csv with a Name / ComputerName / Server / DNSHostName / HostName column (as exported by
    # Get-ADComputer or a spreadsheet) uses that column; anything else is read as plain text.
    param([Parameter(Mandatory)][string]$Path)
    $text = [System.IO.File]::ReadAllText($Path)
    $firstLine = ($text -split '\r?\n' | Where-Object { $_.Trim() } | Select-Object -First 1)
    if ($firstLine -and $firstLine -match ',') {
        $headers = @($firstLine -split ',' | ForEach-Object { $_.Trim().Trim('"') })
        foreach ($col in 'DNSHostName', 'ComputerName', 'Server', 'ServerName', 'HostName', 'Name') {
            $match = $headers | Where-Object { $_ -eq $col } | Select-Object -First 1
            if ($match) {
                $rows = @($text | ConvertFrom-Csv)
                $names = @($rows | ForEach-Object { $_.$match } | Where-Object { $_ })
                return ConvertTo-ServerNames -Text ($names -join "`n")
            }
        }
    }
    return ConvertTo-ServerNames -Text $text
}

function ConvertTo-ShareRelativePath {
    # Turns what the user typed into "<share>\<folder>" relative to each server.
    #   C$\Scripts             -> C$\Scripts
    #   C:\Scripts             -> C$\Scripts       (admin share)
    #   \\SRV01\C$\Scripts     -> C$\Scripts       (the server part is dropped)
    #   Software/Installers/   -> Software\Installers
    param([AllowEmptyString()][string]$Path)
    $note = $null
    $p = ([string]$Path).Trim().Trim('"').Trim().Replace('/', '\')
    if ($p -match '^\\\\[^\\]*\\?(.*)$') {
        $p = $Matches[1]
        $note = 'Only the part after the server name is used.'
    }
    elseif ($p -match '^([A-Za-z]):\\?(.*)$') {
        $drive = $Matches[1].ToUpperInvariant()
        $note = ('{0}: was changed to {0}$, the admin share for drive {0}: on each server.' -f $drive)
        $p = '{0}$\{1}' -f $drive, $Matches[2]
    }
    $p = $p.Trim('\')
    while ($p.Contains('\\')) { $p = $p.Replace('\\', '\') }
    if (-not $p) {
        return [PSCustomObject]@{ Path = ''; Error = 'Type the share and folder to copy into, like C$\Temp.'; Note = $null }
    }
    if ($p -match '[<>:"|?*]') {
        return [PSCustomObject]@{ Path = $p; Error = 'The folder contains a character Windows does not allow in folder names ( < > : " | ? * ).'; Note = $null }
    }
    foreach ($seg in $p.Split('\')) {
        if ($seg.Trim() -in '.', '..' -or $seg -ne $seg.TrimEnd(' ', '.')) {
            return [PSCustomObject]@{ Path = $p; Error = "The folder name '$seg' is not valid (names can't be . or .. or end with a space or dot)."; Note = $null }
        }
    }
    return [PSCustomObject]@{ Path = $p; Error = $null; Note = $note }
}

function Get-DestinationFolder {
    param([string]$Server, [string]$RelativePath)
    return '\\' + $Server + '\' + $RelativePath
}

function Get-FriendlyError {
    # Plain-English text for the errors people actually hit when copying to servers. Falls back
    # to the exception's own message.
    param($ErrorObject)
    $e = $ErrorObject
    if ($e -is [System.Management.Automation.ErrorRecord]) { $e = $e.Exception }
    if (-not $e) { return 'Unknown error.' }
    while ($e.InnerException -and ($e -is [System.Management.Automation.MethodInvocationException] -or $e -is [System.Management.Automation.RuntimeException])) {
        $e = $e.InnerException
    }
    $code = -1
    # Win32 errors arrive as HRESULT 0x8007xxxx (facility 7); the low word is the error code.
    if ((($e.HResult -shr 16) -band 0x1FFF) -eq 7) { $code = $e.HResult -band 0xFFFF }
    if ($e -is [System.UnauthorizedAccessException]) { $code = 5 }
    # https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-
    switch ($code) {
        5    { return 'Access denied. Your account cannot write here (admin shares like C$ need admin rights on that server).' }
        32   { return 'The file is in use on the server (another program has it open).' }
        53   { return 'The network path was not found. Check the server name and that file sharing is on.' }
        64   { return 'The connection to the server dropped during the copy.' }
        67   { return 'That share does not exist on this server. Check the first part of the folder (for example C$).' }
        112  { return 'The disk on the server is full.' }
        1326 { return 'The server rejected your sign-in (wrong account or password for this server).' }
    }
    return $e.Message
}

function Get-ReachProblem {
    # Returns $null when the server answers on the file-sharing port, otherwise the reason.
    # Checked before touching the UNC path, because Windows can take 20+ seconds to give up on
    # an offline server.
    param([Parameter(Mandatory)][string]$ComputerName, [int]$TimeoutMs = 3000)
    try { [void][System.Net.Dns]::GetHostAddresses($ComputerName) }
    catch { return "Can't find a server called $ComputerName (name lookup failed). Check the spelling." }
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        # SMB is directly hosted on TCP 445.
        # https://learn.microsoft.com/troubleshoot/windows-server/networking/direct-hosting-of-smb-over-tcpip
        $ar = $client.BeginConnect($ComputerName, 445, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            return "$ComputerName did not answer on the file-sharing port (TCP 445). It may be turned off, or a firewall is blocking file sharing."
        }
        $client.EndConnect($ar)
        return $null
    }
    catch { return "$ComputerName refused a file-sharing connection (TCP 445). File sharing may be off or blocked." }
    finally { $client.Close() }
}

function Invoke-ServerCheck {
    # Runs in a background runspace. Checks a server can be reached and the share opened,
    # without writing anything.
    param([string]$Server, [string]$DestFolder, [int]$TimeoutMs = 3000)
    $problem = Get-ReachProblem -ComputerName $Server -TimeoutMs $TimeoutMs
    if ($problem) { return [PSCustomObject]@{ Ok = $false; Message = $problem } }
    try {
        if ([System.IO.Directory]::Exists($DestFolder)) {
            return [PSCustomObject]@{ Ok = $true; Message = "Ready. $DestFolder is already there." }
        }
        $parts = $DestFolder.TrimStart('\').Split('\')
        $shareRoot = '\\' + $parts[0] + '\' + $parts[1]
        # Reading one entry is enough to prove the share opens with this account.
        $enum = [System.IO.Directory]::EnumerateFileSystemEntries($shareRoot).GetEnumerator()
        [void]$enum.MoveNext()
        $enum.Dispose()
        return [PSCustomObject]@{ Ok = $true; Message = "Ready. The folder will be created in $shareRoot." }
    }
    catch {
        return [PSCustomObject]@{ Ok = $false; Message = (Get-FriendlyError $_) }
    }
}

function Get-CopyPlan {
    # Expands the chosen files and folders into a flat list of files (with the path they get
    # under the destination folder) and the folders to create. A folder is copied as a folder:
    # choosing C:\Tools copies it to <dest>\Tools.
    param([string[]]$Sources)
    $files = [System.Collections.Generic.List[object]]::new()
    $dirs = [System.Collections.Generic.List[string]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()
    [long]$bytes = 0
    foreach ($src in $Sources) {
        try {
            if ([System.IO.File]::Exists($src)) {
                $fi = [System.IO.FileInfo]::new($src)
                $files.Add([PSCustomObject]@{ Source = $fi.FullName; Relative = $fi.Name; Size = $fi.Length; Modified = $fi.LastWriteTimeUtc })
                $bytes += $fi.Length
            }
            elseif ([System.IO.Directory]::Exists($src)) {
                $root = [System.IO.Path]::GetFullPath($src).TrimEnd('\')
                $name = [System.IO.Path]::GetFileName($root)
                $dirs.Add($name)
                foreach ($d in [System.IO.Directory]::GetDirectories($root, '*', 'AllDirectories')) {
                    $dirs.Add($name + $d.Substring($root.Length))
                }
                foreach ($f in [System.IO.Directory]::GetFiles($root, '*', 'AllDirectories')) {
                    $fi = [System.IO.FileInfo]::new($f)
                    $files.Add([PSCustomObject]@{ Source = $fi.FullName; Relative = $name + $f.Substring($root.Length); Size = $fi.Length; Modified = $fi.LastWriteTimeUtc })
                    $bytes += $fi.Length
                }
            }
            else {
                $errors.Add("$src - not found on this computer any more.")
            }
        }
        catch {
            $errors.Add("$src - $(Get-FriendlyError $_)")
        }
    }
    return [PSCustomObject]@{ Files = $files.ToArray(); Dirs = $dirs.ToArray(); Bytes = $bytes; Errors = $errors.ToArray() }
}

function Invoke-ServerCopy {
    # Runs in a background runspace: copies the plan into one destination folder.
    #   IfExists  replace = always overwrite, newer = overwrite only when the source is newer,
    #             skip = leave files that are already there alone.
    #   Shared    synchronized hashtable: .Cancel (set by the window) and .Progress[Key]
    #             (written here so the window can show "file 3 of 10").
    # With an empty -Server the reachability check is skipped (used by the tests with a local
    # folder).
    param(
        [string]$Server,
        [Parameter(Mandatory)][string]$DestFolder,
        [Parameter(Mandatory)][string[]]$Sources,
        [ValidateSet('replace', 'newer', 'skip')][string]$IfExists = 'replace',
        [hashtable]$Shared,
        [string]$Key,
        [int]$TimeoutMs = 3000
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not $Key) { $Key = $Server }
    $errors = [System.Collections.Generic.List[string]]::new()
    $r = [PSCustomObject]@{
        Server = $Server; Destination = $DestFolder; Outcome = 'Failed'; Copied = 0; Skipped = 0; Failed = 0
        Bytes = [long]0; Total = 0; Message = ''; Errors = @(); Seconds = 0
    }
    $setProgress = { param([string]$Text) if ($Shared -and $Shared.Progress -and $Key) { $Shared.Progress[$Key] = $Text } }
    $finish = {
        $r.Errors = $errors.ToArray()
        $r.Seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
        $r
    }

    if ($Shared -and $Shared.Cancel) {
        $r.Outcome = 'Cancelled'
        $r.Message = 'Not started - the copy was stopped.'
        return (& $finish)
    }
    & $setProgress 'Connecting...'
    if ($Server) {
        $problem = Get-ReachProblem -ComputerName $Server -TimeoutMs $TimeoutMs
        if ($problem) { $r.Message = $problem; $errors.Add($problem); return (& $finish) }
    }
    try {
        if (-not [System.IO.Directory]::Exists($DestFolder)) { [void][System.IO.Directory]::CreateDirectory($DestFolder) }
    }
    catch {
        $r.Message = "Couldn't open or create $DestFolder. $(Get-FriendlyError $_)"
        $errors.Add($r.Message)
        return (& $finish)
    }

    $plan = Get-CopyPlan -Sources $Sources
    foreach ($pe in $plan.Errors) { $r.Failed++; $errors.Add($pe) }
    foreach ($d in $plan.Dirs) {
        try { [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::Combine($DestFolder, $d)) }
        catch { $errors.Add("$d\ - $(Get-FriendlyError $_)") }
    }

    $files = $plan.Files
    $r.Total = $files.Count + $plan.Errors.Count
    $stopped = $false
    $i = 0
    foreach ($f in $files) {
        if ($Shared -and $Shared.Cancel) { $stopped = $true; break }
        $i++
        & $setProgress ('Copying {0} of {1}: {2}' -f $i, $files.Count, $f.Relative)
        $target = [System.IO.Path]::Combine($DestFolder, $f.Relative)
        try {
            if ([System.IO.File]::Exists($target)) {
                if ($IfExists -eq 'skip') { $r.Skipped++; continue }
                if ($IfExists -eq 'newer' -and $f.Modified -le [System.IO.File]::GetLastWriteTimeUtc($target)) { $r.Skipped++; continue }
                # File.Copy refuses to overwrite a read-only file, or a hidden file with a
                # non-hidden one, so those attributes are cleared first. The copy brings the
                # source's attributes with it.
                # https://learn.microsoft.com/dotnet/api/system.io.file.copy
                $attr = [System.IO.File]::GetAttributes($target)
                if ($attr -band ([System.IO.FileAttributes]::ReadOnly -bor [System.IO.FileAttributes]::Hidden)) {
                    [System.IO.File]::SetAttributes($target, [System.IO.FileAttributes]::Normal)
                }
            }
            else {
                $parent = [System.IO.Path]::GetDirectoryName($target)
                if (-not [System.IO.Directory]::Exists($parent)) { [void][System.IO.Directory]::CreateDirectory($parent) }
            }
            [System.IO.File]::Copy($f.Source, $target, $true)
            $r.Copied++
            $r.Bytes += $f.Size
        }
        catch {
            $r.Failed++
            if ($errors.Count -lt 50) { $errors.Add("$($f.Relative) - $(Get-FriendlyError $_)") }
        }
    }

    $skippedText = ''
    if ($r.Skipped -gt 0) { $skippedText = " Skipped $(Format-Count $r.Skipped 'file') already there." }
    if ($stopped) {
        $r.Outcome = 'Stopped'
        $r.Message = "Stopped after copying $($r.Copied) of $(Format-Count $files.Count 'file')."
    }
    elseif ($r.Failed -eq 0) {
        $r.Outcome = 'Done'
        if ($r.Copied -eq 0 -and $r.Skipped -gt 0) { $r.Message = "Nothing new to copy - $(Format-Count $r.Skipped 'file' 'files were') already there." }
        elseif ($r.Copied -eq 0) { $r.Message = 'Nothing to copy (the folders are empty). Folders were created.' }
        else { $r.Message = "Copied $(Format-Count $r.Copied 'file') ($(Format-Bytes $r.Bytes)).$skippedText" }
    }
    elseif ($r.Copied + $r.Skipped -gt 0) {
        $r.Outcome = 'Partial'
        $r.Message = "$($r.Failed) of $(Format-Count $r.Total 'file') failed, $($r.Copied) copied.$skippedText First problem: $($errors[0])"
    }
    else {
        $r.Outcome = 'Failed'
        $r.Message = "Nothing was copied. $($errors[0])"
    }
    & $setProgress $null
    return (& $finish)
}

function Add-SourceItem {
    # Adds a file or folder to the "what to copy" list. Returns $null when added (or already in
    # the list) and a plain-English reason when it can't be added.
    param([System.Collections.Generic.List[object]]$List, [string]$Path)
    try { $full = [System.IO.Path]::GetFullPath($Path.Trim().Trim('"')) }
    catch { return "$Path - not a valid path." }
    $isFolder = [System.IO.Directory]::Exists($full)
    if (-not $isFolder -and -not [System.IO.File]::Exists($full)) { return "$full - not found." }
    if ($isFolder) {
        $full = $full.TrimEnd('\')
        if ($full.Length -le 2 -or [System.IO.Path]::GetPathRoot($full + '\') -eq ($full + '\')) {
            return "$full\ is a whole drive. Pick a folder or files instead."
        }
    }
    $name = [System.IO.Path]::GetFileName($full)
    foreach ($s in $List) {
        if ([string]::Equals($s.Path, $full, [StringComparison]::OrdinalIgnoreCase)) { return $null }
        if ([string]::Equals($s.Name, $name, [StringComparison]::OrdinalIgnoreCase)) {
            return "There is already an item called '$name' in the list. Two items with the same name would land on top of each other on the server."
        }
    }
    $size = $null
    if (-not $isFolder) { $size = ([System.IO.FileInfo]::new($full)).Length }
    $List.Add([PSCustomObject]@{ Path = $full; Name = $name; IsFolder = $isFolder; Size = $size })
    return $null
}

#endregion

#region XAML

$script:Themes = @{
    dark  = @{
        Bg = '#16181D'; Panel = '#101216'; Card = '#1C1F26'; CardHover = '#232833'; SelBg = '#1A2733'
        Input = '#0F1115'; Border = '#262A33'; BorderStrong = '#343A46'
        BtnBg = '#232731'; BtnHover = '#2C313D'; BtnPressed = '#1B1F27'
        Text = '#D7DBE2'; TextStrong = '#F0F3F6'; Muted = '#8B949E'
        Accent = '#5DADE2'; AccentBtn = '#2E86C1'; AccentBtnHover = '#3B97D3'; OnAccent = '#FFFFFF'
        Danger = '#F08A7C'; Ok = '#6FD39B'; Warn = '#F2CC60'
        PillRunBg = '#173A52'; PillOkBg = '#173D2A'; PillWarnBg = '#463A12'; PillBadBg = '#4A1F1B'; PillMutedBg = '#2B2F38'
        Track = '#2B303A'; ScrollThumb = '#3C4350'
    }
    light = @{
        Bg = '#F3F4F6'; Panel = '#FFFFFF'; Card = '#FFFFFF'; CardHover = '#F2F6FA'; SelBg = '#EAF3FB'
        Input = '#FFFFFF'; Border = '#DDE1E7'; BorderStrong = '#C5CBD3'
        BtnBg = '#FFFFFF'; BtnHover = '#EEF1F5'; BtnPressed = '#E2E6EC'
        Text = '#2A2F37'; TextStrong = '#0F1318'; Muted = '#5F6875'
        Accent = '#1F6FA8'; AccentBtn = '#1F6FA8'; AccentBtnHover = '#185C8C'; OnAccent = '#FFFFFF'
        Danger = '#B83227'; Ok = '#1D7A44'; Warn = '#8A5A00'
        PillRunBg = '#DCEBF7'; PillOkBg = '#DCF2E4'; PillWarnBg = '#FBEFCC'; PillBadBg = '#F8DCD8'; PillMutedBg = '#E7EAEE'
        Track = '#E3E7EC'; ScrollThumb = '#C3C9D1'
    }
}

# Shared styles: the same look as RobocopyMigration-GUI.ps1.
$script:ResourcesXaml = @'
<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
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
      <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="{DynamicResource Accent}"/></Trigger>
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
            <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="{DynamicResource Accent}"/></Trigger>
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
            <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="{DynamicResource Accent}"/></Trigger>
            <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/></Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>

  <Style x:Key="Seg" TargetType="RadioButton">
    <Setter Property="Foreground" Value="{DynamicResource Text}"/>
    <Setter Property="Background" Value="{DynamicResource BtnBg}"/>
    <Setter Property="Padding" Value="10,5"/>
    <Setter Property="FontSize" Value="12"/>
    <Setter Property="Cursor" Value="Hand"/>
    <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="RadioButton">
          <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{DynamicResource BorderStrong}"
                  BorderThickness="1" CornerRadius="3" Padding="{TemplateBinding Padding}" Margin="0,0,4,0">
            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
          </Border>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="{DynamicResource BtnHover}"/></Trigger>
            <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="{DynamicResource Accent}"/></Trigger>
            <Trigger Property="IsChecked" Value="True">
              <Setter TargetName="b" Property="Background" Value="{DynamicResource AccentBtn}"/>
              <Setter TargetName="b" Property="BorderBrush" Value="{DynamicResource AccentBtn}"/>
              <Setter Property="Foreground" Value="{DynamicResource OnAccent}"/>
            </Trigger>
            <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/></Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>

  <Style TargetType="CheckBox">
    <Setter Property="Foreground" Value="{DynamicResource Text}"/>
    <Setter Property="Cursor" Value="Hand"/>
    <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="CheckBox">
          <StackPanel Orientation="Horizontal" Background="Transparent">
            <Border x:Name="box" Width="16" Height="16" CornerRadius="3" BorderThickness="1" VerticalAlignment="Center"
                    BorderBrush="{DynamicResource BorderStrong}" Background="{DynamicResource Input}">
              <Grid>
                <Path x:Name="tick" Data="M3,8 L6.5,11.5 L13,4.5" Stroke="{DynamicResource OnAccent}" StrokeThickness="2" Visibility="Collapsed"/>
                <Rectangle x:Name="dash" Width="8" Height="2" Fill="{DynamicResource OnAccent}" Visibility="Collapsed"/>
              </Grid>
            </Border>
            <ContentPresenter x:Name="content" Margin="8,0,0,0" VerticalAlignment="Center"/>
          </StackPanel>
          <ControlTemplate.Triggers>
            <Trigger Property="Content" Value="{x:Null}"><Setter TargetName="content" Property="Margin" Value="0"/></Trigger>
            <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="box" Property="BorderBrush" Value="{DynamicResource Accent}"/></Trigger>
            <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="box" Property="BorderBrush" Value="{DynamicResource Accent}"/></Trigger>
            <Trigger Property="IsChecked" Value="True">
              <Setter TargetName="box" Property="Background" Value="{DynamicResource AccentBtn}"/>
              <Setter TargetName="box" Property="BorderBrush" Value="{DynamicResource AccentBtn}"/>
              <Setter TargetName="tick" Property="Visibility" Value="Visible"/>
            </Trigger>
            <Trigger Property="IsChecked" Value="{x:Null}">
              <Setter TargetName="box" Property="Background" Value="{DynamicResource AccentBtn}"/>
              <Setter TargetName="box" Property="BorderBrush" Value="{DynamicResource AccentBtn}"/>
              <Setter TargetName="dash" Property="Visibility" Value="Visible"/>
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
  <Style x:Key="CardBorder" TargetType="Border">
    <Setter Property="Background" Value="{DynamicResource Card}"/>
    <Style.Triggers>
      <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="{DynamicResource CardHover}"/></Trigger>
    </Style.Triggers>
  </Style>
  <Style x:Key="StepNum" TargetType="Border">
    <Setter Property="Width" Value="20"/>
    <Setter Property="Height" Value="20"/>
    <Setter Property="CornerRadius" Value="10"/>
    <Setter Property="Background" Value="{DynamicResource AccentBtn}"/>
    <Setter Property="VerticalAlignment" Value="Center"/>
  </Style>
  <Style x:Key="StepNumText" TargetType="TextBlock">
    <Setter Property="FontSize" Value="11"/>
    <Setter Property="FontWeight" Value="Bold"/>
    <Setter Property="Foreground" Value="{DynamicResource OnAccent}"/>
    <Setter Property="HorizontalAlignment" Value="Center"/>
    <Setter Property="VerticalAlignment" Value="Center"/>
  </Style>
  <Style x:Key="StepTitle" TargetType="TextBlock">
    <Setter Property="FontSize" Value="13"/>
    <Setter Property="FontWeight" Value="SemiBold"/>
    <Setter Property="Foreground" Value="{DynamicResource TextStrong}"/>
    <Setter Property="Margin" Value="8,0,0,0"/>
    <Setter Property="VerticalAlignment" Value="Center"/>
  </Style>
</ResourceDictionary>
'@

$script:MainXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Copy Files to Servers" Width="1180" Height="780" MinWidth="940" MinHeight="580"
        WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" FontSize="13"
        Background="{DynamicResource Bg}" Foreground="{DynamicResource Text}"
        UseLayoutRounding="True" TextOptions.TextFormattingMode="Display">
  <!--RESOURCES-->
  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="56"/>
      <RowDefinition Height="*"/>
    </Grid.RowDefinitions>

    <!-- Title bar -->
    <Border Grid.Row="0" Background="{DynamicResource Panel}" BorderBrush="{DynamicResource Border}" BorderThickness="0,0,0,1">
      <DockPanel Margin="16,0" LastChildFill="False">
        <StackPanel DockPanel.Dock="Left" Orientation="Horizontal" VerticalAlignment="Center">
          <Border Width="30" Height="30" CornerRadius="4" Background="{DynamicResource AccentBtn}">
            <TextBlock Text="&#x21F6;" FontFamily="{StaticResource Sym}" FontSize="17" Foreground="{DynamicResource OnAccent}"
                       HorizontalAlignment="Center" VerticalAlignment="Center"/>
          </Border>
          <TextBlock Text="Copy Files to Servers" FontSize="16" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}"
                     Margin="10,0,0,0" VerticalAlignment="Center"/>
          <TextBlock x:Name="VersionText" FontSize="11" Foreground="{DynamicResource Muted}" Margin="8,3,0,0" VerticalAlignment="Center"/>
        </StackPanel>
        <Button x:Name="ThemeBtn" DockPanel.Dock="Right" Style="{StaticResource GhostBtn}" VerticalAlignment="Center"/>
      </DockPanel>
    </Border>

    <Grid Grid.Row="1">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="410"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>

      <!-- Left: what, where, options -->
      <Border Grid.Column="0" BorderBrush="{DynamicResource Border}" BorderThickness="0,0,1,0">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <ScrollViewer Grid.Row="0" VerticalScrollBarVisibility="Auto">
            <StackPanel x:Name="LeftForm" Margin="20,4,20,20">

              <StackPanel Orientation="Horizontal" Margin="0,16,0,8">
                <Border Style="{StaticResource StepNum}"><TextBlock Style="{StaticResource StepNumText}" Text="1"/></Border>
                <TextBlock Style="{StaticResource StepTitle}" Text="What to copy"/>
              </StackPanel>
              <Grid x:Name="DropZone" AllowDrop="True" Background="Transparent" MinHeight="92">
                <Rectangle x:Name="DropRect" RadiusX="4" RadiusY="4" StrokeThickness="1.5" StrokeDashArray="4 3"
                           Stroke="{DynamicResource BorderStrong}" Fill="{DynamicResource Input}"/>
                <StackPanel Margin="8">
                  <StackPanel x:Name="SourcePanel"/>
                  <StackPanel x:Name="SourceEmpty" HorizontalAlignment="Center" Margin="0,12">
                    <TextBlock Text="&#x2B07;" FontFamily="{StaticResource Sym}" FontSize="20" Foreground="{DynamicResource Muted}" HorizontalAlignment="Center"/>
                    <TextBlock Text="Drop files or folders here" FontWeight="SemiBold" Foreground="{DynamicResource Text}" HorizontalAlignment="Center" Margin="0,4,0,0"/>
                    <TextBlock Text="or use the buttons below" Style="{StaticResource Hint}" HorizontalAlignment="Center" Margin="0,2,0,0"/>
                  </StackPanel>
                </StackPanel>
              </Grid>
              <WrapPanel Margin="0,8,0,0">
                <Button x:Name="AddFilesBtn" Style="{StaticResource Btn}" Margin="0,0,6,0">
                  <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x1F4C4;"/><Run Text="  Add files"/></TextBlock>
                </Button>
                <Button x:Name="AddFolderBtn" Style="{StaticResource Btn}" Margin="0,0,6,0">
                  <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x1F4C1;"/><Run Text="  Add folder"/></TextBlock>
                </Button>
                <Button x:Name="ClearSourcesBtn" Style="{StaticResource GhostBtn}" Content="Clear" ToolTip="Empty the list of things to copy"/>
              </WrapPanel>
              <TextBlock x:Name="SourceNote" Style="{StaticResource Hint}" Visibility="Collapsed"/>

              <StackPanel Orientation="Horizontal" Margin="0,24,0,8">
                <Border Style="{StaticResource StepNum}"><TextBlock Style="{StaticResource StepNumText}" Text="2"/></Border>
                <TextBlock Style="{StaticResource StepTitle}" Text="Where to put it on each server"/>
              </StackPanel>
              <TextBox x:Name="DestBox" FontFamily="{StaticResource Mono}"/>
              <Border Margin="0,6,0,0" Padding="10,7" CornerRadius="3" Background="{DynamicResource SelBg}">
                <StackPanel>
                  <TextBlock x:Name="DestExampleLabel" Text="FOR EXAMPLE" Style="{StaticResource Lbl}" Margin="0,0,0,2" FontSize="10"/>
                  <TextBlock x:Name="DestExample" FontFamily="{StaticResource Mono}" FontSize="12" Foreground="{DynamicResource Accent}" TextWrapping="Wrap"/>
                  <TextBlock x:Name="DestNote" Style="{StaticResource Hint}" Visibility="Collapsed"/>
                </StackPanel>
              </Border>
              <TextBlock Style="{StaticResource Hint}" Text="A share and folder on each server, like C$\Temp or Software\Installers. You can also type C:\Temp. Missing folders are created."/>

              <StackPanel Orientation="Horizontal" Margin="0,24,0,8">
                <Border Style="{StaticResource StepNum}"><TextBlock Style="{StaticResource StepNumText}" Text="3"/></Border>
                <TextBlock Style="{StaticResource StepTitle}" Text="Options"/>
              </StackPanel>
              <TextBlock Style="{StaticResource Lbl}" Margin="0,2,0,5" Text="IF A FILE IS ALREADY THERE"/>
              <WrapPanel>
                <RadioButton x:Name="IfReplace" GroupName="ifexists" Style="{StaticResource Seg}" Content="Replace it" IsChecked="True" Margin="0,0,0,4"/>
                <RadioButton x:Name="IfNewer" GroupName="ifexists" Style="{StaticResource Seg}" Content="Replace if mine is newer" Margin="0,0,0,4"/>
                <RadioButton x:Name="IfSkip" GroupName="ifexists" Style="{StaticResource Seg}" Content="Leave it" Margin="0,0,0,4"/>
              </WrapPanel>
              <TextBlock x:Name="IfHint" Style="{StaticResource Hint}"/>
              <TextBlock Style="{StaticResource Lbl}" Text="SERVERS AT THE SAME TIME"/>
              <StackPanel Orientation="Horizontal">
                <RadioButton x:Name="Par1" GroupName="par" Style="{StaticResource Seg}" Content="1" MinWidth="40"/>
                <RadioButton x:Name="Par4" GroupName="par" Style="{StaticResource Seg}" Content="4" MinWidth="40"/>
                <RadioButton x:Name="Par8" GroupName="par" Style="{StaticResource Seg}" Content="8" MinWidth="40" IsChecked="True"/>
                <RadioButton x:Name="Par16" GroupName="par" Style="{StaticResource Seg}" Content="16" MinWidth="40"/>
              </StackPanel>
              <TextBlock Style="{StaticResource Hint}" Text="More at once finishes sooner. Use 1 for large files over a slow link."/>
            </StackPanel>
          </ScrollViewer>

          <Border Grid.Row="1" Background="{DynamicResource Panel}" BorderBrush="{DynamicResource Border}" BorderThickness="0,1,0,0" Padding="20,12">
            <StackPanel>
              <TextBlock x:Name="ReadyText" Style="{StaticResource Hint}" Margin="0,0,0,8"/>
              <Grid x:Name="RunBar" Height="6" Margin="0,0,0,10" Visibility="Collapsed">
                <Grid.ColumnDefinitions>
                  <ColumnDefinition x:Name="RunFill" Width="0*"/>
                  <ColumnDefinition x:Name="RunRest" Width="1*"/>
                </Grid.ColumnDefinitions>
                <Border Grid.ColumnSpan="2" CornerRadius="3" Background="{DynamicResource Track}"/>
                <Border Grid.Column="0" CornerRadius="3" Background="{DynamicResource Accent}"/>
              </Grid>
              <DockPanel>
                <Button x:Name="StopBtn" DockPanel.Dock="Right" Style="{StaticResource DangerBtn}" Margin="8,0,0,0" Visibility="Collapsed"
                        ToolTip="Finish the file being copied on each server, then stop. Servers not started yet are skipped.">
                  <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x25A0;"/><Run x:Name="StopText" Text="  Stop"/></TextBlock>
                </Button>
                <Button x:Name="CopyBtn" Style="{StaticResource PrimaryBtn}" Padding="14,9" FontSize="13.5">
                  <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x25B6;"/><Run x:Name="CopyBtnText" Text="  Copy"/></TextBlock>
                </Button>
              </DockPanel>
            </StackPanel>
          </Border>
        </Grid>
      </Border>

      <!-- Right: servers -->
      <Grid x:Name="ServerArea" Grid.Column="1" AllowDrop="True" Background="Transparent">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <StackPanel Grid.Row="0" Margin="24,16,24,0">
          <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
            <Border Style="{StaticResource StepNum}"><TextBlock Style="{StaticResource StepNumText}" Text="4"/></Border>
            <TextBlock Style="{StaticResource StepTitle}" Text="Which servers"/>
          </StackPanel>
          <DockPanel>
            <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Top" Margin="8,0,0,0">
              <Button x:Name="AddServersBtn" Style="{StaticResource PrimaryBtn}" Margin="0,0,6,0" ToolTip="Add the names in the box to the list (Enter)">
                <TextBlock><Run Text="+" FontWeight="Bold"/><Run Text="  Add"/></TextBlock>
              </Button>
              <Button x:Name="ImportBtn" Style="{StaticResource Btn}" ToolTip="Add servers from a .txt or .csv file (one name per line, or a Name / DNSHostName column)">
                <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x1F4C2;"/><Run Text="  Import file"/></TextBlock>
              </Button>
            </StackPanel>
            <TextBox x:Name="AddBox" FontFamily="{StaticResource Mono}" AcceptsReturn="True" TextWrapping="Wrap"
                     MinHeight="34" MaxHeight="120" VerticalScrollBarVisibility="Auto"/>
          </DockPanel>
          <TextBlock Style="{StaticResource Hint}" Text="Type a server name and press Enter, or paste a whole list - one per line, or separated by commas or spaces. Shift+Enter starts a new line."/>
          <TextBlock x:Name="AddResult" TextWrapping="Wrap" FontSize="12" Margin="0,6,0,0" Visibility="Collapsed"/>
        </StackPanel>

        <DockPanel Grid.Row="1" Margin="24,16,24,8">
          <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
            <Button x:Name="CheckBtn" Style="{StaticResource Btn}" Margin="0,0,6,0" Padding="10,4"
                    ToolTip="Test every server in the list: can it be found, does it answer, and can your account open the share. Nothing is copied.">
              <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x2713;"/><Run Text="  Check connection"/></TextBlock>
            </Button>
            <Button x:Name="SaveListBtn" Style="{StaticResource Btn}" Margin="0,0,6,0" Padding="10,4" ToolTip="Save the server list to a text file">
              <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x1F4BE;"/><Run Text="  Save list"/></TextBlock>
            </Button>
            <Button x:Name="ClearServersBtn" Style="{StaticResource GhostBtn}" Foreground="{DynamicResource Danger}" ToolTip="Remove every server from the list">
              <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x2715;"/><Run Text="  Clear list"/></TextBlock>
            </Button>
          </StackPanel>
          <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
            <CheckBox x:Name="AllCheck" VerticalAlignment="Center" Margin="11,0,10,0" ToolTip="Tick or untick every server"/>
            <TextBlock Text="SERVERS" Style="{StaticResource Lbl}" Margin="0" VerticalAlignment="Center"/>
            <TextBlock x:Name="ServerCount" Foreground="{DynamicResource Muted}" FontSize="11.5" Margin="8,0,0,0" VerticalAlignment="Center"/>
          </StackPanel>
        </DockPanel>

        <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto">
          <StackPanel Margin="24,0,24,12">
            <StackPanel x:Name="ServerPanel"/>
            <StackPanel x:Name="ServerEmpty" HorizontalAlignment="Center" Margin="0,40,0,0" MaxWidth="360">
              <TextBlock Text="&#x21F6;" FontFamily="{StaticResource Sym}" FontSize="36" Foreground="{DynamicResource Track}" HorizontalAlignment="Center"/>
              <TextBlock Text="No servers yet" FontSize="15" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}" HorizontalAlignment="Center" Margin="0,8,0,0"/>
              <TextBlock Style="{StaticResource Hint}" TextAlignment="Center" Margin="0,6,0,0"
                         Text="Type or paste server names in the box above, import a list, or drop a .txt file here. The list is remembered next time."/>
            </StackPanel>
          </StackPanel>
        </ScrollViewer>

        <Border x:Name="ResultBar" Grid.Row="3" Visibility="Collapsed" Background="{DynamicResource Panel}"
                BorderBrush="{DynamicResource Border}" BorderThickness="0,1,0,0" Padding="24,12">
          <DockPanel>
            <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
              <Button x:Name="RetryBtn" Style="{StaticResource PrimaryBtn}" Margin="8,0,0,0" ToolTip="Copy again to the servers that failed or were stopped">
                <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x21BB;"/><Run x:Name="RetryText" Text="  Retry failed"/></TextBlock>
              </Button>
              <Button x:Name="OpenLogBtn" Style="{StaticResource Btn}" Margin="8,0,0,0">
                <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x1F4C4;"/><Run Text="  Open log"/></TextBlock>
              </Button>
              <Button x:Name="ExportBtn" Style="{StaticResource Btn}" Margin="8,0,0,0" ToolTip="Save the result for every server to a CSV file">
                <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x1F4BE;"/><Run Text="  Export results"/></TextBlock>
              </Button>
            </StackPanel>
            <StackPanel VerticalAlignment="Center">
              <TextBlock x:Name="ResultHeadline" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}" TextWrapping="Wrap"/>
              <TextBlock x:Name="ResultDetail" Style="{StaticResource Hint}" Margin="0,2,0,0"/>
            </StackPanel>
          </DockPanel>
        </Border>
      </Grid>
    </Grid>
  </Grid>
</Window>
'@

$script:ServerRowXaml = @'
<Border xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Style="{DynamicResource CardBorder}" BorderBrush="{DynamicResource Border}" BorderThickness="1"
        CornerRadius="4" Padding="10,6" Margin="0,0,0,4">
  <Grid>
    <Grid.ColumnDefinitions>
      <ColumnDefinition Width="Auto"/>
      <ColumnDefinition Width="*"/>
      <ColumnDefinition Width="Auto"/>
      <ColumnDefinition Width="Auto"/>
      <ColumnDefinition Width="Auto"/>
    </Grid.ColumnDefinitions>
    <CheckBox x:Name="Inc" VerticalAlignment="Center" Margin="0,0,10,0" ToolTip="Include this server in the copy"/>
    <StackPanel Grid.Column="1" VerticalAlignment="Center">
      <TextBlock x:Name="NameText" FontFamily="{DynamicResource Mono}" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}"
                 TextTrimming="CharacterEllipsis" Cursor="IBeam" ToolTip="Double-click to change the name"/>
      <TextBox x:Name="EditBox" FontFamily="{DynamicResource Mono}" Padding="5,2" Visibility="Collapsed"/>
      <TextBlock x:Name="Sub" FontSize="11.5" Foreground="{DynamicResource Muted}" Margin="0,2,0,0" TextWrapping="Wrap" MaxHeight="34" TextTrimming="CharacterEllipsis"/>
    </StackPanel>
    <Border x:Name="Pill" Grid.Column="2" CornerRadius="9" Padding="8,2" Margin="8,0,4,0" VerticalAlignment="Center" Visibility="Collapsed">
      <TextBlock x:Name="PillText" FontSize="11" FontWeight="SemiBold"/>
    </Border>
    <Button x:Name="EditBtn" Grid.Column="3" Style="{DynamicResource GhostBtn}" ToolTip="Change the name" VerticalAlignment="Center">
      <TextBlock FontFamily="{DynamicResource Sym}" Text="&#x270E;"/>
    </Button>
    <Button x:Name="RemoveBtn" Grid.Column="4" Style="{DynamicResource GhostBtn}" ToolTip="Remove from the list" VerticalAlignment="Center">
      <TextBlock FontFamily="{DynamicResource Sym}" Text="&#x2715;"/>
    </Button>
  </Grid>
</Border>
'@

$script:SourceRowXaml = @'
<Border xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Style="{DynamicResource CardBorder}" BorderBrush="{DynamicResource Border}" BorderThickness="1"
        CornerRadius="3" Padding="8,5" Margin="0,0,0,4">
  <DockPanel>
    <Button x:Name="RemoveBtn" DockPanel.Dock="Right" Style="{DynamicResource GhostBtn}" ToolTip="Remove from the list" VerticalAlignment="Center">
      <TextBlock FontFamily="{DynamicResource Sym}" Text="&#x2715;"/>
    </Button>
    <TextBlock x:Name="Icon" DockPanel.Dock="Left" FontFamily="{DynamicResource Sym}" FontSize="14" Margin="0,0,8,0" VerticalAlignment="Center"/>
    <StackPanel VerticalAlignment="Center">
      <TextBlock x:Name="NameText" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}" TextTrimming="CharacterEllipsis"/>
      <TextBlock x:Name="Sub" FontSize="11" Foreground="{DynamicResource Muted}" FontFamily="{DynamicResource Mono}" TextTrimming="CharacterEllipsis"/>
    </StackPanel>
  </DockPanel>
</Border>
'@

#endregion

#region Window helpers

function New-ThemedWindow {
    # StaticResource references are resolved while the XAML is parsed, so the shared styles
    # are spliced into the window's own resources before parsing, not attached afterwards.
    param([string]$Xaml)
    $inner = $script:ResourcesXaml -replace '(?s)^\s*<ResourceDictionary[^>]*>', '<ResourceDictionary>'
    $w = [System.Windows.Markup.XamlReader]::Parse($Xaml.Replace('<!--RESOURCES-->', "<Window.Resources>$inner</Window.Resources>"))
    Set-WpfTheme -Resources $w.Resources -Theme $script:Settings.theme
    return $w
}

function Set-WpfTheme {
    # Every color is looked up with DynamicResource, so replacing the brushes recolors the
    # whole window in place.
    param($Resources, [string]$Theme)
    $palette = $script:Themes[$Theme]
    foreach ($key in $palette.Keys) {
        $brush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($palette[$key]))
        $brush.Freeze()
        $Resources[$key] = $brush
    }
}

function Set-Res {
    # Points a property at a theme brush so it follows the theme toggle.
    param($Element, $Property, [string]$Key)
    $Element.SetResourceReference($Property, $Key)
}

function Get-StatusVisual {
    param([string]$Status)
    switch ($Status) {
        'Checking'    { @{ Bg = 'PillRunBg';   Fg = 'Accent'; Text = 'Checking...' } }
        'Ready'       { @{ Bg = 'PillOkBg';    Fg = 'Ok';     Text = "$([char]0x2713) Ready" } }
        'Unreachable' { @{ Bg = 'PillBadBg';   Fg = 'Danger'; Text = "$([char]0x2715) Can't connect" } }
        'Waiting'     { @{ Bg = 'PillMutedBg'; Fg = 'Muted';  Text = 'Waiting' } }
        'Copying'     { @{ Bg = 'PillRunBg';   Fg = 'Accent'; Text = "$([char]0x25B6) Copying" } }
        'Done'        { @{ Bg = 'PillOkBg';    Fg = 'Ok';     Text = "$([char]0x2713) Done" } }
        'Partial'     { @{ Bg = 'PillWarnBg';  Fg = 'Warn';   Text = "$([char]0x26A0) Some files failed" } }
        'Failed'      { @{ Bg = 'PillBadBg';   Fg = 'Danger'; Text = "$([char]0x2715) Failed" } }
        'Stopped'     { @{ Bg = 'PillMutedBg'; Fg = 'Muted';  Text = "$([char]0x25A0) Stopped" } }
        'Cancelled'   { @{ Bg = 'PillMutedBg'; Fg = 'Muted';  Text = 'Not started' } }
        default       { $null }
    }
}

#endregion

#region Background work

# Network work (name lookups, connecting, copying) runs in runspace pools; the workers return
# plain data and only the UI thread touches controls. The worker functions are copied into each
# runspace through the initial session state.
$script:WorkerFunctions = 'Format-Bytes', 'Format-Count', 'Get-FriendlyError', 'Get-ReachProblem', 'Get-CopyPlan', 'Invoke-ServerCopy', 'Invoke-ServerCheck'
$script:BgTasks = [System.Collections.Generic.List[object]]::new()

function New-WorkerPool {
    param([int]$Max)
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($n in $script:WorkerFunctions) {
        $def = (Get-Item -LiteralPath "Function:\$n").Definition
        $iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($n, $def))
    }
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Max, $iss, $Host)
    $pool.Open()
    return $pool
}

function Start-BgTask {
    param($Pool, [string]$Command, [hashtable]$Parameters, [scriptblock]$OnDone, $State)
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.RunspacePool = $Pool
    [void]$ps.AddCommand($Command)
    foreach ($k in $Parameters.Keys) { [void]$ps.AddParameter($k, $Parameters[$k]) }
    $script:BgTasks.Add([PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke(); OnDone = $OnDone; State = $State })
}

function Update-BgTasks {
    # OnDone always runs - with $null when the worker threw - so a run never waits forever on
    # a task that crashed.
    foreach ($t in @($script:BgTasks)) {
        if (-not $t.Handle.IsCompleted) { continue }
        [void]$script:BgTasks.Remove($t)
        $result = $null
        try {
            $out = $t.PS.EndInvoke($t.Handle)
            if ($out.Count -gt 0) { $result = $out[$out.Count - 1] }
            foreach ($er in $t.PS.Streams.Error) { Write-GuiError "Worker: $($er.Exception.Message)" }
        }
        catch { Write-GuiError "Background task: $($_.Exception.Message)" }
        finally { $t.PS.Dispose() }
        try { & $t.OnDone $result $t.State }
        catch { Write-GuiError "Background task callback: $($_.Exception.Message)" }
    }
}

#endregion

#region UI state

$script:Settings = [PSCustomObject]@{ theme = 'dark'; destPath = 'C$\Temp'; ifExists = 'replace'; parallel = 8 }
$script:Servers = [System.Collections.Generic.List[object]]::new()
$script:Sources = [System.Collections.Generic.List[object]]::new()
$script:UI = @{}
$script:Run = $null
$script:CheckPool = $null
$script:LastLogPath = $null
$script:Dot = " $([char]0xB7) "

function New-ServerEntry {
    param([string]$Name, [bool]$Include = $true)
    return [PSCustomObject]@{ Name = $Name; Include = $Include; Status = ''; Message = ''; Errors = @(); Result = $null; Ui = $null }
}

function Find-Server {
    param([string]$Name, $Except)
    foreach ($s in $script:Servers) {
        if ($s -ne $Except -and [string]::Equals($s.Name, $Name, [StringComparison]::OrdinalIgnoreCase)) { return $s }
    }
    return $null
}

function Save-Settings {
    try {
        if (-not (Test-Path -LiteralPath $script:StateDir)) { New-Item -ItemType Directory -Path $script:StateDir -Force | Out-Null }
        $data = [PSCustomObject]@{
            theme    = $script:Settings.theme
            destPath = $script:Settings.destPath
            ifExists = $script:Settings.ifExists
            parallel = $script:Settings.parallel
            servers  = @($script:Servers | ForEach-Object { [PSCustomObject]@{ name = $_.Name; include = [bool]$_.Include } })
        }
        $data | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $script:SettingsPath -Encoding UTF8
    }
    catch { Write-GuiError "Save settings: $($_.Exception.Message)" }
}

function Read-Settings {
    if (-not (Test-Path -LiteralPath $script:SettingsPath)) { return }
    try {
        $s = Get-Content -LiteralPath $script:SettingsPath -Raw | ConvertFrom-Json
        if ($s.theme -in 'dark', 'light') { $script:Settings.theme = $s.theme }
        if ($null -ne $s.destPath) { $script:Settings.destPath = [string]$s.destPath }
        if ($s.ifExists -in 'replace', 'newer', 'skip') { $script:Settings.ifExists = $s.ifExists }
        if ([int]$s.parallel -in 1, 4, 8, 16) { $script:Settings.parallel = [int]$s.parallel }
        foreach ($e in @($s.servers)) {
            if ($e -and (Test-ServerName ([string]$e.name)) -and -not (Find-Server ([string]$e.name))) {
                $script:Servers.Add((New-ServerEntry -Name ([string]$e.name) -Include ([bool]$e.include)))
            }
        }
    }
    catch { Write-GuiError "Read settings: $($_.Exception.Message)" }
}

function Get-DestState {
    return ConvertTo-ShareRelativePath -Path $script:UI.DestBox.Text
}

#endregion

#region Sources (step 1)

function Add-Sources {
    param([string[]]$Paths)
    $problems = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $Paths) {
        if (-not $p) { continue }
        $why = Add-SourceItem -List $script:Sources -Path $p
        if ($why) { $problems.Add($why) }
    }
    $note = $script:UI.SourceNote
    if ($problems.Count -gt 0) {
        $note.Text = 'Not added: ' + ($problems -join ' ')
        Set-Res $note ([System.Windows.Controls.TextBlock]::ForegroundProperty) 'Danger'
        $note.Visibility = 'Visible'
    }
    else { $note.Visibility = 'Collapsed' }
    Update-SourcePanel
}

function Update-SourcePanel {
    $panel = $script:UI.SourcePanel
    $panel.Children.Clear()
    $fileIcon = [char]::ConvertFromUtf32(0x1F4C4)
    $folderIcon = [char]::ConvertFromUtf32(0x1F4C1)
    foreach ($s in $script:Sources) {
        $row = [System.Windows.Markup.XamlReader]::Parse($script:SourceRowXaml)
        $icon = $row.FindName('Icon'); $nameText = $row.FindName('NameText'); $sub = $row.FindName('Sub'); $rm = $row.FindName('RemoveBtn')
        $nameText.Text = $s.Name
        if ($s.IsFolder) {
            $icon.Text = $folderIcon
            $sub.Text = "Folder and everything in it$($script:Dot)$($s.Path)"
        }
        else {
            $icon.Text = $fileIcon
            $sub.Text = "$(Format-Bytes $s.Size)$($script:Dot)$($s.Path)"
        }
        $row.ToolTip = $s.Path
        Set-Res $icon ([System.Windows.Controls.TextBlock]::ForegroundProperty) 'Accent'
        $rm.Tag = $s
        $rm.IsEnabled = -not $script:Run
        $rm.Add_Click({
                param($sender, $e)
                [void]$script:Sources.Remove($sender.Tag)
                $script:UI.SourceNote.Visibility = 'Collapsed'
                Update-SourcePanel
            })
        [void]$panel.Children.Add($row)
    }
    $script:UI.SourceEmpty.Visibility = $(if ($script:Sources.Count -eq 0) { 'Visible' } else { 'Collapsed' })
    Update-Summary
}

function Show-AddFilesDialog {
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Title = 'Choose the files to copy'
    $dlg.Multiselect = $true
    $dlg.Filter = 'All files (*.*)|*.*'
    if ($dlg.ShowDialog($script:UI.Window)) { Add-Sources -Paths $dlg.FileNames }
}

function Show-AddFolderDialog {
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Choose a folder to copy. The folder itself and everything in it is copied.'
    $dlg.ShowNewFolderButton = $false
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Add-Sources -Paths @($dlg.SelectedPath) }
    $dlg.Dispose()
}

#endregion

#region Servers (step 4)

function New-ServerRow {
    param($Srv)
    $row = [System.Windows.Markup.XamlReader]::Parse($script:ServerRowXaml)
    $ui = @{ Root = $row }
    foreach ($n in 'Inc', 'NameText', 'EditBox', 'Sub', 'Pill', 'PillText', 'EditBtn', 'RemoveBtn') { $ui[$n] = $row.FindName($n) }
    foreach ($n in 'Inc', 'NameText', 'EditBox', 'EditBtn', 'RemoveBtn') { $ui[$n].Tag = $Srv }
    $Srv.Ui = $ui

    # Handlers find their server through Tag, so no closures are needed.
    $ui.Inc.Add_Click({
            param($sender, $e)
            $sender.Tag.Include = [bool]$sender.IsChecked
            Update-Summary
            Save-Settings
        })
    $ui.RemoveBtn.Add_Click({
            param($sender, $e)
            Remove-Server $sender.Tag
        })
    $ui.EditBtn.Add_Click({
            param($sender, $e)
            Start-ServerEdit $sender.Tag
        })
    $ui.NameText.Add_MouseLeftButtonDown({
            param($sender, $e)
            if ($e.ClickCount -eq 2 -and -not $script:Run) { Start-ServerEdit $sender.Tag; $e.Handled = $true }
        })
    $ui.EditBox.Add_PreviewKeyDown({
            param($sender, $e)
            if ($e.Key -eq 'Return') { Complete-ServerEdit $sender.Tag; $e.Handled = $true }
            elseif ($e.Key -eq 'Escape') { Stop-ServerEdit $sender.Tag; $e.Handled = $true }
        })
    $ui.EditBox.Add_LostKeyboardFocus({
            param($sender, $e)
            if ($sender.Visibility -eq 'Visible') { Complete-ServerEdit $sender.Tag -FocusLost }
        })
    Update-ServerRow $Srv
    return $row
}

function Update-ServerRow {
    param($Srv)
    $ui = $Srv.Ui
    if (-not $ui) { return }
    $ui.NameText.Text = $Srv.Name
    $ui.Inc.IsChecked = [bool]$Srv.Include
    $busy = [bool]$script:Run
    $ui.Inc.IsEnabled = -not $busy
    $ui.EditBtn.IsEnabled = -not $busy
    $ui.RemoveBtn.IsEnabled = -not $busy
    $ui.Root.Opacity = $(if ($Srv.Include) { 1.0 } else { 0.55 })

    $vis = Get-StatusVisual $Srv.Status
    if ($vis) {
        $ui.PillText.Text = $vis.Text
        Set-Res $ui.Pill ([System.Windows.Controls.Border]::BackgroundProperty) $vis.Bg
        Set-Res $ui.PillText ([System.Windows.Controls.TextBlock]::ForegroundProperty) $vis.Fg
        $ui.Pill.Visibility = 'Visible'
    }
    else { $ui.Pill.Visibility = 'Collapsed' }

    $subKey = 'Muted'
    if ($Srv.Message) {
        $ui.Sub.Text = $Srv.Message
        if ($Srv.Status -in 'Failed', 'Unreachable') { $subKey = 'Danger' }
        elseif ($Srv.Status -eq 'Partial') { $subKey = 'Warn' }
    }
    else {
        $dest = Get-DestState
        if ($dest.Error) { $ui.Sub.Text = '' } else { $ui.Sub.Text = Get-DestinationFolder -Server $Srv.Name -RelativePath $dest.Path }
    }
    Set-Res $ui.Sub ([System.Windows.Controls.TextBlock]::ForegroundProperty) $subKey
    if (@($Srv.Errors).Count -gt 1) { $ui.Sub.ToolTip = (@($Srv.Errors) -join "`n") }
    elseif ($Srv.Message) { $ui.Sub.ToolTip = $Srv.Message }
    else { $ui.Sub.ToolTip = $null }
}

function Update-ServerPanel {
    $panel = $script:UI.ServerPanel
    $panel.Children.Clear()
    foreach ($s in $script:Servers) {
        if (-not $s.Ui) { [void](New-ServerRow $s) } else { Update-ServerRow $s }
        [void]$panel.Children.Add($s.Ui.Root)
    }
    $script:UI.ServerEmpty.Visibility = $(if ($script:Servers.Count -eq 0) { 'Visible' } else { 'Collapsed' })
    Update-Summary
}

function Show-AddResult {
    param([string]$Text, [string]$ColorKey = 'Muted')
    $r = $script:UI.AddResult
    if (-not $Text) { $r.Visibility = 'Collapsed'; return }
    $r.Text = $Text
    Set-Res $r ([System.Windows.Controls.TextBlock]::ForegroundProperty) $ColorKey
    $r.Visibility = 'Visible'
}

function Add-ServerNames {
    # Adds parsed names and reports what happened. Returns the names that were not added because
    # they are invalid, so the box can keep them for fixing.
    param($Parsed)
    $added = 0
    $dupes = [System.Collections.Generic.List[string]]::new()
    foreach ($n in $Parsed.Valid) {
        if (Find-Server $n) { $dupes.Add($n); continue }
        $script:Servers.Add((New-ServerEntry -Name $n))
        $added++
    }
    $parts = [System.Collections.Generic.List[string]]::new()
    if ($added -gt 0) { $parts.Add("Added $(Format-Count $added 'server').") }
    if ($dupes.Count -gt 0) { $parts.Add("Already in the list: $($dupes -join ', ').") }
    if ($Parsed.Invalid.Count -gt 0) { $parts.Add("Not added - not a valid server name: $($Parsed.Invalid -join ', '). Fix them in the box and press Enter again.") }
    $color = 'Ok'
    if ($Parsed.Invalid.Count -gt 0) { $color = 'Danger' }
    elseif ($added -eq 0) { $color = 'Warn' }
    if ($parts.Count -eq 0) { Show-AddResult $null } else { Show-AddResult ($parts -join ' ') $color }
    if ($added -gt 0) {
        Update-ServerPanel
        Save-Settings
        # Show the newest servers.
        $last = $script:Servers[$script:Servers.Count - 1].Ui.Root
        $last.BringIntoView()
    }
    return $Parsed.Invalid
}

function Invoke-AddFromBox {
    $box = $script:UI.AddBox
    $parsed = ConvertTo-ServerNames -Text $box.Text
    if ($parsed.Valid.Count -eq 0 -and $parsed.Invalid.Count -eq 0) { Show-AddResult $null; return }
    $bad = Add-ServerNames $parsed
    $box.Text = ($bad -join "`r`n")
    $box.CaretIndex = $box.Text.Length
    [void]$box.Focus()
}

function Import-ServerFile {
    param([string]$Path)
    try {
        $parsed = ConvertFrom-ServerFile -Path $Path
        if ($parsed.Valid.Count -eq 0 -and $parsed.Invalid.Count -eq 0) {
            Show-AddResult "No server names found in $([System.IO.Path]::GetFileName($Path))." 'Warn'
            return
        }
        $bad = Add-ServerNames $parsed
        if ($bad.Count -gt 0) { $script:UI.AddBox.Text = ($bad -join "`r`n") }
    }
    catch { Show-AddResult "Couldn't read $Path. $(Get-FriendlyError $_)" 'Danger' }
}

function Remove-Server {
    param($Srv)
    if ($script:Run) { return }
    [void]$script:Servers.Remove($Srv)
    Update-ServerPanel
    Save-Settings
}

function Start-ServerEdit {
    param($Srv)
    if ($script:Run) { return }
    $ui = $Srv.Ui
    $ui.EditBox.Text = $Srv.Name
    $ui.NameText.Visibility = 'Collapsed'
    $ui.EditBox.Visibility = 'Visible'
    [void]$ui.EditBox.Focus()
    $ui.EditBox.SelectAll()
}

function Stop-ServerEdit {
    param($Srv)
    $ui = $Srv.Ui
    $ui.EditBox.Visibility = 'Collapsed'
    $ui.NameText.Visibility = 'Visible'
    Update-ServerRow $Srv
}

function Complete-ServerEdit {
    # Enter with a bad name keeps the box open so it can be fixed; clicking away with a bad
    # name puts the old name back and says why.
    param($Srv, [switch]$FocusLost)
    $ui = $Srv.Ui
    $new = $ui.EditBox.Text.Trim()
    if ($new -match '^\\\\([^\\]+)') { $new = $Matches[1] }
    if (-not $new -or $new -ceq $Srv.Name) { Stop-ServerEdit $Srv; return }
    $problem = $null
    if (-not (Test-ServerName $new)) { $problem = "'$new' is not a valid server name (letters, digits, - _ and dots only)." }
    elseif (Find-Server $new -Except $Srv) { $problem = "$new is already in the list." }
    if ($problem) {
        if ($FocusLost) {
            Stop-ServerEdit $Srv
            Show-AddResult "Name not changed: $problem" 'Danger'
            return
        }
        $ui.Sub.Text = "$problem Press Esc to keep $($Srv.Name)."
        Set-Res $ui.Sub ([System.Windows.Controls.TextBlock]::ForegroundProperty) 'Danger'
        return
    }
    $Srv.Name = $new
    $Srv.Status = ''
    $Srv.Message = ''
    $Srv.Errors = @()
    Stop-ServerEdit $Srv
    Save-Settings
}

function Save-ServerList {
    if ($script:Servers.Count -eq 0) { return }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Title = 'Save the server list'
    $dlg.Filter = 'Text file (*.txt)|*.txt'
    $dlg.FileName = 'servers.txt'
    if ($dlg.ShowDialog($script:UI.Window)) {
        try {
            [System.IO.File]::WriteAllLines($dlg.FileName, [string[]]@($script:Servers | ForEach-Object { $_.Name }))
            Show-AddResult "Saved $(Format-Count $script:Servers.Count 'server') to $($dlg.FileName)." 'Ok'
        }
        catch { Show-AddResult "Couldn't save the list. $(Get-FriendlyError $_)" 'Danger' }
    }
}

function Start-ConnectionCheck {
    $dest = Get-DestState
    if ($dest.Error) { Show-AddResult "Fix the folder in step 2 first: $($dest.Error)" 'Danger'; return }
    if ($script:Servers.Count -eq 0) { return }
    if (-not $script:CheckPool) { $script:CheckPool = New-WorkerPool -Max 16 }
    foreach ($s in $script:Servers) {
        if ($s.Status -eq 'Checking') { continue }
        $s.Status = 'Checking'
        $s.Message = ''
        $s.Errors = @()
        Update-ServerRow $s
        Start-BgTask -Pool $script:CheckPool -Command 'Invoke-ServerCheck' -State $s -Parameters @{
            Server = $s.Name; DestFolder = (Get-DestinationFolder -Server $s.Name -RelativePath $dest.Path)
        } -OnDone {
            param($result, $srv)
            if ($srv.Status -ne 'Checking') { return }
            if ($result -and $result.Ok) { $srv.Status = 'Ready'; $srv.Message = $result.Message }
            else {
                $srv.Status = 'Unreachable'
                $srv.Message = $(if ($result) { $result.Message } else { 'The check did not finish. See State\gui-errors.log.' })
            }
            Update-ServerRow $srv
            Update-Summary
        }
    }
    Update-Summary
}

#endregion

#region Copy run

function Get-IfExistsText {
    switch ($script:Settings.ifExists) {
        'newer' { 'Replace it only if mine is newer' }
        'skip' { 'Leave it as it is' }
        default { 'Replace it' }
    }
}

function Update-Summary {
    # Keeps the counts, the Copy button and the "ready" line in step with everything else.
    $ui = $script:UI
    if (-not $ui.CopyBtn) { return }
    $total = $script:Servers.Count
    $ticked = @($script:Servers | Where-Object { $_.Include }).Count
    $checking = @($script:Servers | Where-Object { $_.Status -eq 'Checking' }).Count
    if ($total -eq 0) { $ui.ServerCount.Text = '' }
    elseif ($ticked -eq $total) { $ui.ServerCount.Text = Format-Count $total 'server' }
    else { $ui.ServerCount.Text = "$ticked of $total ticked" }
    if ($checking -gt 0) { $ui.ServerCount.Text += "$($script:Dot)checking $checking..." }

    if ($total -eq 0 -or $ticked -eq 0) { $ui.AllCheck.IsChecked = $false }
    elseif ($ticked -eq $total) { $ui.AllCheck.IsChecked = $true }
    else { $ui.AllCheck.IsChecked = $null }

    $busy = [bool]$script:Run
    foreach ($n in 'LeftForm', 'AddBox', 'AddServersBtn', 'ImportBtn', 'ClearServersBtn', 'AllCheck', 'CheckBtn') { $ui[$n].IsEnabled = -not $busy }
    $ui.CheckBtn.IsEnabled = (-not $busy) -and $total -gt 0 -and $checking -eq 0
    $ui.SaveListBtn.IsEnabled = $total -gt 0
    $ui.ClearServersBtn.IsEnabled = (-not $busy) -and $total -gt 0
    $ui.ClearSourcesBtn.IsEnabled = $script:Sources.Count -gt 0
    $ui.StopBtn.Visibility = $(if ($busy) { 'Visible' } else { 'Collapsed' })
    $ui.RunBar.Visibility = $(if ($busy) { 'Visible' } else { 'Collapsed' })

    if ($busy) { $ui.CopyBtn.IsEnabled = $false; return }

    $ui.CopyBtnText.Text = '  Copy to ' + (Format-Count $ticked 'server')
    $dest = Get-DestState
    $reason = $null
    if ($script:Sources.Count -eq 0) { $reason = 'Add the files or folders to copy (step 1).' }
    elseif ($dest.Error) { $reason = 'Fix the folder in step 2.' }
    elseif ($total -eq 0) { $reason = 'Add the servers to copy to (step 4, on the right).' }
    elseif ($ticked -eq 0) { $reason = 'Tick at least one server on the right.' }
    $ui.CopyBtn.IsEnabled = -not $reason
    Set-Res $ui.ReadyText ([System.Windows.Controls.TextBlock]::ForegroundProperty) 'Muted'
    if ($reason) { $ui.ReadyText.Text = $reason }
    else {
        $files = @($script:Sources | Where-Object { -not $_.IsFolder }).Count
        $folders = $script:Sources.Count - $files
        $what = @()
        if ($files) { $what += Format-Count $files 'file' }
        if ($folders) { $what += Format-Count $folders 'folder' }
        $ui.ReadyText.Text = "Ready: $($what -join ' and ') into $($dest.Path) on $(Format-Count $ticked 'server')."
    }
}

function Update-DestView {
    $ui = $script:UI
    $dest = Get-DestState
    $sample = 'SERVER01'
    $first = $script:Servers | Where-Object { $_.Include } | Select-Object -First 1
    if ($first) { $sample = $first.Name }
    if ($dest.Error) {
        $ui.DestExampleLabel.Text = 'PROBLEM'
        $ui.DestExample.Text = $dest.Error
        Set-Res $ui.DestExample ([System.Windows.Controls.TextBlock]::ForegroundProperty) 'Danger'
        $ui.DestNote.Visibility = 'Collapsed'
    }
    else {
        $ui.DestExampleLabel.Text = 'FILES GO TO, FOR EXAMPLE'
        $ui.DestExample.Text = Get-DestinationFolder -Server $sample -RelativePath $dest.Path
        Set-Res $ui.DestExample ([System.Windows.Controls.TextBlock]::ForegroundProperty) 'Accent'
        if ($dest.Note) { $ui.DestNote.Text = $dest.Note; $ui.DestNote.Visibility = 'Visible' } else { $ui.DestNote.Visibility = 'Collapsed' }
    }
    foreach ($s in $script:Servers) { if (-not $s.Message) { Update-ServerRow $s } }
    Update-Summary
}

function Write-RunLog {
    param([string]$Level, [string]$Text)
    if (-not $script:Run) { return }
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Text
    try { Add-Content -LiteralPath $script:Run.LogPath -Value $line -Encoding UTF8 }
    catch { Write-GuiError "Run log: $($_.Exception.Message)" }
}

function Start-CopyRun {
    # Targets: the ticked servers, or (for Retry) the servers that did not finish.
    param([object[]]$Targets, [switch]$IsRetry)
    if ($script:Run) { return }
    $dest = Get-DestState
    if ($dest.Error -or $script:Sources.Count -eq 0 -or @($Targets).Count -eq 0) { Update-Summary; return }

    $missing = @($script:Sources | Where-Object { -not (Test-Path -LiteralPath $_.Path) })
    if ($missing.Count -gt 0) {
        [System.Windows.MessageBox]::Show($script:UI.Window, "These items aren't there any more:`n`n$(($missing | ForEach-Object { $_.Path }) -join "`n")`n`nRemove them from step 1 and try again.", 'Copy Files to Servers', 'OK', 'Warning') | Out-Null
        return
    }

    $what = ($script:Sources | ForEach-Object { '  ' + $_.Name + $(if ($_.IsFolder) { '\  (folder)' } else { '' }) }) -join "`n"
    $verb = $(if ($IsRetry) { 'Retry the copy to' } else { 'Copy to' })
    $msg = "$verb $(Format-Count @($Targets).Count 'server')?`n`nCopying:`n$what`n`nInto: $($dest.Path) on each server`nIf a file is already there: $(Get-IfExistsText)"
    $answer = [System.Windows.MessageBox]::Show($script:UI.Window, $msg, 'Copy Files to Servers', 'OKCancel', 'Question')
    if ($answer -ne 'OK') { return }

    try { if (-not (Test-Path -LiteralPath $script:LogDir)) { New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null } } catch { }
    $logPath = Join-Path $script:LogDir ('CopyToServers_{0}.log' -f (Get-Date -Format 'yyyy-MM-dd_HHmmss'))
    $shared = [hashtable]::Synchronized(@{ Cancel = $false; Progress = [hashtable]::Synchronized(@{}) })
    $script:Run = @{
        Pool = New-WorkerPool -Max ([int]$script:Settings.parallel)
        Shared = $shared; Targets = @($Targets); Pending = @($Targets).Count; LogPath = $logPath
        Started = Get-Date; Dest = $dest.Path; Sources = [string[]]@($script:Sources | ForEach-Object { $_.Path })
    }
    $script:LastLogPath = $logPath
    $script:UI.ResultBar.Visibility = 'Collapsed'
    $script:UI.StopText.Text = '  Stop'
    $script:UI.StopBtn.IsEnabled = $true

    Write-RunLog 'INFO' "Copy Files to Servers v$ScriptVersion - run by $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME"
    foreach ($src in $script:Run.Sources) { Write-RunLog 'INFO' "Source: $src" }
    Write-RunLog 'INFO' "Destination: $($dest.Path) | If a file is already there: $(Get-IfExistsText) | Servers at once: $($script:Settings.parallel)"
    Write-RunLog 'INFO' "Servers ($(@($Targets).Count)): $((@($Targets) | ForEach-Object { $_.Name }) -join ', ')"

    foreach ($t in $Targets) {
        $t.Status = 'Waiting'
        $t.Message = ''
        $t.Errors = @()
        $t.Result = $null
        Start-BgTask -Pool $script:Run.Pool -Command 'Invoke-ServerCopy' -State $t -Parameters @{
            Server = $t.Name; Key = $t.Name; DestFolder = (Get-DestinationFolder -Server $t.Name -RelativePath $dest.Path)
            Sources = $script:Run.Sources; IfExists = $script:Settings.ifExists; Shared = $shared
        } -OnDone { param($result, $srv) Complete-ServerCopy $srv $result }
    }
    Update-SourcePanel
    Update-ServerPanel
    Update-RunProgress
}

function Complete-ServerCopy {
    param($Srv, $Result)
    if ($Result -and $Result.Outcome) {
        $Srv.Status = $Result.Outcome
        $Srv.Message = $Result.Message
        $Srv.Errors = @($Result.Errors)
        $Srv.Result = $Result
    }
    else {
        $Srv.Status = 'Failed'
        $Srv.Message = 'The copy ended without a result. Details are in State\gui-errors.log.'
    }
    $level = switch ($Srv.Status) { 'Done' { 'PASS' } 'Partial' { 'WARN' } 'Stopped' { 'WARN' } 'Cancelled' { 'INFO' } default { 'FAIL' } }
    $destText = Get-DestinationFolder -Server $Srv.Name -RelativePath $script:Run.Dest
    Write-RunLog $level "$($Srv.Name) $destText - $($Srv.Message)"
    foreach ($er in @($Srv.Errors | Select-Object -Skip 1)) { Write-RunLog $level "    $er" }
    Update-ServerRow $Srv
    $script:Run.Pending--
    if ($script:Run.Pending -le 0) { Complete-CopyRun }
}

function Update-RunProgress {
    $run = $script:Run
    if (-not $run) { return }
    $prog = $run.Shared.Progress
    foreach ($srv in $run.Targets) {
        if ($srv.Status -notin 'Waiting', 'Copying') { continue }
        $p = $prog[$srv.Name]
        if ($p -and ($srv.Status -ne 'Copying' -or $srv.Message -ne $p)) {
            $srv.Status = 'Copying'
            $srv.Message = $p
            Update-ServerRow $srv
        }
    }
    $total = $run.Targets.Count
    $done = $total - $run.Pending
    $copying = @($run.Targets | Where-Object { $_.Status -eq 'Copying' }).Count
    $ui = $script:UI
    $fraction = 0
    if ($total -gt 0) { $fraction = $done / $total }
    $ui.RunFill.Width = [System.Windows.GridLength]::new($fraction, 'Star')
    $ui.RunRest.Width = [System.Windows.GridLength]::new(1 - $fraction, 'Star')
    $elapsed = Format-Duration ((Get-Date) - $run.Started).TotalSeconds
    Set-Res $ui.ReadyText ([System.Windows.Controls.TextBlock]::ForegroundProperty) 'Text'
    if ($run.Shared.Cancel) { $ui.ReadyText.Text = "Stopping - waiting for $copying server(s) to finish the current file... ($elapsed)" }
    else { $ui.ReadyText.Text = "$done of $(Format-Count $total 'server') finished$($script:Dot)$copying copying now$($script:Dot)$elapsed" }
}

function Complete-CopyRun {
    $run = $script:Run
    $elapsed = Format-Duration ((Get-Date) - $run.Started).TotalSeconds
    $counts = @{}
    foreach ($t in $run.Targets) { $counts[$t.Status] = 1 + [int]$counts[$t.Status] }
    $done = [int]$counts['Done']; $partial = [int]$counts['Partial']; $failed = [int]$counts['Failed']
    $stopped = [int]$counts['Stopped'] + [int]$counts['Cancelled']
    $bytes = [long]0
    foreach ($t in $run.Targets) { if ($t.Result) { $bytes += $t.Result.Bytes } }

    $parts = @()
    if ($done) { $parts += "$done done" }
    if ($partial) { $parts += "$partial with some files failed" }
    if ($failed) { $parts += "$failed failed" }
    if ($stopped) { $parts += "$stopped stopped" }
    Write-RunLog 'INFO' "Finished in $elapsed. $($parts -join ', '). $(Format-Bytes $bytes) copied in total."

    try { $run.Pool.Close(); $run.Pool.Dispose() } catch { }
    $script:Run = $null

    $ui = $script:UI
    $retryCount = $partial + $failed + $stopped
    if ($retryCount -eq 0) {
        $ui.ResultHeadline.Text = "$([char]0x2713) Copied to all $(Format-Count $done 'server') in $elapsed."
        Set-Res $ui.ResultHeadline ([System.Windows.Controls.TextBlock]::ForegroundProperty) 'Ok'
        $ui.RetryBtn.Visibility = 'Collapsed'
    }
    else {
        $ui.ResultHeadline.Text = "Finished in $elapsed$($script:Dot)$($parts -join $script:Dot)"
        Set-Res $ui.ResultHeadline ([System.Windows.Controls.TextBlock]::ForegroundProperty) $(if ($done -eq 0) { 'Danger' } else { 'Warn' })
        $ui.RetryText.Text = "  Retry $retryCount"
        $ui.RetryBtn.Visibility = 'Visible'
    }
    $ui.ResultDetail.Text = "$(Format-Bytes $bytes) copied in total. Hover over a server's message to see every problem. Log: Logs\$([System.IO.Path]::GetFileName($run.LogPath))"
    $ui.ResultBar.Visibility = 'Visible'
    Update-SourcePanel
    Update-ServerPanel
    Save-Settings
}

function Stop-CopyRun {
    if (-not $script:Run) { return }
    $script:Run.Shared.Cancel = $true
    $script:UI.StopText.Text = '  Stopping...'
    $script:UI.StopBtn.IsEnabled = $false
    Write-RunLog 'WARN' 'Stop requested. Servers not started yet are skipped.'
}

function Export-RunResults {
    $rows = @($script:Servers | Where-Object { $_.Status } | ForEach-Object {
            $r = $_.Result
            [PSCustomObject]@{
                Server       = $_.Name
                Destination  = $(if ($r) { $r.Destination } else { '' })
                Result       = $_.Status
                FilesCopied  = $(if ($r) { $r.Copied } else { 0 })
                FilesSkipped = $(if ($r) { $r.Skipped } else { 0 })
                FilesFailed  = $(if ($r) { $r.Failed } else { 0 })
                Bytes        = $(if ($r) { $r.Bytes } else { 0 })
                Seconds      = $(if ($r) { $r.Seconds } else { 0 })
                Message      = $_.Message
                Problems     = (@($_.Errors) -join ' | ')
            }
        })
    if ($rows.Count -eq 0) { return }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Title = 'Export results'
    $dlg.Filter = 'CSV file (*.csv)|*.csv'
    $dlg.FileName = 'CopyToServers_{0}.csv' -f (Get-Date -Format 'yyyy-MM-dd_HHmmss')
    if ($dlg.ShowDialog($script:UI.Window)) {
        try { $rows | Export-Csv -LiteralPath $dlg.FileName -NoTypeInformation -Encoding UTF8 }
        catch { [System.Windows.MessageBox]::Show($script:UI.Window, "Couldn't save the file. $(Get-FriendlyError $_)", 'Export results', 'OK', 'Warning') | Out-Null }
    }
}

#endregion

#region Main window

function Hide-OwnConsole {
    # Double-clicking the script opens a console just for it; hide that so only the window
    # shows. A console shared with other processes (someone's open terminal) is left alone.
    try {
        if (-not ('CopyToServers.ConsoleWin' -as [type])) {
            Add-Type -Namespace CopyToServers -Name ConsoleWin -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("kernel32.dll")] public static extern uint GetConsoleProcessList(uint[] list, uint count);
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
'@
        }
        $list = New-Object uint32[] 8
        $count = [CopyToServers.ConsoleWin]::GetConsoleProcessList($list, 8)
        $hwnd = [CopyToServers.ConsoleWin]::GetConsoleWindow()
        if ($count -le 1 -and $hwnd -ne [IntPtr]::Zero) { [void][CopyToServers.ConsoleWin]::ShowWindow($hwnd, 0) }
    }
    catch { }
}

function Get-DroppedPaths {
    param($DragEventArgs)
    if ($DragEventArgs.Data.GetDataPresent([System.Windows.DataFormats]::FileDrop)) {
        return [string[]]$DragEventArgs.Data.GetData([System.Windows.DataFormats]::FileDrop)
    }
    return @()
}

function New-CopyWindow {
    # Builds the window and wires its events. Split from Start-CopyWindow so a test harness can
    # build the window without showing it.
    $win = New-ThemedWindow $script:MainXaml
    $ui = $script:UI
    $ui.Window = $win
    $names = 'VersionText', 'ThemeBtn', 'LeftForm', 'DropZone', 'DropRect', 'SourcePanel', 'SourceEmpty',
    'AddFilesBtn', 'AddFolderBtn', 'ClearSourcesBtn', 'SourceNote', 'DestBox', 'DestExampleLabel', 'DestExample', 'DestNote',
    'IfReplace', 'IfNewer', 'IfSkip', 'IfHint', 'Par1', 'Par4', 'Par8', 'Par16',
    'ReadyText', 'RunBar', 'RunFill', 'RunRest', 'StopBtn', 'StopText', 'CopyBtn', 'CopyBtnText',
    'ServerArea', 'AddServersBtn', 'ImportBtn', 'AddBox', 'AddResult', 'CheckBtn', 'SaveListBtn', 'ClearServersBtn',
    'AllCheck', 'ServerCount', 'ServerPanel', 'ServerEmpty',
    'ResultBar', 'RetryBtn', 'RetryText', 'OpenLogBtn', 'ExportBtn', 'ResultHeadline', 'ResultDetail'
    foreach ($n in $names) {
        $ui[$n] = $win.FindName($n)
        if ($null -eq $ui[$n]) { throw "XAML element '$n' not found." }
    }

    # Fit smaller screens.
    $wa = [System.Windows.SystemParameters]::WorkArea
    if ($win.Height -gt $wa.Height - 20) { $win.Height = [Math]::Max($win.MinHeight, $wa.Height - 20) }
    if ($win.Width -gt $wa.Width - 20) { $win.Width = [Math]::Max($win.MinWidth, $wa.Width - 20) }

    $ui.VersionText.Text = "v$ScriptVersion"
    $script:ThemeLabel = {
        if ($script:Settings.theme -eq 'dark') { $script:UI.ThemeBtn.Content = "$([char]0x2600)  Light" }
        else { $script:UI.ThemeBtn.Content = "$([char]0x263E)  Dark" }
    }
    & $script:ThemeLabel

    $ui.DestBox.Text = $script:Settings.destPath
    switch ($script:Settings.ifExists) { 'newer' { $ui.IfNewer.IsChecked = $true } 'skip' { $ui.IfSkip.IsChecked = $true } default { $ui.IfReplace.IsChecked = $true } }
    switch ([int]$script:Settings.parallel) { 1 { $ui.Par1.IsChecked = $true } 4 { $ui.Par4.IsChecked = $true } 16 { $ui.Par16.IsChecked = $true } default { $ui.Par8.IsChecked = $true } }

    # --- Title bar ---
    $ui.ThemeBtn.Add_Click({
            if ($script:Settings.theme -eq 'dark') { $script:Settings.theme = 'light' } else { $script:Settings.theme = 'dark' }
            Set-WpfTheme -Resources $script:UI.Window.Resources -Theme $script:Settings.theme
            & $script:ThemeLabel
            Save-Settings
        })

    # --- Step 1 ---
    $ui.AddFilesBtn.Add_Click({ Show-AddFilesDialog })
    $ui.AddFolderBtn.Add_Click({ Show-AddFolderDialog })
    $ui.ClearSourcesBtn.Add_Click({ $script:Sources.Clear(); $script:UI.SourceNote.Visibility = 'Collapsed'; Update-SourcePanel })
    $ui.DropZone.Add_DragEnter({
            param($sender, $e)
            if (-not $script:Run) { Set-Res $script:UI.DropRect ([System.Windows.Shapes.Shape]::StrokeProperty) 'Accent' }
        })
    $ui.DropZone.Add_DragLeave({ Set-Res $script:UI.DropRect ([System.Windows.Shapes.Shape]::StrokeProperty) 'BorderStrong' })
    $ui.DropZone.Add_Drop({
            param($sender, $e)
            Set-Res $script:UI.DropRect ([System.Windows.Shapes.Shape]::StrokeProperty) 'BorderStrong'
            if (-not $script:Run) { Add-Sources -Paths (Get-DroppedPaths $e) }
            $e.Handled = $true
        })

    # --- Step 2 ---
    $ui.DestBox.Add_TextChanged({
            $script:Settings.destPath = $script:UI.DestBox.Text
            foreach ($s in $script:Servers) { if ($s.Status -in 'Ready', 'Unreachable') { $s.Status = ''; $s.Message = '' } }
            Update-DestView
        })
    $ui.DestBox.Add_LostKeyboardFocus({ Save-Settings })

    # --- Step 3 ---
    $setIf = {
        param([string]$Mode)
        $script:Settings.ifExists = $Mode
        $hint = switch ($Mode) {
            'newer' { 'Copies a file only when the server has no copy, or an older one (by last-modified time).' }
            'skip' { 'Files that are already on the server are left alone, even if they are different.' }
            default { 'Files on the server with the same name are overwritten, even if they are newer.' }
        }
        $script:UI.IfHint.Text = $hint
        Save-Settings
    }
    $script:SetIfExists = $setIf
    $ui.IfReplace.Add_Checked({ & $script:SetIfExists 'replace' })
    $ui.IfNewer.Add_Checked({ & $script:SetIfExists 'newer' })
    $ui.IfSkip.Add_Checked({ & $script:SetIfExists 'skip' })
    & $setIf $script:Settings.ifExists
    $ui.Par1.Add_Checked({ $script:Settings.parallel = 1; Save-Settings })
    $ui.Par4.Add_Checked({ $script:Settings.parallel = 4; Save-Settings })
    $ui.Par8.Add_Checked({ $script:Settings.parallel = 8; Save-Settings })
    $ui.Par16.Add_Checked({ $script:Settings.parallel = 16; Save-Settings })

    # --- Copy / stop ---
    $ui.CopyBtn.Add_Click({ Start-CopyRun -Targets @($script:Servers | Where-Object { $_.Include }) })
    $ui.StopBtn.Add_Click({ Stop-CopyRun })
    $ui.RetryBtn.Add_Click({
            $retry = @($script:Servers | Where-Object { $_.Status -in 'Failed', 'Partial', 'Stopped', 'Cancelled' })
            Start-CopyRun -Targets $retry -IsRetry
        })
    $ui.OpenLogBtn.Add_Click({
            if ($script:LastLogPath -and (Test-Path -LiteralPath $script:LastLogPath)) {
                Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$($script:LastLogPath)`""
            }
        })
    $ui.ExportBtn.Add_Click({ Export-RunResults })

    # --- Servers ---
    $ui.AddServersBtn.Add_Click({ Invoke-AddFromBox })
    $ui.AddBox.Add_PreviewKeyDown({
            param($sender, $e)
            if ($e.Key -eq 'Return' -and -not ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Shift)) {
                Invoke-AddFromBox
                $e.Handled = $true
            }
        })
    $ui.ImportBtn.Add_Click({
            $dlg = New-Object Microsoft.Win32.OpenFileDialog
            $dlg.Title = 'Import servers'
            $dlg.Filter = 'Server lists (*.txt;*.csv)|*.txt;*.csv|All files (*.*)|*.*'
            if ($dlg.ShowDialog($script:UI.Window)) { Import-ServerFile -Path $dlg.FileName }
        })
    $ui.ServerArea.Add_Drop({
            param($sender, $e)
            if ($script:Run) { return }
            foreach ($p in (Get-DroppedPaths $e)) { if ([System.IO.File]::Exists($p)) { Import-ServerFile -Path $p } }
            $e.Handled = $true
        })
    $ui.CheckBtn.Add_Click({ Start-ConnectionCheck })
    $ui.SaveListBtn.Add_Click({ Save-ServerList })
    $ui.ClearServersBtn.Add_Click({
            $n = $script:Servers.Count
            $answer = [System.Windows.MessageBox]::Show($script:UI.Window, "Remove all $n servers from the list?", 'Clear list', 'OKCancel', 'Question')
            if ($answer -ne 'OK') { return }
            $script:Servers.Clear()
            $script:UI.ResultBar.Visibility = 'Collapsed'
            Show-AddResult $null
            Update-ServerPanel
            Update-DestView
            Save-Settings
        })
    $ui.AllCheck.Add_Click({
            # A click on a full tick unticks everything; otherwise everything is ticked.
            $all = @($script:Servers | Where-Object { -not $_.Include }).Count -eq 0
            foreach ($s in $script:Servers) { $s.Include = -not $all; Update-ServerRow $s }
            Update-DestView
            Save-Settings
        })

    $win.Add_PreviewKeyDown({
            param($sender, $e)
            if ($e.Key -eq 'O' -and [System.Windows.Input.Keyboard]::Modifiers -eq 'Control') { Show-AddFilesDialog; $e.Handled = $true }
        })
    $win.Add_Closing({
            param($sender, $e)
            if ($script:Run) {
                $msg = "A copy is still running.`n`nClosing now stops it, and a file that is part-way through copying may be left incomplete on its server.`n`nClose anyway?"
                $answer = [System.Windows.MessageBox]::Show($script:UI.Window, $msg, 'Copy still running', 'YesNo', 'Warning')
                if ($answer -ne 'Yes') { $e.Cancel = $true; return }
                $script:Run.Shared.Cancel = $true
                Write-RunLog 'WARN' 'Window closed while copying. Unfinished servers were not completed.'
            }
            if (-not $script:UI.DestBox.Text) { $script:Settings.destPath = '' }
            Save-Settings
        })

    Update-SourcePanel
    Update-ServerPanel
    Update-DestView
    return $win
}

function Start-CopyWindow {
    Read-Settings
    $win = New-CopyWindow

    $timer = [System.Windows.Threading.DispatcherTimer]::new()
    $timer.Interval = [TimeSpan]::FromMilliseconds(250)
    $timer.Add_Tick({
            try { Update-BgTasks } catch { Write-GuiError "Tick/bg: $($_.Exception.Message)" }
            try { Update-RunProgress } catch { Write-GuiError "Tick/run: $($_.Exception.Message)" }
        })
    $timer.Start()

    $win.Add_ContentRendered({ Hide-OwnConsole; [void]$script:UI.AddBox.Focus() })
    [void]$win.ShowDialog()
    $timer.Stop()
}

#endregion

if ($LoadFunctionsOnly) { return }

#region Startup

# WPF needs a single-threaded apartment. Windows PowerShell is STA by default; relaunch in it
# if this host isn't.
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    Start-Process -FilePath $ps -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$PSCommandPath`"")
    return
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

try {
    Start-CopyWindow
}
catch {
    Write-GuiError "Fatal: $($_.Exception.Message)`n$($_.ScriptStackTrace)"
    [System.Windows.MessageBox]::Show("Copy Files to Servers hit an error and has to close:`n`n$($_.Exception.Message)`n`nDetails were written to $($script:ErrorLogPath).", 'Copy Files to Servers', 'OK', 'Error') | Out-Null
}
finally {
    # BeginClose, not Close: a worker stuck on an offline server must not hold the window open.
    try { if ($script:CheckPool) { [void]$script:CheckPool.BeginClose($null, $null) } } catch { }
    try { if ($script:Run) { [void]$script:Run.Pool.BeginClose($null, $null) } } catch { }
}

#endregion
