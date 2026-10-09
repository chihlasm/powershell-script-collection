#Requires -Version 5.1

<#
.SYNOPSIS
    Robocopy Migration -- native Windows GUI for server-to-server file migrations.

.DESCRIPTION
    Opens a desktop window (WPF) for planning and running robocopy migrations:
      - Four presets: Full Migration, Incremental, Data Only, Mirror
      - Preview (file, folder and size totals) before copying
      - A job queue that runs one at a time or all at once
      - Live progress with % done and time left, the last 500 log lines, and a plain-English
        summary when each job finishes

    Each copy runs as its own hidden background process that writes a robocopy log. Closing the
    window does not stop copies that are already running: reopen the tool and it picks them up
    again. Jobs that are still waiting stay queued until the tool is reopened.

    Files written next to this script:
      Logs\    robocopy logs (default location; can be changed per job)
      State\   jobs.json, per-job exit-code files, gui-errors.log

.PARAMETER LoadFunctionsOnly
    Define the script's functions and return without opening the window. Used by the Pester
    tests.

.EXAMPLE
    .\RobocopyMigration-GUI.ps1
    Opens the migration window.

.NOTES
    Version : 2.0.0
    Requires: Windows PowerShell 5.1 (or PowerShell 7 on Windows), Run as administrator
              (needed to copy NTFS permissions and owners, and for backup mode).

    REFERENCES
    - robocopy: options, /MT cannot be combined with /IPG, /UNILOG, exit codes (0-7 are
      combinations of 1 = copied, 2 = extra files, 4 = mismatched; >= 8 = at least one failure),
      and "modified" files are not copied by default.
      https://learn.microsoft.com/windows-server/administration/windows-commands/robocopy
    - Return codes used by the Robocopy utility (KB 954404).
      https://learn.microsoft.com/troubleshoot/windows-server/backup-and-storage/return-codes-used-robocopy-utility
    - Observed on Windows 11 (2026-10-09), not documented on Learn: a missing source directory
      returns exit code 16 and writes no summary table; /UNILOG writes UTF-16LE with a BOM;
      with /V each file line is written before the copy attempt and repeated on every retry,
      and "ERROR: RETRY LIMIT EXCEEDED." marks the final failure.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$LoadFunctionsOnly
)

$ScriptVersion = '2.0.0'
$ErrorActionPreference = 'Continue'

# This file is deliberately pure ASCII. Windows PowerShell 5.1 reads a BOM-less file as ANSI,
# so any non-ASCII character can silently corrupt a string. Icons in the XAML are written as
# &#x....; entities and display text uses [char] codes.

$script:ScriptRoot = $PSScriptRoot
if (-not $script:ScriptRoot) { $script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
$script:DefaultLogDir = Join-Path $script:ScriptRoot 'Logs'
$script:StateDir = Join-Path $script:ScriptRoot 'State'
$script:JobStorePath = Join-Path $script:StateDir 'jobs.json'
$script:ErrorLogPath = Join-Path $script:StateDir 'gui-errors.log'
$script:Arrow = [string][char]0x2192

#region Log reader (C#)

# Reading robocopy's /V log line by line in PowerShell is what made the web version fall behind
# on million-file copies. This class reads only the bytes added since the last poll and keeps
# counters, a fixed-size tail and the failed files, so memory stays flat.
if (-not ('RoboMigration.RoboLogTailer' -as [type])) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace RoboMigration
{
    public sealed class RoboLogTailer
    {
        // "2026/10/09 15:55:10 ERROR 32 (0x00000020) Copying File C:\src\locked.txt"
        private static readonly Regex ErrorRx = new Regex(@"\bERROR (\d+) \(0x[0-9A-Fa-f]+\) (.+)$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);
        // "   Files :         6         2         2         0         1         1"
        // Matched by position (Dirs, Files, Bytes) because the row labels are localized.
        private static readonly Regex SummaryRx = new Regex(@"^\s*[^:\d\t]+:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private readonly string _path;
        private readonly HashSet<string> _skip;
        private Decoder _decoder;
        private readonly StringBuilder _partial = new StringBuilder();
        private readonly Queue<string> _tail = new Queue<string>();
        private readonly List<string> _failed = new List<string>();
        private long _offset;
        private string _pendingPath;
        private long _pendingSize;
        private string _lastError;
        private bool _expectErrorText;
        private int _summaryRow;

        public int MaxTailLines = 500;
        public int MaxFailed = 1000;
        public long FilesCopied, BytesCopied, FilesSkipped, BytesSkipped, FilesFailed, BytesFailed, ExtraFiles, ErrorCount;
        public string CurrentFile = "";
        public string LastError = "";
        public long[] SummaryDirs, SummaryFiles, SummaryBytes;
        public long Version;
        public bool CaughtUp;

        public RoboLogTailer(string path, string[] skipClasses)
        {
            _path = path;
            _skip = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (skipClasses != null) { foreach (string s in skipClasses) { _skip.Add(s); } }
            _decoder = new UnicodeEncoding(false, false).GetDecoder();
        }

        public long Offset { get { return _offset; } }
        public bool HasSummary { get { return SummaryBytes != null; } }
        public long BytesProcessed { get { return BytesCopied + BytesSkipped + BytesFailed; } }

        public string GetTail() { return string.Join("\r\n", _tail.ToArray()); }
        public string[] GetFailedFiles() { return _failed.ToArray(); }

        // Reads at most maxBytes of new log data. Returns the number of complete lines read.
        public int Poll(int maxBytes)
        {
            if (string.IsNullOrEmpty(_path) || !File.Exists(_path)) { return 0; }
            using (FileStream fs = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                long len = fs.Length;
                if (len < _offset) { Reset(); }
                if (len == _offset) { CaughtUp = true; return 0; }
                fs.Position = _offset;
                long toRead = Math.Min(len - _offset, (long)maxBytes);
                byte[] buf = new byte[65536];
                long done = 0;
                int lines = 0;
                while (done < toRead)
                {
                    int n = fs.Read(buf, 0, (int)Math.Min((long)buf.Length, toRead - done));
                    if (n <= 0) { break; }
                    lines += Feed(buf, n);
                    done += n;
                }
                CaughtUp = _offset >= len;
                return lines;
            }
        }

        // Decodes UTF-16LE bytes. The decoder is stateful, so a character split across two
        // reads is reassembled correctly.
        public int Feed(byte[] data, int count)
        {
            char[] chars = new char[count / 2 + 2];
            int c = _decoder.GetChars(data, 0, count, chars, 0);
            _offset += count;
            int lines = 0;
            for (int i = 0; i < c; i++)
            {
                char ch = chars[i];
                if (ch == '\n')
                {
                    string line = _partial.ToString();
                    _partial.Length = 0;
                    if (line.Length > 0 && line[line.Length - 1] == '\r') { line = line.Substring(0, line.Length - 1); }
                    ProcessLine(line);
                    lines++;
                }
                else
                {
                    _partial.Append(ch);
                }
            }
            if (lines > 0) { Version++; }
            return lines;
        }

        private void Reset()
        {
            _offset = 0;
            _decoder = new UnicodeEncoding(false, false).GetDecoder();
            _partial.Length = 0;
            _tail.Clear();
            _failed.Clear();
            _pendingPath = null;
            _lastError = null;
            _expectErrorText = false;
            _summaryRow = 0;
            FilesCopied = BytesCopied = FilesSkipped = BytesSkipped = FilesFailed = BytesFailed = ExtraFiles = ErrorCount = 0;
            SummaryDirs = SummaryFiles = SummaryBytes = null;
            CurrentFile = "";
            LastError = "";
        }

        private void AddTail(string line)
        {
            _tail.Enqueue(line);
            while (_tail.Count > MaxTailLines) { _tail.Dequeue(); }
        }

        private void ProcessLine(string raw)
        {
            string line = raw.TrimStart('\uFEFF');
            AddTail(line);
            if (line.Trim().Length == 0) { return; }

            // The line after an ERROR line is the Windows error text.
            if (_expectErrorText)
            {
                _expectErrorText = false;
                if (_lastError != null) { _lastError = _lastError + " - " + line.Trim(); LastError = _lastError; }
                return;
            }

            if (line[0] == '\t') { HandleFileLine(line); return; }

            Match m = ErrorRx.Match(line);
            if (m.Success)
            {
                ErrorCount++;
                _lastError = "ERROR " + m.Groups[1].Value + ": " + m.Groups[2].Value.Trim();
                LastError = _lastError;
                _expectErrorText = true;
                return;
            }

            // The file line is logged before the copy attempt, so a final failure takes the
            // pending file back off the copied counters.
            if (line.StartsWith("ERROR: RETRY LIMIT EXCEEDED", StringComparison.OrdinalIgnoreCase))
            {
                if (_pendingPath != null)
                {
                    FilesCopied--;
                    BytesCopied -= _pendingSize;
                    FilesFailed++;
                    BytesFailed += _pendingSize;
                    if (_failed.Count < MaxFailed) { _failed.Add(_lastError != null ? _lastError : ("Failed: " + _pendingPath)); }
                    _pendingPath = null;
                }
                return;
            }

            if (_summaryRow < 3)
            {
                Match s = SummaryRx.Match(line);
                if (s.Success)
                {
                    long[] v = new long[6];
                    for (int k = 0; k < 6; k++) { v[k] = long.Parse(s.Groups[k + 1].Value, CultureInfo.InvariantCulture); }
                    if (_summaryRow == 0) { SummaryDirs = v; } else if (_summaryRow == 1) { SummaryFiles = v; } else { SummaryBytes = v; }
                    _summaryRow++;
                }
            }
        }

        // "\t    New File  \t\t     202\tC:\src\f2.txt"  ->  class, size, path
        private void HandleFileLine(string line)
        {
            string[] parts = line.Split(new char[] { '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 3) { return; }
            string cls = parts[0].Trim();
            if (cls.Length == 0) { return; }
            long size;
            if (!long.TryParse(parts[1].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out size)) { return; }
            string path = parts[2];
            for (int i = 3; i < parts.Length; i++) { path = path + "\t" + parts[i]; }

            if (cls.StartsWith("*EXTRA", StringComparison.OrdinalIgnoreCase))
            {
                if (cls.IndexOf("File", StringComparison.OrdinalIgnoreCase) >= 0) { ExtraFiles++; }
                return;
            }
            if (_skip.Contains(cls))
            {
                FilesSkipped++;
                BytesSkipped += size;
                return;
            }
            // A retry logs the same file again; count it once.
            if (_pendingPath != null && string.Equals(_pendingPath, path, StringComparison.Ordinal)) { return; }
            FilesCopied++;
            BytesCopied += size;
            _pendingPath = path;
            _pendingSize = size;
            CurrentFile = path;
        }
    }
}
'@
}

#endregion

#region Pure helpers

function Write-GuiError {
    # The timer runs twice a second, so each kind of error is written once a minute at most.
    # Digits are ignored when comparing, so the same error with a changing number counts once.
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

function ConvertTo-RoboPath {
    # A trailing backslash before the closing quote ("D:\Data\") is read by the C runtime as an
    # escaped quote, which mangles the arguments. A bare drive (D:) means "current directory on
    # D:", so drive roots become D:\.
    param([string]$Path)
    if (-not $Path) { return $Path }
    $p = $Path.Trim()
    if ($p -match '^[A-Za-z]:\\?$') { return ($p.Substring(0, 2) + '\.') }
    return $p.TrimEnd('\')
}

function Resolve-MappedDrive {
    # Elevated processes don't see the user's mapped drives, so drive letters are converted to
    # the UNC path they point at.
    param([string]$Path, [hashtable]$Map)
    if ($Path -and $Map -and $Path -match '^([A-Za-z]):(\\.*)?$') {
        $unc = $Map[$Matches[1].ToUpper()]
        if ($unc) {
            $rest = $Matches[2]
            if (-not $rest) { $rest = '' }
            return ($unc.TrimEnd('\') + $rest)
        }
    }
    return $Path
}

function Get-MappedDriveTable {
    $map = @{}
    try {
        Get-CimInstance -ClassName Win32_MappedLogicalDisk -ErrorAction Stop | ForEach-Object {
            if ($_.DeviceID -and $_.ProviderName) { $map[$_.DeviceID.TrimEnd(':').ToUpper()] = $_.ProviderName }
        }
    }
    catch { }
    try {
        $netUse = & net.exe use 2>$null
        foreach ($line in $netUse) {
            if ($line -match '^\s*(?:OK|Disconnected|Unavailable)?\s*([A-Z]):\s+(\\\\\S+)') {
                if (-not $map.ContainsKey($Matches[1])) { $map[$Matches[1]] = $Matches[2] }
            }
        }
    }
    catch { }
    return $map
}

function Resolve-LogFilePath {
    # Turns the "Save log to" box into a full .log path:
    #   blank -> default folder + auto name; *.log / *.txt -> as given; anything else -> folder.
    param(
        [string]$UserInput,
        [string]$Source,
        [string]$Destination,
        [string]$Preset,
        [string]$DefaultLogDir
    )
    # String operations only: in 5.1, Split-Path -Leaf returns "server\share" for a UNC share
    # root, and Join-Path fails for a drive letter that doesn't exist on this machine.
    $leaf = {
        param([string]$Name)
        $l = ([string]$Name).TrimEnd('\', '/', '.')
        $i = $l.LastIndexOfAny([char[]]'\/')
        if ($i -ge 0) { $l = $l.Substring($i + 1) }
        $l = ($l -replace '[<>:"/\\|?*]', '_').Trim('_')
        if (-not $l) { $l = 'root' }
        return $l
    }
    $autoName = '{0}_to_{1}_{2}_{3}.log' -f (& $leaf $Source), (& $leaf $Destination), $Preset, (Get-Date -Format 'yyyy-MM-dd_HHmmss')

    $in = $null
    if ($UserInput) { $in = $UserInput.Trim() }
    if ([string]::IsNullOrWhiteSpace($in)) { return [System.IO.Path]::Combine($DefaultLogDir, $autoName) }
    if ($in -match '\.(log|txt)$') { return $in }
    return [System.IO.Path]::Combine($in.TrimEnd('\', '/'), $autoName)
}

function New-JobOptions {
    param(
        [ValidateRange(0, 99)][int]$Retries = 3,
        [ValidateRange(0, 300)][int]$WaitSeconds = 5,
        [ValidateRange(0, 128)][int]$Threads = 0,
        [ValidateRange(0, 999999)][int]$InterPacketGap = 0,
        [ValidateSet('', 'zb', 'b')][string]$BackupMode = '',
        [string]$ExcludeFiles = '',
        [string]$ExcludeDirs = '',
        [string]$LogFolder = ''
    )
    return [PSCustomObject]@{
        retries      = $Retries
        waitTime     = $WaitSeconds
        threads      = $Threads
        ipg          = $InterPacketGap
        backupMode   = $BackupMode
        excludeFiles = $ExcludeFiles
        excludeDirs  = $ExcludeDirs
        logFolder    = $LogFolder
    }
}

function Get-RoboSkipClasses {
    # File classes robocopy lists with /V but does not copy. "modified" files are skipped by
    # default (Learn remarks); Incremental adds /XO, which excludes "Older" files.
    param([string]$Preset)
    $classes = @('same', 'modified', 'tweaked')
    if ($Preset -eq 'incremental') { $classes += 'older' }
    return [string[]]$classes
}

function Build-RobocopyArgs {
    # Returns one string per argument, unquoted. Quoting happens where the command line is built.
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [ValidateSet('full', 'incremental', 'dataonly', 'mirror')][string]$Preset = 'full',
        [Parameter(Mandatory)]$Options,
        [string]$LogPath,
        [switch]$ListOnly
    )
    $a = [System.Collections.Generic.List[string]]::new()
    $a.Add((ConvertTo-RoboPath $Source))
    $a.Add((ConvertTo-RoboPath $Destination))

    switch ($Preset) {
        'mirror'      { $a.Add('/MIR'); $a.Add('/COPY:DATSO') }
        'incremental' { $a.Add('/E'); $a.Add('/COPY:DATSO'); $a.Add('/XO'); $a.Add('/XX') }
        'dataonly'    { $a.Add('/E'); $a.Add('/COPY:DAT') }
        default       { $a.Add('/E'); $a.Add('/COPY:DATSO') }
    }
    $a.Add('/DCOPY:DAT')

    if ($Options.backupMode -eq 'b') { $a.Add('/B') }
    elseif ($Options.backupMode -eq 'zb') { $a.Add('/ZB') }

    # "The /mt parameter can't be used with the /ipg and /efsraw parameters." Threads win.
    # https://learn.microsoft.com/windows-server/administration/windows-commands/robocopy
    if ([int]$Options.threads -gt 0) { $a.Add("/MT:$([int]$Options.threads)") }
    elseif ([int]$Options.ipg -gt 0) { $a.Add("/IPG:$([int]$Options.ipg)") }

    $xf = @(([string]$Options.excludeFiles -split '\s+') | Where-Object { $_ })
    if ($xf.Count) { $a.Add('/XF'); foreach ($p in $xf) { $a.Add($p) } }
    $xd = @(([string]$Options.excludeDirs -split '\s+') | Where-Object { $_ })
    if ($xd.Count) { $a.Add('/XD'); foreach ($p in $xd) { $a.Add($p) } }

    if ($ListOnly) {
        foreach ($f in '/L', '/NFL', '/NDL', '/NJH', '/NP', '/BYTES', '/R:0', '/W:0') { $a.Add($f) }
    }
    else {
        $a.Add("/R:$([int]$Options.retries)")
        $a.Add("/W:$([int]$Options.waitTime)")
        # /V lists skipped files too, which the progress % needs. /UNILOG keeps non-English
        # file names intact. No /TEE: nobody reads the console.
        foreach ($f in '/V', '/BYTES', '/NP', '/NDL') { $a.Add($f) }
        if ($LogPath) { $a.Add("/UNILOG:$LogPath") }
    }
    return [string[]]$a.ToArray()
}

function Get-RoboExitInfo {
    # Robocopy exit codes are bit flags: 1 = files copied, 2 = extra files at the destination,
    # 4 = mismatched files, >= 8 = at least one failure.
    # https://learn.microsoft.com/windows-server/administration/windows-commands/robocopy
    # 16 is not documented on Learn; observed: a missing source directory returns 16.
    param(
        [Parameter(Mandatory)][int]$ExitCode,
        [string]$Preset = 'full',
        [long]$FailedCount = -1,
        [string[]]$FailedText = @()
    )
    $details = [System.Collections.Generic.List[string]]::new()
    $tip = $null

    if ($ExitCode -ge 16) {
        return [PSCustomObject]@{
            Status   = 'Failed'
            Headline = 'The copy could not run.'
            Details  = [string[]]@("Robocopy stopped with a serious error (exit code $ExitCode). This usually means the source or destination folder could not be reached or opened. The log shows the exact error.")
            Tip      = 'Check that both paths exist and that this account can open them, then run the job again.'
        }
    }

    if ($ExitCode -band 1) { $details.Add('New and changed files were copied.') }
    if ($ExitCode -band 2) {
        if ($Preset -eq 'mirror') { $details.Add('Files at the destination that are not in the source were removed (Mirror).') }
        else { $details.Add('The destination has extra files that are not in the source. They were left alone.') }
    }
    if ($ExitCode -band 4) { $details.Add('Some files or folders were mismatched (for example, a file at the source where the destination has a folder of the same name). See the log.') }

    if ($ExitCode -ge 8) {
        $status = 'Problems'
        if ($FailedCount -gt 0) {
            $headline = 'Finished, but {0:N0} file(s) could not be copied.' -f $FailedCount
        }
        else { $headline = 'Finished, but some files could not be copied.' }
        $details.Add('Some files still failed after all retries. Usually that is "access denied" or a file that was in use.')
        if (@($FailedText | Where-Object { $_ -match '^ERROR 5:' }).Count -gt 0) {
            $tip = 'Some files were "access denied". Run again as Incremental with "Files this account can''t open" set to "Always backup mode".'
        }
        else { $tip = 'Run again as Incremental to retry just the files that failed.' }
    }
    elseif ($ExitCode -ge 4) {
        $status = 'Warnings'
        $headline = 'Finished, with some mismatched files to check.'
    }
    else {
        $status = 'Done'
        if ($ExitCode -eq 0) { $headline = 'Nothing needed copying - the destination already matches the source.' }
        else { $headline = 'Copy finished successfully.' }
    }
    if ($details.Count -eq 0 -and $ExitCode -eq 0) { $details.Add('No files were copied and nothing failed.') }

    return [PSCustomObject]@{
        Status   = $status
        Headline = $headline
        Details  = [string[]]$details.ToArray()
        Tip      = $tip
    }
}

function Read-RoboSummary {
    # Reads the Dirs/Files/Bytes totals from robocopy output (the first column of each row).
    # Rows are matched by position because their labels are localized.
    param([string]$Text)
    $rows = @()
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*[^:\d\t]+:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$') {
            $rows += , [long[]]@($Matches[1], $Matches[2], $Matches[3], $Matches[4], $Matches[5], $Matches[6])
            if ($rows.Count -eq 3) { break }
        }
    }
    if ($rows.Count -lt 3) { return $null }
    return [PSCustomObject]@{
        Dirs  = $rows[0][0]
        Files = $rows[1][0]
        Bytes = $rows[2][0]
    }
}

function Get-SecondsLeft {
    # Time left from the copy rate across the samples (each has T = time, B = bytes done).
    # Returns -1 until there are at least 5 seconds of samples showing progress.
    param([long]$TotalBytes, [long]$ProcessedBytes, $Samples)
    if (-not $Samples -or $Samples.Count -lt 2) { return -1.0 }
    $first = $Samples[0]; $last = $Samples[$Samples.Count - 1]
    $dt = ($last.T - $first.T).TotalSeconds
    $db = [double]($last.B - $first.B)
    if ($dt -lt 5 -or $db -le 0) { return -1.0 }
    # [double] on both sides: [Math]::Max(0, $long) binds to the Int32 overload and throws
    # once more than 2 GB is left.
    $remaining = [Math]::Max([double]0, [double]($TotalBytes - $ProcessedBytes))
    return $remaining / ($db / $dt)
}

function Test-FolderName {
    # Returns a plain-English problem with a new folder name, or $null if it's fine.
    # Rules: https://learn.microsoft.com/windows/win32/fileio/naming-a-file
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return 'Type a name for the new folder.' }
    if ($Name.IndexOfAny([char[]]'<>:"/\|?*') -ge 0) { return 'Folder names can''t contain any of these characters: < > : " / \ | ? *' }
    foreach ($ch in $Name.ToCharArray()) {
        if ([int]$ch -lt 32) { return 'Folder names can''t contain control characters (such as tabs).' }
    }
    if ($Name.EndsWith(' ') -or $Name.EndsWith('.')) { return 'Folder names can''t end with a space or a period.' }
    # Device names are reserved with or without an extension (NUL.txt is NUL). Windows also
    # treats the superscript digits 1-3 (U+00B9, U+00B2, U+00B3) as COM/LPT port numbers.
    $base = $Name.Split('.')[0].Trim()
    $sup = "$([char]0xB9)$([char]0xB2)$([char]0xB3)"
    if ($base -match "^(?i:CON|PRN|AUX|NUL|COM[1-9$sup]|LPT[1-9$sup])$") {
        return "'$base' is a reserved Windows device name and can't be used as a folder name."
    }
    return $null
}

function Invoke-NewFolder {
    # Creates Parent\Name. Also used as the body of the background task, so it must not call
    # other functions from this script (the worker runspace doesn't have them).
    param([string]$Parent, [string]$Name)
    try {
        $path = [System.IO.Path]::Combine($Parent, $Name)
        if ([System.IO.Directory]::Exists($path)) {
            return [PSCustomObject]@{ Ok = $false; Path = $path; Error = "A folder named '$Name' already exists here." }
        }
        if (-not [System.IO.Directory]::Exists($Parent)) {
            return [PSCustomObject]@{ Ok = $false; Path = $path; Error = "The parent folder can't be reached: $Parent" }
        }
        [void][System.IO.Directory]::CreateDirectory($path)
        return [PSCustomObject]@{ Ok = $true; Path = $path; Error = $null }
    }
    catch {
        $e = $_.Exception
        while ($e.InnerException) { $e = $e.InnerException }
        return [PSCustomObject]@{ Ok = $false; Path = $null; Error = $e.Message }
    }
}

function Get-ReattachDecision {
    # On startup, decides what a job saved as Running really is. A PID alone is not enough:
    # Windows reuses PIDs, so the process start time must match too.
    param(
        [bool]$ExitFileExists,
        [bool]$ProcessAlive,
        $ProcessStartTime,
        [string]$SavedStartTime
    )
    if ($ExitFileExists) { return 'Finish' }
    $saved = ConvertTo-LocalDate $SavedStartTime
    if ($ProcessAlive -and $ProcessStartTime -and $saved) {
        if ([Math]::Abs(([datetime]$ProcessStartTime - $saved).TotalSeconds) -lt 2) { return 'Running' }
    }
    return 'Interrupted'
}

function ConvertTo-LocalDate {
    # Job times are stored as ISO 8601 strings. PowerShell 7's ConvertFrom-Json turns those
    # into DateTime objects while 5.1 leaves them as strings, so accept both.
    param($Value)
    # Only UTC values are converted: ToLocalTime() treats an unspecified kind as UTC and would
    # shift the time by the UTC offset.
    if ($null -eq $Value -or $Value -eq '') { return $null }
    $d = $null
    if ($Value -is [datetime]) { $d = $Value }
    else {
        try { $d = [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) }
        catch { return $null }
    }
    if ($d.Kind -eq [DateTimeKind]::Utc) { return $d.ToLocalTime() }
    return $d
}

#endregion

#region Job store

function New-MigrationJob {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [ValidateSet('full', 'incremental', 'dataonly', 'mirror')][string]$Preset = 'full',
        [Parameter(Mandatory)]$Options,
        $Preview = $null
    )
    $srcLeaf = Split-Path -Leaf ($Source.TrimEnd('\'))
    if (-not $srcLeaf) { $srcLeaf = $Source }
    $dstLeaf = $Destination.TrimEnd('\')
    if ($dstLeaf -match '^\\\\([^\\]+)') { $dstLeaf = $Matches[1] } else { $dstLeaf = Split-Path -Leaf $dstLeaf }
    if (-not $dstLeaf) { $dstLeaf = $Destination }

    return [PSCustomObject]@{
        id          = [guid]::NewGuid().ToString('N')
        name        = "$srcLeaf $($script:Arrow) $dstLeaf"
        source      = $Source
        destination = $Destination
        preset      = $Preset
        options     = $Options
        preview     = $Preview
        status      = 'Waiting'
        createdAt   = (Get-Date).ToString('o')
        startedAt   = $null
        finishedAt  = $null
        pid         = $null
        pidStart    = $null
        logPath     = $null
        exitFile    = $null
        exitCode    = $null
        headline    = $null
        details     = @()
        tip         = $null
        summary     = $null
        failedFiles = @()
    }
}

function Save-JobStore {
    # Written to a temp file and then swapped in, so a crash mid-write can't leave a half file.
    param([object[]]$Jobs, [Parameter(Mandatory)][string]$Path)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if ($null -eq $Jobs) { $Jobs = @() }
    $json = ConvertTo-Json -InputObject @($Jobs) -Depth 8
    $tmp = "$Path.tmp"
    [System.IO.File]::WriteAllText($tmp, $json, [System.Text.UTF8Encoding]::new($false))
    # [NullString]::Value, not $null: PowerShell passes $null to a .NET string parameter as "",
    # which File.Replace rejects as an illegal backup path.
    if (Test-Path -LiteralPath $Path) { [System.IO.File]::Replace($tmp, $Path, [NullString]::Value) }
    else { [System.IO.File]::Move($tmp, $Path) }
}

function Read-JobStore {
    param([Parameter(Mandatory)][string]$Path)
    $result = [PSCustomObject]@{ Jobs = @(); Warning = $null }
    if (-not (Test-Path -LiteralPath $Path)) { return $result }
    try {
        $text = [System.IO.File]::ReadAllText($Path)
        if ([string]::IsNullOrWhiteSpace($text)) { return $result }
        $parsed = $text | ConvertFrom-Json -ErrorAction Stop
        $result.Jobs = @($parsed | Where-Object { $_ -and $_.id })
    }
    catch {
        $bad = '{0}.bad-{1}' -f $Path, (Get-Date -Format 'yyyy-MM-dd_HHmmss')
        try { Move-Item -LiteralPath $Path -Destination $bad -Force } catch { }
        $result.Warning = "The saved job list could not be read (corrupt file). It was moved to $bad and the queue starts empty."
    }
    return $result
}

#endregion

#region Job runner

function Get-WrapperScript {
    # The detached wrapper runs robocopy, then records its exit code. It is passed to
    # powershell.exe -EncodedCommand (UTF-16), so Unicode paths survive; a .cmd file would be
    # read in the OEM code page.
    param([Parameter(Mandatory)][string[]]$RoboArgs, [Parameter(Mandatory)][string]$ExitFile)
    $quoted = ($RoboArgs | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ', '
    $exitQ = "'" + ($ExitFile -replace "'", "''") + "'"
    return @"
`$a = @($quoted)
& "`$env:SystemRoot\System32\robocopy.exe" @a
`$rc = `$LASTEXITCODE
[System.IO.File]::WriteAllText($exitQ, [string]`$rc)
"@
}

function Get-JobProcessInfo {
    param($Job)
    $info = [PSCustomObject]@{ Alive = $false; StartTime = $null }
    if (-not $Job.pid) { return $info }
    $p = Get-Process -Id ([int]$Job.pid) -ErrorAction SilentlyContinue
    if ($p) {
        $info.Alive = $true
        try { $info.StartTime = $p.StartTime } catch { }
    }
    return $info
}

function Start-MigrationJob {
    param(
        [Parameter(Mandatory)]$Job,
        [Parameter(Mandatory)][string]$StateDir,
        [Parameter(Mandatory)][string]$DefaultLogDir,
        [hashtable]$DriveMap = @{}
    )
    $src = Resolve-MappedDrive -Path $Job.source -Map $DriveMap
    $dst = Resolve-MappedDrive -Path $Job.destination -Map $DriveMap
    $logPath = Resolve-LogFilePath -UserInput $Job.options.logFolder -Source $src -Destination $dst -Preset $Job.preset -DefaultLogDir $DefaultLogDir
    $logDir = Split-Path -Parent $logPath
    if ($logDir -and -not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force -ErrorAction Stop | Out-Null }
    if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }

    $exitFile = Join-Path $StateDir "$($Job.id).exit"
    if (Test-Path -LiteralPath $exitFile) { Remove-Item -LiteralPath $exitFile -Force }

    $roboArgs = Build-RobocopyArgs -Source $src -Destination $dst -Preset $Job.preset -Options $Job.options -LogPath $logPath
    $wrapper = Get-WrapperScript -RoboArgs $roboArgs -ExitFile $exitFile
    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($wrapper))
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

    # Start-Process gives the wrapper its own (hidden) console, so it is not tied to this
    # window's console and keeps running after the GUI closes.
    $proc = Start-Process -FilePath $ps -ArgumentList @('-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-EncodedCommand', $encoded) -WindowStyle Hidden -PassThru -ErrorAction Stop

    $Job.pid = $proc.Id
    $Job.pidStart = $proc.StartTime.ToString('o')
    $Job.logPath = $logPath
    $Job.exitFile = $exitFile
    $Job.status = 'Running'
    $Job.startedAt = (Get-Date).ToString('o')
    $Job.finishedAt = $null
    $Job.exitCode = $null
}

function Stop-MigrationJob {
    param([Parameter(Mandatory)]$Job)
    $info = Get-JobProcessInfo -Job $Job
    if ($info.Alive -and (Get-ReattachDecision -ExitFileExists $false -ProcessAlive $true -ProcessStartTime $info.StartTime -SavedStartTime $Job.pidStart) -eq 'Running') {
        # /T takes robocopy (the wrapper's child) down with it.
        & taskkill.exe /PID ([int]$Job.pid) /T /F 2>&1 | Out-Null
    }
    $Job.status = 'Stopped'
    $Job.finishedAt = (Get-Date).ToString('o')
    $Job.headline = 'Stopped before it finished.'
    $Job.details = @('Files copied so far are kept. Run again as Incremental to finish the job without recopying them.')
    $Job.tip = $null
}

function New-JobTailer {
    param([Parameter(Mandatory)]$Job)
    return [RoboMigration.RoboLogTailer]::new([string]$Job.logPath, (Get-RoboSkipClasses -Preset $Job.preset))
}

function Read-JobExitCode {
    # Returns the exit code, or $null if the exit file isn't there or isn't complete yet.
    param($Job)
    if (-not $Job.exitFile -or -not (Test-Path -LiteralPath $Job.exitFile)) { return $null }
    try {
        $text = [System.IO.File]::ReadAllText($Job.exitFile).Trim()
        $code = 0
        if ([int]::TryParse($text, [ref]$code)) { return $code }
    }
    catch { }
    return $null
}

function Complete-MigrationJob {
    param([Parameter(Mandatory)]$Job, [Parameter(Mandatory)]$Tailer)
    $guard = 0
    do { [void]$Tailer.Poll(64MB); $guard++ } while (-not $Tailer.CaughtUp -and $guard -lt 1000)

    $code = Read-JobExitCode -Job $Job
    if ($null -eq $code) { $code = 16 }
    $failed = $Tailer.GetFailedFiles()
    $failedCount = $Tailer.FilesFailed
    if ($Tailer.HasSummary) { $failedCount = $Tailer.SummaryFiles[4] }
    $info = Get-RoboExitInfo -ExitCode $code -Preset $Job.preset -FailedCount $failedCount -FailedText $failed

    $Job.exitCode = $code
    $Job.status = $info.Status
    $Job.headline = $info.Headline
    $Job.details = $info.Details
    $Job.tip = $info.Tip
    if ($info.Status -eq 'Failed' -and $Tailer.LastError) { $Job.details = @($info.Details) + "Last error: $($Tailer.LastError)" }
    $Job.finishedAt = (Get-Date).ToString('o')
    if ($Tailer.HasSummary) {
        $Job.summary = [PSCustomObject]@{
            dirs  = [long[]]$Tailer.SummaryDirs
            files = [long[]]$Tailer.SummaryFiles
            bytes = [long[]]$Tailer.SummaryBytes
        }
    }
    $Job.failedFiles = @($failed | Select-Object -First 200)
    try { Remove-Item -LiteralPath $Job.exitFile -Force -ErrorAction SilentlyContinue } catch { }
}

function Invoke-RoboPreviewSync {
    # Synchronous preview, used by the tests. The window uses Start-RoboPreview instead.
    param([string]$Source, [string]$Destination, [string]$Preset, $Options)
    $p = Start-RoboPreview -Source $Source -Destination $Destination -Preset $Preset -Options $Options
    $p.Process.WaitForExit()
    return (Read-RoboSummary -Text $p.Output.Result)
}

function Start-RoboPreview {
    # robocopy /L prints only the summary (/NFL /NDL /NJH), read asynchronously so the window
    # never waits on it. Stdout goes to a Task, so there's no pipe deadlock.
    param([string]$Source, [string]$Destination, [string]$Preset, $Options)
    $dest = $Destination
    if (-not $dest) { $dest = Join-Path $env:TEMP ('robomig-preview-' + [guid]::NewGuid().ToString('N')) }
    $roboArgs = Build-RobocopyArgs -Source $Source -Destination $dest -Preset $Preset -Options $Options -ListOnly
    $psi = [System.Diagnostics.ProcessStartInfo]::new((Join-Path $env:SystemRoot 'System32\robocopy.exe'))
    $psi.Arguments = ($roboArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    return [PSCustomObject]@{
        Process   = $proc
        Output    = $proc.StandardOutput.ReadToEndAsync()
        StartedAt = Get-Date
    }
}

#endregion

if ($LoadFunctionsOnly) { return }

#region Startup checks

# WPF needs a single-threaded apartment. Windows PowerShell is STA by default; relaunch in it
# if this host isn't.
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    Start-Process -FilePath $ps -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$PSCommandPath`"")
    return
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

# Elevation is checked here rather than with #Requires so the tests can load the functions.
# Relaunching elevated means "Run with PowerShell" from Explorer just works after a UAC prompt.
$identity = [System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    try {
        Start-Process -FilePath $ps -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$PSCommandPath`"") -ErrorAction Stop
    }
    catch {
        [System.Windows.MessageBox]::Show('Robocopy Migration needs to run as administrator to copy permissions and owners. Right-click PowerShell, choose "Run as administrator", and start the script again.', 'Robocopy Migration', 'OK', 'Warning') | Out-Null
    }
    return
}

# One window per tool folder: two windows would fight over the same jobs.json.
$sha = [System.Security.Cryptography.SHA1]::Create()
$hash = -join ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($script:StateDir.ToLowerInvariant())) | Select-Object -First 8 | ForEach-Object { $_.ToString('x2') })
$createdNew = $false
$script:Mutex = [System.Threading.Mutex]::new($true, "Global\RobocopyMigrationGUI_$hash", [ref]$createdNew)
if (-not $createdNew) {
    [System.Windows.MessageBox]::Show('Robocopy Migration is already open (possibly in another session on this server). Use that window, or close it first.', 'Robocopy Migration', 'OK', 'Information') | Out-Null
    return
}

#endregion

#region Window resources and themes

$script:Themes = @{
    dark  = @{
        Bg = '#16181D'; Panel = '#101216'; Card = '#1C1F26'; CardHover = '#232833'; SelBg = '#1A2733'
        Input = '#0F1115'; Border = '#262A33'; BorderStrong = '#343A46'
        BtnBg = '#232731'; BtnHover = '#2C313D'; BtnPressed = '#1B1F27'
        Text = '#D7DBE2'; TextStrong = '#F0F3F6'; Muted = '#8B949E'
        Accent = '#5DADE2'; AccentBtn = '#2E86C1'; AccentBtnHover = '#3B97D3'; OnAccent = '#FFFFFF'
        Danger = '#F08A7C'; Ok = '#6FD39B'; Warn = '#F2CC60'
        PillRunBg = '#173A52'; PillOkBg = '#173D2A'; PillWarnBg = '#463A12'; PillBadBg = '#4A1F1B'; PillMutedBg = '#2B2F38'
        Scrim = '#A0000000'; BannerBg = '#2D2710'; BannerBorder = '#5A4A14'; LogBg = '#0B0D10'
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
        Scrim = '#66000000'; BannerBg = '#FFF5D6'; BannerBorder = '#E6CB7A'; LogBg = '#F8F9FB'
        Track = '#E3E7EC'; ScrollThumb = '#C3C9D1'
    }
}

$script:ResourcesXaml = @'
<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <BooleanToVisibilityConverter x:Key="B2V"/>
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
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>

  <Style x:Key="PresetCard" TargetType="RadioButton">
    <Setter Property="Foreground" Value="{DynamicResource Text}"/>
    <Setter Property="Cursor" Value="Hand"/>
    <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
    <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="RadioButton">
          <Border x:Name="b" Background="{DynamicResource Card}" BorderBrush="{DynamicResource BorderStrong}"
                  BorderThickness="1" CornerRadius="4" Padding="12,9" Margin="0,0,0,6">
            <ContentPresenter/>
          </Border>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="{DynamicResource CardHover}"/></Trigger>
            <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="{DynamicResource Accent}"/></Trigger>
            <Trigger Property="IsChecked" Value="True">
              <Setter TargetName="b" Property="Background" Value="{DynamicResource SelBg}"/>
              <Setter TargetName="b" Property="BorderBrush" Value="{DynamicResource Accent}"/>
              <Setter TargetName="b" Property="BorderThickness" Value="3,1,1,1"/>
            </Trigger>
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
              <Path x:Name="tick" Data="M3,8 L6.5,11.5 L13,4.5" Stroke="{DynamicResource OnAccent}" StrokeThickness="2" Visibility="Collapsed"/>
            </Border>
            <ContentPresenter Margin="8,0,0,0" VerticalAlignment="Center"/>
          </StackPanel>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="box" Property="BorderBrush" Value="{DynamicResource Accent}"/></Trigger>
            <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="box" Property="BorderBrush" Value="{DynamicResource Accent}"/></Trigger>
            <Trigger Property="IsChecked" Value="True">
              <Setter TargetName="box" Property="Background" Value="{DynamicResource AccentBtn}"/>
              <Setter TargetName="box" Property="BorderBrush" Value="{DynamicResource AccentBtn}"/>
              <Setter TargetName="tick" Property="Visibility" Value="Visible"/>
            </Trigger>
            <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/></Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>

  <Style x:Key="Disclosure" TargetType="ToggleButton">
    <Setter Property="Foreground" Value="{DynamicResource Accent}"/>
    <Setter Property="Cursor" Value="Hand"/>
    <Setter Property="FontWeight" Value="SemiBold"/>
    <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="ToggleButton">
          <StackPanel Orientation="Horizontal" Background="Transparent">
            <TextBlock x:Name="arrow" FontFamily="{StaticResource Sym}" Text="&#x25B8;" Width="14" VerticalAlignment="Center"/>
            <ContentPresenter VerticalAlignment="Center"/>
          </StackPanel>
          <ControlTemplate.Triggers>
            <Trigger Property="IsChecked" Value="True"><Setter TargetName="arrow" Property="Text" Value="&#x25BE;"/></Trigger>
            <Trigger Property="IsMouseOver" Value="True"><Setter Property="Opacity" Value="0.8"/></Trigger>
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
</ResourceDictionary>
'@

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

#endregion

#region Main window XAML

$script:MainXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Robocopy Migration" Width="1220" Height="800" MinWidth="980" MinHeight="600"
        WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" FontSize="13"
        Background="{DynamicResource Bg}" Foreground="{DynamicResource Text}"
        UseLayoutRounding="True" TextOptions.TextFormattingMode="Display">
  <!--RESOURCES-->
  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="56"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
    </Grid.RowDefinitions>

    <!-- Title bar -->
    <Border Grid.Row="0" Background="{DynamicResource Panel}" BorderBrush="{DynamicResource Border}" BorderThickness="0,0,0,1">
      <DockPanel Margin="16,0" LastChildFill="False">
        <StackPanel DockPanel.Dock="Left" Orientation="Horizontal" VerticalAlignment="Center">
          <Border Width="30" Height="30" CornerRadius="4" Background="{DynamicResource AccentBtn}">
            <TextBlock Text="&#x21C4;" FontFamily="{StaticResource Sym}" FontSize="17" Foreground="{DynamicResource OnAccent}"
                       HorizontalAlignment="Center" VerticalAlignment="Center"/>
          </Border>
          <TextBlock Text="Robocopy Migration" FontSize="16" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}"
                     Margin="10,0,0,0" VerticalAlignment="Center"/>
          <TextBlock x:Name="VersionText" FontSize="11" Foreground="{DynamicResource Muted}" Margin="8,3,0,0" VerticalAlignment="Center"/>
        </StackPanel>
        <Button x:Name="NewJobBtn" DockPanel.Dock="Right" Style="{StaticResource PrimaryBtn}" VerticalAlignment="Center" Padding="14,7"
                ToolTip="Plan a new copy (Ctrl+N)">
          <TextBlock><Run Text="+" FontWeight="Bold"/><Run Text="  New Job"/></TextBlock>
        </Button>
        <Button x:Name="ThemeBtn" DockPanel.Dock="Right" Style="{StaticResource GhostBtn}" VerticalAlignment="Center" Margin="0,0,10,0"/>
        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center" Margin="0,0,18,0">
          <TextBlock Text="RUN JOBS" Style="{StaticResource Lbl}" Margin="0,0,8,0" VerticalAlignment="Center"/>
          <RadioButton x:Name="ModeSeq" GroupName="mode" Style="{StaticResource Seg}" Content="One at a time" IsChecked="True"
                       ToolTip="Start the next waiting job when the current one finishes."/>
          <RadioButton x:Name="ModePar" GroupName="mode" Style="{StaticResource Seg}" Content="All at once"
                       ToolTip="Start every waiting job together. Fine for different servers; slower on the same disk."/>
        </StackPanel>
      </DockPanel>
    </Border>

    <!-- Warning banner -->
    <Border x:Name="Banner" Grid.Row="1" Visibility="Collapsed" Background="{DynamicResource BannerBg}"
            BorderBrush="{DynamicResource BannerBorder}" BorderThickness="0,0,0,1" Padding="16,8">
      <DockPanel>
        <Button x:Name="BannerClose" DockPanel.Dock="Right" Style="{StaticResource GhostBtn}" Content="Dismiss"/>
        <TextBlock x:Name="BannerText" Foreground="{DynamicResource Warn}" TextWrapping="Wrap" VerticalAlignment="Center"/>
      </DockPanel>
    </Border>

    <Grid Grid.Row="2">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="370"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>

      <!-- Queue -->
      <Border Grid.Column="0" BorderBrush="{DynamicResource Border}" BorderThickness="0,0,1,0">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <DockPanel Grid.Row="0" Margin="16,14,12,6">
            <Button x:Name="ClearDoneBtn" DockPanel.Dock="Right" Style="{StaticResource GhostBtn}" Content="Clear finished"
                    ToolTip="Remove finished, stopped and interrupted jobs from this list (logs are kept)."/>
            <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
              <TextBlock Text="JOBS" Style="{StaticResource Lbl}" Margin="0"/>
              <TextBlock x:Name="JobCount" Foreground="{DynamicResource Muted}" FontSize="11" Margin="6,0,0,0"/>
            </StackPanel>
          </DockPanel>
          <Border x:Name="QueueBar" Grid.Row="1" Margin="12,0,12,8" Padding="10,8" CornerRadius="4"
                  Background="{DynamicResource Card}" BorderBrush="{DynamicResource Border}" BorderThickness="1">
            <DockPanel>
              <Button x:Name="QueueBtn" DockPanel.Dock="Right" Style="{StaticResource Btn}" Padding="10,4"/>
              <TextBlock x:Name="QueueText" Foreground="{DynamicResource Muted}" FontSize="11.5" TextWrapping="Wrap" VerticalAlignment="Center" Margin="0,0,8,0"/>
            </DockPanel>
          </Border>
          <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto">
            <StackPanel Margin="12,0,12,12">
              <StackPanel x:Name="QueuePanel"/>
              <TextBlock x:Name="QueueEmpty" Style="{StaticResource Hint}" Margin="4,20,4,0" FontSize="12.5"
                         Text="No jobs yet. Click &quot;+ New Job&quot; to plan your first copy."/>
            </StackPanel>
          </ScrollViewer>
        </Grid>
      </Border>

      <!-- Detail -->
      <Grid Grid.Column="1">
        <StackPanel x:Name="DetailEmpty" VerticalAlignment="Center" HorizontalAlignment="Center" MaxWidth="380">
          <TextBlock Text="&#x21C4;" FontFamily="{StaticResource Sym}" FontSize="40" Foreground="{DynamicResource Track}" HorizontalAlignment="Center"/>
          <TextBlock Text="Select a job to see its progress" FontSize="15" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}"
                     HorizontalAlignment="Center" Margin="0,10,0,0"/>
          <TextBlock Style="{StaticResource Hint}" TextAlignment="Center" Margin="0,6,0,0"
                     Text="Copies keep running if you close this window. Reopen the tool to check on them."/>
        </StackPanel>

        <Grid x:Name="DetailView" Margin="24,18,24,16" Visibility="Collapsed">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>

          <DockPanel Grid.Row="0">
            <Border x:Name="DetailPill" DockPanel.Dock="Right" CornerRadius="10" Padding="10,3" VerticalAlignment="Center">
              <TextBlock x:Name="DetailPillText" FontSize="12" FontWeight="SemiBold"/>
            </Border>
            <TextBlock x:Name="DetailName" FontSize="19" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}" TextTrimming="CharacterEllipsis"/>
          </DockPanel>

          <StackPanel Grid.Row="1" Margin="0,6,0,0">
            <TextBlock x:Name="DetailPaths" FontFamily="{StaticResource Mono}" FontSize="12" Foreground="{DynamicResource Text}" TextWrapping="Wrap"/>
            <TextBlock x:Name="DetailMeta" FontSize="12" Foreground="{DynamicResource Muted}" Margin="0,3,0,0" TextWrapping="Wrap"/>
          </StackPanel>

          <StackPanel x:Name="ProgressSection" Grid.Row="2" Margin="0,16,0,0">
            <Grid Height="8">
              <Grid.ColumnDefinitions>
                <ColumnDefinition x:Name="ProgFill" Width="0*"/>
                <ColumnDefinition x:Name="ProgRest" Width="1*"/>
              </Grid.ColumnDefinitions>
              <Border Grid.ColumnSpan="2" CornerRadius="4" Background="{DynamicResource Track}"/>
              <Border Grid.Column="0" CornerRadius="4" Background="{DynamicResource Accent}"/>
            </Grid>
            <DockPanel Margin="0,6,0,0">
              <TextBlock x:Name="ProgPercent" DockPanel.Dock="Left" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}" Margin="0,0,12,0"/>
              <TextBlock x:Name="ProgFile" FontFamily="{StaticResource Mono}" FontSize="11.5" Foreground="{DynamicResource Muted}" TextTrimming="CharacterEllipsis"/>
            </DockPanel>
          </StackPanel>

          <UniformGrid x:Name="StatsSection" Grid.Row="3" Columns="4" Margin="0,14,0,0">
            <StackPanel><TextBlock x:Name="Stat1" FontSize="21" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}"/><TextBlock x:Name="Stat1L" FontSize="11.5" Foreground="{DynamicResource Muted}"/></StackPanel>
            <StackPanel><TextBlock x:Name="Stat2" FontSize="21" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}"/><TextBlock x:Name="Stat2L" FontSize="11.5" Foreground="{DynamicResource Muted}"/></StackPanel>
            <StackPanel><TextBlock x:Name="Stat3" FontSize="21" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}"/><TextBlock x:Name="Stat3L" FontSize="11.5" Foreground="{DynamicResource Muted}"/></StackPanel>
            <StackPanel><TextBlock x:Name="Stat4" FontSize="21" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}"/><TextBlock x:Name="Stat4L" FontSize="11.5" Foreground="{DynamicResource Muted}"/></StackPanel>
          </UniformGrid>

          <StackPanel x:Name="FinishedSection" Grid.Row="4" Margin="0,16,0,0">
            <Border x:Name="VerdictBox" CornerRadius="4" BorderThickness="1" Padding="12,10">
              <StackPanel>
                <TextBlock x:Name="VerdictHeadline" FontWeight="SemiBold" FontSize="13.5" TextWrapping="Wrap"/>
                <TextBlock x:Name="VerdictDetails" Foreground="{DynamicResource Text}" TextWrapping="Wrap" Margin="0,4,0,0"/>
                <TextBlock x:Name="VerdictTip" Foreground="{DynamicResource Muted}" FontSize="12" TextWrapping="Wrap" Margin="0,6,0,0"/>
              </StackPanel>
            </Border>
            <Grid x:Name="SummaryGrid" Margin="0,12,0,0"/>
            <StackPanel x:Name="FailedSection">
              <TextBlock x:Name="FailedLabel" Style="{StaticResource Lbl}"/>
              <TextBox x:Name="FailedBox" IsReadOnly="True" MaxHeight="130" FontFamily="{StaticResource Mono}" FontSize="11.5"
                       Foreground="{DynamicResource Danger}" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"/>
            </StackPanel>
          </StackPanel>

          <TextBlock x:Name="LogLabel" Grid.Row="5" Style="{StaticResource Lbl}" Text="LATEST LOG LINES"/>
          <TextBox x:Name="LogBox" Grid.Row="6" IsReadOnly="True" FontFamily="{StaticResource Mono}" FontSize="11.5"
                   Background="{DynamicResource LogBg}" Foreground="{DynamicResource Muted}"
                   VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" MinHeight="60"/>

          <WrapPanel Grid.Row="7" Margin="0,12,0,0">
            <Button x:Name="StartBtn" Style="{StaticResource PrimaryBtn}" Margin="0,0,8,0">
              <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x25B6;"/><Run Text="  Start now"/></TextBlock>
            </Button>
            <Button x:Name="OpenLogBtn" Style="{StaticResource Btn}" Margin="0,0,8,0">
              <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x1F4C4;"/><Run Text="  Open log"/></TextBlock>
            </Button>
            <Button x:Name="OpenDestBtn" Style="{StaticResource Btn}" Margin="0,0,8,0">
              <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x1F4C1;"/><Run Text="  Open destination"/></TextBlock>
            </Button>
            <Button x:Name="RerunBtn" Style="{StaticResource Btn}" Margin="0,0,8,0"
                    ToolTip="Start a new Incremental job with the same folders and options. Files already copied are skipped.">
              <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x21BB;"/><Run Text="  Run again as Incremental"/></TextBlock>
            </Button>
            <Button x:Name="StopBtn" Style="{StaticResource DangerBtn}" Margin="0,0,8,0">
              <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x25A0;"/><Run Text="  Stop"/></TextBlock>
            </Button>
            <Button x:Name="RemoveBtn" Style="{StaticResource GhostBtn}" Content="Remove from list"
                    ToolTip="Remove this job from the list. Copied files and the log are kept."/>
          </WrapPanel>
        </Grid>
      </Grid>
    </Grid>

    <!-- New Job slide-in panel -->
    <Grid x:Name="Overlay" Grid.RowSpan="3" Visibility="Collapsed">
      <Border x:Name="Scrim" Background="{DynamicResource Scrim}"/>
      <Border x:Name="NewJobPanel" Width="500" HorizontalAlignment="Right" Background="{DynamicResource Bg}"
              BorderBrush="{DynamicResource BorderStrong}" BorderThickness="1,0,0,0">
        <Border.RenderTransform><TranslateTransform x:Name="PanelSlide" X="0"/></Border.RenderTransform>
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <Border Grid.Row="0" Background="{DynamicResource Panel}" BorderBrush="{DynamicResource Border}" BorderThickness="0,0,0,1" Padding="20,14">
            <DockPanel>
              <Button x:Name="PanelClose" DockPanel.Dock="Right" Style="{StaticResource GhostBtn}" ToolTip="Close (Esc)">
                <TextBlock FontFamily="{StaticResource Sym}" Text="&#x2715;"/>
              </Button>
              <TextBlock Text="New Migration Job" FontSize="16" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}" VerticalAlignment="Center"/>
            </DockPanel>
          </Border>

          <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
            <StackPanel Margin="20,4,20,20">
              <TextBlock Style="{StaticResource Lbl}" Text="COPY FROM"/>
              <DockPanel>
                <Button x:Name="SrcBrowse" DockPanel.Dock="Right" Style="{StaticResource Btn}" Margin="6,0,0,0">
                  <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x1F4C1;"/><Run Text="  Browse"/></TextBlock>
                </Button>
                <TextBox x:Name="SrcBox" FontFamily="{StaticResource Mono}"/>
              </DockPanel>
              <TextBlock Style="{StaticResource Hint}" Text="The folder or share to copy. Mapped drives (like F:) are changed to their \\server\share path automatically."/>

              <TextBlock Style="{StaticResource Lbl}" Text="COPY TO"/>
              <DockPanel>
                <Button x:Name="DstBrowse" DockPanel.Dock="Right" Style="{StaticResource Btn}" Margin="6,0,0,0">
                  <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x1F4C1;"/><Run Text="  Browse"/></TextBlock>
                </Button>
                <TextBox x:Name="DstBox" FontFamily="{StaticResource Mono}"/>
              </DockPanel>
              <TextBlock Style="{StaticResource Hint}" Text="The folder to copy into. Robocopy creates it if it doesn't exist."/>

              <TextBlock Style="{StaticResource Lbl}" Text="TYPE OF COPY"/>
              <RadioButton x:Name="PresetFull" GroupName="preset" Style="{StaticResource PresetCard}" IsChecked="True">
                <StackPanel>
                  <TextBlock Text="Full Migration" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}"/>
                  <TextBlock Style="{StaticResource Hint}" Margin="0,2,0,0" Text="Files, folders, timestamps, NTFS permissions and owners. Use for moving a share to a new server."/>
                </StackPanel>
              </RadioButton>
              <RadioButton x:Name="PresetIncr" GroupName="preset" Style="{StaticResource PresetCard}">
                <StackPanel>
                  <TextBlock Text="Incremental" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}"/>
                  <TextBlock Style="{StaticResource Hint}" Margin="0,2,0,0" Text="Only new or updated files, with permissions. Use for a second pass or overnight top-up after a full copy."/>
                </StackPanel>
              </RadioButton>
              <RadioButton x:Name="PresetData" GroupName="preset" Style="{StaticResource PresetCard}">
                <StackPanel>
                  <TextBlock Text="Data Only" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}"/>
                  <TextBlock Style="{StaticResource Hint}" Margin="0,2,0,0" Text="Files, folders and timestamps - no permissions. Use when the destination has its own permission setup."/>
                </StackPanel>
              </RadioButton>
              <RadioButton x:Name="PresetMirror" GroupName="preset" Style="{StaticResource PresetCard}">
                <StackPanel>
                  <TextBlock Text="Mirror" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}"/>
                  <TextBlock Style="{StaticResource Hint}" Margin="0,2,0,0" Foreground="{DynamicResource Danger}"
                             Text="Exact copy, including permissions. DELETES files at the destination that aren't in the source."/>
                </StackPanel>
              </RadioButton>

              <ToggleButton x:Name="AdvToggle" Style="{StaticResource Disclosure}" Content="Advanced options" Margin="0,14,0,0" HorizontalAlignment="Left"/>
              <Grid x:Name="AdvPanel" Visibility="{Binding IsChecked, ElementName=AdvToggle, Converter={StaticResource B2V}}">
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="16"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <StackPanel Grid.Row="0" Grid.Column="0">
                  <TextBlock Style="{StaticResource Lbl}" Text="RETRIES PER FILE"/>
                  <TextBox x:Name="RetriesBox" Text="3"/>
                </StackPanel>
                <StackPanel Grid.Row="0" Grid.Column="2">
                  <TextBlock Style="{StaticResource Lbl}" Text="WAIT BETWEEN RETRIES (SEC)"/>
                  <TextBox x:Name="WaitBox" Text="5"/>
                </StackPanel>
                <StackPanel Grid.Row="1" Grid.Column="0">
                  <TextBlock Style="{StaticResource Lbl}" Text="COPY SEVERAL FILES AT ONCE"/>
                  <DockPanel>
                    <TextBox x:Name="MtBox" DockPanel.Dock="Right" Width="56" Text="8" IsEnabled="False" ToolTip="Number of files copied at the same time (1-128)."/>
                    <CheckBox x:Name="MtCheck" Content="Threads" VerticalAlignment="Center"/>
                  </DockPanel>
                </StackPanel>
                <StackPanel Grid.Row="1" Grid.Column="2">
                  <TextBlock Style="{StaticResource Lbl}" Text="SLOW DOWN (MS BETWEEN PACKETS)"/>
                  <TextBox x:Name="IpgBox" Text="0" ToolTip="Pauses between network packets to leave bandwidth for users. 0 = full speed."/>
                </StackPanel>
                <TextBlock Grid.Row="2" Grid.ColumnSpan="3" Style="{StaticResource Hint}"
                           Text="Several files at once is much faster for lots of small files. Robocopy can't slow down and use several files at once together, so slowing down is turned off while threads are on."/>
                <StackPanel Grid.Row="3" Grid.ColumnSpan="3">
                  <TextBlock Style="{StaticResource Lbl}" Text="FILES THIS ACCOUNT CAN'T OPEN"/>
                  <StackPanel Orientation="Horizontal">
                    <RadioButton x:Name="BkOff" GroupName="bk" Style="{StaticResource Seg}" Content="Skip them" IsChecked="True"/>
                    <RadioButton x:Name="BkZb" GroupName="bk" Style="{StaticResource Seg}" Content="Retry in backup mode"/>
                    <RadioButton x:Name="BkB" GroupName="bk" Style="{StaticResource Seg}" Content="Always backup mode"/>
                  </StackPanel>
                  <TextBlock Style="{StaticResource Hint}" Text="Backup mode reads files even when their permissions would block this account (fixes &quot;Access is denied&quot;). Retry is restartable but slower; Always is fastest."/>
                </StackPanel>
                <StackPanel Grid.Row="4" Grid.Column="0">
                  <TextBlock Style="{StaticResource Lbl}" Text="SKIP FILES MATCHING"/>
                  <TextBox x:Name="XfBox" FontFamily="{StaticResource Mono}" ToolTip="Space-separated, e.g. *.tmp thumbs.db"/>
                </StackPanel>
                <StackPanel Grid.Row="4" Grid.Column="2">
                  <TextBlock Style="{StaticResource Lbl}" Text="SKIP FOLDERS NAMED"/>
                  <TextBox x:Name="XdBox" FontFamily="{StaticResource Mono}" ToolTip="Space-separated, e.g. Temp .git"/>
                </StackPanel>
                <StackPanel Grid.Row="5" Grid.ColumnSpan="3">
                  <TextBlock Style="{StaticResource Lbl}" Text="SAVE LOG TO"/>
                  <TextBox x:Name="LogDirBox" FontFamily="{StaticResource Mono}"/>
                  <TextBlock x:Name="LogDirHint" Style="{StaticResource Hint}"/>
                </StackPanel>
              </Grid>

              <Border x:Name="PreviewBox" Margin="0,18,0,0" Padding="12,10" CornerRadius="4" BorderThickness="1"
                      Background="{DynamicResource SelBg}" BorderBrush="{DynamicResource BorderStrong}">
                <StackPanel>
                  <TextBlock Text="PREVIEW" Style="{StaticResource Lbl}" Margin="0" Foreground="{DynamicResource Accent}"/>
                  <TextBlock x:Name="PreviewText" TextWrapping="Wrap" Margin="0,4,0,0" Foreground="{DynamicResource TextStrong}"/>
                  <TextBlock x:Name="PreviewHint" Style="{StaticResource Hint}"/>
                </StackPanel>
              </Border>
              <TextBlock x:Name="FormError" Foreground="{DynamicResource Danger}" TextWrapping="Wrap" Margin="0,10,0,0" Visibility="Collapsed"/>
            </StackPanel>
          </ScrollViewer>

          <Border Grid.Row="2" Background="{DynamicResource Panel}" BorderBrush="{DynamicResource Border}" BorderThickness="0,1,0,0" Padding="20,12">
            <DockPanel>
              <Button x:Name="PreviewBtn" DockPanel.Dock="Left" Style="{StaticResource Btn}"/>
              <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" HorizontalAlignment="Right">
                <Button x:Name="AddBtn" Style="{StaticResource Btn}" Content="Add to Queue" Margin="0,0,8,0"
                        ToolTip="Add the job without starting it."/>
                <Button x:Name="AddStartBtn" Style="{StaticResource PrimaryBtn}">
                  <TextBlock><Run FontFamily="{StaticResource Sym}" Text="&#x25B6;"/><Run Text="  Add &amp; Start"/></TextBlock>
                </Button>
              </StackPanel>
            </DockPanel>
          </Border>
        </Grid>
      </Border>
    </Grid>
  </Grid>
</Window>
'@

$script:CardXaml = @'
<Border xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Style="{DynamicResource CardBorder}" BorderBrush="{DynamicResource Border}" BorderThickness="1"
        CornerRadius="4" Padding="12,10" Margin="0,0,0,8" Cursor="Hand">
  <StackPanel>
    <DockPanel>
      <Border x:Name="Pill" DockPanel.Dock="Right" CornerRadius="9" Padding="8,2" Margin="8,0,0,0" VerticalAlignment="Top">
        <TextBlock x:Name="PillText" FontSize="11" FontWeight="SemiBold"/>
      </Border>
      <TextBlock x:Name="Name" FontWeight="SemiBold" Foreground="{DynamicResource TextStrong}" TextTrimming="CharacterEllipsis"/>
    </DockPanel>
    <TextBlock x:Name="Sub" FontSize="11.5" Foreground="{DynamicResource Muted}" Margin="0,3,0,0" TextTrimming="CharacterEllipsis"/>
    <Grid x:Name="Bar" Height="4" Margin="0,8,0,0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition x:Name="BarFill" Width="0*"/>
        <ColumnDefinition x:Name="BarRest" Width="1*"/>
      </Grid.ColumnDefinitions>
      <Border Grid.ColumnSpan="2" CornerRadius="2" Background="{DynamicResource Track}"/>
      <Border Grid.Column="0" CornerRadius="2" Background="{DynamicResource Accent}"/>
    </Grid>
  </StackPanel>
</Border>
'@

$script:BrowseXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Choose a folder" Width="600" Height="640" MinWidth="440" MinHeight="400"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False" FontFamily="Segoe UI" FontSize="13"
        Background="{DynamicResource Bg}" Foreground="{DynamicResource Text}"
        UseLayoutRounding="True" TextOptions.TextFormattingMode="Display">
  <!--RESOURCES-->
  <Grid Margin="16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <StackPanel Grid.Row="0">
      <TextBlock Style="{StaticResource Lbl}" Margin="0,0,0,5" Text="GO TO A SERVER OR FOLDER"/>
      <DockPanel>
        <Button x:Name="GoBtn" DockPanel.Dock="Right" Style="{StaticResource Btn}" Content="Go" Margin="6,0,0,0"/>
        <TextBox x:Name="GoBox" FontFamily="{StaticResource Mono}"/>
      </DockPanel>
      <TextBlock Style="{StaticResource Hint}" Margin="0,4,0,10" Text="Type a path like \\fs01\Shares and press Enter. Folders load in the background, so a slow server won't freeze this window."/>
    </StackPanel>
    <TreeView x:Name="Tree" Grid.Row="1" Background="{DynamicResource Input}" BorderBrush="{DynamicResource BorderStrong}"
              Foreground="{DynamicResource Text}" Padding="4">
      <TreeView.Resources>
        <SolidColorBrush x:Key="{x:Static SystemColors.HighlightBrushKey}" Color="#2E86C1"/>
        <SolidColorBrush x:Key="{x:Static SystemColors.HighlightTextBrushKey}" Color="#FFFFFF"/>
        <SolidColorBrush x:Key="{x:Static SystemColors.InactiveSelectionHighlightBrushKey}" Color="#3A6E94"/>
        <SolidColorBrush x:Key="{x:Static SystemColors.InactiveSelectionHighlightTextBrushKey}" Color="#FFFFFF"/>
      </TreeView.Resources>
    </TreeView>
    <Border x:Name="NewFolderRow" Grid.Row="2" Visibility="Collapsed" Margin="0,10,0,0" Padding="12,10" CornerRadius="4"
            BorderThickness="1" Background="{DynamicResource SelBg}" BorderBrush="{DynamicResource BorderStrong}">
      <StackPanel>
        <TextBlock x:Name="NewFolderLabel" Style="{StaticResource Lbl}" Margin="0,0,0,5" TextTrimming="CharacterEllipsis"/>
        <DockPanel>
          <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" Margin="6,0,0,0">
            <Button x:Name="NewFolderCancel" Style="{StaticResource Btn}" Content="Cancel" Margin="0,0,6,0"/>
            <Button x:Name="NewFolderCreate" Style="{StaticResource PrimaryBtn}" Content="Create"/>
          </StackPanel>
          <TextBox x:Name="NewFolderName"/>
        </DockPanel>
        <TextBlock x:Name="NewFolderError" Foreground="{DynamicResource Danger}" TextWrapping="Wrap" Margin="0,6,0,0" Visibility="Collapsed"/>
      </StackPanel>
    </Border>
    <DockPanel Grid.Row="3" Margin="0,12,0,0">
      <Button x:Name="NewFolderBtn" DockPanel.Dock="Left" Style="{StaticResource Btn}" Margin="0,0,12,0" IsEnabled="False"
              Visibility="Collapsed" ToolTip="Create a folder inside the selected folder">
        <TextBlock><Run Text="+" FontWeight="Bold"/><Run Text="  New folder"/></TextBlock>
      </Button>
      <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
        <Button x:Name="CancelBtn" Style="{StaticResource Btn}" Content="Cancel" Margin="0,0,8,0" IsCancel="True"/>
        <Button x:Name="SelectBtn" Style="{StaticResource PrimaryBtn}" Content="Use this folder" IsEnabled="False"/>
      </StackPanel>
      <TextBlock x:Name="SelPath" FontFamily="{StaticResource Mono}" FontSize="12" Foreground="{DynamicResource Muted}"
                 VerticalAlignment="Center" TextTrimming="CharacterEllipsis" Margin="0,0,12,0"/>
    </DockPanel>
  </Grid>
</Window>
'@

#endregion

#region Background work

# Anything that can block on the network (listing a folder on a slow server) runs here. The
# workers return plain data; only the UI thread touches controls.
$script:BgPool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, 3)
$script:BgPool.Open()
$script:BgTasks = [System.Collections.Generic.List[object]]::new()

function Start-BgTask {
    param([scriptblock]$Work, [object[]]$ArgumentList, [scriptblock]$OnDone, $State)
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.RunspacePool = $script:BgPool
    [void]$ps.AddScript($Work.ToString())
    foreach ($a in $ArgumentList) { [void]$ps.AddArgument($a) }
    $script:BgTasks.Add([PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke(); OnDone = $OnDone; State = $State })
}

function Update-BgTasks {
    foreach ($t in @($script:BgTasks)) {
        if (-not $t.Handle.IsCompleted) { continue }
        [void]$script:BgTasks.Remove($t)
        try {
            $out = $t.PS.EndInvoke($t.Handle)
            $result = $null
            if ($out.Count -gt 0) { $result = $out[0] }
            & $t.OnDone $result $t.State
        }
        catch { Write-GuiError "Background task: $($_.Exception.Message)" }
        finally { $t.PS.Dispose() }
    }
}

$script:ListFoldersWork = {
    param([string]$Path)
    try {
        $names = @([System.IO.Directory]::GetDirectories($Path) | ForEach-Object { [System.IO.Path]::GetFileName($_) } | Sort-Object)
        [PSCustomObject]@{ Ok = $true; Names = $names; Error = $null }
    }
    catch {
        $e = $_.Exception
        while ($e.InnerException) { $e = $e.InnerException }
        [PSCustomObject]@{ Ok = $false; Names = @(); Error = $e.Message }
    }
}

#endregion

#region UI state and helpers

$script:Jobs = [System.Collections.Generic.List[object]]::new()
$script:Tailers = @{}
$script:Rates = @{}
$script:Cards = @{}
$script:Reattached = @{}
$script:LastAliveCheck = @{}
$script:SelectedId = $null
$script:ShownLogVersion = -1
$script:QueueRunning = $false
$script:Preview = $null
$script:PreviewResult = $null
$script:SettingsPath = Join-Path $script:StateDir 'settings.json'
$script:Settings = [PSCustomObject]@{ theme = 'dark'; queueMode = 'sequential' }
$script:DriveMap = Get-MappedDriveTable
$script:UI = @{}
$script:Dot = " $([char]0xB7) "

$script:PresetNames = @{ full = 'Full Migration'; incremental = 'Incremental'; dataonly = 'Data Only'; mirror = 'Mirror' }

function Get-StatusVisual {
    param([string]$Status)
    switch ($Status) {
        'Waiting'     { @{ Bg = 'PillMutedBg'; Fg = 'Muted';  Text = 'Waiting' } }
        'Running'     { @{ Bg = 'PillRunBg';   Fg = 'Accent'; Text = "$([char]0x25B6) Running" } }
        'Done'        { @{ Bg = 'PillOkBg';    Fg = 'Ok';     Text = "$([char]0x2713) Done" } }
        'Warnings'    { @{ Bg = 'PillWarnBg';  Fg = 'Warn';   Text = "$([char]0x26A0) Check" } }
        'Problems'    { @{ Bg = 'PillWarnBg';  Fg = 'Warn';   Text = "$([char]0x26A0) Finished with problems" } }
        'Failed'      { @{ Bg = 'PillBadBg';   Fg = 'Danger'; Text = "$([char]0x2715) Failed" } }
        'Stopped'     { @{ Bg = 'PillMutedBg'; Fg = 'Muted';  Text = "$([char]0x25A0) Stopped" } }
        'Interrupted' { @{ Bg = 'PillBadBg';   Fg = 'Danger'; Text = 'Interrupted' } }
        default       { @{ Bg = 'PillMutedBg'; Fg = 'Muted';  Text = $Status } }
    }
}

function Set-Res {
    # Points a property at a theme brush so it follows the theme toggle.
    param($Element, $Property, [string]$Key)
    $Element.SetResourceReference($Property, $Key)
}

function Set-Bar {
    param($FillCol, $RestCol, [double]$Fraction)
    if ($Fraction -lt 0) { $Fraction = 0 }
    if ($Fraction -gt 1) { $Fraction = 1 }
    $FillCol.Width = [System.Windows.GridLength]::new($Fraction, 'Star')
    $RestCol.Width = [System.Windows.GridLength]::new(1 - $Fraction, 'Star')
}

function Show-Banner {
    param([string]$Text)
    $script:UI.BannerText.Text = $Text
    $script:UI.Banner.Visibility = 'Visible'
}

function Save-All {
    try { Save-JobStore -Jobs $script:Jobs.ToArray() -Path $script:JobStorePath }
    catch {
        Write-GuiError "Save jobs: $($_.Exception.Message)"
        Show-Banner "Could not save the job list: $($_.Exception.Message)"
    }
}

function Save-Settings {
    try {
        if (-not (Test-Path -LiteralPath $script:StateDir)) { New-Item -ItemType Directory -Path $script:StateDir -Force | Out-Null }
        $script:Settings | ConvertTo-Json | Set-Content -LiteralPath $script:SettingsPath -Encoding UTF8
    }
    catch { Write-GuiError "Save settings: $($_.Exception.Message)" }
}

function Get-Job {
    param([string]$Id)
    foreach ($j in $script:Jobs) { if ($j.id -eq $Id) { return $j } }
    return $null
}

function Get-JobTailerCached {
    param($Job)
    if (-not $Job.logPath) { return $null }
    $tl = $script:Tailers[$Job.id]
    if (-not $tl) {
        $tl = New-JobTailer -Job $Job
        $script:Tailers[$Job.id] = $tl
    }
    return $tl
}

function Get-JobProgress {
    # Returns processed bytes, total, fraction (or -1 when unknown) and seconds left (or -1).
    param($Job, $Tailer)
    $r = [PSCustomObject]@{ Processed = 0L; Total = 0L; Fraction = -1.0; SecondsLeft = -1.0 }
    if ($Tailer) { $r.Processed = $Tailer.BytesProcessed }
    if ($Job.preview -and [long]$Job.preview.Bytes -gt 0) {
        $r.Total = [long]$Job.preview.Bytes
        $r.Fraction = [Math]::Min(0.999, $r.Processed / [double]$r.Total)
        $r.SecondsLeft = Get-SecondsLeft -TotalBytes $r.Total -ProcessedBytes $r.Processed -Samples $script:Rates[$Job.id]
    }
    return $r
}

function Add-RateSample {
    # Time left uses the rate over the last ~60 seconds, so it doesn't swing on every file.
    param($Job, $Tailer)
    $q = $script:Rates[$Job.id]
    if (-not $q) { $q = [System.Collections.Generic.List[object]]::new(); $script:Rates[$Job.id] = $q }
    $now = Get-Date
    $q.Add([PSCustomObject]@{ T = $now; B = $Tailer.BytesProcessed })
    while ($q.Count -gt 2 -and ($now - $q[0].T).TotalSeconds -gt 60) { $q.RemoveAt(0) }
}

function Format-JobTime {
    param($Value)
    $d = ConvertTo-LocalDate $Value
    if ($d) { return $d.ToString('yyyy-MM-dd HH:mm') }
    return ''
}

#endregion

#region Queue cards

function New-JobCard {
    param($Job)
    $card = [System.Windows.Markup.XamlReader]::Parse($script:CardXaml)
    $refs = @{ Root = $card }
    foreach ($n in 'Pill', 'PillText', 'Name', 'Sub', 'Bar', 'BarFill', 'BarRest') { $refs[$n] = $card.FindName($n) }
    $card.Tag = $Job.id
    $card.Add_MouseLeftButtonUp({ param($s, $e) Select-Job $s.Tag })
    $script:Cards[$Job.id] = $refs
    return $refs
}

function Update-JobCard {
    param($Job)
    $c = $script:Cards[$Job.id]
    if (-not $c) { return }
    $v = Get-StatusVisual $Job.status
    $c.Name.Text = $Job.name
    Set-Res $c.Pill ([System.Windows.Controls.Border]::BackgroundProperty) $v.Bg
    Set-Res $c.PillText ([System.Windows.Controls.TextBlock]::ForegroundProperty) $v.Fg
    $c.PillText.Text = $v.Text
    $preset = $script:PresetNames[[string]$Job.preset]

    $c.Bar.Visibility = 'Collapsed'
    switch ($Job.status) {
        'Waiting' {
            if ($Job.preview) { $c.Sub.Text = $preset + $script:Dot + (Format-Bytes $Job.preview.Bytes) + $script:Dot + ('{0:N0} files' -f [long]$Job.preview.Files) }
            else { $c.Sub.Text = $preset + $script:Dot + 'not previewed' }
        }
        'Running' {
            $tl = $script:Tailers[$Job.id]
            $p = Get-JobProgress -Job $Job -Tailer $tl
            $prefix = ''
            if ($script:Reattached[$Job.id]) { $prefix = 'Reattached' + $script:Dot }
            if ($p.Fraction -ge 0) {
                $c.PillText.Text = "$([char]0x25B6) {0:N0}%" -f [Math]::Floor($p.Fraction * 100)
                $left = ''
                if ($p.SecondsLeft -ge 0) { $left = $script:Dot + '~' + (Format-Duration $p.SecondsLeft) + ' left' }
                $c.Sub.Text = $prefix + (Format-Bytes $p.Processed) + ' of ' + (Format-Bytes $p.Total) + $left
                $c.Bar.Visibility = 'Visible'
                Set-Bar $c.BarFill $c.BarRest $p.Fraction
            }
            else {
                $files = 0
                if ($tl) { $files = $tl.FilesCopied }
                $c.Sub.Text = $prefix + ('{0:N0} files copied' -f $files) + $script:Dot + (Format-Bytes $p.Processed)
            }
        }
        default {
            $when = Format-JobTime $Job.finishedAt
            if ($Job.summary) { $c.Sub.Text = 'Finished ' + $when + $script:Dot + ('{0:N0} files copied' -f [long]$Job.summary.files[1]) }
            elseif ($when) { $c.Sub.Text = $Job.status + ' ' + $when }
            else { $c.Sub.Text = $preset }
        }
    }

    if ($Job.id -eq $script:SelectedId) {
        Set-Res $c.Root ([System.Windows.Controls.Border]::BorderBrushProperty) 'Accent'
        $c.Root.BorderThickness = [System.Windows.Thickness]::new(3, 1, 1, 1)
    }
    else {
        Set-Res $c.Root ([System.Windows.Controls.Border]::BorderBrushProperty) 'Border'
        $c.Root.BorderThickness = [System.Windows.Thickness]::new(1)
    }
}

function Update-QueueView {
    $panel = $script:UI.QueuePanel
    # Remove cards for jobs that are gone.
    foreach ($id in @($script:Cards.Keys)) {
        if (-not (Get-Job $id)) {
            $panel.Children.Remove($script:Cards[$id].Root)
            $script:Cards.Remove($id)
        }
    }
    # Add new cards in list order.
    for ($i = 0; $i -lt $script:Jobs.Count; $i++) {
        $j = $script:Jobs[$i]
        if (-not $script:Cards.ContainsKey($j.id)) {
            $refs = New-JobCard $j
            $panel.Children.Insert([Math]::Min($i, $panel.Children.Count), $refs.Root)
        }
        Update-JobCard $j
    }
    $n = $script:Jobs.Count
    if ($n -eq 0) { $script:UI.QueueEmpty.Visibility = 'Visible' } else { $script:UI.QueueEmpty.Visibility = 'Collapsed' }
    $running = @($script:Jobs | Where-Object { $_.status -eq 'Running' }).Count
    $waiting = @($script:Jobs | Where-Object { $_.status -eq 'Waiting' }).Count
    $script:UI.JobCount.Text = "$n total$($script:Dot)$running running$($script:Dot)$waiting waiting"
    Update-QueueBar -Waiting $waiting -Running $running
}

function Update-QueueBar {
    param([int]$Waiting, [int]$Running)
    $ui = $script:UI
    if ($Waiting -eq 0) {
        $ui.QueueBar.Visibility = 'Collapsed'
        return
    }
    $ui.QueueBar.Visibility = 'Visible'
    if ($script:QueueRunning) {
        $ui.QueueBtn.Content = "$([char]0x275A)$([char]0x275A)  Pause queue"
        $mode = 'one at a time'
        if ($script:Settings.queueMode -eq 'parallel') { $mode = 'all at once' }
        $ui.QueueText.Text = "Queue is running ($mode). $Waiting waiting."
    }
    else {
        $ui.QueueBtn.Content = "$([char]0x25B6)  Start queue"
        $ui.QueueText.Text = "$Waiting job(s) waiting. Nothing starts until you start the queue."
    }
}

#endregion

#region Detail pane

function Select-Job {
    param([string]$Id)
    $script:SelectedId = $Id
    $script:ShownLogVersion = -1
    foreach ($j in $script:Jobs) { Update-JobCard $j }
    Show-JobDetail
}

function Show-JobDetail {
    $ui = $script:UI
    $job = $null
    if ($script:SelectedId) { $job = Get-Job $script:SelectedId }
    if (-not $job) {
        $ui.DetailView.Visibility = 'Collapsed'
        $ui.DetailEmpty.Visibility = 'Visible'
        return
    }
    $ui.DetailEmpty.Visibility = 'Collapsed'
    $ui.DetailView.Visibility = 'Visible'

    $ui.DetailName.Text = $job.name
    $v = Get-StatusVisual $job.status
    Set-Res $ui.DetailPill ([System.Windows.Controls.Border]::BackgroundProperty) $v.Bg
    Set-Res $ui.DetailPillText ([System.Windows.Controls.TextBlock]::ForegroundProperty) $v.Fg
    $ui.DetailPillText.Text = $v.Text
    $ui.DetailPaths.Text = "$($job.source)  $($script:Arrow)  $($job.destination)"
    $meta = @($script:PresetNames[[string]$job.preset])
    if ($job.startedAt) { $meta += 'Started ' + (Format-JobTime $job.startedAt) }
    if ($job.finishedAt) {
        $meta += 'Finished ' + (Format-JobTime $job.finishedAt)
        $s = ConvertTo-LocalDate $job.startedAt; $f = ConvertTo-LocalDate $job.finishedAt
        if ($s -and $f) { $meta += 'took ' + (Format-Duration ($f - $s).TotalSeconds) }
    }
    if ($script:Reattached[$job.id] -and $job.status -eq 'Running') { $meta += 'Reattached after the tool was reopened' }
    $ui.DetailMeta.Text = $meta -join $script:Dot

    $isRunning = $job.status -eq 'Running'
    $isWaiting = $job.status -eq 'Waiting'
    $isFinished = -not $isRunning -and -not $isWaiting

    $ui.ProgressSection.Visibility = if ($isRunning) { 'Visible' } else { 'Collapsed' }
    $ui.FinishedSection.Visibility = if ($isFinished) { 'Visible' } else { 'Collapsed' }
    $ui.StartBtn.Visibility = if ($isWaiting) { 'Visible' } else { 'Collapsed' }
    $ui.StopBtn.Visibility = if ($isRunning) { 'Visible' } else { 'Collapsed' }
    $ui.RerunBtn.Visibility = if ($isFinished) { 'Visible' } else { 'Collapsed' }
    $ui.RemoveBtn.Visibility = if ($isRunning) { 'Collapsed' } else { 'Visible' }
    $ui.OpenLogBtn.IsEnabled = [bool]$job.logPath
    $ui.OpenDestBtn.Visibility = if ($isWaiting) { 'Collapsed' } else { 'Visible' }
    $ui.OpenLogBtn.Visibility = if ($isWaiting) { 'Collapsed' } else { 'Visible' }

    if ($isFinished) { Show-FinishedDetail $job }
    Update-JobDetailLive
}

function Show-FinishedDetail {
    param($Job)
    $ui = $script:UI
    switch ($Job.status) {
        'Done'        { $bg = 'PillOkBg'; $bd = 'Ok' }
        'Warnings'    { $bg = 'BannerBg'; $bd = 'BannerBorder' }
        'Problems'    { $bg = 'BannerBg'; $bd = 'BannerBorder' }
        'Stopped'     { $bg = 'Card'; $bd = 'BorderStrong' }
        default       { $bg = 'PillBadBg'; $bd = 'Danger' }
    }
    Set-Res $ui.VerdictBox ([System.Windows.Controls.Border]::BackgroundProperty) $bg
    Set-Res $ui.VerdictBox ([System.Windows.Controls.Border]::BorderBrushProperty) $bd
    $v = Get-StatusVisual $Job.status
    Set-Res $ui.VerdictHeadline ([System.Windows.Controls.TextBlock]::ForegroundProperty) $v.Fg
    $ui.VerdictHeadline.Text = [string]$Job.headline
    $ui.VerdictDetails.Text = (@($Job.details) | ForEach-Object { "$([char]0x2022) $_" }) -join "`n"
    $tip = [string]$Job.tip
    if ($null -ne $Job.exitCode -and $Job.exitCode -ne '') {
        $codeText = "Robocopy exit code $($Job.exitCode)."
        if ($tip) { $tip = "$codeText Tip: $tip" } else { $tip = $codeText }
    }
    $ui.VerdictTip.Text = $tip
    $ui.VerdictTip.Visibility = if ($tip) { 'Visible' } else { 'Collapsed' }

    Build-SummaryGrid $Job

    $failed = @($Job.failedFiles)
    if ($failed.Count -gt 0) {
        $ui.FailedSection.Visibility = 'Visible'
        $more = ''
        if ($Job.summary -and [long]$Job.summary.files[4] -gt $failed.Count) { $more = " (first $($failed.Count) of $('{0:N0}' -f [long]$Job.summary.files[4]) - the log has the rest)" }
        $ui.FailedLabel.Text = "FILES THAT COULD NOT BE COPIED$more"
        $ui.FailedBox.Text = $failed -join "`r`n"
    }
    else { $ui.FailedSection.Visibility = 'Collapsed' }
}

function Build-SummaryGrid {
    param($Job)
    $g = $script:UI.SummaryGrid
    $g.Children.Clear()
    $g.RowDefinitions.Clear()
    $g.ColumnDefinitions.Clear()
    if (-not $Job.summary) { $g.Visibility = 'Collapsed'; return }
    $g.Visibility = 'Visible'
    $cols = @('', 'Total', 'Copied', 'Skipped', 'Mismatch', 'Failed', 'Extra at dest')
    for ($c = 0; $c -lt $cols.Count; $c++) {
        $cd = [System.Windows.Controls.ColumnDefinition]::new()
        if ($c -eq 0) { $cd.Width = [System.Windows.GridLength]::new(70) } else { $cd.Width = [System.Windows.GridLength]::new(1, 'Star') }
        $g.ColumnDefinitions.Add($cd)
    }
    $rows = @(
        @{ Label = 'Folders'; V = $Job.summary.dirs; Bytes = $false }
        @{ Label = 'Files'; V = $Job.summary.files; Bytes = $false }
        @{ Label = 'Size'; V = $Job.summary.bytes; Bytes = $true }
    )
    for ($r = 0; $r -le $rows.Count; $r++) { $g.RowDefinitions.Add([System.Windows.Controls.RowDefinition]::new()) }

    $add = {
        param([int]$Row, [int]$Col, [string]$Text, [string]$Fg, [bool]$Bold, [bool]$Right)
        $tb = [System.Windows.Controls.TextBlock]::new()
        $tb.Text = $Text
        $tb.Margin = [System.Windows.Thickness]::new(4, 3, 4, 3)
        if ($Right) { $tb.HorizontalAlignment = 'Right' }
        if ($Bold) { $tb.FontWeight = 'SemiBold' }
        if ($Row -gt 0 -and $Col -gt 0) { $tb.SetResourceReference([System.Windows.Controls.TextBlock]::FontFamilyProperty, 'Mono'); $tb.FontSize = 12 }
        if ($Row -eq 0) { $tb.FontSize = 11 }
        $tb.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, $Fg)
        [System.Windows.Controls.Grid]::SetRow($tb, $Row)
        [System.Windows.Controls.Grid]::SetColumn($tb, $Col)
        [void]$g.Children.Add($tb)
    }
    for ($c = 1; $c -lt $cols.Count; $c++) { & $add 0 $c $cols[$c] 'Muted' $true $true }
    for ($r = 0; $r -lt $rows.Count; $r++) {
        $row = $rows[$r]
        & $add ($r + 1) 0 $row.Label 'Muted' $true $false
        for ($c = 0; $c -lt 6; $c++) {
            $val = [long]$row.V[$c]
            if ($row.Bytes) { $text = Format-Bytes $val } else { $text = '{0:N0}' -f $val }
            $fg = 'TextStrong'
            if ($c -eq 4 -and $val -gt 0) { $fg = 'Danger' }
            & $add ($r + 1) ($c + 1) $text $fg ($c -eq 4 -and $val -gt 0) $true
        }
    }
}

function Update-JobDetailLive {
    $ui = $script:UI
    if (-not $script:SelectedId) { return }
    $job = Get-Job $script:SelectedId
    if (-not $job) { return }
    $tl = $script:Tailers[$job.id]

    if ($job.status -eq 'Running') {
        $p = Get-JobProgress -Job $job -Tailer $tl
        if ($p.Fraction -ge 0) {
            Set-Bar $ui.ProgFill $ui.ProgRest $p.Fraction
            $ui.ProgPercent.Text = '{0:N1}%' -f ($p.Fraction * 100)
        }
        else {
            Set-Bar $ui.ProgFill $ui.ProgRest 0
            $ui.ProgPercent.Text = 'No preview - % unknown'
        }
        $ui.ProgFile.Text = ''
        if ($tl -and $tl.CurrentFile) { $ui.ProgFile.Text = $tl.CurrentFile }
        if ($tl -and -not $tl.CaughtUp) { $ui.ProgFile.Text = 'Catching up on the log...' }

        $files = 0; $failed = 0
        if ($tl) { $files = $tl.FilesCopied; $failed = $tl.FilesFailed }
        $ui.Stat1.Text = '{0:N0}' -f $files; $ui.Stat1L.Text = 'files copied'
        if ($p.Total -gt 0) { $ui.Stat2.Text = Format-Bytes $p.Processed; $ui.Stat2L.Text = 'done of ' + (Format-Bytes $p.Total) }
        else { $ui.Stat2.Text = Format-Bytes $p.Processed; $ui.Stat2L.Text = 'processed' }
        $ui.Stat3.Text = '{0:N0}' -f $failed; $ui.Stat3L.Text = 'could not be copied'
        Set-Res $ui.Stat3 ([System.Windows.Controls.TextBlock]::ForegroundProperty) $(if ($failed -gt 0) { 'Danger' } else { 'TextStrong' })
        if ($p.SecondsLeft -ge 0) { $ui.Stat4.Text = '~' + (Format-Duration $p.SecondsLeft); $ui.Stat4L.Text = 'left (at the current speed)' }
        else {
            $s = ConvertTo-LocalDate $job.startedAt
            $ui.Stat4.Text = if ($s) { Format-Duration ((Get-Date) - $s).TotalSeconds } else { '-' }
            $ui.Stat4L.Text = 'running for'
        }
        $ui.StatsSection.Visibility = 'Visible'
    }
    elseif ($job.status -eq 'Waiting') {
        if ($job.preview) {
            $ui.Stat1.Text = '{0:N0}' -f [long]$job.preview.Files; $ui.Stat1L.Text = 'files to check'
            $ui.Stat2.Text = Format-Bytes $job.preview.Bytes; $ui.Stat2L.Text = 'total size'
            $ui.Stat3.Text = '{0:N0}' -f [long]$job.preview.Dirs; $ui.Stat3L.Text = 'folders'
            Set-Res $ui.Stat3 ([System.Windows.Controls.TextBlock]::ForegroundProperty) 'TextStrong'
            $ui.Stat4.Text = ''; $ui.Stat4L.Text = ''
            $ui.StatsSection.Visibility = 'Visible'
        }
        else { $ui.StatsSection.Visibility = 'Collapsed' }
    }
    else {
        $ui.StatsSection.Visibility = 'Collapsed'
    }

    # Log tail: only redraw when the reader has seen new lines.
    if ($tl) {
        $ui.LogLabel.Visibility = 'Visible'; $ui.LogBox.Visibility = 'Visible'
        if ($tl.Version -ne $script:ShownLogVersion) {
            $box = $ui.LogBox
            $atBottom = ($box.VerticalOffset + $box.ViewportHeight) -ge ($box.ExtentHeight - 4)
            $box.Text = $tl.GetTail()
            if ($atBottom -or $script:ShownLogVersion -eq -1) { $box.ScrollToEnd() }
            $script:ShownLogVersion = $tl.Version
        }
    }
    elseif ($job.status -eq 'Waiting') {
        $ui.LogLabel.Visibility = 'Collapsed'; $ui.LogBox.Visibility = 'Collapsed'
    }
    else {
        $ui.LogLabel.Visibility = 'Visible'; $ui.LogBox.Visibility = 'Visible'
        $ui.LogBox.Text = 'The full log is in the log file - click "Open log".'
    }
}

#endregion

#region Job actions

function Start-JobNow {
    param($Job)
    try {
        Start-MigrationJob -Job $Job -StateDir $script:StateDir -DefaultLogDir $script:DefaultLogDir -DriveMap $script:DriveMap
        $script:Tailers.Remove($Job.id)
        $script:Rates.Remove($Job.id)
        $script:Reattached.Remove($Job.id)
        [void](Get-JobTailerCached $Job)
    }
    catch {
        $Job.status = 'Failed'
        $Job.finishedAt = (Get-Date).ToString('o')
        $Job.headline = 'The copy could not be started.'
        $Job.details = @($_.Exception.Message)
        $Job.tip = 'Check the log folder is reachable and that this account can write to it.'
        Write-GuiError "Start $($Job.id): $($_.Exception.Message)"
    }
    Save-All
    Update-QueueView
    if ($Job.id -eq $script:SelectedId) { Show-JobDetail }
}

function Stop-JobNow {
    param($Job)
    $answer = [System.Windows.MessageBox]::Show("Stop copying $($Job.name)?`n`nFiles copied so far are kept. You can finish later with Run again as Incremental.", 'Stop this copy?', 'YesNo', 'Question')
    if ($answer -ne 'Yes') { return }
    $tl = $script:Tailers[$Job.id]
    if ($tl) { try { [void]$tl.Poll(16MB) } catch { } }
    Stop-MigrationJob -Job $Job
    Save-All
    Update-QueueView
    Show-JobDetail
}

function Invoke-RerunIncremental {
    param($Job)
    $opts = $Job.options | ConvertTo-Json -Depth 4 | ConvertFrom-Json
    $preview = $Job.preview
    if (-not $preview -and $Job.summary) {
        $preview = [PSCustomObject]@{ Dirs = [long]$Job.summary.dirs[0]; Files = [long]$Job.summary.files[0]; Bytes = [long]$Job.summary.bytes[0] }
    }
    $new = New-MigrationJob -Source $Job.source -Destination $Job.destination -Preset incremental -Options $opts -Preview $preview
    $script:Jobs.Add($new)
    Start-JobNow $new
    Select-Job $new.id
}

function Remove-JobFromList {
    param($Job)
    if ($Job.status -eq 'Running') { return }
    [void]$script:Jobs.Remove($Job)
    $script:Tailers.Remove($Job.id)
    $script:Rates.Remove($Job.id)
    if ($script:SelectedId -eq $Job.id) { $script:SelectedId = $null }
    Save-All
    Update-QueueView
    Show-JobDetail
}

function Open-JobDestination {
    param($Job)
    $path = Resolve-MappedDrive -Path $Job.destination -Map $script:DriveMap
    if (Test-Path -LiteralPath $path) { Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$path`"" }
    else { [System.Windows.MessageBox]::Show("The destination folder doesn't exist yet:`n$path", 'Open destination', 'OK', 'Information') | Out-Null }
}

#endregion

#region New Job panel

function Open-NewJobPanel {
    $ui = $script:UI
    $ui.FormError.Visibility = 'Collapsed'
    $ui.LogDirHint.Text = "Leave blank to use $($script:DefaultLogDir). Enter a folder, or a full path ending in .log."
    Reset-PreviewView
    $ui.Overlay.Visibility = 'Visible'
    $anim = [System.Windows.Media.Animation.DoubleAnimation]::new(500, 0, [System.Windows.Duration]::new([TimeSpan]::FromMilliseconds(180)))
    $ease = [System.Windows.Media.Animation.CubicEase]::new()
    $ease.EasingMode = 'EaseOut'
    $anim.EasingFunction = $ease
    $ui.PanelSlide.BeginAnimation([System.Windows.Media.TranslateTransform]::XProperty, $anim)
    [void]$ui.SrcBox.Focus()
}

function Close-NewJobPanel {
    Stop-PreviewNow
    $script:UI.Overlay.Visibility = 'Collapsed'
}

function Reset-NewJobForm {
    $ui = $script:UI
    $ui.SrcBox.Text = ''; $ui.DstBox.Text = ''
    $ui.PresetFull.IsChecked = $true
    $script:PreviewResult = $null
}

function Get-FormPreset {
    $ui = $script:UI
    if ($ui.PresetIncr.IsChecked) { return 'incremental' }
    if ($ui.PresetData.IsChecked) { return 'dataonly' }
    if ($ui.PresetMirror.IsChecked) { return 'mirror' }
    return 'full'
}

function Read-FormInt {
    param($Box, [string]$Label, [int]$Min, [int]$Max)
    $v = 0
    if (-not [int]::TryParse($Box.Text.Trim(), [ref]$v) -or $v -lt $Min -or $v -gt $Max) {
        throw "$Label must be a whole number from $Min to $Max."
    }
    return $v
}

function Get-FormOptions {
    $ui = $script:UI
    $threads = 0
    if ($ui.MtCheck.IsChecked) { $threads = Read-FormInt $ui.MtBox 'Threads' 1 128 }
    $bk = ''
    if ($ui.BkZb.IsChecked) { $bk = 'zb' } elseif ($ui.BkB.IsChecked) { $bk = 'b' }
    return New-JobOptions -Retries (Read-FormInt $ui.RetriesBox 'Retries' 0 99) -WaitSeconds (Read-FormInt $ui.WaitBox 'Wait between retries' 0 300) `
        -Threads $threads -InterPacketGap (Read-FormInt $ui.IpgBox 'Slow down' 0 999999) -BackupMode $bk `
        -ExcludeFiles $ui.XfBox.Text.Trim() -ExcludeDirs $ui.XdBox.Text.Trim() -LogFolder $ui.LogDirBox.Text.Trim()
}

function Get-PreviewKey {
    param([string]$Source, [string]$Destination, [string]$Preset, $Options)
    return ($Source, $Destination, $Preset, $Options.excludeFiles, $Options.excludeDirs) -join '|'
}

function Reset-PreviewView {
    $ui = $script:UI
    if ($script:PreviewResult) { return }
    $ui.PreviewBtn.Content = "$([char]::ConvertFromUtf32(0x1F50D))  Preview"
    $ui.PreviewText.Text = 'Not scanned yet.'
    $ui.PreviewHint.Text = 'Preview counts the files and size without copying anything. It gives the job a % bar and time left. Optional, but recommended.'
}

function Show-FormError {
    param([string]$Text)
    $script:UI.FormError.Text = $Text
    $script:UI.FormError.Visibility = if ($Text) { 'Visible' } else { 'Collapsed' }
}

function Start-PreviewNow {
    $ui = $script:UI
    if ($script:Preview) { Stop-PreviewNow; return }
    Show-FormError ''
    $src = $ui.SrcBox.Text.Trim()
    if (-not $src) { Show-FormError 'Enter the folder to copy from first.'; return }
    try { $opts = Get-FormOptions } catch { Show-FormError $_.Exception.Message; return }
    $preset = Get-FormPreset
    $rSrc = Resolve-MappedDrive -Path $src -Map $script:DriveMap
    $rDst = Resolve-MappedDrive -Path $ui.DstBox.Text.Trim() -Map $script:DriveMap
    try {
        $p = Start-RoboPreview -Source $rSrc -Destination $rDst -Preset $preset -Options $opts
        $p | Add-Member -NotePropertyName Key -NotePropertyValue (Get-PreviewKey $src $ui.DstBox.Text.Trim() $preset $opts)
        $script:Preview = $p
        $script:PreviewResult = $null
        $ui.PreviewBtn.Content = "$([char]0x2715)  Cancel preview"
        $ui.PreviewText.Text = 'Scanning...'
        $ui.PreviewHint.Text = 'You can keep editing, or add the job now - the result is attached if the paths and type of copy are unchanged.'
    }
    catch { Show-FormError "Could not start the preview: $($_.Exception.Message)" }
}

function Stop-PreviewNow {
    if ($script:Preview) {
        try { if (-not $script:Preview.Process.HasExited) { $script:Preview.Process.Kill() } } catch { }
        $script:Preview = $null
        $script:PreviewResult = $null
        Reset-PreviewView
        $script:UI.PreviewText.Text = 'Preview cancelled.'
    }
}

function Update-Preview {
    $p = $script:Preview
    if (-not $p) { return }
    $ui = $script:UI
    $elapsed = ((Get-Date) - $p.StartedAt).TotalSeconds
    if (-not ($p.Process.HasExited -and $p.Output.IsCompleted)) {
        $ui.PreviewText.Text = "Scanning... $(Format-Duration $elapsed)"
        return
    }
    $script:Preview = $null
    $ui.PreviewBtn.Content = "$([char]::ConvertFromUtf32(0x1F50D))  Preview again"
    $summary = $null
    try { $summary = Read-RoboSummary -Text $p.Output.Result } catch { }
    if ($summary) {
        $script:PreviewResult = [PSCustomObject]@{ Key = $p.Key; Dirs = $summary.Dirs; Files = $summary.Files; Bytes = $summary.Bytes }
        $ui.PreviewText.Text = ('{0:N0} files{1}{2:N0} folders{1}{3}' -f $summary.Files, $script:Dot, $summary.Dirs, (Format-Bytes $summary.Bytes))
        $ui.PreviewHint.Text = "Scanned in $(Format-Duration $elapsed). These totals drive the % bar and time left."
    }
    else {
        $script:PreviewResult = $null
        $ui.PreviewText.Text = "Couldn't scan the source folder."
        $ui.PreviewHint.Text = "Check the path exists and this account can open it. You can still add the job; it just won't show a % bar."
    }
}

function Add-JobFromForm {
    param([bool]$StartNow)
    $ui = $script:UI
    Show-FormError ''
    $src = $ui.SrcBox.Text.Trim()
    $dst = $ui.DstBox.Text.Trim()
    if (-not $src -or -not $dst) { Show-FormError 'Enter both "Copy from" and "Copy to".'; return }
    if ((ConvertTo-RoboPath $src) -eq (ConvertTo-RoboPath $dst)) { Show-FormError '"Copy from" and "Copy to" are the same folder.'; return }
    try { $opts = Get-FormOptions } catch { Show-FormError $_.Exception.Message; return }
    $preset = Get-FormPreset
    if ($preset -eq 'mirror') {
        $answer = [System.Windows.MessageBox]::Show("Mirror makes the destination an exact copy of the source.`n`nFiles in`n$dst`nthat aren't in the source will be DELETED.`n`nContinue?", 'Mirror deletes files', 'YesNo', 'Warning')
        if ($answer -ne 'Yes') { return }
    }
    $preview = $null
    if ($script:PreviewResult -and $script:PreviewResult.Key -eq (Get-PreviewKey $src $dst $preset $opts)) {
        $preview = [PSCustomObject]@{ Dirs = $script:PreviewResult.Dirs; Files = $script:PreviewResult.Files; Bytes = $script:PreviewResult.Bytes }
    }
    $job = New-MigrationJob -Source $src -Destination $dst -Preset $preset -Options $opts -Preview $preview
    $script:Jobs.Add($job)
    Save-All
    Close-NewJobPanel
    Reset-NewJobForm
    Update-QueueView
    Select-Job $job.id
    if ($StartNow) {
        $running = @($script:Jobs | Where-Object { $_.status -eq 'Running' }).Count
        if ($script:Settings.queueMode -eq 'parallel' -or $running -eq 0) { Start-JobNow $job }
        $script:QueueRunning = $true
        Update-QueueView
    }
}

#endregion

#region Browse dialog

function Add-BrowseNode {
    param($Parent, [string]$Label, [string]$Path, [string]$Icon, [bool]$Expandable = $true)
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
    $item.Tag = $Path
    $item.SetResourceReference([System.Windows.Controls.Control]::ForegroundProperty, 'Text')
    $item.Padding = [System.Windows.Thickness]::new(2, 3, 2, 3)
    if ($Expandable) { [void]$item.Items.Add('__loading__') }
    [void]$Parent.Items.Add($item)
    return $item
}

function Show-BrowseDialog {
    param([string]$StartPath, [string]$Title, [switch]$AllowNewFolder)
    $dlg = New-ThemedWindow $script:BrowseXaml
    $dlg.Owner = $script:UI.Window
    $dlg.Title = $Title
    $tree = $dlg.FindName('Tree'); $goBox = $dlg.FindName('GoBox'); $goBtn = $dlg.FindName('GoBtn')
    $selBtn = $dlg.FindName('SelectBtn'); $selPath = $dlg.FindName('SelPath')
    $nfBtn = $dlg.FindName('NewFolderBtn'); $nfRow = $dlg.FindName('NewFolderRow'); $nfLabel = $dlg.FindName('NewFolderLabel')
    $nfName = $dlg.FindName('NewFolderName'); $nfCreate = $dlg.FindName('NewFolderCreate'); $nfCancel = $dlg.FindName('NewFolderCancel')
    $nfError = $dlg.FindName('NewFolderError')
    if ($AllowNewFolder) { $nfBtn.Visibility = 'Visible' }
    $state = @{ Result = $null; NewFolderParent = $null }
    $script:BrowsePending = $null
    $folderIcon = [char]::ConvertFromUtf32(0x1F4C1)
    $driveIcon = [string][char]0x25A3

    # Local drives. Network drives are covered by the mapped-drive list (as UNC paths).
    foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
        if ($d.DriveType -in 'Fixed', 'Removable') { [void](Add-BrowseNode $tree "$($d.Name)  ($($d.DriveType))" $d.Name $driveIcon) }
    }
    foreach ($k in ($script:DriveMap.Keys | Sort-Object)) {
        [void](Add-BrowseNode $tree "${k}:  $($script:Arrow)  $($script:DriveMap[$k])" $script:DriveMap[$k] $driveIcon)
    }
    # Shares used by earlier jobs.
    $recent = @($script:Jobs | ForEach-Object { $_.source; $_.destination } | Where-Object { $_ -match '^(\\\\[^\\]+\\[^\\]+)' } |
        ForEach-Object { if ($_ -match '^(\\\\[^\\]+\\[^\\]+)') { $Matches[1] } } | Sort-Object -Unique)
    foreach ($r in $recent) { [void](Add-BrowseNode $tree "$r  (used before)" $r $folderIcon) }

    $loadChildren = {
        param($Item)
        if ($Item.Items.Count -ne 1 -or $Item.Items[0] -isnot [string] -or $Item.Items[0] -ne '__loading__') { return }
        $Item.Items[0] = 'Loading...'
        Start-BgTask -Work $script:ListFoldersWork -ArgumentList @([string]$Item.Tag) -State $Item -OnDone {
            param($result, $node)
            $node.Items.Clear()
            if (-not $result -or -not $result.Ok) {
                $msg = 'Could not open this folder'
                if ($result -and $result.Error) { $msg = $result.Error }
                $err = [System.Windows.Controls.TreeViewItem]::new()
                $err.Header = $msg
                $err.IsEnabled = $false
                $err.SetResourceReference([System.Windows.Controls.Control]::ForegroundProperty, 'Danger')
                [void]$node.Items.Add($err)
                return
            }
            if ($result.Names.Count -eq 0) {
                $empty = [System.Windows.Controls.TreeViewItem]::new()
                $empty.Header = '(no subfolders)'
                $empty.IsEnabled = $false
                $empty.SetResourceReference([System.Windows.Controls.Control]::ForegroundProperty, 'Muted')
                [void]$node.Items.Add($empty)
                return
            }
            foreach ($n in $result.Names) {
                [void](Add-BrowseNode $node $n ([System.IO.Path]::Combine([string]$node.Tag, $n)) ([char]::ConvertFromUtf32(0x1F4C1)))
            }
            # Select a folder that was just created here.
            $pending = $script:BrowsePending
            if ($pending -and $pending.Parent -eq $node) {
                $script:BrowsePending = $null
                foreach ($child in $node.Items) {
                    if ($child -is [System.Windows.Controls.TreeViewItem] -and [string]::Equals([string]$child.Tag, $pending.Path, [StringComparison]::OrdinalIgnoreCase)) {
                        $child.IsSelected = $true
                        $child.BringIntoView()
                        break
                    }
                }
            }
        }
    }
    $script:BrowseLoadChildren = $loadChildren

    $tree.AddHandler([System.Windows.Controls.TreeViewItem]::ExpandedEvent, [System.Windows.RoutedEventHandler]{
            param($s, $e)
            & $loadChildren $e.OriginalSource
        })
    $tree.Add_SelectedItemChanged({
            param($s, $e)
            $item = $s.SelectedItem
            if ($item -is [System.Windows.Controls.TreeViewItem] -and $item.Tag) {
                $selPath.Text = [string]$item.Tag
                $selBtn.IsEnabled = $true
                $nfBtn.IsEnabled = $true
            }
            else { $selBtn.IsEnabled = $false; $nfBtn.IsEnabled = $false }
            if ($nfRow.Visibility -eq 'Visible' -and $item -ne $state.NewFolderParent) { & $hideNewFolder }
        })

    # --- New folder (destination only) ---
    $hideNewFolder = {
        $nfRow.Visibility = 'Collapsed'
        $nfError.Visibility = 'Collapsed'
        $nfCreate.IsEnabled = $true
        $nfCreate.Content = 'Create'
        $state.NewFolderParent = $null
    }
    $showNewFolderError = {
        param([string]$Text)
        $nfError.Text = $Text
        $nfError.Visibility = 'Visible'
        $nfCreate.IsEnabled = $true
        $nfCreate.Content = 'Create'
    }
    $nfBtn.Add_Click({
            $parent = $tree.SelectedItem
            if (-not ($parent -is [System.Windows.Controls.TreeViewItem] -and $parent.Tag)) { return }
            $state.NewFolderParent = $parent
            $nfLabel.Text = "NEW FOLDER IN $([string]$parent.Tag)"
            $nfName.Text = 'New folder'
            $nfError.Visibility = 'Collapsed'
            $nfRow.Visibility = 'Visible'
            [void]$nfName.Focus()
            $nfName.SelectAll()
        })
    $createFolder = {
        $parent = $state.NewFolderParent
        if (-not $parent) { return }
        $name = $nfName.Text.Trim()
        $problem = Test-FolderName $name
        if ($problem) { & $showNewFolderError $problem; return }
        $nfError.Visibility = 'Collapsed'
        $nfCreate.IsEnabled = $false
        $nfCreate.Content = 'Creating...'
        # Created in the background: a slow or offline share must not freeze the dialog.
        Start-BgTask -Work ${function:Invoke-NewFolder} -ArgumentList @([string]$parent.Tag, $name) -State $parent -OnDone {
            param($result, $parentNode)
            if (-not $result -or -not $result.Ok) {
                $msg = 'The folder could not be created.'
                if ($result -and $result.Error) { $msg = $result.Error }
                & $showNewFolderError $msg
                return
            }
            & $hideNewFolder
            # Reload the parent and select the new folder once it is listed.
            $script:BrowsePending = @{ Parent = $parentNode; Path = $result.Path }
            $parentNode.Items.Clear()
            [void]$parentNode.Items.Add('__loading__')
            if ($parentNode.IsExpanded) { & $script:BrowseLoadChildren $parentNode } else { $parentNode.IsExpanded = $true }
        }
    }
    $nfCreate.Add_Click($createFolder)
    $nfCancel.Add_Click($hideNewFolder)
    # PreviewKeyDown so Esc closes only the new-folder row, not the whole dialog.
    $nfName.Add_PreviewKeyDown({
            param($s, $e)
            if ($e.Key -eq 'Return') { & $createFolder; $e.Handled = $true }
            elseif ($e.Key -eq 'Escape') { & $hideNewFolder; $e.Handled = $true }
        })
    $go = {
        $p = $goBox.Text.Trim()
        if (-not $p) { return }
        $p = Resolve-MappedDrive -Path $p -Map $script:DriveMap
        $node = Add-BrowseNode $tree $p $p $folderIcon
        $tree.Items.Remove($node); $tree.Items.Insert(0, $node)
        $node.IsSelected = $true
        $node.IsExpanded = $true
    }
    $goBtn.Add_Click($go)
    $goBox.Add_KeyDown({ param($s, $e) if ($e.Key -eq 'Return') { & $go; $e.Handled = $true } })
    $selBtn.Add_Click({
            $state.Result = $selPath.Text
            $dlg.DialogResult = $true
        })

    if ($StartPath) { $goBox.Text = $StartPath }
    [void]$dlg.ShowDialog()
    return $state.Result
}

#endregion

#region Timer

function Invoke-Tick {
    try { Update-BgTasks } catch { Write-GuiError "Tick/bg: $($_.Exception.Message)" }
    try { Update-Preview } catch { Write-GuiError "Tick/preview: $($_.Exception.Message)" }

    $changed = $false
    foreach ($job in @($script:Jobs | Where-Object { $_.status -eq 'Running' })) {
        try {
            $tl = Get-JobTailerCached $job
            if ($tl) {
                [void]$tl.Poll(16MB)
                Add-RateSample -Job $job -Tailer $tl
            }
            $code = Read-JobExitCode -Job $job
            if ($null -ne $code) {
                # Finish once the reader has caught up with the end of the log.
                if (-not $tl -or $tl.CaughtUp) {
                    Complete-MigrationJob -Job $job -Tailer $(if ($tl) { $tl } else { New-JobTailer -Job $job })
                    $script:Reattached.Remove($job.id)
                    $changed = $true
                }
            }
            else {
                $last = $script:LastAliveCheck[$job.id]
                if (-not $last -or ((Get-Date) - $last).TotalSeconds -ge 3) {
                    $script:LastAliveCheck[$job.id] = Get-Date
                    $info = Get-JobProcessInfo -Job $job
                    $decision = Get-ReattachDecision -ExitFileExists ($null -ne (Read-JobExitCode -Job $job)) -ProcessAlive $info.Alive -ProcessStartTime $info.StartTime -SavedStartTime $job.pidStart
                    if ($decision -eq 'Interrupted') { Set-JobInterrupted $job; $changed = $true }
                }
            }
            Update-JobCard $job
        }
        catch {
            Write-GuiError "Tick/job $($job.id): $($_.Exception.Message)"
        }
    }

    # Queue scheduler.
    if ($script:QueueRunning) {
        try {
            $running = @($script:Jobs | Where-Object { $_.status -eq 'Running' }).Count
            $waiting = @($script:Jobs | Where-Object { $_.status -eq 'Waiting' })
            if ($waiting.Count -eq 0) {
                if ($running -eq 0) { $script:QueueRunning = $false; $changed = $true }
            }
            elseif ($script:Settings.queueMode -eq 'parallel') {
                foreach ($w in $waiting) { Start-JobNow $w }
                $changed = $true
            }
            elseif ($running -eq 0) {
                Start-JobNow $waiting[0]
                $changed = $true
            }
        }
        catch { Write-GuiError "Tick/queue: $($_.Exception.Message)" }
    }

    if ($changed) {
        Save-All
        Update-QueueView
        Show-JobDetail
    }
    else {
        try { Update-JobDetailLive } catch { Write-GuiError "Tick/detail: $($_.Exception.Message)" }
    }
}

function Set-JobInterrupted {
    param($Job)
    $Job.status = 'Interrupted'
    $Job.finishedAt = (Get-Date).ToString('o')
    $Job.headline = 'The copy stopped without reporting a result.'
    $Job.details = @('The robocopy process ended unexpectedly - for example, the server restarted or someone ended the process.', 'Files copied so far are kept.')
    $Job.tip = 'Run again as Incremental to finish without recopying what is already there.'
    $script:Reattached.Remove($Job.id)
}

function Resume-SavedJobs {
    # Jobs saved as Running are checked against the live process list.
    foreach ($job in @($script:Jobs | Where-Object { $_.status -eq 'Running' })) {
        $info = Get-JobProcessInfo -Job $job
        $exitExists = $null -ne (Read-JobExitCode -Job $job)
        switch (Get-ReattachDecision -ExitFileExists $exitExists -ProcessAlive $info.Alive -ProcessStartTime $info.StartTime -SavedStartTime $job.pidStart) {
            'Running'     { $script:Reattached[$job.id] = $true; [void](Get-JobTailerCached $job) }
            'Finish'      { [void](Get-JobTailerCached $job) }   # the timer completes it
            'Interrupted' { Set-JobInterrupted $job }
        }
    }
    Save-All
}

#endregion

#region Main

function Hide-OwnConsole {
    # Double-clicking the script opens a console just for it; hide that so only the window
    # shows. A console shared with other processes (someone's open terminal) is left alone.
    try {
        if (-not ('RoboMigration.ConsoleWin' -as [type])) {
            Add-Type -Namespace RoboMigration -Name ConsoleWin -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("kernel32.dll")] public static extern uint GetConsoleProcessList(uint[] list, uint count);
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
'@
        }
        $list = New-Object uint32[] 8
        $count = [RoboMigration.ConsoleWin]::GetConsoleProcessList($list, 8)
        $hwnd = [RoboMigration.ConsoleWin]::GetConsoleWindow()
        if ($count -le 1 -and $hwnd -ne [IntPtr]::Zero) { [void][RoboMigration.ConsoleWin]::ShowWindow($hwnd, 0) }
    }
    catch { }
}

function Start-MigrationWindow {
    if (Test-Path -LiteralPath $script:SettingsPath) {
        try {
            $s = Get-Content -LiteralPath $script:SettingsPath -Raw | ConvertFrom-Json
            if ($s.theme -in 'dark', 'light') { $script:Settings.theme = $s.theme }
            if ($s.queueMode -in 'sequential', 'parallel') { $script:Settings.queueMode = $s.queueMode }
        }
        catch { }
    }

    $store = Read-JobStore -Path $script:JobStorePath
    foreach ($j in $store.Jobs) { $script:Jobs.Add($j) }

    $win = New-ThemedWindow $script:MainXaml
    $ui = $script:UI
    $ui.Window = $win
    $names = 'VersionText', 'NewJobBtn', 'ThemeBtn', 'ModeSeq', 'ModePar', 'Banner', 'BannerText', 'BannerClose',
    'ClearDoneBtn', 'JobCount', 'QueueBar', 'QueueBtn', 'QueueText', 'QueuePanel', 'QueueEmpty',
    'DetailEmpty', 'DetailView', 'DetailPill', 'DetailPillText', 'DetailName', 'DetailPaths', 'DetailMeta',
    'ProgressSection', 'ProgFill', 'ProgRest', 'ProgPercent', 'ProgFile', 'StatsSection',
    'Stat1', 'Stat1L', 'Stat2', 'Stat2L', 'Stat3', 'Stat3L', 'Stat4', 'Stat4L',
    'FinishedSection', 'VerdictBox', 'VerdictHeadline', 'VerdictDetails', 'VerdictTip', 'SummaryGrid',
    'FailedSection', 'FailedLabel', 'FailedBox', 'LogLabel', 'LogBox',
    'StartBtn', 'OpenLogBtn', 'OpenDestBtn', 'RerunBtn', 'StopBtn', 'RemoveBtn',
    'Overlay', 'Scrim', 'NewJobPanel', 'PanelSlide', 'PanelClose', 'SrcBox', 'SrcBrowse', 'DstBox', 'DstBrowse',
    'PresetFull', 'PresetIncr', 'PresetData', 'PresetMirror', 'AdvToggle', 'RetriesBox', 'WaitBox', 'MtCheck', 'MtBox',
    'IpgBox', 'BkOff', 'BkZb', 'BkB', 'XfBox', 'XdBox', 'LogDirBox', 'LogDirHint', 'PreviewBox', 'PreviewText',
    'PreviewHint', 'FormError', 'PreviewBtn', 'AddBtn', 'AddStartBtn'
    foreach ($n in $names) {
        $ui[$n] = $win.FindName($n)
        if ($null -eq $ui[$n]) { throw "XAML element '$n' not found." }
    }

    # Fit smaller screens.
    $wa = [System.Windows.SystemParameters]::WorkArea
    if ($win.Height -gt $wa.Height - 20) { $win.Height = [Math]::Max($win.MinHeight, $wa.Height - 20) }
    if ($win.Width -gt $wa.Width - 20) { $win.Width = [Math]::Max($win.MinWidth, $wa.Width - 20) }

    $ui.VersionText.Text = "v$ScriptVersion"
    $themeLabel = {
        if ($script:Settings.theme -eq 'dark') { $script:UI.ThemeBtn.Content = "$([char]0x2600)  Light" }
        else { $script:UI.ThemeBtn.Content = "$([char]0x263E)  Dark" }
    }
    & $themeLabel
    if ($script:Settings.queueMode -eq 'parallel') { $ui.ModePar.IsChecked = $true } else { $ui.ModeSeq.IsChecked = $true }
    if ($store.Warning) { Show-Banner $store.Warning }

    # --- Events ---
    $ui.ThemeBtn.Add_Click({
            if ($script:Settings.theme -eq 'dark') { $script:Settings.theme = 'light' } else { $script:Settings.theme = 'dark' }
            Set-WpfTheme -Resources $script:UI.Window.Resources -Theme $script:Settings.theme
            & $themeLabel
            Save-Settings
        })
    $ui.ModeSeq.Add_Checked({ $script:Settings.queueMode = 'sequential'; Save-Settings; Update-QueueView })
    $ui.ModePar.Add_Checked({ $script:Settings.queueMode = 'parallel'; Save-Settings; Update-QueueView })
    $ui.BannerClose.Add_Click({ $script:UI.Banner.Visibility = 'Collapsed' })
    $ui.NewJobBtn.Add_Click({ Open-NewJobPanel })
    $ui.PanelClose.Add_Click({ Close-NewJobPanel })
    $ui.Scrim.Add_MouseLeftButtonUp({ Close-NewJobPanel })
    $ui.QueueBtn.Add_Click({
            $script:QueueRunning = -not $script:QueueRunning
            Update-QueueView
            if ($script:QueueRunning) { Invoke-Tick }
        })
    $ui.ClearDoneBtn.Add_Click({
            foreach ($j in @($script:Jobs | Where-Object { $_.status -notin 'Running', 'Waiting' })) {
                [void]$script:Jobs.Remove($j)
                $script:Tailers.Remove($j.id)
                if ($script:SelectedId -eq $j.id) { $script:SelectedId = $null }
            }
            Save-All
            Update-QueueView
            Show-JobDetail
        })

    $ui.StartBtn.Add_Click({ $j = Get-Job $script:SelectedId; if ($j) { Start-JobNow $j } })
    $ui.StopBtn.Add_Click({ $j = Get-Job $script:SelectedId; if ($j) { Stop-JobNow $j } })
    $ui.RerunBtn.Add_Click({ $j = Get-Job $script:SelectedId; if ($j) { Invoke-RerunIncremental $j } })
    $ui.RemoveBtn.Add_Click({ $j = Get-Job $script:SelectedId; if ($j) { Remove-JobFromList $j } })
    $ui.OpenLogBtn.Add_Click({
            $j = Get-Job $script:SelectedId
            if (-not $j -or -not $j.logPath) { return }
            if (Test-Path -LiteralPath $j.logPath) { Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$($j.logPath)`"" }
            else { [System.Windows.MessageBox]::Show("The log file hasn't been created yet:`n$($j.logPath)", 'Open log', 'OK', 'Information') | Out-Null }
        })
    $ui.OpenDestBtn.Add_Click({ $j = Get-Job $script:SelectedId; if ($j) { Open-JobDestination $j } })

    $ui.SrcBrowse.Add_Click({
            $p = Show-BrowseDialog -StartPath $script:UI.SrcBox.Text.Trim() -Title 'Choose the folder to copy from'
            if ($p) { $script:UI.SrcBox.Text = $p }
        })
    $ui.DstBrowse.Add_Click({
            $p = Show-BrowseDialog -StartPath $script:UI.DstBox.Text.Trim() -Title 'Choose the folder to copy into' -AllowNewFolder
            if ($p) { $script:UI.DstBox.Text = $p }
        })
    $ui.MtCheck.Add_Checked({ $script:UI.MtBox.IsEnabled = $true; $script:UI.IpgBox.IsEnabled = $false })
    $ui.MtCheck.Add_Unchecked({ $script:UI.MtBox.IsEnabled = $false; $script:UI.IpgBox.IsEnabled = $true })
    $ui.PreviewBtn.Add_Click({ Start-PreviewNow })
    $ui.AddBtn.Add_Click({ Add-JobFromForm -StartNow $false })
    $ui.AddStartBtn.Add_Click({ Add-JobFromForm -StartNow $true })

    $win.Add_PreviewKeyDown({
            param($s, $e)
            if ($e.Key -eq 'Escape' -and $script:UI.Overlay.Visibility -eq 'Visible') { Close-NewJobPanel; $e.Handled = $true }
            elseif ($e.Key -eq 'N' -and [System.Windows.Input.Keyboard]::Modifiers -eq 'Control') { Open-NewJobPanel; $e.Handled = $true }
        })

    $win.Add_Closing({
            param($s, $e)
            $running = @($script:Jobs | Where-Object { $_.status -eq 'Running' })
            if ($running.Count -gt 0) {
                $msg = "$($running.Count) copy job(s) are still running.`n`n" +
                "Yes - keep them running in the background. Reopen this tool to check on them.`n" +
                "No - stop them now.`n" +
                "Cancel - go back."
                $answer = [System.Windows.MessageBox]::Show($msg, 'Copies still running', 'YesNoCancel', 'Question')
                if ($answer -eq 'Cancel') { $e.Cancel = $true; return }
                if ($answer -eq 'No') { foreach ($j in $running) { Stop-MigrationJob -Job $j } }
            }
            Stop-PreviewNow
            Save-All
        })

    Resume-SavedJobs
    Update-QueueView
    Reset-PreviewView
    $reattached = @($script:Reattached.Keys).Count
    if ($reattached -gt 0) {
        $first = $script:Jobs | Where-Object { $script:Reattached[$_.id] } | Select-Object -First 1
        Select-Job $first.id
    }
    elseif ($script:Jobs.Count -gt 0) { Select-Job $script:Jobs[$script:Jobs.Count - 1].id }
    else { Show-JobDetail }

    $timer = [System.Windows.Threading.DispatcherTimer]::new()
    $timer.Interval = [TimeSpan]::FromMilliseconds(500)
    $timer.Add_Tick({ Invoke-Tick })
    $timer.Start()

    $win.Add_ContentRendered({ Hide-OwnConsole })
    [void]$win.ShowDialog()
    $timer.Stop()
}

try {
    Start-MigrationWindow
}
catch {
    Write-GuiError "Fatal: $($_.Exception.Message)`n$($_.ScriptStackTrace)"
    [System.Windows.MessageBox]::Show("Robocopy Migration hit an error and has to close:`n`n$($_.Exception.Message)`n`nDetails were written to $($script:ErrorLogPath). Running copies are not affected.", 'Robocopy Migration', 'OK', 'Error') | Out-Null
}
finally {
    try { $script:BgPool.Close() } catch { }
    try { $script:Mutex.ReleaseMutex(); $script:Mutex.Dispose() } catch { }
}

#endregion
