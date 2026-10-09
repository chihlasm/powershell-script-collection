#Requires -Version 5.1
# Pester 5+ tests for RobocopyMigration-GUI.ps1. No elevation or window needed - the script is
# dot-sourced with -LoadFunctionsOnly. The end-to-end block runs real robocopy against temp
# folders on the local disk.

BeforeAll {
    $script:ScriptPath = Join-Path $PSScriptRoot '..\RobocopyMigration-GUI.ps1'
    . $script:ScriptPath -LoadFunctionsOnly

    # Encode text the way robocopy /UNILOG writes it: UTF-16LE with a BOM.
    function ConvertTo-UniLogBytes {
        param([string]$Text)
        $bom = [byte[]](0xFF, 0xFE)
        return [byte[]]($bom + [System.Text.Encoding]::Unicode.GetBytes($Text))
    }

    function New-TestTailer {
        param([string]$Preset = 'full')
        return [RoboMigration.RoboLogTailer]::new('', (Get-RoboSkipClasses -Preset $Preset))
    }

    # Lines captured from a real robocopy run (Windows 11, 2026-10-09) with /V /BYTES /NDL /NP,
    # paths shortened. Tabs are significant: robocopy separates class, size and path with tabs.
    $t = "`t"
    $script:SampleCopy = @(
        ''
        '-------------------------------------------------------------------------------'
        '   ROBOCOPY     ::     Robust File Copy for Windows'
        '-------------------------------------------------------------------------------'
        ''
        '  Started : Friday, October 9, 2026 3:55:10 PM'
        "${t}  *EXTRA File ${t}${t}       7${t}C:\dst\extra.txt"
        "${t}      modified${t}${t}     102${t}C:\src\f1.txt"
        "${t}    New File  ${t}${t}     202${t}C:\src\f2.txt"
        "${t}    New File  ${t}${t}      16${t}C:\src\locked.txt"
        '2026/10/09 15:55:10 ERROR 32 (0x00000020) Copying File C:\src\locked.txt'
        'The process cannot access the file because it is being used by another process.'
        ''
        'Waiting 1 seconds... Retrying...'
        "${t}    New File  ${t}${t}      16${t}C:\src\locked.txt"
        '2026/10/09 15:55:11 ERROR 32 (0x00000020) Copying File C:\src\locked.txt'
        'The process cannot access the file because it is being used by another process.'
        ''
        ''
        'ERROR: RETRY LIMIT EXCEEDED.'
        ''
        "${t}          same${t}${t}     302${t}C:\src\f3.txt"
        "${t}    New File  ${t}${t}       7${t}C:\src\sub\$([char]0xDC)n$([char]0xEF)code file.txt"
        ''
        '------------------------------------------------------------------------------'
        ''
        '               Total    Copied   Skipped  Mismatch    FAILED    Extras'
        '    Dirs :         2         1         1         0         0         0'
        '   Files :         6         2         2         0         1         1'
        '   Bytes :       629       209       404         0        16         7'
        '   Times :   0:00:01   0:00:00                       0:00:01   0:00:00'
        ''
        '   Speed :             235,833 Bytes/sec.'
        '   Ended : Friday, October 9, 2026 3:55:11 PM'
        ''
    ) -join "`r`n"
}

Describe 'File encoding (Windows PowerShell 5.1 reads BOM-less files as ANSI)' {
    It 'is pure ASCII' {
        $bytes = [System.IO.File]::ReadAllBytes($script:ScriptPath)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }
    It 'parses with no errors' {
        $tokens = $null; $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$tokens, [ref]$errors)
        $errors.Count | Should -Be 0
    }
}

Describe 'ConvertTo-RoboPath' {
    It 'strips a trailing backslash (it would escape the closing quote)' {
        ConvertTo-RoboPath 'C:\Data\Share\' | Should -Be 'C:\Data\Share'
        ConvertTo-RoboPath '\\srv\share\' | Should -Be '\\srv\share'
    }
    It 'turns a drive root into D:\. so it is not read as "current dir on D:"' {
        ConvertTo-RoboPath 'D:\' | Should -Be 'D:\.'
        ConvertTo-RoboPath 'D:' | Should -Be 'D:\.'
    }
    It 'leaves normal paths alone' {
        ConvertTo-RoboPath 'C:\a b\c' | Should -Be 'C:\a b\c'
    }
}

Describe 'Build-RobocopyArgs' {
    BeforeAll {
        $script:opts = New-JobOptions
    }
    It 'Full preset copies data, attributes, timestamps, ACLs and owner' {
        $a = Build-RobocopyArgs -Source 'C:\s' -Destination 'D:\d' -Preset full -Options $opts -LogPath 'C:\l.log'
        $a[0] | Should -Be 'C:\s'
        $a[1] | Should -Be 'D:\d'
        $a | Should -Contain '/E'
        $a | Should -Contain '/COPY:DATSO'
        $a | Should -Contain '/DCOPY:DAT'
        $a | Should -Not -Contain '/MIR'
    }
    It 'Incremental preset adds /XO /XX' {
        $a = Build-RobocopyArgs -Source 'C:\s' -Destination 'D:\d' -Preset incremental -Options $opts -LogPath 'C:\l.log'
        $a | Should -Contain '/XO'
        $a | Should -Contain '/XX'
    }
    It 'Data Only preset does not copy security' {
        $a = Build-RobocopyArgs -Source 'C:\s' -Destination 'D:\d' -Preset dataonly -Options $opts -LogPath 'C:\l.log'
        $a | Should -Contain '/COPY:DAT'
        $a | Should -Not -Contain '/COPY:DATSO'
    }
    It 'Mirror preset uses /MIR' {
        $a = Build-RobocopyArgs -Source 'C:\s' -Destination 'D:\d' -Preset mirror -Options $opts -LogPath 'C:\l.log'
        $a | Should -Contain '/MIR'
    }
    It 'logs as Unicode to the job log with verbose byte-sized file lines, and never /TEE' {
        $a = Build-RobocopyArgs -Source 'C:\s' -Destination 'D:\d' -Preset full -Options $opts -LogPath 'C:\My Logs\x.log'
        $a | Should -Contain '/UNILOG:C:\My Logs\x.log'
        $a | Should -Contain '/V'
        $a | Should -Contain '/BYTES'
        $a | Should -Contain '/NP'
        $a | Should -Not -Contain '/TEE'
    }
    It 'applies retries and wait' {
        $o = New-JobOptions -Retries 7 -WaitSeconds 2
        $a = Build-RobocopyArgs -Source 'C:\s' -Destination 'D:\d' -Preset full -Options $o -LogPath 'C:\l.log'
        $a | Should -Contain '/R:7'
        $a | Should -Contain '/W:2'
    }
    It 'adds /MT:n when threads are set' {
        $o = New-JobOptions -Threads 16
        $a = Build-RobocopyArgs -Source 'C:\s' -Destination 'D:\d' -Preset full -Options $o -LogPath 'C:\l.log'
        $a | Should -Contain '/MT:16'
    }
    It 'adds /IPG:n when no threads are set' {
        $o = New-JobOptions -InterPacketGap 50
        $a = Build-RobocopyArgs -Source 'C:\s' -Destination 'D:\d' -Preset full -Options $o -LogPath 'C:\l.log'
        $a | Should -Contain '/IPG:50'
    }
    It 'never combines /MT with /IPG (regression: the web version allowed both; Learn says they cannot be used together)' {
        $o = New-JobOptions -Threads 8 -InterPacketGap 50
        $a = Build-RobocopyArgs -Source 'C:\s' -Destination 'D:\d' -Preset full -Options $o -LogPath 'C:\l.log'
        $a | Should -Contain '/MT:8'
        @($a | Where-Object { $_ -like '/IPG*' }).Count | Should -Be 0
    }
    It 'uses /B or /ZB for locked-down files, never both' {
        $a = Build-RobocopyArgs -Source 'C:\s' -Destination 'D:\d' -Preset full -Options (New-JobOptions -BackupMode b) -LogPath 'C:\l.log'
        $a | Should -Contain '/B'
        $a | Should -Not -Contain '/ZB'
        $a = Build-RobocopyArgs -Source 'C:\s' -Destination 'D:\d' -Preset full -Options (New-JobOptions -BackupMode zb) -LogPath 'C:\l.log'
        $a | Should -Contain '/ZB'
        $a | Should -Not -Contain '/B'
    }
    It 'splits exclude patterns into separate arguments after /XF and /XD' {
        $o = New-JobOptions -ExcludeFiles '*.tmp  thumbs.db' -ExcludeDirs 'Temp .git'
        $a = @(Build-RobocopyArgs -Source 'C:\s' -Destination 'D:\d' -Preset full -Options $o -LogPath 'C:\l.log')
        $xf = [array]::IndexOf($a, '/XF')
        $a[$xf + 1] | Should -Be '*.tmp'
        $a[$xf + 2] | Should -Be 'thumbs.db'
        $xd = [array]::IndexOf($a, '/XD')
        $a[$xd + 1] | Should -Be 'Temp'
        $a[$xd + 2] | Should -Be '.git'
    }
    It 'list-only mode adds /L and prints only the summary' {
        $a = Build-RobocopyArgs -Source 'C:\s' -Destination 'D:\d' -Preset full -Options $opts -ListOnly
        $a | Should -Contain '/L'
        $a | Should -Contain '/NFL'
        $a | Should -Contain '/NDL'
        @($a | Where-Object { $_ -like '/UNILOG*' }).Count | Should -Be 0
    }
}

Describe 'Get-RoboExitInfo' {
    # Exit codes per https://learn.microsoft.com/windows-server/administration/windows-commands/robocopy
    It 'treats 0 as done, nothing needed copying' {
        $i = Get-RoboExitInfo -ExitCode 0 -Preset full
        $i.Status | Should -Be 'Done'
        $i.Headline | Should -Match 'already'
    }
    It 'treats 1 as done' { (Get-RoboExitInfo -ExitCode 1 -Preset full).Status | Should -Be 'Done' }
    It 'treats 2 and 3 as done and mentions extra files' {
        $i = Get-RoboExitInfo -ExitCode 3 -Preset full
        $i.Status | Should -Be 'Done'
        ($i.Details -join ' ') | Should -Match 'extra'
    }
    It 'says Mirror removed the extras' {
        $i = Get-RoboExitInfo -ExitCode 3 -Preset mirror
        ($i.Details -join ' ') | Should -Match 'removed'
    }
    It 'treats 4-7 as warnings' {
        foreach ($c in 4, 5, 6, 7) { (Get-RoboExitInfo -ExitCode $c -Preset full).Status | Should -Be 'Warnings' }
    }
    It 'treats 8-15 as finished with problems' {
        foreach ($c in 8, 9, 11, 15) { (Get-RoboExitInfo -ExitCode $c -Preset full).Status | Should -Be 'Problems' }
    }
    It 'includes the failed count in the headline when known' {
        (Get-RoboExitInfo -ExitCode 9 -Preset full -FailedCount 37).Headline | Should -Match '37'
    }
    It 'treats 16 and above as failed' {
        (Get-RoboExitInfo -ExitCode 16 -Preset full).Status | Should -Be 'Failed'
    }
    It 'suggests backup mode when files were access denied' {
        $i = Get-RoboExitInfo -ExitCode 9 -Preset full -FailedCount 1 -FailedText @('ERROR 5: Copying File x - Access is denied.')
        $i.Tip | Should -Match 'Backup mode'
    }
}

Describe 'RoboLogTailer' {
    It 'counts copied, skipped, failed and extra files with retry reversal' {
        $tl = New-TestTailer
        $b = ConvertTo-UniLogBytes $script:SampleCopy
        [void]$tl.Feed($b, $b.Length)
        $tl.FilesCopied | Should -Be 2          # f2 + unicode file; locked.txt reversed
        $tl.BytesCopied | Should -Be 209
        $tl.FilesSkipped | Should -Be 2         # modified + same
        $tl.BytesSkipped | Should -Be 404
        $tl.FilesFailed | Should -Be 1
        $tl.BytesFailed | Should -Be 16
        $tl.ExtraFiles | Should -Be 1
    }
    It 'records the failure reason for failed files' {
        $tl = New-TestTailer
        $b = ConvertTo-UniLogBytes $script:SampleCopy
        [void]$tl.Feed($b, $b.Length)
        $f = $tl.GetFailedFiles()
        $f.Count | Should -Be 1
        $f[0] | Should -Match 'ERROR 32'
        $f[0] | Should -Match 'locked\.txt'
        $f[0] | Should -Match 'being used by another process'
    }
    It 'parses the summary table (Dirs, Files, Bytes x Total/Copied/Skipped/Mismatch/Failed/Extras)' {
        $tl = New-TestTailer
        $b = ConvertTo-UniLogBytes $script:SampleCopy
        [void]$tl.Feed($b, $b.Length)
        $tl.HasSummary | Should -BeTrue
        $tl.SummaryFiles | Should -Be @(6, 2, 2, 0, 1, 1)
        $tl.SummaryBytes[0] | Should -Be 629
        $tl.SummaryDirs[1] | Should -Be 1
    }
    It 'gives identical results however the bytes are split, including mid-character' {
        $b = ConvertTo-UniLogBytes $script:SampleCopy
        foreach ($chunk in 1, 3, 7, 101) {
            $tl = New-TestTailer
            for ($i = 0; $i -lt $b.Length; $i += $chunk) {
                $n = [Math]::Min($chunk, $b.Length - $i)
                $part = New-Object byte[] $n
                [Array]::Copy($b, $i, $part, 0, $n)
                [void]$tl.Feed($part, $n)
            }
            $tl.FilesCopied | Should -Be 2
            $tl.FilesFailed | Should -Be 1
            $tl.SummaryFiles[0] | Should -Be 6
            $tl.GetTail() | Should -Match "$([char]0xDC)n$([char]0xEF)code file\.txt"
        }
    }
    It 'keeps only the last N lines' {
        $tl = New-TestTailer
        $tl.MaxTailLines = 10
        $text = (1..50 | ForEach-Object { "line $_" }) -join "`r`n"
        $text += "`r`n"
        $b = ConvertTo-UniLogBytes $text
        [void]$tl.Feed($b, $b.Length)
        $lines = $tl.GetTail() -split "`r`n"
        $lines.Count | Should -Be 10
        $lines[-1] | Should -Be 'line 50'
    }
    It 'treats Older as skipped for Incremental (/XO) but copied for Full' {
        $line = "`t        Older `t`t     500`tC:\src\old.txt`r`n"
        $b = ConvertTo-UniLogBytes $line
        $inc = New-TestTailer -Preset incremental
        [void]$inc.Feed($b, $b.Length)
        $inc.FilesSkipped | Should -Be 1
        $full = New-TestTailer -Preset full
        [void]$full.Feed($b, $b.Length)
        $full.FilesCopied | Should -Be 1
    }
    It 'handles a log with no summary (fatal error, exit 16)' {
        $text = "2026/10/09 15:54:46 ERROR 2 (0x00000002) Accessing Source Directory C:\nope\`r`nThe system cannot find the file specified.`r`n"
        $tl = New-TestTailer
        $b = ConvertTo-UniLogBytes $text
        [void]$tl.Feed($b, $b.Length)
        $tl.HasSummary | Should -BeFalse
        $tl.LastError | Should -Match 'ERROR 2'
        $tl.LastError | Should -Match 'cannot find'
    }
    It 'reads a growing file incrementally with Poll' {
        $f = Join-Path $TestDrive 'grow.log'
        $all = ConvertTo-UniLogBytes $script:SampleCopy
        $half = [int]($all.Length / 2) + 1    # odd split on purpose
        [System.IO.File]::WriteAllBytes($f, $all[0..($half - 1)])
        $tl = [RoboMigration.RoboLogTailer]::new($f, (Get-RoboSkipClasses -Preset full))
        [void]$tl.Poll(1MB)
        $tl.HasSummary | Should -BeFalse
        $fs = [System.IO.File]::Open($f, 'Append')
        $fs.Write($all, $half, $all.Length - $half); $fs.Close()
        [void]$tl.Poll(1MB)
        $tl.HasSummary | Should -BeTrue
        $tl.FilesCopied | Should -Be 2
        $tl.CaughtUp | Should -BeTrue
    }
    It 'respects the per-poll byte budget and reports when it is behind' {
        $f = Join-Path $TestDrive 'big.log'
        $all = ConvertTo-UniLogBytes $script:SampleCopy
        [System.IO.File]::WriteAllBytes($f, $all)
        $tl = [RoboMigration.RoboLogTailer]::new($f, (Get-RoboSkipClasses -Preset full))
        [void]$tl.Poll(100)
        $tl.CaughtUp | Should -BeFalse
        while (-not $tl.CaughtUp) { [void]$tl.Poll(100) }
        $tl.FilesCopied | Should -Be 2
    }
}

Describe 'Read-RoboSummary (preview output)' {
    It 'reads the totals from robocopy /L output' {
        $s = Read-RoboSummary -Text $script:SampleCopy
        $s.Dirs | Should -Be 2
        $s.Files | Should -Be 6
        $s.Bytes | Should -Be 629
    }
    It 'returns $null when there is no summary' {
        Read-RoboSummary -Text "ERROR 2 (0x00000002) Accessing Source Directory" | Should -BeNullOrEmpty
    }
}

Describe 'Resolve-LogFilePath' {
    It 'uses the default folder and an auto name when blank' {
        $p = Resolve-LogFilePath -UserInput '' -Source '\\fs01\Finance' -Destination 'D:\Finance' -Preset full -DefaultLogDir 'C:\Tool\Logs'
        $p | Should -Match '^C:\\Tool\\Logs\\Finance_to_Finance_full_\d{4}-\d{2}-\d{2}_\d{6}\.log$'
    }
    It 'uses a full .log path as given' {
        Resolve-LogFilePath -UserInput 'E:\x\my.log' -Source 'a' -Destination 'b' -Preset full -DefaultLogDir 'C:\L' | Should -Be 'E:\x\my.log'
    }
    It 'treats anything else as a folder' {
        Resolve-LogFilePath -UserInput 'E:\logs\' -Source 'C:\a' -Destination 'C:\b' -Preset full -DefaultLogDir 'C:\L' | Should -Match '^E:\\logs\\a_to_b_full_'
    }
}

Describe 'Resolve-MappedDrive' {
    It 'converts a mapped drive letter to its UNC path' {
        Resolve-MappedDrive -Path 'F:\Finance' -Map @{ F = '\\fs01\Shares' } | Should -Be '\\fs01\Shares\Finance'
    }
    It 'leaves unmapped paths alone' {
        Resolve-MappedDrive -Path 'C:\Data' -Map @{ F = '\\fs01\Shares' } | Should -Be 'C:\Data'
    }
}

Describe 'Job store' {
    It 'round-trips jobs through JSON' {
        $path = Join-Path $TestDrive 'jobs.json'
        $j1 = New-MigrationJob -Source 'C:\a' -Destination 'D:\b' -Preset full -Options (New-JobOptions -Threads 8)
        $j2 = New-MigrationJob -Source 'C:\c' -Destination 'D:\d' -Preset mirror -Options (New-JobOptions)
        Save-JobStore -Jobs @($j1, $j2) -Path $path
        $r = Read-JobStore -Path $path
        $r.Warning | Should -BeNullOrEmpty
        $r.Jobs.Count | Should -Be 2
        $r.Jobs[0].id | Should -Be $j1.id
        $r.Jobs[0].options.threads | Should -Be 8
        $r.Jobs[1].preset | Should -Be 'mirror'
    }
    It 'round-trips a single job as a list' {
        $path = Join-Path $TestDrive 'one.json'
        Save-JobStore -Jobs @(New-MigrationJob -Source 'C:\a' -Destination 'D:\b' -Preset full -Options (New-JobOptions)) -Path $path
        @((Read-JobStore -Path $path).Jobs).Count | Should -Be 1
    }
    It 'returns an empty list when there is no file' {
        $r = Read-JobStore -Path (Join-Path $TestDrive 'missing.json')
        @($r.Jobs).Count | Should -Be 0
        $r.Warning | Should -BeNullOrEmpty
    }
    It 'moves a corrupt file aside and warns' {
        $path = Join-Path $TestDrive 'bad.json'
        Set-Content -LiteralPath $path -Value '{ this is not json'
        $r = Read-JobStore -Path $path
        @($r.Jobs).Count | Should -Be 0
        $r.Warning | Should -Match 'corrupt|could not be read'
        Test-Path -LiteralPath $path | Should -BeFalse
        @(Get-ChildItem -LiteralPath $TestDrive -Filter 'bad.json.bad*').Count | Should -Be 1
    }
    It 'saves over an existing file (regression: the second save always failed)' {
        $path = Join-Path $TestDrive 'twice.json'
        $j = New-MigrationJob -Source 'C:\a' -Destination 'D:\b' -Preset full -Options (New-JobOptions)
        Save-JobStore -Jobs @($j) -Path $path
        $j.status = 'Running'
        { Save-JobStore -Jobs @($j) -Path $path } | Should -Not -Throw
        (Read-JobStore -Path $path).Jobs[0].status | Should -Be 'Running'
    }
    It 'does not leave a temp file behind' {
        $path = Join-Path $TestDrive 'clean.json'
        Save-JobStore -Jobs @() -Path $path
        Test-Path -LiteralPath "$path.tmp" | Should -BeFalse
    }
}

Describe 'Get-ReattachDecision' {
    BeforeAll { $script:saved = (Get-Date '2026-10-09 10:00:00').ToString('o') }
    It 'finishes the job when the exit file exists' {
        Get-ReattachDecision -ExitFileExists $true -ProcessAlive $true -ProcessStartTime (Get-Date '2026-10-09 10:00:00') -SavedStartTime $saved | Should -Be 'Finish'
    }
    It 'reattaches when the process is alive and its start time matches' {
        Get-ReattachDecision -ExitFileExists $false -ProcessAlive $true -ProcessStartTime (Get-Date '2026-10-09 10:00:00.4') -SavedStartTime $saved | Should -Be 'Running'
    }
    It 'treats a reused PID (different start time) as interrupted' {
        Get-ReattachDecision -ExitFileExists $false -ProcessAlive $true -ProcessStartTime (Get-Date '2026-10-09 11:30:00') -SavedStartTime $saved | Should -Be 'Interrupted'
    }
    It 'treats a dead process with no exit file as interrupted' {
        Get-ReattachDecision -ExitFileExists $false -ProcessAlive $false -ProcessStartTime $null -SavedStartTime $saved | Should -Be 'Interrupted'
    }
}

Describe 'Get-WrapperScript' {
    It 'single-quotes every argument and escapes embedded quotes' {
        $s = Get-WrapperScript -RoboArgs @("C:\O'Brien\Data", 'D:\d', '/E') -ExitFile 'C:\State\x.exit'
        $s | Should -Match ([regex]::Escape("'C:\O''Brien\Data'"))
        $s | Should -Match ([regex]::Escape("'C:\State\x.exit'"))
        $s | Should -Match 'LASTEXITCODE'
    }
    It 'produces a script that parses' {
        $s = Get-WrapperScript -RoboArgs @('C:\a b', 'D:\d', '/E') -ExitFile 'C:\x.exit'
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput($s, [ref]$null, [ref]$errors)
        $errors.Count | Should -Be 0
    }
}

Describe 'End to end with real robocopy' {
    BeforeAll {
        $script:root = Join-Path $TestDrive 'e2e'
        $script:src = Join-Path $root 'src folder'
        $script:dst = Join-Path $root 'dst'
        $script:state = Join-Path $root 'State'
        $script:logs = Join-Path $root 'Logs'
        New-Item -ItemType Directory -Path (Join-Path $src 'sub'), $state -Force | Out-Null
        1..200 | ForEach-Object { [System.IO.File]::WriteAllText((Join-Path $src "f$_.txt"), ('x' * $_)) }
        [System.IO.File]::WriteAllText((Join-Path $src "sub\$([char]0xDC)n$([char]0xEF)code.txt"), 'hello')

        function Wait-JobExit {
            param($Job, [int]$Seconds = 60)
            $deadline = (Get-Date).AddSeconds($Seconds)
            while (-not (Test-Path -LiteralPath $Job.exitFile) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 200 }
            # The exit file may exist a moment before it has content.
            Start-Sleep -Milliseconds 300
        }
    }
    It 'previews, runs a job detached, and finishes with the right counts' {
        $prev = Invoke-RoboPreviewSync -Source $src -Destination $dst -Preset full -Options (New-JobOptions)
        $prev.Files | Should -Be 201

        $job = New-MigrationJob -Source $src -Destination $dst -Preset dataonly -Options (New-JobOptions -Retries 0 -WaitSeconds 0) -Preview $prev
        Start-MigrationJob -Job $job -StateDir $state -DefaultLogDir $logs -DriveMap @{}
        $job.status | Should -Be 'Running'
        $job.pid | Should -BeGreaterThan 0
        Wait-JobExit $job
        $tl = New-JobTailer -Job $job
        Complete-MigrationJob -Job $job -Tailer $tl
        $job.exitCode | Should -Be 1
        $job.status | Should -Be 'Done'
        $job.summary.files[1] | Should -Be 201
        (Test-Path -LiteralPath (Join-Path $dst "sub\$([char]0xDC)n$([char]0xEF)code.txt")) | Should -BeTrue
        $tl.FilesCopied | Should -Be 201
    }
    It 'keeps copying after the process that started it exits, and reattaches as Running' {
        $dst2 = Join-Path $root 'survivor'
        $storePath = Join-Path $state 'survivor.json'
        # A separate PowerShell starts the job and exits, like closing the window.
        $starter = @"
. '$($script:ScriptPath)' -LoadFunctionsOnly
`$job = New-MigrationJob -Source '$src' -Destination '$dst2' -Preset dataonly -Options (New-JobOptions -Retries 0 -WaitSeconds 0 -InterPacketGap 500)
Start-MigrationJob -Job `$job -StateDir '$state' -DefaultLogDir '$logs' -DriveMap @{}
Save-JobStore -Jobs @(`$job) -Path '$storePath'
"@
        $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $p = Start-Process -FilePath $ps -ArgumentList @('-NoProfile', '-EncodedCommand', [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($starter))) -WindowStyle Hidden -PassThru
        # WaitForExit, not -Wait: Start-Process -Wait also waits for descendants (robocopy).
        $p.WaitForExit()
        $p.ExitCode | Should -Be 0
        Start-Sleep -Seconds 2

        $job = (Read-JobStore -Path $storePath).Jobs[0]
        $info = Get-JobProcessInfo -Job $job
        $info.Alive | Should -BeTrue
        Get-ReattachDecision -ExitFileExists $false -ProcessAlive $info.Alive -ProcessStartTime $info.StartTime -SavedStartTime $job.pidStart | Should -Be 'Running'
        @(Get-CimInstance Win32_Process -Filter "Name='robocopy.exe'" | Where-Object { $_.CommandLine -like "*$dst2*" }).Count | Should -Be 1
        Stop-MigrationJob -Job $job
    }
    It 'Stop kills the wrapper and robocopy' {
        $slowDst = Join-Path $root 'slow'
        # A large inter-packet gap keeps robocopy busy long enough to stop it.
        $job = New-MigrationJob -Source $src -Destination $slowDst -Preset dataonly -Options (New-JobOptions -Retries 0 -WaitSeconds 0 -InterPacketGap 500)
        Start-MigrationJob -Job $job -StateDir $state -DefaultLogDir $logs -DriveMap @{}
        Start-Sleep -Seconds 3
        $robo = @(Get-CimInstance Win32_Process -Filter "Name='robocopy.exe'" | Where-Object { $_.CommandLine -like "*$slowDst*" })
        $robo.Count | Should -Be 1
        Stop-MigrationJob -Job $job
        Start-Sleep -Seconds 1
        $job.status | Should -Be 'Stopped'
        Get-Process -Id $robo[0].ProcessId -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        Get-Process -Id $job.pid -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }
}

Describe 'ConvertTo-LocalDate' {
    # Regression: ToLocalTime() on an unspecified-kind time shifted it by the UTC offset, so a
    # live job looked like a reused PID and was marked Interrupted.
    It 'does not shift a time that has no offset' {
        (ConvertTo-LocalDate '2026-10-09T10:00:00.0000000').Hour | Should -Be 10
    }
    It 'keeps a local time with an offset as the same instant' {
        $now = Get-Date
        ([Math]::Abs(((ConvertTo-LocalDate $now.ToString('o')) - $now).TotalSeconds)) | Should -BeLessThan 1
    }
    It 'converts UTC to local' {
        $utc = [datetime]::SpecifyKind((Get-Date '2026-10-09 10:00:00'), 'Utc')
        (ConvertTo-LocalDate $utc).Kind | Should -Be 'Local'
    }
    It 'accepts DateTime objects (PowerShell 7 ConvertFrom-Json produces them)' {
        $d = Get-Date
        ConvertTo-LocalDate $d | Should -Be $d
    }
}

Describe 'Test-FolderName' {
    # Rules from https://learn.microsoft.com/windows/win32/fileio/naming-a-file
    It 'accepts ordinary names, including a leading period' {
        foreach ($n in 'Finance', 'Q3 Reports', '.temp', 'archive.2026') { Test-FolderName $n | Should -BeNullOrEmpty }
    }
    It 'rejects blank names' {
        Test-FolderName '' | Should -Not -BeNullOrEmpty
        Test-FolderName '   ' | Should -Not -BeNullOrEmpty
    }
    It 'rejects reserved characters' {
        foreach ($c in '<', '>', ':', '"', '/', '\', '|', '?', '*') { Test-FolderName "a${c}b" | Should -Match 'character' }
    }
    It 'rejects control characters' {
        Test-FolderName "a$([char]9)b" | Should -Not -BeNullOrEmpty
    }
    It 'rejects reserved device names, with or without an extension, in any case' {
        foreach ($n in 'CON', 'prn', 'Aux', 'NUL', 'COM1', 'lpt9', 'NUL.txt', 'com1.tar.gz', "COM$([char]0xB9)", "LPT$([char]0xB3)") {
            Test-FolderName $n | Should -Match 'reserved'
        }
    }
    It 'allows names that only start like a device name' {
        foreach ($n in 'CONTRACTS', 'Console', 'COM10', 'LPT0x') { Test-FolderName $n | Should -BeNullOrEmpty }
    }
    It 'rejects names ending in a space or a period' {
        Test-FolderName 'Finance ' | Should -Match 'end'
        Test-FolderName 'Finance.' | Should -Match 'end'
    }
}

Describe 'Invoke-NewFolder' {
    It 'creates the folder and reports success' {
        $r = Invoke-NewFolder $TestDrive 'Created'
        $r.Ok | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $TestDrive 'Created') | Should -BeTrue
    }
    It 'refuses a folder that already exists' {
        New-Item -ItemType Directory -Path (Join-Path $TestDrive 'Dupe') | Out-Null
        $r = Invoke-NewFolder $TestDrive 'dupe'
        $r.Ok | Should -BeFalse
        $r.Error | Should -Match 'already exists'
    }
    It 'reports a parent that does not exist' {
        $r = Invoke-NewFolder (Join-Path $TestDrive 'missing') 'x'
        $r.Ok | Should -BeFalse
        $r.Error | Should -Not -BeNullOrEmpty
    }
}
