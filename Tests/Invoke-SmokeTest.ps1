#Requires -Version 5.1

<#
.SYNOPSIS
    Starts each GUI in its -SmokeTest mode with a time limit and reports PASS or FAIL.

.DESCRIPTION
    Unit tests prove logic; they do not prove an app starts. This runner starts the real app in
    a new Windows PowerShell process (-STA, -SmokeTest), waits for it to close by itself, and
    checks the result. A GUI passes only with positive proof: exit code 0 AND its own [PASS]
    line. Exit code 0 alone is not enough: a script that returns before its window opens also
    ends with 0 under -File (that is what 193a907 looked like).

    For each GUI:
      - exit code 0 and a [PASS] line      -> passed
      - exit code 0 and no [PASS] line     -> failed: "the app ended without opening its window"
      - any other exit code                -> failed, with the exit code and the app's lines
      - still running after -TimeoutSeconds -> timed out: the runner ends that process (only the
                                              one it started) and prints its last 20 lines

    The GUI's smoke mode asks for no administrator rights, reads no drives and writes no file;
    see the GUI's own help (-SmokeTest). This runner starts nothing else: no Start-Process, and
    the child gets no -LogFolder, -DriveMap or -NoExit.

    The runner is dev tooling for this repository (the squad's build gate runs it after each
    change); it is not part of the service-desk bundle.

.PARAMETER ScriptPath
    The GUI scripts to smoke-test, instead of the default list. Each must support -SmokeTest.
    Default: FolderPermissionManager\FolderPermissionManager-GUI.ps1, found from this runner's
    own folder (not the current directory).

.PARAMETER TimeoutSeconds
    How long each GUI may run before it is ended and reported as timed out. Default 90 (the
    app's own deadline for its window is 30 seconds; the squad gate's limit is 120, so the
    runner's clearer message comes first).

.PARAMETER LoadFunctionsOnly
    Define the functions and return without starting anything. Used by the Pester tests.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File Tests\Invoke-SmokeTest.ps1
    Smoke-tests every GUI in the default list. Exit code 0 when all passed.

.EXAMPLE
    .\Tests\Invoke-SmokeTest.ps1 -ScriptPath 'D:\Copy\FolderPermissionManager-GUI.ps1' -TimeoutSeconds 120
    Smoke-tests one copy of the Folder Permission Manager with a longer time limit.

.NOTES
    Exit codes: 0 every GUI passed; 1 at least one failed; 2 at least one did not close by
    itself in time (2 wins over 1).

    Requires Windows PowerShell 5.1 for the child (powershell.exe from %SystemRoot%); the
    runner itself runs under 5.1 or PowerShell 7.

    Files written: none. The child's output is only printed.

    REFERENCES
    - Process / ProcessStartInfo with UseShellExecute false, RedirectStandardOutput and
      RedirectStandardError, read asynchronously (BeginOutputReadLine / BeginErrorReadLine, so a
      full pipe cannot block the child), CreateNoWindow, WaitForExit(int) and, after it returned
      true, WaitForExit() so the redirected output is complete; Kill ends only that process:
      https://learn.microsoft.com/dotnet/api/system.diagnostics.processstartinfo.redirectstandardoutput
      https://learn.microsoft.com/dotnet/api/system.diagnostics.process.beginoutputreadline
      https://learn.microsoft.com/dotnet/api/system.diagnostics.process.waitforexit
      https://learn.microsoft.com/dotnet/api/system.diagnostics.process.kill
    - Register-ObjectEvent queues the process's OutputDataReceived / ErrorDataReceived events,
      which Get-Event reads afterwards (no script runs on the reader threads):
      https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/register-objectevent
      https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-event
    - powershell.exe -STA, -File, -NoProfile, -ExecutionPolicy; a script ended without exit
      under -File gives exit code 0:
      https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe
#>

[CmdletBinding()]
param(
    [string[]]$ScriptPath,

    [ValidateRange(10, 600)]
    [int]$TimeoutSeconds = 90,

    [switch]$LoadFunctionsOnly
)

$script:RepoRoot = Split-Path -Parent $PSScriptRoot

# The GUIs smoke-tested by default, relative to the repository root. Each new GUI with a
# -SmokeTest mode is one more line here (D-061).
$script:DefaultTargets = @(
    'FolderPermissionManager\FolderPermissionManager-GUI.ps1'
)

# How many of a timed-out app's last output lines are printed.
$script:TailLines = 20

function Start-SmokeProcess {
    # The only place a process is started. Runs FilePath with Arguments, collects stdout and
    # stderr lines, and waits up to TimeoutSeconds. A child still running then is NOT ended here:
    # the result says TimedOut and carries the Process, and the caller ends it with
    # Stop-SmokeProcess.
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string]$Arguments,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $FilePath
    $psi.Arguments = $Arguments
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $psi

    $tag = [guid]::NewGuid().ToString('N')
    $outId = "SmokeOut_$tag"
    $errId = "SmokeErr_$tag"
    $null = Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -SourceIdentifier $outId
    $null = Register-ObjectEvent -InputObject $process -EventName ErrorDataReceived -SourceIdentifier $errId
    try {
        [void]$process.Start()
        $process.BeginOutputReadLine()
        $process.BeginErrorReadLine()
        $exited = $process.WaitForExit($TimeoutSeconds * 1000)
        # After a timed wait returned true, the parameterless wait lets the redirected output
        # finish, so no last line is lost.
        if ($exited) { $process.WaitForExit() }
        $events = @(@(Get-Event -SourceIdentifier $outId -ErrorAction SilentlyContinue) + @(Get-Event -SourceIdentifier $errId -ErrorAction SilentlyContinue) |
            Where-Object { $_ } | Sort-Object EventIdentifier)
        $output = @($events | ForEach-Object { $_.SourceEventArgs.Data } | Where-Object { $null -ne $_ })
        $exitCode = if ($exited) { $process.ExitCode } else { -1 }
        [PSCustomObject]@{ ExitCode = $exitCode; Output = [string[]]$output; TimedOut = (-not $exited); Process = $process }
    }
    finally {
        Unregister-Event -SourceIdentifier $outId -ErrorAction SilentlyContinue
        Unregister-Event -SourceIdentifier $errId -ErrorAction SilentlyContinue
        Remove-Event -SourceIdentifier $outId -ErrorAction SilentlyContinue
        Remove-Event -SourceIdentifier $errId -ErrorAction SilentlyContinue
    }
}

function Stop-SmokeProcess {
    # Ends the one child process this runner started (by its own process object, never by name).
    param([Parameter(Mandatory)]$Process)
    try {
        if (-not $Process.HasExited) { $Process.Kill() }
        [void]$Process.WaitForExit(5000)
    }
    catch {
        Write-Host "[WARN] Could not end process $($Process.Id): $($_.Exception.Message) End it in Task Manager." -ForegroundColor Yellow
    }
}

function Resolve-SmokeScriptPath {
    # A full path: relative paths are taken from the current location.
    param([Parameter(Mandatory)][string]$Path)
    if (-not [System.IO.Path]::IsPathRooted($Path)) { $Path = Join-Path (Get-Location).ProviderPath $Path }
    [System.IO.Path]::GetFullPath($Path)
}

function Get-SmokeCommandLine {
    # Windows PowerShell 5.1 (what the servers and the service desk run), in a single-threaded
    # apartment, with only -SmokeTest: no -LogFolder, -DriveMap or -NoExit.
    param([Parameter(Mandatory)][string]$ScriptPath)
    [PSCustomObject]@{
        FilePath         = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        Arguments        = '-NoProfile -ExecutionPolicy Bypass -STA -File "' + (Resolve-SmokeScriptPath -Path $ScriptPath) + '" -SmokeTest'
        WorkingDirectory = $script:RepoRoot
    }
}

function Invoke-SmokeTarget {
    # Smoke-tests one GUI and prints its result. Returns Name, Status (Passed, Failed or
    # TimedOut), Message, ExitCode and Output.
    param([Parameter(Mandatory)][string]$ScriptPath, [int]$TimeoutSeconds = 90)
    $name = Split-Path -Leaf $ScriptPath
    $command = Get-SmokeCommandLine -ScriptPath $ScriptPath
    Write-Host "[INFO] ${name}: starting the smoke test (time limit $TimeoutSeconds seconds)" -ForegroundColor Cyan
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $run = Start-SmokeProcess -FilePath $command.FilePath -Arguments $command.Arguments -WorkingDirectory $command.WorkingDirectory -TimeoutSeconds $TimeoutSeconds
    $clock.Stop()
    $output = @($run.Output | Where-Object { $null -ne $_ } | ForEach-Object { "$_" })
    $seconds = [Math]::Round($clock.Elapsed.TotalSeconds, 1)

    if ($run.TimedOut) {
        Stop-SmokeProcess -Process $run.Process
        $message = "did not close by itself within $TimeoutSeconds seconds; it was ended. Its last output lines:"
        Write-Host "[FAIL] ${name}: $message" -ForegroundColor Red
        foreach ($line in @($output | Select-Object -Last $script:TailLines)) { Write-Host "    $name> $line" }
        return [PSCustomObject]@{ Name = $name; Status = 'TimedOut'; Message = $message; ExitCode = $run.ExitCode; Output = $output }
    }

    foreach ($line in $output) { Write-Host "    $name> $line" }
    $passLine = @($output | Where-Object { $_ -match '^\s*\[PASS\]' }) | Select-Object -First 1
    if ($run.ExitCode -eq 0 -and $passLine) {
        $message = "the window opened and closed by itself (exit code 0, $seconds s)"
        Write-Host "[PASS] ${name}: $message" -ForegroundColor Green
        return [PSCustomObject]@{ Name = $name; Status = 'Passed'; Message = $message; ExitCode = 0; Output = $output }
    }
    if ($run.ExitCode -eq 0) {
        $message = 'the app ended without opening its window (no PASS line). It returned before the window, yet reported exit code 0.'
    }
    else {
        $message = "the smoke test failed with exit code $($run.ExitCode) (its [FAIL] lines are above)."
    }
    Write-Host "[FAIL] ${name}: $message" -ForegroundColor Red
    [PSCustomObject]@{ Name = $name; Status = 'Failed'; Message = $message; ExitCode = $run.ExitCode; Output = $output }
}

function Get-SmokeExitCode {
    # 0 all passed, 1 any failed, 2 any timed out (2 wins over 1).
    param([AllowEmptyCollection()][object[]]$Results)
    $all = @($Results)
    if (@($all | Where-Object { $_.Status -eq 'TimedOut' }).Count -gt 0) { return 2 }
    if (@($all | Where-Object { $_.Status -ne 'Passed' }).Count -gt 0) { return 1 }
    0
}

if ($LoadFunctionsOnly) { return }

$targets = if ($PSBoundParameters.ContainsKey('ScriptPath')) { @($ScriptPath) } else { @($script:DefaultTargets | ForEach-Object { Join-Path $script:RepoRoot $_ }) }
$results = [System.Collections.Generic.List[object]]::new()
foreach ($target in $targets) {
    try {
        $results.Add((Invoke-SmokeTarget -ScriptPath $target -TimeoutSeconds $TimeoutSeconds))
    }
    catch {
        # One target that cannot even be started does not stop the others.
        $name = Split-Path -Leaf $target
        $message = "the smoke test could not be started: $($_.Exception.Message)"
        Write-Host "[FAIL] ${name}: $message" -ForegroundColor Red
        $results.Add([PSCustomObject]@{ Name = $name; Status = 'Failed'; Message = $message; ExitCode = $null; Output = @() })
        continue
    }
}

$passed = @($results | Where-Object { $_.Status -eq 'Passed' }).Count
$failed = @($results | Where-Object { $_.Status -eq 'Failed' }).Count
$timedOut = @($results | Where-Object { $_.Status -eq 'TimedOut' }).Count
$code = Get-SmokeExitCode -Results $results.ToArray()

Write-Host "[INFO] Smoke test: $passed passed, $failed failed, $timedOut timed out (exit code $code)." -ForegroundColor Cyan
exit $code
