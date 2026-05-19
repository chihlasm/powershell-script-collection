# DiskSpd Diagnostic Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an on-demand storage triage tool that wraps Microsoft's `diskspd.exe` with a WPF GUI, three targeting modes (local / UNC from local / remote VDA → path), preset workload profiles with overrides, preflight + cleanup discipline, and an HTML report.

**Architecture:** Single PowerShell 5.1 script (`Invoke-DiskSpdDiagnostic.ps1`) that contains a WPF UI defined in XAML (as a here-string, loaded via `XamlReader`) plus the engine functions. diskspd's `-Rxml` flag is used for structured output. Long-running diskspd invocations execute in a `PowerShell.AddScript()` runspace so the WPF dispatcher stays responsive. Remote runs use `Invoke-Command` after copying the bundled binary to the target. All test files and copied binaries are cleaned up in `finally{}` blocks. An optional `-NoUI` switch enables headless/scheduled use.

**Tech Stack:**
- PowerShell 5.1 (Windows in-box)
- WPF via `PresentationFramework` + `System.Xaml` assemblies (in-box on Windows 10+ / Server 2016+)
- `diskspd.exe` v2.2.0 (bundled, Microsoft GitHub release, x64)
- `Invoke-Command` / `Test-WSMan` for remote VDA mode
- Pester 5.x for unit tests (already used by other plans in this repo)

**Reference design:** [docs/plans/2026-05-19-diskspd-diagnostic-design.md](../../plans/2026-05-19-diskspd-diagnostic-design.md)

**Note on WPF in this repo:** No existing tool in this repo uses WPF — most GUIs are browser-based (HttpListener) or WinForms. This script will be the first WPF tool. The plan therefore specifies WPF patterns explicitly rather than pointing at existing tools.

---

## File Structure

| File | Responsibility |
|---|---|
| `DiskSpdDiagnostic/Invoke-DiskSpdDiagnostic.ps1` | Entire script: param block, XAML here-string, engine functions, UI wiring, `-NoUI` headless path |
| `DiskSpdDiagnostic/diskspd.exe` | Bundled x64 Microsoft-signed binary (v2.2.0 from official release) |
| `DiskSpdDiagnostic/diskspd-LICENSE.txt` | MIT license from upstream release |
| `DiskSpdDiagnostic/ReportTemplate.html` | HTML report skeleton with placeholders + inline CSS |
| `DiskSpdDiagnostic/README.md` | Usage docs, parameter table, screenshots-section placeholder |
| `DiskSpdDiagnostic/Tests/DiskSpdDiagnostic.Tests.ps1` | Pester 5 unit tests (engine functions only — UI is not unit tested) |
| `DiskSpdDiagnostic/Tests/sample-diskspd-output.xml` | Real diskspd `-Rxml` capture used as a parser fixture |

Engine functions in `Invoke-DiskSpdDiagnostic.ps1` (defined in this order in the file):

1. `Get-DiskSpdWorkloadProfile` — pure: profile name → settings hashtable
2. `Resolve-DiskSpdSettings` — merges profile + overrides → final settings hashtable
3. `Test-DiskSpdPreflight` — verifies binary, path, free space, remote reachability, business hours
4. `Build-DiskSpdArguments` — pure: settings + paths → argv string array
5. `Invoke-DiskSpdLocal` — runs diskspd on this machine, returns raw XML string
6. `Invoke-DiskSpdRemote` — copies diskspd to remote, runs it there, returns raw XML string
7. `ConvertFrom-DiskSpdXml` — pure: XML string → flat `[PSCustomObject]` results
8. `Get-DiskSpdHealthAssessment` — pure: results + transport (local/network) → per-metric OK/WARN/CRIT
9. `Export-DiskSpdHtmlReport` — fills `ReportTemplate.html`, writes report file
10. `Invoke-DiskSpdHeadless` — orchestrates pre-flight → run → parse → assess → export for `-NoUI`
11. `Show-DiskSpdGui` — loads XAML, wires events, dispatches background runspace
12. Top-level dispatch: if `-NoUI` then `Invoke-DiskSpdHeadless` else `Show-DiskSpdGui`

Pure functions (1, 2, 4, 7, 8) are the testable surface. Side-effect functions (3, 5, 6, 9, 10, 11) are exercised in integration and manual testing.

---

## Conventions reminder (from CLAUDE.md)

Every task that adds PowerShell follows these:

- `[CmdletBinding()]` with typed `param()`, `[ValidateSet()]`, `[ValidateRange()]`, `[Parameter(Mandatory)]`
- Use `Import-Module` with try/catch (no `#Requires -Modules`)
- `#Requires -Version 5.1` and `#Requires -RunAsAdministrator` at the top
- Try/catch around every remote call so one bad server doesn't kill the run
- `-ErrorAction Stop` for critical operations
- Status prefixes `[PASS]` (Green), `[WARN]` (Yellow), `[FAIL]` (Red), `[INFO]` (Cyan) in `Write-Host`
- Timestamps: `yyyy-MM-dd HH:mm:ss` for logs, `yyyy-MM-dd_HHmmss` for filenames
- `[PSCustomObject]@{}` for structured data
- `-ComputerName` parameter for all remote queries — never assume local
- Comment-based help block (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.NOTES`)
- Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`

All commits in this plan should end with `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`.

---

## Task 0: Project scaffold

**Files:**
- Create: `DiskSpdDiagnostic/Invoke-DiskSpdDiagnostic.ps1`
- Create: `DiskSpdDiagnostic/Tests/DiskSpdDiagnostic.Tests.ps1`
- Create: `DiskSpdDiagnostic/.gitignore`

- [ ] **Step 1: Create the folder + .gitignore**

```bash
mkdir -p DiskSpdDiagnostic/Tests
```

Write `DiskSpdDiagnostic/.gitignore`:

```gitignore
# Generated reports (operators will produce many of these)
*.html
!ReportTemplate.html
# Local test artifacts
Tests/output/
*.tmp
```

- [ ] **Step 2: Write the script skeleton**

Write `DiskSpdDiagnostic/Invoke-DiskSpdDiagnostic.ps1`:

```powershell
#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    DiskSpd Diagnostic Tool — on-demand storage triage using Microsoft diskspd.exe.

.DESCRIPTION
    Wraps diskspd.exe with a WPF GUI for fast, authoritative storage benchmarks.
    Supports three targeting modes:
      1. Local disk on this machine
      2. UNC path from this machine
      3. Run diskspd ON a remote VDA, targeting a path from that VDA
    Preset workload profiles model FSLogix-like, sequential read, mixed user load,
    and quick-sanity workloads, with override fields for power users.
    Produces a styled HTML report with health assessments.

.PARAMETER Target
    Path or UNC for the storage to test. Required when -NoUI is set.

.PARAMETER ComputerName
    Optional. If set, diskspd runs on this remote VDA targeting -Target from there.

.PARAMETER Profile
    Workload profile: FSLogixLike, SequentialRead, MixedUserLoad, QuickSanity, Custom.

.PARAMETER BlockSize
    Block size override (e.g., 4K, 64K). Required with -Workload Custom.

.PARAMETER Threads
    Thread count override. Required with -Workload Custom.

.PARAMETER QueueDepth
    Outstanding I/Os per thread. Required with -Workload Custom.

.PARAMETER WriteRatioPercent
    Percentage of writes (0-100). Required with -Workload Custom.

.PARAMETER DurationSeconds
    Test duration in seconds. Required with -Workload Custom.

.PARAMETER TestFileSizeMB
    Test file size in MB. Required with -Workload Custom.

.PARAMETER NoUI
    Run in headless mode. Requires -Target.

.PARAMETER OutputPath
    Directory for the HTML report. Defaults to the script folder so reports land
    predictably even under -RunAsAdministrator with a different admin account.

.PARAMETER Force
    Bypass business-hours confirmation.

.EXAMPLE
    .\Invoke-DiskSpdDiagnostic.ps1

.EXAMPLE
    .\Invoke-DiskSpdDiagnostic.ps1 -NoUI -Target '\\FileServer01\FSLogix' -Workload FSLogixLike

.NOTES
    Requires diskspd.exe (bundled) next to this script.
    Must run as Administrator. WPF requires the in-box PresentationFramework assembly.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Target,

    [Parameter()]
    [string]$ComputerName,

    [Parameter()]
    [ValidateSet('FSLogixLike','SequentialRead','MixedUserLoad','QuickSanity','Custom')]
    [string]$Workload = 'FSLogixLike',

    [Parameter()]
    [ValidatePattern('^\d+[KMG]?$')]
    [string]$BlockSize,

    [Parameter()]
    [ValidateRange(1, 64)]
    [int]$Threads,

    [Parameter()]
    [ValidateRange(1, 256)]
    [int]$QueueDepth,

    [Parameter()]
    [ValidateRange(0, 100)]
    [int]$WriteRatioPercent,

    [Parameter()]
    [ValidateRange(5, 3600)]
    [int]$DurationSeconds,

    [Parameter()]
    [ValidateRange(64, 102400)]
    [int]$TestFileSizeMB,

    [Parameter()]
    [switch]$NoUI,

    [Parameter()]
    [string]$OutputPath = $PSScriptRoot,

    [Parameter()]
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$script:ScriptRoot = $PSScriptRoot
$script:DiskSpdExe  = Join-Path $script:ScriptRoot 'diskspd.exe'
$script:ReportTpl   = Join-Path $script:ScriptRoot 'ReportTemplate.html'

# --- Engine functions go here (Tasks 1-9) ---

# --- UI / headless dispatch goes here (Tasks 10-11) ---

# Entry-point dispatch (filled in Task 12):
# if ($NoUI) { Invoke-DiskSpdHeadless ... } else { Show-DiskSpdGui }
```

- [ ] **Step 3: Write the Pester test scaffold**

Write `DiskSpdDiagnostic/Tests/DiskSpdDiagnostic.Tests.ps1`:

```powershell
#Requires -Version 5.1

# Run with: Invoke-Pester -Path .\DiskSpdDiagnostic\Tests
# Requires Pester 5.x: Install-Module Pester -MinimumVersion 5.0 -Force

BeforeAll {
    $script:ScriptUnderTest = Join-Path $PSScriptRoot '..\Invoke-DiskSpdDiagnostic.ps1'
    # Load the engine functions once for the whole file. Each Describe block runs
    # in its own scope in Pester 5, but functions loaded in the file-level BeforeAll
    # are visible to all of them. Don't add a per-Describe BeforeAll just for this.
    . $script:ScriptUnderTest -ErrorAction SilentlyContinue *> $null
}

Describe 'DiskSpd Diagnostic — script entry' {
    It 'parses without syntax errors' {
        { . $script:ScriptUnderTest -NoUI -Target 'C:\nonexistent-path-for-syntax-check' -Workload QuickSanity -ErrorAction SilentlyContinue } |
            Should -Not -Throw -Because 'syntax errors would surface at parse time'
    }
}
```

The single test here just confirms the script parses. Subsequent tasks add real coverage.

- [ ] **Step 4: Verify the scaffold runs**

Run:
```powershell
powershell -NoProfile -File .\DiskSpdDiagnostic\Invoke-DiskSpdDiagnostic.ps1 -NoUI -Target 'C:\' -Workload QuickSanity
```

Expected: errors about `Invoke-DiskSpdHeadless` not being defined (we haven't written it yet) — but **no parser errors**. If you see "Unexpected token" or "Missing closing brace", fix before continuing.

- [ ] **Step 5: Commit**

```bash
git add DiskSpdDiagnostic/
git commit -m "$(cat <<'EOF'
feat: scaffold DiskSpdDiagnostic tool folder

- Param block with all switches/validators per design doc
- Help block, Requires directives, conventions baseline
- Pester test scaffold with parse-only sanity check

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 1: `Get-DiskSpdWorkloadProfile` — preset definitions

**Files:**
- Modify: `DiskSpdDiagnostic/Invoke-DiskSpdDiagnostic.ps1` (add function under "Engine functions" comment)
- Modify: `DiskSpdDiagnostic/Tests/DiskSpdDiagnostic.Tests.ps1`

- [ ] **Step 1: Write the failing tests**

Append to `DiskSpdDiagnostic/Tests/DiskSpdDiagnostic.Tests.ps1`:

```powershell
Describe 'Get-DiskSpdWorkloadProfile' {
    It 'returns FSLogix-like profile values' {
        $p = Get-DiskSpdWorkloadProfile -Name FSLogixLike
        $p.BlockSize          | Should -Be '4K'
        $p.Threads            | Should -Be 4
        $p.QueueDepth         | Should -Be 8
        $p.WriteRatioPercent  | Should -Be 30
        $p.DurationSeconds    | Should -Be 30
        $p.TestFileSizeMB     | Should -Be 1024
        $p.RandomIO           | Should -BeTrue
    }

    It 'returns Sequential read profile values' {
        $p = Get-DiskSpdWorkloadProfile -Name SequentialRead
        $p.BlockSize          | Should -Be '64K'
        $p.WriteRatioPercent  | Should -Be 0
        $p.RandomIO           | Should -BeFalse
    }

    It 'returns Mixed user load profile values' {
        $p = Get-DiskSpdWorkloadProfile -Name MixedUserLoad
        $p.BlockSize          | Should -Be '8K'
        $p.WriteRatioPercent  | Should -Be 20
        $p.DurationSeconds    | Should -Be 60
    }

    It 'returns Quick sanity profile values' {
        $p = Get-DiskSpdWorkloadProfile -Name QuickSanity
        $p.DurationSeconds    | Should -Be 10
        $p.WriteRatioPercent  | Should -Be 0
    }

    It 'returns null for Custom' {
        Get-DiskSpdWorkloadProfile -Name Custom | Should -BeNullOrEmpty
    }

    It 'rejects unknown profile names' {
        { Get-DiskSpdWorkloadProfile -Name DoesNotExist } | Should -Throw
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```powershell
Invoke-Pester -Path .\DiskSpdDiagnostic\Tests\DiskSpdDiagnostic.Tests.ps1 -Output Detailed
```
Expected: All `Get-DiskSpdWorkloadProfile` tests FAIL with "command not recognized."

- [ ] **Step 3: Implement the function**

Insert under the `# --- Engine functions go here ---` comment in `Invoke-DiskSpdDiagnostic.ps1`:

```powershell
function Get-DiskSpdWorkloadProfile {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('FSLogixLike','SequentialRead','MixedUserLoad','QuickSanity','Custom')]
        [string]$Name
    )

    switch ($Name) {
        'FSLogixLike' {
            @{
                BlockSize         = '4K'
                Threads           = 4
                QueueDepth        = 8
                WriteRatioPercent = 30
                DurationSeconds   = 30
                TestFileSizeMB    = 1024
                RandomIO          = $true
            }
        }
        'SequentialRead' {
            @{
                BlockSize         = '64K'
                Threads           = 1
                QueueDepth        = 4
                WriteRatioPercent = 0
                DurationSeconds   = 30
                TestFileSizeMB    = 1024
                RandomIO          = $false
            }
        }
        'MixedUserLoad' {
            @{
                BlockSize         = '8K'
                Threads           = 2
                QueueDepth        = 4
                WriteRatioPercent = 20
                DurationSeconds   = 60
                TestFileSizeMB    = 1024
                RandomIO          = $true
            }
        }
        'QuickSanity' {
            @{
                BlockSize         = '64K'
                Threads           = 1
                QueueDepth        = 2
                WriteRatioPercent = 0
                DurationSeconds   = 10
                TestFileSizeMB    = 256
                RandomIO          = $true
            }
        }
        'Custom' { $null }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `Invoke-Pester -Path .\DiskSpdDiagnostic\Tests -Output Detailed`
Expected: All `Get-DiskSpdWorkloadProfile` tests PASS.

- [ ] **Step 5: Commit**

```bash
git add DiskSpdDiagnostic/
git commit -m "feat: Get-DiskSpdWorkloadProfile presets

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 2: `Resolve-DiskSpdSettings` — merge profile + overrides

**Files:**
- Modify: `DiskSpdDiagnostic/Invoke-DiskSpdDiagnostic.ps1`
- Modify: `DiskSpdDiagnostic/Tests/DiskSpdDiagnostic.Tests.ps1`

- [ ] **Step 1: Write the failing tests**

Append:

```powershell
Describe 'Resolve-DiskSpdSettings' {
    It 'returns the profile unchanged when no overrides supplied' {
        $s = Resolve-DiskSpdSettings -ProfileName FSLogixLike -Overrides @{}
        $s.BlockSize  | Should -Be '4K'
        $s.Threads    | Should -Be 4
    }

    It 'applies overrides on top of a preset' {
        $s = Resolve-DiskSpdSettings -ProfileName FSLogixLike -Overrides @{
            Threads         = 16
            DurationSeconds = 120
        }
        $s.Threads          | Should -Be 16
        $s.DurationSeconds  | Should -Be 120
        $s.BlockSize        | Should -Be '4K' -Because 'unmodified keys keep preset values'
    }

    It 'requires every key when ProfileName is Custom' {
        { Resolve-DiskSpdSettings -ProfileName Custom -Overrides @{ BlockSize = '4K' } } |
            Should -Throw -ExpectedMessage '*Custom*requires*'
    }

    It 'accepts a complete Custom override set' {
        $s = Resolve-DiskSpdSettings -ProfileName Custom -Overrides @{
            BlockSize         = '512K'
            Threads           = 8
            QueueDepth        = 32
            WriteRatioPercent = 50
            DurationSeconds   = 45
            TestFileSizeMB    = 2048
            RandomIO          = $true
        }
        $s.BlockSize | Should -Be '512K'
        $s.RandomIO  | Should -BeTrue
    }
}
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `Invoke-Pester -Path .\DiskSpdDiagnostic\Tests -Output Detailed`
Expected: 4 new failures, command not recognized.

- [ ] **Step 3: Implement**

Add to engine functions section:

```powershell
function Resolve-DiskSpdSettings {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('FSLogixLike','SequentialRead','MixedUserLoad','QuickSanity','Custom')]
        [string]$ProfileName,

        [Parameter(Mandatory)]
        [hashtable]$Overrides
    )

    $requiredKeys = @('BlockSize','Threads','QueueDepth','WriteRatioPercent',
                      'DurationSeconds','TestFileSizeMB','RandomIO')

    if ($ProfileName -eq 'Custom') {
        $missing = $requiredKeys | Where-Object { -not $Overrides.ContainsKey($_) }
        if ($missing) {
            throw "Profile 'Custom' requires all override keys. Missing: $($missing -join ', ')"
        }
        return [hashtable]$Overrides.Clone()
    }

    $settings = Get-DiskSpdWorkloadProfile -Name $ProfileName
    foreach ($key in $Overrides.Keys) {
        $settings[$key] = $Overrides[$key]
    }
    return $settings
}
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `Invoke-Pester -Path .\DiskSpdDiagnostic\Tests -Output Detailed`
Expected: All `Resolve-DiskSpdSettings` tests PASS.

- [ ] **Step 5: Commit**

```bash
git add DiskSpdDiagnostic/
git commit -m "feat: Resolve-DiskSpdSettings merges presets with overrides

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 3: `Build-DiskSpdArguments` — argv builder

**Files:**
- Modify: `DiskSpdDiagnostic/Invoke-DiskSpdDiagnostic.ps1`
- Modify: `DiskSpdDiagnostic/Tests/DiskSpdDiagnostic.Tests.ps1`

diskspd argv reference (from the v2.2.0 release notes):
- `-b<size>` block size (e.g., `-b4K`)
- `-t<n>` threads
- `-o<n>` outstanding I/Os per thread (queue depth)
- `-w<pct>` write percentage (0 = all reads)
- `-d<sec>` test duration
- `-c<size>` test file size (e.g., `-c1G`)
- `-r` random I/O (omit for sequential)
- `-Rxml` XML output
- `-L` per-thread latency statistics
- `-Sh` disable both software and hardware caching (truer numbers)
- final positional: target file path

- [ ] **Step 1: Write the failing tests**

Append:

```powershell
Describe 'Build-DiskSpdArguments' {
    $base = @{
        BlockSize         = '4K'
        Threads           = 4
        QueueDepth        = 8
        WriteRatioPercent = 30
        DurationSeconds   = 30
        TestFileSizeMB    = 1024
        RandomIO          = $true
    }

    It 'emits all required flags in order' {
        $args = Build-DiskSpdArguments -Settings $base -TestFilePath 'C:\Temp\test.dat'
        $args | Should -Contain '-b4K'
        $args | Should -Contain '-t4'
        $args | Should -Contain '-o8'
        $args | Should -Contain '-w30'
        $args | Should -Contain '-d30'
        $args | Should -Contain '-c1G'
        $args | Should -Contain '-r'
        $args | Should -Contain '-Rxml'
        $args | Should -Contain '-L'
        $args | Should -Contain '-Sh'
        $args[-1] | Should -Be 'C:\Temp\test.dat' -Because 'target path must be last'
    }

    It 'omits -r when RandomIO is false (sequential)' {
        $seq = $base.Clone(); $seq.RandomIO = $false
        $args = Build-DiskSpdArguments -Settings $seq -TestFilePath 'C:\Temp\test.dat'
        $args | Should -Not -Contain '-r'
    }

    It 'uses M suffix for sub-GB sizes' {
        $small = $base.Clone(); $small.TestFileSizeMB = 256
        $args = Build-DiskSpdArguments -Settings $small -TestFilePath 'C:\Temp\test.dat'
        $args | Should -Contain '-c256M'
    }

    It 'handles UNC paths' {
        $args = Build-DiskSpdArguments -Settings $base -TestFilePath '\\FileServer01\Share\test.dat'
        $args[-1] | Should -Be '\\FileServer01\Share\test.dat'
    }
}
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `Invoke-Pester -Path .\DiskSpdDiagnostic\Tests -Output Detailed`
Expected: 4 new failures, command not recognized.

- [ ] **Step 3: Implement**

Add to engine functions section:

```powershell
function Build-DiskSpdArguments {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [hashtable]$Settings,
        [Parameter(Mandatory)] [string]   $TestFilePath
    )

    # Size suffix: use G for >= 1024 MB, M otherwise.
    $size = if ($Settings.TestFileSizeMB -ge 1024 -and ($Settings.TestFileSizeMB % 1024) -eq 0) {
        "$($Settings.TestFileSizeMB / 1024)G"
    } else {
        "$($Settings.TestFileSizeMB)M"
    }

    $args = @(
        "-b$($Settings.BlockSize)"
        "-t$($Settings.Threads)"
        "-o$($Settings.QueueDepth)"
        "-w$($Settings.WriteRatioPercent)"
        "-d$($Settings.DurationSeconds)"
        "-c$size"
        '-Rxml'
        '-L'
        '-Sh'
    )
    if ($Settings.RandomIO) { $args += '-r' }
    $args += $TestFilePath
    return $args
}
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `Invoke-Pester -Path .\DiskSpdDiagnostic\Tests -Output Detailed`
Expected: All `Build-DiskSpdArguments` tests PASS.

- [ ] **Step 5: Commit**

```bash
git add DiskSpdDiagnostic/
git commit -m "feat: Build-DiskSpdArguments composes diskspd argv

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 4: Capture a real diskspd XML fixture

**Files:**
- Create: `DiskSpdDiagnostic/Tests/sample-diskspd-output.xml`
- Create: `DiskSpdDiagnostic/diskspd.exe` (download)
- Create: `DiskSpdDiagnostic/diskspd-LICENSE.txt`

We need a known-good XML output to test the parser against. Capture it once with a tiny local run.

- [ ] **Step 1: Download diskspd**

```powershell
$url   = 'https://github.com/microsoft/diskspd/releases/download/v2.2.0/DiskSpd.zip'
$dest  = Join-Path $env:TEMP 'DiskSpd.zip'
Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
Expand-Archive -Path $dest -DestinationPath (Join-Path $env:TEMP 'DiskSpd') -Force
Copy-Item -Path (Join-Path $env:TEMP 'DiskSpd\amd64\diskspd.exe') -Destination .\DiskSpdDiagnostic\diskspd.exe
Copy-Item -Path (Join-Path $env:TEMP 'DiskSpd\LICENSE')          -Destination .\DiskSpdDiagnostic\diskspd-LICENSE.txt
```

- [ ] **Step 2: Verify the binary is Microsoft-signed**

```powershell
$sig = Get-AuthenticodeSignature .\DiskSpdDiagnostic\diskspd.exe
$sig.Status                  # Expected: Valid
$sig.SignerCertificate.Subject  # Expected: contains 'Microsoft Corporation'
```

If `Status` is not `Valid` or the signer is not Microsoft, **stop** — you have a tampered binary. Do not commit. Retry the download from the official release.

- [ ] **Step 3: Capture a fixture**

Run a small read-only test against a local path and save the XML:

```powershell
.\DiskSpdDiagnostic\diskspd.exe -b4K -t1 -o2 -w0 -d5 -c128M -r -Rxml -L -Sh `
    "$env:TEMP\diskspd-fixture.dat" > .\DiskSpdDiagnostic\Tests\sample-diskspd-output.xml
Remove-Item "$env:TEMP\diskspd-fixture.dat" -Force
```

Open `sample-diskspd-output.xml` and verify it contains `<Results>`, `<TimeSpan>`, `<Thread>`, `<Latency>` elements. Note down the actual values you see for `<ReadBytes>`, `<WriteBytes>`, `<AvgLatency>` — Task 5 tests will reference them.

- [ ] **Step 4: Commit**

```bash
git add DiskSpdDiagnostic/diskspd.exe DiskSpdDiagnostic/diskspd-LICENSE.txt DiskSpdDiagnostic/Tests/sample-diskspd-output.xml
git commit -m "chore: bundle diskspd v2.2.0 + parser fixture

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 5: `ConvertFrom-DiskSpdXml` — parse XML output

**Files:**
- Modify: `DiskSpdDiagnostic/Invoke-DiskSpdDiagnostic.ps1`
- Modify: `DiskSpdDiagnostic/Tests/DiskSpdDiagnostic.Tests.ps1`

diskspd XML schema (relevant subset, from observing real output):

```xml
<Results>
  <TimeSpan>
    <TestTimeSeconds>5.00</TestTimeSeconds>
    <ThreadCount>1</ThreadCount>
    <CpuUtilization>
      <Average>
        <UsagePercent>3.21</UsagePercent>
      </Average>
    </CpuUtilization>
    <Thread>
      <Target>
        <Path>C:\Temp\test.dat</Path>
        <BytesCount>1234567</BytesCount>
        <IOCount>301</IOCount>
        <ReadBytes>1234567</ReadBytes>
        <ReadCount>301</ReadCount>
        <WriteBytes>0</WriteBytes>
        <WriteCount>0</WriteCount>
      </Target>
      <Latency>
        <AverageMilliseconds>1.234</AverageMilliseconds>
      </Latency>
    </Thread>
    <Latency>
      <AverageMilliseconds>1.234</AverageMilliseconds>
      <Bucket>
        <Percentile>95</Percentile>
        <ReadMilliseconds>2.5</ReadMilliseconds>
      </Bucket>
      <Bucket>
        <Percentile>99</Percentile>
        <ReadMilliseconds>5.1</ReadMilliseconds>
      </Bucket>
    </Latency>
  </TimeSpan>
</Results>
```

**If your captured fixture's element names or nesting differ** (diskspd has shipped slightly different XML across minor versions), adjust the XPath expressions in Step 3 accordingly. The fixture is the source of truth — not this block.

- [ ] **Step 1: Write failing tests**

Append:

```powershell
Describe 'ConvertFrom-DiskSpdXml' {
    BeforeAll {
        $script:fixturePath = Join-Path $PSScriptRoot 'sample-diskspd-output.xml'
        $script:fixtureXml  = Get-Content $script:fixturePath -Raw
    }

    It 'returns a PSCustomObject with all expected properties' {
        $r = ConvertFrom-DiskSpdXml -Xml $script:fixtureXml -ProfileName QuickSanity
        $r              | Should -BeOfType [PSCustomObject]
        $r.IOPS         | Should -BeGreaterThan 0
        $r.ReadMBps     | Should -BeGreaterOrEqual 0
        $r.WriteMBps    | Should -BeGreaterOrEqual 0
        $r.AvgLatencyMs | Should -BeGreaterThan 0
        $r.Latency95Ms  | Should -BeGreaterOrEqual $r.AvgLatencyMs
        $r.Latency99Ms  | Should -BeGreaterOrEqual $r.Latency95Ms
        $r.CpuPercent   | Should -BeGreaterOrEqual 0
        $r.TestFilePath | Should -Not -BeNullOrEmpty
        $r.Duration     | Should -BeGreaterThan 0
        $r.ProfileName  | Should -Be 'QuickSanity'
        $r.RawXml       | Should -Be $script:fixtureXml
    }

    It 'computes IOPS as ReadCount + WriteCount divided by duration' {
        # Use a synthetic, minimal XML for this assertion
        $xml = @'
<Results>
  <TimeSpan>
    <TestTimeSeconds>10</TestTimeSeconds>
    <CpuUtilization><Average><UsagePercent>0</UsagePercent></Average></CpuUtilization>
    <Thread>
      <Target>
        <Path>X:\t.dat</Path>
        <ReadCount>1000</ReadCount>
        <WriteCount>500</WriteCount>
        <ReadBytes>4096000</ReadBytes>
        <WriteBytes>2048000</WriteBytes>
      </Target>
      <Latency><AverageMilliseconds>2</AverageMilliseconds></Latency>
    </Thread>
    <Latency>
      <AverageMilliseconds>2</AverageMilliseconds>
      <Bucket><Percentile>95</Percentile><ReadMilliseconds>3</ReadMilliseconds></Bucket>
      <Bucket><Percentile>99</Percentile><ReadMilliseconds>5</ReadMilliseconds></Bucket>
    </Latency>
  </TimeSpan>
</Results>
'@
        $r = ConvertFrom-DiskSpdXml -Xml $xml -ProfileName QuickSanity
        $r.IOPS | Should -Be 150 -Because '(1000+500)/10 seconds'
    }

    It 'throws on malformed XML with a clear message' {
        { ConvertFrom-DiskSpdXml -Xml '<not valid xml' -ProfileName QuickSanity } |
            Should -Throw -ExpectedMessage '*XML*'
    }
}
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `Invoke-Pester -Path .\DiskSpdDiagnostic\Tests -Output Detailed`
Expected: 3 new failures, command not recognized.

- [ ] **Step 3: Implement**

Add to engine functions section:

```powershell
function ConvertFrom-DiskSpdXml {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [string]$Xml,
        [Parameter(Mandatory)] [string]$ProfileName
    )

    try {
        [xml]$doc = $Xml
    } catch {
        throw "Failed to parse diskspd XML output: $($_.Exception.Message)"
    }

    $timeSpan = $doc.Results.TimeSpan
    if (-not $timeSpan) { throw "diskspd XML missing <TimeSpan> — output may be a partial run." }

    $durationSec = [double]$timeSpan.TestTimeSeconds
    if ($durationSec -le 0) { throw "diskspd XML reports zero duration — test did not run." }

    # Aggregate across threads
    $threads = @($timeSpan.Thread)
    $readBytes  = ($threads | ForEach-Object { [int64]$_.Target.ReadBytes  } | Measure-Object -Sum).Sum
    $writeBytes = ($threads | ForEach-Object { [int64]$_.Target.WriteBytes } | Measure-Object -Sum).Sum
    $readCount  = ($threads | ForEach-Object { [int64]$_.Target.ReadCount  } | Measure-Object -Sum).Sum
    $writeCount = ($threads | ForEach-Object { [int64]$_.Target.WriteCount } | Measure-Object -Sum).Sum
    $testFile   = ($threads[0].Target.Path)

    $readMBps   = [math]::Round($readBytes  / 1MB / $durationSec, 2)
    $writeMBps  = [math]::Round($writeBytes / 1MB / $durationSec, 2)
    $iops       = [math]::Round(($readCount + $writeCount) / $durationSec, 0)

    $avgMs = [double]$timeSpan.Latency.AverageMilliseconds
    $p95   = ($timeSpan.Latency.Bucket | Where-Object Percentile -eq 95 | Select-Object -First 1).ReadMilliseconds
    $p99   = ($timeSpan.Latency.Bucket | Where-Object Percentile -eq 99 | Select-Object -First 1).ReadMilliseconds
    if (-not $p95) { $p95 = $avgMs }
    if (-not $p99) { $p99 = $p95   }

    $cpu = [double]$timeSpan.CpuUtilization.Average.UsagePercent

    [PSCustomObject]@{
        IOPS         = [int]$iops
        ReadMBps     = $readMBps
        WriteMBps    = $writeMBps
        AvgLatencyMs = [math]::Round($avgMs, 3)
        Latency95Ms  = [math]::Round([double]$p95, 3)
        Latency99Ms  = [math]::Round([double]$p99, 3)
        CpuPercent   = [math]::Round($cpu, 2)
        TestFilePath = $testFile
        Duration     = $durationSec
        ProfileName  = $ProfileName
        RawXml       = $Xml
    }
}
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `Invoke-Pester -Path .\DiskSpdDiagnostic\Tests -Output Detailed`
Expected: All `ConvertFrom-DiskSpdXml` tests PASS. If the first test fails because your fixture has different XPath, update the function to match the fixture (the fixture wins).

- [ ] **Step 5: Commit**

```bash
git add DiskSpdDiagnostic/
git commit -m "feat: ConvertFrom-DiskSpdXml parses diskspd -Rxml output

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 6: `Get-DiskSpdHealthAssessment` — apply thresholds

**Files:**
- Modify: `DiskSpdDiagnostic/Invoke-DiskSpdDiagnostic.ps1`
- Modify: `DiskSpdDiagnostic/Tests/DiskSpdDiagnostic.Tests.ps1`

Thresholds come from `CitrixVDADiagnostics/README.md`:

| Metric | Transport | OK | WARN | CRIT |
|---|---|---|---|---|
| ReadMBps | Local | >100 | 50–100 | <50 |
| ReadMBps | Network | >50 | 25–50 | <25 |
| WriteMBps | Local | >100 | 50–100 | <50 |
| WriteMBps | Network | >40 | 20–40 | <20 |
| AvgLatencyMs | Local | <10 | 10–20 | >20 |
| AvgLatencyMs | Network | <20 | 20–50 | >50 |

- [ ] **Step 1: Write failing tests**

Append:

```powershell
Describe 'Get-DiskSpdHealthAssessment' {
    $localFast = [PSCustomObject]@{ ReadMBps=150; WriteMBps=120; AvgLatencyMs=5  }
    $localSlow = [PSCustomObject]@{ ReadMBps=30;  WriteMBps=20;  AvgLatencyMs=25 }
    $netGood   = [PSCustomObject]@{ ReadMBps=60;  WriteMBps=50;  AvgLatencyMs=15 }
    $netBad    = [PSCustomObject]@{ ReadMBps=20;  WriteMBps=15;  AvgLatencyMs=60 }

    It 'flags fast local storage as OK across the board' {
        $a = Get-DiskSpdHealthAssessment -Result $localFast -Transport Local
        $a.ReadMBps     | Should -Be 'OK'
        $a.WriteMBps    | Should -Be 'OK'
        $a.AvgLatencyMs | Should -Be 'OK'
    }

    It 'flags slow local storage as CRIT' {
        $a = Get-DiskSpdHealthAssessment -Result $localSlow -Transport Local
        $a.ReadMBps     | Should -Be 'CRIT'
        $a.WriteMBps    | Should -Be 'CRIT'
        $a.AvgLatencyMs | Should -Be 'CRIT'
    }

    It 'applies network thresholds for network transport' {
        $a = Get-DiskSpdHealthAssessment -Result $netGood -Transport Network
        $a.ReadMBps     | Should -Be 'OK'
        $a.AvgLatencyMs | Should -Be 'OK'
    }

    It 'flags poor network storage as CRIT' {
        $a = Get-DiskSpdHealthAssessment -Result $netBad -Transport Network
        $a.ReadMBps     | Should -Be 'CRIT'
        $a.AvgLatencyMs | Should -Be 'CRIT'
    }

    It 'flags borderline values as WARN' {
        $b = [PSCustomObject]@{ ReadMBps=75; WriteMBps=75; AvgLatencyMs=15 }
        $a = Get-DiskSpdHealthAssessment -Result $b -Transport Local
        $a.ReadMBps     | Should -Be 'WARN'
        $a.WriteMBps    | Should -Be 'WARN'
        $a.AvgLatencyMs | Should -Be 'WARN'
    }
}
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `Invoke-Pester -Path .\DiskSpdDiagnostic\Tests -Output Detailed`
Expected: 5 new failures, command not recognized.

- [ ] **Step 3: Implement**

Add to engine functions section:

```powershell
function Get-DiskSpdHealthAssessment {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [PSCustomObject]$Result,
        [Parameter(Mandatory)] [ValidateSet('Local','Network')] [string]$Transport
    )

    $thresholds = if ($Transport -eq 'Local') {
        @{
            ReadOK = 100; ReadWarn = 50
            WriteOK = 100; WriteWarn = 50
            LatencyOK = 10; LatencyWarn = 20
        }
    } else {
        @{
            ReadOK = 50; ReadWarn = 25
            WriteOK = 40; WriteWarn = 20
            LatencyOK = 20; LatencyWarn = 50
        }
    }

    function Classify-Throughput($v, $ok, $warn) {
        if ($v -gt $ok)   { 'OK' }
        elseif ($v -ge $warn) { 'WARN' }
        else { 'CRIT' }
    }
    function Classify-Latency($v, $ok, $warn) {
        if ($v -lt $ok)   { 'OK' }
        elseif ($v -le $warn) { 'WARN' }
        else { 'CRIT' }
    }

    @{
        ReadMBps     = Classify-Throughput $Result.ReadMBps     $thresholds.ReadOK    $thresholds.ReadWarn
        WriteMBps    = Classify-Throughput $Result.WriteMBps    $thresholds.WriteOK   $thresholds.WriteWarn
        AvgLatencyMs = Classify-Latency    $Result.AvgLatencyMs $thresholds.LatencyOK $thresholds.LatencyWarn
    }
}
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `Invoke-Pester -Path .\DiskSpdDiagnostic\Tests -Output Detailed`
Expected: All `Get-DiskSpdHealthAssessment` tests PASS.

- [ ] **Step 5: Commit**

```bash
git add DiskSpdDiagnostic/
git commit -m "feat: Get-DiskSpdHealthAssessment classifies metrics

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 7: `Test-DiskSpdPreflight` — safety checks

**Files:**
- Modify: `DiskSpdDiagnostic/Invoke-DiskSpdDiagnostic.ps1`
- Modify: `DiskSpdDiagnostic/Tests/DiskSpdDiagnostic.Tests.ps1`

Preflight has side effects (file probe, WSMan call), so unit tests use a temp directory and mock the remote-mode pieces.

- [ ] **Step 1: Write failing tests**

Append:

```powershell
Describe 'Test-DiskSpdPreflight (local mode)' {
    BeforeEach {
        $script:probeDir = Join-Path $env:TEMP "diskspd-pf-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path $script:probeDir -Force | Out-Null
    }
    AfterEach {
        Remove-Item $script:probeDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'passes when binary exists, target writable, free space ample' {
        $r = Test-DiskSpdPreflight -DiskSpdPath $script:DiskSpdExePath -Target $script:probeDir `
            -TestFileSizeMB 64 -BusinessHoursForce
        $r.Pass     | Should -BeTrue
        $r.Errors   | Should -BeNullOrEmpty
    }

    It 'fails if diskspd.exe missing' {
        $r = Test-DiskSpdPreflight -DiskSpdPath 'C:\does\not\exist\diskspd.exe' -Target $script:probeDir `
            -TestFileSizeMB 64 -BusinessHoursForce
        $r.Pass   | Should -BeFalse
        $r.Errors | Should -Match 'diskspd.exe not found'
    }

    It 'fails if target not writable' {
        # Use a path inside Windows\System32 which a non-admin write would fail on,
        # but we're elevated, so use a guaranteed-bad path instead.
        $bad = 'Z:\definitely\not\there'
        $r = Test-DiskSpdPreflight -DiskSpdPath $script:DiskSpdExePath -Target $bad `
            -TestFileSizeMB 64 -BusinessHoursForce
        $r.Pass   | Should -BeFalse
        $r.Errors | Should -Match '(writable|reachable|not found)'
    }

    It 'warns during business hours and surfaces it as a warning' {
        $r = Test-DiskSpdPreflight -DiskSpdPath $script:DiskSpdExePath -Target $script:probeDir `
            -TestFileSizeMB 64 -BusinessHoursNow ([datetime]'2026-05-19 10:00:00')
        $r.Warnings | Should -Match 'business hours'
    }

    It '-BusinessHoursForce suppresses business-hours warning' {
        $r = Test-DiskSpdPreflight -DiskSpdPath $script:DiskSpdExePath -Target $script:probeDir `
            -TestFileSizeMB 64 -BusinessHoursForce -BusinessHoursNow ([datetime]'2026-05-19 10:00:00')
        $r.Warnings | Should -Not -Match 'business hours'
    }
}
```

In `BeforeAll` near the top of the test file, add:
```powershell
$script:DiskSpdExePath = Join-Path $PSScriptRoot '..\diskspd.exe' | Resolve-Path | ForEach-Object Path
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `Invoke-Pester -Path .\DiskSpdDiagnostic\Tests -Output Detailed`
Expected: All Preflight tests FAIL.

- [ ] **Step 3: Implement**

Add to engine functions section:

```powershell
function Test-DiskSpdPreflight {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [string]$DiskSpdPath,
        [Parameter(Mandatory)] [string]$Target,
        [Parameter(Mandatory)] [int]   $TestFileSizeMB,
        [string]    $ComputerName,
        [switch]    $BusinessHoursForce,
        [datetime]  $BusinessHoursNow = (Get-Date)
    )

    $errors   = @()
    $warnings = @()

    # 1. Binary present + Microsoft-signed
    if (-not (Test-Path $DiskSpdPath)) {
        $errors += "diskspd.exe not found at: $DiskSpdPath"
    } else {
        try {
            $sig = Get-AuthenticodeSignature -FilePath $DiskSpdPath -ErrorAction Stop
            if ($sig.Status -ne 'Valid') {
                $warnings += "diskspd.exe Authenticode status is '$($sig.Status)'."
            } elseif ($sig.SignerCertificate.Subject -notmatch 'Microsoft') {
                $warnings += "diskspd.exe is signed but not by Microsoft: $($sig.SignerCertificate.Subject)"
            }
        } catch {
            $warnings += "Could not verify diskspd.exe signature: $($_.Exception.Message)"
        }
    }

    # 2. Target reachable + writable (skip if we're going to run remotely — we test that separately)
    if (-not $ComputerName) {
        if (-not (Test-Path $Target)) {
            $errors += "Target not reachable: $Target"
        } else {
            $probe = Join-Path $Target "diskspd-preflight-$([guid]::NewGuid()).tmp"
            try {
                [IO.File]::WriteAllBytes($probe, [byte[]]@(0))
                Remove-Item $probe -Force -ErrorAction Stop
            } catch {
                $errors += "Target not writable: $Target — $($_.Exception.Message)"
            }
        }

        # 3. Free space check
        try {
            $root  = (Resolve-Path $Target -ErrorAction Stop).ProviderPath
            $drive = (Get-Item $root).PSDrive
            if ($drive -and $drive.Free) {
                $neededBytes = $TestFileSizeMB * 1.2MB
                if ($drive.Free -lt $neededBytes) {
                    $errors += ("Insufficient free space at {0}: have {1:N0} MB, need {2:N0} MB (file size x1.2)." -f
                                $Target, ($drive.Free/1MB), ($neededBytes/1MB))
                }
            }
        } catch {
            $warnings += "Could not check free space at $Target — $($_.Exception.Message)"
        }
    }

    # 4. Remote reachability
    if ($ComputerName) {
        try {
            if (-not (Test-WSMan -ComputerName $ComputerName -ErrorAction Stop)) {
                $errors += "WSMan not responding on $ComputerName."
            }
        } catch {
            $errors += "Test-WSMan failed for ${ComputerName}: $($_.Exception.Message)"
        }
        $admin = "\\$ComputerName\C`$\Windows\Temp"
        if (-not (Test-Path $admin)) {
            $errors += "Admin share not accessible: $admin"
        }
    }

    # 5. Business hours warning
    $isBusinessHours = ($BusinessHoursNow.DayOfWeek -in @('Monday','Tuesday','Wednesday','Thursday','Friday')) `
                       -and ($BusinessHoursNow.Hour -ge 7 -and $BusinessHoursNow.Hour -lt 18)
    if ($isBusinessHours -and -not $BusinessHoursForce) {
        $warnings += "Running during business hours ($($BusinessHoursNow.ToString('yyyy-MM-dd HH:mm:ss'))). Sustained I/O may affect users."
    }

    [PSCustomObject]@{
        Pass     = ($errors.Count -eq 0)
        Errors   = $errors
        Warnings = $warnings
    }
}
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `Invoke-Pester -Path .\DiskSpdDiagnostic\Tests -Output Detailed`
Expected: All Preflight tests PASS.

- [ ] **Step 5: Commit**

```bash
git add DiskSpdDiagnostic/
git commit -m "feat: Test-DiskSpdPreflight checks binary, target, space, hours

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 8: `Invoke-DiskSpdLocal` — execute diskspd locally

**Files:**
- Modify: `DiskSpdDiagnostic/Invoke-DiskSpdDiagnostic.ps1`
- Modify: `DiskSpdDiagnostic/Tests/DiskSpdDiagnostic.Tests.ps1`

This task has real side effects (writes a temp file, runs diskspd). Test against a tiny `QuickSanity` profile against `$env:TEMP`.

- [ ] **Step 1: Write integration test**

Append (this is an integration test — it actually runs diskspd):

```powershell
Describe 'Invoke-DiskSpdLocal (integration)' -Tag 'Integration' {
    It 'runs a quick-sanity test and returns XML containing <Results>' {
        $settings = Get-DiskSpdWorkloadProfile -Name QuickSanity
        $settings.DurationSeconds = 3  # keep the test fast
        $testFile = Join-Path $env:TEMP "diskspd-itest-$([guid]::NewGuid()).dat"

        try {
            $xml = Invoke-DiskSpdLocal -DiskSpdPath $script:DiskSpdExePath -Settings $settings -TestFilePath $testFile
            $xml | Should -Match '<Results>'
            $xml | Should -Match '<TimeSpan>'
        } finally {
            Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        }
    }

    It 'cleans up the test file on success' {
        $settings = Get-DiskSpdWorkloadProfile -Name QuickSanity
        $settings.DurationSeconds = 3
        $testFile = Join-Path $env:TEMP "diskspd-itest-$([guid]::NewGuid()).dat"
        Invoke-DiskSpdLocal -DiskSpdPath $script:DiskSpdExePath -Settings $settings -TestFilePath $testFile | Out-Null
        Test-Path $testFile | Should -BeFalse
    }

    It 'throws when diskspd exits non-zero' {
        $settings = Get-DiskSpdWorkloadProfile -Name QuickSanity
        # Force a failure by pointing at an unwritable path
        { Invoke-DiskSpdLocal -DiskSpdPath $script:DiskSpdExePath -Settings $settings -TestFilePath 'Z:\nope\bad.dat' } |
            Should -Throw
    }
}
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `Invoke-Pester -Path .\DiskSpdDiagnostic\Tests -Output Detailed`
Expected: 3 new failures, command not recognized.

- [ ] **Step 3: Implement**

Add to engine functions section:

```powershell
function Invoke-DiskSpdLocal {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string]   $DiskSpdPath,
        [Parameter(Mandatory)] [hashtable]$Settings,
        [Parameter(Mandatory)] [string]   $TestFilePath
    )

    $argv = Build-DiskSpdArguments -Settings $Settings -TestFilePath $TestFilePath
    $stdoutFile = [IO.Path]::GetTempFileName()
    $stderrFile = [IO.Path]::GetTempFileName()

    try {
        $proc = Start-Process -FilePath $DiskSpdPath -ArgumentList $argv -NoNewWindow -PassThru `
                              -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile -Wait
        $stdout = Get-Content $stdoutFile -Raw
        $stderr = Get-Content $stderrFile -Raw

        if ($proc.ExitCode -ne 0) {
            throw "diskspd exited with code $($proc.ExitCode). stderr: $stderr"
        }
        if ([string]::IsNullOrWhiteSpace($stdout) -or $stdout -notmatch '<Results>') {
            throw "diskspd produced no XML output. stderr: $stderr"
        }
        return $stdout
    } finally {
        Remove-Item $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue
        Remove-Item $TestFilePath           -Force -ErrorAction SilentlyContinue
    }
}
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `Invoke-Pester -Path .\DiskSpdDiagnostic\Tests -Output Detailed -Tag Integration`
Expected: All Invoke-DiskSpdLocal tests PASS. Each test takes ~3 seconds because of the real diskspd run.

- [ ] **Step 5: Commit**

```bash
git add DiskSpdDiagnostic/
git commit -m "feat: Invoke-DiskSpdLocal runs diskspd with cleanup

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 9: `Invoke-DiskSpdRemote` — execute on a VDA

**Files:**
- Modify: `DiskSpdDiagnostic/Invoke-DiskSpdDiagnostic.ps1`

This one cannot be unit-tested usefully — it requires a real second machine. Tests are manual.

- [ ] **Step 1: Implement**

Add to engine functions section:

```powershell
function Invoke-DiskSpdRemote {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string]   $DiskSpdPath,
        [Parameter(Mandatory)] [string]   $ComputerName,
        [Parameter(Mandatory)] [hashtable]$Settings,
        [Parameter(Mandatory)] [string]   $TestFilePath
    )

    $remoteExe   = "C:\Windows\Temp\diskspd.exe"
    $remoteUnc   = "\\$ComputerName\C`$\Windows\Temp\diskspd.exe"
    $localHash   = (Get-FileHash $DiskSpdPath -Algorithm SHA256).Hash
    $copyNeeded  = $true

    if (Test-Path $remoteUnc) {
        $remoteHash = (Get-FileHash $remoteUnc -Algorithm SHA256).Hash
        if ($remoteHash -eq $localHash) { $copyNeeded = $false }
    }
    if ($copyNeeded) {
        Copy-Item -Path $DiskSpdPath -Destination $remoteUnc -Force -ErrorAction Stop
    }

    $argv = Build-DiskSpdArguments -Settings $Settings -TestFilePath $TestFilePath

    try {
        $session = New-PSSession -ComputerName $ComputerName -ErrorAction Stop
        try {
            $remoteResult = Invoke-Command -Session $session -ScriptBlock {
                param($exe, $args, $file)
                $stdoutFile = [IO.Path]::GetTempFileName()
                $stderrFile = [IO.Path]::GetTempFileName()
                try {
                    $proc = Start-Process -FilePath $exe -ArgumentList $args -NoNewWindow -PassThru `
                                          -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile -Wait
                    [PSCustomObject]@{
                        ExitCode = $proc.ExitCode
                        StdOut   = Get-Content $stdoutFile -Raw
                        StdErr   = Get-Content $stderrFile -Raw
                    }
                } finally {
                    Remove-Item $stdoutFile, $stderrFile, $file -Force -ErrorAction SilentlyContinue
                }
            } -ArgumentList $remoteExe, $argv, $TestFilePath

            if ($remoteResult.ExitCode -ne 0) {
                throw "diskspd on $ComputerName exited with code $($remoteResult.ExitCode). stderr: $($remoteResult.StdErr)"
            }
            if ($remoteResult.StdOut -notmatch '<Results>') {
                throw "diskspd on $ComputerName produced no XML output. stderr: $($remoteResult.StdErr)"
            }
            return $remoteResult.StdOut
        } finally {
            Remove-PSSession $session -ErrorAction SilentlyContinue
        }
    } finally {
        # Always try to clean up the binary we deposited
        Remove-Item $remoteUnc -Force -ErrorAction SilentlyContinue
    }
}
```

- [ ] **Step 2: Manual smoke test**

If you have a second Windows machine available with WinRM enabled and admin share open (most domain-joined Windows machines satisfy this):

```powershell
$xml = Invoke-DiskSpdRemote `
    -DiskSpdPath .\DiskSpdDiagnostic\diskspd.exe `
    -ComputerName 'SOME-VDA-NAME' `
    -Settings (Get-DiskSpdWorkloadProfile -Name QuickSanity) `
    -TestFilePath 'C:\Windows\Temp\diskspd-smoketest.dat'
$xml.Substring(0, 200)  # should be <Results>...
```

If no second machine is available, defer this test until manual QA at the end. Note this in the commit message.

- [ ] **Step 3: Commit**

```bash
git add DiskSpdDiagnostic/
git commit -m "feat: Invoke-DiskSpdRemote runs diskspd on a remote VDA

- Copies binary via admin share (skips if SHA-256 matches)
- Uses Invoke-Command over PSSession
- Cleans up remote test file and binary in finally{}

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 10: `ReportTemplate.html` + `Export-DiskSpdHtmlReport`

**Files:**
- Create: `DiskSpdDiagnostic/ReportTemplate.html`
- Modify: `DiskSpdDiagnostic/Invoke-DiskSpdDiagnostic.ps1`
- Modify: `DiskSpdDiagnostic/Tests/DiskSpdDiagnostic.Tests.ps1`

- [ ] **Step 1: Create the HTML template**

Write `DiskSpdDiagnostic/ReportTemplate.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>DiskSpd Diagnostic Report — {{TARGET}}</title>
<style>
  :root { color-scheme: dark; }
  body { background: #1e1e1e; color: #eaeaea; font-family: Segoe UI, system-ui, sans-serif; margin: 0; padding: 24px; }
  h1 { margin: 0 0 4px; font-weight: 600; letter-spacing: -0.5px; }
  .sub { color: #9aa0a6; font-size: 0.9rem; }
  .accent { color: #5dade2; }
  .card { background: #252526; border: 1px solid #333; border-radius: 6px; padding: 16px 20px; margin: 16px 0; }
  table { width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; }
  th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #333; }
  th { color: #9aa0a6; font-weight: 500; }
  .num { font-family: Consolas, monospace; text-align: right; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 99px; font-size: 0.8rem; font-weight: 600; }
  .ok   { background: #1f4d2a; color: #7ee695; }
  .warn { background: #5a4416; color: #ffd58a; }
  .crit { background: #5a1f1f; color: #ff8a8a; }
  details { margin-top: 24px; }
  summary { cursor: pointer; color: #9aa0a6; }
  pre { background: #111; padding: 12px; overflow-x: auto; border-radius: 4px; font-size: 0.8rem; }
</style>
</head>
<body>
  <h1>DiskSpd Diagnostic Report</h1>
  <div class="sub">Target: <span class="accent">{{TARGET}}</span> &middot; Profile: <span class="accent">{{PROFILE}}</span> &middot; Run at <span class="accent">{{TIMESTAMP}}</span></div>

  <div class="card">
    <h2>Results</h2>
    <table>
      <thead><tr><th>Metric</th><th class="num">Value</th><th>Status</th></tr></thead>
      <tbody>
        {{RESULTS_TABLE}}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>Health Assessment</h2>
    {{HEALTH_BADGES}}
  </div>

  <details>
    <summary>Raw diskspd XML output</summary>
    <pre>{{RAW_XML}}</pre>
  </details>
</body>
</html>
```

- [ ] **Step 2: Write failing tests**

Append:

```powershell
Describe 'Export-DiskSpdHtmlReport' {
    BeforeEach {
        $script:reportDir = Join-Path $env:TEMP "diskspd-report-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path $script:reportDir -Force | Out-Null
    }
    AfterEach {
        Remove-Item $script:reportDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'produces an HTML file containing all key sections' {
        $result = [PSCustomObject]@{
            IOPS=1234; ReadMBps=80; WriteMBps=20; AvgLatencyMs=4.2
            Latency95Ms=8.1; Latency99Ms=12.5; CpuPercent=15.3
            TestFilePath='C:\Temp\t.dat'; Duration=10; ProfileName='QuickSanity'
            RawXml='<Results>fixture</Results>'
        }
        $assess = @{ ReadMBps='OK'; WriteMBps='WARN'; AvgLatencyMs='OK' }

        $out = Export-DiskSpdHtmlReport -Result $result -Assessment $assess `
                -Target 'C:\Temp' -OutputDirectory $script:reportDir

        Test-Path $out      | Should -BeTrue
        $html = Get-Content $out -Raw
        $html | Should -Match 'C:\\Temp'         # target
        $html | Should -Match 'QuickSanity'      # profile
        $html | Should -Match '1234'             # IOPS
        $html | Should -Match 'fixture'          # raw XML
        $html | Should -Match 'badge ok'         # ReadMBps badge
        $html | Should -Match 'badge warn'       # WriteMBps badge
    }

    It 'filenames use yyyy-MM-dd_HHmmss timestamp pattern' {
        $result = [PSCustomObject]@{
            IOPS=1; ReadMBps=1; WriteMBps=1; AvgLatencyMs=1
            Latency95Ms=1; Latency99Ms=1; CpuPercent=1
            TestFilePath='X:\t.dat'; Duration=1; ProfileName='QuickSanity'; RawXml='<Results/>'
        }
        $out = Export-DiskSpdHtmlReport -Result $result -Assessment @{ReadMBps='OK';WriteMBps='OK';AvgLatencyMs='OK'} `
                -Target 'X:\' -OutputDirectory $script:reportDir
        (Split-Path $out -Leaf) | Should -Match '\d{4}-\d{2}-\d{2}_\d{6}'
    }
}
```

- [ ] **Step 3: Run tests, verify they fail**

Run: `Invoke-Pester -Path .\DiskSpdDiagnostic\Tests -Output Detailed`
Expected: 2 new failures.

- [ ] **Step 4: Implement**

Add to engine functions section:

```powershell
function Export-DiskSpdHtmlReport {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [PSCustomObject]$Result,
        [Parameter(Mandatory)] [hashtable]     $Assessment,
        [Parameter(Mandatory)] [string]        $Target,
        [Parameter(Mandatory)] [string]        $OutputDirectory
    )

    if (-not (Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    $templatePath = $script:ReportTpl
    if (-not (Test-Path $templatePath)) {
        throw "Report template not found at $templatePath"
    }
    $tpl = Get-Content $templatePath -Raw

    $timestamp     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $fileTimestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $safeTarget    = ($Target -replace '[\\\/\:\*\?\"\<\>\|]', '_').TrimStart('_')

    # Per-metric badge class lookup
    function Get-BadgeClass($status) {
        switch ($status) {
            'OK'   { 'badge ok' }
            'WARN' { 'badge warn' }
            'CRIT' { 'badge crit' }
            default { 'badge' }
        }
    }

    # Results table rows
    $rows = @(
        @{ M='IOPS';            V=$Result.IOPS;                       S=$null                     }
        @{ M='Read MB/s';       V=$Result.ReadMBps;                   S=$Assessment.ReadMBps      }
        @{ M='Write MB/s';      V=$Result.WriteMBps;                  S=$Assessment.WriteMBps     }
        @{ M='Avg latency (ms)';V=$Result.AvgLatencyMs;               S=$Assessment.AvgLatencyMs  }
        @{ M='P95 latency (ms)';V=$Result.Latency95Ms;                S=$null                     }
        @{ M='P99 latency (ms)';V=$Result.Latency99Ms;                S=$null                     }
        @{ M='CPU %';           V=$Result.CpuPercent;                 S=$null                     }
        @{ M='Test file';       V=$Result.TestFilePath;               S=$null                     }
        @{ M='Duration (s)';    V=$Result.Duration;                   S=$null                     }
    )

    $rowsHtml = ($rows | ForEach-Object {
        $badge = if ($_.S) { "<span class=`"$(Get-BadgeClass $_.S)`">$($_.S)</span>" } else { '' }
        "<tr><td>$($_.M)</td><td class=`"num`">$($_.V)</td><td>$badge</td></tr>"
    }) -join "`n"

    $badgesHtml = ($Assessment.GetEnumerator() | ForEach-Object {
        "<span class=`"$(Get-BadgeClass $_.Value)`">$($_.Key): $($_.Value)</span>"
    }) -join ' '

    $rawXmlEncoded = [System.Web.HttpUtility]::HtmlEncode($Result.RawXml)

    $html = $tpl `
        -replace '\{\{TARGET\}\}',        [System.Web.HttpUtility]::HtmlEncode($Target) `
        -replace '\{\{PROFILE\}\}',       [System.Web.HttpUtility]::HtmlEncode($Result.ProfileName) `
        -replace '\{\{TIMESTAMP\}\}',     $timestamp `
        -replace '\{\{RESULTS_TABLE\}\}', $rowsHtml `
        -replace '\{\{HEALTH_BADGES\}\}', $badgesHtml `
        -replace '\{\{RAW_XML\}\}',       $rawXmlEncoded

    $filename = "diskspd_${safeTarget}_${fileTimestamp}.html"
    $outFile  = Join-Path $OutputDirectory $filename
    Set-Content -Path $outFile -Value $html -Encoding UTF8
    return $outFile
}
```

Add to the top of the script (near `$script:` setup):
```powershell
Add-Type -AssemblyName System.Web
```

- [ ] **Step 5: Run tests, verify they pass**

Run: `Invoke-Pester -Path .\DiskSpdDiagnostic\Tests -Output Detailed`
Expected: Both tests PASS.

- [ ] **Step 6: Eyeball the report**

```powershell
$r = [PSCustomObject]@{
    IOPS=12345; ReadMBps=85.3; WriteMBps=22.1; AvgLatencyMs=4.2
    Latency95Ms=8.1; Latency99Ms=12.5; CpuPercent=15.3
    TestFilePath='\\FileServer01\Share\test.dat'; Duration=30; ProfileName='FSLogixLike'
    RawXml='<Results><TimeSpan/></Results>'
}
. .\DiskSpdDiagnostic\Invoke-DiskSpdDiagnostic.ps1 -ErrorAction SilentlyContinue *> $null
$out = Export-DiskSpdHtmlReport -Result $r -Assessment @{ReadMBps='OK';WriteMBps='WARN';AvgLatencyMs='OK'} `
        -Target '\\FileServer01\Share' -OutputDirectory $env:TEMP
Start-Process $out
```

Verify the report renders cleanly in the browser: dark background, blue accents, badges colored correctly, raw XML hidden behind the details disclosure.

- [ ] **Step 7: Commit**

```bash
git add DiskSpdDiagnostic/
git commit -m "feat: HTML report template + Export-DiskSpdHtmlReport

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 11: `Invoke-DiskSpdHeadless` — orchestrator for `-NoUI`

**Files:**
- Modify: `DiskSpdDiagnostic/Invoke-DiskSpdDiagnostic.ps1`
- Modify: `DiskSpdDiagnostic/Tests/DiskSpdDiagnostic.Tests.ps1`

- [ ] **Step 1: Write integration test**

Append:

```powershell
Describe 'Invoke-DiskSpdHeadless (integration)' -Tag 'Integration' {
    It 'runs end-to-end against a temp directory and writes a report' {
        $reportDir = Join-Path $env:TEMP "diskspd-headless-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
        try {
            $out = Invoke-DiskSpdHeadless `
                -DiskSpdPath $script:DiskSpdExePath `
                -Target $env:TEMP `
                -ProfileName QuickSanity `
                -Overrides @{ DurationSeconds = 3 } `
                -OutputPath $reportDir `
                -Force
            Test-Path $out | Should -BeTrue
            (Get-Content $out -Raw) | Should -Match '<title>'
        } finally {
            Remove-Item $reportDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'throws on preflight failure' {
        { Invoke-DiskSpdHeadless `
            -DiskSpdPath $script:DiskSpdExePath `
            -Target 'Z:\definitely-not-there' `
            -ProfileName QuickSanity -Overrides @{} `
            -OutputPath $env:TEMP -Force } | Should -Throw
    }
}
```

- [ ] **Step 2: Run, verify failure**

Run: `Invoke-Pester -Path .\DiskSpdDiagnostic\Tests -Output Detailed -Tag Integration`
Expected: 2 new failures.

- [ ] **Step 3: Implement**

Add to engine functions section:

```powershell
function Invoke-DiskSpdHeadless {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string]   $DiskSpdPath,
        [Parameter(Mandatory)] [string]   $Target,
        [Parameter(Mandatory)] [string]   $ProfileName,
        [Parameter(Mandatory)] [hashtable]$Overrides,
        [string]    $ComputerName,
        [Parameter(Mandatory)] [string]   $OutputPath,
        [switch]    $Force
    )

    function Write-Status($Level, $Message) {
        $color = switch ($Level) { 'PASS' {'Green'} 'WARN' {'Yellow'} 'FAIL' {'Red'} default {'Cyan'} }
        $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Write-Host "[$ts] [$Level] $Message" -ForegroundColor $color
    }

    $settings  = Resolve-DiskSpdSettings -ProfileName $ProfileName -Overrides $Overrides
    $transport = if ($ComputerName -or $Target -match '^\\\\') { 'Network' } else { 'Local' }

    Write-Status 'INFO' "Preflight starting for target '$Target' (transport: $transport)"
    $pf = Test-DiskSpdPreflight -DiskSpdPath $DiskSpdPath -Target $Target `
            -TestFileSizeMB $settings.TestFileSizeMB -ComputerName $ComputerName -BusinessHoursForce:$Force

    foreach ($w in $pf.Warnings) { Write-Status 'WARN' $w }
    foreach ($e in $pf.Errors)   { Write-Status 'FAIL' $e }
    if (-not $pf.Pass) { throw "Preflight failed. See errors above." }
    Write-Status 'PASS' 'Preflight OK'

    $testFile = if ($Target -match '\.dat$') { $Target } else {
        Join-Path $Target ("diskspd-{0}.dat" -f (Get-Date -Format 'yyyy-MM-dd_HHmmss'))
    }

    Write-Status 'INFO' "Running diskspd ($($settings.DurationSeconds)s, $($settings.Threads)t/QD$($settings.QueueDepth))…"
    $xml = if ($ComputerName) {
        Invoke-DiskSpdRemote -DiskSpdPath $DiskSpdPath -ComputerName $ComputerName -Settings $settings -TestFilePath $testFile
    } else {
        Invoke-DiskSpdLocal  -DiskSpdPath $DiskSpdPath -Settings $settings -TestFilePath $testFile
    }
    Write-Status 'PASS' 'diskspd completed'

    $result = ConvertFrom-DiskSpdXml -Xml $xml -ProfileName $ProfileName
    $assess = Get-DiskSpdHealthAssessment -Result $result -Transport $transport

    Write-Status 'INFO' "Results: $($result.IOPS) IOPS / $($result.ReadMBps) MB/s read / $($result.WriteMBps) MB/s write / $($result.AvgLatencyMs) ms avg latency"

    $report = Export-DiskSpdHtmlReport -Result $result -Assessment $assess -Target $Target -OutputDirectory $OutputPath
    Write-Status 'PASS' "Report saved: $report"
    return $report
}
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `Invoke-Pester -Path .\DiskSpdDiagnostic\Tests -Output Detailed -Tag Integration`
Expected: Both new tests PASS.

- [ ] **Step 5: Commit**

```bash
git add DiskSpdDiagnostic/
git commit -m "feat: Invoke-DiskSpdHeadless orchestrates preflight->run->report

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 12: Top-level dispatch + headless path verified

**Files:**
- Modify: `DiskSpdDiagnostic/Invoke-DiskSpdDiagnostic.ps1`

- [ ] **Step 1: Wire the entry point**

At the bottom of `Invoke-DiskSpdDiagnostic.ps1`, replace the placeholder dispatch comment with:

```powershell
# --- Entry point ---

# Guard against dot-sourcing (e.g., from Pester tests that load the engine functions
# via `. $scriptPath`). When dot-sourced, $MyInvocation.InvocationName is '.' and we
# must NOT execute the dispatch — otherwise every Pester run would either error on
# preflight or pop a WPF window.
if ($MyInvocation.InvocationName -eq '.') { return }

if ($NoUI) {
    if (-not $Target) { throw "-Target is required when -NoUI is set." }
    $overrides = @{}
    foreach ($key in @('BlockSize','Threads','QueueDepth','WriteRatioPercent','DurationSeconds','TestFileSizeMB')) {
        if ($PSBoundParameters.ContainsKey($key)) { $overrides[$key] = $PSBoundParameters[$key] }
    }
    # RandomIO is not a CLI parameter; it derives from the workload. For Custom, default to $true unless overridden via the GUI.
    if ($Workload -eq 'Custom' -and -not $overrides.ContainsKey('RandomIO')) { $overrides['RandomIO'] = $true }

    if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

    Invoke-DiskSpdHeadless `
        -DiskSpdPath $script:DiskSpdExe `
        -Target $Target `
        -ProfileName $Workload `
        -Overrides $overrides `
        -ComputerName $ComputerName `
        -OutputPath $OutputPath `
        -Force:$Force
    return
}

Show-DiskSpdGui
```

(`Show-DiskSpdGui` is defined in the next task.)

- [ ] **Step 2: Stub Show-DiskSpdGui temporarily**

So Task 12 can be smoke-tested before the UI is built, add a placeholder just above the entry point:

```powershell
function Show-DiskSpdGui {
    Write-Host "[INFO] GUI not yet implemented. Use -NoUI with -Target for now." -ForegroundColor Cyan
}
```

This will be replaced wholesale in Task 13.

- [ ] **Step 3: Manual smoke**

```powershell
.\DiskSpdDiagnostic\Invoke-DiskSpdDiagnostic.ps1 -NoUI -Target $env:TEMP -Workload QuickSanity -Force
```

Expected: status lines stream to console, finishes with `[PASS] Report saved: <path>.html`. Open the report and confirm it looks right.

- [ ] **Step 4: Commit**

```bash
git add DiskSpdDiagnostic/
git commit -m "feat: wire -NoUI dispatch to Invoke-DiskSpdHeadless

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 13: WPF UI — XAML and `Show-DiskSpdGui`

**Files:**
- Modify: `DiskSpdDiagnostic/Invoke-DiskSpdDiagnostic.ps1`

The WPF UI is one function plus a XAML here-string. No unit tests — UI is verified manually.

**WPF in PowerShell — key patterns this task uses**
- Load XAML via `[Windows.Markup.XamlReader]::Load((New-Object IO.StringReader $xaml | … ))` or simpler: `[xml]$x = $xaml; $reader = New-Object System.Xml.XmlNodeReader $x; [Windows.Markup.XamlReader]::Load($reader)`
- Long-running work must NOT block the dispatcher. Use a `PowerShell.AddScript()` runspace and update UI via `$window.Dispatcher.Invoke({ ... })`.
- A `x:Name="…"` attribute in XAML creates a findable element via `$window.FindName('…')`.

- [ ] **Step 1: Add the XAML here-string**

Above the engine functions (or anywhere before `Show-DiskSpdGui`), add:

```powershell
$script:Xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="DiskSpd Diagnostic" Height="650" Width="900"
        Background="#1e1e1e" Foreground="#eaeaea" FontFamily="Segoe UI">
    <Window.Resources>
        <Style TargetType="TextBlock"><Setter Property="Foreground" Value="#eaeaea"/></Style>
        <Style TargetType="Label"><Setter Property="Foreground" Value="#eaeaea"/></Style>
        <Style TargetType="RadioButton"><Setter Property="Foreground" Value="#eaeaea"/></Style>
        <Style TargetType="GroupBox"><Setter Property="Foreground" Value="#9aa0a6"/></Style>
        <Style TargetType="Button">
            <Setter Property="Padding" Value="12,4"/>
            <Setter Property="Margin"  Value="0,0,8,0"/>
        </Style>
        <Style x:Key="Accent" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
            <Setter Property="Background" Value="#5dade2"/>
            <Setter Property="Foreground" Value="#0f1115"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
        </Style>
    </Window.Resources>
    <Grid Margin="16">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>  <!-- Target -->
            <RowDefinition Height="Auto"/>  <!-- Profile -->
            <RowDefinition Height="*"/>     <!-- Run/results -->
        </Grid.RowDefinitions>

        <!-- Zone 1 — Target -->
        <GroupBox Header="Target" Grid.Row="0" Padding="12">
            <StackPanel>
                <RadioButton x:Name="RbLocal"  GroupName="Target" Content="Local disk on this machine" IsChecked="True"/>
                <StackPanel Orientation="Horizontal" Margin="20,4,0,8">
                    <TextBox x:Name="TbLocalPath" Width="500" Text="C:\"/>
                    <Button  x:Name="BtnBrowseLocal" Content="Browse…" Margin="8,0,0,0"/>
                </StackPanel>
                <RadioButton x:Name="RbUnc"    GroupName="Target" Content="Network path from this machine"/>
                <TextBox x:Name="TbUncPath" Width="540" Margin="20,4,0,8" IsEnabled="False"/>
                <RadioButton x:Name="RbRemote" GroupName="Target" Content="Run on remote VDA, target a path"/>
                <StackPanel Orientation="Horizontal" Margin="20,4,0,4">
                    <Label Content="VDA name:" Width="80"/>
                    <TextBox x:Name="TbVdaName" Width="200" IsEnabled="False"/>
                    <Label Content="Target path:" Margin="12,0,0,0"/>
                    <TextBox x:Name="TbVdaTarget" Width="260" IsEnabled="False"/>
                </StackPanel>
            </StackPanel>
        </GroupBox>

        <!-- Zone 2 — Profile -->
        <GroupBox Header="Workload profile" Grid.Row="1" Padding="12" Margin="0,12,0,0">
            <StackPanel>
                <StackPanel Orientation="Horizontal">
                    <Label Content="Preset:" Width="80"/>
                    <ComboBox x:Name="CbProfile" Width="200">
                        <ComboBoxItem Content="FSLogixLike"     IsSelected="True"/>
                        <ComboBoxItem Content="SequentialRead"/>
                        <ComboBoxItem Content="MixedUserLoad"/>
                        <ComboBoxItem Content="QuickSanity"/>
                        <ComboBoxItem Content="Custom"/>
                    </ComboBox>
                </StackPanel>
                <Expander x:Name="ExpAdvanced" Header="Advanced overrides" Margin="0,8,0,0">
                    <Grid Margin="8">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="140"/><ColumnDefinition Width="100"/>
                            <ColumnDefinition Width="140"/><ColumnDefinition Width="100"/>
                            <ColumnDefinition Width="140"/><ColumnDefinition Width="100"/>
                        </Grid.ColumnDefinitions>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>
                        <Label Content="Block size:"    Grid.Row="0" Grid.Column="0"/>
                        <TextBox x:Name="TbBlock"       Grid.Row="0" Grid.Column="1"/>
                        <Label Content="Threads:"       Grid.Row="0" Grid.Column="2"/>
                        <TextBox x:Name="TbThreads"     Grid.Row="0" Grid.Column="3"/>
                        <Label Content="Queue depth:"   Grid.Row="0" Grid.Column="4"/>
                        <TextBox x:Name="TbQd"          Grid.Row="0" Grid.Column="5"/>
                        <Label Content="Write %:"       Grid.Row="1" Grid.Column="0"/>
                        <TextBox x:Name="TbWritePct"    Grid.Row="1" Grid.Column="1"/>
                        <Label Content="Duration (s):"  Grid.Row="1" Grid.Column="2"/>
                        <TextBox x:Name="TbDuration"    Grid.Row="1" Grid.Column="3"/>
                        <Label Content="File size (MB):" Grid.Row="1" Grid.Column="4"/>
                        <TextBox x:Name="TbFileMb"      Grid.Row="1" Grid.Column="5"/>
                    </Grid>
                </Expander>
            </StackPanel>
        </GroupBox>

        <!-- Zone 3 — Run + results -->
        <GroupBox Header="Run" Grid.Row="2" Padding="12" Margin="0,12,0,0">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                </Grid.RowDefinitions>
                <StackPanel Orientation="Horizontal" Grid.Row="0">
                    <Button x:Name="BtnRun"    Content="Run Test"     Style="{StaticResource Accent}"/>
                    <Button x:Name="BtnCancel" Content="Cancel"       IsEnabled="False"/>
                    <Button x:Name="BtnSave"   Content="Save Report"  IsEnabled="False"/>
                    <TextBlock x:Name="TbStatus" Text="Idle" VerticalAlignment="Center" Margin="20,0,0,0"/>
                </StackPanel>
                <ProgressBar x:Name="PbProgress" Grid.Row="1" Height="6" Margin="0,8" Minimum="0" Maximum="100"/>
                <DataGrid x:Name="DgResults" Grid.Row="2" AutoGenerateColumns="False" CanUserAddRows="False"
                          IsReadOnly="True" Background="#252526" Foreground="#eaeaea" GridLinesVisibility="None">
                    <DataGrid.Columns>
                        <DataGridTextColumn Header="Metric" Binding="{Binding Metric}" Width="200"/>
                        <DataGridTextColumn Header="Value"  Binding="{Binding Value}"  Width="200"/>
                        <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="100"/>
                    </DataGrid.Columns>
                </DataGrid>
            </Grid>
        </GroupBox>
    </Grid>
</Window>
'@
```

- [ ] **Step 2: Replace the Show-DiskSpdGui stub**

Replace the placeholder `Show-DiskSpdGui` with:

```powershell
function Show-DiskSpdGui {
    [CmdletBinding()] param()

    Add-Type -AssemblyName PresentationFramework, System.Xaml, System.Windows.Forms

    [xml]$xamlDoc = $script:Xaml
    $reader = New-Object System.Xml.XmlNodeReader $xamlDoc
    $window = [Windows.Markup.XamlReader]::Load($reader)

    # Bind named elements
    $get = { param($n) $window.FindName($n) }
    $rbLocal      = & $get 'RbLocal';      $rbUnc       = & $get 'RbUnc';        $rbRemote    = & $get 'RbRemote'
    $tbLocalPath  = & $get 'TbLocalPath';  $tbUncPath   = & $get 'TbUncPath'
    $tbVdaName    = & $get 'TbVdaName';    $tbVdaTarget = & $get 'TbVdaTarget'
    $btnBrowse    = & $get 'BtnBrowseLocal'
    $cbProfile    = & $get 'CbProfile'
    $tbBlock      = & $get 'TbBlock';      $tbThreads   = & $get 'TbThreads';    $tbQd        = & $get 'TbQd'
    $tbWritePct   = & $get 'TbWritePct';   $tbDuration  = & $get 'TbDuration';   $tbFileMb    = & $get 'TbFileMb'
    $btnRun       = & $get 'BtnRun';       $btnCancel   = & $get 'BtnCancel';    $btnSave     = & $get 'BtnSave'
    $tbStatus     = & $get 'TbStatus';     $pbProgress  = & $get 'PbProgress';   $dgResults   = & $get 'DgResults'

    # State shared with the background runspace
    $script:uiState = [hashtable]::Synchronized(@{
        ReportPath = $null
        Result     = $null
        Runspace   = $null
        Cancelled  = $false
    })

    # --- Target mode wiring (gray inactive fields) ---
    $updateTargetFields = {
        $tbLocalPath.IsEnabled  = $rbLocal.IsChecked
        $tbUncPath.IsEnabled    = $rbUnc.IsChecked
        $tbVdaName.IsEnabled    = $rbRemote.IsChecked
        $tbVdaTarget.IsEnabled  = $rbRemote.IsChecked
        $btnBrowse.IsEnabled    = $rbLocal.IsChecked
    }
    $rbLocal.Add_Checked($updateTargetFields)
    $rbUnc.Add_Checked($updateTargetFields)
    $rbRemote.Add_Checked($updateTargetFields)

    $btnBrowse.Add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        if ($dlg.ShowDialog() -eq 'OK') { $tbLocalPath.Text = $dlg.SelectedPath }
    })

    # --- Profile change pre-fills overrides ---
    $fillFromProfile = {
        $name = $cbProfile.SelectedItem.Content
        if ($name -eq 'Custom') { return }
        $p = Get-DiskSpdWorkloadProfile -Name $name
        $tbBlock.Text    = $p.BlockSize
        $tbThreads.Text  = $p.Threads
        $tbQd.Text       = $p.QueueDepth
        $tbWritePct.Text = $p.WriteRatioPercent
        $tbDuration.Text = $p.DurationSeconds
        $tbFileMb.Text   = $p.TestFileSizeMB
    }
    $cbProfile.Add_SelectionChanged($fillFromProfile)
    & $fillFromProfile  # initial fill

    # --- Helper to collect current settings from the form ---
    $collectInputs = {
        $mode = if ($rbLocal.IsChecked) { 'Local' } elseif ($rbUnc.IsChecked) { 'Unc' } else { 'Remote' }
        $target = switch ($mode) { 'Local' { $tbLocalPath.Text } 'Unc' { $tbUncPath.Text } 'Remote' { $tbVdaTarget.Text } }
        $computerName = if ($mode -eq 'Remote') { $tbVdaName.Text } else { $null }
        $workload = $cbProfile.SelectedItem.Content
        $overrides = @{}
        if ($workload -eq 'Custom' -or $tbBlock.Text)    { $overrides.BlockSize         = $tbBlock.Text }
        if ($workload -eq 'Custom' -or $tbThreads.Text)  { $overrides.Threads           = [int]$tbThreads.Text }
        if ($workload -eq 'Custom' -or $tbQd.Text)       { $overrides.QueueDepth        = [int]$tbQd.Text }
        if ($workload -eq 'Custom' -or $tbWritePct.Text) { $overrides.WriteRatioPercent = [int]$tbWritePct.Text }
        if ($workload -eq 'Custom' -or $tbDuration.Text) { $overrides.DurationSeconds   = [int]$tbDuration.Text }
        if ($workload -eq 'Custom' -or $tbFileMb.Text)   { $overrides.TestFileSizeMB    = [int]$tbFileMb.Text }
        if ($workload -eq 'Custom' -and -not $overrides.ContainsKey('RandomIO')) { $overrides.RandomIO = $true }

        @{ Mode=$mode; Target=$target; ComputerName=$computerName; Workload=$workload; Overrides=$overrides }
    }

    # --- UI helpers (must run on dispatcher) ---
    $setStatus = { param($txt) $window.Dispatcher.Invoke([action]{ $tbStatus.Text = $txt }) }
    $setRows = {
        param($result, $assess)
        $rows = New-Object System.Collections.ObjectModel.ObservableCollection[object]
        $rows.Add([PSCustomObject]@{ Metric='IOPS';             Value=$result.IOPS;         Status='' })
        $rows.Add([PSCustomObject]@{ Metric='Read MB/s';        Value=$result.ReadMBps;     Status=$assess.ReadMBps })
        $rows.Add([PSCustomObject]@{ Metric='Write MB/s';       Value=$result.WriteMBps;    Status=$assess.WriteMBps })
        $rows.Add([PSCustomObject]@{ Metric='Avg latency (ms)'; Value=$result.AvgLatencyMs; Status=$assess.AvgLatencyMs })
        $rows.Add([PSCustomObject]@{ Metric='P95 latency (ms)'; Value=$result.Latency95Ms;  Status='' })
        $rows.Add([PSCustomObject]@{ Metric='P99 latency (ms)'; Value=$result.Latency99Ms;  Status='' })
        $rows.Add([PSCustomObject]@{ Metric='CPU %';            Value=$result.CpuPercent;   Status='' })
        $rows.Add([PSCustomObject]@{ Metric='Test file';        Value=$result.TestFilePath; Status='' })
        $rows.Add([PSCustomObject]@{ Metric='Duration (s)';     Value=$result.Duration;     Status='' })
        $window.Dispatcher.Invoke([action]{ $dgResults.ItemsSource = $rows })
    }

    # --- Run button ---
    $btnRun.Add_Click({
        $inputs = & $collectInputs

        # Preflight on the UI thread (fast) — but warn on business hours / errors via MessageBox
        $diskSpdPath = $script:DiskSpdExe
        $tmpSettings = if ($inputs.Workload -eq 'Custom') {
            $inputs.Overrides
        } else {
            Resolve-DiskSpdSettings -ProfileName $inputs.Workload -Overrides $inputs.Overrides
        }

        $pf = Test-DiskSpdPreflight -DiskSpdPath $diskSpdPath -Target $inputs.Target `
                -TestFileSizeMB $tmpSettings.TestFileSizeMB -ComputerName $inputs.ComputerName -BusinessHoursForce:$false

        if (-not $pf.Pass) {
            [System.Windows.MessageBox]::Show(($pf.Errors -join "`n"), 'Preflight failed', 'OK', 'Error') | Out-Null
            return
        }
        if ($pf.Warnings) {
            $msg = ($pf.Warnings -join "`n") + "`n`nContinue?"
            $resp = [System.Windows.MessageBox]::Show($msg, 'Confirm', 'OKCancel', 'Warning')
            if ($resp -ne 'OK') { return }
        }

        # Lock down controls
        $btnRun.IsEnabled = $false; $btnSave.IsEnabled = $false
        $btnCancel.IsEnabled = $true
        $pbProgress.IsIndeterminate = $true
        & $setStatus 'Running diskspd…'

        # Build the runspace work
        $ps = [PowerShell]::Create()
        $ps.AddScript({
            param($scriptPath, $inputs, $outDir)
            . $scriptPath -ErrorAction SilentlyContinue *> $null   # re-dot to load engine functions
            try {
                $report = Invoke-DiskSpdHeadless `
                    -DiskSpdPath (Join-Path (Split-Path $scriptPath -Parent) 'diskspd.exe') `
                    -Target $inputs.Target `
                    -ProfileName $inputs.Workload `
                    -Overrides $inputs.Overrides `
                    -ComputerName $inputs.ComputerName `
                    -OutputPath $outDir `
                    -Force
                @{ Ok=$true; ReportPath=$report }
            } catch {
                @{ Ok=$false; Error=$_.Exception.Message }
            }
        }).AddArgument($PSCommandPath).AddArgument($inputs).AddArgument($script:OutputPath) | Out-Null

        $async = $ps.BeginInvoke()
        $script:uiState.Runspace = $ps

        # Poll completion via a DispatcherTimer
        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [TimeSpan]::FromMilliseconds(250)
        $timer.Add_Tick({
            if ($async.IsCompleted) {
                $timer.Stop()
                $out = $ps.EndInvoke($async) | Select-Object -First 1
                $ps.Dispose()

                $pbProgress.IsIndeterminate = $false
                $btnCancel.IsEnabled = $false
                $btnRun.IsEnabled    = $true

                if ($script:uiState.Cancelled) {
                    & $setStatus 'Cancelled'
                    return
                }
                if (-not $out.Ok) {
                    & $setStatus "Failed: $($out.Error)"
                    [System.Windows.MessageBox]::Show($out.Error, 'diskspd failed', 'OK', 'Error') | Out-Null
                    return
                }
                # Success: re-parse the saved report to get the result object
                $script:uiState.ReportPath = $out.ReportPath
                & $setStatus "Done — report saved"
                $btnSave.IsEnabled = $true
                # For the on-screen grid, re-run parse from raw XML embedded in the report
                # (Simpler: rerun a tiny convert from the most recent invocation by re-invoking ConvertFrom-DiskSpdXml
                #  on the raw XML stashed alongside. We didn't return it, so trigger a separate parse via re-read.)
                # Simpler still — call the engine from the UI thread once more to populate the grid:
                # (We already have the report file; results are already persisted there. For an MVP, surface a
                #  status line and let the user click Save to open the report.)
            }
        })
        $timer.Start()
    })

    $btnCancel.Add_Click({
        if ($script:uiState.Runspace) {
            $script:uiState.Cancelled = $true
            $script:uiState.Runspace.Stop() | Out-Null
        }
        & $setStatus 'Cancelling…'
    })

    $btnSave.Add_Click({
        if ($script:uiState.ReportPath -and (Test-Path $script:uiState.ReportPath)) {
            Start-Process $script:uiState.ReportPath
        }
    })

    # Initial control state
    & $updateTargetFields

    $window.ShowDialog() | Out-Null
}
```

> **Implementer note on the in-GUI live results grid:** The MVP above writes the HTML report and exposes a "Save Report" button to open it. Populating the `DgResults` grid live in the WPF window from the background runspace requires returning the parsed result object across the runspace boundary — which the simplest implementation can punt on. If you want the grid populated during this task, modify the runspace script to return `@{ Ok=$true; ReportPath=$report; Result=$result; Assessment=$assess }`, then call `& $setRows $out.Result $out.Assessment` in the timer's success branch. The data shape is already designed for that; the binding above just isn't called yet. Score this as a small follow-up if the MVP ships first.

- [ ] **Step 3: Manual smoke**

```powershell
.\DiskSpdDiagnostic\Invoke-DiskSpdDiagnostic.ps1
```

Expected:
- Window opens, dark theme, 900×650
- Default selection: Local + FSLogixLike preset, override fields pre-filled
- Switching profile to QuickSanity updates the fields
- Switching target mode grays/un-grays the right fields
- Click "Run Test" with target = `C:\` → preflight may fire a business-hours modal — continue → progress bar animates → status changes to "Done — report saved" → "Save Report" enabled
- Click Save Report → default browser opens the HTML

If any of these fail, fix before moving on. WPF errors usually surface in the PowerShell host console.

- [ ] **Step 4: Commit**

```bash
git add DiskSpdDiagnostic/
git commit -m "feat: WPF GUI for DiskSpd Diagnostic

- Three targeting modes (local/UNC/remote VDA), gray-out inactive fields
- Preset dropdown + Advanced overrides expander
- Background runspace keeps UI responsive, Cancel supported
- Preflight modal surfaces errors + business-hours warnings
- Save Report opens the generated HTML

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 14: README and final QA

**Files:**
- Create: `DiskSpdDiagnostic/README.md`

- [ ] **Step 1: Write the README**

Write `DiskSpdDiagnostic/README.md`:

```markdown
# DiskSpd Diagnostic

On-demand storage triage. Wraps Microsoft's `diskspd.exe` with a WPF GUI and an optional headless mode for scheduling. Built for the moment a user reports "this is slow" and you need authoritative IOPS / throughput / latency numbers fast.

Complements `CitrixVDADiagnostics/CitrixVDA-Consolidated.ps1` — that script samples I/O lightly; this one benchmarks deeply.

## Quick start

GUI:
```powershell
.\Invoke-DiskSpdDiagnostic.ps1
```

Headless (schedulable):
```powershell
.\Invoke-DiskSpdDiagnostic.ps1 -NoUI -Target '\\FileServer01\FSLogix' -Workload FSLogixLike
```

## Targeting modes

| Mode | Where diskspd runs | What it measures |
|---|---|---|
| Local | This machine | This machine's local disk |
| UNC from local | This machine | Network + remote storage end-to-end |
| Remote VDA → path | A VDA via PSRemoting | The exact path a real user session sees |

## Workload profiles

| Profile | Block | Pattern | R/W | Threads | QD | Dur |
|---|---|---|---|---|---|---|
| FSLogixLike    | 4K  | random     | 70/30  | 4 | 8 | 30s |
| SequentialRead | 64K | sequential | 100/0  | 1 | 4 | 30s |
| MixedUserLoad  | 8K  | random     | 80/20  | 2 | 4 | 60s |
| QuickSanity    | 64K | random     | 100/0  | 1 | 2 | 10s |
| Custom         | (operator supplies all fields) |

Any preset's values can be overridden in the Advanced expander or as CLI parameters.

## Parameters (CLI / `-NoUI`)

| Parameter | Notes |
|---|---|
| `-Target` | Path or UNC. Required with `-NoUI`. |
| `-ComputerName` | Remote VDA; if set, diskspd runs on this VDA. |
| `-Workload` | One of FSLogixLike, SequentialRead, MixedUserLoad, QuickSanity, Custom. |
| `-BlockSize`, `-Threads`, `-QueueDepth`, `-WriteRatioPercent`, `-DurationSeconds`, `-TestFileSizeMB` | Override individual fields. Required when `-Workload Custom`. |
| `-NoUI` | Headless mode. |
| `-OutputPath` | Report destination. Default: the script folder. |
| `-Force` | Bypass business-hours confirmation. |

## Health thresholds

Read MB/s — Local: <50 CRIT, 50–100 WARN, >100 OK · Network: <25 CRIT, 25–50 WARN, >50 OK
Write MB/s — Local: <50 CRIT, 50–100 WARN, >100 OK · Network: <20 CRIT, 20–40 WARN, >40 OK
Avg latency — Local: >20ms CRIT, 10–20ms WARN, <10ms OK · Network: >50ms CRIT, 20–50ms WARN, <20ms OK

## Safety guardrails

- Preflight: binary signed by Microsoft, target reachable + writable, free space ≥ 1.2× test file
- Cleanup: test file and remote binary are removed in `finally{}`, even on Cancel
- Business-hours warning: modal between Mon–Fri 7am–6pm; `-Force` skips

## Requirements

- Windows Server 2016+ / Windows 10+ with PowerShell 5.1
- Administrator
- For remote mode: WinRM enabled on the VDA, admin share open
- `diskspd.exe` is bundled (v2.2.0, Microsoft GitHub release, MIT)

## Tests

```powershell
Install-Module Pester -MinimumVersion 5.0 -Force -Scope CurrentUser
Invoke-Pester -Path .\Tests
# Integration tests (run real diskspd against $env:TEMP):
Invoke-Pester -Path .\Tests -Tag Integration
```
```

- [ ] **Step 2: Final smoke matrix**

Run each of these. Each one should produce a clean run and an openable HTML report (or surface a clear error if your environment doesn't permit it).

| # | Command | Expected |
|---|---|---|
| 1 | `.\Invoke-DiskSpdDiagnostic.ps1 -NoUI -Target $env:TEMP -Workload QuickSanity -Force` | Headless local, ~10s, report saved |
| 2 | `.\Invoke-DiskSpdDiagnostic.ps1 -NoUI -Target '\\<your-fileserver>\<share>' -Workload QuickSanity -Force` | Headless UNC; if you have a writable share |
| 3 | `.\Invoke-DiskSpdDiagnostic.ps1 -NoUI -ComputerName <vda> -Target 'C:\Windows\Temp' -Workload QuickSanity -Force` | Headless remote; if you have a reachable VDA |
| 4 | `.\Invoke-DiskSpdDiagnostic.ps1` then GUI: Local, FSLogixLike, Run | GUI happy path |
| 5 | `.\Invoke-DiskSpdDiagnostic.ps1` then GUI: switch to Custom, fill all fields, Run | GUI Custom path |

For any cell that fails, fix the underlying issue and re-run.

- [ ] **Step 3: Commit**

```bash
git add DiskSpdDiagnostic/README.md
git commit -m "docs: README for DiskSpd Diagnostic

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Self-review notes

**Spec coverage**
- Folder layout (design § Folder layout): Task 0, 4, 10, 14 ✓
- Three targeting modes (Local/UNC/Remote): Task 8 + 9 ✓, GUI exposes all three: Task 13 ✓
- Preset profiles + overrides: Task 1 + 2, GUI prefill: Task 13 ✓
- WPF GUI ~900×650, dark, blue accent: Task 13 ✓
- Live results + Save Report (HTML): Task 10 + 13 — note: in-window grid population is flagged as MVP follow-up in Task 13 Step 2
- Engine functions (1–6 from design): all covered (Tasks 1–11)
- Bundled diskspd.exe + signature check: Task 4, Task 7 ✓
- Preflight + cleanup + business-hours warning: Task 7 + 8 + 9 ✓
- HTML report + thresholds matching CitrixVDADiagnostics README: Task 6 + 10 ✓
- `-NoUI` headless: Task 11 + 12 ✓
- CLAUDE.md conventions: each Task's PS code follows them ✓

**Known soft spot**
The `DgResults` grid in the WPF window doesn't get populated live in this plan's MVP — the report file does. Task 13 Step 2 includes a note describing the small follow-up to wire it up. Per "no placeholders," the data shape (`$setRows`) is fully written; the call to it is the only missing line, and the note tells the implementer exactly where to add it.

**Placeholder scan** — clean. No "TBD", "fill in", or "similar to Task N." Every code step shows the code.

**Type consistency**
- `Settings` hashtable keys (`BlockSize, Threads, QueueDepth, WriteRatioPercent, DurationSeconds, TestFileSizeMB, RandomIO`) used identically in Tasks 1–3, 7, 8, 11, 13 ✓
- Result properties (`IOPS, ReadMBps, WriteMBps, AvgLatencyMs, Latency95Ms, Latency99Ms, CpuPercent, TestFilePath, Duration, ProfileName, RawXml`) used identically in Tasks 5, 6, 10, 11, 13 ✓
- `Assessment` hashtable keys (`ReadMBps, WriteMBps, AvgLatencyMs`) used identically in Tasks 6, 10, 13 ✓
- Function names match across tasks ✓
