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

.PARAMETER Workload
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

# System.Web is in-box on PowerShell 5.1 / .NET Framework 4.x. Required for
# HtmlEncode in Export-DiskSpdHtmlReport. Loaded once at script scope.
Add-Type -AssemblyName System.Web

# Single source of truth for the workload-settings hashtable contract.
# Every preset in Get-DiskSpdWorkloadProfile, every -Overrides hashtable on
# Resolve-DiskSpdSettings, and every $Settings hashtable on Build-DiskSpdArguments
# must contain exactly these keys.
$script:DiskSpdRequiredKeys = @('BlockSize','Threads','QueueDepth','WriteRatioPercent',
                                'DurationSeconds','TestFileSizeMB','RandomIO')

# Color-prefixed status output per CLAUDE.md ([PASS]/[WARN]/[FAIL]/[INFO]).
# Used by Invoke-DiskSpdHeadless and re-usable by the WPF UI's runspace handler
# (Task 13) so the level->color mapping isn't duplicated.
# TODO Task 13: Write-Host output is not captured by a runspace's success stream;
# the WPF status routing will need either Write-Information or a callback param.
function Write-DiskSpdStatus {
    param([string]$Level, [string]$Message)
    $color = switch ($Level) {
        'PASS' { 'Green'  }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red'    }
        default { 'Cyan'  }
    }
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$ts] [$Level] $Message" -ForegroundColor $color
}

# WPF XAML for the diagnostic GUI. Loaded by Show-DiskSpdGui via XamlReader.Load.
# Kept as a here-string (not a separate .xaml file) so the script remains
# self-contained per the project's flat-folder convention.
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
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <!-- Zone 1: Target -->
        <GroupBox Header="Target" Grid.Row="0" Padding="12">
            <StackPanel>
                <RadioButton x:Name="RbLocal"  GroupName="Target" Content="Local disk on this machine" IsChecked="True"/>
                <StackPanel Orientation="Horizontal" Margin="20,4,0,8">
                    <TextBox x:Name="TbLocalPath" Width="500" Text="C:\"/>
                    <Button  x:Name="BtnBrowseLocal" Content="Browse..." Margin="8,0,0,0"/>
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

        <!-- Zone 2: Workload -->
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
                <TextBlock x:Name="TbProfileDescription" Margin="84,4,0,0" Foreground="#9aa0a6"
                           FontSize="11" TextWrapping="Wrap" MaxWidth="760"
                           Text="Pick a preset above to see its description."/>
                <Expander x:Name="ExpAdvanced" Header="Advanced overrides" Margin="0,12,0,0">
                    <Grid Margin="8,12,8,8">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="180"/><ColumnDefinition Width="130"/>
                            <ColumnDefinition Width="180"/><ColumnDefinition Width="130"/>
                            <ColumnDefinition Width="180"/><ColumnDefinition Width="130"/>
                        </Grid.ColumnDefinitions>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>
                        <Label Content="Block size (e.g. 4K, 64K):"    Grid.Row="0" Grid.Column="0" Margin="0,4"/>
                        <TextBox x:Name="TbBlock"       Grid.Row="0" Grid.Column="1" Margin="0,4" Padding="4,2"
                                 ToolTip="diskspd -b flag. Smaller blocks (4K) stress IOPS, larger blocks (64K, 1M) stress throughput."/>
                        <Label Content="Threads (1-64):"               Grid.Row="0" Grid.Column="2" Margin="0,4"/>
                        <TextBox x:Name="TbThreads"     Grid.Row="0" Grid.Column="3" Margin="0,4" Padding="4,2"
                                 ToolTip="diskspd -t flag. Parallel I/O threads. More threads = more concurrent pressure on the storage."/>
                        <Label Content="Queue depth (1-256):"          Grid.Row="0" Grid.Column="4" Margin="0,4"/>
                        <TextBox x:Name="TbQd"          Grid.Row="0" Grid.Column="5" Margin="0,4" Padding="4,2"
                                 ToolTip="diskspd -o flag. Outstanding I/Os per thread. Higher queues saturate NVMe; lower simulates light workloads."/>
                        <Label Content="Write % (0-100):"              Grid.Row="1" Grid.Column="0" Margin="0,4"/>
                        <TextBox x:Name="TbWritePct"    Grid.Row="1" Grid.Column="1" Margin="0,4" Padding="4,2"
                                 ToolTip="diskspd -w flag. 0 = all reads (read-only test), 100 = all writes, 30 = mixed."/>
                        <Label Content="Duration (seconds):"           Grid.Row="1" Grid.Column="2" Margin="0,4"/>
                        <TextBox x:Name="TbDuration"    Grid.Row="1" Grid.Column="3" Margin="0,4" Padding="4,2"
                                 ToolTip="diskspd -d flag. How long the test runs. 10s gives a sanity check; 30-60s gives stable numbers."/>
                        <Label Content="File size (MB):"               Grid.Row="1" Grid.Column="4" Margin="0,4"/>
                        <TextBox x:Name="TbFileMb"      Grid.Row="1" Grid.Column="5" Margin="0,4" Padding="4,2"
                                 ToolTip="diskspd -c flag. Size of the scratch file. Must fit on the target with headroom."/>
                    </Grid>
                </Expander>
            </StackPanel>
        </GroupBox>

        <!-- Zone 3: Run + Results -->
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
                <ProgressBar x:Name="PbProgress" Grid.Row="1" Height="10" Margin="0,8" Minimum="0" Maximum="100"
                             Foreground="#5dade2" Background="#252526"/>
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

# --- Engine functions go here (Tasks 1-9) ---

# Returns hashtable (not PSCustomObject) so callers can merge operator overrides.
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
        default  { throw "Unhandled workload profile: $Name" }
    }
}

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

    # Reject typos like @{ Treads = 16 } before they silently drop the intended override.
    $unknown = $Overrides.Keys | Where-Object { $_ -notin $script:DiskSpdRequiredKeys }
    if ($unknown) {
        throw "Unknown override key(s): $($unknown -join ', '). Expected one of: $($script:DiskSpdRequiredKeys -join ', ')"
    }

    if ($ProfileName -eq 'Custom') {
        $missing = $script:DiskSpdRequiredKeys | Where-Object { -not $Overrides.ContainsKey($_) }
        if ($missing) {
            throw "Profile 'Custom' requires all override keys. Missing: $($missing -join ', ')"
        }
        # Shallow clone is sufficient: all values are primitives (string/int/bool).
        return [hashtable]$Overrides.Clone()
    }

    $settings = Get-DiskSpdWorkloadProfile -Name $ProfileName
    foreach ($key in $Overrides.Keys) {
        $settings[$key] = $Overrides[$key]
    }
    return $settings
}

function Build-DiskSpdArguments {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [hashtable]$Settings,
        [Parameter(Mandatory)] [string]   $TestFilePath
    )

    # Catch malformed settings at the boundary so diskspd doesn't get -t with no value.
    $missing = $script:DiskSpdRequiredKeys | Where-Object { -not $Settings.ContainsKey($_) }
    if ($missing) {
        throw "Build-DiskSpdArguments: Settings hashtable is missing required key(s): $($missing -join ', ')"
    }

    # Size suffix: use G for whole-GB sizes (>= 1024 MB and evenly divisible), M otherwise.
    # Explicit [int] cast so future readers don't wonder whether "1024/1024" produces "1" or "1.0".
    $size = if ($Settings.TestFileSizeMB -ge 1024 -and ($Settings.TestFileSizeMB % 1024) -eq 0) {
        "$([int]($Settings.TestFileSizeMB / 1024))G"
    } else {
        "$($Settings.TestFileSizeMB)M"
    }

    $argv = @(
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
    if ($Settings.RandomIO) { $argv += '-r' }
    $argv += $TestFilePath
    return $argv
}

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
    if (-not $timeSpan) { throw "diskspd XML missing <TimeSpan> - output may be a partial run." }

    $durationSec = [double]$timeSpan.TestTimeSeconds
    if ($durationSec -le 0) { throw "diskspd XML reports zero duration - test did not run." }

    # Force array semantics: PowerShell XML returns a single element (not a 1-element array)
    # when there's only one Thread, so @(...) ensures the sum/aggregate pipeline works in both
    # single-thread and multi-thread cases.
    $threads = @($timeSpan.Thread)
    $readBytes  = ($threads | ForEach-Object { [int64]$_.Target.ReadBytes  } | Measure-Object -Sum).Sum
    $writeBytes = ($threads | ForEach-Object { [int64]$_.Target.WriteBytes } | Measure-Object -Sum).Sum
    $readCount  = ($threads | ForEach-Object { [int64]$_.Target.ReadCount  } | Measure-Object -Sum).Sum
    $writeCount = ($threads | ForEach-Object { [int64]$_.Target.WriteCount } | Measure-Object -Sum).Sum
    $testFile   = $threads[0].Target.Path

    $readMBps   = [math]::Round($readBytes  / 1MB / $durationSec, 2)
    $writeMBps  = [math]::Round($writeBytes / 1MB / $durationSec, 2)
    $iops       = [math]::Round(($readCount + $writeCount) / $durationSec, 0)

    # Average latency: prefer AverageTotalMilliseconds (combined R+W average from diskspd v2.2).
    # Fall back to Read-only or Write-only averages depending on what the test contained.
    # The Write fallback matters for 100%-write workloads (FSLogix profile creation, OLTP)
    # on older diskspd builds that don't emit AverageTotalMilliseconds.
    $avgMs = if ($timeSpan.Latency.AverageTotalMilliseconds) {
        [double]$timeSpan.Latency.AverageTotalMilliseconds
    } elseif ($timeSpan.Latency.AverageReadMilliseconds) {
        [double]$timeSpan.Latency.AverageReadMilliseconds
    } elseif ($timeSpan.Latency.AverageWriteMilliseconds) {
        [double]$timeSpan.Latency.AverageWriteMilliseconds
    } else { 0 }

    # Bucket lookup: TotalMilliseconds is the combined R+W percentile latency.
    # Falls back to Read- or Write-only latency for pure-read / pure-write workloads.
    # The integer-percentile comparison is safe: 95 and 99 parse to exact doubles
    # (would NOT be safe for fractional buckets like 99.9).
    function Get-BucketLatency([object]$buckets, [int]$percentile) {
        $b = $buckets | Where-Object { [double]$_.Percentile -eq $percentile } | Select-Object -First 1
        if (-not $b) { return $null }
        if ($b.TotalMilliseconds) { return [double]$b.TotalMilliseconds }
        if ($b.ReadMilliseconds)  { return [double]$b.ReadMilliseconds }
        if ($b.WriteMilliseconds) { return [double]$b.WriteMilliseconds }
        return $null
    }

    $buckets = @($timeSpan.Latency.Bucket)
    $p95 = Get-BucketLatency -buckets $buckets -percentile 95
    $p99 = Get-BucketLatency -buckets $buckets -percentile 99
    if ($null -eq $p95) { $p95 = $avgMs }
    if ($null -eq $p99) { $p99 = $p95   }

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

function Get-DiskSpdHealthAssessment {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [PSCustomObject]$Result,
        [Parameter(Mandatory)] [ValidateSet('Local','Network')] [string]$Transport
    )

    # Threshold source of truth: CitrixVDADiagnostics/README.md. Keep these in sync
    # so the new diagnostic's color-coding matches the existing FSLogix tooling.
    # WARN band is inclusive on both edges (50/100 MB/s land in WARN, 10/20ms land
    # in WARN) — pinned by the boundary tests in Tests/DiskSpdDiagnostic.Tests.ps1.
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

    # Throughput: higher is better, so > OK is OK, >= Warn is WARN, else CRIT.
    # Latency: lower is better, so < OK is OK, <= Warn is WARN, else CRIT.
    function Classify-Throughput($v, $ok, $warn) {
        if ($v -gt $ok)       { 'OK' }
        elseif ($v -ge $warn) { 'WARN' }
        else                  { 'CRIT' }
    }
    function Classify-Latency($v, $ok, $warn) {
        if ($v -lt $ok)       { 'OK' }
        elseif ($v -le $warn) { 'WARN' }
        else                  { 'CRIT' }
    }

    # P95/P99 are classified with the same latency thresholds as average. P95 in
    # particular is more operationally relevant than mean for storage triage,
    # so the HTML report (Task 10) colors all three latency rows.
    # NOTE: local var is $out (NOT $result) because PowerShell is case-insensitive
    # and $result would silently shadow the $Result parameter — meaning the
    # subsequent $Result.Latency95Ms reads would target our empty hashtable instead.
    $out = @{
        ReadMBps     = Classify-Throughput $Result.ReadMBps     $thresholds.ReadOK    $thresholds.ReadWarn
        WriteMBps    = Classify-Throughput $Result.WriteMBps    $thresholds.WriteOK   $thresholds.WriteWarn
        AvgLatencyMs = Classify-Latency    $Result.AvgLatencyMs $thresholds.LatencyOK $thresholds.LatencyWarn
    }
    if ($null -ne $Result.Latency95Ms) {
        $out.Latency95Ms = Classify-Latency $Result.Latency95Ms $thresholds.LatencyOK $thresholds.LatencyWarn
    }
    if ($null -ne $Result.Latency99Ms) {
        $out.Latency99Ms = Classify-Latency $Result.Latency99Ms $thresholds.LatencyOK $thresholds.LatencyWarn
    }
    $out
}

# Returns [PSCustomObject] (not hashtable) because the result is consumer-facing —
# the WPF UI binds Errors/Warnings to modal dialogs and the headless orchestrator
# logs them by name. Keep the field names (Pass, Errors, Warnings) stable.
#
# NOTE: signature-warning branches (bad Authenticode status / non-Microsoft signer
# / read-failure) are not unit-tested — a fixture exe with each signature state
# is more setup cost than the ~5 lines of logic justify. They are exercised
# manually when the bundled binary is updated.
#
# NOTE: UNC targets ('\\server\share\...') can make Test-Path / Get-Item block
# for the full SMB timeout (~30s) when the server is unreachable. The WPF UI
# (Task 13) runs preflight on a background runspace to avoid hanging the
# dispatcher — don't call this synchronously from a UI-thread event handler.
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

    # 1. Binary present + Microsoft-signed.
    # A missing binary is an ERROR (we cannot proceed). A bad signature is a WARNING
    # (operator can still proceed knowingly — useful for offline lab environments).
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

    # 2-3. Target reachable + writable + free space (local-mode only).
    # When -ComputerName is set, the target lives on the remote machine — we skip these
    # checks here and rely on the remote-mode admin-share check + the actual remote run.
    if (-not $ComputerName) {
        if ([string]::IsNullOrWhiteSpace($Target)) {
            $errors += "Target is empty or whitespace."
        } elseif (-not (Test-Path $Target)) {
            $errors += "Target not reachable: $Target"
        } else {
            $probe = Join-Path $Target "diskspd-preflight-$([guid]::NewGuid()).tmp"
            try {
                [IO.File]::WriteAllBytes($probe, [byte[]]@(0))
                Remove-Item $probe -Force -ErrorAction Stop
            } catch {
                $errors += "Target not writable: $Target - $($_.Exception.Message)"
            }

            # Free space check. UNC shares often don't expose PSDrive.Free reliably;
            # in that case we surface a WARNING (not an error) so the operator decides.
            try {
                $root  = (Resolve-Path $Target -ErrorAction Stop).ProviderPath
                $drive = (Get-Item $root).PSDrive
                if ($drive -and $drive.Free) {
                    $neededBytes = $TestFileSizeMB * 1.2MB
                    if ($drive.Free -lt $neededBytes) {
                        $errors += ("Insufficient free space at {0}: have {1:N0} MB, need {2:N0} MB (file size x1.2)." -f
                                    $Target, ($drive.Free/1MB), ($neededBytes/1MB))
                    }
                } else {
                    $warnings += "Could not determine free space at $Target (UNC share or unmapped drive)."
                }
            } catch {
                $warnings += "Could not check free space at ${Target}: $($_.Exception.Message)"
            }
        }
    }

    # 4. Remote reachability (only in remote mode).
    # Test-WSMan can throw on DNS failure, or return $null when -ErrorAction Stop
    # doesn't catch (varies by Windows build). Handle both by tracking the outcome
    # explicitly, then also probe the admin share as a separate check.
    if ($ComputerName) {
        $wsManReachable = $false
        try {
            $wsManResult = Test-WSMan -ComputerName $ComputerName -ErrorAction Stop
            if ($wsManResult) { $wsManReachable = $true }
        } catch {
            $errors += "Test-WSMan failed for ${ComputerName}: $($_.Exception.Message)"
        }
        if (-not $wsManReachable -and -not ($errors -match 'Test-WSMan')) {
            $errors += "Test-WSMan failed for ${ComputerName}: no response (host unreachable or WinRM not listening)"
        }
        $admin = "\\$ComputerName\C`$\Windows\Temp"
        if (-not (Test-Path $admin)) {
            $errors += "Admin share not accessible: $admin"
        }
    }

    # 5. Business hours warning. 7am-6pm Mon-Fri local time.
    # Upper bound is EXCLUSIVE: 7:00 warns, 18:00 does not (lunchtime to end-of-day).
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

# BLOCKING: this function waits for diskspd to finish (DurationSeconds + warmup),
# which can be 30+ seconds. Callers on UI threads MUST dispatch this to a background
# runspace or the WPF dispatcher will freeze. Task 13's Run-button handler does this.
# The cleanup in finally{} runs even if the caller cancels the runspace.
function Invoke-DiskSpdLocal {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string]   $DiskSpdPath,
        [Parameter(Mandatory)] [hashtable]$Settings,
        [Parameter(Mandatory)] [string]   $TestFilePath
    )

    $argv = Build-DiskSpdArguments -Settings $Settings -TestFilePath $TestFilePath

    # Capture stdout and stderr to temp files because Start-Process can't return them
    # as strings directly — it returns a Process object and requires -RedirectStandard*.
    $stdoutFile = [IO.Path]::GetTempFileName()
    $stderrFile = [IO.Path]::GetTempFileName()

    try {
        $proc = Start-Process -FilePath $DiskSpdPath -ArgumentList $argv -NoNewWindow -PassThru `
                              -RedirectStandardOutput $stdoutFile `
                              -RedirectStandardError  $stderrFile -Wait

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
        # Cleanup regardless of success/failure. -ErrorAction SilentlyContinue
        # because Remove-Item on an already-deleted file shouldn't mask the original error.
        Remove-Item $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue
        Remove-Item $TestFilePath           -Force -ErrorAction SilentlyContinue
    }
}

# BLOCKING and SLOW: copies the binary over SMB, opens a PSSession, runs diskspd
# remotely, then tears down. Callers on UI threads MUST dispatch this off-thread.
# Per the design: this is the most operationally-valuable mode (VDA -> FileServer),
# but also the most likely to surface environmental quirks (WinRM, admin share,
# remote PSSession quotas). Manual integration testing is required — no Pester
# unit tests because we can't simulate a remote machine.
#
# REQUIRES: Test-DiskSpdPreflight -ComputerName <vda> must succeed first. This
# function trusts that WinRM is listening and the admin share is reachable;
# calling it without preflight produces confusing New-PSSession exceptions
# instead of the clean error messages preflight returns.
#
# NOTE on the SHA-256 cache: the goal is to skip the binary copy on repeated
# runs against the same VDA. The outer finally{} only removes the deposited
# binary if THIS invocation copied it ($copyNeeded was true). Otherwise the
# next call's hash check would always miss and the cache would be useless.
function Invoke-DiskSpdRemote {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string]   $DiskSpdPath,
        [Parameter(Mandatory)] [string]   $ComputerName,
        [Parameter(Mandatory)] [hashtable]$Settings,
        [Parameter(Mandatory)] [string]   $TestFilePath
    )

    # Where the binary will live on the remote VDA. We deposit it via the admin share
    # and reference it locally on the remote side via the C:\ path.
    $remoteExe = 'C:\Windows\Temp\diskspd.exe'
    $remoteUnc = "\\$ComputerName\C`$\Windows\Temp\diskspd.exe"

    # Skip the copy if the same SHA-256 is already there. Saves time on repeated runs
    # and avoids hammering the admin share for no reason.
    # Race note: two concurrent operators against the same VDA could (in theory)
    # interleave copies and deletes. Acceptable for on-demand triage tooling because
    # all operators bundle the same binary and the SHA check is byte-identical;
    # if this ever becomes a scheduled job, the cache strategy needs revisiting.
    $localHash  = (Get-FileHash $DiskSpdPath -Algorithm SHA256).Hash
    $copyNeeded = $true
    if (Test-Path $remoteUnc) {
        try {
            $remoteHash = (Get-FileHash $remoteUnc -Algorithm SHA256).Hash
            if ($remoteHash -eq $localHash) { $copyNeeded = $false }
        } catch {
            # If we can't read the existing file, just overwrite it.
            $copyNeeded = $true
        }
    }
    if ($copyNeeded) {
        # Mismatch or missing: our bundled binary is authoritative; overwrite without warning.
        Copy-Item -Path $DiskSpdPath -Destination $remoteUnc -Force -ErrorAction Stop
    }

    $argv = Build-DiskSpdArguments -Settings $Settings -TestFilePath $TestFilePath

    try {
        $session = New-PSSession -ComputerName $ComputerName -ErrorAction Stop
        try {
            # Run diskspd on the remote machine. The remote scriptblock uses the
            # same Start-Process pattern as Invoke-DiskSpdLocal so stdout/stderr
            # capture is consistent. Returns a structured object so we can route
            # the exit code and stderr back into a local exception.
            $remoteResult = Invoke-Command -Session $session -ScriptBlock {
                param($DiskSpdPath, $Arguments, $TestFilePath)
                $stdoutFile = [IO.Path]::GetTempFileName()
                $stderrFile = [IO.Path]::GetTempFileName()
                try {
                    $proc = Start-Process -FilePath $DiskSpdPath -ArgumentList $Arguments -NoNewWindow `
                                          -PassThru -RedirectStandardOutput $stdoutFile `
                                          -RedirectStandardError $stderrFile -Wait
                    [PSCustomObject]@{
                        ExitCode = $proc.ExitCode
                        StdOut   = Get-Content $stdoutFile -Raw
                        StdErr   = Get-Content $stderrFile -Raw
                    }
                } finally {
                    Remove-Item $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue
                    # Clean up the test data file on the remote machine too.
                    Remove-Item $TestFilePath -Force -ErrorAction SilentlyContinue
                }
            } -ArgumentList $remoteExe, $argv, $TestFilePath

            if ($remoteResult.ExitCode -ne 0) {
                throw "diskspd on $ComputerName exited with code $($remoteResult.ExitCode). stderr: $($remoteResult.StdErr)"
            }
            if ([string]::IsNullOrWhiteSpace($remoteResult.StdOut) -or $remoteResult.StdOut -notmatch '<Results>') {
                throw "diskspd on $ComputerName produced no XML output. stderr: $($remoteResult.StdErr)"
            }
            return $remoteResult.StdOut
        } finally {
            Remove-PSSession $session -ErrorAction SilentlyContinue
        }
    } finally {
        # Only clean up the deposited binary if THIS invocation copied it.
        # Otherwise we'd defeat the SHA-256 cache: the next call's hash check
        # would always miss because we'd already deleted the file.
        # Surface cleanup failures as warnings so an orphaned binary on the VDA
        # doesn't go unnoticed; failure is non-fatal so we don't mask the real error.
        if ($copyNeeded) {
            Remove-Item $remoteUnc -Force -ErrorAction SilentlyContinue -ErrorVariable rmErr
            if ($rmErr) {
                Write-Warning "Could not remove deposited diskspd.exe at ${remoteUnc}: $($rmErr[0].Exception.Message)"
            }
        }
    }
}

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

    if (-not (Test-Path $script:ReportTpl)) {
        throw "Report template not found at $script:ReportTpl"
    }
    $tpl = Get-Content $script:ReportTpl -Raw

    $timestamp     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $fileTimestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    # Sanitize target for filename: strip any character Windows rejects in a filename.
    $safeTarget    = ($Target -replace '[\\\/\:\*\?\"\<\>\|]', '_').TrimStart('_').TrimEnd('_')
    if ([string]::IsNullOrWhiteSpace($safeTarget)) { $safeTarget = 'target' }

    function Get-BadgeClass($status) {
        switch ($status) {
            'OK'   { 'badge ok' }
            'WARN' { 'badge warn' }
            'CRIT' { 'badge crit' }
            default { 'badge' }
        }
    }

    # Results table rows. The Status column is only populated for metrics the
    # Assessment hashtable bands (ReadMBps/WriteMBps/AvgLatencyMs and optionally
    # Latency95Ms/Latency99Ms — see Get-DiskSpdHealthAssessment).
    $rows = @(
        @{ M = 'IOPS';             V = $Result.IOPS;         S = $null                     }
        @{ M = 'Read MB/s';        V = $Result.ReadMBps;     S = $Assessment.ReadMBps      }
        @{ M = 'Write MB/s';       V = $Result.WriteMBps;    S = $Assessment.WriteMBps     }
        @{ M = 'Avg latency (ms)'; V = $Result.AvgLatencyMs; S = $Assessment.AvgLatencyMs  }
        @{ M = 'P95 latency (ms)'; V = $Result.Latency95Ms;  S = $Assessment.Latency95Ms   }
        @{ M = 'P99 latency (ms)'; V = $Result.Latency99Ms;  S = $Assessment.Latency99Ms   }
        @{ M = 'CPU %';            V = $Result.CpuPercent;   S = $null                     }
        @{ M = 'Test file';        V = $Result.TestFilePath; S = $null                     }
        @{ M = 'Duration (s)';     V = $Result.Duration;     S = $null                     }
    )

    $rowsHtml = ($rows | ForEach-Object {
        $valueEncoded = [System.Web.HttpUtility]::HtmlEncode([string]$_.V)
        $badge = if ($_.S) { "<span class=`"$(Get-BadgeClass $_.S)`">$($_.S)</span>" } else { '' }
        "<tr><td>$($_.M)</td><td class=`"num`">$valueEncoded</td><td>$badge</td></tr>"
    }) -join "`n"

    # Iterate in a fixed display order so reports from different runs can be
    # diff'd side-by-side without spurious badge reordering. Skip keys the
    # assessment didn't populate (P95/P99 only present when input has them).
    $badgeKeyOrder = @('ReadMBps','WriteMBps','AvgLatencyMs','Latency95Ms','Latency99Ms')
    $badgesHtml = (@(foreach ($key in $badgeKeyOrder) {
        if ($Assessment.ContainsKey($key)) {
            "<span class=`"$(Get-BadgeClass $Assessment[$key])`">${key}: $($Assessment[$key])</span>"
        }
    }) -join ' ')

    $rawXmlEncoded = [System.Web.HttpUtility]::HtmlEncode($Result.RawXml)

    # Use [string]::Replace (not -replace) for placeholder substitution.
    # -replace treats the replacement as a regex pattern, so a target like
    # \\server\C$1 would have $1 consumed as a backreference. .Replace() is
    # a literal-string method on both sides and avoids the foot-gun.
    # (NOTE: {{PROFILE}} placeholder corresponds to the user-facing -Workload
    # parameter; "Profile" is the legacy internal name preserved for now.)
    $encodedTarget   = [System.Web.HttpUtility]::HtmlEncode($Target)
    $encodedWorkload = [System.Web.HttpUtility]::HtmlEncode($Result.ProfileName)
    $html = $tpl
    $html = $html.Replace('{{TARGET}}',        $encodedTarget)
    $html = $html.Replace('{{PROFILE}}',       $encodedWorkload)
    $html = $html.Replace('{{TIMESTAMP}}',     $timestamp)
    $html = $html.Replace('{{RESULTS_TABLE}}', $rowsHtml)
    $html = $html.Replace('{{HEALTH_BADGES}}', $badgesHtml)
    $html = $html.Replace('{{RAW_XML}}',       $rawXmlEncoded)

    $filename = "diskspd_${safeTarget}_${fileTimestamp}.html"
    $outFile  = Join-Path $OutputDirectory $filename
    Set-Content -Path $outFile -Value $html -Encoding UTF8
    return $outFile
}

# --- UI / headless dispatch goes here (Tasks 10-11) ---

# Headless orchestrator: preflight -> run -> parse -> assess -> export. Drives the
# entire diskspd pipeline in one call for -NoUI mode and for the WPF UI's Run
# button. Returns the path to the generated HTML report.
#
# BLOCKING: takes DurationSeconds + ~5s diskspd warmup. Callers must dispatch
# this off the UI thread (Task 13 does so via a background runspace).
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

    # Resolve settings before preflight so we can pass the actual TestFileSizeMB
    # to the free-space check.
    $settings  = Resolve-DiskSpdSettings -ProfileName $ProfileName -Overrides $Overrides
    $transport = if ($ComputerName -or $Target -match '^\\\\') { 'Network' } else { 'Local' }

    Write-DiskSpdStatus 'INFO' "Preflight starting for target '$Target' (transport: $transport)"
    $pf = Test-DiskSpdPreflight -DiskSpdPath $DiskSpdPath -Target $Target `
            -TestFileSizeMB $settings.TestFileSizeMB -ComputerName $ComputerName -BusinessHoursForce:$Force

    foreach ($w in $pf.Warnings) { Write-DiskSpdStatus 'WARN' $w }
    foreach ($e in $pf.Errors)   { Write-DiskSpdStatus 'FAIL' $e }
    if (-not $pf.Pass) {
        # Include the errors in the thrown message so consumers that catch the
        # exception (e.g., Task 13's WPF runspace) see the failure detail without
        # needing access to the host's captured console output.
        throw ("Preflight failed for target '{0}': {1}" -f $Target, ($pf.Errors -join '; '))
    }
    Write-DiskSpdStatus 'PASS' 'Preflight OK'

    # Pick the test data file path. If the operator passed a real .dat file path,
    # use it as-is (advanced use). Otherwise create one inside the target directory
    # named with a millisecond-precision timestamp so concurrent runs within the
    # same second don't collide.
    $testFile = if ($Target -match '\.dat$') {
        $Target
    } else {
        Join-Path $Target ("diskspd-{0}.dat" -f (Get-Date -Format 'yyyy-MM-dd_HHmmss_fff'))
    }

    Write-DiskSpdStatus 'INFO' ("Running diskspd ({0}s, {1}t/QD{2}){3}" -f `
        $settings.DurationSeconds, $settings.Threads, $settings.QueueDepth, `
        $(if ($ComputerName) { " on $ComputerName" } else { '' }))

    $xml = if ($ComputerName) {
        Invoke-DiskSpdRemote -DiskSpdPath $DiskSpdPath -ComputerName $ComputerName `
                             -Settings $settings -TestFilePath $testFile
    } else {
        Invoke-DiskSpdLocal  -DiskSpdPath $DiskSpdPath -Settings $settings -TestFilePath $testFile
    }
    Write-DiskSpdStatus 'PASS' 'diskspd completed'

    $result = ConvertFrom-DiskSpdXml -Xml $xml -ProfileName $ProfileName
    $assess = Get-DiskSpdHealthAssessment -Result $result -Transport $transport

    Write-DiskSpdStatus 'INFO' ("Results: {0} IOPS / {1} MB/s read / {2} MB/s write / {3} ms avg latency" -f `
        $result.IOPS, $result.ReadMBps, $result.WriteMBps, $result.AvgLatencyMs)

    $report = Export-DiskSpdHtmlReport -Result $result -Assessment $assess `
                -Target $Target -OutputDirectory $OutputPath
    Write-DiskSpdStatus 'PASS' "Report saved: $report"
    return $report
}

function Show-DiskSpdGui {
    [CmdletBinding()] param()

    Add-Type -AssemblyName PresentationFramework, System.Xaml, System.Windows.Forms

    [xml]$xamlDoc = $script:Xaml
    $reader = New-Object System.Xml.XmlNodeReader $xamlDoc
    $window = [Windows.Markup.XamlReader]::Load($reader)

    # Bind named XAML elements to local variables for easy reference.
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
    $tbProfileDescription = & $get 'TbProfileDescription'

    # Plain-English descriptions for each preset so the operator can pick
    # without having to remember diskspd flag semantics. Shown below the
    # dropdown and updated on selection change.
    $profileDescriptions = @{
        'FSLogixLike' = "4K random, 30% writes, 4 threads, QD8, 30s. Simulates FSLogix profile container I/O. Best for testing FSLogix shares and VDA local disks."
        'SequentialRead' = "64K sequential read, 1 thread, QD4, 30s. Measures raw read throughput. Best for: boot/login scenarios, large file copies, image deployment."
        'MixedUserLoad' = "8K random, 20% writes, 2 threads, QD4, 60s. Simulates a moderate user session workload. Best for: general 'is this drive fast enough?' checks."
        'QuickSanity' = "64K random, 100% reads, 1 thread, QD2, 10s. Fast smoke test (~10s). Best for: confirming a drive is reachable and producing sane numbers, not a performance benchmark."
        'Custom' = "Operator-supplied values. All 6 advanced fields below must be filled in. Use when none of the presets fit your workload."
    }

    # Shared state between the UI thread and the background runspace.
    # [hashtable]::Synchronized so reads/writes don't race.
    $script:uiState = [hashtable]::Synchronized(@{
        ReportPath    = $null
        Result        = $null
        Assessment    = $null
        Runspace      = $null
        Cancelled     = $false
        StartTime     = $null
        ExpectedSec   = 0
        ProgressTimer = $null
        Async         = $null
        Ps            = $null
        Timer         = $null
    })

    # --- Target mode wiring: enable only the active mode's fields ---
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

    # --- Profile change: prefill the override fields and update the description ---
    $fillFromProfile = {
        $name = $cbProfile.SelectedItem.Content
        # Always update the description line, even for Custom.
        if ($profileDescriptions.ContainsKey($name)) {
            $tbProfileDescription.Text = $profileDescriptions[$name]
        }
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
    & $fillFromProfile  # initial prefill

    # --- Collect inputs from the form into a structured hashtable ---
    $collectInputs = {
        $mode = if ($rbLocal.IsChecked) { 'Local' } elseif ($rbUnc.IsChecked) { 'Unc' } else { 'Remote' }
        $target = switch ($mode) {
            'Local'  { $tbLocalPath.Text }
            'Unc'    { $tbUncPath.Text }
            'Remote' { $tbVdaTarget.Text }
        }
        $computerName = if ($mode -eq 'Remote') { $tbVdaName.Text } else { $null }
        $workload = $cbProfile.SelectedItem.Content

        # Only forward override fields the operator actually filled in. Empty text
        # means "use the preset value" except for Custom, where all fields are required.
        $overrides = @{}
        if ($tbBlock.Text)    { $overrides.BlockSize         = $tbBlock.Text }
        if ($tbThreads.Text)  { $overrides.Threads           = [int]$tbThreads.Text }
        if ($tbQd.Text)       { $overrides.QueueDepth        = [int]$tbQd.Text }
        if ($tbWritePct.Text) { $overrides.WriteRatioPercent = [int]$tbWritePct.Text }
        if ($tbDuration.Text) { $overrides.DurationSeconds   = [int]$tbDuration.Text }
        if ($tbFileMb.Text)   { $overrides.TestFileSizeMB    = [int]$tbFileMb.Text }
        # RandomIO defaults to $true for Custom because the GUI doesn't currently
        # surface a checkbox for it (the preset comes from the dropdown otherwise).
        if ($workload -eq 'Custom' -and -not $overrides.ContainsKey('RandomIO')) {
            $overrides.RandomIO = $true
        }

        @{ Mode = $mode; Target = $target; ComputerName = $computerName; Workload = $workload; Overrides = $overrides }
    }

    # --- UI helpers (must run on the WPF dispatcher) ---
    $setStatus = {
        param($txt)
        $window.Dispatcher.Invoke([action]{ $tbStatus.Text = $txt })
    }

    $populateResultsGrid = {
        param($result, $assess)
        if (-not $result) { return }
        $rows = New-Object System.Collections.ObjectModel.ObservableCollection[object]
        $rows.Add([PSCustomObject]@{ Metric = 'IOPS';             Value = $result.IOPS;         Status = '' })
        $rows.Add([PSCustomObject]@{ Metric = 'Read MB/s';        Value = $result.ReadMBps;     Status = $assess.ReadMBps })
        $rows.Add([PSCustomObject]@{ Metric = 'Write MB/s';       Value = $result.WriteMBps;    Status = $assess.WriteMBps })
        $rows.Add([PSCustomObject]@{ Metric = 'Avg latency (ms)'; Value = $result.AvgLatencyMs; Status = $assess.AvgLatencyMs })
        $rows.Add([PSCustomObject]@{ Metric = 'P95 latency (ms)'; Value = $result.Latency95Ms;  Status = $assess.Latency95Ms })
        $rows.Add([PSCustomObject]@{ Metric = 'P99 latency (ms)'; Value = $result.Latency99Ms;  Status = $assess.Latency99Ms })
        $rows.Add([PSCustomObject]@{ Metric = 'CPU %';            Value = $result.CpuPercent;   Status = '' })
        $rows.Add([PSCustomObject]@{ Metric = 'Test file';        Value = $result.TestFilePath; Status = '' })
        $rows.Add([PSCustomObject]@{ Metric = 'Duration (s)';     Value = $result.Duration;     Status = '' })
        $window.Dispatcher.Invoke([action]{ $dgResults.ItemsSource = $rows })
    }

    # --- Run button: preflight on UI thread, then dispatch the actual run ---
    $btnRun.Add_Click({
        $inputs = & $collectInputs

        # Preflight runs on the UI thread because it's fast (<1s for local paths,
        # could hang up to ~30s for an unreachable UNC — acceptable for an MVP).
        $diskSpdPath = $script:DiskSpdExe
        $resolvedSettings = if ($inputs.Workload -eq 'Custom') {
            $inputs.Overrides
        } else {
            try {
                Resolve-DiskSpdSettings -ProfileName $inputs.Workload -Overrides $inputs.Overrides
            } catch {
                [System.Windows.MessageBox]::Show($_.Exception.Message, 'Invalid settings', 'OK', 'Error') | Out-Null
                return
            }
        }

        $pf = Test-DiskSpdPreflight -DiskSpdPath $diskSpdPath -Target $inputs.Target `
                -TestFileSizeMB $resolvedSettings.TestFileSizeMB `
                -ComputerName $inputs.ComputerName -BusinessHoursForce:$false

        if (-not $pf.Pass) {
            [System.Windows.MessageBox]::Show(($pf.Errors -join "`n"), 'Preflight failed', 'OK', 'Error') | Out-Null
            return
        }
        if ($pf.Warnings) {
            $msg  = ($pf.Warnings -join "`n") + "`n`nContinue?"
            $resp = [System.Windows.MessageBox]::Show($msg, 'Confirm', 'OKCancel', 'Warning')
            if ($resp -ne 'OK') { return }
        }

        # Lock the controls during the run.
        $btnRun.IsEnabled    = $false
        $btnSave.IsEnabled   = $false
        $btnCancel.IsEnabled = $true

        # Determinate progress bar: estimate total runtime as the test's
        # DurationSeconds plus ~6s of diskspd warmup/cooldown overhead. Empirical
        # from the integration tests (a 3s test takes ~9s wall-clock).
        # Store StartTime/ExpectedSec on $script:uiState so the tick handler can
        # read them without relying on closure capture (WPF event handlers in
        # PowerShell don't reliably close over outer-scope locals).
        $script:uiState.StartTime   = Get-Date
        $script:uiState.ExpectedSec = [int]$resolvedSettings.DurationSeconds + 6
        $pbProgress.IsIndeterminate = $false
        $pbProgress.Value = 0
        & $setStatus "Running diskspd (0s / $($script:uiState.ExpectedSec)s)"

        # Tick the progress bar every 250ms based on real elapsed time. Doesn't
        # touch diskspd; just gives the operator a "things are happening" signal.
        $progressTimer = New-Object System.Windows.Threading.DispatcherTimer
        $progressTimer.Interval = [TimeSpan]::FromMilliseconds(250)
        $progressTimer.Add_Tick({
            $elapsed = (New-TimeSpan -Start $script:uiState.StartTime).TotalSeconds
            $total   = $script:uiState.ExpectedSec
            # Cap at 99% until the completion timer fires; never show 100% before done.
            $pct = [math]::Min(99, [int](($elapsed / $total) * 100))
            $pbProgress.Value = $pct
            $tbStatus.Text    = "Running diskspd ($([int]$elapsed)s / ${total}s)"
        })
        $progressTimer.Start()
        $script:uiState.ProgressTimer = $progressTimer

        # Build the background runspace. The scriptblock re-dot-sources the script
        # to access the engine functions in a fresh scope, then runs the orchestrator.
        # Returns a hashtable with Ok + ReportPath + Result + Assessment so the UI
        # timer can populate the in-window grid in addition to the saved report.
        $ps = [PowerShell]::Create()
        $null = $ps.AddScript({
            param($scriptPath, $inputs, $outDir)
            . $scriptPath -ErrorAction SilentlyContinue *> $null
            try {
                $diskSpdPath = Join-Path (Split-Path $scriptPath -Parent) 'diskspd.exe'
                $settings = Resolve-DiskSpdSettings -ProfileName $inputs.Workload -Overrides $inputs.Overrides
                $transport = if ($inputs.ComputerName -or $inputs.Target -match '^\\\\') { 'Network' } else { 'Local' }

                $testFile = if ($inputs.Target -match '\.dat$') {
                    $inputs.Target
                } else {
                    Join-Path $inputs.Target ("diskspd-{0}.dat" -f (Get-Date -Format 'yyyy-MM-dd_HHmmss_fff'))
                }
                $xml = if ($inputs.ComputerName) {
                    Invoke-DiskSpdRemote -DiskSpdPath $diskSpdPath -ComputerName $inputs.ComputerName -Settings $settings -TestFilePath $testFile
                } else {
                    Invoke-DiskSpdLocal  -DiskSpdPath $diskSpdPath -Settings $settings -TestFilePath $testFile
                }
                $result = ConvertFrom-DiskSpdXml -Xml $xml -ProfileName $inputs.Workload
                $assess = Get-DiskSpdHealthAssessment -Result $result -Transport $transport
                $report = Export-DiskSpdHtmlReport -Result $result -Assessment $assess -Target $inputs.Target -OutputDirectory $outDir
                @{ Ok = $true; ReportPath = $report; Result = $result; Assessment = $assess }
            } catch {
                @{ Ok = $false; Error = $_.Exception.Message }
            }
        }).AddArgument($PSCommandPath).AddArgument($inputs).AddArgument($script:ScriptRoot)

        $async = $ps.BeginInvoke()
        $script:uiState.Runspace  = $ps
        $script:uiState.Cancelled = $false
        $script:uiState.Async     = $async
        $script:uiState.Ps        = $ps

        # Poll for completion via DispatcherTimer (runs on the UI thread, safe to
        # touch UI controls). All cross-handler state (timers, async handle, runspace)
        # lives on $script:uiState because WPF event handlers in PowerShell don't
        # reliably close over outer-scope locals — especially value types.
        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [TimeSpan]::FromMilliseconds(250)
        $script:uiState.Timer = $timer
        $timer.Add_Tick({
            $async = $script:uiState.Async
            if (-not $async.IsCompleted) { return }
            $script:uiState.Timer.Stop()
            if ($script:uiState.ProgressTimer) { $script:uiState.ProgressTimer.Stop() }

            $ps = $script:uiState.Ps
            try {
                $out = $ps.EndInvoke($async) | Select-Object -First 1
            } catch {
                $out = @{ Ok = $false; Error = $_.Exception.Message }
            }
            $ps.Dispose()

            $btnCancel.IsEnabled = $false
            $btnRun.IsEnabled    = $true

            if ($script:uiState.Cancelled) {
                $pbProgress.Value = 0
                & $setStatus 'Cancelled'
                return
            }
            if (-not $out.Ok) {
                $pbProgress.Value = 0
                & $setStatus "Failed: $($out.Error)"
                [System.Windows.MessageBox]::Show($out.Error, 'diskspd failed', 'OK', 'Error') | Out-Null
                return
            }

            # Finish the bar — diskspd is done.
            $pbProgress.Value = 100

            $script:uiState.ReportPath = $out.ReportPath
            $script:uiState.Result     = $out.Result
            $script:uiState.Assessment = $out.Assessment

            # Populate the in-window results grid so the operator sees numbers
            # before they click "Save Report" to open the HTML.
            & $populateResultsGrid $out.Result $out.Assessment

            & $setStatus "Done - report saved"
            $btnSave.IsEnabled = $true
        })
        $timer.Start()
    })

    $btnCancel.Add_Click({
        if ($script:uiState.Runspace) {
            $script:uiState.Cancelled = $true
            $script:uiState.Runspace.Stop() | Out-Null
        }
        # The completion timer will see IsCompleted true (because Stop()
        # cancels the runspace) and tear down the progress timer.
        & $setStatus 'Cancelling...'
    })

    $btnSave.Add_Click({
        if ($script:uiState.ReportPath -and (Test-Path $script:uiState.ReportPath)) {
            Start-Process $script:uiState.ReportPath
        }
    })

    & $updateTargetFields  # initial control state

    $window.ShowDialog() | Out-Null
}

# --- Entry point ---

# Guard against dot-sourcing (e.g., from Pester tests that load the engine
# functions via `. $scriptPath`). When dot-sourced, $MyInvocation.InvocationName
# is '.' and we MUST NOT execute the dispatch — otherwise every Pester run would
# either error on preflight or pop a WPF window.
if ($MyInvocation.InvocationName -eq '.') { return }

if ($NoUI) {
    if (-not $Target) { throw "-Target is required when -NoUI is set." }

    # Collect CLI-supplied overrides. Only keys the operator actually passed
    # get added — Resolve-DiskSpdSettings will reject unknown keys and merge
    # the rest on top of the named preset (or use them as the full Custom set).
    $overrides = @{}
    foreach ($key in @('BlockSize','Threads','QueueDepth','WriteRatioPercent','DurationSeconds','TestFileSizeMB')) {
        if ($PSBoundParameters.ContainsKey($key)) { $overrides[$key] = $PSBoundParameters[$key] }
    }
    # RandomIO is not a CLI parameter; it derives from the workload. For Custom,
    # default to $true unless the GUI provided otherwise (the GUI's collectInputs
    # block sets RandomIO explicitly).
    if ($Workload -eq 'Custom' -and -not $overrides.ContainsKey('RandomIO')) {
        $overrides['RandomIO'] = $true
    }

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

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
