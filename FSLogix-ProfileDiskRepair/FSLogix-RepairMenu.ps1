<#
.SYNOPSIS
    Interactive TUI launcher for the FSLogix VHDX Health Manager repair tool.

.DESCRIPTION
    Provides a terminal user interface (TUI) menu wrapping FSLogix-Repair.ps1.
    Features include quick scan, full scan+repair, last report viewer, session host
    status, disk space analysis, and a persistent JSON settings store. All operations
    call FSLogix-Repair.ps1 as a subprocess using the parameters configured in
    Settings. Settings are saved to FSLogix-RepairMenu.config.json alongside this
    script and loaded on each launch.

    Requires administrator rights and the Windows Storage module (ships with all
    modern Windows installs -- no Hyper-V role needed, works inside VMs).

.PARAMETER ConfigPath
    Path to the JSON configuration file. Defaults to FSLogix-RepairMenu.config.json
    in the same directory as this script.

.EXAMPLE
    .\FSLogix-RepairMenu.ps1

    Launches the interactive menu. On first run, prompts for required settings.

.EXAMPLE
    .\FSLogix-RepairMenu.ps1 -ConfigPath 'D:\Config\fslogix-menu.json'

    Launches the menu using a custom config file path.

.NOTES
    Version    : 1.0
    Compatible : PowerShell 5.1+
    Requires   : Run as Administrator, Storage module (ships with Windows)
    Depends on : FSLogix-Repair.ps1 in the same directory as this script
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'FSLogix-RepairMenu.config.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ============================================================
# CONSTANTS
# ============================================================
$script:VERSION      = '1.0'
$script:REPAIR_SCRIPT = Join-Path $PSScriptRoot 'FSLogix-Repair.ps1'
$script:CONFIG_PATH  = $ConfigPath

# Column width constants for table rendering
$script:COL_VHDX    = 40
$script:COL_OWNER   = 20
$script:COL_SIZE    = 10
$script:COL_HEALTH  = 14
$script:COL_STATUS  = 18

# ============================================================
# BANNER
# ============================================================
function Show-Banner {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $width = 62

    Write-Host ''
    Write-Host ('+' + ('-' * ($width - 2)) + '+') -ForegroundColor Cyan
    Write-Host ('|' + (' ' * ($width - 2)) + '|') -ForegroundColor Cyan
    Write-Host ('|' + '   ___  ___  _            _        ___      ____   ___'.PadRight($width - 2) + '|') -ForegroundColor Cyan
    Write-Host ('|' + '  | __||  _|| |  ___  ___ |_| __ _|__ \    |_  /  / _ \'.PadRight($width - 2) + '|') -ForegroundColor Cyan
    Write-Host ('|' + '  | _|  \_ \| |_/ _ \/ _ \| |/ _` |  ) |    / /  | (_) |'.PadRight($width - 2) + '|') -ForegroundColor Cyan
    Write-Host ('|' + '  |_|  |___/|___\___/\_, ||_|\__,_| /_/    /___|  \___/'.PadRight($width - 2) + '|') -ForegroundColor Cyan
    Write-Host ('|' + '                      |__/'.PadRight($width - 2) + '|') -ForegroundColor Cyan
    Write-Host ('|' + (' ' * ($width - 2)) + '|') -ForegroundColor Cyan
    Write-Host ('|' + '       FSLogix VHDX Health Manager'.PadRight($width - 2) + '|') -ForegroundColor White
    Write-Host ('|' + ("       Version $script:VERSION  |  $ts").PadRight($width - 2) + '|') -ForegroundColor Gray
    Write-Host ('|' + (' ' * ($width - 2)) + '|') -ForegroundColor Cyan
    Write-Host ('+' + ('-' * ($width - 2)) + '+') -ForegroundColor Cyan
    Write-Host ''
}

# ============================================================
# SETTINGS  (load / save / first-run prompt)
# ============================================================
function Get-DefaultConfig {
    return [PSCustomObject]@{
        ProfileShare         = ''
        SessionHosts         = @()
        OutputPath           = $PSScriptRoot
        MountTimeoutSeconds  = 15
    }
}

function Import-Config {
    if (-not (Test-Path $script:CONFIG_PATH)) {
        return Get-DefaultConfig
    }

    try {
        $raw = Get-Content -Path $script:CONFIG_PATH -Raw -ErrorAction Stop
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop

        # Ensure all expected keys exist (forward-compat guard)
        $defaults = Get-DefaultConfig
        $defaults.PSObject.Properties | ForEach-Object {
            if ($null -eq $obj.($_.Name)) {
                $obj | Add-Member -NotePropertyName $_.Name -NotePropertyValue $_.Value -Force
            }
        }

        # ConvertFrom-Json returns arrays as fixed-size; convert SessionHosts to string[]
        if ($null -eq $obj.SessionHosts -or $obj.SessionHosts.Count -eq 0) {
            $obj.SessionHosts = @()
        }
        else {
            $obj.SessionHosts = @($obj.SessionHosts | ForEach-Object { "$_" })
        }

        return $obj
    }
    catch {
        Write-Host "[WARN] Could not read config file -- using defaults. ($($_.Exception.Message))" -ForegroundColor Yellow
        return Get-DefaultConfig
    }
}

function Save-Config {
    param([PSCustomObject]$Config)

    try {
        $Config | ConvertTo-Json -Depth 5 | Set-Content -Path $script:CONFIG_PATH -Encoding UTF8 -ErrorAction Stop
        Write-Host "[INFO] Settings saved to: $script:CONFIG_PATH" -ForegroundColor Cyan
    }
    catch {
        Write-Host "[FAIL] Could not save config: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Test-ConfigReady {
    param([PSCustomObject]$Config)
    return ($Config.ProfileShare -ne '') -and ($Config.SessionHosts.Count -gt 0)
}

# ============================================================
# HELPERS  (input, display, progress)
# ============================================================
function Read-MenuChoice {
    <#
    .SYNOPSIS
        Prompts the user with a styled prompt and returns a trimmed uppercase string.
        Never throws; returns empty string on any read failure.
    #>
    param([string]$Prompt = 'Select')

    Write-Host ''
    Write-Host ('+' + ('-' * 40) + '+') -ForegroundColor DarkCyan
    try {
        $raw = Read-Host "  $Prompt"
        return $raw.Trim().ToUpper()
    }
    catch {
        return ''
    }
}

function Read-NonEmptyString {
    <#
    .SYNOPSIS
        Loops until the user enters a non-empty string. Returns the trimmed value.
    #>
    param(
        [string]$Prompt,
        [string]$Default = ''
    )

    while ($true) {
        $display = if ($Default -ne '') { "$Prompt [$Default]" } else { $Prompt }
        try {
            $val = (Read-Host $display).Trim()
        }
        catch {
            $val = ''
        }

        if ($val -eq '' -and $Default -ne '') {
            return $Default
        }
        if ($val -ne '') {
            return $val
        }
        Write-Host '  [WARN] Value cannot be empty. Please try again.' -ForegroundColor Yellow
    }
}

function Read-IntInRange {
    <#
    .SYNOPSIS
        Loops until the user enters an integer within [Min, Max]. Returns the integer.
    #>
    param(
        [string]$Prompt,
        [int]$Min,
        [int]$Max,
        [int]$Default
    )

    while ($true) {
        $display = "$Prompt [$Default] ($Min-$Max)"
        try {
            $raw = (Read-Host $display).Trim()
        }
        catch {
            $raw = ''
        }

        if ($raw -eq '') { return $Default }

        $parsed = 0
        if ([int]::TryParse($raw, [ref]$parsed)) {
            if ($parsed -ge $Min -and $parsed -le $Max) {
                return $parsed
            }
        }
        Write-Host "  [WARN] Enter a number between $Min and $Max." -ForegroundColor Yellow
    }
}

function Write-SectionHeader {
    param([string]$Title)
    $line = '=' * 62
    Write-Host ''
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor White
    Write-Host $line -ForegroundColor Cyan
    Write-Host ''
}

function Write-StatusLine {
    <#
    .SYNOPSIS
        Writes a single status-prefixed line with the appropriate colour.
        Tag must be one of: PASS FAIL WARN INFO SKIP
    #>
    param(
        [ValidateSet('PASS','FAIL','WARN','INFO','SKIP')]
        [string]$Tag,
        [string]$Message
    )

    $colour = switch ($Tag) {
        'PASS' { 'Green'   }
        'FAIL' { 'Red'     }
        'WARN' { 'Yellow'  }
        'INFO' { 'Cyan'    }
        'SKIP' { 'Gray'    }
    }
    Write-Host "  [$Tag] $Message" -ForegroundColor $colour
}

function Write-TableDivider {
    param([int[]]$Widths, [string]$Colour = 'DarkCyan')
    $parts = $Widths | ForEach-Object { '+' + ('-' * ($_)) }
    Write-Host ($parts -join '' + '+') -ForegroundColor $Colour
}

function Write-TableRow {
    param(
        [string[]]$Cells,
        [int[]]$Widths,
        [string[]]$Colours,
        [string]$DefaultColour = 'White'
    )

    $line = ''
    for ($i = 0; $i -lt $Cells.Count; $i++) {
        $w   = if ($i -lt $Widths.Count)  { $Widths[$i]  } else { 20 }
        $c   = if ($i -lt $Colours.Count) { $Colours[$i] } else { $DefaultColour }
        $val = $Cells[$i]
        if ($val.Length -gt ($w - 2)) { $val = $val.Substring(0, $w - 4) + '...' }
        $line += '| ' + $val.PadRight($w - 2) + ' '
    }
    $line += '|'

    # Write column-by-column with individual colours
    $pos = 0
    for ($i = 0; $i -lt $Cells.Count; $i++) {
        $w   = if ($i -lt $Widths.Count)  { $Widths[$i]  } else { 20 }
        $c   = if ($i -lt $Colours.Count) { $Colours[$i] } else { $DefaultColour }
        $val = $Cells[$i]
        if ($val.Length -gt ($w - 2)) { $val = $val.Substring(0, $w - 4) + '...' }
        $cell = '| ' + $val.PadRight($w - 2) + ' '
        Write-Host $cell -ForegroundColor $c -NoNewline
    }
    Write-Host '|' -ForegroundColor DarkCyan
}

function Get-StatusColour {
    param([string]$Status)
    switch -Wildcard ($Status.ToUpper()) {
        'HEALTHY'        { return 'Green'  }
        'REPAIRED'       { return 'Green'  }
        'REPAIR FAILED'  { return 'Red'    }
        'ERROR'          { return 'Red'    }
        'SKIPPED*'       { return 'Gray'   }
        default          { return 'White'  }
    }
}

function Show-InlineProgress {
    <#
    .SYNOPSIS
        Writes an inline progress bar to the current console line.
        Call repeatedly from within a loop; the cursor stays on the same line.
    #>
    param(
        [int]$Current,
        [int]$Total,
        [string]$Label = '',
        [int]$BarWidth = 30
    )

    if ($Total -le 0) { return }

    $pct      = [math]::Round(($Current / $Total) * 100)
    $filled   = [math]::Round(($pct / 100) * $BarWidth)
    $empty    = $BarWidth - $filled
    $bar      = '#' * $filled + '-' * $empty

    $labelTrunc = if ($Label.Length -gt 28) { $Label.Substring(0, 25) + '...' } else { $Label.PadRight(28) }

    $line = "  [INFO] [$bar] $($pct.ToString().PadLeft(3))%  $labelTrunc"
    Write-Host "`r$line" -NoNewline -ForegroundColor Cyan
}

# ============================================================
# MENU: MAIN
# ============================================================
function Show-MainMenu {
    param([PSCustomObject]$Config)

    $shareDisplay = if ($Config.ProfileShare -ne '') { $Config.ProfileShare } else { '(not set)' }
    $hostsDisplay = if ($Config.SessionHosts.Count -gt 0) { $Config.SessionHosts -join ', ' } else { '(not set)' }
    $ready        = Test-ConfigReady $Config

    Write-Host ''
    Write-Host '+--------------------------------------------------------------+' -ForegroundColor DarkCyan
    Write-Host '|  MAIN MENU                                                   |' -ForegroundColor White
    Write-Host '+--------------------------------------------------------------+' -ForegroundColor DarkCyan
    Write-Host '|                                                              |' -ForegroundColor DarkCyan

    # Active config display
    $shareLabel = "  Share : $shareDisplay"
    $hostsLabel = "  Hosts : $hostsDisplay"
    if ($shareLabel.Length -gt 62) { $shareLabel = $shareLabel.Substring(0, 59) + '...' }
    if ($hostsLabel.Length -gt 62) { $hostsLabel = $hostsLabel.Substring(0, 59) + '...' }

    Write-Host ('|  ' + $shareLabel.PadRight(60) + '|') -ForegroundColor Gray
    Write-Host ('|  ' + $hostsLabel.PadRight(60) + '|') -ForegroundColor Gray
    Write-Host '|                                                              |' -ForegroundColor DarkCyan
    Write-Host '+--------------------------------------------------------------+' -ForegroundColor DarkCyan

    if (-not $ready) {
        Write-Host '|  [WARN] Settings incomplete -- configure before scanning.    |' -ForegroundColor Yellow
        Write-Host '+--------------------------------------------------------------+' -ForegroundColor DarkCyan
    }

    Write-Host ''
    Write-Host '  [1]  Quick Scan          (scan only, no repairs)'           -ForegroundColor White
    Write-Host '  [2]  Scan + Repair       (full run with repair)'            -ForegroundColor White
    Write-Host '  [3]  View Last Report    (formatted table from CSV)'        -ForegroundColor White
    Write-Host '  [4]  Session Host Status (query active sessions)'           -ForegroundColor White
    Write-Host '  [5]  Disk Space Analysis (VHDX sizes, largest first)'       -ForegroundColor White
    Write-Host '  [6]  Settings            (configure paths and hosts)'       -ForegroundColor White
    Write-Host '  [7]  Help'                                                   -ForegroundColor White
    Write-Host '  [Q]  Quit'                                                   -ForegroundColor Gray
    Write-Host ''
}

# ============================================================
# MENU ACTION: QUICK SCAN  (scan only via WhatIf)
# ============================================================
function Invoke-QuickScan {
    param([PSCustomObject]$Config)

    Write-SectionHeader 'QUICK SCAN  (scan only -- no repairs performed)'

    if (-not (Test-ConfigReady $Config)) {
        Write-StatusLine WARN 'Settings are incomplete. Please configure the tool first (option 6).'
        return
    }

    if (-not (Test-Path $script:REPAIR_SCRIPT)) {
        Write-StatusLine FAIL "Repair script not found: $script:REPAIR_SCRIPT"
        return
    }

    Write-StatusLine INFO "Profile share : $($Config.ProfileShare)"
    Write-StatusLine INFO "Session hosts : $($Config.SessionHosts -join ', ')"
    Write-StatusLine INFO "Output path   : $($Config.OutputPath)"
    Write-Host ''
    Write-StatusLine INFO 'Running scan in WhatIf mode -- no changes will be made...'
    Write-Host ''

    try {
        $args = @(
            '-NoProfile'
            '-ExecutionPolicy', 'Bypass'
            '-File', $script:REPAIR_SCRIPT
            '-ProfileShare', $Config.ProfileShare
            '-SessionHosts', ($Config.SessionHosts -join ',')
            '-OutputPath', $Config.OutputPath
            '-MountTimeoutSeconds', $Config.MountTimeoutSeconds
            '-WhatIf'
        )
        & powershell.exe $args
        Write-Host ''
        Write-StatusLine PASS 'Quick scan complete.'
    }
    catch {
        Write-StatusLine FAIL "Failed to launch repair script: $($_.Exception.Message)"
    }
}

# ============================================================
# MENU ACTION: SCAN + REPAIR
# ============================================================
function Invoke-ScanAndRepair {
    param([PSCustomObject]$Config)

    Write-SectionHeader 'SCAN + REPAIR'

    if (-not (Test-ConfigReady $Config)) {
        Write-StatusLine WARN 'Settings are incomplete. Please configure the tool first (option 6).'
        return
    }

    if (-not (Test-Path $script:REPAIR_SCRIPT)) {
        Write-StatusLine FAIL "Repair script not found: $script:REPAIR_SCRIPT"
        return
    }

    Write-StatusLine INFO "Profile share : $($Config.ProfileShare)"
    Write-StatusLine INFO "Session hosts : $($Config.SessionHosts -join ', ')"
    Write-StatusLine INFO "Output path   : $($Config.OutputPath)"
    Write-StatusLine WARN 'This operation will REPAIR unhealthy VHDX files. Active users will be skipped.'
    Write-Host ''

    try {
        $confirm = Read-MenuChoice 'Type YES to proceed, or press Enter to cancel'
        if ($confirm -ne 'YES') {
            Write-StatusLine INFO 'Operation cancelled.'
            return
        }
    }
    catch {
        Write-StatusLine INFO 'Operation cancelled.'
        return
    }

    Write-Host ''
    Write-StatusLine INFO 'Launching FSLogix-Repair.ps1...'
    Write-Host ''

    try {
        $args = @(
            '-NoProfile'
            '-ExecutionPolicy', 'Bypass'
            '-File', $script:REPAIR_SCRIPT
            '-ProfileShare', $Config.ProfileShare
            '-SessionHosts', ($Config.SessionHosts -join ',')
            '-OutputPath', $Config.OutputPath
            '-MountTimeoutSeconds', $Config.MountTimeoutSeconds
            '-Force'
        )
        & powershell.exe $args
        Write-Host ''
        Write-StatusLine PASS 'Scan + Repair run complete. Check output above for details.'
        Write-StatusLine INFO "Report saved to: $($Config.OutputPath)"
    }
    catch {
        Write-StatusLine FAIL "Failed to launch repair script: $($_.Exception.Message)"
    }
}

# ============================================================
# MENU ACTION: VIEW LAST REPORT
# ============================================================
function Show-LastReport {
    param([PSCustomObject]$Config)

    Write-SectionHeader 'VIEW LAST REPORT'

    $outputDir = $Config.OutputPath
    if (-not (Test-Path $outputDir)) {
        Write-StatusLine FAIL "Output directory not found: $outputDir"
        return
    }

    try {
        $csvFiles = Get-ChildItem -Path $outputDir -Filter 'VHDX_ScanRepair_*.csv' -ErrorAction Stop |
                    Sort-Object LastWriteTime -Descending

        if (-not $csvFiles -or $csvFiles.Count -eq 0) {
            Write-StatusLine WARN "No report CSV files found in: $outputDir"
            Write-StatusLine INFO 'Run a scan first to generate a report.'
            return
        }

        $latest = $csvFiles | Select-Object -First 1
        Write-StatusLine INFO "Report file : $($latest.FullName)"
        Write-StatusLine INFO "Generated   : $($latest.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))"

        if ($csvFiles.Count -gt 1) {
            Write-StatusLine INFO "$($csvFiles.Count) report(s) found. Showing most recent."
        }
        Write-Host ''

        $rows = Import-Csv -Path $latest.FullName -ErrorAction Stop

        if (-not $rows -or @($rows).Count -eq 0) {
            Write-StatusLine WARN 'Report file is empty.'
            return
        }

        # --- Render table
        $widths = @($script:COL_VHDX, $script:COL_OWNER, $script:COL_SIZE, $script:COL_HEALTH, $script:COL_STATUS)
        $headers = @('VHDX File', 'Owner', 'Size(MB)', 'HealthBefore', 'Status')

        Write-TableDivider $widths
        Write-TableRow -Cells $headers -Widths $widths -Colours @('Cyan','Cyan','Cyan','Cyan','Cyan')
        Write-TableDivider $widths

        foreach ($row in $rows) {
            $statusColour = Get-StatusColour $row.Status
            $colours = @('White', 'Gray', 'Gray', 'Gray', $statusColour)
            Write-TableRow -Cells @($row.VHDX, $row.Owner, $row.SizeMB, $row.HealthBefore, $row.Status) `
                           -Widths $widths -Colours $colours
        }

        Write-TableDivider $widths
        Write-Host ''

        # --- Summary counts
        $healthy  = @($rows | Where-Object { $_.Status -eq 'HEALTHY' }).Count
        $repaired = @($rows | Where-Object { $_.Status -eq 'REPAIRED' }).Count
        $failed   = @($rows | Where-Object { $_.Status -like 'REPAIR FAILED' -or $_.Status -eq 'ERROR' }).Count
        $skipped  = @($rows | Where-Object { $_.Status -like 'SKIPPED*' }).Count

        Write-Host '  Summary:' -ForegroundColor White
        Write-Host "    Total   : $(@($rows).Count)" -ForegroundColor White
        Write-Host "    Healthy : $healthy"           -ForegroundColor Green
        Write-Host "    Repaired: $repaired"          -ForegroundColor Green
        Write-Host "    Failed  : $failed"            -ForegroundColor Red
        Write-Host "    Skipped : $skipped"           -ForegroundColor Gray
        Write-Host ''

        if ($failed -gt 0) {
            Write-Host '  VHDXs requiring manual attention:' -ForegroundColor Red
            $rows | Where-Object { $_.Status -like 'REPAIR FAILED' -or $_.Status -eq 'ERROR' } |
                ForEach-Object {
                    $err = if ($_.Error) { " -- $($_.Error)" } else { '' }
                    Write-Host "    [FAIL] $($_.VHDX)$err" -ForegroundColor Red
                }
            Write-Host ''
        }
    }
    catch {
        Write-StatusLine FAIL "Could not read report: $($_.Exception.Message)"
    }
}

# ============================================================
# MENU ACTION: SESSION HOST STATUS
# ============================================================
function Show-SessionHostStatus {
    param([PSCustomObject]$Config)

    Write-SectionHeader 'SESSION HOST STATUS'

    if ($Config.SessionHosts.Count -eq 0) {
        Write-StatusLine WARN 'No session hosts configured. Please configure the tool first (option 6).'
        return
    }

    $allSessions = [System.Collections.ArrayList]::new()

    foreach ($host in $Config.SessionHosts) {
        Write-Host "  Querying $host..." -ForegroundColor Gray -NoNewline

        try {
            $sessions = query session /server:$host 2>$null
            if (-not $sessions) {
                Write-Host " [WARN] No data returned" -ForegroundColor Yellow
                continue
            }

            $headerLine = $sessions[0]
            $userCol    = $headerLine.IndexOf('USERNAME')
            $sessCol    = $headerLine.IndexOf('SESSIONNAME')
            $stateCol   = $headerLine.IndexOf('STATE')

            if ($userCol -lt 0 -or $stateCol -lt 0) {
                Write-Host " [WARN] Unexpected output format" -ForegroundColor Yellow
                continue
            }

            $sessionCount = 0
            foreach ($line in $sessions | Select-Object -Skip 1) {
                if ($line.Length -lt $stateCol) { continue }

                $stateField = $line.Substring($stateCol).Trim() -split '\s+' | Select-Object -First 1
                $userField  = $line.Substring($userCol, ($stateCol - $userCol)).Trim()

                if ($userField -and $userField -ne '') {
                    $allSessions.Add([PSCustomObject]@{
                        Host     = $host
                        User     = $userField
                        State    = $stateField
                    }) | Out-Null
                    $sessionCount++
                }
            }
            Write-Host " [PASS] $sessionCount session(s)" -ForegroundColor Green
        }
        catch {
            Write-Host " [FAIL] $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Write-Host ''

    if ($allSessions.Count -eq 0) {
        Write-StatusLine PASS 'No active sessions detected across all session hosts.'
        return
    }

    # --- Render session table
    $wHost  = 20
    $wUser  = 24
    $wState = 12
    $widths = @($wHost, $wUser, $wState)

    Write-TableDivider $widths
    Write-TableRow -Cells @('Session Host', 'Username', 'State') -Widths $widths `
                   -Colours @('Cyan','Cyan','Cyan')
    Write-TableDivider $widths

    foreach ($s in $allSessions) {
        $stateColour = switch ($s.State) {
            'Active' { 'Yellow' }
            'Disc'   { 'Gray'   }
            default  { 'White'  }
        }
        Write-TableRow -Cells @($s.Host, $s.User, $s.State) -Widths $widths `
                       -Colours @('White', 'White', $stateColour)
    }

    Write-TableDivider $widths
    Write-Host ''
    Write-StatusLine INFO "Total sessions: $($allSessions.Count)"

    $activeCount = @($allSessions | Where-Object { $_.State -eq 'Active' }).Count
    $discCount   = @($allSessions | Where-Object { $_.State -eq 'Disc'   }).Count

    if ($activeCount -gt 0) {
        Write-StatusLine WARN "$activeCount active session(s) -- these VHDXs will be skipped during repair."
    }
    if ($discCount -gt 0) {
        Write-StatusLine WARN "$discCount disconnected session(s) -- these VHDXs will also be skipped."
    }
    Write-Host ''
}

# ============================================================
# MENU ACTION: DISK SPACE ANALYSIS
# ============================================================
function Show-DiskSpaceAnalysis {
    param([PSCustomObject]$Config)

    Write-SectionHeader 'DISK SPACE ANALYSIS'

    if ($Config.ProfileShare -eq '') {
        Write-StatusLine WARN 'Profile share not configured. Please configure the tool first (option 6).'
        return
    }

    if (-not (Test-Path $Config.ProfileShare)) {
        Write-StatusLine FAIL "Profile share not accessible: $($Config.ProfileShare)"
        return
    }

    Write-StatusLine INFO "Scanning: $($Config.ProfileShare)"
    Write-Host "  Please wait..." -ForegroundColor Gray

    try {
        $vhdxFiles = Get-ChildItem -Path $Config.ProfileShare -Filter '*.vhdx' -Recurse -ErrorAction Stop

        if (-not $vhdxFiles -or $vhdxFiles.Count -eq 0) {
            Write-StatusLine WARN 'No VHDX files found.'
            return
        }

        $vhdxList = @($vhdxFiles) |
            ForEach-Object {
                $owner = ($_.Directory.Name -split '_')[0]
                [PSCustomObject]@{
                    VHDX   = $_.Name
                    Owner  = $owner
                    SizeMB = [math]::Round($_.Length / 1MB, 2)
                    SizeGB = [math]::Round($_.Length / 1GB, 3)
                    Path   = $_.DirectoryName
                }
            } |
            Sort-Object SizeMB -Descending

        $totalMB = ($vhdxList | Measure-Object SizeMB -Sum).Sum
        $totalGB = [math]::Round($totalMB / 1024, 2)
        $avgMB   = [math]::Round($totalMB / $vhdxList.Count, 2)

        Write-Host ''

        # --- Render table
        $wVhdx  = 38
        $wOwner = 18
        $wMB    = 12
        $wGB    = 10
        $widths = @($wVhdx, $wOwner, $wMB, $wGB)

        Write-TableDivider $widths
        Write-TableRow -Cells @('VHDX File', 'Owner', 'Size (MB)', 'Size (GB)') -Widths $widths `
                       -Colours @('Cyan','Cyan','Cyan','Cyan')
        Write-TableDivider $widths

        $rank = 0
        foreach ($v in $vhdxList) {
            $rank++
            $mbColour = if   ($v.SizeMB -ge 10240) { 'Red'    }
                        elseif ($v.SizeMB -ge 4096)  { 'Yellow' }
                        else                          { 'Green'  }

            Write-TableRow -Cells @($v.VHDX, $v.Owner, $v.SizeMB, $v.SizeGB) -Widths $widths `
                           -Colours @('White', 'Gray', $mbColour, $mbColour)
        }

        Write-TableDivider $widths
        Write-Host ''
        Write-Host '  Totals:' -ForegroundColor White
        Write-Host "    Files    : $($vhdxList.Count)"    -ForegroundColor White
        Write-Host "    Total    : ${totalGB} GB ($totalMB MB)" -ForegroundColor White
        Write-Host "    Average  : ${avgMB} MB per disk"        -ForegroundColor White
        Write-Host ''
        Write-Host '  Size thresholds:' -ForegroundColor White
        Write-Host '    Green  = under 4 GB    Yellow = 4-10 GB    Red = over 10 GB' -ForegroundColor Gray
        Write-Host ''

        # --- Identify top consumers
        $top3 = $vhdxList | Select-Object -First 3
        if ($top3) {
            Write-Host '  Top consumers:' -ForegroundColor Yellow
            foreach ($t in $top3) {
                Write-Host "    $($t.SizeMB) MB  --  $($t.VHDX)  ($($t.Owner))" -ForegroundColor Yellow
            }
            Write-Host ''
        }
    }
    catch {
        Write-StatusLine FAIL "Error during disk space analysis: $($_.Exception.Message)"
    }
}

# ============================================================
# MENU ACTION: SETTINGS
# ============================================================
function Show-Settings {
    param([PSCustomObject]$Config)

    Write-SectionHeader 'SETTINGS'

    Write-Host '  Current configuration:' -ForegroundColor White
    Write-Host "    [1] Profile Share         : $($Config.ProfileShare)"         -ForegroundColor Gray
    Write-Host "    [2] Session Hosts         : $($Config.SessionHosts -join ', ')" -ForegroundColor Gray
    Write-Host "    [3] Output Path           : $($Config.OutputPath)"           -ForegroundColor Gray
    Write-Host "    [4] Mount Timeout (sec)   : $($Config.MountTimeoutSeconds)"  -ForegroundColor Gray
    Write-Host "    [S] Save and return"                                          -ForegroundColor White
    Write-Host "    [X] Discard and return"                                       -ForegroundColor Gray
    Write-Host ''

    $choice = Read-MenuChoice 'Setting to change (1-4, S to save, X to cancel)'

    switch ($choice) {
        '1' {
            Write-Host ''
            Write-Host '  UNC path to FSLogix Profile Containers share.' -ForegroundColor Gray
            Write-Host '  Example: \\fileserver\FSLogix\ProfileContainers' -ForegroundColor Gray
            Write-Host ''
            $val = Read-NonEmptyString -Prompt '  Profile Share' -Default $Config.ProfileShare
            $Config.ProfileShare = $val
            Write-StatusLine PASS "Profile share set to: $val"
            Show-Settings -Config $Config
        }

        '2' {
            Write-Host ''
            Write-Host '  Enter session host names one per line.' -ForegroundColor Gray
            Write-Host '  Type a blank line when done. Current: ' -NoNewline -ForegroundColor Gray
            Write-Host ($Config.SessionHosts -join ', ') -ForegroundColor White
            Write-Host ''

            $newHosts = [System.Collections.ArrayList]::new()
            while ($true) {
                try {
                    $h = (Read-Host "  Host (blank to finish)").Trim()
                }
                catch {
                    $h = ''
                }
                if ($h -eq '') { break }
                $newHosts.Add($h) | Out-Null
                Write-StatusLine INFO "Added: $h"
            }

            if ($newHosts.Count -gt 0) {
                $Config.SessionHosts = @($newHosts)
                Write-StatusLine PASS "Session hosts set to: $($Config.SessionHosts -join ', ')"
            }
            else {
                Write-StatusLine WARN 'No hosts entered. Keeping existing value.'
            }
            Show-Settings -Config $Config
        }

        '3' {
            Write-Host ''
            Write-Host '  Directory where CSV reports will be saved.' -ForegroundColor Gray
            Write-Host ''
            $val = Read-NonEmptyString -Prompt '  Output Path' -Default $Config.OutputPath
            if (-not (Test-Path $val)) {
                Write-StatusLine WARN "Path does not exist: $val"
                try {
                    $create = Read-MenuChoice 'Create directory? (Y/N)'
                    if ($create -eq 'Y') {
                        New-Item -ItemType Directory -Path $val -Force -ErrorAction Stop | Out-Null
                        Write-StatusLine PASS "Directory created: $val"
                        $Config.OutputPath = $val
                    }
                    else {
                        Write-StatusLine INFO 'Output path unchanged.'
                    }
                }
                catch {
                    Write-StatusLine FAIL "Could not create directory: $($_.Exception.Message)"
                }
            }
            else {
                $Config.OutputPath = $val
                Write-StatusLine PASS "Output path set to: $val"
            }
            Show-Settings -Config $Config
        }

        '4' {
            Write-Host ''
            $val = Read-IntInRange -Prompt '  Mount timeout (seconds)' -Min 5 -Max 120 `
                                   -Default $Config.MountTimeoutSeconds
            $Config.MountTimeoutSeconds = $val
            Write-StatusLine PASS "Mount timeout set to: $val seconds"
            Show-Settings -Config $Config
        }

        'S' {
            Save-Config -Config $Config
        }

        'X' {
            Write-StatusLine INFO 'Changes discarded.'
        }

        default {
            Write-StatusLine WARN "Invalid selection: '$choice'. Enter 1-4, S, or X."
            Show-Settings -Config $Config
        }
    }
}

# ============================================================
# MENU ACTION: HELP
# ============================================================
function Show-Help {
    Write-SectionHeader 'HELP'

    Write-Host '  FSLogix VHDX Health Manager - TUI Launcher' -ForegroundColor White
    Write-Host '  Version ' + $script:VERSION -ForegroundColor Gray
    Write-Host ''

    Write-Host '  OVERVIEW' -ForegroundColor Cyan
    Write-Host '  --------' -ForegroundColor DarkCyan
    Write-Host '  This tool is a menu-driven interface for FSLogix-Repair.ps1.' -ForegroundColor Gray
    Write-Host '  It scans and repairs VHDX profile disks for filesystem errors.' -ForegroundColor Gray
    Write-Host '  Users with active or disconnected RDS sessions are automatically' -ForegroundColor Gray
    Write-Host '  skipped to prevent data corruption.' -ForegroundColor Gray
    Write-Host ''

    Write-Host '  MENU OPTIONS' -ForegroundColor Cyan
    Write-Host '  ------------' -ForegroundColor DarkCyan
    Write-Host '  [1] Quick Scan     - Runs the repair script with -WhatIf (no changes).' -ForegroundColor Gray
    Write-Host '                       Use this to assess the health of all VHDXs.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  [2] Scan + Repair  - Runs the full repair. Mounts each offline VHDX,' -ForegroundColor Gray
    Write-Host '                       scans for filesystem errors, and repairs unhealthy' -ForegroundColor Gray
    Write-Host '                       volumes. Exports a timestamped CSV report.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  [3] View Last      - Loads the most recent CSV report and displays' -ForegroundColor Gray
    Write-Host '  Report               it as a formatted table with color-coded status.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  [4] Session Host   - Queries each configured RDS session host with' -ForegroundColor Gray
    Write-Host '  Status               "query session" and shows active/disconnected' -ForegroundColor Gray
    Write-Host '                       sessions. Useful for planning maintenance windows.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  [5] Disk Space     - Lists all VHDX files sorted by size (largest' -ForegroundColor Gray
    Write-Host '  Analysis             first). Highlights files over 4 GB and 10 GB.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  [6] Settings       - Configure the profile share UNC path, session' -ForegroundColor Gray
    Write-Host '                       hosts, output directory, and mount timeout.' -ForegroundColor Gray
    Write-Host '                       Settings persist to FSLogix-RepairMenu.config.json.' -ForegroundColor Gray
    Write-Host ''

    Write-Host '  REQUIREMENTS' -ForegroundColor Cyan
    Write-Host '  ------------' -ForegroundColor DarkCyan
    Write-Host '  - Must be run as Administrator' -ForegroundColor Gray
    Write-Host '  - Hyper-V PowerShell module must be installed' -ForegroundColor Gray
    Write-Host '  - Profile share must be accessible from this machine' -ForegroundColor Gray
    Write-Host '  - VHDXs must not be actively mounted by another process' -ForegroundColor Gray
    Write-Host ''

    Write-Host '  STATUS CODES' -ForegroundColor Cyan
    Write-Host '  ------------' -ForegroundColor DarkCyan
    Write-Host '  [PASS]    - ' -NoNewline -ForegroundColor Green
    Write-Host 'Operation succeeded / disk is healthy'               -ForegroundColor Gray
    Write-Host '  [FAIL]    - ' -NoNewline -ForegroundColor Red
    Write-Host 'Operation failed / disk could not be repaired'       -ForegroundColor Gray
    Write-Host '  [WARN]    - ' -NoNewline -ForegroundColor Yellow
    Write-Host 'Non-critical issue / disk was repaired'              -ForegroundColor Gray
    Write-Host '  [INFO]    - ' -NoNewline -ForegroundColor Cyan
    Write-Host 'Informational message'                               -ForegroundColor Gray
    Write-Host '  [SKIP]    - ' -NoNewline -ForegroundColor Gray
    Write-Host 'Item was intentionally skipped'                      -ForegroundColor Gray
    Write-Host ''

    Write-Host '  CONFIG FILE' -ForegroundColor Cyan
    Write-Host '  -----------' -ForegroundColor DarkCyan
    Write-Host "  $script:CONFIG_PATH" -ForegroundColor Gray
    Write-Host ''
}

# ============================================================
# FIRST-RUN SETUP WIZARD
# ============================================================
function Invoke-FirstRunSetup {
    param([PSCustomObject]$Config)

    Write-Host ''
    Write-Host '+--------------------------------------------------------------+' -ForegroundColor Yellow
    Write-Host '|  FIRST-RUN SETUP                                             |' -ForegroundColor Yellow
    Write-Host '|                                                              |' -ForegroundColor Yellow
    Write-Host '|  No configuration found. Enter the required values below.   |' -ForegroundColor Yellow
    Write-Host '|  These will be saved to FSLogix-RepairMenu.config.json.     |' -ForegroundColor Yellow
    Write-Host '+--------------------------------------------------------------+' -ForegroundColor Yellow
    Write-Host ''

    # Profile share
    Write-Host '  [1/3] PROFILE SHARE' -ForegroundColor Cyan
    Write-Host '  UNC path to the FSLogix Profile Containers folder.' -ForegroundColor Gray
    Write-Host '  Example: \\fileserver\FSLogix\ProfileContainers' -ForegroundColor Gray
    Write-Host ''

    $share = Read-NonEmptyString -Prompt '  Profile share UNC path'
    $Config.ProfileShare = $share

    if (-not (Test-Path $share)) {
        Write-StatusLine WARN "Cannot reach path right now: $share"
        Write-StatusLine WARN 'Saved anyway -- verify the path is correct before running scans.'
    }
    else {
        Write-StatusLine PASS "Path is accessible."
    }
    Write-Host ''

    # Session hosts
    Write-Host '  [2/3] SESSION HOSTS' -ForegroundColor Cyan
    Write-Host '  Enter the RDS/VDI session host names to check for active users.' -ForegroundColor Gray
    Write-Host '  Enter one per line. Type a blank line when done.' -ForegroundColor Gray
    Write-Host ''

    $newHosts = [System.Collections.ArrayList]::new()
    while ($true) {
        try {
            $h = (Read-Host '  Hostname (blank to finish)').Trim()
        }
        catch {
            $h = ''
        }
        if ($h -eq '') {
            if ($newHosts.Count -eq 0) {
                Write-StatusLine WARN 'At least one session host is recommended. Enter a name or type SKIP.'
                try {
                    $skip = (Read-Host '  Host or SKIP').Trim().ToUpper()
                }
                catch {
                    $skip = 'SKIP'
                }
                if ($skip -eq 'SKIP') { break }
                if ($skip -ne '') { $newHosts.Add($skip) | Out-Null }
            }
            else {
                break
            }
        }
        else {
            $newHosts.Add($h) | Out-Null
            Write-StatusLine INFO "Added: $h"
        }
    }
    $Config.SessionHosts = @($newHosts)
    Write-Host ''

    # Output path
    Write-Host '  [3/3] OUTPUT PATH' -ForegroundColor Cyan
    Write-Host '  Directory where CSV reports will be saved.' -ForegroundColor Gray
    Write-Host ''

    $outPath = Read-NonEmptyString -Prompt '  Output path' -Default $Config.OutputPath
    if (-not (Test-Path $outPath)) {
        Write-StatusLine WARN "Path does not exist: $outPath"
        try {
            $create = (Read-Host '  Create it now? (Y/N)').Trim().ToUpper()
        }
        catch {
            $create = 'N'
        }
        if ($create -eq 'Y') {
            try {
                New-Item -ItemType Directory -Path $outPath -Force -ErrorAction Stop | Out-Null
                Write-StatusLine PASS "Created: $outPath"
            }
            catch {
                Write-StatusLine FAIL "Could not create: $($_.Exception.Message)"
                $outPath = $PSScriptRoot
                Write-StatusLine WARN "Falling back to script directory: $outPath"
            }
        }
        else {
            $outPath = $PSScriptRoot
            Write-StatusLine WARN "Using script directory as fallback: $outPath"
        }
    }
    $Config.OutputPath = $outPath
    Write-Host ''

    Save-Config -Config $Config
    Write-StatusLine PASS 'Setup complete. You can update settings at any time via option [6].'
    Write-Host ''

    return $Config
}

# ============================================================
# PRESS-ANY-KEY PAUSE
# ============================================================
function Wait-ForKeyPress {
    Write-Host ''
    Write-Host '  Press any key to return to the main menu...' -ForegroundColor DarkGray
    try {
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    catch {
        # Fallback for hosts that don't support RawUI (e.g. ISE, VS Code terminal)
        try { Read-Host '  Press Enter to continue' } catch { }
    }
}

# ============================================================
# MAIN LOOP
# ============================================================
function Start-TuiMenu {
    # Load or initialise config
    $config = Import-Config

    # Clear screen and draw banner
    Clear-Host
    Show-Banner

    # First-run wizard if config is empty
    if (-not (Test-ConfigReady $config)) {
        $config = Invoke-FirstRunSetup -Config $config
        Write-Host ''
        Wait-ForKeyPress
    }

    # Main loop
    while ($true) {
        Clear-Host
        Show-Banner
        Show-MainMenu -Config $config

        $choice = Read-MenuChoice 'Enter selection'

        switch ($choice) {
            '1' {
                Clear-Host
                Show-Banner
                Invoke-QuickScan -Config $config
                Wait-ForKeyPress
            }

            '2' {
                Clear-Host
                Show-Banner
                Invoke-ScanAndRepair -Config $config
                Wait-ForKeyPress
            }

            '3' {
                Clear-Host
                Show-Banner
                Show-LastReport -Config $config
                Wait-ForKeyPress
            }

            '4' {
                Clear-Host
                Show-Banner
                Show-SessionHostStatus -Config $config
                Wait-ForKeyPress
            }

            '5' {
                Clear-Host
                Show-Banner
                Show-DiskSpaceAnalysis -Config $config
                Wait-ForKeyPress
            }

            '6' {
                Clear-Host
                Show-Banner
                Show-Settings -Config $config
                # Reload config from disk in case it was saved
                $config = Import-Config
                Wait-ForKeyPress
            }

            '7' {
                Clear-Host
                Show-Banner
                Show-Help
                Wait-ForKeyPress
            }

            { $_ -eq 'Q' -or $_ -eq 'QUIT' -or $_ -eq 'EXIT' } {
                Write-Host ''
                Write-StatusLine INFO 'Goodbye.'
                Write-Host ''
                return
            }

            '' {
                # Empty input (Enter pressed) -- re-draw menu silently
            }

            default {
                Write-Host ''
                Write-StatusLine WARN "Invalid selection: '$choice'. Choose 1-7 or Q."
                Start-Sleep -Seconds 1
            }
        }
    }
}

# ============================================================
# ENTRY POINT
# ============================================================
Start-TuiMenu
