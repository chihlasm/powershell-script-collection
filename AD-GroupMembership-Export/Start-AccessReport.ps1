<#
.SYNOPSIS
    Guided, menu-driven front end for Export-ADGroupMembership.ps1.

.DESCRIPTION
    Wraps the access-review export in a plain-English flow for someone who should not have
    to know what -IncludeNested or -ExcludeBuiltin mean. Checks the prerequisites, asks a
    small number of questions, runs the export with sensible defaults, confirms the files
    actually contain data, and packages them into a single zip for sending.

    Design notes, since these shape most of the code below:

    1. EVERY FAILURE ENDS WITH A PLAIN-ENGLISH NEXT STEP AND A PAUSE.
       A console window that closes on an error takes the error with it, which is the most
       common way a tool like this fails a non-technical user. Nothing here exits without
       being read first.

    2. OUTPUT NEVER DEFAULTS TO A CLOUD-SYNCED FOLDER.
       Files written into OneDrive (or Dropbox, Box, Google Drive) can become placeholders:
       the file exists but its content lives in the cloud. Copying a placeholder copies an
       empty file, so a report handed off that way arrives blank. C:\ADReports is used
       instead, and a synced destination is refused.

    3. THE ZIP IS THE HANDOFF FORMAT.
       A zip cannot be a half-synced placeholder - it either transfers whole or fails
       loudly - which removes the failure mode above from the handoff entirely.

.PARAMETER OutputRoot
    Where report folders are created. Defaults to C:\ADReports. Overridable for testing;
    the menu never asks, because choosing a path is exactly what this front end exists to
    avoid.

.PARAMETER SkipPrerequisiteCheck
    Skip the AD module and domain connectivity checks. For testing the menu flow on a
    machine that is not domain-joined.

.EXAMPLE
    .\Start-AccessReport.ps1
    Normal use. Launched by double-clicking Run-AccessReport.bat.

.NOTES
    Author  : VC3 Scripts Collection
    Requires: PowerShell 5.1, ActiveDirectory RSAT module, read access to the directory.
              Administrator rights are NOT required.

    This is a front end only. All directory work is done by Export-ADGroupMembership.ps1
    in the same folder; see its help for the full parameter set.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputRoot = 'C:\ADReports',

    [Parameter(Mandatory = $false)]
    [switch]$SkipPrerequisiteCheck
)

$ErrorActionPreference = 'Stop'

#region Console helpers

$script:ExportScript = Join-Path $PSScriptRoot 'Export-ADGroupMembership.ps1'

function Write-Banner {
    param([string]$Subtitle)
    Clear-Host
    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor Cyan
    Write-Host '    ACTIVE DIRECTORY ACCESS REPORT' -ForegroundColor Cyan
    Write-Host '  ============================================================' -ForegroundColor Cyan
    if ($Subtitle) {
        Write-Host "    $Subtitle" -ForegroundColor DarkGray
    }
    Write-Host ''
}

function Write-Step {
    param([string]$Message, [ValidateSet('PASS','WARN','FAIL','INFO')][string]$Level = 'INFO')
    $color = switch ($Level) { 'PASS' {'Green'} 'WARN' {'Yellow'} 'FAIL' {'Red'} default {'Gray'} }
    $mark  = switch ($Level) { 'PASS' {'  [OK]   '} 'WARN' {'  [!]    '} 'FAIL' {'  [X]    '} default {'         '} }
    Write-Host "$mark$Message" -ForegroundColor $color
}

function Stop-WithMessage {
    <#
        The only exit path for an unrecoverable problem. Always states what to do next in
        words the person running this can act on or forward to IT, and always waits.
    #>
    param(
        [Parameter(Mandatory)][string]$Problem,
        [Parameter(Mandatory)][string[]]$WhatToDo,
        [int]$ExitCode = 1
    )
    Write-Host ''
    Write-Host '  ------------------------------------------------------------' -ForegroundColor Red
    Write-Host '   THIS REPORT COULD NOT RUN' -ForegroundColor Red
    Write-Host '  ------------------------------------------------------------' -ForegroundColor Red
    Write-Host ''
    Write-Host "   $Problem" -ForegroundColor White
    Write-Host ''
    Write-Host '   What to do next:' -ForegroundColor Yellow
    foreach ($line in $WhatToDo) { Write-Host "     - $line" -ForegroundColor Yellow }
    Write-Host ''
    Read-Host '   Press Enter to close'
    exit $ExitCode
}

function Read-MenuChoice {
    <#
        Prompts until the answer is one of $Valid. Bad input re-prompts rather than
        crashing or falling through to a default, so a typo cannot silently run the wrong
        report.
    #>
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][string[]]$Valid
    )
    while ($true) {
        Write-Host ''
        $answer = (Read-Host "  $Prompt").Trim()
        if ($Valid -contains $answer.ToUpperInvariant()) { return $answer.ToUpperInvariant() }
        if ($Valid -contains $answer) { return $answer }
        Write-Host "  Please enter one of: $($Valid -join ', ')" -ForegroundColor Yellow
    }
}

function Confirm-YesNo {
    param([Parameter(Mandatory)][string]$Question, [bool]$DefaultYes = $true)
    $suffix = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $a = (Read-Host "  $Question $suffix").Trim().ToUpperInvariant()
        if ($a -eq '')  { return $DefaultYes }
        if ($a -in @('Y','YES')) { return $true }
        if ($a -in @('N','NO'))  { return $false }
        Write-Host '  Please answer Y or N.' -ForegroundColor Yellow
    }
}

#endregion

#region Prerequisite checks

function Test-Prerequisite {
    <#
        Checks everything needed before a single question is asked, so the person is not
        walked through a menu only to hit a wall at the end. Each failure explains itself
        in terms someone can act on or forward verbatim to IT.
    #>

    Write-Banner 'Checking this computer is ready...'

    if (-not (Test-Path -LiteralPath $script:ExportScript)) {
        Stop-WithMessage -Problem 'The main report script (Export-ADGroupMembership.ps1) is missing from this folder.' -WhatToDo @(
            'Copy the ENTIRE report folder to this computer, not just some of the files.',
            "This folder is: $PSScriptRoot"
        )
    }
    Write-Step 'Report files found' 'PASS'

    try {
        if (-not (Get-Module -Name ActiveDirectory)) {
            Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
        }
        Write-Step 'Active Directory tools installed' 'PASS'
    }
    catch {
        Stop-WithMessage -Problem 'The Active Directory tools (RSAT) are not installed on this computer.' -WhatToDo @(
            'Ask your IT administrator to install the Remote Server Administration Tools.',
            'They can do this by running, as administrator:',
            '    Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0',
            'Alternatively, run this report from a domain controller or an admin workstation.'
        )
    }

    try {
        $domain = Get-ADDomain -ErrorAction Stop
        Write-Step "Connected to domain: $($domain.DNSRoot)" 'PASS'
        return $domain
    }
    catch {
        Stop-WithMessage -Problem 'This computer could not reach an Active Directory domain controller.' -WhatToDo @(
            'Check that this computer is connected to the company network (or VPN).',
            'Confirm you are signed in with a domain account, not a local one.',
            'If you are working remotely, connect to the VPN and try again.',
            "Technical detail for IT: $($_.Exception.Message)"
        )
    }
}

#endregion

#region Output location

function Get-ReportFolder {
    <#
        Produces a timestamped folder that is safe to hand off from.

        A cloud-synced destination is refused rather than warned about: this front end
        exists for someone who will not be able to tell a placeholder from a real file, and
        the failure is silent and total - a blank report with no error anywhere.
    #>
    param([Parameter(Mandatory)][string]$Root)

    # The folder name must be a whole path segment: '\OneDrive\' or a trailing '\OneDrive',
    # never a prefix. Without the closing boundary this also blocks innocent local folders
    # like C:\Boxing or C:\OneDriveBackupTool, dead-ending someone with no way forward.
    # OneDrive business paths carry a tenant suffix ('OneDrive - VC3, Inc'), so that form
    # is matched explicitly rather than by a loose prefix match.
    $syncPattern = '(?i)\\(OneDrive( - [^\\]+)?|Dropbox|Box|Google Drive|iCloudDrive)(\\|$)'

    if ($Root -match $syncPattern) {
        Stop-WithMessage -Problem "The chosen save location is inside a cloud-synced folder ($Root)." -WhatToDo @(
            'Reports must be saved to a normal local folder such as C:\ADReports.',
            'Files in synced folders can copy as empty, which produces a blank report.'
        )
    }

    $stamp  = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $folder = Join-Path $Root $stamp

    try {
        $null = New-Item -Path $folder -ItemType Directory -Force -ErrorAction Stop
    }
    catch {
        # C:\ is not always writable by a standard user; Documents nearly always is.
        $fallbackRoot = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'ADReports'
        if ($fallbackRoot -match $syncPattern) {
            Stop-WithMessage -Problem "Could not create a folder in $Root, and the Documents folder is cloud-synced so it cannot be used either." -WhatToDo @(
                'Ask IT for a local folder you can write to, then run this again.',
                "Technical detail for IT: $($_.Exception.Message)"
            )
        }
        $folder = Join-Path $fallbackRoot $stamp
        try {
            $null = New-Item -Path $folder -ItemType Directory -Force -ErrorAction Stop
            Write-Step "Could not write to $Root - using your Documents folder instead" 'WARN'
        }
        catch {
            Stop-WithMessage -Problem 'Could not create a folder to save the report in.' -WhatToDo @(
                'Ask IT whether you have permission to write to this computer.',
                "Technical detail for IT: $($_.Exception.Message)"
            )
        }
    }

    return $folder
}

#endregion

#region Menu

function Show-MainMenu {
    Write-Banner
    Write-Host '   What would you like to find out?' -ForegroundColor White
    Write-Host ''
    Write-Host '     [1] Who has access to what?' -ForegroundColor Green
    Write-Host '         Every person and the groups they belong to.' -ForegroundColor Gray
    Write-Host '         Best choice if you are not sure.' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '     [2] Who is in specific groups?' -ForegroundColor White
    Write-Host '         For example: Domain Admins, or all the HR groups.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '     [3] One department or area only' -ForegroundColor White
    Write-Host '         Pick from a list of the areas in your directory.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '     [Q] Quit without running anything' -ForegroundColor DarkGray
    Write-Host ''
    return Read-MenuChoice -Prompt 'Type 1, 2, 3 or Q and press Enter:' -Valid @('1','2','3','Q')
}

function Get-GroupSelection {
    <#
        Option 2 requires typed text - a group name cannot be picked from a list of
        thousands. Wildcards are explained by example rather than by naming them, and the
        input is checked against the directory before the run so a typo is caught in
        seconds rather than after a long export.
    #>
    Write-Banner 'Who is in specific groups?'
    Write-Host '   Type the group names you want to check, separated by commas.' -ForegroundColor White
    Write-Host ''
    Write-Host '   Examples:' -ForegroundColor Gray
    Write-Host '     Domain Admins' -ForegroundColor DarkGray
    Write-Host '     Domain Admins, Enterprise Admins' -ForegroundColor DarkGray
    Write-Host '     HR-*                 (every group whose name starts with HR-)' -ForegroundColor DarkGray
    Write-Host ''

    while ($true) {
        $raw = (Read-Host '  Group names').Trim()
        if (-not $raw) {
            Write-Host '  Please type at least one group name, or press Ctrl+C to start over.' -ForegroundColor Yellow
            continue
        }

        $names = @($raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

        Write-Host ''
        Write-Step 'Checking those names against the directory...' 'INFO'
        $matched = 0
        foreach ($n in $names) {
            try {
                $escaped = $n -replace "'", "''"
                $hits = @(Get-ADGroup -Filter "Name -like '$escaped' -or SamAccountName -like '$escaped'" -ErrorAction Stop)
                if ($hits.Count -gt 0) {
                    Write-Step "$n - found $($hits.Count) group(s)" 'PASS'
                    $matched += $hits.Count
                }
                else {
                    Write-Step "$n - no group found with that name" 'WARN'
                }
            }
            catch {
                Write-Step "$n - could not be checked: $($_.Exception.Message)" 'WARN'
            }
        }

        if ($matched -eq 0) {
            Write-Host ''
            Write-Host '  None of those names matched a group in your directory.' -ForegroundColor Yellow
            if (Confirm-YesNo -Question 'Try typing them again?' -DefaultYes $true) {
                Write-Banner 'Who is in specific groups?'
                continue
            }
            return $null
        }

        return $names
    }
}

function Get-OrganizationalUnitSelection {
    <#
        Option 3 presents OUs discovered from the directory as a numbered list, so nobody
        has to know what a distinguished name is. Only OUs that actually contain groups are
        offered - picking an empty one produces a confusing empty report.
    #>
    Write-Banner 'One department or area only'
    Write-Step 'Looking up the areas in your directory...' 'INFO'

    try {
        $ous = @(Get-ADOrganizationalUnit -Filter * -ErrorAction Stop |
                 Sort-Object { ($_.DistinguishedName -split ',').Count }, Name)
    }
    catch {
        Write-Step "Could not read the list of areas: $($_.Exception.Message)" 'FAIL'
        return $null
    }

    # An OU with no groups yields an empty report, which reads as a broken tool.
    $withGroups = New-Object System.Collections.Generic.List[object]
    foreach ($ou in $ous) {
        try {
            $count = @(Get-ADGroup -Filter * -SearchBase $ou.DistinguishedName -ErrorAction SilentlyContinue).Count
            if ($count -gt 0) {
                $withGroups.Add([PSCustomObject]@{ Name = $ou.Name; DN = $ou.DistinguishedName; Groups = $count })
            }
        }
        catch { continue }
    }

    if ($withGroups.Count -eq 0) {
        Write-Host ''
        Write-Step 'No areas with groups in them were found.' 'WARN'
        Write-Host '  Choose option 1 from the main menu instead - it covers everything.' -ForegroundColor Yellow
        Write-Host ''
        Read-Host '  Press Enter to go back'
        return $null
    }

    # A long list is unreadable in a console; cap it and point at option 1 instead.
    $display = @($withGroups | Select-Object -First 20)

    Write-Banner 'One department or area only'
    Write-Host '   Which area do you want to report on?' -ForegroundColor White
    Write-Host ''
    for ($i = 0; $i -lt $display.Count; $i++) {
        $n = $i + 1
        Write-Host ("     [{0,2}] {1}" -f $n, $display[$i].Name) -ForegroundColor White -NoNewline
        Write-Host ("  ({0} groups)" -f $display[$i].Groups) -ForegroundColor DarkGray
    }
    if ($withGroups.Count -gt $display.Count) {
        Write-Host ''
        Write-Host ("     ...and $($withGroups.Count - $display.Count) more not shown." ) -ForegroundColor DarkGray
        Write-Host '     If the area you want is missing, use option 1 for everything.' -ForegroundColor DarkGray
    }
    Write-Host ''
    Write-Host '     [B] Go back' -ForegroundColor DarkGray

    $valid = @(1..$display.Count | ForEach-Object { "$_" }) + @('B')
    $choice = Read-MenuChoice -Prompt "Type a number (1-$($display.Count)) or B and press Enter:" -Valid $valid

    if ($choice -eq 'B') { return $null }
    return $display[[int]$choice - 1]
}

#endregion

#region Run and package

function Invoke-Report {
    <#
        Calls the real export script. Splatting keeps the flags in one readable place; the
        three that make this an access review rather than a raw dump (-IncludeNested,
        -ExcludeBuiltin, -UserReport) are always on, because deciding about them is exactly
        what this front end removes.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$ScopeParams,
        [Parameter(Mandatory)][string]$Folder,
        [Parameter(Mandatory)][string]$Description
    )

    Write-Banner 'Running the report'
    Write-Host "   $Description" -ForegroundColor White
    Write-Host ''
    Write-Host '   This can take a few minutes on a large directory.' -ForegroundColor Gray
    Write-Host '   Lines will appear below as it works - that is normal.' -ForegroundColor Gray
    Write-Host '   Please do not close this window.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  ------------------------------------------------------------' -ForegroundColor DarkGray

    $params = @{
        IncludeNested  = $true
        ExcludeBuiltin = $true
        UserReport     = $true
        OutputPath     = $Folder
    } + $ScopeParams

    $started = Get-Date
    try {
        & $script:ExportScript @params
    }
    catch {
        Write-Host '  ------------------------------------------------------------' -ForegroundColor DarkGray
        Stop-WithMessage -Problem 'The report stopped before it finished.' -WhatToDo @(
            'Try running it again - a brief network interruption can cause this.',
            'If it keeps happening, send the message below to IT.',
            "Technical detail: $($_.Exception.Message)"
        )
    }
    Write-Host '  ------------------------------------------------------------' -ForegroundColor DarkGray

    return ((Get-Date) - $started)
}

function Complete-Report {
    <#
        Confirms real content landed, then packages it. The size check is the same one the
        export script performs internally; repeating it here means the person is told
        clearly, at the end, whether what they are about to send is real.
    #>
    param(
        [Parameter(Mandatory)][string]$Folder,
        [Parameter(Mandatory)][timespan]$Duration
    )

    $files = @(Get-ChildItem -Path $Folder -File -ErrorAction SilentlyContinue)

    if ($files.Count -eq 0) {
        Stop-WithMessage -Problem 'The report finished but produced no files.' -WhatToDo @(
            'Run it again and choose option 1 to cover the whole directory.',
            'If it happens again, send this to IT along with the folder path below.',
            "Folder: $Folder"
        )
    }

    $empty = @($files | Where-Object { $_.Length -eq 0 })
    $html  = $files | Where-Object { $_.Extension -eq '.html' } | Select-Object -First 1

    Write-Banner 'Report finished'
    Write-Host ("   Took {0:N0} minute(s), {1:N0} second(s)." -f $Duration.TotalMinutes, $Duration.Seconds) -ForegroundColor Gray
    Write-Host ''
    Write-Host '   Files created:' -ForegroundColor White
    Write-Host ''
    foreach ($f in $files) {
        $size = if ($f.Length -ge 1MB) { '{0,8:N1} MB' -f ($f.Length/1MB) }
                elseif ($f.Length -ge 1KB) { '{0,8:N1} KB' -f ($f.Length/1KB) }
                else { '{0,8} B ' -f $f.Length }
        if ($f.Length -eq 0) {
            Write-Host ("     [X] {0,-42}{1}" -f $f.Name, $size) -ForegroundColor Red
        } else {
            Write-Host ("     [OK] {0,-41}{1}" -f $f.Name, $size) -ForegroundColor Green
        }
    }
    Write-Host ''
    Write-Host "   Saved in: $Folder" -ForegroundColor Cyan
    Write-Host ''

    if ($empty.Count -gt 0) {
        Write-Host '   WARNING: some files are empty and should not be sent.' -ForegroundColor Red
        Write-Host '   Please run the report again, and tell IT if it happens twice.' -ForegroundColor Yellow
        Write-Host ''
        Read-Host '   Press Enter to close'
        return
    }

    # Zip is the handoff format: it cannot arrive as an un-synced placeholder.
    $zipPath = $null
    if (Confirm-YesNo -Question 'Package everything into one file for sending?' -DefaultYes $true) {
        $zipPath = Join-Path (Split-Path $Folder -Parent) ("ADAccessReport_" + (Split-Path $Folder -Leaf) + '.zip')
        try {
            if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
            Compress-Archive -Path (Join-Path $Folder '*') -DestinationPath $zipPath -ErrorAction Stop
            $zipSize = (Get-Item -LiteralPath $zipPath).Length
            if ($zipSize -eq 0) { throw 'The packaged file came out empty.' }
            Write-Host ''
            Write-Step ("Packaged: $zipPath ({0:N1} KB)" -f ($zipSize/1KB)) 'PASS'
        }
        catch {
            Write-Host ''
            Write-Step "Could not package the files: $($_.Exception.Message)" 'WARN'
            Write-Host '  You can still send the folder shown above instead.' -ForegroundColor Yellow
            $zipPath = $null
        }
    }

    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor Green
    Write-Host '    WHAT TO DO NEXT' -ForegroundColor Green
    Write-Host '  ============================================================' -ForegroundColor Green
    Write-Host ''
    if ($zipPath) {
        Write-Host '   Send this one file:' -ForegroundColor White
        Write-Host "     $zipPath" -ForegroundColor Cyan
    }
    else {
        Write-Host '   Send this folder:' -ForegroundColor White
        Write-Host "     $Folder" -ForegroundColor Cyan
    }
    Write-Host ''
    Write-Host '   To read the report yourself, open the .html file in any' -ForegroundColor White
    Write-Host '   web browser - it needs no special software.' -ForegroundColor White
    Write-Host ''

    if ($html -and (Confirm-YesNo -Question 'Open the report now?' -DefaultYes $true)) {
        try { Start-Process $html.FullName }
        catch { Write-Step "Could not open it automatically. Double-click: $($html.FullName)" 'WARN' }
    }

    Write-Host ''
    Read-Host '   Press Enter to close'
}

#endregion

#region Main

try {
    if (-not $SkipPrerequisiteCheck) {
        $null = Test-Prerequisite
        Start-Sleep -Milliseconds 700
    }

    $scope = $null
    $description = $null

    while ($null -eq $scope) {
        switch (Show-MainMenu) {
            '1' {
                $scope = @{}
                $description = 'Reporting on everyone and the groups they belong to.'
            }
            '2' {
                $names = Get-GroupSelection
                if ($names) {
                    $scope = @{ GroupName = $names }
                    $description = "Reporting on: $($names -join ', ')"
                }
            }
            '3' {
                $ou = Get-OrganizationalUnitSelection
                if ($ou) {
                    $scope = @{ SearchBase = $ou.DN }
                    $description = "Reporting on the $($ou.Name) area ($($ou.Groups) groups)."
                }
            }
            'Q' {
                Write-Host ''
                Write-Host '  Nothing was run. You can close this window.' -ForegroundColor Gray
                Write-Host ''
                exit 0
            }
        }
    }

    $folder   = Get-ReportFolder -Root $OutputRoot
    $duration = Invoke-Report -ScopeParams $scope -Folder $folder -Description $description
    Complete-Report -Folder $folder -Duration $duration
}
catch {
    # Last-resort net: an unexpected error must still be readable rather than flashing past.
    Stop-WithMessage -Problem 'Something unexpected went wrong.' -WhatToDo @(
        'Please try running the report again.',
        'If it keeps happening, send the message below to IT.',
        "Technical detail: $($_.Exception.Message)",
        "Where it happened: $($_.InvocationInfo.ScriptLineNumber)"
    )
}

#endregion
