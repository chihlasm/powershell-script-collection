#Requires -Version 3.0
<#
.SYNOPSIS
    Archives or deletes FSLogix profile container folders, after safety checks on each one.

.DESCRIPTION
    Takes a list of FSLogix profile folders (the SID_username or username_SID folders under
    the profile share root), checks each one, and then reports, archives (moves), or deletes it.

    Every folder must pass every check, or it is SKIPPED and left untouched:
      - It is a single folder directly under -ProfileShare (no nested or "..\" paths).
      - Its name contains a domain account SID (S-1-5-21-...).
      - No VHD/VHDX file in it is open. A container that is attached to a session is held
        open, so an exclusive open attempt fails and the folder is skipped.
      - Optional (-MinDaysInactive): nothing in the folder was written within that many days.
      - AD check (on unless -SkipADCheck): the SID belongs to this domain and its account is
        not enabled. An account that no longer exists in AD is OK to remove.

    -Mode Report (the default) changes nothing. Archive and Delete prompt for each folder
    unless -Force is given, and support -WhatIf. Archive and Delete refuse to run if the AD
    check cannot be performed, unless -SkipADCheck is given.

    Every run writes a CSV log of each folder's result to -OutputPath.

.PARAMETER ProfileShare
    The FSLogix share root that holds the profile folders, as a UNC path or mapped drive,
    e.g. \\fileserver\profiles or Z:\

.PARAMETER TargetCsv
    CSV file with a FolderName column. Each value is a folder name under -ProfileShare, or a
    full path to one.

.PARAMETER FolderName
    One or more folder names (or full paths) to process instead of a CSV.

.PARAMETER Mode
    Report  = check only, change nothing (default)
    Archive = move eligible folders to -ArchivePath (recommended first pass)
    Delete  = permanently delete eligible folders

.PARAMETER ArchivePath
    Destination for Archive mode. Default: <ProfileShare>\_Archive_<yyyy-MM-dd>. Keep it on
    the same share so the move is an instant rename instead of a full copy.

.PARAMETER MinDaysInactive
    Skip any folder with a file written within this many days. 0 (default) turns the check off.

.PARAMETER SkipADCheck
    Do not look up the account in Active Directory. Use only when the accounts are known to
    be gone, or when the profiles belong to a domain this machine cannot query.

.PARAMETER Server
    Domain controller (or domain name) to use for the AD check. Defaults to this computer's domain.

.PARAMETER OutputPath
    Folder for the CSV log. Default: the current directory.

.PARAMETER Force
    Do not prompt before each move or delete. The safety checks still apply.

.PARAMETER LoadFunctionsOnly
    Define the functions and return without doing anything (used by the Pester tests).

.EXAMPLE
    .\Remove-FSLogixProfiles.ps1 -ProfileShare \\fileserver\profiles -TargetCsv .\RemovalTargets.csv

    Report only: shows which folders would be removed and why others would be skipped.

.EXAMPLE
    .\Remove-FSLogixProfiles.ps1 -ProfileShare Z:\ -FolderName 'S-1-5-21-1111111111-2222222222-3333333333-1105_jsmith' -Mode Archive

    Moves one user's profile folder to Z:\_Archive_<today>, after confirming.

.EXAMPLE
    .\Remove-FSLogixProfiles.ps1 -ProfileShare Z:\ -TargetCsv .\RemovalTargets.csv -Mode Delete -WhatIf

    Shows what Delete mode would remove, without removing anything.

.EXAMPLE
    .\Remove-FSLogixProfiles.ps1 -ProfileShare Z:\ -TargetCsv .\RemovalTargets.csv -Mode Delete -Force

    Permanently deletes every eligible folder without prompting.

.NOTES
    Changes anything? Yes, in Archive and Delete modes. Report mode is read-only.
    Requires: read/write/delete rights on the profile share. ActiveDirectory module (RSAT)
    for the AD check.

    REFERENCES
    - FSLogix folder naming (%sid%_%username% by default; FlipFlopProfileDirectoryName gives
      %username%_%sid%; SIDDirNamePattern customises it):
      https://learn.microsoft.com/fslogix/reference-configuration-settings
    - Domain account SID = domain SID + RID (S-1-5-21-<3 sub-authorities>-<RID>):
      https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
    - Get-ADUser -Identity accepts a SID (objectSid):
      https://learn.microsoft.com/powershell/module/activedirectory/get-aduser
    - Get-ADDomain returns DomainSID:
      https://learn.microsoft.com/powershell/module/activedirectory/get-addomain
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Csv')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Folder')]
    [string]$ProfileShare,

    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$TargetCsv,

    [Parameter(Mandatory = $true, ParameterSetName = 'Folder')]
    [string[]]$FolderName,

    [ValidateSet('Report', 'Archive', 'Delete')]
    [string]$Mode = 'Report',

    [string]$ArchivePath,

    [ValidateRange(0, 3650)]
    [int]$MinDaysInactive = 0,

    [switch]$SkipADCheck,

    [string]$Server,

    [string]$OutputPath = (Get-Location).ProviderPath,

    [switch]$Force,

    [Parameter(Mandatory = $true, ParameterSetName = 'LoadFunctionsOnly')]
    [switch]$LoadFunctionsOnly
)

function Write-Status {
    param(
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Level,
        [string]$Message
    )
    $colour = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $colour
}

function Resolve-ProfileFolderName {
    <#
        Turns a CSV/parameter value into a folder name directly under $Root and the account
        SID it contains. Throws (so the caller skips the folder) on anything else.
    #>
    param([string]$Value, [string]$Root)

    $name = "$Value".Trim().TrimEnd('\', '/')
    if (-not $name) { throw 'FolderName is empty' }

    # A full path is accepted only when its parent is the share root itself.
    if ($name -match '[\\/]') {
        $parent = (Split-Path -Path $name -Parent).TrimEnd('\', '/')
        if ($parent -ne $Root.TrimEnd('\', '/')) {
            throw 'FolderName must be a single folder directly under the share root'
        }
        $name = Split-Path -Path $name -Leaf
    }
    if ($name -match '\.\.' -or $name -match '[\\/:]') {
        throw 'FolderName must be a single folder directly under the share root'
    }

    # FSLogix names the folder %sid%_%username% (or %username%_%sid% with
    # FlipFlopProfileDirectoryName). A domain account SID is S-1-5-21 + three domain
    # sub-authorities + the RID.
    # https://learn.microsoft.com/fslogix/reference-configuration-settings
    # https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
    if ($name -notmatch '(S-1-5-21-\d+-\d+-\d+-\d+)') { throw 'Folder name does not contain a domain account SID' }

    [pscustomobject]@{ Name = $name; Sid = $Matches[1] }
}

function Test-FileLocked {
    <#
        Returns $null when the file can be opened exclusively, otherwise the reason it
        cannot. Any failure counts as "in use": the caller must never delete on doubt.
    #>
    param([string]$Path)
    try {
        $fs = [System.IO.File]::Open($Path, 'Open', 'ReadWrite', 'None')
        $fs.Close()
        return $null
    }
    catch [System.UnauthorizedAccessException] {
        return 'access denied when opening it'
    }
    catch {
        return 'open by another process or computer'
    }
}

function Get-ADAccountState {
    <#
        Returns State (text for the log) and Block (true = do not remove this folder).
        Lookup errors other than "not found" are thrown so the folder is skipped.
    #>
    param([string]$Sid, [string]$DomainSid, [string]$Server)

    # A SID from another domain would always come back "not in AD" and look safe to remove.
    $sidDomain = $Sid -replace '-\d+$', ''
    if ($DomainSid -and $sidDomain -ne $DomainSid) {
        return [pscustomobject]@{ State = 'OtherDomain'; Block = $true
            Reason = "SID is from another domain ($sidDomain); run with -Server for that domain or -SkipADCheck" }
    }

    $params = @{ Identity = $Sid; ErrorAction = 'Stop' }
    if ($Server) { $params.Server = $Server }
    try {
        # -Identity accepts a SID (objectSid).
        # https://learn.microsoft.com/powershell/module/activedirectory/get-aduser
        $user = Get-ADUser @params
    }
    catch {
        if ($_.Exception.GetType().Name -eq 'ADIdentityNotFoundException') {
            return [pscustomobject]@{ State = 'NotInAD'; Block = $false; Reason = '' }
        }
        throw
    }

    if ($user.Enabled) {
        return [pscustomobject]@{ State = "Enabled ($($user.SamAccountName))"; Block = $true
            Reason = "AD account is still enabled: $($user.SamAccountName)" }
    }
    [pscustomobject]@{ State = "Disabled ($($user.SamAccountName))"; Block = $false; Reason = '' }
}

if ($LoadFunctionsOnly) { return }

$ErrorActionPreference = 'Stop'
if ($Force -and -not $PSBoundParameters.ContainsKey('Confirm')) { $ConfirmPreference = 'None' }

$root = (Resolve-Path -LiteralPath $ProfileShare).ProviderPath.TrimEnd('\')
if (-not $ArchivePath) { $ArchivePath = Join-Path $root ('_Archive_{0}' -f (Get-Date -Format 'yyyy-MM-dd')) }
if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
    New-Item -ItemType Directory -Path $OutputPath -WhatIf:$false -Confirm:$false | Out-Null
}
$logPath = Join-Path $OutputPath ('FSLogixRemoval_{0}_{1}.csv' -f $Mode, (Get-Date -Format 'yyyy-MM-dd_HHmmss'))

Write-Status INFO "Profile share: $root"
Write-Status INFO "Mode: $Mode"

# --- AD check setup -----------------------------------------------------------------
$domainSid = $null
$useAD = $false
if ($SkipADCheck) {
    Write-Status WARN 'AD check skipped (-SkipADCheck): enabled accounts will NOT be protected.'
}
else {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $domainParams = @{ ErrorAction = 'Stop' }
        if ($Server) { $domainParams.Server = $Server }
        # https://learn.microsoft.com/powershell/module/activedirectory/get-addomain
        $domainSid = [string](Get-ADDomain @domainParams).DomainSID
        $useAD = $true
        Write-Status INFO "AD check on (domain SID $domainSid)"
    }
    catch {
        $why = $_.Exception.Message
        if ($Mode -eq 'Report') {
            Write-Status WARN "AD check unavailable: $why. The report continues without it; Archive and Delete will not run until AD is reachable or -SkipADCheck is used."
        }
        else {
            Write-Status FAIL "AD check unavailable: $why"
            throw "Stopped before changing anything: the AD check could not run. Fix AD access (or use -Server), or rerun with -SkipADCheck if the accounts are known to be gone."
        }
    }
}

# --- Targets ------------------------------------------------------------------------
if ($PSCmdlet.ParameterSetName -eq 'Folder') {
    $targets = @($FolderName | ForEach-Object { [pscustomobject]@{ FolderName = $_ } })
}
else {
    $targets = @(Import-Csv -LiteralPath $TargetCsv)
    if ($targets.Count -eq 0) { throw "TargetCsv has no rows: $TargetCsv" }
    if (-not ($targets[0].PSObject.Properties.Name -contains 'FolderName')) { throw 'TargetCsv must contain a FolderName column.' }
}
Write-Status INFO "$($targets.Count) folder(s) to check"

if ($Mode -eq 'Archive' -and -not (Test-Path -LiteralPath $ArchivePath)) {
    if ($PSCmdlet.ShouldProcess($ArchivePath, 'Create archive folder')) {
        New-Item -ItemType Directory -Path $ArchivePath | Out-Null
    }
}

# --- Process ------------------------------------------------------------------------
$results = foreach ($t in $targets) {
    $name = "$($t.FolderName)"
    $status = 'Pending'; $reason = ''; $sizeGB = $null; $newest = $null; $adState = 'n/a'
    $acting = $false

    try {
        $target = Resolve-ProfileFolderName -Value $t.FolderName -Root $root
        $name = $target.Name
        $path = Join-Path $root $name
        if (-not (Test-Path -LiteralPath $path -PathType Container)) { $status = 'NotFound'; throw 'Folder not found' }

        $files  = @(Get-ChildItem -LiteralPath $path -Recurse -File -Force)
        $sizeGB = [math]::Round(((($files | Measure-Object -Property Length -Sum).Sum) / 1GB), 2)
        $newest = ($files | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime

        $locked = foreach ($f in ($files | Where-Object { $_.Extension -eq '.vhd' -or $_.Extension -eq '.vhdx' })) {
            $why = Test-FileLocked -Path $f.FullName
            if ($why) { "$($f.Name) ($why)" }
        }
        if ($locked) { throw "Container in use: $(@($locked) -join ', ')" }

        if ($MinDaysInactive -gt 0 -and $newest -and $newest -gt (Get-Date).AddDays(-$MinDaysInactive)) {
            throw "Written within the last $MinDaysInactive days ($newest)"
        }

        if ($useAD) {
            $ad = Get-ADAccountState -Sid $target.Sid -DomainSid $domainSid -Server $Server
            $adState = $ad.State
            if ($ad.Block) { throw $ad.Reason }
        }

        switch ($Mode) {
            'Report' { $status = 'Eligible' }
            'Archive' {
                $dest = Join-Path $ArchivePath $name
                if (Test-Path -LiteralPath $dest) { throw "Archive destination already exists: $dest" }
                if ($PSCmdlet.ShouldProcess($path, "Move to $ArchivePath")) {
                    $acting = $true
                    Move-Item -LiteralPath $path -Destination $dest
                    $status = 'Archived'
                }
                else { $status = 'WhatIf' }
            }
            'Delete' {
                if ($PSCmdlet.ShouldProcess($path, 'Permanently delete')) {
                    $acting = $true
                    Remove-Item -LiteralPath $path -Recurse -Force
                    $status = 'Deleted'
                }
                else { $status = 'WhatIf' }
            }
        }
    }
    catch {
        # Failed = the move/delete itself errored, so the folder may be partly gone.
        if ($acting) { $status = 'Failed' }
        elseif ($status -eq 'Pending') { $status = 'Skipped' }
        $reason = $_.Exception.Message
    }

    $line = "{0}: {1}" -f $name, $status
    if ($reason) { $line += " - $reason" }
    switch ($status) {
        { $_ -in 'Eligible', 'Archived', 'Deleted' } { Write-Status PASS $line }
        'WhatIf' { Write-Status INFO $line }
        'Failed' { Write-Status FAIL "$line (check the folder by hand: it may be partly moved or deleted)" }
        default  { Write-Status WARN $line }
    }

    [pscustomobject]@{
        FolderName  = $name
        Status      = $status
        Reason      = $reason
        SizeGB      = $sizeGB
        NewestWrite = $newest
        ADAccount   = $adState
        Mode        = $Mode
        Timestamp   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    }
}

# -WhatIf must not suppress the log: it is the record of what would have happened.
$results | Export-Csv -LiteralPath $logPath -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false

Write-Host ''
$results | Group-Object Status | ForEach-Object {
    Write-Status INFO ('{0,-9} {1,4} folder(s) {2,9:N2} GB' -f $_.Name, $_.Count, (($_.Group | Measure-Object -Property SizeGB -Sum).Sum))
}
if ($Mode -eq 'Report' -and @($results | Where-Object { $_.Status -eq 'Eligible' }).Count -gt 0) {
    Write-Status INFO 'Next step: rerun with -Mode Archive to move the eligible folders aside (reversible).'
}
Write-Status INFO "Log: $logPath"
