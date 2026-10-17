#Requires -Version 3.0

<#
.SYNOPSIS
    Takes ownership of a folder tree, shows its permissions, and copies the top folder's
    permissions to every subfolder. Every change is backed up and logged first.

.DESCRIPTION
    The command-line companion of FolderPermissionManager-GUI.ps1, for servers without a
    browser. In order, after asking each time:

    1. Takes ownership of the folder and all its subfolders and files for the account running
       the script (takeown /R /A, then icacls /setowner /T). The current owner of every item
       is saved to <LogFolder>\Backups\<yyyy-MM-dd_HHmmss>_TakeOwnership.csv first; if that
       file cannot be written, nothing is changed.
    2. Shows the top folder's owner and permissions, and the owner of each subfolder.
    3. Copies the top folder's permissions to every subfolder: entries a subfolder does not
       already have are added, nothing is removed. The permissions of every subfolder are
       saved to <LogFolder>\Backups\<yyyy-MM-dd_HHmmss>_CopyPermissions.csv first.

    Before each change it prints the scope with [WARN] (for ownership, the number of items,
    counted read-only first) and asks "Continue? (y/N)". The copy step does not depend on
    ownership, so it is still offered when ownership was declined or failed.

    Every change is written to <LogFolder>\Changes_<yyyy-MM-dd>.csv, the same log the GUI
    writes. See "Undo a change" in README.md to put permissions or owners back.

    Exit code: 1 when a change Failed or was only Partly done, or the folder or log folder
    could not be used; 0 otherwise (done, -WhatIf, or declined).

    CHANGES ANYTHING? Yes: owners and permissions. Use -WhatIf first.

.PARAMETER Path
    The top folder. If not given, the script asks for it. A relative path ('.\HR') is made a
    full path once, and that path is used for everything.

.PARAMETER LogFolder
    Folder for the backups and the change log. Defaults to the Logs folder next to this script
    (not the current directory, which is C:\Windows\System32 when started "as administrator").
    If the script is on a network share or any drive that is not a local fixed disk, or that
    folder is read-only, %LOCALAPPDATA%\FolderPermissionManager\Logs is used instead. A folder
    passed here is used as given (with a warning if it is on the network).

.PARAMETER Force
    Do not ask before taking ownership or copying permissions.

.PARAMETER LoadFunctionsOnly
    Define the functions and return without doing anything (used by the tests).

.EXAMPLE
    .\FolderPermissionManager.ps1 -Path 'D:\Shares\HR' -WhatIf

    Shows what would be changed. Nothing is changed, backed up or logged.

.EXAMPLE
    .\FolderPermissionManager.ps1 -Path 'D:\Shares\HR'

    Asks before taking ownership and again before copying permissions to the subfolders.

.EXAMPLE
    .\FolderPermissionManager.ps1 -Path 'D:\Shares\HR' -Force -LogFolder 'C:\Tickets\12345'

    Takes ownership and copies permissions without asking; backups and the log go to
    C:\Tickets\12345.

.NOTES
    Run in an elevated PowerShell window (checked at start; -WhatIf also runs without it).
    PowerShell 3.0 or later (Windows Server 2012 and later). FolderPermissions.Core.ps1 must be
    in the same folder: it holds the backup, logging and change logic shared with the GUI.

    Not #Requires -RunAsAdministrator: that needs PowerShell 4.0 and stops the script from
    loading at all in a normal window, so elevation is checked at run time instead.

    REFERENCES
    - See FolderPermissions.Core.ps1 for takeown /R /A /D, icacls /setowner /T /C /Q,
      Get-Acl, Set-Acl and GetOwner.
    - #Requires and its PowerShell versions:
      https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_requires
    - WindowsPrincipal.IsInRole(WindowsBuiltInRole.Administrator) is true only in an elevated
      session when UAC is on:
      https://learn.microsoft.com/dotnet/api/system.security.principal.windowsprincipal.isinrole
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$Path,

    [Parameter()]
    [string]$LogFolder,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$LoadFunctionsOnly
)

# Dot-sourcing the core defines its own $LoadFunctionsOnly in this scope, so read ours first.
$loadOnly = $LoadFunctionsOnly.IsPresent
$corePath = Join-Path $PSScriptRoot 'FolderPermissions.Core.ps1'
if (-not (Test-Path -LiteralPath $corePath)) {
    Write-Host "[FAIL] FolderPermissions.Core.ps1 is missing from $PSScriptRoot. Keep all the files in the folder together." -ForegroundColor Red
    exit 1
}
. $corePath -LoadFunctionsOnly

function Write-CliChangeResult {
    <#
    .SYNOPSIS
        Prints the plain-English result of one change with [PASS], [WARN], [FAIL] or [INFO], and
        returns $true when it needs the technician's attention (a row is Failed or Partly done).
    .DESCRIPTION
        [PASS] only when every row is Done, was logged, can be restored from its backup, and
        (for a whole folder) every folder could be opened and every owner read back.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries,
        [AllowNull()][string]$LogPath,
        [Parameter(Mandatory)][string]$LogFolder
    )

    $all = @($Entries | Where-Object { $null -ne $_ })
    $message = Get-ChangeResultMessage -Entries $all -LogPath $LogPath -LogFolder $LogFolder
    $results = @($all | ForEach-Object { $_.Result })
    $notDone = @($results | Where-Object { $_ -ne 'Done' })
    $incomplete = @($all | Where-Object { Test-TreeEntryIncomplete $_ })
    if ($all.Count -gt 0 -and @($results | Where-Object { $_ -ne 'Skipped (WhatIf)' }).Count -eq 0) {
        Write-Host "[INFO] $message" -ForegroundColor Cyan
    } elseif ($all.Count -gt 0 -and $notDone.Count -eq 0 -and $incomplete.Count -eq 0 -and $LogPath -and (Get-UnrestorableItemCount -Entries $all) -eq 0) {
        Write-Host "[PASS] $message" -ForegroundColor Green
    } elseif (@($results | Where-Object { $_ -eq 'Done' -or $_ -eq 'Partly done' }).Count -gt 0) {
        Write-Host "[WARN] $message" -ForegroundColor Yellow
    } else {
        Write-Host "[FAIL] $message" -ForegroundColor Red
    }
    @($results | Where-Object { $_ -eq 'Failed' -or $_ -eq 'Partly done' }).Count -gt 0
}

function Confirm-CliStep {
    # True when the technician types y or Y. Anything else, including Enter, is no (the
    # capital N says so).
    param([string]$Question = 'Continue?')
    $answer = Read-Host "$Question (y/N)"
    $answer -eq 'y' -or $answer -eq 'Y'
}

function Invoke-FolderPermissionCli {
    <#
    .SYNOPSIS
        The script's work: take ownership, show permissions, copy them to the subfolders. Each
        change shows its scope with [WARN], asks first (unless -Force), goes through the core
        (backup, then change, then change log) and prints its result. Never throws for a
        declined prompt.
    .OUTPUTS
        The exit code for the script: 1 when the folder could not be used or a change Failed or
        was only Partly done; 0 otherwise (done, -WhatIf, or declined).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([int])]
    param(
        [string]$Path,
        [string]$LogFolder,
        [switch]$Force
    )

    $whatIf = [bool]$WhatIfPreference
    $exitCode = 0

    if (-not $Path) {
        $Path = Read-Host 'Enter the path to the top-level folder'
    }
    # One full path for everything below: the snapshot, takeown, icacls and the log.
    $Path = Resolve-AclTargetPath -Path "$Path".Trim()
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Container)) {
        Write-Host "[FAIL] The folder '$Path' does not exist or is not a folder. Nothing was changed." -ForegroundColor Red
        return 1
    }

    $defaultLogFolder = Join-Path $PSScriptRoot 'Logs'
    if ($whatIf) {
        # A dry run writes nothing, so the log folder is not created or tested.
        $logFolderUsed = if ($LogFolder) { $LogFolder } else { $defaultLogFolder }
    } else {
        try {
            $logFolderUsed = Resolve-ChangeLogFolder -LogFolder $LogFolder -DefaultFolder $defaultLogFolder
        } catch {
            Write-Host "[FAIL] $($_.Exception.Message)" -ForegroundColor Red
            return 1
        }
        foreach ($notice in @(Get-ChangeLogFolderNotice -LogFolder $LogFolder -ResolvedFolder $logFolderUsed -DefaultFolder $defaultLogFolder)) {
            Write-Host "[WARN] $notice" -ForegroundColor Yellow
        }
        Write-Host "[INFO] Changes are backed up and logged to $logFolderUsed" -ForegroundColor Cyan
    }

    # 1. Take ownership of everything under the folder. The tree is counted first (read only)
    # so the scope is shown before asking; the core lists it again for the snapshot.
    Write-Host "[INFO] Counting the folders and files in $Path..." -ForegroundColor Cyan
    $tree = Get-OwnerTreeItem -Path $Path
    $scope = "$(@($tree.Items).Count) item(s): $Path and every subfolder and file under it"
    if (@($tree.Unlisted).Count -gt 0) {
        $scope += ", plus whatever is inside $(@($tree.Unlisted).Count) folder(s) that could not be opened (their owners cannot be saved first)"
    }
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Host "[WARN] Taking ownership makes $me the owner of $scope. The current owners are saved to a backup first." -ForegroundColor Yellow
    $takeOwnership = $whatIf -or $Force -or (Confirm-CliStep)
    $ownershipTaken = $false
    if ($takeOwnership) {
        if ($whatIf) {
            $rows = @(Set-ItemOwnerToCurrentUser -Path $Path -Recurse -LogFolder $logFolderUsed -WhatIf)
            $null = Write-CliChangeResult -Entries $rows -LogFolder $logFolderUsed
            $ownershipTaken = $true
        } else {
            Write-Host "[INFO] Saving the current owners and taking ownership. This can take a while on a large folder..." -ForegroundColor Cyan
            $result = Invoke-LoggedPermissionChange -LogFolder $logFolderUsed -Change {
                Set-ItemOwnerToCurrentUser -Path $Path -Recurse -LogFolder $logFolderUsed -WhatIf:$false
            }
            if (Write-CliChangeResult -Entries $result.Entries -LogPath $result.LogPath -LogFolder $logFolderUsed) { $exitCode = 1 }
            $ownershipTaken = @($result.Entries | Where-Object { $_.Result -eq 'Done' -or $_.Result -eq 'Partly done' }).Count -gt 0
        }
    } else {
        Write-Host '[INFO] Ownership was not changed.' -ForegroundColor Cyan
    }
    if (-not $ownershipTaken) {
        Write-Host '[INFO] Copying permissions (next) does not depend on taking ownership: it is offered on its own, and any subfolder you cannot change is reported as failed.' -ForegroundColor Cyan
    }

    # 2. Show the permissions.
    try {
        $topAcl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    } catch {
        Write-Host "[FAIL] Could not read the permissions of $($Path): $($_.Exception.Message) Permissions were not copied." -ForegroundColor Red
        return 1
    }
    Write-Host ''
    Write-Host "Permissions on the top-level folder ($Path):"
    Write-Host "Owner: $($topAcl.Owner)"
    Write-Host 'Access rules:'
    $topAcl.Access | Format-Table IdentityReference, FileSystemRights, AccessControlType, IsInherited, InheritanceFlags -AutoSize | Out-Host

    $subFolders = @(Get-ChildItem -LiteralPath $Path -Recurse -Directory -Force -ErrorAction SilentlyContinue)
    Write-Host "Subfolders and their owners ($($subFolders.Count)):"
    foreach ($folder in $subFolders) {
        try {
            $folderAcl = Get-Acl -LiteralPath $folder.FullName -ErrorAction Stop
            Write-Host "  $($folder.FullName) - Owner: $($folderAcl.Owner)"
        } catch {
            Write-Host "[WARN] Cannot read $($folder.FullName): $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    if ($subFolders.Count -eq 0) {
        Write-Host '[INFO] There are no subfolders to copy the permissions to.' -ForegroundColor Cyan
        return $exitCode
    }

    # 3. Copy the top folder's permissions to every subfolder.
    Write-Host ''
    Write-Host "[WARN] Copying adds the permissions of $Path to $($subFolders.Count) subfolder(s). Their current permissions are saved to a backup first. Nothing is removed." -ForegroundColor Yellow
    $copy = $whatIf -or $Force -or (Confirm-CliStep)
    if (-not $copy) {
        Write-Host '[INFO] Permissions were not copied.' -ForegroundColor Cyan
        return $exitCode
    }
    $targets = @($subFolders | ForEach-Object { $_.FullName })
    if ($whatIf) {
        $rows = @(Copy-FolderPermission -SourcePath $Path -TargetPath $targets -LogFolder $logFolderUsed -WhatIf)
        $null = Write-CliChangeResult -Entries $rows -LogFolder $logFolderUsed
    } else {
        $result = Invoke-LoggedPermissionChange -LogFolder $logFolderUsed -Change {
            Copy-FolderPermission -SourcePath $Path -TargetPath $targets -LogFolder $logFolderUsed -WhatIf:$false
        }
        if (Write-CliChangeResult -Entries $result.Entries -LogPath $result.LogPath -LogFolder $logFolderUsed) { $exitCode = 1 }
    }
    $exitCode
}

if ($loadOnly) { return }

$isAdmin = (New-Object Security.Principal.WindowsPrincipal -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $WhatIfPreference) {
    Write-Host '[FAIL] Run this script in an elevated PowerShell window (right-click PowerShell, "Run as administrator"). Taking ownership and changing permissions need administrator rights. Nothing was changed.' -ForegroundColor Red
    exit 1
}

exit (Invoke-FolderPermissionCli -Path $Path -LogFolder $LogFolder -Force:$Force)
