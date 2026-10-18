#Requires -Version 3.0

<#
.SYNOPSIS
    Takes ownership of a folder tree, shows its permissions, and copies the top folder's
    permissions to every subfolder. Every change is backed up and logged first.

.DESCRIPTION
    The command-line companion of FolderPermissionManager-GUI.ps1, for servers without a
    browser. In order, after asking each time:

    1. Takes ownership of the folder and all its subfolders and files for the account running
       the script (takeown /R /A /D N, then icacls /setowner /T). The current owner of every
       item is saved to <LogFolder>\Backups\<yyyy-MM-dd_HHmmss>_TakeOwnership.csv first; if
       that file cannot be written, nothing is changed. A folder that cannot be opened is
       skipped and its permissions are left as they were; the result is Partly done, names it
       so it can be escalated, and lists every such folder (also saved to
       <LogFolder>\Backups\<yyyy-MM-dd_HHmmss>_NotOpened.txt). The root of a drive, the
       Windows system folders, the SYSVOL, NETLOGON and PRINT$ shares, and a folder with a
       junction or symbolic link inside that leads into one are refused unless
       -AllowSystemFolder is given.
    2. Shows the top folder's owner and permissions, and the owner of each subfolder.
    3. Copies the top folder's permissions to every subfolder: entries a subfolder does not
       already have are added, nothing is removed. The permissions of every subfolder are
       saved to <LogFolder>\Backups\<yyyy-MM-dd_HHmmss>_CopyPermissions.csv first.

    Before each change it prints the scope with [WARN] (for ownership, the number of items,
    counted read-only first) and asks "Continue? (y/N)". The copy step does not depend on
    ownership, so it is still offered when ownership was declined or failed.

    Every change is written to <LogFolder>\Changes_<yyyy-MM-dd>.csv, the same log the GUI
    writes. See "Undo a change" in README.md to put permissions or owners back.

    Exit code: 1 when a change Failed or was only Partly done, when taking ownership could not
    be checked everywhere (folders that could not be opened, owners that could not be read
    back, junctions or symbolic links), or the folder or log folder could not be used; 0
    otherwise (done, -WhatIf, or declined).

    If taking ownership is interrupted, its owner snapshot (..._TakeOwnership.csv) is in the
    Backups folder with no matching row in the change log: the row is written when the run
    ends.

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

.PARAMETER AllowSystemFolder
    Take ownership even when the folder is the root of a drive (D:\) or is in %SystemRoot%,
    %ProgramFiles%, %ProgramFiles(x86)% or %ProgramData%, or is another server's ADMIN$ or
    drive share (\\fs01\D$, \\fs01\C$\Windows), also when the folder leads there through a
    junction, a symbolic link or a short name, or is on a SYSVOL, NETLOGON or PRINT$ share, or
    has a junction or symbolic link inside it that leads into one of these (or somewhere that
    cannot be checked). Without it such a folder is refused and nothing
    is changed, because changing every owner in it can stop Windows or installed programs from
    working. The root of an ordinary share (\\fs01\share) is never refused.

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
    - See FolderPermissions.Core.ps1 for icacls /setowner /T /C /Q, Get-Acl, Set-Acl and
      GetOwner.
    - takeown /R /A /D N: /D N skips a folder the account has no List Folder and Read
      permission on (/D Y would replace its permissions with full control for the user only):
      https://learn.microsoft.com/windows-server/administration/windows-commands/takeown
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
    [switch]$AllowSystemFolder,

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
        returns $true when it needs the technician's attention (a row is Failed or Partly done,
        or a whole folder could not be checked everywhere: Test-TreeEntryIncomplete).
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
    @($results | Where-Object { $_ -eq 'Failed' -or $_ -eq 'Partly done' }).Count -gt 0 -or $incomplete.Count -gt 0
}

function Get-CliSubfolder {
    <#
    .SYNOPSIS
        The subfolders to copy permissions to, listed with Get-OwnerTreeItem so junctions and
        symbolic links are never gone into: Folders (paths), plus Unlisted (folders that could
        not be opened) and Links (junctions and symbolic links, which can point outside the
        folder), which are both skipped.
    #>
    param([Parameter(Mandatory)][string]$Path)

    $tree = Get-OwnerTreeItem -Path $Path
    $skip = @(@($tree.Unlisted) + @($tree.Links))
    [PSCustomObject]@{
        Folders  = @($tree.Items | Where-Object { $_.ItemType -eq 'Folder' -and $_.Path -ne $Path -and $skip -notcontains $_.Path } | ForEach-Object { $_.Path })
        Unlisted = @($tree.Unlisted | Where-Object { $_ -ne $Path })
        Links    = @($tree.Links | Where-Object { $_ -ne $Path })
    }
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
        The exit code for the script: 1 when the folder could not be used, a change Failed or
        was only Partly done, or taking ownership could not be checked everywhere; 0 otherwise
        (done, -WhatIf, or declined).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([int])]
    param(
        [string]$Path,
        [string]$LogFolder,
        [switch]$Force,
        [switch]$AllowSystemFolder
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
    # D-036: a drive root or a Windows system folder is refused before anything is asked,
    # counted or saved, also when the folder leads there through a junction, a symbolic link
    # or a short name.
    $refusal = if ($AllowSystemFolder) { $null } else { Get-TreeOwnershipTargetRefusal -Path $Path }
    if ($refusal) {
        Write-Host "[FAIL] $refusal If you are sure, run the script again with -AllowSystemFolder. Nothing was changed." -ForegroundColor Red
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
    # D-036 for the links inside the folder: one that leads into a protected folder, or
    # somewhere that cannot be checked, refuses the whole folder before anything is asked or
    # saved (the core checks again after its snapshot).
    $linkRefusal = if ($AllowSystemFolder) { $null } else { Get-TreeLinkRefusal -Path $Path -LinkPaths @($tree.Links) }
    if ($linkRefusal) {
        Write-Host "[FAIL] $linkRefusal If you are sure, run the script again with -AllowSystemFolder. Nothing was changed." -ForegroundColor Red
        return 1
    }
    $scope = "$(@($tree.Items).Count) item(s): $Path and every subfolder and file under it"
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $warning = "[WARN] Taking ownership makes $me the owner of $scope. The current owners are saved to a backup first."
    $unlisted = @($tree.Unlisted)
    if ($unlisted.Count -gt 0) {
        # takeown /D N skips a folder the account cannot list, so it keeps its permissions (D-034).
        # https://learn.microsoft.com/windows-server/administration/windows-commands/takeown
        $warning += " $($unlisted.Count) folder(s) cannot be opened, so they are skipped and left alone: $($unlisted -join '; ')."
    }
    $links = @($tree.Links)
    if ($links.Count -gt 0) {
        $warning += " It contains $($links.Count) junction(s) or symbolic link(s), which are listed but not gone into. Microsoft's documentation does not say whether takeown and icacls follow them, and icacls changes what a symbolic link points to, so check them afterwards: $($links -join '; ')."
    }
    Write-Host $warning -ForegroundColor Yellow
    $takeOwnership = $whatIf -or $Force -or (Confirm-CliStep)
    $ownershipTaken = $false
    if ($takeOwnership) {
        if ($whatIf) {
            $rows = @(Set-ItemOwnerToCurrentUser -Path $Path -Recurse -AllowSystemFolder:$AllowSystemFolder -LogFolder $logFolderUsed -WhatIf)
            $null = Write-CliChangeResult -Entries $rows -LogFolder $logFolderUsed
            $ownershipTaken = $true
        } else {
            Write-Host "[INFO] Saving the current owners and taking ownership. This can take a while on a large folder..." -ForegroundColor Cyan
            # The change-log row is written when the run ends; the Result values are fixed
            # (D-030), so there is no "started" row. An interrupted run is known by its backup.
            Write-Host "[INFO] If this is interrupted, the owners from before are in $(Join-Path $logFolderUsed 'Backups') (<date_time>_TakeOwnership.csv) with no matching row in the change log. See ""Undo a change"" in README.md to put them back." -ForegroundColor Cyan
            $result = Invoke-LoggedPermissionChange -LogFolder $logFolderUsed -Change {
                Set-ItemOwnerToCurrentUser -Path $Path -Recurse -AllowSystemFolder:$AllowSystemFolder -LogFolder $logFolderUsed -WhatIf:$false
            }
            if (Write-CliChangeResult -Entries $result.Entries -LogPath $result.LogPath -LogFolder $logFolderUsed) { $exitCode = 1 }
            # The result names the first few folders that could not be opened; the escalation
            # needs all of them, one per line so they can be copied into the ticket.
            foreach ($entry in @($result.Entries | Where-Object { (Get-TreeEntryCount $_ 'Unlisted') -gt 0 })) {
                Write-Host "[WARN] Folders that could not be opened ($(Get-TreeEntryCount $entry 'Unlisted')):" -ForegroundColor Yellow
                foreach ($folder in @($entry.TreeCounts.UnlistedFolders)) { Write-Host "  $folder" }
            }
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

    # Listed again: taking ownership may have opened folders that could not be opened before.
    $listing = Get-CliSubfolder -Path $Path
    $subFolders = @($listing.Folders)
    Write-Host "Subfolders and their owners ($($subFolders.Count)):"
    foreach ($folder in $subFolders) {
        try {
            $folderAcl = Get-Acl -LiteralPath $folder -ErrorAction Stop
            Write-Host "  $folder - Owner: $($folderAcl.Owner)"
        } catch {
            Write-Host "[WARN] Cannot read $($folder): $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    if (@($listing.Unlisted).Count -gt 0) {
        Write-Host "[WARN] $(@($listing.Unlisted).Count) folder(s) could not be opened, so they and what is inside them are skipped: $(@($listing.Unlisted) -join '; ')" -ForegroundColor Yellow
    }
    if (@($listing.Links).Count -gt 0) {
        Write-Host "[INFO] $(@($listing.Links).Count) junction(s) or symbolic link(s) are skipped, because they can point outside $($Path): $(@($listing.Links) -join '; ')" -ForegroundColor Cyan
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
    $targets = $subFolders
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

exit (Invoke-FolderPermissionCli -Path $Path -LogFolder $LogFolder -Force:$Force -AllowSystemFolder:$AllowSystemFolder)
