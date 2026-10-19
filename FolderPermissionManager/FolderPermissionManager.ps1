#Requires -Version 3.0

<#
.SYNOPSIS
    Takes ownership of a folder tree and shows its permissions. Every change is backed up and
    logged first.

.DESCRIPTION
    The command-line companion of FolderPermissionManager-GUI.ps1, for servers without a
    browser. It does two things:

    1. After asking once, takes ownership of the folder and all its subfolders and files for the account running
       the script (takeown /R /A /D N, then icacls /setowner /T). The current owner of every
       item is saved to <LogFolder>\Backups\<yyyy-MM-dd_HHmmss>_TakeOwnership.csv first; if
       that file cannot be written, nothing is changed. A folder that cannot be opened is
       skipped and its permissions are left as they were; the result is Partly done, names it
       so it can be escalated, and lists every such folder (also saved to
       <LogFolder>\Backups\<yyyy-MM-dd_HHmmss>_NotOpened.txt). The root of a drive, the
       Windows system folders, the SYSVOL, NETLOGON and PRINT$ shares, and a folder with a
       junction or symbolic link inside that leads into one are refused unless
       -AllowSystemFolder is given.
    2. Shows the top folder's owner and permissions, and the owner of each subfolder, and
       names the subfolders that block inheritance. This is shown also when ownership was
       declined or failed.

    It does not change any permissions. To give someone access: add it on the folder they
    need. Adding it on the top folder gives them everything inside it that inherits, so on
    a share or home-folder root that is everything below. Subfolders that block inheritance
    (inheritance turned off) do not get it, nor do the folders inside them, and an explicit
    Deny on a subfolder still wins. Add it with Add Permission in
    FolderPermissionManager-GUI.ps1 or on Explorer's Security tab. Without a browser:
        icacls "D:\Shares\HR\Finance" /grant "DOMAIN\user:(OI)(CI)RX"
    (RX is read and execute; use M only if they must change or delete files. Do not add /T,
    which writes it onto every subfolder and file, including the ones that block
    inheritance).

    Before taking ownership it prints the scope with [WARN] (the number of items, counted
    read-only first) and asks "Continue? (y/N)". A remote console (Enter-PSSession, psexec)
    is asked like a local one. A host that cannot ask (a scheduled task, or PowerShell
    started with -NonInteractive) needs -Force or -WhatIf; without either the script stops
    with [FAIL] before anything is changed.

    Every change is written to <LogFolder>\Changes_<yyyy-MM-dd>.csv, the same log the GUI
    writes. See "Undo a change" in README.md to put owners back.

    Exit code: 1 when taking ownership Failed, was only Partly done or could not be checked
    everywhere (folders that could not be opened, owners that could not be read back,
    junctions or symbolic links), or when the folder, the log folder or the host could not
    be used; 0 otherwise (done, -WhatIf, or declined).

    If taking ownership is interrupted, its owner snapshot (..._TakeOwnership.csv) is in the
    Backups folder with no matching row in the change log: the row is written when the run
    ends.

    CHANGES ANYTHING? Yes: owners. Use -WhatIf first.

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
    Do not ask before taking ownership. Needed (or -WhatIf) on a host that cannot ask, such as
    a scheduled task or PowerShell started with -NonInteractive.

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

    Asks before taking ownership, then shows the permissions. To give someone access
    afterwards, add it on the folder they need; the folders inside it that inherit get it
    too.

.EXAMPLE
    .\FolderPermissionManager.ps1 -Path 'D:\Shares\HR' -Force -LogFolder 'C:\Tickets\12345'

    Takes ownership without asking and shows the permissions; the owner backup and the log go
    to C:\Tickets\12345.

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
    - icacls /grant adds to the explicit permissions (without :r); (OI) and (CI) make files
      and subfolders inherit it; RX is read and execute access and M is modify access; /T
      performs the operation on every file and subfolder:
      https://learn.microsoft.com/windows-server/administration/windows-commands/icacls
    - Explicit ACEs come before inherited ones, and within them deny before allow, so a Deny
      set on a subfolder wins over access it inherits:
      https://learn.microsoft.com/windows/win32/secauthz/order-of-aces-in-a-dacl
    - ObjectSecurity.AreAccessRulesProtected: the folder's permissions are protected from
      inheritance:
      https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.objectsecurity.areaccessrulesprotected
    - -NonInteractive (-noni in pwsh) makes Read-Host fail; parameters are case-insensitive,
      may start with - or /, and everything after -File or -Command belongs to them. pwsh
      also honours --noninteractive (not documented there; checked on pwsh 7.5):
      https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe
      https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_pwsh
    - Environment.UserInteractive is not used to decide whether the host can ask: it can be
      false in a remote session where Read-Host still works. A Read-Host that throws is
      caught instead:
      https://learn.microsoft.com/dotnet/api/system.environment.userinteractive
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
        (for a whole folder) every folder could be opened and every owner read back. [INFO]
        when nothing was done because every row is -WhatIf.
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

function Get-CliRefusalNextStep {
    <#
    .SYNOPSIS
        What the [FAIL] line of a refused folder tells the technician to do next. Only a
        protected folder (D-036) gets the -AllowSystemFolder hint: a link whose destination
        could not be found out (Test-UnresolvedDestinationRefusal) leads somewhere nobody has
        checked, so the way forward is the folders beside it, or someone more senior. When no
        link is involved (Test-ChosenFolderUncheckedRefusal: the chosen folder's network drive,
        network path or DFS lookup could not be resolved), the way forward is the real server
        path instead.
    #>
    param([Parameter(Mandatory)][string]$Refusal)
    if (Test-ChosenFolderUncheckedRefusal -Refusal $Refusal) {
        return 'Check the path is reachable and run this against the real server path (Properties > DFS tab), or ask a senior engineer.'
    }
    if (Test-UnresolvedDestinationRefusal -Refusal $Refusal) {
        return 'Take ownership of the folders beside the link instead, or ask a senior engineer.'
    }
    'If you are sure, run the script again with -AllowSystemFolder.'
}

function Confirm-CliStep {
    # True when the technician types y or Y. Anything else, including Enter, is no (the
    # capital N says so). Read-Host throws when the host cannot ask; the caller catches it.
    param([string]$Question = 'Continue?')
    $answer = Read-Host "$Question (y/N)"
    $answer -eq 'y' -or $answer -eq 'Y'
}

function Test-CliHostInteractive {
    <#
    .SYNOPSIS
        False when PowerShell was started with -NonInteractive (or -noni, any case, starting
        with -, / or, in pwsh, --), so Read-Host would fail; true otherwise. Arguments after
        -File, -Command, -EncodedCommand or -CommandWithArgs belong to the script or command
        and are not read.
    .DESCRIPTION
        Environment.UserInteractive is deliberately not used: it can be false in an
        Enter-PSSession host (wsmprovhost.exe) or under psexec without -i, where Read-Host still
        works, and refusing there teaches remote technicians to use -Force, which skips the
        confirmation. A Read-Host that fails anyway is caught where it is asked.
    .NOTES
        -NonInteractive makes Read-Host a statement-terminating error; parameters are
        case-insensitive and powershell.exe also accepts /:
        https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe
        https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_pwsh
        about_Pwsh does not document the -- form; pwsh 7.5 honours --noninteractive and --noni
        (checked: Read-Host then fails with "PowerShell is in NonInteractive mode").
        powershell.exe reads --noninteractive as the start of a command, which no technician
        types, so it is treated the same here.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [string[]]$CommandLineArgs = [Environment]::GetCommandLineArgs()
    )

    # The first argument is the program itself.
    foreach ($arg in @($CommandLineArgs | Select-Object -Skip 1)) {
        if ($arg -notmatch '^(?:--|[-/])(?<name>[A-Za-z]+)$') { continue }
        $name = $Matches['name'].ToLowerInvariant()
        if ($name.Length -ge 4 -and 'noninteractive'.StartsWith($name)) { return $false }
        $endsOptions = 'command'.StartsWith($name) -or 'file'.StartsWith($name) -or
            'encodedcommand'.StartsWith($name) -or $name -eq 'ec' -or $name -eq 'cwa' -or $name -eq 'commandwithargs'
        if ($endsOptions) { break }
    }
    $true
}

function Invoke-FolderPermissionCli {
    <#
    .SYNOPSIS
        The script's work: take ownership, then show the permissions (D-035: there is no copy
        to the subfolders; access is added on the folder they need and inherited by what is
        inside it). Taking ownership shows its scope with [WARN], asks first (unless -Force),
        goes through the core (backup, then change, then change log) and prints its result.
        Never throws for a declined prompt or a host that cannot ask.
    .OUTPUTS
        The exit code for the script: 1 when the folder could not be used, taking ownership
        Failed or was only Partly done, or it could not be checked everywhere; 0 otherwise
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
    $noPathMessage = '[FAIL] Give the folder with -Path; this host cannot ask. Nothing was changed.'

    # A -NonInteractive session cannot answer "Continue? (y/N)": stop before anything is
    # asked, counted or saved instead of failing halfway on Read-Host.
    if (-not $Force -and -not $whatIf -and -not (Test-CliHostInteractive)) {
        Write-Host '[FAIL] Run with -Force, or -WhatIf for a dry run; this host cannot ask. Nothing was changed.' -ForegroundColor Red
        return 1
    }

    if (-not $Path) {
        if (-not (Test-CliHostInteractive)) {
            Write-Host $noPathMessage -ForegroundColor Red
            return 1
        }
        # A host without the -NonInteractive switch can still be unable to ask (a scheduled
        # task): Read-Host then throws, and the run stops cleanly.
        try {
            $Path = Read-Host 'Enter the path to the top-level folder'
        } catch {
            Write-Host $noPathMessage -ForegroundColor Red
            return 1
        }
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
        Write-Host "[FAIL] $refusal $(Get-CliRefusalNextStep -Refusal $refusal) Nothing was changed." -ForegroundColor Red
        return 1
    }

    $defaultLogFolder = Join-Path $PSScriptRoot 'Logs'

    # 1. Take ownership of everything under the folder. The tree is counted first (read only)
    # so the scope is shown before asking; the core lists it again for the snapshot.
    Write-Host "[INFO] Counting the folders and files in $Path..." -ForegroundColor Cyan
    $tree = Get-OwnerTreeItem -Path $Path
    # D-036 for the links inside the folder: one that leads into a protected folder, or
    # somewhere that cannot be checked, refuses the whole folder before anything is asked or
    # saved (the core checks again after its snapshot).
    $linkRefusal = if ($AllowSystemFolder) { $null } else { Get-TreeLinkRefusal -Path $Path -LinkPaths @($tree.Links) }
    if ($linkRefusal) {
        Write-Host "[FAIL] $linkRefusal $(Get-CliRefusalNextStep -Refusal $linkRefusal) Nothing was changed." -ForegroundColor Red
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
        $linkText = Get-LinkListText -LinkPaths $links
        $warning += " It contains $($linkText.Noun), which are listed but not gone into. Microsoft's documentation does not say whether takeown and icacls follow them, and icacls changes what a symbolic link points to, so check them afterwards: $(@($linkText.Items) -join '; ')."
    }
    Write-Host $warning -ForegroundColor Yellow
    $takeOwnership = $whatIf -or $Force
    if (-not $takeOwnership) {
        # Read-Host throws when the host cannot ask after all (not every such host is started
        # with -NonInteractive); nothing has been created or changed yet.
        try {
            $takeOwnership = Confirm-CliStep
        } catch {
            Write-Host '[FAIL] This host cannot ask; run with -Force, or -WhatIf for a dry run. Nothing was changed.' -ForegroundColor Red
            return 1
        }
    }
    if ($takeOwnership) {
        # The log folder is set up only once the change is agreed (a dry run writes nothing,
        # so it is not created or tested then).
        if ($whatIf) {
            $logFolderUsed = if ($LogFolder) { $LogFolder } else { $defaultLogFolder }
        } else {
            try {
                $logFolderUsed = Resolve-ChangeLogFolder -LogFolder $LogFolder -DefaultFolder $defaultLogFolder
            } catch {
                Write-Host "[FAIL] $($_.Exception.Message) Nothing was changed." -ForegroundColor Red
                return 1
            }
            foreach ($notice in @(Get-ChangeLogFolderNotice -LogFolder $LogFolder -ResolvedFolder $logFolderUsed -DefaultFolder $defaultLogFolder)) {
                Write-Host "[WARN] $notice" -ForegroundColor Yellow
            }
            Write-Host "[INFO] Changes are backed up and logged to $logFolderUsed" -ForegroundColor Cyan
        }
        if ($whatIf) {
            $rows = @(Set-ItemOwnerToCurrentUser -Path $Path -Recurse -AllowSystemFolder:$AllowSystemFolder -LogFolder $logFolderUsed -WhatIf)
            $null = Write-CliChangeResult -Entries $rows -LogFolder $logFolderUsed
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
        }
    } else {
        Write-Host '[INFO] Ownership was not changed.' -ForegroundColor Cyan
    }

    # 2. Show the permissions.
    try {
        $topAcl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    } catch {
        Write-Host "[FAIL] Could not read the permissions of $($Path): $($_.Exception.Message)" -ForegroundColor Red
        return 1
    }
    Write-Host ''
    Write-Host "Permissions on the top-level folder ($Path):"
    Write-Host "Owner: $($topAcl.Owner)"
    Write-Host 'Access rules:'
    $topAcl.Access | Format-Table IdentityReference, FileSystemRights, AccessControlType, IsInherited, InheritanceFlags -AutoSize | Out-Host

    # The folders counted in step 1 (takeown /D N opens none that could not be opened then).
    # Junctions and symbolic links are not gone into, and a folder that could not be opened
    # is already named in the ownership warning; their owners are not shown.
    $allSubFolders = @($tree.Items | Where-Object { $_.ItemType -eq 'Folder' -and $_.Path -ne $Path } | ForEach-Object { $_.Path })
    $unlistedShown = @($allSubFolders | Where-Object { @($tree.Unlisted) -contains $_ })
    $linksShown = @($allSubFolders | Where-Object { @($tree.Links) -contains $_ -and $unlistedShown -notcontains $_ })
    $subFolders = @($allSubFolders | Where-Object { $unlistedShown -notcontains $_ -and $linksShown -notcontains $_ })
    $leftOut = @()
    if ($unlistedShown.Count -gt 0) { $leftOut += "$($unlistedShown.Count) that could not be opened" }
    if ($linksShown.Count -gt 0) {
        $linkWord = if ($linksShown.Count -eq 1) { 'junction or symbolic link' } else { 'junctions or symbolic links' }
        $leftOut += "$($linksShown.Count) $linkWord"
    }
    $heading = if ($leftOut.Count -gt 0) { "$($subFolders.Count), not counting $($leftOut -join ' and '), listed above" } else { "$($subFolders.Count)" }
    Write-Host "Subfolders and their owners ($heading):"
    # The folders that block inheritance do not get access added above them (D-031, D-035).
    # https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.objectsecurity.areaccessrulesprotected
    $blocking = New-Object System.Collections.Generic.List[string]
    # A folder whose permissions cannot be read may block inheritance too; it is not claimed
    # either way.
    $unchecked = New-Object System.Collections.Generic.List[string]
    foreach ($folder in $subFolders) {
        try {
            $folderAcl = Get-Acl -LiteralPath $folder -ErrorAction Stop
            Write-Host "  $folder - Owner: $($folderAcl.Owner)"
            if ($folderAcl.AreAccessRulesProtected) { $blocking.Add($folder) }
        } catch {
            Write-Host "[WARN] Cannot read $($folder): $($_.Exception.Message)" -ForegroundColor Yellow
            $unchecked.Add($folder)
        }
    }

    # D-035: there is no copy to the subfolders. Access is added on the folder the person
    # needs and inherited from there, so adding it on a share root grants everything below.
    Write-Host "[INFO] To give someone access: add it on the folder they need. Adding it on $Path gives them everything inside it that inherits." -ForegroundColor Cyan
    if ($blocking.Count -gt 0) {
        Write-Host "[INFO] $($blocking.Count) subfolder(s) block inheritance, so they and the folders inside them do not get it: $($blocking -join '; ')." -ForegroundColor Cyan
    }
    if ($unchecked.Count -gt 0) {
        Write-Host "[WARN] Of the subfolders listed above, $($unchecked.Count) could not be checked (their permissions could not be read), so they may block inheritance too: $($unchecked -join '; ')." -ForegroundColor Yellow
    }
    if ($blocking.Count -eq 0 -and $unchecked.Count -eq 0) {
        Write-Host '[INFO] None of the subfolders listed above block inheritance.' -ForegroundColor Cyan
    } elseif ($blocking.Count -eq 0) {
        Write-Host '[INFO] None of the others block inheritance.' -ForegroundColor Cyan
    }
    # Explicit deny ACEs are checked before inherited allow ACEs.
    # https://learn.microsoft.com/windows/win32/secauthz/order-of-aces-in-a-dacl
    Write-Host '[INFO] An explicit Deny on a subfolder still wins.' -ForegroundColor Cyan
    # icacls /grant without :r adds to the explicit permissions; (OI)(CI) lets files and
    # subfolders inherit it; RX is read and execute access, M is modify access. /T would write
    # it onto every item, also those that block inheritance. The folder is a placeholder, not
    # the top folder: a pasted command must not grant everything below by accident.
    # https://learn.microsoft.com/windows-server/administration/windows-commands/icacls
    $grantExample = Join-Path $Path '<folder they need>'
    Write-Host "[INFO] Add it with Add Permission in FolderPermissionManager-GUI.ps1 or on Explorer's Security tab. Without a browser: icacls ""$grantExample"" /grant ""DOMAIN\user:(OI)(CI)RX"" (RX is read and execute; use M only if they must change or delete files. Do not add /T, which writes it onto every subfolder and file, including the ones that block inheritance)." -ForegroundColor Cyan
    $exitCode
}

if ($loadOnly) { return }

$isAdmin = (New-Object Security.Principal.WindowsPrincipal -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $WhatIfPreference) {
    Write-Host '[FAIL] Run this script in an elevated PowerShell window (right-click PowerShell, "Run as administrator"). Taking ownership needs administrator rights. Nothing was changed.' -ForegroundColor Red
    exit 1
}

exit (Invoke-FolderPermissionCli -Path $Path -LogFolder $LogFolder -Force:$Force -AllowSystemFolder:$AllowSystemFolder)
