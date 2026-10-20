<#
    Tests for the changing half of the WPF app FolderPermissionManager-GUI.ps1 (SQ-018, AC26-AC46,
    plus the SQ018N_* tests for the "Notes for SQ-018 from the SQ-017 reviews" in
    squad/specs/SQ-017.md; Pester 5, run under pwsh). AC1-AC25 are in FolderPermissionManager-App.Tests.ps1.

    The app is never started and no window is shown: it is dot-sourced with -LoadFunctionsOnly,
    its app-data paths point into $TestDrive, and every write is faked. Set-Acl, Invoke-AclTool,
    takeown and icacls are mocked with THROWING backstops that record the hit (AfterEach fails the
    test if one was reached unexpectedly). Tests that need the real core to run its flow
    override Set-Acl / Invoke-AclTool inside the test. Files and folders live in $TestDrive.
    Network lookups are seams that are mocked (Get-AppDfsTarget, Get-ThisComputerNames, and
    Test-Path for \\ paths). The only real background pool run is the SQ018N_Pool* test, whose
    pool has Set-Acl / Invoke-AclTool / takeown / icacls REPLACED by recording stubs.

    Names and parameters pinned here for the implementer (the spec leaves them open). The stubs in
    FolderPermissionManager-GUI.ps1 already carry these signatures.

    State the tests set (script scope of the app):
      $script:Current            [PSCustomObject]@{ DisplayPath; RealPath }  (existing) the selected folder
      $script:MappedDrives / $script:MappedDriveSources    letter -> UNC / letter -> Live|PassedOn|Remembered
      $script:WhatIfMode         [bool] the launch's -WhatIf (null under -LoadFunctionsOnly)
      $script:ChangeLogFolder    where backups and the change log go
      $script:UI                 hashtable name -> control; Start-ChangeTask skips names it does not have
      $script:ChangeTask         $null when no change runs, else [PSCustomObject]@{ Action; Path; ... }
      $script:ViewState.FolderPermissions.Rows / $script:FileAclCache[<path>] (Ok, Rows)  (existing)
      Get-SelectedFileRows       (existing) rows with a Path; blank paths are dropped
    Seams (mocked in these tests):
      Get-AppDfsTarget -Path <unc>     $null = not DFS, a string = the real UNC target, THROWS = cannot tell
      Get-ThisComputerNames               string[] this machine's names (short, FQDN) besides localhost/127.0.0.1/::1
      Show-ConfirmDialog -Spec <obj>   $true = go ahead
      Show-AppMessage / Set-Status     (existing) all text the tech sees
      Start-BgTask ... -Kind Read|Change   (new -Kind; stored on the task object as .Kind)
    Change flow:
      Get-ChangeControlNames                       names in $script:UI that are disabled while a change runs
                                                   (AddPermissionBtn, RemovePermissionBtn, TakeOwnershipBtn,
                                                   TakeOwnershipTreeBtn, CopyPermissionsBtn, AddFilePermissionBtn,
                                                   RemoveFilePermissionBtn, TakeFileOwnershipBtn at least)
      Start-ChangeTask -Action -Path -Work -ArgumentList -OnDone   -> [bool]; calls Start-BgTask -Kind Change;
          sets $script:ChangeTask; OnDone is called as ($result, $state); a result with Ok = $false (work threw,
          shape from Update-BgTasks: Ok, Stopped, Error) gives Set-Status Error "The change may or may not have
          been made. Check the folder's permissions. (<Error>)"; busy state is ALWAYS cleared (finally)
      Invoke-AddPermission -Scope Folder|Files -Identity -Rights -Type
      Invoke-RemovePermission -Scope Folder|Files -Identity -Rights -Type   (confirm first)
      Invoke-TakeOwnership -Scope Folder|Files|Tree     (Tree: refuse (D-036) -> Start-ReadTask count -> confirm -> change)
      Invoke-CopyPermissions -TargetText <multi-line text>
          Each reads $script:Current / Get-SelectedFileRows, classifies every path with Get-ChangeTarget, and ends
          in Start-ChangeTask -Work $script:<X>Work -ArgumentList ... -OnDone { param($result) ... }.
          Argument order = the work block's param order.
      Work blocks, plain param() blocks (NO [CmdletBinding()]), return
          [PSCustomObject]@{ Ok; Entries; LogPath; Message; Error } and take $CorePath last:
        $script:AddPermissionWork / $script:RemovePermissionWork
            param([string[]]$Paths, [string]$Identity, [string]$Rights, [string]$Type, [string]$LogFolder, [bool]$WhatIf, [string]$CorePath)
        $script:TakeOwnershipWork   param([string[]]$Paths, [bool]$Recurse, [string]$LogFolder, [bool]$WhatIf, [string]$CorePath)
            (whole tree = Set-ItemOwnerToCurrentUser -Recurse: the SQ-014 whole-tree function on this branch)
        $script:CopyPermissionsWork param([string]$SourcePath, [string[]]$TargetPaths, [string]$LogFolder, [bool]$WhatIf, [string]$CorePath)
        $script:TreeCountWork       param([string]$Path, [string]$CorePath) -> Ok, Path, Folders, Files, Error
            (read only; Folders includes the chosen folder itself, as the core's owner snapshot counts it)
        Message = Get-ChangeResultMessage -Entries -LogPath -LogFolder. Every core call is
        Invoke-LoggedPermissionChange -LogFolder $LogFolder -Change { <core> ... -Confirm:$false -WhatIf:$WhatIf }.
        Before the change a row with Result 'Started' is written to the change log (Write-PermissionChangeLog);
        it is not in Entries.
      Get-ChangeTarget -Path -DriveMap -DriveMapSource [-WholeTree]
          -> [PSCustomObject]@{ Ok; Refusal; DisplayPath; ResolvedPath; IsRemembered; IsLocal }
          Text only apart from the two seams (it does not need the path to exist). Not Ok: alternate data stream
          (':' after the drive or share prefix, Refusal mentions "stream"), DFS lookup failed (Refusal mentions
          "DFS"), not an absolute local or UNC path. -WholeTree adds D-036 on ResolvedPath (volume roots, X$ roots,
          ADMIN$, SYSVOL, NETLOGON, print$, IPC$, Windows folders), with the core's refusal text.
          Loopback names (localhost, 127.0.0.1, <::1>.ipv6-literal.net, Get-ThisComputerNames) set IsLocal and turn
          \\<local>\C$\rest into C:\rest in ResolvedPath. A mapped letter becomes its UNC path; IsRemembered when the
          letter's source is Remembered. DFS: UNC paths go through Get-AppDfsTarget; local paths never do.
      Get-ConfirmSpec -Action AddPermission|RemovePermission|TakeOwnershipFolder|TakeOwnershipFiles|TakeOwnershipTree|CopyPermissions
          -Targets <Get-ChangeTarget results> [-Counts @{Folders;Files}] [-Detail <text>]
          -> Title, Body, ActionLabel, IsDestructive. Body names DisplayPath and, when different, ResolvedPath, and says
          "remembered" for a Remembered target. Texts reused from the browser GUI: "saved to a backup first",
          "cannot be opened is skipped and left alone".
      Set-ConfirmDialog -Spec -TitleBlock (.Text) -BodyBox (.Text) -ActionButton (.Content .Style .IsDefault) -DangerStyle -NormalStyle
      Get-ChangeStatus -Entries -LogPath -Message -> Kind (Success|Warning|Error|Info), Text (Message, prefixed
          "Partly done: " when some items were done and others failed or were not found, else
          "Done, with items to check: " for any other warning, unless Message already starts "Partly done:").
          The spec's "Check this:" is shorthand for the browser's "Done, with items to check: " (parity).
          Deliberate deviation: all rows 'Skipped (WhatIf)' is Info (the browser showed an error).
      Get-RefreshPlan -Scope Folder|Files|Tree -Path -CurrentPath [-ChangedFiles] [-ShownFiles]
          -> ReloadPermissions, ReloadFiles, RefreshTreeEntry (bool), DropFileAcl, ReloadFileAcl (string[])
      Remove-CachedFileAcl -Path <string[]>             drops entries from $script:FileAclCache
      Get-RemoveIdentityChoices -Scope Folder|Files     -> Identities (string[]), NotLoaded (string[] paths)
      Get-PermissionInputError -Identity                -> $null, or the text for the add dialog
      Test-CanClose                                     $false + Show-AppMessage while $script:ChangeTask is set
      Wait-ChangeTasks -Tasks [-PollMilliseconds] [-TimeoutMilliseconds]   $true when every Kind Change task finished
      Invoke-AppShutdown                                a Kind Change task still running: nothing is stopped,
          mutex kept, pool kept, no exit, result .Deferred = $true
      Get-LogFolderMappingNotice -LogFolder -DriveMap -DriveMapSource -> string[] (a warning when the folder is
          reached through a Remembered letter)
      Initialize-BackgroundPool [-FunctionOverride <hashtable name -> function body>]   test hook: those
          function bodies replace the copied definitions in the pool's session state

    Traps found while writing these tests (for the implementer and reviewers):
      - FolderPermissionManager-App.Tests.ps1 AC6 matches the text 'localhost' case-insensitively in every
        non-comment token of the app, so a 'localhost' string literal (or a function name containing it)
        fails that existing test. Build the name at run time (for example 'local' + 'host') or keep it out of
        string literals. That test is not changed here.
      - Pool runspaces of PowerShell 7 do not load Get-Acl's type extensions: (Get-Acl ...).Sddl is empty there,
        so the core's backup check fails every change run through such a pool. Windows PowerShell 5.1 loads them.
        The pool test below substitutes Get-ItemSddl for that reason only.
      - Splat a variable, not an expression: & $work @argList works, & $work @($args) passes one array.

    Run:  Invoke-Pester .\FolderPermissionManager\Tests\FolderPermissionManager-AppChanges.Tests.ps1
#>

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:AppPath = Join-Path $script:Root 'FolderPermissionManager-GUI.ps1'
    $script:CorePath = Join-Path $script:Root 'FolderPermissions.Core.ps1'
    $script:RootReadme = Join-Path (Split-Path -Parent $script:Root) 'README.md'
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:AppPath, [ref]$null, [ref]$null)

    # The core first, so its functions can be mocked; then the app (which loads the core again).
    . $script:CorePath -LoadFunctionsOnly
    . $script:AppPath -LoadFunctionsOnly
    $script:RealGetAcl = Get-Command Get-Acl -CommandType Cmdlet
    $script:RealILPC = ${function:Invoke-LoggedPermissionChange}
    $script:RealStartChangeTask = ${function:Start-ChangeTask}
    $script:Dash = [string][char]0x2014

    # Isolation: the app's own files go to $TestDrive, never to the real %LOCALAPPDATA%.
    $script:AppDataFolder = Join-Path $TestDrive 'appdata\FolderPermissionManager'
    $script:SettingsPath = Join-Path $script:AppDataFolder 'settings.json'
    $script:ErrorLogPath = Join-Path $script:AppDataFolder 'gui-errors.log'

    $script:ChangeButtons = 'AddPermissionBtn', 'RemovePermissionBtn', 'TakeOwnershipBtn', 'TakeOwnershipTreeBtn',
    'CopyPermissionsBtn', 'AddFilePermissionBtn', 'RemoveFilePermissionBtn', 'TakeFileOwnershipBtn'

    function script:New-FakeChangeUi {
        param([string[]]$Names = $script:ChangeButtons)
        $ui = @{}
        foreach ($n in $Names) { $ui[$n] = [PSCustomObject]@{ IsEnabled = $true } }
        $ui
    }
    function script:New-Folder {
        param([string]$Name)
        $p = Join-Path $TestDrive $Name
        New-Item -ItemType Directory -Path $p -Force | Out-Null
        $p
    }
    function script:New-File {
        param([string]$Folder, [string]$Name)
        $p = Join-Path $Folder $Name
        Set-Content -LiteralPath $p -Value 'x'
        $p
    }
    function script:New-Row {
        param(
            [string]$Action = 'Add permission', [string]$Target = 'C:\x', [string]$Result = 'Done',
            [string]$Detail = 'Allow Modify for BUILTIN\Users', [string]$OldValue = 'old', [string]$NewValue = 'new',
            [string]$ErrorText = '', [string]$BackupFile = 'C:\logs\Backups\b.csv', [string]$ItemType = 'Folder'
        )
        New-PermissionChangeEntry -Action $Action -Target $Target -ItemType $ItemType -Detail $Detail -OldValue $OldValue `
            -NewValue $NewValue -Result $Result -ErrorText $ErrorText -BackupFile $BackupFile
    }
    function script:New-TreeRow {
        param([string]$Target = 'C:\x', [string]$Result = 'Done', [hashtable]$Counts = @{}, [string]$NewValue = 'All owned', [string]$ErrorText = '')
        $row = New-Row -Action 'Take ownership (all subfolders and files)' -Target $Target -Result $Result -Detail 'Owner set to me' -NewValue $NewValue -ErrorText $ErrorText
        $c = [ordered]@{
            Unreadable = 0; Unlisted = 0; Unchecked = 0; NotOwned = 0; Changed = 0; ItemCount = 0; Links = 0
            UnlistedFolders = @(); UnlistedChangedFolders = @(); UnlistedUncheckedFolders = @(); NotOpenedFile = ''
        }
        foreach ($k in $Counts.Keys) { $c[$k] = $Counts[$k] }
        Add-TreeEntryCount -Entry $row -Counts $c
        $row
    }
    function script:New-FakeTarget {
        param([string]$Display, [string]$Resolved, [bool]$Remembered = $false, [bool]$Local = $false)
        if (-not $Resolved) { $Resolved = $Display }
        [PSCustomObject]@{ Ok = $true; Refusal = $null; DisplayPath = $Display; ResolvedPath = $Resolved; IsRemembered = $Remembered; IsLocal = $Local }
    }
    function script:Get-AllLogTextIn {
        param([string]$Folder)
        $files = @(Get-ChildItem -LiteralPath $Folder -Recurse -File -ErrorAction SilentlyContinue)
        ($files | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
    }
    function script:Get-AllLogText {
        $files = @(Get-ChildItem -LiteralPath $script:ChangeLogFolder -Recurse -File -ErrorAction SilentlyContinue)
        ($files | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
    }
    # Runs what an action handed to Start-ChangeTask: the work block (as the pool would, but in this
    # session so the mocks apply), then its completion callback. An error in the callback is kept,
    # not thrown (Update-BgTasks catches those too).
    function script:Complete-Captured {
        $c = $script:Captured
        if (-not $c) { throw 'The action did not call Start-ChangeTask.' }
        $argList = @($c.ArgumentList)
        $result = & $c.Work @argList
        try { & $c.OnDone $result $null } catch { $script:OnDoneError = $_ }
        $result
    }
    function script:Get-LastStatus { if ($script:Status.Count -gt 0) { $script:Status[$script:Status.Count - 1] } }
    function script:Get-AllShownText { @($script:Shown) + @($script:Status | ForEach-Object { $_.Text }) }
    function script:Get-XamlButton {
        param([string]$Xaml, [string]$Name)
        $x = [xml]$Xaml
        $x.SelectSingleNode("//*[@*[local-name()='Name' and .='$Name']]")
    }
    function script:New-Rule {
        param([string]$Sid, [string]$Rights)
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]$Sid,
            [System.Security.AccessControl.FileSystemRights]$Rights,
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
    }
    function script:New-FakeAcl {
        param([object[]]$Rule = @())
        $acl = & $script:RealGetAcl -LiteralPath $TestDrive
        $acl.SetSecurityDescriptorSddlForm('O:BAG:SYD:PAI')
        foreach ($r in $Rule) { $acl.AddAccessRule($r) }
        $acl
    }
    function script:Add-CoreCall {
        # Recorded by the mocks of the core change functions.
        param([string]$Name, $Bound, $Path, $Identity, $Rights, $Type, $LogFolder, $Recurse)
        $script:CoreCalls.Add([PSCustomObject]@{ Name = $Name; Path = @($Path); Identity = $Identity; Rights = $Rights; Type = $Type; LogFolder = $LogFolder
                Recurse = [bool]$Recurse; BoundKeys = @($Bound.Keys); WhatIf = $Bound['WhatIf']; Confirm = $Bound['Confirm'] })
    }
    function script:New-FakeTask {
        param([string]$Kind = 'Change', [bool]$Completed = $false)
        $stopped = $script:StoppedTasks
        $ps = [PSCustomObject]@{}
        $ps | Add-Member ScriptMethod BeginStop { param($a, $b) $stopped.Add("stop-$Kind") }.GetNewClosure()
        [PSCustomObject]@{ Kind = $Kind; PS = $ps; Handle = [PSCustomObject]@{ IsCompleted = $Completed } }
    }
}

AfterAll {
    if ($script:BgPool) { try { $script:BgPool.Close() } catch { } }
}

Describe 'FolderPermissionManager app: changes (SQ-018)' {
BeforeEach {
    # Everything that could write is mocked first, with throwing backstops.
    $script:BackstopHit = [System.Collections.Generic.List[string]]::new()
    Mock Set-Acl { $script:BackstopHit.Add('Set-Acl'); throw 'Set-Acl was reached without a test mock.' }
    Mock Invoke-AclTool { $script:BackstopHit.Add('Invoke-AclTool'); throw 'Invoke-AclTool was reached without a test mock.' }
    Mock takeown { $script:BackstopHit.Add('takeown'); throw 'takeown was reached.' }
    Mock icacls { $script:BackstopHit.Add('icacls'); throw 'icacls was reached.' }

    $script:Shown = [System.Collections.Generic.List[string]]::new()
    $script:Status = [System.Collections.Generic.List[object]]::new()
    $script:Confirms = [System.Collections.Generic.List[object]]::new()
    $script:ConfirmAnswer = $true
    $script:Captured = $null
    $script:OnDoneError = $null
    $script:StoppedTasks = [System.Collections.Generic.List[string]]::new()
    Mock Show-AppMessage { $script:Shown.Add($Message) }
    Mock Show-AppQuestion { $false }
    Mock Set-Status { $script:Status.Add([PSCustomObject]@{ Text = $Text; Kind = $Kind }) }
    Mock Show-ConfirmDialog { $script:Confirms.Add($Spec); $script:ConfirmAnswer }
    Mock Get-AppDfsTarget { $null }
    Mock Get-ThisComputerNames { @('TESTPC', 'testpc.contoso.com') }
    Mock Test-Path { $false } -ParameterFilter { "$LiteralPath" -like '\\*' -or "$Path" -like '\\*' }
    Mock Update-CurrentFolder { }
    Mock Select-Folder { }
    Mock Start-ChangeTask { $script:Captured = @{ Action = $Action; Path = $Path; Work = $Work; ArgumentList = $ArgumentList; OnDone = $OnDone }; $true }
    # Seams added in the SQ-018 review round: the disk and network reads behind the target checks.
    # Defaults: no folder is a reparse point, every remote share is an ordinary folder on D:, the
    # profiles folder is C:\Users, and no file size can be read (the relaunch check then hashes).
    Mock Get-AppReparseInfo { [PSCustomObject]@{ Exists = $true; IsReparsePoint = $false; Tag = $null } }
    Mock Get-RemoteShareLocalPath { "D:\Shares\$Share" }
    Mock Get-AppProfilesDirectory { 'C:\Users' }
    Mock Get-RelaunchFileSize { $null }
    # Review round 2: a whole tree is also checked where Windows really reaches it (the core's
    # Get-Win32PathName, final and long forms). Default: every path is what it says it is.
    Mock Get-Win32PathName { $Path }

    $script:WhatIfMode = $false
    $script:ChangeTask = $null
    $script:ChangePending = $null
    $script:CurrentNode = $null
    $script:UI = New-FakeChangeUi
    $script:ChangeLogFolder = Join-Path $TestDrive ('log-' + [guid]::NewGuid().ToString('N'))
    $script:MappedDrives = @{}
    $script:MappedDriveSources = @{}
    $script:SelectedRows = @()
    $script:FileAclCache = @{}
    Mock Get-SelectedFileRows { $script:SelectedRows }
    $folder = New-Folder 'Data'
    $script:Current = [PSCustomObject]@{ DisplayPath = $folder; RealPath = $folder }
}

AfterEach {
    if (-not $script:AllowBackstop) {
        @($script:BackstopHit) | Should -BeNullOrEmpty -Because 'no test may reach a real write'
    }
    $script:AllowBackstop = $false
}

Describe 'One change at a time (AC26-AC28)' {
    It 'AC26_OneChangeAtATime' {
        $names = @(Get-ChangeControlNames)
        foreach ($b in $script:ChangeButtons) { $names | Should -Contain $b }
        $script:UI = New-FakeChangeUi -Names (@($names) + $script:ChangeButtons | Select-Object -Unique)

        $script:Started = [System.Collections.Generic.List[object]]::new()
        Mock Start-BgTask { $script:Started.Add(@{ Work = $Work; OnDone = $OnDone; State = $State; Kind = $Kind }); [PSCustomObject]@{ Kind = 'Change'; PS = $null; Handle = [PSCustomObject]@{ IsCompleted = $false } } }
        $real = $script:RealStartChangeTask
        $r1 = @(& $real -Action 'Adding a permission' -Path 'D:\Data\HR' -Work { 'work' } -ArgumentList @(1) -OnDone { param($r) })
        $r1[$r1.Count - 1] | Should -BeTrue
        foreach ($n in $names) { $script:UI[$n].IsEnabled | Should -BeFalse -Because "$n is disabled while a change runs" }

        $r2 = @(& $real -Action 'Taking ownership' -Path 'D:\Other' -Work { 'work2' } -ArgumentList @(2) -OnDone { param($r) })
        $r2[$r2.Count - 1] | Should -BeFalse
        $script:Started.Count | Should -Be 1 -Because 'the second change must not reach Start-BgTask'
        (Get-LastStatus).Text | Should -Be 'Another change is still running on D:\Data\HR. Wait for it to finish.'

        # When the first one completes, controls are back and a new change can start.
        & $script:Started[0].OnDone ([PSCustomObject]@{ Ok = $true; Message = 'ok'; Entries = @(); LogPath = $null }) $script:Started[0].State
        foreach ($n in $names) { $script:UI[$n].IsEnabled | Should -BeTrue }
        $r3 = @(& $real -Action 'Taking ownership' -Path 'D:\Other' -Work { 'work2' } -ArgumentList @(2) -OnDone { param($r) })
        $r3[$r3.Count - 1] | Should -BeTrue
        $script:Started.Count | Should -Be 2
        $script:Started[1].Kind | Should -Be 'Change' -Because 'a change task is kept apart from reads'
    }

    It 'AC27_BusyAlwaysCleared' {
        $script:Started = [System.Collections.Generic.List[object]]::new()
        Mock Start-BgTask { $script:Started.Add(@{ OnDone = $OnDone; State = $State }); [PSCustomObject]@{ Kind = 'Change'; PS = $null; Handle = [PSCustomObject]@{ IsCompleted = $false } } }
        $real = $script:RealStartChangeTask

        # 1. The work threw: Update-BgTasks hands over Ok = $false and the error text.
        [void](& $real -Action 'Adding a permission' -Path 'D:\Data' -Work { 'w' } -OnDone { param($r) })
        & $script:Started[0].OnDone ([PSCustomObject]@{ Ok = $false; Stopped = $false; Error = 'boom' }) $script:Started[0].State
        $script:ChangeTask | Should -BeNullOrEmpty
        foreach ($n in $script:ChangeButtons) { $script:UI[$n].IsEnabled | Should -BeTrue }
        $last = Get-LastStatus
        $last.Kind | Should -Be 'Error'
        $last.Text | Should -Be "The change may or may not have been made. Check the folder's permissions. (boom)"

        # 2. The completion callback itself throws (a refresh failing): still cleared.
        $script:Status.Clear()
        [void](& $real -Action 'Adding a permission' -Path 'D:\Data' -Work { 'w' } -OnDone { param($r) throw 'refresh broke' })
        try { & $script:Started[1].OnDone ([PSCustomObject]@{ Ok = $true; Message = 'm'; Entries = @(); LogPath = $null }) $script:Started[1].State } catch { }
        $script:ChangeTask | Should -BeNullOrEmpty
        foreach ($n in $script:ChangeButtons) { $script:UI[$n].IsEnabled | Should -BeTrue }

        # 3. The pool cannot start the task at all: not left busy, and says so.
        Mock Start-BgTask { throw 'pool is closed' }
        $r = @(& $real -Action 'Adding a permission' -Path 'D:\Data' -Work { 'w' } -OnDone { param($r) })
        $r[$r.Count - 1] | Should -BeFalse
        $script:ChangeTask | Should -BeNullOrEmpty
        foreach ($n in $script:ChangeButtons) { $script:UI[$n].IsEnabled | Should -BeTrue }
        (Get-LastStatus).Kind | Should -Be 'Error'
    }

    It 'AC28_ChangesOnlyThroughGate' {
        $script:WriteNames = 'Add-FolderPermission', 'Remove-FolderPermission', 'Set-ItemOwnerToCurrentUser', 'Copy-FolderPermission'
        $script:WorkVarPaths = 'script:AddPermissionWork', 'script:RemovePermissionWork', 'script:TakeOwnershipWork', 'script:CopyPermissionsWork'
        $assigns = @($script:Ast.FindAll({ param($n)
                    $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                    $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                    $n.Left.VariablePath.UserPath -in $script:WorkVarPaths }, $true))
        $assigns.Count | Should -Be 4 -Because 'the four change work blocks are $script:<Name>Work = { ... }'

        $calls = @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in $script:WriteNames }, $true))
        $calls.Count | Should -BeGreaterThan 0 -Because 'the work blocks call the core change functions'
        @($calls | ForEach-Object { $_.GetCommandName() } | Sort-Object -Unique).Count | Should -Be 4 -Because 'add, remove, take ownership and copy are all called'
        foreach ($c in $calls) {
            $inside = $false
            for ($p = $c.Parent; $p; $p = $p.Parent) { if ($assigns -contains $p) { $inside = $true; break } }
            $inside | Should -BeTrue -Because "$($c.GetCommandName()) at line $($c.Extent.StartLineNumber) must sit inside a change work block"
        }

        $refs = @($script:Ast.FindAll({ param($n)
                    $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath -in $script:WorkVarPaths }, $true) |
                Where-Object { -not ($_.Parent -is [System.Management.Automation.Language.AssignmentStatementAst] -and $_.Parent.Left -eq $_) })
        $refs.Count | Should -BeGreaterThan 0
        foreach ($v in $refs) {
            $cmd = $v.Parent
            while ($cmd -and $cmd -isnot [System.Management.Automation.Language.CommandAst]) { $cmd = $cmd.Parent }
            $cmd | Should -Not -BeNullOrEmpty -Because "line $($v.Extent.StartLineNumber): $($v.VariablePath.UserPath) may only be an argument of Start-ChangeTask"
            $cmd.GetCommandName() | Should -Be 'Start-ChangeTask' -Because "line $($v.Extent.StartLineNumber): $($v.VariablePath.UserPath) may only be passed to Start-ChangeTask"
        }
        foreach ($w in $script:WorkVarPaths) {
            @($refs | Where-Object { $_.VariablePath.UserPath -eq $w }).Count | Should -BeGreaterThan 0 -Because "$w must be passed to Start-ChangeTask"
        }
    }
}

Describe 'Add and remove permission (AC29-AC31, AC42, AC43)' {
    BeforeEach {
        $script:CoreCalls = [System.Collections.Generic.List[object]]::new()
        $script:LoggedCalls = 0
        Mock Invoke-LoggedPermissionChange { $script:LoggedCalls++; & $script:RealILPC -Change $Change -LogFolder $LogFolder }
        Mock Add-FolderPermission {
            Add-CoreCall 'Add-FolderPermission' $PesterBoundParameters $Path $Identity $Rights $Type $LogFolder $null
            foreach ($p in $Path) { New-Row -Action 'Add permission' -Target $p -Detail "$Type $Rights for $Identity" }
        }
        Mock Remove-FolderPermission {
            Add-CoreCall 'Remove-FolderPermission' $PesterBoundParameters $Path $Identity $Rights $Type $LogFolder $null
            foreach ($p in $Path) { New-Row -Action 'Remove permission' -Target $p -Detail "$Type $Rights for $Identity" }
        }
        Mock Set-ItemOwnerToCurrentUser {
            Add-CoreCall 'Set-ItemOwnerToCurrentUser' $PesterBoundParameters $Path $null $null $null $LogFolder $Recurse
            foreach ($p in $Path) { New-Row -Action 'Take ownership' -Target $p -Detail 'Owner set to me' }
        }
    }

    It 'AC29_AddFolder' {
        $folder = New-Folder 'AddHere'
        $log = $script:ChangeLogFolder
        $r = & $script:AddPermissionWork -Paths @($folder) -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' -LogFolder $log -WhatIf $false -CorePath $null
        $script:LoggedCalls | Should -Be 1 -Because 'the change goes through Invoke-LoggedPermissionChange'
        $script:CoreCalls.Count | Should -Be 1
        $c = $script:CoreCalls[0]
        $c.Name | Should -Be 'Add-FolderPermission'
        $c.Path | Should -Be @($folder)
        $c.Identity | Should -Be 'BUILTIN\Users'
        $c.Rights | Should -Be 'Modify'
        $c.Type | Should -Be 'Allow'
        $c.LogFolder | Should -Be $log
        $c.BoundKeys | Should -Contain 'Confirm'
        [bool]$c.Confirm | Should -BeFalse
        $c.BoundKeys | Should -Contain 'WhatIf' -Because '-WhatIf is always passed explicitly'
        [bool]$c.WhatIf | Should -BeFalse
        $r.Ok | Should -BeTrue
        $r.Message | Should -Be (Get-ChangeResultMessage -Entries $r.Entries -LogPath $r.LogPath -LogFolder $log)
        $r.LogPath | Should -Not -BeNullOrEmpty
        (Get-AllLogText) | Should -Match 'Add permission'

        $null = & $script:AddPermissionWork -Paths @($folder) -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' -LogFolder $log -WhatIf $true -CorePath $null
        [bool]$script:CoreCalls[1].WhatIf | Should -BeTrue -Because "the launch's -WhatIf value is passed on"
    }

    It 'AC30_RemoveFolder' {
        $folder = New-Folder 'RemoveHere'
        $log = $script:ChangeLogFolder
        $r = & $script:RemovePermissionWork -Paths @($folder) -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' -LogFolder $log -WhatIf $false -CorePath $null
        $script:LoggedCalls | Should -Be 1
        $c = $script:CoreCalls[0]
        $c.Name | Should -Be 'Remove-FolderPermission'
        $c.Path | Should -Be @($folder)
        $c.LogFolder | Should -Be $log
        [bool]$c.Confirm | Should -BeFalse
        $c.BoundKeys | Should -Contain 'WhatIf'
        $r.Message | Should -Be (Get-ChangeResultMessage -Entries $r.Entries -LogPath $r.LogPath -LogFolder $log)
        $r.Message | Should -BeLike 'Removed all Allow permissions for BUILTIN\Users (asked: Modify)*'
    }

    It 'AC31_FileBatch_CoreCalledOnceWithAllPaths' {
        $dir = New-Folder 'Batch'
        $f1 = New-File $dir 'a.txt'; $f2 = New-File $dir 'b.txt'; $f3 = New-File $dir 'c.txt'
        $script:SelectedRows = @([PSCustomObject]@{ Path = $f1 }, [PSCustomObject]@{ Path = '' }, [PSCustomObject]@{ Path = $f2 }, [PSCustomObject]@{ Path = $f3 })
        $actions = [ordered]@{
            'Add-FolderPermission'       = { Invoke-AddPermission -Scope Files -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' }
            'Remove-FolderPermission'    = { Invoke-RemovePermission -Scope Files -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' }
            'Set-ItemOwnerToCurrentUser' = { Invoke-TakeOwnership -Scope Files }
        }
        foreach ($name in $actions.Keys) {
            $script:CoreCalls.Clear(); $script:Captured = $null
            & $actions[$name]
            [void](Complete-Captured)
            $script:CoreCalls.Count | Should -Be 1 -Because "$name is called once for the whole batch"
            $script:CoreCalls[0].Name | Should -Be $name
            $script:CoreCalls[0].Path | Should -Be @($f1, $f2, $f3) -Because 'blank entries are dropped'
        }
    }

    It 'AC31_FileBatch_NoFilesSelected' {
        $script:SelectedRows = @()
        Invoke-AddPermission -Scope Files -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow'
        Invoke-RemovePermission -Scope Files -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow'
        Invoke-TakeOwnership -Scope Files
        Should -Invoke Start-ChangeTask -Times 0 -Exactly
        $script:Status.Count | Should -Be 3
        foreach ($s in $script:Status) { $s.Text | Should -Be 'Select at least one file.' }
    }

    It 'AC42_RemoveChoices' {
        $script:ViewState.FolderPermissions = [PSCustomObject]@{ Ok = $true; Rows = @(
                [PSCustomObject]@{ Identity = 'BUILTIN\Administrators'; Type = 'Allow' },
                [PSCustomObject]@{ Identity = 'CONTOSO\HR'; Type = 'Allow' },
                [PSCustomObject]@{ Identity = 'BUILTIN\Administrators'; Type = 'Deny' }) }
        $f = @('X:\a.txt', 'X:\b.txt', 'X:\c.txt')
        $folderChoices = Get-RemoveIdentityChoices -Scope Folder
        ($folderChoices.Identities -join '|') | Should -Be 'BUILTIN\Administrators|CONTOSO\HR'
        @($folderChoices.NotLoaded).Count | Should -Be 0

        $script:SelectedRows = @($f | ForEach-Object { [PSCustomObject]@{ Path = $_ } })
        $script:FileAclCache = @{
            $f[0] = [PSCustomObject]@{ Ok = $true; Path = $f[0]; Rows = @([PSCustomObject]@{ Identity = 'A' }, [PSCustomObject]@{ Identity = 'B' }) }
            $f[1] = [PSCustomObject]@{ Ok = $true; Path = $f[1]; Rows = @([PSCustomObject]@{ Identity = 'B' }, [PSCustomObject]@{ Identity = 'C' }) }
        }
        $choices = Get-RemoveIdentityChoices -Scope Files
        ($choices.Identities -join '|') | Should -Be 'A|B|C' -Because 'the union of the loaded files, each identity once'
        ($choices.NotLoaded -join '|') | Should -Be $f[2] -Because 'files not loaded yet are returned to load first'
        $script:FileAclCache[$f[2]] = [PSCustomObject]@{ Ok = $true; Path = $f[2]; Rows = @([PSCustomObject]@{ Identity = 'D' }) }
        $again = Get-RemoveIdentityChoices -Scope Files
        ($again.Identities -join '|') | Should -Be 'A|B|C|D'
        @($again.NotLoaded).Count | Should -Be 0
    }

    It 'AC43_AddValidation' {
        $text = 'Enter a user or group, for example CONTOSO\HR-Staff.'
        Get-PermissionInputError -Identity '' | Should -Be $text
        Get-PermissionInputError -Identity '   ' | Should -Be $text
        Get-PermissionInputError -Identity $null | Should -Be $text
        Get-PermissionInputError -Identity 'CONTOSO\HR-Staff' | Should -BeNullOrEmpty
        Invoke-AddPermission -Scope Folder -Identity '  ' -Rights 'Modify' -Type 'Allow'
        Should -Invoke Start-ChangeTask -Times 0 -Exactly

        $x = [xml](Get-PermissionDialogXaml)
        $rights = @($x.SelectNodes("//*[@*[local-name()='Name' and .='PermRightsCombo']]/*") | ForEach-Object { $_.GetAttribute('Content') })
        ($rights -join '|') | Should -Be 'Full Control|Modify|Read & Execute|Read|Write'
        $types = @($x.SelectNodes("//*[@*[local-name()='Name' and .='PermTypeCombo']]/*") | ForEach-Object { $_.GetAttribute('Content') })
        ($types -join '|') | Should -Be 'Allow|Deny'
    }
}

Describe 'File batch where one file fails (AC31)' {
    It 'AC31_FileBatch_PartlyDoneWhenOneFileFails' {
        # The real core runs here, with Set-Acl and the native tools faked.
        $script:AllowBackstop = $true
        $dir = New-Folder 'Batch2'
        $f1 = New-File $dir 'a.txt'; $f2 = New-File $dir 'b.txt'; $f3 = New-File $dir 'c.txt'
        $script:SelectedRows = @([PSCustomObject]@{ Path = $f1 }, [PSCustomObject]@{ Path = $f2 }, [PSCustomObject]@{ Path = $f3 })
        $script:Second = $f2
        Mock Set-Acl { if ("$LiteralPath" -eq $script:Second) { throw 'Access is denied' } }
        Mock Invoke-AclTool { [PSCustomObject]@{ ExitCode = 0; Output = '' } }
        foreach ($case in 'Add', 'Remove', 'Own') {
            $script:Captured = $null; $script:Status.Clear()
            switch ($case) {
                'Add' { Invoke-AddPermission -Scope Files -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' }
                'Remove' { Invoke-RemovePermission -Scope Files -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' }
                'Own' { Invoke-TakeOwnership -Scope Files }
            }
            [void](Complete-Captured)
            $last = Get-LastStatus
            $last | Should -Not -BeNullOrEmpty -Because "$case must set a status"
            $last.Kind | Should -Be 'Warning' -Because "$case on three files where the second fails"
            $last.Text | Should -BeLike 'Partly done: *'
        }
    }
}

Describe 'Take ownership and copy permissions (AC32-AC38)' {
    It 'AC32_TakeOwnershipFolder' {
        $folder = New-Folder 'Own1'
        $script:Current = [PSCustomObject]@{ DisplayPath = $folder; RealPath = $folder }
        $script:Calls = [System.Collections.Generic.List[object]]::new()
        Mock Set-ItemOwnerToCurrentUser {
            $script:Calls.Add([PSCustomObject]@{ Path = @($Path); Recurse = [bool]$Recurse })
            New-Row -Action 'Take ownership' -Target $Path[0] -Detail 'Owner set to me'
        }
        Invoke-TakeOwnership -Scope Folder
        Should -Invoke Show-ConfirmDialog -Times 1 -Exactly
        $script:Confirms[0].IsDestructive | Should -BeTrue
        $r = Complete-Captured
        $script:Calls.Count | Should -Be 1
        $script:Calls[0].Path | Should -Be @($folder)
        $script:Calls[0].Recurse | Should -BeFalse
        $r.Message | Should -Be (Get-ChangeResultMessage -Entries $r.Entries -LogPath $r.LogPath -LogFolder $script:ChangeLogFolder)
        (Get-AllLogText) | Should -Match 'Take ownership' -Because 'the change is logged'
    }

    It 'AC32_TakeOwnershipFolder_DeclinedDoesNothing' {
        $script:ConfirmAnswer = $false
        Invoke-TakeOwnership -Scope Folder
        Should -Invoke Start-ChangeTask -Times 0 -Exactly
    }

    It 'AC33_WholeTreeTakeOwnership' {
        $folder = New-Folder 'Tree33'
        $script:Current = [PSCustomObject]@{ DisplayPath = $folder; RealPath = $folder }
        Mock Start-ReadTask { & $OnDone ([PSCustomObject]@{ Ok = $true; Path = $Path; Folders = 3; Files = 4; Error = $null }) $State }
        $script:Row = New-TreeRow -Target $folder -Result 'Partly done' -Counts @{ Unlisted = 2; UnlistedFolders = @("$folder\L1", "$folder\L2"); Changed = 5; ItemCount = 7 }
        Mock Set-ItemOwnerToCurrentUser { $script:Row }
        Invoke-TakeOwnership -Scope Tree
        $script:Captured | Should -Not -BeNullOrEmpty
        [void](Complete-Captured)
        $last = Get-LastStatus
        $last.Kind | Should -Be 'Warning'
        $last.Text | Should -Match ([regex]::Escape('Escalate: 2 folders could not be opened'))

        # A Done row with nothing unreadable or unopened is a success.
        $script:Row = New-TreeRow -Target $folder -Result 'Done' -Counts @{ Changed = 7; ItemCount = 7 }
        $script:Captured = $null; $script:Status.Clear()
        Invoke-TakeOwnership -Scope Tree
        [void](Complete-Captured)
        (Get-LastStatus).Kind | Should -Be 'Success'
    }

    It 'AC34_SystemFolderRefused' {
        Mock Start-ReadTask { }
        $paths = @('D:\', "$env:SystemRoot\System32", "$env:ProgramFiles\Vendor", "$env:ProgramData\Vendor")
        if (${env:ProgramFiles(x86)}) { $paths += "${env:ProgramFiles(x86)}\Vendor" }
        foreach ($p in $paths) {
            $script:Shown.Clear(); $script:Status.Clear()
            $script:Current = [PSCustomObject]@{ DisplayPath = $p; RealPath = $p }
            Invoke-TakeOwnership -Scope Tree
            $expected = Get-TreeOwnershipRefusal -Path $p
            $expected | Should -Not -BeNullOrEmpty
            @(Get-AllShownText | Where-Object { $_ -and $_.Contains($expected) }).Count | Should -BeGreaterThan 0 -Because "$p is refused with the core's D-036 text"
        }
        Should -Invoke Start-ReadTask -Times 0 -Exactly -Because 'no count starts'
        Should -Invoke Show-ConfirmDialog -Times 0 -Exactly
        Should -Invoke Start-ChangeTask -Times 0 -Exactly

        # A share root is allowed.
        $script:Current = [PSCustomObject]@{ DisplayPath = '\\fs01\share'; RealPath = '\\fs01\share' }
        Invoke-TakeOwnership -Scope Tree
        Should -Invoke Start-ReadTask -Times 1 -Exactly
    }

    It 'AC35_WholeTreeScope' {
        $root = New-Folder 'Tree35'
        $a = New-Folder 'Tree35\A'; $b = New-Folder 'Tree35\B'
        New-File $root 'f1.txt' | Out-Null; New-File $a 'f2.txt' | Out-Null; New-File $a 'f3.txt' | Out-Null; New-File $b 'f4.txt' | Out-Null
        $r = & $script:TreeCountWork -Path $root -CorePath $null
        $r.Ok | Should -BeTrue
        $r.Folders | Should -Be 3
        $r.Files | Should -Be 4

        $spec = Get-ConfirmSpec -Action TakeOwnershipTree -Targets @(New-FakeTarget -Display $root) -Counts ([PSCustomObject]@{ Folders = 3; Files = 4 })
        $spec.Body | Should -Match ([regex]::Escape($root))
        $spec.Body | Should -Match '3 folders and 4 files'
        $spec.Body | Should -Match 'saved to a backup first'
        $spec.Body | Should -Match 'cannot be opened is skipped and left alone'
        $spec.ActionLabel | Should -Be 'Take ownership of 7 items'
        $spec.IsDestructive | Should -BeTrue
    }

    It 'AC36_ConfirmSpecs' {
        $one = New-FakeTarget -Display 'D:\Data\HR'
        $files = @('D:\Data\a.txt', 'D:\Data\b.txt', 'D:\Data\c.txt') | ForEach-Object { New-FakeTarget -Display $_ }
        # Folders inside a share: a share root (\\fs01\A) is destructive since D-044 amended AC36
        # (AC49_CopyOntoARoot_DestructiveConfirmWithRealLocation covers that).
        $copyTargets = @('\\fs01\Data\A', '\\fs01\Data\B') | ForEach-Object { New-FakeTarget -Display $_ }
        $cases = @(
            @{ Action = 'AddPermission'; Targets = @($one); Detail = 'Allow Modify for CONTOSO\HR'; Destructive = $false; Count = $null; Verb = '^Add' }
            @{ Action = 'RemovePermission'; Targets = @($one); Detail = 'Allow Modify for CONTOSO\HR'; Destructive = $true; Count = $null; Verb = '^Remove' }
            @{ Action = 'TakeOwnershipFolder'; Targets = @($one); Detail = ''; Destructive = $true; Count = $null; Verb = '^Take ownership' }
            @{ Action = 'TakeOwnershipFiles'; Targets = $files; Detail = ''; Destructive = $true; Count = '3'; Verb = '^Take ownership' }
            @{ Action = 'TakeOwnershipTree'; Targets = @($one); Detail = ''; Destructive = $true; Count = '3'; Verb = '^Take ownership'; Counts = [PSCustomObject]@{ Folders = 3; Files = 4 } }
            @{ Action = 'CopyPermissions'; Targets = $copyTargets; Detail = 'D:\Data\Source'; Destructive = $false; Count = '2'; Verb = '^Copy' }
        )
        foreach ($c in $cases) {
            $args1 = @{ Action = $c.Action; Targets = $c.Targets; Detail = $c.Detail }
            if ($c.Counts) { $args1.Counts = $c.Counts }
            $spec = Get-ConfirmSpec @args1
            $spec.Title | Should -Not -BeNullOrEmpty
            foreach ($t in $c.Targets) { $spec.Body | Should -Match ([regex]::Escape($t.DisplayPath)) -Because "$($c.Action) names the path" }
            if ($c.Count) { $spec.Body | Should -Match "\b$($c.Count)\b" -Because "$($c.Action) says how many items" }
            $spec.ActionLabel | Should -Not -BeIn @('OK', 'Yes', 'No', '')
            $spec.ActionLabel | Should -Match $c.Verb
            $spec.IsDestructive | Should -Be $c.Destructive -Because $c.Action
        }
    }

    It 'AC37_ConfirmDialogSafe' {
        $x = [xml](Get-ConfirmDialogXaml)
        $cancel = Get-XamlButton -Xaml (Get-ConfirmDialogXaml) -Name 'ConfirmCancelBtn'
        $action = Get-XamlButton -Xaml (Get-ConfirmDialogXaml) -Name 'ConfirmActionBtn'
        $cancel.GetAttribute('IsDefault') | Should -Be 'True'
        $cancel.GetAttribute('IsCancel') | Should -Be 'True'
        $action.GetAttribute('IsDefault') | Should -Not -Be 'True'

        $danger = 'DANGER-STYLE'; $normal = 'NORMAL-STYLE'
        foreach ($case in @(@{ D = $true; Style = $danger }, @{ D = $false; Style = $normal })) {
            $title = [PSCustomObject]@{ Text = '' }; $body = [PSCustomObject]@{ Text = '' }
            $btn = [PSCustomObject]@{ Content = ''; Style = $null; IsDefault = $false }
            $spec = [PSCustomObject]@{ Title = 'Check'; Body = 'Body text'; ActionLabel = 'Take ownership'; IsDestructive = $case.D }
            Set-ConfirmDialog -Spec $spec -TitleBlock $title -BodyBox $body -ActionButton $btn -DangerStyle $danger -NormalStyle $normal
            $title.Text | Should -Be 'Check'
            $body.Text | Should -Be 'Body text'
            $btn.Content | Should -Be 'Take ownership'
            $btn.Style | Should -Be $case.Style
            $btn.IsDefault | Should -BeFalse -Because 'the action button is never the default'
        }
    }

    It 'AC38_CopyPermissions' {
        $script:Calls = [System.Collections.Generic.List[object]]::new()
        Mock Copy-FolderPermission {
            $script:Calls.Add([PSCustomObject]@{ Source = $SourcePath; Targets = @($TargetPath); BoundKeys = @($PesterBoundParameters.Keys) })
            foreach ($t in $TargetPath) { New-Row -Action 'Copy permissions' -Target $t -Detail "Copy the permissions set on $SourcePath" }
        }
        $source = $script:Current.RealPath
        Invoke-CopyPermissions -TargetText "\\fs01\A`n`n  \\fs01\B  "
        [void](Complete-Captured)
        $script:Calls.Count | Should -Be 1
        $script:Calls[0].Source | Should -Be $source
        ($script:Calls[0].Targets -join '|') | Should -Be '\\fs01\A|\\fs01\B'

        $script:Captured = $null
        Invoke-CopyPermissions -TargetText "`n   `n`r`n"
        $script:Captured | Should -BeNullOrEmpty -Because 'no task starts for blank lines'
        (Get-LastStatus).Text | Should -BeLike 'Enter at least one target path*'

        $xaml = Get-CopyPermissionsDialogXaml
        $xaml | Should -Not -Match '(?i)recurs'
        $xaml | Should -Not -Match '<CheckBox'
        $xaml | Should -Match ([regex]::Escape('Subfolders that block inheritance'))
    }
}

Describe 'Results, refresh, closing (AC39-AC41)' {
    It 'AC39_ResultStatus' {
        $log = 'C:\logs\change.csv'
        $done = { New-Row -Result 'Done' -Target 'C:\a' }
        $cases = @(
            @{ Name = 'all done and logged'; Entries = @(& $done); Log = $log; Msg = 'Added it.'; Kind = 'Success'; Text = 'Added it.' }
            @{ Name = 'partial batch'; Entries = @((New-Row -Result 'Done' -Target 'C:\a'), (New-Row -Result 'Failed' -Target 'C:\b' -ErrorText 'denied')); Log = $log; Msg = 'Added on 1 of 2 files.'; Kind = 'Warning'; Text = 'Partly done: Added on 1 of 2 files.' }
            @{ Name = 'all failed'; Entries = @((New-Row -Result 'Failed' -Target 'C:\a' -ErrorText 'denied'), (New-Row -Result 'Failed' -Target 'C:\b' -ErrorText 'denied')); Log = $log; Msg = 'Add permission failed.'; Kind = 'Error'; Text = 'Add permission failed.' }
            @{ Name = 'log not written'; Entries = @(& $done); Log = $null; Msg = 'Added it. The change log could not be written.'; Kind = 'Warning'; Text = 'Done, with items to check: Added it. The change log could not be written.' }
            @{ Name = 'unrestorable items'; Entries = @((New-Row -Result 'Done' -OldValue 'Could not read')); Log = $log; Msg = 'Took ownership. 1 item cannot be restored.'; Kind = 'Warning'; Text = 'Done, with items to check: Took ownership. 1 item cannot be restored.' }
            @{ Name = 'tree partly done'; Entries = @((New-TreeRow -Result 'Partly done' -Counts @{ Unlisted = 2; UnlistedFolders = @('a', 'b') })); Log = $log; Msg = 'Took ownership of C:\x and every subfolder and file that could be opened. Escalate: 2 folders could not be opened.'; Kind = 'Warning'; Text = 'Done, with items to check: Took ownership of C:\x and every subfolder and file that could be opened. Escalate: 2 folders could not be opened.' }
            @{ Name = 'tree partly done, message already says so'; Entries = @((New-TreeRow -Result 'Partly done' -Counts @{ NotOwned = 1 })); Log = $log; Msg = 'Partly done: took ownership but not on every item.'; Kind = 'Warning'; Text = 'Partly done: took ownership but not on every item.' }
            @{ Name = 'tree incomplete'; Entries = @((New-TreeRow -Result 'Done' -Counts @{ Unchecked = 2 })); Log = $log; Msg = 'Took ownership. 2 items could not be read after the change.'; Kind = 'Warning'; Text = 'Done, with items to check: Took ownership. 2 items could not be read after the change.' }
            @{ Name = 'tree failed'; Entries = @((New-TreeRow -Result 'Failed' -NewValue '' -ErrorText 'Nothing was changed.')); Log = $log; Msg = 'Could not take ownership.'; Kind = 'Error'; Text = 'Could not take ownership.' }
            @{ Name = 'nothing to copy'; Entries = @((New-Row -Result 'Skipped (nothing to copy)' -Action 'Copy permissions'), (New-Row -Result 'Skipped (nothing to copy)' -Action 'Copy permissions')); Log = $log; Msg = '2 folders already had these permissions and were not changed.'; Kind = 'Info'; Text = '2 folders already had these permissions and were not changed.' }
            @{ Name = 'done plus up-to-date target'; Entries = @((New-Row -Result 'Done' -Action 'Copy permissions'), (New-Row -Result 'Skipped (nothing to copy)' -Action 'Copy permissions')); Log = $log; Msg = 'Permissions copied to 1 of 2 folders.'; Kind = 'Success'; Text = 'Permissions copied to 1 of 2 folders.' }
            @{ Name = 'done plus not found'; Entries = @((New-Row -Result 'Done'), (New-Row -Result 'Skipped (not found)')); Log = $log; Msg = 'Added on 1 of 2 files. 1 not found and skipped.'; Kind = 'Warning'; Text = 'Partly done: Added on 1 of 2 files. 1 not found and skipped.' }
            @{ Name = 'dry run'; Entries = @((New-Row -Result 'Skipped (WhatIf)')); Log = $null; Msg = 'WhatIf: nothing was changed (1 folder would be).'; Kind = 'Info'; Text = 'WhatIf: nothing was changed (1 folder would be).' }
        )
        foreach ($c in $cases) {
            $s = Get-ChangeStatus -Entries $c.Entries -LogPath $c.Log -Message $c.Msg
            $s.Kind | Should -Be $c.Kind -Because $c.Name
            $s.Text | Should -BeExactly $c.Text -Because $c.Name
        }
    }

    It 'AC40_RefreshAfterChange' {
        $same = Get-RefreshPlan -Scope Folder -Path 'D:\Data\HR' -CurrentPath 'd:\data\hr\'
        $same.ReloadPermissions | Should -BeTrue
        $same.ReloadFiles | Should -BeTrue
        $same.RefreshTreeEntry | Should -BeTrue

        $other = Get-RefreshPlan -Scope Folder -Path 'D:\Data\HR' -CurrentPath 'D:\Data\Other'
        $other.ReloadPermissions | Should -BeFalse
        $other.ReloadFiles | Should -BeFalse
        $other.RefreshTreeEntry | Should -BeTrue

        $f = 'D:\Data\HR\a.txt', 'D:\Data\HR\b.txt', 'D:\Data\HR\c.txt'
        $files = Get-RefreshPlan -Scope Files -Path 'D:\Data\HR' -CurrentPath 'D:\Data\HR' -ChangedFiles $f -ShownFiles @($f[1])
        ($files.DropFileAcl -join '|') | Should -Be ($f -join '|')
        ($files.ReloadFileAcl -join '|') | Should -Be $f[1]
        $files.ReloadPermissions | Should -BeFalse
        $moved = Get-RefreshPlan -Scope Files -Path 'D:\Data\HR' -CurrentPath 'D:\Elsewhere' -ChangedFiles $f -ShownFiles @($f[1])
        @($moved.ReloadFileAcl).Count | Should -Be 0

        $inside = Get-RefreshPlan -Scope Tree -Path 'D:\Data' -CurrentPath 'D:\Data\HR\Sub'
        $inside.ReloadPermissions | Should -BeTrue
        $inside.ReloadFiles | Should -BeTrue
        $outside = Get-RefreshPlan -Scope Tree -Path 'D:\Data' -CurrentPath 'D:\Database'
        $outside.ReloadPermissions | Should -BeFalse
        $outside.RefreshTreeEntry | Should -BeTrue

        $script:FileAclCache = @{ $f[0] = 1; $f[1] = 2; $f[2] = 3 }
        Remove-CachedFileAcl -Path @($f[0], $f[1])
        @($script:FileAclCache.Keys) | Should -Be @($f[2])
    }

    It 'AC41_CloseWhileChanging' {
        $script:ChangeTask = [PSCustomObject]@{ Action = 'Taking ownership'; Path = 'D:\Data\HR' }
        $r = @(Test-CanClose)
        $r[$r.Count - 1] | Should -BeFalse
        $script:Shown | Should -Contain 'A permission change is still running on D:\Data\HR. Wait for it to finish: closing now could leave it half done.'

        # Only reads running: closing is fine, and nothing is said.
        $script:ChangeTask = $null
        $script:Shown.Clear()
        $script:BgTasks = [System.Collections.Generic.List[object]]::new()
        $script:BgTasks.Add((New-FakeTask -Kind 'Read'))
        $r2 = @(Test-CanClose)
        $r2[$r2.Count - 1] | Should -BeTrue
        $script:Shown.Count | Should -Be 0
    }
}

Describe 'WhatIf and docs (AC44-AC46)' {
    BeforeEach {
        $script:WhatIfMode = $true
        Mock Start-ReadTask { & $OnDone ([PSCustomObject]@{ Ok = $true; Path = $Path; Folders = 1; Files = 1; Error = $null }) $State }
        $script:AllowBackstop = $false
    }

    It 'AC44_WhatIfEndToEnd' {
        $dir = New-Folder 'WhatIfDir'
        $sub = New-Folder 'WhatIfDir\Sub'
        $f1 = New-File $dir 'a.txt'; $f2 = New-File $dir 'b.txt'
        $dest1 = New-Folder 'Dest1'; $dest2 = New-Folder 'Dest2'
        $script:Current = [PSCustomObject]@{ DisplayPath = $dir; RealPath = $dir }
        $script:SelectedRows = @([PSCustomObject]@{ Path = $f1 }, [PSCustomObject]@{ Path = $f2 })
        $rule = New-Rule -Sid 'S-1-5-32-545' -Rights 'Modify'
        $script:SourceDir = $dir
        $script:SrcAcl = New-FakeAcl -Rule @($rule)
        Mock Get-Acl { if ("$LiteralPath" -eq $script:SourceDir) { $script:SrcAcl } else { New-FakeAcl } }

        $actions = [ordered]@{
            'add folder'       = { Invoke-AddPermission -Scope Folder -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' }
            'remove folder'    = { Invoke-RemovePermission -Scope Folder -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' }
            'add files'        = { Invoke-AddPermission -Scope Files -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' }
            'remove files'     = { Invoke-RemovePermission -Scope Files -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' }
            'ownership folder' = { Invoke-TakeOwnership -Scope Folder }
            'ownership files'  = { Invoke-TakeOwnership -Scope Files }
            'ownership tree'   = { Invoke-TakeOwnership -Scope Tree }
            'copy'             = { Invoke-CopyPermissions -TargetText "$dest1`n$dest2" }
        }
        foreach ($name in $actions.Keys) {
            $script:Captured = $null; $script:Status.Clear()
            & $actions[$name]
            $r = Complete-Captured
            $r.Message | Should -BeLike 'WhatIf: nothing was changed*' -Because $name
            (Get-LastStatus).Kind | Should -Be 'Info' -Because $name
        }
        Should -Invoke Set-Acl -Times 0 -Exactly
        Should -Invoke Invoke-AclTool -Times 0 -Exactly
        @($script:BackstopHit).Count | Should -Be 0
    }

    It 'AC45_Docs' {
        $readme = Get-Content -LiteralPath (Join-Path $script:Root 'README.md') -Raw
        # Booleans, not the text, so a failure does not print the whole README.
        ($readme -match 'View only in this version') | Should -BeFalse -Because 'the app can change things now'
        ($readme -match 'FolderPermissionManager-GUI\.ps1') | Should -BeTrue
        ($readme -match '(?i)UAC') | Should -BeTrue -Because 'admin and UAC relaunch'
        ($readme -match '(?i)one window per log folder') | Should -BeTrue
        ($readme -match '-LogFolder') | Should -BeTrue
        ($readme -match '-WhatIf') | Should -BeTrue
        ($readme -match '(?i)change log') | Should -BeTrue -Because 'where changes are logged'
        ($readme -match '(?i)kept (only )?until the Windows app (above )?(has been|is) lab-tested') | Should -BeTrue
        $rootReadme = Get-Content -LiteralPath $script:RootReadme -Raw
        $row = @($rootReadme -split "`n" | Where-Object { $_ -match '^\|\s*\[FolderPermissionManager\]' })
        $row.Count | Should -Be 1
        ($row[0] -match 'Browser GUI') | Should -BeFalse -Because 'the index row describes the Windows app'
    }

    It 'AC45_NoViewOnlyBannerInWindow' {
        ((Get-MainWindowXaml) -match 'View only in this version') | Should -BeFalse
    }

    It 'AC46_NoRobocopy' {
        $calls = @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                Where-Object { $_.Extent.Text -match '(?i)robocopy' })
        $calls.Count | Should -Be 0 -Because 'the app has no robocopy call'
        ((Get-Content -LiteralPath $script:AppPath -Raw) -match 'Copy Files To') | Should -BeFalse
        ((Get-MainWindowXaml) -match '(?i)robocopy tab|Copy Files To') | Should -BeFalse
        ((Get-Content -LiteralPath (Join-Path $script:Root 'README.md') -Raw) -match 'RobocopyMigration') | Should -BeTrue
    }
}

Describe 'SQ-017 review notes: target classification' {
    It 'SQ018N_Classification_VolumeAndSystemShares' {
        $refused = @(
            @{ P = '\\fs01\D$'; M = '(?i)root of drive' }
            @{ P = '\\fs01\c$\'; M = '(?i)root of drive' }
            @{ P = '\\fs01\ADMIN$\Temp'; M = 'ADMIN' }
            @{ P = '\\fs01\SYSVOL\contoso.com'; M = 'SYSVOL' }
            @{ P = '\\fs01\NETLOGON'; M = 'NETLOGON' }
            @{ P = '\\fs01\print$\x64'; M = '(?i)print\$' }
            @{ P = '\\fs01\IPC$'; M = 'IPC' }
        )
        foreach ($c in $refused) {
            $t = Get-ChangeTarget -Path $c.P -WholeTree
            $t.Ok | Should -BeFalse -Because $c.P
            $t.Refusal | Should -Match $c.M -Because $c.P
        }
        foreach ($p in '\\fs01\Data\HR', '\\fs01\Users$', '\\fs01\Data') {
            (Get-ChangeTarget -Path $p -WholeTree).Ok | Should -BeTrue -Because "$p is an ordinary share"
        }
    }

    It 'SQ018N_Classification_LoopbackNamesAreLocal' {
        foreach ($p in '\\localhost\C$\Windows\System32', '\\127.0.0.1\D$', '\\0-0-0-0-0-0-0-1.ipv6-literal.net\C$\Windows', '\\testpc.contoso.com\C$\ProgramData\Vendor', '\\TESTPC\C$\Windows') {
            $t = Get-ChangeTarget -Path $p -WholeTree
            $t.Ok | Should -BeFalse -Because $p
            $t.IsLocal | Should -BeTrue -Because "$p is this computer"
        }
        $ok = Get-ChangeTarget -Path '\\testpc\C$\Users\bob' -WholeTree
        $ok.Ok | Should -BeTrue
        $ok.IsLocal | Should -BeTrue
        $ok.ResolvedPath | Should -Be 'C:\Users\bob' -Because 'a loopback administrative share is the local folder'
        $remote = Get-ChangeTarget -Path '\\fs01\C$\Users\bob' -WholeTree
        $remote.IsLocal | Should -BeFalse
        $remote.ResolvedPath | Should -Be '\\fs01\C$\Users\bob'
        Should -Invoke Get-AppDfsTarget -Times 0 -ParameterFilter { $Path -like '\\testpc*' -or $Path -like '\\localhost*' -or $Path -like '\\127.*' } -Because 'no folder on these paths is a DFS reparse point (SQ018R1_ThisComputerAsDfsNamespaceServer covers one that is)'
    }

    It 'SQ018N_Dfs_ResolvedThroughTheSeamOrFailsClosed' {
        Mock Get-AppDfsTarget { '\\fs01\Data\HR' } -ParameterFilter { $Path -eq '\\contoso.com\dfs\hr' }
        $t = Get-ChangeTarget -Path '\\contoso.com\dfs\hr'
        $t.Ok | Should -BeTrue
        $t.DisplayPath | Should -Be '\\contoso.com\dfs\hr'
        $t.ResolvedPath | Should -Be '\\fs01\Data\HR'

        # D-036 runs on the resolved path, and the refusal names it.
        Mock Get-AppDfsTarget { '\\fs01\C$\Windows' } -ParameterFilter { $Path -eq '\\contoso.com\dfs\evil' }
        $bad = Get-ChangeTarget -Path '\\contoso.com\dfs\evil' -WholeTree
        $bad.Ok | Should -BeFalse
        $bad.Refusal | Should -Match ([regex]::Escape('\\fs01\C$\Windows'))

        # A lookup that fails is a refusal, for any change.
        Mock Get-AppDfsTarget { throw 'The DFS service did not answer.' } -ParameterFilter { $Path -eq '\\contoso.com\dfs\broken' }
        foreach ($whole in $false, $true) {
            $a = @{ Path = '\\contoso.com\dfs\broken'; WholeTree = $whole }
            $f = Get-ChangeTarget @a
            $f.Ok | Should -BeFalse
            $f.Refusal | Should -Match 'DFS'
        }
        $script:Current = [PSCustomObject]@{ DisplayPath = '\\contoso.com\dfs\broken'; RealPath = '\\contoso.com\dfs\broken' }
        Invoke-AddPermission -Scope Folder -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow'
        Should -Invoke Start-ChangeTask -Times 0 -Exactly
        @(Get-AllShownText | Where-Object { $_ -match 'DFS' }).Count | Should -BeGreaterThan 0

        # Local paths never ask DFS.
        $null = Get-ChangeTarget -Path 'C:\Data\HR'
        Should -Invoke Get-AppDfsTarget -Times 0 -Exactly -ParameterFilter { $Path -like 'C:*' }
    }

    It 'SQ018N_D036RunsOnTheResolvedPathNotTheDisplayPath' {
        Mock Start-ReadTask { }
        # H: is a live mapping of the C$ share on fs01: "H:\Windows" is fs01's Windows folder.
        $script:MappedDrives = @{ H = '\\fs01\C$' }
        $script:MappedDriveSources = @{ H = 'Live' }
        $script:Current = [PSCustomObject]@{ DisplayPath = 'H:\Windows'; RealPath = '\\fs01\C$\Windows' }
        Invoke-TakeOwnership -Scope Tree
        Should -Invoke Start-ReadTask -Times 0 -Exactly
        Should -Invoke Show-ConfirmDialog -Times 0 -Exactly
        Should -Invoke Start-ChangeTask -Times 0 -Exactly
        @(Get-AllShownText | Where-Object { $_ -match [regex]::Escape('\\fs01\C$\Windows') }).Count | Should -BeGreaterThan 0
    }

    It 'SQ018N_ConfirmShowsTheRealLocation' {
        $t = Get-ChangeTarget -Path 'H:\Data' -DriveMap @{ H = '\\fs01\home' } -DriveMapSource @{ H = 'Live' }
        $t.DisplayPath | Should -Be 'H:\Data'
        $t.ResolvedPath | Should -Be '\\fs01\home\Data'
        $spec = Get-ConfirmSpec -Action TakeOwnershipFolder -Targets @($t)
        $spec.Body | Should -Match ([regex]::Escape('H:\Data'))
        $spec.Body | Should -Match ([regex]::Escape('\\fs01\home\Data'))
    }

    It 'SQ018N_AlternateDataStreamsRefused' {
        foreach ($p in 'C:\Data\a.txt:secret', '\\fs01\share\a.txt:s', '\\fs01\share\dir:$I30:$INDEX_ALLOCATION', 'D:\Data\folder::$DATA') {
            $t = Get-ChangeTarget -Path $p
            $t.Ok | Should -BeFalse -Because $p
            $t.Refusal | Should -Match '(?i)stream' -Because $p
        }
        $t2 = Get-ChangeTarget -Path 'H:\a.txt:s' -DriveMap @{ H = '\\fs01\home' } -DriveMapSource @{ H = 'Live' }
        $t2.Ok | Should -BeFalse
        foreach ($p in 'C:\Data', 'C:\', '\\fs01\share', '\\fs01\share\dir') {
            (Get-ChangeTarget -Path $p).Ok | Should -BeTrue -Because "$p has no stream"
        }

        # The actions refuse too, before any task.
        $script:Current = [PSCustomObject]@{ DisplayPath = 'D:\Data\x:hidden'; RealPath = 'D:\Data\x:hidden' }
        Invoke-AddPermission -Scope Folder -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow'
        $script:SelectedRows = @([PSCustomObject]@{ Path = 'D:\Data\a.txt:s' })
        Invoke-TakeOwnership -Scope Files
        Should -Invoke Start-ChangeTask -Times 0 -Exactly
    }
}

Describe 'SQ-017 review notes: remembered mappings' {
    It 'SQ018N_RememberedMappingWarnsInConfirm' {
        $live = Get-ChangeTarget -Path 'H:\Data' -DriveMap @{ H = '\\fs01\home' } -DriveMapSource @{ H = 'Live' }
        $live.IsRemembered | Should -BeFalse
        $rem = Get-ChangeTarget -Path 'H:\Data' -DriveMap @{ H = '\\fs01\home' } -DriveMapSource @{ H = 'Remembered' }
        $rem.IsRemembered | Should -BeTrue
        (Get-ConfirmSpec -Action TakeOwnershipFolder -Targets @($rem)).Body | Should -Match '(?i)remembered'
        (Get-ConfirmSpec -Action AddPermission -Targets @($rem) -Detail 'Allow Modify for X').Body | Should -Match '(?i)remembered'
        (Get-ConfirmSpec -Action TakeOwnershipFolder -Targets @($live)).Body | Should -Not -Match '(?i)remembered'

        # Even Add Permission, which normally needs no extra confirm, asks when the letter is remembered.
        $script:MappedDrives = @{ H = '\\fs01\home' }
        $script:Current = [PSCustomObject]@{ DisplayPath = 'H:\Data'; RealPath = '\\fs01\home\Data' }
        $script:MappedDriveSources = @{ H = 'Remembered' }
        $script:ConfirmAnswer = $false
        Invoke-AddPermission -Scope Folder -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow'
        Should -Invoke Show-ConfirmDialog -Times 1 -Exactly
        $script:Confirms[0].Body | Should -Match '(?i)remembered'
        Should -Invoke Start-ChangeTask -Times 0 -Exactly -Because 'the tech said no'
        $script:ConfirmAnswer = $true
        Invoke-AddPermission -Scope Folder -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow'
        Should -Invoke Start-ChangeTask -Times 1 -Exactly

        # A live mapping needs no extra confirm for Add Permission.
        $script:Confirms.Clear()
        $script:MappedDriveSources = @{ H = 'Live' }
        Invoke-AddPermission -Scope Folder -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow'
        $script:Confirms.Count | Should -Be 0
    }

    It 'SQ018N_RememberedLogFolderGetsAWarning' {
        $notice = @(Get-LogFolderMappingNotice -LogFolder 'L:\Tickets\1' -DriveMap @{ L = '\\fs01\logs' } -DriveMapSource @{ L = 'Remembered' })
        $notice.Count | Should -Be 1
        $notice[0] | Should -Match '(?i)remembered'
        @(Get-LogFolderMappingNotice -LogFolder 'L:\Tickets\1' -DriveMap @{ L = '\\fs01\logs' } -DriveMapSource @{ L = 'Live' }).Count | Should -Be 0
        @(Get-LogFolderMappingNotice -LogFolder 'D:\Tickets\1' -DriveMap @{ L = '\\fs01\logs' } -DriveMapSource @{ L = 'Remembered' }).Count | Should -Be 0
        $rows = @(Get-LogFolderBanner -LogFolder 'L:\Tickets\1' -Notice $notice)
        @($rows | Where-Object { $_.Level -eq 'Warning' -and $_.Text -match '(?i)remembered' }).Count | Should -Be 1
        $main = (Get-Content -LiteralPath $script:AppPath -Raw)
        $main.Substring($main.IndexOf('#region Startup')) | Should -Match 'Get-LogFolderMappingNotice' -Because 'startup adds the notice to the banner'
    }

    It 'SQ018N_RememberedScriptPathIsHashChecked' {
        # A script started from a letter that only a remembered mapping explains is relaunched from
        # that mapping's \\server\share path. The file there must be the one running (SHA-256 of
        # both), or the administrator copy would run whatever a stale mapping now points at.
        # Get-RelaunchFileHash is the seam: it hashes a file, $null when it cannot be read.
        Mock Start-Process { }
        Mock Get-RelaunchFileHash { if ("$Path" -like '\\*') { $script:UncHash } else { 'A1B2C3' } }
        $map = @{ H = '\\fs01\tools' }
        $running = 'H:\FPM\FolderPermissionManager-GUI.ps1'
        $script:Unc = '\\fs01\tools\FPM\FolderPermissionManager-GUI.ps1'

        # The same file: the relaunch goes ahead.
        $script:UncHash = 'A1B2C3'
        Request-Elevation -ScriptPath $running -DriveMap $map -DriveMapSource @{ H = 'Remembered' } | Should -BeTrue
        Should -Invoke Start-Process -Times 1 -Exactly
        Should -Invoke Get-RelaunchFileHash -Times 1 -Exactly -ParameterFilter { $Path -eq $script:Unc }

        # A different file, or none there: refused with a plain message naming the path; nothing starts.
        foreach ($h in 'FFFF00', $null) {
            $script:Shown.Clear()
            $script:UncHash = $h
            Request-Elevation -ScriptPath $running -DriveMap $map -DriveMapSource @{ H = 'Remembered' } | Should -BeFalse -Because "the file at the remembered path differs ($h)"
            Should -Invoke Start-Process -Times 1 -Exactly
            @($script:Shown | Where-Object { $_ -match '(?i)remembered' -and $_.Contains($script:Unc) }).Count | Should -Be 1
        }

        # A live mapping is the drive the tech is using: no check.
        Request-Elevation -ScriptPath $running -DriveMap $map -DriveMapSource @{ H = 'Live' } | Should -BeTrue
        Should -Invoke Start-Process -Times 2 -Exactly
        Should -Invoke Get-RelaunchFileHash -Times 3 -Exactly -ParameterFilter { $Path -eq $script:Unc }
    }
}

Describe 'SQ-017 review notes: closing and fatal errors never stop a change' {
    BeforeEach {
        $script:Order = [System.Collections.Generic.List[string]]::new()
        $order = $script:Order
        $script:FakeMutex = [PSCustomObject]@{}
        $script:FakeMutex | Add-Member ScriptMethod ReleaseMutex { $order.Add('mutex-release') }.GetNewClosure()
        $script:FakeMutex | Add-Member ScriptMethod Dispose { }.GetNewClosure()
        $done = New-Object System.Threading.ManualResetEvent $true
        $script:FakePool = [PSCustomObject]@{}
        $script:FakePool | Add-Member ScriptMethod BeginClose { param($a, $b) $order.Add('pool-close'); [PSCustomObject]@{ AsyncWaitHandle = $done } }.GetNewClosure()
        $script:FakePool | Add-Member ScriptMethod Dispose { }.GetNewClosure()
        $script:Exits = [System.Collections.Generic.List[int]]::new()
    }

    It 'SQ018N_ShutdownLeavesARunningChangeAlone' {
        $exits = $script:Exits
        $exit = { param($c) $exits.Add($c) }.GetNewClosure()
        $running = New-FakeTask -Kind 'Change' -Completed $false
        $read = New-FakeTask -Kind 'Read' -Completed $false
        foreach ($code in 0, 1) {
            $script:Order.Clear(); $script:StoppedTasks.Clear(); $exits.Clear()
            $r = Invoke-AppShutdown -Pool $script:FakePool -Mutex $script:FakeMutex -Tasks @($read, $running) -WaitMilliseconds 50 -ExitWhenDone -ExitCode $code -ExitAction $exit
            $r.Deferred | Should -BeTrue -Because 'a change is still running'
            $script:Order | Should -Not -Contain 'mutex-release'
            $script:Order | Should -Not -Contain 'pool-close'
            $exits.Count | Should -Be 0 -Because "the process must not exit under a running change (exit code $code)"
            $script:StoppedTasks | Should -Not -Contain 'stop-Change' -Because 'a change task is never stopped'
        }
    }

    It 'SQ018N_MutexReleasedOnlyAfterChangesFinish' {
        $exits = $script:Exits
        $exit = { param($c) $exits.Add($c) }.GetNewClosure()
        $finished = New-FakeTask -Kind 'Change' -Completed $true
        $r = Invoke-AppShutdown -Pool $script:FakePool -Mutex $script:FakeMutex -Tasks @($finished) -WaitMilliseconds 50 -ExitAction $exit
        $r.Deferred | Should -Not -BeTrue
        $script:Order | Should -Contain 'mutex-release'
        $script:Order | Should -Contain 'pool-close'
        $script:Order.IndexOf('mutex-release') | Should -BeLessThan $script:Order.IndexOf('pool-close')
    }

    It 'SQ018N_WaitChangeTasks' {
        $h = [PSCustomObject]@{}
        $state = @{ N = 0 }
        $h | Add-Member ScriptProperty IsCompleted { $state.N++; $state.N -ge 3 }.GetNewClosure()
        $slow = [PSCustomObject]@{ Kind = 'Change'; PS = $null; Handle = $h }
        $readForever = New-FakeTask -Kind 'Read' -Completed $false
        Wait-ChangeTasks -Tasks @($slow, $readForever) -PollMilliseconds 10 -TimeoutMilliseconds 5000 | Should -BeTrue -Because 'reads never hold up the wait'
        $stuck = New-FakeTask -Kind 'Change' -Completed $false
        Wait-ChangeTasks -Tasks @($stuck) -PollMilliseconds 10 -TimeoutMilliseconds 100 | Should -BeFalse
        $script:StoppedTasks.Count | Should -Be 0 -Because 'waiting never stops the change'
    }

    It 'SQ018N_MainAndClosingHandlerWaitForChanges' {
        $code = Get-Content -LiteralPath $script:AppPath -Raw
        $main = $code.Substring($code.IndexOf('#region Main'))
        $main.IndexOf('Wait-ChangeTasks') | Should -BeGreaterOrEqual 0 -Because 'the fatal-error path waits for a running change'
        $main.IndexOf('Wait-ChangeTasks') | Should -BeLessThan $main.IndexOf('Invoke-AppShutdown')
        $closing = [regex]::Match($code, '(?s)\$win\.Add_Closing\(\{(.*?)\n\s*\}\)').Groups[1].Value
        $closing | Should -Match 'Change' -Because 'the handler must tell change tasks from reads before it stops anything'
        $closing.IndexOf('Test-CanClose') | Should -BeLessThan $closing.IndexOf('BeginStop')
    }
}

Describe 'SQ-017 review notes: -WhatIf, writes, pool, started row' {
    It 'SQ018N_WhatIfReachesEveryWrite' {
        $script:WriteNames = 'Add-FolderPermission', 'Remove-FolderPermission', 'Set-ItemOwnerToCurrentUser', 'Copy-FolderPermission'
        $calls = @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in $script:WriteNames }, $true))
        $calls.Count | Should -BeGreaterOrEqual 4
        foreach ($c in $calls) {
            $name = $c.GetCommandName()
            $wi = @($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'WhatIf' })
            $wi.Count | Should -Be 1 -Because "$name at line $($c.Extent.StartLineNumber) must pass -WhatIf"
            $wi[0].Argument | Should -Not -BeNullOrEmpty -Because 'a bare -WhatIf is not the launch value'
            $wi[0].Argument.Extent.Text | Should -Match '^\$' -Because 'the value is the passed-in mode'
            $wi[0].Argument.Extent.Text | Should -Not -BeIn @('$false', '$true')
            $cf = @($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'Confirm' })
            $cf.Count | Should -Be 1 -Because "$name must pass -Confirm:`$false (a worker has no host to prompt)"
            $cf[0].Argument.Extent.Text | Should -Be '$false'
        }
        # Each invoker hands the launch value on: $script:WhatIfMode is what ends up in the arguments.
        $dir = New-Folder 'WhatIfArg'
        $script:Current = [PSCustomObject]@{ DisplayPath = $dir; RealPath = $dir }
        foreach ($mode in $true, $false) {
            $script:WhatIfMode = $mode
            $script:Captured = $null
            Invoke-AddPermission -Scope Folder -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow'
            $bools = @($script:Captured.ArgumentList | Where-Object { $_ -is [bool] })
            $bools.Count | Should -Be 1 -Because 'WhatIf is the one [bool] argument of the work block'
            $bools[0] | Should -Be $mode
        }
    }

    It 'SQ018N_AppNeverWritesAclsItself' {
        $script:BadNames = 'Set-Acl', 'Invoke-AclTool', 'takeown', 'takeown.exe', 'icacls', 'icacls.exe'
        $calls = @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in $script:BadNames }, $true) |
                Where-Object { $_.Extent.Text -match '(?i)acl|takeown|icacls' })
        @($calls | ForEach-Object { $_.Extent.Text }) | Should -BeNullOrEmpty -Because 'writes happen only in the core'
    }

    It 'SQ018N_PoolRunBlocksNeverReachRealWrites' {
        $marker = Join-Path $TestDrive 'reached.txt'
        $stub = { param($n) "param([Parameter(ValueFromRemainingArguments)]`$a) Add-Content -LiteralPath '$marker' -Value '$n'; [PSCustomObject]@{ ExitCode = 0; Output = '' }" }
        $override = @{}
        foreach ($n in 'Set-Acl', 'Invoke-AclTool', 'takeown', 'icacls') { $override[$n] = & $stub $n }
        # PowerShell 7 pool runspaces do not load Get-Acl's type extensions, so Get-Acl(...).Sddl is empty
        # there and the core's backup check would fail every change. Windows PowerShell 5.1, which the
        # app runs under, does load them. Only this test (run under pwsh) swaps in an equivalent read.
        $override['Get-ItemSddl'] = 'param([string]$Path) try { (Get-Acl -LiteralPath $Path -ErrorAction Stop).GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All) } catch { ''Could not read'' }'
        $dir = New-Folder 'PoolDir'
        $script:Current = [PSCustomObject]@{ DisplayPath = $dir; RealPath = $dir }
        try {
            Initialize-BackgroundPool -FunctionOverride $override
            $run = {
                param($whatIf)
                $script:WhatIfMode = $whatIf
                $script:Captured = $null
                Invoke-AddPermission -Scope Folder -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow'
                $c = $script:Captured
                $c | Should -Not -BeNullOrEmpty
                $t = Start-BgTask -Work $c.Work -ArgumentList $c.ArgumentList -OnDone { } -State $null -Kind Change
                $t.Handle.AsyncWaitHandle.WaitOne(120000) | Should -BeTrue
                $out = @($t.PS.EndInvoke($t.Handle))
                $errs = @($t.PS.Streams.Error)
                $t.PS.Dispose()
                [PSCustomObject]@{ Out = $out; Errors = $errs }
            }
            # Positive control: with -WhatIf off, the pool run does reach the (stubbed) write layer,
            # so the stub works and the next assertion is not vacuous.
            $live = & $run $false
            $live.Errors.Count | Should -Be 0 -Because "$($live.Errors | Out-String)"
            $liveResult = Select-TaskResult -Output $live.Out
            $liveResult.Ok | Should -BeTrue -Because "$($liveResult.Error)"
            @($liveResult.Entries | ForEach-Object { $_.Result }) | Should -Be @('Done') -Because "$($liveResult.Message)"
            (Test-Path -LiteralPath $marker) | Should -BeTrue -Because 'the control run must reach the stubbed Set-Acl'
            Remove-Item -LiteralPath $marker -Force

            # With -WhatIf on, the pool run (WhatIfPreference starts false there) must reach nothing.
            $dry = & $run $true
            $dry.Errors.Count | Should -Be 0 -Because "$($dry.Errors | Out-String)"
            (Test-Path -LiteralPath $marker) | Should -BeFalse -Because 'a -WhatIf pool run reached Set-Acl, Invoke-AclTool, takeown or icacls'
            $result = Select-TaskResult -Output $dry.Out
            $result.Message | Should -BeLike 'WhatIf: nothing was changed*'
        }
        finally {
            if ($script:BgPool) { try { $script:BgPool.Close() } catch { } }
        }
    }

    It 'SQ018N_StartedRowIsLoggedBeforeTheChange' {
        $dir = New-Folder 'StartedDir'
        $other = New-Folder 'StartedDest'
        $script:SeenAtCall = [System.Collections.Generic.List[string]]::new()
        Mock Add-FolderPermission { $script:SeenAtCall.Add((Get-AllLogText)); New-Row -Action 'Add permission' -Target $Path[0] }
        Mock Remove-FolderPermission { $script:SeenAtCall.Add((Get-AllLogText)); New-Row -Action 'Remove permission' -Target $Path[0] }
        Mock Set-ItemOwnerToCurrentUser { $script:SeenAtCall.Add((Get-AllLogText)); New-TreeRow -Target $Path[0] }
        Mock Copy-FolderPermission { $script:SeenAtCall.Add((Get-AllLogText)); New-Row -Action 'Copy permissions' -Target $TargetPath[0] }
        $script:RunDir = $dir; $script:RunOther = $other
        $runs = @(
            { & $script:AddPermissionWork -Paths @($script:RunDir) -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' -LogFolder $script:ChangeLogFolder -WhatIf $false -CorePath $null }
            { & $script:RemovePermissionWork -Paths @($script:RunDir) -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' -LogFolder $script:ChangeLogFolder -WhatIf $false -CorePath $null }
            { & $script:TakeOwnershipWork -Paths @($script:RunDir) -Recurse $false -LogFolder $script:ChangeLogFolder -WhatIf $false -CorePath $null }
            { & $script:TakeOwnershipWork -Paths @($script:RunDir) -Recurse $true -LogFolder $script:ChangeLogFolder -WhatIf $false -CorePath $null }
            { & $script:CopyPermissionsWork -SourcePath $script:RunDir -TargetPaths @($script:RunOther) -LogFolder $script:ChangeLogFolder -WhatIf $false -CorePath $null }
        )
        $i = 0
        foreach ($run in $runs) {
            $i++
            # A fresh log folder per run, so an earlier run's Started row cannot satisfy this one.
            $script:ChangeLogFolder = Join-Path $TestDrive "started-log-$i"
            $script:SeenAtCall.Clear()
            $r = & $run
            $script:SeenAtCall.Count | Should -Be 1 -Because "run $i calls the core once"
            $script:SeenAtCall[0] | Should -Match 'Started' -Because "run $i must have logged a 'Started' row before the core change function ran"
            @($r.Entries | ForEach-Object { $_.Result }) | Should -Not -Contain 'Started'
        }
    }
}

# ---------------------------------------------------------------------------------------------
# SQ-018 review, round 1 (SQ018R1_*). Each Describe names the review item it covers.
# ---------------------------------------------------------------------------------------------

Describe 'Review 1-2: target lookups run in the background, real locations in the dialogs' {
    BeforeEach {
        # Every background read is captured, not run; the test runs its callback by hand.
        $script:Reads = [System.Collections.Generic.List[object]]::new()
        Mock Start-ReadTask { $script:Reads.Add(@{ Action = $Action; Path = $Path; Work = $Work; ArgumentList = $ArgumentList; OnDone = $OnDone; State = $State }) }
        $script:Dialogs = [System.Collections.Generic.List[object]]::new()
        $script:DialogAnswer = [PSCustomObject]@{ Identity = 'BUILTIN\Users'; Rights = 'Modify'; Type = 'Allow'; Sid = 'S-1-5-32-545' }
        Mock Show-PermissionDialog { $script:Dialogs.Add(@{ Mode = $Mode; Scope = $Scope; TargetText = $TargetText; Choices = $Choices }); $script:DialogAnswer }
        $script:CopyDialogs = [System.Collections.Generic.List[object]]::new()
        $script:CopyText = "\\fs01\A`n\\fs01\B"
        # The dialog opens again with what was typed after a refused folder (AC53d); that second
        # dialog is cancelled here.
        Mock Show-CopyPermissionsDialog { $script:CopyDialogs.Add(@{ Source = $Source }); if ($TypedText) { $null } else { $script:CopyText } }
        $script:MappedDrives = @{ H = '\\fs01\home' }
        $script:MappedDriveSources = @{ H = 'Live' }
        $script:Current = [PSCustomObject]@{ DisplayPath = 'H:\Data'; RealPath = '\\fs01\home\Data' }
        $script:ViewState.FolderPermissions = [PSCustomObject]@{ Ok = $true; Path = '\\fs01\home\Data'; Rows = @(
                [PSCustomObject]@{ Identity = 'BUILTIN\Users'; Sid = 'S-1-5-32-545'; Type = 'Allow'; IsInherited = $false; Rights = 'Modify, Synchronize' }) }
        $script:SelectedRows = @([PSCustomObject]@{ Path = '\\fs01\home\Data\a.txt' })
        $script:FileAclCache = @{ '\\fs01\home\Data\a.txt' = [PSCustomObject]@{ Ok = $true; Path = '\\fs01\home\Data\a.txt'; Rows = @(
                    [PSCustomObject]@{ Identity = 'BUILTIN\Users'; Sid = 'S-1-5-32-545'; Type = 'Allow'; IsInherited = $false; Rights = 'Modify' }) } }
        $script:FileAclPending = @{}
    }

    It 'SQ018R1_ClickHandlersStartALookupTask' {
        # No click may look up a target on the window's thread: each one starts a background read
        # of $script:ChangeTargetWork and calls none of the lookups itself.
        Mock Get-ChangeTarget { throw 'Get-ChangeTarget ran on the window thread' }
        Mock Resolve-ChangeTargetSet { throw 'Resolve-ChangeTargetSet ran on the window thread' }
        $clicks = [ordered]@{
            'add folder'       = { Open-AddPermission -Scope Folder }
            'add files'        = { Open-AddPermission -Scope Files }
            'remove folder'    = { Open-RemovePermission -Scope Folder }
            'remove files'     = { Open-RemovePermission -Scope Files }
            'ownership folder' = { Open-TakeOwnership -Scope Folder }
            'ownership files'  = { Open-TakeOwnership -Scope Files }
            'ownership tree'   = { Open-TakeOwnership -Scope Tree }
            'copy'             = { Open-CopyPermissions }
        }
        foreach ($name in $clicks.Keys) {
            $script:Reads.Clear(); $script:ChangePending = $null
            & $clicks[$name]
            $script:Reads.Count | Should -Be 1 -Because "$name starts one background read"
            $script:Reads[0].Work.ToString() | Should -Be $script:ChangeTargetWork.ToString() -Because "$name starts the target lookup"
            $script:Reads[0].Action | Should -Be 'Checking where'
            $script:ChangePending | Should -Not -BeNullOrEmpty -Because "$name is a pending change until the lookup and the dialog are done"
        }
        Should -Invoke Get-ChangeTarget -Times 0 -Exactly
        Should -Invoke Resolve-ChangeTargetSet -Times 0 -Exactly
        Should -Invoke Get-AppDfsTarget -Times 0 -Exactly
        Should -Invoke Get-ThisComputerNames -Times 0 -Exactly
        Should -Invoke Get-RemoteShareLocalPath -Times 0 -Exactly
        Should -Invoke Show-PermissionDialog -Times 0 -Exactly -Because 'the dialog opens only from the lookup callback'
        Should -Invoke Show-ConfirmDialog -Times 0 -Exactly

        # The buttons are wired to those Open-* functions only.
        $init = @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-PermissionWindow' }, $true))[0]
        foreach ($b in $script:ChangeButtons) {
            $wire = @($init.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Expression.Extent.Text -eq "`$ui.$b" -and $n.Member.Extent.Text -eq 'Add_Click' }, $true))
            $wire.Count | Should -Be 1 -Because "$b has one click handler"
            $called = @($wire[0].FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ -ne 'Invoke-UiAction' })
            $called.Count | Should -Be 1
            $called[0] | Should -BeLike 'Open-*' -Because "$b starts with a background lookup"
        }
    }

    It 'SQ018R1_StaleLookupOpensNoDialog' {
        # The tech opened another folder while the lookup ran: its result is dropped.
        Open-AddPermission -Scope Folder
        $script:Current = [PSCustomObject]@{ DisplayPath = 'H:\Other'; RealPath = '\\fs01\home\Other' }
        & $script:Reads[0].OnDone ([PSCustomObject]@{ Ok = $true; Targets = @(New-FakeTarget -Display 'H:\Data'); Refusal = $null }) $script:Reads[0].State
        $script:Dialogs.Count | Should -Be 0
        $script:Captured | Should -BeNullOrEmpty
        (Get-LastStatus).Text | Should -Match ([regex]::Escape('H:\Data'))
        (Get-LastStatus).Text | Should -Match '(?i)nothing was changed'
        $script:ChangePending | Should -BeNullOrEmpty
    }

    It 'SQ018R1_PoolHasEveryFunctionTheWorkCalls' {
        # Pool runspaces get only the core and $script:WorkHelperFunctions. Every app function that
        # a work block calls, directly or through another app function, must be in that list, or it
        # fails only at run time in the real window (Pester mocks do not reach the pool).
        $appFunctions = @{}
        foreach ($f in $script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { $appFunctions[$f.Name] = $f }
        $core = @(Get-CoreFunctionNames -CorePath $script:CorePath)
        $listed = @($script:WorkHelperFunctions)
        $called = { param($node) @($node.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique) }
        $work = @($script:Ast.FindAll({ param($n)
                    $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and "$($n.Left)" -match '^\$script:\w+Work$' }, $true))
        $work.Count | Should -BeGreaterThan 5
        $queue = [System.Collections.Generic.Queue[string]]::new()
        $seen = @{}
        foreach ($w in $work) { foreach ($c in & $called $w) { $queue.Enqueue($c) } }
        $missing = [System.Collections.Generic.List[string]]::new()
        while ($queue.Count -gt 0) {
            $name = $queue.Dequeue()
            if ($seen[$name]) { continue }
            $seen[$name] = $true
            if (-not $appFunctions.ContainsKey($name) -or $core -contains $name) { continue }
            if ($listed -notcontains $name) { $missing.Add($name) }
            foreach ($c in & $called $appFunctions[$name]) { $queue.Enqueue($c) }
        }
        @($missing) | Should -BeNullOrEmpty -Because 'these app functions run in the pool but are not copied there'
    }

    It 'SQ018R1_LookupWorkRunsInThePool' {
        # The lookup block and every helper it calls exist in the pool (read-only paths only).
        $dir = New-Folder 'LookupPool'
        try {
            # No real configuration of this computer is read: its names, its shares, its
            # directory entries, its profiles folder and its final paths are stubs in the pool.
            Initialize-BackgroundPool -FunctionOverride @{
                'Get-ThisComputerNames'    = "@('TESTPC', 'testpc.contoso.com')"
                'Get-LocalSharePath'       = "param([string]`$Name) throw 'no share in this test'"
                'Get-AppReparseInfo'       = "param([string]`$Path) [PSCustomObject]@{ Exists = `$true; IsReparsePoint = `$false; Tag = `$null }"
                'Get-AppProfilesDirectory' = "'C:\Users'"
                'Get-Win32PathName'        = "param([string]`$Path, [string]`$Kind) `$Path"
            }
            $loop = '\\' + 'local' + 'host\C$\Windows'
            $t = Start-BgTask -Work $script:ChangeTargetWork -ArgumentList @([string[]]@($dir), @{}, @{}, $false, $null, $null, $null) -OnDone { } -Kind Read
            $t.Handle.AsyncWaitHandle.WaitOne(60000) | Should -BeTrue
            $r = Select-TaskResult -Output @($t.PS.EndInvoke($t.Handle))
            @($t.PS.Streams.Error).Count | Should -Be 0 -Because "$($t.PS.Streams.Error | Out-String)"
            $t.PS.Dispose()
            $r.Ok | Should -BeTrue -Because "$($r.Refusal)"
            $r.Targets[0].ResolvedPath | Should -Be $dir

            $t2 = Start-BgTask -Work $script:ChangeTargetWork -ArgumentList @([string[]]@($loop), @{}, @{}, $true, $null, $null, $null) -OnDone { } -Kind Read
            $t2.Handle.AsyncWaitHandle.WaitOne(60000) | Should -BeTrue
            $r2 = Select-TaskResult -Output @($t2.PS.EndInvoke($t2.Handle))
            $t2.PS.Dispose()
            $r2.Ok | Should -BeFalse
            $r2.Refusal | Should -Match '(?i)Windows system folder' -Because 'this computer''s C$\Windows is its Windows folder'
        }
        finally {
            if ($script:BgPool) { try { $script:BgPool.Close() } catch { } }
        }
    }

    It 'SQ018R1_AddDialogShowsTheRealLocation' {
        Open-AddPermission -Scope Folder
        $script:Reads.Count | Should -Be 1
        $script:Reads[0].Path | Should -Be 'H:\Data really is'
        @($script:Status | Where-Object { $_.Text -like 'Checking where H:\Data really is*' }).Count | Should -Be 1
        $real = New-FakeTarget -Display 'H:\Data' -Resolved '\\fs02\real\Data'
        & $script:Reads[0].OnDone ([PSCustomObject]@{ Ok = $true; Targets = @($real); Refusal = $null }) $script:Reads[0].State
        $script:Dialogs.Count | Should -Be 1
        $script:Dialogs[0].TargetText | Should -Match ([regex]::Escape('Real location: \\fs02\real\Data'))
        $script:Captured | Should -Not -BeNullOrEmpty
        @($script:Captured.ArgumentList[0]) | Should -Be @('\\fs02\real\Data') -Because 'the change goes where the lookup said'
        $script:ChangePending | Should -BeNullOrEmpty -Because 'the dialog closed'

        # Files: one line per file, with its real location.
        $text = Get-DialogTargetText -Scope Files -Targets @((New-FakeTarget -Display 'H:\Data\a.txt' -Resolved '\\fs02\real\Data\a.txt'), (New-FakeTarget -Display 'C:\b.txt'))
        $text | Should -Match ([regex]::Escape('H:\Data\a.txt'))
        $text | Should -Match ([regex]::Escape('real location: \\fs02\real\Data\a.txt'))
        $text | Should -Match '2 files'

        # A lookup that refuses opens no dialog and says why, in the status line and a message box.
        $script:Reads.Clear(); $script:Dialogs.Clear(); $script:Shown.Clear()
        Open-AddPermission -Scope Folder
        & $script:Reads[0].OnDone ([PSCustomObject]@{ Ok = $false; Targets = @(); Refusal = 'H:\Data is refused for a test.' }) $script:Reads[0].State
        $script:Dialogs.Count | Should -Be 0
        $script:Shown | Should -Contain 'H:\Data is refused for a test.'
        (Get-LastStatus).Kind | Should -Be 'Error'
        $script:ChangePending | Should -BeNullOrEmpty
        # The task itself failing (no result) is said too.
        $script:Reads.Clear()
        Open-AddPermission -Scope Folder
        & $script:Reads[0].OnDone ([PSCustomObject]@{ Ok = $false; Stopped = $false; Error = 'pool broke' }) $script:Reads[0].State
        (Get-LastStatus).Text | Should -Match 'pool broke'
        $script:ChangePending | Should -BeNullOrEmpty
    }

    It 'SQ018R1_CopyShowsTheSourceAndResolvesTypedTargetsAfterTheDialog' {
        Open-CopyPermissions
        $source = New-FakeTarget -Display 'H:\Data' -Resolved '\\fs02\real\Data'
        & $script:Reads[0].OnDone ([PSCustomObject]@{ Ok = $true; Targets = @($source); Refusal = $null }) $script:Reads[0].State
        $script:CopyDialogs.Count | Should -Be 1
        $script:CopyDialogs[0].Source.ResolvedPath | Should -Be '\\fs02\real\Data' -Because 'the dialog shows the ResolvedPath the work uses'
        Get-CopyDialogSourceText -Source $source | Should -Match ([regex]::Escape('real location: \\fs02\real\Data'))

        # The typed folders are looked up after the dialog, in the background too.
        $script:Reads.Count | Should -Be 2
        $script:Reads[1].Work.ToString() | Should -Be $script:ChangeTargetWork.ToString()
        @($script:Reads[1].ArgumentList[0]) | Should -Be @('\\fs01\A', '\\fs01\B')
        $script:Captured | Should -BeNullOrEmpty -Because 'nothing starts before the typed folders are checked'

        # One cannot be resolved: refused, no task, still pending until now and then cleared.
        $state = $script:Reads[1].State
        & $script:Reads[1].OnDone ([PSCustomObject]@{ Ok = $false; Targets = @(); Refusal = 'Windows could not tell whether \\fs01\B is in a DFS namespace.' }) $state
        $script:Captured | Should -BeNullOrEmpty
        $script:Shown | Should -Contain 'Windows could not tell whether \\fs01\B is in a DFS namespace.'
        $script:ChangePending | Should -BeNullOrEmpty

        # All resolved: the change starts with the real paths, and the status line names them.
        $script:Reads.Clear()
        Open-CopyPermissions
        & $script:Reads[0].OnDone ([PSCustomObject]@{ Ok = $true; Targets = @($source); Refusal = $null }) $script:Reads[0].State
        $targets = @((New-FakeTarget -Display '\\fs01\A' -Resolved '\\fs03\A'), (New-FakeTarget -Display '\\fs01\B'))
        & $script:Reads[1].OnDone ([PSCustomObject]@{ Ok = $true; Targets = $targets; Refusal = $null }) $script:Reads[1].State
        $script:Captured | Should -Not -BeNullOrEmpty
        $script:Captured.ArgumentList[0] | Should -Be '\\fs02\real\Data'
        @($script:Captured.ArgumentList[1]) | Should -Be @('\\fs03\A', '\\fs01\B')
        (Get-LastStatus).Text | Should -Match ([regex]::Escape('\\fs01\A (real location: \\fs03\A)'))
        $script:ChangePending | Should -BeNullOrEmpty
    }
}

Describe 'Review 3: one pending change while counting and confirming' {
    It 'SQ018R1_DoubleClickStartsOneCountAndOneConfirm' {
        $folder = New-Folder 'Pending3'
        $script:Current = [PSCustomObject]@{ DisplayPath = $folder; RealPath = $folder }
        $script:Reads = [System.Collections.Generic.List[object]]::new()
        Mock Start-ReadTask { $script:Reads.Add(@{ Work = $Work; OnDone = $OnDone; State = $State }) }

        # Two clicks on the whole-tree button (the direct entry point): one count only.
        Invoke-TakeOwnership -Scope Tree
        Invoke-TakeOwnership -Scope Tree
        $script:Reads.Count | Should -Be 1 -Because 'the second click is refused while the first is pending'
        (Get-LastStatus).Kind | Should -Be 'Warning'
        (Get-LastStatus).Text | Should -Match ([regex]::Escape($folder))
        foreach ($b in $script:ChangeButtons) { $script:UI[$b].IsEnabled | Should -BeFalse -Because "$b is off while the count runs" }
        Test-ReadyForChange -Scope Folder | Should -BeFalse
        (Get-ChangeControlState).Reason | Should -Match '(?i)being prepared'

        # While the confirm is open, no other change can start, and no second confirm opens.
        Mock Show-ConfirmDialog {
            $script:Confirms.Add($Spec)
            Invoke-TakeOwnership -Scope Tree
            Open-AddPermission -Scope Folder
            Open-TakeOwnership -Scope Tree
            $true
        }
        & $script:Reads[0].OnDone ([PSCustomObject]@{ Ok = $true; Path = $folder; Folders = 3; Files = 4; NotOpened = 0; Links = 2; Error = $null }) $script:Reads[0].State
        $script:Confirms.Count | Should -Be 1
        $script:Reads.Count | Should -Be 1 -Because 'nothing new started while the confirm was open'
        Should -Invoke Start-ChangeTask -Times 1 -Exactly
        $script:Confirms[0].Body | Should -Match '2 junctions or symbolic links' -Because 'the count''s links are in the confirm'
        $script:ChangePending | Should -BeNullOrEmpty -Because 'the confirm closed'
        foreach ($b in $script:ChangeButtons) { $script:UI[$b].IsEnabled | Should -BeTrue }

        # Through the lookup (the window's buttons): two clicks, one lookup.
        $script:Reads.Clear()
        Open-TakeOwnership -Scope Tree
        Open-TakeOwnership -Scope Tree
        $script:Reads.Count | Should -Be 1
    }

    It 'SQ018R1_PendingClearedOnEveryExit' {
        $folder = New-Folder 'Pending3b'
        $script:Current = [PSCustomObject]@{ DisplayPath = $folder; RealPath = $folder }
        $script:Reads = [System.Collections.Generic.List[object]]::new()
        Mock Start-ReadTask { $script:Reads.Add(@{ OnDone = $OnDone; State = $State }) }
        $count = [PSCustomObject]@{ Ok = $true; Path = $folder; Folders = 1; Files = 1; NotOpened = 0; Links = 0; Error = $null }
        $cases = [ordered]@{
            'count failed'     = { & $script:Reads[0].OnDone ([PSCustomObject]@{ Ok = $false; Error = 'no count' }) $script:Reads[0].State }
            'confirm declined' = { $script:ConfirmAnswer = $false; & $script:Reads[0].OnDone $count $script:Reads[0].State }
            'confirm threw'    = { Mock Show-ConfirmDialog { throw 'dialog broke' }; try { & $script:Reads[0].OnDone $count $script:Reads[0].State } catch { } }
        }
        foreach ($name in $cases.Keys) {
            $script:Reads.Clear(); $script:ChangePending = $null; $script:ConfirmAnswer = $true
            Invoke-TakeOwnership -Scope Tree
            $script:ChangePending | Should -Not -BeNullOrEmpty
            & $cases[$name]
            $script:ChangePending | Should -BeNullOrEmpty -Because "$name ends the pending change"
            foreach ($b in $script:ChangeButtons) { $script:UI[$b].IsEnabled | Should -BeTrue -Because "$($name): $b is back" }
        }
        # The confirm says the count in its first line.
        $spec = Get-ConfirmSpec -Action TakeOwnershipTree -Targets @(New-FakeTarget -Display 'D:\Data') -Counts ([PSCustomObject]@{ Folders = 3201; Files = 9207; NotOpened = 0; Links = 0 })
        ($spec.Body -split "`n")[0] | Should -Be "This will change ownership on $((12408).ToString('N0')) items ($((3201).ToString('N0')) folders and $((9207).ToString('N0')) files) under:"
        $spec.Body | Should -Match 'ask a senior admin to open them'
        $spec.Body | Should -Not -Match 'escalate them'
    }
}

Describe 'Review 4: the remove dialog' {
    It 'SQ018R1_RemoveOffersExplicitEntriesBySid' {
        $script:ViewState.FolderPermissions = [PSCustomObject]@{ Ok = $true; Rows = @(
                [PSCustomObject]@{ Identity = 'BUILTIN\Users'; Sid = 'S-1-5-32-545'; Type = 'Allow'; IsInherited = $true; Rights = 'ReadAndExecute, Synchronize' },
                [PSCustomObject]@{ Identity = 'CONTOSO\HR'; Sid = 'S-1-5-21-1-2-3-1001'; Type = 'Deny'; IsInherited = $false; Rights = 'Write' },
                [PSCustomObject]@{ Identity = 'CONTOSO\Sales'; Sid = 'S-1-5-21-1-2-3-1002'; Type = 'Allow'; IsInherited = $false; Rights = 'Modify, Synchronize' },
                [PSCustomObject]@{ Identity = 'CONTOSO\Sales'; Sid = 'S-1-5-21-1-2-3-1002'; Type = 'Deny'; IsInherited = $false; Rights = 'Delete' },
                [PSCustomObject]@{ Identity = 'CONTOSO\sales-renamed'; Sid = 'S-1-5-21-1-2-3-1002'; Type = 'Allow'; IsInherited = $false; Rights = 'Read' }) }
        $c = Get-RemoveIdentityChoices -Scope Folder
        @($c.Choices).Count | Should -Be 2 -Because 'inherited-only identities are not offered, and one SID is one choice'
        $c.Identities | Should -Not -Contain 'BUILTIN\Users'
        $hr = @($c.Choices | Where-Object { $_.Sid -eq 'S-1-5-21-1-2-3-1001' })[0]
        $hr.Identity | Should -Be 'CONTOSO\HR'
        @($hr.Types) | Should -Be @('Deny')
        (Get-RemoveTypeChoice -Choice $hr).Default | Should -Be 'Deny' -Because 'Deny-only gives Deny'
        @((Get-RemoveTypeChoice -Choice $hr).Allowed) | Should -Be @('Deny')
        $hr.Rights['Deny'] | Should -Be 'Write'
        $sales = @($c.Choices | Where-Object { $_.Sid -eq 'S-1-5-21-1-2-3-1002' })[0]
        @($sales.Types) | Should -Be @('Allow', 'Deny')
        (Get-RemoveTypeChoice -Choice $sales).Default | Should -Be 'Allow'
        $sales.Rights['Allow'] | Should -Be 'Modify' -Because 'Synchronize is not a level of its own'
        $sales.Label | Should -Match 'Allow and Deny'

        # The confirm no longer says "(asked: ...)", and the dialog hides the level in Remove mode.
        $spec = Get-ConfirmSpec -Action RemovePermission -Targets @(New-FakeTarget -Display 'D:\Data') -Detail 'Deny Write for CONTOSO\HR'
        $spec.Body | Should -Not -Match 'asked'
        $spec.Body | Should -Match ([regex]::Escape('Remove all Deny permissions for CONTOSO\HR'))
        Get-XamlButton -Xaml (Get-PermissionDialogXaml) -Name 'PermRightsLabel' | Should -Not -BeNullOrEmpty
        $code = Get-Content -LiteralPath $script:AppPath -Raw
        $code | Should -Match ([regex]::Escape("`$dlg.FindName('PermRightsLabel').Visibility = 'Collapsed'"))
        $code | Should -Match ([regex]::Escape("`$dlg.FindName('PermRightsCombo').Visibility = 'Collapsed'"))

        # The SID goes to the work block (for the read-back); the core gets the name.
        $dir = New-Folder 'RemoveSid'
        $script:Current = [PSCustomObject]@{ DisplayPath = $dir; RealPath = $dir }
        Invoke-RemovePermission -Scope Folder -Identity 'CONTOSO\HR' -Rights 'Write' -Type 'Deny' -Sid 'S-1-5-21-1-2-3-1001'
        $script:Captured.ArgumentList[1] | Should -Be 'CONTOSO\HR'
        $script:Captured.ArgumentList | Should -Contain 'S-1-5-21-1-2-3-1001'
    }

    It 'SQ018R1_AclRowsCarrySidAndRights' {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetSecurityDescriptorSddlForm('O:BAG:SYD:(A;;FA;;;BU)(D;;0x1200a9;;;WD)')
        $rows = @((ConvertTo-AclViewModel -Acl $acl).Rows)
        $rows[0].Sid | Should -Be 'S-1-5-32-545'
        $rows[1].Sid | Should -Be 'S-1-1-0'
        $rows[0].Rights | Should -Match 'FullControl'
    }
}

Describe 'Review 5-7: log folder, relaunch, fatal error and close' {
    It 'SQ018R1_LogFolderInASyncedFolder' {
        $sync = New-Folder 'Profile\OneDrive - Contoso'
        $tools = New-Folder 'Profile\OneDrive - Contoso\Tools\FPM'
        $local = Join-Path $TestDrive 'LocalAppData'
        $scriptLogs = Join-Path $tools 'Logs'
        $default = Get-AppDefaultLogFolder -ScriptLogsFolder $scriptLogs -LocalAppData $local -SyncRoot @($sync)
        $default | Should -Be (Join-Path $local 'FolderPermissionManager\Logs')
        $notice = @(Get-SyncedLogFolderNotice -ScriptLogsFolder $scriptLogs -DefaultFolder $default -SyncRoot @($sync))
        $notice.Count | Should -Be 1
        $notice[0] | Should -Match ([regex]::Escape($default))

        $plain = Join-Path (New-Folder 'Tools2') 'Logs'
        Get-AppDefaultLogFolder -ScriptLogsFolder $plain -LocalAppData $local -SyncRoot @($sync) | Should -Be $plain
        @(Get-SyncedLogFolderNotice -ScriptLogsFolder $plain -DefaultFolder $plain -SyncRoot @($sync)).Count | Should -Be 0

        # An explicit -LogFolder inside a sync root is used as given, with a warning.
        $explicit = Join-Path $sync 'Tickets\1'
        $warn = @(Get-SyncedLogFolderNotice -LogFolder $explicit -ScriptLogsFolder $plain -DefaultFolder $plain -SyncRoot @($sync))
        $warn.Count | Should -Be 1
        $warn[0] | Should -Match '(?i)uploaded to the cloud'
        @(Get-SyncedLogFolderNotice -LogFolder (Join-Path $TestDrive 'Tickets') -ScriptLogsFolder $plain -DefaultFolder $plain -SyncRoot @($sync)).Count | Should -Be 0

        # Startup works the default out before Resolve-ChangeLogFolder and shows the notice.
        $code = Get-Content -LiteralPath $script:AppPath -Raw
        $startup = $code.Substring($code.IndexOf('#region Startup'))
        $startup.IndexOf('Get-AppDefaultLogFolder') | Should -BeGreaterThan 0
        $startup.IndexOf('Get-AppDefaultLogFolder') | Should -BeLessThan $startup.IndexOf('Resolve-ChangeLogFolder')
        $startup | Should -Match 'Get-SyncedLogFolderNotice'
    }

    It 'SQ018R1_RelaunchChecksEveryFileItLoads' {
        $map = @{ H = '\\fs01\tools' }
        $running = 'H:\FPM\FolderPermissionManager-GUI.ps1'
        $uncCore = '\\fs01\tools\FPM\FolderPermissions.Core.ps1'
        # Only the core differs: refused, naming the core.
        Mock Get-RelaunchFileHash { if ("$Path" -eq $uncCore) { 'DIFFERENT' } else { 'SAME' } }
        $p = Get-RelaunchScriptProblem -ScriptPath $running -DriveMap $map -DriveMapSource @{ H = 'Remembered' }
        $p | Should -Not -BeNullOrEmpty
        $p | Should -Match ([regex]::Escape($uncCore))
        # Both the same: allowed.
        Mock Get-RelaunchFileHash { 'SAME' }
        Get-RelaunchScriptProblem -ScriptPath $running -DriveMap $map -DriveMapSource @{ H = 'Remembered' } | Should -BeNullOrEmpty
        # A size that differs is refused without reading the files.
        $script:HashCalls = 0
        Mock Get-RelaunchFileHash { $script:HashCalls++; 'SAME' }
        Mock Get-RelaunchFileSize { if ("$Path" -like '\\*') { 200 } else { 100 } }
        Get-RelaunchScriptProblem -ScriptPath $running -DriveMap $map -DriveMapSource @{ H = 'Remembered' } | Should -Match '(?i)not the same file'
        $script:HashCalls | Should -Be 0 -Because 'a size mismatch is refused without reading the files'
        # .NOTES says the check connects to the remembered server.
        ($script:Ast.GetHelpContent().Notes) | Should -Match '(?i)connects to the server'
    }

    It 'SQ018R1_FatalErrorAndCloseFollowTheTaskState' {
        $m = Get-FatalErrorMessage -ErrorText 'boom' -ErrorLogPath 'C:\x\gui-errors.log' -ChangeLogFolder 'D:\Logs' -ChangeRunning $false -ChangeStarted $false
        $m | Should -Match 'Nothing was changed'
        foreach ($case in @(@{ R = $true; S = $true }, @{ R = $false; S = $true }, @{ R = $true; S = $false })) {
            $m2 = Get-FatalErrorMessage -ErrorText 'boom' -ErrorLogPath 'C:\x\gui-errors.log' -ChangeLogFolder 'D:\Logs' -ChangeRunning $case.R -ChangeStarted $case.S
            $m2 | Should -Not -Match 'Nothing was changed'
            $m2 | Should -Match ([regex]::Escape('check the change log in D:\Logs'))
        }
        (Get-FatalErrorMessage -ErrorText 'b' -ErrorLogPath 'l' -ChangeLogFolder 'D:\Logs' -ChangeRunning $true -ChangeStarted $true) | Should -Match 'A change may still be running or may have been made'
        $code = Get-Content -LiteralPath $script:AppPath -Raw
        $main = $code.Substring($code.IndexOf('#region Main'))
        $main | Should -Match 'Get-FatalErrorMessage'
        $main | Should -Match 'ChangeMadeThisSession'
        $main.IndexOf('Show-OwnConsole') | Should -BeGreaterThan 0 -Because 'the wait is visible'
        $main.IndexOf('Show-OwnConsole') | Should -BeLessThan $main.IndexOf('Wait-ChangeTasks')

        # A change started this session sets the flag.
        $script:ChangeMadeThisSession = $false
        Mock Start-BgTask { [PSCustomObject]@{ Kind = 'Change'; PS = $null; Handle = [PSCustomObject]@{ IsCompleted = $false } } }
        [void](& $script:RealStartChangeTask -Action 'Adding a permission on' -Path 'D:\Data' -Work { 'w' } -OnDone { param($r) })
        $script:ChangeMadeThisSession | Should -BeTrue

        # Closing follows the task's own state, not only that $script:ChangeTask is set.
        $script:ChangeTask = [PSCustomObject]@{ Action = 'x'; Path = 'D:\Data'; Task = (New-FakeTask -Kind 'Change' -Completed $true) }
        $script:BgTasks = [System.Collections.Generic.List[object]]::new()
        @(Test-CanClose)[-1] | Should -BeTrue -Because 'the change task has finished'
        $script:ChangeTask = [PSCustomObject]@{ Action = 'x'; Path = 'D:\Data'; Task = (New-FakeTask -Kind 'Change' -Completed $false) }
        @(Test-CanClose)[-1] | Should -BeFalse
        $script:ChangeTask = $null

        $readme = Get-Content -LiteralPath (Join-Path $script:Root 'README.md') -Raw
        ($readme -match '(?i)stuck') -and ($readme -match '(?i)mutex|single-instance lock|one window per log folder') | Should -BeTrue
    }
}

Describe 'Review 8: -WhatIf writes no change log' {
    It 'SQ018R1_WhatIfLeavesTheLogFolderAlone' {
        $script:LoggedCalls = 0
        Mock Invoke-LoggedPermissionChange { $script:LoggedCalls++; throw 'a -WhatIf run must not go through the change log' }
        $dir = New-Folder 'WhatIfNoLog'
        $dest = New-Folder 'WhatIfNoLogDest'
        $f = New-File $dir 'a.txt'
        $log = Join-Path $TestDrive 'whatif-log'
        $runs = [ordered]@{
            'add'       = { & $script:AddPermissionWork -Paths @($dir) -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' -LogFolder $log -WhatIf $true -CorePath $null }
            'remove'    = { & $script:RemovePermissionWork -Paths @($f) -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' -LogFolder $log -WhatIf $true -CorePath $null }
            'own'       = { & $script:TakeOwnershipWork -Paths @($dir) -Recurse $false -LogFolder $log -WhatIf $true -CorePath $null }
            'own tree'  = { & $script:TakeOwnershipWork -Paths @($dir) -Recurse $true -LogFolder $log -WhatIf $true -CorePath $null }
            'copy'      = { & $script:CopyPermissionsWork -SourcePath $dir -TargetPaths @($dest) -LogFolder $log -WhatIf $true -CorePath $null }
        }
        foreach ($name in $runs.Keys) {
            $r = & $runs[$name]
            $r.Ok | Should -BeTrue -Because "$name ($($r.Error))"
            $r.LogPath | Should -BeNullOrEmpty
            (Test-Path -LiteralPath $log) | Should -BeFalse -Because "$name under -WhatIf creates no log folder"
        }
        $script:LoggedCalls | Should -Be 0
        ($script:Ast.GetHelpContent().Examples -join "`n") | Should -Match 'Nothing is backed up or logged'
    }

    It 'SQ018R1_WhatIfPoolRunWritesNothing' {
        $marker = Join-Path $TestDrive 'whatif-reached.txt'
        $stub = { param($n) "param([Parameter(ValueFromRemainingArguments)]`$a) Add-Content -LiteralPath '$marker' -Value '$n'; [PSCustomObject]@{ ExitCode = 0; Output = '' }" }
        $override = @{}
        foreach ($n in 'Set-Acl', 'Invoke-AclTool', 'takeown', 'icacls') { $override[$n] = & $stub $n }
        # Records any change-log write instead of making it.
        $override['Write-PermissionChangeLog'] = "param(`$Entries, `$LogFolder) Add-Content -LiteralPath '$marker' -Value 'log'; `$null"
        # The whole-tree run checks the high-impact roots; the pool must not read this computer's
        # profiles folder either.
        $override['Get-AppProfilesDirectory'] = "'C:\Users'"
        $dir = New-Folder 'WhatIfPool'
        $dest = New-Folder 'WhatIfPoolDest'
        $log = Join-Path $TestDrive 'whatif-pool-log'
        try {
            Initialize-BackgroundPool -FunctionOverride $override
            $jobs = @(
                @{ W = $script:AddPermissionWork; A = @([string[]]@($dir), 'BUILTIN\Users', 'Modify', 'Allow', $log, $true, $null) }
                @{ W = $script:RemovePermissionWork; A = @([string[]]@($dir), 'BUILTIN\Users', 'Modify', 'Allow', $log, $true, '', $null) }
                @{ W = $script:TakeOwnershipWork; A = @([string[]]@($dir), $false, $log, $true, $null) }
                @{ W = $script:TakeOwnershipWork; A = @([string[]]@($dir), $true, $log, $true, $null) }
                @{ W = $script:CopyPermissionsWork; A = @($dir, [string[]]@($dest), $log, $true, $null) }
            )
            foreach ($j in $jobs) {
                $t = Start-BgTask -Work $j.W -ArgumentList $j.A -OnDone { } -Kind Change
                $t.Handle.AsyncWaitHandle.WaitOne(120000) | Should -BeTrue
                $r = Select-TaskResult -Output @($t.PS.EndInvoke($t.Handle))
                $t.PS.Dispose()
                $r.Ok | Should -BeTrue -Because "$($r.Error)"
            }
            (Test-Path -LiteralPath $marker) | Should -BeFalse -Because 'no write and no change-log write was reached'
            (Test-Path -LiteralPath $log) | Should -BeFalse
        }
        finally {
            if ($script:BgPool) { try { $script:BgPool.Close() } catch { } }
        }
    }
}

Describe 'Review 9: results are read back' {
    BeforeEach {
        $script:Dir9 = New-Folder ('ReadBack-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
        $script:Log9 = Join-Path $TestDrive ('rb-log-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
        function script:New-SddlAcl { param([string]$Sddl) $a = New-Object System.Security.AccessControl.DirectorySecurity; $a.SetSecurityDescriptorSddlForm($Sddl); $a }
    }

    It 'SQ018R1_AddReadBackFails' {
        Mock Add-FolderPermission { New-Row -Action 'Add permission' -Target $Path[0] -Detail "$Type $Rights for $Identity" }
        Mock Get-Acl { New-SddlAcl 'O:BAG:SYD:(A;OICI;FA;;;SY)' }
        $r = & $script:AddPermissionWork -Paths @($script:Dir9) -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' -LogFolder $script:Log9 -WhatIf $false -CorePath $null
        $r.Message | Should -Be (Get-ChangeResultMessage -Entries $r.Entries -LogPath $r.LogPath -LogFolder $script:Log9) -Because 'the core message is kept'
        $r.Entries[0].Result | Should -Be 'Done' -Because 'the core row is not rewritten'
        $r.Entries[0].CheckProblem | Should -Match '(?i)no explicit Allow'
        $s = Get-ChangeStatus -Entries $r.Entries -LogPath $r.LogPath -Message $r.Message
        $s.Kind | Should -Be 'Warning'
        $s.Text | Should -BeLike 'Done, with items to check: *'
        $s.Text | Should -Match ([regex]::Escape($script:Dir9))
        (Get-AllLogTextIn $script:Log9) | Should -Match 'Done, with items to check' -Because 'the failed check is logged too'

        # The entry is there: no problem.
        Mock Get-Acl { New-SddlAcl 'O:BAG:SYD:(A;OICI;0x1301bf;;;BU)' }
        $ok = & $script:AddPermissionWork -Paths @($script:Dir9) -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' -LogFolder $script:Log9 -WhatIf $false -CorePath $null
        $ok.Entries[0].PSObject.Properties['CheckProblem'] | Should -BeNullOrEmpty
        (Get-ChangeStatus -Entries $ok.Entries -LogPath $ok.LogPath -Message $ok.Message).Kind | Should -Be 'Success'
    }

    It 'SQ018R1_RemoveInheritedOnlyWrongTypeAndNoOp' {
        Mock Remove-FolderPermission { New-Row -Action 'Remove permission' -Target $Path[0] -Detail "$Type $Rights for $Identity" -OldValue 'D:SAME' -NewValue 'D:SAME' }
        $cases = @(
            @{ Name = 'inherited only'; Sddl = 'O:BAG:SYD:(A;OICIID;0x1301bf;;;BU)' }
            @{ Name = 'wrong type'; Sddl = 'O:BAG:SYD:(D;OICI;0x1301bf;;;BU)' }
        )
        foreach ($c in $cases) {
            $script:Sddl9 = $c.Sddl
            Mock Get-Acl { New-SddlAcl $script:Sddl9 }
            $r = & $script:RemovePermissionWork -Paths @($script:Dir9) -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' -LogFolder $script:Log9 -WhatIf $false -Sid 'S-1-5-32-545' -CorePath $null
            $s = Get-ChangeStatus -Entries $r.Entries -LogPath $r.LogPath -Message $r.Message
            $s.Kind | Should -Be 'Info' -Because $c.Name
            $s.Text | Should -BeLike 'Nothing was removed: BUILTIN\Users had no explicit Allow entry here.*' -Because $c.Name
        }
        # The same SDDL, yet the SID still has an explicit entry of that type: the name went elsewhere.
        Mock Get-Acl { New-SddlAcl 'O:BAG:SYD:(A;OICI;0x1301bf;;;BU)' }
        $r = & $script:RemovePermissionWork -Paths @($script:Dir9) -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' -LogFolder $script:Log9 -WhatIf $false -Sid 'S-1-5-32-545' -CorePath $null
        $r.Entries[0].CheckProblem | Should -Match '(?i)still has an explicit Allow'
        (Get-ChangeStatus -Entries $r.Entries -LogPath $r.LogPath -Message $r.Message).Kind | Should -Be 'Warning'

        # A real removal that left an explicit entry behind is not a success either.
        Mock Remove-FolderPermission { New-Row -Action 'Remove permission' -Target $Path[0] -Detail "$Type $Rights for $Identity" -OldValue 'D:OLD' -NewValue 'D:NEW' }
        $r2 = & $script:RemovePermissionWork -Paths @($script:Dir9) -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' -LogFolder $script:Log9 -WhatIf $false -Sid 'S-1-5-32-545' -CorePath $null
        (Get-ChangeStatus -Entries $r2.Entries -LogPath $r2.LogPath -Message $r2.Message).Text | Should -BeLike 'Done, with items to check: *'
    }

    It 'SQ018R1_OwnerAndCopyReadBack' {
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        Mock Set-ItemOwnerToCurrentUser { New-Row -Action 'Take ownership' -Target $Path[0] -Detail 'Owner set to me' }
        Mock Get-Acl { New-SddlAcl 'O:SYG:SYD:(A;OICI;FA;;;SY)' }
        $r = & $script:TakeOwnershipWork -Paths @($script:Dir9) -Recurse $false -LogFolder $script:Log9 -WhatIf $false -CorePath $null
        $r.Entries[0].CheckProblem | Should -Match '(?i)owner'
        $script:Me9 = $me
        Mock Get-Acl { New-SddlAcl "O:$($script:Me9)G:SYD:(A;OICI;FA;;;SY)" }
        $r = & $script:TakeOwnershipWork -Paths @($script:Dir9) -Recurse $false -LogFolder $script:Log9 -WhatIf $false -CorePath $null
        $r.Entries[0].PSObject.Properties['CheckProblem'] | Should -BeNullOrEmpty

        $dest = New-Folder ('ReadBackDest-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
        $script:Src9 = $script:Dir9
        Mock Copy-FolderPermission { foreach ($t in $TargetPath) { New-Row -Action 'Copy permissions' -Target $t -Detail "Copied from $($SourcePath): Allow Modify for BUILTIN\Users" } }
        Mock Get-Acl { if ("$LiteralPath" -eq $script:Src9) { New-SddlAcl 'O:BAG:SYD:(A;OICI;0x1301bf;;;BU)' } else { New-SddlAcl 'O:BAG:SYD:(A;OICI;FA;;;SY)' } }
        $c = & $script:CopyPermissionsWork -SourcePath $script:Dir9 -TargetPaths @($dest) -LogFolder $script:Log9 -WhatIf $false -CorePath $null
        $c.Entries[0].CheckProblem | Should -Match '(?i)not on it'
        Mock Get-Acl { New-SddlAcl 'O:BAG:SYD:(A;OICI;0x1301bf;;;BU)' }
        $c2 = & $script:CopyPermissionsWork -SourcePath $script:Dir9 -TargetPaths @($dest) -LogFolder $script:Log9 -WhatIf $false -CorePath $null
        $c2.Entries[0].PSObject.Properties['CheckProblem'] | Should -BeNullOrEmpty
    }
}

Describe 'Review 10-12: this computer as a DFS server, whole-tree guards, DFS with two targets' {
    It 'SQ018R1_ThisComputerAsDfsNamespaceServer' {
        # \\testpc\Public is a DFS namespace root shared from C:\DFSRoots\Public; Link is a DFS folder.
        Mock Get-LocalSharePath { 'C:\DFSRoots\Public' }
        Mock Get-AppReparseInfo { [PSCustomObject]@{ Exists = $true; IsReparsePoint = ($Path -eq 'C:\DFSRoots\Public\Link'); Tag = $(if ($Path -eq 'C:\DFSRoots\Public\Link') { [uint32]2147483658 } else { $null }) } }
        Mock Get-AppDfsTarget { '\\fs02\HR\Sub' } -ParameterFilter { $Path -eq '\\testpc\Public\Link\Sub' }
        $t = Get-ChangeTarget -Path '\\testpc\Public\Link\Sub'
        $t.Ok | Should -BeTrue
        $t.ResolvedPath | Should -Be '\\fs02\HR\Sub' -Because 'the DFS folder on this computer is looked up, not changed in place'
        Should -Invoke Get-AppDfsTarget -Times 1 -Exactly -ParameterFilter { $Path -eq '\\testpc\Public\Link\Sub' }

        # A folder on the namespace share that is not a DFS folder stays local and is not looked up.
        $plain = Get-ChangeTarget -Path '\\testpc\Public\Readme'
        $plain.ResolvedPath | Should -Be 'C:\DFSRoots\Public\Readme'
        $plain.IsLocal | Should -BeTrue

        # The lookup fails, or finds nothing, or finds two: refused.
        Mock Get-AppDfsTarget { throw 'DFS did not answer' } -ParameterFilter { $Path -eq '\\testpc\Public\Link\Sub' }
        (Get-ChangeTarget -Path '\\testpc\Public\Link\Sub').Refusal | Should -Match 'DFS'
        Mock Get-AppDfsTarget { } -ParameterFilter { $Path -eq '\\testpc\Public\Link\Sub' }
        $none = Get-ChangeTarget -Path '\\testpc\Public\Link\Sub'
        $none.Ok | Should -BeFalse
        $none.Refusal | Should -Match 'DFS'
        # The reparse point cannot be read: refused (fail closed).
        Mock Get-AppReparseInfo { throw 'Access is denied' }
        $unread = Get-ChangeTarget -Path '\\testpc\Public\Link\Sub'
        $unread.Ok | Should -BeFalse
        $unread.Refusal | Should -Match 'DFS'

        # The walk finds the DFS folder above the path, and stops below the drive root.
        Mock Get-AppReparseInfo { [PSCustomObject]@{ Exists = ($Path -ne 'C:\DFSRoots\Public\Link\HR\New'); IsReparsePoint = ($Path -eq 'C:\DFSRoots\Public\Link'); Tag = [uint32]2147483658 } }
        Find-DfsReparsePoint -Path 'C:\DFSRoots\Public\Link\HR\New' | Should -Be 'C:\DFSRoots\Public\Link'
        Should -Invoke Get-AppReparseInfo -Times 0 -ParameterFilter { $Path -eq 'C:\' -or $Path -eq 'C:' }
        # 2684354563 = 0xA0000003, IO_REPARSE_TAG_MOUNT_POINT (the hex literal is a negative Int32 in PowerShell).
        Mock Get-AppReparseInfo { [PSCustomObject]@{ Exists = $true; IsReparsePoint = $true; Tag = [uint32]2684354563 } }
        Find-DfsReparsePoint -Path 'C:\Data\Junction' | Should -BeNullOrEmpty -Because 'a junction is not a DFS folder'
    }

    It 'SQ018R1_ReparseInfoReadsTheDirectoryEntry' {
        # Real read, inside $TestDrive only.
        $dir = New-Folder 'ReparseReal'
        $i = & (Get-Command Get-AppReparseInfo -CommandType Function).ScriptBlock -Path $dir
        $i.Exists | Should -BeTrue
        $i.IsReparsePoint | Should -BeFalse
        $missing = & (Get-Command Get-AppReparseInfo -CommandType Function).ScriptBlock -Path (Join-Path $dir 'nope')
        $missing.Exists | Should -BeFalse
    }

    It 'SQ018R1_WholeTreeOnAShareChecksTheServerSidePath' {
        $cases = @(
            @{ Local = 'D:\'; Match = '(?i)root of drive' }
            @{ Local = 'C:\Windows'; Match = '(?i)Windows system folder' }
            @{ Local = 'C:\Users'; Match = '(?i)profile' }
            @{ Local = 'E:\Data\$RECYCLE.BIN'; Match = '(?i)Recycle Bin' }
        )
        foreach ($c in $cases) {
            $script:Local11 = $c.Local
            Mock Get-RemoteShareLocalPath { $script:Local11 }
            $t = Get-ChangeTarget -Path '\\fs01\Data' -WholeTree
            $t.Ok | Should -BeFalse -Because "the share is $($c.Local) on fs01"
            $t.Refusal | Should -Match $c.Match
            $t.Refusal | Should -Match ([regex]::Escape($c.Local))
        }
        Mock Get-RemoteShareLocalPath { 'D:\Shares\Data' }
        (Get-ChangeTarget -Path '\\fs01\Data\HR' -WholeTree).Ok | Should -BeTrue
        Should -Invoke Get-RemoteShareLocalPath -ParameterFilter { $Server -eq 'fs01' -and $Share -eq 'Data' }

        # It cannot be told: refused (fail closed).
        Mock Get-RemoteShareLocalPath { throw 'Access is denied' }
        $f = Get-ChangeTarget -Path '\\fs01\Data\HR' -WholeTree
        $f.Ok | Should -BeFalse
        $f.Refusal | Should -Match ([regex]::Escape('\\fs01\D$'))
        Mock Get-RemoteShareLocalPath { '\\?\Volume{1234}\Data' }
        (Get-ChangeTarget -Path '\\fs01\Data\HR' -WholeTree).Ok | Should -BeFalse

        # Only whole-tree changes ask, and never for an administrative share.
        $script:ShareCalls = 0
        Mock Get-RemoteShareLocalPath { $script:ShareCalls++; 'D:\Shares\Data' }
        $null = Get-ChangeTarget -Path '\\fs01\Data\HR'
        $null = Get-ChangeTarget -Path '\\fs01\E$\Data' -WholeTree
        $script:ShareCalls | Should -Be 0
    }

    It 'SQ018R1_WholeTreeRefusesHighImpactRoots' {
        foreach ($p in 'C:\Users', 'C:\Users\', '\\testpc\C$\Users', '\\fs01\C$\Users', '\\fs01\D$\Users', 'D:\System Volume Information', 'D:\System Volume Information\x', 'E:\$Recycle.Bin', '\\fs01\E$\$RECYCLE.BIN\S-1-5-21') {
            $t = Get-ChangeTarget -Path $p -WholeTree
            $t.Ok | Should -BeFalse -Because "$p is a high-impact root"
        }
        Mock Get-AppProfilesDirectory { 'E:\Profiles' }
        (Get-ChangeTarget -Path 'E:\Profiles' -WholeTree).Ok | Should -BeFalse -Because 'the ProfilesDirectory is refused wherever it is'
        (Get-ChangeTarget -Path 'E:\Profiles\bob' -WholeTree).Ok | Should -BeTrue -Because 'one profile folder is allowed'
        Mock Get-AppProfilesDirectory { 'C:\Users' }
        foreach ($p in 'C:\Users\bob', '\\testpc\C$\Users\bob', '\\fs01\C$\Users\bob', 'D:\Data\Users') {
            (Get-ChangeTarget -Path $p -WholeTree).Ok | Should -BeTrue -Because "$p is one profile or an ordinary folder"
        }
        # Only whole-tree changes are guarded this way.
        (Get-ChangeTarget -Path 'C:\Users').Ok | Should -BeTrue
    }

    It 'SQ018R1_DfsWithTwoTargetsIsRefused' {
        Mock Get-AppDfsTarget { '\\fs01\Data\HR'; '\\fs02\Data\HR' } -ParameterFilter { $Path -eq '\\contoso.com\dfs\hr' }
        $t = Get-ChangeTarget -Path '\\contoso.com\dfs\hr'
        $t.Ok | Should -BeFalse
        $t.Refusal | Should -Match ([regex]::Escape('\\fs01\Data\HR'))
        $t.Refusal | Should -Match ([regex]::Escape('\\fs02\Data\HR'))
        $t.Refusal | Should -Match 'a DFS folder that points to 2 servers'
        $script:Current = [PSCustomObject]@{ DisplayPath = '\\contoso.com\dfs\hr'; RealPath = '\\contoso.com\dfs\hr' }
        Invoke-AddPermission -Scope Folder -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow'
        Should -Invoke Start-ChangeTask -Times 0 -Exactly
        @($script:Shown | Where-Object { $_ -match '2 servers' }).Count | Should -Be 1 -Because 'the refusal is also a message box'
    }
}

Describe 'Review minors' {
    It 'SQ018R1_DefaultButtonsAndValidation' {
        (Get-XamlButton -Xaml (Get-PermissionDialogXaml) -Name 'PermSubmitBtn').GetAttribute('IsDefault') | Should -Be 'True'
        (Get-XamlButton -Xaml (Get-CopyPermissionsDialogXaml) -Name 'CopySubmitBtn').GetAttribute('IsDefault') | Should -Be 'True'
        (Get-XamlButton -Xaml (Get-ConfirmDialogXaml) -Name 'ConfirmActionBtn').GetAttribute('IsDefault') | Should -Not -Be 'True'
        $code = Get-Content -LiteralPath $script:AppPath -Raw
        $code | Should -Match ([regex]::Escape('$submit.IsDefault = $false')) -Because 'Remove is never the default button'
        $code | Should -Match 'Add_TextChanged' -Because 'a validation error clears when the tech types'

        Add-Type -AssemblyName PresentationCore, PresentationFramework, WindowsBase
        $set = [System.Collections.Generic.List[object]]::new()
        $fake = [PSCustomObject]@{}
        $fake | Add-Member ScriptMethod SetValue { param($dp, $value) $set.Add(@($dp, $value)) }.GetNewClosure()
        Enable-LiveRegion -Element $fake -Setting Assertive | Should -BeTrue
        "$($set[0][1])" | Should -Be 'Assertive'
    }

    It 'SQ018R1_RefusalsArePlainAndAlsoAMessageBox' {
        $t = Get-ChangeTarget -Path 'C:\Data\a.txt:secret'
        $t.Refusal | Should -Match ([regex]::Escape("contains a ':' after the drive, so it points at hidden data inside a file"))
        (Get-ChangeTarget -Path '\\fs01\share\a.txt:s').Refusal | Should -Match ([regex]::Escape("contains a ':' after the share name"))
        $script:Current = [PSCustomObject]@{ DisplayPath = 'D:\Data\x:hidden'; RealPath = 'D:\Data\x:hidden' }
        Invoke-TakeOwnership -Scope Folder
        @($script:Shown | Where-Object { $_ -match 'hidden data inside a file' }).Count | Should -Be 1
        (Get-LastStatus).Kind | Should -Be 'Error'
    }

    It 'SQ018R1_DisabledButtonsSayWhyAndBusyLineShowsTheChangeFirst' {
        $script:UI = @{}
        foreach ($b in $script:ChangeButtons) { $script:UI[$b] = [PSCustomObject]@{ IsEnabled = $true; ToolTip = "tip $b" } }
        $script:ChangeButtonTips = @{}
        $script:Current = $null
        Update-ChangeControls
        $script:UI['AddPermissionBtn'].IsEnabled | Should -BeFalse
        $script:UI['AddPermissionBtn'].ToolTip | Should -Be 'Choose a folder first.'
        $script:Current = [PSCustomObject]@{ DisplayPath = 'D:\Data'; RealPath = 'D:\Data' }
        $script:ChangeTask = [PSCustomObject]@{ Action = 'Taking ownership of'; Path = 'D:\Data\HR'; Key = 'k1' }
        Update-ChangeControls
        $script:UI['AddPermissionBtn'].ToolTip | Should -BeLike 'A change is running on D:\Data\HR*'
        $script:ChangeTask = $null
        Update-ChangeControls
        $script:UI['AddPermissionBtn'].IsEnabled | Should -BeTrue
        $script:UI['AddPermissionBtn'].ToolTip | Should -Be 'tip AddPermissionBtn' -Because 'the normal tooltip comes back'

        $entries = [ordered]@{
            k1 = [PSCustomObject]@{ Action = 'Taking ownership of'; Path = 'D:\Data\HR'; Started = [DateTime]::UtcNow }
            k2 = [PSCustomObject]@{ Action = 'Opening folder'; Path = 'D:\Other'; Started = [DateTime]::UtcNow }
        }
        (Get-BusyLineEntry -Entries $entries -ChangeKey 'k1').Path | Should -Be 'D:\Data\HR'
        (Get-BusyLineEntry -Entries $entries -ChangeKey $null).Path | Should -Be 'D:\Other' -Because 'without a change, the newest read'
    }

    It 'SQ018R1_FailedChangeRefreshesToo' {
        $script:Started = [System.Collections.Generic.List[object]]::new()
        Mock Start-BgTask { $script:Started.Add(@{ OnDone = $OnDone; State = $State }); [PSCustomObject]@{ Kind = 'Change'; PS = $null; Handle = [PSCustomObject]@{ IsCompleted = $false } } }
        Mock Invoke-ChangeRefresh { }
        $refresh = @{ Scope = 'Folder'; Paths = @('D:\Data'); ChangedFiles = @(); Node = $null }
        [void](& $script:RealStartChangeTask -Action 'Adding a permission on' -Path 'D:\Data' -Work { 'w' } -State $refresh -OnDone { param($r) })
        & $script:Started[0].OnDone ([PSCustomObject]@{ Ok = $false; Stopped = $false; Error = 'boom' }) $script:Started[0].State
        Should -Invoke Invoke-ChangeRefresh -Times 1 -Exactly
    }

    It 'SQ018R1_UnloggedRowsGoToAFallbackFile' {
        $old = $env:LOCALAPPDATA
        $env:LOCALAPPDATA = Join-Path $TestDrive 'la-unlogged'
        try {
            Mock Write-PermissionChangeLog { if (@($Entries)[0].Result -eq 'Started') { Join-Path $TestDrive 'started.csv' } else { $null } }
            Mock Add-FolderPermission { New-Row -Action 'Add permission' -Target $Path[0] -Detail "$Type $Rights for $Identity" }
            Mock Get-Acl { $a = New-Object System.Security.AccessControl.DirectorySecurity; $a.SetSecurityDescriptorSddlForm('O:BAG:SYD:(A;OICI;0x1301bf;;;BU)'); $a }
            $dir = New-Folder 'Unlogged'
            $r = & $script:AddPermissionWork -Paths @($dir) -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' -LogFolder (Join-Path $TestDrive 'nolog') -WhatIf $false -CorePath $null
            $r.LogPath | Should -BeNullOrEmpty
            $r.UnloggedPath | Should -BeLike (Join-Path $env:LOCALAPPDATA 'FolderPermissionManager\Logs\Unlogged_*.csv')
            (Test-Path -LiteralPath $r.UnloggedPath) | Should -BeTrue
            (Get-Content -LiteralPath $r.UnloggedPath -Raw) | Should -Match ([regex]::Escape($dir))
            Complete-ChangeTask -Result $r -State $null
            (Get-LastStatus).Text | Should -Match ([regex]::Escape($r.UnloggedPath))

            # Text Excel would run as a formula gets a leading quote in the fallback file too.
            $formula = Save-UnloggedChangeRows -Entries @(New-Row -Target '=1+1')
            (Get-Content -LiteralPath $formula -Raw) | Should -Match ([regex]::Escape('"''=1+1"'))
        }
        finally { $env:LOCALAPPDATA = $old }
    }

    It 'SQ018R1_ChangeStatusMatchesTheBrowser' {
        # Failed and nothing done is an error even when another item was already up to date.
        $s = Get-ChangeStatus -Entries @((New-Row -Result 'Failed' -ErrorText 'denied'), (New-Row -Result 'Skipped (nothing to copy)')) -LogPath 'C:\l.csv' -Message 'm'
        $s.Kind | Should -Be 'Error'
        # Every item not found is a warning, not an error.
        (Get-ChangeStatus -Entries @((New-Row -Result 'Skipped (not found)')) -LogPath 'C:\l.csv' -Message 'm').Kind | Should -Be 'Warning'
    }

    It 'SQ018R1_ThisComputerNameIPv6ScopeAndMappedLoopback' {
        Test-ThisComputerName -Name '0--ffff-7f00-1.ipv6-literal.net' | Should -BeTrue -Because '::ffff:127.0.0.1 is loopback'
        Test-ThisComputerName -Name '[::ffff:127.0.0.1]' | Should -BeTrue
        Mock Get-ThisComputerNames { @('TESTPC', 'fe80::1234%4', '10.0.0.5') }
        Test-ThisComputerName -Name 'fe80--1234s7.ipv6-literal.net' | Should -BeTrue -Because 'the scope ID does not change which address it is'
        Test-ThisComputerName -Name '0--ffff-a00-5.ipv6-literal.net' | Should -BeTrue -Because '::ffff:10.0.0.5 is this computer''s IPv4 address'
        Test-ThisComputerName -Name 'fe80--9999.ipv6-literal.net' | Should -BeFalse
        $code = Get-Content -LiteralPath $script:AppPath -Raw
        $code | Should -Match '(?i)DNS alias'
    }

    It 'SQ018R1_StaleCommentsAndReadme' {
        $code = Get-Content -LiteralPath $script:AppPath -Raw
        $code | Should -Not -Match '(?i)wired up in SQ-018'
        $readme = Get-Content -LiteralPath (Join-Path $script:Root 'README.md') -Raw
        $app = [regex]::Match($readme, '(?s)### FolderPermissionManager-GUI\.ps1 \(Windows app\)(.*?)\n### ').Groups[1].Value
        $app | Should -Match '`Started`'
        $app | Should -Match '(?i)orphan'
        $app | Should -Match ([regex]::Escape('%LOCALAPPDATA%\FolderPermissionManager\Logs'))
        $app | Should -Match 'Unlogged_'
        $app | Should -Match ([regex]::Escape('Done, with items to check'))
    }
}

Describe 'Review round 2: remove by the matched SID' {
    BeforeEach {
        $script:Dir12 = New-Folder ('RemoveSid2-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
        $script:Log12 = Join-Path $TestDrive ('rs-log-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
        $script:RemoveCalls = 0
        Mock Remove-FolderPermission { $script:RemoveCalls++; New-Row -Action 'Remove permission' -Target $Path[0] -Detail "$Type $Rights for $Identity" -OldValue 'D:OLD' -NewValue 'D:NEW' }
        Mock Get-Acl { $a = New-Object System.Security.AccessControl.DirectorySecurity; $a.SetSecurityDescriptorSddlForm('O:BAG:SYD:(A;OICI;FA;;;SY)'); $a }
        $script:LogWrites = 0
        Mock Write-PermissionChangeLog { $script:LogWrites++; Join-Path $TestDrive 'changes.csv' }
    }

    It 'SQ018R2_RemoveRefusedWhenTheNameNowMeansAnotherAccount' {
        Mock ConvertTo-IdentitySid { 'S-1-5-21-9-9-9-5000' }
        $r = & $script:RemovePermissionWork -Paths @($script:Dir12) -Identity 'CONTOSO\HR' -Rights 'Write' -Type 'Allow' -LogFolder $script:Log12 -WhatIf $false -Sid 'S-1-5-21-1-2-3-1001' -CorePath $null
        $r.Ok | Should -BeFalse
        $r.NotStarted | Should -BeTrue -Because 'nothing was changed, so the status must not say it may have been'
        $r.Error | Should -Match ([regex]::Escape('CONTOSO\HR now resolves to a different account than the entry you chose (for example after a domain migration or rename), so nothing was changed. Ask a senior admin.'))
        $script:RemoveCalls | Should -Be 0 -Because 'the core is not called'
        $script:LogWrites | Should -Be 0 -Because 'no Started row for a change that never starts'

        # The status line says it as it is, not "may or may not have been made".
        $script:Started = [System.Collections.Generic.List[object]]::new()
        Mock Start-BgTask { $script:Started.Add(@{ OnDone = $OnDone; State = $State }); [PSCustomObject]@{ Kind = 'Change'; PS = $null; Handle = [PSCustomObject]@{ IsCompleted = $false } } }
        [void](& $script:RealStartChangeTask -Action 'Removing a permission from' -Path $script:Dir12 -Work { 'w' } -OnDone { param($x) })
        & $script:Started[0].OnDone $r $script:Started[0].State
        (Get-LastStatus).Text | Should -Not -Match 'may or may not'
        (Get-LastStatus).Text | Should -Match 'nothing was changed'
    }

    It 'SQ018R2_RemoveRefusedForAnOrphanedSid' {
        $sid = 'S-1-5-21-1-2-3-1009'
        Mock ConvertTo-SidAccountName { $null }
        $r = & $script:RemovePermissionWork -Paths @($script:Dir12) -Identity $sid -Rights 'Modify' -Type 'Allow' -LogFolder $script:Log12 -WhatIf $false -Sid $sid -CorePath $null
        $r.Ok | Should -BeFalse
        $r.NotStarted | Should -BeTrue
        # Wording changed by AC53b (owner decision, review 2026-10-19).
        $r.Error | Should -Match ([regex]::Escape("Windows can't look up this account from here (it may be deleted, or local to the server): $sid. This tool can't remove entries for an account it can't look up; ask a senior admin"))
        $r.Error | Should -Match ([regex]::Escape("icacls `"$($script:Dir12)`" /remove:g *$sid"))
        $script:RemoveCalls | Should -Be 0

        # A name that no longer translates, for a SID that does not either: orphaned too (Deny: /remove:d).
        Mock ConvertTo-IdentitySid { $null }
        $r2 = & $script:RemovePermissionWork -Paths @($script:Dir12) -Identity 'CONTOSO\Gone' -Rights 'Write' -Type 'Deny' -LogFolder $script:Log12 -WhatIf $false -Sid $sid -CorePath $null
        $r2.Ok | Should -BeFalse
        $r2.Error | Should -Match ([regex]::Escape("icacls `"$($script:Dir12)`" /remove:d *$sid"))
        $script:RemoveCalls | Should -Be 0

        # The icacls syntax is cited from Learn next to the code.
        $code = Get-Content -LiteralPath $script:AppPath -Raw
        $code | Should -Match ([regex]::Escape('https://learn.microsoft.com/windows-server/administration/windows-commands/icacls'))
    }

    It 'SQ018R2_RemoveGoesAheadWhenTheNameStillMatches' {
        Mock ConvertTo-IdentitySid { 'S-1-5-21-1-2-3-1001' }
        $r = & $script:RemovePermissionWork -Paths @($script:Dir12) -Identity 'CONTOSO\HR' -Rights 'Write' -Type 'Allow' -LogFolder $script:Log12 -WhatIf $false -Sid 'S-1-5-21-1-2-3-1001' -CorePath $null
        $r.Ok | Should -BeTrue -Because "$($r.Error)"
        $script:RemoveCalls | Should -Be 1
    }
}

Describe 'Review round 2: high-impact roots on resolved paths' {
    It 'SQ018R2_JunctionToUsersIsRefused' {
        $dir = New-Folder 'LooksHarmless'
        $script:Dir13 = $dir
        Mock Get-Win32PathName { if ($Path -eq $script:Dir13) { '\\?\C:\Users' } else { $Path } }
        $t = Get-ChangeTarget -Path $dir -WholeTree
        $t.Ok | Should -BeFalse -Because 'the folder is a junction to C:\Users'
        $t.Refusal | Should -Match ([regex]::Escape('C:\Users'))
        $t.Refusal | Should -Match '(?i)profile'
        Should -Invoke Get-Win32PathName -ParameterFilter { $Kind -eq 'Final' -and $Path -eq $script:Dir13 }

        # D-036 on the resolved form too.
        Mock Get-Win32PathName { if ($Path -eq $script:Dir13) { '\\?\C:\Windows' } else { $Path } }
        (Get-ChangeTarget -Path $dir -WholeTree).Refusal | Should -Match '(?i)Windows system folder'

        # A final path that cannot be told is refused (fail closed).
        Mock Get-Win32PathName { $null }
        $f = Get-ChangeTarget -Path $dir -WholeTree
        $f.Ok | Should -BeFalse
        $f.Refusal | Should -Match '(?i)could not tell where'

        # Only whole-tree changes resolve.
        (Get-ChangeTarget -Path $dir).Ok | Should -BeTrue
    }

    It 'SQ018R2_ShortNameIsRefused' {
        Mock Get-AppProfilesDirectory { 'E:\UserProfiles' }
        Mock Get-Win32PathName { if ($Kind -eq 'Long' -and $Path -eq 'E:\USERPR~1') { 'E:\UserProfiles' } else { $Path } }
        $t = Get-ChangeTarget -Path 'E:\USERPR~1' -WholeTree
        $t.Ok | Should -BeFalse -Because 'E:\USERPR~1 is the 8.3 name of the profiles folder'
        $t.Refusal | Should -Match ([regex]::Escape('E:\UserProfiles'))
    }

    It 'SQ018R2_LinkInsideTheTreeToUsersIsRefusedBeforeTheConfirm' {
        $dir = New-Folder 'TreeWithLink'
        $link = New-Folder 'TreeWithLink\ToUsers'
        $script:Link14 = $link
        $script:Dir14 = $dir
        Mock Get-OwnerTreeItem { [PSCustomObject]@{ Items = @([PSCustomObject]@{ Path = $script:Dir14; ItemType = 'Folder' }, [PSCustomObject]@{ Path = $script:Link14; ItemType = 'Folder' }); Unlisted = @(); Links = @($script:Link14) } }
        Mock Get-Win32PathName { if ($Path -eq $script:Link14) { '\\?\C:\Users' } else { $Path } }
        $count = & $script:TreeCountWork -Path $dir -CorePath $null
        $count.Ok | Should -BeTrue
        $count.LinkRefusal | Should -Match ([regex]::Escape($link))
        $count.LinkRefusal | Should -Match '(?i)profile'

        $script:Current = [PSCustomObject]@{ DisplayPath = $dir; RealPath = $dir }
        Mock Start-ReadTask { $argList = @($ArgumentList); & $OnDone (& $Work @argList) $State }
        Invoke-TakeOwnership -Scope Tree
        Should -Invoke Show-ConfirmDialog -Times 0 -Exactly -Because 'the refusal comes before the confirm opens'
        Should -Invoke Start-ChangeTask -Times 0 -Exactly
        @($script:Shown | Where-Object { $_ -match [regex]::Escape($link) }).Count | Should -Be 1 -Because 'the refusal is a message box'
        $script:ChangePending | Should -BeNullOrEmpty

        # A link that cannot be resolved is refused too.
        Mock Get-Win32PathName { if ($Path -eq $script:Link14) { $null } else { $Path } }
        (& $script:TreeCountWork -Path $dir -CorePath $null).LinkRefusal | Should -Not -BeNullOrEmpty

        # A link to an ordinary folder: the confirm opens.
        Mock Get-Win32PathName { if ($Path -eq $script:Link14) { '\\?\D:\Data\Other' } else { $Path } }
        (& $script:TreeCountWork -Path $dir -CorePath $null).LinkRefusal | Should -BeNullOrEmpty
        Invoke-TakeOwnership -Scope Tree
        Should -Invoke Show-ConfirmDialog -Times 1 -Exactly
    }

    It 'SQ018R2_UsersOnAnyDriveIsRefusedLocallyAndRemotely' {
        foreach ($p in 'D:\Users', 'd:\users\', '\\fs01\D$\Users', '\\testpc\D$\Users', 'E:\Users') {
            $t = Get-ChangeTarget -Path $p -WholeTree
            $t.Ok | Should -BeFalse -Because "$p is a Users folder at the top of a drive"
            $t.Refusal | Should -Match '(?i)profile'
        }
        # A share whose folder on the server is D:\Users.
        Mock Get-RemoteShareLocalPath { 'D:\Users' }
        (Get-ChangeTarget -Path '\\fs01\Profiles' -WholeTree).Ok | Should -BeFalse
        Mock Get-RemoteShareLocalPath { "D:\Shares\$Share" }
        # A local folder whose final path is another server's Users folder.
        $dir = New-Folder 'ToRemoteUsers'
        $script:Dir15 = $dir
        Mock Get-Win32PathName { if ($Path -eq $script:Dir15) { '\\?\UNC\fs01\E$\Users' } else { $Path } }
        (Get-ChangeTarget -Path $dir -WholeTree).Ok | Should -BeFalse
        foreach ($p in 'D:\Users\bob', 'D:\Data\Users', '\\fs01\D$\Users\bob') {
            (Get-ChangeTarget -Path $p -WholeTree).Ok | Should -BeTrue -Because "$p is one profile or an ordinary folder"
        }
        $readme = Get-Content -LiteralPath (Join-Path $script:Root 'README.md') -Raw
        $readme | Should -Match '(?is)profiles folder on another server.{0,80}moved.{0,120}not\s+detected'
    }
}

Describe 'Review round 2: minors' {
    It 'SQ018R2_ReadBackRowsGoToTheFallbackFile' {
        $old = $env:LOCALAPPDATA
        $env:LOCALAPPDATA = Join-Path $TestDrive 'la-readback'
        try {
            Mock Write-PermissionChangeLog { if (@($Entries)[0].Result -eq 'Done, with items to check') { $null } else { Join-Path $TestDrive 'changes.csv' } }
            Mock Add-FolderPermission { New-Row -Action 'Add permission' -Target $Path[0] -Detail "$Type $Rights for $Identity" }
            Mock Get-Acl { $a = New-Object System.Security.AccessControl.DirectorySecurity; $a.SetSecurityDescriptorSddlForm('O:BAG:SYD:(A;OICI;FA;;;SY)'); $a }
            $dir = New-Folder 'ReadBackUnlogged'
            $r = & $script:AddPermissionWork -Paths @($dir) -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' -LogFolder (Join-Path $TestDrive 'rb-nolog') -WhatIf $false -CorePath $null
            $r.LogPath | Should -Not -BeNullOrEmpty
            $r.ReadBackUnlogged | Should -BeTrue
            $r.ReadBackUnloggedPath | Should -BeLike (Join-Path $env:LOCALAPPDATA 'FolderPermissionManager\Logs\Unlogged_*.csv')
            (Get-Content -LiteralPath $r.ReadBackUnloggedPath -Raw) | Should -Match 'Done, with items to check'
            Complete-ChangeTask -Result $r -State $null
            (Get-LastStatus).Text | Should -Match ([regex]::Escape($r.ReadBackUnloggedPath))
        }
        finally { $env:LOCALAPPDATA = $old }
    }

    It 'SQ018R2_SyncedLogFolderNoticeUsesTheFullPath' {
        $sync = New-Folder 'Profile2\OneDrive - Contoso'
        $plain = Join-Path (New-Folder 'Tools3') 'Logs'
        Push-Location -LiteralPath $sync
        try {
            $warn = @(Get-SyncedLogFolderNotice -LogFolder 'Tickets\2' -ScriptLogsFolder $plain -DefaultFolder $plain -SyncRoot @($sync))
        }
        finally { Pop-Location }
        $warn.Count | Should -Be 1 -Because 'a relative folder typed inside OneDrive is inside OneDrive'
        $warn[0] | Should -Match ([regex]::Escape((Join-Path $sync 'Tickets\2')))

        # The script's Logs folder is in a sync root and %LOCALAPPDATA% is not known: a warning.
        $synced = Join-Path (New-Folder 'Profile2\OneDrive - Contoso\Tools\FPM') 'Logs'
        $default = Get-AppDefaultLogFolder -ScriptLogsFolder $synced -LocalAppData '' -SyncRoot @($sync)
        $default | Should -Be $synced
        $n = @(Get-SyncedLogFolderNotice -ScriptLogsFolder $synced -DefaultFolder $default -SyncRoot @($sync))
        $n.Count | Should -Be 1
        $n[0] | Should -Match '(?i)LOCALAPPDATA'
        $n[0] | Should -Match '(?i)uploaded to the cloud'

        # Startup passes the resolved folder.
        $code = Get-Content -LiteralPath $script:AppPath -Raw
        $startup = $code.Substring($code.IndexOf('#region Startup'))
        $startup | Should -Match 'Get-SyncedLogFolderNotice -LogFolder \$explicitLogFolder'
        $startup | Should -Match '\$explicitLogFolder = if \(\$LogFolder\) \{ \$script:ChangeLogFolder \}'
    }

    It 'SQ018R2_LogFolderTextMentionsSyncFolders' {
        $readme = Get-Content -LiteralPath (Join-Path $script:Root 'README.md') -Raw
        $readme | Should -Match ([regex]::Escape('(when that is a local fixed disk and not in a OneDrive or SharePoint sync folder)'))
        ($script:Ast.GetHelpContent().Notes) | Should -Match '(?s)local fixed disk and not in a OneDrive\s+or SharePoint sync folder'
    }

    It 'SQ018R2_ChangeStatusWording' {
        # Nothing done and every item not found.
        $s = Get-ChangeStatus -Entries @((New-Row -Target 'D:\a' -Result 'Skipped (not found)'), (New-Row -Target 'D:\b' -Result 'Skipped (not found)')) -LogPath 'C:\l.csv' -Message 'm'
        $s.Kind | Should -Be 'Warning'
        $s.Text | Should -BeLike 'Nothing was changed: *'

        # A mixed result where one remove did nothing is a warning.
        $noop = New-Row -Action 'Remove permission' -Target 'D:\Data\B' -Detail 'Allow Modify for CONTOSO\HR'
        $noop | Add-Member -NotePropertyName NothingRemoved -NotePropertyValue $true
        $real = New-Row -Action 'Remove permission' -Target 'D:\Data\A' -Detail 'Allow Modify for CONTOSO\HR'
        $m = Get-ChangeStatus -Entries @($real, $noop) -LogPath 'C:\l.csv' -Message 'Removed.'
        $m.Kind | Should -Be 'Warning'
        $m.Text | Should -Match ([regex]::Escape('D:\Data\B'))
        $m.Text | Should -Match ([regex]::Escape('It may be inherited: remove it on the folder above.'))

        # Nothing removed anywhere names the path.
        $only = Get-ChangeStatus -Entries @($noop) -LogPath 'C:\l.csv' -Message 'Removed.'
        $only.Kind | Should -Be 'Info'
        $only.Text | Should -BeLike 'Nothing was removed: CONTOSO\HR had no explicit Allow entry here.*'
        $only.Text | Should -Match ([regex]::Escape('D:\Data\B'))
        $only.Text | Should -Match ([regex]::Escape('It may be inherited: remove it on the folder above.'))

        # A read-back problem.
        $bad = New-Row -Target 'D:\Data\C'
        $bad | Add-Member -NotePropertyName CheckProblem -NotePropertyValue 'no explicit Allow Modify entry for X was found on it afterwards'
        $p = Get-ChangeStatus -Entries @($bad) -LogPath 'C:\l.csv' -Message 'Added.'
        $p.Text | Should -Match ([regex]::Escape('Check this: D:\Data\C - no explicit Allow Modify entry'))
        $p.Text | Should -Match ([regex]::Escape('If it is still wrong after Refresh, check the change log or ask a senior admin.'))
    }

    It 'SQ018R2_PendingTooltipAndRemoveDialogError' {
        $script:ChangeTask = $null
        $script:ChangePending = [PSCustomObject]@{ Action = 'Remove Permission'; Path = 'D:\Data'; Step = 1 }
        $reason = (Get-ChangeControlState).Reason
        $reason | Should -Match '(?i)being prepared'
        $reason | Should -BeLike '*Wait for it to finish, or close its dialog.'
        $script:ChangePending = $null

        $fn = (Get-Command Show-PermissionDialog -CommandType Function).Definition
        $fn | Should -Match "(?s)Add_SelectionChanged\(\{[^}]*PermDialogError'\)\.Visibility = 'Collapsed'" -Because 'the selection error clears when another entry is chosen'
    }

    It 'SQ018R2_FilesStaleGuardComparesTheSelectedPaths' {
        $script:PaneRequests = @{ Files = 4 }
        $dir = $script:Current.DisplayPath
        $script:SelectedRows = @([PSCustomObject]@{ Path = "$dir\a.txt" }, [PSCustomObject]@{ Path = "$dir\b.txt" })
        $request = Get-ChangeRequest -Scope Files
        Test-ChangeRequestCurrent -Request $request | Should -BeTrue
        $script:SelectedRows = @([PSCustomObject]@{ Path = "$dir\a.txt" })
        Test-ChangeRequestCurrent -Request $request | Should -BeFalse -Because 'the selection changed while the lookup ran'

        # The lookup that comes back says so, and opens nothing.
        $script:Reads = [System.Collections.Generic.List[object]]::new()
        Mock Start-ReadTask { $script:Reads.Add(@{ OnDone = $OnDone; State = $State }) }
        $script:Resolved = 0
        [void](Start-ChangeLookup -Paths $request.Paths -Label $request.Label -Request $request -OnResolved { $script:Resolved++ })
        & $script:Reads[0].OnDone ([PSCustomObject]@{ Ok = $true; Targets = @(); Refusal = $null }) $script:Reads[0].State
        $script:Resolved | Should -Be 0
        (Get-LastStatus).Text | Should -Match '(?i)files selected when you clicked'
    }

    It 'SQ018R2_DfsTagCitedAtBothReaders' {
        foreach ($name in 'Get-AppReparseInfo', 'Find-DfsReparsePoint') {
            $text = (Get-Command $name -CommandType Function).Definition
            $text | Should -Match '0x8000000A' -Because $name
            $text | Should -Match ([regex]::Escape('https://learn.microsoft.com/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4')) -Because $name
        }
    }
}

# ---------------------------------------------------------------------------------------------
# Revision run (review 2026-10-19: D-043, D-044, D-045, D-046): AC47-AC53, plus the AC36 amendment.
# AC54 (the AC6 amendment) is in FolderPermissionManager-App.Tests.ps1. Names and parameters
# pinned here for the implementer (the spec leaves them open); the stubs in
# FolderPermissionManager-GUI.ps1 already carry these signatures:
#   Set-PermissionSubmitStyle -Mode Add|Remove -Type Allow|Deny -Button <obj .Style .IsDefault> -DangerStyle -NormalStyle
#       Remove, and Add with Deny: danger style, IsDefault $false. Add with Allow: normal style, IsDefault $true.
#       Show-PermissionDialog calls it on open and when the type combo changes.
#   Get-ConfirmSpec ... -Type Allow|Deny          (AddPermission: Deny gives IsDestructive $true)
#   Get-ConfirmSpec ... -DenyEntries <string[]>   (CopyPermissions: any entry gives IsDestructive $true and is listed in Body)
#   Get-TargetRootKind -Path -> 'DriveRoot' (X:\) | 'ShareRoot' (\\server\share) | 'AdminShareRoot' (\\server\X$) | $null
#       Get-ConfirmSpec makes an Add or Copy IsDestructive when a target's ResolvedPath has a root kind.
#   Get-ChangeTarget / Resolve-ChangeTargetSet ... -RefuseProtected   (Copy targets: admin shares, IPC$, SYSVOL, NETLOGON,
#       D-036 folders and the high-impact roots are not Ok; Invoke-CopyPermissions and the typed-folders lookup of
#       Open-CopyPermissions pass it). Volume roots (D:\) are D-036, so a Copy to D:\ is refused (see the report).
#   Invoke-CopyPermissions finds the source's explicit Deny entries in $script:ViewState.FolderPermissions.Rows
#       (not IsInherited, Type Deny), the same rows the copy dialog's note uses.
#   Show-CopyPermissionsDialog -Source [-TypedText <text>]; after a refused typed folder, Open-CopyPermissions opens it again
#       with the typed text.
#   AC52: Get-ChangeTarget -WholeTree reads each component of the share's server-side path over the admin share with
#       Get-AppReparseInfo -Path '\\server\X$\...' (the existing seam).
#   AC53: the core's late re-check in Invoke-TreeOwnershipChange calls Get-HighImpactRootRefusal (or a core copy of it).
# ---------------------------------------------------------------------------------------------
Describe 'Revision 2026-10-19: Deny, roots, protected Copy targets, server-side junctions (AC47-AC53)' {
    BeforeAll {
        function script:New-ViewRows {
            param([object[]]$Row)
            $script:ViewState.FolderPermissions = [PSCustomObject]@{ Ok = $true; Path = $script:Current.RealPath; Rows = @($Row) }
        }
        function script:New-ViewRow {
            param([string]$Identity, [string]$Type = 'Allow', [bool]$Inherited = $false, [string]$Rights = 'Modify')
            [PSCustomObject]@{ Identity = $Identity; Sid = 'S-1-5-21-1-2-3-1100'; Type = $Type; IsInherited = $Inherited; Rights = $Rights }
        }
    }
    BeforeEach {
        $script:Reads = [System.Collections.Generic.List[object]]::new()
        Mock Start-ReadTask { $script:Reads.Add(@{ Action = $Action; Path = $Path; Work = $Work; ArgumentList = $ArgumentList; OnDone = $OnDone; State = $State }) }
        $script:AtConfirm = [System.Collections.Generic.List[object]]::new()
        # The confirm records whether a change task had already been started when it opened.
        Mock Show-ConfirmDialog { $script:Confirms.Add($Spec); $script:AtConfirm.Add($script:Captured); $script:ConfirmAnswer }
        New-ViewRows -Row @((New-ViewRow -Identity 'BUILTIN\Users'))
    }

    # ---- AC47 ----------------------------------------------------------------------------------
    It 'AC47_AddDeny_DangerStyle' {
        $danger = 'DANGER-STYLE'; $normal = 'NORMAL-STYLE'
        $btn = [PSCustomObject]@{ Style = $null; IsDefault = $true }
        Set-PermissionSubmitStyle -Mode Add -Type Deny -Button $btn -DangerStyle $danger -NormalStyle $normal
        $btn.Style | Should -Be $danger -Because 'adding a Deny uses the danger button style'
        # Choosing Allow again goes back to the normal style.
        Set-PermissionSubmitStyle -Mode Add -Type Allow -Button $btn -DangerStyle $danger -NormalStyle $normal
        $btn.Style | Should -Be $normal
        # Remove is always danger.
        Set-PermissionSubmitStyle -Mode Remove -Type Allow -Button $btn -DangerStyle $danger -NormalStyle $normal
        $btn.Style | Should -Be $danger
        # The dialog applies it (on open and when the type changes).
        (Get-Command Show-PermissionDialog -CommandType Function).Definition | Should -Match 'Set-PermissionSubmitStyle'
    }

    It 'AC47_AddDeny_ButtonIsNotDefault' {
        $btn = [PSCustomObject]@{ Style = $null; IsDefault = $true }
        Set-PermissionSubmitStyle -Mode Add -Type Deny -Button $btn -DangerStyle 'D' -NormalStyle 'N'
        $btn.IsDefault | Should -BeFalse -Because 'a Deny add is never the default (Enter) button'
        Set-PermissionSubmitStyle -Mode Add -Type Allow -Button $btn -DangerStyle 'D' -NormalStyle 'N'
        $btn.IsDefault | Should -BeTrue -Because 'a plain Allow add keeps Enter as submit'
        Set-PermissionSubmitStyle -Mode Remove -Type Allow -Button $btn -DangerStyle 'D' -NormalStyle 'N'
        $btn.IsDefault | Should -BeFalse
    }

    It 'AC47_AddDeny_ConfirmWithRealLocationBeforeAnyChange' {
        $t = New-FakeTarget -Display 'H:\Data' -Resolved '\\fs02\real\Data'
        Invoke-AddPermission -Scope Folder -Identity 'CONTOSO\Temps' -Rights 'Modify' -Type 'Deny' -Targets @($t)
        $script:Confirms.Count | Should -Be 1 -Because 'a Deny add opens the confirm'
        $script:AtConfirm[0] | Should -BeNullOrEmpty -Because 'no change task may have started when the confirm opens'
        $spec = $script:Confirms[0]
        $spec.IsDestructive | Should -BeTrue
        $spec.ActionLabel | Should -Match '^Add'
        $spec.ActionLabel | Should -Not -BeIn @('OK', 'Yes')
        $spec.Body | Should -Match ([regex]::Escape('H:\Data'))
        $spec.Body | Should -Match ([regex]::Escape('\\fs02\real\Data')) -Because 'the real location is shown'
        $spec.Body | Should -Match 'Deny'
        $spec.Body | Should -Match ([regex]::Escape('CONTOSO\Temps'))
        $script:Captured | Should -Not -BeNullOrEmpty -Because 'the change starts once confirmed'
        @($script:Captured.ArgumentList[0]) | Should -Be @('\\fs02\real\Data')

        # Declined: nothing starts.
        $script:Captured = $null; $script:Confirms.Clear(); $script:ConfirmAnswer = $false
        Invoke-AddPermission -Scope Folder -Identity 'CONTOSO\Temps' -Rights 'Modify' -Type 'Deny' -Targets @($t)
        $script:Confirms.Count | Should -Be 1
        $script:Captured | Should -BeNullOrEmpty
    }

    It 'AC47_AddDeny_ConfirmSpec' {
        $one = New-FakeTarget -Display 'D:\Data\HR'
        $deny = Get-ConfirmSpec -Action AddPermission -Targets @($one) -Detail 'Deny Modify for CONTOSO\Temps' -Type Deny
        $deny.IsDestructive | Should -BeTrue
        $allow = Get-ConfirmSpec -Action AddPermission -Targets @($one) -Detail 'Allow Modify for CONTOSO\HR' -Type Allow
        $allow.IsDestructive | Should -BeFalse
    }

    # Guard for the amended AC36 (D-044): passes before and after the revision.
    It 'AC36_Amended_PlainAllowAddAndCopyStayOneStep' {
        # One step only for a plain Allow add or copy on ordinary folders that resolve to themselves.
        $folder = New-FakeTarget -Display 'D:\Data\HR'
        Invoke-AddPermission -Scope Folder -Identity 'CONTOSO\HR' -Rights 'Modify' -Type 'Allow' -Targets @($folder)
        $script:Confirms.Count | Should -Be 0
        $script:Captured | Should -Not -BeNullOrEmpty

        $script:Captured = $null
        # The source has an explicit Allow and an inherited Deny only: no explicit Deny.
        New-ViewRows -Row @((New-ViewRow -Identity 'BUILTIN\Users'), (New-ViewRow -Identity 'CONTOSO\Inh' -Type Deny -Inherited $true))
        $source = New-FakeTarget -Display $script:Current.DisplayPath
        $targets = @((New-FakeTarget -Display '\\fs01\Data\A'), (New-FakeTarget -Display 'D:\Data\B'))
        Invoke-CopyPermissions -Source $source -Targets $targets
        $script:Confirms.Count | Should -Be 0
        $script:Captured | Should -Not -BeNullOrEmpty
    }

    # ---- AC48 ----------------------------------------------------------------------------------
    It 'AC48_CopyWithExplicitDeny_DestructiveConfirm' {
        New-ViewRows -Row @(
            (New-ViewRow -Identity 'BUILTIN\Users'),
            (New-ViewRow -Identity 'CONTOSO\Temps' -Type Deny -Rights 'Write'),
            (New-ViewRow -Identity 'CONTOSO\InheritedDeny' -Type Deny -Inherited $true))
        $source = New-FakeTarget -Display $script:Current.DisplayPath
        $t1 = New-FakeTarget -Display '\\fs01\A' -Resolved '\\fs03\A'
        $t2 = New-FakeTarget -Display 'D:\B'
        Invoke-CopyPermissions -Source $source -Targets @($t1, $t2)
        $script:Confirms.Count | Should -Be 1 -Because 'a copy of explicit Deny entries needs a confirm'
        $script:AtConfirm[0] | Should -BeNullOrEmpty
        $spec = $script:Confirms[0]
        $spec.IsDestructive | Should -BeTrue
        $spec.ActionLabel | Should -Match '^Copy'
        $spec.Body | Should -Match ([regex]::Escape('CONTOSO\Temps')) -Because 'the Deny entries are listed'
        $spec.Body | Should -Match 'Deny'
        $spec.Body | Should -Not -Match ([regex]::Escape('CONTOSO\InheritedDeny')) -Because 'only the folder''s own (explicit) entries are copied'
        $spec.Body | Should -Match ([regex]::Escape('\\fs01\A'))
        $spec.Body | Should -Match ([regex]::Escape('\\fs03\A')) -Because 'every target''s real location is shown'
        $spec.Body | Should -Match ([regex]::Escape('D:\B'))
        $script:Captured | Should -Not -BeNullOrEmpty

        $script:Captured = $null; $script:Confirms.Clear(); $script:AtConfirm.Clear(); $script:ConfirmAnswer = $false
        Invoke-CopyPermissions -Source $source -Targets @($t1, $t2)
        $script:Confirms.Count | Should -Be 1
        $script:Captured | Should -BeNullOrEmpty -Because 'declined'
    }

    It 'AC48_ConfirmSpec_DenyEntries' {
        $t = New-FakeTarget -Display 'D:\B'
        $spec = Get-ConfirmSpec -Action CopyPermissions -Targets @($t) -Detail 'D:\Src' -DenyEntries @('CONTOSO\Temps (Deny, Write)')
        $spec.IsDestructive | Should -BeTrue
        $spec.Body | Should -Match ([regex]::Escape('CONTOSO\Temps'))
        (Get-ConfirmSpec -Action CopyPermissions -Targets @($t) -Detail 'D:\Src').IsDestructive | Should -BeFalse
    }

    # ---- AC49 ----------------------------------------------------------------------------------
    It 'AC49_RootKinds' {
        Get-TargetRootKind -Path 'D:\' | Should -Be 'DriveRoot'
        Get-TargetRootKind -Path 'd:\' | Should -Be 'DriveRoot'
        Get-TargetRootKind -Path '\\fs01\Data' | Should -Be 'ShareRoot'
        Get-TargetRootKind -Path '\\fs01\Data\' | Should -Be 'ShareRoot'
        Get-TargetRootKind -Path '\\fs01\D$' | Should -Be 'AdminShareRoot'
        foreach ($p in 'D:\Data', '\\fs01\Data\HR', '\\fs01\D$\Data', 'C:\Users\bob') { Get-TargetRootKind -Path $p | Should -BeNullOrEmpty -Because "$p is not a root" }
    }

    It 'AC49_AddOnARoot_DestructiveConfirmWithRealLocation' {
        $cases = @(
            @{ Display = 'D:\'; Resolved = 'D:\' }
            @{ Display = '\\fs01\Data'; Resolved = '\\fs01\Data' }
            @{ Display = '\\fs01\D$'; Resolved = '\\fs01\D$' }
            @{ Display = 'H:\'; Resolved = '\\fs01\home' }                          # a mapped drive: the root of its share
            @{ Display = '\\contoso.com\dfs\hr'; Resolved = '\\fs02\HR' }           # DFS: resolves to a share root
        )
        foreach ($c in $cases) {
            $script:Captured = $null; $script:Confirms.Clear(); $script:AtConfirm.Clear(); $script:ConfirmAnswer = $true
            $t = New-FakeTarget -Display $c.Display -Resolved $c.Resolved
            Invoke-AddPermission -Scope Folder -Identity 'CONTOSO\HR' -Rights 'Modify' -Type 'Allow' -Targets @($t)
            $script:Confirms.Count | Should -Be 1 -Because "an Allow add on $($c.Display) (really $($c.Resolved)) is a root"
            $script:AtConfirm[0] | Should -BeNullOrEmpty
            $script:Confirms[0].IsDestructive | Should -BeTrue
            $script:Confirms[0].Body | Should -Match ([regex]::Escape($c.Resolved))
            $script:Captured | Should -Not -BeNullOrEmpty

            $script:Captured = $null; $script:Confirms.Clear(); $script:AtConfirm.Clear(); $script:ConfirmAnswer = $false
            Invoke-AddPermission -Scope Folder -Identity 'CONTOSO\HR' -Rights 'Modify' -Type 'Allow' -Targets @($t)
            $script:Captured | Should -BeNullOrEmpty -Because 'declined'
        }
        # Not a root: one step.
        $script:Captured = $null; $script:Confirms.Clear(); $script:ConfirmAnswer = $true
        foreach ($p in 'D:\Data', '\\fs01\Data\HR', '\\fs01\D$\Data') {
            $script:Captured = $null
            Invoke-AddPermission -Scope Folder -Identity 'CONTOSO\HR' -Rights 'Modify' -Type 'Allow' -Targets @((New-FakeTarget -Display $p))
            $script:Captured | Should -Not -BeNullOrEmpty -Because "$p is an ordinary folder"
        }
        $script:Confirms.Count | Should -Be 0
    }

    It 'AC49_CopyOntoARoot_DestructiveConfirmWithRealLocation' {
        $source = New-FakeTarget -Display $script:Current.DisplayPath
        $cases = @(
            @{ Display = '\\fs01\Data'; Resolved = '\\fs01\Data' }
            @{ Display = 'H:\'; Resolved = '\\fs01\home' }
            @{ Display = '\\contoso.com\dfs\hr'; Resolved = '\\fs02\HR' }
        )
        foreach ($c in $cases) {
            $script:Captured = $null; $script:Confirms.Clear(); $script:AtConfirm.Clear(); $script:ConfirmAnswer = $true
            $t = New-FakeTarget -Display $c.Display -Resolved $c.Resolved
            $ok = New-FakeTarget -Display 'D:\Data\Other'
            Invoke-CopyPermissions -Source $source -Targets @($ok, $t)
            $script:Confirms.Count | Should -Be 1 -Because "a copy onto $($c.Display) (really $($c.Resolved)) is a root"
            $script:AtConfirm[0] | Should -BeNullOrEmpty
            $script:Confirms[0].IsDestructive | Should -BeTrue
            $script:Confirms[0].Body | Should -Match ([regex]::Escape($c.Resolved))
            $script:Captured | Should -Not -BeNullOrEmpty

            $script:Captured = $null; $script:Confirms.Clear(); $script:AtConfirm.Clear(); $script:ConfirmAnswer = $false
            Invoke-CopyPermissions -Source $source -Targets @($ok, $t)
            $script:Captured | Should -BeNullOrEmpty -Because 'declined'
        }
    }

    # ---- AC50 ----------------------------------------------------------------------------------
    It 'AC50_CopyTargetsThatAreProtectedAreRefused' {
        $sysRoot = "$env:SystemRoot"
        $sysUnc = '\\testpc\' + $sysRoot.Substring(0, 1) + '$' + $sysRoot.Substring(2)
        $refused = @(
            '\\fs01\D$', '\\fs01\ADMIN$', '\\fs01\IPC$', '\\fs01\print$', '\\fs01\SYSVOL', '\\fs01\NETLOGON',   # admin shares and the DC shares
            "$sysRoot\System32",                                                                                  # D-036: a Windows folder
            $sysUnc,                                                                                              # D-036 through this computer's own admin share
            'C:\Users', 'D:\System Volume Information'                                                            # high-impact roots
        )
        foreach ($p in $refused) {
            $script:Captured = $null; $script:Shown.Clear(); $script:Status.Clear(); $script:Confirms.Clear(); $script:ConfirmAnswer = $true
            Invoke-CopyPermissions -TargetText $p
            $script:Captured | Should -BeNullOrEmpty -Because "no task starts for the protected target $p"
            $script:Confirms.Count | Should -Be 0 -Because 'it is refused, not confirmed'
            @($script:Shown).Count | Should -BeGreaterThan 0 -Because "$p is refused with a message the tech sees"
            $script:Shown[0] | Should -Not -Match 'Exception'
            (Get-LastStatus).Kind | Should -Be 'Error'
        }
        # One protected folder in a list refuses the whole copy.
        $script:Captured = $null; $script:Shown.Clear()
        Invoke-CopyPermissions -TargetText "D:\Data\A`n\\fs01\ADMIN$"
        $script:Captured | Should -BeNullOrEmpty

        # An ordinary share folder is not refused.
        $script:Captured = $null; $script:Shown.Clear(); $script:Status.Clear()
        Invoke-CopyPermissions -TargetText '\\fs01\Data\HR'
        $script:Captured | Should -Not -BeNullOrEmpty
    }

    It 'AC50_GetChangeTarget_RefuseProtected' {
        foreach ($p in '\\fs01\ADMIN$', '\\fs01\IPC$', '\\fs01\D$', '\\fs01\SYSVOL') {
            (Get-ChangeTarget -Path $p -RefuseProtected).Ok | Should -BeFalse -Because $p
            (Get-ChangeTarget -Path $p).Ok | Should -BeTrue -Because "$p is only refused for a Copy target"
        }
        (Get-ChangeTarget -Path '\\fs01\Data\HR' -RefuseProtected).Ok | Should -BeTrue
        (Get-ChangeTarget -Path '\\fs01\Data' -RefuseProtected).Ok | Should -BeTrue -Because 'a share root is confirmed (AC49), not refused'
        $set = Resolve-ChangeTargetSet -Path @('D:\Data', '\\fs01\ADMIN$') -DriveMap @{} -DriveMapSource @{} -RefuseProtected
        $set.Ok | Should -BeFalse
    }

    It 'AC50_CopyDialogFlow_TypedFoldersAreCheckedInTheBackground' {
        $script:MappedDrives = @{ H = '\\fs01\home' }; $script:MappedDriveSources = @{ H = 'Live' }
        $script:Current = [PSCustomObject]@{ DisplayPath = 'H:\Data'; RealPath = '\\fs01\home\Data' }
        New-ViewRows -Row @((New-ViewRow -Identity 'BUILTIN\Users'))
        $script:CopyDialogs = [System.Collections.Generic.List[object]]::new()
        $script:CopyAnswers = [System.Collections.Generic.Queue[object]]::new()
        $script:CopyAnswers.Enqueue("\\fs01\ADMIN`$`n\\fs01\Data\HR")
        $script:CopyAnswers.Enqueue($null)
        Mock Show-CopyPermissionsDialog { $script:CopyDialogs.Add(@{ Source = $Source; TypedText = $TypedText }); $script:CopyAnswers.Dequeue() }
        Open-CopyPermissions
        & $script:Reads[0].OnDone ([PSCustomObject]@{ Ok = $true; Targets = @(New-FakeTarget -Display 'H:\Data' -Resolved '\\fs01\home\Data'); Refusal = $null }) $script:Reads[0].State
        $script:Reads.Count | Should -BeGreaterThan 1 -Because 'the typed folders are looked up after the dialog'
        $argList = @($script:Reads[1].ArgumentList)
        $r = & $script:Reads[1].Work @argList
        $r.Ok | Should -BeFalse -Because 'the background lookup of the typed folders refuses \\fs01\ADMIN$'
        & $script:Reads[1].OnDone $r $script:Reads[1].State
        $script:Captured | Should -BeNullOrEmpty
        @($script:Shown | Where-Object { $_ -match [regex]::Escape('ADMIN$') }).Count | Should -BeGreaterThan 0
    }

    # ---- AC51 ----------------------------------------------------------------------------------
    It 'AC51_CopyTargetResolvedElsewhere_ConfirmListsTypedAndRealLocation' {
        $source = New-FakeTarget -Display $script:Current.DisplayPath
        $cases = @(
            @{ What = 'mapped drive'; Display = 'H:\Share\Sub'; Resolved = '\\fs01\home\Share\Sub' }
            @{ What = 'DFS'; Display = '\\contoso.com\dfs\hr\Sub'; Resolved = '\\fs02\HR\Sub' }
            @{ What = 'loopback admin share'; Display = '\\testpc\C$\Temp'; Resolved = 'C:\Temp' }
            @{ What = 'local share'; Display = '\\testpc\Data\Sub'; Resolved = 'D:\Shares\Data\Sub' }
        )
        foreach ($c in $cases) {
            $script:Captured = $null; $script:Confirms.Clear(); $script:AtConfirm.Clear(); $script:ConfirmAnswer = $true
            $same = New-FakeTarget -Display 'D:\Data\Same'
            $t = New-FakeTarget -Display $c.Display -Resolved $c.Resolved
            Invoke-CopyPermissions -Source $source -Targets @($same, $t)
            $script:Confirms.Count | Should -Be 1 -Because "$($c.What): $($c.Display) is really $($c.Resolved)"
            $script:AtConfirm[0] | Should -BeNullOrEmpty -Because 'the confirm comes before the change'
            $script:Confirms[0].Body | Should -Match ([regex]::Escape($c.Display)) -Because 'what was typed'
            $script:Confirms[0].Body | Should -Match ([regex]::Escape($c.Resolved)) -Because 'where it really is'
            $script:Captured | Should -Not -BeNullOrEmpty
            @($script:Captured.ArgumentList[1]) | Should -Contain $c.Resolved

            $script:Captured = $null; $script:Confirms.Clear(); $script:AtConfirm.Clear(); $script:ConfirmAnswer = $false
            Invoke-CopyPermissions -Source $source -Targets @($same, $t)
            $script:Confirms.Count | Should -Be 1
            $script:Captured | Should -BeNullOrEmpty -Because 'declined'
        }
    }

    # Guard (passes before and after): with nothing to flag, Copy stays one step.
    It 'AC51_CopyStaysOneStepWhenEveryTargetResolvesToItself' {
        $source = New-FakeTarget -Display $script:Current.DisplayPath
        Invoke-CopyPermissions -Source $source -Targets @((New-FakeTarget -Display 'D:\Data\A'), (New-FakeTarget -Display '\\fs01\Data\B'))
        $script:Confirms.Count | Should -Be 0
        $script:Captured | Should -Not -BeNullOrEmpty
    }

    # ---- AC52 ----------------------------------------------------------------------------------
    # FILE_ATTRIBUTE_REPARSE_POINT is 1024 (0x400): "A file or directory that has an associated reparse
    # point, or a file that is a symbolic link". Get-AppReparseInfo (FindFirstFileW dwFileAttributes) is the
    # seam; its reads are mocked here. NetShareGetInfo level 2 (SHARE_INFO_2.shi2_path) is the existing
    # Get-RemoteShareLocalPath seam, also mocked. 2684354563 = 0xA0000003, IO_REPARSE_TAG_MOUNT_POINT.
    # https://learn.microsoft.com/windows/win32/fileio/file-attribute-constants
    # https://learn.microsoft.com/windows/win32/api/lmshare/nf-lmshare-netsharegetinfo
    It 'AC52_ServerSidePathComponentsAreChecked_NoJunction' {
        $script:Asked = [System.Collections.Generic.List[string]]::new()
        Mock Get-RemoteShareLocalPath { 'D:\Shares\Data' }
        Mock Get-AppReparseInfo { $script:Asked.Add($Path); [PSCustomObject]@{ Exists = $true; IsReparsePoint = $false; Tag = $null } }
        $t = Get-ChangeTarget -Path '\\fs01\Data\HR' -WholeTree
        $t.Ok | Should -BeTrue -Because "$($t.Refusal)"
        @($script:Asked) | Should -Contain '\\fs01\D$\Shares' -Because 'each component of the server-side path is read over the admin share'
        @($script:Asked) | Should -Contain '\\fs01\D$\Shares\Data'
    }

    It 'AC52_AReparsePointInTheServerSidePathRefuses' {
        Mock Get-RemoteShareLocalPath { 'D:\Shares\Data' }
        foreach ($bad in '\\fs01\D$\Shares', '\\fs01\D$\Shares\Data') {
            $script:Bad = $bad
            Mock Get-AppReparseInfo { [PSCustomObject]@{ Exists = $true; IsReparsePoint = ($Path -eq $script:Bad); Tag = $(if ($Path -eq $script:Bad) { [uint32]2684354563 } else { $null }) } }
            $t = Get-ChangeTarget -Path '\\fs01\Data\HR' -WholeTree
            $t.Ok | Should -BeFalse -Because "$bad is a junction on the server"
            $t.Refusal | Should -Match ([regex]::Escape($bad)) -Because 'the refusal names the component'
            $t.Refusal | Should -Match '(?i)junction|symbolic link|link|reparse'
        }
    }

    It 'AC52_AComponentThatCannotBeCheckedRefuses' {
        Mock Get-RemoteShareLocalPath { 'D:\Shares\Data' }
        Mock Get-AppReparseInfo { if ($Path -eq '\\fs01\D$\Shares') { throw 'Access is denied' }; [PSCustomObject]@{ Exists = $true; IsReparsePoint = $false; Tag = $null } }
        $t = Get-ChangeTarget -Path '\\fs01\Data\HR' -WholeTree
        $t.Ok | Should -BeFalse -Because 'a guard that cannot read the component fails closed'
        $t.Refusal | Should -Match ([regex]::Escape('\\fs01\D$\Shares'))
    }

    It 'AC52_OnlyWholeTreeChangesAreGuardedThisWay' {
        $script:Asked = [System.Collections.Generic.List[string]]::new()
        Mock Get-RemoteShareLocalPath { 'D:\Shares\Data' }
        Mock Get-AppReparseInfo { $script:Asked.Add($Path); [PSCustomObject]@{ Exists = $true; IsReparsePoint = $true; Tag = [uint32]2684354563 } }
        (Get-ChangeTarget -Path '\\fs01\Data\HR').Ok | Should -BeTrue -Because 'a one-item change is not guarded this way'
        @($script:Asked | Where-Object { $_ -like '\\fs01\*' }).Count | Should -Be 0
    }

    It 'AC52_RefusedBeforeTheCountAndTheConfirm' {
        Mock Get-RemoteShareLocalPath { 'D:\Shares\Data' }
        Mock Get-AppReparseInfo { [PSCustomObject]@{ Exists = $true; IsReparsePoint = ($Path -eq '\\fs01\D$\Shares'); Tag = $(if ($Path -eq '\\fs01\D$\Shares') { [uint32]2684354563 } else { $null }) } }
        $script:Current = [PSCustomObject]@{ DisplayPath = '\\fs01\Data\HR'; RealPath = '\\fs01\Data\HR' }
        Open-TakeOwnership -Scope Tree
        $script:Reads.Count | Should -Be 1 -Because 'only the lookup of where the folder is has started'
        $argList = @($script:Reads[0].ArgumentList)
        $r = & $script:Reads[0].Work @argList
        $r.Ok | Should -BeFalse
        & $script:Reads[0].OnDone $r $script:Reads[0].State
        $script:Reads.Count | Should -Be 1 -Because 'no count starts'
        $script:Confirms.Count | Should -Be 0
        $script:Captured | Should -BeNullOrEmpty
        @($script:Shown | Where-Object { $_ -match [regex]::Escape('\\fs01\D$\Shares') }).Count | Should -BeGreaterThan 0
    }

    # ---- AC53 (a): the late re-check before takeown also runs the high-impact-root check --------
    It 'AC53a_LateRecheckAlsoChecksHighImpactRoots' {
        $dir = New-Folder 'Late53'
        $log = Join-Path $TestDrive ('late-log-' + [guid]::NewGuid().ToString('N'))
        $script:SnapshotTaken = $false
        $script:ToolCalls = [System.Collections.Generic.List[string]]::new()
        # The snapshot is faked (no owners are read); the flag marks "after the snapshot", the late check.
        Mock Save-OwnerSnapshot {
            $script:SnapshotTaken = $true
            [PSCustomObject]@{ File = (Join-Path $TestDrive 'snap.csv'); Count = 1; Items = @(); Unreadable = 0; Unlisted = 0; UnlistedFolders = @(); Links = 0; LinkPaths = @() }
        }
        Mock Get-TreeOwnershipTargetRefusal { $null }
        Mock Get-TreeLinkRefusal { $null }
        Mock Get-OwnerReadBack { [PSCustomObject]@{ Mine = 1; NotMine = 0; Changed = 1; Unchecked = 0; AdministratorsOnly = $false; WatchedChanged = @(); WatchedUnchecked = @() } }
        Mock Invoke-AclTool { $script:ToolCalls.Add("$Tool"); [PSCustomObject]@{ ExitCode = 0; Output = @() } }
        # The folder is fine on the first check and is the profiles folder at the late one (swapped in meanwhile).
        Mock Get-HighImpactRootRefusal { if ($script:SnapshotTaken) { "$Path is the folder that holds every user profile on this computer (C:\Users). Taking ownership of everything in it changes the owner of every user profile." } else { $null } }
        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -LogFolder $log -Recurse -Confirm:$false)
        $row = $rows | Where-Object { $_ } | Select-Object -Last 1
        $row.Result | Should -Be 'Failed' -Because 'the late re-check must refuse a high-impact root'
        # The row's column is Error (New-PermissionChangeEntry -ErrorText fills it).
        $row.Error | Should -Match 'user profile'
        $row.Error | Should -Match 'Nothing was changed'
        $script:ToolCalls.Count | Should -Be 0 -Because 'takeown and icacls must not run'
    }

    # ---- AC53 (b): orphan wording and the icacls hint ------------------------------------------
    It 'AC53b_OrphanWordingAndIcaclsHint' {
        $sid = 'S-1-5-21-1-2-3-1009'
        Mock ConvertTo-SidAccountName { $null }
        Mock ConvertTo-IdentitySid { $null }
        foreach ($case in @(@{ Identity = $sid; Type = 'Allow'; Switch = '/remove:g' }, @{ Identity = 'CONTOSO\Gone'; Type = 'Deny'; Switch = '/remove:d' })) {
            $r = Get-RemoveIdentityProblem -Identity $case.Identity -Sid $sid -Path @('D:\Data') -Type $case.Type
            $r.Problem | Should -Match ([regex]::Escape("Windows can't look up this account from here (it may be deleted, or local to the server)"))
            $r.Problem | Should -Not -Match 'no longer exists' -Because 'an untranslatable live SID is not necessarily deleted'
            $save = $r.Problem.IndexOf('icacls "D:\Data" /save ')
            $save | Should -BeGreaterThan -1 -Because 'the hint starts with a backup of the permissions'
            $remove = $r.Problem.IndexOf("$($case.Switch) *$sid")
            $remove | Should -BeGreaterThan $save -Because '/save comes before /remove'
            $r.Problem | Should -Match 'Nothing was changed'
        }
    }

    # ---- AC53 (c): the final-path refusal's next step ------------------------------------------
    It 'AC53c_FinalPathRefusalNextStep' {
        Mock Get-Win32PathName { $null }
        $text = Get-ResolvedRootRefusal -Path 'D:\Data'
        $text | Should -Match ([regex]::Escape('run the tool on the server itself, or ask a senior admin'))
        $text | Should -Not -Match 'Press Refresh'
        $dir = New-Folder 'Final53'
        $t = Get-ChangeTarget -Path $dir -WholeTree
        $t.Ok | Should -BeFalse
        $t.Refusal | Should -Match ([regex]::Escape('run the tool on the server itself, or ask a senior admin'))
    }

    # ---- AC53 (d): the Copy dialog keeps the typed list when a target is refused ---------------
    It 'AC53d_CopyDialogKeepsTheTypedListAfterARefusal' {
        $script:MappedDrives = @{ H = '\\fs01\home' }; $script:MappedDriveSources = @{ H = 'Live' }
        $script:Current = [PSCustomObject]@{ DisplayPath = 'H:\Data'; RealPath = '\\fs01\home\Data' }
        New-ViewRows -Row @((New-ViewRow -Identity 'BUILTIN\Users'))
        $typed = "\\fs01\ADMIN`$`n\\fs01\Data\HR"
        $script:CopyDialogs = [System.Collections.Generic.List[object]]::new()
        $script:CopyAnswers = [System.Collections.Generic.Queue[object]]::new()
        $script:CopyAnswers.Enqueue($typed)
        $script:CopyAnswers.Enqueue($null)
        Mock Show-CopyPermissionsDialog { $script:CopyDialogs.Add(@{ Source = $Source; TypedText = $TypedText }); $script:CopyAnswers.Dequeue() }
        Open-CopyPermissions
        & $script:Reads[0].OnDone ([PSCustomObject]@{ Ok = $true; Targets = @(New-FakeTarget -Display 'H:\Data' -Resolved '\\fs01\home\Data'); Refusal = $null }) $script:Reads[0].State
        $script:CopyDialogs[0].TypedText | Should -BeNullOrEmpty -Because 'the first time the box is empty'

        # One typed folder is refused: the refusal is shown and the dialog opens again with what was typed.
        & $script:Reads[1].OnDone ([PSCustomObject]@{ Ok = $false; Targets = @(); Refusal = '\\fs01\ADMIN$ is an administrative share, so nothing was changed.' }) $script:Reads[1].State
        $script:Shown | Should -Contain '\\fs01\ADMIN$ is an administrative share, so nothing was changed.'
        $script:CopyDialogs.Count | Should -Be 2 -Because 'the dialog opens again after the refusal'
        $script:CopyDialogs[1].TypedText | Should -Be $typed -Because 'the typed list is kept'
        $script:CopyDialogs[1].Source.ResolvedPath | Should -Be '\\fs01\home\Data'
        # Cancelling the second dialog ends it cleanly.
        $script:Captured | Should -BeNullOrEmpty
        $script:ChangePending | Should -BeNullOrEmpty
    }

    It 'AC53d_CopyDialogPutsTheTypedTextBackInTheBox' {
        $fn = @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Show-CopyPermissionsDialog' }, $true))[0]
        @($fn.Body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) | Should -Contain 'TypedText'
        $afterParams = $fn.Body.ParamBlock.Extent.EndOffset
        $uses = @($fn.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath -eq 'TypedText' -and $n.Extent.StartOffset -gt $afterParams }, $true))
        $uses.Count | Should -BeGreaterThan 0 -Because 'the body must use -TypedText to fill CopyTargetsBox'
        $fn.Extent.Text | Should -Match 'CopyTargetsBox'
    }

    # ---- Review round 1 of the revision (2026-10-19) ---------------------------------------------
    # M1: the late re-check must see where the folder really leads, not only the text of the path.
    It 'AC53a_LateRecheckSeesAJunctionSwappedInAfterTheConfirm' {
        $dir = New-Folder 'Late53Swap'
        $script:Dir53 = $dir
        $log = Join-Path $TestDrive ('late-swap-log-' + [guid]::NewGuid().ToString('N'))
        $script:SnapshotTaken = $false
        $script:ToolCalls = [System.Collections.Generic.List[string]]::new()
        Mock Save-OwnerSnapshot {
            $script:SnapshotTaken = $true
            [PSCustomObject]@{ File = (Join-Path $TestDrive 'snap-swap.csv'); Count = 1; Items = @(); Unreadable = 0; Unlisted = 0; UnlistedFolders = @(); Links = 0; LinkPaths = @() }
        }
        Mock Get-OwnerReadBack { [PSCustomObject]@{ Mine = 1; NotMine = 0; Changed = 1; Unchecked = 0; AdministratorsOnly = $false; WatchedChanged = @(); WatchedUnchecked = @() } }
        Mock Invoke-AclTool { $script:ToolCalls.Add("$Tool"); [PSCustomObject]@{ ExitCode = 0; Output = @() } }
        # Nothing about this computer's drives or folders above $TestDrive is read.
        Mock Resolve-NetworkDrivePath { $Path }
        Mock Find-PathLink { $null }
        # The folder is itself at the first check; by the late check it has become a junction to C:\Users.
        Mock Get-Win32PathName { if ($script:SnapshotTaken -and $Kind -eq 'Final' -and $Path -eq $script:Dir53) { '\\?\C:\Users' } else { $Path } }
        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -LogFolder $log -Recurse -Confirm:$false)
        $row = $rows | Where-Object { $_ } | Select-Object -Last 1
        $row.Result | Should -Be 'Failed' -Because 'the late re-check runs the high-impact check on the final path'
        $row.Error | Should -Match ([regex]::Escape('C:\Users'))
        $row.Error | Should -Match 'user profile'
        $row.Error | Should -Match 'Nothing was changed'
        $script:ToolCalls.Count | Should -Be 0 -Because 'takeown and icacls must not run'
        Should -Invoke Invoke-AclTool -Times 0 -Exactly
        Should -Invoke Get-Win32PathName -ParameterFilter { $Kind -eq 'Final' -and $Path -eq $script:Dir53 }
    }

    It 'AC53a_LateRecheckSeesALinkInsideTheTreeThatLeadsToUsers' {
        $dir = New-Folder 'Late53Link'
        $link = New-Folder 'Late53Link\Profiles'
        $script:Link53 = $link
        $log = Join-Path $TestDrive ('late-link-log-' + [guid]::NewGuid().ToString('N'))
        $script:ToolCalls = [System.Collections.Generic.List[string]]::new()
        Mock Save-OwnerSnapshot {
            [PSCustomObject]@{ File = (Join-Path $TestDrive 'snap-link.csv'); Count = 2; Items = @(); Unreadable = 0; Unlisted = 0; UnlistedFolders = @(); Links = 1; LinkPaths = @($script:Link53) }
        }
        Mock Invoke-AclTool { $script:ToolCalls.Add("$Tool"); [PSCustomObject]@{ ExitCode = 0; Output = @() } }
        Mock Resolve-NetworkDrivePath { $Path }
        Mock Find-PathLink { $null }
        Mock Get-LinkKind { 'junction' }
        Mock Get-Win32PathName { if ($Kind -eq 'Final' -and $Path -eq $script:Link53) { '\\?\C:\Users' } else { $Path } }
        $row = @(Set-ItemOwnerToCurrentUser -Path $dir -LogFolder $log -Recurse -Confirm:$false) | Where-Object { $_ } | Select-Object -Last 1
        $row.Result | Should -Be 'Failed'
        $row.Error | Should -Match ([regex]::Escape($link))
        $row.Error | Should -Match 'user profile'
        $row.Error | Should -Match 'Nothing was changed'
        $script:ToolCalls.Count | Should -Be 0
    }

    # M2: a trailing or doubled backslash must not skip the D-045 check.
    It 'AC52_TrailingOrDoubledBackslashStillChecksTheServerSidePath' {
        Mock Get-RemoteShareLocalPath { 'D:\Shares\Data' }
        Mock Get-AppReparseInfo { [PSCustomObject]@{ Exists = $true; IsReparsePoint = ($Path -eq '\\fs01\D$\Shares'); Tag = $(if ($Path -eq '\\fs01\D$\Shares') { [uint32]2684354563 } else { $null }) } }
        foreach ($typed in '\\fs01\Data\HR\', '\\fs01\Data\HR\\Sub', '\\fs01\Data\\HR') {
            $t = Get-ChangeTarget -Path $typed -WholeTree
            $t.Ok | Should -BeFalse -Because "$typed is behind the junction \\fs01\D$\Shares on the server"
            $t.Refusal | Should -Match ([regex]::Escape('\\fs01\D$\Shares'))
            $t.Refusal | Should -Match '(?i)junction'
        }
    }

    It 'AC52_AServerPathThatIsNotAFolderOnADriveIsRefusedNotAllowed' {
        Mock Get-AppReparseInfo { [PSCustomObject]@{ Exists = $true; IsReparsePoint = $false; Tag = $null } }
        Get-ServerSideLinkRefusal -Server 'fs01' -ServerPath '\\fs01\D$\Shares\Data\' | Should -BeNullOrEmpty -Because 'a trailing \ is the same folder'
        Get-ServerSideLinkRefusal -Server 'fs01' -ServerPath '\\fs01\Data\HR' | Should -Not -BeNullOrEmpty -Because 'a guard that cannot read the path fails closed'
        Get-ServerSideLinkRefusal -Server 'fs01' -ServerPath '\\fs01\D$' | Should -BeNullOrEmpty -Because 'the drive root has no folder to check (D-036 refuses it already)'
        Get-ServerSideLinkRefusal -Server 'fs01' -ServerPath '\\fs01\D$\' | Should -BeNullOrEmpty
    }

    # M3: a Copy target is checked where Windows really reaches it.
    It 'AC50_CopyTargetThatLeadsToAProtectedFolderIsRefused' {
        $dir = New-Folder 'CopyIntoJunction'
        $script:Dir50 = $dir
        foreach ($real in '\\?\C:\Users', "\\?\$env:SystemRoot") {
            $script:Real50 = $real
            Mock Get-Win32PathName { if ($Kind -eq 'Final' -and $Path -eq $script:Dir50) { $script:Real50 } else { $Path } }
            $t = Get-ChangeTarget -Path $dir -RefuseProtected
            $t.Ok | Should -BeFalse -Because "$dir is a junction to $real"
            $t.Refusal | Should -Match ([regex]::Escape($real.Substring(4)))
            $t.Refusal | Should -Match "can't be copied"
        }
        # 8.3 names of a Windows folder and of System Volume Information.
        Mock Get-Win32PathName { if ($Kind -eq 'Long' -and $Path -eq 'C:\PROGRA~1') { $env:ProgramFiles } elseif ($Kind -eq 'Long' -and $Path -eq 'D:\SYSTEM~1') { 'D:\System Volume Information' } else { $Path } }
        foreach ($short in 'C:\PROGRA~1', 'D:\SYSTEM~1') {
            (Get-ChangeTarget -Path $short -RefuseProtected).Ok | Should -BeFalse -Because "$short is a short name of a protected folder"
        }
        # A target whose final path cannot be told fails closed.
        Mock Get-Win32PathName { $null }
        $f = Get-ChangeTarget -Path $dir -RefuseProtected
        $f.Ok | Should -BeFalse
        $f.Refusal | Should -Match '(?i)could not tell where'
        # Through the Copy flow: refused, no confirm, no task.
        Mock Get-Win32PathName { if ($Kind -eq 'Final' -and $Path -eq $script:Dir50) { '\\?\C:\Users' } else { $Path } }
        $script:Captured = $null; $script:Shown.Clear(); $script:Confirms.Clear()
        Invoke-CopyPermissions -TargetText $dir
        $script:Captured | Should -BeNullOrEmpty
        $script:Confirms.Count | Should -Be 0
        @($script:Shown | Where-Object { $_ -match [regex]::Escape('C:\Users') }).Count | Should -Be 1
        # An ordinary folder that is where it says still copies.
        Mock Get-Win32PathName { $Path }
        (Get-ChangeTarget -Path $dir -RefuseProtected).Ok | Should -BeTrue
    }

    # M4 and m7: check on the server first, then a full, per-item backup path.
    It 'AC53b_OrphanNextStepChecksOnTheServerBeforeTheIcaclsCommands' {
        $sid = 'S-1-5-21-1-2-3-1009'
        Mock ConvertTo-SidAccountName { $null }
        $r = Get-RemoveIdentityProblem -Identity $sid -Sid $sid -Path @('\\fs01\Data\HR') -Type Allow
        $r.Problem | Should -Match ([regex]::Escape("Windows can't look up this account from here (it may be deleted, or local to the server)"))
        $check = $r.Problem.IndexOf('on the server itself')
        $check | Should -BeGreaterThan -1 -Because 'the senior admin looks at the entry on the server first'
        $save = $r.Problem.IndexOf('/save ')
        $check | Should -BeLessThan $save -Because 'the check comes before the icacls commands'
        $r.Problem.IndexOf('/remove:g') | Should -BeGreaterThan $check
        $r.Problem | Should -Match '(?i)do not remove it'
        $r.Problem | Should -Match ([regex]::Escape("Only if it still shows as $sid there"))
    }

    It 'AC53b_IcaclsBackupFileIsAFullPerItemTimestampedPath' {
        $sid = 'S-1-5-21-1-2-3-1009'
        Mock ConvertTo-SidAccountName { $null }
        $r = Get-RemoveIdentityProblem -Identity $sid -Sid $sid -Path @('D:\Data\HR') -Type Allow
        $r.Problem | Should -Match 'icacls "D:\\Data\\HR" /save "%USERPROFILE%\\acl-backup-HR-\d{4}-\d{2}-\d{2}_\d{6}\.txt"'
        $r.Problem | Should -Match 'icacls "D:\\Data" /restore "%USERPROFILE%\\acl-backup-HR-\d{4}-\d{2}-\d{2}_\d{6}\.txt"' -Because 'it is put back on the folder above'
        # A drive root is written D:\. so the closing quote is not escaped by a backslash.
        $root = Get-RemoveIdentityProblem -Identity $sid -Sid $sid -Path @('D:\') -Type Deny
        $root.Problem | Should -Match ([regex]::Escape('icacls "D:\." /save "%USERPROFILE%\acl-backup-'))
        $root.Problem | Should -Match ([regex]::Escape('icacls "D:\." /remove:d *' + $sid))
        $root.Problem | Should -Not -Match ([regex]::Escape('\"'))
        Format-IcaclsPathArgument -Path '\\fs01\Data\' | Should -Be '\\fs01\Data'
        $readme = Get-Content -LiteralPath (Join-Path $script:Root 'README.md') -Raw
        $readme | Should -Match '(?s)account SIDs and paths.{0,40}delete it once the ticket is closed'
    }

    # m5: the renamed case does not say the account may be deleted.
    It 'SQ018R2_RenamedAccountWordingDoesNotContradictItself' {
        Mock ConvertTo-IdentitySid { $null }
        Mock ConvertTo-SidAccountName { 'CONTOSO\HR-Team' }
        $r = Get-RemoveIdentityProblem -Identity 'CONTOSO\HR' -Sid 'S-1-5-21-1-2-3-1001' -Path @('D:\Data') -Type Allow
        $r.Problem | Should -Match ([regex]::Escape("Windows can't find CONTOSO\HR any more; the account of the entry you chose"))
        $r.Problem | Should -Match ([regex]::Escape('is now called CONTOSO\HR-Team (it may have been renamed)'))
        $r.Problem | Should -Not -Match 'may be deleted'
        $r.Problem | Should -Match 'Nothing was changed|nothing was changed'
    }

    # m2: Copy fails closed when the source's entries could not be checked.
    It 'AC48_CopyConfirmsWhenTheSourceCouldNotBeChecked_<Case>' -ForEach @(
        @{ Case = 'NotLoaded' }
        @{ Case = 'LoadFailed' }
        @{ Case = 'AnotherFolder' }
        @{ Case = 'AnotherSource' }
    ) {
        $source = New-FakeTarget -Display $script:Current.DisplayPath -Resolved $script:Current.RealPath
        switch ($Case) {
            'NotLoaded' { $script:ViewState.FolderPermissions = $null }
            'LoadFailed' { $script:ViewState.FolderPermissions = [PSCustomObject]@{ Ok = $false; Path = $script:Current.RealPath; Rows = @() } }
            'AnotherFolder' { $script:ViewState.FolderPermissions = [PSCustomObject]@{ Ok = $true; Path = 'D:\Elsewhere'; Rows = @() } }
            'AnotherSource' { $source = New-FakeTarget -Display 'H:\Other' -Resolved $script:Current.RealPath }
        }
        $target = New-FakeTarget -Display 'D:\Data\Other'
        Invoke-CopyPermissions -Source $source -Targets @($target)
        $script:Confirms.Count | Should -Be 1 -Because "the source's own entries could not be checked ($Case)"
        $script:AtConfirm[0] | Should -BeNullOrEmpty
        $script:Confirms[0].IsDestructive | Should -BeTrue
        $script:Confirms[0].Body | Should -Match 'could not be checked'
        $script:Captured | Should -Not -BeNullOrEmpty

        $script:Captured = $null; $script:Confirms.Clear(); $script:ConfirmAnswer = $false
        Invoke-CopyPermissions -Source $source -Targets @($target)
        $script:Confirms.Count | Should -Be 1
        $script:Captured | Should -BeNullOrEmpty -Because 'declined: no task starts'
    }

    # m3: a root that is only the typed path is not called the root of a drive.
    It 'AC49_ConfirmRootTextForAMappedDriveRootNamesTheRealFolder' {
        $t = New-FakeTarget -Display 'H:\' -Resolved '\\fs01\Data\Dept'
        $text = Get-ConfirmRootText -Targets @($t)
        $text | Should -Match ([regex]::Escape('H:\ (the top of the mapped drive H:, really \\fs01\Data\Dept)'))
        $text | Should -Not -Match ([regex]::Escape('\\fs01\Data\Dept is the root of a whole drive'))
        # A real root still says what it is.
        Get-ConfirmRootText -Targets @((New-FakeTarget -Display 'D:\')) | Should -Match ([regex]::Escape('D:\ is the root of a whole drive'))
        # The confirm for an Add there carries it, destructive.
        Invoke-AddPermission -Scope Folder -Identity 'CONTOSO\HR' -Rights 'Modify' -Type 'Allow' -Targets @($t)
        $script:Confirms[0].IsDestructive | Should -BeTrue
        $script:Confirms[0].Body | Should -Match ([regex]::Escape('the top of the mapped drive H:'))
    }

    # m6: Deny wording follows the canonical ACE order.
    It 'AC47_DenyWarningDoesNotOverstateDeny' {
        $spec = Get-ConfirmSpec -Action AddPermission -Targets @((New-FakeTarget -Display 'D:\Data\HR')) -Detail 'Deny Modify for CONTOSO\Temps' -Type Deny
        $spec.Body | Should -Match ([regex]::Escape('A Deny blocks access even where another permission on the same folder allows it.'))
        $spec.Body | Should -Match ([regex]::Escape('a permission set directly on a subfolder can still allow access there'))
        $spec.Body | Should -Not -Match 'reaches every subfolder'
        Get-Content -LiteralPath $script:AppPath -Raw | Should -Match ([regex]::Escape('https://learn.microsoft.com/windows/win32/secauthz/order-of-aces-in-a-dacl'))
    }

    # m8: IPC$ is not a folder.
    It 'AC50_IpcShareRefusalSaysItIsNotAFolder' {
        $text = Get-CopyTargetRefusal -Path '\\fs01\IPC$'
        $text | Should -Match 'it is not a folder'
        $text | Should -Match 'Choose the folder that needs these permissions instead'
        $text | Should -Not -Match 'let people into it'
    }

    # m9: the second refusal check says how many more were refused.
    It 'AC50_SecondCheckCountsTheRefusalsItDoesNotList' {
        $source = New-FakeTarget -Display $script:Current.DisplayPath
        $targets = @('\\fs01\ADMIN$', '\\fs01\SYSVOL', '\\fs01\NETLOGON', '\\fs01\PRINT$', '\\fs01\IPC$' | ForEach-Object { New-FakeTarget -Display $_ })
        Invoke-CopyPermissions -Source $source -Targets $targets
        $script:Captured | Should -BeNullOrEmpty
        $script:Shown.Count | Should -Be 1
        $script:Shown[0] | Should -Match 'and 2 more'
    }

    # SQ-022 AC10 (D-052): the core refuses a source with Deny entries unless -AllowDeny is passed,
    # so the app passes it only after the Deny confirm was accepted. The captured work block is run
    # in this session (as Complete-Captured does) with Copy-FolderPermission mocked.
    It 'AC10_AppPassesAllowDenyOnlyAfterTheDenyConfirm_<Case>' -ForEach @(
        @{ Case = 'ExplicitDeny'; Expect = $true }
        @{ Case = 'DenyUnchecked'; Expect = $true }
        @{ Case = 'PlainCopy'; Expect = $false }
    ) {
        switch ($Case) {
            'ExplicitDeny' { New-ViewRows -Row @((New-ViewRow -Identity 'BUILTIN\Users'), (New-ViewRow -Identity 'CONTOSO\Temps' -Type Deny -Rights 'Write')) }
            'DenyUnchecked' { $script:ViewState.FolderPermissions = $null }
            'PlainCopy' { New-ViewRows -Row @((New-ViewRow -Identity 'BUILTIN\Users')) }
        }
        $dest = New-Folder ('Ac10Dest-' + $Case)
        $source = New-FakeTarget -Display $script:Current.DisplayPath -Resolved $script:Current.RealPath
        $script:CopyCalls10 = [System.Collections.Generic.List[object]]::new()
        Mock Copy-FolderPermission {
            $script:CopyCalls10.Add(@{ Keys = @($PSBoundParameters.Keys); AllowDeny = $PSBoundParameters['AllowDeny'] })
            foreach ($t in $TargetPath) { New-Row -Action 'Copy permissions' -Target $t -Detail "Copied from $($SourcePath): Allow Modify for BUILTIN\Users" }
        }
        Mock Get-Acl { New-FakeAcl }

        Invoke-CopyPermissions -Source $source -Targets @((New-FakeTarget -Display $dest))

        $script:Confirms.Count | Should -Be $(if ($Expect) { 1 } else { 0 }) -Because 'only the Deny cases show the destructive confirm'
        $script:Captured | Should -Not -BeNullOrEmpty
        $null = Complete-Captured
        $script:CopyCalls10.Count | Should -Be 1
        $passed = ($script:CopyCalls10[0].Keys -contains 'AllowDeny') -and [bool]$script:CopyCalls10[0].AllowDeny
        $passed | Should -Be $Expect -Because "-AllowDeny follows the accepted Deny confirm ($Case)"
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
    }
}

Describe 'Revision 3 (owner lab test, 2026-10-19): .\name, account lookup in the dialog, dry-run result (AC55-AC57)' {
    # Pinned for the implementer (the spec leaves the names open; stubs carry these signatures):
    #   Resolve-AddIdentity -Identity <typed text> -Targets <Get-ChangeTarget results>
    #       -> Ok, Identity, Problem.  ".\name" -> "<COMPUTERNAME>\name" when every target IsLocal;
    #       refused (Ok = $false) for any target that is not local (UNC path, mapped drive);
    #       any other text is returned unchanged.
    #   Find-PermissionAccount -Identity <text> [-Lookup { param($identity) -> SID text or $null }] [-TimeoutMilliseconds]
    #       -> Found, Sid, TimedOut, Problem.  -Lookup is the test seam; the default is the app's own
    #       lookup (ConvertTo-IdentitySid), which must not freeze the window.
    #   Show-PermissionDialog gains -Targets; its Add click calls Resolve-AddIdentity and then
    #       Find-PermissionAccount before it sets Tag.Answer and DialogResult.
    #   Get-DryRunSummary -Entries <core rows, all 'Skipped (WhatIf)'> -> Title, Text.
    #   Complete-ChangeTask shows that text with Show-AppMessage when every row was a dry run.
    # The WPF dialog is never opened: its wiring is checked on the syntax tree.

    BeforeEach {
        $script:Me = $env:COMPUTERNAME
    }

    It 'AC55_DotBackslashOnLocalTargetsUsesTheComputerName' {
        $local = New-FakeTarget -Display 'D:\Data\HR' -Local $true
        $r = Resolve-AddIdentity -Identity '.\micha' -Targets @($local)
        $r.Ok | Should -BeTrue
        $r.Identity | Should -BeExactly "$($script:Me)\micha"
        $r.Problem | Should -BeNullOrEmpty

        $files = @((New-FakeTarget -Display 'D:\Data\a.txt' -Local $true), (New-FakeTarget -Display 'D:\Data\b.txt' -Local $true))
        (Resolve-AddIdentity -Identity '  .\micha  ' -Targets $files).Identity | Should -BeExactly "$($script:Me)\micha" -Because 'surrounding spaces are trimmed'
    }

    It 'AC55_DotBackslashOnNetworkTargetsIsRefusedInPlace' {
        $text = "Type the server's name instead, for example FS01\name."
        $unc = New-FakeTarget -Display '\\fs01\share\HR' -Local $false
        $mapped = New-FakeTarget -Display 'H:\HR' -Resolved '\\fs01\home\HR' -Local $false
        $mixed = @((New-FakeTarget -Display 'D:\Data\a.txt' -Local $true), $unc)
        foreach ($case in @(@{ N = 'UNC path'; T = @($unc) }, @{ N = 'mapped drive'; T = @($mapped) }, @{ N = 'one network target among local ones'; T = $mixed })) {
            $r = Resolve-AddIdentity -Identity '.\micha' -Targets $case.T
            $r.Ok | Should -BeFalse -Because $case.N
            $r.Problem | Should -BeExactly $text -Because $case.N
        }
    }

    It 'AC55_OtherNamesAreUnchanged' {
        $local = New-FakeTarget -Display 'D:\Data\HR' -Local $true
        $unc = New-FakeTarget -Display '\\fs01\share\HR' -Local $false
        foreach ($t in @($local, $unc)) {
            foreach ($name in 'micha', 'CONTOSO\HR-Staff', 'BUILTIN\Users', 'micha@contoso.com', "$($script:Me)\micha") {
                $r = Resolve-AddIdentity -Identity $name -Targets @($t)
                $r.Ok | Should -BeTrue -Because "$name on $($t.DisplayPath)"
                $r.Identity | Should -BeExactly $name -Because "$name on $($t.DisplayPath)"
            }
        }
    }

    It 'AC55_AddUsesTheComputerNameOnALocalFolder' {
        $dir = New-Folder 'DotLocal'
        Invoke-AddPermission -Scope Folder -Identity '.\micha' -Rights 'Modify' -Type 'Allow' -Targets @((New-FakeTarget -Display $dir -Local $true))
        $script:Captured | Should -Not -BeNullOrEmpty -Because 'the change starts'
        $script:Captured.ArgumentList[1] | Should -BeExactly "$($script:Me)\micha" -Because 'the account is added under the computer name'
    }

    It 'AC55_AddRefusesDotBackslashOnANetworkFolder' {
        Invoke-AddPermission -Scope Folder -Identity '.\micha' -Rights 'Modify' -Type 'Allow' -Targets @((New-FakeTarget -Display '\\fs01\share\HR' -Local $false))
        Should -Invoke Start-ChangeTask -Times 0 -Exactly
        (Get-LastStatus).Text | Should -Match ([regex]::Escape("Type the server's name instead, for example FS01\name."))
    }

    It 'AC55_AddDialogChecksTheNameBeforeItCloses' {
        $fn = $script:Ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Show-PermissionDialog' }, $true)
        $names = @($fn.Body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        $names | Should -Contain 'Targets' -Because 'the dialog needs the targets to know if they are local'
        $resolve = @($fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Resolve-AddIdentity' }, $true))
        $resolve.Count | Should -BeGreaterThan 0 -Because 'the dialog resolves .\name'
        $close = @($fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [System.Management.Automation.Language.MemberExpressionAst] -and "$($n.Left.Member.Value)" -eq 'DialogResult' }, $true))
        $close.Count | Should -BeGreaterThan 0
        foreach ($c in $resolve) { $c.Extent.StartOffset | Should -BeLessThan $close[0].Extent.StartOffset }

        $open = $script:Ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Open-AddPermission' }, $true)
        $call = @($open.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Show-PermissionDialog' }, $true))
        $call.Count | Should -Be 1
        @($call[0].CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'Targets' }).Count | Should -Be 1 -Because 'Open-AddPermission hands the dialog its targets'
    }

    It 'AC56_UnknownAccountKeepsTheDialogOpenWithTheMessage' {
        $r = Find-PermissionAccount -Identity 'CONTOSO\nobody' -Lookup { param($identity) $null }
        $r.Found | Should -BeFalse
        $r.Problem | Should -BeExactly 'Windows could not find the account CONTOSO\nobody. Check the name, or ask a senior admin.'
    }

    It 'AC56_KnownAccountIsFoundAndTheNameIsPassedToTheLookup' {
        $r = Find-PermissionAccount -Identity 'CONTOSO\HR-Staff' -Lookup { param($identity) "S-FAKE-$identity" }
        $r.Found | Should -BeTrue
        $r.Sid | Should -BeExactly 'S-FAKE-CONTOSO\HR-Staff'
        $r.Problem | Should -BeNullOrEmpty
    }

    It 'AC56_ALookupThatThrowsCountsAsNotFound' {
        $r = Find-PermissionAccount -Identity 'CONTOSO\broken' -Lookup { param($identity) throw 'The trust relationship failed' }
        $r.Found | Should -BeFalse
        $r.Problem | Should -Match ([regex]::Escape('Windows could not find the account CONTOSO\broken.'))
    }

    It 'AC56_AnUnreachableDomainDoesNotFreezeTheWindow' {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = Find-PermissionAccount -Identity 'GHOSTDOMAIN\someone' -TimeoutMilliseconds 300 -Lookup { param($identity) Start-Sleep -Seconds 10; 'S-FAKE-LATE' }
        $sw.Stop()
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 5 -Because 'the lookup is cut off, not waited for'
        $r.Found | Should -BeFalse
        $r.TimedOut | Should -BeTrue
        $r.Problem | Should -Not -BeNullOrEmpty
    }

    It 'AC56_TheDefaultTimeoutIsShortAndTheDialogChecksBeforeItCloses' {
        $find = $script:Ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Find-PermissionAccount' }, $true)
        $timeout = @($find.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'TimeoutMilliseconds' })
        $timeout.Count | Should -Be 1
        [int]"$($timeout[0].DefaultValue.Extent.Text)" | Should -BeLessOrEqual 5000

        $fn = $script:Ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Show-PermissionDialog' }, $true)
        $lookups = @($fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Find-PermissionAccount' }, $true))
        $lookups.Count | Should -BeGreaterThan 0 -Because 'Add looks the account up before the dialog closes'
        $close = @($fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [System.Management.Automation.Language.MemberExpressionAst] -and "$($n.Left.Member.Value)" -eq 'DialogResult' }, $true))
        $close.Count | Should -BeGreaterThan 0
        foreach ($c in $lookups) { $c.Extent.StartOffset | Should -BeLessThan $close[0].Extent.StartOffset }
        $answer = @($fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and "$($n.Left.Extent.Text)" -match 'Tag\.Answer' }, $true))
        $answer.Count | Should -BeGreaterThan 0
        foreach ($c in $lookups) { $c.Extent.StartOffset | Should -BeLessThan $answer[0].Extent.StartOffset -Because 'nothing is answered before the account is found' }
    }

    It 'AC57_DryRunCountsUseTheRightPlural' {
        function script:Get-DryMessage { param([string]$Type, [int]$Count) Get-ChangeResultMessage -Entries @(1..$Count | ForEach-Object { New-Row -Result 'Skipped (WhatIf)' -ItemType $Type -Target "C:\x$_" }) -LogPath $null -LogFolder 'C:\logs' }
        Get-DryMessage -Type Folder -Count 1 | Should -BeExactly 'WhatIf: nothing was changed (1 folder would be).'
        Get-DryMessage -Type Folder -Count 2 | Should -BeExactly 'WhatIf: nothing was changed (2 folders would be).'
        Get-DryMessage -Type File -Count 1 | Should -BeExactly 'WhatIf: nothing was changed (1 file would be).'
        Get-DryMessage -Type File -Count 3 | Should -BeExactly 'WhatIf: nothing was changed (3 files would be).'
        Get-DryMessage -Type Unknown -Count 1 | Should -BeExactly 'WhatIf: nothing was changed (1 item would be).'
        Get-DryMessage -Type Unknown -Count 2 | Should -BeExactly 'WhatIf: nothing was changed (2 items would be).'
    }

    It 'AC57_RealResultCountsUseTheRightPlural' {
        # Review round 1: AC57 covers real results too, not only dry runs.
        function script:Get-RealMessage { param([object[]]$Rows) Get-ChangeResultMessage -Entries $Rows -LogPath 'C:\logs\change.csv' -LogFolder 'C:\logs' }
        $copy = { param($n) @((New-Row -Action 'Copy permissions' -Target 'E:\Done' -Result 'Done')) + @(1..$n | ForEach-Object { New-Row -Action 'Copy permissions' -Target "E:\Same$_" -Result 'Skipped (nothing to copy)' }) }
        $one = Get-RealMessage -Rows (& $copy 1)
        $two = Get-RealMessage -Rows (& $copy 2)
        $one | Should -Match ([regex]::Escape(' 1 folder already had these permissions and was not changed.'))
        $two | Should -Match ([regex]::Escape(' 2 folders already had these permissions and were not changed.'))

        $tree = { param($n) Get-RealMessage -Rows @(New-TreeRow -Result 'Done' -Counts @{ Unlisted = $n; UnlistedFolders = @(1..$n | ForEach-Object { "C:\x\locked$_" }); Unchecked = $n }) }
        $tree1 = & $tree 1
        $tree2 = & $tree 2
        $tree1 | Should -Match ([regex]::Escape('Escalate: 1 folder could not be opened'))
        $tree2 | Should -Match ([regex]::Escape('Escalate: 2 folders could not be opened'))
        $tree1 | Should -Match ([regex]::Escape('1 item could not be read after the change, so it is not known who owns it now; check it.'))
        $tree2 | Should -Match ([regex]::Escape('2 items could not be read after the change, so it is not known who owns them now; check them.'))

        $unreadable = { param($n) Get-RealMessage -Rows @(1..$n | ForEach-Object { New-Row -Action 'Take ownership' -Target "C:\x$_" -Result 'Done' -OldValue 'Could not read' }) }
        & $unreadable 1 | Should -Match ([regex]::Escape('1 item had no readable permissions before the change'))
        & $unreadable 2 | Should -Match ([regex]::Escape('2 items had no readable permissions before the change'))

        foreach ($m in $one, $two, $tree1, $tree2) { $m | Should -Not -Match '\(s\)' -Because 'every count picks its own word' }
    }

    It 'AC57_LinkCountsUseTheRightPlural' {
        Mock Get-LinkKind { 'junction' }
        (Get-LinkListText -LinkPaths @('C:\x\j1')).Noun | Should -BeExactly '1 junction or symbolic link'
        (Get-LinkListText -LinkPaths @('C:\x\j1', 'C:\x\j2')).Noun | Should -BeExactly '2 junctions or symbolic links'
    }

    It 'AC55_ReviewFix_DriveLetterTargetIsLocalOnlyWhenTheDriveItselfIsThisComputers' {
        # H: is not in the drive map (mapped after the app started), so the target lookup did not
        # mark it IsLocal; the drive's own type decides, and a drive that cannot be read refuses.
        $text = "Type the server's name instead, for example FS01\name."
        $h = New-FakeTarget -Display 'H:\HR' -Local $false

        Mock Get-DriveLetterType { 'Network' }
        $r = Resolve-AddIdentity -Identity '.\micha' -Targets @($h)
        $r.Ok | Should -BeFalse -Because 'H: is a network drive'
        $r.Problem | Should -BeExactly $text
        Should -Invoke Get-DriveLetterType -Times 1 -Exactly -Scope It -ParameterFilter { $Letter -eq 'H' }

        foreach ($other in 'Unknown', 'NoRootDirectory', 'CDRom', '') {
            Mock Get-DriveLetterType { $other }.GetNewClosure()
            (Resolve-AddIdentity -Identity '.\micha' -Targets @($h)).Ok | Should -BeFalse -Because "DriveType '$other' is not this computer's own disk"
        }

        Mock Get-DriveLetterType { throw 'The drive could not be read' }
        $r = Resolve-AddIdentity -Identity '.\micha' -Targets @($h)
        $r.Ok | Should -BeFalse -Because 'a drive that cannot be read is refused (fail closed)'
        $r.Problem | Should -BeExactly $text

        foreach ($own in 'Fixed', 'Removable') {
            Mock Get-DriveLetterType { $own }.GetNewClosure()
            $r = Resolve-AddIdentity -Identity '.\micha' -Targets @($h)
            $r.Ok | Should -BeTrue -Because "DriveType $own is this computer's own drive"
            $r.Identity | Should -BeExactly "$($script:Me)\micha"
        }
    }

    It 'AC56_ReviewFix_MessagesNameWhatWasTypedAndWhatWasLookedUp' {
        $r = Find-PermissionAccount -Identity 'PC01\micha' -TypedIdentity '.\micha' -Lookup { param($identity) $null }
        $r.Found | Should -BeFalse
        $r.Problem | Should -BeExactly 'Windows could not find the account .\micha (looked up as PC01\micha). Check the name, or ask a senior admin.'

        $t = Find-PermissionAccount -Identity 'PC01\micha' -TypedIdentity '.\micha' -TimeoutMilliseconds 300 -Lookup { param($identity) Start-Sleep -Seconds 10; 'S-FAKE-LATE' }
        $t.TimedOut | Should -BeTrue
        $t.Problem | Should -Match ([regex]::Escape('the account .\micha (looked up as PC01\micha) in time'))

        $same = Find-PermissionAccount -Identity 'CONTOSO\nobody' -TypedIdentity '  CONTOSO\nobody ' -Lookup { param($identity) $null }
        $same.Problem | Should -BeExactly 'Windows could not find the account CONTOSO\nobody. Check the name, or ask a senior admin.' -Because 'nothing is added when the typed name is the one looked up'

        $fn = $script:Ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Show-PermissionDialog' }, $true)
        $lookup = @($fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Find-PermissionAccount' }, $true))
        $lookup.Count | Should -Be 1
        @($lookup[0].CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'TypedIdentity' }).Count | Should -Be 1 -Because 'the dialog hands over what the tech typed'
    }

    It 'AC56_ReviewFix_TheDialogShowsItIsBusyBeforeTheLookupAndRestoresAfter' {
        $fn = $script:Ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Show-PermissionDialog' }, $true)
        $lookup = @($fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Find-PermissionAccount' }, $true))[0]
        $try = $lookup.Parent
        while ($try -and $try -isnot [System.Management.Automation.Language.TryStatementAst]) { $try = $try.Parent }
        $try | Should -Not -BeNullOrEmpty -Because 'the lookup runs in a try whose finally restores the dialog'
        $before = $fn.Extent.Text.Substring(0, $try.Extent.StartOffset - $fn.Extent.StartOffset)
        $before | Should -Match '\$s\.IsEnabled\s*=\s*\$false' -Because 'Add is disabled before the wait'
        $before | Should -Match '\$cancel\.IsEnabled\s*=\s*\$false' -Because 'Cancel is disabled before the wait'
        $before | Should -Match "Content\s*=\s*'Checking\.\.\.'"
        $before | Should -Match '\[System\.Windows\.Input\.Mouse\]::OverrideCursor\s*=\s*\[System\.Windows\.Input\.Cursors\]::Wait'
        $body = $try.Body.Extent.Text
        $body | Should -Match 'DispatcherPriority\]::Render' -Because 'the busy state is painted before the wait'
        $body.IndexOf('DispatcherPriority]::Render') | Should -BeLessThan $body.IndexOf('Find-PermissionAccount')
        $finally = $try.Finally.Extent.Text
        $finally | Should -Match '\[System\.Windows\.Input\.Mouse\]::OverrideCursor\s*=\s*\$null'
        $finally | Should -Match '\$s\.Content\s*=\s*\$label'
        $finally | Should -Match '\$s\.IsEnabled\s*=\s*\$true'
        $finally | Should -Match '\$cancel\.IsEnabled\s*=\s*\$true'
    }

    It 'AC57_DryRunSummaryNamesWhatWouldChangeAndWhere' {
        $cases = @(
            @{ N = 'add'; Rows = @(New-Row -Action 'Add permission' -Target 'D:\Data\HR' -Detail 'Allow Modify for CONTOSO\HR-Staff' -Result 'Skipped (WhatIf)'); Has = @('CONTOSO\HR-Staff', 'Modify', 'Allow', 'D:\Data\HR', 'add') }
            @{ N = 'add deny'; Rows = @(New-Row -Action 'Add permission' -Target 'D:\Data\HR' -Detail 'Deny Write for CONTOSO\Temps' -Result 'Skipped (WhatIf)'); Has = @('CONTOSO\Temps', 'Write', 'Deny', 'D:\Data\HR') }
            @{ N = 'remove'; Rows = @(New-Row -Action 'Remove permission' -Target 'D:\Data\HR' -Detail 'Allow Modify for CONTOSO\HR-Staff' -Result 'Skipped (WhatIf)'); Has = @('CONTOSO\HR-Staff', 'Allow', 'D:\Data\HR', 'remove') }
            @{ N = 'take ownership'; Rows = @(New-Row -Action 'Take ownership' -Target 'D:\Data\HR' -Detail 'Owner set to me' -Result 'Skipped (WhatIf)'); Has = @('D:\Data\HR', 'ownership') }
            @{ N = 'copy to two folders'; Rows = @((New-Row -Action 'Copy permissions' -Target 'E:\One' -Detail 'Added Modify for CONTOSO\HR' -Result 'Skipped (WhatIf)'), (New-Row -Action 'Copy permissions' -Target 'E:\Two' -Detail 'Added Modify for CONTOSO\HR' -Result 'Skipped (WhatIf)')); Has = @('E:\One', 'E:\Two', 'copy') }
        )
        foreach ($c in $cases) {
            $s = Get-DryRunSummary -Entries $c.Rows
            $s.Title | Should -Match '(?i)dry run' -Because $c.N
            $s.Text | Should -Match '(?i)nothing was changed' -Because $c.N
            foreach ($piece in $c.Has) { $s.Text | Should -Match "(?i)$([regex]::Escape($piece))" -Because "$($c.N): the result names '$piece'" }
            $s.Text | Should -Not -Match '\b1 (folders|files|items)\b' -Because $c.N
        }
    }

    It 'AC57_AFinishedDryRunShowsTheResultNotOnlyTheStatusLine' {
        $row = New-Row -Action 'Add permission' -Target 'D:\Data\HR' -Detail 'Allow Modify for CONTOSO\HR-Staff' -Result 'Skipped (WhatIf)'
        $result = [PSCustomObject]@{ Ok = $true; Entries = @($row); LogPath = $null; UnloggedPath = $null; Message = 'WhatIf: nothing was changed (1 folder would be).'; Error = $null }
        Complete-ChangeTask -Result $result -State $null
        $script:Shown.Count | Should -Be 1 -Because 'one dry-run result is shown'
        $script:Shown[0] | Should -Match ([regex]::Escape('CONTOSO\HR-Staff'))
        $script:Shown[0] | Should -Match ([regex]::Escape('D:\Data\HR'))
        $script:Shown[0] | Should -Match '(?i)nothing was changed'
        (Get-LastStatus).Kind | Should -Be 'Info'
        (Get-LastStatus).Text | Should -Match 'WhatIf: nothing was changed \(1 folder would be\)\.'
    }

    It 'AC57_ARealChangeShowsNoDryRunResult' {
        $row = New-Row -Action 'Add permission' -Target 'D:\Data\HR' -Detail 'Allow Modify for CONTOSO\HR-Staff' -Result 'Done'
        $result = [PSCustomObject]@{ Ok = $true; Entries = @($row); LogPath = 'C:\logs\change.csv'; UnloggedPath = $null; Message = 'Added Allow Modify for CONTOSO\HR-Staff on D:\Data\HR.'; Error = $null }
        Complete-ChangeTask -Result $result -State $null
        $script:Shown.Count | Should -Be 0
        (Get-LastStatus).Kind | Should -Be 'Success'
    }

    It 'AC57_DryRunEndToEndAddAndTakeOwnership' {
        $script:WhatIfMode = $true
        $dir = New-Folder 'DryRunE2E'
        $script:Current = [PSCustomObject]@{ DisplayPath = $dir; RealPath = $dir }
        Mock Get-Acl { New-FakeAcl }
        $actions = [ordered]@{
            'add'            = { Invoke-AddPermission -Scope Folder -Identity 'BUILTIN\Users' -Rights 'Modify' -Type 'Allow' }
            'take ownership' = { Invoke-TakeOwnership -Scope Folder }
        }
        foreach ($name in $actions.Keys) {
            $script:Captured = $null; $script:Shown.Clear()
            & $actions[$name]
            $null = Complete-Captured
            $script:Shown.Count | Should -Be 1 -Because "$name shows a dry-run result"
            $script:Shown[0] | Should -Match ([regex]::Escape($dir)) -Because $name
            $script:Shown[0] | Should -Match '(?i)nothing was changed' -Because $name
        }
        $script:Shown.Clear(); $script:Captured = $null
        & $actions['add']
        $null = Complete-Captured
        foreach ($piece in 'BUILTIN\Users', 'Modify', 'Allow') { $script:Shown[0] | Should -Match ([regex]::Escape($piece)) }
        @($script:BackstopHit).Count | Should -Be 0
    }
}
}
