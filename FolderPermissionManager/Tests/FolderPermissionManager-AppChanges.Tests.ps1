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

    $script:WhatIfMode = $false
    $script:ChangeTask = $null
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
        $last.Text | Should -Match ([regex]::Escape('Escalate: 2 folder(s) could not be opened'))

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
        $copyTargets = @('\\fs01\A', '\\fs01\B') | ForEach-Object { New-FakeTarget -Display $_ }
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
            @{ Name = 'unrestorable items'; Entries = @((New-Row -Result 'Done' -OldValue 'Could not read')); Log = $log; Msg = 'Took ownership. 1 item(s) cannot be restored.'; Kind = 'Warning'; Text = 'Done, with items to check: Took ownership. 1 item(s) cannot be restored.' }
            @{ Name = 'tree partly done'; Entries = @((New-TreeRow -Result 'Partly done' -Counts @{ Unlisted = 2; UnlistedFolders = @('a', 'b') })); Log = $log; Msg = 'Took ownership of C:\x and every subfolder and file that could be opened. Escalate: 2 folder(s) could not be opened.'; Kind = 'Warning'; Text = 'Done, with items to check: Took ownership of C:\x and every subfolder and file that could be opened. Escalate: 2 folder(s) could not be opened.' }
            @{ Name = 'tree partly done, message already says so'; Entries = @((New-TreeRow -Result 'Partly done' -Counts @{ NotOwned = 1 })); Log = $log; Msg = 'Partly done: took ownership but not on every item.'; Kind = 'Warning'; Text = 'Partly done: took ownership but not on every item.' }
            @{ Name = 'tree incomplete'; Entries = @((New-TreeRow -Result 'Done' -Counts @{ Unchecked = 2 })); Log = $log; Msg = 'Took ownership. 2 item(s) could not be read after the change.'; Kind = 'Warning'; Text = 'Done, with items to check: Took ownership. 2 item(s) could not be read after the change.' }
            @{ Name = 'tree failed'; Entries = @((New-TreeRow -Result 'Failed' -NewValue '' -ErrorText 'Nothing was changed.')); Log = $log; Msg = 'Could not take ownership.'; Kind = 'Error'; Text = 'Could not take ownership.' }
            @{ Name = 'nothing to copy'; Entries = @((New-Row -Result 'Skipped (nothing to copy)' -Action 'Copy permissions'), (New-Row -Result 'Skipped (nothing to copy)' -Action 'Copy permissions')); Log = $log; Msg = '2 folder(s) already had these permissions and were not changed.'; Kind = 'Info'; Text = '2 folder(s) already had these permissions and were not changed.' }
            @{ Name = 'done plus up-to-date target'; Entries = @((New-Row -Result 'Done' -Action 'Copy permissions'), (New-Row -Result 'Skipped (nothing to copy)' -Action 'Copy permissions')); Log = $log; Msg = 'Permissions copied to 1 of 2 folders.'; Kind = 'Success'; Text = 'Permissions copied to 1 of 2 folders.' }
            @{ Name = 'done plus not found'; Entries = @((New-Row -Result 'Done'), (New-Row -Result 'Skipped (not found)')); Log = $log; Msg = 'Added on 1 of 2 files. 1 not found and skipped.'; Kind = 'Warning'; Text = 'Partly done: Added on 1 of 2 files. 1 not found and skipped.' }
            @{ Name = 'dry run'; Entries = @((New-Row -Result 'Skipped (WhatIf)')); Log = $null; Msg = 'WhatIf: nothing was changed (1 folders would be).'; Kind = 'Info'; Text = 'WhatIf: nothing was changed (1 folders would be).' }
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
        Should -Invoke Get-AppDfsTarget -Times 0 -ParameterFilter { $Path -like '\\testpc*' -or $Path -like '\\localhost*' -or $Path -like '\\127.*' } -Because 'this computer is not a DFS namespace'
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
}
