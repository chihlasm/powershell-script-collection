<#
    Tests for recursive take ownership in FolderPermissions.Core.ps1 (SQ-014, ACs 16-18, and the
    core side of 19; Pester 5, run under pwsh). ACs 14, 15 and the copy case of 17 are retired
    (D-031); recursive copy is SQ-015.

    Safety: Set-Acl and the native-tool wrapper (Invoke-AclTool) are ALWAYS mocked, and so are
    the bare takeown/icacls names. Get-Acl is real, read-only, and only reads items inside
    $TestDrive (or is mocked to throw for one "locked" item).

    The Invoke-AclTool fake records, at the moment of each call, which files exist in
    <LogFolder>\Backups and what they hold, so "the snapshot exists before takeown" is testable.

    Pinned for the implementer:
      Set-ItemOwnerToCurrentUser -Path <dir> -Recurse -LogFolder <log> [-WhatIf]
        returns ONE row: Action 'Take ownership (all subfolders and files)', ItemType 'Folder tree',
        Target <dir>, OldValue 'Saved in <snapshot>', NewValue 'Owner: <WindowsIdentity name>',
        BackupFile <snapshot>.
      Owner snapshot: <log>\Backups\<stamp>_TakeOwnership.csv, columns Path, ItemType, Owner,
        OwnerSid, one row for the target and every folder/file under it, read with
        Get-Acl -LiteralPath; unreadable -> Owner 'Could not read'.
      Native calls (arguments as the GUI used, plus the full account name):
        Invoke-AclTool -Tool takeown -Arguments '/F', <dir>, '/R', '/A', '/D', 'N'   (D-034; was /D Y)
        Invoke-AclTool -Tool icacls  -Arguments <dir>, '/setowner', <WindowsIdentity name>, '/T', '/C', '/Q'

    Run:  Invoke-Pester .\FolderPermissionManager\Tests
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..\FolderPermissions.Core.ps1') -LoadFunctionsOnly
    # Guard: the real Invoke-AclTool runs takeown.exe and icacls.exe by full path, which the
    # bare 'Mock takeown' / 'Mock icacls' below cannot catch. Replaced here (same parameters)
    # so a test that forgets to mock it fails instead of changing real owners.
    function Invoke-AclTool {
        param(
            [Parameter(Mandatory)][ValidateSet('icacls', 'takeown')][string]$Tool,
            [Parameter(Mandatory)][string[]]$Arguments
        )
        throw "Invoke-AclTool ($Tool) was called without a mock in a test."
    }
    # Guard: the real Get-DfsTarget asks the DFS client (NetDfsGetClientInfo) and reads the
    # network path. Replaced here (same parameter) so a test that forgets to mock it never
    # reaches a real share; the code under test treats the throw as "could not be found out".
    $script:RealGetDfsTarget = ${function:Get-DfsTarget}
    function Get-DfsTarget {
        param([Parameter(Mandatory)][string]$Path)
        throw "Get-DfsTarget ($Path) was called without a mock in a test."
    }
    # Guard: the real Resolve-NetworkDrivePath reads this computer's drive letters and asks
    # Windows (WNetGetConnection) which server path a network drive is mapped to. Replaced here
    # (same parameter) so nothing reaches a real drive mapping, then mocked to hand every path
    # back as given; tests about mapped drives mock it themselves. The WNetGetConnection
    # wrapper is replaced the same way, for the tests of the real function.
    $script:RealResolveNetworkDrivePath = ${function:Resolve-NetworkDrivePath}
    function Resolve-NetworkDrivePath {
        param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)
        throw "Resolve-NetworkDrivePath ($Path) was called without a mock in a test."
    }
    function Get-NetworkDriveRemoteName {
        param([Parameter(Mandatory)][string]$Letter)
        throw "Get-NetworkDriveRemoteName ($Letter) was called without a mock in a test."
    }
    Mock Resolve-NetworkDrivePath { $Path }
    $script:RealGetAcl = Get-Command Get-Acl -CommandType Cmdlet
    $script:RealGetItemOwner = ${function:Get-ItemOwner}
    $script:MySid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $script:ExpectedColumns = @('Time', 'Technician', 'Computer', 'Action', 'Target', 'ItemType',
        'Detail', 'OldValue', 'NewValue', 'Result', 'Error', 'BackupFile')
    $script:TreeAction = 'Take ownership (all subfolders and files)'

    function New-TestTree {
        param([string]$Name)
        $root = Join-Path $TestDrive $Name
        New-Item -ItemType Directory -Path (Join-Path $root 'sub') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $root 'b.txt') -Value 'x'
        Set-Content -LiteralPath (Join-Path $root 'sub\a.txt') -Value 'x'
        $root
    }
}

Describe 'Recursive take ownership' {
    BeforeEach {
        $script:Log = Join-Path $TestDrive ('logs-' + [guid]::NewGuid().ToString('N'))
        $script:ToolCalls = [System.Collections.Generic.List[object]]::new()
        $script:ToolResult = @{
            takeown = [PSCustomObject]@{ ExitCode = 0; Output = '' }
            icacls  = [PSCustomObject]@{ ExitCode = 0; Output = 'Successfully processed 4 files; Failed processing 0 files' }
        }
        $script:UnreadableLike = $null

        Mock Set-Acl { }
        Mock takeown { }
        Mock icacls { }
        Mock Get-Acl {
            $p = if ($LiteralPath) { $LiteralPath } else { $Path }
            if ($script:UnreadableLike -and $p -like $script:UnreadableLike) { throw 'Attempted to perform an unauthorized operation. (test)' }
            if ($LiteralPath) { & $script:RealGetAcl -LiteralPath $LiteralPath } else { & $script:RealGetAcl -Path $Path }
        }
        Mock Invoke-AclTool {
            $dir = Join-Path $script:Log 'Backups'
            $files = if (Test-Path -LiteralPath $dir) { @(Get-ChildItem -LiteralPath $dir -File) } else { @() }
            $script:ToolCalls.Add([PSCustomObject]@{
                Tool        = $Tool
                Arguments   = @($Arguments)
                BackupFiles = @($files | ForEach-Object { $_.FullName })
                Content     = @($files | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw })
            })
            $script:ToolResult[$Tool]
        }
    }

    It 'AC16_RecursiveTakeOwnership_SavesOwnerSnapshotOfEveryItemBeforeTakeownAndRowShowsNewOwner' {
        $dir = New-TestTree 'ac16'
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        $takeown = @($script:ToolCalls | Where-Object { $_.Tool -eq 'takeown' })
        $takeown.Count | Should -Be 1
        $takeown[0].Arguments | Should -Be @('/F', $dir, '/R', '/A', '/D', 'N')   # D-034 (was /D Y)
        # Every native call happened after the snapshot existed.
        foreach ($c in $script:ToolCalls) { $c.BackupFiles.Count | Should -Be 1 -Because 'the owner snapshot must exist before any native call' }
        $snapshot = $takeown[0].BackupFiles[0]
        $snapshot | Should -BeLike '*_TakeOwnership.csv'

        $saved = @(Import-Csv -LiteralPath $snapshot)
        $saved[0].PSObject.Properties.Name | Should -Be @('Path', 'ItemType', 'Owner', 'OwnerSid')
        @($saved | ForEach-Object { $_.Path } | Sort-Object) | Should -Be @($dir, (Join-Path $dir 'b.txt'), (Join-Path $dir 'sub'), (Join-Path $dir 'sub\a.txt') | Sort-Object)
        ($saved | Where-Object { $_.Path -eq $dir }).ItemType | Should -Be 'Folder'
        ($saved | Where-Object { $_.Path -eq (Join-Path $dir 'b.txt') }).ItemType | Should -Be 'File'
        foreach ($s in $saved) {
            $s.Owner | Should -Not -BeNullOrEmpty
            $s.OwnerSid | Should -Match '^S-1-'
        }

        $rows.Count | Should -Be 1
        $rows[0].PSObject.Properties.Name | Should -Be $script:ExpectedColumns
        $rows[0].Action | Should -Be $script:TreeAction
        $rows[0].ItemType | Should -Be 'Folder tree'
        $rows[0].Target | Should -Be $dir
        $rows[0].OldValue | Should -Be "Saved in $snapshot"
        $rows[0].NewValue | Should -Be "Owner: $me"
        $rows[0].BackupFile | Should -Be $snapshot
        $rows[0].Result | Should -Be 'Done'
    }

    It 'AC16_RecursiveTakeOwnership_SetsOwnerByFullAccountNameNotBareUsername' {
        # Regression: the old code ran icacls /setowner $env:USERNAME, which has no domain and is
        # wrong (or empty) under SYSTEM and service accounts.
        $dir = New-TestTree 'ac16-name'
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $saved = $env:USERNAME
        try {
            $env:USERNAME = 'bare-username-from-env'
            $null = Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log
        } finally { $env:USERNAME = $saved }

        $icacls = @($script:ToolCalls | Where-Object { $_.Tool -eq 'icacls' })
        $icacls.Count | Should -Be 1
        $icacls[0].Arguments | Should -Be @($dir, '/setowner', $me, '/T', '/C', '/Q')
        $icacls[0].Arguments[2] | Should -Match '\\'
        $icacls[0].Arguments | Should -Not -Contain 'bare-username-from-env'
    }

    It 'AC16_SnapshotCannotBeSaved_NoNativeToolIsCalledAndResultFailed' {
        $dir = New-TestTree 'ac16-fail'
        Mock Export-Csv { throw 'disk full (test)' }

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        $rows.Count | Should -Be 1
        $rows[0].Result | Should -Be 'Failed'
        $rows[0].ItemType | Should -Be 'Folder tree'
        $rows[0].Error | Should -Match '^Could not save a backup of the current permissions'
        $rows[0].Error | Should -Match 'Nothing was changed\.$'
    }

    It 'AC17_ToolReportsSomeItemsFailed_ResultIsPartlyDoneWithToolOutput' -ForEach @(
        @{ Name = 'icacls'; Tool = 'icacls'; Exit = 1; Output = 'Successfully processed 3 files; Failed processing 2 files' }
        @{ Name = 'takeown'; Tool = 'takeown'; Exit = 1; Output = 'ERROR: Access is denied. (locked.txt)' }
    ) {
        $dir = New-TestTree "ac17-$Name"
        $script:ToolResult[$Tool] = [PSCustomObject]@{ ExitCode = $Exit; Output = $Output }

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        $rows.Count | Should -Be 1
        $rows[0].Result | Should -Be 'Partly done'
        $rows[0].ItemType | Should -Be 'Folder tree'
        $rows[0].Error | Should -BeLike "*$Output*"
        $rows[0].BackupFile | Should -BeLike '*_TakeOwnership.csv'
    }

    It 'AC17_NothingSucceeded_ResultIsFailedNotPartlyDone' {
        $dir = New-TestTree 'ac17-none'
        $script:ToolResult['takeown'] = [PSCustomObject]@{ ExitCode = 1; Output = 'ERROR: Access is denied.' }
        $script:ToolResult['icacls'] = [PSCustomObject]@{ ExitCode = 1; Output = 'Successfully processed 0 files; Failed processing 4 files' }

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        $rows[0].Result | Should -Be 'Failed'
        $rows[0].Error | Should -BeLike '*Failed processing 4 files*'
    }

    It 'AC17_PartlyDone_MessageSaysPartlyChangedAndPointsAtTheBackup' {
        $dir = New-TestTree 'ac17-msg'
        $script:ToolResult['icacls'] = [PSCustomObject]@{ ExitCode = 1; Output = 'Successfully processed 3 files; Failed processing 2 files' }
        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log

        $message | Should -Match '(?i)partly'
        $message | Should -BeLike "*$($rows[0].BackupFile)*"
        $message | Should -Not -Match 'Nothing was changed'
        $message | Should -BeLike '*Failed processing 2 files*'
    }

    It 'AC18_UnreadableItem_IsRecordedAsCouldNotReadAndTheActionContinues' {
        $dir = New-TestTree 'ac18'
        $locked = Join-Path $dir 'sub\locked.txt'
        Set-Content -LiteralPath $locked -Value 'x'
        $script:UnreadableLike = '*locked.txt'

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        # D-027: continue. Both native tools still ran and the action succeeded.
        @($script:ToolCalls | ForEach-Object { $_.Tool }) | Should -Be @('takeown', 'icacls')
        $rows[0].Result | Should -Be 'Done'
        $snapshot = $script:ToolCalls[0].BackupFiles[0]
        $saved = @(Import-Csv -LiteralPath $snapshot)
        $item = @($saved | Where-Object { $_.Path -eq $locked })
        $item.Count | Should -Be 1
        $item[0].Owner | Should -Be 'Could not read'
        $item[0].OwnerSid | Should -BeNullOrEmpty
        @($saved | Where-Object { $_.Owner -ne 'Could not read' }).Count | Should -Be 4 -Because 'readable items are still saved'

        $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
        $message | Should -Match '1 item\(s\) had no readable permissions before the change and cannot be restored from this backup'
    }

    It 'AC19_CoreRecursiveTakeOwnership_WhatIfCallsNoToolAndWritesNoSnapshot' {
        $dir = New-TestTree 'ac19-core'

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log -WhatIf)

        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
        Test-Path -LiteralPath (Join-Path $script:Log 'Backups') | Should -BeFalse
        $rows.Count | Should -Be 1
        $rows[0].Action | Should -Be $script:TreeAction
        $rows[0].ItemType | Should -Be 'Folder tree'
        $rows[0].Result | Should -Be 'Skipped (WhatIf)'
    }

    # --- Fix round 1 (SQ-014 review) ---------------------------------------------------------

    It 'AC18_FolderThatCannotBeListed_IsNeverReportedAsCompleteAndTheMessageNamesIt' {
        $dir = New-TestTree 'ac18-unlisted'
        $locked = Join-Path $dir 'sub'
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $locked }

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        # D-034: a folder that could not be opened makes the result Partly done, never Done
        # (was 'Done' before D-034; changed in fix round 1 of the 2026-10-17 review).
        $rows[0].Result | Should -Be 'Partly done'
        $rows[0].TreeCounts.Unlisted | Should -Be 1
        @($rows[0].TreeCounts.UnlistedFolders) | Should -Be @($locked)
        Test-TreeEntryIncomplete $rows[0] | Should -BeTrue
        $saved = @(Import-Csv -LiteralPath $rows[0].BackupFile)
        @($saved | ForEach-Object { $_.Path }) | Should -Not -Contain (Join-Path $locked 'a.txt')
        $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
        # One merged escalation (review 2026-10-17, UI): the pinned sentence, then the names.
        $message | Should -BeLike "*Escalate: 1 folder(s) could not be opened, so they were left alone. Not opened: $locked.*"
        $message | Should -Match 'cannot be restored from this backup'
    }

    It 'AC17_ToolsReportSuccessButOwnersReadBackUnchanged_ResultIsPartlyDone' {
        # Exit code 0 and no summary line: only reading the owners back shows what happened.
        $dir = New-TestTree 'ac17-readback'
        $script:ToolResult['icacls'] = [PSCustomObject]@{ ExitCode = 0; Output = '' }
        Mock Get-ItemOwner {
            if ($script:ToolCalls.Count -gt 0 -and $Path -like '*.txt') { return [PSCustomObject]@{ Owner = 'CONTOSO\old.owner'; OwnerSid = 'S-1-5-21-1-2-3-1105' } }
            & $script:RealGetItemOwner -Path $Path
        }
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        $rows[0].Result | Should -Be 'Partly done'
        $rows[0].NewValue | Should -Be "Owner: $me on 2 of 4 items"
        $rows[0].Error | Should -BeLike "2 of 4 items are not owned by $me after the change*"
        $rows[0].TreeCounts.NotOwned | Should -Be 2
    }

    It 'AC17_OwnersReadBackNotChangedAtAll_ResultIsFailedAndNothingClaimed' {
        $dir = New-TestTree 'ac17-none-readback'
        $script:ToolResult['icacls'] = [PSCustomObject]@{ ExitCode = 0; Output = '' }
        Mock Get-ItemOwner { [PSCustomObject]@{ Owner = 'CONTOSO\old.owner'; OwnerSid = 'S-1-5-21-1-2-3-1105' } }

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        $rows[0].Result | Should -Be 'Failed'
        $rows[0].NewValue | Should -Be 'Owner unchanged'
        Get-FailedChangeState $rows[0] | Should -Be 'Unchanged'
        $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
        $message | Should -Match 'No owner was changed'
    }

    It 'AC17_TakeownSucceededButIcaclsSetNothing_NewValueNamesAdministrators' {
        $dir = New-TestTree 'ac17-admins'
        $script:ToolResult['icacls'] = [PSCustomObject]@{ ExitCode = 5; Output = "$dir`: Access is denied.`r`nSuccessfully processed 0 files; Failed processing 4 files" }
        Mock Get-ItemOwner {
            if ($script:ToolCalls.Count -gt 0) { return [PSCustomObject]@{ Owner = 'BUILTIN\Administrators'; OwnerSid = 'S-1-5-32-544' } }
            & $script:RealGetItemOwner -Path $Path
        }

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        $rows[0].NewValue | Should -Be 'Owner: Administrators (icacls failed)'
        $rows[0].Result | Should -Be 'Failed'
        $rows[0].Error | Should -BeLike "*$dir`: Access is denied.*"
        $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
        $message | Should -BeLike '*Some owners were changed (Owner: Administrators (icacls failed))*'
        $message | Should -BeLike "*$($rows[0].BackupFile)*"
    }

    It 'AC16_RelativePathWithTrailingBackslashAndSpace_IsResolvedOnceAndUsedEverywhere' {
        $dir = New-TestTree 'ac16 rel tree'
        Push-Location -LiteralPath $TestDrive
        try {
            $rows = @(Set-ItemOwnerToCurrentUser -Path '.\ac16 rel tree\' -Recurse -LogFolder $script:Log)
        } finally { Pop-Location }

        $rows[0].Target | Should -Be $dir
        $rows[0].Result | Should -Be 'Done'
        ($script:ToolCalls | Where-Object { $_.Tool -eq 'takeown' }).Arguments[1] | Should -Be $dir
        ($script:ToolCalls | Where-Object { $_.Tool -eq 'icacls' }).Arguments[0] | Should -Be $dir
        (Import-Csv -LiteralPath $rows[0].BackupFile)[0].Path | Should -Be $dir
        $rows[0].Detail | Should -BeLike "*Ran: takeown /F ""$dir"" /R /A /D N; icacls ""$dir"" /setowner *"
    }

    It 'AC16_JunctionInTheTree_IsListedButNotGoneInto' {
        $dir = New-TestTree 'ac16-junction'
        $elsewhere = Join-Path $TestDrive 'ac16-junction-target'
        New-Item -ItemType Directory -Path $elsewhere -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $elsewhere 'outside.txt') -Value 'x'
        $link = Join-Path $dir 'link'
        New-Item -ItemType Junction -Path $link -Target $elsewhere | Out-Null

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        $paths = @(Import-Csv -LiteralPath $rows[0].BackupFile | ForEach-Object { $_.Path })
        $paths | Should -Contain $link
        $paths | Should -Not -Contain (Join-Path $link 'outside.txt')
        $paths.Count | Should -Be 5
    }

    It 'AC16_OwnerSnapshotEscapesFormulaTextAndStillReadsBack' {
        $dir = New-TestTree 'ac16-formula'
        $formulaFolder = Join-Path $dir '=x'
        New-Item -ItemType Directory -Path $formulaFolder | Out-Null
        $script:FormulaOwner = '=HYPERLINK("http://example.invalid","x")'
        Mock Get-ItemOwner { [PSCustomObject]@{ Owner = $script:FormulaOwner; OwnerSid = $script:MySid } }

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        $rows[0].Result | Should -Be 'Done' -Because 'the read-back check of the snapshot passes with escaped text'
        $saved = @(Import-Csv -LiteralPath $rows[0].BackupFile)
        foreach ($s in $saved) { $s.Owner | Should -Be "'$($script:FormulaOwner)" }
        @($saved | ForEach-Object { $_.Path }) | Should -Contain $formulaFolder
    }

    It 'AC16_TreeRowKeepsTheLogColumnsAndTheCountsAreReadFromTheRowNotFromDetail' {
        $dir = New-TestTree 'ac16-counts'
        $script:UnreadableLike = '*b.txt'

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        $rows[0].PSObject.Properties.Name | Should -Be $script:ExpectedColumns
        $rows[0].TreeCounts.Unreadable | Should -Be 1
        $rows[0].Detail = 'reworded'
        Get-UnrestorableItemCount -Entries $rows | Should -Be 1
        $logPath = Write-PermissionChangeLog -Entries $rows -LogFolder $script:Log
        (Get-Content -LiteralPath $logPath -TotalCount 1) | Should -Be ('"' + ($script:ExpectedColumns -join '","') + '"')
    }

    # --- Fix round 2 (SQ-014 review) ---------------------------------------------------------

    # Fix round 2 pinned /D Y here: the permissions of a folder that could not be listed were
    # saved to *_TakeOwnership_Permissions.csv because takeown replaced them. D-034 superseded
    # that: takeown /D N skips such a folder, so its permissions are never changed or saved.
    It 'AC18_FolderThatCannotBeListed_IsSkippedByTakeownAndItsPermissionsAreNotSavedBecauseTheyNeverChange' {
        $dir = New-TestTree 'ac18-perm'
        $locked = Join-Path $dir 'sub'
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $locked }

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        $rows[0].Result | Should -Be 'Partly done' -Because 'D-034: a skipped folder never leaves the result Done'
        $takeown = @($script:ToolCalls | Where-Object { $_.Tool -eq 'takeown' })
        $takeown[0].Arguments | Should -Be @('/F', $dir, '/R', '/A', '/D', 'N')
        foreach ($c in $script:ToolCalls) {
            @($c.BackupFiles) | Should -Be @($rows[0].BackupFile) -Because 'the owner snapshot is the only backup'
        }
        $rows[0].TreeCounts.PSObject.Properties.Name | Should -Not -Contain 'PermissionsFile'
        $rows[0].Detail | Should -BeLike "*1 folder(s) could not be opened, so takeown /D N skipped them*$locked*"
        $rows[0].Detail | Should -Not -Match 'full control'

        $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
        $message | Should -BeLike '*Escalate: 1 folder(s) could not be opened, so they were left alone.*'
        $message | Should -Not -Match 'full control'
    }

    It 'AC18_FolderThatCannotBeListedOrRead_IsCountedAndNamedForEscalationNotAsLost' {
        $dir = New-TestTree 'ac18-perm-lost'
        $locked = Join-Path $dir 'sub'
        $script:UnreadableLike = $locked
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $locked }

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        @($script:ToolCalls).Count | Should -Be 2 -Because 'D-027: an unreadable folder does not stop the action'
        $rows[0].TreeCounts.Unlisted | Should -Be 1
        @($rows[0].TreeCounts.UnlistedFolders) | Should -Be @($locked)
        $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
        $message | Should -BeLike "*Escalate: 1 folder(s) could not be opened, so they were left alone. Not opened: $locked.*cannot be restored from this backup*"
        $message | Should -Not -Match 'are lost'
    }

    It 'AC18_FolderThatCannotBeListed_OwnerSnapshotCannotBeSaved_NothingIsChanged' {
        $dir = New-TestTree 'ac18-perm-fail'
        $locked = Join-Path $dir 'sub'
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $locked }
        Mock Export-Csv { throw 'disk full (test)' }

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        $rows[0].Result | Should -Be 'Failed'
        $rows[0].Error | Should -Match '^Could not save a backup of the current permissions'
        $rows[0].Error | Should -Match 'Nothing was changed\.$'
        Test-Path -LiteralPath (Join-Path $script:Log 'Backups') | Should -BeFalse -Because 'a snapshot that could not be saved leaves no backup folder behind'
    }

    It 'AC17_NoOwnerCouldBeReadBack_IsPartlyDoneNeverDone' {
        $dir = New-TestTree 'ac17-unchecked'
        Mock Get-ItemOwner {
            if ($script:ToolCalls.Count -gt 0) { return [PSCustomObject]@{ Owner = 'Could not read'; OwnerSid = '' } }
            & $script:RealGetItemOwner -Path $Path
        }

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        $rows[0].Result | Should -Be 'Partly done'
        $rows[0].NewValue | Should -Be 'Not checked'
        $rows[0].TreeCounts.Unchecked | Should -Be 4
        Test-TreeEntryIncomplete $rows[0] | Should -BeTrue
        $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
        $message | Should -BeLike 'Partly done: ran takeown and icacls on *, but no owner could be read back afterwards*'
        $message | Should -Not -Match '^Took ownership'
    }

    It 'AC16_JunctionInTheTree_IsCountedAndMakesTheResultIncomplete' {
        $dir = New-TestTree 'ac16-junction-count'
        $elsewhere = Join-Path $TestDrive 'ac16-junction-count-target'
        New-Item -ItemType Directory -Path $elsewhere -Force | Out-Null
        $link = Join-Path $dir 'link'
        New-Item -ItemType Junction -Path $link -Target $elsewhere | Out-Null

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        $rows[0].TreeCounts.Links | Should -Be 1
        @($rows[0].TreeCounts.LinkPaths) | Should -Be @($link)
        Test-TreeEntryIncomplete $rows[0] | Should -BeTrue
        $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
        $message | Should -BeLike "*1 junction(s) or symbolic link(s) ($link) were listed but not gone into. Microsoft's documentation does not say whether takeown and icacls follow them*"
    }

    It 'AC18_FailedTreeRowThatChangedSomething_CountsItsUnreadableItems' {
        $partly = New-PermissionChangeEntry -Action $script:TreeAction -Target 'D:\x' -ItemType 'Folder tree' `
            -NewValue 'Owner: Administrators (icacls failed)' -Result 'Failed'
        Add-TreeEntryCount -Entry $partly -Counts ([ordered]@{ Unreadable = 2; Changed = 3 })
        $unchanged = New-PermissionChangeEntry -Action $script:TreeAction -Target 'D:\y' -ItemType 'Folder tree' `
            -NewValue 'Owner unchanged' -Result 'Failed'
        Add-TreeEntryCount -Entry $unchanged -Counts ([ordered]@{ Unreadable = 5; Changed = 0 })

        Get-FailedChangeState $partly | Should -Be 'Partly'
        Get-UnrestorableItemCount -Entries @($partly) | Should -Be 2
        Get-UnrestorableItemCount -Entries @($unchanged) | Should -Be 0 -Because 'nothing was changed, so nothing needs restoring'
    }
}

Describe 'Native tool guard and tool output' {
    It 'an unmocked Invoke-AclTool throws instead of running takeown or icacls' {
        { Invoke-AclTool -Tool takeown -Arguments '/?' } | Should -Throw '*without a mock*'
    }

    It 'Get-AclToolSummary prefers error-looking lines and the last line, in any language' {
        $dir = 'D:\Daten\HR'
        $output = (@(1..40 | ForEach-Object { "ERFOLGREICH: Die Datei (oder der Ordner) ""$dir\f$_.txt"" gehoert jetzt der Gruppe Administratoren." }) +
            "$dir\gesperrt.txt: Zugriff verweigert" + '1 Dateien erfolgreich verarbeitet; Fehler bei 1 Dateien') -join "`r`n"

        $summary = Get-AclToolSummary -Output $output -Path $dir

        $summary | Should -Be "$dir\gesperrt.txt: Zugriff verweigert 1 Dateien erfolgreich verarbeitet; Fehler bei 1 Dateien"
    }

    It 'Get-AclToolSummary falls back to the last line when nothing looks like an error' {
        $output = "ERFOLGREICH: a`r`nERFOLGREICH: b`r`nERFOLGREICH: c"
        Get-AclToolSummary -Output $output -Path 'D:\Daten' | Should -Be 'ERFOLGREICH: c'
    }

    It 'Get-AclToolSummary never sums up a tool with a SUCCESS line when another line is there' {
        $output = "INFO: No files with the specified name were found.`r`nSUCCESS: The file (or folder): ""D:\HR\a.txt"" now owned by the administrators group.`r`nSUCCESS: The file (or folder): ""D:\HR\b.txt"" now owned by the administrators group."
        Get-AclToolSummary -Output $output -Path 'D:\HR' | Should -Be 'INFO: No files with the specified name were found.'
    }

    It 'Test-AclToolErrorLine does not read error words inside a path as errors' {
        Test-AclToolErrorLine -Line 'SUCCESS: The file (or folder): "D:\Failed Jobs\a.txt" now owned by user "CONTOSO\tech".' -Path 'E:\Other' | Should -BeFalse
        Test-AclToolErrorLine -Line 'Processing D:\Errors\Invalid\x.txt' -Path 'E:\Other' | Should -BeFalse
        Test-AclToolErrorLine -Line 'D:\Failed Jobs\x.txt: Access is denied.' -Path 'E:\Other' | Should -BeTrue
        Test-AclToolErrorLine -Line 'ERROR: Access is denied.' -Path 'E:\Other' | Should -BeTrue
        $summary = Get-AclToolSummary -Output "SUCCESS: The file (or folder): ""D:\Failed\a.txt"" now owned by X.`r`nINFO: done" -Path 'E:\Other'
        $summary | Should -Be 'INFO: done'
    }

    It 'Resolve-AclTargetPath keeps a drive root and trims other trailing backslashes' {
        Resolve-AclTargetPath -Path 'C:\' | Should -Be 'C:\'
        Resolve-AclTargetPath -Path 'C:\Shares\HR Team\' | Should -Be 'C:\Shares\HR Team'
        Resolve-AclTargetPath -Path 'C:\Shares\HR [old]' | Should -Be 'C:\Shares\HR [old]'
    }
}

# --- Revision (SQ-014 review 2026-10-17): D-034 and D-036 -----------------------------------
#
# Pinned for the implementer:
#   D-034  Recursive take ownership runs takeown /F <dir> /R /A /D N (never /D Y). A folder
#          takeown cannot open is skipped and keeps its permissions: no
#          *_TakeOwnership_Permissions.csv is written, Set-Acl is not used on it, the read-back
#          marks it not owned, the row is Partly done, and the message says
#          "Escalate: <n> folder(s) could not be opened, so they were left alone."
#   D-036  Get-TreeOwnershipRefusal -Path <string> (pure, no file system access) returns $null
#          when whole-tree take ownership is allowed, else the plain-English refusal text
#          (contains the path). Refused: a volume root (C:\, D:\) and anything under
#          %SystemRoot%, %ProgramFiles%, %ProgramFiles(x86)%, %ProgramData% (the folders
#          themselves included), compared case-insensitively on whole path segments and read
#          from the environment at call time. A share root (\\fs01\share) is allowed.
#          Set-ItemOwnerToCurrentUser -Recurse [-AllowSystemFolder] returns ONE row with
#          Result 'Failed' and an Error that names the path and ends with "Nothing was
#          changed." when refused: no snapshot, no backup folder, no tool call. -AllowSystemFolder
#          skips the check. The GUI never passes it.
Describe 'Recursive take ownership: skip folders it cannot open (D-034) and refuse drive roots and system folders (D-036)' {
    BeforeAll {
        function Invoke-WithRedirectedEnv {
            # Points one of the protected-folder variables at a folder in $TestDrive for the
            # duration of the script block (restored in finally).
            param([string]$Name, [string]$Value, [scriptblock]$Do)
            $old = [Environment]::GetEnvironmentVariable($Name, 'Process')
            [Environment]::SetEnvironmentVariable($Name, $Value, 'Process')
            try { & $Do } finally { [Environment]::SetEnvironmentVariable($Name, $old, 'Process') }
        }
    }
    BeforeEach {
        $script:Log = Join-Path $TestDrive ('logs-' + [guid]::NewGuid().ToString('N'))
        $script:ToolCalls = [System.Collections.Generic.List[object]]::new()
        $script:ToolResult = @{
            takeown = [PSCustomObject]@{ ExitCode = 0; Output = '' }
            icacls  = [PSCustomObject]@{ ExitCode = 0; Output = 'Successfully processed 4 files; Failed processing 0 files' }
        }
        $script:AfterToolsOwner = $null

        Mock Set-Acl { }
        Mock takeown { }
        Mock icacls { }
        Mock Invoke-AclTool {
            $script:ToolCalls.Add([PSCustomObject]@{ Tool = $Tool; Arguments = @($Arguments) })
            $script:ToolResult[$Tool]
        }
        # takeown /D N leaves a folder it cannot open alone: after the tools ran, the owner
        # read back for that folder is still the old one.
        Mock Get-ItemOwner {
            if ($script:AfterToolsOwner -and $script:ToolCalls.Count -gt 0 -and $Path -eq $script:AfterToolsOwner) {
                return [PSCustomObject]@{ Owner = 'CONTOSO\old.owner'; OwnerSid = 'S-1-5-21-1-2-3-1105' }
            }
            & $script:RealGetItemOwner -Path $Path
        }
    }

    It 'AC16b_RecursiveTakeOwnership_RunsTakeownWithDNeverDY' {
        $dir = New-TestTree 'ac16b'

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        $takeown = @($script:ToolCalls | Where-Object { $_.Tool -eq 'takeown' })
        $takeown.Count | Should -Be 1
        $takeown[0].Arguments | Should -Be @('/F', $dir, '/R', '/A', '/D', 'N')
        $takeown[0].Arguments | Should -Not -Contain 'Y'
        $rows[0].Detail | Should -BeLike "*Ran: takeown /F ""$dir"" /R /A /D N; icacls *"
        $rows[0].Detail | Should -Not -Match '/D Y'
    }

    It 'AC16c_FolderTakeownCannotOpen_IsPartlyDoneNamedWithEscalateAndNotBackedUpOrChanged' {
        $dir = New-TestTree 'ac16c'
        $locked = Join-Path $dir 'sub'
        $script:AfterToolsOwner = $locked
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $locked }

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        $rows[0].Result | Should -Be 'Partly done'
        $rows[0].TreeCounts.Unlisted | Should -Be 1
        @($rows[0].TreeCounts.UnlistedFolders) | Should -Be @($locked)
        $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
        $message | Should -Match ([regex]::Escape('Escalate: 1 folder(s) could not be opened, so they were left alone.'))
        $message | Should -Match ([regex]::Escape($locked))
        # Their permissions are never changed, so there is nothing to back up.
        @(Get-ChildItem -LiteralPath (Join-Path $script:Log 'Backups') -Filter '*_Permissions.csv').Count | Should -Be 0
        @(Get-ChildItem -LiteralPath (Join-Path $script:Log 'Backups') -Filter '*_TakeOwnership.csv').Count | Should -Be 1
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
        ($script:ToolCalls | Where-Object { $_.Tool -eq 'takeown' }).Arguments | Should -Contain 'N'
    }

    It 'AC16c_EscalateSentenceCountsEveryFolderAndNothingSaysPermissionsAreReplacedOrLost' {
        $dir = New-TestTree 'ac16c-two'
        New-Item -ItemType Directory -Path (Join-Path $dir 'sub2') | Out-Null
        $lockedA = Join-Path $dir 'sub'
        $lockedB = Join-Path $dir 'sub2'
        $script:LockedPair = @($lockedA, $lockedB)
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $script:LockedPair -contains $LiteralPath }
        # Their permissions cannot be read either: with D-034 that no longer matters.
        Mock Get-Acl { throw 'Attempted to perform an unauthorized operation. (test)' } -ParameterFilter { $script:LockedPair -contains $LiteralPath }

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
        $message | Should -Match ([regex]::Escape('Escalate: 2 folder(s) could not be opened, so they were left alone.'))
        $message | Should -Not -Match 'full control'
        $message | Should -Not -Match 'replaces the permissions'
        $message | Should -Not -Match '_Permissions\.csv'
        $message | Should -Not -Match 'permissions were not backed up'
        $rows[0].Detail | Should -Not -Match 'full control'
        @(Get-ChildItem -LiteralPath (Join-Path $script:Log 'Backups') -Filter '*_Permissions.csv').Count | Should -Be 0
        $script:ToolCalls.Count | Should -Be 2 -Because 'D-027: an unreadable folder does not stop the action'
    }

    It 'AC16d_VolumeRoot_IsRefusedWithNoSnapshotAndNoToolCall' {
        $root = [System.IO.Path]::GetPathRoot($TestDrive)
        # If the refusal is missing, these keep the test from walking the whole drive.
        Mock Save-OwnerSnapshot { throw 'snapshot must not be taken (test)' }
        Mock Get-OwnerTreeItem { [PSCustomObject]@{ Items = @(); Unlisted = @(); Links = @() } }

        $rows = @(Set-ItemOwnerToCurrentUser -Path $root -Recurse -LogFolder $script:Log)

        $rows.Count | Should -Be 1
        $rows[0].Result | Should -Be 'Failed'
        $rows[0].Error | Should -Match ([regex]::Escape($root))
        $rows[0].Error | Should -Match 'Nothing was changed\.$'
        Should -Invoke Save-OwnerSnapshot -Times 0 -Exactly -Scope It
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
        Test-Path -LiteralPath (Join-Path $script:Log 'Backups') | Should -BeFalse
    }

    It 'AC16d_FolderUnder<Name>_IsRefusedWithNoSnapshotAndNoToolCall' -ForEach @(
        @{ Name = 'SystemRoot' }
        @{ Name = 'ProgramFiles' }
        @{ Name = 'ProgramFiles(x86)' }
        @{ Name = 'ProgramData' }
    ) {
        $base = Join-Path $TestDrive ('protected-' + [guid]::NewGuid().ToString('N'))
        $dir = Join-Path $base 'Contoso'
        New-Item -ItemType Directory -Path (Join-Path $dir 'sub') -Force | Out-Null
        Mock Save-OwnerSnapshot { throw 'snapshot must not be taken (test)' }
        $script:ProtectedDir = $dir

        $rows = @(Invoke-WithRedirectedEnv -Name $Name -Value $base -Do {
            Set-ItemOwnerToCurrentUser -Path $script:ProtectedDir -Recurse -LogFolder $script:Log
        })

        $rows[0].Result | Should -Be 'Failed'
        $rows[0].Error | Should -Match ([regex]::Escape($dir))
        $rows[0].Error | Should -Match 'Nothing was changed\.$'
        Should -Invoke Save-OwnerSnapshot -Times 0 -Exactly -Scope It
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        Test-Path -LiteralPath (Join-Path $script:Log 'Backups') | Should -BeFalse
    }

    It 'AC16d_AllowSystemFolder_SkipsTheRefusalAndTakesOwnership' {
        $base = Join-Path $TestDrive ('protected-' + [guid]::NewGuid().ToString('N'))
        $dir = Join-Path $base 'Contoso'
        New-Item -ItemType Directory -Path (Join-Path $dir 'sub') -Force | Out-Null
        $script:ProtectedDir = $dir

        $rows = @(Invoke-WithRedirectedEnv -Name 'ProgramData' -Value $base -Do {
            Set-ItemOwnerToCurrentUser -Path $script:ProtectedDir -Recurse -AllowSystemFolder -LogFolder $script:Log
        })

        $rows[0].Result | Should -Be 'Done'
        @($script:ToolCalls | Where-Object { $_.Tool -eq 'takeown' }).Count | Should -Be 1
    }

    It 'AC16d_AFolderUnderANormalPath_IsNotRefused' {
        $dir = New-TestTree 'ac16d-normal'

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        $rows[0].Result | Should -Be 'Done'
    }
}

Describe 'Get-TreeOwnershipRefusal' {
    It 'AC16d_Refuses_<Path>' -ForEach @(
        @{ Path = 'C:\' }
        @{ Path = 'D:\' }
        @{ Path = 'd:\' }
        @{ Path = $env:SystemRoot }
        @{ Path = ($env:SystemRoot + '\') }
        @{ Path = ($env:SystemRoot + '\System32\drivers') }
        @{ Path = ($env:SystemRoot.ToLowerInvariant() + '\system32') }
        @{ Path = $env:ProgramFiles }
        @{ Path = ($env:ProgramFiles + '\Contoso\App') }
        @{ Path = ${env:ProgramFiles(x86)} }
        @{ Path = (${env:ProgramFiles(x86)} + '\Contoso') }
        @{ Path = $env:ProgramData }
        @{ Path = ($env:ProgramData + '\Contoso') }
    ) {
        $text = Get-TreeOwnershipRefusal -Path $Path

        $text | Should -Not -BeNullOrEmpty
        $text | Should -Match ([regex]::Escape($Path))
    }

    It 'AC16d_Allows_<Path>' -ForEach @(
        @{ Path = '\\fs01\share' }
        @{ Path = '\\fs01\share\' }
        @{ Path = '\\fs01\share\HR\2024' }
        @{ Path = 'D:\Data' }
        @{ Path = 'D:\Shares\HR Team' }
        @{ Path = ($env:SystemRoot + 'Old\x') }
        @{ Path = ($env:ProgramFiles + ' Archive') }
        @{ Path = ($env:ProgramData + 'Backup') }
    ) {
        Get-TreeOwnershipRefusal -Path $Path | Should -BeNullOrEmpty
    }
}

Describe 'README after D-034 and D-036' {
    BeforeAll {
        $script:Readme = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\README.md') -Raw -Encoding UTF8
    }

    It 'AC16b_ReadmeSaysDN_AndNoLongerMentionsDYOrTheReplacedPermissionsWarning' {
        $script:Readme | Should -Match '/R /A /D N'
        $script:Readme | Should -Not -Match '/D Y'
        $script:Readme | Should -Not -Match '_TakeOwnership_Permissions'
        $script:Readme | Should -Not -Match 'full control for you'
    }

    It 'AC16c_ReadmeSaysFoldersThatCannotBeOpenedAreSkippedAndToEscalate' {
        $script:Readme | Should -Match '(?is)cannot be opened.{0,200}(skipped|left alone)'
        $script:Readme | Should -Match 'Escalate'
    }

    It 'AC16d_ReadmeExplainsTheDriveRootRefusalAndAllowSystemFolder' {
        $script:Readme | Should -Match '-AllowSystemFolder'
        $script:Readme | Should -Match '(?i)drive root|volume root|whole drive'
    }

    It 'AC16d_ReadmeNamesTheOtherSpellingsThatAreRefused' {
        $script:Readme | Should -Match ([regex]::Escape('ADMIN$'))
        $script:Readme | Should -Match '(?i)junction'
        $script:Readme | Should -Match '(?i)short name'
    }

    It 'AC16c_ReadmeListsTheNotOpenedFileAndWhoToEscalateTo' {
        $script:Readme | Should -Match '_NotOpened\.txt'
        $script:Readme | Should -Match '(?i)senior engineer'
    }

    It 'ReadmeSaysTheLogsHoldClientDataAndWhenToDeleteThem' {
        $script:Readme | Should -Match '(?is)Logs\\.{0,80}client paths, account names and SIDs'
        $script:Readme | Should -Match '(?i)delete it when the ticket is closed'
    }
}

# --- Fix round 1 (SQ-014 review 2026-10-17, D-034 and D-036) ---------------------------------
#
# Pinned for the implementer:
#   D-036  Get-TreeOwnershipRefusal stays text only. It compares a canonical form of the path:
#          \\?\ and \\.\ are dropped, \\?\UNC\ becomes \\, trailing dots and spaces are trimmed
#          from every segment. On a UNC path the ADMIN$ share is refused, \\host\<letter>$ is a
#          volume root, and \\host\<letter>$\{Windows, Program Files, Program Files (x86),
#          ProgramData} and anything under them are refused. %ProgramW6432% is checked as well
#          (skipped when empty). Get-TreeOwnershipTargetRefusal -Path <string> reads the disk:
#          the text check, then the same check on the path's final form (junctions and symbolic
#          links on the folder or any parent followed, 8.3 short names expanded); a refusal
#          found that way names the path as given. Invoke-TreeOwnershipChange and the CLI use it.
#   D-034  A folder that could not be opened always makes the row at best Partly done. Its owner
#          is read back: "left alone" only when unchanged, otherwise "its owner was changed, but
#          its permissions were not". The message keeps "Escalate: <n> folder(s) could not be
#          opened, so they were left alone." (or the owner-changed form), then "Not opened:
#          <first 3>[ and <n> more]." and "Full list: <Backups\<stamp>_NotOpened.txt>.", then
#          "Ask a senior engineer to take ownership of them with an account that can open them."
#          Detail names at most 20 folders, then "and <n> more (full list: <file>)".
#          TreeCounts gains UnlistedChanged, UnlistedChangedFolders and NotOpenedFile.
#   Single-item take ownership passes no /D (takeown: /D is used with /R only).
Describe 'Fix round 1 (review 2026-10-17): canonical refusal, truthful skip results, full escalation list' {
    BeforeAll {
        function Invoke-WithEnv {
            # Sets process environment variables for the duration of the script block.
            param([hashtable]$Values, [scriptblock]$Do)
            $old = @{}
            foreach ($k in $Values.Keys) {
                $old[$k] = [Environment]::GetEnvironmentVariable($k, 'Process')
                [Environment]::SetEnvironmentVariable($k, $Values[$k], 'Process')
            }
            try { & $Do } finally { foreach ($k in $old.Keys) { [Environment]::SetEnvironmentVariable($k, $old[$k], 'Process') } }
        }
        function New-TestJunction {
            # A junction at $Link pointing at $Target, or $null when this machine cannot make one.
            param([string]$Link, [string]$Target)
            try { New-Item -ItemType Junction -Path $Link -Target $Target -ErrorAction Stop | Out-Null } catch { return $null }
            if (Test-Path -LiteralPath $Link) { $Link } else { $null }
        }
        if (-not ('FpmTest.ShortName' -as [type])) {
            Add-Type -Namespace FpmTest -Name ShortName -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint GetShortPathNameW(string lpszLongPath, System.Text.StringBuilder lpszShortPath, uint cchBuffer);
'@
        }
        function Get-TestShortPath {
            # The 8.3 form of an existing path, or the path itself when the volume has none.
            # https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getshortpathnamew
            param([string]$Path)
            $sb = New-Object System.Text.StringBuilder -ArgumentList 1024
            $n = [FpmTest.ShortName]::GetShortPathNameW($Path, $sb, 1024)
            if ($n -eq 0) { return $Path }
            $sb.ToString()
        }
    }
    BeforeEach {
        $script:Log = Join-Path $TestDrive ('logs-' + [guid]::NewGuid().ToString('N'))
        $script:ToolCalls = [System.Collections.Generic.List[object]]::new()
        $script:ToolResult = @{
            takeown = [PSCustomObject]@{ ExitCode = 0; Output = '' }
            icacls  = [PSCustomObject]@{ ExitCode = 0; Output = '' }
        }
        Mock Set-Acl { }
        Mock takeown { }
        Mock icacls { }
        Mock Invoke-AclTool {
            $script:ToolCalls.Add([PSCustomObject]@{ Tool = $Tool; Arguments = @($Arguments) })
            $script:ToolResult[$Tool]
        }
    }

    Context 'Get-TreeOwnershipRefusal: other spellings of a protected path (text only)' {
        It 'AC16d_Refuses_<Path>' -ForEach @(
            @{ Path = '\\?\C:\' }
            @{ Path = '\\?\D:' }
            @{ Path = '\\.\C:\' }
            @{ Path = ('\\?\' + $env:SystemRoot) }
            @{ Path = ('\\?\' + $env:SystemRoot + '\System32') }
            @{ Path = ('\\.\' + $env:ProgramData + '\Contoso') }
            @{ Path = ('\\?\' + $env:ProgramFiles + '\') }
            @{ Path = ($env:SystemRoot + '.') }
            @{ Path = ($env:SystemRoot + '. \System32') }
            @{ Path = ($env:ProgramFiles + ' \Contoso') }
            @{ Path = ($env:ProgramData + '...\Contoso ') }
            @{ Path = ('\\?\' + $env:SystemRoot + ' .\System32') }
            @{ Path = ($env:SystemRoot + '\System32\..\System32') }
            @{ Path = '\\fs01\ADMIN$' }
            @{ Path = '\\fs01\admin$\System32' }
            @{ Path = '\\?\UNC\fs01\ADMIN$\System32' }
            @{ Path = '\\fs01\C$' }
            @{ Path = '\\fs01\d$\' }
            @{ Path = '\\localhost\C$' }
            @{ Path = '\\127.0.0.1\E$' }
            @{ Path = '\\?\UNC\fs01\C$' }
            @{ Path = '\\fs01\C$\Windows' }
            @{ Path = '\\fs01\c$\windows\System32\drivers' }
            @{ Path = '\\fs01\C$\Windows.\System32' }
            @{ Path = '\\fs01\C$\Program Files' }
            @{ Path = '\\fs01\C$\Program Files\Contoso' }
            @{ Path = '\\fs01\C$\Program Files (x86)\Contoso' }
            @{ Path = '\\fs01\E$\ProgramData\Contoso' }
            @{ Path = '\\?\UNC\localhost\C$\Windows' }
        ) {
            $text = Get-TreeOwnershipRefusal -Path $Path

            $text | Should -Not -BeNullOrEmpty
            $text | Should -Match ([regex]::Escape($Path))
        }

        It 'AC16d_Allows_<Path>' -ForEach @(
            @{ Path = '\\fs01\C$\Data' }
            @{ Path = '\\fs01\D$\Shares\HR' }
            @{ Path = '\\fs01\C$\WindowsOld' }
            @{ Path = '\\fs01\C$\Program Files Archive' }
            @{ Path = '\\fs01\share\Windows' }
            @{ Path = '\\fs01\share\Program Files' }
            @{ Path = '\\fs01\ADMIN' }
            @{ Path = '\\fs01\CD$' }
            @{ Path = '\\?\UNC\fs01\share' }
            @{ Path = '\\?\D:\Data' }
            @{ Path = 'D:\Data.\HR ' }
        ) {
            Get-TreeOwnershipRefusal -Path $Path | Should -BeNullOrEmpty
        }

        It 'AC16d_Wow64_ProgramW6432IsRefusedWhenProgramFilesIsTheX86Folder' {
            # In a 32-bit PowerShell on 64-bit Windows, %ProgramFiles% is the x86 folder and
            # only %ProgramW6432% names the 64-bit one.
            $x86 = 'C:\Program Files (x86)'
            $native = 'C:\Program Files'
            $text = Invoke-WithEnv -Values @{ ProgramFiles = $x86; ProgramW6432 = $native } -Do {
                Get-TreeOwnershipRefusal -Path "$native\Contoso"
            }

            $text | Should -Not -BeNullOrEmpty
            $text | Should -Match ([regex]::Escape("$native\Contoso"))
        }

        It 'AC16d_Wow64_AnEmptyProgramW6432IsSkipped' {
            # 32-bit Windows has no %ProgramW6432%.
            $text = Invoke-WithEnv -Values @{ ProgramW6432 = $null } -Do {
                Get-TreeOwnershipRefusal -Path 'D:\Data'
            }

            $text | Should -BeNullOrEmpty
        }
    }

    Context 'Get-TreeOwnershipTargetRefusal: junctions, symbolic links and short names (reads the disk)' {
        BeforeEach {
            $script:Base = Join-Path $TestDrive ('ProtectedFolderForTests-' + [guid]::NewGuid().ToString('N'))
            $script:Protected = Join-Path $script:Base 'ContosoApplication'
            New-Item -ItemType Directory -Path (Join-Path $script:Protected 'sub') -Force | Out-Null
            Mock Save-OwnerSnapshot { throw 'snapshot must not be taken (test)' }
        }

        It 'AC16d_JunctionToAProtectedFolder_IsRefusedWithNoSnapshotAndNoToolCall' {
            $link = New-TestJunction -Link (Join-Path $TestDrive ('jn-' + [guid]::NewGuid().ToString('N'))) -Target $script:Protected
            if (-not $link) { Set-ItResult -Skipped -Because 'a junction could not be created here'; return }
            $script:LinkPath = $link

            $rows = @(Invoke-WithEnv -Values @{ ProgramData = $script:Base } -Do {
                Set-ItemOwnerToCurrentUser -Path $script:LinkPath -Recurse -LogFolder $script:Log
            })

            $rows.Count | Should -Be 1
            $rows[0].Result | Should -Be 'Failed'
            $rows[0].Error | Should -Match ([regex]::Escape($link))
            $rows[0].Error | Should -Match 'Nothing was changed\.$'
            Should -Invoke Save-OwnerSnapshot -Times 0 -Exactly -Scope It
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
            Test-Path -LiteralPath (Join-Path $script:Log 'Backups') | Should -BeFalse
        }

        It 'AC16d_FolderInsideAJunctionToAProtectedFolder_IsRefused' {
            $link = New-TestJunction -Link (Join-Path $TestDrive ('jn-' + [guid]::NewGuid().ToString('N'))) -Target $script:Base
            if (-not $link) { Set-ItResult -Skipped -Because 'a junction could not be created here'; return }
            $script:Inside = Join-Path $link 'ContosoApplication\sub'

            $text = Invoke-WithEnv -Values @{ ProgramData = $script:Base } -Do {
                Get-TreeOwnershipTargetRefusal -Path $script:Inside
            }

            $text | Should -Not -BeNullOrEmpty
            $text | Should -Match ([regex]::Escape($script:Inside))
        }

        It 'AC16d_JunctionToAnOrdinaryFolder_IsAllowed' {
            $plain = Join-Path $TestDrive ('plain-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $plain | Out-Null
            $link = New-TestJunction -Link (Join-Path $TestDrive ('jn-' + [guid]::NewGuid().ToString('N'))) -Target $plain
            if (-not $link) { Set-ItResult -Skipped -Because 'a junction could not be created here'; return }
            $script:LinkPath = $link

            $text = Invoke-WithEnv -Values @{ ProgramData = $script:Base } -Do {
                Get-TreeOwnershipTargetRefusal -Path $script:LinkPath
            }

            $text | Should -BeNullOrEmpty
        }

        It 'AC16d_ShortNameOfAProtectedFolder_IsRefused' {
            $short = Get-TestShortPath -Path $script:Protected
            if ($short -eq $script:Protected) { Set-ItResult -Skipped -Because '8.3 short names are turned off on this volume'; return }
            $script:ShortPath = $short
            Invoke-WithEnv -Values @{ ProgramData = $script:Base } -Do {
                Get-TreeOwnershipRefusal -Path $script:ShortPath
            } | Should -BeNullOrEmpty -Because 'the text alone does not show it is protected'

            $text = Invoke-WithEnv -Values @{ ProgramData = $script:Base } -Do {
                Get-TreeOwnershipTargetRefusal -Path $script:ShortPath
            }

            $text | Should -Not -BeNullOrEmpty
            $text | Should -Match ([regex]::Escape($short))
        }

        It 'AC16d_TextRefusalStillWorksForAPathThatDoesNotExist' {
            Get-TreeOwnershipTargetRefusal -Path '\\fs01\C$\Windows\NoSuchFolder' | Should -Not -BeNullOrEmpty
            Get-TreeOwnershipTargetRefusal -Path (Join-Path $TestDrive 'no-such-folder') | Should -BeNullOrEmpty
        }
    }

    Context 'D-034: a folder that could not be opened' {
        It 'AC16c_UnopenedFolderWhoseOwnerWasChanged_IsPartlyDoneAndSaysSoInsteadOfLeftAlone' {
            # icacls /setowner /T may still change the owner of the skipped folder itself; the
            # read-back is what the message reports.
            $dir = New-TestTree 'fr1-changed'
            $script:Locked = Join-Path $dir 'sub'
            Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $script:Locked }
            Mock Get-ItemOwner {
                if ($Path -eq $script:Locked) {
                    if ($script:ToolCalls.Count -gt 0) { return [PSCustomObject]@{ Owner = 'me'; OwnerSid = $script:MySid } }
                    return [PSCustomObject]@{ Owner = 'CONTOSO\old.owner'; OwnerSid = 'S-1-5-21-1-2-3-1105' }
                }
                & $script:RealGetItemOwner -Path $Path
            }

            $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

            $rows[0].Result | Should -Be 'Partly done'
            $rows[0].TreeCounts.UnlistedChanged | Should -Be 1
            @($rows[0].TreeCounts.UnlistedChangedFolders) | Should -Be @($script:Locked)
            $rows[0].Detail | Should -BeLike "*owner*changed*$($script:Locked)*"
            $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
            $message | Should -Match ([regex]::Escape('Escalate: 1 folder(s) could not be opened: its owner was changed, but its permissions were not.'))
            $message | Should -Not -Match 'left alone'
            $message | Should -Match ([regex]::Escape($script:Locked))
            $message | Should -Match ([regex]::Escape('Ask a senior engineer to take ownership of them with an account that can open them.'))
        }

        It 'AC16c_UnopenedFolderWhoseOwnerIsUnchanged_SaysLeftAlone' {
            $dir = New-TestTree 'fr1-unchanged'
            $script:Locked = Join-Path $dir 'sub'
            Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $script:Locked }
            Mock Get-ItemOwner {
                if ($Path -eq $script:Locked) { return [PSCustomObject]@{ Owner = 'CONTOSO\old.owner'; OwnerSid = 'S-1-5-21-1-2-3-1105' } }
                & $script:RealGetItemOwner -Path $Path
            }

            $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

            $rows[0].Result | Should -Be 'Partly done'
            $rows[0].TreeCounts.UnlistedChanged | Should -Be 0
            $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
            $message | Should -Match ([regex]::Escape('Escalate: 1 folder(s) could not be opened, so they were left alone.'))
            $message | Should -Not -Match 'owner was changed'
        }

        It 'AC16c_ManyUnopenedFolders_MessageNamesThreeAndPointsAtTheFullListFile' {
            $dir = New-TestTree 'fr1-five'
            $script:LockedSet = @(1..5 | ForEach-Object {
                $p = Join-Path $dir ('locked{0}' -f $_)
                New-Item -ItemType Directory -Path $p | Out-Null
                $p
            })
            Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $script:LockedSet -contains $LiteralPath }

            $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

            $file = $rows[0].TreeCounts.NotOpenedFile
            $file | Should -Not -BeNullOrEmpty
            (Split-Path -Parent $file) | Should -Be (Split-Path -Parent $rows[0].BackupFile)
            (Split-Path -Leaf $file) | Should -Be ((Split-Path -Leaf $rows[0].BackupFile) -replace '_TakeOwnership\.csv$', '_NotOpened.txt')
            $listed = @(Get-Content -LiteralPath $file)
            foreach ($p in $script:LockedSet) { $listed | Should -Contain $p }

            $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
            $message | Should -Match ([regex]::Escape('Escalate: 5 folder(s) could not be opened, so they were left alone.'))
            $shown = @($rows[0].TreeCounts.UnlistedFolders | Select-Object -First 3)
            $message | Should -Match ([regex]::Escape("Not opened: $($shown -join '; ') and 2 more."))
            $message | Should -Match ([regex]::Escape("Full list: $file."))
            $message | Should -Match ([regex]::Escape('Ask a senior engineer to take ownership of them with an account that can open them.'))
            @([regex]::Matches($message, 'could not be opened')).Count | Should -Be 1 -Because 'one escalation, not two sentences saying the same thing'
        }

        It 'AC16c_MoreThanTwentyUnopenedFolders_DetailNamesTwentyAndPointsAtTheFullList' {
            $dir = New-TestTree 'fr1-many'
            $script:LockedSet = @(1..25 | ForEach-Object {
                $p = Join-Path $dir ('locked{0:00}' -f $_)
                New-Item -ItemType Directory -Path $p | Out-Null
                $p
            })
            Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $script:LockedSet -contains $LiteralPath }

            $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

            $file = $rows[0].TreeCounts.NotOpenedFile
            $detail = $rows[0].Detail
            $named = @($script:LockedSet | Where-Object { $detail.Contains($_ + ';') -or $detail.Contains($_ + ' and') })
            $named.Count | Should -Be 20
            $detail | Should -BeLike "* and 5 more (full list: $([WildcardPattern]::Escape($file)))*"
            @(Get-Content -LiteralPath $file | Where-Object { $script:LockedSet -contains $_ }).Count | Should -Be 25
        }

        It 'AC16c_NotOpenedListIsWrittenAfterTheToolsSoTheSnapshotIsTheOnlyBackupBeforeTheChange' {
            $dir = New-TestTree 'fr1-order'
            $script:Locked = Join-Path $dir 'sub'
            $script:FilesAtToolTime = [System.Collections.Generic.List[string]]::new()
            Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $script:Locked }
            Mock Invoke-AclTool {
                foreach ($f in @([System.IO.Directory]::GetFiles((Join-Path $script:Log 'Backups')))) { $script:FilesAtToolTime.Add($f) }
                [PSCustomObject]@{ ExitCode = 0; Output = '' }
            }

            $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

            @($script:FilesAtToolTime | Where-Object { $_ -like '*_NotOpened.txt' }).Count | Should -Be 0
            Test-Path -LiteralPath $rows[0].TreeCounts.NotOpenedFile | Should -BeTrue
        }

        It 'AC16c_NoFolderLeftUnopened_WritesNoNotOpenedList' {
            $dir = New-TestTree 'fr1-none'

            $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

            $rows[0].Result | Should -Be 'Done'
            $rows[0].TreeCounts.NotOpenedFile | Should -BeNullOrEmpty
            @(Get-ChildItem -LiteralPath (Join-Path $script:Log 'Backups') -Filter '*_NotOpened.txt').Count | Should -Be 0
        }
    }

    Context 'takeown /D only with /R' {
        It 'AC6_SingleItemTakeOwnership_PassesNoDAnswerWithoutR' {
            $dir = New-TestTree 'fr1-single'

            $null = @(Set-ItemOwnerToCurrentUser -Path $dir -LogFolder $script:Log)

            $takeown = @($script:ToolCalls | Where-Object { $_.Tool -eq 'takeown' })
            $takeown.Count | Should -Be 1
            $takeown[0].Arguments | Should -Not -Contain '/D'
            $takeown[0].Arguments | Should -Not -Contain 'Y'
        }

        It 'AC16b_NoTakeownCallInAnyScriptPassesYAfterD' {
            # Learn: "You must use this option in conjunction with the /r option"; Y replaces permissions.
            # https://learn.microsoft.com/windows-server/administration/windows-commands/takeown
            # -GUI.ps1 is the WPF app; -WebGUI.ps1 is the browser version it replaces (D-038). Both are scanned.
            foreach ($name in 'FolderPermissions.Core.ps1', 'FolderPermissionManager.ps1', 'FolderPermissionManager-GUI.ps1', 'FolderPermissionManager-WebGUI.ps1') {
                $path = (Resolve-Path (Join-Path $PSScriptRoot "..\$name")).Path
                $tokens = $null; $errors = $null
                $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
                $skip = @('Comment', 'NewLine', 'Comma', 'LineContinuation')
                $words = @($tokens | Where-Object { $skip -notcontains "$($_.Kind)" } | ForEach-Object {
                    if ($_ -is [System.Management.Automation.Language.StringToken]) { $_.Value } else { $_.Text }
                })
                for ($i = 0; $i -lt $words.Count - 1; $i++) {
                    if ($words[$i] -eq '/D') { $words[$i + 1] | Should -Not -Be 'Y' -Because "$name passes /D Y" }
                }
                foreach ($s in @($tokens | Where-Object { $_ -is [System.Management.Automation.Language.StringToken] })) {
                    $s.Value | Should -Not -Match '/D Y\b' -Because "$name builds a takeown /D Y command line"
                }
            }
        }
    }
}

# --- Fix round 2 (SQ-014 review 2026-10-18, D-036) --------------------------------------------
#
# Pinned for the implementer:
#   Links inside the tree: after Save-OwnerSnapshot and before takeown, every junction or symbolic
#          link the snapshot found (LinkPaths) goes through Get-TreeOwnershipTargetRefusal. One
#          that leads into a protected folder, or whose destination cannot be found out, refuses
#          the whole tree: the row is Failed, names the link, ends "Nothing was changed.", keeps
#          the snapshot and names it (BackupFile). The top-level check runs again right before
#          takeown. -AllowSystemFolder skips both.
#   Server-side links: a reparse point on the path (or above it) whose final form does not differ
#          from the path as given is refused ("where it leads could not be found out").
#   Which reparse points count as links (Test-LinkReparsePoint, D-040 allowlist): only the tags in
#          $script:RedirectFreeReparseTags (Data Deduplication, WOF, HSM, SIS, cloud placeholders)
#          are plain files; every other tag, DFS included, and a tag that cannot be read is a link.
#   System shares: \\host\SYSVOL, \\host\NETLOGON and \\host\PRINT$ (and under them) are refused.
#   Short names: an existing path with a '~<digit>' segment whose real path cannot be read at
#          all is refused ("could not check the real path").
#   An unopened folder whose owner cannot be read afterwards "could not be checked", never
#          "left alone". When _NotOpened.txt cannot be written, the message and Detail say the
#          full list could not be saved.
Describe 'Fix round 2 (review 2026-10-18): links inside the tree, server-side junctions, system shares' {
    BeforeAll {
        function Invoke-WithEnv {
            param([hashtable]$Values, [scriptblock]$Do)
            $old = @{}
            foreach ($k in $Values.Keys) {
                $old[$k] = [Environment]::GetEnvironmentVariable($k, 'Process')
                [Environment]::SetEnvironmentVariable($k, $Values[$k], 'Process')
            }
            try { & $Do } finally { foreach ($k in $old.Keys) { [Environment]::SetEnvironmentVariable($k, $old[$k], 'Process') } }
        }
        function New-TestJunction {
            param([string]$Link, [string]$Target)
            try { New-Item -ItemType Junction -Path $Link -Target $Target -ErrorAction Stop | Out-Null } catch { return $null }
            if (Test-Path -LiteralPath $Link) { $Link } else { $null }
        }
    }
    BeforeEach {
        $script:Log = Join-Path $TestDrive ('logs-' + [guid]::NewGuid().ToString('N'))
        $script:ToolCalls = [System.Collections.Generic.List[object]]::new()
        $script:ToolResult = @{
            takeown = [PSCustomObject]@{ ExitCode = 0; Output = '' }
            icacls  = [PSCustomObject]@{ ExitCode = 0; Output = '' }
        }
        Mock Set-Acl { }
        Mock takeown { }
        Mock icacls { }
        Mock Invoke-AclTool {
            $script:ToolCalls.Add([PSCustomObject]@{ Tool = $Tool; Arguments = @($Arguments) })
            $script:ToolResult[$Tool]
        }
        # A network path here is in no DFS namespace unless a test says otherwise.
        Mock Get-DfsTarget { }
        $script:Base = Join-Path $TestDrive ('ProtectedFolderForTests-' + [guid]::NewGuid().ToString('N'))
        $script:Protected = Join-Path $script:Base 'ContosoApplication'
        New-Item -ItemType Directory -Path (Join-Path $script:Protected 'sub') -Force | Out-Null
    }

    Context 'A junction or symbolic link inside the tree' {
        It 'AC16d_JunctionInsideTheTreeToAProtectedFolder_RefusesTheWholeTreeKeepsTheSnapshotAndCallsNoTool' {
            $dir = New-TestTree ('fr2-inner-' + [guid]::NewGuid().ToString('N'))
            $link = New-TestJunction -Link (Join-Path $dir 'sub\app') -Target $script:Protected
            if (-not $link) { Set-ItResult -Skipped -Because 'a junction could not be created here'; return }
            $script:Dir = $dir

            $rows = @(Invoke-WithEnv -Values @{ ProgramData = $script:Base } -Do {
                Set-ItemOwnerToCurrentUser -Path $script:Dir -Recurse -LogFolder $script:Log
            })

            $rows.Count | Should -Be 1
            $rows[0].Result | Should -Be 'Failed'
            $rows[0].Error | Should -Match ([regex]::Escape($link))
            $rows[0].Error | Should -Match 'Nothing was changed\.$'
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
            $rows[0].BackupFile | Should -Not -BeNullOrEmpty
            Test-Path -LiteralPath $rows[0].BackupFile | Should -BeTrue -Because 'the snapshot is kept'
            $rows[0].Error | Should -Match ([regex]::Escape($rows[0].BackupFile))
            (Get-FailedChangeState $rows[0]) | Should -Be 'Unchanged'
            $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
            $message | Should -Match ([regex]::Escape($link))
            $message | Should -Match 'Nothing was changed'
            $message | Should -Not -Match 'Some items may still have changed'
        }

        It 'AC16d_LinkInsideTheTreeWhoseDestinationCannotBeFoundOut_RefusesTheWholeTree' {
            $plain = Join-Path $TestDrive ('fr2-plain-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $plain | Out-Null
            $dir = New-TestTree ('fr2-unknown-' + [guid]::NewGuid().ToString('N'))
            $link = New-TestJunction -Link (Join-Path $dir 'elsewhere') -Target $plain
            if (-not $link) { Set-ItResult -Skipped -Because 'a junction could not be created here'; return }
            $script:Link = $link
            Mock Get-Win32PathName { $null } -ParameterFilter { $Path -eq $script:Link }

            $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

            $rows[0].Result | Should -Be 'Failed'
            $rows[0].Error | Should -Match ([regex]::Escape($link))
            $rows[0].Error | Should -Match 'where it leads could not be found out'
            $rows[0].Error | Should -Match 'Nothing was changed\.$'
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        }

        It 'AC16d_JunctionInsideTheTreeToAnOrdinaryFolder_StillTakesOwnership' {
            $plain = Join-Path $TestDrive ('fr2-plain-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $plain | Out-Null
            $dir = New-TestTree ('fr2-ok-' + [guid]::NewGuid().ToString('N'))
            $link = New-TestJunction -Link (Join-Path $dir 'elsewhere') -Target $plain
            if (-not $link) { Set-ItResult -Skipped -Because 'a junction could not be created here'; return }
            $script:Dir = $dir

            $rows = @(Invoke-WithEnv -Values @{ ProgramData = $script:Base } -Do {
                Set-ItemOwnerToCurrentUser -Path $script:Dir -Recurse -LogFolder $script:Log
            })

            $rows[0].Result | Should -Not -Be 'Failed'
            Should -Invoke Invoke-AclTool -Times 1 -Exactly -Scope It -ParameterFilter { $Tool -eq 'takeown' }
        }

        It 'AC16d_AllowSystemFolder_AlsoAllowsAJunctionInsideTheTreeToAProtectedFolder' {
            $dir = New-TestTree ('fr2-allow-' + [guid]::NewGuid().ToString('N'))
            $link = New-TestJunction -Link (Join-Path $dir 'app') -Target $script:Protected
            if (-not $link) { Set-ItResult -Skipped -Because 'a junction could not be created here'; return }
            $script:Dir = $dir

            $null = @(Invoke-WithEnv -Values @{ ProgramData = $script:Base } -Do {
                Set-ItemOwnerToCurrentUser -Path $script:Dir -Recurse -AllowSystemFolder -LogFolder $script:Log
            })

            Should -Invoke Invoke-AclTool -Times 1 -Exactly -Scope It -ParameterFilter { $Tool -eq 'takeown' }
        }

        It 'AC16d_TopLevelCheckRunsAgainRightBeforeTakeown' {
            $dir = New-TestTree ('fr2-toctou-' + [guid]::NewGuid().ToString('N'))
            $script:Dir = $dir
            $script:Checks = 0
            Mock Get-TreeOwnershipTargetRefusal {
                if ($Path -ne $script:Dir) { return $null }
                $script:Checks++
                if ($script:Checks -ge 2) { return "$Path now leads into a Windows system folder (test)." }
                $null
            }

            $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

            $script:Checks | Should -Be 2
            $rows[0].Result | Should -Be 'Failed'
            $rows[0].Error | Should -Match 'now leads into a Windows system folder \(test\)'
            $rows[0].Error | Should -Match 'Nothing was changed\.$'
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        }
    }

    Context 'Get-TreeOwnershipTargetRefusal: what the disk check cannot see' {
        It 'AC16d_ReparsePointThatResolvesToItself_IsRefusedAsUnknownDestination' {
            # On a share, the server follows its own junctions: the final path the client gets
            # back is the path as given, so where the junction leads cannot be seen.
            $script:Unc = '\\fs01\share\HR'
            Mock Test-Path { $true } -ParameterFilter { $LiteralPath -eq $script:Unc }
            Mock Get-Win32PathName { $Path }
            Mock Get-ReparsePointTag { $null }
            Mock Get-Item {
                if ($LiteralPath -eq $script:Unc) { return [PSCustomObject]@{ FullName = $LiteralPath; Attributes = [System.IO.FileAttributes]'Directory, ReparsePoint' } }
                [PSCustomObject]@{ FullName = $LiteralPath; Attributes = [System.IO.FileAttributes]::Directory }
            } -ParameterFilter { "$LiteralPath" -like '\\fs01\*' }

            $text = Get-TreeOwnershipTargetRefusal -Path $script:Unc

            $text | Should -Not -BeNullOrEmpty
            $text | Should -Match ([regex]::Escape($script:Unc))
            $text | Should -Match 'where it leads could not be found out'
        }

        It 'AC16d_FolderWithBracketsInsideAJunction_IsStillFound' {
            $target = Join-Path $TestDrive ('fr2-target-' + [guid]::NewGuid().ToString('N'))
            [System.IO.Directory]::CreateDirectory((Join-Path $target 'in[2]')) | Out-Null
            $link = New-TestJunction -Link (Join-Path $TestDrive ('fr2-jn-' + [guid]::NewGuid().ToString('N'))) -Target $target
            if (-not $link) { Set-ItResult -Skipped -Because 'a junction could not be created here'; return }
            $script:Inside = Join-Path $link 'in[2]'
            Mock Get-Win32PathName { $null }

            Test-PathThroughLink -Path $script:Inside | Should -BeTrue
            Get-TreeOwnershipTargetRefusal -Path $script:Inside | Should -Match 'where it leads could not be found out'
            Test-PathThroughLink -Path (Join-Path $target 'in[2]') | Should -BeFalse
        }

        It 'AC16d_ShortNameSpellingWhoseRealPathCannotBeRead_IsRefused' {
            $dir = Join-Path $TestDrive ('fr2-short-' + [guid]::NewGuid().ToString('N'))
            $script:Short = Join-Path $dir 'CONTOS~1\sub'
            New-Item -ItemType Directory -Path $script:Short -Force | Out-Null
            Mock Get-Win32PathName { $null }

            $text = Get-TreeOwnershipTargetRefusal -Path $script:Short

            $text | Should -Match ([regex]::Escape($script:Short))
            $text | Should -Match 'could not check the real path'
        }

        It 'AC16d_OrdinaryFolderWhoseRealPathCannotBeRead_IsAllowed' {
            $dir = Join-Path $TestDrive ('fr2-long-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $dir | Out-Null
            Mock Get-Win32PathName { $null }

            Get-TreeOwnershipTargetRefusal -Path $dir | Should -BeNullOrEmpty
        }

        It 'AC16d_OnlyAllowlistedReparseTagsArePlainFilesEveryOtherTagIsALink_<Name>' -ForEach @(
            @{ Name = 'junction'; Tag = [uint32]'0xA0000003'; Expected = $true }
            @{ Name = 'symbolic link'; Tag = [uint32]'0xA000000C'; Expected = $true }
            @{ Name = 'DFS link'; Tag = [uint32]'0x8000000A'; Expected = $true }
            @{ Name = 'deduplicated file'; Tag = [uint32]'0x80000013'; Expected = $false }
            @{ Name = 'cloud placeholder'; Tag = [uint32]'0x9000001A'; Expected = $false }
            @{ Name = 'tag that cannot be read'; Tag = $null; Expected = $true }
        ) {
            # D-040: only the tags in $script:RedirectFreeReparseTags are plain files; every other
            # tag (DFS 0x8000000A, which has no name-surrogate bit, included) is a link.
            # https://learn.microsoft.com/windows/win32/fileio/reparse-point-tags
            # https://learn.microsoft.com/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4
            $script:Tag = $Tag
            Mock Get-ReparsePointTag { $script:Tag }
            $item = [PSCustomObject]@{ FullName = 'D:\Data\x'; Attributes = [System.IO.FileAttributes]'Directory, ReparsePoint' }

            Test-LinkReparsePoint -Item $item | Should -Be $Expected
        }

        It 'AC16d_ItemWithoutReparsePointIsNeverALink' {
            Mock Get-ReparsePointTag { throw 'must not be read (test)' }
            Test-LinkReparsePoint -Item ([PSCustomObject]@{ FullName = 'D:\Data'; Attributes = [System.IO.FileAttributes]::Directory }) | Should -BeFalse
        }

        It 'AC16d_RealJunctionTagIsRead' {
            $plain = Join-Path $TestDrive ('fr2-plain-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $plain | Out-Null
            $link = New-TestJunction -Link (Join-Path $TestDrive ('fr2-jn-' + [guid]::NewGuid().ToString('N'))) -Target $plain
            if (-not $link) { Set-ItResult -Skipped -Because 'a junction could not be created here'; return }

            Get-ReparsePointTag -Path $link | Should -Be ([uint32]'0xA0000003')
            Get-ReparsePointTag -Path $plain | Should -BeNullOrEmpty
        }
    }

    Context 'Get-TreeOwnershipRefusal: system shares' {
        It 'AC16d_Refuses_<Path>' -ForEach @(
            @{ Path = '\\dc01\SYSVOL' }
            @{ Path = '\\dc01\sysvol\contoso.com\Policies' }
            @{ Path = '\\dc01.contoso.com\SysVol\' }
            @{ Path = '\\dc01\NETLOGON' }
            @{ Path = '\\dc01\netlogon\scripts' }
            @{ Path = '\\ps01\PRINT$' }
            @{ Path = '\\ps01\print$\x64' }
            @{ Path = '\\?\UNC\dc01\SYSVOL\contoso.com' }
        ) {
            $text = Get-TreeOwnershipRefusal -Path $Path

            $text | Should -Not -BeNullOrEmpty
            $text | Should -Match ([regex]::Escape($Path))
        }

        It 'AC16d_Allows_<Path>' -ForEach @(
            @{ Path = '\\fs01\Users$' }
            @{ Path = '\\fs01\HR$\2024' }
            @{ Path = '\\fs01\SYSVOLBackup' }
            @{ Path = '\\fs01\share\SYSVOL' }
            @{ Path = '\\fs01\share\NETLOGON' }
            @{ Path = '\\fs01\PRINT' }
        ) {
            Get-TreeOwnershipRefusal -Path $Path | Should -BeNullOrEmpty
        }
    }

    Context 'D-034 wording' {
        It 'AC16c_UnopenedFolderWhoseOwnerCannotBeReadAfterwards_SaysCouldNotBeCheckedNotLeftAlone' {
            $dir = New-TestTree ('fr2-unchecked-' + [guid]::NewGuid().ToString('N'))
            $script:Locked = Join-Path $dir 'sub'
            Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $script:Locked }
            Mock Get-ItemOwner {
                if ($Path -eq $script:Locked) {
                    if ($script:ToolCalls.Count -gt 0) { return [PSCustomObject]@{ Owner = 'Could not read'; OwnerSid = '' } }
                    return [PSCustomObject]@{ Owner = 'CONTOSO\old.owner'; OwnerSid = 'S-1-5-21-1-2-3-1105' }
                }
                & $script:RealGetItemOwner -Path $Path
            }

            $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

            $rows[0].Result | Should -Be 'Partly done'
            @($rows[0].TreeCounts.UnlistedUncheckedFolders) | Should -Be @($script:Locked)
            $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
            $message | Should -Not -Match 'left alone'
            $message | Should -Match 'could not be checked'
            $message | Should -Match ([regex]::Escape($script:Locked))
            $listed = @(Get-Content -LiteralPath $rows[0].TreeCounts.NotOpenedFile)
            @($listed | Where-Object { $_ -like "$($script:Locked)*could not be checked*" }).Count | Should -Be 1
        }

        It 'AC16c_NotOpenedListCannotBeWritten_MessageAndDetailSayTheFullListCouldNotBeSaved' {
            $dir = New-TestTree ('fr2-nolist-' + [guid]::NewGuid().ToString('N'))
            $script:LockedSet = @(1..25 | ForEach-Object {
                $p = Join-Path $dir ('locked{0:00}' -f $_)
                New-Item -ItemType Directory -Path $p | Out-Null
                $p
            })
            Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $script:LockedSet -contains $LiteralPath }
            Mock Set-Content { throw 'The disk is full. (test)' } -ParameterFilter { "$LiteralPath" -like '*_NotOpened*' }

            $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

            $rows[0].TreeCounts.NotOpenedFile | Should -BeNullOrEmpty
            $rows[0].Detail | Should -Match 'and 5 more \(the full list could not be saved'
            $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
            $message | Should -Match 'and 22 more\.'
            $message | Should -Match ([regex]::Escape('The full list could not be saved'))
        }
    }

    Context 'Owner snapshot clean-up' {
        It 'AC16_SnapshotCannotBeWritten_EmptyBackupsFolderIsRemovedWithoutRemoveItem' {
            $dir = New-TestTree ('fr2-cleanup-' + [guid]::NewGuid().ToString('N'))
            # The Backups folder is created as usual, but the snapshot goes to a folder that does
            # not exist, so Export-Csv fails.
            Mock New-BackupFilePath {
                $folder = Join-Path $LogFolder 'Backups'
                New-Item -ItemType Directory -Path $folder -Force | Out-Null
                Join-Path $folder 'no-such-folder\x_TakeOwnership.csv'
            }
            Mock Remove-Item { throw 'Remove-Item must not be used here (test)' }

            { Save-OwnerSnapshot -Path $dir -LogFolder $script:Log } | Should -Throw

            Test-Path -LiteralPath (Join-Path $script:Log 'Backups') | Should -BeFalse
            Should -Invoke Remove-Item -Times 0 -Exactly -Scope It
        }
    }
}

Describe 'README after fix round 2' {
    It 'AC16d_ReadmeSaysLinksInsideTheFolderAndSystemSharesAreRefused' {
        $readme = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\README.md') -Raw -Encoding UTF8
        $readme | Should -Match '(?i)junction or symbolic link inside the folder'
        $readme | Should -Match 'SYSVOL'
        $readme | Should -Match 'NETLOGON'
        $readme | Should -Match ([regex]::Escape('PRINT$'))
    }
}

# --- Revision (SQ-014 review 2026-10-18, Q-005 -> D-040): reparse allowlist -------------------
#
# Pinned for the implementer:
#   $script:RedirectFreeReparseTags  an [ordered] hashtable in FolderPermissions.Core.ps1,
#          tag name (IO_REPARSE_TAG_*) -> [uint32] value. The ONLY reparse tags that count as
#          plain files in Test-LinkReparsePoint. Every other tag (DFS 0x8000000A included, and
#          a tag that cannot be read) counts as a link and goes through Get-TreeLinkRefusal.
#          Each entry has a learn.microsoft.com citation on its own line or in the two lines
#          above it. Values from MS-FSCC 2.1.2.1 "Reparse Tags":
#          https://learn.microsoft.com/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4
#   IO_REPARSE_TAG_ONEDRIVE (0x80000021) is allowlisted too (lead decision: D-040 says the
#          cloud/OneDrive family). 22 entries in all.
Describe 'D-040 reparse allowlist: links inside the tree' {
    BeforeAll {
        # Learn MS-FSCC 2.1.2.1 values. Do not edit without owner approval (AC20d).
        $script:AllowedTags = [ordered]@{
            IO_REPARSE_TAG_DEDUP   = [uint32]'0x80000013'
            IO_REPARSE_TAG_WOF     = [uint32]'0x80000017'
            IO_REPARSE_TAG_HSM     = [uint32]'0xC0000004'
            IO_REPARSE_TAG_HSM2    = [uint32]'0x80000006'
            IO_REPARSE_TAG_SIS     = [uint32]'0x80000007'
            IO_REPARSE_TAG_ONEDRIVE = [uint32]'0x80000021'
            IO_REPARSE_TAG_CLOUD   = [uint32]'0x9000001A'
            IO_REPARSE_TAG_CLOUD_1 = [uint32]'0x9000101A'
            IO_REPARSE_TAG_CLOUD_2 = [uint32]'0x9000201A'
            IO_REPARSE_TAG_CLOUD_3 = [uint32]'0x9000301A'
            IO_REPARSE_TAG_CLOUD_4 = [uint32]'0x9000401A'
            IO_REPARSE_TAG_CLOUD_5 = [uint32]'0x9000501A'
            IO_REPARSE_TAG_CLOUD_6 = [uint32]'0x9000601A'
            IO_REPARSE_TAG_CLOUD_7 = [uint32]'0x9000701A'
            IO_REPARSE_TAG_CLOUD_8 = [uint32]'0x9000801A'
            IO_REPARSE_TAG_CLOUD_9 = [uint32]'0x9000901A'
            IO_REPARSE_TAG_CLOUD_A = [uint32]'0x9000A01A'
            IO_REPARSE_TAG_CLOUD_B = [uint32]'0x9000B01A'
            IO_REPARSE_TAG_CLOUD_C = [uint32]'0x9000C01A'
            IO_REPARSE_TAG_CLOUD_D = [uint32]'0x9000D01A'
            IO_REPARSE_TAG_CLOUD_E = [uint32]'0x9000E01A'
            IO_REPARSE_TAG_CLOUD_F = [uint32]'0x9000F01A'
        }
        # A reparse point as Get-ChildItem returns it. The folder is real (inside $TestDrive)
        # so Test-Path and Get-ItemOwner work; the reparse tag and the destination are faked.
        function New-FakeReparseChild {
            param([string]$Path)
            [PSCustomObject]@{
                FullName = $Path; Name = (Split-Path -Leaf $Path); PSIsContainer = $true
                Attributes = [System.IO.FileAttributes]'Directory, ReparsePoint'
            }
        }
    }
    BeforeEach {
        $script:Log = Join-Path $TestDrive ('logs-' + [guid]::NewGuid().ToString('N'))
        Mock Set-Acl { }
        Mock takeown { }
        Mock icacls { }
        Mock Invoke-AclTool { [PSCustomObject]@{ ExitCode = 0; Output = '' } }
        $script:Dir = Join-Path $TestDrive ('d040-' + [guid]::NewGuid().ToString('N'))
        $script:LinkPath = Join-Path $script:Dir 'redirected'
        New-Item -ItemType Directory -Path $script:LinkPath -Force | Out-Null
        Mock Get-ChildItem { New-FakeReparseChild -Path $script:LinkPath } -ParameterFilter { $LiteralPath -eq $script:Dir }
        Mock Get-ReparsePointTag { $script:Tag } -ParameterFilter { $Path -eq $script:LinkPath }
        Mock Get-DfsTarget { }
    }

    Context 'AC20a: a DFS reparse point to a protected folder or system share' {
        It 'AC20a_DfsReparsePointToAProtectedTarget_RefusesTheWholeTree_<Name>' -ForEach @(
            @{ Name = 'NETLOGON share'; Target = '\\dc01\NETLOGON' }
            @{ Name = 'SYSVOL share'; Target = '\\dc01\SYSVOL\contoso.com' }
            @{ Name = 'Windows folder'; Target = (Join-Path $env:SystemRoot 'System32') }
        ) {
            $script:Tag = [uint32]'0x8000000A'
            $script:Target = $Target
            Mock Get-Win32PathName { $script:Target } -ParameterFilter { $Path -eq $script:LinkPath }

            $rows = @(Set-ItemOwnerToCurrentUser -Path $script:Dir -Recurse -LogFolder $script:Log)

            $rows.Count | Should -Be 1
            $rows[0].Result | Should -Be 'Failed'
            $rows[0].Error | Should -Match ([regex]::Escape($script:LinkPath))
            $rows[0].Error | Should -Match 'Nothing was changed\.$'
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        }

        It 'AC20a_DfsReparsePointInsideTheTree_IsListedAsALink' {
            $script:Tag = [uint32]'0x8000000A'

            $tree = Get-OwnerTreeItem -Path $script:Dir

            @($tree.Links) | Should -Be @($script:LinkPath)
        }
    }

    Context 'AC20b: allowlisted tags are plain files' {
        It 'AC20b_ReparsePointWithTag_<Name>_IsNotALinkAndDoesNotRefuseTheTree' -ForEach @(
            @{ Name = 'IO_REPARSE_TAG_DEDUP'; Value = [uint32]'0x80000013' }
            @{ Name = 'IO_REPARSE_TAG_WOF'; Value = [uint32]'0x80000017' }
            @{ Name = 'IO_REPARSE_TAG_HSM'; Value = [uint32]'0xC0000004' }
            @{ Name = 'IO_REPARSE_TAG_HSM2'; Value = [uint32]'0x80000006' }
            @{ Name = 'IO_REPARSE_TAG_SIS'; Value = [uint32]'0x80000007' }
            @{ Name = 'IO_REPARSE_TAG_ONEDRIVE'; Value = [uint32]'0x80000021' }
            @{ Name = 'IO_REPARSE_TAG_CLOUD'; Value = [uint32]'0x9000001A' }
            @{ Name = 'IO_REPARSE_TAG_CLOUD_1'; Value = [uint32]'0x9000101A' }
            @{ Name = 'IO_REPARSE_TAG_CLOUD_2'; Value = [uint32]'0x9000201A' }
            @{ Name = 'IO_REPARSE_TAG_CLOUD_3'; Value = [uint32]'0x9000301A' }
            @{ Name = 'IO_REPARSE_TAG_CLOUD_4'; Value = [uint32]'0x9000401A' }
            @{ Name = 'IO_REPARSE_TAG_CLOUD_5'; Value = [uint32]'0x9000501A' }
            @{ Name = 'IO_REPARSE_TAG_CLOUD_6'; Value = [uint32]'0x9000601A' }
            @{ Name = 'IO_REPARSE_TAG_CLOUD_7'; Value = [uint32]'0x9000701A' }
            @{ Name = 'IO_REPARSE_TAG_CLOUD_8'; Value = [uint32]'0x9000801A' }
            @{ Name = 'IO_REPARSE_TAG_CLOUD_9'; Value = [uint32]'0x9000901A' }
            @{ Name = 'IO_REPARSE_TAG_CLOUD_A'; Value = [uint32]'0x9000A01A' }
            @{ Name = 'IO_REPARSE_TAG_CLOUD_B'; Value = [uint32]'0x9000B01A' }
            @{ Name = 'IO_REPARSE_TAG_CLOUD_C'; Value = [uint32]'0x9000C01A' }
            @{ Name = 'IO_REPARSE_TAG_CLOUD_D'; Value = [uint32]'0x9000D01A' }
            @{ Name = 'IO_REPARSE_TAG_CLOUD_E'; Value = [uint32]'0x9000E01A' }
            @{ Name = 'IO_REPARSE_TAG_CLOUD_F'; Value = [uint32]'0x9000F01A' }
        ) {
            $script:Tag = $Value
            # If the tag were treated as a link, this destination would refuse the tree.
            Mock Get-Win32PathName { '\\dc01\NETLOGON' } -ParameterFilter { $Path -eq $script:LinkPath }

            $tree = Get-OwnerTreeItem -Path $script:Dir
            @($tree.Links).Count | Should -Be 0
            Get-TreeLinkRefusal -Path $script:Dir -LinkPaths @($tree.Links) | Should -BeNullOrEmpty

            $rows = @(Set-ItemOwnerToCurrentUser -Path $script:Dir -Recurse -LogFolder $script:Log)
            $rows[0].Result | Should -Not -Be 'Failed'
            Should -Invoke Invoke-AclTool -Times 1 -Exactly -Scope It -ParameterFilter { $Tool -eq 'takeown' }
        }
    }

    Context 'AC20c: any other tag is a link, and an unresolvable link fails closed' {
        It 'AC20c_ReparsePointWithOtherTag_<Name>_WhoseTargetCannotBeFound_RefusesTheTree' -ForEach @(
            @{ Name = 'unknown 0x8000ABCD'; Value = [uint32]'0x8000ABCD' }
            @{ Name = 'IO_REPARSE_TAG_DFS'; Value = [uint32]'0x8000000A' }
            @{ Name = 'IO_REPARSE_TAG_APPEXECLINK'; Value = [uint32]'0x8000001B' }
            @{ Name = 'IO_REPARSE_TAG_NFS'; Value = [uint32]'0x80000014' }
        ) {
            $script:Tag = $Value
            Mock Get-Win32PathName { $null } -ParameterFilter { $Path -eq $script:LinkPath }

            $rows = @(Set-ItemOwnerToCurrentUser -Path $script:Dir -Recurse -LogFolder $script:Log)

            $rows[0].Result | Should -Be 'Failed'
            $rows[0].Error | Should -Match ([regex]::Escape($script:LinkPath))
            $rows[0].Error | Should -Match 'where it leads could not be found out'
            $rows[0].Error | Should -Match 'Nothing was changed\.$'
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        }

        It 'AC20c_ReparsePointWithUnknownTag_IsListedAsALink' {
            $script:Tag = [uint32]'0x8000ABCD'

            @((Get-OwnerTreeItem -Path $script:Dir).Links) | Should -Be @($script:LinkPath)
        }

        It 'AC20c_ReparsePointWithUnknownTag_ToAnOrdinaryFolderOutsideTheTree_IsStillAllowed' {
            $plain = Join-Path $TestDrive ('d040-plain-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $plain | Out-Null
            $script:Plain = $plain
            $script:Tag = [uint32]'0x8000ABCD'
            Mock Get-Win32PathName { $script:Plain } -ParameterFilter { $Path -eq $script:LinkPath }

            $rows = @(Set-ItemOwnerToCurrentUser -Path $script:Dir -Recurse -LogFolder $script:Log)

            $rows[0].Result | Should -Not -Be 'Failed'
            Should -Invoke Invoke-AclTool -Times 1 -Exactly -Scope It -ParameterFilter { $Tool -eq 'takeown' }
        }
    }

    Context 'AC20d: one allowlist, cited, pinned' {
        It 'AC20d_AllowlistExistsAsOneOrderedTableOfNameToValue' {
            $script:RedirectFreeReparseTags | Should -Not -BeNullOrEmpty
            $script:RedirectFreeReparseTags.Keys.Count | Should -Be $script:AllowedTags.Keys.Count
        }

        It 'AC20d_AllowlistHoldsExactlyTheApprovedTags' {
            @($script:RedirectFreeReparseTags.Keys | Sort-Object) | Should -Be @($script:AllowedTags.Keys | Sort-Object)
        }

        It 'AC20d_AllowlistValue_<Name>' -ForEach @(
            @{ Name = 'IO_REPARSE_TAG_DEDUP'; Value = [uint32]'0x80000013' }
            @{ Name = 'IO_REPARSE_TAG_WOF'; Value = [uint32]'0x80000017' }
            @{ Name = 'IO_REPARSE_TAG_HSM'; Value = [uint32]'0xC0000004' }
            @{ Name = 'IO_REPARSE_TAG_HSM2'; Value = [uint32]'0x80000006' }
            @{ Name = 'IO_REPARSE_TAG_SIS'; Value = [uint32]'0x80000007' }
            @{ Name = 'IO_REPARSE_TAG_ONEDRIVE'; Value = [uint32]'0x80000021' }
            @{ Name = 'IO_REPARSE_TAG_CLOUD'; Value = [uint32]'0x9000001A' }
            @{ Name = 'IO_REPARSE_TAG_CLOUD_F'; Value = [uint32]'0x9000F01A' }
        ) {
            [uint32]$script:RedirectFreeReparseTags[$Name] | Should -Be $Value
        }

        It 'AC20d_AllowlistValues_MatchTheApprovedTableForEveryEntry' {
            foreach ($name in $script:AllowedTags.Keys) {
                $script:RedirectFreeReparseTags.Contains($name) | Should -BeTrue -Because "$name is approved"
                [uint32]$script:RedirectFreeReparseTags[$name] | Should -Be $script:AllowedTags[$name] -Because $name
            }
        }

        It 'AC20d_EveryEntryHasALearnCitationOnItsLineOrTheTwoAbove' {
            $lines = @(Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\FolderPermissions.Core.ps1'))
            foreach ($name in $script:AllowedTags.Keys) {
                $hit = @(0..($lines.Count - 1) | Where-Object { $lines[$_] -match "^\s*['""]?$([regex]::Escape($name))['""]?\s*=" })
                $hit.Count | Should -Be 1 -Because "$name is defined once in the allowlist"
                $window = @($lines[([Math]::Max(0, $hit[0] - 2))..$hit[0]]) -join "`n"
                $window | Should -Match 'learn\.microsoft\.com' -Because "$name needs a Learn citation next to it"
            }
        }

        It 'AC20d_TestLinkReparsePoint_NoLongerUsesTheNameSurrogateBitInCode' {
            $text = (Get-Command Test-LinkReparsePoint).ScriptBlock.ToString()
            $tokens = $null
            [void][System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$null)
            @($tokens | Where-Object { $_.Kind -eq 'Number' -and $_.Text -match '(?i)^0x20000000$' }).Count | Should -Be 0
            $text | Should -Match 'RedirectFreeReparseTags'
        }
    }
}

# --- Fix round 1 of the D-040 revision (SQ-014 review 2026-10-19) ------------------------------
#
# Pinned for the implementer:
#   Get-DfsTarget -Path <\\server\share\...>  the targets (\\server\share\rest) of a path in a DFS
#          namespace, from NetDfsGetClientInfo level 3 (DFS_INFO_3). Outputs nothing when Windows
#          says the path is in no DFS namespace (NERR_DfsNoSuchVolume, 2662); throws when the
#          lookup fails. Mocked in every test; the file-level stub throws.
#   A link the listing found (LinkPaths) whose final path cannot be shown to differ from its own
#          path is refused ("where it leads could not be found out"); Get-Item is not asked again.
#   A DFS link (0x8000000A) on a network path is looked up with Get-DfsTarget and every target
#          goes through the D-036 checks (Get-TreeOwnershipRefusal). A protected target, no target
#          or a failed lookup refuses the tree; an ordinary target is allowed (owner chose A).
#   The chosen folder on a network path is looked up with Get-DfsTarget too: a protected target
#          or a failed lookup refuses; a path Windows says is not in DFS goes on as before.
#   Get-LinkKindName -Tag  'junction', 'symbolic link', 'DFS link', or
#          'other redirect (reparse point 0x........)'; refusals and results name what was found.
Describe 'D-040 fix round 1 (review 2026-10-19): DFS targets, unresolvable links, link kinds' {
    BeforeAll {
        function New-FakeReparseChild {
            param([string]$Path)
            [PSCustomObject]@{
                FullName = $Path; Name = (Split-Path -Leaf $Path); PSIsContainer = $true
                Attributes = [System.IO.FileAttributes]'Directory, ReparsePoint'
            }
        }
        # A folder tree on a network path, with nothing read from the network: the path exists,
        # it and every folder above it look like plain folders (as a DFS client shows a DFS
        # folder), its final path is -Final (or the path itself), and the owner snapshot,
        # the listing and the read-back are faked.
        function Set-UncTreeMock {
            param([string]$Top, [string]$Final, [string[]]$Links = @())
            $script:UncTop = $Top
            $script:UncFinal = $Final
            $script:UncLinks = @($Links)
            $script:SnapFile = Join-Path $TestDrive ('snap-' + [guid]::NewGuid().ToString('N') + '_TakeOwnership.csv')
            Set-Content -LiteralPath $script:SnapFile -Value 'Path,ItemType,Owner,OwnerSid'
            Mock Test-Path { $true } -ParameterFilter { "$LiteralPath" -like '\\*' }
            Mock Get-Item { [PSCustomObject]@{ FullName = "$LiteralPath"; Attributes = [System.IO.FileAttributes]::Directory } } -ParameterFilter { "$LiteralPath" -like '\\*' }
            Mock Get-Win32PathName { if ($Path -eq $script:UncTop -and $script:UncFinal) { $script:UncFinal } else { $Path } } -ParameterFilter { "$Path" -like '\\*' }
            Mock Get-OwnerTreeItem { [PSCustomObject]@{ Items = @([PSCustomObject]@{ Path = $script:UncTop; ItemType = 'Folder' }); Unlisted = @(); Links = @($script:UncLinks) } }
            Mock Save-OwnerSnapshot {
                [PSCustomObject]@{
                    File = $script:SnapFile; Count = 1
                    Items = @([PSCustomObject]@{ Path = $script:UncTop; ItemType = 'Folder'; Owner = 'CONTOSO\old.owner'; OwnerSid = 'S-1-5-21-1-2-3-1105' })
                    Unreadable = 0; Unlisted = 0; UnlistedFolders = @(); Links = @($script:UncLinks).Count; LinkPaths = @($script:UncLinks)
                }
            }
            Mock Get-OwnerReadBack { [PSCustomObject]@{ Mine = 1; NotMine = 0; Unchecked = 0; Changed = 1; AdministratorsOnly = $false; WatchedChanged = @(); WatchedUnchecked = @() } }
        }
    }
    BeforeEach {
        $script:Log = Join-Path $TestDrive ('logs-' + [guid]::NewGuid().ToString('N'))
        Mock Set-Acl { }
        Mock takeown { }
        Mock icacls { }
        Mock Invoke-AclTool { [PSCustomObject]@{ ExitCode = 0; Output = '' } }
        # A network path is in no DFS namespace unless a test says otherwise.
        Mock Get-DfsTarget { }
    }

    Context 'A link inside the tree whose destination cannot be shown to differ from its own path' {
        BeforeEach {
            $script:Dir = Join-Path $TestDrive ('d040fr1-' + [guid]::NewGuid().ToString('N'))
            $script:LinkPath = Join-Path $script:Dir 'redirected'
            New-Item -ItemType Directory -Path $script:LinkPath -Force | Out-Null
            Mock Get-ChildItem { New-FakeReparseChild -Path $script:LinkPath } -ParameterFilter { $LiteralPath -eq $script:Dir }
            Mock Get-ReparsePointTag { $script:Tag } -ParameterFilter { $Path -eq $script:LinkPath }
            # Asked again, the link looks like a plain folder (what a DFS client shows over SMB).
            Mock Get-Item { [PSCustomObject]@{ FullName = $script:LinkPath; Attributes = [System.IO.FileAttributes]::Directory } } -ParameterFilter { $LiteralPath -eq $script:LinkPath }
        }

        It 'AC20c_KnownLinkWhoseFinalPathIsItsOwnPath_IsRefusedWithoutAskingGetItem_<Name>_<Spelling>' -ForEach @(
            @{ Name = 'DFS link'; Tag = [uint32]'0x8000000A'; Spelling = 'as listed'; Prefix = '' }
            @{ Name = 'DFS link'; Tag = [uint32]'0x8000000A'; Spelling = 'with the long-path prefix'; Prefix = '\\?\' }
            @{ Name = 'junction'; Tag = [uint32]'0xA0000003'; Spelling = 'as listed'; Prefix = '' }
            @{ Name = 'other redirect'; Tag = [uint32]'0x8000ABCD'; Spelling = 'as listed'; Prefix = '' }
        ) {
            $script:Tag = $Tag
            $script:Prefix = $Prefix
            Mock Get-Win32PathName { "$($script:Prefix)$Path" } -ParameterFilter { $Path -eq $script:LinkPath }

            Get-TreeLinkRefusal -Path $script:Dir -LinkPaths @($script:LinkPath) | Should -Match 'where it leads could not be found out'
            $rows = @(Set-ItemOwnerToCurrentUser -Path $script:Dir -Recurse -LogFolder $script:Log)

            $rows[0].Result | Should -Be 'Failed'
            $rows[0].Error | Should -Match ([regex]::Escape($script:LinkPath))
            $rows[0].Error | Should -Match 'where it leads could not be found out'
            $rows[0].Error | Should -Match 'Nothing was changed\.$'
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
            Should -Invoke Get-Item -Times 0 -Exactly -Scope It -ParameterFilter { $LiteralPath -eq $script:LinkPath }
        }

        It 'AC20c_TheChosenFolderItselfIsAKnownLinkToItself_IsRefused' {
            # The chosen folder is in the listing's links too; it is not skipped.
            $script:Tag = [uint32]'0x8000000A'
            $script:Top = $script:LinkPath
            Mock Get-Win32PathName { $Path } -ParameterFilter { $Path -eq $script:Top }

            Get-TreeLinkRefusal -Path $script:Top -LinkPaths @($script:Top) | Should -Match 'where it leads could not be found out'
        }
    }

    Context 'A DFS link inside a tree on a network path' {
        BeforeEach {
            $script:Top = '\\fs01\share\Dept'
            $script:DfsLink = '\\fs01\share\Dept\Apps'
            Set-UncTreeMock -Top $script:Top -Links @($script:DfsLink)
            Mock Get-ReparsePointTag { [uint32]'0x8000000A' } -ParameterFilter { $Path -eq $script:DfsLink }
        }

        It 'AC20a_DfsLinkWhoseTargetIsNetlogon_IsRefusedAndNothingIsChanged' {
            Mock Get-DfsTarget { '\\dc01\NETLOGON' } -ParameterFilter { $Path -eq $script:DfsLink }

            $text = Get-TreeLinkRefusal -Path $script:Top -LinkPaths @($script:DfsLink)
            $rows = @(Set-ItemOwnerToCurrentUser -Path $script:Top -Recurse -LogFolder $script:Log)

            $text | Should -Match ([regex]::Escape($script:DfsLink))
            $text | Should -Match 'NETLOGON'
            $text | Should -Match 'DFS link'
            $rows[0].Result | Should -Be 'Failed'
            $rows[0].Error | Should -Match ([regex]::Escape($script:DfsLink))
            $rows[0].Error | Should -Match 'NETLOGON'
            $rows[0].Error | Should -Match 'Nothing was changed\.$'
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
            Should -Invoke Get-DfsTarget -Scope It -ParameterFilter { $Path -eq $script:DfsLink }
        }

        It 'AC20a_DfsLinkWithSeveralTargets_IsRefusedWhenAnyTargetIsProtected' {
            Mock Get-DfsTarget { '\\fs02\Apps$'; '\\dc01\SYSVOL\contoso.com' } -ParameterFilter { $Path -eq $script:DfsLink }

            Get-TreeLinkRefusal -Path $script:Top -LinkPaths @($script:DfsLink) | Should -Match 'SYSVOL'
        }

        It 'AC20a_DfsLinkWhoseTargetIsAnOrdinaryShareFolder_IsAllowed' {
            Mock Get-DfsTarget { '\\fs02\Apps$\Current' } -ParameterFilter { $Path -eq $script:DfsLink }

            Get-TreeLinkRefusal -Path $script:Top -LinkPaths @($script:DfsLink) | Should -BeNullOrEmpty
            $rows = @(Set-ItemOwnerToCurrentUser -Path $script:Top -Recurse -LogFolder $script:Log)

            $rows[0].Result | Should -Not -Be 'Failed'
            Should -Invoke Invoke-AclTool -Times 1 -Exactly -Scope It -ParameterFilter { $Tool -eq 'takeown' }
            $rows[0].Detail | Should -Match 'DFS link'
            $rows[0].Detail | Should -Not -Match ([regex]::Escape('junction(s) or symbolic link(s)'))
            $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
            $message | Should -Match 'DFS link'
            $message | Should -Match ([regex]::Escape($script:DfsLink))
            $message | Should -Not -Match ([regex]::Escape('junction(s) or symbolic link(s)'))
        }

        It 'AC20c_DfsLinkWhoseTargetLookupFails_IsRefused' {
            Mock Get-DfsTarget { throw 'The network path was not found. (test)' } -ParameterFilter { $Path -eq $script:DfsLink }

            $text = Get-TreeLinkRefusal -Path $script:Top -LinkPaths @($script:DfsLink)
            $rows = @(Set-ItemOwnerToCurrentUser -Path $script:Top -Recurse -LogFolder $script:Log)

            $text | Should -Match ([regex]::Escape($script:DfsLink))
            $text | Should -Match 'where it leads could not be found out'
            $rows[0].Result | Should -Be 'Failed'
            $rows[0].Error | Should -Match 'where it leads could not be found out'
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        }

        It 'AC20c_DfsLinkThatWindowsSaysIsInNoDfsNamespace_IsRefused' {
            # The tag says DFS, but no target is reported: nothing to check, so refused.
            $text = Get-TreeLinkRefusal -Path $script:Top -LinkPaths @($script:DfsLink)

            $text | Should -Match ([regex]::Escape($script:DfsLink))
            $text | Should -Match 'where it leads could not be found out'
        }
    }

    Context 'The chosen folder is a DFS link or under a DFS namespace' {
        BeforeEach {
            $script:Top = '\\contoso.com\dfs\HR'
        }

        It 'AC20a_TopLevelDfsToNetlogon_IsRefused_FinalPathIs<FinalIs>' -ForEach @(
            @{ FinalIs = 'the target' }
            @{ FinalIs = 'the path as given' }
        ) {
            $script:Target = '\\dc01\NETLOGON\scripts'
            Set-UncTreeMock -Top $script:Top -Final $(if ($FinalIs -eq 'the target') { $script:Target } else { '' })
            Mock Get-DfsTarget { $script:Target } -ParameterFilter { $Path -eq $script:Top }

            $text = Get-TreeOwnershipTargetRefusal -Path $script:Top
            $rows = @(Set-ItemOwnerToCurrentUser -Path $script:Top -Recurse -LogFolder $script:Log)

            $text | Should -Match ([regex]::Escape($script:Top))
            $text | Should -Match 'NETLOGON'
            $rows[0].Result | Should -Be 'Failed'
            $rows[0].Error | Should -Match 'Nothing was changed\.$'
            Should -Invoke Save-OwnerSnapshot -Times 0 -Exactly -Scope It
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        }

        It 'AC20a_TopLevelDfsToAnOrdinaryFolder_IsAllowed_FinalPathIs<FinalIs>' -ForEach @(
            @{ FinalIs = 'the target' }
            @{ FinalIs = 'the path as given' }
        ) {
            $script:Target = '\\fs02\HR$\Dept'
            Set-UncTreeMock -Top $script:Top -Final $(if ($FinalIs -eq 'the target') { $script:Target } else { '' })
            Mock Get-DfsTarget { $script:Target } -ParameterFilter { $Path -eq $script:Top }

            Get-TreeOwnershipTargetRefusal -Path $script:Top | Should -BeNullOrEmpty
            $rows = @(Set-ItemOwnerToCurrentUser -Path $script:Top -Recurse -LogFolder $script:Log)

            $rows[0].Result | Should -Not -Be 'Failed'
            Should -Invoke Invoke-AclTool -Times 1 -Exactly -Scope It -ParameterFilter { $Tool -eq 'takeown' }
        }

        It 'AC20c_TopLevelDfsThatCannotBeResolved_IsRefused_FinalPathIs<FinalIs>' -ForEach @(
            @{ FinalIs = 'the target' }
            @{ FinalIs = 'the path as given' }
        ) {
            Set-UncTreeMock -Top $script:Top -Final $(if ($FinalIs -eq 'the target') { '\\fs02\HR$\Dept' } else { '' })
            Mock Get-DfsTarget { throw 'NetDfsGetClientInfo failed (test)' } -ParameterFilter { $Path -eq $script:Top }

            $text = Get-TreeOwnershipTargetRefusal -Path $script:Top
            $rows = @(Set-ItemOwnerToCurrentUser -Path $script:Top -Recurse -LogFolder $script:Log)

            $text | Should -Match ([regex]::Escape($script:Top))
            $text | Should -Match 'where it leads could not be found out'
            $rows[0].Result | Should -Be 'Failed'
            Should -Invoke Save-OwnerSnapshot -Times 0 -Exactly -Scope It
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        }

        It 'AC20_TopLevelNetworkPathThatIsNotInDfs_GoesOnAsBefore' {
            $script:Top = '\\fs01\share\HR'
            Set-UncTreeMock -Top $script:Top

            Get-TreeOwnershipTargetRefusal -Path $script:Top | Should -BeNullOrEmpty
            Should -Invoke Get-DfsTarget -Scope It -ParameterFilter { $Path -eq $script:Top }
        }
    }

    Context 'What was found is named in plain English' {
        It 'AC20_LinkKindName_<Expected>' -ForEach @(
            @{ Tag = [uint32]'0xA0000003'; Expected = 'junction' }
            @{ Tag = [uint32]'0xA000000C'; Expected = 'symbolic link' }
            @{ Tag = [uint32]'0x8000000A'; Expected = 'DFS link' }
            @{ Tag = [uint32]'0x8000ABCD'; Expected = 'other redirect (reparse point 0x8000ABCD)' }
            @{ Tag = [uint32]'0x80000014'; Expected = 'other redirect (reparse point 0x80000014)' }
        ) {
            # MS-FSCC 2.1.2.1: IO_REPARSE_TAG_MOUNT_POINT 0xA0000003, IO_REPARSE_TAG_SYMLINK
            # 0xA000000C, IO_REPARSE_TAG_DFS 0x8000000A.
            Get-LinkKindName -Tag $Tag | Should -BeExactly $Expected
        }

        It 'AC20_LinkKindName_TagThatCannotBeRead_IsAnOtherRedirect' {
            Get-LinkKindName -Tag $null | Should -Match '^other redirect \(reparse point'
        }

        It 'AC20_RefusalNamesTheKind_<Name>' -ForEach @(
            @{ Name = 'DFS link'; Tag = [uint32]'0x8000000A'; Expected = 'a DFS link' }
            @{ Name = 'other redirect'; Tag = [uint32]'0x8000ABCD'; Expected = 'an other redirect (reparse point 0x8000ABCD)' }
            @{ Name = 'junction'; Tag = [uint32]'0xA0000003'; Expected = 'a junction' }
            @{ Name = 'symbolic link'; Tag = [uint32]'0xA000000C'; Expected = 'a symbolic link' }
        ) {
            $script:Tag = $Tag
            $dir = Join-Path $TestDrive ('d040kind-' + [guid]::NewGuid().ToString('N'))
            $script:KindLink = Join-Path $dir 'x'
            Mock Get-ReparsePointTag { $script:Tag } -ParameterFilter { $Path -eq $script:KindLink }
            Mock Get-Win32PathName { $null } -ParameterFilter { $Path -eq $script:KindLink }

            $text = Get-TreeLinkRefusal -Path $dir -LinkPaths @($script:KindLink)

            $text | Should -Match ([regex]::Escape($Expected))
            if ($Name -ne 'junction' -and $Name -ne 'symbolic link') {
                $text | Should -Not -Match 'junction or symbolic link'
            }
        }

        It 'AC20_ChosenFolderInsideALinkThatCannotBeFollowed_NamesTheKind' {
            $dir = Join-Path $TestDrive ('d040top-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $dir | Out-Null
            $script:TopDir = $dir
            Mock Get-Win32PathName { $null } -ParameterFilter { $Path -eq $script:TopDir }
            Mock Get-Item { [PSCustomObject]@{ FullName = $script:TopDir; Attributes = [System.IO.FileAttributes]'Directory, ReparsePoint' } } -ParameterFilter { $LiteralPath -eq $script:TopDir }
            Mock Get-ReparsePointTag { [uint32]'0x8000000A' } -ParameterFilter { $Path -eq $script:TopDir }

            $text = Get-TreeOwnershipTargetRefusal -Path $dir

            $text | Should -Match 'where it leads could not be found out'
            $text | Should -Match 'DFS link'
            $text | Should -Not -Match 'junction or symbolic link'
        }

        It 'AC20_AllowedLinkOfAnotherKind_DetailAndMessageNameItsKind' {
            $dir = Join-Path $TestDrive ('d040other-' + [guid]::NewGuid().ToString('N'))
            $script:OtherLink = Join-Path $dir 'redirected'
            New-Item -ItemType Directory -Path $script:OtherLink -Force | Out-Null
            $plain = Join-Path $TestDrive ('d040other-plain-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $plain | Out-Null
            $script:OtherDir = $dir
            $script:Plain = $plain
            Mock Get-ChildItem { New-FakeReparseChild -Path $script:OtherLink } -ParameterFilter { $LiteralPath -eq $script:OtherDir }
            Mock Get-ReparsePointTag { [uint32]'0x8000ABCD' } -ParameterFilter { $Path -eq $script:OtherLink }
            Mock Get-Win32PathName { $script:Plain } -ParameterFilter { $Path -eq $script:OtherLink }

            $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

            $rows[0].Result | Should -Not -Be 'Failed'
            $rows[0].Detail | Should -Match ([regex]::Escape('other redirect (reparse point 0x8000ABCD)'))
            $rows[0].Detail | Should -Not -Match ([regex]::Escape('junction(s) or symbolic link(s)'))
            $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
            $message | Should -Match ([regex]::Escape('other redirect (reparse point 0x8000ABCD)'))
            $message | Should -Not -Match ([regex]::Escape('junction(s) or symbolic link(s)'))
        }

        It 'AC20_UnresolvableRefusal_IsToldApartFromAProtectedFolderRefusal' {
            $dir = Join-Path $TestDrive ('d040hint-' + [guid]::NewGuid().ToString('N'))
            $script:HintLink = Join-Path $dir 'x'
            Mock Get-ReparsePointTag { [uint32]'0x8000ABCD' } -ParameterFilter { $Path -eq $script:HintLink }
            Mock Get-Win32PathName { $null } -ParameterFilter { $Path -eq $script:HintLink }
            $unresolved = Get-TreeLinkRefusal -Path $dir -LinkPaths @($script:HintLink)
            $protected = Get-TreeOwnershipRefusal -Path '\\dc01\NETLOGON'

            Test-UnresolvedDestinationRefusal -Refusal $unresolved | Should -BeTrue
            Test-UnresolvedDestinationRefusal -Refusal $protected | Should -BeFalse
        }
    }

    Context 'Test-LinkReparsePoint fails closed' {
        It 'AC20c_TagThatIsNotANumber_CountsAsALink' {
            Mock Get-ReparsePointTag { 'not a tag (test)' }
            $item = [PSCustomObject]@{ FullName = 'D:\Data\x'; Attributes = [System.IO.FileAttributes]'Directory, ReparsePoint' }

            Test-LinkReparsePoint -Item $item | Should -BeTrue
        }
    }

    Context 'Get-DfsTarget (the real one, no network)' {
        It 'AC20_GetDfsTarget_ALocalPathIsInNoDfsNamespaceAndTheLookupTypeCompiles' {
            # A local path never reaches NetDfsGetClientInfo or the network; the P/Invoke type is
            # still compiled, so a broken signature fails here rather than on a client's server.
            # On a build machine whose test folder is itself on the network, the real lookup
            # would ask the DFS client about a real share, so the test steps aside.
            $testDriveIsNetwork = "$TestDrive".StartsWith('\\') -or
                ((New-Object System.IO.DriveInfo -ArgumentList ([System.IO.Path]::GetPathRoot("$TestDrive"))).DriveType -eq [System.IO.DriveType]::Network)
            if ($testDriveIsNetwork) {
                Set-ItResult -Skipped -Because "the test folder $TestDrive is on a network path, and the real DFS lookup must not reach a real share"
                return
            }
            @(& $script:RealGetDfsTarget -Path $TestDrive).Count | Should -Be 0
            'FolderPermissionManager.Win32Dfs' -as [type] | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Windows PowerShell 5.1 reads the reparse allowlist the same way (D-040)' {
    It 'AC20d_UnderWindowsPowerShell51_AllowlistValuesAndLinkDecisionsMatch' {
        $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if (-not (Test-Path -LiteralPath $exe)) { Set-ItResult -Skipped -Because 'Windows PowerShell 5.1 is not installed here'; return }
        $core = (Resolve-Path (Join-Path $PSScriptRoot '..\FolderPermissions.Core.ps1')).Path
        $child = Join-Path $TestDrive 'ps51-allowlist.ps1'
        # A local path that is never created: the real Get-DfsTarget compiles its P/Invoke type
        # and returns for a path that is not on the network, without asking the DFS client. On a
        # build machine whose test folder is on the network, a path on the system drive is used.
        $localFake = Join-Path $TestDrive 'not-created-dfs-check'
        if ("$TestDrive".StartsWith('\\') -or
            (New-Object System.IO.DriveInfo -ArgumentList ([System.IO.Path]::GetPathRoot("$TestDrive"))).DriveType -eq [System.IO.DriveType]::Network) {
            $localFake = Join-Path $env:SystemDrive 'FolderPermissionManager-not-created'
        }
        # The child dot-sources the core as the suites do, then replaces Get-ReparsePointTag with
        # a stub, so no reparse point is created or read: the tag comes from the fake path. The
        # WNetGetConnection type (Import-Win32NetworkDriveType) is compiled but never called.
        Set-Content -LiteralPath $child -Encoding UTF8 -Value @'
param([string]$Core, [string]$LocalFake)
. $Core -LoadFunctionsOnly
function Get-ReparsePointTag { param([string]$Path) if ($Path -like '*dedup') { [uint32]'0x80000013' } else { [uint32]'0x8000000A' } }
function New-FakeItem { param([string]$Path) New-Object PSObject -Property @{ FullName = $Path; Attributes = [System.IO.FileAttributes]'Directory, ReparsePoint' } }
$dfsTargets = @(Get-DfsTarget -Path $LocalFake).Count
Import-Win32NetworkDriveType
'{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}' -f $PSVersionTable.PSVersion.Major,
    [uint32]$script:RedirectFreeReparseTags['IO_REPARSE_TAG_DEDUP'],
    [uint32]$script:RedirectFreeReparseTags['IO_REPARSE_TAG_CLOUD_F'],
    (Test-LinkReparsePoint -Item (New-FakeItem 'X:\fake\dedup')),
    (Test-LinkReparsePoint -Item (New-FakeItem 'X:\fake\dfs')),
    $dfsTargets,
    [bool]('FolderPermissionManager.Win32Dfs' -as [type]),
    [bool]('FolderPermissionManager.Win32NetworkDrive' -as [type])
'@

        $out = @(& $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $child -Core $core -LocalFake $localFake 2>&1 | ForEach-Object { "$_" })

        $LASTEXITCODE | Should -Be 0 -Because ($out -join "`n")
        $line = @($out | Where-Object { $_ -match '^\d+\|' })
        $line.Count | Should -Be 1 -Because ($out -join "`n")
        $parts = $line[0] -split '\|'
        $parts[0] | Should -Be '5'
        [uint32]$parts[1] | Should -Be ([uint32]'0x80000013')
        [uint32]$parts[2] | Should -Be ([uint32]'0x9000F01A')
        $parts[3] | Should -Be 'False' -Because 'a deduplicated file is a plain file'
        $parts[4] | Should -Be 'True' -Because 'a DFS link is a link'
        $parts[5] | Should -Be '0' -Because 'a local path is in no DFS namespace'
        $parts[6] | Should -Be 'True' -Because 'the NetDfsGetClientInfo declaration compiles under Windows PowerShell 5.1'
        $parts[7] | Should -Be 'True' -Because 'the WNetGetConnection declaration compiles under Windows PowerShell 5.1'
    }
}

Describe 'README after the D-040 fix round 1' {
    It 'AC20_ReadmeSplitsReparsePointsIntoRefusedAndAllowedAndSaysDfsTargetsAreLookedUp' {
        $readme = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\README.md') -Raw -Encoding UTF8
        $readme | Should -Match '\*\*Refused[^*]*\*\*'
        $readme | Should -Match '\*\*Allowed[^*]*\*\*'
        $readme | Should -Match '(?i)DFS[^.]*looked up'
    }
}

# --- Fix round 2 of the D-040 revision (SQ-014 review 2026-10-19) ------------------------------
#
# Pinned for the implementer:
#   Resolve-NetworkDrivePath -Path <path>  a path on a mapped network drive (H:\HR) as the
#          server path it stands for (\\contoso.com\dfs\HR); any other path as given. Throws when
#          the drive is a network drive whose server path Windows does not give. Uses
#          Get-DriveLetterType -Letter (DriveInfo.DriveType name) and
#          Get-NetworkDriveRemoteName -Letter (WNetGetConnection). Mocked in every test (the
#          file-level stub throws, a file-level mock hands the path back as given).
#   Get-TreeOwnershipTargetRefusal and Get-TreeLinkRefusal resolve -Path and every link first.
#          A network drive that cannot be resolved, and a network path that cannot be reached,
#          are refused ("where it leads could not be found out").
#   A link whose kind is 'DFS link' is looked up with Get-DfsTarget -IsDfsLink on its server
#          path whatever its spelling; any link on a network path is also looked up itself.
#   $script:ChosenFolderUncheckedText marks a refusal about the chosen folder itself (no link
#          involved); Test-ChosenFolderUncheckedRefusal tells it apart.
Describe 'D-040 fix round 2 (review 2026-10-19): mapped network drives, network paths fail closed' {
    BeforeAll {
        function New-FakeReparseChild {
            param([string]$Path)
            [PSCustomObject]@{
                FullName = $Path; Name = (Split-Path -Leaf $Path); PSIsContainer = $true
                Attributes = [System.IO.FileAttributes]'Directory, ReparsePoint'
            }
        }
        # A folder tree on mapped network drive H:, with nothing read from a drive or the
        # network: H:\... and \\... exist and look like plain folders, Resolve-NetworkDrivePath
        # turns H:\ into -Unc (or throws with -Unresolvable), Get-Win32PathName answers $null for
        # every H:\ path (CreateFile failed, as access denied on a parent does) unless -Final is
        # given for -Top or -LinkFinal for a link, and the listing, snapshot and read-back are
        # faked.
        function Set-MappedDriveTreeMock {
            param([string]$Top, [string]$Unc, [string]$Final, [string[]]$Links = @(), [string]$LinkFinal, [switch]$Unresolvable)
            $script:MapTop = $Top
            $script:MapUnc = $Unc
            $script:MapFinal = $Final
            $script:MapLinks = @($Links)
            $script:MapLinkFinal = $LinkFinal
            $script:SnapFile = Join-Path $TestDrive ('snap-' + [guid]::NewGuid().ToString('N') + '_TakeOwnership.csv')
            Set-Content -LiteralPath $script:SnapFile -Value 'Path,ItemType,Owner,OwnerSid'
            Mock Test-Path { $true } -ParameterFilter { "$LiteralPath" -like 'H:\*' -or "$LiteralPath" -like '\\*' }
            Mock Get-Item { [PSCustomObject]@{ FullName = "$LiteralPath"; Attributes = [System.IO.FileAttributes]::Directory } } -ParameterFilter { "$LiteralPath" -like 'H:\*' -or "$LiteralPath" -like '\\*' }
            Mock Get-Win32PathName {
                if ($Kind -eq 'Final' -and $Path -eq $script:MapTop -and $script:MapFinal) { return $script:MapFinal }
                if ($Kind -eq 'Final' -and @($script:MapLinks) -contains $Path -and $script:MapLinkFinal) { return $script:MapLinkFinal }
                $null
            } -ParameterFilter { "$Path" -like 'H:\*' }
            if ($Unresolvable) {
                Mock Resolve-NetworkDrivePath { throw 'The device is not currently connected, but it is a persistent connection. (test)' } -ParameterFilter { "$Path" -like 'H:*' }
            } else {
                Mock Resolve-NetworkDrivePath { $script:MapUnc + "$Path".Substring(2) } -ParameterFilter { "$Path" -like 'H:*' }
            }
            Mock Get-OwnerTreeItem { [PSCustomObject]@{ Items = @([PSCustomObject]@{ Path = $script:MapTop; ItemType = 'Folder' }); Unlisted = @(); Links = @($script:MapLinks) } }
            Mock Save-OwnerSnapshot {
                [PSCustomObject]@{
                    File = $script:SnapFile; Count = 1
                    Items = @([PSCustomObject]@{ Path = $script:MapTop; ItemType = 'Folder'; Owner = 'CONTOSO\old.owner'; OwnerSid = 'S-1-5-21-1-2-3-1105' })
                    Unreadable = 0; Unlisted = 0; UnlistedFolders = @(); Links = @($script:MapLinks).Count; LinkPaths = @($script:MapLinks)
                }
            }
            Mock Get-OwnerReadBack { [PSCustomObject]@{ Mine = 1; NotMine = 0; Unchecked = 0; Changed = 1; AdministratorsOnly = $false; WatchedChanged = @(); WatchedUnchecked = @() } }
        }
    }
    BeforeEach {
        $script:Log = Join-Path $TestDrive ('logs-' + [guid]::NewGuid().ToString('N'))
        Mock Set-Acl { }
        Mock takeown { }
        Mock icacls { }
        Mock Invoke-AclTool { [PSCustomObject]@{ ExitCode = 0; Output = '' } }
        # A network path is in no DFS namespace (2662) unless a test says otherwise.
        Mock Get-DfsTarget { }
    }

    Context 'The chosen folder is on a mapped network drive' {
        It 'AC20a_MappedDriveWithNoFinalPath_IsLookedUpInDfsByItsServerPathAndRefused' {
            # H: -> \\contoso.com\dfs; CreateFile failed, so there is no final path to go on.
            Set-MappedDriveTreeMock -Top 'H:\HR' -Unc '\\contoso.com\dfs'
            Mock Get-DfsTarget { '\\dc01\NETLOGON' } -ParameterFilter { $Path -eq '\\contoso.com\dfs\HR' }

            $text = Get-TreeOwnershipTargetRefusal -Path 'H:\HR'
            $rows = @(Set-ItemOwnerToCurrentUser -Path 'H:\HR' -Recurse -LogFolder $script:Log)

            $text | Should -Match ([regex]::Escape('H:\HR'))
            $text | Should -Match 'NETLOGON'
            $rows[0].Result | Should -Be 'Failed'
            $rows[0].Error | Should -Match 'NETLOGON'
            $rows[0].Error | Should -Match 'Nothing was changed\.$'
            Should -Invoke Get-DfsTarget -Scope It -ParameterFilter { $Path -eq '\\contoso.com\dfs\HR' }
            Should -Invoke Save-OwnerSnapshot -Times 0 -Exactly -Scope It
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        }

        It 'AC20a_MappedDriveToASystemShare_IsRefusedByItsServerPath' {
            Set-MappedDriveTreeMock -Top 'H:\scripts' -Unc '\\dc01\NETLOGON'

            $text = Get-TreeOwnershipTargetRefusal -Path 'H:\scripts'

            $text | Should -Match ([regex]::Escape('H:\scripts'))
            $text | Should -Match 'NETLOGON'
            Test-UnresolvedDestinationRefusal -Refusal $text | Should -BeFalse
        }

        It 'AC20c_MappedDriveThatCannotBeResolved_IsRefusedAsUnresolvedAndAboutTheChosenFolder' {
            Set-MappedDriveTreeMock -Top 'H:\HR' -Unresolvable

            $text = Get-TreeOwnershipTargetRefusal -Path 'H:\HR'
            $rows = @(Set-ItemOwnerToCurrentUser -Path 'H:\HR' -Recurse -LogFolder $script:Log)

            $text | Should -Match ([regex]::Escape('H:\HR'))
            $text | Should -Match 'where it leads could not be found out'
            Test-UnresolvedDestinationRefusal -Refusal $text | Should -BeTrue
            Test-ChosenFolderUncheckedRefusal -Refusal $text | Should -BeTrue
            $rows[0].Result | Should -Be 'Failed'
            $rows[0].Error | Should -Match 'where it leads could not be found out'
            Should -Invoke Save-OwnerSnapshot -Times 0 -Exactly -Scope It
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        }

        It 'AC20c_DfsLinkUnderAMappedDriveThatWindowsSaysIsInNoDfsNamespace_IsRefused_FinalPathIs<FinalIs>' -ForEach @(
            @{ FinalIs = 'unknown'; LinkFinal = '' }
            @{ FinalIs = 'another server'; LinkFinal = '\\?\UNC\fs02\Apps$\Current' }
        ) {
            # H: -> \\fs01\share. The listing found a DFS link; the DFS client answers 2662 for
            # it (the default mock), so there is no target to check: refused, whatever the
            # final path says.
            Set-MappedDriveTreeMock -Top 'H:\Dept' -Unc '\\fs01\share' -Links @('H:\Dept\Apps') -LinkFinal $LinkFinal
            Mock Get-ReparsePointTag { [uint32]'0x8000000A' } -ParameterFilter { $Path -eq 'H:\Dept\Apps' }

            $text = Get-TreeLinkRefusal -Path 'H:\Dept' -LinkPaths @('H:\Dept\Apps')
            $rows = @(Set-ItemOwnerToCurrentUser -Path 'H:\Dept' -Recurse -LogFolder $script:Log)

            $text | Should -Match ([regex]::Escape('H:\Dept\Apps'))
            $text | Should -Match 'DFS link'
            $text | Should -Match 'where it leads could not be found out'
            Test-ChosenFolderUncheckedRefusal -Refusal $text | Should -BeFalse
            Should -Invoke Get-DfsTarget -Scope It -ParameterFilter { $Path -eq '\\fs01\share\Dept\Apps' }
            $rows[0].Result | Should -Be 'Failed'
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        }

        It 'AC20a_DfsLinkUnderAMappedDriveToAProtectedTarget_IsRefused' {
            Set-MappedDriveTreeMock -Top 'H:\Dept' -Unc '\\fs01\share' -Links @('H:\Dept\Apps') -LinkFinal '\\?\UNC\fs02\Apps$'
            Mock Get-ReparsePointTag { [uint32]'0x8000000A' } -ParameterFilter { $Path -eq 'H:\Dept\Apps' }
            Mock Get-DfsTarget { '\\fs02\Apps$'; '\\dc01\SYSVOL\contoso.com' } -ParameterFilter { $Path -eq '\\fs01\share\Dept\Apps' }

            Get-TreeLinkRefusal -Path 'H:\Dept' -LinkPaths @('H:\Dept\Apps') | Should -Match 'SYSVOL'
        }

        It 'AC20_MappedDriveToAnOrdinaryShareNotInDfs_IsAllowed' {
            Set-MappedDriveTreeMock -Top 'H:\HR' -Unc '\\fs01\share'

            Get-TreeOwnershipTargetRefusal -Path 'H:\HR' | Should -BeNullOrEmpty
            $rows = @(Set-ItemOwnerToCurrentUser -Path 'H:\HR' -Recurse -LogFolder $script:Log)

            $rows[0].Result | Should -Not -Be 'Failed'
            Should -Invoke Get-DfsTarget -Scope It -ParameterFilter { $Path -eq '\\fs01\share\HR' }
            Should -Invoke Invoke-AclTool -Times 1 -Exactly -Scope It -ParameterFilter { $Tool -eq 'takeown' }
        }

        It 'AC20c_ChosenFolderInsideADfsLinkOnAMappedDrive_IsLookedUpAsADfsLink' {
            # The chosen folder H:\Dept\Apps is itself a DFS link (seen through Find-PathLink);
            # Windows has no DFS target for it: refused, even though H: is not a UNC spelling.
            Set-MappedDriveTreeMock -Top 'H:\Dept\Apps' -Unc '\\fs01\share'
            Mock Get-Item { [PSCustomObject]@{ FullName = 'H:\Dept\Apps'; Attributes = [System.IO.FileAttributes]'Directory, ReparsePoint' } } -ParameterFilter { $LiteralPath -eq 'H:\Dept\Apps' }
            Mock Get-ReparsePointTag { [uint32]'0x8000000A' } -ParameterFilter { $Path -eq 'H:\Dept\Apps' }

            $text = Get-TreeOwnershipTargetRefusal -Path 'H:\Dept\Apps'

            $text | Should -Match 'DFS link'
            $text | Should -Match 'where it leads could not be found out'
            Should -Invoke Get-DfsTarget -Scope It -ParameterFilter { $Path -eq '\\fs01\share\Dept\Apps' }
        }
    }

    Context 'A network path that cannot be confirmed fails closed' {
        It 'AC20c_UncPathThatCannotBeReached_IsRefusedInsteadOfCheckedAsText' {
            Mock Test-Path { $false } -ParameterFilter { "$LiteralPath" -like '\\*' }

            $text = Get-TreeOwnershipTargetRefusal -Path '\\contoso.com\dfs\HR'

            $text | Should -Match ([regex]::Escape('\\contoso.com\dfs\HR'))
            $text | Should -Match 'where it leads could not be found out'
            Test-ChosenFolderUncheckedRefusal -Refusal $text | Should -BeTrue
        }

        It 'AC20c_MappedDrivePathThatCannotBeReached_IsRefused' {
            Mock Resolve-NetworkDrivePath { '\\fs01\share' + "$Path".Substring(2) } -ParameterFilter { "$Path" -like 'H:*' }
            Mock Test-Path { $false } -ParameterFilter { "$LiteralPath" -like 'H:\*' }

            $text = Get-TreeOwnershipTargetRefusal -Path 'H:\HR'

            $text | Should -Match 'where it leads could not be found out'
            Test-ChosenFolderUncheckedRefusal -Refusal $text | Should -BeTrue
        }

        It 'AC20_LocalPathThatDoesNotExist_IsStillCheckedAsTextOnly' {
            $missing = Join-Path $TestDrive ('missing-' + [guid]::NewGuid().ToString('N'))

            Get-TreeOwnershipTargetRefusal -Path $missing | Should -BeNullOrEmpty
            Should -Invoke Get-DfsTarget -Times 0 -Exactly -Scope It
        }
    }

    Context 'Links inside a tree on a network path are looked up themselves' {
        BeforeEach {
            $script:Top = '\\fs01\share\Dept'
            $script:NetLink = '\\fs01\share\Dept\Data'
            Mock Test-Path { $true } -ParameterFilter { "$LiteralPath" -like '\\*' }
            Mock Get-Item { [PSCustomObject]@{ FullName = "$LiteralPath"; Attributes = [System.IO.FileAttributes]::Directory } } -ParameterFilter { "$LiteralPath" -like '\\*' }
        }

        It 'AC20a_JunctionOnANetworkPathWhoseOwnPathIsInDfs_IsRefusedByItsDfsTarget_TagIs<TagIs>' -ForEach @(
            @{ TagIs = 'a junction'; Tag = [uint32]'0xA0000003' }
            @{ TagIs = 'unreadable'; Tag = $null }
        ) {
            # The final path is an ordinary folder on another server, but the link's own path
            # is in a DFS namespace with a protected target: the link path is looked up too.
            $script:Tag = $Tag
            Mock Get-ReparsePointTag { $script:Tag } -ParameterFilter { $Path -eq $script:NetLink }
            Mock Get-Win32PathName { '\\?\UNC\fs03\data\x' } -ParameterFilter { $Path -eq $script:NetLink }
            Mock Get-DfsTarget { '\\dc01\SYSVOL\contoso.com' } -ParameterFilter { $Path -eq $script:NetLink }

            $text = Get-TreeLinkRefusal -Path $script:Top -LinkPaths @($script:NetLink)

            $text | Should -Match ([regex]::Escape($script:NetLink))
            $text | Should -Match 'SYSVOL'
            Should -Invoke Get-DfsTarget -Scope It -ParameterFilter { $Path -eq $script:NetLink }
        }

        It 'AC20c_LinkOnANetworkPathWhoseOwnDfsLookupFails_IsRefused' {
            Mock Get-ReparsePointTag { $null } -ParameterFilter { $Path -eq $script:NetLink }
            Mock Get-Win32PathName { '\\?\UNC\fs03\data\x' } -ParameterFilter { $Path -eq $script:NetLink }
            Mock Get-DfsTarget { throw 'The network path was not found. (test)' } -ParameterFilter { $Path -eq $script:NetLink }

            $text = Get-TreeLinkRefusal -Path $script:Top -LinkPaths @($script:NetLink)

            $text | Should -Match 'where it leads could not be found out'
            Test-ChosenFolderUncheckedRefusal -Refusal $text | Should -BeFalse
        }

        It 'AC20_JunctionOnANetworkPathToAnOrdinaryFolderNotInDfs_IsAllowed' {
            Mock Get-ReparsePointTag { [uint32]'0xA0000003' } -ParameterFilter { $Path -eq $script:NetLink }
            Mock Get-Win32PathName { '\\?\UNC\fs03\data\x' } -ParameterFilter { $Path -eq $script:NetLink }

            Get-TreeLinkRefusal -Path $script:Top -LinkPaths @($script:NetLink) | Should -BeNullOrEmpty
            Should -Invoke Get-DfsTarget -Scope It -ParameterFilter { $Path -eq $script:NetLink }
        }

        It 'AC20c_DfsLinkSpeltWithTheLongPathPrefix_IsLookedUpAsADfsLink' {
            $prefixed = '\\?\UNC\fs01\share\Dept\Apps'
            $script:Prefixed = $prefixed
            Mock Get-ReparsePointTag { [uint32]'0x8000000A' } -ParameterFilter { $Path -eq $script:Prefixed }
            Mock Get-Win32PathName { '\\?\UNC\fs02\Apps$' } -ParameterFilter { $Path -eq $script:Prefixed }

            $text = Get-TreeLinkRefusal -Path $script:Top -LinkPaths @($prefixed)

            $text | Should -Match 'where it leads could not be found out'
            Should -Invoke Get-DfsTarget -Scope It -ParameterFilter { $Path -eq '\\fs01\share\Dept\Apps' }
        }
    }

    Context 'Refusals about the chosen folder itself are told apart from link refusals' {
        It 'AC20c_TopLevelDfsLookupThatFails_IsAboutTheChosenFolder' {
            Mock Test-Path { $true } -ParameterFilter { "$LiteralPath" -like '\\*' }
            Mock Get-Item { [PSCustomObject]@{ FullName = "$LiteralPath"; Attributes = [System.IO.FileAttributes]::Directory } } -ParameterFilter { "$LiteralPath" -like '\\*' }
            Mock Get-Win32PathName { $Path } -ParameterFilter { "$Path" -like '\\*' }
            Mock Get-DfsTarget { throw 'NetDfsGetClientInfo failed (test)' } -ParameterFilter { $Path -eq '\\contoso.com\dfs\HR' }

            $text = Get-TreeOwnershipTargetRefusal -Path '\\contoso.com\dfs\HR'

            Test-UnresolvedDestinationRefusal -Refusal $text | Should -BeTrue
            Test-ChosenFolderUncheckedRefusal -Refusal $text | Should -BeTrue
        }

        It 'AC20c_LinkWhoseDestinationCannotBeFoundOut_IsNotAboutTheChosenFolder' {
            $dir = Join-Path $TestDrive ('r2link-' + [guid]::NewGuid().ToString('N'))
            $script:R2Link = Join-Path $dir 'x'
            Mock Get-ReparsePointTag { [uint32]'0x8000ABCD' } -ParameterFilter { $Path -eq $script:R2Link }
            Mock Get-Win32PathName { $null } -ParameterFilter { $Path -eq $script:R2Link }

            $text = Get-TreeLinkRefusal -Path $dir -LinkPaths @($script:R2Link)

            Test-UnresolvedDestinationRefusal -Refusal $text | Should -BeTrue
            Test-ChosenFolderUncheckedRefusal -Refusal $text | Should -BeFalse
        }

        It 'AC20_TheMarkerIsOneSharedConstant' {
            $script:ChosenFolderUncheckedText | Should -Not -BeNullOrEmpty
            (Get-Command Test-ChosenFolderUncheckedRefusal).ScriptBlock.ToString() | Should -Match 'ChosenFolderUncheckedText'
        }
    }

    Context 'Resolve-NetworkDrivePath (the real one, with the drive and WNetGetConnection faked)' {
        It 'AC20_NetworkDriveLetter_BecomesItsServerPath_<Spelling>' -ForEach @(
            @{ Spelling = 'plain'; Given = 'H:\HR\Payroll'; Expected = '\\contoso.com\dfs\HR\Payroll' }
            @{ Spelling = 'lower case'; Given = 'h:\HR'; Expected = '\\contoso.com\dfs\HR' }
            @{ Spelling = 'long-path prefix'; Given = '\\?\H:\HR'; Expected = '\\contoso.com\dfs\HR' }
            @{ Spelling = 'drive root'; Given = 'H:\'; Expected = '\\contoso.com\dfs' }
        ) {
            Mock Get-DriveLetterType { 'Network' }
            Mock Get-NetworkDriveRemoteName { '\\contoso.com\dfs' }

            & $script:RealResolveNetworkDrivePath -Path $Given | Should -BeExactly $Expected
            Should -Invoke Get-NetworkDriveRemoteName -Scope It -ParameterFilter { $Letter -eq 'H' }
        }

        It 'AC20_LocalFixedDriveOrUncPath_IsReturnedAsGiven_<Case>' -ForEach @(
            @{ Case = 'fixed drive'; Given = 'D:\Data\HR' }
            @{ Case = 'UNC path'; Given = '\\fs01\share\HR' }
        ) {
            Mock Get-DriveLetterType { 'Fixed' }
            Mock Get-NetworkDriveRemoteName { throw 'not called (test)' }

            & $script:RealResolveNetworkDrivePath -Path $Given | Should -BeExactly $Given
            Should -Invoke Get-NetworkDriveRemoteName -Times 0 -Exactly -Scope It
        }

        It 'AC20c_NetworkDriveWhoseServerPathCannotBeRead_Throws_<Case>' -ForEach @(
            @{ Case = 'WNetGetConnection fails'; Type = 'Network'; Remote = 'throw' }
            @{ Case = 'no server path'; Type = 'Network'; Remote = '' }
            @{ Case = 'not a server path'; Type = 'Network'; Remote = 'Z:\elsewhere' }
            @{ Case = 'drive type unknown'; Type = 'Unknown'; Remote = 'throw' }
        ) {
            $script:Type = $Type
            $script:Remote = $Remote
            Mock Get-DriveLetterType { $script:Type }
            Mock Get-NetworkDriveRemoteName { if ($script:Remote -eq 'throw') { throw 'The device is not currently connected (test)' } else { $script:Remote } }

            { & $script:RealResolveNetworkDrivePath -Path 'H:\HR' } | Should -Throw
        }

        It 'AC20c_DriveTypeThatCannotBeRead_Throws' {
            Mock Get-DriveLetterType { throw 'driveName does not refer to a valid drive (test)' }

            { & $script:RealResolveNetworkDrivePath -Path 'H:\HR' } | Should -Throw
        }

        It 'AC20_WNetGetConnectionDeclarationCompiles' {
            # Compiled only, never called: no drive mapping is read.
            Import-Win32NetworkDriveType
            'FolderPermissionManager.Win32NetworkDrive' -as [type] | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'README after the D-040 fix round 2' {
    It 'AC20_ReadmeSaysMappedNetworkDrivesAreResolvedToTheirServerPath' {
        $readme = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\README.md') -Raw -Encoding UTF8
        $readme | Should -Match '(?i)mapped network drives? (is|are) (resolved|turned) (in)?to (its|their) server path'
    }
}
