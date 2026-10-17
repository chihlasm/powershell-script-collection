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
        Invoke-AclTool -Tool takeown -Arguments '/F', <dir>, '/R', '/A', '/D', 'Y'
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
        $takeown[0].Arguments | Should -Be @('/F', $dir, '/R', '/A', '/D', 'Y')
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

        $rows[0].Result | Should -Be 'Done'
        $rows[0].TreeCounts.Unlisted | Should -Be 1
        @($rows[0].TreeCounts.UnlistedFolders) | Should -Be @($locked)
        Test-TreeEntryIncomplete $rows[0] | Should -BeTrue
        $saved = @(Import-Csv -LiteralPath $rows[0].BackupFile)
        @($saved | ForEach-Object { $_.Path }) | Should -Not -Contain (Join-Path $locked 'a.txt')
        $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
        $message | Should -BeLike "*1 folder(s) could not be opened ($locked)*"
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
        $rows[0].Detail | Should -BeLike "*Ran: takeown /F ""$dir"" /R /A /D Y; icacls ""$dir"" /setowner *"
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

    It 'AC18_FolderThatCannotBeListed_ItsPermissionsAreSavedBeforeTakeownReplacesThem' {
        # takeown /D Y replaces the permissions of a folder the account cannot list with full
        # control for the user only (takeown page on Learn), so they are saved first.
        $dir = New-TestTree 'ac18-perm'
        $locked = Join-Path $dir 'sub'
        $sddl = (& $script:RealGetAcl -LiteralPath $locked).Sddl
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $locked }

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        $permissionsFile = $rows[0].TreeCounts.PermissionsFile
        $permissionsFile | Should -Be ($rows[0].BackupFile -replace '\.csv$', '_Permissions.csv')
        foreach ($c in $script:ToolCalls) {
            $c.BackupFiles | Should -Contain $permissionsFile -Because 'the permissions must be saved before any native call'
        }
        $saved = @(Import-Csv -LiteralPath $permissionsFile)
        $saved.Count | Should -Be 1
        $saved[0].PSObject.Properties.Name | Should -Be @('Path', 'ItemType', 'Sddl')
        $saved[0].Path | Should -Be $locked
        $saved[0].Sddl | Should -Be $sddl
        $rows[0].TreeCounts.PermissionsUnsaved | Should -Be 0
        $rows[0].Detail | Should -BeLike "*replaces the permissions of those folders with full control*1 of 1 were saved to $permissionsFile*"

        $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
        $message | Should -BeLike "*takeown replaces the permissions of a folder it cannot open with full control for you only; the permissions those folders had were backed up to $permissionsFile first.*"
    }

    It 'AC18_FolderThatCannotBeListedOrRead_IsCountedAndNamedAsNotBackedUp' {
        $dir = New-TestTree 'ac18-perm-lost'
        $locked = Join-Path $dir 'sub'
        $script:UnreadableLike = $locked
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $locked }

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        @($script:ToolCalls).Count | Should -Be 2 -Because 'D-027: an unreadable folder does not stop the action'
        $saved = @(Import-Csv -LiteralPath $rows[0].TreeCounts.PermissionsFile)
        $saved[0].Sddl | Should -Be 'Could not read'
        $rows[0].TreeCounts.PermissionsUnsaved | Should -Be 1
        @($rows[0].TreeCounts.PermissionsUnsavedFolders) | Should -Be @($locked)
        $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $script:Log 'Changes_x.csv') -LogFolder $script:Log
        $message | Should -BeLike "*full control for you only; 1 could not be read, so their permissions were not backed up and are lost ($locked).*"
    }

    It 'AC18_PermissionsOfUnlistedFoldersCannotBeSaved_NothingIsChanged' {
        $dir = New-TestTree 'ac18-perm-fail'
        $locked = Join-Path $dir 'sub'
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $locked }
        Mock Export-Csv { throw 'disk full (test)' } -ParameterFilter { $LiteralPath -like '*_Permissions.csv' }

        $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -Recurse -LogFolder $script:Log)

        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        $rows[0].Result | Should -Be 'Failed'
        $rows[0].Error | Should -Match '^Could not save a backup of the current permissions'
        $rows[0].Error | Should -Match 'Nothing was changed\.$'
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
