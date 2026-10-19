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
#   Only name-surrogate reparse points count as links (Test-LinkReparsePoint): Data Deduplication
#          and cloud placeholders do not; a tag that cannot be read counts as a link.
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

        It 'AC16d_OnlyNameSurrogateReparsePointsCountAsLinks_<Name>' -ForEach @(
            @{ Name = 'junction'; Tag = [uint32]'0xA0000003'; Expected = $true }
            @{ Name = 'symbolic link'; Tag = [uint32]'0xA000000C'; Expected = $true }
            @{ Name = 'deduplicated file'; Tag = [uint32]'0x80000013'; Expected = $false }
            @{ Name = 'cloud placeholder'; Tag = [uint32]'0x9000001A'; Expected = $false }
            @{ Name = 'tag that cannot be read'; Tag = $null; Expected = $true }
        ) {
            # https://learn.microsoft.com/windows/win32/fileio/reparse-point-tags
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
