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
    $script:RealGetAcl = Get-Command Get-Acl -CommandType Cmdlet
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
}
