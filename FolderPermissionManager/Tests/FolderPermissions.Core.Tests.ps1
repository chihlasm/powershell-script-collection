<#
    Tests for FolderPermissions.Core.ps1 (SQ-008, ACs 1-13 and 21; Pester 5, run under pwsh).

    Safety: Set-Acl and the native-tool wrapper (Invoke-AclTool) are ALWAYS mocked. Get-Acl is
    real, read-only, and only ever pointed at folders/files inside $TestDrive (or mocked). The GUI
    script is never loaded or launched.

    The Get-Acl / Set-Acl fakes model a tiny file system: Set-Acl records the ACL it was given,
    and a later Get-Acl for that path returns it (so "read back after the change" is testable).
    The Get-Acl fake forwards -LiteralPath / -Path exactly as the caller used them, so code that
    wrongly uses -Path on 'HR [old]' fails like the real cmdlet would (AC12).

    Run:  Invoke-Pester .\FolderPermissionManager\Tests
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..\FolderPermissions.Core.ps1') -LoadFunctionsOnly

    # The real cmdlet object: Pester mocks also intercept the module-qualified name.
    $script:RealGetAcl = Get-Command Get-Acl -CommandType Cmdlet
    $script:ExpectedColumns = @('Time', 'Technician', 'Computer', 'Action', 'Target', 'ItemType',
        'Detail', 'OldValue', 'NewValue', 'Result', 'Error', 'BackupFile')

    function New-TestFolder {
        param([string]$Name)
        $p = Join-Path $TestDrive $Name
        New-Item -ItemType Directory -Path $p -Force | Out-Null
        $p
    }
    function New-TestFile {
        param([string]$Name)
        $p = Join-Path $TestDrive $Name
        Set-Content -LiteralPath $p -Value 'x'
        $p
    }
    function Get-BackupFiles {
        param([string]$LogFolder)
        $dir = Join-Path $LogFolder 'Backups'
        if (-not (Test-Path -LiteralPath $dir)) { return @() }
        @(Get-ChildItem -LiteralPath $dir -File)
    }
    # SDDL of a real folder with an extra explicit rule added in memory (nothing is written).
    function Get-SeededSddl {
        param([string]$Path)
        $acl = & $script:RealGetAcl -LiteralPath $Path
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.NTAccount]'BUILTIN\Users',
            [System.Security.AccessControl.FileSystemRights]'Modify',
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
        $acl.Sddl
    }
}

Describe 'FolderPermissions.Core' {
    BeforeEach {
        $script:Applied = @{}      # path -> ACL object passed to Set-Acl
        $script:SetAclCalls = [System.Collections.Generic.List[object]]::new()
        $script:Seed = @{}         # path -> SDDL that Get-Acl should report before any change
        $script:FailSetAclFor = $null

        Mock Set-Acl {
            $p = if ($LiteralPath) { $LiteralPath } else { $Path }
            $backups = @()
            $dirs = @(Get-ChildItem -LiteralPath $TestDrive -Recurse -Directory -Filter Backups -ErrorAction SilentlyContinue)
            foreach ($d in $dirs) { $backups += @(Get-ChildItem -LiteralPath $d.FullName -File -ErrorAction SilentlyContinue) }
            $script:SetAclCalls.Add([PSCustomObject]@{
                Path          = $p
                BackupFiles   = @($backups | ForEach-Object { $_.FullName })
                BackupContent = @($backups | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw })
            })
            if ($script:FailSetAclFor -and $p -like $script:FailSetAclFor) { throw 'Access to the path is denied (test)' }
            $script:Applied[$p] = $AclObject
        }
        Mock Get-Acl {
            $p = if ($LiteralPath) { $LiteralPath } else { $Path }
            if ($script:Applied.ContainsKey($p)) { return $script:Applied[$p] }
            if ($LiteralPath) {
                $real = & $script:RealGetAcl -LiteralPath $LiteralPath
            } else {
                $real = & $script:RealGetAcl -Path $Path
            }
            if ($script:Seed.ContainsKey($p)) { $real.SetSecurityDescriptorSddlForm($script:Seed[$p]) }
            $real
        }
        Mock Invoke-AclTool { [PSCustomObject]@{ ExitCode = 0; Output = '' } }
    }

    Context 'Single-item changes' {
        It 'AC1_AddPermission_BacksUpOldSddlBeforeSetAclAndCallsSetAclOnce' {
            $dir = New-TestFolder 'ac1'
            $log = Join-Path $TestDrive 'ac1-logs'
            $old = (& $script:RealGetAcl -LiteralPath $dir).Sddl

            $null = Add-FolderPermission -Path $dir -Identity 'BUILTIN\Users' -Rights 'Modify' -Type Allow -LogFolder $log

            Should -Invoke Set-Acl -Times 1 -Exactly -Scope It
            $script:SetAclCalls[0].BackupFiles.Count | Should -Be 1 -Because 'the backup must exist when Set-Acl runs'
            $script:SetAclCalls[0].BackupFiles[0] | Should -BeLike '*.csv'
            $script:SetAclCalls[0].BackupContent[0] | Should -BeLike "*$old*"
        }

        It 'AC2_BackupCannotBeWritten_NothingChangedAndResultFailed' -ForEach @(
            @{ Which = 'Add' }, @{ Which = 'Remove' }, @{ Which = 'TakeOwnership' }, @{ Which = 'Copy' }
        ) {
            $dir = New-TestFolder "ac2-$Which"
            $src = New-TestFolder "ac2-src-$Which"
            $log = Join-Path $TestDrive "ac2-logs-$Which"
            Mock New-Item { throw 'disk full (test)' }
            Mock Export-Csv { throw 'disk full (test)' }

            $rows = switch ($Which) {
                'Add'           { Add-FolderPermission -Path $dir -Identity 'BUILTIN\Users' -Rights 'Modify' -LogFolder $log }
                'Remove'        { Remove-FolderPermission -Path $dir -Identity 'BUILTIN\Users' -Rights 'Modify' -LogFolder $log }
                'TakeOwnership' { Set-ItemOwnerToCurrentUser -Path $dir -LogFolder $log }
                'Copy'          { Copy-FolderPermission -SourcePath $src -TargetPath $dir -LogFolder $log }
            }

            Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
            @($rows).Count | Should -BeGreaterThan 0
            foreach ($r in @($rows)) {
                $r.Result | Should -Be 'Failed'
                $r.Error | Should -Match '^Could not save a backup of the current permissions'
                $r.Error | Should -Match 'Nothing was changed\.$'
            }
        }

        It 'AC3_AddPermission_RowHasPinnedColumnsAndValues' {
            $dir = New-TestFolder 'ac3'
            $log = Join-Path $TestDrive 'ac3-logs'
            $old = (& $script:RealGetAcl -LiteralPath $dir).Sddl

            $rows = @(Add-FolderPermission -Path $dir -Identity 'BUILTIN\Users' -Rights 'Modify' -Type Allow -LogFolder $log)

            $rows.Count | Should -Be 1
            $r = $rows[0]
            ($r.PSObject.Properties.Name -join ',') | Should -Be ($script:ExpectedColumns -join ',')
            $r.Time | Should -Match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$'
            $r.Technician | Should -Be ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
            $r.Computer | Should -Be $env:COMPUTERNAME
            $r.Action | Should -Be 'Add permission'
            $r.Target | Should -Be $dir
            $r.ItemType | Should -Be 'Folder'
            $r.Detail | Should -Be 'Allow Modify for BUILTIN\Users'
            $r.OldValue | Should -Be $old
            $r.NewValue | Should -Be $script:Applied[$dir].Sddl
            $r.NewValue | Should -Not -Be $old
            $r.Result | Should -Be 'Done'
            $r.Error | Should -BeNullOrEmpty
            $backups = Get-BackupFiles $log
            $backups.Count | Should -Be 1
            $r.BackupFile | Should -Be $backups[0].FullName
        }

        It 'AC4_RemovePermission_RowNamesIdentityRightsAndHasOldAndNewSddl' {
            $dir = New-TestFolder 'ac4'
            $log = Join-Path $TestDrive 'ac4-logs'
            $script:Seed[$dir] = Get-SeededSddl $dir

            $rows = @(Remove-FolderPermission -Path $dir -Identity 'BUILTIN\Users' -Rights 'Modify' -Type Allow -LogFolder $log)

            $rows.Count | Should -Be 1
            $r = $rows[0]
            $r.Action | Should -Be 'Remove permission'
            $r.Detail | Should -Be 'Allow Modify for BUILTIN\Users'
            $r.OldValue | Should -Be $script:Seed[$dir]
            $r.NewValue | Should -Be $script:Applied[$dir].Sddl
            $r.NewValue | Should -Not -Be $r.OldValue
            $r.Result | Should -Be 'Done'
        }

        It 'AC5_AddPermissionToThreeFiles_SecondFailsOthersContinue' {
            $files = @((New-TestFile 'a.txt'), (New-TestFile 'b.txt'), (New-TestFile 'c.txt'))
            $log = Join-Path $TestDrive 'ac5-logs'
            $script:FailSetAclFor = '*b.txt'

            $rows = @(Add-FolderPermission -Path $files -Identity 'BUILTIN\Users' -Rights 'Modify' -LogFolder $log)
            $logPath = Write-PermissionChangeLog -Entries $rows -LogFolder $log

            $backups = Get-BackupFiles $log
            $backups.Count | Should -Be 1
            @(Import-Csv -LiteralPath $backups[0].FullName).Count | Should -Be 3
            $rows.Count | Should -Be 3
            ($rows.Result -join ',') | Should -Be 'Done,Failed,Done'
            $rows[0].ItemType | Should -Be 'File'
            $rows[1].Error | Should -BeLike '*Access to the path is denied (test)*'
            Should -Invoke Set-Acl -Times 3 -Exactly -Scope It
            @(Import-Csv -LiteralPath $logPath).Count | Should -Be 3
        }

        It 'AC6_TakeOwnership_BackupHoldsOldSddlWithOwnerPart' {
            $dir = New-TestFolder 'ac6'
            $log = Join-Path $TestDrive 'ac6-logs'
            $old = (& $script:RealGetAcl -LiteralPath $dir).Sddl

            $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -LogFolder $log)

            $old | Should -Match '^O:'
            $backups = Get-BackupFiles $log
            $backups.Count | Should -Be 1
            $saved = @(Import-Csv -LiteralPath $backups[0].FullName)
            $saved[0].Sddl | Should -Be $old
            $rows[0].Action | Should -Be 'Take ownership'
            $rows[0].ItemType | Should -Be 'Folder'
            $rows[0].OldValue | Should -Be $old
            $rows[0].Result | Should -Be 'Done'
        }

        It 'AC7_CopyPermissionsToTwoTargets_MissingOneSkippedWithoutSetAcl' {
            $src = New-TestFolder 'ac7-src'
            $exists = New-TestFolder 'ac7-target'
            $missing = Join-Path $TestDrive 'ac7-missing'
            $log = Join-Path $TestDrive 'ac7-logs'
            $script:Seed[$src] = Get-SeededSddl $src

            $rows = @(Copy-FolderPermission -SourcePath $src -TargetPath @($exists, $missing) -LogFolder $log)

            $rows.Count | Should -Be 2
            $rows[0].Target | Should -Be $exists
            $rows[0].Action | Should -Be 'Copy permissions'
            $rows[0].Result | Should -Be 'Done'
            $rows[1].Target | Should -Be $missing
            $rows[1].Result | Should -Be 'Skipped (not found)'
            Should -Invoke Set-Acl -Times 1 -Exactly -Scope It
            Should -Invoke Set-Acl -Times 0 -Exactly -Scope It -ParameterFilter { $LiteralPath -eq $missing -or $Path -eq $missing }
            $backups = Get-BackupFiles $log
            $backups.Count | Should -Be 1
            $saved = @(Import-Csv -LiteralPath $backups[0].FullName)
            $saved.Path | Should -Contain $exists
            $saved.Path | Should -Not -Contain $missing
        }

        It 'AC8_WhatIf_NoSetAclNoToolNoBackupAndResultSkipped' {
            $dir = New-TestFolder 'ac8'
            $src = New-TestFolder 'ac8-src'
            $log = Join-Path $TestDrive 'ac8-logs'

            $rows = @()
            $rows += Add-FolderPermission -Path $dir -Identity 'BUILTIN\Users' -Rights 'Modify' -LogFolder $log -WhatIf
            $rows += Remove-FolderPermission -Path $dir -Identity 'BUILTIN\Users' -Rights 'Modify' -LogFolder $log -WhatIf
            $rows += Set-ItemOwnerToCurrentUser -Path $dir -LogFolder $log -WhatIf
            $rows += Copy-FolderPermission -SourcePath $src -TargetPath $dir -LogFolder $log -WhatIf

            Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
            (Get-BackupFiles $log).Count | Should -Be 0
            $rows.Count | Should -Be 4
            foreach ($r in $rows) { $r.Result | Should -Be 'Skipped (WhatIf)' }
        }

        It 'AC12_FolderNameWithBrackets_BackupHoldsItsRealSddl' {
            $dir = New-TestFolder 'HR [old]'
            $log = Join-Path $TestDrive 'ac12-logs'
            $real = (& $script:RealGetAcl -LiteralPath $dir).Sddl

            $rows = @(Add-FolderPermission -Path $dir -Identity 'BUILTIN\Users' -Rights 'Modify' -LogFolder $log)

            $rows[0].Result | Should -Be 'Done'
            $backups = Get-BackupFiles $log
            $backups.Count | Should -Be 1
            $saved = @(Import-Csv -LiteralPath $backups[0].FullName)
            $saved[0].Path | Should -Be $dir
            $saved[0].Sddl | Should -Be $real
            $rows[0].OldValue | Should -Be $real
        }

        It 'AC13_BackedUpSddl_RestoresModifiedAclInMemory' {
            $dir = New-TestFolder 'ac13'
            $log = Join-Path $TestDrive 'ac13-logs'
            $original = & $script:RealGetAcl -LiteralPath $dir

            $backup = Save-AclBackup -Path $dir -ActionSlug 'AddPermission' -LogFolder $log
            $sddl = @(Import-Csv -LiteralPath $backup)[0].Sddl

            $modified = & $script:RealGetAcl -LiteralPath $dir
            $modified.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
                [System.Security.Principal.NTAccount]'BUILTIN\Guests', 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Deny'))
            $modified.SetOwner([System.Security.Principal.NTAccount]'BUILTIN\Guests')
            $modified.GetSecurityDescriptorSddlForm('Access, Owner') | Should -Not -Be $original.GetSecurityDescriptorSddlForm('Access, Owner')

            $modified.SetSecurityDescriptorSddlForm($sddl)

            $modified.GetSecurityDescriptorSddlForm('Access') | Should -Be $original.GetSecurityDescriptorSddlForm('Access')
            $modified.GetOwner([System.Security.Principal.SecurityIdentifier]).Value |
                Should -Be $original.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        }
    }

    Context 'Change log' {
        It 'AC9_TwoWritesSameDay_OneFileOneHeaderAllRows' {
            $log = Join-Path $TestDrive 'ac9-logs'
            $e1 = New-PermissionChangeEntry -Action 'Add permission' -Target 'C:\a' -ItemType 'Folder' -Result 'Done'
            $e2 = New-PermissionChangeEntry -Action 'Remove permission' -Target 'C:\b' -ItemType 'Folder' -Result 'Done'
            $e3 = New-PermissionChangeEntry -Action 'Take ownership' -Target 'C:\c' -ItemType 'Folder' -Result 'Done'

            $p1 = Write-PermissionChangeLog -Entries @($e1) -LogFolder $log
            $p2 = Write-PermissionChangeLog -Entries @($e2, $e3) -LogFolder $log

            $p1 | Should -Be $p2
            (Split-Path $p1 -Leaf) | Should -Be ('Changes_{0}.csv' -f (Get-Date -Format 'yyyy-MM-dd'))
            @(Get-ChildItem -LiteralPath $log -File).Count | Should -Be 1
            $lines = @(Get-Content -LiteralPath $p1)
            @($lines | Where-Object { $_ -like '"Time","Technician"*' }).Count | Should -Be 1
            $rows = @(Import-Csv -LiteralPath $p1)
            $rows.Count | Should -Be 3
            ($rows[0].PSObject.Properties.Name -join ',') | Should -Be ($script:ExpectedColumns -join ',')
            ($rows.Target -join ',') | Should -Be 'C:\a,C:\b,C:\c'
        }

        It 'AC10_LogFolderUnwritable_ReturnsNullAndMessageSaysChangeWasMadeWithBackupPath' {
            $log = Join-Path $TestDrive 'ac10-logs'
            $backup = Join-Path $TestDrive 'ac10-backup.csv'
            $entry = New-PermissionChangeEntry -Action 'Add permission' -Target 'C:\a' -ItemType 'Folder' `
                -Result 'Done' -BackupFile $backup
            Mock New-Item { throw 'read-only (test)' }
            Mock Add-Content { throw 'read-only (test)' }

            $path = $null
            { $script:path = Write-PermissionChangeLog -Entries @($entry) -LogFolder $log } | Should -Not -Throw
            $script:path | Should -BeNullOrEmpty

            $msg = Get-ChangeResultMessage -Entries @($entry) -LogPath $null -LogFolder $log
            $msg | Should -BeLike '*The change was made*'
            $msg | Should -BeLike "*the change log could not be written to $log*"
            $msg | Should -BeLike "*$backup*"
        }

        It 'AC11_LogFolderResolution_FallsBackToLocalAppDataOrKeepsExplicitFolder' {
            $oldLocal = $env:LOCALAPPDATA
            try {
                $env:LOCALAPPDATA = Join-Path $TestDrive 'localappdata'
                $default = Join-Path $TestDrive 'readonly-share\Logs'
                $explicit = Join-Path $TestDrive 'chosen'
                Mock Test-LogFolderWritable { $false }

                $fallback = Resolve-ChangeLogFolder -DefaultFolder $default
                $fallback | Should -Be (Join-Path $env:LOCALAPPDATA 'FolderPermissionManager\Logs')

                Resolve-ChangeLogFolder -LogFolder $explicit -DefaultFolder $default | Should -Be $explicit
                Should -Invoke Test-LogFolderWritable -Times 0 -Exactly -Scope It -ParameterFilter { $Path -eq $explicit }

                Mock Test-LogFolderWritable { $true }
                Resolve-ChangeLogFolder -DefaultFolder $default | Should -Be $default
            } finally {
                $env:LOCALAPPDATA = $oldLocal
            }
        }
    }

    # Regression tests from the SQ-008 review (round 1). Not acceptance criteria of their own.
    Context 'Partly changed items (take ownership)' {
        It 'takeown succeeds and Set-Acl fails: Failed, NewValue read back, and the message says partly changed and points at the backup' {
            $dir = New-TestFolder 'own-partial'
            $log = Join-Path $TestDrive 'own-partial-logs'
            $old = (& $script:RealGetAcl -LiteralPath $dir).Sddl
            $script:FailSetAclFor = $dir
            # takeown /A really gives the folder to Administrators before Set-Acl runs.
            Mock Invoke-AclTool {
                $acl = & $script:RealGetAcl -LiteralPath $Arguments[1]
                $acl.SetOwner([System.Security.Principal.SecurityIdentifier]'S-1-5-32-544')
                $script:Seed[$Arguments[1]] = $acl.Sddl
                [PSCustomObject]@{ ExitCode = 0; Output = 'SUCCESS: The file (or folder) now owned by the administrators group.' }
            }

            $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -LogFolder $log)

            $r = $rows[0]
            $r.Result | Should -Be 'Failed'
            $r.OldValue | Should -Be $old
            $r.NewValue | Should -Match '^O:BA'
            $r.Error | Should -BeLike "Ownership was given to Administrators by takeown but could not be set to $([WildcardPattern]::Escape([Security.Principal.WindowsIdentity]::GetCurrent().Name)): Access to the path is denied (test).*"
            $r.Error | Should -BeLike '*partly changed*'
            $msg = Get-ChangeResultMessage -Entries $rows -LogPath 'C:\log.csv' -LogFolder $log
            $msg | Should -BeLike "*partly changed*$([WildcardPattern]::Escape($r.BackupFile))*Undo a change*"
            $msg | Should -Not -BeLike '*Nothing was changed*'
        }

        It 'takeown fails and Set-Acl fails: the error includes the exit code and what takeown said' {
            $dir = New-TestFolder 'own-both-fail'
            $log = Join-Path $TestDrive 'own-both-fail-logs'
            $script:FailSetAclFor = $dir
            Mock Invoke-AclTool { [PSCustomObject]@{ ExitCode = 1; Output = 'ERROR: The current logged on user does not have ownership privileges' } }

            $rows = @(Set-ItemOwnerToCurrentUser -Path $dir -LogFolder $log)

            $rows[0].Result | Should -Be 'Failed'
            $rows[0].Error | Should -BeLike '*takeown also failed (exit code 1): ERROR: The current logged on user does not have ownership privileges*'
            $msg = Get-ChangeResultMessage -Entries $rows -LogPath 'C:\log.csv' -LogFolder $log
            $msg | Should -BeLike '*Nothing was changed.*'
        }
    }

    Context 'Items whose permissions cannot be read' {
        BeforeEach {
            $script:TookOwn = $false
            Mock Get-Acl { throw 'Attempted to perform an unauthorized operation.' } -ParameterFilter {
                $LiteralPath -eq $script:Locked -and -not $script:TookOwn
            }
        }

        It 'Add, Remove and Copy refuse the item and change nothing' -ForEach @(
            @{ Which = 'Add' }, @{ Which = 'Remove' }, @{ Which = 'Copy' }
        ) {
            $script:Locked = New-TestFolder "locked-$Which"
            $src = New-TestFolder "locked-src-$Which"
            $log = Join-Path $TestDrive "locked-logs-$Which"

            $rows = @(switch ($Which) {
                'Add'    { Add-FolderPermission -Path $script:Locked -Identity 'BUILTIN\Users' -Rights 'Modify' -LogFolder $log }
                'Remove' { Remove-FolderPermission -Path $script:Locked -Identity 'BUILTIN\Users' -Rights 'Modify' -LogFolder $log }
                'Copy'   { Copy-FolderPermission -SourcePath $src -TargetPath $script:Locked -LogFolder $log }
            })

            Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
            (Get-BackupFiles $log).Count | Should -Be 0
            $rows.Count | Should -Be 1
            $rows[0].Result | Should -Be 'Failed'
            $rows[0].Error | Should -Match '^Could not read the current permissions, so nothing was changed'
            Get-ChangeResultMessage -Entries $rows -LogPath 'C:\log.csv' -LogFolder $log |
                Should -BeLike '*Could not read the current permissions, so nothing was changed*'
        }

        It 'Take ownership of one folder still proceeds: Could not read in the backup and the row, and the message says it cannot be restored' {
            $script:Locked = New-TestFolder 'locked-own'
            $log = Join-Path $TestDrive 'locked-own-logs'
            Mock Invoke-AclTool { $script:TookOwn = $true; [PSCustomObject]@{ ExitCode = 0; Output = '' } }

            $rows = @(Set-ItemOwnerToCurrentUser -Path $script:Locked -LogFolder $log)

            $rows[0].Result | Should -Be 'Done'
            $rows[0].OldValue | Should -Be 'Could not read'
            Should -Invoke Set-Acl -Times 1 -Exactly -Scope It
            $saved = @(Import-Csv -LiteralPath (Get-BackupFiles $log)[0].FullName)
            $saved[0].Sddl | Should -Be 'Could not read'
            Get-ChangeResultMessage -Entries $rows -LogPath 'C:\log.csv' -LogFolder $log |
                Should -BeLike '*1 item(s) had no readable permissions before the change and cannot be restored from this backup.*'
        }
    }

    Context 'Batch edges' {
        It 'every item failing: all rows Failed, one backup, and the message says nothing was changed' {
            $files = @((New-TestFile 'all1.txt'), (New-TestFile 'all2.txt'))
            $log = Join-Path $TestDrive 'all-fail-logs'
            $script:FailSetAclFor = '*all?.txt'

            $rows = @(Add-FolderPermission -Path $files -Identity 'BUILTIN\Users' -Rights 'Modify' -LogFolder $log)

            ($rows.Result -join ',') | Should -Be 'Failed,Failed'
            (Get-BackupFiles $log).Count | Should -Be 1
            $msg = Get-ChangeResultMessage -Entries $rows -LogPath 'C:\log.csv' -LogFolder $log
            $msg | Should -BeLike 'Nothing was changed. 2 failed. First error (*all1.txt): You do not have permission to change this item.*'
        }

        It 'zero items: no rows, no backup, no Set-Acl, nothing logged' {
            $log = Join-Path $TestDrive 'zero-logs'

            $rows = @(Add-FolderPermission -Path @() -Identity 'BUILTIN\Users' -Rights 'Modify' -LogFolder $log)

            $rows.Count | Should -Be 0
            (Get-BackupFiles $log).Count | Should -Be 0
            Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
            Write-PermissionChangeLog -Entries @() -LogFolder $log | Should -BeNullOrEmpty
            Get-ChangeResultMessage -Entries @() -LogPath $null -LogFolder $log | Should -Be 'Nothing was changed.'
        }

        It 'an empty path is a Skipped (not found) row, not a binding error' -ForEach @(
            @{ Which = 'Add' }, @{ Which = 'Remove' }, @{ Which = 'TakeOwnership' }, @{ Which = 'Copy' }
        ) {
            $dir = New-TestFolder "empty-$Which"
            $src = New-TestFolder "empty-src-$Which"
            $log = Join-Path $TestDrive "empty-logs-$Which"

            $rows = @(switch ($Which) {
                'Add'           { Add-FolderPermission -Path @('', $dir) -Identity 'BUILTIN\Users' -Rights 'Modify' -LogFolder $log }
                'Remove'        { Remove-FolderPermission -Path @('', $dir) -Identity 'BUILTIN\Users' -Rights 'Modify' -LogFolder $log }
                'TakeOwnership' { Set-ItemOwnerToCurrentUser -Path @('', $dir) -LogFolder $log }
                'Copy'          { Copy-FolderPermission -SourcePath $src -TargetPath @('', $dir) -LogFolder $log }
            })

            ($rows.Result -join ',') | Should -Be 'Skipped (not found),Done'
            $rows[0].Error | Should -Be 'No path was given.'
        }
    }

    Context 'Log folder' {
        It 'a UNC default folder falls back to LOCALAPPDATA without touching the share; an explicit UNC folder is kept and warned about' {
            $oldLocal = $env:LOCALAPPDATA
            try {
                $env:LOCALAPPDATA = Join-Path $TestDrive 'localappdata'
                Mock Test-LogFolderWritable { $true }
                $unc = '\\fs01\tools\FolderPermissionManager\Logs'

                Resolve-ChangeLogFolder -DefaultFolder $unc | Should -Be (Join-Path $env:LOCALAPPDATA 'FolderPermissionManager\Logs')
                Should -Invoke Test-LogFolderWritable -Times 0 -Exactly -Scope It

                Resolve-ChangeLogFolder -LogFolder $unc -DefaultFolder $unc | Should -Be $unc
                @(Get-ChangeLogFolderNotice -LogFolder $unc -ResolvedFolder $unc -DefaultFolder $unc)[0] |
                    Should -BeLike "The log folder $([WildcardPattern]::Escape($unc)) is on a network drive or share*"
                @(Get-ChangeLogFolderNotice -ResolvedFolder 'C:\x' -DefaultFolder $unc)[0] |
                    Should -BeLike '*running from a network or removable location*'
                @(Get-ChangeLogFolderNotice -ResolvedFolder 'C:\Tools\Logs' -DefaultFolder 'C:\Tools\Logs').Count | Should -Be 0
            } finally {
                $env:LOCALAPPDATA = $oldLocal
            }
        }

        It 'an empty LOCALAPPDATA uses the folder Windows reports; with none at all it stops and asks for -LogFolder' {
            $oldLocal = $env:LOCALAPPDATA
            try {
                $env:LOCALAPPDATA = ''
                Mock Test-LogFolderWritable { $false }
                $expected = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'FolderPermissionManager\Logs'
                Resolve-ChangeLogFolder -DefaultFolder (Join-Path $TestDrive 'ro\Logs') | Should -Be $expected

                Mock Get-LocalAppDataFolder { '' }
                { Resolve-ChangeLogFolder -DefaultFolder (Join-Path $TestDrive 'ro\Logs') } | Should -Throw '*-LogFolder*'
            } finally {
                $env:LOCALAPPDATA = $oldLocal
            }
        }
    }

    Context 'Backup integrity and the CSV files' {
        It 'a backup that does not read back as written is refused and nothing is changed' {
            $dir = New-TestFolder 'verify'
            $log = Join-Path $TestDrive 'verify-logs'
            Mock Import-Csv { [PSCustomObject]@{ Path = $dir; ItemType = 'Folder'; Sddl = 'D:(A;;FA;;;WD)' } }

            $rows = @(Add-FolderPermission -Path $dir -Identity 'BUILTIN\Users' -Rights 'Modify' -LogFolder $log)

            Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
            $rows[0].Result | Should -Be 'Failed'
            $rows[0].Error | Should -Match '^Could not save a backup of the current permissions.*does not hold the permissions read from.*Nothing was changed\.$'
        }

        It 'two backups in the same second get two files, and an existing backup is never overwritten' {
            $dir = New-TestFolder 'same-second'
            $log = Join-Path $TestDrive 'same-second-logs'

            $a = Save-AclBackup -Path $dir -ActionSlug 'AddPermission' -LogFolder $log
            $b = Save-AclBackup -Path $dir -ActionSlug 'AddPermission' -LogFolder $log

            $a | Should -Not -Be $b
            (Get-BackupFiles $log).Count | Should -Be 2
        }

        It 'text Excel would run as a formula is quoted in the change log and the backup, and the backup still verifies' {
            $log = Join-Path $TestDrive 'formula-logs'
            $src = New-TestFolder 'formula-src'

            $rows = @(Copy-FolderPermission -SourcePath $src -TargetPath '=1+1' -LogFolder $log)
            $rows[0].Result | Should -Be 'Skipped (not found)'
            $rows[0].Target | Should -Be '=1+1' -Because 'the GUI shows the real value'
            $logPath = Write-PermissionChangeLog -Entries $rows -LogFolder $log
            (Get-Content -LiteralPath $logPath -Raw) | Should -BeLike "*""'=1+1""*"
            @(Import-Csv -LiteralPath $logPath)[0].Target | Should -Be "'=1+1"

            Push-Location $TestDrive
            try {
                New-Item -ItemType Directory -Path '=sum' -Force | Out-Null
                $backup = Save-AclBackup -Path '=sum' -ActionSlug 'AddPermission' -LogFolder $log
            } finally {
                Pop-Location
            }
            $saved = @(Import-Csv -LiteralPath $backup)
            $saved[0].Path | Should -Be "'=sum"
            ConvertFrom-CsvSafeText $saved[0].Path | Should -Be '=sum'
            ConvertFrom-CsvSafeText "'quoted" | Should -Be "'quoted" -Because 'only a quote guarding a formula character is removed'
        }
    }

    Context 'Change log as each item completes' {
        It 'each row is in the log before the next item is changed, with one header' {
            $files = @((New-TestFile 'p1.txt'), (New-TestFile 'p2.txt'), (New-TestFile 'p3.txt'))
            $log = Join-Path $TestDrive 'stream-logs'
            $script:StreamLog = $log
            $script:RowsLoggedAtSetAcl = New-Object System.Collections.Generic.List[int]
            Mock Set-Acl {
                $day = Join-Path $script:StreamLog ('Changes_{0}.csv' -f (Get-Date -Format 'yyyy-MM-dd'))
                $script:RowsLoggedAtSetAcl.Add($(if (Test-Path -LiteralPath $day) { @(Import-Csv -LiteralPath $day).Count } else { 0 }))
            }

            $result = Invoke-LoggedPermissionChange -LogFolder $log -Change {
                Add-FolderPermission -Path $files -Identity 'BUILTIN\Users' -Rights 'Modify' -LogFolder $log
            }

            ($script:RowsLoggedAtSetAcl -join ',') | Should -Be '0,1,2'
            $result.Entries.Count | Should -Be 3
            $result.LogPath | Should -Exist
            @(Get-Content -LiteralPath $result.LogPath | Where-Object { $_ -like '"Time","Technician"*' }).Count | Should -Be 1
            @(Import-Csv -LiteralPath $result.LogPath).Count | Should -Be 3
        }

        It 'an interrupted batch still leaves the rows already done in the log' {
            $log = Join-Path $TestDrive 'interrupted-logs'

            { Invoke-LoggedPermissionChange -LogFolder $log -Change {
                New-PermissionChangeEntry -Action 'Add permission' -Target 'C:\a' -ItemType 'Folder' -Result 'Done'
                throw 'interrupted (test)'
            } } | Should -Throw '*interrupted (test)*'

            $day = Join-Path $log ('Changes_{0}.csv' -f (Get-Date -Format 'yyyy-MM-dd'))
            @(Import-Csv -LiteralPath $day).Target | Should -Be 'C:\a'
        }

        It 'one row that cannot be logged makes LogPath null so the message warns' {
            $log = Join-Path $TestDrive 'one-fails-logs'
            $script:LogCalls = 0
            Mock Write-PermissionChangeLog { $script:LogCalls++; if ($script:LogCalls -eq 1) { $null } else { 'C:\log.csv' } }

            $result = Invoke-LoggedPermissionChange -LogFolder $log -Change {
                New-PermissionChangeEntry -Action 'Add permission' -Target 'C:\a' -ItemType 'Folder' -Result 'Done'
                New-PermissionChangeEntry -Action 'Add permission' -Target 'C:\b' -ItemType 'Folder' -Result 'Done'
            }

            $result.LogPath | Should -BeNullOrEmpty
            $result.Entries.Count | Should -Be 2
        }
    }

    Context 'Messages' {
        It 'Remove permission says it removed all rules of that type for the account' {
            $e = New-PermissionChangeEntry -Action 'Remove permission' -Target 'C:\a' -ItemType 'Folder' -Detail 'Allow Modify for BUILTIN\Users' -Result 'Done' -BackupFile 'C:\b.csv'
            Get-ChangeResultMessage -Entries @($e) -LogPath 'C:\log.csv' -LogFolder 'C:\logs' |
                Should -BeLike 'Removed all Allow permissions for BUILTIN\Users (asked: Modify) from C:\a.*'
        }

        It 'raw access-denied errors are put in plain English; the log keeps the raw text' {
            $e = New-PermissionChangeEntry -Action 'Add permission' -Target 'C:\a' -ItemType 'Folder' -Result 'Failed' `
                -OldValue 'O:BAD:' -NewValue 'O:BAD:' -Error 'Attempted to perform an unauthorized operation.'
            $e.Error | Should -Be 'Attempted to perform an unauthorized operation.' -Because '-Error still binds (alias of -ErrorText)'
            Get-ChangeResultMessage -Entries @($e) -LogPath 'C:\log.csv' -LogFolder 'C:\logs' |
                Should -BeLike 'Add permission failed on C:\a: You do not have permission to change this item. Run the tool as administrator or take ownership first. Nothing was changed.*'
        }
    }
}

Describe 'Real cmdlet parameter names' {
    It 'AC21_ParametersCoreUsesOnGetAclAndSetAclExistOnTheRealCmdlets' {
        $corePath = Join-Path $PSScriptRoot '..\FolderPermissions.Core.ps1'
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $corePath).Path, [ref]$tokens, [ref]$errors)
        $calls = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)

        foreach ($name in 'Get-Acl', 'Set-Acl') {
            $real = Get-Command $name -CommandType Cmdlet
            $mine = @($calls | Where-Object { $_.GetCommandName() -eq $name })
            $mine.Count | Should -BeGreaterThan 0 -Because "the core must call $name (and with literal parameter names)"
            $used = @($mine | ForEach-Object {
                $_.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } |
                    ForEach-Object { $_.ParameterName }
            } | Sort-Object -Unique)
            foreach ($p in $used) {
                $real.Parameters.Keys -contains $p -or ($real.Parameters.Values.Aliases -contains $p) |
                    Should -BeTrue -Because "$name has no parameter -$p"
            }
        }
        # The parameters the spec names must be used and must exist on the real cmdlets.
        (Get-Command Get-Acl -CommandType Cmdlet).Parameters.Keys | Should -Contain 'LiteralPath'
        (Get-Command Set-Acl -CommandType Cmdlet).Parameters.Keys | Should -Contain 'LiteralPath'
        (Get-Command Set-Acl -CommandType Cmdlet).Parameters.Keys | Should -Contain 'AclObject'
        (Get-Command Set-Acl -CommandType Cmdlet).Parameters.Keys | Should -Contain 'WhatIf'
        $setUsed = @($calls | Where-Object { $_.GetCommandName() -eq 'Set-Acl' } | ForEach-Object {
            $_.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } |
                ForEach-Object { $_.ParameterName } })
        $setUsed | Should -Contain 'LiteralPath'
        $setUsed | Should -Contain 'AclObject'
    }
}
