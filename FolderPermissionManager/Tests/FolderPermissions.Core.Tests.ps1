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
