<#
    Tests for SQ-022: the core's Copy-FolderPermission enforces the D-044 Copy refusals itself
    (Pester 5, run under pwsh). AC10 (the WPF app passes -AllowDeny) is in
    FolderPermissionManager-AppChanges.Tests.ps1.

    Decisions: D-051 (build the core guard), D-052 (Q2 = A: a source with explicit Deny entries is
    refused unless the caller passes -AllowDeny), D-053 (no server-side checks here).

    Safety: nothing is read from or written to the real machine.
    - Set-Acl, Invoke-AclTool, takeown and icacls are mocked with THROWING backstops that record
      the hit (AfterEach fails the test if one was reached unexpectedly; Set-Acl is replaced by a
      recording mock inside the tests that expect writes).
    - Get-Acl is mocked and returns in-memory ACLs built from SDDL; it never reads a path other
      than $TestDrive (the typed targets C:\Windows\... are never opened).
    - Get-AclItemType, Get-Win32PathName (final and long path reads) and Get-AppProfilesDirectory
      are mocked, so no protected folder and no profiles API is touched.
    - The protected-folder text check reads the Windows folder variables; they are set to literal
      values for the process in BeforeAll and restored in AfterAll, so the expected values never
      depend on this machine's %SystemRoot%.
    - Save-AclBackup writes its CSV into $TestDrive only (through a recording pass-through mock).

    Run:  Invoke-Pester .\FolderPermissionManager\Tests\CopyPermissions.Refusal.Tests.ps1
#>

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:CorePath = Join-Path $script:Root 'FolderPermissions.Core.ps1'
    $script:AppPath = Join-Path $script:Root 'FolderPermissionManager-GUI.ps1'

    . $script:CorePath -LoadFunctionsOnly
    # Guard: the real Invoke-AclTool runs takeown.exe and icacls.exe.
    function Invoke-AclTool {
        param(
            [Parameter(Mandatory)][ValidateSet('icacls', 'takeown')][string]$Tool,
            [Parameter(Mandatory)][string[]]$Arguments
        )
        throw "Invoke-AclTool ($Tool) was called without a mock in a test."
    }

    $script:RealGetAcl = Get-Command Get-Acl -CommandType Cmdlet
    $script:RealSaveAclBackup = ${function:Save-AclBackup}

    # Literal values for the folder variables the text check reads (Get-TreeOwnershipRefusal).
    $script:EnvNames = 'SystemRoot', 'ProgramFiles', 'ProgramW6432', 'ProgramFiles(x86)', 'ProgramData'
    $script:SavedEnv = @{}
    foreach ($n in $script:EnvNames) { $script:SavedEnv[$n] = [Environment]::GetEnvironmentVariable($n) }
    [Environment]::SetEnvironmentVariable('SystemRoot', 'C:\Windows')
    [Environment]::SetEnvironmentVariable('ProgramFiles', 'C:\Program Files')
    [Environment]::SetEnvironmentVariable('ProgramW6432', 'C:\Program Files')
    [Environment]::SetEnvironmentVariable('ProgramFiles(x86)', 'C:\Program Files (x86)')
    [Environment]::SetEnvironmentVariable('ProgramData', 'C:\ProgramData')

    function New-TestFolder {
        param([string]$Name)
        $p = Join-Path $TestDrive $Name
        New-Item -ItemType Directory -Path $p -Force | Out-Null
        $p
    }
    function New-Rule {
        param(
            [string]$Sid, [string]$Rights, [string]$Type = 'Allow',
            [string]$Inherit = 'ContainerInherit, ObjectInherit', [string]$Propagate = 'None'
        )
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]$Sid,
            [System.Security.AccessControl.FileSystemRights]$Rights,
            [System.Security.AccessControl.InheritanceFlags]$Inherit,
            [System.Security.AccessControl.PropagationFlags]$Propagate,
            [System.Security.AccessControl.AccessControlType]$Type)
    }
    function New-FakeAcl {
        param([object[]]$Rule = @(), [string]$Base = 'O:BAG:SYD:PAI')
        $acl = & $script:RealGetAcl -LiteralPath $TestDrive
        $acl.SetSecurityDescriptorSddlForm($Base)
        foreach ($r in $Rule) { $acl.AddAccessRule($r) }
        $acl
    }
    # Two explicit Allow rules: an ordinary source.
    function Get-AllowOnlySddl {
        (New-FakeAcl -Rule @(
            (New-Rule 'S-1-5-32-545' 'Modify')
            (New-Rule 'S-1-5-32-551' 'ReadAndExecute')
        )).Sddl
    }
    # Two explicit Allow rules and one explicit Deny.
    function Get-WithDenySddl {
        (New-FakeAcl -Rule @(
            (New-Rule 'S-1-5-32-545' 'Modify')
            (New-Rule 'S-1-5-32-551' 'ReadAndExecute')
            (New-Rule 'S-1-5-32-556' 'ReadData, AppendData' -Type 'Deny' -Inherit 'None')
        )).Sddl
    }
}

AfterAll {
    foreach ($n in $script:EnvNames) { [Environment]::SetEnvironmentVariable($n, $script:SavedEnv[$n]) }
}

# AC1 is a static check over both scripts and needs no mocks.
Describe 'SQ-022 AC1: the refusal helpers live in the core' {
    It 'AC1_CopyRefusalHelpersLiveInTheCore' {
        $names = 'Get-CopyTargetRefusal', 'Get-CopyTargetResolvedRefusal'
        $core = [System.Management.Automation.Language.Parser]::ParseFile($script:CorePath, [ref]$null, [ref]$null)
        $app = [System.Management.Automation.Language.Parser]::ParseFile($script:AppPath, [ref]$null, [ref]$null)
        $defs = { param($ast) @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name }) }
        $calls = { param($ast) @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() }) }

        $coreDefs = & $defs $core
        $appDefs = & $defs $app
        $appCalls = & $calls $app
        foreach ($n in $names) {
            $coreDefs | Should -Contain $n -Because "FolderPermissions.Core.ps1 must define $n"
            $appDefs | Should -Not -Contain $n -Because "FolderPermissionManager-GUI.ps1 must not keep its own copy of $n"
            $appCalls | Should -Contain $n -Because "the app still calls $n (now the core's)"
        }
    }
}

Describe 'Copy-FolderPermission refuses protected targets itself (SQ-022)' {
    BeforeEach {
        $script:Applied = @{}      # path -> ACL object passed to Set-Acl
        $script:Seed = @{}         # path -> SDDL Get-Acl reports (anything else: an empty ACL)
        $script:BackstopHit = [System.Collections.Generic.List[string]]::new()
        $script:BackupPaths = [System.Collections.Generic.List[object]]::new()

        Mock Set-Acl {
            $p = if ($LiteralPath) { $LiteralPath } else { $Path }
            $script:Applied[$p] = $AclObject
        }
        # Never reads a real path: a seeded SDDL or an empty in-memory ACL.
        Mock Get-Acl {
            $p = if ($LiteralPath) { $LiteralPath } else { $Path }
            if ($script:Applied.ContainsKey($p)) { return $script:Applied[$p] }
            $acl = & $script:RealGetAcl -LiteralPath $TestDrive
            $sddl = if ($script:Seed.ContainsKey($p)) { $script:Seed[$p] } else { 'O:BAG:SYD:PAI' }
            $acl.SetSecurityDescriptorSddlForm($sddl)
            $acl
        }
        Mock Invoke-AclTool { $script:BackstopHit.Add('Invoke-AclTool'); throw 'Invoke-AclTool was reached without a test mock.' }
        Mock takeown { $script:BackstopHit.Add('takeown'); throw 'takeown was reached.' }
        Mock icacls { $script:BackstopHit.Add('icacls'); throw 'icacls was reached.' }

        # Every typed target "exists" as a folder; every path is what it says it is; the profiles
        # folder is the literal C:\Users (the real GetProfilesDirectoryW never runs).
        Mock Get-AclItemType { 'Folder' }
        Mock Get-Win32PathName { $Path }
        Mock Get-AppProfilesDirectory { 'C:\Users' }
        Mock Write-PermissionChangeLog { }
        # Records the paths of each backup and still writes the CSV (into $TestDrive only).
        Mock Save-AclBackup {
            $script:BackupPaths.Add(@($Path))
            & $script:RealSaveAclBackup -Path $Path -ActionSlug $ActionSlug -LogFolder $LogFolder
        }
    }
    AfterEach {
        $script:BackstopHit.Count | Should -Be 0 -Because 'a native ACL tool must never be reached'
    }

    It 'AC2_CopyRefusesProtectedTargetsByText_<Target>' -ForEach @(
        @{ Target = '\\fs01\ADMIN$\x'; Reason = 'ADMIN\$ administrative share' }
        @{ Target = '\\fs01\SYSVOL\corp.local\scripts'; Reason = 'SYSVOL share' }
        @{ Target = '\\fs01\netlogon'; Reason = 'NETLOGON share' }
        @{ Target = '\\fs01\PRINT$\x64'; Reason = 'PRINT\$ share' }
        @{ Target = '\\fs01\IPC$'; Reason = 'IPC\$ share' }
        @{ Target = '\\fs01\D$'; Reason = 'D\$ administrative share' }
        @{ Target = 'C:\Windows\Temp'; Reason = 'Windows system folder' }
        @{ Target = 'C:\Windows\'; Reason = 'Windows system folder' }
        @{ Target = 'C:\\Windows'; Reason = 'Windows system folder' }
        @{ Target = '\\?\C:\Windows.'; Reason = 'Windows system folder' }
        @{ Target = 'C:\Program Files\App'; Reason = 'Windows system folder' }
        @{ Target = 'C:\ProgramData\Vendor'; Reason = 'Windows system folder' }
        @{ Target = 'D:\'; Reason = 'root of a whole drive' }
        @{ Target = 'C:\Users'; Reason = 'every user profile' }
    ) {
        $src = New-TestFolder 'ac2-src'
        $log = Join-Path $TestDrive 'ac2-logs'
        $script:Seed[$src] = Get-AllowOnlySddl

        $rows = @(Copy-FolderPermission -SourcePath $src -TargetPath $Target -LogFolder $log)

        $rows.Count | Should -Be 1
        $rows[0].Result | Should -Be 'Failed' -Because "$Target is protected"
        $rows[0].Error | Should -Match $Reason
        $rows[0].Error | Should -BeLike '*Nothing was changed.'
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
        Should -Invoke Save-AclBackup -Times 0 -Exactly -Scope It
    }

    It 'AC3_CopyRefusesATargetThatReallyLeadsIntoAProtectedFolder_<Case>' -ForEach @(
        @{ Case = 'FinalPath'; Final = '\\?\C:\Windows\System32'; Long = $null; Leads = 'C:\Windows\System32' }
        @{ Case = 'LongNameOnly'; Final = $null; Long = 'C:\Program Files'; Leads = 'C:\Program Files' }
    ) {
        $src = New-TestFolder 'ac3-src'
        $target = New-TestFolder "ac3-junction-$Case"
        $log = Join-Path $TestDrive 'ac3-logs'
        $script:Seed[$src] = Get-AllowOnlySddl
        $script:Real3 = $target; $script:Final3 = $Final; $script:Long3 = $Long
        Mock Get-Win32PathName {
            if ($Path -ne $script:Real3) { return $Path }
            if ($Kind -eq 'Long') { if ($script:Long3) { $script:Long3 } else { $Path } }
            else { if ($script:Final3) { $script:Final3 } else { $Path } }
        }

        $rows = @(Copy-FolderPermission -SourcePath $src -TargetPath $target -LogFolder $log)

        $rows.Count | Should -Be 1
        $rows[0].Result | Should -Be 'Failed'
        $rows[0].Error | Should -Match ([regex]::Escape($Leads)) -Because 'the row names where the folder really is'
        $rows[0].Error | Should -BeLike '*Nothing was changed.'
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
    }

    It 'AC4_CopyFailsClosedWhenTheRealLocationCannotBeRead_<Case>' -ForEach @(
        @{ Case = 'ReadThrows' }
        @{ Case = 'ReadReturnsNothing' }
    ) {
        $src = New-TestFolder 'ac4-src'
        $target = New-TestFolder "ac4-target-$Case"
        $log = Join-Path $TestDrive 'ac4-logs'
        $script:Seed[$src] = Get-AllowOnlySddl
        $script:Real4 = $target; $script:Throws4 = ($Case -eq 'ReadThrows')
        Mock Get-Win32PathName {
            if ($Path -eq $script:Real4 -and $Kind -ne 'Long') {
                if ($script:Throws4) { throw 'The path could not be opened (test).' }
                return $null
            }
            $Path
        }

        $rows = @(Copy-FolderPermission -SourcePath $src -TargetPath $target -LogFolder $log)

        $rows.Count | Should -Be 1
        $rows[0].Result | Should -Be 'Failed'
        $rows[0].Error | Should -Match 'could not tell where .+ really is'
        $rows[0].Error | Should -BeLike '*Nothing was changed.'
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
    }

    It 'AC5_CopyMixedTargets_OnlyAllowedTargetsAreBackedUpAndWritten' {
        $src = New-TestFolder 'ac5-src'
        $ok = New-TestFolder 'ac5-ok'
        $log = Join-Path $TestDrive 'ac5-logs'
        $script:Seed[$src] = Get-AllowOnlySddl

        $rows = @(Copy-FolderPermission -SourcePath $src -TargetPath @($ok, 'C:\Windows\Temp') -LogFolder $log)

        $rows.Count | Should -Be 2
        $rows[0].Result | Should -Be 'Done' -Because "the ordinary target is copied (ErrorText: $($rows[0].Error))"
        $rows[1].Result | Should -Be 'Failed'
        Should -Invoke Set-Acl -Times 1 -Exactly -Scope It
        Should -Invoke Set-Acl -Times 1 -Exactly -Scope It -ParameterFilter { $LiteralPath -eq $ok }
        $backups = @(Get-ChildItem -LiteralPath (Join-Path $log 'Backups') -File -ErrorAction SilentlyContinue)
        $backups.Count | Should -Be 1
        $listed = @(Import-Csv -LiteralPath $backups[0].FullName | ForEach-Object { $_.Path })
        $listed | Should -Be @($ok) -Because 'the refused target must not be in the backup'
    }

    It 'AC6_CopyRefusalStandsUnderWhatIf' {
        $src = New-TestFolder 'ac6-src'
        $ok = New-TestFolder 'ac6-ok'
        $log = Join-Path $TestDrive 'ac6-logs'
        $script:Seed[$src] = Get-AllowOnlySddl

        $rows = @(Copy-FolderPermission -SourcePath $src -TargetPath @($ok, 'C:\Windows\Temp') -LogFolder $log -WhatIf)

        $rows.Count | Should -Be 2
        $rows[0].Result | Should -Be 'Skipped (WhatIf)'
        $rows[1].Result | Should -Be 'Failed' -Because 'a dry run shows the refusal the real run would give'
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
        Should -Invoke Save-AclBackup -Times 0 -Exactly -Scope It
        Should -Invoke Write-PermissionChangeLog -Times 0 -Exactly -Scope It
    }

    It 'AC7_CopyChecksTheRealLocationAgainJustBeforeTheWrite' {
        $src = New-TestFolder 'ac7-src'
        $target = New-TestFolder 'ac7-target'
        $log = Join-Path $TestDrive 'ac7-logs'
        $script:Seed[$src] = Get-AllowOnlySddl
        $script:Real7 = $target
        $script:FinalReads7 = 0
        # The path read itself changes (a junction swapped in after the plan step); the guard is not mocked.
        Mock Get-Win32PathName {
            if ($Path -ne $script:Real7 -or $Kind -eq 'Long') { return $Path }
            $script:FinalReads7++
            if ($script:FinalReads7 -eq 1) { $Path } else { '\\?\C:\Windows' }
        }

        $rows = @(Copy-FolderPermission -SourcePath $src -TargetPath $target -LogFolder $log)

        $script:FinalReads7 | Should -BeGreaterThan 1 -Because 'the real location must be read again before the write'
        $rows.Count | Should -Be 1
        $rows[0].Result | Should -Be 'Failed'
        $rows[0].Error | Should -Match 'Windows system folder'
        $rows[0].Error | Should -BeLike '*Nothing was changed.'
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
    }

    It 'AC8_CopyLeavesOrdinaryTargetsAlone_<Name>' -ForEach @(
        @{ Name = 'UserProfileFolder'; Target = 'C:\Users\alice\Documents\Proj' }
        @{ Name = 'TestDriveFolder'; Target = '<TestDrive>' }
        @{ Name = 'OrdinaryShare'; Target = '\\fs01\Data\Dept' }
        @{ Name = 'InsideAnAdminShare'; Target = '\\fs01\D$\Shares\Data' }
    ) {
        $src = New-TestFolder 'ac8-src'
        $log = Join-Path $TestDrive 'ac8-logs'
        $target = if ($Target -eq '<TestDrive>') { New-TestFolder 'ac8-ordinary' } else { $Target }
        $script:Seed[$src] = Get-AllowOnlySddl

        Get-CopyTargetRefusal -Path $target | Should -BeNullOrEmpty
        Get-CopyTargetResolvedRefusal -Path $target | Should -BeNullOrEmpty

        $rows = @(Copy-FolderPermission -SourcePath $src -TargetPath $target -LogFolder $log)
        $rows.Count | Should -Be 1
        $rows[0].Result | Should -Be 'Done' -Because "$target is an ordinary folder"
        Should -Invoke Set-Acl -Times 1 -Exactly -Scope It
    }

    It 'AC9_CopyRefusesDenyEntriesTheCallerDidNotAcknowledge' {
        $src = New-TestFolder 'ac9-src'
        $t1 = New-TestFolder 'ac9-t1'
        $t2 = New-TestFolder 'ac9-t2'
        $log = Join-Path $TestDrive 'ac9-logs'
        $script:Seed[$src] = Get-WithDenySddl
        $deny = @((Get-Acl -LiteralPath $src).Access | Where-Object { -not $_.IsInherited -and $_.AccessControlType -eq 'Deny' })
        $deny.Count | Should -Be 1

        $rows = @(Copy-FolderPermission -SourcePath $src -TargetPath @($t1, $t2) -LogFolder $log)

        $rows.Count | Should -Be 2
        foreach ($row in $rows) {
            $row.Result | Should -Be 'Failed'
            $row.Error | Should -Match ([regex]::Escape($src)) -Because 'the row names the source'
            foreach ($d in $deny) { $row.Error | Should -Match ([regex]::Escape((Format-PermissionRule $d))) }
            $row.Error | Should -BeLike '*Nothing was changed.'
        }
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
        Should -Invoke Save-AclBackup -Times 0 -Exactly -Scope It

        # The same call with -AllowDeny copies.
        $ok = @(Copy-FolderPermission -SourcePath $src -TargetPath @($t1, $t2) -LogFolder $log -AllowDeny)
        $ok.Count | Should -Be 2
        $ok[0].Result | Should -Be 'Done'
        $ok[1].Result | Should -Be 'Done'
    }

    It 'AC9_DenyDecisionUsesTheSameReadThatIsCopied' {
        $src = New-TestFolder 'ac9b-src'
        $t1 = New-TestFolder 'ac9b-t1'
        $log = Join-Path $TestDrive 'ac9b-logs'
        $script:SrcPath9 = $src
        $script:SrcReads9 = 0
        $script:WithDeny9 = Get-WithDenySddl
        $script:AllowOnly9 = Get-AllowOnlySddl
        # The source's first read has a Deny; any later read has none. The decision must come from
        # the first read (the one whose rules are copied), not from a second look.
        Mock Get-Acl {
            $script:SrcReads9++
            $acl = & $script:RealGetAcl -LiteralPath $TestDrive
            $acl.SetSecurityDescriptorSddlForm($(if ($script:SrcReads9 -eq 1) { $script:WithDeny9 } else { $script:AllowOnly9 }))
            $acl
        } -ParameterFilter { $LiteralPath -eq $script:SrcPath9 }

        $rows = @(Copy-FolderPermission -SourcePath $src -TargetPath $t1 -LogFolder $log)

        $rows.Count | Should -Be 1
        $rows[0].Result | Should -Be 'Failed' -Because 'the Deny that was read is the Deny that would be copied'
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
    }
}
