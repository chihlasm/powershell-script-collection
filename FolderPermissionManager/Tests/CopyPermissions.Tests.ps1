<#
    Tests for Copy permissions (SQ-015, ACs 1-3, 5-10, 12-13 and the behaviour half of 14;
    Pester 5, run under pwsh). The static ACs (4, 11, 14) are in LiteralPath.Tests.ps1.

    Owner decision D-031: copy is add-only. The target gets the rules set directly on the source
    (never the ones the source only inherits), as the source's own .NET rule objects, with ONE
    Set-Acl on the target. Nothing is removed, nothing below the target is touched, no icacls.

    Safety: Set-Acl and the native-tool wrapper (Invoke-AclTool, and the bare icacls/takeown
    names) are ALWAYS mocked. Get-Acl is mocked to return in-memory ACLs built from SDDL, or is
    the real read-only cmdlet pointed at folders inside $TestDrive. The GUI script is never
    loaded or launched; only its handler function is read from the syntax tree.

    In-memory ACLs start from a real Get-Acl object (it carries the Access and Sddl members that
    a bare DirectorySecurity does not have) and then get their descriptor replaced. Identities
    are well-known SIDs so the tests resolve on any machine:
    S-1-5-32-545 Users, -551 Backup Operators, -555 Remote Desktop Users, -556 Network
    Configuration Operators.

    Run:  Invoke-Pester .\FolderPermissionManager\Tests\CopyPermissions.Tests.ps1
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..\FolderPermissions.Core.ps1') -LoadFunctionsOnly
    # Guard: the real Invoke-AclTool runs takeown.exe and icacls.exe. Replaced here (same
    # parameters) so a test that forgets to mock it fails instead of changing real permissions.
    function Invoke-AclTool {
        param(
            [Parameter(Mandatory)][ValidateSet('icacls', 'takeown')][string]$Tool,
            [Parameter(Mandatory)][string[]]$Arguments
        )
        throw "Invoke-AclTool ($Tool) was called without a mock in a test."
    }

    $script:RealGetAcl = Get-Command Get-Acl -CommandType Cmdlet

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
    # An in-memory folder ACL: nothing is read from or written to disk.
    function New-FakeAcl {
        param([object[]]$Rule = @(), [string]$Base = 'O:BAG:SYD:PAI')
        $acl = & $script:RealGetAcl -LiteralPath $TestDrive
        $acl.SetSecurityDescriptorSddlForm($Base)
        foreach ($r in $Rule) { $acl.AddAccessRule($r) }
        $acl
    }
    function Get-RuleSid {
        param($Rule)
        $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    # How many EXPLICIT rules in $Acl match $Rule exactly (identity, rights, type, flags).
    function Get-ExplicitMatchCount {
        param($Acl, $Rule)
        $sid = Get-RuleSid $Rule
        @($Acl.Access | Where-Object {
            -not $_.IsInherited -and
            (Get-RuleSid $_) -eq $sid -and
            $_.FileSystemRights -eq $Rule.FileSystemRights -and
            $_.AccessControlType -eq $Rule.AccessControlType -and
            $_.InheritanceFlags -eq $Rule.InheritanceFlags -and
            $_.PropagationFlags -eq $Rule.PropagationFlags
        }).Count
    }
    function Get-ExplicitCount {
        param($Acl)
        @($Acl.Access | Where-Object { -not $_.IsInherited }).Count
    }
    # The four-rule source of AC1 and AC2: ReadAndExecute, Modify, Write+ReadData (the old
    # switch mapped it to R) and a Deny with special rights.
    function Get-FourRuleSddl {
        (New-FakeAcl -Rule @(
            (New-Rule 'S-1-5-32-545' 'ReadAndExecute, Synchronize')
            (New-Rule 'S-1-5-32-551' 'Modify, Synchronize' -Inherit 'ContainerInherit')
            (New-Rule 'S-1-5-32-555' 'Write, ReadData' -Inherit 'ObjectInherit' -Propagate 'InheritOnly')
            (New-Rule 'S-1-5-32-556' 'ReadData, AppendData' -Type 'Deny' -Inherit 'None')
        )).Sddl
    }
    function Get-TwoRuleSddl {
        (New-FakeAcl -Rule @(
            (New-Rule 'S-1-5-32-545' 'Modify')
            (New-Rule 'S-1-5-32-551' 'ReadAndExecute')
        )).Sddl
    }
}

Describe 'Copy-FolderPermission (SQ-015, add-only)' {
    BeforeEach {
        $script:Applied = @{}      # path -> ACL object passed to Set-Acl
        $script:Seed = @{}         # path -> SDDL that Get-Acl should report before any change

        Mock Set-Acl {
            $p = if ($LiteralPath) { $LiteralPath } else { $Path }
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
            # A fresh object per call, so the code under test cannot change what a later read sees.
            if ($script:Seed.ContainsKey($p)) { $real.SetSecurityDescriptorSddlForm($script:Seed[$p]) }
            $real
        }
        Mock Invoke-AclTool { [PSCustomObject]@{ ExitCode = 0; Output = '' } }
    }

    It 'AC1_CopyAddsEachSourceRuleWithIdenticalRightsTypeAndFlags' {
        $src = New-TestFolder 'ac1-src'
        $dst = New-TestFolder 'ac1-dst'
        $log = Join-Path $TestDrive 'ac1-logs'
        $script:Seed[$src] = Get-FourRuleSddl
        $script:Seed[$dst] = (New-FakeAcl).Sddl
        $expected = @((Get-Acl -LiteralPath $src).Access)
        $expected.Count | Should -Be 4

        $null = Copy-FolderPermission -SourcePath $src -TargetPath $dst -LogFolder $log

        Should -Invoke Set-Acl -Times 1 -Exactly -Scope It
        $script:Applied.ContainsKey($dst) | Should -BeTrue
        foreach ($rule in $expected) {
            Get-ExplicitMatchCount $script:Applied[$dst] $rule |
                Should -Be 1 -Because "$($rule.AccessControlType) $($rule.FileSystemRights) for $($rule.IdentityReference) with $($rule.InheritanceFlags)/$($rule.PropagationFlags) must arrive unchanged"
        }
        Get-ExplicitCount $script:Applied[$dst] | Should -Be 4 -Because 'nothing else may be added'
    }

    It 'AC2_CopyNeverCallsTheNativeAclTool' {
        $src = New-TestFolder 'ac2-src'
        $dst = New-TestFolder 'ac2-dst'
        $log = Join-Path $TestDrive 'ac2-logs'
        $script:Seed[$src] = Get-FourRuleSddl
        $script:Seed[$dst] = (New-FakeAcl).Sddl

        $rows = @(Copy-FolderPermission -SourcePath $src -TargetPath $dst -LogFolder $log)

        $rows[0].Result | Should -Be 'Done' -Because 'the copy must really have run, or "no icacls call" proves nothing'
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
    }

    It 'AC3_CopyWritesOnlyTheTargetAndNeverResets' {
        $src = New-TestFolder 'ac3-src'
        $dst = New-TestFolder 'ac3-dst'
        $sub = New-TestFolder 'ac3-dst\sub'
        $log = Join-Path $TestDrive 'ac3-logs'
        $script:Seed[$src] = Get-TwoRuleSddl

        $rows = @(Copy-FolderPermission -SourcePath $src -TargetPath $dst -LogFolder $log)

        $rows[0].Result | Should -Be 'Done'
        Should -Invoke Set-Acl -Times 1 -Exactly -Scope It
        Should -Invoke Set-Acl -Times 1 -Exactly -Scope It -ParameterFilter { $LiteralPath -eq $dst }
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It -ParameterFilter { $LiteralPath -eq $sub -or $Path -eq $sub }
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It -ParameterFilter { $Arguments -contains '/reset' }
    }

    It 'AC5_CopyLeavesOutRulesTheSourceOnlyInherits' {
        $src = New-TestFolder 'ac5-src'
        $dst = New-TestFolder 'ac5-dst'
        $log = Join-Path $TestDrive 'ac5-logs'
        # Users: set on the source itself. Backup Operators: flagged ID (inherited) from its parent.
        $script:Seed[$src] = 'O:BAG:SYD:AI(A;OICI;0x1301bf;;;S-1-5-32-545)(A;OICIID;0x1200a9;;;S-1-5-32-551)'
        $script:Seed[$dst] = (New-FakeAcl).Sddl
        ((Get-Acl -LiteralPath $src).Access | Where-Object { $_.IsInherited }).Count | Should -Be 1

        $null = Copy-FolderPermission -SourcePath $src -TargetPath $dst -LogFolder $log

        Should -Invoke Set-Acl -Times 1 -Exactly -Scope It
        $applied = @($script:Applied[$dst].Access)
        @($applied | Where-Object { (Get-RuleSid $_) -eq 'S-1-5-32-545' -and -not $_.IsInherited }).Count | Should -Be 1
        @($applied | Where-Object { (Get-RuleSid $_) -eq 'S-1-5-32-551' }).Count | Should -Be 0 -Because 'an inherited source rule must not be frozen onto the target as an explicit one'
    }

    It 'AC6_SourceWithOnlyInheritedRules_SkippedWithNothingToCopyMessage' {
        $src = New-TestFolder 'ac6-src'
        $dst = New-TestFolder 'ac6-dst'
        $log = Join-Path $TestDrive 'ac6-logs'
        $script:Seed[$src] = 'O:BAG:SYD:AI(A;OICIID;0x1200a9;;;S-1-5-32-545)(A;OICIID;0x1301bf;;;S-1-5-32-551)'

        $rows = @(Copy-FolderPermission -SourcePath $src -TargetPath $dst -LogFolder $log)

        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
        $rows.Count | Should -Be 1
        $rows[0].Result | Should -Be 'Skipped (nothing to copy)'
        # Pinned: the sentence is the entry's Detail (as in AC8) and is part of the status message.
        $sentence = "Nothing to copy: $src has no permissions of its own."
        $rows[0].Detail | Should -BeLike "$([WildcardPattern]::Escape($sentence))*"
        $rows[0].Detail | Should -BeLike "*All of its permissions come from $([WildcardPattern]::Escape((Split-Path $src -Parent)))*"
        $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $log 'Changes.csv') -LogFolder $log
        $message | Should -BeLike "*$([WildcardPattern]::Escape($sentence))*"
    }

    It 'AC7_CopyKeepsRulesTheTargetAlreadyHas' {
        $src = New-TestFolder 'ac7-src'
        $dst = New-TestFolder 'ac7-dst'
        $log = Join-Path $TestDrive 'ac7-logs'
        $script:Seed[$src] = (New-FakeAcl -Rule @(New-Rule 'S-1-5-32-545' 'Modify')).Sddl
        $own = New-Rule 'S-1-5-32-555' 'FullControl'
        $script:Seed[$dst] = (New-FakeAcl -Rule @($own)).Sddl

        $null = Copy-FolderPermission -SourcePath $src -TargetPath $dst -LogFolder $log

        Should -Invoke Set-Acl -Times 1 -Exactly -Scope It
        Get-ExplicitMatchCount $script:Applied[$dst] $own | Should -Be 1 -Because 'copy adds, it never replaces'
        @($script:Applied[$dst].Access | Where-Object { (Get-RuleSid $_) -eq 'S-1-5-32-545' -and -not $_.IsInherited }).Count | Should -Be 1
    }

    It 'AC8_TargetAlreadyHasEveryRule_NoSetAclAndSkipped' {
        $src = New-TestFolder 'ac8-src'
        $dst = New-TestFolder 'ac8-dst'
        $log = Join-Path $TestDrive 'ac8-logs'
        $script:Seed[$src] = Get-TwoRuleSddl
        $script:Seed[$dst] = Get-TwoRuleSddl

        $rows = @(Copy-FolderPermission -SourcePath $src -TargetPath $dst -LogFolder $log)

        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
        $rows.Count | Should -Be 1
        $rows[0].Result | Should -Be 'Skipped (nothing to copy)'
        $rows[0].Detail | Should -Be 'Already has these permissions; nothing changed.'
    }

    It 'AC9_FolderNamesWithBrackets_TargetFoundAndWrittenByLiteralPath' {
        $src = New-TestFolder 'HR [old]'
        $dst = New-TestFolder 'Archive [2024]'
        $log = Join-Path $TestDrive 'ac9-logs'
        $script:Seed[$src] = Get-TwoRuleSddl     # the target keeps its real ACL (real Get-Acl)

        $rows = @(Copy-FolderPermission -SourcePath $src -TargetPath $dst -LogFolder $log)

        $rows.Count | Should -Be 1
        $rows[0].Result | Should -Be 'Done' -Because $rows[0].Error
        Should -Invoke Set-Acl -Times 1 -Exactly -Scope It
        Should -Invoke Set-Acl -Times 1 -Exactly -Scope It -ParameterFilter { $LiteralPath -ceq $dst }
    }

    It 'AC10_BracketNameIsNotAWildcard_SiblingNotMatched' {
        $src = New-TestFolder 'ac10-src'
        $root = New-TestFolder 'ac10-root'          # its own parent: AC9 creates 'HR [old]' in $TestDrive
        $null = New-TestFolder 'ac10-root\HR o'
        $missing = Join-Path $root 'HR [old]'
        $log = Join-Path $TestDrive 'ac10-logs'
        $script:Seed[$src] = Get-TwoRuleSddl
        Test-Path -LiteralPath $missing | Should -BeFalse

        $rows = @(Copy-FolderPermission -SourcePath $src -TargetPath $missing -LogFolder $log)

        $rows.Count | Should -Be 1
        $rows[0].Result | Should -Be 'Skipped (not found)'
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
    }

    It 'AC12_FileTarget_RefusedAndNothingChanged' {
        $src = New-TestFolder 'ac12-src'
        $file = New-TestFile 'ac12-target.txt'
        $log = Join-Path $TestDrive 'ac12-logs'
        $script:Seed[$src] = Get-TwoRuleSddl

        $rows = @(Copy-FolderPermission -SourcePath $src -TargetPath $file -LogFolder $log)

        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
        $rows.Count | Should -Be 1
        $rows[0].Result | Should -Be 'Failed'
        $rows[0].Error | Should -Be "$file is a file. Copy permissions copies to folders only."
    }

    It 'AC13_SuccessfulCopy_LogsPinnedRowAndStatusMessageNamesInheritance' {
        $src = New-TestFolder 'ac13-src'
        $dst = New-TestFolder 'ac13-dst'
        $log = Join-Path $TestDrive 'ac13-logs'
        $script:Seed[$src] = Get-TwoRuleSddl
        $script:Seed[$dst] = (New-FakeAcl).Sddl
        $before = (Get-Acl -LiteralPath $dst).Sddl
        $who = @((Get-Acl -LiteralPath $src).Access | ForEach-Object { $_.IdentityReference.Value })
        $who.Count | Should -Be 2

        $rows = @(Copy-FolderPermission -SourcePath $src -TargetPath $dst -LogFolder $log)

        $rows.Count | Should -Be 1
        $r = $rows[0]
        $r.Result | Should -Be 'Done'
        $r.Action | Should -Be 'Copy permissions'
        $r.ItemType | Should -Be 'Folder'
        $r.Detail | Should -Be "Copied from $($src): Allow Modify for $($who[0]); Allow Read & execute for $($who[1])"
        $r.OldValue | Should -Be $before
        $r.NewValue | Should -Be $script:Applied[$dst].Sddl
        $r.NewValue | Should -Not -Be $before
        $message = Get-ChangeResultMessage -Entries $rows -LogPath (Join-Path $log 'Changes.csv') -LogFolder $log
        $message | Should -BeLike '*Subfolders and files that inherit permissions get them too. Any that block inheritance were not changed.*'
    }
}

Describe 'GUI replicate endpoint ignores an old client''s recursive flag (SQ-015, AC14)' {
    BeforeAll {
        $guiPath = (Resolve-Path (Join-Path $PSScriptRoot '..\FolderPermissionManager-GUI.ps1')).Path
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($guiPath, [ref]$null, [ref]$null)
        $handlers = 'Resolve-MappedDrive', 'Complete-PermissionChange', 'ConvertTo-ChangeResultRow',
            'Send-SingleChangeResult', 'Send-BatchChangeResult', 'Invoke-ReplicatePermissions'
        $definitions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) |
            Where-Object { $handlers -contains $_.Name }
        foreach ($d in $definitions) {
            $text = $d.Extent.Text -replace '\[System\.Net\.HttpListenerResponse\]', '[object]'
            . ([scriptblock]::Create($text))
        }
        function Send-Json { param($Response, $Data) $script:Sent = $Data }
        function Read-RequestBody { param($Request) $script:Body }
    }

    BeforeEach {
        $script:driveMappings = @{}
        $script:ChangeLogFolder = Join-Path $TestDrive ('logs-' + [guid]::NewGuid().ToString('N'))
        $script:Applied = @{}
        $script:Seed = @{}
        Mock Set-Acl {
            $p = if ($LiteralPath) { $LiteralPath } else { $Path }
            $script:Applied[$p] = $AclObject
        }
        Mock Get-Acl {
            $p = if ($LiteralPath) { $LiteralPath } else { $Path }
            if ($script:Applied.ContainsKey($p)) { return $script:Applied[$p] }
            $real = if ($LiteralPath) { & $script:RealGetAcl -LiteralPath $LiteralPath } else { & $script:RealGetAcl -Path $Path }
            if ($script:Seed.ContainsKey($p)) { $real.SetSecurityDescriptorSddlForm($script:Seed[$p]) }
            $real
        }
        Mock Invoke-AclTool { [PSCustomObject]@{ ExitCode = 0; Output = '' } }
        # The old recursive branch calls the bare icacls.exe: never let it reach the real tool.
        Mock icacls { }
        Mock takeown { }
    }

    It 'AC14_OlderClientSendingRecursiveTrue_StillGetsAddOnlyCopyThroughTheCore' {
        $src = New-TestFolder 'ac14-src'
        $dst = New-TestFolder 'ac14-dst'
        $script:Seed[$src] = Get-TwoRuleSddl
        $script:Body = [PSCustomObject]@{ sourcePath = $src; targetPaths = @($dst); recursive = $true }
        $script:Sent = $null
        $response = [PSCustomObject]@{ StatusCode = 200 }

        Invoke-ReplicatePermissions $null $response

        Should -Invoke icacls -Times 0 -Exactly -Scope It
        Should -Invoke Set-Acl -Times 1 -Exactly -Scope It -ParameterFilter { $LiteralPath -eq $dst }
        @($script:Sent.results).Count | Should -Be 1
        $script:Sent.results[0].status | Should -Be 'success'
        $script:Sent.message | Should -BeLike "*$([WildcardPattern]::Escape($src))*"
    }
}
