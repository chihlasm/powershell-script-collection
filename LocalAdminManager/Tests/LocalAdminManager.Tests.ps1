<#
    SQ-009: LocalAdminManager logs every add and remove of a local administrator.

    Nothing here touches a real Administrators group or a real remote computer. The wrappers that
    reach the target (Get-/Add-/Remove-LocalAdminMember, Get-LocalAdminGroupName) are mocked, the
    transport (Invoke-Command) is mocked, and every log write goes to $TestDrive.

    Root cause of the original bug (verified): Add-LocalGroupMember, Remove-LocalGroupMember and
    Get-LocalGroupMember have NO -ComputerName parameter, so the old call failed on every run.
      https://learn.microsoft.com/powershell/module/microsoft.powershell.localaccounts/add-localgroupmember
      https://learn.microsoft.com/powershell/module/microsoft.powershell.localaccounts/remove-localgroupmember
      https://learn.microsoft.com/powershell/module/microsoft.powershell.localaccounts/get-localgroupmember
    Well-known SID S-1-5-32-544 = built-in Administrators (the name is localized):
      https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
    Invoke-Command -ComputerName:
      https://learn.microsoft.com/powershell/module/microsoft.powershell.core/invoke-command

    Interface pinned for the builder (see the stubs in LocalAdminManager.ps1):
      Members are objects with .Name ('DOMAIN\Name', empty when unresolvable) and .Sid.
      Get-LocalAdminMember -ComputerName            -> member objects
      Get-LocalAdminGroupName -ComputerName         -> localized group name (string)
      Add-/Remove-LocalAdminMember -ComputerName -Member
      Resolve-BuiltinAdministratorsName [-Translator <scriptblock>]
          the translator gets the SID string 'S-1-5-32-544' and returns an NT account such as
          'BUILTIN\Administratoren'; the function returns only the name part.
      Set-LocalAdminMembership -Action -Member -ComputerName   (SupportsShouldProcess, never throws)
      Invoke-LocalAdminManagerMain -Action -Member -ComputerName -LogFolder [-Force]
          the main body; returns the exit code (0/1) instead of calling exit.
          The script ends with:  exit (Invoke-LocalAdminManagerMain ...)

    Run:  pwsh -NoProfile -File Tests\Invoke-AllTests.ps1 -Path .\LocalAdminManager\Tests
#>

BeforeAll {
    $script:Script = Join-Path (Split-Path -Parent $PSScriptRoot) 'LocalAdminManager.ps1'
    . $script:Script -LoadFunctionsOnly -Action Add -Member 'x'

    function New-FakeMember {
        param([string]$Name, [string]$Sid)
        if (-not $Sid) { $Sid = 'S-1-5-21-1-2-3-' + (1000 + ($Name.GetHashCode() -band 0xFFF)) }
        [PSCustomObject]@{ Name = $Name; Sid = $Sid }
    }
    $script:A = New-FakeMember 'CONTOSO\A' 'S-1-5-21-1-2-3-1001'
    $script:B = New-FakeMember 'CONTOSO\B' 'S-1-5-21-1-2-3-1002'
    $script:C = New-FakeMember 'CONTOSO\C' 'S-1-5-21-1-2-3-1003'
    $script:Columns = 'Time', 'Technician', 'Computer', 'Action', 'Target', 'ItemType', 'Detail',
                      'OldValue', 'NewValue', 'Result', 'Error', 'BackupFile'

    # The fake target resolves the members above by SID, as the real one does on the target.
    # Anything else (a typo, a deleted account) cannot be translated: ''.
    function Resolve-FakeMemberSid {
        param([string]$Member)
        if ($Member -match '^S-1-\d+(-\d+)+$') { return $Member }
        $known = @{ 'CONTOSO\A' = $script:A.Sid; 'CONTOSO\B' = $script:B.Sid; 'CONTOSO\C' = $script:C.Sid }
        [string]$known[$Member]
    }
}

Describe 'Set-LocalAdminMembership' {

    BeforeEach {
        # Backstop: nothing may reach a real computer. Tests that need the transport mock it.
        Mock Invoke-Command { throw 'unmocked Invoke-Command' }
        Mock Invoke-OnTarget { throw 'unmocked Invoke-OnTarget' }
        Mock Resolve-LocalAdminMemberSid { Resolve-FakeMemberSid -Member $Member }
        Mock Get-LocalAdminGroupName { 'Administratoren' }
        Mock Add-LocalAdminMember { }
        Mock Remove-LocalAdminMember { }
    }

    It 'AC1_AddRecordsOldAndReReadNewValues' {
        $script:reads = 0
        Mock Get-LocalAdminMember {
            $script:reads++
            if ($script:reads -eq 1) { @($script:A, $script:B) } else { @($script:A, $script:B, $script:C) }
        }

        $e = Set-LocalAdminMembership -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -Confirm:$false

        Should -Invoke Add-LocalAdminMember -Times 1 -Exactly -ParameterFilter { $ComputerName -eq 'PC01' -and $Member -eq 'CONTOSO\C' }
        $e.Action     | Should -Be 'Add administrator'
        $e.Target     | Should -Be 'PC01\Administratoren'
        $e.ItemType   | Should -Be 'Local group'
        $e.Detail     | Should -Be 'CONTOSO\C'
        $e.BackupFile | Should -BeNullOrEmpty
        $e.OldValue   | Should -Be 'CONTOSO\A; CONTOSO\B'
        # Re-read from the target after the change (second call), not computed.
        $e.NewValue   | Should -Be 'CONTOSO\A; CONTOSO\B; CONTOSO\C'
        $e.Result     | Should -Be 'Done'
        $e.Error      | Should -BeNullOrEmpty
        $e.Time       | Should -Match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$'
        $e.Technician | Should -Be "$env:USERDOMAIN\$env:USERNAME"
        $e.Computer   | Should -Be $env:COMPUTERNAME
        $script:reads | Should -BeGreaterOrEqual 2
    }

    It 'AC2_RemoveRecordsOldAndNewValues' {
        $script:reads = 0
        Mock Get-LocalAdminMember {
            $script:reads++
            if ($script:reads -eq 1) { @($script:A, $script:B, $script:C) } else { @($script:A, $script:B) }
        }

        $e = Set-LocalAdminMembership -Action Remove -Member 'CONTOSO\C' -ComputerName 'PC01' -Confirm:$false

        Should -Invoke Remove-LocalAdminMember -Times 1 -Exactly -ParameterFilter { $ComputerName -eq 'PC01' -and $Member -eq 'CONTOSO\C' }
        $e.Action   | Should -Be 'Remove administrator'
        $e.OldValue | Should -Be 'CONTOSO\A; CONTOSO\B; CONTOSO\C'
        $e.NewValue | Should -Be 'CONTOSO\A; CONTOSO\B'
        $e.Result   | Should -Be 'Done'
    }

    It 'AC3_AddOfExistingMemberIsNoChange' {
        Mock Get-LocalAdminMember { @($script:A, $script:B, $script:C) }

        $e = Set-LocalAdminMembership -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -Confirm:$false

        Should -Invoke Add-LocalAdminMember -Times 0 -Exactly
        $e.Result   | Should -Be 'No change (already a member)'
        $e.NewValue | Should -Be $e.OldValue
    }

    It 'AC3_AddOfExistingMemberMatchesCaseInsensitively' {
        Mock Get-LocalAdminMember { @($script:A, $script:C) }

        $e = Set-LocalAdminMembership -Action Add -Member 'contoso\c' -ComputerName 'PC01' -Confirm:$false

        Should -Invoke Add-LocalAdminMember -Times 0 -Exactly
        $e.Result | Should -Be 'No change (already a member)'
    }

    It 'AC4_RemoveOfNonMemberIsNoChange' {
        Mock Get-LocalAdminMember { @($script:A, $script:B) }

        $e = Set-LocalAdminMembership -Action Remove -Member 'CONTOSO\C' -ComputerName 'PC01' -Confirm:$false

        Should -Invoke Remove-LocalAdminMember -Times 0 -Exactly
        $e.Result | Should -Be 'No change (not a member)'
    }

    It 'AC5_FailedAddIsReturnedNotThrown' {
        $script:reads = 0
        Mock Get-LocalAdminMember { $script:reads++; @($script:A, $script:B) }
        Mock Add-LocalAdminMember { throw 'Access is denied' }

        $script:e = $null
        { $script:e = Set-LocalAdminMembership -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -Confirm:$false } | Should -Not -Throw
        $e = $script:e  # the block runs in a child scope (Pester: & $ActualValue)

        $e.Result   | Should -Be 'Failed'
        $e.Error    | Should -Match 'Access is denied'
        $e.OldValue | Should -Be 'CONTOSO\A; CONTOSO\B'
        $e.NewValue | Should -Be 'CONTOSO\A; CONTOSO\B'
        $script:reads | Should -BeGreaterOrEqual 2
    }

    It 'AC5_FailedRemoveIsReturnedNotThrown' {
        Mock Get-LocalAdminMember { @($script:A, $script:C) }
        Mock Remove-LocalAdminMember { throw 'Access is denied' }

        $script:e = $null
        { $script:e = Set-LocalAdminMembership -Action Remove -Member 'CONTOSO\C' -ComputerName 'PC01' -Confirm:$false } | Should -Not -Throw
        $e = $script:e  # the block runs in a child scope (Pester: & $ActualValue)

        $e.Result | Should -Be 'Failed'
        $e.Error  | Should -Match 'Access is denied'
    }

    It 'AC5_NewValueIsEmptyWhenTheReReadAlsoFails' {
        $script:reads = 0
        Mock Get-LocalAdminMember {
            $script:reads++
            if ($script:reads -eq 1) { @($script:A, $script:B) } else { throw 'connection lost' }
        }
        Mock Add-LocalAdminMember { throw 'Access is denied' }

        $e = Set-LocalAdminMembership -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -Confirm:$false

        $e.Result   | Should -Be 'Failed'
        $e.OldValue | Should -Be 'CONTOSO\A; CONTOSO\B'
        $e.NewValue | Should -BeNullOrEmpty
    }

    It 'AC6_UnreachableComputerFailsBeforeAnyChange' {
        Mock Get-LocalAdminMember { throw 'The RPC server is unavailable' }

        $script:e = $null
        { $script:e = Set-LocalAdminMembership -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -Confirm:$false } | Should -Not -Throw
        $e = $script:e  # the block runs in a child scope (Pester: & $ActualValue)

        Should -Invoke Add-LocalAdminMember -Times 0 -Exactly
        Should -Invoke Remove-LocalAdminMember -Times 0 -Exactly
        $e.Result | Should -Be 'Failed'
        $e.Error  | Should -Match 'PC01'
        $e.Error  | Should -Match 'RPC server is unavailable'
    }

    It 'AC7_WhatIfChangesNothing' {
        Mock Get-LocalAdminMember { @($script:A, $script:B) }

        $e = Set-LocalAdminMembership -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -WhatIf

        Should -Invoke Add-LocalAdminMember -Times 0 -Exactly
        Should -Invoke Remove-LocalAdminMember -Times 0 -Exactly
        $e.Result | Should -Be 'Skipped (WhatIf)'
    }

    It 'AC13_EntryColumnsAreInThePinnedOrder' {
        Mock Get-LocalAdminMember { @($script:A) }
        $e = Set-LocalAdminMembership -Action Add -Member 'CONTOSO\A' -ComputerName 'PC01' -Confirm:$false
        @($e.PSObject.Properties.Name) | Should -Be $script:Columns
    }
}

Describe 'Main body' {

    BeforeEach {
        # Backstop: nothing may reach a real computer. Tests that need the transport mock it.
        Mock Invoke-Command { throw 'unmocked Invoke-Command' }
        Mock Invoke-OnTarget { throw 'unmocked Invoke-OnTarget' }
        $script:logFolder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        Mock Test-Administrator { $true }
        Mock Get-LocalAdminGroupName { 'Administratoren' }
        Mock Get-LocalAdminMember { @($script:A, $script:B) }
        # The one-round-trip read the main body previews with, built from the mocks above so a
        # test that overrides Get-LocalAdminMember changes the preview too.
        Mock Get-LocalAdminGroup {
            [PSCustomObject]@{
                Group     = Get-LocalAdminGroupName -ComputerName $ComputerName
                Members   = @(Get-LocalAdminMember -ComputerName $ComputerName)
                MemberSid = Resolve-FakeMemberSid -Member $Member
            }
        }
        Mock Add-LocalAdminMember { }
        Mock Remove-LocalAdminMember { }
        Mock Write-Status { }
    }

    It 'AC7_WhatIfCreatesNoChangeLogFile' {
        Invoke-LocalAdminManagerMain -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -LogFolder $script:logFolder -WhatIf | Out-Null

        Should -Invoke Add-LocalAdminMember -Times 0 -Exactly
        @(Get-ChildItem -LiteralPath $TestDrive -Filter 'Changes_*.csv' -Recurse -ErrorAction SilentlyContinue).Count | Should -Be 0
    }

    It 'AC9_ForceMakesTheChangeWithNoConfirmationPrompt' {
        $script:seenConfirm = $null
        Mock Test-LogFolderWritable { $true }
        Mock Write-LocalAdminChangeLog { 'C:\fake\Changes_2026-10-18.csv' }
        Mock Set-LocalAdminMembership {
            $script:seenConfirm = $ConfirmPreference
            [PSCustomObject]@{ Result = 'Done'; Error = '' }
        }

        $ConfirmPreference = 'High'
        Invoke-LocalAdminManagerMain -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -LogFolder $script:logFolder -Force | Out-Null

        Should -Invoke Set-LocalAdminMembership -Times 1 -Exactly
        $script:seenConfirm | Should -Be 'None'
    }

    It 'AC14_UnwritableLogFolderFailsClosed' {
        Mock New-Item { throw 'Access to the path is denied' }
        Mock Set-LocalAdminMembership { throw 'must not run' }

        $code = Invoke-LocalAdminManagerMain -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -LogFolder $script:logFolder -Force

        $code | Should -Be 1
        Should -Invoke Add-LocalAdminMember -Times 0 -Exactly
        Should -Invoke Remove-LocalAdminMember -Times 0 -Exactly
        Should -Invoke Set-LocalAdminMembership -Times 0 -Exactly
        Should -Invoke Write-Status -Times 1 -ParameterFilter { $Level -eq 'FAIL' -and $Message -like "*$($script:logFolder)*" }
    }

    It 'AC16_SuccessShowsPassWithLogPathAndExitCode0' {
        $logPath = 'C:\fake\Logs\Changes_2026-10-18.csv'
        Mock Test-LogFolderWritable { $true }
        Mock Write-LocalAdminChangeLog { $logPath }
        Mock Set-LocalAdminMembership { [PSCustomObject]@{ Result = 'Done'; Error = '' } }

        $code = Invoke-LocalAdminManagerMain -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -LogFolder $script:logFolder -Force

        $code | Should -Be 0
        Should -Invoke Write-Status -Times 1 -ParameterFilter { $Level -eq 'PASS' -and $Message -like "*$logPath*" }
    }

    It 'AC16_FailureShowsFailAndExitCode1' {
        Mock Test-LogFolderWritable { $true }
        Mock Write-LocalAdminChangeLog { 'C:\fake\Logs\Changes_2026-10-18.csv' }
        Mock Set-LocalAdminMembership { [PSCustomObject]@{ Result = 'Failed'; Error = 'Access is denied' } }

        $code = Invoke-LocalAdminManagerMain -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -LogFolder $script:logFolder -Force

        $code | Should -Be 1
        Should -Invoke Write-Status -Times 1 -ParameterFilter { $Level -eq 'FAIL' }
        Should -Invoke Write-Status -Times 0 -ParameterFilter { $Level -eq 'PASS' }
    }
}

Describe 'Script declaration' {

    It 'AC8_CmdletBindingDeclaresSupportsShouldProcessAndConfirmImpactHigh' {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Script, [ref]$tokens, [ref]$errors)
        $errors.Count | Should -Be 0
        $binding = $ast.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq 'CmdletBinding' }
        $binding | Should -Not -BeNullOrEmpty
        $names = @($binding.NamedArguments | ForEach-Object { $_.ArgumentName })
        $names | Should -Contain 'SupportsShouldProcess'
        $impact = $binding.NamedArguments | Where-Object { $_.ArgumentName -eq 'ConfirmImpact' }
        $impact.Argument.Value | Should -Be 'High'
    }

    It 'AC10_NoHardcodedEnglishAdministratorsGroupName' {
        # Regression: the old script changed the group named "Administrators", which does not
        # exist on a German Windows ("Administratoren").
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Script, [ref]$tokens, [ref]$errors)
        $literals = $ast.FindAll({
            $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
            $args[0].Value -eq 'Administrators'
        }, $true)
        @($literals | ForEach-Object { "line $($_.Extent.StartLineNumber)" }) | Should -BeNullOrEmpty
    }

    It 'AC17_RequiresPowerShell3' {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Script, [ref]$tokens, [ref]$errors)
        [version]$ast.ScriptRequirements.RequiredPSVersion | Should -Be ([version]'3.0')
    }
}

Describe 'Resolve-BuiltinAdministratorsName' {

    It 'AC10_ResolvesTheLocalizedNameFromTheWellKnownSid' {
        $script:askedFor = $null
        $translator = { param($sid) $script:askedFor = [string]$sid; 'BUILTIN\Administratoren' }

        Resolve-BuiltinAdministratorsName -Translator $translator | Should -Be 'Administratoren'
        $script:askedFor | Should -Be 'S-1-5-32-544'
    }
}

Describe 'Transport' {

    BeforeEach {
        # Backstop: Invoke-OnTarget is under test here, so only the remoting cmdlet is stubbed.
        Mock Invoke-Command { throw 'unmocked Invoke-Command' }
    }

    It 'AC11_LocalNamesRunInProcessWithoutInvokeCommand' -ForEach @(
        @{ Name = $env:COMPUTERNAME }, @{ Name = 'localhost' }, @{ Name = '.' }, @{ Name = '' }
    ) {
        Mock Invoke-Command { throw 'Invoke-Command must not be used for the local computer' }

        Test-IsLocalComputer -ComputerName $Name | Should -BeTrue
        Invoke-OnTarget -ComputerName $Name -ScriptBlock { param($x) "ran $x" } -ArgumentList @('here') | Should -Be 'ran here'

        Should -Invoke Invoke-Command -Times 0 -Exactly
    }

    It 'AC11_ReadAndChangeWrappersGoThroughInvokeOnTargetWithTheComputerName' {
        # A fake local name: this machine's own name must never be the target of a write wrapper.
        Mock Test-IsLocalComputer { $true }
        Mock Invoke-OnTarget { }

        Get-LocalAdminMember -ComputerName 'FAKE-LOCAL' | Out-Null
        Add-LocalAdminMember -ComputerName 'FAKE-LOCAL' -Member 'CONTOSO\C'
        Remove-LocalAdminMember -ComputerName 'FAKE-LOCAL' -Member 'CONTOSO\C'

        Should -Invoke Invoke-OnTarget -Times 3 -Exactly -ParameterFilter { $ComputerName -eq 'FAKE-LOCAL' }
    }

    It 'AC12_RemoteComputerUsesInvokeCommandWithComputerName' {
        Mock Invoke-Command { 'remote result' }

        Test-IsLocalComputer -ComputerName 'PC01' | Should -BeFalse
        Invoke-OnTarget -ComputerName 'PC01' -ScriptBlock { 'x' } -ArgumentList @() | Should -Be 'remote result'

        Should -Invoke Invoke-Command -Times 1 -Exactly -ParameterFilter { $ComputerName -eq 'PC01' }
    }

    It 'AC12_WrappersPassTheRemoteNameToTheTransport' {
        Mock Invoke-OnTarget { }

        Get-LocalAdminMember -ComputerName 'PC01' | Out-Null
        Add-LocalAdminMember -ComputerName 'PC01' -Member 'CONTOSO\C'
        Remove-LocalAdminMember -ComputerName 'PC01' -Member 'CONTOSO\C'

        Should -Invoke Invoke-OnTarget -Times 3 -Exactly -ParameterFilter { $ComputerName -eq 'PC01' }
    }
}

Describe 'Change log' {

    BeforeEach {
        # Backstop: nothing may reach a real computer. Tests that need the transport mock it.
        Mock Invoke-Command { throw 'unmocked Invoke-Command' }
        Mock Invoke-OnTarget { throw 'unmocked Invoke-OnTarget' }
        Mock Resolve-LocalAdminMemberSid { Resolve-FakeMemberSid -Member $Member }
        Mock Get-LocalAdminGroupName { 'Administratoren' }
        Mock Get-LocalAdminMember { @($script:A) }
        Mock Add-LocalAdminMember { }
    }

    It 'AC13_TwoRunsShareOneDailyCsvWithASingleHeader' {
        $folder = Join-Path $TestDrive 'logs13'
        $e1 = Set-LocalAdminMembership -Action Add -Member 'CONTOSO\B' -ComputerName 'PC01' -Confirm:$false
        $e2 = Set-LocalAdminMembership -Action Add -Member 'CONTOSO\A' -ComputerName 'PC02' -Confirm:$false

        $p1 = Write-LocalAdminChangeLog -Entries @($e1) -LogFolder $folder
        $p2 = Write-LocalAdminChangeLog -Entries @($e2) -LogFolder $folder

        $p1 | Should -Be $p2
        (Split-Path -Leaf $p1) | Should -Be ("Changes_{0}.csv" -f (Get-Date -Format 'yyyy-MM-dd'))
        @(Get-Content -LiteralPath $p1 | Where-Object { $_ -match '^"Time"' }).Count | Should -Be 1
        $rows = @(Import-Csv -LiteralPath $p1)
        $rows.Count | Should -Be 2
        @($rows[0].PSObject.Properties.Name) | Should -Be $script:Columns
        $rows[0].Target | Should -Be 'PC01\Administratoren'
        $rows[1].Target | Should -Be 'PC02\Administratoren'
    }

    It 'AC14_LogFolderThatCannotBeCreatedIsReportedAsNotWritable' {
        Mock New-Item { throw 'Access to the path is denied' }
        Test-LogFolderWritable -LogFolder (Join-Path $TestDrive 'nope\deeper') | Should -BeFalse
    }

    It 'AC14_WritableLogFolderIsReportedWritable' {
        Test-LogFolderWritable -LogFolder (Join-Path $TestDrive 'ok14') | Should -BeTrue
    }
}

Describe 'Format-MemberList' {

    It 'AC15_SortsCaseInsensitivelyAndJoinsWithSemicolonSpace' {
        $members = @(
            (New-FakeMember 'CONTOSO\carol' 'S-1-5-21-1-2-3-1'),
            (New-FakeMember 'CONTOSO\Alice' 'S-1-5-21-1-2-3-2'),
            (New-FakeMember 'CONTOSO\bob'   'S-1-5-21-1-2-3-3')
        )
        Format-MemberList -Members $members | Should -Be 'CONTOSO\Alice; CONTOSO\bob; CONTOSO\carol'
    }

    It 'AC15_OrphanedMemberShowsItsSid' {
        $members = @(
            (New-FakeMember 'CONTOSO\Alice' 'S-1-5-21-1-2-3-2'),
            [PSCustomObject]@{ Name = ''; Sid = 'S-1-5-21-9-9-9-1105' }
        )
        $text = Format-MemberList -Members $members
        $text | Should -Match 'S-1-5-21-9-9-9-1105'
        $text | Should -Be 'CONTOSO\Alice; S-1-5-21-9-9-9-1105'
    }

    It 'AC15_EmptyGroupGivesAnEmptyString' {
        Format-MemberList -Members @() | Should -BeNullOrEmpty
    }
}

Describe 'Matching the member (review round 1)' {

    BeforeEach {
        Mock Invoke-Command { throw 'unmocked Invoke-Command' }
        Mock Invoke-OnTarget { throw 'unmocked Invoke-OnTarget' }
        Mock Resolve-LocalAdminMemberSid { Resolve-FakeMemberSid -Member $Member }
        Mock Get-LocalAdminGroupName { 'Administratoren' }
        Mock Add-LocalAdminMember { }
        Mock Remove-LocalAdminMember { }
    }

    It 'AC3_MatchesByTheSidTheTargetResolvesEvenWhenTheGroupShowsAnotherName' {
        # CONTOSO\JSmith was renamed CONTOSO\C: same SID, so it is already a member.
        Mock Resolve-LocalAdminMemberSid { $script:C.Sid }
        Mock Get-LocalAdminMember { @($script:A, $script:C) }

        $e = Set-LocalAdminMembership -Action Add -Member 'CONTOSO\JSmith' -ComputerName 'PC01' -Confirm:$false

        Should -Invoke Add-LocalAdminMember -Times 0 -Exactly
        $e.Result | Should -Be 'No change (already a member)'
    }

    It 'AC3_ANameMatchCountsOnlyWhenTheAccountCannotBeTranslated' {
        # CONTOSO\C was deleted and recreated: the group still holds the old SID under the old
        # name, the new account has a new SID. That is not the same member.
        $script:reads = 0
        Mock Resolve-LocalAdminMemberSid { 'S-1-5-21-1-2-3-9999' }
        Mock Get-LocalAdminMember {
            $script:reads++
            if ($script:reads -eq 1) { @($script:A, $script:C) }
            else { @($script:A, $script:C, [PSCustomObject]@{ Name = 'CONTOSO\C'; Sid = 'S-1-5-21-1-2-3-9999' }) }
        }

        $e = Set-LocalAdminMembership -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -Confirm:$false

        Should -Invoke Add-LocalAdminMember -Times 1 -Exactly
        $e.Result | Should -Be 'Done'
    }

    It 'AC4_RemoveOfAnAccountThatCannotBeFoundAndIsNotInTheGroupFails' {
        Mock Get-LocalAdminMember { @($script:A, $script:B) }

        $e = Set-LocalAdminMembership -Action Remove -Member 'CONTOSO\Ghost' -ComputerName 'PC01' -Confirm:$false

        Should -Invoke Remove-LocalAdminMember -Times 0 -Exactly
        $e.Result | Should -Be 'Failed'
        $e.Error  | Should -BeLike '*CONTOSO\Ghost could not be found on PC01*'
    }

    It 'AC15_AnOrphanedSidCanBeRemovedByItsSid' {
        $orphan = [PSCustomObject]@{ Name = ''; Sid = 'S-1-5-21-9-9-9-1105' }
        $script:reads = 0
        Mock Get-LocalAdminMember { $script:reads++; if ($script:reads -eq 1) { @($script:A, $orphan) } else { @($script:A) } }

        $e = Set-LocalAdminMembership -Action Remove -Member 'S-1-5-21-9-9-9-1105' -ComputerName 'PC01' -Confirm:$false

        Should -Invoke Remove-LocalAdminMember -Times 1 -Exactly -ParameterFilter { $Member -eq 'S-1-5-21-9-9-9-1105' }
        $e.OldValue | Should -Be 'CONTOSO\A; S-1-5-21-9-9-9-1105'
        $e.NewValue | Should -Be 'CONTOSO\A'
        $e.Result   | Should -Be 'Done'
    }

    It 'AC3_AMemberWithoutADomainIsTheLocalAccountOnTheTarget' {
        # 'LocalAdmin' cannot be translated here (fake), so it falls back to PC01\LocalAdmin.
        Mock Get-LocalAdminMember { @($script:A, [PSCustomObject]@{ Name = 'PC01\LocalAdmin'; Sid = 'S-1-5-21-7-7-7-1001' }) }

        $e = Set-LocalAdminMembership -Action Add -Member 'LocalAdmin' -ComputerName 'PC01' -Confirm:$false

        Should -Invoke Add-LocalAdminMember -Times 0 -Exactly
        $e.Result | Should -Be 'No change (already a member)'
    }

    It 'AC6_AUserPrincipalNameIsRejectedBeforeTheGroupIsRead' {
        Mock Get-LocalAdminMember { @($script:A) }

        $e = Set-LocalAdminMembership -Action Add -Member 'jsmith@contoso.com' -ComputerName 'PC01' -Confirm:$false

        Should -Invoke Get-LocalAdminMember -Times 0 -Exactly
        Should -Invoke Add-LocalAdminMember -Times 0 -Exactly
        $e.Result | Should -Be 'Failed'
        $e.Error  | Should -BeLike '*DOMAIN\Name*'
    }
}

Describe 'Set-LocalAdminMembership edge cases (review round 1)' {

    BeforeEach {
        Mock Invoke-Command { throw 'unmocked Invoke-Command' }
        Mock Invoke-OnTarget { throw 'unmocked Invoke-OnTarget' }
        Mock Resolve-LocalAdminMemberSid { Resolve-FakeMemberSid -Member $Member }
        Mock Get-LocalAdminGroupName { 'Administratoren' }
        Mock Add-LocalAdminMember { }
        Mock Remove-LocalAdminMember { }
    }

    It 'AC1_AnAddThatIsNotVisibleInTheReReadIsFailed' {
        Mock Get-LocalAdminMember { @($script:A, $script:B) }

        $e = Set-LocalAdminMembership -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -Confirm:$false

        $e.Result | Should -Be 'Failed'
        $e.Error  | Should -BeLike '*not visible after re-read*'
    }

    It 'AC2_ARemoveThatIsNotVisibleInTheReReadIsFailed' {
        Mock Get-LocalAdminMember { @($script:A, $script:C) }

        $e = Set-LocalAdminMembership -Action Remove -Member 'CONTOSO\C' -ComputerName 'PC01' -Confirm:$false

        $e.Result | Should -Be 'Failed'
        $e.Error  | Should -BeLike '*not visible after re-read*'
    }

    It 'AC1_AddToAnEmptyGroup' {
        $script:reads = 0
        Mock Get-LocalAdminMember { $script:reads++; if ($script:reads -eq 1) { @() } else { @($script:C) } }

        $e = Set-LocalAdminMembership -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -Confirm:$false

        Should -Invoke Add-LocalAdminMember -Times 1 -Exactly
        $e.OldValue | Should -BeNullOrEmpty
        $e.NewValue | Should -Be 'CONTOSO\C'
        $e.Result   | Should -Be 'Done'
    }

    It 'AC4_RemoveFromAnEmptyGroupIsNoChange' {
        Mock Get-LocalAdminMember { @() }

        $e = Set-LocalAdminMembership -Action Remove -Member 'CONTOSO\C' -ComputerName 'PC01' -Confirm:$false

        Should -Invoke Remove-LocalAdminMember -Times 0 -Exactly
        $e.Result   | Should -Be 'No change (not a member)'
        $e.OldValue | Should -BeNullOrEmpty
    }

    It 'AC7_WhatIfOnRemoveChangesNothing' {
        Mock Get-LocalAdminMember { @($script:A, $script:C) }

        $e = Set-LocalAdminMembership -Action Remove -Member 'CONTOSO\C' -ComputerName 'PC01' -WhatIf

        Should -Invoke Remove-LocalAdminMember -Times 0 -Exactly
        $e.Result   | Should -Be 'Skipped (WhatIf)'
        $e.NewValue | Should -Be $e.OldValue
    }

    It 'AC1_UsesThePreviewInsteadOfReadingTheGroupAgain' {
        Mock Get-LocalAdminMember { @($script:A, $script:B, $script:C) }
        $preview = [PSCustomObject]@{ Group = 'Administratoren'; Members = @($script:A, $script:B); MemberSid = $script:C.Sid }

        $e = Set-LocalAdminMembership -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -Preview $preview -Confirm:$false

        Should -Invoke Get-LocalAdminGroupName -Times 0 -Exactly
        Should -Invoke Resolve-LocalAdminMemberSid -Times 0 -Exactly
        Should -Invoke Get-LocalAdminMember -Times 1 -Exactly   # the re-read only
        $e.Target   | Should -Be 'PC01\Administratoren'
        $e.OldValue | Should -Be 'CONTOSO\A; CONTOSO\B'
        $e.NewValue | Should -Be 'CONTOSO\A; CONTOSO\B; CONTOSO\C'
        $e.Result   | Should -Be 'Done'
    }

    It 'AC9_ANonInteractiveSessionThatCannotConfirmIsFailedNotThrown' {
        # A child pwsh -NonInteractive cannot show the prompt. Every wrapper is replaced by a
        # fake before the call, and the transport throws, so nothing is reached.
        $child = Join-Path $TestDrive 'noninteractive.ps1'
        $lines = @(
            ". '$($script:Script)' -LoadFunctionsOnly -Action Add -Member x"
            "function Invoke-Command { throw 'unmocked Invoke-Command' }"
            "function Invoke-OnTarget { throw 'unmocked Invoke-OnTarget' }"
            "function Get-LocalAdminGroupName { 'Administratoren' }"
            "function Get-LocalAdminMember { @() }"
            "function Resolve-LocalAdminMemberSid { '' }"
            "function Add-LocalAdminMember { throw 'must not run' }"
            '$ConfirmPreference = ''High'''
            "Set-LocalAdminMembership -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' | ConvertTo-Json -Compress"
        )
        Set-Content -LiteralPath $child -Value $lines -Encoding UTF8
        $pwsh = (Get-Process -Id $PID).Path

        $json = & $pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $child
        $e = ($json | Out-String) | ConvertFrom-Json

        $e.Result | Should -Be 'Failed'
        $e.Error  | Should -BeLike '*non-interactive*-Force*'
    }
}

Describe 'Main body (review round 1)' {

    BeforeEach {
        Mock Invoke-Command { throw 'unmocked Invoke-Command' }
        Mock Invoke-OnTarget { throw 'unmocked Invoke-OnTarget' }
        $script:logFolder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        Mock Test-Administrator { $true }
        Mock Get-LocalAdminGroupName { 'Administratoren' }
        Mock Get-LocalAdminMember { @($script:A, $script:B) }
        Mock Resolve-LocalAdminMemberSid { Resolve-FakeMemberSid -Member $Member }
        Mock Get-LocalAdminGroup {
            [PSCustomObject]@{
                Group     = Get-LocalAdminGroupName -ComputerName $ComputerName
                Members   = @(Get-LocalAdminMember -ComputerName $ComputerName)
                MemberSid = Resolve-FakeMemberSid -Member $Member
            }
        }
        Mock Add-LocalAdminMember { }
        Mock Remove-LocalAdminMember { }
        Mock Write-Status { }
    }

    It 'AC7_DryRunOfAnAddThatIsNotNeededWritesNoLog' {
        Mock Get-LocalAdminMember { @($script:A, $script:B, $script:C) }
        Mock Write-LocalAdminChangeLog { throw 'must not run' }

        $code = Invoke-LocalAdminManagerMain -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -LogFolder $script:logFolder -WhatIf

        $code | Should -Be 0
        Should -Invoke Write-LocalAdminChangeLog -Times 0 -Exactly
        Should -Invoke Write-Status -Times 0 -ParameterFilter { $Message -like '*Logged to*' }
        Should -Invoke Write-Status -Times 1 -ParameterFilter { $Level -eq 'INFO' -and $Message -like 'Dry run:*already a member*' }
        Test-Path -LiteralPath $script:logFolder | Should -BeFalse
    }

    It 'AC7_DryRunAgainstAnUnreachableComputerWritesNoLogAndExits1' {
        Mock Get-LocalAdminGroup { throw 'WinRM cannot complete the operation' }
        Mock Get-LocalAdminMember { throw 'WinRM cannot complete the operation' }
        Mock Write-LocalAdminChangeLog { throw 'must not run' }

        $code = Invoke-LocalAdminManagerMain -Action Remove -Member 'CONTOSO\C' -ComputerName 'PC01' -LogFolder $script:logFolder -WhatIf

        $code | Should -Be 1
        Should -Invoke Write-LocalAdminChangeLog -Times 0 -Exactly
        Should -Invoke Remove-LocalAdminMember -Times 0 -Exactly
        Should -Invoke Write-Status -Times 0 -ParameterFilter { $Message -like '*Logged to*' }
        Test-Path -LiteralPath $script:logFolder | Should -BeFalse
    }

    It 'AC14_DoneButLogWriteFailedSaysTheChangeWasMadeAndSavesAFallbackCopy' {
        $fallback = Join-Path $TestDrive 'fallback-temp'
        Mock Test-LogFolderWritable { $true }
        Mock Get-FallbackLogFolder { $fallback }
        Mock Write-LocalAdminChangeLog { $null } -ParameterFilter { $LogFolder -eq $script:logFolder }
        Mock Set-LocalAdminMembership {
            [PSCustomObject]([ordered]@{ Time = '2026-10-18 10:00:00'; Technician = 'CONTOSO\tech'; Computer = 'ADMIN01'
                Action = 'Add administrator'; Target = 'PC01\Administratoren'; ItemType = 'Local group'
                Detail = 'CONTOSO\C'; OldValue = 'CONTOSO\A'; NewValue = 'CONTOSO\A; CONTOSO\C'
                Result = 'Done'; Error = ''; BackupFile = '' })
        }

        $code = Invoke-LocalAdminManagerMain -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -LogFolder $script:logFolder -Force

        $code | Should -Be 1
        Should -Invoke Write-Status -Times 1 -Exactly -ParameterFilter { $Level -eq 'FAIL' -and $Message -like '*WAS made*' -and $Message -like "*$($script:logFolder)*" }
        Should -Invoke Write-Status -Times 0 -ParameterFilter { $Level -eq 'PASS' }
        foreach ($field in 'Target: PC01\Administratoren', 'Detail: CONTOSO\C', 'OldValue: CONTOSO\A', 'NewValue: CONTOSO\A; CONTOSO\C', 'Result: Done') {
            Should -Invoke Write-Status -Times 1 -ParameterFilter { $Message -eq $field }
        }
        $saved = Join-Path $fallback ("LocalAdminManager_Changes_{0}.csv" -f (Get-Date -Format 'yyyy-MM-dd'))
        Test-Path -LiteralPath $saved | Should -BeTrue
        $row = @(Import-Csv -LiteralPath $saved)
        $row.Count | Should -Be 1
        $row[0].NewValue | Should -Be 'CONTOSO\A; CONTOSO\C'
    }

    It 'AC16_NotConfirmedExits1' {
        Mock Test-LogFolderWritable { $true }
        Mock Write-LocalAdminChangeLog { 'C:\fake\Logs\Changes_2026-10-18.csv' }
        Mock Set-LocalAdminMembership { [PSCustomObject]@{ Result = 'Skipped (not confirmed)'; Error = '' } }

        Invoke-LocalAdminManagerMain -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -LogFolder $script:logFolder | Should -Be 1
    }

    It 'AC16_AUserPrincipalNameIsRefusedWithExitCode1' {
        Mock Set-LocalAdminMembership { throw 'must not run' }

        $code = Invoke-LocalAdminManagerMain -Action Add -Member 'jsmith@contoso.com' -ComputerName 'PC01' -LogFolder $script:logFolder -Force

        $code | Should -Be 1
        Should -Invoke Set-LocalAdminMembership -Times 0 -Exactly
        Should -Invoke Write-Status -Times 1 -ParameterFilter { $Level -eq 'FAIL' -and $Message -like '*DOMAIN\Name*' }
    }

    It 'AC1_PassesThePreviewItShowedToTheChange' {
        Mock Test-LogFolderWritable { $true }
        Mock Write-LocalAdminChangeLog { 'C:\fake\Logs\Changes_2026-10-18.csv' }
        Mock Set-LocalAdminMembership { [PSCustomObject]@{ Target = 'PC01\Administratoren'; Result = 'Done'; Error = '' } }

        Invoke-LocalAdminManagerMain -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -LogFolder $script:logFolder -Force | Should -Be 0

        Should -Invoke Get-LocalAdminGroup -Times 1 -Exactly
        Should -Invoke Set-LocalAdminMembership -Times 1 -Exactly -ParameterFilter { $Preview -and $Preview.Group -eq 'Administratoren' -and @($Preview.Members).Count -eq 2 }
        Should -Invoke Write-Status -Times 1 -ParameterFilter { $Level -eq 'PASS' -and $Message -like 'Added CONTOSO\C to Administratoren on PC01.*' }
    }

    It 'AC11_ThisComputersOwnFqdnIsChangedAsTheLocalComputer' {
        Mock Get-LocalComputerFqdn { "$env:COMPUTERNAME.contoso.test" }
        Mock Test-LogFolderWritable { $true }
        Mock Write-LocalAdminChangeLog { 'C:\fake\Logs\Changes_2026-10-18.csv' }
        Mock Set-LocalAdminMembership { [PSCustomObject]@{ Result = 'Done'; Error = '' } }

        Invoke-LocalAdminManagerMain -Action Add -Member 'CONTOSO\C' -ComputerName "$env:COMPUTERNAME.contoso.test" -LogFolder $script:logFolder -Force | Out-Null
        Invoke-LocalAdminManagerMain -Action Add -Member 'CONTOSO\C' -ComputerName "$env:COMPUTERNAME.otherdomain.tld" -LogFolder $script:logFolder -Force | Out-Null

        Should -Invoke Set-LocalAdminMembership -Times 1 -Exactly -ParameterFilter { $ComputerName -eq $env:COMPUTERNAME }
        Should -Invoke Set-LocalAdminMembership -Times 1 -Exactly -ParameterFilter { $ComputerName -eq "$env:COMPUTERNAME.otherdomain.tld" }
    }

    It 'AC14_ScriptOnAShareLogsToLocalAppDataAndWarns' {
        $oldLocal = $env:LOCALAPPDATA
        try {
            $env:LOCALAPPDATA = Join-Path $TestDrive 'localappdata'
            $script:expected = Join-Path $env:LOCALAPPDATA 'LocalAdminManager\Logs'
            Mock Test-LogFolderWritable { $true }
            Mock Write-LocalAdminChangeLog { Join-Path $LogFolder 'Changes_2026-10-18.csv' }
            Mock Set-LocalAdminMembership { [PSCustomObject]@{ Result = 'Done'; Error = '' } }

            $code = Invoke-LocalAdminManagerMain -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -DefaultLogFolder '\\fs01\tools\LocalAdminManager\Logs' -Force

            $code | Should -Be 0
            Should -Invoke Test-LogFolderWritable -Times 1 -Exactly -ParameterFilter { $LogFolder -eq $script:expected }
            Should -Invoke Write-LocalAdminChangeLog -Times 1 -Exactly -ParameterFilter { $LogFolder -eq $script:expected }
            Should -Invoke Write-Status -Times 1 -ParameterFilter { $Level -eq 'WARN' -and $Message -like '*network or removable location*' }
        } finally {
            $env:LOCALAPPDATA = $oldLocal
        }
    }
}

Describe 'Change log (review round 1)' {

    It 'AC13_ValuesThatExcelWouldRunAsAFormulaGetALeadingQuote' {
        $folder = Join-Path $TestDrive 'formula'
        $entry = [PSCustomObject]([ordered]@{ Time = '2026-10-18 10:00:00'; Technician = 'CONTOSO\tech'; Computer = 'ADMIN01'
            Action = 'Add administrator'; Target = 'PC01\Administratoren'; ItemType = 'Local group'
            Detail = '=1+1'; OldValue = '@SUM(A1)'; NewValue = '+A1'; Result = 'Failed'; Error = '-cmd|calc'; BackupFile = '' })

        $path = Write-LocalAdminChangeLog -Entries @($entry) -LogFolder $folder
        $row = @(Import-Csv -LiteralPath $path)[0]

        $row.Detail   | Should -Be "'=1+1"
        $row.OldValue | Should -Be "'@SUM(A1)"
        $row.NewValue | Should -Be "'+A1"
        $row.Error    | Should -Be "'-cmd|calc"
        $row.Target   | Should -Be 'PC01\Administratoren'
    }

    It 'AC14_TheProbeOpensTodaysLogSoALockedLogFailsClosed' {
        $folder = Join-Path $TestDrive 'locked'
        New-Item -ItemType Directory -Path $folder | Out-Null
        $today = Join-Path $folder ("Changes_{0}.csv" -f (Get-Date -Format 'yyyy-MM-dd'))
        $lock = [System.IO.File]::Open($today, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            Test-LogFolderWritable -LogFolder $folder | Should -BeFalse
        } finally {
            $lock.Dispose()
        }
        Test-LogFolderWritable -LogFolder $folder | Should -BeTrue
        @(Get-ChildItem -LiteralPath $folder -Filter '*.tmp' -Force).Count | Should -Be 0
    }

    It 'AC14_ADefaultFolderOnAShareFallsBackToLocalAppDataAndAnExplicitShareIsKeptWithAWarning' {
        $oldLocal = $env:LOCALAPPDATA
        try {
            $env:LOCALAPPDATA = Join-Path $TestDrive 'localappdata'
            $unc = '\\fs01\tools\LocalAdminManager\Logs'

            $resolved = Resolve-ChangeLogFolder -DefaultFolder $unc
            $resolved | Should -Be (Join-Path $env:LOCALAPPDATA 'LocalAdminManager\Logs')
            @(Get-ChangeLogFolderNotice -ResolvedFolder $resolved -DefaultFolder $unc)[0] | Should -BeLike '*running from a network or removable location*'

            Resolve-ChangeLogFolder -LogFolder $unc -DefaultFolder $unc | Should -Be $unc
            @(Get-ChangeLogFolderNotice -LogFolder $unc -ResolvedFolder $unc -DefaultFolder $unc)[0] |
                Should -BeLike "The log folder $([WildcardPattern]::Escape($unc)) is on a network drive or share*"

            $local = Join-Path $TestDrive 'tool\Logs'
            Resolve-ChangeLogFolder -DefaultFolder $local | Should -Be $local
            @(Get-ChangeLogFolderNotice -ResolvedFolder $local -DefaultFolder $local).Count | Should -Be 0

            Mock Get-LocalAppDataFolder { '' }
            { Resolve-ChangeLogFolder -DefaultFolder $unc } | Should -Throw '*-LogFolder*'
        } finally {
            $env:LOCALAPPDATA = $oldLocal
        }
    }
}

Describe 'Target and ADsPath (review round 1)' {

    BeforeEach {
        Mock Invoke-Command { throw 'unmocked Invoke-Command' }
    }

    It 'AC11_OtherLocalFormsAreLocal' -ForEach @(
        @{ Name = '127.0.0.1' }, @{ Name = '::1' }, @{ Name = "$env:COMPUTERNAME.contoso.test" }
    ) {
        Mock Get-LocalComputerFqdn { "$env:COMPUTERNAME.contoso.test" }
        Test-IsLocalComputer -ComputerName $Name | Should -BeTrue
    }

    It 'AC12_ThisHostNameInAnotherDnsDomainIsRemote' {
        Mock Get-LocalComputerFqdn { "$env:COMPUTERNAME.contoso.test" }
        Test-IsLocalComputer -ComputerName "$env:COMPUTERNAME.otherdomain.tld" | Should -BeFalse

        # Outside a domain the FQDN is just the host name, so no dotted name is local.
        Mock Get-LocalComputerFqdn { $env:COMPUTERNAME }
        Test-IsLocalComputer -ComputerName "$env:COMPUTERNAME.contoso.test" | Should -BeFalse
    }

    It 'AC12_ScriptRefusesAnEmptyComputerName' {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Script, [ref]$tokens, [ref]$errors)
        $param = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'ComputerName' }
        @($param.Attributes | ForEach-Object { $_.TypeName.Name }) | Should -Contain 'ValidateNotNullOrEmpty'
    }

    It 'AC3_ADsPathFor_<Member>' -ForEach @(
        @{ Member = 'CONTOSO\JSmith';      Expected = 'WinNT://CONTOSO/JSmith' }
        @{ Member = 'LocalAdmin';          Expected = 'WinNT://PC01/LocalAdmin' }
        @{ Member = 'S-1-5-21-9-9-9-1105'; Expected = 'WinNT://S-1-5-21-9-9-9-1105' }
    ) {
        ConvertTo-WinNTMemberPath -Member $Member -ComputerName 'PC01' | Should -Be $Expected

        # Parity: the target runs this function's own text, passed in by the write wrappers.
        $script:sent = $null
        Mock Invoke-OnTarget { $script:sent = $ArgumentList }
        Add-LocalAdminMember -ComputerName 'PC01' -Member $Member
        $script:sent[0] | Should -Be 'Add'
        (& ([scriptblock]::Create([string]$script:sent[3])) $Member 'PC01') | Should -Be $Expected
        Remove-LocalAdminMember -ComputerName 'PC01' -Member $Member
        $script:sent[0] | Should -Be 'Remove'
        (& ([scriptblock]::Create([string]$script:sent[3])) $Member 'PC01') | Should -Be $Expected
    }

    It 'AC1_ThePreviewReadAsksTheTargetToResolveTheMember' {
        $script:sent = $null
        Mock Invoke-OnTarget { $script:sent = $ArgumentList; [PSCustomObject]@{ Group = 'Administratoren'; Members = @($script:A); MemberSid = $script:A.Sid } }

        $info = Get-LocalAdminGroup -ComputerName 'PC01' -Member 'CONTOSO\A'

        $script:sent[0] | Should -Be 'Get'
        $script:sent[2] | Should -Be 'CONTOSO\A'
        $info.MemberSid | Should -Be $script:A.Sid
        @(Get-LocalAdminMember -ComputerName 'PC01').Count | Should -Be 1
    }
}
