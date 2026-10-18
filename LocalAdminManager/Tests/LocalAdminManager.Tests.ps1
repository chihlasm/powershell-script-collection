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
}

Describe 'Set-LocalAdminMembership' {

    BeforeEach {
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

        $e = $null
        { $e = Set-LocalAdminMembership -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -Confirm:$false } | Should -Not -Throw

        $e.Result   | Should -Be 'Failed'
        $e.Error    | Should -Match 'Access is denied'
        $e.OldValue | Should -Be 'CONTOSO\A; CONTOSO\B'
        $e.NewValue | Should -Be 'CONTOSO\A; CONTOSO\B'
        $script:reads | Should -BeGreaterOrEqual 2
    }

    It 'AC5_FailedRemoveIsReturnedNotThrown' {
        Mock Get-LocalAdminMember { @($script:A, $script:C) }
        Mock Remove-LocalAdminMember { throw 'Access is denied' }

        $e = $null
        { $e = Set-LocalAdminMembership -Action Remove -Member 'CONTOSO\C' -ComputerName 'PC01' -Confirm:$false } | Should -Not -Throw

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

        $e = $null
        { $e = Set-LocalAdminMembership -Action Add -Member 'CONTOSO\C' -ComputerName 'PC01' -Confirm:$false } | Should -Not -Throw

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
        $script:logFolder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        Mock Test-Administrator { $true }
        Mock Get-LocalAdminGroupName { 'Administratoren' }
        Mock Get-LocalAdminMember { @($script:A, $script:B) }
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

    It 'AC11_LocalNamesRunInProcessWithoutInvokeCommand' -ForEach @(
        @{ Name = $env:COMPUTERNAME }, @{ Name = 'localhost' }, @{ Name = '.' }, @{ Name = '' }
    ) {
        Mock Invoke-Command { throw 'Invoke-Command must not be used for the local computer' }

        Test-IsLocalComputer -ComputerName $Name | Should -BeTrue
        Invoke-OnTarget -ComputerName $Name -ScriptBlock { param($x) "ran $x" } -ArgumentList @('here') | Should -Be 'ran here'

        Should -Invoke Invoke-Command -Times 0 -Exactly
    }

    It 'AC11_ReadAndChangeWrappersGoThroughInvokeOnTargetWithTheComputerName' {
        Mock Invoke-OnTarget { }

        Get-LocalAdminMember -ComputerName $env:COMPUTERNAME | Out-Null
        Add-LocalAdminMember -ComputerName $env:COMPUTERNAME -Member 'CONTOSO\C'
        Remove-LocalAdminMember -ComputerName $env:COMPUTERNAME -Member 'CONTOSO\C'

        Should -Invoke Invoke-OnTarget -Times 3 -Exactly -ParameterFilter { $ComputerName -eq $env:COMPUTERNAME }
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
