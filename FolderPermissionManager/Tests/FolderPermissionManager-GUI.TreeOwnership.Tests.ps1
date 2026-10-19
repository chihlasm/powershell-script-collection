<#
    Wiring tests for the GUI's recursive take-ownership endpoint (SQ-014, AC16; Pester 5, pwsh).

    As in FolderPermissionManager-GUI.Handlers.Tests.ps1, the GUI script is never run: only its
    handler function definitions are read from the syntax tree. Set-Acl, Invoke-AclTool and the
    bare takeown/icacls names are mocked, so nothing can take ownership of anything.

    Pinned: the recursive branch of Invoke-TakeOwnership goes through
    Set-ItemOwnerToCurrentUser -Recurse (the core), returns the usual JSON (status, message,
    logPath, backupPath), and the confirm dialog says the owners are saved first.
#>

BeforeAll {
    $folder = Join-Path $PSScriptRoot '..'
    . (Join-Path $folder 'FolderPermissions.Core.ps1') -LoadFunctionsOnly
    # Guard: the real Invoke-AclTool runs takeown.exe and icacls.exe by full path, which the
    # bare 'Mock takeown' / 'Mock icacls' cannot catch. Replaced here (same parameters) so a
    # test that forgets to mock it fails instead of changing real owners.
    function Invoke-AclTool {
        param(
            [Parameter(Mandatory)][ValidateSet('icacls', 'takeown')][string]$Tool,
            [Parameter(Mandatory)][string[]]$Arguments
        )
        throw "Invoke-AclTool ($Tool) was called without a mock in a test."
    }
    $script:RealGetItemOwner = ${function:Get-ItemOwner}

    $script:GuiPath = (Resolve-Path (Join-Path $folder 'FolderPermissionManager-GUI.ps1')).Path
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:GuiPath, [ref]$null, [ref]$null)
    $handlers = 'Resolve-MappedDrive', 'Complete-PermissionChange', 'ConvertTo-ChangeResultRow',
        'Send-SingleChangeResult', 'Send-BatchChangeResult', 'Invoke-TakeOwnership'
    $definitions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) |
        Where-Object { $handlers -contains $_.Name }
    foreach ($d in $definitions) {
        $text = $d.Extent.Text -replace '\[System\.Net\.HttpListenerResponse\]', '[object]'
        . ([scriptblock]::Create($text))
    }

    function Send-Json { param($Response, $Data) $script:Sent = $Data }
    function Read-RequestBody { param($Request) $script:Body }
}

Describe 'GUI recursive take ownership' {
    BeforeEach {
        $script:driveMappings = @{}
        $script:ChangeLogFolder = Join-Path $TestDrive ('logs-' + [guid]::NewGuid().ToString('N'))
        $script:Dir = Join-Path $TestDrive 'Tree [old]'
        New-Item -ItemType Directory -Path (Join-Path $script:Dir 'sub') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:Dir 'sub\a.txt') -Value 'x'
        Mock Set-Acl { }
        Mock takeown { }
        Mock icacls { }
        Mock Invoke-AclTool { [PSCustomObject]@{ ExitCode = 0; Output = '' } }
    }

    It 'AC16_GuiRecursiveTakeOwnership_BacksUpOwnersLogsAndUsesTheFullAccountName' {
        $script:Body = [PSCustomObject]@{ path = $script:Dir; recursive = $true }
        $script:Sent = $null
        $response = [PSCustomObject]@{ StatusCode = 200 }
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        Invoke-TakeOwnership $null $response

        $response.StatusCode | Should -Be 200
        $script:Sent.status | Should -Be 'success'
        $script:Sent.message | Should -Match 'Backed up to .*_TakeOwnership\.csv and logged to'
        Should -Invoke takeown -Times 0 -Exactly -Scope It
        Should -Invoke icacls -Times 0 -Exactly -Scope It
        Should -Invoke Invoke-AclTool -Times 1 -Exactly -Scope It -ParameterFilter { $Tool -eq 'takeown' -and $Arguments -contains '/R' }
        Should -Invoke Invoke-AclTool -Times 1 -Exactly -Scope It -ParameterFilter {
            $Tool -eq 'icacls' -and $Arguments[1] -eq '/setowner' -and $Arguments[2] -eq $me
        }
        $snapshot = @(Get-ChildItem -LiteralPath (Join-Path $script:ChangeLogFolder 'Backups') -Filter '*_TakeOwnership.csv')
        $snapshot.Count | Should -Be 1
        @(Import-Csv -LiteralPath $snapshot[0].FullName).Count | Should -Be 3
        $log = @(Import-Csv -LiteralPath $script:Sent.logPath)
        $log.Count | Should -Be 1
        $log[0].Action | Should -Be 'Take ownership (all subfolders and files)'
        $log[0].ItemType | Should -Be 'Folder tree'
    }

    It 'AC16_GuiRecursiveConfirmText_SaysOwnersAreBackedUpNotThatItCannotBeUndone' {
        $raw = Get-Content -LiteralPath $script:GuiPath -Raw
        $m = [regex]::Match($raw, '(?s)This will change ownership on ALL files and subfolders under:.*?Continue\?')
        $m.Success | Should -BeTrue
        $m.Value | Should -Match 'The current owners will be saved to a backup first'
        $m.Value | Should -Not -Match 'This cannot be undone'
        $m.Value | Should -Match 'You become the owner\.'
    }

    # --- Fix round 1 (SQ-014 review) ---------------------------------------------------------

    It 'AC17_GuiRecursiveTakeOwnership_PartlyDoneReturns200WithStatusPartial' {
        $script:ToolsRan = $false
        Mock Invoke-AclTool { $script:ToolsRan = $true; [PSCustomObject]@{ ExitCode = 0; Output = '' } }
        Mock Get-ItemOwner {
            if ($script:ToolsRan -and $Path -like '*a.txt') { return [PSCustomObject]@{ Owner = 'CONTOSO\old.owner'; OwnerSid = 'S-1-5-21-1-2-3-1105' } }
            & $script:RealGetItemOwner -Path $Path
        }
        $script:Body = [PSCustomObject]@{ path = $script:Dir; recursive = $true }
        $response = [PSCustomObject]@{ StatusCode = 200 }

        Invoke-TakeOwnership $null $response

        $response.StatusCode | Should -Be 200
        $script:Sent.status | Should -Be 'partial'
        $script:Sent.message | Should -BeLike 'Partly done: *'
        $script:Sent.Keys | Should -Not -Contain 'error'
    }

    It 'AC17_GuiRecursiveTakeOwnership_FailedReturns500WithTheMessageAsError' {
        Mock Invoke-AclTool { [PSCustomObject]@{ ExitCode = 1; Output = 'ERROR: Access is denied.' } }
        Mock Get-ItemOwner { [PSCustomObject]@{ Owner = 'CONTOSO\old.owner'; OwnerSid = 'S-1-5-21-1-2-3-1105' } }
        $script:Body = [PSCustomObject]@{ path = $script:Dir; recursive = $true }
        $response = [PSCustomObject]@{ StatusCode = 200 }

        Invoke-TakeOwnership $null $response

        $response.StatusCode | Should -Be 500
        $script:Sent.error | Should -Not -BeNullOrEmpty
        $script:Sent.error | Should -Be $script:Sent.message
        $script:Sent.error | Should -BeLike 'Could not take ownership of *'
    }

    It 'AC18_GuiRecursiveTakeOwnership_FolderThatCannotBeListed_IsNotSuccess' {
        $locked = Join-Path $script:Dir 'sub'
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $locked }
        $script:Body = [PSCustomObject]@{ path = $script:Dir; recursive = $true }
        $response = [PSCustomObject]@{ StatusCode = 200 }

        Invoke-TakeOwnership $null $response

        $response.StatusCode | Should -Be 200
        $script:Sent.status | Should -Be 'partial'
        $script:Sent.message | Should -BeLike "*Escalate: 1 folder(s) could not be opened, so they were left alone. Not opened: $([WildcardPattern]::Escape($locked)).*cannot be restored from this backup*"
    }

    It 'AC17_GuiPage_ShowsPartialAsAWarningWithoutDoublingThePrefix' {
        $raw = Get-Content -LiteralPath $script:GuiPath -Raw
        $statusType = [regex]::Match($raw, '(?s)function changeStatusType\(r\) \{.*?\n\}')
        $statusType.Success | Should -BeTrue
        $statusType.Value | Should -Match "if \(r\.status === 'partial'\) return 'warning';"
        $show = [regex]::Match($raw, '(?s)function showChangeResult\(r\) \{.*?\n\}')
        $show.Success | Should -BeTrue
        # The prefix is only added when the message does not already start with it.
        $show.Value | Should -Match "msg\.indexOf\('Partly done:'\) !== 0"
        $show.Value | Should -Not -Match "r\.status !== 'partial'"
    }

    It 'AC16_GuiPage_SecondTakeOwnershipClickWhileBusySaysStillWorking' {
        $raw = Get-Content -LiteralPath $script:GuiPath -Raw
        $fn = [regex]::Match($raw, '(?s)function takeOwnership\(recursive\) \{.*?\n\}')
        $fn.Success | Should -BeTrue
        $fn.Value | Should -Match '(?s)if \(ownershipBusy\) \{\s*setStatus\(''Still working on the previous change'
        $fn.Value | Should -Match 'ownershipBusy = true;'
        @([regex]::Matches($fn.Value, 'ownershipBusy = false;')).Count | Should -Be 2 -Because 'cleared on success and on error'
    }

    # --- Fix round 2 (SQ-014 review) ---------------------------------------------------------

    # Fix round 2 pinned /D Y here (permissions replaced with full control and backed up);
    # D-034 superseded that: takeown /D N skips such folders and leaves them alone.
    It 'AC16_GuiRecursiveConfirmText_SaysFoldersThatCannotBeOpenedAreSkippedAndNamedForEscalation' {
        $raw = Get-Content -LiteralPath $script:GuiPath -Raw
        $m = [regex]::Match($raw, '(?s)This will change ownership on ALL files and subfolders under:.*?Continue\?')
        $m.Success | Should -BeTrue
        $m.Value | Should -Match 'Any folder in it that cannot be opened is skipped and left alone'
        $m.Value | Should -Match 'the result names those folders so you can escalate them'
        $m.Value | Should -Not -Match 'backed up first where they can be read'
    }

    It 'AC18_GuiRecursiveTakeOwnership_FolderThatCannotBeListed_MessageSaysToEscalateAndNothingIsBackedUpForIt' {
        $locked = Join-Path $script:Dir 'sub'
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $locked }
        $script:Body = [PSCustomObject]@{ path = $script:Dir; recursive = $true }
        $response = [PSCustomObject]@{ StatusCode = 200 }

        Invoke-TakeOwnership $null $response

        $script:Sent.status | Should -Be 'partial'
        $script:Sent.message | Should -BeLike '*Escalate: 1 folder(s) could not be opened, so they were left alone.*'
        $script:Sent.message | Should -Not -Match 'full control'
        @(Get-ChildItem -LiteralPath (Join-Path $script:ChangeLogFolder 'Backups') -Filter '*_TakeOwnership_Permissions.csv').Count | Should -Be 0
    }

    It 'AC16_GuiRecursiveTakeOwnership_JunctionMakesTheResultAWarningAndIsCounted' {
        $elsewhere = Join-Path $TestDrive ('gui-junction-target-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $elsewhere -Force | Out-Null
        New-Item -ItemType Junction -Path (Join-Path $script:Dir 'link') -Target $elsewhere | Out-Null
        try {
            $script:Body = [PSCustomObject]@{ path = $script:Dir; recursive = $true }
            $response = [PSCustomObject]@{ StatusCode = 200 }

            Invoke-TakeOwnership $null $response

            $script:Sent.status | Should -Be 'partial'
            $script:Sent.message | Should -BeLike '*1 junction(s) or symbolic link(s) (*link) were listed but not gone into*'
        } finally {
            [System.IO.Directory]::Delete((Join-Path $script:Dir 'link'))
        }
    }

    # --- Revision (SQ-014 review 2026-10-18, D-040) --------------------------------------------
    # Pinned: a DFS reparse point (tag 0x8000000A, no name-surrogate bit) inside the folder counts
    # as a link, so one that leads to a protected folder or a system share answers 500 with the
    # refusal naming the link, and nothing is saved or changed.

    It 'AC20a_GuiRecursiveTakeOwnership_DfsReparsePointToASystemShare_IsRefusedAndNothingIsDone' -ForEach @(
        @{ Name = 'NETLOGON share'; Target = '\\dc01\NETLOGON' }
        @{ Name = 'Windows folder'; Target = (Join-Path $env:SystemRoot 'System32') }
    ) {
        $script:DfsLink = Join-Path $script:Dir 'dfs'
        New-Item -ItemType Directory -Path $script:DfsLink -Force | Out-Null
        $script:DfsTarget = $Target
        Mock Get-ChildItem {
            [PSCustomObject]@{
                FullName = $script:DfsLink; Name = 'dfs'; PSIsContainer = $true
                Attributes = [System.IO.FileAttributes]'Directory, ReparsePoint'
            }
        } -ParameterFilter { $LiteralPath -eq $script:Dir }
        Mock Get-ReparsePointTag { [uint32]'0x8000000A' } -ParameterFilter { $Path -eq $script:DfsLink }
        Mock Get-Win32PathName { $script:DfsTarget } -ParameterFilter { $Path -eq $script:DfsLink }
        $script:Body = [PSCustomObject]@{ path = $script:Dir; recursive = $true }
        $script:Sent = $null
        $response = [PSCustomObject]@{ StatusCode = 200 }

        Invoke-TakeOwnership $null $response

        $response.StatusCode | Should -Be 500
        $script:Sent.error | Should -Not -BeNullOrEmpty
        $script:Sent.error | Should -Be $script:Sent.message
        $script:Sent.error | Should -Match ([regex]::Escape($script:DfsLink))
        $script:Sent.error | Should -Match 'Nothing was changed'
        $script:Sent.error | Should -Not -Match 'AllowSystemFolder'
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
    }

    It 'AC16_GuiPage_EveryChangeActionSharesTheBusyFlag' {
        $raw = Get-Content -LiteralPath $script:GuiPath -Raw
        foreach ($name in 'submitAddAce', 'submitRemoveAce', 'submitReplicate', 'takeFileOwnership') {
            $fn = [regex]::Match($raw, "(?s)function $name\(\) \{.*?\n\}")
            $fn.Success | Should -BeTrue -Because "$name exists"
            $fn.Value | Should -Match 'if \(changeIsBusy\(\)\) return;' -Because "$name refuses to start while a change runs"
            $fn.Value | Should -Match 'ownershipBusy = true;' -Because "$name marks a change as running"
            @([regex]::Matches($fn.Value, 'ownershipBusy = false;')).Count | Should -BeGreaterOrEqual 2 -Because "$name clears the flag on success and on error"
        }
        $busy = [regex]::Match($raw, '(?s)function changeIsBusy\(\) \{.*?\n\}')
        $busy.Success | Should -BeTrue
        $busy.Value | Should -Match "setStatus\('Still working on the previous change"
    }

    # --- Revision (SQ-014 review 2026-10-17): D-034 and D-036 -------------------------------
    # Pinned: the GUI never passes -AllowSystemFolder (no override, whatever the request says);
    # a refused folder answers 500 with the refusal as `error`/`message` and does nothing.

    It 'AC16b_GuiRecursiveTakeOwnership_TakeownRunsWithDNeverDY' {
        $script:Body = [PSCustomObject]@{ path = $script:Dir; recursive = $true }
        $script:Sent = $null
        $response = [PSCustomObject]@{ StatusCode = 200 }

        Invoke-TakeOwnership $null $response

        Should -Invoke Invoke-AclTool -Times 1 -Exactly -Scope It -ParameterFilter {
            $Tool -eq 'takeown' -and ($Arguments -join ' ') -eq "/F $($script:Dir) /R /A /D N"
        }
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It -ParameterFilter { $Tool -eq 'takeown' -and $Arguments -contains 'Y' }
    }

    It 'AC16c_GuiRecursiveTakeOwnership_FolderThatCannotBeOpened_IsPartialNamedWithEscalateAndNotBackedUpOrChanged' {
        $locked = Join-Path $script:Dir 'sub'
        $script:LockedPath = $locked
        $script:ToolsRan = $false
        Mock Invoke-AclTool { $script:ToolsRan = $true; [PSCustomObject]@{ ExitCode = 0; Output = '' } }
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $script:LockedPath }
        # takeown /D N leaves a folder it cannot open alone, so its owner is still the old one.
        Mock Get-ItemOwner {
            if ($script:ToolsRan -and $Path -eq $script:LockedPath) { return [PSCustomObject]@{ Owner = 'CONTOSO\old.owner'; OwnerSid = 'S-1-5-21-1-2-3-1105' } }
            & $script:RealGetItemOwner -Path $Path
        }
        $script:Body = [PSCustomObject]@{ path = $script:Dir; recursive = $true }
        $response = [PSCustomObject]@{ StatusCode = 200 }

        Invoke-TakeOwnership $null $response

        $response.StatusCode | Should -Be 200
        $script:Sent.status | Should -Be 'partial'
        $script:Sent.message | Should -Match '^Partly done'
        $script:Sent.message | Should -Match ([regex]::Escape('Escalate: 1 folder(s) could not be opened, so they were left alone.'))
        $script:Sent.message | Should -Match ([regex]::Escape($locked))
        $script:Sent.message | Should -Not -Match 'full control'
        $script:Sent.message | Should -Not -Match '_Permissions\.csv'
        @(Get-ChildItem -LiteralPath (Join-Path $script:ChangeLogFolder 'Backups') -Filter '*_Permissions.csv').Count | Should -Be 0
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
    }

    It 'AC16c_GuiRecursiveConfirmText_SaysFoldersThatCannotBeOpenedAreSkipped_AndNoLongerPromisesFullControl' {
        $raw = Get-Content -LiteralPath $script:GuiPath -Raw
        $m = [regex]::Match($raw, '(?s)This will change ownership on ALL files and subfolders under:.*?Continue\?')
        $m.Success | Should -BeTrue
        $m.Value | Should -Match '(?i)cannot be opened[^.]*(skipped|left alone)'
        $m.Value | Should -Not -Match 'full control'
        $m.Value | Should -Not -Match 'backed up first where they can be read'
        $m.Value | Should -Match 'The current owners will be saved to a backup first'
    }

    It 'AC16d_GuiRecursiveTakeOwnership_VolumeRoot_IsRefusedWithAPlainMessageAndNothingIsDone' {
        $root = [System.IO.Path]::GetPathRoot($TestDrive)
        # If the refusal is missing, these keep the test from walking the whole drive.
        Mock Save-OwnerSnapshot { throw 'snapshot must not be taken (test)' }
        $script:Body = [PSCustomObject]@{ path = $root; recursive = $true }
        $script:Sent = $null
        $response = [PSCustomObject]@{ StatusCode = 200 }

        Invoke-TakeOwnership $null $response

        $response.StatusCode | Should -Be 500
        $script:Sent.error | Should -Not -BeNullOrEmpty
        $script:Sent.error | Should -Be $script:Sent.message
        $script:Sent.error | Should -Match ([regex]::Escape($root))
        $script:Sent.error | Should -Match 'Nothing was changed'
        $script:Sent.error | Should -Not -Match 'AllowSystemFolder'
        Should -Invoke Save-OwnerSnapshot -Times 0 -Exactly -Scope It
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
        Test-Path -LiteralPath (Join-Path $script:ChangeLogFolder 'Backups') | Should -BeFalse
    }

    It 'AC16d_GuiRecursiveTakeOwnership_FolderUnderAProtectedPath_IsRefusedAndTheRequestCannotOverrideIt' {
        $base = Join-Path $TestDrive ('gui-protected-' + [guid]::NewGuid().ToString('N'))
        $dir = Join-Path $base 'Contoso'
        New-Item -ItemType Directory -Path (Join-Path $dir 'sub') -Force | Out-Null
        $script:Body = [PSCustomObject]@{ path = $dir; recursive = $true; allowSystemFolder = $true; force = $true }
        $script:Sent = $null
        $response = [PSCustomObject]@{ StatusCode = 200 }
        $old = [Environment]::GetEnvironmentVariable('ProgramData', 'Process')
        [Environment]::SetEnvironmentVariable('ProgramData', $base, 'Process')
        try {
            Invoke-TakeOwnership $null $response
        } finally {
            [Environment]::SetEnvironmentVariable('ProgramData', $old, 'Process')
        }

        $response.StatusCode | Should -Be 500
        $script:Sent.error | Should -Match ([regex]::Escape($dir))
        $script:Sent.error | Should -Match 'Nothing was changed'
        $script:Sent.error | Should -Not -Match 'AllowSystemFolder'
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        Test-Path -LiteralPath (Join-Path $script:ChangeLogFolder 'Backups') | Should -BeFalse
    }

    It 'AC16d_GuiScript_HasNoSystemFolderOverride' {
        $raw = Get-Content -LiteralPath $script:GuiPath -Raw
        $raw | Should -Not -Match 'AllowSystemFolder'
    }

    # --- Fix round 1 (SQ-014 review 2026-10-17) ------------------------------------------------

    It 'AC16c_GuiRecursiveTakeOwnership_ManyFoldersThatCannotBeOpened_MessagePointsAtTheFullList' {
        $script:LockedSet = @(1..5 | ForEach-Object {
            $p = Join-Path $script:Dir ('locked{0}' -f $_)
            New-Item -ItemType Directory -Path $p -Force | Out-Null
            $p
        })
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $script:LockedSet -contains $LiteralPath }
        $script:Body = [PSCustomObject]@{ path = $script:Dir; recursive = $true }
        $response = [PSCustomObject]@{ StatusCode = 200 }

        Invoke-TakeOwnership $null $response

        $script:Sent.status | Should -Be 'partial'
        $script:Sent.message | Should -Match 'and 2 more\.'
        $script:Sent.message | Should -Match 'Full list: .*_NotOpened\.txt\.'
        $script:Sent.message | Should -Match ([regex]::Escape('Ask a senior engineer to take ownership of them with an account that can open them.'))
    }

    It 'AC17_GuiPage_DoneWithItemsToCheckInsteadOfCheckThis' {
        $raw = Get-Content -LiteralPath $script:GuiPath -Raw
        $show = [regex]::Match($raw, '(?s)function showChangeResult\(r\) \{.*?\n\}')
        $show.Success | Should -BeTrue
        $show.Value | Should -Match "'Done, with items to check: '"
        $show.Value | Should -Not -Match 'Check this:'
    }

    It 'AC16c_GuiPage_LongStatusMessagesScrollInsteadOfGrowingTheWindow' {
        $raw = Get-Content -LiteralPath $script:GuiPath -Raw
        $css = [regex]::Match($raw, '\.status-bar \{[^}]*\}')
        $css.Success | Should -BeTrue
        $css.Value | Should -Match 'max-height:'
        $css.Value | Should -Match 'overflow-y: auto'
    }
}
