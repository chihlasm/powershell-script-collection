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
    }
}
