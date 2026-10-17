<#
    Wiring tests for the GUI's single-item change endpoints (SQ-008; Pester 5, run under pwsh).

    The GUI script is never run or launched: only its handler function definitions are taken
    from its syntax tree and defined here. Set-Acl and Invoke-AclTool are always mocked;
    Get-Acl is real and only reads folders and files inside $TestDrive. Send-Json and
    Read-RequestBody are replaced so no HTTP listener is needed.

    Run:  Invoke-Pester .\FolderPermissionManager\Tests
#>

BeforeAll {
    $folder = Join-Path $PSScriptRoot '..'
    . (Join-Path $folder 'FolderPermissions.Core.ps1') -LoadFunctionsOnly

    $guiPath = (Resolve-Path (Join-Path $folder 'FolderPermissionManager-GUI.ps1')).Path
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($guiPath, [ref]$null, [ref]$null)
    $handlers = 'Resolve-MappedDrive', 'Complete-PermissionChange', 'ConvertTo-ChangeResultRow',
        'Send-SingleChangeResult', 'Send-BatchChangeResult', 'Invoke-AddAce', 'Invoke-RemoveAce',
        'Invoke-AddFileAce', 'Invoke-RemoveFileAce', 'Invoke-TakeOwnership', 'Invoke-TakeFileOwnership',
        'Invoke-ReplicatePermissions'
    $definitions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) |
        Where-Object { $handlers -contains $_.Name }
    # HttpListenerResponse has no public constructor, so the handlers are defined with that one
    # parameter type loosened to [object] and given a stand-in that only carries StatusCode.
    foreach ($d in $definitions) {
        $text = $d.Extent.Text -replace '\[System\.Net\.HttpListenerResponse\]', '[object]'
        . ([scriptblock]::Create($text))
    }

    function Send-Json { param($Response, $Data) $script:Sent = $Data }
    function Read-RequestBody { param($Request) $script:Body }
    function Invoke-Handler {
        param([string]$Name, [hashtable]$Body)
        $script:Body = [PSCustomObject]$Body
        $script:Sent = $null
        $response = [PSCustomObject]@{ StatusCode = 200 }
        & $Name $null $response
        [PSCustomObject]@{ StatusCode = $response.StatusCode; Data = $script:Sent }
    }
}

Describe 'GUI single-item change endpoints' {
    BeforeEach {
        $script:driveMappings = @{}
        $script:LogFolder = Join-Path $TestDrive ('logs-' + [guid]::NewGuid().ToString('N'))
        $script:Dir = Join-Path $TestDrive 'HR [old]'
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
        $script:File = Join-Path $script:Dir 'a.txt'
        Set-Content -LiteralPath $script:File -Value 'x'
        Mock Set-Acl { }
        Mock Invoke-AclTool { [PSCustomObject]@{ ExitCode = 0; Output = '' } }
    }

    It 'add-ace backs up, logs, and returns the message with log and backup paths' {
        $r = Invoke-Handler 'Invoke-AddAce' @{ path = $script:Dir; identity = 'BUILTIN\Users'; rights = 'Modify'; type = 'Allow' }

        $r.StatusCode | Should -Be 200
        $r.Data.status | Should -Be 'success'
        $r.Data.message | Should -BeLike "Added Allow Modify for BUILTIN\Users on $([WildcardPattern]::Escape($script:Dir)).*"
        $r.Data.logPath | Should -Exist
        $r.Data.backupPath | Should -Exist
        $r.Data.message | Should -BeLike "*$($r.Data.backupPath)*"
        Should -Invoke Set-Acl -Times 1 -Exactly -ParameterFilter { $LiteralPath -eq $script:Dir }
        @(Import-Csv -LiteralPath $r.Data.logPath).Action | Should -Be 'Add permission'
    }

    It 'remove-ace on a missing folder keeps the 400 error shape and changes nothing' {
        $missing = Join-Path $TestDrive 'missing'
        $r = Invoke-Handler 'Invoke-RemoveAce' @{ path = $missing; identity = 'BUILTIN\Users'; rights = 'Modify' }

        $r.StatusCode | Should -Be 400
        $r.Data.error | Should -BeLike "*$missing does not exist*"
        Should -Invoke Set-Acl -Times 0 -Exactly
    }

    It 'a backup that cannot be written returns an error saying nothing was changed' {
        Mock Export-Csv { throw 'disk full (test)' }
        $r = Invoke-Handler 'Invoke-AddAce' @{ path = $script:Dir; identity = 'BUILTIN\Users'; rights = 'Modify' }

        $r.StatusCode | Should -Be 500
        $r.Data.error | Should -Match '^Could not save a backup of the current permissions.*Nothing was changed\.$'
        Should -Invoke Set-Acl -Times 0 -Exactly
    }

    It 'file-acl/add keeps the batch shape and reports a missing file as skipped' {
        $gone = Join-Path $script:Dir 'gone.txt'
        $r = Invoke-Handler 'Invoke-AddFileAce' @{ paths = @($script:File, $gone); identity = 'BUILTIN\Users'; rights = 'Read' }

        $r.Data.status | Should -Be 'complete'
        ($r.Data.results.status -join ',') | Should -Be 'success,skipped'
        $r.Data.message | Should -BeLike 'Added Allow Read for BUILTIN\Users on 1 of 2 files.*'
        Should -Invoke Set-Acl -Times 1 -Exactly -ParameterFilter { $LiteralPath -eq $script:File }
    }

    It 'file-acl/remove goes through the core' {
        $r = Invoke-Handler 'Invoke-RemoveFileAce' @{ paths = @($script:File); identity = 'BUILTIN\Users'; rights = 'Read'; type = 'Deny' }

        $r.Data.results[0].status | Should -Be 'success'
        $r.Data.message | Should -BeLike 'Removed Deny Read for BUILTIN\Users from *'
    }

    It 'take-ownership of this folder only runs takeown through the wrapper and logs it' {
        $r = Invoke-Handler 'Invoke-TakeOwnership' @{ path = $script:Dir; recursive = $false }

        $r.Data.status | Should -Be 'success'
        $r.Data.message | Should -BeLike "Took ownership of $([WildcardPattern]::Escape($script:Dir)).*"
        Should -Invoke Invoke-AclTool -Times 1 -Exactly -ParameterFilter { $Tool -eq 'takeown' -and $Arguments -contains $script:Dir }
        @(Import-Csv -LiteralPath $r.Data.logPath).Action | Should -Be 'Take ownership'
    }

    It 'file-acl/take-ownership goes through the core' {
        $r = Invoke-Handler 'Invoke-TakeFileOwnership' @{ paths = @($script:File) }

        $r.Data.results[0].status | Should -Be 'success'
        $r.Data.backupPath | Should -Exist
    }

    It 'replicate without "apply recursively" copies through the core and skips a missing target' {
        $source = Join-Path $TestDrive 'source'
        New-Item -ItemType Directory -Path $source -Force | Out-Null
        $missing = Join-Path $TestDrive 'nope'
        $r = Invoke-Handler 'Invoke-ReplicatePermissions' @{ sourcePath = $source; targetPaths = @($script:Dir, $missing); recursive = $false }

        $r.Data.status | Should -Be 'complete'
        ($r.Data.results.status -join ',') | Should -Be 'success,skipped'
        $r.Data.message | Should -BeLike "Permissions copied from $source to 1 of 2 folders.*"
        Should -Invoke Set-Acl -Times 1 -Exactly -ParameterFilter { $LiteralPath -eq $script:Dir }
    }
}
