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
    # Guard: the real Invoke-AclTool runs takeown.exe and icacls.exe. Replaced here (same
    # parameters) so a test that forgets to mock it fails instead of changing real owners.
    function Invoke-AclTool {
        param(
            [Parameter(Mandatory)][ValidateSet('icacls', 'takeown')][string]$Tool,
            [Parameter(Mandatory)][string[]]$Arguments
        )
        throw "Invoke-AclTool ($Tool) was called without a mock in a test."
    }
    # Guard: the real Get-DfsTarget asks the DFS client (NetDfsGetClientInfo) and reads the
    # network path. Replaced here (same parameter) so a test that forgets to mock it never
    # reaches a real share; the code under test treats the throw as "could not be found out".
    $script:RealGetDfsTarget = ${function:Get-DfsTarget}
    function Get-DfsTarget {
        param([Parameter(Mandatory)][string]$Path)
        throw "Get-DfsTarget ($Path) was called without a mock in a test."
    }

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
        $script:ChangeLogFolder = Join-Path $TestDrive ('logs-' + [guid]::NewGuid().ToString('N'))
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
        # RemoveAccessRuleAll removes every Deny rule for the account, so the message says so.
        $r.Data.message | Should -BeLike 'Removed all Deny permissions for BUILTIN\Users (asked: Read) from *'
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

    It 'blank entries in paths are dropped, and a selection of only blanks is a 400 with no change' {
        $r = Invoke-Handler 'Invoke-AddFileAce' @{ paths = @('', '  ', $script:File); identity = 'BUILTIN\Users'; rights = 'Read' }
        $r.StatusCode | Should -Be 200
        @($r.Data.results).Count | Should -Be 1
        $r.Data.results[0].status | Should -Be 'success'

        foreach ($name in 'Invoke-AddFileAce', 'Invoke-RemoveFileAce', 'Invoke-TakeFileOwnership') {
            $r = Invoke-Handler $name @{ paths = @('', ' '); identity = 'BUILTIN\Users'; rights = 'Read' }
            $r.StatusCode | Should -Be 400 -Because "$name with only blank paths"
            $r.Data.error | Should -BeLike 'Missing required field*'
        }
        $r = Invoke-Handler 'Invoke-AddFileAce' @{ paths = @(); identity = 'BUILTIN\Users'; rights = 'Read' }
        $r.StatusCode | Should -Be 400
        Should -Invoke Set-Acl -Times 1 -Exactly
    }

    It 'replicate drops blank target lines, and only blanks is a 400 with no change' {
        $source = Join-Path $TestDrive 'source-blank'
        New-Item -ItemType Directory -Path $source -Force | Out-Null
        $r = Invoke-Handler 'Invoke-ReplicatePermissions' @{ sourcePath = $source; targetPaths = @('', $script:Dir); recursive = $false }
        @($r.Data.results).Count | Should -Be 1

        $r = Invoke-Handler 'Invoke-ReplicatePermissions' @{ sourcePath = $source; targetPaths = @(' '); recursive = $false }
        $r.StatusCode | Should -Be 400
        $r.Data.error | Should -Be 'Missing required field: targetPaths'
        Should -Invoke Set-Acl -Times 1 -Exactly
    }
}

Describe 'Change result JSON shapes' {
    BeforeAll {
        function New-Row {
            param([string]$Target, [string]$Result, [string]$ErrorText = '', [string]$OldValue = 'O:BAD:(A;;FA;;;BA)',
                [string]$NewValue = '', [string]$BackupFile = '')
            New-PermissionChangeEntry -Action 'Add permission' -Target $Target -ItemType 'Folder' -Detail 'Allow Modify for BUILTIN\Users' `
                -OldValue $OldValue -NewValue $NewValue -Result $Result -ErrorText $ErrorText -BackupFile $BackupFile
        }
        function Invoke-Send {
            param([string]$Name, [scriptblock]$Change)
            $script:Sent = $null
            $response = [PSCustomObject]@{ StatusCode = 200 }
            & $Name $response $Change
            [PSCustomObject]@{ StatusCode = $response.StatusCode; Data = $script:Sent }
        }
    }
    BeforeEach {
        $script:ChangeLogFolder = Join-Path $TestDrive ('shapes-' + [guid]::NewGuid().ToString('N'))
        $script:Backup = Join-Path $TestDrive 'backup.csv'
    }

    It 'success: status, message, logPath, backupPath, unrestorable 0' {
        $r = Invoke-Send 'Send-SingleChangeResult' { New-Row 'C:\a' 'Done' -NewValue 'O:BAD:' -BackupFile $script:Backup }
        $r.StatusCode | Should -Be 200
        $r.Data.status | Should -Be 'success'
        $r.Data.message | Should -BeLike 'Added Allow Modify for BUILTIN\Users on C:\a.*'
        $r.Data.logPath | Should -Exist
        $r.Data.backupPath | Should -Be $script:Backup
        $r.Data.unrestorable | Should -Be 0
        $r.Data.Keys | Should -Not -Contain 'error'
    }

    It 'partial batch: complete, one result per item, message counts the failure' {
        $r = Invoke-Send 'Send-BatchChangeResult' {
            New-Row 'C:\a' 'Done' -NewValue 'O:BAD:' -BackupFile $script:Backup
            New-Row 'C:\b' 'Failed' -ErrorText 'Access to the path is denied' -NewValue 'O:BAD:(A;;FA;;;BA)' -BackupFile $script:Backup
        }
        $r.Data.status | Should -Be 'complete'
        ($r.Data.results.status -join ',') | Should -Be 'success,error'
        $r.Data.results[1].message | Should -Be 'Access to the path is denied'
        $r.Data.message | Should -BeLike '*1 of 2 folders.*1 failed. First error (C:\b): You do not have permission to change this item.*'
        $r.Data.logPath | Should -Exist
    }

    It 'all failed: a single folder is a 500 with error = message; a batch is complete with every result an error' {
        $r = Invoke-Send 'Send-SingleChangeResult' { New-Row 'C:\a' 'Failed' -ErrorText 'Access is denied.' -NewValue 'O:BAD:(A;;FA;;;BA)' }
        $r.StatusCode | Should -Be 500
        $r.Data.error | Should -Be $r.Data.message
        $r.Data.error | Should -BeLike 'Add permission failed on C:\a: You do not have permission*Nothing was changed.*'

        $r = Invoke-Send 'Send-BatchChangeResult' {
            New-Row 'C:\a' 'Failed' -ErrorText 'x' -NewValue 'O:BAD:(A;;FA;;;BA)'
            New-Row 'C:\b' 'Failed' -ErrorText 'y' -NewValue 'O:BAD:(A;;FA;;;BA)'
        }
        ($r.Data.results.status -join ',') | Should -Be 'error,error'
        $r.Data.message | Should -BeLike 'Nothing was changed. 2 failed.*'
    }

    It 'log failed: logPath is null and the message says the change log could not be written' {
        Mock Write-PermissionChangeLog { $null }
        $r = Invoke-Send 'Send-SingleChangeResult' { New-Row 'C:\a' 'Done' -NewValue 'O:BAD:' -BackupFile $script:Backup }
        $r.Data.status | Should -Be 'success'
        $r.Data.logPath | Should -BeNullOrEmpty
        $r.Data.message | Should -BeLike "*the change log could not be written to $($script:ChangeLogFolder)*$($script:Backup)*"
    }

    It 'backup failed: 500 and the error is the backup text' {
        $text = Get-BackupFailureText -LogFolder $script:ChangeLogFolder -Reason 'disk full'
        $r = Invoke-Send 'Send-SingleChangeResult' { New-Row 'C:\a' 'Failed' -ErrorText $text }
        $r.StatusCode | Should -Be 500
        $r.Data.error | Should -Be $text
        $r.Data.backupPath | Should -BeNullOrEmpty
    }

    It 'unrestorable: counts changed items whose permissions could not be read first' {
        $r = Invoke-Send 'Send-BatchChangeResult' { New-Row 'C:\a' 'Done' -OldValue 'Could not read' -NewValue 'O:BAD:' -BackupFile $script:Backup }
        $r.Data.unrestorable | Should -Be 1
        $r.Data.message | Should -BeLike '*cannot be restored from this backup*'
    }

    It 'zero items: complete, no results, nothing was changed, nothing logged' {
        $r = Invoke-Send 'Send-BatchChangeResult' { }
        $r.Data.status | Should -Be 'complete'
        @($r.Data.results).Count | Should -Be 0
        $r.Data.message | Should -Be 'Nothing was changed.'
        $r.Data.logPath | Should -BeNullOrEmpty
    }
}
