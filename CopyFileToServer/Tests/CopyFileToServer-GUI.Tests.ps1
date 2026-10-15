#Requires -Version 5.1
# Pester 5+ tests for CopyFileToServer-GUI.ps1. No window or network needed - the script is
# dot-sourced with -LoadFunctionsOnly, and the copy tests write to a local temp folder (an empty
# -Server skips the reachability check).

BeforeAll {
    $script:ScriptPath = Join-Path $PSScriptRoot '..\CopyFileToServer-GUI.ps1'
    . $script:ScriptPath -LoadFunctionsOnly

    function New-TestFile {
        param([string]$Path, [string]$Content = 'x', [datetime]$Modified = (Get-Date))
        $dir = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        [System.IO.File]::WriteAllText($Path, $Content)
        [System.IO.File]::SetLastWriteTimeUtc($Path, $Modified.ToUniversalTime())
    }
}

Describe 'ConvertTo-ServerNames' {
    It 'splits on new lines, commas, semicolons, spaces and tabs' {
        $r = ConvertTo-ServerNames -Text "SRV01`r`nSRV02, SRV03;SRV04 SRV05`tSRV06"
        $r.Valid | Should -Be @('SRV01', 'SRV02', 'SRV03', 'SRV04', 'SRV05', 'SRV06')
        $r.Invalid.Count | Should -Be 0
    }

    It 'drops duplicates case-insensitively and keeps the first spelling' {
        $r = ConvertTo-ServerNames -Text "Srv01`nSRV01`nsrv01"
        $r.Valid | Should -Be @('Srv01')
    }

    It 'keeps only the server part of a pasted UNC path' {
        $r = ConvertTo-ServerNames -Text '\\fs01.contoso.local\C$\Scripts'
        $r.Valid | Should -Be @('fs01.contoso.local')
    }

    It 'ignores comments, blank lines and quotes' {
        $r = ConvertTo-ServerNames -Text "# prod servers`n`n`"SRV01`"  # main`n'SRV02'"
        $r.Valid | Should -Be @('SRV01', 'SRV02')
    }

    It 'reports names that cannot be server names' {
        $r = ConvertTo-ServerNames -Text 'SRV01 bad!name -leading'
        $r.Valid | Should -Be @('SRV01')
        $r.Invalid | Should -Be @('bad!name', '-leading')
    }

    It 'returns empty lists for empty text' {
        $r = ConvertTo-ServerNames -Text ''
        $r.Valid.Count | Should -Be 0
        $r.Invalid.Count | Should -Be 0
    }
}

Describe 'Test-ServerName' {
    It 'accepts <Name>' -ForEach @(
        @{ Name = 'SRV01' }, @{ Name = 'fs-01.contoso.local' }, @{ Name = '10.0.0.15' }, @{ Name = 'OLD_FILESRV' }
    ) {
        Test-ServerName $Name | Should -BeTrue
    }

    It 'rejects <Name>' -ForEach @(
        @{ Name = '' }, @{ Name = 'two words' }, @{ Name = 'srv\share' }, @{ Name = '-srv' }, @{ Name = 'srv..local' }
    ) {
        Test-ServerName $Name | Should -BeFalse
    }
}

Describe 'ConvertFrom-ServerFile' {
    BeforeEach { $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString()); New-Item -ItemType Directory -Path $script:Tmp | Out-Null }
    AfterEach { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }

    It 'reads a plain text list' {
        $p = Join-Path $script:Tmp 'servers.txt'
        [System.IO.File]::WriteAllText($p, "SRV01`r`nSRV02`r`n")
        (ConvertFrom-ServerFile -Path $p).Valid | Should -Be @('SRV01', 'SRV02')
    }

    It 'uses the DNSHostName column of a Get-ADComputer export' {
        $p = Join-Path $script:Tmp 'computers.csv'
        [System.IO.File]::WriteAllText($p, "`"Name`",`"DNSHostName`",`"Enabled`"`r`n`"SRV01`",`"srv01.contoso.local`",`"True`"`r`n`"SRV02`",`"srv02.contoso.local`",`"True`"`r`n")
        (ConvertFrom-ServerFile -Path $p).Valid | Should -Be @('srv01.contoso.local', 'srv02.contoso.local')
    }

    It 'uses a Name column when there is no host name column' {
        $p = Join-Path $script:Tmp 'list.csv'
        [System.IO.File]::WriteAllText($p, "Name,Site`r`nSRV01,London`r`nSRV02,Leeds`r`n")
        (ConvertFrom-ServerFile -Path $p).Valid | Should -Be @('SRV01', 'SRV02')
    }
}

Describe 'ConvertTo-ShareRelativePath' {
    It 'turns <In> into <Out>' -ForEach @(
        @{ In = 'C$\Scripts'; Out = 'C$\Scripts' }
        @{ In = 'C:\Scripts'; Out = 'C$\Scripts' }
        @{ In = 'd:\Apps\Tool\'; Out = 'D$\Apps\Tool' }
        @{ In = '\\SRV01\C$\Scripts'; Out = 'C$\Scripts' }
        @{ In = 'Software/Installers/'; Out = 'Software\Installers' }
        @{ In = '  "C$\Temp"  '; Out = 'C$\Temp' }
        @{ In = '\Share\\Folder'; Out = 'Share\Folder' }
    ) {
        $r = ConvertTo-ShareRelativePath -Path $In
        $r.Error | Should -BeNullOrEmpty
        $r.Path | Should -Be $Out
    }

    It 'explains the conversion of a drive letter' {
        (ConvertTo-ShareRelativePath -Path 'C:\Temp').Note | Should -Match 'admin share'
    }

    It 'rejects <In>' -ForEach @(
        @{ In = '' }, @{ In = '   ' }, @{ In = 'C$\Te*mp' }, @{ In = 'Share\..\Other' }, @{ In = 'Share\Folder.' }
    ) {
        (ConvertTo-ShareRelativePath -Path $In).Error | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-FriendlyError' {
    # HRESULT 0x8007xxxx carries Win32 error xxxx.
    # https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-
    It 'maps Win32 error <Code>' -ForEach @(
        @{ Code = 53; Pattern = 'network path was not found' }
        @{ Code = 67; Pattern = 'share does not exist' }
        @{ Code = 32; Pattern = 'in use' }
        @{ Code = 112; Pattern = 'full' }
    ) {
        $hr = [int](0x80070000L - 0x100000000L) -bor $Code
        $ex = [System.IO.IOException]::new('raw message', $hr)
        Get-FriendlyError $ex | Should -Match $Pattern
    }

    It 'treats UnauthorizedAccessException as access denied' {
        Get-FriendlyError ([System.UnauthorizedAccessException]::new('Access to the path is denied.')) | Should -Match '^Access denied'
    }

    It 'unwraps the MethodInvocationException PowerShell adds around .NET errors' {
        try { [System.IO.File]::ReadAllText((Join-Path ([System.IO.Path]::GetTempPath()) "$([guid]::NewGuid())\nope.txt")) }
        catch { $err = $_ }
        Get-FriendlyError $err | Should -Not -Match 'Exception calling'
    }

    It 'falls back to the exception message' {
        Get-FriendlyError ([System.InvalidOperationException]::new('something odd')) | Should -Be 'something odd'
    }
}

Describe 'Add-SourceItem' {
    BeforeEach {
        $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-TestFile (Join-Path $script:Tmp 'a\setup.msi')
        New-TestFile (Join-Path $script:Tmp 'b\setup.msi')
        $script:List = [System.Collections.Generic.List[object]]::new()
    }
    AfterEach { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }

    It 'adds a file with its size and a folder' {
        Add-SourceItem -List $script:List -Path (Join-Path $script:Tmp 'a\setup.msi') | Should -BeNullOrEmpty
        Add-SourceItem -List $script:List -Path (Join-Path $script:Tmp 'b') | Should -BeNullOrEmpty
        $script:List.Count | Should -Be 2
        $script:List[0].Size | Should -Be 1
        $script:List[1].IsFolder | Should -BeTrue
    }

    It 'ignores the same path twice' {
        $p = Join-Path $script:Tmp 'a\setup.msi'
        Add-SourceItem -List $script:List -Path $p | Out-Null
        Add-SourceItem -List $script:List -Path $p | Should -BeNullOrEmpty
        $script:List.Count | Should -Be 1
    }

    It 'refuses two items with the same name, which would overwrite each other' {
        Add-SourceItem -List $script:List -Path (Join-Path $script:Tmp 'a\setup.msi') | Out-Null
        Add-SourceItem -List $script:List -Path (Join-Path $script:Tmp 'b\setup.msi') | Should -Match 'already an item'
        $script:List.Count | Should -Be 1
    }

    It 'refuses a whole drive' {
        Add-SourceItem -List $script:List -Path ($env:SystemDrive + '\') | Should -Match 'whole drive'
    }

    It 'reports a missing path' {
        Add-SourceItem -List $script:List -Path (Join-Path $script:Tmp 'missing.txt') | Should -Match 'not found'
    }
}

Describe 'Invoke-ServerCopy' {
    BeforeEach {
        $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:Src = Join-Path $script:Tmp 'src'
        $script:Dst = Join-Path $script:Tmp 'dst\Scripts'
        $old = (Get-Date).AddDays(-2)
        New-TestFile (Join-Path $script:Src 'run.ps1') 'new script' $old.AddDays(1)
        New-TestFile (Join-Path $script:Src 'Tool\tool.exe') 'tool' $old
        New-TestFile (Join-Path $script:Src 'Tool\sub\cfg.ini') 'cfg' $old
        New-Item -ItemType Directory -Path (Join-Path $script:Src 'Tool\empty') -Force | Out-Null
        $script:Sources = [string[]]@((Join-Path $script:Src 'run.ps1'), (Join-Path $script:Src 'Tool'))
    }
    AfterEach {
        Get-ChildItem -LiteralPath $script:Tmp -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Attributes = 'Normal' }
        Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'creates the destination and copies files and folders, keeping folder structure' {
        $r = Invoke-ServerCopy -DestFolder $script:Dst -Sources $script:Sources
        $r.Outcome | Should -Be 'Done'
        $r.Copied | Should -Be 3
        $r.Bytes | Should -Be ('new script'.Length + 'tool'.Length + 'cfg'.Length)
        Test-Path -LiteralPath (Join-Path $script:Dst 'run.ps1') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:Dst 'Tool\sub\cfg.ini') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:Dst 'Tool\empty') -PathType Container | Should -BeTrue
        $r.Message | Should -Match 'Copied 3 files'
    }

    It 'replaces an existing file, even a read-only hidden one' {
        $target = Join-Path $script:Dst 'run.ps1'
        New-TestFile $target 'old'
        [System.IO.File]::SetAttributes($target, 'ReadOnly, Hidden')
        $r = Invoke-ServerCopy -DestFolder $script:Dst -Sources $script:Sources -IfExists replace
        $r.Outcome | Should -Be 'Done'
        [System.IO.File]::ReadAllText($target) | Should -Be 'new script'
    }

    It 'leaves existing files alone with -IfExists skip' {
        $target = Join-Path $script:Dst 'run.ps1'
        New-TestFile $target 'old'
        $r = Invoke-ServerCopy -DestFolder $script:Dst -Sources $script:Sources -IfExists skip
        $r.Skipped | Should -Be 1
        $r.Copied | Should -Be 2
        [System.IO.File]::ReadAllText($target) | Should -Be 'old'
        $r.Message | Should -Match 'Skipped 1 file already there'
    }

    It 'with -IfExists newer replaces only older files' {
        $older = Join-Path $script:Dst 'run.ps1'
        $newer = Join-Path $script:Dst 'Tool\tool.exe'
        New-TestFile $older 'older' (Get-Date).AddDays(-10)
        New-TestFile $newer 'newer on server' (Get-Date)
        $r = Invoke-ServerCopy -DestFolder $script:Dst -Sources $script:Sources -IfExists newer
        [System.IO.File]::ReadAllText($older) | Should -Be 'new script'
        [System.IO.File]::ReadAllText($newer) | Should -Be 'newer on server'
        $r.Skipped | Should -Be 1
    }

    It 'says nothing new was copied when everything is already there' {
        Invoke-ServerCopy -DestFolder $script:Dst -Sources $script:Sources | Out-Null
        $r = Invoke-ServerCopy -DestFolder $script:Dst -Sources $script:Sources -IfExists skip
        $r.Outcome | Should -Be 'Done'
        $r.Message | Should -Match 'Nothing new to copy - 3 files were already there'
    }

    It 'reports a partial copy when one file fails' {
        $locked = Join-Path $script:Dst 'Tool\tool.exe'
        New-TestFile $locked 'locked'
        $fs = [System.IO.File]::Open($locked, 'Open', 'ReadWrite', 'None')
        try { $r = Invoke-ServerCopy -DestFolder $script:Dst -Sources $script:Sources }
        finally { $fs.Dispose() }
        $r.Outcome | Should -Be 'Partial'
        $r.Failed | Should -Be 1
        $r.Copied | Should -Be 2
        $r.Errors[0] | Should -Match 'tool\.exe - The file is in use'
    }

    It 'fails cleanly when the destination cannot be created' {
        $blocker = Join-Path $script:Tmp 'blocker'
        New-TestFile $blocker 'a file where a folder should go'
        $r = Invoke-ServerCopy -DestFolder (Join-Path $blocker 'sub') -Sources $script:Sources
        $r.Outcome | Should -Be 'Failed'
        $r.Copied | Should -Be 0
        $r.Message | Should -Match "Couldn't open or create"
    }

    It 'counts a source that disappeared as a failure' {
        $r = Invoke-ServerCopy -DestFolder $script:Dst -Sources ([string[]]@((Join-Path $script:Src 'gone.txt'), (Join-Path $script:Src 'run.ps1')))
        $r.Outcome | Should -Be 'Partial'
        $r.Errors[0] | Should -Match 'not found on this computer'
    }

    It 'does not start when the run was already stopped' {
        $shared = [hashtable]::Synchronized(@{ Cancel = $true; Progress = [hashtable]::Synchronized(@{}) })
        $r = Invoke-ServerCopy -DestFolder $script:Dst -Sources $script:Sources -Shared $shared -Key 'SRV01'
        $r.Outcome | Should -Be 'Cancelled'
        Test-Path -LiteralPath $script:Dst | Should -BeFalse
    }

    It 'clears its progress entry when finished' {
        $shared = [hashtable]::Synchronized(@{ Cancel = $false; Progress = [hashtable]::Synchronized(@{}) })
        Invoke-ServerCopy -DestFolder $script:Dst -Sources $script:Sources -Shared $shared -Key 'SRV01' | Out-Null
        $shared.Progress['SRV01'] | Should -BeNullOrEmpty
    }
}

Describe 'Get-ReachProblem' {
    It 'explains a name that does not resolve' {
        Get-ReachProblem -ComputerName "no-such-host-$([guid]::NewGuid().ToString('N').Substring(0,8)).invalid" -TimeoutMs 500 |
            Should -Match "Can't find a server"
    }
}

Describe 'Worker runspace' {
    It 'runs Invoke-ServerCopy inside a pool built from the worker functions' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        try {
            New-TestFile (Join-Path $tmp 'src\a.txt') 'a'
            $pool = New-WorkerPool -Max 2
            $ps = [System.Management.Automation.PowerShell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddCommand('Invoke-ServerCopy').AddParameter('DestFolder', (Join-Path $tmp 'dst')).AddParameter('Sources', [string[]]@((Join-Path $tmp 'src\a.txt')))
            $out = $ps.Invoke()
            $ps.Streams.Error.Count | Should -Be 0
            $out[0].Outcome | Should -Be 'Done'
            $ps.Dispose(); $pool.Close()
        }
        finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
