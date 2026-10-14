<#
    Regression guard: the AD access report must run on Windows Server 2012 (PowerShell 3.0)
    and 2012 R2 (PowerShell 4.0) as shipped.

    Both scripts once declared '#Requires -Version 5.1', which stopped them before any code
    ran on those servers, although nothing in them needed more than 3.0. The launcher also
    called Compress-Archive (PowerShell 5.0+) with no fallback. These tests catch either
    problem coming back. A parse-time feature like '::new()' or a class definition is the
    worst case, because on PS 3/4 the whole script fails to load and nothing explains why.

    Run with Pester 5:  Invoke-Pester .\AD-GroupMembership-Export\Tests

    https://learn.microsoft.com/powershell/scripting/install/powershell-support-lifecycle
#>

BeforeDiscovery {
    $script:ScriptFiles = @(
        @{ Name = 'Export-ADGroupMembership.ps1' }
        @{ Name = 'Start-AccessReport.ps1' }
    )
}

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot

    function Get-ScriptAst {
        param([string]$Name)
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $script:Root $Name), [ref]$tokens, [ref]$errors)
        if ($errors.Count -gt 0) { throw "Parse errors in ${Name}: $($errors[0].Message)" }
        return $ast
    }

    # Cmdlets that first shipped in PowerShell 5.0/5.1. Calling one unguarded fails at
    # runtime on Server 2012 / 2012 R2.
    $script:Ps5OnlyCommands = @(
        'Compress-Archive', 'Expand-Archive', 'New-TemporaryFile', 'Get-ItemPropertyValue',
        'Get-Clipboard', 'Set-Clipboard', 'Write-Information', 'Format-Hex',
        'ConvertFrom-String', 'Clear-RecycleBin', 'New-Guid'
    )
}

Describe '<Name> stays PowerShell 3.0 compatible' -ForEach $script:ScriptFiles {

    BeforeAll {
        $ast = Get-ScriptAst -Name $Name
    }

    It 'requires no more than PowerShell 3.0' {
        $required = $ast.ScriptRequirements.RequiredPSVersion
        $required | Should -Not -BeNullOrEmpty
        $required | Should -BeLessOrEqual ([version]'3.0')
    }

    It 'defines no classes or enums (PowerShell 5.0 syntax - a parse error on 3/4)' {
        $types = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.TypeDefinitionAst] }, $true)
        @($types).Count | Should -Be 0
    }

    It 'does not call ::new() (PowerShell 5.0 syntax)' {
        $news = $ast.FindAll({
            $n = $args[0]
            $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
            $n.Static -and $n.Member.Extent.Text -eq 'new'
        }, $true)
        @($news | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Extent.Text)" }) |
            Should -BeNullOrEmpty
    }

    It 'has no using statements (PowerShell 5.0 syntax)' {
        @($ast.UsingStatements).Count | Should -Be 0
    }

    It 'calls PowerShell 5-only cmdlets only inside a guarded fallback (New-ReportArchive)' {
        $offenders = $ast.FindAll({
            $c = $args[0]
            $c -is [System.Management.Automation.Language.CommandAst] -and
            $script:Ps5OnlyCommands -contains $c.GetCommandName()
        }, $true) | Where-Object {
            # Walk up to the enclosing function; the only sanctioned home is New-ReportArchive,
            # which checks Get-Command first and falls back to .NET.
            $p = $_.Parent
            while ($p -and -not ($p -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $p = $p.Parent }
            -not ($p -and $p.Name -eq 'New-ReportArchive')
        }
        @($offenders | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Extent.Text)" }) |
            Should -BeNullOrEmpty
    }
}

Describe 'New-ReportArchive' {

    BeforeAll {
        $ast = Get-ScriptAst -Name 'Start-AccessReport.ps1'
        $fn = $ast.Find({
            $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $args[0].Name -eq 'New-ReportArchive'
        }, $true)
        . ([scriptblock]::Create($fn.Extent.Text))
        Add-Type -AssemblyName System.IO.Compression.FileSystem

        function Get-ZipEntryNames {
            param([string]$Path)
            $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
            try { return @($archive.Entries | ForEach-Object { $_.FullName } | Sort-Object) }
            finally { $archive.Dispose() }
        }
    }

    BeforeEach {
        $work   = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $folder = Join-Path $work 'report'
        $null = New-Item -ItemType Directory -Path $folder -Force
        Set-Content -LiteralPath (Join-Path $folder 'ADUserAccess.html') -Value '<html>report</html>'
        Set-Content -LiteralPath (Join-Path $folder 'ADGroupMembership.csv') -Value 'a,b'
        $zip = Join-Path $work 'report.zip'
    }

    It 'zips with the .NET fallback when Compress-Archive does not exist (PS 3.0 / 4.0)' {
        Mock Get-Command -ParameterFilter { $Name -eq 'Compress-Archive' } -MockWith { $null }
        Mock Compress-Archive { throw 'Compress-Archive must not be called on the fallback path' }

        New-ReportArchive -Folder $folder -ZipPath $zip

        Should -Invoke Compress-Archive -Times 0
        (Get-Item -LiteralPath $zip).Length | Should -BeGreaterThan 0
        # Files sit at the zip root, the same layout Compress-Archive '<folder>\*' produces.
        Get-ZipEntryNames -Path $zip | Should -Be @('ADGroupMembership.csv', 'ADUserAccess.html')
    }

    It 'uses Compress-Archive when it exists, with the same layout' -Skip:(-not (Get-Command Compress-Archive -ErrorAction SilentlyContinue)) {
        New-ReportArchive -Folder $folder -ZipPath $zip
        Get-ZipEntryNames -Path $zip | Should -Be @('ADGroupMembership.csv', 'ADUserAccess.html')
    }

    It 'replaces an existing zip on the fallback path instead of failing' {
        # ZipFile.CreateFromDirectory throws IOException if the archive already exists.
        Mock Get-Command -ParameterFilter { $Name -eq 'Compress-Archive' } -MockWith { $null }
        Set-Content -LiteralPath $zip -Value 'stale'

        New-ReportArchive -Folder $folder -ZipPath $zip

        Get-ZipEntryNames -Path $zip | Should -Be @('ADGroupMembership.csv', 'ADUserAccess.html')
    }
}
