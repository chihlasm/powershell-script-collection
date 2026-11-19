<#
    Pester 5 tests for Build-TestZip.ps1: the zip copied to test servers holds exactly the
    tool's files, never the Reports folder (client data) or the tests.
    Run:  pwsh -File Tests\Invoke-AllTests.ps1 -Path .\Server-EventTimeline\Tests
#>

BeforeAll {
    $script:ToolDir = Split-Path -Parent $PSScriptRoot
    $script:BuildScript = Join-Path $script:ToolDir 'Build-TestZip.ps1'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    function Get-ZipEntries {
        param([string]$Path)
        $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
        try { @($zip.Entries | ForEach-Object { $_.FullName -replace '\\', '/' }) } finally { $zip.Dispose() }
    }
}

Describe 'Build-TestZip.ps1' {
    BeforeAll {
        $script:Out = Join-Path $TestDrive 'dist'
        $script:Result = & $script:BuildScript -OutputPath $script:Out
        $script:Zip = Join-Path $script:Out 'Server-EventTimeline.zip'
        $script:Entries = Get-ZipEntries -Path $script:Zip
    }

    It 'writes Server-EventTimeline.zip to -OutputPath and returns its path' {
        Test-Path -LiteralPath $script:Zip | Should -BeTrue
        "$script:Result" | Should -Be $script:Zip
    }

    It 'puts every script the tool needs, the README and BUILD.txt in a Server-EventTimeline folder' {
        foreach ($f in 'Start-ServerEventTimeline.ps1', 'ServerEventTimeline.Core.ps1', 'ServerEventTimeline.Engine.ps1', 'ServerEventTimeline.ServerList.ps1',
            'ServerEventTimeline.AddServersDialog.ps1', 'ServerEventTimeline.Story.ps1', 'CaseKit.ps1', 'README.md', 'BUILD.txt') {
            $script:Entries | Should -Contain "Server-EventTimeline/$f"
        }
    }

    It 'includes every .ps1 in the tool folder except this build script, so a new file is never left out' {
        $needed = @(Get-ChildItem -LiteralPath $script:ToolDir -Filter *.ps1 -File | Where-Object Name -ne 'Build-TestZip.ps1' | ForEach-Object { "Server-EventTimeline/$($_.Name)" })
        foreach ($n in $needed) { $script:Entries | Should -Contain $n }
    }

    It 'never includes the Reports folder, the tests, the build script or a nested copy' {
        @($script:Entries | Where-Object { $_ -match '/Reports/|/Tests/|Build-TestZip|Server-EventTimeline/Server-EventTimeline/' }).Count | Should -Be 0
        $script:Entries.Count | Should -Be 9
    }

    It 'says in BUILD.txt which commit and when' {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($script:Zip)
        try {
            $reader = New-Object System.IO.StreamReader ($zip.GetEntry('Server-EventTimeline/BUILD.txt').Open())
            $text = $reader.ReadToEnd(); $reader.Dispose()
        }
        finally { $zip.Dispose() }
        $text | Should -Match 'Commit: [0-9a-f]{7,}'
        $text | Should -Match 'Built: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'
    }

    It 'replaces the zip on the next build' {
        $again = & $script:BuildScript -OutputPath $script:Out
        (Get-ZipEntries -Path $again).Count | Should -Be 9
    }
}
