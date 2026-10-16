#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
    Run with Pester 5:  Invoke-Pester .\AD-LockoutDiagnostics\Tests\Build-LockoutToolkit.Tests.ps1
    Builds the zip into a temporary folder from the real repository (needs git).
#>

BeforeAll {
    $script:Build = Join-Path $PSScriptRoot '..\Build-LockoutToolkit.ps1'
    $script:Out = Join-Path ([System.IO.Path]::GetTempPath()) ("LockoutBuildTest_" + [guid]::NewGuid().ToString('N'))
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:Build -OutputPath $script:Out -Force *> $null
    $script:ExitCode = $LASTEXITCODE
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $script:Entries = @()
    $zip = Join-Path $script:Out 'AD-Lockout-Diagnostics.zip'
    if (Test-Path -LiteralPath $zip) {
        $z = [System.IO.Compression.ZipFile]::OpenRead($zip)
        try { $script:Entries = @($z.Entries | ForEach-Object { $_.FullName }) } finally { $z.Dispose() }
    }
}

AfterAll {
    Remove-Item -LiteralPath $script:Out -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Build-LockoutToolkit' {
    It 'builds the zip' {
        $script:ExitCode | Should -Be 0
        $script:Entries.Count | Should -BeGreaterThan 0
    }

    It 'includes every companion script the investigation resolves' {
        # The hand-built zip silently lacked steps, which the investigation then skipped.
        $src = Get-Content -Raw (Join-Path $PSScriptRoot '..\Invoke-ADLockoutInvestigation.ps1')
        $companions = @([regex]::Matches($src, "Resolve-CompanionScript -FileName '([^']+)'") | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
        $companions.Count | Should -BeGreaterThan 0
        foreach ($c in $companions) { $script:Entries | Should -Contain $c }
    }

    It 'includes the device timeline and the reference data' {
        # Regression: the zip it replaced dated from 2026-08-27 and had no timeline step.
        $script:Entries | Should -Contain 'Get-SourceMachineActivity.ps1'
        $script:Entries | Should -Contain 'LockoutReference.psd1'
        $script:Entries | Should -Contain 'Invoke-ADLockoutInvestigation.ps1'
    }

    It 'is flat - no folders, so companions are found beside the investigation' {
        @($script:Entries | Where-Object { $_ -match '[\\/]' }).Count | Should -Be 0
    }

    It 'leaves out tests, zips and the build script itself' {
        @($script:Entries | Where-Object { $_ -match '\.Tests\.ps1$|\.zip$' }).Count | Should -Be 0
        $script:Entries | Should -Not -Contain 'Build-LockoutToolkit.ps1'
    }
}
