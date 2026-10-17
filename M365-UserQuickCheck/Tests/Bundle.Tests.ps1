<#
    SQ-002 AC29: the new tool is in the service-desk bundle and the indexes.
    Static text checks only; nothing is built or run.

    Run:  Invoke-Pester .\M365-UserQuickCheck\Tests\Bundle.Tests.ps1
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    function Read-Repo([string]$Relative) {
        $p = Join-Path $script:RepoRoot $Relative
        if (Test-Path -LiteralPath $p) { [System.IO.File]::ReadAllText($p) } else { '' }
    }
}

Describe 'AC29 bundle and index' {
    It 'AC29_BundleAndIndex: Build-ServiceDeskToolkit.ps1 manifest includes M365-UserQuickCheck as a folder entry' {
        $build = Read-Repo 'ServiceDesk-Toolkit\Build-ServiceDeskToolkit.ps1'
        $build | Should -Match "(?m)^\s*@\{\s*Source\s*=\s*'M365-UserQuickCheck'\s*;\s*Destination\s*=\s*'M365-UserQuickCheck'\s*\}"
    }

    It 'AC29_BundleAndIndex: START HERE has a "Can''t sign in to Microsoft 365 / Outlook / Teams" row pointing to it, Changes anything? No' {
        $readme = Read-Repo 'ServiceDesk-Toolkit\README.md'
        $row = @(($readme -split "`r?`n") | Where-Object { $_ -match "Can['’]t sign in to Microsoft 365 / Outlook / Teams" })
        $row.Count | Should -Be 1
        $row[0] | Should -Match 'M365-UserQuickCheck'
        $row[0] | Should -Match '\|\s*No\s*\|\s*$'
    }

    It 'AC29_BundleAndIndex: the root README index lists the folder' {
        (Read-Repo 'README.md') | Should -Match '\[M365-UserQuickCheck\]\(M365-UserQuickCheck/\)'
    }

    It 'AC29_BundleAndIndex: .gitignore keeps the saved reports out of git (Customer data)' {
        (Read-Repo '.gitignore') | Should -Match '(?m)^M365-UserQuickCheck/\*\*/M365UserCheck_\*\s*$'
    }

    It 'AC29_BundleAndIndex: the tool folder has a README' {
        Test-Path -LiteralPath (Join-Path $script:RepoRoot 'M365-UserQuickCheck\README.md') | Should -BeTrue
    }
}
