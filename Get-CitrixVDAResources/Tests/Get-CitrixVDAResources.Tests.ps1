BeforeAll {
    . "$PSScriptRoot\..\Get-CitrixVDAResources.ps1" -LoadFunctionsOnly
}

Describe 'Script loading' {
    It 'dot-sources with -LoadFunctionsOnly without attempting discovery' {
        Get-Command Write-StatusLine -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}
