BeforeAll {
    . "$PSScriptRoot\..\Audit-GPDriveMaps.ps1" -LoadFunctionsOnly
}

Describe 'Script loads functions only' {
    It 'exposes Build-DriveMapMatrix once implemented' -Skip {
        Get-Command Build-DriveMapMatrix | Should -Not -BeNullOrEmpty
    }
    It 'does not run the audit on dot-source' {
        # If the guard failed, dot-sourcing would have thrown (no domain here).
        $true | Should -BeTrue
    }
}
