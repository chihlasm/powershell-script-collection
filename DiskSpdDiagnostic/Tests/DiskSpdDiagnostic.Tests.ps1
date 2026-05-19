#Requires -Version 5.1

# Run with: Invoke-Pester -Path .\DiskSpdDiagnostic\Tests
# Requires Pester 5.x: Install-Module Pester -MinimumVersion 5.0 -Force

BeforeAll {
    $script:ScriptUnderTest = Join-Path $PSScriptRoot '..\Invoke-DiskSpdDiagnostic.ps1'
}

Describe 'DiskSpd Diagnostic — script entry' {
    It 'parses without syntax errors' {
        { . $script:ScriptUnderTest -NoUI -Target 'C:\nonexistent-path-for-syntax-check' -Profile QuickSanity -ErrorAction SilentlyContinue } |
            Should -Not -Throw -Because 'syntax errors would surface at parse time'
    }
}
