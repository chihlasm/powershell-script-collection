BeforeAll {
    . "$PSScriptRoot\..\Get-CitrixVDAResources.ps1" -LoadFunctionsOnly
}

Describe 'Script loading' {
    It 'dot-sources with -LoadFunctionsOnly without attempting discovery' {
        Get-Command Write-StatusLine -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-ResourceStatus' {
    It 'returns PASS below the warn threshold' {
        Get-ResourceStatus -Value 79.9 -WarnAt 80 -CriticalAt 90 | Should -Be 'PASS'
    }

    It 'returns WARN exactly at the warn threshold' {
        Get-ResourceStatus -Value 80 -WarnAt 80 -CriticalAt 90 | Should -Be 'WARN'
    }

    It 'returns WARN between warn and critical' {
        Get-ResourceStatus -Value 85 -WarnAt 80 -CriticalAt 90 | Should -Be 'WARN'
    }

    It 'returns FAIL exactly at the critical threshold' {
        Get-ResourceStatus -Value 90 -WarnAt 80 -CriticalAt 90 | Should -Be 'FAIL'
    }

    It 'returns FAIL above the critical threshold' {
        Get-ResourceStatus -Value 99.5 -WarnAt 80 -CriticalAt 90 | Should -Be 'FAIL'
    }

    It 'returns UNKNOWN for a null value rather than throwing' {
        Get-ResourceStatus -Value $null -WarnAt 80 -CriticalAt 90 | Should -Be 'UNKNOWN'
    }

    It 'returns PASS at zero' {
        Get-ResourceStatus -Value 0 -WarnAt 80 -CriticalAt 90 | Should -Be 'PASS'
    }
}

Describe 'Get-WorstStatus' {
    It 'picks FAIL over WARN and PASS' {
        Get-WorstStatus -Statuses @('PASS', 'WARN', 'FAIL') | Should -Be 'FAIL'
    }

    It 'picks WARN over PASS' {
        Get-WorstStatus -Statuses @('PASS', 'WARN', 'PASS') | Should -Be 'WARN'
    }

    It 'returns PASS when everything passes' {
        Get-WorstStatus -Statuses @('PASS', 'PASS') | Should -Be 'PASS'
    }

    It 'ignores UNKNOWN when a real status is present' {
        Get-WorstStatus -Statuses @('UNKNOWN', 'WARN') | Should -Be 'WARN'
    }

    It 'returns UNKNOWN when nothing else is present' {
        Get-WorstStatus -Statuses @('UNKNOWN', 'UNKNOWN') | Should -Be 'UNKNOWN'
    }
}
