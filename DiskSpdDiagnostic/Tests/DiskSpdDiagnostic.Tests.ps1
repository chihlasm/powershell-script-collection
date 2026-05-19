#Requires -Version 5.1

# Run with: Invoke-Pester -Path .\DiskSpdDiagnostic\Tests
# Requires Pester 5.x: Install-Module Pester -MinimumVersion 5.0 -Force

BeforeAll {
    $script:ScriptUnderTest = Join-Path $PSScriptRoot '..\Invoke-DiskSpdDiagnostic.ps1'
}

Describe 'DiskSpd Diagnostic — script entry' {
    It 'parses without syntax errors' {
        { . $script:ScriptUnderTest -NoUI -Target 'C:\nonexistent-path-for-syntax-check' -Workload QuickSanity -ErrorAction SilentlyContinue } |
            Should -Not -Throw -Because 'syntax errors would surface at parse time'
    }
}

Describe 'Get-DiskSpdWorkloadProfile' {
    BeforeAll {
        . $script:ScriptUnderTest -ErrorAction SilentlyContinue *> $null
    }

    It 'returns FSLogix-like profile values' {
        $p = Get-DiskSpdWorkloadProfile -Name FSLogixLike
        $p.BlockSize          | Should -Be '4K'
        $p.Threads            | Should -Be 4
        $p.QueueDepth         | Should -Be 8
        $p.WriteRatioPercent  | Should -Be 30
        $p.DurationSeconds    | Should -Be 30
        $p.TestFileSizeMB     | Should -Be 1024
        $p.RandomIO           | Should -BeTrue
    }

    It 'returns SequentialRead profile values' {
        $p = Get-DiskSpdWorkloadProfile -Name SequentialRead
        $p.BlockSize          | Should -Be '64K'
        $p.WriteRatioPercent  | Should -Be 0
        $p.RandomIO           | Should -BeFalse
    }

    It 'returns Mixed user load profile values' {
        $p = Get-DiskSpdWorkloadProfile -Name MixedUserLoad
        $p.BlockSize          | Should -Be '8K'
        $p.WriteRatioPercent  | Should -Be 20
        $p.DurationSeconds    | Should -Be 60
    }

    It 'returns Quick sanity profile values' {
        $p = Get-DiskSpdWorkloadProfile -Name QuickSanity
        $p.DurationSeconds    | Should -Be 10
        $p.WriteRatioPercent  | Should -Be 0
    }

    It 'returns null (not empty hashtable) for Custom' {
        $p = Get-DiskSpdWorkloadProfile -Name Custom
        ($null -eq $p) | Should -BeTrue -Because 'Resolve-DiskSpdSettings distinguishes $null (use overrides) from @{} (merge nothing)'
    }

    It 'every named preset has all 7 expected keys' {
        $expected = @('BlockSize','Threads','QueueDepth','WriteRatioPercent','DurationSeconds','TestFileSizeMB','RandomIO')
        foreach ($name in @('FSLogixLike','SequentialRead','MixedUserLoad','QuickSanity')) {
            $p = Get-DiskSpdWorkloadProfile -Name $name
            foreach ($key in $expected) {
                $p.ContainsKey($key) | Should -BeTrue -Because "$name must define $key"
            }
        }
    }

    It 'rejects unknown profile names' {
        { Get-DiskSpdWorkloadProfile -Name DoesNotExist } | Should -Throw
    }
}
