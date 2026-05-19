#Requires -Version 5.1

# Run with: Invoke-Pester -Path .\DiskSpdDiagnostic\Tests
# Requires Pester 5.x: Install-Module Pester -MinimumVersion 5.0 -Force

BeforeAll {
    $script:ScriptUnderTest = Join-Path $PSScriptRoot '..\Invoke-DiskSpdDiagnostic.ps1'
    # Load the engine functions once for the whole file. Each Describe block runs
    # in its own scope in Pester 5, but functions loaded in the file-level BeforeAll
    # are visible to all of them. Don't add a per-Describe BeforeAll just for this.
    . $script:ScriptUnderTest -ErrorAction SilentlyContinue *> $null
}

Describe 'DiskSpd Diagnostic — script entry' {
    It 'parses without syntax errors' {
        { . $script:ScriptUnderTest -NoUI -Target 'C:\nonexistent-path-for-syntax-check' -Workload QuickSanity -ErrorAction SilentlyContinue } |
            Should -Not -Throw -Because 'syntax errors would surface at parse time'
    }
}

Describe 'Get-DiskSpdWorkloadProfile' {
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

Describe 'Resolve-DiskSpdSettings' {
    It 'returns the profile unchanged when no overrides supplied' {
        $s = Resolve-DiskSpdSettings -ProfileName FSLogixLike -Overrides @{}
        $s.BlockSize  | Should -Be '4K'
        $s.Threads    | Should -Be 4
    }

    It 'applies overrides on top of a preset' {
        $s = Resolve-DiskSpdSettings -ProfileName FSLogixLike -Overrides @{
            Threads         = 16
            DurationSeconds = 120
        }
        $s.Threads          | Should -Be 16
        $s.DurationSeconds  | Should -Be 120
        $s.BlockSize        | Should -Be '4K' -Because 'unmodified keys keep preset values'
    }

    It 'requires every key when ProfileName is Custom' {
        { Resolve-DiskSpdSettings -ProfileName Custom -Overrides @{ BlockSize = '4K' } } |
            Should -Throw -ExpectedMessage "*Profile 'Custom' requires all override keys*"
    }

    It 'accepts a complete Custom override set' {
        $s = Resolve-DiskSpdSettings -ProfileName Custom -Overrides @{
            BlockSize         = '512K'
            Threads           = 8
            QueueDepth        = 32
            WriteRatioPercent = 50
            DurationSeconds   = 45
            TestFileSizeMB    = 2048
            RandomIO          = $true
        }
        $s.BlockSize | Should -Be '512K'
        $s.RandomIO  | Should -BeTrue
    }

    It 'rejects unknown override keys (typo guard)' {
        { Resolve-DiskSpdSettings -ProfileName FSLogixLike -Overrides @{ Treads = 16 } } |
            Should -Throw -ExpectedMessage '*Unknown override key*Treads*'
    }

    It 'does not mutate the caller''s overrides hashtable' {
        $overrides = @{ Threads = 16 }
        $s = Resolve-DiskSpdSettings -ProfileName FSLogixLike -Overrides $overrides
        $s.BlockSize = 'mutated-by-test'
        $overrides.ContainsKey('BlockSize') | Should -BeFalse -Because 'callers may keep using the overrides hashtable after the call'
    }

    It 'returns a fresh hashtable per call (no shared state across calls)' {
        $a = Resolve-DiskSpdSettings -ProfileName FSLogixLike -Overrides @{}
        $b = Resolve-DiskSpdSettings -ProfileName FSLogixLike -Overrides @{}
        $a.Threads = 99
        $b.Threads | Should -Be 4 -Because 'each call must return an independent hashtable'
    }
}

Describe 'Build-DiskSpdArguments' {
    BeforeAll {
        $script:baseSettings = @{
            BlockSize         = '4K'
            Threads           = 4
            QueueDepth        = 8
            WriteRatioPercent = 30
            DurationSeconds   = 30
            TestFileSizeMB    = 1024
            RandomIO          = $true
        }
    }

    It 'emits all required flags in order' {
        $argv = Build-DiskSpdArguments -Settings $script:baseSettings -TestFilePath 'C:\Temp\test.dat'
        $argv | Should -Contain '-b4K'
        $argv | Should -Contain '-t4'
        $argv | Should -Contain '-o8'
        $argv | Should -Contain '-w30'
        $argv | Should -Contain '-d30'
        $argv | Should -Contain '-c1G'
        $argv | Should -Contain '-r'
        $argv | Should -Contain '-Rxml'
        $argv | Should -Contain '-L'
        $argv | Should -Contain '-Sh'
        $argv[-1] | Should -Be 'C:\Temp\test.dat' -Because 'target path must be last'
    }

    It 'omits -r when RandomIO is false (sequential)' {
        $seq = $script:baseSettings.Clone()
        $seq.RandomIO = $false
        $argv = Build-DiskSpdArguments -Settings $seq -TestFilePath 'C:\Temp\test.dat'
        $argv | Should -Not -Contain '-r'
    }

    It 'uses M suffix for sub-GB sizes' {
        $small = $script:baseSettings.Clone()
        $small.TestFileSizeMB = 256
        $argv = Build-DiskSpdArguments -Settings $small -TestFilePath 'C:\Temp\test.dat'
        $argv | Should -Contain '-c256M'
    }

    It 'handles UNC paths' {
        $argv = Build-DiskSpdArguments -Settings $script:baseSettings -TestFilePath '\\FileServer01\Share\test.dat'
        $argv[-1] | Should -Be '\\FileServer01\Share\test.dat'
    }
}
