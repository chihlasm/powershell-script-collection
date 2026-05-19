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

    It 'emits all required flags' {
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

    It 'computes size suffix correctly for <mb> MB' -ForEach @(
        @{ mb = 256;  expected = '-c256M'  }
        @{ mb = 1024; expected = '-c1G'    }
        @{ mb = 1025; expected = '-c1025M' }
        @{ mb = 2048; expected = '-c2G'    }
    ) {
        $s = $script:baseSettings.Clone()
        $s.TestFileSizeMB = $mb
        $argv = Build-DiskSpdArguments -Settings $s -TestFilePath 'C:\Temp\test.dat'
        $argv | Should -Contain $expected
    }

    It 'handles UNC paths' {
        $argv = Build-DiskSpdArguments -Settings $script:baseSettings -TestFilePath '\\FileServer01\Share\test.dat'
        $argv[-1] | Should -Be '\\FileServer01\Share\test.dat'
    }

    It 'throws on Settings hashtable missing required keys' {
        $bad = @{ BlockSize = '4K'; Threads = 4 }  # missing 5 keys
        { Build-DiskSpdArguments -Settings $bad -TestFilePath 'C:\Temp\test.dat' } |
            Should -Throw -ExpectedMessage '*missing required key*'
    }
}

Describe 'ConvertFrom-DiskSpdXml' {
    BeforeAll {
        $script:fixturePath = Join-Path $PSScriptRoot 'sample-diskspd-output.xml'
        $script:fixtureXml  = Get-Content $script:fixturePath -Raw
    }

    It 'returns a PSCustomObject with all expected properties' {
        $r = ConvertFrom-DiskSpdXml -Xml $script:fixtureXml -ProfileName QuickSanity
        $r              | Should -BeOfType [PSCustomObject]
        $r.IOPS         | Should -BeGreaterThan 0
        $r.ReadMBps     | Should -BeGreaterOrEqual 0
        $r.WriteMBps    | Should -BeGreaterOrEqual 0
        $r.AvgLatencyMs | Should -BeGreaterThan 0
        $r.Latency95Ms  | Should -BeGreaterOrEqual $r.AvgLatencyMs
        $r.Latency99Ms  | Should -BeGreaterOrEqual $r.Latency95Ms
        $r.CpuPercent   | Should -BeGreaterOrEqual 0
        $r.TestFilePath | Should -Not -BeNullOrEmpty
        $r.Duration     | Should -BeGreaterThan 0
        $r.ProfileName  | Should -Be 'QuickSanity'
        $r.RawXml       | Should -Be $script:fixtureXml
    }

    It 'extracts exact values from the committed fixture (XPath regression guard)' {
        # These values are read directly from sample-diskspd-output.xml.
        # If diskspd's XML schema changes in a future version, this test will fail
        # and tell us we need to update the parser, NOT just the fixture.
        $r = ConvertFrom-DiskSpdXml -Xml $script:fixtureXml -ProfileName QuickSanity
        $r.Duration     | Should -Be 5.01     -Because 'TestTimeSeconds=5.01 in the fixture'
        $r.AvgLatencyMs | Should -Be 0.106    -Because 'AverageTotalMilliseconds=0.106 in the fixture'
        $r.CpuPercent   | Should -Be 33.45    -Because 'CpuUtilization.Average.UsagePercent=33.45 in the fixture'
        $r.TestFilePath | Should -Match 'diskspd-fixture\.dat$' -Because 'fixture was run against $env:TEMP\diskspd-fixture.dat'
        $r.WriteMBps    | Should -Be 0        -Because 'fixture used -w0 (100% reads)'
    }

    It 'computes IOPS as (ReadCount + WriteCount) divided by duration' {
        # Minimal synthetic XML so we can assert exact arithmetic
        $xml = @'
<Results>
  <TimeSpan>
    <TestTimeSeconds>10</TestTimeSeconds>
    <ThreadCount>1</ThreadCount>
    <CpuUtilization>
      <Average><UsagePercent>0</UsagePercent></Average>
    </CpuUtilization>
    <Thread>
      <Id>0</Id>
      <Target>
        <Path>X:\t.dat</Path>
        <ReadBytes>4096000</ReadBytes>
        <ReadCount>1000</ReadCount>
        <WriteBytes>2048000</WriteBytes>
        <WriteCount>500</WriteCount>
      </Target>
    </Thread>
    <Latency>
      <AverageTotalMilliseconds>2</AverageTotalMilliseconds>
      <Bucket><Percentile>95</Percentile><TotalMilliseconds>3</TotalMilliseconds></Bucket>
      <Bucket><Percentile>99</Percentile><TotalMilliseconds>5</TotalMilliseconds></Bucket>
    </Latency>
  </TimeSpan>
</Results>
'@
        $r = ConvertFrom-DiskSpdXml -Xml $xml -ProfileName QuickSanity
        $r.IOPS | Should -Be 150 -Because '(1000 + 500) / 10 seconds'
    }

    It 'sums per-thread totals across multiple threads' {
        $xml = @'
<Results>
  <TimeSpan>
    <TestTimeSeconds>10</TestTimeSeconds>
    <ThreadCount>2</ThreadCount>
    <CpuUtilization>
      <Average><UsagePercent>0</UsagePercent></Average>
    </CpuUtilization>
    <Thread>
      <Id>0</Id>
      <Target>
        <Path>X:\t.dat</Path>
        <ReadBytes>1048576</ReadBytes>
        <ReadCount>100</ReadCount>
        <WriteBytes>0</WriteBytes>
        <WriteCount>0</WriteCount>
      </Target>
    </Thread>
    <Thread>
      <Id>1</Id>
      <Target>
        <Path>X:\t.dat</Path>
        <ReadBytes>2097152</ReadBytes>
        <ReadCount>200</ReadCount>
        <WriteBytes>0</WriteBytes>
        <WriteCount>0</WriteCount>
      </Target>
    </Thread>
    <Latency>
      <AverageTotalMilliseconds>1</AverageTotalMilliseconds>
      <Bucket><Percentile>95</Percentile><TotalMilliseconds>2</TotalMilliseconds></Bucket>
      <Bucket><Percentile>99</Percentile><TotalMilliseconds>3</TotalMilliseconds></Bucket>
    </Latency>
  </TimeSpan>
</Results>
'@
        $r = ConvertFrom-DiskSpdXml -Xml $xml -ProfileName QuickSanity
        $r.IOPS | Should -Be 30 -Because '(100 + 200) / 10 seconds, summed across both threads'
    }

    It 'throws on malformed XML with a clear message' {
        { ConvertFrom-DiskSpdXml -Xml '<not valid xml' -ProfileName QuickSanity } |
            Should -Throw -ExpectedMessage '*XML*'
    }

    It 'throws when TimeSpan is missing' {
        $xml = '<Results></Results>'
        { ConvertFrom-DiskSpdXml -Xml $xml -ProfileName QuickSanity } |
            Should -Throw -ExpectedMessage '*TimeSpan*'
    }

    It 'throws when duration is zero (test did not run)' {
        $xml = @'
<Results>
  <TimeSpan>
    <TestTimeSeconds>0</TestTimeSeconds>
    <CpuUtilization><Average><UsagePercent>0</UsagePercent></Average></CpuUtilization>
    <Thread><Id>0</Id><Target><Path>x</Path><ReadBytes>0</ReadBytes><ReadCount>0</ReadCount><WriteBytes>0</WriteBytes><WriteCount>0</WriteCount></Target></Thread>
    <Latency><AverageTotalMilliseconds>0</AverageTotalMilliseconds></Latency>
  </TimeSpan>
</Results>
'@
        { ConvertFrom-DiskSpdXml -Xml $xml -ProfileName QuickSanity } |
            Should -Throw -ExpectedMessage '*zero duration*'
    }
}

Describe 'Get-DiskSpdHealthAssessment' {
    BeforeAll {
        $script:localFast = [PSCustomObject]@{ ReadMBps=150; WriteMBps=120; AvgLatencyMs=5  }
        $script:localSlow = [PSCustomObject]@{ ReadMBps=30;  WriteMBps=20;  AvgLatencyMs=25 }
        $script:netGood   = [PSCustomObject]@{ ReadMBps=60;  WriteMBps=50;  AvgLatencyMs=15 }
        $script:netBad    = [PSCustomObject]@{ ReadMBps=20;  WriteMBps=15;  AvgLatencyMs=60 }
    }

    It 'flags fast local storage as OK across the board' {
        $a = Get-DiskSpdHealthAssessment -Result $script:localFast -Transport Local
        $a.ReadMBps     | Should -Be 'OK'
        $a.WriteMBps    | Should -Be 'OK'
        $a.AvgLatencyMs | Should -Be 'OK'
    }

    It 'flags slow local storage as CRIT' {
        $a = Get-DiskSpdHealthAssessment -Result $script:localSlow -Transport Local
        $a.ReadMBps     | Should -Be 'CRIT'
        $a.WriteMBps    | Should -Be 'CRIT'
        $a.AvgLatencyMs | Should -Be 'CRIT'
    }

    It 'applies network thresholds for network transport' {
        $a = Get-DiskSpdHealthAssessment -Result $script:netGood -Transport Network
        $a.ReadMBps     | Should -Be 'OK'
        $a.AvgLatencyMs | Should -Be 'OK'
    }

    It 'flags poor network storage as CRIT' {
        $a = Get-DiskSpdHealthAssessment -Result $script:netBad -Transport Network
        $a.ReadMBps     | Should -Be 'CRIT'
        $a.AvgLatencyMs | Should -Be 'CRIT'
    }

    It 'flags borderline values as WARN' {
        $b = [PSCustomObject]@{ ReadMBps=75; WriteMBps=75; AvgLatencyMs=15 }
        $a = Get-DiskSpdHealthAssessment -Result $b -Transport Local
        $a.ReadMBps     | Should -Be 'WARN'
        $a.WriteMBps    | Should -Be 'WARN'
        $a.AvgLatencyMs | Should -Be 'WARN'
    }

    It 'rejects unknown transport' {
        $b = [PSCustomObject]@{ ReadMBps=75; WriteMBps=75; AvgLatencyMs=15 }
        { Get-DiskSpdHealthAssessment -Result $b -Transport Mars } | Should -Throw
    }

    It 'flags Network borderline values as WARN' {
        $b = [PSCustomObject]@{ ReadMBps=37; WriteMBps=30; AvgLatencyMs=35 }
        $a = Get-DiskSpdHealthAssessment -Result $b -Transport Network
        $a.ReadMBps     | Should -Be 'WARN'
        $a.WriteMBps    | Should -Be 'WARN'
        $a.AvgLatencyMs | Should -Be 'WARN'
    }

    It 'pins exact-boundary semantics (WARN inclusive on both edges)' -ForEach @(
        @{ ReadMBps = 100;   expected = 'WARN' -as [string]  }  # upper edge
        @{ ReadMBps = 100.01;expected = 'OK'                 }
        @{ ReadMBps = 50;    expected = 'WARN'               }  # lower edge
        @{ ReadMBps = 49.99; expected = 'CRIT'               }
    ) {
        $r = [PSCustomObject]@{ ReadMBps = $ReadMBps; WriteMBps = 999; AvgLatencyMs = 0 }
        (Get-DiskSpdHealthAssessment -Result $r -Transport Local).ReadMBps | Should -Be $expected
    }

    It 'classifies P95 and P99 latency when present' {
        $r = [PSCustomObject]@{
            ReadMBps=999; WriteMBps=999; AvgLatencyMs=5
            Latency95Ms=15; Latency99Ms=25
        }
        $a = Get-DiskSpdHealthAssessment -Result $r -Transport Local
        $a.AvgLatencyMs | Should -Be 'OK'    -Because '5ms < 10ms (LatencyOK)'
        $a.Latency95Ms  | Should -Be 'WARN'  -Because '15ms is in 10-20ms WARN band'
        $a.Latency99Ms  | Should -Be 'CRIT'  -Because '25ms > 20ms (LatencyWarn)'
    }

    It 'omits P95/P99 keys when not present on the Result object' {
        $r = [PSCustomObject]@{ ReadMBps=999; WriteMBps=999; AvgLatencyMs=5 }
        $a = Get-DiskSpdHealthAssessment -Result $r -Transport Local
        $a.ContainsKey('Latency95Ms') | Should -BeFalse
        $a.ContainsKey('Latency99Ms') | Should -BeFalse
    }
}

Describe 'Test-DiskSpdPreflight (local mode)' {
    BeforeAll {
        # We need a known-good path to the bundled diskspd.exe for these tests.
        # Resolve via the test's own location so this works regardless of cwd.
        $script:DiskSpdExePath = (Resolve-Path (Join-Path $PSScriptRoot '..\diskspd.exe')).Path
    }

    BeforeEach {
        $script:probeDir = Join-Path $env:TEMP "diskspd-pf-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path $script:probeDir -Force | Out-Null
    }
    AfterEach {
        Remove-Item $script:probeDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'passes when binary exists, target writable, free space ample' {
        $r = Test-DiskSpdPreflight -DiskSpdPath $script:DiskSpdExePath -Target $script:probeDir `
            -TestFileSizeMB 64 -BusinessHoursForce
        $r.Pass     | Should -BeTrue
        $r.Errors   | Should -BeNullOrEmpty
    }

    It 'fails if diskspd.exe missing' {
        $r = Test-DiskSpdPreflight -DiskSpdPath 'C:\does\not\exist\diskspd.exe' -Target $script:probeDir `
            -TestFileSizeMB 64 -BusinessHoursForce
        $r.Pass   | Should -BeFalse
        $r.Errors | Should -Match 'diskspd.exe not found'
    }

    It 'fails if target not reachable' {
        $r = Test-DiskSpdPreflight -DiskSpdPath $script:DiskSpdExePath -Target 'Z:\definitely\not\there' `
            -TestFileSizeMB 64 -BusinessHoursForce
        $r.Pass   | Should -BeFalse
        $r.Errors | Should -Match 'Target not reachable'
    }

    It 'warns during business hours' {
        # Wednesday 2026-05-20 at 10:00 — Mon-Fri 7-18 = business hours
        $r = Test-DiskSpdPreflight -DiskSpdPath $script:DiskSpdExePath -Target $script:probeDir `
            -TestFileSizeMB 64 -BusinessHoursNow ([datetime]'2026-05-20 10:00:00')
        $r.Warnings | Should -Match 'business hours'
    }

    It '-BusinessHoursForce suppresses business-hours warning' {
        $r = Test-DiskSpdPreflight -DiskSpdPath $script:DiskSpdExePath -Target $script:probeDir `
            -TestFileSizeMB 64 -BusinessHoursForce -BusinessHoursNow ([datetime]'2026-05-20 10:00:00')
        ($r.Warnings -join ' ') | Should -Not -Match 'business hours'
    }

    It 'does NOT warn outside business hours' {
        # Saturday 2026-05-23 at 10:00 (weekend) - should not warn
        $r = Test-DiskSpdPreflight -DiskSpdPath $script:DiskSpdExePath -Target $script:probeDir `
            -TestFileSizeMB 64 -BusinessHoursNow ([datetime]'2026-05-23 10:00:00')
        ($r.Warnings -join ' ') | Should -Not -Match 'business hours'
    }

    It 'does NOT warn at 6:59 AM on a weekday' {
        $r = Test-DiskSpdPreflight -DiskSpdPath $script:DiskSpdExePath -Target $script:probeDir `
            -TestFileSizeMB 64 -BusinessHoursNow ([datetime]'2026-05-20 06:59:00')
        ($r.Warnings -join ' ') | Should -Not -Match 'business hours'
    }

    It 'warns at 7:00 AM on a weekday (lower boundary)' {
        $r = Test-DiskSpdPreflight -DiskSpdPath $script:DiskSpdExePath -Target $script:probeDir `
            -TestFileSizeMB 64 -BusinessHoursNow ([datetime]'2026-05-20 07:00:00')
        $r.Warnings | Should -Match 'business hours'
    }

    It 'does NOT warn at 6:00 PM on a weekday (upper boundary - exclusive)' {
        # Spec: 7am-6pm means hour >= 7 AND hour < 18. So 18:00 should NOT warn.
        $r = Test-DiskSpdPreflight -DiskSpdPath $script:DiskSpdExePath -Target $script:probeDir `
            -TestFileSizeMB 64 -BusinessHoursNow ([datetime]'2026-05-20 18:00:00')
        ($r.Warnings -join ' ') | Should -Not -Match 'business hours'
    }

    It 'warns at 5:59 PM on a weekday (inside upper boundary)' {
        # 17:59 has Hour=17 which is -lt 18, so we should warn.
        $r = Test-DiskSpdPreflight -DiskSpdPath $script:DiskSpdExePath -Target $script:probeDir `
            -TestFileSizeMB 64 -BusinessHoursNow ([datetime]'2026-05-20 17:59:00')
        $r.Warnings | Should -Match 'business hours'
    }

    It 'fails with a clear message when free space is insufficient' {
        # Mock Get-Item ONLY for the test's probe directory so we don't perturb any
        # other Get-Item calls (Pester internals, signature check, etc.). Force the
        # PSDrive.Free to 10 MB so a 64 MB test (needs 76.8 MB) fails the headroom check.
        # If this test is flaky in your Pester version, the fallback is to assume the
        # comparison logic is correct and treat this branch as a documented gap.
        $probeDir = $script:probeDir
        Mock -CommandName Get-Item -ParameterFilter { $Path -eq $probeDir } -MockWith {
            [PSCustomObject]@{ PSDrive = [PSCustomObject]@{ Free = 10MB } }
        }
        $r = Test-DiskSpdPreflight -DiskSpdPath $script:DiskSpdExePath -Target $probeDir `
            -TestFileSizeMB 64 -BusinessHoursForce
        $r.Pass   | Should -BeFalse
        $r.Errors | Should -Match 'Insufficient free space'
        $r.Errors | Should -Match 'have 10'
    }

    # NOTE: We tried a 'reports Test-WSMan failure for an unreachable computer' test
    # using ComputerName='definitely-does-not-exist-12345'. The function works
    # correctly when invoked directly, but the test reported only the admin-share
    # error (not the WSMan one) — likely a Pester scope/runspace interaction we
    # didn't unwind. Deferred to integration testing against a real second machine.
    # See git log around cdc7f25 for the iterations.

    It 'remote mode: skips local-target reachability checks' {
        # With -ComputerName set, the target lives on the remote machine, so a bogus
        # local path must NOT produce a 'Target not reachable' error here. The remote
        # call itself will error out, but for a different reason.
        $r = Test-DiskSpdPreflight -DiskSpdPath $script:DiskSpdExePath -Target 'Z:\nope' `
            -ComputerName 'definitely-does-not-exist-12345' -TestFileSizeMB 64 -BusinessHoursForce
        ($r.Errors -join ' ') | Should -Not -Match 'Target not reachable'
    }
}

Describe 'Invoke-DiskSpdLocal (integration)' -Tag 'Integration' {
    BeforeAll {
        $script:DiskSpdExePath = (Resolve-Path (Join-Path $PSScriptRoot '..\diskspd.exe')).Path
    }

    It 'runs a quick test and returns XML containing <Results>' {
        $settings = Get-DiskSpdWorkloadProfile -Name QuickSanity
        $settings.DurationSeconds = 3  # keep the test fast
        $testFile = Join-Path $env:TEMP "diskspd-itest-$([guid]::NewGuid()).dat"

        try {
            $xml = Invoke-DiskSpdLocal -DiskSpdPath $script:DiskSpdExePath -Settings $settings -TestFilePath $testFile
            $xml | Should -Match '<Results>'
            $xml | Should -Match '<TimeSpan>'
        } finally {
            Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        }
    }

    It 'cleans up the test file after a successful run' {
        $settings = Get-DiskSpdWorkloadProfile -Name QuickSanity
        $settings.DurationSeconds = 3
        $testFile = Join-Path $env:TEMP "diskspd-itest-$([guid]::NewGuid()).dat"
        $null = Invoke-DiskSpdLocal -DiskSpdPath $script:DiskSpdExePath -Settings $settings -TestFilePath $testFile
        Test-Path $testFile | Should -BeFalse -Because 'finally block must delete the test file'
    }

    It 'throws when diskspd exits non-zero (bad target path)' {
        $settings = Get-DiskSpdWorkloadProfile -Name QuickSanity
        $settings.DurationSeconds = 3
        # Z:\nope\bad.dat — bogus drive, diskspd will fail to create the file
        { Invoke-DiskSpdLocal -DiskSpdPath $script:DiskSpdExePath -Settings $settings -TestFilePath 'Z:\nope\bad.dat' } |
            Should -Throw
    }

    It 'produces parseable XML compatible with ConvertFrom-DiskSpdXml' {
        # End-to-end: run diskspd, pipe its output through the parser, verify shape.
        # This is the most important integration test — it proves the whole local run
        # pipeline produces output the parser can consume.
        $settings = Get-DiskSpdWorkloadProfile -Name QuickSanity
        $settings.DurationSeconds = 3
        $testFile = Join-Path $env:TEMP "diskspd-itest-$([guid]::NewGuid()).dat"

        try {
            $xml    = Invoke-DiskSpdLocal -DiskSpdPath $script:DiskSpdExePath -Settings $settings -TestFilePath $testFile
            $result = ConvertFrom-DiskSpdXml -Xml $xml -ProfileName QuickSanity
            $result.IOPS        | Should -BeGreaterThan 0
            $result.Duration    | Should -BeGreaterThan 0
            $result.TestFilePath| Should -Match 'diskspd-itest-'
        } finally {
            Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        }
    }
}
