<#
    Tests for Invoke-CitrixFSLogixTriage.ps1 (Pester 5; runs under Windows PowerShell 5.1 and 7.x).

    Every remote call (Test-Connection, Get-CimInstance, Get-WinEvent, Invoke-Command,
    Test-Path, and the registry snapshot) is mocked, so the real decision logic runs against
    a pretend session host called RDSH01.

    The expectations come from Microsoft Learn, cited in the script's .NOTES REFERENCES:
    profile settings live under HKLM\SOFTWARE\FSLogix\Profiles; VHDLocations and CCDLocations
    must not both be set; CCDLocations names are case sensitive (type=smb, connectionString=);
    Get-Service has no -ComputerName in PowerShell 6+.

    Run:  Invoke-Pester .\Citrix-FSLogix-Triage\Tests
#>

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:ScriptPath = Join-Path $script:Root 'Invoke-CitrixFSLogixTriage.ps1'
    . $script:ScriptPath -LoadFunctionsOnly

    function New-RegKey {
        param([string]$SubKey, [hashtable]$Values, [switch]$Missing)
        $label = if ($SubKey -like 'SOFTWARE\Policies\*') { 'Policies path (not documented for profile settings)' } else { 'Profile settings' }
        if ($Missing) {
            return [PSCustomObject]@{ Label = $label; Path = "HKLM:\$SubKey"; Found = $false; Error = '' }
        }
        $ordered = [ordered]@{}
        foreach ($k in $Values.Keys) { $ordered[$k] = $Values[$k] }
        [PSCustomObject]@{ Label = $label; Path = "HKLM:\$SubKey"; Found = $true; Error = ''; Values = [PSCustomObject]$ordered }
    }

    function Set-HealthyHost {
        param(
            [hashtable]$Profile = @{ Enabled = '1'; VHDLocations = '\\fs01\profiles' },
            [hashtable]$Policy = $null
        )
        $script:ProfileValues = $Profile
        $script:PolicyValues = $Policy

        Mock Test-Connection { $true }
        Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_Service' } {
            @(
                [PSCustomObject]@{ Name = 'frxsvc'; DisplayName = 'FSLogix Apps Services'; State = 'Running'; StartMode = 'Auto' }
                [PSCustomObject]@{ Name = 'frxccds'; DisplayName = 'FSLogix Cloud Caching Service'; State = 'Running'; StartMode = 'Auto' }
            )
        }
        Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_LogicalDisk' } {
            [PSCustomObject]@{ DeviceID = 'C:'; Size = 200GB; FreeSpace = 120GB }
        }
        Mock Get-WinEvent { throw 'No events were found that match the specified selection criteria.' }
        Mock Get-FSLogixRegistrySnapshot {
            @(
                New-RegKey -SubKey 'SOFTWARE\FSLogix\Profiles' -Values $script:ProfileValues
                if ($script:PolicyValues) { New-RegKey -SubKey 'SOFTWARE\Policies\FSLogix\Profiles' -Values $script:PolicyValues }
                else { New-RegKey -SubKey 'SOFTWARE\Policies\FSLogix\Profiles' -Missing }
            )
        }
        Mock Invoke-Command { $true }
        Mock Test-Path { $true }
    }

    function Get-Evidence($Result, [string]$Name) { @($Result.Evidence | Where-Object { $_.Name -eq $Name }) }
}

Describe 'Healthy session host' {
    BeforeEach { Set-HealthyHost }

    It 'reports Pass with a plain summary' {
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01 -UserName jdoe
        $r.Status | Should -Be 'Pass'
        $r.Summary | Should -Match 'No FSLogix problems found on RDSH01'
    }

    It 'keeps the result shape the retired workbench (and any caller) reads' {
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01
        foreach ($name in 'CheckId', 'Name', 'Category', 'Status', 'Summary', 'Evidence', 'RecommendedNextSteps', 'RawOutput', 'StartedAt', 'FinishedAt', 'Error') {
            $r.PSObject.Properties.Name | Should -Contain $name
        }
        $r.CheckId | Should -Be 'citrix.fslogix.triage'
        $r.RawOutput.AffectedDevice | Should -Be 'RDSH01'
    }

    It 'tests the profile share from the server, with %username% filled in' {
        $script:ProfileValues = @{ Enabled = '1'; VHDLocations = '\\fs01\profiles\%username%' }
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01 -UserName jdoe
        $r.RawOutput.ProfilePaths[0].TestedPath | Should -Be '\\fs01\profiles\jdoe'
        Should -Invoke Invoke-Command -Times 1 -Exactly
    }
}

Describe 'Services are read through CIM, not Get-Service (PowerShell 7 has no Get-Service -ComputerName)' {
    It 'never calls Get-Service' {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$tokens, [ref]$errors)
        $calls = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] -and $args[0].GetCommandName() -eq 'Get-Service' }, $true)
        @($calls).Count | Should -Be 0
    }

    It 'reports a stopped FSLogix service as a problem' {
        Set-HealthyHost
        Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_Service' } {
            @(
                [PSCustomObject]@{ Name = 'frxsvc'; DisplayName = 'FSLogix Apps Services'; State = 'Stopped'; StartMode = 'Auto' }
                [PSCustomObject]@{ Name = 'frxccds'; DisplayName = 'FSLogix Cloud Caching Service'; State = 'Running'; StartMode = 'Auto' }
            )
        }
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01
        $r.Status | Should -Be 'Fail'
        (Get-Evidence $r 'Service frxsvc').Status | Should -Be 'Fail'
    }

    It 'reports an unreadable service list as a warning, never as healthy' {
        Set-HealthyHost
        Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_Service' } { throw 'The WinRM client cannot process the request.' }
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01
        (Get-Evidence $r 'FSLogix services').Status | Should -Be 'Warn'
        $r.Status | Should -Not -Be 'Pass'
    }
}

Describe 'Registry: only HKLM\SOFTWARE\FSLogix\Profiles is the effective setting (regression)' {
    It 'does not let a Policies-path Enabled=1 hide a documented Enabled=0' {
        Set-HealthyHost -Profile @{ Enabled = '0'; VHDLocations = '\\fs01\profiles' } -Policy @{ Enabled = '1' }
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01
        (Get-Evidence $r 'FSLogix profiles switched on').Status | Should -Be 'Fail'
        (Get-Evidence $r 'Settings in an unexpected place').Status | Should -Be 'Warn'
    }

    It 'fails when the documented key is missing even if the Policies path has values' {
        Set-HealthyHost -Policy @{ Enabled = '1'; VHDLocations = '\\fs01\profiles' }
        Mock Get-FSLogixRegistrySnapshot {
            @(
                New-RegKey -SubKey 'SOFTWARE\FSLogix\Profiles' -Missing
                New-RegKey -SubKey 'SOFTWARE\Policies\FSLogix\Profiles' -Values @{ Enabled = '1'; VHDLocations = '\\fs01\profiles' }
            )
        }
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01
        (Get-Evidence $r 'FSLogix settings').Status | Should -Be 'Fail'
        Should -Invoke Invoke-Command -Times 0 -Exactly
    }

    It 'treats Enabled not set as off' {
        Set-HealthyHost -Profile @{ VHDLocations = '\\fs01\profiles' }
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01
        (Get-Evidence $r 'FSLogix profiles switched on').Status | Should -Be 'Fail'
    }

    It 'reports an unreachable registry as a warning' {
        Set-HealthyHost
        Mock Get-FSLogixRegistrySnapshot { throw 'The network path was not found.' }
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01
        (Get-Evidence $r 'FSLogix settings').Status | Should -Be 'Warn'
    }
}

Describe 'Profile storage setting rules from the FSLogix reference' {
    It 'fails when VHDLocations and CCDLocations are both set' {
        $e = @(Get-FSLogixStorageSettingEvidence -VhdLocations '\\fs01\p' -CcdLocations 'type=smb,connectionString=\\fs02\p')
        @($e | Where-Object { $_.Name -eq 'Profile storage setting' })[0].Status | Should -Be 'Fail'
    }

    It 'fails when neither is set' {
        $e = @(Get-FSLogixStorageSettingEvidence -VhdLocations '' -CcdLocations '')
        $e[0].Status | Should -Be 'Fail'
    }

    It 'passes a single VHDLocations value' {
        $e = @(Get-FSLogixStorageSettingEvidence -VhdLocations '\\fs01\p' -CcdLocations '')
        $e[0].Status | Should -Be 'Pass'
    }

    It 'flags type=SMB (upper case) - FSLogix names are case sensitive (regression)' {
        $e = @(Get-FSLogixStorageSettingEvidence -VhdLocations '' -CcdLocations 'type=SMB,connectionString=\\fs02\p')
        @($e | Where-Object { $_.Name -eq 'Cloud Cache location spelling' })[0].Status | Should -Be 'Fail'
    }

    It 'flags connectionstring= (lower-case s)' {
        @(Test-FSLogixCloudCacheProviderSpelling -ProviderString 'type=smb,connectionstring=\\fs02\p').Count | Should -Be 1
    }

    It 'accepts the documented spellings for smb and azure' {
        @(Test-FSLogixCloudCacheProviderSpelling -ProviderString 'type=smb,name="SMB PROVIDER 1",connectionString=\\fs02\p').Count | Should -Be 0
        @(Test-FSLogixCloudCacheProviderSpelling -ProviderString 'type=azure,name="AZURE BLOB 1",connectionString="|fslogix/azureblob1|"').Count | Should -Be 0
    }

    It 'checks every provider in a multi-provider CCDLocations value' {
        $value = 'type=smb,connectionString=\\fs01\p;type=Azure,connectionString="|fslogix/k|"'
        $e = @(Get-FSLogixStorageSettingEvidence -VhdLocations '' -CcdLocations $value)
        @($e | Where-Object { $_.Name -eq 'Cloud Cache location spelling' }).Count | Should -Be 1
    }
}

Describe 'Secrets stay out of the output' {
    It 'redacts an azure connectionString in the raw output and the text report' {
        Set-HealthyHost -Profile @{ Enabled = '1'; CCDLocations = 'type=azure,name="BLOB",connectionString="DefaultEndpointsProtocol=https;AccountKey=SECRETKEY"' }
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01
        ($r.RawOutput.Registry | Out-String) | Should -Not -Match 'SECRETKEY'
        (ConvertTo-TriageText -Result $r) -join "`n" | Should -Not -Match 'SECRETKEY'
    }

    It 'keeps an SMB path readable' {
        ConvertTo-RedactedFSLogixCloudCacheProviderEntry -ProviderString 'type=smb,connectionString=\\fs02\p' | Should -Be 'type=smb,connectionString=\\fs02\p'
    }
}

Describe 'Profile share reachability and the double hop' {
    It 'is only a warning when the remote test fails but your PC can reach the share' {
        Set-HealthyHost
        Mock Invoke-Command { $false }
        Mock Test-Path { $true }
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01
        $item = Get-Evidence $r 'Profile share reachable'
        $item.Status | Should -Be 'Warn'
        $item.Detail | Should -Match 'CAN be reached from your PC'
    }

    It 'is a problem when run on the server itself and the share is unreachable' {
        Set-HealthyHost
        Mock Test-Path { $false }
        $r = Invoke-CitrixFSLogixTriage -ComputerName $env:COMPUTERNAME
        (Get-Evidence $r 'Profile share reachable').Status | Should -Be 'Fail'
        Should -Invoke Invoke-Command -Times 0 -Exactly
    }

    It 'does not test an azure Cloud Cache location as a file share' {
        Set-HealthyHost -Profile @{ Enabled = '1'; CCDLocations = 'type=azure,connectionString="|fslogix/k|"' }
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01
        Should -Invoke Invoke-Command -Times 0 -Exactly
        (Get-Evidence $r 'Profile storage reachable').Status | Should -Be 'Warn'
    }
}

Describe 'Event logs' {
    It 'calls a missing FSLogix log "missing", not a permissions problem' {
        Set-HealthyHost
        Mock Get-WinEvent { throw 'There is not an event log on the RDSH01 computer that matches "Microsoft-FSLogix-Apps/Operational".' }
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01
        @(Get-Evidence $r 'Event log missing').Count | Should -BeGreaterThan 0
        @(Get-Evidence $r 'Event log access').Count | Should -Be 0
    }

    It 'reports recent FSLogix errors as a problem' {
        Set-HealthyHost
        Mock Get-WinEvent -ParameterFilter { $FilterHashtable.LogName -eq 'Microsoft-FSLogix-Apps/Operational' } {
            [PSCustomObject]@{ LevelDisplayName = 'Error'; TimeCreated = (Get-Date); Id = 26; ProviderName = 'Microsoft-FSLogix-Apps'; Message = 'Profile failed to attach' }
        }
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01
        $r.Status | Should -Be 'Fail'
        $r.RawOutput.Events[0].Id | Should -Be 26
    }
}

Describe 'Disk space rule of thumb' {
    It 'does not call a large, mostly free disk full (77 GB free of 952 GB)' {
        Get-DiskSpaceStatus -FreeGB 77.28 -FreePercent 8.12 | Should -Be 'Pass'
    }
    It 'fails under 5 GB' { Get-DiskSpaceStatus -FreeGB 4 -FreePercent 40 | Should -Be 'Fail' }
    It 'fails at 8 percent of a 100 GB disk' { Get-DiskSpaceStatus -FreeGB 8 -FreePercent 8 | Should -Be 'Fail' }
    It 'warns at 12 GB / 12 percent' { Get-DiskSpaceStatus -FreeGB 12 -FreePercent 12 | Should -Be 'Warn' }
}

Describe 'Helpers' {
    It 'inserts a user name containing $ literally' {
        ConvertTo-ProfilePathForTest -Path '\\fs\p\%USERNAME%' -UserName 'svc$1' | Should -Be '\\fs\p\svc$1'
    }
    It 'treats localhost, . and this computer as local' {
        Test-IsLocalComputerTarget -ComputerName 'localhost' | Should -BeTrue
        Test-IsLocalComputerTarget -ComputerName '.' | Should -BeTrue
        Test-IsLocalComputerTarget -ComputerName $env:COMPUTERNAME | Should -BeTrue
        Test-IsLocalComputerTarget -ComputerName 'RDSH01' | Should -BeFalse
    }
    It 'splits a REG_SZ VHDLocations value on semicolons' {
        @(Split-FSLogixRegistryLocationEntries -Value '\\a\p; \\b\p').Count | Should -Be 2
    }
}

Describe 'Report output' {
    BeforeEach { Set-HealthyHost }

    It 'leads the text report with the verdict' {
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01 -UserName jdoe
        (ConvertTo-TriageText -Result $r)[0] | Should -Be 'FSLogix check for RDSH01 (user jdoe):  LOOKS HEALTHY'
    }

    It 'writes a text file and a CSV to -OutputPath' {
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01
        # Test-Path is mocked for the share checks, so create the folder and check files via .NET.
        $out = Join-Path $TestDrive 'out'
        $null = New-Item -ItemType Directory -Path $out -Force
        $files = @(Export-TriageReport -Result $r -OutputPath $out)
        $files.Count | Should -Be 2
        foreach ($f in $files) { [System.IO.File]::Exists($f) | Should -BeTrue }
        (Import-Csv -LiteralPath $files[1])[0].PSObject.Properties.Name | Should -Contain 'Action'
    }
}
