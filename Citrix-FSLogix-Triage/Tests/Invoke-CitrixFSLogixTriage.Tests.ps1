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

# =============================================================================
# SQ-010 (SQ-001 Part B): Citrix-FSLogix-Triage adopts the ticket note (AC30-AC33)
#
# Expected of the script: it dot-sources its own CaseKit.ps1 (before the -LoadFunctionsOnly
# return) and defines the adapter
#     ConvertTo-CitrixFSLogixTriageTicketNote -Result <result> [-EvidencePaths <string[]>]
# which holds this tool's gate decisions. New-EvidenceItem gains a -NotChecked switch (stored
# as a NotChecked property, default $false) that is set on every "could not run" item; the
# Status values stay Warn, so the verdict does not change. Nothing here touches a real host,
# the registry, the network or the clipboard: every remote cmdlet and the registry snapshot
# are mocked or replaced; all files go under $TestDrive.
# =============================================================================

Describe 'ticket note (adapter)' {
    BeforeAll {
        # The lines of one note section: after its header, up to the next header or blank line.
        function Get-NoteSection([string[]]$Lines, [string]$Header) {
            $headers = 'Checked:', 'Ruled out:', 'Could not check:', 'Next step:'
            $at = [array]::IndexOf($Lines, $Header)
            if ($at -lt 0) { return @() }
            $out = @()
            for ($i = $at + 1; $i -lt $Lines.Count; $i++) {
                if ($headers -contains $Lines[$i] -or -not $Lines[$i].Trim()) { break }
                $out += $Lines[$i]
            }
            , $out
        }
        function Get-NoteLines($Result, [string[]]$Evidence = @()) {
            $note = ConvertTo-CitrixFSLogixTriageTicketNote -Result $Result -EvidencePaths $Evidence
            [PSCustomObject]@{ Note = $note; Lines = @(ConvertTo-TicketNoteText -Note $note) }
        }
    }
    BeforeEach { Set-HealthyHost }

    It 'AC30_TriageCouldNotRead: <Case> -> Could not check, never Ruled out, and the verdict stays WARNINGS' -ForEach @(
        @{ Case = 'ping throws'; Find = 'Ping could not run'; NotRuledOut = 'answered a ping' }
        @{ Case = 'services CIM throws'; Find = 'Could not read services'; NotRuledOut = 'is running' }
        @{ Case = 'registry read throws'; Find = "Could not read the server's registry"; NotRuledOut = 'profile containers are enabled|Profile location is set' }
        @{ Case = 'registry key error'; Find = 'Could not read the FSLogix settings'; NotRuledOut = 'profile containers are enabled|Profile location is set' }
        @{ Case = 'event log access denied'; Find = 'Could not read Microsoft-'; NotRuledOut = 'No events|No errors or warnings' }
        @{ Case = 'disks CIM throws'; Find = 'Could not read disk space'; NotRuledOut = 'GB free' }
        @{ Case = 'no disks returned'; Find = 'No local disks were returned'; NotRuledOut = 'GB free' }
    ) {
        switch ($Case) {
            'ping throws' { Mock Test-Connection { throw 'Testing connection to computer RDSH01 failed.' } }
            'services CIM throws' { Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_Service' } { throw 'The WinRM client cannot process the request.' } }
            'registry read throws' { Mock Get-FSLogixRegistrySnapshot { throw 'The network path was not found.' } }
            'registry key error' {
                Mock Get-FSLogixRegistrySnapshot {
                    @(
                        [PSCustomObject]@{ Label = 'Profile settings'; Path = 'HKLM:\SOFTWARE\FSLogix\Profiles'; Found = $false; Error = 'Requested registry access is not allowed.' }
                        [PSCustomObject]@{ Label = 'Policies path (not documented for profile settings)'; Path = 'HKLM:\SOFTWARE\Policies\FSLogix\Profiles'; Found = $false; Error = '' }
                    )
                }
            }
            'event log access denied' { Mock Get-WinEvent { throw 'Attempted to perform an unauthorized operation.' } }
            'disks CIM throws' { Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_LogicalDisk' } { throw 'Access is denied.' } }
            'no disks returned' { Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_LogicalDisk' } { @() } }
        }
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01 -UserName jdoe
        $r.Status | Should -Be 'Warn'
        $n = Get-NoteLines $r
        @(Get-NoteSection $n.Lines 'Could not check:' | Where-Object { $_ -match [regex]::Escape($Find) }).Count | Should -BeGreaterThan 0
        @(Get-NoteSection $n.Lines 'Ruled out:' | Where-Object { $_ -match $NotRuledOut }).Count | Should -Be 0
        @(Get-NoteSection $n.Lines 'Checked:' | Where-Object { $_ -match [regex]::Escape($Find) }).Count | Should -Be 0 -Because 'a check that could not run is not a finding'
    }

    It 'AC31_TriageDoubleHop: share not confirmed from the server -> Could not check, and says whether it worked from your PC (<Case>)' -ForEach @(
        @{ Case = 'reachable from the PC'; FromPc = $true; Says = 'CAN be reached from your PC' }
        @{ Case = 'not reachable from the PC either'; FromPc = $false; Says = 'cannot be reached from your PC either' }
    ) {
        Mock Invoke-Command { $false }
        if ($FromPc) { Mock Test-Path { $true } } else { Mock Test-Path { $false } }
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01 -UserName jdoe
        $n = Get-NoteLines $r
        $could = @(Get-NoteSection $n.Lines 'Could not check:' | Where-Object { $_ -match 'could not be confirmed from RDSH01' })
        $could.Count | Should -Be 1
        $could[0] | Should -Match ([regex]::Escape($Says))
        @(Get-NoteSection $n.Lines 'Ruled out:' | Where-Object { $_ -match '(?i)profile share|fs01' }).Count | Should -Be 0
        @(Get-NoteSection $n.Lines 'Checked:' | Where-Object { $_ -match 'could not be confirmed' }).Count | Should -Be 0
    }

    It 'AC31_TriageCloudCacheNotTested: a Cloud Cache location that is not a file share is Could not check' {
        Set-HealthyHost -Profile @{ Enabled = '1'; CCDLocations = 'type=azure,name="BLOB",connectionString="|fslogix/k|"' }
        $n = Get-NoteLines (Invoke-CitrixFSLogixTriage -ComputerName RDSH01)
        @(Get-NoteSection $n.Lines 'Could not check:' | Where-Object { $_ -match 'was not tested' }).Count | Should -Be 1
        @(Get-NoteSection $n.Lines 'Ruled out:' | Where-Object { $_ -match 'was not tested|Cloud Cache location' }).Count | Should -Be 0
    }

    It 'AC32_TriageSettingsStayOut: Cloud Cache connection strings and the FSLogix settings block never reach the note' {
        Set-HealthyHost -Profile @{
            Enabled      = '1'
            CCDLocations = 'type=smb,name="SMB1",connectionString=\\fs02\profiles;type=azure,name="BLOB",connectionString="DefaultEndpointsProtocol=https;AccountKey=SECRETKEY"'
        }
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01 -UserName jdoe
        $r.RawOutput.Registry.Count | Should -BeGreaterThan 0 -Because 'the settings were read, so the report has them; the note must still leave them out'
        $n = Get-NoteLines $r
        $all = $n.Lines -join "`n"
        $all | Should -Not -Match '(?i)connection\s?string'
        $all | Should -Not -Match 'SECRETKEY|AccountKey'
        $all | Should -Not -Match 'secrets redacted'
        $all | Should -Not -Match 'HKLM:'
        $all | Should -Not -Match 'CCDLocations=|VHDLocations=|Enabled='
    }

    It 'AC33_TriageFindingsAndClears: a missing event log is a WARNING under Checked; a running frxsvc is Ruled out' {
        Mock Get-WinEvent { throw ('There is not an event log on the RDSH01 computer that matches "{0}".' -f $FilterHashtable.LogName) }
        $n = Get-NoteLines (Invoke-CitrixFSLogixTriage -ComputerName RDSH01)
        $checked = Get-NoteSection $n.Lines 'Checked:'
        @($checked | Where-Object { $_ -like '- WARNING: *Microsoft-FSLogix-Apps/Operational does not exist*' }).Count | Should -Be 1
        @($checked | Where-Object { $_ -like '- WARNING: *' }).Count | Should -Be 4 -Because 'four logs are missing'
        @(Get-NoteSection $n.Lines 'Could not check:' | Where-Object { $_ -match 'does not exist' }).Count | Should -Be 0
        Get-NoteSection $n.Lines 'Ruled out:' | Should -Contain '- FSLogix Apps Services is running.'
    }

    It 'TriageMapping_ProblemAndStopped: a stopped service is a PROBLEM under Checked, not Ruled out' {
        Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_Service' } {
            @(
                [PSCustomObject]@{ Name = 'frxsvc'; DisplayName = 'FSLogix Apps Services'; State = 'Stopped'; StartMode = 'Auto' }
                [PSCustomObject]@{ Name = 'frxccds'; DisplayName = 'FSLogix Cloud Caching Service'; State = 'Running'; StartMode = 'Auto' }
            )
        }
        $n = Get-NoteLines (Invoke-CitrixFSLogixTriage -ComputerName RDSH01)
        @(Get-NoteSection $n.Lines 'Checked:' | Where-Object { $_ -like '- PROBLEM: FSLogix Apps Services is Stopped*' }).Count | Should -Be 1
        @(Get-NoteSection $n.Lines 'Ruled out:' | Where-Object { $_ -match 'FSLogix Apps Services' }).Count | Should -Be 0
    }

    It 'TriageMapping_HeadlineStampSteps: headline reuses the triage headline, stamp is the target, next steps and evidence are listed' {
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01 -UserName jdoe
        $n = Get-NoteLines $r @('C:\x\FSLogixTriage_RDSH01_2026-10-17_090000.txt', 'C:\x\FSLogixTriage_RDSH01_2026-10-17_090000.csv')
        $n.Lines[0] | Should -Be '[Ticket note] Citrix-FSLogix-Triage: FSLogix check for RDSH01 (user jdoe):  LOOKS HEALTHY'
        $stamp = @($n.Lines | Where-Object { $_ -like 'Computer: *' })[0]
        $stamp | Should -BeLike 'Computer: RDSH01 | *'
        $stamp | Should -BeLike '*Changed anything: No'
        Get-NoteSection $n.Lines 'Next step:' | Should -Contain ('- ' + $r.RecommendedNextSteps[0])
        $n.Lines | Should -Contain 'Evidence: FSLogixTriage_RDSH01_2026-10-17_090000.txt, FSLogixTriage_RDSH01_2026-10-17_090000.csv'
    }

    It 'TriageMapping_PasteSafe: paste-safe rendering removes the share path from the note body' {
        $r = Invoke-CitrixFSLogixTriage -ComputerName RDSH01 -UserName jdoe
        $note = ConvertTo-CitrixFSLogixTriageTicketNote -Result $r
        $plain = (ConvertTo-TicketNoteText -Note $note) -join "`n"
        $safe = (ConvertTo-TicketNoteText -Note $note -PasteSafe) -join "`n"
        $plain | Should -Match 'fs01'
        $safe | Should -Not -Match 'fs01'
        $safe | Should -Match '\[share path removed\]'
    }

    It 'TriageMapping_NotCheckedProperty: New-EvidenceItem has -NotChecked, stored as NotChecked and false by default' {
        (New-EvidenceItem -Name 'x' -Status 'Warn' -Detail 'd').NotChecked | Should -BeFalse
        (New-EvidenceItem -Name 'x' -Status 'Warn' -Detail 'd' -NotChecked).NotChecked | Should -BeTrue
    }
}

# The script itself, run in-process against a pretend session host (RDSH01). Everything that
# would reach out is replaced:
#  - cmdlets (Test-Connection, Get-CimInstance, Get-WinEvent, Invoke-Command, Test-Path for
#    UNC paths, Set-Clipboard) are Pester mocks;
#  - the script's own functions that would read a real registry (Get-FSLogixRegistrySnapshot)
#    or touch the real clipboard / profile (Invoke-WinFormsClipboard, Get-TicketNoteDefaultRoot)
#    are shadowed by GLOBAL ALIASES, because an alias outranks a function, and a function the
#    script defines in its own scope would otherwise outrank a Pester mock. The aliases are
#    removed after every test.
#  - Test-Path is only mocked for \\ paths, so the kit and the report writer use the real one
#    inside $TestDrive (an unfiltered "return true" would make the kit's unique-name loop spin).
Describe 'ticket note (script, in-process)' {
    BeforeAll {
        function global:TrgFake-Registry { param($ComputerName, $IsLocal)
            @(
                [PSCustomObject]@{ Label = 'Profile settings'; Path = 'HKLM:\SOFTWARE\FSLogix\Profiles'; Found = $true; Error = ''; Values = [PSCustomObject]@{ Enabled = '1'; VHDLocations = '\\fs01\profiles' } }
                [PSCustomObject]@{ Label = 'Policies path (not documented for profile settings)'; Path = 'HKLM:\SOFTWARE\Policies\FSLogix\Profiles'; Found = $false; Error = '' }
            )
        }
        function global:TrgFake-Clipboard { param($Text) }
        function global:TrgFake-DefaultRoot { $global:TrgRoot }
        function global:TrgFake-Throw { throw 'simulated note failure' }
        $script:AliasNames = 'Get-FSLogixRegistrySnapshot', 'Invoke-WinFormsClipboard', 'Get-TicketNoteDefaultRoot', 'ConvertTo-CitrixFSLogixTriageTicketNote'
        function Clear-TrgAliases { foreach ($a in $script:AliasNames) { Remove-Item -LiteralPath "Alias:\$a" -Force -ErrorAction SilentlyContinue } }
        function Set-TriageScriptMocks {
            Mock Test-Connection { $true }
            Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_Service' } {
                @(
                    [PSCustomObject]@{ Name = 'frxsvc'; DisplayName = 'FSLogix Apps Services'; State = 'Running'; StartMode = 'Auto' }
                    [PSCustomObject]@{ Name = 'frxccds'; DisplayName = 'FSLogix Cloud Caching Service'; State = 'Running'; StartMode = 'Auto' }
                )
            }
            Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_LogicalDisk' } { [PSCustomObject]@{ DeviceID = 'C:'; Size = 200GB; FreeSpace = 120GB } }
            Mock Get-WinEvent { throw 'No events were found that match the specified selection criteria.' }
            Mock Invoke-Command { $true }
            Mock Test-Path -ParameterFilter { "$LiteralPath" -like '\\*' } { $true }
            Mock Set-Clipboard { }
        }
        function Invoke-Trg([hashtable]$Splat, [string]$Path = $script:ScriptPath) {
            $global:LASTEXITCODE = 0
            $out = @(& $Path @Splat *>&1)
            [PSCustomObject]@{ ExitCode = $global:LASTEXITCODE; Out = $out; Text = (@($out | ForEach-Object { "$_" }) -join "`n") }
        }
    }
    BeforeEach {
        $global:TrgRoot = Join-Path $TestDrive 'defaultroot'
        Set-Alias -Name Get-FSLogixRegistrySnapshot -Value TrgFake-Registry -Scope Global
        Set-Alias -Name Invoke-WinFormsClipboard -Value TrgFake-Clipboard -Scope Global
        Set-Alias -Name Get-TicketNoteDefaultRoot -Value TrgFake-DefaultRoot -Scope Global
        Set-TriageScriptMocks
    }
    AfterEach { Clear-TrgAliases }
    AfterAll {
        Clear-TrgAliases
        Remove-Item -LiteralPath Function:\TrgFake-Registry, Function:\TrgFake-Clipboard, Function:\TrgFake-DefaultRoot, Function:\TrgFake-Throw -ErrorAction SilentlyContinue
    }

    It 'loading the functions also loads the kit (the adapter can call New-TicketNote)' {
        $loaded = & { . $script:ScriptPath -LoadFunctionsOnly; [bool](Get-Command New-TicketNote -ErrorAction SilentlyContinue) }
        $loaded | Should -BeTrue
    }

    It 'Wiring_Clipboard: -NoClipboard and -Quiet skip the clipboard; the default copies exactly once' {
        $null = Invoke-Trg @{ ComputerName = 'RDSH01'; NoClipboard = $true }
        Should -Invoke Set-Clipboard -Times 0 -Exactly
        $null = Invoke-Trg @{ ComputerName = 'RDSH01'; Quiet = $true }
        Should -Invoke Set-Clipboard -Times 0 -Exactly
        $null = Invoke-Trg @{ ComputerName = 'RDSH01' }
        Should -Invoke Set-Clipboard -Times 1 -Exactly
    }

    It 'Wiring_TicketFolder: -TicketNumber puts the reports and the note in Ticket_<n>, and the note names the reports' {
        $root = Join-Path $TestDrive 'ticket'
        $null = New-Item -ItemType Directory -Path $root
        $null = Invoke-Trg @{ ComputerName = 'RDSH01'; UserName = 'jdoe'; TicketNumber = '482113'; OutputPath = $root; NoClipboard = $true }
        $dir = Join-Path $root 'Ticket_482113'
        $txt = @(Get-ChildItem -LiteralPath $dir -Filter 'FSLogixTriage_*.txt' -ErrorAction SilentlyContinue)
        $csv = @(Get-ChildItem -LiteralPath $dir -Filter 'FSLogixTriage_*.csv' -ErrorAction SilentlyContinue)
        $note = @(Get-ChildItem -LiteralPath $dir -Filter 'Note_*_Citrix-FSLogix-Triage.txt' -ErrorAction SilentlyContinue)
        $txt.Count | Should -Be 1
        $csv.Count | Should -Be 1
        $note.Count | Should -Be 1
        $text = [System.IO.File]::ReadAllText($note[0].FullName)
        $text | Should -Match ([regex]::Escape($txt[0].Name))
        $text | Should -Match ([regex]::Escape($csv[0].Name))
    }

    It 'Wiring_OnlyOutputPath: with just -OutputPath the note is saved beside the reports' {
        $root = Join-Path $TestDrive 'beside'
        $null = Invoke-Trg @{ ComputerName = 'RDSH01'; OutputPath = $root; NoClipboard = $true }
        @(Get-ChildItem -LiteralPath $root -Filter 'Note_*_Citrix-FSLogix-Triage.txt' -ErrorAction SilentlyContinue).Count | Should -Be 1
    }

    It 'Wiring_BadTicketNumber: a mistyped -TicketNumber gets a plain [FAIL] line and exit 3, before any check, and no clipboard' {
        $x = Invoke-Trg @{ ComputerName = 'RDSH01'; TicketNumber = '..\x'; OutputPath = $TestDrive }
        $x.ExitCode | Should -Be 3
        $x.Text | Should -Match ([regex]::Escape("[FAIL] '..\x' is not a usable ticket number"))
        Should -Invoke Test-Connection -Times 0 -Exactly
        Should -Invoke Set-Clipboard -Times 0 -Exactly
    }

    It 'Wiring_TicketNumberIsNotValidatePattern: the parameter has no ValidatePattern (the body gives the plain-English message)' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$null)
        $p = @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'TicketNumber' })
        $p.Count | Should -Be 1
        @($p[0].Attributes | Where-Object { $_.TypeName.Name -eq 'ValidatePattern' }).Count | Should -Be 0
        foreach ($name in 'NoClipboard', 'FullDetail') {
            @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq $name }).Count | Should -Be 1
        }
    }

    It 'Wiring_PasteSafeDefault: the saved note hides share paths (except in the headline); -FullDetail keeps them (D-009)' {
        $safe = Join-Path $TestDrive 'safe'
        $full = Join-Path $TestDrive 'full'
        $null = Invoke-Trg @{ ComputerName = 'RDSH01'; OutputPath = $safe; NoClipboard = $true }
        $null = Invoke-Trg @{ ComputerName = 'RDSH01'; OutputPath = $full; NoClipboard = $true; FullDetail = $true }
        $safeLines = @([System.IO.File]::ReadAllLines((Get-ChildItem -LiteralPath $safe -Filter 'Note_*.txt')[0].FullName))
        $fullLines = @([System.IO.File]::ReadAllLines((Get-ChildItem -LiteralPath $full -Filter 'Note_*.txt')[0].FullName))
        ($safeLines | Select-Object -Skip 2) -join "`n" | Should -Not -Match 'fs01'
        ($safeLines | Select-Object -Skip 2) -join "`n" | Should -Match '\[share path removed\]'
        ($fullLines | Select-Object -Skip 2) -join "`n" | Should -Match 'fs01'
    }

    It 'Wiring_ClipboardIsPasteSafe: the clipboard text is redacted by default' {
        $null = Invoke-Trg @{ ComputerName = 'RDSH01' }
        Should -Invoke Set-Clipboard -Times 1 -Exactly -ParameterFilter { $Value -notmatch 'fs01' -and $Value -match '\[Ticket note\] Citrix-FSLogix-Triage' }
    }

    It 'Wiring_ExitCodesUnchanged: with the note on, exit is 0 when healthy, 1 on a warning, 2 on a problem' {
        (Invoke-Trg @{ ComputerName = 'RDSH01'; NoClipboard = $true }).ExitCode | Should -Be 0
        Mock Test-Connection { $false }
        (Invoke-Trg @{ ComputerName = 'RDSH01'; NoClipboard = $true }).ExitCode | Should -Be 1
        Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_Service' } {
            @(
                [PSCustomObject]@{ Name = 'frxsvc'; DisplayName = 'FSLogix Apps Services'; State = 'Stopped'; StartMode = 'Auto' }
                [PSCustomObject]@{ Name = 'frxccds'; DisplayName = 'FSLogix Cloud Caching Service'; State = 'Running'; StartMode = 'Auto' }
            )
        }
        (Invoke-Trg @{ ComputerName = 'RDSH01'; NoClipboard = $true }).ExitCode | Should -Be 2
    }

    It 'Wiring_NoteFailureKeepsExitCode: if building the note throws, the check still reports and exits as before' {
        Set-Alias -Name ConvertTo-CitrixFSLogixTriageTicketNote -Value TrgFake-Throw -Scope Global
        $x = Invoke-Trg @{ ComputerName = 'RDSH01' }
        $x.ExitCode | Should -Be 0
        $x.Text | Should -Match '\[WARN\] Could not make the ticket note'
        Should -Invoke Set-Clipboard -Times 0 -Exactly
        Mock Test-Connection { $false }
        (Invoke-Trg @{ ComputerName = 'RDSH01' }).ExitCode | Should -Be 1
    }

    It 'Wiring_UnwritableFolderKeepsExitCode: a ticket folder that cannot be made is a warning, not a different exit code' {
        $blocker = Join-Path $TestDrive 'iamafile'
        Set-Content -LiteralPath $blocker -Value 'x'
        $x = Invoke-Trg @{ ComputerName = 'RDSH01'; TicketNumber = '482113'; OutputPath = $blocker; NoClipboard = $true }
        $x.ExitCode | Should -Be 0
        $x.Text | Should -Match '\[WARN\]'
    }

    It 'Wiring_PassThru: -PassThru -Quiet returns the result with a TicketNote and writes nothing to the host' {
        $x = Invoke-Trg @{ ComputerName = 'RDSH01'; PassThru = $true; Quiet = $true }
        $res = @($x.Out | Where-Object { $_ -is [pscustomobject] -and $_.PSObject.Properties['CheckId'] })
        $res.Count | Should -Be 1
        foreach ($name in 'CheckId', 'Status', 'Summary', 'Evidence', 'RecommendedNextSteps', 'RawOutput', 'TicketNote') { $res[0].PSObject.Properties.Name | Should -Contain $name }
        $res[0].TicketNote.Tool | Should -Be 'Citrix-FSLogix-Triage'
        @($x.Out | Where-Object { $_ -isnot [pscustomobject] }).Count | Should -Be 0
        Should -Invoke Set-Clipboard -Times 0 -Exactly
    }

    It 'Wiring_MissingKit: without CaseKit.ps1 next to it, the tool runs as today and says there is no note' {
        $dir = Join-Path $TestDrive 'nokit'
        $null = New-Item -ItemType Directory -Path $dir
        Copy-Item -LiteralPath $script:ScriptPath -Destination $dir
        $copy = Join-Path $dir 'Invoke-CitrixFSLogixTriage.ps1'
        $x = Invoke-Trg @{ ComputerName = 'RDSH01' } $copy
        $x.ExitCode | Should -Be 0
        $x.Text | Should -Match '\[WARN\] CaseKit\.ps1 is missing from this folder - no ticket note this time\.'
        Should -Invoke Set-Clipboard -Times 0 -Exactly
    }
}
