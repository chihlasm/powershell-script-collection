#Requires -Version 5.1
# Pester 5 tests for Get-RAMUsage.ps1. No elevation, remoting, or real servers needed -
# collection is mocked.

BeforeAll {
    $script:ScriptPath = Join-Path $PSScriptRoot '..\Get-RAMUsage.ps1'
    . $script:ScriptPath -LoadFunctionsOnly

    function New-FakeProc {
        param([string]$User, [string]$Name, [long]$Bytes, [int]$Session = 2, [string]$Server = 'VDA01')
        [PSCustomObject]@{
            Server = $Server; UserName = $User; ProcessName = $Name; PID = (Get-Random -Maximum 60000)
            SessionId = $Session; PrivateWorkingSet = $Bytes; PrivateWSMB = [math]::Round($Bytes / 1MB, 2)
            WorkingSetBytes = $Bytes; WorkingSetMB = [math]::Round($Bytes / 1MB, 2); CPU_Seconds = 1.5
            HandleCount = 100; ThreadCount = 8; StartTime = (Get-Date '2026-09-29 08:00:00')
        }
    }

    function New-FakeData {
        $list = [System.Collections.Generic.List[object]]::new()
        $list.Add((New-FakeProc 'CONTOSO\jdoe' 'chrome' 800MB))
        $list.Add((New-FakeProc 'CONTOSO\jdoe' 'outlook' 400MB))
        $list.Add((New-FakeProc 'CONTOSO\asmith' 'excel' 300MB -Session 3))
        $list.Add((New-FakeProc 'NT AUTHORITY\SYSTEM' 'MsMpEng' 250MB -Session 0))
        $list.Add((New-FakeProc 'NT AUTHORITY\NETWORK SERVICE' 'svchost' 50MB -Session 0))
        return , $list
    }
}

Describe 'File encoding (regression: v1.1.0 did not parse under Windows PowerShell 5.1)' {
    It 'is pure ASCII so 5.1 cannot misread it as ANSI' {
        $bytes = [System.IO.File]::ReadAllBytes($script:ScriptPath)
        $nonAscii = @($bytes | Where-Object { $_ -gt 127 })
        $nonAscii.Count | Should -Be 0
    }
    It 'parses with no errors' {
        $tokens = $null; $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$tokens, [ref]$errors)
        $errors.Count | Should -Be 0
    }
    It 'does not run a collection when dot-sourced with -LoadFunctionsOnly' {
        Get-Command Start-RAMReport | Should -Not -BeNullOrEmpty
    }
}

Describe 'Test-IsLocalComputer' {
    It 'treats <Name> as local' -TestCases @(
        @{ Name = '.' }, @{ Name = 'localhost' }, @{ Name = 'LOCALHOST' }, @{ Name = '' }
    ) {
        Test-IsLocalComputer $Name | Should -BeTrue
    }
    It 'treats this computer name and its FQDN as local' {
        Test-IsLocalComputer $env:COMPUTERNAME | Should -BeTrue
        Test-IsLocalComputer "$($env:COMPUTERNAME).contoso.local" | Should -BeTrue
    }
    It 'treats another server as remote' {
        Test-IsLocalComputer 'SOME-OTHER-VDA-99' | Should -BeFalse
    }
    It 'does not treat a name that only starts with this computer name as local' {
        Test-IsLocalComputer "$($env:COMPUTERNAME)X" | Should -BeFalse
    }
}

Describe 'Output path resolution' {
    It 'defaults a blank OutputPath to the current directory' {
        Resolve-OutputFolder '' | Should -Be (Get-Location).ProviderPath
    }
    It 'puts a bare export file name inside the output folder' {
        Resolve-ExportFilePath -Path 'ram.csv' -Folder 'C:\Reports' | Should -Be 'C:\Reports\ram.csv'
    }
    It 'uses a full export path as-is' {
        Resolve-ExportFilePath -Path 'D:\Other\ram.csv' -Folder 'C:\Reports' | Should -Be 'D:\Other\ram.csv'
    }
    It 'returns nothing when no export path was given' {
        Resolve-ExportFilePath -Path '' -Folder 'C:\Reports' | Should -BeNullOrEmpty
    }
}

Describe 'JavaScript value encoding' {
    It 'turns a missing number into 0 instead of an empty value' {
        ConvertTo-JsNumber $null | Should -Be '0'
    }
    It 'uses a dot decimal separator even under a comma-decimal culture' {
        $old = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]'de-DE'
            ConvertTo-JsNumber 1.5 | Should -Be '1.5'
        }
        finally { [System.Threading.Thread]::CurrentThread.CurrentCulture = $old }
    }
    It 'escapes backslashes, quotes, and < in strings' {
        ConvertTo-JsString 'CONTOSO\jdoe "x" </script>' | Should -Be '"CONTOSO\\jdoe \"x\" \u003c/script>"'
    }
}

Describe 'Get-AccountGroups' {
    It 'returns only user accounts by default, largest first' {
        $groups = Get-AccountGroups -Processes (New-FakeData)
        $groups.Name | Should -Be @('CONTOSO\jdoe', 'CONTOSO\asmith')
    }
    It 'returns only system accounts with -SystemAccounts' {
        $groups = Get-AccountGroups -Processes (New-FakeData) -SystemAccounts
        $groups.Name | Should -Be @('NT AUTHORITY\SYSTEM', 'NT AUTHORITY\NETWORK SERVICE')
    }
}

Describe 'Start-RAMReport end to end (collection mocked)' {
    BeforeEach {
        $script:outDir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $ComputerName = @('VDA01')
        $Credential = $null
        $Top = 15
        $OutputPath = $script:outDir
        $ExportCSV = ''
        $ExportHTML = ''
        $SkipBrowserOpen = [switch]$true
        $IncludeSystemProcesses = [switch]$false

        Mock Get-ServerMemoryInfo { [PSCustomObject]@{ TotalPhysicalMB = 32768; FreePhysicalMB = 8192; UsedPhysicalMB = 24576; PercentUsed = 75 } }
        Mock Get-ProcessesByUser { New-FakeData }
        Mock Write-Host { }
        Mock Start-Process { }
    }

    It 'writes the HTML report into -OutputPath with a yyyy-MM-dd_HHmmss name' {
        $null = Start-RAMReport
        $html = @(Get-ChildItem $script:outDir -Filter 'RAMUsage_*.html')
        $html.Count | Should -Be 1
        $html[0].Name | Should -Match '^RAMUsage_\d{4}-\d{2}-\d{2}_\d{6}\.html$'
    }

    It 'creates -OutputPath when it does not exist' {
        $OutputPath = Join-Path $script:outDir 'nested\deeper'
        $null = Start-RAMReport
        @(Get-ChildItem $OutputPath -Filter 'RAMUsage_*.html').Count | Should -Be 1
    }

    It 'writes a bare -ExportCSV file name into -OutputPath' {
        $ExportCSV = 'ram.csv'
        $null = Start-RAMReport
        Test-Path (Join-Path $script:outDir 'ram.csv') | Should -BeTrue
    }

    It 'does not itemise system accounts by default' {
        Mock Write-AccountBreakdown { }
        $null = Start-RAMReport
        Should -Invoke Write-AccountBreakdown -Times 1 -Exactly -ParameterFilter { $Heading -eq 'User Sessions' }
        Should -Invoke Write-AccountBreakdown -Times 0 -Exactly -ParameterFilter { $Heading -like 'System*' }
    }

    It 'itemises system accounts with -IncludeSystemProcesses (regression: the switch used to do nothing)' {
        $IncludeSystemProcesses = [switch]$true
        Mock Write-AccountBreakdown { }
        $null = Start-RAMReport
        Should -Invoke Write-AccountBreakdown -Times 1 -Exactly -ParameterFilter {
            $Heading -like 'System*' -and ($Groups.Name -contains 'NT AUTHORITY\SYSTEM')
        }
    }

    It 'opens the HTML report with system accounts hidden by default' {
        $null = Start-RAMReport
        $content = Get-Content (Get-ChildItem $script:outDir -Filter 'RAMUsage_*.html').FullName -Raw
        $content | Should -Match 'let showSystem = false;'
        $content | Should -Match '>Show System Accounts<'
    }

    It 'opens the HTML report with system accounts shown under -IncludeSystemProcesses' {
        $IncludeSystemProcesses = [switch]$true
        $null = Start-RAMReport
        $content = Get-Content (Get-ChildItem $script:outDir -Filter 'RAMUsage_*.html').FullName -Raw
        $content | Should -Match 'let showSystem = true;'
        $content | Should -Match '>Hide System Accounts<'
    }
}

Describe 'Export-InteractiveHTMLReport data' {
    It 'writes 0 rather than an empty value when a process has no memory reading' {
        $data = New-FakeData
        $data[0].PrivateWorkingSet = $null
        $out = Join-Path $TestDrive 'nullpws.html'
        Export-InteractiveHTMLReport -AllData $data -ServerMemory @{} -OutputFile $out -Servers 'VDA01'
        $content = Get-Content $out -Raw
        $content | Should -Match 'pws:0,'
        $content | Should -Not -Match 'pws:,'
    }
}
