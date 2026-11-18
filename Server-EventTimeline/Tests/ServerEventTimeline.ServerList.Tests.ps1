<#
    Pester 5 tests for ServerEventTimeline.ServerList.ps1 (the server list: directory entries,
    suggestions, notes, file parsing, background lookups). No AD, DNS or real settings: the
    background jobs get fake loader and lookup scriptblocks.
    Run:  pwsh -File Tests\Invoke-AllTests.ps1 -Path .\Server-EventTimeline\Tests
#>

BeforeAll {
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'ServerEventTimeline.Core.ps1')

    function New-FakeComputer {
        param([string]$Name, [string]$Dns = '', [string]$OS = 'Windows Server 2019 Standard', [bool]$Enabled = $true,
            $LastLogon = $null, [string]$DN = '')
        if (-not $DN) { $DN = "CN=$Name,OU=Servers,DC=contoso,DC=local" }
        [PSCustomObject]@{ Name = $Name; DNSHostName = $Dns; OperatingSystem = $OS; Enabled = $Enabled; lastLogonTimestamp = $LastLogon; DistinguishedName = $DN }
    }
    $script:Now = [datetime]::new(2026, 11, 18, 0, 0, 0, [DateTimeKind]::Utc)
    function New-FakeDirectory {
        @(
            (New-FakeComputer -Name 'FS01' -Dns 'FS01.contoso.local'),
            (New-FakeComputer -Name 'FS02' -Dns 'FS02.contoso.local' -OS 'Windows Server 2012 R2 Standard'),
            (New-FakeComputer -Name 'PRINTFS' -Dns 'PRINTFS.contoso.local'),
            (New-FakeComputer -Name 'FSOLD' -Dns 'FSOLD.contoso.local' -Enabled $false),
            (New-FakeComputer -Name 'WS-FS9' -Dns 'WS-FS9.contoso.local' -OS 'Windows 11 Enterprise'),
            (New-FakeComputer -Name 'DC01' -Dns 'DC01.contoso.local' -DN 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=local')
        ) | ForEach-Object { ConvertTo-DirectoryEntry -Computer $_ -DomainControllers @('DC01.contoso.local') -Now $script:Now }
    }
}

Describe 'ConvertTo-DirectoryEntry' {
    It 'reads a server computer object' {
        $c = New-FakeComputer -Name 'FS01' -Dns 'FS01.contoso.local' -LastLogon ([datetime]::new(2026, 11, 8, 0, 0, 0, [DateTimeKind]::Utc).ToFileTimeUtc())
        $e = ConvertTo-DirectoryEntry -Computer $c -DomainControllers @('dc01.contoso.local') -Now $script:Now
        $e.Name | Should -Be 'FS01'
        $e.DnsName | Should -Be 'FS01.contoso.local'
        $e.OS | Should -Be 'Windows Server 2019 Standard'
        $e.Enabled | Should -BeTrue
        $e.IsServer | Should -BeTrue
        $e.IsDC | Should -BeFalse
        $e.DaysSinceLogon | Should -Be 10
        $e.OU | Should -Be 'OU=Servers,DC=contoso,DC=local'
    }

    It 'treats 0, missing and Int64.MaxValue lastLogonTimestamp as never' {
        # lastLogonTimestamp: 0 / absent / Int64.MaxValue mean "never" (repo CLAUDE.md), not 1601-01-01.
        foreach ($v in @(0, $null, [Int64]::MaxValue)) {
            $c = New-FakeComputer -Name 'X' -LastLogon $v
            (ConvertTo-DirectoryEntry -Computer $c -DomainControllers @() -Now $script:Now).DaysSinceLogon | Should -BeNullOrEmpty
        }
    }

    It 'marks a DC by short or DNS name and falls back to Name when DNSHostName is empty' {
        $e = ConvertTo-DirectoryEntry -Computer (New-FakeComputer -Name 'DC01') -DomainControllers @('DC01.contoso.local') -Now $script:Now
        $e.IsDC | Should -BeTrue
        $e.DnsName | Should -Be 'DC01'
        $e2 = ConvertTo-DirectoryEntry -Computer (New-FakeComputer -Name 'DC02' -Dns 'dc02.contoso.local') -DomainControllers @('DC02') -Now $script:Now
        $e2.IsDC | Should -BeTrue
    }

    It 'is not a server when the operating system is empty or a client OS' {
        (ConvertTo-DirectoryEntry -Computer (New-FakeComputer -Name 'A' -OS '') -DomainControllers @() -Now $script:Now).IsServer | Should -BeFalse
        (ConvertTo-DirectoryEntry -Computer (New-FakeComputer -Name 'B' -OS 'Windows 11 Pro') -DomainControllers @() -Now $script:Now).IsServer | Should -BeFalse
    }
}

Describe 'Find-ServerSuggestions' {
    BeforeAll { $script:Dir = @(New-FakeDirectory) }

    It 'puts names starting with the text first, then names containing it' {
        $s = @(Find-ServerSuggestions -Directory $script:Dir -Recent @() -Text 'fs' -Max 8)
        ($s | ForEach-Object Name) -join ',' | Should -Be 'FS01.contoso.local,FS02.contoso.local,PRINTFS.contoso.local'
        $s[0].Detail | Should -Be 'Windows Server 2019 Standard'
    }

    It 'returns at most -Max suggestions' {
        @(Find-ServerSuggestions -Directory $script:Dir -Recent @() -Text 'fs' -Max 2).Count | Should -Be 2
    }

    It 'never suggests disabled accounts or non-servers' {
        $names = @(Find-ServerSuggestions -Directory $script:Dir -Recent @() -Text 'fs' -Max 8 | ForEach-Object Name)
        $names | Should -Not -Contain 'FSOLD.contoso.local'
        $names | Should -Not -Contain 'WS-FS9.contoso.local'
    }

    It 'adds Recent names marked "searched before" without repeating a suggested one' {
        $s = @(Find-ServerSuggestions -Directory $script:Dir -Recent @('fs01.contoso.local, FS-BRANCH', 'APP01') -Text 'fs' -Max 8)
        $branch = @($s | Where-Object Name -eq 'FS-BRANCH')
        $branch.Count | Should -Be 1
        $branch[0].Detail | Should -Be 'searched before'
        @($s | Where-Object { $_.Name -eq 'FS01.contoso.local' -or $_.Name -eq 'fs01.contoso.local' }).Count | Should -Be 1
        @($s | Where-Object Name -eq 'APP01').Count | Should -Be 0
    }

    It 'returns Recent matches only when the directory is empty (AD not loaded)' {
        $s = @(Find-ServerSuggestions -Directory @() -Recent @('FS-BRANCH, APP01') -Text 'app' -Max 8)
        ($s | ForEach-Object Name) -join ',' | Should -Be 'APP01'
    }

    It 'returns nothing for blank text' {
        @(Find-ServerSuggestions -Directory $script:Dir -Recent @('FS01') -Text '  ' -Max 8).Count | Should -Be 0
    }
}
