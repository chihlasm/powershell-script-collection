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

Describe 'Server list' {
    BeforeAll {
        $script:Local = @('APP02', 'app02.contoso.local', 'localhost', '.', '127.0.0.1', '::1')
        $script:Dir = @(New-FakeDirectory)
        function New-List { New-Object 'System.Collections.ObjectModel.ObservableCollection[object]' }
    }

    It 'adds each name from pasted text, in order' {
        $items = New-List
        $added = @(Add-ServerListItems -Items $items -Names @("FS01, FS02`nFS03") -LocalNames $script:Local)
        ($items | ForEach-Object Name) -join ',' | Should -Be 'FS01,FS02,FS03'
        $added -join ',' | Should -Be 'FS01,FS02,FS03'
    }

    It 'turns every name for this computer into one row noted "this computer"' {
        $items = New-List
        $null = Add-ServerListItems -Items $items -Names @('localhost', '127.0.0.1', '.', 'app02.contoso.local', 'APP02') -LocalNames $script:Local
        $items.Count | Should -Be 1
        $items[0].Name | Should -Be 'APP02'
        $items[0].IsLocal | Should -BeTrue
        Update-ServerListNote -Item $items[0] -Directory $script:Dir -LoadedDomain 'contoso.local' -Lookup $null
        $items[0].Note | Should -Be 'this computer'
    }

    It 'strips a DOMAIN\ prefix and skips a name already in the list (any case)' {
        $items = New-List
        $null = Add-ServerListItems -Items $items -Names @('CONTOSO\FS01') -LocalNames $script:Local
        $items[0].Name | Should -Be 'FS01'
        @(Add-ServerListItems -Items $items -Names @('fs01') -LocalNames $script:Local).Count | Should -Be 0
        $items.Count | Should -Be 1
    }

    It 'notes domain controllers, disabled accounts and the OS from AD' {
        $dc = New-ServerListItem -Name 'DC01.contoso.local' -LocalNames $script:Local
        Update-ServerListNote -Item $dc -Directory $script:Dir -LoadedDomain 'contoso.local' -Lookup $null
        $dc.Note | Should -Be 'domain controller'
        $old = New-ServerListItem -Name 'FSOLD' -LocalNames $script:Local
        Update-ServerListNote -Item $old -Directory $script:Dir -LoadedDomain 'contoso.local' -Lookup $null
        $old.Note | Should -Be 'disabled in AD'
        $old.NoteKind | Should -Be 'Warn'
        $fs = New-ServerListItem -Name 'fs02' -LocalNames $script:Local
        Update-ServerListNote -Item $fs -Directory $script:Dir -LoadedDomain 'contoso.local' -Lookup $null
        $fs.Note | Should -Be 'Windows Server 2012 R2 Standard'
        $fs.NoteKind | Should -Be 'Info'
    }

    It 'says "not in AD" only for short names and names in the loaded domain' {
        $a = New-ServerListItem -Name 'FS9' -LocalNames $script:Local
        Update-ServerListNote -Item $a -Directory $script:Dir -LoadedDomain 'contoso.local' -Lookup $null
        $a.Note | Should -Be 'not in AD'
        $a.NoteKind | Should -Be 'Warn'
        $b = New-ServerListItem -Name 'fs9.contoso.local' -LocalNames $script:Local
        Update-ServerListNote -Item $b -Directory $script:Dir -LoadedDomain 'contoso.local' -Lookup $null
        $b.Note | Should -Be 'not in AD'
        $c = New-ServerListItem -Name 'fs9.fabrikam.com' -LocalNames $script:Local
        Update-ServerListNote -Item $c -Directory $script:Dir -LoadedDomain 'contoso.local' -Lookup $null
        $c.Note | Should -Be ''
        $d = New-ServerListItem -Name 'FS9' -LocalNames $script:Local
        Update-ServerListNote -Item $d -Directory @() -LoadedDomain '' -Lookup $null
        $d.Note | Should -Be ''
    }

    It 'searches the DNS name of an IP only when it looks back up to the same IP' {
        $ip = New-ServerListItem -Name '10.0.4.21' -LocalNames $script:Local
        $ip.IsIp | Should -BeTrue
        Update-ServerListNote -Item $ip -Directory $script:Dir -LoadedDomain 'contoso.local' -Lookup $null
        $ip.Note | Should -Be ''
        $ip.Lookup | Should -Be 'Pending'
        Update-ServerListNote -Item $ip -Directory $script:Dir -LoadedDomain 'contoso.local' -Lookup ([PSCustomObject]@{ Name = '10.0.4.21'; IsIp = $true; PtrName = 'SQL01.contoso.local'; ForwardMatches = $true })
        $ip.Display | Should -Be '10.0.4.21 → SQL01.contoso.local'
        $ip.SearchName | Should -Be 'SQL01.contoso.local'
        $ip.Lookup | Should -Be 'Done'

        $stale = New-ServerListItem -Name '10.0.4.22' -LocalNames $script:Local
        Update-ServerListNote -Item $stale -Directory $script:Dir -LoadedDomain 'contoso.local' -Lookup ([PSCustomObject]@{ Name = '10.0.4.22'; IsIp = $true; PtrName = 'OLD01.contoso.local'; ForwardMatches = $false })
        $stale.Note | Should -Be "IP · name doesn't match"
        $stale.NoteKind | Should -Be 'Warn'
        $stale.SearchName | Should -Be '10.0.4.22'

        $none = New-ServerListItem -Name '10.0.4.23' -LocalNames $script:Local
        Update-ServerListNote -Item $none -Directory $script:Dir -LoadedDomain 'contoso.local' -Lookup ([PSCustomObject]@{ Name = '10.0.4.23'; IsIp = $true; PtrName = ''; ForwardMatches = $false })
        $none.Note | Should -Be 'IP · no name found'
        $none.SearchName | Should -Be '10.0.4.23'
    }

    It 'builds the server text the search reads' {
        $fs = New-ServerListItem -Name 'FS01' -LocalNames $script:Local
        $ip = New-ServerListItem -Name '10.0.4.21' -LocalNames $script:Local
        Update-ServerListNote -Item $ip -Directory @() -LoadedDomain '' -Lookup ([PSCustomObject]@{ Name = '10.0.4.21'; IsIp = $true; PtrName = 'SQL01.contoso.local'; ForwardMatches = $true })
        Get-ServerSearchText -Items @($fs, $ip) | Should -Be 'FS01, SQL01.contoso.local'
    }

    It 'recognises IP addresses' {
        Test-IpAddress -Text '10.0.4.21' | Should -BeTrue
        Test-IpAddress -Text 'fe80::1' | Should -BeTrue
        Test-IpAddress -Text '5' | Should -BeFalse
        Test-IpAddress -Text 'FS01' | Should -BeFalse
    }
}

Describe 'Reading a server list file' {
    It 'reads a .txt, one name per line, skipping blank lines and # comments' {
        $p = Join-Path $TestDrive 'servers.txt'
        Set-Content -LiteralPath $p -Value @('# Contoso servers', 'FS01', '', '  10.0.4.21  ', '#old', 'CONTOSO\APP02') -Encoding UTF8
        $r = Read-ServerListFile -Path $p
        $r.Names -join ',' | Should -Be 'FS01,10.0.4.21,APP02'
        $r.NeedsColumn | Should -BeFalse
    }

    It 'reads a UTF-8 CSV with a BOM and quoted values from the Name column' {
        $p = Join-Path $TestDrive 'servers.csv'
        [System.IO.File]::WriteAllText($p, "`"Name`",`"OperatingSystem`"`r`n`"CONTOSO\FS01`",`"Windows Server 2019`"`r`n`"FS02`",`"Windows Server 2022`"`r`n", (New-Object System.Text.UTF8Encoding $true))
        $r = Read-ServerListFile -Path $p
        $r.Column | Should -Be 'Name'
        $r.Names -join ',' | Should -Be 'FS01,FS02'
    }

    It 'asks for the column when no header is a known one, then reads the one chosen' {
        $p = Join-Path $TestDrive 'hosts.csv'
        Set-Content -LiteralPath $p -Value @('Host,Site', 'SRV-A,London', 'SRV-B,Leeds') -Encoding UTF8
        $r = Read-ServerListFile -Path $p
        $r.NeedsColumn | Should -BeTrue
        $r.Headers -join ',' | Should -Be 'Host,Site'
        @($r.Names).Count | Should -Be 0
        (Read-ServerListFile -Path $p -Column 'Host').Names -join ',' | Should -Be 'SRV-A,SRV-B'
    }

    It 'picks the names column in a fixed order, ignoring case' {
        Select-ServerNameColumn -Headers @('ipaddress', 'dnshostname') | Should -Be 'dnshostname'
        Select-ServerNameColumn -Headers @('Site', 'Owner') | Should -Be ''
    }

    It 'refuses other kinds of file with a plain message' {
        $p = Join-Path $TestDrive 'servers.xlsx'
        Set-Content -LiteralPath $p -Value 'x'
        { Read-ServerListFile -Path $p } | Should -Throw '*.txt or .csv*'
    }
}

Describe 'Background AD load and DNS lookups' {
    BeforeAll {
        function Wait-Job2 {
            param([scriptblock]$Receive)
            $sw = [Diagnostics.Stopwatch]::StartNew()
            while ($sw.Elapsed.TotalSeconds -lt 10) {
                $r = & $Receive
                if ($null -ne $r) { return $r }
                Start-Sleep -Milliseconds 50
            }
            throw 'the background job did not finish within 10 seconds'
        }
    }

    It 'returns the loaded servers and the generation it was started with' {
        $loader = { param($ListPath, $Server, $Credential) @{ Domain = 'contoso.local'; Entries = @([PSCustomObject]@{ Name = 'FS01' }) } }
        $job = Start-DirectoryLoad -Server '' -Credential $null -Generation 7 -Loader $loader
        $r = Wait-Job2 { Receive-DirectoryLoad -Job $job }
        $r.Ok | Should -BeTrue
        $r.Domain | Should -Be 'contoso.local'
        $r.Generation | Should -Be 7
        @($r.Entries)[0].Name | Should -Be 'FS01'
    }

    It 'reports why the load failed' {
        $job = Start-DirectoryLoad -Server '' -Credential $null -Generation 1 -Loader { param($ListPath, $Server, $Credential) throw 'The server is not operational' }
        $r = Wait-Job2 { Receive-DirectoryLoad -Job $job }
        $r.Ok | Should -BeFalse
        $r.Error | Should -BeLike '*not operational*'
    }

    It 'passes the chosen domain or DC to the loader' {
        $job = Start-DirectoryLoad -Server 'dc01.contoso.local' -Credential $null -Generation 1 -Loader { param($ListPath, $Server, $Credential) @{ Domain = $Server; Entries = @() } }
        (Wait-Job2 { Receive-DirectoryLoad -Job $job }).Domain | Should -Be 'dc01.contoso.local'
    }

    It 'gives the loader the path of this file, so it can build directory entries' {
        $job = Start-DirectoryLoad -Server '' -Credential $null -Generation 1 -Loader { param($ListPath, $Server, $Credential) @{ Domain = $ListPath; Entries = @() } }
        (Wait-Job2 { Receive-DirectoryLoad -Job $job }).Domain | Should -BeLike '*ServerEventTimeline.ServerList.ps1'
    }

    It 'returns DNS results keyed by name' {
        $lookup = { param($Names) foreach ($n in $Names) { @{ Name = $n; IsIp = $false; Resolves = ($n -eq 'FS01') } } }
        $job = Start-NameLookups -Names @('FS01', 'NOPE') -Lookup $lookup
        $r = Wait-Job2 { Receive-NameLookups -Job $job }
        $r['FS01'].Resolves | Should -BeTrue
        $r['NOPE'].Resolves | Should -BeFalse
    }
}
