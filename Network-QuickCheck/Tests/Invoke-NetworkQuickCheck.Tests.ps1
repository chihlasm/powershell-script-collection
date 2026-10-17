<#
    Tests for Invoke-NetworkQuickCheck.ps1 (Pester 5; runs under Windows PowerShell 5.1 and 7.x).

    DNS, ping, port and route lookups are mocked for the verdict tests. Test-TcpPort itself is
    exercised for real against a listener on 127.0.0.1, so the timeout and endpoint handling
    are proven without touching the network.

    Run:  Invoke-Pester .\Network-QuickCheck\Tests
#>

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:ScriptPath = Join-Path $script:Root 'Invoke-NetworkQuickCheck.ps1'
    . $script:ScriptPath -LoadFunctionsOnly

    function Set-ReachableTarget {
        Mock Resolve-TargetName { [PSCustomObject]@{ Name = 'filesrv01.contoso.com'; Type = 'A'; IPAddress = '10.0.0.5'; NameHost = '' } }
        Mock Test-Connection { $true }
        Mock Test-TcpPort { [PSCustomObject]@{ Succeeded = $true; LocalAddress = '10.0.0.20:50000'; RemoteAddress = "10.0.0.5:$Port"; Error = '' } }
        Mock Get-NetRoute { [PSCustomObject]@{ DestinationPrefix = '0.0.0.0/0'; NextHop = '10.0.0.1'; InterfaceAlias = 'Ethernet'; RouteMetric = 0; ifIndex = 4 } }
    }

    function Get-Evidence($Result, [string]$Name) { @($Result.Evidence | Where-Object { $_.Name -eq $Name }) }
}

Describe 'Verdict' {
    BeforeEach { Set-ReachableTarget }

    It 'answers YES when DNS, ping and the port all work' {
        $r = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445
        $r.Status | Should -Be 'Pass'
        $r.Answer | Should -Be 'YES'
        (Get-Evidence $r 'Port 445 (file shares (SMB))').Status | Should -Be 'Pass'
    }

    It 'answers YES WITH WARNINGS when only ping is blocked (many servers block ping)' {
        Mock Test-Connection { $false }
        $r = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445
        $r.Status | Should -Be 'Warn'
        $r.Answer | Should -Be 'YES, WITH WARNINGS'
    }

    It 'answers PARTLY when one of two ports is closed' {
        Mock Test-TcpPort -ParameterFilter { $Port -eq 3389 } { [PSCustomObject]@{ Succeeded = $false; LocalAddress = ''; RemoteAddress = ''; Error = 'No answer within 3000 ms' } }
        $r = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445, 3389
        $r.Status | Should -Be 'Fail'
        $r.Answer | Should -Be 'PARTLY'
    }

    It 'answers NO when the port is closed' {
        Mock Test-TcpPort { [PSCustomObject]@{ Succeeded = $false; LocalAddress = ''; RemoteAddress = ''; Error = 'Connection refused' } }
        $r = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445
        $r.Answer | Should -Be 'NO'
        $r.Summary | Should -Match 'cannot reach filesrv01 on port 445'
    }

    It 'fails when the name is not in DNS' {
        Mock Resolve-TargetName { throw 'filesrv99 : DNS name does not exist' }
        $r = Invoke-NetworkQuickCheck -TargetAddress filesrv99 -Port 445
        (Get-Evidence $r 'Name lookup (DNS)').Status | Should -Be 'Fail'
    }

    It 'tests each port only once' {
        $null = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445, 445, 3389
        Should -Invoke Test-TcpPort -Times 2 -Exactly
    }
}

Describe 'IP addresses skip DNS (regression: an IP used to give a misleading DNS warning)' {
    BeforeEach { Set-ReachableTarget }

    It 'does not look up an IPv4 address' {
        $r = Invoke-NetworkQuickCheck -TargetAddress 10.0.0.5 -Port 445
        Should -Invoke Resolve-TargetName -Times 0 -Exactly
        (Get-Evidence $r 'Name lookup (DNS)').Status | Should -Be 'Pass'
        $r.Answer | Should -Be 'YES'
    }

    It 'recognises an IPv6 address' {
        Test-IsIpAddress -Value 'fe80::1' | Should -BeTrue
        Test-IsIpAddress -Value 'filesrv01' | Should -BeFalse
    }
}

Describe 'Result shape (kept from the retired workbench check)' {
    It 'has the fields callers read' {
        Set-ReachableTarget
        $r = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 443
        foreach ($name in 'CheckId', 'Name', 'Category', 'Status', 'Summary', 'Evidence', 'RecommendedNextSteps', 'RawOutput', 'StartedAt', 'FinishedAt', 'Error') {
            $r.PSObject.Properties.Name | Should -Contain $name
        }
        $r.CheckId | Should -Be 'network.quick'
        $r.RawOutput.Tcp[0].TcpTestSucceeded | Should -BeTrue
    }
}

Describe 'Test-TcpPort against a real local listener' {
    BeforeAll {
        $script:Listener = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Loopback), 0
        $script:Listener.Start()
        $script:OpenPort = $script:Listener.LocalEndpoint.Port
        # A port that was free a moment ago: bind, read the number, release.
        $probe = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Loopback), 0
        $probe.Start(); $script:ClosedPort = $probe.LocalEndpoint.Port; $probe.Stop()
    }
    AfterAll { $script:Listener.Stop() }

    It 'connects to an open port and reports plain IPv4 endpoints' {
        $t = Test-TcpPort -ComputerName '127.0.0.1' -Port $script:OpenPort -TimeoutMilliseconds 2000
        $t.Succeeded | Should -BeTrue
        $t.RemoteAddress | Should -Be "127.0.0.1:$($script:OpenPort)"
    }

    It 'reports a closed port as not reachable within the timeout' {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $t = Test-TcpPort -ComputerName '127.0.0.1' -Port $script:ClosedPort -TimeoutMilliseconds 1500
        $sw.Stop()
        $t.Succeeded | Should -BeFalse
        $t.Error | Should -Not -BeNullOrEmpty
        $sw.ElapsedMilliseconds | Should -BeLessThan 5000
    }
}

Describe 'Helpers' {
    It 'shows an IPv4-mapped IPv6 endpoint as plain IPv4' {
        Format-Endpoint -Endpoint '[::ffff:140.82.112.4]:443' | Should -Be '140.82.112.4:443'
        Format-Endpoint -Endpoint '[fe80::1]:445' | Should -Be '[fe80::1]:445'
    }
    It 'names well-known ports' {
        Get-PortLabel -Port 3389 | Should -Be '3389 (Remote Desktop)'
        Get-PortLabel -Port 12345 | Should -Be '12345'
    }
}

Describe 'Report output' {
    BeforeEach { Set-ReachableTarget }

    It 'leads with the question and the answer' {
        $r = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445
        (ConvertTo-NetworkText -Result $r)[0] | Should -Be ("Can {0} reach filesrv01 on port 445?  YES" -f $env:COMPUTERNAME)
    }

    It 'writes a text file and a CSV to -OutputPath' {
        $r = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445
        $files = @(Export-NetworkReport -Result $r -OutputPath (Join-Path $TestDrive 'out'))
        $files.Count | Should -Be 2
        foreach ($f in $files) { Test-Path -LiteralPath $f | Should -BeTrue }
    }

    It 'refuses to run without a target, instead of silently testing localhost' {
        $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:ScriptPath 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 2
        $out | Should -Match 'Name the server to test'
    }
}

# =============================================================================
# SQ-010 (SQ-001 Part B): Network-QuickCheck adopts the ticket note (AC27-AC29)
#
# Expected of the script: it dot-sources its own CaseKit.ps1 (before the -LoadFunctionsOnly
# return) and defines the adapter
#     ConvertTo-NetworkQuickCheckTicketNote -Result <result> [-EvidencePaths <string[]>]
# which holds this tool's gate decisions. New-EvidenceItem gains a -NotChecked switch (stored
# as a NotChecked property, default $false). Nothing here touches the real network or the
# real clipboard: Test-Connection, Test-TcpPort, Resolve-TargetName, Get-NetRoute and
# Set-Clipboard are mocked or replaced; all files go under $TestDrive.
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
            $note = ConvertTo-NetworkQuickCheckTicketNote -Result $Result -EvidencePaths $Evidence
            [PSCustomObject]@{ Note = $note; Lines = @(ConvertTo-TicketNoteText -Note $note) }
        }
    }
    BeforeEach { Set-ReachableTarget }

    It 'AC27_NetworkGate: ping throws -> Could not check; ping answers -> Ruled out; closed port -> PROBLEM under Checked' {
        Mock Test-Connection { throw 'Testing connection to computer filesrv01 failed: No such host is known.' }
        $r = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445
        $n = Get-NoteLines $r
        @(Get-NoteSection $n.Lines 'Could not check:' | Where-Object { $_ -match '(?i)ping' }).Count | Should -BeGreaterThan 0
        @(Get-NoteSection $n.Lines 'Ruled out:' | Where-Object { $_ -match '(?i)ping' }).Count | Should -Be 0
        @(Get-NoteSection $n.Lines 'Checked:' | Where-Object { $_ -match '(?i)ping' }).Count | Should -Be 0 -Because 'a ping that could not run is not a finding'

        Mock Test-Connection { $true }
        $n = Get-NoteLines (Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445)
        @(Get-NoteSection $n.Lines 'Ruled out:' | Where-Object { $_ -match 'answered a ping' }).Count | Should -Be 1
        @(Get-NoteSection $n.Lines 'Could not check:' | Where-Object { $_ -match '(?i)ping' }).Count | Should -Be 0

        Mock Test-TcpPort -ParameterFilter { $Port -eq 445 } { [PSCustomObject]@{ Succeeded = $false; LocalAddress = ''; RemoteAddress = ''; Error = 'No answer within 3000 ms' } }
        $n = Get-NoteLines (Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445)
        @(Get-NoteSection $n.Lines 'Checked:' | Where-Object { $_ -like '- PROBLEM: *' -and $_ -match 'port 445' }).Count | Should -Be 1
        @(Get-NoteSection $n.Lines 'Ruled out:' | Where-Object { $_ -match 'port 445' }).Count | Should -Be 0
    }

    It 'NetworkMapping_PingBlocked: a ping that ran and got no answer is a WARNING under Checked, in neither other section' {
        Mock Test-Connection { $false }
        $n = Get-NoteLines (Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445)
        @(Get-NoteSection $n.Lines 'Checked:' | Where-Object { $_ -like '- WARNING: *' -and $_ -match 'did not answer a ping' }).Count | Should -Be 1
        @(Get-NoteSection $n.Lines 'Ruled out:' | Where-Object { $_ -match '(?i)ping' }).Count | Should -Be 0
        @(Get-NoteSection $n.Lines 'Could not check:' | Where-Object { $_ -match '(?i)ping' }).Count | Should -Be 0
    }

    It 'NetworkMapping_RouteReadFails: a routing table that could not be read is Could not check, not Ruled out' {
        Mock Get-NetRoute { throw 'Access denied' }
        $r = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445
        $n = Get-NoteLines $r
        @(Get-NoteSection $n.Lines 'Could not check:' | Where-Object { $_ -match 'Could not read the routing table' }).Count | Should -Be 1
        @(Get-NoteSection $n.Lines 'Ruled out:' | Where-Object { $_ -match '(?i)gateway|routing' }).Count | Should -Be 0
        $r.Status | Should -Be 'Warn' -Because 'the verdict is unchanged: the gate only moves the note'
    }

    It 'NetworkMapping_NameNotFound: a name missing from DNS is a PROBLEM under Checked' {
        Mock Resolve-TargetName { throw 'filesrv99 : DNS name does not exist' }
        $n = Get-NoteLines (Invoke-NetworkQuickCheck -TargetAddress filesrv99 -Port 445)
        @(Get-NoteSection $n.Lines 'Checked:' | Where-Object { $_ -like '- PROBLEM: *could not be found in DNS*' }).Count | Should -Be 1
    }

    It 'AC28_NetworkNoRouteCmdlet: no Get-NetRoute -> Could not check says so; verdict and exit status are unchanged' {
        $withRoute = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445
        Mock Get-Command -ParameterFilter { $Name -eq 'Get-NetRoute' } { $null }
        $r = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445
        $n = Get-NoteLines $r
        $could = Get-NoteSection $n.Lines 'Could not check:'
        $could | Should -Contain '- Default gateway: not checked (this Windows version has no Get-NetRoute)'
        @(Get-NoteSection $n.Lines 'Ruled out:' | Where-Object { $_ -match '(?i)gateway' }).Count | Should -Be 0
        $r.Status | Should -Be $withRoute.Status
        $r.Answer | Should -Be $withRoute.Answer
        @($r.Evidence | Where-Object { $_.Name -eq 'Default gateway' }).Count | Should -Be 0 -Because 'the note-only item must not become a new evidence item (it would change the verdict)'
    }

    It 'AC29_NetworkIpTarget: an IP target leaves the name-lookup item out of Ruled out and Could not check, and the scope line says so' {
        $n = Get-NoteLines (Invoke-NetworkQuickCheck -TargetAddress 10.0.0.5 -Port 445)
        @(Get-NoteSection $n.Lines 'Ruled out:' | Where-Object { $_ -match '(?i)name lookup|dns' }).Count | Should -Be 0
        @(Get-NoteSection $n.Lines 'Could not check:' | Where-Object { $_ -match '(?i)name lookup|dns' }).Count | Should -Be 0
        $checked = Get-NoteSection $n.Lines 'Checked:'
        $checked[0] | Should -Match '(?i)no name lookup was needed'
    }

    It 'NetworkMapping_HeadlineStampSteps: headline names the tool and answer, stamp is Computer scope, next steps are the existing ones' {
        $r = Invoke-NetworkQuickCheck -TargetAddress filesrv01 -Port 445 -TimeoutMilliseconds 1000
        $n = Get-NoteLines $r @('C:\x\NetworkQuickCheck_filesrv01_2026-10-17_090000.txt', 'C:\x\NetworkQuickCheck_filesrv01_2026-10-17_090000.csv')
        $n.Lines[0] | Should -BeLike '[[]Ticket note] Network-QuickCheck: *YES*'
        $stamp = @($n.Lines | Where-Object { $_ -like 'Computer: *' })[0]
        $stamp | Should -BeLike "Computer: $($env:COMPUTERNAME) | *"
        $stamp | Should -BeLike '*Changed anything: No'
        $steps = Get-NoteSection $n.Lines 'Next step:'
        $steps | Should -Contain ('- ' + $r.RecommendedNextSteps[0])
        $n.Lines | Should -Contain 'Evidence: NetworkQuickCheck_filesrv01_2026-10-17_090000.txt, NetworkQuickCheck_filesrv01_2026-10-17_090000.csv'
    }

    It 'NetworkMapping_NotCheckedProperty: New-EvidenceItem has -NotChecked, stored as NotChecked and false by default' {
        (New-EvidenceItem -Name 'x' -Status 'Warn' -Detail 'd').NotChecked | Should -BeFalse
        (New-EvidenceItem -Name 'x' -Status 'Warn' -Detail 'd' -NotChecked).NotChecked | Should -BeTrue
    }
}

# The script itself, run in-process. Everything that would reach out is replaced:
#  - cmdlets (Test-Connection, Get-NetRoute, Set-Clipboard) are Pester mocks;
#  - the script's own functions (Test-TcpPort, Resolve-TargetName, the kit's
#    Invoke-WinFormsClipboard and Get-TicketNoteDefaultRoot) are shadowed by GLOBAL ALIASES,
#    because an alias outranks a function, and a function the script defines in its own scope
#    would otherwise outrank a Pester mock. The aliases are removed after every test.
Describe 'ticket note (script, in-process)' {
    BeforeAll {
        function global:NqcFake-TcpPort { param($ComputerName, $Port, $TimeoutMilliseconds)
            if ($global:NqcTcpOk) { [PSCustomObject]@{ Succeeded = $true; LocalAddress = '10.0.0.20:50000'; RemoteAddress = "10.0.0.5:$Port"; Error = '' } }
            else { [PSCustomObject]@{ Succeeded = $false; LocalAddress = ''; RemoteAddress = ''; Error = 'No answer within 3000 ms' } }
        }
        function global:NqcFake-Resolve { param($Name) [PSCustomObject]@{ Name = "$Name.contoso.com"; Type = 'A'; IPAddress = '10.0.0.5'; NameHost = '' } }
        function global:NqcFake-Clipboard { param($Text) }
        function global:NqcFake-DefaultRoot { $global:NqcRoot }
        function global:NqcFake-Throw { throw 'simulated note failure' }
        $script:AliasNames = 'Test-TcpPort', 'Resolve-TargetName', 'Invoke-WinFormsClipboard', 'Get-TicketNoteDefaultRoot', 'ConvertTo-NetworkQuickCheckTicketNote'
        function Clear-NqcAliases { foreach ($a in $script:AliasNames) { Remove-Item -LiteralPath "Alias:\$a" -Force -ErrorAction SilentlyContinue } }
        function Invoke-Nqc([hashtable]$Splat, [string]$Path = $script:ScriptPath) {
            $global:LASTEXITCODE = 0
            $out = @(& $Path @Splat *>&1)
            [PSCustomObject]@{ ExitCode = $global:LASTEXITCODE; Out = $out; Text = (@($out | ForEach-Object { "$_" }) -join "`n") }
        }
    }
    BeforeEach {
        $global:NqcTcpOk = $true
        $global:NqcRoot = Join-Path $TestDrive 'defaultroot'
        Set-Alias -Name Test-TcpPort -Value NqcFake-TcpPort -Scope Global
        Set-Alias -Name Resolve-TargetName -Value NqcFake-Resolve -Scope Global
        Set-Alias -Name Invoke-WinFormsClipboard -Value NqcFake-Clipboard -Scope Global
        Set-Alias -Name Get-TicketNoteDefaultRoot -Value NqcFake-DefaultRoot -Scope Global
        Mock Test-Connection { $true }
        Mock Get-NetRoute { [PSCustomObject]@{ DestinationPrefix = '0.0.0.0/0'; NextHop = '10.0.0.1'; InterfaceAlias = 'Ethernet'; RouteMetric = 0; ifIndex = 4 } }
        Mock Set-Clipboard { }
    }
    AfterEach { Clear-NqcAliases }
    AfterAll {
        Clear-NqcAliases
        Remove-Item -LiteralPath Function:\NqcFake-TcpPort, Function:\NqcFake-Resolve, Function:\NqcFake-Clipboard, Function:\NqcFake-DefaultRoot, Function:\NqcFake-Throw -ErrorAction SilentlyContinue
    }

    It 'loading the functions also loads the kit (the adapter can call New-TicketNote)' {
        $loaded = & { . $script:ScriptPath -LoadFunctionsOnly; [bool](Get-Command New-TicketNote -ErrorAction SilentlyContinue) }
        $loaded | Should -BeTrue
    }

    It 'Wiring_Clipboard: -NoClipboard and -Quiet skip the clipboard; the default copies exactly once' {
        $null = Invoke-Nqc @{ TargetAddress = 'filesrv01'; Port = 445; NoClipboard = $true }
        Should -Invoke Set-Clipboard -Times 0 -Exactly
        $null = Invoke-Nqc @{ TargetAddress = 'filesrv01'; Port = 445; Quiet = $true }
        Should -Invoke Set-Clipboard -Times 0 -Exactly
        $null = Invoke-Nqc @{ TargetAddress = 'filesrv01'; Port = 445 }
        Should -Invoke Set-Clipboard -Times 1 -Exactly
    }

    It 'Wiring_TicketFolder: -TicketNumber puts the reports and the note in Ticket_<n>, and the note names the reports' {
        $root = Join-Path $TestDrive 'ticket'
        $null = New-Item -ItemType Directory -Path $root
        $null = Invoke-Nqc @{ TargetAddress = 'filesrv01'; Port = 445; TicketNumber = '482113'; OutputPath = $root; NoClipboard = $true }
        $dir = Join-Path $root 'Ticket_482113'
        $txt = @(Get-ChildItem -LiteralPath $dir -Filter 'NetworkQuickCheck_*.txt' -ErrorAction SilentlyContinue)
        $csv = @(Get-ChildItem -LiteralPath $dir -Filter 'NetworkQuickCheck_*.csv' -ErrorAction SilentlyContinue)
        $note = @(Get-ChildItem -LiteralPath $dir -Filter 'Note_*_Network-QuickCheck.txt' -ErrorAction SilentlyContinue)
        $txt.Count | Should -Be 1
        $csv.Count | Should -Be 1
        $note.Count | Should -Be 1
        $text = [System.IO.File]::ReadAllText($note[0].FullName)
        $text | Should -Match ([regex]::Escape($txt[0].Name))
        $text | Should -Match ([regex]::Escape($csv[0].Name))
    }

    It 'Wiring_OnlyOutputPath: with just -OutputPath the note is saved beside the reports' {
        $root = Join-Path $TestDrive 'beside'
        $null = Invoke-Nqc @{ TargetAddress = 'filesrv01'; Port = 445; OutputPath = $root; NoClipboard = $true }
        @(Get-ChildItem -LiteralPath $root -Filter 'Note_*_Network-QuickCheck.txt' -ErrorAction SilentlyContinue).Count | Should -Be 1
    }

    It 'Wiring_BadTicketNumber: a mistyped -TicketNumber gets a plain [FAIL] line and exit 3, before any check, and no clipboard' {
        $x = Invoke-Nqc @{ TargetAddress = 'filesrv01'; Port = 445; TicketNumber = '..\x'; OutputPath = $TestDrive }
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

    It 'Wiring_PasteSafeDefault: the saved note hides IP addresses (except in the headline); -FullDetail keeps them (D-009)' {
        $safe = Join-Path $TestDrive 'safe'
        $full = Join-Path $TestDrive 'full'
        $null = Invoke-Nqc @{ TargetAddress = 'filesrv01'; Port = 445; OutputPath = $safe; NoClipboard = $true }
        $null = Invoke-Nqc @{ TargetAddress = 'filesrv01'; Port = 445; OutputPath = $full; NoClipboard = $true; FullDetail = $true }
        $safeLines = @([System.IO.File]::ReadAllLines((Get-ChildItem -LiteralPath $safe -Filter 'Note_*.txt')[0].FullName))
        $fullLines = @([System.IO.File]::ReadAllLines((Get-ChildItem -LiteralPath $full -Filter 'Note_*.txt')[0].FullName))
        ($safeLines | Select-Object -Skip 2) -join "`n" | Should -Not -Match '10\.0\.0\.5'
        ($safeLines | Select-Object -Skip 2) -join "`n" | Should -Match '\[IP removed\]'
        ($fullLines | Select-Object -Skip 2) -join "`n" | Should -Match '10\.0\.0\.5'
    }

    It 'Wiring_ClipboardIsPasteSafe: the clipboard text is redacted by default' {
        $null = Invoke-Nqc @{ TargetAddress = 'filesrv01'; Port = 445 }
        Should -Invoke Set-Clipboard -Times 1 -Exactly -ParameterFilter { $Value -notmatch '10\.0\.0\.5' -and $Value -match '\[Ticket note\] Network-QuickCheck' }
    }

    It 'Wiring_ExitCodesUnchanged: with the note on, exit is 0 when reachable, 1 on a warning, 2 when the port is closed' {
        (Invoke-Nqc @{ TargetAddress = 'filesrv01'; Port = 445; NoClipboard = $true }).ExitCode | Should -Be 0
        Mock Test-Connection { $false }
        (Invoke-Nqc @{ TargetAddress = 'filesrv01'; Port = 445; NoClipboard = $true }).ExitCode | Should -Be 1
        $global:NqcTcpOk = $false
        (Invoke-Nqc @{ TargetAddress = 'filesrv01'; Port = 445; NoClipboard = $true }).ExitCode | Should -Be 2
    }

    It 'Wiring_NoteFailureKeepsExitCode: if building the note throws, the check still reports and exits as before' {
        Set-Alias -Name ConvertTo-NetworkQuickCheckTicketNote -Value NqcFake-Throw -Scope Global
        $x = Invoke-Nqc @{ TargetAddress = 'filesrv01'; Port = 445 }
        $x.ExitCode | Should -Be 0
        $x.Text | Should -Match '\[WARN\] Could not make the ticket note'
        Should -Invoke Set-Clipboard -Times 0 -Exactly
        $global:NqcTcpOk = $false
        (Invoke-Nqc @{ TargetAddress = 'filesrv01'; Port = 445 }).ExitCode | Should -Be 2
    }

    It 'Wiring_UnwritableFolderKeepsExitCode: a ticket folder that cannot be made is a warning, not a different exit code' {
        $blocker = Join-Path $TestDrive 'iamafile'
        Set-Content -LiteralPath $blocker -Value 'x'
        $x = Invoke-Nqc @{ TargetAddress = 'filesrv01'; Port = 445; TicketNumber = '482113'; OutputPath = $blocker; NoClipboard = $true }
        $x.ExitCode | Should -Be 0
        $x.Text | Should -Match '\[WARN\]'
    }

    It 'Wiring_PassThru: -PassThru -Quiet returns the result with a TicketNote and writes nothing to the host' {
        $x = Invoke-Nqc @{ TargetAddress = 'filesrv01'; Port = 445; PassThru = $true; Quiet = $true }
        $res = @($x.Out | Where-Object { $_ -is [pscustomobject] -and $_.PSObject.Properties['CheckId'] })
        $res.Count | Should -Be 1
        foreach ($name in 'CheckId', 'Status', 'Answer', 'Summary', 'Evidence', 'RecommendedNextSteps', 'RawOutput', 'TicketNote') { $res[0].PSObject.Properties.Name | Should -Contain $name }
        $res[0].TicketNote.Tool | Should -Be 'Network-QuickCheck'
        @($x.Out | Where-Object { $_ -isnot [pscustomobject] }).Count | Should -Be 0
        Should -Invoke Set-Clipboard -Times 0 -Exactly
    }

    It 'Wiring_MissingKit: without CaseKit.ps1 next to it, the tool runs as today and says there is no note' {
        $dir = Join-Path $TestDrive 'nokit'
        $null = New-Item -ItemType Directory -Path $dir
        Copy-Item -LiteralPath $script:ScriptPath -Destination $dir
        $copy = Join-Path $dir 'Invoke-NetworkQuickCheck.ps1'
        $x = Invoke-Nqc @{ TargetAddress = 'filesrv01'; Port = 445 } $copy
        $x.ExitCode | Should -Be 0
        $x.Text | Should -Match '\[WARN\] CaseKit\.ps1 is missing from this folder - no ticket note this time\.'
        Should -Invoke Set-Clipboard -Times 0 -Exactly
    }
}
