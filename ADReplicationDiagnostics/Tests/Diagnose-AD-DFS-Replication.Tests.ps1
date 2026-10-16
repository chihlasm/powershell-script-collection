<#
    Pester 5 tests for Diagnose-AD-DFS-Replication.ps1. All AD / DFSR / DFSN cmdlets are
    stubbed and mocked; the tests assert that the REAL cmdlet names are called and that the
    cmdlets the script used to call (which do not exist) are not.

    Run with Pester 5:  Invoke-Pester .\ADReplicationDiagnostics\Tests

    Real cmdlets (Microsoft Learn):
      https://learn.microsoft.com/powershell/module/dfsr/
      https://learn.microsoft.com/powershell/module/dfsn/
#>

BeforeAll {
    $script:ScriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Diagnose-AD-DFS-Replication.ps1'

    # Stubs so Pester can mock commands that are not installed here.
    function Get-ADDomain                 { [CmdletBinding()] param() }
    function Get-ADDomainController       { [CmdletBinding()] param($Filter, $Identity) }
    function Get-ADReplicationFailure     { [CmdletBinding()] param($Target, $Scope) }
    function Get-ADReplicationPartnerMetadata { [CmdletBinding()] param($Target, $Partition) }
    function Get-DfsReplicationGroup      { [CmdletBinding()] param($GroupName, [switch]$IncludeSysvol, $DomainName) }
    function Get-DfsrMember               { [CmdletBinding()] param($GroupName, $ComputerName, $DomainName) }
    function Get-DfsrConnection           { [CmdletBinding()] param($GroupName, $SourceComputerName, $DestinationComputerName, $DomainName) }
    function Get-DfsReplicatedFolder      { [CmdletBinding()] param($GroupName, $FolderName, $DomainName) }
    function Get-DfsrBacklog              { [CmdletBinding()] param($GroupName, $FolderName, $SourceComputerName, $DestinationComputerName) }
    function Get-DfsnRoot                 { [CmdletBinding()] param($Domain, $Path, $ComputerName) }
    function Get-DfsnRootTarget           { [CmdletBinding()] param($Path, $TargetPath) }
    function Get-DfsnFolder               { [CmdletBinding()] param($Path) }
    function Get-DfsnFolderTarget         { [CmdletBinding()] param($Path, $TargetPath) }
    # Names the old script called; they do not exist in any Microsoft module.
    function Get-DfsReplicationGroupMember     { [CmdletBinding()] param() }
    function Get-DfsReplicationGroupConnection { [CmdletBinding()] param() }
    function Get-DfsReplicationBacklog         { [CmdletBinding()] param() }
    function Get-DfsNamespace                  { [CmdletBinding()] param() }
    function Get-DfsReplicationTarget          { [CmdletBinding()] param() }

    . $script:ScriptPath -LoadFunctionsOnly

    function Set-HealthyEnvironmentMocks {
        Mock Import-Module {}
        Mock Get-Module { [PSCustomObject]@{ Name = $Name } } -ParameterFilter { $ListAvailable }
        Mock Get-ADDomain { [PSCustomObject]@{ DNSRoot = 'corp.local' } }
        Mock Get-ADDomainController {
            @([PSCustomObject]@{ HostName = 'dc1.corp.local' }, [PSCustomObject]@{ HostName = 'dc2.corp.local' })
        } -ParameterFilter { $Filter }
        Mock Get-ADReplicationFailure { @() }
        Mock Get-ADReplicationPartnerMetadata {
            [PSCustomObject]@{
                Partner = 'CN=NTDS Settings,CN=DC2,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=local'
                Partition = 'DC=corp,DC=local'
                LastReplicationAttempt = Get-Date
                LastReplicationSuccess = Get-Date
                ConsecutiveReplicationFailures = 0
            }
        }
        Mock Get-CimInstance { [PSCustomObject]@{ Name = 'DFSR'; State = 'Running' } }
        Mock Get-DfsReplicationGroup { @([PSCustomObject]@{ GroupName = 'RG01'; DomainName = 'corp.local'; State = 'Normal'; Description = '' }) }
        Mock Get-DfsrMember { @([PSCustomObject]@{ ComputerName = 'DC1'; DnsName = 'dc1.corp.local'; Site = 'S'; State = 'Normal' }) }
        Mock Get-DfsrConnection { @([PSCustomObject]@{ SourceComputerName = 'DC1'; DestinationComputerName = 'DC2'; Enabled = $true; State = 'Normal'; RdcEnabled = $true }) }
        Mock Get-DfsReplicatedFolder { @([PSCustomObject]@{ GroupName = 'RG01'; FolderName = 'RF01' }) }
        Mock Get-DfsrBacklog {
            Write-Verbose 'The replicated folder has a backlog of files. Replicated folder: "RF01". Count: 2400'
            [PSCustomObject]@{ FileName = 'a.txt' }
        }
        Mock Get-DfsnRoot { @([PSCustomObject]@{ Path = '\\corp.local\Public'; Type = 'Domain V2'; State = 'Online'; Description = '' }) }
        Mock Get-DfsnRootTarget { @([PSCustomObject]@{ TargetPath = '\\dc1\Public'; State = 'Online' }) }
        Mock Get-DfsnFolder { @([PSCustomObject]@{ Path = '\\corp.local\Public\Docs'; State = 'Online' }) }
        Mock Get-DfsnFolderTarget { @([PSCustomObject]@{ TargetPath = '\\fs1\Docs'; State = 'Online'; ReferralPriorityClass = 'sitecost-normal'; ReferralPriorityRank = 0 }) }
        Mock Get-DfsReplicationGroupMember {}
        Mock Get-DfsReplicationGroupConnection {}
        Mock Get-DfsReplicationBacklog {}
        Mock Get-DfsNamespace {}
        Mock Get-DfsReplicationTarget {}
        Mock Get-Service {}
    }
}

Describe 'Script header and static checks' {
    BeforeAll {
        $tokens = $null; $errors = $null
        $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$tokens, [ref]$errors)
        $script:ParseErrors = @($errors)
        $script:CommandNames = @($script:Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) |
            ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
    }

    It 'parses without errors' { $script:ParseErrors.Count | Should -Be 0 }

    It 'requires no more than PowerShell 3.0 and uses no #Requires -Modules' {
        $script:Ast.ScriptRequirements.RequiredPSVersion | Should -BeLessOrEqual ([version]'3.0')
        $script:Ast.ScriptRequirements.RequiredModules | Should -BeNullOrEmpty
    }

    It 'uses [CmdletBinding()] and OutputPath with a LogFile alias' {
        $script:Ast.ParamBlock.Attributes.TypeName.Name | Should -Contain 'CmdletBinding'
        $p = $script:Ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'OutputPath' }
        $p | Should -Not -BeNullOrEmpty
        $p.Attributes.PositionalArguments.Value | Should -Contain 'LogFile'
        $p.DefaultValue.Extent.Text | Should -Match 'Get-Location'
    }

    It 'never calls the non-existent cmdlets the old script used' {
        foreach ($bad in 'Get-DfsReplicationGroupMember', 'Get-DfsReplicationGroupConnection', 'Get-DfsReplicationBacklog', 'Get-DfsNamespace', 'Get-DfsReplicationTarget') {
            $script:CommandNames | Should -Not -Contain $bad
        }
    }

    It 'calls the real DFSR and DFSN cmdlets' {
        foreach ($good in 'Get-DfsReplicationGroup', 'Get-DfsrMember', 'Get-DfsrConnection', 'Get-DfsReplicatedFolder', 'Get-DfsnRoot', 'Get-DfsnRootTarget', 'Get-DfsnFolder', 'Get-DfsnFolderTarget') {
            $script:CommandNames | Should -Contain $good
        }
        $script:CommandNames | Should -Contain 'Get-DfsrBacklog'
    }

    It 'does not use Get-Service -ComputerName (removed in PowerShell 6+)' {
        $svc = $script:Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] -and $args[0].GetCommandName() -eq 'Get-Service' }, $true)
        @($svc).Count | Should -Be 0
    }
}

Describe 'Get-DfsrBacklogCount' {
    It 'reads the full count from the verbose stream (the cmdlet only returns 100 records)' {
        Mock Get-DfsrBacklog {
            Write-Verbose 'The replicated folder has a backlog of files. Replicated folder: "RF01". Count: 2400'
            1..100 | ForEach-Object { [PSCustomObject]@{ FileName = "f$_" } }
        }
        Get-DfsrBacklogCount -GroupName 'RG01' -FolderName 'RF01' -SourceComputerName 'A' -DestinationComputerName 'B' | Should -Be 2400
        Should -Invoke Get-DfsrBacklog -ParameterFilter { $SourceComputerName -eq 'A' -and $DestinationComputerName -eq 'B' -and $GroupName -eq 'RG01' -and $FolderName -eq 'RF01' }
    }

    It 'returns 0 when nothing is backlogged' {
        Mock Get-DfsrBacklog { }
        Get-DfsrBacklogCount -GroupName 'RG01' -FolderName 'RF01' -SourceComputerName 'A' -DestinationComputerName 'B' | Should -Be 0
    }

    It 'falls back to counting returned records when no verbose count is present' {
        Mock Get-DfsrBacklog { 1..3 | ForEach-Object { [PSCustomObject]@{ FileName = "f$_" } } }
        Get-DfsrBacklogCount -GroupName 'RG01' -FolderName 'RF01' -SourceComputerName 'A' -DestinationComputerName 'B' | Should -Be 3
    }
}

Describe 'Get-PartnerName' {
    It 'extracts the server name from an NTDS Settings DN' {
        Get-PartnerName 'CN=NTDS Settings,CN=DC2,CN=Servers,CN=Site,CN=Sites,CN=Configuration,DC=corp,DC=local' | Should -Be 'DC2'
    }
    It 'returns other values unchanged' {
        Get-PartnerName 'dc2.corp.local' | Should -Be 'dc2.corp.local'
    }
}

Describe 'Full run with mocked modules' {
    BeforeEach {
        Set-HealthyEnvironmentMocks
        $script:OutDir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    }

    It 'calls the correct DFSR / DFSN cmdlets with the correct parameters' {
        $null = & $script:ScriptPath -OutputPath $script:OutDir 6>&1

        Should -Invoke Get-DfsReplicationGroup -ParameterFilter { $IncludeSysvol -and $DomainName -eq 'corp.local' }
        Should -Invoke Get-DfsrMember -ParameterFilter { $GroupName -eq 'RG01' }
        Should -Invoke Get-DfsrConnection -ParameterFilter { $GroupName -eq 'RG01' }
        Should -Invoke Get-DfsReplicatedFolder -ParameterFilter { $GroupName -eq 'RG01' }
        Should -Invoke Get-DfsrBacklog -Times 1 -ParameterFilter {
            $GroupName -eq 'RG01' -and $FolderName -eq 'RF01' -and $SourceComputerName -eq 'DC1' -and $DestinationComputerName -eq 'DC2' }
        Should -Invoke Get-DfsnRoot -ParameterFilter { $Domain -eq 'corp.local' }
        Should -Invoke Get-DfsnRootTarget -ParameterFilter { $Path -eq '\\corp.local\Public' }
        Should -Invoke Get-DfsnFolder -ParameterFilter { $Path -eq '\\corp.local\Public\*' }
        Should -Invoke Get-DfsnFolderTarget -ParameterFilter { $Path -eq '\\corp.local\Public\Docs' }
    }

    It 'never calls the non-existent legacy cmdlets or Get-Service' {
        $null = & $script:ScriptPath -OutputPath $script:OutDir 6>&1
        Should -Invoke Get-DfsReplicationGroupMember -Times 0
        Should -Invoke Get-DfsReplicationGroupConnection -Times 0
        Should -Invoke Get-DfsReplicationBacklog -Times 0
        Should -Invoke Get-DfsNamespace -Times 0
        Should -Invoke Get-DfsReplicationTarget -Times 0
        Should -Invoke Get-Service -Times 0
    }

    It 'checks the DFSR service on every DC with CIM -ComputerName' {
        $null = & $script:ScriptPath -OutputPath $script:OutDir 6>&1
        Should -Invoke Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_Service' -and $ComputerName -eq 'dc1.corp.local' }
        Should -Invoke Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_Service' -and $ComputerName -eq 'dc2.corp.local' }
    }

    It 'passes -Target to Get-ADReplicationFailure (it is mandatory)' {
        $null = & $script:ScriptPath -OutputPath $script:OutDir 6>&1
        Should -Invoke Get-ADReplicationFailure -ParameterFilter { $Target.Count -eq 2 -and $Target -contains 'dc1.corp.local' }
    }

    It 'writes a log and CSVs to -OutputPath, with the verbose backlog count' {
        $null = & $script:ScriptPath -OutputPath $script:OutDir 6>&1
        $log = @(Get-ChildItem -LiteralPath $script:OutDir -Filter '*.log')
        $log.Count | Should -Be 1
        $text = Get-Content -LiteralPath $log[0].FullName -Raw
        $text | Should -Match '\[WARN\].*DC1 -> DC2 \[RF01\]: 2400 file'
        $csv = @(Get-ChildItem -LiteralPath $script:OutDir -Filter '*-DfsrBacklog.csv')
        $csv.Count | Should -Be 1
        (Import-Csv -LiteralPath $csv[0].FullName).BacklogCount | Should -Be '2400'
        @(Get-ChildItem -LiteralPath $script:OutDir -Filter '*-ADReplication.csv').Count | Should -Be 1
    }

    It 'accepts the old -LogFile parameter name as a file path' {
        $file = Join-Path $script:OutDir 'custom.log'
        $null = & $script:ScriptPath -LogFile $file 6>&1
        Test-Path -LiteralPath $file | Should -BeTrue
    }

    It 'keeps going when one DC cannot be queried' {
        Mock Get-CimInstance { throw 'RPC server unavailable' } -ParameterFilter { $ComputerName -eq 'dc2.corp.local' }
        Mock Get-CimInstance { [PSCustomObject]@{ Name = 'DFSR'; State = 'Running' } } -ParameterFilter { $ComputerName -eq 'dc1.corp.local' }
        $null = & $script:ScriptPath -OutputPath $script:OutDir 6>&1
        Should -Invoke Get-DfsrBacklog -Times 1
        (Get-Content -LiteralPath (Get-ChildItem -LiteralPath $script:OutDir -Filter '*.log')[0].FullName -Raw) | Should -Match 'dc2\.corp\.local: could not check DFSR service'
    }

    It 'skips the DFS halves with a warning when the DFSR and DFSN modules are missing' {
        Mock Get-Module { $null } -ParameterFilter { $ListAvailable -and ($Name -eq 'DFSR' -or $Name -eq 'DFSN') }
        $null = & $script:ScriptPath -OutputPath $script:OutDir 6>&1
        Should -Invoke Get-DfsReplicationGroup -Times 0
        Should -Invoke Get-DfsnRoot -Times 0
        (Get-Content -LiteralPath (Get-ChildItem -LiteralPath $script:OutDir -Filter '*.log')[0].FullName -Raw) | Should -Match 'DFSR PowerShell module not available'
    }
}

Describe 'ActiveDirectory module missing' {
    It 'exits 1 with install guidance' {
        Mock Import-Module { throw 'module not found' }
        $out = & $script:ScriptPath -OutputPath $TestDrive 6>&1 | Out-String
        $LASTEXITCODE | Should -Be 1
        $out | Should -Match '\[FAIL\]'
        $out | Should -Match 'RSAT'
    }
}
