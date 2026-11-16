<#
    The module must load and give the same answers on Windows PowerShell 5.1 and PowerShell 7,
    with nothing installed beyond PowerShell itself for this phase.

    The suite runs under PowerShell 7 (Pester 5). The 5.1 checks start powershell.exe as a
    child process against files under $TestDrive; they read no machine state and contact
    nothing.
#>

BeforeDiscovery {
    $script:HasWindowsPowerShell = [bool](Get-Command powershell.exe -ErrorAction SilentlyContinue)
    $srcRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'src'
    $script:SourceFiles = @(
        Get-ChildItem -Path $srcRoot -Recurse -File -Include '*.ps1', '*.psm1', '*.psd1' |
            ForEach-Object { @{ Name = $_.FullName.Substring($srcRoot.Length + 1); Path = $_.FullName } }
    )
    $script:ExportedFunctions = @(
        @{ Function = 'Import-OrrClientConfig' }, @{ Function = 'Test-OrrSpec' },
        @{ Function = 'Test-OrrKql' }, @{ Function = 'New-OrrKqlQuery' }
    )
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:OrrModulePath -Force
}

AfterAll {
    Remove-Module ORR.Core -ErrorAction SilentlyContinue
}

Describe 'Module manifest' {

    It 'is a valid manifest that targets 5.1 and both editions' {
        $manifest = Test-ModuleManifest -Path $script:OrrModulePath -ErrorAction Stop
        $manifest.PowerShellVersion | Should -Be ([version]'5.1')
        $manifest.CompatiblePSEditions | Should -Contain 'Desktop'
        $manifest.CompatiblePSEditions | Should -Contain 'Core'
    }

    It 'does not list required modules, so a missing Graph module cannot block loading' {
        (Import-PowerShellDataFile -Path $script:OrrModulePath).ContainsKey('RequiredModules') | Should -BeFalse
    }

    It 'exports exactly the documented functions' {
        @((Get-Module ORR.Core).ExportedFunctions.Keys | Sort-Object) |
            Should -Be @('Import-OrrClientConfig', 'New-OrrKqlQuery', 'Test-OrrKql', 'Test-OrrSpec')
        @((Get-Module ORR.Core).ExportedCmdlets.Keys).Count | Should -Be 0
        @((Get-Module ORR.Core).ExportedAliases.Keys).Count | Should -Be 0
    }

    It 'uses only approved verbs' {
        $approved = (Get-Verb).Verb
        foreach ($name in (Get-Module ORR.Core).ExportedFunctions.Keys) {
            $approved | Should -Contain ($name -split '-')[0]
        }
    }
}

Describe 'Comment-based help on <Function>' -ForEach $script:ExportedFunctions {

    BeforeAll {
        $script:Help = Get-Help -Name $Function -Full
        $script:Command = Get-Command -Name $Function
    }

    It 'has a synopsis and a description' {
        $script:Help.Synopsis | Should -Not -BeNullOrEmpty
        $script:Help.Synopsis | Should -Not -Match "^\s*$Function\s"
        ($script:Help.description | Out-String).Trim() | Should -Not -BeNullOrEmpty
    }

    It 'has at least one example' {
        @($script:Help.examples.example).Count | Should -BeGreaterThan 0
    }

    It 'describes every parameter' {
        $common = [System.Management.Automation.PSCmdlet]::CommonParameters + [System.Management.Automation.PSCmdlet]::OptionalCommonParameters
        foreach ($parameter in $script:Command.Parameters.Keys | Where-Object { $common -notcontains $_ }) {
            $text = ($script:Help.parameters.parameter | Where-Object name -eq $parameter).description | Out-String
            $text.Trim() | Should -Not -BeNullOrEmpty -Because "-$parameter needs a .PARAMETER entry"
        }
    }
}

Describe 'Source file <Name>' -ForEach $script:SourceFiles {

    It 'is plain ASCII, so Windows PowerShell reads it the same with or without a BOM' {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }

    It 'parses without errors' {
        $tokens = $null
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        $errors | Should -BeNullOrEmpty
    }

    It 'uses no PowerShell 7-only syntax or cmdlets' {
        $text = [System.IO.File]::ReadAllText($Path)
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        # Ternary, null-coalescing, pipeline chain operators and null-conditional access.
        @($ast.FindAll({ param($node) $node.GetType().Name -in 'TernaryExpressionAst', 'PipelineChainAst' }, $true)).Count | Should -Be 0
        @($tokens | Where-Object { "$($_.Kind)" -in 'QuestionQuestion', 'QuestionQuestionEquals', 'QuestionDot', 'QuestionLBracket' }).Count | Should -Be 0
        $text | Should -Not -Match '(?i)\bTest-Json\b(?!,)\s+-'
        $text | Should -Not -Match '(?i)-AsHashtable\b'
        $text | Should -Not -Match '(?i)ForEach-Object\s+-Parallel'
    }
}

Describe 'Windows PowerShell 5.1 gives the same answers as PowerShell 7' -Skip:(-not $script:HasWindowsPowerShell) {

    BeforeAll {
        $script:ConfigPath = Join-Path $TestDrive 'clients-51.json'
        [System.IO.File]::WriteAllText($script:ConfigPath, (New-OrrTestClientJson))

        # One custodian (a one-item list), a keyword with curly quotes, and a site.
        $phrase = [char]0x201C + 'road repair' + [char]0x201D
        $spec = New-OrrTestSpec -Set @{
            custodians = @('Clerk@Contoso.gov')
            keywords   = @('budget', $phrase, 'rfp*', 'and')
            locations  = @('exchange', 'onedrive', 'teams', 'sharepoint')
            sites      = @('https://contoso.sharepoint.com/sites/PublicWorks')
        }
        $script:GoodSpecPath = Join-Path $TestDrive 'good.json'
        [System.IO.File]::WriteAllText($script:GoodSpecPath, (ConvertTo-OrrTestJson $spec), (New-Object System.Text.UTF8Encoding $false))

        $bad = New-OrrTestSpec -Set @{ ticketNumber = '12'; custodians = @('x@evil.example'); dateEnd = '2023-01-01'; purge = $true }
        $script:BadSpecPath = Join-Path $TestDrive 'bad.json'
        [System.IO.File]::WriteAllText($script:BadSpecPath, (ConvertTo-OrrTestJson $bad), (New-Object System.Text.UTF8Encoding $false))

        $script:ProbePath = Join-Path $TestDrive 'probe.ps1'
        [System.IO.File]::WriteAllText($script:ProbePath, @'
param([string]$ModulePath, [string]$ConfigPath, [string]$GoodSpecPath, [string]$BadSpecPath)
$ErrorActionPreference = 'Stop'
Import-Module $ModulePath -Force
$clients = Import-OrrClientConfig -Path $ConfigPath
$good = Test-OrrSpec -Json ([System.IO.File]::ReadAllText($GoodSpecPath)) -ClientConfig $clients
$kql = $null
if ($good.IsValid) { $kql = (New-OrrKqlQuery -Spec $good.Spec -ClientConfig $clients).Kql }
$bad = Test-OrrSpec -Json ([System.IO.File]::ReadAllText($BadSpecPath)) -ClientConfig $clients
# Text the two built-in JSON parsers read differently; the module must not.
$goodText = [System.IO.File]::ReadAllText($GoodSpecPath)
$odd = @(
    $goodText.Replace('123456', '0123456')
    $goodText.Replace('123456', '0x1F')
    '[' + $goodText + ']'
    $goodText.Replace('"search"', '"search",')
    $goodText.Replace('"action"', '/* c */ "action"')
    $goodText.Replace('"action"', '"action": "export", "action"')
    $goodText.Replace('"budget"', '"2024-03-15T10:30:00Z"')
) | ForEach-Object { $r = Test-OrrSpec -Json $_ -ClientConfig $clients; "$($r.IsValid)|$(@($r.Errors) -join ';')|$(@($r.Spec.Keywords) -join ',')" }
$tampered = 'not attempted'
if ($good.IsValid) {
    $good.Spec.Action = 'export'
    try { [void](New-OrrKqlQuery -Spec $good.Spec -ClientConfig $clients); $tampered = 'accepted' } catch { $tampered = 'refused' }
}
[PSCustomObject]@{
    Major          = $PSVersionTable.PSVersion.Major
    GoodIsValid    = $good.IsValid
    GoodErrors     = @($good.Errors)
    GoodWarnings   = @($good.Warnings)
    CustodianCount = @($good.Spec.Custodians).Count
    Kql            = $kql
    BadIsValid     = $bad.IsValid
    BadErrors      = @($bad.Errors)
    Odd            = @($odd)
    Tampered       = $tampered
} | ConvertTo-Json -Depth 4 -Compress
'@)

        $arguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script:ProbePath,
            '-ModulePath', $script:OrrModulePath, '-ConfigPath', $script:ConfigPath,
            '-GoodSpecPath', $script:GoodSpecPath, '-BadSpecPath', $script:BadSpecPath)

        # Windows PowerShell must not inherit PowerShell 7's module path.
        $savedModulePath = $env:PSModulePath
        try {
            $env:PSModulePath = [System.Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
            $script:DesktopRaw = (& powershell.exe @arguments 2>&1 | Out-String).Trim()
        } finally {
            $env:PSModulePath = $savedModulePath
        }
        $script:Desktop = $null
        try { $script:Desktop = $script:DesktopRaw | ConvertFrom-Json -ErrorAction Stop } catch { }

        $script:Core = (& $script:ProbePath -ModulePath $script:OrrModulePath -ConfigPath $script:ConfigPath `
                -GoodSpecPath $script:GoodSpecPath -BadSpecPath $script:BadSpecPath) | ConvertFrom-Json
        Import-Module $script:OrrModulePath -Force
    }

    It 'ran under Windows PowerShell 5' {
        $script:Desktop | Should -Not -BeNullOrEmpty -Because "powershell.exe printed: $script:DesktopRaw"
        $script:Desktop.Major | Should -Be 5
    }

    It 'accepts the same valid spec' {
        $script:Desktop.GoodErrors | Should -BeNullOrEmpty
        $script:Desktop.GoodIsValid | Should -BeTrue
        $script:Desktop.CustodianCount | Should -Be 1
    }

    It 'builds the identical query' {
        $script:Desktop.Kql | Should -BeExactly '(budget OR "road repair" OR rfp* OR "and") AND (date>=2023-12-31 AND date<2024-04-02)'
        $script:Desktop.Kql | Should -BeExactly $script:Core.Kql
    }

    It 'gives the same warnings' {
        @($script:Desktop.GoodWarnings) | Should -Be @($script:Core.GoodWarnings)
    }

    It 'rejects the same bad spec for the same reasons' {
        $script:Desktop.BadIsValid | Should -BeFalse
        @($script:Desktop.BadErrors).Count | Should -BeGreaterOrEqual 4
        @($script:Desktop.BadErrors) | Should -Be @($script:Core.BadErrors)
    }

    It 'reads awkward JSON the same way: six refusals and one timestamp keyword kept as text' {
        @($script:Desktop.Odd).Count | Should -Be 7
        @($script:Desktop.Odd) | Should -Be @($script:Core.Odd)
        @($script:Desktop.Odd | Where-Object { $_ -like 'False|*' }).Count | Should -Be 6
        $script:Desktop.Odd[6] | Should -BeLike 'True||2024-03-15T10:30:00Z,*'
    }

    It 'refuses a spec changed after validation' {
        $script:Desktop.Tampered | Should -BeExactly 'refused'
        $script:Core.Tampered | Should -BeExactly 'refused'
    }
}
