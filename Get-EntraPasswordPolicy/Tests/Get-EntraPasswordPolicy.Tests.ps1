<#
    Pester 5 tests for Get-EntraPasswordPolicy.ps1. Graph cmdlets are stubbed and mocked, so
    no tenant or module is needed.

    Run with Pester 5:  Invoke-Pester .\Get-EntraPasswordPolicy\Tests

    Documented behavior covered:
      - Domain passwordValidityPeriodInDays that is not set means 90 days (NOT "never"):
        https://learn.microsoft.com/graph/api/resources/domain
      - Missing modules are never installed silently; the script prints the command and exits.
#>

BeforeAll {
    $script:ScriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Get-EntraPasswordPolicy.ps1'

    # Stubs for commands that are not installed on the test machine.
    function Connect-MgGraph        { [CmdletBinding()] param($TenantId, [switch]$NoWelcome, $Scopes) }
    function Install-Module         { [CmdletBinding()] param($Name, $Scope) }
    function Disconnect-MgGraph     { [CmdletBinding()] param() }
    function Get-MgOrganization     { [CmdletBinding()] param() }
    function Get-MgDomain           { [CmdletBinding()] param() }
    function Get-MgUser             { [CmdletBinding()] param([switch]$All, $Property) }
    function Invoke-MgGraphRequest  { [CmdletBinding()] param($Method, $Uri) }
    function Export-Excel           { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject, $Path, $WorksheetName, [switch]$AutoSize, [switch]$FreezeTopRow, [switch]$BoldTopRow, [switch]$AutoFilter, $TableName) process {} }

    . $script:ScriptPath -TenantId 'contoso.com' -LoadFunctionsOnly
}

Describe 'Script header' {
    BeforeAll {
        $tokens = $null; $errors = $null
        $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$tokens, [ref]$errors)
    }
    It 'parses without errors' {
        $tokens = $null; $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$tokens, [ref]$errors)
        @($errors).Count | Should -Be 0
    }
    It 'requires PowerShell 5.1 (Microsoft.Graph needs it)' {
        $script:Ast.ScriptRequirements.RequiredPSVersion | Should -Be ([version]'5.1')
    }
    It 'never calls Install-Module (no silent installs)' {
        $calls = $script:Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] -and $args[0].GetCommandName() -eq 'Install-Module' }, $true)
        @($calls).Count | Should -Be 0
    }
}

Describe 'Get-EffectivePasswordExpiration' {
    BeforeAll { $script:Now = [datetime]'2026-06-01' }

    It 'defers to on-prem AD for synced users, even with a flag set' {
        $r = Get-EffectivePasswordExpiration -Synced $true -NeverFlag $true -DomainDays 90 -LastPasswordChange $script:Now.AddDays(-400) -Now $script:Now
        $r.Effective | Should -Be 'On-prem AD governs'
        $r.PasswordExpiresOn | Should -BeNullOrEmpty
        $r.CurrentlyExpired | Should -BeFalse
    }

    It 'honours the DisablePasswordExpiration user flag over the domain policy' {
        $r = Get-EffectivePasswordExpiration -Synced $false -NeverFlag $true -DomainDays 90 -LastPasswordChange $script:Now.AddDays(-400) -Now $script:Now
        $r.Effective | Should -Be 'Never (user flag)'
        $r.CurrentlyExpired | Should -BeFalse
    }

    It 'treats Int32.MaxValue as a never-expiring domain policy' {
        $r = Get-EffectivePasswordExpiration -Synced $false -NeverFlag $false -DomainDays 2147483647 -LastPasswordChange $script:Now.AddDays(-4000) -Now $script:Now
        $r.Effective | Should -Be 'Never (domain policy)'
        $r.CurrentlyExpired | Should -BeFalse
    }

    It 'applies the documented 90-day default when the domain value is not set (not "never")' {
        $r = Get-EffectivePasswordExpiration -Synced $false -NeverFlag $false -DomainDays $null -LastPasswordChange $script:Now.AddDays(-100) -Now $script:Now
        $r.Effective | Should -Match '^90 days'
        $r.Effective | Should -Match 'default'
        $r.PasswordExpiresOn | Should -Be $script:Now.AddDays(-10)
        $r.CurrentlyExpired | Should -BeTrue
    }

    It 'computes expiry from the domain policy and flags it expired only after the date' {
        $valid = Get-EffectivePasswordExpiration -Synced $false -NeverFlag $false -DomainDays 60 -LastPasswordChange $script:Now.AddDays(-30) -Now $script:Now
        $valid.Effective | Should -Be '60 days (domain policy)'
        $valid.PasswordExpiresOn | Should -Be $script:Now.AddDays(30)
        $valid.CurrentlyExpired | Should -BeFalse

        $old = Get-EffectivePasswordExpiration -Synced $false -NeverFlag $false -DomainDays 60 -LastPasswordChange $script:Now.AddDays(-61) -Now $script:Now
        $old.CurrentlyExpired | Should -BeTrue
    }

    It 'reports an unknown UPN domain instead of guessing "never"' {
        $r = Get-EffectivePasswordExpiration -Synced $false -NeverFlag $false -DomainDays $null -DomainKnown $false -LastPasswordChange $script:Now -Now $script:Now
        $r.Effective | Should -Match '^Unknown'
        $r.CurrentlyExpired | Should -BeFalse
    }

    It 'does not fabricate an expiry date when the last change is unknown' {
        $r = Get-EffectivePasswordExpiration -Synced $false -NeverFlag $false -DomainDays 90 -LastPasswordChange $null -Now $script:Now
        $r.PasswordExpiresOn | Should -BeNullOrEmpty
        $r.CurrentlyExpired | Should -BeFalse
    }
}

Describe 'Export-PolicyReport' {
    BeforeEach {
        $script:Sheets = [ordered]@{
            'Summary' = @([PSCustomObject]@{ Setting = 'A'; Value = 'caf' + [char]0xE9 })
            'Users'   = @([PSCustomObject]@{ UserPrincipalName = 'a@contoso.com' })
        }
    }

    It 'falls back to one UTF-8 CSV per sheet without ImportExcel' {
        Mock Export-Excel {}
        $base = Join-Path $TestDrive 'report'
        $files = @(Export-PolicyReport -Sheets $script:Sheets -BasePath $base)

        Should -Invoke Export-Excel -Times 0
        $files.Count | Should -Be 2
        Test-Path "$base-Summary.csv" | Should -BeTrue
        Test-Path "$base-Users.csv" | Should -BeTrue
        (Get-Content -LiteralPath "$base-Summary.csv" -Encoding UTF8 -Raw) | Should -Match ([string][char]0xE9)
        (Get-Content -LiteralPath "$base-Users.csv" -Raw) | Should -Match 'a@contoso.com'
    }

    It 'writes a single workbook, one worksheet per sheet, when ImportExcel is available' {
        Mock Export-Excel {}
        $base = Join-Path $TestDrive 'book'
        $files = @(Export-PolicyReport -Sheets $script:Sheets -BasePath $base -UseExcel)

        $files | Should -Be @("$base.xlsx")
        Should -Invoke Export-Excel -Times 2
        Should -Invoke Export-Excel -ParameterFilter { $WorksheetName -eq 'Users' -and $TableName -eq 'Users' }
    }
}

Describe 'Missing Microsoft Graph modules' {
    It 'Get-MissingModule lists the modules that are not available' {
        Mock Get-Module { if ($Name -eq 'Present') { [PSCustomObject]@{ Name = 'Present' } } }
        Get-MissingModule -Name 'Present', 'Absent1', 'Absent2' | Should -Be @('Absent1', 'Absent2')
    }

    It 'prints the Install-Module command and exits 1 without connecting or installing' {
        Mock Get-Module { $null }
        Mock Import-Module {}
        Mock Connect-MgGraph {}
        Mock Install-Module {}

        $out = & $script:ScriptPath -TenantId 'contoso.com' -OutputPath $TestDrive 6>&1 | Out-String

        $LASTEXITCODE | Should -Be 1
        $out | Should -Match '\[FAIL\]'
        $out | Should -Match 'Install-Module Microsoft\.Graph\.Authentication'
        $out | Should -Match '-Scope CurrentUser'
        Should -Invoke Connect-MgGraph -Times 0
        Should -Invoke Install-Module -Times 0
    }
}

Describe 'End-to-end with mocked Graph and no ImportExcel' {
    BeforeAll {
        $script:OutDir = Join-Path $TestDrive 'out'
    }

    It 'writes CSV reports with effective-expiry results' {
        # Graph modules present, ImportExcel absent.
        Mock Get-Module { if ($Name -ne 'ImportExcel') { [PSCustomObject]@{ Name = $Name } } }
        Mock Import-Module {}
        Mock Connect-MgGraph {}
        Mock Disconnect-MgGraph {}
        Mock Get-MgOrganization { [PSCustomObject]@{ DisplayName = 'Contoso'; Id = 'tid'; OnPremisesSyncEnabled = $false; OnPremisesLastSyncDateTime = $null } }
        Mock Get-MgDomain {
            @(
                [PSCustomObject]@{ Id = 'contoso.com'; IsDefault = $true;  IsVerified = $true; AuthenticationType = 'Managed'; PasswordValidityPeriodInDays = $null; PasswordNotificationWindowInDays = $null }
                [PSCustomObject]@{ Id = 'never.com';   IsDefault = $false; IsVerified = $true; AuthenticationType = 'Managed'; PasswordValidityPeriodInDays = 2147483647; PasswordNotificationWindowInDays = 14 }
            )
        }
        Mock Invoke-MgGraphRequest {
            if ($Uri -like '*groupSettings') { [PSCustomObject]@{ value = @() } }
            else { [PSCustomObject]@{ isEnabled = $true } }
        }
        Mock Get-MgUser {
            @(
                [PSCustomObject]@{ UserPrincipalName = 'old@contoso.com'; DisplayName = 'Old'; AccountEnabled = $true; UserType = 'Member'; PasswordPolicies = $null; LastPasswordChangeDateTime = (Get-Date).AddDays(-200); OnPremisesSyncEnabled = $null }
                [PSCustomObject]@{ UserPrincipalName = 'svc@never.com';   DisplayName = 'Svc'; AccountEnabled = $true; UserType = 'Member'; PasswordPolicies = $null; LastPasswordChangeDateTime = (Get-Date).AddDays(-900); OnPremisesSyncEnabled = $null }
                [PSCustomObject]@{ UserPrincipalName = 'flag@contoso.com'; DisplayName = 'Flag'; AccountEnabled = $true; UserType = 'Member'; PasswordPolicies = 'DisablePasswordExpiration'; LastPasswordChangeDateTime = (Get-Date).AddDays(-900); OnPremisesSyncEnabled = $null }
            )
        }

        $null = & $script:ScriptPath -TenantId 'contoso.com' -OutputPath $script:OutDir 6>&1

        $users = Get-ChildItem -LiteralPath $script:OutDir -Filter '*-Users.csv'
        @($users).Count | Should -Be 1
        $rows = Import-Csv -LiteralPath $users[0].FullName
        ($rows | Where-Object UserPrincipalName -eq 'old@contoso.com').CurrentlyExpired  | Should -Be 'True'
        ($rows | Where-Object UserPrincipalName -eq 'old@contoso.com').EffectiveExpiration | Should -Match '^90 days'
        ($rows | Where-Object UserPrincipalName -eq 'svc@never.com').CurrentlyExpired    | Should -Be 'False'
        ($rows | Where-Object UserPrincipalName -eq 'flag@contoso.com').EffectiveExpiration | Should -Be 'Never (user flag)'
        @(Get-ChildItem -LiteralPath $script:OutDir -Filter '*.csv').Count | Should -Be 6
        Should -Invoke Connect-MgGraph -ParameterFilter { $Scopes -contains 'Organization.Read.All' -and $Scopes -contains 'GroupSettings.Read.All' }
    }
}
