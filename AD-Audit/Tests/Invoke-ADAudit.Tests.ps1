<#
    Pester 5 regression tests for Invoke-ADAudit.ps1 (dot-sourced with -LoadFunctionsOnly,
    AD cmdlets stubbed and mocked - no domain needed).

    Run with Pester 5:  Invoke-Pester .\AD-Audit\Tests

    Corrected facts (do not revert without re-reading the sources):
      - Schema objectVersion 91 = Windows Server 2025 (90 is not a released version):
        https://learn.microsoft.com/windows-server/identity/ad-ds/deploy/find-active-directory-schema
      - trustAttributes QUARANTINED_DOMAIN (0x4) set = SID filtering enforced:
        https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c
      - Privileged groups are matched by well-known SID/RID, not English name:
        https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
#>

BeforeAll {
    $script:ScriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Invoke-ADAudit.ps1'

    # Stubs so Pester can mock cmdlets that are not installed on the test machine.
    function Get-ADDomain         { [CmdletBinding()] param($Identity, $Server, $Credential) }
    function Get-ADForest         { [CmdletBinding()] param($Identity, $Server, $Credential) }
    function Get-ADGroup          { [CmdletBinding()] param($Identity, $Filter, $Properties, $Server, $Credential) }
    function Get-ADGroupMember    { [CmdletBinding()] param($Identity, $Server, $Credential) }
    function Get-ADTrust          { [CmdletBinding()] param($Filter, $Properties, $Server, $Credential) }
    function Get-ADRootDSE        { [CmdletBinding()] param($Server, $Credential) }
    function Get-ADObject         { [CmdletBinding()] param($Identity, $Filter, $Properties, $Server, $Credential) }
    function Get-ADOptionalFeature{ [CmdletBinding()] param($Filter, $Server, $Credential) }
    function Get-ADComputer       { [CmdletBinding()] param($Identity, $Filter, $Properties, $Server, $Credential) }
    function Get-ADUser           { [CmdletBinding()] param($Identity, $Filter, $Properties, $Server, $Credential) }

    . $script:ScriptPath -LoadFunctionsOnly -SkipBrowserOpen

    function New-DomainObject {
        param([string]$Sid)
        [PSCustomObject]@{ DomainSID = [PSCustomObject]@{ Value = $Sid } }
    }
}

Describe 'Script header' {
    BeforeAll { $text = Get-Content -LiteralPath $script:ScriptPath -Raw }

    It 'does not use #Requires -Modules (runtime Import-Module instead)' {
        $text | Should -Not -Match '(?m)^\s*#Requires\s+-Modules'
    }
    It 'declares #Requires -Version 5.1 (uses ::new())' {
        $text | Should -Match '(?m)^#Requires -Version 5\.1'
    }
    It 'defaults OutputPath to the current directory, not the script folder' {
        $text | Should -Not -Match 'OutputPath\s*=\s*\$PSScriptRoot'
    }
    It 'points to the dedicated privileged access tool' {
        $text | Should -Match 'Get-DomainPrivilegedAccess\.ps1'
    }
}

Describe 'Get-SchemaVersionOS' {
    It 'maps <Version> to <Expected>' -ForEach @(
        @{ Version = 91; Expected = 'Windows Server 2025' }
        @{ Version = 88; Expected = 'Windows Server 2019/2022' }
        @{ Version = 87; Expected = 'Windows Server 2016' }
        @{ Version = 69; Expected = 'Windows Server 2012 R2' }
        @{ Version = 56; Expected = 'Windows Server 2012' }
        @{ Version = 47; Expected = 'Windows Server 2008 R2' }
        @{ Version = 44; Expected = 'Windows Server 2008' }
        @{ Version = 31; Expected = 'Windows Server 2003 R2' }
        @{ Version = 30; Expected = 'Windows Server 2003' }
    ) {
        Get-SchemaVersionOS -Version $Version | Should -Be $Expected
    }

    It 'does not claim version 90 is Windows Server 2025' {
        Get-SchemaVersionOS -Version 90 | Should -Match '^Unknown'
    }
}

Describe 'Get-TrustSidFilteringState' {
    It 'reports an external trust WITHOUT the quarantine bit as disabled / High' {
        $r = Get-TrustSidFilteringState -TrustAttributes 0
        $r.Severity | Should -Be 'High'
        $r.State | Should -Match 'DISABLED'
    }
    It 'reports an external trust WITH the quarantine bit (0x4) as enforced / Low' {
        $r = Get-TrustSidFilteringState -TrustAttributes 0x4
        $r.Severity | Should -Be 'Low'
        $r.State | Should -Match 'Enforced'
    }
    It 'reports a default forest trust (0x8) as enforced / Low even though quarantine bit is clear' {
        $r = Get-TrustSidFilteringState -TrustAttributes 0x8
        $r.Severity | Should -Be 'Low'
        $r.State | Should -Match 'Enforced'
    }
    It 'flags a forest trust relaxed with TREAT_AS_EXTERNAL (0x40) as Warning' {
        $r = Get-TrustSidFilteringState -TrustAttributes (0x8 -bor 0x40)
        $r.Severity | Should -Be 'Warning'
    }
    It 'treats a within-forest trust (0x20) as not applicable, not as a failure' {
        $r = Get-TrustSidFilteringState -TrustAttributes 0x20
        $r.Severity | Should -Be 'Low'
        $r.State | Should -Match 'within forest'
    }
    It 'treats IntraForest as within-forest even if the attribute is missing' {
        (Get-TrustSidFilteringState -TrustAttributes 0 -IntraForest $true).Severity | Should -Be 'Low'
    }
    It 'does not rate a non-Windows realm trust as disabled' {
        (Get-TrustSidFilteringState -TrustAttributes 0 -TrustType 'MIT').Severity | Should -Be 'Low'
    }
}

Describe 'Get-ADInfrastructureAudit trust health' {
    BeforeEach {
        Mock Get-ADRootDSE { [PSCustomObject]@{ configurationNamingContext = 'CN=Configuration,DC=c,DC=local'; schemaNamingContext = 'CN=Schema,CN=Configuration,DC=c,DC=local' } }
        Mock Get-ADObject { [PSCustomObject]@{ objectVersion = 91; tombstoneLifetime = 180 } }
        Mock Get-ADOptionalFeature { [PSCustomObject]@{ EnabledScopes = @('x') } }
        Mock Get-ADDomain { [PSCustomObject]@{ DistinguishedName = 'DC=c,DC=local' } }
        Mock Write-AuditLog {}
    }

    It 'rates an unquarantined external trust High and a quarantined one Low' {
        Mock Get-ADTrust {
            @(
                [PSCustomObject]@{ Name = 'open.ext';   Direction = 'Bidirectional'; TrustType = 'Uplevel'; IntraForest = $false; TrustAttributes = 0; SelectiveAuthentication = $false; TGTDelegation = $false }
                [PSCustomObject]@{ Name = 'locked.ext'; Direction = 'Bidirectional'; TrustType = 'Uplevel'; IntraForest = $false; TrustAttributes = 4; SelectiveAuthentication = $false; TGTDelegation = $false }
            )
        }
        $r = Get-ADInfrastructureAudit
        $open   = @($r.TrustHealth | Where-Object Name -eq 'open.ext')[0]
        $locked = @($r.TrustHealth | Where-Object Name -eq 'locked.ext')[0]
        $open.SIDFilteringSeverity   | Should -Be 'High'
        $locked.SIDFilteringSeverity | Should -Be 'Low'
        Should -Invoke Get-ADTrust -ParameterFilter { $Properties -contains 'TrustAttributes' }
    }

    It 'maps the schema version through the corrected table' {
        Mock Get-ADTrust { @() }
        (Get-ADInfrastructureAudit).SchemaOS | Should -Be 'Windows Server 2025'
    }

    It 'falls back to SIDFilteringQuarantined when TrustAttributes is not returned' {
        Mock Get-ADTrust {
            [PSCustomObject]@{ Name = 'q.ext'; Direction = 'Inbound'; TrustType = 'Uplevel'; IntraForest = $false; SIDFilteringQuarantined = $true; SelectiveAuthentication = $false; TGTDelegation = $false }
        }
        $r = Get-ADInfrastructureAudit
        @($r.TrustHealth)[0].SIDFilteringSeverity | Should -Be 'Low'
    }
}

Describe 'Privileged groups are matched by well-known SID' {
    BeforeEach {
        Mock Write-AuditLog {}
        Mock Get-ADGroup {
            @([PSCustomObject]@{ Name = 'g'; Members = @('x'); GroupCategory = 'Security'; GroupScope = 'Global'; Description = '' })
        }
        Mock Get-ADGroupMember {
            [PSCustomObject]@{ name = 'Alice'; SamAccountName = 'alice'; objectClass = 'user' }
        }
    }

    Context 'Get-PrivilegedGroupSet in the forest root domain' {
        BeforeEach {
            Mock Get-ADDomain { New-DomainObject 'S-1-5-21-1-2-3' }
            Mock Get-ADForest { [PSCustomObject]@{ RootDomain = 'corp.local' } }
        }
        It 'builds RID-based SIDs and fixed BUILTIN SIDs' {
            $set = @(Get-PrivilegedGroupSet)
            ($set | Where-Object Name -eq 'Domain Admins').Sid     | Should -Be 'S-1-5-21-1-2-3-512'
            ($set | Where-Object Name -eq 'Schema Admins').Sid     | Should -Be 'S-1-5-21-1-2-3-518'
            ($set | Where-Object Name -eq 'Enterprise Admins').Sid | Should -Be 'S-1-5-21-1-2-3-519'
            ($set | Where-Object Name -eq 'Administrators').Sid    | Should -Be 'S-1-5-32-544'
            ($set | Where-Object Name -eq 'Account Operators').Sid | Should -Be 'S-1-5-32-548'
            ($set | Where-Object Name -eq 'Server Operators').Sid  | Should -Be 'S-1-5-32-549'
            ($set | Where-Object Name -eq 'Backup Operators').Sid  | Should -Be 'S-1-5-32-551'
        }
        It 'does not redirect to another server when audited domain is the root' {
            @(Get-PrivilegedGroupSet | Where-Object { $_.Server }).Count | Should -Be 0
        }
    }

    Context 'Get-PrivilegedGroupSet in a child domain' {
        BeforeEach {
            Mock Get-ADDomain { New-DomainObject 'S-1-5-21-9-9-9' }
            Mock Get-ADDomain { New-DomainObject 'S-1-5-21-1-2-3' } -ParameterFilter { $Server -eq 'corp.local' }
            Mock Get-ADForest { [PSCustomObject]@{ RootDomain = 'corp.local' } }
        }
        It 'uses the FOREST ROOT domain SID for Schema/Enterprise Admins and targets the root' {
            $set = @(Get-PrivilegedGroupSet)
            $ea = $set | Where-Object Name -eq 'Enterprise Admins'
            $ea.Sid | Should -Be 'S-1-5-21-1-2-3-519'
            $ea.Server | Should -Be 'corp.local'
            ($set | Where-Object Name -eq 'Schema Admins').Sid | Should -Be 'S-1-5-21-1-2-3-518'
            ($set | Where-Object Name -eq 'Domain Admins').Sid | Should -Be 'S-1-5-21-9-9-9-512'
        }
    }

    Context 'Get-GroupAudit' {
        BeforeEach {
            Mock Get-ADDomain { New-DomainObject 'S-1-5-21-1-2-3' }
            Mock Get-ADForest { [PSCustomObject]@{ RootDomain = 'corp.local' } }
        }
        It 'queries members by SID and never by English group name' {
            $r = Get-GroupAudit
            Should -Invoke Get-ADGroupMember -Times 1 -ParameterFilter { $Identity -eq 'S-1-5-21-1-2-3-512' }
            Should -Invoke Get-ADGroupMember -Times 1 -ParameterFilter { $Identity -eq 'S-1-5-32-544' }
            Should -Invoke Get-ADGroupMember -Times 0 -ParameterFilter { $Identity -eq 'Domain Admins' -or $Identity -eq 'Administrators' }
            @($r.PrivilegedMembers).Count | Should -Be 7
            (@($r.PrivilegedMembers)[0]).GroupSid | Should -Match '^S-1-5-'
        }
        It 'keeps going and records a warning when one group cannot be read' {
            Mock Get-ADGroupMember { throw 'not found' } -ParameterFilter { $Identity -eq 'S-1-5-21-1-2-3-518' }
            $r = Get-GroupAudit
            @($r.PrivilegedMembers).Count | Should -Be 6
            Should -Invoke Write-AuditLog -ParameterFilter { $Level -eq 'Warning' -and $Message -match 'Schema Admins' }
        }
    }

    Context 'Kerberoastable admin check' {
        It 'finds Domain Admins by RID 512' {
            Mock Get-ADDomain { New-DomainObject 'S-1-5-21-1-2-3' }
            Mock Get-ADForest { [PSCustomObject]@{ RootDomain = 'corp.local' } }
            Mock Get-ADUser { @() }
            Mock Get-ADComputer { @() }
            Mock Get-ADObject { @() }
            $null = Get-PrivilegedAccessAudit
            Should -Invoke Get-ADGroupMember -ParameterFilter { $Identity -eq 'S-1-5-21-1-2-3-512' }
            Should -Invoke Get-ADGroupMember -Times 0 -ParameterFilter { $Identity -eq 'Domain Admins' }
        }
    }
}

Describe 'Test-Prerequisites' {
    It 'fails cleanly (returns $false) when the ActiveDirectory module cannot be imported' {
        Mock Write-AuditLog {}
        Mock Import-Module { throw 'module not found' }
        Test-Prerequisites | Should -BeFalse
    }
}
