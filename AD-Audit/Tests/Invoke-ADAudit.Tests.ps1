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

# ---------------------------------------------------------------------------------------------
# SQ-005: End-of-support section. Synthetic data only (contoso.com, SRV01). Lifecycle rows are
# synthetic wherever the real Microsoft date does not matter, so a table update cannot break them.
# Interfaces under test (see squad/specs/SQ-005.md):
#   Get-ServerLifecycleTable                      -> @{ CheckedOn; Rows }
#   Resolve-ServerLifecycle -OperatingSystem -Table   (Table = the object above) -> row or $null
#   Get-EndOfSupportStatus -Lifecycle -AsOf       -> Status, Severity, Note, DaysUntilExtendedEnd
#   Get-EndOfSupportAudit                         -> @{ Servers; PastEndCount; StaleTableWarning; Error }
#   $auditResults.EndOfSupport                    -> the hashtable above
# ---------------------------------------------------------------------------------------------
Describe 'SQ-005 End of support' {
    BeforeAll {
        $script:Inv = [System.Globalization.CultureInfo]::InvariantCulture
        function D {
            param([string]$s)
            $f = if ($s.Length -gt 10) { 'yyyy-MM-dd HH:mm' } else { 'yyyy-MM-dd' }
            [datetime]::ParseExact($s, $f, [System.Globalization.CultureInfo]::InvariantCulture)
        }
        function New-LcRow {
            param([string]$Mainstream = '2020-01-01', [string]$Extended = '2030-01-01', $Esu = $null)
            [PSCustomObject]@{
                Product       = 'Synthetic Server'
                Pattern       = '^Synthetic'
                MainstreamEnd = $Mainstream
                ExtendedEnd   = $Extended
                EsuEnd        = $Esu
                Source        = 'https://learn.microsoft.com/lifecycle/products/synthetic'
            }
        }
        function New-FakeServer {
            param([string]$Name = 'SRV01', [string]$Os = 'Windows Server 2022 Datacenter', $LastLogon = (D '2027-01-20'), [bool]$Enabled = $true)
            [PSCustomObject]@{ Name = $Name; OperatingSystem = $Os; OperatingSystemVersion = '10.0 (20348)'; LastLogonDate = $LastLogon; Enabled = $Enabled }
        }
        function New-EosRow {
            param([string]$Name = 'SRV01', [string]$Status = 'Mainstream support', [string]$Severity = 'Low', [string]$Note = 'In mainstream support until 2031-10-14.')
            [PSCustomObject]@{
                Name = $Name; OperatingSystem = 'Windows Server 2022 Datacenter'; OperatingSystemVersion = '10.0 (20348)'
                Product = 'Windows Server 2022'; Status = $Status; Severity = $Severity; DaysUntilExtendedEnd = 100
                MainstreamEnd = '2026-10-13'; ExtendedEnd = '2031-10-14'; EsuEnd = $null; Note = $Note
                LastLogonDate = '2027-01-20'; Stale = $false; Source = 'https://learn.microsoft.com/lifecycle/products/windows-server-2022'
                TableCheckedOn = '2026-09-30'; AuditDate = '2027-02-01 09:00:00'; AuditedDomain = 'contoso.com'
                RunBy = 'CONTOSO\tech1'; RunOn = 'WS01'
            }
        }
        function New-EmptyAuditResults {
            @{
                Overview          = @{ DomainName = 'contoso.com'; ForestName = 'contoso.com'; DomainControllers = 0; FSMORoles = @(); Trusts = @(); Sites = @(); Subnets = @() }
                DomainControllers = @{ DomainControllers = @(); ReplicationFailures = @() }
                Users             = @{ TotalUsers = 0; EnabledCount = 0; DisabledCount = 0; StaleUsers = @(); PasswordNeverExpires = @(); PasswordNotRequired = @(); NeverLoggedOn = @(); LockedOut = @(); SIDHistory = @() }
                Groups            = @{ TotalGroups = 0; EmptyGroups = @(); LargeGroups = @(); PrivilegedMembers = @(); NestedWarnings = @() }
                Computers         = @{ TotalComputers = 0; EnabledCount = 0; DisabledCount = 0; StaleComputers = @(); OSDistribution = @(); UnsupportedComputers = @() }
                PasswordPolicy    = @{ DefaultPolicy = $null; NISTFindings = @(); FineGrained = @() }
                Privileged        = @{ AdminSDHolder = @(); Delegation = @(); KerberoastableAdmins = @(); ASREPRoastable = @() }
                Security          = @{ Findings = @() }
                Infrastructure    = @{ TombstoneLifetime = 'Skipped'; RecycleBinEnabled = $false; SchemaVersion = 'Skipped'; SchemaOS = 'Skipped'; SysvolReplication = 'Skipped'; TrustHealth = @() }
                OUStructure       = @{ TotalOUs = 0; MaxDepth = 0; OUs = @(); EmptyOUs = @(); NoGPOLink = @() }
                EndOfSupport      = @{ Servers = @(); PastEndCount = 0; StaleTableWarning = $null; Error = $null }
            }
        }
        function New-SyntheticTable {
            param([string]$CheckedOn = '2027-01-15')
            @{ CheckedOn = $CheckedOn; Rows = @(
                [PSCustomObject]@{ Product = 'Windows Server 2022'; Pattern = '^Windows Server\W*2022\b'; MainstreamEnd = '2026-10-13'; ExtendedEnd = '2031-10-14'; EsuEnd = $null; Source = 'https://learn.microsoft.com/lifecycle/products/windows-server-2022' }
            ) }
        }
    }

    BeforeEach {
        $env:ADPS_LoadDefaultDrive = '0'
        $AuditDate  = D '2027-02-01'
        $StaleDate  = $AuditDate.AddDays(-90)
        $DaysInactive = 90
        $ADParams   = @{}
        $Credential = $null
        $ReportName = 'AD-Audit-test'
        Mock Write-AuditLog {}
        Mock Get-ADDomain { [PSCustomObject]@{ DNSRoot = 'contoso.com'; DistinguishedName = 'DC=contoso,DC=com' } }
    }

    Context 'Lifecycle table and pure functions' {
        It 'AC1_LifecycleTableIsCitedAndWellFormed' {
            $t = Get-ServerLifecycleTable
            $null = [datetime]::ParseExact([string]$t.CheckedOn, 'yyyy-MM-dd', $script:Inv)
            @($t.Rows).Count | Should -BeGreaterThan 0
            foreach ($r in @($t.Rows)) {
                $r.Product | Should -Not -BeNullOrEmpty
                $r.Pattern | Should -Not -BeNullOrEmpty
                $r.Source  | Should -BeLike 'https://learn.microsoft.com/lifecycle/*'
                $m = [datetime]::ParseExact([string]$r.MainstreamEnd, 'yyyy-MM-dd', $script:Inv)
                $x = [datetime]::ParseExact([string]$r.ExtendedEnd,   'yyyy-MM-dd', $script:Inv)
                $m | Should -BeLessOrEqual $x
                if ($r.EsuEnd) {
                    $s = [datetime]::ParseExact([string]$r.EsuEnd, 'yyyy-MM-dd', $script:Inv)
                    $x | Should -BeLessOrEqual $s
                }
            }
        }

        It 'AC2_OsStringsMapToTheRightProduct: <Os>' -ForEach @(
            @{ Os = 'Windows Server 2012 R2 Standard';   Expect = '2012 R2$' }
            @{ Os = 'Windows Server 2012 Datacenter';    Expect = '2012$' }
            @{ Os = 'Windows Server 2008 R2 Enterprise'; Expect = '2008 R2$' }
            @{ Os = ('Windows Server{0} 2008 Standard' -f [char]0x00AE); Expect = '2008$' }
            @{ Os = 'Windows Server 2003';               Expect = '2003$' }
            @{ Os = 'Windows Server 2016 Standard';      Expect = '2016$' }
            @{ Os = 'Windows Server 2019 Datacenter';    Expect = '2019$' }
            @{ Os = 'Windows Server 2022 Datacenter';    Expect = '2022$' }
            @{ Os = 'Windows Server 2025 Datacenter';    Expect = '2025$' }
        ) {
            $t = Get-ServerLifecycleTable
            $r = Resolve-ServerLifecycle -OperatingSystem $Os -Table $t
            $r | Should -Not -BeNullOrEmpty
            $r.Product | Should -Match $Expect
        }

        It 'AC2_OsStringsMapToTheRightProduct_EachToItsOwnProduct' {
            $t = Get-ServerLifecycleTable
            $oses = @('Windows Server 2012 R2 Standard', 'Windows Server 2012 Datacenter', 'Windows Server 2008 R2 Enterprise',
                      ('Windows Server{0} 2008 Standard' -f [char]0x00AE), 'Windows Server 2003', 'Windows Server 2016 Standard',
                      'Windows Server 2019 Datacenter', 'Windows Server 2022 Datacenter', 'Windows Server 2025 Datacenter')
            $products = @($oses | ForEach-Object { (Resolve-ServerLifecycle -OperatingSystem $_ -Table $t).Product })
            @($products | Select-Object -Unique).Count | Should -Be 9
        }

        It 'AC3_UnknownOsIsNeverReportedSupported: <Os>' -ForEach @(
            @{ Os = 'Windows Server Datacenter' }
            @{ Os = 'Windows Storage Server 2016 Standard' }
            @{ Os = 'Windows Server 2031 Standard' }
        ) {
            $t  = Get-ServerLifecycleTable
            $lc = Resolve-ServerLifecycle -OperatingSystem $Os -Table $t
            $s  = Get-EndOfSupportStatus -Lifecycle $lc -AsOf (D '2027-02-01')
            $s.Status   | Should -Be 'Unknown'
            $s.Severity | Should -Be 'Warning'
            $s.Note     | Should -Match 'check https://learn\.microsoft\.com/lifecycle manually'
        }

        It 'AC4_ExtendedEndDayBoundary: AsOf <AsOf>' -ForEach @(
            @{ AsOf = '2027-01-11';       Days = 1;  Expect = 'Security updates only' }
            @{ AsOf = '2027-01-12 23:59'; Days = 0;  Expect = 'Security updates only' }
            @{ AsOf = '2027-01-13 00:01'; Days = -1; Expect = 'No support' }
        ) {
            $row = New-LcRow -Extended '2027-01-12'
            $s = Get-EndOfSupportStatus -Lifecycle $row -AsOf (D $AsOf)
            $s.DaysUntilExtendedEnd | Should -Be $Days
            $s.Status | Should -Be $Expect
        }

        It 'AC5_EsuWindowIsHedged_BeforeEsuEnds' {
            $row = New-LcRow -Extended '2023-10-10' -Esu '2026-10-13'
            $s = Get-EndOfSupportStatus -Lifecycle $row -AsOf (D '2024-06-01')
            $s.Status | Should -Be 'Extended support ended'
            $s.Note   | Should -Match 'covered only if the client bought ESU'
        }

        It 'AC5_EsuWindowIsHedged_AfterEsuEnds' {
            $row = New-LcRow -Extended '2023-10-10' -Esu '2026-10-13'
            $s = Get-EndOfSupportStatus -Lifecycle $row -AsOf (D '2026-10-14')
            $s.Status | Should -Be 'No support'
            $s.Note   | Should -Match 'ESU'
            $s.Note   | Should -Not -Match 'covered only if the client bought ESU'
        }

        It 'AC6_MainstreamToExtendedTransition: AsOf <AsOf>' -ForEach @(
            @{ AsOf = '2026-10-13'; Expect = 'Mainstream support' }
            @{ AsOf = '2026-10-14'; Expect = 'Security updates only' }
        ) {
            $row = New-LcRow -Mainstream '2026-10-13' -Extended '2031-10-14'
            (Get-EndOfSupportStatus -Lifecycle $row -AsOf (D $AsOf)).Status | Should -Be $Expect
        }

        It 'AC7_WarningThreshold: <Left> days left is <Expect>' -ForEach @(
            @{ Left = 365; Expect = 'Warning' }
            @{ Left = 366; Expect = 'Info' }
        ) {
            $row = New-LcRow -Extended '2030-06-30'
            $asOf = (D '2030-06-30').AddDays(-$Left)
            $s = Get-EndOfSupportStatus -Lifecycle $row -AsOf $asOf
            $s.Status   | Should -Be 'Security updates only'
            $s.Severity | Should -Be $Expect
        }

        It 'AC8_CultureIndependent' {
            $row = New-LcRow -Mainstream '2020-01-01' -Extended '2027-01-12'
            $dates = @('2027-01-11', '2027-01-12 23:59', '2027-01-13 00:01')
            $expected = @($dates | ForEach-Object {
                $s = Get-EndOfSupportStatus -Lifecycle $row -AsOf (D $_)
                '{0}|{1}' -f $s.Status, $s.DaysUntilExtendedEnd
            })
            $expectedTable = Get-ServerLifecycleTable
            $thread = [System.Threading.Thread]::CurrentThread
            $old = $thread.CurrentCulture
            try {
                $thread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('de-DE')
                $actual = @($dates | ForEach-Object {
                    $s = Get-EndOfSupportStatus -Lifecycle $row -AsOf (D $_)
                    '{0}|{1}' -f $s.Status, $s.DaysUntilExtendedEnd
                })
                $deTable = Get-ServerLifecycleTable
            } finally { $thread.CurrentCulture = $old }
            $actual | Should -Be $expected
            $deTable.CheckedOn | Should -Be $expectedTable.CheckedOn
            @($deTable.Rows).Count | Should -Be @($expectedTable.Rows).Count
        }
    }

    Context 'Get-EndOfSupportAudit collection' {
        It 'AC9_QueriesOnlyEnabledWindowsServersWithAdParams' {
            $ADParams = @{ Server = 'dc01.contoso.com'; Credential = (New-Object System.Management.Automation.PSCredential('CONTOSO\svc-audit', (ConvertTo-SecureString 'Placeholder-1' -AsPlainText -Force))) }
            Mock Get-ADComputer {
                @(
                    (New-FakeServer -Name 'SRV01')
                    (New-FakeServer -Name 'SRV02')
                    (New-FakeServer -Name 'SRV03' -Enabled $false)
                )
            }
            $r = Get-EndOfSupportAudit
            Should -Invoke Get-ADComputer -Times 1 -ParameterFilter {
                $Filter -match "OperatingSystem\s+-like\s+'\*Windows Server\*'" -and
                ($Properties -contains 'OperatingSystem') -and ($Properties -contains 'OperatingSystemVersion') -and
                ($Properties -contains 'LastLogonDate') -and ($Properties -contains 'Enabled') -and
                $Server -eq 'dc01.contoso.com' -and $null -ne $Credential
            }
            @($r.Servers).Count | Should -Be 2
            @($r.Servers | ForEach-Object Name) | Should -Not -Contain 'SRV03'
        }

        It 'AC10_RowsCarryStampAndNoSecrets' {
            $Credential = New-Object System.Management.Automation.PSCredential('CONTOSO\svc-audit', (ConvertTo-SecureString 'Placeholder-1' -AsPlainText -Force))
            $ADParams = @{ Credential = $Credential }
            Mock Get-ADComputer { @(New-FakeServer -Name 'SRV01') }
            $r = Get-EndOfSupportAudit
            $row = @($r.Servers)[0]
            $row.AuditDate      | Should -Match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$'
            $row.AuditedDomain  | Should -Be 'contoso.com'
            $row.RunBy          | Should -Match 'CONTOSO\\svc-audit'
            $row.RunOn          | Should -Be $env:COMPUTERNAME
            $row.TableCheckedOn | Should -Match '^\d{4}-\d{2}-\d{2}$'
            $row.Source         | Should -Not -BeNullOrEmpty
            foreach ($p in $row.PSObject.Properties) {
                $p.Value | Should -Not -BeOfType [System.Management.Automation.PSCredential]
                $p.Value | Should -Not -BeOfType [System.Security.SecureString]
                [string]$p.Value | Should -Not -Match '(?i)password'
                $p.Name | Should -Not -Match '(?i)password'
            }
        }

        It 'AC11_StaleAndNeverLoggedOn' {
            Mock Get-ADComputer {
                @(
                    (New-FakeServer -Name 'SRV01' -LastLogon (D '2026-06-01'))
                    (New-FakeServer -Name 'SRV02' -LastLogon (D '2027-01-25'))
                    (New-FakeServer -Name 'SRV03' -LastLogon $null)
                )
            }
            $r = Get-EndOfSupportAudit
            $by = @{}; foreach ($s in @($r.Servers)) { $by[$s.Name] = $s }
            $by['SRV01'].Stale | Should -BeTrue
            $by['SRV02'].Stale | Should -BeFalse
            $by['SRV03'].Stale | Should -BeTrue
            $by['SRV03'].LastLogonDate | Should -Be 'Never'
        }

        It 'AC14_StaleTableWarns_WhenOlderThan180Days' {
            Mock Get-ADComputer { @(New-FakeServer) }
            $checked = $AuditDate.AddDays(-181).ToString('yyyy-MM-dd')
            Mock Get-ServerLifecycleTable { New-SyntheticTable -CheckedOn $checked }
            $r = Get-EndOfSupportAudit
            $r.StaleTableWarning | Should -Match ([regex]::Escape($checked))
            $r.StaleTableWarning | Should -Match 'https://learn\.microsoft\.com/lifecycle'
            Should -Invoke Write-AuditLog -ParameterFilter {
                $Level -eq 'Warning' -and $Message -match [regex]::Escape($checked) -and $Message -match 'https://learn\.microsoft\.com/lifecycle'
            }
        }

        It 'AC14_StaleTableWarns_NoWarningAt180Days' {
            Mock Get-ADComputer { @(New-FakeServer) }
            $checked = $AuditDate.AddDays(-180).ToString('yyyy-MM-dd')
            Mock Get-ServerLifecycleTable { New-SyntheticTable -CheckedOn $checked }
            $r = Get-EndOfSupportAudit
            $r.StaleTableWarning | Should -BeNullOrEmpty
            Should -Invoke Write-AuditLog -Times 0 -ParameterFilter { $Level -eq 'Warning' }
        }

        It 'AC16_AdFailureIsReportedNotHidden_Collection' {
            Mock Get-ADComputer { throw 'RPC server is unavailable' }
            { $script:r16 = Get-EndOfSupportAudit } | Should -Not -Throw
            @($script:r16.Servers).Count | Should -Be 0
            $script:r16.Error | Should -Match 'RPC server is unavailable'
            Should -Invoke Write-AuditLog -ParameterFilter { $Level -eq 'Error' }
        }

        It 'AC17_EmptyState_Collection' {
            Mock Get-ADComputer { @() }
            $r = Get-EndOfSupportAudit
            @($r.Servers).Count | Should -Be 0
            $r.PastEndCount | Should -Be 0
            $r.Error | Should -BeNullOrEmpty
        }
    }

    Context 'Reports' {
        BeforeEach {
            Mock Get-ServerLifecycleTable { New-SyntheticTable -CheckedOn '2026-09-30' }
        }

        It 'AC12_CsvExport_ColumnsInOrder' {
            $res = New-EmptyAuditResults
            $res.EndOfSupport = @{ Servers = @((New-EosRow -Name 'SRV01'), (New-EosRow -Name 'SRV02')); PastEndCount = 0; StaleTableWarning = $null; Error = $null }
            Export-CSVReports -AuditResults $res -BasePath $TestDrive
            $file = Join-Path $TestDrive 'AD-Audit-test-EndOfSupport.csv'
            $file | Should -Exist
            $header = (Get-Content -LiteralPath $file -TotalCount 1) -split ',' | ForEach-Object { $_.Trim('"') }
            ($header -join ',') | Should -Be 'Name,OperatingSystem,OperatingSystemVersion,Product,Status,Severity,DaysUntilExtendedEnd,MainstreamEnd,ExtendedEnd,EsuEnd,Note,LastLogonDate,Stale,Source,TableCheckedOn,AuditDate,AuditedDomain,RunBy,RunOn'
            @(Import-Csv -LiteralPath $file).Count | Should -Be 2
        }

        It 'AC12_CsvExport_ZeroRowsWritesNoFile' {
            $res = New-EmptyAuditResults
            Export-CSVReports -AuditResults $res -BasePath $TestDrive
            (Join-Path $TestDrive 'AD-Audit-test-EndOfSupport.csv') | Should -Not -Exist
        }

        It 'AC13_HtmlSectionAndSummary' {
            $res = New-EmptyAuditResults
            $rows = @(
                (New-EosRow -Name 'SRV-MAIN' -Status 'Mainstream support'      -Severity 'Low'     -Note 'In mainstream support until 2031-10-14.')
                (New-EosRow -Name 'SRV-SEC'  -Status 'Security updates only'   -Severity 'Info'    -Note 'Mainstream support ended. Security updates until 2029-01-09; 700 days left.')
                (New-EosRow -Name 'SRV-EXT'  -Status 'Extended support ended'  -Severity 'Warning' -Note 'Extended support ended on 2023-10-10; covered only if the client bought ESU (ESU available until 2026-10-13).')
                (New-EosRow -Name 'SRV-NONE' -Status 'No support'              -Severity 'High'    -Note 'All support ended on 2026-10-13, including paid ESU.')
                (New-EosRow -Name 'SRV-UNK'  -Status 'Unknown'                 -Severity 'Warning' -Note 'Not in the lifecycle table - check https://learn.microsoft.com/lifecycle manually.')
                (New-EosRow -Name '<script>x</script>' -Status 'Mainstream support' -Severity 'Low')
            )
            $res.EndOfSupport = @{ Servers = $rows; PastEndCount = 2; StaleTableWarning = $null; Error = $null }
            $out = Join-Path $TestDrive 'r.html'
            Export-HTMLReport -AuditResults $res -OutputFile $out
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match 'id="endofsupport"'
            $html | Should -Match 'href="#endofsupport"'
            $html | Should -Match '2026-09-30'
            $html | Should -Match '14 days'
            $html | Should -Match 'covered only if the client bought ESU'
            $html | Should -Match '(?s)>\s*2\s*</div>\s*<div class="metric-label">Servers past end of support'
            $html | Should -Match ([regex]::Escape('&lt;script&gt;x&lt;/script&gt;'))
            $html | Should -Not -Match ([regex]::Escape('<script>x</script>'))
        }

        It 'AC14_StaleTableWarns_HtmlShowsWarning' {
            $res = New-EmptyAuditResults
            $msg = 'Lifecycle table last checked 2026-06-01 - verify at https://learn.microsoft.com/lifecycle'
            $res.EndOfSupport = @{ Servers = @((New-EosRow)); PastEndCount = 0; StaleTableWarning = $msg; Error = $null }
            $out = Join-Path $TestDrive 'stale.html'
            Export-HTMLReport -AuditResults $res -OutputFile $out
            (Get-Content -LiteralPath $out -Raw) | Should -Match ([regex]::Escape('last checked 2026-06-01'))
        }

        It 'AC15_SectionIsSelectable' {
            $script = Get-Content -LiteralPath $script:ScriptPath -Raw
            $gui    = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $script:ScriptPath) 'Show-ADAuditGUI.ps1') -Raw
            $script | Should -Match "(?s)ValidateSet\([^)]*'EndOfSupport'"
            $script | Should -Match '(?s)\$AllSections\s*=\s*@\([^)]*''EndOfSupport'''
            $gui    | Should -Match "@\{\s*Name\s*=\s*'EndOfSupport'\s*;"
        }

        It 'AC16_AdFailureIsReportedNotHidden_Html' {
            Mock Get-ADComputer { throw 'RPC server is unavailable' }
            $res = New-EmptyAuditResults
            $res.EndOfSupport = Get-EndOfSupportAudit
            $out = Join-Path $TestDrive 'err.html'
            Export-HTMLReport -AuditResults $res -OutputFile $out
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match 'Could not read servers from AD: RPC server is unavailable'
            $html | Should -Not -Match 'No Windows Server computer accounts found'
        }

        It 'AC17_EmptyState_Html' {
            Mock Get-ADComputer { @() }
            $res = New-EmptyAuditResults
            $res.EndOfSupport = Get-EndOfSupportAudit
            $out = Join-Path $TestDrive 'empty.html'
            Export-HTMLReport -AuditResults $res -OutputFile $out
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match 'No enabled Windows Server computer accounts found\.'
            $html | Should -Match '(?s)>\s*0\s*</div>\s*<div class="metric-label">Servers past end of support'
        }
    }

    Context 'Existing Unsupported OS list uses the lifecycle table (D-020)' {
        It 'AC18_ComputersUnsupportedListUsesTable' {
            Mock Get-ADComputer {
                @(
                    (New-FakeServer -Name 'SRV2012' -Os 'Windows Server 2012 R2 Standard')
                    (New-FakeServer -Name 'SRV2016' -Os 'Windows Server 2016 Standard')
                    (New-FakeServer -Name 'SRV2022' -Os 'Windows Server 2022 Datacenter')
                    (New-FakeServer -Name 'PC7'     -Os 'Windows 7 Professional')
                )
            }
            $r = Get-ComputerAccountAudit
            $names = @($r.UnsupportedComputers | ForEach-Object Name)
            $names | Should -Contain 'SRV2012'
            $names | Should -Contain 'SRV2016'
            $names | Should -Not -Contain 'SRV2022'
            $names | Should -Contain 'PC7'
            $names.Count | Should -Be 3
        }
    }
}
