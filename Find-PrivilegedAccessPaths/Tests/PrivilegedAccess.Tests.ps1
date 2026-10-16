#Requires -Version 5.1
<#
    Pester 5 tests for Get-DomainPrivilegedAccess.ps1 and Find-PrivilegedAccessPaths.ps1.

    The ActiveDirectory cmdlets are replaced by small in-memory fakes (defined below) so the
    group-walking logic runs against a known directory: nesting, a circular nest, a primary-group
    member, localized group names and a decoy group that only LOOKS privileged by name.
#>

BeforeAll {
    $script:Domain  = Join-Path $PSScriptRoot '..\Get-DomainPrivilegedAccess.ps1'
    $script:Single  = Join-Path $PSScriptRoot '..\Find-PrivilegedAccessPaths.ps1'
    $script:DomSid  = 'S-1-5-21-1111-2222-3333'
    $script:Calls   = New-Object System.Collections.ArrayList

    # Localized "Domain Admins" ("Domaenen-Admins" with an a-umlaut) - built with [char] so this file stays ASCII.
    $script:LocalizedDA = 'Dom' + [char]0x00E4 + 'nen-Admins'
    $script:LocalizedAdmins = 'Administratoren'

    function script:New-FakeSid([string]$Sid) { New-Object System.Security.Principal.SecurityIdentifier $Sid }
    function script:New-FakeGroup([string]$Name, [string]$Sid) {
        [PSCustomObject]@{ Name = $Name; SamAccountName = $Name; DistinguishedName = "CN=$Name,OU=G,DC=c,DC=com"
            SID = (New-FakeSid $Sid); objectClass = 'group'; GroupScope = 'Global'; GroupCategory = 'Security'; MemberOf = @() }
    }
    function script:New-FakeUser([string]$Sam, [int]$Rid, [int]$PrimaryRid = 513) {
        [PSCustomObject]@{ Name = $Sam; SamAccountName = $Sam; DistinguishedName = "CN=$Sam,OU=U,DC=c,DC=com"
            SID = (New-FakeSid "$($script:DomSid)-$Rid"); ObjectSID = (New-FakeSid "$($script:DomSid)-$Rid")
            objectClass = 'user'; PrimaryGroupID = $PrimaryRid; MemberOf = @() }
    }

    function script:Initialize-FakeDirectory {
        $sid = $script:DomSid
        $da      = New-FakeGroup $script:LocalizedDA "$sid-512"                  # localized name, well-known RID
        $admins  = New-FakeGroup $script:LocalizedAdmins 'S-1-5-32-544'          # localized BUILTIN\Administrators
        $itAdm   = New-FakeGroup 'IT-Admins' "$sid-1100"
        $help    = New-FakeGroup 'Helpdesk' "$sid-1101"
        $ops     = New-FakeGroup 'Ops' "$sid-1200"
        $decoy   = New-FakeGroup 'Domain Admins' "$sid-2000"                     # English name, NOT the well-known RID
        $dns     = New-FakeGroup 'DnsAdmins' "$sid-1300"
        $du      = New-FakeGroup 'Domain Users' "$sid-513"
        $script:Groups = @($da, $admins, $itAdm, $help, $ops, $decoy, $dns, $du)

        $alice = New-FakeUser 'alice' 2001           # Helpdesk -> IT-Admins -> DA
        $bob   = New-FakeUser 'bob' 2002             # direct DA
        $carol = New-FakeUser 'carol' 2003 512       # primary group = DA, NOT in member
        $dave  = New-FakeUser 'dave' 2004 1200       # primary group = Ops (nested into IT-Admins), NOT in member
        $eve   = New-FakeUser 'eve' 2005             # member of the decoy 'Domain Admins'
        $frank = New-FakeUser 'frank' 2006 512       # direct member of DA AND primary group DA
        $gina  = New-FakeUser 'gina' 2007            # DnsAdmins (name-only group)
        $script:Users = @($alice, $bob, $carol, $dave, $eve, $frank, $gina)

        # Directory 'member' attribute. IT-Admins <-> Helpdesk is a circular nest.
        $script:Members = @{
            $da.DistinguishedName     = @($bob, $itAdm, $frank)
            $itAdm.DistinguishedName  = @($help, $ops)
            $help.DistinguishedName   = @($alice, $itAdm)
            $decoy.DistinguishedName  = @($eve)
            $dns.DistinguishedName    = @($gina)
            $admins.DistinguishedName = @()
        }
        # Back-links (memberOf) derived from member so both views agree.
        foreach ($g in $script:Groups) { $g.MemberOf = @() }
        foreach ($parentDn in $script:Members.Keys) {
            foreach ($m in $script:Members[$parentDn]) { $m.MemberOf = @($m.MemberOf) + @($parentDn) }
        }
        $script:RecursiveUsed = $false
        $script:Calls.Clear()
    }

    function script:Get-ADGroup {
        [CmdletBinding()] param([Parameter(Position = 0)]$Identity, $Filter, $Properties, $Server, $Credential)
        [void]$script:Calls.Add(@{ Cmd = 'Get-ADGroup'; Server = $Server })
        if ($Filter) {
            if ($Filter -match "Name -eq '(.+)'") { $n = $Matches[1]; return @($script:Groups | Where-Object Name -eq $n) }
            return $script:Groups
        }
        $g = $script:Groups | Where-Object { $_.DistinguishedName -eq $Identity -or $_.SID.Value -eq $Identity -or $_.Name -eq $Identity }
        if (-not $g) { throw "Cannot find an object with identity: '$Identity'" }
        return $g
    }
    function script:Get-ADGroupMember {
        [CmdletBinding()] param([Parameter(Position = 0)]$Identity, $Server, $Credential, [switch]$Recursive)
        [void]$script:Calls.Add(@{ Cmd = 'Get-ADGroupMember'; Server = $Server })
        if ($Recursive) { $script:RecursiveUsed = $true }
        @($script:Members[$Identity])
    }
    function script:Get-ADUser {
        [CmdletBinding()] param([Parameter(Position = 0)]$Identity, $Filter, $Properties, $Server, $Credential)
        [void]$script:Calls.Add(@{ Cmd = 'Get-ADUser'; Server = $Server })
        if ($Filter -match 'primaryGroupID -eq (\d+)') { $rid = [int]$Matches[1]; return @($script:Users | Where-Object { $_.primaryGroupID -eq $rid }) }
        $script:Users | Where-Object { $_.DistinguishedName -eq $Identity -or $_.SamAccountName -eq $Identity }
    }
    function script:Get-ADForest { throw 'single-domain forest in these tests' }
    function script:Get-ADDomain { throw 'not used' }

    function script:Get-FunctionText {
        param([string]$Path, [string]$Name)
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true)
        if (-not $fn) { return $null }
        return ($fn.Body.Extent.Text -replace '\s+', ' ').Trim()
    }
}

Describe 'Script shape' {
    It '<_> declares #Requires -Version 3.0 and no -Modules' -ForEach @('Get-DomainPrivilegedAccess.ps1', 'Find-PrivilegedAccessPaths.ps1') {
        $head = (Get-Content -Path (Join-Path $PSScriptRoot "..\$_") -TotalCount 3) -join "`n"
        $head | Should -Match '#Requires -Version 3\.0'
        $head | Should -Not -Match '#Requires -Modules'
    }
    It '<_> has OutputPath (alias ExportPath), Server, Credential and LoadFunctionsOnly' -ForEach @('Get-DomainPrivilegedAccess.ps1', 'Find-PrivilegedAccessPaths.ps1') {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot "..\$_"), [ref]$null, [ref]$null)
        $names = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        $names | Should -Contain 'OutputPath'
        $names | Should -Contain 'Server'
        $names | Should -Contain 'Credential'
        $names | Should -Contain 'LoadFunctionsOnly'
        $names | Should -Not -Contain 'ExportPath'
        $out = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'OutputPath' }
        (($out.Attributes | ForEach-Object { $_.Extent.Text }) -join ' ') | Should -Match "Alias\('ExportPath'\)"
    }
    It '<_> exports CSV as UTF8 and carries no client branding' -ForEach @('Get-DomainPrivilegedAccess.ps1', 'Find-PrivilegedAccessPaths.ps1') {
        $text = Get-Content -Path (Join-Path $PSScriptRoot "..\$_") -Raw
        $text | Should -Not -Match 'VC3'
        foreach ($m in [regex]::Matches($text, 'Export-Csv[^\r\n]*')) { $m.Value | Should -Match '-Encoding UTF8' }
        $text | Should -Match 'REFERENCES'
    }
    It 'does not use Get-ADGroupMember -Recursive' {
        # Inspect real command usage (the help text mentions the switch to explain why it is avoided).
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Domain, [ref]$null, [ref]$null)
        $cmds = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Get-ADGroupMember' }, $true)
        @($cmds).Count | Should -BeGreaterThan 0
        foreach ($c in $cmds) { $c.Extent.Text | Should -Not -Match '-Recursive' }
    }
    It 'shared helper <_> is identical in both scripts' -ForEach @('Get-PrivilegedGroupDefinition', 'Get-NameOnlyPrivilegedGroup', 'Find-PrivilegedGroupBySid', 'Resolve-ReportFilePath') {
        $a = Get-FunctionText -Path $script:Domain -Name $_
        $a | Should -Not -BeNullOrEmpty
        (Get-FunctionText -Path $script:Single -Name $_) | Should -Be $a
    }
}

Describe 'Well-known privileged group definitions' {
    BeforeAll { . $script:Domain -LoadFunctionsOnly }

    It 'is keyed by SID: domain-relative RIDs under the domain SID, builtin under S-1-5-32' {
        $defs = @(Get-PrivilegedGroupDefinition -DomainSid $script:DomSid)
        ($defs | Where-Object Sid -eq "$($script:DomSid)-512").Name | Should -Be 'Domain Admins'
        ($defs | Where-Object Sid -eq 'S-1-5-32-544').Name | Should -Be 'Administrators'
        ($defs | Where-Object Sid -eq 'S-1-5-32-578').Name | Should -Be 'Hyper-V Administrators'
        ($defs | Where-Object Sid -eq 'S-1-5-32-580').Name | Should -Be 'Remote Management Users'
    }
    It 'adds forest-root SIDs for forest-wide groups only when the root differs' {
        $same = @(Get-PrivilegedGroupDefinition -DomainSid $script:DomSid -RootDomainSid $script:DomSid)
        $diff = @(Get-PrivilegedGroupDefinition -DomainSid $script:DomSid -RootDomainSid 'S-1-5-21-9-9-9')
        @($diff | Where-Object Sid -eq 'S-1-5-21-9-9-9-519').Count | Should -Be 1
        @($diff | Where-Object Sid -eq 'S-1-5-21-9-9-9-512').Count | Should -Be 0   # Domain Admins is per-domain
        $diff.Count | Should -BeGreaterThan $same.Count
    }
    It 'flags the AdminSDHolder-protected groups' {
        $defs = @(Get-PrivilegedGroupDefinition -DomainSid $script:DomSid)
        ($defs | Where-Object Rid -eq 512).AdminSdHolder | Should -BeTrue
        ($defs | Where-Object Rid -eq 544).AdminSdHolder | Should -BeTrue
        ($defs | Where-Object Rid -eq 517).AdminSdHolder | Should -BeFalse   # Cert Publishers is not protected
    }
    It 'matches by exact SID, never by name' {
        $defs = @(Get-PrivilegedGroupDefinition -DomainSid $script:DomSid)
        (Find-PrivilegedGroupBySid -Sid "$($script:DomSid)-512" -Definitions $defs).Name | Should -Be 'Domain Admins'
        Find-PrivilegedGroupBySid -Sid "$($script:DomSid)-2000" -Definitions $defs | Should -BeNullOrEmpty
    }
    It 'matches the whole RID for SID history, so RID 12 can not match 512' {
        $defs = @(Get-PrivilegedGroupDefinition -DomainSid $script:DomSid)
        (Find-PrivilegedGroupBySid -Sid 'S-1-5-21-7-8-9-512' -Definitions $defs -AnyDomain).Name | Should -Be 'Domain Admins'
        Find-PrivilegedGroupBySid -Sid 'S-1-5-21-7-8-9-12' -Definitions $defs -AnyDomain | Should -BeNullOrEmpty
        Find-PrivilegedGroupBySid -Sid 'S-1-5-21-7-8-9-512' -Definitions $defs | Should -BeNullOrEmpty   # no -AnyDomain: wrong domain
    }
}

Describe 'Resolve-ReportFilePath' {
    BeforeAll { . $script:Domain -LoadFunctionsOnly }
    It 'treats a .csv path as the file and a directory as a folder for the default name' {
        $file = Join-Path $TestDrive 'a\b.csv'
        Resolve-ReportFilePath -Path $file -DefaultFileName 'x.csv' | Should -Be $file
        Test-Path (Join-Path $TestDrive 'a') | Should -BeTrue
        Resolve-ReportFilePath -Path (Join-Path $TestDrive 'out') -DefaultFileName 'x.csv' | Should -Be (Join-Path $TestDrive 'out\x.csv')
    }
}

Describe 'Get-DomainPrivilegedAccess - group membership walk' {
    BeforeAll {
        . $script:Domain -LoadFunctionsOnly
        $script:Defs = @(Get-PrivilegedGroupDefinition -DomainSid $script:DomSid)
    }
    BeforeEach {
        Initialize-FakeDirectory
        $script:Map = Get-PrivilegedGroupMembership -Definitions $script:Defs -DomainSid $script:DomSid -NameOnly @() 6>$null
        function script:Get-Entry($sam, $label) {
            $dn = "CN=$sam,OU=U,DC=c,DC=com"
            if (-not $script:Map.ContainsKey($dn)) { return $null }
            @($script:Map[$dn] | Where-Object GroupName -eq $label)
        }
    }

    It 'records a direct member as Direct with no path' {
        $e = @(Get-Entry 'bob' 'Domain Admins')
        $e.Count | Should -Be 1
        $e[0].MembershipType | Should -Be 'Direct'
        $e[0].NestedVia | Should -Be ''
    }
    It 'records the nesting path for a nested member' {
        $e = @(Get-Entry 'alice' 'Domain Admins')
        $e.Count | Should -Be 1
        $e[0].MembershipType | Should -Be 'Nested'
        $e[0].NestedVia | Should -Be 'IT-Admins -> Helpdesk'
        $e[0].NestingDepth | Should -Be 2
    }
    It 'does not loop on circular nesting and reports each user once per group' {
        # IT-Admins contains Helpdesk which contains IT-Admins. Reaching here at all means no infinite loop.
        @(Get-Entry 'alice' 'Domain Admins').Count | Should -Be 1
        @(Get-Entry 'bob' 'Domain Admins').Count | Should -Be 1
    }
    It 'includes a user whose primaryGroupID points at the group but who is not in member' {
        $e = @(Get-Entry 'carol' 'Domain Admins')
        $e.Count | Should -Be 1
        $e[0].MembershipType | Should -Be 'Primary'
    }
    It 'reports a user who is both a member and has the group as primary group once, as Primary' {
        $e = @(Get-Entry 'frank' 'Domain Admins')
        $e.Count | Should -Be 1
        $e[0].MembershipType | Should -Be 'Primary'
    }
    It 'follows a primary group that is itself nested into a privileged group' {
        $e = @(Get-Entry 'dave' 'Domain Admins')
        $e.Count | Should -Be 1
        $e[0].MembershipType | Should -Be 'Nested'
        $e[0].NestedVia | Should -Be 'IT-Admins -> Ops (primary group)'
    }
    It 'detects privileged groups with localized names through their SID' {
        # The group is called "Domaenen-Admins" / "Administratoren" in this directory.
        @(Get-Entry 'bob' 'Domain Admins').Count | Should -Be 1
        $script:Groups | Where-Object Name -eq $script:LocalizedDA | Should -Not -BeNullOrEmpty
        $all = @($script:Map.Values | ForEach-Object { $_ } | Select-Object -ExpandProperty GroupName -Unique)
        $all | Should -Contain 'Domain Admins'
        $all | Should -Not -Contain $script:LocalizedDA
    }
    It 'ignores a group that is merely NAMED like a privileged group' {
        $script:Map.ContainsKey('CN=eve,OU=U,DC=c,DC=com') | Should -BeFalse
    }
    It 'never calls Get-ADGroupMember -Recursive' {
        $script:RecursiveUsed | Should -BeFalse
    }
    It 'locates the name-only groups (DnsAdmins) by name' {
        Initialize-FakeDirectory
        $map = Get-PrivilegedGroupMembership -Definitions $script:Defs -DomainSid $script:DomSid -NameOnly @(Get-NameOnlyPrivilegedGroup) 6>$null
        @($map['CN=gina,OU=U,DC=c,DC=com'] | Where-Object GroupName -eq 'DnsAdmins').Count | Should -Be 1
    }
    It 'passes -Server to every Active Directory call' {
        Initialize-FakeDirectory
        # Local $ADParams shadows the one from dot-sourcing for the functions called below (dynamic scoping).
        $ADParams = @{ Server = 'dc1.contoso.com' }
        $null = Get-PrivilegedGroupMembership -Definitions $script:Defs -DomainSid $script:DomSid -NameOnly @() 6>$null
        $script:Calls.Count | Should -BeGreaterThan 0
        @($script:Calls | Where-Object { $_.Server -ne 'dc1.contoso.com' }).Count | Should -Be 0
    }
    It 'stops at MaxNestingDepth' {
        Initialize-FakeDirectory
        $g = $script:Groups | Where-Object Name -eq $script:LocalizedDA
        $rows = @(Get-GroupMemberPath -Group $g -DomainSid $script:DomSid -MaxNestingDepth 1 3>$null)
        @($rows | Where-Object { $_.UserDN -like 'CN=alice,*' }).Count | Should -Be 0
        @($rows | Where-Object { $_.UserDN -like 'CN=bob,*' }).Count | Should -Be 1
    }
}

Describe 'Find-PrivilegedAccessPaths - upward group walk' {
    BeforeAll {
        . $script:Single -LoadFunctionsOnly
        $script:Defs = @(Get-PrivilegedGroupDefinition -DomainSid $script:DomSid)
        $script:NameOnly = @(Get-NameOnlyPrivilegedGroup)
        function script:Get-Rows($sam) {
            $u = $script:Users | Where-Object SamAccountName -eq $sam
            @(Get-UserGroupPath -User $u -DomainSid $script:DomSid -Definitions $script:Defs -NameOnly $script:NameOnly)
        }
    }
    BeforeEach { Initialize-FakeDirectory }

    It 'records the nested path and finds the privileged group by SID' {
        $rows = Get-Rows 'alice'
        $da = @($rows | Where-Object { $_.Privileged -and $_.Privileged.Name -eq 'Domain Admins' })
        $da.Count | Should -Be 1
        $da[0].MembershipType | Should -Be 'Nested'
        $da[0].NestedVia | Should -Be 'Helpdesk -> IT-Admins'
        $da[0].GroupName | Should -Be $script:LocalizedDA
    }
    It 'does not loop on circular nesting' {
        $rows = Get-Rows 'alice'
        @($rows | Where-Object GroupName -eq 'Helpdesk').Count | Should -Be 1
        @($rows | Where-Object GroupName -eq 'IT-Admins').Count | Should -Be 1
    }
    It 'treats a direct privileged membership as Direct' {
        $rows = Get-Rows 'bob'
        $da = @($rows | Where-Object { $_.Privileged -and $_.Privileged.Name -eq 'Domain Admins' })
        $da.Count | Should -Be 1
        $da[0].MembershipType | Should -Be 'Direct'
    }
    It 'includes the primary group even though it is not in memberOf' {
        $rows = Get-Rows 'carol'
        $da = @($rows | Where-Object { $_.Privileged -and $_.Privileged.Name -eq 'Domain Admins' })
        $da.Count | Should -Be 1
        $da[0].MembershipType | Should -Be 'Primary'
    }
    It 'follows the parents of a nested primary group' {
        $rows = Get-Rows 'dave'
        $da = @($rows | Where-Object { $_.Privileged -and $_.Privileged.Name -eq 'Domain Admins' })
        $da.Count | Should -Be 1
        $da[0].NestedVia | Should -Be 'Ops (primary group) -> IT-Admins'
    }
    It 'does not treat a group merely named Domain Admins as privileged' {
        $rows = Get-Rows 'eve'
        @($rows | Where-Object { $_.Privileged }).Count | Should -Be 0
    }
    It 'matches DnsAdmins by name' {
        $rows = Get-Rows 'gina'
        @($rows | Where-Object { $_.Privileged -and $_.Privileged.Name -eq 'DnsAdmins' }).Count | Should -Be 1
    }
    It 'passes -Server to every Active Directory call' {
        $ADParams = @{ Server = 'dc1.contoso.com' }
        $null = Get-Rows 'alice'
        $script:Calls.Count | Should -BeGreaterThan 0
        @($script:Calls | Where-Object { $_.Server -ne 'dc1.contoso.com' }).Count | Should -Be 0
    }
}
