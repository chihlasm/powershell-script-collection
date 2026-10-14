<#
    Nesting graph: edge recording during the walk, protected/built-in detection, and the
    upward completion (Resolve-NestGraph). Functions are loaded from the script by AST.
#>
BeforeAll {
    $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Export-ADGroupMembership.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    foreach ($fn in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        . ([scriptblock]::Create($fn.Extent.Text))
    }
    function Write-Status { }
    function G([string]$Name, [string]$Sid = 'S-1-5-21-1-2-3-1500', [string[]]$MemberOf = @(), [string]$Ou = 'OU=Groups') {
        [PSCustomObject]@{ Name = $Name; SamAccountName = $Name; DistinguishedName = "CN=$Name,$Ou,DC=contoso,DC=com"
            GroupCategory = 'Security'; GroupScope = 'Global'; SID = $Sid; MemberOf = $MemberOf }
    }
    function DN([string]$Name, [string]$Ou = 'OU=Groups') { "CN=$Name,$Ou,DC=contoso,DC=com" }
}

Describe 'Add-NestEdge' {
    It 'stores each parent/child link once' {
        $e = @{}
        Add-NestEdge -Edges $e -ParentDN 'CN=A' -ChildDN 'CN=B'
        Add-NestEdge -Edges $e -ParentDN 'cn=a' -ChildDN 'CN=B'
        $e.Count | Should -Be 1
        $e['CN=A'].Count | Should -Be 1
    }
}

Describe 'Resolve-GroupMembership records nesting edges' {
    BeforeAll {
        $script:IncludeNested = $true; $script:UserMembersOnly = $false; $script:MaxNestingDepth = 10; $script:ADParams = @{}
        function Get-UserDetail { $null }
        # Pester can only mock commands that exist; the AD module is not installed on dev boxes.
        function Get-ADGroupMember { [CmdletBinding()] param([Parameter(Position = 0)]$Identity, $Server, $Credential, [switch]$Recursive) }
    }
    It 'records every group-in-group link, including the one that closes a loop' {
        $script:NestEdges = @{}; $script:NestNames = @{}
        Mock Get-ADGroupMember {
            if ($Identity -eq (DN 'A')) { @([PSCustomObject]@{ Name = 'B'; SamAccountName = 'B'; objectClass = 'group'; DistinguishedName = (DN 'B') }) }
            else { @([PSCustomObject]@{ Name = 'A'; SamAccountName = 'A'; objectClass = 'group'; DistinguishedName = (DN 'A') }) }
        }
        $root = [PSCustomObject]@{ Name = 'A'; DistinguishedName = (DN 'A') }
        $visited = New-Object 'System.Collections.Generic.HashSet[string]'
        [void]$visited.Add((DN 'A'))
        $null = Resolve-GroupMembership -Group $root -RootGroup $root -Depth 0 -Path '' -VisitedGroups $visited
        $script:NestEdges[(DN 'A')].ContainsKey((DN 'B')) | Should -BeTrue
        $script:NestEdges[(DN 'B')].ContainsKey((DN 'A')) | Should -BeTrue -Because 'the loop-closing edge must be recorded'
        $script:NestNames[(DN 'B')] | Should -Be 'B'
    }
}

Describe 'Protected and built-in detection' {
    It 'recognises protected groups by SID, whatever their name' {
        Test-ProtectedGroupSid 'S-1-5-32-544' | Should -BeTrue
        Test-ProtectedGroupSid 'S-1-5-21-111-222-333-512' | Should -BeTrue
        Test-ProtectedGroupSid 'S-1-5-21-111-222-333-519' | Should -BeTrue
        Test-ProtectedGroupSid 'S-1-5-21-111-222-333-513' | Should -BeFalse -Because 'Domain Users is not protected'
        Test-ProtectedGroupSid 'S-1-5-32-545' | Should -BeFalse
        Test-ProtectedGroupSid 'S-1-5-21-111-222-333-1512' | Should -BeFalse
        Test-ProtectedGroupSid '' | Should -BeFalse
    }
    It 'recognises built-in groups by container or well-known SID' {
        Test-BuiltinGroup -DistinguishedName 'CN=Administrators,CN=Builtin,DC=contoso,DC=com' -Sid '' | Should -BeTrue
        Test-BuiltinGroup -DistinguishedName 'CN=X,OU=Groups,DC=contoso,DC=com' -Sid 'S-1-5-21-1-2-3-512' | Should -BeTrue
        Test-BuiltinGroup -DistinguishedName 'CN=X,OU=Groups,DC=contoso,DC=com' -Sid 'S-1-5-21-1-2-3-1105' | Should -BeFalse
    }
}

Describe 'Resolve-NestGraph' {
    BeforeAll {
        # Directory: Helpdesk -> IT-Staff -> IT-Admins -> Administrators (builtin, not exported)
        $script:Dir = @{}
        foreach ($g in @(
            (G 'IT-Staff' 'S-1-5-21-1-2-3-1201' @((DN 'IT-Admins')))
            (G 'IT-Admins' 'S-1-5-21-1-2-3-1202' @((DN 'Administrators' 'CN=Builtin')))
            (G 'Administrators' 'S-1-5-32-544' @() 'CN=Builtin')
        )) { $script:Dir[$g.DistinguishedName] = $g }
        $script:Lookup = { param($dn) if ($script:Dir.ContainsKey($dn)) { $script:Dir[$dn] } else { throw "not found: $dn" } }
    }

    It 'follows parents outside the export up to the top' {
        $edges = @{}
        $helpdesk = G 'Helpdesk' 'S-1-5-21-1-2-3-1200' @((DN 'IT-Staff'))
        $r = Resolve-NestGraph -Groups @($helpdesk) -Edges $edges -Lookup $script:Lookup
        $r.Nodes.ContainsKey((DN 'Administrators' 'CN=Builtin')) | Should -BeTrue
        $r.Nodes[(DN 'Administrators' 'CN=Builtin')].InExport | Should -BeFalse
        $r.Nodes[(DN 'Helpdesk')].InExport | Should -BeTrue
        $edges[(DN 'IT-Admins')].ContainsKey((DN 'IT-Staff')) | Should -BeTrue
        $edges[(DN 'Administrators' 'CN=Builtin')].ContainsKey((DN 'IT-Admins')) | Should -BeTrue
        $r.Lookups | Should -Be 3
        $r.CapReached | Should -BeFalse
    }

    It 'never looks up the same group twice' {
        $edges = @{}
        $a = G 'A1' 'S-1-5-21-1-2-3-1301' @((DN 'IT-Staff'))
        $b = G 'B1' 'S-1-5-21-1-2-3-1302' @((DN 'IT-Staff'))
        $r = Resolve-NestGraph -Groups @($a, $b) -Edges $edges -Lookup $script:Lookup
        $r.Lookups | Should -Be 3
    }

    It 'records an unreadable parent as unresolved and carries on' {
        $edges = @{}
        $x = G 'X1' 'S-1-5-21-1-2-3-1401' @('CN=Gone,OU=Old,DC=contoso,DC=com', (DN 'IT-Staff'))
        $r = Resolve-NestGraph -Groups @($x) -Edges $edges -Lookup $script:Lookup
        $r.Nodes['CN=Gone,OU=Old,DC=contoso,DC=com'].Unresolved | Should -BeTrue
        $r.Nodes['CN=Gone,OU=Old,DC=contoso,DC=com'].Name | Should -Be 'Gone'
        $r.Nodes.ContainsKey((DN 'Administrators' 'CN=Builtin')) | Should -BeTrue
    }

    It 'stops at the lookup cap and marks the rest unresolved' {
        $edges = @{}
        $helpdesk = G 'Helpdesk' 'S-1-5-21-1-2-3-1200' @((DN 'IT-Staff'))
        $r = Resolve-NestGraph -Groups @($helpdesk) -Edges $edges -Lookup $script:Lookup -Cap 1
        $r.CapReached | Should -BeTrue
        $r.Lookups | Should -Be 1
        $r.Nodes[(DN 'IT-Admins')].Unresolved | Should -BeTrue
    }

    It 'resolves children seen in the walk that were not exported' {
        $edges = @{}
        Add-NestEdge -Edges $edges -ParentDN (DN 'Helpdesk') -ChildDN (DN 'IT-Staff')
        $helpdesk = G 'Helpdesk' 'S-1-5-21-1-2-3-1200'
        $r = Resolve-NestGraph -Groups @($helpdesk) -Edges $edges -Lookup $script:Lookup
        $r.Nodes[(DN 'IT-Staff')].Unresolved | Should -BeFalse
        $r.Nodes[(DN 'IT-Staff')].Sid | Should -Be 'S-1-5-21-1-2-3-1201'
    }

    It 'accepts a SecurityIdentifier object as the SID' {
        $edges = @{}
        $g = G 'Sid1'
        $g.SID = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
        $r = Resolve-NestGraph -Groups @($g) -Edges $edges -Lookup $script:Lookup
        $r.Nodes[(DN 'Sid1')].Sid | Should -Be 'S-1-5-32-544'
    }
}

Describe 'ConvertTo-NestModel and ConvertTo-NestJson' {
    BeforeAll {
        $edges = @{}
        Add-NestEdge -Edges $edges -ParentDN (DN 'IT-Admins') -ChildDN (DN 'IT-Staff')
        Add-NestEdge -Edges $edges -ParentDN (DN 'Administrators' 'CN=Builtin') -ChildDN (DN 'IT-Admins')
        $nodes = @{}
        foreach ($n in @(
            [PSCustomObject]@{ DN = (DN 'IT-Staff'); Name = 'IT-Staff'; Sam = 'IT-Staff'; Category = 'Security'; Scope = 'Global'; Sid = 'S-1-5-21-1-2-3-1201'; InExport = $true; Unresolved = $false }
            [PSCustomObject]@{ DN = (DN 'IT-Admins'); Name = 'IT-Admins'; Sam = 'IT-Admins'; Category = 'Security'; Scope = 'Global'; Sid = 'S-1-5-21-1-2-3-1202'; InExport = $true; Unresolved = $false }
            [PSCustomObject]@{ DN = (DN 'Administrators' 'CN=Builtin'); Name = 'Administrators'; Sam = 'Administrators'; Category = 'Security'; Scope = 'DomainLocal'; Sid = 'S-1-5-32-544'; InExport = $false; Unresolved = $false }
            [PSCustomObject]@{ DN = (DN 'Lonely'); Name = 'Lonely'; Sam = 'Lonely'; Category = 'Security'; Scope = 'Global'; Sid = 'S-1-5-21-1-2-3-1999'; InExport = $true; Unresolved = $false }
        )) { $nodes[$n.DN] = $n }
        $script:Graph = [PSCustomObject]@{ Nodes = $nodes; CapReached = $false; Lookups = 1 }
        $script:Model = ConvertTo-NestModel -Graph $script:Graph -Edges $edges -NestedExpanded
        function Id([string]$Name) { for ($i = 0; $i -lt $script:Model.Nodes.Count; $i++) { if ($script:Model.Nodes[$i].n -eq $Name) { return $i } }; -1 }
    }

    It 'includes only groups with at least one nesting link' {
        $script:Model.Nodes.Count | Should -Be 3
        Id 'Lonely' | Should -Be -1
    }
    It 'stores direct parents and children by index' {
        @($script:Model.Up[(Id 'IT-Staff')]) | Should -Be @((Id 'IT-Admins'))
        @($script:Model.Down[(Id 'Administrators')]) | Should -Be @((Id 'IT-Admins'))
        @($script:Model.Up[(Id 'Administrators')]).Count | Should -Be 0
    }
    It 'flags protected, built-in and fetched-only groups' {
        $a = $script:Model.Nodes[(Id 'Administrators')]
        $a.p | Should -BeTrue; $a.b | Should -BeTrue; $a.x | Should -BeFalse
        $script:Model.Nodes[(Id 'IT-Staff')].p | Should -BeFalse
        $script:Model.Nodes[(Id 'IT-Staff')].x | Should -BeTrue
    }
    It 'serialises to JSON that parses back, with flags' {
        $j = ConvertFrom-Json (ConvertTo-NestJson -Model $script:Model)
        @($j.nodes).Count | Should -Be 3
        $j.flags.nestedExpanded | Should -BeTrue
        $j.flags.capReached | Should -BeFalse
        @($j.up[(Id 'IT-Staff')]) | Should -Be @((Id 'IT-Admins'))
    }
    It 'escapes hostile names' {
        $edges = @{}
        Add-NestEdge -Edges $edges -ParentDN 'CN=P,DC=x' -ChildDN 'CN=C,DC=x'
        $nodes = @{
            'CN=P,DC=x' = [PSCustomObject]@{ DN = 'CN=P,DC=x'; Name = '</script><img src=x onerror=alert(1)>'; Sam = ''; Category = ''; Scope = ''; Sid = ''; InExport = $true; Unresolved = $false }
            'CN=C,DC=x' = [PSCustomObject]@{ DN = 'CN=C,DC=x'; Name = '"q"'; Sam = ''; Category = ''; Scope = ''; Sid = ''; InExport = $true; Unresolved = $false }
        }
        $json = ConvertTo-NestJson -Model (ConvertTo-NestModel -Graph ([PSCustomObject]@{ Nodes = $nodes; CapReached = $true }) -Edges $edges)
        $json | Should -Not -Match '<'
        (ConvertFrom-Json $json).flags.capReached | Should -BeTrue
        @((ConvertFrom-Json $json).nodes | ForEach-Object { $_.n }) | Should -Contain '</script><img src=x onerror=alert(1)>'
    }
}
