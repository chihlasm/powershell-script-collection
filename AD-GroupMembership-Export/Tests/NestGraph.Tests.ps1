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
