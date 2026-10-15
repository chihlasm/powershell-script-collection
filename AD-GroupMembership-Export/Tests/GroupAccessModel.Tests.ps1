<#
    Tests for the data behind the report's Groups and Overlap tabs: the group model, the
    JSON embedding, and the page structure. No domain needed - every function is loaded
    from the script by AST (defining functions runs nothing) and fed hand-built rows.
#>

BeforeAll {
    $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Export-ADGroupMembership.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    foreach ($fn in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        . ([scriptblock]::Create($fn.Extent.Text))
    }

    function New-Grp([string]$Name, [string]$Ou = 'OU=Groups,OU=HR', [string]$ManagedBy = $null) {
        [PSCustomObject]@{
            Name = $Name; SamAccountName = $Name; GroupCategory = 'Security'; GroupScope = 'Global'
            Description = "$Name description"; DistinguishedName = "CN=$Name,$Ou,DC=contoso,DC=com"; ManagedBy = $ManagedBy
        }
    }
    function New-Mbr([string]$Name, [string]$Class = 'user') {
        [PSCustomObject]@{ Name = $Name; SamAccountName = $Name; objectClass = $Class; DistinguishedName = "CN=$Name,OU=Staff,DC=contoso,DC=com" }
    }
    function New-Detail([bool]$Enabled = $true, [string]$Dept = 'HR') {
        [PSCustomObject]@{ DisplayName = $null; UserPrincipalName = $null; EmailAddress = $null; Department = $Dept
                           Title = $null; Enabled = $Enabled; LastLogonDate = $null; PasswordLastSet = $null }
    }
    function Row($Group, $Member, [string]$Type, [int]$Depth = 0, [string]$Via = '', $Detail = (New-Detail)) {
        $d = if ($Member.objectClass -eq 'user') { $Detail } else { $null }
        New-MembershipRow -Group $Group -Member $Member -MembershipType $Type -NestingDepth $Depth -NestedVia $Via -UserDetail $d
    }

    $hr    = New-Grp 'HR-Staff' -ManagedBy 'CN=Doe\, Jane,OU=Staff,DC=contoso,DC=com'
    $temps = New-Grp 'HR-Temps'
    $fin   = New-Grp 'Finance' 'OU=Groups,OU=Finance'
    $empty = New-Grp 'Old-Project' 'CN=Users'
    $pcs   = New-Grp 'Kiosk-PCs'
    $script:Groups = @($hr, $temps, $fin, $empty, $pcs)

    $alice = New-Mbr 'alice'; $bob = New-Mbr 'bob'; $carol = New-Mbr 'carol'
    $dave = New-Mbr 'dave'; $frank = New-Mbr 'frank'; $kiosk = New-Mbr 'KIOSK01' 'computer'
    $tempsAsMember = [PSCustomObject]@{ Name = 'HR-Temps'; SamAccountName = 'HR-Temps'; objectClass = 'group'; DistinguishedName = $temps.DistinguishedName }

    $script:Rows = @(
        (Row $hr $alice 'Direct')
        (Row $hr $alice 'Nested' 1 'HR-Temps')          # alice also via HR-Temps: strongest (direct) wins
        (Row $hr $bob 'Direct')
        (Row $hr $tempsAsMember 'Direct')
        (Row $hr $carol 'Nested' 1 'HR-Temps')
        (Row $temps $carol 'Direct')
        (Row $temps $alice 'Direct')
        (Row $fin $dave 'Primary')
        (Row $fin $bob 'Direct' 0 '' (New-Detail $true 'Finance'))
        (Row $fin $frank 'Direct' 0 '' (New-Detail $false))   # disabled
        (Row $pcs $kiosk 'Direct')
        (New-MembershipRow -Group $empty -Member $null -MembershipType 'EmptyGroup' -NestingDepth 0 -NestedVia '' -UserDetail $null)
    )

    function Find-Group($Model, [string]$Name) { @($Model.Groups | Where-Object { $_.n -eq $Name })[0] }
    function Find-PersonId($Model, [string]$Sam) {
        for ($i = 0; $i -lt $Model.People.Count; $i++) { if ($Model.People[$i].s -eq $Sam) { return $i } }
        return -1
    }
}

Describe 'DN helpers' {
    It 'reads the first RDN value, unescaping commas' {
        Get-DnFirstValue 'CN=Doe\, Jane,OU=Staff,DC=contoso,DC=com' | Should -Be 'Doe, Jane'
    }
    It 'unescapes hex-escaped characters' {
        Get-DnFirstValue 'CN=Smith\2C Bob,OU=Staff,DC=contoso,DC=com' | Should -Be 'Smith, Bob'
    }
    It 'turns a DN into a top-down OU path without domain components' {
        ConvertTo-OuPath 'CN=HR-Staff,OU=Groups,OU=HR,DC=contoso,DC=com' | Should -Be 'HR / Groups'
        ConvertTo-OuPath 'CN=Old-Project,CN=Users,DC=contoso,DC=com' | Should -Be 'Users'
    }
}

Describe 'ConvertTo-GroupAccessModel' {
    BeforeAll {
        $script:Model = ConvertTo-GroupAccessModel -Rows $script:Rows -Groups $script:Groups
    }

    It 'includes every exported group, including empty ones' {
        @($script:Model.Groups).Count | Should -Be 5
        (Find-Group $script:Model 'Old-Project').m.Count | Should -Be 0
    }

    It 'keeps the strongest route per person (direct beats nested)' {
        $g = Find-Group $script:Model 'HR-Staff'
        $aliceId = Find-PersonId $script:Model 'alice'
        $entry = @($g.m | Where-Object { $_[0] -eq $aliceId })
        $entry.Count | Should -Be 1
        $entry[0][1] | Should -Be 0
    }

    It 'records nested members with how=2 and the via path' {
        $g = Find-Group $script:Model 'HR-Staff'
        $carolId = Find-PersonId $script:Model 'carol'
        $entry = @($g.m | Where-Object { $_[0] -eq $carolId })[0]
        $entry[1] | Should -Be 2
        $entry[2] | Should -Be 'HR-Temps'
    }

    It 'records primary-group members with how=1 (counted as direct membership)' {
        $g = Find-Group $script:Model 'Finance'
        $daveId = Find-PersonId $script:Model 'dave'
        @($g.m | Where-Object { $_[0] -eq $daveId })[0][1] | Should -Be 1
    }

    It 'leaves disabled accounts out by default, like the People tab' {
        Find-PersonId $script:Model 'frank' | Should -Be -1
    }

    It 'includes disabled accounts with -IncludeDisabled, marked disabled' {
        $m = ConvertTo-GroupAccessModel -Rows $script:Rows -Groups $script:Groups -IncludeDisabled
        $id = Find-PersonId $m 'frank'
        $id | Should -BeGreaterOrEqual 0
        $m.People[$id].e | Should -BeFalse
    }

    It 'stores each person once across groups' {
        @($script:Model.People | Where-Object { $_.s -eq 'bob' }).Count | Should -Be 1
    }

    It 'lists computers and nested groups as other members, not as people' {
        $pcs = Find-Group $script:Model 'Kiosk-PCs'
        $pcs.m.Count | Should -Be 0
        $pcs.o[0][0] | Should -Be 'KIOSK01'
        $pcs.o[0][1] | Should -Be 'computer'
        (Find-Group $script:Model 'HR-Staff').o[0][1] | Should -Be 'group'
    }

    It 'records which exported groups a group contains' {
        $tempsId = [array]::IndexOf(@($script:Model.Groups | ForEach-Object { $_.n }), 'HR-Temps')
        @((Find-Group $script:Model 'HR-Staff').k) | Should -Be @($tempsId)
        @((Find-Group $script:Model 'Finance').k).Count | Should -Be 0
    }

    It 'shows the owner as a name and the OU as a path' {
        $g = Find-Group $script:Model 'HR-Staff'
        $g.ow | Should -Be 'Doe, Jane'
        $g.ou | Should -Be 'HR / Groups'
        (Find-Group $script:Model 'Finance').ow | Should -Be ''
    }

    It 'handles no rows and no groups' {
        $m = ConvertTo-GroupAccessModel -Rows @() -Groups @()
        @($m.People).Count | Should -Be 0
        @($m.Groups).Count | Should -Be 0
    }
}

Describe 'JSON embedding' {
    It 'escapes characters that could break out of a script block' {
        $json = ConvertTo-JsonText '</script><b>"quoted" back\slash & é'
        $json | Should -Not -Match '<|>|&'
        $json | Should -Not -Match '[^\x20-\x7E]'
        (ConvertFrom-Json ('{"v":' + $json + '}')).v | Should -BeExactly '</script><b>"quoted" back\slash & é'
    }

    It 'escapes control characters and line separators' {
        $value = "line1`nline2`ttab" + [char]0x2028
        (ConvertFrom-Json ('{"v":' + (ConvertTo-JsonText $value) + '}')).v | Should -BeExactly $value
    }

    It 'round-trips the whole model' {
        $model = ConvertTo-GroupAccessModel -Rows $script:Rows -Groups $script:Groups
        $parsed = ConvertFrom-Json (ConvertTo-ReportJson -Model $model)
        @($parsed.people).Count | Should -Be @($model.People).Count
        @($parsed.groups).Count | Should -Be 5
        $hr = @($parsed.groups | Where-Object { $_.n -eq 'HR-Staff' })[0]
        $hr.ow | Should -Be 'Doe, Jane'
        @($hr.m).Count | Should -Be 3
        @($hr.k).Count | Should -Be 1
    }
}

Describe 'New-UserAccessHtml with the group model' {
    BeforeAll {
        $hostile = New-Grp '</script><img src=x onerror=alert(1)>'
        $member = New-Mbr 'mallory'
        $rows = @($script:Rows) + @(Row $hostile $member 'Direct')
        $groups = @($script:Groups) + @($hostile)
        $users = @(ConvertTo-UserAccessModel -Rows $rows)
        $model = ConvertTo-GroupAccessModel -Rows $rows -Groups $groups
        $script:Html = New-UserAccessHtml -Users $users -DomainName 'contoso.com' -ScopeNote 'test' `
            -NestedExpanded -GroupsProcessed $groups.Count -GroupModel $model
    }

    It 'has the three tabs' {
        $script:Html | Should -Match 'id="tab-people"'
        $script:Html | Should -Match 'id="tab-groups"'
        $script:Html | Should -Match 'id="tab-overlap"'
        $script:Html | Should -Match 'id="tb-overlap"'
    }

    It 'embeds data that parses back' {
        $m = [regex]::Match($script:Html, '<script type="application/json" id="report-data">(.*?)</script>', 'Singleline')
        $m.Success | Should -BeTrue
        @((ConvertFrom-Json $m.Groups[1].Value).groups).Count | Should -Be 6
    }

    It 'cannot be broken out of by a hostile group name' {
        # Exactly the four script blocks the generator writes: people, data, overlap core, UI.
        ([regex]::Matches($script:Html, '</script>')).Count | Should -Be 4
        $script:Html | Should -Not -Match '<img src=x'
    }

    It 'renders the People view alone when no group model is passed' {
        $html = New-UserAccessHtml -Users @() -DomainName 'contoso.com' -ScopeNote 'test' -GroupsProcessed 0
        $html | Should -Match 'id="tab-people"'
        $html | Should -Not -Match 'id="tab-groups"'
        $html | Should -Not -Match 'report-data'
    }
}

Describe 'New-UserAccessHtml with a nesting model' {
    BeforeAll {
        $edges = @{}
        Add-NestEdge -Edges $edges -ParentDN 'CN=P,DC=x' -ChildDN 'CN=C,DC=x'
        $nodes = @{
            'CN=P,DC=x' = [PSCustomObject]@{ DN = 'CN=P,DC=x'; Name = '</script><img src=x onerror=alert(1)>'; Sam = 'P'; Category = 'Security'; Scope = 'Global'; Sid = 'S-1-5-32-544'; InExport = $false; Unresolved = $false }
            'CN=C,DC=x' = [PSCustomObject]@{ DN = 'CN=C,DC=x'; Name = 'Child'; Sam = 'C'; Category = 'Security'; Scope = 'Global'; Sid = ''; InExport = $true; Unresolved = $false }
        }
        $nest = ConvertTo-NestModel -Graph ([PSCustomObject]@{ Nodes = $nodes; CapReached = $false }) -Edges $edges -NestedExpanded
        $model = ConvertTo-GroupAccessModel -Rows $script:Rows -Groups $script:Groups
        $script:NestHtml = New-UserAccessHtml -Users @() -DomainName 'contoso.com' -ScopeNote 'test' -NestedExpanded `
            -GroupsProcessed 5 -GroupModel $model -NestModel $nest
    }
    It 'adds the Nesting tab and its data' {
        $script:NestHtml | Should -Match 'id="tb-nesting"'
        $script:NestHtml | Should -Match 'id="tab-nesting"'
        $m = [regex]::Match($script:NestHtml, '<script type="application/json" id="nest-data">(.*?)</script>', 'Singleline')
        $m.Success | Should -BeTrue
        @((ConvertFrom-Json $m.Groups[1].Value).nodes).Count | Should -Be 2
    }
    It 'cannot be broken out of by a hostile group name' {
        # people, group data, nest data, overlap core, nest core, overlap UI, nest UI
        ([regex]::Matches($script:NestHtml, '</script>')).Count | Should -Be 7
        $script:NestHtml | Should -Not -Match '<img src=x'
    }
    It 'omits the tab when no nesting model is passed' {
        $html = New-UserAccessHtml -Users @() -DomainName 'contoso.com' -ScopeNote 'test' -GroupsProcessed 0
        $html | Should -Not -Match 'tab-nesting'
    }
}
