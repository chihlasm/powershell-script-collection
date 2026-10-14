<#
    Regression test: users whose primary group is the exported group were reported as
    "1 duplicate - 1 extra path".

    Get-ADGroupMember can return primary-group members (Microsoft does not document this
    either way), and Get-PrimaryGroupMember then added the same user again as 'Primary'.
    The user report saw two routes to one group and flagged it - a false duplicate, since a
    primary group is a single membership. Merge-PrimaryGroupRows keeps one row.

    No domain needed: the script's own row-shaping and report-model functions are extracted
    by AST and fed the rows a real run produced.
#>

BeforeAll {
    $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Export-ADGroupMembership.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    $wanted = 'Write-Status', 'New-MembershipRow', 'Merge-PrimaryGroupRows', 'Get-StrongestPathRank',
              'Format-AccessPath', 'ConvertTo-UserAccessModel'
    foreach ($fn in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        if ($wanted -contains $fn.Name) { . ([scriptblock]::Create($fn.Extent.Text)) }
    }

    $script:Group = [PSCustomObject]@{
        Name = 'RDS-Users'; SamAccountName = 'RDS-Users'; GroupCategory = 'Security'
        GroupScope = 'Global'; Description = ''; DistinguishedName = 'CN=RDS-Users,OU=Groups,DC=contoso,DC=com'
    }

    function New-TestUser([string]$Sam) {
        [PSCustomObject]@{
            Name = $Sam; SamAccountName = $Sam; objectClass = 'user'
            DistinguishedName = "CN=$Sam,OU=Staff,DC=contoso,DC=com"
        }
    }
    $script:Detail = [PSCustomObject]@{
        DisplayName = 'Test User'; UserPrincipalName = 'u@contoso.com'; EmailAddress = $null
        Department = $null; Title = $null; Enabled = $true; LastLogonDate = $null; PasswordLastSet = $null
    }

    function New-Row($User, [string]$Type, [int]$Depth = 0, [string]$Via = '') {
        New-MembershipRow -Group $script:Group -Member $User -MembershipType $Type `
            -NestingDepth $Depth -NestedVia $Via -UserDetail $script:Detail
    }
}

Describe 'Merge-PrimaryGroupRows' {
    BeforeEach { Mock Write-Status { } }

    It 'reproduces the false duplicate when rows are simply appended (the old behavior)' {
        $alice = New-TestUser 'alice'
        $old = @((New-Row $alice 'Direct'), (New-Row $alice 'Primary'))
        $model = @(ConvertTo-UserAccessModel -Rows $old)
        $model[0].RedundantCount | Should -Be 1
        $model[0].SurplusPathCount | Should -Be 1
    }

    It 'counts a primary member returned by Get-ADGroupMember once, as Primary' {
        $alice = New-TestUser 'alice'
        $merged = @(Merge-PrimaryGroupRows -MemberRows @(New-Row $alice 'Direct') -PrimaryRows @(New-Row $alice 'Primary'))

        $merged.Count | Should -Be 1
        $merged[0].MembershipType | Should -Be 'Primary'

        $model = @(ConvertTo-UserAccessModel -Rows $merged)
        $model[0].RedundantCount | Should -Be 0
        $model[0].SurplusPathCount | Should -Be 0
        $model[0].PrimaryCount | Should -Be 1
    }

    It 'leaves output unchanged when Get-ADGroupMember did not return the primary member' {
        $alice = New-TestUser 'alice'; $bob = New-TestUser 'bob'
        $merged = @(Merge-PrimaryGroupRows -MemberRows @(New-Row $bob 'Direct') -PrimaryRows @(New-Row $alice 'Primary'))
        $merged.Count | Should -Be 2
        @($merged | Where-Object { $_.MembershipType -eq 'Direct' }).MemberSamAccountName | Should -Be 'bob'
        @($merged | Where-Object { $_.MembershipType -eq 'Primary' }).MemberSamAccountName | Should -Be 'alice'
    }

    It 'still flags a REAL second route through a nested group' {
        $alice = New-TestUser 'alice'
        $member = @((New-Row $alice 'Direct'), (New-Row $alice 'Nested' 1 'RDS-Contractors'))
        $merged = @(Merge-PrimaryGroupRows -MemberRows $member -PrimaryRows @(New-Row $alice 'Primary'))

        $merged.Count | Should -Be 2
        $model = @(ConvertTo-UserAccessModel -Rows $merged)
        $model[0].RedundantCount | Should -Be 1 -Because 'the nested route must be removed separately'
    }

    It 'does not drop other users or nested-group member rows' {
        $alice = New-TestUser 'alice'; $bob = New-TestUser 'bob'
        $nestedGroup = [PSCustomObject]@{
            Name = 'RDS-Contractors'; SamAccountName = 'RDS-Contractors'; objectClass = 'group'
            DistinguishedName = 'CN=RDS-Contractors,OU=Groups,DC=contoso,DC=com'
        }
        $member = @((New-Row $alice 'Direct'), (New-Row $bob 'Direct'),
                    (New-MembershipRow -Group $script:Group -Member $nestedGroup -MembershipType 'Direct' -NestingDepth 0 -NestedVia '' -UserDetail $null))
        $merged = @(Merge-PrimaryGroupRows -MemberRows $member -PrimaryRows @(New-Row $alice 'Primary'))

        $merged.Count | Should -Be 3
        @($merged | ForEach-Object { "$($_.MemberSamAccountName)/$($_.MembershipType)" } | Sort-Object) |
            Should -Be @('alice/Primary', 'bob/Direct', 'RDS-Contractors/Direct')
    }

    It 'matches distinguished names case-insensitively' {
        $alice = New-TestUser 'alice'
        $upper = New-Row $alice 'Direct'; $upper.MemberDN = $upper.MemberDN.ToUpperInvariant()
        @(Merge-PrimaryGroupRows -MemberRows @($upper) -PrimaryRows @(New-Row $alice 'Primary')).Count | Should -Be 1
    }

    It 'handles empty inputs' {
        @(Merge-PrimaryGroupRows -MemberRows @() -PrimaryRows @()).Count | Should -Be 0
        $alice = New-TestUser 'alice'
        @(Merge-PrimaryGroupRows -MemberRows @() -PrimaryRows @(New-Row $alice 'Primary')).Count | Should -Be 1
        @(Merge-PrimaryGroupRows -MemberRows @(New-Row $alice 'Direct') -PrimaryRows @()).Count | Should -Be 1
    }
}
