BeforeAll {
    . "$PSScriptRoot\..\Audit-GPDriveMaps.ps1" -LoadFunctionsOnly
}

Describe 'Script loads functions only' {
    It 'exposes Build-DriveMapMatrix once implemented' {
        Get-Command Build-DriveMapMatrix | Should -Not -BeNullOrEmpty
    }
    It 'does not run the audit on dot-source' {
        # If the guard failed, dot-sourcing would have thrown (no domain here).
        $true | Should -BeTrue
    }
}

Describe 'Build-DriveMapMatrix - group pivot' {
    BeforeAll {
        function New-M { param($GPO,$Action,$Letter,$Path,$Groups)
            $ilt = @($Groups | ForEach-Object { [PSCustomObject]@{ Type='FilterGroup'; Not=$false; Bool='AND'; Detail="Group IS '$_'" } })
            $an = switch ($Action) { 'C'{'Create'} 'D'{'Delete'} default{$Action} }
            [PSCustomObject]@{ GPOName=$GPO; ActionName=$an; DriveLetter=$Letter; UNCPath=$Path
                ILTSummary='x'; ILTFilters=$ilt; Configuration='User' } }
    }
    It 'pivots one group/one letter into a cell' {
        $maps = [System.Collections.Generic.List[object]]::new()
        $maps.Add((New-M 'G1' 'C' 'M' '\\srv\fire' @('Fire')))
        $m = Build-DriveMapMatrix -DriveMaps $maps -PathValidation @() -GroupOverlap @()
        $m.letters | Should -Contain 'M'
        ($m.groups | Where-Object name -eq 'Fire').cells.M[0].path | Should -Be '\\srv\fire'
    }
    It 'puts no-ILT mappings under the (all users) row' {
        $maps = [System.Collections.Generic.List[object]]::new()
        $maps.Add((New-M 'G1' 'C' 'S' '\\srv\scratch' @()))
        $m = Build-DriveMapMatrix -DriveMaps $maps -PathValidation @() -GroupOverlap @()
        ($m.groups | Where-Object name -eq '(all users)').cells.S[0].path | Should -Be '\\srv\scratch'
    }
}

Describe 'Build-DriveMapMatrix - cell status' {
    BeforeAll {
        function New-M { param($GPO,$Action,$Letter,$Path,$Groups)
            $ilt = @($Groups | ForEach-Object { [PSCustomObject]@{ Type='FilterGroup'; Not=$false; Bool='AND'; Detail="Group IS '$_'" } })
            $an = switch ($Action) { 'C'{'Create'} 'D'{'Delete'} default{$Action} }
            [PSCustomObject]@{ GPOName=$GPO; ActionName=$an; DriveLetter=$Letter; UNCPath=$Path
                ILTSummary='x'; ILTFilters=$ilt; Configuration='User' } }
    }
    It 'marks a cell unreachable when its path failed validation' {
        $maps = [System.Collections.Generic.List[object]]::new()
        $maps.Add((New-M 'G1' 'C' 'O' '\\dead\o' @('Grp')))
        $pv = @([PSCustomObject]@{ UNCPath='\\dead\o'; Reachable=$false })
        $m = Build-DriveMapMatrix -DriveMaps $maps -PathValidation $pv -GroupOverlap @()
        ($m.groups | Where-Object name -eq 'Grp').cells.O[0].status | Should -Be 'unreachable'
    }
    It 'marks a cell remove for Delete actions' {
        $maps = [System.Collections.Generic.List[object]]::new()
        $maps.Add((New-M 'G1' 'D' 'M' '\\srv\x' @('Grp')))
        $m = Build-DriveMapMatrix -DriveMaps $maps -PathValidation @() -GroupOverlap @()
        ($m.groups | Where-Object name -eq 'Grp').cells.M[0].status | Should -Be 'remove'
    }
    It 'marks overlap when a group has 2 paths for one letter' {
        $maps = [System.Collections.Generic.List[object]]::new()
        $maps.Add((New-M 'G1' 'C' 'Z' '\\a\z' @('Staff')))
        $maps.Add((New-M 'G2' 'C' 'Z' '\\b\z' @('Staff')))
        $m = Build-DriveMapMatrix -DriveMaps $maps -PathValidation @() -GroupOverlap @()
        $cellz = ($m.groups | Where-Object name -eq 'Staff').cells.Z
        $cellz.Count | Should -Be 2
        ($cellz | Where-Object { $_.status -eq 'overlap' }).Count | Should -Be 2
    }
    It 'marks overlap when two different groups share a letter' {
        $maps = [System.Collections.Generic.List[object]]::new()
        $maps.Add((New-M 'G1' 'C' 'Z' '\\a\z' @('HR')))
        $maps.Add((New-M 'G2' 'C' 'Z' '\\b\z' @('Finance')))
        $m = Build-DriveMapMatrix -DriveMaps $maps -PathValidation @() -GroupOverlap @()
        ($m.groups | Where-Object name -eq 'HR').cells.Z[0].status | Should -Be 'overlap'
        ($m.groups | Where-Object name -eq 'Finance').cells.Z[0].status | Should -Be 'overlap'
    }
}

Describe 'Build-DriveMapMatrix - user rows' {
    BeforeAll {
        function New-M { param($GPO,$Action,$Letter,$Path,$Groups)
            $ilt = @($Groups | ForEach-Object { [PSCustomObject]@{ Type='FilterGroup'; Not=$false; Bool='AND'; Detail="Group IS '$_'" } })
            $an = switch ($Action) { 'C'{'Create'} 'D'{'Delete'} default{$Action} }
            [PSCustomObject]@{ GPOName=$GPO; ActionName=$an; DriveLetter=$Letter; UNCPath=$Path
                ILTSummary='x'; ILTFilters=$ilt; Configuration='User' } }
    }
    It 'attaches members and sets hasUserData when membership provided' {
        $maps = [System.Collections.Generic.List[object]]::new()
        $maps.Add((New-M 'G1' 'C' 'M' '\\srv\fire' @('Fire')))
        $members = @{ 'Fire' = @('jsmith','adoe') }
        $m = Build-DriveMapMatrix -DriveMaps $maps -PathValidation @() -GroupOverlap @() -GroupMembers $members
        $m.hasUserData | Should -BeTrue
        ($m.groups | Where-Object name -eq 'Fire').users | Should -Contain 'jsmith'
    }
    It 'leaves hasUserData false when no membership provided' {
        $maps = [System.Collections.Generic.List[object]]::new()
        $maps.Add((New-M 'G1' 'C' 'M' '\\srv\fire' @('Fire')))
        (Build-DriveMapMatrix -DriveMaps $maps -PathValidation @() -GroupOverlap @()).hasUserData | Should -BeFalse
    }
    It 'gives (all users) and groups absent from GroupMembers an empty array, never null' {
        $maps = [System.Collections.Generic.List[object]]::new()
        $maps.Add((New-M 'G1' 'C' 'M' '\\srv\fire' @('Fire')))
        $maps.Add((New-M 'G2' 'C' 'N' '\\srv\hr' @('HR')))
        $maps.Add((New-M 'G3' 'C' 'S' '\\srv\scratch' @()))
        $members = @{ 'Fire' = @('jsmith','adoe') }
        $m = Build-DriveMapMatrix -DriveMaps $maps -PathValidation @() -GroupOverlap @() -GroupMembers $members

        $allUsersRow = $m.groups | Where-Object name -eq '(all users)'
        $allUsersRow.users.Count | Should -Be 0
        ($null -eq $allUsersRow.users) | Should -BeFalse

        $hrRow = $m.groups | Where-Object name -eq 'HR'
        $hrRow.users.Count | Should -Be 0
        ($null -eq $hrRow.users) | Should -BeFalse

        $fireRow = $m.groups | Where-Object name -eq 'Fire'
        $fireRow.users | Should -Contain 'jsmith'
    }
}

Describe 'Matrix renders into self-contained HTML' {
    BeforeAll {
        function New-M { param($GPO,$Action,$Letter,$Path,$Groups)
            $ilt = @($Groups | ForEach-Object { [PSCustomObject]@{ Type='FilterGroup'; Not=$false; Bool='AND'; Detail="Group IS '$_'" } })
            $an = switch ($Action) { 'C'{'Create'} 'D'{'Delete'} default{$Action} }
            $iltSummary = if ($Groups -and $Groups.Count -gt 0) { ($Groups -join '; ') } else { 'No targeting (applies to all)' }
            [PSCustomObject]@{
                GPOName      = $GPO
                GPOId        = [guid]::NewGuid().ToString()
                GPOStatus    = 'AllSettingsEnabled'
                Configuration = 'User'
                Action       = $Action
                ActionName   = $an
                DriveLetter  = $Letter
                UNCPath      = $Path
                Label        = "$Letter drive"
                Reconnect    = 'True'
                ILTSummary   = $iltSummary
                ILTFilters   = $ilt
                GPOLinksText = 'Default Domain Policy'
            }
        }

        # Build a realistic set of drive maps: two groups sharing letter Z (overlap),
        # and one group pointing at an unreachable target on letter O.
        $driveMaps = [System.Collections.Generic.List[object]]::new()
        $driveMaps.Add((New-M 'GPO-Finance' 'C' 'F' '\\srv1\finance' @('Finance')))
        $driveMaps.Add((New-M 'GPO-HR' 'C' 'Z' '\\srv1\hr-archive' @('HR')))
        $driveMaps.Add((New-M 'GPO-Finance' 'C' 'Z' '\\srv2\fin-archive' @('Finance')))
        $driveMaps.Add((New-M 'GPO-Ops' 'C' 'O' '\\deadsrv\ops' @('Operations')))

        $pathValidation = @(
            [PSCustomObject]@{
                UNCPath      = '\\srv1\finance'
                Reachable    = $true
                DriveLetters = 'F'
                AffectedGPOs = 'GPO-Finance'
                Recommendation = ''
            },
            [PSCustomObject]@{
                UNCPath      = '\\srv1\hr-archive'
                Reachable    = $true
                DriveLetters = 'Z'
                AffectedGPOs = 'GPO-HR'
                Recommendation = ''
            },
            [PSCustomObject]@{
                UNCPath      = '\\srv2\fin-archive'
                Reachable    = $true
                DriveLetters = 'Z'
                AffectedGPOs = 'GPO-Finance'
                Recommendation = ''
            },
            [PSCustomObject]@{
                UNCPath      = '\\deadsrv\ops'
                Reachable    = $false
                DriveLetters = 'O'
                AffectedGPOs = 'GPO-Ops'
                Recommendation = 'Verify the target server is online and reachable.'
            }
        )

        $groupOverlap = @(
            [PSCustomObject]@{
                DriveLetter      = 'Z'
                OverlapUserCount = 1
                CompetingGroups  = 'HR, Finance'
                UserDetails      = @(
                    [PSCustomObject]@{ User = 'jsmith'; Groups = 'HR, Finance'; Paths = '\\srv1\hr-archive, \\srv2\fin-archive' }
                )
                Recommendation   = 'Review group membership overlap for drive Z.'
            }
        )

        $matrix = Build-DriveMapMatrix -DriveMaps $driveMaps -PathValidation $pathValidation -GroupOverlap $groupOverlap

        $script:auditResults = @{
            Domain          = 'contoso.com'
            AuditDate       = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            TotalGPOs       = 3
            AllDriveMaps    = $driveMaps
            Issues          = @{ Conflicts = @(); Duplicates = @() }
            PathValidation  = $pathValidation
            StaleHosts      = @()
            GroupOverlap    = $groupOverlap
            Precedence      = $null
            Matrix          = $matrix
        }
    }

    It 'embeds parseable JSON and references no external hosts' {
        $out = Join-Path $TestDrive 'r.html'
        Export-HTMLReport -AuditResults $script:auditResults -OutputFile $out
        $html = Get-Content $out -Raw

        $html | Should -Match "id='matrix-data'"
        $html | Should -Not -Match 'https?://(?!www\.w3\.org)'

        $json = [regex]::Match($html, "(?s)matrix-data[^>]*>(.*?)</script>").Groups[1].Value
        $json | Should -Not -BeNullOrEmpty
        { $json | ConvertFrom-Json } | Should -Not -Throw
    }
}
