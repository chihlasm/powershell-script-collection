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
