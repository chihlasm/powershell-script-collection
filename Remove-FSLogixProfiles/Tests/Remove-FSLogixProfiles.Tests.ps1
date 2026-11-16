BeforeAll {
    $script:Script = Join-Path $PSScriptRoot '..\Remove-FSLogixProfiles.ps1'

    # Never autoload the real ActiveDirectory module or reach a DC.
    $env:ADPS_LoadDefaultDrive = '0'
    function global:Get-ADUser   { param($Identity, $Server, $Filter, $Properties, $ErrorAction) throw 'Get-ADUser stub called without a mock' }
    function global:Get-ADDomain { param($Identity, $Server, $ErrorAction) throw 'Get-ADDomain stub called without a mock' }

    # Same short type name the AD module throws for a missing account.
    if (-not ('FakeAD.ADIdentityNotFoundException' -as [type])) {
        Add-Type -TypeDefinition 'namespace FakeAD { public class ADIdentityNotFoundException : System.Exception { public ADIdentityNotFoundException(string m) : base(m) {} } }'
    }

    . $script:Script -LoadFunctionsOnly

    $script:Sid1 = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
    $script:Sid2 = 'S-1-5-21-1111111111-2222222222-3333333333-1106'
    $script:DomSid = 'S-1-5-21-1111111111-2222222222-3333333333'

    function script:New-FakeProfile {
        param([string]$Root, [string]$Name)
        $dir = Join-Path $Root $Name
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $dir 'Profile_user.vhdx') -Value 'fake'
        $dir
    }
}

AfterAll {
    Remove-Item function:global:Get-ADUser, function:global:Get-ADDomain -ErrorAction SilentlyContinue
}

Describe 'Script shape' {
    It 'declares a 3.0 floor and no #Requires -Modules' {
        $head = (Get-Content -LiteralPath $script:Script -TotalCount 3) -join "`n"
        $head | Should -Match '#Requires -Version 3\.0'
        $head | Should -Not -Match '#Requires\s+-Modules'
    }
}

Describe 'Resolve-ProfileFolderName' {
    It 'accepts SID_username and returns the SID' {
        $r = Resolve-ProfileFolderName -Value "${Sid1}_jsmith" -Root '\\fs\profiles'
        $r.Name | Should -Be "${Sid1}_jsmith"
        $r.Sid  | Should -Be $Sid1
    }
    It 'accepts username_SID (FlipFlopProfileDirectoryName)' {
        (Resolve-ProfileFolderName -Value "jsmith_$Sid1" -Root '\\fs\profiles').Sid | Should -Be $Sid1
    }
    It 'accepts a full path directly under the root' {
        (Resolve-ProfileFolderName -Value "Z:\${Sid1}_jsmith" -Root 'Z:').Name | Should -Be "${Sid1}_jsmith"
        (Resolve-ProfileFolderName -Value "\\fs\profiles\${Sid1}_jsmith\" -Root '\\fs\profiles').Name | Should -Be "${Sid1}_jsmith"
    }
    It 'rejects a path under a different root' {
        { Resolve-ProfileFolderName -Value "\\other\share\${Sid1}_jsmith" -Root '\\fs\profiles' } | Should -Throw '*directly under the share root*'
    }
    It 'rejects nested and traversal paths' {
        { Resolve-ProfileFolderName -Value "sub\${Sid1}_jsmith" -Root '\\fs\profiles' } | Should -Throw
        { Resolve-ProfileFolderName -Value "..${Sid1}_jsmith" -Root '\\fs\profiles' } | Should -Throw
    }
    It 'rejects a folder without a domain account SID' {
        { Resolve-ProfileFolderName -Value 'jsmith' -Root '\\fs\profiles' } | Should -Throw '*SID*'
        { Resolve-ProfileFolderName -Value 'S-1-5-18_system' -Root '\\fs\profiles' } | Should -Throw '*SID*'
    }
    It 'rejects an empty value' {
        { Resolve-ProfileFolderName -Value '  ' -Root '\\fs\profiles' } | Should -Throw '*empty*'
    }
}

Describe 'Test-FileLocked' {
    It 'returns $null for a file nobody has open' {
        $f = Join-Path $TestDrive 'free.vhdx'; Set-Content -LiteralPath $f -Value 'x'
        Test-FileLocked -Path $f | Should -BeNullOrEmpty
    }
    It 'returns a reason while the file is held open' {
        $f = Join-Path $TestDrive 'held.vhdx'; Set-Content -LiteralPath $f -Value 'x'
        $h = [System.IO.File]::Open($f, 'Open', 'Read', 'Read')
        try { Test-FileLocked -Path $f | Should -Not -BeNullOrEmpty }
        finally { $h.Close() }
    }
}

Describe 'Get-ADAccountState' {
    It 'blocks an enabled account' {
        Mock Get-ADUser { [pscustomobject]@{ Enabled = $true; SamAccountName = 'jsmith' } }
        $r = Get-ADAccountState -Sid $Sid1 -DomainSid $DomSid
        $r.Block | Should -BeTrue
        $r.Reason | Should -Match 'still enabled'
    }
    It 'allows a disabled account' {
        Mock Get-ADUser { [pscustomobject]@{ Enabled = $false; SamAccountName = 'jsmith' } }
        (Get-ADAccountState -Sid $Sid1 -DomainSid $DomSid).Block | Should -BeFalse
    }
    It 'looks the SID up with the documented -Identity parameter' {
        Mock Get-ADUser { [pscustomobject]@{ Enabled = $false; SamAccountName = 'jsmith' } }
        Get-ADAccountState -Sid $Sid1 -DomainSid $DomSid -Server 'dc01' | Out-Null
        Should -Invoke Get-ADUser -Times 1 -ParameterFilter { $Identity -eq $Sid1 -and $Server -eq 'dc01' -and -not $Filter }
    }
    It 'allows an account that no longer exists' {
        Mock Get-ADUser { throw (New-Object FakeAD.ADIdentityNotFoundException 'not found') }
        $r = Get-ADAccountState -Sid $Sid1 -DomainSid $DomSid
        $r.Block | Should -BeFalse
        $r.State | Should -Be 'NotInAD'
    }
    It 'rethrows any other lookup error (DC unreachable must not mean "gone")' {
        Mock Get-ADUser { throw 'Unable to contact the server' }
        { Get-ADAccountState -Sid $Sid1 -DomainSid $DomSid } | Should -Throw '*contact*'
    }
    It 'blocks a SID from another domain without querying AD' {
        Mock Get-ADUser { throw 'should not be called' }
        $r = Get-ADAccountState -Sid 'S-1-5-21-9-9-9-1105' -DomainSid $DomSid
        $r.Block | Should -BeTrue
        $r.State | Should -Be 'OtherDomain'
        Should -Invoke Get-ADUser -Times 0
    }
}

Describe 'End-to-end on a fake share' {
    BeforeEach {
        $script:Share = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:Out   = Join-Path $TestDrive 'out'
        New-Item -ItemType Directory -Path $Share | Out-Null
        $script:P1 = New-FakeProfile -Root $Share -Name "${Sid1}_jsmith"
        $script:P2 = New-FakeProfile -Root $Share -Name "${Sid2}_adoe"
        New-Item -ItemType Directory -Path (Join-Path $Share 'NotAProfile') | Out-Null
        Remove-Item -LiteralPath $Out -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'Report mode changes nothing and logs each folder' {
        & $script:Script -ProfileShare $Share -FolderName "${Sid1}_jsmith", 'NotAProfile', "${Sid1}_missing" -SkipADCheck -OutputPath $Out 6>$null
        Test-Path -LiteralPath $P1 | Should -BeTrue
        $log = Import-Csv -LiteralPath (Get-ChildItem -LiteralPath $Out -Filter 'FSLogixRemoval_Report_*.csv').FullName
        ($log | Where-Object FolderName -eq "${Sid1}_jsmith").Status | Should -Be 'Eligible'
        ($log | Where-Object FolderName -eq 'NotAProfile').Status   | Should -Be 'Skipped'
        ($log | Where-Object FolderName -eq "${Sid1}_missing").Status | Should -Be 'NotFound'
    }

    It 'Archive mode moves eligible folders to the archive path' {
        $arch = Join-Path $Share '_Archive'
        & $script:Script -ProfileShare $Share -FolderName "${Sid1}_jsmith" -Mode Archive -ArchivePath $arch -SkipADCheck -Force -OutputPath $Out 6>$null
        Test-Path -LiteralPath $P1 | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $arch "${Sid1}_jsmith\Profile_user.vhdx") | Should -BeTrue
    }

    It 'Delete mode removes only the listed folder, read from a CSV' {
        $csv = Join-Path $TestDrive 'targets.csv'
        [pscustomobject]@{ FolderName = "${Sid1}_jsmith" } | Export-Csv -LiteralPath $csv -NoTypeInformation
        & $script:Script -ProfileShare $Share -TargetCsv $csv -Mode Delete -SkipADCheck -Force -OutputPath $Out 6>$null
        Test-Path -LiteralPath $P1 | Should -BeFalse
        Test-Path -LiteralPath $P2 | Should -BeTrue
    }

    It 'Delete -WhatIf removes nothing but still writes the log' {
        & $script:Script -ProfileShare $Share -FolderName "${Sid1}_jsmith" -Mode Delete -SkipADCheck -WhatIf -OutputPath $Out 6>$null
        Test-Path -LiteralPath $P1 | Should -BeTrue
        $log = Import-Csv -LiteralPath (Get-ChildItem -LiteralPath $Out -Filter '*.csv').FullName
        $log.Status | Should -Be 'WhatIf'
    }

    It 'skips a folder whose container is open' {
        $vhdx = Join-Path $P1 'Profile_user.vhdx'
        $h = [System.IO.File]::Open($vhdx, 'Open', 'Read', 'Read')
        try {
            & $script:Script -ProfileShare $Share -FolderName "${Sid1}_jsmith" -Mode Delete -SkipADCheck -Force -OutputPath $Out 6>$null
        }
        finally { $h.Close() }
        Test-Path -LiteralPath $P1 | Should -BeTrue
        (Import-Csv -LiteralPath (Get-ChildItem -LiteralPath $Out -Filter '*.csv').FullName).Reason | Should -Match 'Container in use'
    }

    It 'skips a folder written within -MinDaysInactive' {
        & $script:Script -ProfileShare $Share -FolderName "${Sid1}_jsmith" -Mode Delete -MinDaysInactive 30 -SkipADCheck -Force -OutputPath $Out 6>$null
        Test-Path -LiteralPath $P1 | Should -BeTrue
    }

    It 'refuses to delete anything when the AD check cannot run' {
        Mock Import-Module { throw 'module not found' } -ParameterFilter { $Name -eq 'ActiveDirectory' }
        { & $script:Script -ProfileShare $Share -FolderName "${Sid1}_jsmith" -Mode Delete -Force -OutputPath $Out 6>$null } | Should -Throw '*Stopped before changing anything*'
        Test-Path -LiteralPath $P1 | Should -BeTrue
    }

    It 'keeps an enabled account''s folder and removes a disabled one' {
        Mock Import-Module { } -ParameterFilter { $Name -eq 'ActiveDirectory' }
        Mock Get-ADDomain { [pscustomobject]@{ DomainSID = $DomSid } }
        Mock Get-ADUser { [pscustomobject]@{ Enabled = ($Identity -eq $Sid1); SamAccountName = 'u' } }
        & $script:Script -ProfileShare $Share -FolderName "${Sid1}_jsmith", "${Sid2}_adoe" -Mode Delete -Force -OutputPath $Out 6>$null
        Test-Path -LiteralPath $P1 | Should -BeTrue
        Test-Path -LiteralPath $P2 | Should -BeFalse
    }
}
