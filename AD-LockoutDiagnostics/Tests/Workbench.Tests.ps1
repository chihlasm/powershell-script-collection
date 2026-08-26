BeforeAll {
    . "$PSScriptRoot\..\Start-LockoutWorkbench.ps1" -LoadFunctionsOnly
}

Describe 'Format-AccountChoice' {
    # The menu exists so a technician does not have to know an account name before
    # starting. It scans, ranks, and lets them pick a number.

    It 'renders a numbered row with the account and its lockout count' {
        $row = [PSCustomObject]@{ User='jdoe'; Lockouts=7; LastLockout=[datetime]'2026-08-26T09:15:00'
                                  Sources=@('LAPTOP-7'); LockedNow=$false }
        $line = Format-AccountChoice -Index 1 -Account $row
        $line | Should -Match '1'
        $line | Should -Match 'jdoe'
        $line | Should -Match '7'
    }

    It 'flags an account that is locked right now' {
        # The difference between "locked out three times last week" and "locked out at
        # this moment" decides whether someone is waiting on you.
        $row = [PSCustomObject]@{ User='jdoe'; Lockouts=2; LastLockout=(Get-Date)
                                  Sources=@(); LockedNow=$true }
        Format-AccountChoice -Index 1 -Account $row | Should -Match 'LOCKED NOW|LOCKED'
    }

    It 'names the dominant source when there is one' {
        $row = [PSCustomObject]@{ User='jdoe'; Lockouts=5; LastLockout=(Get-Date)
                                  Sources=@('LAPTOP-7'); LockedNow=$false }
        Format-AccountChoice -Index 1 -Account $row | Should -Match 'LAPTOP-7'
    }

    It 'summarizes rather than listing when sources are many' {
        $row = [PSCustomObject]@{ User='jdoe'; Lockouts=9; LastLockout=(Get-Date)
                                  Sources=@('A','B','C','D','E'); LockedNow=$false }
        $line = Format-AccountChoice -Index 1 -Account $row
        $line | Should -Match '5 sources|5 different'
    }

    It 'handles an account with no recorded source' {
        $row = [PSCustomObject]@{ User='jdoe'; Lockouts=1; LastLockout=(Get-Date)
                                  Sources=@(); LockedNow=$false }
        { Format-AccountChoice -Index 1 -Account $row } | Should -Not -Throw
    }
}

Describe 'Get-RankedAccounts' {
    # Ranking decides what the technician sees first, so it must put the account most
    # likely to need attention at the top.

    BeforeAll {
        $script:Events = @(
            [PSCustomObject]@{ User='quiet';  CallerComputer='PC1'; Time=(Get-Date).AddDays(-6) }
            [PSCustomObject]@{ User='noisy';  CallerComputer='PC2'; Time=(Get-Date).AddHours(-2) }
            [PSCustomObject]@{ User='noisy';  CallerComputer='PC2'; Time=(Get-Date).AddHours(-3) }
            [PSCustomObject]@{ User='noisy';  CallerComputer='PC3'; Time=(Get-Date).AddHours(-4) }
        )
    }

    It 'ranks the most frequently locked account first' {
        $r = Get-RankedAccounts -Events $script:Events
        $r[0].User     | Should -Be 'noisy'
        $r[0].Lockouts | Should -Be 3
    }

    It 'collects the distinct sources per account' {
        $r = Get-RankedAccounts -Events $script:Events
        $noisy = $r | Where-Object User -eq 'noisy'
        @($noisy.Sources).Count | Should -Be 2
    }

    It 'records the most recent lockout time' {
        $r = Get-RankedAccounts -Events $script:Events
        $noisy = $r | Where-Object User -eq 'noisy'
        $noisy.LastLockout | Should -BeGreaterThan (Get-Date).AddHours(-3)
    }

    It 'limits to the requested number of accounts' {
        $r = Get-RankedAccounts -Events $script:Events -Top 1
        @($r).Count | Should -Be 1
    }

    It 'returns an empty list rather than throwing when nothing locked out' {
        $r = Get-RankedAccounts -Events @()
        @($r).Count | Should -Be 0
    }

    It 'ignores events with no user name' {
        # Malformed rows must not become a blank menu entry the technician can select.
        $r = Get-RankedAccounts -Events @([PSCustomObject]@{ User=''; CallerComputer='X'; Time=(Get-Date) })
        @($r).Count | Should -Be 0
    }
}

Describe 'Read-MenuChoice' {
    # Pure input parsing, so the menu loop can be tested without a console.

    It 'accepts a number within range' {
        $r = Read-MenuChoice -InputText '2' -Max 5
        $r.Kind  | Should -Be 'Account'
        $r.Index | Should -Be 2
    }

    It 'rejects a number outside the range' {
        (Read-MenuChoice -InputText '9' -Max 5).Kind | Should -Be 'Invalid'
    }

    It 'rejects zero, since the menu is 1-based' {
        (Read-MenuChoice -InputText '0' -Max 5).Kind | Should -Be 'Invalid'
    }

    It 'treats a non-numeric entry as a literal account name' {
        # A technician who already knows the account should not have to find it in a list.
        $r = Read-MenuChoice -InputText 'jdoe' -Max 5
        $r.Kind     | Should -Be 'Account'
        $r.Identity | Should -Be 'jdoe'
    }

    It 'recognizes the quit commands' {
        foreach ($q in 'q','Q','quit','exit') {
            (Read-MenuChoice -InputText $q -Max 5).Kind | Should -Be 'Quit'
        }
    }

    It 'recognizes a rescan request' {
        foreach ($r in 'r','R','rescan') {
            (Read-MenuChoice -InputText $r -Max 5).Kind | Should -Be 'Rescan'
        }
    }

    It 'treats empty input as no choice rather than an error' {
        (Read-MenuChoice -InputText '' -Max 5).Kind | Should -Be 'None'
    }

    It 'trims surrounding whitespace' {
        (Read-MenuChoice -InputText '  3  ' -Max 5).Index | Should -Be 3
    }
}

Describe 'Resolve-EntraConnectChoice' {
    # The Entra Connect server is optional and cannot be discovered from AD, so the menu
    # asks - but must not force a technician who does not know to guess.

    It 'accepts a supplied server name' {
        (Resolve-EntraConnectChoice -InputText 'AADCONNECT01').Server | Should -Be 'AADCONNECT01'
    }

    It 'treats empty input as skip, not as an error' {
        $r = Resolve-EntraConnectChoice -InputText ''
        $r.Server  | Should -BeNullOrEmpty
        $r.Skipped | Should -BeTrue
    }

    It 'treats an explicit no as skip' {
        foreach ($n in 'n','no','skip') {
            (Resolve-EntraConnectChoice -InputText $n).Skipped | Should -BeTrue
        }
    }

    It 'trims whitespace from a supplied name' {
        (Resolve-EntraConnectChoice -InputText '  AADCONNECT01 ').Server | Should -Be 'AADCONNECT01'
    }
}

Describe 'The workbench is a wrapper, not a reimplementation' {
    # Everything the menu does must route through the existing scripts. Duplicating the
    # collection logic here would create a second place for the documented event
    # semantics to drift out of sync.

    It 'invokes the existing orchestrator rather than collecting directly' {
        $src = Get-Content -Raw "$PSScriptRoot\..\Start-LockoutWorkbench.ps1"
        $src | Should -Match 'Invoke-ADLockoutInvestigation\.ps1'
    }

    It 'does not parse security event XML itself' {
        $src = Get-Content -Raw "$PSScriptRoot\..\Start-LockoutWorkbench.ps1"
        $src | Should -Not -Match '\$x\.Event\.EventData'
    }

    It 'passes the chosen Entra Connect server through to the investigation' {
        $src = Get-Content -Raw "$PSScriptRoot\..\Start-LockoutWorkbench.ps1"
        $src | Should -Match 'EntraConnectServer'
    }
}
