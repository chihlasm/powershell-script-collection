BeforeAll {
    $script:Orchestrator = "$PSScriptRoot\..\Invoke-ADLockoutInvestigation.ps1"
    $script:Diagnose     = "$PSScriptRoot\..\Diagnose-ADAccountLockout.ps1"
}

Describe 'Entra Connect evidence reaches the all-in-one runner' {
    # REGRESSION GUARD. The Entra Connect collector existed in Diagnose-ADAccountLockout
    # for months but Invoke-ADLockoutInvestigation never passed anything to it, so a full
    # toolkit run silently skipped every hybrid check. Someone investigating a synced
    # account got a report that looked complete and had examined no sync evidence at all.

    It 'exposes -EntraConnectServer on the orchestrator' {
        (Get-Command $script:Orchestrator).Parameters.Keys | Should -Contain 'EntraConnectServer'
    }

    It 'exposes -HybridAuthMode on the orchestrator' {
        (Get-Command $script:Orchestrator).Parameters.Keys | Should -Contain 'HybridAuthMode'
    }

    It 'constrains -HybridAuthMode to the modes the collector understands' {
        $p = (Get-Command $script:Orchestrator).Parameters['HybridAuthMode']
        $valid = $p.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
        $valid.ValidValues | Should -Contain 'PHS'
        $valid.ValidValues | Should -Contain 'PTA'
        $valid.ValidValues | Should -Contain 'Auto'
    }

    It 'names both parameters identically on the orchestrator and the collector' {
        # A rename on one side alone would pass the value into nothing.
        $inner = (Get-Command $script:Diagnose).Parameters.Keys
        foreach ($name in 'EntraConnectServer', 'HybridAuthMode') {
            $inner | Should -Contain $name -Because "the orchestrator forwards -$name by name"
        }
    }

    It 'forwards both parameters in the step 4 invocation' {
        $src = Get-Content -Raw $script:Orchestrator
        $src | Should -Match "args4\['EntraConnectServer'\]"
        $src | Should -Match "args4\['HybridAuthMode'\]"
    }

    It 'tells the operator when hybrid evidence was NOT collected' {
        # Silence here is the failure mode that matters: an on-prem-only report must not
        # read as a clean bill of health for a synced account.
        $src = Get-Content -Raw $script:Orchestrator
        $src | Should -Match 'No -EntraConnectServer supplied'
    }

    It 'documents both parameters in comment-based help' {
        $help = Get-Help $script:Orchestrator -Full
        ($help.parameters.parameter | ForEach-Object { $_.name }) | Should -Contain 'EntraConnectServer'
        ($help.parameters.parameter | ForEach-Object { $_.name }) | Should -Contain 'HybridAuthMode'
    }
}

Describe 'Documented Microsoft sources are cited in the script' {
    # CLAUDE.md requires a REFERENCES block listing the pages consulted, so the next
    # person can re-verify the PHS event meanings without repeating the research.

    It 'lists the password hash sync troubleshooting page' {
        Get-Content -Raw $script:Diagnose |
            Should -Match 'tshoot-connect-password-hash-synchronization'
    }

    It 'lists the pass-through authentication troubleshooting page' {
        Get-Content -Raw $script:Diagnose |
            Should -Match 'tshoot-connect-pass-through-authentication'
    }
}
