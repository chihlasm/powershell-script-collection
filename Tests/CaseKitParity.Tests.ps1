<#
    Drift guard for the shared ticket-note kit (SQ-001 AC14). Every tool folder carries its own
    copy of CaseKit.ps1 (self-contained folders); TicketNote\CaseKit.ps1 is the canonical one.
    The copies must match it byte for byte, ignoring line endings.

    Modelled on AD-LockoutDiagnostics\Tests\SharedReferenceParity.Tests.ps1.
    Run:  Invoke-Pester .\Tests\CaseKitParity.Tests.ps1
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:Canonical = Join-Path $script:RepoRoot 'TicketNote\CaseKit.ps1'
    function Get-KitText([string]$Path) { ([System.IO.File]::ReadAllText($Path)) -replace "`r`n", "`n" }
}

Describe 'CaseKit.ps1 copies' {
    It 'AC14_KitCopiesIdentical: every copy matches TicketNote\CaseKit.ps1' {
        Test-Path -LiteralPath $script:Canonical | Should -BeTrue
        $copies = @(Get-ChildItem -LiteralPath $script:RepoRoot -Recurse -Filter 'CaseKit.ps1' -File |
            Where-Object { $_.FullName.Substring($script:RepoRoot.Length) -notmatch '(?i)[\\/](dist|work-in-progress|\.worktrees)[\\/]' })
        $relative = @($copies | ForEach-Object { $_.FullName.Substring($script:RepoRoot.Length).TrimStart('\', '/').Replace('/', '\') })
        foreach ($required in 'TicketNote\CaseKit.ps1', 'AD-UserQuickCheck\CaseKit.ps1', 'Network-QuickCheck\CaseKit.ps1', 'Citrix-FSLogix-Triage\CaseKit.ps1') {
            $relative | Should -Contain $required
        }
        $want = Get-KitText $script:Canonical
        $drifted = @($copies | Where-Object { (Get-KitText $_.FullName) -ne $want } | ForEach-Object { $_.FullName })
        $drifted | Should -BeNullOrEmpty
    }
}
