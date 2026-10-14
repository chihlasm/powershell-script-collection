<#
    Repo-wide guard: every script that declares '#Requires -Version' must not use a language
    feature, cmdlet, or parameter newer than that version.

    Scripts here are lowered to 3.0/4.0 where they may run on Windows Server 2012 (PS 3.0)
    or 2012 R2 (PS 4.0). A later edit that adds '::new()', a class, or Compress-Archive to
    such a script would break it on those servers - with a parse error for syntax features,
    so nothing in the script runs at all - while still passing every test on a modern
    machine. This test fails instead.

    The analysis is static (see PSVersionFloor.Analyzer.ps1 for what it can and cannot see).
    Scripts without a '#Requires -Version' line are not checked.

    Run with Pester 5:  Invoke-Pester .\Tests\PSVersionFloor.Tests.ps1
#>

BeforeDiscovery {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $PSScriptRoot 'PSVersionFloor.Analyzer.ps1')

    $script:Cases = @(
        git -C $repoRoot ls-files '*.ps1' |
            Where-Object {
                $_ -notmatch '(?i)(^|/)(tests?|dist|work-in-progress)/' -and
                $_ -notmatch '(?i)\.Tests\.ps1$'
            } |
            ForEach-Object {
                $full = Join-Path $repoRoot $_
                $result = Get-PSVersionFloor -Path $full
                if ($result.DeclaredVersion) {
                    @{ Script = $_; Result = $result }
                }
            }
    )
}

Describe '<Script>' -ForEach $script:Cases {

    It 'uses nothing newer than its #Requires -Version' {
        # A parse error under this host means the script targets a newer PowerShell than
        # the one running the test (e.g. a 7.x-only script under 5.1); nothing to compare.
        if ($Result.ParseErrors.Count -gt 0 -and $Result.DeclaredVersion -gt $PSVersionTable.PSVersion) {
            Set-ItResult -Skipped -Because "it requires PowerShell $($Result.DeclaredVersion)"
            return
        }

        $tooNew = @($Result.Findings | Where-Object { $_.Version -gt $Result.DeclaredVersion } |
                    ForEach-Object { "needs $($_.Version): $($_.Feature) (line $($_.Line))" })
        $tooNew | Should -BeNullOrEmpty -Because "the script declares #Requires -Version $($Result.DeclaredVersion)"
    }
}
