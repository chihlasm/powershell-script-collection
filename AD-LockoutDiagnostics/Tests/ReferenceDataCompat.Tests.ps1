<#
    Regression guard for the PS 3.0/4.0 reference-data loader.

    The lockout tools load LockoutReference.psd1 with Import-PowerShellDataFile, which does
    not exist before PowerShell 5.0. Every caller wraps the load in try/catch and falls back
    to a built-in copy of the constants, so on Server 2012 / 2012 R2 the failure was silent:
    the tools ran on exactly the duplicated copies the shared file exists to replace (copies
    that have drifted before - 4776 0x0 was once labelled a failure).

    Import-ReferenceDataFile uses Import-PowerShellDataFile when present and
    Import-LocalizedData otherwise. These tests prove the fallback returns the same data,
    and that the helper copies in each script have not drifted apart.
#>

BeforeDiscovery {
    $script:Scripts = @(
        @{ File = 'AD-AuthSourceEvidence\Export-ADAuthSourceEvidence.ps1' }
        @{ File = 'AD-AuthSourceEvidence\Get-LockoutCause.ps1' }
        @{ File = 'AD-LockoutDiagnostics\Diagnose-ADAccountLockout.ps1' }
        @{ File = 'AD-LockoutDiagnostics\Get-ADLockoutHistory.ps1' }
        @{ File = 'AD-LockoutDiagnostics\Invoke-ADLockoutForensics.ps1' }
        @{ File = 'AD-LockoutDiagnostics\Invoke-ADLockoutInvestigation.ps1' }
        @{ File = 'AD-LockoutDiagnostics\New-LockoutCaseReport.ps1' }
        @{ File = 'AD-LockoutDiagnostics\Test-ADAuditPolicy.ps1' }
    )
}

BeforeAll {
    $script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:RefPath  = Join-Path $script:RepoRoot 'AD-LockoutDiagnostics\LockoutReference.psd1'

    function Get-HelperText {
        param([string]$File)
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $script:RepoRoot $File), [ref]$null, [ref]$null)
        $fn = $ast.Find({
            $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $args[0].Name -eq 'Import-ReferenceDataFile'
        }, $true)
        if ($fn) { $fn.Extent.Text -replace "`r`n", "`n" }
    }

    # Structural equality for the nested hashtables/arrays/scalars a .psd1 can hold.
    function Test-DeepEqual {
        param($A, $B)
        if ($null -eq $A -or $null -eq $B) { return ($null -eq $A -and $null -eq $B) }
        if ($A -is [System.Collections.IDictionary]) {
            if (-not ($B -is [System.Collections.IDictionary]) -or $A.Count -ne $B.Count) { return $false }
            foreach ($k in $A.Keys) {
                if (-not $B.Contains($k)) { return $false }
                if (-not (Test-DeepEqual $A[$k] $B[$k])) { return $false }
            }
            return $true
        }
        if ($A -is [System.Collections.IList]) {
            if (-not ($B -is [System.Collections.IList]) -or $A.Count -ne $B.Count) { return $false }
            for ($i = 0; $i -lt $A.Count; $i++) { if (-not (Test-DeepEqual $A[$i] $B[$i])) { return $false } }
            return $true
        }
        return ($A.GetType() -eq $B.GetType() -and $A -ceq $B)
    }
}

Describe 'Import-ReferenceDataFile in <File>' -ForEach $script:Scripts {
    It 'is defined' {
        Get-HelperText -File $File | Should -Not -BeNullOrEmpty
    }

    It 'is identical to the copy in Invoke-ADLockoutInvestigation.ps1 (no drift)' {
        Get-HelperText -File $File |
            Should -BeExactly (Get-HelperText -File 'AD-LockoutDiagnostics\Invoke-ADLockoutInvestigation.ps1')
    }
}

Describe 'Import-ReferenceDataFile fallback' {
    BeforeAll {
        . ([scriptblock]::Create((Get-HelperText -File 'AD-LockoutDiagnostics\Invoke-ADLockoutInvestigation.ps1')))
        $script:Expected = Import-PowerShellDataFile -LiteralPath $script:RefPath
    }

    It 'returns the same data as Import-PowerShellDataFile when that cmdlet is missing (PS 3.0 / 4.0)' {
        Mock Get-Command -ParameterFilter { $Name -eq 'Import-PowerShellDataFile' } -MockWith { $null }
        Mock Import-PowerShellDataFile { throw 'must not be called on the fallback path' }

        $actual = Import-ReferenceDataFile -Path $script:RefPath

        Should -Invoke Import-PowerShellDataFile -Times 0
        $actual.Keys.Count | Should -Be $script:Expected.Keys.Count
        Test-DeepEqual $script:Expected $actual | Should -BeTrue
    }

    It 'uses Import-PowerShellDataFile when it exists' {
        Mock Import-PowerShellDataFile { @{ Marker = 'native' } }
        (Import-ReferenceDataFile -Path $script:RefPath).Marker | Should -Be 'native'
    }

    It 'resolves a relative path against the PowerShell location on the fallback path' {
        Mock Get-Command -ParameterFilter { $Name -eq 'Import-PowerShellDataFile' } -MockWith { $null }
        Push-Location (Split-Path -Parent $script:RefPath)
        try { $actual = Import-ReferenceDataFile -Path '.\LockoutReference.psd1' }
        finally { Pop-Location }
        Test-DeepEqual $script:Expected $actual | Should -BeTrue
    }

    It 'throws (so callers fall back) when the file does not exist' {
        Mock Get-Command -ParameterFilter { $Name -eq 'Import-PowerShellDataFile' } -MockWith { $null }
        { Import-ReferenceDataFile -Path (Join-Path $TestDrive 'missing.psd1') } | Should -Throw
    }
}
