<#
    Repo-wide guard: every script must be readable by Windows PowerShell.

    Windows PowerShell (3.0 through 5.1) reads a .ps1 without a byte-order mark as the
    system ANSI code page, not UTF-8. One em dash in a BOM-less file is enough to break it:
    the dash's last UTF-8 byte (0x94) decodes as a right double quote, which PowerShell
    treats as a string delimiter, and the script fails to parse - while running perfectly
    in PowerShell 7, which defaults to UTF-8. Eight scripts here were broken this way on
    every Windows PowerShell version, including Get-DriveStorageReport.ps1, which declared
    5.1 and could only ever have run on 7.

    Run this under Windows PowerShell (powershell.exe) to get the parse check; under
    PowerShell 7 only the BOM rule is checked, because 7 would parse the files anyway.
    https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_character_encoding
#>

BeforeDiscovery {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $script:Files = @(
        git -C $repoRoot ls-files '*.ps1' '*.psm1' '*.psd1' |
            Where-Object { $_ -notmatch '(?i)(^|/)(dist|work-in-progress)/' } |
            ForEach-Object { @{ File = $_; FullPath = (Join-Path $repoRoot $_) } }
    )
}

Describe '<File>' -ForEach $script:Files {

    It 'has a UTF-8 BOM if it contains any non-ASCII character' {
        $bytes = [System.IO.File]::ReadAllBytes($FullPath)
        $hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
        $nonAscii = $false
        foreach ($b in $bytes) { if ($b -gt 0x7F) { $nonAscii = $true; break } }
        if ($nonAscii) { $hasBom | Should -BeTrue -Because 'Windows PowerShell decodes BOM-less files as ANSI' }
    }

    It 'parses under Windows PowerShell' -Skip:($PSVersionTable.PSEdition -eq 'Core') {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($FullPath, [ref]$tokens, [ref]$errors)
        $required = if ($ast.ScriptRequirements) { $ast.ScriptRequirements.RequiredPSVersion }
        if ($required -and $required -gt $PSVersionTable.PSVersion) {
            Set-ItResult -Skipped -Because "it requires PowerShell $required"
            return
        }
        @($errors | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" }) | Should -BeNullOrEmpty
    }
}
