<#
.SYNOPSIS
    Parses every PowerShell script in the repository and fails if any has a syntax error.

.DESCRIPTION
    The repository has no compile step, so this is its build check. Run it under Windows
    PowerShell (powershell.exe): that is the engine the scripts run on in production, and it
    decodes BOM-less files as ANSI, so it catches encoding breakage that PowerShell 7 hides.
    Skips dist, work-in-progress and .worktrees.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Tests\Test-ScriptParse.ps1

.NOTES
    Uses System.Management.Automation.Language.Parser.ParseInput, available since PowerShell 3.0.
    https://learn.microsoft.com/dotnet/api/system.management.automation.language.parser.parseinput
#>
[CmdletBinding()]
param()

$repoRoot = Split-Path -Parent $PSScriptRoot
$skip = '[\\/](dist|work-in-progress|\.worktrees|\.git)[\\/]'
$files = @(Get-ChildItem -Path $repoRoot -Recurse -Include '*.ps1', '*.psm1', '*.psd1' -File |
    Where-Object { $_.FullName.Substring($repoRoot.Length) -notmatch $skip })

$failed = 0
foreach ($file in $files) {
    $tokens = $null
    $errors = $null
    # Read the way Windows PowerShell does when it runs a script: honor a BOM, otherwise ANSI
    # (Encoding.Default on .NET Framework). Parsing that text is what exposes a BOM-less
    # file whose non-ASCII characters break string literals.
    $text = [System.IO.File]::ReadAllText($file.FullName, [System.Text.Encoding]::Default)
    [void][System.Management.Automation.Language.Parser]::ParseInput($text, $file.FullName, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        $failed++
        $relative = $file.FullName.Substring($repoRoot.Length + 1)
        foreach ($err in $errors) {
            Write-Host ("[FAIL] {0}:{1}: {2}" -f $relative, $err.Extent.StartLineNumber, $err.Message) -ForegroundColor Red
        }
    }
}

if ($failed -gt 0) {
    Write-Host ("[FAIL] {0} of {1} scripts have parse errors (PowerShell {2})." -f $failed, $files.Count, $PSVersionTable.PSVersion) -ForegroundColor Red
    exit 1
}
Write-Host ("[PASS] All {0} scripts parse (PowerShell {1})." -f $files.Count, $PSVersionTable.PSVersion) -ForegroundColor Green
exit 0
