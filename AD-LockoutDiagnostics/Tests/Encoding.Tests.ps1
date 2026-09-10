BeforeAll {
    $script:Roots = @(
        (Join-Path $PSScriptRoot '..'),
        (Join-Path $PSScriptRoot '..\..\AD-AuthSourceEvidence'),
        (Join-Path $PSScriptRoot '..\AD-Lockout-Diagnostics')
    ) | Where-Object { Test-Path -LiteralPath $_ }

    $script:ScriptFiles = @(
        foreach ($r in $script:Roots) {
            # -Include is silently ignored when -LiteralPath has no trailing wildcard,
            # which made this scan every file (zips, markdown) and report false failures.
            # -Filter takes one pattern, so run it once per extension.
            foreach ($pattern in '*.ps1', '*.psd1') {
                Get-ChildItem -LiteralPath $r -File -Filter $pattern -Recurse -ErrorAction SilentlyContinue
            }
        }
    )
}

Describe 'Deployed scripts must be readable by PowerShell 5.1' {
    # REGRESSION GUARD, from a live failure on DC02.
    #
    # Diagnose-ADAccountLockout.ps1 contained seven em-dashes (U+2014) in report strings
    # and was saved as UTF-8 WITHOUT a BOM. Windows PowerShell 5.1 reads a BOM-less file
    # as ANSI (code page 1252), so each em-dash became three characters - the third being
    # a quote - which terminated the surrounding string early and produced a cascade of
    # "Missing closing ')'" parse errors. The script would not run at all.
    #
    # It parsed fine on the authoring machine because the editor and PowerShell 7 both
    # assume UTF-8. Only the 5.1 deployment target saw the corruption, which is exactly
    # the class of bug that unit tests on the dev box cannot catch.
    #
    # Two independent guards, because either alone would have prevented this:
    #   1. No non-ASCII characters in script source at all.
    #   2. A UTF-8 BOM, so any reader gets the encoding right regardless.

    It 'finds script files to check' {
        @($script:ScriptFiles).Count | Should -BeGreaterThan 0
    }

    It 'contains no non-ASCII characters in script source' {
        $offenders = foreach ($f in $script:ScriptFiles) {
            $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
            # TrimStart the BOM before inspecting: the BOM is itself a non-ASCII
            # character and is REQUIRED by the test below, so counting it here would
            # make the two assertions contradict each other.
            $text  = [System.Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF)
            $bad   = [char[]]$text | Where-Object { [int]$_ -gt 126 }
            if ($bad) {
                $codes = ($bad | Select-Object -Unique | ForEach-Object { 'U+{0:X4}' -f [int]$_ }) -join ','
                "$($f.Name) [$codes]"
            }
        }
        # Em-dashes, smart quotes and arrows are the usual culprits - they arrive by
        # copy/paste from documentation and look harmless in an editor.
        $offenders | Should -BeNullOrEmpty -Because 'PowerShell 5.1 misreads non-ASCII in BOM-less files as ANSI, corrupting string literals'
    }

    It 'saves every script with a UTF-8 BOM' {
        $missing = foreach ($f in $script:ScriptFiles) {
            $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
            $hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
            if (-not $hasBom) { $f.Name }
        }
        $missing | Should -BeNullOrEmpty -Because 'a BOM makes the encoding unambiguous to Windows PowerShell 5.1'
    }

    It 'reads identically whether interpreted as UTF-8 or as ANSI' {
        # The direct test of the actual failure: if these two readings differ, the file
        # means something different on the deployment target than it does here.
        #
        # The BOM is excluded from both sides before comparing. PowerShell consumes the
        # BOM as an encoding marker rather than as content, so its ANSI rendering
        # ("i>>?") is not a corruption of the script body - unlike an em-dash, which
        # lands inside a string literal and breaks it.
        $differing = foreach ($f in $script:ScriptFiles) {
            $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
            $body  = if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
                         $bytes[3..($bytes.Length - 1)]
                     } else { $bytes }
            $utf8  = [System.Text.Encoding]::UTF8.GetString($body)
            $ansi  = [System.Text.Encoding]::GetEncoding(1252).GetString($body)
            if ($utf8 -ne $ansi) { $f.Name }
        }
        $differing | Should -BeNullOrEmpty -Because 'PS 5.1 may read the file as ANSI; the two readings must agree'
    }

    It 'parses cleanly with the PowerShell language parser' {
        $failed = foreach ($f in $script:ScriptFiles | Where-Object { $_.Extension -eq '.ps1' }) {
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errors) | Out-Null
            if ($errors) { "$($f.Name): $($errors[0].Message)" }
        }
        $failed | Should -BeNullOrEmpty
    }
}
