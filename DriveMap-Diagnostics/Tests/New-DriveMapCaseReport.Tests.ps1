BeforeAll {
    . "$PSScriptRoot\..\New-DriveMapCaseReport.ps1" -LoadFunctionsOnly
}

Describe 'ConvertTo-SafeHtml' {
    # UNC paths and script lines land in the report verbatim. An unescaped angle bracket
    # from a script line would break the document.
    It 'escapes HTML metacharacters' {
        ConvertTo-SafeHtml -Text '<script>' | Should -Be '&lt;script&gt;'
        ConvertTo-SafeHtml -Text 'a & b'    | Should -Be 'a &amp; b'
    }
    It 'escapes ampersands before angle brackets so entities are not double-escaped' {
        ConvertTo-SafeHtml -Text '<a & b>' | Should -Be '&lt;a &amp; b&gt;'
    }
    It 'passes a UNC path through unchanged' {
        ConvertTo-SafeHtml -Text '\\server\share' | Should -Be '\\server\share'
    }
    It 'returns empty string for null input' {
        ConvertTo-SafeHtml -Text $null | Should -Be ''
    }
    It 'escapes BOTH quote characters so the output is safe in single- and double-quoted attributes' {
        # This script's generated HTML quotes attributes with SINGLE quotes, so escaping only
        # '"' would leave a single-quoted attribute breakable by an apostrophe in customer
        # data (a GPO name or UNC path can contain one). Defence in depth: no customer value
        # reaches an attribute today, but a future caller must not be able to open the hole.
        ConvertTo-SafeHtml -Text "O'Brien"   | Should -Be 'O&#39;Brien'
        ConvertTo-SafeHtml -Text 'say "hi"'  | Should -Be 'say &quot;hi&quot;'
    }
    It 'does not double-escape the ampersand it introduces when escaping a quote' {
        ConvertTo-SafeHtml -Text "a & 'b'" | Should -Be 'a &amp; &#39;b&#39;'
    }
    It 'neutralizes an apostrophe-based attribute break attempt' {
        # The concrete shape the escaping prevents: closing a single-quoted attribute early
        # and appending an event handler.
        $escaped = ConvertTo-SafeHtml -Text "x' onmouseover='alert(1)"
        $escaped | Should -Not -Match "'"
        $escaped | Should -Match '&#39;'
    }
}

Describe 'New-CollectionStateBadge' {
    # The three states must remain visually distinct all the way into the report. If
    # "could not look" renders the same as "nothing found", the whole design is defeated
    # at the last step.
    It 'renders the three states distinguishably' {
        $found   = New-CollectionStateBadge -State 'Found'
        $empty   = New-CollectionStateBadge -State 'EmptyButValid'
        $blind   = New-CollectionStateBadge -State 'CouldNotCollect'

        $found | Should -Not -Be $empty
        $empty | Should -Not -Be $blind
        $found | Should -Not -Be $blind
    }

    It 'makes clear that CouldNotCollect is not a clean result' {
        New-CollectionStateBadge -State 'CouldNotCollect' | Should -Match 'not|could'
    }
}

Describe 'New-DriveMapHtmlReport' {
    It 'produces a complete HTML document' {
        $html = New-DriveMapHtmlReport -Verdicts @() -Sections @{} -DriveLetter 'X' `
                    -Identity 'jsmith' -GeneratedOn '2026-09-14 10:00:00'
        $html | Should -Match '(?i)<!DOCTYPE html>'
        $html | Should -Match '(?i)</html>'
    }

    It 'shows the drive letter and account in the header' {
        $html = New-DriveMapHtmlReport -Verdicts @() -Sections @{} -DriveLetter 'X' `
                    -Identity 'jsmith' -GeneratedOn '2026-09-14 10:00:00'
        $html | Should -Match 'X'
        $html | Should -Match 'jsmith'
    }

    # Confidence is a visible tag, never a buried field - a guess must never read as fact.
    It 'renders the confidence of every verdict' {
        $html = New-DriveMapHtmlReport -DriveLetter 'X' -Identity 'jsmith' `
                    -GeneratedOn '2026-09-14 10:00:00' -Sections @{} `
                    -Verdicts @([PSCustomObject]@{
                        Cause = 'A logon script deletes the drive'; Confidence = 'High'
                        Evidence = @('GPO: DomainWideSettings'); Remediation = @('Remove the script')
                    })
        $html | Should -Match 'High'
        $html | Should -Match 'logon script'
    }

    It 'escapes verdict text rather than emitting it raw' {
        $html = New-DriveMapHtmlReport -DriveLetter 'X' -Identity 'jsmith' `
                    -GeneratedOn '2026-09-14 10:00:00' -Sections @{} `
                    -Verdicts @([PSCustomObject]@{
                        Cause = 'Bad <script>alert(1)</script>'; Confidence = 'Low'
                        Evidence = @(); Remediation = @()
                    })
        $html | Should -Not -Match '<script>alert'
    }
}

Describe 'ConvertTo-ReportSections' {
    # Evidence.json (written by Invoke-DriveMapInvestigation.ps1) holds the same flattened
    # evidence object ConvertFrom-EvidenceBundle produced to build that case's verdicts. This
    # function is the single place THIS script turns that object into the -Sections hashtable
    # tabs 2-4 read from - it must never coerce a $null ("not established") property to
    # $false or to an empty array, because those mean opposite things everywhere else in this
    # toolkit and a silent coercion here would defeat the whole three-state design one script
    # away from where its own tests could catch it.

    It 'returns an empty hashtable when Evidence is $null, so the report keeps working on older case folders' {
        $sections = ConvertTo-ReportSections -Evidence $null
        $sections | Should -BeOfType [hashtable]
        $sections.Count | Should -Be 0
    }

    It 'passes a $null evidence property through as $null, never $false or an empty array' {
        $evidence = [PSCustomObject]@{
            Action = $null; DrivePresent = $null; InRegistry = $null
            ElevatedVisible = $null; UnelevatedVisible = $null
            ScriptDeletions = $null; TargetingFailures = $null
        }
        $sections = ConvertTo-ReportSections -Evidence $evidence

        ($null -eq $sections['DrivePresent']) | Should -Be $true
        ($sections['DrivePresent'] -eq $false) | Should -Be $false
        ($null -eq $sections['InRegistry']) | Should -Be $true
        ($null -eq $sections['ScriptDeletions']) | Should -Be $true
        ($null -eq $sections['TargetingFailures']) | Should -Be $true
        ($null -eq $sections['ElevatedVisible']) | Should -Be $true
        ($null -eq $sections['UnelevatedVisible']) | Should -Be $true
        ($null -eq $sections['Action']) | Should -Be $true
    }

    It 'carries a confirmed $false evidence property through as $false, not $null' {
        $evidence = [PSCustomObject]@{
            Action = 'Replace'; DrivePresent = $false; InRegistry = $true
            ElevatedVisible = $false; UnelevatedVisible = $true
            ScriptDeletions = @(); TargetingFailures = @()
        }
        $sections = ConvertTo-ReportSections -Evidence $evidence

        $sections['DrivePresent'] | Should -Be $false
        $sections['InRegistry'] | Should -Be $true
        $sections['Action'] | Should -Be 'Replace'
    }

    It 'keeps a single-element ScriptDeletions as an array, not a bare object' {
        # A single deleting logon script is the most likely real-world shape. If this
        # unwrapped to a bare object, New-InterferenceSectionHtml's ForEach-Object over
        # $ScriptDeletions would iterate the object's PROPERTIES instead of one list element.
        $evidence = [PSCustomObject]@{
            ScriptDeletions = [PSCustomObject]@{ Source = 'DomainWideSettings\logon.bat'; Line = 'net use x: /delete' }
        }
        $sections = ConvertTo-ReportSections -Evidence $evidence

        $sections['ScriptDeletions'] | Should -Not -BeNullOrEmpty
        @($sections['ScriptDeletions']).Count | Should -Be 1
        @($sections['ScriptDeletions'])[0].Source | Should -Be 'DomainWideSettings\logon.bat'
    }

    It 'does not set GpoAuditNote - no source for it exists in the evidence today' {
        $evidence = [PSCustomObject]@{ Action = 'Replace' }
        $sections = ConvertTo-ReportSections -Evidence $evidence
        $sections.ContainsKey('GpoAuditNote') | Should -Be $false
    }
}

Describe 'New-DriveMapCaseReport.ps1 orchestration - Evidence.json' {
    # End-to-end through the actual script file (not just the dot-sourced functions), so a
    # regression in how the orchestration body reads Evidence.json and threads it into
    # -Sections is caught even if ConvertTo-ReportSections itself is correct in isolation.
    BeforeEach {
        $script:caseFolder = Join-Path $TestDrive ("Case_{0}" -f ([guid]::NewGuid().Guid.Substring(0, 8)))
        New-Item -ItemType Directory -Path $script:caseFolder -Force | Out-Null
    }

    It 'renders real endpoint-state data in tab 3 when Evidence.json is present' {
        $evidence = [PSCustomObject]@{
            Action = 'Replace'; DrivePresent = $true; InRegistry = $true
            ElevatedVisible = $null; UnelevatedVisible = $null
            ScriptDeletions = @(); TargetingFailures = @()
        }
        $evidenceJson = ConvertTo-Json -InputObject $evidence -Depth 6
        [System.IO.File]::WriteAllText((Join-Path $script:caseFolder 'Evidence.json'), $evidenceJson, (New-Object System.Text.UTF8Encoding($true)))

        $reportPath = Join-Path $script:caseFolder 'DriveMapInvestigationReport.html'
        & "$PSScriptRoot\..\New-DriveMapCaseReport.ps1" -CaseFolder $script:caseFolder -OutputPath $script:caseFolder -SkipBrowserOpen | Out-Null

        Test-Path -LiteralPath $reportPath | Should -Be $true
        $html = Get-Content -LiteralPath $reportPath -Raw
        $html | Should -Match 'Replace'
        $html | Should -Not -Match 'was not established from the evidence collected'
    }

    It 'still produces a report with the "not established" fallback when Evidence.json is absent' {
        $reportPath = Join-Path $script:caseFolder 'DriveMapInvestigationReport.html'
        & "$PSScriptRoot\..\New-DriveMapCaseReport.ps1" -CaseFolder $script:caseFolder -OutputPath $script:caseFolder -SkipBrowserOpen | Out-Null

        Test-Path -LiteralPath $reportPath | Should -Be $true
        $html = Get-Content -LiteralPath $reportPath -Raw
        $html | Should -Match 'was not established from the evidence collected'
    }
}
