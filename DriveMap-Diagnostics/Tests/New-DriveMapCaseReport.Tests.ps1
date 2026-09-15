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
