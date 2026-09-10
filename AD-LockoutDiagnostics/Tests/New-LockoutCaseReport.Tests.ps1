BeforeAll {
    . "$PSScriptRoot\..\New-LockoutCaseReport.ps1" -LoadFunctionsOnly
}

Describe 'Get-HtmlBody' {
    # Each tool writes a complete standalone page. Combining them means lifting the body
    # out of each and discarding the wrapper, rather than refactoring five working
    # scripts that are also useful on their own.

    It 'extracts the content between the body tags' {
        $page = '<!DOCTYPE html><html><head><style>x{}</style></head><body><h1>Hi</h1><p>Text</p></body></html>'
        $body = Get-HtmlBody -Html $page
        $body | Should -Match '<h1>Hi</h1>'
        $body | Should -Not -Match '<style>'
        $body | Should -Not -Match 'DOCTYPE'
    }

    It 'handles a body tag carrying attributes' {
        $page = '<html><body class="report" id="x"><p>Content</p></body></html>'
        Get-HtmlBody -Html $page | Should -Match '<p>Content</p>'
    }

    It 'is case-insensitive about tag casing' {
        $page = '<HTML><BODY><p>Content</p></BODY></HTML>'
        Get-HtmlBody -Html $page | Should -Match '<p>Content</p>'
    }

    It 'returns the input unchanged when there is no body tag' {
        # A fragment is already a body. Returning empty would silently drop a report.
        Get-HtmlBody -Html '<p>Just a fragment</p>' | Should -Match 'Just a fragment'
    }

    It 'returns empty for empty input rather than throwing' {
        Get-HtmlBody -Html '' | Should -Be ''
    }
}

Describe 'Get-TabDefinition' {
    # Tabs are ordered by the investigation, not by filename. The first tab must be the
    # one to read first.

    It 'maps each known report to its investigation step' {
        (Get-TabDefinition -FileName 'ADAuditPolicy_2026.html').Order        | Should -Be 1
        (Get-TabDefinition -FileName 'ADLockoutHistory_2026.html').Order     | Should -Be 2
        (Get-TabDefinition -FileName 'ADLockout_jdoe_2026.html').Order       | Should -Be 3
        (Get-TabDefinition -FileName 'ADLockoutForensics_2026.html').Order   | Should -Be 4
        (Get-TabDefinition -FileName 'AuthSources_2026.html').Order          | Should -Be 5
        (Get-TabDefinition -FileName 'LockoutCauses_2026.html').Order        | Should -Be 6
    }

    It 'gives each tab a plain-English label, not the filename' {
        # "ADLockoutForensics" means nothing to someone who did not write it.
        (Get-TabDefinition -FileName 'ADAuditPolicy_2026.html').Label | Should -Not -Match 'ADAuditPolicy'
        (Get-TabDefinition -FileName 'ADAuditPolicy_2026.html').Label | Should -Match 'Trust|Audit'
        (Get-TabDefinition -FileName 'LockoutCauses_2026.html').Label | Should -Match 'Fix'
    }

    It 'still places an unrecognized report rather than dropping it' {
        $t = Get-TabDefinition -FileName 'SomethingNew_2026.html'
        $t          | Should -Not -BeNullOrEmpty
        $t.Order    | Should -BeGreaterThan 6
        $t.Label    | Should -Not -BeNullOrEmpty
    }
}

Describe 'New-CombinedReport' {
    BeforeAll {
        $script:Sections = @(
            [PSCustomObject]@{ Order=1; Label='Can We Trust This Data'; Body='<h2>Audit</h2><p>Auditing is on.</p>'; Source='ADAuditPolicy_2026.html' }
            [PSCustomObject]@{ Order=5; Label='What To Fix';            Body='<h2>Causes</h2><p>Stale service password.</p>'; Source='LockoutCauses_2026.html' }
        )
    }

    It 'produces one self-contained page' {
        $html = New-CombinedReport -Sections $script:Sections -Summary '' -GeneratedOn 'now' -CaseName 'Case_jdoe'
        $html | Should -Match '<!DOCTYPE html>'
        $html | Should -Match '</html>'
        $html | Should -Match '<style>'
        # No external references - these get opened offline from a ticket.
        $html | Should -Not -Match 'https?://[^"]*\.(css|js)'
    }

    It 'renders a tab button per section, in investigation order' {
        $html = New-CombinedReport -Sections $script:Sections -Summary '' -GeneratedOn 'now' -CaseName 'Case_jdoe'
        $html | Should -Match 'Can We Trust This Data'
        $html | Should -Match 'What To Fix'
        $html.IndexOf('Can We Trust This Data') | Should -BeLessThan $html.IndexOf('What To Fix')
    }

    It 'includes every section body' {
        $html = New-CombinedReport -Sections $script:Sections -Summary '' -GeneratedOn 'now' -CaseName 'Case_jdoe'
        $html | Should -Match 'Auditing is on\.'
        $html | Should -Match 'Stale service password\.'
    }

    It 'shows the summary as the landing tab when one is supplied' {
        # The answer should be on screen before any clicking happens.
        $html = New-CombinedReport -Sections $script:Sections -Summary "FINDINGS`nStale password on SQLSRV02" -GeneratedOn 'now' -CaseName 'Case_jdoe'
        $html | Should -Match 'SQLSRV02'
        $html.IndexOf('SQLSRV02') | Should -BeLessThan $html.IndexOf('Auditing is on')
    }

    It 'escapes the summary so it cannot inject markup' {
        $html = New-CombinedReport -Sections @() -Summary '<script>alert(1)</script>' -GeneratedOn 'now' -CaseName 'c'
        $html | Should -Not -Match '<script>alert'
        $html | Should -Match '&lt;script&gt;'
    }

    It 'produces a usable page even with no sections at all' {
        $html = New-CombinedReport -Sections @() -Summary '' -GeneratedOn 'now' -CaseName 'c'
        $html | Should -Match '<!DOCTYPE html>'
        $html | Should -Match 'No reports'
    }

    It 'carries the case name so a saved file identifies itself' {
        $html = New-CombinedReport -Sections $script:Sections -Summary '' -GeneratedOn '2026-08-20 14:30' -CaseName 'Case_jdoe_2026'
        $html | Should -Match 'Case_jdoe_2026'
        $html | Should -Match '2026-08-20 14:30'
    }

    It 'works without JavaScript by keeping every section in the document' {
        # Tabs are progressive enhancement. If script is blocked - common in locked-down
        # environments and some email previews - the content must still all be there.
        $html = New-CombinedReport -Sections $script:Sections -Summary '' -GeneratedOn 'now' -CaseName 'c'
        $html | Should -Match 'Auditing is on\.'
        $html | Should -Match 'Stale service password\.'
        $html | Should -Match '<noscript>'
    }
}


Describe 'Get-BaseCss' {
    # REGRESSION GUARD. The first version of the combiner hand-wrote a small stylesheet
    # covering only .verdict, .card and table. The reports also use .stats/.stat (the
    # headline number tiles) and .kv/dt/dd (definition lists), so those rendered as bare
    # stacked text - "0 / Not logging / 4 / Logging" running down the page instead of a
    # row of tiles.
    #
    # The fix is to build on the SHARED stylesheet rather than a partial copy of it, so a
    # class added to a report cannot silently lose its styling here.

    It 'includes the tile styles the reports use for headline numbers' {
        $css = Get-BaseCss
        $css | Should -Match '\.stats'
        $css | Should -Match '\.stat'
    }

    It 'includes the definition-list styles used for key/value blocks' {
        $css = Get-BaseCss
        $css | Should -Match '\.kv'
        $css | Should -Match '\.kv dt'
        $css | Should -Match '\.kv dd'
    }

    It 'includes the collapsible and table styles' {
        $css = Get-BaseCss
        $css | Should -Match 'details'
        $css | Should -Match 'summary'
        $css | Should -Match '\.tablewrap'
    }

    It 'includes the alert and tag styles' {
        $css = Get-BaseCss
        $css | Should -Match '\.alert'
        $css | Should -Match '\.tag'
    }

    It 'is substantial enough to be the real shared stylesheet, not a stub' {
        (Get-BaseCss).Length | Should -BeGreaterThan 4000
    }
}

Describe 'New-CombinedReport styling completeness' {
    It 'carries every class the source reports rely on' {
        # Rendering a body that uses these classes must not produce unstyled text.
        $sections = @([PSCustomObject]@{ Order=1; Label='Test'; Source='x.html'
            Body='<div class="stats"><div class="stat"><div class="n">4</div><div class="k">Logging</div></div></div><dl class="kv"><dt>DC</dt><dd>DC01</dd></dl>' })
        $html = New-CombinedReport -Sections $sections -Summary '' -GeneratedOn 'now' -CaseName 'c'
        foreach ($cls in '\.stats', '\.stat', '\.kv', '\.tablewrap', 'details', '\.card', '\.verdict') {
            $html | Should -Match $cls
        }
    }

    It 'still scopes the tab chrome so it cannot collide with report styles' {
        $html = New-CombinedReport -Sections @() -Summary 'x' -GeneratedOn 'now' -CaseName 'c'
        $html | Should -Match '\.tabs'
        $html | Should -Match '\.panel'
    }
}

Describe 'Every class the source reports emit must be styled in the combined page' {
    # REGRESSION GUARD, second occurrence. The first was .stats/.stat/.kv; this one was
    # .rank/.rank-head/.rank-name/.rank-count/.rank-meta, which Get-ADLockoutHistory.ps1
    # defines in its OWN <style> block rather than in the shared LockoutReference.psd1.
    # The combiner discards each page's style block, so those cards rendered as bare
    # stacked text: account names as plain body copy and the Source/Last seen/First seen
    # definition list collapsed into a vertical run of labels and values.
    #
    # The lesson from the first occurrence was "build on the shared stylesheet". That was
    # necessary but not sufficient - it only helps for classes that ARE in the shared
    # sheet. This test closes the actual gap by checking the emitted page against the
    # classes the report generators really use.

    It 'styles the ranked-account card classes' {
        $css = Get-BaseCss
        foreach ($cls in '\.rank\b', '\.rank-head', '\.rank-name', '\.rank-count', '\.rank-meta') {
            $css | Should -Match $cls -Because 'Get-ADLockoutHistory.ps1 emits this class'
        }
    }

    It 'styles the rank-meta definition list so it renders as a grid, not stacked text' {
        $css = Get-BaseCss
        $css | Should -Match '\.rank-meta dt'
        $css | Should -Match '\.rank-meta dd'
    }

    It 'covers every class emitted by the report generators' {
        # Scrapes class="..." out of the sibling report scripts and asserts the combined
        # stylesheet defines each one. This catches the NEXT report that adds a class
        # without adding it to the shared sheet, rather than waiting for someone to
        # notice unstyled output in a screenshot.
        $generators = @(
            'Get-ADLockoutHistory.ps1', 'Diagnose-ADAccountLockout.ps1',
            'Test-ADAuditPolicy.ps1', 'Invoke-ADLockoutForensics.ps1'
        ) | ForEach-Object { Join-Path (Split-Path $PSScriptRoot -Parent) $_ } |
            Where-Object { Test-Path -LiteralPath $_ }

        $emitted = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($g in $generators) {
            $src = Get-Content -Raw $g
            foreach ($m in [regex]::Matches($src, 'class="([^"$]+)"')) {
                foreach ($token in ($m.Groups[1].Value -split '\s+')) {
                    if ($token -and $token -notmatch '[^a-zA-Z0-9_-]') { $null = $emitted.Add($token) }
                }
            }
        }

        # Layout/state classes that intentionally have no styling of their own.
        $exempt = @('no-js')
        $css = (Get-BaseCss) + (Get-TabCss)
        $unstyled = @($emitted | Where-Object {
            $_ -notin $exempt -and $css -notmatch ('\.' + [regex]::Escape($_) + '(?![\w-])')
        })

        $unstyled | Should -BeNullOrEmpty -Because 'a class with no rule renders as unstyled text in the combined report'
    }
}
