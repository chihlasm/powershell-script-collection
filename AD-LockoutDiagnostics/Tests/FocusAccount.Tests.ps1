BeforeAll {
    . "$PSScriptRoot\..\New-LockoutCaseReport.ps1" -LoadFunctionsOnly
}

Describe 'Add-FocusHighlight' {
    # When -Identity is supplied, the investigation still runs three DOMAIN-WIDE steps
    # (who is locking out, which devices, likely causes) because the surrounding context
    # is what makes one account's evidence interpretable - a single account locking out
    # means something different when forty others are too.
    #
    # But nothing in the combined report marked WHICH account was being investigated, so
    # the reader had to scan tables of unrelated accounts looking for their own. The
    # context is worth keeping; the ambiguity is not.

    It 'marks the focus account inside a table cell' {
        $html = '<table><tr><td>jdoe</td><td>5</td></tr></table>'
        $out = Add-FocusHighlight -Html $html -Identity 'jdoe'
        $out | Should -Match 'class="focus"'
        $out | Should -Match 'jdoe'
    }

    It 'leaves other accounts untouched' {
        $html = '<table><tr><td>asmith</td></tr><tr><td>jdoe</td></tr></table>'
        $out = Add-FocusHighlight -Html $html -Identity 'jdoe'
        # Exactly one highlight, on the focus row only.
        ([regex]::Matches($out, 'class="focus"')).Count | Should -Be 1
        $out | Should -Match 'asmith'
    }

    It 'matches case-insensitively, as AD account names are' {
        $out = Add-FocusHighlight -Html '<td>JDoe</td>' -Identity 'jdoe'
        $out | Should -Match 'class="focus"'
    }

    It 'matches a bare sAMAccountName inside a UPN' {
        # Reports render the account differently in different places - sAMAccountName in
        # one table, UPN in another. Both are the focus account.
        $out = Add-FocusHighlight -Html '<td>jdoe@contoso.com</td>' -Identity 'jdoe'
        $out | Should -Match 'class="focus"'
    }

    It 'does not match an account that merely contains the name as a substring' {
        # 'jdoe' must not highlight 'bjdoevic' or 'jdoe2' - a false highlight points the
        # technician at the wrong row, which is worse than no highlight at all.
        $out = Add-FocusHighlight -Html '<td>jdoe2</td><td>bjdoevic</td>' -Identity 'jdoe'
        $out | Should -Not -Match 'class="focus"'
    }

    It 'does not corrupt HTML by matching inside tags or attributes' {
        # A name appearing in a class, id or href must not be rewritten - that would
        # produce broken markup.
        $html = '<a href="/users/jdoe" class="jdoe-row"><td>other</td></a>'
        $out = Add-FocusHighlight -Html $html -Identity 'jdoe'
        $out | Should -Match 'href="/users/jdoe"'
        $out | Should -Match 'class="jdoe-row"'
    }

    It 'returns the html unchanged when no identity is supplied' {
        $html = '<td>jdoe</td>'
        Add-FocusHighlight -Html $html -Identity '' | Should -Be $html
    }

    It 'returns the html unchanged when the account does not appear' {
        $html = '<td>asmith</td>'
        Add-FocusHighlight -Html $html -Identity 'jdoe' | Should -Be $html
    }

    It 'escapes regex metacharacters in the account name' {
        # Account names can contain dots and other regex-significant characters.
        { Add-FocusHighlight -Html '<td>first.last</td>' -Identity 'first.last' } | Should -Not -Throw
        Add-FocusHighlight -Html '<td>first.last</td>' -Identity 'first.last' | Should -Match 'class="focus"'
    }
}

Describe 'The combined report identifies the account under investigation' {
    It 'names the focus account in the page header' {
        $sections = @([PSCustomObject]@{ Order=1; Label='Test'; Source='x.html'; Body='<p>x</p>' })
        $html = New-CombinedReport -Sections $sections -Summary '' -GeneratedOn 'now' `
                  -CaseName 'Case_jdoe' -Identity 'jdoe'
        $html | Should -Match 'jdoe'
        $html | Should -Match 'Investigating|Focus|Account'
    }

    It 'ships the focus styling so highlighted rows actually render' {
        $html = New-CombinedReport -Sections @() -Summary '' -GeneratedOn 'now' `
                  -CaseName 'c' -Identity 'jdoe'
        $html | Should -Match '\.focus'
    }

    It 'highlights the focus account inside section bodies' {
        $sections = @([PSCustomObject]@{ Order=1; Label='Who Is Locking Out'; Source='hist.html'
                       Body='<table><tr><td>asmith</td></tr><tr><td>jdoe</td></tr></table>' })
        $html = New-CombinedReport -Sections $sections -Summary '' -GeneratedOn 'now' `
                  -CaseName 'c' -Identity 'jdoe'
        $html | Should -Match 'class="focus"'
    }

    It 'still produces a valid report for a domain-wide survey with no identity' {
        $sections = @([PSCustomObject]@{ Order=1; Label='Test'; Source='x.html'; Body='<td>jdoe</td>' })
        $html = New-CombinedReport -Sections $sections -Summary '' -GeneratedOn 'now' -CaseName 'survey'
        $html | Should -Match '<!DOCTYPE html>'
        $html | Should -Not -Match 'class="focus"'
    }

    It 'escapes the identity so it cannot inject markup' {
        $html = New-CombinedReport -Sections @() -Summary '' -GeneratedOn 'now' `
                  -CaseName 'c' -Identity '<script>alert(1)</script>'
        $html | Should -Not -Match '<script>alert'
    }
}
