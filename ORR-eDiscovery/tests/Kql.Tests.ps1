<#
    New-OrrKqlQuery and Test-OrrKql: the query the tool sends to eDiscovery.

    The rules tested here come from Microsoft Learn; the page behind each rule is cited next
    to the code in src/ORR.Core/ORR.Core.psm1.
#>

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:OrrModulePath -Force
    $script:Clients = Import-OrrTestClientConfig

    # Builds the query for the baseline spec with the given changes. 'nopad-town' has
    # DatePaddingDays 0 and 'contoso-city' has 1.
    function Get-Query {
        param([hashtable]$Set = @{}, [switch]$NoPadding)
        if ($NoPadding) {
            $Set = $Set.Clone()
            $Set['client'] = 'nopad-town'
            if (-not $Set.ContainsKey('custodians')) { $Set['custodians'] = @('clerk@nopad.example.org') }
        }
        $result = Test-OrrSpec -Json (ConvertTo-OrrTestJson (New-OrrTestSpec -Set $Set)) -ClientConfig $script:Clients
        if (-not $result.IsValid) { throw ("Spec was rejected: " + ($result.Errors -join '; ')) }
        return (New-OrrKqlQuery -Spec $result.Spec -ClientConfig $script:Clients)
    }
}

AfterAll {
    Remove-Module ORR.Core -ErrorAction SilentlyContinue
}

Describe 'New-OrrKqlQuery builds the query from keywords and dates' {

    It 'joins keywords with OR, quotes phrases, and adds the date range' {
        $query = Get-Query -NoPadding
        $query.Kql | Should -BeExactly '(budget OR "road repair") AND (date>=2024-01-01 AND date<2024-04-01)'
        $query.Source | Should -BeExactly 'Generated'
        $query.KeywordCount | Should -Be 2
        $query.OperatorCount | Should -Be 3
        $query.Length | Should -Be $query.Kql.Length
    }

    It 'widens the range by the client padding on both sides' {
        $query = Get-Query
        $query.Kql | Should -BeExactly '(budget OR "road repair") AND (date>=2023-12-31 AND date<2024-04-02)'
        $query.DatePaddingDays | Should -Be 1
        $query.DateStartInclusive | Should -BeExactly '2023-12-31'
        $query.DateEndExclusive | Should -BeExactly '2024-04-02'
    }

    It 'includes the whole end day by searching up to the next day: <End> -> <Next>' -ForEach @(
        @{ Start = '2024-12-01'; End = '2024-12-31'; Next = '2025-01-01' }
        @{ Start = '2024-02-01'; End = '2024-02-28'; Next = '2024-02-29' }
        @{ Start = '2023-02-01'; End = '2023-02-28'; Next = '2023-03-01' }
        @{ Start = '2024-06-15'; End = '2024-06-15'; Next = '2024-06-16' }
    ) {
        $query = Get-Query -NoPadding -Set @{ dateStart = $Start; dateEnd = $End }
        $query.Kql | Should -BeLike "*(date>=$Start AND date<$Next)"
    }

    It 'writes dates the same way whatever the machine culture is' {
        $previous = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]'th-TH'
            (Get-Query -NoPadding).Kql | Should -BeLike '*(date>=2024-01-01 AND date<2024-04-01)'
        } finally {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = $previous
        }
    }

    It 'wraps a single keyword the same way' {
        (Get-Query -NoPadding -Set @{ keywords = @('budget') }).Kql |
            Should -BeExactly '(budget) AND (date>=2024-01-01 AND date<2024-04-01)'
    }

    It 'builds a date-only query, with a warning, when there are no keywords' {
        $query = Get-Query -NoPadding -Set @{ keywords = @() }
        $query.Kql | Should -BeExactly '(date>=2024-01-01 AND date<2024-04-01)'
        ($query.Warnings -join "`n") | Should -Match 'No keywords'
    }

    It 'explains UTC, padding and what the date means' {
        $notes = (Get-Query).Notes -join "`n"
        $notes | Should -Match 'UTC'
        $notes | Should -Match 'widened by 1 day'
        $notes | Should -Match 'last-modified date for documents'
        ((Get-Query -NoPadding).Notes -join "`n") | Should -Not -Match 'widened'
    }

    It 'does not put custodian addresses in the query' {
        (Get-Query).Kql | Should -Not -Match 'contoso\.gov'
    }
}

Describe 'New-OrrKqlQuery turns each keyword into a safe term' {

    It 'writes <Keyword> as <Term>' -ForEach @(
        @{ Keyword = 'budget'; Term = 'budget' }
        @{ Keyword = '  budget  '; Term = 'budget' }
        @{ Keyword = 'road repair'; Term = '"road repair"' }
        @{ Keyword = 'road    repair'; Term = '"road repair"' }
        @{ Keyword = '"budget"'; Term = '"budget"' }
        @{ Keyword = '"road repair"'; Term = '"road repair"' }
        @{ Keyword = 'budget*'; Term = 'budget*' }
        @{ Keyword = 'rfp2024*'; Term = 'rfp2024*' }
        @{ Keyword = 'and'; Term = '"and"' }
        @{ Keyword = 'OR'; Term = '"OR"' }
        @{ Keyword = 'Not'; Term = '"Not"' }
        @{ Keyword = 'near'; Term = '"near"' }
        @{ Keyword = 'ONEAR'; Term = '"ONEAR"' }
        @{ Keyword = 'words'; Term = '"words"' }
        @{ Keyword = 'XRANK'; Term = '"XRANK"' }
        @{ Keyword = 'and*'; Term = 'and*' }
        @{ Keyword = 'C++'; Term = '"C++"' }
        @{ Keyword = 'budget AND roads'; Term = '"budget AND roads"' }
        @{ Keyword = 'budget OR 1=1'; Term = '"budget OR 1=1"' }
        @{ Keyword = 'co-op'; Term = '"co-op"' }
        @{ Keyword = '-budget'; Term = '"-budget"' }
        @{ Keyword = '+budget'; Term = '"+budget"' }
        @{ Keyword = 'from:mayor'; Term = '"from:mayor"' }
        @{ Keyword = 'kind:email'; Term = '"kind:email"' }
        @{ Keyword = 'budget)'; Term = '"budget)"' }
        @{ Keyword = '(budget'; Term = '"(budget"' }
        @{ Keyword = 'jordan@contoso.gov'; Term = '"jordan@contoso.gov"' }
        @{ Keyword = "O'Brien"; Term = "`"O'Brien`"" }
        @{ Keyword = 'RFP 2024-17'; Term = '"RFP 2024-17"' }
        @{ Keyword = '2024'; Term = '2024' }
    ) {
        $query = Get-Query -NoPadding -Set @{ keywords = @($Keyword) }
        $query.Kql | Should -BeExactly "($Term) AND (date>=2024-01-01 AND date<2024-04-01)"
    }

    It 'turns smart quotes from a pasted ticket into a plain phrase' {
        $keyword = [char]0x201C + 'road repair' + [char]0x201D
        (Get-Query -NoPadding -Set @{ keywords = @($keyword) }).Kql | Should -BeLike '("road repair") AND*'
    }

    It 'removes hidden characters from a pasted keyword' {
        $keyword = 'bud' + [char]0x200B + 'get' + [char]0x200E
        (Get-Query -NoPadding -Set @{ keywords = @($keyword) }).Kql | Should -BeLike '(budget) AND*'
    }

    It 'treats a line break inside a keyword as a space' {
        (Get-Query -NoPadding -Set @{ keywords = @("road`r`nrepair") }).Kql | Should -BeLike '("road repair") AND*'
    }

    It 'keeps accented letters as a plain word' {
        $keyword = 'caf' + [char]0x00E9
        (Get-Query -NoPadding -Set @{ keywords = @($keyword) }).Kql | Should -BeLike "($keyword) AND*"
    }

    It 'warns when a keyword has punctuation the index ignores' {
        $query = Get-Query -Set @{ keywords = @('jordan@contoso.gov') }
        ($query.Warnings -join "`n") | Should -Match "keywords\[0\]: 'jordan@contoso.gov' contains punctuation"
    }

    It 'uses a repeated keyword once and says so' {
        $query = Get-Query -NoPadding -Set @{ keywords = @('budget', 'Budget', 'roads') }
        $query.Kql | Should -BeLike '(budget OR roads) AND*'
        ($query.Warnings -join "`n") | Should -Match 'duplicate'
    }

    It 'rejects keyword <Keyword>' -ForEach @(
        @{ Keyword = '*budget' }
        @{ Keyword = 'bud*get' }
        @{ Keyword = 'bu*' }
        @{ Keyword = 'a1*' }
        @{ Keyword = '*' }
        @{ Keyword = 'road rep*' }
        @{ Keyword = '"road rep*"' }
        @{ Keyword = 'budget.*' }
        @{ Keyword = 'budget**' }
        @{ Keyword = 'say "hello" twice' }
        @{ Keyword = '"' }
        @{ Keyword = '""' }
        @{ Keyword = 'budget" OR "x' }
        @{ Keyword = ',' }
        @{ Keyword = '---' }
        @{ Keyword = '"_"' }
        @{ Keyword = '( )' }
        @{ Keyword = '&&& ///' }
        @{ Keyword = 'AND*' }
        @{ Keyword = 'NOT*' }
    ) {
        $result = Test-OrrSpec -Json (ConvertTo-OrrTestJson (New-OrrTestSpec -Set @{ keywords = @($Keyword) })) -ClientConfig $script:Clients
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match 'keywords\[0\]'
    }

    It 'always produces a query that passes its own check with no structural warnings' {
        $nasty = @(
            'and', 'OR', 'not', 'NEAR', 'a b', 'x AND y', '(x', 'y)', 'to: mayor', 'date>=2020-01-01',
            '-x', '+y', 'c:c', '(c:c)', 'a,b;c', 'one two three', 'budget*', "tab`tseparated", 'kind:im NOT kind:email'
        )
        $query = Get-Query -Set @{ keywords = $nasty }
        $check = Test-OrrKql -Kql $query.Kql
        $check.Errors | Should -BeNullOrEmpty
        ($check.Warnings -join "`n") | Should -Not -Match 'lowercase|separated only by a space|space after a property'
        $check.OperatorCount | Should -Be ($query.KeywordCount - 1 + 2)
    }

    It 'rejects a keyword list that would exceed the operator limit' {
        $many = 1..100 | ForEach-Object { "word$_" }
        $result = Test-OrrSpec -Json (ConvertTo-OrrTestJson (New-OrrTestSpec -Set @{ keywords = $many })) -ClientConfig $script:Clients
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match 'uses 101 operators'
    }
}

Describe 'New-OrrKqlQuery with a kqlOverride' {

    It 'uses the override as written and does not add the spec dates' {
        $query = Get-Query -Set @{ kqlOverride = 'subject:"road repair" AND sent>=2024-01-01' }
        $query.Kql | Should -BeExactly 'subject:"road repair" AND sent>=2024-01-01'
        $query.Source | Should -BeExactly 'Override'
        $query.DateStartInclusive | Should -BeNullOrEmpty
        $query.DateEndExclusive | Should -BeNullOrEmpty
        ($query.Notes -join "`n") | Should -Match 'dateStart and dateEnd in the spec are not added'
        ($query.Warnings -join "`n") | Should -Match 'keywords list is not used'
    }

    It 'joins a multi-line override into one line' {
        $query = Get-Query -Set @{ kqlOverride = "budget`r`n  AND`tdate>=2024-01-01" }
        $query.Kql | Should -BeExactly 'budget AND date>=2024-01-01'
    }

    It 'warns loudly when the override has no date condition' {
        $query = Get-Query -Set @{ kqlOverride = 'budget AND roads' }
        ($query.Warnings -join "`n") | Should -Match 'no date condition'
    }

    It 'does not mistake date-like text inside a phrase for a date condition: <Override>' -ForEach @(
        @{ Override = 'budget AND "sent: yesterday"' }
        @{ Override = 'budget AND "the date: line"' }
        @{ Override = 'budget AND x_date:1' }
    ) {
        $query = Get-Query -Set @{ kqlOverride = $Override }
        ($query.Warnings -join "`n") | Should -Match 'no date condition'
    }

    It 'sees a date condition written in capitals or inside parentheses' {
        ((Get-Query -Set @{ kqlOverride = 'budget AND (RECEIVED>=2024-01-01)' }).Warnings -join "`n") | Should -Not -Match 'no date condition'
    }

    It 'turns non-breaking spaces pasted from Word into ordinary spaces' {
        $query = Get-Query -Set @{ kqlOverride = ('budget' + [char]0x00A0 + 'AND' + [char]0x00A0 + 'date>=2024-01-01') }
        $query.Kql | Should -BeExactly 'budget AND date>=2024-01-01'
    }

    It 'does not mistake a word containing "date" for a date condition' {
        $query = Get-Query -Set @{ kqlOverride = 'update AND "candidate: Jordan"' }
        ($query.Warnings -join "`n") | Should -Match 'no date condition'
    }
}

Describe 'Test-OrrKql' {

    It 'accepts <Kql>' -ForEach @(
        @{ Kql = 'budget' }
        @{ Kql = '(budget OR "road repair") AND (date>=2024-01-01 AND date<2024-04-01)' }
        @{ Kql = 'budget AND NOT draft' }
        @{ Kql = 'NOT kind:im' }
        @{ Kql = 'budget NEAR(5) roads' }
        @{ Kql = 'subject:"a (b" AND from:mayor@contoso.gov' }
        @{ Kql = '"AND"' }
        @{ Kql = 'sent=2024-01-01..2024-03-31' }
    ) {
        $check = Test-OrrKql -Kql $Kql
        $check.Errors | Should -BeNullOrEmpty
        $check.IsValid | Should -BeTrue
    }

    It 'rejects <Name>' -ForEach @(
        @{ Name = 'an empty query'; Kql = ''; Match = 'empty' }
        @{ Name = 'a blank query'; Kql = "  `t "; Match = 'empty' }
        @{ Name = 'an unclosed quote'; Kql = 'subject:"budget'; Match = 'odd number of double quotes' }
        @{ Name = 'an unclosed parenthesis'; Kql = '(budget AND roads'; Match = 'unbalanced parentheses' }
        @{ Name = 'parentheses in the wrong order'; Kql = ')budget('; Match = 'unbalanced parentheses' }
        @{ Name = 'only operators'; Kql = 'AND OR'; Match = 'only operators' }
        @{ Name = 'only parentheses'; Kql = '(())'; Match = 'only operators' }
        @{ Name = 'a leading AND'; Kql = 'AND budget'; Match = 'missing the term' }
        @{ Name = 'a trailing OR'; Kql = 'budget OR'; Match = 'missing the term' }
        @{ Name = 'two operators in a row'; Kql = 'budget AND OR roads'; Match = 'missing the term' }
        @{ Name = 'an empty group joined to a term'; Kql = '() AND budget'; Match = 'missing the term' }
        @{ Name = 'the condition-builder marker'; Kql = 'budget(c:c)roads'; Match = '\(c:c\)' }
        @{ Name = 'the condition-builder marker with spaces'; Kql = 'budget ( c:c ) roads'; Match = '\(c:c\)' }
        @{ Name = 'an empty quoted phrase'; Kql = '""'; Match = 'empty quoted phrase' }
        @{ Name = 'a blank quoted phrase'; Kql = '(" ")'; Match = 'empty quoted phrase' }
        @{ Name = 'a real term joined to an empty phrase'; Kql = 'budget AND ""'; Match = 'empty quoted phrase' }
        @{ Name = 'a punctuation-only phrase'; Kql = '"---"'; Match = 'empty quoted phrase' }
        @{ Name = 'a bare asterisk'; Kql = '*'; Match = 'only operators' }
        @{ Name = 'a bare comma'; Kql = ','; Match = 'only operators' }
        @{ Name = 'a bare underscore'; Kql = '_'; Match = 'only operators' }
        @{ Name = 'an empty group next to a real one'; Kql = '(budget) AND ()'; Match = 'empty pair of parentheses|missing the term' }
    ) {
        $check = Test-OrrKql -Kql $Kql
        $check.IsValid | Should -BeFalse
        ($check.Errors -join "`n") | Should -Match $Match
    }

    It 'rejects curly quotes' {
        $check = Test-OrrKql -Kql ('subject:' + [char]0x201C + 'budget' + [char]0x201D)
        ($check.Errors -join "`n") | Should -Match 'curly'
    }

    It 'rejects hidden characters' {
        (Test-OrrKql -Kql ('bud' + [char]0x200B + 'get')).IsValid | Should -BeFalse
        (Test-OrrKql -Kql ('bud' + [char]0x0007 + 'get')).IsValid | Should -BeFalse
    }

    It 'warns about lowercase operators' {
        $check = Test-OrrKql -Kql 'budget and roads'
        $check.IsValid | Should -BeTrue
        ($check.Warnings -join "`n") | Should -Match 'lowercase'
        $check.OperatorCount | Should -Be 0
    }

    It 'warns that a bare space means OR' {
        ((Test-OrrKql -Kql 'budget roads').Warnings -join "`n") | Should -Match 'treats a space as OR'
        ((Test-OrrKql -Kql '"budget" "roads"').Warnings -join "`n") | Should -Match 'treats a space as OR'
        ((Test-OrrKql -Kql 'budget OR roads').Warnings -join "`n") | Should -Not -Match 'treats a space as OR'
    }

    It 'warns about a space after a property operator' {
        ((Test-OrrKql -Kql 'to: mayor').Warnings -join "`n") | Should -Match 'space after a property operator'
        ((Test-OrrKql -Kql 'date>= 2024-01-01').Warnings -join "`n") | Should -Match 'space after a property operator'
        ((Test-OrrKql -Kql 'to:mayor').Warnings -join "`n") | Should -Not -Match 'space after a property operator'
        ((Test-OrrKql -Kql 'subject:"to: mayor"').Warnings -join "`n") | Should -Not -Match 'space after a property operator'
    }

    It 'counts only uppercase operators outside quotes' {
        (Test-OrrKql -Kql 'a AND b OR c AND NOT d').OperatorCount | Should -Be 4
        (Test-OrrKql -Kql '"a AND b" OR c').OperatorCount | Should -Be 1
        (Test-OrrKql -Kql 'a NEAR(3) b').OperatorCount | Should -Be 1
        (Test-OrrKql -Kql 'a NEAR(3)b').OperatorCount | Should -Be 1
        (Test-OrrKql -Kql 'ANDREW OR ORLANDO').OperatorCount | Should -Be 1
    }

    It 'rejects more than 100 operators and warns above 80' {
        $over = (1..102 | ForEach-Object { "w$_" }) -join ' OR '
        ((Test-OrrKql -Kql $over).Errors -join "`n") | Should -Match 'uses 101 operators'
        $atLimit = (1..101 | ForEach-Object { "w$_" }) -join ' OR '
        (Test-OrrKql -Kql $atLimit).IsValid | Should -BeTrue -Because 'exactly 100 operators is allowed'
        $near = (1..82 | ForEach-Object { "w$_" }) -join ' OR '
        $check = Test-OrrKql -Kql $near
        $check.IsValid | Should -BeTrue
        ($check.Warnings -join "`n") | Should -Match 'close to the limit'
    }

    It 'rejects a query over 10,000 characters and warns above 4,000' {
        $long = '"' + ('x' * 10001) + '"'
        ((Test-OrrKql -Kql $long).Errors -join "`n") | Should -Match 'allows 10000'
        $medium = '"' + ('x' * 4500) + '"'
        $check = Test-OrrKql -Kql $medium
        $check.IsValid | Should -BeTrue
        ($check.Warnings -join "`n") | Should -Match 'characters'
    }
}
