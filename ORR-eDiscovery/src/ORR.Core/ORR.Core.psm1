#Requires -Version 5.1
<#
    ORR.Core - open records request (ORR) logic for Microsoft Purview eDiscovery.

    This module holds every rule about what an ORR may search for and how the query is
    written. It contains no UI code. Phase 1 (this file) makes no Graph calls: it loads the
    per-client configuration, validates an ORR spec, and builds the KQL (KeyQL) query.

    The module runs on Windows PowerShell 5.1 and PowerShell 7. Windows PowerShell 5.1 has no
    Test-Json, so the spec is validated by the code below; schemas/orr-spec.v1.schema.json is
    the published contract and tests/Spec.Tests.ps1 checks a table of cases against both.
    Two deliberate differences: the code accepts only a whole-number literal for ticketNumber
    (the schema's "integer" also allows 1.0), and it trims keywords before checking them.

    REFERENCES (Microsoft Learn pages the rules below are taken from)
      KQL operators, case rules, empty query, UTC:
        https://learn.microsoft.com/purview/edisc-search-query
      Condition builder, special characters, Date condition, Between/Before/After:
        https://learn.microsoft.com/purview/edisc-condition-builder
      KeyQL editor (Date is a KeyQL property, nested quotes unsupported):
        https://learn.microsoft.com/purview/edisc-keyword-query-language
      Search limits (query length, operators, wildcard prefix length):
        https://learn.microsoft.com/purview/edisc-ref-limits
      Meaning of the computed Date field per item type:
        https://learn.microsoft.com/purview/edisc-ref-document-metadata-fields
      Where Teams content is stored:
        https://learn.microsoft.com/purview/edisc-search-teams
      ediscoverySearch resource (contentQuery, dataSourceScopes):
        https://learn.microsoft.com/graph/api/resources/security-ediscoverysearch?view=graph-rest-1.0
      Add additional sources (userSource by SMTP address, siteSource by URL):
        https://learn.microsoft.com/graph/api/security-ediscoverysearch-post-additionalsources?view=graph-rest-1.0
      SharePoint KQL reference (operator list, range and date formats):
        https://learn.microsoft.com/sharepoint/dev/general-development/keyword-query-language-kql-syntax-reference
      Unsupported characters (documented for Exchange Server In-Place eDiscovery only):
        https://learn.microsoft.com/exchange/policy-and-compliance/ediscovery/message-properties-and-search-operators
#>

Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------------------

$script:OrrSpecVersion = '1'
$script:OrrLocations = @('exchange', 'onedrive', 'sharepoint', 'teams')
$script:OrrActions = @('search', 'export')
$script:OrrEnvironments = @('Global', 'USGov', 'USGovDoD')

$script:OrrSpecRequired = @(
    'specVersion', 'ticketNumber', 'client', 'requester', 'requestSummary',
    'custodians', 'dateStart', 'dateEnd', 'keywords', 'locations', 'action'
)
$script:OrrSpecOptional = @('kqlOverride', 'sites', 'teamMailboxes')

$script:OrrClientRequired = @('TenantId', 'DisplayName', 'AllowedDomains')
$script:OrrClientOptional = @(
    'CaseNamePrefix', 'DefaultLocations', 'PurviewPortalUrl', 'SummaryTemplate',
    'AllowedSharePointHosts', 'DatePaddingDays', 'Environment'
)

# The same patterns appear in schemas/orr-spec.v1.schema.json. Keep them identical.
# The part before @ is limited to plain ASCII letters, digits and a few symbols, so an
# address can later be placed in a request URL (escaped) without changing its meaning, and
# look-alike Unicode characters cannot pass the domain allow-list.
$script:OrrEmailPattern = '^[A-Za-z0-9!$&''+=^_`{|}~.-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$'
$script:OrrClientKeyPattern = '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'
$script:OrrDatePattern = '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
# "SharePoint site URLs must use the standard .sharepoint.com format." The quote is from the
# Graph page for adding a site as a case-level data source; its address is recorded in
# CLAUDE.md because tests/Safety.Tests.ps1 does not allow that operation's name in src.
# The search-level call this tool uses takes the same site object:
# https://learn.microsoft.com/graph/api/security-ediscoverysearch-post-additionalsources?view=graph-rest-1.0
$script:OrrSiteUrlPattern = '^https://[A-Za-z0-9-]+\.sharepoint\.com(/[^?#\s]*)?$'

# Search limits. 10,000 characters and 100 Boolean operators per query are the documented
# maximums, and both budgets are shared with any search permission filter applied to the
# person running the search, so the tool warns earlier.
# https://learn.microsoft.com/purview/edisc-ref-limits
$script:OrrKqlMaxLength = 10000
$script:OrrKqlWarnLength = 4000
$script:OrrKqlMaxOperators = 100
$script:OrrKqlWarnOperators = 80

# Boolean operators must be uppercase to be parsed as operators; lowercase ones are treated
# as keywords. https://learn.microsoft.com/purview/edisc-search-query
# ONEAR, WORDS and XRANK come from the SharePoint KQL reference; a keyword spelled like one
# of these is quoted so it can never act as an operator.
$script:OrrKqlOperators = @('AND', 'OR', 'NOT', 'NEAR', 'ONEAR')
$script:OrrKqlReservedWords = @('AND', 'OR', 'NOT', 'NEAR', 'ONEAR', 'WORDS', 'XRANK')

# "Here's a list of special characters that are either replaced by a blank space in the
# actual search query or cause a search error": + - = : ! @ # % ^ & , ; _ / ? ( ) [ ] { }
# https://learn.microsoft.com/purview/edisc-condition-builder
$script:OrrKqlSpecialCharPattern = '[+\-=:!@#%^&,;_/?()\[\]{}]'

# Specs that passed Test-OrrSpec in this module instance: ValidationId -> fingerprint.
$script:OrrValidatedSpecs = @{}

# ---------------------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------------------

# Strict JSON reader (RFC 8259). ConvertFrom-Json is not used for the spec or clients.json:
# it accepts comments, trailing commas, single quotes and repeated names (the last one
# silently wins); PowerShell 7 also reads 0123 as octal, unwraps a one-item list and turns
# date-like strings into DateTime, and Windows PowerShell 5.1 differs on each of those.
# One reader gives both editions the same answer for the same text.
$script:OrrJsonToken = New-Object regex ('\G[ \t\r\n]*(?:(?<p>[{}\[\],:])|"(?<s>(?:[^"\\\x00-\x1F]|\\(?:["\\/bfnrt]|u[0-9A-Fa-f]{4}))*)"|(?<n>-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)(?![0-9A-Za-z.+-])|(?<l>true|false|null)(?![0-9A-Za-z]))')

function ConvertFrom-OrrJsonString {
    param([string]$Body)
    if ($Body.IndexOf([char]'\') -lt 0) { return $Body }
    $builder = New-Object System.Text.StringBuilder
    $i = 0
    while ($i -lt $Body.Length) {
        $c = $Body[$i]
        if ($c -ne [char]'\') { [void]$builder.Append($c); $i++; continue }
        $e = [string]$Body[$i + 1]
        if ($e -ceq 'u') {
            [void]$builder.Append([char][Convert]::ToInt32($Body.Substring($i + 2, 4), 16))
            $i += 6
            continue
        }
        if ($e -ceq 'n') { [void]$builder.Append([char]10) }
        elseif ($e -ceq 'r') { [void]$builder.Append([char]13) }
        elseif ($e -ceq 't') { [void]$builder.Append([char]9) }
        elseif ($e -ceq 'b') { [void]$builder.Append([char]8) }
        elseif ($e -ceq 'f') { [void]$builder.Append([char]12) }
        else { [void]$builder.Append($e) }
        $i += 2
    }
    return $builder.ToString()
}

function Read-OrrJsonValue {
    # Returns @{ Value = ... } so that lists are never unrolled on the way out.
    param($State, [int]$Depth)
    if ($Depth -gt 32) { throw 'it is nested too deeply.' }
    if ($State['Index'] -ge $State['Tokens'].Count) { throw 'it ends too early.' }
    $tokens = $State['Tokens']
    $token = $tokens[$State['Index']]
    $State['Index']++
    $kind = $token['Kind']
    $text = $token['Text']
    if ($kind -ceq 's') { return @{ Value = $text } }
    if ($kind -ceq 'l') {
        if ($text -ceq 'true') { return @{ Value = $true } }
        if ($text -ceq 'false') { return @{ Value = $false } }
        return @{ Value = $null }
    }
    if ($kind -ceq 'n') {
        $invariant = [System.Globalization.CultureInfo]::InvariantCulture
        $whole = [long]0
        if ($text -cmatch '^-?[0-9]+$' -and [long]::TryParse($text, [System.Globalization.NumberStyles]::AllowLeadingSign, $invariant, [ref]$whole)) {
            return @{ Value = $whole }
        }
        return @{ Value = [double]::Parse($text, [System.Globalization.NumberStyles]::Float, $invariant) }
    }
    if ($text -ceq '{') {
        $object = New-Object System.Collections.Specialized.OrderedDictionary ([System.StringComparer]::Ordinal)
        if ($State['Index'] -lt $tokens.Count -and $tokens[$State['Index']]['Kind'] -ceq 'p' -and $tokens[$State['Index']]['Text'] -ceq '}') {
            $State['Index']++
            return @{ Value = $object }
        }
        while ($true) {
            if ($State['Index'] + 1 -ge $tokens.Count) { throw 'it ends too early.' }
            $name = $tokens[$State['Index']]
            $colon = $tokens[$State['Index'] + 1]
            if ($name['Kind'] -cne 's' -or $colon['Kind'] -cne 'p' -or $colon['Text'] -cne ':') {
                throw "a field name in double quotes followed by ':' is expected at character $($name['Position'])."
            }
            $State['Index'] += 2
            $inner = Read-OrrJsonValue -State $State -Depth ($Depth + 1)
            if ($object.Contains($name['Text'])) {
                throw "the name '$($name['Text'])' appears twice in the same object. Each name may appear once."
            }
            $object.Add($name['Text'], $inner['Value'])
            if ($State['Index'] -ge $tokens.Count) { throw 'it ends too early.' }
            $next = $tokens[$State['Index']]
            $State['Index']++
            if ($next['Kind'] -ceq 'p' -and $next['Text'] -ceq '}') { return @{ Value = $object } }
            if ($next['Kind'] -cne 'p' -or $next['Text'] -cne ',') { throw "',' or '}' is expected at character $($next['Position'])." }
        }
    }
    if ($text -ceq '[') {
        $items = New-Object System.Collections.ArrayList
        if ($State['Index'] -lt $tokens.Count -and $tokens[$State['Index']]['Kind'] -ceq 'p' -and $tokens[$State['Index']]['Text'] -ceq ']') {
            $State['Index']++
            return @{ Value = $items.ToArray() }
        }
        while ($true) {
            $inner = Read-OrrJsonValue -State $State -Depth ($Depth + 1)
            [void]$items.Add($inner['Value'])
            if ($State['Index'] -ge $tokens.Count) { throw 'it ends too early.' }
            $next = $tokens[$State['Index']]
            $State['Index']++
            if ($next['Kind'] -ceq 'p' -and $next['Text'] -ceq ']') { return @{ Value = $items.ToArray() } }
            if ($next['Kind'] -cne 'p' -or $next['Text'] -cne ',') { throw "',' or ']' is expected at character $($next['Position'])." }
        }
    }
    throw "'$text' is not expected at character $($token['Position'])."
}

function ConvertFrom-OrrStrictJson {
    # Returns @{ Value = <parsed> }; objects are ordinal ordered dictionaries, lists are
    # arrays, whole numbers are Int64. Throws a short reason on anything that is not JSON.
    param([string]$Text)
    $tokens = New-Object System.Collections.ArrayList
    $position = 0
    if ($Text.Length -gt 0 -and $Text[0] -eq [char]0xFEFF) { $position = 1 }
    while ($true) {
        $match = $script:OrrJsonToken.Match($Text, $position)
        if (-not $match.Success) { break }
        $kind = 'p'
        $value = $match.Groups['p'].Value
        if ($match.Groups['s'].Success) { $kind = 's'; $value = ConvertFrom-OrrJsonString -Body $match.Groups['s'].Value }
        elseif ($match.Groups['n'].Success) { $kind = 'n'; $value = $match.Groups['n'].Value }
        elseif ($match.Groups['l'].Success) { $kind = 'l'; $value = $match.Groups['l'].Value }
        [void]$tokens.Add(@{ Kind = $kind; Text = $value; Position = $match.Index })
        $position = $match.Index + $match.Length
    }
    $rest = $Text.Substring($position).TrimStart(' ', "`t", "`r", "`n")
    if ($rest.Length -gt 0) {
        $shown = $rest
        if ($shown.Length -gt 20) { $shown = $shown.Substring(0, 20) }
        throw "strict JSON does not allow what starts at character $($Text.Length - $rest.Length): $shown"
    }
    $state = @{ Tokens = $tokens; Index = 0 }
    $result = Read-OrrJsonValue -State $state -Depth 0
    if ($state['Index'] -ne $tokens.Count) { throw "there is extra text after the end, at character $($tokens[$state['Index']]['Position'])." }
    return $result
}

function Get-OrrSortedKeys {
    # Key names in ordinal order, so messages come out in the same order on every edition
    # and culture. get_Keys() is called as a method on purpose: on a dictionary, '.Keys'
    # returns the ENTRY named "Keys" when the data contains one.
    param($Table)
    $names = [string[]]@($Table.get_Keys())
    [array]::Sort($names, [System.StringComparer]::Ordinal)
    return , $names
}

function Test-OrrInList {
    # Ordinal membership test. -contains is a linguistic comparison (it treats the Kelvin
    # sign as 'k' and ignores soft hyphens), which is not good enough for an allow-list.
    param([string[]]$List, [string]$Value)
    return ([Array]::IndexOf([string[]]@($List), $Value) -ge 0)
}

function Get-OrrClientStamp {
    # The client settings a validated spec depends on. Stored in the spec's fingerprint so a
    # spec is refused if clients.json is changed and reloaded after validation.
    param($Client)
    $domains = [string[]]@($Client.AllowedDomains)
    [array]::Sort($domains, [System.StringComparer]::Ordinal)
    $hosts = [string[]]@($Client.AllowedSharePointHosts)
    [array]::Sort($hosts, [System.StringComparer]::Ordinal)
    return (@([string]$Client.Key, [string]$Client.TenantId, ($domains -join ','), ($hosts -join ','),
            [string]$Client.DatePaddingDays, [string]$Client.Environment) -join [string][char]0x1F)
}

function ConvertTo-OrrPropertyBag {
    # Turns a parsed JSON object or a dictionary into a case-sensitive name -> value table.
    # Values are stored as they are, so a one-item array stays an array.
    param($InputObject)

    $bag = New-Object System.Collections.Hashtable ([System.StringComparer]::Ordinal)
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in @($InputObject.get_Keys())) { $bag[[string]$key] = $InputObject[$key] }
        return $bag
    }
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        foreach ($property in $InputObject.PSObject.Properties) { $bag[$property.Name] = $property.Value }
        return $bag
    }
    return $null
}

function Test-OrrIsList {
    param($Value)
    return (($Value -is [System.Collections.IList]) -and ($Value -isnot [string]))
}

function Test-OrrIsInteger {
    # JSON numbers arrive as Int32 on Windows PowerShell 5.1 and Int64 on PowerShell 7.
    param($Value)
    return (($Value -is [int]) -or ($Value -is [long]))
}

function ConvertTo-OrrCleanText {
    # Smart quotes, control characters and left-to-right / right-to-left marks are listed as
    # unsupported in search queries, and are "often hidden ... when you copy the query ...
    # from other applications (such as Microsoft Word or Microsoft Excel)". That statement is
    # documented for Exchange Server In-Place eDiscovery only; applying it to Purview is an
    # inference, made because a spec is usually pasted from a ticket.
    # https://learn.microsoft.com/exchange/policy-and-compliance/ediscovery/message-properties-and-search-operators
    param([string]$Text)

    $doubleQuotes = '[' + [char]0x201C + [char]0x201D + [char]0x201E + [char]0x201F + ']'
    $singleQuotes = '[' + [char]0x2018 + [char]0x2019 + [char]0x201A + [char]0x201B + ']'
    $clean = $Text -replace $doubleQuotes, '"'
    $clean = $clean -replace $singleQuotes, "'"
    $clean = $clean -replace '\p{Cc}', ' '
    $clean = $clean -replace '\p{Cf}', ''
    $clean = $clean -replace '\s+', ' '
    return $clean.Trim()
}

function ConvertTo-OrrKqlTerm {
    # Turns one keyword from a spec into one KQL term, or explains why it cannot be used.
    param([string]$Keyword)

    $result = [PSCustomObject]@{ Term = $null; Text = $null; Error = $null; Warning = $null }

    $hadHiddenCharacters = ($Keyword -match '\p{Cf}')
    $text = ConvertTo-OrrCleanText -Text $Keyword
    if ($text.Length -eq 0) {
        $result.Error = 'is empty.'
        return $result
    }

    # A keyword the requester already wrapped in quotes is an exact phrase.
    $quoted = $false
    # String comparisons here are ordinal: the culture-sensitive overloads give different
    # answers under some Windows regional settings.
    $ordinal = [System.StringComparison]::Ordinal
    if ($text.Length -ge 2 -and $text.StartsWith('"', $ordinal) -and $text.EndsWith('"', $ordinal)) {
        $quoted = $true
        $text = $text.Substring(1, $text.Length - 2).Trim()
        if ($text.Length -eq 0) {
            $result.Error = 'is an empty quoted phrase.'
            return $result
        }
    }

    # "Nested quotation marks aren't supported in the KeyQL editor", and no escape character
    # is documented. https://learn.microsoft.com/purview/edisc-keyword-query-language
    if ($text.Contains('"')) {
        $result.Error = 'contains a double quote inside the text. eDiscovery has no way to search for a quote character; remove it.'
        return $result
    }

    # Punctuation is not indexed, so a keyword with no letter or digit is an empty search
    # term, and an empty term matches everything.
    if ($text -notmatch '[\p{L}\p{Nd}]') {
        $result.Error = 'has no letters or digits, so there is nothing to search for.'
        return $result
    }

    $result.Text = $text
    if ($hadHiddenCharacters) {
        $result.Warning = "had hidden characters removed; check it reads correctly: $text"
    }

    if ($text.Contains('*')) {
        # Only prefix wildcards are supported, with at least 3 letters before the asterisk.
        # https://learn.microsoft.com/purview/edisc-ref-limits
        # The docs say "Using quotes stops wild cards" and also show wildcards inside quotes,
        # so the tool only allows the unambiguous form: one unquoted word ending in *.
        # https://learn.microsoft.com/purview/edisc-search-query
        $prefix = $text.Substring(0, $text.Length - 1)
        $letterCount = [regex]::Matches($prefix, '\p{L}').Count
        if ($quoted -or -not $text.EndsWith('*', $ordinal) -or $prefix -notmatch '^[\p{L}\p{Nd}]+$' -or $letterCount -lt 3) {
            $result.Error = "uses * in a way eDiscovery does not support. A wildcard is only allowed at the end of a single unquoted word with at least 3 letters before it, for example 'budget*'."
            return $result
        }
        if ($script:OrrKqlReservedWords -ccontains $prefix) {
            $result.Error = "starts with an operator word in capitals. Write it in lowercase, for example '$($prefix.ToLowerInvariant())*'."
            return $result
        }
        $result.Term = $text
        return $result
    }

    $isPlainWord = ($text -match '^[\p{L}\p{Nd}]+$')
    $isReserved = ($script:OrrKqlReservedWords -contains $text.ToUpperInvariant())
    if ($isPlainWord -and -not $quoted -and -not $isReserved) {
        $result.Term = $text
        return $result
    }

    # Anything else is sent as a quoted phrase so that spaces (a space between keywords means
    # OR), operator words and operator characters cannot change the logic of the query.
    # https://learn.microsoft.com/purview/edisc-search-query
    $result.Term = '"' + $text + '"'
    if ($text -match $script:OrrKqlSpecialCharPattern) {
        $punctuation = "contains punctuation (+ - = : ! @ # % ^ & , ; _ / ? ( ) [ ] { }) that Microsoft documents as replaced by a space or causing a search error. It is sent as a quoted phrase; check the estimate, and consider listing the parts as separate keywords."
        if ($result.Warning) { $result.Warning = "$($result.Warning). It also $punctuation" } else { $result.Warning = $punctuation }
    }
    return $result
}

function Get-OrrKqlBuild {
    # Builds the KQL for spec values that have already been type-checked. Returns errors
    # instead of throwing so Test-OrrSpec can report them against the right field.
    param(
        [string[]]$Keywords,
        [string]$KqlOverride,
        [datetime]$DateStart,
        [datetime]$DateEnd,
        [int]$DatePaddingDays
    )

    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $notes = New-Object System.Collections.Generic.List[string]

    # The requested end date is included by asking for everything before the following day.
    # Whether 'date<=2024-12-31' covers the whole of the 31st is not stated on any eDiscovery
    # page; 'date<2025-01-01' covers it under either reading. The Before operator
    # (property<date) is documented at https://learn.microsoft.com/purview/edisc-condition-builder
    # "The time zone for all searches is Coordinated Universal Time (UTC)", so the range is
    # widened by DatePaddingDays on each side to keep items sent near local midnight.
    # https://learn.microsoft.com/purview/edisc-search-query
    $rangeStart = $DateStart.AddDays(-$DatePaddingDays)
    $rangeEndExclusive = $DateEnd.AddDays(1 + $DatePaddingDays)
    $startText = $rangeStart.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
    $endText = $rangeEndExclusive.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)

    $build = [PSCustomObject]@{
        Kql              = $null
        Source           = 'Generated'
        DateProperty     = 'date'
        DateStartInclusive = $startText
        DateEndExclusive = $endText
        DatePaddingDays  = $DatePaddingDays
        KeywordCount     = 0
        OperatorCount    = 0
        Length           = 0
        Errors           = @()
        Warnings         = @()
        Notes            = @()
    }

    if (-not [string]::IsNullOrWhiteSpace($KqlOverride)) {
        $build.Source = 'Override'
        $build.DateProperty = $null
        $build.DateStartInclusive = $null
        $build.DateEndExclusive = $null
        $build.DatePaddingDays = 0
        # Every run of whitespace (including non-breaking spaces pasted from Word or a web
        # page) becomes one ordinary space, the same as for keywords.
        $kql = ($KqlOverride -replace '\s+', ' ').Trim()
        if (@($Keywords).Count -gt 0) {
            $warnings.Add('kqlOverride is set, so the keywords list is not used.')
        }
        # Look for a date condition outside quoted phrases only, at the start of a term.
        $outsideQuotes = [regex]::Replace($kql, '"[^"]*"', 'Q')
        $hasDate = [regex]::IsMatch($outsideQuotes, '(^|[\s(\-])(date|sent|received|created|lastmodifiedtime)\s*(:|=|<|>)',
            [System.Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant')
        if (-not $hasDate) {
            $warnings.Add('kqlOverride has no date condition. dateStart and dateEnd are NOT applied to an override; the search covers every date.')
        } else {
            $notes.Add('kqlOverride contains a date condition of its own; check that it limits the whole query. dateStart and dateEnd in the spec are not added to it.')
        }
    } else {
        $terms = New-Object System.Collections.Generic.List[string]
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $index = 0
        foreach ($keyword in @($Keywords)) {
            $term = ConvertTo-OrrKqlTerm -Keyword $keyword
            if ($term.Error) {
                $errors.Add("keywords[$index]: '$keyword' $($term.Error)")
            } elseif (-not $seen.Add($term.Term)) {
                $warnings.Add("keywords[$index]: '$keyword' is a duplicate and is used once.")
            } else {
                $terms.Add($term.Term)
                if ($term.Warning) { $warnings.Add("keywords[$index]: '$keyword' $($term.Warning)") }
            }
            $index++
        }

        # 'Date' is the one date condition documented for both mailbox and site items. The
        # shape 'Date>=... AND Date<=...' is the example on the ediscoverySearch resource page.
        # https://learn.microsoft.com/graph/api/resources/security-ediscoverysearch?view=graph-rest-1.0
        $dateClause = "(date>=$startText AND date<$endText)"
        if ($terms.Count -eq 0) {
            $kql = $dateClause
            $warnings.Add('No keywords: the search returns every item in the date range from every selected source.')
        } else {
            # Every join is an explicit uppercase operator inside parentheses. A bare space
            # is never emitted because eDiscovery reads it as OR.
            $kql = '(' + ($terms -join ' OR ') + ') AND ' + $dateClause
        }
        $build.KeywordCount = $terms.Count

        $notes.Add("Dates are evaluated in UTC. The query covers $startText up to, but not including, $endText.")
        if ($DatePaddingDays -gt 0) {
            $notes.Add("The requested range is widened by $DatePaddingDays day(s) on each side so items sent near midnight local time are not missed.")
        }
        # "Date is a computed field that depends on the file type: Email: Sent date ...
        # SharePoint documents: Last modified date ... Meetings: Meeting start date", and
        # drafts "might also be returned unexpectedly by date-range conditions".
        # https://learn.microsoft.com/purview/edisc-ref-document-metadata-fields
        # The condition builder page defines it differently for email: "the date a message
        # was created or imported from a PST file". Which one search uses is not settled.
        # https://learn.microsoft.com/purview/edisc-condition-builder
        $notes.Add('Microsoft documents the date as the sent date for email and Teams messages (another Microsoft page says the date an email was created or imported from a PST), the last-modified date for documents, and the start date for meetings. Imported mail may match on its import date. Draft emails can also match.')
    }

    if ($errors.Count -eq 0) {
        $check = Test-OrrKql -Kql $kql
        foreach ($item in $check.Errors) { $errors.Add($item) }
        foreach ($item in $check.Warnings) { $warnings.Add($item) }
        $build.OperatorCount = $check.OperatorCount
        $build.Length = $check.Length
        $build.Kql = $kql
    }

    $build.Errors = @($errors)
    $build.Warnings = @($warnings)
    $build.Notes = @($notes)
    return $build
}

function Get-OrrSpecFingerprint {
    # A hash of the request values in a validated spec and of the client settings it was
    # checked against. Assert-OrrValidatedSpec compares it with the one recorded by
    # Test-OrrSpec, so a spec changed after validation is refused.
    # CustodiansResolved is deliberately left out: it is set after validation, once the
    # custodians have been looked up in the tenant.
    param($Spec)

    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $fields = @(
        , @([string]$Spec.SpecVersion)
        , @(([long]$Spec.TicketNumber).ToString($invariant))
        , @([string]$Spec.Client)
        , @([string]$Spec.ClientStamp)
        , @([string]$Spec.Requester)
        , @([string]$Spec.RequestSummary)
        , @($Spec.Custodians)
        , @(([datetime]$Spec.DateStart).ToString('yyyy-MM-dd', $invariant))
        , @(([datetime]$Spec.DateEnd).ToString('yyyy-MM-dd', $invariant))
        , @($Spec.Keywords)
        , @([string]$Spec.KqlOverride)
        , @($Spec.Locations)
        , @($Spec.Sites)
        , @($Spec.TeamMailboxes)
        , @([string]$Spec.Action)
        , @([string]$Spec.ValidationId)
    )
    # Each field is written as its item count followed by length-prefixed items, so one
    # item that contains a separator can never hash the same as two items.
    $builder = New-Object System.Text.StringBuilder
    foreach ($field in $fields) {
        [void]$builder.Append(@($field).Count).Append('[')
        foreach ($item in @($field)) {
            $itemText = [string]$item
            [void]$builder.Append($itemText.Length).Append(':').Append($itemText)
        }
        [void]$builder.Append(']')
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($builder.ToString())
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '')
    } finally {
        $sha.Dispose()
    }
}

function Assert-OrrValidatedSpec {
    # Every function that acts on a spec calls this first. It throws unless the object came
    # out of Test-OrrSpec in this module instance and has not been changed since.
    param($Spec)

    $message = 'This is not a validated ORR spec. Pass the spec through Test-OrrSpec and use the Spec it returns, unchanged.'
    if ($null -eq $Spec -or $Spec -isnot [System.Management.Automation.PSCustomObject]) { throw $message }
    if ($Spec.PSObject.TypeNames -notcontains 'ORR.ValidatedSpec') { throw $message }
    $idProperty = $Spec.PSObject.Properties['ValidationId']
    if ($null -eq $idProperty -or [string]::IsNullOrEmpty([string]$idProperty.Value)) { throw $message }
    $id = [string]$idProperty.Value
    if (-not $script:OrrValidatedSpecs.ContainsKey($id)) { throw $message }
    try {
        $fingerprint = Get-OrrSpecFingerprint -Spec $Spec
    } catch {
        throw $message
    }
    if ($fingerprint -cne $script:OrrValidatedSpecs[$id]) {
        throw 'This ORR spec was changed after it was validated. Run Test-OrrSpec again.'
    }
}

function Get-OrrStringList {
    # Checks that a spec field is a list of non-empty strings and returns the trimmed values.
    param(
        $Value,
        [string]$Field,
        [int]$MaxItems,
        [int]$MaxLength,
        [System.Collections.Generic.List[string]]$Errors,
        # Refuse a value with a space or line break around it instead of trimming it. Used
        # for the fields the schema checks with a pattern or a fixed list.
        [switch]$Exact
    )

    $items = New-Object System.Collections.Generic.List[string]
    if (-not (Test-OrrIsList $Value)) {
        $Errors.Add("${Field}: must be a list, for example [`"value`"].")
        return [PSCustomObject]@{ Items = @(); IsList = $false }
    }
    if ($Value.Count -gt $MaxItems) {
        $Errors.Add("${Field}: has $($Value.Count) entries; the limit is $MaxItems.")
    }
    $index = 0
    foreach ($item in $Value) {
        if ($item -isnot [string]) {
            $Errors.Add("${Field}[$index]: must be text in double quotes.")
        } elseif ([string]::IsNullOrWhiteSpace($item)) {
            $Errors.Add("${Field}[$index]: is empty.")
        } elseif ($item.Length -gt $MaxLength) {
            $Errors.Add("${Field}[$index]: is longer than $MaxLength characters.")
        } elseif ($Exact -and $item.Length -ne $item.Trim().Length) {
            $Errors.Add("${Field}[$index]: has a space or line break before or after it. Remove it.")
        } else {
            $items.Add($item.Trim())
        }
        $index++
    }
    return [PSCustomObject]@{ Items = @($items); IsList = $true }
}

function Get-OrrEmailDomain {
    param([string]$Address)
    # Ordinal search: the culture-sensitive LastIndexOf(string) fails to find '@' under some
    # regional settings (caught by the th-TH test in tests/Kql.Tests.ps1).
    return $Address.Substring($Address.LastIndexOf('@', [System.StringComparison]::Ordinal) + 1).ToLowerInvariant()
}

# ---------------------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------------------

function Import-OrrClientConfig {
    <#
    .SYNOPSIS
        Loads and checks the per-client configuration file (clients.json).

    .DESCRIPTION
        Reads a clients.json file, checks every client entry, fills in defaults, and returns
        a table of clients keyed by client key. The key is what an ORR spec names in its
        "client" field, and the match is case-sensitive.

        The file is refused as a whole if any entry is wrong, so a typo in one client cannot
        leave the tool running with a half-loaded configuration. Unknown properties are
        refused for the same reason.

        The real clients.json holds tenant IDs and is never committed; copy
        config/clients.example.json and edit the copy.

    .PARAMETER Path
        Path to the clients.json file.

    .EXAMPLE
        $clients = Import-OrrClientConfig -Path .\config\clients.json
        $clients['contoso-city'].AllowedDomains

    .OUTPUTS
        System.Collections.Hashtable. One ORR.ClientConfig object per client key.

    .NOTES
        Environment maps to Connect-MgGraph -Environment (Global, USGov, USGovDoD).
        https://learn.microsoft.com/powershell/microsoftgraph/authentication-commands
        The Purview portal has no documented deep link to a case, so PurviewPortalUrl is the
        portal's base address. https://learn.microsoft.com/purview/purview-portal
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Client configuration file not found: $Path. Copy config\clients.example.json to config\clients.json and fill it in."
    }
    Write-Verbose "Reading client configuration from $Path"
    # Strict UTF-8: a file saved in an ANSI code page would otherwise load with silently
    # corrupted client names.
    try {
        $raw = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path).ProviderPath, (New-Object System.Text.UTF8Encoding($false, $true)))
    } catch [System.Text.DecoderFallbackException] {
        throw "Client configuration file $Path is not saved as UTF-8. Save it again as UTF-8."
    }

    try {
        $parsed = (ConvertFrom-OrrStrictJson -Text $raw)['Value']
    } catch {
        throw "Client configuration file $Path is not valid JSON: $($_.Exception.Message)"
    }

    $errors = New-Object System.Collections.Generic.List[string]
    $root = ConvertTo-OrrPropertyBag -InputObject $parsed
    if ($null -eq $root) { throw "Client configuration file $Path must contain a JSON object." }

    foreach ($name in (Get-OrrSortedKeys $root)) {
        if (@('configVersion', 'clients') -cnotcontains $name) { $errors.Add("Unknown property '$name' at the top level.") }
    }
    if (-not $root.ContainsKey('configVersion') -or $root['configVersion'] -isnot [string] -or $root['configVersion'] -cne '1') {
        $errors.Add('configVersion must be the text "1".')
    }
    $clientBag = $null
    if ($root.ContainsKey('clients')) { $clientBag = ConvertTo-OrrPropertyBag -InputObject $root['clients'] }
    if ($null -eq $clientBag) {
        $errors.Add('clients must be an object with one entry per client.')
        $clientBag = New-Object System.Collections.Hashtable ([System.StringComparer]::Ordinal)
    } elseif ($clientBag.get_Count() -eq 0) {
        $errors.Add('clients has no entries.')
    }

    $result = New-Object System.Collections.Hashtable ([System.StringComparer]::Ordinal)
    $allowedNames = $script:OrrClientRequired + $script:OrrClientOptional
    # Names that would hide a member of the returned table (for example $clients.Count).
    $reservedKeys = @('Keys', 'Values', 'Count', 'IsReadOnly', 'IsFixedSize', 'IsSynchronized', 'SyncRoot')

    foreach ($key in (Get-OrrSortedKeys $clientBag)) {
        $prefix = "clients.$key"
        if ($key -cnotmatch $script:OrrClientKeyPattern -or $key -match '[\r\n]') {
            $errors.Add("${prefix}: the client key may only use letters, digits, '-' and '_' (up to 64 characters).")
        } elseif ($reservedKeys -contains $key) {
            $errors.Add("${prefix}: '$key' cannot be used as a client key. Choose another name.")
        }
        $entry = ConvertTo-OrrPropertyBag -InputObject $clientBag[$key]
        if ($null -eq $entry) {
            $errors.Add("${prefix}: must be an object.")
            continue
        }
        foreach ($name in (Get-OrrSortedKeys $entry)) {
            if ($allowedNames -cnotcontains $name) { $errors.Add("${prefix}: unknown property '$name'.") }
        }
        foreach ($name in $script:OrrClientRequired) {
            if (-not $entry.ContainsKey($name)) { $errors.Add("${prefix}: '$name' is missing.") }
        }

        $tenantId = $null
        if ($entry.ContainsKey('TenantId')) {
            $guid = [guid]::Empty
            if ($entry['TenantId'] -is [string] -and [guid]::TryParse($entry['TenantId'], [ref]$guid) -and $entry['TenantId'].Length -eq 36) {
                $tenantId = $guid.ToString()
            } else {
                $errors.Add("${prefix}.TenantId: must be the tenant's directory ID, for example 11111111-2222-3333-4444-555555555555.")
            }
        }

        $displayName = $null
        if ($entry.ContainsKey('DisplayName')) {
            if ($entry['DisplayName'] -is [string] -and -not [string]::IsNullOrWhiteSpace($entry['DisplayName'])) {
                $displayName = $entry['DisplayName'].Trim()
            } else {
                $errors.Add("${prefix}.DisplayName: must be a non-empty name.")
            }
        }

        $domains = @()
        if ($entry.ContainsKey('AllowedDomains')) {
            $list = Get-OrrStringList -Value $entry['AllowedDomains'] -Field "$prefix.AllowedDomains" -MaxItems 200 -MaxLength 255 -Errors $errors
            $domains = @($list.Items | ForEach-Object { $_.ToLowerInvariant() })
            if ($list.IsList -and $domains.Count -eq 0) { $errors.Add("${prefix}.AllowedDomains: list at least one email domain.") }
            foreach ($domain in $domains) {
                if ($domain -cnotmatch '^[a-z0-9-]+(\.[a-z0-9-]+)+\z') {
                    $errors.Add("${prefix}.AllowedDomains: '$domain' is not a domain name such as contoso.gov.")
                }
            }
        }

        $casePrefix = 'ORR'
        if ($entry.ContainsKey('CaseNamePrefix') -and $null -ne $entry['CaseNamePrefix']) {
            if ($entry['CaseNamePrefix'] -is [string] -and $entry['CaseNamePrefix'] -cmatch '^[A-Za-z0-9]{1,16}\z') {
                $casePrefix = $entry['CaseNamePrefix']
            } else {
                $errors.Add("${prefix}.CaseNamePrefix: use 1 to 16 letters or digits.")
            }
        }

        $defaultLocations = @('exchange', 'onedrive')
        if ($entry.ContainsKey('DefaultLocations') -and $null -ne $entry['DefaultLocations']) {
            $list = Get-OrrStringList -Value $entry['DefaultLocations'] -Field "$prefix.DefaultLocations" -MaxItems 4 -MaxLength 20 -Errors $errors
            foreach ($location in $list.Items) {
                if ($script:OrrLocations -cnotcontains $location) {
                    $errors.Add("${prefix}.DefaultLocations: '$location' is not one of $($script:OrrLocations -join ', ').")
                }
            }
            if ($list.IsList -and $list.Items.Count -eq 0) { $errors.Add("${prefix}.DefaultLocations: list at least one location.") }
            $defaultLocations = @($list.Items | Select-Object -Unique)
        }

        $portalUrl = 'https://purview.microsoft.com'
        if ($entry.ContainsKey('PurviewPortalUrl') -and $null -ne $entry['PurviewPortalUrl']) {
            $uri = $null
            if ($entry['PurviewPortalUrl'] -is [string] -and
                [uri]::TryCreate($entry['PurviewPortalUrl'], [System.UriKind]::Absolute, [ref]$uri) -and
                $uri.Scheme -eq 'https') {
                $portalUrl = $entry['PurviewPortalUrl'].TrimEnd('/')
            } else {
                $errors.Add("${prefix}.PurviewPortalUrl: must be an https address, for example https://purview.microsoft.com.")
            }
        }

        $summaryTemplate = $null
        if ($entry.ContainsKey('SummaryTemplate') -and $null -ne $entry['SummaryTemplate']) {
            if ($entry['SummaryTemplate'] -is [string]) {
                $summaryTemplate = $entry['SummaryTemplate']
            } else {
                $errors.Add("${prefix}.SummaryTemplate: must be text, or null to use the built-in summary.")
            }
        }

        $sharePointHosts = @()
        if ($entry.ContainsKey('AllowedSharePointHosts') -and $null -ne $entry['AllowedSharePointHosts']) {
            $list = Get-OrrStringList -Value $entry['AllowedSharePointHosts'] -Field "$prefix.AllowedSharePointHosts" -MaxItems 50 -MaxLength 255 -Errors $errors
            $sharePointHosts = @($list.Items | ForEach-Object { $_.ToLowerInvariant() })
            foreach ($hostName in $sharePointHosts) {
                if ($hostName -cnotmatch '^[a-z0-9-]+\.sharepoint\.com\z') {
                    $errors.Add("${prefix}.AllowedSharePointHosts: '$hostName' must be a host name such as contoso.sharepoint.com or contoso-my.sharepoint.com.")
                }
            }
        }

        $padding = 1
        if ($entry.ContainsKey('DatePaddingDays') -and $null -ne $entry['DatePaddingDays']) {
            if ((Test-OrrIsInteger $entry['DatePaddingDays']) -and $entry['DatePaddingDays'] -ge 0 -and $entry['DatePaddingDays'] -le 2) {
                $padding = [int]$entry['DatePaddingDays']
            } else {
                $errors.Add("${prefix}.DatePaddingDays: must be 0, 1 or 2.")
            }
        }

        $environment = 'Global'
        if ($entry.ContainsKey('Environment') -and $null -ne $entry['Environment']) {
            if ($entry['Environment'] -is [string] -and $script:OrrEnvironments -ccontains $entry['Environment']) {
                $environment = $entry['Environment']
            } else {
                $errors.Add("${prefix}.Environment: must be one of $($script:OrrEnvironments -join ', ').")
            }
        }

        $result[$key] = [PSCustomObject]@{
            PSTypeName             = 'ORR.ClientConfig'
            Key                    = $key
            TenantId               = $tenantId
            DisplayName            = $displayName
            AllowedDomains         = $domains
            CaseNamePrefix         = $casePrefix
            DefaultLocations       = $defaultLocations
            PurviewPortalUrl       = $portalUrl
            SummaryTemplate        = $summaryTemplate
            AllowedSharePointHosts = $sharePointHosts
            DatePaddingDays        = $padding
            Environment            = $environment
        }
    }

    if ($errors.Count -gt 0) {
        throw ("Client configuration file $Path has $($errors.Count) problem(s):`n - " + ($errors -join "`n - "))
    }
    Write-Verbose "Loaded $($result.get_Count()) client(s): $((Get-OrrSortedKeys $result) -join ', ')"
    return $result
}

function Test-OrrKql {
    <#
    .SYNOPSIS
        Checks a KQL query string before it is sent to eDiscovery.

    .DESCRIPTION
        Checks a query for the mistakes that make an eDiscovery search fail, or worse, run
        and quietly return the wrong thing: an empty query (which returns everything),
        unbalanced quotes or parentheses, a query made only of operators, hidden characters
        pasted from Word or a ticket, and the documented length and operator limits.

        Warnings point out things that are legal but usually not what was meant: lowercase
        and/or/not (treated as keywords), a bare space between terms (treated as OR), and a
        space after a property name such as "to: name".

        This is a pre-flight check, not a full KQL parser. A query that passes can still be
        rejected by the service.

    .PARAMETER Kql
        The query text to check.

    .EXAMPLE
        Test-OrrKql -Kql '(budget OR "road repair") AND (date>=2024-01-01 AND date<2024-04-01)'

    .EXAMPLE
        (Test-OrrKql -Kql 'budget and roads').Warnings

    .OUTPUTS
        ORR.KqlCheck with IsValid, Errors, Warnings, OperatorCount and Length.

    .NOTES
        REFERENCES
        https://learn.microsoft.com/purview/edisc-search-query
        https://learn.microsoft.com/purview/edisc-condition-builder
        https://learn.microsoft.com/purview/edisc-keyword-query-language
        https://learn.microsoft.com/purview/edisc-ref-limits
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Kql
    )

    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $operatorCount = 0
    $text = [string]$Kql

    # "An empty keyword condition returns all content in the selected data sources, not no
    # content." The Graph API marks contentQuery as optional, so the tool must refuse it.
    # https://learn.microsoft.com/purview/edisc-search-query
    if ([string]::IsNullOrWhiteSpace($text)) {
        $errors.Add('The query is empty. An empty eDiscovery query returns every item in every selected location.')
    } else {
        $smartQuotes = '[' + [char]0x201C + [char]0x201D + [char]0x201E + [char]0x201F + ']'
        foreach ($phrase in [regex]::Matches($text, '"[^"]*"')) {
            if ($phrase.Value -notmatch '[\p{L}\p{Nd}]') {
                $errors.Add('The query contains an empty quoted phrase, or one with no letters or digits. It would match everything; remove it.')
                break
            }
        }
        if ($text -match $smartQuotes) {
            $errors.Add('The query contains curly (smart) quotes. Replace them with straight double quotes.')
        }
        if ($text -match '[\p{Cc}-[\r\n\t]]' -or $text -match '\p{Cf}') {
            $errors.Add('The query contains hidden control or formatting characters, usually from copy and paste. Retype the query.')
        }

        $quoteCount = [regex]::Matches($text, '"').Count
        if ($quoteCount % 2 -ne 0) {
            $errors.Add('The query has an odd number of double quotes. Every phrase needs an opening and a closing quote.')
        } else {
            # Look at what is outside quoted phrases; each phrase becomes the placeholder Q.
            $outside = [regex]::Replace($text, '"[^"]*"', 'Q')

            $depth = 0
            $balanced = $true
            foreach ($character in $outside.ToCharArray()) {
                if ($character -eq '(') { $depth++ }
                elseif ($character -eq ')') { $depth--; if ($depth -lt 0) { $balanced = $false } }
            }
            if ($depth -ne 0) { $balanced = $false }
            if (-not $balanced) { $errors.Add('The query has unbalanced parentheses.') }

            # "Don't use (c:c) in manually entered queries. (c:c) isn't equal to AND or OR."
            # https://learn.microsoft.com/purview/edisc-condition-builder
            if ($outside -match '\(\s*\)') {
                $errors.Add('The query has an empty pair of parentheses ( ). Remove it or put a term inside.')
            }
            if ($outside -match '\(\s*c:c\s*\)') {
                $errors.Add('The query contains (c:c), which only the Purview condition builder may write. Use AND or OR.')
            }

            # "Don't include a space between the property operator and the value", otherwise
            # the value is searched as a plain keyword.
            # https://learn.microsoft.com/purview/edisc-search-query
            if ([regex]::IsMatch($outside, '\p{L}(:|=|>=|<=|>|<)\s+\S')) {
                $warnings.Add('There is a space after a property operator (for example "to: name"). eDiscovery then searches the value as a plain keyword. Remove the space.')
            }

            $flat = [regex]::Replace($outside, 'O?NEAR\(\s*(n=)?[0-9]+\s*\)', ' NEAR ')
            $flat = $flat -replace '[()]', ' '
            $tokens = @($flat -split '\s+' | Where-Object { $_ })
            $termCount = 0
            $implicitOr = $false
            $lowercaseOperator = $false
            $badOperatorOrder = $false
            $previousWasOperator = $false
            $previousWasTerm = $false
            $position = 0
            foreach ($token in $tokens) {
                $isOperator = ($script:OrrKqlOperators -ccontains $token)
                if ($isOperator) {
                    $operatorCount++
                    if ($position -eq 0 -and $token -cne 'NOT') { $badOperatorOrder = $true }
                    if ($previousWasOperator -and $token -cne 'NOT') { $badOperatorOrder = $true }
                    if ($position -eq ($tokens.Count - 1)) { $badOperatorOrder = $true }
                } elseif ($token -notmatch '[\p{L}\p{Nd}]') {
                    # Bare punctuation such as * , : or - is not something to search for.
                    $position++
                    continue
                } else {
                    $termCount++
                    if ($previousWasTerm) { $implicitOr = $true }
                    if ($script:OrrKqlOperators -contains $token) { $lowercaseOperator = $true }
                }
                $previousWasOperator = $isOperator
                $previousWasTerm = -not $isOperator
                $position++
            }

            if ($termCount -eq 0) {
                $errors.Add('The query contains only operators or parentheses and nothing to search for.')
            } elseif ($badOperatorOrder) {
                $errors.Add('An operator (AND, OR, NOT, NEAR) is missing the term before or after it.')
            }
            if ($lowercaseOperator) {
                $warnings.Add('The query has and/or/not/near in lowercase. eDiscovery treats those as keywords; operators must be UPPERCASE.')
            }
            if ($implicitOr) {
                $warnings.Add('Two terms are separated only by a space. eDiscovery treats a space as OR. Write AND or OR between terms, or put a phrase in double quotes.')
            }
            if ($operatorCount -gt $script:OrrKqlMaxOperators) {
                $errors.Add("The query uses $operatorCount operators; eDiscovery allows $($script:OrrKqlMaxOperators). Split the keywords across more than one request.")
            } elseif ($operatorCount -gt $script:OrrKqlWarnOperators) {
                $warnings.Add("The query uses $operatorCount operators, close to the limit of $($script:OrrKqlMaxOperators). Search permission filters count toward the same limit.")
            }
        }

        if ($text.Length -gt $script:OrrKqlMaxLength) {
            $errors.Add("The query is $($text.Length) characters; eDiscovery allows $($script:OrrKqlMaxLength).")
        } elseif ($text.Length -gt $script:OrrKqlWarnLength) {
            $warnings.Add("The query is $($text.Length) characters. Site URLs and search permission filters count toward the $($script:OrrKqlMaxLength)-character limit, so a query this long may be rejected.")
        }
    }

    return [PSCustomObject]@{
        PSTypeName    = 'ORR.KqlCheck'
        IsValid       = ($errors.Count -eq 0)
        Errors        = @($errors)
        Warnings      = @($warnings)
        OperatorCount = $operatorCount
        Length        = $text.Length
    }
}

function Test-OrrSpec {
    <#
    .SYNOPSIS
        Validates an ORR spec and returns the validated spec the rest of the tool acts on.

    .DESCRIPTION
        Checks an ORR spec (version 1) against the published schema and the rules the schema
        cannot express, and reports every problem at once in plain English.

        A spec is refused when it has unknown or missing fields, wrong types, a client that
        is not in clients.json, a custodian or team mailbox outside the client's allowed
        email domains, a SharePoint address outside the client's allowed SharePoint hosts,
        missing, impossible or reversed dates, a keyword that cannot be searched, or no
        location to search.

        When the spec is valid, the result's Spec property holds a validated spec. That
        object is the only thing New-OrrKqlQuery (and, later, the Graph functions) accept,
        and it is refused if it is changed afterwards. Nothing in the tool acts on free text.

        This function works offline. Checking that each custodian exists in the tenant needs
        a sign-in and happens later; CustodiansResolved on the result's Spec is false until
        then.

    .PARAMETER Json
        The ORR spec as JSON text, as pasted by the technician.

    .PARAMETER InputObject
        The ORR spec as a hashtable or object with the same field names as the JSON, for a
        form that builds the spec field by field. It goes through exactly the same checks.

    .PARAMETER ClientConfig
        The table of clients returned by Import-OrrClientConfig.

    .EXAMPLE
        $clients = Import-OrrClientConfig -Path .\config\clients.json
        $result = Test-OrrSpec -Json (Get-Clipboard -Raw) -ClientConfig $clients
        if (-not $result.IsValid) { $result.Errors }

    .EXAMPLE
        Test-OrrSpec -InputObject @{ specVersion = '1'; ticketNumber = 123456; client = 'contoso-city'
            requester = 'J. Doe'; requestSummary = 'Road repair emails'; custodians = @('clerk@contoso.gov')
            dateStart = '2024-01-01'; dateEnd = '2024-03-31'; keywords = @('road repair')
            locations = @('exchange'); action = 'search' } -ClientConfig $clients

    .OUTPUTS
        ORR.SpecValidationResult with IsValid, Errors, Warnings and Spec (an ORR.ValidatedSpec,
        or $null when the spec is not valid).

    .NOTES
        The published contract is schemas/orr-spec.v1.schema.json. Windows PowerShell 5.1 has
        no Test-Json, so the checks are implemented here and tests/Spec.Tests.ps1 confirms
        under PowerShell 7 that this function and the schema agree.

        REFERENCES
        A custodian is added to a search by SMTP address and brings the mailbox and OneDrive
        together; a site is added by URL:
        https://learn.microsoft.com/graph/api/security-ediscoverysearch-post-additionalsources?view=graph-rest-1.0
        Teams chats are stored in user mailboxes and channel messages in the team's group
        mailbox: https://learn.microsoft.com/purview/edisc-search-teams
    #>
    [CmdletBinding(DefaultParameterSetName = 'Json')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Json')]
        [AllowEmptyString()]
        [string]$Json,

        [Parameter(Mandatory, ParameterSetName = 'Object')]
        [ValidateNotNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [hashtable]$ClientConfig
    )

    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]

    $invalid = {
        param($errorList, $warningList)
        [PSCustomObject]@{
            PSTypeName = 'ORR.SpecValidationResult'
            IsValid    = $false
            Errors     = @($errorList)
            Warnings   = @($warningList)
            Spec       = $null
        }
    }

    # ---- Read the spec into a name -> value table -------------------------------------
    $source = $InputObject
    if ($PSCmdlet.ParameterSetName -eq 'Json') {
        if ([string]::IsNullOrWhiteSpace($Json)) {
            $errors.Add('The spec is empty. Paste the ORR spec JSON.')
            return (& $invalid $errors $warnings)
        }
        try {
            $source = (ConvertFrom-OrrStrictJson -Text $Json)['Value']
        } catch {
            $errors.Add("The spec is not valid JSON: $($_.Exception.Message)")
            return (& $invalid $errors $warnings)
        }
    }
    $bag = ConvertTo-OrrPropertyBag -InputObject $source
    if ($null -eq $bag) {
        $errors.Add('The spec must be a single JSON object in curly braces { }.')
        return (& $invalid $errors $warnings)
    }

    # ---- Unknown and missing fields ---------------------------------------------------
    $allowedNames = $script:OrrSpecRequired + $script:OrrSpecOptional
    foreach ($name in (Get-OrrSortedKeys $bag)) {
        if ($allowedNames -cnotcontains $name) {
            $errors.Add("${name}: unknown field. Field names are case-sensitive; allowed fields are $($allowedNames -join ', ').")
        }
    }
    foreach ($name in $script:OrrSpecRequired) {
        if (-not $bag.ContainsKey($name)) { $errors.Add("${name}: required field is missing.") }
    }

    # ---- specVersion, ticketNumber, action --------------------------------------------
    if ($bag.ContainsKey('specVersion')) {
        if ($bag['specVersion'] -isnot [string] -or $bag['specVersion'] -cne $script:OrrSpecVersion) {
            $errors.Add('specVersion: must be the text "1". This tool only understands version 1 specs.')
        }
    }

    $ticketNumber = $null
    if ($bag.ContainsKey('ticketNumber')) {
        $value = $bag['ticketNumber']
        if ((Test-OrrIsInteger $value) -and $value -ge 1 -and $value -le 999999999999) {
            $ticketNumber = [long]$value
        } else {
            $errors.Add('ticketNumber: must be a whole number with no quotes, for example 123456.')
        }
    }

    $action = $null
    if ($bag.ContainsKey('action')) {
        if ($bag['action'] -is [string] -and $script:OrrActions -ccontains $bag['action']) {
            $action = $bag['action']
        } else {
            $errors.Add('action: must be "search" or "export".')
        }
    }

    # ---- requester, requestSummary ----------------------------------------------------
    $requester = $null
    if ($bag.ContainsKey('requester')) {
        $value = $bag['requester']
        if ($value -is [string] -and -not [string]::IsNullOrWhiteSpace($value) -and $value.Length -le 200) {
            $requester = $value.Trim()
        } else {
            $errors.Add('requester: must be the name of the person or organisation making the request (1 to 200 characters).')
        }
    }
    $requestSummary = $null
    if ($bag.ContainsKey('requestSummary')) {
        $value = $bag['requestSummary']
        if ($value -is [string] -and -not [string]::IsNullOrWhiteSpace($value) -and $value.Length -le 2000) {
            $requestSummary = $value.Trim()
        } else {
            $errors.Add('requestSummary: must describe what was requested (1 to 2000 characters).')
        }
    }

    # ---- client -----------------------------------------------------------------------
    $client = $null
    if ($bag.ContainsKey('client')) {
        $value = $bag['client']
        if ($value -isnot [string] -or $value -cnotmatch $script:OrrClientKeyPattern -or $value -match '[\r\n]') {
            $errors.Add('client: must be a client key from clients.json.')
        } else {
            # Find the client by exact, case-sensitive key whatever kind of table was passed.
            foreach ($key in @($ClientConfig.get_Keys())) {
                if ([string]$key -ceq $value) { $client = $ClientConfig[$key] }
            }
            if ($null -eq $client) {
                $known = (Get-OrrSortedKeys $ClientConfig) -join ', '
                $errors.Add("client: '$value' is not in clients.json. Known clients: $known.")
            } elseif ($client -isnot [System.Management.Automation.PSCustomObject] -or $client.PSObject.TypeNames -notcontains 'ORR.ClientConfig') {
                throw 'ClientConfig must be the table returned by Import-OrrClientConfig.'
            }
        }
    }

    # ---- dates ------------------------------------------------------------------------
    $dates = @{}
    foreach ($name in @('dateStart', 'dateEnd')) {
        if (-not $bag.ContainsKey($name)) { continue }
        $value = $bag[$name]
        $parsedDate = [datetime]::MinValue
        if ($value -is [string] -and $value -match $script:OrrDatePattern -and
            [datetime]::TryParseExact($value, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::None, [ref]$parsedDate)) {
            if ($parsedDate.Year -lt 1990) {
                $errors.Add("${name}: '$value' is before 1990. Check the year.")
            } elseif ($parsedDate.Year -gt 2100) {
                $errors.Add("${name}: '$value' is after 2100. Check the year.")
            } else {
                $dates[$name] = $parsedDate
            }
        } else {
            $errors.Add("${name}: must be a real calendar date written as YYYY-MM-DD, for example 2024-03-31.")
        }
    }
    if ($dates.ContainsKey('dateStart') -and $dates.ContainsKey('dateEnd')) {
        if ($dates['dateEnd'] -lt $dates['dateStart']) {
            $errors.Add('dateEnd: is earlier than dateStart. Swap the dates.')
        } elseif ($dates['dateEnd'] -gt [datetime]::Today) {
            $warnings.Add('dateEnd is in the future. The search only finds items that exist when it runs.')
        }
    }

    # ---- locations --------------------------------------------------------------------
    $locations = @()
    if ($bag.ContainsKey('locations')) {
        $list = Get-OrrStringList -Value $bag['locations'] -Field 'locations' -MaxItems 4 -MaxLength 20 -Errors $errors -Exact
        foreach ($location in $list.Items) {
            if ($script:OrrLocations -cnotcontains $location) {
                $errors.Add("locations: '$location' is not one of $($script:OrrLocations -join ', ').")
            } elseif ($locations -ccontains $location) {
                $errors.Add("locations: '$location' is listed twice.")
            } else {
                $locations += $location
            }
        }
        if ($list.IsList -and $bag['locations'].Count -eq 0) {
            $errors.Add('locations: list at least one of exchange, onedrive, sharepoint, teams.')
        }
    }

    # ---- custodians and team mailboxes (email addresses) ------------------------------
    $addressFields = @{}
    foreach ($field in @('custodians', 'teamMailboxes')) {
        $addresses = @()
        if ($bag.ContainsKey($field) -and -not ($field -eq 'teamMailboxes' -and $null -eq $bag[$field])) {
            $list = Get-OrrStringList -Value $bag[$field] -Field $field -MaxItems 100 -MaxLength 320 -Errors $errors -Exact
            $index = 0
            foreach ($address in $list.Items) {
                # The pattern is checked case-sensitively against the address as written, so
                # only plain ASCII gets through; it is lower-cased afterwards.
                $lower = $address.ToLowerInvariant()
                if ($address -cnotmatch $script:OrrEmailPattern -or $address[0] -eq '.') {
                    $errors.Add("${field}[$index]: '$address' is not an email address such as clerk@contoso.gov.")
                } elseif (Test-OrrInList -List $addresses -Value $lower) {
                    $errors.Add("${field}[$index]: '$address' is listed twice.")
                } else {
                    if ($null -ne $client -and -not (Test-OrrInList -List $client.AllowedDomains -Value (Get-OrrEmailDomain $lower))) {
                        $errors.Add("${field}[$index]: '$address' is outside the email domains allowed for $($client.DisplayName) ($($client.AllowedDomains -join ', ')).")
                    }
                    $addresses += $lower
                }
                $index++
            }
        }
        $addressFields[$field] = $addresses
    }
    $custodians = @($addressFields['custodians'])
    $teamMailboxes = @($addressFields['teamMailboxes'])
    foreach ($address in $teamMailboxes) {
        if ($custodians -contains $address) { $errors.Add("teamMailboxes: '$address' is also listed in custodians. List each address once.") }
    }

    # ---- sites ------------------------------------------------------------------------
    $sites = @()
    if ($bag.ContainsKey('sites') -and $null -ne $bag['sites']) {
        $list = Get-OrrStringList -Value $bag['sites'] -Field 'sites' -MaxItems 100 -MaxLength 400 -Errors $errors -Exact
        $index = 0
        foreach ($site in $list.Items) {
            $uri = $null
            if ($site -cnotmatch $script:OrrSiteUrlPattern -or -not [uri]::TryCreate($site, [System.UriKind]::Absolute, [ref]$uri)) {
                $errors.Add("sites[$index]: '$site' must be a SharePoint or OneDrive address such as https://contoso.sharepoint.com/sites/PublicWorks, with no ? or # part.")
            } else {
                $normalized = $site.TrimEnd('/')
                $hostName = $uri.Host.ToLowerInvariant()
                if (Test-OrrInList -List $sites -Value $normalized) {
                    $errors.Add("sites[$index]: '$site' is listed twice.")
                } elseif ($null -ne $client -and -not (Test-OrrInList -List $client.AllowedSharePointHosts -Value $hostName)) {
                    if (@($client.AllowedSharePointHosts).Count -eq 0) {
                        $errors.Add("sites[$index]: $($client.DisplayName) has no AllowedSharePointHosts in clients.json, so site addresses cannot be searched. Add the client's SharePoint host names there first.")
                    } else {
                        $errors.Add("sites[$index]: '$hostName' is outside the SharePoint hosts allowed for $($client.DisplayName) ($($client.AllowedSharePointHosts -join ', ')).")
                    }
                    $sites += $normalized
                } else {
                    $sites += $normalized
                }
            }
            $index++
        }
    }

    # ---- keywords and kqlOverride -----------------------------------------------------
    $keywords = @()
    $keywordsOk = $false
    if ($bag.ContainsKey('keywords')) {
        $before = $errors.Count
        $list = Get-OrrStringList -Value $bag['keywords'] -Field 'keywords' -MaxItems 100 -MaxLength 256 -Errors $errors
        $keywords = @($list.Items)
        $keywordsOk = ($errors.Count -eq $before)
    }
    $kqlOverride = $null
    $overrideOk = $true
    if ($bag.ContainsKey('kqlOverride') -and $null -ne $bag['kqlOverride']) {
        if ($bag['kqlOverride'] -is [string] -and -not [string]::IsNullOrWhiteSpace($bag['kqlOverride'])) {
            $kqlOverride = $bag['kqlOverride']
        } else {
            $overrideOk = $false
            $errors.Add('kqlOverride: must be a KQL query, or null to build the query from keywords and dates.')
        }
    }

    # ---- Rules that tie fields together -----------------------------------------------
    if ($bag.ContainsKey('custodians') -and $bag.ContainsKey('locations') -and
        ($custodians.Count + $sites.Count + $teamMailboxes.Count) -eq 0 -and $errors.Count -eq 0) {
        $errors.Add('custodians: nothing to search. List at least one custodian, site or team mailbox.')
    }
    if ($locations -ccontains 'sharepoint' -and $sites.Count -eq 0) {
        $errors.Add('sites: locations includes sharepoint, so list the site addresses to search in "sites". A SharePoint site can only be searched by its address.')
    }
    if ($sites.Count -gt 0 -and $locations -cnotcontains 'sharepoint' -and $locations -cnotcontains 'onedrive') {
        $errors.Add('sites: site addresses are listed, but locations has neither sharepoint nor onedrive.')
    }
    if ($teamMailboxes.Count -gt 0 -and $locations -cnotcontains 'teams' -and $locations -cnotcontains 'exchange') {
        $errors.Add('teamMailboxes: team mailboxes are listed, but locations has neither teams nor exchange.')
    }
    $custodianLocations = @('exchange', 'onedrive', 'teams')
    if ($custodians.Count -gt 0 -and $locations.Count -gt 0) {
        $requested = @($custodianLocations | Where-Object { $locations -ccontains $_ })
        if ($requested.Count -eq 0) {
            $errors.Add('custodians: custodians are listed, but locations has none of exchange, onedrive or teams. Remove the custodians or add a location.')
        } else {
            # Graph adds a person to a search as one source that covers the mailbox and the
            # OneDrive together, and Teams chats are stored in the mailbox, so a narrower
            # request cannot be honoured exactly.
            # https://learn.microsoft.com/graph/api/security-ediscoverysearch-post-additionalsources?view=graph-rest-1.0
            $unrequested = @($custodianLocations | Where-Object { $locations -cnotcontains $_ })
            if ($unrequested.Count -gt 0) {
                $warnings.Add("Each custodian is searched as one source covering their mailbox (email and Teams chats) and their OneDrive. The request did not list $($unrequested -join ' or '), but those items can still appear in the results. Check the estimate before exporting.")
            }
        }
    }
    if ($locations -ccontains 'teams' -and $teamMailboxes.Count -eq 0 -and $custodians.Count -gt 0) {
        # https://learn.microsoft.com/purview/edisc-search-teams
        $warnings.Add("Teams: only chats stored in the custodians' own mailboxes are searched. Channel messages are stored in each team's group mailbox; add the team's email address to teamMailboxes to include them. Private channel messages may not be covered.")
    }

    # ---- Build the query once so keyword problems are reported now ---------------------
    if ($keywordsOk -and $overrideOk -and $dates.ContainsKey('dateStart') -and $dates.ContainsKey('dateEnd') -and
        $dates['dateEnd'] -ge $dates['dateStart']) {
        $padding = 1
        if ($null -ne $client) { $padding = $client.DatePaddingDays }
        $build = Get-OrrKqlBuild -Keywords $keywords -KqlOverride $kqlOverride -DateStart $dates['dateStart'] -DateEnd $dates['dateEnd'] -DatePaddingDays $padding
        foreach ($item in $build.Errors) {
            if ($build.Source -eq 'Override') { $errors.Add("kqlOverride: $item") } else { $errors.Add($item) }
        }
        foreach ($item in $build.Warnings) { $warnings.Add($item) }
    }

    if ($errors.Count -gt 0) {
        Write-Verbose "Spec rejected with $($errors.Count) error(s)."
        return (& $invalid $errors $warnings)
    }

    $spec = [PSCustomObject]@{
        PSTypeName         = 'ORR.ValidatedSpec'
        SpecVersion        = $script:OrrSpecVersion
        TicketNumber       = $ticketNumber
        Client             = $client.Key
        ClientStamp        = Get-OrrClientStamp -Client $client
        Requester          = $requester
        RequestSummary     = $requestSummary
        Custodians         = [string[]]$custodians
        DateStart          = $dates['dateStart']
        DateEnd            = $dates['dateEnd']
        Keywords           = [string[]]$keywords
        KqlOverride        = $kqlOverride
        Locations          = [string[]]$locations
        Sites              = [string[]]$sites
        TeamMailboxes      = [string[]]$teamMailboxes
        Action             = $action
        ValidationId       = [guid]::NewGuid().ToString()
        CustodiansResolved = $false
    }
    $script:OrrValidatedSpecs[$spec.ValidationId] = Get-OrrSpecFingerprint -Spec $spec
    Write-Verbose "Spec for ticket $ticketNumber ($($client.Key)) is valid with $($warnings.Count) warning(s)."

    return [PSCustomObject]@{
        PSTypeName = 'ORR.SpecValidationResult'
        IsValid    = $true
        Errors     = @()
        Warnings   = @($warnings)
        Spec       = $spec
    }
}

function New-OrrKqlQuery {
    <#
    .SYNOPSIS
        Builds the KQL query for a validated ORR spec.

    .DESCRIPTION
        Returns the query that will be sent to eDiscovery, together with the plain-English
        notes a technician needs to read before running it.

        Without a kqlOverride the query has the shape
            (keyword OR "a phrase" OR prefix*) AND (date>=START AND date<DAY-AFTER-END)
        Keywords are joined with OR. Anything that is not a single plain word is sent as a
        quoted phrase, so spaces, punctuation and words like "and" cannot change the logic.
        The end date is included by searching up to the following day. All dates are UTC, and
        the range is widened by the client's DatePaddingDays on each side.

        With a kqlOverride, that text is the query, with every run of whitespace (spaces,
        tabs, line breaks, including inside quoted phrases) reduced to one space. The spec's
        dates are not added to it.

        The query does not name the custodians. People, sites and team mailboxes are attached
        to the search as data sources, which is the documented way to scope a search.

        To change the query after previewing it, put the edited text in the spec's
        kqlOverride and validate the spec again; this function only accepts a spec that came
        from Test-OrrSpec unchanged.

    .PARAMETER Spec
        The Spec property of a successful Test-OrrSpec result.

    .PARAMETER ClientConfig
        The table of clients returned by Import-OrrClientConfig.

    .EXAMPLE
        $result = Test-OrrSpec -Json $json -ClientConfig $clients
        $query = New-OrrKqlQuery -Spec $result.Spec -ClientConfig $clients
        $query.Kql
        $query.Notes

    .OUTPUTS
        ORR.KqlQuery with Kql, Source (Generated or Override), DateProperty,
        DateStartInclusive, DateEndExclusive, DatePaddingDays, KeywordCount, OperatorCount,
        Length, Warnings and Notes.

    .NOTES
        Not yet confirmed on a live tenant (the documentation is silent or contradicts
        itself): that a date-only value means 00:00 UTC, and how the 'date' condition treats
        each item type. Compare the first real estimate with a manual portal search.

        REFERENCES
        https://learn.microsoft.com/purview/edisc-search-query
        https://learn.microsoft.com/purview/edisc-condition-builder
        https://learn.microsoft.com/purview/edisc-ref-document-metadata-fields
        https://learn.microsoft.com/graph/api/resources/security-ediscoverysearch?view=graph-rest-1.0
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [object]$Spec,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [hashtable]$ClientConfig
    )

    Assert-OrrValidatedSpec -Spec $Spec

    $client = $null
    foreach ($key in @($ClientConfig.get_Keys())) {
        if ([string]$key -ceq $Spec.Client) { $client = $ClientConfig[$key] }
    }
    if ($null -eq $client) { throw "Client '$($Spec.Client)' is not in the client configuration that was passed." }
    if ($client -isnot [System.Management.Automation.PSCustomObject] -or $client.PSObject.TypeNames -notcontains 'ORR.ClientConfig') {
        throw 'ClientConfig must be the table returned by Import-OrrClientConfig.'
    }
    if ((Get-OrrClientStamp -Client $client) -cne $Spec.ClientStamp) {
        throw 'The client configuration changed since this spec was validated. Run Test-OrrSpec again.'
    }

    $build = Get-OrrKqlBuild -Keywords $Spec.Keywords -KqlOverride $Spec.KqlOverride -DateStart $Spec.DateStart -DateEnd $Spec.DateEnd -DatePaddingDays $client.DatePaddingDays
    if (@($build.Errors).Count -gt 0) {
        throw ("The query could not be built:`n - " + ($build.Errors -join "`n - "))
    }
    Write-Verbose "Built $($build.Source.ToLowerInvariant()) query for ticket $($Spec.TicketNumber): $($build.Kql)"

    return [PSCustomObject]@{
        PSTypeName         = 'ORR.KqlQuery'
        Kql                = $build.Kql
        Source             = $build.Source
        DateProperty       = $build.DateProperty
        DateStartInclusive = $build.DateStartInclusive
        DateEndExclusive   = $build.DateEndExclusive
        DatePaddingDays    = $build.DatePaddingDays
        KeywordCount       = $build.KeywordCount
        OperatorCount      = $build.OperatorCount
        Length             = $build.Length
        Warnings           = @($build.Warnings)
        Notes              = @($build.Notes)
    }
}

Export-ModuleMember -Function Import-OrrClientConfig, Test-OrrSpec, Test-OrrKql, New-OrrKqlQuery
