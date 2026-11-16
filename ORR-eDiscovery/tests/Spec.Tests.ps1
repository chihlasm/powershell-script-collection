<#
    Test-OrrSpec: what an ORR spec must look like before the tool will act on it, and the
    guard that stops anything acting on a spec that was not validated.

    Run with Pester 5 under PowerShell 7:
        pwsh -File ..\Tests\Invoke-AllTests.ps1 -Path .\ORR-eDiscovery\tests
#>

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:OrrModulePath -Force
    $script:Clients = Import-OrrTestClientConfig

    function Test-Spec {
        param([hashtable]$Set = @{}, [string[]]$Remove = @())
        $json = ConvertTo-OrrTestJson (New-OrrTestSpec -Set $Set -Remove $Remove)
        return (Test-OrrSpec -Json $json -ClientConfig $script:Clients)
    }
}

AfterAll {
    Remove-Module ORR.Core -ErrorAction SilentlyContinue
}

Describe 'Test-OrrSpec accepts a well-formed spec' {

    It 'returns a validated spec with normalised values' {
        $result = Test-Spec
        $result.Errors | Should -BeNullOrEmpty
        $result.IsValid | Should -BeTrue
        $result.Spec.PSObject.TypeNames | Should -Contain 'ORR.ValidatedSpec'
        $result.Spec.TicketNumber | Should -Be 123456
        $result.Spec.Client | Should -BeExactly 'contoso-city'
        $result.Spec.Custodians | Should -Be @('clerk@contoso.gov', 'engineer@contoso.gov')
        $result.Spec.DateStart | Should -Be ([datetime]'2024-01-01')
        $result.Spec.DateEnd | Should -Be ([datetime]'2024-03-31')
        $result.Spec.Action | Should -BeExactly 'search'
        $result.Spec.CustodiansResolved | Should -BeFalse
    }

    It 'keeps a single custodian as a list' {
        $result = Test-Spec -Set @{ custodians = @('clerk@contoso.gov') }
        $result.IsValid | Should -BeTrue
        @($result.Spec.Custodians).Count | Should -Be 1
        , $result.Spec.Custodians | Should -BeOfType [string[]]
    }

    It 'accepts a spec with no kqlOverride field at all' {
        (Test-Spec -Remove 'kqlOverride').IsValid | Should -BeTrue
    }

    It 'accepts the same day as start and end' {
        (Test-Spec -Set @{ dateStart = '2024-03-31'; dateEnd = '2024-03-31' }).IsValid | Should -BeTrue
    }

    It 'accepts action export' {
        (Test-Spec -Set @{ action = 'export' }).Spec.Action | Should -BeExactly 'export'
    }

    It 'gives the same answer for a hashtable as for JSON' {
        $fromObject = Test-OrrSpec -InputObject (New-OrrTestSpec) -ClientConfig $script:Clients
        $fromObject.IsValid | Should -BeTrue
        $fromObject.Spec.Custodians | Should -Be @('clerk@contoso.gov', 'engineer@contoso.gov')

        $bad = Test-OrrSpec -InputObject (New-OrrTestSpec -Set @{ custodians = @('x@evil.example') }) -ClientConfig $script:Clients
        $bad.IsValid | Should -BeFalse
    }
}

Describe 'Test-OrrSpec rejects input that is not a spec object' {

    It 'rejects <Name>' -ForEach @(
        @{ Name = 'an empty string'; Json = '' }
        @{ Name = 'text that is not JSON'; Json = 'search for budget emails please' }
        @{ Name = 'a JSON list'; Json = '[{"specVersion":"1"}]' }
        @{ Name = 'a JSON string'; Json = '"budget"' }
        @{ Name = 'JSON null'; Json = 'null' }
    ) {
        $result = Test-OrrSpec -Json $Json -ClientConfig $script:Clients
        $result.IsValid | Should -BeFalse
        $result.Spec | Should -BeNullOrEmpty
        @($result.Errors).Count | Should -BeGreaterThan 0
    }

    It 'rejects a complete, valid spec wrapped in a list' {
        $result = Test-OrrSpec -Json ('[' + (ConvertTo-OrrTestJson (New-OrrTestSpec)) + ']') -ClientConfig $script:Clients
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match 'single JSON object'
    }
}

Describe 'Test-OrrSpec reads strict JSON only, the same on every PowerShell' {

    BeforeAll {
        $script:Good = ConvertTo-OrrTestJson (New-OrrTestSpec)
    }

    It 'rejects a field that appears twice, instead of quietly keeping the last one' {
        $json = $script:Good -replace '"action":\s*"search"', '"action": "search", "action": "export"'
        $result = Test-OrrSpec -Json $json -ClientConfig $script:Clients
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match "the name 'action' appears twice"
    }

    It 'rejects a second custodians list' {
        $json = $script:Good.TrimEnd().TrimEnd('}') + ', "custodians": ["clerk@contoso.gov"] }'
        (Test-OrrSpec -Json $json -ClientConfig $script:Clients).IsValid | Should -BeFalse
    }

    It 'rejects <Name>' -ForEach @(
        @{ Name = 'a ticket number with a leading zero (octal on PowerShell 7)'; Find = '123456'; Replace = '0123456' }
        @{ Name = 'a hex ticket number'; Find = '123456'; Replace = '0x1F' }
        @{ Name = 'a ticket number with a plus sign'; Find = '123456'; Replace = '+5' }
        @{ Name = 'a trailing comma'; Find = '"search"'; Replace = '"search",' }
        @{ Name = 'a comment'; Find = '"action"'; Replace = '/* note */ "action"' }
        @{ Name = 'single-quoted text'; Find = '"search"'; Replace = "'search'" }
    ) {
        $json = $script:Good.Replace($Find, $Replace)
        $json | Should -Not -BeExactly $script:Good
        $result = Test-OrrSpec -Json $json -ClientConfig $script:Clients
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match 'not valid JSON'
    }

    It 'keeps text that looks like a timestamp as text' {
        $result = Test-Spec -Set @{ keywords = @('2024-03-15T10:30:00Z'); requester = '2024-01-01T00:00:00' }
        $result.Errors | Should -BeNullOrEmpty
        $result.Spec.Keywords | Should -Be @('2024-03-15T10:30:00Z')
        $result.Spec.Requester | Should -BeExactly '2024-01-01T00:00:00'
    }

    It 'rejects an unknown field even when a field named <Name> is present' -ForEach @(
        @{ Name = 'Keys' }, @{ Name = 'Count' }, @{ Name = 'Values' }
    ) {
        $result = Test-Spec -Set @{ $Name = @('client'); teammailboxes = @('council@contoso.gov') }
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match "${Name}: unknown field"
        ($result.Errors -join "`n") | Should -Match 'teammailboxes: unknown field'
    }

    It 'reads JSON escapes in text' {
        $json = $script:Good.Replace('Jordan Doe, Contoso Gazette', 'Jordan \"JD\" Doe A')
        (Test-OrrSpec -Json $json -ClientConfig $script:Clients).Spec.Requester | Should -BeExactly 'Jordan "JD" Doe A'
    }
}

Describe 'Test-OrrSpec rejects unknown and missing fields' {

    It 'rejects a missing <Field>' -ForEach @(
        @{ Field = 'specVersion' }, @{ Field = 'ticketNumber' }, @{ Field = 'client' },
        @{ Field = 'requester' }, @{ Field = 'requestSummary' }, @{ Field = 'custodians' },
        @{ Field = 'dateStart' }, @{ Field = 'dateEnd' }, @{ Field = 'keywords' },
        @{ Field = 'locations' }, @{ Field = 'action' }
    ) {
        $result = Test-Spec -Remove $Field
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match "(?m)^${Field}: required field is missing"
    }

    It 'rejects an unknown field' {
        $result = Test-Spec -Set @{ purge = $true }
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match 'purge: unknown field'
    }

    It 'treats field names as case-sensitive' {
        $spec = New-OrrTestSpec -Remove 'client'
        $spec['Client'] = 'contoso-city'
        $result = Test-OrrSpec -Json (ConvertTo-OrrTestJson $spec) -ClientConfig $script:Clients
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match 'Client: unknown field'
        ($result.Errors -join "`n") | Should -Match 'client: required field is missing'
    }

    It 'reports every problem in one pass' {
        $result = Test-Spec -Set @{ ticketNumber = 'abc'; dateStart = '01/02/2024'; action = 'delete'; custodians = @('x@evil.example') }
        @($result.Errors).Count | Should -BeGreaterOrEqual 4
    }
}

Describe 'Test-OrrSpec checks simple fields' {

    It 'rejects specVersion <Value>' -ForEach @(
        @{ Value = '2' }, @{ Value = 1 }, @{ Value = '' }
    ) {
        (Test-Spec -Set @{ specVersion = $Value }).IsValid | Should -BeFalse
    }

    It 'rejects ticketNumber <Value>' -ForEach @(
        @{ Value = '123456' }, @{ Value = 0 }, @{ Value = -5 }, @{ Value = 12.5 }, @{ Value = $true }, @{ Value = $null }
    ) {
        $result = Test-Spec -Set @{ ticketNumber = $Value }
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match 'ticketNumber:'
    }

    It 'rejects action <Value>' -ForEach @(
        @{ Value = 'purge' }, @{ Value = 'delete' }, @{ Value = 'Search' }, @{ Value = '' }, @{ Value = $null }
    ) {
        (Test-Spec -Set @{ action = $Value }).IsValid | Should -BeFalse
    }

    It 'rejects a blank <Field>' -ForEach @(
        @{ Field = 'requester' }, @{ Field = 'requestSummary' }
    ) {
        (Test-Spec -Set @{ $Field = '   ' }).IsValid | Should -BeFalse
    }

    It 'rejects a client that is not in clients.json' {
        $result = Test-Spec -Set @{ client = 'unknown-town' }
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match "client: 'unknown-town' is not in clients.json"
    }

    It 'matches the client key case-sensitively' {
        (Test-Spec -Set @{ client = 'Contoso-City' }).IsValid | Should -BeFalse
    }
}

Describe 'Test-OrrSpec checks dates' {

    It 'rejects <Field> = <Value>' -ForEach @(
        @{ Field = 'dateStart'; Value = '01/02/2024' }
        @{ Field = 'dateStart'; Value = '2024-1-2' }
        @{ Field = 'dateEnd'; Value = '2024-02-30' }
        @{ Field = 'dateEnd'; Value = '2024-13-01' }
        @{ Field = 'dateEnd'; Value = '2024-03-31T23:59:59Z' }
        @{ Field = 'dateStart'; Value = '' }
        @{ Field = 'dateStart'; Value = $null }
        @{ Field = 'dateStart'; Value = 20240101 }
        @{ Field = 'dateStart'; Value = '0024-01-01' }
    ) {
        $result = Test-Spec -Set @{ $Field = $Value }
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match "${Field}:"
    }

    It 'rejects an end date before the start date' {
        $result = Test-Spec -Set @{ dateStart = '2024-03-31'; dateEnd = '2024-01-01' }
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match 'dateEnd: is earlier than dateStart'
    }

    It 'returns an error, not an exception, for a year-9999 "no end date"' {
        $result = Test-Spec -Set @{ dateEnd = '9999-12-31' }
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match 'dateEnd: .*after 2100'
    }

    It 'accepts 29 February in a leap year and rejects it otherwise' {
        (Test-Spec -Set @{ dateStart = '2024-02-29'; dateEnd = '2024-02-29' }).IsValid | Should -BeTrue
        (Test-Spec -Set @{ dateStart = '2023-02-29'; dateEnd = '2023-03-01' }).IsValid | Should -BeFalse
    }

    It 'warns, but does not fail, when the end date is in the future' {
        $future = (Get-Date).AddYears(1).ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
        $result = Test-Spec -Set @{ dateEnd = $future }
        $result.IsValid | Should -BeTrue
        ($result.Warnings -join "`n") | Should -Match 'dateEnd is in the future'
    }
}

Describe 'Test-OrrSpec checks custodians against the client' {

    It 'rejects a custodian outside the allowed domains' {
        $result = Test-Spec -Set @{ custodians = @('clerk@contoso.gov', 'someone@fabrikam.example') }
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match "custodians\[1\]: 'someone@fabrikam.example' is outside the email domains allowed for City of Contoso"
    }

    It 'does not treat a subdomain or a look-alike as allowed: <Address>' -ForEach @(
        @{ Address = 'clerk@mail.contoso.gov' }
        @{ Address = 'clerk@contoso.gov.evil.example' }
        @{ Address = 'clerk@notcontoso.gov' }
        @{ Address = 'clerk@contoso.gov@evil.example' }
    ) {
        (Test-Spec -Set @{ custodians = @($Address) }).IsValid | Should -BeFalse
    }

    It 'accepts every domain in the allow list, in any letter case' {
        (Test-Spec -Set @{ custodians = @('Chief@ContosoPD.GOV') }).Spec.Custodians | Should -Be @('chief@contosopd.gov')
    }

    It 'rejects <Name>' -ForEach @(
        @{ Name = 'a name instead of an address'; Value = @('Jordan Doe') }
        @{ Name = 'an address with a space'; Value = @('jordan doe@contoso.gov') }
        @{ Name = 'a display-name form'; Value = @('Jordan <jordan@contoso.gov>') }
        @{ Name = 'two addresses in one entry'; Value = @('a@contoso.gov;b@contoso.gov') }
        @{ Name = 'a leading dot (inactive-mailbox form)'; Value = @('.clerk@contoso.gov') }
        @{ Name = 'the same person twice'; Value = @('clerk@contoso.gov', 'CLERK@contoso.gov') }
        @{ Name = 'an address with a space around it'; Value = @(' clerk@contoso.gov ') }
        @{ Name = 'a wildcard address'; Value = @('*@contoso.gov') }
        @{ Name = 'an address with URL characters'; Value = @('x/../groups?a#b@contoso.gov') }
        @{ Name = 'a look-alike letter in the domain (Kelvin sign)'; Value = @('clerk@' + [char]0x212A + 'ontoso.gov') }
        @{ Name = 'a look-alike letter in the name'; Value = @([char]0x0441 + 'lerk@contoso.gov') }
        @{ Name = 'a number in the list'; Value = @(42) }
        @{ Name = 'a bare string instead of a list'; Value = 'clerk@contoso.gov' }
        @{ Name = 'null'; Value = $null }
    ) {
        $result = Test-Spec -Set @{ custodians = $Value }
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match 'custodians'
    }

    It 'rejects a spec with nothing to search' {
        $result = Test-Spec -Set @{ custodians = @() }
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match 'nothing to search'
    }

    It 'rejects a team mailbox outside the allowed domains' {
        (Test-Spec -Set @{ teamMailboxes = @('publicworks@fabrikam.example') }).IsValid | Should -BeFalse
    }

    It 'rejects an address listed as both custodian and team mailbox' {
        (Test-Spec -Set @{ teamMailboxes = @('clerk@contoso.gov') }).IsValid | Should -BeFalse
    }
}

Describe 'Test-OrrSpec checks locations, sites and team mailboxes' {

    It 'rejects locations <Name>' -ForEach @(
        @{ Name = 'empty'; Value = @() }
        @{ Name = 'with an unknown value'; Value = @('exchange', 'dropbox') }
        @{ Name = 'with a repeated value'; Value = @('exchange', 'exchange') }
        @{ Name = 'in the wrong case'; Value = @('Exchange') }
        @{ Name = 'as a string'; Value = 'exchange' }
    ) {
        (Test-Spec -Set @{ locations = $Value }).IsValid | Should -BeFalse
    }

    It 'requires site addresses when sharepoint is requested' {
        $result = Test-Spec -Set @{ locations = @('exchange', 'sharepoint') }
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match 'sites: locations includes sharepoint'
    }

    It 'accepts a site on an allowed host' {
        $result = Test-Spec -Set @{ locations = @('exchange', 'onedrive', 'teams', 'sharepoint'); sites = @('https://contoso.sharepoint.com/sites/PublicWorks/') }
        $result.Errors | Should -BeNullOrEmpty
        $result.Spec.Sites | Should -Be @('https://contoso.sharepoint.com/sites/PublicWorks')
    }

    It 'accepts a site-only request with no custodians' {
        $result = Test-Spec -Set @{ custodians = @(); locations = @('sharepoint'); sites = @('https://contoso.sharepoint.com/sites/Clerk') }
        $result.Errors | Should -BeNullOrEmpty
        $result.IsValid | Should -BeTrue
    }

    It 'rejects site <Site>' -ForEach @(
        @{ Site = 'https://fabrikam.sharepoint.com/sites/PublicWorks' }
        @{ Site = 'http://contoso.sharepoint.com/sites/PublicWorks' }
        @{ Site = 'https://contoso.sharepoint.com.evil.example/sites/x' }
        @{ Site = 'https://evil.example/contoso.sharepoint.com' }
        @{ Site = 'https://contoso.sharepoint.com/sites/x?web=1' }
        @{ Site = 'https://contoso.sharepoint.com/sites/x#frag' }
        @{ Site = 'https://user@contoso.sharepoint.com/sites/x' }
        @{ Site = 'contoso.sharepoint.com/sites/x' }
        @{ Site = 'HTTPS://contoso.SharePoint.COM/sites/x' }
        @{ Site = ' https://contoso.sharepoint.com/sites/x' }
    ) {
        $result = Test-Spec -Set @{ locations = @('exchange', 'sharepoint'); sites = @($Site) }
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match 'sites\[0\]'
    }

    It 'rejects any site for a client with no AllowedSharePointHosts' {
        $spec = New-OrrTestSpec -Set @{
            client = 'nopad-town'; custodians = @('clerk@nopad.example.org')
            locations = @('exchange', 'sharepoint'); sites = @('https://nopad.sharepoint.com/sites/Clerk')
        }
        $result = Test-OrrSpec -Json (ConvertTo-OrrTestJson $spec) -ClientConfig $script:Clients
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match 'has no AllowedSharePointHosts'
    }

    It 'rejects the same site listed twice, with or without a trailing slash' {
        $result = Test-Spec -Set @{ locations = @('exchange', 'sharepoint'); sites = @('https://contoso.sharepoint.com/sites/Clerk', 'https://contoso.sharepoint.com/sites/Clerk/') }
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match 'sites\[1\].*listed twice'
    }

    It 'rejects team mailboxes when neither teams nor exchange is requested' {
        $result = Test-Spec -Set @{ locations = @('onedrive'); teamMailboxes = @('publicworks@contoso.gov') }
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match 'teamMailboxes: team mailboxes are listed'
    }

    It 'rejects a location with a space around it' {
        (Test-Spec -Set @{ locations = @(' exchange') }).IsValid | Should -BeFalse
    }

    It 'rejects sites when neither sharepoint nor onedrive is requested' {
        (Test-Spec -Set @{ locations = @('exchange'); sites = @('https://contoso.sharepoint.com/sites/Clerk') }).IsValid | Should -BeFalse
    }

    It 'rejects custodians when only sharepoint is requested' {
        $result = Test-Spec -Set @{ locations = @('sharepoint'); sites = @('https://contoso.sharepoint.com/sites/Clerk') }
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match 'custodians are listed, but locations has none of'
    }

    It 'warns that a custodian search also covers locations that were not requested' {
        $result = Test-Spec -Set @{ locations = @('exchange') }
        $result.IsValid | Should -BeTrue
        ($result.Warnings -join "`n") | Should -Match 'did not list onedrive or teams'
    }

    It 'does not give that warning when exchange, onedrive and teams are all requested' {
        ((Test-Spec).Warnings -join "`n") | Should -Not -Match 'did not list'
    }

    It 'warns that Teams channel messages need the team mailbox' {
        ((Test-Spec).Warnings -join "`n") | Should -Match 'Channel messages are stored in each team'
        ((Test-Spec -Set @{ teamMailboxes = @('publicworks@contoso.gov') }).Warnings -join "`n") | Should -Not -Match 'Channel messages'
    }
}

Describe 'Test-OrrSpec checks keywords and kqlOverride' {

    It 'rejects keywords <Name>' -ForEach @(
        @{ Name = 'as a string'; Value = 'budget' }
        @{ Name = 'containing a number'; Value = @('budget', 7) }
        @{ Name = 'containing a blank entry'; Value = @('budget', '  ') }
        @{ Name = 'with a leading wildcard'; Value = @('*budget') }
        @{ Name = 'with a quote inside a word'; Value = @('5" pipe') }
        @{ Name = 'null'; Value = $null }
    ) {
        $result = Test-Spec -Set @{ keywords = $Value }
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match 'keywords'
    }

    It 'accepts an empty keyword list but warns that everything in range is returned' {
        $result = Test-Spec -Set @{ keywords = @() }
        $result.IsValid | Should -BeTrue
        ($result.Warnings -join "`n") | Should -Match 'No keywords'
    }

    It 'rejects kqlOverride <Name>' -ForEach @(
        @{ Name = 'that is blank'; Value = '   ' }
        @{ Name = 'that is a number'; Value = 5 }
        @{ Name = 'with an unclosed quote'; Value = 'subject:"budget AND date>=2024-01-01' }
        @{ Name = 'with unbalanced parentheses'; Value = '(budget AND date>=2024-01-01' }
        @{ Name = 'made only of operators'; Value = '() AND ()' }
    ) {
        $result = Test-Spec -Set @{ kqlOverride = $Value }
        $result.IsValid | Should -BeFalse
        ($result.Errors -join "`n") | Should -Match 'kqlOverride:'
    }

    It 'accepts a kqlOverride and warns when it has no date condition' {
        $result = Test-Spec -Set @{ kqlOverride = 'subject:"road repair"' }
        $result.IsValid | Should -BeTrue
        $result.Spec.KqlOverride | Should -BeExactly 'subject:"road repair"'
        ($result.Warnings -join "`n") | Should -Match 'no date condition'
        ($result.Warnings -join "`n") | Should -Match 'keywords list is not used'
    }
}

Describe 'Only a validated, unchanged spec can be acted on' {

    It 'accepts the spec that Test-OrrSpec returned' {
        $spec = (Test-Spec).Spec
        { InModuleScope ORR.Core -Parameters @{ S = $spec } { Assert-OrrValidatedSpec -Spec $S } } | Should -Not -Throw
    }

    It 'refuses a spec that was changed after validation: <Name>' -ForEach @(
        @{ Name = 'custodian added'; Change = { param($s) $s.Custodians = @($s.Custodians) + 'mayor@contoso.gov' } }
        @{ Name = 'client swapped'; Change = { param($s) $s.Client = 'nopad-town' } }
        @{ Name = 'action raised to export'; Change = { param($s) $s.Action = 'export' } }
        @{ Name = 'override injected'; Change = { param($s) $s.KqlOverride = 'budget' } }
        @{ Name = 'date widened'; Change = { param($s) $s.DateEnd = [datetime]'2030-01-01' } }
        @{ Name = 'site added'; Change = { param($s) $s.Sites = @('https://contoso.sharepoint.com/sites/HR') } }
        @{ Name = 'keywords replaced'; Change = { param($s) $s.Keywords = [string[]]@('salary') } }
        @{ Name = 'keyword appended'; Change = { param($s) $s.Keywords = [string[]](@($s.Keywords) + 'salary') } }
        @{ Name = 'phrase keyword split in two'; Change = { param($s) $s.Keywords = [string[]]@('budget', 'road', 'repair') } }
        @{ Name = 'start date moved'; Change = { param($s) $s.DateStart = [datetime]'2000-01-01' } }
        @{ Name = 'team mailbox added'; Change = { param($s) $s.TeamMailboxes = [string[]]@('hr@contoso.gov') } }
        @{ Name = 'location added'; Change = { param($s) $s.Locations = [string[]]@('exchange', 'onedrive', 'teams', 'sharepoint') } }
        @{ Name = 'ticket number changed'; Change = { param($s) $s.TicketNumber = 999 } }
        @{ Name = 'requester changed'; Change = { param($s) $s.Requester = 'Someone Else' } }
        @{ Name = 'summary changed'; Change = { param($s) $s.RequestSummary = 'Everything' } }
        @{ Name = 'version changed'; Change = { param($s) $s.SpecVersion = '2' } }
        @{ Name = 'client stamp changed'; Change = { param($s) $s.ClientStamp = 'x' } }
    ) {
        $spec = (Test-Spec).Spec
        & $Change $spec
        { InModuleScope ORR.Core -Parameters @{ S = $spec } { Assert-OrrValidatedSpec -Spec $S } } |
            Should -Throw '*changed after it was validated*'
        { New-OrrKqlQuery -Spec $spec -ClientConfig $script:Clients } | Should -Throw '*changed after it was validated*'
    }

    It 'refuses <Name>' -ForEach @(
        @{ Name = 'a hashtable'; Value = @{ Client = 'contoso-city'; Keywords = @('budget') } }
        @{ Name = 'free text'; Value = 'find all budget emails' }
        @{ Name = 'a look-alike object with the right type name'; Value = [PSCustomObject]@{ PSTypeName = 'ORR.ValidatedSpec'; ValidationId = 'not-a-real-id'; Client = 'contoso-city' } }
    ) {
        { New-OrrKqlQuery -Spec $Value -ClientConfig $script:Clients } | Should -Throw '*not a validated ORR spec*'
    }

    It 'cannot be fooled by one list item that contains a separator' {
        $one = Test-Spec -Set @{ locations = @('exchange', 'onedrive', 'teams', 'sharepoint'); sites = @('https://contoso.sharepoint.com/a,https://contoso.sharepoint.com/b') }
        $one.Errors | Should -BeNullOrEmpty
        $spec = $one.Spec
        $spec.Sites = [string[]]@('https://contoso.sharepoint.com/a', 'https://contoso.sharepoint.com/b')
        { New-OrrKqlQuery -Spec $spec -ClientConfig $script:Clients } | Should -Throw '*changed after it was validated*'
    }

    It 'refuses a spec when the client settings were changed and reloaded after validation' {
        $spec = (Test-Spec).Spec
        $changed = Import-OrrTestClientConfig -Override @{ AllowedDomains = @('contoso.gov'); DatePaddingDays = 0 } -FileName 'clients-changed.json'
        { New-OrrKqlQuery -Spec $spec -ClientConfig $changed } | Should -Throw '*client configuration changed*'
        { New-OrrKqlQuery -Spec $spec -ClientConfig $script:Clients } | Should -Not -Throw
    }

    It 'refuses a client table that did not come from Import-OrrClientConfig' {
        $handBuilt = @{ 'contoso-city' = [PSCustomObject]@{ Key = 'contoso-city'; AllowedDomains = @('evil.example') } }
        { Test-OrrSpec -Json (ConvertTo-OrrTestJson (New-OrrTestSpec)) -ClientConfig $handBuilt } | Should -Throw '*returned by Import-OrrClientConfig*'
    }

    It 'leaves CustodiansResolved out of the check on purpose (it is set after validation)' {
        $spec = (Test-Spec).Spec
        $spec.CustodiansResolved = $true
        { New-OrrKqlQuery -Spec $spec -ClientConfig $script:Clients } | Should -Not -Throw
    }

    It 'refuses a copy that reuses a real validation id with different content' {
        $real = (Test-Spec).Spec
        $forged = $real.PSObject.Copy()
        $forged.Custodians = [string[]]@('mayor@contoso.gov')
        { New-OrrKqlQuery -Spec $forged -ClientConfig $script:Clients } | Should -Throw '*changed after it was validated*'
    }
}

Describe 'Test-OrrSpec agrees with the published JSON schema' {

    BeforeDiscovery {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        $script:CanUseSchema = [bool]((Get-Command Test-Json -ErrorAction SilentlyContinue) -and
            (Get-Command Test-Json).Parameters.ContainsKey('SchemaFile'))

        # Valid: both the schema and Test-OrrSpec must accept it.
        # SchemaInvalid: the schema itself must reject it, and so must Test-OrrSpec.
        # Neither: only Test-OrrSpec can know (rules that need clients.json or two fields).
        $script:SchemaCases = @(
            @{ Name = 'baseline spec'; Valid = $true; SchemaInvalid = $false; Set = @{}; Remove = @() }
            @{ Name = 'no kqlOverride field'; Valid = $true; SchemaInvalid = $false; Set = @{}; Remove = @('kqlOverride') }
            @{ Name = 'empty keywords'; Valid = $true; SchemaInvalid = $false; Set = @{ keywords = @() }; Remove = @() }
            @{ Name = 'null sites and teamMailboxes'; Valid = $true; SchemaInvalid = $false; Set = @{ sites = $null; teamMailboxes = $null }; Remove = @() }
            @{ Name = 'sharepoint with a site'; Valid = $true; SchemaInvalid = $false; Set = @{ locations = @('exchange', 'onedrive', 'teams', 'sharepoint'); sites = @('https://contoso.sharepoint.com/sites/PublicWorks') }; Remove = @() }
            @{ Name = 'team mailbox'; Valid = $true; SchemaInvalid = $false; Set = @{ teamMailboxes = @('publicworks@contoso.gov') }; Remove = @() }
            @{ Name = 'kqlOverride set'; Valid = $true; SchemaInvalid = $false; Set = @{ kqlOverride = 'budget AND date>=2024-01-01' }; Remove = @() }
            @{ Name = 'action export'; Valid = $true; SchemaInvalid = $false; Set = @{ action = 'export' }; Remove = @() }

            @{ Name = 'unknown field'; Valid = $false; SchemaInvalid = $true; Set = @{ purge = $true }; Remove = @() }
            @{ Name = 'missing client'; Valid = $false; SchemaInvalid = $true; Set = @{}; Remove = @('client') }
            @{ Name = 'missing dateEnd'; Valid = $false; SchemaInvalid = $true; Set = @{}; Remove = @('dateEnd') }
            @{ Name = 'specVersion 2'; Valid = $false; SchemaInvalid = $true; Set = @{ specVersion = '2' }; Remove = @() }
            @{ Name = 'ticketNumber as text'; Valid = $false; SchemaInvalid = $true; Set = @{ ticketNumber = '123456' }; Remove = @() }
            @{ Name = 'ticketNumber zero'; Valid = $false; SchemaInvalid = $true; Set = @{ ticketNumber = 0 }; Remove = @() }
            @{ Name = 'date in US format'; Valid = $false; SchemaInvalid = $true; Set = @{ dateStart = '01/02/2024' }; Remove = @() }
            @{ Name = 'unknown location'; Valid = $false; SchemaInvalid = $true; Set = @{ locations = @('dropbox') }; Remove = @() }
            @{ Name = 'repeated location'; Valid = $false; SchemaInvalid = $true; Set = @{ locations = @('exchange', 'exchange') }; Remove = @() }
            @{ Name = 'empty locations'; Valid = $false; SchemaInvalid = $true; Set = @{ locations = @() }; Remove = @() }
            @{ Name = 'action purge'; Valid = $false; SchemaInvalid = $true; Set = @{ action = 'purge' }; Remove = @() }
            @{ Name = 'custodian that is not an address'; Valid = $false; SchemaInvalid = $true; Set = @{ custodians = @('Jordan Doe') }; Remove = @() }
            @{ Name = 'custodians as a string'; Valid = $false; SchemaInvalid = $true; Set = @{ custodians = 'clerk@contoso.gov' }; Remove = @() }
            @{ Name = 'blank requester'; Valid = $false; SchemaInvalid = $true; Set = @{ requester = '  ' }; Remove = @() }
            @{ Name = 'blank keyword'; Valid = $false; SchemaInvalid = $true; Set = @{ keywords = @(' ') }; Remove = @() }
            @{ Name = 'blank kqlOverride'; Valid = $false; SchemaInvalid = $true; Set = @{ kqlOverride = '  ' }; Remove = @() }
            @{ Name = 'http site'; Valid = $false; SchemaInvalid = $true; Set = @{ locations = @('exchange', 'sharepoint'); sites = @('http://contoso.sharepoint.com/sites/x') }; Remove = @() }
            @{ Name = 'site with a query string'; Valid = $false; SchemaInvalid = $true; Set = @{ locations = @('exchange', 'sharepoint'); sites = @('https://contoso.sharepoint.com/sites/x?a=1') }; Remove = @() }

            @{ Name = 'custodian with a space around it'; Valid = $false; SchemaInvalid = $true; Set = @{ custodians = @(' clerk@contoso.gov ') }; Remove = @() }
            @{ Name = 'location with a space around it'; Valid = $false; SchemaInvalid = $true; Set = @{ locations = @(' exchange') }; Remove = @() }
            @{ Name = 'site with an upper-case scheme'; Valid = $false; SchemaInvalid = $true; Set = @{ locations = @('exchange', 'sharepoint'); sites = @('HTTPS://contoso.sharepoint.com/sites/x') }; Remove = @() }
            @{ Name = 'wildcard custodian'; Valid = $false; SchemaInvalid = $true; Set = @{ custodians = @('*@contoso.gov') }; Remove = @() }
            @{ Name = '101 custodians'; Valid = $false; SchemaInvalid = $true; Set = @{ custodians = @(1..101 | ForEach-Object { "user$_@contoso.gov" }) }; Remove = @() }
            @{ Name = '100 custodians'; Valid = $true; SchemaInvalid = $false; Set = @{ custodians = @(1..100 | ForEach-Object { "user$_@contoso.gov" }) }; Remove = @() }
            @{ Name = '201-character requester'; Valid = $false; SchemaInvalid = $true; Set = @{ requester = ('x' * 201) }; Remove = @() }
            @{ Name = '200-character requester'; Valid = $true; SchemaInvalid = $false; Set = @{ requester = ('x' * 200) }; Remove = @() }
            @{ Name = '257-character keyword'; Valid = $false; SchemaInvalid = $true; Set = @{ keywords = @('x' * 257) }; Remove = @() }
            @{ Name = 'ticketNumber one past the maximum'; Valid = $false; SchemaInvalid = $true; Set = @{ ticketNumber = 1000000000000 }; Remove = @() }
            @{ Name = 'ticketNumber at the maximum'; Valid = $true; SchemaInvalid = $false; Set = @{ ticketNumber = 999999999999 }; Remove = @() }

            @{ Name = 'custodian outside allowed domains'; Valid = $false; SchemaInvalid = $false; Set = @{ custodians = @('x@fabrikam.example') }; Remove = @() }
            @{ Name = 'dates reversed'; Valid = $false; SchemaInvalid = $false; Set = @{ dateStart = '2024-03-31'; dateEnd = '2024-01-01' }; Remove = @() }
            @{ Name = 'impossible date'; Valid = $false; SchemaInvalid = $false; Set = @{ dateEnd = '2024-02-30' }; Remove = @() }
            @{ Name = 'unknown client'; Valid = $false; SchemaInvalid = $false; Set = @{ client = 'unknown-town' }; Remove = @() }
            @{ Name = 'sharepoint without sites'; Valid = $false; SchemaInvalid = $false; Set = @{ locations = @('exchange', 'sharepoint') }; Remove = @() }
        )
    }

    It 'the schema file is itself valid JSON' {
        { Get-Content -LiteralPath $script:OrrSchemaPath -Raw | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
    }

    It 'lists the same required and allowed fields as the module' {
        $schema = Get-Content -LiteralPath $script:OrrSchemaPath -Raw | ConvertFrom-Json
        $moduleFields = InModuleScope ORR.Core { [PSCustomObject]@{ Required = $script:OrrSpecRequired; Optional = $script:OrrSpecOptional } }
        @($schema.required | Sort-Object) | Should -Be @($moduleFields.Required | Sort-Object)
        @($schema.properties.PSObject.Properties.Name | Sort-Object) | Should -Be @(($moduleFields.Required + $moduleFields.Optional) | Sort-Object)
        $schema.additionalProperties | Should -BeFalse
    }

    It 'uses the same patterns as the module' {
        $schema = Get-Content -LiteralPath $script:OrrSchemaPath -Raw | ConvertFrom-Json
        $patterns = InModuleScope ORR.Core { [PSCustomObject]@{ Email = $script:OrrEmailPattern; Key = $script:OrrClientKeyPattern; Date = $script:OrrDatePattern; Site = $script:OrrSiteUrlPattern } }
        $schema.properties.custodians.items.pattern | Should -BeExactly $patterns.Email
        $schema.properties.teamMailboxes.items.pattern | Should -BeExactly $patterns.Email
        $schema.properties.client.pattern | Should -BeExactly $patterns.Key
        $schema.properties.dateStart.pattern | Should -BeExactly $patterns.Date
        $schema.properties.dateEnd.pattern | Should -BeExactly $patterns.Date
        $schema.properties.sites.items.pattern | Should -BeExactly $patterns.Site
    }

    It '<Name>' -Skip:(-not $script:CanUseSchema) -ForEach $script:SchemaCases {
        $json = ConvertTo-OrrTestJson (New-OrrTestSpec -Set $Set -Remove $Remove)
        $schemaAccepts = Test-Json -Json $json -SchemaFile $script:OrrSchemaPath -ErrorAction SilentlyContinue
        $result = Test-OrrSpec -Json $json -ClientConfig $script:Clients

        if ($Valid) {
            $schemaAccepts | Should -BeTrue -Because 'the schema must accept a valid spec'
            $result.Errors | Should -BeNullOrEmpty
            $result.IsValid | Should -BeTrue
        } else {
            $result.IsValid | Should -BeFalse -Because 'Test-OrrSpec must never be looser than the schema'
            if ($SchemaInvalid) {
                $schemaAccepts | Should -BeFalse -Because 'the schema is expected to catch this on its own'
            } else {
                $schemaAccepts | Should -BeTrue -Because 'this rule is only enforced in code, and the case should not fail for another reason'
            }
        }
    }
}
