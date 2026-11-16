<#
    Import-OrrClientConfig: the per-client configuration file (clients.json).
#>

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:OrrModulePath -Force

    function Import-FromJson {
        param([string]$Json)
        $path = Join-Path $TestDrive ("clients-{0}.json" -f [guid]::NewGuid().ToString('N'))
        [System.IO.File]::WriteAllText($path, $Json)
        return (Import-OrrClientConfig -Path $path)
    }

    function New-ConfigJson {
        # One client entry with the given changes applied.
        param([hashtable]$Set = @{}, [string[]]$Remove = @(), [string]$Key = 'contoso-city')
        $client = [ordered]@{
            TenantId       = '11111111-2222-3333-4444-555555555555'
            DisplayName    = 'City of Contoso'
            AllowedDomains = @('contoso.gov')
        }
        foreach ($name in @($Set.get_Keys())) { $client[$name] = $Set[$name] }
        foreach ($name in $Remove) { $client.Remove($name) }
        return (ConvertTo-Json -Depth 6 -InputObject ([ordered]@{ configVersion = '1'; clients = [ordered]@{ $Key = $client } }))
    }
}

AfterAll {
    Remove-Module ORR.Core -ErrorAction SilentlyContinue
}

Describe 'Import-OrrClientConfig loads a valid file' {

    It 'loads the example file that ships with the tool' {
        $clients = Import-OrrClientConfig -Path $script:OrrExampleConfigPath
        $clients | Should -BeOfType [hashtable]
        @($clients.Keys | Sort-Object) | Should -Be @('contoso-city', 'fabrikam-county')
        $clients['contoso-city'].TenantId | Should -BeExactly '11111111-2222-3333-4444-555555555555'
        $clients['contoso-city'].AllowedDomains | Should -Be @('contoso.gov', 'contosopd.gov')
        $clients['contoso-city'].PSObject.TypeNames | Should -Contain 'ORR.ClientConfig'
    }

    It 'fills in defaults for optional settings' {
        $client = (Import-FromJson (New-ConfigJson))['contoso-city']
        $client.Key | Should -BeExactly 'contoso-city'
        $client.CaseNamePrefix | Should -BeExactly 'ORR'
        $client.DefaultLocations | Should -Be @('exchange', 'onedrive')
        $client.PurviewPortalUrl | Should -BeExactly 'https://purview.microsoft.com'
        $client.SummaryTemplate | Should -BeNullOrEmpty
        @($client.AllowedSharePointHosts).Count | Should -Be 0
        $client.DatePaddingDays | Should -Be 1
        $client.Environment | Should -BeExactly 'Global'
    }

    It 'lower-cases domains and SharePoint hosts' {
        $client = (Import-FromJson (New-ConfigJson -Set @{ AllowedDomains = @('Contoso.GOV'); AllowedSharePointHosts = @('Contoso.SharePoint.com') }))['contoso-city']
        $client.AllowedDomains | Should -Be @('contoso.gov')
        $client.AllowedSharePointHosts | Should -Be @('contoso.sharepoint.com')
    }

    It 'keeps a single allowed domain as a list' {
        $client = (Import-FromJson (New-ConfigJson))['contoso-city']
        @($client.AllowedDomains).Count | Should -Be 1
    }

    It 'looks clients up by exact key' {
        $clients = Import-FromJson (New-ConfigJson)
        $clients.ContainsKey('contoso-city') | Should -BeTrue
        $clients.ContainsKey('Contoso-City') | Should -BeFalse
    }

    It 'accepts DatePaddingDays 0 and a government cloud environment' {
        $client = (Import-FromJson (New-ConfigJson -Set @{ DatePaddingDays = 0; Environment = 'USGov' }))['contoso-city']
        $client.DatePaddingDays | Should -Be 0
        $client.Environment | Should -BeExactly 'USGov'
    }
}

Describe 'Import-OrrClientConfig refuses a bad file' {

    It 'explains what to do when the file does not exist' {
        { Import-OrrClientConfig -Path (Join-Path $TestDrive 'missing.json') } | Should -Throw '*clients.example.json*'
    }

    It 'rejects a file that is not JSON' {
        { Import-FromJson 'this is not json' } | Should -Throw '*not valid JSON*'
    }

    It 'rejects <Name>' -ForEach @(
        @{ Name = 'a missing TenantId'; Set = @{}; Remove = @('TenantId'); Match = "'TenantId' is missing" }
        @{ Name = 'a missing DisplayName'; Set = @{}; Remove = @('DisplayName'); Match = "'DisplayName' is missing" }
        @{ Name = 'a missing AllowedDomains'; Set = @{}; Remove = @('AllowedDomains'); Match = "'AllowedDomains' is missing" }
        @{ Name = 'a TenantId that is a domain name'; Set = @{ TenantId = 'contoso.onmicrosoft.com' }; Remove = @(); Match = 'TenantId' }
        @{ Name = 'a TenantId in braces'; Set = @{ TenantId = '{11111111-2222-3333-4444-555555555555}' }; Remove = @(); Match = 'TenantId' }
        @{ Name = 'an empty AllowedDomains'; Set = @{ AllowedDomains = @() }; Remove = @(); Match = 'at least one email domain' }
        @{ Name = 'a domain with an @'; Set = @{ AllowedDomains = @('@contoso.gov') }; Remove = @(); Match = 'not a domain name' }
        @{ Name = 'a wildcard domain'; Set = @{ AllowedDomains = @('*.gov') }; Remove = @(); Match = 'not a domain name' }
        @{ Name = 'AllowedDomains as a string'; Set = @{ AllowedDomains = 'contoso.gov' }; Remove = @(); Match = 'must be a list' }
        @{ Name = 'a blank DisplayName'; Set = @{ DisplayName = ' ' }; Remove = @(); Match = 'DisplayName' }
        @{ Name = 'a case prefix with a dash'; Set = @{ CaseNamePrefix = 'ORR-' }; Remove = @(); Match = 'CaseNamePrefix' }
        @{ Name = 'an unknown default location'; Set = @{ DefaultLocations = @('dropbox') }; Remove = @(); Match = 'DefaultLocations' }
        @{ Name = 'an http portal address'; Set = @{ PurviewPortalUrl = 'http://purview.microsoft.com' }; Remove = @(); Match = 'PurviewPortalUrl' }
        @{ Name = 'a SharePoint host with a path'; Set = @{ AllowedSharePointHosts = @('contoso.sharepoint.com/sites/x') }; Remove = @(); Match = 'AllowedSharePointHosts' }
        @{ Name = 'a SharePoint host on another domain'; Set = @{ AllowedSharePointHosts = @('contoso.example.com') }; Remove = @(); Match = 'AllowedSharePointHosts' }
        @{ Name = 'DatePaddingDays of 3'; Set = @{ DatePaddingDays = 3 }; Remove = @(); Match = 'DatePaddingDays' }
        @{ Name = 'DatePaddingDays as text'; Set = @{ DatePaddingDays = '1' }; Remove = @(); Match = 'DatePaddingDays' }
        @{ Name = 'an unknown environment'; Set = @{ Environment = 'China' }; Remove = @(); Match = 'Environment' }
        @{ Name = 'an unknown property'; Set = @{ ClientSecret = 'abc' }; Remove = @(); Match = "unknown property 'ClientSecret'" }
    ) {
        { Import-FromJson (New-ConfigJson -Set $Set -Remove $Remove) } | Should -Throw "*$Match*"
    }

    It 'treats property names as case-sensitive' {
        $json = '{"configVersion":"1","clients":{"a":{"tenantid":"11111111-2222-3333-4444-555555555555","DisplayName":"A","AllowedDomains":["a.example"]}}}'
        { Import-FromJson $json } | Should -Throw "*unknown property 'tenantid'*"
    }

    It 'rejects two clients with the same key instead of quietly keeping the second' {
        $json = '{"configVersion":"1","clients":{' +
            '"c1":{"TenantId":"11111111-2222-3333-4444-555555555555","DisplayName":"City A","AllowedDomains":["a.example"]},' +
            '"c1":{"TenantId":"66666666-7777-8888-9999-000000000000","DisplayName":"City B","AllowedDomains":["b.example"]}}}'
        { Import-FromJson $json } | Should -Throw "*the name 'c1' appears twice*"
    }

    It 'rejects <Name>' -ForEach @(
        @{ Name = 'a trailing comma'; Json = '{"configVersion":"1","clients":{"a":{"TenantId":"11111111-2222-3333-4444-555555555555","DisplayName":"A","AllowedDomains":["a.example"],}}}' }
        @{ Name = 'a comment'; Json = '{"configVersion":"1", /* x */ "clients":{"a":{"TenantId":"11111111-2222-3333-4444-555555555555","DisplayName":"A","AllowedDomains":["a.example"]}}}' }
        @{ Name = 'a leading-zero number'; Json = '{"configVersion":"1","clients":{"a":{"TenantId":"11111111-2222-3333-4444-555555555555","DisplayName":"A","AllowedDomains":["a.example"],"DatePaddingDays":01}}}' }
    ) {
        { Import-FromJson $Json } | Should -Throw '*not valid JSON*'
    }

    It 'still reports unknown properties when one is named Keys' {
        { Import-FromJson (New-ConfigJson -Set @{ Keys = @('TenantId'); Bogus = 1 }) } | Should -Throw "*unknown property 'Bogus'*"
    }

    It 'refuses the client key <Key>, which would hide a member of the client table' -ForEach @(
        @{ Key = 'Keys' }, @{ Key = 'Count' }, @{ Key = 'Values' }
    ) {
        { Import-FromJson (New-ConfigJson -Key $Key) } | Should -Throw '*cannot be used as a client key*'
    }

    It 'refuses a file that is not saved as UTF-8' {
        $path = Join-Path $TestDrive 'ansi.json'
        $json = New-ConfigJson -Set @{ DisplayName = ('Caf' + [char]0x00E9 + ' City') }
        [System.IO.File]::WriteAllText($path, $json, [System.Text.Encoding]::GetEncoding(28591))
        { Import-OrrClientConfig -Path $path } | Should -Throw '*not saved as UTF-8*'
    }

    It 'rejects a client key or case prefix that ends in a line break' {
        { Import-FromJson (New-ConfigJson -Key "contoso-city`n") } | Should -Throw '*client key may only use*'
        { Import-FromJson (New-ConfigJson -Set @{ CaseNamePrefix = "ORR`n" }) } | Should -Throw '*CaseNamePrefix*'
    }

    It 'rejects a client key with a space' {
        { Import-FromJson (New-ConfigJson -Key 'contoso city') } | Should -Throw '*client key may only use*'
    }

    It 'rejects a missing or wrong configVersion' {
        { Import-FromJson '{"clients":{"a":{"TenantId":"11111111-2222-3333-4444-555555555555","DisplayName":"A","AllowedDomains":["a.example"]}}}' } |
            Should -Throw '*configVersion*'
        { Import-FromJson '{"configVersion":1,"clients":{"a":{"TenantId":"11111111-2222-3333-4444-555555555555","DisplayName":"A","AllowedDomains":["a.example"]}}}' } |
            Should -Throw '*configVersion*'
    }

    It 'rejects a file with no clients' {
        { Import-FromJson '{"configVersion":"1","clients":{}}' } | Should -Throw '*no entries*'
        { Import-FromJson '{"configVersion":"1"}' } | Should -Throw '*clients must be an object*'
    }

    It 'reports every problem in the file together' {
        $json = New-ConfigJson -Set @{ TenantId = 'nope'; AllowedDomains = @(); DatePaddingDays = 9 }
        $message = $null
        try { Import-FromJson $json } catch { $message = $_.Exception.Message }
        $message | Should -Match 'has 3 problem'
        $message | Should -Match 'TenantId'
        $message | Should -Match 'AllowedDomains'
        $message | Should -Match 'DatePaddingDays'
    }
}
