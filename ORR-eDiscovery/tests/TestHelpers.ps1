<#
    Shared helpers for the ORR.Core Pester suites. Dot-source from BeforeAll:
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Nothing here touches a tenant, the clipboard, or any folder outside $TestDrive.
#>

$script:OrrRoot = Split-Path -Parent $PSScriptRoot
$script:OrrModulePath = Join-Path $script:OrrRoot 'src\ORR.Core\ORR.Core.psd1'
$script:OrrSchemaPath = Join-Path $script:OrrRoot 'schemas\orr-spec.v1.schema.json'
$script:OrrExampleConfigPath = Join-Path $script:OrrRoot 'config\clients.example.json'

function New-OrrTestClientJson {
    # A clients.json with one fully specified client and one that relies on defaults.
    param([hashtable]$Override = @{})

    $contoso = [ordered]@{
        TenantId               = '11111111-2222-3333-4444-555555555555'
        DisplayName            = 'City of Contoso'
        AllowedDomains         = @('contoso.gov', 'contosopd.gov')
        AllowedSharePointHosts = @('contoso.sharepoint.com', 'contoso-my.sharepoint.com')
        CaseNamePrefix         = 'ORR'
        DefaultLocations       = @('exchange', 'onedrive')
        DatePaddingDays        = 1
    }
    foreach ($key in @($Override.get_Keys())) { $contoso[$key] = $Override[$key] }

    $config = [ordered]@{
        configVersion = '1'
        clients       = [ordered]@{
            'contoso-city' = $contoso
            'nopad-town'   = [ordered]@{
                TenantId        = '66666666-7777-8888-9999-000000000000'
                DisplayName     = 'Town of Nopad'
                AllowedDomains  = @('nopad.example.org')
                DatePaddingDays = 0
            }
        }
    }
    return (ConvertTo-Json -InputObject $config -Depth 6)
}

function Import-OrrTestClientConfig {
    # Writes the test clients.json under $TestDrive and loads it through the real loader.
    param([hashtable]$Override = @{}, [string]$FileName = 'clients.json')

    $path = Join-Path $TestDrive $FileName
    [System.IO.File]::WriteAllText($path, (New-OrrTestClientJson -Override $Override))
    return (Import-OrrClientConfig -Path $path)
}

function New-OrrTestSpec {
    # A valid spec as an ordered table. -Set replaces or adds fields; -Remove drops them.
    param([hashtable]$Set = @{}, [string[]]$Remove = @())

    $spec = [ordered]@{
        specVersion    = '1'
        ticketNumber   = 123456
        client         = 'contoso-city'
        requester      = 'Jordan Doe, Contoso Gazette'
        requestSummary = 'Emails about the Main Street road repair contract.'
        custodians     = @('Clerk@Contoso.gov', 'engineer@contoso.gov')
        dateStart      = '2024-01-01'
        dateEnd        = '2024-03-31'
        keywords       = @('budget', 'road repair')
        kqlOverride    = $null
        locations      = @('exchange', 'onedrive', 'teams')
        action         = 'search'
    }
    foreach ($key in @($Set.get_Keys())) { $spec[$key] = $Set[$key] }
    foreach ($key in $Remove) { $spec.Remove($key) }
    return $spec
}

function ConvertTo-OrrTestJson {
    param([Parameter(Mandatory)]$Spec)
    return (ConvertTo-Json -InputObject $Spec -Depth 6)
}
