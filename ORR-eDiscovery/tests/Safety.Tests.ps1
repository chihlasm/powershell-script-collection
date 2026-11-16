<#
    Hard safety rule: the tool may create a case, create or update a search, add sources to a
    search, estimate, export and read status. It must never purge, delete, close or reopen a
    case, create custodians (the documented samples show a hold being applied), or apply,
    remove or release a hold.

    This suite reads every file under src\ as plain text - comments included - and fails if
    it finds a Graph command that is not on the allow-list, or any banned operation name.
    An allow-list is used because the destructive commands do not share a verb: purge is
    Clear-...SearchData, release is Publish-...Custodian, and several have no cmdlet at all
    and can only be reached with a raw request.

    Sources (cmdlet names checked against Microsoft.Graph.Security 2.36.0 with Get-Command):
      purgeData   https://learn.microsoft.com/graph/api/security-ediscoverysearch-purgedata?view=graph-rest-1.0
      close       https://learn.microsoft.com/graph/api/security-ediscoverycase-close?view=graph-rest-1.0
      removeHold  https://learn.microsoft.com/graph/api/security-ediscoverycustodian-removehold?view=graph-rest-1.0
      release     https://learn.microsoft.com/graph/api/security-ediscoverycustodian-release?view=graph-rest-1.0
      custodians  https://learn.microsoft.com/graph/api/security-ediscoverycase-post-custodians?view=graph-rest-1.0
#>

BeforeDiscovery {
    $srcRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'src'
    # Every file under src, whatever its extension.
    $script:SourceFiles = @(
        Get-ChildItem -Path $srcRoot -Recurse -File |
            ForEach-Object { @{ Name = $_.FullName.Substring($srcRoot.Length + 1); Path = $_.FullName } }
    )
}

BeforeAll {
    # The only Microsoft Graph commands the tool is allowed to contain.
    $script:AllowedGraphCommands = @(
        'Connect-MgGraph'
        'Disconnect-MgGraph'
        'Get-MgContext'
        'Invoke-MgGraphRequest'
        'New-MgSecurityCaseEdiscoveryCase'
        'Get-MgSecurityCaseEdiscoveryCase'
        'New-MgSecurityCaseEdiscoveryCaseSearch'
        'Get-MgSecurityCaseEdiscoveryCaseSearch'
        'Update-MgSecurityCaseEdiscoveryCaseSearch'
        'New-MgSecurityCaseEdiscoveryCaseSearchAdditionalSource'
        'Get-MgSecurityCaseEdiscoveryCaseSearchAdditionalSource'
        'Invoke-MgEstimateSecurityCaseEdiscoveryCaseSearchStatistics'
        'Get-MgSecurityCaseEdiscoveryCaseSearchLastEstimateStatisticsOperation'
        'Export-MgSecurityCaseEdiscoveryCaseSearchResult'
        'Export-MgSecurityCaseEdiscoveryCaseSearchReport'
        'Get-MgSecurityCaseEdiscoveryCaseOperation'
    )

    # Operation names that must not appear anywhere in src, in any letter case. Learn's own
    # examples write some URL segments in lowercase, so matching ignores case.
    $script:BannedPatterns = [ordered]@{
        'purge'                          = '(?i)purge'
        'hold apply/remove'              = '(?i)(apply|remove)hold'
        'legal hold policies'            = '(?i)legalholds?'
        'custodians (holds are applied)' = '(?i)/custodians?\b|custodians\('
        'non-custodial data sources'     = '(?i)noncustodialdatasources'
        'release'                        = '(?i)/release\b|microsoft\.graph\.security\.release'
        'close or reopen a case'         = '(?i)/(close|reopen)\b|microsoft\.graph\.security\.(close|reopen|\$)|[''"](close|reopen|release)[''"]'
        'whole-tenant search scope'      = '(?i)alltenant'
        'raw DELETE/PUT/PATCH request'   = '(?i)[''"](DELETE|PUT|PATCH)[''"]|::(Delete|Put|Patch)\b|(Delete|Put|Patch)Async|Invoke-(Mg)?GraphRequest\s+[''"]?(DELETE|PUT|PATCH)\b'
        '$ref removal'                   = '(?i)/`?\$ref\b'
        'custodian source binding'       = '(?i)custodi(an|al)Sources@odata\.bind'
        'deprecated download function'   = '(?i)getDownloadUrl'
        # Graph is reached only through the allow-listed Mg commands, and no command is
        # assembled at run time, so this scan can see every call.
        'other HTTP transport'           = '(?i)Invoke-(RestMethod|WebRequest|GraphRequest)\b|\b(irm|iwr)\b|HttpClient|HttpRequestMessage|WebClient|HttpWebRequest'
        'code built at run time'         = '(?i)Invoke-Expression|\biex\b|\[scriptblock\]::Create'
    }

    # Case-insensitive matching that does not change with the Windows regional setting
    # (under Turkish, a plain (?i) no longer matches the I in Invoke-).
    $script:ScanOptions = [System.Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant'

    function Get-OrrSafetyViolation {
        param([string]$Text)
        $found = New-Object System.Collections.Generic.List[string]

        # Every Verb-Mg... command name in the text, wherever it appears.
        foreach ($match in [regex]::Matches($Text, '\b[a-z]+-Mg[a-z0-9]+\b', $script:ScanOptions)) {
            if ($script:AllowedGraphCommands -notcontains $match.Value) {
                $found.Add("Graph command not on the allow-list: $($match.Value)")
            }
        }
        # Every -Method (or abbreviation) must be followed by a literal GET or POST.
        foreach ($match in [regex]::Matches($Text, '-(Method|HttpMethod|CustomMethod|Verb|Me|Met|Meth|Metho)(?![a-z0-9-])\s*:?\s*(\S+)', $script:ScanOptions)) {
            if (-not [regex]::IsMatch($match.Groups[2].Value, '^[''"]?(GET|POST)[''"]?$', $script:ScanOptions)) {
                $found.Add("Request method must be a literal GET or POST: '$($match.Value)'")
            }
        }
        foreach ($name in $script:BannedPatterns.Keys) {
            $match = [regex]::Match($Text, $script:BannedPatterns[$name], $script:ScanOptions)
            if ($match.Success) { $found.Add("Banned operation ($name): '$($match.Value)'") }
        }
        return @($found)
    }
}

Describe 'Source files contain only allow-listed eDiscovery operations' {

    It 'found source files to check' {
        $srcRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'src'
        $files = @(Get-ChildItem -Path $srcRoot -Recurse -File -Include '*.ps1', '*.psm1', '*.psd1', '*.xaml')
        $files.Name | Should -Contain 'ORR.Core.psm1'
    }

    It '<Name>' -ForEach $script:SourceFiles {
        $text = [System.IO.File]::ReadAllText($Path)
        Get-OrrSafetyViolation -Text $text | Should -BeNullOrEmpty
    }
}

Describe 'The safety scan catches what it is meant to catch' {

    It 'flags <Sample>' -ForEach @(
        @{ Sample = 'Clear-MgSecurityCaseEdiscoveryCaseSearchData -EdiscoveryCaseId $c' }
        @{ Sample = 'Remove-MgSecurityCaseEdiscoveryCase -EdiscoveryCaseId $c' }
        @{ Sample = 'Remove-MgSecurityCaseEdiscoveryCaseSearch' }
        @{ Sample = 'Remove-MgSecurityCaseEdiscoveryCaseSearchAdditionalSource' }
        @{ Sample = 'Close-MgSecurityCaseEdiscoveryCase' }
        @{ Sample = 'Invoke-MgReopenSecurityCaseEdiscoveryCase' }
        @{ Sample = 'Update-MgSecurityCaseEdiscoveryCase -EdiscoveryCaseId $c' }
        @{ Sample = 'Publish-MgSecurityCaseEdiscoveryCaseCustodian' }
        @{ Sample = 'Publish-MgSecurityCaseEdiscoveryCaseNoncustodialDataSource' }
        @{ Sample = 'Remove-MgSecurityCaseEdiscoveryCaseCustodianHold' }
        @{ Sample = 'Add-MgSecurityCaseEdiscoveryCaseCustodianHold' }
        @{ Sample = 'New-MgSecurityCaseEdiscoveryCaseCustodian' }
        @{ Sample = 'Reset-MgSecurityCaseEdiscoveryCaseSettingToDefault' }
        @{ Sample = 'remove-mgsecuritycaseediscoverycase' }
        @{ Sample = 'New-MgBetaSecurityCaseEdiscoveryCase' }
        @{ Sample = 'Get-MgUser -UserId $upn' }
        @{ Sample = 'Invoke-MgGraphRequest -Method POST -Uri "/v1.0/security/cases/ediscoveryCases/$c/searches/$s/purgeData"' }
        @{ Sample = 'Invoke-MgGraphRequest -Method POST -Uri "/v1.0/security/cases/ediscoveryCases/$c/searches/$s/purgedata"' }
        @{ Sample = 'Invoke-MgGraphRequest -Method POST -Uri "/v1.0/security/cases/ediscoveryCases/$c/close"' }
        @{ Sample = 'Invoke-MgGraphRequest -Method POST -Uri "/v1.0/security/cases/ediscoveryCases/$c/reopen"' }
        @{ Sample = '"/v1.0/security/cases/ediscoveryCases/$c/custodians/removeHold"' }
        @{ Sample = '"/v1.0/security/cases/ediscoveryCases/$c/noncustodialdatasources/applyHold"' }
        @{ Sample = '"/v1.0/security/cases/ediscoveryCases/$c/custodians/$id/release"' }
        @{ Sample = '"/v1.0/security/cases/ediscoveryCases/$c/custodians"' }
        @{ Sample = '"/v1.0/security/cases/ediscoverycases(''x'')/custodians(''y'')"' }
        @{ Sample = '"/v1.0/security/cases/ediscoveryCases/$c/legalHolds"' }
        @{ Sample = '"/v1.0/security/cases/ediscoveryCases/$c/searches/$s/custodianSources/$id/$ref"' }
        @{ Sample = 'Invoke-MgGraphRequest -Method DELETE -Uri $u' }
        @{ Sample = 'Invoke-MgGraphRequest -Method "Delete" -Uri $u' }
        @{ Sample = '$method = ''PATCH''' }
        @{ Sample = 'dataSourceScopes = "allTenantMailboxes"' }
        @{ Sample = 'dataSourceScopes = "allTenantSites"' }
        @{ Sample = '# TODO: call purgeData once the request is closed' }
        @{ Sample = '.../operations/$id/microsoft.graph.security.ediscoveryExportOperation/getDownloadUrl' }
        @{ Sample = 'Invoke-MgGraphRequest -Method:DELETE -Uri $u' }
        @{ Sample = 'Invoke-MgGraphRequest -Me DELETE -Uri $u' }
        @{ Sample = 'Invoke-MgGraphRequest DELETE $u' }
        @{ Sample = 'Invoke-MgGraphRequest -Method $method -Uri $u' }
        @{ Sample = 'Invoke-OrrGraph -HttpMethod Patch -Uri $u' }
        @{ Sample = '[Microsoft.Graph.PowerShell.Authentication.Models.GraphRequestMethod]::Delete' }
        @{ Sample = '$client.DeleteAsync($u)' }
        @{ Sample = 'Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/cases" -Headers $h' }
        @{ Sample = 'Invoke-WebRequest -Uri $downloadUrl -OutFile $path' }
        @{ Sample = 'Invoke-GraphRequest -Uri $u' }
        @{ Sample = 'New-Object System.Net.Http.HttpClient' }
        @{ Sample = 'Invoke-Expression "$verb-MgSecurityCaseEdiscoveryCase"' }
        @{ Sample = '[scriptblock]::Create($text)' }
        @{ Sample = '$action = ''close''' }
        @{ Sample = '"$base/searches/$s/custodianSources/$id/`$ref"' }
        @{ Sample = '"custodianSources@odata.bind" = $urls' }
        @{ Sample = '$scope = "allTenant" + "Mailboxes"' }
    ) {
        Get-OrrSafetyViolation -Text $Sample | Should -Not -BeNullOrEmpty
    }

    It 'allows <Sample>' -ForEach @(
        @{ Sample = 'New-MgSecurityCaseEdiscoveryCase -BodyParameter $body' }
        @{ Sample = 'Update-MgSecurityCaseEdiscoveryCaseSearch -EdiscoveryCaseId $c -EdiscoverySearchId $s -BodyParameter $body' }
        @{ Sample = 'New-MgSecurityCaseEdiscoveryCaseSearchAdditionalSource -EdiscoveryCaseId $c -EdiscoverySearchId $s -BodyParameter $body' }
        @{ Sample = 'Invoke-MgGraphRequest -Method POST -Uri "/v1.0/security/cases/ediscoveryCases/$c/searches/$s/estimateStatistics" -Body $json' }
        @{ Sample = 'Invoke-MgGraphRequest -Method GET -Uri "/v1.0/security/cases/ediscoveryCases/$c/operations/$o"' }
        @{ Sample = 'Invoke-MgGraphRequest -Method GET -Uri "/v1.0/users/$upn"' }
        @{ Sample = 'Export-MgSecurityCaseEdiscoveryCaseSearchResult -EdiscoveryCaseId $c -EdiscoverySearchId $s -BodyParameter $body' }
        @{ Sample = 'Connect-MgGraph -TenantId $t -Scopes $scopes -ContextScope Process -NoWelcome' }
        @{ Sample = '$spec.Custodians | ForEach-Object { $_ }  # custodians in the spec are fine' }
        @{ Sample = 'The case is closed, so it is refused.' }
    ) {
        Get-OrrSafetyViolation -Text $Sample | Should -BeNullOrEmpty
    }
}

Describe 'The allow-list names real commands' {

    BeforeDiscovery {
        # Read the exported command names from the installed manifests without importing the
        # modules or contacting anything.
        $installed = @(Get-Module -ListAvailable -Name Microsoft.Graph.Security, Microsoft.Graph.Authentication -ErrorAction SilentlyContinue)
        $script:HasGraphModules = (@($installed | Where-Object Name -eq 'Microsoft.Graph.Security').Count -gt 0) -and
            (@($installed | Where-Object Name -eq 'Microsoft.Graph.Authentication').Count -gt 0)
    }

    It 'every allow-listed command exists in the installed Graph modules' -Skip:(-not $script:HasGraphModules) {
        $exported = @(
            foreach ($name in 'Microsoft.Graph.Security', 'Microsoft.Graph.Authentication') {
                $newest = Get-Module -ListAvailable -Name $name | Sort-Object Version -Descending | Select-Object -First 1
                $newest.ExportedCommands.Keys
            }
        )
        foreach ($command in $script:AllowedGraphCommands) {
            $exported | Should -Contain $command
        }
    }
}
