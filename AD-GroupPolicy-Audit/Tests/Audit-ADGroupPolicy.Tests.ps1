BeforeAll {
    $script:Audit    = Join-Path $PSScriptRoot '..\Audit-ADGroupPolicy.ps1'
    $script:DriveMap = Join-Path $PSScriptRoot '..\..\DriveMap-Diagnostics\Audit-GPDriveMaps.ps1'
    . $script:Audit -LoadFunctionsOnly

    function script:Get-FunctionText {
        param([string]$Path, [string]$Name)
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true)
        if (-not $fn) { return $null }
        # Normalize whitespace so indentation / line-ending differences do not matter.
        return ($fn.Body.Extent.Text -replace '\s+', ' ').Trim()
    }

    function script:New-Element {
        param([string]$Xml)
        $doc = New-Object System.Xml.XmlDocument
        $doc.LoadXml($Xml)
        return $doc.DocumentElement
    }
}

Describe 'Audit-ADGroupPolicy script shape' {
    It 'loads functions without running the audit' {
        Get-Command Start-GPOAudit | Should -Not -BeNullOrEmpty
    }
    It 'does not use #Requires -Modules (runtime Import-Module try/catch instead)' {
        (Get-Content -Path $script:Audit -TotalCount 5) -join "`n" | Should -Not -Match '#Requires\s+-Modules'
    }
    It 'imports both modules at runtime' {
        $text = Get-FunctionText -Path $script:Audit -Name 'Test-Prerequisites'
        $text | Should -Match 'Import-Module \$module -ErrorAction Stop'
        $text | Should -Match "'GroupPolicy', 'ActiveDirectory'"
    }
    It 'no longer contains its own drive map duplicate detection' {
        Get-Command Find-DuplicateDriveMaps -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        Get-Command Get-DriveMapSummary | Should -Not -BeNullOrEmpty
    }
}

Describe 'Copied helpers stay identical to DriveMap-Diagnostics\Audit-GPDriveMaps.ps1' {
    It '<_> body matches' -ForEach @('Write-AuditLog', 'Get-CachedGPOReports', 'Escape-Html', 'Get-ItemLevelTargeting', 'Get-FilterCollectionSummary') {
        $mine   = Get-FunctionText -Path $script:Audit -Name $_
        $theirs = Get-FunctionText -Path $script:DriveMap -Name $_
        $theirs | Should -Not -BeNullOrEmpty
        $mine | Should -Be $theirs
    }
    It '<_> carries a kept-in-sync comment' -ForEach @('Write-AuditLog', 'Get-CachedGPOReports', 'Escape-Html', 'Get-ItemLevelTargeting', 'Get-FilterCollectionSummary') {
        $raw = Get-Content -Path $script:Audit -Raw
        $raw | Should -Match ("(?s)Kept in sync with DriveMap-Diagnostics[^\r\n]*\r?\n[^\r\n]*\r?\n(#[^\r\n]*\r?\n)*function " + [regex]::Escape($_) + ' ')
    }
}

Describe 'Escape-Html' {
    It 'escapes markup characters' {
        Escape-Html '<a href="x">&</a>' | Should -Be '&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;'
    }
    It 'returns an empty string for null or empty' {
        Escape-Html $null | Should -Be ''
        Escape-Html '' | Should -Be ''
    }
}

Describe 'Get-ItemLevelTargeting' {
    It 'reports no targeting when there is no Filters node' {
        $el = New-Element '<Registry><Properties/></Registry>'
        $r = Get-ItemLevelTargeting $el
        $r.Summary | Should -Be 'No targeting (applies to all)'
        $r.Filters.Count | Should -Be 0
    }
    It 'summarises group and user filters and records Not/Bool' {
        $el = New-Element '<Drive><Filters><FilterGroup bool="AND" not="0" name="CONTOSO\Sales"/><FilterUser bool="AND" not="1" name="CONTOSO\bob"/></Filters></Drive>'
        $r = Get-ItemLevelTargeting $el
        $r.Summary | Should -Be "Group IS 'CONTOSO\Sales'; User IS NOT 'CONTOSO\bob'"
        $r.Filters.Count | Should -Be 2
        $r.Filters[0].Type | Should -Be 'FilterGroup'
        $r.Filters[1].Not | Should -BeTrue
    }
    It 'works for printer elements (positional parameter)' {
        $el = New-Element '<SharedPrinter><Filters><FilterSite bool="AND" not="0" name="HQ"/></Filters></SharedPrinter>'
        (Get-ItemLevelTargeting $el).Summary | Should -Be "Site IS 'HQ'"
    }
    It 'handles filter types it has no special case for' {
        $el = New-Element '<Drive><Filters><FilterWeird bool="AND" not="0" name="x"/></Filters></Drive>'
        (Get-ItemLevelTargeting $el).Summary | Should -Be "FilterWeird IS 'x'"
    }
    It 'recurses into filter collections' {
        $el = New-Element '<Drive><Filters><FilterCollection bool="AND" not="0"><FilterGroup bool="AND" not="0" name="A"/><FilterGroup bool="OR" not="1" name="B"/></FilterCollection></Filters></Drive>'
        (Get-ItemLevelTargeting $el).Summary | Should -Match '^Collection: \(Group  .A. AND Group NOT .B.\)$'
    }
}

Describe 'Get-FilterCollectionSummary' {
    It 'joins with OR when the collection bool is OR' {
        $el = New-Element '<FilterCollection bool="OR"><FilterUser name="u1"/><FilterComputer name="pc1" not="1"/></FilterCollection>'
        Get-FilterCollectionSummary $el | Should -Be "User  'u1' OR Computer NOT 'pc1'"
    }
    It 'handles nested collections and IP ranges' {
        $el = New-Element '<FilterCollection bool="AND"><FilterNetworkAddress ipAddress="10.0.0.0"/><FilterCollection bool="OR"><FilterSite name="S"/></FilterCollection></FilterCollection>'
        Get-FilterCollectionSummary $el | Should -Be "IP  '10.0.0.0' AND (Site  'S')"
    }
}

Describe 'Get-DriveMapPreferenceItems' {
    It 'extracts drives recursively and resolves NOCHANGE letters' {
        $el = New-Element '<DriveMapSettings><Drive><Properties action="U" thisDrive="NOCHANGE" letter="H" path="\\s\home" label="Home"/></Drive><Collection name="c"><Drive><Properties action="C" thisDrive="S" path="\\s\share"/></Drive></Collection></DriveMapSettings>'
        $out = New-Object 'System.Collections.Generic.List[object]'
        Get-DriveMapPreferenceItems -Node $el -GPOName 'G' -GPOId ([guid]::NewGuid()) -Scope 'User' -Results $out
        $out.Count | Should -Be 2
        ($out | Where-Object UNCPath -eq '\\s\home').DriveLetter | Should -Be 'H'
        ($out | Where-Object UNCPath -eq '\\s\share').DriveLetter | Should -Be 'S'
    }
}

Describe 'Get-DriveMapSummary' {
    It 'counts mappings and distinct GPOs only (no conflict analysis)' {
        $id1 = [guid]::NewGuid(); $id2 = [guid]::NewGuid()
        $x1 = [xml]'<GPO><User><ExtensionData><Extension><DriveMapSettings><Drive><Properties thisDrive="H" path="\\s\a"/></Drive><Drive><Properties thisDrive="H" path="\\s\b"/></Drive></DriveMapSettings></Extension></ExtensionData></User></GPO>'
        $x2 = [xml]'<GPO><User><ExtensionData><Extension><Other/></Extension></ExtensionData></User></GPO>'
        $gpos = @([PSCustomObject]@{ Id = $id1; DisplayName = 'G1' }, [PSCustomObject]@{ Id = $id2; DisplayName = 'G2' })
        $cache = @{ $id1.ToString() = @{ XmlDoc = $x1 }; $id2.ToString() = @{ XmlDoc = $x2 } }
        $r = Get-DriveMapSummary -GPOs $gpos -GPOCache $cache 6>$null
        $r.MappingCount | Should -Be 2
        $r.GPOCount | Should -Be 1
        $r.GPONames | Should -Be @('G1')
        $r.ContainsKey('ConflictingLetters') | Should -BeFalse
    }
}
