<#
    The launcher's flags for the export. Option 2 (named groups) once always passed
    -ExcludeBuiltin, which drops Domain Admins (RID 512) and the other well-known groups -
    so the menu's own example, "Domain Admins", passed the name check and then produced an
    empty run. Groups the person typed by name must always be reported.
#>

BeforeAll {
    $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Start-AccessReport.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    foreach ($fn in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        if ($fn.Name -eq 'Get-ExportParameter') { . ([scriptblock]::Create($fn.Extent.Text)) }
    }
}

Describe 'Get-ExportParameter' {
    It 'option 1 (everything): nested, built-ins excluded, user report' {
        $p = Get-ExportParameter -ScopeParams @{} -Folder 'C:\ADReports\x'
        $p.IncludeNested | Should -BeTrue
        $p.ExcludeBuiltin | Should -BeTrue
        $p.UserReport | Should -BeTrue
        $p.OutputPath | Should -Be 'C:\ADReports\x'
    }

    It 'option 3 (one area): built-ins still excluded' {
        $p = Get-ExportParameter -ScopeParams @{ SearchBase = 'OU=HR,DC=contoso,DC=com' } -Folder 'C:\r'
        $p.SearchBase | Should -Be 'OU=HR,DC=contoso,DC=com'
        $p.ExcludeBuiltin | Should -BeTrue
    }

    It 'option 2 (named groups): built-ins are NOT excluded, so "Domain Admins" is reported' {
        $p = Get-ExportParameter -ScopeParams @{ GroupName = @('Domain Admins', 'HR-*') } -Folder 'C:\r'
        $p.GroupName | Should -Be @('Domain Admins', 'HR-*')
        $p.ContainsKey('ExcludeBuiltin') | Should -BeFalse
        $p.IncludeNested | Should -BeTrue
        $p.UserReport | Should -BeTrue
    }
}
