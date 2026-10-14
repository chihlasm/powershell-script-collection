<#
    The launcher ends by showing the report in File Explorer, because people were closing
    the window without seeing where the files were saved. Start-Process is mocked, so these
    run headless and check exactly what would be launched.
#>

BeforeAll {
    $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Start-AccessReport.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    foreach ($fn in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        if ($fn.Name -in 'Write-Step', 'Open-ReportLocation') { . ([scriptblock]::Create($fn.Extent.Text)) }
    }
}

Describe 'Open-ReportLocation' {
    BeforeEach {
        $folder = Join-Path $TestDrive 'ADReports\2026-10-14_101500'
        $null = New-Item -ItemType Directory -Path $folder -Force
        $zip = Join-Path $TestDrive 'ADReports\ADAccessReport_2026-10-14_101500.zip'
        # TestDrive persists across tests in a Describe; start each without a zip.
        Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
        Mock Write-Host { }
    }

    It 'opens Explorer with the zip selected when a zip was made' {
        Set-Content -LiteralPath $zip -Value 'zip'
        Mock Start-Process { }

        Open-ReportLocation -Folder $folder -ZipPath $zip

        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter {
            $FilePath -eq 'explorer.exe' -and $ArgumentList -eq "/select,`"$zip`""
        }
    }

    It 'opens the report folder when no zip was made' {
        Mock Start-Process { }

        Open-ReportLocation -Folder $folder -ZipPath $null

        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter {
            $FilePath -eq 'explorer.exe' -and $ArgumentList -eq "`"$folder`""
        }
    }

    It 'falls back to the folder when the zip path does not exist (packaging failed)' {
        Mock Start-Process { }

        Open-ReportLocation -Folder $folder -ZipPath $zip

        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter { $ArgumentList -eq "`"$folder`"" }
    }

    It 'prints the path instead of failing when Explorer cannot start (remote session, Server Core)' {
        Mock Start-Process { throw 'no desktop' }
        Mock Write-Step { }

        { Open-ReportLocation -Folder $folder -ZipPath $null } | Should -Not -Throw

        Should -Invoke Write-Step -Times 1 -Exactly -ParameterFilter { $Level -eq 'WARN' -and $Message -like "*$folder*" }
    }
}
