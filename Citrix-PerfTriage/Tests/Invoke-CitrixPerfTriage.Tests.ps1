BeforeAll {
    . "$PSScriptRoot/../Invoke-CitrixPerfTriage.ps1" -LoadFunctionsOnly
}

Describe 'Script loading' {
    It 'dot-sources with -LoadFunctionsOnly without starting a triage' {
        Get-Command Invoke-ToolScript -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'points every tool path at a script that exists in this repository' {
        foreach ($rel in $script:ToolPaths.Values) {
            Join-Path $script:RepoRoot $rel | Should -Exist
        }
    }
}

Describe 'ConvertTo-AdminSharePath' {
    It 'maps a local path on the remote machine to its admin share' {
        ConvertTo-AdminSharePath -ComputerName VDA01 -LocalPath 'C:\ProgramData\FSLogix\Logs' |
            Should -Be '\\VDA01\C$\ProgramData\FSLogix\Logs'
    }

    It 'handles a drive root' {
        ConvertTo-AdminSharePath -ComputerName VDA01 -LocalPath 'd:\' | Should -Be '\\VDA01\D$'
    }

    It 'returns a UNC LogDir unchanged - FSLogix accepts network log folders' {
        # https://learn.microsoft.com/fslogix/reference-configuration-settings#log-settings
        ConvertTo-AdminSharePath -ComputerName VDA01 -LocalPath '\\fs01\fslogix-logs' | Should -Be '\\fs01\fslogix-logs'
    }

    It 'returns nothing for a path it cannot translate rather than guessing' {
        ConvertTo-AdminSharePath -ComputerName VDA01 -LocalPath '%ProgramData%\FSLogix\Logs' | Should -BeNullOrEmpty
        ConvertTo-AdminSharePath -ComputerName VDA01 -LocalPath '' | Should -BeNullOrEmpty
    }
}

Describe 'Split-FSLogixLocation' {
    # VHDLocations may be REG_SZ (semicolon-delimited) or REG_MULTI_SZ.
    # https://learn.microsoft.com/fslogix/troubleshooting-old-temp-local-profiles#incorrect-settings-in-vhdlocations-or-ccdlocations
    It 'splits a semicolon-delimited REG_SZ value' {
        Split-FSLogixLocation -Value '\\fs01\profiles; \\fs02\profiles' | Should -Be @('\\fs01\profiles', '\\fs02\profiles')
    }

    It 'accepts a REG_MULTI_SZ value' {
        Split-FSLogixLocation -Value @('\\fs01\profiles', '\\fs02\profiles') | Should -Be @('\\fs01\profiles', '\\fs02\profiles')
    }

    It 'returns an empty list when the value is absent' {
        @(Split-FSLogixLocation -Value $null).Count | Should -Be 0
    }
}

Describe 'Get-CcdConnectionPath' {
    It 'returns the SMB connection strings and skips non-SMB providers' {
        $value = 'type=smb,name="PRIMARY",connectionString=\\fs01\p;type=azure,name="BLOB",connectionString="|fslogix/key|";type=smb,connectionString=\\fs02\p'
        Get-CcdConnectionPath -Value $value | Should -Be @('\\fs01\p', '\\fs02\p')
    }

    It 'accepts a REG_MULTI_SZ value' {
        Get-CcdConnectionPath -Value @('type=smb,connectionString=\\fs01\p', 'type=smb,connectionString=\\fs02\p') |
            Should -Be @('\\fs01\p', '\\fs02\p')
    }
}

Describe 'Get-ShortComputerName' {
    It 'reduces <Name> to <Expected>' -ForEach @(
        @{ Name = 'VDA01';              Expected = 'VDA01' }
        @{ Name = 'vda01.corp.local';   Expected = 'vda01' }
        @{ Name = 'CORP\VDA01';         Expected = 'VDA01' }
    ) {
        Get-ShortComputerName -Name $Name | Should -Be $Expected
    }
}

Describe 'ConvertFrom-FSLogixLogSeverity' {
    It 'maps <Severity> to <Expected>' -ForEach @(
        @{ Severity = 'High';   Expected = 'Critical' }
        @{ Severity = 'Medium'; Expected = 'Warning' }
        @{ Severity = 'Low';    Expected = 'Info' }
        @{ Severity = 'Info';   Expected = 'Info' }
    ) {
        ConvertFrom-FSLogixLogSeverity -Severity $Severity | Should -Be $Expected
    }
}

Describe 'Get-HyperVFlagFromLog' {
    It 'reads only the numbered lines of the FINDINGS SUMMARY block' {
        $log = @(
            ('=' * 80)
            'FINDINGS SUMMARY - HV01 - 2026-09-25 10:00:00'
            ('=' * 80)
            '2 item(s) flagged for review:'
            "  [1] CSV 'Cluster Disk 1' is in Redirected Access mode"
            '  [2] 14 error/warning event(s) in Microsoft-Windows-Hyper-V-VMMS-Admin'
            ''
            'Hyper-V Host Diagnostics'
            '  [9] a numbered line in the body is not a flag'
        ) -join "`r`n"
        $flags = @(Get-HyperVFlagFromLog -Text $log)
        $flags.Count | Should -Be 2
        $flags[0] | Should -Be "CSV 'Cluster Disk 1' is in Redirected Access mode"
    }

    It 'returns nothing when no flags were raised' {
        $log = "FINDINGS SUMMARY - HV01`r`nNo automated flags raised. Review full report below.`r`n`r`n  [1] body"
        @(Get-HyperVFlagFromLog -Text $log).Count | Should -Be 0
    }

    It 'returns nothing for an empty log' {
        @(Get-HyperVFlagFromLog -Text '').Count | Should -Be 0
    }
}

Describe 'Get-DiskSpdResultFromConsole' {
    It 'parses the DiskSpdDiagnostic results line' {
        $r = Get-DiskSpdResultFromConsole -Text '[INFO] Results: 1,234 IOPS / 4.8 MB/s read / 2.1 MB/s write / 6.5 ms avg latency'
        $r.IOPS         | Should -Be 1234
        $r.ReadMBps     | Should -Be 4.8
        $r.WriteMBps    | Should -Be 2.1
        $r.AvgLatencyMs | Should -Be 6.5
    }

    It 'returns nothing when the line is missing, rather than zeros' {
        Get-DiskSpdResultFromConsole -Text 'Preflight failed' | Should -BeNullOrEmpty
    }
}

Describe 'Get-TriageOverallStatus' {
    It 'is Critical when any finding is Critical' {
        $f = @([pscustomobject]@{ Severity = 'Info' }, [pscustomobject]@{ Severity = 'Critical' })
        Get-TriageOverallStatus -Finding $f | Should -Be 'Critical'
    }

    It 'ignores Info findings' {
        Get-TriageOverallStatus -Finding @([pscustomobject]@{ Severity = 'Info' }) | Should -Be 'Healthy'
    }

    It 'is Healthy with no findings' {
        Get-TriageOverallStatus -Finding @() | Should -Be 'Healthy'
    }
}

Describe 'Get-RelativeReportPath' {
    It 'makes paths inside the run folder relative' {
        Get-RelativeReportPath -RunFolder 'C:\Out\Run' -Path 'C:\Out\Run\1-ServerHealth\r.html' | Should -Be '1-ServerHealth\r.html'
    }

    It 'leaves paths outside the run folder alone' {
        Get-RelativeReportPath -RunFolder 'C:\Out\Run' -Path 'D:\Other\r.html' | Should -Be 'D:\Other\r.html'
    }
}

Describe 'ConvertTo-PSLiteral' {
    It 'escapes embedded single quotes' {
        ConvertTo-PSLiteral -Value "O'Brien" | Should -Be "'O''Brien'"
    }
}

Describe 'Invoke-ToolScript' {
    BeforeAll {
        $tools = Join-Path $TestDrive 'tools'
        New-Item -ItemType Directory -Path $tools | Out-Null
        Set-Content (Join-Path $tools 'ok.ps1') 'param([string[]]$Names, [switch]$Flag, [datetime[]]$When) Write-Host "console text"; foreach ($n in $Names) { [pscustomobject]@{ Name = $n; Flag = [bool]$Flag; When = $When[0] } }'
        Set-Content (Join-Path $tools 'exits.ps1') 'exit 3'
        Set-Content (Join-Path $tools 'throws.ps1') 'throw "boom"'
        Set-Content (Join-Path $tools 'hangs.ps1') 'Start-Sleep -Seconds 120'
    }

    It 'passes typed parameters in and returns objects and console text' {
        $when = [datetime]'2026-09-25 10:00'
        $r = Invoke-ToolScript -ScriptPath (Join-Path $tools 'ok.ps1') -WorkFolder (Join-Path $TestDrive 'w-ok') `
            -Parameters @{ Names = @('a', 'b'); Flag = $true; When = @($when) } -TimeoutSeconds 60
        $r.Status | Should -Be 'Completed'
        $r.Output.Count | Should -Be 2
        $r.Output[0].Flag | Should -BeTrue
        $r.Output[0].When | Should -Be $when
        $r.ConsoleText | Should -Match 'console text'
    }

    It 'deletes the parameter file once the tool has finished' {
        $dir = Join-Path $TestDrive 'w-clean'
        $null = Invoke-ToolScript -ScriptPath (Join-Path $tools 'ok.ps1') -WorkFolder $dir -Parameters @{ Names = @('a') } -TimeoutSeconds 60
        Join-Path $dir '_parameters.clixml' | Should -Not -Exist
    }

    It 'reports a tool that calls exit with a non-zero code as Failed' {
        # Several tools call 'exit 1' on a fatal error; that must not look like success.
        $r = Invoke-ToolScript -ScriptPath (Join-Path $tools 'exits.ps1') -WorkFolder (Join-Path $TestDrive 'w-exit') -TimeoutSeconds 60
        $r.Status | Should -Be 'Failed'
        $r.Error | Should -Match 'code 3'
    }

    It 'reports a tool that throws as Failed with the message' {
        $r = Invoke-ToolScript -ScriptPath (Join-Path $tools 'throws.ps1') -WorkFolder (Join-Path $TestDrive 'w-throw') -TimeoutSeconds 60
        $r.Status | Should -Be 'Failed'
        $r.Error | Should -Be 'boom'
    }

    It 'stops a tool that runs past its time limit' {
        $r = Invoke-ToolScript -ScriptPath (Join-Path $tools 'hangs.ps1') -WorkFolder (Join-Path $TestDrive 'w-hang') -TimeoutSeconds 5
        $r.Status | Should -Be 'TimedOut'
        $r.Duration.TotalSeconds | Should -BeLessThan 60
    }
}

Describe 'New-HyperVHandoffPackage' {
    BeforeAll {
        $pkg = New-HyperVHandoffPackage -Folder (Join-Path $TestDrive 'handoff') `
            -Blocked @([pscustomobject]@{ ComputerName = 'HV01'; State = 'NoRemoting' }) `
            -VMNames @('VDA01', "O'Brien-VDA") -DaysBack 14 -Cluster 'HVCL01' `
            -HostScriptPath (Join-Path $script:RepoRoot $script:ToolPaths.HyperVHost) `
            -InventoryScriptPath (Join-Path $script:RepoRoot $script:ToolPaths.HyperVInventory)
        $collector = Join-Path $pkg 'Collect-HyperVEvidence.ps1'
    }

    It 'contains the collector, both Hyper-V scripts and the instructions' {
        foreach ($name in 'Collect-HyperVEvidence.ps1', 'Get-HyperVHostDiagnostics.ps1',
                          'Get-HyperVInfrastructureInventory.ps1', 'README-HyperV-Team.txt') {
            Join-Path $pkg $name | Should -Exist
        }
    }

    It 'generates a collector script that parses' {
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($collector, [ref]$null, [ref]$errors)
        @($errors).Count | Should -Be 0
    }

    It 'bakes in the VM names as safely quoted literals and the lookback' {
        $text = Get-Content -LiteralPath $collector -Raw
        $text | Should -Match ([regex]::Escape("`$vmNames  = @('VDA01', 'O''Brien-VDA')"))
        $text | Should -Match '\$daysBack = 14'
    }

    It 'explains why access was needed' {
        Get-Content -LiteralPath (Join-Path $pkg 'README-HyperV-Team.txt') -Raw | Should -Match 'HV01: remote PowerShell was refused'
    }
}

Describe 'New-TriageHtmlReport' {
    BeforeAll {
        $ctx = @{
            RunFolder = 'C:\Out\Run'; Targets = @('VDA01'); WindowStart = (Get-Date).AddHours(-24); WindowEnd = Get-Date
            HyperVText = 'HVCL01'; RunBy = 'CORP\tech'; HandoffFolder = $null
        }
        $finding = [pscustomobject]@{ Severity = 'Critical'; Area = 'Server health'; Target = 'VDA01'; Finding = 'Memory <script>'; Evidence = '' }
        $step = [pscustomobject]@{ Step = 'Server health'; Status = 'Completed'; Detail = ''; Duration = [TimeSpan]::FromSeconds(75); ReportPath = 'C:\Out\Run\1-ServerHealth\r.html' }
        $html = New-TriageHtmlReport -Context $ctx -Step @($step) -Finding @($finding)
    }

    It 'HTML-encodes collected text' {
        $html | Should -Match '&lt;script&gt;'
        $html | Should -Not -Match 'Memory <script>'
    }

    It 'links step reports relative to the run folder' {
        $html | Should -Match "href='1-ServerHealth/r.html'"
    }
}
