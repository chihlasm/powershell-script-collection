BeforeAll {
    . "$PSScriptRoot\..\Get-CitrixVDAResources.ps1" -LoadFunctionsOnly
}

Describe 'Script loading' {
    It 'dot-sources with -LoadFunctionsOnly without attempting discovery' {
        Get-Command Write-StatusLine -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-ResourceStatus' {
    It 'returns PASS below the warn threshold' {
        Get-ResourceStatus -Value 79.9 -WarnAt 80 -CriticalAt 90 | Should -Be 'PASS'
    }

    It 'returns WARN exactly at the warn threshold' {
        Get-ResourceStatus -Value 80 -WarnAt 80 -CriticalAt 90 | Should -Be 'WARN'
    }

    It 'returns WARN between warn and critical' {
        Get-ResourceStatus -Value 85 -WarnAt 80 -CriticalAt 90 | Should -Be 'WARN'
    }

    It 'returns FAIL exactly at the critical threshold' {
        Get-ResourceStatus -Value 90 -WarnAt 80 -CriticalAt 90 | Should -Be 'FAIL'
    }

    It 'returns FAIL above the critical threshold' {
        Get-ResourceStatus -Value 99.5 -WarnAt 80 -CriticalAt 90 | Should -Be 'FAIL'
    }

    It 'returns UNKNOWN for a null value rather than throwing' {
        Get-ResourceStatus -Value $null -WarnAt 80 -CriticalAt 90 | Should -Be 'UNKNOWN'
    }

    It 'returns PASS at zero' {
        Get-ResourceStatus -Value 0 -WarnAt 80 -CriticalAt 90 | Should -Be 'PASS'
    }
}

Describe 'Get-WorstStatus' {
    It 'picks FAIL over WARN and PASS' {
        Get-WorstStatus -Statuses @('PASS', 'WARN', 'FAIL') | Should -Be 'FAIL'
    }

    It 'picks WARN over PASS' {
        Get-WorstStatus -Statuses @('PASS', 'WARN', 'PASS') | Should -Be 'WARN'
    }

    It 'returns PASS when everything passes' {
        Get-WorstStatus -Statuses @('PASS', 'PASS') | Should -Be 'PASS'
    }

    It 'ignores UNKNOWN when a real status is present' {
        Get-WorstStatus -Statuses @('UNKNOWN', 'WARN') | Should -Be 'WARN'
    }

    It 'returns UNKNOWN when nothing else is present' {
        Get-WorstStatus -Statuses @('UNKNOWN', 'UNKNOWN') | Should -Be 'UNKNOWN'
    }
}

Describe 'Get-VDAInventory' {
    BeforeAll {
        # Get-BrokerMachine only exists on a Delivery Controller. Define a stub so Pester
        # has a command to mock, then mock it.
        function Get-BrokerMachine { param($AdminAddress, $DesktopGroupName, $CatalogName, $MachineName, $MaxRecordCount) }
    }

    It 'maps broker properties onto the output schema' {
        Mock Get-BrokerMachine {
            [PSCustomObject]@{
                MachineName       = 'CONTOSO\VDA-0001'
                DNSName           = 'vda-0001.contoso.local'
                CatalogName       = 'Win2019 Catalog'
                DesktopGroupName  = 'Finance Desktops'
                RegistrationState = 'Registered'
                InMaintenanceMode = $false
                LoadIndex         = 3200
                SessionCount      = 7
                PowerState        = 'On'
            }
        }

        $result = @(Get-VDAInventory -DeliveryController 'DDC01' -MaxRecordCount 1000)

        $result.Count                | Should -Be 1
        $result[0].MachineName       | Should -Be 'CONTOSO\VDA-0001'
        $result[0].DnsName           | Should -Be 'vda-0001.contoso.local'
        $result[0].DeliveryGroup     | Should -Be 'Finance Desktops'
        $result[0].RegistrationState | Should -Be 'Registered'
        $result[0].SessionCount      | Should -Be 7
    }

    It 'always passes MaxRecordCount so the broker does not silently cap at 250' {
        Mock Get-BrokerMachine { @() }

        Get-VDAInventory -DeliveryController 'DDC01' -MaxRecordCount 5000 | Out-Null

        Should -Invoke Get-BrokerMachine -Times 1 -ParameterFilter {
            $MaxRecordCount -eq 5000
        }
    }

    It 'passes the delivery group filter through when supplied' {
        Mock Get-BrokerMachine { @() }

        Get-VDAInventory -DeliveryController 'DDC01' -DesktopGroupName 'Finance Desktops' -MaxRecordCount 1000 | Out-Null

        Should -Invoke Get-BrokerMachine -Times 1 -ParameterFilter {
            $DesktopGroupName -eq 'Finance Desktops'
        }
    }

    It 'omits the delivery group filter when not supplied' {
        # Assert on PSBoundParameters rather than the variable: an unsupplied [string]
        # parameter binds as an empty string, so a $null check would pass even if the
        # implementation had wrongly passed the key through.
        Mock Get-BrokerMachine { @() }

        Get-VDAInventory -DeliveryController 'DDC01' -MaxRecordCount 1000 | Out-Null

        Should -Invoke Get-BrokerMachine -Times 1 -ParameterFilter {
            -not $PSBoundParameters.ContainsKey('DesktopGroupName')
        }
    }

    It 'returns an empty collection when the broker returns nothing' {
        Mock Get-BrokerMachine { @() }

        $result = @(Get-VDAInventory -DeliveryController 'DDC01' -MaxRecordCount 1000)

        $result.Count | Should -Be 0
    }
}

Describe 'ConvertTo-MemoryMetrics' {
    It 'treats input as kilobytes per Win32_OperatingSystem' {
        # 16 GB total, 4 GB free, expressed in KB as WMI reports it.
        $m = ConvertTo-MemoryMetrics -TotalKb (16 * 1024 * 1024) -FreeKb (4 * 1024 * 1024)

        $m.TotalGB     | Should -Be 16
        $m.FreeGB      | Should -Be 4
        $m.UsedGB      | Should -Be 12
        $m.UsedPercent | Should -Be 75
    }

    It 'returns null percent when total is zero rather than dividing by zero' {
        $m = ConvertTo-MemoryMetrics -TotalKb 0 -FreeKb 0
        $m.UsedPercent | Should -BeNullOrEmpty
    }
}

Describe 'ConvertTo-DiskMetrics' {
    It 'treats input as bytes per Win32_LogicalDisk and reports the worst drive' {
        $disks = @(
            [PSCustomObject]@{ DeviceID = 'C:'; Size = 100GB; FreeSpace = 40GB }  # 60% used
            [PSCustomObject]@{ DeviceID = 'D:'; Size = 200GB; FreeSpace = 20GB }  # 90% used
        )

        $d = ConvertTo-DiskMetrics -Disks $disks

        $d.MaxUsedPercent | Should -Be 90
        $d.Summary        | Should -Match 'C:'
        $d.Summary        | Should -Match 'D:'
    }

    It 'ignores a zero-size disk without dividing by zero' {
        $disks = @(
            [PSCustomObject]@{ DeviceID = 'C:'; Size = 100GB; FreeSpace = 50GB }
            [PSCustomObject]@{ DeviceID = 'E:'; Size = 0;     FreeSpace = 0 }
        )

        $d = ConvertTo-DiskMetrics -Disks $disks

        $d.MaxUsedPercent | Should -Be 50
    }

    It 'returns null max when there are no disks' {
        $d = ConvertTo-DiskMetrics -Disks @()
        $d.MaxUsedPercent | Should -BeNullOrEmpty
    }
}

Describe 'Get-UptimeDays' {
    It 'computes whole and fractional days between boot and now' {
        $boot = [datetime]'2026-08-01 00:00:00'
        $now  = [datetime]'2026-08-11 12:00:00'

        Get-UptimeDays -LastBootUpTime $boot -Now $now | Should -Be 10.5
    }

    It 'returns 0 when boot time is in the future rather than a negative number' {
        $boot = [datetime]'2026-08-20 00:00:00'
        $now  = [datetime]'2026-08-19 00:00:00'

        Get-UptimeDays -LastBootUpTime $boot -Now $now | Should -Be 0
    }
}

Describe 'Get-VDAResourceSnapshot' {
    BeforeAll {
        # Get-CimInstance -CimSession is strongly typed to CimSession[], so a PSCustomObject
        # stub fails parameter binding before the mock is ever consulted. CimSession::Create
        # builds a correctly typed object without opening a connection, and since
        # Get-CimInstance is itself mocked no traffic is ever attempted.
        function New-FakeCimSession {
            [Microsoft.Management.Infrastructure.CimSession]::Create('pester-fake-host')
        }
    }

    It 'returns Success with populated metrics when every query works' {
        Mock New-CimSession { New-FakeCimSession }
        Mock Remove-CimSession { }
        Mock Get-CimInstance {
            switch ($ClassName) {
                'Win32_OperatingSystem' {
                    [PSCustomObject]@{
                        TotalVisibleMemorySize = 16 * 1024 * 1024
                        FreePhysicalMemory     = 4 * 1024 * 1024
                        LastBootUpTime         = (Get-Date).AddDays(-5)
                    }
                }
                'Win32_LogicalDisk' {
                    [PSCustomObject]@{ DeviceID = 'C:'; Size = 100GB; FreeSpace = 40GB }
                }
                'Win32_PerfFormattedData_PerfOS_Processor' {
                    [PSCustomObject]@{ Name = '_Total'; PercentProcessorTime = 42 }
                }
            }
        }

        $snap = Get-VDAResourceSnapshot -ComputerName 'VDA-0001' -TimeoutSeconds 15

        $snap.CollectionStatus   | Should -Be 'Success'
        $snap.CpuPercent         | Should -Be 42
        $snap.MemoryUsedPercent  | Should -Be 75
        $snap.MaxDiskUsedPercent | Should -Be 60
        $snap.UptimeDays         | Should -BeGreaterThan 4
    }

    It 'returns Unreachable with the error message when the session cannot be created' {
        Mock New-CimSession { throw 'WinRM cannot complete the operation' }
        Mock Remove-CimSession { }

        $snap = Get-VDAResourceSnapshot -ComputerName 'VDA-DEAD' -TimeoutSeconds 15

        $snap.CollectionStatus | Should -Be 'Unreachable'
        $snap.ErrorMessage     | Should -Match 'WinRM'
        $snap.CpuPercent       | Should -BeNullOrEmpty
    }

    It 'still returns other metrics when only the CPU query fails' {
        Mock New-CimSession { New-FakeCimSession }
        Mock Remove-CimSession { }
        Mock Get-CimInstance {
            switch ($ClassName) {
                'Win32_OperatingSystem' {
                    [PSCustomObject]@{
                        TotalVisibleMemorySize = 8 * 1024 * 1024
                        FreePhysicalMemory     = 2 * 1024 * 1024
                        LastBootUpTime         = (Get-Date).AddDays(-1)
                    }
                }
                'Win32_LogicalDisk' {
                    [PSCustomObject]@{ DeviceID = 'C:'; Size = 50GB; FreeSpace = 25GB }
                }
                'Win32_PerfFormattedData_PerfOS_Processor' { throw 'perf counters unavailable' }
            }
        }

        $snap = Get-VDAResourceSnapshot -ComputerName 'VDA-0002' -TimeoutSeconds 15

        $snap.CollectionStatus  | Should -Be 'Success'
        $snap.CpuPercent        | Should -BeNullOrEmpty
        $snap.MemoryUsedPercent | Should -Be 75
    }

    It 'always removes the CIM session even when a query throws' {
        Mock New-CimSession { New-FakeCimSession }
        Mock Remove-CimSession { }
        Mock Get-CimInstance { throw 'boom' }

        Get-VDAResourceSnapshot -ComputerName 'VDA-0003' -TimeoutSeconds 15 | Out-Null

        Should -Invoke Remove-CimSession -Times 1
    }

    It 'filters to fixed disks only using DriveType 3' {
        Mock New-CimSession { New-FakeCimSession }
        Mock Remove-CimSession { }
        Mock Get-CimInstance {
            switch ($ClassName) {
                'Win32_OperatingSystem' {
                    [PSCustomObject]@{
                        TotalVisibleMemorySize = 8 * 1024 * 1024
                        FreePhysicalMemory     = 4 * 1024 * 1024
                        LastBootUpTime         = (Get-Date).AddDays(-1)
                    }
                }
                'Win32_LogicalDisk' { [PSCustomObject]@{ DeviceID = 'C:'; Size = 50GB; FreeSpace = 25GB } }
                'Win32_PerfFormattedData_PerfOS_Processor' { [PSCustomObject]@{ Name = '_Total'; PercentProcessorTime = 10 } }
            }
        }

        Get-VDAResourceSnapshot -ComputerName 'VDA-0004' -TimeoutSeconds 15 | Out-Null

        Should -Invoke Get-CimInstance -Times 1 -ParameterFilter {
            $ClassName -eq 'Win32_LogicalDisk' -and $Filter -match 'DriveType\s*=\s*3'
        }
    }
}

Describe 'New-VDAResultRow' {
    BeforeAll {
        $script:Thresholds = @{
            CpuWarn = 80; CpuCritical = 90
            MemoryWarn = 80; MemoryCritical = 90
            DiskWarn = 80; DiskCritical = 90
        }

        $script:Inv = [PSCustomObject]@{
            MachineName       = 'CONTOSO\VDA-0001'
            DnsName           = 'vda-0001.contoso.local'
            CatalogName       = 'Win2019'
            DeliveryGroup     = 'Finance'
            RegistrationState = 'Registered'
            InMaintenanceMode = $false
            LoadIndex         = 3200
            SessionCount      = 7
            PowerState        = 'On'
        }
    }

    It 'carries broker fields onto the row' {
        $snap = [PSCustomObject]@{
            CpuPercent = 10; MemoryTotalGB = 16; MemoryUsedGB = 4; MemoryFreeGB = 12
            MemoryUsedPercent = 25; DiskSummary = 'C: 30/100GB (30%)'; MaxDiskUsedPercent = 30
            UptimeDays = 5; CollectionStatus = 'Success'; ErrorMessage = $null
        }

        $row = New-VDAResultRow -Inventory $script:Inv -Snapshot $snap -Thresholds $script:Thresholds

        $row.MachineName   | Should -Be 'CONTOSO\VDA-0001'
        $row.DeliveryGroup | Should -Be 'Finance'
        $row.SessionCount  | Should -Be 7
        $row.OverallStatus | Should -Be 'PASS'
    }

    It 'escalates OverallStatus to FAIL when memory is critical' {
        $snap = [PSCustomObject]@{
            CpuPercent = 10; MemoryTotalGB = 16; MemoryUsedGB = 15; MemoryFreeGB = 1
            MemoryUsedPercent = 94; DiskSummary = 'C: 30/100GB (30%)'; MaxDiskUsedPercent = 30
            UptimeDays = 5; CollectionStatus = 'Success'; ErrorMessage = $null
        }

        $row = New-VDAResultRow -Inventory $script:Inv -Snapshot $snap -Thresholds $script:Thresholds

        $row.MemoryStatus  | Should -Be 'FAIL'
        $row.OverallStatus | Should -Be 'FAIL'
    }

    It 'produces a row for an unreachable machine rather than dropping it' {
        $snap = [PSCustomObject]@{
            CpuPercent = $null; MemoryTotalGB = $null; MemoryUsedGB = $null; MemoryFreeGB = $null
            MemoryUsedPercent = $null; DiskSummary = $null; MaxDiskUsedPercent = $null
            UptimeDays = $null; CollectionStatus = 'Unreachable'; ErrorMessage = 'WinRM timed out'
        }

        $row = New-VDAResultRow -Inventory $script:Inv -Snapshot $snap -Thresholds $script:Thresholds

        $row.MachineName      | Should -Be 'CONTOSO\VDA-0001'
        $row.CollectionStatus | Should -Be 'Unreachable'
        $row.ErrorMessage     | Should -Be 'WinRM timed out'
        $row.OverallStatus    | Should -Be 'UNKNOWN'
    }

    It 'marks a skipped machine as UNKNOWN overall' {
        $snap = [PSCustomObject]@{
            CpuPercent = $null; MemoryTotalGB = $null; MemoryUsedGB = $null; MemoryFreeGB = $null
            MemoryUsedPercent = $null; DiskSummary = $null; MaxDiskUsedPercent = $null
            UptimeDays = $null; CollectionStatus = 'Skipped'; ErrorMessage = 'Not registered'
        }

        $row = New-VDAResultRow -Inventory $script:Inv -Snapshot $snap -Thresholds $script:Thresholds

        $row.OverallStatus | Should -Be 'UNKNOWN'
    }
}

Describe 'ConvertTo-HtmlSafe' {
    It 'escapes the characters that would break the document' {
        ConvertTo-HtmlSafe -Text 'A&B<C>D"E' | Should -Be 'A&amp;B&lt;C&gt;D&quot;E'
    }

    It 'returns an empty string for null input' {
        ConvertTo-HtmlSafe -Text $null | Should -Be ''
    }
}

Describe 'New-VDAHtmlReport' {
    BeforeAll {
        $script:Thresholds = @{
            CpuWarn = 80; CpuCritical = 90
            MemoryWarn = 80; MemoryCritical = 90
            DiskWarn = 80; DiskCritical = 90
        }

        $script:Rows = @(
            [PSCustomObject]@{
                MachineName = 'VDA-0001'; DnsName = 'vda-0001.contoso.local'
                CatalogName = 'Win2019'; DeliveryGroup = 'Finance'
                RegistrationState = 'Registered'; InMaintenanceMode = $false
                LoadIndex = 1000; SessionCount = 3; PowerState = 'On'
                CpuPercent = 12; CpuStatus = 'PASS'
                MemoryTotalGB = 16; MemoryUsedGB = 6; MemoryFreeGB = 10
                MemoryUsedPercent = 38; MemoryStatus = 'PASS'
                DiskSummary = 'C: 45/120GB (37%)'; MaxDiskUsedPercent = 37; DiskStatus = 'PASS'
                UptimeDays = 6; CollectionStatus = 'Success'; ErrorMessage = $null
                OverallStatus = 'PASS'
            },
            [PSCustomObject]@{
                MachineName = 'VDA-0012'; DnsName = 'vda-0012.contoso.local'
                CatalogName = 'Win2019'; DeliveryGroup = 'Finance'
                RegistrationState = 'Registered'; InMaintenanceMode = $false
                LoadIndex = 9000; SessionCount = 22; PowerState = 'On'
                CpuPercent = 71; CpuStatus = 'PASS'
                MemoryTotalGB = 16; MemoryUsedGB = 15; MemoryFreeGB = 1
                MemoryUsedPercent = 94; MemoryStatus = 'FAIL'
                DiskSummary = 'C: 109/120GB (91%)'; MaxDiskUsedPercent = 91; DiskStatus = 'FAIL'
                UptimeDays = 118; CollectionStatus = 'Success'; ErrorMessage = $null
                OverallStatus = 'FAIL'
            },
            [PSCustomObject]@{
                MachineName = 'VDA-0019'; DnsName = 'vda-0019.contoso.local'
                CatalogName = 'Win2019'; DeliveryGroup = 'Finance'
                RegistrationState = 'Registered'; InMaintenanceMode = $false
                LoadIndex = 0; SessionCount = 0; PowerState = 'On'
                CpuPercent = $null; CpuStatus = 'UNKNOWN'
                MemoryTotalGB = $null; MemoryUsedGB = $null; MemoryFreeGB = $null
                MemoryUsedPercent = $null; MemoryStatus = 'UNKNOWN'
                DiskSummary = $null; MaxDiskUsedPercent = $null; DiskStatus = 'UNKNOWN'
                UptimeDays = $null; CollectionStatus = 'Unreachable'
                ErrorMessage = 'WinRM connection timed out'
                OverallStatus = 'UNKNOWN'
            }
        )
    }

    It 'produces a complete standalone HTML document' {
        $html = New-VDAHtmlReport -Rows $script:Rows -Scope 'All delivery groups' -GeneratedAt ([datetime]'2026-08-19 10:14:02') -Thresholds $script:Thresholds

        $html | Should -Match '<!DOCTYPE html>'
        $html | Should -Match '</html>\s*$'
    }

    It 'references no external resources so it survives being emailed' {
        $html = New-VDAHtmlReport -Rows $script:Rows -Scope 'All' -GeneratedAt (Get-Date) -Thresholds $script:Thresholds

        $html | Should -Not -Match 'src="http'
        $html | Should -Not -Match 'href="http'
        $html | Should -Not -Match '<script src'
    }

    It 'includes every machine, unreachable ones included' {
        $html = New-VDAHtmlReport -Rows $script:Rows -Scope 'All' -GeneratedAt (Get-Date) -Thresholds $script:Thresholds

        $html | Should -Match 'VDA-0001'
        $html | Should -Match 'VDA-0012'
        $html | Should -Match 'VDA-0019'
    }

    It 'surfaces the unreachable count in the summary' {
        $html = New-VDAHtmlReport -Rows $script:Rows -Scope 'All' -GeneratedAt (Get-Date) -Thresholds $script:Thresholds

        $html | Should -Match 'Unreachable'
    }

    It 'escapes machine names so an ampersand cannot corrupt the document' {
        $rows = @(
            [PSCustomObject]@{
                MachineName = 'VDA&<01>'; DnsName = 'x'; CatalogName = 'c'; DeliveryGroup = 'd'
                RegistrationState = 'Registered'; InMaintenanceMode = $false
                LoadIndex = 0; SessionCount = 0; PowerState = 'On'
                CpuPercent = 1; CpuStatus = 'PASS'
                MemoryTotalGB = 8; MemoryUsedGB = 1; MemoryFreeGB = 7
                MemoryUsedPercent = 12; MemoryStatus = 'PASS'
                DiskSummary = 'C: 1/10GB (10%)'; MaxDiskUsedPercent = 10; DiskStatus = 'PASS'
                UptimeDays = 1; CollectionStatus = 'Success'; ErrorMessage = $null
                OverallStatus = 'PASS'
            }
        )

        $html = New-VDAHtmlReport -Rows $rows -Scope 'All' -GeneratedAt (Get-Date) -Thresholds $script:Thresholds

        $html | Should -Match 'VDA&amp;&lt;01&gt;'
        $html | Should -Not -Match 'VDA&<01>'
    }

    It 'sorts the chart worst-first so problem machines lead' {
        $html = New-VDAHtmlReport -Rows $script:Rows -Scope 'All' -GeneratedAt (Get-Date) -Thresholds $script:Thresholds

        # VDA-0012 is the worst machine and must appear before the healthy VDA-0001.
        $html.IndexOf('VDA-0012') | Should -BeLessThan $html.IndexOf('VDA-0001')
    }

    It 'handles an empty row set without throwing' {
        { New-VDAHtmlReport -Rows @() -Scope 'All' -GeneratedAt (Get-Date) -Thresholds $script:Thresholds } | Should -Not -Throw
    }
}
