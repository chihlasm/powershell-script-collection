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
