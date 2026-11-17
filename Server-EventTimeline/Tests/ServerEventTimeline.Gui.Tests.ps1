<#
    Pester 5 tests for Start-ServerEventTimeline.ps1 (the window). Loaded with
    -LoadFunctionsOnly: no window opens and no server is queried. XAML is only loaded on an
    STA thread (pwsh and Windows PowerShell both start STA).
    Run:  pwsh -File Tests\Invoke-AllTests.ps1 -Path .\Server-EventTimeline\Tests
#>

BeforeAll {
    $script:AppPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Start-ServerEventTimeline.ps1'
    . $script:AppPath -LoadFunctionsOnly
    $script:IsSta = ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')
    $script:Help = Get-Help $script:AppPath -Full
}

Describe 'Help and parameters' {
    It 'has every help section' {
        $script:Help.Synopsis | Should -Not -BeNullOrEmpty
        $script:Help.Description | Should -Not -BeNullOrEmpty
        @($script:Help.Examples.Example).Count | Should -BeGreaterThan 0
        ($script:Help.alertSet | Out-String) | Should -BeLike '*REFERENCES*'
    }

    It 'documents -SmokeTest with an example' {
        ($script:Help.Parameters.Parameter | Where-Object Name -eq 'SmokeTest') | Should -Not -BeNullOrEmpty
        ($script:Help.Examples.Example.Code -join "`n") | Should -BeLike '*-SmokeTest*'
    }

    It 'has the parameters the plan names' {
        $params = (Get-Command $script:AppPath).Parameters.Keys
        foreach ($p in 'ComputerName', 'OutputPath', 'SmokeTest', 'LoadFunctionsOnly') { $params | Should -Contain $p }
    }

    It '-LoadFunctionsOnly defines the window function without opening it' {
        Get-Command Show-ServerEventTimeline -CommandType Function | Should -Not -BeNullOrEmpty
        Get-Command New-TimelineWindowXaml -CommandType Function | Should -Not -BeNullOrEmpty
    }
}

Describe 'Window layout' {
    BeforeAll {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA') {
            Add-Type -AssemblyName PresentationFramework
            $script:Window = [System.Windows.Markup.XamlReader]::Parse((New-TimelineWindowXaml))
        }
    }

    It 'loads in WPF with every named control' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $names = 'ServersBox', 'AroundRadio', 'RangeRadio', 'AtBox', 'PlusMinusCombo', 'FromBox', 'ToBox', 'LastHourButton', 'Last24Button',
            'LogPanel', 'SecurityCheck', 'AllLogsCheck', 'CapBox', 'TimeoutBox', 'RunAsButton', 'PickFromAdButton', 'SearchButton',
            'CancelButton', 'StatusList', 'BannerText', 'TimeZoneNote', 'LevelFilter', 'ServerFilter', 'LogFilter', 'FlaggedOnlyCheck',
            'FilterText', 'CountText', 'EventGrid', 'DetailText', 'ExportCsvButton', 'ExportHtmlButton', 'CopyButton'
        foreach ($n in $names) { $script:Window.FindName($n) | Should -Not -BeNullOrEmpty -Because "control $n" }
    }

    It 'keeps the event grid virtualized and ungrouped' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $grid = $script:Window.FindName('EventGrid')
        $grid.EnableRowVirtualization | Should -BeTrue
        $grid.IsReadOnly | Should -BeTrue
        @($grid.Items.GroupDescriptions).Count | Should -Be 0
    }

    It 'labels the time column as server local time' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $headers = @($script:Window.FindName('EventGrid').Columns | ForEach-Object Header)
        $headers | Should -Contain 'Time (server local)'
        $headers | Should -Contain 'UTC'
    }
}
