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

Describe 'Own process for the window' {
    # The window crashed long-running sessions (VS Code's PowerShell, a terminal open for hours)
    # with Win32Exception 1816 from WPF, taking the whole session down. It now always runs in a
    # process of its own; this decides whether the current one already is.
    BeforeAll { $script:Me = 'C:\Tools\Server-EventTimeline\Start-ServerEventTimeline.ps1' }

    It 'is its own process when started with -File for this script' {
        Test-TimelineOwnProcess -CommandLineArgs @('C:\Program Files\PowerShell\7\pwsh.dll', '-NoProfile', '-STA', '-File', $script:Me, '-ComputerName', 'APP01') -ScriptPath $script:Me | Should -BeTrue
        Test-TimelineOwnProcess -CommandLineArgs @('powershell.exe', '-file', 'c:\tools\server-eventtimeline\start-servereventtimeline.ps1') -ScriptPath $script:Me | Should -BeTrue
    }

    It 'is not its own process in an interactive session, VS Code, or with -NoExit' {
        Test-TimelineOwnProcess -CommandLineArgs @('C:\Program Files\PowerShell\7\pwsh.dll') -ScriptPath $script:Me | Should -BeFalse
        Test-TimelineOwnProcess -CommandLineArgs @('pwsh.dll', '-NoProfile', '-Command', "Import-Module 'PowerShellEditorServices'") -ScriptPath $script:Me | Should -BeFalse
        Test-TimelineOwnProcess -CommandLineArgs @('pwsh.dll', '-NoExit', '-File', $script:Me) -ScriptPath $script:Me | Should -BeFalse
    }

    It 'is not its own process when -File runs a different script that calls this one' {
        Test-TimelineOwnProcess -CommandLineArgs @('pwsh.dll', '-File', 'C:\Tools\Launcher.ps1') -ScriptPath $script:Me | Should -BeFalse
    }
}

Describe 'Copy selected rows' {
    # The window vanished after a right-click copy: [System.Windows.Clipboard]::SetText threw
    # (another program had the clipboard open) and nothing caught it.
    BeforeAll {
        $script:CopyRows = @(
            [PSCustomObject]@{ Server = 'APP01'; TimeUtc = [datetime]'2026-11-17 08:02:14'; TimeServerLocal = [datetime]'2026-11-17 03:02:14'
                RecordId = 7; LevelName = 'Error'; Provider = 'Service Control Manager'; EventId = 7031; MessageFirstLine = 'The Print Spooler service terminated unexpectedly.' }
        )
    }

    It 'copies the rows and says how many' {
        Mock Copy-TicketNoteToClipboard { $true }
        Copy-TimelineRows -Rows $script:CopyRows | Should -Be 'Copied 1 row(s) - paste them into the ticket.'
        Should -Invoke Copy-TicketNoteToClipboard -Times 1 -ParameterFilter { $Text -like '*APP01*Service Control Manager*7031*' }
    }

    It 'says so, instead of failing, when the clipboard is busy' {
        Mock Copy-TicketNoteToClipboard { $false }
        Copy-TimelineRows -Rows $script:CopyRows | Should -BeLike "Couldn't copy*clipboard*try again*"
    }

    It 'asks for a selection when no row is selected' {
        Mock Copy-TicketNoteToClipboard { throw 'should not run' }
        Copy-TimelineRows -Rows @() | Should -Be 'Select one or more rows first.'
        Should -Invoke Copy-TicketNoteToClipboard -Times 0
    }
}

Describe 'An error in a button or menu does not close the window' {
    # An exception thrown inside a WPF event handler escapes the dispatcher, ShowDialog throws,
    # and the window's process (its console hidden) exits without a word. The guard reports it
    # and keeps the window open. Tested on a real dispatcher with no window.
    It 'reports the error and keeps the dispatcher running' {
        Add-Type -AssemblyName WindowsBase
        $dispatcher = [System.Windows.Threading.Dispatcher]::CurrentDispatcher
        $seen = New-Object System.Collections.ArrayList
        $handler = Register-TimelineErrorGuard -Dispatcher $dispatcher -OnError { param($Message) [void]$seen.Add($Message) }
        try {
            $frame = New-Object System.Windows.Threading.DispatcherFrame
            [void]$dispatcher.BeginInvoke([Action] { $null = [System.IO.File]::ReadAllText((Join-Path $TestDrive 'missing\none.txt')) })
            [void]$dispatcher.BeginInvoke([Action] { $frame.Continue = $false })
            { [System.Windows.Threading.Dispatcher]::PushFrame($frame) } | Should -Not -Throw
            $seen.Count | Should -Be 1
            $seen[0] | Should -BeLike '*missing*'
        }
        finally { $dispatcher.remove_UnhandledException($handler) }
    }
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
        $names = 'ServerInput', 'ServerInputHint', 'AddServerButton', 'ServerCountText', 'DomainText', 'ChangeDomainButton', 'ServerList',
            'SuggestPopup', 'SuggestList', 'AddSeveralButton', 'ClearServersButton', 'AroundRadio', 'RangeRadio', 'AtBox', 'PlusMinusCombo', 'FromBox', 'ToBox', 'LastHourButton', 'Last24Button',
            'LogPanel', 'SecurityCheck', 'AllLogsCheck', 'CapBox', 'TimeoutBox', 'RunAsButton', 'SearchButton',
            'CancelButton', 'StatusList', 'BannerText', 'TimeZoneNote', 'LevelFilter', 'ServerFilter', 'LogFilter', 'FlaggedOnlyCheck',
            'FilterText', 'CountText', 'EventGrid', 'DetailText', 'ExportCsvButton', 'ExportHtmlButton', 'CopyButton', 'ThisComputerButton', 'LogsButton', 'LogsPopup', 'CoreLogPanel', 'LogsAllButton', 'LogsNoneButton', 'LogsDefaultButton', 'SaveFolderBox', 'BrowseFolderButton', 'OpenFolderButton',
            'SummaryList', 'CollapseCheck', 'HiddenNote', 'ShowAllButton', 'TotalCapBox', 'RecentButton', 'TicketNoteButton'
        foreach ($n in $names) { $script:Window.FindName($n) | Should -Not -BeNullOrEmpty -Because "control $n" }
    }

    It 'says what the ticket button does, even before a search has run' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $button = $script:Window.FindName('TicketNoteButton')
        # A noun ("Ticket note...") left people guessing; the label names the result.
        $button.Content | Should -Be 'Copy summary for ticket...'
        # WPF hides tooltips on disabled controls unless ShowOnDisabled is set, and this button
        # is disabled until a search finishes - exactly when someone hovers to find out what it is.
        [System.Windows.Controls.ToolTipService]::GetShowOnDisabled($button) | Should -BeTrue
        $tip = "$($button.ToolTip)"
        $tip | Should -BeLike '*paste*ticket*'
        $tip | Should -BeLike '*Documents\TicketNotes\Ticket_*'
        $tip | Should -BeLike '*Run a search first*'
        $tip | Should -Not -BeLike '*ticket note*'
    }

    It 'no longer has the free-text servers box or the Pick from AD button' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $script:Window.FindName('ServersBox') | Should -BeNullOrEmpty
        $script:Window.FindName('PickFromAdButton') | Should -BeNullOrEmpty
    }

    It 'says what to type in the empty server box' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $script:Window.FindName('ServerInputHint').Text | Should -Be 'Type a server name or IP address'
        $script:Window.FindName('ServerInputHint').IsHitTestVisible | Should -BeFalse
    }

    It 'shows each server with its note and a remove button' {
        $xaml = New-TimelineWindowXaml
        $xaml | Should -Match '<ListBox x:Name="ServerList"'
        $xaml | Should -Match 'Binding Display'
        $xaml | Should -Match 'Binding Note'
        $xaml | Should -Match 'Content="×"'
        $xaml | Should -Match 'Binding NoteKind'
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

Describe 'Invoke-TimelineSearch' {
    It 'passes the Run as credential, the window, the logs and the limits to the engine' {
        Mock Start-TimelineEngine { 'fake-engine' }
        $cred = New-Object System.Management.Automation.PSCredential ('CONTOSO\admin', (New-Object System.Security.SecureString))
        $req = [PSCustomObject]@{ Servers = @('srv-fake-01'); Window = (New-TimelineWindow -Mode Relative -LastMinutes 60); Cap = 1234; TimeoutSec = 45 }
        $engine = Invoke-TimelineSearch -Request $req -Logs @('System', 'Security') -AllLogs $true -Credential $cred
        $engine | Should -Be 'fake-engine'
        Should -Invoke Start-TimelineEngine -Times 1 -ParameterFilter {
            $Credential.UserName -eq 'CONTOSO\admin' -and $Cap -eq 1234 -and $TimeoutSec -eq 45 -and $AllLogs -and
            ($SelectedLogs -join ',') -eq 'System,Security' -and ($Servers -join ',') -eq 'srv-fake-01'
        }
    }

    It 'passes no credential when Run as is not set' {
        Mock Start-TimelineEngine { 'fake-engine' }
        $req = [PSCustomObject]@{ Servers = @('srv-fake-01'); Window = (New-TimelineWindow -Mode Relative -LastMinutes 60); Cap = 5000; TimeoutSec = 60 }
        $null = Invoke-TimelineSearch -Request $req -Logs @('System') -AllLogs $false -Credential $null
        Should -Invoke Start-TimelineEngine -Times 1 -ParameterFilter { $null -eq $Credential -and -not $AllLogs }
    }

    It 'passes the per-server total limit from the window' {
        Mock Start-TimelineEngine { 'fake-engine' }
        $req = [PSCustomObject]@{ Servers = @('srv-fake-01'); Window = (New-TimelineWindow -Mode Relative -LastMinutes 60); Cap = 5000; TimeoutSec = 60; TotalCap = 120000 }
        $null = Invoke-TimelineSearch -Request $req -Logs @('System') -AllLogs $false -Credential $null
        Should -Invoke Start-TimelineEngine -Times 1 -ParameterFilter { $ServerTotalCap -eq 120000 }
    }
}

Describe 'Set-GridItemsPreservingState (rows arriving while you work)' {
    BeforeAll {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA') {
            Add-Type -AssemblyName PresentationFramework
        }
        function New-GridRow { param($Server, $RecordId) [PSCustomObject]@{ Server = $Server; Log = 'System'; RecordId = $RecordId } }
    }

    It 'keeps the column sort and the selected rows when new rows arrive' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $grid = New-Object System.Windows.Controls.DataGrid
        $grid.AutoGenerateColumns = $false
        $col = New-Object System.Windows.Controls.DataGridTextColumn
        $col.Header = 'Server'; $col.SortMemberPath = 'Server'
        $col.Binding = New-Object System.Windows.Data.Binding 'Server'
        $grid.Columns.Add($col)
        $a = New-GridRow 'APP01' 1; $b = New-GridRow 'SQL01' 2
        Set-GridItemsPreservingState -Grid $grid -Items @($a, $b)
        $grid.Items.SortDescriptions.Add((New-Object System.ComponentModel.SortDescription 'Server', 'Descending'))
        $col.SortDirection = 'Descending'
        [void]$grid.SelectedItems.Add($a)

        $c = New-GridRow 'DC01' 3
        Set-GridItemsPreservingState -Grid $grid -Items @($a, $b, $c)

        $col.SortDirection | Should -Be 'Descending'
        @($grid.Items.SortDescriptions).Count | Should -Be 1
        @($grid.SelectedItems) | Should -Contain $a
        @($grid.SelectedItems).Count | Should -Be 1
    }

    It 'does not try to restore a huge selection (Ctrl+A on thousands of rows would freeze the window)' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $grid = New-Object System.Windows.Controls.DataGrid
        $rows = @(1..300 | ForEach-Object { New-GridRow 'APP01' $_ })
        Set-GridItemsPreservingState -Grid $grid -Items $rows
        foreach ($r in $rows) { [void]$grid.SelectedItems.Add($r) }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        # A new array, as Update-View always passes (the same array would not reset the grid).
        Set-GridItemsPreservingState -Grid $grid -Items $rows.Clone()
        # Before the fix this re-added every row one by one (44 s for 1,000 rows). WPF itself
        # keeps rows that are still in the new list selected, so nothing is lost.
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 2
        $grid.SelectedItems.Count | Should -BeGreaterThan 0
    }

    It 'keeps a collapsed row selected even though it is rebuilt as a new object' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $grid = New-Object System.Windows.Controls.DataGrid
        $old = New-GridRow 'APP01' 7
        Set-GridItemsPreservingState -Grid $grid -Items @($old)
        [void]$grid.SelectedItems.Add($old)
        $rebuilt = New-GridRow 'APP01' 7
        Set-GridItemsPreservingState -Grid $grid -Items @($rebuilt)
        @($grid.SelectedItems) | Should -Contain $rebuilt
    }
}

Describe 'Console mode (-NoGui)' {
    BeforeAll {
        $script:OkProbe = {
            param($EnginePath, $Server, $Credential, $WindowStartLocal)
            if ($Server -eq 'srv-fake-dead') {
                return [PSCustomObject]@{ Server = $Server; Reachable = $false; Transport = ''; UtcOffsetMinutes = 0; TimeZoneId = ''
                    Channels = @(); FailureKind = 'Connection'; Reason = 'WinRM and remote event log are both unreachable from here.' }
            }
            [PSCustomObject]@{ Server = $Server; Reachable = $true; Transport = 'WinRM'; UtcOffsetMinutes = 0; TimeZoneId = 'X'
                Channels = @(); FailureKind = ''; Reason = '' }
        }
        $script:TwoEventLog = {
            param($EnginePath, $Server, $Transport, $LogName, $StartUtc, $EndUtc, $Cap, $Credential)
            $mk = { param($m, $id, $prov) [PSCustomObject]@{ TimeCreatedUtc = ([datetime]$StartUtc).AddMinutes($m); Id = $id; ProviderName = $prov
                Level = 2; LogName = $LogName; Message = "event from $Server"; RecordId = $m; UserSid = ''; MachineName = $Server } }
            $events = if ($LogName -eq 'System') { @((& $mk 1 41 'Microsoft-Windows-Kernel-Power'), (& $mk 2 7036 'Service Control Manager')) } else { @() }
            [PSCustomObject]@{ Server = $Server; Log = $LogName; Outcome = 'Read'; Count = $events.Count; Events = $events; Reason = '' }
        }
        $script:Fakes = @{ ProbeScript = $script:OkProbe; LogScript = $script:TwoEventLog }
    }

    It 'reads the servers, writes the CSV and HTML report, and exits 0 when everything was read' {
        $out = Join-Path $TestDrive 'run1'
        $code = Invoke-TimelineConsole -ComputerName 'srv-fake-01', 'srv-fake-02' -LastMinutes 60 -LogName System, Application `
            -OutputPath $out -DefaultOutputPath (Join-Path $TestDrive 'default') -EngineOptions $script:Fakes -PollMs 20 6>$null
        $code | Should -Be 0
        $csv = @(Get-ChildItem -LiteralPath $out -Filter 'ServerEventTimeline_*.csv')
        $csv.Count | Should -Be 1
        @(Import-Csv -LiteralPath $csv[0].FullName).Count | Should -Be 4
        $html = Get-Content -LiteralPath (Get-ChildItem -LiteralPath $out -Filter 'ServerEventTimeline_*.html')[0].FullName -Raw
        $html | Should -BeLike '*srv-fake-01: 1 unexpected restart*'
        @(Get-ChildItem -LiteralPath $out -Filter 'ServerEventTimeline_*.log').Count | Should -Be 1
    }

    It 'says the Security log was not read, with the console switch that adds it, in the output and the report' {
        $out = Join-Path $TestDrive 'nosec'
        $said = @(Invoke-TimelineConsole -ComputerName 'srv-fake-01' -LastMinutes 60 -LogName System `
                -OutputPath $out -DefaultOutputPath (Join-Path $TestDrive 'default') -EngineOptions $script:Fakes -PollMs 20 6>&1) -join "`n"
        $said | Should -BeLike '*Security log not read*-IncludeSecurity*'
        $html = Get-Content -LiteralPath (Get-ChildItem -LiteralPath $out -Filter 'ServerEventTimeline_*.html')[0].FullName -Raw
        $html | Should -BeLike '*What was found*Security log not read*'
    }

    It 'exits 1 when a server could not be read' {
        $out = Join-Path $TestDrive 'run2'
        $code = Invoke-TimelineConsole -ComputerName 'srv-fake-01', 'srv-fake-dead' -LastMinutes 60 -LogName System `
            -OutputPath $out -DefaultOutputPath (Join-Path $TestDrive 'default') -EngineOptions $script:Fakes -PollMs 20 6>$null
        $code | Should -Be 1
    }

    It 'writes a ticket note and the report into the ticket folder' {
        $root = Join-Path $TestDrive 'tickets'
        $code = Invoke-TimelineConsole -ComputerName 'srv-fake-01' -LastMinutes 60 -LogName System -TicketNumber 'T482113' `
            -OutputPath $root -DefaultOutputPath (Join-Path $TestDrive 'default') -NoClipboard -EngineOptions $script:Fakes -PollMs 20 6>$null
        $code | Should -Be 0
        $folder = Join-Path $root 'Ticket_T482113'
        $note = @(Get-ChildItem -LiteralPath $folder -Filter 'Note_*_Server-EventTimeline.txt')
        $note.Count | Should -Be 1
        (Get-Content -LiteralPath $note[0].FullName -Raw) | Should -BeLike '*PROBLEM: srv-fake-01: 1 unexpected restart*'
        @(Get-ChildItem -LiteralPath $folder -Filter 'ServerEventTimeline_*.html').Count | Should -Be 1
    }

    It 'exits 1 when no chosen log could be read on a server (for example a mistyped log name)' {
        $probe = {
            param($EnginePath, $Server, $Credential, $WindowStartLocal)
            [PSCustomObject]@{ Server = $Server; Reachable = $true; Transport = 'WinRM'; UtcOffsetMinutes = 0; TimeZoneId = 'X'; FailureKind = ''; Reason = ''
                Channels = @([PSCustomObject]@{ Name = 'System'; IsEnabled = $true; RecordCount = 10 }) }
        }
        $out = Join-Path $TestDrive 'typo'
        $code = Invoke-TimelineConsole -ComputerName 'srv-fake-01' -LastMinutes 60 -LogName 'Sytem' -OutputPath $out `
            -DefaultOutputPath $out -EngineOptions @{ ProbeScript = $probe; LogScript = $script:TwoEventLog } -PollMs 20 6>$null
        $code | Should -Be 1
    }

    It 'refuses an unusable ticket number or time with exit code 2, reading nothing' {
        Mock Start-TimelineEngine { throw 'should not run' }
        Invoke-TimelineConsole -ComputerName 'srv-fake-01' -TicketNumber '..\x' -OutputPath $TestDrive -DefaultOutputPath $TestDrive -NoClipboard 6>$null | Should -Be 2
        Invoke-TimelineConsole -ComputerName 'srv-fake-01' -At 'not a time' -OutputPath $TestDrive -DefaultOutputPath $TestDrive 6>$null | Should -Be 2
        Should -Invoke Start-TimelineEngine -Times 0
    }

    It 'is documented with -NoGui parameters and an example' {
        $params = (Get-Command $script:AppPath).Parameters.Keys
        foreach ($p in 'NoGui', 'At', 'PlusMinusMinutes', 'From', 'To', 'LastMinutes', 'LogName', 'IncludeSecurity', 'AllLogs', 'TicketNumber', 'NoClipboard', 'Credential') {
            $params | Should -Contain $p
        }
        ($script:Help.Examples.Example.Code -join "`n") | Should -BeLike '*-NoGui*'
    }
}
