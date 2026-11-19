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
            'CancelButton', 'SidebarColumn', 'SidebarPanel', 'SidebarStrip', 'CollapseSidebarButton', 'ExpandSidebarButton', 'NotesList', 'BannerText', 'TimeZoneNote', 'LevelFilter', 'ServerFilter', 'LogFilter', 'FlaggedOnlyCheck',
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

    It 'folds the sidebar to a thin strip and back, keeping its width' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $w = [System.Windows.Markup.XamlReader]::Parse((New-TimelineWindowXaml))
        $col = $w.FindName('SidebarColumn')
        $col.Width = New-Object System.Windows.GridLength 360
        Set-TimelineSidebar -Window $w -Collapsed $true
        $col.Width.Value | Should -Be 28
        $w.FindName('SidebarPanel').Visibility | Should -Be 'Collapsed'
        $w.FindName('SidebarStrip').Visibility | Should -Be 'Visible'
        Set-TimelineSidebar -Window $w -Collapsed $false
        $col.Width.Value | Should -Be 360
        $w.FindName('SidebarPanel').Visibility | Should -Be 'Visible'
        $w.FindName('SidebarStrip').Visibility | Should -Be 'Collapsed'
    }

    It 'gives the event list the remaining height, with the detail pane below a drag handle' {
        $xaml = New-TimelineWindowXaml
        $xaml | Should -Match '<DataGrid x:Name="EventGrid" Grid.Row="2"'
        $xaml | Should -Match '<GridSplitter Grid.Row="3"'
        $xaml | Should -Match '<ScrollViewer x:Name="SidebarScroll"'
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

Describe 'Add several servers dialog' {
    It 'loads in WPF with every named control' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        Add-Type -AssemblyName PresentationFramework
        $dlg = [System.Windows.Markup.XamlReader]::Parse((New-AddServersDialogXaml))
        foreach ($n in 'Tabs', 'PasteTab', 'FindTab', 'FileTab', 'PasteBox', 'CheckNamesButton', 'FindBox', 'ScopeAll', 'ScopeDcs', 'ScopeOu', 'OuCombo', 'FindNote',
            'FileButton', 'FilePathText', 'ColumnPanel', 'ColumnCombo', 'ResultList', 'TickAllButton', 'TickNoneButton', 'TickedText', 'AddButton', 'CancelButton') {
            $dlg.FindName($n) | Should -Not -BeNullOrEmpty -Because "control $n"
        }
        $dlg.Title | Should -Be 'Add several servers'
    }

    It 'says how many servers the Add button adds' {
        Get-AddButtonText -Count 0 | Should -Be 'Add servers'
        Get-AddButtonText -Count 1 | Should -Be 'Add 1 server'
        Get-AddButtonText -Count 4 | Should -Be 'Add 4 servers'
    }
}

Describe 'Add several servers dialog, driven end to end (off-screen, fake DNS)' {
    It 'adds the pasted servers that were found, and leaves out one nobody knows' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        Add-Type -AssemblyName PresentationFramework
        $dir = @([PSCustomObject]@{ Name = 'FS01'; DnsName = 'FS01.contoso.local'; OS = 'Windows Server 2019'; Enabled = $true; IsServer = $true; IsDC = $false
                DaysSinceLogon = 3; DistinguishedName = 'CN=FS01,OU=Servers,DC=contoso,DC=local'; OU = 'OU=Servers,DC=contoso,DC=local' })
        $fakeDns = {
            param($Names)
            foreach ($n in $Names) {
                if ($n -eq '10.0.4.21') { @{ Name = $n; IsIp = $true; PtrName = 'SQL01.contoso.local'; ForwardMatches = $true } }
                else { @{ Name = $n; IsIp = $false; Resolves = $false } }
            }
        }
        # Every Window that loads from here on is this dialog: move it off-screen and drive it.
        $drive = @{ Steps = 0; Seen = '' }
        $handler = [System.Windows.RoutedEventHandler] {
            param($w, $e)
            if ($w.Title -ne 'Add several servers' -or $drive.Started) { return }
            $drive.Started = $true
            # GetNewClosure captures this scope's own variables only: copy the state in.
            $drv = $drive
            $w.Left = -20000; $w.Top = -20000
            $w.FindName('PasteBox').Text = "FS01, 10.0.4.21`nCONTOSO\NOPE"
            $click = [System.Windows.Controls.Primitives.ButtonBase]::ClickEvent
            $w.FindName('CheckNamesButton').RaiseEvent((New-Object System.Windows.RoutedEventArgs $click))
            $t = New-Object System.Windows.Threading.DispatcherTimer
            $t.Interval = [TimeSpan]::FromMilliseconds(100)
            $t.add_Tick({
                    $drv.Steps++
                    $rows = @($w.FindName('ResultList').ItemsSource)
                    $pending = @($rows | Where-Object { $_.Note -eq 'checking...' }).Count
                    if (($rows.Count -eq 3 -and $pending -eq 0) -or $drv.Steps -gt 100) {
                        $t.Stop()
                        $drv.Seen = (@($rows | ForEach-Object { '{0}={1}' -f $_.Name, $_.Note }) -join '; ')
                        $w.FindName('AddButton').RaiseEvent((New-Object System.Windows.RoutedEventArgs $click))
                    }
                }.GetNewClosure())
            $t.Start()
        }.GetNewClosure()
        [System.Windows.EventManager]::RegisterClassHandler([System.Windows.Window], [System.Windows.FrameworkElement]::LoadedEvent, $handler)
        $result = @(Show-AddServersDialog -Owner $null -Directory $dir -DirectoryState 'Loaded' -DomainText 'Suggestions from: contoso.local (1 server)' -Lookup $fakeDns)
        $drive.Seen | Should -Be "FS01=in AD; 10.0.4.21=IP · is SQL01.contoso.local; NOPE=not found in AD or DNS"
        $result -join ',' | Should -Be 'FS01,10.0.4.21'
    }
}

Describe 'Pasting several servers into the one-line server box' {
    # Review finding: a one-line TextBox drops everything after the first line break of a paste,
    # so 10 servers pasted from a column became 1. The paste is taken over when it has lines.
    BeforeAll {
        function Invoke-FakePaste {
            param($Box, [string]$Text)
            $data = New-Object System.Windows.DataObject ([System.Windows.DataFormats]::UnicodeText, $Text)
            $e = New-Object System.Windows.DataObjectPastingEventArgs ($data, $false, [System.Windows.DataFormats]::UnicodeText)
            $Box.RaiseEvent($e)
            $e
        }
    }

    It 'hands every pasted line to the list and cancels the one-line paste' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        Add-Type -AssemblyName PresentationFramework
        $box = New-Object System.Windows.Controls.TextBox
        $got = New-Object System.Collections.ArrayList
        Register-ServerInputPaste -TextBox $box -OnNames { param($Text) [void]$got.Add($Text) }.GetNewClosure()
        $e = Invoke-FakePaste -Box $box -Text "FS01, FS02`r`nFS03`nFS04"
        $got.Count | Should -Be 1
        $got[0] | Should -Be "FS01, FS02`r`nFS03`nFS04"
        $e.CommandCancelled | Should -BeTrue
    }

    It 'leaves a one-line paste to the box as usual' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        Add-Type -AssemblyName PresentationFramework
        $box = New-Object System.Windows.Controls.TextBox
        $got = New-Object System.Collections.ArrayList
        Register-ServerInputPaste -TextBox $box -OnNames { param($Text) [void]$got.Add($Text) }.GetNewClosure()
        $e = Invoke-FakePaste -Box $box -Text 'FS01'
        $got.Count | Should -Be 0
        $e.CommandCancelled | Should -BeFalse
    }
}

Describe 'Choosing the domain for suggestions' {
    # Review finding: Cancel on the old InputBox returned '' - the same as "this computer's
    # domain" - so cancelling silently dropped the client domain. The prompt now has a Cancel
    # that changes nothing and its own button for this computer's domain.
    BeforeAll {
        function Invoke-DomainPrompt {
            param([string]$Current, [string]$Press, [string]$Type)
            $state = @{ Press = $Press; Type = $Type; Done = $false }
            $h = [System.Windows.RoutedEventHandler] {
                param($w, $e)
                if ($w.Title -ne 'Suggestions from' -or $state.Done) { return }
                $state.Done = $true
                $w.Left = -20000; $w.Top = -20000
                if ($null -ne $state.Type) { $w.FindName('DomainBox').Text = $state.Type }
                $w.FindName($state.Press).RaiseEvent((New-Object System.Windows.RoutedEventArgs ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
            }.GetNewClosure()
            [System.Windows.EventManager]::RegisterClassHandler([System.Windows.Window], [System.Windows.FrameworkElement]::LoadedEvent, $h)
            Show-DomainPrompt -Owner $null -Current $Current
        }
    }

    It 'changes nothing on Cancel' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        Add-Type -AssemblyName PresentationFramework
        Invoke-DomainPrompt -Current 'client.local' -Press 'CancelButton' -Type $null | Should -BeNullOrEmpty
        (Invoke-DomainPrompt -Current 'client.local' -Press 'CancelButton' -Type $null) -eq '' | Should -BeFalse
    }

    It "returns '' for this computer's domain, and the typed name on OK" -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        Add-Type -AssemblyName PresentationFramework
        Invoke-DomainPrompt -Current 'client.local' -Press 'ThisDomainButton' -Type $null | Should -Be ''
        Invoke-DomainPrompt -Current '' -Press 'OkButton' -Type '  dc01.client.local ' | Should -Be 'dc01.client.local'
    }
}

Describe 'The What happened tab' {
    BeforeAll {
        $script:StRec = 0
        function New-StoryTestRow {
            param([string]$Server = 'AD-01', [string]$Time, [string]$Provider = 'Service Control Manager', [int]$Id = 7036, [int]$Level = 4, [string]$Log = 'System')
            $script:StRec++
            $e = [PSCustomObject]@{ TimeCreatedUtc = [datetime]::SpecifyKind([datetime]$Time, [DateTimeKind]::Utc); Id = $Id; ProviderName = $Provider
                Level = $Level; LogName = $Log; Message = "event $script:StRec"; RecordId = $script:StRec; UserSid = ''; MachineName = $Server }
            ConvertTo-TimelineRow -Server $Server -EventRecord $e -UtcOffsetMinutes 0
        }
        function New-StoryTestUi {
            # The controls the story click touches, from the real XAML, with the filters filled
            # the way the window fills them.
            param([object[]]$Rows)
            $w = [System.Windows.Markup.XamlReader]::Parse((New-TimelineWindowXaml))
            $ui = @{ Window = $w; Store = (New-TimelineRowStore); Hidden = (New-Object System.Collections.Generic.List[string]); EventKey = '' }
            foreach ($n in 'LevelFilter', 'ServerFilter', 'LogFilter', 'FlaggedOnlyCheck', 'FilterText', 'EventGrid', 'CollapseCheck') { $ui[$n] = $w.FindName($n) }
            foreach ($pair in @(@($ui.LevelFilter, @('All', 'Warning', 'Error', 'Critical')), @($ui.ServerFilter, @('*', 'AD-01', 'AD-03')), @($ui.LogFilter, @('*', 'System', 'Application')))) {
                foreach ($tag in $pair[1]) { $i = New-Object System.Windows.Controls.ComboBoxItem; $i.Content = $tag; $i.Tag = $tag; [void]$pair[0].Items.Add($i) }
                $pair[0].SelectedIndex = 0
            }
            if (@($Rows).Count -gt 0) { Add-TimelineRows -Store $ui.Store -NewRows $Rows }
            $ui
        }
        $script:Refresh = { param($Ui) $Ui.EventGrid.ItemsSource = @(Select-TimelineRows -Rows $Ui.Store.Rows.ToArray() -Filter (Get-TimelineGridFilter -Ui $Ui)) }
    }

    It 'has the two detail tabs, the story list and Copy for ticket' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $w = [System.Windows.Markup.XamlReader]::Parse((New-TimelineWindowXaml))
        foreach ($n in 'DetailTabs', 'DetailText', 'StoryList', 'StoryEmptyText', 'CopyStoryButton') { $w.FindName($n) | Should -Not -BeNullOrEmpty -Because "control $n" }
        @($w.FindName('DetailTabs').Items | ForEach-Object Header) | Should -Be @('Event details', 'What happened')
        $w.FindName('CopyStoryButton').Content | Should -Be 'Copy for ticket'
    }

    It 'shows the waiting text before any search' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $w = [System.Windows.Markup.XamlReader]::Parse((New-TimelineWindowXaml))
        $w.FindName('StoryEmptyText').Text | Should -Be 'Search to see the important events here, in order.'
        Set-TimelineStoryView -Window $w -Story $null
        $w.FindName('StoryEmptyText').Text | Should -Be 'Search to see the important events here, in order.'
        $w.FindName('CopyStoryButton').IsEnabled | Should -BeFalse
    }

    It 'shows the nothing-recognised text when no row is flagged' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $w = [System.Windows.Markup.XamlReader]::Parse((New-TimelineWindowXaml))
        Set-TimelineStoryView -Window $w -Story (Get-TimelineStory -Rows @(New-StoryTestRow -Time '2026-11-18 17:00'))
        $w.FindName('StoryEmptyText').Text | Should -Be 'Nothing the tool recognises happened in this window - check the errors in the list.'
        $w.FindName('StoryEmptyText').Visibility | Should -Be 'Visible'
    }

    It 'fills the story from the rows' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $w = [System.Windows.Markup.XamlReader]::Parse((New-TimelineWindowXaml))
        $rows = @((New-StoryTestRow -Time '2026-11-18 17:00' -Provider 'Disk' -Id 153 -Level 3), (New-StoryTestRow -Time '2026-11-18 17:30' -Provider 'Microsoft-Windows-WindowsUpdateClient' -Id 19))
        Set-TimelineStoryView -Window $w -Story (Get-TimelineStory -Rows $rows)
        @($w.FindName('StoryList').ItemsSource).Count | Should -Be 3
        $w.FindName('StoryEmptyText').Visibility | Should -Be 'Collapsed'
        $w.FindName('CopyStoryButton').IsEnabled | Should -BeTrue
    }

    It 'refreshes the story with the summary, and resets it for a new search' {
        $src = Get-Content -LiteralPath $script:AppPath -Raw
        $summary = $src.Substring($src.IndexOf('function Update-Summary'), 1800)
        $summary | Should -Match 'Set-TimelineStoryView'
        $start = $src.Substring($src.IndexOf('function Start-Search'), 1500)
        $start | Should -Match 'Set-TimelineStoryView -Window \$window -Story \$null'
    }

    It "selects the clicked line's row, clearing filters that hide it" -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $update = New-StoryTestRow -Time '2026-11-18 17:30' -Provider 'Microsoft-Windows-WindowsUpdateClient' -Id 19
        $ui = New-StoryTestUi -Rows @((New-StoryTestRow -Time '2026-11-18 17:00' -Level 2 -Provider 'Ntfs' -Id 5), $update)
        $ui.LevelFilter.SelectedIndex = 2      # Errors and worse: hides the Information update
        $ui.EventKey = 'Ntfs|5'
        $ui.Hidden.Add('Microsoft-Windows-WindowsUpdateClient')
        & $script:Refresh $ui
        @($ui.EventGrid.ItemsSource) -contains $update | Should -BeFalse

        Show-TimelineStoryRow -Ui $ui -RowId (Get-TimelineRowId -Row $update) -Refresh { & $script:Refresh $ui } | Should -BeTrue
        $ui.EventKey | Should -Be ''
        $ui.Hidden.Count | Should -Be 0
        [string]$ui.LevelFilter.SelectedItem.Tag | Should -Be 'All'
        $ui.EventGrid.SelectedItem | Should -Be $update
    }

    It 'leaves the filters alone when the row is already shown' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $update = New-StoryTestRow -Time '2026-11-18 17:30' -Provider 'Microsoft-Windows-WindowsUpdateClient' -Id 19
        $ui = New-StoryTestUi -Rows @($update)
        $ui.ServerFilter.SelectedIndex = 1
        & $script:Refresh $ui
        Show-TimelineStoryRow -Ui $ui -RowId (Get-TimelineRowId -Row $update) -Refresh { & $script:Refresh $ui } | Should -BeTrue
        [string]$ui.ServerFilter.SelectedItem.Tag | Should -Be 'AD-01'
        $ui.EventGrid.SelectedItem | Should -Be $update
    }

    It 'says so when the row is no longer there' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $ui = New-StoryTestUi -Rows @()
        Show-TimelineStoryRow -Ui $ui -RowId 'AD-09|System|1' -Refresh { } | Should -BeFalse
    }

    It 'Copy for ticket copies the story lines' {
        Mock Copy-TicketNoteToClipboard { $true }
        $story = Get-TimelineStory -Rows @(New-StoryTestRow -Time '2026-11-18 17:30' -Provider 'Microsoft-Windows-WindowsUpdateClient' -Id 19)
        Copy-TimelineStory -Story $story | Should -Be 'Copied what happened (1 line) - paste it into the ticket.'
        Should -Invoke Copy-TicketNoteToClipboard -Times 1 -ParameterFilter { $Text -like '*AD-01 2026-11-18 17:30 (server local): Windows Update installed an update*' }
    }

    It 'Copy for ticket says so instead of failing when the clipboard is busy' {
        Mock Copy-TicketNoteToClipboard { $false }
        $story = Get-TimelineStory -Rows @(New-StoryTestRow -Time '2026-11-18 17:30' -Provider 'Microsoft-Windows-WindowsUpdateClient' -Id 19)
        Copy-TimelineStory -Story $story | Should -BeLike "Couldn't copy*clipboard*try again*"
    }
}

Describe 'The picture strip in the window' {
    BeforeAll {
        $script:PicRec = 0
        function New-PicRow {
            param([string]$Server = 'AD-01', [string]$Time, [string]$Provider = 'Service Control Manager', [int]$Id = 7036, [int]$Level = 4)
            $script:PicRec++
            $e = [PSCustomObject]@{ TimeCreatedUtc = [datetime]::SpecifyKind([datetime]$Time, [DateTimeKind]::Utc); Id = $Id; ProviderName = $Provider
                Level = $Level; LogName = 'System'; Message = "event $script:PicRec"; RecordId = $script:PicRec; UserSid = ''; MachineName = $Server }
            ConvertTo-TimelineRow -Server $Server -EventRecord $e -UtcOffsetMinutes 0
        }
        $script:P0 = [datetime]::SpecifyKind([datetime]'2026-11-18 17:45', [DateTimeKind]::Utc)
        $script:P1 = [datetime]::SpecifyKind([datetime]'2026-11-18 18:05', [DateTimeKind]::Utc)
        function New-PicModel { param([string[]]$Servers = @('AD-01'), [object[]]$Rows = @())
            Get-TimelineStripModel -Rows $Rows -Servers $Servers -StartUtc $script:P0 -EndUtc $script:P1 -Width 700 }
        function New-PicUi {
            $w = [System.Windows.Markup.XamlReader]::Parse((New-TimelineWindowXaml))
            $ui = @{ Window = $w; Store = (New-TimelineRowStore); Hidden = (New-Object System.Collections.Generic.List[string]); EventKey = ''; TimeRange = $null }
            foreach ($n in 'LevelFilter', 'ServerFilter', 'LogFilter', 'FlaggedOnlyCheck', 'FilterText', 'EventGrid', 'TimeRangeChip', 'TimeRangeText', 'ClearRangeButton') { $ui[$n] = $w.FindName($n) }
            foreach ($pair in @(@($ui.LevelFilter, @('All', 'Warning', 'Error', 'Critical')), @($ui.ServerFilter, @('*', 'AD-01')), @($ui.LogFilter, @('*', 'System')))) {
                foreach ($tag in $pair[1]) { $i = New-Object System.Windows.Controls.ComboBoxItem; $i.Content = $tag; $i.Tag = $tag; [void]$pair[0].Items.Add($i) }
                $pair[0].SelectedIndex = 0
            }
            $ui
        }
    }

    It 'has the picture strip between the filters and the event list' {
        $xaml = New-TimelineWindowXaml
        $xaml | Should -Match '<Border x:Name="StripBorder" Grid.Row="1"'
        $xaml | Should -Match '<DataGrid x:Name="EventGrid" Grid.Row="2"'
        $xaml | Should -Match '<GridSplitter Grid.Row="3"'
    }

    It 'has the strip controls and the time range chip' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $w = [System.Windows.Markup.XamlReader]::Parse((New-TimelineWindowXaml))
        foreach ($n in 'StripBorder', 'StripScroll', 'StripCanvas', 'StripAxisNote', 'HidePictureToggle', 'TimeRangeChip', 'TimeRangeText', 'ClearRangeButton') {
            $w.FindName($n) | Should -Not -BeNullOrEmpty -Because "control $n"
        }
        $w.FindName('TimeRangeChip').Visibility | Should -Be 'Collapsed'
    }

    It 'is about 110 px for 4 servers and stops growing past 6 lanes' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $w = [System.Windows.Markup.XamlReader]::Parse((New-TimelineWindowXaml))
        Show-TimelineStrip -Window $w -Model (New-PicModel -Servers @(1..4 | ForEach-Object { "S$_" })) -Width 800
        $four = $w.FindName('StripCanvas').Height
        $four | Should -BeGreaterOrEqual 100
        $four | Should -BeLessOrEqual 120
        Show-TimelineStrip -Window $w -Model (New-PicModel -Servers @(1..6 | ForEach-Object { "S$_" })) -Width 800
        $six = $w.FindName('StripCanvas').Height
        $six | Should -Be ($four + 44)
        Show-TimelineStrip -Window $w -Model (New-PicModel -Servers @(1..10 | ForEach-Object { "S$_" })) -Width 800
        $w.FindName('StripCanvas').Height | Should -BeGreaterThan $six
        $w.FindName('StripScroll').MaxHeight | Should -Be $six
    }

    It 'draws one shape per mark, dot and down bar, each carrying its row or item' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $rows = @(
            (New-PicRow -Time '2026-11-18 17:50' -Provider 'Disk' -Id 153 -Level 3)
            (New-PicRow -Time '2026-11-18 17:51' -Level 2 -Provider 'Ntfs' -Id 5)
            (New-PicRow -Time '2026-11-18 17:52')
            (New-PicRow -Time '2026-11-18 17:58' -Level 2 -Provider 'Other' -Id 9)
            (New-PicRow -Time '2026-11-18 18:04' -Provider 'Microsoft-Windows-Kernel-Power' -Id 41 -Level 1)
        )
        $model = New-PicModel -Rows $rows
        $w = [System.Windows.Markup.XamlReader]::Parse((New-TimelineWindowXaml))
        Show-TimelineStrip -Window $w -Model $model -Width 800
        $kids = @($w.FindName('StripCanvas').Children)
        @($kids | Where-Object Uid -eq 'mark').Count | Should -Be @($model.Marks).Count
        @($kids | Where-Object Uid -eq 'dot').Count | Should -Be @($model.Dots).Count
        @($kids | Where-Object Uid -eq 'bar').Count | Should -Be 1
        $mark = @($kids | Where-Object Uid -eq 'mark')[0]
        $mark.Tag | Should -Be $model.Marks[0].RowId
        Update-TimelineStripToolTip -Element $mark
        "$($mark.ToolTip)" | Should -BeLike 'Disk I/O had to be retried*'
    }

    It 'labels the axis UTC only when the servers are in different time zones' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $w = [System.Windows.Markup.XamlReader]::Parse((New-TimelineWindowXaml))
        Show-TimelineStrip -Window $w -Model (New-PicModel -Rows @(New-PicRow -Time '2026-11-18 17:50' -Provider 'Disk' -Id 153 -Level 3)) -Width 800
        $w.FindName('StripAxisNote').Text | Should -Be '(server local time)'
        $m = New-PicModel
        $m.AxisIsUtc = $true
        Show-TimelineStrip -Window $w -Model $m -Width 800
        $w.FindName('StripAxisNote').Text | Should -Be '(UTC)'
    }

    It 'follows the Level filter' {
        $store = New-TimelineRowStore
        Add-TimelineRows -Store $store -NewRows @((New-PicRow -Time '2026-11-18 17:50' -Provider 'Disk' -Id 153 -Level 3), (New-PicRow -Time '2026-11-18 17:55' -Provider 'Microsoft-Windows-WindowsUpdateClient' -Id 19))
        $all = Get-TimelineStoreStripModel -Store $store -Filter @{ MinLevel = 'All' } -Servers @('AD-01') -StartUtc $script:P0 -EndUtc $script:P1 -Width 700
        $errors = Get-TimelineStoreStripModel -Store $store -Filter @{ MinLevel = 'Warning' } -Servers @('AD-01') -StartUtc $script:P0 -EndUtc $script:P1 -Width 700
        @($all.Marks).Count | Should -Be 2
        @($errors.Marks | ForEach-Object Shape) | Should -Be @('Triangle')
    }

    It 'maps a point on the strip back to a time' {
        Convert-TimelineStripXToUtc -X 0 -Width 700 -StartUtc $script:P0 -EndUtc $script:P1 | Should -Be $script:P0
        Convert-TimelineStripXToUtc -X 350 -Width 700 -StartUtc $script:P0 -EndUtc $script:P1 | Should -Be $script:P0.AddMinutes(10)
        Convert-TimelineStripXToUtc -X 900 -Width 700 -StartUtc $script:P0 -EndUtc $script:P1 | Should -Be $script:P1
        Convert-TimelineStripXToUtc -X -5 -Width 700 -StartUtc $script:P0 -EndUtc $script:P1 | Should -Be $script:P0
    }

    It 'takes the whole search window across servers in different time zones' {
        $window = New-TimelineWindow -Mode Around -At ([datetime]'2026-11-18 18:00') -PlusMinusMinutes 15
        $status = [ordered]@{
            'AD-01' = [PSCustomObject]@{ Server = 'AD-01'; State = 'Done'; Transport = 'WinRM'; UtcOffsetMinutes = -300 }
            'AD-03' = [PSCustomObject]@{ Server = 'AD-03'; State = 'Done'; Transport = 'WinRM'; UtcOffsetMinutes = 0 }
        }
        $span = Get-TimelineStripWindow -Window $window -Status $status
        $span.StartUtc | Should -Be ([datetime]::SpecifyKind([datetime]'2026-11-18 17:45', [DateTimeKind]::Utc))
        $span.EndUtc | Should -Be ([datetime]::SpecifyKind([datetime]'2026-11-18 23:15', [DateTimeKind]::Utc))
    }

    It 'Set-TimelineTimeRange narrows the list and shows the chip; clearing it hides the chip' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $ui = New-PicUi
        $from = [datetime]::SpecifyKind([datetime]'2026-11-18 22:52', [DateTimeKind]::Utc)
        Set-TimelineTimeRange -Ui $ui -FromUtc $from -ToUtc $from.AddMinutes(6) -OffsetMinutes -300
        $ui.TimeRangeChip.Visibility | Should -Be 'Visible'
        $ui.TimeRangeText.Text | Should -Be '17:52 - 17:58'
        $f = Get-TimelineGridFilter -Ui $ui
        $f.FromUtc | Should -Be $from
        $f.ToUtc | Should -Be $from.AddMinutes(6)
        Set-TimelineTimeRange -Ui $ui -FromUtc $null -ToUtc $null
        $ui.TimeRangeChip.Visibility | Should -Be 'Collapsed'
        (Get-TimelineGridFilter -Ui $ui).FromUtc | Should -BeNullOrEmpty
    }

    It 'a story click clears a time range that hides the row' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $ui = New-PicUi
        $row = New-PicRow -Time '2026-11-18 17:50' -Provider 'Disk' -Id 153 -Level 3
        Add-TimelineRows -Store $ui.Store -NewRows @($row)
        Set-TimelineTimeRange -Ui $ui -FromUtc $script:P1 -ToUtc $script:P1.AddMinutes(5)
        Show-TimelineStoryRow -Ui $ui -RowId (Get-TimelineRowId -Row $row) -Refresh { $ui.EventGrid.ItemsSource = @(Select-TimelineRows -Rows $ui.Store.Rows.ToArray() -Filter (Get-TimelineGridFilter -Ui $ui)) } | Should -BeTrue
        $ui.TimeRange | Should -BeNullOrEmpty
        $ui.TimeRangeChip.Visibility | Should -Be 'Collapsed'
        $ui.EventGrid.SelectedItem | Should -Be $row
    }

    It 'Show everything again clears the time range, and the chip and strip are wired up' {
        $src = Get-Content -LiteralPath $script:AppPath -Raw
        $showAll = $src.Substring($src.IndexOf('$ui.ShowAllButton.add_Click'), 400)
        $showAll | Should -Match 'Set-TimelineTimeRange -Ui \$ui -FromUtc \$null -ToUtc \$null'
        $src | Should -Match '\$ui.ClearRangeButton.add_Click'
        $view = $src.Substring($src.IndexOf('function Update-View'), 2600)
        $view | Should -Match 'Update-Strip'
    }

    It 'Hide picture folds the strip and says how to bring it back' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $w = [System.Windows.Markup.XamlReader]::Parse((New-TimelineWindowXaml))
        Set-TimelineStripHidden -Window $w -Hidden $true
        $w.FindName('StripScroll').Visibility | Should -Be 'Collapsed'
        $w.FindName('HidePictureToggle').Content | Should -Be 'Show picture'
        $w.FindName('HidePictureToggle').IsChecked | Should -BeTrue
        Set-TimelineStripHidden -Window $w -Hidden $false
        $w.FindName('StripScroll').Visibility | Should -Be 'Visible'
        $w.FindName('HidePictureToggle').Content | Should -Be 'Hide picture'
    }

    It 'does not redraw more than once in 2 seconds while results arrive' {
        $clock = [PSCustomObject]@{ IsRunning = $true; Elapsed = [TimeSpan]::FromSeconds(0.5) }
        Test-TimelineStripDue -Clock $clock -Finished $false | Should -BeFalse
        $clock.Elapsed = [TimeSpan]::FromSeconds(2.1)
        Test-TimelineStripDue -Clock $clock -Finished $false | Should -BeTrue
        $clock.Elapsed = [TimeSpan]::FromSeconds(0.1)
        Test-TimelineStripDue -Clock $clock -Finished $true | Should -BeTrue
        Test-TimelineStripDue -Clock $clock -Finished $false -Force | Should -BeTrue
        Test-TimelineStripDue -Clock ([PSCustomObject]@{ IsRunning = $false; Elapsed = [TimeSpan]::Zero }) -Finished $false | Should -BeTrue
    }
}
