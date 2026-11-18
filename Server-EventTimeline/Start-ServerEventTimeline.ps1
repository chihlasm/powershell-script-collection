#Requires -Version 5.1

<#
.SYNOPSIS
    What happened on these servers around a time? Every event from several servers, merged
    into one timeline you can filter, with the important ones flagged.

.DESCRIPTION
    Type one or more servers and a time ("around 03:00, plus or minus 15 minutes"), pick the
    logs, and press Search. Each server is read in the background (the window never freezes),
    and all events land on one timeline sorted by time. Known-important events (unexpected
    restarts, service crashes, disk errors, update installs, app crashes, blue screens, time
    jumps, low memory) are flagged in colour; nothing is hidden unless you filter it.

    Times are each server's local time (what Event Viewer on that server shows), with a UTC
    column beside them. The time you type is read as each server's local time.

    Each server shows how it went: done, done with gaps (a log stopped at the cap, timed out,
    or could not be read), couldn't reach (and why), or cancelled. A log that stopped early is
    named in a yellow banner, so a short log is never mistaken for a quiet one.

    Read-only: nothing on any server is changed. Servers are reached over WinRM (TCP 5985)
    first; if WinRM can't connect, the remote event log over RPC (TCP 135 and dynamic ports,
    "Remote Event Log Management" firewall rule) is used instead. Access denied is reported,
    not retried.

    Export the visible rows to CSV or an HTML report, or copy the selected rows as text for a
    ticket. Files go to -OutputPath (default: a Reports folder beside this script). Ticket
    note... writes the four-part ticket note (TicketNote\Join-TicketNotes.ps1 can merge it
    with the quick checks' notes) and the HTML report into the ticket's folder.

    A summary line per server sits above the grid ("APP01: 1 unexpected restart, 3 service
    failures"). Right-click a row to search every server around that event, show only that
    kind of event, hide a noisy source or show only that server. Collapse repeats turns
    hundreds of identical routine events into one row.

    With -NoGui it runs in the console instead (for RMM scripts and scheduled tasks): it reads
    the servers, prints how each went and what was found, and writes the CSV and HTML report
    (and the ticket note with -TicketNumber). Exit code 0 = every log read, 1 = a server or
    log could not be read in full, 2 = could not run (for example a time it couldn't read).

.PARAMETER ComputerName
    Servers to fill in when the window opens. You can also type them in the window. Without
    it, the list starts with this computer. This computer (by its name, FQDN, localhost, . or
    127.0.0.1) is always read directly from its own logs: no WinRM or network needed.

.PARAMETER OutputPath
    Folder for CSV/HTML exports and the activity log. Without it, the folder chosen last time
    with Browse... (remembered per user in %APPDATA%\ServerEventTimeline\settings.json) is
    used, else a Reports folder beside this script. You can also change it in the window.

.PARAMETER SmokeTest
    Opens the window off-screen, checks it built correctly, prints a [PASS] or [FAIL] line,
    and closes by itself (exit code 0 or 1). Queries no server, reads no event log, writes no
    file, touches no clipboard and asks for no administrator rights. Used by
    Tests\Invoke-SmokeTest.ps1 in the repository.

.PARAMETER LoadFunctionsOnly
    Define the functions and return without opening anything (used by the tests).

.PARAMETER NoGui
    Run in the console: no window. Use -At (with -PlusMinusMinutes), -From and -To, or
    -LastMinutes (default 60) for the time, and -ComputerName (default: this computer).

.PARAMETER At
    -NoGui: look around this time, each server's local time (yyyy-MM-dd HH:mm).

.PARAMETER PlusMinusMinutes
    -NoGui: minutes either side of -At (default 15).

.PARAMETER From
    -NoGui: start of the window, each server's local time (yyyy-MM-dd HH:mm). Needs -To.

.PARAMETER To
    -NoGui: end of the window, each server's local time (yyyy-MM-dd HH:mm). Needs -From.

.PARAMETER LastMinutes
    -NoGui: the last N minutes, when neither -At nor -From/-To is given (default 60).

.PARAMETER LogName
    -NoGui: logs to read, by their checkbox label (System, Task Scheduler, Group Policy...) or
    their log name. Default: the same logs ticked by default in the window.

.PARAMETER IncludeSecurity
    -NoGui: also read the Security log (slow on domain controllers and file servers).

.PARAMETER AllLogs
    -NoGui: also read every log on each server that has events (can be 100+ logs).

.PARAMETER Cap
    -NoGui: stop each log at this many events (default 5000).

.PARAMETER TotalCap
    -NoGui: stop each server at this many events in total (default 50000).

.PARAMETER TimeoutSec
    -NoGui: give up on a log after this many seconds (default 60).

.PARAMETER Credential
    -NoGui: read the servers with this account (the window has Run as... instead).

.PARAMETER TicketNumber
    -NoGui: write the ticket note, the CSV and the HTML report into
    <OutputPath or Documents\TicketNotes>\Ticket_<number>, the folder TicketNote's
    Join-TicketNotes.ps1 reads. Letters, digits, - or _, up to 32 characters.

.PARAMETER NoClipboard
    -NoGui with -TicketNumber: don't copy the ticket note to the clipboard.

.EXAMPLE
    .\Start-ServerEventTimeline.ps1
    Opens the window.

.EXAMPLE
    .\Start-ServerEventTimeline.ps1 -NoGui -ComputerName APP01, SQL01 -At '2026-11-17 03:00' -PlusMinusMinutes 30 -OutputPath D:\Reports
    No window: reads both servers around 03:00 and writes the CSV and HTML report to D:\Reports.

.EXAMPLE
    .\Start-ServerEventTimeline.ps1 -NoGui -ComputerName APP01 -LastMinutes 120 -TicketNumber 482113
    No window: the last two hours on APP01, with a ticket note in Documents\TicketNotes\Ticket_482113.

.EXAMPLE
    .\Start-ServerEventTimeline.ps1 -ComputerName APP01, SQL01, DC01
    Opens the window with three servers filled in.

.EXAMPLE
    powershell.exe -NoProfile -STA -File .\Start-ServerEventTimeline.ps1 -SmokeTest
    Checks the window opens on this workstation, then closes it.

.NOTES
    Version 1.0. Needs Windows PowerShell 5.1 or PowerShell 7 on Windows (WPF). Run it on an
    admin workstation with rights to read the servers' event logs (Event Log Readers or local
    admin on each server).

    Files: ServerEventTimeline.Core.ps1 (logic), ServerEventTimeline.Engine.ps1 (remote reads
    and the background engine) and this window must stay in the same folder.

    REFERENCES
    - Get-WinEvent: https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent
    - Event IDs, log channel names and error codes are cited in ServerEventTimeline.Core.ps1
      and ServerEventTimeline.Engine.ps1 next to the code that uses them.
    - SystemParameters.VirtualScreenLeft (smoke-test window placement):
      https://learn.microsoft.com/dotnet/api/system.windows.systemparameters.virtualscreenleft
    - DataGrid row virtualization: https://learn.microsoft.com/dotnet/api/system.windows.controls.datagrid.enablerowvirtualization
    - Keeping the sort when ItemsSource changes (the view's SortDescriptions are rebuilt, and
      DataGridColumn.SortDirection is only the header arrow):
      https://learn.microsoft.com/dotnet/api/system.windows.controls.datagridcolumn.sortdirection
      https://learn.microsoft.com/dotnet/api/system.windows.controls.itemcollection.sortdescriptions
    - Ticket notes: CaseKit.ps1 (copy of TicketNote\CaseKit.ps1), see TicketNote\README.md.
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName,
    [string]$OutputPath,
    [switch]$SmokeTest,
    [switch]$LoadFunctionsOnly,
    [switch]$NoGui,
    [string]$At,
    [ValidateRange(1, 1440)][int]$PlusMinusMinutes = 15,
    [string]$From,
    [string]$To,
    [ValidateRange(1, 525600)][int]$LastMinutes = 60,
    [string[]]$LogName,
    [switch]$IncludeSecurity,
    [switch]$AllLogs,
    [ValidateRange(1, 1000000)][int]$Cap = 5000,
    [ValidateRange(1, 10000000)][int]$TotalCap = 50000,
    [ValidateRange(1, 3600)][int]$TimeoutSec = 60,
    [pscredential]$Credential,
    # Checked with Test-TicketNumber (CaseKit.ps1) so a bad value gets a plain message and exit 2.
    [string]$TicketNumber,
    [switch]$NoClipboard
)

. (Join-Path $PSScriptRoot 'ServerEventTimeline.Engine.ps1')

function New-TimelineWindowXaml {
    <# The window's XAML (dark, blue accent). #>
    @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Server Event Timeline" Width="1400" Height="900" MinWidth="980" MinHeight="640"
        Background="#16181D" Foreground="#D7DCE3" FontFamily="Segoe UI" FontSize="13" WindowStartupLocation="CenterScreen">
  <Window.Resources>
    <SolidColorBrush x:Key="Panel" Color="#101216"/>
    <SolidColorBrush x:Key="Card" Color="#1C1F26"/>
    <SolidColorBrush x:Key="Input" Color="#0F1115"/>
    <SolidColorBrush x:Key="Line" Color="#262A33"/>
    <SolidColorBrush x:Key="LineStrong" Color="#343A46"/>
    <SolidColorBrush x:Key="Text" Color="#D7DCE3"/>
    <SolidColorBrush x:Key="Muted" Color="#8B94A3"/>
    <SolidColorBrush x:Key="Accent" Color="#5DADE2"/>
    <SolidColorBrush x:Key="Warn" Color="#E0B43A"/>
    <SolidColorBrush x:Key="Danger" Color="#E5534B"/>
    <Style TargetType="TextBlock"><Setter Property="Foreground" Value="{StaticResource Text}"/></Style>
    <Style x:Key="Label" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource Muted}"/><Setter Property="FontSize" Value="11"/>
      <Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Margin" Value="0,0,0,4"/>
    </Style>
    <Style TargetType="Button">
      <Setter Property="Background" Value="#232731"/><Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="BorderBrush" Value="{StaticResource LineStrong}"/><Setter Property="Padding" Value="12,6"/>
      <Setter Property="Margin" Value="0,0,8,0"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="3" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#2C313D"/></Trigger>
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="b" Property="Background" Value="#1B1F27"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/><Setter Property="Cursor" Value="Arrow"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Primary" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="#2A7AB0"/><Setter Property="BorderBrush" Value="#2A7AB0"/>
      <Setter Property="Foreground" Value="White"/><Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="{StaticResource Input}"/><Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="BorderBrush" Value="{StaticResource LineStrong}"/><Setter Property="CaretBrush" Value="{StaticResource Text}"/>
      <Setter Property="Padding" Value="6,4"/><Setter Property="VerticalContentAlignment" Value="Center"/>
      <Style.Triggers>
        <Trigger Property="IsKeyboardFocused" Value="True"><Setter Property="BorderBrush" Value="{StaticResource Accent}"/></Trigger>
        <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="CheckBox"><Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="Margin" Value="0,0,16,6"/><Setter Property="Cursor" Value="Hand"/></Style>
    <Style TargetType="RadioButton"><Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="Margin" Value="0,0,12,0"/><Setter Property="VerticalAlignment" Value="Center"/><Setter Property="Cursor" Value="Hand"/></Style>
    <Style TargetType="ComboBoxItem">
      <Setter Property="Background" Value="{StaticResource Card}"/><Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="Padding" Value="8,4"/>
      <Style.Triggers>
        <Trigger Property="IsHighlighted" Value="True"><Setter Property="Background" Value="#1F6FA8"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="ComboBox">
      <Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="Margin" Value="0,0,8,0"/><Setter Property="MinWidth" Value="120"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ComboBox">
            <Grid>
              <ToggleButton x:Name="t" Focusable="False" ClickMode="Press" IsChecked="{Binding IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}">
                <ToggleButton.Template>
                  <ControlTemplate TargetType="ToggleButton">
                    <Border x:Name="tb" Background="{StaticResource Input}" BorderBrush="{StaticResource LineStrong}" BorderThickness="1" CornerRadius="3">
                      <TextBlock Text="v" Foreground="{StaticResource Muted}" HorizontalAlignment="Right" VerticalAlignment="Center" Margin="0,0,8,0"/>
                    </Border>
                    <ControlTemplate.Triggers>
                      <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="tb" Property="BorderBrush" Value="{StaticResource Accent}"/></Trigger>
                    </ControlTemplate.Triggers>
                  </ControlTemplate>
                </ToggleButton.Template>
              </ToggleButton>
              <ContentPresenter IsHitTestVisible="False" Margin="8,5,24,5" VerticalAlignment="Center"
                                Content="{TemplateBinding SelectionBoxItem}" ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}"/>
              <Popup IsOpen="{TemplateBinding IsDropDownOpen}" Placement="Bottom" AllowsTransparency="True" Focusable="False" PopupAnimation="Fade">
                <Border Background="{StaticResource Card}" BorderBrush="{StaticResource LineStrong}" BorderThickness="1"
                        MinWidth="{Binding ActualWidth, RelativeSource={RelativeSource TemplatedParent}}" MaxHeight="320">
                  <ScrollViewer><ItemsPresenter/></ScrollViewer>
                </Border>
              </Popup>
            </Grid>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>

  <Grid Margin="16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="5"/>
      <RowDefinition Height="170"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- What to look at -->
    <Border Grid.Row="0" Background="{StaticResource Card}" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="4" Padding="14,12">
      <Grid>
        <Grid.ColumnDefinitions>
          <!-- Wide enough for the three server buttons in one row (the smoke test checks nothing is cut off). -->
          <ColumnDefinition Width="340"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <StackPanel Grid.Column="0" Margin="0,0,20,0">
          <TextBlock Style="{StaticResource Label}" Text="WHICH SERVERS?"/>
          <TextBox x:Name="ServersBox" Height="58" AcceptsReturn="True" TextWrapping="Wrap" VerticalContentAlignment="Top"
                   VerticalScrollBarVisibility="Auto" ToolTip="Server names, separated by commas, spaces or new lines"/>
          <StackPanel Orientation="Horizontal" Margin="0,8,0,0">
            <Button x:Name="ThisComputerButton" Content="This computer" ToolTip="Add this computer: its logs are read directly, no network needed"/>
            <Button x:Name="PickFromAdButton" Content="Pick from AD..." ToolTip="Add domain controllers or search Active Directory for servers"/>
            <Button x:Name="RecentButton" Content="Recent" ToolTip="Server lists you searched before (remembered per user)"/>
          </StackPanel>
        </StackPanel>
        <StackPanel Grid.Column="1" Margin="0,0,20,0">
          <TextBlock Style="{StaticResource Label}" Text="WHEN? (EACH SERVER'S LOCAL TIME)"/>
          <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
            <RadioButton x:Name="AroundRadio" Content="Around" GroupName="When" IsChecked="True"/>
            <TextBox x:Name="AtBox" Width="140" ToolTip="yyyy-MM-dd HH:mm"/>
            <TextBlock Text="  +/-  " VerticalAlignment="Center" Foreground="{StaticResource Muted}"/>
            <ComboBox x:Name="PlusMinusCombo" MinWidth="90"/>
          </StackPanel>
          <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
            <RadioButton x:Name="RangeRadio" Content="From" GroupName="When"/>
            <TextBox x:Name="FromBox" Width="140" ToolTip="yyyy-MM-dd HH:mm"/>
            <TextBlock Text="  to  " VerticalAlignment="Center" Foreground="{StaticResource Muted}"/>
            <TextBox x:Name="ToBox" Width="140" ToolTip="yyyy-MM-dd HH:mm"/>
          </StackPanel>
          <StackPanel Orientation="Horizontal">
            <Button x:Name="LastHourButton" Content="Last hour" ToolTip="Search the last 60 minutes now"/>
            <Button x:Name="Last24Button" Content="Last 24 hours" ToolTip="Search the last 24 hours now (can be a lot of events)"/>
          </StackPanel>
        </StackPanel>
        <StackPanel Grid.Column="2">
          <TextBlock Style="{StaticResource Label}" Text="WHICH LOGS?"/>
          <ToggleButton x:Name="LogsButton" HorizontalAlignment="Left" MinWidth="340" Foreground="{StaticResource Text}" Cursor="Hand" ToolTip="Choose which logs to read">
            <ToggleButton.Template>
              <ControlTemplate TargetType="ToggleButton">
                <Border x:Name="b" Background="{StaticResource Input}" BorderBrush="{StaticResource LineStrong}" BorderThickness="1" CornerRadius="3" Padding="8,5">
                  <DockPanel>
                    <TextBlock DockPanel.Dock="Right" Text="v" Foreground="{StaticResource Muted}" Margin="12,0,0,0" VerticalAlignment="Center"/>
                    <ContentPresenter VerticalAlignment="Center"/>
                  </DockPanel>
                </Border>
                <ControlTemplate.Triggers>
                  <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="{StaticResource Accent}"/></Trigger>
                  <Trigger Property="IsChecked" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="{StaticResource Accent}"/></Trigger>
                </ControlTemplate.Triggers>
              </ControlTemplate>
            </ToggleButton.Template>
          </ToggleButton>
          <Popup x:Name="LogsPopup" PlacementTarget="{Binding ElementName=LogsButton}" Placement="Bottom" StaysOpen="False"
                 AllowsTransparency="True" IsOpen="{Binding IsChecked, ElementName=LogsButton, Mode=TwoWay}">
            <Border Background="{StaticResource Card}" BorderBrush="{StaticResource LineStrong}" BorderThickness="1" CornerRadius="3" Padding="14,12" Width="480" Margin="0,4,0,0">
              <StackPanel>
                <TextBlock Style="{StaticResource Label}" Text="EVERYDAY"/>
                <UniformGrid x:Name="CoreLogPanel" Columns="2" Margin="0,0,0,8"/>
                <TextBlock Style="{StaticResource Label}" Text="EXTRA DETAIL"/>
                <UniformGrid x:Name="LogPanel" Columns="2" Margin="0,0,0,8"/>
                <TextBlock Style="{StaticResource Label}" Text="SLOW - TICK WHEN YOU NEED THEM"/>
                <UniformGrid Columns="2" Margin="0,0,0,10">
                  <CheckBox x:Name="SecurityCheck" Content="Security" ToolTip="Slow on domain controllers and file servers"/>
                  <CheckBox x:Name="AllLogsCheck" Content="All logs with events" ToolTip="Every log on the server that has events (can be 100+ logs)"/>
                </UniformGrid>
                <StackPanel Orientation="Horizontal">
                  <Button x:Name="LogsAllButton" Content="All" ToolTip="Tick every log listed here (not 'All logs with events')"/>
                  <Button x:Name="LogsNoneButton" Content="None"/>
                  <Button x:Name="LogsDefaultButton" Content="Default" ToolTip="Everyday and extra detail logs; Security off"/>
                </StackPanel>
              </StackPanel>
            </Border>
          </Popup>
          <Expander Header="More options" Foreground="{StaticResource Muted}" Margin="0,4,0,0">
            <WrapPanel Margin="0,8,0,0">
              <TextBlock Text="Stop each log at" VerticalAlignment="Center" Margin="0,0,6,0"/>
              <TextBox x:Name="CapBox" Width="70" Text="5000"/>
              <TextBlock Text="events.   Give up on a log after" VerticalAlignment="Center" Margin="6,0,6,0"/>
              <TextBox x:Name="TimeoutBox" Width="50" Text="60"/>
              <TextBlock Text="seconds." VerticalAlignment="Center" Margin="6,0,6,0"/>
              <TextBlock Text="Stop each server at" VerticalAlignment="Center" Margin="0,6,6,0"/>
              <TextBox x:Name="TotalCapBox" Width="80" Text="50000" Margin="0,6,0,0" ToolTip="A safety limit for All logs: once a server reaches this many events, its remaining logs are not read (and are named)"/>
              <TextBlock Text="events in total.   " VerticalAlignment="Center" Margin="6,6,6,0"/>
              <Button x:Name="RunAsButton" Content="Run as another account..." Margin="0,6,8,0" ToolTip="Read the servers with a different account (for example another domain)"/>
            </WrapPanel>
          </Expander>
        </StackPanel>
      </Grid>
    </Border>

    <!-- Go, and how each server is doing -->
    <Grid Grid.Row="1" Margin="0,12,0,0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Top">
        <Button x:Name="SearchButton" Style="{StaticResource Primary}" Content="Search" Padding="22,7" IsDefault="True"/>
        <Button x:Name="CancelButton" Content="Cancel" IsEnabled="False"/>
      </StackPanel>
      <StackPanel Grid.Column="1" Margin="8,0,0,0">
        <TextBlock x:Name="InputError" Foreground="{StaticResource Warn}" TextWrapping="Wrap"/>
        <ItemsControl x:Name="StatusList" Foreground="{StaticResource Text}" FontFamily="Consolas"/>
        <TextBlock x:Name="BannerText" Foreground="{StaticResource Warn}" TextWrapping="Wrap" Margin="0,4,0,0" Visibility="Collapsed"/>
        <TextBlock x:Name="TimeZoneNote" Foreground="{StaticResource Accent}" TextWrapping="Wrap" Margin="0,4,0,0" Visibility="Collapsed"/>
      </StackPanel>
    </Grid>

    <!-- What was found, then narrow it down -->
    <StackPanel Grid.Row="2" Margin="0,12,0,8">
      <Border x:Name="SummaryBorder" Background="{StaticResource Card}" BorderBrush="{StaticResource Accent}" BorderThickness="3,0,0,0"
              CornerRadius="2" Padding="12,8" Margin="0,0,0,10" Visibility="Collapsed">
        <StackPanel>
          <TextBlock Style="{StaticResource Label}" Text="WHAT WAS FOUND (EVERY EVENT READ, BEFORE FILTERS)"/>
          <ItemsControl x:Name="SummaryList" FontSize="13"/>
        </StackPanel>
      </Border>
      <WrapPanel>
        <TextBlock Text="Show" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="{StaticResource Muted}"/>
        <ComboBox x:Name="LevelFilter" MinWidth="170"/>
        <ComboBox x:Name="ServerFilter" MinWidth="150"/>
        <ComboBox x:Name="LogFilter" MinWidth="200"/>
        <CheckBox x:Name="FlaggedOnlyCheck" Content="Flagged only" VerticalAlignment="Center" Margin="4,0,12,0"/>
        <CheckBox x:Name="CollapseCheck" Content="Collapse repeats" VerticalAlignment="Center" Margin="0,0,12,0"
                  ToolTip="Show the same routine event on the same server once, with how many times it happened. Flagged events are never collapsed."/>
        <TextBox x:Name="FilterText" Width="260" ToolTip="Search message, source or event ID"/>
        <TextBlock x:Name="CountText" VerticalAlignment="Center" Margin="12,0,0,0" Foreground="{StaticResource Muted}"/>
        <TextBlock x:Name="HiddenNote" VerticalAlignment="Center" Margin="12,0,8,0" Foreground="{StaticResource Warn}" Visibility="Collapsed"/>
        <Button x:Name="ShowAllButton" Content="Show everything again" Visibility="Collapsed" ToolTip="Bring back hidden sources and leave 'only this event'"/>
      </WrapPanel>
    </StackPanel>

    <!-- The timeline -->
    <DataGrid x:Name="EventGrid" Grid.Row="3" AutoGenerateColumns="False" IsReadOnly="True" EnableRowVirtualization="True"
              EnableColumnVirtualization="True" VirtualizingPanel.IsVirtualizing="True" VirtualizingPanel.VirtualizationMode="Recycling"
              SelectionMode="Extended" SelectionUnit="FullRow" HeadersVisibility="Column" CanUserAddRows="False"
              Background="{StaticResource Panel}" RowBackground="{StaticResource Panel}" AlternatingRowBackground="#14171C"
              Foreground="{StaticResource Text}" BorderBrush="{StaticResource Line}" GridLinesVisibility="Horizontal"
              HorizontalGridLinesBrush="#1E222A" FontFamily="Segoe UI">
      <DataGrid.ColumnHeaderStyle>
        <Style TargetType="DataGridColumnHeader">
          <Setter Property="Background" Value="{StaticResource Card}"/><Setter Property="Foreground" Value="{StaticResource Muted}"/>
          <Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Padding" Value="8,6"/>
          <Setter Property="BorderBrush" Value="{StaticResource Line}"/><Setter Property="BorderThickness" Value="0,0,1,1"/>
        </Style>
      </DataGrid.ColumnHeaderStyle>
      <DataGrid.RowStyle>
        <Style TargetType="DataGridRow">
          <Style.Triggers>
            <DataTrigger Binding="{Binding Level}" Value="1"><Setter Property="Foreground" Value="{StaticResource Danger}"/></DataTrigger>
            <DataTrigger Binding="{Binding Level}" Value="2"><Setter Property="Foreground" Value="{StaticResource Danger}"/></DataTrigger>
            <DataTrigger Binding="{Binding Level}" Value="3"><Setter Property="Foreground" Value="{StaticResource Warn}"/></DataTrigger>
            <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="#1F6FA8"/><Setter Property="Foreground" Value="White"/></Trigger>
          </Style.Triggers>
        </Style>
      </DataGrid.RowStyle>
      <DataGrid.CellStyle>
        <Style TargetType="DataGridCell">
          <Setter Property="BorderThickness" Value="0"/><Setter Property="Padding" Value="6,3"/>
          <Setter Property="Template">
            <Setter.Value>
              <ControlTemplate TargetType="DataGridCell">
                <Border Padding="{TemplateBinding Padding}" Background="Transparent"><ContentPresenter/></Border>
              </ControlTemplate>
            </Setter.Value>
          </Setter>
        </Style>
      </DataGrid.CellStyle>
      <DataGrid.Columns>
        <DataGridTextColumn Header="Time (server local)" Binding="{Binding TimeServerLocal, StringFormat=yyyy-MM-dd HH:mm:ss}" Width="140"/>
        <DataGridTextColumn Header="UTC" Binding="{Binding TimeUtc, StringFormat=HH:mm:ss}" Width="70"/>
        <DataGridTextColumn Header="Server" Binding="{Binding Server}" Width="110"/>
        <DataGridTextColumn Header="Level" Binding="{Binding LevelName}" Width="85"/>
        <DataGridTextColumn Header="Flag" Binding="{Binding Flag}" Width="210">
          <DataGridTextColumn.ElementStyle>
            <Style TargetType="TextBlock"><Setter Property="Foreground" Value="#5DADE2"/><Setter Property="FontWeight" Value="SemiBold"/></Style>
          </DataGridTextColumn.ElementStyle>
        </DataGridTextColumn>
        <DataGridTextColumn Header="Source" Binding="{Binding Provider}" Width="190"/>
        <DataGridTextColumn Header="ID" Binding="{Binding EventId}" Width="60"/>
        <DataGridTextColumn Header="Log" Binding="{Binding Log}" Width="110"/>
        <DataGridTextColumn Header="Message" Binding="{Binding MessageFirstLine}" Width="*"/>
      </DataGrid.Columns>
    </DataGrid>

    <GridSplitter Grid.Row="4" HorizontalAlignment="Stretch" Background="{StaticResource Line}" Cursor="SizeNS"/>

    <!-- Everything about the selected event -->
    <TextBox x:Name="DetailText" Grid.Row="5" IsReadOnly="True" TextWrapping="Wrap" VerticalContentAlignment="Top"
             VerticalScrollBarVisibility="Auto" FontFamily="Consolas" Background="{StaticResource Panel}"
             Text="Select an event to see everything about it here."/>

    <!-- Get it into the ticket -->
    <StackPanel Grid.Row="6" Margin="0,10,0,0">
      <DockPanel LastChildFill="True" Margin="0,0,0,8">
        <TextBlock DockPanel.Dock="Left" Text="Save reports to:" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="{StaticResource Muted}"/>
        <Button x:Name="OpenFolderButton" DockPanel.Dock="Right" Content="Open folder" Margin="8,0,0,0" ToolTip="Open this folder in File Explorer"/>
        <Button x:Name="BrowseFolderButton" DockPanel.Dock="Right" Content="Browse..." Margin="8,0,0,0" ToolTip="Pick the folder for exports (remembered for next time)"/>
        <TextBox x:Name="SaveFolderBox" ToolTip="Folder for CSV and HTML exports and the activity log. Created on the first export if it doesn't exist."/>
      </DockPanel>
      <DockPanel LastChildFill="True">
        <StackPanel DockPanel.Dock="Left" Orientation="Horizontal">
          <Button x:Name="ExportCsvButton" Content="Export CSV" IsEnabled="False" ToolTip="Save the rows you can see as a CSV file"/>
          <Button x:Name="ExportHtmlButton" Content="Export HTML report" IsEnabled="False" ToolTip="Save a report with the rows you can see and how each server went"/>
          <Button x:Name="CopyButton" Content="Copy selected rows" IsEnabled="False" ToolTip="Copy the selected rows as text, to paste into a ticket or an email"/>
          <!-- ShowOnDisabled: the button is disabled until a search finishes, which is when people hover to find out what it does. -->
          <Button x:Name="TicketNoteButton" Content="Copy summary for ticket..." IsEnabled="False" ToolTipService.ShowOnDisabled="True"
                  ToolTip="Asks for the ticket number, then writes a short summary you can paste into the ticket:&#10;- what was found on each server&#10;- what's ruled out&#10;- what couldn't be checked&#10;- what to do next&#10;&#10;The summary is copied to the clipboard and saved with the HTML report in&#10;Documents\TicketNotes\Ticket_&lt;number&gt;.&#10;&#10;Run a search first."/>
        </StackPanel>
        <TextBlock x:Name="StatusMessage" VerticalAlignment="Center" Margin="8,0,0,0" Foreground="{StaticResource Muted}" TextTrimming="CharacterEllipsis"/>
      </DockPanel>
    </StackPanel>
  </Grid>
</Window>
'@
}

function Get-TimelineWindowText {
    <# The window in words, for the log and the report. #>
    param([Parameter(Mandatory)]$Window, [int]$PlusMinusMinutes)
    switch ($Window.Mode) {
        'Around' {
            $center = $Window.StartLocal.AddMinutes(($Window.EndLocal - $Window.StartLocal).TotalMinutes / 2)
            'Around {0:yyyy-MM-dd HH:mm} +/- {1} min (each server''s local time)' -f $center, [int](($Window.EndLocal - $Window.StartLocal).TotalMinutes / 2)
        }
        'Range' { 'From {0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm} (each server''s local time)' -f $Window.StartLocal, $Window.EndLocal }
        'Relative' { 'The last {0} minutes' -f $Window.LastMinutes }
    }
}

function Invoke-TimelineSearch {
    <# Starts the background engine for one search request (Run as credential included). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Request, [string[]]$Logs, [bool]$AllLogs, [pscredential]$Credential, [hashtable]$EngineOptions = @{})
    $totalCap = if ($Request.PSObject.Properties['TotalCap'] -and $Request.TotalCap -gt 0) { [int]$Request.TotalCap } else { 50000 }
    Start-TimelineEngine -Servers $Request.Servers -Window $Request.Window -SelectedLogs $Logs -AllLogs:$AllLogs `
        -Cap $Request.Cap -ServerTotalCap $totalCap -TimeoutSec $Request.TimeoutSec -Credential $Credential @EngineOptions
}

function Get-GridRowKey {
    # Server|Log|RecordId: the same event, even when a collapsed row is rebuilt as a new object.
    param($Row)
    '{0}|{1}|{2}' -f $Row.Server, $Row.Log, $Row.RecordId
}

function Set-GridItemsPreservingState {
    <#
        Replaces the grid's rows without losing what the tech was doing: the column they sorted
        by and the rows they selected. Setting ItemsSource rebuilds the view, which drops its
        SortDescriptions, and the header arrow (DataGridColumn.SortDirection) is only a display.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Grid, [object[]]$Items, [int]$MaxRestore = 200)
    $sorts = @($Grid.Items.SortDescriptions | ForEach-Object { $_ })
    $arrows = @($Grid.Columns | Where-Object { $null -ne $_.SortDirection } | ForEach-Object { [PSCustomObject]@{ Column = $_; Direction = $_.SortDirection } })
    # Each SelectedItems.Add raises SelectionChanged, so restoring thousands of rows (Ctrl+A)
    # would freeze the window: above MaxRestore only the row with focus is kept.
    $selected = New-Object 'System.Collections.Generic.HashSet[string]'
    $selectedCount = $Grid.SelectedItems.Count
    if ($selectedCount -gt $MaxRestore) {
        if ($Grid.SelectedItem) { [void]$selected.Add((Get-GridRowKey $Grid.SelectedItem)) }
    }
    else {
        foreach ($s in @($Grid.SelectedItems)) { [void]$selected.Add((Get-GridRowKey $s)) }
    }

    $Grid.ItemsSource = $Items

    if ($sorts.Count -gt 0) {
        $Grid.Items.SortDescriptions.Clear()
        foreach ($sd in $sorts) { $Grid.Items.SortDescriptions.Add($sd) }
    }
    foreach ($a in $arrows) { $a.Column.SortDirection = $a.Direction }
    if ($selected.Count -gt 0) {
        $left = $selected.Count
        foreach ($r in @($Items)) {
            # Key built inline: a function call per row is too slow for 50,000 rows.
            if ($selected.Contains(('{0}|{1}|{2}' -f $r.Server, $r.Log, $r.RecordId))) {
                [void]$Grid.SelectedItems.Add($r)
                if (--$left -le 0) { break }
            }
        }
    }
}

function Invoke-TimelineConsole {
    <#
        -NoGui: reads the servers without a window, prints how each went and what was found,
        writes the CSV, the HTML report and a log (and a ticket note with -TicketNumber).
        Returns the exit code: 0 every log read, 1 something couldn't be read in full,
        2 couldn't run.
    #>
    [CmdletBinding()]
    param(
        [string[]]$ComputerName,
        [string]$At, [int]$PlusMinusMinutes = 15, [string]$From, [string]$To, [int]$LastMinutes = 60,
        [string[]]$LogName, [switch]$IncludeSecurity, [switch]$AllLogs,
        [int]$Cap = 5000, [int]$TotalCap = 50000, [int]$TimeoutSec = 60,
        [pscredential]$Credential,
        [string]$OutputPath,
        [Parameter(Mandatory)][string]$DefaultOutputPath,
        [string]$TicketNumber,
        [switch]$NoClipboard,
        [hashtable]$EngineOptions = @{},
        [int]$PollMs = 250
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $say = {
        param([string]$Level, [string]$Message)
        $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$Level]
        Write-Host "[$Level] $Message" -ForegroundColor $color
        $lines.Add(('{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message))
    }

    # What to read
    $serversText = if (@($ComputerName).Count -gt 0) { @($ComputerName) -join ',' } else { @(Get-LocalComputerNames)[0] }
    $mode = if ($From -or $To) { 'Range' } elseif ($At) { 'Around' } else { 'Relative' }
    $req = ConvertFrom-TimelineInputs -ServersText $serversText -Mode $mode -AtText $At -PlusMinusMinutes $PlusMinusMinutes `
        -FromText $From -ToText $To -LastMinutes $LastMinutes -CapText ([string]$Cap) -TimeoutText ([string]$TimeoutSec) -TotalCapText ([string]$TotalCap)
    if (-not $req.Ok) { & $say FAIL $req.Message; return 2 }
    if ($TicketNumber -and -not (Test-TicketNumber -TicketNumber $TicketNumber)) {
        & $say FAIL "'$TicketNumber' is not a usable ticket number. Use letters, digits, - or _ (up to 32 characters, starting with a letter or digit), for example 482113."
        return 2
    }
    $logs = @(Resolve-TimelineLogNames -Names $LogName)
    if ($IncludeSecurity -and $logs -notcontains 'Security') { $logs += 'Security' }

    # Where the files go
    try {
        if ($TicketNumber) {
            $root = if ($OutputPath) { $OutputPath } else { Get-TicketNoteDefaultRoot }
            $folder = Resolve-TicketFolder -TicketNumber $TicketNumber -Root $root
        }
        else {
            $folder = if ($OutputPath) { $OutputPath } else { $DefaultOutputPath }
            if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop | Out-Null }
        }
    }
    catch { & $say FAIL "Couldn't create the output folder: $($_.Exception.Message)"; return 2 }

    $windowText = Get-TimelineWindowText -Window $req.Window
    & $say INFO ('Searching {0} server(s): {1}. {2}. Logs: {3}{4}' -f $req.Servers.Count, ($req.Servers -join ', '), $windowText,
        ($logs -join ', '), $(if ($AllLogs) { ' + all logs with events' } else { '' }))

    # Read, the same background engine as the window
    $engine = Invoke-TimelineSearch -Request $req -Logs $logs -AllLogs ([bool]$AllLogs) -Credential $Credential -EngineOptions $EngineOptions
    $store = New-TimelineRowStore
    $reported = @{}
    try {
        do {
            $u = Update-TimelineEngine -Engine $engine
            if (@($u.NewRows).Count -gt 0) { Add-TimelineRows -Store $store -NewRows @($u.NewRows) }
            foreach ($s in $engine.Status.Values) {
                if ($reported.ContainsKey($s.Server) -or $s.State -in @('Waiting', 'Querying')) { continue }
                $reported[$s.Server] = $true
                switch ($s.State) {
                    'Done'         { & $say PASS ('{0}: {1:N0} events (via {2})' -f $s.Server, $s.EventCount, $s.Transport) }
                    'DoneWithGaps' { & $say WARN ('{0}: {1:N0} events, some logs incomplete (via {2})' -f $s.Server, $s.EventCount, $s.Transport) }
                    'Unreachable'  { & $say FAIL ("{0}: couldn't reach - {1}" -f $s.Server, $s.Reason) }
                    default        { & $say WARN ('{0}: {1}' -f $s.Server, $s.State) }
                }
            }
            if (-not $u.Finished) { Start-Sleep -Milliseconds $PollMs }
        } until ($u.Finished)
    }
    finally { Close-TimelineEngine -Engine $engine }

    $rows = $store.Rows.ToArray()
    $summary = @(Get-TimelineSummaryLines -Rows $rows -Status $engine.Status -Logs $logs `
            -SecurityHint 'Security log not read: add -IncludeSecurity for sign-in or lockout problems.')
    foreach ($line in $summary) { & $say INFO "Found - $line" }
    $banner = Get-TimelineBannerText -Status $engine.Status
    foreach ($line in @($banner -split [Environment]::NewLine | Where-Object { $_ })) { & $say WARN $line }

    # Files
    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $htmlPath = Join-Path $folder "ServerEventTimeline_$stamp.html"
    try {
        Export-TimelineCsv -Rows $rows -Path (Join-Path $folder "ServerEventTimeline_$stamp.csv")
        $context = @{
            WindowText = $windowText; Servers = $req.Servers; Logs = $logs; FiltersText = 'none (console mode: every event read)'
            GeneratedAt = Get-Date; ServerOutcomes = @($engine.Status.Values); Summary = $summary
        }
        [System.IO.File]::WriteAllText($htmlPath, (ConvertTo-TimelineHtml -Rows $rows -Context $context), (New-Object System.Text.UTF8Encoding $true))
        & $say PASS ('Saved {0:N0} events to {1}' -f $rows.Count, $folder)
    }
    catch { & $say FAIL "Couldn't save the report: $($_.Exception.Message)" }

    if ($TicketNumber) {
        $note = New-TimelineTicketNote -Status $engine.Status -Rows $rows -WindowText $windowText -Logs $logs -EvidencePaths @($htmlPath)
        $null = Publish-TicketNote -Note $note -Folder $folder -PasteSafe -NoClipboard:$NoClipboard
    }

    try { [System.IO.File]::WriteAllLines((Join-Path $folder "ServerEventTimeline_$stamp.log"), $lines.ToArray(), (New-Object System.Text.UTF8Encoding $true)) } catch { }

    # Exit 0 only when every server is Done and had at least one log read, so a mistyped
    # -LogName (skipped as "doesn't exist") can't pass as success.
    $incomplete = @($engine.Status.Values | Where-Object {
            $_.State -ne 'Done' -or @($_.Logs | Where-Object Outcome -eq 'Read').Count -eq 0
        }).Count
    if ($incomplete -gt 0) { return 1 }
    return 0
}

function Set-SmokeWindowPosition {
    # Beyond the top-left of the virtual screen, so it renders without being seen or taking focus.
    param([Parameter(Mandatory)]$Window)
    $Window.WindowStartupLocation = 'Manual'
    $Window.ShowInTaskbar = $false
    $Window.ShowActivated = $false
    $Window.Left = [System.Windows.SystemParameters]::VirtualScreenLeft - $Window.Width - 200
    $Window.Top = [System.Windows.SystemParameters]::VirtualScreenTop - $Window.Height - 200
}

function Get-ClippedRowItems {
    <#
        Names of controls cut off at the right edge of a horizontal row (StackPanel) after the
        window has rendered. A StackPanel never shrinks or wraps its children: whatever does not
        fit is clipped silently, which is how the Recent button lost half its label.
    #>
    param([Parameter(Mandatory)]$Root)
    $found = New-Object System.Collections.ArrayList
    $stack = New-Object System.Collections.Stack
    $stack.Push($Root)
    while ($stack.Count -gt 0) {
        $node = $stack.Pop()
        # The row itself reports its full width; the cut happens in the panel that holds it, so
        # measure each child's right edge against that container.
        $container = if ($node -is [System.Windows.FrameworkElement]) { $node.Parent } else { $null }
        if ($node -is [System.Windows.Controls.StackPanel] -and $node.Orientation -eq 'Horizontal' -and $node.IsVisible -and
            $container -is [System.Windows.Controls.Panel]) {
            foreach ($child in $node.Children) {
                if ($child -isnot [System.Windows.FrameworkElement] -or -not $child.IsVisible) { continue }
                $right = $child.TranslatePoint((New-Object System.Windows.Point ($child.ActualWidth, 0)), $container).X
                if ($right -gt $container.ActualWidth + 0.5) {
                    $label = if ($child.Name) { $child.Name } elseif ($child -is [System.Windows.Controls.ContentControl]) { "$($child.Content)" } else { $child.GetType().Name }
                    [void]$found.Add($label)
                }
            }
        }
        if ($node -is [System.Windows.Media.Visual]) {
            $count = [System.Windows.Media.VisualTreeHelper]::GetChildrenCount($node)
            for ($i = 0; $i -lt $count; $i++) { $stack.Push([System.Windows.Media.VisualTreeHelper]::GetChild($node, $i)) }
        }
    }
    return $found.ToArray()
}

function Show-ServerEventTimeline {
    <# Opens the window. Returns the exit code (smoke test: 0 pass, 1 fail; otherwise 0). #>
    [CmdletBinding()]
    param(
        [string[]]$ComputerName,
        [string]$OutputPath,
        [Parameter(Mandatory)][string]$DefaultOutputPath,
        [string]$SettingsPath = (Get-TimelineSettingsPath),
        [switch]$SmokeTest
    )

    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

    $window = [System.Windows.Markup.XamlReader]::Parse((New-TimelineWindowXaml))
    $ui = @{
        Window = $window; Smoke = [bool]$SmokeTest; SmokeFailures = New-Object System.Collections.ArrayList
        Engine = $null; Store = (New-TimelineRowStore); PendingRows = New-Object System.Collections.Generic.List[object]
        LastRebuild = [Diagnostics.Stopwatch]::StartNew(); Reported = @{}; Finished = $true
        OutputPath = $OutputPath; LogFile = $null; Credential = $null; LogChecks = @(); ExitCode = 0
        Request = $null; Selected = @()
        Hidden = New-Object System.Collections.Generic.List[string]; EventKey = ''; VisibleRows = @(); InUpdate = $false
        Restoring = $false; SummaryKey = ''
    }
    foreach ($name in 'SummaryBorder', 'SummaryList', 'CollapseCheck', 'HiddenNote', 'ShowAllButton', 'TotalCapBox', 'RecentButton', 'TicketNoteButton', 'LogsButton','LogsPopup', 'CoreLogPanel', 'LogsAllButton', 'LogsNoneButton', 'LogsDefaultButton',
        'SaveFolderBox', 'BrowseFolderButton', 'OpenFolderButton', 'ThisComputerButton', 'ServersBox', 'AroundRadio', 'RangeRadio', 'AtBox', 'PlusMinusCombo', 'FromBox', 'ToBox', 'LastHourButton',
        'Last24Button', 'LogPanel', 'SecurityCheck', 'AllLogsCheck', 'CapBox', 'TimeoutBox', 'RunAsButton', 'PickFromAdButton',
        'SearchButton', 'CancelButton', 'InputError', 'StatusList', 'BannerText', 'TimeZoneNote', 'LevelFilter', 'ServerFilter',
        'LogFilter', 'FlaggedOnlyCheck', 'FilterText', 'CountText', 'EventGrid', 'DetailText', 'ExportCsvButton', 'ExportHtmlButton',
        'CopyButton', 'StatusMessage') {
        $ui[$name] = $window.FindName($name)
    }

    function Write-TimelineLog {
        param([ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Level, [string]$Message)
        $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$Level]
        $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
        Write-Host "[$Level] $Message" -ForegroundColor $color
        if ($ui.Smoke) { return }
        try {
            if (-not $ui.LogFile) {
                if (-not (Test-Path -LiteralPath $ui.OutputPath)) { New-Item -ItemType Directory -Path $ui.OutputPath -Force | Out-Null }
                $ui.LogFile = Join-Path $ui.OutputPath ('ServerEventTimeline_{0}.log' -f (Get-Date -Format 'yyyy-MM-dd_HHmmss'))
            }
            Add-Content -LiteralPath $ui.LogFile -Value $line -Encoding UTF8
        }
        catch { }
    }

    function Set-StatusMessage { param([string]$Text) $ui.StatusMessage.Text = $Text }

    # Inputs: defaults
    $now = Get-Date
    # Starts with this computer filled in when no servers were given.
    $ui.ServersBox.Text = if (@($ComputerName).Count -gt 0) { (@($ComputerName) -join ', ') } else { @(Get-LocalComputerNames)[0] }
    $ui.AtBox.Text = $now.ToString('yyyy-MM-dd HH:mm')
    $ui.FromBox.Text = $now.AddHours(-1).ToString('yyyy-MM-dd HH:mm')
    $ui.ToBox.Text = $now.ToString('yyyy-MM-dd HH:mm')
    foreach ($pm in @(@('5 min', 5), @('15 min', 15), @('30 min', 30), @('1 hour', 60), @('2 hours', 120), @('6 hours', 360))) {
        $item = New-Object System.Windows.Controls.ComboBoxItem
        $item.Content = $pm[0]; $item.Tag = $pm[1]
        [void]$ui.PlusMinusCombo.Items.Add($item)
    }
    $ui.PlusMinusCombo.SelectedIndex = 1

    $checks = New-Object System.Collections.ArrayList
    foreach ($log in @(Get-TimelineLogCatalog | Where-Object { $_.Group -ne 'Security' })) {
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Content = $log.Label; $cb.Tag = $log.Name; $cb.IsChecked = [bool]$log.Default; $cb.ToolTip = $log.Name
        if ($log.Group -eq 'Core') { [void]$ui.CoreLogPanel.Children.Add($cb) } else { [void]$ui.LogPanel.Children.Add($cb) }
        [void]$checks.Add($cb)
    }
    $ui.LogChecks = $checks.ToArray()
    $ui.LogDefaults = @{}
    foreach ($log in @(Get-TimelineLogCatalog)) { $ui.LogDefaults[$log.Name] = [bool]$log.Default }

    function Update-LogsSummary {
        $labels = @($ui.LogChecks | Where-Object { $_.IsChecked } | ForEach-Object { [string]$_.Content })
        if ($ui.SecurityCheck.IsChecked) { $labels += 'Security' }
        $ui.LogsButton.Content = Get-LogSelectionSummary -Labels $labels -AllLogs:([bool]$ui.AllLogsCheck.IsChecked)
    }
    foreach ($cb in @($ui.LogChecks) + @($ui.SecurityCheck, $ui.AllLogsCheck)) { $cb.add_Click({ Update-LogsSummary }) }
    $ui.LogsAllButton.add_Click({
            foreach ($cb in $ui.LogChecks) { $cb.IsChecked = $true }
            $ui.SecurityCheck.IsChecked = $true
            Update-LogsSummary
        })
    $ui.LogsNoneButton.add_Click({
            foreach ($cb in $ui.LogChecks) { $cb.IsChecked = $false }
            $ui.SecurityCheck.IsChecked = $false; $ui.AllLogsCheck.IsChecked = $false
            Update-LogsSummary
        })
    $ui.LogsDefaultButton.add_Click({
            foreach ($cb in $ui.LogChecks) { $cb.IsChecked = [bool]$ui.LogDefaults[[string]$cb.Tag] }
            $ui.SecurityCheck.IsChecked = $false; $ui.AllLogsCheck.IsChecked = $false
            Update-LogsSummary
        })
    # Clicking the dropdown button while the list is open: the list closes on mouse-down,
    # so ignore the click that would immediately reopen it.
    $ui.LogsClosedAt = [datetime]::MinValue
    $ui.LogsPopup.add_Closed({ $ui.LogsClosedAt = Get-Date })
    $ui.LogsButton.add_PreviewMouseLeftButtonDown({
            if (((Get-Date) - $ui.LogsClosedAt).TotalMilliseconds -lt 250) { $_.Handled = $true }
        })
    Update-LogsSummary

    # Where exports go: -OutputPath, else the folder remembered from last time, else Reports.
    $remembered = if ($ui.Smoke) { '' } else { (Read-TimelineSettings -Path $SettingsPath).SaveFolder }
    $ui.OutputPath = Resolve-TimelineOutputFolder -OutputPath $OutputPath -Remembered $remembered -Default $DefaultOutputPath
    $ui.SaveFolderBox.Text = $ui.OutputPath
    function Sync-SaveFolder {
        $typed = $ui.SaveFolderBox.Text.Trim()
        $folder = if ($typed) { $typed } else { $DefaultOutputPath }
        if ($folder -ne $ui.OutputPath) { $ui.OutputPath = $folder; $ui.LogFile = $null }
        if (-not $typed) { $ui.SaveFolderBox.Text = $folder }
    }
    $ui.SaveFolderBox.add_LostFocus({ Sync-SaveFolder })
    $ui.BrowseFolderButton.add_Click({
            if ($ui.Smoke) { return }
            Add-Type -AssemblyName System.Windows.Forms
            $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
            $dialog.Description = 'Folder for Server Event Timeline exports'
            $dialog.ShowNewFolderButton = $true
            if (Test-Path -LiteralPath $ui.OutputPath -PathType Container) { $dialog.SelectedPath = $ui.OutputPath }
            if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $ui.SaveFolderBox.Text = $dialog.SelectedPath
                Sync-SaveFolder
                try { Save-TimelineSettings -Path $SettingsPath -SaveFolder $ui.OutputPath } catch { }
                Set-StatusMessage "Exports will be saved to $($ui.OutputPath)"
            }
            $dialog.Dispose()
        })
    $ui.OpenFolderButton.add_Click({
            if ($ui.Smoke) { return }
            Sync-SaveFolder
            if (Test-Path -LiteralPath $ui.OutputPath -PathType Container) { Start-Process -FilePath explorer.exe -ArgumentList "`"$($ui.OutputPath)`"" }
            else { Set-StatusMessage "That folder doesn't exist yet. It's created on the first export." }
        })

    foreach ($lv in @(@('All levels', 'All'), @('Warnings and worse', 'Warning'), @('Errors and worse', 'Error'), @('Critical only', 'Critical'))) {
        $item = New-Object System.Windows.Controls.ComboBoxItem
        $item.Content = $lv[0]; $item.Tag = $lv[1]
        [void]$ui.LevelFilter.Items.Add($item)
    }
    $ui.LevelFilter.SelectedIndex = 0

    function Set-ChoiceItems {
        # Refills a filter combo with "All ..." plus names, keeping the current choice.
        param($Combo, [string]$AllLabel, [string[]]$Names)
        $current = if ($Combo.SelectedItem) { [string]$Combo.SelectedItem.Tag } else { '*' }
        $existing = @($Combo.Items | ForEach-Object { [string]$_.Tag })
        $wanted = @('*') + @($Names | Sort-Object -Unique)
        if (($existing -join '|') -eq ($wanted -join '|')) { return }
        $Combo.Items.Clear()
        foreach ($n in $wanted) {
            $item = New-Object System.Windows.Controls.ComboBoxItem
            $item.Content = if ($n -eq '*') { $AllLabel } else { $n }; $item.Tag = $n
            [void]$Combo.Items.Add($item)
        }
        $index = [Array]::IndexOf($wanted, $current)
        $Combo.SelectedIndex = if ($index -ge 0) { $index } else { 0 }
    }
    Set-ChoiceItems -Combo $ui.ServerFilter -AllLabel 'All servers' -Names @()
    Set-ChoiceItems -Combo $ui.LogFilter -AllLabel 'All logs' -Names @()

    function Get-InputRequest {
        param([string]$Mode, [int]$LastMinutes = 60)
        if (-not $Mode) { $Mode = if ($ui.RangeRadio.IsChecked) { 'Range' } else { 'Around' } }
        ConvertFrom-TimelineInputs -ServersText $ui.ServersBox.Text -Mode $Mode -AtText $ui.AtBox.Text `
            -PlusMinusMinutes ([int]$ui.PlusMinusCombo.SelectedItem.Tag) -FromText $ui.FromBox.Text -ToText $ui.ToBox.Text `
            -LastMinutes $LastMinutes -CapText $ui.CapBox.Text -TimeoutText $ui.TimeoutBox.Text -TotalCapText $ui.TotalCapBox.Text
    }

    function Update-InputState {
        $around = [bool]$ui.AroundRadio.IsChecked
        $ui.AtBox.IsEnabled = $around; $ui.PlusMinusCombo.IsEnabled = $around
        $ui.FromBox.IsEnabled = -not $around; $ui.ToBox.IsEnabled = -not $around
        $running = $ui.Engine -and -not $ui.Finished
        $req = Get-InputRequest
        $ui.InputError.Text = if ($req.Ok) { '' } else { $req.Message }
        $ui.SearchButton.IsEnabled = $req.Ok -and -not $running
        $serversOk = @(ConvertTo-ServerList -Text $ui.ServersBox.Text).Count -gt 0
        $ui.LastHourButton.IsEnabled = $serversOk -and -not $running
        $ui.Last24Button.IsEnabled = $serversOk -and -not $running
        $ui.CancelButton.IsEnabled = [bool]$running
        $ui.TicketNoteButton.IsEnabled = [bool]($ui.Engine -and $ui.Finished)
    }

    function Get-CurrentFilter {
        @{
            MinLevel    = [string]$ui.LevelFilter.SelectedItem.Tag
            Server      = if ($ui.ServerFilter.SelectedItem) { [string]$ui.ServerFilter.SelectedItem.Tag } else { '*' }
            Log         = if ($ui.LogFilter.SelectedItem) { [string]$ui.LogFilter.SelectedItem.Tag } else { '*' }
            FlaggedOnly   = [bool]$ui.FlaggedOnlyCheck.IsChecked
            Text          = $ui.FilterText.Text
            HiddenSources = $ui.Hidden.ToArray()
            EventKey      = $ui.EventKey
        }
    }

    function Update-Summary {
        # The strip above the grid: what was found on each server, from every event read.
        if (-not $ui.Engine) { $ui.SummaryBorder.Visibility = 'Collapsed'; return }
        # Recounted only when rows arrived or a server's state changed (not on every filter change).
        $key = '{0}|{1}' -f $ui.Store.Rows.Count, (@($ui.Engine.Status.Values | ForEach-Object { "$($_.Server)=$($_.State)" }) -join ',')
        if ($key -eq $ui.SummaryKey) { return }
        $ui.SummaryKey = $key
        $ui.SummaryList.ItemsSource = @(Get-TimelineSummaryLines -Rows $ui.Store.Rows.ToArray() -Status $ui.Engine.Status -Logs $ui.Selected `
                -ErrorHint " - set Show to 'Errors and worse' to review them" `
                -SecurityHint "Security log not read: tick it under Which logs? to see sign-in or lockout problems.")
        $ui.SummaryBorder.Visibility = 'Visible'
    }

    function Update-HiddenNote {
        $parts = @()
        if ($ui.Hidden.Count -gt 0) { $parts += 'Hidden: {0}' -f ($ui.Hidden -join ', ') }
        if ($ui.EventKey) { $parts += 'Only: {0}' -f ($ui.EventKey -replace '\|', ' event ') }
        $ui.HiddenNote.Text = $parts -join '   '
        $shown = if ($parts.Count -gt 0) { 'Visible' } else { 'Collapsed' }
        $ui.HiddenNote.Visibility = $shown
        $ui.ShowAllButton.Visibility = $shown
    }

    function Update-View {
        # Merges rows that arrived, re-applies the filter and refreshes the grid, keeping the
        # tech's sort and selection. Refilling a filter combo fires SelectionChanged, which
        # would call this again mid-update: the InUpdate guard skips that nested call.
        if ($ui.InUpdate) { return }
        $ui.InUpdate = $true
        try {
            if ($ui.PendingRows.Count -gt 0) {
                Add-TimelineRows -Store $ui.Store -NewRows $ui.PendingRows.ToArray()
                $ui.PendingRows.Clear()
                Set-ChoiceItems -Combo $ui.LogFilter -AllLabel 'All logs' -Names @($ui.Store.Logs)
            }
            $visible = @(Select-TimelineRows -Rows $ui.Store.Rows.ToArray() -Filter (Get-CurrentFilter))
            $ui.VisibleRows = $visible
            # @() around the whole if: assigning an if unrolls a one-row array, and a single
            # PSCustomObject has no .Count on Windows PowerShell.
            $shown = @(if ($ui.CollapseCheck.IsChecked) { Group-TimelineRepeats -Rows $visible } else { $visible })
            $ui.Restoring = $true
            try { Set-GridItemsPreservingState -Grid $ui.EventGrid -Items $shown }
            finally { $ui.Restoring = $false }
            $ui.CopyButton.IsEnabled = $ui.EventGrid.SelectedItems.Count -gt 0
            $ui.CountText.Text = if ($shown.Count -ne $visible.Count) {
                'Showing {0:N0} of {1:N0} events ({2:N0} rows after collapsing repeats)' -f $visible.Count, $ui.Store.Rows.Count, $shown.Count
            }
            else { 'Showing {0:N0} of {1:N0} events' -f $visible.Count, $ui.Store.Rows.Count }
            $has = $visible.Count -gt 0
            $ui.ExportCsvButton.IsEnabled = $has
            $ui.ExportHtmlButton.IsEnabled = $has
            Update-Summary
            Update-HiddenNote
            $ui.LastRebuild.Restart()
        }
        finally { $ui.InUpdate = $false }
    }

    function Update-StatusPanel {
        if (-not $ui.Engine) { return }
        $status = $ui.Engine.Status
        $ui.StatusList.ItemsSource = @(Get-TimelineStatusLines -Status $status)
        $banner = Get-TimelineBannerText -Status $status
        $ui.BannerText.Text = $banner
        $ui.BannerText.Visibility = if ($banner) { 'Visible' } else { 'Collapsed' }
        $note = Get-TimelineTimeZoneNote -Status $status
        $ui.TimeZoneNote.Text = [string]$note
        $ui.TimeZoneNote.Visibility = if ($note) { 'Visible' } else { 'Collapsed' }
        Set-ChoiceItems -Combo $ui.ServerFilter -AllLabel 'All servers' -Names @($status.Keys)
        Update-Summary
        foreach ($s in $status.Values) {
            if ($ui.Reported.ContainsKey($s.Server) -or $s.State -in @('Waiting', 'Querying')) { continue }
            $ui.Reported[$s.Server] = $true
            switch ($s.State) {
                'Done'         { Write-TimelineLog PASS ('{0}: {1:N0} events (via {2})' -f $s.Server, $s.EventCount, $s.Transport) }
                'DoneWithGaps' { Write-TimelineLog WARN ('{0}: {1:N0} events, some logs incomplete (via {2})' -f $s.Server, $s.EventCount, $s.Transport) }
                'Unreachable'  { Write-TimelineLog FAIL ("{0}: couldn't reach - {1}" -f $s.Server, $s.Reason) }
                'Cancelled'    { Write-TimelineLog WARN ('{0}: cancelled' -f $s.Server) }
            }
            foreach ($l in @($s.Logs | Where-Object { $_.Outcome -notin @('Read', 'Pending') })) {
                Write-TimelineLog INFO ('{0} {1}: {2} {3}' -f $s.Server, $l.Log, $l.Outcome, $l.Reason)
            }
        }
    }

    function Start-Search {
        param([string]$Mode, [int]$LastMinutes = 60)
        $req = Get-InputRequest -Mode $Mode -LastMinutes $LastMinutes
        if (-not $req.Ok) { $ui.InputError.Text = $req.Message; return }
        if ($ui.Engine) { Close-TimelineEngine -Engine $ui.Engine; $ui.Engine = $null }

        $logs = @($ui.LogChecks | Where-Object { $_.IsChecked } | ForEach-Object { [string]$_.Tag })
        if ($ui.SecurityCheck.IsChecked) { $logs += 'Security' }
        if ($logs.Count -eq 0 -and -not $ui.AllLogsCheck.IsChecked) { $ui.InputError.Text = 'Tick at least one log.'; return }

        $ui.Store = New-TimelineRowStore; $ui.PendingRows.Clear(); $ui.Reported = @{}; $ui.Request = $req; $ui.Selected = $logs; $ui.SummaryKey = ''
        $ui.DetailText.Text = 'Select an event to see everything about it here.'
        $ui.Finished = $false
        $ui.Engine = Invoke-TimelineSearch -Request $req -Logs $logs -AllLogs ([bool]$ui.AllLogsCheck.IsChecked) -Credential $ui.Credential
        if (-not $ui.Smoke) {
            try {
                $recent = @((Read-TimelineSettings -Path $SettingsPath).RecentServerLists)
                Save-TimelineSettings -Path $SettingsPath -RecentServerLists @(Add-RecentServerList -Recent $recent -Servers $req.Servers)
            }
            catch { }
        }
        Write-TimelineLog INFO ('Searching {0} server(s): {1}. {2}. Logs: {3}{4}' -f $req.Servers.Count, ($req.Servers -join ', '),
            (Get-TimelineWindowText -Window $req.Window), ($logs -join ', '), $(if ($ui.AllLogsCheck.IsChecked) { ' + all logs with events' } else { '' }))
        Set-StatusMessage 'Reading the servers in the background - you can filter and scroll while it works.'
        Update-View
        Update-StatusPanel
        Update-InputState
    }

    function Get-ExportContext {
        $filter = Get-CurrentFilter
        $filtersText = 'Level: {0}; server: {1}; log: {2}; flagged only: {3}; text: "{4}"' -f $ui.LevelFilter.SelectedItem.Content,
            $ui.ServerFilter.SelectedItem.Content, $ui.LogFilter.SelectedItem.Content, $(if ($filter.FlaggedOnly) { 'yes' } else { 'no' }), $filter.Text
        if ($ui.Hidden.Count -gt 0) { $filtersText += '; hidden sources: {0}' -f ($ui.Hidden -join ', ') }
        if ($ui.EventKey) { $filtersText += '; only event: {0}' -f $ui.EventKey }
        @{
            WindowText = Get-TimelineWindowText -Window $ui.Request.Window
            Servers = $ui.Request.Servers; Logs = $ui.Selected; FiltersText = $filtersText; GeneratedAt = Get-Date
            ServerOutcomes = @($ui.Engine.Status.Values)
            Summary = @(Get-TimelineSummaryLines -Rows $ui.Store.Rows.ToArray() -Status $ui.Engine.Status -Logs $ui.Selected)
        }
    }

    function Invoke-Export {
        param([ValidateSet('Csv', 'Html')][string]$Kind)
        if ($ui.Smoke) { [void]$ui.SmokeFailures.Add('an export would have been written'); return }
        Sync-SaveFolder
        # Every filtered event, even when repeats are collapsed on screen.
        $rows = @($ui.VisibleRows)
        try {
            if (-not (Test-Path -LiteralPath $ui.OutputPath)) { New-Item -ItemType Directory -Path $ui.OutputPath -Force | Out-Null }
            $stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
            if ($Kind -eq 'Csv') {
                $path = Join-Path $ui.OutputPath "ServerEventTimeline_$stamp.csv"
                Export-TimelineCsv -Rows $rows -Path $path
            }
            else {
                $path = Join-Path $ui.OutputPath "ServerEventTimeline_$stamp.html"
                [System.IO.File]::WriteAllText($path, (ConvertTo-TimelineHtml -Rows $rows -Context (Get-ExportContext)), (New-Object System.Text.UTF8Encoding $true))
            }
            Write-TimelineLog PASS "Saved $($rows.Count) rows to $path"
            Set-StatusMessage "Saved: $path"
            try { Save-TimelineSettings -Path $SettingsPath -SaveFolder $ui.OutputPath } catch { }
        }
        catch {
            Write-TimelineLog FAIL "Couldn't save the $Kind file: $($_.Exception.Message)"
            Set-StatusMessage "Couldn't save the file: $($_.Exception.Message)"
        }
    }

    # Events
    $ui.AroundRadio.add_Checked({ Update-InputState })
    $ui.RangeRadio.add_Checked({ Update-InputState })
    foreach ($box in @($ui.ServersBox, $ui.AtBox, $ui.FromBox, $ui.ToBox, $ui.CapBox, $ui.TimeoutBox, $ui.TotalCapBox)) { $box.add_TextChanged({ Update-InputState }) }
    $ui.CollapseCheck.add_Click({ Update-View })
    $ui.ShowAllButton.add_Click({
            $ui.Hidden.Clear(); $ui.EventKey = ''
            Update-View
            Set-StatusMessage 'Showing every event again.'
        })
    $ui.PlusMinusCombo.add_SelectionChanged({ Update-InputState })
    $ui.SearchButton.add_Click({ Start-Search })
    $ui.LastHourButton.add_Click({ Start-Search -Mode Relative -LastMinutes 60 })
    $ui.Last24Button.add_Click({ Start-Search -Mode Relative -LastMinutes 1440 })
    $ui.CancelButton.add_Click({
            if ($ui.Engine) { Stop-TimelineEngine -Engine $ui.Engine; Write-TimelineLog WARN 'Search cancelled.'; Set-StatusMessage 'Cancelled. The events read so far are kept.' }
        })
    foreach ($combo in @($ui.LevelFilter, $ui.ServerFilter, $ui.LogFilter)) { $combo.add_SelectionChanged({ if ($ui.LevelFilter.SelectedItem) { Update-View } }) }
    $ui.FlaggedOnlyCheck.add_Click({ Update-View })

    $filterDelay = New-Object System.Windows.Threading.DispatcherTimer
    $filterDelay.Interval = [TimeSpan]::FromMilliseconds(300)
    $filterDelay.add_Tick({ $filterDelay.Stop(); Update-View })
    $ui.FilterText.add_TextChanged({ $filterDelay.Stop(); $filterDelay.Start() })

    $ui.EventGrid.add_SelectionChanged({
            # Muted while Update-View puts the selection back (one event per restored row).
            if ($ui.Restoring) { return }
            $count = $ui.EventGrid.SelectedItems.Count
            $ui.CopyButton.IsEnabled = $count -gt 0
            $r = $ui.EventGrid.SelectedItem
            if (-not $r) { return }
            $ui.DetailText.Text = (@(
                    "Time (server local): $($r.TimeServerLocal.ToString('yyyy-MM-dd HH:mm:ss'))    UTC: $($r.TimeUtc.ToString('yyyy-MM-dd HH:mm:ss'))"
                    "Server: $($r.Server)    Machine: $($r.Machine)"
                    "Log: $($r.Log)    Level: $($r.LevelName)    Source: $($r.Provider)    Event ID: $($r.EventId)    Record: $($r.RecordId)"
                    "User: $($r.User)"
                    $(if ($r.Flag) { "Flag: $($r.Flag)" })
                    $(if ($r.PSObject.Properties['Members']) {
                            $times = @($r.Members | Select-Object -First 50 | ForEach-Object { ([datetime]$_.TimeServerLocal).ToString('HH:mm:ss') })
                            $more = if (@($r.Members).Count -gt 50) { ' ...' } else { '' }
                            'Happened {0} times on {1}, from {2:yyyy-MM-dd HH:mm:ss} to {3:yyyy-MM-dd HH:mm:ss} (server local). Times: {4}{5}' -f `
                                $r.RepeatCount, $r.Server, $r.TimeServerLocal, $r.LastTimeServerLocal, ($times -join ', '), $more
                        })
                    ''
                    $r.Message
                ) | Where-Object { $null -ne $_ }) -join [Environment]::NewLine
        })

    # Right-click a row: dig in around it, or quiet the noise.
    $rowMenu = New-Object System.Windows.Controls.ContextMenu
    $newItem = {
        param([string]$Header, [scriptblock]$OnClick)
        $mi = New-Object System.Windows.Controls.MenuItem
        $mi.Header = $Header
        $mi.add_Click($OnClick)
        [void]$rowMenu.Items.Add($mi)
        $mi
    }
    $miAround = & $newItem 'Search all servers around this event (+/- 5 min)' {
        $r = $ui.EventGrid.SelectedItem
        if (-not $r -or ($ui.Engine -and -not $ui.Finished)) { return }
        $ui.AroundRadio.IsChecked = $true
        $ui.AtBox.Text = Get-AroundEventText -Row $r
        $five = @($ui.PlusMinusCombo.Items | Where-Object { [int]$_.Tag -eq 5 })[0]
        if ($five) { $ui.PlusMinusCombo.SelectedItem = $five }
        Start-Search
        Set-StatusMessage ("Searching every server 5 minutes either side of {0} (each server's local time)." -f $ui.AtBox.Text)
    }
    $miOnly = & $newItem 'Show only this event (same source and ID)' {
        $r = $ui.EventGrid.SelectedItem
        if (-not $r) { return }
        $ui.EventKey = Get-TimelineEventKey -Row $r
        Update-View
    }
    $miHide = & $newItem 'Hide events from this source' {
        $r = $ui.EventGrid.SelectedItem
        if (-not $r -or $ui.Hidden.Contains([string]$r.Provider)) { return }
        $ui.Hidden.Add([string]$r.Provider)
        Update-View
        Set-StatusMessage ("Hidden: {0}. 'Show everything again' brings it back." -f $r.Provider)
    }
    $miServer = & $newItem 'Show only this server' {
        $r = $ui.EventGrid.SelectedItem
        if (-not $r) { return }
        $item = @($ui.ServerFilter.Items | Where-Object { [string]$_.Tag -eq [string]$r.Server })[0]
        if ($item) { $ui.ServerFilter.SelectedItem = $item }
    }
    [void]$rowMenu.Items.Add((New-Object System.Windows.Controls.Separator))
    $null = & $newItem 'Copy selected rows' { $ui.CopyButton.RaiseEvent((New-Object System.Windows.RoutedEventArgs ([System.Windows.Controls.Button]::ClickEvent))) }
    $miShowAll = & $newItem 'Show everything again' { $ui.ShowAllButton.RaiseEvent((New-Object System.Windows.RoutedEventArgs ([System.Windows.Controls.Button]::ClickEvent))) }
    $rowMenu.add_Opened({
            $has = [bool]$ui.EventGrid.SelectedItem
            foreach ($mi in @($miOnly, $miHide, $miServer)) { $mi.IsEnabled = $has }
            # The row's time is one server's local time; "around" reads it as each server's local
            # time, so with mixed time zones it would search the wrong moment elsewhere.
            $mixedZones = $ui.Engine -and [bool](Get-TimelineTimeZoneNote -Status $ui.Engine.Status)
            $miAround.IsEnabled = $has -and -not ($ui.Engine -and -not $ui.Finished) -and -not $mixedZones
            $miAround.Header = if ($mixedZones) { 'Search around this event: not available, these servers are in different time zones (use From/To)' }
            else { 'Search all servers around this event (+/- 5 min)' }
            $miShowAll.IsEnabled = ($ui.Hidden.Count -gt 0) -or [bool]$ui.EventKey
        })
    $ui.EventGrid.ContextMenu = $rowMenu

    # Recent: the server lists searched before (per user, with the save folder).
    $recentMenu = New-Object System.Windows.Controls.ContextMenu
    $ui.RecentButton.ContextMenu = $recentMenu
    $ui.RecentButton.add_Click({
            $recentMenu.Items.Clear()
            $lists = if ($ui.Smoke) { @() } else { @((Read-TimelineSettings -Path $SettingsPath).RecentServerLists) }
            if ($lists.Count -eq 0) {
                $none = New-Object System.Windows.Controls.MenuItem
                $none.Header = 'No recent searches yet'; $none.IsEnabled = $false
                [void]$recentMenu.Items.Add($none)
            }
            foreach ($l in $lists) {
                $mi = New-Object System.Windows.Controls.MenuItem
                $mi.Header = if ($l.Length -gt 90) { $l.Substring(0, 87) + '...' } else { $l }
                $mi.Tag = $l; $mi.ToolTip = $l
                $mi.add_Click({ param($clicked) $ui.ServersBox.Text = [string]$clicked.Tag })
                [void]$recentMenu.Items.Add($mi)
            }
            $recentMenu.PlacementTarget = $ui.RecentButton
            $recentMenu.Placement = 'Bottom'
            $recentMenu.IsOpen = $true
        })

    # Ticket note: the note and the HTML report into Documents\TicketNotes\Ticket_<n>, where
    # TicketNote\Join-TicketNotes.ps1 finds it alongside the quick checks' notes.
    $ui.TicketNoteButton.add_Click({
            if ($ui.Smoke) { [void]$ui.SmokeFailures.Add('a ticket note would have been written'); return }
            if (-not $ui.Engine -or -not $ui.Finished) { return }
            Add-Type -AssemblyName Microsoft.VisualBasic
            $prompt = "This writes a short summary of the search to paste into the ticket: what was found, what's ruled out, " +
                "what couldn't be checked and what to do next. It's copied to the clipboard and saved with the HTML report " +
                "in Documents\TicketNotes\Ticket_<number>.`n`nTicket number (letters, digits, - or _):"
            $number = [Microsoft.VisualBasic.Interaction]::InputBox($prompt, 'Copy summary for ticket', '')
            if (-not $number) { return }
            $number = $number.Trim()
            if (-not (Test-TicketNumber -TicketNumber $number)) {
                Set-StatusMessage "'$number' is not a usable ticket number. Use letters, digits, - or _ (up to 32 characters)."
                return
            }
            try {
                $folder = Resolve-TicketFolder -TicketNumber $number -Root (Get-TicketNoteDefaultRoot)
                $context = Get-ExportContext
                $htmlPath = Join-Path $folder ('ServerEventTimeline_{0}.html' -f (Get-Date -Format 'yyyy-MM-dd_HHmmss'))
                [System.IO.File]::WriteAllText($htmlPath, (ConvertTo-TimelineHtml -Rows @($ui.VisibleRows) -Context $context), (New-Object System.Text.UTF8Encoding $true))
                $note = New-TimelineTicketNote -Status $ui.Engine.Status -Rows $ui.Store.Rows.ToArray() -WindowText $context.WindowText -Logs $ui.Selected -EvidencePaths @($htmlPath)
                $published = Publish-TicketNote -Note $note -Folder $folder -PasteSafe
                Write-TimelineLog PASS "Ticket summary saved to $($published.NotePath)"
                if ($published.Copied) { Set-StatusMessage "Summary copied - paste it into the ticket. Also saved in $folder." }
                else { Set-StatusMessage "Summary saved in $folder (the clipboard wasn't available - copy it from the file)." }
            }
            catch {
                Write-TimelineLog FAIL "Couldn't write the ticket note: $($_.Exception.Message)"
                Set-StatusMessage "Couldn't write the ticket note: $($_.Exception.Message)"
            }
        })
    # Run as: prompt for an account; cancelling the prompt goes back to the signed-in account.
    $ui.RunAsButton.add_Click({
            if ($ui.Smoke) { return }
            $cred = $null
            try { $cred = Get-Credential -Message 'Account to read the servers with (for example DOMAIN\admin). Cancel to use your own account.' }
            catch { $cred = $null }
            $ui.Credential = $cred
            if ($cred) {
                $ui.RunAsButton.Content = "Run as: $($cred.UserName) (click to change)"
                Write-TimelineLog INFO "Reading servers as $($cred.UserName)."
            }
            else {
                $ui.RunAsButton.Content = 'Run as another account...'
                Write-TimelineLog INFO 'Reading servers as the signed-in account.'
            }
        })

    # Pick from AD: needs the RSAT ActiveDirectory module (checked without loading it).
    $adAvailable = [bool](Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue)
    if (-not $adAvailable) {
        $ui.PickFromAdButton.IsEnabled = $false
        $ui.PickFromAdButton.ToolTip = 'Needs the RSAT Active Directory tools on this workstation. You can still type server names.'
        [System.Windows.Controls.ToolTipService]::SetShowOnDisabled($ui.PickFromAdButton, $true)
    }
    $adMenu = New-Object System.Windows.Controls.ContextMenu
    $miDcs = New-Object System.Windows.Controls.MenuItem
    $miDcs.Header = 'Add all domain controllers'
    $miFind = New-Object System.Windows.Controls.MenuItem
    $miFind.Header = 'Find servers by name...'
    [void]$adMenu.Items.Add($miDcs); [void]$adMenu.Items.Add($miFind)
    $ui.PickFromAdButton.ContextMenu = $adMenu
    $ui.PickFromAdButton.add_Click({
            $adMenu.PlacementTarget = $ui.PickFromAdButton
            $adMenu.Placement = 'Bottom'
            $adMenu.IsOpen = $true
        })
    $addFromAd = {
        param([string]$Kind, [string]$Text)
        $window.Cursor = [System.Windows.Input.Cursors]::Wait
        try {
            $names = @(Get-AdServerCandidates -Kind $Kind -SearchText $Text)
            if ($names.Count -eq 0) { Set-StatusMessage 'Active Directory returned no matching servers.'; return }
            if ($names.Count -gt 25) {
                $answer = [System.Windows.MessageBox]::Show("Add $($names.Count) servers to the list?", 'Server Event Timeline', 'YesNo', 'Question')
                if ($answer -ne 'Yes') { return }
            }
            $ui.ServersBox.Text = Add-ServerNames -ExistingText $ui.ServersBox.Text -Names $names
            Set-StatusMessage "Added $($names.Count) server(s) from Active Directory."
        }
        catch { Set-StatusMessage $_.Exception.Message; Write-TimelineLog WARN $_.Exception.Message }
        finally { $window.Cursor = $null }
    }
    $miDcs.add_Click({ & $addFromAd 'DomainControllers' '' })
    $miFind.add_Click({
            Add-Type -AssemblyName Microsoft.VisualBasic
            $text = [Microsoft.VisualBasic.Interaction]::InputBox('Part of the server name (for example SQL or FS):', 'Find servers in Active Directory', '')
            if ($text) { & $addFromAd 'Search' $text }
        })

    $ui.ThisComputerButton.add_Click({
            $ui.ServersBox.Text = Add-ServerNames -ExistingText $ui.ServersBox.Text -Names @(@(Get-LocalComputerNames)[0])
        })

    $ui.ExportCsvButton.add_Click({ Invoke-Export -Kind Csv })
    $ui.ExportHtmlButton.add_Click({ Invoke-Export -Kind Html })
    $ui.CopyButton.add_Click({
            if ($ui.Smoke) { [void]$ui.SmokeFailures.Add('the clipboard would have been changed'); return }
            $rows = @(Merge-TimelineRows -Rows @($ui.EventGrid.SelectedItems))
            if ($rows.Count -eq 0) { Set-StatusMessage 'Select one or more rows first.'; return }
            [System.Windows.Clipboard]::SetText((ConvertTo-TimelineText -Rows $rows))
            Set-StatusMessage ('Copied {0} row(s) - paste them into the ticket.' -f $rows.Count)
        })

    # The heartbeat: collect background results without ever waiting on a server.
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(250)
    $timer.add_Tick({
            try {
                if (-not $ui.Engine -or $ui.Finished) { return }
                $u = Update-TimelineEngine -Engine $ui.Engine
                foreach ($r in @($u.NewRows)) { $ui.PendingRows.Add($r) }
                if ($u.StatusChanged) { Update-StatusPanel }
                if ($ui.PendingRows.Count -gt 0 -and ($u.Finished -or $ui.LastRebuild.Elapsed.TotalSeconds -ge 1)) { Update-View }
                if ($u.Finished) {
                    $ui.Finished = $true
                    Update-View
                    Update-StatusPanel
                    Update-InputState
                    if (-not $ui.Engine.Cancelled) {
                        Write-TimelineLog INFO ('Search finished: {0:N0} events from {1} server(s).' -f $ui.Store.Rows.Count, $ui.Engine.Status.Count)
                        Set-StatusMessage ('Finished: {0:N0} events.' -f $ui.Store.Rows.Count)
                    }
                }
            }
            catch { Write-TimelineLog FAIL "Background update failed: $($_.Exception.Message)" }
        })
    $timer.Start()

    $window.add_Closing({
            $timer.Stop()
            if ($ui.Engine) { Close-TimelineEngine -Engine $ui.Engine }
        })

    if ($ui.Smoke) {
        Set-SmokeWindowPosition -Window $window
        $deadline = New-Object System.Windows.Threading.DispatcherTimer
        $deadline.Interval = [TimeSpan]::FromSeconds(30)
        $deadline.add_Tick({
                $deadline.Stop()
                [void]$ui.SmokeFailures.Add('the window did not finish rendering within 30 seconds')
                $window.Close()
            })
        $deadline.Start()
        $window.add_ContentRendered({
                if ($ui.LogPanel.Children.Count -eq 0) { [void]$ui.SmokeFailures.Add('the log checkboxes were not built') }
                if (-not $ui.EventGrid.EnableRowVirtualization) { [void]$ui.SmokeFailures.Add('the event grid is not virtualized') }
                if ($ui.PlusMinusCombo.Items.Count -eq 0 -or $ui.LevelFilter.Items.Count -eq 0) { [void]$ui.SmokeFailures.Add('the choice lists are empty') }
                if (-not $ui.EventGrid.ContextMenu -or $ui.EventGrid.ContextMenu.Items.Count -lt 4) { [void]$ui.SmokeFailures.Add('the right-click menu was not built') }
                try { Update-View } catch { [void]$ui.SmokeFailures.Add("refreshing the empty grid failed: $($_.Exception.Message)") }
                $clipped = @(Get-ClippedRowItems -Root $window)
                if ($clipped.Count -gt 0) { [void]$ui.SmokeFailures.Add("these are cut off at the right edge: $($clipped -join ', ')") }
                $deadline.Stop()
                $window.Close()
            })
    }

    Update-InputState
    [void]$window.ShowDialog()

    if ($ui.Smoke) {
        if ($ui.SmokeFailures.Count -eq 0) {
            Write-Host '[PASS] Server Event Timeline: the window opened, built its controls and closed.' -ForegroundColor Green
            return 0
        }
        foreach ($f in $ui.SmokeFailures) { Write-Host "[FAIL] Server Event Timeline: $f" -ForegroundColor Red }
        return 1
    }
    return 0
}

if ($LoadFunctionsOnly) { return }

$defaultOutputPath = Join-Path $PSScriptRoot 'Reports'

if ($NoGui) {
    try {
        $code = Invoke-TimelineConsole -ComputerName $ComputerName -At $At -PlusMinusMinutes $PlusMinusMinutes -From $From -To $To `
            -LastMinutes $LastMinutes -LogName $LogName -IncludeSecurity:$IncludeSecurity -AllLogs:$AllLogs -Cap $Cap -TotalCap $TotalCap `
            -TimeoutSec $TimeoutSec -Credential $Credential -OutputPath $OutputPath -DefaultOutputPath $defaultOutputPath `
            -TicketNumber $TicketNumber -NoClipboard:$NoClipboard
        exit ([int](@($code)[-1]))
    }
    catch {
        Write-Host "[FAIL] Server Event Timeline could not run: $($_.Exception.Message)" -ForegroundColor Red
        exit 2
    }
}

# WPF needs an STA thread. Windows PowerShell and pwsh start STA by default, but a host can be
# MTA: relaunch in an STA process with the same parameters.
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
    $exe = (Get-Process -Id $PID).Path
    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$PSCommandPath`"")
    # A trailing backslash would escape the closing quote on the command line.
    if ($OutputPath) { $relaunch += @('-OutputPath', "`"$($OutputPath.TrimEnd('\'))`"") }
    if ($ComputerName) { $relaunch += @('-ComputerName', ($ComputerName -join ',')) }
    if ($SmokeTest) {
        $relaunch += '-SmokeTest'
        $child = Start-Process -FilePath $exe -ArgumentList $relaunch -NoNewWindow -Wait -PassThru
        exit $child.ExitCode
    }
    Start-Process -FilePath $exe -ArgumentList $relaunch -WindowStyle Hidden
    return
}

try {
    $code = Show-ServerEventTimeline -ComputerName $ComputerName -OutputPath $OutputPath -DefaultOutputPath $defaultOutputPath -SmokeTest:$SmokeTest
    exit ([int](@($code)[-1]))
}
catch {
    Write-Host "[FAIL] Server Event Timeline could not start its window: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
