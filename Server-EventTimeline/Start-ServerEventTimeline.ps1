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
    ticket. Files go to -OutputPath (default: a Reports folder beside this script).

.PARAMETER ComputerName
    Servers to fill in when the window opens. You can also type them in the window. Without
    it, the list starts with this computer. This computer (by its name, FQDN, localhost, . or
    127.0.0.1) is always read directly from its own logs: no WinRM or network needed.

.PARAMETER OutputPath
    Folder for CSV/HTML exports and the activity log. Default: Reports beside this script.

.PARAMETER SmokeTest
    Opens the window off-screen, checks it built correctly, prints a [PASS] or [FAIL] line,
    and closes by itself (exit code 0 or 1). Queries no server, reads no event log, writes no
    file, touches no clipboard and asks for no administrator rights. Used by
    Tests\Invoke-SmokeTest.ps1 in the repository.

.PARAMETER LoadFunctionsOnly
    Define the functions and return without opening anything (used by the tests).

.EXAMPLE
    .\Start-ServerEventTimeline.ps1
    Opens the window.

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
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName,
    [string]$OutputPath,
    [switch]$SmokeTest,
    [switch]$LoadFunctionsOnly
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
          <ColumnDefinition Width="300"/>
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
          <WrapPanel x:Name="LogPanel"/>
          <WrapPanel>
            <CheckBox x:Name="SecurityCheck" Content="Security (slow on DCs and file servers)"/>
            <CheckBox x:Name="AllLogsCheck" Content="All logs with events (slow)"/>
          </WrapPanel>
          <Expander Header="More options" Foreground="{StaticResource Muted}" Margin="0,4,0,0">
            <WrapPanel Margin="0,8,0,0">
              <TextBlock Text="Stop each log at" VerticalAlignment="Center" Margin="0,0,6,0"/>
              <TextBox x:Name="CapBox" Width="70" Text="5000"/>
              <TextBlock Text="events.   Give up on a log after" VerticalAlignment="Center" Margin="6,0,6,0"/>
              <TextBox x:Name="TimeoutBox" Width="50" Text="60"/>
              <TextBlock Text="seconds.   " VerticalAlignment="Center" Margin="6,0,6,0"/>
              <Button x:Name="RunAsButton" Content="Run as another account..." ToolTip="Read the servers with a different account (for example another domain)"/>
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

    <!-- Narrow it down -->
    <WrapPanel Grid.Row="2" Margin="0,12,0,8">
      <TextBlock Text="Show" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="{StaticResource Muted}"/>
      <ComboBox x:Name="LevelFilter" MinWidth="170"/>
      <ComboBox x:Name="ServerFilter" MinWidth="150"/>
      <ComboBox x:Name="LogFilter" MinWidth="200"/>
      <CheckBox x:Name="FlaggedOnlyCheck" Content="Flagged only" VerticalAlignment="Center" Margin="4,0,12,0"/>
      <TextBox x:Name="FilterText" Width="260" ToolTip="Search message, source or event ID"/>
      <TextBlock x:Name="CountText" VerticalAlignment="Center" Margin="12,0,0,0" Foreground="{StaticResource Muted}"/>
    </WrapPanel>

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
    <DockPanel Grid.Row="6" Margin="0,10,0,0" LastChildFill="True">
      <StackPanel DockPanel.Dock="Left" Orientation="Horizontal">
        <Button x:Name="ExportCsvButton" Content="Export CSV" IsEnabled="False" ToolTip="Save the rows you can see as a CSV file"/>
        <Button x:Name="ExportHtmlButton" Content="Export HTML report" IsEnabled="False" ToolTip="Save a report with the rows you can see and how each server went"/>
        <Button x:Name="CopyButton" Content="Copy selected rows" IsEnabled="False" ToolTip="Copy the selected rows as text for a ticket note"/>
      </StackPanel>
      <TextBlock x:Name="StatusMessage" VerticalAlignment="Center" Margin="8,0,0,0" Foreground="{StaticResource Muted}" TextTrimming="CharacterEllipsis"/>
    </DockPanel>
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
    param([Parameter(Mandatory)]$Request, [string[]]$Logs, [bool]$AllLogs, [pscredential]$Credential)
    Start-TimelineEngine -Servers $Request.Servers -Window $Request.Window -SelectedLogs $Logs -AllLogs:$AllLogs `
        -Cap $Request.Cap -TimeoutSec $Request.TimeoutSec -Credential $Credential
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

function Show-ServerEventTimeline {
    <# Opens the window. Returns the exit code (smoke test: 0 pass, 1 fail; otherwise 0). #>
    [CmdletBinding()]
    param([string[]]$ComputerName, [Parameter(Mandatory)][string]$OutputPath, [switch]$SmokeTest)

    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

    $window = [System.Windows.Markup.XamlReader]::Parse((New-TimelineWindowXaml))
    $ui = @{
        Window = $window; Smoke = [bool]$SmokeTest; SmokeFailures = New-Object System.Collections.ArrayList
        Engine = $null; Store = (New-TimelineRowStore); PendingRows = New-Object System.Collections.Generic.List[object]
        LastRebuild = [Diagnostics.Stopwatch]::StartNew(); Reported = @{}; Finished = $true
        OutputPath = $OutputPath; LogFile = $null; Credential = $null; LogChecks = @(); ExitCode = 0
        Request = $null; Selected = @()
    }
    foreach ($name in 'ThisComputerButton', 'ServersBox', 'AroundRadio', 'RangeRadio', 'AtBox', 'PlusMinusCombo', 'FromBox', 'ToBox', 'LastHourButton',
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
        [void]$ui.LogPanel.Children.Add($cb)
        [void]$checks.Add($cb)
    }
    $ui.LogChecks = $checks.ToArray()

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
            -LastMinutes $LastMinutes -CapText $ui.CapBox.Text -TimeoutText $ui.TimeoutBox.Text
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
    }

    function Get-CurrentFilter {
        @{
            MinLevel    = [string]$ui.LevelFilter.SelectedItem.Tag
            Server      = if ($ui.ServerFilter.SelectedItem) { [string]$ui.ServerFilter.SelectedItem.Tag } else { '*' }
            Log         = if ($ui.LogFilter.SelectedItem) { [string]$ui.LogFilter.SelectedItem.Tag } else { '*' }
            FlaggedOnly = [bool]$ui.FlaggedOnlyCheck.IsChecked
            Text        = $ui.FilterText.Text
        }
    }

    function Update-View {
        # Merges rows that arrived, re-applies the filter and refreshes the grid.
        if ($ui.PendingRows.Count -gt 0) {
            Add-TimelineRows -Store $ui.Store -NewRows $ui.PendingRows.ToArray()
            $ui.PendingRows.Clear()
            Set-ChoiceItems -Combo $ui.LogFilter -AllLabel 'All logs' -Names @($ui.Store.Logs)
        }
        $visible = @(Select-TimelineRows -Rows $ui.Store.Rows.ToArray() -Filter (Get-CurrentFilter))
        $ui.EventGrid.ItemsSource = $visible
        $ui.CountText.Text = 'Showing {0:N0} of {1:N0} events' -f $visible.Count, $ui.Store.Rows.Count
        $has = $visible.Count -gt 0
        $ui.ExportCsvButton.IsEnabled = $has
        $ui.ExportHtmlButton.IsEnabled = $has
        $ui.LastRebuild.Restart()
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

        $ui.Store = New-TimelineRowStore; $ui.PendingRows.Clear(); $ui.Reported = @{}; $ui.Request = $req; $ui.Selected = $logs
        $ui.DetailText.Text = 'Select an event to see everything about it here.'
        $ui.Finished = $false
        $ui.Engine = Invoke-TimelineSearch -Request $req -Logs $logs -AllLogs ([bool]$ui.AllLogsCheck.IsChecked) -Credential $ui.Credential
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
        @{
            WindowText = Get-TimelineWindowText -Window $ui.Request.Window
            Servers = $ui.Request.Servers; Logs = $ui.Selected; FiltersText = $filtersText; GeneratedAt = Get-Date
            ServerOutcomes = @($ui.Engine.Status.Values)
        }
    }

    function Invoke-Export {
        param([ValidateSet('Csv', 'Html')][string]$Kind)
        if ($ui.Smoke) { [void]$ui.SmokeFailures.Add('an export would have been written'); return }
        $rows = @($ui.EventGrid.ItemsSource)
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
        }
        catch {
            Write-TimelineLog FAIL "Couldn't save the $Kind file: $($_.Exception.Message)"
            Set-StatusMessage "Couldn't save the file: $($_.Exception.Message)"
        }
    }

    # Events
    $ui.AroundRadio.add_Checked({ Update-InputState })
    $ui.RangeRadio.add_Checked({ Update-InputState })
    foreach ($box in @($ui.ServersBox, $ui.AtBox, $ui.FromBox, $ui.ToBox, $ui.CapBox, $ui.TimeoutBox)) { $box.add_TextChanged({ Update-InputState }) }
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
            $count = @($ui.EventGrid.SelectedItems).Count
            $ui.CopyButton.IsEnabled = $count -gt 0
            $r = $ui.EventGrid.SelectedItem
            if (-not $r) { return }
            $ui.DetailText.Text = (@(
                    "Time (server local): $($r.TimeServerLocal.ToString('yyyy-MM-dd HH:mm:ss'))    UTC: $($r.TimeUtc.ToString('yyyy-MM-dd HH:mm:ss'))"
                    "Server: $($r.Server)    Machine: $($r.Machine)"
                    "Log: $($r.Log)    Level: $($r.LevelName)    Source: $($r.Provider)    Event ID: $($r.EventId)    Record: $($r.RecordId)"
                    "User: $($r.User)"
                    $(if ($r.Flag) { "Flag: $($r.Flag)" })
                    ''
                    $r.Message
                ) | Where-Object { $null -ne $_ }) -join [Environment]::NewLine
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

if (-not $OutputPath) { $OutputPath = Join-Path $PSScriptRoot 'Reports' }

# WPF needs an STA thread. Windows PowerShell and pwsh start STA by default, but a host can be
# MTA: relaunch in an STA process with the same parameters.
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
    $exe = (Get-Process -Id $PID).Path
    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$PSCommandPath`"", '-OutputPath', "`"$OutputPath`"")
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
    $code = Show-ServerEventTimeline -ComputerName $ComputerName -OutputPath $OutputPath -SmokeTest:$SmokeTest
    exit ([int](@($code)[-1]))
}
catch {
    Write-Host "[FAIL] Server Event Timeline could not start its window: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
