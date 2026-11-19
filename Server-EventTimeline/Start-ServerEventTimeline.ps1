#Requires -Version 5.1

<#
.SYNOPSIS
    What happened on these servers around a time? Every event from several servers, merged
    into one timeline you can filter, with the important ones flagged.

.DESCRIPTION
    Add one or more servers and a time ("around 03:00, plus or minus 15 minutes"), pick the
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

    Everything about what to search sits in a sidebar on the left; the events fill the right.
    Under Search, a card per server says how reading it went and what was found ("APP01: 1
    unexpected restart, 3 service failures"); click a card to see only that server's events.
    The << button folds the sidebar away to give the events the full width, and both the
    sidebar's edge and the line above the event details can be dragged. Right-click a row to search every server around that event, show only that
    kind of event, hide a noisy source or show only that server. Collapse repeats turns
    hundreds of identical routine events into one row.

    Above the events, a timeline picture gives each server a lane: a symbol per flagged event,
    red dots for errors the tool doesn't recognise, and a grey bar for the quiet stretch before
    an unexpected restart. Hover for what it was, click to select it, drag across to see only
    that stretch of time (double-click to see all of it), or Hide picture. The What happened
    tab beside the event details tells the story in plain English, in order, with repeats and
    restarts folded into one line each; Copy for ticket copies it. The ticket summary and the
    HTML report carry the same story, and the report has the picture.

    Servers go in a list, one row each, with a note beside it (domain controller, the OS, not
    in AD, this computer). Type a name or an IP address and press Enter; suggestions come from
    Active Directory as you type. The "Suggestions from:" line says which domain they come
    from: this computer's domain unless you choose another domain or a domain controller with
    Change... (remembered per user), read with the Run as account when one is set. The arrow
    next to Add holds Add several..., Add this computer, Recent lists and Clear the list. "Add
    several..." pastes a list, finds servers in AD (by name, domain controllers, or an OU) or
    reads a .txt/.csv file, then adds the ones you tick. An IP address is looked up in DNS:
    when its name points back to the same IP, that name is searched (shown as "10.0.4.21 ->
    SQL01.contoso.local"); otherwise the IP itself is searched, which reads the remote event
    log over RPC (WinRM with an IP needs TrustedHosts and an explicit credential).

    With -NoGui it runs in the console instead (for RMM scripts and scheduled tasks): it reads
    the servers, prints how each went and what was found, and writes the CSV and HTML report
    (and the ticket note with -TicketNumber). Exit code 0 = every log read, 1 = a server or
    log could not be read in full, 2 = could not run (for example a time it couldn't read).

.PARAMETER ComputerName
    Servers to fill in when the window opens (names or IP addresses). You can also add them in
    the window. Without
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

    Files: ServerEventTimeline.Core.ps1 (logic), ServerEventTimeline.ServerList.ps1 (the server
    list: AD suggestions, notes, file import), ServerEventTimeline.Engine.ps1 (remote reads and
    the background engine), ServerEventTimeline.AddServersDialog.ps1 (the "Add several servers"
    dialog), CaseKit.ps1 and this window must stay in the same folder.

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
    - Server list: lastLogonTimestamp is updated only every 9-14 days, so "no sign-in for N
      days" is coarse and the threshold is 30 days:
      https://learn.microsoft.com/windows/win32/adschema/a-lastlogontimestamp
    - An IP address in a remote command uses NTLM, so WinRM needs HTTPS or TrustedHosts plus
      -Credential; a DNS name that looks back up to the IP is searched instead:
      https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_remote_troubleshooting#how-to-use-an-ip-address-in-a-remote-command
    - Get-ADComputer / Get-ADDomainController / Get-ADDomain (-Server, -Credential):
      https://learn.microsoft.com/powershell/module/activedirectory/get-adcomputer
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
. (Join-Path $PSScriptRoot 'ServerEventTimeline.AddServersDialog.ps1')

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
    <Style x:Key="CardButton" TargetType="Button">
      <Setter Property="Background" Value="#191C22"/><Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="BorderBrush" Value="{StaticResource Line}"/><Setter Property="Padding" Value="8,5"/>
      <Setter Property="Margin" Value="0,0,0,4"/><Setter Property="Cursor" Value="Hand"/><Setter Property="HorizontalContentAlignment" Value="Stretch"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="3" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Stretch"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="{StaticResource Accent}"/></Trigger>
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="b" Property="Background" Value="#1B1F27"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <!-- Toggle buttons look like the other buttons (the logs button has its own template). -->
    <Style TargetType="ToggleButton">
      <Setter Property="Background" Value="#232731"/><Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="BorderBrush" Value="{StaticResource LineStrong}"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ToggleButton">
            <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="3" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#2C313D"/></Trigger>
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="b" Property="Background" Value="#1B1F27"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="TabControl">
      <Setter Property="Background" Value="Transparent"/><Setter Property="BorderThickness" Value="0"/><Setter Property="Padding" Value="0"/>
    </Style>
    <Style TargetType="TabItem">
      <Setter Property="Foreground" Value="{StaticResource Muted}"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Border x:Name="b" BorderThickness="0,0,0,2" BorderBrush="Transparent" Background="Transparent" Padding="12,3,12,4">
              <ContentPresenter ContentSource="Header"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsSelected" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="{StaticResource Accent}"/><Setter Property="Foreground" Value="{StaticResource Text}"/></Trigger>
              <Trigger Property="IsMouseOver" Value="True"><Setter Property="Foreground" Value="{StaticResource Text}"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
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

  <Grid Margin="12">
    <Grid.ColumnDefinitions>
      <!-- The sidebar: everything about what to search. Drag the handle to widen it, or fold it with the << button. -->
      <ColumnDefinition x:Name="SidebarColumn" Width="300" MinWidth="28" MaxWidth="520"/>
      <ColumnDefinition Width="8"/>
      <ColumnDefinition Width="*"/>
    </Grid.ColumnDefinitions>

    <!-- Folded sidebar: a thin strip that brings it back -->
    <Border x:Name="SidebarStrip" Grid.Column="0" Visibility="Collapsed" Background="{StaticResource Card}" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="4">
      <Button x:Name="ExpandSidebarButton" Content="&#187;" VerticalAlignment="Top" Margin="2,8,2,0" Padding="4,4" ToolTip="Show the search panel"/>
    </Border>

    <!-- The sidebar -->
    <Border x:Name="SidebarPanel" Grid.Column="0" Background="{StaticResource Card}" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="4">
      <ScrollViewer x:Name="SidebarScroll" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled" Padding="12,10">
        <StackPanel>
          <DockPanel LastChildFill="False" Margin="0,0,0,6">
            <Button x:Name="CollapseSidebarButton" DockPanel.Dock="Right" Content="&#171;" Margin="0" Padding="7,1" ToolTip="Hide the search panel to give the events the full width"/>
            <TextBlock DockPanel.Dock="Left" Text="Search" FontSize="15" FontWeight="SemiBold" VerticalAlignment="Center"/>
          </DockPanel>

          <DockPanel LastChildFill="False">
            <TextBlock DockPanel.Dock="Left" Style="{StaticResource Label}" Text="WHICH SERVERS?"/>
            <TextBlock x:Name="ServerCountText" DockPanel.Dock="Right" Foreground="{StaticResource Accent}" FontSize="11" FontWeight="SemiBold" Text="0 servers"/>
          </DockPanel>
          <DockPanel LastChildFill="True" Margin="0,0,0,4">
            <Button x:Name="ChangeDomainButton" DockPanel.Dock="Right" Content="Change..." Padding="8,1" Margin="6,0,0,0" FontSize="11"
                    ToolTip="Choose the domain (or a domain controller) whose servers are suggested"/>
            <TextBlock x:Name="DomainText" Foreground="{StaticResource Muted}" FontSize="11" VerticalAlignment="Center"
                       TextWrapping="Wrap" Text="Suggestions from: ..."/>
          </DockPanel>
          <DockPanel LastChildFill="True">
            <Button x:Name="AddMenuButton" DockPanel.Dock="Right" Content="&#9662;" FontSize="15" Margin="2,0,0,0" Padding="8,0"
                    ToolTip="More ways to add servers: several at once (paste, find in AD, or a file), this computer, recent lists - or clear the list"/>
            <Button x:Name="AddServerButton" DockPanel.Dock="Right" Content="Add" Style="{StaticResource Primary}" Margin="6,0,0,0" Padding="14,4"
                    ToolTip="Add the server typed on the left (Enter does the same)"/>
            <Grid>
              <TextBox x:Name="ServerInput" ToolTip="A server name or IP address. Paste several, separated by commas, spaces or new lines, to add them all."/>
              <TextBlock x:Name="ServerInputHint" Text="Server name or IP address" Foreground="{StaticResource Muted}" Margin="9,0,0,0"
                         VerticalAlignment="Center" IsHitTestVisible="False"/>
            </Grid>
          </DockPanel>
          <Popup x:Name="SuggestPopup" Placement="Bottom" StaysOpen="True" AllowsTransparency="True" Focusable="False">
            <Border Background="{StaticResource Card}" BorderBrush="{StaticResource LineStrong}" BorderThickness="1" MinWidth="300">
              <ListBox x:Name="SuggestList" Background="Transparent" BorderThickness="0" Foreground="{StaticResource Text}" MaxHeight="240"
                       ScrollViewer.HorizontalScrollBarVisibility="Disabled" Focusable="False">
                <ListBox.ItemTemplate>
                  <DataTemplate>
                    <DockPanel Width="280">
                      <TextBlock DockPanel.Dock="Right" Text="{Binding Detail}" Foreground="{StaticResource Muted}" FontSize="11" Margin="12,0,0,0" VerticalAlignment="Center"/>
                      <TextBlock Text="{Binding Name}" TextTrimming="CharacterEllipsis"/>
                    </DockPanel>
                  </DataTemplate>
                </ListBox.ItemTemplate>
              </ListBox>
            </Border>
          </Popup>
          <Grid Margin="0,6,0,0">
          <ListBox x:Name="ServerList" MinHeight="30" MaxHeight="220" Background="{StaticResource Panel}" BorderBrush="{StaticResource Line}"
                   Foreground="{StaticResource Text}" ScrollViewer.HorizontalScrollBarVisibility="Disabled" HorizontalContentAlignment="Stretch">
            <ListBox.ItemTemplate>
              <DataTemplate>
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="22"/>
                  </Grid.ColumnDefinitions>
                  <StackPanel Grid.Column="0" Margin="0,1,0,1">
                    <TextBlock Text="{Binding Display}" TextTrimming="CharacterEllipsis" ToolTip="{Binding Display}"/>
                    <TextBlock Text="{Binding Note}" FontSize="11" TextTrimming="CharacterEllipsis">
                      <TextBlock.Style>
                        <Style TargetType="TextBlock">
                          <Setter Property="Foreground" Value="{StaticResource Muted}"/>
                          <Style.Triggers>
                            <DataTrigger Binding="{Binding NoteKind}" Value="Warn"><Setter Property="Foreground" Value="{StaticResource Warn}"/></DataTrigger>
                            <DataTrigger Binding="{Binding Note}" Value=""><Setter Property="Visibility" Value="Collapsed"/></DataTrigger>
                          </Style.Triggers>
                        </Style>
                      </TextBlock.Style>
                    </TextBlock>
                  </StackPanel>
                  <Button Grid.Column="1" Content="×" Tag="{Binding}" Padding="0" Margin="0" Width="20" Height="20" Background="Transparent" VerticalAlignment="Center"
                          BorderBrush="Transparent" Foreground="{StaticResource Muted}" ToolTip="Remove this server from the list"/>
                </Grid>
              </DataTemplate>
            </ListBox.ItemTemplate>
          </ListBox>
          <TextBlock x:Name="ServerListHint" Text="Type a name above, or use &#9662; for several at once" Foreground="{StaticResource Muted}" FontSize="11"
                     Margin="8,0" VerticalAlignment="Center" TextWrapping="Wrap" IsHitTestVisible="False"/>
          </Grid>

          <TextBlock Style="{StaticResource Label}" Text="WHEN? (EACH SERVER'S LOCAL TIME)" Margin="0,14,0,4"/>
          <RadioButton x:Name="AroundRadio" Content="Around" GroupName="When" IsChecked="True" Margin="0,0,0,4"/>
          <Grid Margin="0,0,0,8">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBox x:Name="AtBox" Grid.Column="0" ToolTip="yyyy-MM-dd HH:mm"/>
            <TextBlock Grid.Column="1" Text=" +/- " VerticalAlignment="Center" Foreground="{StaticResource Muted}"/>
            <ComboBox x:Name="PlusMinusCombo" Grid.Column="2" MinWidth="90" Margin="0"/>
          </Grid>
          <RadioButton x:Name="RangeRadio" Content="From ... to ..." GroupName="When" Margin="0,0,0,4"/>
          <Grid Margin="0,0,0,8">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <TextBox x:Name="FromBox" Grid.Column="0" ToolTip="yyyy-MM-dd HH:mm"/>
            <TextBlock Grid.Column="1" Text=" to " VerticalAlignment="Center" Foreground="{StaticResource Muted}"/>
            <TextBox x:Name="ToBox" Grid.Column="2" ToolTip="yyyy-MM-dd HH:mm"/>
          </Grid>
          <WrapPanel>
            <Button x:Name="LastHourButton" Content="Last hour" Margin="0,0,6,4" ToolTip="Search the last 60 minutes now"/>
            <Button x:Name="Last24Button" Content="Last 24 hours" Margin="0,0,0,4" ToolTip="Search the last 24 hours now (can be a lot of events)"/>
          </WrapPanel>

          <StackPanel Margin="0,10,0,0">
            <TextBlock Style="{StaticResource Label}" Text="WHICH LOGS?"/>
            <ToggleButton x:Name="LogsButton" HorizontalAlignment="Stretch" Foreground="{StaticResource Text}" Cursor="Hand" ToolTip="Choose which logs to read">
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

          <Grid Margin="0,14,0,0">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <Button x:Name="SearchButton" Grid.Column="0" Style="{StaticResource Primary}" Content="Search" Padding="22,7" IsDefault="True"/>
            <Button x:Name="CancelButton" Grid.Column="1" Content="Cancel" IsEnabled="False" Margin="0"/>
          </Grid>
          <TextBlock x:Name="InputError" Foreground="{StaticResource Warn}" TextWrapping="Wrap" Margin="0,6,0,0"/>

          <!-- How each server went and what was found: click a card to see only that server -->
          <StackPanel x:Name="SummaryBorder" Margin="0,12,0,0" Visibility="Collapsed">
            <TextBlock Style="{StaticResource Label}" Text="EACH SERVER (CLICK TO SHOW ONLY ITS EVENTS)" TextWrapping="Wrap"/>
            <ItemsControl x:Name="SummaryList">
              <ItemsControl.ItemTemplate>
                <DataTemplate>
                  <Button Tag="{Binding Server}" Style="{StaticResource CardButton}" ToolTip="{Binding Findings}">
                    <StackPanel>
                      <TextBlock Text="{Binding Heading}" FontWeight="SemiBold" TextWrapping="Wrap">
                        <TextBlock.Style>
                          <Style TargetType="TextBlock">
                            <Setter Property="Foreground" Value="{StaticResource Text}"/>
                            <Style.Triggers>
                              <DataTrigger Binding="{Binding Warn}" Value="True"><Setter Property="Foreground" Value="{StaticResource Warn}"/></DataTrigger>
                            </Style.Triggers>
                          </Style>
                        </TextBlock.Style>
                      </TextBlock>
                      <TextBlock Text="{Binding Findings}" Foreground="{StaticResource Muted}" FontSize="12" TextWrapping="Wrap" Margin="0,2,0,0"/>
                    </StackPanel>
                  </Button>
                </DataTemplate>
              </ItemsControl.ItemTemplate>
            </ItemsControl>
            <ItemsControl x:Name="NotesList" Foreground="{StaticResource Muted}" FontSize="12">
              <ItemsControl.ItemTemplate>
                <DataTemplate><TextBlock Text="{Binding}" TextWrapping="Wrap" Foreground="{StaticResource Muted}" Margin="0,2,0,0"/></DataTemplate>
              </ItemsControl.ItemTemplate>
            </ItemsControl>
          </StackPanel>
          <TextBlock x:Name="BannerText" Foreground="{StaticResource Warn}" TextWrapping="Wrap" Margin="0,6,0,0" Visibility="Collapsed"/>
          <TextBlock x:Name="TimeZoneNote" Foreground="{StaticResource Accent}" TextWrapping="Wrap" Margin="0,6,0,0" Visibility="Collapsed"/>
        </StackPanel>
      </ScrollViewer>
    </Border>

    <GridSplitter x:Name="SidebarSplitter" Grid.Column="1" Width="8" HorizontalAlignment="Stretch" ResizeDirection="Columns"
                  Background="Transparent" Cursor="SizeWE" ToolTip="Drag to widen or narrow the search panel"/>

    <!-- The results -->
    <Grid Grid.Column="2">
      <Grid.RowDefinitions>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="*" MinHeight="120"/>
        <RowDefinition Height="6"/>
        <RowDefinition Height="150" MinHeight="90"/>
        <RowDefinition Height="Auto"/>
      </Grid.RowDefinitions>

      <!-- Narrow it down -->
      <StackPanel Grid.Row="0" Margin="0,0,0,8">
        <WrapPanel>
          <TextBlock Text="Show" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="{StaticResource Muted}"/>
          <ComboBox x:Name="LevelFilter" MinWidth="170"/>
          <ComboBox x:Name="ServerFilter" MinWidth="150"/>
          <ComboBox x:Name="LogFilter" MinWidth="200"/>
          <CheckBox x:Name="FlaggedOnlyCheck" Content="Flagged only" VerticalAlignment="Center" Margin="4,0,12,0"/>
          <CheckBox x:Name="CollapseCheck" Content="Collapse repeats" VerticalAlignment="Center" Margin="0,0,12,0"
                    ToolTip="Show the same routine event on the same server once, with how many times it happened. Flagged events are never collapsed."/>
          <TextBox x:Name="FilterText" Width="260" ToolTip="Search message, source or event ID"/>
          <Border x:Name="TimeRangeChip" Visibility="Collapsed" Background="#1F3A52" BorderBrush="{StaticResource Accent}" BorderThickness="1" CornerRadius="10"
                  Padding="8,1,2,1" Margin="8,0,0,0" VerticalAlignment="Center" ToolTip="Only events in this stretch of time (dragged on the timeline picture)">
            <StackPanel Orientation="Horizontal">
              <TextBlock x:Name="TimeRangeText" VerticalAlignment="Center"/>
              <Button x:Name="ClearRangeButton" Content="&#215;" Padding="5,0" Margin="4,0,0,0" ToolTip="Show the whole search window again"/>
            </StackPanel>
          </Border>
          <TextBlock x:Name="CountText" VerticalAlignment="Center" Margin="12,0,0,0" Foreground="{StaticResource Muted}"/>
          <TextBlock x:Name="HiddenNote" VerticalAlignment="Center" Margin="12,0,8,0" Foreground="{StaticResource Warn}" Visibility="Collapsed"/>
          <Button x:Name="ShowAllButton" Content="Show everything again" Visibility="Collapsed" ToolTip="Bring back hidden sources and leave 'only this event'"/>
        </WrapPanel>
      </StackPanel>

      <!-- The picture: what happened on each server, and when -->
      <Border x:Name="StripBorder" Grid.Row="1" Background="{StaticResource Panel}" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="3"
              Margin="0,0,0,8" Visibility="Collapsed">
        <DockPanel>
          <DockPanel DockPanel.Dock="Top" Margin="8,3,4,0" LastChildFill="False">
            <TextBlock DockPanel.Dock="Left" Text="TIMELINE" FontSize="11" FontWeight="SemiBold" Foreground="{StaticResource Muted}" VerticalAlignment="Center"/>
            <TextBlock x:Name="StripAxisNote" DockPanel.Dock="Left" Foreground="{StaticResource Muted}" FontSize="11" Margin="6,0,0,0" VerticalAlignment="Center"/>
            <ToggleButton x:Name="HidePictureToggle" DockPanel.Dock="Right" Content="Hide picture" Padding="8,1" Margin="0" ToolTip="Fold the timeline picture away (remembered next time)"/>
            <TextBlock x:Name="StripLegend" DockPanel.Dock="Right" FontSize="11" Foreground="{StaticResource Muted}" VerticalAlignment="Center" Margin="0,0,12,0"/>
          </DockPanel>
          <ScrollViewer x:Name="StripScroll" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
            <Canvas x:Name="StripCanvas" Height="108" Background="Transparent" ClipToBounds="True" Cursor="Cross"
                    ToolTip="Hover a symbol to see what it was, click it to show it in the list. Drag across to see only that stretch of time; double-click to see all of it again."
                    ToolTipService.InitialShowDelay="1500"/>
          </ScrollViewer>
        </DockPanel>
      </Border>

      <!-- The timeline -->
      <DataGrid x:Name="EventGrid" Grid.Row="2" AutoGenerateColumns="False" IsReadOnly="True" EnableRowVirtualization="True"
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
          <DataGridTextColumn Header="Time (server local)" Binding="{Binding TimeServerLocal, StringFormat=yyyy-MM-dd HH:mm:ss}" Width="145" MinWidth="145"/>
          <DataGridTextColumn Header="UTC" Binding="{Binding TimeUtc, StringFormat=HH:mm:ss}" Width="64" MinWidth="64"/>
          <DataGridTextColumn Header="Server" Binding="{Binding Server}" Width="140"/>
          <DataGridTextColumn Header="Level" Binding="{Binding LevelName}" Width="88" MinWidth="88"/>
          <DataGridTextColumn Header="Flag" Binding="{Binding Flag}" Width="135">
            <DataGridTextColumn.ElementStyle>
              <Style TargetType="TextBlock"><Setter Property="Foreground" Value="#5DADE2"/><Setter Property="FontWeight" Value="SemiBold"/></Style>
            </DataGridTextColumn.ElementStyle>
          </DataGridTextColumn>
          <DataGridTextColumn Header="Source" Binding="{Binding Provider}" Width="150"/>
          <DataGridTextColumn Header="ID" Binding="{Binding EventId}" Width="50" MinWidth="50"/>
          <DataGridTextColumn Header="Log" Binding="{Binding Log}" Width="95"/>
          <DataGridTextColumn Header="Message" Binding="{Binding MessageFirstLine}" Width="*" MinWidth="180"/>
        </DataGrid.Columns>
      </DataGrid>

      <GridSplitter Grid.Row="3" HorizontalAlignment="Stretch" Background="{StaticResource Line}" Cursor="SizeNS" ToolTip="Drag to resize the event details"/>

      <!-- Everything about the selected event, and what happened in order -->
      <Grid Grid.Row="4">
        <TabControl x:Name="DetailTabs">
          <TabItem Header="Event details">
            <TextBox x:Name="DetailText" IsReadOnly="True" TextWrapping="Wrap" VerticalContentAlignment="Top"
                     VerticalScrollBarVisibility="Auto" FontFamily="Consolas" Background="{StaticResource Panel}"
                     Text="Select an event to see everything about it here."/>
          </TabItem>
          <TabItem Header="What happened">
            <Grid Background="{StaticResource Panel}">
              <TextBlock x:Name="StoryEmptyText" Text="Search to see the important events here, in order." Foreground="{StaticResource Muted}" Margin="10,8" TextWrapping="Wrap"/>
              <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
                <ItemsControl x:Name="StoryList" Margin="6,4">
                  <ItemsControl.ItemTemplate>
                    <DataTemplate>
                      <Grid>
                        <Button x:Name="line" Tag="{Binding RowId}" Style="{StaticResource CardButton}" Margin="0,0,0,2" Padding="8,3" ToolTip="Show this event in the list">
                          <Grid>
                            <Grid.ColumnDefinitions>
                              <ColumnDefinition Width="18"/>
                              <ColumnDefinition Width="Auto"/>
                              <ColumnDefinition Width="Auto"/>
                              <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <TextBlock Grid.Column="0" Text="{Binding Glyph}" Foreground="{Binding GlyphColor}" FontFamily="Segoe UI Symbol"/>
                            <TextBlock Grid.Column="1" Text="{Binding TimeText}" Foreground="{StaticResource Muted}" Margin="0,0,8,0"/>
                            <Border Grid.Column="2" Background="#232731" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="8" Padding="6,0" Margin="0,0,8,0" VerticalAlignment="Top">
                              <TextBlock Text="{Binding Server}" FontSize="11"/>
                            </Border>
                            <StackPanel Grid.Column="3">
                              <TextBlock Text="{Binding Text}" TextWrapping="Wrap"/>
                              <TextBlock Text="{Binding Detail}" Foreground="{StaticResource Muted}" FontSize="11" TextWrapping="Wrap" Visibility="{Binding DetailVisibility}"/>
                            </StackPanel>
                          </Grid>
                        </Button>
                        <TextBlock x:Name="gap" Text="{Binding Text}" Foreground="{StaticResource Muted}" FontSize="11" Margin="34,1,0,3" Visibility="Collapsed"/>
                      </Grid>
                      <DataTemplate.Triggers>
                        <DataTrigger Binding="{Binding Kind}" Value="Gap"><Setter TargetName="line" Property="Visibility" Value="Collapsed"/><Setter TargetName="gap" Property="Visibility" Value="Visible"/></DataTrigger>
                        <DataTrigger Binding="{Binding Kind}" Value="More"><Setter TargetName="line" Property="Visibility" Value="Collapsed"/><Setter TargetName="gap" Property="Visibility" Value="Visible"/></DataTrigger>
                      </DataTemplate.Triggers>
                    </DataTemplate>
                  </ItemsControl.ItemTemplate>
                </ItemsControl>
              </ScrollViewer>
            </Grid>
          </TabItem>
        </TabControl>
        <Button x:Name="CopyStoryButton" Content="Copy for ticket" HorizontalAlignment="Right" VerticalAlignment="Top" Margin="0" Padding="8,1" IsEnabled="False"
                ToolTip="Copy what happened, in order, to paste into the ticket"/>
      </Grid>

      <!-- Get it into the ticket -->
      <StackPanel Grid.Row="5" Margin="0,10,0,0">
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
        <DockPanel LastChildFill="True" Margin="0,8,0,0">
          <TextBlock DockPanel.Dock="Left" Text="Save reports to:" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="{StaticResource Muted}"/>
          <Button x:Name="OpenFolderButton" DockPanel.Dock="Right" Content="Open folder" Margin="8,0,0,0" ToolTip="Open this folder in File Explorer"/>
          <Button x:Name="BrowseFolderButton" DockPanel.Dock="Right" Content="Browse..." Margin="8,0,0,0" ToolTip="Pick the folder for exports (remembered for next time)"/>
          <TextBox x:Name="SaveFolderBox" ToolTip="Folder for CSV and HTML exports and the activity log. Created on the first export if it doesn't exist."/>
        </DockPanel>
      </StackPanel>
    </Grid>
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
    $startedUtc = [datetime]::UtcNow
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
        $span = Get-TimelineStripWindow -Window $engine.Window -Status $engine.Status -NowUtc $startedUtc
        $context = @{
            WindowText = $windowText; Servers = $req.Servers; Logs = $logs; FiltersText = 'none (console mode: every event read)'
            GeneratedAt = Get-Date; ServerOutcomes = @($engine.Status.Values); Summary = $summary
            StartUtc = $span.StartUtc; EndUtc = $span.EndUtc
        }
        [System.IO.File]::WriteAllText($htmlPath, (ConvertTo-TimelineHtml -Rows $rows -Context $context -ContextRows $rows), (New-Object System.Text.UTF8Encoding $true))
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

function Set-TimelineSidebar {
    <#
        Folds the search sidebar to a thin strip (the events get the full width) or brings it
        back at the width it had. The width is kept on the column's Tag while folded.
    #>
    param([Parameter(Mandatory)]$Window, [Parameter(Mandatory)][bool]$Collapsed)
    $col = $Window.FindName('SidebarColumn')
    $panel = $Window.FindName('SidebarPanel'); $strip = $Window.FindName('SidebarStrip'); $splitter = $Window.FindName('SidebarSplitter')
    if ($Collapsed) {
        if ($col.ActualWidth -gt 28 -or $col.Width.Value -gt 28) { $col.Tag = $col.Width }
        $col.Width = New-Object System.Windows.GridLength 28
        $panel.Visibility = 'Collapsed'; $strip.Visibility = 'Visible'
        if ($splitter) { $splitter.IsEnabled = $false }
    }
    else {
        $col.Width = if ($col.Tag -is [System.Windows.GridLength]) { $col.Tag } else { New-Object System.Windows.GridLength 300 }
        $panel.Visibility = 'Visible'; $strip.Visibility = 'Collapsed'
        if ($splitter) { $splitter.IsEnabled = $true }
    }
}

function Register-ServerInputPaste {
    <#
        A one-line TextBox keeps only the first line of a paste, so a column of servers pasted
        from Excel or a ticket would silently become one. A paste with line breaks is taken
        over here and handed to -OnNames whole; a one-line paste is left to the box.
          https://learn.microsoft.com/dotnet/api/system.windows.dataobject.addpastinghandler
    #>
    param([Parameter(Mandatory)][System.Windows.Controls.TextBox]$TextBox, [Parameter(Mandatory)][scriptblock]$OnNames)
    $handler = [System.Windows.DataObjectPastingEventHandler] {
        param($source, $e)
        if (-not $e.DataObject.GetDataPresent([System.Windows.DataFormats]::UnicodeText)) { return }
        $text = [string]$e.DataObject.GetData([System.Windows.DataFormats]::UnicodeText)
        if ($text.IndexOf("`n") -lt 0 -and $text.IndexOf("`r") -lt 0) { return }
        $e.CancelCommand()
        & $OnNames $text
    }.GetNewClosure()
    [System.Windows.DataObject]::AddPastingHandler($TextBox, $handler)
}
function Copy-TimelineRows {
    <#
        Puts the rows on the clipboard as text and returns the status line to show. Never
        throws: [System.Windows.Clipboard]::SetText threw when another program (clipboard
        history, RDP's clipboard, a chat app) had the clipboard open, and that closed the window.
        Copy-TicketNoteToClipboard (CaseKit.ps1) returns $false instead.
    #>
    param([object[]]$Rows)
    $merged = @(Merge-TimelineRows -Rows @($Rows | Where-Object { $null -ne $_ }))
    if ($merged.Count -eq 0) { return 'Select one or more rows first.' }
    if (Copy-TicketNoteToClipboard -Text (ConvertTo-TimelineText -Rows $merged)) {
        return ('Copied {0} row(s) - paste them into the ticket.' -f $merged.Count)
    }
    "Couldn't copy: another program is using the clipboard. Wait a moment and try again."
}

function Get-TimelineGridFilter {
    <# The event list's filters as Select-TimelineRows takes them, read from the window's controls. #>
    param([Parameter(Mandatory)][hashtable]$Ui)
    @{
        MinLevel      = if ($Ui.LevelFilter.SelectedItem) { [string]$Ui.LevelFilter.SelectedItem.Tag } else { 'All' }
        Server        = if ($Ui.ServerFilter.SelectedItem) { [string]$Ui.ServerFilter.SelectedItem.Tag } else { '*' }
        Log           = if ($Ui.LogFilter.SelectedItem) { [string]$Ui.LogFilter.SelectedItem.Tag } else { '*' }
        FlaggedOnly   = [bool]$Ui.FlaggedOnlyCheck.IsChecked
        Text          = $Ui.FilterText.Text
        HiddenSources = $Ui.Hidden.ToArray()
        EventKey      = $Ui.EventKey
        FromUtc       = if ($Ui.TimeRange) { $Ui.TimeRange.StartUtc } else { $null }
        ToUtc         = if ($Ui.TimeRange) { $Ui.TimeRange.EndUtc } else { $null }
    }
}

function Set-TimelineStoryView {
    <#
        Fills the "What happened" tab. $null = no search yet; a story with no lines = nothing
        flagged. Each line gets its symbol and colour (Get-TimelineCategoryStyle), the time and
        the detail line only when there is one.
    #>
    param([Parameter(Mandatory)]$Window, $Story)
    $list = $Window.FindName('StoryList')
    $empty = $Window.FindName('StoryEmptyText')
    $copy = $Window.FindName('CopyStoryButton')
    $lines = if ($Story) { @($Story.Lines) } else { @() }
    if ($lines.Count -eq 0) {
        $list.ItemsSource = $null
        $empty.Text = if ($Story) { 'Nothing the tool recognises happened in this window - check the errors in the list.' } else { 'Search to see the important events here, in order.' }
        $empty.Visibility = 'Visible'
        $copy.IsEnabled = $false
        return
    }
    $events = @($lines | Where-Object { $_.Kind -eq 'Event' })
    # Times show the date too when the story spans more than one day.
    $days = @($events | ForEach-Object { ([datetime]$_.TimeServerLocal).Date } | Select-Object -Unique)
    $format = if ($days.Count -gt 1) { 'MM-dd HH:mm' } else { 'HH:mm' }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($l in $lines) {
        if ($l.Kind -ne 'Event') { $items.Add([PSCustomObject]@{ Kind = $l.Kind; Text = $l.Text; RowId = '' }); continue }
        $style = Get-TimelineCategoryStyle -Category $l.Category
        $items.Add([PSCustomObject]@{
                Kind = 'Event'; Glyph = $style.Glyph; GlyphColor = $style.Color; TimeText = ([datetime]$l.TimeServerLocal).ToString($format)
                Server = $l.Server; Text = $l.Text; Detail = $l.Detail; RowId = $l.RowId
                DetailVisibility = $(if ($l.Detail) { 'Visible' } else { 'Collapsed' })
            })
    }
    if ($Story.MoreCount -gt 0) {
        $items.Add([PSCustomObject]@{ Kind = 'More'; Text = ('... and {0:N0} more flagged events - filter the list to see them' -f $Story.MoreCount); RowId = '' })
    }
    $list.ItemsSource = $items.ToArray()
    $empty.Visibility = 'Collapsed'
    $copy.IsEnabled = $true
}

function Show-TimelineStoryRow {
    <#
        Selects one row (by Get-TimelineRowId) in the event list and scrolls to it. When the
        current filters hide it, they are cleared first and $Refresh rebuilds the list. Returns
        $false when the row isn't in the search results any more.
    #>
    param([Parameter(Mandatory)][hashtable]$Ui, [Parameter(Mandatory)][string]$RowId, [Parameter(Mandatory)][scriptblock]$Refresh)
    $parts = $RowId -split '\|'
    if ($parts.Count -lt 3) { return $false }
    $server = ($parts[0..($parts.Count - 3)] -join '|'); $log = $parts[-2]; $record = $parts[-1]
    $row = $null
    # Inline compare, not a function call per row: the store can hold 100,000 rows.
    foreach ($r in $Ui.Store.Rows) {
        if ([string]$r.RecordId -eq $record -and [string]$r.Server -eq $server -and [string]$r.Log -eq $log) { $row = $r; break }
    }
    if (-not $row) { return $false }

    if (@(Select-TimelineRows -Rows @($row) -Filter (Get-TimelineGridFilter -Ui $Ui)).Count -eq 0) {
        foreach ($combo in @($Ui.LevelFilter, $Ui.ServerFilter, $Ui.LogFilter)) { if ($combo.Items.Count -gt 0) { $combo.SelectedIndex = 0 } }
        $Ui.FlaggedOnlyCheck.IsChecked = $false
        $Ui.FilterText.Text = ''
        $Ui.Hidden.Clear()
        $Ui.EventKey = ''
        Set-TimelineTimeRange -Ui $Ui -FromUtc $null -ToUtc $null
        & $Refresh
    }
    # Flagged rows are never collapsed into repeats, so the row itself is in the list.
    $Ui.EventGrid.SelectedItem = $row
    $Ui.EventGrid.ScrollIntoView($row)
    return $true
}

function Copy-TimelineStory {
    <# Puts the story on the clipboard as ticket lines and returns the status line. Never throws. #>
    param($Story)
    $lines = if ($Story) { @(Format-TimelineStoryText -Story $Story) } else { @() }
    if ($lines.Count -eq 0) { return 'Nothing to copy yet: run a search first.' }
    $n = @($Story.Lines | Where-Object { $_.Kind -eq 'Event' }).Count
    if (Copy-TicketNoteToClipboard -Text ($lines -join [Environment]::NewLine)) {
        return ('Copied what happened ({0} {1}) - paste it into the ticket.' -f $n, $(if ($n -eq 1) { 'line' } else { 'lines' }))
    }
    "Couldn't copy: another program is using the clipboard. Wait a moment and try again."
}


# The picture strip's layout in the window: server names on the left, then the time axis.
$script:StripLabelPx = 118
$script:StripAxisPx = 14
$script:StripLanePx = 22
$script:StripPadPx = 6
$script:StripMaxLanes = 6
$script:StripBrushes = @{}

function Get-TimelineStripBrush {
    param([string]$Color)
    $b = $script:StripBrushes[$Color]
    if (-not $b) {
        $b = [System.Windows.Media.SolidColorBrush][System.Windows.Media.ColorConverter]::ConvertFromString($Color)
        $b.Freeze()
        $script:StripBrushes[$Color] = $b
    }
    $b
}

function Get-TimelineStripCanvasHeight {
    <# The canvas height for this many lanes (the axis on top, a little room below). #>
    param([int]$LaneCount)
    $script:StripAxisPx + [Math]::Max(1, $LaneCount) * $script:StripLanePx + $script:StripPadPx
}

function Convert-TimelineStripXToUtc {
    <# A point on the strip's plot area (0 = left edge) back to a UTC time, kept inside the window. #>
    param([double]$X, [Parameter(Mandatory)][double]$Width, [Parameter(Mandatory)][datetime]$StartUtc, [Parameter(Mandatory)][datetime]$EndUtc)
    $f = [Math]::Min(1.0, [Math]::Max(0.0, $X / [Math]::Max(1.0, $Width)))
    [datetime]::SpecifyKind($StartUtc.AddTicks([long](($EndUtc - $StartUtc).Ticks * $f)), [DateTimeKind]::Utc)
}

function Test-TimelineStripDue {
    <#
        Whether the strip should be drawn now: always when forced, when the search has finished
        or on the first draw; while results arrive, at most once every 2 seconds.
    #>
    param([Parameter(Mandatory)]$Clock, [bool]$Finished, [switch]$Force)
    if ($Force -or $Finished -or -not $Clock.IsRunning) { return $true }
    $Clock.Elapsed.TotalSeconds -ge 2
}

function Set-TimelineStripHidden {
    <# Folds the picture away (the header stays, with a button to bring it back) or shows it. #>
    param([Parameter(Mandatory)]$Window, [bool]$Hidden)
    $Window.FindName('StripScroll').Visibility = if ($Hidden) { 'Collapsed' } else { 'Visible' }
    $toggle = $Window.FindName('HidePictureToggle')
    $toggle.IsChecked = $Hidden
    $toggle.Content = if ($Hidden) { 'Show picture' } else { 'Hide picture' }
}

function Set-TimelineTimeRange {
    <#
        Narrows the event list to a stretch of time (dragged on the strip), or clears it with
        $null. The chip in the filter bar shows the range in the strip's time (server local, or
        UTC when the servers' clocks differ) and its x clears it.
    #>
    param([Parameter(Mandatory)][hashtable]$Ui, $FromUtc, $ToUtc, [int]$OffsetMinutes = 0, [bool]$Utc = $false)
    if ($null -eq $FromUtc -or $null -eq $ToUtc) {
        $Ui.TimeRange = $null
        if ($Ui.TimeRangeChip) { $Ui.TimeRangeChip.Visibility = 'Collapsed' }
        return
    }
    $from = [datetime]$FromUtc; $to = [datetime]$ToUtc
    if ($to -lt $from) { $from, $to = $to, $from }
    $Ui.TimeRange = @{ StartUtc = $from; EndUtc = $to }
    if ($Ui.TimeRangeChip) {
        $a = $from.AddMinutes($OffsetMinutes); $b = $to.AddMinutes($OffsetMinutes)
        $fmt = if ($a.Date -eq $b.Date) { 'HH:mm' } else { 'MM-dd HH:mm' }
        $Ui.TimeRangeText.Text = '{0} - {1}{2}' -f $a.ToString($fmt), $b.ToString($fmt), $(if ($Utc) { ' UTC' } else { '' })
        $Ui.TimeRangeChip.Visibility = 'Visible'
    }
}

function Update-TimelineStripToolTip {
    <# Fills a strip shape's hover text when it opens (made on demand: there can be hundreds). #>
    param([Parameter(Mandatory)]$Element)
    if ($Element.DataContext) { $Element.ToolTip = Get-TimelineStripToolTip -Item $Element.DataContext }
}

$script:StripToolTipHandler = $null

function Show-TimelineStrip {
    <#
        Draws a Get-TimelineStripModel result on the window's strip: lane names, the time axis,
        down bars, error dots and flagged-event symbols. Marks carry their row (Tag = row id)
        for a click; dots and marks get their hover text when it opens. -Width is the plot area.
    #>
    param([Parameter(Mandatory)]$Window, [Parameter(Mandatory)]$Model, [Parameter(Mandatory)][double]$Width)
    $canvas = $Window.FindName('StripCanvas')
    $scroll = $Window.FindName('StripScroll')
    $lanes = @($Model.Lanes)
    $canvas.Children.Clear()
    $canvas.Height = Get-TimelineStripCanvasHeight -LaneCount $lanes.Count
    $scroll.MaxHeight = Get-TimelineStripCanvasHeight -LaneCount $script:StripMaxLanes
    $Window.FindName('StripAxisNote').Text = if ($Model.AxisIsUtc) { '(UTC)' } else { '(server local time)' }
    if (-not $script:StripToolTipHandler) {
        $script:StripToolTipHandler = [System.Windows.Controls.ToolTipEventHandler] { param($s, $e) Update-TimelineStripToolTip -Element $s }
    }
    $x0 = $script:StripLabelPx
    $top = $script:StripAxisPx
    $lanePx = $script:StripLanePx
    $muted = Get-TimelineStripBrush '#8B94A3'
    $line = Get-TimelineStripBrush '#262A33'
    $grid = Get-TimelineStripBrush '#1E222A'
    $add = {
        param($el, [double]$left, [double]$y)
        [System.Windows.Controls.Canvas]::SetLeft($el, $left)
        [System.Windows.Controls.Canvas]::SetTop($el, $y)
        [void]$canvas.Children.Add($el)
    }

    foreach ($t in @($Model.Ticks)) {
        $g = [System.Windows.Shapes.Line]::new()
        $g.X1 = $x0 + $t.X; $g.X2 = $g.X1; $g.Y1 = $top - 2; $g.Y2 = $canvas.Height - 4; $g.Stroke = $grid; $g.StrokeThickness = 1
        [void]$canvas.Children.Add($g)
        $tb = [System.Windows.Controls.TextBlock]::new()
        $tb.Text = $t.Label; $tb.FontSize = 10; $tb.Foreground = $muted
        & $add $tb ($x0 + $t.X - 14) -1
    }
    foreach ($l in $lanes) {
        $y = $top + $l.Index * $lanePx + $lanePx / 2
        $name = [string]$l.Server
        $short = if ($name -match '^\d{1,3}(\.\d{1,3}){3}$') { $name } else { ($name -split '\.')[0] }
        $tb = [System.Windows.Controls.TextBlock]::new()
        $tb.Text = $short; $tb.ToolTip = $name; $tb.FontSize = 11; $tb.Width = $x0 - 10; $tb.TextTrimming = 'CharacterEllipsis'
        $tb.Foreground = Get-TimelineStripBrush '#D7DCE3'
        & $add $tb 6 ($y - 8)
        $base = [System.Windows.Shapes.Line]::new()
        $base.X1 = $x0; $base.X2 = $x0 + $Width; $base.Y1 = $y; $base.Y2 = $y; $base.Stroke = $line; $base.StrokeThickness = 1
        [void]$canvas.Children.Add($base)
    }
    foreach ($b in @($Model.DownBars)) {
        $r = [System.Windows.Shapes.Rectangle]::new()
        $r.Uid = 'bar'; $r.Width = [Math]::Max(2, $b.X2 - $b.X1); $r.Height = 12; $r.RadiusX = 2; $r.RadiusY = 2
        $r.Fill = Get-TimelineStripBrush '#2A2F3A'; $r.Stroke = Get-TimelineStripBrush '#4A5160'; $r.ToolTip = $b.Text
        & $add $r ($x0 + $b.X1) ($top + $b.Lane * $lanePx + $lanePx / 2 - 6)
    }
    $red = Get-TimelineStripBrush '#E06C5A'
    foreach ($d in @($Model.Dots)) {
        $e = [System.Windows.Shapes.Ellipse]::new()
        # A 5 px dot was too small to hover: the dot is drawn 5 px wide (WPF fills inside half
        # the stroke, so 14 - 9) inside a clear 14 px
        # ring that still takes the mouse (a Transparent brush is hit-testable, null isn't).
        $e.Uid = 'dot'; $e.Width = 14; $e.Height = 14; $e.Fill = $red; $e.Opacity = $d.Opacity
        $e.Stroke = [System.Windows.Media.Brushes]::Transparent; $e.StrokeThickness = 9
        $e.Tag = $d.RowId; $e.Cursor = [System.Windows.Input.Cursors]::Hand
        $e.DataContext = $d; $e.ToolTip = ' '; $e.add_ToolTipOpening($script:StripToolTipHandler)
        & $add $e ($x0 + $d.X - 7) ($top + $d.Lane * $lanePx + $lanePx / 2 - 7)
    }
    foreach ($m in @($Model.Marks)) {
        $brush = Get-TimelineStripBrush $m.Color
        $cx = $x0 + $m.X; $cy = $top + $m.Lane * $lanePx + $lanePx / 2
        switch ($m.Shape) {
            'Triangle' { $s = [System.Windows.Shapes.Polygon]::new(); $s.Points = [System.Windows.Media.PointCollection]::Parse('5,0 10,9 0,9'); $s.Fill = $brush; $ox = 5; $oy = 5 }
            'Diamond' { $s = [System.Windows.Shapes.Polygon]::new(); $s.Points = [System.Windows.Media.PointCollection]::Parse('5,0 10,5 5,10 0,5'); $s.Fill = $brush; $ox = 5; $oy = 5 }
            'Square' { $s = [System.Windows.Shapes.Rectangle]::new(); $s.Width = 9; $s.Height = 9; $s.RadiusX = 1.5; $s.RadiusY = 1.5; $s.Fill = $brush; $ox = 4.5; $oy = 4.5 }
            'Cross' {
                $s = [System.Windows.Shapes.Path]::new(); $s.Data = [System.Windows.Media.Geometry]::Parse('M0,0 L9,9 M9,0 L0,9')
                $s.Stroke = $brush; $s.StrokeThickness = 2.6; $s.StrokeStartLineCap = 'Round'; $s.StrokeEndLineCap = 'Round'
                # A clear backing so the gaps between the strokes still take the click.
                $s.Fill = [System.Windows.Media.Brushes]::Transparent; $ox = 4.5; $oy = 4.5
            }
            default { $s = [System.Windows.Shapes.Ellipse]::new(); $s.Width = 8; $s.Height = 8; $s.Fill = $brush; $ox = 4; $oy = 4 }
        }
        $s.Uid = 'mark'; $s.Tag = $m.RowId; $s.DataContext = $m; $s.Cursor = [System.Windows.Input.Cursors]::Hand
        $s.ToolTip = ' '; $s.add_ToolTipOpening($script:StripToolTipHandler)
        & $add $s ($cx - $ox) ($cy - $oy)
    }

    $legend = $Window.FindName('StripLegend')
    if ($legend -and $legend.Inlines.Count -eq 0) {
        foreach ($part in @(@('Disk', 'disk'), @('AppCrash', 'crash'), @('Update', 'update'), @('TimeJump', 'time'), @('Restart', 'restart/other'))) {
            $st = Get-TimelineCategoryStyle -Category $part[0]
            $glyph = [System.Windows.Documents.Run]::new($st.Glyph + ' ')
            $glyph.Foreground = Get-TimelineStripBrush $st.Color; $glyph.FontFamily = 'Segoe UI Symbol'
            $legend.Inlines.Add($glyph); $legend.Inlines.Add([System.Windows.Documents.Run]::new($part[1] + '   '))
        }
        $dot = [System.Windows.Documents.Run]::new([string][char]0x2022 + ' '); $dot.Foreground = $red
        $legend.Inlines.Add($dot); $legend.Inlines.Add([System.Windows.Documents.Run]::new('errors   drag to zoom, double-click to zoom out'))
    }
}

function New-ServerAddMenu {
    <#
        The menu behind the arrow next to Add: Add several..., Add this computer, Recent lists
        (a submenu; picking one replaces the list) and, below a line, Clear the list (greyed out
        when it's empty). Each item's Tag says what it does: AddSeveral, ThisComputer, Clear,
        or Recent:<the list>.
    #>
    param([int]$ServerCount, [string[]]$RecentLists)
    $menu = [System.Windows.Controls.ContextMenu]::new()
    $item = {
        param([string]$Header, [string]$Tag, [string]$Tip)
        $mi = [System.Windows.Controls.MenuItem]::new()
        $mi.Header = $Header; $mi.Tag = $Tag
        if ($Tip) { $mi.ToolTip = $Tip }
        $mi
    }
    [void]$menu.Items.Add((& $item 'Add several... (paste, find in AD, or a file)' 'AddSeveral' 'Paste a list, find servers in Active Directory, or read them from a .txt or .csv file'))
    [void]$menu.Items.Add((& $item 'Add this computer' 'ThisComputer' 'Its logs are read directly: no network needed'))
    $recent = & $item 'Recent lists' 'Recent' 'Server lists you searched before (remembered per user). Picking one replaces the list.'
    $lists = @($RecentLists | Where-Object { $_ })
    if ($lists.Count -eq 0) {
        $none = & $item 'No recent searches yet' ''
        $none.IsEnabled = $false
        [void]$recent.Items.Add($none)
    }
    foreach ($l in $lists) {
        $header = if ($l.Length -gt 90) { $l.Substring(0, 87) + '...' } else { $l }
        [void]$recent.Items.Add((& $item $header "Recent:$l" $l))
    }
    [void]$menu.Items.Add($recent)
    [void]$menu.Items.Add([System.Windows.Controls.Separator]::new())
    $clearHeader = if ($ServerCount -eq 1) { 'Clear the list (1 server)' } elseif ($ServerCount -gt 1) { "Clear the list ($ServerCount servers)" } else { 'Clear the list' }
    $clear = & $item $clearHeader 'Clear' 'Remove every server from the list (asks first when there are more than 3)'
    $clear.IsEnabled = $ServerCount -gt 0
    [void]$menu.Items.Add($clear)
    $menu
}

function Register-TimelineErrorGuard {
    <#
        An exception inside a button or menu handler escapes the WPF dispatcher, ShowDialog
        throws and the window closes; its console is hidden, so nobody sees why. This handles
        the dispatcher's UnhandledException instead: $OnError gets the message and the window
        stays open. Returns the handler so it can be removed.
          https://learn.microsoft.com/dotnet/api/system.windows.threading.dispatcher.unhandledexception
    #>
    param([Parameter(Mandatory)][System.Windows.Threading.Dispatcher]$Dispatcher, [Parameter(Mandatory)][scriptblock]$OnError)
    $handler = [System.Windows.Threading.DispatcherUnhandledExceptionEventHandler] {
        param($source, $e)
        $e.Handled = $true
        $ex = $e.Exception
        # PowerShell wraps a failed .NET call in MethodInvocationException; the inner one says what went wrong.
        while ($ex.InnerException -and $ex -is [System.Management.Automation.MethodInvocationException]) { $ex = $ex.InnerException }
        try { & $OnError $ex.Message } catch { }
    }.GetNewClosure()
    $Dispatcher.add_UnhandledException($handler)
    $handler
}

function Test-TimelineOwnProcess {
    <#
        True when this PowerShell process was started only to run this script (-File <this
        script>, without -NoExit), so the window can run here. Otherwise the window is started in
        a new process: in a long-running session (VS Code's PowerShell, a terminal open for hours)
        WPF crashed with Win32Exception 1816 "Not enough quota is available to process this
        command" (HwndTarget.UpdateWindowSettings), killing the whole session. Every crash on
        record was in a process that had been open for 30 minutes to 20 hours; none in a fresh one.
    #>
    param([string[]]$CommandLineArgs, [Parameter(Mandatory)][string]$ScriptPath)
    $fileArg = $null
    for ($i = 0; $i -lt $CommandLineArgs.Count; $i++) {
        $a = $CommandLineArgs[$i]
        if ($a -like '-noe*') { return $false }
        if (($a -eq '-File' -or $a -eq '-f') -and $i + 1 -lt $CommandLineArgs.Count) { $fileArg = $CommandLineArgs[$i + 1]; break }
    }
    if (-not $fileArg) { return $false }
    try { $full = [System.IO.Path]::GetFullPath($fileArg.Trim('"')) } catch { return $false }
    return [string]::Equals($full, [System.IO.Path]::GetFullPath($ScriptPath), [StringComparison]::OrdinalIgnoreCase)
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
        Restoring = $false; SummaryKey = ''; Story = $null
        TimeRange = $null; StripClock = (New-Object System.Diagnostics.Stopwatch); StripModel = $null; StripSpan = $null; StripWidth = 0; SearchStartedUtc = $null; StripDrag = $null
    }
    foreach ($name in 'SummaryBorder', 'SummaryList', 'CollapseCheck', 'HiddenNote', 'ShowAllButton', 'TotalCapBox', 'TicketNoteButton', 'LogsButton','LogsPopup', 'CoreLogPanel', 'LogsAllButton', 'LogsNoneButton', 'LogsDefaultButton',
        'SaveFolderBox', 'BrowseFolderButton', 'OpenFolderButton', 'AddMenuButton', 'ServerListHint', 'ServerInput', 'ServerInputHint', 'AddServerButton', 'ServerCountText', 'DomainText', 'ChangeDomainButton',
        'ServerList', 'SuggestPopup', 'SuggestList', 'AroundRadio', 'RangeRadio', 'AtBox', 'PlusMinusCombo', 'FromBox', 'ToBox', 'LastHourButton',
        'Last24Button', 'LogPanel', 'SecurityCheck', 'AllLogsCheck', 'CapBox', 'TimeoutBox', 'RunAsButton',
        'SearchButton', 'CancelButton', 'InputError', 'BannerText', 'TimeZoneNote', 'LevelFilter', 'ServerFilter',
        'LogFilter', 'FlaggedOnlyCheck', 'FilterText', 'CountText', 'EventGrid', 'DetailText', 'ExportCsvButton', 'ExportHtmlButton',
        'CopyButton', 'StatusMessage', 'DetailTabs', 'StoryList', 'StoryEmptyText', 'CopyStoryButton', 'StripBorder', 'StripScroll', 'StripCanvas', 'StripAxisNote', 'StripLegend', 'HidePictureToggle', 'TimeRangeChip', 'TimeRangeText', 'ClearRangeButton', 'SidebarColumn', 'SidebarPanel', 'SidebarStrip', 'SidebarSplitter', 'CollapseSidebarButton', 'ExpandSidebarButton', 'NotesList') {
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

    # Whatever goes wrong in a button or menu, the window stays open and says what happened.
    $null = Register-TimelineErrorGuard -Dispatcher $window.Dispatcher -OnError {
        param($Message)
        if ($ui.Smoke) { [void]$ui.SmokeFailures.Add("an error in the window: $Message") }
        Write-TimelineLog FAIL "Something went wrong (the window stays open): $Message"
        Set-StatusMessage "Something went wrong: $Message"
    }

    # Inputs: defaults
    $now = Get-Date
    # Starts with this computer filled in when no servers were given.
    # The server list: one row per server (ServerList.ps1 builds the rows and their notes).
    $ui.LocalNames = @(Get-LocalComputerNames)
    $ui.ServerItems = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
    $ui.ServerList.ItemsSource = $ui.ServerItems
    $ui.Directory = @(); $ui.LoadedDomain = ''
    function Update-ServerCount {
        $n = $ui.ServerItems.Count
        $ui.ServerCountText.Text = if ($n -eq 1) { '1 server' } else { "$n servers" }
        $ui.ServerListHint.Visibility = if ($n -eq 0) { 'Visible' } else { 'Collapsed' }
    }
    function Update-ServerNotes {
        foreach ($item in @($ui.ServerItems)) {
            $lookup = if ($ui.Lookups) { $ui.Lookups[[string]$item.Name] } else { $null }
            Update-ServerListNote -Item $item -Directory $ui.Directory -LoadedDomain $ui.LoadedDomain -Lookup $lookup
        }
        # The rows are plain objects: redraw them so new notes show.
        $ui.ServerList.Items.Refresh()
    }
    function Add-ServersToList {
        param([string[]]$Names)
        $added = @(Add-ServerListItems -Items $ui.ServerItems -Names $Names -LocalNames $ui.LocalNames)
        Update-ServerNotes
        Update-ServerCount
        Update-InputState
        if (Get-Command Request-ServerLookups -ErrorAction SilentlyContinue) { Request-ServerLookups -Names $added }
        $added
    }
    # Starts with this computer filled in when no servers were given.
    $given = @($ComputerName | Where-Object { $_ })
    $startNames = if ($given.Count -gt 0) { $given } else { @($ui.LocalNames[0]) }
    $null = Add-ServerListItems -Items $ui.ServerItems -Names $startNames -LocalNames $ui.LocalNames
    Update-ServerCount
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
        ConvertFrom-TimelineInputs -ServersText (Get-ServerSearchText -Items @($ui.ServerItems)) -Mode $Mode -AtText $ui.AtBox.Text `
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
        $serversOk = $ui.ServerItems.Count -gt 0
        $ui.LastHourButton.IsEnabled = $serversOk -and -not $running
        $ui.Last24Button.IsEnabled = $serversOk -and -not $running
        $ui.CancelButton.IsEnabled = [bool]$running
        $ui.TicketNoteButton.IsEnabled = [bool]($ui.Engine -and $ui.Finished)
    }

    function Get-CurrentFilter { Get-TimelineGridFilter -Ui $ui }

    function Update-Summary {
        # The strip above the grid: what was found on each server, from every event read.
        if (-not $ui.Engine) { $ui.SummaryBorder.Visibility = 'Collapsed'; return }
        # Recounted only when rows arrived or a server's state changed (not on every filter change).
        $key = '{0}|{1}' -f $ui.Store.Rows.Count, (@($ui.Engine.Status.Values | ForEach-Object { "$($_.Server)=$($_.State)" }) -join ',')
        if ($key -eq $ui.SummaryKey) { return }
        $ui.SummaryKey = $key
        $lines = @(Get-TimelineSummaryLines -Rows $ui.Store.Rows.ToArray() -Status $ui.Engine.Status -Logs $ui.Selected `
                -ErrorHint " - set Show to 'Errors and worse' to review them" `
                -SecurityHint "Security log not read: tick it under Which logs? to see sign-in or lockout problems.")
        # One card per server in the sidebar: how reading it went, then what was found.
        $ui.SummaryList.ItemsSource = @(Get-TimelineServerCards -Status $ui.Engine.Status -SummaryLines $lines)
        $ui.NotesList.ItemsSource = @(Get-TimelineServerNotes -Status $ui.Engine.Status -SummaryLines $lines)
        $ui.SummaryBorder.Visibility = 'Visible'
        # What happened, in order, from every event read (same "rows arrived" trigger).
        # From the flagged and error rows only (every row is context for quiet gaps): walking
        # every row took ~0.8 s per update at 40,000 rows and froze the window.
        $ui.Story = Get-TimelineStory -Rows $ui.Store.Notable.ToArray() -ContextRows $ui.Store.Rows.ToArray()
        Set-TimelineStoryView -Window $window -Story $ui.Story
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

    function Update-Strip {
        # The picture above the list: flagged events and errors per server, following the
        # filters. Drawn when a search finishes or a filter changes, at most every 2 seconds
        # while results arrive (Test-TimelineStripDue), from the store's notable rows only.
        param([switch]$Force)
        if (-not $ui.Engine) { $ui.StripBorder.Visibility = 'Collapsed'; return }
        $ui.StripBorder.Visibility = 'Visible'
        if ($ui.HidePictureToggle.IsChecked) { return }
        if (-not (Test-TimelineStripDue -Clock $ui.StripClock -Finished $ui.Finished -Force:$Force)) { return }
        $ui.StripClock.Restart()
        $span = if ($ui.TimeRange) { $ui.TimeRange } else { Get-TimelineStripWindow -Window $ui.Engine.Window -Status $ui.Engine.Status -NowUtc $ui.SearchStartedUtc }
        $room = if ($ui.StripScroll.ActualWidth -gt 0) { $ui.StripScroll.ActualWidth } else { 900 }
        $width = [Math]::Max(120, $room - $script:StripLabelPx - 24)
        $ui.StripModel = Get-TimelineStoreStripModel -Store $ui.Store -Filter (Get-CurrentFilter) -Servers @($ui.Engine.Status.Keys) -StartUtc $span.StartUtc -EndUtc $span.EndUtc -Width $width `
            -UtcOffsets (Get-TimelineServerOffsets -Status $ui.Engine.Status)
        $ui.StripSpan = $span; $ui.StripWidth = $width
        Show-TimelineStrip -Window $window -Model $ui.StripModel -Width $width
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
            Update-Strip
            $ui.LastRebuild.Restart()
        }
        finally { $ui.InUpdate = $false }
    }

    function Update-StatusPanel {
        if (-not $ui.Engine) { return }
        $status = $ui.Engine.Status
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
        $ui.Story = $null
        Set-TimelineStoryView -Window $window -Story $null
        Set-TimelineTimeRange -Ui $ui -FromUtc $null -ToUtc $null
        $ui.SearchStartedUtc = [datetime]::UtcNow
        $ui.StripClock.Reset()
        $ui.StripCanvas.Children.Clear()
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
        # The server cards are below the inputs; bring them into view on a short window.
        $ui.SummaryBorder.Visibility = 'Visible'
        $ui.SummaryBorder.BringIntoView()
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
        if ($ui.TimeRange) { $filtersText += '; time: {0}' -f $ui.TimeRangeText.Text }
        $span = if ($ui.TimeRange) { $ui.TimeRange } else { Get-TimelineStripWindow -Window $ui.Engine.Window -Status $ui.Engine.Status -NowUtc $ui.SearchStartedUtc }
        @{
            WindowText = Get-TimelineWindowText -Window $ui.Request.Window
            Servers = $ui.Request.Servers; Logs = $ui.Selected; FiltersText = $filtersText; GeneratedAt = Get-Date
            ServerOutcomes = @($ui.Engine.Status.Values)
            Summary = @(Get-TimelineSummaryLines -Rows $ui.Store.Rows.ToArray() -Status $ui.Engine.Status -Logs $ui.Selected)
            # The picture's time: the dragged range, else the whole search window.
            StartUtc = $span.StartUtc; EndUtc = $span.EndUtc
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
                [System.IO.File]::WriteAllText($path, (ConvertTo-TimelineHtml -Rows $rows -Context (Get-ExportContext) -ContextRows $ui.Store.Rows.ToArray()), (New-Object System.Text.UTF8Encoding $true))
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
    foreach ($box in @($ui.AtBox, $ui.FromBox, $ui.ToBox, $ui.CapBox, $ui.TimeoutBox, $ui.TotalCapBox)) { $box.add_TextChanged({ Update-InputState }) }
    $ui.CollapseCheck.add_Click({ Update-View })
    $ui.ShowAllButton.add_Click({
            $ui.Hidden.Clear(); $ui.EventKey = ''
            Set-TimelineTimeRange -Ui $ui -FromUtc $null -ToUtc $null
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

    # The arrow next to Add: several at once, this computer, a recent list, or clear the list.
    # Built fresh each time it opens, so the recent lists and the server count are current.
    $ui.AddMenuButton.add_Click({
            $lists = if ($ui.Smoke) { @() } else { @((Read-TimelineSettings -Path $SettingsPath).RecentServerLists) }
            $menu = New-ServerAddMenu -ServerCount $ui.ServerItems.Count -RecentLists $lists
            $menu.AddHandler([System.Windows.Controls.MenuItem]::ClickEvent, [System.Windows.RoutedEventHandler] {
                    param($sender, $e)
                    $tag = [string]$e.OriginalSource.Tag
                    if ($tag -eq 'AddSeveral') { & $addSeveral }
                    elseif ($tag -eq 'ThisComputer') { & $addThisComputer }
                    elseif ($tag -eq 'Clear') { & $clearServers }
                    elseif ($tag -like 'Recent:*') {
                        # A remembered list replaces the current one.
                        $ui.ServerItems.Clear()
                        $null = Add-ServersToList -Names @($tag.Substring(7))
                        Update-ServerCount
                    }
                })
            $menu.PlacementTarget = $ui.AddMenuButton
            $menu.Placement = 'Bottom'
            $menu.IsOpen = $true
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
                [System.IO.File]::WriteAllText($htmlPath, (ConvertTo-TimelineHtml -Rows @($ui.VisibleRows) -Context $context -ContextRows $ui.Store.Rows.ToArray()), (New-Object System.Text.UTF8Encoding $true))
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
            # Suggestions come from AD as this account too.
            Start-WindowDirectoryLoad
        })

    # The sidebar folds away (<<) and comes back (>>).
    $ui.CollapseSidebarButton.add_Click({ Set-TimelineSidebar -Window $window -Collapsed $true })
    $ui.ExpandSidebarButton.add_Click({ Set-TimelineSidebar -Window $window -Collapsed $false })

    # Clicking a server card shows only that server's events; clicking it again shows them all.
    $ui.SummaryList.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler] {
            param($source, $e)
            $server = [string]$e.OriginalSource.Tag
            if (-not $server) { return }
            $current = if ($ui.ServerFilter.SelectedItem) { [string]$ui.ServerFilter.SelectedItem.Tag } else { '*' }
            $want = if ($current -eq $server) { '*' } else { $server }
            $item = @($ui.ServerFilter.Items | Where-Object { [string]$_.Tag -eq $want })[0]
            if ($item) { $ui.ServerFilter.SelectedItem = $item }
        })

    $addThisComputer = {
        $null = Add-ServersToList -Names @($ui.LocalNames[0])
    }

    # Typing a server: Enter or Add puts it in the list (pasted text with commas, spaces or new
    # lines becomes several rows).
    $addTyped = {
        $text = $ui.ServerInput.Text
        if (-not $text.Trim()) { return }
        $null = Add-ServersToList -Names @($text)
        $ui.ServerInput.Text = ''
        $ui.SuggestPopup.IsOpen = $false
    }
    $ui.ServerInput.add_TextChanged({ $ui.ServerInputHint.Visibility = if ($ui.ServerInput.Text) { 'Collapsed' } else { 'Visible' } })
    $ui.ServerInput.add_KeyDown({ param($s, $e) if ($e.Key -eq 'Return') { $e.Handled = $true; & $addTyped } })
    $ui.AddServerButton.add_Click({ & $addTyped })
    Register-ServerInputPaste -TextBox $ui.ServerInput -OnNames {
        param($Text)
        $added = @(Add-ServersToList -Names @($Text))
        Set-StatusMessage ('Added {0} pasted server(s) to the list.' -f $added.Count)
    }

    # The x on a row removes that server.
    $ui.ServerList.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler] {
            param($s, $e)
            $item = $e.OriginalSource.Tag
            if ($null -eq $item) { return }
            [void]$ui.ServerItems.Remove($item)
            Update-ServerCount
            Update-InputState
        })
    $clearServers = {
        $n = $ui.ServerItems.Count
        if ($n -eq 0) { return }
        if ($n -gt 3 -and -not $ui.Smoke) {
            $answer = [System.Windows.MessageBox]::Show("Remove all $n servers from the list?", 'Server Event Timeline', 'YesNo', 'Question')
            if ($answer -ne 'Yes') { return }
        }
        $ui.ServerItems.Clear()
        Update-ServerCount
        Update-InputState
    }

    # Suggestions: every computer account of the chosen domain (or DC) is read once in the
    # background (ServerList.ps1); typing then filters that list instantly. The heartbeat below
    # collects the load and the DNS lookups. A load started before the domain or Run as account
    # changed is thrown away (its generation is old).
    $ui.DirectoryGeneration = 0; $ui.DirectoryJob = $null; $ui.DirectoryState = 'NoDomain'
    $ui.RetiredJobs = New-Object System.Collections.Generic.List[object]
    $ui.Lookups = @{}; $ui.LookupJob = $null; $ui.LookupQueue = New-Object System.Collections.Generic.List[string]
    $ui.AdTarget = if ($ui.Smoke) { '' } else { [string](Read-TimelineSettings -Path $SettingsPath).AdTarget }
    $ui.AdAvailable = [bool](Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue)
    function Start-WindowDirectoryLoad {
        $ui.DirectoryGeneration++
        # A load for the old domain or account: stop it and let the heartbeat dispose of it.
        if ($ui.DirectoryJob) { Stop-BackgroundJob -Job $ui.DirectoryJob; $ui.RetiredJobs.Add($ui.DirectoryJob); $ui.DirectoryJob = $null }
        $ui.Directory = @(); $ui.LoadedDomain = ''
        if ($ui.Smoke -or -not $ui.AdAvailable) {
            $ui.DirectoryState = 'NoDomain'; $ui.DomainText.Text = Get-DomainLineText -State NoDomain
            Update-ServerNotes
            return
        }
        $ui.DirectoryState = 'Loading'
        $ui.DomainText.Text = Get-DomainLineText -State Loading -Domain $ui.AdTarget
        $ui.DirectoryJob = Start-DirectoryLoad -Server $ui.AdTarget -Credential $ui.Credential -Generation $ui.DirectoryGeneration
        Update-ServerNotes
    }
    function Receive-WindowDirectoryLoad {
        if (-not $ui.DirectoryJob) { return }
        $r = Receive-DirectoryLoad -Job $ui.DirectoryJob
        if ($null -eq $r) { return }
        $ui.DirectoryJob = $null
        if (Test-StaleDirectoryResult -Result $r -CurrentGeneration $ui.DirectoryGeneration) { return }
        if ($r.Ok) {
            $ui.Directory = @($r.Entries); $ui.LoadedDomain = $r.Domain; $ui.DirectoryState = 'Loaded'
            $ui.DomainText.Text = Get-DomainLineText -State Loaded -Domain $r.Domain -Count (Get-DirectoryServerCount -Directory $ui.Directory)
            Write-TimelineLog INFO $ui.DomainText.Text
            # Names typed before AD arrived and not found there: ask DNS about them.
            Request-ServerLookups -Names @($ui.ServerItems | ForEach-Object Name)
        }
        elseif (-not $ui.AdTarget -and -not (Get-LocalComputerIdentity).DomainName) {
            # Not joined to a domain and none chosen: only servers searched before are suggested.
            $ui.DirectoryState = 'NoDomain'; $ui.DomainText.Text = Get-DomainLineText -State NoDomain
        }
        else {
            $ui.DirectoryState = 'Failed'
            $ui.DomainText.Text = Get-DomainLineText -State Failed -Domain $ui.AdTarget -ErrorText $r.Error
            Write-TimelineLog WARN $ui.DomainText.Text
        }
        $ui.DomainText.Foreground = $window.FindResource($(if ($ui.DirectoryState -eq 'Failed') { 'Warn' } else { 'Muted' }))
        $ui.DomainText.ToolTip = $ui.DomainText.Text
        Update-ServerNotes
    }
    function Request-ServerLookups {
        # DNS for new IPs, and for names AD doesn't know; one background job at a time.
        param([string[]]$Names)
        if ($ui.Smoke) { return }
        foreach ($n in @($Names | Where-Object { $_ })) {
            if ($ui.Lookups.ContainsKey($n) -or $ui.LookupQueue.Contains($n)) { continue }
            $isIp = Test-IpAddress -Text $n
            $local = Test-IsLocalComputer -Name $n -LocalNames $ui.LocalNames
            $known = $null -ne (Find-DirectoryEntry -Directory $ui.Directory -Name $n)
            if ($isIp -or (-not $local -and -not $known -and $ui.DirectoryState -eq 'Loaded')) { $ui.LookupQueue.Add($n) }
        }
        if (-not $ui.LookupJob -and $ui.LookupQueue.Count -gt 0) {
            $ui.LookupJob = Start-NameLookups -Names $ui.LookupQueue.ToArray()
            $ui.LookupQueue.Clear()
        }
    }
    function Receive-WindowLookups {
        if (-not $ui.LookupJob) { return }
        $r = Receive-NameLookups -Job $ui.LookupJob
        if ($null -eq $r) { return }
        $ui.LookupJob = $null
        foreach ($k in $r.Keys) { $ui.Lookups[$k] = $r[$k] }
        Update-ServerNotes
        Request-ServerLookups -Names @()
    }
    if (-not $ui.AdAvailable) {
        $ui.ChangeDomainButton.IsEnabled = $false
        $ui.ChangeDomainButton.ToolTip = 'Needs the RSAT Active Directory tools on this workstation. You can still type server names and IP addresses.'
        [System.Windows.Controls.ToolTipService]::SetShowOnDisabled($ui.ChangeDomainButton, $true)
    }
    $ui.ChangeDomainButton.add_Click({
            if ($ui.Smoke) { return }
            # $null = Cancel (nothing changes); '' = this computer's domain.
            $text = Show-DomainPrompt -Owner $window -Current $ui.AdTarget
            if ($null -eq $text) { return }
            if ($text -eq $ui.AdTarget) { return }
            $ui.AdTarget = $text
            try { Save-TimelineSettings -Path $SettingsPath -AdTarget $text } catch { }
            Start-WindowDirectoryLoad
        })

    # "Add several...": paste, find in the loaded AD, or read a file; adds the ticked servers.
    $addSeveral = {
        if ($ui.Smoke) { return }
        $ui.SuggestPopup.IsOpen = $false
        $names = @(Show-AddServersDialog -Owner $window -Directory $ui.Directory -DirectoryState $ui.DirectoryState -DomainText $ui.DomainText.Text)
        if ($names.Count -gt 0) {
            $added = @(Add-ServersToList -Names $names)
            Set-StatusMessage ('Added {0} server(s) to the list.' -f $added.Count)
        }
    }

    # Autocomplete under the server box: Down/Up choose, Enter adds, Esc closes.
    $ui.ServerInput.add_TextChanged({
            $s = @(Find-ServerSuggestions -Directory $ui.Directory -Recent $(if ($ui.Smoke) { @() } else { @((Read-TimelineSettings -Path $SettingsPath).RecentServerLists) }) -Text $ui.ServerInput.Text -Max 8)
            $ui.SuggestList.ItemsSource = $s
            $ui.SuggestList.SelectedIndex = -1
            $ui.SuggestPopup.PlacementTarget = $ui.ServerInput
            $ui.SuggestPopup.IsOpen = $s.Count -gt 0 -and $ui.ServerInput.IsKeyboardFocused
        })
    $ui.ServerInput.add_PreviewKeyDown({
            param($s, $e)
            if (-not $ui.SuggestPopup.IsOpen) { return }
            $count = $ui.SuggestList.Items.Count
            switch ([string]$e.Key) {
                'Down' { $ui.SuggestList.SelectedIndex = [math]::Min($ui.SuggestList.SelectedIndex + 1, $count - 1); $ui.SuggestList.ScrollIntoView($ui.SuggestList.SelectedItem); $e.Handled = $true }
                'Up' { $ui.SuggestList.SelectedIndex = [math]::Max($ui.SuggestList.SelectedIndex - 1, 0); $ui.SuggestList.ScrollIntoView($ui.SuggestList.SelectedItem); $e.Handled = $true }
                'Escape' { $ui.SuggestPopup.IsOpen = $false; $e.Handled = $true }
                'Return' {
                    if ($ui.SuggestList.SelectedItem) {
                        $ui.ServerInput.Text = [string]$ui.SuggestList.SelectedItem.Name
                        & $addTyped
                        $e.Handled = $true
                    }
                }
            }
        })
    $ui.SuggestList.add_PreviewMouseLeftButtonUp({
            param($s, $e)
            $item = [System.Windows.Controls.ItemsControl]::ContainerFromElement($ui.SuggestList, $e.OriginalSource)
            if (-not $item) { return }
            $ui.ServerInput.Text = [string]$item.Content.Name
            & $addTyped
            $ui.ServerInput.Focus()
        })
    $ui.ServerInput.add_LostKeyboardFocus({ if (-not $ui.SuggestList.IsMouseOver) { $ui.SuggestPopup.IsOpen = $false } })
    # The popup does not follow the window when it moves; close it instead.
    $window.add_LocationChanged({ $ui.SuggestPopup.IsOpen = $false })
    $window.add_Deactivated({ $ui.SuggestPopup.IsOpen = $false })

    $ui.ExportCsvButton.add_Click({ Invoke-Export -Kind Csv })
    $ui.ExportHtmlButton.add_Click({ Invoke-Export -Kind Html })
    # A story line: select its event in the list (clearing filters that hide it).
    $ui.StoryList.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler] {
            param($sender, $e)
            $id = [string]$e.OriginalSource.Tag
            if (-not $id) { return }
            if (-not (Show-TimelineStoryRow -Ui $ui -RowId $id -Refresh { Update-View })) { Set-StatusMessage 'That event is no longer in the list.' }
        })
    # The picture: hover a symbol, click it, drag across to narrow the list, double-click to widen.
    $hidden = $false
    try { $hidden = -not (Read-TimelineSettings -Path $SettingsPath).ShowPicture } catch { }
    Set-TimelineStripHidden -Window $window -Hidden $hidden
    $ui.HidePictureToggle.add_Click({
            $hide = [bool]$ui.HidePictureToggle.IsChecked
            Set-TimelineStripHidden -Window $window -Hidden $hide
            if (-not $ui.Smoke) { try { Save-TimelineSettings -Path $SettingsPath -ShowPicture (-not $hide) } catch { } }
            if (-not $hide) { Update-Strip -Force }
        })
    $setRange = {
        param($From, $To)
        $utc = $ui.StripModel -and $ui.StripModel.AxisIsUtc
        $offset = if ($ui.StripModel) { [int]$ui.StripModel.AxisOffsetMinutes } else { 0 }
        Set-TimelineTimeRange -Ui $ui -FromUtc $From -ToUtc $To -OffsetMinutes $offset -Utc $utc
        Update-View
        Update-Strip -Force
    }
    $ui.ClearRangeButton.add_Click({ & $setRange $null $null })
    $ui.StripCanvas.add_MouseLeftButtonDown({
            param($sender, $e)
            if ($e.ClickCount -ge 2) { $ui.StripDrag = $null; if ($ui.TimeRange) { & $setRange $null $null }; return }
            $x = $e.GetPosition($ui.StripCanvas).X
            $band = [System.Windows.Shapes.Rectangle]::new()
            $band.Uid = 'drag'; $band.Height = $ui.StripCanvas.Height; $band.Width = 0; $band.IsHitTestVisible = $false
            $band.Fill = Get-TimelineStripBrush '#335DADE2'
            [System.Windows.Controls.Canvas]::SetLeft($band, $x); [System.Windows.Controls.Canvas]::SetTop($band, 0)
            [void]$ui.StripCanvas.Children.Add($band)
            $ui.StripDrag = @{ X = $x; Source = $e.OriginalSource; Band = $band }
            [void]$ui.StripCanvas.CaptureMouse()
        })
    $ui.StripCanvas.add_MouseMove({
            param($sender, $e)
            $d = $ui.StripDrag
            if (-not $d) { return }
            $x = $e.GetPosition($ui.StripCanvas).X
            [System.Windows.Controls.Canvas]::SetLeft($d.Band, [Math]::Min($x, $d.X))
            $d.Band.Width = [Math]::Abs($x - $d.X)
        })
    $ui.StripCanvas.add_MouseLeftButtonUp({
            param($sender, $e)
            $d = $ui.StripDrag
            $ui.StripDrag = $null
            $ui.StripCanvas.ReleaseMouseCapture()
            if (-not $d) { return }
            $ui.StripCanvas.Children.Remove($d.Band)
            $x = $e.GetPosition($ui.StripCanvas).X
            if ([Math]::Abs($x - $d.X) -gt 6 -and $ui.StripSpan) {
                $a = Convert-TimelineStripXToUtc -X ([Math]::Min($x, $d.X) - $script:StripLabelPx) -Width $ui.StripWidth -StartUtc $ui.StripSpan.StartUtc -EndUtc $ui.StripSpan.EndUtc
                $b = Convert-TimelineStripXToUtc -X ([Math]::Max($x, $d.X) - $script:StripLabelPx) -Width $ui.StripWidth -StartUtc $ui.StripSpan.StartUtc -EndUtc $ui.StripSpan.EndUtc
                if ($b -gt $a) { & $setRange $a $b }
                return
            }
            $id = [string]$d.Source.Tag
            if ($d.Source.Uid -in @('mark', 'dot') -and $id) {
                if (-not (Show-TimelineStoryRow -Ui $ui -RowId $id -Refresh { Update-View })) { Set-StatusMessage 'That event is no longer in the list.' }
            }
        })
    $stripResize = New-Object System.Windows.Threading.DispatcherTimer
    $stripResize.Interval = [TimeSpan]::FromMilliseconds(200)
    $stripResize.add_Tick({ $stripResize.Stop(); if ($ui.Engine) { Update-Strip -Force } })
    $ui.StripScroll.add_SizeChanged({ param($sender, $e) if ($e.WidthChanged) { $stripResize.Stop(); $stripResize.Start() } })
    $ui.CopyStoryButton.add_Click({ Set-StatusMessage (Copy-TimelineStory -Story $ui.Story) })
    $ui.CopyButton.add_Click({
            if ($ui.Smoke) { [void]$ui.SmokeFailures.Add('the clipboard would have been changed'); return }
            Set-StatusMessage (Copy-TimelineRows -Rows @($ui.EventGrid.SelectedItems))
        })

    # The heartbeat: collect background results without ever waiting on a server.
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(250)
    $timer.add_Tick({
            try {
                # The server list's background work runs whether or not a search is.
                Receive-WindowDirectoryLoad
                Receive-WindowLookups
                if ($ui.RetiredJobs.Count -gt 0) { Clear-FinishedJobs -Jobs $ui.RetiredJobs }
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
    # Read the chosen domain's servers for suggestions (in the background; not in smoke mode).
    Start-WindowDirectoryLoad

    $window.add_Closing({
            $timer.Stop()
            if ($ui.Engine) { Close-TimelineEngine -Engine $ui.Engine }
            # A slow AD or DNS call must not hold the window open: ask it to stop, don't wait.
            # (The process then exits with [Environment]::Exit, which doesn't wait for it either.)
            foreach ($job in @($ui.DirectoryJob, $ui.LookupJob)) { Stop-BackgroundJob -Job $job }
            foreach ($job in $ui.RetiredJobs.ToArray()) { Stop-BackgroundJob -Job $job }
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
                if ($ui.ServerItems.Count -lt 1) { [void]$ui.SmokeFailures.Add('the server list was not filled') }
                try { $null = [System.Windows.Markup.XamlReader]::Parse((New-AddServersDialogXaml)) }
                catch { [void]$ui.SmokeFailures.Add("the Add several servers dialog would not load: $($_.Exception.Message)") }
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

# The window always runs in a PowerShell process of its own, started with -STA (WPF needs an
# STA thread; some hosts are MTA). Run inside a long-lived session (VS Code's PowerShell, a
# terminal open for hours), WPF crashed with "Not enough quota is available to process this
# command" and took the whole session with it - see Test-TimelineOwnProcess.
$ownProcess = Test-TimelineOwnProcess -CommandLineArgs ([Environment]::GetCommandLineArgs()) -ScriptPath $PSCommandPath
if (-not $ownProcess -or [System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
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
    Write-Host '[INFO] Server Event Timeline is opening in its own window. This PowerShell stays free to use.' -ForegroundColor Cyan
    return
}

try {
    $code = Show-ServerEventTimeline -ComputerName $ComputerName -OutputPath $OutputPath -DefaultOutputPath $defaultOutputPath -SmokeTest:$SmokeTest
    # This process exists only for the window (see the relaunch above). A background AD or DNS
    # call blocked in .NET keeps a foreground thread alive, so a plain exit would leave the
    # hidden process running until that call times out; Environment.Exit ends it now.
    [Environment]::Exit([int](@($code)[-1]))
}
catch {
    Write-Host "[FAIL] Server Event Timeline could not start its window: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
