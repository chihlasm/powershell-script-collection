#Requires -Version 5.1
<#
    The "Add several servers" dialog for Server Event Timeline: paste a list, find servers in
    the Active Directory already loaded for suggestions, or read a .txt/.csv file. Every tab
    fills one list of results with tick boxes; "Add N servers" returns the ticked names.
    The checks (ServerEventTimeline.ServerList.ps1) run in the background: the dialog never
    waits on AD or DNS. Dot-sourced by Start-ServerEventTimeline.ps1.
#>

function Get-AddButtonText {
    <# "Add 4 servers" - the dialog's main button says what it does. #>
    param([int]$Count)
    if ($Count -le 0) { return 'Add servers' }
    if ($Count -eq 1) { return 'Add 1 server' }
    return "Add $Count servers"
}

function New-AddServersDialogXaml {
    <# The dialog's XAML: the same dark look as the main window (the folder is self-contained). #>
    @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Add several servers" Width="480" Height="560" MinWidth="420" MinHeight="460"
        Background="#16181D" Foreground="#D7DCE3" FontFamily="Segoe UI" FontSize="13"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False" ResizeMode="CanResizeWithGrip">
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
    <Style TargetType="TextBlock"><Setter Property="Foreground" Value="{StaticResource Text}"/></Style>
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
      <Setter Property="Padding" Value="6,4"/>
      <Style.Triggers>
        <Trigger Property="IsKeyboardFocused" Value="True"><Setter Property="BorderBrush" Value="{StaticResource Accent}"/></Trigger>
        <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="CheckBox"><Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="Cursor" Value="Hand"/><Setter Property="VerticalAlignment" Value="Center"/></Style>
    <Style TargetType="RadioButton"><Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="Margin" Value="0,0,12,0"/><Setter Property="VerticalAlignment" Value="Center"/><Setter Property="Cursor" Value="Hand"/></Style>
    <Style TargetType="TabItem">
      <Setter Property="Foreground" Value="{StaticResource Muted}"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Border x:Name="tb" Padding="12,7" BorderThickness="0,0,0,2" BorderBrush="Transparent" Background="Transparent">
              <ContentPresenter ContentSource="Header"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="tb" Property="BorderBrush" Value="{StaticResource Accent}"/>
                <Setter Property="Foreground" Value="{StaticResource Text}"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True"><Setter Property="Foreground" Value="{StaticResource Text}"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>

  <Grid Margin="14">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <TabControl x:Name="Tabs" Grid.Row="0" Background="Transparent" BorderThickness="0,1,0,0" BorderBrush="{StaticResource Line}" Padding="0,10,0,0">
      <TabItem x:Name="PasteTab" Header="Paste">
        <StackPanel>
          <TextBlock Foreground="{StaticResource Muted}" FontSize="12" Margin="0,0,0,6" TextWrapping="Wrap"
                     Text="Paste server names or IP addresses, separated by commas, spaces or new lines. Each one is checked against Active Directory and DNS."/>
          <TextBox x:Name="PasteBox" Height="96" AcceptsReturn="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" FontFamily="Consolas" FontSize="12"/>
          <Button x:Name="CheckNamesButton" Content="Check names" HorizontalAlignment="Left" Margin="0,8,0,0" Padding="10,4"/>
        </StackPanel>
      </TabItem>
      <TabItem x:Name="FindTab" Header="Find in AD">
        <StackPanel>
          <TextBlock x:Name="FindNote" Foreground="{StaticResource Warn}" FontSize="12" Margin="0,0,0,6" TextWrapping="Wrap" Visibility="Collapsed"/>
          <TextBox x:Name="FindBox" ToolTip="Part of the server name, for example SQL or FS. Leave empty to list them all."/>
          <WrapPanel Margin="0,8,0,0">
            <RadioButton x:Name="ScopeAll" Content="All servers" GroupName="Scope" IsChecked="True" Margin="0,0,12,4"/>
            <RadioButton x:Name="ScopeDcs" Content="Domain controllers" GroupName="Scope" Margin="0,0,12,4"/>
            <RadioButton x:Name="ScopeOu" Content="In an OU:" GroupName="Scope" Margin="0,0,6,4"/>
          </WrapPanel>
          <ComboBox x:Name="OuCombo" IsEnabled="False" Margin="0,2,0,0" ToolTip="Servers in this OU and the OUs beneath it"/>
        </StackPanel>
      </TabItem>
      <TabItem x:Name="FileTab" Header="From a file">
        <StackPanel>
          <TextBlock Foreground="{StaticResource Muted}" FontSize="12" Margin="0,0,0,6" TextWrapping="Wrap"
                     Text="A .txt file with one server per line, or a .csv file with a column of server names (Name, DNSHostName, IPAddress and similar are found by themselves)."/>
          <StackPanel Orientation="Horizontal">
            <Button x:Name="FileButton" Content="Choose file..." Padding="10,4"/>
          </StackPanel>
          <TextBlock x:Name="FilePathText" Foreground="{StaticResource Muted}" FontSize="12" Margin="0,8,0,0" TextWrapping="Wrap" Text="No file chosen."/>
          <StackPanel x:Name="ColumnPanel" Orientation="Horizontal" Margin="0,8,0,0" Visibility="Collapsed">
            <TextBlock Text="Server names are in column:" VerticalAlignment="Center" Margin="0,0,8,0"/>
            <ComboBox x:Name="ColumnCombo" MinWidth="160"/>
          </StackPanel>
        </StackPanel>
      </TabItem>
    </TabControl>

    <ListBox x:Name="ResultList" Grid.Row="1" Margin="0,12,0,0" Background="{StaticResource Panel}" BorderBrush="{StaticResource Line}"
             Foreground="{StaticResource Text}" HorizontalContentAlignment="Stretch" ScrollViewer.HorizontalScrollBarVisibility="Disabled">
      <ListBox.ItemTemplate>
        <DataTemplate>
          <Grid>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <CheckBox Grid.Column="0" IsChecked="{Binding Ticked, Mode=OneWay}" Tag="{Binding}" Margin="0,0,8,0"/>
            <TextBlock Grid.Column="1" Text="{Binding Name}" TextTrimming="CharacterEllipsis" VerticalAlignment="Center" ToolTip="{Binding Name}"/>
            <TextBlock Grid.Column="2" Text="{Binding Note}" FontSize="11" Margin="10,0,2,0" VerticalAlignment="Center" MaxWidth="200" TextTrimming="CharacterEllipsis">
              <TextBlock.Style>
                <Style TargetType="TextBlock">
                  <Setter Property="Foreground" Value="{StaticResource Muted}"/>
                  <Style.Triggers>
                    <DataTrigger Binding="{Binding NoteKind}" Value="Warn"><Setter Property="Foreground" Value="{StaticResource Warn}"/></DataTrigger>
                  </Style.Triggers>
                </Style>
              </TextBlock.Style>
            </TextBlock>
          </Grid>
        </DataTemplate>
      </ListBox.ItemTemplate>
    </ListBox>

    <DockPanel Grid.Row="2" Margin="0,12,0,0" LastChildFill="False">
      <Button x:Name="TickAllButton" DockPanel.Dock="Left" Content="Tick all" Padding="10,4"/>
      <Button x:Name="TickNoneButton" DockPanel.Dock="Left" Content="Tick none" Padding="10,4"/>
      <Button x:Name="CancelButton" DockPanel.Dock="Right" Content="Cancel" Margin="0" IsCancel="True"/>
      <Button x:Name="AddButton" DockPanel.Dock="Right" Content="Add servers" Style="{StaticResource Primary}" IsDefault="True" IsEnabled="False"/>
      <TextBlock x:Name="TickedText" DockPanel.Dock="Right" Foreground="{StaticResource Muted}" FontSize="12" VerticalAlignment="Center" Margin="0,0,10,0"/>
    </DockPanel>
  </Grid>
</Window>
'@
}

function Show-AddServersDialog {
    <#
        Shows the dialog over -Owner and returns the ticked server names (@() on Cancel).
        -Directory is what the main window loaded from AD; -DirectoryState says whether that
        load finished ('Loaded'), and -DomainText is the main window's "Suggestions from" line.
    #>
    param($Owner, [object[]]$Directory, [string]$DirectoryState, [string]$DomainText, [scriptblock]$Lookup)

    Add-Type -AssemblyName PresentationFramework
    $dlg = [System.Windows.Markup.XamlReader]::Parse((New-AddServersDialogXaml))
    if ($Owner) { $dlg.Owner = $Owner }
    $c = @{}
    foreach ($n in 'Tabs', 'PasteTab', 'FindTab', 'FileTab', 'PasteBox', 'CheckNamesButton', 'FindBox', 'ScopeAll', 'ScopeDcs', 'ScopeOu', 'OuCombo', 'FindNote',
        'FileButton', 'FilePathText', 'ColumnPanel', 'ColumnCombo', 'ResultList', 'TickAllButton', 'TickNoneButton', 'TickedText', 'AddButton', 'CancelButton') {
        $c[$n] = $dlg.FindName($n)
    }
    $d = @{
        Rows = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
        Lookups = @{}; Job = $null; Queue = New-Object System.Collections.Generic.List[string]
        ShowOS = $false; PasteDirty = $false; LastKey = [Diagnostics.Stopwatch]::StartNew()
        FilePath = ''; Result = @()
        Loaded = $DirectoryState -eq 'Loaded'
    }
    $c.ResultList.ItemsSource = $d.Rows

    $refresh = {
        $ticked = @($d.Rows | Where-Object { $_.Ticked }).Count
        $c.TickedText.Text = if ($d.Rows.Count) { "$ticked of $($d.Rows.Count) ticked" } else { '' }
        $c.AddButton.Content = Get-AddButtonText -Count $ticked
        $c.AddButton.IsEnabled = $ticked -gt 0
        $c.ResultList.Items.Refresh()
    }
    $startLookups = {
        if ($d.Job -or $d.Queue.Count -eq 0) { return }
        $d.Job = if ($Lookup) { Start-NameLookups -Names $d.Queue.ToArray() -Lookup $Lookup } else { Start-NameLookups -Names $d.Queue.ToArray() }
        $d.Queue.Clear()
    }
    # Rebuilds the results for these names, keeping the tick a person changed by hand.
    $setResults = {
        param([string[]]$Names, [bool]$ShowOS)
        $d.ShowOS = $ShowOS
        $manual = @{}
        foreach ($r in $d.Rows) { if ($r.PSObject.Properties['Manual']) { $manual[$r.Name] = $r.Ticked } }
        $d.Rows.Clear()
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($n in @($Names | Where-Object { $_ })) {
            if (-not $seen.Add($n)) { continue }
            $row = New-AddCandidate -Name $n -Directory $Directory -Lookup $d.Lookups[$n] -ShowOS:$ShowOS
            if ($manual.ContainsKey($n)) { $row.Ticked = $manual[$n]; $row | Add-Member -NotePropertyName Manual -NotePropertyValue $true }
            [void]$d.Rows.Add($row)
            $needsDns = (Test-IpAddress -Text $n) -or -not (Find-DirectoryEntry -Directory $Directory -Name $n)
            if ($needsDns -and -not $d.Lookups.ContainsKey($n) -and -not $d.Queue.Contains($n)) { $d.Queue.Add($n) }
        }
        & $startLookups
        & $refresh
    }
    $pasteNames = {
        @(foreach ($line in @(ConvertTo-ServerList -Text $c.PasteBox.Text)) {
                $t = $line.Trim(); $slash = $t.LastIndexOf('\')
                if ($slash -ge 0) { $t = $t.Substring($slash + 1) }
                if ($t) { $t }
            })
    }
    $runFind = {
        if (-not $d.Loaded) { $d.Rows.Clear(); & $refresh; return }
        $scope = if ($c.ScopeDcs.IsChecked) { 'DomainControllers' } elseif ($c.ScopeOu.IsChecked) { 'OU' } else { 'All' }
        $ou = if ($c.OuCombo.SelectedItem) { [string]$c.OuCombo.SelectedItem } else { '' }
        if ($scope -eq 'OU' -and -not $ou) { $d.Rows.Clear(); & $refresh; return }
        $names = @(Find-DirectoryServers -Directory $Directory -Text $c.FindBox.Text -Scope $scope -OU $ou | ForEach-Object DnsName)
        & $setResults $names $true
    }
    $readFile = {
        param([string]$Column)
        if (-not $d.FilePath) { return }
        try {
            $r = if ($Column) { Read-ServerListFile -Path $d.FilePath -Column $Column } else { Read-ServerListFile -Path $d.FilePath }
            $c.FilePathText.Text = $d.FilePath
            if ($r.NeedsColumn) {
                $c.ColumnCombo.ItemsSource = @($r.Headers)
                $c.ColumnPanel.Visibility = 'Visible'
                $c.FilePathText.Text = "$($d.FilePath)`nChoose the column that holds the server names."
                & $setResults @() $false
                return
            }
            if (-not $Column) { $c.ColumnPanel.Visibility = 'Collapsed' }
            & $setResults @($r.Names) $false
            if (@($r.Names).Count -eq 0) { $c.FilePathText.Text = "$($d.FilePath)`nNo server names found in this file." }
        }
        catch {
            $c.FilePathText.Text = "Couldn't read $($d.FilePath): $($_.Exception.Message)"
            & $setResults @() $false
        }
    }

    # Paste: check the names once typing pauses (or straight away with "Check names").
    $c.PasteBox.add_TextChanged({ $d.PasteDirty = $true; $d.LastKey.Restart() })
    $c.CheckNamesButton.add_Click({ $d.PasteDirty = $false; & $setResults (& $pasteNames) $false })

    # Find in AD: only from what the main window already loaded; no new AD query.
    if (-not $d.Loaded) {
        $c.FindNote.Text = "Active Directory isn't loaded ($DomainText). Use Paste or From a file."
        $c.FindNote.Visibility = 'Visible'
        foreach ($x in 'FindBox', 'ScopeAll', 'ScopeDcs', 'ScopeOu') { $c[$x].IsEnabled = $false }
    }
    else { $c.OuCombo.ItemsSource = @(Get-DirectoryOUs -Directory $Directory) }
    $c.FindBox.add_TextChanged({ & $runFind })
    foreach ($rb in @($c.ScopeAll, $c.ScopeDcs, $c.ScopeOu)) { $rb.add_Checked({ $c.OuCombo.IsEnabled = [bool]$c.ScopeOu.IsChecked; & $runFind }) }
    $c.OuCombo.add_SelectionChanged({ & $runFind })

    # From a file.
    $c.FileButton.add_Click({
            $open = New-Object Microsoft.Win32.OpenFileDialog
            $open.Filter = 'Server lists (*.txt;*.csv)|*.txt;*.csv'
            $open.Title = 'Choose a server list'
            if ($open.ShowDialog($dlg)) { $d.FilePath = $open.FileName; & $readFile '' }
        })
    $c.ColumnCombo.add_SelectionChanged({ if ($c.ColumnCombo.SelectedItem) { & $readFile ([string]$c.ColumnCombo.SelectedItem) } })

    # Switching tabs shows that tab's results; "Add" adds only what the current tab shows.
    $c.Tabs.add_SelectionChanged({
            param($s, $e)
            if ($e.OriginalSource -ne $c.Tabs) { return }
            if ($c.Tabs.SelectedItem -eq $c.PasteTab) { & $setResults (& $pasteNames) $false }
            elseif ($c.Tabs.SelectedItem -eq $c.FindTab) { & $runFind }
            else { $d.Rows.Clear(); & $readFile $(if ($c.ColumnCombo.SelectedItem) { [string]$c.ColumnCombo.SelectedItem } else { '' }) }
            & $refresh
        })

    # Ticks: the box only shows the row's state; a click changes it and is remembered.
    $c.ResultList.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler] {
            param($s, $e)
            $box = $e.OriginalSource
            if ($box -isnot [System.Windows.Controls.CheckBox] -or $null -eq $box.Tag) { return }
            $box.Tag.Ticked = [bool]$box.IsChecked
            if (-not $box.Tag.PSObject.Properties['Manual']) { $box.Tag | Add-Member -NotePropertyName Manual -NotePropertyValue $true }
            & $refresh
        })
    $c.TickAllButton.add_Click({ foreach ($r in $d.Rows) { $r.Ticked = $true }; & $refresh })
    $c.TickNoneButton.add_Click({ foreach ($r in $d.Rows) { $r.Ticked = $false }; & $refresh })
    $c.AddButton.add_Click({ $d.Result = @($d.Rows | Where-Object { $_.Ticked } | ForEach-Object Name); $dlg.DialogResult = $true })

    # The dialog's heartbeat: DNS results and the paste pause.
    $tick = New-Object System.Windows.Threading.DispatcherTimer
    $tick.Interval = [TimeSpan]::FromMilliseconds(250)
    $tick.add_Tick({
            if ($d.PasteDirty -and $d.LastKey.ElapsedMilliseconds -ge 400 -and $c.Tabs.SelectedItem -eq $c.PasteTab) {
                $d.PasteDirty = $false
                & $setResults (& $pasteNames) $false
            }
            if ($d.Job) {
                $r = Receive-NameLookups -Job $d.Job
                if ($null -ne $r) {
                    $d.Job = $null
                    foreach ($k in $r.Keys) { $d.Lookups[$k] = $r[$k] }
                    & $setResults @($d.Rows | ForEach-Object Name) $d.ShowOS
                }
            }
        })
    $tick.Start()
    $dlg.add_Closing({
            $tick.Stop()
            if ($d.Job) { try { [void]$d.Job.PowerShell.BeginStop($null, $null) } catch { } }
        })
    $dlg.add_ContentRendered({ $c.PasteBox.Focus() })

    [void]$dlg.ShowDialog()
    return @($d.Result)
}
