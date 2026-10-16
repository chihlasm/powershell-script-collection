# 3.0 so it opens on Server 2012 (PS 3.0) / 2012 R2 (PS 4.0) domain controllers as shipped. WPF is
# available from PowerShell 3.0. Tests\PSVersionFloor.Tests.ps1 guards it.
#Requires -Version 3.0

<#
.SYNOPSIS
    Microsoft 365 fixes for people whose accounts are synced from Active Directory: block
    Microsoft 365 sign-in, hide from the address book, and set up the Entra Connect sync
    rules that make both work.
.DESCRIPTION
    When an account comes from Active Directory, the Microsoft 365 admin center will not let
    you block its sign-in or hide it from the address book ("this user is synchronized with
    your on-premises directory"). This window does both from AD, using a marker attribute
    that a custom Entra Connect sync rule acts on:

      Block Microsoft 365 sign-in   They keep their PC login and file shares.
      Hide from address book        They disappear from the Outlook address book.
      Set up sync rules             Checks the two Entra Connect rules and builds any that
                                    are missing (for sysadmins).

    Before writing anything, the window checks the sync rule on the Entra Connect server and
    says plainly whether it is in place, missing, or could not be checked. When the rule is
    confirmed missing, blocking/hiding is switched off, because it would look like it worked
    while changing nothing. Restoring sign-in and showing someone again always work.

    Every change is written to Logs\Changes_<date>.csv (who, when, which person, old and new
    value).
.PARAMETER Tab
    Section to open first: BlockSignIn (default), HideFromGAL or SyncRules.
.PARAMETER EntraConnectServer
    Entra Connect server to check against. Omit to find it automatically (this computer,
    then the last server found, then Active Directory).
.PARAMETER Credential
    Optional credential for connecting to the Entra Connect server.
.PARAMETER SearchBase
    Optional OU distinguished name to limit which people are listed.
.PARAMETER SkipRuleCheck
    Break-glass: allow blocking/hiding even when the rule is confirmed missing. The status
    card still shows what was found.
.PARAMETER LogFolder
    Folder for the change log. Defaults to the Logs folder next to this script (not the
    current directory, which is C:\Windows\System32 when started "as administrator").
.PARAMETER LoadFunctionsOnly
    Define the functions and return without opening the window (used by the tests).
.EXAMPLE
    .\Start-M365SyncedUserFixes.ps1
    Open the window on "Block Microsoft 365 sign-in".
.EXAMPLE
    .\Start-M365SyncedUserFixes.ps1 -Tab SyncRules -EntraConnectServer AADC01
    Open "Set up sync rules" against a named Entra Connect server.
.NOTES
    Start it with "Start M365 Synced User Fixes.cmd" to avoid a PowerShell console window.

    Needs the ActiveDirectory module (RSAT) and rights to change the two attributes on user
    objects. Checking and creating sync rules additionally needs local administrator rights
    on the Entra Connect server; it works best when the tool runs ON that server, because
    Entra Connect refuses rule queries over a remote connection.

    Replaces the "Block 365 Sign-in" (CloudSignInMgr.ps1) and "HideFromGal" (HideFromGAL.ps1)
    tools. Same attributes, same marker values, so people already blocked or hidden stay so.

    REFERENCES
    - See SyncedUserFixes.Core.ps1 for the Entra Connect and AD references.
    - WPF needs a single-threaded apartment; powershell.exe 3.0+ starts in STA:
      https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe
#>
[CmdletBinding()]
param(
    [ValidateSet('BlockSignIn', 'HideFromGAL', 'SyncRules')]
    [string]$Tab = 'BlockSignIn',

    [string]$EntraConnectServer,

    [System.Management.Automation.PSCredential]$Credential,

    [string]$SearchBase,

    [switch]$SkipRuleCheck,

    [string]$LogFolder,

    [switch]$LoadFunctionsOnly
)

$script:CorePath = Join-Path $PSScriptRoot 'SyncedUserFixes.Core.ps1'
if (-not $LogFolder) { $LogFolder = Join-Path $PSScriptRoot 'Logs' }

#region Window markup

function Get-ActionViewXaml {
    <#
    .SYNOPSIS
        XAML for one of the two people-list sections. P is the name prefix (Block / Hide).
    #>
    param(
        [string]$P,
        [string]$Title,
        [string]$Intro,
        [string]$OnlyMarkedText,
        [string]$ApplyText,
        [string]$RemoveText,
        [string]$StatusHeader,
        [string]$ApplyStyle = 'DangerButton'
    )

@"
<Grid x:Name="${P}View" Margin="28,22,28,18">
  <Grid.RowDefinitions>
    <RowDefinition Height="Auto"/>
    <RowDefinition Height="Auto"/>
    <RowDefinition Height="Auto"/>
    <RowDefinition Height="*"/>
    <RowDefinition Height="Auto"/>
  </Grid.RowDefinitions>

  <StackPanel Grid.Row="0">
    <TextBlock Text="$Title" FontSize="22" FontWeight="SemiBold" Foreground="{DynamicResource Text}"/>
    <TextBlock Text="$Intro" Margin="0,4,0,0" FontSize="13" TextWrapping="Wrap" Foreground="{DynamicResource Muted}"/>
  </StackPanel>

  <Border Grid.Row="1" x:Name="${P}RuleCard" Margin="0,16,0,0" Style="{StaticResource Card}" BorderThickness="4,1,1,1" BorderBrush="{DynamicResource Info}">
    <Grid>
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <StackPanel Grid.Column="0" Margin="14,10,14,10">
        <TextBlock x:Name="${P}RuleHeadline" Text="Checking the sync rule..." FontSize="14" FontWeight="SemiBold" Foreground="{DynamicResource Text}"/>
        <TextBlock x:Name="${P}RuleDetail" Margin="0,3,0,0" TextWrapping="Wrap" Foreground="{DynamicResource Muted}" Text="Looking for the Entra Connect server. This can take a minute the first time."/>
        <TextBlock x:Name="${P}RuleWarning" Margin="0,6,0,0" TextWrapping="Wrap" Foreground="{DynamicResource Danger}" FontWeight="SemiBold" Visibility="Collapsed"/>
      </StackPanel>
      <Button Grid.Column="1" x:Name="${P}RuleFix" Content="Open sync rules" Margin="0,0,14,0" VerticalAlignment="Center" Style="{StaticResource GhostButton}" Visibility="Collapsed"/>
    </Grid>
  </Border>

  <Grid Grid.Row="2" Margin="0,16,0,10">
    <Grid.ColumnDefinitions>
      <ColumnDefinition Width="360"/>
      <ColumnDefinition Width="Auto"/>
      <ColumnDefinition Width="Auto"/>
      <ColumnDefinition Width="*"/>
      <ColumnDefinition Width="Auto"/>
    </Grid.ColumnDefinitions>
    <TextBox Grid.Column="0" x:Name="${P}Search" Tag="Find a person: name, username or email" Style="{StaticResource SearchBox}"/>
    <CheckBox Grid.Column="1" x:Name="${P}IncludeDisabled" Content="Include disabled accounts" Margin="18,0,0,0" VerticalAlignment="Center" Style="{StaticResource ToggleCheck}"/>
    <CheckBox Grid.Column="2" x:Name="${P}OnlyMarked" Content="$OnlyMarkedText" Margin="18,0,0,0" VerticalAlignment="Center" Style="{StaticResource ToggleCheck}"/>
    <TextBlock Grid.Column="4" x:Name="${P}Count" VerticalAlignment="Center" Foreground="{DynamicResource Muted}" Text=""/>
  </Grid>

  <Border Grid.Row="3" Style="{StaticResource Card}" Padding="0">
    <Grid>
      <DataGrid x:Name="${P}Grid" Style="{StaticResource PeopleGrid}">
        <DataGrid.Columns>
          <DataGridTemplateColumn Width="44" CanUserResize="False">
            <DataGridTemplateColumn.CellTemplate>
              <DataTemplate>
                <CheckBox IsChecked="{Binding IsSelected, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}" HorizontalAlignment="Center" Style="{StaticResource RowCheck}"/>
              </DataTemplate>
            </DataGridTemplateColumn.CellTemplate>
          </DataGridTemplateColumn>
          <DataGridTextColumn IsReadOnly="True" Header="Name" Binding="{Binding Name}" Width="2*"/>
          <DataGridTextColumn IsReadOnly="True" Header="Username" Binding="{Binding SamAccountName}" Width="1.2*"/>
          <DataGridTextColumn IsReadOnly="True" Header="Account in AD" Binding="{Binding AccountText}" Width="1*"/>
          <DataGridTextColumn IsReadOnly="True" Header="Where in AD" Binding="{Binding OU}" Width="1.6*"/>
          <DataGridTemplateColumn Header="$StatusHeader" Width="1.8*" SortMemberPath="StatusText">
            <DataGridTemplateColumn.CellTemplate>
              <DataTemplate>
                <Border x:Name="Badge" CornerRadius="2" Padding="8,2" HorizontalAlignment="Left" Background="Transparent">
                  <TextBlock x:Name="BadgeText" Text="{Binding StatusText}" Foreground="{DynamicResource Muted}"/>
                </Border>
                <DataTemplate.Triggers>
                  <DataTrigger Binding="{Binding StatusKind}" Value="On">
                    <Setter TargetName="Badge" Property="Background" Value="{DynamicResource AccentSoft}"/>
                    <Setter TargetName="BadgeText" Property="Foreground" Value="{DynamicResource Accent}"/>
                    <Setter TargetName="BadgeText" Property="FontWeight" Value="SemiBold"/>
                  </DataTrigger>
                  <DataTrigger Binding="{Binding StatusKind}" Value="Warn">
                    <Setter TargetName="Badge" Property="Background" Value="{DynamicResource DangerSoft}"/>
                    <Setter TargetName="BadgeText" Property="Foreground" Value="{DynamicResource Danger}"/>
                    <Setter TargetName="BadgeText" Property="FontWeight" Value="SemiBold"/>
                  </DataTrigger>
                  <DataTrigger Binding="{Binding StatusKind}" Value="Unverified">
                    <Setter TargetName="Badge" Property="Background" Value="{DynamicResource WarnSoft}"/>
                    <Setter TargetName="BadgeText" Property="Foreground" Value="{DynamicResource Warn}"/>
                  </DataTrigger>
                </DataTemplate.Triggers>
              </DataTemplate>
            </DataGridTemplateColumn.CellTemplate>
          </DataGridTemplateColumn>
        </DataGrid.Columns>
      </DataGrid>
      <TextBlock x:Name="${P}Empty" Text="Loading people from Active Directory..." HorizontalAlignment="Center" VerticalAlignment="Center" Foreground="{DynamicResource Muted}" FontSize="13"/>
    </Grid>
  </Border>

  <Grid Grid.Row="4" Margin="0,14,0,0">
    <Grid.ColumnDefinitions>
      <ColumnDefinition Width="Auto"/>
      <ColumnDefinition Width="Auto"/>
      <ColumnDefinition Width="*"/>
      <ColumnDefinition Width="Auto"/>
      <ColumnDefinition Width="Auto"/>
    </Grid.ColumnDefinitions>
    <Button Grid.Column="0" x:Name="${P}SelectAll" Content="Tick everyone shown" Style="{StaticResource GhostButton}"/>
    <Button Grid.Column="1" x:Name="${P}Clear" Content="Untick all" Margin="8,0,0,0" Style="{StaticResource GhostButton}"/>
    <TextBlock Grid.Column="2" x:Name="${P}Selected" Margin="16,0,0,0" VerticalAlignment="Center" Foreground="{DynamicResource Muted}" Text="Nobody ticked"/>
    <Button Grid.Column="3" x:Name="${P}Remove" Content="$RemoveText" Margin="0,0,10,0" Style="{StaticResource SecondaryButton}" IsEnabled="False"/>
    <Button Grid.Column="4" x:Name="${P}Apply" Content="$ApplyText" Style="{StaticResource $ApplyStyle}" IsEnabled="False"/>
  </Grid>
</Grid>
"@
}

function Get-MainWindowXaml {
    $block = Get-ActionViewXaml -P 'Block' -Title 'Block Microsoft 365 sign-in' `
        -Intro 'Stops someone signing in to Outlook, Teams and the rest of Microsoft 365. They can still sign in to their PC and reach file shares. Use it for leavers on their last day or a compromised cloud account.' `
        -OnlyMarkedText 'Only show people who are blocked' -ApplyText 'Block sign-in' -RemoveText 'Restore sign-in' -StatusHeader 'Microsoft 365 sign-in'
    $hide = Get-ActionViewXaml -P 'Hide' -Title 'Hide from address book' `
        -Intro 'Removes someone from the Outlook address book (GAL) so colleagues stop finding them. Mail to them still works. Common for leavers, shared mailboxes and service accounts.' `
        -OnlyMarkedText 'Only show people who are hidden' -ApplyText 'Hide' -RemoveText 'Show again' -StatusHeader 'Address book' -ApplyStyle 'PrimaryButton'

@"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Microsoft 365 - Synced User Fixes" Width="1220" Height="780" MinWidth="1000" MinHeight="640"
        WindowStartupLocation="CenterScreen" Background="{DynamicResource Bg}" FontFamily="Segoe UI" FontSize="13"
        TextOptions.TextFormattingMode="Display" UseLayoutRounding="True" SnapsToDevicePixels="True">
  <Window.Resources>
    <SolidColorBrush x:Key="Bg" Color="#14161B"/>
    <SolidColorBrush x:Key="Surface" Color="#1B1E25"/>
    <SolidColorBrush x:Key="Surface2" Color="#232731"/>
    <SolidColorBrush x:Key="Hover" Color="#2B303B"/>
    <SolidColorBrush x:Key="Border" Color="#333946"/>
    <SolidColorBrush x:Key="Text" Color="#E6EAF0"/>
    <SolidColorBrush x:Key="Muted" Color="#97A1AF"/>
    <SolidColorBrush x:Key="Accent" Color="#4FA8E8"/>
    <SolidColorBrush x:Key="AccentSoft" Color="#1A3347"/>
    <SolidColorBrush x:Key="OnAccent" Color="#0B1520"/>
    <SolidColorBrush x:Key="Danger" Color="#F06A60"/>
    <SolidColorBrush x:Key="DangerFill" Color="#C93A31"/>
    <SolidColorBrush x:Key="DangerSoft" Color="#3A1F1F"/>
    <SolidColorBrush x:Key="Success" Color="#46C267"/>
    <SolidColorBrush x:Key="Warn" Color="#E0A93B"/>
    <SolidColorBrush x:Key="WarnSoft" Color="#3A3020"/>
    <SolidColorBrush x:Key="Info" Color="#58A6FF"/>

    <Style x:Key="Card" TargetType="Border">
      <Setter Property="Background" Value="{DynamicResource Surface}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Border}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="CornerRadius" Value="3"/>
    </Style>

    <Style x:Key="BaseButton" TargetType="Button">
      <Setter Property="Foreground" Value="{DynamicResource Text}"/>
      <Setter Property="Background" Value="{DynamicResource Surface2}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Border}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="16,7"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="3" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Opacity" Value="0.88"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter TargetName="Bd" Property="Opacity" Value="0.72"/>
              </Trigger>
              <Trigger Property="IsKeyboardFocused" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource Accent}"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="Bd" Property="Opacity" Value="0.4"/>
                <Setter Property="Cursor" Value="Arrow"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="SecondaryButton" TargetType="Button" BasedOn="{StaticResource BaseButton}"/>
    <Style x:Key="GhostButton" TargetType="Button" BasedOn="{StaticResource BaseButton}">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="FontWeight" Value="Normal"/>
      <Setter Property="Padding" Value="12,6"/>
    </Style>
    <Style x:Key="PrimaryButton" TargetType="Button" BasedOn="{StaticResource BaseButton}">
      <Setter Property="Background" Value="{DynamicResource Accent}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Accent}"/>
      <Setter Property="Foreground" Value="{DynamicResource OnAccent}"/>
    </Style>
    <Style x:Key="DangerButton" TargetType="Button" BasedOn="{StaticResource BaseButton}">
      <Setter Property="Background" Value="{DynamicResource DangerFill}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource DangerFill}"/>
      <Setter Property="Foreground" Value="White"/>
    </Style>

    <Style x:Key="SearchBox" TargetType="TextBox">
      <Setter Property="Foreground" Value="{DynamicResource Text}"/>
      <Setter Property="Background" Value="{DynamicResource Surface}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Border}"/>
      <Setter Property="CaretBrush" Value="{DynamicResource Text}"/>
      <Setter Property="Padding" Value="10,7"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="3">
              <Grid>
                <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}" VerticalAlignment="Center"/>
                <TextBlock x:Name="Hint" Text="{TemplateBinding Tag}" Margin="13,0,0,0" VerticalAlignment="Center" Foreground="{DynamicResource Muted}" IsHitTestVisible="False" Visibility="Collapsed"/>
              </Grid>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="Text" Value="">
                <Setter TargetName="Hint" Property="Visibility" Value="Visible"/>
              </Trigger>
              <Trigger Property="IsKeyboardFocused" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource Accent}"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource Muted}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="MonoBox" TargetType="TextBox">
      <Setter Property="Foreground" Value="{DynamicResource Text}"/>
      <Setter Property="Background" Value="{DynamicResource Bg}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Border}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="10,8"/>
      <Setter Property="FontFamily" Value="Consolas"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="IsReadOnly" Value="True"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
      <Setter Property="VerticalScrollBarVisibility" Value="Auto"/>
    </Style>

    <Style x:Key="ToggleCheck" TargetType="CheckBox">
      <Setter Property="Foreground" Value="{DynamicResource Text}"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="CheckBox">
            <StackPanel Orientation="Horizontal" Background="Transparent">
              <Border x:Name="Box" Width="16" Height="16" CornerRadius="2" BorderThickness="1.5" BorderBrush="{DynamicResource Muted}" Background="Transparent" VerticalAlignment="Center">
                <Path x:Name="Tick" Data="M3,8 L6.5,11.5 L13,4.5" Stroke="{DynamicResource OnAccent}" StrokeThickness="2" Visibility="Collapsed"/>
              </Border>
              <ContentPresenter Margin="8,0,0,0" VerticalAlignment="Center"/>
            </StackPanel>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Box" Property="Background" Value="{DynamicResource Accent}"/>
                <Setter TargetName="Box" Property="BorderBrush" Value="{DynamicResource Accent}"/>
                <Setter TargetName="Tick" Property="Visibility" Value="Visible"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Box" Property="BorderBrush" Value="{DynamicResource Accent}"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Opacity" Value="0.4"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="RowCheck" TargetType="CheckBox" BasedOn="{StaticResource ToggleCheck}"/>

    <Style x:Key="OptionRadio" TargetType="RadioButton">
      <Setter Property="Foreground" Value="{DynamicResource Text}"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Margin" Value="0,0,0,8"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Border x:Name="Bd" Background="{DynamicResource Surface2}" BorderBrush="{DynamicResource Border}" BorderThickness="1" CornerRadius="3" Padding="12,9">
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="Auto"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Grid Width="16" Height="16" VerticalAlignment="Top" Margin="0,2,0,0">
                  <Ellipse x:Name="Ring" Stroke="{DynamicResource Muted}" StrokeThickness="1.5"/>
                  <Ellipse x:Name="Dot" Width="8" Height="8" Fill="{DynamicResource Accent}" Visibility="Collapsed"/>
                </Grid>
                <ContentPresenter Grid.Column="1" Margin="10,0,0,0"/>
              </Grid>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource Accent}"/>
                <Setter TargetName="Ring" Property="Stroke" Value="{DynamicResource Accent}"/>
                <Setter TargetName="Dot" Property="Visibility" Value="Visible"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="{DynamicResource Hover}"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Opacity" Value="0.4"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="NavItem" TargetType="RadioButton">
      <Setter Property="Foreground" Value="{DynamicResource Muted}"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="GroupName" Value="Nav"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Border x:Name="Bd" Background="Transparent" Padding="0,10,12,10" Margin="0,0,0,2" CornerRadius="0,3,3,0">
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="3"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Border x:Name="Bar" Grid.Column="0" Background="Transparent"/>
                <ContentPresenter Grid.Column="1" Margin="17,0,0,0"/>
              </Grid>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="{DynamicResource Hover}"/>
                <Setter Property="Foreground" Value="{DynamicResource Text}"/>
              </Trigger>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="{DynamicResource Surface2}"/>
                <Setter TargetName="Bar" Property="Background" Value="{DynamicResource Accent}"/>
                <Setter Property="Foreground" Value="{DynamicResource Text}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- Thin themed scrollbars; the default light Windows ones glare in the dark theme. -->
    <Style x:Key="ScrollThumb" TargetType="Thumb">
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Thumb">
            <Border x:Name="T" Background="{DynamicResource Border}" CornerRadius="4"/>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="T" Property="Background" Value="{DynamicResource Muted}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="ScrollBar">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Width" Value="10"/>
      <Setter Property="MinWidth" Value="10"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ScrollBar">
            <Grid Background="{TemplateBinding Background}">
              <Track x:Name="PART_Track" IsDirectionReversed="True" Margin="2">
                <Track.Thumb>
                  <Thumb Style="{StaticResource ScrollThumb}"/>
                </Track.Thumb>
              </Track>
            </Grid>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="Orientation" Value="Horizontal">
          <Setter Property="Width" Value="Auto"/>
          <Setter Property="MinWidth" Value="0"/>
          <Setter Property="Height" Value="10"/>
          <Setter Property="Template">
            <Setter.Value>
              <ControlTemplate TargetType="ScrollBar">
                <Grid Background="{TemplateBinding Background}">
                  <Track x:Name="PART_Track" IsDirectionReversed="False" Margin="2">
                    <Track.Thumb>
                      <Thumb Style="{StaticResource ScrollThumb}"/>
                    </Track.Thumb>
                  </Track>
                </Grid>
              </ControlTemplate>
            </Setter.Value>
          </Setter>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style x:Key="PeopleGrid" TargetType="DataGrid">
      <Setter Property="AutoGenerateColumns" Value="False"/>
      <Setter Property="CanUserAddRows" Value="False"/>
      <Setter Property="CanUserDeleteRows" Value="False"/>
      <Setter Property="CanUserResizeRows" Value="False"/>
      <Setter Property="SelectionMode" Value="Extended"/>
      <Setter Property="SelectionUnit" Value="FullRow"/>
      <Setter Property="HeadersVisibility" Value="Column"/>
      <Setter Property="GridLinesVisibility" Value="Horizontal"/>
      <Setter Property="HorizontalGridLinesBrush" Value="{DynamicResource Border}"/>
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="RowBackground" Value="Transparent"/>
      <Setter Property="AlternatingRowBackground" Value="Transparent"/>
      <Setter Property="Foreground" Value="{DynamicResource Text}"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="RowHeight" Value="34"/>
      <Setter Property="IsReadOnly" Value="False"/>
      <Setter Property="EnableRowVirtualization" Value="True"/>
      <Setter Property="ColumnHeaderStyle">
        <Setter.Value>
          <Style TargetType="DataGridColumnHeader">
            <Setter Property="Background" Value="{DynamicResource Surface2}"/>
            <Setter Property="Foreground" Value="{DynamicResource Muted}"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding" Value="10,8"/>
            <Setter Property="BorderBrush" Value="{DynamicResource Border}"/>
            <Setter Property="BorderThickness" Value="0,0,0,1"/>
          </Style>
        </Setter.Value>
      </Setter>
      <Setter Property="CellStyle">
        <Setter.Value>
          <Style TargetType="DataGridCell">
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Foreground" Value="{DynamicResource Text}"/>
            <Setter Property="Template">
              <Setter.Value>
                <ControlTemplate TargetType="DataGridCell">
                  <Border Background="Transparent" Padding="10,0">
                    <ContentPresenter VerticalAlignment="Center"/>
                  </Border>
                </ControlTemplate>
              </Setter.Value>
            </Setter>
          </Style>
        </Setter.Value>
      </Setter>
      <Setter Property="RowStyle">
        <Setter.Value>
          <Style TargetType="DataGridRow">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Style.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter Property="Background" Value="{DynamicResource Hover}"/>
              </Trigger>
              <DataTrigger Binding="{Binding IsSelected}" Value="True">
                <Setter Property="Background" Value="{DynamicResource AccentSoft}"/>
              </DataTrigger>
            </Style.Triggers>
          </Style>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>

  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Header: what this is, and where it is pointed -->
    <Border Grid.Row="0" Background="{DynamicResource Surface}" BorderBrush="{DynamicResource Border}" BorderThickness="0,0,0,1" Padding="24,14">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel Grid.Column="0" Orientation="Horizontal">
          <Border Width="34" Height="34" CornerRadius="3" Background="{DynamicResource Accent}" VerticalAlignment="Center">
            <Path Data="M7,17 C4,17 3,15 3,13 C3,10.5 5,9 7,9.3 C7.8,6.5 10,5 12.5,5 C15.5,5 17.5,7.2 17.7,9.8 C19.8,10 21,11.6 21,13.4 C21,15.5 19.5,17 17.3,17 Z" Stroke="{DynamicResource OnAccent}" StrokeThickness="1.8" Width="20" Height="20" Stretch="Uniform"/>
          </Border>
          <StackPanel Margin="12,0,0,0" VerticalAlignment="Center">
            <TextBlock Text="Microsoft 365 - Synced User Fixes" FontSize="17" FontWeight="SemiBold" Foreground="{DynamicResource Text}"/>
            <TextBlock Text="For accounts that come from Active Directory, where the Microsoft 365 admin center says &quot;this user is synchronized&quot;" Foreground="{DynamicResource Muted}" FontSize="12"/>
          </StackPanel>
        </StackPanel>
        <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
          <Border Background="{DynamicResource Surface2}" BorderBrush="{DynamicResource Border}" BorderThickness="1" CornerRadius="3" Padding="10,5" Margin="0,0,8,0">
            <StackPanel Orientation="Horizontal">
              <TextBlock Text="Domain  " Foreground="{DynamicResource Muted}" FontSize="12"/>
              <TextBlock x:Name="DomainChip" Text="..." Foreground="{DynamicResource Text}" FontSize="12" FontWeight="SemiBold"/>
            </StackPanel>
          </Border>
          <Border Background="{DynamicResource Surface2}" BorderBrush="{DynamicResource Border}" BorderThickness="1" CornerRadius="3" Padding="10,5" Margin="0,0,8,0">
            <StackPanel Orientation="Horizontal">
              <TextBlock Text="Entra Connect  " Foreground="{DynamicResource Muted}" FontSize="12"/>
              <TextBlock x:Name="ServerChip" Text="finding..." Foreground="{DynamicResource Text}" FontSize="12" FontWeight="SemiBold"/>
            </StackPanel>
          </Border>
          <Button x:Name="ThemeToggle" Content="Light mode" Style="{StaticResource GhostButton}"/>
        </StackPanel>
      </Grid>
    </Border>

    <Grid Grid.Row="1">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="250"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>

      <!-- Navigation -->
      <Border Grid.Column="0" Background="{DynamicResource Surface}" BorderBrush="{DynamicResource Border}" BorderThickness="0,0,1,0">
        <DockPanel Margin="0,18,0,14">
          <TextBlock DockPanel.Dock="Bottom" Margin="20,0,16,0" TextWrapping="Wrap" FontSize="11.5" Foreground="{DynamicResource Muted}"
                     Text="Changes are made in Active Directory and reach Microsoft 365 at the next Entra Connect sync (about 30 minutes, or straight away if you run a sync)."/>
          <StackPanel>
            <TextBlock Text="FIXES" Margin="20,0,0,8" FontSize="11" FontWeight="SemiBold" Foreground="{DynamicResource Muted}"/>
            <RadioButton x:Name="NavBlock" Style="{StaticResource NavItem}">
              <StackPanel Orientation="Horizontal">
                <Path Data="M7,11 V8 A5,5 0 0 1 17,8 V11 M5,11 H19 V21 H5 Z M12,15 V17" Stroke="{Binding Foreground, RelativeSource={RelativeSource AncestorType=RadioButton}}" StrokeThickness="1.8" Width="18" Height="18" Stretch="Uniform" VerticalAlignment="Top" Margin="0,1,0,0"/>
                <StackPanel Margin="12,0,0,0">
                  <TextBlock Text="Block Microsoft 365 sign-in" FontWeight="SemiBold" Foreground="{Binding Foreground, RelativeSource={RelativeSource AncestorType=RadioButton}}"/>
                  <TextBlock Text="Leavers, compromised accounts" FontSize="11.5" Foreground="{DynamicResource Muted}"/>
                </StackPanel>
              </StackPanel>
            </RadioButton>
            <RadioButton x:Name="NavHide" Style="{StaticResource NavItem}">
              <StackPanel Orientation="Horizontal">
                <Path Data="M2,12 C5,6.5 19,6.5 22,12 C19,17.5 5,17.5 2,12 Z M12,9.2 A2.8,2.8 0 1 1 11.99,9.2 M4,4 L20,20" Stroke="{Binding Foreground, RelativeSource={RelativeSource AncestorType=RadioButton}}" StrokeThickness="1.8" Width="18" Height="18" Stretch="Uniform" VerticalAlignment="Top" Margin="0,1,0,0"/>
                <StackPanel Margin="12,0,0,0">
                  <TextBlock Text="Hide from address book" FontWeight="SemiBold" Foreground="{Binding Foreground, RelativeSource={RelativeSource AncestorType=RadioButton}}"/>
                  <TextBlock Text="Remove someone from the GAL" FontSize="11.5" Foreground="{DynamicResource Muted}"/>
                </StackPanel>
              </StackPanel>
            </RadioButton>
            <TextBlock Text="SETUP" Margin="20,22,0,8" FontSize="11" FontWeight="SemiBold" Foreground="{DynamicResource Muted}"/>
            <RadioButton x:Name="NavRules" Style="{StaticResource NavItem}">
              <StackPanel Orientation="Horizontal">
                <Path Data="M4.5,12 A7.5,7.5 0 0 1 17.6,7 M18,3 V7.4 H13.6 M19.5,12 A7.5,7.5 0 0 1 6.4,17 M6,21 V16.6 H10.4" Stroke="{Binding Foreground, RelativeSource={RelativeSource AncestorType=RadioButton}}" StrokeThickness="1.8" Width="18" Height="18" Stretch="Uniform" VerticalAlignment="Top" Margin="0,1,0,0"/>
                <StackPanel Margin="12,0,0,0">
                  <TextBlock Text="Set up sync rules" FontWeight="SemiBold" Foreground="{Binding Foreground, RelativeSource={RelativeSource AncestorType=RadioButton}}"/>
                  <TextBlock Text="For sysadmins: Entra Connect" FontSize="11.5" Foreground="{DynamicResource Muted}"/>
                  <Border x:Name="RulesBadge" Background="{DynamicResource DangerFill}" CornerRadius="2" Padding="6,1" Margin="0,5,0,0" Visibility="Collapsed" HorizontalAlignment="Left">
                    <TextBlock Text="A rule needs attention" FontSize="11" Foreground="White" FontWeight="SemiBold"/>
                  </Border>
                </StackPanel>
              </StackPanel>
            </RadioButton>
          </StackPanel>
        </DockPanel>
      </Border>

      <!-- Content -->
      <Grid Grid.Column="1" Background="{DynamicResource Bg}">
        $block
        $hide

        <ScrollViewer x:Name="RulesView" VerticalScrollBarVisibility="Auto" Visibility="Collapsed">
          <StackPanel Margin="28,22,28,24" MaxWidth="1100" HorizontalAlignment="Left">
            <TextBlock Text="Set up sync rules" FontSize="22" FontWeight="SemiBold" Foreground="{DynamicResource Text}"/>
            <TextBlock Margin="0,4,0,0" TextWrapping="Wrap" FontSize="13" Foreground="{DynamicResource Muted}"
                       Text="Blocking and hiding only work if Entra Connect has a custom sync rule for each. These rules are NOT copied when Entra Connect moves to a new server, so check here after any move. This part is for sysadmins."/>

            <Border Style="{StaticResource Card}" Margin="0,18,0,0" Padding="16,14">
              <StackPanel>
                <TextBlock Text="Entra Connect server" FontWeight="SemiBold" Foreground="{DynamicResource Text}"/>
                <Grid Margin="0,8,0,0">
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="320"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                  </Grid.ColumnDefinitions>
                  <TextBox Grid.Column="0" x:Name="ServerBox" Tag="Server name, e.g. AADC01" Style="{StaticResource SearchBox}"/>
                  <Button Grid.Column="1" x:Name="FindServer" Content="Find it for me" Margin="8,0,0,0" Style="{StaticResource SecondaryButton}"/>
                  <Button Grid.Column="2" x:Name="CheckRules" Content="Check rules" Margin="8,0,0,0" Style="{StaticResource PrimaryButton}"/>
                </Grid>
                <TextBlock x:Name="ServerNote" Margin="0,8,0,0" TextWrapping="Wrap" FontSize="12" Foreground="{DynamicResource Muted}"
                           Text="Rules can only be read and created when this tool runs ON the Entra Connect server; Entra Connect refuses these requests over a remote connection. From anywhere else, save the script below and run it there."/>
              </StackPanel>
            </Border>

            <UniformGrid Columns="2" Margin="0,12,0,0">
              <Border x:Name="BlockSetupCard" Style="{StaticResource Card}" BorderThickness="4,1,1,1" BorderBrush="{DynamicResource Info}" Margin="0,0,6,0" Padding="14,12">
                <StackPanel>
                  <TextBlock Text="Block Microsoft 365 sign-in rule" Foreground="{DynamicResource Muted}" FontSize="12"/>
                  <TextBlock x:Name="BlockSetupState" Text="Not checked yet" FontSize="15" FontWeight="SemiBold" Margin="0,2,0,0" Foreground="{DynamicResource Text}"/>
                  <TextBlock x:Name="BlockSetupReason" TextWrapping="Wrap" Margin="0,4,0,0" Foreground="{DynamicResource Muted}"/>
                  <TextBlock x:Name="BlockSetupWarnings" TextWrapping="Wrap" Margin="0,6,0,0" Foreground="{DynamicResource Warn}" Visibility="Collapsed"/>
                </StackPanel>
              </Border>
              <Border x:Name="HideSetupCard" Style="{StaticResource Card}" BorderThickness="4,1,1,1" BorderBrush="{DynamicResource Info}" Margin="6,0,0,0" Padding="14,12">
                <StackPanel>
                  <TextBlock Text="Hide from address book rule" Foreground="{DynamicResource Muted}" FontSize="12"/>
                  <TextBlock x:Name="HideSetupState" Text="Not checked yet" FontSize="15" FontWeight="SemiBold" Margin="0,2,0,0" Foreground="{DynamicResource Text}"/>
                  <TextBlock x:Name="HideSetupReason" TextWrapping="Wrap" Margin="0,4,0,0" Foreground="{DynamicResource Muted}"/>
                  <TextBlock x:Name="HideSetupWarnings" TextWrapping="Wrap" Margin="0,6,0,0" Foreground="{DynamicResource Warn}" Visibility="Collapsed"/>
                </StackPanel>
              </Border>
            </UniformGrid>

            <Border Style="{StaticResource Card}" Margin="0,12,0,0" Padding="16,14">
              <StackPanel>
                <TextBlock Text="Build a rule" FontSize="15" FontWeight="SemiBold" Foreground="{DynamicResource Text}"/>
                <TextBlock Margin="0,2,0,12" TextWrapping="Wrap" Foreground="{DynamicResource Muted}" Text="Only needed where the rule above is missing or broken. Nothing changes until you press Create, and the tool refuses to add a second rule for the same fix."/>

                <TextBlock Text="Which fix" Foreground="{DynamicResource Muted}" FontSize="12" Margin="0,0,0,6"/>
                <UniformGrid Columns="2">
                  <RadioButton x:Name="PickBlock" GroupName="PickRule" Style="{StaticResource OptionRadio}" Margin="0,0,6,8" IsChecked="True">
                    <TextBlock Text="Block Microsoft 365 sign-in" FontWeight="SemiBold" Foreground="{DynamicResource Text}"/>
                  </RadioButton>
                  <RadioButton x:Name="PickHide" GroupName="PickRule" Style="{StaticResource OptionRadio}" Margin="6,0,0,8">
                    <TextBlock Text="Hide from address book" FontWeight="SemiBold" Foreground="{DynamicResource Text}"/>
                  </RadioButton>
                </UniformGrid>

                <StackPanel x:Name="MethodPanel">
                  <TextBlock Text="What blocking should do" Foreground="{DynamicResource Muted}" FontSize="12" Margin="0,6,0,6"/>
                  <RadioButton x:Name="MethodDisable" GroupName="PickMethod" Style="{StaticResource OptionRadio}" IsChecked="True">
                    <StackPanel>
                      <TextBlock Text="Disable the Microsoft 365 account (recommended)" FontWeight="SemiBold" Foreground="{DynamicResource Text}"/>
                      <TextBlock TextWrapping="Wrap" Foreground="{DynamicResource Muted}" Text="They cannot sign in. Mailbox, licences, OneDrive and group memberships are kept, so restoring sign-in puts everything back."/>
                    </StackPanel>
                  </RadioButton>
                  <RadioButton x:Name="MethodRemove" GroupName="PickMethod" Style="{StaticResource OptionRadio}">
                    <StackPanel>
                      <TextBlock Text="Remove the person from Microsoft 365" FontWeight="SemiBold" Foreground="{DynamicResource Danger}"/>
                      <TextBlock TextWrapping="Wrap" Foreground="{DynamicResource Muted}" Text="Microsoft 365 DELETES the account. The mailbox, licences and group memberships go with it. Only choose this if that is what the client wants for every blocked person."/>
                    </StackPanel>
                  </RadioButton>
                </StackPanel>

                <TextBlock Text="The rule that will be created" Foreground="{DynamicResource Muted}" FontSize="12" Margin="0,8,0,6"/>
                <TextBox x:Name="RulePreview" Style="{StaticResource MonoBox}" MinHeight="150"/>

                <CheckBox x:Name="ReplaceExisting" Margin="0,12,0,0" Style="{StaticResource ToggleCheck}" Visibility="Collapsed"
                          Content="Replace the broken rule that is there now"/>
                <CheckBox x:Name="AcceptDelete" Margin="0,10,0,0" Style="{StaticResource ToggleCheck}" Visibility="Collapsed"
                          Content="I understand this rule deletes blocked people from Microsoft 365"/>

                <WrapPanel Margin="0,14,0,0">
                  <Button x:Name="SaveScript" Content="Save as script for the Entra Connect server..." Style="{StaticResource SecondaryButton}" Margin="0,0,8,8"/>
                  <Button x:Name="CopyScript" Content="Copy script" Style="{StaticResource GhostButton}" Margin="0,0,8,8"/>
                  <Button x:Name="PreviewRule" Content="Check what would change" Style="{StaticResource SecondaryButton}" Margin="0,0,8,8"/>
                  <Button x:Name="CreateRule" Content="Create the rule" Style="{StaticResource PrimaryButton}" Margin="0,0,8,8"/>
                </WrapPanel>

                <TextBox x:Name="RuleResult" Style="{StaticResource MonoBox}" Margin="0,6,0,0" MinHeight="60" Visibility="Collapsed"/>
              </StackPanel>
            </Border>
          </StackPanel>
        </ScrollViewer>
      </Grid>
    </Grid>

    <!-- Status bar -->
    <Border Grid.Row="2" Background="{DynamicResource Surface}" BorderBrush="{DynamicResource Border}" BorderThickness="0,1,0,0" Padding="24,6">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <TextBlock x:Name="StatusText" Text="Ready." Foreground="{DynamicResource Muted}" FontSize="12" TextTrimming="CharacterEllipsis"/>
        <Button Grid.Column="1" x:Name="SyncNow" Content="Run a sync now" Style="{StaticResource GhostButton}" Padding="10,3" FontSize="12"/>
      </Grid>
    </Border>
  </Grid>
</Window>
"@
}

#endregion

#region Theme

$script:Themes = @{
    Dark = @{
        Bg = '#14161B'; Surface = '#1B1E25'; Surface2 = '#232731'; Hover = '#2B303B'; Border = '#333946'
        Text = '#E6EAF0'; Muted = '#97A1AF'; Accent = '#4FA8E8'; AccentSoft = '#1A3347'; OnAccent = '#0B1520'
        Danger = '#F06A60'; DangerFill = '#C93A31'; DangerSoft = '#3A1F1F'; Success = '#46C267'
        Warn = '#E0A93B'; WarnSoft = '#3A3020'; Info = '#58A6FF'
    }
    Light = @{
        Bg = '#F4F6F9'; Surface = '#FFFFFF'; Surface2 = '#EEF1F5'; Hover = '#E4E9EF'; Border = '#D0D7DE'
        Text = '#1F2328'; Muted = '#59636E'; Accent = '#0B6BCB'; AccentSoft = '#DCEBFA'; OnAccent = '#FFFFFF'
        Danger = '#C4262E'; DangerFill = '#C4262E'; DangerSoft = '#FBE3E4'; Success = '#1A7F37'
        Warn = '#8A5A00'; WarnSoft = '#FFF1D6'; Info = '#0B6BCB'
    }
}

function Set-UiTheme {
    param([Parameter(Mandatory)][ValidateSet('Dark', 'Light')][string]$Name)
    foreach ($k in $script:Themes[$Name].Keys) {
        $color = [System.Windows.Media.Color][System.Windows.Media.ColorConverter]::ConvertFromString($script:Themes[$Name][$k])
        # Cast, do not store New-Object's output directly: that is a PSObject wrapper, and WPF
        # rejects it as a Background ("'#FFFFFFFF' is not a valid value for property").
        $script:Window.Resources[$k] = [System.Windows.Media.SolidColorBrush](New-Object System.Windows.Media.SolidColorBrush $color)
    }
    $script:ThemeName = $Name
    $script:Ui.ThemeToggle.Content = $(if ($Name -eq 'Dark') { 'Light mode' } else { 'Dark mode' })
}

function Get-ThemeBrush {
    param([string]$Key)
    $script:Window.Resources[$Key]
}

#endregion

#region Background work

# Slow work (finding the Entra Connect server, reading rules, AD searches, AD writes) runs in
# a small runspace pool so the window never freezes. A single DispatcherTimer collects
# finished tasks and runs their callbacks on the UI thread.
$script:PendingTasks = New-Object System.Collections.ArrayList

function Start-UiTask {
    param(
        [Parameter(Mandatory)][string]$Command,
        [hashtable]$Arguments = @{},
        [scriptblock]$OnDone,
        [string]$Busy,
        # Handed to OnDone as its third argument, so callbacks stay plain script blocks.
        $Context
    )

    $ps = [powershell]::Create()
    $ps.RunspacePool = $script:Pool
    [void]$ps.AddScript({
        param($CorePath, $Command, $Arguments)
        if (-not (Get-Command -Name Get-SyncedUserRows -ErrorAction SilentlyContinue)) {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue -Verbose:$false
            . $CorePath -LoadFunctionsOnly
        }
        & $Command @Arguments
    }).AddArgument($script:CorePath).AddArgument($Command).AddArgument($Arguments)

    if ($Busy) { Set-Status -Text $Busy -Busy }
    $task = [PSCustomObject]@{ PowerShell = $ps; Handle = $ps.BeginInvoke(); OnDone = $OnDone; Busy = [bool]$Busy; Context = $Context }
    [void]$script:PendingTasks.Add($task)
    if (-not $script:TaskTimer.IsEnabled) { $script:TaskTimer.Start() }
}

function Complete-UiTasks {
    foreach ($task in @($script:PendingTasks)) {
        if (-not $task.Handle.IsCompleted) { continue }
        [void]$script:PendingTasks.Remove($task)
        $output = $null
        $errorText = $null
        try {
            $output = $task.PowerShell.EndInvoke($task.Handle)
            if ($task.PowerShell.Streams.Error.Count -gt 0 -and ($null -eq $output -or @($output).Count -eq 0)) {
                $errorText = ($task.PowerShell.Streams.Error | Select-Object -First 1).ToString()
            }
        } catch {
            $errorText = $_.Exception.Message
            if ($_.Exception.InnerException) { $errorText = $_.Exception.InnerException.Message }
        } finally {
            $task.PowerShell.Dispose()
        }
        if ($task.OnDone) {
            try { & $task.OnDone $output $errorText $task.Context } catch { Show-Problem -Message "Something went wrong: $($_.Exception.Message)" }
        }
    }
    if ($script:PendingTasks.Count -eq 0) {
        $script:TaskTimer.Stop()
        $script:Window.Cursor = $null
    }
}

#endregion

#region UI helpers

function Set-Status {
    param([string]$Text, [switch]$Busy)
    $script:Ui.StatusText.Text = $Text
    $script:Window.Cursor = $(if ($Busy) { [System.Windows.Input.Cursors]::AppStarting } else { $null })
}

function Show-Problem {
    param([string]$Message, [string]$Title = 'Problem')
    [void][System.Windows.MessageBox]::Show($script:Window, $Message, $Title, 'OK', 'Warning')
}

function Confirm-Action {
    param([string]$Message, [string]$Title = 'Please confirm', [string]$Icon = 'Question')
    ([System.Windows.MessageBox]::Show($script:Window, $Message, $Title, 'YesNo', $Icon) -eq 'Yes')
}

function Invoke-Safely {
    param([scriptblock]$Action)
    try { & $Action } catch { Show-Problem -Message "Something went wrong: $($_.Exception.Message)" }
}

function Show-Section {
    param([ValidateSet('BlockSignIn', 'HideFromGAL', 'SyncRules')][string]$Name)
    $script:Ui.BlockView.Visibility = $(if ($Name -eq 'BlockSignIn') { 'Visible' } else { 'Collapsed' })
    $script:Ui.HideView.Visibility  = $(if ($Name -eq 'HideFromGAL') { 'Visible' } else { 'Collapsed' })
    $script:Ui.RulesView.Visibility = $(if ($Name -eq 'SyncRules')   { 'Visible' } else { 'Collapsed' })
    switch ($Name) {
        'BlockSignIn' { $script:Ui.NavBlock.IsChecked = $true }
        'HideFromGAL' { $script:Ui.NavHide.IsChecked = $true }
        'SyncRules'   { $script:Ui.NavRules.IsChecked = $true }
    }
}

function Get-ViewPrefix { param([string]$FeatureKey) if ($FeatureKey -eq 'BlockSignIn') { 'Block' } else { 'Hide' } }

function Get-FeatureFromControl {
    <#
    .SYNOPSIS
        BlockSignIn or HideFromGAL, from a control's x:Name prefix (BlockSearch, HideApply, ...).
        Lets one plain event handler serve both sections.
    #>
    param($Control)
    if ([string]$Control.Name -like 'Block*') { 'BlockSignIn' } else { 'HideFromGAL' }
}
function Get-UiElement { param([string]$Name) $script:Ui[$Name] }

#endregion

#region Rule status

function Get-RuleStatusLines {
    <#
    .SYNOPSIS
        Headline, detail, extra warning and accent key for a feature's rule card. Pure, so
        the wording is testable.
    #>
    param(
        [Parameter(Mandatory)][string]$FeatureKey,
        [AllowNull()][object]$Status,
        [bool]$SkipRuleCheck = $false
    )

    if ($null -eq $Status) {
        return [PSCustomObject]@{ Headline = 'Checking the sync rule...'; Detail = 'Looking for the Entra Connect server. This can take a minute the first time.'; Warning = ''; Accent = 'Info'; ShowFix = $false }
    }

    $look = Get-EntraConnectStatusPresentation -State $Status.State
    $server = if ($Status.Server) { $Status.Server } else { 'not found' }
    $detail = "$($Status.Reason)  Entra Connect server: $server."
    $warning = ''
    $accent = switch ($Status.State) { 'Present' { 'Success' } 'Unknown' { 'Warn' } default { 'Danger' } }

    if ($Status.ShouldBlock) {
        $what = if ($FeatureKey -eq 'BlockSignIn') { 'Blocking' } else { 'Hiding' }
        $warning = if ($SkipRuleCheck) { "$what is still allowed because -SkipRuleCheck was used, but it will NOT take effect until the rule is fixed." } `
                   else { "$what is switched off until the rule is fixed: it would look like it worked while changing nothing." }
    } elseif ($FeatureKey -eq 'BlockSignIn' -and $Status.Mechanism -eq 'cloudFiltered') {
        $warning = 'Careful: on this server, blocking DELETES the person from Microsoft 365. Their mailbox and licences go with it.'
    }
    if (@($Status.Warnings).Count -gt 0) {
        $joined = (@($Status.Warnings) -join ' ')
        $warning = (($warning, $joined) | Where-Object { $_ }) -join ' '
    }

    [PSCustomObject]@{
        Headline = $look.Headline
        Detail   = $detail
        Warning  = $warning
        Accent   = $accent
        ShowFix  = ($Status.State -ne 'Present')
    }
}

function Update-RuleCard {
    param([string]$FeatureKey)

    $feature = Get-SyncedUserFeature -Key $FeatureKey
    $status = $script:RuleStatus[$feature.RuleKey]
    $p = Get-ViewPrefix -FeatureKey $FeatureKey
    $lines = Get-RuleStatusLines -FeatureKey $FeatureKey -Status $status -SkipRuleCheck ([bool]$SkipRuleCheck)

    (Get-UiElement "${p}RuleHeadline").Text = $lines.Headline
    (Get-UiElement "${p}RuleDetail").Text = $lines.Detail
    $warn = Get-UiElement "${p}RuleWarning"
    $warn.Text = $lines.Warning
    $warn.Visibility = $(if ($lines.Warning) { 'Visible' } else { 'Collapsed' })
    (Get-UiElement "${p}RuleCard").BorderBrush = Get-ThemeBrush $lines.Accent
    (Get-UiElement "${p}RuleFix").Visibility = $(if ($lines.ShowFix) { 'Visible' } else { 'Collapsed' })

    # The card for the same rule on the "Set up sync rules" page.
    (Get-UiElement "${p}SetupCard").BorderBrush = Get-ThemeBrush $lines.Accent
    (Get-UiElement "${p}SetupState").Text = $(if ($status) { $lines.Headline } else { 'Checking...' })
    (Get-UiElement "${p}SetupReason").Text = $(if ($status) { $status.Reason } else { '' })
    $setupWarn = Get-UiElement "${p}SetupWarnings"
    $setupWarn.Text = $(if ($status) { (@($status.Warnings) -join ' ') } else { '' })
    $setupWarn.Visibility = $(if ($setupWarn.Text) { 'Visible' } else { 'Collapsed' })

    # Only for a rule confirmed missing or broken; "could not check" is not a fault to fix.
    $attention = @($script:RuleStatus.Values | Where-Object { $_ -and $_.ShouldBlock }).Count -gt 0
    $script:Ui.RulesBadge.Visibility = $(if ($attention) { 'Visible' } else { 'Collapsed' })

    Update-SelectionSummary -FeatureKey $FeatureKey
    Update-RuleBuilder
}

function Start-RuleCheck {
    param([string]$Server)

    foreach ($k in @('BlockCloudSignIn', 'HideFromGAL')) { $script:RuleStatus[$k] = $null }
    Update-RuleCard -FeatureKey 'BlockSignIn'
    Update-RuleCard -FeatureKey 'HideFromGAL'
    $script:Ui.ServerChip.Text = 'finding...'

    Start-UiTask -Command 'Get-BothRuleStatuses' -Arguments @{ ComputerName = $Server; SettingsPath = $script:SettingsPath; Credential = $Credential } `
        -Busy 'Checking the sync rules on the Entra Connect server...' -OnDone {
            param($out, $err)
            if ($err -or -not $out) {
                $fallback = New-EntraConnectStatus -State 'Unknown' -Reason "The check failed: $err"
                $script:RuleStatus['BlockCloudSignIn'] = $fallback
                $script:RuleStatus['HideFromGAL'] = $fallback
            } else {
                $result = @($out)[0]
                $script:RuleStatus['BlockCloudSignIn'] = $result.BlockCloudSignIn
                $script:RuleStatus['HideFromGAL'] = $result.HideFromGAL
            }
            $server = $script:RuleStatus['BlockCloudSignIn'].Server
            $script:ServerName = $server
            $script:Ui.ServerChip.Text = $(if ($server) { $server } else { 'not found' })
            if ($server -and -not $script:Ui.ServerBox.Text) { $script:Ui.ServerBox.Text = $server }
            Update-RuleCard -FeatureKey 'BlockSignIn'
            Update-RuleCard -FeatureKey 'HideFromGAL'
            Update-RowStatuses -FeatureKey 'BlockSignIn'
            Update-RowStatuses -FeatureKey 'HideFromGAL'
            Set-Status -Text "Sync rules checked at $(Get-Date -Format 'HH:mm')."
        }
}

#endregion

#region People lists

function Update-SelectionSummary {
    param([string]$FeatureKey)

    $p = Get-ViewPrefix -FeatureKey $FeatureKey
    $rows = $script:Rows[$FeatureKey]
    $ticked = @($rows | Where-Object { $_.IsSelected })
    $feature = Get-SyncedUserFeature -Key $FeatureKey
    $status = $script:RuleStatus[$feature.RuleKey]

    (Get-UiElement "${p}Selected").Text = $(switch ($ticked.Count) { 0 { 'Nobody ticked' } 1 { '1 person ticked' } default { "$_ people ticked" } })

    $applyBlocked = ($status -and $status.ShouldBlock -and -not $SkipRuleCheck)
    $apply = Get-UiElement "${p}Apply"
    $remove = Get-UiElement "${p}Remove"
    $apply.IsEnabled = ($ticked.Count -gt 0 -and -not $applyBlocked)
    $remove.IsEnabled = ($ticked.Count -gt 0)
    $apply.Content = $(if ($ticked.Count -gt 0) { "$($feature.ApplyVerb) ($($ticked.Count))" } else { $feature.ApplyVerb })
    $remove.Content = $(if ($ticked.Count -gt 0) { "$($feature.RemoveVerb) ($($ticked.Count))" } else { $feature.RemoveVerb })
    $apply.ToolTip = $(if ($applyBlocked) { 'Switched off until the sync rule is fixed (see the card above).' } else { $null })
}

function Update-RowStatuses {
    param([string]$FeatureKey)

    $feature = Get-SyncedUserFeature -Key $FeatureKey
    $status = $script:RuleStatus[$feature.RuleKey]
    foreach ($row in $script:Rows[$FeatureKey]) {
        $s = Get-MarkerStatus -Feature $feature -Marked $row.Marked -RuleStatus $status
        $row.StatusText = $s.Text
        $row.StatusKind = $s.Kind
    }
    (Get-UiElement "$(Get-ViewPrefix -FeatureKey $FeatureKey)Grid").Items.Refresh()
}

function Start-PeopleLoad {
    param([string]$FeatureKey)

    $p = Get-ViewPrefix -FeatureKey $FeatureKey
    $feature = Get-SyncedUserFeature -Key $FeatureKey
    $script:LoadVersion[$FeatureKey]++
    $version = $script:LoadVersion[$FeatureKey]
    (Get-UiElement "${p}Empty").Text = 'Searching Active Directory...'
    (Get-UiElement "${p}Empty").Visibility = 'Visible'

    $taskArgs = @{
        FeatureKey      = $FeatureKey
        Search          = (Get-UiElement "${p}Search").Text
        IncludeDisabled = [bool](Get-UiElement "${p}IncludeDisabled").IsChecked
        OnlyMarked      = [bool](Get-UiElement "${p}OnlyMarked").IsChecked
        RuleStatus      = $script:RuleStatus[$feature.RuleKey]
        ResultSize      = $script:ResultSize
    }
    if ($SearchBase) { $taskArgs['SearchBase'] = $SearchBase }

    # The version travels with the task so a slower, older search cannot overwrite a newer one.
    Start-UiTask -Command 'Get-SyncedUserRows' -Arguments $taskArgs `
        -Context ([PSCustomObject]@{ FeatureKey = $FeatureKey; Version = $version }) `
        -OnDone {
            param($out, $err, $ctx)
            Complete-PeopleLoad -FeatureKey $ctx.FeatureKey -Version $ctx.Version -Output $out -ErrorText $err
        }
}

function Complete-PeopleLoad {
    param([string]$FeatureKey, [int]$Version, $Output, [string]$ErrorText)

    if ($Version -ne $script:LoadVersion[$FeatureKey]) { return }   # a newer search replaced this one
    $p = Get-ViewPrefix -FeatureKey $FeatureKey
    $grid = Get-UiElement "${p}Grid"
    $empty = Get-UiElement "${p}Empty"

    if ($ErrorText) {
        $script:Rows[$FeatureKey] = New-Object System.Collections.ArrayList
        $grid.ItemsSource = $script:Rows[$FeatureKey]
        $empty.Text = "Could not search Active Directory: $ErrorText"
        $empty.Visibility = 'Visible'
        (Get-UiElement "${p}Count").Text = ''
        Update-SelectionSummary -FeatureKey $FeatureKey
        return
    }

    $list = New-Object System.Collections.ArrayList
    foreach ($r in @($Output)) { if ($null -ne $r) { [void]$list.Add($r) } }
    $script:Rows[$FeatureKey] = $list
    $grid.ItemsSource = $list

    $count = $list.Count
    $more = if ($count -ge $script:ResultSize) { " (first $($script:ResultSize) - type more of the name to narrow it down)" } else { '' }
    (Get-UiElement "${p}Count").Text = $(if ($count -eq 1) { '1 person' } else { "$count people$more" })
    $empty.Text = 'Nobody matches. Try part of the name, the username, or tick "Include disabled accounts".'
    $empty.Visibility = $(if ($count -eq 0) { 'Visible' } else { 'Collapsed' })
    Update-SelectionSummary -FeatureKey $FeatureKey
    if (-not ($script:PendingTasks | Where-Object { $_.Busy })) { Set-Status -Text 'Ready.' }
}

function Set-AllTicks {
    param([string]$FeatureKey, [bool]$Value)
    foreach ($row in $script:Rows[$FeatureKey]) { $row.IsSelected = $Value }
    (Get-UiElement "$(Get-ViewPrefix -FeatureKey $FeatureKey)Grid").Items.Refresh()
    Update-SelectionSummary -FeatureKey $FeatureKey
}

function Get-ApplyConfirmation {
    <#
    .SYNOPSIS
        The confirmation text for a change. Pure, so the wording is testable.
    #>
    param(
        [Parameter(Mandatory)][string]$FeatureKey,
        [Parameter(Mandatory)][ValidateSet('Apply', 'Remove')][string]$Action,
        [Parameter(Mandatory)][string[]]$Names,
        [AllowNull()][object]$RuleStatus
    )

    $feature = Get-SyncedUserFeature -Key $FeatureKey
    $verb = if ($Action -eq 'Apply') { $feature.ApplyVerb } else { $feature.RemoveVerb }
    $list = ($Names | Select-Object -First 10 | ForEach-Object { "   - $_" }) -join "`r`n"
    if ($Names.Count -gt 10) { $list += "`r`n   ... and $($Names.Count - 10) more" }

    $lines = @("$verb for $($Names.Count) $(if ($Names.Count -eq 1) { 'person' } else { 'people' })?", '', $list, '')
    if ($Action -eq 'Apply' -and $FeatureKey -eq 'BlockSignIn') {
        if ($RuleStatus -and $RuleStatus.Mechanism -eq 'cloudFiltered') {
            $lines += 'WARNING: on this server blocking DELETES the person from Microsoft 365, including their mailbox and licences.'
        } elseif ($RuleStatus -and $RuleStatus.Mechanism -eq 'accountEnabled') {
            $lines += 'Their Microsoft 365 account will be disabled. Mailbox and licences are kept.'
        } else {
            $lines += 'The sync rule could not be checked, so what blocking does on this server is unconfirmed.'
        }
        $lines += 'People already signed in can stay signed in until their session ends. For an immediate cut-off, also revoke their sessions in the Entra admin center.'
    }
    $lines += 'The change reaches Microsoft 365 at the next Entra Connect sync.'
    $lines -join "`r`n"
}

function Invoke-MarkerChange {
    param([string]$FeatureKey, [ValidateSet('Apply', 'Remove')][string]$Action)

    $feature = Get-SyncedUserFeature -Key $FeatureKey
    $status = $script:RuleStatus[$feature.RuleKey]
    $ticked = @($script:Rows[$FeatureKey] | Where-Object { $_.IsSelected })
    if ($ticked.Count -eq 0) { return }

    if ($Action -eq 'Apply' -and $status -and $status.ShouldBlock -and -not $SkipRuleCheck) {
        Show-Problem -Title 'Not available yet' -Message "This is switched off because the sync rule is not working.`r`n`r`n$($status.Reason)`r`n`r`nOpen 'Set up sync rules' to fix it."
        return
    }

    $text = Get-ApplyConfirmation -FeatureKey $FeatureKey -Action $Action -Names @($ticked | ForEach-Object { $_.Name }) -RuleStatus $status
    $icon = if ($Action -eq 'Apply' -and $status -and $status.Mechanism -eq 'cloudFiltered') { 'Warning' } else { 'Question' }
    if (-not (Confirm-Action -Message $text -Icon $icon)) { return }

    $dns = @($ticked | ForEach-Object { $_.DistinguishedName })
    Start-UiTask -Command 'Invoke-SyncedUserMarkerBatch' -Arguments @{ FeatureKey = $FeatureKey; Action = $Action; Identities = $dns; RuleStatus = $status } `
        -Busy "Updating $($dns.Count) $(if ($dns.Count -eq 1) { 'person' } else { 'people' }) in Active Directory..." `
        -Context ([PSCustomObject]@{ FeatureKey = $FeatureKey; Action = $Action }) `
        -OnDone {
            param($out, $err, $ctx)
            Complete-MarkerChange -FeatureKey $ctx.FeatureKey -Action $ctx.Action -Output $out -ErrorText $err
        }
}

function Complete-MarkerChange {
    param([string]$FeatureKey, [string]$Action, $Output, [string]$ErrorText)

    if ($ErrorText) { Show-Problem -Message "The change could not be made: $ErrorText"; Set-Status -Text 'Change failed.'; return }

    $entries = @($Output | Where-Object { $null -ne $_ })
    $logPath = Write-SyncedUserChangeLog -Entries $entries -LogFolder $LogFolder
    $done = @($entries | Where-Object { $_.Result -eq 'Done' })
    $failed = @($entries | Where-Object { $_.Result -eq 'Failed' })

    $feature = Get-SyncedUserFeature -Key $FeatureKey
    $status = $script:RuleStatus[$feature.RuleKey]
    foreach ($row in $script:Rows[$FeatureKey]) {
        $hit = @($done | Where-Object { $_.User -eq $row.SamAccountName })
        if ($hit.Count -gt 0) {
            $row.Marked = ($Action -eq 'Apply')
            $s = Get-MarkerStatus -Feature $feature -Marked $row.Marked -RuleStatus $status
            $row.StatusText = $s.Text
            $row.StatusKind = $s.Kind
            $row.IsSelected = $false
        }
    }
    (Get-UiElement "$(Get-ViewPrefix -FeatureKey $FeatureKey)Grid").Items.Refresh()
    Update-SelectionSummary -FeatureKey $FeatureKey

    $logNote = if ($logPath) { "Logged to $logPath." } else { "The change log could not be written to $LogFolder." }
    Set-Status -Text "Updated $($done.Count) of $($entries.Count). $logNote"

    if ($failed.Count -gt 0) {
        $detail = ($failed | Select-Object -First 8 | ForEach-Object { "   $($_.User): $($_.Error)" }) -join "`r`n"
        Show-Problem -Title 'Some changes failed' -Message "Updated $($done.Count) of $($entries.Count).`r`n`r`nFailed:`r`n$detail"
    }
    if ($done.Count -gt 0) { Request-DeltaSync -Prompt }
}

#endregion

#region Sync

function Request-DeltaSync {
    param([switch]$Prompt)

    $server = $script:ServerName
    if (-not $server) {
        if ($Prompt) {
            Show-Problem -Title 'Saved in Active Directory' -Message 'The change is saved in Active Directory. No Entra Connect server is known, so a sync could not be started; it will apply at the next scheduled sync (about 30 minutes).'
        } else {
            Show-Problem -Message 'No Entra Connect server is known yet. Set it in "Set up sync rules".'
        }
        return
    }
    if ($Prompt -and -not (Confirm-Action -Title 'Run a sync?' -Message "Saved in Active Directory.`r`n`r`nRun an Entra Connect sync on $server now, so it reaches Microsoft 365 in a few minutes instead of up to 30?")) { return }

    Start-UiTask -Command 'Invoke-EntraConnectDeltaSync' -Arguments @{ ComputerName = $server; Credential = $Credential } `
        -Busy "Starting a sync on $server..." -OnDone {
            param($out, $err)
            $r = @($out)[0]
            if ($r -and $r.Success) {
                Set-Status -Text "Sync started on $($script:ServerName) at $(Get-Date -Format 'HH:mm'). Microsoft 365 usually shows the change within a few minutes."
            } else {
                $msg = if ($r) { $r.Error } else { $err }
                $hint = if ($msg -match 'busy|already|in progress') { "`r`n`r`nA sync is probably already running; it will pick the change up." } else { "`r`n`r`nThe change will still apply at the next scheduled sync." }
                Set-Status -Text 'Sync not started.'
                Show-Problem -Title 'Sync not started' -Message "Could not start a sync on $($script:ServerName).`r`n`r`n$msg$hint"
            }
        }
}

#endregion

#region Rule builder

function Get-SelectedBlueprint {
    $key = if ($script:Ui.PickHide.IsChecked) { 'HideFromGAL' } else { 'BlockCloudSignIn' }
    $method = if ($key -eq 'HideFromGAL') { 'Hide' } elseif ($script:Ui.MethodRemove.IsChecked) { 'RemoveFromM365' } else { 'DisableSignIn' }
    $domain = if ($script:DomainName) { $script:DomainName } else { 'your.domain' }
    Get-SyncRuleBlueprint -Key $key -Method $method -Domain $domain
}

function Update-RuleBuilder {
    if (-not $script:Ui) { return }
    $bp = Get-SelectedBlueprint
    $script:Ui.MethodPanel.Visibility = $(if ($bp.Key -eq 'BlockCloudSignIn') { 'Visible' } else { 'Collapsed' })
    $script:Ui.RulePreview.Text = Format-SyncRuleBlueprint -Blueprint $bp

    $status = $script:RuleStatus[$bp.Key]
    $isBroken = ($status -and $status.State -eq 'Misconfigured')
    $isPresent = ($status -and $status.State -eq 'Present')
    $script:Ui.ReplaceExisting.Visibility = $(if ($isBroken) { 'Visible' } else { 'Collapsed' })
    if (-not $isBroken) { $script:Ui.ReplaceExisting.IsChecked = $false }
    $script:Ui.AcceptDelete.Visibility = $(if ($bp.IsDestructive) { 'Visible' } else { 'Collapsed' })
    if (-not $bp.IsDestructive) { $script:Ui.AcceptDelete.IsChecked = $false }

    $server = $script:Ui.ServerBox.Text.Trim()
    $ready = $server -and -not $isPresent -and (-not $isBroken -or $script:Ui.ReplaceExisting.IsChecked) -and (-not $bp.IsDestructive -or $script:Ui.AcceptDelete.IsChecked)
    $script:Ui.CreateRule.IsEnabled = [bool]$ready
    $script:Ui.PreviewRule.IsEnabled = [bool]$server
    $script:Ui.CreateRule.Content = $(if ($server) { "Create the rule on $server" } else { 'Create the rule' })
    $script:Ui.CreateRule.ToolTip = $(if ($isPresent) { 'A rule for this fix is already in place. Creating another would conflict with it.' } else { $null })
}

function Show-RuleResult {
    param([string]$Text)
    $script:Ui.RuleResult.Text = $Text
    $script:Ui.RuleResult.Visibility = 'Visible'
}

function Format-RuleCreationResult {
    <#
    .SYNOPSIS
        Plain-text outcome of a preview or creation. Pure, so the wording is testable.
    #>
    param([Parameter(Mandatory)][object]$Result, [Parameter(Mandatory)][object]$Blueprint, [string]$Server)

    $lines = @()
    foreach ($w in @($Result.Warnings)) { $lines += "[WARN] $w" }
    if (-not $Result.Success) {
        switch ($Result.Stage) {
            'RemoteBlocked' { $lines += "[WARN] $Server refused the request over a remote connection; Entra Connect only accepts it locally. Use 'Save as script', copy the file to $Server and run it there." }
            'AlreadyExists' { $lines += "[INFO] $($Result.Error)" }
            default         { $lines += "[FAIL] $($Result.Error)" }
        }
        return ($lines -join "`r`n")
    }
    if ($Result.Stage -eq 'Preview') {
        $lines += "[INFO] Would create '$($Result.Rule.Name)' at precedence $($Result.Rule.Precedence) on connector '$($Result.Rule.Connector)'."
        foreach ($n in @($Result.Removed)) { $lines += "[INFO] Would remove the existing rule '$n'." }
        $lines += '[INFO] Nothing has been changed.'
        return ($lines -join "`r`n")
    }
    foreach ($n in @($Result.Removed)) { $lines += "[INFO] Removed the old rule '$n'." }
    $lines += "[PASS] Created '$($Result.Rule.Name)' (precedence $($Result.Rule.Precedence), connector '$($Result.Rule.Connector)')."
    $lines += ''
    $lines += Get-FullSyncInstructions -Server $Server -Destructive $Blueprint.IsDestructive
    $lines -join "`r`n"
}

function Start-RuleCreation {
    param([switch]$PreviewOnly)

    $bp = Get-SelectedBlueprint
    $server = $script:Ui.ServerBox.Text.Trim()
    if (-not $server) { Show-Problem -Message 'Type the Entra Connect server name first.'; return }

    if (-not $PreviewOnly) {
        $msg = "Create this rule on ${server}?`r`n`r`n$($bp.Name)`r`n`r`n$($bp.Consequence)`r`n`r`nAfterwards a Full Synchronization is needed before it does anything."
        if (-not (Confirm-Action -Title 'Create sync rule' -Message $msg -Icon $(if ($bp.IsDestructive) { 'Warning' } else { 'Question' }))) { return }
    }

    $taskArgs = @{ Blueprint = $bp; ComputerName = $server; Credential = $Credential; ReplaceExisting = [bool]$script:Ui.ReplaceExisting.IsChecked; PreviewOnly = [bool]$PreviewOnly }
    $script:LastBlueprint = $bp
    Start-UiTask -Command 'Invoke-SyncRuleCreation' -Arguments $taskArgs `
        -Busy $(if ($PreviewOnly) { "Asking $server what would change..." } else { "Creating the rule on $server..." }) `
        -OnDone {
            param($out, $err)
            $r = @($out)[0]
            if (-not $r) { $r = [PSCustomObject]@{ Success = $false; Stage = 'Connect'; Error = $err; Warnings = @(); Rule = $null; Removed = @() } }
            Show-RuleResult -Text (Format-RuleCreationResult -Result $r -Blueprint $script:LastBlueprint -Server $script:Ui.ServerBox.Text.Trim())
            Set-Status -Text $(if ($r.Success) { 'Done.' } else { 'The rule was not created.' })
            if ($r.Success -and $r.Stage -eq 'Created') { Start-RuleCheck -Server $script:Ui.ServerBox.Text.Trim() }
        }
}

function Save-RuleScript {
    $bp = Get-SelectedBlueprint
    $dialog = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.FileName = Get-SyncRuleScriptFileName -Blueprint $bp
    $dialog.Filter = 'PowerShell script (*.ps1)|*.ps1'
    $dialog.Title = 'Save the rule script'
    if (-not $dialog.ShowDialog($script:Window)) { return }

    # UTF-8 with BOM: Windows PowerShell 5.1 reads BOM-less files as ANSI.
    $encoding = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($dialog.FileName, (New-SyncRuleScriptText -Blueprint $bp), $encoding)
    Show-RuleResult -Text "[PASS] Saved $($dialog.FileName).`r`n`r`nCopy it to the Entra Connect server and run it in an elevated PowerShell window:`r`n    .\$([System.IO.Path]::GetFileName($dialog.FileName)) -WhatIf    (preview)`r`n    .\$([System.IO.Path]::GetFileName($dialog.FileName))            (create)"
}

#endregion

if ($LoadFunctionsOnly) {
    . $script:CorePath -LoadFunctionsOnly
    return
}

#region Start

# WPF needs STA. powershell.exe 3.0+ is STA by default; relaunch if started some other way.
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$PSCommandPath`"", '-Tab', $Tab)
    if ($EntraConnectServer) { $relaunch += @('-EntraConnectServer', $EntraConnectServer) }
    if ($SearchBase) { $relaunch += @('-SearchBase', "`"$SearchBase`"") }
    if ($SkipRuleCheck) { $relaunch += '-SkipRuleCheck' }
    Start-Process -FilePath 'powershell.exe' -ArgumentList $relaunch
    return
}

try {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

    # A launcher starts this with no console, so every startup failure must be shown in a box.
    try {
        Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
    } catch {
        [void][System.Windows.MessageBox]::Show("The ActiveDirectory PowerShell module could not be loaded.`r`n`r`n$($_.Exception.Message)`r`n`r`nInstall RSAT (Active Directory module for Windows PowerShell) or run this on a domain controller.", 'Missing prerequisite', 'OK', 'Error')
        return
    }
    if (-not (Test-Path -LiteralPath $script:CorePath)) {
        [void][System.Windows.MessageBox]::Show("SyncedUserFixes.Core.ps1 is missing from:`r`n$PSScriptRoot`r`n`r`nKeep all the files in the folder together.", 'Missing file', 'OK', 'Error')
        return
    }
    . $script:CorePath -LoadFunctionsOnly

    $script:SettingsPath = Get-EntraConnectSettingsPath -ScriptRoot $PSScriptRoot
    $script:RuleStatus = @{ BlockCloudSignIn = $null; HideFromGAL = $null }
    $script:Rows = @{ BlockSignIn = (New-Object System.Collections.ArrayList); HideFromGAL = (New-Object System.Collections.ArrayList) }
    $script:LoadVersion = @{ BlockSignIn = 0; HideFromGAL = 0 }
    $script:ResultSize = 1000
    $script:ServerName = $EntraConnectServer
    $script:DomainName = $null
    try { $script:DomainName = (Get-ADDomain -ErrorAction Stop).DNSRoot } catch { $script:DomainName = $null }

    [xml]$xaml = Get-MainWindowXaml
    $script:Window = [System.Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml))

    $script:Ui = @{}
    $names = @('DomainChip', 'ServerChip', 'ThemeToggle', 'NavBlock', 'NavHide', 'NavRules', 'RulesBadge', 'BlockView', 'HideView', 'RulesView',
               'ServerBox', 'FindServer', 'CheckRules', 'ServerNote', 'BlockSetupCard', 'HideSetupCard', 'BlockSetupState', 'HideSetupState',
               'BlockSetupReason', 'HideSetupReason', 'BlockSetupWarnings', 'HideSetupWarnings', 'PickBlock', 'PickHide', 'MethodPanel',
               'MethodDisable', 'MethodRemove', 'RulePreview', 'ReplaceExisting', 'AcceptDelete', 'SaveScript', 'CopyScript', 'PreviewRule',
               'CreateRule', 'RuleResult', 'StatusText', 'SyncNow')
    foreach ($p in @('Block', 'Hide')) {
        foreach ($s in @('RuleCard', 'RuleHeadline', 'RuleDetail', 'RuleWarning', 'RuleFix', 'Search', 'IncludeDisabled', 'OnlyMarked', 'Count', 'Grid', 'Empty', 'SelectAll', 'Clear', 'Selected', 'Remove', 'Apply')) {
            $names += "$p$s"
        }
    }
    foreach ($n in $names) { $script:Ui[$n] = $script:Window.FindName($n) }

    $script:ThemeName = 'Dark'
    $script:Ui.DomainChip.Text = $(if ($script:DomainName) { $script:DomainName } else { 'unknown' })
    if ($EntraConnectServer) { $script:Ui.ServerBox.Text = $EntraConnectServer }
    $script:Ui.HideIncludeDisabled.IsChecked = $true   # hiding leavers usually means disabled accounts

    $script:Pool = [runspacefactory]::CreateRunspacePool(1, 3)
    $script:Pool.Open()
    $script:TaskTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:TaskTimer.Interval = [TimeSpan]::FromMilliseconds(120)
    $script:TaskTimer.Add_Tick({ Complete-UiTasks })

    # Search-as-you-type, debounced so AD is not queried on every keystroke.
    $script:SearchTimers = @{}
    foreach ($fk in @('BlockSignIn', 'HideFromGAL')) {
        $t = New-Object System.Windows.Threading.DispatcherTimer
        $t.Interval = [TimeSpan]::FromMilliseconds(350)
        $t.Tag = $fk
        $t.Add_Tick({ param($timer, $e) $timer.Stop(); Start-PeopleLoad -FeatureKey $timer.Tag })
        $script:SearchTimers[$fk] = $t
    }

    # --- Wiring -------------------------------------------------------------------------
    $script:Ui.NavBlock.Add_Checked({ Show-Section -Name 'BlockSignIn' })
    $script:Ui.NavHide.Add_Checked({ Show-Section -Name 'HideFromGAL' })
    $script:Ui.NavRules.Add_Checked({ Show-Section -Name 'SyncRules' })
    $script:Ui.ThemeToggle.Add_Click({ Set-UiTheme -Name $(if ($script:ThemeName -eq 'Dark') { 'Light' } else { 'Dark' }); Update-RuleCard -FeatureKey 'BlockSignIn'; Update-RuleCard -FeatureKey 'HideFromGAL' })
    $script:Ui.SyncNow.Add_Click({ Invoke-Safely { Request-DeltaSync } })

    # One plain handler per event, shared by both sections: the control's name says which.
    foreach ($fk in @('BlockSignIn', 'HideFromGAL')) {
        $p = Get-ViewPrefix -FeatureKey $fk
        $script:Ui["${p}Search"].Add_TextChanged({
            param($box, $e)
            $timer = $script:SearchTimers[(Get-FeatureFromControl $box)]
            $timer.Stop(); $timer.Start()
        })
        $script:Ui["${p}IncludeDisabled"].Add_Click({ param($c, $e) Start-PeopleLoad -FeatureKey (Get-FeatureFromControl $c) })
        $script:Ui["${p}OnlyMarked"].Add_Click({ param($c, $e) Start-PeopleLoad -FeatureKey (Get-FeatureFromControl $c) })
        $script:Ui["${p}SelectAll"].Add_Click({ param($c, $e) Set-AllTicks -FeatureKey (Get-FeatureFromControl $c) -Value $true })
        $script:Ui["${p}Clear"].Add_Click({ param($c, $e) Set-AllTicks -FeatureKey (Get-FeatureFromControl $c) -Value $false })
        $script:Ui["${p}Apply"].Add_Click({ param($c, $e) Invoke-Safely { Invoke-MarkerChange -FeatureKey (Get-FeatureFromControl $c) -Action 'Apply' } })
        $script:Ui["${p}Remove"].Add_Click({ param($c, $e) Invoke-Safely { Invoke-MarkerChange -FeatureKey (Get-FeatureFromControl $c) -Action 'Remove' } })
        $script:Ui["${p}RuleFix"].Add_Click({ Show-Section -Name 'SyncRules' })

        # Clicking anywhere on a row ticks it; the tick box itself handles its own clicks.
        $script:Ui["${p}Grid"].Add_PreviewMouseLeftButtonUp({
            param($grid, $e)
            $node = $e.OriginalSource
            while ($node -and -not ($node -is [System.Windows.Controls.DataGridRow])) {
                if ($node -is [System.Windows.Controls.CheckBox] -or $node -is [System.Windows.Controls.Primitives.DataGridColumnHeader] -or $node -is [System.Windows.Controls.Primitives.ScrollBar]) { $node = $null; break }
                if ($node -is [System.Windows.Media.Visual] -or $node -is [System.Windows.Media.Media3D.Visual3D]) {
                    $node = [System.Windows.Media.VisualTreeHelper]::GetParent($node)
                } else {
                    $node = [System.Windows.LogicalTreeHelper]::GetParent($node)
                }
            }
            if ($node -and $node.Item) {
                $node.Item.IsSelected = -not [bool]$node.Item.IsSelected
                $grid.Items.Refresh()
            }
            Update-SelectionSummary -FeatureKey (Get-FeatureFromControl $grid)
        })
        # A tick made in the box itself: CheckBox.Click bubbles up to the grid.
        $script:Ui["${p}Grid"].AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler]{
            param($grid, $e)
            Update-SelectionSummary -FeatureKey (Get-FeatureFromControl $grid)
        })
    }

    $script:Ui.FindServer.Add_Click({
        $script:Ui.ServerBox.Text = ''
        Start-UiTask -Command 'Find-EntraConnectServer' -Arguments @{ SettingsPath = $script:SettingsPath } -Busy 'Looking for the Entra Connect server...' -OnDone {
            param($out, $err)
            $r = @($out)[0]
            if ($r -and $r.Server) {
                $script:Ui.ServerBox.Text = $r.Server
                Set-Status -Text "Found the Entra Connect server: $($r.Server)."
                Start-RuleCheck -Server $r.Server
            } else {
                Set-Status -Text 'No Entra Connect server found.'
                Show-Problem -Message 'No server running Entra Connect (the ADSync service) could be found from here. Type its name instead.'
            }
        }
    })
    $script:Ui.CheckRules.Add_Click({ Start-RuleCheck -Server $script:Ui.ServerBox.Text.Trim() })
    $script:Ui.ServerBox.Add_TextChanged({ Update-RuleBuilder })
    foreach ($n in @('PickBlock', 'PickHide', 'MethodDisable', 'MethodRemove', 'ReplaceExisting', 'AcceptDelete')) {
        $script:Ui[$n].Add_Click({ Update-RuleBuilder })
    }
    $script:Ui.SaveScript.Add_Click({ Invoke-Safely { Save-RuleScript } })
    $script:Ui.CopyScript.Add_Click({
        Invoke-Safely {
            [System.Windows.Clipboard]::SetText((New-SyncRuleScriptText -Blueprint (Get-SelectedBlueprint)))
            Set-Status -Text 'Rule script copied. Paste it into a .ps1 file on the Entra Connect server and run it there.'
        }
    })
    $script:Ui.PreviewRule.Add_Click({ Invoke-Safely { Start-RuleCreation -PreviewOnly } })
    $script:Ui.CreateRule.Add_Click({ Invoke-Safely { Start-RuleCreation } })

    $script:Window.Add_Loaded({
        Show-Section -Name $Tab
        Update-RuleBuilder
        Start-RuleCheck -Server $EntraConnectServer
        Start-PeopleLoad -FeatureKey 'BlockSignIn'
        Start-PeopleLoad -FeatureKey 'HideFromGAL'
    })
    $script:Window.Add_Closed({
        $script:TaskTimer.Stop()
        try { $script:Pool.Close(); $script:Pool.Dispose() } catch { Write-Verbose $_.Exception.Message }
    })

    [void]$script:Window.ShowDialog()
} catch {
    $message = $_.Exception.Message
    try {
        [void][System.Windows.MessageBox]::Show("M365 Synced User Fixes could not start.`r`n`r`n$message", 'Could not start', 'OK', 'Error')
    } catch {
        Write-Error "M365 Synced User Fixes could not start: $message"
    }
}

#endregion
