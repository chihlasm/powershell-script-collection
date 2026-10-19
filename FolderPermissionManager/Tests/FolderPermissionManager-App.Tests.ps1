<#
    Tests for the WPF app FolderPermissionManager-GUI.ps1, read-only half (SQ-017, AC1-AC25;
    Pester 5, run under pwsh). AC26-AC46 belong to SQ-018 and are not here.

    The app is never started and no window is ever shown: it is dot-sourced with
    -LoadFunctionsOnly. XAML is loaded with XamlReader only in the STA tests (AC3, AC4), and the
    windows are closed without being shown. Everything external is mocked (Start-Process,
    Add-Type, Show-AppMessage, Get-PSDrive, Get-ChildItem, Get-Acl, Get-ItemOwner). Files and
    folders live in $TestDrive. No network, no HttpListener, nothing is written to a real ACL.
    The only real background run is AC15 (a read inside $TestDrive).

    Names and parameters pinned here for the implementer (the spec leaves them open):
      Show-AppMessage -Message <text> [-Title] [-Icon]      all message boxes go through this
      Set-AppTheme [-Name] Dark|Light                       uses $script:Window and $script:UI.ThemeToggle
      $script:Themes.Dark / .Light                          palettes (same keys)
      Set-SavedTheme -Theme <Dark|Light> -SettingsPath <p>  /  Get-SavedTheme -SettingsPath <p>
      Get-StartupAction -IsSta <bool> -IsAdmin <bool>       RelaunchSta | RelaunchElevated | Continue
      Get-RelaunchArgumentList -ScriptPath -LogFolder -WhatIfMode -DriveMap   returns string[]
      ConvertTo-DriveMapArgument -DriveMap / ConvertFrom-DriveMapArgument -Argument
      Request-Elevation -ScriptPath -LogFolder -WhatIfMode -DriveMap   $true = relaunched, $false = declined
      Get-InstanceMutexName -LogFolder / Enter-SingleInstance -LogFolder   (uses createdNew, so a
          mutex already held, even by the same thread, makes it return $false)
      Resolve-MappedDrive -Path -DriveMap
      Get-DriveListModel -DriveMap                          rows: Label, IsMapped
      Initialize-BackgroundPool ($script:BgPool, $script:BgTasks), Start-BgTask -Work -ArgumentList
          -OnDone -State, Update-BgTasks; work blocks take ($Path, $CorePath) / ($Path, $OutputPath,
          $CorePath): $script:ListChildrenWork -> Ok, Children (Name, Path), Error;
          $script:ExportWork -> Ok, RowCount, OutputPath
      New-PaneRequest -Pane <name>, Test-CurrentRequest -Pane -Request,
          Set-FolderPermissionsResult -Result -Request ($script:ViewState.FolderPermissions: Path, Owner, Rows)
      ConvertTo-AclViewModel -Acl -> Owner, AreAccessRulesProtected, Rows (Identity, PermissionLevel, Type, IsInherited)
      ConvertTo-FileRows -Item -> Name, Path, SizeText, Modified
      Test-FileAclDiffers -Model (objects with Rows) / Get-FileAclDiffWarning
      Get-PathHeaderModel -Path -DriveMap -> Path, RealPath ($null when the path is not behind a mapping)
      Get-DefaultExportFileName -Path
      Get-LogFolderBanner -LogFolder -Notice -WhatIfMode -> rows with Level (Info|Warning) and Text
      Get-PaneState -Pane TreeNode|FolderPermissions|Files|FilePermissions -Phase Loading|Loaded|Failed
          [-Count] [-ErrorText] -> State (Loading|Empty|Error|Loaded), Text
      Format-Elapsed -Elapsed <TimeSpan>, Get-BusyLine -Action -Path -Elapsed

    Run:  Invoke-Pester .\FolderPermissionManager\Tests\FolderPermissionManager-App.Tests.ps1
#>

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:AppPath = Join-Path $script:Root 'FolderPermissionManager-GUI.ps1'
    $script:CorePath = Join-Path $script:Root 'FolderPermissions.Core.ps1'
    $script:IsSta = ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')
    $script:Dash = [string][char]0x2014

    # Guard: the pre-WPF script at this path is the browser GUI, which starts an HttpListener. Only
    # dot-source it when it declares -LoadFunctionsOnly (i.e. it is the new app).
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:AppPath, [ref]$null, [ref]$null)
    $script:ParamNames = @()
    if ($script:Ast.ParamBlock) { $script:ParamNames = @($script:Ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) }
    # The core is loaded first so core functions can be mocked even before the app exists.
    . $script:CorePath -LoadFunctionsOnly
    $script:AppLoaded = $false
    if ($script:ParamNames -contains 'LoadFunctionsOnly') {
        . $script:AppPath -LoadFunctionsOnly
        $script:AppLoaded = $true
    }

    $script:RealGetAcl = Get-Command Get-Acl -CommandType Cmdlet
    if ($script:IsSta) { Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase }

    # Isolation: the app's own files (settings, gui-errors.log) go to $TestDrive, never to the
    # real %LOCALAPPDATA%. Set again after each 'Script shape' test, because AC8 loads the app a
    # second time.
    function script:Set-TestAppPaths {
        $script:AppDataFolder = Join-Path $TestDrive 'appdata\FolderPermissionManager'
        $script:SettingsPath = Join-Path $script:AppDataFolder 'settings.json'
        $script:ErrorLogPath = Join-Path $script:AppDataFolder 'gui-errors.log'
    }
    Set-TestAppPaths

    # Backstop: nothing in SQ-017 changes a permission. If a test ever reaches a real ACL write,
    # it fails loudly instead of touching the machine.
    Mock Set-Acl { throw 'Set-Acl must not run in the SQ-017 tests.' }
    Mock Invoke-AclTool { throw 'Invoke-AclTool must not run in the SQ-017 tests.' }

    function script:Get-Luminance {
        # WCAG 2 relative luminance of a #RRGGBB colour.
        # https://www.w3.org/TR/WCAG21/#dfn-relative-luminance
        param([Parameter(Mandatory)][string]$Hex)
        $h = $Hex.TrimStart('#')
        $c = foreach ($i in 0..2) {
            $v = [Convert]::ToInt32($h.Substring($i * 2, 2), 16) / 255.0
            if ($v -le 0.04045) { $v / 12.92 } else { [math]::Pow(($v + 0.055) / 1.055, 2.4) }
        }
        0.2126 * $c[0] + 0.7152 * $c[1] + 0.0722 * $c[2]
    }
    function script:Get-ContrastRatio {
        # https://www.w3.org/TR/WCAG21/#dfn-contrast-ratio
        param([Parameter(Mandatory)][string]$A, [Parameter(Mandatory)][string]$B)
        $x = Get-Luminance $A
        $y = Get-Luminance $B
        ([math]::Max($x, $y) + 0.05) / ([math]::Min($x, $y) + 0.05)
    }

    function script:Get-AllXaml {
        # The four XAML documents the app defines, as strings, keyed by getter name.
        $h = [ordered]@{}
        foreach ($g in 'Get-MainWindowXaml', 'Get-PermissionDialogXaml', 'Get-CopyPermissionsDialogXaml', 'Get-ConfirmDialogXaml') {
            $h[$g] = & $g
        }
        $h
    }
    function script:Get-XamlNames {
        param([xml]$Xml)
        $xpath = '//*[@*[local-name()="Name"]][not(ancestor::*[local-name()="ControlTemplate" or local-name()="DataTemplate"])]'
        @($Xml.SelectNodes($xpath) | ForEach-Object { $_.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml') } | Where-Object { $_ })
    }
}

AfterAll {
    if ($script:BgPool) { try { $script:BgPool.Close() } catch { } }
}

Describe 'Window markup' {
    It 'AC1_XamlWellFormed' {
        $all = Get-AllXaml
        $all.Count | Should -Be 4
        foreach ($k in $all.Keys) {
            { [xml]$all[$k] } | Should -Not -Throw -Because "$k must return well-formed XML"
            # The scriptblock above runs in a child scope, so parse again here for the name check.
            $xml = [xml]$all[$k]
            $names = Get-XamlNames -Xml $xml
            $dupes = @($names | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)
            $dupes | Should -BeNullOrEmpty -Because "$k has duplicate x:Name values"
        }
    }

    It 'AC2_EveryControlExists' {
        $code = Get-Content -LiteralPath $script:AppPath -Raw
        $used = @([regex]::Matches($code, '(?i)\$script:UI\.(\w+)') | ForEach-Object { $_.Groups[1].Value })
        $used += @([regex]::Matches($code, "FindName\(\s*'(\w+)'\s*\)") | ForEach-Object { $_.Groups[1].Value })
        $used = @($used | Sort-Object -Unique)
        $used.Count | Should -BeGreaterThan 0 -Because 'the app looks up controls by name'
        $names = @()
        foreach ($x in (Get-AllXaml).Values) { $names += Get-XamlNames -Xml ([xml]$x) }
        $missing = @($used | Where-Object { $names -notcontains $_ })
        $missing | Should -BeNullOrEmpty
    }

    It 'AC3_LoadsInWpf' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $all = Get-AllXaml
        foreach ($k in $all.Keys) {
            $w = [System.Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$all[$k])))
            $w | Should -Not -BeNullOrEmpty -Because "$k must load"
            if ($k -eq 'Get-MainWindowXaml') { $w.Title | Should -Be 'Folder Permission Manager' }
            $w.Close()
        }
    }

    It 'AC4_ThemesSwitch' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $script:Themes.Dark.Keys.Count | Should -BeGreaterThan 0
        @(Compare-Object @($script:Themes.Dark.Keys) @($script:Themes.Light.Keys)).Count | Should -Be 0
        $script:Window = [System.Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml](Get-MainWindowXaml))))
        $script:UI = @{ ThemeToggle = $script:Window.FindName('ThemeToggle') }
        try {
            $b0 = "$($script:Window.Background.Color)"
            { Set-AppTheme Light } | Should -Not -Throw
            $b1 = "$($script:Window.Background.Color)"
            $b1 | Should -Not -Be $b0
            { Set-AppTheme Dark } | Should -Not -Throw
            $b2 = "$($script:Window.Background.Color)"
            $b2 | Should -Not -Be $b1
        }
        finally { $script:Window.Close() }
    }

    It 'AC4b_SelectionContrast' {
        # Pinned so a palette edit has to come back through this test.
        $script:Themes.Dark.SelBg | Should -Be '#3276AB'
        $script:Themes.Dark.SelText | Should -Be '#FFFFFF'
        $script:Themes.Dark.SelBar | Should -Be '#BFE3FA'
        $script:Themes.Dark.FocusRing | Should -Be '#FFFFFF'
        $script:Themes.Dark.AccentBtn | Should -Be '#2A7AB0'
        $script:Themes.Light.SelBg | Should -Be '#1F6FA8'
        $script:Themes.Light.SelText | Should -Be '#FFFFFF'
        $script:Themes.Light.SelBar | Should -Be '#05080C'
        $script:Themes.Light.FocusRing | Should -Be '#0F1318'
        foreach ($name in 'Dark', 'Light') {
            $t = $script:Themes[$name]
            # Rows are transparent on the Card background (and CardHover under the mouse).
            (Get-ContrastRatio $t.SelBg $t.Card) | Should -BeGreaterOrEqual 3 -Because "$name selection fill vs the row"
            (Get-ContrastRatio $t.SelBg $t.CardHover) | Should -BeGreaterOrEqual 3 -Because "$name selection fill vs a hovered row"
            (Get-ContrastRatio $t.SelBg $t.Input) | Should -BeGreaterOrEqual 3 -Because "$name tree selection vs the tree background"
            (Get-ContrastRatio $t.SelText $t.SelBg) | Should -BeGreaterOrEqual 4.5 -Because "$name text on a selected row"
            (Get-ContrastRatio $t.SelBar $t.SelBg) | Should -BeGreaterOrEqual 3 -Because "$name selection bar vs the fill"
            (Get-ContrastRatio $t.OnAccent $t.AccentBtn) | Should -BeGreaterOrEqual 4.5 -Because "$name text on the primary button"
            foreach ($bg in 'Card', 'SelBg', 'AccentBtn', 'BtnBg', 'Input') {
                $t.FocusRing | Should -Not -Be $t[$bg]
                (Get-ContrastRatio $t.FocusRing $t[$bg]) | Should -BeGreaterOrEqual 3 -Because "$name focus ring vs $bg"
            }
        }

        # Both grids: selected rows get the fill, the selected text colour and a 2px bar; a row
        # with keyboard focus gets a FocusRing border; keyboard focus never uses the fill colour.
        $xml = [xml](Get-MainWindowXaml)
        $tpl = @($xml.SelectNodes('//*[local-name()="ControlTemplate"][@TargetType="DataGridRow"]'))
        $tpl.Count | Should -Be 1 -Because 'one shared row template'
        $bar = @($tpl[0].SelectNodes('.//*[local-name()="Rectangle"][@Width="2"]'))
        $bar.Count | Should -Be 1
        $bar[0].Fill | Should -Be '{DynamicResource SelBar}'
        $tplText = $tpl[0].OuterXml
        $tplText | Should -Match 'Property="IsKeyboardFocusWithin" Value="True"><Setter TargetName="\w+" Property="BorderBrush" Value="\{DynamicResource FocusRing\}"'
        foreach ($style in 'AclGrid', 'FileGrid') {
            $s = $xml.SelectSingleNode("//*[local-name()='Style'][@*[local-name()='Key']='$style']")
            $s | Should -Not -BeNullOrEmpty
            $s.OuterXml | Should -Match 'Property="IsSelected" Value="True"><Setter Property="Background" Value="\{DynamicResource SelBg\}" /><Setter Property="Foreground" Value="\{DynamicResource SelText\}" />'
        }
        (Get-MainWindowXaml) | Should -Not -Match 'IsKeyboardFocused" Value="True"><Setter TargetName="\w+" Property="BorderBrush" Value="\{DynamicResource Accent\}"'
    }

    It 'AC4c_TreeSelectionFromTheme' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $xml = [xml](Get-MainWindowXaml)
        $tree = $xml.SelectSingleNode('//*[local-name()="TreeView"]')
        @($tree.SelectNodes('.//*[@Color]')).Count | Should -Be 0 -Because 'tree selection colours come from the theme, not literals'
        $script:Window = [System.Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xml))
        $script:UI = @{ ThemeToggle = $script:Window.FindName('ThemeToggle'); FolderTree = $script:Window.FindName('FolderTree') }
        try {
            foreach ($name in 'Light', 'Dark') {
                Set-AppTheme $name
                $res = $script:UI.FolderTree.Resources
                "$($res[[System.Windows.SystemColors]::HighlightBrushKey].Color)" | Should -Be ('#FF' + $script:Themes[$name].SelBg.TrimStart('#'))
                "$($res[[System.Windows.SystemColors]::HighlightTextBrushKey].Color)" | Should -Be ('#FF' + $script:Themes[$name].SelText.TrimStart('#'))
                "$($res[[System.Windows.SystemColors]::InactiveSelectionHighlightBrushKey].Color)" | Should -Be ('#FF' + $script:Themes[$name].SelBg.TrimStart('#'))
            }
        }
        finally { $script:Window.Close() }
    }

    It 'AC4d_ThemeToggleText' {
        Get-ThemeToggleText -Current Dark | Should -Match 'Switch to light$'
        Get-ThemeToggleText -Current Light | Should -Match 'Switch to dark$'
    }

    It 'AC2b_TabOrderSplittersAndSize' {
        $text = Get-MainWindowXaml
        $xml = [xml]$text
        # Tab order follows the markup: each path box comes before its button.
        $text.IndexOf('x:Name="GoBox"') | Should -BeLessThan $text.IndexOf('x:Name="GoBtn"')
        $text.IndexOf('x:Name="PathText"') | Should -BeLessThan $text.IndexOf('x:Name="RefreshBtn"')
        $text.IndexOf('x:Name="ThemeToggle"') | Should -BeLessThan $text.IndexOf('x:Name="OpenLogFolderBtn"')
        # Splitters are dragged with the mouse; they must not take a Tab stop.
        $splitStyle = $xml.SelectSingleNode('//*[local-name()="Style"][@TargetType="GridSplitter"]')
        $splitStyle.OuterXml | Should -Match 'Property="IsTabStop" Value="False"'
        $xml.Window.MinHeight | Should -Be '560'
    }

    It 'AC20b_FilesGridCheckBoxes' {
        $xml = [xml](Get-MainWindowXaml)
        $grid = $xml.SelectSingleNode('//*[local-name()="DataGrid"][@*[local-name()="Name"]="FilesGrid"]')
        $cols = @($grid.SelectNodes('./*[local-name()="DataGrid.Columns"]/*'))
        $cols[0].LocalName | Should -Be 'DataGridCheckBoxColumn' -Because 'the files grid has a tick box per file, first'
        $binding = $cols[0].GetAttribute('Binding')
        $binding | Should -Match 'IsSelected'
        $binding | Should -Match 'AncestorType=\{x:Type DataGridRow\}'
        $binding | Should -Match 'Mode=TwoWay'
        $binding | Should -Match 'UpdateSourceTrigger=PropertyChanged'
        # The default element style is not clickable; this one is, so a tick adds to the selection.
        $cols[0].OuterXml | Should -Match 'Property="IsHitTestVisible" Value="True"'
        $hint = $xml.SelectSingleNode('//*[local-name()="TextBlock"][@*[local-name()="Name"]="FilesHint"]')
        $hint.Text | Should -Be 'Tick files, or Ctrl-click / Shift-click to select several.'
    }

    It 'AC20c_CheckBoxNameAndBorder' {
        $xml = [xml](Get-MainWindowXaml)
        # Screen readers name each tick box.
        $grid = $xml.SelectSingleNode('//*[local-name()="DataGrid"][@*[local-name()="Name"]="FilesGrid"]')
        $col = $grid.SelectSingleNode('./*[local-name()="DataGrid.Columns"]/*[local-name()="DataGridCheckBoxColumn"]')
        $col.OuterXml | Should -Match 'Property="AutomationProperties.Name" Value="Select file"'
        # The empty box's border uses Muted, which reaches 3:1 against the box and the row.
        $style = $xml.SelectSingleNode('//*[local-name()="Style"][@TargetType="CheckBox"][not(@BasedOn)]')
        $box = $style.SelectSingleNode('.//*[local-name()="Border"][@*[local-name()="Name"]="box"]')
        $box.BorderBrush | Should -Be '{DynamicResource Muted}'
        foreach ($name in 'Dark', 'Light') {
            $t = $script:Themes[$name]
            foreach ($bg in 'Input', 'Card', 'CardHover', 'Panel') {
                (Get-ContrastRatio $t.Muted $t[$bg]) | Should -BeGreaterOrEqual 3 -Because "$name unchecked box border vs $bg"
            }
        }
    }
}

Describe 'Theme setting' {
    It 'AC5_ThemeRemembered' {
        $file = Join-Path $TestDrive 'settings.json'
        Set-SavedTheme -Theme Light -SettingsPath $file
        Get-SavedTheme -SettingsPath $file | Should -Be 'Light'
        Set-SavedTheme -Theme Dark -SettingsPath $file
        Get-SavedTheme -SettingsPath $file | Should -Be 'Dark'
        Get-SavedTheme -SettingsPath (Join-Path $TestDrive 'nope.json') | Should -Be 'Dark'
        $bad = Join-Path $TestDrive 'bad.json'
        Set-Content -LiteralPath $bad -Value '{ this is not json'
        Get-SavedTheme -SettingsPath $bad | Should -Be 'Dark'
    }

    It 'AC5b_ErrorLogCapped' {
        # The tests' own error log is in $TestDrive (isolation), never the real %LOCALAPPDATA%.
        $script:ErrorLogPath | Should -BeLike "$TestDrive*"
        Write-AppError 'first entry'
        (Get-Content -LiteralPath $script:ErrorLogPath -Raw) | Should -Match 'first entry'

        $log = Join-Path $TestDrive 'big-errors.log'
        $lines = foreach ($i in 1..2000) { '2026-10-19 10:00:00  error number {0:D5} with some detail text' -f $i }
        Set-Content -LiteralPath $log -Value $lines -Encoding UTF8
        (Get-Item -LiteralPath $log).Length | Should -BeGreaterThan 20000
        Limit-AppErrorLog -Path $log -MaxBytes 20000
        $after = Get-Item -LiteralPath $log
        $after.Length | Should -BeLessOrEqual 20000
        $kept = @(Get-Content -LiteralPath $log)
        $kept[-1] | Should -Match 'error number 02000'
        $kept[0] | Should -Match '^2026-10-19 10:00:00  error number \d{5} with some detail text$' -Because 'trimmed at a line boundary'

        $small = Join-Path $TestDrive 'small-errors.log'
        Set-Content -LiteralPath $small -Value 'one line' -Encoding UTF8
        Limit-AppErrorLog -Path $small -MaxBytes 20000
        (Get-Content -LiteralPath $small) | Should -Be 'one line'
        { Limit-AppErrorLog -Path (Join-Path $TestDrive 'missing.log') -MaxBytes 100 } | Should -Not -Throw
    }
}

Describe 'Script shape' {
    AfterEach { Set-TestAppPaths }

    It 'AC6_NoNetworkListener' {
        $tokens = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($script:AppPath, [ref]$tokens, [ref]$null)
        $code = (@($tokens | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text }) -join "`n")
        $hits = @('HttpListener', 'TcpListener', 'System.Net.Sockets', 'WebClient', 'Invoke-WebRequest', 'Invoke-RestMethod', 'localhost', 'http://' |
            Where-Object { $code -match [regex]::Escape($_) })
        $hits | Should -BeNullOrEmpty -Because 'the app must not reference any network listener or client'
        $script:AppLoaded | Should -BeTrue -Because 'the app must be the WPF script with a param() block'
        $script:ParamNames | Should -Not -Contain 'Port'
        $script:ParamNames | Should -Not -Contain 'NoBrowserOpen'
    }

    It 'AC7_ScriptHeader' {
        $lines = Get-Content -LiteralPath $script:AppPath -TotalCount 1
        $lines | Should -Be '#Requires -Version 5.1'
        ((Get-Content -LiteralPath $script:AppPath -Raw) -match '(?im)^\s*#Requires\s+-RunAsAdministrator') | Should -BeFalse -Because 'the app asks for elevation itself (UAC relaunch)'
        $script:ParamNames | Should -Contain 'LogFolder'
        $script:ParamNames | Should -Contain 'LoadFunctionsOnly'
        $cb = $script:Ast.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq 'CmdletBinding' }
        $cb | Should -Not -BeNullOrEmpty
        @($cb.NamedArguments | Where-Object ArgumentName -eq 'SupportsShouldProcess').Count | Should -Be 1
        $help = $script:Ast.GetHelpContent()
        $help.Synopsis | Should -Not -BeNullOrEmpty
        $help.Description | Should -Not -BeNullOrEmpty
        foreach ($p in $script:ParamNames) { $help.Parameters.Keys | Should -Contain $p.ToUpper() }
        @($help.Examples).Count | Should -BeGreaterThan 0
        ($help.Notes -match 'REFERENCES') | Should -BeTrue
    }

    It 'AC8_LoadFunctionsOnlyIsInert' {
        Mock Start-Process { }
        Mock Add-Type { }
        $script:BgPool = $null
        $script:InstanceMutex = $null
        $result = & {
            # Sentinel: proves the core is (re)defined by loading the app, not left over from earlier.
            function Add-FolderPermission { 'sentinel' }
            . $script:AppPath -LoadFunctionsOnly
            (Get-Command Add-FolderPermission -CommandType Function).ScriptBlock.ToString()
        }
        ($result -match 'sentinel') | Should -BeFalse -Because 'loading the app must define the core functions'
        Should -Invoke Start-Process -Times 0 -Exactly
        Should -Invoke Add-Type -Times 0 -Exactly
        $script:BgPool | Should -BeNullOrEmpty
        $script:InstanceMutex | Should -BeNullOrEmpty
    }

    It 'AC8b_CloseNeverHangs' {
        $order = [System.Collections.Generic.List[string]]::new()
        $mutex = [PSCustomObject]@{}
        $mutex | Add-Member ScriptMethod ReleaseMutex { $order.Add('mutex-release') }.GetNewClosure()
        $mutex | Add-Member ScriptMethod Dispose { $order.Add('mutex-dispose') }.GetNewClosure()
        $ps = [PSCustomObject]@{}
        $ps | Add-Member ScriptMethod BeginStop { param($a, $b) $order.Add('task-stop') }.GetNewClosure()
        $tasks = @([PSCustomObject]@{ PS = $ps })
        # A pool whose runspace is stuck in I/O: BeginClose returns, but never completes.
        $stuck = New-Object System.Threading.ManualResetEvent $false
        $pool = [PSCustomObject]@{}
        $pool | Add-Member ScriptMethod BeginClose { param($a, $b) $order.Add('pool-beginclose'); [PSCustomObject]@{ AsyncWaitHandle = $stuck } }.GetNewClosure()
        $exits = @{ N = 0 }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = Invoke-AppShutdown -Pool $pool -Mutex $mutex -Tasks $tasks -WaitMilliseconds 50 -ExitAction { $exits.N++ }.GetNewClosure()
        $sw.Stop()
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 5 -Because 'closing must not wait on a stuck runspace'
        $order[0] | Should -Be 'mutex-release' -Because 'the mutex is released first, so the tool can be opened again at once'
        $order.IndexOf('pool-beginclose') | Should -BeGreaterThan $order.IndexOf('mutex-release')
        $order | Should -Contain 'task-stop'
        $r.PoolClosed | Should -BeFalse
        $exits.N | Should -Be 1 -Because 'a stuck pool would keep the process alive, so it exits'

        # A pool that closes in time: exit only when the process was started just for this window.
        $done = New-Object System.Threading.ManualResetEvent $true
        $okPool = [PSCustomObject]@{}
        $okPool | Add-Member ScriptMethod BeginClose { param($a, $b) [PSCustomObject]@{ AsyncWaitHandle = $done } }.GetNewClosure()
        $exits.N = 0
        $r2 = Invoke-AppShutdown -Pool $okPool -Mutex $null -Tasks @() -WaitMilliseconds 50 -ExitAction { $exits.N++ }.GetNewClosure()
        $r2.PoolClosed | Should -BeTrue
        $exits.N | Should -Be 0 -Because "a tech's own console is not closed when nothing is stuck"
        $null = Invoke-AppShutdown -Pool $okPool -Mutex $null -Tasks @() -WaitMilliseconds 50 -ExitWhenDone -ExitAction { $exits.N++ }.GetNewClosure()
        $exits.N | Should -Be 1

        # BeginClose itself failing still ends the process.
        $badPool = [PSCustomObject]@{}
        $badPool | Add-Member ScriptMethod BeginClose { param($a, $b) throw 'broken' }
        $exits.N = 0
        # The closure is made here: inside the Should script block $exits would not be in scope.
        $countExit = { $exits.N++ }.GetNewClosure()
        { Invoke-AppShutdown -Pool $badPool -Mutex $null -Tasks @() -WaitMilliseconds 50 -ExitAction $countExit } | Should -Not -Throw
        $exits.N | Should -Be 1

        # Started by the tool's own relaunch (-File <this script>), or from a tech's console.
        Test-OwnProcess -CommandLineArgs @('powershell.exe', '-NoProfile', '-STA', '-File', '\\fs01\tools\FPM\FolderPermissionManager-GUI.ps1') -ScriptPath 'H:\FPM\FolderPermissionManager-GUI.ps1' | Should -BeTrue
        Test-OwnProcess -CommandLineArgs @('powershell.exe') -ScriptPath 'C:\FPM\FolderPermissionManager-GUI.ps1' | Should -BeFalse

        # The Closing handler asks Test-CanClose before it stops anything (SQ-018 wires changes in).
        Test-CanClose | Should -BeTrue
        $code = Get-Content -LiteralPath $script:AppPath -Raw
        $closing = [regex]::Match($code, '(?s)\$win\.Add_Closing\(\{(.*?)\n\s*\}\)').Groups[1].Value
        $closing | Should -Not -BeNullOrEmpty
        $closing.IndexOf('Test-CanClose') | Should -BeGreaterOrEqual 0
        $closing.IndexOf('Test-CanClose') | Should -BeLessThan $closing.IndexOf('BeginStop')
    }

    It 'AC8c_OwnConsoleAndExitCode' {
        # -NoExit means the tech wants the console afterwards: ending the process would close it.
        Test-OwnProcess -CommandLineArgs @('powershell.exe', '-NoExit', '-File', 'C:\FPM\FolderPermissionManager-GUI.ps1') -ScriptPath 'C:\FPM\FolderPermissionManager-GUI.ps1' | Should -BeFalse
        Test-OwnProcess -CommandLineArgs @('powershell.exe', '-noexit', '-STA', '-File', 'C:\FPM\FolderPermissionManager-GUI.ps1') -ScriptPath 'C:\FPM\FolderPermissionManager-GUI.ps1' | Should -BeFalse
        # A -NoExit after the script path is the script's own argument, not powershell.exe's.
        Test-OwnProcess -CommandLineArgs @('powershell.exe', '-File', 'C:\FPM\FolderPermissionManager-GUI.ps1', '-NoExit') -ScriptPath 'C:\FPM\FolderPermissionManager-GUI.ps1' | Should -BeTrue

        # The exit code reaches the exit action: non-zero after a fatal error.
        $codes = [System.Collections.Generic.List[int]]::new()
        $record = { param($code) $codes.Add($code) }.GetNewClosure()
        $done = New-Object System.Threading.ManualResetEvent $true
        $okPool = [PSCustomObject]@{}
        $okPool | Add-Member ScriptMethod BeginClose { param($a, $b) [PSCustomObject]@{ AsyncWaitHandle = $done } }.GetNewClosure()
        $null = Invoke-AppShutdown -Pool $okPool -Mutex $null -Tasks @() -WaitMilliseconds 50 -ExitWhenDone -ExitCode 1 -ExitAction $record
        $null = Invoke-AppShutdown -Pool $okPool -Mutex $null -Tasks @() -WaitMilliseconds 50 -ExitWhenDone -ExitAction $record
        @($codes) | Should -Be @(1, 0)

        # The main block records the fatal error and the script ends with a non-zero exit code.
        $code = Get-Content -LiteralPath $script:AppPath -Raw
        $main = $code.Substring($code.IndexOf('#region Main'))
        $main | Should -Match '(?s)catch \{.*\$script:FatalError = \$true'
        $main | Should -Match ([regex]::Escape('-ExitCode $exitCode'))
        $main | Should -Match '(?m)^if \(\$script:FatalError\) \{ exit 1 \}'
    }

    It 'AC8d_CoreTopLevelHasNoState' {
        # SQ-018 copies the core's functions into the background pool instead of running the file
        # there. That only loses nothing while the core's top level holds just its param() block,
        # function definitions and the -LoadFunctionsOnly guard: any other top-level statement
        # (a variable, an Add-Type, a module import) would be missing in the pool.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:CorePath, [ref]$null, [ref]$null)
        $ast.ParamBlock | Should -Not -BeNullOrEmpty
        $ast.BeginBlock | Should -BeNullOrEmpty
        $ast.ProcessBlock | Should -BeNullOrEmpty
        $ast.DynamicParamBlock | Should -BeNullOrEmpty
        # Since SQ-014 (D-040) the core also assigns $script: variables at top level (the reparse
        # allowlist, tag constants, message markers). Those are allowed only because the pool
        # copies every one of them (Get-CoreScriptVariableNames); anything else is not.
        $copied = @(Get-CoreScriptVariableNames -CorePath $script:CorePath)
        $other = @($ast.EndBlock.Statements | Where-Object {
            $_ -isnot [System.Management.Automation.Language.FunctionDefinitionAst] -and
            -not ($_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                  $_.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                  $_.Left.VariablePath.IsScript -and
                  $copied -contains ($_.Left.VariablePath.UserPath -replace '^script:', '')) })
        $other.Count | Should -Be 1 -Because 'only the -LoadFunctionsOnly guard and the copied $script: variables may sit beside the functions'
        $other[0].Extent.Text | Should -Match '^if \(\$LoadFunctionsOnly\) \{ return \}$'
        $copied | Should -Contain 'RedirectFreeReparseTags'
    }

    It 'AC8e_PoolSeesTheCoreScriptVariables' {
        # The pool must see the same reparse allowlist the window loaded, or every dedup or
        # OneDrive file would count as a link in a pool-run guard.
        Initialize-BackgroundPool
        try {
            $ps = [System.Management.Automation.PowerShell]::Create()
            $ps.RunspacePool = $script:BgPool
            [void]$ps.AddScript({ [PSCustomObject]@{ Count = @($RedirectFreeReparseTags.Keys).Count; Dfs = $DfsReparseTag; Dedup = $RedirectFreeReparseTags['IO_REPARSE_TAG_DEDUP'] } }.ToString())
            $r = $ps.Invoke() | Select-Object -Last 1
            $ps.Dispose()
            $r.Count | Should -Be @($script:RedirectFreeReparseTags.Keys).Count
            $r.Count | Should -BeGreaterThan 0
            $r.Dfs | Should -Be ([uint32]'0x8000000A')
            $r.Dedup | Should -Be ([uint32]'0x80000013')
        }
        finally { $script:BgPool.Close(); $script:BgPool = $null }
    }
}

Describe 'Startup' {
    It 'AC9_StartupAction' {
        Get-StartupAction -IsSta:$false -IsAdmin:$false | Should -Be 'RelaunchSta'
        Get-StartupAction -IsSta:$false -IsAdmin:$true  | Should -Be 'RelaunchSta'
        Get-StartupAction -IsSta:$true  -IsAdmin:$false | Should -Be 'RelaunchElevated'
        Get-StartupAction -IsSta:$true  -IsAdmin:$true  | Should -Be 'Continue'
    }

    It 'AC10_RelaunchArguments' {
        $script = 'C:\Tools\FPM\FolderPermissionManager-GUI.ps1'
        $a = @(Get-RelaunchArgumentList -ScriptPath $script -LogFolder 'D:\Tickets\1 2' -WhatIfMode -DriveMap @{ H = '\\fs01\home' })
        ($a[0..5] -join '|') | Should -Be ('-NoProfile|-ExecutionPolicy|Bypass|-STA|-File|"' + $script + '"')
        $i = [array]::IndexOf($a, '-LogFolder')
        $i | Should -BeGreaterThan 5
        $a[$i + 1] | Should -Be '"D:\Tickets\1 2"'
        $a | Should -Contain '-WhatIf'
        $j = [array]::IndexOf($a, '-DriveMap')
        $j | Should -BeGreaterThan 5
        $a.Count | Should -BeGreaterThan ($j + 1)

        $bare = @(Get-RelaunchArgumentList -ScriptPath $script)
        ($bare -join '|') | Should -Be ('-NoProfile|-ExecutionPolicy|Bypass|-STA|-File|"' + $script + '"')
    }

    It 'AC10b_RelativeLogFolderIsResolved' {
        # The elevated copy starts in System32, so a relative -LogFolder must be made full first,
        # against the PowerShell location the tech typed it in.
        Push-Location -LiteralPath $TestDrive
        try {
            $expected = Join-Path (Get-Location).ProviderPath 'Tickets\1 2'
            Resolve-LogFolderArgument -LogFolder 'Tickets\1 2' | Should -Be $expected
            Resolve-LogFolderArgument -LogFolder '.\Tickets\1 2' | Should -Be $expected
            $a = @(Get-RelaunchArgumentList -ScriptPath 'C:\Tools\FPM\FolderPermissionManager-GUI.ps1' -LogFolder 'Tickets\1 2')
            $i = [array]::IndexOf($a, '-LogFolder')
            $a[$i + 1] | Should -Be ('"' + $expected + '"')
        }
        finally { Pop-Location }
        Resolve-LogFolderArgument -LogFolder 'D:\Tickets\1 2' | Should -Be 'D:\Tickets\1 2'
        Resolve-LogFolderArgument -LogFolder '' | Should -BeNullOrEmpty
        { Resolve-LogFolderArgument -LogFolder 'D:\Tickets\"x' } | Should -Throw '*cannot contain a double quote*'
        { Get-RelaunchArgumentList -ScriptPath 'C:\a.ps1' -LogFolder 'D:\a"b' } | Should -Throw '*cannot contain a double quote*'
    }

    It 'AC10c_RelaunchFromMappedDrive' {
        # The elevated copy cannot see H:, so the script and log folder go as UNC paths.
        $map = @{ H = '\\fs01\home' }
        $a = @(Get-RelaunchArgumentList -ScriptPath 'H:\Tools\FPM\FolderPermissionManager-GUI.ps1' -LogFolder 'H:\Tickets\1' -DriveMap $map)
        $a[5] | Should -Be '"\\fs01\home\Tools\FPM\FolderPermissionManager-GUI.ps1"'
        $a[[array]::IndexOf($a, '-LogFolder') + 1] | Should -Be '"\\fs01\home\Tickets\1"'
    }

    It 'AC11b_ElevationFailureShowsReason' {
        Mock Show-AppMessage { }
        # 1223 = ERROR_CANCELLED, the user chose No on the UAC prompt: no extra detail.
        Mock Start-Process { throw [System.ComponentModel.Win32Exception]::new(1223) }
        Request-Elevation -ScriptPath 'C:\a.ps1' | Should -BeFalse
        Should -Invoke Show-AppMessage -Times 1 -Exactly -ParameterFilter { $Message -like 'Folder Permission Manager needs to run as administrator*' -and $Message -notmatch 'Windows said' }

        Mock Start-Process { throw [System.InvalidOperationException]::new('outer', [System.ComponentModel.Win32Exception]::new(2, 'The system cannot find the file specified')) }
        Request-Elevation -ScriptPath 'C:\a.ps1' | Should -BeFalse
        Should -Invoke Show-AppMessage -Times 1 -Exactly -ParameterFilter { $Message -like 'Folder Permission Manager needs to run as administrator*' -and $Message -match 'Windows said: The system cannot find the file specified' }

        Mock Start-Process { }
        Request-Elevation -ScriptPath 'C:\a.ps1' -LogFolder 'C:\bad"quote' | Should -BeFalse
        Should -Invoke Start-Process -Times 2 -Exactly -Because 'the first two cases called it; the bad -LogFolder never reaches it'
        Should -Invoke Show-AppMessage -Times 1 -Exactly -ParameterFilter { $Message -like '*cannot contain a double quote*' }
    }

    It 'AC12b_MutexNameUsesFullPath' {
        $a = Get-InstanceMutexName -LogFolder 'C:\Tools\FPM\Logs'
        Get-InstanceMutexName -LogFolder 'C:\Tools\FPM\Logs\' | Should -Be $a
        Get-InstanceMutexName -LogFolder 'C:\Tools\FPM\Other\..\Logs' | Should -Be $a
        Get-InstanceMutexName -LogFolder 'C:/Tools/FPM/Logs' | Should -Be $a
    }

    It 'AC13b_DriveMapValidation' {
        # A share name with a space survives every step.
        $good = @{ H = '\\fs01\Home Drives'; S = '\\fs01.contoso.com\Data\Sub Folder' }
        $back = ConvertFrom-DriveMapArgument -Argument (ConvertTo-DriveMapArgument -DriveMap $good)
        $back['H'] | Should -Be '\\fs01\Home Drives'
        $back['S'] | Should -Be '\\fs01.contoso.com\Data\Sub Folder'
        Resolve-MappedDrive -Path 'H:\HR [old]' -DriveMap $good | Should -Be '\\fs01\Home Drives\HR [old]'
        Test-UncSharePath -Path '\\fs01\Home Drives' | Should -BeTrue

        # Anything that is not a real \\server\share is dropped, and the letter stays unresolved.
        $badValues = '\\?\C:\Windows', '\\?\UNC\fs01\x', '\\.\pipe\x', '\\.\C:', '\\fs01', '\\fs01\', '\\\fs01\x',
        '\\fs01\share\..\other', '\\fs01\.\x', '\\fs01\share\.', '\\..\x', 'C:\Data', '//fs01/x', '\\.hidden\x', '',
        # '/' anywhere, and a folder, share or server name that ends in '.' or ' ' (Windows drops
        # those, so the name would point somewhere else than it reads).
        '\\fs01\share/x', '\\fs01/share', '\\fs01\share\sub/..', '\\fs01.\x', '\\fs01 \x', '\\fs01\share.\x',
        '\\fs01\share \x', '\\fs01\share\x.', '\\fs01\share\x '
        foreach ($v in $badValues) {
            Test-UncSharePath -Path $v | Should -BeFalse -Because "'$v' is not a plain \\server\share path"
            $m = @{ X = $v }
            (ConvertFrom-DriveMapArgument -Argument (ConvertTo-DriveMapArgument -DriveMap $m)).Count | Should -Be 0 -Because "'$v' is dropped on the way out"
            $json = ConvertTo-Json -InputObject ([PSCustomObject]@{ X = $v }) -Compress
            $raw = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
            (ConvertFrom-DriveMapArgument -Argument $raw).Count | Should -Be 0 -Because "'$v' is dropped on the way in"
            Resolve-MappedDrive -Path 'X:\Data' -DriveMap $m | Should -Be 'X:\Data' -Because "'$v' is not used to resolve X:"
            (Merge-DriveMap -Primary $m -Secondary @{}).Count | Should -Be 0
        }
    }

    It 'AC13c_MappedDriveTableFromRegistry' {
        # Fallback for drives CIM does not list: HKCU:\Network\<letter>, value RemotePath. Read only.
        Mock Get-CimInstance { throw 'WMI is not available' }
        Mock Get-ChildItem -ParameterFilter { $LiteralPath -eq 'HKCU:\Network' } {
            @([PSCustomObject]@{ PSChildName = 'h' }, [PSCustomObject]@{ PSChildName = 'x' }, [PSCustomObject]@{ PSChildName = 'toolong' })
        }
        Mock Get-ItemProperty -ParameterFilter { $LiteralPath -like 'HKCU:\Network\*' } {
            $letter = Split-Path -Leaf $LiteralPath
            switch ($letter) {
                'h' { [PSCustomObject]@{ RemotePath = '\\fs01\Home Drives' } }
                'x' { [PSCustomObject]@{ RemotePath = '\\?\C:\Windows' } }
                default { [PSCustomObject]@{ RemotePath = '\\fs01\x' } }
            }
        }
        $t = Get-MappedDriveTable
        $t['H'] | Should -Be '\\fs01\Home Drives'
        $t.ContainsKey('X') | Should -BeFalse
        $t.Count | Should -Be 1

        # CIM wins for a letter it knows; bad CIM values are dropped too.
        Mock Get-CimInstance {
            @([PSCustomObject]@{ DeviceID = 'H:'; ProviderName = '\\fs02\home' }, [PSCustomObject]@{ DeviceID = 'Q:'; ProviderName = '\\.\pipe\x' })
        }
        $t2 = Get-MappedDriveTable
        $t2['H'] | Should -Be '\\fs02\home'
        $t2.ContainsKey('Q') | Should -BeFalse

        # No 'net use' text parsing any more (it cut share names at the first space).
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:AppPath, [ref]$null, [ref]$null)
        $netCalls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -match '^net(\.exe)?$' }, $true))
        $netCalls.Count | Should -Be 0
    }

    It 'AC13d_LiveAndPassedOnMappingsBeatRemembered' {
        # Elevated copy: CIM sees no mappings, the registry still remembers H: -> \\fs01\home (stale),
        # and the first window passed on the live H: -> \\fs02\home. The live one must win, or the
        # script path, -LogFolder and browsed paths would point at the old server.
        Mock Get-CimInstance { @() }
        Mock Get-ChildItem -ParameterFilter { $LiteralPath -eq 'HKCU:\Network' } {
            @([PSCustomObject]@{ PSChildName = 'H' }, [PSCustomObject]@{ PSChildName = 'R' })
        }
        Mock Get-ItemProperty -ParameterFilter { $LiteralPath -like 'HKCU:\Network\*' } {
            switch (Split-Path -Leaf $LiteralPath) {
                'H' { [PSCustomObject]@{ RemotePath = '\\fs01\home' } }
                default { [PSCustomObject]@{ RemotePath = '\\fs01\old' } }
            }
        }
        $passed = ConvertTo-DriveMapArgument -DriveMap @{ H = '\\fs02\home' }
        $set = Get-DriveMapSet -DriveMapArgument $passed
        $set.Map['H'] | Should -Be '\\fs02\home'
        $set.Source['H'] | Should -Be 'PassedOn'
        # The registry only fills a letter neither CIM nor the first window has.
        $set.Map['R'] | Should -Be '\\fs01\old'
        $set.Source['R'] | Should -Be 'Remembered'

        $a = @(Get-RelaunchArgumentList -ScriptPath 'H:\Tools\FPM\FolderPermissionManager-GUI.ps1' -LogFolder 'H:\Tickets\1' -DriveMap $set.Map -DriveMapSource $set.Source)
        $a[5] | Should -Be '"\\fs02\home\Tools\FPM\FolderPermissionManager-GUI.ps1"'
        $a[[array]::IndexOf($a, '-LogFolder') + 1] | Should -Be '"\\fs02\home\Tickets\1"'
        Resolve-MappedDrive -Path 'H:\Tickets\1' -DriveMap $set.Map | Should -Be '\\fs02\home\Tickets\1'
        Get-InstanceMutexName -LogFolder 'H:\Tickets\1' -DriveMap $set.Map | Should -Be (Get-InstanceMutexName -LogFolder '\\fs02\home\Tickets\1')
        $h = Get-PathHeaderModel -Path 'H:\Data' -DriveMap $set.Map -DriveMapSource $set.Source
        $h.RealPath | Should -Be '\\fs02\home\Data'
        $h.RealPathNote | Should -BeNullOrEmpty

        # This process's own live mappings beat both.
        Mock Get-CimInstance { @([PSCustomObject]@{ DeviceID = 'H:'; ProviderName = '\\fs03\home' }) }
        $live = Get-DriveMapSet -DriveMapArgument $passed
        $live.Map['H'] | Should -Be '\\fs03\home'
        $live.Source['H'] | Should -Be 'Live'
        (Merge-DriveMap -Primary @{} -Secondary @{ H = '\\fs02\home' } -Remembered @{ H = '\\fs01\home' })['H'] | Should -Be '\\fs02\home'
        (Merge-DriveMap -Primary @{ H = '\\fs03\home' } -Secondary @{ H = '\\fs02\home' } -Remembered @{ H = '\\fs01\home' })['H'] | Should -Be '\\fs03\home'

        # The window builds its map this way, not with the remembered drives first.
        $code = Get-Content -LiteralPath $script:AppPath -Raw
        $startup = $code.Substring($code.IndexOf('if ($LoadFunctionsOnly) { return }'))
        $startup | Should -Match ([regex]::Escape('Get-DriveMapSet -DriveMapArgument $DriveMap'))
        $startup | Should -Not -Match 'Get-MappedDriveTable'
    }

    It 'AC13e_RememberedMappingWhenCimFails' {
        # First (non-elevated) window where CIM fails: the remembered mapping may be used, but it
        # is marked as remembered, and it is not passed on as if it were live.
        Mock Get-CimInstance { throw 'WMI is not available' }
        Mock Get-ChildItem -ParameterFilter { $LiteralPath -eq 'HKCU:\Network' } { @([PSCustomObject]@{ PSChildName = 'H' }) }
        Mock Get-ItemProperty -ParameterFilter { $LiteralPath -like 'HKCU:\Network\*' } { [PSCustomObject]@{ RemotePath = '\\fs01\home' } }
        $set = Get-DriveMapSet -DriveMapArgument ''
        $set.Map['H'] | Should -Be '\\fs01\home'
        $set.Source['H'] | Should -Be 'Remembered'

        $h = Get-PathHeaderModel -Path 'H:\Data\HR' -DriveMap $set.Map -DriveMapSource $set.Source
        $h.Path | Should -Be 'H:\Data\HR'
        $h.RealPath | Should -Be '\\fs01\home\Data\HR'
        $h.RealPathNote | Should -Be '(remembered mapping)'
        (Get-PathHeaderModel -Path 'C:\Data' -DriveMap $set.Map -DriveMapSource $set.Source).RealPathNote | Should -BeNullOrEmpty

        $a = @(Get-RelaunchArgumentList -ScriptPath 'H:\FPM\FolderPermissionManager-GUI.ps1' -DriveMap $set.Map -DriveMapSource $set.Source)
        $a[5] | Should -Be '"\\fs01\home\FPM\FolderPermissionManager-GUI.ps1"' -Because 'the script must still be found'
        $a | Should -Not -Contain '-DriveMap' -Because 'a remembered mapping is not handed on as a live one'

        # The path header shows the note next to the UNC path.
        $code = Get-Content -LiteralPath $script:AppPath -Raw
        $code | Should -Match ([regex]::Escape('$ui.RealPathNote.Text = $header.RealPathNote'))
    }

    It 'AC12c_MutexKeyFollowsMappedDrive' {
        $map = @{ H = '\\fs01\home' }
        Get-InstanceMutexName -LogFolder 'H:\X' -DriveMap $map | Should -Be (Get-InstanceMutexName -LogFolder '\\fs01\home\X')
        Get-InstanceMutexName -LogFolder 'H:\X' | Should -Not -Be (Get-InstanceMutexName -LogFolder '\\fs01\home\X') -Because 'without the map H: stays a letter'
        $code = Get-Content -LiteralPath $script:AppPath -Raw
        $code | Should -Match ([regex]::Escape('Enter-SingleInstance -LogFolder $script:ChangeLogFolder -DriveMap $script:MappedDrives'))

        foreach ($bad in '\\?\C:\Logs', '\\.\C:\Logs', '\\?\UNC\fs01\x', '//?/C:/Logs', '//./C:/Logs') {
            { Resolve-LogFolderArgument -LogFolder $bad } | Should -Throw '*full folder path*' -Because "'$bad' is a device or long-path form"
        }

        $readme = Get-Content -LiteralPath (Join-Path $script:Root 'README.md') -Raw
        $readme | Should -Match '(?s)Known limits.*short name.*(FQDN|fully qualified)'
    }

    It 'AC10d_RelaunchRefusesSessionOnlyDrives' {
        # The elevated copy cannot see a SUBST drive or a drive letter that exists only in this
        # session, so the relaunch is refused with a plain message instead of failing later.
        Mock Get-DriveLetterType {
            switch ($Letter) { 'C' { 'Fixed' } 'E' { 'Removable' } 'S' { 'Fixed' } 'N' { 'Network' } 'H' { 'Network' } default { 'NoRootDirectory' } }
        }
        Mock Get-DosDeviceTarget {
            switch ($Letter) { 'S' { '\??\C:\Work' } default { '\Device\HarddiskVolume3' } }
        }
        $map = @{ H = '\\fs01\home' }
        Get-RelaunchPathProblem -Path 'C:\Tools\FPM\FolderPermissionManager-GUI.ps1' -DriveMap $map | Should -BeNullOrEmpty
        Get-RelaunchPathProblem -Path 'E:\FPM\FolderPermissionManager-GUI.ps1' -DriveMap $map | Should -BeNullOrEmpty
        Get-RelaunchPathProblem -Path 'H:\FPM\FolderPermissionManager-GUI.ps1' -DriveMap $map | Should -BeNullOrEmpty
        Get-RelaunchPathProblem -Path '\\fs01\tools\FPM\FolderPermissionManager-GUI.ps1' -DriveMap $map | Should -BeNullOrEmpty
        foreach ($p in 'S:\FPM\FolderPermissionManager-GUI.ps1', 'N:\FPM\FolderPermissionManager-GUI.ps1', 'Q:\FPM\FolderPermissionManager-GUI.ps1') {
            $text = Get-RelaunchPathProblem -Path $p -DriveMap $map
            $text | Should -Not -BeNullOrEmpty -Because "$p is on a drive the administrator copy cannot see"
            $text | Should -Match ([regex]::Escape($p.Substring(0, 2)))
        }

        Mock Show-AppMessage { }
        Mock Start-Process { }
        Request-Elevation -ScriptPath 'S:\FPM\FolderPermissionManager-GUI.ps1' -DriveMap $map | Should -BeFalse
        Request-Elevation -ScriptPath 'C:\FPM\FolderPermissionManager-GUI.ps1' -LogFolder 'N:\Tickets\1' -DriveMap $map | Should -BeFalse
        Should -Invoke Start-Process -Times 0 -Exactly
        Should -Invoke Show-AppMessage -Times 1 -Exactly -ParameterFilter { $Message -match 'S:' -and $Message -match 'local disk' }
        Should -Invoke Show-AppMessage -Times 1 -Exactly -ParameterFilter { $Message -match 'N:' -and $Message -match '-LogFolder' }
        Request-Elevation -ScriptPath 'C:\FPM\FolderPermissionManager-GUI.ps1' -LogFolder 'H:\Tickets\1' -DriveMap $map | Should -BeTrue
        Should -Invoke Start-Process -Times 1 -Exactly

        $readme = Get-Content -LiteralPath (Join-Path $script:Root 'README.md') -Raw
        $readme | Should -Match '(?s)Known limits.*SUBST'
    }

    It 'AC11_ElevationDeclined' {
        Mock Start-Process { throw 'The operation was canceled by the user.' }
        Mock Show-AppMessage { }
        $r = Request-Elevation -ScriptPath 'C:\Tools\FPM\FolderPermissionManager-GUI.ps1' -LogFolder 'C:\L' -DriveMap @{}
        $r | Should -BeFalse
        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter { $Verb -eq 'RunAs' }
        Should -Invoke Show-AppMessage -Times 1 -Exactly -ParameterFilter { $Message -like 'Folder Permission Manager needs to run as administrator*' }
    }

    It 'AC12_SingleInstance' {
        $a = Get-InstanceMutexName -LogFolder 'C:\Tools\FPM\Logs'
        $b = Get-InstanceMutexName -LogFolder 'c:\tools\fpm\logs'
        $a | Should -Match '^Global\\FolderPermissionManagerGUI_[0-9A-Fa-f]{16}$'
        $b | Should -Be $a
        (Get-InstanceMutexName -LogFolder 'C:\Tools\FPM\Other') | Should -Not -Be $a

        Mock Show-AppMessage { }
        $folder = Join-Path $TestDrive ('log-' + [guid]::NewGuid().ToString('N'))
        $held = New-Object System.Threading.Mutex($true, (Get-InstanceMutexName -LogFolder $folder))
        try {
            Enter-SingleInstance -LogFolder $folder | Should -BeFalse
            Should -Invoke Show-AppMessage -Times 1 -Exactly -ParameterFilter {
                $Message -eq 'Folder Permission Manager is already open (possibly in another session on this computer). Use that window, or close it first.'
            }
        }
        finally { $held.Dispose() }
    }

    It 'AC13_MappedDrives' {
        $map = @{ H = '\\fs01\home' }
        Resolve-MappedDrive -Path 'H:\Data\HR [old]' -DriveMap $map | Should -Be '\\fs01\home\Data\HR [old]'
        Resolve-MappedDrive -Path 'H:' -DriveMap $map | Should -Be '\\fs01\home'
        Resolve-MappedDrive -Path 'C:\Data' -DriveMap $map | Should -Be 'C:\Data'
        Resolve-MappedDrive -Path '\\fs02\x' -DriveMap $map | Should -Be '\\fs02\x'

        $a = @(Get-RelaunchArgumentList -ScriptPath 'C:\a.ps1' -DriveMap $map)
        $j = [array]::IndexOf($a, '-DriveMap')
        $j | Should -BeGreaterThan 0
        $value = ([string]$a[$j + 1]).Trim('"')
        $back = ConvertFrom-DriveMapArgument -Argument $value
        $back['H'] | Should -Be '\\fs01\home'
        $back.Count | Should -Be 1
        $direct = ConvertFrom-DriveMapArgument -Argument (ConvertTo-DriveMapArgument -DriveMap $map)
        $direct['H'] | Should -Be '\\fs01\home'
    }
}

Describe 'Browsing' {
    It 'AC14_DriveList' {
        Mock Get-PSDrive {
            @(
                [PSCustomObject]@{ Name = 'C'; Root = 'C:\'; Description = 'Windows'; Used = 1GB; Free = 1GB }
                [PSCustomObject]@{ Name = 'D'; Root = 'D:\'; Description = $null; Used = 1GB; Free = 1GB }
            )
        }
        $rows = @(Get-DriveListModel -DriveMap @{ H = '\\fs01\home' })
        $c = @($rows | Where-Object Label -eq "C:\ $($script:Dash) Windows")
        $d = @($rows | Where-Object Label -eq 'D:\')
        $h = @($rows | Where-Object Label -eq 'H: (\\fs01\home)')
        $c.Count | Should -Be 1
        $d.Count | Should -Be 1
        $h.Count | Should -Be 1
        $h[0].IsMapped | Should -BeTrue
        $c[0].IsMapped | Should -BeFalse
        $d[0].IsMapped | Should -BeFalse
    }

    It 'AC15_RealPoolRuns' {
        $dir = Join-Path $TestDrive 'pool'
        New-Item -ItemType Directory -Path (Join-Path $dir 'one'), (Join-Path $dir 'two') -Force | Out-Null
        Initialize-BackgroundPool
        $script:BgPool | Should -Not -BeNullOrEmpty
        $state = @{ Result = $null }
        Start-BgTask -Work $script:ListChildrenWork -ArgumentList @($dir, $script:CorePath) -OnDone { param($r, $s) $s.Result = $r } -State $state
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        while ($null -eq $state.Result -and [DateTime]::UtcNow -lt $deadline) {
            Update-BgTasks
            Start-Sleep -Milliseconds 100
        }
        $state.Result | Should -Not -BeNullOrEmpty -Because 'the completion callback must run within 10 s'
        $state.Result.Ok | Should -BeTrue
        @($state.Result.Children).Count | Should -Be 2
    }

    It 'AC15b_ReadTaskThatCannotStart' {
        # The pool refusing a task must not leave the busy line or a pane on "Loading...".
        Mock Start-BgTask { throw 'The runspace pool is closed.' }
        $script:BusyEntries = [ordered]@{}
        $state = @{ Result = $null; State = $null }
        $t = Start-ReadTask -Action 'Opening folder' -Path 'C:\Data' -Work { 'unused' } -State 'pane-state' -OnDone { param($r, $s) $state.Result = $r; $state.State = $s }.GetNewClosure()
        $t | Should -BeNullOrEmpty
        $script:BusyEntries.Count | Should -Be 0
        $state.Result.Ok | Should -BeFalse
        $state.Result.Error | Should -Match 'The runspace pool is closed\.'
        $state.State | Should -Be 'pane-state'
    }

    It 'AC15c_CallbackThatThrows' {
        # A callback that throws: the status line shows the error, and the same callback gets a
        # failed result so its pane shows its Failed state instead of staying on "Loading...".
        $script:Captured = $null
        Mock Start-BgTask { $script:Captured = @{ OnDone = $OnDone; State = $State }; [PSCustomObject]@{ Id = 1 } }
        Mock Set-Status { }
        $script:BusyEntries = [ordered]@{}
        $calls = [System.Collections.Generic.List[object]]::new()
        $null = Start-ReadTask -Action 'Loading the permissions of' -Path 'C:\Data' -Work { 'unused' } -State 'pane' -OnDone {
            param($r, $s)
            $calls.Add($r)
            if ($r.Ok) { throw 'the grid could not be filled' }
        }.GetNewClosure()
        $script:BusyEntries.Count | Should -Be 1
        & $script:Captured.OnDone ([PSCustomObject]@{ Ok = $true; Path = 'C:\Data' }) $script:Captured.State
        $script:BusyEntries.Count | Should -Be 0
        $calls.Count | Should -Be 2
        $calls[1].Ok | Should -BeFalse
        $calls[1].Error | Should -Match 'the grid could not be filled'
        Should -Invoke Set-Status -Times 1 -Exactly -ParameterFilter { $Kind -eq 'Error' -and $Text -match 'the grid could not be filled' }
    }

    It 'AC15d_TaskResultIsTheOkObject' {
        # Stray output from a work block must not be taken for its result.
        $ok = [PSCustomObject]@{ Ok = $true; Children = @() }
        (Select-TaskResult -Output @('noise', $ok, 'trailing text')) | Should -Be $ok
        (Select-TaskResult -Output @('a', 'b')) | Should -Be 'b'
        (Select-TaskResult -Output @()) | Should -BeNullOrEmpty
        (Select-TaskResult -Output $null) | Should -BeNullOrEmpty
    }

    It 'AC15e_CoreLoadedOncePerPool' {
        # The core's functions are part of the pool's session state; work blocks only fall back
        # to dot-sourcing when a runspace does not have them.
        $names = @(Get-CoreFunctionNames -CorePath $script:CorePath)
        $names | Should -Contain 'Get-ItemOwner'
        $names | Should -Contain 'ConvertTo-CsvSafeText'
        foreach ($w in 'DrivesWork', 'ListChildrenWork', 'FolderAclWork', 'FilesWork', 'FileAclWork', 'ExportWork') {
            $text = (Get-Variable -Name $w -Scope Script -ValueOnly).ToString()
            $text | Should -Match 'Get-Command\s+-Name\s+Get-ItemOwner' -Because "$w loads the core only when it is missing"
        }
    }

    It 'AC16_ListChildren' {
        $one = Join-Path $TestDrive 'onechild'
        New-Item -ItemType Directory -Path (Join-Path $one 'only') -Force | Out-Null
        $r = & $script:ListChildrenWork $one $null
        $r.Ok | Should -BeTrue
        $r.Children -is [array] | Should -BeTrue -Because 'a single child must still be a list (regression b900061)'
        $r.Children.Count | Should -Be 1

        $br = Join-Path $TestDrive 'brackets'
        $old = Join-Path $br 'HR [old]'
        $o = Join-Path $br 'HR o'
        New-Item -ItemType Directory -Path $old, $o -Force | Out-Null
        $r2 = & $script:ListChildrenWork $br $null
        $r2.Ok | Should -BeTrue
        $paths = @($r2.Children | ForEach-Object Path)
        $paths.Count | Should -Be 2
        $paths | Should -Contain $old
        $paths | Should -Contain $o
    }

    It 'AC17_AccessDenied' {
        $dir = Join-Path $TestDrive 'locked'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Mock Get-ChildItem { throw [System.UnauthorizedAccessException]::new('Access to the path is denied.') }

        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Mock Get-ItemOwner { [PSCustomObject]@{ Owner = $me; OwnerSid = 'S-1-5-21-1' } }
        $mine = & $script:ListChildrenWork $dir $null
        $mine.Ok | Should -BeFalse
        $mine.Error | Should -Be "You own '$dir' but have no permission to open it. Use Add Permission to give yourself access."

        Mock Get-ItemOwner { [PSCustomObject]@{ Owner = 'BUILTIN\Administrators'; OwnerSid = 'S-1-5-32-544' } }
        $admin = & $script:ListChildrenWork $dir $null
        $admin.Error | Should -Be "You own '$dir' but have no permission to open it. Use Add Permission to give yourself access."

        Mock Get-ItemOwner { [PSCustomObject]@{ Owner = 'CONTOSO\someone-else'; OwnerSid = 'S-1-5-21-2' } }
        $other = & $script:ListChildrenWork $dir $null
        $other.Ok | Should -BeFalse
        $other.Error | Should -Be "Access denied to '$dir'. Take ownership (this folder only) first, then use Add Permission to give yourself access."
    }

    It 'AC18_StaleResultsIgnored' {
        $r1 = New-PaneRequest -Pane 'FolderPermissions'
        $r2 = New-PaneRequest -Pane 'FolderPermissions'
        $r2 | Should -Not -Be $r1
        $resB = [PSCustomObject]@{ Ok = $true; Path = 'C:\B'; Owner = 'BUILTIN\Administrators'; AreAccessRulesProtected = $false
            Rows = @([PSCustomObject]@{ Identity = 'BUILTIN\Users'; PermissionLevel = 'Read'; Type = 'Allow'; IsInherited = $false }) }
        $resA = [PSCustomObject]@{ Ok = $true; Path = 'C:\A'; Owner = 'NT AUTHORITY\SYSTEM'; AreAccessRulesProtected = $false
            Rows = @([PSCustomObject]@{ Identity = 'Everyone'; PermissionLevel = 'Modify'; Type = 'Deny'; IsInherited = $false }) }
        Set-FolderPermissionsResult -Result $resB -Request $r2 | Should -BeTrue
        Set-FolderPermissionsResult -Result $resA -Request $r1 | Should -BeFalse
        Test-CurrentRequest -Pane 'FolderPermissions' -Request $r1 | Should -BeFalse
        Test-CurrentRequest -Pane 'FolderPermissions' -Request $r2 | Should -BeTrue
        $v = $script:ViewState.FolderPermissions
        $v.Path | Should -Be 'C:\B'
        $v.Owner | Should -Be 'BUILTIN\Administrators'
        @($v.Rows).Count | Should -Be 1
        @($v.Rows)[0].Identity | Should -Be 'BUILTIN\Users'
    }
}

Describe 'Viewing' {
    It 'AC19_AclRows' {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetSecurityDescriptorSddlForm('O:BAG:SYD:(A;;FA;;;BU)(D;;0x1200a9;;;WD)(A;ID;0x1200a9;;;SY)')
        $m = ConvertTo-AclViewModel -Acl $acl
        $m.Owner | Should -Be 'BUILTIN\Administrators'
        $m.AreAccessRulesProtected | Should -Be $acl.AreAccessRulesProtected
        $rows = @($m.Rows)
        $rows.Count | Should -Be 3
        $rows[0].Identity | Should -Be 'BUILTIN\Users'
        $rows[0].Type | Should -Be 'Allow'
        $rows[0].PermissionLevel | Should -Be 'Full control'
        $rows[0].IsInherited | Should -BeFalse
        $rows[1].Identity | Should -Be 'Everyone'
        $rows[1].Type | Should -Be 'Deny'
        $rows[1].IsInherited | Should -BeFalse
        $rows[2].Identity | Should -Be 'NT AUTHORITY\SYSTEM'
        $rows[2].Type | Should -Be 'Allow'
        $rows[2].IsInherited | Should -BeTrue
        foreach ($r in $rows) { $r.PermissionLevel | Should -Not -BeNullOrEmpty }
    }

    It 'AC20_FileRows' {
        $dir = Join-Path $TestDrive 'files'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        foreach ($f in @(@('small.bin', 10), @('mid.bin', 1536), @('big.bin', 2MB))) {
            [System.IO.File]::WriteAllBytes((Join-Path $dir $f[0]), (New-Object byte[] $f[1]))
        }
        $items = @(Get-ChildItem -LiteralPath $dir -File)
        $rows = @(ConvertTo-FileRows -Item $items)
        $rows.Count | Should -Be 3
        ($rows | Where-Object Name -eq 'small.bin').SizeText | Should -Be '10 B'
        ($rows | Where-Object Name -eq 'mid.bin').SizeText | Should -Be '1.5 KB'
        $big = $rows | Where-Object Name -eq 'big.bin'
        $big.SizeText | Should -Be '2 MB'
        $big.Path | Should -Be (Join-Path $dir 'big.bin')
        $big.Modified | Should -Match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$'

        @(ConvertTo-FileRows -Item @()).Count | Should -Be 0
        $empty = Get-PaneState -Pane Files -Phase Loaded -Count 0
        $empty.State | Should -Be 'Empty'
        $empty.Text | Should -Be 'No files in this folder'
    }

    It 'AC21_FileAclDiff' {
        $row = { param($id, $lvl) [PSCustomObject]@{ Identity = $id; PermissionLevel = $lvl; Type = 'Allow'; IsInherited = $false } }
        $same1 = [PSCustomObject]@{ Path = 'C:\a.txt'; Rows = @((& $row 'BUILTIN\Users' 'Read'), (& $row 'Everyone' 'Modify')) }
        $same2 = [PSCustomObject]@{ Path = 'C:\b.txt'; Rows = @((& $row 'Everyone' 'Modify'), (& $row 'BUILTIN\Users' 'Read')) }
        $diff  = [PSCustomObject]@{ Path = 'C:\c.txt'; Rows = @((& $row 'BUILTIN\Users' 'Full control')) }
        Test-FileAclDiffers -Model @() | Should -BeFalse
        Test-FileAclDiffers -Model @($same1) | Should -BeFalse
        Test-FileAclDiffers -Model @($same1, $same2) | Should -BeFalse
        Test-FileAclDiffers -Model @($same1, $same2, $diff) | Should -BeTrue
        Get-FileAclDiffWarning | Should -Be "Selected files have different permissions $($script:Dash) this operation applies uniformly to all"
    }

    It 'AC21c_FailedRetryKeepsLoadedPermissions' {
        # A retry that fails must not replace permissions that were already read for a file.
        $request = New-PaneRequest -Pane 'Files'
        $script:FileAclPending = @{}
        $script:FileAclCache = @{}
        $good = [PSCustomObject]@{ Ok = $true; Path = 'C:\F\a.txt'; Owner = 'BUILTIN\Administrators'; AreAccessRulesProtected = $false
            Rows = @([PSCustomObject]@{ Identity = 'BUILTIN\Users'; PermissionLevel = 'Read'; Type = 'Allow'; IsInherited = $true }); Error = $null }
        Set-FileAclResult -Result ([PSCustomObject]@{ Ok = $true; Items = @($good); Error = $null }) -Request $request -Paths @('C:\F\a.txt') | Should -BeTrue
        $failed = [PSCustomObject]@{ Ok = $false; Items = @(); Error = 'The network path was not found.' }
        Set-FileAclResult -Result $failed -Request $request -Paths @('C:\F\a.txt', 'C:\F\b.txt') | Should -BeTrue
        $script:FileAclCache['C:\F\a.txt'].Ok | Should -BeTrue
        $script:FileAclCache['C:\F\a.txt'].Owner | Should -Be 'BUILTIN\Administrators'
        $script:FileAclCache['C:\F\b.txt'].Ok | Should -BeFalse
        $script:FileAclCache['C:\F\b.txt'].Error | Should -Be 'The network path was not found.'
        # A failed entry can still be replaced by a later failure or success.
        Set-FileAclResult -Result ([PSCustomObject]@{ Ok = $false; Items = @(); Error = 'Second try failed.' }) -Request $request -Paths @('C:\F\b.txt') | Should -BeTrue
        $script:FileAclCache['C:\F\b.txt'].Error | Should -Be 'Second try failed.'
    }

    It 'AC21b_DiffWarningLine' {
        $base = "Selected files have different permissions $($script:Dash) this operation applies uniformly to all"
        Get-FileAclDiffWarningText -Checked 3 -Selected 3 | Should -Be "Warning: $base"
        Get-FileAclDiffWarningText -Checked 20 -Selected 75 | Should -Be "Warning: $base (checked 20 of 75 selected files)"
    }

    It 'AC22_PathHeader' {
        $map = @{ H = '\\fs01\home' }
        $m = Get-PathHeaderModel -Path 'H:\Data\HR' -DriveMap $map
        $m.Path | Should -Be 'H:\Data\HR'
        $m.RealPath | Should -Be '\\fs01\home\Data\HR'
        $u = Get-PathHeaderModel -Path '\\fs01\Data\HR' -DriveMap $map
        $u.Path | Should -Be '\\fs01\Data\HR'
        $u.RealPath | Should -BeNullOrEmpty -Because 'a UNC path is shown once'
        $long = 'C:\' + ('LongFolderName\' * 20) + 'End'
        (Get-PathHeaderModel -Path $long -DriveMap $map).Path | Should -Be $long
    }
}

Describe 'Export' {
    It 'AC23_ExportCsv' {
        $root = Join-Path $TestDrive 'exp'
        New-Item -ItemType Directory -Path (Join-Path $root 'a'), (Join-Path $root 'b') -Force | Out-Null
        $out = Join-Path $TestDrive 'out.csv'
        Mock Get-Acl {
            if ("$LiteralPath" -like '*\b') { throw '=boom' }
            & $script:RealGetAcl @PSBoundParameters
        }
        $r = & $script:ExportWork $root $out $null
        $r.Ok | Should -BeTrue
        $r.OutputPath | Should -Be $out
        (Get-Content -LiteralPath $out -TotalCount 1) | Should -Be '"Path","Owner","Identity","Rights","AccessType","IsInherited","InheritanceFlags"'
        $rows = @(Import-Csv -LiteralPath $out -Encoding UTF8)
        $r.RowCount | Should -Be $rows.Count
        $err = @($rows | Where-Object { $_.Path -eq (Join-Path $root 'b') })
        $err.Count | Should -Be 1
        $err[0].Owner | Should -Be 'ERROR'
        $err[0].InheritanceFlags | Should -Be "'=boom" -Because 'cells go through ConvertTo-CsvSafeText'
        @($rows | Where-Object { $_.Path -eq $root -and $_.Owner -ne 'ERROR' }).Count | Should -BeGreaterThan 0

        Get-DefaultExportFileName -Path '\\fs01\Data\HR' | Should -Match '^Permissions-__fs01_Data_HR_\d{4}-\d{2}-\d{2}_\d{6}\.csv$'
    }

    It 'AC23f_ExportFormulaGuardEveryColumn' {
        # Folder names, owners, accounts and the other columns can all start with a character
        # Excel runs as a formula; every such cell must come out with a leading quote.
        $root = Join-Path $TestDrive 'exp-formula'
        $names = '=1+1', '@x', '-x', '+x'
        foreach ($n in $names) { New-Item -ItemType Directory -Path (Join-Path $root $n) -Force | Out-Null }
        Mock Get-Acl {
            $acl = [PSCustomObject]@{}
            $acl | Add-Member ScriptMethod GetOwner { param($type) [PSCustomObject]@{ Value = '=HYPERLINK("http://x")' } }
            $acl | Add-Member ScriptMethod GetAccessRules {
                param($explicit, $inherited, $type)
                @([PSCustomObject]@{
                        IdentityReference = [PSCustomObject]@{ Value = '@SUM(A1)' }
                        FileSystemRights  = '+Modify'
                        AccessControlType = '-Allow'
                        IsInherited       = '=TRUE'
                        InheritanceFlags  = '@ContainerInherit'
                    })
            }
            $acl
        }
        $out = Join-Path $TestDrive 'formula.csv'
        $r = & $script:ExportWork $root $out $null
        $r.Ok | Should -BeTrue
        $rows = @(Import-Csv -LiteralPath $out -Encoding UTF8)
        $rows.Count | Should -Be ($names.Count + 1)
        foreach ($n in $names) {
            @($rows | Where-Object { $_.Path -eq (Join-Path $root $n) }).Count | Should -Be 1 -Because "the folder '$n' is in the report"
        }
        $columns = 'Path', 'Owner', 'Identity', 'Rights', 'AccessType', 'IsInherited', 'InheritanceFlags'
        foreach ($row in $rows) {
            foreach ($c in $columns) {
                "$($row.$c)" | Should -Not -Match '^[=+\-@\t\r]' -Because "column $c must never start with a formula character"
            }
            $row.Owner | Should -Be "'=HYPERLINK(`"http://x`")"
            $row.Identity | Should -Be "'@SUM(A1)"
            $row.Rights | Should -Be "'+Modify"
            $row.AccessType | Should -Be "'-Allow"
            $row.IsInherited | Should -Be "'=TRUE"
            $row.InheritanceFlags | Should -Be "'@ContainerInherit"
        }
        # A full folder path starts with its drive letter, so the Path column is checked by the
        # loop above; the leaf names keep their characters unchanged inside it.
        @($rows | Where-Object { $_.Path -like '*\=1+1' }).Count | Should -Be 1
    }

    It 'AC23h_OneDriveSyncRootRegistryRead' {
        Mock Get-ChildItem -ParameterFilter { $LiteralPath -eq 'HKCU:\Software\SyncEngines\Providers\OneDrive' } {
            @([PSCustomObject]@{ PSPath = 'HKCU:\Software\SyncEngines\Providers\OneDrive\lib1' }, [PSCustomObject]@{ PSPath = 'HKCU:\Software\SyncEngines\Providers\OneDrive\bad' })
        }
        Mock Get-ChildItem -ParameterFilter { $LiteralPath -eq 'HKCU:\Software\Microsoft\OneDrive\Accounts' } {
            @([PSCustomObject]@{ PSPath = 'HKCU:\Software\Microsoft\OneDrive\Accounts\Business1' }, [PSCustomObject]@{ PSPath = 'HKCU:\Software\Microsoft\OneDrive\Accounts\Personal' })
        }
        Mock Get-ItemProperty -ParameterFilter { $LiteralPath -like 'HKCU:\Software\*' } {
            switch -Wildcard ($LiteralPath) {
                '*\lib1' { [PSCustomObject]@{ MountPoint = 'C:\Users\tech\Contoso\HR - Documents' } }
                '*\bad' { [PSCustomObject]@{ MountPoint = 'not a path' } }
                '*\Business1' { [PSCustomObject]@{ UserFolder = 'C:\Users\tech\OneDrive - Contoso' } }
                default { throw 'Property UserFolder does not exist.' }
            }
        }
        $roots = @(Get-OneDriveSyncRoot)
        $roots | Should -Contain 'C:\Users\tech\Contoso\HR - Documents'
        $roots | Should -Contain 'C:\Users\tech\OneDrive - Contoso'
        $roots.Count | Should -Be 2
    }

    Context 'Where the export is saved' {
        BeforeAll {
            $script:SavedOneDrive = @{ OneDrive = $env:OneDrive; OneDriveCommercial = $env:OneDriveCommercial; OneDriveConsumer = $env:OneDriveConsumer }
        }
        BeforeEach {
            $env:OneDrive = $null; $env:OneDriveCommercial = $null; $env:OneDriveConsumer = $null
            # DriveInfo stand-in: C: is a local fixed disk, every other letter is not.
            Mock Test-LocalFixedPath { "$Path" -match '^[Cc]:' }
            # This computer's OneDrive sync roots in the registry: none, unless a test says so.
            Mock Get-OneDriveSyncRoot { @() }
        }
        AfterAll {
            $env:OneDrive = $script:SavedOneDrive.OneDrive
            $env:OneDriveCommercial = $script:SavedOneDrive.OneDriveCommercial
            $env:OneDriveConsumer = $script:SavedOneDrive.OneDriveConsumer
        }

        It 'AC23b_ExportLocationInfo' {
            $local = Get-ExportLocationInfo -Path 'C:\Users\tech\Documents\Permissions.csv'
            $local.IsLocal | Should -BeTrue
            $local.Warning | Should -BeNullOrEmpty

            $unc = Get-ExportLocationInfo -Path '\\fs01\Data\Permissions.csv'
            $unc.IsLocal | Should -BeFalse
            $unc.Warning | Should -Match ([regex]::Escape('\\fs01\Data\Permissions.csv'))
            $unc.Warning | Should -Match 'network share'

            $mapped = Get-ExportLocationInfo -Path 'H:\Permissions.csv' -DriveMap @{ H = '\\fs01\home' }
            $mapped.IsLocal | Should -BeFalse
            $mapped.Warning | Should -Match 'mapped'

            $removable = Get-ExportLocationInfo -Path 'E:\Permissions.csv'
            $removable.IsLocal | Should -BeFalse
            $removable.Warning | Should -Match 'network, mapped or removable drive'

            foreach ($var in 'OneDrive', 'OneDriveCommercial', 'OneDriveConsumer') {
                Set-Item -Path "Env:$var" -Value 'C:\Users\tech\OneDrive - Contoso'
                $od = Get-ExportLocationInfo -Path 'C:\Users\tech\OneDrive - Contoso\Documents\Permissions.csv'
                $od.IsLocal | Should -BeFalse -Because "a folder under `$env:$var is synced to the cloud"
                $od.Warning | Should -Match 'OneDrive'
                # Only under it: a sibling folder with the same prefix is still local.
                (Get-ExportLocationInfo -Path 'C:\Users\tech\OneDrive - Contoso2\x.csv').IsLocal | Should -BeTrue
                Set-Item -Path "Env:$var" -Value ''
            }
        }

        It 'AC23c_DefaultExportFolder' {
            Get-DefaultExportFolder -DocumentsPath 'C:\Users\tech\Documents' -LocalAppDataPath 'C:\Users\tech\AppData\Local' |
                Should -Be 'C:\Users\tech\Documents'
            # Folder redirection to a share, or Documents on another disk that is not fixed.
            Get-DefaultExportFolder -DocumentsPath '\\fs01\Redirected$\tech\Documents' -LocalAppDataPath 'C:\Users\tech\AppData\Local' |
                Should -Be 'C:\Users\tech\AppData\Local\FolderPermissionManager\Exports'
            # OneDrive Known Folder Move.
            $env:OneDriveCommercial = 'C:\Users\tech\OneDrive - Contoso'
            Get-DefaultExportFolder -DocumentsPath 'C:\Users\tech\OneDrive - Contoso\Documents' -LocalAppDataPath 'C:\Users\tech\AppData\Local' |
                Should -Be 'C:\Users\tech\AppData\Local\FolderPermissionManager\Exports'
        }

        It 'AC23g_OneDriveSyncRootsAndOtherProfiles' {
            # A synced SharePoint library is not under %OneDrive%; its folder comes from the
            # OneDrive client's registry keys (read only).
            Mock Get-OneDriveSyncRoot { @('C:\Users\tech\Contoso\HR - Documents', 'C:\Users\tech\OneDrive - Contoso') }
            $sp = Get-ExportLocationInfo -Path 'C:\Users\tech\Contoso\HR - Documents\Permissions.csv'
            $sp.IsLocal | Should -BeFalse -Because 'a synced SharePoint library is uploaded to the cloud'
            $sp.Warning | Should -Match ([regex]::Escape('C:\Users\tech\Contoso\HR - Documents'))
            (Get-ExportLocationInfo -Path 'C:\Users\tech\Contoso\Local\x.csv').IsLocal | Should -BeTrue

            # Another user's OneDrive: not in this account's registry or environment, so the
            # backstop flags a folder starting "OneDrive" in any profile.
            $other = Get-ExportLocationInfo -Path 'C:\Users\someone.else\OneDrive - Contoso\Exports\Permissions.csv'
            $other.IsLocal | Should -BeFalse
            $other.Warning | Should -Match 'OneDrive'
            (Get-ExportLocationInfo -Path 'C:\Users\someone.else\OneDrive\x.csv').IsLocal | Should -BeFalse
            (Get-ExportLocationInfo -Path 'C:\Users\someone.else\Documents\x.csv').IsLocal | Should -BeTrue

            # The registry is read for both keys, with Get-ChildItem and Get-ItemProperty only.
            $code = Get-Content -LiteralPath $script:AppPath -Raw
            $code | Should -Match ([regex]::Escape('HKCU:\Software\SyncEngines\Providers\OneDrive'))
            $code | Should -Match ([regex]::Escape('HKCU:\Software\Microsoft\OneDrive\Accounts'))
        }

        It 'AC23d_ExportConfirmWhenNotLocal' {
            Mock Set-Status { }
            Mock Show-AppQuestion { $false }
            Confirm-ExportLocation -Path '\\fs01\Data\Permissions.csv' | Should -BeFalse
            Should -Invoke Set-Status -Times 1 -Exactly -ParameterFilter { $Kind -eq 'Warning' -and $Text -match ([regex]::Escape('\\fs01\Data\Permissions.csv')) }
            Should -Invoke Show-AppQuestion -Times 1 -Exactly -ParameterFilter { $Message -match ([regex]::Escape('\\fs01\Data\Permissions.csv')) }

            Mock Show-AppQuestion { $true }
            Confirm-ExportLocation -Path 'E:\Permissions.csv' | Should -BeTrue
            Should -Invoke Show-AppQuestion -Times 2 -Exactly

            Confirm-ExportLocation -Path 'C:\Users\tech\Documents\Permissions.csv' | Should -BeTrue
            Should -Invoke Show-AppQuestion -Times 2 -Exactly -Because 'a local fixed disk needs no question'
        }
    }

    It 'AC23e_ExportIncludesHiddenFolders' {
        $root = Join-Path $TestDrive 'exp-hidden'
        $hidden = Join-Path $root 'Secret'
        New-Item -ItemType Directory -Path $hidden -Force | Out-Null
        (Get-Item -LiteralPath $hidden -Force).Attributes = 'Directory, Hidden'
        $out = Join-Path $TestDrive 'hidden.csv'
        $r = & $script:ExportWork $root $out $null
        $r.Ok | Should -BeTrue
        @(Import-Csv -LiteralPath $out -Encoding UTF8 | Where-Object { $_.Path -eq $hidden }).Count | Should -BeGreaterThan 0 -Because 'hidden and system subfolders are part of the report'
    }
}

Describe 'Banner and pane states' {
    It 'AC24_LogFolderNotice' {
        $log = '\\fs01\logs'
        $resolved = Resolve-ChangeLogFolder -LogFolder $log -DefaultFolder 'C:\Tools\FPM\Logs'
        $notice = @(Get-ChangeLogFolderNotice -LogFolder $log -ResolvedFolder $resolved -DefaultFolder 'C:\Tools\FPM\Logs')
        $notice.Count | Should -BeGreaterThan 0
        $rows = @(Get-LogFolderBanner -LogFolder $resolved -Notice $notice)
        ($rows | Where-Object { $_.Level -eq 'Info' -and $_.Text -eq "Changes are backed up and logged to $resolved" }).Count | Should -Be 1
        foreach ($n in $notice) {
            @($rows | Where-Object { $_.Level -eq 'Warning' -and $_.Text -eq $n }).Count | Should -Be 1
        }
        @($rows | Where-Object Text -like 'Dry run*').Count | Should -Be 0

        $dry = @(Get-LogFolderBanner -LogFolder $resolved -Notice $notice -WhatIfMode)
        @($dry | Where-Object Text -eq 'Dry run (WhatIf): nothing will be changed.').Count | Should -Be 1
    }

    It 'AC25_PaneStates' {
        foreach ($pane in 'TreeNode', 'FolderPermissions', 'Files', 'FilePermissions') {
            $loading = Get-PaneState -Pane $pane -Phase Loading
            $empty = Get-PaneState -Pane $pane -Phase Loaded -Count 0
            $err = Get-PaneState -Pane $pane -Phase Failed -ErrorText 'Access denied to X.'
            $blankErr = Get-PaneState -Pane $pane -Phase Failed -ErrorText ''
            $loaded = Get-PaneState -Pane $pane -Phase Loaded -Count 3
            $loading.State | Should -Be 'Loading'
            $loading.Text | Should -Be 'Loading...'
            $empty.State | Should -Be 'Empty'
            $empty.Text | Should -Not -BeNullOrEmpty
            $err.State | Should -Be 'Error'
            $err.Text | Should -Be 'Access denied to X.'
            $blankErr.State | Should -Be 'Error'
            $blankErr.Text | Should -Not -BeNullOrEmpty -Because 'an error is never shown blank'
            $loaded.State | Should -Be 'Loaded'
            @($loading.State, $empty.State, $err.State, $loaded.State | Select-Object -Unique).Count | Should -Be 4
        }
        Format-Elapsed -Elapsed ([TimeSpan]::FromSeconds(0)) | Should -Be '0s'
        Format-Elapsed -Elapsed ([TimeSpan]::FromSeconds(65)) | Should -Be '1m 05s'
        $line = Get-BusyLine -Action 'Loading permissions' -Path 'C:\Data\HR' -Elapsed ([TimeSpan]::FromSeconds(65))
        $line | Should -Match 'Loading permissions'
        $line | Should -Match ([regex]::Escape('C:\Data\HR'))
        $line | Should -Match '1m 05s'
        (Get-BusyLine -Action 'Loading' -Path 'C:\x' -Elapsed ([TimeSpan]::Zero)) | Should -Match '\b0s\b'
    }

    It 'AC25b_BusyLineReadsAsASentence' {
        Get-BusyLine -Action 'Opening folder' -Path 'C:\Data\HR' -Elapsed ([TimeSpan]::FromSeconds(3)) | Should -Be 'Opening folder C:\Data\HR... (3s)'
        Get-BusyLine -Action 'Loading the drive list' -Elapsed ([TimeSpan]::FromSeconds(65)) | Should -Be 'Loading the drive list... (1m 05s)'
        # The actions the window passes are full sentence openings, not "<verb> on <path>".
        $code = Get-Content -LiteralPath $script:AppPath -Raw
        $actions = @([regex]::Matches($code, "Start-ReadTask -Action '([^']+)'") | ForEach-Object { $_.Groups[1].Value })
        $actions.Count | Should -BeGreaterThan 3
        $actions | Should -Contain 'Opening folder'
        foreach ($a in $actions) { $a | Should -Not -Match '^(Opening|Loading permissions|Loading files)$' }
    }

    It 'AC25c_StatusLine' {
        Get-StatusText -Text 'Done.' -Kind Success | Should -Be 'Done.'
        Get-StatusText -Text 'Read it.' -Kind Info | Should -Be 'Read it.'
        Get-StatusText -Text 'Check this.' -Kind Warning | Should -Be 'Warning: Check this.'
        Get-StatusText -Text 'It broke.' -Kind Error | Should -Be 'Error: It broke.'
        Get-StatusText -Text 'Warning: already said.' -Kind Warning | Should -Be 'Warning: already said.'

        # The status box is a polite live region, so screen readers announce new messages.
        # LiveSetting exists from .NET Framework 4.7.1; on older frameworks nothing is set.
        Add-Type -AssemblyName PresentationCore, PresentationFramework, WindowsBase
        $set = [System.Collections.Generic.List[object]]::new()
        $fake = [PSCustomObject]@{}
        $fake | Add-Member ScriptMethod SetValue { param($dp, $value) $set.Add(@($dp, $value)) }.GetNewClosure()
        Enable-LiveRegion -Element $fake | Should -BeTrue
        $set.Count | Should -Be 1
        $set[0][0].Name | Should -Be 'LiveSetting'
        "$($set[0][1])" | Should -Be 'Polite'
    }

    It 'AC24b_ReadmeDataHandling' {
        $readme = Get-Content -LiteralPath (Join-Path $script:Root 'README.md') -Raw
        $app = [regex]::Match($readme, '(?s)### FolderPermissionManager-GUI\.ps1 \(Windows app\)(.*?)\n### ').Groups[1].Value
        $app | Should -Not -BeNullOrEmpty
        foreach ($phrase in 'gui-errors.log', 'inherit', 'OneDrive', 'delete the local copy', 'clipboard history', 'RDP', 'probe file', 'hidden and system') {
            $app | Should -Match ([regex]::Escape($phrase)) -Because "the app section covers '$phrase'"
        }
        $code = Get-Content -LiteralPath $script:AppPath -Raw
        $code | Should -Not -Match 'is created with the first change'
    }
}
