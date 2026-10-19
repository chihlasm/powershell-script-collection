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
            $xml = $null
            { $xml = [xml]$all[$k] } | Should -Not -Throw -Because "$k must return well-formed XML"
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
}

Describe 'Script shape' {
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
}
