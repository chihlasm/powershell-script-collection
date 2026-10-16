<#
    Tests for the window (Start-M365SyncedUserFixes.ps1) and the .cmd launchers.

    The window's decisions live in small pure functions (status card wording, confirmation
    text, rule-creation result text), tested here directly. The XAML is loaded for real when
    the test runs in a single-threaded apartment (Windows PowerShell 5.1 and pwsh both do by
    default); otherwise those tests are skipped.

    Run:  Invoke-Pester .\M365-SyncedUserFixes\Tests
#>

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:GuiPath = Join-Path $script:Root 'Start-M365SyncedUserFixes.ps1'
    . $script:GuiPath -LoadFunctionsOnly
    $script:IsSta = ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')
    if ($script:IsSta) { Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase }
}

Describe 'Window markup' {
    BeforeAll {
        [xml]$script:Xaml = Get-MainWindowXaml
        # Window-level names only: names inside a ControlTemplate/DataTemplate live in that
        # template's own namescope and may legitimately repeat (Bd, Badge, PART_Track).
        $xpath = '//*[@*[local-name()="Name"]][not(ancestor::*[local-name()="ControlTemplate" or local-name()="DataTemplate"])]'
        $script:Names = @($script:Xaml.SelectNodes($xpath) | ForEach-Object { $_.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml') } | Where-Object { $_ })
    }

    It 'is well-formed XML' {
        $script:Xaml.Window | Should -Not -BeNullOrEmpty
    }
    It 'has no duplicate control names (WPF refuses to load the window otherwise)' {
        $dupes = @($script:Names | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)
        $dupes | Should -BeNullOrEmpty
    }
    It 'defines every control the code looks up' {
        $code = Get-Content -LiteralPath $script:GuiPath -Raw
        $used = @([regex]::Matches($code, '\$script:Ui\.(\w+)') | ForEach-Object { $_.Groups[1].Value })
        foreach ($s in [regex]::Matches($code, 'Get-UiElement "\$\{p\}(\w+)"') | ForEach-Object { $_.Groups[1].Value }) { $used += "Block$s"; $used += "Hide$s" }
        foreach ($s in [regex]::Matches($code, '\$script:Ui\["\$\{p\}(\w+)"\]') | ForEach-Object { $_.Groups[1].Value }) { $used += "Block$s"; $used += "Hide$s" }
        $missing = @($used | Sort-Object -Unique | Where-Object { $script:Names -notcontains $_ })
        $missing | Should -BeNullOrEmpty
    }
    It 'loads in WPF' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
        $w = [System.Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $script:Xaml))
        $w.Title | Should -Be 'Microsoft 365 - Synced User Fixes'
        $w.FindName('BlockGrid') | Should -Not -BeNullOrEmpty
        $w.Close()
    }
    It 'uses the danger style only for blocking, not for hiding' {
        $block = $script:Xaml.SelectSingleNode('//*[@*[local-name()="Name"]="BlockApply"]')
        $hide  = $script:Xaml.SelectSingleNode('//*[@*[local-name()="Name"]="HideApply"]')
        $block.Style | Should -Match 'DangerButton'
        $hide.Style  | Should -Match 'PrimaryButton'
    }
    It 'makes the text columns read-only so a double-click cannot edit a name' {
        $cols = @($script:Xaml.SelectNodes('//*[local-name()="DataGridTextColumn"]'))
        $cols.Count | Should -BeGreaterThan 0
        @($cols | Where-Object { $_.IsReadOnly -ne 'True' }).Count | Should -Be 0
    }
}

Describe 'Theme switching' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
    It 'switches to light and back without the "not a valid value for property Background" error (regression)' {
        # New-Object's output is a PSObject wrapper; storing it as a resource made WPF reject it.
        [xml]$x = Get-MainWindowXaml
        $script:Window = [System.Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $x))
        $script:Ui = @{ ThemeToggle = $script:Window.FindName('ThemeToggle') }
        { Set-UiTheme -Name 'Light' } | Should -Not -Throw
        $script:Window.Background.Color.ToString() | Should -Be '#FFF4F6F9'
        $script:Ui.ThemeToggle.Content | Should -Be 'Dark mode'
        { Set-UiTheme -Name 'Dark' } | Should -Not -Throw
        $script:Window.Background.Color.ToString() | Should -Be '#FF14161B'
        $script:Window.Close()
    }
    It 'has the same colour keys in both themes' {
        @(Compare-Object @($script:Themes.Dark.Keys) @($script:Themes.Light.Keys)).Count | Should -Be 0
    }
}

Describe 'Get-RuleStatusLines (the card at the top)' {
    It 'says blocking is switched off when the rule is confirmed missing' {
        $l = Get-RuleStatusLines -FeatureKey 'BlockSignIn' -Status (New-EntraConnectStatus -State 'Missing' -Server 'AADC01' -Reason 'r')
        $l.Headline | Should -Be 'Sync rule NOT FOUND'
        $l.Warning  | Should -Match 'Blocking is switched off'
        $l.Accent   | Should -Be 'Danger'
        $l.ShowFix  | Should -BeTrue
    }
    It 'says hiding is switched off on the Hide page' {
        (Get-RuleStatusLines -FeatureKey 'HideFromGAL' -Status (New-EntraConnectStatus -State 'Misconfigured' -Reason 'r')).Warning | Should -Match 'Hiding is switched off'
    }
    It 'warns that blocking deletes people when the server''s rule uses cloudFiltered' {
        $l = Get-RuleStatusLines -FeatureKey 'BlockSignIn' -Status (New-EntraConnectStatus -State 'Present' -Reason 'r' -Mechanism 'cloudFiltered')
        $l.Warning | Should -Match 'DELETES'
        $l.Accent  | Should -Be 'Success'
    }
    It 'does not warn for the accountEnabled rule' {
        (Get-RuleStatusLines -FeatureKey 'BlockSignIn' -Status (New-EntraConnectStatus -State 'Present' -Reason 'r' -Mechanism 'accountEnabled')).Warning | Should -BeNullOrEmpty
    }
    It 'shows "could not check" in amber and does not switch anything off' {
        $l = Get-RuleStatusLines -FeatureKey 'BlockSignIn' -Status (New-EntraConnectStatus -State 'Unknown' -Reason 'r')
        $l.Accent  | Should -Be 'Warn'
        $l.Warning | Should -Not -Match 'switched off'
    }
    It 'explains -SkipRuleCheck instead of claiming it is switched off' {
        (Get-RuleStatusLines -FeatureKey 'BlockSignIn' -Status (New-EntraConnectStatus -State 'Missing' -Reason 'r') -SkipRuleCheck $true).Warning | Should -Match 'will NOT take effect'
    }
    It 'passes on extra warnings such as the attribute not being imported' {
        (Get-RuleStatusLines -FeatureKey 'BlockSignIn' -Status (New-EntraConnectStatus -State 'Present' -Reason 'r' -Mechanism 'accountEnabled' -Warnings @('does not import x'))).Warning | Should -Match 'does not import'
    }
    It 'shows a checking message before the first result' {
        (Get-RuleStatusLines -FeatureKey 'BlockSignIn' -Status $null).Headline | Should -Match 'Checking'
    }
}

Describe 'Get-ApplyConfirmation' {
    It 'warns about deletion when the rule uses cloudFiltered' {
        $t = Get-ApplyConfirmation -FeatureKey 'BlockSignIn' -Action 'Apply' -Names @('Jane Doe') -RuleStatus (New-EntraConnectStatus -State 'Present' -Mechanism 'cloudFiltered')
        $t | Should -Match 'DELETES'
        $t | Should -Match 'Block sign-in for 1 person\?'
    }
    It 'says mailbox and licences are kept for the accountEnabled rule, and mentions revoking sessions' {
        $t = Get-ApplyConfirmation -FeatureKey 'BlockSignIn' -Action 'Apply' -Names @('a', 'b') -RuleStatus (New-EntraConnectStatus -State 'Present' -Mechanism 'accountEnabled')
        $t | Should -Match 'Mailbox and licences are kept'
        $t | Should -Match 'revoke their sessions'
        $t | Should -Match 'for 2 people'
    }
    It 'lists at most 10 names' {
        $names = 1..14 | ForEach-Object { "Person $_" }
        $t = Get-ApplyConfirmation -FeatureKey 'HideFromGAL' -Action 'Apply' -Names $names -RuleStatus $null
        $t | Should -Match 'and 4 more'
        $t | Should -Not -Match 'Person 11'
    }
    It 'keeps the undo message plain' {
        $t = Get-ApplyConfirmation -FeatureKey 'HideFromGAL' -Action 'Remove' -Names @('a') -RuleStatus $null
        $t | Should -Match '^Show again for 1 person\?'
        $t | Should -Not -Match 'DELETES'
    }
}

Describe 'Format-RuleCreationResult' {
    BeforeAll { $script:Bp = Get-SyncRuleBlueprint -Key 'BlockCloudSignIn' -Domain 'contoso.local' }

    It 'points to the saved script when Entra Connect refuses a remote request' {
        $t = Format-RuleCreationResult -Result ([PSCustomObject]@{ Success = $false; Stage = 'RemoteBlocked'; Error = 'net.pipe'; Warnings = @(); Removed = @() }) -Blueprint $script:Bp -Server 'AADC01'
        $t | Should -Match "Save as script"
    }
    It 'shows the full-sync steps after creating a rule' {
        $r = [PSCustomObject]@{ Success = $true; Stage = 'Created'; Error = $null; Warnings = @(); Removed = @('old'); Rule = [PSCustomObject]@{ Name = 'n'; Precedence = 60; Connector = 'c' } }
        $t = Format-RuleCreationResult -Result $r -Blueprint $script:Bp -Server 'AADC01'
        $t | Should -Match '\[PASS\] Created'
        $t | Should -Match "Removed the old rule 'old'"
        $t | Should -Match 'Full Synchronization'
    }
    It 'says nothing changed after a preview' {
        $r = [PSCustomObject]@{ Success = $true; Stage = 'Preview'; Error = $null; Warnings = @('Precedence 60 is already used'); Removed = @(); Rule = [PSCustomObject]@{ Name = 'n'; Precedence = 59; Connector = 'c' } }
        $t = Format-RuleCreationResult -Result $r -Blueprint $script:Bp -Server 'AADC01'
        $t | Should -Match 'Nothing has been changed'
        $t | Should -Match '\[WARN\] Precedence 60'
    }
    It 'treats "already exists" as information, not failure' {
        (Format-RuleCreationResult -Result ([PSCustomObject]@{ Success = $false; Stage = 'AlreadyExists'; Error = 'exists'; Warnings = @(); Removed = @() }) -Blueprint $script:Bp -Server 'x') | Should -Match '^\[INFO\]'
    }
}

Describe 'Background tasks' {
    It 'only run commands defined in SyncedUserFixes.Core.ps1, the one file the background runspace loads (regression)' {
        # Get-BothRuleStatuses once lived in the window script, so the real window reported
        # "The term 'Get-BothRuleStatuses' is not recognized" and never checked the rules.
        $gui = Get-Content -LiteralPath $script:GuiPath -Raw
        $commands = @([regex]::Matches($gui, "Start-UiTask -Command '([\w-]+)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $commands.Count | Should -BeGreaterThan 3
        $tokens = $null; $errors = $null
        $coreAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Root 'SyncedUserFixes.Core.ps1'), [ref]$tokens, [ref]$errors)
        $defined = @($coreAst.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object Name)
        @($commands | Where-Object { $defined -notcontains $_ }) | Should -BeNullOrEmpty
    }
}

Describe 'Get-FeatureFromControl' {
    It 'maps a control name prefix to its section' {
        Get-FeatureFromControl ([PSCustomObject]@{ Name = 'BlockSearch' }) | Should -Be 'BlockSignIn'
        Get-FeatureFromControl ([PSCustomObject]@{ Name = 'HideApply' })   | Should -Be 'HideFromGAL'
    }
}

Describe 'Launchers' {
    BeforeAll {
        $script:Launchers = @{
            'Start M365 Synced User Fixes.cmd' = $null
            'Launch-CloudSignInMgr.cmd'        = 'BlockSignIn'
            'Launch-HideFromGAL.cmd'           = 'HideFromGAL'
        }
    }
    It 'each starts the window from its own folder, hidden, in STA, bypassing execution policy' {
        foreach ($name in $script:Launchers.Keys) {
            $text = Get-Content -LiteralPath (Join-Path $script:Root $name) -Raw
            $text | Should -Match 'cd /d "%~dp0"'
            $text | Should -Match 'start "" powershell\.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0Start-M365SyncedUserFixes\.ps1"'
            $text | Should -Match '%\*'
            if ($script:Launchers[$name]) { $text | Should -Match "-Tab $($script:Launchers[$name])" }
        }
    }
    It 'are not VBScript (deprecated; removed from future Windows)' {
        @(Get-ChildItem -LiteralPath $script:Root -Filter '*.vbs').Count | Should -Be 0
    }
    It 'are plain ASCII' {
        foreach ($name in $script:Launchers.Keys) {
            $bytes = [System.IO.File]::ReadAllBytes((Join-Path $script:Root $name))
            @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
        }
    }
}
