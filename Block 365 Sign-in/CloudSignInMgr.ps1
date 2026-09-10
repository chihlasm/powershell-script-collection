<#
.SYNOPSIS
    GUI for blocking and restoring Microsoft 365 cloud sign-in for Active Directory users.
.DESCRIPTION
    Blocks cloud sign-in by writing msDS-cloudExtensionAttribute10 = "BlockCloudSignIn"
    on the user object in Active Directory. The user keeps full access to on-premises
    domain resources.

    IMPORTANT: that attribute is only a marker. Enforcement comes from a custom inbound
    synchronization rule inside Entra Connect - usually running on a DIFFERENT server -
    which flows the marker to cloudFiltered so the user stops syncing to Entra ID.

    Custom sync rules are NOT carried over when Entra Connect is moved to a new server.
    Earlier versions of this tool assumed the rule existed and reported success either
    way, so after a Connect migration it silently stopped blocking anyone. This version
    verifies the rule on the Connect server before it will write anything, and shows a
    status banner naming the server it checked.
.PARAMETER EntraConnectServer
    Entra Connect server to verify against. Omit to auto-discover and cache it.
.PARAMETER Credential
    Optional credential for the connection to the Entra Connect server.
.PARAMETER SearchBase
    Optional AD OU distinguished name to limit which users are listed.
.PARAMETER SkipRuleCheck
    Skip enforcement-rule verification and allow writes regardless. For break-glass use
    when the check itself is the problem; the status banner still reports what it found.
.EXAMPLE
    .\CloudSignInMgr.ps1
    Auto-discover the Entra Connect server and open the manager.
.EXAMPLE
    .\CloudSignInMgr.ps1 -EntraConnectServer AADC02
    Verify against a named Entra Connect server.
.NOTES
    Requires the ActiveDirectory module (RSAT) and rights to modify user attributes.
    Verifying the sync rule additionally requires WinRM access to the Entra Connect
    server and local administrator rights there. If that check cannot run, the tool
    still works and says so - "could not verify" is reported separately from
    "rule is missing", because they need different responses.

    REFERENCES
    - Custom rules and cloudFiltered:
      https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-change-the-configuration
    - Custom rules are not migrated automatically:
      https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-import-export-config
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$EntraConnectServer,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$SearchBase,
    [switch]$SkipRuleCheck
)

# --- Prerequisites ------------------------------------------------------------
# Runtime import rather than #Requires -Modules: the directive blocks execution outright
# on servers where RSAT cmdlets work but the module is not formally registered.
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show(
        "The ActiveDirectory PowerShell module could not be loaded.`r`n`r`n$($_.Exception.Message)`r`n`r`nInstall RSAT or run this on a domain controller.",
        'Missing prerequisite', 'OK', 'Error') | Out-Null
    return
}

. "$PSScriptRoot\Shared-EntraConnect.ps1" -LoadFunctionsOnly

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$settingsPath      = Get-EntraConnectSettingsPath -ScriptRoot $PSScriptRoot
$script:RuleStatus = $null

# --- Theme --------------------------------------------------------------------
$Theme = @{
    Back       = [System.Drawing.ColorTranslator]::FromHtml('#1E1E1E')
    Panel      = [System.Drawing.ColorTranslator]::FromHtml('#252526')
    GridBack   = [System.Drawing.ColorTranslator]::FromHtml('#1E1E1E')
    GridAlt    = [System.Drawing.ColorTranslator]::FromHtml('#232323')
    Text       = [System.Drawing.ColorTranslator]::FromHtml('#E8E8E8')
    Muted      = [System.Drawing.ColorTranslator]::FromHtml('#9A9A9A')
    Accent     = [System.Drawing.ColorTranslator]::FromHtml('#5DADE2')
    Border     = [System.Drawing.ColorTranslator]::FromHtml('#3C3C3C')
    Danger     = [System.Drawing.ColorTranslator]::FromHtml('#C0392B')
}

# --- Main form ----------------------------------------------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text            = 'Cloud Sign-In Manager'
$form.Size            = New-Object System.Drawing.Size(940, 700)
$form.MinimumSize     = New-Object System.Drawing.Size(820, 600)
$form.StartPosition   = 'CenterScreen'
$form.BackColor       = $Theme.Back
$form.ForeColor       = $Theme.Text
$form.Font            = New-Object System.Drawing.Font('Segoe UI', 9)

# --- Status banner ------------------------------------------------------------
# Always visible. The tool's whole failure mode was an invisible dependency, so the
# state of that dependency gets permanent screen real estate rather than a popup.
$bannerPanel = New-Object System.Windows.Forms.Panel
$bannerPanel.Dock      = 'Top'
$bannerPanel.Height    = 92
$bannerPanel.BackColor = $Theme.Panel

$bannerTitle = New-Object System.Windows.Forms.Label
$bannerTitle.Location  = New-Object System.Drawing.Point(14, 10)
$bannerTitle.Size      = New-Object System.Drawing.Size(640, 20)
$bannerTitle.Font      = New-Object System.Drawing.Font('Segoe UI Semibold', 10, [System.Drawing.FontStyle]::Bold)
$bannerTitle.Text      = 'Checking enforcement rule...'
$bannerTitle.Anchor    = 'Top,Left,Right'

# AutoEllipsis so a long reason is truncated with "..." inside the banner instead of
# overflowing under the toolbar. The full text is always available via "How to fix".
$bannerDetail = New-Object System.Windows.Forms.Label
$bannerDetail.Location  = New-Object System.Drawing.Point(14, 32)
$bannerDetail.Size      = New-Object System.Drawing.Size(640, 52)
$bannerDetail.ForeColor = $Theme.Muted
$bannerDetail.AutoEllipsis = $true
$bannerDetail.Anchor    = 'Top,Left,Right'
$bannerDetail.Text      = ''

$bannerButton = New-Object System.Windows.Forms.Button
$bannerButton.Text      = 'How to fix'
$bannerButton.Size      = New-Object System.Drawing.Size(110, 30)
$bannerButton.FlatStyle = 'Flat'
$bannerButton.BackColor = $Theme.Panel
$bannerButton.ForeColor = $Theme.Text
$bannerButton.FlatAppearance.BorderColor = $Theme.Border
$bannerButton.Visible   = $false
$bannerButton.Anchor    = 'Top,Right'

$bannerPanel.Controls.AddRange(@($bannerTitle, $bannerDetail, $bannerButton))

# Keep the labels clear of the button as the window resizes.
$bannerPanel.Add_Resize({
    $bannerButton.Left = $bannerPanel.Width - $bannerButton.Width - 14
    $bannerButton.Top  = 12
    $w = [Math]::Max(200, $bannerPanel.Width - $bannerButton.Width - 44)
    $bannerTitle.Width  = $w
    $bannerDetail.Width = $w
})

# --- Toolbar ------------------------------------------------------------------
$toolbar = New-Object System.Windows.Forms.Panel
$toolbar.Dock      = 'Top'
$toolbar.Height    = 52
$toolbar.BackColor = $Theme.Back

$searchLabel = New-Object System.Windows.Forms.Label
$searchLabel.Text     = 'Find a person'
$searchLabel.Location = New-Object System.Drawing.Point(14, 8)
$searchLabel.Size     = New-Object System.Drawing.Size(100, 16)
$searchLabel.ForeColor = $Theme.Muted

$searchBox = New-Object System.Windows.Forms.TextBox
$searchBox.Location  = New-Object System.Drawing.Point(14, 25)
$searchBox.Size      = New-Object System.Drawing.Size(260, 24)
$searchBox.BackColor = $Theme.Panel
$searchBox.ForeColor = $Theme.Text
$searchBox.BorderStyle = 'FixedSingle'

function New-ToolButton {
    param([string]$Text, [int]$X, [int]$Width = 110)
    $b = New-Object System.Windows.Forms.Button
    $b.Text      = $Text
    $b.Location  = New-Object System.Drawing.Point($X, 24)
    $b.Size      = New-Object System.Drawing.Size($Width, 26)
    $b.FlatStyle = 'Flat'
    $b.BackColor = $Theme.Panel
    $b.ForeColor = $Theme.Text
    $b.FlatAppearance.BorderColor = $Theme.Border
    $b
}

$refreshButton     = New-ToolButton -Text 'Refresh'      -X 288 -Width 90
$selectAllButton   = New-ToolButton -Text 'Select all'   -X 384 -Width 90
$deselectAllButton = New-ToolButton -Text 'Clear'        -X 480 -Width 90

$toolbar.Controls.AddRange(@($searchLabel, $searchBox, $refreshButton, $selectAllButton, $deselectAllButton))

# --- Grid ---------------------------------------------------------------------
$dataGridView = New-Object System.Windows.Forms.DataGridView
$dataGridView.Dock                = 'Fill'
$dataGridView.AutoSizeColumnsMode = 'Fill'
$dataGridView.SelectionMode       = 'FullRowSelect'
$dataGridView.MultiSelect         = $false
$dataGridView.AllowUserToAddRows  = $false
$dataGridView.RowHeadersVisible   = $false
$dataGridView.BackgroundColor     = $Theme.GridBack
$dataGridView.BorderStyle         = 'None'
$dataGridView.EnableHeadersVisualStyles = $false
$dataGridView.GridColor           = $Theme.Border
$dataGridView.ColumnHeadersDefaultCellStyle.BackColor = $Theme.Panel
$dataGridView.ColumnHeadersDefaultCellStyle.ForeColor = $Theme.Text
$dataGridView.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 9, [System.Drawing.FontStyle]::Bold)
$dataGridView.ColumnHeadersHeight = 32
$dataGridView.RowsDefaultCellStyle.BackColor = $Theme.GridBack
$dataGridView.RowsDefaultCellStyle.ForeColor = $Theme.Text
$dataGridView.AlternatingRowsDefaultCellStyle.BackColor = $Theme.GridAlt
$dataGridView.DefaultCellStyle.SelectionBackColor = $Theme.Accent
$dataGridView.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::Black

$checkboxColumn = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$checkboxColumn.Name       = 'Select'
$checkboxColumn.HeaderText = ''
# Fixed narrow width: under AutoSizeColumnsMode=Fill a FillWeight still stretches the
# checkbox column across a wide window, leaving a large empty gutter.
$checkboxColumn.AutoSizeMode = 'None'
$checkboxColumn.Width        = 34
$checkboxColumn.Resizable    = 'False'
$dataGridView.Columns.Add($checkboxColumn) | Out-Null
$dataGridView.Columns.Add('SamAccountName', 'Username')        | Out-Null
$dataGridView.Columns.Add('Name',           'Full name')       | Out-Null
$dataGridView.Columns.Add('Status',         'Cloud sign-in')   | Out-Null
$dataGridView.Columns['SamAccountName'].FillWeight = 24
$dataGridView.Columns['Name'].FillWeight           = 42
$dataGridView.Columns['Status'].FillWeight         = 34

# --- Action bar ---------------------------------------------------------------
$actionBar = New-Object System.Windows.Forms.Panel
$actionBar.Dock      = 'Bottom'
$actionBar.Height    = 60
$actionBar.BackColor = $Theme.Panel

$applyButton = New-Object System.Windows.Forms.Button
$applyButton.Text      = 'Block cloud sign-in'
$applyButton.Location  = New-Object System.Drawing.Point(14, 14)
$applyButton.Size      = New-Object System.Drawing.Size(170, 32)
$applyButton.FlatStyle = 'Flat'
$applyButton.BackColor = $Theme.Danger
$applyButton.ForeColor = [System.Drawing.Color]::White
$applyButton.FlatAppearance.BorderColor = $Theme.Danger

$clearButton = New-Object System.Windows.Forms.Button
$clearButton.Text      = 'Restore cloud sign-in'
$clearButton.Location  = New-Object System.Drawing.Point(194, 14)
$clearButton.Size      = New-Object System.Drawing.Size(170, 32)
$clearButton.FlatStyle = 'Flat'
$clearButton.BackColor = $Theme.Panel
$clearButton.ForeColor = $Theme.Text
$clearButton.FlatAppearance.BorderColor = $Theme.Border

$countLabel = New-Object System.Windows.Forms.Label
$countLabel.Location  = New-Object System.Drawing.Point(380, 22)
$countLabel.Size      = New-Object System.Drawing.Size(120, 18)
$countLabel.ForeColor = $Theme.Muted

# Separate from the row count so a status message and the count cannot overwrite
# each other.
$blockedLabel = New-Object System.Windows.Forms.Label
$blockedLabel.Location  = New-Object System.Drawing.Point(505, 22)
$blockedLabel.Size      = New-Object System.Drawing.Size(400, 18)
$blockedLabel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml('#F2D06B')

$actionBar.Controls.AddRange(@($applyButton, $clearButton, $countLabel, $blockedLabel))

# --- Behavior -----------------------------------------------------------------

function Update-Banner {
    param($Status)

    $look = Get-EntraConnectStatusPresentation -State $Status.State
    $bannerPanel.BackColor = [System.Drawing.ColorTranslator]::FromHtml($look.BannerBack)
    $bannerTitle.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($look.BannerFore)
    $bannerTitle.Text      = $look.Headline

    $serverText = if ($Status.Server) { "Entra Connect server: $($Status.Server)" } else { 'Entra Connect server: not found' }
    $bannerDetail.Text = "$serverText`r`n$($Status.Reason)"
    $bannerDetail.ForeColor = $Theme.Text

    $bannerButton.Visible = [bool]$Status.Remediation
    $bannerButton.Left    = $bannerPanel.Width - 130

    # Writes are disabled only when the rule was positively confirmed broken. An
    # unverifiable check leaves the tool usable - it reports what it could not do.
    $blocked = $Status.ShouldBlock -and -not $SkipRuleCheck
    $applyButton.Enabled = -not $blocked
    $clearButton.Enabled = $true   # restoring access must always be possible

    if ($blocked) {
        $applyButton.BackColor = $Theme.Border
        $blockedLabel.Text     = 'Blocking is disabled until the enforcement rule is fixed.'
    } else {
        $applyButton.BackColor = $Theme.Danger
        $blockedLabel.Text     = ''
    }
}

function Update-RuleStatus {
    $form.Cursor = 'WaitCursor'
    try {
        $script:RuleStatus = Test-EntraConnectRule -RuleKey 'BlockCloudSignIn' `
                                                   -ComputerName $EntraConnectServer `
                                                   -SettingsPath $settingsPath `
                                                   -Credential $Credential
        Update-Banner -Status $script:RuleStatus
    } finally {
        $form.Cursor = 'Default'
    }
}

function Load-ADUsers {
    param([string]$SearchFilter = '')

    $dataGridView.Rows.Clear()
    try {
        # Escape the user's text before it reaches an AD filter string so a name
        # containing a quote cannot break or alter the query.
        $safe = ($SearchFilter -replace "'", "''")
        $filter = if ([string]::IsNullOrWhiteSpace($safe)) {
            "Enabled -eq 'True'"
        } else {
            "Enabled -eq 'True' -and (Name -like '*$safe*' -or SamAccountName -like '*$safe*')"
        }

        $params = @{
            Filter      = $filter
            Properties  = @('SamAccountName', 'Name', 'Enabled', 'msDS-cloudExtensionAttribute10')
            ErrorAction = 'Stop'
        }
        if ($SearchBase) { $params['SearchBase'] = $SearchBase }

        $users = Get-ADUser @params | Sort-Object Name

        foreach ($user in $users) {
            $marked = ($user.'msDS-cloudExtensionAttribute10' -eq 'BlockCloudSignIn')

            # The status column reflects marker AND enforcement together. A marked user
            # on a server with no working rule is NOT blocked, and saying "Blocked"
            # there would repeat the exact deception this rewrite removes.
            $status = if (-not $marked) {
                'Allowed'
            } elseif ($script:RuleStatus -and $script:RuleStatus.CanEnforce) {
                'Blocked'
            } elseif ($script:RuleStatus -and $script:RuleStatus.ShouldBlock) {
                'Marked - NOT enforced'
            } else {
                'Marked - enforcement unverified'
            }

            $dataGridView.Rows.Add($false, $user.SamAccountName, $user.Name, $status) | Out-Null
        }

        # Clear the highlight the grid applies to row 0 after filling: it reads as
        # "this person is selected" when no checkbox is actually ticked.
        $dataGridView.ClearSelection()
        $countLabel.Text = "$($dataGridView.Rows.Count) people"
    } catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Could not load users from Active Directory.`r`n`r`n$($_.Exception.Message)",
            'Error', 'OK', 'Error') | Out-Null
    }
}

function Get-SelectedRows {
    @($dataGridView.Rows | Where-Object { $_.Cells[0].Value -eq $true })
}

function Set-CloudSignIn {
    param(
        [ValidateSet('Block', 'Restore')]
        [string]$Action
    )

    $selected = Get-SelectedRows
    if ($selected.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Select at least one person first.', 'Nothing selected', 'OK', 'Information') | Out-Null
        return
    }

    if ($Action -eq 'Block' -and $script:RuleStatus -and $script:RuleStatus.ShouldBlock -and -not $SkipRuleCheck) {
        [System.Windows.Forms.MessageBox]::Show(
            "Blocking is disabled because the enforcement rule is not working.`r`n`r`n$($script:RuleStatus.Reason)`r`n`r`nSetting the attribute now would look like it worked but would not block anyone.",
            'Cannot block yet', 'OK', 'Warning') | Out-Null
        return
    }

    $verb = if ($Action -eq 'Block') { 'Block cloud sign-in for' } else { 'Restore cloud sign-in for' }
    $names = ($selected | Select-Object -First 8 | ForEach-Object { "  - $($_.Cells[2].Value)" }) -join "`r`n"
    if ($selected.Count -gt 8) { $names += "`r`n  ... and $($selected.Count - 8) more" }

    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "$verb $($selected.Count) person(s)?`r`n`r`n$names",
        'Confirm', 'YesNo', 'Question')
    if ($confirm -ne 'Yes') { return }

    $succeeded = 0
    $failures  = @()
    $form.Cursor = 'WaitCursor'

    # Per-user try/catch so one failure does not abandon the rest of the batch.
    foreach ($row in $selected) {
        $username = $row.Cells[1].Value
        try {
            if ($Action -eq 'Block') {
                Set-ADUser -Identity $username -Replace @{ 'msDS-cloudExtensionAttribute10' = 'BlockCloudSignIn' } -ErrorAction Stop
            } else {
                Set-ADUser -Identity $username -Clear 'msDS-cloudExtensionAttribute10' -ErrorAction Stop
            }
            $succeeded++
        } catch {
            $failures += "$username : $($_.Exception.Message)"
        }
    }
    $form.Cursor = 'Default'

    if ($failures.Count -gt 0) {
        $detail = ($failures | Select-Object -First 10) -join "`r`n"
        [System.Windows.Forms.MessageBox]::Show(
            "Updated $succeeded of $($selected.Count).`r`n`r`nFailed:`r`n$detail",
            'Completed with errors', 'OK', 'Warning') | Out-Null
    } else {
        [System.Windows.Forms.MessageBox]::Show(
            "Updated $succeeded person(s) in Active Directory.`r`n`r`nThe change takes effect in Microsoft 365 after the next Entra Connect sync.",
            'Done', 'OK', 'Information') | Out-Null
    }

    Load-ADUsers -SearchFilter $searchBox.Text

    if ($succeeded -gt 0) { Invoke-SyncPrompt }
}

function Invoke-SyncPrompt {
    if (-not $script:RuleStatus -or -not $script:RuleStatus.Server) {
        [System.Windows.Forms.MessageBox]::Show(
            'Changes are saved in Active Directory but no Entra Connect server is known, so a sync could not be started. The change will apply at the next scheduled sync.',
            'Sync not started', 'OK', 'Information') | Out-Null
        return
    }

    $server = $script:RuleStatus.Server
    $ask = [System.Windows.Forms.MessageBox]::Show(
        "Run an Entra Connect sync on $server now to apply the change?",
        'Run sync', 'YesNo', 'Question')
    if ($ask -ne 'Yes') { return }

    $form.Cursor = 'WaitCursor'
    $result = Invoke-EntraConnectDeltaSync -ComputerName $server -Credential $Credential
    $form.Cursor = 'Default'

    if ($result.Success) {
        [System.Windows.Forms.MessageBox]::Show("Sync started on $server.", 'Sync started', 'OK', 'Information') | Out-Null
    } else {
        # A sync already running is the common, harmless case - name it rather than
        # presenting a bare exception.
        $hint = if ($result.Error -match 'already') { "`r`n`r`nA sync cycle is probably already running. The change will be picked up by it." } else { '' }
        [System.Windows.Forms.MessageBox]::Show(
            "Could not start the sync on $server.`r`n`r`n$($result.Error)$hint",
            'Sync not started', 'OK', 'Warning') | Out-Null
    }
}

# --- Wire up ------------------------------------------------------------------
# Clicking anywhere on a row toggles its checkbox. The checkbox column is deliberately
# narrow, so the whole row is the practical hit target.
$dataGridView.Add_CellClick({
    param($eventSender, $e)
    if ($e.RowIndex -lt 0) { return }
    if ($e.ColumnIndex -eq 0) { return }   # let the checkbox handle its own clicks
    $cell = $dataGridView.Rows[$e.RowIndex].Cells[0]
    $cell.Value = -not [bool]$cell.Value
})

$searchBox.Add_TextChanged({ Load-ADUsers -SearchFilter $searchBox.Text })
$refreshButton.Add_Click({
    $searchBox.Text = ''
    Update-RuleStatus
    Load-ADUsers
})
$selectAllButton.Add_Click({   foreach ($r in $dataGridView.Rows) { $r.Cells[0].Value = $true  } })
$deselectAllButton.Add_Click({ foreach ($r in $dataGridView.Rows) { $r.Cells[0].Value = $false } })
$applyButton.Add_Click({ Set-CloudSignIn -Action 'Block' })
$clearButton.Add_Click({ Set-CloudSignIn -Action 'Restore' })

$bannerButton.Add_Click({
    if ($script:RuleStatus -and $script:RuleStatus.Remediation) {
        [System.Windows.Forms.MessageBox]::Show(
            "$($script:RuleStatus.Reason)`r`n`r`n$($script:RuleStatus.Remediation)",
            'How to fix this', 'OK', 'Information') | Out-Null
    }
})

$form.Controls.Add($dataGridView)
$form.Controls.Add($actionBar)
$form.Controls.Add($toolbar)
$form.Controls.Add($bannerPanel)

$form.Add_Shown({
    Update-RuleStatus
    Load-ADUsers
})

[void]$form.ShowDialog()
$form.Dispose()
