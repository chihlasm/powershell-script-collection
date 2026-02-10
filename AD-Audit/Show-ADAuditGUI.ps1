<#
.SYNOPSIS
    WinForms GUI launcher for Invoke-ADAudit.ps1.

.DESCRIPTION
    Provides a graphical interface for running AD audits with section
    selection, parameter configuration, and real-time log output.
    Runs the audit in a background runspace to keep the GUI responsive.

.EXAMPLE
    .\Show-ADAuditGUI.ps1
    Launches the AD Audit GUI.

.NOTES
    Author: PowerShell Script Collection
    Version: 2.0
    Requires: ActiveDirectory module (RSAT), Windows PowerShell
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()

#region Form Setup
$form = New-Object System.Windows.Forms.Form
$form.Text = 'AD Audit Tool'
$form.Size = New-Object System.Drawing.Size(620, 720)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedSingle'
$form.MaximizeBox = $false
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$yPos = 15

#--- Parameters Panel ---
$paramGroup = New-Object System.Windows.Forms.GroupBox
$paramGroup.Text = 'Parameters'
$paramGroup.Location = New-Object System.Drawing.Point(10, $yPos)
$paramGroup.Size = New-Object System.Drawing.Size(585, 140)
$form.Controls.Add($paramGroup)

# Output Path
$lblOutput = New-Object System.Windows.Forms.Label
$lblOutput.Text = 'Output Path:'
$lblOutput.Location = New-Object System.Drawing.Point(10, 25)
$lblOutput.AutoSize = $true
$paramGroup.Controls.Add($lblOutput)

$txtOutput = New-Object System.Windows.Forms.TextBox
$txtOutput.Location = New-Object System.Drawing.Point(110, 22)
$txtOutput.Size = New-Object System.Drawing.Size(390, 23)
$txtOutput.Text = $PSScriptRoot
$paramGroup.Controls.Add($txtOutput)

$btnBrowse = New-Object System.Windows.Forms.Button
$btnBrowse.Text = '...'
$btnBrowse.Location = New-Object System.Drawing.Point(505, 21)
$btnBrowse.Size = New-Object System.Drawing.Size(35, 25)
$btnBrowse.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.SelectedPath = $txtOutput.Text
    if ($dlg.ShowDialog() -eq 'OK') { $txtOutput.Text = $dlg.SelectedPath }
})
$paramGroup.Controls.Add($btnBrowse)

# Domain
$lblDomain = New-Object System.Windows.Forms.Label
$lblDomain.Text = 'Domain:'
$lblDomain.Location = New-Object System.Drawing.Point(10, 58)
$lblDomain.AutoSize = $true
$paramGroup.Controls.Add($lblDomain)

$txtDomain = New-Object System.Windows.Forms.TextBox
$txtDomain.Location = New-Object System.Drawing.Point(110, 55)
$txtDomain.Size = New-Object System.Drawing.Size(200, 23)
$txtDomain.Text = ''
$paramGroup.Controls.Add($txtDomain)

# Days Inactive
$lblDays = New-Object System.Windows.Forms.Label
$lblDays.Text = 'Days Inactive:'
$lblDays.Location = New-Object System.Drawing.Point(330, 58)
$lblDays.AutoSize = $true
$paramGroup.Controls.Add($lblDays)

$numDays = New-Object System.Windows.Forms.NumericUpDown
$numDays.Location = New-Object System.Drawing.Point(430, 55)
$numDays.Size = New-Object System.Drawing.Size(70, 23)
$numDays.Minimum = 1
$numDays.Maximum = 365
$numDays.Value = 90
$paramGroup.Controls.Add($numDays)

# Export Format
$lblFormat = New-Object System.Windows.Forms.Label
$lblFormat.Text = 'Export Format:'
$lblFormat.Location = New-Object System.Drawing.Point(10, 92)
$lblFormat.AutoSize = $true
$paramGroup.Controls.Add($lblFormat)

$cboFormat = New-Object System.Windows.Forms.ComboBox
$cboFormat.Location = New-Object System.Drawing.Point(110, 89)
$cboFormat.Size = New-Object System.Drawing.Size(100, 23)
$cboFormat.DropDownStyle = 'DropDownList'
$cboFormat.Items.AddRange(@('Both', 'HTML', 'CSV'))
$cboFormat.SelectedIndex = 0
$paramGroup.Controls.Add($cboFormat)

# Skip Browser Open
$chkSkipBrowser = New-Object System.Windows.Forms.CheckBox
$chkSkipBrowser.Text = 'Skip opening report in browser'
$chkSkipBrowser.Location = New-Object System.Drawing.Point(250, 90)
$chkSkipBrowser.AutoSize = $true
$paramGroup.Controls.Add($chkSkipBrowser)

$yPos += 150

#--- Sections Panel ---
$sectionGroup = New-Object System.Windows.Forms.GroupBox
$sectionGroup.Text = 'Audit Sections'
$sectionGroup.Location = New-Object System.Drawing.Point(10, $yPos)
$sectionGroup.Size = New-Object System.Drawing.Size(585, 175)
$form.Controls.Add($sectionGroup)

$sections = @(
    @{ Name = 'DomainOverview';    Label = 'Domain Overview' }
    @{ Name = 'DomainControllers'; Label = 'Domain Controllers' }
    @{ Name = 'Users';             Label = 'User Accounts' }
    @{ Name = 'Groups';            Label = 'Group Analysis' }
    @{ Name = 'Computers';         Label = 'Computer Accounts' }
    @{ Name = 'PasswordPolicy';    Label = 'Password Policy' }
    @{ Name = 'PrivilegedAccess';  Label = 'Privileged Access' }
    @{ Name = 'Security';          Label = 'Security Findings' }
    @{ Name = 'Infrastructure';    Label = 'Infrastructure Health' }
    @{ Name = 'OUStructure';       Label = 'OU Structure' }
)

$sectionCheckboxes = @{}
$col = 0; $row = 0
foreach ($s in $sections) {
    $chk = New-Object System.Windows.Forms.CheckBox
    $chk.Text = $s.Label
    $chk.Tag = $s.Name
    $chk.Checked = $true
    $chk.AutoSize = $true
    $chk.Location = New-Object System.Drawing.Point((15 + $col * 195), (25 + $row * 25))
    $sectionGroup.Controls.Add($chk)
    $sectionCheckboxes[$s.Name] = $chk
    $col++
    if ($col -ge 3) { $col = 0; $row++ }
}

# Select All / Deselect All
$lnkSelectAll = New-Object System.Windows.Forms.LinkLabel
$lnkSelectAll.Text = 'Select All'
$lnkSelectAll.Location = New-Object System.Drawing.Point(15, 148)
$lnkSelectAll.AutoSize = $true
$lnkSelectAll.Add_LinkClicked({ $sectionCheckboxes.Values | ForEach-Object { $_.Checked = $true } })
$sectionGroup.Controls.Add($lnkSelectAll)

$lnkDeselectAll = New-Object System.Windows.Forms.LinkLabel
$lnkDeselectAll.Text = 'Deselect All'
$lnkDeselectAll.Location = New-Object System.Drawing.Point(90, 148)
$lnkDeselectAll.AutoSize = $true
$lnkDeselectAll.Add_LinkClicked({ $sectionCheckboxes.Values | ForEach-Object { $_.Checked = $false } })
$sectionGroup.Controls.Add($lnkDeselectAll)

$yPos += 185

#--- Buttons ---
$btnRun = New-Object System.Windows.Forms.Button
$btnRun.Text = 'Run Audit'
$btnRun.Location = New-Object System.Drawing.Point(10, $yPos)
$btnRun.Size = New-Object System.Drawing.Size(100, 30)
$btnRun.BackColor = [System.Drawing.Color]::FromArgb(52, 152, 219)
$btnRun.ForeColor = [System.Drawing.Color]::White
$btnRun.FlatStyle = 'Flat'
$form.Controls.Add($btnRun)

$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text = 'Close'
$btnClose.Location = New-Object System.Drawing.Point(120, $yPos)
$btnClose.Size = New-Object System.Drawing.Size(80, 30)
$btnClose.FlatStyle = 'Flat'
$btnClose.Add_Click({ $form.Close() })
$form.Controls.Add($btnClose)

$yPos += 40

#--- Log Output ---
$lblLog = New-Object System.Windows.Forms.Label
$lblLog.Text = 'Log Output:'
$lblLog.Location = New-Object System.Drawing.Point(10, $yPos)
$lblLog.AutoSize = $true
$form.Controls.Add($lblLog)

$yPos += 20

$txtLog = New-Object System.Windows.Forms.TextBox
$txtLog.Location = New-Object System.Drawing.Point(10, $yPos)
$txtLog.Size = New-Object System.Drawing.Size(585, 210)
$txtLog.Multiline = $true
$txtLog.ScrollBars = 'Vertical'
$txtLog.ReadOnly = $true
$txtLog.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
$txtLog.Font = New-Object System.Drawing.Font('Consolas', 8.5)
$form.Controls.Add($txtLog)
#endregion

#region Run Logic
$syncHash = [hashtable]::Synchronized(@{
    Form   = $form
    Log    = $txtLog
    BtnRun = $btnRun
})

function Add-LogMessage {
    param([string]$Message)
    if ($syncHash.Form.InvokeRequired) {
        $syncHash.Form.Invoke([Action[string]]{ param($m) $syncHash.Log.AppendText("$m`r`n"); $syncHash.Log.ScrollToCaret() }, $Message)
    } else {
        $syncHash.Log.AppendText("$Message`r`n")
        $syncHash.Log.ScrollToCaret()
    }
}

$btnRun.Add_Click({
    # Validate at least one section selected
    $selectedSections = @($sectionCheckboxes.GetEnumerator() | Where-Object { $_.Value.Checked } | ForEach-Object { $_.Key })
    if ($selectedSections.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Please select at least one audit section.', 'Validation', 'OK', 'Warning')
        return
    }

    # Disable controls during run
    $btnRun.Enabled = $false
    $btnRun.Text = 'Running...'
    $txtLog.Clear()

    # Build params
    $scriptPath = Join-Path $PSScriptRoot 'Invoke-ADAudit.ps1'
    $params = @{
        OutputPath      = $txtOutput.Text
        ExportFormat    = $cboFormat.SelectedItem.ToString()
        DaysInactive    = [int]$numDays.Value
        SkipBrowserOpen = $chkSkipBrowser.Checked
        IncludeSection  = $selectedSections
    }
    if ($txtDomain.Text.Trim()) { $params['Domain'] = $txtDomain.Text.Trim() }

    # Run in background runspace
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.ApartmentState = 'STA'
    $runspace.Open()
    $runspace.SessionStateProxy.SetVariable('syncHash', $syncHash)
    $runspace.SessionStateProxy.SetVariable('scriptPath', $scriptPath)
    $runspace.SessionStateProxy.SetVariable('params', $params)

    $ps = [powershell]::Create().AddScript({
        try {
            $logCb = {
                param($msg)
                if ($syncHash.Form.InvokeRequired) {
                    $syncHash.Form.Invoke([Action[string]]{ param($m) $syncHash.Log.AppendText("$m`r`n"); $syncHash.Log.ScrollToCaret() }, $msg)
                }
            }
            $params['LogCallback'] = $logCb

            $null = & $scriptPath @params
        }
        catch {
            $errMsg = "ERROR: $_"
            if ($syncHash.Form.InvokeRequired) {
                $syncHash.Form.Invoke([Action[string]]{ param($m) $syncHash.Log.AppendText("$m`r`n") }, $errMsg)
            }
        }
        finally {
            if ($syncHash.Form.InvokeRequired) {
                $syncHash.Form.Invoke([Action]{
                    $syncHash.BtnRun.Enabled = $true
                    $syncHash.BtnRun.Text = 'Run Audit'
                    $syncHash.Log.AppendText("`r`n--- Audit Complete ---`r`n")
                    $syncHash.Log.ScrollToCaret()
                })
            }
        }
    })
    $ps.Runspace = $runspace
    $ps.BeginInvoke() | Out-Null
})
#endregion

# Show form
$form.ShowDialog() | Out-Null
