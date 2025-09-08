# FileCopyMoveGUI.ps1
# PowerShell script with GUI for file/folder copy/move operations using Robocopy-like features

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create the main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "File Copy/Move GUI"
$form.Size = New-Object System.Drawing.Size(600, 500)
$form.StartPosition = "CenterScreen"

# Source folder/file selection
$sourceLabel = New-Object System.Windows.Forms.Label
$sourceLabel.Text = "Source:"
$sourceLabel.Location = New-Object System.Drawing.Point(10, 20)
$sourceLabel.Size = New-Object System.Drawing.Size(50, 20)
$form.Controls.Add($sourceLabel)

$sourceTextBox = New-Object System.Windows.Forms.TextBox
$sourceTextBox.Location = New-Object System.Drawing.Point(70, 20)
$sourceTextBox.Size = New-Object System.Drawing.Size(400, 20)
$form.Controls.Add($sourceTextBox)

$sourceBrowseButton = New-Object System.Windows.Forms.Button
$sourceBrowseButton.Text = "Browse"
$sourceBrowseButton.Location = New-Object System.Drawing.Point(480, 18)
$sourceBrowseButton.Size = New-Object System.Drawing.Size(80, 23)
$form.Controls.Add($sourceBrowseButton)

# Destination folder selection
$destLabel = New-Object System.Windows.Forms.Label
$destLabel.Text = "Destination:"
$destLabel.Location = New-Object System.Drawing.Point(10, 50)
$destLabel.Size = New-Object System.Drawing.Size(70, 20)
$form.Controls.Add($destLabel)

$destTextBox = New-Object System.Windows.Forms.TextBox
$destTextBox.Location = New-Object System.Drawing.Point(85, 50)
$destTextBox.Size = New-Object System.Drawing.Size(385, 20)
$form.Controls.Add($destTextBox)

$destBrowseButton = New-Object System.Windows.Forms.Button
$destBrowseButton.Text = "Browse"
$destBrowseButton.Location = New-Object System.Drawing.Point(480, 48)
$destBrowseButton.Size = New-Object System.Drawing.Size(80, 23)
$form.Controls.Add($destBrowseButton)

# Operation type
$operationLabel = New-Object System.Windows.Forms.Label
$operationLabel.Text = "Operation:"
$operationLabel.Location = New-Object System.Drawing.Point(10, 80)
$operationLabel.Size = New-Object System.Drawing.Size(60, 20)
$form.Controls.Add($operationLabel)

$copyRadioButton = New-Object System.Windows.Forms.RadioButton
$copyRadioButton.Text = "Copy"
$copyRadioButton.Location = New-Object System.Drawing.Point(80, 80)
$copyRadioButton.Checked = $true
$form.Controls.Add($copyRadioButton)

$moveRadioButton = New-Object System.Windows.Forms.RadioButton
$moveRadioButton.Text = "Move"
$moveRadioButton.Location = New-Object System.Drawing.Point(140, 80)
$form.Controls.Add($moveRadioButton)

# Options
$optionsTable = New-Object System.Windows.Forms.TableLayoutPanel
$optionsTable.Location = New-Object System.Drawing.Point(10, 110)
$optionsTable.Size = New-Object System.Drawing.Size(550, 120)
$optionsTable.AutoSize = $true
$optionsTable.ColumnCount = 2
$optionsTable.RowCount = 2
$optionsTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50)))
$optionsTable.ColumnStyles.Add((New-Object System.Windows.Forms.SizeType([System.Windows.Forms.SizeType]::Percent, 50)))
$optionsTable.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
$optionsTable.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
$form.Controls.Add($optionsTable)

$recursiveCheckBox = New-Object System.Windows.Forms.CheckBox
$recursiveCheckBox.Text = "Recursive (copy subdirectories)"
$recursiveCheckBox.Checked = $true
$recursiveCheckBox.AutoSize = $true
$optionsTable.Controls.Add($recursiveCheckBox, 0, 0)

$mirrorCheckBox = New-Object System.Windows.Forms.CheckBox
$mirrorCheckBox.Text = "Mirror (delete extra files in destination)"
$mirrorCheckBox.AutoSize = $true
$optionsTable.Controls.Add($mirrorCheckBox, 1, 0)

$excludeLabel = New-Object System.Windows.Forms.Label
$excludeLabel.Text = "Exclude files/folders:"
$excludeLabel.AutoSize = $true
$optionsTable.Controls.Add($excludeLabel, 0, 1)

$excludeTextBox = New-Object System.Windows.Forms.TextBox
$excludeTextBox.Size = New-Object System.Drawing.Size(200, 20)
$excludeTextBox.Text = "*.tmp;*.log"
$optionsTable.Controls.Add($excludeTextBox, 1, 1)

# Progress bar
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(10, 220)
$progressBar.Size = New-Object System.Drawing.Size(550, 20)
$form.Controls.Add($progressBar)

# Log text box
$logTextBox = New-Object System.Windows.Forms.TextBox
$logTextBox.Location = New-Object System.Drawing.Point(10, 250)
$logTextBox.Size = New-Object System.Drawing.Size(550, 150)
$logTextBox.Multiline = $true
$logTextBox.ScrollBars = "Vertical"
$form.Controls.Add($logTextBox)

# Buttons
$startButton = New-Object System.Windows.Forms.Button
$startButton.Text = "Start"
$startButton.Location = New-Object System.Drawing.Point(400, 410)
$startButton.Size = New-Object System.Drawing.Size(80, 30)
$form.Controls.Add($startButton)

$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Text = "Cancel"
$cancelButton.Location = New-Object System.Drawing.Point(490, 410)
$cancelButton.Size = New-Object System.Drawing.Size(80, 30)
$cancelButton.Enabled = $false
$form.Controls.Add($cancelButton)

# Event handlers
$sourceBrowseButton.Add_Click({
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($folderBrowser.ShowDialog() -eq "OK") {
        $sourceTextBox.Text = $folderBrowser.SelectedPath
    }
})

$destBrowseButton.Add_Click({
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($folderBrowser.ShowDialog() -eq "OK") {
        $destTextBox.Text = $folderBrowser.SelectedPath
    }
})

$startButton.Add_Click({
    $startButton.Enabled = $false
    $cancelButton.Enabled = $true
    $progressBar.Value = 0
    $logTextBox.Text = ""

    $source = $sourceTextBox.Text
    $destination = $destTextBox.Text
    $operation = if ($copyRadioButton.Checked) { "COPY" } else { "MOVE" }

    if ([string]::IsNullOrEmpty($source) -or [string]::IsNullOrEmpty($destination)) {
        [System.Windows.Forms.MessageBox]::Show("Please select both source and destination.", "Error", "OK", "Error")
        $startButton.Enabled = $true
        $cancelButton.Enabled = $false
        return
    }

    # Build robocopy arguments
    $robocopyArgs = @($source, $destination)

    if ($recursiveCheckBox.Checked) {
        $robocopyArgs += "/S"
    }

    if ($mirrorCheckBox.Checked) {
        $robocopyArgs += "/MIR"
    }

    if (-not [string]::IsNullOrEmpty($excludeTextBox.Text)) {
        $excludes = $excludeTextBox.Text -split ";"
        foreach ($exclude in $excludes) {
            $robocopyArgs += "/XF"
            $robocopyArgs += $exclude.Trim()
        }
    }

    $robocopyArgs += "/NJH"  # No job header
    $robocopyArgs += "/NJS"  # No job summary

    $logTextBox.AppendText("Starting $operation operation...`r`n")
    $logTextBox.AppendText("Source: $source`r`n")
    $logTextBox.AppendText("Destination: $destination`r`n")
    $logTextBox.AppendText("Command: robocopy $($robocopyArgs -join ' ')`r`n`r`n")

    # Run robocopy
    try {
        $process = Start-Process -FilePath "robocopy.exe" -ArgumentList $robocopyArgs -NoNewWindow -PassThru -RedirectStandardOutput "temp_output.txt" -RedirectStandardError "temp_error.txt"

        while (-not $process.HasExited) {
            Start-Sleep -Milliseconds 100
            # Update progress (simplified)
            if ($progressBar.Value -lt 90) {
                $progressBar.Value += 1
            }
        }

        $output = Get-Content "temp_output.txt" -ErrorAction SilentlyContinue
        $errorOutput = Get-Content "temp_error.txt" -ErrorAction SilentlyContinue

        if ($output) {
            $logTextBox.AppendText($output -join "`r`n")
        }

        if ($errorOutput) {
            $logTextBox.AppendText("Errors:`r`n")
            $logTextBox.AppendText($errorOutput -join "`r`n")
        }

        $progressBar.Value = 100
        $logTextBox.AppendText("`r`nOperation completed.`r`n")

        # Clean up temp files
        Remove-Item "temp_output.txt" -ErrorAction SilentlyContinue
        Remove-Item "temp_error.txt" -ErrorAction SilentlyContinue

    } catch {
        $logTextBox.AppendText("Error: $($_.Exception.Message)`r`n")
    }

    $startButton.Enabled = $true
    $cancelButton.Enabled = $false
})

$cancelButton.Add_Click({
    # Cancel the robocopy process
    if ($process -and -not $process.HasExited) {
        $process.Kill()
        $logTextBox.AppendText("Operation cancelled by user.`r`n")
        $progressBar.Value = 0
        $startButton.Enabled = $true
        $cancelButton.Enabled = $false
    }
})

# Show the form
$form.ShowDialog()
