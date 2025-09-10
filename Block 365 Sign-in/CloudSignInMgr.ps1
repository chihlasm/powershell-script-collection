
# Import required modules
Import-Module ActiveDirectory
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Hide the PowerShell console window
Add-Type -Name Win32 -Namespace Console -MemberDefinition '
[DllImport("kernel32.dll")]
public static extern IntPtr GetConsoleWindow();

[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

public const int SW_HIDE = 0;
'

$consolePtr = [Console.Win32]::GetConsoleWindow()
[Console.Win32]::ShowWindow($consolePtr, 0) # 0 = SW_HIDE

# Create the main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "AD User Cloud Sign-In Manager"
$form.Size = New-Object System.Drawing.Size(800, 600)
$form.StartPosition = "CenterScreen"

# Create DataGridView to display users
$dataGridView = New-Object System.Windows.Forms.DataGridView
$dataGridView.Location = New-Object System.Drawing.Point(10, 60)
$dataGridView.Size = New-Object System.Drawing.Size(760, 400)
$dataGridView.AutoSizeColumnsMode = "Fill"
$dataGridView.SelectionMode = "FullRowSelect"
$dataGridView.MultiSelect = $false
$dataGridView.AllowUserToAddRows = $false
$dataGridView.RowHeadersVisible = $false

# Add checkbox column
$checkboxColumn = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$checkboxColumn.Name = "Select"
$checkboxColumn.HeaderText = "Select"
$checkboxColumn.Width = 60
$dataGridView.Columns.Add($checkboxColumn)

# Add columns for user details
$dataGridView.Columns.Add("SamAccountName", "Username") | Out-Null
$dataGridView.Columns.Add("Name", "Full Name") | Out-Null
$dataGridView.Columns.Add("Enabled", "Enabled") | Out-Null
$dataGridView.Columns.Add("msDS-cloudExtensionAttribute10", "Cloud Sign-In Status") | Out-Null

# Function to load active users
function Load-ADUsers {
    param($searchFilter = "*")
    $dataGridView.Rows.Clear()
    $users = Get-ADUser -Filter "Enabled -eq '$true' -and (Name -like '$searchFilter' -or SamAccountName -like '$searchFilter')" -Properties SamAccountName, Name, Enabled, msDS-cloudExtensionAttribute10 |
             Sort-Object Name
    foreach ($user in $users) {
        $cloudStatus = if ($user.'msDS-cloudExtensionAttribute10' -eq "BlockCloudSignIn") { "Blocked" } else { "Allowed" }
        $dataGridView.Rows.Add($false, $user.SamAccountName, $user.Name, $user.Enabled, $cloudStatus) | Out-Null
    }
}

# Function to prompt for Entra Connect sync
function Prompt-ForSync {
    $syncPrompt = [System.Windows.Forms.MessageBox]::Show(
        "Would you like to run a Microsoft Entra Connect sync to apply changes now?",
        "Run Sync",
        "YesNo",
        "Question"
    )
    if ($syncPrompt -eq "Yes") {
        try {
            Import-Module ADSync -ErrorAction Stop
            Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Stop
            [System.Windows.Forms.MessageBox]::Show(
                "Synchronization triggered successfully.",
                "Success",
                "OK",
                "Information"
            )
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to run sync: $($_.Exception.Message)",
                "Sync Error",
                "OK",
                "Error"
            )
        }
    }
}

# Create search label and textbox
$searchLabel = New-Object System.Windows.Forms.Label
$searchLabel.Text = "Search Users:"
$searchLabel.Location = New-Object System.Drawing.Point(10, 20)
$searchLabel.Size = New-Object System.Drawing.Size(80, 20)

$searchBox = New-Object System.Windows.Forms.TextBox
$searchBox.Location = New-Object System.Drawing.Point(90, 20)
$searchBox.Size = New-Object System.Drawing.Size(200, 20)
$searchBox.Add_TextChanged({
    Load-ADUsers -searchFilter "*$($searchBox.Text)*"
})

# Create refresh button
$refreshButton = New-Object System.Windows.Forms.Button
$refreshButton.Text = "Refresh List"
$refreshButton.Location = New-Object System.Drawing.Point(300, 20)
$refreshButton.Size = New-Object System.Drawing.Size(100, 30)
$refreshButton.Add_Click({
    $searchBox.Text = ""
    Load-ADUsers
})

# Create select all button
$selectAllButton = New-Object System.Windows.Forms.Button
$selectAllButton.Text = "Select All"
$selectAllButton.Location = New-Object System.Drawing.Point(410, 20)
$selectAllButton.Size = New-Object System.Drawing.Size(100, 30)
$selectAllButton.Add_Click({
    foreach ($row in $dataGridView.Rows) {
        $row.Cells[0].Value = $true
    }
})

# Create deselect all button
$deselectAllButton = New-Object System.Windows.Forms.Button
$deselectAllButton.Text = "Deselect All"
$deselectAllButton.Location = New-Object System.Drawing.Point(520, 20)
$deselectAllButton.Size = New-Object System.Drawing.Size(100, 30)
$deselectAllButton.Add_Click({
    foreach ($row in $dataGridView.Rows) {
        $row.Cells[0].Value = $false
    }
})

# Create apply button (Block Cloud Sign-In)
$applyButton = New-Object System.Windows.Forms.Button
$applyButton.Text = "Block Cloud Sign-In"
$applyButton.Location = New-Object System.Drawing.Point(10, 470)
$applyButton.Size = New-Object System.Drawing.Size(150, 30)
$applyButton.Add_Click({
    $selectedUsers = $dataGridView.Rows | Where-Object { $_.Cells[0].Value -eq $true }
    if ($selectedUsers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No users selected.", "Warning", "OK", "Warning")
        return
    }
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Block cloud sign-in for $($selectedUsers.Count) user(s)?", 
        "Confirm", 
        "YesNo", 
        "Question"
    )
    if ($confirm -eq "Yes") {
        try {
            foreach ($row in $selectedUsers) {
                $username = $row.Cells[1].Value
                Set-ADUser -Identity $username -Add @{'msDS-cloudExtensionAttribute10'="BlockCloudSignIn"} -ErrorAction Stop
            }
            [System.Windows.Forms.MessageBox]::Show(
                "Successfully blocked cloud sign-in for selected users.",
                "Success",
                "OK",
                "Information"
            )
            Load-ADUsers -searchFilter "*$($searchBox.Text)*"
            Prompt-ForSync
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Error: $($_.Exception.Message)",
                "Error",
                "OK",
                "Error"
            )
        }
    }
})

# Create clear attribute button (Unblock Cloud Sign-In)
$clearButton = New-Object System.Windows.Forms.Button
$clearButton.Text = "Unblock Cloud Sign-In"
$clearButton.Location = New-Object System.Drawing.Point(170, 470)
$clearButton.Size = New-Object System.Drawing.Size(150, 30)
$clearButton.Add_Click({
    $selectedUsers = $dataGridView.Rows | Where-Object { $_.Cells[0].Value -eq $true }
    if ($selectedUsers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No users selected.", "Warning", "OK", "Warning")
        return
    }
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Unblock cloud sign-in for $($selectedUsers.Count) user(s)?", 
        "Confirm", 
        "YesNo", 
        "Question"
    )
    if ($confirm -eq "Yes") {
        try {
            foreach ($row in $selectedUsers) {
                $username = $row.Cells[1].Value
                Set-ADUser -Identity $username -Clear 'msDS-cloudExtensionAttribute10' -ErrorAction Stop
            }
            [System.Windows.Forms.MessageBox]::Show(
                "Successfully unblocked cloud sign-in for selected users.",
                "Success",
                "OK",
                "Information"
            )
            Load-ADUsers -searchFilter "*$($searchBox.Text)*"
            Prompt-ForSync
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Error: $($_.Exception.Message)",
                "Error",
                "OK",
                "Error"
            )
        }
    }
})

# Add controls to form
$form.Controls.Add($dataGridView)
$form.Controls.Add($searchLabel)
$form.Controls.Add($searchBox)
$form.Controls.Add($refreshButton)
$form.Controls.Add($selectAllButton)
$form.Controls.Add($deselectAllButton)
$form.Controls.Add($applyButton)
$form.Controls.Add($clearButton)

# Load users on form load
$form.Add_Load({ Load-ADUsers })

# Show the form
[void]$form.ShowDialog()

# Clean up
$form.Dispose()