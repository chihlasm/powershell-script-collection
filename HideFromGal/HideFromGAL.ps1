# Check for administrative privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    [System.Windows.Forms.MessageBox]::Show(
        "This script requires administrative privileges. Please run PowerShell as Administrator.",
        "Permission Error",
        "OK",
        "Error"
    )
    exit
}

# Import required modules
Import-Module ActiveDirectory -ErrorAction Stop
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Set up logging
$logFile = "C:\Temp\ADUserUpdateLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
if (-not (Test-Path "C:\Temp")) { New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null }
function Write-Log {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logFile -Append
}

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
$form.Text = "AD User GAL Manager"
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
$dataGridView.Columns.Add("msDS-cloudExtensionAttribute1", "GAL Status") | Out-Null

# Function to sanitize search filter
function Format-SearchFilter {
    param($Filter)
    # Replace special LDAP characters to prevent filter errors
    $Filter = $Filter -replace '\*', '*' # Ensure wildcards are preserved
    $Filter = $Filter -replace '[\\]', '\5c' # Escape backslashes
    $Filter = $Filter -replace '\(', '\28' # Escape parentheses
    $Filter = $Filter -replace '\)', '\29'
    $Filter = $Filter -replace '&', '\26' # Escape ampersands
    $Filter = $Filter -replace '\|', '\7c' # Escape pipes
    return $Filter
}

# Function to load all users
function Get-ADUsers {
    param($searchFilter = "*")
    $dataGridView.Rows.Clear()
    try {
        $sanitizedFilter = Format-SearchFilter -Filter $searchFilter
        $filter = "(Name -like '$sanitizedFilter' -or SamAccountName -like '$sanitizedFilter')"
        $users = Get-ADUser -Filter $filter -Properties SamAccountName, Name, Enabled, msDS-cloudExtensionAttribute1 -ErrorAction Stop |
                 Sort-Object Name
        foreach ($user in $users) {
            $cloudStatus = if ($user.'msDS-cloudExtensionAttribute1' -eq "HideFromGAL") { "Hidden" } else { "Visible" }
            $dataGridView.Rows.Add($false, $user.SamAccountName, $user.Name, $user.Enabled, $cloudStatus) | Out-Null
            Write-Log "Loaded user: $($user.SamAccountName), Enabled: $($user.Enabled), GAL Status: $cloudStatus"
        }
        Write-Log "Successfully loaded $($users.Count) users."
    } catch {
        Write-Log "Error loading users with filter '$searchFilter': $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show(
            "Error loading users: $($_.Exception.Message)",
            "Error",
            "OK",
            "Error"
        )
    }
}

# Function to trigger Entra Connect sync
function Request-EntraSync {
    try {
        Import-Module ADSync -ErrorAction Stop
        Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Stop
        Write-Log "Synchronization triggered successfully."
        [System.Windows.Forms.MessageBox]::Show(
            "Synchronization triggered successfully.",
            "Success",
            "OK",
            "Information"
        )
    } catch {
        Write-Log "Sync error: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to run sync: $($_.Exception.Message)",
            "Sync Error",
            "OK",
            "Error"
        )
    }
}

# Create search label and textbox
$searchLabel = New-Object System.Windows.Forms.Label
$searchLabel.Text = "Search Users:"
$searchLabel.Location = New-Object System.Drawing.Point(10, 20)
$searchLabel.Size = New-Object System.Drawing.Size(80, 20)

$searchBox = New-Object System.Windows.Forms.TextBox
$searchBox.Location = New-Object System.Drawing.Point(90, 20)
$searchBox.Size = New-Object System.Drawing.Size(180, 20)
$searchBox.Add_TextChanged({
    $sanitizedFilter = Format-SearchFilter -Filter $searchBox.Text
    Get-ADUsers -searchFilter "*$sanitizedFilter*"
})

# Create clear search button (X)
$clearSearchButton = New-Object System.Windows.Forms.Button
$clearSearchButton.Text = "X"
$clearSearchButton.Location = New-Object System.Drawing.Point(270, 20)
$clearSearchButton.Size = New-Object System.Drawing.Size(20, 20)
$clearSearchButton.Add_Click({
    $searchBox.Text = ""
    Get-ADUsers
})

# Create refresh button
$refreshButton = New-Object System.Windows.Forms.Button
$refreshButton.Text = "Refresh List"
$refreshButton.Location = New-Object System.Drawing.Point(300, 20)
$refreshButton.Size = New-Object System.Drawing.Size(100, 30)
$refreshButton.Add_Click({
    $searchBox.Text = ""
    Get-ADUsers
})

# Create manual sync button
$syncButton = New-Object System.Windows.Forms.Button
$syncButton.Text = "Sync to Entra"
$syncButton.Location = New-Object System.Drawing.Point(630, 20)
$syncButton.Size = New-Object System.Drawing.Size(100, 30)
$syncButton.Add_Click({
    Request-EntraSync
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

# Create apply button (Hide from GAL)
$applyButton = New-Object System.Windows.Forms.Button
$applyButton.Text = "Hide from GAL"
$applyButton.Location = New-Object System.Drawing.Point(10, 470)
$applyButton.Size = New-Object System.Drawing.Size(150, 30)
$applyButton.Add_Click({
    $selectedUsers = $dataGridView.Rows | Where-Object { $_.Cells[0].Value -eq $true }
    if ($selectedUsers.Count -eq 0) {
        Write-Log "No users selected for hiding from GAL."
        [System.Windows.Forms.MessageBox]::Show("No users selected.", "Warning", "OK", "Warning")
        return
    }
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Hide $($selectedUsers.Count) user(s) from GAL?", 
        "Confirm", 
        "YesNo", 
        "Question"
    )
    if ($confirm -eq "Yes") {
        $successCount = 0
        foreach ($row in $selectedUsers) {
            $username = $row.Cells[1].Value
            $isEnabled = $row.Cells[3].Value
            try {
                Set-ADUser -Identity $username -Add @{'msDS-cloudExtensionAttribute1'="HideFromGAL"} -ErrorAction Stop
                $successCount++
                Write-Log "Successfully hid user $username from GAL (Enabled: $isEnabled)."
            } catch {
                Write-Log "Error hiding user $username from GAL (Enabled: $isEnabled): $($_.Exception.Message)"
                [System.Windows.Forms.MessageBox]::Show(
                    "Error updating user $username (Enabled: $isEnabled): $($_.Exception.Message)",
                    "Error",
                    "OK",
                    "Error"
                )
            }
        }
        if ($successCount -gt 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "Successfully hid $successCount user(s) from GAL.",
                "Success",
                "OK",
                "Information"
            )
        }
        Get-ADUsers -searchFilter "*$(Format-SearchFilter -Filter $searchBox.Text)*"
        Request-EntraSync
    }
})

# Create clear attribute button (Unhide from GAL)
$clearButton = New-Object System.Windows.Forms.Button
$clearButton.Text = "Unhide from GAL"
$clearButton.Location = New-Object System.Drawing.Point(170, 470)
$clearButton.Size = New-Object System.Drawing.Size(150, 30)
$clearButton.Add_Click({
    $selectedUsers = $dataGridView.Rows | Where-Object { $_.Cells[0].Value -eq $true }
    if ($selectedUsers.Count -eq 0) {
        Write-Log "No users selected for unhiding from GAL."
        [System.Windows.Forms.MessageBox]::Show("No users selected.", "Warning", "OK", "Warning")
        return
    }
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Unhide $($selectedUsers.Count) user(s) from GAL?", 
        "Confirm", 
        "YesNo", 
        "Question"
    )
    if ($confirm -eq "Yes") {
        $successCount = 0
        foreach ($row in $selectedUsers) {
            $username = $row.Cells[1].Value
            $isEnabled = $row.Cells[3].Value
            try {
                Set-ADUser -Identity $username -Clear 'msDS-cloudExtensionAttribute1' -ErrorAction Stop
                $successCount++
                Write-Log "Successfully unhid user $username from GAL (Enabled: $isEnabled)."
            } catch {
                Write-Log "Error unhiding user $username from GAL (Enabled: $isEnabled): $($_.Exception.Message)"
                [System.Windows.Forms.MessageBox]::Show(
                    "Error updating user $username (Enabled: $isEnabled): $($_.Exception.Message)",
                    "Error",
                    "OK",
                    "Error"
                )
            }
        }
        if ($successCount -gt 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "Successfully unhid $successCount user(s) from GAL.",
                "Success",
                "OK",
                "Information"
            )
        }
        Get-ADUsers -searchFilter "*$(Format-SearchFilter -Filter $searchBox.Text)*"
        Request-EntraSync
    }
})

# Add controls to form
$form.Controls.Add($dataGridView)
$form.Controls.Add($searchLabel)
$form.Controls.Add($searchBox)
$form.Controls.Add($clearSearchButton)
$form.Controls.Add($refreshButton)
$form.Controls.Add($selectAllButton)
$form.Controls.Add($deselectAllButton)
$form.Controls.Add($applyButton)
$form.Controls.Add($clearButton)
$form.Controls.Add($syncButton)

# Load users on form load
$form.Add_Load({ Get-ADUsers })

# Show the form
[void]$form.ShowDialog()

# Clean up
$form.Dispose()
Write-Log "Script execution completed."