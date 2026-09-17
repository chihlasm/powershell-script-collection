<#
.SYNOPSIS
    GUI for hiding and unhiding Active Directory users in the Exchange Online GAL.
.DESCRIPTION
    Hides a user by writing msDS-cloudExtensionAttribute1 = "HideFromGAL" on the user
    object in Active Directory.

    IMPORTANT: that attribute is only a marker. Enforcement comes from a custom inbound
    synchronization rule inside Entra Connect - usually running on a DIFFERENT server -
    which flows the marker to msExchHideFromAddressLists.

    Custom sync rules are NOT carried over when Entra Connect is moved to a new server.
    Earlier versions of this tool assumed the rule existed and reported success either
    way, so after a Connect migration it silently stopped hiding anyone. This version
    verifies the rule on the Connect server before it will hide anyone, and shows a
    status banner naming the server it checked.
.PARAMETER EntraConnectServer
    Entra Connect server to verify against. Omit to auto-discover and cache it.
.PARAMETER Credential
    Optional credential for the connection to the Entra Connect server.
.PARAMETER SkipRuleCheck
    Skip enforcement-rule verification and allow writes regardless. For break-glass use
    when the check itself is the problem; the status banner still reports what it found.
.EXAMPLE
    .\HideFromGAL.ps1
    Auto-discover the Entra Connect server and open the manager.
.EXAMPLE
    .\HideFromGAL.ps1 -EntraConnectServer AADC02
    Verify against a named Entra Connect server.
.NOTES
    Requires the ActiveDirectory module (RSAT) and rights to modify user attributes.
    Verifying the sync rule additionally requires WinRM access to the Entra Connect
    server and local administrator rights there. If that check cannot run, the tool
    still works and says so - "could not verify" is reported separately from
    "rule is missing", because they need different responses.

    REFERENCES
    - Custom rules and expression syntax:
      https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-change-the-configuration
    - Custom rules are not migrated automatically:
      https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-import-export-config
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$EntraConnectServer,
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$SkipRuleCheck
)

# Check for administrative privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Add-Type -AssemblyName System.Windows.Forms
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

# Entra Connect discovery and sync-rule verification helpers.
. "$PSScriptRoot\Shared-EntraConnect.ps1" -LoadFunctionsOnly
$settingsPath      = Get-EntraConnectSettingsPath -ScriptRoot $PSScriptRoot
$script:RuleStatus = $null

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
$form.Size = New-Object System.Drawing.Size(800, 680)
$form.StartPosition = "CenterScreen"

# Enforcement-rule status banner. Always visible: this tool's failure mode was an
# invisible dependency on a sync rule living on another server, so the state of that
# dependency gets permanent screen space rather than a popup.
$bannerPanel = New-Object System.Windows.Forms.Panel
$bannerPanel.Location  = New-Object System.Drawing.Point(10, 505)
$bannerPanel.Size      = New-Object System.Drawing.Size(760, 66)
$bannerPanel.BorderStyle = 'FixedSingle'

$bannerTitle = New-Object System.Windows.Forms.Label
$bannerTitle.Location = New-Object System.Drawing.Point(10, 6)
$bannerTitle.Size     = New-Object System.Drawing.Size(600, 18)
$bannerTitle.Font     = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$bannerTitle.Text     = 'Checking enforcement rule...'

$bannerDetail = New-Object System.Windows.Forms.Label
$bannerDetail.Location = New-Object System.Drawing.Point(10, 26)
$bannerDetail.Size     = New-Object System.Drawing.Size(620, 36)

$bannerButton = New-Object System.Windows.Forms.Button
$bannerButton.Text     = 'How to fix'
$bannerButton.Location = New-Object System.Drawing.Point(640, 18)
$bannerButton.Size     = New-Object System.Drawing.Size(105, 28)
$bannerButton.Visible  = $false

$bannerPanel.Controls.AddRange(@($bannerTitle, $bannerDetail, $bannerButton))

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

# Function to refresh the enforcement-rule banner
function Update-Banner {
    param($Status)

    $look = Get-EntraConnectStatusPresentation -State $Status.State
    $bannerPanel.BackColor = [System.Drawing.ColorTranslator]::FromHtml($look.BannerBack)
    $bannerTitle.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($look.BannerFore)
    $bannerDetail.ForeColor = [System.Drawing.Color]::White
    $bannerTitle.Text      = $look.Headline

    $serverText = if ($Status.Server) { "Entra Connect server: $($Status.Server)" } else { 'Entra Connect server: not found' }
    $bannerDetail.Text     = "$serverText`r`n$($Status.Reason)"
    $bannerButton.Visible  = [bool]$Status.Remediation

    # Hiding is disabled only when the rule was positively confirmed broken. An
    # unverifiable check leaves the tool usable - it reports what it could not do.
    # Unhiding stays available always: restoring visibility must never be blocked.
    $blocked = $Status.ShouldBlock -and -not $SkipRuleCheck
    $applyButton.Enabled = -not $blocked
    Write-Log "Enforcement rule check: $($Status.State) on '$($Status.Server)' - $($Status.Reason)"
}

function Update-RuleStatus {
    $form.Cursor = 'WaitCursor'
    try {
        $script:RuleStatus = Test-EntraConnectRule -RuleKey 'HideFromGAL' `
                                                   -ComputerName $EntraConnectServer `
                                                   -SettingsPath $settingsPath `
                                                   -Credential $Credential
        Update-Banner -Status $script:RuleStatus
    } finally {
        $form.Cursor = 'Default'
    }
}

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
        if ([string]::IsNullOrWhiteSpace($searchFilter) -or $searchFilter -eq "*") {
            # Load all users without filter
            $users = Get-ADUser -Filter * -Properties SamAccountName, Name, Enabled, msDS-cloudExtensionAttribute1 -ErrorAction Stop |
                     Sort-Object Name
        } else {
            $sanitizedFilter = Format-SearchFilter -Filter $searchFilter
            $users = Get-ADUser -Filter "Name -like '$sanitizedFilter' -or SamAccountName -like '$sanitizedFilter'" -Properties SamAccountName, Name, Enabled, msDS-cloudExtensionAttribute1 -ErrorAction Stop |
                     Sort-Object Name
        }
        foreach ($user in $users) {
            $marked = ($user.'msDS-cloudExtensionAttribute1' -eq "HideFromGAL")

            # The status column reflects marker AND enforcement together. A marked user
            # on a server with no working rule is NOT hidden, and saying "Hidden" there
            # would repeat the exact deception this rewrite removes.
            $cloudStatus = if (-not $marked) {
                "Visible"
            } elseif ($script:RuleStatus -and $script:RuleStatus.CanEnforce) {
                "Hidden"
            } elseif ($script:RuleStatus -and $script:RuleStatus.ShouldBlock) {
                "Marked - NOT hidden"
            } else {
                "Marked - enforcement unverified"
            }

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
# Runs against the discovered Connect server rather than the local machine: the ADSync
# module only exists on the Connect server, which is usually not this one.
function Request-EntraSync {
    if (-not $script:RuleStatus -or -not $script:RuleStatus.Server) {
        [System.Windows.Forms.MessageBox]::Show(
            "Changes are saved in Active Directory but no Entra Connect server is known, so a sync could not be started. The change will apply at the next scheduled sync.",
            "Sync not started",
            "OK",
            "Information"
        )
        return
    }

    $server = $script:RuleStatus.Server
    $form.Cursor = 'WaitCursor'
    $result = Invoke-EntraConnectDeltaSync -ComputerName $server -Credential $Credential
    $form.Cursor = 'Default'

    if ($result.Success) {
        Write-Log "Synchronization triggered successfully on $server."
        [System.Windows.Forms.MessageBox]::Show(
            "Sync started on $server.",
            "Sync started",
            "OK",
            "Information"
        )
    } else {
        Write-Log "Sync error on ${server}: $($result.Error)"
        # A sync already running is the common, harmless case - name it rather than
        # presenting a bare exception.
        $hint = if ($result.Error -match 'already') { "`r`n`r`nA sync cycle is probably already running. The change will be picked up by it." } else { '' }
        [System.Windows.Forms.MessageBox]::Show(
            "Could not start the sync on $server.`r`n`r`n$($result.Error)$hint",
            "Sync not started",
            "OK",
            "Warning"
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
    if ([string]::IsNullOrWhiteSpace($searchBox.Text)) {
        Get-ADUsers
    } else {
        $sanitizedFilter = Format-SearchFilter -Filter $searchBox.Text
        Get-ADUsers -searchFilter "*$sanitizedFilter*"
    }
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

    # Refuse to write a marker that nothing will act on. Without this the tool reports
    # success while leaving every selected user visible in the GAL.
    if ($script:RuleStatus -and $script:RuleStatus.ShouldBlock -and -not $SkipRuleCheck) {
        Write-Log "Hide blocked: enforcement rule is $($script:RuleStatus.State) on '$($script:RuleStatus.Server)'."
        [System.Windows.Forms.MessageBox]::Show(
            "Hiding is disabled because the enforcement rule is not working.`r`n`r`n$($script:RuleStatus.Reason)`r`n`r`nSetting the attribute now would look like it worked but would not hide anyone.",
            "Cannot hide yet",
            "OK",
            "Warning"
        )
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
                # -Replace, not -Add: msDS-cloudExtensionAttribute1 is single-valued, so
                # -Add throws "attribute already exists" when re-hiding a user that was
                # marked before. -Replace is idempotent.
                Set-ADUser -Identity $username -Replace @{'msDS-cloudExtensionAttribute1'="HideFromGAL"} -ErrorAction Stop
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
        if ([string]::IsNullOrWhiteSpace($searchBox.Text)) {
            Get-ADUsers
        } else {
            Get-ADUsers -searchFilter "*$(Format-SearchFilter -Filter $searchBox.Text)*"
        }
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
        if ([string]::IsNullOrWhiteSpace($searchBox.Text)) {
            Get-ADUsers
        } else {
            Get-ADUsers -searchFilter "*$(Format-SearchFilter -Filter $searchBox.Text)*"
        }
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
$form.Controls.Add($bannerPanel)

$bannerButton.Add_Click({
    if ($script:RuleStatus -and $script:RuleStatus.Remediation) {
        [System.Windows.Forms.MessageBox]::Show(
            "$($script:RuleStatus.Reason)`r`n`r`n$($script:RuleStatus.Remediation)",
            "How to fix this",
            "OK",
            "Information"
        )
    }
})

# Load users on form load
# Add_Shown rather than Add_Load: verification makes a remote call, and running it
# after the window is painted avoids a blank form while it completes. The rule check
# runs first so the GAL Status column can reflect enforcement, not just the marker.
$form.Add_Shown({
    Update-RuleStatus
    Get-ADUsers
})

# Show the form
[void]$form.ShowDialog()

# Clean up
$form.Dispose()
Write-Log "Script execution completed."