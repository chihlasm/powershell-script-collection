<#
.SYNOPSIS
    Browser-based GUI for Juniper EX/SRX console-cable provisioning.

.DESCRIPTION
    Launches a local web server that provides a modern dashboard interface for
    Juniper device setup via serial console cable. Supports:
      - COM port detection and serial connection management
      - Factory-default and credential-based login
      - vc3admin super-user account provisioning
      - Management interface IP configuration
      - Firmware upgrade via SCP
      - Running config backup and export
      - Raw Junos command terminal

    Communicates with the Juniper device over a serial COM port while presenting
    a clean browser UI on localhost.

.PARAMETER Port
    TCP port for the local web server. Default is 8280.

.PARAMETER ComPort
    Pre-select a COM port instead of choosing in the GUI.

.PARAMETER BaudRate
    Serial baud rate. Default is 9600 (standard Juniper console).

.PARAMETER NoBrowserOpen
    Do not auto-launch the browser. Useful for remote/headless scenarios.

.EXAMPLE
    .\Invoke-JuniperConsoleSetup-GUI.ps1
    Launches the GUI on http://localhost:8280 and opens the browser.

.EXAMPLE
    .\Invoke-JuniperConsoleSetup-GUI.ps1 -Port 9090 -ComPort COM5
    Uses port 9090 and pre-connects to COM5.

.NOTES
    Author  : VC3 Network Engineering
    Requires: Windows with .NET SerialPort support, USB-to-serial console cable
    Tested  : PowerShell 5.1 on Windows 10/11
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8280,

    [string]$ComPort,

    [ValidateRange(1200, 115200)]
    [int]$BaudRate = 9600,

    [switch]$NoBrowserOpen
)

# ============================================================================
# GLOBALS
# ============================================================================
$script:SerialPort    = $null
$script:SessionLog    = [System.Collections.ArrayList]::new()
$script:IsConnected   = $false
$script:IsLoggedIn    = $false
$script:IsConfigMode  = $false
$script:DeviceInfo    = @{
    Hostname = ''
    Model    = ''
    Firmware = ''
    Serial   = ''
}
$script:PromptPattern = '(login:\s*$|Password:\s*$|root@[\w%-]+[>#]\s*$|[\w.-]+[>#]\s*$|root@:~#\s*$|\{master:\d+\})'

function Get-Timestamp { (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
function Get-FileTimestamp { (Get-Date).ToString('yyyy-MM-dd_HHmmss') }

function Add-LogEntry {
    param([string]$Message, [string]$Level = 'INFO')
    $entry = @{ time = (Get-Timestamp); level = $Level; message = $Message }
    [void]$script:SessionLog.Add($entry)
    $colors = @{ INFO = 'Cyan'; PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red' }
    $color = if ($colors.ContainsKey($Level)) { $colors[$Level] } else { 'White' }
    Write-Host "[$Level] $($entry.time)  $Message" -ForegroundColor $color
}

# ============================================================================
# SERIAL PORT MANAGEMENT
# ============================================================================
function Get-AvailableComPorts {
    # Use .NET Registry class directly - GetPortNames() caches and PowerShell's
    # Get-ItemProperty has issues with backslash-containing property names like \Device\VCP0
    try {
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('HARDWARE\DEVICEMAP\SERIALCOMM')
        if ($regKey) {
            $ports = @($regKey.GetValueNames() | ForEach-Object { $regKey.GetValue($_) } | Sort-Object)
            $regKey.Close()
            if ($ports.Count -gt 0) { return $ports }
        }
    } catch { }
    # Fallback to .NET method
    try {
        return @([System.IO.Ports.SerialPort]::GetPortNames() | Sort-Object)
    } catch {
        return @()
    }
}

function Connect-SerialPort {
    param([string]$PortName, [int]$Baud = 9600)
    try {
        if ($script:SerialPort -and $script:SerialPort.IsOpen) {
            $script:SerialPort.Close()
            $script:SerialPort.Dispose()
        }
        $port = New-Object System.IO.Ports.SerialPort
        $port.PortName    = $PortName
        $port.BaudRate    = $Baud
        $port.DataBits    = 8
        $port.Parity      = [System.IO.Ports.Parity]::None
        $port.StopBits    = [System.IO.Ports.StopBits]::One
        $port.Handshake   = [System.IO.Ports.Handshake]::None
        $port.ReadTimeout  = 3000
        $port.WriteTimeout = 3000
        $port.NewLine     = "`n"
        $port.Encoding    = [System.Text.Encoding]::ASCII
        $port.Open()
        $script:SerialPort  = $port
        $script:IsConnected = $true
        Add-LogEntry "Connected to $PortName at ${Baud} baud (8N1)" 'PASS'
        return @{ success = $true; message = "Connected to $PortName" }
    } catch {
        $script:IsConnected = $false
        Add-LogEntry "Failed to open ${PortName}: $_" 'FAIL'
        return @{ success = $false; message = "Failed to open ${PortName}: $_" }
    }
}

function Disconnect-SerialPort {
    if ($script:SerialPort -and $script:SerialPort.IsOpen) {
        try {
            $script:SerialPort.Close()
            $script:SerialPort.Dispose()
        } catch { }
    }
    $script:SerialPort  = $null
    $script:IsConnected = $false
    $script:IsLoggedIn  = $false
    $script:IsConfigMode = $false
    $script:DeviceInfo = @{ Hostname = ''; Model = ''; Firmware = ''; Serial = '' }
    Add-LogEntry "Disconnected from serial port." 'INFO'
}

function Send-SerialData {
    param([string]$Data, [switch]$NoNewline)
    if (-not $script:SerialPort -or -not $script:SerialPort.IsOpen) { return }
    try {
        if ($NoNewline) { $script:SerialPort.Write($Data) }
        else { $script:SerialPort.Write("$Data`r") }
    } catch {
        Add-LogEntry "Send failed: $_" 'FAIL'
    }
}

function Read-SerialResponse {
    param([int]$TimeoutSeconds = 15, [string]$WaitFor = '')
    if (-not $script:SerialPort -or -not $script:SerialPort.IsOpen) { return '' }
    $buffer   = New-Object System.Text.StringBuilder
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $available = $script:SerialPort.BytesToRead
            if ($available -gt 0) {
                $data = $script:SerialPort.ReadExisting()
                [void]$buffer.Append($data)
                $current = $buffer.ToString()
                if ($WaitFor -and $current -match $WaitFor) { break }
                if (-not $WaitFor -and $current -match $script:PromptPattern) {
                    Start-Sleep -Milliseconds 200
                    $extra = $script:SerialPort.ReadExisting()
                    if ($extra) { [void]$buffer.Append($extra) }
                    break
                }
            } else {
                Start-Sleep -Milliseconds 100
            }
        } catch {
            Start-Sleep -Milliseconds 100
        }
    }
    return $buffer.ToString()
}

function Invoke-JunosCommand {
    param([string]$Command, [int]$TimeoutSeconds = 15, [string]$WaitFor = '')
    Send-SerialData -Data $Command
    Start-Sleep -Milliseconds 300
    return (Read-SerialResponse -TimeoutSeconds $TimeoutSeconds -WaitFor $WaitFor)
}

# ============================================================================
# DEVICE OPERATIONS (API-friendly - return structured data)
# ============================================================================
function Invoke-DeviceLogin {
    param([string]$Username, [string]$Password, [switch]$TryFactoryDefault)

    # Wake console
    Send-SerialData -Data ''
    Start-Sleep -Milliseconds 500
    Send-SerialData -Data ''
    Start-Sleep -Milliseconds 500
    $response = Read-SerialResponse -TimeoutSeconds 5

    # Already at CLI prompt
    if ($response -match '[\w.-]+>\s*$') {
        Invoke-JunosCommand -Command 'set cli screen-length 0' | Out-Null
        $script:IsLoggedIn = $true
        Add-LogEntry "Already at operational CLI prompt." 'PASS'
        return @{ success = $true; message = "Already logged in at CLI prompt." }
    }
    if ($response -match '[\w.-]+#\s*$' -and $response -notmatch 'root@:~#') {
        $script:IsLoggedIn = $true
        $script:IsConfigMode = $true
        Add-LogEntry "Already in configuration mode." 'PASS'
        return @{ success = $true; message = "Already in configuration mode." }
    }

    # At root shell (factory default already logged in)
    if ($response -match 'root@[\w%-]*:~#' -or $response -match 'root@:~#') {
        Add-LogEntry "At root shell. Entering CLI..." 'INFO'
        Invoke-JunosCommand -Command 'cli' | Out-Null
        Invoke-JunosCommand -Command 'set cli screen-length 0' | Out-Null
        $script:IsLoggedIn = $true
        return @{ success = $true; message = "Logged in (root shell, entered CLI)." }
    }

    # At login prompt
    if ($response -match 'login:\s*$') {
        if ($TryFactoryDefault) {
            Add-LogEntry "Trying factory-default login (root / no password)..." 'INFO'
            Send-SerialData -Data 'root'
            Start-Sleep -Milliseconds 500
            $passPrompt = Read-SerialResponse -TimeoutSeconds 5

            if ($passPrompt -match 'Password:\s*$') {
                Send-SerialData -Data ''
                Start-Sleep -Milliseconds 1000
                $result = Read-SerialResponse -TimeoutSeconds 5
                if ($result -match 'Login incorrect' -or $result -match 'login:\s*$') {
                    Add-LogEntry "Factory-default login failed. Device has a password." 'WARN'
                    return @{ success = $false; message = "Factory-default login failed. Device has credentials set."; needsCredentials = $true }
                } else {
                    if ($result -match 'root@[\w%-]*:~#' -or $result -match 'root@:~#') {
                        Invoke-JunosCommand -Command 'cli' | Out-Null
                    }
                    Invoke-JunosCommand -Command 'set cli screen-length 0' | Out-Null
                    $script:IsLoggedIn = $true
                    Add-LogEntry "Logged in as root (factory default)." 'PASS'
                    return @{ success = $true; message = "Logged in as root (factory default)."; factoryDefault = $true }
                }
            } elseif ($passPrompt -match 'root@[\w%-]*:~#' -or $passPrompt -match '%\s*$') {
                Invoke-JunosCommand -Command 'cli' | Out-Null
                Invoke-JunosCommand -Command 'set cli screen-length 0' | Out-Null
                $script:IsLoggedIn = $true
                Add-LogEntry "Logged in as root (no password)." 'PASS'
                return @{ success = $true; message = "Logged in as root (no password required)."; factoryDefault = $true }
            }
        }

        # Manual credentials
        if (-not $Username) {
            return @{ success = $false; message = "At login prompt. Provide credentials."; needsCredentials = $true }
        }

        Add-LogEntry "Logging in as $Username..." 'INFO'
        # Make sure we're at login prompt
        $current = Read-SerialResponse -TimeoutSeconds 2
        if ($current -notmatch 'login:\s*$') {
            Send-SerialData -Data ''
            Start-Sleep -Milliseconds 500
            Read-SerialResponse -TimeoutSeconds 3 | Out-Null
        }
        Send-SerialData -Data $Username
        Start-Sleep -Milliseconds 500
        $passPrompt = Read-SerialResponse -TimeoutSeconds 5

        if ($passPrompt -match 'Password:\s*$') {
            Send-SerialData -Data $Password
            Start-Sleep -Milliseconds 1000
            $result = Read-SerialResponse -TimeoutSeconds 10
            if ($result -match 'Login incorrect' -or $result -match 'login:\s*$') {
                Add-LogEntry "Login failed for $Username." 'FAIL'
                return @{ success = $false; message = "Login failed. Check credentials." }
            }
            if ($result -match 'root@[\w%-]*:~#' -or $result -match ':~#') {
                Invoke-JunosCommand -Command 'cli' | Out-Null
            }
            Invoke-JunosCommand -Command 'set cli screen-length 0' | Out-Null
            $script:IsLoggedIn = $true
            Add-LogEntry "Logged in as $Username." 'PASS'
            return @{ success = $true; message = "Logged in as $Username." }
        }
        return @{ success = $false; message = "Unexpected response during login." }
    }

    # Unknown state
    Add-LogEntry "Console in unrecognized state." 'WARN'
    return @{ success = $false; message = "Unrecognized console state. Try pressing Enter on the device first."; raw = $response }
}

function Get-DeviceInfoData {
    if ($script:IsConfigMode) {
        Invoke-JunosCommand -Command 'exit' | Out-Null
        $script:IsConfigMode = $false
    }

    $versionOutput = Invoke-JunosCommand -Command 'show version' -TimeoutSeconds 10
    if ($versionOutput -match 'Hostname:\s+(\S+)')          { $script:DeviceInfo.Hostname = $Matches[1] }
    if ($versionOutput -match 'Model:\s+(\S+)')             { $script:DeviceInfo.Model = $Matches[1] }
    if ($versionOutput -match 'Junos:\s+(\S+)')             { $script:DeviceInfo.Firmware = $Matches[1] }
    elseif ($versionOutput -match 'JUNOS\s+\S+\s+\[(\S+)\]') { $script:DeviceInfo.Firmware = $Matches[1] }

    $chassisOutput = Invoke-JunosCommand -Command 'show chassis hardware | match Chassis' -TimeoutSeconds 10
    if ($chassisOutput -match 'Chassis\s+\S+\s+\S+\s+(\S+)') { $script:DeviceInfo.Serial = $Matches[1] }
    elseif ($chassisOutput -match 'Chassis\s+(\S+)')          { $script:DeviceInfo.Serial = $Matches[1] }

    Add-LogEntry "Device: $($script:DeviceInfo.Hostname) / $($script:DeviceInfo.Model) / Junos $($script:DeviceInfo.Firmware) / SN $($script:DeviceInfo.Serial)" 'PASS'
    return @{
        success  = $true
        hostname = $script:DeviceInfo.Hostname
        model    = $script:DeviceInfo.Model
        firmware = $script:DeviceInfo.Firmware
        serial   = $script:DeviceInfo.Serial
        raw      = $versionOutput
    }
}

function New-Vc3AdminAccountApi {
    param([string]$AccountPassword, [string]$RootPassword)

    Add-LogEntry "Starting vc3admin provisioning..." 'INFO'

    # Check existing
    $existingCheck = Invoke-JunosCommand -Command 'show configuration system login user vc3admin' -TimeoutSeconds 10
    $alreadyExists = ($existingCheck -match 'class super-user' -or $existingCheck -match 'encrypted-password')

    # Enter config mode
    Invoke-JunosCommand -Command 'configure' -TimeoutSeconds 5 | Out-Null
    $script:IsConfigMode = $true

    # Check if root password is needed (factory default)
    $rootCheck = Invoke-JunosCommand -Command 'show system login user root' -TimeoutSeconds 5
    $needsRootPassword = ($rootCheck -notmatch 'encrypted-password')

    if ($needsRootPassword) {
        if (-not $RootPassword) {
            Invoke-JunosCommand -Command 'exit' | Out-Null
            $script:IsConfigMode = $false
            return @{ success = $false; message = "Factory-default device: root password must be set before commit. Provide a root password."; needsRootPassword = $true }
        }
        Add-LogEntry "Setting root password (factory-default requirement)..." 'INFO'
        Send-SerialData -Data 'set system root-authentication plain-text-password'
        Start-Sleep -Milliseconds 500
        Read-SerialResponse -TimeoutSeconds 5 -WaitFor 'New password:' | Out-Null
        Send-SerialData -Data $RootPassword
        Start-Sleep -Milliseconds 500
        Read-SerialResponse -TimeoutSeconds 5 -WaitFor 'Retype new password:' | Out-Null
        Send-SerialData -Data $RootPassword
        Start-Sleep -Milliseconds 500
        Read-SerialResponse -TimeoutSeconds 3 | Out-Null
        Add-LogEntry "Root password staged." 'PASS'
    }

    # Create vc3admin
    $action = if ($alreadyExists) { "Resetting" } else { "Creating" }
    Add-LogEntry "$action vc3admin account (super-user)..." 'INFO'
    Send-SerialData -Data 'set system login user vc3admin class super-user authentication plain-text-password'
    Start-Sleep -Milliseconds 500
    Read-SerialResponse -TimeoutSeconds 5 -WaitFor 'New password:' | Out-Null
    Send-SerialData -Data $AccountPassword
    Start-Sleep -Milliseconds 500
    Read-SerialResponse -TimeoutSeconds 5 -WaitFor 'Retype new password:' | Out-Null
    Send-SerialData -Data $AccountPassword
    Start-Sleep -Milliseconds 500
    Read-SerialResponse -TimeoutSeconds 3 | Out-Null

    # Commit
    Add-LogEntry "Committing configuration..." 'INFO'
    $commitResult = Invoke-JunosCommand -Command 'commit' -TimeoutSeconds 60 -WaitFor '(commit complete|error|failed)'

    Invoke-JunosCommand -Command 'exit' | Out-Null
    $script:IsConfigMode = $false

    if ($commitResult -match 'commit complete') {
        Add-LogEntry "vc3admin account $($action.ToLower()) and committed successfully." 'PASS'
        return @{ success = $true; message = "vc3admin account $($action.ToLower()) successfully."; alreadyExisted = $alreadyExists }
    } else {
        Add-LogEntry "Commit may have failed." 'WARN'
        return @{ success = $false; message = "Commit returned unexpected output."; raw = $commitResult }
    }
}

function Set-ManagementInterfaceApi {
    param([string]$IpAddress, [string]$Gateway, [string]$Interface)

    if (-not $Interface) {
        # Auto-detect
        $info = Invoke-JunosCommand -Command 'show version' -TimeoutSeconds 10
        if ($info -match 'EX\d+')     { $Interface = 'vme' }
        elseif ($info -match 'SRX\d+') { $Interface = 'fxp0' }
        else { $Interface = 'me0' }
    }

    Add-LogEntry "Configuring $Interface with $IpAddress..." 'INFO'
    Invoke-JunosCommand -Command 'configure' -TimeoutSeconds 5 | Out-Null
    $script:IsConfigMode = $true

    Invoke-JunosCommand -Command "set interfaces $Interface unit 0 family inet address $IpAddress" -TimeoutSeconds 5 | Out-Null

    if ($Gateway -and $Gateway.Trim()) {
        Invoke-JunosCommand -Command "set routing-options static route 0.0.0.0/0 next-hop $($Gateway.Trim())" -TimeoutSeconds 5 | Out-Null
    }

    $commitResult = Invoke-JunosCommand -Command 'commit' -TimeoutSeconds 30 -WaitFor '(commit complete|error|failed)'
    Invoke-JunosCommand -Command 'exit' | Out-Null
    $script:IsConfigMode = $false

    if ($commitResult -match 'commit complete') {
        $ipOnly = ($IpAddress -split '/')[0]
        Add-LogEntry "Management interface $Interface configured with $IpAddress. Device reachable at $ipOnly." 'PASS'
        return @{ success = $true; message = "Management IP configured. Device reachable at $ipOnly."; interface = $Interface; ip = $ipOnly }
    } else {
        Add-LogEntry "Commit may have failed for management IP." 'WARN'
        return @{ success = $false; message = "Commit returned unexpected output."; raw = $commitResult }
    }
}

function Invoke-FirmwareStage {
    param([string]$LaptopIP, [string]$ScpUser, [string]$ScpPath)

    $fileName = $ScpPath.Split('/')[-1]
    $scpCmd = "scp ${ScpUser}@${LaptopIP}:${ScpPath} /var/tmp/${fileName}"
    Add-LogEntry "Starting SCP: $scpCmd" 'INFO'
    Send-SerialData -Data $scpCmd
    return @{ success = $true; message = "SCP command sent. Watch the log for host-key/password prompts."; command = $scpCmd; remoteFile = "/var/tmp/$fileName" }
}

function Invoke-FirmwareInstall {
    param([string]$ImagePath, [switch]$Reboot)

    $cmd = "request system software add $ImagePath no-validate"
    if ($Reboot) { $cmd += " reboot" }

    Add-LogEntry "Running: $cmd" 'WARN'
    Send-SerialData -Data $cmd
    return @{ success = $true; message = "Firmware install command sent. This takes 10-30 minutes."; command = $cmd; willReboot = [bool]$Reboot }
}

function Get-RunningConfigText {
    if ($script:IsConfigMode) {
        Invoke-JunosCommand -Command 'exit' | Out-Null
        $script:IsConfigMode = $false
    }
    Invoke-JunosCommand -Command 'set cli screen-length 0' | Out-Null
    $config = Invoke-JunosCommand -Command 'show configuration' -TimeoutSeconds 30
    Add-LogEntry "Running configuration retrieved." 'PASS'
    return $config
}

function Invoke-RawJunosCommand {
    param([string]$Command)
    Add-LogEntry "CMD> $Command" 'INFO'
    $output = Invoke-JunosCommand -Command $Command -TimeoutSeconds 15
    return $output
}

# ============================================================================
# API ROUTE HANDLER
# ============================================================================
function Invoke-ApiRoute {
    param(
        [string]$Method,
        [string]$Path,
        [hashtable]$Body
    )

    switch ("$Method $Path") {

        'GET /api/status' {
            return @{
                connected  = $script:IsConnected
                loggedIn   = $script:IsLoggedIn
                configMode = $script:IsConfigMode
                device     = $script:DeviceInfo
                comPort    = if ($script:SerialPort) { $script:SerialPort.PortName } else { '' }
                baudRate   = if ($script:SerialPort) { $script:SerialPort.BaudRate } else { $BaudRate }
            }
        }

        'GET /api/ports' {
            $ports = Get-AvailableComPorts
            return @{ ports = $ports }
        }

        'POST /api/connect' {
            $portName = $Body['port']
            $baud = if ($Body['baudRate']) { [int]$Body['baudRate'] } else { 9600 }
            if (-not $portName) { return @{ success = $false; message = "No port specified." } }
            return (Connect-SerialPort -PortName $portName -Baud $baud)
        }

        'POST /api/disconnect' {
            Disconnect-SerialPort
            return @{ success = $true; message = "Disconnected." }
        }

        'POST /api/login' {
            if (-not $script:IsConnected) { return @{ success = $false; message = "Not connected to a serial port." } }
            $tryDefault = [bool]$Body['tryFactoryDefault']
            return (Invoke-DeviceLogin -Username $Body['username'] -Password $Body['password'] -TryFactoryDefault:$tryDefault)
        }

        'GET /api/device-info' {
            if (-not $script:IsLoggedIn) { return @{ success = $false; message = "Not logged in." } }
            return (Get-DeviceInfoData)
        }

        'POST /api/create-account' {
            if (-not $script:IsLoggedIn) { return @{ success = $false; message = "Not logged in." } }
            $pass = $Body['password']
            $rootPass = $Body['rootPassword']
            if (-not $pass -or $pass.Length -lt 6) { return @{ success = $false; message = "Password must be at least 6 characters." } }
            return (New-Vc3AdminAccountApi -AccountPassword $pass -RootPassword $rootPass)
        }

        'POST /api/mgmt-ip' {
            if (-not $script:IsLoggedIn) { return @{ success = $false; message = "Not logged in." } }
            $ip = $Body['ipAddress']
            if ($ip -notmatch '^\d+\.\d+\.\d+\.\d+/\d+$') { return @{ success = $false; message = "Use CIDR notation (e.g. 192.168.1.2/24)." } }
            return (Set-ManagementInterfaceApi -IpAddress $ip -Gateway $Body['gateway'] -Interface $Body['interface'])
        }

        'POST /api/firmware/scp' {
            if (-not $script:IsLoggedIn) { return @{ success = $false; message = "Not logged in." } }
            return (Invoke-FirmwareStage -LaptopIP $Body['laptopIp'] -ScpUser $Body['scpUser'] -ScpPath $Body['scpPath'])
        }

        'POST /api/firmware/list' {
            if (-not $script:IsLoggedIn) { return @{ success = $false; message = "Not logged in." } }
            $output = Invoke-JunosCommand -Command 'file list /var/tmp/' -TimeoutSeconds 10
            return @{ success = $true; output = $output }
        }

        'POST /api/firmware/install' {
            if (-not $script:IsLoggedIn) { return @{ success = $false; message = "Not logged in." } }
            $reboot = [bool]$Body['reboot']
            return (Invoke-FirmwareInstall -ImagePath $Body['imagePath'] -Reboot:$reboot)
        }

        'GET /api/config' {
            if (-not $script:IsLoggedIn) { return @{ success = $false; message = "Not logged in." } }
            $config = Get-RunningConfigText
            return @{ success = $true; config = $config }
        }

        'POST /api/command' {
            if (-not $script:IsLoggedIn) { return @{ success = $false; message = "Not logged in." } }
            $cmd = $Body['command']
            if (-not $cmd) { return @{ success = $false; message = "No command provided." } }
            $output = Invoke-RawJunosCommand -Command $cmd
            return @{ success = $true; output = $output }
        }

        'GET /api/log' {
            $startIdx = 0
            return @{ entries = @($script:SessionLog) }
        }

        'POST /api/serial-input' {
            # For sending raw keystrokes during interactive prompts (SCP host key, passwords)
            if (-not $script:IsConnected) { return @{ success = $false; message = "Not connected." } }
            Send-SerialData -Data $Body['input']
            Start-Sleep -Milliseconds 500
            $output = Read-SerialResponse -TimeoutSeconds 3
            return @{ success = $true; output = $output }
        }

        'POST /api/shutdown' {
            return @{ success = $true; message = "Shutting down." }
        }

        default {
            return @{ error = "Unknown route: $Method $Path" }
        }
    }
}

# ============================================================================
# HTML / CSS / JAVASCRIPT FRONTEND
# ============================================================================
$htmlContent = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Juniper Console Setup</title>
<style>
:root {
    --bg: #0f172a;
    --bg-card: #1e293b;
    --bg-card-hover: #263348;
    --bg-input: #334155;
    --bg-sidebar: #0c1322;
    --text: #e2e8f0;
    --text-muted: #94a3b8;
    --text-heading: #f1f5f9;
    --border: #334155;
    --accent: #38bdf8;
    --accent-hover: #7dd3fc;
    --accent-dim: rgba(56, 189, 248, 0.15);
    --success: #34d399;
    --success-dim: rgba(52, 211, 153, 0.15);
    --warning: #fbbf24;
    --warning-dim: rgba(251, 191, 36, 0.15);
    --danger: #f87171;
    --danger-dim: rgba(248, 113, 113, 0.15);
    --radius: 8px;
    --shadow: 0 1px 3px rgba(0,0,0,0.4);
    --font-mono: 'Cascadia Code', 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
}
[data-theme="light"] {
    --bg: #f1f5f9;
    --bg-card: #ffffff;
    --bg-card-hover: #f8fafc;
    --bg-input: #e2e8f0;
    --bg-sidebar: #e2e8f0;
    --text: #1e293b;
    --text-muted: #64748b;
    --text-heading: #0f172a;
    --border: #cbd5e1;
    --accent: #0284c7;
    --accent-hover: #0369a1;
    --accent-dim: rgba(2, 132, 199, 0.1);
    --success: #059669;
    --success-dim: rgba(5, 150, 105, 0.1);
    --warning: #d97706;
    --warning-dim: rgba(217, 119, 6, 0.1);
    --danger: #dc2626;
    --danger-dim: rgba(220, 38, 38, 0.1);
    --shadow: 0 1px 3px rgba(0,0,0,0.1);
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    height: 100vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
}
/* ---- TOP BAR ---- */
.topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 20px;
    height: 56px;
    background: var(--bg-sidebar);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
}
.topbar-left {
    display: flex;
    align-items: center;
    gap: 14px;
}
.topbar-logo {
    font-size: 18px;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: -0.5px;
}
.topbar-logo span { color: var(--text-muted); font-weight: 400; font-size: 13px; margin-left: 6px; }
.topbar-right {
    display: flex;
    align-items: center;
    gap: 12px;
}
.status-badge {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.status-badge.disconnected { background: var(--danger-dim); color: var(--danger); }
.status-badge.connected    { background: var(--warning-dim); color: var(--warning); }
.status-badge.logged-in    { background: var(--success-dim); color: var(--success); }
.status-dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: currentColor;
    animation: pulse 2s infinite;
}
@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
}
.theme-toggle {
    background: var(--bg-input);
    border: 1px solid var(--border);
    color: var(--text);
    width: 36px; height: 36px;
    border-radius: 50%;
    cursor: pointer;
    font-size: 16px;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.2s;
}
.theme-toggle:hover { background: var(--bg-card-hover); border-color: var(--accent); }
.btn-shutdown {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text-muted);
    padding: 6px 12px;
    border-radius: var(--radius);
    cursor: pointer;
    font-size: 12px;
    transition: all 0.2s;
}
.btn-shutdown:hover { border-color: var(--danger); color: var(--danger); }

/* ---- LAYOUT ---- */
.main-layout {
    display: flex;
    flex: 1;
    overflow: hidden;
}
/* ---- SIDEBAR ---- */
.sidebar {
    width: 220px;
    background: var(--bg-sidebar);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
    padding: 12px 0;
}
.nav-item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 20px;
    color: var(--text-muted);
    cursor: pointer;
    font-size: 13px;
    font-weight: 500;
    transition: all 0.15s;
    border-left: 3px solid transparent;
    user-select: none;
}
.nav-item:hover { color: var(--text); background: var(--bg-card); }
.nav-item.active {
    color: var(--accent);
    background: var(--accent-dim);
    border-left-color: var(--accent);
}
.nav-item.disabled { opacity: 0.35; pointer-events: none; }
.nav-icon { font-size: 16px; width: 20px; text-align: center; }
.nav-label { flex: 1; }
.nav-step {
    font-size: 10px;
    background: var(--bg-input);
    color: var(--text-muted);
    width: 20px; height: 20px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 700;
}
.nav-item.done .nav-step { background: var(--success-dim); color: var(--success); }
.nav-divider {
    height: 1px;
    background: var(--border);
    margin: 8px 20px;
}
.sidebar-footer {
    margin-top: auto;
    padding: 12px 20px;
    font-size: 11px;
    color: var(--text-muted);
    border-top: 1px solid var(--border);
}

/* ---- CONTENT ---- */
.content-area {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
}
.content-main {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
}
.page { display: none; }
.page.active { display: block; }
.page-title {
    font-size: 20px;
    font-weight: 700;
    color: var(--text-heading);
    margin-bottom: 4px;
}
.page-subtitle {
    font-size: 13px;
    color: var(--text-muted);
    margin-bottom: 20px;
}
/* ---- CARDS ---- */
.card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px;
    margin-bottom: 16px;
    box-shadow: var(--shadow);
}
.card-title {
    font-size: 14px;
    font-weight: 600;
    color: var(--text-heading);
    margin-bottom: 12px;
}
.info-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
}
.info-item label {
    display: block;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    margin-bottom: 4px;
}
.info-item .value {
    font-size: 16px;
    font-weight: 600;
    color: var(--text-heading);
    font-family: var(--font-mono);
}
.info-item .value.empty { color: var(--text-muted); font-style: italic; font-weight: 400; }

/* ---- FORMS ---- */
.form-group { margin-bottom: 16px; }
.form-group label {
    display: block;
    font-size: 13px;
    font-weight: 500;
    color: var(--text);
    margin-bottom: 6px;
}
.form-group .hint {
    font-size: 11px;
    color: var(--text-muted);
    margin-top: 4px;
}
input[type="text"], input[type="password"], select, textarea {
    width: 100%;
    padding: 9px 12px;
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text);
    font-size: 14px;
    font-family: inherit;
    outline: none;
    transition: border-color 0.2s;
}
input:focus, select:focus, textarea:focus { border-color: var(--accent); }
input::placeholder, textarea::placeholder { color: var(--text-muted); }
textarea { resize: vertical; font-family: var(--font-mono); font-size: 13px; }
.form-row { display: flex; gap: 12px; }
.form-row .form-group { flex: 1; }
.checkbox-group {
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    font-size: 13px;
}
.checkbox-group input[type="checkbox"] { width: auto; cursor: pointer; }

/* ---- BUTTONS ---- */
.btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 9px 18px;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    border: 1px solid transparent;
    transition: all 0.2s;
    font-family: inherit;
}
.btn:disabled { opacity: 0.5; cursor: not-allowed; }
.btn-primary { background: var(--accent); color: #fff; }
.btn-primary:hover:not(:disabled) { background: var(--accent-hover); }
.btn-success { background: var(--success); color: #fff; }
.btn-success:hover:not(:disabled) { filter: brightness(1.1); }
.btn-danger  { background: var(--danger); color: #fff; }
.btn-danger:hover:not(:disabled) { filter: brightness(1.1); }
.btn-outline {
    background: transparent;
    border-color: var(--border);
    color: var(--text);
}
.btn-outline:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
.btn-group { display: flex; gap: 8px; margin-top: 16px; flex-wrap: wrap; }

/* ---- ALERTS ---- */
.alert {
    padding: 12px 16px;
    border-radius: 6px;
    font-size: 13px;
    margin-bottom: 16px;
    display: none;
    align-items: flex-start;
    gap: 8px;
    line-height: 1.5;
}
.alert.show { display: flex; }
.alert-success { background: var(--success-dim); color: var(--success); border: 1px solid var(--success); }
.alert-danger  { background: var(--danger-dim); color: var(--danger); border: 1px solid var(--danger); }
.alert-warning { background: var(--warning-dim); color: var(--warning); border: 1px solid var(--warning); }
.alert-info    { background: var(--accent-dim); color: var(--accent); border: 1px solid var(--accent); }

/* ---- LOG PANEL ---- */
.log-panel {
    height: 200px;
    min-height: 100px;
    background: #0a0e17;
    border-top: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
}
[data-theme="light"] .log-panel { background: #1e293b; }
.log-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 6px 16px;
    background: rgba(0,0,0,0.2);
    border-bottom: 1px solid rgba(255,255,255,0.06);
}
.log-header-title { font-size: 11px; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; }
.log-body {
    flex: 1;
    overflow-y: auto;
    padding: 8px 16px;
    font-family: var(--font-mono);
    font-size: 12px;
    line-height: 1.6;
    color: #cbd5e1;
}
.log-entry { white-space: pre-wrap; word-break: break-all; }
.log-entry.INFO { color: #67e8f9; }
.log-entry.PASS { color: #6ee7b7; }
.log-entry.WARN { color: #fcd34d; }
.log-entry.FAIL { color: #fca5a5; }
.log-resize {
    height: 4px;
    background: var(--border);
    cursor: ns-resize;
}
.log-resize:hover { background: var(--accent); }

/* ---- TERMINAL ---- */
.terminal-wrap {
    background: #0a0e17;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
}
[data-theme="light"] .terminal-wrap { background: #1e293b; }
.terminal-output {
    height: 300px;
    overflow-y: auto;
    padding: 12px 16px;
    font-family: var(--font-mono);
    font-size: 13px;
    line-height: 1.5;
    color: #e2e8f0;
    white-space: pre-wrap;
    word-break: break-all;
}
.terminal-input-row {
    display: flex;
    border-top: 1px solid rgba(255,255,255,0.06);
}
.terminal-prompt {
    padding: 10px 12px;
    color: var(--accent);
    font-family: var(--font-mono);
    font-size: 13px;
    font-weight: 700;
    user-select: none;
}
.terminal-input {
    flex: 1;
    background: transparent;
    border: none;
    color: #e2e8f0;
    font-family: var(--font-mono);
    font-size: 13px;
    padding: 10px 0;
    outline: none;
}
/* ---- FIRMWARE PROGRESS ---- */
.progress-bar {
    height: 4px;
    background: var(--bg-input);
    border-radius: 2px;
    overflow: hidden;
    margin: 12px 0;
}
.progress-fill {
    height: 100%;
    background: var(--accent);
    border-radius: 2px;
    width: 0%;
    transition: width 0.3s;
}
.progress-fill.indeterminate {
    width: 30%;
    animation: indeterminate 1.5s infinite ease-in-out;
}
@keyframes indeterminate {
    0% { margin-left: 0%; }
    50% { margin-left: 70%; }
    100% { margin-left: 0%; }
}

/* ---- CONFIG VIEWER ---- */
.config-viewer {
    background: #0a0e17;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px;
    font-family: var(--font-mono);
    font-size: 13px;
    line-height: 1.5;
    color: #e2e8f0;
    max-height: 500px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-all;
}
[data-theme="light"] .config-viewer { background: #1e293b; }

/* ---- SPINNER ---- */
.spinner {
    display: inline-block;
    width: 14px; height: 14px;
    border: 2px solid rgba(255,255,255,0.3);
    border-top-color: #fff;
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
.btn .spinner { width: 12px; height: 12px; }
</style>
</head>
<body>

<!-- TOP BAR -->
<div class="topbar">
    <div class="topbar-left">
        <div class="topbar-logo">Juniper Console Setup <span>VC3 Engineering</span></div>
    </div>
    <div class="topbar-right">
        <div id="statusBadge" class="status-badge disconnected">
            <span class="status-dot"></span>
            <span id="statusText">Disconnected</span>
        </div>
        <button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme">&#9681;</button>
        <button class="btn-shutdown" onclick="shutdown()">Shut Down</button>
    </div>
</div>

<!-- MAIN LAYOUT -->
<div class="main-layout">
    <!-- SIDEBAR -->
    <div class="sidebar">
        <div class="nav-item active" data-page="connect" onclick="showPage('connect')">
            <span class="nav-icon">&#9986;</span>
            <span class="nav-label">Connect</span>
            <span class="nav-step">1</span>
        </div>
        <div class="nav-item disabled" data-page="login" onclick="showPage('login')">
            <span class="nav-icon">&#128274;</span>
            <span class="nav-label">Login</span>
            <span class="nav-step">2</span>
        </div>
        <div class="nav-item disabled" data-page="info" onclick="showPage('info')">
            <span class="nav-icon">&#8505;</span>
            <span class="nav-label">Device Info</span>
            <span class="nav-step">3</span>
        </div>
        <div class="nav-item disabled" data-page="account" onclick="showPage('account')">
            <span class="nav-icon">&#128100;</span>
            <span class="nav-label">vc3admin Account</span>
            <span class="nav-step">4</span>
        </div>
        <div class="nav-item disabled" data-page="network" onclick="showPage('network')">
            <span class="nav-icon">&#127760;</span>
            <span class="nav-label">Management IP</span>
            <span class="nav-step">5</span>
        </div>
        <div class="nav-item disabled" data-page="firmware" onclick="showPage('firmware')">
            <span class="nav-icon">&#11014;</span>
            <span class="nav-label">Firmware</span>
            <span class="nav-step">6</span>
        </div>
        <div class="nav-divider"></div>
        <div class="nav-item disabled" data-page="config" onclick="showPage('config')">
            <span class="nav-icon">&#128196;</span>
            <span class="nav-label">Save Config</span>
        </div>
        <div class="nav-item disabled" data-page="terminal" onclick="showPage('terminal')">
            <span class="nav-icon">&#62;</span>
            <span class="nav-label">Terminal</span>
        </div>
        <div class="sidebar-footer">
            COM: <span id="sidebarPort">--</span><br>
            Baud: <span id="sidebarBaud">9600</span>
        </div>
    </div>

    <!-- CONTENT -->
    <div class="content-area">
        <div class="content-main">

            <!-- PAGE: CONNECT -->
            <div id="page-connect" class="page active">
                <div class="page-title">Connect to Device</div>
                <div class="page-subtitle">Select a COM port and connect to the Juniper console.</div>
                <div class="card">
                    <div class="card-title">Serial Connection</div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>COM Port</label>
                            <div style="display:flex; gap:8px;">
                                <select id="comPortSelect" style="flex:1;">
                                    <option value="">-- Scanning... --</option>
                                </select>
                                <button class="btn btn-outline" onclick="refreshPorts()">Refresh</button>
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Baud Rate</label>
                            <select id="baudSelect">
                                <option value="9600" selected>9600 (standard)</option>
                                <option value="19200">19200</option>
                                <option value="38400">38400</option>
                                <option value="57600">57600</option>
                                <option value="115200">115200</option>
                            </select>
                        </div>
                    </div>
                    <div id="connectAlert" class="alert"></div>
                    <div class="btn-group">
                        <button id="btnConnect" class="btn btn-primary" onclick="connectPort()">Connect</button>
                        <button id="btnDisconnect" class="btn btn-danger" onclick="disconnectPort()" style="display:none;">Disconnect</button>
                    </div>
                </div>
            </div>

            <!-- PAGE: LOGIN -->
            <div id="page-login" class="page">
                <div class="page-title">Login to Device</div>
                <div class="page-subtitle">Authenticate with the Juniper device. Factory-default devices use root with no password.</div>
                <div class="card">
                    <div class="card-title">Authentication</div>
                    <div id="loginAlert" class="alert"></div>
                    <div class="form-group">
                        <label class="checkbox-group">
                            <input type="checkbox" id="tryFactory" checked>
                            Try factory-default first (root / no password)
                        </label>
                    </div>
                    <div id="credentialsSection">
                        <div class="form-row">
                            <div class="form-group">
                                <label>Username</label>
                                <input type="text" id="loginUser" placeholder="root">
                            </div>
                            <div class="form-group">
                                <label>Password</label>
                                <input type="password" id="loginPass" placeholder="Enter password">
                            </div>
                        </div>
                    </div>
                    <div class="btn-group">
                        <button id="btnLogin" class="btn btn-primary" onclick="doLogin()">Login</button>
                    </div>
                </div>
            </div>

            <!-- PAGE: DEVICE INFO -->
            <div id="page-info" class="page">
                <div class="page-title">Device Information</div>
                <div class="page-subtitle">Query the device for identification details.</div>
                <div class="card">
                    <div id="infoAlert" class="alert"></div>
                    <div class="info-grid" id="deviceInfoGrid">
                        <div class="info-item"><label>Hostname</label><div class="value empty" id="infoHostname">--</div></div>
                        <div class="info-item"><label>Model</label><div class="value empty" id="infoModel">--</div></div>
                        <div class="info-item"><label>Firmware</label><div class="value empty" id="infoFirmware">--</div></div>
                        <div class="info-item"><label>Serial Number</label><div class="value empty" id="infoSerial">--</div></div>
                    </div>
                    <div class="btn-group">
                        <button id="btnGetInfo" class="btn btn-primary" onclick="getDeviceInfo()">Get Device Info</button>
                    </div>
                </div>
            </div>

            <!-- PAGE: VC3ADMIN ACCOUNT -->
            <div id="page-account" class="page">
                <div class="page-title">vc3admin Account</div>
                <div class="page-subtitle">Create or reset the vc3admin super-user account on this device.</div>
                <div class="card">
                    <div id="accountAlert" class="alert"></div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>vc3admin Password</label>
                            <input type="password" id="vc3Pass1" placeholder="Min 6 characters">
                        </div>
                        <div class="form-group">
                            <label>Confirm Password</label>
                            <input type="password" id="vc3Pass2" placeholder="Re-enter password">
                        </div>
                    </div>
                    <div id="rootPassSection" class="card" style="background: var(--warning-dim); border-color: var(--warning); display:none;">
                        <div class="card-title" style="color: var(--warning);">Root Password Required</div>
                        <p style="font-size:13px; color: var(--text-muted); margin-bottom:12px;">
                            This is a factory-default device. Junos requires a root password before any commit.
                        </p>
                        <div class="form-row">
                            <div class="form-group">
                                <label>Root Password</label>
                                <input type="password" id="rootPass1" placeholder="Set root password">
                            </div>
                            <div class="form-group">
                                <label>Confirm Root Password</label>
                                <input type="password" id="rootPass2" placeholder="Re-enter root password">
                            </div>
                        </div>
                    </div>
                    <div class="btn-group">
                        <button id="btnCreateAccount" class="btn btn-success" onclick="createAccount()">Create vc3admin Account</button>
                    </div>
                </div>
            </div>

            <!-- PAGE: MANAGEMENT IP -->
            <div id="page-network" class="page">
                <div class="page-title">Management Interface</div>
                <div class="page-subtitle">Configure a management IP so you can SCP firmware from your laptop.</div>
                <div class="card">
                    <div id="networkAlert" class="alert"></div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Interface</label>
                            <select id="mgmtInterface">
                                <option value="">Auto-detect</option>
                                <option value="vme">vme (EX switches)</option>
                                <option value="fxp0">fxp0 (SRX firewalls)</option>
                                <option value="me0">me0 (other)</option>
                            </select>
                            <div class="hint">Leave on auto-detect unless you know the interface name.</div>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>IP Address (CIDR)</label>
                            <input type="text" id="mgmtIp" placeholder="192.168.1.2/24">
                        </div>
                        <div class="form-group">
                            <label>Gateway (optional)</label>
                            <input type="text" id="mgmtGw" placeholder="192.168.1.1">
                        </div>
                    </div>
                    <div class="btn-group">
                        <button id="btnSetMgmt" class="btn btn-primary" onclick="setMgmtIp()">Configure Management IP</button>
                    </div>
                </div>
            </div>

            <!-- PAGE: FIRMWARE -->
            <div id="page-firmware" class="page">
                <div class="page-title">Firmware Upgrade</div>
                <div class="page-subtitle">Transfer and install Junos firmware on this device.</div>

                <div class="card">
                    <div class="card-title">Step 1: Transfer Firmware via SCP</div>
                    <div id="fwScpAlert" class="alert"></div>
                    <p style="font-size:13px; color: var(--text-muted); margin-bottom:12px;">
                        The device will SCP the firmware image from your laptop. You need an SSH server running on your laptop.
                    </p>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Your Laptop IP</label>
                            <input type="text" id="fwLaptopIp" placeholder="192.168.1.100">
                        </div>
                        <div class="form-group">
                            <label>SSH Username</label>
                            <input type="text" id="fwScpUser" placeholder="admin">
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Firmware File Path (on your laptop)</label>
                        <input type="text" id="fwScpPath" placeholder="/c/temp/junos-arm-32-21.4R3-S7.2.tgz">
                        <div class="hint">Use forward slashes. For Windows paths: /c/Users/you/Downloads/firmware.tgz</div>
                    </div>
                    <div class="btn-group">
                        <button id="btnScpFw" class="btn btn-primary" onclick="scpFirmware()">Start SCP Transfer</button>
                        <button class="btn btn-outline" onclick="listFirmwareFiles()">List /var/tmp/ Files</button>
                    </div>
                    <div id="fwFileList" style="display:none; margin-top:12px;">
                        <div class="card-title">Files on Device (/var/tmp/):</div>
                        <pre class="config-viewer" id="fwFileListContent" style="max-height:150px;"></pre>
                    </div>
                </div>

                <div class="card">
                    <div class="card-title">Step 2: Install Firmware</div>
                    <div id="fwInstallAlert" class="alert"></div>
                    <div class="form-group">
                        <label>Image Path on Device</label>
                        <input type="text" id="fwImagePath" placeholder="/var/tmp/junos-arm-32-21.4R3-S7.2.tgz">
                    </div>
                    <div class="form-group">
                        <label class="checkbox-group">
                            <input type="checkbox" id="fwReboot" checked>
                            Reboot automatically after install
                        </label>
                    </div>
                    <div class="btn-group">
                        <button id="btnInstallFw" class="btn btn-danger" onclick="installFirmware()">Install Firmware</button>
                    </div>
                    <div id="fwProgress" style="display:none; margin-top: 12px;">
                        <div style="font-size:13px; color: var(--warning);">Firmware installation in progress. This can take 10-30 minutes...</div>
                        <div class="progress-bar"><div class="progress-fill indeterminate"></div></div>
                    </div>
                </div>
            </div>

            <!-- PAGE: SAVE CONFIG -->
            <div id="page-config" class="page">
                <div class="page-title">Running Configuration</div>
                <div class="page-subtitle">View and download the current device configuration.</div>
                <div class="card">
                    <div id="configAlert" class="alert"></div>
                    <div class="btn-group" style="margin-top:0; margin-bottom:16px;">
                        <button id="btnGetConfig" class="btn btn-primary" onclick="getConfig()">Retrieve Config</button>
                        <button id="btnDownloadConfig" class="btn btn-outline" onclick="downloadConfig()" style="display:none;">Download .txt</button>
                    </div>
                    <div id="configContent" class="config-viewer" style="display:none;"></div>
                </div>
            </div>

            <!-- PAGE: TERMINAL -->
            <div id="page-terminal" class="page">
                <div class="page-title">Raw Terminal</div>
                <div class="page-subtitle">Send Junos CLI commands directly to the device.</div>
                <div class="terminal-wrap">
                    <div class="terminal-output" id="terminalOutput"></div>
                    <div class="terminal-input-row">
                        <span class="terminal-prompt">junos&gt;</span>
                        <input class="terminal-input" id="terminalInput" type="text" placeholder="Type a command..." autofocus
                               onkeydown="if(event.key==='Enter') sendTerminalCmd()">
                    </div>
                </div>
                <div style="margin-top:8px; font-size:11px; color: var(--text-muted);">
                    Tip: Use &quot;configure&quot; to enter config mode, &quot;exit&quot; to leave it.
                    For interactive prompts during SCP, use the serial input box below.
                </div>
                <div class="card" style="margin-top:16px;">
                    <div class="card-title">Serial Input (for interactive prompts)</div>
                    <p style="font-size:12px; color: var(--text-muted); margin-bottom:8px;">
                        Send raw text for host-key confirmations, password prompts during SCP, etc.
                    </p>
                    <div style="display:flex; gap:8px;">
                        <input type="text" id="serialInput" placeholder="yes / password / etc." style="flex:1;"
                               onkeydown="if(event.key==='Enter') sendSerialInput()">
                        <button class="btn btn-outline" onclick="sendSerialInput()">Send</button>
                    </div>
                </div>
            </div>

        </div>

        <!-- LOG PANEL -->
        <div class="log-resize" id="logResize"></div>
        <div class="log-panel" id="logPanel">
            <div class="log-header">
                <span class="log-header-title">Console Log</span>
                <button class="btn-shutdown" onclick="clearLog()" style="font-size:11px;">Clear</button>
            </div>
            <div class="log-body" id="logBody"></div>
        </div>
    </div>
</div>

<script>
// ---- STATE ----
var state = { connected: false, loggedIn: false, configMode: false, device: {}, lastLogCount: 0 };
var currentPage = 'connect';
var configText = '';
var logPollTimer = null;

// ---- THEME ----
function initTheme() {
    var saved = localStorage.getItem('jcs-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
}
function toggleTheme() {
    var current = document.documentElement.getAttribute('data-theme') || 'dark';
    var next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('jcs-theme', next);
}
initTheme();

// ---- API ----
function api(method, path, body) {
    var opts = { method: method, headers: { 'Content-Type': 'application/json' } };
    if (body) opts.body = JSON.stringify(body);
    return fetch(path, opts).then(function(r) { return r.json(); });
}

// ---- NAVIGATION ----
function showPage(page) {
    var navItem = document.querySelector('.nav-item[data-page="' + page + '"]');
    if (navItem && navItem.classList.contains('disabled')) return;
    document.querySelectorAll('.page').forEach(function(p) { p.classList.remove('active'); });
    document.querySelectorAll('.nav-item').forEach(function(n) { n.classList.remove('active'); });
    document.getElementById('page-' + page).classList.add('active');
    if (navItem) navItem.classList.add('active');
    currentPage = page;
}

function updateNav() {
    var pages = ['login','info','account','network','firmware','config','terminal'];
    pages.forEach(function(p) {
        var nav = document.querySelector('.nav-item[data-page="' + p + '"]');
        if (!nav) return;
        if (p === 'login') {
            nav.classList.toggle('disabled', !state.connected);
        } else {
            nav.classList.toggle('disabled', !state.loggedIn);
        }
    });
    // Status badge
    var badge = document.getElementById('statusBadge');
    var text = document.getElementById('statusText');
    badge.className = 'status-badge';
    if (state.loggedIn) {
        badge.classList.add('logged-in');
        text.textContent = state.device.Hostname || 'Logged In';
    } else if (state.connected) {
        badge.classList.add('connected');
        text.textContent = 'Connected';
    } else {
        badge.classList.add('disconnected');
        text.textContent = 'Disconnected';
    }
}

// ---- ALERTS ----
function showAlert(id, type, msg) {
    var el = document.getElementById(id);
    el.className = 'alert alert-' + type + ' show';
    el.innerHTML = msg;
}
function hideAlert(id) {
    var el = document.getElementById(id);
    if (el) { el.className = 'alert'; el.innerHTML = ''; }
}

function setLoading(btnId, loading) {
    var btn = document.getElementById(btnId);
    if (!btn) return;
    btn.disabled = loading;
    if (loading) {
        btn.dataset.origText = btn.innerHTML;
        btn.innerHTML = '<span class="spinner"></span> Working...';
    } else {
        btn.innerHTML = btn.dataset.origText || btn.innerHTML;
    }
}

// ---- CONNECT ----
function refreshPorts() {
    api('GET', '/api/ports').then(function(data) {
        var sel = document.getElementById('comPortSelect');
        sel.innerHTML = '';
        if (data.ports && data.ports.length > 0) {
            data.ports.forEach(function(p) {
                var opt = document.createElement('option');
                opt.value = p; opt.textContent = p;
                sel.appendChild(opt);
            });
        } else {
            sel.innerHTML = '<option value="">No COM ports found</option>';
        }
    });
}

function connectPort() {
    var port = document.getElementById('comPortSelect').value;
    var baud = document.getElementById('baudSelect').value;
    if (!port) { showAlert('connectAlert', 'danger', 'Select a COM port.'); return; }
    hideAlert('connectAlert');
    setLoading('btnConnect', true);
    api('POST', '/api/connect', { port: port, baudRate: parseInt(baud) }).then(function(data) {
        setLoading('btnConnect', false);
        if (data.success) {
            state.connected = true;
            showAlert('connectAlert', 'success', 'Connected to ' + port + ' at ' + baud + ' baud.');
            document.getElementById('btnConnect').style.display = 'none';
            document.getElementById('btnDisconnect').style.display = '';
            document.getElementById('sidebarPort').textContent = port;
            document.getElementById('sidebarBaud').textContent = baud;
            updateNav();
            // Auto-advance to login
            setTimeout(function() { showPage('login'); }, 500);
        } else {
            showAlert('connectAlert', 'danger', data.message);
        }
    });
}

function disconnectPort() {
    api('POST', '/api/disconnect').then(function() {
        state.connected = false;
        state.loggedIn = false;
        state.device = {};
        document.getElementById('btnConnect').style.display = '';
        document.getElementById('btnDisconnect').style.display = 'none';
        document.getElementById('sidebarPort').textContent = '--';
        showAlert('connectAlert', 'info', 'Disconnected.');
        updateNav();
        showPage('connect');
        clearDeviceInfo();
    });
}

// ---- LOGIN ----
function doLogin() {
    hideAlert('loginAlert');
    var tryFactory = document.getElementById('tryFactory').checked;
    var user = document.getElementById('loginUser').value;
    var pass = document.getElementById('loginPass').value;
    setLoading('btnLogin', true);
    api('POST', '/api/login', { tryFactoryDefault: tryFactory, username: user, password: pass }).then(function(data) {
        setLoading('btnLogin', false);
        if (data.success) {
            state.loggedIn = true;
            showAlert('loginAlert', 'success', data.message);
            if (data.factoryDefault) {
                document.getElementById('rootPassSection').style.display = '';
            }
            updateNav();
            // Mark login step as done
            var loginNav = document.querySelector('.nav-item[data-page="login"]');
            if (loginNav) loginNav.classList.add('done');
            setTimeout(function() { showPage('info'); }, 600);
        } else {
            if (data.needsCredentials) {
                showAlert('loginAlert', 'warning', data.message + ' Enter credentials below.');
            } else {
                showAlert('loginAlert', 'danger', data.message);
            }
        }
    });
}

// ---- DEVICE INFO ----
function getDeviceInfo() {
    hideAlert('infoAlert');
    setLoading('btnGetInfo', true);
    api('GET', '/api/device-info').then(function(data) {
        setLoading('btnGetInfo', false);
        if (data.success) {
            state.device = { Hostname: data.hostname, Model: data.model, Firmware: data.firmware, Serial: data.serial };
            setInfoField('infoHostname', data.hostname);
            setInfoField('infoModel', data.model);
            setInfoField('infoFirmware', data.firmware);
            setInfoField('infoSerial', data.serial);
            updateNav();
            var infoNav = document.querySelector('.nav-item[data-page="info"]');
            if (infoNav) infoNav.classList.add('done');
        } else {
            showAlert('infoAlert', 'danger', data.message);
        }
    });
}
function setInfoField(id, val) {
    var el = document.getElementById(id);
    el.textContent = val || '--';
    el.classList.toggle('empty', !val);
}
function clearDeviceInfo() {
    ['infoHostname','infoModel','infoFirmware','infoSerial'].forEach(function(id) { setInfoField(id, ''); });
}

// ---- VC3ADMIN ACCOUNT ----
function createAccount() {
    hideAlert('accountAlert');
    var p1 = document.getElementById('vc3Pass1').value;
    var p2 = document.getElementById('vc3Pass2').value;
    if (!p1 || p1.length < 6) { showAlert('accountAlert', 'danger', 'Password must be at least 6 characters.'); return; }
    if (p1 !== p2) { showAlert('accountAlert', 'danger', 'Passwords do not match.'); return; }
    var rootP1 = document.getElementById('rootPass1').value;
    var rootP2 = document.getElementById('rootPass2').value;
    if (document.getElementById('rootPassSection').style.display !== 'none') {
        if (rootP1 && rootP1 !== rootP2) { showAlert('accountAlert', 'danger', 'Root passwords do not match.'); return; }
    }
    setLoading('btnCreateAccount', true);
    api('POST', '/api/create-account', { password: p1, rootPassword: rootP1 || null }).then(function(data) {
        setLoading('btnCreateAccount', false);
        if (data.success) {
            showAlert('accountAlert', 'success', data.message);
            var nav = document.querySelector('.nav-item[data-page="account"]');
            if (nav) nav.classList.add('done');
        } else {
            if (data.needsRootPassword) {
                document.getElementById('rootPassSection').style.display = '';
                showAlert('accountAlert', 'warning', data.message);
            } else {
                showAlert('accountAlert', 'danger', data.message || 'Operation failed.');
            }
        }
    });
}

// ---- MANAGEMENT IP ----
function setMgmtIp() {
    hideAlert('networkAlert');
    var ip = document.getElementById('mgmtIp').value;
    var gw = document.getElementById('mgmtGw').value;
    var iface = document.getElementById('mgmtInterface').value;
    if (!ip) { showAlert('networkAlert', 'danger', 'Enter an IP address.'); return; }
    setLoading('btnSetMgmt', true);
    api('POST', '/api/mgmt-ip', { ipAddress: ip, gateway: gw, interface: iface || null }).then(function(data) {
        setLoading('btnSetMgmt', false);
        if (data.success) {
            showAlert('networkAlert', 'success', data.message);
            var nav = document.querySelector('.nav-item[data-page="network"]');
            if (nav) nav.classList.add('done');
        } else {
            showAlert('networkAlert', 'danger', data.message);
        }
    });
}

// ---- FIRMWARE ----
function scpFirmware() {
    hideAlert('fwScpAlert');
    var ip = document.getElementById('fwLaptopIp').value;
    var user = document.getElementById('fwScpUser').value;
    var path = document.getElementById('fwScpPath').value;
    if (!ip || !user || !path) { showAlert('fwScpAlert', 'danger', 'Fill in all SCP fields.'); return; }
    setLoading('btnScpFw', true);
    api('POST', '/api/firmware/scp', { laptopIp: ip, scpUser: user, scpPath: path }).then(function(data) {
        setLoading('btnScpFw', false);
        if (data.success) {
            showAlert('fwScpAlert', 'warning', data.message + '<br>Check the <b>Terminal</b> page to handle host-key and password prompts.');
            document.getElementById('fwImagePath').value = data.remoteFile || '';
        } else {
            showAlert('fwScpAlert', 'danger', data.message);
        }
    });
}
function listFirmwareFiles() {
    api('POST', '/api/firmware/list').then(function(data) {
        document.getElementById('fwFileList').style.display = '';
        document.getElementById('fwFileListContent').textContent = data.output || '(empty)';
    });
}
function installFirmware() {
    hideAlert('fwInstallAlert');
    var path = document.getElementById('fwImagePath').value;
    var reboot = document.getElementById('fwReboot').checked;
    if (!path) { showAlert('fwInstallAlert', 'danger', 'Enter the image path.'); return; }
    if (!confirm('Install firmware and ' + (reboot ? 'REBOOT' : 'stage (no reboot)') + '?\n\nImage: ' + path)) return;
    setLoading('btnInstallFw', true);
    document.getElementById('fwProgress').style.display = '';
    api('POST', '/api/firmware/install', { imagePath: path, reboot: reboot }).then(function(data) {
        setLoading('btnInstallFw', false);
        if (data.success) {
            showAlert('fwInstallAlert', 'warning', data.message);
            var nav = document.querySelector('.nav-item[data-page="firmware"]');
            if (nav) nav.classList.add('done');
        } else {
            showAlert('fwInstallAlert', 'danger', data.message);
            document.getElementById('fwProgress').style.display = 'none';
        }
    });
}

// ---- CONFIG ----
function getConfig() {
    hideAlert('configAlert');
    setLoading('btnGetConfig', true);
    api('GET', '/api/config').then(function(data) {
        setLoading('btnGetConfig', false);
        if (data.success) {
            configText = data.config || '';
            document.getElementById('configContent').textContent = configText;
            document.getElementById('configContent').style.display = '';
            document.getElementById('btnDownloadConfig').style.display = '';
            showAlert('configAlert', 'success', 'Configuration retrieved (' + configText.length + ' characters).');
        } else {
            showAlert('configAlert', 'danger', data.message);
        }
    });
}
function downloadConfig() {
    var name = (state.device.Hostname || 'device') + '_config_' + new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19) + '.txt';
    var blob = new Blob([configText], { type: 'text/plain' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
}

// ---- TERMINAL ----
function sendTerminalCmd() {
    var input = document.getElementById('terminalInput');
    var cmd = input.value;
    if (!cmd) return;
    input.value = '';
    appendTerminal('> ' + cmd, 'color: #38bdf8;');
    api('POST', '/api/command', { command: cmd }).then(function(data) {
        appendTerminal(data.output || data.message || '(no output)');
    });
}
function sendSerialInput() {
    var input = document.getElementById('serialInput');
    var text = input.value;
    input.value = '';
    api('POST', '/api/serial-input', { input: text }).then(function(data) {
        if (data.output) appendTerminal(data.output);
    });
}
function appendTerminal(text, style) {
    var el = document.getElementById('terminalOutput');
    var line = document.createElement('div');
    line.textContent = text;
    if (style) line.setAttribute('style', style);
    el.appendChild(line);
    el.scrollTop = el.scrollHeight;
}

// ---- LOG ----
function pollLog() {
    api('GET', '/api/log').then(function(data) {
        if (!data.entries) return;
        var body = document.getElementById('logBody');
        if (data.entries.length > state.lastLogCount) {
            var newEntries = data.entries.slice(state.lastLogCount);
            newEntries.forEach(function(e) {
                var div = document.createElement('div');
                div.className = 'log-entry ' + e.level;
                div.textContent = '[' + e.level + '] ' + e.time + '  ' + e.message;
                body.appendChild(div);
            });
            state.lastLogCount = data.entries.length;
            body.scrollTop = body.scrollHeight;
        }
    }).catch(function() {});
}
function clearLog() {
    document.getElementById('logBody').innerHTML = '';
}

// ---- LOG RESIZE ----
(function() {
    var resizer = document.getElementById('logResize');
    var panel = document.getElementById('logPanel');
    var startY, startH;
    resizer.addEventListener('mousedown', function(e) {
        startY = e.clientY;
        startH = panel.offsetHeight;
        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
        e.preventDefault();
    });
    function onMove(e) { panel.style.height = Math.max(60, startH - (e.clientY - startY)) + 'px'; }
    function onUp() { document.removeEventListener('mousemove', onMove); document.removeEventListener('mouseup', onUp); }
})();

// ---- SHUTDOWN ----
function shutdown() {
    if (!confirm('Shut down the console setup server?')) return;
    api('POST', '/api/shutdown').then(function() {
        document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;"><div style="text-align:center;color:var(--text-muted);"><h2>Server Stopped</h2><p>You can close this tab.</p></div></div>';
    });
}

// ---- INIT ----
refreshPorts();
logPollTimer = setInterval(pollLog, 1500);
pollLog();
updateNav();
</script>
</body>
</html>
'@

# ============================================================================
# HTTP SERVER
# ============================================================================
$baseUrl = "http://localhost:${Port}/"
$listener = $null

try {
    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add($baseUrl)
    $listener.Start()

    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "  JUNIPER CONSOLE SETUP - GUI" -ForegroundColor Cyan
    Write-Host "  Server running at: $baseUrl" -ForegroundColor White
    Write-Host "  Press Ctrl+C to stop." -ForegroundColor Gray
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""

    Add-LogEntry "Web server started at $baseUrl" 'PASS'

    # Auto-connect if ComPort was specified
    if ($ComPort) {
        $result = Connect-SerialPort -PortName $ComPort -Baud $BaudRate
        if ($result.success) {
            Add-LogEntry "Pre-connected to $ComPort." 'PASS'
        }
    }

    # Launch browser
    if (-not $NoBrowserOpen) {
        Start-Process $baseUrl
    }

    # Request loop
    while ($listener.IsListening) {
        $contextTask = $listener.GetContextAsync()
        while (-not $contextTask.AsyncWaitHandle.WaitOne(100)) { }
        $context = $contextTask.GetAwaiter().GetResult()

        $request  = $context.Request
        $response = $context.Response

        $path   = $request.Url.AbsolutePath
        $method = $request.HttpMethod

        try {
            if ($path -eq '/' -or $path -eq '/index.html') {
                # Serve HTML
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($htmlContent)
                $response.ContentType = 'text/html; charset=utf-8'
                $response.ContentLength64 = $bytes.Length
                $response.OutputStream.Write($bytes, 0, $bytes.Length)

            } elseif ($path.StartsWith('/api/')) {
                # Parse JSON body
                $body = @{}
                if ($request.HasEntityBody) {
                    $reader = New-Object System.IO.StreamReader($request.InputStream, $request.ContentEncoding)
                    $bodyText = $reader.ReadToEnd()
                    $reader.Close()
                    if ($bodyText) {
                        try { $body = $bodyText | ConvertFrom-Json -ErrorAction Stop
                            # Convert PSObject to hashtable
                            $ht = @{}
                            $body.PSObject.Properties | ForEach-Object { $ht[$_.Name] = $_.Value }
                            $body = $ht
                        } catch { $body = @{} }
                    }
                }

                # Route
                $result = Invoke-ApiRoute -Method $method -Path $path -Body $body
                $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Depth 5 -Compress))
                $response.ContentType = 'application/json; charset=utf-8'
                $response.ContentLength64 = $jsonBytes.Length
                $response.OutputStream.Write($jsonBytes, 0, $jsonBytes.Length)

                # Check for shutdown
                if ($path -eq '/api/shutdown' -and $method -eq 'POST') {
                    $response.Close()
                    break
                }
            } else {
                $response.StatusCode = 404
                $notFound = [System.Text.Encoding]::UTF8.GetBytes('{"error":"Not found"}')
                $response.ContentType = 'application/json'
                $response.ContentLength64 = $notFound.Length
                $response.OutputStream.Write($notFound, 0, $notFound.Length)
            }
        } catch {
            Write-Host "[ERROR] Request handler: $_" -ForegroundColor Red
            try {
                $errBytes = [System.Text.Encoding]::UTF8.GetBytes((@{ error = "$_" } | ConvertTo-Json -Compress))
                $response.StatusCode = 500
                $response.ContentType = 'application/json'
                $response.ContentLength64 = $errBytes.Length
                $response.OutputStream.Write($errBytes, 0, $errBytes.Length)
            } catch { }
        } finally {
            try { $response.Close() } catch { }
        }
    }
} catch {
    Write-Host "[FATAL] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  If port $Port is in use, try: .\Invoke-JuniperConsoleSetup-GUI.ps1 -Port 8281" -ForegroundColor Yellow
} finally {
    Disconnect-SerialPort
    if ($listener) {
        try { $listener.Stop(); $listener.Close() } catch { }
    }
    Write-Host ""
    Write-Host "[INFO] Server stopped." -ForegroundColor Cyan
}
