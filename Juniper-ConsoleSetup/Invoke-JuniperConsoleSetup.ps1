<#
.SYNOPSIS
    Interactive console-cable automation for Juniper EX/SRX devices.

.DESCRIPTION
    Connects to a Juniper device via serial console cable (COM port) and provides
    a menu-driven interface to:
      - Detect device model, hostname, and firmware version
      - Create a vc3admin super-user account (password-based)
      - Configure a management IP so you can SCP firmware
      - Stage and install Junos firmware upgrades
      - Save the running configuration to a local file

    Handles both factory-default devices (root with no password) and devices
    with existing credentials. Works with EX2300, EX3400, EX4300, SRX300,
    SRX340, and other Junos-based platforms.

.PARAMETER ComPort
    Serial COM port name (e.g., COM3, COM5). If omitted, the script lists
    available COM ports and lets you choose.

.PARAMETER BaudRate
    Serial baud rate. Default is 9600 (standard Juniper console).

.PARAMETER LogPath
    Directory for session logs. Defaults to a timestamped folder under the
    current directory.

.EXAMPLE
    .\Invoke-JuniperConsoleSetup.ps1
    Lists available COM ports, connects, and shows the interactive menu.

.EXAMPLE
    .\Invoke-JuniperConsoleSetup.ps1 -ComPort COM5
    Connects directly to COM5 and shows the interactive menu.

.NOTES
    Author  : VC3 Network Engineering
    Requires: Windows with .NET SerialPort support, USB-to-serial console cable
    Tested  : PowerShell 5.1 on Windows 10/11
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$ComPort,

    [ValidateRange(1200, 115200)]
    [int]$BaudRate = 9600,

    [string]$LogPath
)

# ============================================================================
# GLOBALS
# ============================================================================
$script:SerialPort   = $null
$script:SessionLog   = @()
$script:DeviceInfo   = @{
    Hostname = ''
    Model    = ''
    Firmware = ''
    Serial   = ''
}
$script:IsConfigMode = $false
$script:PromptPattern = '(login:\s*$|Password:\s*$|root@[\w%-]+[>#]\s*$|[\w.-]+[>#]\s*$|root@:~#\s*$|\{master:\d+\})'

# Timestamp helper
function Get-Timestamp { (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
function Get-FileTimestamp { (Get-Date).ToString('yyyy-MM-dd_HHmmss') }

# ============================================================================
# LOGGING
# ============================================================================
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','PASS','WARN','FAIL')]
        [string]$Level = 'INFO'
    )
    $ts = Get-Timestamp
    $colors = @{ INFO = 'Cyan'; PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red' }
    Write-Host "[$Level] $ts  $Message" -ForegroundColor $colors[$Level]
    $script:SessionLog += "[$Level] $ts  $Message"
}

function Save-SessionLog {
    if (-not $script:LogFile) { return }
    try {
        $script:SessionLog | Out-File -FilePath $script:LogFile -Encoding UTF8
        Write-Host "[INFO] Session log saved to: $script:LogFile" -ForegroundColor Cyan
    } catch {
        Write-Host "[WARN] Could not save session log: $_" -ForegroundColor Yellow
    }
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
        $ports = [System.IO.Ports.SerialPort]::GetPortNames() | Sort-Object
        if ($ports.Count -eq 0) {
            Write-Log "No COM ports detected. Is the USB console cable plugged in?" -Level WARN
            return @()
        }
        return $ports
    } catch {
        Write-Log "Failed to enumerate COM ports: $_" -Level FAIL
        return @()
    }
}

function Connect-SerialPort {
    param(
        [Parameter(Mandatory)]
        [string]$PortName,
        [int]$Baud = 9600
    )

    try {
        $port = New-Object System.IO.Ports.SerialPort
        $port.PortName  = $PortName
        $port.BaudRate   = $Baud
        $port.DataBits   = 8
        $port.Parity     = [System.IO.Ports.Parity]::None
        $port.StopBits   = [System.IO.Ports.StopBits]::One
        $port.Handshake  = [System.IO.Ports.Handshake]::None
        $port.ReadTimeout  = 3000
        $port.WriteTimeout = 3000
        $port.NewLine    = "`n"
        $port.Encoding   = [System.Text.Encoding]::ASCII

        $port.Open()
        $script:SerialPort = $port
        Write-Log "Connected to $PortName at ${Baud} baud (8N1)" -Level PASS
        return $true
    } catch {
        Write-Log "Failed to open ${PortName}: $_" -Level FAIL
        return $false
    }
}

function Disconnect-SerialPort {
    if ($script:SerialPort -and $script:SerialPort.IsOpen) {
        try {
            $script:SerialPort.Close()
            $script:SerialPort.Dispose()
            Write-Log "Serial port closed." -Level INFO
        } catch {
            Write-Log "Error closing serial port: $_" -Level WARN
        }
    }
    $script:SerialPort = $null
}

# ============================================================================
# SERIAL I/O HELPERS
# ============================================================================
function Send-SerialData {
    <#
    .DESCRIPTION
        Sends a string over the serial port followed by a carriage return.
    #>
    param(
        [string]$Data,
        [switch]$NoNewline
    )

    if (-not $script:SerialPort -or -not $script:SerialPort.IsOpen) {
        Write-Log "Serial port is not open." -Level FAIL
        return
    }

    try {
        if ($NoNewline) {
            $script:SerialPort.Write($Data)
        } else {
            $script:SerialPort.Write("$Data`r")
        }
        $script:SessionLog += ">>> $Data"
    } catch {
        Write-Log "Failed to send data: $_" -Level FAIL
    }
}

function Read-SerialResponse {
    <#
    .DESCRIPTION
        Reads from the serial port until a recognizable prompt appears or timeout.
        Returns the accumulated text.
    #>
    param(
        [int]$TimeoutSeconds = 15,
        [string]$WaitFor = ''
    )

    if (-not $script:SerialPort -or -not $script:SerialPort.IsOpen) {
        return ''
    }

    $buffer   = New-Object System.Text.StringBuilder
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ((Get-Date) -lt $deadline) {
        try {
            $available = $script:SerialPort.BytesToRead
            if ($available -gt 0) {
                $data = $script:SerialPort.ReadExisting()
                [void]$buffer.Append($data)

                $current = $buffer.ToString()

                # Check for specific wait-for pattern
                if ($WaitFor -and $current -match $WaitFor) {
                    break
                }

                # Check for any known Junos prompt
                if (-not $WaitFor -and $current -match $script:PromptPattern) {
                    # Small delay to catch any trailing output
                    Start-Sleep -Milliseconds 200
                    $extra = $script:SerialPort.ReadExisting()
                    if ($extra) { [void]$buffer.Append($extra) }
                    break
                }
            } else {
                Start-Sleep -Milliseconds 100
            }
        } catch {
            # ReadTimeout is expected when no data
            Start-Sleep -Milliseconds 100
        }
    }

    $result = $buffer.ToString()
    $script:SessionLog += $result
    return $result
}

function Invoke-JunosCommand {
    <#
    .DESCRIPTION
        Sends a Junos CLI command and returns the output.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Command,
        [int]$TimeoutSeconds = 15,
        [string]$WaitFor = ''
    )

    Send-SerialData -Data $Command
    Start-Sleep -Milliseconds 300
    $response = Read-SerialResponse -TimeoutSeconds $TimeoutSeconds -WaitFor $WaitFor
    return $response
}

# ============================================================================
# DEVICE INTERACTION
# ============================================================================
function Wake-Device {
    <#
    .DESCRIPTION
        Sends a couple of Enter keys to wake up the console and figure out
        what state we're in (login prompt, CLI, shell, etc.)
    #>
    Write-Log "Waking device console..." -Level INFO
    Send-SerialData -Data ''
    Start-Sleep -Milliseconds 500
    Send-SerialData -Data ''
    Start-Sleep -Milliseconds 500
    $response = Read-SerialResponse -TimeoutSeconds 5
    return $response
}

function Enter-DeviceCLI {
    <#
    .DESCRIPTION
        Handles login to the Juniper device. Detects factory-default (root, no password)
        vs. existing credentials and gets to an operational CLI prompt.
    #>

    $response = Wake-Device

    # Already at a CLI prompt?
    if ($response -match '[\w.-]+>\s*$') {
        Write-Log "Already at operational CLI prompt." -Level PASS
        Invoke-JunosCommand -Command 'set cli screen-length 0' | Out-Null
        return $true
    }

    if ($response -match '[\w.-]+#\s*$' -and $response -notmatch 'root@:~#') {
        Write-Log "Already in configuration mode." -Level PASS
        $script:IsConfigMode = $true
        return $true
    }

    # At a shell prompt (factory default root logged in)
    if ($response -match 'root@[\w%-]*:~#\s*$' -or $response -match 'root@:~#') {
        Write-Log "At root shell (factory default). Entering CLI..." -Level INFO
        $cliResponse = Invoke-JunosCommand -Command 'cli'
        if ($cliResponse -match '>\s*$') {
            Write-Log "Entered CLI mode." -Level PASS
            Invoke-JunosCommand -Command 'set cli screen-length 0' | Out-Null
            return $true
        }
    }

    # At login prompt
    if ($response -match 'login:\s*$') {
        Write-Log "Device is at login prompt." -Level INFO

        # Try factory-default root first
        Write-Host ""
        Write-Host "  Attempt factory-default login (root / no password)? " -ForegroundColor Yellow -NoNewline
        $tryDefault = Read-Host "(Y/n)"
        if ($tryDefault -ne 'n') {
            Send-SerialData -Data 'root'
            Start-Sleep -Milliseconds 500
            $passPrompt = Read-SerialResponse -TimeoutSeconds 5

            if ($passPrompt -match 'Password:\s*$') {
                # Has a password set - send empty and see
                Send-SerialData -Data ''
                Start-Sleep -Milliseconds 1000
                $result = Read-SerialResponse -TimeoutSeconds 5

                if ($result -match 'Login incorrect' -or $result -match 'login:\s*$') {
                    Write-Log "Factory-default login failed. Device has a password." -Level WARN
                } else {
                    Write-Log "Logged in as root." -Level PASS
                    if ($result -match 'root@[\w%-]*:~#' -or $result -match 'root@:~#') {
                        $cliResponse = Invoke-JunosCommand -Command 'cli'
                        Invoke-JunosCommand -Command 'set cli screen-length 0' | Out-Null
                    }
                    return $true
                }
            } elseif ($passPrompt -match 'root@[\w%-]*:~#' -or $passPrompt -match '%\s*$') {
                # No password required - straight to shell
                Write-Log "Logged in as root (no password)." -Level PASS
                $cliResponse = Invoke-JunosCommand -Command 'cli'
                Invoke-JunosCommand -Command 'set cli screen-length 0' | Out-Null
                return $true
            }
        }

        # Manual credentials
        Write-Host ""
        $username = Read-Host "  Username"
        $secPass  = Read-Host "  Password" -AsSecureString
        $bstr     = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPass)
        $password = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

        # If we're still at login prompt, send username; otherwise wake and start fresh
        $current = Wake-Device
        if ($current -match 'login:\s*$') {
            Send-SerialData -Data $username
        } else {
            Send-SerialData -Data ''
            Start-Sleep -Milliseconds 500
            Read-SerialResponse -TimeoutSeconds 3 | Out-Null
            Send-SerialData -Data $username
        }

        Start-Sleep -Milliseconds 500
        $passPrompt = Read-SerialResponse -TimeoutSeconds 5
        if ($passPrompt -match 'Password:\s*$') {
            Send-SerialData -Data $password
            Start-Sleep -Milliseconds 1000
            $result = Read-SerialResponse -TimeoutSeconds 10

            if ($result -match 'Login incorrect' -or $result -match 'login:\s*$') {
                Write-Log "Login failed - check credentials." -Level FAIL
                return $false
            }

            Write-Log "Logged in as $username." -Level PASS

            if ($result -match 'root@[\w%-]*:~#' -or $result -match ':~#') {
                Invoke-JunosCommand -Command 'cli' | Out-Null
            }
            Invoke-JunosCommand -Command 'set cli screen-length 0' | Out-Null
            return $true
        }

        Write-Log "Unexpected response during login." -Level FAIL
        return $false
    }

    # Unknown state - show what we got
    Write-Log "Unrecognized console state. Raw output below:" -Level WARN
    Write-Host $response -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Press Enter on the device console and try again, or type credentials manually." -ForegroundColor Yellow
    return $false
}

# ============================================================================
# DEVICE INFO
# ============================================================================
function Get-DeviceInfo {
    Write-Log "Gathering device information..." -Level INFO

    # Exit config mode if needed
    if ($script:IsConfigMode) {
        Invoke-JunosCommand -Command 'exit' | Out-Null
        Start-Sleep -Milliseconds 300
        $script:IsConfigMode = $false
    }

    $versionOutput = Invoke-JunosCommand -Command 'show version' -TimeoutSeconds 10

    # Parse hostname
    if ($versionOutput -match 'Hostname:\s+(\S+)') {
        $script:DeviceInfo.Hostname = $Matches[1]
    }

    # Parse model
    if ($versionOutput -match 'Model:\s+(\S+)') {
        $script:DeviceInfo.Model = $Matches[1]
    }

    # Parse Junos version
    if ($versionOutput -match 'Junos:\s+(\S+)') {
        $script:DeviceInfo.Firmware = $Matches[1]
    } elseif ($versionOutput -match 'JUNOS\s+\S+\s+\[(\S+)\]') {
        $script:DeviceInfo.Firmware = $Matches[1]
    }

    # Get serial number
    $chassisOutput = Invoke-JunosCommand -Command 'show chassis hardware | match Chassis' -TimeoutSeconds 10
    if ($chassisOutput -match 'Chassis\s+\S+\s+\S+\s+(\S+)') {
        $script:DeviceInfo.Serial = $Matches[1]
    } elseif ($chassisOutput -match 'Chassis\s+(\S+)') {
        $script:DeviceInfo.Serial = $Matches[1]
    }

    Write-Host ""
    Write-Host "  ============================================" -ForegroundColor Cyan
    Write-Host "  DEVICE INFORMATION" -ForegroundColor Cyan
    Write-Host "  ============================================" -ForegroundColor Cyan
    Write-Host "  Hostname : $($script:DeviceInfo.Hostname)" -ForegroundColor White
    Write-Host "  Model    : $($script:DeviceInfo.Model)" -ForegroundColor White
    Write-Host "  Firmware : $($script:DeviceInfo.Firmware)" -ForegroundColor White
    Write-Host "  Serial   : $($script:DeviceInfo.Serial)" -ForegroundColor White
    Write-Host "  ============================================" -ForegroundColor Cyan
    Write-Host ""
}

# ============================================================================
# VC3ADMIN ACCOUNT PROVISIONING
# ============================================================================
function New-Vc3AdminAccount {
    Write-Log "Starting vc3admin account provisioning..." -Level INFO

    # Check if account already exists
    $existingCheck = Invoke-JunosCommand -Command 'show configuration system login user vc3admin' -TimeoutSeconds 10
    if ($existingCheck -match 'class super-user' -or $existingCheck -match 'encrypted-password') {
        Write-Log "vc3admin account already exists on this device." -Level WARN
        Write-Host "  Do you want to reset the password? " -ForegroundColor Yellow -NoNewline
        $reset = Read-Host "(y/N)"
        if ($reset -ne 'y') {
            Write-Log "Skipping account creation." -Level INFO
            return
        }
    }

    # Get desired password
    Write-Host ""
    $secPass1 = Read-Host "  Enter password for vc3admin" -AsSecureString
    $secPass2 = Read-Host "  Confirm password for vc3admin" -AsSecureString

    $bstr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPass1)
    $pass1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr1)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1)

    $bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPass2)
    $pass2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr2)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)

    if ($pass1 -ne $pass2) {
        Write-Log "Passwords do not match. Aborting." -Level FAIL
        return
    }

    if ($pass1.Length -lt 6) {
        Write-Log "Password must be at least 6 characters (Junos requirement)." -Level FAIL
        return
    }

    # Enter configuration mode
    Write-Log "Entering configuration mode..." -Level INFO
    $configResponse = Invoke-JunosCommand -Command 'configure' -TimeoutSeconds 5
    $script:IsConfigMode = $true

    # On factory-default, root password must be set before commit works
    # Check if root has a password
    $rootCheck = Invoke-JunosCommand -Command 'show system login user root' -TimeoutSeconds 5
    if ($rootCheck -notmatch 'encrypted-password') {
        Write-Log "Factory-default detected: root has no password. Setting root password first (Junos requires this)." -Level WARN
        Write-Host "  Enter a root password for this device: " -ForegroundColor Yellow -NoNewline
        $secRoot1 = Read-Host -AsSecureString
        Write-Host "  Confirm root password: " -ForegroundColor Yellow -NoNewline
        $secRoot2 = Read-Host -AsSecureString

        $bstrR1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secRoot1)
        $rootPass1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrR1)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrR1)

        $bstrR2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secRoot2)
        $rootPass2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrR2)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrR2)

        if ($rootPass1 -ne $rootPass2) {
            Write-Log "Root passwords do not match. Aborting." -Level FAIL
            Invoke-JunosCommand -Command 'rollback 0' | Out-Null
            Invoke-JunosCommand -Command 'exit' | Out-Null
            $script:IsConfigMode = $false
            return
        }

        # Set root password via plain-text-password
        Send-SerialData -Data 'set system root-authentication plain-text-password'
        Start-Sleep -Milliseconds 500
        $pwPrompt = Read-SerialResponse -TimeoutSeconds 5 -WaitFor 'New password:'
        Send-SerialData -Data $rootPass1
        Start-Sleep -Milliseconds 500
        $rePrompt = Read-SerialResponse -TimeoutSeconds 5 -WaitFor 'Retype new password:'
        Send-SerialData -Data $rootPass1
        Start-Sleep -Milliseconds 500
        Read-SerialResponse -TimeoutSeconds 3 | Out-Null
        Write-Log "Root password staged." -Level PASS
    }

    # Create vc3admin user with super-user class
    Write-Log "Creating vc3admin account with super-user class..." -Level INFO
    Send-SerialData -Data 'set system login user vc3admin class super-user authentication plain-text-password'
    Start-Sleep -Milliseconds 500
    $pwPrompt = Read-SerialResponse -TimeoutSeconds 5 -WaitFor 'New password:'
    Send-SerialData -Data $pass1
    Start-Sleep -Milliseconds 500
    $rePrompt = Read-SerialResponse -TimeoutSeconds 5 -WaitFor 'Retype new password:'
    Send-SerialData -Data $pass1
    Start-Sleep -Milliseconds 500
    Read-SerialResponse -TimeoutSeconds 3 | Out-Null

    # Commit
    Write-Log "Committing configuration..." -Level INFO
    $commitResult = Invoke-JunosCommand -Command 'commit' -TimeoutSeconds 60 -WaitFor '(commit complete|error|failed)'

    if ($commitResult -match 'commit complete') {
        Write-Log "vc3admin account created and committed successfully." -Level PASS
    } elseif ($commitResult -match 'error|failed') {
        Write-Log "Commit failed. Output:" -Level FAIL
        Write-Host $commitResult -ForegroundColor Red
        Write-Host "  Rolling back..." -ForegroundColor Yellow
        Invoke-JunosCommand -Command 'rollback 0' | Out-Null
    } else {
        Write-Log "Commit returned unexpected output (may still have succeeded):" -Level WARN
        Write-Host $commitResult -ForegroundColor Gray
    }

    # Exit config mode
    Invoke-JunosCommand -Command 'exit' | Out-Null
    $script:IsConfigMode = $false
}

# ============================================================================
# MANAGEMENT IP CONFIGURATION
# ============================================================================
function Set-ManagementInterface {
    Write-Log "Configuring management interface for firmware SCP..." -Level INFO

    Write-Host ""
    Write-Host "  This sets a temporary management IP so you can SCP firmware" -ForegroundColor Cyan
    Write-Host "  from your laptop to the device." -ForegroundColor Cyan
    Write-Host ""

    # Detect platform for correct interface name
    $infoOutput = Invoke-JunosCommand -Command 'show version' -TimeoutSeconds 10
    $isEX = $infoOutput -match 'EX\d+'
    $isSRX = $infoOutput -match 'SRX\d+'

    if ($isEX) {
        $mgmtInterface = 'vme'
        Write-Host "  Detected EX switch - using interface: vme" -ForegroundColor Cyan
    } elseif ($isSRX) {
        $mgmtInterface = 'fxp0'
        Write-Host "  Detected SRX firewall - using interface: fxp0" -ForegroundColor Cyan
    } else {
        $mgmtInterface = Read-Host "  Could not auto-detect. Enter management interface name (me0/vme/fxp0)"
    }

    Write-Host ""
    $mgmtIP   = Read-Host "  Management IP for this device (e.g. 192.168.1.2/24)"
    $gateway  = Read-Host "  Default gateway (or press Enter to skip)"

    # Validate IP format
    if ($mgmtIP -notmatch '^\d+\.\d+\.\d+\.\d+/\d+$') {
        Write-Log "Invalid IP format. Use CIDR notation (e.g. 192.168.1.2/24)." -Level FAIL
        return
    }

    Write-Log "Entering configuration mode..." -Level INFO
    Invoke-JunosCommand -Command 'configure' -TimeoutSeconds 5 | Out-Null
    $script:IsConfigMode = $true

    $setCmd = "set interfaces $mgmtInterface unit 0 family inet address $mgmtIP"
    Write-Log "Setting: $setCmd" -Level INFO
    Invoke-JunosCommand -Command $setCmd -TimeoutSeconds 5 | Out-Null

    if ($gateway -and $gateway.Trim()) {
        $gwCmd = "set routing-options static route 0.0.0.0/0 next-hop $($gateway.Trim())"
        Write-Log "Setting: $gwCmd" -Level INFO
        Invoke-JunosCommand -Command $gwCmd -TimeoutSeconds 5 | Out-Null
    }

    Write-Log "Committing management interface config..." -Level INFO
    $commitResult = Invoke-JunosCommand -Command 'commit' -TimeoutSeconds 30 -WaitFor '(commit complete|error|failed)'

    if ($commitResult -match 'commit complete') {
        Write-Log "Management interface configured. Device should now be reachable." -Level PASS
        $ipOnly = ($mgmtIP -split '/')[0]
        Write-Host ""
        Write-Host "  You can now SCP to this device at: $ipOnly" -ForegroundColor Green
        Write-Host "  Make sure your laptop is on the same subnet and cabled to the mgmt port." -ForegroundColor Cyan
        Write-Host ""
    } else {
        Write-Log "Commit may have failed. Output:" -Level WARN
        Write-Host $commitResult -ForegroundColor Gray
    }

    Invoke-JunosCommand -Command 'exit' | Out-Null
    $script:IsConfigMode = $false
}

# ============================================================================
# FIRMWARE UPGRADE
# ============================================================================
function Install-JunosFirmware {
    Write-Log "Starting firmware upgrade workflow..." -Level INFO

    Write-Host ""
    Write-Host "  ============================================" -ForegroundColor Yellow
    Write-Host "  FIRMWARE UPGRADE" -ForegroundColor Yellow
    Write-Host "  ============================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Current firmware: $($script:DeviceInfo.Firmware)" -ForegroundColor White
    Write-Host "  Current model   : $($script:DeviceInfo.Model)" -ForegroundColor White
    Write-Host ""
    Write-Host "  This will SCP the firmware image from your laptop" -ForegroundColor Cyan
    Write-Host "  to the device and install it." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Prerequisites:" -ForegroundColor Yellow
    Write-Host "    - Management interface is configured and reachable" -ForegroundColor Yellow
    Write-Host "    - You know your laptop's IP on the mgmt network" -ForegroundColor Yellow
    Write-Host "    - SSH/SCP is running on your laptop (or use device-pull method)" -ForegroundColor Yellow
    Write-Host ""

    Write-Host "  Choose transfer method:" -ForegroundColor Cyan
    Write-Host "    1) Push from device (device SCPs from your laptop)" -ForegroundColor White
    Write-Host "    2) Image already on device (/var/tmp/)" -ForegroundColor White
    Write-Host ""
    $method = Read-Host "  Selection (1-2)"

    $imagePath = ''

    switch ($method) {
        '1' {
            Write-Host ""
            $laptopIP   = Read-Host "  Your laptop IP on the mgmt network"
            $scpUser    = Read-Host "  SSH username on your laptop"
            $scpPath    = Read-Host "  Full path to firmware .tgz on your laptop (e.g. /c/temp/junos-ex3400.tgz)"
            $fileName   = Split-Path $scpPath -Leaf

            Write-Host ""
            Write-Log "Device will SCP the image from ${scpUser}@${laptopIP}:${scpPath}" -Level INFO
            Write-Host "  You will need to accept the host key and enter your laptop password" -ForegroundColor Yellow
            Write-Host "  on the console when prompted." -ForegroundColor Yellow
            Write-Host ""

            $scpCmd = "scp ${scpUser}@${laptopIP}:${scpPath} /var/tmp/${fileName}"
            Write-Log "Running: $scpCmd" -Level INFO

            # SCP can take a long time - use extended timeout
            Send-SerialData -Data $scpCmd
            Write-Host "  Waiting for SCP transfer (this may take several minutes)..." -ForegroundColor Cyan
            Write-Host "  Watch the console for host-key and password prompts." -ForegroundColor Yellow
            Write-Host "  Press Enter here when the transfer completes." -ForegroundColor Yellow
            Read-Host "  "
            Read-SerialResponse -TimeoutSeconds 5 | Out-Null

            $imagePath = "/var/tmp/$fileName"
        }
        '2' {
            Write-Host ""
            Write-Host "  Files in /var/tmp/:" -ForegroundColor Cyan
            $lsOutput = Invoke-JunosCommand -Command 'file list /var/tmp/*.tgz' -TimeoutSeconds 10
            Write-Host $lsOutput -ForegroundColor Gray
            Write-Host ""
            $imagePath = Read-Host "  Full path to firmware image (e.g. /var/tmp/junos-arm-32-21.4R3-S7.2.tgz)"
        }
        default {
            Write-Log "Invalid selection." -Level WARN
            return
        }
    }

    if (-not $imagePath) {
        Write-Log "No image path specified." -Level FAIL
        return
    }

    Write-Host ""
    Write-Host "  ============================================" -ForegroundColor Red
    Write-Host "  ABOUT TO INSTALL FIRMWARE" -ForegroundColor Red
    Write-Host "  Image : $imagePath" -ForegroundColor White
    Write-Host "  Device: $($script:DeviceInfo.Hostname) ($($script:DeviceInfo.Model))" -ForegroundColor White
    Write-Host "  ============================================" -ForegroundColor Red
    Write-Host ""

    Write-Host "  Options:" -ForegroundColor Cyan
    Write-Host "    1) Install and reboot now" -ForegroundColor White
    Write-Host "    2) Install only (reboot manually later)" -ForegroundColor White
    Write-Host "    3) Cancel" -ForegroundColor White
    $installChoice = Read-Host "  Selection (1-3)"

    switch ($installChoice) {
        '1' {
            $installCmd = "request system software add $imagePath no-validate reboot"
            Write-Log "Running: $installCmd" -Level WARN
            Write-Log "Device will reboot after installation completes!" -Level WARN
            Send-SerialData -Data $installCmd
            Write-Host ""
            Write-Host "  Firmware installation in progress. This can take 10-30 minutes." -ForegroundColor Yellow
            Write-Host "  The device will reboot automatically when done." -ForegroundColor Yellow
            Write-Host "  Watch the console output for progress." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Press Enter here once the device has rebooted and you see a login prompt." -ForegroundColor Cyan
            Read-Host "  "
            Read-SerialResponse -TimeoutSeconds 5 | Out-Null
        }
        '2' {
            $installCmd = "request system software add $imagePath no-validate"
            Write-Log "Running: $installCmd (no auto-reboot)" -Level INFO
            Send-SerialData -Data $installCmd
            Write-Host ""
            Write-Host "  Firmware installation in progress. This can take 10-30 minutes." -ForegroundColor Yellow
            Write-Host "  The device will NOT reboot automatically." -ForegroundColor Yellow
            Write-Host "  Run 'request system reboot' when ready." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Press Enter here once the installation completes." -ForegroundColor Cyan
            Read-Host "  "
            Read-SerialResponse -TimeoutSeconds 5 | Out-Null
        }
        '3' {
            Write-Log "Firmware install cancelled." -Level INFO
            return
        }
    }

    Write-Log "Firmware operation submitted. Verify with 'show version' after reboot." -Level PASS
}

# ============================================================================
# SAVE RUNNING CONFIG
# ============================================================================
function Save-RunningConfig {
    Write-Log "Pulling running configuration..." -Level INFO

    if ($script:IsConfigMode) {
        Invoke-JunosCommand -Command 'exit' | Out-Null
        $script:IsConfigMode = $false
    }

    Invoke-JunosCommand -Command 'set cli screen-length 0' | Out-Null
    Start-Sleep -Milliseconds 300

    $config = Invoke-JunosCommand -Command 'show configuration' -TimeoutSeconds 30

    $hostname = if ($script:DeviceInfo.Hostname) { $script:DeviceInfo.Hostname } else { 'unknown-device' }
    $fileName = "${hostname}_config_$(Get-FileTimestamp).txt"
    $filePath = Join-Path $script:LogDir $fileName

    try {
        $config | Out-File -FilePath $filePath -Encoding UTF8
        Write-Log "Configuration saved to: $filePath" -Level PASS
    } catch {
        Write-Log "Failed to save configuration: $_" -Level FAIL
    }
}

# ============================================================================
# RAW COMMAND MODE
# ============================================================================
function Enter-RawCommandMode {
    Write-Host ""
    Write-Host "  ============================================" -ForegroundColor Cyan
    Write-Host "  RAW COMMAND MODE" -ForegroundColor Cyan
    Write-Host "  Type Junos commands directly. Type 'exit-raw' to return to menu." -ForegroundColor Cyan
    Write-Host "  ============================================" -ForegroundColor Cyan
    Write-Host ""

    while ($true) {
        $cmd = Read-Host "  junos"
        if ($cmd -eq 'exit-raw') { break }
        if (-not $cmd) { continue }

        $output = Invoke-JunosCommand -Command $cmd -TimeoutSeconds 15
        Write-Host $output -ForegroundColor Gray
    }
    Write-Host ""
}

# ============================================================================
# INTERACTIVE MENU
# ============================================================================
function Show-Menu {
    $deviceLabel = if ($script:DeviceInfo.Hostname) {
        "$($script:DeviceInfo.Hostname) ($($script:DeviceInfo.Model) - Junos $($script:DeviceInfo.Firmware))"
    } else {
        "(not yet identified)"
    }

    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "  JUNIPER CONSOLE SETUP TOOL                    VC3 Engineering" -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "  Device: $deviceLabel" -ForegroundColor White
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    1)  Login / Connect to Device" -ForegroundColor White
    Write-Host "    2)  Get Device Info (model, firmware, serial)" -ForegroundColor White
    Write-Host "    3)  Create vc3admin Account" -ForegroundColor White
    Write-Host "    4)  Configure Management IP" -ForegroundColor White
    Write-Host "    5)  Upgrade Firmware (SCP + install)" -ForegroundColor White
    Write-Host "    6)  Save Running Config to File" -ForegroundColor White
    Write-Host "    7)  Raw Command Mode" -ForegroundColor White
    Write-Host ""
    Write-Host "    Q)  Quit" -ForegroundColor Gray
    Write-Host ""
}

# ============================================================================
# MAIN
# ============================================================================
function Main {
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "  JUNIPER CONSOLE SETUP TOOL" -ForegroundColor Cyan
    Write-Host "  Serial console automation for EX/SRX device provisioning" -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""

    # Setup logging directory
    if ($LogPath) {
        $script:LogDir = $LogPath
    } else {
        $script:LogDir = Join-Path $PSScriptRoot "Logs_$(Get-FileTimestamp)"
    }
    if (-not (Test-Path $script:LogDir)) {
        New-Item -Path $script:LogDir -ItemType Directory -Force | Out-Null
    }
    $script:LogFile = Join-Path $script:LogDir "session_$(Get-FileTimestamp).log"

    # Select COM port
    if (-not $ComPort) {
        $ports = Get-AvailableComPorts
        if ($ports.Count -eq 0) {
            Write-Log "No COM ports found. Plug in your console cable and try again." -Level FAIL
            return
        }

        Write-Host "  Available COM ports:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $ports.Count; $i++) {
            Write-Host "    $($i + 1)) $($ports[$i])" -ForegroundColor White
        }
        Write-Host ""

        if ($ports.Count -eq 1) {
            $ComPort = $ports[0]
            Write-Log "Auto-selected $ComPort (only port available)." -Level INFO
        } else {
            $sel = Read-Host "  Select port (1-$($ports.Count))"
            $idx = [int]$sel - 1
            if ($idx -lt 0 -or $idx -ge $ports.Count) {
                Write-Log "Invalid selection." -Level FAIL
                return
            }
            $ComPort = $ports[$idx]
        }
    }

    # Connect
    $connected = Connect-SerialPort -PortName $ComPort -Baud $BaudRate
    if (-not $connected) { return }

    # Main menu loop
    try {
        while ($true) {
            Show-Menu
            $choice = Read-Host "  Selection"

            switch ($choice.ToUpper()) {
                '1' { Enter-DeviceCLI }
                '2' { Get-DeviceInfo }
                '3' { New-Vc3AdminAccount }
                '4' { Set-ManagementInterface }
                '5' { Install-JunosFirmware }
                '6' { Save-RunningConfig }
                '7' { Enter-RawCommandMode }
                'Q' { break }
                default {
                    Write-Host "  Invalid selection." -ForegroundColor Yellow
                }
            }

            if ($choice.ToUpper() -eq 'Q') { break }
        }
    } finally {
        Write-Host ""
        Save-SessionLog
        Disconnect-SerialPort
        Write-Log "Session ended." -Level INFO
    }
}

# Run
Main
