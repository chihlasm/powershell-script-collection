# Juniper-ConsoleSetup

> **Work in Progress** — This tool is in very early stages of development. Features described below may be incomplete, untested, or subject to significant change.

Interactive console-cable automation for provisioning Juniper EX and SRX devices. Available as a **Python browser GUI** (recommended) and a **PowerShell CLI menu**. Connects via serial COM port.

## Three Interfaces

| Script | Language | Interface | Best For |
|--------|----------|-----------|----------|
| `juniper_console_setup.py` | Python | Browser dashboard (localhost) | **Recommended** - reliable serial, nice UI |
| `Invoke-JuniperConsoleSetup-GUI.ps1` | PowerShell | Browser dashboard (localhost) | Windows-only, no Python available |
| `Invoke-JuniperConsoleSetup.ps1` | PowerShell | PowerShell menu | Headless / no-browser scenarios |

All tools share the same capabilities:

- **Login handling** - Auto-detects factory-default devices (root/no password) or prompts for existing credentials
- **Device identification** - Pulls hostname, model, firmware version, and serial number
- **vc3admin provisioning** - Creates a `vc3admin` super-user account with password auth; handles factory-default root password requirement automatically
- **Management IP setup** - Configures vme (EX) or fxp0 (SRX) so you can SCP firmware from your laptop
- **Firmware upgrade** - SCP image from your laptop to the device, then install with optional auto-reboot
- **Config backup** - Saves/downloads the running configuration
- **Raw command mode** - Type Junos commands directly through the serial connection

## Supported Platforms

EX2300, EX3400, EX4300, SRX300, SRX340, and other Junos-based devices with a standard serial console (9600/8N1).

## Requirements

### Python GUI (recommended)
- Python 3.x
- `pyserial` package (`pip install pyserial`)
- USB-to-serial console cable with driver installed

### PowerShell versions
- Windows 10/11 with PowerShell 5.1
- USB-to-serial console cable with driver installed

### For firmware SCP
- OpenSSH server running on your laptop (Windows: enable in Optional Features)

## Usage - Python GUI (Recommended)

```bash
# Install dependency (one-time)
pip install pyserial

# Launch the browser dashboard
python juniper_console_setup.py

# Specify port and COM port
python juniper_console_setup.py --port 9090 --com COM3

# Don't auto-open browser
python juniper_console_setup.py --no-browser
```

The GUI walks you through each step with a sidebar navigator:

1. **Connect** - Select COM port (with device descriptions) and baud rate
2. **Login** - Factory-default or credential-based authentication
3. **Device Info** - View hostname, model, firmware, serial
4. **vc3admin Account** - Create the account with password
5. **Management IP** - Set up vme/fxp0 for network access
6. **Firmware** - SCP transfer + install with progress
7. **Save Config** - View and download running config
8. **Terminal** - Raw Junos command line with serial input for interactive prompts

## Usage - PowerShell CLI

```powershell
# Auto-detect COM port
.\Invoke-JuniperConsoleSetup.ps1

# Specify COM port directly
.\Invoke-JuniperConsoleSetup.ps1 -ComPort COM5

# Custom baud rate and log location
.\Invoke-JuniperConsoleSetup.ps1 -ComPort COM5 -BaudRate 115200 -LogPath C:\Temp\JuniperLogs
```

## Typical Workflow

1. Plug in your console cable and run the script
2. **Connect** to the COM port
3. **Login** - tries factory-default root first, falls back to manual credentials
4. **Get Device Info** - see what you're working with
5. **Create vc3admin** - provisions the super-user account
6. **Configure Management IP** - so you can reach the device over Ethernet
7. **SCP Firmware** from your laptop and install
8. **Save Config** before you unplug and move to the next device

## Firmware Upgrade Notes

The firmware SCP uses a "device pulls from laptop" approach:

1. Configure a management IP on the device
2. Connect your laptop to the device's management port with an Ethernet cable
3. Set your laptop to a static IP on the same subnet
4. Run an SSH/SCP server on your laptop (Windows: enable OpenSSH Server in Optional Features)
5. Have the device SCP the firmware from your laptop, then install

Alternatively, if the image is already on the device (USB stick copied to `/var/tmp/`), point directly to the file and skip the SCP step.

## Session Logging

- **Python GUI**: Console log panel in the browser + terminal output
- **PowerShell CLI**: Timestamped log files in the `Logs_*` folder (or your custom `-LogPath`)
