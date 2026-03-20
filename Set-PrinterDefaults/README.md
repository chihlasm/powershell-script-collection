# Set-PrinterDefaults

Sets default print configuration (black & white, two-sided) on a predefined list of printers.

## Usage

1. Edit the `$Printers` array at the top of the script with your printer names.
2. Run as Administrator:

```powershell
.\Set-PrinterDefaults.ps1
```

## What It Does

For each printer in the list:
- Sets duplex mode to **Two-Sided Long Edge**
- Disables color (sets to **B&W**)
- Skips any printer not found on the machine

## Configuration

Edit the `$Printers` array to match your environment:

```powershell
$Printers = @(
    "Office Toshiba",
    "Lobby HP LaserJet"
)
```

## Requirements

- PowerShell 5.1+
- Run as Administrator
- Printers must be installed on the local machine
