# ===========================
# Set Printer Defaults: B&W + Two-Sided
# ===========================

$Printers = @(
    "ComDev Toshiba",
    "CityHall KM Bizhub",
    "Courts Toshiba",
    "Finance Toshiba",
    "Parks Toshiba",
    "Police Toshiba",
    "PublicWorks Toshiba"
)

foreach ($printerName in $Printers) {
    if (Get-Printer -Name $printerName -ErrorAction SilentlyContinue) {
        Write-Host "Applying defaults to: $printerName"
        try {
            Set-PrintConfiguration -PrinterName $printerName `
                -DuplexingMode TwoSidedLongEdge `
                -Color $false `
                -ErrorAction Stop
            Write-Host "Done."
        } catch {
            Write-Host "Warning: Could not apply defaults to $printerName. Error: $_"
        }
    } else {
        Write-Host "Skipping: $printerName not found on this machine."
    }
}

Write-Host "`nAll done."
