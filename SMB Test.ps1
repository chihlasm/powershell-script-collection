# ==============================================
# Universal SMB Diagnostic & Protocol Detection Script
# Works: Windows 11 client → Windows Server 2008–2022
# ==============================================

# ====== CONFIGURE ======
$ServerIP   = "xxx.xxx.xxx.xxx"        # Replace with your server IP
$ShareName  = "folder"                 # Replace with your share name
$UNCPath    = "\\$ServerIP\$ShareName"
$DriveLetter = "Z"                     # Drive letter to map

# ====== Step 1: Test TCP connectivity on port 445 ======
Write-Host "=== Step 1: Test TCP connectivity on port 445 ==="
$tcpTest = Test-NetConnection -ComputerName $ServerIP -Port 445
if ($tcpTest.TcpTestSucceeded) {
    Write-Host "[PASS] TCP connection to SMB port 445 successful." -ForegroundColor Green
} else {
    Write-Host "[FAIL] Cannot reach SMB port 445. Check firewall/network." -ForegroundColor Red
}

# ====== Step 2: Check existing SMB sessions ======
Write-Host "`n=== Step 2: Check existing SMB sessions ==="
$osVer = (Get-CimInstance Win32_OperatingSystem).Version
if ([version]$osVer -ge [version]"6.2") {
    # Windows 8 / Server 2012+
    try {
        $smbConn = Get-SmbConnection -Server $ServerIP -ErrorAction Stop
        if ($smbConn) {
            Write-Host "[INFO] Active SMB sessions found:" -ForegroundColor Cyan
            $smbConn | Format-Table -AutoSize
        } else {
            Write-Host "[INFO] No active SMB sessions yet."
        }
    } catch {
        Write-Host "[WARN] Could not query SMB sessions. Continuing..." -ForegroundColor Yellow
    }
} else {
    # Windows 7 / Server 2008 R2 fallback
    Write-Host "[INFO] Using legacy net use for SMB sessions (Server 2008 / 2008 R2)." -ForegroundColor Cyan
    net use | ForEach-Object { Write-Host $_ }
}

# ====== Step 3: Detect SMB protocol version on client ======
Write-Host "`n=== Step 3: Detect SMB protocol version ==="
if ([version]$osVer -ge [version]"6.2") {
    try {
        $clientSMB = Get-SmbConnection -Server $ServerIP | Select-Object -First 1
        if ($clientSMB) {
            Write-Host "[INFO] Current SMB dialect negotiated: $($clientSMB.Dialect)" -ForegroundColor Cyan
            if ($clientSMB.Dialect -like "1*") {
                Write-Host "[WARN] SMB1 protocol in use. Explorer may hang. Consider enabling SMB2/3 on server." -ForegroundColor Yellow
            } else {
                Write-Host "[PASS] SMB2/3 in use — modern protocol, Explorer should work." -ForegroundColor Green
            }
        } else {
            Write-Host "[INFO] No SMB session yet. Will test after mapping drive." -ForegroundColor Cyan
        }
    } catch {
        Write-Host "[WARN] Could not detect SMB dialect. Continuing..." -ForegroundColor Yellow
    }
} else {
    Write-Host "[WARN] SMB dialect detection not supported on Windows 7 / Server 2008 R2." -ForegroundColor Yellow
}

# ====== Step 4: Test folder access ======
Write-Host "`n=== Step 4: Test folder access ==="
try {
    if (Test-Path $UNCPath) {
        Write-Host "[PASS] Access to ${UNCPath} successful." -ForegroundColor Green
    } else {
        Write-Host "[FAIL] Cannot access ${UNCPath}. Check permissions or SMB session." -ForegroundColor Red
    }
} catch {
    Write-Host "[ERROR] Exception while testing folder access: $_" -ForegroundColor Red
}

# ====== Step 5: List files/folders ======
Write-Host "`n=== Step 5: List files/folders ==="
try {
    $files = Get-ChildItem $UNCPath -ErrorAction Stop
    Write-Host "[PASS] Files/folders in ${UNCPath}:" -ForegroundColor Green
    $files | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
} catch {
    Write-Host "[FAIL] Could not list files. Possibly SMB negotiation issue." -ForegroundColor Red
}

# ====== Step 6: Map network drive ======
Write-Host "`n=== Step 6: Map network drive ${DriveLetter}: ==="
try {
    if (Get-PSDrive -Name $DriveLetter -ErrorAction SilentlyContinue) {
        Remove-PSDrive -Name $DriveLetter -Force
    }

    New-PSDrive -Name $DriveLetter -PSProvider FileSystem -Root $UNCPath -Persist
    Write-Host "[PASS] Mapped ${UNCPath} to drive ${DriveLetter}:" -ForegroundColor Green

    # Check dialect after mapping (only for SMB2+)
    if ([version]$osVer -ge [version]"6.2") {
        $mappedConn = Get-SmbConnection -Server $ServerIP | Select-Object -First 1
        if ($mappedConn) {
            Write-Host "[INFO] SMB dialect after mapping: $($mappedConn.Dialect)" -ForegroundColor Cyan
            if ($mappedConn.Dialect -like "1*") {
                Write-Host "[WARN] SMB1 detected. Enable SMB2/3 on server to prevent Explorer hangs." -ForegroundColor Yellow
            } else {
                Write-Host "[PASS] SMB2/3 in use. Explorer should work properly." -ForegroundColor Green
            }
        }
    }
} catch {
    Write-Host "[FAIL] Could not map network drive. $_" -ForegroundColor Red
}

Write-Host "`n=== Diagnostic Complete ==="
